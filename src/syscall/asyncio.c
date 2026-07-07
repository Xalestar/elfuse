/*
 * Signal-driven I/O (O_ASYNC / SIGIO / SIGURG)
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * See asyncio.h for the design. The watcher owns one kqueue; arm/disarm
 * register EVFILT_READ (and EVFILT_EXCEPT/NOTE_OOB for sockets) as EV_CLEAR
 * edge-triggered knotes so a persistently-ready fd fires once per readiness
 * transition instead of storming signals. kevent() registration from a syscall
 * thread while the watcher blocks in kevent() on the same kqueue is safe on
 * macOS/BSD.
 */

#include "syscall/asyncio.h"

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdint.h>
#include <sys/event.h>
#include <unistd.h>

#include "utils.h"

#include "runtime/thread.h"
#include "syscall/abi.h"
#include "syscall/internal.h"
#include "syscall/proc.h"
#include "syscall/signal.h"

static int async_kq = -1;
static pthread_once_t async_once = PTHREAD_ONCE_INIT;

/* fd types that can generate SIGIO. Regular files and directories are always
 * "ready" and never carry ->fasync in Linux, so registering them would storm.
 * FD_FUSE_FILE/FD_FUSE_DIR are omitted for the same reason and because they
 * carry host_fd == -1 (no readiness fd to hand kqueue). Only /dev/fuse itself
 * (FD_FUSE_DEV) has a real host fd worth watching.
 */
static bool async_is_pollable(int fd_type)
{
    switch (fd_type) {
    case FD_SOCKET:
    case FD_PIPE:
    case FD_STDIO:
    case FD_FUSE_DEV:
        return true;
    default:
        return false;
    }
}

/* True when the fd owner names this guest process (its pid, its process group,
 * or one of its live threads). elfuse runs one guest process per host process,
 * so a foreign pid belongs to a forked child that this watcher cannot reach.
 */
static bool async_owner_is_local(int owner_type, int owner)
{
    switch (owner_type) {
    case FASYNC_OWNER_PID:
        return owner == (int) proc_get_pid();
    case FASYNC_OWNER_PGRP:
        return owner == (int) proc_get_pgid();
    case FASYNC_OWNER_TID:
        return thread_find(owner) != NULL;
    default:
        return false;
    }
}

/* kqueue udata packs the guest fd (low 16 bits) plus the fd slot generation at
 * arm time (upper 48 bits). The generation guards against ABA: if the slot was
 * closed and reused between arm and a stale event firing, the generation no
 * longer matches and the event is dropped, so a SIGIO cannot land on a later,
 * unrelated occupant of the same guest fd number. FD_TABLE_SIZE is 1024 (fits
 * 16 bits) and the generation counter is monotonic, so 48 bits will not wrap.
 */
static void *async_pack(int guest_fd, uint64_t generation)
{
    return (void *) (uintptr_t) (((generation & 0xFFFFFFFFFFFFULL) << 16) |
                                 (uint32_t) (guest_fd & 0xFFFF));
}

static void async_unpack(void *udata, int *guest_fd, uint64_t *generation)
{
    uint64_t v = (uint64_t) (uintptr_t) udata;
    *guest_fd = (int) (v & 0xFFFF);
    *generation = (v >> 16) & 0xFFFFFFFFFFFFULL;
}

static void async_deliver(void *udata, int signum)
{
    int guest_fd;
    uint64_t generation;
    async_unpack(udata, &guest_fd, &generation);

    fd_entry_t snap;
    if (!fd_snapshot(guest_fd, &snap))
        return; /* slot closed since the knote fired */
    if ((snap.generation & 0xFFFFFFFFFFFFULL) != generation)
        return; /* slot reused (ABA): this event belongs to the prior open */
    if (signum != LINUX_SIGURG && !(snap.linux_flags & LINUX_O_ASYNC))
        return; /* disarmed between fire and here (EV_CLEAR raced a disarm) */
    if (!async_owner_is_local(snap.fasync_owner_type, snap.fasync_owner))
        return; /* no owner, or a foreign guest pid */

    /* ponytail: owner delivery is process-wide. F_OWNER_TID does not target a
     * single thread and a foreign guest pid is not forwarded across the fork
     * IPC boundary. Add per-thread signal queueing + cross-process forwarding
     * when a real workload needs directed SIGIO.
     */
    signal_queue(signum);
}

static void *async_watcher(void *arg)
{
    (void) arg;
    struct kevent evs[32];
    for (;;) {
        int n = kevent(async_kq, NULL, 0, evs, 32, NULL);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return NULL; /* kqueue closed or fatal; disable delivery */
        }
        for (int i = 0; i < n; i++) {
            int signum =
                (evs[i].filter == EVFILT_EXCEPT) ? LINUX_SIGURG : LINUX_SIGIO;
            async_deliver(evs[i].udata, signum);
        }
    }
}

static void async_init_once(void)
{
    async_kq = kqueue();
    if (async_kq < 0)
        return;
    fcntl(async_kq, F_SETFD, FD_CLOEXEC);
    pthread_t t;
    if (pthread_create(&t, NULL, async_watcher, NULL) != 0) {
        close(async_kq);
        async_kq = -1;
        return;
    }
    pthread_detach(t);
}

void asyncio_init(void)
{
    pthread_once(&async_once, async_init_once);
}

void asyncio_arm(int guest_fd, uint64_t generation, int host_fd, int fd_type)
{
    if (async_kq < 0 || host_fd < 0 || !async_is_pollable(fd_type))
        return;
    void *udata = async_pack(guest_fd, generation);
    struct kevent ch[2];
    int n = 0;
    EV_SET(&ch[n++], host_fd, EVFILT_READ, EV_ADD | EV_CLEAR, 0, 0, udata);
    if (fd_type == FD_SOCKET)
        EV_SET(&ch[n++], host_fd, EVFILT_EXCEPT, EV_ADD | EV_CLEAR, NOTE_OOB, 0,
               udata);
    kevent(async_kq, ch, n, NULL, 0, NULL);
}

void asyncio_disarm(int host_fd)
{
    if (async_kq < 0)
        return;
    /* Issue each delete on its own kevent() call: with a NULL eventlist kevent
     * stops at the first failing change, and ENOENT is expected here (the
     * EVFILT_EXCEPT knote exists only for sockets, and a closed host fd has
     * already auto-removed both).
     */
    struct kevent ch;
    EV_SET(&ch, host_fd, EVFILT_READ, EV_DELETE, 0, 0, NULL);
    kevent(async_kq, &ch, 1, NULL, 0, NULL);
    EV_SET(&ch, host_fd, EVFILT_EXCEPT, EV_DELETE, 0, 0, NULL);
    kevent(async_kq, &ch, 1, NULL, 0, NULL);
}

/* Recompute one alias slot's readiness watch after its O_ASYNC bit or fasync
 * owner changed. A slot is armed iff O_ASYNC is set (SIGIO on readiness) or it
 * is a socket with an owner (SIGURG on OOB), matching the delivery-side checks
 * in async_deliver. Caller holds fd_lock. This single rule replaces the two
 * hand-rolled arm/disarm variants fasync_owner_set and asyncio_apply used to
 * carry, which had diverged (the owner path relied on the O_ASYNC path having
 * already armed non-socket slots rather than stating the invariant itself).
 */
static void async_reeval_slot_locked(int i)
{
    bool async = (fd_table[i].linux_flags & LINUX_O_ASYNC) != 0;
    bool owned = fd_table[i].fasync_owner_type != FASYNC_OWNER_NONE;
    if (async || (fd_table[i].type == FD_SOCKET && owned))
        asyncio_arm(i, fd_table[i].generation, fd_table[i].host_fd,
                    fd_table[i].type);
    else
        asyncio_disarm(fd_table[i].host_fd);
}

void fasync_owner_set(int guest_fd,
                      uint64_t expect_gen,
                      int owner_type,
                      int owner)
{
    if (!RANGE_CHECK(guest_fd, 0, FD_TABLE_SIZE))
        return;
    /* Arm/disarm under fd_lock with the live host fd and generation. Doing the
     * kevent registration inside the lock (rather than snapshotting aliases and
     * acting after unlock) closes the close+reuse race: a sibling close cannot
     * retire and reopen a host fd number while this scan holds fd_lock, so a
     * disarm can never clobber the fresh registration of a reused fd. kevent()
     * registration does not block, and the watcher thread never holds fd_lock
     * while parked in kevent(), so there is no deadlock.
     */
    pthread_mutex_lock(&fd_lock);
    uint64_t ofd_id = 0;
    if (fd_table[guest_fd].type != FD_CLOSED &&
        fd_table[guest_fd].generation == expect_gen)
        ofd_id = fd_table[guest_fd].ofd_id;
    if (ofd_id) {
        /* ponytail: O(FD_TABLE_SIZE) scan to reach every alias sharing this
         * open-file-description. Cold path (F_SETOWN only); an ofd_id->fd index
         * is the upgrade if it ever shows up in a profile.
         */
        for (int i = 0; i < FD_TABLE_SIZE; i++) {
            if (fd_table[i].type == FD_CLOSED || fd_table[i].ofd_id != ofd_id)
                continue;
            fd_table[i].fasync_owner_type = owner_type;
            fd_table[i].fasync_owner = owner;
            async_reeval_slot_locked(i);
        }
    }
    pthread_mutex_unlock(&fd_lock);
}

void fasync_owner_get(int guest_fd,
                      uint64_t expect_gen,
                      int *owner_type_out,
                      int *owner_out)
{
    *owner_type_out = FASYNC_OWNER_NONE;
    *owner_out = 0;
    if (!RANGE_CHECK(guest_fd, 0, FD_TABLE_SIZE))
        return;
    pthread_mutex_lock(&fd_lock);
    if (fd_table[guest_fd].type != FD_CLOSED &&
        fd_table[guest_fd].generation == expect_gen) {
        *owner_type_out = fd_table[guest_fd].fasync_owner_type;
        *owner_out = fd_table[guest_fd].fasync_owner;
    }
    pthread_mutex_unlock(&fd_lock);
}

void asyncio_apply(int guest_fd, uint64_t expect_gen, bool on)
{
    if (!RANGE_CHECK(guest_fd, 0, FD_TABLE_SIZE))
        return;
    /* Guard on generation, not just (type, host_fd): a close+reopen can reuse
     * the same guest fd number, host fd number, and type, so only the monotonic
     * generation distinguishes the caller's open from a new one. Arm/disarm run
     * under fd_lock so a host fd cannot be retired and reused mid-scan; see
     * fasync_owner_set for the deadlock argument.
     */
    pthread_mutex_lock(&fd_lock);
    uint64_t ofd_id = 0;
    if (fd_table[guest_fd].type != FD_CLOSED &&
        fd_table[guest_fd].generation == expect_gen)
        ofd_id = fd_table[guest_fd].ofd_id;
    if (ofd_id) {
        /* ponytail: O(FD_TABLE_SIZE) scan to reach every alias sharing this
         * open-file-description. Cold path (O_ASYNC toggles only); an
         * ofd_id->fd index is the upgrade if it ever shows up in a profile.
         */
        for (int i = 0; i < FD_TABLE_SIZE; i++) {
            if (fd_table[i].type == FD_CLOSED || fd_table[i].ofd_id != ofd_id)
                continue;
            if (on)
                fd_table[i].linux_flags |= LINUX_O_ASYNC;
            else
                fd_table[i].linux_flags &= ~LINUX_O_ASYNC;
            async_reeval_slot_locked(i);
        }
    }
    pthread_mutex_unlock(&fd_lock);
}
