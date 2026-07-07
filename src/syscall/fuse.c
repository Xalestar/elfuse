/*
 * Guest-internal FUSE transport and minimal VFS dispatch
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "utils.h"

#include "runtime/procemu.h"

#include "syscall/abi.h"
#include "syscall/asyncio.h"
#include "syscall/fuse.h"
#include "syscall/internal.h"
#include "syscall/path.h"
#include "syscall/proc.h"
#include "syscall/signal.h"

#define FUSE_KERNEL_VERSION 7
#define FUSE_KERNEL_MINOR_VERSION 45
#define FUSE_ROOT_ID 1

#define FUSE_ASYNC_READ (1u << 0)
#define FUSE_BIG_WRITES (1u << 5)
#define FUSE_MAX_PAGES (1u << 22)

enum fuse_opcode {
    FUSE_LOOKUP = 1,
    FUSE_FORGET = 2,
    FUSE_GETATTR = 3,
    FUSE_OPEN = 14,
    FUSE_READ = 15,
    FUSE_RELEASE = 18,
    FUSE_INIT = 26,
    FUSE_OPENDIR = 27,
    FUSE_READDIR = 28,
    FUSE_RELEASEDIR = 29,
    FUSE_INTERRUPT = 36,
    FUSE_BATCH_FORGET = 42,
};

typedef struct {
    uint64_t ino;
    uint64_t size;
    uint64_t blocks;
    uint64_t atime;
    uint64_t mtime;
    uint64_t ctime;
    uint32_t atimensec;
    uint32_t mtimensec;
    uint32_t ctimensec;
    uint32_t mode;
    uint32_t nlink;
    uint32_t uid;
    uint32_t gid;
    uint32_t rdev;
    uint32_t blksize;
    uint32_t flags;
} fuse_attr_t;

typedef struct {
    uint64_t nodeid;
    uint64_t generation;
    uint64_t entry_valid;
    uint64_t attr_valid;
    uint32_t entry_valid_nsec;
    uint32_t attr_valid_nsec;
    fuse_attr_t attr;
} fuse_entry_out_t;

typedef struct {
    uint64_t attr_valid;
    uint32_t attr_valid_nsec;
    uint32_t dummy;
    fuse_attr_t attr;
} fuse_attr_out_t;

typedef struct {
    uint32_t flags;
    uint32_t open_flags;
} fuse_open_in_t;

typedef struct {
    uint64_t fh;
    uint32_t open_flags;
    int32_t backing_id;
} fuse_open_out_t;

typedef struct {
    uint64_t fh;
    uint64_t offset;
    uint32_t size;
    uint32_t read_flags;
    uint64_t lock_owner;
    uint32_t flags;
    uint32_t padding;
} fuse_read_in_t;

typedef struct {
    uint64_t fh;
    uint32_t flags;
    uint32_t release_flags;
    uint64_t lock_owner;
} fuse_release_in_t;

typedef struct {
    uint64_t nlookup;
} fuse_forget_in_t;

typedef struct {
    uint64_t unique;
} fuse_interrupt_in_t;

typedef struct {
    uint32_t count;
    uint32_t dummy;
} fuse_batch_forget_in_t;

typedef struct {
    uint64_t nodeid;
    uint64_t nlookup;
} fuse_forget_one_t;

typedef struct {
    uint32_t major;
    uint32_t minor;
    uint32_t max_readahead;
    uint32_t flags;
    uint32_t flags2;
    uint32_t unused[11];
} fuse_init_in_t;

typedef struct {
    uint32_t major;
    uint32_t minor;
    uint32_t max_readahead;
    uint32_t flags;
    uint16_t max_background;
    uint16_t congestion_threshold;
    uint32_t max_write;
    uint32_t time_gran;
    uint16_t max_pages;
    uint16_t map_alignment;
    uint32_t flags2;
    uint32_t max_stack_depth;
    uint16_t request_timeout;
    uint16_t unused[11];
} fuse_init_out_t;

typedef struct {
    uint32_t len;
    uint32_t opcode;
    uint64_t unique;
    uint64_t nodeid;
    uint32_t uid;
    uint32_t gid;
    uint32_t pid;
    uint16_t total_extlen;
    uint16_t padding;
} fuse_in_header_t;

typedef struct {
    uint32_t len;
    int32_t error;
    uint64_t unique;
} fuse_out_header_t;

typedef struct {
    uint64_t ino;
    uint64_t off;
    uint32_t namelen;
    uint32_t type;
    char name[];
} fuse_dirent_t;

#define FUSE_REC_ALIGN(x) \
    (((x) + sizeof(uint64_t) - 1) & ~(sizeof(uint64_t) - 1))
#define FUSE_NAME_OFFSET offsetof(fuse_dirent_t, name)
#define FUSE_DIRENT_SIZE_RAW(namelen) \
    FUSE_REC_ALIGN(FUSE_NAME_OFFSET + (namelen))

#define FUSE_MAX_SESSIONS 8
#define FUSE_MAX_MOUNTS 8
#define FUSE_MAX_OPEN_FILES 128
#define FUSE_MAX_PENDING 128
/* Per-session capacity for held lookup references. Sized for recursive
 * directory walks (ls -R style) without pushing the per-session struct into
 * multi-page territory; node_refs at this cap is ~96 KiB, kept off the stack.
 * Beyond this, fuse_lookup_locked() emits a compensating FORGET to keep the
 * daemon balanced instead of leaking a reference.
 */
#define FUSE_MAX_NODE_REFS 4096
#define FUSE_FAKE_DEV 0xF00D

/* Implementation ceiling for a single FUSE frame (header + payload). The kernel
 * FUSE protocol caps a READ or WRITE payload at FUSE_MAX_PAGES * page_size = ~1
 * MiB by default and up to 4 MiB under recent kernels. The 8 MiB hard cap below
 * leaves headroom for the FUSE header, in-band sub-headers, and any future
 * readahead growth while still bounding the largest single malloc the daemon
 * can force. Daemon-negotiated max_write is clamped to (FUSE_FRAME_CAP
 * - sizeof(fuse_in_header_t) - sizeof(fuse_write_in)) at FUSE_INIT time so the
 * read-reply path cannot negotiate a size larger than fuse_dev_write will
 * accept.
 */
#define FUSE_FRAME_CAP ((size_t) (8 * 1024 * 1024))
#define FUSE_MAX_NEGOTIATED_WRITE ((uint32_t) (FUSE_FRAME_CAP - 256))

typedef struct fuse_request {
    bool used;
    bool answered;
    bool no_reply;
    bool detached;
    bool interrupt_sent;
    uint64_t unique;
    uint8_t *frame;
    size_t frame_len;
    uint8_t *reply;
    size_t reply_len;
    int error;
    pthread_cond_t cond;
    struct fuse_request *next;
} fuse_request_t;

typedef struct {
    bool used;
    int guest_fd;
    int refcount;
    pthread_mutex_t lock;
    pthread_cond_t queue_cond;
    pthread_cond_t init_cond;
    bool closed;
    bool daemon_dead;
    bool init_done;
    int notify_wr;
    uint32_t max_write;
    uint16_t max_pages;
    uint64_t next_unique;
    fuse_request_t requests[FUSE_MAX_PENDING];
    fuse_request_t *queue_head;
    fuse_request_t *queue_tail;
    struct {
        bool used;
        uint64_t nodeid;
        uint64_t nlookup;
    } node_refs[FUSE_MAX_NODE_REFS];
} fuse_session_t;

typedef struct {
    bool used;
    char path[LINUX_PATH_MAX];
    char source[256];
    char fstype[16];
    int mount_id;
    /* session is the live transport for this mount; NULL once the owning
     * /dev/fuse fd is closed (the slot is tombstoned, keeping path/source/
     * fstype/mount_id intact so consumers stuck on this mount path can be
     * routed to a deterministic -LINUX_ENOTCONN instead of leaking through to
     * host-filesystem resolution). Re-binding the slot requires
     * fuse_alloc_mount_locked or sys_mount replacing a tombstoned entry.
     */
    fuse_session_t *session;
} fuse_mount_t;

typedef struct {
    bool used;
    /* refcount keeps the slot alive while any thread holds a snapshot or does
     * an in-flight FUSE request against this fd. 1 = held by the underlying
     * open fd; +1 per in-flight op acquired via fuse_file_get_locked. The slot
     * is zeroed only when refcount hits 0 so a concurrent close cannot pull the
     * io_cond out from under a waiting reader.
     */
    int refcount;
    int guest_fd;
    bool dir;
    uint64_t nodeid;
    uint64_t fh;
    uint64_t offset;
    int linux_flags;
    bool path_only;
    /* session is pinned by the file's own session ref taken at open time. The
     * mount slot the file came from may be reassigned independently; mount_id
     * is the stable identifier used to detect that case without dereferencing a
     * possibly-recycled fuse_mount_t.
     */
    fuse_session_t *session;
    int mount_id;
    char path[LINUX_PATH_MAX];
    fuse_attr_t attr;
    /* Serialize stream read() / readdir() against the offset field. lseek also
     * waits on io_in_progress to avoid clobbering an in-flight read's
     * post-update.
     */
    bool io_in_progress;
    pthread_cond_t io_cond;
} fuse_file_t;

typedef struct {
    bool used;
    int guest_fd;
    fuse_session_t *session;
} fuse_dev_binding_t;

typedef struct {
    bool used;
    int guest_fd;
    fuse_file_t *file;
} fuse_file_binding_t;

static pthread_mutex_t fuse_lock = PTHREAD_MUTEX_INITIALIZER;
static fuse_session_t fuse_sessions[FUSE_MAX_SESSIONS];
static fuse_mount_t fuse_mounts[FUSE_MAX_MOUNTS];
static fuse_file_t fuse_files[FUSE_MAX_OPEN_FILES];
static fuse_dev_binding_t fuse_dev_bindings[FD_TABLE_SIZE];
static fuse_file_binding_t fuse_file_bindings[FD_TABLE_SIZE];
static int fuse_next_mount_id = 100;

static const char *skip_slashes(const char *s)
{
    while (s && *s == '/')
        s++;
    return s;
}

static void trim_mount_path(char *path)
{
    size_t len = strlen(path);
    while (len > 1 && path[len - 1] == '/') {
        path[len - 1] = '\0';
        len--;
    }
}

static bool path_component_boundary(const char *base, const char *path)
{
    size_t len = strlen(base);
    return !strncmp(base, path, len) && (path[len] == '\0' || path[len] == '/');
}

static int fuse_join_virtual_path(const char *base,
                                  const char *path,
                                  char *out,
                                  size_t outsz)
{
    if (!base || !path || !out || outsz == 0 || base[0] != '/') {
        errno = EINVAL;
        return -1;
    }

    size_t depth = 0;
    /* marks[i] stores the output index at which the i-th surviving component
     * begins. Each value is bounded by outsz (capped at LINUX_PATH_MAX = 4096),
     * so uint16_t is sufficient and shrinks the host-stack footprint from 16
     * KiB to 4 KiB per call.
     */
    uint16_t marks[LINUX_PATH_MAX / 2];
    out[0] = '/';
    out[1] = '\0';

    const char *segments[2] = {base, path};
    for (size_t seg = 0; seg < ARRAY_SIZE(segments); seg++) {
        const char *cur = segments[seg];
        while (*cur) {
            while (*cur == '/')
                cur++;
            if (*cur == '\0')
                break;
            const char *start = cur;
            while (*cur && *cur != '/')
                cur++;
            size_t len = (size_t) (cur - start);
            if (len == 1 && start[0] == '.')
                continue;
            if (len == 2 && start[0] == '.' && start[1] == '.') {
                if (depth > 0) {
                    out[marks[--depth]] = '\0';
                    if (out[0] == '\0') {
                        out[0] = '/';
                        out[1] = '\0';
                    }
                }
                continue;
            }

            size_t cur_len = strlen(out);
            size_t prefix_len = cur_len;
            size_t needed = cur_len + len + 1;
            if (cur_len > 1)
                needed++;
            if (needed > outsz || depth >= ARRAY_SIZE(marks) ||
                prefix_len > UINT16_MAX) {
                errno = ENAMETOOLONG;
                return -1;
            }
            if (cur_len > 1)
                out[cur_len++] = '/';
            else
                cur_len = 1;
            memcpy(out + cur_len, start, len);
            cur_len += len;
            out[cur_len] = '\0';
            marks[depth++] = (uint16_t) (prefix_len > 1 ? prefix_len : 1);
        }
    }

    if (out[0] == '\0') {
        out[0] = '/';
        out[1] = '\0';
    }
    return 0;
}

/* Canonicalize an absolute guest path, collapsing "." and ".." against the
 * filesystem root.
 *
 * Returns 0 on success with the canonical form written to out, or -1 (errno
 * set) on overflow. Always overwrites out on success. Callers use this before
 * mount-prefix matching so paths like "/mnt/fuse/./foo" and
 * "/mnt/fuse/sub/../foo" route consistently with "/mnt/fuse/foo" and paths like
 * "/mnt/fuse/../etc" escape FUSE land deterministically.
 */
static int fuse_canonical_abs(const char *in, char *out, size_t outsz)
{
    return fuse_join_virtual_path("/", in, out, outsz);
}

static fuse_session_t *fuse_session_by_fd_locked(int guest_fd)
{
    for (int i = 0; i < FD_TABLE_SIZE; i++) {
        if (fuse_dev_bindings[i].used &&
            fuse_dev_bindings[i].guest_fd == guest_fd)
            return fuse_dev_bindings[i].session;
    }
    return NULL;
}

static int fuse_bind_dev_fd_locked(int guest_fd, fuse_session_t *session)
{
    for (int i = 0; i < FD_TABLE_SIZE; i++) {
        if (!fuse_dev_bindings[i].used) {
            fuse_dev_bindings[i].used = true;
            fuse_dev_bindings[i].guest_fd = guest_fd;
            fuse_dev_bindings[i].session = session;
            return 0;
        }
    }
    errno = EMFILE;
    return -1;
}

static fuse_session_t *fuse_unbind_dev_fd_locked(int guest_fd)
{
    for (int i = 0; i < FD_TABLE_SIZE; i++) {
        if (fuse_dev_bindings[i].used &&
            fuse_dev_bindings[i].guest_fd == guest_fd) {
            fuse_session_t *session = fuse_dev_bindings[i].session;
            memset(&fuse_dev_bindings[i], 0, sizeof(fuse_dev_bindings[i]));
            return session;
        }
    }
    return NULL;
}

static int fuse_dev_alias_count_locked(fuse_session_t *session)
{
    int count = 0;
    for (int i = 0; i < FD_TABLE_SIZE; i++) {
        if (fuse_dev_bindings[i].used &&
            fuse_dev_bindings[i].session == session)
            count++;
    }
    return count;
}

/* Bump session reference under fuse_lock. Each live mount, each FUSE-backed
 * file fd, and the /dev/fuse fd itself hold one ref. Destruction is deferred
 * until refcount drops to zero so a slow read/write on a mount-backed fd cannot
 * race with the daemon closing /dev/fuse and tearing down the lock.
 */
static void fuse_session_get_locked(fuse_session_t *session)
{
    session->refcount++;
}

/* Drop a session reference under fuse_lock. When the last reference is dropped
 * and the session has been closed, destroy the synchronization primitives and
 * clear the slot. Callers must not hold session->lock.
 *
 * The /dev/fuse fd is itself one of the session's refs (taken when the fd is
 * allocated, dropped in fuse_fd_cleanup), so the only path that can drive
 * refcount to zero runs through fuse_fd_cleanup setting session->closed = true
 * and session->daemon_dead = true before its matching put. Any residual
 * node_refs entries at this point therefore cannot reach the daemon --
 * fuse_emit_forget_multi_locked short- circuits on daemon_dead -- so no
 * terminal FUSE_FORGET sweep is emitted here. The compensating FORGET paths
 * elsewhere in this file (fuse_lookup_locked overflow, fuse_walk_path_locked
 * mid-walk drop failure, fuse_open_path error exits) keep the daemon's nlookup
 * view balanced while the daemon is still alive; teardown after the daemon's
 * exit needs no further reconciliation.
 */
static void fuse_session_put_locked(fuse_session_t *session)
{
    if (--session->refcount > 0)
        return;
    if (session->notify_wr >= 0)
        close(session->notify_wr);
    pthread_mutex_destroy(&session->lock);
    pthread_cond_destroy(&session->queue_cond);
    pthread_cond_destroy(&session->init_cond);
    memset(session, 0, sizeof(*session));
}

static void fuse_notify_readable_locked(fuse_session_t *session)
{
    if (session->notify_wr < 0)
        return;
    uint8_t byte = 1;
    write(session->notify_wr, &byte, 1);
}

static void fuse_notify_drain_fd_locked(int fd)
{
    if (fd < 0)
        return;
    uint8_t byte;
    while (read(fd, &byte, 1) > 0)
        ;
}

static fuse_mount_t *fuse_mount_for_path_locked(const char *path,
                                                const char **relpath_out)
{
    fuse_mount_t *best = NULL;
    size_t best_len = 0;
    for (int i = 0; i < FUSE_MAX_MOUNTS; i++) {
        if (!fuse_mounts[i].used)
            continue;
        size_t len = strlen(fuse_mounts[i].path);
        if (len < best_len ||
            !path_component_boundary(fuse_mounts[i].path, path))
            continue;
        best = &fuse_mounts[i];
        best_len = len;
    }
    if (best && relpath_out) {
        const char *rel = path + best_len;
        if (*rel == '/')
            rel++;
        *relpath_out = rel;
    }
    return best;
}

/* Fully free a mount slot. Drops any live session ref (tombstoned slots have
 * NULL session and have already dropped their ref via fuse_fd_cleanup). Used by
 * sys_mount error paths and by fuse_alloc_mount_locked when reclaiming a
 * tombstoned slot.
 */
static void fuse_uninstall_mount_locked(fuse_mount_t *mount)
{
    if (!mount || !mount->used)
        return;
    if (mount->session)
        fuse_session_put_locked(mount->session);
    memset(mount, 0, sizeof(*mount));
}

/* Allocate a mount slot, preferring fully-free entries. If none are free,
 * reclaim the first tombstoned slot (used==true with session==NULL).
 * Returns NULL when no slot is available even after tombstone reclamation.
 */
static fuse_mount_t *fuse_alloc_mount_locked(void)
{
    for (int i = 0; i < FUSE_MAX_MOUNTS; i++) {
        if (!fuse_mounts[i].used) {
            memset(&fuse_mounts[i], 0, sizeof(fuse_mounts[i]));
            fuse_mounts[i].used = true;
            return &fuse_mounts[i];
        }
    }
    for (int i = 0; i < FUSE_MAX_MOUNTS; i++) {
        if (fuse_mounts[i].used && fuse_mounts[i].session == NULL) {
            fuse_uninstall_mount_locked(&fuse_mounts[i]);
            memset(&fuse_mounts[i], 0, sizeof(fuse_mounts[i]));
            fuse_mounts[i].used = true;
            return &fuse_mounts[i];
        }
    }
    return NULL;
}

static void fuse_fill_stat_from_attr(const fuse_attr_t *attr, struct stat *st)
{
    memset(st, 0, sizeof(*st));
    st->st_dev = (dev_t) FUSE_FAKE_DEV;
    st->st_ino = (ino_t) attr->ino;
    st->st_mode = (mode_t) attr->mode;
    st->st_nlink = attr->nlink;
    st->st_uid = attr->uid;
    st->st_gid = attr->gid;
    st->st_rdev = attr->rdev;
    st->st_size = (off_t) attr->size;
    st->st_blocks = (blkcnt_t) attr->blocks;
    st->st_blksize = (blksize_t) (attr->blksize ? attr->blksize : 4096);
    st->st_atimespec.tv_sec = (time_t) attr->atime;
    st->st_atimespec.tv_nsec = attr->atimensec;
    st->st_mtimespec.tv_sec = (time_t) attr->mtime;
    st->st_mtimespec.tv_nsec = attr->mtimensec;
    st->st_ctimespec.tv_sec = (time_t) attr->ctime;
    st->st_ctimespec.tv_nsec = attr->ctimensec;
}

static fuse_request_t *fuse_alloc_request_locked(fuse_session_t *session)
{
    for (int i = 0; i < FUSE_MAX_PENDING; i++) {
        if (!session->requests[i].used) {
            memset(&session->requests[i], 0, sizeof(session->requests[i]));
            session->requests[i].used = true;
            pthread_cond_init(&session->requests[i].cond, NULL);
            return &session->requests[i];
        }
    }
    return NULL;
}

static int fuse_node_ref_hold_locked(fuse_session_t *session,
                                     uint64_t nodeid,
                                     uint64_t nlookup)
{
    if (nodeid == FUSE_ROOT_ID || nlookup == 0)
        return 0;
    for (int i = 0; i < FUSE_MAX_NODE_REFS; i++) {
        if (session->node_refs[i].used &&
            session->node_refs[i].nodeid == nodeid) {
            session->node_refs[i].nlookup += nlookup;
            return 0;
        }
    }
    for (int i = 0; i < FUSE_MAX_NODE_REFS; i++) {
        if (!session->node_refs[i].used) {
            session->node_refs[i].used = true;
            session->node_refs[i].nodeid = nodeid;
            session->node_refs[i].nlookup = nlookup;
            return 0;
        }
    }
    return -LINUX_ENOMEM;
}

static int fuse_queue_noreply_locked(fuse_session_t *session,
                                     uint32_t opcode,
                                     uint64_t nodeid,
                                     const void *payload,
                                     size_t payload_len);
static void fuse_free_request_locked(fuse_request_t *req);

static int fuse_emit_forget_multi_locked(fuse_session_t *session,
                                         const fuse_forget_one_t *items,
                                         uint32_t count)
{
    if (!session || session->closed || session->daemon_dead || count == 0)
        return 0;
    if (count == 1) {
        fuse_forget_in_t in = {.nlookup = items[0].nlookup};
        return fuse_queue_noreply_locked(session, FUSE_FORGET, items[0].nodeid,
                                         &in, sizeof(in));
    }

    size_t payload_len =
        sizeof(fuse_batch_forget_in_t) + count * sizeof(fuse_forget_one_t);
    uint8_t *payload = calloc(1, payload_len);
    if (!payload)
        return -LINUX_ENOMEM;

    fuse_batch_forget_in_t *hdr = (fuse_batch_forget_in_t *) payload;
    hdr->count = count;
    memcpy(payload + sizeof(*hdr), items, count * sizeof(*items));
    int rc = fuse_queue_noreply_locked(session, FUSE_BATCH_FORGET, 0, payload,
                                       payload_len);
    free(payload);
    return rc;
}

static int fuse_node_ref_drop_locked(fuse_session_t *session,
                                     uint64_t nodeid,
                                     uint64_t nlookup,
                                     bool emit_forget)
{
    if (nodeid == FUSE_ROOT_ID || nlookup == 0)
        return 0;
    for (int i = 0; i < FUSE_MAX_NODE_REFS; i++) {
        if (!session->node_refs[i].used ||
            session->node_refs[i].nodeid != nodeid)
            continue;
        if (nlookup >= session->node_refs[i].nlookup) {
            nlookup = session->node_refs[i].nlookup;
            memset(&session->node_refs[i], 0, sizeof(session->node_refs[i]));
        } else {
            session->node_refs[i].nlookup -= nlookup;
        }
        if (!emit_forget)
            return 0;
        fuse_forget_one_t one = {.nodeid = nodeid, .nlookup = nlookup};
        return fuse_emit_forget_multi_locked(session, &one, 1);
    }
    return 0;
}

static int fuse_queue_request_locked(fuse_session_t *session,
                                     uint32_t opcode,
                                     uint64_t nodeid,
                                     const void *payload,
                                     size_t payload_len,
                                     bool no_reply,
                                     fuse_request_t **req_out)
{
    fuse_request_t *req = fuse_alloc_request_locked(session);
    if (!req)
        return -LINUX_ENOMEM;

    req->no_reply = no_reply;
    req->unique = session->next_unique++;
    req->frame_len = sizeof(fuse_in_header_t) + payload_len;
    req->frame = calloc(1, req->frame_len);
    if (!req->frame) {
        fuse_free_request_locked(req);
        return -LINUX_ENOMEM;
    }

    fuse_in_header_t *hdr = (fuse_in_header_t *) req->frame;
    hdr->len = (uint32_t) req->frame_len;
    hdr->opcode = opcode;
    hdr->unique = req->unique;
    hdr->nodeid = nodeid;
    hdr->uid = proc_get_uid();
    hdr->gid = proc_get_gid();
    hdr->pid = (uint32_t) proc_get_pid();
    if (payload_len)
        memcpy(req->frame + sizeof(*hdr), payload, payload_len);

    bool was_empty = session->queue_head == NULL;
    if (session->queue_tail)
        session->queue_tail->next = req;
    else
        session->queue_head = req;
    session->queue_tail = req;
    if (was_empty)
        fuse_notify_readable_locked(session);
    pthread_cond_broadcast(&session->queue_cond);
    if (req_out)
        *req_out = req;
    return 0;
}

static int fuse_queue_noreply_locked(fuse_session_t *session,
                                     uint32_t opcode,
                                     uint64_t nodeid,
                                     const void *payload,
                                     size_t payload_len)
{
    return fuse_queue_request_locked(session, opcode, nodeid, payload,
                                     payload_len, true, NULL);
}

static void fuse_free_request_locked(fuse_request_t *req)
{
    pthread_cond_destroy(&req->cond);
    free(req->frame);
    free(req->reply);
    memset(req, 0, sizeof(*req));
}

static int fuse_wait_for_init_locked(fuse_session_t *session)
{
    while (!session->closed && !session->daemon_dead && !session->init_done)
        pthread_cond_wait(&session->init_cond, &session->lock);
    if (session->closed || session->daemon_dead)
        return -LINUX_ENOTCONN;
    return 0;
}

static int fuse_request_locked(fuse_session_t *session,
                               uint32_t opcode,
                               uint64_t nodeid,
                               const void *payload,
                               size_t payload_len,
                               uint8_t **reply_out,
                               size_t *reply_len_out);

static int fuse_send_init_locked(fuse_session_t *session)
{
    fuse_init_in_t init = {
        .major = FUSE_KERNEL_VERSION,
        .minor = FUSE_KERNEL_MINOR_VERSION,
        .max_readahead = 1024 * 1024,
        .flags = FUSE_ASYNC_READ | FUSE_BIG_WRITES | FUSE_MAX_PAGES,
    };
    return fuse_request_locked(session, FUSE_INIT, FUSE_ROOT_ID, &init,
                               sizeof(init), NULL, NULL);
}

/* Issue one FUSE request and wait for the reply.
 *
 * Returns 0 on success, or a negative Linux errno on failure. The caller must
 * hold session->lock.
 *
 * Known limitation: the wait uses a plain pthread_cond_wait, so a signal
 * delivered to a blocked consumer does not return -EINTR and does not emit a
 * FUSE_INTERRUPT frame to the daemon. Honoring SA_RESTART and emitting
 * FUSE_INTERRUPT requires integrating with the per-thread signal eventfd and
 * remains a deferred compatibility item. Until then, daemon death or session
 * close are the only paths that wake a blocked consumer.
 */
static int fuse_request_locked(fuse_session_t *session,
                               uint32_t opcode,
                               uint64_t nodeid,
                               const void *payload,
                               size_t payload_len,
                               uint8_t **reply_out,
                               size_t *reply_len_out)
{
    if (!session->init_done && opcode != FUSE_INIT) {
        int init_rc = fuse_wait_for_init_locked(session);
        if (init_rc < 0)
            return init_rc;
    }
    if (session->closed || session->daemon_dead)
        return -LINUX_ENOTCONN;

    fuse_request_t *req = NULL;
    int qrc = fuse_queue_request_locked(session, opcode, nodeid, payload,
                                        payload_len, false, &req);
    if (qrc < 0)
        return qrc;

    while (!req->answered && !session->closed && !session->daemon_dead) {
        struct timespec ts;
        timespec_deadline_in_ms(&ts, 20);
        int wait_rc = pthread_cond_timedwait(&req->cond, &session->lock, &ts);
        if (!req->answered && wait_rc == ETIMEDOUT) {
            /* Only detach for non-restartable signals. SA_RESTART signals are
             * delivered after the syscall completes naturally; breaking out
             * here would force the guest to retry a request whose handler
             * contract says no retry is necessary, and would emit a useless
             * FUSE_INTERRUPT to the daemon for work the guest still wants.
             */
            bool restart = false;
            if (signal_pending_interruption(&restart) && !restart) {
                if (!req->interrupt_sent) {
                    fuse_interrupt_in_t in = {.unique = req->unique};
                    (void) fuse_queue_noreply_locked(session, FUSE_INTERRUPT, 0,
                                                     &in, sizeof(in));
                    req->interrupt_sent = true;
                }
                req->detached = true;
                return -LINUX_EINTR;
            }
        }
    }

    int rc = 0;
    if (req->answered) {
        if (req->error < 0)
            rc = req->error;
    } else if (session->closed || session->daemon_dead) {
        rc = -LINUX_ENOTCONN;
    }

    if (rc == 0 && reply_out && reply_len_out) {
        *reply_len_out = req->reply_len;
        *reply_out = NULL;
        if (req->reply_len) {
            *reply_out = malloc(req->reply_len);
            if (!*reply_out)
                rc = -LINUX_ENOMEM;
            else
                memcpy(*reply_out, req->reply, req->reply_len);
        }
    }

    if (req->detached)
        return rc;
    fuse_free_request_locked(req);
    return rc;
}

static int fuse_lookup_locked(fuse_session_t *session,
                              uint64_t parent,
                              const char *name,
                              fuse_entry_out_t *out)
{
    uint8_t *reply = NULL;
    size_t reply_len = 0;
    int rc = fuse_request_locked(session, FUSE_LOOKUP, parent, name,
                                 strlen(name) + 1, &reply, &reply_len);
    if (rc < 0)
        return rc;
    if (reply_len < sizeof(*out)) {
        free(reply);
        return -LINUX_EPROTO;
    }
    memcpy(out, reply, sizeof(*out));
    free(reply);
    int hold_rc = fuse_node_ref_hold_locked(session, out->nodeid, 1);
    if (hold_rc < 0) {
        /* Daemon already accepted the lookup and bumped its nlookup. The
         * per-session ref table is full, so emit a compensating FORGET to keep
         * the daemon's view balanced rather than leaking a reference.
         */
        fuse_forget_one_t one = {.nodeid = out->nodeid, .nlookup = 1};
        (void) fuse_emit_forget_multi_locked(session, &one, 1);
    }
    return hold_rc;
}

static int fuse_getattr_locked(fuse_session_t *session,
                               uint64_t nodeid,
                               fuse_attr_t *attr)
{
    uint8_t *reply = NULL;
    size_t reply_len = 0;
    int rc = fuse_request_locked(session, FUSE_GETATTR, nodeid, NULL, 0, &reply,
                                 &reply_len);
    if (rc < 0)
        return rc;
    if (reply_len < sizeof(fuse_attr_out_t)) {
        free(reply);
        return -LINUX_EPROTO;
    }
    fuse_attr_out_t out;
    memcpy(&out, reply, sizeof(out));
    *attr = out.attr;
    free(reply);
    return 0;
}

static int fuse_walk_path_locked(fuse_session_t *session,
                                 const char *relpath,
                                 bool retain_final_lookup,
                                 uint64_t *nodeid_out,
                                 fuse_attr_t *attr_out)
{
    uint64_t nodeid = FUSE_ROOT_ID;
    fuse_attr_t attr = {0};
    uint64_t held_lookup = 0;
    const char *p = skip_slashes(relpath);

    if (*p == '\0') {
        int rc = fuse_getattr_locked(session, nodeid, &attr);
        if (rc < 0)
            return rc;
        *nodeid_out = nodeid;
        if (attr_out)
            *attr_out = attr;
        return 0;
    }

    while (*p) {
        const char *slash = strchr(p, '/');
        size_t len = slash ? (size_t) (slash - p) : strlen(p);
        char name[LINUX_PATH_MAX];
        if (len == 0 || len >= sizeof(name))
            return -LINUX_ENOENT;
        memcpy(name, p, len);
        name[len] = '\0';
        /* The path is canonicalized before reaching the walk, so "." and ".."
         * should never appear as a real component. Defend against accidental
         * forwarding to the daemon (which has no notion of the mount root's
         * containment) just in case a future caller skips canonicalization. The
         * advance-then-continue order matters: a bare "continue" without
         * advancing p would spin on the same component forever if a
         * non-canonical path ever reached here.
         */
        if (len == 1 && name[0] == '.') {
            if (!slash)
                break;
            p = skip_slashes(slash);
            continue;
        }
        if (len == 2 && name[0] == '.' && name[1] == '.')
            return -LINUX_ENOENT;

        fuse_entry_out_t entry;
        int rc = fuse_lookup_locked(session, nodeid, name, &entry);
        if (rc < 0) {
            /* Release the lookup hold from the previous component before
             * propagating the error: every successful lookup along the way
             * incremented nlookup on the daemon side, and bailing out without a
             * matching FORGET would leak that reference.
             */
            if (held_lookup != 0)
                (void) fuse_node_ref_drop_locked(session, held_lookup, 1, true);
            return rc;
        }
        if (held_lookup != 0) {
            rc = fuse_node_ref_drop_locked(session, held_lookup, 1, true);
            if (rc < 0) {
                /* The previous component's drop already updated the local ref
                 * table but failed to queue its FUSE_FORGET. The just-acquired
                 * entry.nodeid hold would otherwise be stranded in the local
                 * table on this error path and the daemon would never see a
                 * matching FORGET for it. Drop the new hold best-effort before
                 * propagating; if this second drop also fails to emit, the
                 * caller still gets the original error and the session teardown
                 * FORGET sweep will reconcile any residual daemon-side count.
                 */
                (void) fuse_node_ref_drop_locked(session, entry.nodeid, 1,
                                                 true);
                return rc;
            }
        }
        nodeid = entry.nodeid;
        attr = entry.attr;
        held_lookup = entry.nodeid;
        if (!slash)
            break;
        p = skip_slashes(slash);
    }

    if (!retain_final_lookup && held_lookup != 0) {
        int rc = fuse_node_ref_drop_locked(session, held_lookup, 1, true);
        if (rc < 0)
            return rc;
    }

    *nodeid_out = nodeid;
    if (attr_out)
        *attr_out = attr;
    return 0;
}

static fuse_file_t *fuse_file_by_fd_locked(int guest_fd)
{
    for (int i = 0; i < FD_TABLE_SIZE; i++) {
        if (fuse_file_bindings[i].used &&
            fuse_file_bindings[i].guest_fd == guest_fd)
            return fuse_file_bindings[i].file;
    }
    return NULL;
}

static int fuse_bind_file_fd_locked(int guest_fd, fuse_file_t *file)
{
    for (int i = 0; i < FD_TABLE_SIZE; i++) {
        if (!fuse_file_bindings[i].used) {
            fuse_file_bindings[i].used = true;
            fuse_file_bindings[i].guest_fd = guest_fd;
            fuse_file_bindings[i].file = file;
            return 0;
        }
    }
    errno = EMFILE;
    return -1;
}

static fuse_file_t *fuse_unbind_file_fd_locked(int guest_fd)
{
    for (int i = 0; i < FD_TABLE_SIZE; i++) {
        if (fuse_file_bindings[i].used &&
            fuse_file_bindings[i].guest_fd == guest_fd) {
            fuse_file_t *file = fuse_file_bindings[i].file;
            memset(&fuse_file_bindings[i], 0, sizeof(fuse_file_bindings[i]));
            return file;
        }
    }
    return NULL;
}

static int fuse_file_alias_count_locked(fuse_file_t *file)
{
    int count = 0;
    for (int i = 0; i < FD_TABLE_SIZE; i++) {
        if (fuse_file_bindings[i].used && fuse_file_bindings[i].file == file)
            count++;
    }
    return count;
}

/* Bump file slot refcount. Holder must release via fuse_file_put_locked. */
static void fuse_file_get_locked(fuse_file_t *file)
{
    file->refcount++;
}

/* Drop a file slot refcount under fuse_lock. The slot is destroyed and cleared
 * only when no one else holds a reference, so a concurrent close cannot tear
 * down io_cond out from under a thread that has already snapshotted this slot.
 */
static void fuse_file_put_locked(fuse_file_t *file)
{
    if (--file->refcount > 0)
        return;
    if (file->session)
        fuse_session_put_locked(file->session);
    pthread_cond_destroy(&file->io_cond);
    memset(file, 0, sizeof(*file));
}

static fuse_file_t *fuse_alloc_file_locked(void)
{
    for (int i = 0; i < FUSE_MAX_OPEN_FILES; i++) {
        /* A slot with refcount > 0 is still owned by an in-flight op even if
         * its underlying fd has been closed; skip it until that op releases.
         * used==false && refcount==0 is the only fully-free state.
         */
        if (!fuse_files[i].used && fuse_files[i].refcount == 0) {
            memset(&fuse_files[i], 0, sizeof(fuse_files[i]));
            fuse_files[i].used = true;
            fuse_files[i].refcount = 1; /* held by the open fd */
            pthread_cond_init(&fuse_files[i].io_cond, NULL);
            return &fuse_files[i];
        }
    }
    return NULL;
}

static int fuse_open_common_locked(fuse_session_t *session,
                                   uint64_t nodeid,
                                   int linux_flags,
                                   bool dir,
                                   fuse_open_out_t *out)
{
    fuse_open_in_t in = {.flags = (uint32_t) linux_flags};
    uint8_t *reply = NULL;
    size_t reply_len = 0;
    int rc = fuse_request_locked(session, dir ? FUSE_OPENDIR : FUSE_OPEN,
                                 nodeid, &in, sizeof(in), &reply, &reply_len);
    if (rc < 0)
        return rc;
    if (reply_len < sizeof(*out)) {
        free(reply);
        return -LINUX_EPROTO;
    }
    memcpy(out, reply, sizeof(*out));
    free(reply);
    return 0;
}

/* Emit FUSE_RELEASE / FUSE_RELEASEDIR for a file snapshot. session must be
 * non-NULL and pinned by the caller; if the daemon has died the request is
 * skipped silently.
 */
static int fuse_release_common_locked(fuse_session_t *session,
                                      bool dir,
                                      uint64_t nodeid,
                                      uint64_t fh,
                                      int linux_flags)
{
    if (!session || session->daemon_dead || session->closed)
        return 0;
    /* O_PATH opens skip FUSE_OPEN, so there is no fh to release. The path walk
     * still incremented the daemon's nlookup, so emit FORGET to balance it.
     * Without this, every successful O_PATH close leaks one reference.
     */
    if (linux_flags & LINUX_O_PATH)
        return fuse_node_ref_drop_locked(session, nodeid, 1, true);

    fuse_release_in_t in = {
        .fh = fh,
        .flags = (uint32_t) linux_flags,
    };
    int rc = fuse_request_locked(session, dir ? FUSE_RELEASEDIR : FUSE_RELEASE,
                                 nodeid, &in, sizeof(in), NULL, NULL);
    int forget_rc = fuse_node_ref_drop_locked(session, nodeid, 1, true);
    if (rc < 0)
        return rc;
    return forget_rc;
}

static void fuse_fd_cleanup(int guest_fd)
{
    /* Step 1: snapshot the file slot's release-relevant fields and detach the
     * slot from the fd. The slot itself stays alive (refcount > 0) until any
     * in-flight op releases its ref; only then is io_cond destroyed and the
     * slot zeroed.
     */
    fuse_session_t *file_session = NULL;
    bool have_file = false;
    bool file_dir = false;
    uint64_t file_nodeid = 0, file_fh = 0;
    int file_linux_flags = 0;

    pthread_mutex_lock(&fuse_lock);
    fuse_file_t *file = fuse_unbind_file_fd_locked(guest_fd);
    if (file) {
        file_session = file->session;
        file_dir = file->dir;
        file_nodeid = file->nodeid;
        file_fh = file->fh;
        file_linux_flags = file->linux_flags;
        have_file = true;
        bool final_alias = (fuse_file_alias_count_locked(file) == 0);
        if (final_alias) {
            /* Mark the slot logically closed but keep refcount intact so an
             * in-flight read sees io_cond / session through its existing snap.
             * fuse_file_put_locked decrements when those ops release.
             */
            file->used = false;
            pthread_cond_broadcast(&file->io_cond);
            fuse_session_get_locked(file_session);
        } else {
            have_file = false;
        }
        fuse_file_put_locked(file); /* drop this fd alias ref */
    }
    pthread_mutex_unlock(&fuse_lock);

    if (have_file && file_session) {
        pthread_mutex_lock(&file_session->lock);
        fuse_release_common_locked(file_session, file_dir, file_nodeid, file_fh,
                                   file_linux_flags);
        pthread_mutex_unlock(&file_session->lock);
        pthread_mutex_lock(&fuse_lock);
        fuse_session_put_locked(file_session);
        pthread_mutex_unlock(&fuse_lock);
    }

    pthread_mutex_lock(&fuse_lock);
    fuse_session_t *session = fuse_unbind_dev_fd_locked(guest_fd);
    if (!session) {
        pthread_mutex_unlock(&fuse_lock);
        return;
    }

    if (fuse_dev_alias_count_locked(session) > 0) {
        fuse_session_put_locked(session);
        pthread_mutex_unlock(&fuse_lock);
        return;
    }

    /* Mark dead and wake every blocked waiter under the session lock so they
     * see daemon_dead=true and exit with -LINUX_ENOTCONN before the lock itself
     * goes away.
     */
    pthread_mutex_lock(&session->lock);
    session->closed = true;
    session->daemon_dead = true;
    pthread_cond_broadcast(&session->queue_cond);
    pthread_cond_broadcast(&session->init_cond);
    for (int i = 0; i < FUSE_MAX_PENDING; i++) {
        if (session->requests[i].used) {
            if (session->requests[i].detached ||
                session->requests[i].no_reply) {
                fuse_free_request_locked(&session->requests[i]);
                continue;
            }
            session->requests[i].answered = true;
            session->requests[i].error = -LINUX_ENOTCONN;
            pthread_cond_broadcast(&session->requests[i].cond);
        }
    }
    pthread_mutex_unlock(&session->lock);

    /* Wake any file slots blocked on io_in_progress; their owners will see the
     * session's daemon_dead flag and exit with -LINUX_ENOTCONN.
     */
    for (int i = 0; i < FUSE_MAX_OPEN_FILES; i++) {
        if (fuse_files[i].used && fuse_files[i].session == session)
            pthread_cond_broadcast(&fuse_files[i].io_cond);
    }

    /* Tombstone each mount whose transport has just died: drop the per-mount
     * session ref but keep the slot's path/source/fstype/ mount_id intact so a
     * process whose virtual cwd is on this mount still routes to a
     * deterministic -LINUX_ENOTCONN instead of falling through to
     * host-filesystem resolution. session is cleared to NULL as the tombstone
     * marker; the slot is reclaimed by a later sys_mount at the same path or by
     * fuse_alloc_mount_locked.
     */
    for (int i = 0; i < FUSE_MAX_MOUNTS; i++) {
        if (fuse_mounts[i].used && fuse_mounts[i].session == session) {
            fuse_mounts[i].session = NULL;
            fuse_session_put_locked(session);
        }
    }

    /* Drop the /dev/fuse fd's own session ref. Destruction is deferred until
     * the last mount-backed fd closes.
     */
    fuse_session_put_locked(session);
    pthread_mutex_unlock(&fuse_lock);
}

void fuse_init(void)
{
    pthread_mutex_lock(&fuse_lock);
    memset(fuse_sessions, 0, sizeof(fuse_sessions));
    memset(fuse_mounts, 0, sizeof(fuse_mounts));
    memset(fuse_files, 0, sizeof(fuse_files));
    memset(fuse_dev_bindings, 0, sizeof(fuse_dev_bindings));
    memset(fuse_file_bindings, 0, sizeof(fuse_file_bindings));
    fuse_next_mount_id = 100;
    pthread_mutex_unlock(&fuse_lock);
    fd_register_cleanup(FD_FUSE_DEV, fuse_fd_cleanup);
    fd_register_cleanup(FD_FUSE_FILE, fuse_fd_cleanup);
    fd_register_cleanup(FD_FUSE_DIR, fuse_fd_cleanup);
}

int fuse_proc_open(int linux_flags)
{
    pthread_mutex_lock(&fuse_lock);
    fuse_session_t *slot = NULL;
    for (int i = 0; i < FUSE_MAX_SESSIONS; i++) {
        if (!fuse_sessions[i].used) {
            slot = &fuse_sessions[i];
            memset(slot, 0, sizeof(*slot));
            slot->used = true;
            slot->refcount = 1; /* held by the /dev/fuse fd itself */
            pthread_mutex_init(&slot->lock, NULL);
            pthread_cond_init(&slot->queue_cond, NULL);
            pthread_cond_init(&slot->init_cond, NULL);
            slot->notify_wr = -1;
            slot->max_write = 64 * 1024;
            slot->max_pages = 16;
            slot->next_unique = 1;
            break;
        }
    }
    pthread_mutex_unlock(&fuse_lock);
    if (!slot) {
        errno = EMFILE;
        return -1;
    }

    int notify_pipe[2];
    if (pipe(notify_pipe) < 0) {
        pthread_mutex_lock(&fuse_lock);
        fuse_session_put_locked(slot);
        pthread_mutex_unlock(&fuse_lock);
        return -1;
    }
    fcntl(notify_pipe[0], F_SETFL, O_NONBLOCK);
    fcntl(notify_pipe[1], F_SETFL, O_NONBLOCK);
    fcntl(notify_pipe[0], F_SETFD, FD_CLOEXEC);
    fcntl(notify_pipe[1], F_SETFD, FD_CLOEXEC);
    slot->notify_wr = notify_pipe[1];

    int guest_fd = fd_alloc(FD_FUSE_DEV, notify_pipe[0], fuse_fd_cleanup);
    if (guest_fd < 0) {
        close(notify_pipe[0]);
        pthread_mutex_lock(&fuse_lock);
        fuse_session_put_locked(slot);
        pthread_mutex_unlock(&fuse_lock);
        errno = EMFILE;
        return -1;
    }

    pthread_mutex_lock(&fuse_lock);
    slot->guest_fd = guest_fd;
    if (fuse_bind_dev_fd_locked(guest_fd, slot) < 0) {
        fuse_session_put_locked(slot);
        pthread_mutex_unlock(&fuse_lock);
        fd_mark_closed(guest_fd);
        errno = EMFILE;
        return -1;
    }
    pthread_mutex_unlock(&fuse_lock);
    /* Publish under fd_lock so the write is on the same lock domain as
     * sys_fcntl(F_SETFL/F_SETFD), not stranded behind fuse_lock.
     */
    fd_publish_linux_flags(guest_fd, linux_flags);
    return guest_fd;
}

int fuse_proc_stat(struct stat *st)
{
    memset(st, 0, sizeof(*st));
    st->st_mode = S_IFCHR | 0666;
    st->st_nlink = 1;
    st->st_dev = (dev_t) FUSE_FAKE_DEV;
    st->st_rdev = (dev_t) FUSE_FAKE_DEV;
    st->st_blksize = 4096;
    return 0;
}

static int parse_mount_fd(const char *data)
{
    const char *fdp = data ? strstr(data, "fd=") : NULL;
    if (!fdp)
        return -1;
    fdp += 3;
    char *endp;
    errno = 0;
    long fd = strtol(fdp, &endp, 10);
    /* Reject empty digit run, overflow, negative, and out-of-range fd values so
     * a malformed options string cannot smuggle in an integer that bypasses
     * later RANGE_CHECK gates.
     */
    if (endp == fdp || errno != 0 || fd < 0 || fd > INT_MAX)
        return -1;
    return (int) fd;
}

int64_t sys_mount(guest_t *g,
                  uint64_t source_gva,
                  uint64_t target_gva,
                  uint64_t fstype_gva,
                  unsigned long flags,
                  uint64_t data_gva)
{
    (void) source_gva;
    (void) flags;

    char target[LINUX_PATH_MAX];
    char source[256];
    char fstype[64];
    char data[LINUX_PATH_MAX];
    if (target_gva == 0 ||
        guest_read_str(g, target_gva, target, sizeof(target)) < 0 ||
        guest_read_str(g, fstype_gva, fstype, sizeof(fstype)) < 0)
        return -LINUX_EFAULT;
    if (source_gva) {
        if (guest_read_str(g, source_gva, source, sizeof(source)) < 0)
            return -LINUX_EFAULT;
    } else {
        str_copy_trunc(source, "fuse", sizeof(source));
    }
    if (data_gva && guest_read_str(g, data_gva, data, sizeof(data)) < 0)
        return -LINUX_EFAULT;
    if (!data_gva)
        data[0] = '\0';

    if (strcmp(fstype, "fuse") && strcmp(fstype, "fuseblk"))
        return -LINUX_ENODEV;
    if (target[0] != '/')
        return -LINUX_EINVAL;
    trim_mount_path(target);
    char target_canon[LINUX_PATH_MAX];
    if (fuse_canonical_abs(target, target_canon, sizeof(target_canon)) < 0)
        return -LINUX_ENAMETOOLONG;

    path_translation_t tx;
    if (path_translate_at(LINUX_AT_FDCWD, target_canon, PATH_TR_NONE, &tx) < 0)
        return linux_errno();

    struct stat st;
    if (stat(tx.host_path, &st) < 0)
        return linux_errno();
    if (!S_ISDIR(st.st_mode))
        return -LINUX_ENOTDIR;

    int fuse_fd = parse_mount_fd(data);
    if (fuse_fd < 0)
        return -LINUX_EINVAL;

    pthread_mutex_lock(&fuse_lock);
    fuse_session_t *session = fuse_session_by_fd_locked(fuse_fd);
    if (!session) {
        pthread_mutex_unlock(&fuse_lock);
        return -LINUX_EBADF;
    }
    for (int i = 0; i < FUSE_MAX_MOUNTS; i++) {
        if (fuse_mounts[i].used && fuse_mounts[i].session != NULL &&
            !strcmp(fuse_mounts[i].path, target_canon)) {
            /* Live mount at this path already; reject as EBUSY. A tombstoned
             * slot at the same path is reclaimed below.
             */
            pthread_mutex_unlock(&fuse_lock);
            return -LINUX_EBUSY;
        }
    }
    /* Prefer reclaiming a tombstoned slot at the same path so the mount_id
     * sequence stays stable for consumers that cached it.
     */
    fuse_mount_t *mount = NULL;
    for (int i = 0; i < FUSE_MAX_MOUNTS; i++) {
        if (fuse_mounts[i].used && fuse_mounts[i].session == NULL &&
            !strcmp(fuse_mounts[i].path, target_canon)) {
            fuse_uninstall_mount_locked(&fuse_mounts[i]);
            memset(&fuse_mounts[i], 0, sizeof(fuse_mounts[i]));
            fuse_mounts[i].used = true;
            mount = &fuse_mounts[i];
            break;
        }
    }
    if (!mount)
        mount = fuse_alloc_mount_locked();
    if (mount) {
        mount->session = session;
        fuse_session_get_locked(session);
        str_copy_trunc(mount->path, target_canon, sizeof(mount->path));
        str_copy_trunc(mount->source, source, sizeof(mount->source));
        str_copy_trunc(mount->fstype, fstype, sizeof(mount->fstype));
        mount->mount_id = fuse_next_mount_id++;
    }
    pthread_mutex_unlock(&fuse_lock);
    if (!mount)
        return -LINUX_ENOMEM;

    pthread_mutex_lock(&session->lock);
    int init_rc = fuse_send_init_locked(session);
    pthread_mutex_unlock(&session->lock);
    if (init_rc < 0) {
        pthread_mutex_lock(&fuse_lock);
        fuse_uninstall_mount_locked(mount);
        pthread_mutex_unlock(&fuse_lock);
        return init_rc;
    }
    return 0;
}

bool fuse_path_matches_mount(const char *path)
{
    if (!path || path[0] != '/')
        return false;
    char canon[LINUX_PATH_MAX];
    if (fuse_canonical_abs(path, canon, sizeof(canon)) < 0)
        return false;
    pthread_mutex_lock(&fuse_lock);
    /* Matches both live and tombstoned mounts so post-daemon-death operations
     * get routed to a deterministic -LINUX_ENOTCONN instead of silently falling
     * through to host-filesystem resolution.
     */
    bool matched = fuse_mount_for_path_locked(canon, NULL) != NULL;
    pthread_mutex_unlock(&fuse_lock);
    return matched;
}

int fuse_path_mount_id(const char *path)
{
    if (!path || path[0] != '/')
        return -1;
    char canon[LINUX_PATH_MAX];
    if (fuse_canonical_abs(path, canon, sizeof(canon)) < 0)
        return -1;
    pthread_mutex_lock(&fuse_lock);
    fuse_mount_t *m = fuse_mount_for_path_locked(canon, NULL);
    int id = m ? m->mount_id : -1;
    pthread_mutex_unlock(&fuse_lock);
    return id;
}

/* Resolve a guest-absolute path to a (session, mount_id, nodeid, attr).
 * retain_final_lookup controls whether the terminal LOOKUP's nlookup is kept
 * alive for a later open/release cycle, or forgotten before return for
 * stat-like callers.
 *
 * Returns 0 on success, or a negative Linux errno. The session refcount is
 * bumped on success; callers must drop it via fuse_session_put_locked when done
 * with the resolution.
 */
static int fuse_path_lookup(const char *path,
                            bool retain_final_lookup,
                            fuse_session_t **session_out,
                            int *mount_id_out,
                            uint64_t *nodeid_out,
                            fuse_attr_t *attr_out)
{
    char canon[LINUX_PATH_MAX];
    if (fuse_canonical_abs(path, canon, sizeof(canon)) < 0)
        return -LINUX_ENAMETOOLONG;

    pthread_mutex_lock(&fuse_lock);
    const char *relpath = NULL;
    fuse_mount_t *mount = fuse_mount_for_path_locked(canon, &relpath);
    if (!mount) {
        pthread_mutex_unlock(&fuse_lock);
        return -LINUX_ENOENT;
    }
    if (!mount->session) {
        /* Tombstoned mount: daemon dropped /dev/fuse already. */
        pthread_mutex_unlock(&fuse_lock);
        return -LINUX_ENOTCONN;
    }
    fuse_session_t *session = mount->session;
    int mount_id = mount->mount_id;
    fuse_session_get_locked(session);
    pthread_mutex_lock(&session->lock);
    pthread_mutex_unlock(&fuse_lock);

    bool keep_lookup = retain_final_lookup && session_out != NULL;
    int rc = fuse_walk_path_locked(session, relpath, keep_lookup, nodeid_out,
                                   attr_out);
    pthread_mutex_unlock(&session->lock);

    if (rc < 0) {
        pthread_mutex_lock(&fuse_lock);
        fuse_session_put_locked(session);
        pthread_mutex_unlock(&fuse_lock);
        return rc;
    }
    if (session_out)
        *session_out = session;
    else {
        pthread_mutex_lock(&fuse_lock);
        fuse_session_put_locked(session);
        pthread_mutex_unlock(&fuse_lock);
    }
    if (mount_id_out)
        *mount_id_out = mount_id;
    return 0;
}

/* Stat a FUSE-mounted path.
 *
 * Returns 0 on success, or a negative Linux errno (LINUX_E*). Errno-via-globals
 * is intentionally avoided: callers in src/syscall/fs-stat.c return this value
 * directly to the guest.
 *
 * at_flags is the LINUX_AT_* mask from the caller. Today only
 * LINUX_AT_SYMLINK_NOFOLLOW is honored: when the daemon's final LOOKUP returns
 * S_IFLNK and NOFOLLOW is unset, the call returns -LINUX_ENOSYS because symlink
 * target resolution is not implemented yet. With NOFOLLOW (lstat-equivalent)
 * the symlink's own attrs are returned.
 */
int fuse_stat_path(const char *path, struct stat *st, int at_flags)
{
    fuse_attr_t attr;
    uint64_t nodeid = 0;
    int rc = fuse_path_lookup(path, false, NULL, NULL, &nodeid, &attr);
    (void) nodeid;
    if (rc < 0)
        return rc;
    if (S_ISLNK(attr.mode) && !(at_flags & LINUX_AT_SYMLINK_NOFOLLOW))
        return -LINUX_ENOSYS;
    fuse_fill_stat_from_attr(&attr, st);
    return 0;
}

int fuse_access_path(const char *path, int mode, int flags)
{
    struct stat st;
    int rc = fuse_stat_path(path, &st, flags);
    if (rc < 0)
        return rc;
    if (path_check_intercept_access(&st, mode, flags) < 0)
        return linux_errno();
    return 0;
}

static int fuse_write_all(int fd, const void *buf, size_t len)
{
    const uint8_t *p = buf;
    while (len > 0) {
        ssize_t nw = write(fd, p, len);
        if (nw < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        p += (size_t) nw;
        len -= (size_t) nw;
    }
    return 0;
}

static int fuse_materialize_open_file_locked(fuse_session_t *session,
                                             uint64_t nodeid,
                                             uint64_t fh,
                                             int linux_flags,
                                             char *out_path,
                                             size_t outsz)
{
    char tmp_template[] = "/tmp/elfuse-fuse-exec.XXXXXX";
    if (sizeof(tmp_template) > outsz)
        return -LINUX_ENAMETOOLONG;

    int tmp_fd = mkstemp(tmp_template);
    if (tmp_fd < 0)
        return linux_errno();

    int rc = 0;
    uint64_t offset = 0;
    uint32_t size = session->max_write ? session->max_write : 65536;
    for (;;) {
        fuse_read_in_t in = {
            .fh = fh,
            .offset = offset,
            .size = size,
            .flags = (uint32_t) linux_flags,
        };
        uint8_t *reply = NULL;
        size_t reply_len = 0;
        rc = fuse_request_locked(session, FUSE_READ, nodeid, &in, sizeof(in),
                                 &reply, &reply_len);
        if (rc < 0) {
            free(reply);
            break;
        }
        if (reply_len == 0) {
            free(reply);
            break;
        }
        if (fuse_write_all(tmp_fd, reply, reply_len) < 0) {
            rc = linux_errno();
            free(reply);
            break;
        }
        offset += reply_len;
        free(reply);
    }
    if (close(tmp_fd) < 0 && rc == 0)
        rc = linux_errno();

    if (rc < 0) {
        unlink(tmp_template);
        return rc;
    }

    memcpy(out_path, tmp_template, sizeof(tmp_template));
    return 0;
}

int fuse_materialize_path(const char *path, char *out_path, size_t outsz)
{
    fuse_session_t *session = NULL;
    int mount_id = 0;
    uint64_t nodeid = 0;
    fuse_attr_t attr;
    int rc = fuse_path_lookup(path, true, &session, &mount_id, &nodeid, &attr);
    (void) mount_id;
    if (rc < 0)
        return rc;
    if (S_ISDIR(attr.mode)) {
        pthread_mutex_lock(&session->lock);
        (void) fuse_node_ref_drop_locked(session, nodeid, 1, true);
        pthread_mutex_unlock(&session->lock);
        pthread_mutex_lock(&fuse_lock);
        fuse_session_put_locked(session);
        pthread_mutex_unlock(&fuse_lock);
        return -LINUX_EACCES;
    }

    pthread_mutex_lock(&session->lock);
    fuse_open_out_t out;
    bool opened = false;
    rc = fuse_open_common_locked(session, nodeid, LINUX_O_RDONLY, false, &out);
    if (rc == 0) {
        opened = true;
        rc = fuse_materialize_open_file_locked(session, nodeid, out.fh,
                                               LINUX_O_RDONLY, out_path, outsz);
    }
    if (opened) {
        int rel_rc = fuse_release_common_locked(session, false, nodeid, out.fh,
                                                LINUX_O_RDONLY);
        if (rc == 0 && rel_rc < 0)
            rc = rel_rc;
    } else {
        (void) fuse_node_ref_drop_locked(session, nodeid, 1, true);
    }
    pthread_mutex_unlock(&session->lock);

    pthread_mutex_lock(&fuse_lock);
    fuse_session_put_locked(session);
    pthread_mutex_unlock(&fuse_lock);
    return rc;
}

/* fstat against a FUSE-backed fd.
 *
 * Returns 0 on success, negative Linux errno otherwise.
 *
 * Returns -LINUX_EBADF when the fd does not refer to a live FUSE file so
 * callers can distinguish "not ours" from "ours but failed".
 */
int fuse_fstat_fd(int fd, struct stat *st)
{
    fd_entry_t snap;
    if (fd_snapshot(fd, &snap) && snap.type == FD_FUSE_DEV)
        return fuse_proc_stat(st);

    pthread_mutex_lock(&fuse_lock);
    fuse_file_t *file = fuse_file_by_fd_locked(fd);
    if (!file || !file->session) {
        pthread_mutex_unlock(&fuse_lock);
        return -LINUX_EBADF;
    }
    fuse_session_t *session = file->session;
    int mount_id = file->mount_id;
    uint64_t nodeid = file->nodeid;
    fuse_session_get_locked(session);
    pthread_mutex_lock(&session->lock);
    pthread_mutex_unlock(&fuse_lock);
    fuse_attr_t attr;
    int rc = fuse_getattr_locked(session, nodeid, &attr);
    pthread_mutex_unlock(&session->lock);
    pthread_mutex_lock(&fuse_lock);
    fuse_session_put_locked(session);
    if (rc == 0) {
        /* file may have been concurrently closed and the slot reused. Refetch
         * by guest_fd and only update the attr cache if it still maps to the
         * same (session, mount_id, nodeid) identity.
         */
        file = fuse_file_by_fd_locked(fd);
        if (file && file->session == session && file->mount_id == mount_id &&
            file->nodeid == nodeid)
            file->attr = attr;
    }
    pthread_mutex_unlock(&fuse_lock);
    if (rc < 0)
        return rc;
    fuse_fill_stat_from_attr(&attr, st);
    return 0;
}

int64_t fuse_open_path(guest_t *g, const char *path, int linux_flags, int mode)
{
    (void) g;
    (void) mode;
    if (!path || path[0] != '/')
        return INT64_MIN;

    char canon[LINUX_PATH_MAX];
    if (fuse_canonical_abs(path, canon, sizeof(canon)) < 0)
        return -LINUX_ENAMETOOLONG;

    pthread_mutex_lock(&fuse_lock);
    const char *relpath = NULL;
    fuse_mount_t *mount = fuse_mount_for_path_locked(canon, &relpath);
    if (!mount) {
        pthread_mutex_unlock(&fuse_lock);
        return INT64_MIN;
    }
    if (!mount->session) {
        /* Tombstoned mount; daemon already dropped /dev/fuse. */
        pthread_mutex_unlock(&fuse_lock);
        return -LINUX_ENOTCONN;
    }
    fuse_session_t *session = mount->session;
    int mount_id = mount->mount_id;
    fuse_session_get_locked(session);
    pthread_mutex_lock(&session->lock);
    pthread_mutex_unlock(&fuse_lock);

    uint64_t nodeid = 0;
    fuse_attr_t attr;
    int rc = fuse_walk_path_locked(session, relpath, true, &nodeid, &attr);
    if (rc < 0) {
        pthread_mutex_unlock(&session->lock);
        pthread_mutex_lock(&fuse_lock);
        fuse_session_put_locked(session);
        pthread_mutex_unlock(&fuse_lock);
        return rc;
    }

    bool want_dir = (linux_flags & LINUX_O_DIRECTORY) || S_ISDIR(attr.mode);
    bool path_only = (linux_flags & LINUX_O_PATH) != 0;
    if ((linux_flags & LINUX_O_DIRECTORY) && !S_ISDIR(attr.mode)) {
        (void) fuse_node_ref_drop_locked(session, nodeid, 1, true);
        pthread_mutex_unlock(&session->lock);
        pthread_mutex_lock(&fuse_lock);
        fuse_session_put_locked(session);
        pthread_mutex_unlock(&fuse_lock);
        return -LINUX_ENOTDIR;
    }
    /* Linux open(2): when O_PATH is set, access-mode bits (O_RDONLY / O_WRONLY
     * / O_RDWR) are ignored. The descriptor is opaque to read/write but usable
     * for fstat, fchdir, *at() dirfd, etc. Reject non-RDONLY only for ordinary
     * file opens until FUSE write support exists for FD_FUSE_FILE.
     */
    if (!want_dir && !path_only && (linux_flags & 3) != LINUX_O_RDONLY) {
        (void) fuse_node_ref_drop_locked(session, nodeid, 1, true);
        pthread_mutex_unlock(&session->lock);
        pthread_mutex_lock(&fuse_lock);
        fuse_session_put_locked(session);
        pthread_mutex_unlock(&fuse_lock);
        return -LINUX_EACCES;
    }

    int guest_fd =
        fd_alloc(want_dir ? FD_FUSE_DIR : FD_FUSE_FILE, -1, fuse_fd_cleanup);
    if (guest_fd < 0) {
        (void) fuse_node_ref_drop_locked(session, nodeid, 1, true);
        pthread_mutex_unlock(&session->lock);
        pthread_mutex_lock(&fuse_lock);
        fuse_session_put_locked(session);
        pthread_mutex_unlock(&fuse_lock);
        return -LINUX_EMFILE;
    }

    fuse_file_t *file = NULL;
    pthread_mutex_lock(&fuse_lock);
    file = fuse_alloc_file_locked();
    pthread_mutex_unlock(&fuse_lock);
    if (!file) {
        fd_mark_closed(guest_fd);
        (void) fuse_node_ref_drop_locked(session, nodeid, 1, true);
        pthread_mutex_unlock(&session->lock);
        pthread_mutex_lock(&fuse_lock);
        fuse_session_put_locked(session);
        pthread_mutex_unlock(&fuse_lock);
        return -LINUX_ENOMEM;
    }

    fuse_open_out_t out;
    memset(&out, 0, sizeof(out));
    if (!path_only) {
        rc = fuse_open_common_locked(session, nodeid, linux_flags, want_dir,
                                     &out);
        if (rc < 0) {
            (void) fuse_node_ref_drop_locked(session, nodeid, 1, true);
            pthread_mutex_unlock(&session->lock);
            pthread_mutex_lock(&fuse_lock);
            fuse_file_put_locked(file); /* releases the open-fd ref */
            fuse_session_put_locked(session);
            pthread_mutex_unlock(&fuse_lock);
            fd_mark_closed(guest_fd);
            return rc;
        }
    }
    pthread_mutex_unlock(&session->lock);

    pthread_mutex_lock(&fuse_lock);
    file->dir = want_dir;
    file->nodeid = nodeid;
    file->fh = out.fh;
    file->linux_flags = linux_flags;
    file->path_only = path_only;
    /* Donate the session ref taken above to the file's own ref slot. The mount
     * pointer itself is not cached; mount_id is enough to detect stale
     * mount-slot reassignment without dereferencing a recycled fuse_mount_t.
     */
    file->session = session;
    file->mount_id = mount_id;
    str_copy_trunc(file->path, canon, sizeof(file->path));
    file->attr = attr;
    if (fuse_bind_file_fd_locked(guest_fd, file) < 0) {
        fuse_session_get_locked(session);
        fuse_file_put_locked(file);
        pthread_mutex_unlock(&fuse_lock);
        pthread_mutex_lock(&session->lock);
        (void) fuse_release_common_locked(session, want_dir, nodeid, out.fh,
                                          linux_flags);
        pthread_mutex_unlock(&session->lock);
        pthread_mutex_lock(&fuse_lock);
        fuse_session_put_locked(session);
        pthread_mutex_unlock(&fuse_lock);
        fd_mark_closed(guest_fd);
        return -LINUX_EMFILE;
    }
    pthread_mutex_unlock(&fuse_lock);
    /* Publish under fd_lock so the open's flags land on the same lock domain
     * that sys_fcntl(F_SETFL/F_SETFD) uses.
     */
    fd_publish_linux_flags(guest_fd, linux_flags);
    return guest_fd;
}

/* Snapshot of fuse_file_t fields needed for a single read/readdir request. The
 * snapshot pins both the session (via session_get_locked) and the file slot
 * (via file_get_locked) for the duration of the operation. file is the actual
 * fuse_file_t pointer so io_in_progress / io_cond can be touched on release
 * without re-looking-up by guest_fd.
 */
typedef struct {
    fuse_file_t *file;
    fuse_session_t *session;
    uint64_t nodeid;
    uint64_t fh;
    int mount_id;
    int linux_flags;
    bool path_only;
    bool dir;
    bool serialize; /* true for stream reads/readdir; false for pread */
} fuse_file_snap_t;

/* Acquire exclusive offset-affecting access to a FUSE file, bump the file and
 * session refcounts, and snapshot the identity into @snap. Stream reads (and
 * readdir) pass @serialize=true so concurrent read() calls on the same fd are
 * serialized via io_in_progress, matching Linux f_pos_lock semantics.
 * pread/getattr-style operations that do not touch the stream offset pass
 * @serialize=false.
 *
 * Returns 0 on success or a negative Linux errno.
 */
static int fuse_file_acquire(int guest_fd,
                             bool want_dir,
                             bool serialize,
                             fuse_file_snap_t *snap)
{
    pthread_mutex_lock(&fuse_lock);
    for (;;) {
        fuse_file_t *file = fuse_file_by_fd_locked(guest_fd);
        if (!file || !file->session) {
            pthread_mutex_unlock(&fuse_lock);
            return -LINUX_EBADF;
        }
        if (file->dir != want_dir) {
            pthread_mutex_unlock(&fuse_lock);
            return want_dir ? -LINUX_ENOTDIR : -LINUX_EBADF;
        }
        if (serialize && file->io_in_progress) {
            /* Bump file ref so the slot (and io_cond) survive the wait. */
            fuse_file_get_locked(file);
            pthread_cond_wait(&file->io_cond, &fuse_lock);
            fuse_file_put_locked(file);
            /* Re-look-up: the slot may have been closed or replaced. */
            continue;
        }
        if (serialize)
            file->io_in_progress = true;
        snap->file = file;
        snap->session = file->session;
        snap->nodeid = file->nodeid;
        snap->fh = file->fh;
        snap->mount_id = file->mount_id;
        snap->linux_flags = file->linux_flags;
        snap->path_only = file->path_only;
        snap->dir = file->dir;
        snap->serialize = serialize;
        fuse_file_get_locked(file);
        fuse_session_get_locked(snap->session);
        pthread_mutex_unlock(&fuse_lock);
        return 0;
    }
}

static void fuse_file_release(fuse_file_snap_t *snap)
{
    pthread_mutex_lock(&fuse_lock);
    if (snap->serialize) {
        /* Clearing io_in_progress on the pinned slot is safe even if the slot
         * has been logically closed; in that case the broadcast goes to no live
         * waiter and the slot will be zeroed on the final put.
         */
        snap->file->io_in_progress = false;
        pthread_cond_broadcast(&snap->file->io_cond);
    }
    fuse_file_put_locked(snap->file);
    fuse_session_put_locked(snap->session);
    pthread_mutex_unlock(&fuse_lock);
}

int fuse_materialize_fd(int fd, char *out_path, size_t outsz)
{
    fuse_file_snap_t snap;
    int rc = fuse_file_acquire(fd, false, false, &snap);
    if (rc < 0)
        return rc;

    if (snap.path_only) {
        char path[LINUX_PATH_MAX];
        str_copy_trunc(path, snap.file->path, sizeof(path));
        fuse_file_release(&snap);
        return fuse_materialize_path(path, out_path, outsz);
    }

    pthread_mutex_lock(&snap.session->lock);
    rc = fuse_materialize_open_file_locked(snap.session, snap.nodeid, snap.fh,
                                           LINUX_O_RDONLY, out_path, outsz);
    pthread_mutex_unlock(&snap.session->lock);
    fuse_file_release(&snap);
    return rc;
}

/* Read up to count bytes from a FUSE-backed file or directory at offset. Writes
 * the daemon's reply into the guest buffer at @buf_gva. Updates the stream
 * offset on success when @advance_offset is true and the fd still references
 * the same (session, mount_id, nodeid) identity (post-close races leave offsets
 * untouched).
 */
static int64_t fuse_read_common(guest_t *g,
                                int guest_fd,
                                fuse_file_snap_t *snap,
                                uint64_t buf_gva,
                                uint64_t count,
                                uint64_t offset,
                                bool advance_offset)
{
    if (snap->path_only)
        return -LINUX_EBADF;

    pthread_mutex_lock(&snap->session->lock);
    uint32_t size = (count < (uint64_t) snap->session->max_write)
                        ? (uint32_t) count
                        : snap->session->max_write;
    fuse_read_in_t in = {
        .fh = snap->fh,
        .offset = offset,
        .size = size,
        .flags = (uint32_t) snap->linux_flags,
    };
    uint8_t *reply = NULL;
    size_t reply_len = 0;
    int rc =
        fuse_request_locked(snap->session, snap->dir ? FUSE_READDIR : FUSE_READ,
                            snap->nodeid, &in, sizeof(in), &reply, &reply_len);
    pthread_mutex_unlock(&snap->session->lock);
    if (rc < 0)
        return rc;
    if (guest_write(g, buf_gva, reply, reply_len) < 0) {
        free(reply);
        return -LINUX_EFAULT;
    }
    free(reply);
    if (advance_offset) {
        pthread_mutex_lock(&fuse_lock);
        fuse_file_t *file = fuse_file_by_fd_locked(guest_fd);
        if (file && file->session == snap->session &&
            file->mount_id == snap->mount_id && file->nodeid == snap->nodeid)
            file->offset = offset + reply_len;
        pthread_mutex_unlock(&fuse_lock);
    }
    return (int64_t) reply_len;
}

int64_t fuse_read_fd(guest_t *g, int fd, uint64_t buf_gva, uint64_t count)
{
    fuse_file_snap_t snap;
    int err = fuse_file_acquire(fd, false, true, &snap);
    if (err < 0)
        return err;
    /* The acquire holds io_in_progress, so the offset is stable. */
    uint64_t offset = snap.file->offset;
    int64_t rc = fuse_read_common(g, fd, &snap, buf_gva, count, offset, true);
    fuse_file_release(&snap);
    return rc;
}

int64_t fuse_pread_fd(guest_t *g,
                      int fd,
                      uint64_t buf_gva,
                      uint64_t count,
                      int64_t offset)
{
    if (offset < 0)
        return -LINUX_EINVAL;
    fuse_file_snap_t snap;
    int err = fuse_file_acquire(fd, false, false, &snap);
    if (err < 0)
        return err;
    int64_t rc = fuse_read_common(g, fd, &snap, buf_gva, count,
                                  (uint64_t) offset, false);
    fuse_file_release(&snap);
    return rc;
}

int64_t fuse_getdents64(guest_t *g, int fd, uint64_t buf_gva, uint64_t count)
{
    fuse_file_snap_t snap;
    int err = fuse_file_acquire(fd, true, true, &snap);
    if (err < 0)
        return err;

    uint64_t dir_off = snap.file->offset;

    int64_t raw =
        fuse_read_common(g, fd, &snap, buf_gva, count, dir_off, false);
    if (raw <= 0) {
        fuse_file_release(&snap);
        return raw;
    }

    uint8_t *tmp = malloc((size_t) raw);
    if (!tmp) {
        fuse_file_release(&snap);
        return -LINUX_ENOMEM;
    }
    if (guest_read(g, buf_gva, tmp, (size_t) raw) < 0) {
        free(tmp);
        fuse_file_release(&snap);
        return -LINUX_EFAULT;
    }

    size_t src = 0;
    size_t dst = 0;
    while (src + FUSE_NAME_OFFSET <= (size_t) raw) {
        fuse_dirent_t *fde = (fuse_dirent_t *) (tmp + src);
        /* The daemon supplies fde->namelen; bound it to Linux NAME_MAX before
         * any further arithmetic so a malicious daemon cannot make lreclen
         * overflow the fixed entry[] buffer below or exceed the remaining frame
         * body.
         */
        if (fde->namelen > 255) {
            free(tmp);
            fuse_file_release(&snap);
            return dst ? (int64_t) dst : -LINUX_EIO;
        }
        size_t freclen = FUSE_DIRENT_SIZE_RAW(fde->namelen);
        if (freclen < FUSE_NAME_OFFSET + fde->namelen)
            break;
        if (src + freclen > (size_t) raw)
            break;

        size_t lreclen = (19 + fde->namelen + 1 + 7) & ~7ULL;
        /* d_ino(8) + d_off(8) + d_reclen(2) + d_type(1) + name(<=255) + NUL(1)
         * + padding(<=7) <= 280. Defense in depth against an arithmetic error
         * -- never trust the daemon's record length.
         */
        uint8_t entry[280];
        if (lreclen > sizeof(entry))
            break;
        if (dst + lreclen > count)
            break;

        struct {
            uint64_t d_ino;
            int64_t d_off;
            uint16_t d_reclen;
            uint8_t d_type;
        } lde = {
            .d_ino = fde->ino,
            .d_off = (int64_t) fde->off,
            .d_reclen = (uint16_t) lreclen,
            .d_type = (uint8_t) fde->type,
        };
        memcpy(entry, &lde, sizeof(lde));
        memcpy(entry + 19, fde->name, fde->namelen);
        entry[19 + fde->namelen] = '\0';
        if (19 + fde->namelen + 1 < lreclen)
            memset(entry + 19 + fde->namelen + 1, 0,
                   lreclen - (19 + fde->namelen + 1));
        if (guest_write(g, buf_gva + dst, entry, lreclen) < 0) {
            free(tmp);
            fuse_file_release(&snap);
            return dst ? (int64_t) dst : -LINUX_EFAULT;
        }
        dst += lreclen;
        src += freclen;
        pthread_mutex_lock(&fuse_lock);
        fuse_file_t *cur = fuse_file_by_fd_locked(fd);
        if (cur && cur->session == snap.session &&
            cur->mount_id == snap.mount_id && cur->nodeid == snap.nodeid)
            cur->offset = fde->off;
        pthread_mutex_unlock(&fuse_lock);
    }

    free(tmp);
    fuse_file_release(&snap);
    return (int64_t) dst;
}

int64_t fuse_dev_read(int guest_fd,
                      guest_t *g,
                      uint64_t buf_gva,
                      uint64_t count)
{
    host_fd_ref_t notify_ref;
    if (host_fd_ref_open_io(guest_fd, &notify_ref) < 0)
        return -LINUX_EBADF;

    pthread_mutex_lock(&fuse_lock);
    fuse_session_t *session = fuse_session_by_fd_locked(guest_fd);
    if (!session) {
        pthread_mutex_unlock(&fuse_lock);
        host_fd_ref_close(&notify_ref);
        return -LINUX_EBADF;
    }
    fuse_session_get_locked(session);
    pthread_mutex_unlock(&fuse_lock);

    pthread_mutex_lock(&session->lock);
    while (!session->closed && !session->queue_head) {
        if (fd_table[guest_fd].linux_flags & LINUX_O_NONBLOCK) {
            pthread_mutex_unlock(&session->lock);
            pthread_mutex_lock(&fuse_lock);
            fuse_session_put_locked(session);
            pthread_mutex_unlock(&fuse_lock);
            host_fd_ref_close(&notify_ref);
            return -LINUX_EAGAIN;
        }
        pthread_cond_wait(&session->queue_cond, &session->lock);
    }
    if (session->closed || session->daemon_dead) {
        pthread_mutex_unlock(&session->lock);
        pthread_mutex_lock(&fuse_lock);
        fuse_session_put_locked(session);
        pthread_mutex_unlock(&fuse_lock);
        host_fd_ref_close(&notify_ref);
        return -LINUX_ENOTCONN;
    }

    /* Peek the head request: short reads MUST NOT consume the frame, or the
     * consumer blocks forever waiting for a reply that can never be matched.
     * fuse(4) lets the daemon retry the read with a larger buffer.
     */
    fuse_request_t *req = session->queue_head;
    size_t frame_len = req->frame_len;
    if (count < frame_len) {
        pthread_mutex_unlock(&session->lock);
        pthread_mutex_lock(&fuse_lock);
        fuse_session_put_locked(session);
        pthread_mutex_unlock(&fuse_lock);
        host_fd_ref_close(&notify_ref);
        return -LINUX_EINVAL;
    }
    if (guest_write(g, buf_gva, req->frame, frame_len) < 0) {
        pthread_mutex_unlock(&session->lock);
        pthread_mutex_lock(&fuse_lock);
        fuse_session_put_locked(session);
        pthread_mutex_unlock(&fuse_lock);
        host_fd_ref_close(&notify_ref);
        return -LINUX_EFAULT;
    }
    /* Commit: dequeue only after the copy succeeded. */
    session->queue_head = req->next;
    if (!session->queue_head)
        session->queue_tail = NULL;
    req->next = NULL;
    if (!session->queue_head)
        fuse_notify_drain_fd_locked(notify_ref.fd);
    if (req->no_reply)
        fuse_free_request_locked(req);
    pthread_mutex_unlock(&session->lock);
    pthread_mutex_lock(&fuse_lock);
    fuse_session_put_locked(session);
    pthread_mutex_unlock(&fuse_lock);
    host_fd_ref_close(&notify_ref);
    return (int64_t) frame_len;
}

int64_t fuse_dev_write(guest_t *g,
                       int guest_fd,
                       uint64_t buf_gva,
                       uint64_t count)
{
    if (count < sizeof(fuse_out_header_t))
        return -LINUX_EINVAL;
    /* Reject any daemon write that exceeds the implementation hard ceiling. The
     * same ceiling is applied at FUSE_INIT negotiation, so a daemon cannot
     * advertise max_write larger than this and then have its reply payload
     * silently rejected here.
     */
    if (count > FUSE_FRAME_CAP)
        return -LINUX_EINVAL;

    uint8_t *buf = malloc((size_t) count);
    if (!buf)
        return -LINUX_ENOMEM;
    if (guest_read(g, buf_gva, buf, (size_t) count) < 0) {
        free(buf);
        return -LINUX_EFAULT;
    }

    fuse_out_header_t hdr;
    memcpy(&hdr, buf, sizeof(hdr));
    if (hdr.len > count || hdr.len < sizeof(hdr)) {
        free(buf);
        return -LINUX_EINVAL;
    }

    pthread_mutex_lock(&fuse_lock);
    fuse_session_t *session = fuse_session_by_fd_locked(guest_fd);
    if (!session) {
        pthread_mutex_unlock(&fuse_lock);
        free(buf);
        return -LINUX_EBADF;
    }
    fuse_session_get_locked(session);
    pthread_mutex_unlock(&fuse_lock);

    pthread_mutex_lock(&session->lock);
    fuse_request_t *req = NULL;
    for (int i = 0; i < FUSE_MAX_PENDING; i++) {
        if (session->requests[i].used &&
            session->requests[i].unique == hdr.unique) {
            req = &session->requests[i];
            break;
        }
    }
    if (!req) {
        pthread_mutex_unlock(&session->lock);
        pthread_mutex_lock(&fuse_lock);
        fuse_session_put_locked(session);
        pthread_mutex_unlock(&fuse_lock);
        free(buf);
        return -LINUX_EINVAL;
    }

    req->answered = true;
    /* The daemon's error field is in Linux errno space (negative). Pass it
     * through unchanged; the consumer side already treats req->error as a
     * negative Linux errno.
     */
    req->error = hdr.error;
    req->reply_len = hdr.len - sizeof(hdr);
    if (req->reply_len) {
        req->reply = malloc(req->reply_len);
        if (!req->reply)
            req->error = -LINUX_ENOMEM;
        else
            memcpy(req->reply, buf + sizeof(hdr), req->reply_len);
    }

    if (req->frame && ((fuse_in_header_t *) req->frame)->opcode == FUSE_INIT) {
        /* fuse(4): the daemon may return a fuse_init_out_t shorter than the
         * current struct size (older libfuse), and may negotiate a minor
         * version different from ours. Accept any reply whose major matches and
         * that is large enough to carry max_write. Reject only on an actual
         * major-version mismatch or daemon-reported error.
         */
        const size_t init_min_len = offsetof(fuse_init_out_t, max_write) +
                                    sizeof(((fuse_init_out_t *) 0)->max_write);
        bool local_oom = (req->reply_len > 0 && !req->reply);
        if (local_oom) {
            /* Local reply-buffer malloc failed earlier; req->error is already
             * -LINUX_ENOMEM and must stay so the originator of the FUSE_INIT
             * request sees the root cause. The daemon itself is still healthy,
             * but elfuse never decoded its reply, so init_done cannot be set
             * and the session cannot carry further traffic. Mark daemon_dead to
             * release any fuse_wait_for_init_locked waiters with
             * -LINUX_ENOTCONN and to fail subsequent fuse_request_locked calls;
             * without this, init_cond's broadcast below wakes waiters that
             * immediately re-block on the still-false init_done flag.
             */
            session->daemon_dead = true;
        } else if (hdr.error == 0 && req->reply_len >= init_min_len) {
            fuse_init_out_t init_out;
            memset(&init_out, 0, sizeof(init_out));
            size_t copy_len = req->reply_len < sizeof(init_out)
                                  ? req->reply_len
                                  : sizeof(init_out);
            memcpy(&init_out, req->reply, copy_len);
            if (init_out.major != FUSE_KERNEL_VERSION) {
                req->error = -LINUX_EPROTO;
                session->daemon_dead = true;
            } else {
                uint32_t neg_write =
                    init_out.max_write ? init_out.max_write : 65536;
                if (neg_write > FUSE_MAX_NEGOTIATED_WRITE)
                    neg_write = FUSE_MAX_NEGOTIATED_WRITE;
                session->max_write = neg_write;
                session->max_pages =
                    init_out.max_pages ? init_out.max_pages : 16;
                session->init_done = true;
            }
        } else if (hdr.error < 0) {
            req->error = hdr.error;
            session->daemon_dead = true;
        } else {
            req->error = -LINUX_EPROTO;
            session->daemon_dead = true;
        }
        pthread_cond_broadcast(&session->init_cond);
    }
    if (req->detached) {
        fuse_free_request_locked(req);
    } else {
        pthread_cond_broadcast(&req->cond);
    }
    pthread_mutex_unlock(&session->lock);
    pthread_mutex_lock(&fuse_lock);
    fuse_session_put_locked(session);
    pthread_mutex_unlock(&fuse_lock);
    free(buf);
    return (int64_t) count;
}

bool fuse_is_device_fd(int fd)
{
    fd_entry_t snap;
    return fd_snapshot(fd, &snap) && snap.type == FD_FUSE_DEV;
}

bool fuse_is_file_fd(int fd)
{
    fd_entry_t snap;
    return fd_snapshot(fd, &snap) && snap.type == FD_FUSE_FILE;
}

bool fuse_is_dir_fd(int fd)
{
    fd_entry_t snap;
    return fd_snapshot(fd, &snap) && snap.type == FD_FUSE_DIR;
}

bool fuse_fd_refuse_mmap(int fd)
{
    fd_entry_t snap;
    if (!fd_snapshot(fd, &snap) ||
        (snap.type != FD_FUSE_FILE && snap.type != FD_FUSE_DIR))
        return false;

    pthread_mutex_lock(&fuse_lock);
    fuse_file_t *file = fuse_file_by_fd_locked(fd);
    bool refuse = file && !file->path_only;
    pthread_mutex_unlock(&fuse_lock);
    return refuse;
}

int64_t fuse_lseek_fd(int fd, int64_t offset, int whence)
{
    fd_entry_t snap;
    if (!fd_snapshot(fd, &snap))
        return -LINUX_EBADF;
    /* /dev/fuse: stream-like, no absolute position. Linux returns ESPIPE on
     * lseek of a pipe-equivalent fd.
     */
    if (snap.type == FD_FUSE_DEV)
        return -LINUX_ESPIPE;
    if (snap.type != FD_FUSE_FILE && snap.type != FD_FUSE_DIR)
        return INT64_MIN;

    /* Fast-reject O_PATH fds before the wait loop, then re-lookup under the
     * lock for the seek itself.
     */
    pthread_mutex_lock(&fuse_lock);
    fuse_file_t *probe = fuse_file_by_fd_locked(fd);
    if (!probe || !probe->session) {
        pthread_mutex_unlock(&fuse_lock);
        return -LINUX_EBADF;
    }
    if (probe->path_only) {
        pthread_mutex_unlock(&fuse_lock);
        return -LINUX_EBADF;
    }
    pthread_mutex_unlock(&fuse_lock);

    /* Linux SEEK_SET=0, SEEK_CUR=1, SEEK_END=2. SEEK_HOLE/SEEK_DATA are not
     * supported against FUSE files without daemon round-trip; reject for now.
     */
    if (whence != 0 && whence != 1 && whence != 2)
        return -LINUX_EINVAL;

    pthread_mutex_lock(&fuse_lock);
    /* Block while a stream read is in flight on this fd so the seek does not
     * race the post-read offset update. The wait holds a file ref so io_cond
     * cannot be destroyed under it.
     */
    for (;;) {
        fuse_file_t *waiter = fuse_file_by_fd_locked(fd);
        if (!waiter || !waiter->session) {
            pthread_mutex_unlock(&fuse_lock);
            return -LINUX_EBADF;
        }
        if (!waiter->io_in_progress)
            break;
        fuse_file_get_locked(waiter);
        pthread_cond_wait(&waiter->io_cond, &fuse_lock);
        fuse_file_put_locked(waiter);
    }
    fuse_file_t *file = fuse_file_by_fd_locked(fd);
    if (!file || !file->session) {
        pthread_mutex_unlock(&fuse_lock);
        return -LINUX_EBADF;
    }
    int64_t cur = (int64_t) file->offset;
    int64_t end_size = (int64_t) file->attr.size;
    int64_t base;
    switch (whence) {
    case 0:
        base = 0;
        break;
    case 1:
        base = cur;
        break;
    case 2:
        base = end_size;
        break;
    default:
        pthread_mutex_unlock(&fuse_lock);
        return -LINUX_EINVAL;
    }

    /* Both overflow checks complete before the addition itself; INT64_MIN for
     * offset would otherwise produce signed-overflow UB on the bounds test.
     */
    if (offset > 0 && base > INT64_MAX - offset) {
        pthread_mutex_unlock(&fuse_lock);
        return -LINUX_EOVERFLOW;
    }
    if (offset < 0 && base < INT64_MIN - offset) {
        pthread_mutex_unlock(&fuse_lock);
        return -LINUX_EOVERFLOW;
    }
    int64_t new_off = base + offset;
    if (new_off < 0) {
        pthread_mutex_unlock(&fuse_lock);
        return -LINUX_EINVAL;
    }
    file->offset = (uint64_t) new_off;
    pthread_mutex_unlock(&fuse_lock);
    return new_off;
}

int64_t fuse_fchdir(int fd)
{
    fd_entry_t snap;
    if (!fd_snapshot(fd, &snap))
        return INT64_MIN;
    if (snap.type != FD_FUSE_DIR) {
        if (snap.type == FD_FUSE_FILE || snap.type == FD_FUSE_DEV)
            return -LINUX_ENOTDIR;
        return INT64_MIN;
    }

    pthread_mutex_lock(&fuse_lock);
    fuse_file_t *file = fuse_file_by_fd_locked(fd);
    if (!file || !file->session || !file->dir || file->path[0] != '/') {
        pthread_mutex_unlock(&fuse_lock);
        return -LINUX_EBADF;
    }
    char path[LINUX_PATH_MAX];
    str_copy_trunc(path, file->path, sizeof(path));
    pthread_mutex_unlock(&fuse_lock);
    proc_cwd_set_virtual(path);
    return 0;
}

int fuse_dup_fd(int src_fd,
                int min_guest_fd,
                int fixed_guest_fd,
                bool fixed_slot,
                int linux_flags)
{
    fd_entry_t snap;
    if (!fd_snapshot(src_fd, &snap)) {
        errno = EBADF;
        return -1;
    }
    if (snap.type != FD_FUSE_DEV && snap.type != FD_FUSE_FILE &&
        snap.type != FD_FUSE_DIR) {
        errno = EBADF;
        return -1;
    }

    /* Install cleanup atomically with the type. Without this, a racing close
     * between fd_alloc_*_relaxed publishing the slot and the later
     * fd_table[guest_fd].cleanup assignment would skip fuse_fd_cleanup and leak
     * the session or file ref.
     */
    int new_host_fd = snap.type == FD_FUSE_DEV ? dup(snap.host_fd) : -1;
    if (snap.type == FD_FUSE_DEV && new_host_fd < 0)
        return -1;
    uint64_t alloc_gen = 0;
    int guest_fd =
        fixed_slot ? fd_alloc_at_relaxed(fixed_guest_fd, snap.type, new_host_fd,
                                         fuse_fd_cleanup, &alloc_gen)
                   : fd_alloc_from_relaxed(min_guest_fd, snap.type, new_host_fd,
                                           fuse_fd_cleanup, &alloc_gen);
    if (guest_fd < 0) {
        if (new_host_fd >= 0)
            close(new_host_fd);
        if (fixed_slot)
            errno = EBADF;
        return -1;
    }

    pthread_mutex_lock(&fuse_lock);
    if (snap.type == FD_FUSE_DEV) {
        fuse_session_t *session = fuse_session_by_fd_locked(src_fd);
        if (!session) {
            pthread_mutex_unlock(&fuse_lock);
            fd_mark_closed(guest_fd);
            errno = EBADF;
            return -1;
        }
        fuse_session_get_locked(session);
        if (fuse_bind_dev_fd_locked(guest_fd, session) < 0) {
            fuse_session_put_locked(session);
            pthread_mutex_unlock(&fuse_lock);
            fd_mark_closed(guest_fd);
            errno = EMFILE;
            return -1;
        }
    } else {
        fuse_file_t *file = fuse_file_by_fd_locked(src_fd);
        if (!file || !file->session) {
            pthread_mutex_unlock(&fuse_lock);
            fd_mark_closed(guest_fd);
            errno = EBADF;
            return -1;
        }
        fuse_file_get_locked(file);
        if (fuse_bind_file_fd_locked(guest_fd, file) < 0) {
            fuse_file_put_locked(file);
            pthread_mutex_unlock(&fuse_lock);
            fd_mark_closed(guest_fd);
            errno = EMFILE;
            return -1;
        }
    }

    pthread_mutex_unlock(&fuse_lock);

    /* Copy the source snapshot, not the live src fd: dup aliases one coherent
     * open-file-description state even if another thread closes/reuses src_fd
     * while the FUSE refs are being pinned.
     *
     * Revalidate the destination slot under fd_lock before publishing metadata,
     * mirroring install_fd_alias_metadata_atomic in fs.c: a sibling close +
     * reopen on a fixed-slot dup2 target could have replaced this slot in the
     * window since fd_alloc. The generation stamped at alloc is the unique
     * discriminator (a close+reopen can reuse the same type and host_fd,
     * including host_fd == -1 for FUSE file/dir); a mismatch means the slot was
     * reused, so skip the write and the asyncio arm rather than stomp the new
     * occupant or fire SIGIO on an unrelated fd.
     */
    pthread_mutex_lock(&fd_lock);
    if (fd_table[guest_fd].type == snap.type &&
        fd_table[guest_fd].host_fd == new_host_fd &&
        fd_table[guest_fd].generation == alloc_gen) {
        int preserved_flags =
            snap.linux_flags &
            (LINUX_O_ACCMODE | LINUX_O_PATH | LINUX_O_DIRECTORY |
             LINUX_O_NOFOLLOW | LINUX_O_DIRECT | LINUX_O_LARGEFILE |
             LINUX_O_NONBLOCK | LINUX_O_ASYNC);
        fd_table[guest_fd].linux_flags = preserved_flags | linux_flags;
        fd_table[guest_fd].ofd_id = snap.ofd_id;
        fd_table[guest_fd].fasync_owner_type = snap.fasync_owner_type;
        fd_table[guest_fd].fasync_owner = snap.fasync_owner;
        if (fd_table[guest_fd].linux_flags & LINUX_O_ASYNC)
            asyncio_arm(guest_fd, fd_table[guest_fd].generation,
                        fd_table[guest_fd].host_fd, fd_table[guest_fd].type);
    }
    pthread_mutex_unlock(&fd_lock);
    return guest_fd;
}

int fuse_resolve_at_path(guest_fd_t dirfd,
                         const char *path,
                         char *out,
                         size_t outsz)
{
    if (!path || path[0] == '\0' || path[0] == '/')
        return 0;

    if (dirfd != LINUX_AT_FDCWD) {
        fd_entry_t snap;
        if (!fd_snapshot(dirfd, &snap) || snap.type != FD_FUSE_DIR)
            return 0;

        pthread_mutex_lock(&fuse_lock);
        fuse_file_t *file = fuse_file_by_fd_locked(dirfd);
        if (!file || !file->session || !file->dir || file->path[0] != '/') {
            pthread_mutex_unlock(&fuse_lock);
            errno = EBADF;
            return -1;
        }
        char base[LINUX_PATH_MAX];
        str_copy_trunc(base, file->path, sizeof(base));
        pthread_mutex_unlock(&fuse_lock);
        if (fuse_join_virtual_path(base, path, out, outsz) < 0)
            return -1;
        return 1;
    }

    proc_cwd_view_t view;
    if (proc_acquire_cwd_view(&view) < 0)
        return 0;

    /* fuse_path_matches_mount returns true for both live and tombstoned mounts,
     * so a virtual cwd left dangling by daemon death still routes the relative
     * lookup into FUSE land. The follow-on fuse_{path_lookup,open_path,
     * stat_path} call detects the tombstoned mount and surfaces -LINUX_ENOTCONN
     * instead of letting the resolution fall back to host-relative open against
     * the host cwd.
     */
    int rc = 0;
    if (view.path && view.path[0] == '/' &&
        fuse_path_matches_mount(view.path)) {
        rc = fuse_join_virtual_path(view.path, path, out, outsz) < 0 ? -1 : 1;
    }
    proc_release_cwd_view(&view);
    return rc;
}

int fuse_fd_mnt_id(int fd, int *mnt_id_out)
{
    if (!mnt_id_out) {
        errno = EINVAL;
        return -1;
    }

    pthread_mutex_lock(&fuse_lock);
    fuse_file_t *file = fuse_file_by_fd_locked(fd);
    if (!file || !file->session) {
        pthread_mutex_unlock(&fuse_lock);
        errno = ENOENT;
        return -1;
    }
    *mnt_id_out = file->mount_id;
    pthread_mutex_unlock(&fuse_lock);
    return 0;
}

int fuse_append_mountinfo(char *buf, size_t bufsz, size_t *off)
{
    if (!buf || !off || *off > bufsz) {
        errno = EINVAL;
        return -1;
    }

    pthread_mutex_lock(&fuse_lock);
    for (int i = 0; i < FUSE_MAX_MOUNTS; i++) {
        if (!fuse_mounts[i].used)
            continue;
        int n = snprintf(
            buf + *off, bufsz - *off,
            "%d 1 0:%d / %s rw,nosuid,nodev,relatime - %s %s rw\n",
            fuse_mounts[i].mount_id, FUSE_FAKE_DEV, fuse_mounts[i].path,
            fuse_mounts[i].fstype[0] ? fuse_mounts[i].fstype : "fuse",
            fuse_mounts[i].source[0] ? fuse_mounts[i].source : "fuse");
        if (n < 0 || (size_t) n >= bufsz - *off) {
            pthread_mutex_unlock(&fuse_lock);
            errno = ENAMETOOLONG;
            return -1;
        }
        *off += (size_t) n;
    }
    pthread_mutex_unlock(&fuse_lock);
    return 0;
}

int fuse_append_mounts(char *buf, size_t bufsz, size_t *off)
{
    if (!buf || !off || *off > bufsz) {
        errno = EINVAL;
        return -1;
    }

    pthread_mutex_lock(&fuse_lock);
    for (int i = 0; i < FUSE_MAX_MOUNTS; i++) {
        if (!fuse_mounts[i].used)
            continue;
        int n = snprintf(
            buf + *off, bufsz - *off, "%s %s %s rw,nosuid,nodev,relatime 0 0\n",
            fuse_mounts[i].source[0] ? fuse_mounts[i].source : "fuse",
            fuse_mounts[i].path,
            fuse_mounts[i].fstype[0] ? fuse_mounts[i].fstype : "fuse");
        if (n < 0 || (size_t) n >= bufsz - *off) {
            pthread_mutex_unlock(&fuse_lock);
            errno = ENAMETOOLONG;
            return -1;
        }
        *off += (size_t) n;
    }
    pthread_mutex_unlock(&fuse_lock);
    return 0;
}
