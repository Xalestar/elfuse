/* epoll_ctl close+reopen ABA regression test
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Companion to test-epoll-mt.c. That test covers the original dup-as-ident
 * bug (registrations vanishing across epoll_ctl). This one covers the ABA
 * race jserv flagged in review (PR #73, poll.c:723):
 *
 *   A registration in inst->regs[fd] is keyed on the guest fd *number*, but
 *   the kqueue knote is keyed on the underlying host fd. When the guest
 *   close()s a registered fd, the kernel drops the knote immediately, yet
 *   sys_close leaves reg->active set. If the guest then reopens the same fd
 *   number (a different open file behind the same number -- the A->B->A ABA),
 *   a later EPOLL_CTL_DEL/MOD would see the stale reg->active and act on the
 *   *new* file's host fd: EV_DELETE/EV_MOD against the wrong knote, returning
 *   success for a registration Linux considers already gone.
 *
 * The fix stamps fd_entry_t.generation into epoll_reg_t at ADD time and
 * rejects DEL/MOD when fd_table[fd].generation no longer matches, so a
 * close+reopen is detected as a stale registration. The generation counter is
 * monotonic, so the reused fd number gets a fresh stamp that never collides
 * with the old one.
 *
 * Asserted behavior (matches Linux, which auto-removes an fd from the epoll
 * interest list on close):
 *   - DEL on a closed-then-reopened fd number -> ENOENT, not success.
 *   - MOD on it -> ENOENT.
 *   - A fresh ADD on it succeeds and delivers edges for the *new* file.
 *   - The guard does not over-fire: DEL on a still-open registration that was
 *     never closed still succeeds.
 *
 * A CLONE_THREAD sibling is kept alive throughout so the guest stays
 * multi-threaded -- that is the only mode in which host_fd_ref_open() hands
 * back a dup, i.e. the exact path the snapshot+generation logic guards.
 *
 * Syscalls exercised: clone(220), epoll_create1(20), epoll_ctl(21),
 *                     epoll_pwait(22), eventfd2(19), dup3(24), write(64),
 *                     read(63), close(57), futex(98), nanosleep(101), exit(93)
 */

#include <stdint.h>
#include <errno.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>

#include "test-harness.h"
#include "raw-syscall.h"

int passes = 0, fails = 0;

static volatile int child_should_exit = 0;
static char sibling_stack[16384] __attribute__((aligned(16)));

/* Sibling thread: stays alive so the guest is multi-threaded across the
 * parent's epoll_ctl() calls, then exits. Raw syscalls only -- a
 * clone(CLONE_THREAD) child has no libc TLS. */
static int sibling_fn(void *arg)
{
    (void) arg;
    struct {
        long tv_sec, tv_nsec;
    } ts = {0, 5000000}; /* 5ms */
    while (!child_should_exit)
        raw_syscall2(__NR_nanosleep, (long) &ts, 0);
    raw_syscall1(__NR_exit, 0);
    return 0;
}

/* Reopen a fresh eventfd onto exactly the guest fd number that was just
 * closed, so the ABA (same number, new open file, new generation) is exercised
 * regardless of fd-allocator policy. The lowest-free allocator normally hands
 * back oldfd directly; dup3() forces it otherwise. Returns oldfd, or -1. */
static int reopen_same_number(int oldfd)
{
    int nf = eventfd(0, EFD_NONBLOCK);
    if (nf < 0)
        return -1;
    if (nf == oldfd)
        return oldfd;
    /* dup3 with flags=0 == dup2; lands the new open file on oldfd. */
    if (raw_syscall3(__NR_dup3, nf, oldfd, 0) < 0) {
        close(nf);
        return -1;
    }
    close(nf);
    return oldfd;
}

/* Register fd for EPOLLIN, make it readable, and assert the edge is observed
 * with the expected data.fd within a generous finite budget. Returns 1 on
 * success. Leaves the eventfd counter signalled (caller drains/closes). */
static int add_and_expect_edge(int epfd, int fd)
{
    struct epoll_event ev = {.events = EPOLLIN, .data.fd = fd};
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev) < 0)
        return 0;

    uint64_t one = 1;
    if (write(fd, &one, sizeof(one)) != (ssize_t) sizeof(one))
        return 0;

    struct epoll_event out[4];
    int n = epoll_wait(epfd, out, 4, 2000);
    return n == 1 && out[0].data.fd == fd;
}

static void drain_eventfd(int fd)
{
    uint64_t v;
    (void) !read(fd, &v, sizeof(v));
}

int main(void)
{
    printf("test-epoll-aba: epoll_ctl close+reopen ABA guard\n");

    /* Keep the guest multi-threaded for the whole test (see file header). */
    long flags = 0x00000100 | 0x00000200 | 0x00000400 | 0x00000800 |
                 0x00010000 | 0x00200000;
    volatile uint32_t child_tid = 1;
    long ret = raw_syscall5(__NR_clone, flags,
                            (long) (sibling_stack + sizeof(sibling_stack)), 0,
                            0, (long) &child_tid);
    if (ret == 0) {
        sibling_fn(NULL);
        return 0; /* unreachable */
    }

    TEST("clone sibling for multi-threaded context");
    EXPECT_TRUE(ret > 0, "clone failed");

    int epfd = epoll_create1(EPOLL_CLOEXEC);
    TEST("epoll_create1");
    EXPECT_TRUE(epfd >= 0, "epoll_create1 failed");

    /* Control: the generation guard must not over-fire. A registration on a
     * fd that is never closed must still DEL cleanly (generation matches). */
    TEST("DEL on still-open registration succeeds");
    {
        int efd = eventfd(0, EFD_NONBLOCK);
        struct epoll_event ev = {.events = EPOLLIN, .data.fd = efd};
        int ok = efd >= 0 && epoll_ctl(epfd, EPOLL_CTL_ADD, efd, &ev) == 0 &&
                 epoll_ctl(epfd, EPOLL_CTL_DEL, efd, NULL) == 0;
        EXPECT_TRUE(ok, "valid DEL rejected");
        close(efd);
    }

    /* Register file A on a fd number, confirm it really is live, then close
     * it and reopen a different file B onto the same number. */
    int efd = eventfd(0, EFD_NONBLOCK);
    TEST("ABA setup: register + observe edge on file A");
    EXPECT_TRUE(efd >= 0 && add_and_expect_edge(epfd, efd),
                "file A failed to register/deliver");
    drain_eventfd(efd);
    close(efd);

    int reused = reopen_same_number(efd);
    TEST("ABA setup: reopen reuses the same fd number");
    EXPECT_EQ(reused, efd, "could not reuse fd number");

    /* The stale registration must be treated as gone. Without the generation
     * guard these act on file B's host fd and return success. */
    TEST("DEL after close+reopen -> ENOENT");
    {
        struct epoll_event ev = {.events = EPOLLIN, .data.fd = efd};
        (void) ev;
        EXPECT_ERRNO(epoll_ctl(epfd, EPOLL_CTL_DEL, efd, NULL), ENOENT,
                     "stale DEL did not report ENOENT");
    }

    TEST("MOD after close+reopen -> ENOENT");
    {
        struct epoll_event ev = {.events = EPOLLIN | EPOLLOUT, .data.fd = efd};
        EXPECT_ERRNO(epoll_ctl(epfd, EPOLL_CTL_MOD, efd, &ev), ENOENT,
                     "stale MOD did not report ENOENT");
    }

    /* A fresh registration on the reused number must work end to end and
     * report the *new* file's readiness -- proving the new knote is keyed on
     * file B's host fd, not corrupted by the cleared stale state. */
    TEST("fresh ADD after ABA delivers edge for file B");
    EXPECT_TRUE(add_and_expect_edge(epfd, efd),
                "reused fd failed to register/deliver after ABA");
    drain_eventfd(efd);

    TEST("DEL of the fresh registration succeeds");
    EXPECT_TRUE(epoll_ctl(epfd, EPOLL_CTL_DEL, efd, NULL) == 0,
                "fresh DEL rejected");
    close(efd);
    close(epfd);

    /* Release the sibling and join via the CLONE_CHILD_CLEARTID futex. */
    child_should_exit = 1;
    for (int i = 0; i < 200 && child_tid != 0; i++) {
        struct {
            long tv_sec, tv_nsec;
        } ts = {0, 10000000}; /* 10ms */
        raw_syscall6(__NR_futex, (long) &child_tid, 0 /* FUTEX_WAIT */,
                     child_tid, (long) &ts, 0, 0);
    }

    SUMMARY("test-epoll-aba");
    return fails > 0 ? 1 : 0;
}
