/*
 * epoll close/dup2 interest-list eager-removal regression test
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Companion to test-epoll-aba.c. That test drives the cross-call generation
 * guard in sys_epoll_ctl() under a multi-threaded guest. This one pins the
 * complementary invariant: closing (or dup2-replacing) a registered fd eagerly
 * drops it from every epoll instance's interest table, matching Linux, which
 * auto-removes an fd from all epoll interest lists when its last descriptor
 * closes (src/syscall/poll.c epoll_note_fd_closed).
 *
 * The eager cleanup is what keeps sys_epoll_pwait's regs[gfd].active check
 * honest instead of leaning on the epoll_ctl generation guard as the only
 * defense. The generation guard alone already yields the correct observable
 * DEL/MOD/ADD results after a reopen -- so these assertions pass with or
 * without eager cleanup -- but this test exercises the cleanup code across the
 * close chokepoints the guard never touches:
 *
 *   - single-threaded close (the relaxed fast paths fd_close_regular_relaxed /
 *     fd_snapshot_and_close_relaxed, which the multi-threaded aba test
 * bypasses);
 *   - multiple epoll instances watching the same fd;
 *   - dup2/dup3 over an already-registered fd number (fd_alloc_at overwrite),
 *     which retires the old open file description without a close syscall.
 *
 * Deliberately single-threaded: no CLONE_THREAD sibling, so the close paths
 * take their single-active-thread fast branches.
 *
 * Syscalls exercised: epoll_create1(20), epoll_ctl(21), epoll_pwait(22),
 *                     eventfd2(19), dup3(24), write(64), read(63), close(57)
 */

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>

#include "test-harness.h"

int passes = 0, fails = 0;

/* Reopen a fresh eventfd onto exactly the guest fd number just closed, so the
 * A->B->A reuse is exercised regardless of allocator policy. The lowest-free
 * allocator normally hands back oldfd; dup3() forces it otherwise.
 *
 * Returns oldfd on success, or -1.
 */
static int reopen_same_number(int oldfd)
{
    int nf = eventfd(0, EFD_NONBLOCK);
    if (nf < 0)
        return -1;
    if (nf == oldfd)
        return oldfd;
    if (dup3(nf, oldfd, 0) < 0) {
        close(nf);
        return -1;
    }
    close(nf);
    return oldfd;
}

static void drain_eventfd(int fd)
{
    uint64_t v;
    (void) !read(fd, &v, sizeof(v));
}

/* Register fd for EPOLLIN, make it readable, and assert the edge is observed
 * with the expected data.fd. Leaves the counter signalled; caller drains.
 *
 * Returns 1 on success.
 */
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

int main(void)
{
    printf("test-epoll-close: epoll interest-list eager removal on close\n");

    int epfd = epoll_create1(EPOLL_CLOEXEC);
    TEST("epoll_create1");
    EXPECT_TRUE(epfd >= 0, "epoll_create1 failed");

    /* Case 1: single-instance close+reopen. The stale registration for the old
     * open file must be gone; DEL/MOD report ENOENT and a fresh ADD delivers
     * the new file's edge.
     */
    int efd = eventfd(0, EFD_NONBLOCK);
    TEST("register + observe edge on file A");
    EXPECT_TRUE(efd >= 0 && add_and_expect_edge(epfd, efd),
                "file A failed to register/deliver");
    drain_eventfd(efd);
    close(efd);

    int reused = reopen_same_number(efd);
    TEST("reopen reuses the same fd number");
    EXPECT_EQ(reused, efd, "could not reuse fd number");

    TEST("DEL after close+reopen -> ENOENT");
    EXPECT_ERRNO(epoll_ctl(epfd, EPOLL_CTL_DEL, efd, NULL), ENOENT,
                 "stale DEL did not report ENOENT");

    TEST("MOD after close+reopen -> ENOENT");
    {
        struct epoll_event ev = {.events = EPOLLIN | EPOLLOUT, .data.fd = efd};
        EXPECT_ERRNO(epoll_ctl(epfd, EPOLL_CTL_MOD, efd, &ev), ENOENT,
                     "stale MOD did not report ENOENT");
    }

    TEST("fresh ADD after reopen delivers edge for file B");
    EXPECT_TRUE(add_and_expect_edge(epfd, efd),
                "reused fd failed to register/deliver");
    drain_eventfd(efd);
    EXPECT_TRUE(epoll_ctl(epfd, EPOLL_CTL_DEL, efd, NULL) == 0,
                "fresh DEL rejected");
    close(efd);

    /* Case 2: two epoll instances watching the same fd. A close must drop the
     * fd from both interest tables independently -- eager cleanup walks every
     * live instance, not just the one an epoll_ctl happens to touch next.
     */
    int epfd2 = epoll_create1(EPOLL_CLOEXEC);
    TEST("second epoll_create1");
    EXPECT_TRUE(epfd2 >= 0, "epoll_create1 #2 failed");

    int shared = eventfd(0, EFD_NONBLOCK);
    TEST("register shared fd in both instances");
    {
        struct epoll_event ev = {.events = EPOLLIN, .data.fd = shared};
        int ok = shared >= 0 &&
                 epoll_ctl(epfd, EPOLL_CTL_ADD, shared, &ev) == 0 &&
                 epoll_ctl(epfd2, EPOLL_CTL_ADD, shared, &ev) == 0;
        EXPECT_TRUE(ok, "shared registration failed");
    }
    close(shared);
    int shared2 = reopen_same_number(shared);
    TEST("reopen shared fd number");
    EXPECT_EQ(shared2, shared, "could not reuse shared fd number");

    TEST("instance A: stale DEL after reopen -> ENOENT");
    EXPECT_ERRNO(epoll_ctl(epfd, EPOLL_CTL_DEL, shared, NULL), ENOENT,
                 "instance A stale DEL did not report ENOENT");
    TEST("instance B: stale DEL after reopen -> ENOENT");
    EXPECT_ERRNO(epoll_ctl(epfd2, EPOLL_CTL_DEL, shared, NULL), ENOENT,
                 "instance B stale DEL did not report ENOENT");
    close(shared);
    close(epfd2);

    /* Case 3: dup2/dup3 over a registered fd number retires the old open file
     * description without a close syscall (the fd_alloc_at overwrite path). The
     * old registration must be gone -- MOD on it reports ENOENT.
     */
    int a = eventfd(0, EFD_NONBLOCK);
    int b = eventfd(0, EFD_NONBLOCK);
    TEST("register fd, then dup2 another file over it");
    {
        struct epoll_event ev = {.events = EPOLLIN, .data.fd = a};
        int ok = a >= 0 && b >= 0 &&
                 epoll_ctl(epfd, EPOLL_CTL_ADD, a, &ev) == 0 &&
                 dup3(b, a, 0) == a;
        EXPECT_TRUE(ok, "setup for dup2-over-registered failed");
    }
    TEST("MOD after dup2-over-registered -> ENOENT");
    {
        struct epoll_event ev = {.events = EPOLLIN | EPOLLOUT, .data.fd = a};
        EXPECT_ERRNO(epoll_ctl(epfd, EPOLL_CTL_MOD, a, &ev), ENOENT,
                     "MOD on dup2-retired registration did not report ENOENT");
    }
    close(a);
    close(b);
    close(epfd);

    SUMMARY("test-epoll-close");
    return fails > 0 ? 1 : 0;
}
