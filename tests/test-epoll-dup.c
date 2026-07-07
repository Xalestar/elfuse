/*
 * epoll fd dup shares the eventpoll instance
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Linux dup(2)/dup3(2)/F_DUPFD of an epoll fd yield a second descriptor onto
 * the SAME eventpoll instance: the interest list registered through one fd is
 * visible through the other, and the instance survives until the last of them
 * closes. elfuse keys epoll state on fd_table[epfd].dir; the generic dup path
 * would leave the alias with dir == NULL, so this pins that epoll_dup_fd()
 * shares the instance instead (src/syscall/poll.c epoll_dup_fd).
 *
 * Syscalls exercised: epoll_create1(20), epoll_ctl(21), epoll_pwait(22),
 *                     eventfd2(19), dup(23), dup3(24), fcntl(25),
 *                     write(64), read(63), close(57)
 */

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>

#include "test-harness.h"

int passes = 0, fails = 0;

static void drain_eventfd(int fd)
{
    uint64_t v;
    (void) !read(fd, &v, sizeof(v));
}

/* Signal fd and assert epoll_wait on wait_fd reports exactly its edge. */
static int expect_edge(int wait_fd, int fd)
{
    uint64_t one = 1;
    if (write(fd, &one, sizeof(one)) != (ssize_t) sizeof(one))
        return 0;
    struct epoll_event out[4];
    int n = epoll_wait(wait_fd, out, 4, 2000);
    int ok = n == 1 && out[0].data.fd == fd;
    drain_eventfd(fd);
    return ok;
}

int main(void)
{
    printf("test-epoll-dup: epoll fd dup shares the eventpoll instance\n");

    int epfd = epoll_create1(EPOLL_CLOEXEC);
    TEST("epoll_create1");
    EXPECT_TRUE(epfd >= 0, "epoll_create1 failed");

    int efd = eventfd(0, EFD_NONBLOCK);
    TEST("eventfd");
    EXPECT_TRUE(efd >= 0, "eventfd failed");

    /* Register through the original fd, wait through the dup: they must share
     * the interest list.
     */
    int dupfd = dup(epfd);
    TEST("dup(epfd)");
    EXPECT_TRUE(dupfd >= 0 && dupfd != epfd, "dup failed");

    {
        struct epoll_event ev = {.events = EPOLLIN, .data.fd = efd};
        EXPECT_TRUE(epoll_ctl(epfd, EPOLL_CTL_ADD, efd, &ev) == 0,
                    "ADD via original failed");
    }
    TEST("edge registered via original is visible through the dup");
    EXPECT_TRUE(expect_edge(dupfd, efd), "dup did not see shared registration");

    /* Mutate the interest list through the dup, observe through the original.
     */
    TEST("MOD via dup, then DEL via original -> instance is shared");
    {
        struct epoll_event ev = {.events = EPOLLIN | EPOLLOUT, .data.fd = efd};
        int ok = epoll_ctl(dupfd, EPOLL_CTL_MOD, efd, &ev) == 0 &&
                 epoll_ctl(epfd, EPOLL_CTL_DEL, efd, NULL) == 0;
        EXPECT_TRUE(ok, "MOD/DEL across dup did not target one instance");
    }

    /* A duped-but-not-registered fd must report ENOENT on DEL, proving the dup
     * really reaches a valid (shared, now-empty) instance rather than failing
     * as a NULL-dir slot (which would give EBADF/EINVAL).
     */
    TEST("DEL of unregistered fd via dup -> ENOENT");
    EXPECT_ERRNO(epoll_ctl(dupfd, EPOLL_CTL_DEL, efd, NULL), ENOENT,
                 "dup slot is not a live epoll instance");

    /* Closing the original must keep the instance alive for the dup. */
    close(epfd);
    {
        struct epoll_event ev = {.events = EPOLLIN, .data.fd = efd};
        TEST("dup still works after original closes");
        EXPECT_TRUE(epoll_ctl(dupfd, EPOLL_CTL_ADD, efd, &ev) == 0,
                    "dup broke after original close");
    }
    TEST("edge delivery through dup after original close");
    EXPECT_TRUE(expect_edge(dupfd, efd), "dup lost delivery after close");
    close(dupfd);

    /* fcntl(F_DUPFD) and dup3 to a fixed high slot exercise the min-slot and
     * fixed-slot allocator branches of epoll_dup_fd.
     */
    int ep2 = epoll_create1(0);
    TEST("second epoll_create1");
    EXPECT_TRUE(ep2 >= 0, "epoll_create1 #2 failed");

    int dupf = fcntl(ep2, F_DUPFD, 100);
    TEST("fcntl(F_DUPFD, 100)");
    EXPECT_TRUE(dupf >= 100, "F_DUPFD failed");

    int fixed = dup3(ep2, 150, O_CLOEXEC);
    TEST("dup3 to fixed slot 150");
    EXPECT_TRUE(fixed == 150, "dup3 to fixed slot failed");

    {
        struct epoll_event ev = {.events = EPOLLIN, .data.fd = efd};
        TEST("register via ep2, observe through both alias fds");
        int ok = epoll_ctl(ep2, EPOLL_CTL_ADD, efd, &ev) == 0;
        EXPECT_TRUE(ok, "ADD via ep2 failed");
    }
    TEST("F_DUPFD alias sees ep2 registration");
    EXPECT_TRUE(expect_edge(dupf, efd), "F_DUPFD alias missed edge");
    TEST("dup3 fixed alias sees ep2 registration");
    EXPECT_TRUE(expect_edge(fixed, efd), "dup3 alias missed edge");

    close(dupf);
    close(fixed);
    close(ep2);
    close(efd);

    SUMMARY("test-epoll-dup");
    return fails > 0 ? 1 : 0;
}
