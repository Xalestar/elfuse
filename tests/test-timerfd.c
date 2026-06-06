/* Test timerfd emulation (kqueue backend)
 *
 * Copyright 2026 elfuse contributors
 * Copyright 2025 Moritz Angermann, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Tests: timerfd_create, timerfd_settime (one-shot + interval),
 *        timerfd_gettime, read expiration count, poll readiness
 *
 * Syscalls exercised: timerfd_create(85), timerfd_settime(86),
 *                     timerfd_gettime(87), read(63), ppoll(73), close(57),
 *                     nanosleep(101)
 */

#include <stdint.h>
#include <unistd.h>
#include <time.h>
#include <poll.h>
#include <fcntl.h>
#include <sys/timerfd.h>

#include "test-harness.h"

int main(void)
{
    int passes = 0, fails = 0;

    printf("test-timerfd: timerfd emulation tests\n");

    /* Test timerfd_create */
    TEST("timerfd_create");
    {
        int fd = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC);
        EXPECT_TRUE(fd >= 0, "timerfd_create failed");
        close(fd);
    }

    /* Test one-shot timer: 20ms, then read expiration count */
    TEST("one-shot 20ms timer");
    {
        int fd = timerfd_create(CLOCK_MONOTONIC, 0);
        if (fd >= 0) {
            struct itimerspec its = {
                .it_value = {.tv_sec = 0, .tv_nsec = 20000000}, /* 20ms */
                .it_interval = {0, 0}};
            if (timerfd_settime(fd, 0, &its, NULL) == 0) {
                usleep(50000); /* 50ms, plenty of time */
                uint64_t count = 0;
                ssize_t r = read(fd, &count, sizeof(count));
                EXPECT_TRUE(r == 8 && count >= 1, "read failed or count=0");
            } else
                FAIL("timerfd_settime failed");
            close(fd);
        } else
            FAIL("timerfd_create failed");
    }

    /* Test timerfd_gettime: one-shot interval should be 0 after expiry */
    TEST("timerfd_gettime after expiry");
    {
        int fd = timerfd_create(CLOCK_MONOTONIC, 0);
        if (fd >= 0) {
            struct itimerspec its = {
                .it_value = {.tv_sec = 0, .tv_nsec = 10000000}, /* 10ms */
                .it_interval = {0, 0}};
            timerfd_settime(fd, 0, &its, NULL);
            usleep(30000); /* 30ms */

            /* Drain the expiration */
            uint64_t count;
            read(fd, &count, sizeof(count));

            struct itimerspec cur;
            if (timerfd_gettime(fd, &cur) == 0) {
                EXPECT_TRUE(
                    cur.it_interval.tv_sec == 0 && cur.it_interval.tv_nsec == 0,
                    "interval not zero for one-shot");
            } else
                FAIL("timerfd_gettime failed");
            close(fd);
        } else
            FAIL("timerfd_create failed");
    }

    /* Test interval timer: 20ms interval, wait ~90ms, expect 3-5 fires */
    TEST("interval timer (20ms x~4)");
    {
        int fd = timerfd_create(CLOCK_MONOTONIC, 0);
        if (fd >= 0) {
            struct itimerspec its = {
                .it_value = {.tv_sec = 0, .tv_nsec = 20000000},   /* 20ms */
                .it_interval = {.tv_sec = 0, .tv_nsec = 20000000} /* 20ms */
            };
            if (timerfd_settime(fd, 0, &its, NULL) == 0) {
                usleep(90000); /* 90ms */
                uint64_t count = 0;
                ssize_t r = read(fd, &count, sizeof(count));
                EXPECT_TRUE(r == 8 && count >= 2, "interval count wrong");
            } else
                FAIL("timerfd_settime failed");
            close(fd);
        } else
            FAIL("timerfd_create failed");
    }

    /* Test poll on timerfd: should report POLLIN after timer fires */
    TEST("poll on timerfd");
    {
        int fd = timerfd_create(CLOCK_MONOTONIC, 0);
        if (fd >= 0) {
            struct itimerspec its = {
                .it_value = {.tv_sec = 0, .tv_nsec = 10000000}, /* 10ms */
                .it_interval = {0, 0}};
            timerfd_settime(fd, 0, &its, NULL);

            struct pollfd pfd = {.fd = fd, .events = POLLIN};
            int ret = poll(&pfd, 1, 200); /* 200ms timeout */
            EXPECT_TRUE(ret > 0 && (pfd.revents & POLLIN),
                        "poll did not report POLLIN");
            close(fd);
        } else
            FAIL("timerfd_create failed");
    }

    TEST("absolute monotonic timer");
    {
        int fd = timerfd_create(CLOCK_MONOTONIC, 0);
        if (fd >= 0) {
            struct timespec now;
            clock_gettime(CLOCK_MONOTONIC, &now);
            struct itimerspec its = {
                .it_value = {.tv_sec = now.tv_sec,
                             .tv_nsec = now.tv_nsec + 20000000},
                .it_interval = {0, 0}};
            if (its.it_value.tv_nsec >= 1000000000L) {
                its.it_value.tv_sec++;
                its.it_value.tv_nsec -= 1000000000L;
            }
            if (timerfd_settime(fd, TFD_TIMER_ABSTIME, &its, NULL) == 0) {
                usleep(50000);
                uint64_t count = 0;
                ssize_t r = read(fd, &count, sizeof(count));
                EXPECT_TRUE(r == 8 && count >= 1,
                            "absolute timer did not fire");
            } else
                FAIL("timerfd_settime ABSTIME failed");
            close(fd);
        } else
            FAIL("timerfd_create failed");
    }

    /* CLOCK_BOOTTIME backs foot's keyboard repeat timer; on macOS it
     * resolves to CLOCK_MONOTONIC since no boottime equivalent exists.
     * Paired with TFD_NONBLOCK to mirror foot's actual call.
     */
    TEST("create accepts CLOCK_BOOTTIME with TFD_NONBLOCK");
    {
        int fd = timerfd_create(CLOCK_BOOTTIME, TFD_CLOEXEC | TFD_NONBLOCK);
        EXPECT_TRUE(fd >= 0, "timerfd_create(CLOCK_BOOTTIME) failed");
        if (fd >= 0)
            close(fd);
    }

    /* NONBLOCK shadow: the kqueue host fd cannot carry O_NONBLOCK, so the
     * flag lives in fd_table[gfd].linux_flags. Arm with a 1s deadline so
     * the read is non-trivially blocked, then verify EAGAIN comes from the
     * NONBLOCK path; an unarmed timer would also return EAGAIN, so the arm
     * step is what makes this a real probe of the shadow.
     */
    TEST("NONBLOCK: armed-but-unfired returns EAGAIN");
    {
        int fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
        if (fd >= 0) {
            struct itimerspec its = {.it_value = {.tv_sec = 1, .tv_nsec = 0},
                                     .it_interval = {0, 0}};
            EXPECT_TRUE(timerfd_settime(fd, 0, &its, NULL) == 0,
                        "settime failed");
            uint64_t count = 0;
            errno = 0;
            ssize_t r = read(fd, &count, sizeof(count));
            EXPECT_TRUE(r == -1 && errno == EAGAIN,
                        "non-blocking read did not return EAGAIN");
            close(fd);
        } else
            FAIL("timerfd_create");
    }

    /* fcntl coherence: F_GETFL must surface O_RDWR plus the writable bits
     * Linux honors on a timerfd (O_APPEND, O_NONBLOCK, O_NOATIME).
     * F_SETFL persists the writable bits and silently drops everything
     * else; O_DIRECT returns EINVAL.
     */
    TEST("fcntl F_GETFL/F_SETFL match Linux setfl semantics");
    {
        int fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
        if (fd >= 0) {
            int fl = fcntl(fd, F_GETFL);
            EXPECT_TRUE(
                fl >= 0 && (fl & O_NONBLOCK) && (fl & O_ACCMODE) == O_RDWR,
                "F_GETFL did not surface O_RDWR | O_NONBLOCK");

            /* Stray O_CLOEXEC and O_WRONLY must not land in the shadow. */
            EXPECT_TRUE(
                fcntl(fd, F_SETFL,
                      O_APPEND | O_NONBLOCK | O_WRONLY | O_CLOEXEC) == 0,
                "F_SETFL accepted-plus-stray bits failed");
            fl = fcntl(fd, F_GETFL);
            EXPECT_TRUE(fl >= 0 && (fl & O_APPEND) && (fl & O_NONBLOCK) &&
                            (fl & O_ACCMODE) == O_RDWR && !(fl & O_CLOEXEC),
                        "F_GETFL leaked stray F_SETFL bits");

            errno = 0;
            EXPECT_TRUE(
                fcntl(fd, F_SETFL, fl | O_DIRECT) == -1 && errno == EINVAL,
                "F_SETFL accepted unsupported O_DIRECT");

            /* Round-trip O_NOATIME. */
            EXPECT_TRUE(fcntl(fd, F_SETFL, O_NOATIME) == 0,
                        "F_SETFL O_NOATIME failed");
            fl = fcntl(fd, F_GETFL);
            EXPECT_TRUE(fl >= 0 && (fl & O_NOATIME),
                        "F_GETFL did not surface O_NOATIME");
            close(fd);
        } else
            FAIL("timerfd_create");
    }

    /* dup must carry the linux_flags shadow's NONBLOCK bit through; without
     * the preserved-mask fix the new fd's F_GETFL would report blocking.
     * (The timerfd slot table is keyed by guest_fd with no alias support,
     * so read/settime through the dup return EBADF -- that pre-existing
     * limitation is outside #82's scope.)
     */
    TEST("dup preserves O_NONBLOCK and O_RDWR in linux_flags");
    {
        int fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
        if (fd >= 0) {
            int dfd = dup(fd);
            EXPECT_TRUE(dfd >= 0, "dup failed");
            if (dfd >= 0) {
                int fl = fcntl(dfd, F_GETFL);
                EXPECT_TRUE(
                    fl >= 0 && (fl & O_NONBLOCK) && (fl & O_ACCMODE) == O_RDWR,
                    "dup lost O_NONBLOCK or O_RDWR");
                close(dfd);
            }
            close(fd);
        } else
            FAIL("timerfd_create");
    }

    TEST("timerfd_create invalid clock");
    EXPECT_ERRNO(timerfd_create(9999, 0), EINVAL, "expected EINVAL");

    TEST("timerfd_create invalid flags");
    EXPECT_ERRNO(timerfd_create(CLOCK_MONOTONIC, 0x40000000), EINVAL,
                 "expected EINVAL");

    SUMMARY("test-timerfd");
    return fails > 0 ? 1 : 0;
}
