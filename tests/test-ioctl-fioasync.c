/* FIOASYNC ioctl + F_SETOWN/F_GETOWN fcntl regression test
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * nginx's ngx_spawn_process arms the master->worker channel socket with
 * ioctl(FIOASYNC) immediately followed by fcntl(F_SETOWN), right before fork(),
 * and treats a failure of EITHER as fatal: it logs an alert, ngx_close_channel,
 * and returns NGX_INVALID_PID -- so it never forks the worker. elfuse used to
 * answer FIOASYNC with ENOTTY and F_SETOWN with EINVAL, which silently left the
 * master with zero workers: the listen socket still accepted connections at the
 * host kernel, but nothing in the guest ever accept()ed them, so every request
 * hung. This test pins the fix by replaying that pre-fork channel arming.
 *
 * elfuse does not forward host SIGIO into the guest, and nginx workers receive
 * client I/O and channel commands via epoll rather than SIGIO, so both calls
 * are accepted as no-ops that report success (F_GETOWN reports "no owner", 0).
 *
 * Syscalls exercised: socketpair(199), socket(198), ioctl(29) FIOASYNC,
 * fcntl(25) F_SETOWN/F_GETOWN, getpid(172), close(57)
 */

#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include "test-harness.h"

#ifndef FIOASYNC
#define FIOASYNC 0x5452
#endif
#ifndef F_SETOWN_EX
#define F_SETOWN_EX 15
#endif
#ifndef F_OWNER_PID
#define F_OWNER_PID 1
#endif

/* struct f_owner_ex is _GNU_SOURCE-gated; declare a layout-compatible struct
 * locally so the test does not depend on glibc feature macros. */
struct elfuse_f_owner_ex {
    int type;
    int pid;
};

int passes = 0, fails = 0;

/* Replay nginx's ngx_spawn_process async/owner arming on a single fd. */
static void check_async_owner(int fd, const char *what)
{
    char label[80];
    int on = 1;

    snprintf(label, sizeof(label), "%s: ioctl(FIOASYNC) enable -> 0", what);
    TEST(label);
    EXPECT_EQ(ioctl(fd, FIOASYNC, &on), 0, "FIOASYNC enable rejected");

    snprintf(label, sizeof(label), "%s: fcntl(F_SETOWN) -> 0", what);
    TEST(label);
    EXPECT_EQ(fcntl(fd, F_SETOWN, getpid()), 0, "F_SETOWN rejected");

    /* F_SETOWN_EX takes a struct f_owner_ex* and is the variant glibc uses
     * when targeting a thread/pgrp; a valid pointer is accepted as a no-op. */
    struct elfuse_f_owner_ex owner = {F_OWNER_PID, getpid()};
    snprintf(label, sizeof(label), "%s: fcntl(F_SETOWN_EX) valid -> 0", what);
    TEST(label);
    EXPECT_EQ(fcntl(fd, F_SETOWN_EX, &owner), 0, "F_SETOWN_EX rejected");

    /* F_GETOWN reports the owner; elfuse tracks none, so 0 (no error). glibc
     * may probe F_GETOWN_EX first and fall back to plain F_GETOWN on EINVAL --
     * either way the visible result must not be a failure. */
    snprintf(label, sizeof(label), "%s: fcntl(F_GETOWN) -> not an error", what);
    TEST(label);
    EXPECT_TRUE(fcntl(fd, F_GETOWN) >= 0, "F_GETOWN returned an error");

    on = 0;
    snprintf(label, sizeof(label), "%s: ioctl(FIOASYNC) disable -> 0", what);
    TEST(label);
    EXPECT_EQ(ioctl(fd, FIOASYNC, &on), 0, "FIOASYNC disable rejected");
}

int main(void)
{
    printf("test-ioctl-fioasync: FIOASYNC ioctl + F_SETOWN/F_GETOWN fcntl\n");

    /* nginx's channel is an AF_UNIX SOCK_STREAM socketpair; FIOASYNC/F_SETOWN
     * are applied to channel[0] (nginx also marks it non-blocking via FIONBIO
     * first, which this test omits to stay focused on the calls added here). */
    int sp[2];
    TEST("socketpair(AF_UNIX, SOCK_STREAM)");
    EXPECT_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, sp), 0, "socketpair failed");

    check_async_owner(sp[0], "unix socketpair");

    close(sp[0]);
    close(sp[1]);

    /* A plain TCP socket too -- the same family as nginx's listen sockets. */
    int s = socket(AF_INET, SOCK_STREAM, 0);
    TEST("socket(AF_INET, SOCK_STREAM)");
    EXPECT_TRUE(s >= 0, "socket failed");
    if (s >= 0) {
        check_async_owner(s, "tcp socket");

        /* F_SETOWN_EX reads the struct before applying, so a bad guest pointer
         * must fault with EFAULT rather than silently succeeding (the no-op
         * owner path used to skip the read entirely). Page 0 is never mapped.
         */
        TEST("fcntl(F_SETOWN_EX) bad pointer -> EFAULT");
        EXPECT_ERRNO(fcntl(s, F_SETOWN_EX, (struct elfuse_f_owner_ex *) 16),
                     EFAULT,
                     "F_SETOWN_EX with bad pointer did not fail with EFAULT");

        close(s);
    }

    SUMMARY("test-ioctl-fioasync");
    return fails > 0 ? 1 : 0;
}
