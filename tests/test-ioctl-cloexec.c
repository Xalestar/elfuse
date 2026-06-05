/* FIOCLEX/FIONCLEX ioctl close-on-exec regression test
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * FIOCLEX/FIONCLEX are the ioctl form of fcntl(F_SETFD): they set/clear the
 * close-on-exec flag and take no real host fd. Two properties are covered:
 *
 *   1. Toggling round-trips: after ioctl(FIOCLEX) the flag reads back via
 *      fcntl(F_GETFD), and ioctl(FIONCLEX) clears it again.
 *
 *   2. O_PATH descriptors are accepted. Linux permits FIOCLEX/FIONCLEX (like
 *      fcntl(F_SETFD)) on O_PATH fds; elfuse used to route every ioctl through
 *      the regular-IO host-fd open, which rejects O_PATH with EBADF, so the two
 *      cloexec ioctls now dispatch before that gate.
 *
 * Syscalls exercised: openat(56), ioctl(29), fcntl(25), close(57)
 */

#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include "test-harness.h"

#ifndef O_PATH
#define O_PATH 010000000
#endif
#ifndef FIOCLEX
#define FIOCLEX 0x5451
#endif
#ifndef FIONCLEX
#define FIONCLEX 0x5450
#endif

int passes = 0, fails = 0;

/* Run the FIOCLEX -> FIONCLEX toggle round-trip on an already-open fd. */
static void check_cloexec_toggle(int fd, const char *what)
{
    char label[64];

    snprintf(label, sizeof(label), "%s: starts without cloexec", what);
    TEST(label);
    EXPECT_EQ(fcntl(fd, F_GETFD) & FD_CLOEXEC, 0, "expected cloexec clear");

    snprintf(label, sizeof(label), "%s: ioctl(FIOCLEX) sets cloexec", what);
    TEST(label);
    EXPECT_TRUE(ioctl(fd, FIOCLEX) == 0 && (fcntl(fd, F_GETFD) & FD_CLOEXEC),
                "FIOCLEX did not set cloexec");

    snprintf(label, sizeof(label), "%s: ioctl(FIONCLEX) clears cloexec", what);
    TEST(label);
    EXPECT_TRUE(
        ioctl(fd, FIONCLEX) == 0 && (fcntl(fd, F_GETFD) & FD_CLOEXEC) == 0,
        "FIONCLEX did not clear cloexec");
}

int main(void)
{
    printf("test-ioctl-cloexec: FIOCLEX/FIONCLEX close-on-exec\n");

    /* A plain readable fd: the ordinary path. */
    int rfd = open("/", O_RDONLY | O_DIRECTORY);
    TEST("open(/) O_RDONLY");
    EXPECT_TRUE(rfd >= 0, "open failed");
    if (rfd >= 0) {
        check_cloexec_toggle(rfd, "regular fd");
        close(rfd);
    }

    /* An O_PATH fd: must be accepted, not rejected with EBADF. */
    int pfd = open("/", O_PATH | O_DIRECTORY);
    TEST("open(/) O_PATH");
    EXPECT_TRUE(pfd >= 0, "open O_PATH failed");
    if (pfd >= 0) {
        check_cloexec_toggle(pfd, "O_PATH fd");
        close(pfd);
    }

    SUMMARY("test-ioctl-cloexec");
    return fails > 0 ? 1 : 0;
}
