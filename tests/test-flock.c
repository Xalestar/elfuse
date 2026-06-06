/* Test POSIX advisory record locking via fcntl(F_SETLK/F_GETLK/F_SETLKW)
 *
 * Copyright 2026 elfuse contributors
 * Copyright 2025 Moritz Angermann, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Regression coverage for the Linux<->macOS struct flock translation. The
 * l_type constants differ between the two ABIs (Linux F_RDLCK=0/F_WRLCK=1,
 * macOS F_RDLCK=1/F_WRLCK=3), so passing the guest value straight through to
 * the host made the very first lock SQLite takes (a shared F_RDLCK) fail with
 * EINVAL and surface as "disk I/O error". The byte offsets below mirror the
 * ones SQLite locks around its 1GiB "pending byte".
 */

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "test-harness.h"

#define PENDING_BYTE 0x40000000L
#define RESERVED_BYTE (PENDING_BYTE + 1)
#define SHARED_FIRST (PENDING_BYTE + 2)
#define SHARED_SIZE 510

static int set_lock(int fd, short type, off_t start, off_t len)
{
    struct flock fl = {
        .l_type = type,
        .l_whence = SEEK_SET,
        .l_start = start,
        .l_len = len,
    };
    return fcntl(fd, F_SETLK, &fl);
}

int main(void)
{
    int passes = 0, fails = 0;
    const char *path = "/tmp/elfuse-test-flock.db";

    int fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        perror("open");
        return 1;
    }

    /* Shared read lock -- this is the call that regressed to EINVAL. */
    TEST("F_SETLK F_RDLCK (shared)");
    EXPECT_EQ(set_lock(fd, F_RDLCK, SHARED_FIRST, SHARED_SIZE), 0,
              "shared read lock rejected");

    /* Promote the pending byte to a write lock, then drop it. */
    TEST("F_SETLK F_WRLCK (pending)");
    EXPECT_EQ(set_lock(fd, F_WRLCK, PENDING_BYTE, 1), 0,
              "pending write lock rejected");

    TEST("F_SETLK F_WRLCK (reserved)");
    EXPECT_EQ(set_lock(fd, F_WRLCK, RESERVED_BYTE, 1), 0,
              "reserved write lock rejected");

    TEST("F_SETLK F_UNLCK (release shared)");
    EXPECT_EQ(set_lock(fd, F_UNLCK, SHARED_FIRST, SHARED_SIZE), 0,
              "unlock rejected");

    /* Blocking variant must take the same translation path. */
    TEST("F_SETLKW F_WRLCK");
    struct flock wfl = {
        .l_type = F_WRLCK,
        .l_whence = SEEK_SET,
        .l_start = 0,
        .l_len = 16,
    };
    EXPECT_EQ(fcntl(fd, F_SETLKW, &wfl), 0, "F_SETLKW rejected");

    /* F_GETLK on a region this process already write-locks must report back a
     * Linux l_type. Linux reports F_UNLCK for locks held by the *same* owner,
     * so the only thing we can assert portably is that the type round-trips to
     * a valid Linux constant and the call succeeds. */
    TEST("F_GETLK round-trips l_type");
    struct flock gfl = {
        .l_type = F_WRLCK,
        .l_whence = SEEK_SET,
        .l_start = 0,
        .l_len = 16,
    };
    int gr = fcntl(fd, F_GETLK, &gfl);
    EXPECT_TRUE(gr == 0 && (gfl.l_type == F_UNLCK || gfl.l_type == F_RDLCK ||
                            gfl.l_type == F_WRLCK),
                "F_GETLK returned an invalid l_type");

    close(fd);
    unlink(path);

    SUMMARY("test-flock");
    return fails == 0 ? 0 : 1;
}
