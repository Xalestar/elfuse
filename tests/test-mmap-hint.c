/* Low-address mmap hint regression test
 *
 * Copyright 2026 elfuse contributors
 * Copyright 2025 Moritz Angermann, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Verifies that non-fixed anonymous mmap() honors a free low address hint such
 * as 0x400000. box64 uses this pattern to reserve the ET_EXEC image window for
 * static x86-64 binaries.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>

#include "test-harness.h"

#ifndef MAP_FIXED_NOREPLACE
#define MAP_FIXED_NOREPLACE 0x100000
#endif

int passes = 0, fails = 0;

static void *reserve_free_low_hint(size_t len)
{
    static const uintptr_t candidates[] = {
        0x00400000ULL, 0x00800000ULL, 0x01000000ULL,
        0x02000000ULL, 0x04000000ULL, 0x06000000ULL,
    };

    for (size_t i = 0; i < sizeof(candidates) / sizeof(candidates[0]); i++) {
        void *hint = (void *) candidates[i];
        void *p =
            mmap(hint, len, PROT_NONE,
                 MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
        if (p == MAP_FAILED) {
            if (errno == EEXIST || errno == EINVAL)
                continue;
            return MAP_FAILED;
        }
        return p;
    }

    errno = ENOMEM;
    return MAP_FAILED;
}

static void test_low_hint_exact(void)
{
    TEST("mmap low hint preserves ET_EXEC-style address");

    size_t len = 0x21000;
    void *hint = reserve_free_low_hint(len);
    if (hint == MAP_FAILED) {
        FAIL("no free low hint candidate");
        return;
    }
    munmap(hint, len);

    void *p = mmap(hint, len, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) {
        FAIL("mmap failed");
        return;
    }

    EXPECT_TRUE((uintptr_t) p == (uintptr_t) hint,
                "low mmap hint should be honored when range is free");
    munmap(p, len);
}

static void test_shared_file_hint_falls_back_from_2m_alignment(void)
{
    TEST("MAP_SHARED file hint falls back from 2MiB alignment");

    const size_t page = (size_t) sysconf(_SC_PAGESIZE);
    const uintptr_t block_2m = 2ULL * 1024ULL * 1024ULL;

    void *anchor =
        mmap(NULL, page, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (anchor == MAP_FAILED) {
        FAIL("anchor mmap failed");
        return;
    }

    uintptr_t anchor_addr = (uintptr_t) anchor;
    uintptr_t anchor_block = anchor_addr & ~(block_2m - 1);
    if (anchor_addr != anchor_block) {
        munmap(anchor, page);
        FAIL("anchor not 2MiB-aligned");
        return;
    }
    if (anchor_block < 0x00400000ULL + 0x10000ULL) {
        munmap(anchor, page);
        FAIL("anchor too low for regression hint");
        return;
    }
    uintptr_t hint_addr = anchor_block - 0x10000ULL;

    char path[] = "/tmp/elfuse-mmap-hint-XXXXXX";
    int fd = mkstemp(path);
    if (fd < 0) {
        munmap(anchor, page);
        FAIL("mkstemp failed");
        return;
    }
    unlink(path);

    if (ftruncate(fd, (off_t) page) < 0) {
        close(fd);
        munmap(anchor, page);
        FAIL("ftruncate failed");
        return;
    }

    void *hint = (void *) hint_addr;
    void *p = mmap(hint, page, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (p == MAP_FAILED) {
        close(fd);
        munmap(anchor, page);
        FAIL("shared file mmap failed");
        return;
    }

    EXPECT_TRUE((uintptr_t) p == hint_addr,
                "shared file mmap should honor host-page-aligned hint");

    munmap(p, page);
    close(fd);
    munmap(anchor, page);
}

int main(void)
{
    test_low_hint_exact();
    test_shared_file_hint_falls_back_from_2m_alignment();
    SUMMARY("test-mmap-hint");
    return fails ? 1 : 0;
}
