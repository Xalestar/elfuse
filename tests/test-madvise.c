/* MADV_DONTNEED semantics tests
 *
 * Copyright 2026 elfuse contributors
 * Copyright 2025 Moritz Angermann, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Tests: MADV_DONTNEED zero-fill guarantee, page-aligned and
 *        multi-page ranges, advisory hints accepted.
 *
 * Syscalls exercised: mmap(222), madvise(233), munmap(215)
 */

#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "test-harness.h"

int passes = 0, fails = 0;

/* Test 1: MADV_DONTNEED zeros a single page */

static void test_dontneed_single(void)
{
    TEST("MADV_DONTNEED single page");
    void *p = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) {
        FAIL("mmap failed");
        return;
    }

    /* Write a pattern */
    memset(p, 0xAA, 4096);

    /* MADV_DONTNEED should zero the page */
    if (madvise(p, 4096, MADV_DONTNEED) != 0) {
        FAIL("madvise failed");
        munmap(p, 4096);
        return;
    }

    /* Verify zero-fill */
    unsigned char *cp = (unsigned char *) p;
    bool ok = true;
    for (int i = 0; i < 4096; i++) {
        if (cp[i] != 0) {
            ok = false;
            break;
        }
    }

    EXPECT_TRUE(ok, "page not zeroed after MADV_DONTNEED");

    munmap(p, 4096);
}

/* Test 2: MADV_DONTNEED multi-page span */

static void test_dontneed_multi(void)
{
    TEST("MADV_DONTNEED multi-page");
    size_t sz = 4096 * 16;
    void *p = mmap(NULL, sz, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) {
        FAIL("mmap failed");
        return;
    }

    /* Fill with non-zero */
    memset(p, 0xBB, sz);

    /* DONTNEED the entire range */
    if (madvise(p, sz, MADV_DONTNEED) != 0) {
        FAIL("madvise failed");
        munmap(p, sz);
        return;
    }

    /* Verify all zeroed */
    unsigned char *cp = (unsigned char *) p;
    bool ok = true;
    for (size_t i = 0; i < sz; i++) {
        if (cp[i] != 0) {
            ok = false;
            break;
        }
    }

    EXPECT_TRUE(ok, "multi-page not zeroed");

    munmap(p, sz);
}

/* Test 3: partial range within a mapping */

static void test_dontneed_partial(void)
{
    TEST("MADV_DONTNEED partial range");
    size_t sz = 4096 * 4;
    void *p = mmap(NULL, sz, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) {
        FAIL("mmap failed");
        return;
    }

    memset(p, 0xCC, sz);

    /* Only DONTNEED pages 1-2 (leave page 0 and 3 intact) */
    if (madvise((char *) p + 4096, 4096 * 2, MADV_DONTNEED) != 0) {
        FAIL("madvise failed");
        munmap(p, sz);
        return;
    }

    unsigned char *cp = (unsigned char *) p;
    bool ok = true;

    /* Page 0: should still be 0xCC */
    for (int i = 0; i < 4096; i++) {
        if (cp[i] != 0xCC) {
            ok = false;
            break;
        }
    }
    /* Pages 1-2: should be zeroed */
    for (int i = 4096; i < 4096 * 3; i++) {
        if (cp[i] != 0) {
            ok = false;
            break;
        }
    }
    /* Page 3: should still be 0xCC */
    for (int i = 4096 * 3; i < (int) sz; i++) {
        if (cp[i] != 0xCC) {
            ok = false;
            break;
        }
    }

    EXPECT_TRUE(ok, "partial DONTNEED corrupted adjacent pages");

    munmap(p, sz);
}

/* Test 4: write-after-DONTNEED works */

static void test_dontneed_rewrite(void)
{
    TEST("MADV_DONTNEED then rewrite");
    void *p = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) {
        FAIL("mmap failed");
        return;
    }

    memset(p, 0xDD, 4096);
    madvise(p, 4096, MADV_DONTNEED);

    /* Write new data after DONTNEED */
    memset(p, 0xEE, 4096);

    unsigned char *cp = (unsigned char *) p;
    bool ok = true;
    for (int i = 0; i < 4096; i++) {
        if (cp[i] != 0xEE) {
            ok = false;
            break;
        }
    }

    EXPECT_TRUE(ok, "rewrite after DONTNEED failed");

    munmap(p, 4096);
}

/* Test 5: advisory hints accepted */

static void test_advisory_hints(void)
{
    TEST("madvise advisory hints");
    void *p = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) {
        FAIL("mmap failed");
        return;
    }

    bool ok = true;
    if (madvise(p, 4096, MADV_NORMAL) != 0)
        ok = false;
    if (madvise(p, 4096, MADV_RANDOM) != 0)
        ok = false;
    if (madvise(p, 4096, MADV_SEQUENTIAL) != 0)
        ok = false;
    if (madvise(p, 4096, MADV_WILLNEED) != 0)
        ok = false;

    EXPECT_TRUE(ok, "advisory hint rejected");

    munmap(p, 4096);
}

/* Test 6: large MADV_DONTNEED (jemalloc pattern) */

static void test_dontneed_large(void)
{
    TEST("MADV_DONTNEED 1MiB range");
    size_t sz = 1024 * 1024;
    void *p = mmap(NULL, sz, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) {
        FAIL("mmap failed");
        return;
    }

    memset(p, 0xFF, sz);

    if (madvise(p, sz, MADV_DONTNEED) != 0) {
        FAIL("madvise failed");
        munmap(p, sz);
        return;
    }

    /* Spot-check zeroed */
    unsigned char *cp = (unsigned char *) p;
    bool ok = true;
    for (size_t i = 0; i < sz; i += 4096) {
        if (cp[i] != 0) {
            ok = false;
            break;
        }
    }

    EXPECT_TRUE(ok, "1MiB range not zeroed");

    munmap(p, sz);
}

/* Test 7: unaligned address rejected */

static void test_dontneed_unaligned(void)
{
    TEST("madvise unaligned addr rejected");
    void *p = mmap(NULL, 4096 * 2, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) {
        FAIL("mmap failed");
        return;
    }

    /* Unaligned address should fail */
    int ret = madvise((char *) p + 1, 4096, MADV_DONTNEED);
    EXPECT_TRUE(ret != 0, "should reject unaligned address");

    munmap(p, 4096 * 2);
}

/* Test 8: file-backed private mappings keep file contents */

static void test_dontneed_file_backed(void)
{
    TEST("MADV_DONTNEED file-backed mapping");

    char template[] = "/tmp/elfuse-madvise-XXXXXX";
    int fd = mkstemp(template);
    if (fd < 0) {
        FAIL("mkstemp failed");
        return;
    }
    unlink(template);

    unsigned char pattern[4096];
    memset(pattern, 0x5A, sizeof(pattern));
    if (write(fd, pattern, sizeof(pattern)) != (ssize_t) sizeof(pattern)) {
        FAIL("write failed");
        close(fd);
        return;
    }

    void *p = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, fd, 0);
    if (p == MAP_FAILED) {
        FAIL("mmap file failed");
        close(fd);
        return;
    }

    if (madvise(p, 4096, MADV_DONTNEED) != 0) {
        FAIL("madvise failed");
        munmap(p, 4096);
        close(fd);
        return;
    }

    unsigned char *cp = (unsigned char *) p;
    bool ok = true;
    for (int i = 0; i < 4096; i++) {
        if (cp[i] != 0x5A) {
            ok = false;
            break;
        }
    }

    EXPECT_TRUE(ok, "file-backed contents were zeroed");

    munmap(p, 4096);
    close(fd);
}

int main(void)
{
    printf("test-madvise: MADV_DONTNEED semantics tests\n");

    test_dontneed_single();
    test_dontneed_multi();
    test_dontneed_partial();
    test_dontneed_rewrite();
    test_advisory_hints();
    test_dontneed_large();
    test_dontneed_unaligned();
    test_dontneed_file_backed();

    SUMMARY("test-madvise");
    return fails > 0 ? 1 : 0;
}
