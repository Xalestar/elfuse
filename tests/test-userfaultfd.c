/*
 * userfaultfd syscall tests
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Syscalls exercised: userfaultfd(282)
 */

#include "test-harness.h"
#include "raw-syscall.h"

#ifndef SYS_userfaultfd
#define SYS_userfaultfd 282
#endif

int passes = 0, fails = 0;

static long raw_userfaultfd(unsigned long flags)
{
    return raw_syscall1(SYS_userfaultfd, (long) flags);
}

int main(void)
{
    printf("test-userfaultfd: userfaultfd syscall tests\n\n");

    TEST("userfaultfd unsupported");
    EXPECT_RAW_ERRNO(raw_userfaultfd(0), -ENOSYS, "expected -ENOSYS");

    TEST("userfaultfd flags unsupported");
    EXPECT_RAW_ERRNO(raw_userfaultfd(0x40000000UL), -ENOSYS,
                     "expected -ENOSYS");

    SUMMARY("test-userfaultfd");
    return fails > 0 ? 1 : 0;
}
