/* Low-linked ET_EXEC memory-syscall regression test
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Validates that sys_mprotect, sys_munmap, and the page-table build path
 * accept operations from an ET_EXEC linked below ELF_DEFAULT_BASE
 * (0x400000). The legacy layout pinned page-table pool + shim at fixed
 * low addresses [0x10000, 0x400000) and the four infra-range guards
 * (sys_mmap MAP_FIXED, sys_munmap, sys_mprotect, rt_sigreturn) blanket-
 * rejected operations on [SHIM_BASE, ELF_DEFAULT_BASE), so a low-linked
 * binary could not RELRO its own data or munmap anything in the same
 * window. The fix relocated infra to [interp_base - 4 MiB, interp_base)
 * and retargeted the guards via guest_range_hits_infra.
 *
 * Two link addresses are exercised:
 *   - 0x200000: inside the legacy shim_data block, was rejected.
 *   - 0x300000: also inside [SHIM_BASE, ELF_DEFAULT_BASE); catches an
 *     off-by-one if a future patch ever re-introduces a partial low
 *     guard at the OLD shim_data upper edge.
 *
 * Primary failure mode: the binary loads but mprotect/munmap on a low
 * address returns -EINVAL. The checks below assert the syscall return
 * values explicitly so a silent fall-through cannot mask the regression.
 */

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "test-harness.h"

int passes = 0, fails = 0;

/* A full page in the binary's own .data, forced page-aligned so the
 * mprotect target covers exactly one page and does not stomp neighboring
 * globals. The initializer keeps it out of .bss.
 */
__attribute__((aligned(4096), used)) static volatile char data_page[4096] =
    "low-base test data page\n";

static void test_binary_low_linked(void)
{
    TEST("binary linked below ELF_DEFAULT_BASE");
    uintptr_t pc = (uintptr_t) &test_binary_low_linked;
    /* The legacy guard window is [0x100000, 0x400000); the test binary's
     * .text must land inside it for the regression to be meaningful.
     */
    EXPECT_TRUE(pc >= 0x100000ULL && pc < 0x400000ULL,
                "test binary not linked below 0x400000");
}

static void test_mprotect_own_data_page(void)
{
    TEST("mprotect own .data page to PROT_READ");
    void *page = (void *) data_page;
    /* Drop the page to read-only, RELRO-style. Pre-fix this returned
     * -EINVAL because [SHIM_BASE, ELF_DEFAULT_BASE) was rejected outright.
     */
    int rc_drop = mprotect(page, 4096, PROT_READ);
    if (rc_drop != 0) {
        FAIL("mprotect(PROT_READ) on low-linked .data page failed");
        return;
    }
    /* Restore RW immediately so any later code that touches the page
     * (e.g. printf's stdout buffer if the linker placed it nearby, or
     * libc exit cleanup) cannot fault. mprotect-restoring is itself
     * the same code path; failing here also indicates a guard bug.
     */
    int rc_restore = mprotect(page, 4096, PROT_READ | PROT_WRITE);
    EXPECT_TRUE(rc_drop == 0 && rc_restore == 0,
                "mprotect restore after low-page RELRO failed");
}

static void test_munmap_low_scratch_range(void)
{
    TEST("munmap on scratch range below ELF_DEFAULT_BASE");
    /* 0x180000 sits in the legacy guard window [0x100000, 0x400000) but
     * outside the binary's loaded segments (which start at the link
     * address >= 0x200000). With the new high-IPA infra reserve, this
     * range has no PT entries and no tracked region, so munmap must
     * fast-path to success (return 0). Pre-fix this returned -EINVAL.
     */
    int rc = munmap((void *) 0x180000UL, 4096);
    EXPECT_TRUE(rc == 0, "munmap on low scratch range returned EINVAL");
}

int main(void)
{
    printf("test-lowbase-mem: starting\n");

    test_binary_low_linked();
    test_mprotect_own_data_page();
    test_munmap_low_scratch_range();

    SUMMARY("test-lowbase-mem");
    return fails ? 1 : 0;
}
