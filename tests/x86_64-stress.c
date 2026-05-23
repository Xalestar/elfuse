/* x86_64-stress.c - High-VA mmap stress for x86_64-via-Rosetta
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Exercises the high-VA mmap path in elfuse's sys_mmap_fixed_high_va by
 * issuing many small MAP_FIXED requests inside the same 2 MiB block. The
 * regression fixed in this branch was that gap-page invalidation after
 * each mmap could clobber neighbor mappings sharing the block. This
 * program installs N tiny mappings, fills each with a distinct sentinel,
 * then verifies every sentinel is still readable. If the freshness
 * detection regresses, sentinels read back as zero or fault.
 *
 * Build (on an x86_64-linux host): gcc -static -O2 -o x86_64-stress
 * x86_64-stress.c Run via elfuse: ./build/elfuse /path/to/x86_64-stress Exit
 * code 0 means every sentinel survived; non-zero pinpoints the first mapping
 * whose value was lost.
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

/* Pick a high VA inside the rosetta-mapped guest range that elfuse routes
 * through sys_mmap_fixed_high_va. 0xeffff7000000 sits in the same 2 MiB
 * block family as the addresses rosetta itself uses during bring-up.
 */
#define HIGH_VA_BASE 0xeffff7000000ULL

/* Number of 4 KiB pages. Sized so each lands in the same 2 MiB block as
 * the next, exercising the "pre-existing block" branch repeatedly. 64
 * pages * 4 KiB = 256 KiB, well inside one 2 MiB block.
 */
#define N_PAGES 64
#define PAGE_BYTES 4096
#define BLOCK_OFFSET PAGE_BYTES /* gap between successive mappings */

/* Sentinel pattern derived from page index. Embedding the index makes
 * any cross-page corruption immediately visible.
 */
static uint64_t sentinel_for(int i)
{
    return 0xCAFEBABE00000000ULL | (uint64_t) i;
}

int main(void)
{
    void *addrs[N_PAGES];
    int i;

    /* Phase 1: install N small MAP_FIXED mappings, each in the same
     * 2 MiB high-VA block. Each call goes through the high-VA helper;
     * after the first, the L2 entry is already a table descriptor and
     * the install path must avoid touching pre-existing neighbor PTEs.
     */
    for (i = 0; i < N_PAGES; i++) {
        uint64_t va = HIGH_VA_BASE + (uint64_t) i * BLOCK_OFFSET;
        void *p = mmap((void *) va, PAGE_BYTES, PROT_READ | PROT_WRITE,
                       MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (p == MAP_FAILED) {
            fprintf(stderr, "mmap %d at 0x%llx failed: errno=%d\n", i,
                    (unsigned long long) va, 12);
            return 1;
        }
        if ((uint64_t) p != va) {
            fprintf(stderr, "mmap %d returned 0x%llx, expected 0x%llx\n", i,
                    (unsigned long long) (uintptr_t) p,
                    (unsigned long long) va);
            return 2;
        }
        addrs[i] = p;
    }

    /* Phase 2: stamp each mapping with its sentinel. */
    for (i = 0; i < N_PAGES; i++) {
        volatile uint64_t *cell = (uint64_t *) addrs[i];
        *cell = sentinel_for(i);
    }

    /* Phase 3: verify every sentinel survived. A freshness-detection
     * regression typically zeros earlier mappings; the loop reports the
     * first violator.
     */
    for (i = 0; i < N_PAGES; i++) {
        volatile uint64_t *cell = (uint64_t *) addrs[i];
        uint64_t got = *cell;
        uint64_t want = sentinel_for(i);
        if (got != want) {
            fprintf(stderr,
                    "page %d (addr 0x%llx): got 0x%016llx, want 0x%016llx\n", i,
                    (unsigned long long) (uintptr_t) addrs[i],
                    (unsigned long long) got, (unsigned long long) want);
            return 3;
        }
    }

    printf("OK: %d high-VA mappings survived intact\n", N_PAGES);
    return 0;
}
