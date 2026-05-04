/* Guest memory syscalls
 *
 * Copyright 2026 elfuse contributors
 * Copyright 2025 Moritz Angermann, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Guest memory syscalls: brk, mmap, munmap, mprotect, mremap, madvise, msync
 */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>
#include <sys/stat.h>
#include <pthread.h>

#include "debug/log.h"
#include "utils.h"

#include "syscall/abi.h"
#include "syscall/internal.h"
#include "syscall/mem.h"

/* Protects mmap/brk bump allocators and page table extension. Multiple
 * threads may call mmap/brk concurrently; without this lock they could
 * get overlapping allocations or corrupt page table structures.
 */
pthread_mutex_t mmap_lock = PTHREAD_MUTEX_INITIALIZER; /* Lock order: 1 */

/* Gap-finding allocator for mmap.
 *
 * find_free_gap_inner() scans guest_t.regions[] (sorted) for the first free
 * gap of length bytes within [min_addr, max_addr). Replaces a bump
 * allocator so munmap'd ranges become reusable (critical for runtimes that
 * reserve, trim, and re-reserve in the same address window).
 *
 * The cached hints below amortize the O(n) scan to O(1) for sequential
 * allocations: after each success, the hint is set to the end of the
 * allocation. munmap resets the hint when freeing a region before it.
 */
static uint64_t mmap_rw_gap_hint = 0, mmap_rx_gap_hint = 0;

typedef struct {
    uint64_t start, end;
} remove_range_t;

static int region_count_after_removes(const guest_t *g,
                                      const remove_range_t *ranges,
                                      int nranges)
{
    int count = 0;

    for (int i = 0; i < g->nregions; i++) {
        remove_range_t segments[3] = {{g->regions[i].start, g->regions[i].end}};
        int nsegments = 1;

        for (int r = 0; r < nranges; r++) {
            remove_range_t next[3] = {0};
            int next_nsegments = 0;

            for (int s = 0; s < nsegments; s++) {
                uint64_t start = segments[s].start, end = segments[s].end;

                if (end <= ranges[r].start || start >= ranges[r].end) {
                    next[next_nsegments++] = segments[s];
                    continue;
                }
                if (start < ranges[r].start)
                    next[next_nsegments++] =
                        (remove_range_t) {start, ranges[r].start};
                if (end > ranges[r].end)
                    next[next_nsegments++] =
                        (remove_range_t) {ranges[r].end, end};
            }

            memcpy(segments, next, sizeof(next));
            nsegments = next_nsegments;
        }

        count += nsegments;
    }

    return count;
}

static int region_has_capacity_after_removes(const guest_t *g,
                                             const remove_range_t *ranges,
                                             int nranges,
                                             int added_regions)
{
    return region_count_after_removes(g, ranges, nranges) + added_regions <=
           GUEST_MAX_REGIONS;
}

static int dup_region_backing_fd(const guest_region_t *region)
{
    if (!region || region->backing_fd < 0)
        return -1;

    return dup(region->backing_fd);
}

/* Reset mmap gap hints after execve. Without this, the gap-finder starts
 * searching past the previous binary's allocations, wasting address space
 * and potentially causing issues with the new dynamic linker.
 */
void mmap_reset_hints(void)
{
    mmap_rw_gap_hint = 0;
    mmap_rx_gap_hint = 0;
}

static uint64_t find_free_gap_inner(const guest_t *g,
                                    uint64_t length,
                                    uint64_t min_addr,
                                    uint64_t max_addr)
{
    uint64_t gap_start = min_addr;

    for (int i = 0; i < g->nregions; i++) {
        /* Skip regions entirely before the current search position */
        if (g->regions[i].end <= gap_start)
            continue;

        /* If this region starts far enough after gap_start, the allocator found
         * a gap. Must also verify the gap is within max_addr; regions[] may
         * contain entries beyond max_addr that could push gap_start past
         * the valid range.
         */
        if (gap_start <= max_addr && length <= max_addr - gap_start &&
            g->regions[i].start >= gap_start + length)
            return gap_start;

        /* Region overlaps; advance past it */
        gap_start = g->regions[i].end;
        /* Page-align the next candidate position */
        gap_start = PAGE_ALIGN_UP(gap_start);
    }

    /* Check trailing space after all regions */
    if (gap_start <= max_addr && length <= max_addr - gap_start)
        return gap_start;
    return UINT64_MAX; /* No suitable gap found */
}

/* Find a free gap, probing the cached post-allocation hint before a full
 * scan. The hint tracks the first address after the last successful mapping
 * in each region, which avoids rescanning the same prefix on sequential
 * mmap activity. A miss falls back to the region base so holes reopened by
 * munmap are still reusable.
 */
static uint64_t find_free_gap(const guest_t *g,
                              uint64_t length,
                              uint64_t min_addr,
                              uint64_t max_addr)
{
    /* RX and RW mappings advance independently, so keep separate hints. */
    uint64_t *hint =
        (min_addr < MMAP_BASE) ? &mmap_rx_gap_hint : &mmap_rw_gap_hint;

    /* Try cached hint first (only if within the valid range) */
    if (*hint >= min_addr && *hint < max_addr) {
        uint64_t result = find_free_gap_inner(g, length, *hint, max_addr);
        if (result != UINT64_MAX) {
            *hint = result + length;
            return result;
        }
    }

    /* Full scan from base */
    uint64_t result = find_free_gap_inner(g, length, min_addr, max_addr);
    if (result != UINT64_MAX)
        *hint = result + length;
    return result;
}

/* Convert Linux PROT_* flags to guest page table permission bits.
 * MEM_PERM_R is always set. PROT_NONE callers should skip this.
 */
static int prot_to_perms(int prot)
{
    int perms = MEM_PERM_R;
    if (prot & LINUX_PROT_WRITE)
        perms |= MEM_PERM_W;
    if (prot & LINUX_PROT_EXEC)
        perms |= MEM_PERM_X;
    return perms;
}

static int mremap_extend_range(guest_t *g,
                               uint64_t off,
                               uint64_t size,
                               int prot)
{
    if (prot == LINUX_PROT_NONE) {
        guest_invalidate_ptes(g, off, off + size);
        return 0;
    }

    int page_perms = prot_to_perms(prot);
    uint64_t ext_start = ALIGN_DOWN(off, BLOCK_2MIB);
    uint64_t ext_end = ALIGN_UP(off + size, BLOCK_2MIB);
    if (ext_end > g->guest_size)
        ext_end = g->guest_size;
    if (guest_extend_page_tables(g, ext_start, ext_end, page_perms) < 0)
        return -1;
    guest_update_perms(g, off, off + size, page_perms);
    return 0;
}

/* Memory syscalls (tightly coupled to guest.h). */

int64_t sys_brk(guest_t *g, uint64_t addr)
{
    /* brk addresses as seen by the guest are IPA-based */
    uint64_t ipa_brk = guest_ipa(g, g->brk_current);
    uint64_t ipa_base = guest_ipa(g, g->brk_base);

    if (addr == 0) {
        return (int64_t) ipa_brk;
    }

    if (addr < ipa_base) {
        return (int64_t) ipa_brk;
    }

    /* Convert IPA back to offset for internal tracking */
    uint64_t new_off = addr - g->ipa_base;
    if (new_off >= g->guest_size) {
        return (int64_t) ipa_brk;
    }

    /* Extend page tables if brk grows beyond currently-mapped region.
     * The brk region is initially mapped up to MMAP_RX_BASE; if it grows
     * past that, the mmap allocator needs to extend dynamically.
     */
    uint64_t brk_pt_end = ALIGN_UP(g->brk_current, BLOCK_2MIB);
    if (brk_pt_end < MMAP_RX_BASE)
        brk_pt_end = MMAP_RX_BASE;
    if (new_off > brk_pt_end) {
        uint64_t new_end = ALIGN_UP(new_off, BLOCK_2MIB);
        if (guest_extend_page_tables(g, brk_pt_end, new_end, MEM_PERM_RW) < 0)
            return (int64_t) ipa_brk;
    }

    /* Zero new pages if growing */
    if (new_off > g->brk_current) {
        memset((uint8_t *) g->host_base + g->brk_current, 0,
               new_off - g->brk_current);
    }

    uint64_t old_brk = g->brk_current;
    g->brk_current = new_off;

    /* Update "[heap]" region tracking atomically.
     * Find-and-update-in-place avoids the remove+add gap where a
     * concurrent /proc/self/maps reader could see no heap region.
     */
    if (new_off > g->brk_base) {
        bool found = false;
        for (int i = 0; i < g->nregions; i++) {
            if (g->regions[i].start == g->brk_base &&
                !strcmp(g->regions[i].name, "[heap]")) {
                g->regions[i].end = new_off;
                found = true;
                break;
            }
        }
        if (!found) {
            guest_region_add(
                g, g->brk_base, new_off, LINUX_PROT_READ | LINUX_PROT_WRITE,
                LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS, 0, "[heap]");
        }
    } else {
        /* brk shrank back to base; remove heap region */
        guest_region_remove(g, g->brk_base,
                            old_brk > g->brk_base ? old_brk : g->brk_base + 1);
    }

    return (int64_t) guest_ipa(g, g->brk_current);
}

int64_t sys_mmap(guest_t *g,
                 uint64_t addr,
                 uint64_t length,
                 int prot,
                 int flags,
                 int fd,
                 int64_t offset)
{
    bool is_anon = (flags & LINUX_MAP_ANONYMOUS) != 0;
    bool needs_exec = (prot & LINUX_PROT_EXEC) != 0;
    bool is_prot_none = (prot == LINUX_PROT_NONE);
    bool is_noreserve = is_anon && (flags & LINUX_MAP_NORESERVE) != 0;
    host_fd_ref_t backing_ref = {.fd = -1, .owned = 0};
    int host_backing_fd = -1, track_backing_fd = -1;
    int track_flags = is_anon
                          ? (LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS)
                          : ((flags & LINUX_MAP_SHARED) ? LINUX_MAP_SHARED
                                                        : LINUX_MAP_PRIVATE);

    /* Preserve MAP_NORESERVE in region metadata before merge checks run. */
    if (is_noreserve)
        track_flags |= LINUX_MAP_NORESERVE;

    /* The memory syscall layer handles all mmap variants. For file-backed
     * MAP_SHARED, it falls
     * back to MAP_PRIVATE semantics (copy-on-write). All threads share
     * the same guest_t address space (CLONE_VM semantics), so MAP_SHARED
     * and MAP_PRIVATE are equivalent within the guest.
     */

    /* Linux rejects zero-length mmap */
    if (length == 0)
        return -LINUX_EINVAL;

    /* Linux requires page-aligned offset for file-backed mmap */
    if (!is_anon && (offset & 4095))
        return -LINUX_EINVAL;

    /* Round length up to page size (overflow-safe) */
    if (length > UINT64_MAX - 4095)
        return -LINUX_ENOMEM;
    length = PAGE_ALIGN_UP(length);
    if (length == 0)
        return -LINUX_ENOMEM;

    /* Linux kernel rejects MAP_FIXED with non-page-aligned address */
    bool is_fixed =
        (flags & LINUX_MAP_FIXED) || (flags & LINUX_MAP_FIXED_NOREPLACE);
    if (is_fixed && (addr & 4095))
        return -LINUX_EINVAL;

    /* MAP_FIXED_NOREPLACE: like MAP_FIXED but fail with -EEXIST if the
     * range overlaps any existing mapping.
     */
    bool is_noreplace = (flags & LINUX_MAP_FIXED_NOREPLACE) != 0;

    uint64_t result_off; /* Result as offset (0-based) */
    if (is_fixed) {
        /* Addresses above TASK_SIZE (bit 63 set or beyond user VA range)
         * are rejected, matching real Linux kernel behavior.
         */
        if (addr > 0x0000FFFFFFFFFFFFULL)
            return -LINUX_ENOMEM;

        /* MAP_FIXED: addr is IPA-based, convert to offset */
        uint64_t off = addr - g->ipa_base;
        /* Use subtraction-based check to avoid off+length overflow */
        if (off > g->guest_size || length > g->guest_size - off)
            return -LINUX_ENOMEM;

        /* Reject MAP_FIXED targeting VM infrastructure: page table pool,
         * shim code, and shim data/stack regions.  A guest must not be
         * able to overwrite EL1 exception vectors or page tables.
         */
        uint64_t fix_end = off + length;
        if (off < ELF_DEFAULT_BASE && fix_end > PT_POOL_BASE)
            return -LINUX_EINVAL;

        result_off = off;

        /* MAP_FIXED_NOREPLACE: reject if any existing region overlaps.
         * Use binary search (regions are sorted by start address) to
         * find the first region that could overlap [result_off,
         * result_off+length).
         */
        if (is_noreplace) {
            int lo = 0, hi = g->nregions - 1, first = g->nregions;
            while (lo <= hi) {
                int mid = (lo + hi) / 2;
                if (g->regions[mid].end > result_off) {
                    first = mid;
                    hi = mid - 1;
                } else {
                    lo = mid + 1;
                }
            }
            if (first < g->nregions &&
                g->regions[first].start < result_off + length)
                return -LINUX_EEXIST;
        }

        if (!is_anon) {
            if (host_fd_ref_open(fd, &backing_ref) < 0)
                return -LINUX_EBADF;
            host_backing_fd = backing_ref.fd;
        }

        remove_range_t replaced = {result_off, result_off + length};
        if (!region_has_capacity_after_removes(g, &replaced, 1, 1)) {
            host_fd_ref_close(&backing_ref);
            return -LINUX_ENOMEM;
        }
        if (!is_anon) {
            track_backing_fd = dup(host_backing_fd);
            if (track_backing_fd < 0) {
                host_fd_ref_close(&backing_ref);
                return -LINUX_ENOMEM;
            }
            if (!is_prot_none) {
                char probe;
                ssize_t nr;
                do {
                    nr = pread(host_backing_fd, &probe, sizeof(probe), offset);
                } while (nr < 0 && errno == EINTR);
                if (nr < 0) {
                    close(track_backing_fd);
                    host_fd_ref_close(&backing_ref);
                    return linux_errno();
                }
            }
        }

        if (!is_prot_none) {
            /* Ensure page table entries exist for the fixed range.
             * PROT_NONE reservations skip page table creation, so when
             * MAP_FIXED commits pages within a PROT_NONE region (e.g., a
             * runtime carves an RW slab out of its previously reserved
             * PROT_NONE heap), the memory syscall layer must create L2
             * block descriptors first. guest_extend_page_tables is
             * idempotent for already-mapped blocks.
             */
            int page_perms = prot_to_perms(prot);

            uint64_t ext_start = ALIGN_DOWN(result_off, BLOCK_2MIB);
            uint64_t ext_end = ALIGN_UP(result_off + length, BLOCK_2MIB);
            if (ext_end > g->guest_size)
                ext_end = g->guest_size;

            if (guest_extend_page_tables(g, ext_start, ext_end, page_perms) <
                0) {
                if (track_backing_fd >= 0)
                    close(track_backing_fd);
                host_fd_ref_close(&backing_ref);
                return -LINUX_ENOMEM;
            }

            /* Remove old metadata only after fallible page-table preparation
             * succeeds.
             */
            guest_region_remove(g, result_off, result_off + length);

            /* Fine-tune permissions for the exact range. Handles L3
             * splitting when MAP_FIXED overlays different permissions
             * onto an existing 2MiB block (e.g., .data RW over .text RX).
             */
            guest_update_perms(g, result_off, result_off + length, page_perms);

            /* For MAP_ANONYMOUS: zero the region (host memory may contain
             * stale data from earlier mappings).
             * For file-backed: read file contents into guest memory.
             * Short reads leave the remainder zeroed (memset first).
             */
            if (is_anon) {
                memset((uint8_t *) g->host_base + result_off, 0, length);
            } else if (fd >= 0) {
                /* Zero first, then overlay with file data. This matches
                 * Linux MAP_FIXED semantics: pages beyond EOF are zeroed.
                 */
                memset((uint8_t *) g->host_base + result_off, 0, length);
                uint8_t *dst = (uint8_t *) g->host_base + result_off;
                size_t remaining = length;
                off_t file_off = offset;
                while (remaining > 0) {
                    ssize_t nr =
                        pread(host_backing_fd, dst, remaining, file_off);
                    if (nr < 0) {
                        if (errno == EINTR)
                            continue;
                        break; /* partial read is acceptable (zeroed tail) */
                    }
                    if (nr == 0)
                        break; /* EOF */
                    dst += nr;
                    remaining -= (size_t) nr;
                    file_off += nr;
                }
            }
        } else {
            /* Remove any existing region coverage in the fixed range. */
            guest_region_remove(g, result_off, result_off + length);

            /* PROT_NONE with MAP_FIXED: invalidate existing page table
             * entries so the region becomes truly inaccessible. Without
             * this, stale PTEs from initial page table setup (e.g., ELF
             * segment pre-mapping) remain valid, making pages accessible
             * when they should fault on access. A real Linux kernel's
             * mmap(MAP_FIXED, PROT_NONE) removes existing VMAs and their
             * page table entries, making the range fault on access.
             */
            guest_invalidate_ptes(g, result_off, result_off + length);
            g->need_tlbi = true;
        }
    }

    /* Non-fixed mmap: allocate from the gap-finding allocator and snapshot
     * file backing once the final guest range is known.
     */
    if (!is_fixed) {
        if (needs_exec && !(prot & LINUX_PROT_WRITE)) {
            /* PROT_EXEC without PROT_WRITE: allocate from the RX mmap region.
             * Apple HVF enforces W^X on 2MiB block page table entries, so
             * executable mappings must be in separate 2MiB blocks from writable
             * ones. The RX region at MMAP_RX_BASE is pre-mapped with execute
             * permission.
             */
            result_off = find_free_gap(g, length, MMAP_RX_BASE, g->mmap_limit);
            if (result_off == UINT64_MAX) {
                log_debug(
                    "mmap: RX address space exhausted "
                    "(len=0x%llx, limit=0x%llx, %u-bit IPA / %llu GiB)",
                    (unsigned long long) length,
                    (unsigned long long) g->mmap_limit, g->ipa_bits,
                    (unsigned long long) (g->guest_size >> 30));
                return -LINUX_ENOMEM;
            }
            /* High-water mark for fork IPC state transfer */
            uint64_t rx_hwm = result_off + length;
            if (rx_hwm > g->mmap_rx_next)
                g->mmap_rx_next = rx_hwm;
        } else {
            /* RW (or PROT_NONE, or PROT_READ): allocate from main mmap region.
             * Honor the address hint if provided and within bounds. Some
             * managed-runtime allocators need the heap at a specific high
             * address range (e.g., ~264GiB for a megablock-style map) and
             * spin-retry if they get a low address instead. On real Linux,
             * mmap tries the hint first and falls back to any suitable address.
             */
            result_off = UINT64_MAX;
            if (addr != 0) {
                uint64_t hint_off = addr - g->ipa_base;
                if (hint_off >= MMAP_BASE && hint_off <= g->mmap_limit &&
                    length <= g->mmap_limit - hint_off)
                    result_off =
                        find_free_gap(g, length, hint_off, g->mmap_limit);
            }
            if (result_off == UINT64_MAX)
                result_off = find_free_gap(g, length, MMAP_BASE, g->mmap_limit);
            if (result_off == UINT64_MAX) {
                log_debug(
                    "mmap: RW address space exhausted "
                    "(len=0x%llx, limit=0x%llx, %u-bit IPA / %llu GiB)",
                    (unsigned long long) length,
                    (unsigned long long) g->mmap_limit, g->ipa_bits,
                    (unsigned long long) (g->guest_size >> 30));
                return -LINUX_ENOMEM;
            }
            /* High-water mark for fork IPC state transfer */
            uint64_t rw_hwm = result_off + length;
            if (rw_hwm > g->mmap_next)
                g->mmap_next = rw_hwm;
        }
        if (!is_anon) {
            if (host_fd_ref_open(fd, &backing_ref) < 0)
                return -LINUX_EBADF;
            host_backing_fd = backing_ref.fd;
        }
        if (!region_has_capacity_after_removes(g, NULL, 0, 1)) {
            host_fd_ref_close(&backing_ref);
            return -LINUX_ENOMEM;
        }
        if (!is_anon) {
            track_backing_fd = dup(host_backing_fd);
            if (track_backing_fd < 0) {
                host_fd_ref_close(&backing_ref);
                return -LINUX_ENOMEM;
            }
        }
    }

    /* PROT_NONE mappings do not need new page table entries, but mmap must
     * invalidate any stale PTEs from previous allocations at this address.
     * Without this, a freed-then-reallocated-as-PROT_NONE range retains
     * the old RW page table entries, letting the guest read/write what
     * should be inaccessible memory.
     */
    if (is_prot_none && !is_fixed) {
        guest_invalidate_ptes(g, result_off, result_off + length);
        g->need_tlbi = true;
    }

    if (!is_prot_none && !is_fixed && !is_noreserve) {
        /* Extend page tables for this specific allocation range only.
         * guest_extend_page_tables skips already-mapped blocks, so
         * calling it on pre-mapped regions is a no-op. This avoids
         * creating entries for PROT_NONE gaps between allocations.
         */
        if (needs_exec && !(prot & LINUX_PROT_WRITE)) {
            uint64_t ext_start = ALIGN_DOWN(result_off, BLOCK_2MIB);
            uint64_t ext_end = ALIGN_UP(result_off + length, BLOCK_2MIB);
            if (ext_end > g->mmap_limit)
                ext_end = g->mmap_limit;
            if (guest_extend_page_tables(g, ext_start, ext_end, MEM_PERM_RX) <
                0) {
                if (track_backing_fd >= 0)
                    close(track_backing_fd);
                host_fd_ref_close(&backing_ref);
                return -LINUX_ENOMEM;
            }
            /* Re-validate any previously-invalidated L3 entries (see
             * the RW path comment below for the full explanation).
             */
            guest_update_perms(g, result_off, result_off + length, MEM_PERM_RX);
            if (ext_end > g->mmap_rx_end)
                g->mmap_rx_end = ext_end;
        } else {
            uint64_t ext_start = ALIGN_DOWN(result_off, BLOCK_2MIB);
            uint64_t ext_end = ALIGN_UP(result_off + length, BLOCK_2MIB);
            if (ext_end > g->mmap_limit)
                ext_end = g->mmap_limit;
            /* Preserve execute permission for RWX requests. Stage-2
             * (hv_vm_map) is RWX for the whole buffer; stage-1 PTEs set
             * AP=RW_EL0 with UXN/PXN=0 for combined W+X. HVF allows
             * this in stage-1 even though normal W^X enforcement
             * disallows it per HV_MEMORY flags.
             */
            int ext_perms = MEM_PERM_RW;
            if (prot & LINUX_PROT_EXEC)
                ext_perms |= MEM_PERM_X;
            if (guest_extend_page_tables(g, ext_start, ext_end, ext_perms) <
                0) {
                if (track_backing_fd >= 0)
                    close(track_backing_fd);
                host_fd_ref_close(&backing_ref);
                return -LINUX_ENOMEM;
            }
            /* Update permissions on the allocated range. This handles two
             * cases:
             * 1. RWX: pre-existing RW blocks need execute permission added
             * 2. L3 split entries: if an L2 block was previously split into
             *    L3 page entries (e.g., via mprotect(PROT_NONE) on a sub-block
             *    range), guest_extend_page_tables skips the L2 entry (it sees
             *    a valid table descriptor). The L3 entries may be invalidated,
             *    so the memory syscall layer must re-create them with the
             *    correct permissions.
             */
            guest_update_perms(g, result_off, result_off + length, ext_perms);
            if (ext_end > g->mmap_end)
                g->mmap_end = ext_end;
        }

        /* Zero the mapped region */
        memset((uint8_t *) g->host_base + result_off, 0, length);
    }

    /* MAP_NORESERVE: invalidate any stale PTEs (like PROT_NONE path)
     * but track the region for lazy materialization on first fault.
     * Page table entries will be created by guest_materialize_lazy()
     * when the guest first touches a page in this range.
     */
    if (is_noreserve && !is_fixed) {
        guest_invalidate_ptes(g, result_off, result_off + length);
        g->need_tlbi = true;
    }

    /* For file-backed mmap, read file contents into the region.
     * Short reads are acceptable (region is already zeroed above),
     * but total failure means the mapping is useless.
     * Skip for PROT_NONE: the region has no page table entries yet;
     * data is faulted in when mprotect makes the pages accessible.
     */
    if (!is_anon && fd >= 0 && !is_prot_none) {
        uint8_t *dst = (uint8_t *) g->host_base + result_off;
        size_t remaining = length;
        off_t file_off = offset;
        bool read_err = false;
        while (remaining > 0) {
            ssize_t nr = pread(host_backing_fd, dst, remaining, file_off);
            if (nr < 0) {
                if (errno == EINTR)
                    continue;
                read_err = true;
                break;
            }
            if (nr == 0)
                break; /* EOF; remaining pages stay zeroed */
            dst += nr;
            remaining -= (size_t) nr;
            file_off += nr;
        }
        if (read_err && remaining == length) {
            /* Total failure (no bytes read). Undo the mapping. */
            if (track_backing_fd >= 0)
                close(track_backing_fd);
            host_fd_ref_close(&backing_ref);
            return linux_errno();
        }
    }

    /* Record the new region. guest_region_add_ex derives shared from
     * the LINUX_MAP_SHARED bit in track_flags for msync write-back.
     */
    if (guest_region_add_ex_owned(g, result_off, result_off + length, prot,
                                  track_flags, is_anon ? 0 : (uint64_t) offset,
                                  NULL, track_backing_fd) < 0) {
        host_fd_ref_close(&backing_ref);
        return -LINUX_ENOMEM;
    }

    host_fd_ref_close(&backing_ref);

    /* Return IPA-based address to guest */
    return (int64_t) guest_ipa(g, result_off);
}

/* sys_mremap. */

int64_t sys_mremap(guest_t *g,
                   uint64_t old_addr,
                   uint64_t old_size,
                   uint64_t new_size,
                   int flags,
                   uint64_t new_addr)
{
    /* Validate alignment */
    if (old_addr & 4095)
        return -LINUX_EINVAL;

    /* Round sizes to page boundary */
    if (old_size > UINT64_MAX - 4095 || new_size > UINT64_MAX - 4095)
        return -LINUX_EINVAL;
    old_size = PAGE_ALIGN_UP(old_size);
    new_size = PAGE_ALIGN_UP(new_size);
    if (new_size == 0)
        return -LINUX_EINVAL;
    /* Linux allows old_size==0 only for certain vma types (e.g., shared
     * anonymous with MREMAP_MAYMOVE). mremap does not support these; reject.
     */
    if (old_size == 0)
        return -LINUX_EINVAL;

    /* Reject MREMAP_DONTUNMAP (not implemented) */
    if (flags & LINUX_MREMAP_DONTUNMAP)
        return -LINUX_EINVAL;

    /* MREMAP_FIXED requires MREMAP_MAYMOVE */
    if ((flags & LINUX_MREMAP_FIXED) && !(flags & LINUX_MREMAP_MAYMOVE))
        return -LINUX_EINVAL;

    /* Reject unknown flags */
    if (flags &
        ~(LINUX_MREMAP_MAYMOVE | LINUX_MREMAP_FIXED | LINUX_MREMAP_DONTUNMAP))
        return -LINUX_EINVAL;

    /* Overflow check on old range */
    uint64_t old_off = old_addr - g->ipa_base;
    if (old_off > g->guest_size)
        return -LINUX_EFAULT;
    if (old_size > 0 && old_size > g->guest_size - old_off)
        return -LINUX_EFAULT;

    /* Verify the whole source range is covered by one tracked VMA. mremap()
     * must not copy holes or unrelated adjacent mappings.
     */
    const guest_region_t *src_reg = guest_region_find(g, old_off);
    if (!src_reg || src_reg->end - old_off < old_size)
        return -LINUX_EFAULT;

    /* Same size: nothing to do */
    if (old_size == new_size && !(flags & LINUX_MREMAP_FIXED))
        return (int64_t) old_addr;

    /* Shrinking mremap keeps the base address and releases only the tail. */
    if (new_size < old_size && !(flags & LINUX_MREMAP_FIXED)) {
        uint64_t tail_off = old_off + new_size, tail_end = old_off + old_size;
        /* Zero the trimmed region */
        memset((uint8_t *) g->host_base + tail_off, 0, tail_end - tail_off);
        guest_region_remove(g, tail_off, tail_end);
        guest_invalidate_ptes(g, tail_off, tail_end);
        if (tail_off < mmap_rw_gap_hint)
            mmap_rw_gap_hint = tail_off;
        if (tail_off < mmap_rx_gap_hint)
            mmap_rx_gap_hint = tail_off;
        return (int64_t) old_addr;
    }

    /* MREMAP_FIXED: move to a specific new address */
    if (flags & LINUX_MREMAP_FIXED) {
        if (new_addr & 4095)
            return -LINUX_EINVAL;
        uint64_t new_off = new_addr - g->ipa_base;
        if (new_off > g->guest_size || new_size > g->guest_size - new_off)
            return -LINUX_ENOMEM;

        /* Linux rejects MREMAP_FIXED when old and new ranges overlap */
        uint64_t old_end = old_off + old_size, new_end = new_off + new_size;
        if (old_off < new_end && new_off < old_end)
            return -LINUX_EINVAL;

        remove_range_t removed[] = {
            {old_off, old_end},
            {new_off, new_end},
        };
        if (!region_has_capacity_after_removes(g, removed, 2, 1))
            return -LINUX_ENOMEM;

        /* Capture old region metadata BEFORE modifying any regions.
         * If mremap removed destination first, an overlapping source would
         * lose its metadata. The overlap check above prevents this case,
         * but capturing first is still the safe ordering.
         */
        const guest_region_t *old_reg = guest_region_find(g, old_off);
        int prot =
            old_reg ? old_reg->prot : (LINUX_PROT_READ | LINUX_PROT_WRITE);
        int track_flags = old_reg ? old_reg->flags
                                  : (LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS);
        uint64_t track_offset = old_reg ? old_reg->offset : 0;
        int track_backing_fd = dup_region_backing_fd(old_reg);
        if (old_reg && old_reg->backing_fd >= 0 && track_backing_fd < 0)
            return -LINUX_ENOMEM;
        char track_name[sizeof(old_reg->name)] = {0};
        if (old_reg)
            str_copy_trunc(track_name, old_reg->name, sizeof(track_name));

        if (mremap_extend_range(g, new_off, new_size, prot) < 0) {
            if (track_backing_fd >= 0)
                close(track_backing_fd);
            return -LINUX_ENOMEM;
        }

        /* Remove existing mappings at the destination after all fallible
         * preparation is complete.
         */
        guest_region_remove(g, new_off, new_off + new_size);

        /* Copy data (use memmove for potential overlap) */
        uint64_t copy_len = old_size < new_size ? old_size : new_size;
        if (prot == LINUX_PROT_NONE)
            memset((uint8_t *) g->host_base + new_off, 0, new_size);
        else
            memmove((uint8_t *) g->host_base + new_off,
                    (uint8_t *) g->host_base + old_off, copy_len);
        /* Zero any extension beyond old data */
        if (new_size > old_size)
            memset((uint8_t *) g->host_base + new_off + old_size, 0,
                   new_size - old_size);

        /* Remove old mapping */
        if (old_size > 0) {
            memset((uint8_t *) g->host_base + old_off, 0, old_size);
            guest_region_remove(g, old_off, old_off + old_size);
            guest_invalidate_ptes(g, old_off, old_off + old_size);
            if (old_off < mmap_rw_gap_hint)
                mmap_rw_gap_hint = old_off;
            if (old_off < mmap_rx_gap_hint)
                mmap_rx_gap_hint = old_off;
        }

        if (guest_region_add_ex_owned(
                g, new_off, new_off + new_size, prot, track_flags, track_offset,
                track_name[0] ? track_name : NULL, track_backing_fd) < 0)
            return -LINUX_ENOMEM;
        g->need_tlbi = true;
        return (int64_t) guest_ipa(g, new_off);
    }

    /* Grow in place: try to extend without moving */
    if (new_size > old_size) {
        uint64_t grow_off = old_off + old_size, grow_len = new_size - old_size;

        /* Check if the space after the old region is free (overflow-safe) */
        if (grow_off <= g->guest_size && grow_len <= g->guest_size - grow_off) {
            bool can_grow = true;
            for (int i = 0; i < g->nregions; i++) {
                if (g->regions[i].start >= grow_off + grow_len)
                    break;
                if (g->regions[i].end > grow_off &&
                    g->regions[i].start < grow_off + grow_len) {
                    /* Skip the region being extended */
                    if (g->regions[i].start == old_off)
                        continue;
                    can_grow = false;
                    break;
                }
            }

            if (can_grow) {
                remove_range_t removed = {old_off, old_off + old_size};
                if (!region_has_capacity_after_removes(g, &removed, 1, 1))
                    return -LINUX_ENOMEM;

                /* Extend in place */
                const guest_region_t *old_reg = guest_region_find(g, old_off);
                int prot = old_reg ? old_reg->prot
                                   : (LINUX_PROT_READ | LINUX_PROT_WRITE);
                int track_flags =
                    old_reg ? old_reg->flags
                            : (LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS);
                uint64_t track_offset = old_reg ? old_reg->offset : 0;
                int track_backing_fd = dup_region_backing_fd(old_reg);
                if (old_reg && old_reg->backing_fd >= 0 && track_backing_fd < 0)
                    return -LINUX_ENOMEM;
                char track_name[sizeof(old_reg->name)] = {0};
                if (old_reg)
                    str_copy_trunc(track_name, old_reg->name,
                                   sizeof(track_name));

                if (mremap_extend_range(g, grow_off, grow_len, prot) < 0) {
                    if (track_backing_fd >= 0)
                        close(track_backing_fd);
                    return -LINUX_ENOMEM;
                }

                memset((uint8_t *) g->host_base + grow_off, 0, grow_len);

                /* Update region tracking: remove old, add extended */
                guest_region_remove(g, old_off, old_off + old_size);
                if (guest_region_add_ex_owned(g, old_off, old_off + new_size,
                                              prot, track_flags, track_offset,
                                              track_name[0] ? track_name : NULL,
                                              track_backing_fd) < 0)
                    return -LINUX_ENOMEM;
                g->need_tlbi = true;

                /* Update high-water marks */
                uint64_t hwm = old_off + new_size;
                if (old_off >= MMAP_RX_BASE && old_off < MMAP_BASE) {
                    if (hwm > g->mmap_rx_next)
                        g->mmap_rx_next = hwm;
                } else if (old_off >= MMAP_BASE) {
                    if (hwm > g->mmap_next)
                        g->mmap_next = hwm;
                }

                return (int64_t) old_addr;
            }
        }

        /* Growth in place failed; MREMAP_MAYMOVE is required */
        if (!(flags & LINUX_MREMAP_MAYMOVE))
            return -LINUX_ENOMEM;

        /* Allocate a new region and move */
        const guest_region_t *old_reg = guest_region_find(g, old_off);
        int prot =
            old_reg ? old_reg->prot : (LINUX_PROT_READ | LINUX_PROT_WRITE);
        int track_flags = old_reg ? old_reg->flags
                                  : (LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS);
        uint64_t track_offset = old_reg ? old_reg->offset : 0;
        int track_backing_fd = dup_region_backing_fd(old_reg);
        if (old_reg && old_reg->backing_fd >= 0 && track_backing_fd < 0)
            return -LINUX_ENOMEM;
        char track_name[sizeof(old_reg->name)] = {0};
        if (old_reg)
            str_copy_trunc(track_name, old_reg->name, sizeof(track_name));
        int needs_exec = (prot & LINUX_PROT_EXEC) != 0;

        uint64_t new_off;
        if (needs_exec && !(prot & LINUX_PROT_WRITE))
            new_off = find_free_gap(g, new_size, MMAP_RX_BASE, g->mmap_limit);
        else
            new_off = find_free_gap(g, new_size, MMAP_BASE, g->mmap_limit);

        if (new_off == UINT64_MAX) {
            if (track_backing_fd >= 0)
                close(track_backing_fd);
            return -LINUX_ENOMEM;
        }

        remove_range_t removed = {old_off, old_off + old_size};
        if (!region_has_capacity_after_removes(g, &removed, 1, 1)) {
            if (track_backing_fd >= 0)
                close(track_backing_fd);
            return -LINUX_ENOMEM;
        }

        if (mremap_extend_range(g, new_off, new_size, prot) < 0) {
            if (track_backing_fd >= 0)
                close(track_backing_fd);
            return -LINUX_ENOMEM;
        }

        /* Copy old data, zero extension */
        if (prot == LINUX_PROT_NONE)
            memset((uint8_t *) g->host_base + new_off, 0, new_size);
        else
            memcpy((uint8_t *) g->host_base + new_off,
                   (uint8_t *) g->host_base + old_off, old_size);
        memset((uint8_t *) g->host_base + new_off + old_size, 0,
               new_size - old_size);

        /* Remove old mapping */
        memset((uint8_t *) g->host_base + old_off, 0, old_size);
        guest_region_remove(g, old_off, old_off + old_size);
        guest_invalidate_ptes(g, old_off, old_off + old_size);
        if (old_off < mmap_rw_gap_hint)
            mmap_rw_gap_hint = old_off;
        if (old_off < mmap_rx_gap_hint)
            mmap_rx_gap_hint = old_off;

        /* Track new region */
        if (guest_region_add_ex_owned(
                g, new_off, new_off + new_size, prot, track_flags, track_offset,
                track_name[0] ? track_name : NULL, track_backing_fd) < 0)
            return -LINUX_ENOMEM;

        /* Update high-water marks */
        uint64_t hwm = new_off + new_size;
        if (new_off >= MMAP_RX_BASE && new_off < MMAP_BASE) {
            if (hwm > g->mmap_rx_next)
                g->mmap_rx_next = hwm;
        } else if (new_off >= MMAP_BASE) {
            if (hwm > g->mmap_next)
                g->mmap_next = hwm;
        }

        g->need_tlbi = true;
        return (int64_t) guest_ipa(g, new_off);
    }

    /* Should not reach here */
    return -LINUX_EINVAL;
}

/* sys_madvise. */

int64_t sys_madvise(guest_t *g, uint64_t addr, uint64_t length, int advice)
{
    if (addr & 4095)
        return -LINUX_EINVAL;

    if (length > UINT64_MAX - 4095)
        return -LINUX_EINVAL;
    length = PAGE_ALIGN_UP(length);
    if (length == 0)
        return 0;

    switch (advice) {
    case LINUX_MADV_DONTNEED: {
        /* MADV_DONTNEED: zero the pages so next access sees zero-fill.
         * Linux guarantees zero-fill on next access for anonymous pages.
         * Linux returns -ENOMEM if any part of the range is unmapped.
         */
        uint64_t off = addr - g->ipa_base;
        if (off > g->guest_size || length > g->guest_size - off)
            return -LINUX_EINVAL;

        uint64_t end = off + length;

        /* Verify the entire range is covered by regions (Linux returns
         * -ENOMEM for unmapped holes). Walk regions and check for gaps.
         */
        uint64_t covered = off;
        for (int i = 0; i < g->nregions; i++) {
            const guest_region_t *r = &g->regions[i];
            if (r->start >= end)
                break;
            if (r->end <= covered)
                continue;
            if (r->start > covered)
                return -LINUX_ENOMEM; /* Unmapped hole */
            covered = r->end;
        }
        if (covered < end)
            return -LINUX_ENOMEM; /* Tail unmapped */

        /* Anonymous pages become zero-fill. MAP_PRIVATE file mappings discard
         * private pages so later reads see the backing file contents again.
         */
        for (int i = 0; i < g->nregions; i++) {
            const guest_region_t *r = &g->regions[i];
            if (r->start >= end)
                break;
            if (r->end <= off)
                continue;
            if (r->prot == LINUX_PROT_NONE)
                continue;
            if (!(r->flags & LINUX_MAP_ANONYMOUS) && r->backing_fd < 0)
                continue;

            /* Compute overlap with the requested range */
            uint64_t zstart = (r->start > off) ? r->start : off;
            uint64_t zend = (r->end < end) ? r->end : end;
            memset((uint8_t *) g->host_base + zstart, 0, zend - zstart);
            if (!(r->flags & LINUX_MAP_ANONYMOUS)) {
                uint64_t file_off = r->offset + (zstart - r->start);
                ssize_t nr =
                    pread(r->backing_fd, (uint8_t *) g->host_base + zstart,
                          zend - zstart, (off_t) file_off);
                if (nr < 0)
                    return linux_errno();
            }
        }
        return 0;
    }

    case LINUX_MADV_NORMAL:
    case LINUX_MADV_RANDOM:
    case LINUX_MADV_SEQUENTIAL:
    case LINUX_MADV_WILLNEED:
    case LINUX_MADV_FREE:
    case LINUX_MADV_HUGEPAGE:
    case LINUX_MADV_NOHUGEPAGE:
    case LINUX_MADV_COLD:
    case LINUX_MADV_PAGEOUT:
        /* Advisory hints: no-op in emulation */
        return 0;

    default:
        return -LINUX_EINVAL;
    }
}

/* Anonymous mmap wrapper for other modules. */
int64_t sys_mmap_anon(guest_t *g, uint64_t addr, uint64_t length, int prot)
{
    return sys_mmap(g, addr, length, prot,
                    LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS, -1, 0);
}

/* sys_munmap. */

int64_t sys_munmap(guest_t *g, uint64_t addr, uint64_t length)
{
    if ((addr & 4095) || length == 0)
        return -LINUX_EINVAL;
    length = PAGE_ALIGN_UP(length);
    if (length == 0)
        return -LINUX_EINVAL;
    if (addr > UINT64_MAX - length)
        return -LINUX_EINVAL;

    if (addr <= 0x0000FFFFFFFFFFFFULL) {
        uint64_t unmap_off = addr - g->ipa_base;
        if (unmap_off <= g->guest_size && length <= g->guest_size - unmap_off) {
            uint64_t end = unmap_off + length;

            /* Reject munmap targeting VM infrastructure regions. */
            if (unmap_off < ELF_DEFAULT_BASE && end > PT_POOL_BASE)
                return -LINUX_EINVAL;

            /* Invalidate PTEs first. This may need to split a 2MiB block
             * which can fail if the page table pool is exhausted. Failing
             * before region removal keeps metadata consistent.
             */
            if (guest_invalidate_ptes(g, unmap_off, end) < 0)
                return -LINUX_ENOMEM;
            g->need_tlbi = true;
            for (int i = 0; i < g->nregions; i++) {
                guest_region_t *r = &g->regions[i];
                if (r->start >= end)
                    break;
                if (r->end <= unmap_off)
                    continue;
                if (r->prot == LINUX_PROT_NONE)
                    continue;
                uint64_t zstart = (r->start > unmap_off) ? r->start : unmap_off;
                uint64_t zend = (r->end < end) ? r->end : end;
                memset((uint8_t *) g->host_base + zstart, 0, zend - zstart);
            }
            guest_region_remove(g, unmap_off, end);
            if (unmap_off < mmap_rw_gap_hint)
                mmap_rw_gap_hint = unmap_off;
            if (unmap_off < mmap_rx_gap_hint)
                mmap_rx_gap_hint = unmap_off;
        }
    }
    return 0;
}

/* sys_mprotect. */

int64_t sys_mprotect(guest_t *g, uint64_t addr, uint64_t length, int prot)
{
    if (addr & 4095)
        return -LINUX_EINVAL;
    if (length == 0)
        return 0;
    length = PAGE_ALIGN_UP(length);
    if (length == 0)
        return -LINUX_EINVAL;
    if (addr > UINT64_MAX - length)
        return -LINUX_EINVAL;

    if (addr <= 0x0000FFFFFFFFFFFFULL) {
        uint64_t mprot_off = addr - g->ipa_base;
        if (mprot_off <= g->guest_size && length <= g->guest_size - mprot_off) {
            uint64_t mprot_end = mprot_off + length;

            /* Reject mprotect targeting VM infrastructure (page tables, shim).
             * Matches the guard in sys_munmap.
             */
            if (mprot_off < ELF_DEFAULT_BASE && mprot_end > PT_POOL_BASE)
                return -LINUX_EINVAL;

            guest_region_set_prot(g, mprot_off, mprot_end, prot);
            if (prot != LINUX_PROT_NONE) {
                int page_perms = prot_to_perms(prot);
                if (guest_extend_page_tables(g, mprot_off, mprot_end,
                                             page_perms) < 0)
                    return -LINUX_ENOMEM;
                guest_update_perms(g, mprot_off, mprot_end, page_perms);
            } else {
                guest_invalidate_ptes(g, mprot_off, mprot_end);
            }
            g->need_tlbi = true;
        }
    }
    return 0;
}

/* msync helpers. */

static int same_backing_file(int fd_a, int fd_b)
{
    if (fd_a < 0 || fd_b < 0)
        return 0;
    struct stat st_a, st_b;
    if (fstat(fd_a, &st_a) < 0 || fstat(fd_b, &st_b) < 0)
        return 0;
    return st_a.st_dev == st_b.st_dev && st_a.st_ino == st_b.st_ino;
}

static int64_t pwrite_all_at(int fd,
                             const uint8_t *src,
                             uint64_t len,
                             uint64_t file_off)
{
    while (len > 0) {
        size_t chunk =
            len > (uint64_t) SSIZE_MAX ? (size_t) SSIZE_MAX : (size_t) len;
        ssize_t nw = pwrite(fd, src, chunk, (off_t) file_off);
        if (nw < 0)
            return linux_errno();
        if (nw == 0)
            return -LINUX_EIO;
        src += nw;
        file_off += (uint64_t) nw;
        len -= (uint64_t) nw;
    }

    return 0;
}

static int64_t sync_shared_aliases_range(guest_t *g,
                                         int backing_fd,
                                         uint64_t file_start,
                                         uint64_t file_end)
{
    uint8_t original[4096];

    for (uint64_t chunk_start = file_start; chunk_start < file_end;) {
        uint64_t chunk_end = ALIGN_DOWN(chunk_start + sizeof(original), 4096);
        if (chunk_end <= chunk_start || chunk_end > file_end)
            chunk_end = file_end;
        size_t chunk_len = (size_t) (chunk_end - chunk_start);

        memset(original, 0, chunk_len);
        ssize_t nr =
            pread(backing_fd, original, chunk_len, (off_t) chunk_start);
        if (nr < 0)
            return linux_errno();

        for (int i = 0; i < g->nregions; i++) {
            const guest_region_t *src = &g->regions[i];
            if (!src->shared || src->backing_fd < 0)
                continue;
            if (!(src->prot & LINUX_PROT_WRITE))
                continue;
            if (!same_backing_file(backing_fd, src->backing_fd))
                continue;

            uint64_t region_file_start = src->offset;
            uint64_t region_file_end = src->offset + (src->end - src->start);
            uint64_t wfile_start = chunk_start > region_file_start
                                       ? chunk_start
                                       : region_file_start;
            uint64_t wfile_end =
                chunk_end < region_file_end ? chunk_end : region_file_end;
            if (wfile_start >= wfile_end)
                continue;

            const uint8_t *guest = (const uint8_t *) g->host_base + src->start +
                                   (wfile_start - src->offset);
            size_t offset = (size_t) (wfile_start - chunk_start);
            size_t len = (size_t) (wfile_end - wfile_start);

            for (size_t pos = 0; pos < len;) {
                while (pos < len && guest[pos] == original[offset + pos])
                    pos++;
                size_t run_start = pos;
                while (pos < len && guest[pos] != original[offset + pos])
                    pos++;
                if (pos > run_start) {
                    int64_t err =
                        pwrite_all_at(src->backing_fd, guest + run_start,
                                      pos - run_start, wfile_start + run_start);
                    if (err < 0)
                        return err;
                }
            }
        }

        chunk_start = chunk_end;
    }

    return 0;
}

static int64_t refresh_shared_region_range(guest_t *g,
                                           guest_region_t *r,
                                           uint64_t file_start,
                                           uint64_t file_end)
{
    uint64_t region_file_start = r->offset;
    uint64_t region_file_end = r->offset + (r->end - r->start);
    uint64_t rfile_start =
        file_start > region_file_start ? file_start : region_file_start;
    uint64_t rfile_end =
        file_end < region_file_end ? file_end : region_file_end;
    if (rfile_start >= rfile_end)
        return 0;

    uint64_t guest_off = r->start + (rfile_start - r->offset);
    uint64_t len = rfile_end - rfile_start, file_off = rfile_start;
    uint8_t *buf = (uint8_t *) g->host_base + guest_off;

    while (len > 0) {
        size_t chunk =
            len > (uint64_t) SSIZE_MAX ? (size_t) SSIZE_MAX : (size_t) len;
        ssize_t nr = pread(r->backing_fd, buf, chunk, (off_t) file_off);
        if (nr < 0)
            return linux_errno();
        if (nr == 0)
            break;
        buf += nr;
        file_off += (uint64_t) nr;
        len -= (uint64_t) nr;
    }

    return 0;
}

/* sys_msync. */

int64_t sys_msync(guest_t *g, uint64_t addr, uint64_t length, int flags)
{
    if (addr & 4095)
        return -LINUX_EINVAL;
    if (flags & ~(LINUX_MS_ASYNC | LINUX_MS_INVALIDATE | LINUX_MS_SYNC))
        return -LINUX_EINVAL;
    if ((flags & LINUX_MS_ASYNC) && (flags & LINUX_MS_SYNC))
        return -LINUX_EINVAL;
    if (length == 0)
        return 0;
    if (length > UINT64_MAX - 4095)
        return -LINUX_EINVAL;
    length = PAGE_ALIGN_UP(length);
    if (addr > UINT64_MAX - length)
        return -LINUX_EINVAL;
    if (addr < g->ipa_base)
        return -LINUX_ENOMEM;

    uint64_t off = addr - g->ipa_base;
    if (off > g->guest_size || length > g->guest_size - off)
        return -LINUX_ENOMEM;
    uint64_t end = off + length;

    uint64_t cursor = off;
    while (cursor < end) {
        const guest_region_t *r = guest_region_find(g, cursor);
        if (!r || r->start > cursor)
            return -LINUX_ENOMEM;
        cursor = r->end < end ? r->end : end;
    }

    for (int i = 0; i < g->nregions; i++) {
        const guest_region_t *r = &g->regions[i];
        if (r->start >= end)
            break;
        if (r->end <= off)
            continue;
        if (!r->shared || r->backing_fd < 0)
            continue;

        uint64_t sync_start = r->start > off ? r->start : off;
        uint64_t sync_end = r->end < end ? r->end : end;
        uint64_t file_start = r->offset + (sync_start - r->start);
        uint64_t file_end = file_start + (sync_end - sync_start);

        int64_t err =
            sync_shared_aliases_range(g, r->backing_fd, file_start, file_end);
        if (err < 0)
            return err;

        if (flags & LINUX_MS_SYNC) {
            if (fsync(r->backing_fd) < 0)
                return linux_errno();
        }

        for (int j = 0; j < g->nregions; j++) {
            guest_region_t *dst = &g->regions[j];
            if (!dst->shared || dst->backing_fd < 0)
                continue;
            if (!same_backing_file(r->backing_fd, dst->backing_fd))
                continue;

            int64_t refresh_err =
                refresh_shared_region_range(g, dst, file_start, file_end);
            if (refresh_err < 0)
                return refresh_err;
        }
    }

    return 0;
}
