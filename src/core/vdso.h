/* Minimal vDSO (Virtual Dynamic Shared Object)
 *
 * Copyright 2026 elfuse contributors
 * Copyright 2025 Moritz Angermann, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Provides a minimal vDSO ELF image for the guest. The vDSO provides
 * __kernel_rt_sigreturn (signal frame restorer) and standard Linux kernel
 * helper functions. Mapped into guest memory; address provided via
 * AT_SYSINFO_EHDR in the auxiliary vector.
 */

#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "core/guest.h"

/* Guest address where the vDSO is placed (one 4KiB page, below PT pool) */
#define VDSO_BASE 0x0000F000ULL
#define VDSO_SIZE 0x00001000ULL /* 4KiB */
/* Offset of __kernel_rt_sigreturn (the signal trampoline glibc/musl jumps
 * to via X30/LR after the handler returns). Must match TEXT_OFF_SIGRET in
 * src/core/vdso.c; kept here so signal.c can target it without including
 * the vDSO internals.
 */
#define VDSO_OFF_SIGRET 0x0E0

/* Build a minimal vDSO ELF image at VDSO_BASE in guest memory.
 * The image contains a valid ELF header, one LOAD program header, SHT_DYNSYM
 * and SHT_STRTAB sections, and a __kernel_rt_sigreturn symbol pointing to a
 * small trampoline (mov x8, #139; svc #0).
 * Returns the GVA of the ELF header (== VDSO_BASE), or 0 on failure.
 */
uint64_t vdso_build(guest_t *g);

/* Publish a new vvar anchor under the seqlock. Handles both the initial
 * seed (seq 0 -> 1 -> 2) and refresh (seq 2K -> 2K+1 -> 2K+2) atomically
 * through one CAS-then-release-store sequence. Concurrent publishers
 * either lose the CAS or observe an odd seq and bail without blocking;
 * trampoline readers detect mid-write tearing via their own LDAR
 * snapshot/recheck. Callers (sys_clock_gettime / sys_gettimeofday) only
 * need to invoke this when an SVC trap from the vDSO trampoline carries a
 * trustworthy guest CNTVCT in X9.
 *
 * Overflow invariant: this function, the trampoline math, and
 * vdso_realtime_drift_exceeded all depend on VDSO_ANCHOR_AGE_SHIFT == 22
 * capping the per-call CNTVCT delta below 2^22. That bound keeps
 * (delta * 699050666) below 2^52 (no uint64 overflow) and keeps
 * anchor_nsec + delta_ns below 2e9 (so the trampoline's sub-1e9 carry
 * collapses to a single SUBS + CSEL + CINC instead of a UDIV). The
 * host-side drift check must apply the same formula and the same cap;
 * any divergence lets the trampoline interpolate from a stale anchor.
 */
void vdso_seed_anchor(guest_t *g,
                      uint64_t guest_cntvct,
                      int64_t mono_sec,
                      int64_t mono_nsec,
                      int64_t real_sec,
                      int64_t real_nsec);

/* GVA at which the trampoline's svc_fallback issues its SVC. Used by
 * sys_clock_gettime to verify a clock_gettime trap actually came from the vDSO
 * fallback path (and thus carries a guest-frame CNTVCT in X9) versus an
 * unrelated raw syscall(SYS_clock_gettime, ...). The trap returns to SVC_PC
 * + 4, so callers compare ELR_EL1 against that.
 */
uint64_t vdso_clock_gettime_svc_pc(void);
uint64_t vdso_gettimeofday_svc_pc(void);

/* Returns true when the seqlock counter is at a stable (nonzero, even)
 * generation, i.e. the anchor is currently publishable. Uses acquire
 * ordering paired with vdso_seed_anchor's release store of the next
 * even generation. Callers use this to gate the age / drift checks
 * that decide whether to publish a refresh.
 */
bool vdso_anchor_is_seeded(guest_t *g);

/* Mirror the shim attention bitmask into the vvar page. The vDSO
 * clock_gettime fast path reads this word and falls back to SVC whenever
 * it is nonzero, preserving the normal post-HVC timer/signal epilogue while
 * guest attention is pending.
 */
void vdso_attention_or(guest_t *g, uint32_t bits);
void vdso_attention_and(guest_t *g, uint32_t mask);

/* True iff the anchor is currently stable AND (current_cntvct -
 * anchor_cntvct) has exceeded the trampoline's age cap. The host uses
 * this with a freshly-sampled CNTVCT to decide whether to publish a
 * refresh through vdso_seed_anchor.
 */
bool vdso_anchor_age_exceeded(guest_t *g, uint64_t current_cntvct);

/* True iff the anchor is seeded AND the wall-clock value predicted from
 * the anchor + CNTVCT delta differs from the supplied freshly-sampled
 * REALTIME (real_sec, real_nsec) by more than VDSO_ANCHOR_MAX_DRIFT_NS.
 * Catches macOS NTP steps that shift wall time without bumping CNTVCT.
 */
bool vdso_realtime_drift_exceeded(guest_t *g,
                                  uint64_t current_cntvct,
                                  int64_t real_sec,
                                  int64_t real_nsec);
