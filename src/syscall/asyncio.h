/*
 * Signal-driven I/O (O_ASYNC / SIGIO / SIGURG)
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Linux delivers SIGIO to the owner of an O_ASYNC descriptor whenever the fd
 * becomes ready, and SIGURG to a socket owner when out-of-band data arrives
 * even without O_ASYNC. macOS classic BSD SIGIO does not name the fd and
 * coalesces, so instead a dedicated kqueue watcher thread registers the async
 * host fds and, on a readiness edge, resolves the per-fd owner and injects the
 * guest signal via signal_queue().
 *
 * O_ASYNC is per open-file-description: the armed bit lives in
 * fd_entry_t.linux_flags and the owner in fd_entry_t.fasync_owner*. This module
 * only owns the readiness watching; fs.c/io.c drive the arm/disarm from the
 * fcntl(F_SETFL)/ioctl(FIOASYNC) paths through asyncio_apply().
 */

#pragma once

#include <stdbool.h>
#include <stdint.h>

/* fasync owner kinds stored in fd_entry_t.fasync_owner_type. Zero == NONE so a
 * zero-initialized fd slot means "no owner", independent of the Linux
 * f_owner_ex type numbering (which fs.c translates at the fcntl boundary).
 */
#define FASYNC_OWNER_NONE 0
#define FASYNC_OWNER_TID 1
#define FASYNC_OWNER_PID 2
#define FASYNC_OWNER_PGRP 3

/* Initialize the watcher (kqueue + detached thread). Idempotent; call once from
 * syscall_init() before guest code runs. A failure to create the kqueue or
 * thread leaves the subsystem disabled: arm/apply become no-ops and O_ASYNC is
 * still tracked for F_GETFL round-trip, just without delivery.
 */
void asyncio_init(void);

/* Flip the O_ASYNC armed bit for guest_fd and (dis)arm the readiness watcher.
 * expect_gen is the caller's fd-slot snapshot generation; the linux_flags
 * update is serialized under fd_lock and applied only when the slot still holds
 * that generation, so a concurrent close+reopen cannot resurrect a stale bit.
 * The scan reaches every alias sharing the open-file-description and reads each
 * one's own host fd and class; pollability is decided per slot (regular files
 * and directories never generate SIGIO on Linux, so they only carry the flag
 * bit and are never registered).
 */
void asyncio_apply(int guest_fd, uint64_t expect_gen, bool on);

/* Register readiness watching for an already-armed fd. Used by the dup path,
 * which copies the armed bit under fd_lock and then arms the alias. generation
 * is the fd-slot generation captured at arm time; it is packed into the kqueue
 * event so a stale event on a reused slot is dropped. No-op for non-pollable fd
 * types.
 */
void asyncio_arm(int guest_fd, uint64_t generation, int host_fd, int fd_type);

/* Deregister readiness watching for host_fd. Keyed by host_fd because the guest
 * slot may already be gone (close path). Safe to call for fds that were never
 * armed.
 */
void asyncio_disarm(int host_fd);

/* Store the SIGIO/SIGURG owner for guest_fd under fd_lock, guarded by the
 * caller's snapshot generation so a close+reopen in the race window is a no-op.
 * owner_type is a FASYNC_OWNER_* value.
 */
void fasync_owner_set(int guest_fd,
                      uint64_t expect_gen,
                      int owner_type,
                      int owner);

/* Read the owner back under fd_lock. A closed slot reports {NONE, 0}. */
void fasync_owner_get(int guest_fd,
                      uint64_t expect_gen,
                      int *owner_type_out,
                      int *owner_out);
