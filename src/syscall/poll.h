/*
 * Poll/select/epoll syscall handlers
 *
 * Copyright 2026 elfuse contributors
 * Copyright 2025 Moritz Angermann, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * ppoll, pselect6, and epoll (emulated via macOS kqueue).
 */

#pragma once

#include <stdint.h>
#include "core/guest.h"

/* polling/select */
int64_t sys_ppoll(guest_t *g,
                  uint64_t fds_gva,
                  uint32_t nfds,
                  uint64_t timeout_gva,
                  uint64_t sigmask_gva);
int64_t sys_pselect6(guest_t *g,
                     int nfds,
                     uint64_t readfds_gva,
                     uint64_t writefds_gva,
                     uint64_t exceptfds_gva,
                     uint64_t timeout_gva,
                     uint64_t sigmask_gva);

/* epoll (emulated via kqueue) */
int64_t sys_epoll_create1(int flags);
int64_t sys_epoll_ctl(guest_t *g, int epfd, int op, int fd, uint64_t event_gva);
int64_t sys_epoll_pwait(guest_t *g,
                        int epfd,
                        uint64_t events_gva,
                        int maxevents,
                        int timeout_ms,
                        uint64_t sigmask_gva);

/* Eagerly clear a closed guest fd from every epoll instance's interest table.
 * Called from the fd-table close chokepoint; caller holds fd_lock (or runs
 * single-threaded on the relaxed close path).
 */
void epoll_note_fd_closed(int closed_fd);

/* Free an epoll instance (fd_table[epfd].dir) and drop it from the live count.
 * Called from fd_cleanup_entry() for FD_EPOLL slots.
 */
void epoll_instance_free(void *inst);

/* Duplicate an epoll fd so the alias shares the source's eventpoll instance.
 * src_host_fd and src_generation must be snapshotted from fd_table[src_fd] by
 * the caller so a close+reopen ABA is rejected before pinning the instance.
 *
 * Returns the new guest fd or -1 with errno set.
 */
int epoll_dup_fd(int src_fd,
                 int src_host_fd,
                 uint64_t src_generation,
                 int min_guest_fd,
                 int fixed_guest_fd,
                 bool fixed_slot,
                 int linux_flags);

/* Global wakeup pipe for interrupting blocking poll/select/epoll. When
 * exit_group, futex_interrupt, or a guest signal is requested, write to
 * wakeup_pipe_wr to unblock any thread stuck in a host-side poll/select/kevent
 * with infinite timeout.
 */
void wakeup_pipe_init(void);
void wakeup_pipe_signal(void);
int wakeup_pipe_read_fd(void);
void wakeup_pipe_drain(void);
