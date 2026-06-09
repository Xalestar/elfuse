/* Shared guest/host path handling
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/stat.h>

#include "syscall/internal.h"

typedef enum {
    PATH_TR_NONE = 0,
    PATH_TR_NOFOLLOW = 1u << 0,
    PATH_TR_CREATE = 1u << 1,
    PATH_TR_CREATE_PARENTS = 1u << 2,
} path_translate_flags_t;

typedef struct {
    const char *guest_path;
    const char *intercept_path;
    const char *host_path;
    int proc_resolved;
    bool fuse_path;
    char proc_path[LINUX_PATH_MAX];
    char guest_buf[LINUX_PATH_MAX];
    char host_buf[LINUX_PATH_MAX];
} path_translation_t;

bool path_might_use_open_intercept(const char *path);
bool path_might_use_stat_intercept(const char *path);
int path_check_intercept_access(const struct stat *st, int mode, int flags);
int path_translate_at(guest_fd_t dirfd,
                      const char *path,
                      unsigned int flags,
                      path_translation_t *tx);
int path_translate_dirent_name(guest_fd_t dirfd,
                               const char *host_name,
                               char *guest_name,
                               size_t guest_name_sz);
int resolve_proc_at_path(guest_fd_t dirfd,
                         const char *path,
                         char *out,
                         size_t outsz);
int resolve_proc_dirfd_path(guest_fd_t dirfd,
                            const char *path,
                            char *out,
                            size_t outsz);
int sys_path_has_symlink(guest_fd_t dirfd, const char *path);

const char *path_resolve_sysroot_path(const char *path,
                                      char *buf,
                                      size_t bufsz);
const char *path_resolve_sysroot_nofollow_path(const char *path,
                                               char *buf,
                                               size_t bufsz);
const char *path_resolve_sysroot_create_path(const char *path,
                                             char *buf,
                                             size_t bufsz,
                                             bool create_parents);

int path_openat2_stays_beneath(const char *path, bool clamp_at_root);
int path_openat2_normalize_in_root(const char *path, char *out, size_t outsz);
bool path_openat2_is_fd_magiclink_anchor(guest_fd_t dirfd, const char *path);
int path_openat2_resolved_within_root(guest_fd_t dirfd,
                                      const char *path,
                                      uint64_t oflags,
                                      bool in_root);
/* Returns 1 if resolving path against dirfd would cross a mount boundary
 * from the guest's perspective, 0 if it stays inside the same logical
 * filesystem, and -1 with errno set on dirfd lookup failures. Mount
 * classes are: regular guest filesystem, /proc, /dev, /sys, /tmp,
 * /dev/shm, and each live or tombstoned FUSE mount (keyed by mount_id).
 * The walker classifies every intermediate prefix as it advances, so
 * transient excursions through /proc that lexically resolve back into
 * the root class still surface as a crossing. Symlink components are
 * expanded inline against the host-walk fd when possible so a link
 * whose target lives in a different class is caught at the precheck.
 *
 * When out_start_class is non-NULL it is populated with the dirfd's
 * mount class on every non-error return so the caller can re-run the
 * check against the actually opened fd via path_openat2_check_fd_xdev.
 * The post-open check is what closes the symlink bypass for callers
 * that do not also set RESOLVE_NO_SYMLINKS: the precheck's fstatat
 * walk cannot see symlinks that live in a sidecar shadow directory
 * (case-fold sysroot), so the kernel may follow a link the walker did
 * not, and only F_GETPATH on the resulting fd reveals the real
 * landing site.
 *
 * Known gaps (best-effort by design):
 *  - host_path_to_guest_path strips the configured sysroot prefix with
 *    a case-sensitive strncmp; on case-insensitive macOS volumes a
 *    differently-cased F_GETPATH could fail to strip and the dirfd is
 *    then classified as the root class. Sysroots that happen to live
 *    under /proc, /dev, or /sys on the host are not supported.
 *  - A sibling vCPU that chdir(2)s, dup3(2)s over dirfd, or mounts /
 *    unmounts a FUSE filesystem between this check and the subsequent
 *    sys_openat may shift the resolution into a different mount class
 *    without the cross being detected. The race window is narrow and
 *    the guest is in elfuse's trust domain.
 */
int path_openat2_crosses_mount(guest_fd_t dirfd,
                               const char *path,
                               bool in_root,
                               int *out_start_class);

/* Post-open verification for RESOLVE_NO_XDEV. Reads the host-side
 * canonical path of the just-opened guest fd via fcntl(F_GETPATH),
 * strips the sysroot prefix, and classifies the result against the
 * start class captured by path_openat2_crosses_mount. Returns 1 if
 * the resolved fd sits in a different mount class than the resolution
 * started in, 0 if it stays in the same class, -1 with errno set on
 * lookup failures (e.g. fd closed, F_GETPATH refused). Catches the
 * symlink-driven crossings that the string-only precheck misses by
 * design.
 */
int path_openat2_check_fd_xdev(int guest_fd, int start_class);
