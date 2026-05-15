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
int path_openat2_is_proc_magiclink(guest_fd_t dirfd, const char *path);
int path_openat2_resolved_within_root(guest_fd_t dirfd,
                                      const char *path,
                                      uint64_t oflags,
                                      bool in_root);
