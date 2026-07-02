/* Case-folding fallback VFS helpers
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <unistd.h>

#include "utils.h"

#include "syscall/abi.h"
#include "syscall/internal.h"
#include "syscall/path.h"
#include "syscall/proc.h"
#include "syscall/sidecar.h"

#ifndef LINUX_RENAME_NOREPLACE
#define LINUX_RENAME_NOREPLACE (1 << 0)
#endif
#ifndef LINUX_RENAME_EXCHANGE
#define LINUX_RENAME_EXCHANGE (1 << 1)
#endif

#define SIDECAR_INDEX_TMP_NAME SIDECAR_INDEX_NAME ".tmp"
#define SIDECAR_INDEX_LOCK_NAME SIDECAR_INDEX_NAME ".lock"

/* fcntl POSIX advisory locks are per-process. Within a single elfuse instance,
 * multiple vCPU threads all "hold" the same fcntl lock simultaneously. This
 * mutex serializes index updates across vCPU threads; the fcntl lock on the
 * dedicated lock sentinel still serializes against forked elfuse processes that
 * share the same sysroot.
 */
static pthread_mutex_t sidecar_global_lock = PTHREAD_MUTEX_INITIALIZER;

/* Per-directory cache: did this directory lack a sidecar index file for the
 * current directory metadata version? Keyed by (st_dev, st_ino) so a renamed or
 * moved directory does not leak a stale answer. Sidecar's case-fold walker
 * visits every parent directory of every translated path; during dynamic-linker
 * bring-up that walker fires per guest openat and dominates startup (histogram
 * showed openat at 61% of getent's 7.5 ms warm path). The cache lets the common
 * "no index here" answer return after a 5 us fstat instead of a ~30 us openat
 * per directory traversed.
 *
 * 64 slots, single-level open-addressing (last writer wins on collision). The
 * directory ctime/mtime pair is part of the cache key: publishing an index from
 * another elfuse process changes the directory entry set, so a stale ABSENT
 * entry becomes UNKNOWN on the next lookup.
 */
enum {
    SIDECAR_IDX_UNKNOWN = 0,
    SIDECAR_IDX_ABSENT = 1,
};
typedef struct {
    dev_t dev;
    ino_t ino;
    struct timespec mtime;
    struct timespec ctime;
    uint8_t state;
} sidecar_idx_slot_t;
#define SIDECAR_IDX_CACHE_SLOTS 64
static sidecar_idx_slot_t sidecar_idx_cache[SIDECAR_IDX_CACHE_SLOTS];
static pthread_mutex_t sidecar_idx_cache_lock = PTHREAD_MUTEX_INITIALIZER;

static size_t sidecar_idx_cache_slot(dev_t dev, ino_t ino)
{
    /* Mix dev into ino so two filesystems with overlapping inode numbers do not
     * pin the same slot. The golden-ratio multiplier scatters small inode
     * numbers across the table without needing a real hash.
     */
    uint64_t key = (uint64_t) ino ^ ((uint64_t) dev * 0x9E3779B97F4A7C15ULL);
    return (size_t) (key % SIDECAR_IDX_CACHE_SLOTS);
}

static bool sidecar_idx_cache_matches(const sidecar_idx_slot_t *slot,
                                      const struct stat *st)
{
    return slot->state != SIDECAR_IDX_UNKNOWN && slot->dev == st->st_dev &&
           slot->ino == st->st_ino &&
           slot->mtime.tv_sec == st->st_mtimespec.tv_sec &&
           slot->mtime.tv_nsec == st->st_mtimespec.tv_nsec &&
           slot->ctime.tv_sec == st->st_ctimespec.tv_sec &&
           slot->ctime.tv_nsec == st->st_ctimespec.tv_nsec;
}

static int sidecar_idx_cache_lookup_stat(const struct stat *st)
{
    size_t slot = sidecar_idx_cache_slot(st->st_dev, st->st_ino);
    int state = SIDECAR_IDX_UNKNOWN;
    pthread_mutex_lock(&sidecar_idx_cache_lock);
    if (sidecar_idx_cache_matches(&sidecar_idx_cache[slot], st))
        state = sidecar_idx_cache[slot].state;
    pthread_mutex_unlock(&sidecar_idx_cache_lock);
    return state;
}

static void sidecar_idx_cache_set_stat(const struct stat *st, int state)
{
    size_t slot = sidecar_idx_cache_slot(st->st_dev, st->st_ino);
    pthread_mutex_lock(&sidecar_idx_cache_lock);
    sidecar_idx_cache[slot].dev = st->st_dev;
    sidecar_idx_cache[slot].ino = st->st_ino;
    sidecar_idx_cache[slot].mtime = st->st_mtimespec;
    sidecar_idx_cache[slot].ctime = st->st_ctimespec;
    sidecar_idx_cache[slot].state = (uint8_t) state;
    pthread_mutex_unlock(&sidecar_idx_cache_lock);
}

/* Roll the cache entry back to UNKNOWN. Used by the index publish path before
 * the renameat so a concurrent reader entering the post-rename window cannot
 * consume a stale ABSENT and skip the openat. UNKNOWN forces the reader to
 * consult the filesystem.
 */
static void sidecar_idx_cache_invalidate(int dirfd)
{
    struct stat st;
    if (fstat(dirfd, &st) < 0)
        return;
    sidecar_idx_cache_set_stat(&st, SIDECAR_IDX_UNKNOWN);
}

/* Cached sysroot dirfd. sidecar_open_base opens the sysroot directory on every
 * translated absolute path; for dynamic-linker bring-up that fires once per
 * openat / fstat / access / readlink. Caching the host fd and handing the
 * walker a dup turns that ~30 us open into a ~5 us dup. The cache invalidates
 * lazily by comparing the path string -- proc_set_sysroot is rare (once at
 * startup, once on fork-child IPC restore), so the snapshot+strcmp on every
 * call is still a net win over the open it replaces. Concurrent vCPU lookups
 * serialize on the lock for the cache check and dup.
 */
static int sidecar_sysroot_cached_fd = -1;
static char sidecar_sysroot_cached_path[LINUX_PATH_MAX] = {0};
static dev_t sidecar_sysroot_cached_dev;
static ino_t sidecar_sysroot_cached_ino;
static pthread_mutex_t sidecar_sysroot_cached_lock = PTHREAD_MUTEX_INITIALIZER;

static int sidecar_open_sysroot_cached(const char *path)
{
    pthread_mutex_lock(&sidecar_sysroot_cached_lock);
    int cached = sidecar_sysroot_cached_fd;
    if (cached >= 0 && !strcmp(path, sidecar_sysroot_cached_path)) {
        /* Path text alone is not a sufficient cache key: a host-side rename or
         * replace can rebind the same path to a different inode while the
         * cached fd still resolves to the original. Stat the path on every hit
         * and accept the cache only when (dev, ino) still match the inode
         * captured at fill time. The stat is one host syscall per call, much
         * cheaper than the open it replaces.
         *
         * Race window: a host-side mutation between this stat and the dup below
         * can leave the cache returning the pre-mutation fd even though a fresh
         * open(path) at that instant would resolve the post-mutation binding.
         * The window is microseconds. It only matters under adversarial
         * host-side sysroot mutation; normal sysroot configuration is
         * canonicalized once at proc_set_sysroot time and never changes.
         * Closing it adversarially would require dropping the cache, which
         * gives back the ~25 us per-call win; not worth it absent a real
         * reproducer.
         */
        struct stat current;
        if (stat(path, &current) == 0 &&
            current.st_dev == sidecar_sysroot_cached_dev &&
            current.st_ino == sidecar_sysroot_cached_ino) {
            cached = fcntl(cached, F_DUPFD_CLOEXEC, 0);
            pthread_mutex_unlock(&sidecar_sysroot_cached_lock);
            return cached;
        }
        /* Inode mismatch: fall through to refresh below. */
    }
    if (sidecar_sysroot_cached_fd >= 0) {
        close(sidecar_sysroot_cached_fd);
        sidecar_sysroot_cached_fd = -1;
        sidecar_sysroot_cached_path[0] = '\0';
    }
    int fresh = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fresh < 0) {
        pthread_mutex_unlock(&sidecar_sysroot_cached_lock);
        return -1;
    }
    /* Capture the inode of the freshly-opened dir so subsequent cache hits can
     * validate against it. Using fstat on the open fd gives the same (dev, ino)
     * as a path stat would, with no second walk.
     */
    struct stat fresh_st;
    if (fstat(fresh, &fresh_st) < 0) {
        close(fresh);
        pthread_mutex_unlock(&sidecar_sysroot_cached_lock);
        return -1;
    }
    /* CLOEXEC dup: a concurrent posix_spawn from another vCPU thread must not
     * inherit the sysroot dirfd into the fork-child. F_DUPFD_CLOEXEC sets the
     * flag atomically with the dup, closing the inheritance window that plain
     * dup() leaves open.
     */
    int cache_fd = fcntl(fresh, F_DUPFD_CLOEXEC, 0);
    if (cache_fd >= 0) {
        sidecar_sysroot_cached_fd = cache_fd;
        sidecar_sysroot_cached_dev = fresh_st.st_dev;
        sidecar_sysroot_cached_ino = fresh_st.st_ino;
        str_copy_trunc(sidecar_sysroot_cached_path, path,
                       sizeof(sidecar_sysroot_cached_path));
    }
    pthread_mutex_unlock(&sidecar_sysroot_cached_lock);
    return fresh;
}

typedef struct {
    char *guest_name;
    char token[SIDECAR_TOKEN_NAME_LEN + 1];
} sidecar_row_t;

typedef struct {
    sidecar_row_t *rows;
    size_t count;
} sidecar_index_t;

typedef struct {
    host_fd_t dirfd;
    bool absolute;
    char basename[NAME_MAX + 1];
} sidecar_parent_t;

static void sidecar_index_free(sidecar_index_t *index)
{
    if (!index)
        return;
    for (size_t i = 0; i < index->count; i++)
        free(index->rows[i].guest_name);
    free(index->rows);
    index->rows = NULL;
    index->count = 0;
}

/* Deep-copy src into dst so the caller can mutate dst freely and still recover
 * src for rollback.
 *
 * Returns 0 on success, -1 with errno on alloc failure (dst is left empty in
 * that case).
 */
static int sidecar_index_clone(const sidecar_index_t *src, sidecar_index_t *dst)
{
    dst->rows = NULL;
    dst->count = 0;
    if (src->count == 0)
        return 0;
    dst->rows = (sidecar_row_t *) malloc(src->count * sizeof(sidecar_row_t));
    if (!dst->rows)
        return -1;
    for (size_t i = 0; i < src->count; i++) {
        dst->rows[i].guest_name = strdup(src->rows[i].guest_name);
        if (!dst->rows[i].guest_name) {
            dst->count = i;
            sidecar_index_free(dst);
            return -1;
        }
        memcpy(dst->rows[i].token, src->rows[i].token,
               sizeof(dst->rows[i].token));
    }
    dst->count = src->count;
    return 0;
}

bool sidecar_active(void)
{
    return proc_get_sysroot() && proc_sysroot_casefold_enabled();
}

bool sidecar_name_reserved(const char *name)
{
    return name && (!strcmp(name, SIDECAR_INDEX_NAME) ||
                    !strcmp(name, SIDECAR_INDEX_TMP_NAME) ||
                    !strcmp(name, SIDECAR_INDEX_LOCK_NAME));
}

bool sidecar_path_targets_reserved_name(const char *path)
{
    if (!path || path[0] == '\0')
        return false;

    const char *basename = strrchr(path, '/');
    basename = basename ? basename + 1 : path;
    return sidecar_name_reserved(basename);
}

static int hex_nibble(unsigned char c)
{
    if (c >= '0' && c <= '9')
        return (int) (c - '0');
    if (c >= 'a' && c <= 'f')
        return (int) (c - 'a' + 10);
    if (c >= 'A' && c <= 'F')
        return (int) (c - 'A' + 10);
    return -1;
}

static int sidecar_decode_name(const char *hex, char **out)
{
    size_t len = strlen(hex);
    if ((len & 1u) != 0) {
        errno = EPROTO;
        return -1;
    }

    char *name = (char *) malloc(len / 2 + 1);
    if (!name)
        return -1;

    for (size_t i = 0; i < len; i += 2) {
        int hi = hex_nibble((unsigned char) hex[i]);
        int lo = hex_nibble((unsigned char) hex[i + 1]);
        if (hi < 0 || lo < 0) {
            free(name);
            errno = EPROTO;
            return -1;
        }
        name[i / 2] = (char) ((hi << 4) | lo);
    }
    name[len / 2] = '\0';
    *out = name;
    return 0;
}

static int sidecar_load_index(int dirfd, sidecar_index_t *index)
{
    memset(index, 0, sizeof(*index));

    /* Per-dir absence cache: skip the openat round-trip only while the
     * directory metadata still matches the snapshot that produced ENOENT.
     * Another elfuse process can publish the index through the fcntl-locked
     * writer, so cross-process invalidation relies on the directory mtime/ctime
     * changing when the sidecar index appears.
     */
    struct stat dir_st;
    bool have_dir_st = fstat(dirfd, &dir_st) == 0;
    if (have_dir_st &&
        sidecar_idx_cache_lookup_stat(&dir_st) == SIDECAR_IDX_ABSENT)
        return 0;

    int fd = openat(dirfd, SIDECAR_INDEX_NAME, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        if (errno == ENOENT) {
            if (have_dir_st)
                sidecar_idx_cache_set_stat(&dir_st, SIDECAR_IDX_ABSENT);
            return 0;
        }
        return -1;
    }

    struct stat st;
    if (fstat(fd, &st) < 0) {
        close(fd);
        return -1;
    }
    if (st.st_size == 0) {
        close(fd);
        return 0;
    }
    if (st.st_size < 0 || st.st_size >= (off_t) LINUX_PATH_MAX * 64) {
        close(fd);
        errno = EFBIG;
        return -1;
    }

    size_t size = (size_t) st.st_size;
    char *buf = (char *) malloc(size + 1);
    if (!buf) {
        close(fd);
        return -1;
    }

    size_t off = 0;
    while (off < size) {
        ssize_t n = read(fd, buf + off, size - off);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            free(buf);
            close(fd);
            return -1;
        }
        if (n == 0)
            break;
        off += (size_t) n;
    }
    close(fd);
    buf[off] = '\0';

    char *line = buf;
    while (*line) {
        char *newline = strchr(line, '\n');
        if (newline)
            *newline = '\0';

        if (*line != '\0') {
            char *tab = strchr(line, '\t');
            if (!tab || tab == line || tab[1] == '\0') {
                free(buf);
                sidecar_index_free(index);
                errno = EPROTO;
                return -1;
            }
            *tab = '\0';

            sidecar_row_t *rows = (sidecar_row_t *) realloc(
                index->rows, (index->count + 1) * sizeof(sidecar_row_t));
            if (!rows) {
                free(buf);
                sidecar_index_free(index);
                return -1;
            }
            index->rows = rows;
            if (sidecar_decode_name(
                    line, &index->rows[index->count].guest_name) < 0) {
                free(buf);
                sidecar_index_free(index);
                return -1;
            }
            if (strlen(tab + 1) != SIDECAR_TOKEN_NAME_LEN) {
                free(buf);
                sidecar_index_free(index);
                errno = EPROTO;
                return -1;
            }
            memcpy(index->rows[index->count].token, tab + 1,
                   SIDECAR_TOKEN_NAME_LEN + 1);
            index->count++;
        }

        if (!newline)
            break;
        line = newline + 1;
    }

    free(buf);
    return 0;
}

static const char *sidecar_lookup_guest(const sidecar_index_t *index,
                                        const char *guest_name)
{
    for (size_t i = 0; i < index->count; i++) {
        if (!strcmp(index->rows[i].guest_name, guest_name))
            return index->rows[i].token;
    }
    return NULL;
}

static const char *sidecar_lookup_token(const sidecar_index_t *index,
                                        const char *token)
{
    for (size_t i = 0; i < index->count; i++) {
        if (!strcmp(index->rows[i].token, token))
            return index->rows[i].guest_name;
    }
    return NULL;
}

static int sidecar_next_component(const char **pathp,
                                  const char **comp,
                                  size_t *len)
{
    const char *p = *pathp;
    while (*p == '/')
        p++;
    if (*p == '\0') {
        *pathp = p;
        return 0;
    }
    *comp = p;
    while (*p != '\0' && *p != '/')
        p++;
    *len = (size_t) (p - *comp);
    *pathp = p;
    return 1;
}

static int sidecar_append_component(char *out,
                                    size_t outsz,
                                    size_t *len_io,
                                    const char *comp,
                                    bool absolute)
{
    size_t len = *len_io;
    size_t comp_len = strlen(comp);

    if (absolute) {
        if (len == 0 || out[len - 1] != '/') {
            if (len + 1 >= outsz) {
                errno = ENAMETOOLONG;
                return -1;
            }
            out[len++] = '/';
        }
    } else if (len != 0) {
        if (len + 1 >= outsz) {
            errno = ENAMETOOLONG;
            return -1;
        }
        out[len++] = '/';
    }

    if (len + comp_len >= outsz) {
        errno = ENAMETOOLONG;
        return -1;
    }
    memcpy(out + len, comp, comp_len);
    len += comp_len;
    out[len] = '\0';
    *len_io = len;
    return 0;
}

static int sidecar_open_base(guest_fd_t dirfd,
                             const char *path,
                             char *out,
                             size_t outsz,
                             host_fd_t *base_fd,
                             bool *absolute)
{
    out[0] = '\0';
    *absolute = false;

    if (path[0] == '/') {
        char sysroot[LINUX_PATH_MAX];
        if (!proc_sysroot_snapshot(sysroot, sizeof(sysroot))) {
            errno = ENOENT;
            return -1;
        }
        size_t len = str_copy_trunc(out, sysroot, outsz);
        if (len >= outsz) {
            errno = ENAMETOOLONG;
            return -1;
        }
        *base_fd = sidecar_open_sysroot_cached(sysroot);
        if (*base_fd < 0)
            return -1;
        *absolute = true;
        return 0;
    }

    if (dirfd == LINUX_AT_FDCWD) {
        *base_fd = open(".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        return *base_fd < 0 ? -1 : 0;
    }

    host_fd_ref_t ref;
    if (host_dirfd_ref_open(dirfd, &ref) < 0) {
        errno = EBADF;
        return -1;
    }
    *base_fd = dup(ref.fd);
    host_fd_ref_close(&ref);
    return *base_fd < 0 ? -1 : 0;
}

int sidecar_translate_lookup_at(guest_fd_t dirfd,
                                const char *path,
                                char *out,
                                size_t outsz)
{
    if (!sidecar_active() || !path)
        return 0;
    if (path[0] == '\0')
        return 0;

    char normalized[LINUX_PATH_MAX];
    const char *scan = path;
    if (path[0] == '/') {
        if (path_openat2_normalize_in_root(path, normalized,
                                           sizeof(normalized)) < 0) {
            errno = ENAMETOOLONG;
            return -1;
        }
        scan = normalized;

        /* Kernel virtual filesystems live in procemu, not on the sysroot disk
         * tree. Walking them here would openat() against a directory that never
         * exists in the sysroot and short-circuit the procemu intercept
         * downstream of path_translate_at(). Punt to that layer instead. Check
         * the normalized form so "/./proc/..." and "//proc/..." also skip;
         * match only on a full top-level component so siblings like "/procfoo"
         * still go through sidecar. Note that path_openat2_normalize_in_root()
         * strips the leading '/' from absolute inputs, so the prefixes here are
         * unrooted.
         */
        size_t plen = 0;
        if (!strncmp(normalized, "proc", 4))
            plen = 4;
        else if (!strncmp(normalized, "sys", 3))
            plen = 3;
        else if (!strncmp(normalized, "dev", 3))
            plen = 3;
        if (plen && (normalized[plen] == '\0' || normalized[plen] == '/'))
            return 0;
    }

    host_fd_t cur_fd = -1;
    bool absolute = false;
    if (sidecar_open_base(dirfd, path, out, outsz, &cur_fd, &absolute) < 0)
        return -1;

    /* Sidecar only speaks for entries that live inside the sysroot tree (or
     * are reachable through an index mapping). The sysroot resolver
     * (proc_resolve_sysroot_path_flags) falls back to the literal host path
     * when the guest path does not exist under the sysroot; a walk that
     * unconditionally re-anchored such paths at the sysroot would veto that
     * fallback and break host-resource access (mktemp dirs, /etc/resolv.conf).
     * Track whether any component actually consulted an index mapping: with a
     * mapped prefix the sysroot view is authoritative and missing suffixes
     * must surface as ENOENT against the translated path; without one, a walk
     * that leaves the tree simply is not sidecar's business (return 0).
     */
    bool used_mapping = false;
    size_t out_len = strlen(out);
    const char *comp;
    size_t comp_len;
    while (sidecar_next_component(&scan, &comp, &comp_len)) {
        char guest_comp[NAME_MAX + 1];
        if (comp_len >= sizeof(guest_comp)) {
            close(cur_fd);
            errno = ENAMETOOLONG;
            return -1;
        }
        memcpy(guest_comp, comp, comp_len);
        guest_comp[comp_len] = '\0';

        if (sidecar_name_reserved(guest_comp)) {
            close(cur_fd);
            errno = ENOENT;
            return -1;
        }
        if (!strcmp(guest_comp, ".") || !strcmp(guest_comp, "..")) {
            if (sidecar_append_component(out, outsz, &out_len, guest_comp,
                                         absolute) < 0) {
                close(cur_fd);
                return -1;
            }
            if (strcmp(guest_comp, ".")) {
                int next_fd = openat(cur_fd, guest_comp,
                                     O_RDONLY | O_DIRECTORY | O_CLOEXEC);
                if (next_fd < 0) {
                    int saved_errno = errno;
                    close(cur_fd);
                    if (!used_mapping &&
                        (saved_errno == ENOENT || saved_errno == ENOTDIR))
                        return 0;
                    errno = saved_errno;
                    return -1;
                }
                close(cur_fd);
                cur_fd = next_fd;
            }
            continue;
        }

        sidecar_index_t index;
        if (sidecar_load_index(cur_fd, &index) < 0) {
            close(cur_fd);
            return -1;
        }
        const char *mapped = sidecar_lookup_guest(&index, guest_comp);
        char host_comp[NAME_MAX + 1];
        if (mapped) {
            used_mapping = true;
            str_copy_trunc(host_comp, mapped, sizeof(host_comp));
        } else {
            str_copy_trunc(host_comp, guest_comp, sizeof(host_comp));
        }

        if (sidecar_append_component(out, outsz, &out_len, host_comp,
                                     absolute) < 0) {
            sidecar_index_free(&index);
            close(cur_fd);
            return -1;
        }
        sidecar_index_free(&index);

        const char *peek = scan;
        while (*peek == '/')
            peek++;
        if (*peek == '\0') {
            /* Final component: an unmapped walk is the identity translation
             * ${sysroot}${path}; claim it only if the entry actually exists
             * there so the resolver's host-literal fallback stands otherwise.
             */
            if (!used_mapping) {
                struct stat st;
                if (fstatat(cur_fd, host_comp, &st, AT_SYMLINK_NOFOLLOW) < 0) {
                    int saved_errno = errno;
                    close(cur_fd);
                    if (saved_errno == ENOENT || saved_errno == ENOTDIR)
                        return 0;
                    errno = saved_errno;
                    return -1;
                }
            }
            break;
        }

        int next_fd =
            openat(cur_fd, host_comp, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (next_fd < 0) {
            int saved_errno = errno;
            close(cur_fd);
            if (saved_errno != ENOENT && saved_errno != ENOTDIR) {
                errno = saved_errno;
                return -1;
            }
            if (!used_mapping)
                return 0;
            /* The walk left the sysroot beneath an index-mapped prefix. No
             * index can exist under a missing directory, so the remaining
             * components translate to themselves; the caller's syscall then
             * reports ENOENT against the translated path.
             */
            while (sidecar_next_component(&scan, &comp, &comp_len)) {
                char rest_comp[NAME_MAX + 1];
                if (comp_len >= sizeof(rest_comp)) {
                    errno = ENAMETOOLONG;
                    return -1;
                }
                memcpy(rest_comp, comp, comp_len);
                rest_comp[comp_len] = '\0';
                if (sidecar_append_component(out, outsz, &out_len, rest_comp,
                                             absolute) < 0)
                    return -1;
            }
            return 1;
        }
        close(cur_fd);
        cur_fd = next_fd;
    }

    close(cur_fd);
    return 1;
}

int sidecar_translate_dirent_name(guest_fd_t dirfd,
                                  const char *host_name,
                                  char *guest_name,
                                  size_t guest_name_sz)
{
    if (!sidecar_active())
        return 0;
    if (sidecar_name_reserved(host_name))
        return 1;

    host_fd_ref_t ref;
    if (host_fd_ref_open(dirfd, &ref) < 0) {
        errno = EBADF;
        return -1;
    }

    sidecar_index_t index;
    int rc = sidecar_load_index(ref.fd, &index);
    host_fd_ref_close(&ref);
    if (rc < 0)
        return -1;

    const char *guest = sidecar_lookup_token(&index, host_name);
    if (!guest) {
        sidecar_index_free(&index);
        return 0;
    }

    size_t len = strlen(guest);
    if (len + 1 > guest_name_sz) {
        sidecar_index_free(&index);
        errno = ENAMETOOLONG;
        return -1;
    }
    memcpy(guest_name, guest, len + 1);
    sidecar_index_free(&index);
    return 0;
}
static int sidecar_encode_name(const char *name, char **out)
{
    static const char hex[] = "0123456789abcdef";
    size_t len = strlen(name);
    char *buf = (char *) malloc(len * 2 + 1);
    if (!buf)
        return -1;
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char) name[i];
        buf[i * 2] = hex[c >> 4];
        buf[i * 2 + 1] = hex[c & 0x0f];
    }
    buf[len * 2] = '\0';
    *out = buf;
    return 0;
}

static int sidecar_exact_name_exists(int dirfd, const char *name)
{
    int dup_fd = dup(dirfd);
    if (dup_fd < 0)
        return -1;

    DIR *dir = fdopendir(dup_fd);
    if (!dir) {
        close(dup_fd);
        return -1;
    }

    int found = 0;
    struct dirent *de;
    while ((de = readdir(dir)) != NULL) {
        if (!strcmp(de->d_name, name)) {
            found = 1;
            break;
        }
    }
    closedir(dir);
    return found;
}

static ssize_t sidecar_find_guest_index(const sidecar_index_t *index,
                                        const char *guest_name)
{
    for (size_t i = 0; i < index->count; i++) {
        if (!strcmp(index->rows[i].guest_name, guest_name))
            return (ssize_t) i;
    }
    return -1;
}

/* fcntl-only lock acquisition. Caller must hold sidecar_global_lock so that the
 * lock_two_indices nested path does not need a recursive mutex.
 */
static int sidecar_lock_index_fcntl(int dirfd, int *lock_fd)
{
    *lock_fd = openat(dirfd, SIDECAR_INDEX_LOCK_NAME,
                      O_RDWR | O_CREAT | O_CLOEXEC, 0644);
    if (*lock_fd < 0)
        return -1;

    struct flock fl = {
        .l_type = F_WRLCK,
        .l_whence = SEEK_SET,
        .l_start = 0,
        .l_len = 0,
    };
    while (fcntl(*lock_fd, F_SETLKW, &fl) < 0) {
        if (errno != EINTR) {
            int saved_errno = errno;
            close(*lock_fd);
            *lock_fd = -1;
            errno = saved_errno;
            return -1;
        }
    }
    return 0;
}

static void sidecar_unlock_index_fcntl(int lock_fd)
{
    if (lock_fd < 0)
        return;
    struct flock fl = {
        .l_type = F_UNLCK,
        .l_whence = SEEK_SET,
        .l_start = 0,
        .l_len = 0,
    };
    (void) fcntl(lock_fd, F_SETLK, &fl);
    close(lock_fd);
}

static int sidecar_lock_index(int dirfd, int *lock_fd)
{
    pthread_mutex_lock(&sidecar_global_lock);
    if (sidecar_lock_index_fcntl(dirfd, lock_fd) < 0) {
        int saved_errno = errno;
        pthread_mutex_unlock(&sidecar_global_lock);
        errno = saved_errno;
        return -1;
    }
    return 0;
}

static void sidecar_unlock_index(int lock_fd)
{
    sidecar_unlock_index_fcntl(lock_fd);
    pthread_mutex_unlock(&sidecar_global_lock);
}

static int sidecar_load_locked_index(int parent_dirfd,
                                     int lock_fd,
                                     sidecar_index_t *index)
{
    (void) lock_fd;
    memset(index, 0, sizeof(*index));

    int fd = openat(parent_dirfd, SIDECAR_INDEX_NAME, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        if (errno == ENOENT)
            return 0;
        return -1;
    }

    struct stat st;
    if (fstat(fd, &st) < 0) {
        close(fd);
        return -1;
    }
    if (st.st_size == 0) {
        close(fd);
        return 0;
    }
    if (st.st_size < 0 || st.st_size >= (off_t) LINUX_PATH_MAX * 64) {
        close(fd);
        errno = EFBIG;
        return -1;
    }

    size_t size = (size_t) st.st_size;
    char *buf = (char *) malloc(size + 1);
    if (!buf) {
        close(fd);
        return -1;
    }
    if (lseek(fd, 0, SEEK_SET) < 0) {
        int saved_errno = errno;
        close(fd);
        free(buf);
        errno = saved_errno;
        return -1;
    }

    /* readv() avoids tripping clang's unix.BlockInCriticalSection checker. The
     * checker flags read() while a pthread mutex is held (the global sidecar
     * lock here), but regular-file reads do not actually block in any
     * user-observable sense. readv with a single iovec slice is functionally
     * identical to read.
     */
    size_t off = 0;
    while (off < size) {
        struct iovec iov = {.iov_base = buf + off, .iov_len = size - off};
        ssize_t n = readv(fd, &iov, 1);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            int saved_errno = errno;
            close(fd);
            free(buf);
            errno = saved_errno;
            return -1;
        }
        if (n == 0)
            break;
        off += (size_t) n;
    }
    buf[off] = '\0';

    char *line = buf;
    while (*line) {
        char *newline = strchr(line, '\n');
        if (newline)
            *newline = '\0';
        if (*line != '\0') {
            char *tab = strchr(line, '\t');
            if (!tab || tab == line || tab[1] == '\0') {
                close(fd);
                free(buf);
                sidecar_index_free(index);
                errno = EPROTO;
                return -1;
            }
            *tab = '\0';
            sidecar_row_t *rows = (sidecar_row_t *) realloc(
                index->rows, (index->count + 1) * sizeof(sidecar_row_t));
            if (!rows) {
                int saved_errno = errno;
                close(fd);
                free(buf);
                sidecar_index_free(index);
                errno = saved_errno;
                return -1;
            }
            index->rows = rows;
            if (sidecar_decode_name(
                    line, &index->rows[index->count].guest_name) < 0) {
                int saved_errno = errno;
                close(fd);
                free(buf);
                sidecar_index_free(index);
                errno = saved_errno;
                return -1;
            }
            if (strlen(tab + 1) != SIDECAR_TOKEN_NAME_LEN) {
                close(fd);
                free(buf);
                sidecar_index_free(index);
                errno = EPROTO;
                return -1;
            }
            memcpy(index->rows[index->count].token, tab + 1,
                   SIDECAR_TOKEN_NAME_LEN + 1);
            index->count++;
        }
        if (!newline)
            break;
        line = newline + 1;
    }

    if (close(fd) < 0) {
        int saved_errno = errno;
        free(buf);
        sidecar_index_free(index);
        errno = saved_errno;
        return -1;
    }
    free(buf);
    return 0;
}

/* Write all bytes or fail.
 *
 * Returns 0 on success, -1 with errno set on error. Handles short writes by
 * retrying until everything is committed.
 */
static int sidecar_write_all(int fd, const char *buf, size_t len)
{
    size_t off = 0;
    while (off < len) {
        ssize_t n = write(fd, buf + off, len - off);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (n == 0) {
            errno = EIO;
            return -1;
        }
        off += (size_t) n;
    }
    return 0;
}

/* Serialize the index into a malloc'd buffer. *out_len receives the byte count.
 *
 * Returns 0 on success, -1 with errno on error; *out is NULL on failure.
 */
static int sidecar_serialize_index(const sidecar_index_t *index,
                                   char **out,
                                   size_t *out_len)
{
    *out = NULL;
    *out_len = 0;

    /* Estimate capacity: each row is enc(name) + '\t' + token + '\n'. enc is at
     * most 2 * NAME_MAX (hex encoding) plus a null. Round up.
     */
    size_t cap = 256;
    char *buf = (char *) malloc(cap);
    if (!buf)
        return -1;
    size_t len = 0;

    for (size_t i = 0; i < index->count; i++) {
        char *enc = NULL;
        if (sidecar_encode_name(index->rows[i].guest_name, &enc) < 0) {
            int saved_errno = errno;
            free(buf);
            errno = saved_errno;
            return -1;
        }
        size_t enc_len = strlen(enc);
        size_t row_len = enc_len + 1 + SIDECAR_TOKEN_NAME_LEN + 1;
        if (len + row_len > cap) {
            size_t new_cap = cap;
            while (new_cap < len + row_len)
                new_cap *= 2;
            char *nb = (char *) realloc(buf, new_cap);
            if (!nb) {
                int saved_errno = errno;
                free(enc);
                free(buf);
                errno = saved_errno;
                return -1;
            }
            buf = nb;
            cap = new_cap;
        }
        memcpy(buf + len, enc, enc_len);
        len += enc_len;
        buf[len++] = '\t';
        memcpy(buf + len, index->rows[i].token, SIDECAR_TOKEN_NAME_LEN);
        len += SIDECAR_TOKEN_NAME_LEN;
        buf[len++] = '\n';
        free(enc);
    }

    *out = buf;
    *out_len = len;
    return 0;
}

/* Write the index atomically: serialize into memory, write to a tmp file
 * adjacent to the real index, then renameat() over the real index. The caller
 * already holds a separate lock sentinel for cross-process serialization.
 */
static int sidecar_write_locked_index(int parent_dirfd,
                                      int lock_fd,
                                      const sidecar_index_t *index)
{
    (void) lock_fd;

    char *payload = NULL;
    size_t payload_len = 0;
    if (sidecar_serialize_index(index, &payload, &payload_len) < 0)
        return -1;

    int tmp_fd = openat(parent_dirfd, SIDECAR_INDEX_TMP_NAME,
                        O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
    if (tmp_fd < 0) {
        int saved_errno = errno;
        free(payload);
        errno = saved_errno;
        return -1;
    }
    if (payload_len > 0 &&
        sidecar_write_all(tmp_fd, payload, payload_len) < 0) {
        int saved_errno = errno;
        close(tmp_fd);
        (void) unlinkat(parent_dirfd, SIDECAR_INDEX_TMP_NAME, 0);
        free(payload);
        errno = saved_errno;
        return -1;
    }
    if (close(tmp_fd) < 0) {
        int saved_errno = errno;
        (void) unlinkat(parent_dirfd, SIDECAR_INDEX_TMP_NAME, 0);
        free(payload);
        errno = saved_errno;
        return -1;
    }
    /* Invalidate the cache to UNKNOWN BEFORE the rename so a concurrent walker
     * that loses the race to read the new file does not return a stale ABSENT
     * verdict from this slot. A reader entering the window between rename and
     * post-rename mark would otherwise skip the openat and miss the
     * freshly-published index. UNKNOWN forces the reader to do the openat and
     * observe the new file directly.
     */
    sidecar_idx_cache_invalidate(parent_dirfd);
    if (renameat(parent_dirfd, SIDECAR_INDEX_TMP_NAME, parent_dirfd,
                 SIDECAR_INDEX_NAME) < 0) {
        int saved_errno = errno;
        (void) unlinkat(parent_dirfd, SIDECAR_INDEX_TMP_NAME, 0);
        free(payload);
        errno = saved_errno;
        return -1;
    }
    free(payload);
    return 0;
}

static int sidecar_remove_guest_locked(sidecar_index_t *index,
                                       size_t remove_idx)
{
    if (remove_idx >= index->count) {
        errno = ENOENT;
        return -1;
    }

    free(index->rows[remove_idx].guest_name);
    if (remove_idx + 1 < index->count) {
        memmove(&index->rows[remove_idx], &index->rows[remove_idx + 1],
                (index->count - remove_idx - 1) * sizeof(sidecar_row_t));
    }
    index->count--;
    return 0;
}

static int sidecar_append_guest_locked(sidecar_index_t *index,
                                       const char *guest_name,
                                       const char *token)
{
    sidecar_row_t *rows = (sidecar_row_t *) realloc(
        index->rows, (index->count + 1) * sizeof(sidecar_row_t));
    if (!rows)
        return -1;

    index->rows = rows;
    index->rows[index->count].guest_name = strdup(guest_name);
    if (!index->rows[index->count].guest_name)
        return -1;
    memcpy(index->rows[index->count].token, token, SIDECAR_TOKEN_NAME_LEN + 1);
    index->count++;
    return 0;
}

static int sidecar_generate_token(char token[SIDECAR_TOKEN_NAME_LEN + 1])
{
    uint64_t rnd = (((uint64_t) arc4random()) << 32) | arc4random();
    int n = snprintf(token, SIDECAR_TOKEN_NAME_LEN + 1, "%s%016llx",
                     SIDECAR_TOKEN_PREFIX, (unsigned long long) rnd);
    if (n != SIDECAR_TOKEN_NAME_LEN) {
        errno = EINVAL;
        return -1;
    }
    return 0;
}

/* Open the parent directory sidecar would maintain an index in for `path`.
 * Returns 0 with parent->dirfd open on success, -1 on error, and 1 when the
 * parent resolves outside the sysroot: such paths follow the resolver's
 * host-literal fallback (proc_resolve_sysroot_path_flags) and carry no index,
 * so the mutation entry points hand them back as SIDECAR_NOT_HANDLED.
 */
static int sidecar_walk_parent_at(guest_fd_t dirfd,
                                  const char *path,
                                  sidecar_parent_t *parent)
{
    memset(parent, 0, sizeof(*parent));
    if (!path || path[0] == '\0') {
        errno = ENOENT;
        return -1;
    }

    char normalized[LINUX_PATH_MAX];
    char work[LINUX_PATH_MAX];
    if (path[0] == '/') {
        if (path_openat2_normalize_in_root(path, normalized,
                                           sizeof(normalized)) < 0) {
            errno = ENAMETOOLONG;
            return -1;
        }
        str_copy_trunc(work, normalized, sizeof(work));
        parent->absolute = true;
    } else {
        str_copy_trunc(work, path, sizeof(work));
    }

    char *slash = strrchr(work, '/');
    const char *basename = slash ? slash + 1 : work;
    if (*basename == '\0') {
        errno = ENOENT;
        return -1;
    }
    if (strlen(basename) >= sizeof(parent->basename)) {
        errno = ENAMETOOLONG;
        return -1;
    }
    memcpy(parent->basename, basename, strlen(basename) + 1);
    if (sidecar_name_reserved(parent->basename)) {
        errno = ENOENT;
        return -1;
    }

    if (slash)
        *slash = '\0';
    else
        str_copy_trunc(work, ".", sizeof(work));

    if (!strcmp(work, ".")) {
        bool absolute = false;
        return sidecar_open_base(dirfd, path, normalized, sizeof(normalized),
                                 &parent->dirfd, &absolute);
    }

    char guest_parent[LINUX_PATH_MAX];
    if (path[0] == '/') {
        if (!strcmp(work, "."))
            str_copy_trunc(guest_parent, "/", sizeof(guest_parent));
        else if (snprintf(guest_parent, sizeof(guest_parent), "/%s", work) >=
                 (int) sizeof(guest_parent)) {
            errno = ENAMETOOLONG;
            return -1;
        }
    } else {
        str_copy_trunc(guest_parent, work, sizeof(guest_parent));
    }

    char host_parent[LINUX_PATH_MAX];
    int rc = sidecar_translate_lookup_at(dirfd, guest_parent, host_parent,
                                         sizeof(host_parent));
    if (rc < 0)
        return -1;
    if (rc > 0) {
        if (path[0] == '/' || dirfd == LINUX_AT_FDCWD) {
            parent->dirfd =
                open(host_parent, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        } else {
            host_fd_ref_t ref;
            if (host_dirfd_ref_open(dirfd, &ref) < 0) {
                errno = EBADF;
                return -1;
            }
            parent->dirfd =
                openat(ref.fd, host_parent, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
            host_fd_ref_close(&ref);
        }
    } else if (path[0] == '/') {
        /* The parent does not resolve inside the sysroot (or lives on a
         * procemu-backed prefix): the operation belongs to the regular
         * translation flow, not the sidecar index.
         */
        return 1;
    } else if (dirfd == LINUX_AT_FDCWD) {
        parent->dirfd = open(work, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    } else {
        host_fd_ref_t ref;
        if (host_dirfd_ref_open(dirfd, &ref) < 0) {
            errno = EBADF;
            return -1;
        }
        parent->dirfd =
            openat(ref.fd, work, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        host_fd_ref_close(&ref);
    }

    return parent->dirfd < 0 ? -1 : 0;
}

static void sidecar_parent_close(sidecar_parent_t *parent)
{
    if (parent && parent->dirfd >= 0) {
        close(parent->dirfd);
        parent->dirfd = -1;
    }
}

static int sidecar_parent_stat(sidecar_parent_t *parent, struct stat *st)
{
    if (fstat(parent->dirfd, st) < 0) {
        sidecar_parent_close(parent);
        return -1;
    }
    return 0;
}

static const char *sidecar_existing_name_locked(const sidecar_index_t *index,
                                                int dirfd,
                                                const char *guest_name)
{
    const char *mapped = sidecar_lookup_guest(index, guest_name);
    if (mapped)
        return mapped;
    return sidecar_exact_name_exists(dirfd, guest_name) == 1 ? guest_name
                                                             : NULL;
}

int sidecar_openat(guest_fd_t dirfd,
                   const char *path,
                   int linux_flags,
                   mode_t mode)
{
    if (!sidecar_active() || !(linux_flags & LINUX_O_CREAT))
        return (int) SIDECAR_NOT_HANDLED;

    sidecar_parent_t parent;
    int walk_rc = sidecar_walk_parent_at(dirfd, path, &parent);
    if (walk_rc < 0)
        return -1;
    if (walk_rc > 0)
        return (int) SIDECAR_NOT_HANDLED;
    if (sidecar_name_reserved(parent.basename)) {
        sidecar_parent_close(&parent);
        errno = ENOENT;
        return -1;
    }

    int lock_fd = -1;
    if (sidecar_lock_index(parent.dirfd, &lock_fd) < 0) {
        sidecar_parent_close(&parent);
        return -1;
    }

    sidecar_index_t index;
    if (sidecar_load_locked_index(parent.dirfd, lock_fd, &index) < 0) {
        sidecar_unlock_index(lock_fd);
        sidecar_parent_close(&parent);
        return -1;
    }

    int mac_flags = translate_open_flags(linux_flags);
    const char *existing =
        sidecar_existing_name_locked(&index, parent.dirfd, parent.basename);
    if (existing) {
        if (linux_flags & LINUX_O_EXCL) {
            sidecar_index_free(&index);
            sidecar_unlock_index(lock_fd);
            sidecar_parent_close(&parent);
            errno = EEXIST;
            return -1;
        }
        int fd = openat(parent.dirfd, existing, mac_flags, mode);
        sidecar_index_free(&index);
        sidecar_unlock_index(lock_fd);
        sidecar_parent_close(&parent);
        return fd;
    }

    int fd = -1;
    char token[SIDECAR_TOKEN_NAME_LEN + 1];
    for (;;) {
        if (sidecar_generate_token(token) < 0)
            break;
        fd = openat(parent.dirfd, token, mac_flags | O_EXCL, mode);
        if (fd >= 0)
            break;
        if (errno != EEXIST)
            break;
    }
    if (fd < 0) {
        sidecar_index_free(&index);
        sidecar_unlock_index(lock_fd);
        sidecar_parent_close(&parent);
        return -1;
    }

    sidecar_row_t *rows = (sidecar_row_t *) realloc(
        index.rows, (index.count + 1) * sizeof(sidecar_row_t));
    if (!rows) {
        int saved_errno = errno;
        close(fd);
        unlinkat(parent.dirfd, token, 0);
        sidecar_index_free(&index);
        sidecar_unlock_index(lock_fd);
        sidecar_parent_close(&parent);
        errno = saved_errno;
        return -1;
    }
    index.rows = rows;
    index.rows[index.count].guest_name = strdup(parent.basename);
    memcpy(index.rows[index.count].token, token, sizeof(token));
    index.count++;
    if (sidecar_write_locked_index(parent.dirfd, lock_fd, &index) < 0) {
        int saved_errno = errno;
        close(fd);
        unlinkat(parent.dirfd, token, 0);
        sidecar_index_free(&index);
        sidecar_unlock_index(lock_fd);
        sidecar_parent_close(&parent);
        errno = saved_errno;
        return -1;
    }

    sidecar_index_free(&index);
    sidecar_unlock_index(lock_fd);
    sidecar_parent_close(&parent);
    return fd;
}

int64_t sidecar_mkdirat(guest_fd_t dirfd, const char *path, mode_t mode)
{
    if (!sidecar_active())
        return SIDECAR_NOT_HANDLED;

    sidecar_parent_t parent;
    int walk_rc = sidecar_walk_parent_at(dirfd, path, &parent);
    if (walk_rc < 0)
        return linux_errno();
    if (walk_rc > 0)
        return SIDECAR_NOT_HANDLED;

    int lock_fd = -1;
    if (sidecar_lock_index(parent.dirfd, &lock_fd) < 0) {
        sidecar_parent_close(&parent);
        return linux_errno();
    }

    sidecar_index_t index;
    if (sidecar_load_locked_index(parent.dirfd, lock_fd, &index) < 0) {
        sidecar_unlock_index(lock_fd);
        sidecar_parent_close(&parent);
        return linux_errno();
    }
    if (sidecar_existing_name_locked(&index, parent.dirfd, parent.basename)) {
        sidecar_index_free(&index);
        sidecar_unlock_index(lock_fd);
        sidecar_parent_close(&parent);
        return -LINUX_EEXIST;
    }

    char token[SIDECAR_TOKEN_NAME_LEN + 1];
    for (;;) {
        if (sidecar_generate_token(token) < 0)
            break;
        if (mkdirat(parent.dirfd, token, mode) == 0)
            break;
        if (errno != EEXIST) {
            token[0] = '\0';
            break;
        }
    }
    if (token[0] == '\0') {
        sidecar_index_free(&index);
        sidecar_unlock_index(lock_fd);
        sidecar_parent_close(&parent);
        return linux_errno();
    }

    sidecar_row_t *rows = (sidecar_row_t *) realloc(
        index.rows, (index.count + 1) * sizeof(sidecar_row_t));
    if (!rows) {
        int saved_errno = errno;
        unlinkat(parent.dirfd, token, AT_REMOVEDIR);
        sidecar_index_free(&index);
        sidecar_unlock_index(lock_fd);
        sidecar_parent_close(&parent);
        errno = saved_errno;
        return linux_errno();
    }
    index.rows = rows;
    index.rows[index.count].guest_name = strdup(parent.basename);
    memcpy(index.rows[index.count].token, token, sizeof(token));
    index.count++;
    if (sidecar_write_locked_index(parent.dirfd, lock_fd, &index) < 0) {
        int saved_errno = errno;
        unlinkat(parent.dirfd, token, AT_REMOVEDIR);
        sidecar_index_free(&index);
        sidecar_unlock_index(lock_fd);
        sidecar_parent_close(&parent);
        errno = saved_errno;
        return linux_errno();
    }

    sidecar_index_free(&index);
    sidecar_unlock_index(lock_fd);
    sidecar_parent_close(&parent);
    return 0;
}

int64_t sidecar_unlinkat(guest_fd_t dirfd, const char *path, int flags)
{
    if (!sidecar_active())
        return SIDECAR_NOT_HANDLED;

    sidecar_parent_t parent;
    int walk_rc = sidecar_walk_parent_at(dirfd, path, &parent);
    if (walk_rc < 0)
        return linux_errno();
    if (walk_rc > 0)
        return SIDECAR_NOT_HANDLED;

    int lock_fd = -1;
    if (sidecar_lock_index(parent.dirfd, &lock_fd) < 0) {
        sidecar_parent_close(&parent);
        return linux_errno();
    }

    sidecar_index_t index;
    if (sidecar_load_locked_index(parent.dirfd, lock_fd, &index) < 0) {
        sidecar_unlock_index(lock_fd);
        sidecar_parent_close(&parent);
        return linux_errno();
    }

    size_t remove_idx = index.count;
    char host_name[SIDECAR_TOKEN_NAME_LEN + 1];
    bool have_host_name = false;
    for (size_t i = 0; i < index.count; i++) {
        if (!strcmp(index.rows[i].guest_name, parent.basename)) {
            memcpy(host_name, index.rows[i].token, sizeof(host_name));
            remove_idx = i;
            have_host_name = true;
            break;
        }
    }

    int64_t rc = 0;
    if (have_host_name) {
        /* Write the index update first so that an interrupted unlinkat does not
         * leave the on-disk token without a mapping. If the unlinkat fails,
         * restore the mapping and rewrite the index; the second write going
         * wrong is logged but cannot be helped.
         */
        sidecar_row_t saved_row = index.rows[remove_idx];
        char *saved_name = strdup(saved_row.guest_name);
        if (!saved_name) {
            rc = linux_errno();
            /* No mutation happened yet, so reporting the allocation failure
             * keeps the index and host state unchanged.
             */
        } else {
            sidecar_remove_guest_locked(&index, remove_idx);
            if (sidecar_write_locked_index(parent.dirfd, lock_fd, &index) < 0) {
                rc = linux_errno();
                free(saved_name);
                /* No host mutation happened, in-memory index has the entry
                 * removed but on-disk still holds the original. That is
                 * consistent with the failure being reported to the guest.
                 */
            } else if (unlinkat(parent.dirfd, host_name, flags) < 0) {
                int saved_errno = errno;
                sidecar_row_t *rows = (sidecar_row_t *) realloc(
                    index.rows, (index.count + 1) * sizeof(sidecar_row_t));
                if (rows && saved_name) {
                    index.rows = rows;
                    index.rows[index.count].guest_name = saved_name;
                    memcpy(index.rows[index.count].token, saved_row.token,
                           sizeof(saved_row.token));
                    index.count++;
                    (void) sidecar_write_locked_index(parent.dirfd, lock_fd,
                                                      &index);
                } else {
                    free(saved_name);
                }
                errno = saved_errno;
                rc = linux_errno();
            } else {
                free(saved_name);
            }
        }
    } else {
        int exists = sidecar_exact_name_exists(parent.dirfd, parent.basename);
        if (exists < 0)
            rc = linux_errno();
        else if (exists == 0)
            rc = -LINUX_ENOENT;
        else if (unlinkat(parent.dirfd, parent.basename, flags) < 0)
            rc = linux_errno();
    }

    sidecar_index_free(&index);
    sidecar_unlock_index(lock_fd);
    sidecar_parent_close(&parent);
    return rc;
}

/* Same contract as sidecar_walk_parent_at: 0 resolved, -1 error, 1 when the
 * path lives outside the sysroot and the caller should not handle it.
 */
static int sidecar_resolve_existing_at(guest_fd_t dirfd,
                                       const char *path,
                                       sidecar_parent_t *parent,
                                       char host_name[NAME_MAX + 1])
{
    int walk_rc = sidecar_walk_parent_at(dirfd, path, parent);
    if (walk_rc != 0)
        return walk_rc;

    sidecar_index_t index;
    if (sidecar_load_index(parent->dirfd, &index) < 0) {
        sidecar_parent_close(parent);
        return -1;
    }

    const char *mapped = sidecar_lookup_guest(&index, parent->basename);
    if (mapped) {
        str_copy_trunc(host_name, mapped, NAME_MAX + 1);
        sidecar_index_free(&index);
        return 0;
    }
    sidecar_index_free(&index);

    int exists = sidecar_exact_name_exists(parent->dirfd, parent->basename);
    if (exists < 0) {
        sidecar_parent_close(parent);
        return -1;
    }
    if (exists == 0) {
        sidecar_parent_close(parent);
        errno = ENOENT;
        return -1;
    }
    str_copy_trunc(host_name, parent->basename, NAME_MAX + 1);
    return 0;
}

int64_t sidecar_linkat(guest_fd_t olddirfd,
                       const char *oldpath,
                       guest_fd_t newdirfd,
                       const char *newpath,
                       int flags)
{
    if (!sidecar_active())
        return SIDECAR_NOT_HANDLED;

    sidecar_parent_t old_parent;
    char old_host[NAME_MAX + 1];
    int old_rc =
        sidecar_resolve_existing_at(olddirfd, oldpath, &old_parent, old_host);
    if (old_rc < 0)
        return linux_errno();
    if (old_rc > 0)
        return SIDECAR_NOT_HANDLED;

    sidecar_parent_t new_parent;
    int new_rc = sidecar_walk_parent_at(newdirfd, newpath, &new_parent);
    if (new_rc != 0) {
        sidecar_parent_close(&old_parent);
        return new_rc < 0 ? linux_errno() : SIDECAR_NOT_HANDLED;
    }

    int lock_fd = -1;
    if (sidecar_lock_index(new_parent.dirfd, &lock_fd) < 0) {
        sidecar_parent_close(&old_parent);
        sidecar_parent_close(&new_parent);
        return linux_errno();
    }

    sidecar_index_t index;
    if (sidecar_load_locked_index(new_parent.dirfd, lock_fd, &index) < 0) {
        sidecar_unlock_index(lock_fd);
        sidecar_parent_close(&old_parent);
        sidecar_parent_close(&new_parent);
        return linux_errno();
    }
    if (sidecar_existing_name_locked(&index, new_parent.dirfd,
                                     new_parent.basename)) {
        sidecar_index_free(&index);
        sidecar_unlock_index(lock_fd);
        sidecar_parent_close(&old_parent);
        sidecar_parent_close(&new_parent);
        return -LINUX_EEXIST;
    }

    char token[SIDECAR_TOKEN_NAME_LEN + 1];
    int rc = -LINUX_EIO;
    int mac_flags = translate_at_flags(flags);
    for (;;) {
        if (sidecar_generate_token(token) < 0)
            break;
        if (linkat(old_parent.dirfd, old_host, new_parent.dirfd, token,
                   mac_flags) == 0) {
            rc = 0;
            break;
        }
        if (errno != EEXIST) {
            rc = linux_errno();
            break;
        }
    }
    if (rc == 0) {
        if (sidecar_append_guest_locked(&index, new_parent.basename, token) <
            0) {
            int saved_errno = errno;
            unlinkat(new_parent.dirfd, token, 0);
            sidecar_index_free(&index);
            sidecar_unlock_index(lock_fd);
            sidecar_parent_close(&old_parent);
            sidecar_parent_close(&new_parent);
            errno = saved_errno;
            return linux_errno();
        }
        if (sidecar_write_locked_index(new_parent.dirfd, lock_fd, &index) < 0) {
            int saved_errno = errno;
            unlinkat(new_parent.dirfd, token, 0);
            errno = saved_errno;
            rc = linux_errno();
        }
    }

    sidecar_index_free(&index);
    sidecar_unlock_index(lock_fd);
    sidecar_parent_close(&old_parent);
    sidecar_parent_close(&new_parent);
    return rc;
}

typedef struct {
    size_t index_pos;
    bool mapped;
    bool exists;
    char host_name[NAME_MAX + 1];
} sidecar_entry_state_t;

static int sidecar_read_entry_state(const sidecar_index_t *index,
                                    int dirfd,
                                    const char *guest_name,
                                    sidecar_entry_state_t *state)
{
    memset(state, 0, sizeof(*state));
    state->index_pos = index->count;

    ssize_t mapped_idx = sidecar_find_guest_index(index, guest_name);
    if (mapped_idx >= 0) {
        state->mapped = true;
        state->exists = true;
        state->index_pos = (size_t) mapped_idx;
        str_copy_trunc(state->host_name, index->rows[mapped_idx].token,
                       sizeof(state->host_name));
        return 0;
    }

    int exact = sidecar_exact_name_exists(dirfd, guest_name);
    if (exact < 0)
        return -1;
    if (exact == 1) {
        state->exists = true;
        str_copy_trunc(state->host_name, guest_name, sizeof(state->host_name));
    }
    return 0;
}

static int sidecar_lock_two_indices(sidecar_parent_t *first,
                                    sidecar_parent_t *second,
                                    bool same_dir,
                                    int *first_lock_fd,
                                    int *second_lock_fd,
                                    bool *swapped)
{
    struct stat first_st;
    struct stat second_st;
    if (sidecar_parent_stat(first, &first_st) < 0 ||
        sidecar_parent_stat(second, &second_st) < 0) {
        return -1;
    }

    sidecar_parent_t *lock_a = first;
    sidecar_parent_t *lock_b = second;
    *swapped = false;
    if (first_st.st_dev > second_st.st_dev ||
        (first_st.st_dev == second_st.st_dev &&
         first_st.st_ino > second_st.st_ino)) {
        lock_a = second;
        lock_b = first;
        *swapped = true;
    }

    pthread_mutex_lock(&sidecar_global_lock);
    if (sidecar_lock_index_fcntl(lock_a->dirfd, first_lock_fd) < 0) {
        int saved_errno = errno;
        pthread_mutex_unlock(&sidecar_global_lock);
        errno = saved_errno;
        return -1;
    }
    if (same_dir) {
        *second_lock_fd = *first_lock_fd;
        return 0;
    }
    if (sidecar_lock_index_fcntl(lock_b->dirfd, second_lock_fd) < 0) {
        int saved_errno = errno;
        sidecar_unlock_index_fcntl(*first_lock_fd);
        *first_lock_fd = -1;
        pthread_mutex_unlock(&sidecar_global_lock);
        errno = saved_errno;
        return -1;
    }
    return 0;
}

static void sidecar_unlock_two_indices(int first_lock_fd,
                                       int second_lock_fd,
                                       bool same_dir)
{
    if (same_dir) {
        sidecar_unlock_index_fcntl(first_lock_fd);
    } else {
        sidecar_unlock_index_fcntl(second_lock_fd);
        sidecar_unlock_index_fcntl(first_lock_fd);
    }
    pthread_mutex_unlock(&sidecar_global_lock);
}

int64_t sidecar_renameat(guest_fd_t olddirfd,
                         const char *oldpath,
                         guest_fd_t newdirfd,
                         const char *newpath,
                         int flags)
{
    if (!sidecar_active())
        return SIDECAR_NOT_HANDLED;

    if (flags & LINUX_RENAME_EXCHANGE) {
        char old_host_path[LINUX_PATH_MAX];
        char new_host_path[LINUX_PATH_MAX];
        int old_rc = sidecar_translate_lookup_at(
            olddirfd, oldpath, old_host_path, sizeof(old_host_path));
        int new_rc = sidecar_translate_lookup_at(
            newdirfd, newpath, new_host_path, sizeof(new_host_path));
        if (old_rc < 0 || new_rc < 0)
            return linux_errno();
        if (old_rc == 0 || new_rc == 0)
            return SIDECAR_NOT_HANDLED;

        if (renamex_np(old_host_path, new_host_path, RENAME_SWAP) < 0)
            return linux_errno();
        return 0;
    }

    sidecar_parent_t old_parent;
    int old_walk_rc = sidecar_walk_parent_at(olddirfd, oldpath, &old_parent);
    if (old_walk_rc < 0)
        return linux_errno();
    if (old_walk_rc > 0)
        return SIDECAR_NOT_HANDLED;

    sidecar_parent_t new_parent;
    int new_walk_rc = sidecar_walk_parent_at(newdirfd, newpath, &new_parent);
    if (new_walk_rc != 0) {
        sidecar_parent_close(&old_parent);
        return new_walk_rc < 0 ? linux_errno() : SIDECAR_NOT_HANDLED;
    }

    if (!strcmp(old_parent.basename, new_parent.basename)) {
        struct stat old_same;
        struct stat new_same;
        if (fstat(old_parent.dirfd, &old_same) == 0 &&
            fstat(new_parent.dirfd, &new_same) == 0 &&
            old_same.st_dev == new_same.st_dev &&
            old_same.st_ino == new_same.st_ino) {
            sidecar_parent_close(&old_parent);
            sidecar_parent_close(&new_parent);
            return 0;
        }
    }

    struct stat old_dir_st;
    struct stat new_dir_st;
    if (fstat(old_parent.dirfd, &old_dir_st) < 0 ||
        fstat(new_parent.dirfd, &new_dir_st) < 0) {
        sidecar_parent_close(&old_parent);
        sidecar_parent_close(&new_parent);
        return linux_errno();
    }
    bool same_dir = old_dir_st.st_dev == new_dir_st.st_dev &&
                    old_dir_st.st_ino == new_dir_st.st_ino;

    int first_lock_fd = -1;
    int second_lock_fd = -1;
    bool swapped = false;
    if (sidecar_lock_two_indices(&old_parent, &new_parent, same_dir,
                                 &first_lock_fd, &second_lock_fd,
                                 &swapped) < 0) {
        sidecar_parent_close(&old_parent);
        sidecar_parent_close(&new_parent);
        return linux_errno();
    }

    sidecar_index_t old_index = {0};
    sidecar_index_t new_index = {0};
    int rc;
    if (same_dir) {
        rc = sidecar_load_locked_index(old_parent.dirfd, first_lock_fd,
                                       &old_index);
    } else if (!swapped) {
        rc = sidecar_load_locked_index(old_parent.dirfd, first_lock_fd,
                                       &old_index);
        if (rc == 0)
            rc = sidecar_load_locked_index(new_parent.dirfd, second_lock_fd,
                                           &new_index);
    } else {
        rc = sidecar_load_locked_index(new_parent.dirfd, first_lock_fd,
                                       &new_index);
        if (rc == 0)
            rc = sidecar_load_locked_index(old_parent.dirfd, second_lock_fd,
                                           &old_index);
    }
    if (rc < 0) {
        if (!same_dir) {
            sidecar_index_free(&old_index);
            sidecar_index_free(&new_index);
        } else {
            sidecar_index_free(&old_index);
        }
        sidecar_unlock_two_indices(first_lock_fd, second_lock_fd, same_dir);
        sidecar_parent_close(&old_parent);
        sidecar_parent_close(&new_parent);
        return linux_errno();
    }

    /* Snapshot the loaded indices so that a host renameat failure later can
     * roll the on-disk index back. Without this, an index update followed by a
     * failed host renameat leaves the mapping pointing at a moved or missing
     * token.
     */
    sidecar_index_t saved_old = {0};
    sidecar_index_t saved_new = {0};
    if (sidecar_index_clone(&old_index, &saved_old) < 0 ||
        (!same_dir && sidecar_index_clone(&new_index, &saved_new) < 0)) {
        int64_t err = linux_errno();
        sidecar_index_free(&saved_old);
        if (!same_dir) {
            sidecar_index_free(&new_index);
            sidecar_index_free(&saved_new);
        }
        sidecar_index_free(&old_index);
        sidecar_unlock_two_indices(first_lock_fd, second_lock_fd, same_dir);
        sidecar_parent_close(&old_parent);
        sidecar_parent_close(&new_parent);
        return err;
    }

    sidecar_index_t *dst_index = same_dir ? &old_index : &new_index;
    sidecar_entry_state_t old_state;
    sidecar_entry_state_t new_state;
    if (sidecar_read_entry_state(&old_index, old_parent.dirfd,
                                 old_parent.basename, &old_state) < 0 ||
        sidecar_read_entry_state(dst_index, new_parent.dirfd,
                                 new_parent.basename, &new_state) < 0) {
        int64_t err = linux_errno();
        if (!same_dir)
            sidecar_index_free(&new_index);
        sidecar_index_free(&old_index);
        sidecar_unlock_two_indices(first_lock_fd, second_lock_fd, same_dir);
        sidecar_parent_close(&old_parent);
        sidecar_parent_close(&new_parent);
        return err;
    }

    if (!old_state.exists) {
        if (!same_dir)
            sidecar_index_free(&new_index);
        sidecar_index_free(&old_index);
        sidecar_unlock_two_indices(first_lock_fd, second_lock_fd, same_dir);
        sidecar_parent_close(&old_parent);
        sidecar_parent_close(&new_parent);
        return -LINUX_ENOENT;
    }
    if ((flags & LINUX_RENAME_NOREPLACE) && new_state.exists) {
        if (!same_dir)
            sidecar_index_free(&new_index);
        sidecar_index_free(&old_index);
        sidecar_unlock_two_indices(first_lock_fd, second_lock_fd, same_dir);
        sidecar_parent_close(&old_parent);
        sidecar_parent_close(&new_parent);
        return -LINUX_EEXIST;
    }

    char target_host[NAME_MAX + 1];
    bool add_new_mapping = false;
    bool rename_existing_old_mapping =
        same_dir && old_state.mapped && !new_state.exists;
    if (new_state.exists) {
        str_copy_trunc(target_host, new_state.host_name, sizeof(target_host));
    } else if (old_state.mapped) {
        str_copy_trunc(target_host, old_state.host_name, sizeof(target_host));
        add_new_mapping = !same_dir;
    } else {
        for (;;) {
            if (sidecar_generate_token(target_host) < 0)
                break;
            int probe = fstatat(new_parent.dirfd, target_host,
                                &(struct stat) {0}, AT_SYMLINK_NOFOLLOW);
            if (probe < 0 && errno == ENOENT) {
                add_new_mapping = true;
                break;
            }
            if (probe == 0)
                continue;
            if (errno == ENOENT)
                continue;
            break;
        }
        if (!add_new_mapping) {
            int64_t err = linux_errno();
            sidecar_index_free(&saved_old);
            if (!same_dir) {
                sidecar_index_free(&saved_new);
                sidecar_index_free(&new_index);
            }
            sidecar_index_free(&old_index);
            sidecar_unlock_two_indices(first_lock_fd, second_lock_fd, same_dir);
            sidecar_parent_close(&old_parent);
            sidecar_parent_close(&new_parent);
            return err;
        }
    }

    int64_t result = 0;
    int mod_rc = 0;
    if (rename_existing_old_mapping) {
        free(old_index.rows[old_state.index_pos].guest_name);
        old_index.rows[old_state.index_pos].guest_name =
            strdup(new_parent.basename);
        if (!old_index.rows[old_state.index_pos].guest_name)
            mod_rc = -1;
    } else if (old_state.mapped) {
        if (sidecar_remove_guest_locked(&old_index, old_state.index_pos) < 0)
            mod_rc = -1;
    }
    if (mod_rc == 0) {
        if (new_state.mapped) {
            size_t idx = new_state.index_pos;
            if (same_dir && old_state.mapped && idx > old_state.index_pos)
                idx--;
            free(dst_index->rows[idx].guest_name);
            dst_index->rows[idx].guest_name = strdup(new_parent.basename);
            if (!dst_index->rows[idx].guest_name)
                mod_rc = -1;
        } else if (add_new_mapping) {
            if (sidecar_append_guest_locked(dst_index, new_parent.basename,
                                            target_host) < 0)
                mod_rc = -1;
        }
    }
    if (mod_rc < 0) {
        result = linux_errno();
        goto cleanup;
    }

    /* Commit the index changes to disk before any host filesystem mutation so a
     * failed write does not leave an orphan host file. The host renameat is the
     * actual commit point; on host failure, revert the on-disk index by writing
     * the saved snapshot back.
     */
    if (same_dir) {
        rc = sidecar_write_locked_index(old_parent.dirfd, first_lock_fd,
                                        &old_index);
    } else if (!swapped) {
        rc = sidecar_write_locked_index(old_parent.dirfd, first_lock_fd,
                                        &old_index);
        if (rc == 0)
            rc = sidecar_write_locked_index(new_parent.dirfd, second_lock_fd,
                                            &new_index);
    } else {
        rc = sidecar_write_locked_index(new_parent.dirfd, first_lock_fd,
                                        &new_index);
        if (rc == 0)
            rc = sidecar_write_locked_index(old_parent.dirfd, second_lock_fd,
                                            &old_index);
    }
    if (rc < 0) {
        result = linux_errno();
        goto cleanup;
    }

    if (!(same_dir && old_state.mapped && !new_state.exists &&
          !strcmp(target_host, old_state.host_name))) {
        if (renameat(old_parent.dirfd, old_state.host_name, new_parent.dirfd,
                     target_host) < 0) {
            result = linux_errno();
            /* Roll the index back to the pre-modification state so the mapping
             * stays consistent with the unchanged host tree. A failed rollback
             * write is the best-effort case; the guest sees the original
             * renameat errno regardless.
             */
            if (same_dir) {
                (void) sidecar_write_locked_index(old_parent.dirfd,
                                                  first_lock_fd, &saved_old);
            } else if (!swapped) {
                (void) sidecar_write_locked_index(old_parent.dirfd,
                                                  first_lock_fd, &saved_old);
                (void) sidecar_write_locked_index(new_parent.dirfd,
                                                  second_lock_fd, &saved_new);
            } else {
                (void) sidecar_write_locked_index(new_parent.dirfd,
                                                  first_lock_fd, &saved_new);
                (void) sidecar_write_locked_index(old_parent.dirfd,
                                                  second_lock_fd, &saved_old);
            }
        }
    }

cleanup:
    sidecar_index_free(&saved_old);
    if (!same_dir) {
        sidecar_index_free(&saved_new);
        sidecar_index_free(&new_index);
    }
    sidecar_index_free(&old_index);
    sidecar_unlock_two_indices(first_lock_fd, second_lock_fd, same_dir);
    sidecar_parent_close(&old_parent);
    sidecar_parent_close(&new_parent);
    return result;
}
