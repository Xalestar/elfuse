/* Linux syscall fidelity tests
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Covers Linux syscalls whose semantics elfuse must emulate exactly:
 * fchmodat2 (SYS 452) including AT_SYMLINK_NOFOLLOW, getcpu (SYS 168),
 * openat2 (SYS 437) with each RESOLVE_* flag variant (BENEATH,
 * IN_ROOT, NO_SYMLINKS, NO_MAGICLINKS), O_PATH descriptor enforcement
 * for read/write/fstat, madvise corner cases (MADV_COLD acceptance and
 * MADV_DONTNEED across an unmapped hole), and the low-address mmap
 * hint preservation that ET_EXEC layout depends on.
 */

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#include "test-harness.h"

#ifndef MAP_FIXED_NOREPLACE
#define MAP_FIXED_NOREPLACE 0x100000
#endif

int passes = 0, fails = 0;

/* Some Linux fidelity tests probe semantics that depend on filesystem
 * support (e.g. changing a symlink's own mode via AT_SYMLINK_NOFOLLOW
 * fails with EOPNOTSUPP on most Linux filesystems). Counting those as
 * skips keeps the summary honest: the syscall path was reached and
 * answered correctly, but the kernel declined the specific request.
 * Hard-failing on EOPNOTSUPP would turn the regression into a false
 * negative on perfectly conforming kernels.
 */
static int syscall_skips = 0;
#define SYSCALL_SKIP(reason)          \
    do {                              \
        printf("SKIP: %s\n", reason); \
        syscall_skips++;              \
    } while (0)

/* fchmodat2 (SYS 452). */

#ifndef SYS_fchmodat2
#define SYS_fchmodat2 452
#endif

#ifndef SYS_getcpu
#define SYS_getcpu 168
#endif

static void test_fchmodat2_basic(void)
{
    TEST("fchmodat2 basic");
    char path[] = "/tmp/elfuse-test-fchmodat2-XXXXXX";
    int fd = mkstemp(path);
    if (fd < 0) {
        FAIL("mkstemp");
        return;
    }
    close(fd);
    /* fchmodat2(AT_FDCWD, path, 0644, 0) should work like fchmodat */
    long rc = syscall(SYS_fchmodat2, AT_FDCWD, path, 0644, 0);
    if (rc < 0) {
        FAIL("fchmodat2");
        unlink(path);
        return;
    }
    struct stat st;
    stat(path, &st);
    unlink(path);
    EXPECT_TRUE((st.st_mode & 0777) == 0644, "mode mismatch");
}

static void test_getcpu_basic(void)
{
    TEST("getcpu basic");
    unsigned cpu = 99, node = 99;
    long rc = syscall(SYS_getcpu, &cpu, &node, 0);
    if (rc < 0) {
        FAIL("getcpu");
        return;
    }
    EXPECT_TRUE(cpu == 0, "cpu should be 0");
    EXPECT_TRUE(node == 0, "node should be 0");
}

static void test_fchmodat2_symlink_nofollow(void)
{
    TEST("fchmodat2 AT_SYMLINK_NOFOLLOW");
    char target[] = "/tmp/elfuse-test-fchmodat2-target-XXXXXX";
    char linkpath[64];

    int fd = mkstemp(target);
    if (fd < 0) {
        FAIL("mkstemp target");
        return;
    }
    close(fd);
    /* Derive the symlink name from the unique target so we never call mktemp,
     * which is racy and triggers a linker warning on glibc.
     */
    snprintf(linkpath, sizeof(linkpath), "%s.lnk", target);

    if (symlink(target, linkpath) < 0) {
        FAIL("symlink");
        unlink(target);
        return;
    }

    /* AT_SYMLINK_NOFOLLOW must change the symlink's mode, not the target's.
     * Most Linux filesystems (including tmpfs, ext4, btrfs without the
     * symlink-mode opt-in) reject this with EOPNOTSUPP because the on-disk
     * inode for a symlink has no separately writable mode bit. Treat that
     * answer as an honest skip: the kernel reached fchmodat2_write and
     * declined the specific request. Any other negative return is a real
     * failure that the test should surface.
     */
    long rc =
        syscall(SYS_fchmodat2, AT_FDCWD, linkpath, 0700, AT_SYMLINK_NOFOLLOW);
    if (rc < 0) {
        if (errno == EOPNOTSUPP) {
            SYSCALL_SKIP(
                "fchmodat2 AT_SYMLINK_NOFOLLOW unsupported by host fs");
            goto out;
        }
        FAIL("fchmodat2 nofollow");
        goto out;
    }

    struct stat st_link, st_target;
    if (lstat(linkpath, &st_link) < 0) {
        FAIL("lstat link");
        goto out;
    }
    if (stat(target, &st_target) < 0) {
        FAIL("stat target");
        goto out;
    }

    EXPECT_TRUE((st_link.st_mode & 0777) == 0700, "link mode mismatch");
    EXPECT_TRUE((st_target.st_mode & 0777) == 0600, "target mode changed");

out:
    unlink(linkpath);
    unlink(target);
}

/* openat2 (SYS 437). */

#ifndef SYS_openat2
#define SYS_openat2 437
#endif

struct open_how {
    unsigned long long flags, mode, resolve;
};

#define RESOLVE_BENEATH 0x08
#define RESOLVE_IN_ROOT 0x10
#define RESOLVE_NO_MAGICLINKS 0x02
#define RESOLVE_NO_SYMLINKS 0x04

static void test_openat2_basic(void)
{
    TEST("openat2 basic open");
    struct open_how how = {.flags = O_RDONLY, .mode = 0, .resolve = 0};
    long fd = syscall(SYS_openat2, AT_FDCWD, "/dev/null", &how, sizeof(how));
    if (fd < 0) {
        FAIL("openat2");
        return;
    }
    close(fd);
    PASS();
}

static void test_openat2_resolve_beneath(void)
{
    TEST("openat2 RESOLVE_BENEATH rejects ..");
    /* Open a directory first */
    int dirfd = open("/tmp", O_RDONLY | O_DIRECTORY);
    if (dirfd < 0) {
        FAIL("open /tmp");
        return;
    }
    struct open_how how = {
        .flags = O_RDONLY, .mode = 0, .resolve = RESOLVE_BENEATH};
    long fd = syscall(SYS_openat2, dirfd, "../etc/passwd", &how, sizeof(how));
    close(dirfd);
    if (fd >= 0) {
        close(fd);
        FAIL("should have rejected .. traversal");
        return;
    }
    EXPECT_TRUE(errno == EXDEV, "wrong errno");
}

static void test_openat2_resolve_beneath_allows_internal_dotdot(void)
{
    TEST("openat2 RESOLVE_BENEATH allows in-root ..");

    char dir_template[] = "/tmp/elfuse-openat2-beneath-XXXXXX";
    char subdir[PATH_MAX], target[PATH_MAX];
    int dirfd = -1, filefd = -1;

    if (!mkdtemp(dir_template)) {
        FAIL("mkdtemp");
        return;
    }

    snprintf(subdir, sizeof(subdir), "%s/subdir", dir_template);
    snprintf(target, sizeof(target), "%s/file", dir_template);
    if (mkdir(subdir, 0700) < 0) {
        FAIL("mkdir");
        goto out;
    }

    filefd = open(target, O_CREAT | O_RDONLY, 0600);
    if (filefd < 0) {
        FAIL("open file");
        goto out;
    }
    close(filefd);
    filefd = -1;

    dirfd = open(dir_template, O_RDONLY | O_DIRECTORY);
    if (dirfd < 0) {
        FAIL("open dir");
        goto out;
    }

    struct open_how how = {
        .flags = O_RDONLY, .mode = 0, .resolve = RESOLVE_BENEATH};
    long fd = syscall(SYS_openat2, dirfd, "subdir/../file", &how, sizeof(how));
    if (fd < 0) {
        FAIL("openat2");
        goto out;
    }
    close((int) fd);
    PASS();

out:
    if (dirfd >= 0)
        close(dirfd);
    if (filefd >= 0)
        close(filefd);
    unlink(target);
    rmdir(subdir);
    rmdir(dir_template);
}

static void test_openat2_resolve_in_root_clamps_dotdot(void)
{
    TEST("openat2 RESOLVE_IN_ROOT clamps .. at root");

    char dir_template[] = "/tmp/elfuse-openat2-inroot-XXXXXX";
    char target[PATH_MAX];
    int dirfd = -1, filefd = -1;

    if (!mkdtemp(dir_template)) {
        FAIL("mkdtemp");
        return;
    }

    snprintf(target, sizeof(target), "%s/file", dir_template);
    filefd = open(target, O_CREAT | O_RDONLY, 0600);
    if (filefd < 0) {
        FAIL("open file");
        goto out;
    }
    close(filefd);
    filefd = -1;

    dirfd = open(dir_template, O_RDONLY | O_DIRECTORY);
    if (dirfd < 0) {
        FAIL("open dir");
        goto out;
    }

    struct open_how how = {
        .flags = O_RDONLY, .mode = 0, .resolve = RESOLVE_IN_ROOT};
    long fd = syscall(SYS_openat2, dirfd, "/../file", &how, sizeof(how));
    if (fd < 0) {
        FAIL("openat2");
        goto out;
    }
    close((int) fd);
    PASS();

out:
    if (dirfd >= 0)
        close(dirfd);
    if (filefd >= 0)
        close(filefd);
    unlink(target);
    rmdir(dir_template);
}

static void test_openat2_resolve_no_symlinks_intermediate(void)
{
    TEST("openat2 RESOLVE_NO_SYMLINKS rejects intermediate symlink");

    char dir_template[] = "/tmp/elfuse-openat2-XXXXXX";
    char target_dir[PATH_MAX], subfile[PATH_MAX];
    char link_path[PATH_MAX];
    int dirfd = -1, filefd = -1;

    if (!mkdtemp(dir_template)) {
        FAIL("mkdtemp");
        return;
    }

    snprintf(target_dir, sizeof(target_dir), "%s/real", dir_template);
    snprintf(subfile, sizeof(subfile), "%s/subfile", target_dir);
    snprintf(link_path, sizeof(link_path), "%s/link", dir_template);

    if (mkdir(target_dir, 0700) < 0) {
        FAIL("mkdir");
        goto out;
    }
    filefd = open(subfile, O_CREAT | O_RDWR, 0600);
    if (filefd < 0) {
        FAIL("open subfile");
        goto out;
    }
    close(filefd);
    filefd = -1;
    if (symlink("real", link_path) < 0) {
        FAIL("symlink");
        goto out;
    }

    dirfd = open(dir_template, O_RDONLY | O_DIRECTORY);
    if (dirfd < 0) {
        FAIL("open dir");
        goto out;
    }

    struct open_how how = {
        .flags = O_RDONLY, .mode = 0, .resolve = RESOLVE_NO_SYMLINKS};
    long fd = syscall(SYS_openat2, dirfd, "link/subfile", &how, sizeof(how));
    if (fd >= 0) {
        close((int) fd);
        FAIL("expected ELOOP");
        goto out;
    }
    EXPECT_TRUE(errno == ELOOP, "wrong errno");

out:
    if (dirfd >= 0)
        close(dirfd);
    if (filefd >= 0)
        close(filefd);
    unlink(link_path);
    unlink(subfile);
    rmdir(target_dir);
    rmdir(dir_template);
}

static void test_openat2_resolve_beneath_rejects_symlink_escape(void)
{
    TEST("openat2 RESOLVE_BENEATH rejects symlink escape");

    char dir_template[] = "/tmp/elfuse-openat2-escape-XXXXXX";
    char link_path[PATH_MAX];
    int dirfd = -1;

    if (!mkdtemp(dir_template)) {
        FAIL("mkdtemp");
        return;
    }

    snprintf(link_path, sizeof(link_path), "%s/link", dir_template);
    if (symlink("/etc", link_path) < 0) {
        FAIL("symlink");
        goto out;
    }

    dirfd = open(dir_template, O_RDONLY | O_DIRECTORY);
    if (dirfd < 0) {
        FAIL("open dir");
        goto out;
    }

    struct open_how how = {
        .flags = O_RDONLY, .mode = 0, .resolve = RESOLVE_BENEATH};
    long fd = syscall(SYS_openat2, dirfd, "link/passwd", &how, sizeof(how));
    if (fd >= 0) {
        close((int) fd);
        FAIL("expected EXDEV");
        goto out;
    }
    EXPECT_TRUE(errno == EXDEV, "wrong errno");

out:
    if (dirfd >= 0)
        close(dirfd);
    unlink(link_path);
    rmdir(dir_template);
}

static void test_openat2_resolve_no_magiclinks_proc_fd(void)
{
    TEST("openat2 RESOLVE_NO_MAGICLINKS rejects /proc/self/fd");
    struct open_how how = {
        .flags = O_RDONLY, .mode = 0, .resolve = RESOLVE_NO_MAGICLINKS};
    long fd =
        syscall(SYS_openat2, AT_FDCWD, "/proc/self/fd/0", &how, sizeof(how));
    if (fd >= 0) {
        close((int) fd);
        FAIL("expected ELOOP");
        return;
    }
    EXPECT_TRUE(errno == ELOOP, "wrong errno");
}

static void test_openat2_resolve_no_magiclinks_proc_cwd(void)
{
    TEST("openat2 RESOLVE_NO_MAGICLINKS rejects proc cwd magiclinks");
    struct open_how how = {
        .flags = O_RDONLY, .mode = 0, .resolve = RESOLVE_NO_MAGICLINKS};
    char cwd[256];

    if (!getcwd(cwd, sizeof(cwd))) {
        FAIL("getcwd");
        return;
    }
    if (chdir("/proc") < 0) {
        FAIL("chdir");
        return;
    }

    errno = 0;
    long fd = syscall(SYS_openat2, AT_FDCWD, "self/fd/0", &how, sizeof(how));
    int saved_errno = errno;
    if (chdir(cwd) < 0) {
        FAIL("restore cwd");
        return;
    }

    errno = saved_errno;
    if (fd >= 0) {
        close((int) fd);
        FAIL("expected ELOOP");
        return;
    }
    EXPECT_TRUE(errno == ELOOP, "wrong errno");
}

/* O_PATH enforcement. */

#ifndef O_PATH
#define O_PATH 010000000
#endif

#ifndef MADV_COLD
#define MADV_COLD 20
#endif

static void test_opath_read_fails(void)
{
    TEST("O_PATH fd rejects read");
    int fd = open("/dev/null", O_PATH);
    if (fd < 0) {
        FAIL("open O_PATH");
        return;
    }
    char buf[1];
    ssize_t n = read(fd, buf, 1);
    close(fd);
    EXPECT_TRUE(n < 0 && errno == EBADF, "read should return EBADF");
}

static void test_opath_write_fails(void)
{
    TEST("O_PATH fd rejects write");
    int fd = open("/dev/null", O_PATH);
    if (fd < 0) {
        FAIL("open O_PATH");
        return;
    }
    ssize_t n = write(fd, "x", 1);
    close(fd);
    EXPECT_TRUE(n < 0 && errno == EBADF, "write should return EBADF");
}

static void test_opath_fstat_works(void)
{
    TEST("O_PATH fd allows fstat");
    int fd = open("/dev/null", O_PATH);
    if (fd < 0) {
        FAIL("open O_PATH");
        return;
    }
    struct stat st;
    int rc = fstat(fd, &st);
    close(fd);
    EXPECT_TRUE(rc == 0, "fstat should work on O_PATH");
}

/* madvise parity. */

static void test_madvise_cold(void)
{
    TEST("madvise MADV_COLD accepted");
    void *p = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) {
        FAIL("mmap");
        return;
    }
    int rc = madvise(p, 4096, MADV_COLD);
    munmap(p, 4096);
    EXPECT_TRUE(rc == 0, "madvise MADV_COLD");
}

static void test_madvise_dontneed_unmapped(void)
{
    TEST("madvise DONTNEED on unmapped returns ENOMEM");
    /* Map a page, then unmap the second half to create a hole */
    void *p = mmap(NULL, 8192, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) {
        FAIL("mmap");
        return;
    }
    munmap((char *) p + 4096, 4096);
    /* MADV_DONTNEED across the boundary should fail */
    int rc = madvise(p, 8192, MADV_DONTNEED);
    munmap(p, 4096);
    EXPECT_TRUE(rc < 0 && errno == ENOMEM, "expected ENOMEM for unmapped hole");
}

/* mmap low-hint preservation. */

static void test_mmap_low_hint_exact(void)
{
    TEST("mmap low hint preserves ET_EXEC-style address");
    size_t len = 0x21000;
    static const uintptr_t candidates[] = {
        0x00400000ULL, 0x00800000ULL, 0x01000000ULL,
        0x02000000ULL, 0x04000000ULL, 0x06000000ULL,
    };
    void *hint = MAP_FAILED;
    for (size_t i = 0; i < sizeof(candidates) / sizeof(candidates[0]); i++) {
        hint = mmap((void *) candidates[i], len, PROT_NONE,
                    MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
        if (hint != MAP_FAILED)
            break;
        if (errno != EEXIST && errno != EINVAL) {
            FAIL("probe mmap");
            return;
        }
    }
    if (hint == MAP_FAILED) {
        FAIL("no free low hint candidate");
        return;
    }
    munmap(hint, len);

    void *p = mmap(hint, len, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) {
        FAIL("mmap");
        return;
    }
    EXPECT_TRUE((uintptr_t) p == (uintptr_t) hint,
                "low mmap hint should be honored when range is free");
    munmap(p, len);
}

int main(void)
{
    printf("Linux syscall fidelity tests:\n");

    /* fchmodat2 / getcpu */
    test_fchmodat2_basic();
    test_fchmodat2_symlink_nofollow();
    test_getcpu_basic();

    /* openat2 RESOLVE_* */
    test_openat2_basic();
    test_openat2_resolve_beneath();
    test_openat2_resolve_beneath_allows_internal_dotdot();
    test_openat2_resolve_in_root_clamps_dotdot();
    test_openat2_resolve_no_symlinks_intermediate();
    test_openat2_resolve_beneath_rejects_symlink_escape();
    test_openat2_resolve_no_magiclinks_proc_fd();
    test_openat2_resolve_no_magiclinks_proc_cwd();

    /* O_PATH */
    test_opath_read_fails();
    test_opath_write_fails();
    test_opath_fstat_works();

    /* madvise */
    test_madvise_cold();
    test_madvise_dontneed_unmapped();

    /* mmap low-hint */
    test_mmap_low_hint_exact();

    printf("\ntest-syscall-fidelity: %d passed, %d failed, %d skipped%s\n",
           passes, fails, syscall_skips, fails == 0 ? " - PASS" : " - FAIL");
    return fails ? 1 : 0;
}
