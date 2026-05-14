/* Direct syscall smoke coverage for less frequently hit dispatch entries
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <sched.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/sem.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "test-harness.h"

#ifndef SYS_close_range
#define SYS_close_range 436
#endif

#ifndef SYS_execveat
#define SYS_execveat 281
#endif

#ifndef SYS_pwrite64
#define SYS_pwrite64 68
#endif

#ifndef SYS_preadv2
#define SYS_preadv2 286
#endif

#ifndef SYS_renameat
#define SYS_renameat 38
#endif

#ifndef SYS_sigaltstack
#define SYS_sigaltstack 132
#endif

#ifndef SYS_set_tid_address
#define SYS_set_tid_address 96
#endif

int passes = 0, fails = 0;
extern char **environ;

struct linux_cap_user_header {
    uint32_t version;
    int32_t pid;
};

struct linux_cap_user_data {
    uint32_t effective;
    uint32_t permitted;
    uint32_t inheritable;
};

union semun {
    int val;
    struct semid_ds *buf;
    unsigned short *array;
};

static void test_pwrite64_basic(void)
{
    TEST("pwrite64");
    char path[] = "/tmp/elfuse-pwrite64-XXXXXX";
    int fd = mkstemp(path);
    if (fd < 0) {
        FAIL("mkstemp");
        return;
    }
    unlink(path);

    const char *msg = "xyz";
    ssize_t rc = (ssize_t) syscall(SYS_pwrite64, fd, msg, 3, 1);
    if (rc != 3) {
        FAIL("pwrite64");
        close(fd);
        return;
    }

    char buf[8] = {0};
    lseek(fd, 0, SEEK_SET);
    if (read(fd, buf, sizeof(buf)) >= 4 && memcmp(buf, "\0xyz", 4) == 0)
        PASS();
    else
        FAIL("pwrite64 contents");
    close(fd);
}

static void test_splice_family(void)
{
    TEST("vmsplice + splice");
    int src[2] = {-1, -1};
    int mid[2] = {-1, -1};
    struct iovec iov = {.iov_base = (void *) "pipe-data", .iov_len = 9};
    char out[16] = {0};
    bool ok = false;

    if (pipe(src) != 0 || pipe(mid) != 0) {
        FAIL("pipe");
        goto out;
    }
    if (syscall(SYS_vmsplice, src[1], &iov, 1, 0) != 9) {
        FAIL("vmsplice");
        goto out;
    }
    if (syscall(SYS_splice, src[0], NULL, mid[1], NULL, 9, 0) != 9) {
        FAIL("splice");
        goto out;
    }
    if (read(mid[0], out, sizeof(out)) != 9 ||
        memcmp(out, "pipe-data", 9) != 0) {
        FAIL("splice payload");
        goto out;
    }
    ok = true;

out:
    if (src[0] >= 0)
        close(src[0]);
    if (src[1] >= 0)
        close(src[1]);
    if (mid[0] >= 0)
        close(mid[0]);
    if (mid[1] >= 0)
        close(mid[1]);
    if (ok)
        PASS();
}

static void test_tee_stub_errno(void)
{
    TEST("tee returns EINVAL");
    int src[2] = {-1, -1};
    int dst[2] = {-1, -1};

    if (pipe(src) != 0 || pipe(dst) != 0) {
        FAIL("pipe");
        goto out;
    }

    errno = 0;
    EXPECT_ERRNO(syscall(SYS_tee, src[0], dst[1], 1, 0), EINVAL,
                 "tee should report EINVAL");

out:
    if (src[0] >= 0)
        close(src[0]);
    if (src[1] >= 0)
        close(src[1]);
    if (dst[0] >= 0)
        close(dst[0]);
    if (dst[1] >= 0)
        close(dst[1]);
}

static void test_close_range_basic(void)
{
    TEST("close_range");
    int pipes[3][2];
    memset(pipes, -1, sizeof(pipes));
    for (size_t i = 0; i < 3; i++) {
        if (pipe(pipes[i]) != 0) {
            FAIL("pipe");
            goto out;
        }
    }

    unsigned first = (unsigned) pipes[0][0];
    unsigned last = (unsigned) pipes[2][1];
    if (syscall(SYS_close_range, first, last, 0) != 0) {
        FAIL("close_range");
        goto out;
    }

    /* Probe before clearing pipes[] so the EXPECT_ERRNO actually tests
     * close_range's effect, not close(-1). On success every fd in the
     * range is closed, so leave pipes[] zeroed afterward to keep the
     * cleanup loop from double-closing.
     */
    int probe_fd = pipes[1][0];
    memset(pipes, -1, sizeof(pipes));
    errno = 0;
    EXPECT_ERRNO(close(probe_fd), EBADF, "close_range left fd open");

out:
    for (size_t i = 0; i < 3; i++) {
        if (pipes[i][0] >= 0)
            close(pipes[i][0]);
        if (pipes[i][1] >= 0)
            close(pipes[i][1]);
    }
}

static void test_at_path_ops(void)
{
    TEST("mknodat + mkdirat + symlinkat + renameat");
    char dir_template[] = "/tmp/elfuse-atops-XXXXXX";
    char fifo_path[256] = "";
    char link_path[256] = "";
    char moved_path[256] = "";
    char subdir_path[256] = "";
    int dirfd = -1;
    bool ok = false;

    if (!mkdtemp(dir_template)) {
        FAIL("mkdtemp");
        return;
    }
    /* Materialize cleanup paths up-front so that any early goto-out still
     * unlinks/rmdirs whatever the syscalls under test managed to create.
     */
    snprintf(fifo_path, sizeof(fifo_path), "%s/fifo", dir_template);
    snprintf(link_path, sizeof(link_path), "%s/fifo.link", dir_template);
    snprintf(moved_path, sizeof(moved_path), "%s/fifo.moved", dir_template);
    snprintf(subdir_path, sizeof(subdir_path), "%s/sub", dir_template);

    dirfd = open(dir_template, O_RDONLY | O_DIRECTORY);
    if (dirfd < 0) {
        FAIL("open dir");
        goto out;
    }
    if (syscall(SYS_mkdirat, dirfd, "sub", 0700) != 0) {
        FAIL("mkdirat");
        goto out;
    }
    if (syscall(SYS_mknodat, dirfd, "fifo", S_IFIFO | 0600, 0) != 0) {
        FAIL("mknodat");
        goto out;
    }
    if (syscall(SYS_symlinkat, "fifo", dirfd, "fifo.link") != 0) {
        FAIL("symlinkat");
        goto out;
    }
    if (syscall(SYS_renameat, dirfd, "fifo.link", dirfd, "fifo.moved") != 0) {
        FAIL("renameat");
        goto out;
    }
    if (access(link_path, F_OK) == 0 || errno != ENOENT ||
        access(moved_path, F_OK) != 0 || access(fifo_path, F_OK) != 0) {
        FAIL("path ops verification");
        goto out;
    }
    ok = true;

out:
    if (dirfd >= 0)
        close(dirfd);
    if (moved_path[0])
        unlink(moved_path);
    if (link_path[0])
        unlink(link_path);
    if (fifo_path[0])
        unlink(fifo_path);
    if (subdir_path[0])
        rmdir(subdir_path);
    rmdir(dir_template);
    /* Body-side FAIL() already reported the specific step on failure; only
     * report PASS here. Adding a trailing else-FAIL would double-count.
     */
    if (ok)
        PASS();
}

static void test_statfs_and_umask(void)
{
    TEST("statfs + umask");
    struct statfs st;
    mode_t old = umask(022);
    mode_t restored = umask(old);
    if (statfs("/tmp", &st) == 0 && st.f_bsize > 0 && restored == 022)
        PASS();
    else
        FAIL("statfs/umask");
}

static void test_direct_gap_syscalls(void)
{
    TEST(
        "preadv2 + fstatfs + fchmodat + sync + setregid + setresgid + "
        "sched_yield");
    char path[] = "/tmp/elfuse-syscall-gap-XXXXXX";
    int fd = -1;
    struct iovec iov;
    char buf[8] = {0};
    struct statfs st;
    struct stat sb;
    bool ok = false;

    fd = mkstemp(path);
    if (fd < 0) {
        FAIL("mkstemp");
        return;
    }

    if (write(fd, "abcd", 4) != 4) {
        FAIL("write");
        goto out;
    }

    iov.iov_base = buf;
    iov.iov_len = 3;
    if (preadv2(fd, &iov, 1, 1, 0) != 3 || memcmp(buf, "bcd", 3) != 0) {
        FAIL("preadv2");
        goto out;
    }
    if (fstatfs(fd, &st) != 0 || st.f_bsize <= 0) {
        FAIL("fstatfs");
        goto out;
    }
    if (fchmodat(AT_FDCWD, path, 0600, 0) != 0) {
        FAIL("fchmodat");
        goto out;
    }
    if (stat(path, &sb) != 0 || (sb.st_mode & 0777) != 0600) {
        FAIL("fchmodat verify");
        goto out;
    }
    sync();
    if (setregid((gid_t) -1, (gid_t) -1) != 0) {
        FAIL("setregid");
        goto out;
    }
    if (setresgid((gid_t) -1, (gid_t) -1, (gid_t) -1) != 0) {
        FAIL("setresgid");
        goto out;
    }
    if (sched_yield() != 0) {
        FAIL("sched_yield");
        goto out;
    }
    ok = true;

out:
    if (fd >= 0)
        close(fd);
    unlink(path);
    if (ok)
        PASS();
}

static void test_sigaltstack_and_timers(void)
{
    TEST("sigaltstack + getitimer + setitimer + clock_getres");
    stack_t old_ss;
    stack_t ss = {0};
    sigset_t oldmask, blockmask;
    bool mask_saved = false;
    struct itimerval old_timer;
    struct itimerval timer = {0};
    struct timespec ts;
    bool ok = false;

    ss.ss_size = SIGSTKSZ;
    ss.ss_sp = malloc(ss.ss_size);
    if (!ss.ss_sp) {
        FAIL("malloc");
        return;
    }
    if (syscall(SYS_sigaltstack, &ss, &old_ss) != 0) {
        FAIL("sigaltstack");
        goto out;
    }
    sigemptyset(&blockmask);
    sigaddset(&blockmask, SIGALRM);
    if (sigprocmask(SIG_BLOCK, &blockmask, &oldmask) != 0) {
        FAIL("sigprocmask");
        goto out;
    }
    mask_saved = true;
    timer.it_value.tv_usec = 1000;
    if (setitimer(ITIMER_REAL, &timer, &old_timer) != 0) {
        FAIL("setitimer");
        goto out;
    }
    if (getitimer(ITIMER_REAL, &timer) != 0) {
        FAIL("getitimer");
        goto out;
    }
    if (clock_getres(CLOCK_MONOTONIC, &ts) != 0) {
        FAIL("clock_getres");
        goto out;
    }
    if (timer.it_value.tv_sec < 0 || ts.tv_nsec < 0) {
        FAIL("timer query");
        goto out;
    }
    ok = true;

out:
    timer.it_value.tv_sec = 0;
    timer.it_value.tv_usec = 0;
    timer.it_interval.tv_sec = 0;
    timer.it_interval.tv_usec = 0;
    setitimer(ITIMER_REAL, &timer, NULL);
    if (mask_saved)
        sigprocmask(SIG_SETMASK, &oldmask, NULL);
    ss.ss_flags = SS_DISABLE;
    syscall(SYS_sigaltstack, &ss, NULL);
    free(ss.ss_sp);
    /* Body-side FAIL() already reported the specific step on failure. */
    if (ok)
        PASS();
}

static void test_waitid(void)
{
    TEST("waitid");
    pid_t pid = fork();
    if (pid < 0) {
        FAIL("fork");
        return;
    }
    if (pid == 0)
        _exit(17);

    siginfo_t info;
    memset(&info, 0, sizeof(info));
    long rc = syscall(SYS_waitid, P_PID, pid, &info, WEXITED, NULL);
    if (rc == 0 && info.si_pid == pid && info.si_status == 17) {
        PASS();
        return;
    }
    /* waitid failed or returned the wrong siginfo; reap with waitpid so
     * the child does not linger as a zombie and skew later tests.
     */
    int status;
    waitpid(pid, &status, 0);
    FAIL("waitid");
}

static void test_execveat(int argc, char **argv)
{
    if (argc > 1 && strcmp(argv[1], "--execveat-child") == 0)
        _exit(23);

    TEST("execveat");
    pid_t pid = fork();
    if (pid < 0) {
        FAIL("fork");
        return;
    }
    if (pid == 0) {
        char *child_argv[] = {argv[0], "--execveat-child", NULL};
        syscall(SYS_execveat, AT_FDCWD, argv[0], child_argv, environ, 0);
        _exit(127);
    }

    int status = 0;
    if (waitpid(pid, &status, 0) == pid && WIFEXITED(status) &&
        WEXITSTATUS(status) == 23)
        PASS();
    else
        FAIL("execveat");
}

static void test_process_query_stubs(void)
{
    TEST("set_tid_address + capget + personality");
    int clear_tid = 0;
    struct linux_cap_user_header hdr = {
        .version = 0x20080522,
        .pid = 0,
    };
    struct linux_cap_user_data data[2];
    memset(data, 0, sizeof(data));

    long tid = syscall(SYS_set_tid_address, &clear_tid);
    long caps = syscall(SYS_capget, &hdr, data);
    long pers = syscall(SYS_personality, 0xffffffffu);
    if (tid > 0 && caps == 0 && pers >= 0)
        PASS();
    else
        FAIL("process query stubs");
}

static void test_stub_errnos(void)
{
    TEST("sethostname returns EPERM");
    errno = 0;
    EXPECT_ERRNO(syscall(SYS_sethostname, "elfuse", 6), EPERM,
                 "sethostname should fail with EPERM");

    TEST("io_destroy returns EINVAL");
    errno = 0;
    EXPECT_ERRNO(syscall(SYS_io_destroy, 1), EINVAL,
                 "io_destroy should fail with EINVAL");

    TEST("mincore returns ENOSYS");
    char page[4096];
    unsigned char vec = 0xff;
    errno = 0;
    EXPECT_ERRNO(syscall(SYS_mincore, page, sizeof(page), &vec), ENOSYS,
                 "mincore should fail with ENOSYS");
}

static void test_memory_stubs(void)
{
    TEST("mlock + munlock");
    void *p = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) {
        FAIL("mmap");
        return;
    }
    if (mlock(p, 4096) == 0 && munlock(p, 4096) == 0)
        PASS();
    else
        FAIL("mlock/munlock");
    munmap(p, 4096);
}

static void test_accept4(void)
{
    TEST("accept4");
    int listen_fd = -1, client_fd = -1, server_fd = -1;
    struct sockaddr_in addr;
    socklen_t addrlen = sizeof(addr);
    pid_t pid;
    int status = 0;

    listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) {
        FAIL("socket");
        return;
    }
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(listen_fd, (struct sockaddr *) &addr, sizeof(addr)) != 0 ||
        listen(listen_fd, 1) != 0 ||
        getsockname(listen_fd, (struct sockaddr *) &addr, &addrlen) != 0) {
        FAIL("listen setup");
        goto out;
    }

    pid = fork();
    if (pid < 0) {
        FAIL("fork");
        goto out;
    }
    if (pid == 0) {
        client_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (client_fd < 0)
            _exit(1);
        int rc = connect(client_fd, (struct sockaddr *) &addr, sizeof(addr));
        _exit(rc == 0 ? 0 : 2);
    }

    /* Gate the blocking accept4() on a poll(): if the child fails before
     * connect(), no incoming connection will ever arrive and the parent
     * would wedge the test until the driver timeout. The poll bounds the
     * wait so we can detect that case and fail fast.
     */
    struct pollfd pfd = {.fd = listen_fd, .events = POLLIN};
    int pr = poll(&pfd, 1, 2000);
    if (pr <= 0) {
        waitpid(pid, &status, 0);
        FAIL("no client connection within 2s");
        goto out;
    }
    server_fd = accept4(listen_fd, NULL, NULL, SOCK_CLOEXEC);
    waitpid(pid, &status, 0);
    if (server_fd < 0 || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        FAIL("accept4 handshake");
        goto out;
    }
    int flags = fcntl(server_fd, F_GETFD);
    if (flags < 0 || !(flags & FD_CLOEXEC)) {
        FAIL("SOCK_CLOEXEC not applied");
        goto out;
    }
    PASS();

out:
    if (server_fd >= 0)
        close(server_fd);
    if (client_fd >= 0)
        close(client_fd);
    if (listen_fd >= 0)
        close(listen_fd);
}

static void test_sysv_semaphore_ops(void)
{
    TEST("semget + semctl + semop");
    int semid = semget(IPC_PRIVATE, 1, IPC_CREAT | 0600);
    if (semid < 0) {
        FAIL("semget");
        return;
    }

    union semun arg = {.val = 1};
    struct sembuf sop = {.sem_num = 0, .sem_op = -1, .sem_flg = 0};
    if (semctl(semid, 0, SETVAL, arg) == 0 && semop(semid, &sop, 1) == 0 &&
        semctl(semid, 0, IPC_RMID, arg) == 0)
        PASS();
    else {
        semctl(semid, 0, IPC_RMID, arg);
        FAIL("semop");
    }
}

int main(int argc, char **argv)
{
    printf("test-syscall-smoke: direct syscall smoke coverage\n\n");

    test_pwrite64_basic();
    test_splice_family();
    test_tee_stub_errno();
    test_close_range_basic();
    test_at_path_ops();
    test_statfs_and_umask();
    test_direct_gap_syscalls();
    test_sigaltstack_and_timers();
    test_waitid();
    test_execveat(argc, argv);
    test_process_query_stubs();
    test_stub_errnos();
    test_memory_stubs();
    test_accept4();
    test_sysv_semaphore_ops();

    SUMMARY("test-syscall-smoke");
    return fails > 0 ? 1 : 0;
}
