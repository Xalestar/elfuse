/*
 * Process lifecycle compatibility tests
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Portable probes for guest-observable Linux fork/wait behavior. The same
 * binary is intended to run under elfuse and the qemu-aarch64 reference lane.
 * Keep host implementation details out of the assertions.
 *
 * Initial coverage:
 *   PID-01  nested-fork process IDs are unique
 *   WAIT-01 WNOHANG does not consume a running child
 *   WAIT-02 WNOWAIT can be repeated before a consuming wait
 *   WAIT-03..04 waitid(P_PGID) honors process groups and auto-reap state
 *   Z-01..06 zombie retention, no-zombie dispositions, and SIGCHLD timing
 *   O-01..03 orphan adoption by PID 1 and a child subreaper
 */

#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "test-harness.h"

int passes = 0, fails = 0;

static int write_full(int fd, const void *buf, size_t len)
{
    const unsigned char *p = buf;
    while (len > 0) {
        ssize_t n = write(fd, p, len);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (n == 0)
            return -1;
        p += (size_t) n;
        len -= (size_t) n;
    }
    return 0;
}

static int read_full(int fd, void *buf, size_t len)
{
    unsigned char *p = buf;
    while (len > 0) {
        ssize_t n = read(fd, p, len);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (n == 0)
            return -1;
        p += (size_t) n;
        len -= (size_t) n;
    }
    return 0;
}

static int child_exited_cleanly(pid_t pid, int expected_code)
{
    int status = 0;
    pid_t ret;
    do {
        ret = waitpid(pid, &status, 0);
    } while (ret < 0 && errno == EINTR);
    return ret == pid && WIFEXITED(status) &&
           WEXITSTATUS(status) == expected_code;
}

struct nested_pids {
    pid_t child;
    pid_t grandchild;
    int grandchild_ok;
};

static void test_nested_pid_uniqueness(void)
{
    TEST("PID-01 nested PIDs are unique");

    int report[2];
    if (pipe(report) < 0) {
        FAIL("PID-01 pipe failed");
        return;
    }

    pid_t parent = getpid();
    pid_t child = fork();
    if (child < 0) {
        close(report[0]);
        close(report[1]);
        FAIL("PID-01 first fork failed");
        return;
    }

    if (child == 0) {
        close(report[0]);
        struct nested_pids observed = {
            .child = getpid(),
            .grandchild = -1,
            .grandchild_ok = 0,
        };

        pid_t grandchild = fork();
        if (grandchild == 0)
            _exit(37);
        if (grandchild > 0) {
            observed.grandchild = grandchild;
            observed.grandchild_ok = child_exited_cleanly(grandchild, 37);
        }
        (void) write_full(report[1], &observed, sizeof(observed));
        close(report[1]);
        _exit(grandchild < 0 ? 2 : 0);
    }

    close(report[1]);
    struct nested_pids observed;
    memset(&observed, 0, sizeof(observed));
    int read_ok = read_full(report[0], &observed, sizeof(observed)) == 0;
    close(report[0]);
    int child_ok = child_exited_cleanly(child, 0);

    int unique = parent > 0 && child > 0 && observed.child > 0 &&
                 observed.grandchild > 0 && parent != observed.child &&
                 parent != observed.grandchild &&
                 observed.child != observed.grandchild;
    if (!read_ok || !child_ok || !observed.grandchild_ok || !unique) {
        printf(
            "[PID-01 parent=%d fork_child=%d child_self=%d "
            "grandchild=%d child_ok=%d grandchild_ok=%d] ",
            (int) parent, (int) child, (int) observed.child,
            (int) observed.grandchild, child_ok, observed.grandchild_ok);
        FAIL("nested process IDs were not unique/waitable");
        return;
    }
    PASS();
}

static void test_wnohang_running_child(void)
{
    TEST("WAIT-01 WNOHANG preserves child");

    int release[2];
    int ready[2];
    if (pipe(release) < 0 || pipe(ready) < 0) {
        FAIL("WAIT-01 pipe failed");
        return;
    }

    pid_t child = fork();
    if (child < 0) {
        FAIL("WAIT-01 fork failed");
        return;
    }
    if (child == 0) {
        close(release[1]);
        close(ready[0]);
        char byte = 'R';
        if (write_full(ready[1], &byte, 1) < 0)
            _exit(2);
        close(ready[1]);
        if (read_full(release[0], &byte, 1) < 0)
            _exit(3);
        close(release[0]);
        _exit(41);
    }

    close(release[0]);
    close(ready[1]);
    char byte;
    int synchronized = read_full(ready[0], &byte, 1) == 0;
    close(ready[0]);

    int status = 0;
    errno = 0;
    pid_t first = synchronized ? waitpid(child, &status, WNOHANG) : -1;
    int first_errno = errno;
    byte = 'X';
    int released = write_full(release[1], &byte, 1) == 0;
    close(release[1]);
    int reaped = child_exited_cleanly(child, 41);

    if (!synchronized || first != 0 || !released || !reaped) {
        printf(
            "[WAIT-01 child=%d first=%d errno=%d synchronized=%d "
            "released=%d reaped=%d] ",
            (int) child, (int) first, first_errno, synchronized, released,
            reaped);
        FAIL("WNOHANG changed or lost a running child");
        return;
    }
    PASS();
}

static int64_t monotonic_milliseconds(void)
{
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) < 0)
        return -1;
    return (int64_t) now.tv_sec * 1000 + now.tv_nsec / 1000000;
}

/* Fork a child that holds @done's write end until process exit. A zero-byte
 * read in the parent is an exit-side barrier: every writer has been closed by
 * the kernel. It does not consume the child's wait status.
 */
static pid_t fork_exit_with_eof(int exit_code)
{
    int done[2];
    if (pipe(done) < 0)
        return -1;
    pid_t child = fork();
    if (child < 0) {
        close(done[0]);
        close(done[1]);
        return -1;
    }
    if (child == 0) {
        close(done[0]);
        _exit(exit_code);
    }
    close(done[1]);
    char byte;
    ssize_t n;
    do {
        n = read(done[0], &byte, 1);
    } while (n < 0 && errno == EINTR);
    close(done[0]);
    if (n != 0) {
        int saved = errno;
        kill(child, SIGKILL);
        (void) child_exited_cleanly(child, 0);
        errno = saved ? saved : EIO;
        return -1;
    }
    return child;
}

static int wait_for_pid_gone(pid_t pid, int timeout_ms)
{
    int64_t deadline = monotonic_milliseconds() + timeout_ms;
    do {
        errno = 0;
        if (kill(pid, 0) < 0 && errno == ESRCH)
            return 0;
        usleep(10000);
    } while (monotonic_milliseconds() < deadline);
    errno = ETIMEDOUT;
    return -1;
}

static int waitid_wnowait_until_ready(pid_t child, siginfo_t *info)
{
    int64_t deadline = monotonic_milliseconds() + 5000;
    do {
        memset(info, 0, sizeof(*info));
        if (waitid(P_PID, (id_t) child, info, WEXITED | WNOWAIT | WNOHANG) < 0)
            return -1;
        if (info->si_pid == child)
            return 0;
        usleep(10000);
    } while (monotonic_milliseconds() < deadline);
    errno = ETIMEDOUT;
    return -1;
}

static void test_waitid_wnowait_repeat(void)
{
    TEST("WAIT-02 repeated WNOWAIT then reap");

    pid_t child = fork();
    if (child < 0) {
        FAIL("WAIT-02 fork failed");
        return;
    }
    if (child == 0)
        _exit(42);

    siginfo_t first;
    errno = 0;
    int first_rc = waitid_wnowait_until_ready(child, &first);
    int first_errno = errno;

    siginfo_t second;
    memset(&second, 0, sizeof(second));
    errno = 0;
    int second_rc =
        waitid(P_PID, (id_t) child, &second, WEXITED | WNOWAIT | WNOHANG);
    int second_errno = errno;

    int status = 0;
    errno = 0;
    pid_t consumed = waitpid(child, &status, 0);
    int consume_errno = errno;
    int consumed_status = status;

    errno = 0;
    pid_t after = waitpid(child, &status, WNOHANG);
    int after_errno = errno;

    int first_ok = first_rc == 0 && first.si_pid == child &&
                   first.si_code == CLD_EXITED && first.si_status == 42;
    int second_ok = second_rc == 0 && second.si_pid == child &&
                    second.si_code == CLD_EXITED && second.si_status == 42;
    int consume_ok = consumed == child && WIFEXITED(consumed_status) &&
                     WEXITSTATUS(consumed_status) == 42;
    int after_ok = after == -1 && after_errno == ECHILD;

    if (!first_ok || !second_ok || !consume_ok || !after_ok) {
        printf(
            "[WAIT-02 child=%d first=(rc=%d errno=%d pid=%d code=%d "
            "status=%d) second=(rc=%d errno=%d pid=%d code=%d status=%d) "
            "consume=(ret=%d errno=%d status=0x%x) "
            "after=(ret=%d errno=%d)] ",
            (int) child, first_rc, first_errno, (int) first.si_pid,
            first.si_code, first.si_status, second_rc, second_errno,
            (int) second.si_pid, second.si_code, second.si_status,
            (int) consumed, consume_errno, consumed_status, (int) after,
            after_errno);
        FAIL("WNOWAIT did not preserve a repeatable wait status");
        return;
    }
    PASS();
}

static void test_waitid_pgid_matching(void)
{
    TEST("WAIT-03 waitid P_PGID matches group");

    int release[2];
    if (pipe(release) < 0) {
        FAIL("WAIT-03 pipe failed");
        return;
    }

    pid_t group_child = fork();
    if (group_child == 0) {
        close(release[1]);
        char byte;
        int ok = read_full(release[0], &byte, 1) == 0;
        close(release[0]);
        _exit(ok ? 43 : 2);
    }
    close(release[0]);
    if (group_child < 0) {
        close(release[1]);
        FAIL("WAIT-03 group child fork failed");
        return;
    }

    int setpgid_ok = setpgid(group_child, group_child) == 0;
    pid_t other_child = fork_exit_with_eof(44);

    siginfo_t empty;
    memset(&empty, 0, sizeof(empty));
    errno = 0;
    int empty_rc =
        waitid(P_PGID, (id_t) group_child, &empty, WEXITED | WNOHANG);
    int empty_errno = errno;
    int empty_ok = empty_rc == 0 && empty.si_pid == 0;

    int other_ok = other_child > 0 && child_exited_cleanly(other_child, 44);
    char byte = 'X';
    int released = write_full(release[1], &byte, 1) == 0;
    close(release[1]);

    siginfo_t exited;
    memset(&exited, 0, sizeof(exited));
    errno = 0;
    int exited_rc = waitid(P_PGID, (id_t) group_child, &exited, WEXITED);
    int exited_errno = errno;
    int exited_ok = exited_rc == 0 && exited.si_pid == group_child &&
                    exited.si_code == CLD_EXITED && exited.si_status == 43;

    if (!setpgid_ok || other_child < 0 || !empty_ok || !other_ok || !released ||
        !exited_ok) {
        printf(
            "[WAIT-03 group=%d other=%d setpgid=%d "
            "empty=(rc=%d errno=%d pid=%d) other_ok=%d released=%d "
            "exited=(rc=%d errno=%d pid=%d code=%d status=%d)] ",
            (int) group_child, (int) other_child, setpgid_ok, empty_rc,
            empty_errno, (int) empty.si_pid, other_ok, released, exited_rc,
            exited_errno, (int) exited.si_pid, exited.si_code,
            exited.si_status);
        FAIL("waitid(P_PGID) selected a child outside the requested group");
        return;
    }
    PASS();
}

static void test_waitid_pgid_autoreap(void)
{
    TEST("WAIT-04 P_PGID sees live auto-reap child");

    struct sigaction old_action;
    struct sigaction action;
    memset(&action, 0, sizeof(action));
    action.sa_handler = SIG_IGN;
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGCHLD, &action, &old_action) < 0) {
        FAIL("WAIT-04 installing SIGCHLD disposition failed");
        return;
    }

    int release[2];
    if (pipe(release) < 0) {
        (void) sigaction(SIGCHLD, &old_action, NULL);
        FAIL("WAIT-04 pipe failed");
        return;
    }
    pid_t child = fork();
    if (child == 0) {
        close(release[1]);
        char byte;
        int ok = read_full(release[0], &byte, 1) == 0;
        close(release[0]);
        _exit(ok ? 45 : 2);
    }
    close(release[0]);

    int setpgid_ok = child > 0 && setpgid(child, child) == 0;
    siginfo_t live;
    memset(&live, 0, sizeof(live));
    errno = 0;
    int live_rc =
        child > 0 ? waitid(P_PGID, (id_t) child, &live, WEXITED | WNOHANG) : -1;
    int live_errno = errno;
    int live_ok = live_rc == 0 && live.si_pid == 0;

    char byte = 'X';
    int released = child > 0 && write_full(release[1], &byte, 1) == 0;
    close(release[1]);
    int gone_ok = child > 0 && wait_for_pid_gone(child, 5000) == 0;

    siginfo_t gone;
    memset(&gone, 0, sizeof(gone));
    errno = 0;
    int gone_rc =
        child > 0 ? waitid(P_PGID, (id_t) child, &gone, WEXITED | WNOHANG) : -2;
    int gone_errno = errno;
    int gone_wait_ok = gone_rc == -1 && gone_errno == ECHILD;
    int restore_ok = sigaction(SIGCHLD, &old_action, NULL) == 0;

    if (child < 0 || !setpgid_ok || !live_ok || !released || !gone_ok ||
        !gone_wait_ok || !restore_ok) {
        printf(
            "[WAIT-04 child=%d setpgid=%d live=(rc=%d errno=%d pid=%d) "
            "released=%d gone=%d final=(rc=%d errno=%d pid=%d) "
            "restore=%d] ",
            (int) child, setpgid_ok, live_rc, live_errno, (int) live.si_pid,
            released, gone_ok, gone_rc, gone_errno, (int) gone.si_pid,
            restore_ok);
        FAIL("auto-reap waitid(P_PGID) did not track the requested group");
        return;
    }
    PASS();
}

static void test_delayed_zombie_reap(void)
{
    TEST("Z-01 delayed zombie retains status");

    pid_t child = fork_exit_with_eof(51);
    if (child < 0) {
        FAIL("Z-01 fork/exit barrier failed");
        return;
    }
    usleep(50000);
    if (!child_exited_cleanly(child, 51)) {
        FAIL("delayed wait lost child exit status");
        return;
    }
    PASS();
}

static void test_reverse_zombie_reap(void)
{
    TEST("Z-02 reverse-order zombie reap");

    enum { CHILDREN = 8 };
    pid_t children[CHILDREN];
    int created = 0;
    for (int i = 0; i < CHILDREN; i++) {
        children[i] = fork_exit_with_eof(20 + i);
        if (children[i] < 0)
            break;
        created++;
    }

    int ok = created == CHILDREN;
    for (int i = created - 1; i >= 0; i--)
        if (!child_exited_cleanly(children[i], 20 + i))
            ok = 0;

    if (!ok) {
        printf("[Z-02 created=%d/%d] ", created, CHILDREN);
        FAIL("reverse wait lost or changed a child status");
        return;
    }
    PASS();
}

static void test_zombie_table_pressure(void)
{
    TEST("Z-03 retain 65 zombie statuses");

    enum { CHILDREN = 65 };
    pid_t children[CHILDREN];
    int created = 0;
    for (int i = 0; i < CHILDREN; i++) {
        children[i] = fork_exit_with_eof(i);
        if (children[i] < 0)
            break;
        created++;
    }

    int reaped = 0;
    int first_failure = -1;
    int first_errno = 0;
    for (int i = 0; i < created; i++) {
        errno = 0;
        if (child_exited_cleanly(children[i], i)) {
            reaped++;
        } else if (first_failure < 0) {
            first_failure = i;
            first_errno = errno;
        }
    }

    if (created != CHILDREN || reaped != CHILDREN) {
        printf("[Z-03 created=%d/%d reaped=%d first_failure=%d errno=%d] ",
               created, CHILDREN, reaped, first_failure, first_errno);
        FAIL("internal child-table pressure lost wait statuses");
        return;
    }
    PASS();
}

static void test_no_zombie_disposition(int use_no_cldwait)
{
    TEST(use_no_cldwait ? "Z-05 SA_NOCLDWAIT auto-reaps"
                        : "Z-04 SIGCHLD=SIG_IGN auto-reaps");

    struct sigaction old_action;
    struct sigaction action;
    memset(&action, 0, sizeof(action));
    sigemptyset(&action.sa_mask);
    if (use_no_cldwait) {
        action.sa_handler = SIG_DFL;
        action.sa_flags = SA_NOCLDWAIT;
    } else {
        action.sa_handler = SIG_IGN;
    }
    if (sigaction(SIGCHLD, &action, &old_action) < 0) {
        FAIL("installing SIGCHLD disposition failed");
        return;
    }

    pid_t child = fork_exit_with_eof(53 + use_no_cldwait);
    int gone_ok = child > 0 && wait_for_pid_gone(child, 5000) == 0;

    int status = 0;
    int restore_ok = sigaction(SIGCHLD, &old_action, NULL) == 0;
    errno = 0;
    pid_t waited = child < 0 ? -2 : waitpid(child, &status, 0);
    int wait_errno = errno;

    if (child < 0 || !gone_ok || waited != -1 || wait_errno != ECHILD ||
        !restore_ok) {
        printf(
            "[Z-%02d child=%d gone=%d wait=%d errno=%d status=0x%x "
            "restore=%d] ",
            use_no_cldwait ? 5 : 4, (int) child, gone_ok, (int) waited,
            wait_errno, status, restore_ok);
        FAIL("no-zombie SIGCHLD disposition retained a waitable child");
        return;
    }
    PASS();
}

static volatile sig_atomic_t sigchld_count;

static void sigchld_handler(int signum)
{
    (void) signum;
    sigchld_count++;
}

static void test_sigchld_before_wait(void)
{
    TEST("Z-06 SIGCHLD arrives before wait");

    struct sigaction old_action;
    struct sigaction action;
    memset(&action, 0, sizeof(action));
    action.sa_handler = sigchld_handler;
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGCHLD, &action, &old_action) < 0) {
        FAIL("installing SIGCHLD handler failed");
        return;
    }

    sigchld_count = 0;
    pid_t child = fork();
    if (child == 0)
        _exit(56);

    int64_t deadline = monotonic_milliseconds() + 3000;
    while (child > 0 && sigchld_count == 0 &&
           monotonic_milliseconds() < deadline)
        usleep(10000);
    int before_wait = sigchld_count;
    int reaped = child > 0 && child_exited_cleanly(child, 56);
    int after_wait = sigchld_count;
    int restore_ok = sigaction(SIGCHLD, &old_action, NULL) == 0;

    if (child < 0 || before_wait == 0 || !reaped || !restore_ok) {
        printf(
            "[Z-06 child=%d before_wait=%d after_wait=%d reaped=%d "
            "restore=%d] ",
            (int) child, before_wait, after_wait, reaped, restore_ok);
        FAIL("SIGCHLD was not delivered when child became waitable");
        return;
    }
    PASS();
}

struct orphan_report {
    pid_t child_pid;
    pid_t original_ppid;
    pid_t adopted_ppid;
};

static pid_t wait_for_ppid(pid_t expected, int timeout_ms)
{
    int64_t deadline = monotonic_milliseconds() + timeout_ms;
    pid_t observed;
    do {
        observed = getppid();
        if (observed == expected)
            return observed;
        usleep(10000);
    } while (monotonic_milliseconds() < deadline);
    return observed;
}

static void test_orphan_reparent_to_init(void)
{
    TEST("O-01 orphan reparents to PID 1");

    int meta[2];
    int result[2];
    int leaf_ready[2];
    if (pipe(meta) < 0 || pipe(result) < 0 || pipe(leaf_ready) < 0) {
        FAIL("O-01 pipe failed");
        return;
    }

    pid_t middle = fork();
    if (middle < 0) {
        FAIL("O-01 middle fork failed");
        return;
    }
    if (middle == 0) {
        close(meta[0]);
        close(result[0]);
        pid_t leaf = fork();
        if (leaf == 0) {
            close(meta[1]);
            close(leaf_ready[0]);
            struct orphan_report report = {
                .child_pid = getpid(),
                .original_ppid = getppid(),
                .adopted_ppid = -1,
            };
            char ready = 'R';
            (void) write_full(leaf_ready[1], &ready, 1);
            close(leaf_ready[1]);
            report.adopted_ppid = wait_for_ppid(1, 3000);
            (void) write_full(result[1], &report, sizeof(report));
            close(result[1]);
            _exit(report.adopted_ppid == 1 ? 0 : 2);
        }
        close(leaf_ready[1]);
        char ready;
        int ready_ok = read_full(leaf_ready[0], &ready, 1) == 0;
        close(leaf_ready[0]);
        (void) write_full(meta[1], &leaf, sizeof(leaf));
        close(meta[1]);
        close(result[1]);
        _exit(ready_ok ? 0 : 3);
    }

    close(meta[1]);
    close(result[1]);
    close(leaf_ready[0]);
    close(leaf_ready[1]);
    pid_t leaf = -1;
    int meta_ok = read_full(meta[0], &leaf, sizeof(leaf)) == 0;
    close(meta[0]);
    int middle_ok = child_exited_cleanly(middle, 0);
    struct orphan_report report;
    memset(&report, 0, sizeof(report));
    int result_ok = read_full(result[0], &report, sizeof(report)) == 0;
    close(result[0]);

    if (!meta_ok || !middle_ok || !result_ok || leaf <= 0 ||
        report.child_pid != leaf || report.original_ppid != middle ||
        report.adopted_ppid != 1) {
        printf(
            "[O-01 middle=%d leaf=%d report=(pid=%d old=%d new=%d) "
            "meta=%d middle_ok=%d result=%d] ",
            (int) middle, (int) leaf, (int) report.child_pid,
            (int) report.original_ppid, (int) report.adopted_ppid, meta_ok,
            middle_ok, result_ok);
        FAIL("orphan PPID did not change to 1");
        return;
    }
    PASS();
}

static void test_orphan_reparent_to_subreaper(void)
{
    TEST("O-02 subreaper adopts live orphan");

    if (prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) < 0) {
        FAIL("O-02 setting subreaper failed");
        return;
    }

    int meta[2];
    if (pipe(meta) < 0) {
        FAIL("O-02 pipe failed");
        return;
    }
    pid_t subreaper = getpid();
    pid_t middle = fork();
    if (middle == 0) {
        close(meta[0]);
        pid_t leaf = fork();
        if (leaf == 0) {
            close(meta[1]);
            pid_t adopted = wait_for_ppid(subreaper, 3000);
            _exit(adopted == subreaper ? 62 : 63);
        }
        (void) write_full(meta[1], &leaf, sizeof(leaf));
        close(meta[1]);
        _exit(61);
    }

    close(meta[1]);
    pid_t leaf = -1;
    int meta_ok = middle > 0 && read_full(meta[0], &leaf, sizeof(leaf)) == 0;
    close(meta[0]);
    int middle_ok = middle > 0 && child_exited_cleanly(middle, 61);
    int leaf_status = 0;
    errno = 0;
    pid_t leaf_reaped = leaf > 0 ? waitpid(leaf, &leaf_status, 0) : -1;
    int leaf_errno = errno;
    int leaf_ok = leaf_reaped == leaf && WIFEXITED(leaf_status) &&
                  WEXITSTATUS(leaf_status) == 62;
    int clear_ok = prctl(PR_SET_CHILD_SUBREAPER, 0, 0, 0, 0) == 0;

    if (!meta_ok || !middle_ok || !leaf_ok || !clear_ok) {
        printf(
            "[O-02 self=%d middle=%d leaf=%d meta=%d middle_ok=%d "
            "leaf_reaped=%d leaf_status=0x%x leaf_errno=%d leaf_ok=%d "
            "clear=%d] ",
            (int) subreaper, (int) middle, (int) leaf, meta_ok, middle_ok,
            (int) leaf_reaped, leaf_status, leaf_errno, leaf_ok, clear_ok);
        FAIL("subreaper did not adopt and reap live orphan");
        return;
    }
    PASS();
}

static void test_subreaper_adopts_zombie(void)
{
    TEST("O-03 subreaper adopts exited children");

    enum { ZOMBIE_CHILDREN = 16 };
    struct zombie_report {
        pid_t leaves[ZOMBIE_CHILDREN];
        int created;
        int exit_barrier_ok;
    };

    if (prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) < 0) {
        FAIL("O-03 setting subreaper failed");
        return;
    }

    int meta[2];
    if (pipe(meta) < 0) {
        FAIL("O-03 pipe failed");
        return;
    }
    pid_t middle = fork();
    if (middle == 0) {
        close(meta[0]);
        int exited[2];
        if (pipe(exited) < 0)
            _exit(2);

        struct zombie_report report;
        memset(&report, 0, sizeof(report));
        for (int i = 0; i < ZOMBIE_CHILDREN; i++) {
            pid_t leaf = fork();
            if (leaf == 0) {
                close(exited[0]);
                _exit(72 + i);
            }
            if (leaf < 0)
                break;
            report.leaves[report.created++] = leaf;
        }
        close(exited[1]);
        char byte;
        ssize_t n;
        do {
            n = read(exited[0], &byte, 1);
        } while (n < 0 && errno == EINTR);
        close(exited[0]);
        report.exit_barrier_ok = n == 0;
        (void) write_full(meta[1], &report, sizeof(report));
        close(meta[1]);
        _exit(71);
    }

    close(meta[1]);
    struct zombie_report report;
    memset(&report, 0, sizeof(report));
    int meta_ok =
        middle > 0 && read_full(meta[0], &report, sizeof(report)) == 0;
    close(meta[0]);
    int middle_ok = middle > 0 && child_exited_cleanly(middle, 71);
    int reaped = 0;
    for (int i = 0; i < report.created; i++)
        if (report.leaves[i] > 0 &&
            child_exited_cleanly(report.leaves[i], 72 + i))
            reaped++;
    int clear_ok = prctl(PR_SET_CHILD_SUBREAPER, 0, 0, 0, 0) == 0;

    if (!meta_ok || report.created != ZOMBIE_CHILDREN ||
        !report.exit_barrier_ok || !middle_ok || reaped != ZOMBIE_CHILDREN ||
        !clear_ok) {
        printf(
            "[O-03 middle=%d created=%d/%d reaped=%d meta=%d barrier=%d "
            "middle_ok=%d clear=%d errno=%d] ",
            (int) middle, report.created, ZOMBIE_CHILDREN, reaped, meta_ok,
            report.exit_barrier_ok, middle_ok, clear_ok, errno);
        FAIL("subreaper did not inherit and reap exited child statuses");
        return;
    }
    PASS();
}

int main(void)
{
    printf("test-process-lifecycle: Linux process lifecycle semantics\n");

    test_nested_pid_uniqueness();
    test_wnohang_running_child();
    test_waitid_wnowait_repeat();
    test_waitid_pgid_matching();
    test_waitid_pgid_autoreap();
    test_delayed_zombie_reap();
    test_reverse_zombie_reap();
    test_zombie_table_pressure();
    test_no_zombie_disposition(0);
    test_no_zombie_disposition(1);
    test_sigchld_before_wait();
    test_orphan_reparent_to_init();
    test_orphan_reparent_to_subreaper();
    test_subreaper_adopts_zombie();

    SUMMARY("test-process-lifecycle");
    return fails == 0 ? 0 : 1;
}
