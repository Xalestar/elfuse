/* Multi-threaded epoll registration regression test
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Regression for the epoll_ctl host-fd-reference bug: in a multi-threaded
 * guest, host_fd_ref_open() hands back a *dup* of the target fd that is
 * closed when the syscall returns. sys_epoll_ctl() used that transient dup
 * as the kqueue knote ident, so the kernel dropped the registration the
 * moment epoll_ctl() returned -- and epoll_pwait() never reported readiness
 * again. Single-threaded guests borrow the raw fd (no dup, no close) and so
 * never hit it; this only reproduces with at least one CLONE_THREAD sibling
 * active. Node's libuv DelayedTaskScheduler relied on exactly this path
 * (eventfd + epoll for uv_async_send) and hung forever at process exit.
 *
 * The test keeps a sibling thread alive across the epoll_ctl() call, then
 * checks that both a pipe and an eventfd registered while multi-threaded
 * still deliver an EPOLLIN edge.
 *
 * Syscalls exercised: clone(220), epoll_create1(20), epoll_ctl(21),
 *                     epoll_pwait(22), eventfd2(19), pipe2(59), write(64),
 *                     read(63), close(57), futex(98), exit(93)
 */

#include <stdint.h>
#include <errno.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>

#include "test-harness.h"
#include "raw-syscall.h"

int passes = 0, fails = 0;

static volatile int child_should_exit = 0;
static char sibling_stack[16384] __attribute__((aligned(16)));

/* Sibling thread: stays alive (raw nanosleep loop) so the guest is
 * multi-threaded for the duration of the parent's epoll_ctl() calls, then
 * exits via the raw exit syscall. Uses only raw syscalls because a
 * clone(CLONE_THREAD) child has no libc TLS set up.
 */
static int sibling_fn(void *arg)
{
    (void) arg;
    struct {
        long tv_sec, tv_nsec;
    } ts = {0, 5000000}; /* 5ms */
    while (!child_should_exit)
        raw_syscall2(__NR_nanosleep, (long) &ts, 0);
    raw_syscall1(__NR_exit, 0);
    return 0;
}

/* Register host_fd for EPOLLIN on epfd, make it readable via make_ready(),
 * and assert epoll_pwait() observes the edge within the timeout. Returns 1
 * on success. */
static int expect_ready_edge(int epfd, int fd, void (*make_ready)(int), int arg)
{
    struct epoll_event ev = {.events = EPOLLIN, .data.fd = fd};
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev) < 0)
        return 0;

    make_ready(arg);

    struct epoll_event out[4];
    /* 2s budget: the bug manifests as an indefinite miss, so any generous
     * finite timeout distinguishes pass from fail without flaking. */
    int n = epoll_wait(epfd, out, 4, 2000);
    return n == 1 && out[0].data.fd == fd;
}

static void poke_eventfd(int fd)
{
    uint64_t one = 1;
    (void) !write(fd, &one, sizeof(one));
}

static int g_pipe_wr;
static void poke_pipe(int unused)
{
    (void) unused;
    (void) !write(g_pipe_wr, "x", 1);
}

int main(void)
{
    printf("test-epoll-mt: epoll registration under CLONE_THREAD\n");

    /* Spawn a CLONE_THREAD sibling so host_fd_ref_open() takes the dup path.
     * Flags: CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_THREAD|
     *        CLONE_CHILD_CLEARTID.
     */
    long flags = 0x00000100 | 0x00000200 | 0x00000400 | 0x00000800 |
                 0x00010000 | 0x00200000;
    volatile uint32_t child_tid = 1;
    long ret = raw_syscall5(__NR_clone, flags,
                            (long) (sibling_stack + sizeof(sibling_stack)), 0,
                            0, (long) &child_tid);
    if (ret == 0) {
        sibling_fn(NULL);
        return 0; /* unreachable: sibling_fn exits the thread */
    }

    TEST("clone sibling for multi-threaded context");
    EXPECT_TRUE(ret > 0, "clone failed");

    /* eventfd registered + signalled while multi-threaded (the Node path). */
    TEST("MT epoll: eventfd EPOLLIN edge delivered");
    {
        int epfd = epoll_create1(EPOLL_CLOEXEC);
        int efd = eventfd(0, EFD_NONBLOCK);
        EXPECT_TRUE(epfd >= 0 && efd >= 0, "epoll/eventfd create failed");
        EXPECT_TRUE(expect_ready_edge(epfd, efd, poke_eventfd, efd),
                    "eventfd registration lost across epoll_ctl");
        close(efd);
        close(epfd);
    }

    /* Same with a pipe read end, to show the fix is fd-type independent. */
    TEST("MT epoll: pipe EPOLLIN edge delivered");
    {
        int epfd = epoll_create1(EPOLL_CLOEXEC);
        int pipefd[2];
        EXPECT_TRUE(epfd >= 0 && pipe(pipefd) == 0, "epoll/pipe create failed");
        g_pipe_wr = pipefd[1];
        EXPECT_TRUE(expect_ready_edge(epfd, pipefd[0], poke_pipe, 0),
                    "pipe registration lost across epoll_ctl");
        close(pipefd[0]);
        close(pipefd[1]);
        close(epfd);
    }

    /* Release the sibling and join via the CLONE_CHILD_CLEARTID futex. */
    child_should_exit = 1;
    for (int i = 0; i < 200 && child_tid != 0; i++) {
        struct {
            long tv_sec, tv_nsec;
        } ts = {0, 10000000}; /* 10ms */
        raw_syscall6(__NR_futex, (long) &child_tid, 0 /* FUTEX_WAIT */,
                     child_tid, (long) &ts, 0, 0);
    }

    SUMMARY("test-epoll-mt");
    return fails > 0 ? 1 : 0;
}
