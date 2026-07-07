/*
 * epoll instance lifetime stress: close(epfd) racing a sibling's epoll_pwait
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Guards the epoll-instance reference count in src/syscall/poll.c. An epoll
 * instance (epoll_instance_t) is heap-allocated and reachable only through
 * fd_table[epfd].dir. sys_epoll_ctl / sys_epoll_pwait read that pointer and
 * walk inst->regs[] for the whole call -- including across the blocking
 * kevent() in pwait. host_fd_ref_open() only pins the host kqueue fd, not the
 * instance, so without a lifetime pin a sibling thread that close()es epfd
 * frees the instance out from under an in-flight call (use-after-free).
 *
 * epoll_instance_acquire()/_release() bump a refcount under fd_lock so the
 * allocation survives until the last in-flight caller releases it, even after
 * close() drops the fd-table's reference.
 *
 * This test hammers that window: a long-lived sibling spins epoll_pwait() on a
 * shared epfd while the main thread repeatedly creates an epoll instance,
 * publishes it to the sibling, and close()es it -- so a close lands while the
 * sibling is inside pwait on the same fd. Racing close() with epoll ops on the
 * same fd is guest-undefined, so the sibling's return value is not asserted;
 * the contract under test is that elfuse never faults or double-frees. Survival
 * across all iterations with a clean exit is the pass condition.
 *
 * Raw syscalls in the sibling (a CLONE_THREAD child has no libc TLS).
 *
 * Syscalls exercised: clone(220), epoll_create1(20), epoll_ctl(21),
 *                     epoll_pwait(22), eventfd2(19), close(57), nanosleep(101),
 *                     futex(98), exit(93)
 */

#include <errno.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>

#include "test-harness.h"
#include "raw-syscall.h"

int passes = 0, fails = 0;

/* Shared with the clone sibling; atomic because both threads touch them. */
static _Atomic int shared_epfd = -1;
static _Atomic int sibling_stop = 0;
static char sibling_stack[32768] __attribute__((aligned(16)));

/* Spin epoll_pwait() on whatever epfd the main thread has published. The fd may
 * be closed (or reused) concurrently; a raw syscall just returns an error,
 * which is exactly the window the refcount must make memory-safe.
 */
static int sibling_fn(void *arg)
{
    (void) arg;
    while (!sibling_stop) {
        int e = shared_epfd;
        if (e >= 0) {
            struct epoll_event evs[4];
            /* epoll_pwait(epfd, events, maxevents, timeout_ms, sigmask,
             * sigsetsize); 5ms timeout keeps the spin tight against close(). */
            raw_syscall6(__NR_epoll_pwait, (long) e, (long) evs, 4, 5, 0, 0);
        } else {
            struct {
                long tv_sec, tv_nsec;
            } ts = {0, 200000}; /* 0.2ms */
            raw_syscall2(__NR_nanosleep, (long) &ts, 0);
        }
    }
    raw_syscall1(__NR_exit, 0);
    return 0;
}

int main(void)
{
    printf("test-epoll-refcount: close(epfd) vs concurrent epoll_pwait\n");

    long flags = 0x00000100 | 0x00000200 | 0x00000400 | 0x00000800 |
                 0x00010000 | 0x00200000; /* CLONE_VM|FS|FILES|SIGHAND|THREAD|
                                             CHILD_CLEARTID */
    volatile uint32_t child_tid = 1;
    long ret = raw_syscall5(__NR_clone, flags,
                            (long) (sibling_stack + sizeof(sibling_stack)), 0,
                            0, (long) &child_tid);
    if (ret == 0) {
        sibling_fn(NULL);
        return 0; /* unreachable */
    }

    TEST("clone sibling waiter");
    EXPECT_TRUE(ret > 0, "clone failed");

    const int iterations = 300;
    int completed = 0;
    for (int i = 0; i < iterations; i++) {
        int epfd = epoll_create1(EPOLL_CLOEXEC);
        if (epfd < 0)
            break;
        int efd = eventfd(0, EFD_NONBLOCK);
        if (efd >= 0) {
            struct epoll_event ev = {.events = EPOLLIN, .data.fd = efd};
            epoll_ctl(epfd, EPOLL_CTL_ADD, efd, &ev);
        }

        /* Publish to the sibling and give it a moment to enter pwait(epfd). */
        shared_epfd = epfd;
        struct {
            long tv_sec, tv_nsec;
        } ts = {0, 500000}; /* 0.5ms */
        raw_syscall2(__NR_nanosleep, (long) &ts, 0);

        /* Mutate the same regs[] entry the sibling's pwait is reading, so the
         * per-instance lock (not just the refcount) is exercised.
         */
        if (efd >= 0) {
            struct epoll_event mev = {.events = EPOLLIN | EPOLLOUT,
                                      .data.fd = efd};
            epoll_ctl(epfd, EPOLL_CTL_MOD, efd, &mev);
        }

        /* Retract, then close under the sibling's in-flight pwait. Closing efd
         * first fires the close hook (epoll_note_fd_closed) on the instance the
         * sibling is still waiting on. */
        shared_epfd = -1;
        if (efd >= 0)
            close(efd);
        close(epfd);
        completed++;
    }

    TEST("all iterations survived close/pwait race");
    EXPECT_EQ(completed, iterations, "did not complete every iteration");

    /* A fresh epoll instance still works after the churn (no leaked/corrupt
     * state, refcount returned to a clean baseline).
     */
    TEST("epoll still functional after churn");
    {
        int epfd = epoll_create1(EPOLL_CLOEXEC);
        int efd = eventfd(0, EFD_NONBLOCK);
        struct epoll_event ev = {.events = EPOLLIN, .data.fd = efd};
        uint64_t one = 1;
        struct epoll_event out[4];
        int ok = epfd >= 0 && efd >= 0 &&
                 epoll_ctl(epfd, EPOLL_CTL_ADD, efd, &ev) == 0 &&
                 write(efd, &one, sizeof(one)) == (ssize_t) sizeof(one) &&
                 epoll_wait(epfd, out, 4, 2000) == 1 && out[0].data.fd == efd;
        EXPECT_TRUE(ok, "epoll broken after stress");
        if (epfd >= 0)
            close(epfd);
        if (efd >= 0)
            close(efd);
    }

    /* Release the sibling and join via the CLONE_CHILD_CLEARTID futex. */
    sibling_stop = 1;
    for (int i = 0; i < 200 && child_tid != 0; i++) {
        struct {
            long tv_sec, tv_nsec;
        } ts = {0, 10000000}; /* 10ms */
        raw_syscall6(__NR_futex, (long) &child_tid, 0 /* FUTEX_WAIT */,
                     child_tid, (long) &ts, 0, 0);
    }

    SUMMARY("test-epoll-refcount");
    return fails > 0 ? 1 : 0;
}
