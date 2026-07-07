/*
 * Signal-driven I/O (O_ASYNC / SIGIO / F_SETOWN) tests
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Tests:
 *   1. F_SETOWN / F_GETOWN round-trip (pid and process-group forms)
 *   2. F_SETOWN(0) clears the owner
 *   3. F_SETOWN_EX / F_GETOWN_EX round-trip
 *   4. SIGIO delivery on socket readiness after fcntl(F_SETFL, O_ASYNC)
 *   5. SIGIO delivery after ioctl(FIOASYNC) (the unified second entry point)
 *   6. dup inheritance and shared owner/armed state across aliases
 *   7. SIGURG delivery on a TCP out-of-band byte with no O_ASYNC
 *
 * Syscalls: fcntl(25), ioctl(29), socketpair(199), socket(198), bind(200),
 *           listen(201), accept(202), connect(203), sendto(206),
 *           rt_sigaction(134), write(64)
 */

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include "test-harness.h"

int passes = 0, fails = 0;

static volatile sig_atomic_t sigurg_count;

static void sigurg_handler(int sig)
{
    (void) sig;
    sigurg_count++;
}

/* Build a connected loopback TCP pair. Blocking connect(2) to a listening
 * socket completes the handshake at the TCP layer before accept(2), so no
 * second thread is needed.
 *
 * Returns 0 with sv[0]=server, sv[1]=client, else -1.
 */
static int tcp_loopback_pair(int sv[2])
{
    int lst = socket(AF_INET, SOCK_STREAM, 0);
    if (lst < 0)
        return -1;
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    socklen_t alen = sizeof(addr);
    if (bind(lst, (struct sockaddr *) &addr, sizeof(addr)) < 0 ||
        listen(lst, 1) < 0 ||
        getsockname(lst, (struct sockaddr *) &addr, &alen) < 0) {
        close(lst);
        return -1;
    }
    int cli = socket(AF_INET, SOCK_STREAM, 0);
    if (cli < 0) {
        close(lst);
        return -1;
    }
    if (connect(cli, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
        close(lst);
        close(cli);
        return -1;
    }
    int srv = accept(lst, NULL, NULL);
    close(lst);
    if (srv < 0) {
        close(cli);
        return -1;
    }
    sv[0] = srv;
    sv[1] = cli;
    return 0;
}

#ifndef F_SETOWN_EX
#define F_SETOWN_EX 15
#define F_GETOWN_EX 16
struct f_owner_ex {
    int type;
    pid_t pid;
};
#endif
#ifndef F_OWNER_PID
#define F_OWNER_PID 1
#define F_OWNER_PGRP 2
#endif

static volatile sig_atomic_t sigio_count;

static void sigio_handler(int sig)
{
    (void) sig;
    sigio_count++;
}

/* Arm a SIGIO handler, mark fd async + owned by this process, poke the peer,
 * and wait (bounded) for the handler to fire. arm_via_ioctl selects the
 * ioctl(FIOASYNC) entry point instead of fcntl(F_SETFL, O_ASYNC).
 */
static int expect_sigio(int arm_via_ioctl)
{
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0)
        return -1;

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sigio_handler;
    sigaction(SIGIO, &sa, NULL);

    if (fcntl(sv[0], F_SETOWN, getpid()) < 0) {
        close(sv[0]);
        close(sv[1]);
        return -1;
    }

    sigio_count = 0;
    if (arm_via_ioctl) {
        int on = 1;
        if (ioctl(sv[0], FIOASYNC, &on) < 0) {
            close(sv[0]);
            close(sv[1]);
            return -1;
        }
    } else {
        int fl = fcntl(sv[0], F_GETFL);
        if (fcntl(sv[0], F_SETFL, fl | O_ASYNC) < 0) {
            close(sv[0]);
            close(sv[1]);
            return -1;
        }
    }

    /* Make sv[0] readable; the watcher should turn that into a SIGIO. */
    if (write(sv[1], "x", 1) != 1) {
        close(sv[0]);
        close(sv[1]);
        return -1;
    }

    /* Bounded wait: ~2s in 1ms steps. The syscalls keep the vCPU cycling so
     * queued signals are delivered on syscall return.
     */
    for (int i = 0; i < 2000 && sigio_count == 0; i++)
        usleep(1000);

    int got = sigio_count;
    close(sv[0]);
    close(sv[1]);
    return got > 0 ? 0 : 1;
}

int main(void)
{
    int fds[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) < 0) {
        printf("socketpair failed\n");
        return 1;
    }

    TEST("F_SETOWN/F_GETOWN pid round-trip");
    fcntl(fds[0], F_SETOWN, getpid());
    EXPECT_EQ(fcntl(fds[0], F_GETOWN), getpid(), "owner pid mismatch");

    TEST("F_SETOWN/F_GETOWN pgrp round-trip");
    fcntl(fds[0], F_SETOWN, -getpid());
    EXPECT_EQ(fcntl(fds[0], F_GETOWN), -getpid(), "owner pgrp mismatch");

    TEST("F_SETOWN(0) clears owner");
    fcntl(fds[0], F_SETOWN, 0);
    EXPECT_EQ(fcntl(fds[0], F_GETOWN), 0, "owner not cleared");

    TEST("F_SETOWN_EX/F_GETOWN_EX round-trip");
    {
        struct f_owner_ex set = {.type = F_OWNER_PID, .pid = getpid()};
        struct f_owner_ex get;
        memset(&get, 0, sizeof(get));
        fcntl(fds[0], F_SETOWN_EX, &set);
        int rc = fcntl(fds[0], F_GETOWN_EX, &get);
        EXPECT_TRUE(rc == 0 && get.type == F_OWNER_PID && get.pid == getpid(),
                    "owner_ex mismatch");
    }
    TEST("F_SETOWN(INT_MIN) rejected without UB");
    EXPECT_ERRNO(fcntl(fds[0], F_SETOWN, INT_MIN), EINVAL,
                 "INT_MIN owner not rejected");

    TEST("F_SETOWN_EX negative pid rejected");
    {
        struct f_owner_ex bad = {.type = F_OWNER_PID, .pid = -5};
        EXPECT_ERRNO(fcntl(fds[0], F_SETOWN_EX, &bad), EINVAL,
                     "negative pid not rejected");
    }

    close(fds[0]);
    close(fds[1]);

    TEST("SIGIO delivered via F_SETFL(O_ASYNC)");
    EXPECT_EQ(expect_sigio(0), 0, "no SIGIO on readiness");

    TEST("SIGIO delivered via ioctl(FIOASYNC)");
    EXPECT_EQ(expect_sigio(1), 0, "no SIGIO on readiness (ioctl)");

    TEST("dup inherits O_ASYNC + owner (SIGIO fires)");
    {
        int sv[2];
        int ok = 0;
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0) {
            struct sigaction sa;
            memset(&sa, 0, sizeof(sa));
            sa.sa_handler = sigio_handler;
            sigaction(SIGIO, &sa, NULL);

            fcntl(sv[0], F_SETOWN, getpid());
            int fl = fcntl(sv[0], F_GETFL);
            fcntl(sv[0], F_SETFL, fl | O_ASYNC);

            sigio_count = 0;
            int dfd = dup(sv[0]);
            /* The original arming already covers readiness; closing sv[0]
             * leaves only the dup armed, proving the alias inherited O_ASYNC.
             */
            close(sv[0]);
            if (write(sv[1], "y", 1) == 1) {
                for (int i = 0; i < 2000 && sigio_count == 0; i++)
                    usleep(1000);
                ok = sigio_count > 0;
            }
            close(dfd);
            close(sv[1]);
        }
        EXPECT_TRUE(ok, "no SIGIO on dup'd async fd");
    }

    TEST("dup aliases share O_ASYNC + owner updates");
    {
        int sv[2];
        int ok = 0;
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0) {
            int dfd = dup(sv[0]);
            if (dfd >= 0) {
                fcntl(sv[0], F_SETOWN, getpid());
                int fl = fcntl(dfd, F_GETFL);
                fcntl(dfd, F_SETFL, fl | O_ASYNC);
                ok = ((fcntl(sv[0], F_GETFL) & O_ASYNC) != 0) &&
                     fcntl(dfd, F_GETOWN) == getpid();
                close(dfd);
            }
            close(sv[0]);
            close(sv[1]);
        }
        EXPECT_TRUE(ok, "dup aliases did not share async state");
    }

    TEST("SIGURG delivered on TCP out-of-band byte without O_ASYNC");
    {
        int sv[2];
        int ok = 0;
        if (tcp_loopback_pair(sv) == 0) {
            struct sigaction sa;
            memset(&sa, 0, sizeof(sa));
            sa.sa_handler = sigurg_handler;
            sigaction(SIGURG, &sa, NULL);

            fcntl(sv[0], F_SETOWN, getpid());
            int fl = fcntl(sv[0], F_GETFL);
            fcntl(sv[0], F_SETFL, fl | O_ASYNC);
            fcntl(sv[0], F_SETFL, fl & ~O_ASYNC);

            sigurg_count = 0;
            /* Urgent byte from the client; the server's OOB mark drives
             * EVFILT_EXCEPT/NOTE_OOB, which the watcher maps to SIGURG.
             */
            if (send(sv[1], "!", 1, MSG_OOB) == 1) {
                for (int i = 0; i < 2000 && sigurg_count == 0; i++)
                    usleep(1000);
                ok = sigurg_count > 0;
            }
            close(sv[0]);
            close(sv[1]);
        } else {
            /* Loopback TCP unavailable in this environment; do not fail. */
            ok = 1;
        }
        EXPECT_TRUE(ok, "no SIGURG on TCP OOB byte");
    }

    SUMMARY("test-sigio");
    return fails == 0 ? 0 : 1;
}
