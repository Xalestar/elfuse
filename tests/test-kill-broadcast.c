/*
 * Test kill(-1, sig) broadcast semantics
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Per kill(2): kill(-1, sig) delivers to every process the caller may signal
 * except init, and explicitly does NOT signal the calling process itself.
 * Verifies:
 * 1. kill(-1, sig) reaches a fork child.
 * 2. kill(-1, sig) does NOT signal the caller (Linux excludes self).
 * 3. A directed kill(getpid(), sig) still delivers to the caller, so the
 *    exclusion check above cannot pass merely because delivery is broken.
 *
 * SIGWINCH is the broadcast signal: it is ignored by default, so reaching
 * unrelated processes in a full system guest (init, getty) is harmless while
 * our processes install a handler to observe delivery.
 */

#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static volatile sig_atomic_t got_winch = 0;
static volatile sig_atomic_t got_usr1 = 0;

static void winch_handler(int sig)
{
    (void) sig;
    got_winch = 1;
}

static void usr1_handler(int sig)
{
    (void) sig;
    got_usr1 = 1;
}

/* Spin up to ~2 s waiting for a flag so slow HVC-forwarded delivery has time
 * to land without hanging the suite. */
static bool wait_flag(volatile sig_atomic_t *flag)
{
    for (int i = 0; i < 2000 && !*flag; i++) {
        struct timespec ts = {0, 1000000}; /* 1 ms */
        nanosleep(&ts, NULL);
    }
    return *flag != 0;
}

int main(void)
{
    int failed = 0;

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = winch_handler;
    sigaction(SIGWINCH, &sa, NULL);
    sa.sa_handler = usr1_handler;
    sigaction(SIGUSR1, &sa, NULL);

    /* Child re-installs the handler, then reports delivery via exit code. */
    int pipefd[2];
    if (pipe(pipefd) != 0) {
        perror("pipe");
        return 1;
    }
    pid_t child = fork();
    if (child == 0) {
        close(pipefd[0]);
        struct sigaction csa;
        memset(&csa, 0, sizeof(csa));
        csa.sa_handler = winch_handler;
        sigaction(SIGWINCH, &csa, NULL);
        char c = 'R';
        if (write(pipefd[1], &c, 1) != 1)
            _exit(2);
        _exit(wait_flag(&got_winch) ? 0 : 1);
    }
    if (child < 0) {
        perror("fork");
        return 1;
    }
    close(pipefd[1]);

    /* Wait for the child to arm its handler before broadcasting. */
    char c = 0;
    if (read(pipefd[0], &c, 1) != 1 || c != 'R') {
        fprintf(stderr, "child never signaled readiness\n");
        return 1;
    }
    close(pipefd[0]);

    /* 0: sig==0 broadcast probe succeeds while a signalable peer (the child)
     * exists. Only the positive case is asserted: the no-peers ESRCH result
     * would diverge from a full system guest where init is always signalable.
     */
    if (kill(-1, 0) != 0) {
        perror("kill(-1, 0) probe");
        failed++;
    }

    got_winch = 0;
    if (kill(-1, SIGWINCH) != 0) {
        perror("kill(-1)");
        failed++;
    }

    /* 1: broadcast reaches the child. */
    int status = 0;
    if (waitpid(child, &status, 0) != child) {
        perror("waitpid");
        failed++;
    } else if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        fprintf(stderr, "FAIL: kill(-1) did not reach the fork child\n");
        failed++;
    }

    /* 2: caller is excluded. Give any (incorrect) self-delivery time to land.
     */
    struct timespec settle = {0, 20000000}; /* 20 ms */
    nanosleep(&settle, NULL);
    if (got_winch) {
        fprintf(stderr, "FAIL: kill(-1) wrongly signaled the caller itself\n");
        failed++;
    }

    /* 3: directed self-signal still works. */
    got_usr1 = 0;
    if (kill(getpid(), SIGUSR1) != 0) {
        perror("kill(self)");
        failed++;
    }
    if (!wait_flag(&got_usr1)) {
        fprintf(stderr, "FAIL: kill(getpid()) did not deliver to the caller\n");
        failed++;
    }

    printf("%s: %d failed\n", failed == 0 ? "PASS" : "FAIL", failed);
    return failed == 0 ? 0 : 1;
}
