/* fd-family tests
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Verifies semantics of the eventfd/timerfd/signalfd family of
 * descriptors. The current coverage focuses on signalfd's promise
 * that an EFAULT during read leaves the pending signal queue intact
 * so a subsequent good-pointer read still observes the signal.
 * Future eventfd and timerfd primitive tests should land here.
 */

#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/signalfd.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#include "test-harness.h"

int passes = 0, fails = 0;

static void test_signalfd_efault_preserves_pending(void)
{
    TEST("signalfd EFAULT preserves pending signal");

    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGUSR1);
    sigprocmask(SIG_BLOCK, &mask, NULL);

    int fd = signalfd(-1, &mask, SFD_NONBLOCK);
    if (fd < 0) {
        FAIL("signalfd");
        return;
    }

    kill(getpid(), SIGUSR1);
    errno = 0;
    /* Deliberately bad pointer to verify the kernel reports EFAULT. */
    ssize_t bad = syscall(SYS_read, fd,
                          /* cppcheck-suppress intToPointerCast */
                          (void *) 1, sizeof(struct signalfd_siginfo));
    if (bad != -1 || errno != EFAULT) {
        close(fd);
        FAIL("expected EFAULT");
        return;
    }

    struct signalfd_siginfo info;
    memset(&info, 0, sizeof(info));
    ssize_t good = read(fd, &info, sizeof(info));
    close(fd);
    if (good == (ssize_t) sizeof(info) &&
        info.ssi_signo == (uint32_t) SIGUSR1) {
        PASS();
    } else {
        FAIL("signal was lost after EFAULT");
    }
}

int main(void)
{
    printf("fd-family tests:\n");

    test_signalfd_efault_preserves_pending();

    printf("\ntest-fd-family: %d passed, %d failed%s\n", passes, fails,
           fails == 0 ? " - PASS" : " - FAIL");
    return fails ? 1 : 0;
}
