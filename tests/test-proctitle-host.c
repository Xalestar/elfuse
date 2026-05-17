/* Host-side regression for runtime_set_process_title.
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * This is a native macOS test (not a guest ELF). It deterministically
 * catches two distinct regression classes against the proctitle fix:
 *
 *   (a) any overshoot past the contiguous argv block in the current
 *       implementation. The argv strings are laid out so their NUL
 *       terminator sits at the last writable byte of a page, with the
 *       next page mapped PROT_NONE. The volatile bytewise loop cannot
 *       step into the guard; an optimizing compiler that folds it into
 *       a libc memset emitting cache-line-aligned stp/DC ZVA overshoot
 *       on Apple Silicon would trip the guard.
 *
 *   (b) reverts to the pre-fix "argv+envp" upper-bound walk. The old
 *       code computed avail = max_end(argv, environ) - argv[0] and
 *       memset across that span. The test overrides the process-global
 *       environ to point at a sentinel string mmapped immediately above
 *       the PROT_NONE guard page; any reverted walk that consults
 *       environ produces an avail spanning the guard and SIGSEGVs.
 *       Without this override the test's catch on reverted code is
 *       non-deterministic because environ's address vs the test's
 *       anonymous mmap is unconstrained.
 */

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "runtime/proctitle.h"

static void on_sigsegv(int sig)
{
    (void) sig;
    /* Cannot rely on stdio inside an async signal handler, but a single
     * _exit with a recognizable code is sufficient: the run target prints
     * a meaningful failure when the child exits with 139.
     */
    _exit(139);
}

int main(void)
{
    struct sigaction sa = {0};
    sa.sa_handler = on_sigsegv;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESETHAND;
    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGBUS, &sa, NULL);

    long pgsz = sysconf(_SC_PAGESIZE);
    if (pgsz <= 0) {
        fprintf(stderr, "test-proctitle-host: sysconf(_SC_PAGESIZE) failed\n");
        return 1;
    }

    size_t page = (size_t) pgsz;
    /* Layout: [page 0: writable argv] [page 1: PROT_NONE guard]
     *         [page 2: writable envp sentinel]
     * A reverted argv+envp walk that consults environ computes an
     * avail spanning all three pages and memsets through the guard.
     */
    size_t map_size = page * 3;
    char *base = (char *) mmap(NULL, map_size, PROT_READ | PROT_WRITE,
                               MAP_PRIVATE | MAP_ANON, -1, 0);
    if (base == MAP_FAILED) {
        perror("test-proctitle-host: mmap");
        return 1;
    }
    if (mprotect(base + page, page, PROT_NONE) < 0) {
        perror("test-proctitle-host: mprotect");
        return 1;
    }

    /* Synthesize a contiguous argv block whose tail aligns with the
     * boundary, mimicking the host kernel placing argv at the top of the
     * initial stack. Total length is chosen so the bin field after the
     * last "/" character ("busybox") drives the rewritten title past the
     * pre-existing argv[0] string length, exercising the truncation
     * branch as well as the simple-copy branch on the next argv entry.
     */
    static const char *parts[] = {
        "elfuse",
        "/path/to/busybox",
        "echo",
        "hello",
    };
    const int nparts = (int) (sizeof(parts) / sizeof(parts[0]));

    size_t total = 0;
    for (int i = 0; i < nparts; i++)
        total += strlen(parts[i]) + 1;
    if (total > page) {
        fprintf(stderr,
                "test-proctitle-host: synthetic argv exceeds one page\n");
        return 1;
    }

    char *start = base + page - total;
    char *cursor = start;
    char *argv[5];
    for (int i = 0; i < nparts; i++) {
        argv[i] = cursor;
        size_t n = strlen(parts[i]) + 1;
        memcpy(cursor, parts[i], n);
        cursor += n;
    }
    argv[nparts] = NULL;

    if (cursor != base + page) {
        fprintf(stderr,
                "test-proctitle-host: layout did not reach the guard\n");
        return 1;
    }

    /* Plant a sentinel envp string above the guard so the reverted
     * argv+envp upper-bound walk computes avail spanning the guard.
     */
    char *envp_str = base + page * 2;
    static const char sentinel[] = "ELFUSE_PROCTITLE_TEST_SENTINEL=1";
    memcpy(envp_str, sentinel, sizeof(sentinel));
    char *synthetic_environ[] = {envp_str, NULL};
    extern char **environ;
    char **saved_environ = environ;
    environ = synthetic_environ;

    /* Any write past argv[0]+avail-1 (page boundary) trips the guard. */
    runtime_set_process_title(nparts, argv, "/path/to/busybox");

    environ = saved_environ;

    /* Tail byte must be NUL, the prefix must form a non-empty C string,
     * and the rewritten title must not have escaped the argv span (the
     * byte after the block tail is unreadable, so verifying the tail
     * byte alone is the strongest check available).
     */
    if (start[total - 1] != '\0') {
        fprintf(stderr, "test-proctitle-host: tail byte was not zeroed\n");
        return 1;
    }
    if (strnlen(start, total) == 0) {
        fprintf(stderr, "test-proctitle-host: argv[0] left empty\n");
        return 1;
    }

    printf("test-proctitle-host: PASS\n");
    return 0;
}
