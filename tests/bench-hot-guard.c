/* Hot-syscall guardrail bench
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Minimal bench that measures the three labels the guardrail script
 * checks against the TODO ceilings:
 *
 *   getpid          (raw SVC; shim identity fast path)
 *   clock_gettime   (vDSO trampoline; see -DGUARD_USE_LIBC_CG below)
 *   read-urandom1   (raw read; shim urandom ring fast path)
 *
 * Built twice from this single source:
 *   build/bench-hot-guard       -- static glibc. Compiled without
 *       -DGUARD_USE_LIBC_CG: `clock_gettime` calls the vDSO trampoline
 *       directly via its function-pointer address resolved through
 *       AT_SYSINFO_EHDR. Static glibc never initializes
 *       dl_sysinfo_dso, so its libc clock_gettime wrapper falls back
 *       to raw SVC (~2000 ns/op) regardless of trampoline health --
 *       measuring it would fail the 50 ns ceiling for reasons that
 *       have nothing to do with the vDSO. Direct call isolates the
 *       trampoline.
 *   build/bench-hot-guard-glibc -- dynamic glibc. Compiled with
 *       -DGUARD_USE_LIBC_CG so `clock_gettime` invokes the libc
 *       wrapper, which on glibc 2.41 + a correctly-stamped vDSO
 *       (NT_GNU_ABI_TAG present, LINUX_2.6.39 versioning) routes the
 *       call through the same trampoline. The guardrail's 50 ns
 *       ceiling here is exactly the "did glibc accept the vDSO?"
 *       regression check called out in the TODO baseline: if the
 *       PT_NOTE or versioning regresses, this measurement jumps to
 *       SVC time and the guardrail fails. The cross-toolchain sysroot
 *       must be passed via --sysroot at runtime.
 *
 * Output format mirrors bench-hot-syscalls.c:
 *
 *   name<padding> XX.X ns/op  last=N
 *
 * so the guardrail's awk extractor reads identical labels across both
 * variants.
 */

#include <elf.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

typedef int (*clock_gettime_fn)(clockid_t, struct timespec *);

typedef long (*bench_fn_t)(void *ctx);

typedef struct {
    const char *name;
    bench_fn_t fn;
    void *ctx;
} bench_case_t;

typedef struct {
    clock_gettime_fn fn;
    struct timespec ts;
} cg_ctx_t;

static uint32_t sysv_hash(const char *name)
{
    uint32_t h = 0, g;
    while (*name) {
        h = (h << 4) + (unsigned char) *name++;
        g = h & 0xf0000000U;
        if (g)
            h ^= g >> 24;
        h &= ~g;
    }
    return h;
}

/* Walk the vDSO ELF at AT_SYSINFO_EHDR and return the absolute address
 * of __kernel_clock_gettime, or NULL if anything is missing.
 */
static clock_gettime_fn resolve_vdso_clock_gettime(void)
{
    unsigned long base = getauxval(AT_SYSINFO_EHDR);
    if (!base)
        return NULL;

    const Elf64_Ehdr *eh = (const Elf64_Ehdr *) base;
    const Elf64_Phdr *ph =
        (const Elf64_Phdr *) ((const uint8_t *) eh + eh->e_phoff);
    const Elf64_Dyn *dyn = NULL;
    for (int i = 0; i < eh->e_phnum; i++) {
        if (ph[i].p_type == PT_DYNAMIC) {
            dyn = (const Elf64_Dyn *) ((const uint8_t *) eh + ph[i].p_offset);
            break;
        }
    }
    if (!dyn)
        return NULL;

    const Elf64_Sym *st = NULL;
    const char *str = NULL;
    const uint32_t *hsh = NULL;
    for (; dyn->d_tag; dyn++) {
        const uint8_t *p = (const uint8_t *) eh + dyn->d_un.d_ptr;
        switch (dyn->d_tag) {
        case DT_SYMTAB:
            st = (const Elf64_Sym *) p;
            break;
        case DT_STRTAB:
            str = (const char *) p;
            break;
        case DT_HASH:
            hsh = (const uint32_t *) p;
            break;
        default:
            break;
        }
    }
    if (!st || !str || !hsh)
        return NULL;

    uint32_t nbucket = hsh[0];
    uint32_t nchain = hsh[1];
    const uint32_t *bucket = &hsh[2];
    const uint32_t *chain = &bucket[nbucket];
    const char *name = "__kernel_clock_gettime";
    uint32_t h = sysv_hash(name) % nbucket;
    for (uint32_t i = bucket[h]; i && i < nchain; i = chain[i]) {
        if (strcmp(&str[st[i].st_name], name) == 0)
            return (clock_gettime_fn) (base + st[i].st_value);
    }
    return NULL;
}

static uint64_t monotonic_ns(clock_gettime_fn cg)
{
    struct timespec ts;
    if (cg(CLOCK_MONOTONIC, &ts) != 0) {
        perror("clock_gettime");
        exit(1);
    }
    return (uint64_t) ts.tv_sec * 1000000000ULL + (uint64_t) ts.tv_nsec;
}

static long bench_getpid(void *ctx)
{
    (void) ctx;
    return (long) syscall(SYS_getpid);
}

static long bench_clock_gettime(void *ctx)
{
    cg_ctx_t *c = ctx;
#ifdef GUARD_USE_LIBC_CG
    /* Dynamic glibc build: exercise the libc wrapper so the
     * NT_GNU_ABI_TAG / LINUX_2.6.39 vDSO routing is validated end to
     * end. If glibc falls back to SVC (broken note / version regress)
     * this measurement jumps to ~2000 ns and the guardrail fails.
     */
    (void) c->fn;
    return clock_gettime(CLOCK_MONOTONIC, &c->ts);
#else
    /* Static build (no dl_sysinfo_dso): call the trampoline directly
     * via the resolved function pointer.
     */
    return c->fn(CLOCK_MONOTONIC, &c->ts);
#endif
}

static long bench_read_urandom1(void *ctx)
{
    int fd = *(int *) ctx;
    unsigned char byte;
    return read(fd, &byte, 1);
}

static void run_case(clock_gettime_fn cg,
                     const bench_case_t *bc,
                     unsigned long iters)
{
    uint64_t start = monotonic_ns(cg);
    long last = 0;
    for (unsigned long i = 0; i < iters; i++)
        last = bc->fn(bc->ctx);
    uint64_t elapsed = monotonic_ns(cg) - start;
    double ns_per_op = (double) elapsed / (double) iters;
    printf("%-20s %10.1f ns/op  last=%ld\n", bc->name, ns_per_op, last);
}

int main(int argc, char **argv)
{
    /* Line-buffered stdout so each completed case is visible
     * immediately when stdout is piped or captured.
     */
    setvbuf(stdout, NULL, _IOLBF, 0);

    unsigned long iters = 50000;
    if (argc > 1)
        iters = strtoul(argv[1], NULL, 10);
    if (iters == 0) {
        fprintf(stderr, "iterations must be > 0\n");
        return 1;
    }

    clock_gettime_fn vdso_cg = resolve_vdso_clock_gettime();
    if (!vdso_cg) {
        fprintf(stderr,
                "could not resolve __kernel_clock_gettime via "
                "AT_SYSINFO_EHDR\n");
        return 1;
    }

    int urandomfd = open("/dev/urandom", O_RDONLY);
    if (urandomfd < 0) {
        perror("open /dev/urandom");
        return 1;
    }

    cg_ctx_t cg_ctx = {.fn = vdso_cg};
    const bench_case_t cases[] = {
        {"getpid", bench_getpid, NULL},
        {"clock_gettime", bench_clock_gettime, &cg_ctx},
        {"read-urandom1", bench_read_urandom1, &urandomfd},
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
        run_case(vdso_cg, &cases[i], iters);

    close(urandomfd);
    return 0;
}
