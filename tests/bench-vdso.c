/* vDSO fast-path microbenchmark
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Compares each elfuse vDSO trampoline against the equivalent raw SVC
 * for clock_gettime, clock_getres, gettimeofday, and getcpu. Reports
 * ns/op and the vDSO/SVC speedup ratio so the seqlock + DMB ISHLD
 * overhead introduced this cycle can be measured against the prior
 * baseline. Resolves symbol addresses by walking the vDSO ELF via
 * AT_SYSINFO_EHDR, the same path glibc uses, so the numbers reflect
 * what real workloads see.
 */

#include <elf.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include "raw-syscall.h"

#ifndef SYS_getcpu
#define SYS_getcpu 168
#endif

typedef int (*clock_gettime_fn)(clockid_t, struct timespec *);
typedef int (*clock_getres_fn)(clockid_t, struct timespec *);
typedef int (*gettimeofday_fn)(struct timeval *, void *);
typedef int (*getcpu_fn)(unsigned *, unsigned *, void *);

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

static const Elf64_Sym *lookup_sym(const Elf64_Sym *symtab,
                                   const char *strtab,
                                   const uint32_t *hash,
                                   const char *name)
{
    uint32_t nbucket = hash[0];
    uint32_t nchain = hash[1];
    const uint32_t *bucket = &hash[2];
    const uint32_t *chain = &bucket[nbucket];
    uint32_t h = sysv_hash(name) % nbucket;
    for (uint32_t i = bucket[h]; i && i < nchain; i = chain[i]) {
        if (strcmp(&strtab[symtab[i].st_name], name) == 0)
            return &symtab[i];
    }
    return NULL;
}

static uint64_t monotonic_ns(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        perror("clock_gettime");
        exit(1);
    }
    return (uint64_t) ts.tv_sec * 1000000000ULL + (uint64_t) ts.tv_nsec;
}

typedef long (*bench_fn_t)(void *ctx);

static double time_loop(bench_fn_t fn, void *ctx, unsigned long iters)
{
    /* Warm-up: ensure the vDSO anchor is seeded so the first loop
     * iteration is not artificially slow.
     */
    for (unsigned long i = 0; i < 1000; i++)
        (void) fn(ctx);

    uint64_t t0 = monotonic_ns();
    for (unsigned long i = 0; i < iters; i++)
        (void) fn(ctx);
    uint64_t elapsed = monotonic_ns() - t0;
    return (double) elapsed / (double) iters;
}

typedef struct {
    clock_gettime_fn fn;
    clockid_t id;
    struct timespec ts;
} cg_ctx_t;

static long bench_cg_vdso(void *p)
{
    cg_ctx_t *c = p;
    return c->fn(c->id, &c->ts);
}

static long bench_cg_svc(void *p)
{
    cg_ctx_t *c = p;
    return raw_syscall2(__NR_clock_gettime, c->id, (long) &c->ts);
}

typedef struct {
    clock_getres_fn fn;
    clockid_t id;
    struct timespec ts;
} gr_ctx_t;

static long bench_gr_vdso(void *p)
{
    gr_ctx_t *c = p;
    return c->fn(c->id, &c->ts);
}

static long bench_gr_svc(void *p)
{
    gr_ctx_t *c = p;
    return raw_syscall2(__NR_clock_getres, c->id, (long) &c->ts);
}

typedef struct {
    gettimeofday_fn fn;
    struct timeval tv;
} tod_ctx_t;

static long bench_tod_vdso(void *p)
{
    tod_ctx_t *c = p;
    return c->fn(&c->tv, NULL);
}

static long bench_tod_svc(void *p)
{
    tod_ctx_t *c = p;
    return raw_syscall2(__NR_gettimeofday, (long) &c->tv, 0);
}

typedef struct {
    getcpu_fn fn;
    unsigned cpu, node;
} cpu_ctx_t;

static long bench_cpu_vdso(void *p)
{
    cpu_ctx_t *c = p;
    return c->fn(&c->cpu, &c->node, NULL);
}

static long bench_cpu_svc(void *p)
{
    cpu_ctx_t *c = p;
    return raw_syscall3(SYS_getcpu, (long) &c->cpu, (long) &c->node, 0);
}

static void report(const char *label, double svc_ns, double vdso_ns)
{
    double speedup = svc_ns / vdso_ns;
    printf("  %-32s svc=%8.1f ns  vdso=%8.1f ns  speedup=%6.1fx\n", label,
           svc_ns, vdso_ns, speedup);
}

int main(int argc, char **argv)
{
    unsigned long iters = 200000;
    if (argc > 1)
        iters = strtoul(argv[1], NULL, 10);
    if (iters == 0) {
        fprintf(stderr, "iterations must be > 0\n");
        return 1;
    }

    unsigned long base = getauxval(AT_SYSINFO_EHDR);
    if (!base) {
        fprintf(stderr, "AT_SYSINFO_EHDR not set; no vDSO to benchmark\n");
        return 1;
    }

    /* Resolve vDSO trampolines via the same dynsym + ELF hash path glibc
     * uses. The trampolines are inside the 4 KiB page at AT_SYSINFO_EHDR.
     */
    const Elf64_Ehdr *ehdr = (const Elf64_Ehdr *) base;
    const Elf64_Phdr *phdr =
        (const Elf64_Phdr *) ((const uint8_t *) ehdr + ehdr->e_phoff);
    const Elf64_Dyn *dyn = NULL;
    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type == PT_DYNAMIC) {
            dyn =
                (const Elf64_Dyn *) ((const uint8_t *) ehdr + phdr[i].p_offset);
            break;
        }
    }
    if (!dyn) {
        fprintf(stderr, "vDSO has no PT_DYNAMIC\n");
        return 1;
    }
    const Elf64_Sym *symtab = NULL;
    const char *strtab = NULL;
    const uint32_t *hash = NULL;
    for (const Elf64_Dyn *d = dyn; d->d_tag != DT_NULL; d++) {
        const uint8_t *p = (const uint8_t *) ehdr + d->d_un.d_ptr;
        if (d->d_tag == DT_SYMTAB)
            symtab = (const Elf64_Sym *) p;
        else if (d->d_tag == DT_STRTAB)
            strtab = (const char *) p;
        else if (d->d_tag == DT_HASH)
            hash = (const uint32_t *) p;
    }
    if (!symtab || !strtab || !hash) {
        fprintf(stderr, "vDSO dynamic table incomplete\n");
        return 1;
    }

    const Elf64_Sym *s_cg =
        lookup_sym(symtab, strtab, hash, "__kernel_clock_gettime");
    const Elf64_Sym *s_gr =
        lookup_sym(symtab, strtab, hash, "__kernel_clock_getres");
    const Elf64_Sym *s_tod =
        lookup_sym(symtab, strtab, hash, "__kernel_gettimeofday");
    const Elf64_Sym *s_cpu =
        lookup_sym(symtab, strtab, hash, "__kernel_getcpu");

    if (!s_cg || !s_gr || !s_tod || !s_cpu) {
        fprintf(stderr, "missing vDSO symbol(s)\n");
        return 1;
    }

    printf("bench-vdso: %lu iterations per case\n", iters);
    printf("AT_SYSINFO_EHDR = 0x%lx\n", base);

    {
        cg_ctx_t ctx_mono = {
            .fn = (clock_gettime_fn) (uintptr_t) (base + s_cg->st_value),
            .id = CLOCK_MONOTONIC,
        };
        double svc = time_loop(bench_cg_svc, &ctx_mono, iters);
        double vd = time_loop(bench_cg_vdso, &ctx_mono, iters);
        report("clock_gettime(MONOTONIC)", svc, vd);
    }
    {
        cg_ctx_t ctx_real = {
            .fn = (clock_gettime_fn) (uintptr_t) (base + s_cg->st_value),
            .id = CLOCK_REALTIME,
        };
        double svc = time_loop(bench_cg_svc, &ctx_real, iters);
        double vd = time_loop(bench_cg_vdso, &ctx_real, iters);
        report("clock_gettime(REALTIME)", svc, vd);
    }
    {
        gr_ctx_t ctx = {
            .fn = (clock_getres_fn) (uintptr_t) (base + s_gr->st_value),
            .id = CLOCK_MONOTONIC,
        };
        double svc = time_loop(bench_gr_svc, &ctx, iters);
        double vd = time_loop(bench_gr_vdso, &ctx, iters);
        report("clock_getres(MONOTONIC)", svc, vd);
    }
    {
        tod_ctx_t ctx = {
            .fn = (gettimeofday_fn) (uintptr_t) (base + s_tod->st_value),
        };
        double svc = time_loop(bench_tod_svc, &ctx, iters);
        double vd = time_loop(bench_tod_vdso, &ctx, iters);
        report("gettimeofday", svc, vd);
    }
    {
        cpu_ctx_t ctx = {
            .fn = (getcpu_fn) (uintptr_t) (base + s_cpu->st_value),
        };
        double svc = time_loop(bench_cpu_svc, &ctx, iters);
        double vd = time_loop(bench_cpu_vdso, &ctx, iters);
        report("getcpu", svc, vd);
    }

    return 0;
}
