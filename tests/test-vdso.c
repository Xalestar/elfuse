/* test-vdso.c -- vDSO ELF correctness and symbol-resolution probe
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Confirms the synthetic vDSO emitted by src/core/vdso.c:
 *   1. is published via AT_SYSINFO_EHDR
 *   2. parses as a valid ELF shared object
 *   3. exports the four __kernel_* symbols at addresses inside the page
 *   4. carries GNU symbol versioning naming LINUX_2.6.39 so glibc/musl
 *      dl_vdso_vsym() can resolve unversioned lookups
 *   5. trampolines actually execute (call __kernel_clock_gettime and
 *      compare the result against a direct SVC clock_gettime)
 *
 * Static binary so the standard test driver runs it under elfuse with
 * no sysroot. The probe walks the vDSO's dynamic linker structure
 * itself rather than relying on dlsym (which is unavailable in static
 * builds anyway), so a regression in the elf layout fails this test
 * regardless of which libc would later consume it.
 */

#include <elf.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

static int failures = 0;

#define FAIL(msg)                           \
    do {                                    \
        fprintf(stderr, "FAIL: %s\n", msg); \
        failures++;                         \
    } while (0)

#define EXPECT(cond, msg) \
    do {                  \
        if (!(cond))      \
            FAIL(msg);    \
    } while (0)

/* SysV ELF hash, matches the implementation in src/core/vdso.c. */
static uint32_t elf_hash(const char *name)
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

static const Elf64_Sym *lookup_sym(const Elf64_Ehdr *ehdr,
                                   const Elf64_Sym *symtab,
                                   const char *strtab,
                                   const uint32_t *hash,
                                   const char *name)
{
    uint32_t nbucket = hash[0];
    uint32_t nchain = hash[1];
    const uint32_t *bucket = &hash[2];
    const uint32_t *chain = &bucket[nbucket];
    uint32_t h = elf_hash(name) % nbucket;
    for (uint32_t i = bucket[h]; i && i < nchain; i = chain[i]) {
        if (strcmp(&strtab[symtab[i].st_name], name) == 0)
            return &symtab[i];
    }
    (void) ehdr;
    return NULL;
}

typedef struct {
    const Elf64_Sym *symtab;
    const char *strtab;
    const uint32_t *hash;
    const uint16_t *versym;
    const Elf64_Verdef *verdef;
    size_t strsz;
    int verdef_count;
} vdso_t;

static int parse_vdso(const Elf64_Ehdr *ehdr, vdso_t *v)
{
    memset(v, 0, sizeof(*v));
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
    if (!dyn)
        return -1;
    for (; dyn->d_tag != DT_NULL; dyn++) {
        const uint8_t *p = (const uint8_t *) ehdr + dyn->d_un.d_ptr;
        switch (dyn->d_tag) {
        case DT_SYMTAB:
            v->symtab = (const Elf64_Sym *) p;
            break;
        case DT_STRTAB:
            v->strtab = (const char *) p;
            break;
        case DT_STRSZ:
            v->strsz = (size_t) dyn->d_un.d_val;
            break;
        case DT_HASH:
            v->hash = (const uint32_t *) p;
            break;
        case DT_VERSYM:
            v->versym = (const uint16_t *) p;
            break;
        case DT_VERDEF:
            v->verdef = (const Elf64_Verdef *) p;
            break;
        case DT_VERDEFNUM:
            v->verdef_count = (int) dyn->d_un.d_val;
            break;
        default:
            break;
        }
    }
    return (v->symtab && v->strtab && v->hash) ? 0 : -1;
}

static const char *verdef_name_for_ndx(const vdso_t *v, uint16_t ndx)
{
    const Elf64_Verdef *vd = v->verdef;
    for (int i = 0; i < v->verdef_count && vd; i++) {
        if (vd->vd_ndx == ndx) {
            const Elf64_Verdaux *aux =
                (const Elf64_Verdaux *) ((const uint8_t *) vd + vd->vd_aux);
            return &v->strtab[aux->vda_name];
        }
        if (!vd->vd_next)
            break;
        vd = (const Elf64_Verdef *) ((const uint8_t *) vd + vd->vd_next);
    }
    return NULL;
}

typedef int (*clock_gettime_fn)(clockid_t, struct timespec *);
typedef int (*gettimeofday_fn)(struct timeval *, void *);

static void test_vdso(void)
{
    unsigned long base = getauxval(AT_SYSINFO_EHDR);
    EXPECT(base != 0, "AT_SYSINFO_EHDR is zero");
    if (!base)
        return;
    printf("AT_SYSINFO_EHDR = 0x%lx\n", base);

    const Elf64_Ehdr *ehdr = (const Elf64_Ehdr *) base;
    EXPECT(memcmp(ehdr->e_ident,
                  "\x7f"
                  "ELF",
                  4) == 0,
           "vDSO ELF magic");
    EXPECT(ehdr->e_machine == EM_AARCH64, "vDSO e_machine");
    EXPECT(ehdr->e_type == ET_DYN, "vDSO e_type");

    /* NT_GNU_ABI_TAG note. glibc 2.41's vDSO probe expects a Linux ABI tag
     * note alongside the dynamic symbol table; walk every PT_NOTE segment
     * the EHDR advertises and confirm exactly one entry matches the
     * (name="GNU", type=NT_GNU_ABI_TAG, desc[0]=Linux) shape with a
     * minimum-kernel descriptor that is at least 2.6.39 (matching the
     * LINUX_2.6.39 symbol version this vDSO exports).
     */
    const Elf64_Phdr *probe_phdr =
        (const Elf64_Phdr *) ((const uint8_t *) ehdr + ehdr->e_phoff);
    int gnu_abi_tag_count = 0;
    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (probe_phdr[i].p_type != PT_NOTE)
            continue;
        const uint8_t *note_base =
            (const uint8_t *) ehdr + probe_phdr[i].p_offset;
        uint32_t namesz = *(const uint32_t *) (note_base + 0);
        uint32_t descsz = *(const uint32_t *) (note_base + 4);
        uint32_t type = *(const uint32_t *) (note_base + 8);
        const char *name = (const char *) (note_base + 12);
        if (type != 1 /* NT_GNU_ABI_TAG */ || namesz != 4 || descsz != 16)
            continue;
        if (memcmp(name, "GNU\0", 4) != 0)
            continue;
        const uint32_t *desc = (const uint32_t *) (note_base + 12 + 4);
        EXPECT(desc[0] == 0, "NT_GNU_ABI_TAG OS == Linux");
        uint32_t k = (desc[1] << 24) | (desc[2] << 16) | (desc[3] << 8);
        uint32_t want = (2 << 24) | (6 << 16) | (39 << 8);
        EXPECT(k >= want, "NT_GNU_ABI_TAG kernel ABI >= 2.6.39");
        gnu_abi_tag_count++;
    }
    EXPECT(gnu_abi_tag_count == 1,
           "exactly one PT_NOTE carrying NT_GNU_ABI_TAG");
    printf("vDSO NT_GNU_ABI_TAG: count=%d\n", gnu_abi_tag_count);

    vdso_t v;
    EXPECT(parse_vdso(ehdr, &v) == 0, "vDSO dynamic section parse");
    if (!v.symtab || !v.strtab || !v.hash)
        return;

    /* All five __kernel_* symbols must resolve and land in the vDSO page. */
    static const char *names[] = {
        "__kernel_rt_sigreturn", "__kernel_clock_getres",
        "__kernel_clock_gettime", "__kernel_gettimeofday", "__kernel_getcpu"};
    const Elf64_Sym *syms[5] = {0};
    for (int i = 0; i < 5; i++) {
        syms[i] = lookup_sym(ehdr, v.symtab, v.strtab, v.hash, names[i]);
        char buf[64];
        snprintf(buf, sizeof(buf), "lookup %s", names[i]);
        EXPECT(syms[i] != NULL, buf);
        if (!syms[i])
            continue;
        uint64_t addr = base + syms[i]->st_value;
        snprintf(buf, sizeof(buf), "%s address in vDSO page", names[i]);
        EXPECT(addr >= base && addr < base + 0x1000, buf);
    }

    /* Symbol versioning: every defined symbol must point at LINUX_2.6.39. */
    EXPECT(v.versym != NULL, "vDSO DT_VERSYM present");
    EXPECT(v.verdef != NULL, "vDSO DT_VERDEF present");
    if (v.versym && v.verdef) {
        for (int i = 0; i < 5; i++) {
            if (!syms[i])
                continue;
            uint32_t sym_idx = (uint32_t) (syms[i] - v.symtab);
            uint16_t ndx = v.versym[sym_idx];
            const char *ver = verdef_name_for_ndx(&v, ndx);
            char buf[80];
            snprintf(buf, sizeof(buf), "%s versioned LINUX_2.6.39", names[i]);
            EXPECT(ver && strcmp(ver, "LINUX_2.6.39") == 0, buf);
        }
    }

    /* Probe gettimeofday before clock_gettime so the first vDSO-mediated
     * time fallback must be able to seed the shared vvar anchor by itself.
     */
    const Elf64_Sym *gtod =
        lookup_sym(ehdr, v.symtab, v.strtab, v.hash, "__kernel_gettimeofday");
    if (gtod) {
        gettimeofday_fn fn =
            (gettimeofday_fn) (uintptr_t) (base + gtod->st_value);
        struct timeval tv = {0};
        EXPECT(fn(&tv, NULL) == 0, "vDSO gettimeofday pre-seed returned 0");
        EXPECT(tv.tv_sec > 0, "vDSO gettimeofday pre-seed produced time");
    }

    /* Direct call into the vDSO trampoline. Must agree with SVC for both
     * CLOCK_MONOTONIC and CLOCK_REALTIME. The preceding gettimeofday probe
     * seeded the shared CNTVCT anchor, so both clockids exercise the
     * post-seed fast path.
     */
    const Elf64_Sym *cg =
        lookup_sym(ehdr, v.symtab, v.strtab, v.hash, "__kernel_clock_gettime");
    if (cg) {
        clock_gettime_fn fn =
            (clock_gettime_fn) (uintptr_t) (base + cg->st_value);
        struct {
            clockid_t id;
            const char *label;
            int64_t tolerance_ns;
        } cases[] = {
            /* CLOCK_MONOTONIC: tight tolerance, anchor-derived value
             * cannot drift relative to the SVC reference beyond the gap
             * between calls.
             */
            {CLOCK_MONOTONIC, "MONOTONIC", 10000000},
            /* CLOCK_REALTIME: tolerance loose enough to absorb host
             * scheduling jitter between the two clock_gettime calls.
             */
            {CLOCK_REALTIME, "REALTIME", 10000000},
        };
        for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
            struct timespec via_vdso = {0}, via_svc = {0};
            int r1 = fn(cases[i].id, &via_vdso);
            int r2 = (int) syscall(SYS_clock_gettime, cases[i].id, &via_svc);
            char buf[80];
            snprintf(buf, sizeof(buf), "vDSO clock_gettime(%s) returned 0",
                     cases[i].label);
            EXPECT(r1 == 0, buf);
            snprintf(buf, sizeof(buf), "SVC clock_gettime(%s) returned 0",
                     cases[i].label);
            EXPECT(r2 == 0, buf);
            int64_t delta_ns =
                ((int64_t) via_svc.tv_sec - via_vdso.tv_sec) * 1000000000LL +
                (via_svc.tv_nsec - via_vdso.tv_nsec);
            if (delta_ns < 0)
                delta_ns = -delta_ns;
            snprintf(buf, sizeof(buf), "vDSO and SVC clock_gettime(%s) agree",
                     cases[i].label);
            EXPECT(delta_ns < cases[i].tolerance_ns, buf);
            printf("vDSO/SVC clock_gettime(%s) delta = %" PRId64 " ns\n",
                   cases[i].label, delta_ns);
        }
    }

    /* clock_getres vDSO entry must match raw SVC for supported clockids.
     * NULL res must succeed for valid clockids.
     */
    typedef int (*clock_getres_fn)(clockid_t, struct timespec *);
    const Elf64_Sym *cr =
        lookup_sym(ehdr, v.symtab, v.strtab, v.hash, "__kernel_clock_getres");
    if (cr) {
        clock_getres_fn fn =
            (clock_getres_fn) (uintptr_t) (base + cr->st_value);
        static const struct {
            clockid_t id;
            const char *label;
            long expected_nsec;
        } cases[] = {
            {CLOCK_REALTIME, "REALTIME", 1},
            {CLOCK_MONOTONIC, "MONOTONIC", 1},
            {CLOCK_MONOTONIC_RAW, "MONOTONIC_RAW", 1},
            {CLOCK_REALTIME_COARSE, "REALTIME_COARSE", 1000000},
            {CLOCK_MONOTONIC_COARSE, "MONOTONIC_COARSE", 1000000},
            {CLOCK_BOOTTIME, "BOOTTIME", 1},
        };
        for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
            struct timespec res = {.tv_sec = 99, .tv_nsec = 99};
            struct timespec svc_res = {.tv_sec = 99, .tv_nsec = 99};
            int rc = fn(cases[i].id, &res);
            int svc_rc = (int) syscall(SYS_clock_getres, cases[i].id, &svc_res);
            char buf[80];
            snprintf(buf, sizeof(buf), "vDSO clock_getres(%s) returned 0",
                     cases[i].label);
            EXPECT(rc == 0, buf);
            snprintf(buf, sizeof(buf), "SVC clock_getres(%s) returned 0",
                     cases[i].label);
            EXPECT(svc_rc == 0, buf);
            snprintf(buf, sizeof(buf), "vDSO/SVC clock_getres(%s) agree",
                     cases[i].label);
            EXPECT(
                res.tv_sec == svc_res.tv_sec && res.tv_nsec == svc_res.tv_nsec,
                buf);
            snprintf(buf, sizeof(buf), "clock_getres(%s) expected resolution",
                     cases[i].label);
            EXPECT(res.tv_sec == 0 && res.tv_nsec == cases[i].expected_nsec,
                   buf);
        }
        int rc_null = fn(CLOCK_MONOTONIC, NULL);
        EXPECT(rc_null == 0, "vDSO clock_getres(NULL res) returns 0");
    }

    /* gettimeofday fast path: result must agree with SVC reference. */
    if (gtod) {
        gettimeofday_fn fn =
            (gettimeofday_fn) (uintptr_t) (base + gtod->st_value);
        struct timeval via_vdso = {0};
        struct timeval via_svc = {0};
        int r1 = fn(&via_vdso, NULL);
        int r2 = (int) syscall(SYS_gettimeofday, &via_svc, NULL);
        EXPECT(r1 == 0, "vDSO gettimeofday returned 0");
        EXPECT(r2 == 0, "SVC gettimeofday returned 0");
        int64_t delta_us =
            ((int64_t) via_svc.tv_sec - via_vdso.tv_sec) * 1000000LL +
            (via_svc.tv_usec - via_vdso.tv_usec);
        if (delta_us < 0)
            delta_us = -delta_us;
        EXPECT(delta_us < 10000, "vDSO and SVC gettimeofday agree");
        printf("vDSO/SVC gettimeofday delta = %" PRId64 " us\n", delta_us);

        /* tz path must clear the supplied structure. */
        struct timezone tz = {.tz_minuteswest = 1234, .tz_dsttime = 56};
        struct timeval tv2 = {0};
        EXPECT(fn(&tv2, &tz) == 0, "vDSO gettimeofday(tv, tz) returned 0");
        EXPECT(tz.tz_minuteswest == 0 && tz.tz_dsttime == 0,
               "vDSO gettimeofday zeroed tz");

        /* NULL tv must succeed (no write). */
        EXPECT(fn(NULL, NULL) == 0, "vDSO gettimeofday(NULL, NULL) returned 0");
    }

    /* getcpu fast path: must always return cpu=0 / node=0 (elfuse models
     * one online CPU and one NUMA node).
     */
    typedef int (*getcpu_fn)(unsigned *, unsigned *, void *);
    const Elf64_Sym *gc =
        lookup_sym(ehdr, v.symtab, v.strtab, v.hash, "__kernel_getcpu");
    if (gc) {
        getcpu_fn fn = (getcpu_fn) (uintptr_t) (base + gc->st_value);
        unsigned cpu = 0xDEAD, node = 0xBEEF;
        EXPECT(fn(&cpu, &node, NULL) == 0, "vDSO getcpu returned 0");
        EXPECT(cpu == 0, "vDSO getcpu cpu is 0");
        EXPECT(node == 0, "vDSO getcpu node is 0");

        /* NULL out-pointers must succeed. */
        EXPECT(fn(NULL, NULL, NULL) == 0, "vDSO getcpu(NULL, NULL, NULL) ok");
    }
}

int main(void)
{
    printf("test-vdso: vDSO ELF + symbol-versioning probe\n");
    test_vdso();
    if (failures) {
        printf("test-vdso: %d FAIL\n", failures);
        return 1;
    }
    puts("test-vdso: PASS");
    return 0;
}
