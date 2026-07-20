/*
 * test-cntvct-thread.c -- EL0 timer counter access on cloned vCPUs
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Linux exposes EL0 timer counter reads on AArch64. elfuse's vDSO fast path
 * depends on CNTVCT_EL0, so this test verifies worker vCPUs created by
 * clone(CLONE_THREAD) get the same virtual-counter configuration as the
 * bootstrap vCPU.
 *
 * This does not exercise elfuse's CLONE_VM-without-CLONE_THREAD worker path.
 * The production fix uses the same CNTKCTL_EL1_EL0_TIMER_EN constant for both
 * clone paths so they cannot drift, but this regression test stays on the
 * pthread/CLONE_THREAD path to remain valid on the QEMU reference lane too.
 */

#include <pthread.h>
#include <stdint.h>

#include "test-harness.h"

#if !defined(__aarch64__)
#error "test-cntvct-thread is aarch64-only"
#endif

int passes = 0, fails = 0;

typedef struct {
    uint64_t first;
    uint64_t second;
} timer_sample_t;

static inline uint64_t read_cntvct(void)
{
    uint64_t value;
    __asm__ volatile("mrs %0, cntvct_el0" : "=r"(value));
    return value;
}

static void expect_timer_sample(const char *label, const timer_sample_t *sample)
{
    char msg[128];

    /* Today elfuse's trapped-MRS fallback returns 0 for CNTVCT_EL0, so the
     * nonzero check catches missing CNTKCTL_EL1.EL0VCTEN on cloned vCPUs. If a
     * CNTVCT_EL0 host fallback is added later, this regression test must grow a
     * stronger signal that EL0 direct counter access was configured.
     */
    snprintf(msg, sizeof(msg), "%s CNTVCT_EL0 was zero or non-monotonic",
             label);
    EXPECT_TRUE(sample->first != 0 && sample->second >= sample->first, msg);
}

static void *read_timer_thread(void *arg)
{
    timer_sample_t *sample = (timer_sample_t *) arg;

    sample->first = read_cntvct();
    sample->second = read_cntvct();

    return NULL;
}

static void test_main_vcpu_timers(void)
{
    TEST("main vCPU EL0 timers");

    timer_sample_t sample = {0};
    sample.first = read_cntvct();
    sample.second = read_cntvct();
    expect_timer_sample("main vCPU", &sample);
}

static void test_clone_thread_vcpu_timers(void)
{
    TEST("clone(CLONE_THREAD) vCPU EL0 timers");

    timer_sample_t sample = {0};
    pthread_t thread;
    int err = pthread_create(&thread, NULL, read_timer_thread, &sample);
    if (err != 0) {
        FAIL("pthread_create failed");
        return;
    }

    err = pthread_join(thread, NULL);
    if (err != 0) {
        FAIL("pthread_join failed");
        return;
    }

    expect_timer_sample("clone(CLONE_THREAD) vCPU", &sample);
}

int main(void)
{
    printf("test-cntvct-thread: EL0 timer cloned vCPU tests\n\n");

    test_main_vcpu_timers();
    test_clone_thread_vcpu_timers();

    SUMMARY("test-cntvct-thread");
    return fails ? 1 : 0;
}
