/* test-shim-urandom-wrap.c -- regression for wrapped shim urandom copies.
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * The EL1 getrandom fast path copies out of a 4096-byte ring. When a read
 * starts at ring[4095], the copy splits into a one-byte tail segment plus a
 * wrapped second segment. A missing post-increment on the first segment's
 * byte store used to make the second segment overwrite byte 0 of the caller
 * buffer and leave the final requested byte untouched while still returning
 * success.
 */

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

#define RING_SIZE 4096
#define INLINE_LIMIT 256
#define SLOW_LEN (INLINE_LIMIT + 1)
#define ITERATIONS 8
#define SENTINEL 0xA5

static int getrandom_exact(void *buf, size_t len)
{
    long r = syscall(SYS_getrandom, buf, len, 0);
    if (r != (long) len) {
        fprintf(stderr, "getrandom(%zu) returned %ld errno=%d\n", len, r,
                errno);
        return -1;
    }
    return 0;
}

static int refill_ring(void)
{
    unsigned char scratch[SLOW_LEN];
    return getrandom_exact(scratch, sizeof(scratch));
}

static int advance_fast_bytes(unsigned *pos, unsigned target)
{
    unsigned char b;

    while (*pos != target) {
        if (getrandom_exact(&b, 1) != 0)
            return -1;
        *pos = (*pos + 1) & (RING_SIZE - 1);
    }
    return 0;
}

int main(void)
{
    unsigned pos = 0;
    int untouched = 0;

    for (int i = 0; i < ITERATIONS; i++) {
        if (refill_ring() != 0)
            return 1;
        if (advance_fast_bytes(&pos, RING_SIZE - 1) != 0)
            return 1;
        if (refill_ring() != 0)
            return 1;

        unsigned char buf[INLINE_LIMIT];
        memset(buf, SENTINEL, sizeof(buf));
        if (getrandom_exact(buf, sizeof(buf)) != 0)
            return 1;
        pos = (pos + INLINE_LIMIT) & (RING_SIZE - 1);

        if (buf[sizeof(buf) - 1] == SENTINEL)
            untouched++;
    }

    if (untouched == ITERATIONS) {
        fprintf(stderr,
                "FAIL: wrapped getrandom left the final byte untouched\n");
        return 1;
    }

    printf("OK: wrapped getrandom wrote through the caller buffer\n");
    return 0;
}
