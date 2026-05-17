#!/usr/bin/env bash
# test-proctitle-low-stack.sh -- Regress Apple Silicon argv/env stack overwrite
#
# Copyright 2026 elfuse contributors
# SPDX-License-Identifier: Apache-2.0
#
# Usage: tests/test-proctitle-low-stack.sh <elfuse-binary> <busybox-binary>
#
# The original failure (see git log for runtime/proctitle.c) was an argv
# tail overshoot by Apple libc memset stp/DC ZVA ladders writing past the
# explicit byte count when the destination touched the stack ceiling. The
# fix walks only the contiguous argv block and stores byte-by-byte through
# a volatile pointer.
#
# This regression launches the standard busybox echo path under a host
# RLIMIT_STACK far below every macOS default (8176 KiB on Apple Silicon,
# 8192 KiB on Intel), and verifies the rewrite still terminates cleanly.
# Earlier revisions of this script gated the cap behind a -gt comparison
# that became a no-op on hosts whose default soft cap already met or
# beat the gate value; the cap is now applied unconditionally.

set -euo pipefail

ELFUSE="${1:?Usage: $0 <elfuse-binary> <busybox-binary>}"
BB="${2:?Usage: $0 <elfuse-binary> <busybox-binary>}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck disable=SC2034  # Consumed by tests/lib/test-runner.sh.
TEST_TIMEOUT="${TEST_TIMEOUT:-10}"
# shellcheck source=tests/lib/test-runner.sh
source "$SCRIPT_DIR/lib/test-runner.sh"

# Override via env for local experiments. The default sits an order of
# magnitude below every observed macOS shell default and well above the
# floor where elfuse's own host runtime needs more stack than is provided
# (empirically ~560 KiB on macOS 26 / Apple M-series).
PROCTITLE_LOW_STACK_KIB="${PROCTITLE_LOW_STACK_KIB:-1024}"

# Distinct exit codes from the wrapped child shell let the parent
# distinguish "rlimit setup failed" from "elfuse crashed".
ULIMIT_SETUP_FAIL=98
ULIMIT_VERIFY_FAIL=99

output=
if output="$(
    # shellcheck disable=SC2016  # Positional params are expanded by the child shell.
    timeout "$TEST_TIMEOUT" sh -c '
        cap=$3
        if ! ulimit -S -s "$cap" 2>/dev/null; then
            printf "test-proctitle-low-stack: ulimit -S -s %s rejected by shell\n" \
                "$cap" >&2
            exit 98
        fi
        applied=$(ulimit -S -s)
        if [ "$applied" != "$cap" ]; then
            printf "test-proctitle-low-stack: requested %s KiB, got %s\n" \
                "$cap" "$applied" >&2
            exit 99
        fi
        exec "$1" "$2" echo hello
    ' sh "$ELFUSE" "$BB" "$PROCTITLE_LOW_STACK_KIB"
)"; then
    :
else
    rc=$?
    case $rc in
        124)
            printf "test-proctitle-low-stack: elfuse hung at %s KiB stack (timeout %ss)\n" \
                "$PROCTITLE_LOW_STACK_KIB" "$TEST_TIMEOUT" >&2
            exit 1
            ;;
        "$ULIMIT_SETUP_FAIL" | "$ULIMIT_VERIFY_FAIL")
            # The wrapper already explained the failure.
            exit 1
            ;;
        *)
            printf "test-proctitle-low-stack: elfuse failed at %s KiB stack (rc=%d)\n" \
                "$PROCTITLE_LOW_STACK_KIB" "$rc" >&2
            exit "$rc"
            ;;
    esac
fi

if [ "$output" != "hello" ]; then
    printf "test-proctitle-low-stack: unexpected output at %s KiB stack: %s\n" \
        "$PROCTITLE_LOW_STACK_KIB" "$output" >&2
    exit 1
fi

printf "test-proctitle-low-stack: PASS (stack=%s KiB)\n" "$PROCTITLE_LOW_STACK_KIB"
