#!/usr/bin/env bash
# bench-rosetta.sh - Wall-clock benchmark harness for x86_64-via-Rosetta
#
# Copyright 2026 elfuse contributors
# SPDX-License-Identifier: Apache-2.0
#
# Measures wall-clock time for a curated set of static x86_64 workloads
# running under elfuse + Rosetta. The intent is a stable reproducible
# regression baseline; absolute numbers are noisy on macOS so the script
# prints best-of-N runs and a coefficient of variation.
#
# The bench deliberately stays self-contained:
#   - workloads come from the Alpine x86_64 staticbin tree
#   - no external comparison runs (those need separate hardware access)
#
# To compare against native x86_64 hardware or aarch64 hosts, capture the
# same workloads' wall-clock there and paste them into the output yourself.
#
# Usage: tests/bench-rosetta.sh [path/to/elfuse] [iterations]

set -euo pipefail

ELFUSE_INPUT="${1:-build/elfuse}"
ITERS="${2:-5}"
case "$ELFUSE_INPUT" in
    /*) ELFUSE="$ELFUSE_INPUT" ;;
    *) ELFUSE="$(pwd)/$ELFUSE_INPUT" ;;
esac

FIXTURES="${FIXTURES_DIR:-externals/test-fixtures}"
STATICBIN_LONG="${FIXTURES}/x86_64-musl/staticbin/bin"
ROSETTA_PATH=/Library/Apple/usr/libexec/oah/RosettaLinux/rosetta
SHORTDIR=/tmp/elfuse-br

if [ ! -x "$ROSETTA_PATH" ]; then
    printf 'rosetta translator not found at %s\n' "$ROSETTA_PATH" >&2
    exit 77
fi
if [ ! -x "${STATICBIN_LONG}/busybox" ]; then
    printf 'x86_64 fixture tree missing at %s\n' "$STATICBIN_LONG" >&2
    printf 'stage via: INCLUDE_X86_64=1 bash tests/fetch-fixtures.sh\n' >&2
    exit 77
fi
if [ ! -x "$ELFUSE" ]; then
    printf 'elfuse not found: %s\n' "$ELFUSE" >&2
    exit 1
fi

# Stage symlinks so paths stay inside rosetta's 42-byte caps cap.
rm -rf "$SHORTDIR"
mkdir -p "${SHORTDIR}/bin" "${SHORTDIR}/data"
staticbin_abs="$(cd "$STATICBIN_LONG" && pwd)"
ln -s "${staticbin_abs}/busybox" "${SHORTDIR}/bin/busybox"
for applet in echo cat seq factor sha256sum md5sum sha512sum sort wc \
    expr base64 cksum; do
    ln -s busybox "${SHORTDIR}/bin/${applet}"
done

trap 'rm -rf "$SHORTDIR"' EXIT

# Pre-generate a small input file for hash/sort workloads. 64 KiB.
data="${SHORTDIR}/data/in.bin"
dd if=/dev/urandom of="$data" bs=1024 count=64 status=none

# Capture wall-clock in nanoseconds across N iterations of CMD. Returns
# the best (minimum) sample and a basic spread (max - min).
# Args: <label> <cmd...>
run_bench()
{
    local label="$1"
    shift
    local samples=()
    local i
    for ((i = 0; i < ITERS; i++)); do
        local start_ns end_ns
        start_ns=$(python3 -c 'import time; print(time.monotonic_ns())')
        # Discard stdout to keep terminal IO out of the measurement.
        "$@" > /dev/null 2>&1 || true
        end_ns=$(python3 -c 'import time; print(time.monotonic_ns())')
        samples+=("$((end_ns - start_ns))")
    done

    # Compute min and max via printf | sort -n (small N, no perf cost).
    local min max sum count
    min=$(printf '%s\n' "${samples[@]}" | sort -n | head -1)
    max=$(printf '%s\n' "${samples[@]}" | sort -n | tail -1)
    count=${#samples[@]}
    sum=0
    for s in "${samples[@]}"; do
        sum=$((sum + s))
    done
    local mean=$((sum / count))

    # Format milliseconds for readability.
    printf '  %-22s best=%6.1fms  mean=%6.1fms  spread=%6.1fms  (n=%d)\n' \
        "$label" \
        "$(python3 -c "print($min / 1e6)")" \
        "$(python3 -c "print($mean / 1e6)")" \
        "$(python3 -c "print(($max - $min) / 1e6)")" \
        "$count"
}

printf 'elfuse:     %s\n' "$ELFUSE"
printf 'rosetta:    %s\n' "$ROSETTA_PATH"
printf 'iterations: %d per workload\n\n' "$ITERS"

# Warm the rosetta AOT cache. The first launch of any binary pays a
# translation cost; subsequent launches hit ~/.cache/elfuse-rosettad/.
printf 'Warming AOT cache:\n'
for app in echo seq factor sha256sum md5sum sha512sum sort wc; do
    "$ELFUSE" "${SHORTDIR}/bin/${app}" --help > /dev/null 2>&1 || true
done
printf '  done\n\n'

# Workload set:
#   - echo, true:   minimum bootstrap cost (vCPU + rosetta init)
#   - seq:          libc IO-bound, light arith
#   - factor:       compute-heavy, small mem footprint
#   - sha256sum:    libc + per-byte loop over 64 KiB
#   - sort:         tmpfile + sort + write back
printf 'Benchmark (wall-clock):\n'
run_bench "bootstrap-echo" "$ELFUSE" "${SHORTDIR}/bin/echo" "ready"
run_bench "seq-1k" "$ELFUSE" "${SHORTDIR}/bin/seq" "1" "1000"
run_bench "factor-1m" "$ELFUSE" "${SHORTDIR}/bin/factor" "999983"
run_bench "sha256-64k" "$ELFUSE" "${SHORTDIR}/bin/sha256sum" "$data"
run_bench "md5-64k" "$ELFUSE" "${SHORTDIR}/bin/md5sum" "$data"
run_bench "sha512-64k" "$ELFUSE" "${SHORTDIR}/bin/sha512sum" "$data"
run_bench "wc-64k" "$ELFUSE" "${SHORTDIR}/bin/wc" "-c" "$data"

# Compare against the aarch64 equivalent so the cost of rosetta vs native
# guest translation is visible. The aarch64 staticbin tree is the source
# of truth (same Alpine version, different arch).
aarch64_bin="${FIXTURES}/aarch64-musl/staticbin/bin/busybox"
if [ -x "$aarch64_bin" ]; then
    printf '\nAarch64 reference (same workload, native elfuse path):\n'
    ln -sfn "$aarch64_bin" "${SHORTDIR}/bin/busybox-arm"
    for applet in echo seq factor sha256sum md5sum sha512sum sort wc; do
        ln -sfn busybox-arm "${SHORTDIR}/bin/${applet}-arm"
    done
    run_bench "bootstrap-echo-arm" "$ELFUSE" "${SHORTDIR}/bin/echo-arm" "ready"
    run_bench "seq-1k-arm" "$ELFUSE" "${SHORTDIR}/bin/seq-arm" "1" "1000"
    run_bench "factor-1m-arm" "$ELFUSE" "${SHORTDIR}/bin/factor-arm" "999983"
    run_bench "sha256-64k-arm" "$ELFUSE" "${SHORTDIR}/bin/sha256sum-arm" "$data"
fi

printf '\nNotes: best-of-%d sample is the most reliable comparison point on a\n' "$ITERS"
printf '       noisy macOS host. Spread tracks scheduler/IO jitter.\n'
