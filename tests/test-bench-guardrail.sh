#!/usr/bin/env bash
# Hot-syscall performance guardrail
#
# Runs bench-hot-guard (musl-static) and, when the cross-glibc toolchain
# is available, bench-hot-guard-glibc (dynamic glibc)
# under elfuse, then enforces explicit ns/op ceilings on the three hot
# paths the TODO baseline tracked:
#
#   getpid                <= 200 ns/op   (shim identity fast path)
#   clock_gettime(libc)   <=  50 ns/op   (vDSO CNTVCT fast path)
#   read(/dev/urandom, 1) <= 200 ns/op   (shim urandom ring fast path)
#
# The static (musl) bench is the baseline; the dynamic-glibc bench
# verifies that glibc 2.41's vDSO probe (NT_GNU_ABI_TAG PT_NOTE) keeps
# clock_gettime on the trampolines instead of trapping. When
# LINUX_TOOLCHAIN is missing the glibc variant skips cleanly.

set -u

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ELFUSE="${ELFUSE:-${REPO_ROOT}/build/elfuse}"
BENCH_GUARDRAIL_DIR="${BENCH_GUARDRAIL_DIR:-${REPO_ROOT}/build}"
BENCH_GUARDRAIL_REQUIRE_STATIC="${BENCH_GUARDRAIL_REQUIRE_STATIC:-1}"
STATIC_BENCH="${BENCH_GUARDRAIL_DIR}/bench-hot-guard"
GLIBC_BENCH="${BENCH_GUARDRAIL_DIR}/bench-hot-guard-glibc"
GLIBC_TOOLCHAIN="${LINUX_TOOLCHAIN:-/opt/toolchain/aarch64-linux-gnu}"
GLIBC_SYSROOT="${GLIBC_TOOLCHAIN}/aarch64-unknown-linux-gnu/sysroot"
ITERS="${BENCH_GUARDRAIL_ITERS:-200000}"

# Thresholds in ns/op. The TODO baseline calls for 200 / 50 / 200,
# which leaves a tight 1.5x margin for read-urandom1 (~140 ns measured
# baseline). On shared / virtualized hosts under load the urandom
# numbers were observed up to ~280 ns/op across 5 sequential runs on a
# laptop with concurrent workloads, so the ceiling is widened to 400 ns
# while still catching the real regression target: a fast-path bail
# back to SVC would push the measurement into the ~1000+ ns range.
THRESH_GETPID=200
THRESH_CLOCK_GETTIME=50
THRESH_URANDOM=400

C_RED='\033[0;31m'
C_GREEN='\033[0;32m'
C_YELLOW='\033[0;33m'
C_RESET='\033[0m'

if [ ! -x "$ELFUSE" ]; then
    echo "elfuse binary missing at $ELFUSE" >&2
    exit 1
fi

run_static=1
if [ ! -x "$STATIC_BENCH" ]; then
    if [ "$BENCH_GUARDRAIL_REQUIRE_STATIC" = 1 ]; then
        echo "bench-hot-guard missing at $STATIC_BENCH" >&2
        exit 1
    fi
    /usr/bin/printf "  ${C_YELLOW}SKIP${C_RESET}  static        bench-hot-guard absent: %s\n" \
        "$STATIC_BENCH"
    run_static=0
fi

failures=0
benchmarks_run=0

# extract_ns <bench-output> <label>
# Prints the floating-point ns/op for the line whose first column is
# exactly <label>. Returns nothing if the line is absent.
extract_ns()
{
    awk -v label="$2" '$1 == label { print $2 }' "$1"
}

# check_threshold <variant> <label> <ns/op> <ceiling-ns>
check_threshold()
{
    local variant="$1" label="$2" actual="$3" ceiling="$4"
    if [ -z "$actual" ]; then
        printf "  ${C_RED}MISS${C_RESET}  %-12s %-22s no measurement reported\n" \
            "$variant" "$label" >&2
        failures=$((failures + 1))
        return
    fi
    awk -v a="$actual" -v c="$ceiling" 'BEGIN { exit !(a <= c) }'
    if [ $? -eq 0 ]; then
        printf "  ${C_GREEN}OK${C_RESET}    %-12s %-22s %7.1f ns/op  (ceiling %d)\n" \
            "$variant" "$label" "$actual" "$ceiling"
    else
        printf "  ${C_RED}FAIL${C_RESET}  %-12s %-22s %7.1f ns/op  > %d\n" \
            "$variant" "$label" "$actual" "$ceiling" >&2
        failures=$((failures + 1))
    fi
}

run_and_check()
{
    local variant="$1" bench="$2"
    shift 2
    local out
    out="$(mktemp)"
    benchmarks_run=$((benchmarks_run + 1))
    if ! "$ELFUSE" "$@" "$bench" "$ITERS" > "$out" 2>&1; then
        echo "  ${C_RED}FAIL${C_RESET}  $variant bench exited non-zero" >&2
        cat "$out" >&2
        failures=$((failures + 1))
        rm -f "$out"
        return
    fi

    check_threshold "$variant" "getpid" \
        "$(extract_ns "$out" getpid)" "$THRESH_GETPID"
    check_threshold "$variant" "clock_gettime" \
        "$(extract_ns "$out" clock_gettime)" "$THRESH_CLOCK_GETTIME"
    check_threshold "$variant" "read-urandom1" \
        "$(extract_ns "$out" read-urandom1)" "$THRESH_URANDOM"

    rm -f "$out"
}

echo "=== bench-guardrail (iters=$ITERS) ==="

if [ "$run_static" = 1 ]; then
    echo "[static (musl)]"
    run_and_check static "$STATIC_BENCH"
fi

if [ -x "$GLIBC_BENCH" ] && [ -d "$GLIBC_SYSROOT" ]; then
    echo "[dynamic-glibc]"
    run_and_check dyn-glibc "$GLIBC_BENCH" --sysroot "$GLIBC_SYSROOT"
else
    /usr/bin/printf "  ${C_YELLOW}SKIP${C_RESET}  dyn-glibc      cross-toolchain absent: %s\n" \
        "$GLIBC_TOOLCHAIN"
fi

if [ "$benchmarks_run" -eq 0 ]; then
    echo
    echo "guardrail FAILED (no benchmark variants were available to run)" >&2
    exit 1
fi

if [ "$failures" -ne 0 ]; then
    echo
    echo "guardrail FAILED ($failures threshold violation(s))" >&2
    exit 1
fi
echo
echo "guardrail PASS"
exit 0
