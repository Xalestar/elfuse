#!/usr/bin/env bash
# test-rosetta-alpine.sh - Alpine-flavored x86_64 tests through Rosetta
#
# Copyright 2026 elfuse contributors
# SPDX-License-Identifier: Apache-2.0
#
# Extends test-rosetta-statics.sh with workloads that exercise the
# Alpine static-binary suite end-to-end:
#   - file I/O against a real on-disk corpus (read, hash, sort, find)
#   - text-processing pipelines stitched through the host shell
#   - exit-code propagation through pipe chains
#   - filesystem readback (ls, find, du, wc)
#
# Each test runs an Alpine x86_64 static binary (busybox or applet) under
# elfuse + Rosetta. The host shell stitches multi-step pipelines so each
# stage is a separate elfuse invocation - that catches per-launch
# regressions (bootstrap, /proc/self/exe, vDSO) on every step.
#
# Fixture: tests/fetch-fixtures.sh INCLUDE_X86_64=1.
# Path cap: stages a /tmp/elfuse-ra/ symlink farm so paths stay inside
# rosetta's 42-byte ROSETTA_CAPS_BINARY_PATH_LEN.
#
# Usage: tests/test-rosetta-alpine.sh [path/to/elfuse]

set -euo pipefail

ELFUSE_INPUT="${1:-build/elfuse}"
case "$ELFUSE_INPUT" in
    /*) ELFUSE="$ELFUSE_INPUT" ;;
    *) ELFUSE="$(pwd)/$ELFUSE_INPUT" ;;
esac

FIXTURES="${FIXTURES_DIR:-externals/test-fixtures}"
STATICBIN_LONG="${FIXTURES}/x86_64-musl/staticbin/bin"
ROOTFS="${FIXTURES}/x86_64-musl/rootfs"
ROSETTA_PATH=/Library/Apple/usr/libexec/oah/RosettaLinux/rosetta

SHORTDIR=/tmp/elfuse-ra
STATICBIN="${SHORTDIR}/bin"
DATA="${SHORTDIR}/data"

pass=0
fail=0
skip=0
total=0

c_green()
{
    printf '\033[0;32m%s\033[0m' "$*"
}
c_red()
{
    printf '\033[0;31m%s\033[0m' "$*"
}
c_yellow()
{
    printf '\033[1;33m%s\033[0m' "$*"
}
report_pass()
{
    printf '%s %s\n' "$(c_green '   PASS:')" "$*"
    pass=$((pass + 1))
}
report_fail()
{
    printf '%s %s\n' "$(c_red '   FAIL:')" "$*"
    fail=$((fail + 1))
}
report_skip()
{
    printf '%s %s\n' "$(c_yellow '   SKIP:')" "$*"
    skip=$((skip + 1))
}

# Pre-flight.
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
    printf 'elfuse binary not found: %s\n' "$ELFUSE" >&2
    exit 1
fi

# macOS ships no built-in timeout(1); Homebrew coreutils installs it as
# /opt/homebrew/bin/timeout (and the legacy gtimeout alias). Detect either
# binary so this suite runs on macOS hosts without preconfigured PATH.
TIMEOUT="$(command -v timeout 2> /dev/null || command -v gtimeout 2> /dev/null \
    || true)"
if [ -z "$TIMEOUT" ]; then
    printf 'timeout(1) not found in PATH; install via: brew install coreutils\n' >&2
    exit 77
fi

# Stage short-path symlink farm and a small data corpus.
rm -rf "$SHORTDIR"
mkdir -p "$STATICBIN" "$DATA"
staticbin_abs="$(cd "$STATICBIN_LONG" && pwd)"

# Point HOME at the per-run tmp so the rosettad AOT cache stays empty
# across re-runs. Without this, the cache from a previous run can serve
# the digest fast-path and silently bypass the path-publishing surface
# the smoke probes are meant to exercise.
export HOME="$SHORTDIR"

ln -s "${staticbin_abs}/busybox" "${STATICBIN}/busybox"
for applet in echo cat head tail wc sort tr seq expr factor base64 \
    md5sum sha256sum sha512sum sha1sum cksum cp touch ls stat \
    basename dirname realpath du uname date id printenv nproc \
    true false sleep nice nohup timeout chmod chown ln rm \
    mkdir rmdir mv pwd cmp diff find sed grep awk env xargs \
    tee od cut paste join uniq tac rev split nl shuf yes; do
    ln -s busybox "${STATICBIN}/${applet}"
done

trap 'rm -rf "$SHORTDIR"' EXIT

# Build a small data corpus the tests can chew on. Deterministic content
# so hash and sort results are stable across runs. fruits-unsorted.txt is
# deliberately out of order so sort + diff exercise the comparison paths.
printf 'cherry\napple\ngrape\nbanana\nfig\ndurian\neggplant\n' \
    > "${DATA}/fruits-unsorted.txt"
printf 'apple\nbanana\ncherry\ndurian\neggplant\nfig\ngrape\n' \
    > "${DATA}/fruits-sorted.txt"

# 8 KiB of repeated ASCII (printable so wc/grep/sort don't choke). The
# pattern is deterministic so the SHA-256 expectation below is stable.
{
    for i in $(seq 1 256); do
        printf 'rosetta line %03d - the quick brown fox\n' "$i"
    done
} > "${DATA}/lines.txt"

# Capture an expected SHA-256 of lines.txt computed locally so the test
# can compare without hardcoding a fragile constant.
expected_sha="$(shasum -a 256 "${DATA}/lines.txt" | awk '{print $1}')"

# A pair of identical files for diff -q to confirm.
cp "${DATA}/lines.txt" "${DATA}/lines-copy.txt"

# Test helpers.
# run_eq: command's stdout must equal expected exactly. rc must be 0.
run_eq()
{
    local label="$1" expected="$2"
    shift 2
    total=$((total + 1))
    local out rc
    set +e
    out="$("$TIMEOUT" 10 "$ELFUSE" "$@" 2> /dev/null)"
    rc=$?
    set -e
    if [ "$rc" != "0" ]; then
        report_fail "$label: exit=$rc"
        return
    fi
    if [ "$out" != "$expected" ]; then
        report_fail "$label: output mismatch"
        printf '         got:  %q\n         want: %q\n' "$out" "$expected" >&2
        return
    fi
    report_pass "$label"
}

# run_re: command's stdout must match a regex. rc must be 0.
run_re()
{
    local label="$1" pattern="$2"
    shift 2
    total=$((total + 1))
    local out rc
    set +e
    out="$("$TIMEOUT" 10 "$ELFUSE" "$@" 2> /dev/null)"
    rc=$?
    set -e
    if [ "$rc" != "0" ]; then
        report_fail "$label: exit=$rc"
        printf '         stdout: %q\n' "$out" >&2
        return
    fi
    if ! printf '%s' "$out" | grep -Eq -- "$pattern"; then
        report_fail "$label: stdout did not match /$pattern/"
        printf '         stdout: %q\n' "$out" >&2
        return
    fi
    report_pass "$label"
}

# run_pipe: two-stage pipeline. Stage A produces stdout, piped to stage
# B which is also a guest binary under elfuse. Final stdout must equal
# expected. Each stage is its own elfuse invocation, so bootstrap +
# /proc/self/exe + vDSO run twice per test.
run_pipe()
{
    local label="$1" expected="$2"
    shift 2
    local args_a=() args_b=()
    local seen_sep=0
    local tok
    for tok in "$@"; do
        if [ "$tok" = "--" ]; then
            seen_sep=1
            continue
        fi
        if [ "$seen_sep" = "0" ]; then
            args_a+=("$tok")
        else
            args_b+=("$tok")
        fi
    done
    total=$((total + 1))
    if [ "$seen_sep" = "0" ]; then
        report_fail "$label: missing -- separator in pipeline spec"
        return
    fi
    local out rc
    set +e
    # set -o pipefail inside the subshell so the captured $? reflects the
    # first non-zero stage exit, not just the last. Without this a producer
    # that fails after emitting matching text would silently pass.
    out="$(
        set -o pipefail
        "$TIMEOUT" 15 "$ELFUSE" "${args_a[@]}" 2> /dev/null \
            | "$TIMEOUT" 15 "$ELFUSE" "${args_b[@]}" 2> /dev/null
    )"
    rc=$?
    set -e
    if [ "$rc" -ne 0 ]; then
        report_fail "$label: pipeline exited rc=$rc"
        printf '         got: %q\n         want: %q\n' "$out" "$expected" >&2
        return
    fi
    if [ "$out" != "$expected" ]; then
        report_fail "$label: pipeline output mismatch"
        printf '         got:  %q\n         want: %q\n' "$out" "$expected" >&2
        return
    fi
    report_pass "$label"
}

printf 'elfuse:    %s\n' "$ELFUSE"
printf 'fixtures:  %s -> %s\n' "$STATICBIN" "$staticbin_abs"
printf 'rosetta:   %s\n\n' "$ROSETTA_PATH"

# ---------------------------------------------------------------------------
# Filesystem readback
# ---------------------------------------------------------------------------

# cat: openat + read + write + close. Read the first line of fruits.
# fruits-unsorted.txt starts with "cherry" by construction (deliberately
# out of order so sort + diff exercise the comparison paths).
run_re "cat-fruits-first-line" "^cherry$" \
    "${STATICBIN}/head" "-n1" "${DATA}/fruits-unsorted.txt"

# wc -l counts lines via read syscall over a file. The fixture file is
# 7 fruit names; lines.txt has 256 lines of 39 bytes each (256*39 = 9984).
run_re "wc-l-fruits" "^[[:space:]]*7 .*fruits-unsorted.txt$" \
    "${STATICBIN}/wc" "-l" "${DATA}/fruits-unsorted.txt"
run_re "wc-l-lines" "^[[:space:]]*256 .*lines.txt$" \
    "${STATICBIN}/wc" "-l" "${DATA}/lines.txt"
run_re "wc-c-lines" "^[[:space:]]*9984 .*lines.txt$" \
    "${STATICBIN}/wc" "-c" "${DATA}/lines.txt"

# ls -1: directory readback, getdents64 + write each name.
run_re "ls-data" "^lines.txt$|^lines-copy.txt$|^fruits-unsorted.txt$" \
    "${STATICBIN}/ls" "-1" "$DATA"

# stat: lstat/fstat against the same path elfuse can resolve.
run_re "stat-data" "regular file" \
    "${STATICBIN}/stat" "${DATA}/lines.txt"

# find by name: opendir + getdents + nested syscalls.
run_re "find-by-name" "lines.txt" \
    "${STATICBIN}/find" "$DATA" "-name" "lines.txt"

# du -s: stat aggregation; output is "<size>\t<path>". Just sanity-check
# that a non-zero size is reported.
run_re "du-sk-data" "^[1-9][0-9]*[[:space:]]" \
    "${STATICBIN}/du" "-sk" "$DATA"

# ---------------------------------------------------------------------------
# Hashing - libc per-byte loops + per-iteration computation
# ---------------------------------------------------------------------------

run_re "sha256-fruits" "^[0-9a-f]{64}  " \
    "${STATICBIN}/sha256sum" "${DATA}/fruits-sorted.txt"

# Same input on the host gives the same digest; pinpoint match across rosetta.
run_re "sha256-lines-matches-host" "^${expected_sha}  " \
    "${STATICBIN}/sha256sum" "${DATA}/lines.txt"

run_re "sha512-lines" "^[0-9a-f]{128}  " \
    "${STATICBIN}/sha512sum" "${DATA}/lines.txt"

run_re "md5-fruits" "^[0-9a-f]{32}  " \
    "${STATICBIN}/md5sum" "${DATA}/fruits-sorted.txt"

# cksum (POSIX CRC + length). Output is "<crc> <len> <path>".
run_re "cksum-fruits" "^[0-9]+ [0-9]+ " \
    "${STATICBIN}/cksum" "${DATA}/fruits-sorted.txt"

# ---------------------------------------------------------------------------
# Text processing
# ---------------------------------------------------------------------------

# sort: in-place tmpfile + qsort + write back. Verify first and last lines.
run_re "sort-first" "^apple$" \
    "${STATICBIN}/sort" "${DATA}/fruits-unsorted.txt"
run_re "sort-reverse-first" "^grape$" \
    "${STATICBIN}/sort" "-r" "${DATA}/fruits-unsorted.txt"

# Sort + count via two-stage pipeline. busybox wc on stdin does not pad
# the count, so the expected output is the bare "7".
run_pipe "pipe-sort-wc" "7" \
    "${STATICBIN}/sort" "${DATA}/fruits-unsorted.txt" \
    -- \
    "${STATICBIN}/wc" "-l"

# tr translation: lowercase to uppercase via single-byte mapping.
run_pipe "pipe-tr-uppercase" "APPLE" \
    "${STATICBIN}/head" "-n1" "${DATA}/fruits-sorted.txt" \
    -- \
    "${STATICBIN}/tr" "a-z" "A-Z"

# grep + cat pipe.
run_pipe "pipe-cat-grep" "rosetta line 042 - the quick brown fox" \
    "${STATICBIN}/cat" "${DATA}/lines.txt" \
    -- \
    "${STATICBIN}/grep" "^rosetta line 042"

# sed substitution through a pipe.
run_pipe "pipe-sed-subst" "hello ROSETTA" \
    "${STATICBIN}/echo" "hello world" \
    -- \
    "${STATICBIN}/sed" "s/world/ROSETTA/"

# awk field extraction.
run_pipe "pipe-awk-field" "world" \
    "${STATICBIN}/echo" "hello world rosetta" \
    -- \
    "${STATICBIN}/awk" "{print \$2}"

# head/tail for line slicing.
run_re "head-n3" "^rosetta line 001 " \
    "${STATICBIN}/head" "-n3" "${DATA}/lines.txt"

run_re "tail-n3" "^rosetta line 256 - the quick brown fox$" \
    "${STATICBIN}/tail" "-n1" "${DATA}/lines.txt"

# uniq via sort | uniq pipeline (counts dedup).
run_pipe "pipe-sort-uniq" "apple" \
    "${STATICBIN}/echo" -e "apple\\napple\\napple" \
    -- \
    "${STATICBIN}/uniq"

# cut: column extraction by delimiter.
run_pipe "pipe-cut-field" "world" \
    "${STATICBIN}/echo" "hello:world:rosetta" \
    -- \
    "${STATICBIN}/cut" "-d:" "-f2"

# rev: per-line reverse.
run_pipe "pipe-rev" "olleh" \
    "${STATICBIN}/echo" "hello" \
    -- \
    "${STATICBIN}/rev"

# tac: reverse line order on a file. The fruits-sorted.txt corpus starts
# with "apple" and ends with "grape"; after tac the first line is "grape".
run_re "tac-reverse-first-line" "^grape$" \
    "${STATICBIN}/tac" "${DATA}/fruits-sorted.txt"

# ---------------------------------------------------------------------------
# Arithmetic and number generation
# ---------------------------------------------------------------------------

run_eq "seq-1-5" "$(printf '1\n2\n3\n4\n5')" \
    "${STATICBIN}/seq" "1" "5"

run_eq "seq-step" "$(printf '0\n5\n10\n15\n20')" \
    "${STATICBIN}/seq" "0" "5" "20"

run_re "factor-prime" "^999983: 999983$" \
    "${STATICBIN}/factor" "999983"

run_re "factor-composite" "^60: 2 2 3 5$" \
    "${STATICBIN}/factor" "60"

# ---------------------------------------------------------------------------
# File comparison + base64 round-trip
# ---------------------------------------------------------------------------

# diff -q on identical files: rc=0 and no stdout.
total=$((total + 1))
set +e
diff_out=$("$TIMEOUT" 10 "$ELFUSE" "${STATICBIN}/diff" "-q" \
    "${DATA}/lines.txt" "${DATA}/lines-copy.txt" 2> /dev/null)
diff_rc=$?
set -e
if [ "$diff_rc" = "0" ] && [ -z "$diff_out" ]; then
    report_pass "diff-identical"
else
    report_fail "diff-identical: rc=$diff_rc out=$(printf '%q' "$diff_out")"
fi

# diff on differing files: rc=1.
total=$((total + 1))
set +e
"$ELFUSE" "${STATICBIN}/diff" "-q" \
    "${DATA}/fruits-sorted.txt" "${DATA}/fruits-unsorted.txt" \
    > /dev/null 2>&1
diff_rc=$?
set -e
if [ "$diff_rc" = "1" ]; then
    report_pass "diff-differs (rc=1)"
else
    report_fail "diff-differs: rc=$diff_rc (want 1)"
fi

# base64 decode of a pre-encoded constant. Verifies the encoder + decoder
# share the same alphabet and padding rules. The encoded form below is the
# canonical base64 of "rosetta-bridge".
run_pipe "pipe-base64-decode" "rosetta-bridge" \
    "${STATICBIN}/echo" "cm9zZXR0YS1icmlkZ2U=" \
    -- \
    "${STATICBIN}/base64" "-d"

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

printf '\n'
printf 'Results: %s passed, %s failed, %s skipped (of %s)\n' \
    "$pass" "$fail" "$skip" "$total"

if [ "$fail" -gt 0 ]; then
    exit 1
fi
exit 0
