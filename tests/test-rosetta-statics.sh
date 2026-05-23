#!/usr/bin/env bash
# test-rosetta-statics.sh - Smoke test x86_64 statics under Rosetta
#
# Copyright 2026 elfuse contributors
# SPDX-License-Identifier: Apache-2.0
#
# Runs a curated set of static x86_64 binaries through elfuse and verifies
# expected output. Aimed at fast-iteration regression coverage of the
# rosetta runtime path (VZ ioctl gate, /proc/self/exe redirect, high-VA
# mmap, kbuf alias). Distinct from test-matrix.sh elfuse-x86_64 which runs
# the broader corpus.
#
# Fixture source: the Alpine x86_64 staticbin tree assembled by
# tests/fetch-fixtures.sh INCLUDE_X86_64=1. The tree contains busybox.static
# plus a list of applet symlinks; both are statically-linked musl ELFs.
#
# Rosetta caps the binary-path field in its VZ_CAPS payload at 42 bytes
# (ROSETTA_CAPS_BINARY_PATH_LEN). Keep these probes on the real checkout
# path so they catch regressions in the runtime aliasing workaround rather
# than masking them with a short-path staging tree.
#
# Skips cleanly when:
#   - Rosetta Linux is not installed on the host
#   - The x86_64 fixture tree is missing (run fetch-fixtures.sh first)
#
# Usage: tests/test-rosetta-statics.sh [path/to/elfuse]

set -euo pipefail

ELFUSE_INPUT="${1:-build/elfuse}"
case "$ELFUSE_INPUT" in
    /*) ELFUSE="$ELFUSE_INPUT" ;;
    *) ELFUSE="$(pwd)/$ELFUSE_INPUT" ;;
esac

FIXTURES="${FIXTURES_DIR:-externals/test-fixtures}"
STATICBIN_LONG="${FIXTURES}/x86_64-musl/staticbin/bin"
ROSETTA_PATH=/Library/Apple/usr/libexec/oah/RosettaLinux/rosetta

SHORTDIR=/tmp/elfuse-r
STATICBIN=""

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

# Run a binary, check exit code and (optionally) stdout regex.
# Args: <label> <expected-stdout-regex|""> <expected-exit-code> <binary> [args...]
# An empty regex skips the stdout check.
run_check()
{
    local label="$1" expected_re="$2" expected_rc="$3"
    shift 3
    total=$((total + 1))

    local out rc
    set +e
    out="$("$TIMEOUT" 10 "$ELFUSE" "$@" 2> /dev/null)"
    rc=$?
    set -e

    if [ "$rc" != "$expected_rc" ]; then
        report_fail "$label: exit=$rc want=$expected_rc"
        printf '         stdout: %q\n' "$out" >&2
        return
    fi
    if [ -n "$expected_re" ] && ! printf '%s' "$out" | grep -Eq -- "$expected_re"; then
        report_fail "$label: stdout did not match /$expected_re/"
        printf '         stdout: %q\n' "$out" >&2
        return
    fi
    report_pass "$label"
}

# Pre-flight checks.
if [ ! -x "$ROSETTA_PATH" ]; then
    printf 'rosetta translator not found at %s\n' "$ROSETTA_PATH" >&2
    printf 'install via: softwareupdate --install-rosetta\n' >&2
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

rm -rf "$SHORTDIR"
mkdir -p "$SHORTDIR"
staticbin_abs="$(cd "$STATICBIN_LONG" && pwd)"
STATICBIN="$staticbin_abs"

# Point HOME at the per-run tmp so the rosettad AOT cache lives at
# $SHORTDIR/.cache/elfuse-rosettad and is empty on every invocation.
# Without this, the cache from a previous run can satisfy rosetta via
# the digest fast-path and silently bypass the /proc/self/fd/3 alias
# that the long-path tests are meant to exercise.
export HOME="$SHORTDIR"

trap 'rm -rf "$SHORTDIR"' EXIT

printf 'elfuse:    %s\n' "$ELFUSE"
printf 'fixtures:  %s\n' "$STATICBIN"
printf 'rosetta:   %s\n\n' "$ROSETTA_PATH"

# ---------------------------------------------------------------------------
# busybox applets - statics validated to work end-to-end on M1.
# ---------------------------------------------------------------------------

# Simple stdout-producing applets. true/false return immediately; the
# empty regex skips the stdout check.
run_check "echo" "^hello rosetta$" 0 "${STATICBIN}/echo" "hello rosetta"
run_check "true" "" 0 "${STATICBIN}/true"
run_check "false" "" 1 "${STATICBIN}/false"

# env propagation: the host shell's environ reaches the rosetta guest's
# printenv via execve auxiliary vector + ELF entry. env -i isolates the
# environment so the probe variable is the only signal. The env wrapper
# wraps the elfuse invocation; passing env -i as elfuse's argv[1] would
# make elfuse try to load env as an ELF.
total=$((total + 1))
set +e
penv_out="$(env -i HOME=/ TZ=UTC ELFUSE_PROBE=elfuse-test \
    "$ELFUSE" "${STATICBIN}/printenv" ELFUSE_PROBE 2> /dev/null)"
penv_rc=$?
set -e
if [ "$penv_rc" = "0" ] && [ "$penv_out" = "elfuse-test" ]; then
    report_pass "printenv"
else
    report_fail "printenv: rc=$penv_rc out=$(printf '%q' "$penv_out")"
fi

# Busybox expr returns 1 when the arithmetic result is zero (POSIX), and
# 0 otherwise. expr-zero deliberately exercises the 0-result path.
run_check "expr-zero" "^0$" 1 "${STATICBIN}/expr" "1" "-" "1"
run_check "expr-mul" "^42$" 0 "${STATICBIN}/expr" "6" "*" "7"

# argv passing through the binfmt-misc convention (rosetta strips its own
# argv[0] and exposes argv[1..] to the guest).
run_check "basename" "^rosetta$" 0 "${STATICBIN}/basename" "/some/path/rosetta"
run_check "dirname" "^/a/b$" 0 "${STATICBIN}/dirname" "/a/b/c"

# Filesystem read: stat the rosetta binary itself, prove that openat
# against a real host path works.
run_check "stat-self" "regular file" 0 "${STATICBIN}/stat" "$ROSETTA_PATH"

# Compute-heavy: factor a small number through libc / busybox arith.
run_check "factor" "^60: 2 2 3 5$" 0 "${STATICBIN}/factor" "60"

# seq writes one integer per line. Build the expected joined output and
# match against the captured stdout via the helper.
seq_out="$(printf '%s\n' 1 2 3 4 5)"
out_seq="$("$TIMEOUT" 5 "$ELFUSE" "${STATICBIN}/seq" 1 5 2> /dev/null || true)"
total=$((total + 1))
if [ "$out_seq" = "$seq_out" ]; then
    report_pass "seq"
else
    report_fail "seq: output mismatch"
    printf '         got: %q\n         want: %q\n' "$out_seq" "$seq_out" >&2
fi

# Hash families exercise libc memcpy and per-byte loops.
input_tmp="${SHORTDIR}/input"
echo -n "rosetta" > "$input_tmp"
run_check "sha256sum" "^[0-9a-f]{64}  " 0 \
    "${STATICBIN}/sha256sum" "$input_tmp"
run_check "md5sum" "^[0-9a-f]{32}  " 0 \
    "${STATICBIN}/md5sum" "$input_tmp"

# Date + uname use clock_gettime and uname syscalls; their guest-side ABI
# translation (translate_clockid, sys_uname) covers a different surface.
run_check "uname-m" "^x86_64$" 0 "${STATICBIN}/uname" "-m"
# Busybox 'arch' applet (separate dispatch from uname -m) confirms the
# rosetta-translated guest reports its actual ISA via the dedicated
# applet entry-point. Both forms must agree.
run_check "arch" "^x86_64$" 0 "${STATICBIN}/busybox" "arch"
run_check "busybox-arch-subcommand" "^x86_64$" 0 \
    "${STATICBIN}/busybox" "arch"

# date: TZ propagates the same way as ELFUSE_PROBE above (wrap elfuse,
# don't pass env to elfuse as argv[1]).
total=$((total + 1))
set +e
date_out="$(env TZ=UTC "$ELFUSE" "${STATICBIN}/date" 2> /dev/null)"
date_rc=$?
set -e
if [ "$date_rc" = "0" ] && printf '%s' "$date_out" | grep -Eq '^[A-Z][a-z]{2} '; then
    report_pass "date-utc"
else
    report_fail "date-utc: rc=$date_rc out=$(printf '%q' "$date_out")"
fi

# id / nproc hit getuid + sysconf; nproc returns the host cpu count.
run_check "id-u" "^0$|^[0-9]+$" 0 "${STATICBIN}/id" "-u"
run_check "nproc" "^[1-9][0-9]*$" 0 "${STATICBIN}/nproc"

# ---------------------------------------------------------------------------
# Mid-process execve into x86_64 (rosetta re-bootstrap).
# ---------------------------------------------------------------------------

# env executes its argv[1] via execve. The post-reset rosetta re-bootstrap
# path now handles x86_64 -> x86_64 mid-process execve, so the child
# (env -> true) must exit 0. A timeout (rc=124) indicates a hang in the
# re-bootstrap, distinct from a clean rejection.
total=$((total + 1))
set +e
env_rc=$(
    "$TIMEOUT" 10 "$ELFUSE" "${STATICBIN}/env" "${STATICBIN}/true" \
        > /dev/null 2>&1
    printf '%s' "$?"
)
set -e
if [ "$env_rc" = "0" ]; then
    report_pass "env-execve (rosetta re-bootstrap)"
elif [ "$env_rc" = "124" ]; then
    report_fail "env-execve: timed out (likely hang in re-bootstrap)"
else
    report_fail "env-execve: rc=$env_rc (expected 0)"
fi

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
