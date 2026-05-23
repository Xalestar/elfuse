#!/usr/bin/env bash
# test-rosetta-failure-modes.sh - Probe known x86_64-via-Rosetta limits
#
# Copyright 2026 elfuse contributors
# SPDX-License-Identifier: Apache-2.0
#
# Verifies that known-unsupported scenarios fail with a clear, stable
# error rather than crashing or succeeding silently. Treats the failure
# itself as the test: every probe is expected to exit non-zero AND emit
# a recognisable error fragment.
#
# Categories covered:
#   1. Mid-process aarch64 -> x86_64 execve: rejected -ENOEXEC
#   2. Dynamic x86_64 binary (PT_INTERP): "failed to mmap segment"
#   3. --gdb on x86_64 ELF: rejected by main.c
#   4. --no-rosetta with x86_64: rejected at exec.c
#   5. ELFUSE_NO_ROSETTA=1 with x86_64: same rejection via env
#
# Usage: tests/test-rosetta-failure-modes.sh [path/to/elfuse]

set -euo pipefail

ELFUSE_INPUT="${1:-build/elfuse}"
case "$ELFUSE_INPUT" in
    /*) ELFUSE="$ELFUSE_INPUT" ;;
    *) ELFUSE="$(pwd)/$ELFUSE_INPUT" ;;
esac

FIXTURES="${FIXTURES_DIR:-externals/test-fixtures}"
STATICBIN_LONG="${FIXTURES}/x86_64-musl/staticbin/bin"
DYNBIN_LONG="${FIXTURES}/x86_64-musl/dyn-bin"
SHORTDIR=/tmp/elfuse-rfm

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

# Expect a non-zero exit AND a stderr fragment match.
# Args: <label> <stderr-grep-pattern> <command...>
probe_fail()
{
    local label="$1" pattern="$2"
    shift 2
    total=$((total + 1))

    local stderr rc
    stderr="$(mktemp "${SHORTDIR}/${label}.XXXXXX.stderr")"
    set +e
    "$TIMEOUT" 5 "$@" > /dev/null 2> "$stderr"
    rc=$?
    set -e

    if [ "$rc" = "0" ]; then
        report_fail "$label: unexpected success (rc=0)"
        head -3 "$stderr" >&2 || true
        return
    fi
    if ! grep -Eq -- "$pattern" "$stderr"; then
        report_fail "$label: stderr missing /$pattern/ (rc=$rc)"
        head -3 "$stderr" >&2 || true
        return
    fi
    report_pass "$label (rc=$rc)"
}

# Pre-flight.
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

mkdir -p "$SHORTDIR"
trap 'rm -rf "$SHORTDIR"' EXIT

# Synthesize a minimal x86_64 ELF (header-only, no segments worth loading).
# This is enough to drive the CLI gates that key on e_machine = EM_X86_64.
min_elf="${SHORTDIR}/min-x86_64.elf"
python3 - "$min_elf" << 'PY'
import struct, sys
ehdr = struct.pack("<16sHHIQQQIHHHHHH",
    b"\x7fELF" + bytes([2, 1, 1, 0]) + bytes(8),
    2, 62, 1, 0x400000, 64, 0, 0, 64, 56, 1, 0, 0, 0)
phdr = struct.pack("<IIQQQQQQ",
    1, 5, 0, 0x400000, 0, 0, 0x1000, 0x1000)
open(sys.argv[1], "wb").write(ehdr + phdr)
PY

# --- Gating tests that do not require Rosetta to be installed ---------------

probe_fail "no-rosetta-flag" \
    "x86_64 ELF rejected by --no-rosetta" \
    "$ELFUSE" --no-rosetta "$min_elf"

probe_fail "no-rosetta-env" \
    "x86_64 ELF rejected by --no-rosetta" \
    env ELFUSE_NO_ROSETTA=1 "$ELFUSE" "$min_elf"

probe_fail "gdb-x86_64" \
    "--gdb is not supported for x86_64 guests" \
    "$ELFUSE" --gdb 4242 "$min_elf"

# --- Tests that require Rosetta + fixtures ---------------------------------

# Bootstrap the x86_64 fixture tree on-demand when rosetta is installed but
# the staging dir is absent. Keeps `make test-rosetta-failure-modes`
# self-sufficient on a fresh checkout instead of silently skipping the two
# rosetta-dependent probes. The fetch is cached on disk so the first run
# pays the download cost and every subsequent run is a no-op.
if [ -x /Library/Apple/usr/libexec/oah/RosettaLinux/rosetta ] \
    && {
        [ ! -d "$DYNBIN_LONG" ] || [ ! -d "$STATICBIN_LONG" ]
    }; then
    printf 'staging x86_64 fixture tree (one-time download via fetch-fixtures.sh)\n'
    INCLUDE_X86_64=1 bash "$(dirname "$0")/fetch-fixtures.sh" \
        > /dev/null 2>&1 || true
fi

if [ ! -x /Library/Apple/usr/libexec/oah/RosettaLinux/rosetta ]; then
    report_skip "dynamic-x86_64-segment-mmap (rosetta not installed)"
    report_skip "mid-process-execve-x86_64 (rosetta not installed)"
else
    # Stage a short-path symlink farm so rosetta's 42-byte caps field does
    # not truncate fixture paths in a normal checkout.
    [ -d "$DYNBIN_LONG" ] \
        && ln -sfn "$(cd "$DYNBIN_LONG" && pwd)" "${SHORTDIR}/dyn"
    [ -d "$STATICBIN_LONG" ] \
        && ln -sfn "$(cd "$STATICBIN_LONG" && pwd)" "${SHORTDIR}/sb"

    # Probe 1: dynamic binary. PT_INTERP load currently fails with
    # rosetta error "failed to mmap segment: 12". The probe only needs
    # the dyn-bin tree; missing staticbin does not affect it.
    if [ ! -d "${SHORTDIR}/dyn" ] \
        || [ -z "$(ls -A "${SHORTDIR}/dyn" 2> /dev/null)" ]; then
        report_skip "dynamic-x86_64-segment-mmap (dyn-bin fixtures missing)"
    else
        dyn_pick=""
        for cand in echo cat ls true uname; do
            if [ -x "${SHORTDIR}/dyn/${cand}" ]; then
                dyn_pick="${SHORTDIR}/dyn/${cand}"
                break
            fi
        done
        if [ -z "$dyn_pick" ]; then
            report_skip "dynamic-x86_64-segment-mmap (no dyn binary found)"
        else
            probe_fail "dynamic-x86_64-segment-mmap" \
                "failed to mmap segment|Translation failed" \
                "$ELFUSE" "$dyn_pick"
        fi
    fi

    # Probe 2: mid-process execve into x86_64. busybox env spawns its argv[1]
    # via execve. As of the rosetta re-bootstrap landing this is supported,
    # so this is now a positive probe: env <true> must exit 0 with no
    # output, exercising the post-reset rosetta_prepare re-entry branch +
    # the bridge-idle drain in sys_execve. Only needs the staticbin tree.
    if [ -x "${SHORTDIR}/sb/env" ] && [ -x "${SHORTDIR}/sb/true" ]; then
        total=$((total + 1))
        set +e
        env_exec_rc=$(
            "$TIMEOUT" 10 "$ELFUSE" "${SHORTDIR}/sb/env" \
                "${SHORTDIR}/sb/true" > /dev/null 2>&1
            printf '%s' "$?"
        )
        set -e
        if [ "$env_exec_rc" = "0" ]; then
            report_pass "mid-process-execve-x86_64 (rosetta re-bootstrap)"
        else
            report_fail "mid-process-execve-x86_64: rc=$env_exec_rc (expected 0)"
        fi
    else
        report_skip "mid-process-execve-x86_64 (staticbin env/true missing)"
    fi
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
