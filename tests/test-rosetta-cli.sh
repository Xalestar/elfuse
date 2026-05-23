#!/usr/bin/env bash
# test-rosetta-cli.sh - Exercise x86_64/Rosetta CLI gating paths
#
# Copyright 2026 elfuse contributors
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

ELFUSE="${1:-build/elfuse}"

tmpdir="$(mktemp -d "${TMPDIR:-/tmp}/elfuse-rosetta-cli.XXXXXX")"
trap 'rm -rf "$tmpdir"' EXIT

x64_elf="$tmpdir/min-x86_64.elf"

python3 - "$x64_elf" << 'PY'
import struct
import sys

path = sys.argv[1]
ehdr = struct.pack(
    "<16sHHIQQQIHHHHHH",
    b"\x7fELF" + bytes([2, 1, 1, 0]) + bytes(8),
    2,          # ET_EXEC
    62,         # EM_X86_64
    1,          # EV_CURRENT
    0x400000,   # e_entry
    64,         # e_phoff
    0,          # e_shoff
    0,          # e_flags
    64,         # e_ehsize
    56,         # e_phentsize
    1,          # e_phnum
    0, 0, 0,
)
phdr = struct.pack(
    "<IIQQQQQQ",
    1,          # PT_LOAD
    5,          # PF_R | PF_X
    0,          # p_offset
    0x400000,   # p_vaddr
    0,          # p_paddr
    0,          # p_filesz
    0x1000,     # p_memsz
    0x1000,     # p_align
)
with open(path, "wb") as f:
    f.write(ehdr)
    f.write(phdr)
PY

run_expect_fail()
{
    local label="$1"
    local pattern="$2"
    shift 2

    local stderr="$tmpdir/${label}.stderr"
    if "$@" > /dev/null 2> "$stderr"; then
        printf 'FAIL %s: command succeeded unexpectedly\n' "$label" >&2
        cat "$stderr" >&2
        exit 1
    fi
    if ! grep -q -- "$pattern" "$stderr"; then
        printf 'FAIL %s: stderr did not contain %s\n' "$label" "$pattern" >&2
        cat "$stderr" >&2
        exit 1
    fi
    printf 'PASS %s\n' "$label"
}

# Rosetta is on by default and architecture is auto-detected from the ELF
# header; --no-rosetta opts out, and the rejection message points at the
# right flag.
run_expect_fail "rosetta-disabled-flag" \
    "x86_64 ELF rejected by --no-rosetta" \
    "$ELFUSE" --no-rosetta "$x64_elf"

run_expect_fail "rosetta-disabled-env" \
    "x86_64 ELF rejected by --no-rosetta" \
    env ELFUSE_NO_ROSETTA=1 "$ELFUSE" "$x64_elf"

run_expect_fail "rosetta-gdb" \
    "--gdb is not supported for x86_64 guests" \
    "$ELFUSE" --gdb 4010 "$x64_elf"

# With Rosetta installed, elfuse bootstrap now reaches the translator and
# rosettad bridge. Depending on host/runtime state, the remaining gaps can
# fail in rosettad's translation cache path, in Rosetta's high-VA allocator,
# or with the translator's own VZ-environment complaint. On hosts without
# Rosetta installed the failure surfaces earlier with an install hint.
# Accept any of those Rosetta-specific signatures to avoid masking unrelated
# elfuse failures.
run_expect_fail "rosetta-default" \
    "requires the Rosetta Linux translator\\|translate produced empty/missing output\\|Translation failed, invalid path or invalid executable\\|VMAllocationTracker\\|Rosetta is only intended to run on Apple Silicon" \
    "$ELFUSE" "$x64_elf"
