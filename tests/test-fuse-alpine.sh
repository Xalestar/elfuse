#!/usr/bin/env bash
# test-fuse-alpine.sh — Validate guest FUSE inside the Alpine musl sysroot.
#
# Copyright 2026 elfuse contributors
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

ELFUSE="${1:?Usage: $0 <elfuse-binary> <sysroot-dir> <guest-test-binary>}"
SYSROOT="${2:?Usage: $0 <elfuse-binary> <sysroot-dir> <guest-test-binary>}"
TEST_BIN="${3:?Usage: $0 <elfuse-binary> <sysroot-dir> <guest-test-binary>}"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TEST_LABEL_WIDTH=14
TEST_TIMEOUT=20
source "$SCRIPT_DIR/lib/test-runner.sh"

TEST_RUNNER=("$ELFUSE" --sysroot "$SYSROOT")

if [ ! -d "$SYSROOT" ]; then
    printf "%s\n" "missing sysroot: $SYSROOT" >&2
    exit 1
fi

if [ ! -x "$TEST_BIN" ]; then
    printf "%s\n" "missing test binary: $TEST_BIN" >&2
    exit 1
fi

mkdir -p "$SYSROOT/mnt/fuse"

printf "%b\n" "${BLUE}Dynamic FUSE test suite (Alpine sysroot)${RESET}"
if output=$(timeout "$TEST_TIMEOUT" "${TEST_RUNNER[@]}" "$TEST_BIN" 2>&1); then
    test_report ok "fuse-basic"
    pass=$((pass + 1))
else
    rc=$?
    test_report fail "fuse-basic" " (exit rc=$rc)"
    test_excerpt "$output"
    fail=$((fail + 1))
fi

printf "%b\n" "${BLUE}FUSE results${RESET}"
printf "  pass=%d fail=%d skip=%d xfail=%d\n" "$pass" "$fail" "$skip" "$expected_fail"

if [ "$fail" -gt 0 ]; then
    exit 1
fi
