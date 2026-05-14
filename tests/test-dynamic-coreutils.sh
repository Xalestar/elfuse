#!/usr/bin/env bash
# test-dynamic-coreutils.sh — Dynamically-linked GNU coreutils test suite for elfuse
#
# Copyright 2026 elfuse contributors
# Copyright 2025 Moritz Angermann, zw3rk pte. ltd.
# SPDX-License-Identifier: Apache-2.0
#
# shellcheck disable=SC1091,SC2034,SC2059,SC2154
#
# Shared entry point for dynamic coreutils coverage through elfuse --sysroot.
#
# Usage: tests/test-dynamic-coreutils.sh <elfuse-binary> <sysroot-dir> <coreutils-bin-dir>
# Example: tests/test-dynamic-coreutils.sh build/elfuse $GUEST_SYSROOT $GUEST_DYNAMIC_COREUTILS/bin

set -euo pipefail

ELFUSE="${1:?Usage: $0 <elfuse-binary> <sysroot-dir> <coreutils-bin-dir>}"
SYSROOT="${2:?Usage: $0 <elfuse-binary> <sysroot-dir> <coreutils-bin-dir>}"
BIN="${3:?Usage: $0 <elfuse-binary> <sysroot-dir> <coreutils-bin-dir>}"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
COREUTILS_PROFILE="${COREUTILS_PROFILE:-full}"
TEST_RUNNER=("$ELFUSE" --sysroot "$SYSROOT")
TEST_LABEL_WIDTH=14
TEST_TIMEOUT=10
TEST_SKIP_MISSING_TOOLS=0
if [ "$COREUTILS_PROFILE" = "smoke" ]; then
    TEST_SKIP_MISSING_TOOLS=1
fi
source "$SCRIPT_DIR/lib/test-runner.sh"
source "$SCRIPT_DIR/lib/coreutils-common.sh"
source "$SCRIPT_DIR/lib/coreutils-suite.sh"

TMPDIR=$(coreutils_make_tmpdir)
trap 'rm -rf "$TMPDIR"' EXIT

coreutils_populate_fixtures "$TMPDIR"

coreutils_print_suite_header "${SUITE_LABEL:-Dynamic GNU coreutils test suite (--sysroot)}"
coreutils_run_suite "$COREUTILS_PROFILE"
if [ "$COREUTILS_PROFILE" = "smoke" ]; then
    run_skip chroot "needs root privileges"
else
    run chroot 0 "/" "$BIN/true"
fi
coreutils_print_summary "${SUITE_SUMMARY:-Dynamic results}"

if [ "$fail" -gt 0 ]; then
    exit 1
fi
exit 0
