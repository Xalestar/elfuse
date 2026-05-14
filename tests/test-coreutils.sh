#!/usr/bin/env bash
# test-coreutils.sh — GNU coreutils integration suite for elfuse
#
# Copyright 2026 elfuse contributors
# Copyright 2025 Moritz Angermann, zw3rk pte. ltd.
# SPDX-License-Identifier: Apache-2.0
#
# shellcheck disable=SC1091,SC2034,SC2059,SC2154
#
# Shared entry point for both smoke and full coreutils coverage.
#
# Usage: tests/test-coreutils.sh <elfuse-binary> <coreutils-bin-dir> [sysroot]
# Example: tests/test-coreutils.sh build/elfuse /path/to/coreutils/bin /path/to/sysroot

set -euo pipefail

ELFUSE="${1:?Usage: $0 <elfuse-binary> <coreutils-bin-dir>}"
BIN="${2:?Usage: $0 <elfuse-binary> <coreutils-bin-dir>}"
SYSROOT="${3:-}"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
COREUTILS_PROFILE="${COREUTILS_PROFILE:-full}"
TEST_RUNNER=("$ELFUSE")
if [ -n "$SYSROOT" ]; then
    TEST_RUNNER+=(--sysroot "$SYSROOT")
fi
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

coreutils_print_suite_header "${SUITE_LABEL:-GNU coreutils integration suite}"
coreutils_run_suite "$COREUTILS_PROFILE"
run_skip chroot "needs root privileges"
coreutils_print_summary "${SUITE_SUMMARY:-Results}"

if [ "$fail" -gt 0 ]; then
    exit 1
fi
exit 0
