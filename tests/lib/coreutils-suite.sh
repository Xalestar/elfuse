#!/usr/bin/env bash
# Shared GNU coreutils suite definitions
#
# Copyright 2026 elfuse contributors
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

coreutils_suite_basic_text()
{
    coreutils_print_section "Output / text utilities"
    run_check cat "hello world" "$TMPDIR/hello.txt"
    run_check echo "hello" "hello"
    run_check printf "42" "%d" 42
    run_timeout 2 yes 124
    run_check head "line1" "$TMPDIR/lines.txt"
    run_check tail "line5" "$TMPDIR/lines.txt"
    run_check wc "5" "-l" "$TMPDIR/lines.txt"
    run_check sort "^apple" "$TMPDIR/unsorted.txt"
    run_check uniq "aaa" "$TMPDIR/dups.txt"
    run_check cut "b" "-d:" "-f2" "$TMPDIR/delim.txt"
    run_pipe tr "HELLO" "hello" "a-z" "A-Z"
    run_check paste "one" "$TMPDIR/tabs.txt"
    run_check nl "hello" "$TMPDIR/hello.txt"
    run_check od "0000000" "-c" "$TMPDIR/hello.txt"
}

coreutils_suite_extended_text()
{
    run_check expand "one" "$TMPDIR/tabs.txt"
    run_check unexpand "one" "$TMPDIR/tabs.txt"
    run_check fmt "hello world" "$TMPDIR/hello.txt"
    run_check fold "hello" "-w5" "$TMPDIR/hello.txt"
    run_check pr "hello" "-l20" "$TMPDIR/hello.txt"
    run_check tac "line5" "$TMPDIR/lines.txt"
    run_check comm "apple" "$TMPDIR/unsorted.txt" "$TMPDIR/unsorted.txt"
    run_check join "a:b:c" "$TMPDIR/delim.txt" "$TMPDIR/delim.txt"
    run_check ptx "hello" "$TMPDIR/hello.txt"
    run_pipe tsort "a" "a b\nb c\n"
    run_check shuf "line" "-n1" "$TMPDIR/lines.txt"
    run split 0 "-l2" "$TMPDIR/lines.txt" "$TMPDIR/split-"
    coreutils_assert_exists "split xaa" "$TMPDIR/split-aa"
    run csplit 0 "-f" "$TMPDIR/xx" "$TMPDIR/lines.txt" 3
    coreutils_assert_exists "csplit xx00" "$TMPDIR/xx00"
}

coreutils_suite_basic_encoding()
{
    coreutils_print_section "Encoding / hashing"
    # Optional binaries (base32/basenc/sha224sum/sha384sum/b2sum/sum) are
    # gated by test_skip_missing_tool inside run_check: when the wrapper
    # sets TEST_SKIP_MISSING_TOOLS=1 they report SKIP with accounting,
    # otherwise the missing binary surfaces as a hard FAIL. The previous
    # raw "if [ -e ... ]; then" blocks bypassed both paths, silently
    # erasing assertions whenever the binary was absent.
    run_check base32 "NBSWY" "$TMPDIR/hello.txt"
    run_check base64 "aGVsbG8" "$TMPDIR/hello.txt"
    run_check basenc "aGVsbG8" "--base64" "$TMPDIR/hello.txt"
    run_check md5sum "hello.txt" "$TMPDIR/hello.txt"
    run_check sha1sum "hello.txt" "$TMPDIR/hello.txt"
    run_check sha224sum "95041d" "$TMPDIR/hello.txt"
    run_check sha256sum "hello.txt" "$TMPDIR/hello.txt"
    run_check sha384sum "6b3b69" "$TMPDIR/hello.txt"
    run_check sha512sum "hello.txt" "$TMPDIR/hello.txt"
    run_check b2sum "hello.txt" "$TMPDIR/hello.txt"
    run_check cksum "hello.txt" "$TMPDIR/hello.txt"
    run_check sum "[0-9]" "$TMPDIR/hello.txt"
}

coreutils_suite_basic_files()
{
    coreutils_print_section "File operations"

    run cp 0 "$TMPDIR/hello.txt" "$TMPDIR/hello-copy.txt"
    coreutils_assert_file_equals "cp preserved data" \
        "$TMPDIR/hello-copy.txt" "$TMPDIR/hello.txt"

    run mv 0 "$TMPDIR/hello-copy.txt" "$TMPDIR/hello-moved.txt"
    coreutils_assert_not_exists "mv removed source" "$TMPDIR/hello-copy.txt"
    coreutils_assert_file_equals "mv preserved data" \
        "$TMPDIR/hello-moved.txt" "$TMPDIR/hello.txt"

    run rm 0 "$TMPDIR/hello-moved.txt"
    coreutils_assert_not_exists "rm removed file" "$TMPDIR/hello-moved.txt"

    run ln 0 "-s" "$TMPDIR/hello.txt" "$TMPDIR/newlink.txt"
    coreutils_assert_symlink_target "ln -s target" \
        "$TMPDIR/newlink.txt" "$TMPDIR/hello.txt"

    run link 0 "$TMPDIR/hello.txt" "$TMPDIR/hardlink.txt"
    coreutils_assert_file_equals "link preserved data" \
        "$TMPDIR/hardlink.txt" "$TMPDIR/hello.txt"

    run unlink 0 "$TMPDIR/hardlink.txt"
    coreutils_assert_not_exists "unlink removed hardlink" "$TMPDIR/hardlink.txt"

    run mkdir 0 "$TMPDIR/newdir"
    coreutils_assert_exists "mkdir created dir" "$TMPDIR/newdir"

    run rmdir 0 "$TMPDIR/newdir"
    coreutils_assert_not_exists "rmdir removed dir" "$TMPDIR/newdir"

    run mkfifo 0 "$TMPDIR/testfifo"
    coreutils_assert_fifo "mkfifo created fifo" "$TMPDIR/testfifo"

    run touch 0 "$TMPDIR/touched.txt"
    coreutils_assert_exists "touch created file" "$TMPDIR/touched.txt"

    run truncate 0 "-s0" "$TMPDIR/touched.txt"
    coreutils_assert_size "truncate size 0" "$TMPDIR/touched.txt" 0

    run install 0 "-m" "644" "$TMPDIR/hello.txt" "$TMPDIR/installed.txt"
    coreutils_assert_file_equals "install preserved data" \
        "$TMPDIR/installed.txt" "$TMPDIR/hello.txt"
    coreutils_assert_mode "install mode 644" "$TMPDIR/installed.txt" 644

    run dd 0 "if=$TMPDIR/hello.txt" "of=$TMPDIR/dd-out.txt" "bs=12" "count=1"
    coreutils_assert_file_equals "dd preserved block" \
        "$TMPDIR/dd-out.txt" "$TMPDIR/hello.txt"

    run sync 0
    run_check mktemp "$TMPDIR/" "-p" "$TMPDIR"
}

coreutils_suite_extended_files()
{
    run shred 0 "-u" "$TMPDIR/touched.txt"
    coreutils_assert_not_exists "shred removed file" "$TMPDIR/touched.txt"
}

coreutils_suite_basic_info()
{
    coreutils_print_section "File info"
    run_check ls "hello.txt" "$TMPDIR"
    run_check dir "hello.txt" "$TMPDIR"
    run_check vdir "hello.txt" "$TMPDIR"
    run_check stat "File:" "$TMPDIR/hello.txt"
    run_check du "[0-9]" "-s" "$TMPDIR"
    run_check df "Filesystem" "$TMPDIR"
    run_check readlink "$TMPDIR/hello.txt" "$TMPDIR/symlink.txt"
    run_check realpath "hello.txt" "$TMPDIR/hello.txt"

    coreutils_print_section "Path utilities"
    run_check basename "hello.txt" "$TMPDIR/hello.txt"
    run_check dirname "$TMPDIR" "$TMPDIR/hello.txt"
    run_check pathchk "" "$TMPDIR/hello.txt"
    run_check pwd "/"
}

coreutils_suite_extended_info()
{
    run_check dircolors "COLOR" "-b"
}

coreutils_suite_basic_math()
{
    coreutils_print_section "Math / sequence"
    run_check seq "5" "1" "5"
    run_check expr "3" "1" "+" "2"
    run_check factor "2 2 3" "12"
    # numfmt is optional in some packages; rely on test_skip_missing_tool
    # so absence becomes a SKIP under TEST_SKIP_MISSING_TOOLS=1 and a FAIL
    # otherwise, rather than a silent omission.
    run_check numfmt "1\\.0[kK]" "--to=si" "1000"
}

coreutils_suite_basic_sysinfo()
{
    coreutils_print_section "System info"
    run_check uname "Linux" "-s"
    run_check date "202" "+%Y"
    run_check nproc "[0-9]"
    run_check printenv "/" "PATH"
    run_check id "uid="
}

coreutils_suite_extended_sysinfo()
{
    run_check uptime "load average"
    run_check hostid "[0-9a-f]"
}

coreutils_suite_basic_process()
{
    coreutils_print_section "Process utilities"
    run true 0
    run false 1
    run sleep 0 "0"
    run env 0 "$BIN/true"
    run nice 0 "$BIN/true"
    run nohup 0 "$BIN/true"
    run_check kill "TERM" "-l"
    run timeout 124 "1" "$BIN/sleep" "5"
}

coreutils_suite_extended_permissions()
{
    coreutils_print_section "Permissions / ownership"
    run chmod 0 "644" "$TMPDIR/hello.txt"
    coreutils_assert_mode "chmod mode 644" "$TMPDIR/hello.txt" 644
    run chown 1 "root:root" "$TMPDIR/hello.txt"
    run chgrp 0 "root" "$TMPDIR/hello.txt"
    run mknod 1 "$TMPDIR/testnode" "c" "1" "1"
}

coreutils_suite_extended_users()
{
    coreutils_print_section "User info"
    run_check whoami "user"
    run logname 1
    run_check groups "user"
    run_check pinky "Login" "-l" "user"
    run who 0
    run users 0
}

coreutils_suite_extended_terminal()
{
    coreutils_print_section "Terminal"
    run tty 1
    run stty 1
}

coreutils_suite_extended_io()
{
    coreutils_print_section "I/O utilities"
    run_pipe tee "hello world" "hello world\n" "$TMPDIR/tee-out.txt"
    coreutils_assert_contains "tee wrote file" "$TMPDIR/tee-out.txt" "^hello world$"
}

coreutils_suite_extended_special()
{
    coreutils_print_section "Special / test"
    run test 0 "-f" "$TMPDIR/hello.txt"
    run "[" 0 "-f" "$TMPDIR/hello.txt" "]"

    coreutils_print_section "Expected failures / skips"
    run_timeout 10 timeout 0 "5" "$BIN/true"
    run_skip stdbuf "requires LD_PRELOAD"
}

coreutils_run_smoke_suite()
{
    coreutils_suite_basic_text
    coreutils_suite_basic_encoding
    coreutils_suite_basic_files
    coreutils_suite_basic_info
    coreutils_suite_basic_math
    coreutils_suite_basic_sysinfo
    coreutils_suite_basic_process
}

coreutils_run_full_suite()
{
    coreutils_suite_basic_text
    coreutils_suite_extended_text
    coreutils_suite_basic_encoding
    coreutils_suite_basic_files
    coreutils_suite_extended_files
    coreutils_suite_basic_info
    coreutils_suite_extended_info
    coreutils_suite_basic_math
    coreutils_suite_basic_sysinfo
    coreutils_suite_extended_sysinfo
    coreutils_suite_basic_process
    coreutils_suite_extended_permissions
    coreutils_suite_extended_users
    coreutils_suite_extended_terminal
    coreutils_suite_extended_io
    coreutils_suite_extended_special
}

coreutils_run_suite()
{
    local profile="${1:?missing profile}"
    case "$profile" in
        smoke) coreutils_run_smoke_suite ;;
        full) coreutils_run_full_suite ;;
        *)
            echo "unknown coreutils suite profile: $profile" >&2
            return 1
            ;;
    esac
}
