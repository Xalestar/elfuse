/*
 * Native-host unit test for shebang parsing.
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdarg.h>
#include <assert.h>

#include "core/elf.h"

#include "debug/log.h"

/* Dummy log implementation to avoid linking debug/log.o */
void log_impl(int level, const char *file, int line, const char *fmt, ...)
{
    (void) level;
    (void) file;
    (void) line;
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fprintf(stderr, "\n");
}

static char *write_temp_file(const char *content, size_t len)
{
    char template[] = "/tmp/elfuse-shebang-test-XXXXXX";
    int fd = mkstemp(template);
    if (fd < 0) {
        perror("mkstemp");
        exit(1);
    }
    if (write(fd, content, len) != (ssize_t) len) {
        perror("write");
        close(fd);
        exit(1);
    }
    close(fd);
    return strdup(template);
}

static void test_case(const char *content,
                      size_t content_len,
                      int expected_rc,
                      const char *expected_interp,
                      const char *expected_arg)
{
    char *path = write_temp_file(content, content_len);
    char interp[256] = {0};
    char arg[256] = {0};

    int rc = elf_read_shebang(path, interp, sizeof(interp), arg, sizeof(arg));
    unlink(path);
    free(path);

    if (rc != expected_rc) {
        fprintf(stderr, "FAIL: expected rc %d, got %d for content: '",
                expected_rc, rc);
        for (size_t i = 0; i < content_len && i < 20; i++) {
            if (content[i] == '\r')
                fprintf(stderr, "\\r");
            else if (content[i] == '\n')
                fprintf(stderr, "\\n");
            else
                fputc(content[i], stderr);
        }
        fprintf(stderr, "'\n");
        exit(1);
    }

    if (rc == 1) {
        if (strcmp(interp, expected_interp) != 0) {
            fprintf(stderr, "FAIL: expected interp '%s', got '%s'\n",
                    expected_interp, interp);
            exit(1);
        }
        if (strcmp(arg, expected_arg) != 0) {
            fprintf(stderr, "FAIL: expected arg '%s', got '%s'\n", expected_arg,
                    arg);
            exit(1);
        }
    }
}

int main(void)
{
    printf("Running shebang parsing unit tests...\n");

    /* 1. LF line ending */
    const char case1[] = "#! /bin/sh -x\nline2\n";
    test_case(case1, sizeof(case1) - 1, 1, "/bin/sh", "-x");

    /* 2. CRLF line ending */
    const char case2[] = "#!/usr/bin/env python\r\nline2\n";
    test_case(case2, sizeof(case2) - 1, 1, "/usr/bin/env", "python");

    /* 3. CR line ending */
    const char case3[] = "#!/bin/bash -e\rline2\n";
    test_case(case3, sizeof(case3) - 1, 1, "/bin/bash", "-e");

    /* 3b. Linux passes the whole optional suffix as one interpreter argument */
    const char case3b[] = "#!/usr/bin/env -S python3 -O\n";
    test_case(case3b, sizeof(case3b) - 1, 1, "/usr/bin/env", "-S python3 -O");

    /* 4. No trailing newline (EOF) */
    const char case4[] = "#!/bin/sh";
    test_case(case4, sizeof(case4) - 1, 1, "/bin/sh", "");

    /* 5. Blank/empty interpreter */
    const char case5[] = "#!  \n";
    test_case(case5, sizeof(case5) - 1, -ENOEXEC, "", "");

    /* 6. Not a shebang script */
    const char case6[] = "echo hello\n";
    test_case(case6, sizeof(case6) - 1, 0, "", "");

    /* 7. File too short */
    const char case7[] = "#";
    test_case(case7, sizeof(case7) - 1, 0, "", "");

    /* 8. Over-long/unterminated shebang line (exactly 511 bytes of 'a' without
     * EOL)
     */
    char case8[512];
    case8[0] = '#';
    case8[1] = '!';
    for (int i = 2; i < 511; i++) {
        case8[i] = 'a';
    }
    case8[511] = '\0';
    test_case(case8, 511, -ENOEXEC, "", "");

    /* 9. Long shebang line that IS terminated within 511 bytes */
    char case9[512];
    case9[0] = '#';
    case9[1] = '!';
    for (int i = 2; i < 510; i++) {
        case9[i] = 'a';
    }
    case9[510] = '\n';
    case9[511] = '\0';
    /* Since the interpreter is 508 characters, and our interp buffer is only
     * 256, it should return -ENOEXEC (buffer too small)
     */
    test_case(case9, 511, -ENOEXEC, "", "");

    printf("test-shebang-host: PASS\n");
    return 0;
}
