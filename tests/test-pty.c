/* PTY ioctl regression test
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Foot, sshd, tmux, and any libvte-derived terminal need the multiplexer
 * primitives glibc's posix_openpt(3) / ptsname(3) / openpty(3) stack rests
 * on. Exercise the four pieces wired in for issue #88:
 *
 *   1. TIOCSWINSZ on the /dev/ptmx master fd (the direct failure foot saw)
 *   2. TIOCGPTN -> /dev/pts/N path round trip
 *   3. TIOCSPTLCK(0) for unlockpt(), plus non-zero lock request fd typing
 *   4. /dev/pts/N open + stat intercept and the slave fd's window size
 *
 * The test stays self-contained on the syscall surface (no libutil/openpty),
 * so it runs the same way under elfuse-aarch64, qemu-aarch64, and any future
 * elfuse-x86_64 reuse.
 */

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>

#include "test-harness.h"

#ifndef TIOCSWINSZ
#define TIOCSWINSZ 0x5414
#endif
#ifndef TIOCGPTN
#define TIOCGPTN 0x80045430
#endif
#ifndef TIOCSPTLCK
#define TIOCSPTLCK 0x40045431
#endif
#ifndef TIOCGPTPEER
#define TIOCGPTPEER 0x5441
#endif

int passes = 0, fails = 0;

int main(void)
{
    printf("test-pty: PTY ioctl + /dev/pts/N path support (issue #88)\n");

    /* Regression guard for the pty_keepalive_table BSS-zero collision: any
     * close that runs before the very first /dev/ptmx open would walk the
     * still-zero-initialized table and match a master_host_fd of zero,
     * silently closing the wrong slave_host_fd (also zero). Closing stdin
     * here forces fd_cleanup_entry to invoke proc_pty_close_keepalive in
     * that vulnerable window. If the fix regresses, every subsequent test
     * still passes locally but a future stdio fd in another vCPU may go
     * missing. The cheap sentinel makes sure stdin's close itself does
     * not corrupt elfuse's own file table.
     */
    close(STDIN_FILENO);

    int ptmx = open("/dev/ptmx", O_RDWR | O_NOCTTY);
    TEST("open(/dev/ptmx, O_RDWR | O_NOCTTY)");
    EXPECT_TRUE(ptmx >= 0, "open /dev/ptmx failed");
    if (ptmx < 0) {
        SUMMARY("test-pty");
        return 1;
    }

    /* TIOCSWINSZ on the master is the direct regression from issue #88.
     * Before the fix, sys_ioctl had no case for it and fell through to the
     * default -ENOTTY arm, breaking foot's terminal initialization.
     */
    TEST("TIOCSWINSZ on /dev/ptmx master");
    struct winsize ws_set = {
        .ws_row = 40,
        .ws_col = 132,
        .ws_xpixel = 1056,
        .ws_ypixel = 640,
    };
    EXPECT_TRUE(ioctl(ptmx, TIOCSWINSZ, &ws_set) == 0, "TIOCSWINSZ failed");

    TEST("TIOCGWINSZ round-trips the values set above");
    struct winsize ws_get = {0};
    int ok = ioctl(ptmx, TIOCGWINSZ, &ws_get) == 0 && ws_get.ws_row == 40 &&
             ws_get.ws_col == 132 && ws_get.ws_xpixel == 1056 &&
             ws_get.ws_ypixel == 640;
    EXPECT_TRUE(ok, "TIOCGWINSZ round trip mismatch");

    TEST("TIOCSPTLCK(0) unlocks the slave");
    int unlock = 0;
    EXPECT_TRUE(ioctl(ptmx, TIOCSPTLCK, &unlock) == 0, "TIOCSPTLCK(0) failed");

    /* Linux TIOCSPTLCK(non-zero) locks the slave and returns success.
     * elfuse cannot actually enforce the lock on macOS (no re-lock primitive)
     * but must still report success so callers do not misread the result as
     * "this kernel has no devpts".
     */
    TEST("TIOCSPTLCK(1) accepted as best-effort no-op");
    int lock = 1;
    EXPECT_TRUE(ioctl(ptmx, TIOCSPTLCK, &lock) == 0, "TIOCSPTLCK(1)");

    TEST("TIOCSPTLCK(1) rejects a regular file");
    char lock_template[] = "/tmp/elfuse-pty-lock-XXXXXX";
    int regular = mkstemp(lock_template);
    if (regular < 0) {
        FAIL("mkstemp failed");
    } else {
        EXPECT_ERRNO(ioctl(regular, TIOCSPTLCK, &lock), ENOTTY,
                     "regular fd accepted TIOCSPTLCK(1)");
        close(regular);
        unlink(lock_template);
    }

    TEST("TIOCSPTLCK(1) rejects a pipe");
    int lock_pipe[2];
    if (pipe(lock_pipe) != 0) {
        FAIL("pipe(lock_pipe) failed");
    } else {
        EXPECT_ERRNO(ioctl(lock_pipe[0], TIOCSPTLCK, &lock), ENOTTY,
                     "pipe fd accepted TIOCSPTLCK(1)");
        close(lock_pipe[0]);
        close(lock_pipe[1]);
    }

    TEST("TIOCGPTN returns a numeric slave id");
    unsigned int ptyno = (unsigned int) -1;
    EXPECT_TRUE(ioctl(ptmx, TIOCGPTN, &ptyno) == 0 && ptyno < 100000u,
                "TIOCGPTN failed");

    TEST("stat(/dev/pts) succeeds and reports a directory");
    struct stat pts_dir_st;
    int pts_dir_statrc = stat("/dev/pts", &pts_dir_st);
    EXPECT_TRUE(pts_dir_statrc == 0 && S_ISDIR(pts_dir_st.st_mode),
                "stat /dev/pts failed");

    TEST("open(/dev/pts, O_DIRECTORY) succeeds");
    int pts_dir_fd = open("/dev/pts", O_RDONLY | O_DIRECTORY);
    EXPECT_TRUE(pts_dir_fd >= 0, "open /dev/pts directory failed");
    if (pts_dir_fd >= 0)
        close(pts_dir_fd);

    TEST("readdir(/dev/pts) lists the active slave id");
    DIR *pts_dir = opendir("/dev/pts");
    if (!pts_dir) {
        FAIL("opendir /dev/pts failed");
    } else {
        char want[32];
        snprintf(want, sizeof(want), "%u", ptyno);
        int saw_ptyno = 0;
        struct dirent *ent;
        while ((ent = readdir(pts_dir))) {
            if (!strcmp(ent->d_name, want)) {
                saw_ptyno = 1;
                break;
            }
        }
        closedir(pts_dir);
        EXPECT_TRUE(saw_ptyno, "active pts id missing from /dev/pts");
    }

    char pts_path[32];
    snprintf(pts_path, sizeof(pts_path), "/dev/pts/%u", ptyno);

    /* glibc ptsname(3) stats the formatted path before returning it.
     * Until the path.c stat allowlist included /dev/pts/N, the stat went
     * to the host (which has no /dev/pts at all) and ptsname returned
     * ENOENT, leaving every caller without a usable slave path.
     */
    TEST("stat(/dev/pts/N) succeeds and reports a char device");
    struct stat st;
    int statrc = stat(pts_path, &st);
    EXPECT_TRUE(statrc == 0 && S_ISCHR(st.st_mode), "stat /dev/pts/N failed");

    TEST("stat(/dev/pts/N) major is Linux pts (136)");
    EXPECT_EQ(major(st.st_rdev), 136, "wrong pts major");

    TEST("open(/dev/pts/N) returns a usable slave fd");
    int slave = open(pts_path, O_RDWR | O_NOCTTY);
    EXPECT_TRUE(slave >= 0, "open /dev/pts/N failed");

    if (slave >= 0) {
        TEST("TIOCGWINSZ on the slave reflects the master-side update");
        struct winsize ws_slave = {0};
        int slave_ok = ioctl(slave, TIOCGWINSZ, &ws_slave) == 0 &&
                       ws_slave.ws_row == 40 && ws_slave.ws_col == 132;
        EXPECT_TRUE(slave_ok, "slave winsize mismatch");

        TEST("TIOCSPTLCK(1) rejects the pty slave");
        EXPECT_ERRNO(ioctl(slave, TIOCSPTLCK, &lock), ENOTTY,
                     "slave fd accepted TIOCSPTLCK(1)");

        TEST("TIOCSWINSZ on the slave propagates back to the master");
        struct winsize ws_resize = {
            .ws_row = 24,
            .ws_col = 80,
            .ws_xpixel = 0,
            .ws_ypixel = 0,
        };
        if (ioctl(slave, TIOCSWINSZ, &ws_resize) != 0) {
            FAIL("slave TIOCSWINSZ failed");
        } else {
            struct winsize ws_after = {0};
            int after_ok = ioctl(ptmx, TIOCGWINSZ, &ws_after) == 0 &&
                           ws_after.ws_row == 24 && ws_after.ws_col == 80;
            EXPECT_TRUE(after_ok, "master did not see slave resize");
        }

        close(slave);
    }

    /* TIOCGPTPEER short-circuits the ptsname/stat/open dance. Recent foot
     * and util-linux prefer it; older kernels return ENOTTY and the caller
     * falls back to /dev/pts. Accept either an fd or ENOTTY (some hosts
     * legitimately do not implement it), but never silent corruption. */
    TEST("TIOCGPTPEER returns a slave fd or ENOTTY");
    int peer = ioctl(ptmx, TIOCGPTPEER, O_RDWR | O_NOCTTY);
    int peer_ok = peer >= 0 || (peer == -1 && errno == ENOTTY);
    EXPECT_TRUE(peer_ok, "TIOCGPTPEER returned unexpected status");
    if (peer >= 0)
        close(peer);

    /* dup of the master must keep both aliases functional even after the
     * original is closed. The keepalive slave needs to be mirrored across
     * the dup so the surviving alias still observes master-side tty ioctls.
     */
    TEST("dup(ptmx) followed by close(orig) leaves alias usable");
    int alias = dup(ptmx);
    if (alias < 0) {
        FAIL("dup(ptmx) failed");
    } else {
        close(ptmx);
        struct winsize ws_alias = {.ws_row = 50, .ws_col = 100};
        if (ioctl(alias, TIOCSWINSZ, &ws_alias) != 0) {
            FAIL("TIOCSWINSZ on alias after closing original");
        } else {
            struct winsize ws_check = {0};
            int alias_ok = ioctl(alias, TIOCGWINSZ, &ws_check) == 0 &&
                           ws_check.ws_row == 50 && ws_check.ws_col == 100;
            EXPECT_TRUE(alias_ok, "alias winsize did not stick");
        }
        ptmx = alias; /* the alias is the live master from here on */
    }

    /* Fork must propagate the master's keepalive across the IPC handoff so
     * the child can do master-side tty ioctls without the macOS ENOTTY
     * fallback. The parent's keepalive slave fd is independent (each side
     * holds its own slot) so closing one side does not affect the other.
     */
    TEST("child fork inherits master keepalive (TIOCSWINSZ works)");
    int sync_pipe[2];
    if (pipe(sync_pipe) != 0) {
        FAIL("pipe(sync_pipe) failed");
    } else {
        pid_t pid = fork();
        if (pid < 0) {
            FAIL("fork failed");
            close(sync_pipe[0]);
            close(sync_pipe[1]);
        } else if (pid == 0) {
            /* Child: do master-side TIOCSWINSZ and report rc via pipe. */
            close(sync_pipe[0]);
            struct winsize ws_child = {
                .ws_row = 30,
                .ws_col = 90,
            };
            int rc = ioctl(ptmx, TIOCSWINSZ, &ws_child);
            char status = (rc == 0) ? 'Y' : 'N';
            (void) !write(sync_pipe[1], &status, 1);
            close(sync_pipe[1]);
            _exit(rc == 0 ? 0 : 1);
        } else {
            close(sync_pipe[1]);
            char status = '?';
            ssize_t n = read(sync_pipe[0], &status, 1);
            close(sync_pipe[0]);
            int wstatus = 0;
            waitpid(pid, &wstatus, 0);
            int child_ok = (n == 1) && (status == 'Y') && WIFEXITED(wstatus) &&
                           WEXITSTATUS(wstatus) == 0;
            EXPECT_TRUE(child_ok, "child TIOCSWINSZ on master failed");
            /* Parent should still see the child's update because the slave
             * keepalive in the parent is still alive. */
            struct winsize ws_parent = {0};
            int parent_ok = ioctl(ptmx, TIOCGWINSZ, &ws_parent) == 0 &&
                            ws_parent.ws_row == 30 && ws_parent.ws_col == 90;
            TEST("parent observes the child's master-side resize");
            EXPECT_TRUE(parent_ok, "parent winsize mismatch after child");
        }
    }

    close(ptmx);

    /* Re-open and immediately close should not leak the keepalive slave.
     * Without the proc_pty_close_keepalive call in sys_close's fast path,
     * single-thread close goes through fd_close_regular_relaxed and
     * bypasses fd_cleanup_entry, leaving the hidden slave fd open until
     * elfuse exits. Loop enough times to expose any per-close leak.
     */
    TEST("repeated open/close does not exhaust the keepalive table");
    int leak_loop_ok = 1;
    for (int i = 0; i < 300; i++) {
        int f = open("/dev/ptmx", O_RDWR | O_NOCTTY);
        if (f < 0) {
            leak_loop_ok = 0;
            break;
        }
        close(f);
    }
    EXPECT_TRUE(leak_loop_ok,
                "repeated /dev/ptmx open/close exhausted the keepalive table");

    /* A pty master received via SCM_RIGHTS bypasses the /dev/ptmx open
     * intercept, so the receiver process has no keepalive entry for it.
     * proc_pty_master_adopt must lazily register one before master-side tty
     * ioctls, even when TIOCSWINSZ runs before the first TIOCGPTN. Two
     * checks live inside this block: TIOCSWINSZ-first and the post-adopt
     * stat(/dev/pts/N). Each has its own TEST() label below.
     */
    int sp[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sp) != 0) {
        TEST("socketpair for SCM_RIGHTS adoption setup");
        FAIL("socketpair failed");
    } else {
        int donor = open("/dev/ptmx", O_RDWR | O_NOCTTY);
        if (donor < 0) {
            FAIL("donor open(/dev/ptmx) failed");
            close(sp[0]);
            close(sp[1]);
        } else {
            char iobuf = 'x';
            struct iovec iov = {.iov_base = &iobuf, .iov_len = 1};
            char ctrl[CMSG_SPACE(sizeof(int))] = {0};
            struct msghdr msg = {.msg_iov = &iov,
                                 .msg_iovlen = 1,
                                 .msg_control = ctrl,
                                 .msg_controllen = sizeof(ctrl)};
            struct cmsghdr *cm = CMSG_FIRSTHDR(&msg);
            cm->cmsg_level = SOL_SOCKET;
            cm->cmsg_type = SCM_RIGHTS;
            cm->cmsg_len = CMSG_LEN(sizeof(int));
            memcpy(CMSG_DATA(cm), &donor, sizeof(int));
            ssize_t sent = sendmsg(sp[0], &msg, 0);
            close(donor);
            if (sent < 0) {
                FAIL("sendmsg(SCM_RIGHTS) failed");
            } else {
                char rbuf;
                struct iovec riov = {.iov_base = &rbuf, .iov_len = 1};
                char rctrl[CMSG_SPACE(sizeof(int))] = {0};
                struct msghdr rmsg = {.msg_iov = &riov,
                                      .msg_iovlen = 1,
                                      .msg_control = rctrl,
                                      .msg_controllen = sizeof(rctrl)};
                ssize_t got = recvmsg(sp[1], &rmsg, 0);
                if (got < 0) {
                    FAIL("recvmsg(SCM_RIGHTS) failed");
                } else {
                    struct cmsghdr *rcm = CMSG_FIRSTHDR(&rmsg);
                    int recv_master = -1;
                    if (rcm && rcm->cmsg_level == SOL_SOCKET &&
                        rcm->cmsg_type == SCM_RIGHTS)
                        memcpy(&recv_master, CMSG_DATA(rcm), sizeof(int));
                    if (recv_master < 0) {
                        TEST("SCM_RIGHTS recv yields a master fd");
                        FAIL("recv_master fd not received");
                    } else {
                        TEST("TIOCSWINSZ first on SCM_RIGHTS-received master");
                        struct winsize ws_recv = {
                            .ws_row = 33,
                            .ws_col = 101,
                            .ws_xpixel = 808,
                            .ws_ypixel = 528,
                        };
                        EXPECT_TRUE(
                            ioctl(recv_master, TIOCSWINSZ, &ws_recv) == 0,
                            "TIOCSWINSZ before TIOCGPTN on "
                            "SCM_RIGHTS-received master");
                        TEST("TIOCGPTN on SCM_RIGHTS-received master");
                        unsigned int recv_ptyno = (unsigned int) -1;
                        int gpn_rc = ioctl(recv_master, TIOCGPTN, &recv_ptyno);
                        EXPECT_TRUE(gpn_rc == 0 && recv_ptyno < 100000u,
                                    "TIOCGPTN on SCM_RIGHTS-received master");
                        char recv_pts_path[32];
                        snprintf(recv_pts_path, sizeof(recv_pts_path),
                                 "/dev/pts/%u", recv_ptyno);
                        TEST("stat(/dev/pts/N) after SCM_RIGHTS adoption");
                        struct stat recv_st;
                        EXPECT_TRUE(stat(recv_pts_path, &recv_st) == 0 &&
                                        S_ISCHR(recv_st.st_mode),
                                    "stat after SCM_RIGHTS adoption failed");
                        close(recv_master);
                    }
                }
            }
            close(sp[0]);
            close(sp[1]);
        }
    }

    SUMMARY("test-pty");
    return fails > 0 ? 1 : 0;
}
