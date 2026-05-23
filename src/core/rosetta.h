/* x86_64-via-Apple-Rosetta translator setup for elfuse.
 *
 * Copyright 2026 elfuse contributors
 * Copyright 2025 Moritz Angermann, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Two-phase API:
 * - rosetta_prepare() runs before guest_build_page_tables(), loading Rosetta
 *   binary into the primary buffer at a low GPA below interp_base, initializes
 *   the TTBR1 kbuf, and appends a non-identity mem_region_t so the page-table
 *   builder exposes the segments at their statically-linked high VA
 *   (0x800000000000). The primary-buffer placement is required because HVF o
 *   Apple Silicon caps Stage-2 hv_vm_map at the hardware-default IPA width (36
 *   bits on M1), so a separate high-IPA mapping is not viable.
 * - rosetta_finalize() runs after guest_build_page_tables(), installing TTBR0
 *   kbuf user-VA alias, builds the vDSO, registers semantic regions for
 *   /proc/self/maps, pre-opens the x86_64 binary at fd 3, constructs
 *   binfmt_misc-style argv, and refreshes proc state.
 *
 * Bootstrap-side wiring (placement, kbuf, page-tables, fd 3, binfmt argv, TTBR0
 * kbuf alias, VZ probe ioctls, rosettad socket bridge and AOT cache) is in. The
 * runtime still depends on the high-VA mmap body refactor for Rosetta's own
 * fixed-address slab and JIT allocations.
 */

#pragma once

#include <Hypervisor/Hypervisor.h>
#include <stdbool.h>
#include <stdint.h>

#include "core/elf.h"
#include "core/guest.h"

/* Apple Rosetta Linux translator path. The OS ships the binary inside the
 * platform image; users who have not run 'softwareupdate --install-rosetta'
 * will not have this file and elfuse must refuse the load with a helpful
 * error.
 */
#define ROSETTA_PATH "/Library/Apple/usr/libexec/oah/RosettaLinux/rosetta"

/* Path of Apple's standalone translator daemon. The 'elfuse rosettad
 * translate' subcommand re-execs into this binary inside an aarch64-linux
 * guest to materialise an AOT translation on cache miss.
 */
#define ROSETTAD_TRANSLATOR_PATH \
    "/Library/Apple/usr/libexec/oah/RosettaLinux/rosettad"

/* Rosetta's Virtualization.framework probe ioctls. Rosetta issues these on
 * an open fd very early at startup to verify that it is running inside a
 * supported VZ environment. Without affirmative responses, rosetta prints
 * "Rosetta is only intended to run on Apple Silicon ..." and exits.
 *
 * Reverse-engineered from the rosetta binary; values match what the
 * Lima-on-VZ Linux VM observes via strace.
 */
#define ROSETTA_VZ_CHECK 0x80456125 /* Returns 69-byte signature */
#define ROSETTA_VZ_CAPS 0x80806123  /* Returns 128-byte capability blob */
#define ROSETTA_VZ_ACTIVATE 0x6124  /* Activate VZ mode (just returns 1) */

/* VZ_CAPS buffer layout */
#define ROSETTA_CAPS_SIZE 128
#define ROSETTA_CAPS_VZ_ENABLE 0
#define ROSETTA_CAPS_SOCKET_PATH 1
#define ROSETTA_CAPS_SOCKET_PATH_LEN 64
#define ROSETTA_CAPS_BINARY_PATH 66
#define ROSETTA_CAPS_BINARY_PATH_LEN 42
#define ROSETTA_CAPS_VZ_SECONDARY 108
#define ROSETTA_VZ_SIG_LEN 69
#define ROSETTAD_SOCKET_PATH "/run/rosettad/rosetta.sock"

/* Record the x86_64 binary path for both Rosetta consumers:
 * - VZ_CAPS exposes a 42-byte inline path field to rosetta itself. When the
 *   original host path is longer, publish a short runtime alias instead of a
 *   truncated string.
 * - The host-side translate subprocess needs the full original path.
 * Subsequent calls overwrite the previous value (execve into a different
 * x86_64 binary).
 */
void rosettad_set_binary_path(const char *path, bool take_ownership);
void rosettad_clear_binary_path(void);

/* Snapshot the published paths into caller-supplied buffers under the
 * setter's mutex. Returns the byte count written (excluding NUL). The
 * lock keeps the VZ_CAPS reader (any vCPU) and the execve writer from
 * racing on the static buffer contents.
 *
 * Caller buffers:
 *   rosettad_snapshot_binary_path        - PATH_MAX wide for full host path
 *   rosettad_snapshot_caps_binary_path   - >= ROSETTA_CAPS_BINARY_PATH_LEN
 */
size_t rosettad_snapshot_binary_path(char *out_buf, size_t out_size);
size_t rosettad_snapshot_caps_binary_path(char *out_buf, size_t out_size);

/* rosettad wire protocol.
 *
 * Rosetta opens AF_UNIX SOCK_SEQPACKET and connects to a socket; macOS
 * lacks SOCK_SEQPACKET for AF_UNIX so elfuse intercepts socket(SEQPACKET)
 * with socketpair(SOCK_STREAM) and runs a handler thread on the other
 * end. The thread implements the single-byte command protocol below.
 *
 * Wire sequence (rosetta is the client, handler is the daemon):
 *   '?' (HANDSHAKE): handler replies one byte HIT (0x01) when ready.
 *   't' (TRANSLATE): rosetta sendmsg's the x86_64 binary fd via SCM_RIGHTS
 *       with up to 256 bytes of params. Handler computes SHA-256, checks
 *       the persistent AOT cache, on miss spawns the real rosettad to do
 *       the translation, then sends back {success_byte, 32-byte digest,
 *       AOT fd via SCM_RIGHTS in a 1-byte iov payload}.
 *   'd' (DIGEST): rosetta sends a 32-byte SHA-256 fingerprint; handler
 *       looks up the persistent cache and replies HIT + fd or MISS.
 *   'q' (QUIT): handler thread exits and closes its end of the socket.
 */
#define ROSETTAD_CMD_HANDSHAKE '?'
#define ROSETTAD_CMD_TRANSLATE 't'
#define ROSETTAD_CMD_DIGEST 'd'
#define ROSETTAD_CMD_QUIT 'q'

#define ROSETTAD_RESP_HIT 0x01
#define ROSETTAD_RESP_MISS 0x00

#define ROSETTAD_DIGEST_SIZE 32
#define ROSETTAD_DIGEST_HEX_LEN (ROSETTAD_DIGEST_SIZE * 2 + 1)

/* Persistent AOT cache directory, relative to $HOME. Real rosettad uses
 * ~/.cache/rosetta/ for its own .flu cache; elfuse's intercept runs in
 * parallel under a separate subdirectory to keep the two from colliding.
 */
#define ROSETTAD_CACHE_SUBDIR ".cache/elfuse-rosettad"

/* Spawn the rosettad handler thread on the elfuse-side end of the
 * socketpair. handler_fd is the host fd the thread reads/writes; client_fd
 * is the rosetta-visible side, recorded so rosettad_is_socket can later
 * identify it (sys_recvmsg / sys_sendmsg paths use this to decide whether
 * to take the rosettad-aware code branch).
 *
 * Returns 0 on success, -1 on pthread_create failure. The thread runs
 * detached; its lifetime is bounded by the client closing its fd (read
 * returns 0) or by an explicit ROSETTAD_CMD_QUIT.
 */
int rosettad_start_handler(int handler_fd, int client_fd);

/* True when host_fd is the rosetta-visible end of a socketpair installed
 * by rosettad_start_handler. Used by sys_connect to short-circuit the
 * connect (the socketpair is pre-wired) and by sendmsg/recvmsg to pick
 * the rosettad-aware code paths.
 */
bool rosettad_is_socket(int host_fd);

/* Block (with a short poll loop) until the rosettad bridge handler thread
 * has cleared its process-global client-fd marker, OR the timeout elapses.
 * Used by sys_execve before installing a fresh bridge so a stale handler
 * winding down does not collide with the new rosettad_start_handler CAS.
 *
 * Returns true if the bridge is idle on return, false if the timeout
 * expired with the bridge still claimed.
 */
bool rosettad_wait_for_idle(unsigned int max_ms);

/* Rosetta is statically linked at the 128 TiB mark. Stage-2 mapping installed
 * via guest_add_mapping covers this IPA; guest page tables map the VA range
 * identity-within-segment to that IPA.
 */
#define ROSETTA_VA_BASE_DEFAULT 0x800000000000ULL

typedef struct {
    elf_info_t rosetta_info;
    uint64_t entry_point; /* High-VA entry from rosetta ELF */
} rosetta_result_t;

/* First-pass rosetta setup, runs before guest_build_page_tables(): parse
 * the rosetta binary, place its segments in the primary buffer (or reload
 * into the existing placement on execve), initialise the TTBR1 kbuf, and
 * append page-table regions for the builder. A single non-identity
 * mem_region_t covers the rosetta image, mapping its statically-linked high
 * VA to the chosen low GPA via mem_region_t.va_base.
 *
 * The caller's regions array and *nregions cursor are updated. Returns 0 on
 * success, -1 on any failure; on failure g->rosetta_* state is left in the
 * configuration it had on entry (so a retry can succeed).
 */
int rosetta_prepare(guest_t *g,
                    const char *binary_path,
                    mem_region_t *regions,
                    int *nregions,
                    int max_regions,
                    bool verbose,
                    rosetta_result_t *result);

/* Second-pass rosetta setup, runs after guest_build_page_tables(): install
 * the TTBR0 user-VA alias for the kbuf, pre-open the x86_64 binary at fd 3,
 * build the binfmt_misc argv ([ROSETTA_PATH, binary, original argv[1..]])
 * for build_linux_stack to consume, and refresh proc state. The remaining
 * runtime blocker after this stage is high-VA mmap support for Rosetta's
 * own internal fixed-address allocations.
 */
int rosetta_finalize(guest_t *g,
                     hv_vcpu_t vcpu,
                     const char *binary_host_path,
                     bool binary_host_path_temp,
                     const char *binary_guest_path,
                     int guest_argc,
                     const char **guest_argv,
                     const rosetta_result_t *rr,
                     bool verbose,
                     int *out_argc,
                     const char ***out_argv,
                     uint64_t *out_vdso_addr);
