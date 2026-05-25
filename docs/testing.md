# Building And Testing

This document describes the development toolchain, the main `make` targets, and
how the repository validation flow is structured.

## Build Requirements

Host build requirements:

- Apple Silicon macOS host
- Xcode Command Line Tools
- `clang`
- `codesign`
- GNU `make`
- GNU `objcopy` or `llvm-objcopy`

Guest test builds additionally require:

- An AArch64 Linux cross-compiler for C test programs
- An AArch64 bare-metal toolchain for the assembly smoke test

The repository defaults are defined in `mk/toolchain.mk`, but these variables
are intended to be overridden when needed:

- `CROSS_COMPILE`
- `BAREMETAL_CROSS`
- `SIGN_IDENTITY`

## Main Targets

The most useful development targets are:

```sh
make elfuse
make check
make test-rosetta-all
make test-gdbstub
make test-matrix
make lint
make clean
```

What they do:

- `make elfuse`: build and sign `build/elfuse`
- `make check`: unit suite from `tests/manifest.txt` followed by the BusyBox
  applet smoke suite. The BusyBox binary is auto-resolved from
  `externals/test-fixtures/aarch64-musl/staticbin/bin/busybox` if present, or
  downloaded into `build/busybox` on first run.
- `make test-rosetta-all`: Rosetta-specific x86_64 acceptance scripts
  (`test-rosetta-cli`, `test-rosetta-failure-modes`,
  `test-rosetta-statics`, `test-rosetta-alpine`,
  `test-rosetta-audit`, `test-rosetta-jit`, `test-rosetta-glibc`)
- `make test-busybox`: just the BusyBox suite, useful when iterating on a
  single applet failure without rerunning the unit suite
- `make test-fuse-alpine`: validate guest `/dev/fuse` + `mount("fuse")`
  against the Alpine musl sysroot fixture
- `make test-gdbstub`: debugger integration checks against the built-in GDB stub
- `make test-matrix`: broader `elfuse` and QEMU cross-check
- `make lint`: static analysis through `clang-tidy`

## Quick Iteration

For normal code changes:

```sh
make elfuse
make check
```

For changes that touch procfs, path handling, `/dev`, FUSE, networking, dynamic
linking, or guest process semantics, run the matrix as well:

```sh
make test-matrix
```

`make check` already runs the BusyBox applet suite as a second stage, so a
green `make check` covers BusyBox validation. Use `make test-busybox` to
iterate on a single applet failure without rerunning the unit suite.

## Test Matrix

The matrix driver lives in `tests/test-matrix.sh`. It currently covers three
execution modes:

- `elfuse-aarch64`: every binary is executed via `build/elfuse` on macOS
- `qemu-aarch64`: the same binaries run natively inside an Alpine
  `aarch64-linux-musl` minirootfs booted by `qemu-system-aarch64`
- `elfuse-x86_64`: Rosetta-for-Linux acceptance scripts against the staged
  Alpine x86_64 fixture tree

The goal is not to compare performance. The goal is to compare guest-observable
behavior against a ground-truth Linux AArch64 environment so that any divergence
in syscall translation, procfs emulation, or process semantics is caught early.
The x86_64 mode is narrower: it aggregates the Rosetta-specific acceptance
scripts and their per-binary summaries into the same matrix runner, including
the Rosetta thread/signal audit smoke, the LuaJIT guest-JIT probe, and the
glibc dynamic-binary acceptance helper.

Run a single mode with `bash tests/test-matrix.sh elfuse-aarch64`,
`bash tests/test-matrix.sh qemu-aarch64`, or
`bash tests/test-matrix.sh elfuse-x86_64`; `all` runs all three back-to-back.

Fixture handling is self-contained:

- On first use, `tests/fetch-fixtures.sh` downloads the required Alpine
  packages and the `linux-virt` kernel into `externals/test-fixtures/` and
  assembles an initramfs. Subsequent runs are zero-config.
- The same fixture tree is reused across the matrix modes.
- When Rosetta mode is requested and the translator is installed,
  `tests/test-matrix.sh` auto-fetches the x86_64 fixture tree
  (`INCLUDE_X86_64=1`) on demand.
- QEMU mode requires `qemu-system-aarch64` on `PATH` (Homebrew `qemu`
  provides it).
- musl is the only Alpine libc; the glibc-dynamic suite is skipped unless
  `GUEST_GLIBC_*` environment variables point at an external sysroot.

## Rosetta Limitations

`elfuse-x86_64` is expected to inherit two Rosetta-internal limitations that are
not treated as elfuse regressions:

- `SA_RESETHAND` is not reset reliably because Rosetta shadows guest signal
  handler state internally. This matches the vendored `externals/hyper-linux`
  reference behavior.
- `clone(..., CLONE_SETTLS, tls=0, ...)` can hang. The upstream reproducer is
  the raw-thread path in `externals/hyper-linux/test/test-thread.c`, and the
  same limitation is documented in `externals/hyper-linux/hl.1`.

The x86_64 matrix branch is therefore a Rosetta acceptance gate, not a claim
that translated guests fully match native Linux thread and signal semantics.

## x86_64 Acceptance Inventory and Per-Host Baselines

The `elfuse-x86_64` matrix mode aggregates seven sub-suites. Each one
emits a deterministic per-binary pass list; the matrix runner sums
those into a single `Results:` line and compares against a per-host
baseline. The exact labels each sub-suite emits, and the contract
they verify, are:

- `tests/test-rosetta-cli.sh` (4): `rosetta-disabled-flag`,
  `rosetta-disabled-env`, `rosetta-gdb`, `rosetta-default` --
  command-line gating of the translator path (opt-out flag, env
  override, `--gdb` rejection, install-hint surface).

- `tests/test-rosetta-failure-modes.sh` (3): `no-rosetta-flag`,
  `no-rosetta-env`, `gdb-x86_64` -- command-line rejection paths.
  Self-contained against a synthesized minimal x86_64 ELF; no
  external fixture tree required. The dynamic-linker bring-up and
  mid-process execve scenarios that used to live here are now
  exclusively in the glibc and statics suites against the vendored
  rootfs (see `glibc-hello` / `glibc-hello-via-ldso` and
  `env-execve`).

- `tests/test-rosetta-statics.sh` (20): `echo`, `true`, `false`,
  `printenv`, `expr-zero`, `expr-mul`, `basename`, `dirname`,
  `stat-self`, `factor`, `seq`, `sha256sum`, `md5sum`, `uname-m`, `arch`,
  `busybox-arch-subcommand`, `date-utc`, `id-u`, `nproc`,
  `env-execve` -- statically-linked Alpine busybox applets,
  exercising VZ ioctl gate, `/proc/self/exe` redirect, high-VA mmap,
  and the kbuf alias.

- `tests/test-rosetta-alpine.sh` (33): `cat-fruits-first-line`,
  `wc-l-fruits`, `wc-l-lines`, `wc-c-lines`, `ls-data`, `stat-data`,
  `find-by-name`, `du-sk-data`, `sha256-fruits`,
  `sha256-lines-matches-host`, `sha512-lines`, `md5-fruits`,
  `cksum-fruits`, `sort-first`, `sort-reverse-first`, `pipe-sort-wc`,
  `pipe-tr-uppercase`, `pipe-cat-grep`, `pipe-sed-subst`,
  `pipe-awk-field`, `head-n3`, `tail-n3`, `pipe-sort-uniq`,
  `pipe-cut-field`, `pipe-rev`, `tac-reverse-first-line`, `seq-1-5`,
  `seq-step`, `factor-prime`, `factor-composite`, `diff-identical`,
  `diff-differs`, `pipe-base64-decode` -- broader file I/O, text
  processing, and host-shell pipelines stitched through Rosetta on
  every stage.

- `tests/test-rosetta-audit.sh` (2): `audit-known-limitations`,
  `tls0-known-hang` -- bookkeeping probe that asserts the documented
  Rosetta shadowing failures (above) remain the only divergences;
  fails loudly if a new threading/signal-state edge case starts
  diverging.

- `tests/test-rosetta-jit.sh` (2): `luajit-trace`,
  `luajit-coroutine` -- guest-side JIT under translation
  (LuaJIT trace emission + coroutine allocation), covering the
  small-mprotect RW->RX and per-thread icache observation path that
  rosetta's own JIT does not exercise.

- `tests/test-rosetta-glibc.sh` (7): `glibc-hello`,
  `glibc-hello-via-ldso`, `glibc-hello-list`, `glibc-dlopen`,
  `glibc-tls`, `glibc-gdtls`, `glibc-pthread-tls` --
  dynamically-linked glibc x86_64 binary acceptance through
  `--sysroot` against the staged minimal glibc rootfs under
  `externals/test-fixtures/x86_64-glibc/rootfs/`. The first three
  cover load-time `PT_INTERP` resolution and `ld.so --list`
  introspection. `glibc-dlopen` runs `dlopen("libm.so.6")` plus a
  `dlsym(sqrt)` round-trip to exercise the runtime fresh-`.so`-mmap
  codepath, which is distinct from the load-time path the first
  three probes touch. `glibc-tls` reads and writes two
  initial-exec `__thread` variables (one integer, one pointer) so a
  broken FS-register to `TPIDR_EL0` translation surfaces as a
  value mismatch rather than as a silent skip. `glibc-gdtls`
  `dlopen`s a companion `libgdtls.so` whose `__thread` variable
  must use the general-dynamic model (calls `__tls_get_addr`);
  this is the only probe that exercises that lowering path, which
  the initial-exec probe cannot reach. `glibc-pthread-tls`
  `pthread_create`s a worker thread that reads and writes its own
  `__thread` slot; the probe asserts the worker saw its own
  default value (not the main thread's overwritten marker) and that
  the main thread's slot survives the worker's write, so a broken
  per-thread `TPIDR_EL0` setup on additional threads surfaces as
  isolation failure rather than as a silent crash.

Total: 71 expected passes, 0 expected failures.

### Per-Host Baseline Capture

The matrix runner keys its `elfuse-x86_64` baseline by detected host
SoC class. Two classes matter because `sys_mmap_fixed_high_va` takes
different paths under different IPA widths:

- `apple-m1-m2`: 36-bit native IPA, exercises the overflow-segment
  path. Captured on this codebase against Apple M1 hardware
  (MacBookAir10,1). The seven sub-suites land at 73/0/0.

- `apple-m3-plus`: 40-bit native IPA, exercises the bisected-slab
  path (and the M5 slab-bisection variant). Currently held equal to
  `apple-m1-m2` pending operator capture on real M3+ hardware. When
  that capture lands, only the
  `EXPECTED_MIN_PASS[elfuse-x86_64:apple-m3-plus]` and
  `EXPECTED_FAIL[elfuse-x86_64:apple-m3-plus]` entries in
  `tests/test-matrix.sh` move; the M1/M2 row stays intact.

- `apple-unknown`: fallback for SoC brand strings the detector does
  not recognise. Inherits the M1/M2 numbers and triggers a one-line
  warning so a new SoC does not silently graft onto an existing row.

Class detection reads `sysctl -n machdep.cpu.brand_string` and matches
against `Apple M1`/`Apple M2` (M1/M2) and `Apple M3`/`Apple M4`/`Apple
M5` (M3+). To exercise the M3+ row from an M1/M2 host (and vice
versa) without changing the detector, set
`MATRIX_HOST_CLASS_OVERRIDE=apple-m3-plus` (or `apple-m1-m2`,
`apple-unknown`) before invoking `tests/test-matrix.sh`.

When the seven sub-suites grow or trim a test, the per-sub-suite
counts in the comment block above `EXPECTED_MIN_PASS` and the
inventory list above must move in the same commit so the per-host
baseline stays in sync with reality.

## Test Inventory

The repository contains several layers of validation:

- unit-style guest tests compiled from `tests/*.c`
- shell integration suites such as BusyBox, coreutils, and dynamic-loader tests
- debugger integration tests for the GDB stub
- native macOS HVF checks such as multi-vCPU and RWX validation

The quick suite is driven by `tests/driver.sh`, which supports:

- `-f PATTERN` to filter tests
- `-l` to list them
- `-T` for TAP output

Example:

```sh
bash tests/driver.sh -f test-proc
```

## Validation Strategy By Change Type

Suggested minimum validation:

| Change area | Recommended validation |
|-------------|------------------------|
| CLI, logging, docs-only build rules | `make elfuse` |
| General syscall or runtime logic | `make elfuse && make check` |
| `/proc`, `/dev`, path, or BusyBox-sensitive behavior | `make elfuse && make check` |
| Broad behavioral changes | `make elfuse && make check && make test-matrix` |
| Debugger or ptrace flow | `make elfuse && make test-gdbstub` |
