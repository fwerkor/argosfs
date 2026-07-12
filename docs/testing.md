# Testing ArgosFS

ArgosFS uses two layers of filesystem tests.

## Library and CLI Tests

`cargo test` exercises the Rust volume, journal, ACL, import/export, path
encoding, repair, and command-line paths without mounting FUSE. These tests are
fast, deterministic, and suitable for every CI runner.

Raw/loop backend checks:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
scripts/tests/host/cli_features.sh
scripts/tests/host/loop_backend.sh
scripts/tests/host/block_lifecycle.sh
scripts/tests/host/crash_consistency.sh --unprivileged
scripts/tests/host/initramfs_dry_run.sh
scripts/tests/host/rootfs_smoke.sh
```

Privileged checks are provided but skip unless the environment is ready:

```bash
sudo ARGOSFS_RAW_TEST_DEVICES=/dev/...,/dev/... scripts/tests/host/raw_backend.sh --force
scripts/tests/host/privileged_fuse.sh
scripts/qemu/boot.sh
scripts/qemu/ops.sh
scripts/qemu/hotplug.sh
```

Loop/raw integration tests include raw superblock backup recovery, duplicate
device detection, one-missing-image degraded read, rootfs fail-closed preflight,
raw extent corruption repair, and raw data-write crash injection before journal
commit. The crash script runs only unprivileged crash/replay cases by default;
raw block devices, FUSE mounts, and QEMU boot are explicit privileged/local
checks and print a skip reason when unavailable.
`scripts/qemu/ops.sh` extends the QEMU boot check by activating the serial
console and running rootfs operations: verify the ArgosFS `/` mount, verify the
initramfs root marker under `/run`, read `/etc/openwrt_release`, exercise
create/read/symlink/delete on `/tmp`, and call `sync`.


`scripts/tests/host/cli_features.sh` is the fast host-backed feature gate used by the
CI architecture matrix. It covers CLI create/read/write/stat/ls/cat/get, chmod,
truncate, symlink, rename, snapshot, POSIX ACL, NFSv4 ACL, transparent
compression, encryption with re-encryption, scrub, fsck, journal verification,
and health output.

`scripts/tests/host/block_lifecycle.sh` is the non-destructive loop-block device
lifecycle gate. It creates a three-device pool, imports a dataset, adds a new
device, drains and removes an old device, replaces another device, reshapes the
pool, scrubs/fscks it, exports the dataset, and checks byte-for-byte equality.

`scripts/compat/run_deep_roundtrip.sh` adds host-filesystem import/export
coverage for byte-preserving names, hardlinks, symlinks, xattrs, metadata, and
CLI path literals. Its default mode does not require `/dev/fuse`.

## Real Mounted-FUSE Tests

`scripts/compat/with_fuse_mount.sh` is the shared mounted-test fixture. It:

- builds `target/release/argosfs`;
- creates a temporary ArgosFS volume and mountpoint;
- mounts through the real FUSE frontend;
- waits for readiness with `mountpoint(1)`;
- exports `ARGOSFS_COMPAT_MOUNTPOINT`, `ARGOSFS_COMPAT_ROOT`, and
  `ARGOSFS_COMPAT_WORKDIR` to the command it runs;
- unmounts and removes temporary files through a trap.

It skips with JSONL output when `/dev/fuse`, kernel FUSE support,
`fusermount3`/`fusermount`, `mountpoint(1)`, or Python 3 are unavailable.

Run the mounted compatibility suite with:

```bash
scripts/compat/run_mounted_fuse_compat.sh
```

The mounted suite performs normal Unix syscalls through the mounted directory:
create/read/write/truncate, `chmod`, permitted `chown`, `utimensat`/`stat`,
`user.*` xattrs, symlink/readlink, hardlink inode equality, non-UTF-8 byte
filenames, rename overwrite, `RENAME_NOREPLACE` when the kernel exposes it,
sticky directory setup and cross-user enforcement when uid switching is
available, concurrent readers/writers, `fsync`, and `sync`.
Timestamp checks require sub-millisecond round trips because the current
metadata format stores times as floating-point seconds.

The unmounted integration suite also covers sparse-file `SEEK_DATA`/`SEEK_HOLE`
planning from ArgosFS block extents. Mounted FUSE `lseek` forwards those queries
after flushing any dirty writeback extent for the inode.
FUSE `copy_file_range` is wired through the same range read/write path and is
covered by unmounted range-copy tests.
`fallocate(mode=0)` extends regular files with zero-filled allocated ranges;
advanced fallocate modes such as punch-hole and keep-size currently return
`ENOTSUP`.

`scripts/compat/run_fuse_smoke.sh` remains a quick mounted smoke check for basic
I/O and metadata.

## pjdfstest

Run the default pjdfstest subset on a temporary ArgosFS mount with:

```bash
scripts/compat/run_pjdfstest.sh target/argosfs-artifacts/compat/pjdfstest.jsonl
```

Or run against an existing ArgosFS mount:

```bash
scripts/compat/run_pjdfstest.sh --mounted /mnt/argosfs target/argosfs-artifacts/compat/pjdfstest.jsonl
```

The wrapper refuses to run unless `mountpoint(1)` confirms the target is an
actual mounted filesystem. The general-purpose wrapper emits a structured skip
when `prove` or a pjdfstest checkout is absent. Required CI uses
`scripts/tests/host/pjdfstest_compat.sh`, checks out pjdfstest explicitly, mounts
with `allow_other,default_permissions`, runs the subset as root, and treats any
missing prerequisite as a failure. Clone pjdfstest at `./pjdfstest` or set
`PJDFSTEST_ROOT=/path/to/pjdfstest` for local runs.

The default subset is:

```text
chmod chown link mkdir open rename rmdir symlink truncate unlink utimensat
```

Override it with `ARGOSFS_PJDFSTEST_TESTS="open rename unlink"` when narrowing a
local debug run.

## xfstests-Style Local Runs

The full xfstests generic suite is not enabled in default CI because it expects
root-managed scratch devices, loopback or block-device setup, and kernel-level
test controls that are not reliably available on GitHub-hosted runners. For
local compatibility work, use the mounted harness to create the ArgosFS mount,
then point selected generic tests at that mount from an xfstests checkout.

Recommended local prerequisites:

```bash
sudo apt-get install -y build-essential pkg-config libfuse3-dev fuse3 attr acl \
  perl python3
```

Optional:

```bash
# pjdfstest
git clone https://github.com/pjd/pjdfstest.git

# xfstests and its distro-specific dependencies
git clone https://git.kernel.org/pub/scm/fs/xfs/xfstests-dev.git
```


## CI Matrix

The default GitHub Actions workflow splits validation into parallel jobs:

- Rust format, Clippy, and docs on x86_64.
- Rust unit/integration tests on x86_64 and arm64 GitHub-hosted Linux runners.
- Host CLI feature tests on x86_64 and arm64.
- Loop-block lifecycle tests on x86_64 and arm64.
- Compatibility/rootfs suites split by test family, including mandatory
  cross-user FUSE permission enforcement and a real pjdfstest checkout.
- Artifact-gated QEMU boot, guest operation, and hotplug harnesses for x86_64
  and arm64.
- CapOS target compile smoke jobs for `x86_64` and `armsr_armv8`.


## Weekly High-Intensity Chaos CI

`Weekly high-intensity chaos CI` runs on Saturday and can also be dispatched
manually. It contains three independent gates so a failure in one family does
not hide results from the others:

- The randomized reference-model matrix generates 12 fresh cryptographic
  64-bit seeds by default for each run. Every seed runs independently on
  x86_64 and arm64 with 1,200 operations against a 4+2 volume. The generated
  seed set, commit, run ID, parameters, operation stream, and exported-tree
  checkpoints are retained for exact replay. Manual dispatch accepts explicit
  comma-separated seeds for reproducing a prior failure.
- The mounted POSIX gate uses a real FUSE mount with
  `allow_other,default_permissions`. It switches UID and GID to verify owner,
  group, and other access; directory search permission; setgid inheritance;
  chown behavior; sticky-directory enforcement; and the configured pjdfstest
  subset. Missing FUSE or pjdfstest prerequisites fail this gate rather than
  producing a successful skip.
- The raw block fault gate creates loop-backed device-mapper devices, injects a
  real `EIO` target into one member, verifies read-write root preflight failure,
  performs concurrent degraded exports, restores the device, corrupts a raw
  data extent, requires scrub reconstruction, and finishes with fsck, journal,
  and byte-for-byte export checks.

A scheduled failure opens or updates an issue. The seed manifest and per-shard
artifacts provide the exact values needed to replay randomized and block-fault
runs.


## Full CapOS QEMU CI

The heavy `Full CapOS QEMU CI` workflow runs for pull requests, pushes to
`main`, manual dispatches, and its weekly schedule. The workflow builds
full CapOS images with ArgosFS as the root filesystem, discovers bootable QEMU
artifacts, then runs real guest tests instead of artifact-gated skips.

Default full targets:

- `x86_64` / CapOS `x86_64`
- `arm64` / CapOS `armsr_armv8`

The full guest test covers:

- booting the generated CapOS image under QEMU;
- verifying the ArgosFS root marker and `/` mounted through FUSE;
- ordinary root filesystem operations on `/root` rather than only `/tmp`;
- package database queries, UCI query, and init/service status queries when the
  image exposes those tools;
- running the `argosfs` CLI inside the guest;
- creating a guest ArgosFS volume and testing compression, encryption,
  re-encryption, scrub, fsck, journal verification, and health output;
- virtio block hot-add and hot-remove, including an ArgosFS raw-backend mkfs,
  import, readback, fsck, and scrub cycle on the hot-added disk;
- rebooting the guest and verifying rootfs persistence across journal replay;
- a mixed chaos scenario that keeps concurrent rootfs mutations active while a
  3+2 raw-pool member is physically hot-removed, verifies reads using exactly
  the minimum three members, replaces and scrubs the failed member, hard-kills
  QEMU during dirty root writes, and validates both rootfs and raw-pool recovery
  after reboot.

The workflow uploads the CapOS build logs, target configs, discovered QEMU
artifact manifest, serial logs, QEMU command files, and `bin/targets` outputs.

Known limits:

- The quick unprivileged mounted smoke suite may still skip `chown` or
  cross-user sticky checks, but the required mounted-permissions job covers
  those operations under a privileged UID-switching harness.
- `RENAME_NOREPLACE` is skipped only on kernels or architectures without
  `renameat2`.
- The complete xfstests generic suite remains local-run only; required CI uses
  the mounted compatibility and pjdfstest subsets plus dedicated block and QEMU
  fault scenarios.
