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
scripts/test_loop_backend.sh
scripts/test_crash_consistency.sh --unprivileged
scripts/test_initramfs_dry_run.sh
scripts/test_rootfs_smoke.sh
```

Privileged checks are provided but skip unless the environment is ready:

```bash
sudo ARGOSFS_RAW_TEST_DEVICES=/dev/...,/dev/... scripts/test_raw_backend.sh --force
scripts/test_privileged_fuse.sh
scripts/test_qemu_boot.sh
```

Loop/raw integration tests include raw superblock backup recovery, duplicate
device detection, one-missing-image degraded read, rootfs fail-closed preflight,
raw extent corruption repair, and raw data-write crash injection before journal
commit. The crash script runs only unprivileged crash/replay cases by default;
raw block devices, FUSE mounts, and QEMU boot are explicit privileged/local
checks and print a skip reason when unavailable.

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
scripts/compat/run_pjdfstest.sh paper-data/compat/pjdfstest.jsonl
```

Or run against an existing ArgosFS mount:

```bash
scripts/compat/run_pjdfstest.sh --mounted /mnt/argosfs paper-data/compat/pjdfstest.jsonl
```

The wrapper refuses to run unless `mountpoint(1)` confirms the target is an
actual mounted filesystem. If `prove` or a pjdfstest checkout is missing, it
emits a structured skipped record and exits successfully. Clone pjdfstest at
`./pjdfstest` or set `PJDFSTEST_ROOT=/path/to/pjdfstest`.

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

Known skipped cases:

- `chown` is skipped when the current user lacks permission.
- Cross-user sticky-directory enforcement is skipped unless the test process can
  switch uid.
- `RENAME_NOREPLACE` is skipped on kernels or architectures without
  `renameat2`.
- Full xfstests is local-run only until the project has a privileged, stable
  runner with scratch-device support.
