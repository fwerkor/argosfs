#!/usr/bin/env bash
set -euo pipefail

fail() {
  echo "guard failed: $*" >&2
  exit 1
}

require_absent() {
  local pattern="$1"
  local file="$2"
  local reason="$3"
  if grep -nE "$pattern" "$file" >/tmp/argosfs-guard-match 2>/dev/null; then
    cat /tmp/argosfs-guard-match >&2
    fail "$reason"
  fi
}

require_present() {
  local pattern="$1"
  local file="$2"
  local reason="$3"
  if ! grep -nE "$pattern" "$file" >/dev/null 2>/dev/null; then
    fail "$reason"
  fi
}

echo "[1/9] rust formatting / clippy / tests"
cargo fmt -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test

echo "[2/9] deep roundtrip checks"
bash scripts/compat/run_deep_roundtrip.sh
if [ -e /dev/fuse ] && { command -v fusermount3 >/dev/null 2>&1 || command -v fusermount >/dev/null 2>&1; } && grep -q 'nodev[[:space:]]\+fuse' /proc/filesystems; then
  ARGOSFS_DEEP_FUSE=1 bash scripts/compat/run_deep_roundtrip.sh
else
  echo "skip FUSE deep roundtrip: /dev/fuse, fusermount, or kernel fuse unavailable"
fi

echo "[3/9] mounted FUSE compatibility checks"
bash scripts/compat/run_mounted_fuse_compat.sh

echo "[4/9] block lossy xattr/FUSE regressions"
require_absent 'name\.to_string_lossy\(\)' src/fusefs.rs \
  "FUSE xattr/name handling must not use to_string_lossy"
require_present 'fn xattr_name\(name: &OsStr\) -> Result<&str>' src/fusefs.rs \
  "FUSE should use explicit UTF-8 xattr validation helper"
require_present 'unsupported setxattr position' src/fusefs.rs \
  "FUSE setxattr must reject nonzero position"
require_present 'flags & !supported' src/fusefs.rs \
  "FUSE setxattr/rename should reject unsupported flags"

echo "[5/9] import/export metadata guard"
require_present 'iter_path_bytes' src/bin/argosfs.rs \
  "export_tree must use byte-preserving paths"
require_present 'readlink_inode_bytes' src/bin/argosfs.rs \
  "export_tree must export symlink targets as bytes"
require_present 'fs::hard_link' src/bin/argosfs.rs \
  "export_tree must preserve hardlinks"
require_present 'imported_files = BTreeMap::<\(u64, u64\), u64>::new\(\)' src/bin/argosfs.rs \
  "import_tree must detect hardlinks by source dev/inode"
require_present 'let mut directories = vec!\[\(source\.to_path_buf\(\), dest_ino\)\]' src/bin/argosfs.rs \
  "import_tree must restore source-root metadata onto destination root"
require_present 'apply_export_metadata\(volume, root_attr\.ino, dest, &root_attr\)' src/bin/argosfs.rs \
  "export_tree must restore ArgosFS root metadata onto export root"
require_present 'is_internal_export_xattr' src/bin/argosfs.rs \
  "export must filter ArgosFS-internal xattrs"
require_absent 'Some\(libc::EPERM\).*return Ok\(Vec::new\(\)\)' src/bin/argosfs.rs \
  "import must not treat xattr EPERM as no xattrs"
require_absent 'Some\(libc::EACCES\).*return Ok\(Vec::new\(\)\)' src/bin/argosfs.rs \
  "import must not treat xattr EACCES as no xattrs"

echo "[6/9] device number / mknod guard"
require_present 'rdev: u64' src/types.rs \
  "Inode/NodeAttr rdev must be u64"
require_present 'rdev: u64' src/volume.rs \
  "mknod paths must carry u64 rdev"
require_present 'parse_u64_auto' src/bin/argosfs.rs \
  "CLI mknod --rdev must parse u64"

echo "[7/9] transaction and durability guard"
require_present 'load_or_recover' src/volume.rs \
  "failed uncommitted/conflict commits should reload metadata"
require_present 'before-journal' src/volume.rs \
  "commit failure handling must distinguish before-journal"
require_present 'file\.sync_all\(\)\?' src/volume.rs \
  "ArgosFs::sync must flush shard file contents"

echo "[8/9] compat script guard"
require_present 'cd "\$mountpoint"' scripts/compat/run_pjdfstest.sh \
  "pjdfstest must run inside requested mountpoint"
require_present 'mountpoint -q "\$mountpoint"' scripts/compat/run_pjdfstest.sh \
  "pjdfstest must verify actual mountpoint"
require_present 'mountpoint -q "\$ARGOSFS_COMPAT_MOUNTPOINT"' scripts/compat/run_fuse_smoke.sh \
  "fuse smoke must verify actual mountpoint"
require_present 'kill -0 "\$pid"' scripts/compat/with_fuse_mount.sh \
  "FUSE helper must fail if mount process exits"
require_present 'mountpoint -q "\$mountpoint"' scripts/compat/with_fuse_mount.sh \
  "FUSE helper must wait for mountpoint(1)"
require_present 'mounted_fuse_ops.py' scripts/compat/run_mounted_fuse_compat.sh \
  "mounted FUSE compatibility script must run syscall behavior checks"

echo "[9/9] experiment reproducibility guard"
require_absent 'random\.Random\(424242\)' scripts/experiments/run_failure_matrix.py \
  "failure matrix must not hardcode seed"
require_present 'ARGOSFS_EXPERIMENT_SEED' scripts/experiments/run_failure_matrix.py \
  "failure matrix should use configured experiment seed"

echo "regression checks passed"
