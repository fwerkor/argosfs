#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
export ARGOSFS_COMPAT_SUITE="${ARGOSFS_COMPAT_SUITE:-mounted-fuse-compat}"

if [ "${ARGOSFS_COMPAT_RUN_AS_ROOT:-0}" = "1" ]; then
  "$repo_root/scripts/compat/with_fuse_mount.sh" \
    bash -c 'sudo env ARGOSFS_REQUIRE_CROSS_USER="${ARGOSFS_REQUIRE_CROSS_USER:-0}" ARGOSFS_COMPAT_CHECK="${ARGOSFS_COMPAT_CHECK:-}" python3 "$1" "$ARGOSFS_COMPAT_MOUNTPOINT"' _ \
    "$repo_root/scripts/compat/mounted_fuse_ops.py"
else
  "$repo_root/scripts/compat/with_fuse_mount.sh" \
    bash -c 'python3 "$1" "$ARGOSFS_COMPAT_MOUNTPOINT"' _ \
    "$repo_root/scripts/compat/mounted_fuse_ops.py"
fi
