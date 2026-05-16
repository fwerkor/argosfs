#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
export ARGOSFS_COMPAT_SUITE="${ARGOSFS_COMPAT_SUITE:-mounted-fuse-compat}"

"$repo_root/scripts/compat/with_fuse_mount.sh" \
  bash -c 'python3 "$1" "$ARGOSFS_COMPAT_MOUNTPOINT"' _ \
  "$repo_root/scripts/compat/mounted_fuse_ops.py"
