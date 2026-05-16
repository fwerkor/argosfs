#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
export ARGOSFS_COMPAT_SUITE="${ARGOSFS_COMPAT_SUITE:-fuse-smoke}"

"$repo_root/scripts/compat/with_fuse_mount.sh" bash -c '
  set -euo pipefail
  mountpoint -q "$ARGOSFS_COMPAT_MOUNTPOINT"
  printf "hello\n" > "$ARGOSFS_COMPAT_MOUNTPOINT/hello.txt"
  chmod 600 "$ARGOSFS_COMPAT_MOUNTPOINT/hello.txt"
  truncate -s 64 "$ARGOSFS_COMPAT_MOUNTPOINT/hello.txt"
  cat "$ARGOSFS_COMPAT_MOUNTPOINT/hello.txt" >/dev/null
  printf "{\"suite\":\"fuse-smoke\",\"status\":\"passed\",\"step\":\"basic-mounted-io\"}\n"
'
