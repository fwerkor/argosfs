#!/usr/bin/env bash
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"

if [ ! -e /dev/fuse ]; then
  echo "ERROR: /dev/fuse is required for mandatory cross-user permission checks" >&2
  exit 1
fi

if [ -w /etc/fuse.conf ]; then
  grep -qxF user_allow_other /etc/fuse.conf || printf '%s\n' user_allow_other >>/etc/fuse.conf
else
  sudo sh -c 'grep -qxF user_allow_other /etc/fuse.conf 2>/dev/null || printf "%s\n" user_allow_other >>/etc/fuse.conf'
fi

export ARGOSFS_COMPAT_RUN_AS_ROOT=1
export ARGOSFS_REQUIRE_CROSS_USER=1

mode="${ARGOSFS_PERMISSION_COMPAT_MODE:-all}"
case "$mode" in
  all|internal)
    export ARGOSFS_COMPAT_SUITE="mounted-fuse-internal-permissions"
    export ARGOSFS_COMPAT_MOUNT_OPTIONS="allow_other"
    export ARGOSFS_COMPAT_CHECK="readdirplus-permissions"
    "$repo/scripts/compat/run_mounted_fuse_compat.sh"
    unset ARGOSFS_COMPAT_CHECK
    ;;
  kernel)
    ;;
  *)
    echo "ERROR: ARGOSFS_PERMISSION_COMPAT_MODE must be all, internal, or kernel" >&2
    exit 2
    ;;
esac

case "$mode" in
  all|kernel)
    export ARGOSFS_COMPAT_SUITE="mounted-fuse-kernel-permissions"
    export ARGOSFS_COMPAT_MOUNT_OPTIONS="allow_other,default_permissions"
    "$repo/scripts/compat/run_mounted_fuse_compat.sh"
    ;;
esac
