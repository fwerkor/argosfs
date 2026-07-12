#!/usr/bin/env bash
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
out="${1:-${ARGOSFS_PJDFSTEST_OUT:-target/argosfs-artifacts/compat/pjdfstest.jsonl}}"

if [ ! -e /dev/fuse ]; then
  echo "ERROR: /dev/fuse is required for mandatory pjdfstest coverage" >&2
  exit 1
fi
if [ -z "${PJDFSTEST_ROOT:-}" ] || [ ! -d "$PJDFSTEST_ROOT/tests" ]; then
  echo "ERROR: PJDFSTEST_ROOT must point to a checked-out pjdfstest tree" >&2
  exit 1
fi

if [ -w /etc/fuse.conf ]; then
  grep -qxF user_allow_other /etc/fuse.conf || printf '%s\n' user_allow_other >>/etc/fuse.conf
else
  sudo sh -c 'grep -qxF user_allow_other /etc/fuse.conf 2>/dev/null || printf "%s\n" user_allow_other >>/etc/fuse.conf'
fi

export ARGOSFS_COMPAT_MOUNT_OPTIONS="allow_other,default_permissions"
export ARGOSFS_PJDFSTEST_REQUIRE=1
export ARGOSFS_PJDFSTEST_RUN_AS_ROOT=1

"$repo/scripts/compat/run_pjdfstest.sh" "$out"
