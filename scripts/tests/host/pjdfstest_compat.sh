#!/usr/bin/env bash
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
out="${1:-${ARGOSFS_PJDFSTEST_OUT:-target/argosfs-artifacts/compat/pjdfstest.jsonl}}"
build_log="${out%.jsonl}.build.log"

if [ ! -e /dev/fuse ]; then
  echo "ERROR: /dev/fuse is required for mandatory pjdfstest coverage" >&2
  exit 1
fi
if [ -z "${PJDFSTEST_ROOT:-}" ] || [ ! -d "$PJDFSTEST_ROOT/tests" ]; then
  echo "ERROR: PJDFSTEST_ROOT must point to a checked-out pjdfstest tree" >&2
  exit 1
fi

mkdir -p "$(dirname "$out")"
if [ ! -x "$PJDFSTEST_ROOT/pjdfstest" ]; then
  for command in autoreconf make; do
    if ! command -v "$command" >/dev/null 2>&1; then
      echo "ERROR: $command is required to build pjdfstest" >&2
      exit 1
    fi
  done
  if ! (
    cd "$PJDFSTEST_ROOT"
    autoreconf -ifs
    ./configure
    make -j"$(nproc)" pjdfstest
  ) >"$build_log" 2>&1; then
    echo "ERROR: failed to build pjdfstest; log=$build_log" >&2
    tail -n 200 "$build_log" >&2 || true
    exit 1
  fi
fi
if [ ! -x "$PJDFSTEST_ROOT/pjdfstest" ]; then
  echo "ERROR: pjdfstest executable is missing after build" >&2
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
