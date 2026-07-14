#!/usr/bin/env bash
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
artifacts="${ARGOSFS_TEST_ARTIFACTS:-$repo/target/argosfs-test-artifacts/randomized-fuse}"
required="${ARGOSFS_REQUIRE_FUSE_RANDOM:-0}"

fail_or_skip() {
  local message="$1"
  if [ "$required" = "1" ]; then
    echo "ERROR: $message" >&2
    exit 1
  fi
  echo "SKIP: $message" >&2
  exit 0
}

[ -e /dev/fuse ] || fail_or_skip "/dev/fuse is unavailable"
if [ ! -r /dev/fuse ] || [ ! -w /dev/fuse ]; then
  fail_or_skip "/dev/fuse is not readable and writable"
fi
grep -q 'nodev[[:space:]]\+fuse' /proc/filesystems 2>/dev/null || fail_or_skip "kernel FUSE support is unavailable"
command -v mountpoint >/dev/null 2>&1 || fail_or_skip "mountpoint(1) is unavailable"
if command -v fusermount3 >/dev/null 2>&1; then
  fusermount="$(command -v fusermount3)"
elif command -v fusermount >/dev/null 2>&1; then
  fusermount="$(command -v fusermount)"
else
  fail_or_skip "fusermount3/fusermount is unavailable"
fi

cargo build --manifest-path "$repo/Cargo.toml" --bin argosfs --locked
argosfs="$repo/target/debug/argosfs"

python3 "$repo/scripts/tests/host/randomized_fuse.py" \
  --argosfs "$argosfs" \
  --artifacts "$artifacts" \
  --seed "${ARGOSFS_FUSE_RANDOM_SEED:-0xA2605F5}" \
  --ops "${ARGOSFS_FUSE_RANDOM_OPS:-1000}" \
  --checkpoint-interval "${ARGOSFS_FUSE_RANDOM_CHECK_INTERVAL:-200}" \
  --max-file-size "${ARGOSFS_FUSE_RANDOM_MAX_FILE_SIZE:-131072}" \
  --fusermount "$fusermount"
