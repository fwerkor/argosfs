#!/usr/bin/env bash
set -euo pipefail

suite="${ARGOSFS_COMPAT_SUITE:-fuse-mount}"
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
work="${ARGOSFS_COMPAT_WORKDIR:-$(mktemp -d "${TMPDIR:-/tmp}/argosfs-fuse-compat.XXXXXX")}"
root="${ARGOSFS_COMPAT_ROOT:-$work/volume}"
mountpoint="${ARGOSFS_COMPAT_MOUNTPOINT:-$work/mnt}"
bin="${ARGOSFS_BIN:-$repo_root/target/release/argosfs}"
pid=""
mounted=0

json_escape() {
  local value="$1"
  value="${value//\\/\\\\}"
  value="${value//\"/\\\"}"
  value="${value//$'\n'/\\n}"
  printf '%s' "$value"
}

log() {
  local status="$1"
  local step="$2"
  local message="${3:-}"
  local escaped
  escaped="$(json_escape "$message")"
  printf '{"suite":"%s","status":"%s","step":"%s","message":"%s"}\n' \
    "$suite" "$status" "$step" "$escaped"
}

skip() {
  log skipped "$1" "$2"
  exit 0
}

fail() {
  log failed "$1" "$2"
  exit 1
}

cleanup() {
  local code=$?
  if [ "$mounted" = 1 ] && mountpoint -q "$mountpoint" 2>/dev/null; then
    "$fusermount" -u "$mountpoint" >/dev/null 2>&1 || umount "$mountpoint" >/dev/null 2>&1 || true
  fi
  if [ -n "$pid" ] && kill -0 "$pid" >/dev/null 2>&1; then
    kill "$pid" >/dev/null 2>&1 || true
    wait "$pid" >/dev/null 2>&1 || true
  fi
  if [ "${ARGOSFS_COMPAT_KEEP_WORKDIR:-0}" != "1" ]; then
    rm -rf "$work"
  else
    log info keep-workdir "$work"
  fi
  exit "$code"
}
trap cleanup EXIT INT TERM

if [ "$#" -eq 0 ]; then
  fail arguments "usage: $0 COMMAND [ARG...]"
fi

if [ ! -e /dev/fuse ]; then
  skip capability "/dev/fuse unavailable"
fi
if [ ! -r /dev/fuse ] || [ ! -w /dev/fuse ]; then
  skip capability "/dev/fuse is not readable and writable by this user"
fi
if ! grep -q 'nodev[[:space:]]\+fuse' /proc/filesystems 2>/dev/null; then
  skip capability "kernel fuse filesystem is unavailable"
fi
if command -v fusermount3 >/dev/null 2>&1; then
  fusermount="$(command -v fusermount3)"
elif command -v fusermount >/dev/null 2>&1; then
  fusermount="$(command -v fusermount)"
else
  skip capability "fusermount3/fusermount unavailable"
fi
if ! command -v mountpoint >/dev/null 2>&1; then
  skip capability "mountpoint(1) unavailable"
fi
if ! command -v python3 >/dev/null 2>&1; then
  skip capability "python3 unavailable"
fi

log info build "building release argosfs binary"
cargo build --release >/dev/null

log info prepare "$work"
rm -rf "$root" "$mountpoint"
mkdir -p "$mountpoint"
"$bin" mkfs "$root" --disks "${ARGOSFS_COMPAT_DISKS:-4}" --k "${ARGOSFS_COMPAT_K:-2}" --m "${ARGOSFS_COMPAT_M:-2}" --force >/dev/null

log info mount "$mountpoint"
"$bin" mount "$root" "$mountpoint" --foreground &
pid=$!

for _ in $(seq 1 "${ARGOSFS_COMPAT_MOUNT_ATTEMPTS:-100}"); do
  if ! kill -0 "$pid" >/dev/null 2>&1; then
    fail mount "mount process exited before readiness"
  fi
  if mountpoint -q "$mountpoint"; then
    mounted=1
    break
  fi
  sleep 0.1
done

if [ "$mounted" != 1 ]; then
  fail mount "mountpoint was not confirmed by mountpoint(1)"
fi

log info run "$*"
export ARGOSFS_COMPAT_ROOT="$root"
export ARGOSFS_COMPAT_MOUNTPOINT="$mountpoint"
export ARGOSFS_COMPAT_WORKDIR="$work"
export ARGOSFS_COMPAT_FUSERMOUNT="$fusermount"
"$@"
log passed complete "$mountpoint"
