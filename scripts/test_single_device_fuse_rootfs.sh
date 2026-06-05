#!/usr/bin/env bash
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
artifacts="${ARGOSFS_TEST_ARTIFACTS:-$repo/target/argosfs-test-artifacts/single-device-fuse-rootfs}"

if [ ! -e /dev/fuse ]; then
	echo "SKIP: /dev/fuse is not available; single-device FUSE rootfs test was not run" >&2
	exit 0
fi
if ! command -v fusermount3 >/dev/null 2>&1; then
	echo "SKIP: fusermount3 is not available; single-device FUSE rootfs test was not run" >&2
	exit 0
fi
if ! command -v mountpoint >/dev/null 2>&1; then
	echo "SKIP: mountpoint is not available; single-device FUSE rootfs test was not run" >&2
	exit 0
fi

rm -rf "$artifacts"
mkdir -p "$artifacts/source/sbin" "$artifacts/mnt"
cargo build --manifest-path "$repo/Cargo.toml" --bin argosfs >/dev/null
argosfs="$repo/target/debug/argosfs"
image="$artifacts/disk0.img"

printf '#!/bin/sh\nexit 0\n' >"$artifacts/source/sbin/init"
chmod 0755 "$artifacts/source/sbin/init"
"$argosfs" mkfs --backend loop --images "$image" --k 1 --m 0 --image-size $((32 * 1024 * 1024)) --pool-name capos-root >/dev/null
"$argosfs" import-tree --backend loop --images "$image" "$artifacts/source" /

pid=""
cleanup() {
	if mountpoint -q "$artifacts/mnt" 2>/dev/null; then
		fusermount3 -u "$artifacts/mnt" >/dev/null 2>&1 || true
	fi
	if [ -n "$pid" ] && kill -0 "$pid" >/dev/null 2>&1; then
		kill "$pid" >/dev/null 2>&1 || true
		wait "$pid" >/dev/null 2>&1 || true
	fi
}
trap cleanup EXIT INT TERM

mount_once() {
	local log="$1"
	"$argosfs" mount-root --backend loop --images "$image" --target "$artifacts/mnt" --mode rw --foreground >"$log" 2>&1 &
	pid=$!
	for _ in $(seq 1 100); do
		if mountpoint -q "$artifacts/mnt"; then
			return 0
		fi
		if ! kill -0 "$pid" >/dev/null 2>&1; then
			cat "$log" >&2
			return 1
		fi
		sleep 0.1
	done
	cat "$log" >&2
	return 1
}

unmount_once() {
	fusermount3 -u "$artifacts/mnt"
	wait "$pid" >/dev/null 2>&1 || true
	pid=""
}

mount_once "$artifacts/mount1.log"
printf mounted-write >"$artifacts/mnt/etc-test"
test "$(cat "$artifacts/mnt/etc-test")" = mounted-write
unmount_once
"$argosfs" fsck --backend loop --images "$image" >"$artifacts/fsck1.json"

mount_once "$artifacts/mount2.log"
test "$(cat "$artifacts/mnt/etc-test")" = mounted-write
unmount_once
"$argosfs" fsck --backend loop --images "$image" >"$artifacts/fsck2.json"

echo "single-device FUSE rootfs smoke passed; artifacts=$artifacts"
