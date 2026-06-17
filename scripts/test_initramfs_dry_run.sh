#!/usr/bin/env bash
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
artifacts="${ARGOSFS_TEST_ARTIFACTS:-$repo/target/argosfs-test-artifacts/initramfs-dry-run}"
rm -rf "$artifacts"
mkdir -p "$artifacts/source/sbin" "$artifacts/sysroot" "$artifacts/run" "$artifacts/dev" "$artifacts/sys/class/block/vda2"

sh -n "$repo/contrib/capos/initramfs/argosfs-root.sh"
cargo build --manifest-path "$repo/Cargo.toml" --bin argosfs
argosfs="$repo/target/debug/argosfs"

printf '#!/bin/sh\nexit 0\n' >"$artifacts/source/sbin/init"
chmod 0755 "$artifacts/source/sbin/init"
images="$artifacts/disk0.img"
"$argosfs" mkfs --backend loop --images "$images" --k 1 --m 0 --image-size $((32 * 1024 * 1024)) --pool-name capos-root >/dev/null
"$argosfs" import-tree --backend loop --images "$images" "$artifacts/source" /
ln -sf ../disk0.img "$artifacts/dev/argos-root"
{
	printf 'DEVNAME=argos-root\n'
	printf 'DEVTYPE=partition\n'
	printf 'PARTN=2\n'
} >"$artifacts/sys/class/block/vda2/uevent"
ARGOSFS_INITRD_LOG="$artifacts/initrd.log" \
ARGOSFS_INITRD_RUN_DIR="$artifacts/run" \
ARGOSFS_INITRD_DEV_ROOT="$artifacts/dev" \
ARGOSFS_INITRD_SYS_CLASS_BLOCK="$artifacts/sys/class/block" \
	"$repo/contrib/capos/initramfs/argosfs-root.sh" \
	--dry-run --images /dev/disk/by-partuuid/5a5e744d-02 --sysroot "$artifacts/sysroot" --argosfs-bin "$argosfs"
grep -q "resolved /dev/disk/by-partuuid/5a5e744d-02 by partition number 2 to $artifacts/dev/argos-root" "$artifacts/initrd.log"
rm -f "$artifacts/initrd.log"
ARGOSFS_INITRD_LOG="$artifacts/initrd.log" \
ARGOSFS_INITRD_RUN_DIR="$artifacts/run" \
ARGOSFS_INITRD_DEV_ROOT="$artifacts/dev" \
ARGOSFS_INITRD_SYS_CLASS_BLOCK="$artifacts/sys/class/block" \
	"$repo/contrib/capos/initramfs/argosfs-root.sh" \
	--dry-run --autoscan --sysroot "$artifacts/sysroot" --argosfs-bin "$argosfs"
grep -q "autoscan selected loop images $artifacts/dev/argos-root" "$artifacts/initrd.log"
rm -f "$artifacts/initrd.log"
if ARGOSFS_INITRD_LOG="$artifacts/initrd.log" \
	ARGOSFS_INITRD_RUN_DIR="$artifacts/run" \
	ARGOSFS_INITRD_DEV_ROOT="$artifacts/dev" \
	ARGOSFS_INITRD_SYS_CLASS_BLOCK="$artifacts/sys/class/block" \
	"$repo/contrib/capos/initramfs/argosfs-root.sh" \
	--dry-run --images "$images" --sysroot "$artifacts/sysroot" --argosfs-bin "$artifacts/missing-argosfs"
then
	echo "expected missing argosfs binary to fail" >&2
	exit 1
fi
grep -q "argosfs binary is missing or not executable" "$artifacts/initrd.log"
echo "initramfs dry-run passed; artifacts=$artifacts"
