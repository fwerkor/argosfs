#!/usr/bin/env bash
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
artifacts="${ARGOSFS_TEST_ARTIFACTS:-$repo/target/argosfs-test-artifacts/initramfs-dry-run}"
rm -rf "$artifacts"
mkdir -p "$artifacts/source/sbin" "$artifacts/sysroot" "$artifacts/run"

sh -n "$repo/contrib/capos/initramfs/argosfs-root.sh"
cargo build --manifest-path "$repo/Cargo.toml" --bin argosfs
argosfs="$repo/target/debug/argosfs"

printf '#!/bin/sh\nexit 0\n' >"$artifacts/source/sbin/init"
chmod 0755 "$artifacts/source/sbin/init"
images="$artifacts/disk0.img"
"$argosfs" mkfs --backend loop --images "$images" --k 1 --m 0 --image-size $((32 * 1024 * 1024)) --pool-name capos-root >/dev/null
"$argosfs" import-tree --backend loop --images "$images" "$artifacts/source" /
ARGOSFS_INITRD_LOG="$artifacts/initrd.log" \
ARGOSFS_INITRD_RUN_DIR="$artifacts/run" \
	"$repo/contrib/capos/initramfs/argosfs-root.sh" \
	--dry-run --images "$images" --sysroot "$artifacts/sysroot" --argosfs-bin "$argosfs"
echo "initramfs dry-run passed; artifacts=$artifacts"
