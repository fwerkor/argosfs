#!/usr/bin/env bash
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
artifacts="$repo/target/argosfs-test-artifacts/loop-backend"
rm -rf "$artifacts"
mkdir -p "$artifacts"

cargo build --manifest-path "$repo/Cargo.toml" --bin argosfs
argosfs="$repo/target/debug/argosfs"

src="$artifacts/source"
dst="$artifacts/export"
mkdir -p "$src/etc" "$src/usr/bin" "$src/var" "$src/home"
printf 'NAME=CapOS\n' >"$src/etc/os-release"
printf '#!/bin/sh\nexit 0\n' >"$src/usr/bin/true"
chmod 0755 "$src/usr/bin/true"
ln "$src/etc/os-release" "$src/etc/os-release.hard"
ln -s /etc/os-release "$src/os-release.link"

images="$artifacts/disk0.img,$artifacts/disk1.img,$artifacts/disk2.img"
"$argosfs" mkfs --backend loop --images "$images" --k 2 --m 1 --image-size $((32 * 1024 * 1024)) --pool-name capos-root >"$artifacts/mkfs.json"
"$argosfs" scan --backend loop --images "$images" --json >"$artifacts/scan.json"
"$argosfs" inspect-device --backend loop "$artifacts/disk0.img" >"$artifacts/inspect-device.json"
"$argosfs" import-tree --backend loop --images "$images" "$src" /
"$argosfs" fsck --backend loop --images "$images" >"$artifacts/fsck.json"
"$argosfs" preflight-root --backend loop --images "$images" --mode rw >"$artifacts/preflight.json"
"$argosfs" export-tree --backend loop --images "$images" "$dst"
cmp "$src/etc/os-release" "$dst/etc/os-release"
test -L "$dst/os-release.link"
test "$(stat -c %i "$dst/etc/os-release")" = "$(stat -c %i "$dst/etc/os-release.hard")"
echo "loop backend smoke passed; artifacts=$artifacts"
