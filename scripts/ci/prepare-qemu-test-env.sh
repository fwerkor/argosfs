#!/usr/bin/env bash
set -euo pipefail

bundle="${ARGOSFS_QEMU_BUNDLE_DIR:?ARGOSFS_QEMU_BUNDLE_DIR is required}"
work="${ARGOSFS_QEMU_WORKDIR:?ARGOSFS_QEMU_WORKDIR is required}"
mkdir -p "$work"
# shellcheck disable=SC1091
. "$bundle/bundle.env"

env_file="${GITHUB_ENV:-$work/qemu.env}"
{
  echo "ARGOSFS_QEMU_ARCH=${BUNDLE_ARCH}"
  echo "ARGOSFS_QEMU_KERNEL="
  echo "ARGOSFS_QEMU_ROOTFS="
  echo "ARGOSFS_QEMU_DISK_IMAGE="
} >>"$env_file"

if [ -n "${BUNDLE_KERNEL:-}" ]; then
  echo "ARGOSFS_QEMU_KERNEL=$bundle/$BUNDLE_KERNEL" >>"$env_file"
fi
if [ -n "${BUNDLE_ROOTFS:-}" ]; then
  cp --sparse=always "$bundle/$BUNDLE_ROOTFS" "$work/rootfs.img"
  echo "ARGOSFS_QEMU_ROOTFS=$work/rootfs.img" >>"$env_file"
fi
if [ -n "${BUNDLE_DISK_IMAGE:-}" ]; then
  cp --sparse=always "$bundle/$BUNDLE_DISK_IMAGE" "$work/disk.img"
  echo "ARGOSFS_QEMU_DISK_IMAGE=$work/disk.img" >>"$env_file"
fi

echo "Prepared QEMU test env from $bundle into $work"
cat "$bundle/bundle.env"
