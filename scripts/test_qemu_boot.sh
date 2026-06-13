#!/usr/bin/env bash
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
artifacts="${ARGOSFS_TEST_ARTIFACTS:-$repo/target/argosfs-test-artifacts/qemu-boot}"
mkdir -p "$artifacts"

if ! command -v qemu-system-x86_64 >/dev/null 2>&1; then
	echo "SKIP: qemu-system-x86_64 not found" >&2
	exit 0
fi

kernel="${ARGOSFS_QEMU_KERNEL:-}"
rootfs="${ARGOSFS_QEMU_ROOTFS:-}"
initrd="${ARGOSFS_QEMU_INITRD:-}"
if [ -z "$kernel" ] || [ ! -e "$kernel" ]; then
	echo "SKIP: QEMU boot requires ARGOSFS_QEMU_KERNEL pointing at a CapOS kernel/initramfs artifact" >&2
	exit 0
fi
if [ -n "$rootfs" ] && [ ! -e "$rootfs" ]; then
	echo "ARGOSFS_QEMU_ROOTFS does not exist: $rootfs" >&2
	exit 1
fi
if [ -n "$initrd" ] && [ ! -e "$initrd" ]; then
	echo "ARGOSFS_QEMU_INITRD does not exist: $initrd" >&2
	exit 1
fi

log="$artifacts/qemu-boot.log"
append="${ARGOSFS_QEMU_APPEND:-console=ttyS0 rootwait argosfs.images=${ARGOSFS_QEMU_ROOTDEV:-/dev/vda} argosfs.mode=ro}"
expect="${ARGOSFS_QEMU_EXPECT:-switch_root|Please press Enter to activate this console|procd}"
reject="${ARGOSFS_QEMU_REJECT:-Kernel panic|Bad file descriptor|argosfs-initrd: emergency}"
timeout_s="${ARGOSFS_QEMU_TIMEOUT:-90}"
qemu_args=(
	-m "${ARGOSFS_QEMU_MEM:-1024}"
	-kernel "$kernel"
	-append "$append"
	-nographic
	-no-reboot
)
if [ -n "$initrd" ]; then
	qemu_args+=(-initrd "$initrd")
fi
if [ -n "$rootfs" ]; then
	qemu_args+=(-drive "file=$rootfs,format=raw,if=virtio")
fi

status=0
timeout "$timeout_s" qemu-system-x86_64 "${qemu_args[@]}" >"$log" 2>&1 || status=$?
if grep -Eiq "$reject" "$log"; then
	echo "QEMU boot smoke failed; qemu status=$status; rejected pattern: $reject" >&2
	tail -n 200 "$log" >&2 || true
	exit 1
fi
if grep -Eiq "$expect" "$log"; then
	echo "QEMU boot smoke passed; artifacts=$artifacts"
	exit 0
fi

echo "QEMU boot smoke failed; qemu status=$status; expected pattern: $expect" >&2
tail -n 200 "$log" >&2 || true
exit 1
