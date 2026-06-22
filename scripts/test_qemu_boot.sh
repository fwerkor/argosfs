#!/usr/bin/env bash
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
artifacts="${ARGOSFS_TEST_ARTIFACTS:-$repo/target/argosfs-test-artifacts/qemu-boot}"
mkdir -p "$artifacts"

arch="${ARGOSFS_QEMU_ARCH:-x86_64}"
case "$arch" in
	x86_64)
		qemu_bin="${ARGOSFS_QEMU_BIN:-qemu-system-x86_64}"
		machine=("${ARGOSFS_QEMU_MACHINE:-pc}")
		cpu_args=()
		default_rootdev="/dev/vda"
		;;
	aarch64|arm64)
		qemu_bin="${ARGOSFS_QEMU_BIN:-qemu-system-aarch64}"
		machine=("${ARGOSFS_QEMU_MACHINE:-virt}")
		cpu_args=(-cpu "${ARGOSFS_QEMU_CPU:-cortex-a57}")
		default_rootdev="/dev/vda"
		;;
	riscv64)
		qemu_bin="${ARGOSFS_QEMU_BIN:-qemu-system-riscv64}"
		machine=("${ARGOSFS_QEMU_MACHINE:-virt}")
		cpu_args=()
		default_rootdev="/dev/vda"
		;;
	*)
		echo "unknown ARGOSFS_QEMU_ARCH=$arch" >&2
		exit 2
		;;
esac

if ! command -v "$qemu_bin" >/dev/null 2>&1; then
	echo "SKIP: $qemu_bin not found" >&2
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

log="$artifacts/qemu-boot-$arch.log"
append="${ARGOSFS_QEMU_APPEND:-console=ttyS0 rootwait argosfs.images=${ARGOSFS_QEMU_ROOTDEV:-$default_rootdev} argosfs.mode=ro}"
expect="${ARGOSFS_QEMU_EXPECT:-switch_root|Please press Enter to activate this console|procd}"
reject="${ARGOSFS_QEMU_REJECT:-Kernel panic|Bad file descriptor|argosfs-initrd: emergency}"
timeout_s="${ARGOSFS_QEMU_TIMEOUT:-90}"
qemu_args=(
	-machine "${machine[0]}"
	-m "${ARGOSFS_QEMU_MEM:-1024}"
	"${cpu_args[@]}"
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
timeout "$timeout_s" "$qemu_bin" "${qemu_args[@]}" >"$log" 2>&1 || status=$?
if grep -Eiq "$reject" "$log"; then
	echo "QEMU boot smoke failed; qemu status=$status; rejected pattern: $reject" >&2
	tail -n 200 "$log" >&2 || true
	exit 1
fi
if grep -Eiq "$expect" "$log"; then
	echo "QEMU boot smoke passed for $arch; artifacts=$artifacts"
	exit 0
fi

echo "QEMU boot smoke failed; qemu status=$status; expected pattern: $expect" >&2
tail -n 200 "$log" >&2 || true
exit 1
