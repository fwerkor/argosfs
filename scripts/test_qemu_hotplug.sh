#!/usr/bin/env bash
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
artifacts="${ARGOSFS_TEST_ARTIFACTS:-$repo/target/argosfs-test-artifacts/qemu-hotplug}"
mkdir -p "$artifacts"

arch="${ARGOSFS_QEMU_ARCH:-x86_64}"
case "$arch" in
	x86_64)
		qemu_bin="${ARGOSFS_QEMU_BIN:-qemu-system-x86_64}"
		machine=("${ARGOSFS_QEMU_MACHINE:-pc}")
		cpu_args=()
		rootdev="${ARGOSFS_QEMU_ROOTDEV:-/dev/vda}"
		;;
	aarch64|arm64)
		qemu_bin="${ARGOSFS_QEMU_BIN:-qemu-system-aarch64}"
		machine=("${ARGOSFS_QEMU_MACHINE:-virt}")
		cpu_args=(-cpu "${ARGOSFS_QEMU_CPU:-cortex-a57}")
		rootdev="${ARGOSFS_QEMU_ROOTDEV:-/dev/vda}"
		;;
	riscv64)
		qemu_bin="${ARGOSFS_QEMU_BIN:-qemu-system-riscv64}"
		machine=("${ARGOSFS_QEMU_MACHINE:-virt}")
		cpu_args=()
		rootdev="${ARGOSFS_QEMU_ROOTDEV:-/dev/vda}"
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
	echo "SKIP: QEMU hotplug requires ARGOSFS_QEMU_KERNEL pointing at a CapOS kernel/initramfs artifact" >&2
	exit 0
fi
if [ -z "$rootfs" ] || [ ! -e "$rootfs" ]; then
	echo "SKIP: QEMU hotplug requires ARGOSFS_QEMU_ROOTFS pointing at an ArgosFS rootfs image" >&2
	exit 0
fi
if [ -n "$initrd" ] && [ ! -e "$initrd" ]; then
	echo "ARGOSFS_QEMU_INITRD does not exist: $initrd" >&2
	exit 1
fi

hotplug_disk="$artifacts/hotplug.img"
qemu-img create -f raw "$hotplug_disk" "${ARGOSFS_QEMU_HOTPLUG_SIZE:-64M}" >/dev/null
monitor="$artifacts/qemu-monitor.sock"
log="$artifacts/qemu-hotplug.log"
commands="$artifacts/qemu-hotplug.commands"
append="${ARGOSFS_QEMU_APPEND:-console=ttyS0 rootwait argosfs.images=$rootdev argosfs.mode=rw}"
reject="${ARGOSFS_QEMU_REJECT:-Kernel panic|Bad file descriptor|argosfs-initrd: emergency|Oops:|BUG:}"
timeout_s="${ARGOSFS_QEMU_TIMEOUT:-260}"
login_delay_s="${ARGOSFS_QEMU_HOTPLUG_LOGIN_DELAY:-90}"
command_delay_s="${ARGOSFS_QEMU_HOTPLUG_COMMAND_DELAY:-1}"
done_marker="ARGOSFS_QEMU_HOTPLUG_DONE"

cat >"$commands" <<'CMDS'
echo ARGOSFS_QEMU_HOTPLUG_BEGIN
awk '$2=="/"{print "ARGOSFS_ROOT_MOUNT " $1 " " $3 " " $4; exit}' /proc/mounts
ls -l /dev/vd* 2>/dev/null || true
echo ARGOSFS_WAIT_HOTPLUG
for i in $(seq 1 30); do [ -b /dev/vdb ] && break; sleep 1; done
ls -l /dev/vd* 2>/dev/null || true
test -b /dev/vdb && echo ARGOSFS_HOTPLUG_BLOCK_DEVICE_OK
mkdir -p /tmp/argosfs-hotplug
printf 'hotplug payload\n' >/tmp/argosfs-hotplug/payload.txt
sync
echo ARGOSFS_WAIT_UNPLUG
for i in $(seq 1 30); do [ ! -b /dev/vdb ] && break; sleep 1; done
if [ ! -b /dev/vdb ]; then echo ARGOSFS_UNPLUG_BLOCK_DEVICE_OK; fi
test "$(cat /tmp/argosfs-hotplug/payload.txt)" = "hotplug payload" && echo ARGOSFS_ROOT_SURVIVED_HOTPLUG_OK
rm -rf /tmp/argosfs-hotplug
sync
echo ARGOSFS_QEMU_HOTPLUG_DONE
poweroff -f || reboot -f || halt -f
CMDS

qemu_args=(
	-machine "${machine[0]}"
	-m "${ARGOSFS_QEMU_MEM:-1024}"
	"${cpu_args[@]}"
	-kernel "$kernel"
	-append "$append"
	-nographic
	-no-reboot
	-monitor "unix:$monitor,server,nowait"
)
if [ -n "$initrd" ]; then
	qemu_args+=(-initrd "$initrd")
fi
qemu_args+=(-drive "file=$rootfs,format=raw,if=virtio,id=rootdisk")

set +e
(
	sleep "$login_delay_s"
	printf '\r'
	sleep "$command_delay_s"
	while IFS= read -r line; do
		printf '%s\r' "$line"
		sleep "$command_delay_s"
		if [ "$line" = "echo ARGOSFS_WAIT_HOTPLUG" ]; then
			for _ in $(seq 1 30); do [ -S "$monitor" ] && break; sleep 1; done
			printf 'drive_add 0 if=none,file=%s,format=raw,id=hot0\n' "$hotplug_disk" | socat - "UNIX-CONNECT:$monitor" || true
			printf 'device_add virtio-blk-pci,drive=hot0,id=hotdisk0\n' | socat - "UNIX-CONNECT:$monitor" || true
		fi
		if [ "$line" = "echo ARGOSFS_WAIT_UNPLUG" ]; then
			printf 'device_del hotdisk0\n' | socat - "UNIX-CONNECT:$monitor" || true
			sleep 2
			printf 'drive_del hot0\n' | socat - "UNIX-CONNECT:$monitor" || true
		fi
	done <"$commands"
) | timeout "$timeout_s" "$qemu_bin" "${qemu_args[@]}" >"$log" 2>&1
status=${PIPESTATUS[1]}
set -e

if grep -Eiq "$reject" "$log"; then
	echo "QEMU hotplug failed; qemu status=$status; rejected pattern: $reject" >&2
	tail -n 260 "$log" >&2 || true
	exit 1
fi
missing=()
for marker in ARGOSFS_QEMU_HOTPLUG_BEGIN ARGOSFS_HOTPLUG_BLOCK_DEVICE_OK ARGOSFS_ROOT_SURVIVED_HOTPLUG_OK "$done_marker"; do
	if ! grep -Fq "$marker" "$log"; then
		missing+=("$marker")
	fi
done
if ! grep -Eq 'ARGOSFS_ROOT_MOUNT .* fuse' "$log"; then
	missing+=("ARGOSFS_ROOT_MOUNT fuse")
fi
if [ "${ARGOSFS_QEMU_HOTPLUG_REQUIRE_UNPLUG:-1}" = "1" ] && ! grep -Fq ARGOSFS_UNPLUG_BLOCK_DEVICE_OK "$log"; then
	missing+=("ARGOSFS_UNPLUG_BLOCK_DEVICE_OK")
fi
if [ "${#missing[@]}" -eq 0 ]; then
	echo "QEMU hotplug test passed for $arch; artifacts=$artifacts"
	exit 0
fi

echo "QEMU hotplug failed; qemu status=$status; missing markers: ${missing[*]}" >&2
tail -n 260 "$log" >&2 || true
exit 1
