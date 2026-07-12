#!/usr/bin/env bash
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=scripts/qemu/lib/common.sh
. "$repo/scripts/qemu/lib/common.sh"
artifacts="${ARGOSFS_TEST_ARTIFACTS:-$repo/target/argosfs-test-artifacts/qemu-hotplug}"
mkdir -p "$artifacts"

argosfs_qemu_select_arch
argosfs_qemu_require_binary

hotplug_disk="$artifacts/hotplug.img"
qemu-img create -f raw "$hotplug_disk" "${ARGOSFS_QEMU_HOTPLUG_SIZE:-64M}" >/dev/null
monitor="$artifacts/qemu-monitor.sock"
monitor_log="$artifacts/qemu-monitor.log"
log="$artifacts/qemu-hotplug.log"
commands="$artifacts/qemu-hotplug.commands"
reject="${ARGOSFS_QEMU_REJECT:-Kernel panic|Bad file descriptor|argosfs-initrd: emergency|Oops:|BUG:|I/O error|missing device}"
timeout_s="${ARGOSFS_QEMU_TIMEOUT:-260}"
login_delay_s="${ARGOSFS_QEMU_HOTPLUG_LOGIN_DELAY:-90}"
login_delay_s="$(argosfs_qemu_adjust_login_delay "$login_delay_s")"
command_delay_s="${ARGOSFS_QEMU_HOTPLUG_COMMAND_DELAY:-1}"
done_marker="ARGOSFS_QEMU_HOTPLUG_DONE"

cat >"$commands" <<'CMDS'
echo ARGOSFS_QEMU_HOTPLUG_BEGIN
awk '$2=="/"{print "ARGOSFS_ROOT_MOUNT " $1 " " $3 " " $4; exit}' /proc/mounts
ls -l /dev/vd* 2>/dev/null || true
echo ARGOSFS_WAIT_HOTPLUG
for i in $(seq 1 30); do [ -b /dev/vdb ] && [ -e /sys/class/block/vdb ] && break; sleep 1; done
ls -l /dev/vd* 2>/dev/null || true
test -b /dev/vdb && test -e /sys/class/block/vdb && echo ARGOSFS_HOTPLUG_BLOCK_DEVICE_OK
mkdir -p /tmp/argosfs-hotplug/src /tmp/argosfs-hotplug/out
printf 'hotplug payload\n' >/tmp/argosfs-hotplug/payload.txt
printf 'raw hotplug payload\n' >/tmp/argosfs-hotplug/src/raw.txt
if command -v argosfs >/dev/null; then
  if argosfs mkfs --backend raw --devices /dev/vdb --k 1 --m 0 --chunk-size 32768 --compression zstd --force >/tmp/argosfs-hotplug/mkfs-raw.json &&
     argosfs import-tree --backend raw --devices /dev/vdb /tmp/argosfs-hotplug/src / &&
     argosfs export-tree --backend raw --devices /dev/vdb /tmp/argosfs-hotplug/out &&
     cmp /tmp/argosfs-hotplug/src/raw.txt /tmp/argosfs-hotplug/out/raw.txt &&
     argosfs fsck --backend raw --devices /dev/vdb --repair --remove-orphans >/tmp/argosfs-hotplug/fsck-raw.json &&
     argosfs scrub --backend raw --devices /dev/vdb >/tmp/argosfs-hotplug/scrub-raw.json; then
    echo ARGOSFS_HOTPLUG_RAW_ARGOSFS_OK
  else
    echo ARGOSFS_HOTPLUG_RAW_ARGOSFS_FAILED
  fi
fi
sync
echo ARGOSFS_WAIT_UNPLUG
for i in $(seq 1 30); do [ ! -e /sys/class/block/vdb ] && break; sleep 1; done
if [ ! -e /sys/class/block/vdb ]; then echo ARGOSFS_UNPLUG_BLOCK_DEVICE_OK; fi
test "$(cat /tmp/argosfs-hotplug/payload.txt)" = "hotplug payload" && echo ARGOSFS_ROOT_SURVIVED_HOTPLUG_OK
rm -rf /tmp/argosfs-hotplug
sync
echo ARGOSFS_QEMU_HOTPLUG_DONE
poweroff -f || reboot -f || halt -f
CMDS

argosfs_qemu_build_args
argosfs_qemu_add_hotplug_ports 1 hot
qemu_args+=(-monitor "unix:$monitor,server,nowait")
: >"$monitor_log"

set +e
# QEMU output is intentionally polled while this pipeline appends to the log.
# shellcheck disable=SC2094
(
	sleep "$login_delay_s"
	printf '\r'
	sleep "$command_delay_s"
	while IFS= read -r line; do
		printf '%s\r' "$line"
		sleep "$command_delay_s"
		if [ "$line" = "echo ARGOSFS_WAIT_HOTPLUG" ]; then
			argosfs_qemu_wait_log_marker "$log" ARGOSFS_WAIT_HOTPLUG 180
			for _ in $(seq 1 30); do [ -S "$monitor" ] && break; sleep 1; done
			argosfs_qemu_monitor_command "$monitor" \
				"drive_add 0 if=none,file=$hotplug_disk,format=raw,id=hot0" "$monitor_log"
			bus_arg="$(argosfs_qemu_hotplug_bus_arg hot 0)"
			rom_arg=""
			[ "$arch" != "arm64" ] || rom_arg=",romfile="
			argosfs_qemu_monitor_command "$monitor" \
				"device_add virtio-blk-pci,drive=hot0,id=hotdisk0${bus_arg}${rom_arg}" "$monitor_log"
		fi
		if [ "$line" = "echo ARGOSFS_WAIT_UNPLUG" ]; then
			argosfs_qemu_wait_log_marker "$log" ARGOSFS_WAIT_UNPLUG 600
			argosfs_qemu_monitor_command "$monitor" "device_del hotdisk0" "$monitor_log"
			sleep 2
			argosfs_qemu_monitor_command "$monitor" "drive_del hot0" "$monitor_log"
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
for marker in ARGOSFS_QEMU_HOTPLUG_BEGIN ARGOSFS_HOTPLUG_BLOCK_DEVICE_OK ARGOSFS_HOTPLUG_RAW_ARGOSFS_OK ARGOSFS_ROOT_SURVIVED_HOTPLUG_OK "$done_marker"; do
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
