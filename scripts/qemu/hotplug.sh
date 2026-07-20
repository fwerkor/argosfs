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
console_timeout_s="${ARGOSFS_QEMU_HOTPLUG_CONSOLE_TIMEOUT:-420}"
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
	set -e
	argosfs_qemu_wait_console_prompt "$log" 1 "$console_timeout_s" "$reject" "hotplug console prompt"
	argosfs_qemu_stream_script "$commands" 1 /tmp/argosfs-qemu-hotplug.sh "$log"
	argosfs_qemu_wait_log_marker "$log" ARGOSFS_WAIT_HOTPLUG 300
	argosfs_qemu_wait_monitor "$monitor" 60
	argosfs_qemu_monitor_command "$monitor" \
		"drive_add 0 if=none,file=$hotplug_disk,format=raw,id=hot0" "$monitor_log"
	bus_arg="$(argosfs_qemu_hotplug_bus_arg hot 0)"
	rom_arg=""
	[ "$arch" != "arm64" ] || rom_arg=",romfile="
	argosfs_qemu_monitor_command "$monitor" \
		"device_add virtio-blk-pci,drive=hot0,id=hotdisk0${bus_arg}${rom_arg}" "$monitor_log"
	argosfs_qemu_wait_log_marker "$log" ARGOSFS_WAIT_UNPLUG 600
	argosfs_qemu_monitor_command "$monitor" "device_del hotdisk0" "$monitor_log"
	sleep 2
	# The guest powers off immediately after observing the unplug. The monitor may
	# therefore disappear before this optional backend cleanup reaches QEMU; the
	# guest markers below remain the authoritative validation of the operation.
	argosfs_qemu_monitor_command "$monitor" "drive_del hot0" "$monitor_log" "Device '[^']+' not found" || true
) | timeout "$timeout_s" "$qemu_bin" "${qemu_args[@]}" >"$log" 2>&1
pipeline_status=("${PIPESTATUS[@]}")
feeder_status="${pipeline_status[0]}"
status="${pipeline_status[1]}"
set -e

if [ "$feeder_status" -ne 0 ]; then
	echo "QEMU hotplug feeder failed; status=$feeder_status" >&2
	tail -n 260 "$log" >&2 || true
	exit 1
fi

if grep -Eiq "$reject" "$log"; then
	echo "QEMU hotplug failed; qemu status=$status; rejected pattern: $reject" >&2
	tail -n 260 "$log" >&2 || true
	exit 1
fi
missing=()
for marker in ARGOSFS_QEMU_HOTPLUG_BEGIN ARGOSFS_HOTPLUG_BLOCK_DEVICE_OK ARGOSFS_HOTPLUG_RAW_ARGOSFS_OK ARGOSFS_ROOT_SURVIVED_HOTPLUG_OK "$done_marker"; do
	if ! argosfs_qemu_log_has_marker "$log" "$marker"; then
		missing+=("$marker")
	fi
done
if ! argosfs_qemu_log_has_root_mount "$log"; then
	missing+=("ARGOSFS_ROOT_MOUNT fuse")
fi
if [ "${ARGOSFS_QEMU_HOTPLUG_REQUIRE_UNPLUG:-1}" = "1" ] && ! argosfs_qemu_log_has_marker "$log" ARGOSFS_UNPLUG_BLOCK_DEVICE_OK; then
	missing+=("ARGOSFS_UNPLUG_BLOCK_DEVICE_OK")
fi
if [ "${#missing[@]}" -eq 0 ]; then
	echo "QEMU hotplug test passed for $arch; artifacts=$artifacts"
	exit 0
fi

echo "QEMU hotplug failed; qemu status=$status; missing markers: ${missing[*]}" >&2
tail -n 260 "$log" >&2 || true
exit 1
