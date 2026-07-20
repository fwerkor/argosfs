#!/usr/bin/env bash
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
. "$repo/scripts/qemu/lib/common.sh"
artifacts="${ARGOSFS_TEST_ARTIFACTS:-$repo/target/argosfs-test-artifacts/qemu-block-lifecycle-stress}"
mkdir -p "$artifacts"
argosfs_qemu_select_arch
argosfs_qemu_require_binary

monitor="$artifacts/qemu-monitor.sock"
monitor_log="$artifacts/qemu-monitor.log"
log="$artifacts/qemu-block-lifecycle-stress-$arch.log"
commands="$artifacts/qemu-block-lifecycle-stress.commands"
reject="${ARGOSFS_QEMU_REJECT:-Kernel panic|Bad file descriptor|argosfs-initrd: emergency|Oops:|BUG:|segfault|I/O error}"
timeout_s="${ARGOSFS_QEMU_TIMEOUT:-1800}"
console_timeout_s="${ARGOSFS_QEMU_LIFECYCLE_CONSOLE_TIMEOUT:-600}"
done_marker="ARGOSFS_QEMU_BLOCK_LIFECYCLE_STRESS_DONE"

disks=()
for idx in 0 1 2 3 4; do
  disk="$artifacts/lifecycle-$idx.img"
  qemu-img create -f raw "$disk" "${ARGOSFS_QEMU_LIFECYCLE_DISK_SIZE:-128M}" >/dev/null
  disks+=("$disk")
done

cat >"$commands" <<'CMDS'
set -eu
echo ARGOSFS_QEMU_BLOCK_LIFECYCLE_STRESS_BEGIN
awk '$2=="/"{print "ARGOSFS_ROOT_MOUNT " $1 " " $3 " " $4; exit}' /proc/mounts
test -e /run/argosfs-root-active && echo ARGOSFS_ROOT_MARKER_OK
echo ARGOSFS_WAIT_LIFECYCLE_HOTPLUG
for dev in /dev/vdb /dev/vdc /dev/vdd /dev/vde /dev/vdf; do
  name="${dev##*/}"
  for i in $(seq 1 60); do [ -b "$dev" ] && [ -e "/sys/class/block/$name" ] && break; sleep 1; done
  test -b "$dev"
  test -e "/sys/class/block/$name"
done
echo ARGOSFS_LIFECYCLE_BLOCK_DEVICES_OK
src=/tmp/argosfs-lifecycle-src
out=/tmp/argosfs-lifecycle-out
rm -rf "$src" "$out"
mkdir -p "$src/data" "$out"
i=0
while [ "$i" -lt 160 ]; do
  printf 'metadata file %s\n' "$i" >"$src/data/meta-$i.txt"
  dd if=/dev/zero of="$src/data/blob-$i.bin" bs=2048 count=8 2>/dev/null
  i=$((i + 1))
done
devs=/dev/vdb,/dev/vdc,/dev/vdd
argosfs mkfs --backend raw --devices "$devs" --k 2 --m 1 --chunk-size 65536 --compression zstd --force >/tmp/argosfs-lifecycle-mkfs.json
argosfs import-tree --backend raw --devices "$devs" "$src" /
argosfs fsck --backend raw --devices "$devs" --repair --remove-orphans >/tmp/argosfs-lifecycle-fsck-initial.json
all="$devs"
argosfs add-device --backend raw --devices "$all" --device /dev/vde --force >/tmp/argosfs-lifecycle-add.json
all="$all,/dev/vde"
argosfs list-devices --backend raw --devices "$all" >/tmp/argosfs-lifecycle-devices-after-add.json
argosfs reshape --backend raw --devices "$all" --k 2 --m 1 --max-files 96 >/tmp/argosfs-lifecycle-reshape.json
argosfs scrub --backend raw --devices "$all" >/tmp/argosfs-lifecycle-scrub-after-reshape.json
argosfs drain-device --backend raw --devices "$all" --device disk-0000 >/tmp/argosfs-lifecycle-drain.json
argosfs remove-device --backend raw --devices "$all" --device disk-0000 >/tmp/argosfs-lifecycle-remove.json
argosfs replace-device --backend raw --devices "$all" --old disk-0001 --new /dev/vdf --force >/tmp/argosfs-lifecycle-replace.json
all="$all,/dev/vdf"
argosfs fsck --backend raw --devices "$all" --repair --remove-orphans >/tmp/argosfs-lifecycle-fsck-final.json
argosfs scrub --backend raw --devices "$all" >/tmp/argosfs-lifecycle-scrub-final.json
argosfs export-tree --backend raw --devices "$all" "$out"
if cmp "$src/data/meta-37.txt" "$out/data/meta-37.txt" &&
   cmp "$src/data/blob-111.bin" "$out/data/blob-111.bin"; then
  echo ARGOSFS_BLOCK_LIFECYCLE_CONTENT_OK
else
  echo ARGOSFS_BLOCK_LIFECYCLE_CONTENT_FAILED
fi
sync
echo ARGOSFS_QEMU_BLOCK_LIFECYCLE_STRESS_DONE
poweroff -f || reboot -f || halt -f
CMDS

argosfs_qemu_build_args
argosfs_qemu_add_hotplug_ports 5 life
qemu_args+=(-monitor "unix:$monitor,server,nowait")
: >"$monitor_log"

qemu_device_add() {
  local idx="$1" path="$2"
  local bus_arg rom_arg
  argosfs_qemu_monitor_command "$monitor" \
    "drive_add 0 if=none,file=$path,format=raw,id=life$idx" "$monitor_log" || return
  bus_arg="$(argosfs_qemu_hotplug_bus_arg life "$idx")"
  rom_arg=""
  [ "$arch" != "arm64" ] || rom_arg=",romfile="
  argosfs_qemu_monitor_command "$monitor" \
    "device_add virtio-blk-pci,drive=life$idx,id=lifedisk$idx${bus_arg}${rom_arg}" "$monitor_log" || return
}

set +e
# QEMU output is intentionally polled while this pipeline appends to the log.
# shellcheck disable=SC2094
(
  set -e
  argosfs_qemu_wait_console_prompt "$log" 1 "$console_timeout_s" "$reject" "block-lifecycle console prompt"
  argosfs_qemu_stream_script "$commands" 1 /tmp/argosfs-qemu-block-lifecycle.sh "$log"
  argosfs_qemu_wait_log_marker "$log" ARGOSFS_WAIT_LIFECYCLE_HOTPLUG 300
  argosfs_qemu_wait_monitor "$monitor" 60
  idx=0
  for disk in "${disks[@]}"; do
    qemu_device_add "$idx" "$disk"
    idx=$((idx + 1))
  done
) | timeout "$timeout_s" "$qemu_bin" "${qemu_args[@]}" >"$log" 2>&1
pipeline_status=("${PIPESTATUS[@]}")
feeder_status="${pipeline_status[0]}"
status="${pipeline_status[1]}"
set -e

if [ "$feeder_status" -ne 0 ]; then
  echo "QEMU block lifecycle feeder failed; status=$feeder_status" >&2
  tail -n 500 "$log" >&2 || true
  exit 1
fi

if grep -Eiq "$reject" "$log"; then
  echo "QEMU block lifecycle stress failed; qemu status=$status; rejected pattern: $reject" >&2
  tail -n 500 "$log" >&2 || true
  exit 1
fi
missing=()
for marker in ARGOSFS_QEMU_BLOCK_LIFECYCLE_STRESS_BEGIN ARGOSFS_ROOT_MARKER_OK ARGOSFS_LIFECYCLE_BLOCK_DEVICES_OK ARGOSFS_BLOCK_LIFECYCLE_CONTENT_OK "$done_marker"; do
  argosfs_qemu_log_has_marker "$log" "$marker" || missing+=("$marker")
done
argosfs_qemu_log_has_root_mount "$log" || missing+=("ARGOSFS_ROOT_MOUNT fuse")
if [ "${#missing[@]}" -eq 0 ]; then
  echo "QEMU block lifecycle stress test passed for $arch; artifacts=$artifacts"
  exit 0
fi

echo "QEMU block lifecycle stress failed; qemu status=$status; missing markers: ${missing[*]}" >&2
tail -n 500 "$log" >&2 || true
exit 1
