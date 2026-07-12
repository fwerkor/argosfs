#!/usr/bin/env bash
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
. "$repo/scripts/qemu/lib/common.sh"
artifacts="${ARGOSFS_TEST_ARTIFACTS:-$repo/target/argosfs-test-artifacts/qemu-degraded-rootfs}"
mkdir -p "$artifacts"
argosfs_qemu_select_arch
argosfs_qemu_require_binary

monitor="$artifacts/qemu-monitor.sock"
monitor_log="$artifacts/qemu-monitor.log"
log="$artifacts/qemu-degraded-rootfs-$arch.log"
commands="$artifacts/qemu-degraded-rootfs.commands"
reject="${ARGOSFS_QEMU_REJECT:-Kernel panic|Bad file descriptor|argosfs-initrd: emergency|Oops:|BUG:|segfault|I/O error}"
timeout_s="${ARGOSFS_QEMU_TIMEOUT:-1200}"
login_delay_s="${ARGOSFS_QEMU_DEGRADED_LOGIN_DELAY:-140}"
login_delay_s="$(argosfs_qemu_adjust_login_delay "$login_delay_s")"
command_delay_s="${ARGOSFS_QEMU_DEGRADED_COMMAND_DELAY:-1}"
done_marker="ARGOSFS_QEMU_DEGRADED_ROOTFS_DONE"

disks=()
for idx in 0 1 2; do
  disk="$artifacts/degraded-$idx.img"
  qemu-img create -f raw "$disk" "${ARGOSFS_QEMU_DEGRADED_DISK_SIZE:-128M}" >/dev/null
  disks+=("$disk")
done

cat >"$commands" <<'CMDS'
set -eu
echo ARGOSFS_QEMU_DEGRADED_ROOTFS_BEGIN
awk '$2=="/"{print "ARGOSFS_ROOT_MOUNT " $1 " " $3 " " $4; exit}' /proc/mounts
test -e /run/argosfs-root-active && echo ARGOSFS_ROOT_MARKER_OK
echo ARGOSFS_WAIT_DEGRADED_HOTPLUG
for dev in /dev/vdb /dev/vdc /dev/vdd; do
  name="${dev##*/}"
  for i in $(seq 1 60); do [ -b "$dev" ] && [ -e "/sys/class/block/$name" ] && break; sleep 1; done
  test -b "$dev"
  test -e "/sys/class/block/$name"
done
src=/tmp/argosfs-degraded-src
mnt=/mnt/argosfs-degraded-root
rm -rf "$src" "$mnt"
mkdir -p "$src/dev" "$src/etc" "$src/proc" "$src/run" "$src/sbin" "$src/sys" "$src/tmp" "$mnt"
printf 'NAME=ArgosFS-Degraded-CI\n' >"$src/etc/os-release"
printf '#!/bin/sh\necho degraded-root-init\nexec sh\n' >"$src/sbin/init"
chmod 0755 "$src/sbin/init"
printf 'degraded root payload\n' >"$src/etc/payload.txt"
devs=/dev/vdb,/dev/vdc,/dev/vdd
argosfs mkfs --backend raw --devices "$devs" --k 2 --m 1 --chunk-size 65536 --compression zstd --force --pool-name degraded-root >/tmp/argosfs-degraded-mkfs.json
argosfs import-tree --backend raw --devices "$devs" "$src" /
argosfs preflight-root --backend raw --devices "$devs" --mode rw >/tmp/argosfs-degraded-preflight-rw.json
partial=/dev/vdb,/dev/vdc
if argosfs preflight-root --backend raw --devices "$partial" --mode rw >/tmp/argosfs-degraded-preflight-rw-missing.json 2>&1; then
  echo unexpected degraded rw success >&2
  exit 1
fi
echo ARGOSFS_DEGRADED_RW_REJECTED_OK
argosfs preflight-root --backend raw --devices "$partial" --mode degraded-ro >/tmp/argosfs-degraded-preflight-ro.json
argosfs mount-root --backend raw --devices "$partial" --mode degraded-ro --target "$mnt" -o ro >/tmp/argosfs-degraded-mount.log 2>&1 &
mpid=$!
for i in $(seq 1 60); do [ -r "$mnt/etc/os-release" ] && break; sleep 1; done
grep -q 'ArgosFS-Degraded-CI' "$mnt/etc/os-release"
grep -q 'degraded root payload' "$mnt/etc/payload.txt"
echo ARGOSFS_DEGRADED_ROOT_MOUNT_OK
umount "$mnt" 2>/dev/null || fusermount3 -u "$mnt" 2>/dev/null || true
for i in $(seq 1 20); do [ -r "$mnt/etc/os-release" ] || break; sleep 1; done
if kill -0 "$mpid" 2>/dev/null; then kill "$mpid" 2>/dev/null || true; fi
wait "$mpid" 2>/dev/null || true
sync
echo ARGOSFS_QEMU_DEGRADED_ROOTFS_DONE
poweroff -f || reboot -f || halt -f
CMDS

argosfs_qemu_build_args
argosfs_qemu_add_hotplug_ports 3 deg
qemu_args+=(-monitor "unix:$monitor,server,nowait")
: >"$monitor_log"

qemu_device_add() {
  local idx="$1" path="$2"
  local bus_arg rom_arg
  argosfs_qemu_monitor_command "$monitor" \
    "drive_add 0 if=none,file=$path,format=raw,id=deg$idx" "$monitor_log"
  bus_arg="$(argosfs_qemu_hotplug_bus_arg deg "$idx")"
  rom_arg=""
  [ "$arch" != "arm64" ] || rom_arg=",romfile="
  argosfs_qemu_monitor_command "$monitor" \
    "device_add virtio-blk-pci,drive=deg$idx,id=degdisk$idx${bus_arg}${rom_arg}" "$monitor_log"
}

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
    if [ "$line" = "echo ARGOSFS_WAIT_DEGRADED_HOTPLUG" ]; then
      argosfs_qemu_wait_log_marker "$log" ARGOSFS_WAIT_DEGRADED_HOTPLUG 180
      for _ in $(seq 1 30); do [ -S "$monitor" ] && break; sleep 1; done
      idx=0
      for disk in "${disks[@]}"; do qemu_device_add "$idx" "$disk"; idx=$((idx + 1)); done
    fi
  done <"$commands"
) | timeout "$timeout_s" "$qemu_bin" "${qemu_args[@]}" >"$log" 2>&1
status=${PIPESTATUS[1]}
set -e

if grep -Eiq "$reject" "$log"; then
  echo "QEMU degraded rootfs failed; qemu status=$status; rejected pattern: $reject" >&2
  tail -n 460 "$log" >&2 || true
  exit 1
fi
missing=()
for marker in ARGOSFS_QEMU_DEGRADED_ROOTFS_BEGIN ARGOSFS_ROOT_MARKER_OK ARGOSFS_DEGRADED_RW_REJECTED_OK ARGOSFS_DEGRADED_ROOT_MOUNT_OK "$done_marker"; do
  grep -Fq "$marker" "$log" || missing+=("$marker")
done
grep -Eq 'ARGOSFS_ROOT_MOUNT .* fuse' "$log" || missing+=("ARGOSFS_ROOT_MOUNT fuse")
if [ "${#missing[@]}" -eq 0 ]; then
  echo "QEMU degraded rootfs test passed for $arch; artifacts=$artifacts"
  exit 0
fi

echo "QEMU degraded rootfs failed; qemu status=$status; missing markers: ${missing[*]}" >&2
tail -n 460 "$log" >&2 || true
exit 1
