#!/usr/bin/env bash
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
. "$repo/scripts/lib/qemu_common.sh"
artifacts="${ARGOSFS_TEST_ARTIFACTS:-$repo/target/argosfs-test-artifacts/qemu-block-lifecycle-stress}"
mkdir -p "$artifacts"
argosfs_qemu_select_arch
argosfs_qemu_require_binary

monitor="$artifacts/qemu-monitor.sock"
log="$artifacts/qemu-block-lifecycle-stress-$arch.log"
commands="$artifacts/qemu-block-lifecycle-stress.commands"
reject="${ARGOSFS_QEMU_REJECT:-Kernel panic|Bad file descriptor|argosfs-initrd: emergency|Oops:|BUG:|segfault|I/O error}"
timeout_s="${ARGOSFS_QEMU_TIMEOUT:-1800}"
login_delay_s="${ARGOSFS_QEMU_LIFECYCLE_LOGIN_DELAY:-140}"
login_delay_s="$(argosfs_qemu_adjust_login_delay "$login_delay_s")"
command_delay_s="${ARGOSFS_QEMU_LIFECYCLE_COMMAND_DELAY:-1}"
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
  for i in $(seq 1 60); do [ -b "$dev" ] && break; sleep 1; done
  test -b "$dev"
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
argosfs add-device --backend raw --devices "$all" --device /dev/vde --image-size 134217728 --force >/tmp/argosfs-lifecycle-add.json
all="$all,/dev/vde"
argosfs list-devices --backend raw --devices "$all" >/tmp/argosfs-lifecycle-devices-after-add.json
argosfs reshape --backend raw --devices "$all" --k 2 --m 1 --max-files 96 >/tmp/argosfs-lifecycle-reshape.json
argosfs scrub --backend raw --devices "$all" >/tmp/argosfs-lifecycle-scrub-after-reshape.json
argosfs drain-device --backend raw --devices "$all" --device disk-0000 >/tmp/argosfs-lifecycle-drain.json
argosfs remove-device --backend raw --devices "$all" --device disk-0000 >/tmp/argosfs-lifecycle-remove.json
argosfs replace-device --backend raw --devices "$all" --old disk-0001 --new /dev/vdf --image-size 134217728 --force >/tmp/argosfs-lifecycle-replace.json
all="$all,/dev/vdf"
argosfs fsck --backend raw --devices "$all" --repair --remove-orphans >/tmp/argosfs-lifecycle-fsck-final.json
argosfs scrub --backend raw --devices "$all" >/tmp/argosfs-lifecycle-scrub-final.json
argosfs export-tree --backend raw --devices "$all" "$out"
cmp "$src/data/meta-37.txt" "$out/data/meta-37.txt"
cmp "$src/data/blob-111.bin" "$out/data/blob-111.bin"
echo ARGOSFS_BLOCK_LIFECYCLE_CONTENT_OK
sync
echo ARGOSFS_QEMU_BLOCK_LIFECYCLE_STRESS_DONE
poweroff -f || reboot -f || halt -f
CMDS

argosfs_qemu_build_args
qemu_args+=(-monitor "unix:$monitor,server,nowait")

qemu_device_add() {
  local idx="$1" path="$2"
  printf 'drive_add 0 if=none,file=%s,format=raw,id=life%s\n' "$path" "$idx" | socat - "UNIX-CONNECT:$monitor" >/dev/null 2>&1 || true
  if [ "$arch" = "arm64" ]; then
    printf 'device_add virtio-blk-pci,drive=life%s,id=lifedisk%s,romfile=\n' "$idx" "$idx" | socat - "UNIX-CONNECT:$monitor" >/dev/null 2>&1 || true
  else
    printf 'device_add virtio-blk-pci,drive=life%s,id=lifedisk%s\n' "$idx" "$idx" | socat - "UNIX-CONNECT:$monitor" >/dev/null 2>&1 || true
  fi
}

set +e
(
  sleep "$login_delay_s"
  printf '\r'
  sleep "$command_delay_s"
  while IFS= read -r line; do
    printf '%s\r' "$line"
    sleep "$command_delay_s"
    if [ "$line" = "echo ARGOSFS_WAIT_LIFECYCLE_HOTPLUG" ]; then
      for _ in $(seq 1 30); do [ -S "$monitor" ] && break; sleep 1; done
      idx=0
      for disk in "${disks[@]}"; do qemu_device_add "$idx" "$disk"; idx=$((idx + 1)); done
    fi
  done <"$commands"
) | timeout "$timeout_s" "$qemu_bin" "${qemu_args[@]}" >"$log" 2>&1
status=${PIPESTATUS[1]}
set -e

if grep -Eiq "$reject" "$log"; then
  echo "QEMU block lifecycle stress failed; qemu status=$status; rejected pattern: $reject" >&2
  tail -n 500 "$log" >&2 || true
  exit 1
fi
missing=()
for marker in ARGOSFS_QEMU_BLOCK_LIFECYCLE_STRESS_BEGIN ARGOSFS_ROOT_MARKER_OK ARGOSFS_LIFECYCLE_BLOCK_DEVICES_OK ARGOSFS_BLOCK_LIFECYCLE_CONTENT_OK "$done_marker"; do
  grep -Fq "$marker" "$log" || missing+=("$marker")
done
grep -Eq 'ARGOSFS_ROOT_MOUNT .* fuse' "$log" || missing+=("ARGOSFS_ROOT_MOUNT fuse")
if [ "${#missing[@]}" -eq 0 ]; then
  echo "QEMU block lifecycle stress test passed for $arch; artifacts=$artifacts"
  exit 0
fi

echo "QEMU block lifecycle stress failed; qemu status=$status; missing markers: ${missing[*]}" >&2
tail -n 500 "$log" >&2 || true
exit 1
