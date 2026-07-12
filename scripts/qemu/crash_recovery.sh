#!/usr/bin/env bash
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
. "$repo/scripts/qemu/lib/common.sh"
artifacts="${ARGOSFS_TEST_ARTIFACTS:-$repo/target/argosfs-test-artifacts/qemu-crash-recovery}"
mkdir -p "$artifacts"
argosfs_qemu_select_arch
argosfs_qemu_require_binary

monitor="$artifacts/qemu-monitor.sock"
monitor_log="$artifacts/qemu-monitor.log"
log1="$artifacts/qemu-crash-recovery-phase1-$arch.log"
log2="$artifacts/qemu-crash-recovery-phase2-$arch.log"
commands1="$artifacts/qemu-crash-recovery-phase1.commands"
commands2="$artifacts/qemu-crash-recovery-phase2.commands"
reject="${ARGOSFS_QEMU_REJECT:-Kernel panic|Bad file descriptor|argosfs-initrd: emergency|Oops:|BUG:|segfault}"
timeout_s="${ARGOSFS_QEMU_TIMEOUT:-1800}"
login_delay_s="${ARGOSFS_QEMU_CRASH_LOGIN_DELAY:-140}"
login_delay_s="$(argosfs_qemu_adjust_login_delay "$login_delay_s")"
command_delay_s="${ARGOSFS_QEMU_CRASH_COMMAND_DELAY:-1}"
done_marker="ARGOSFS_QEMU_CRASH_RECOVERY_DONE"

disks=()
for idx in 0 1 2; do
  disk="$artifacts/crash-$idx.img"
  qemu-img create -f raw "$disk" "${ARGOSFS_QEMU_CRASH_DISK_SIZE:-128M}" >/dev/null
  disks+=("$disk")
done

cat >"$commands1" <<'CMDS'
set -eu
echo ARGOSFS_QEMU_CRASH_RECOVERY_PHASE1_BEGIN
awk '$2=="/"{print "ARGOSFS_ROOT_MOUNT_PHASE1 " $1 " " $3 " " $4; exit}' /proc/mounts
test -e /run/argosfs-root-active && echo ARGOSFS_CRASH_ROOT_MARKER_PHASE1_OK
echo ARGOSFS_WAIT_CRASH_HOTPLUG
for dev in /dev/vdb /dev/vdc /dev/vdd; do
  name="${dev##*/}"
  for i in $(seq 1 60); do [ -b "$dev" ] && [ -e "/sys/class/block/$name" ] && break; sleep 1; done
  test -b "$dev"
  test -e "/sys/class/block/$name"
done
base=/tmp/argosfs-crash-base
next=/tmp/argosfs-crash-next
out=/tmp/argosfs-crash-out
rm -rf "$base" "$next" "$out"
mkdir -p "$base/data" "$next/data" "$out"
printf 'before crash journal replay\n' >"$base/data/crash.txt"
printf 'after crash journal replay\n' >"$next/data/crash.txt"
devs=/dev/vdb,/dev/vdc,/dev/vdd
argosfs mkfs --backend raw --devices "$devs" --k 2 --m 1 --chunk-size 65536 --compression zstd --force --pool-name crash-root >/tmp/argosfs-crash-mkfs.json
argosfs import-tree --backend raw --devices "$devs" "$base" /
if ARGOSFS_CRASH_POINT=after-journal argosfs import-tree --backend raw --devices "$devs" "$next" / >/tmp/argosfs-crash-injected.log 2>&1; then
  echo expected injected crash failure >&2
  exit 1
fi
echo ARGOSFS_RAW_CRASH_INJECTED_OK
argosfs list-devices --backend raw --devices "$devs" >/tmp/argosfs-crash-devices-before-replay.json
argosfs replay-journal --backend raw --devices "$devs" >/tmp/argosfs-crash-replay.json
argosfs fsck --backend raw --devices "$devs" --repair --remove-orphans >/tmp/argosfs-crash-fsck.json
argosfs export-tree --backend raw --devices "$devs" "$out"
grep -q 'after crash journal replay' "$out/data/crash.txt"
echo ARGOSFS_RAW_JOURNAL_REPLAY_OK
mkdir -p /root/argosfs-hardkill
printf 'hardkill persistent baseline\n' >/root/argosfs-hardkill/marker.txt
sync
echo ARGOSFS_READY_FOR_HOST_KILL
i=0
while true; do
  printf 'dirty root write %s\n' "$i" >"/root/argosfs-hardkill/dirty-$i.txt"
  i=$((i + 1))
  [ "$i" -lt 100000 ] || i=0
done
CMDS

cat >"$commands2" <<'CMDS'
set -eu
echo ARGOSFS_QEMU_CRASH_RECOVERY_PHASE2_BEGIN
awk '$2=="/"{print "ARGOSFS_ROOT_MOUNT_PHASE2 " $1 " " $3 " " $4; exit}' /proc/mounts
test -e /run/argosfs-root-active && echo ARGOSFS_CRASH_ROOT_MARKER_PHASE2_OK
grep -q 'hardkill persistent baseline' /root/argosfs-hardkill/marker.txt
echo ARGOSFS_HARDKILL_ROOT_REBOOT_OK
mkdir -p /root/argosfs-hardkill/after-recovery
printf 'after recovery write\n' >/root/argosfs-hardkill/after-recovery/payload.txt
sync
grep -q 'after recovery write' /root/argosfs-hardkill/after-recovery/payload.txt
echo ARGOSFS_QEMU_CRASH_RECOVERY_DONE
poweroff -f || reboot -f || halt -f
CMDS

qemu_device_add() {
  local idx="$1" path="$2"
  local bus_arg rom_arg
  argosfs_qemu_monitor_command "$monitor" \
    "drive_add 0 if=none,file=$path,format=raw,id=crash$idx" "$monitor_log"
  bus_arg="$(argosfs_qemu_hotplug_bus_arg crash "$idx")"
  rom_arg=""
  [ "$arch" != "arm64" ] || rom_arg=",romfile="
  argosfs_qemu_monitor_command "$monitor" \
    "device_add virtio-blk-pci,drive=crash$idx,id=crashdisk$idx${bus_arg}${rom_arg}" "$monitor_log"
}

run_phase1_until_kill_marker() {
  rm -f "$monitor"
  argosfs_qemu_build_args
  argosfs_qemu_add_hotplug_ports 3 crash
  qemu_args+=(-monitor "unix:$monitor,server,nowait")
  : >"$monitor_log"
  : >"$log1"
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
      if [ "$line" = "echo ARGOSFS_WAIT_CRASH_HOTPLUG" ]; then
        argosfs_qemu_wait_log_marker "$log1" ARGOSFS_WAIT_CRASH_HOTPLUG 180
        for _ in $(seq 1 30); do [ -S "$monitor" ] && break; sleep 1; done
        idx=0
        for disk in "${disks[@]}"; do qemu_device_add "$idx" "$disk"; idx=$((idx + 1)); done
      fi
    done <"$commands1"
  ) | timeout "$timeout_s" "$qemu_bin" "${qemu_args[@]}" >"$log1" 2>&1 &
  qemu_pid=$!
  deadline=$((SECONDS + timeout_s))
  wait_status=1
  while [ "$SECONDS" -lt "$deadline" ]; do
    if grep -Eiq "$reject" "$log1" 2>/dev/null; then wait_status=2; break; fi
    if grep -Fq ARGOSFS_READY_FOR_HOST_KILL "$log1" 2>/dev/null; then wait_status=0; break; fi
    if ! kill -0 "$qemu_pid" 2>/dev/null; then wait_status=3; break; fi
    sleep 1
  done
  if [ "$wait_status" -eq 0 ] && kill -0 "$qemu_pid" 2>/dev/null; then
    argosfs_qemu_kill_tree "$qemu_pid"
  fi
  wait "$qemu_pid" >/dev/null 2>&1 || true
  argosfs_qemu_wait_process_gone "$qemu_pid" 30 || true
  set -e
  return "$wait_status"
}

run_phase2() {
  argosfs_qemu_build_args
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
    done <"$commands2"
  ) | timeout "$timeout_s" "$qemu_bin" "${qemu_args[@]}" >"$log2" 2>&1
  status=${PIPESTATUS[1]}
  set -e
  return "$status"
}

if ! run_phase1_until_kill_marker; then
  echo "QEMU crash recovery phase1 failed before host kill" >&2
  tail -n 500 "$log1" >&2 || true
  exit 1
fi
if ! grep -Fq ARGOSFS_RAW_CRASH_INJECTED_OK "$log1" || ! grep -Fq ARGOSFS_RAW_JOURNAL_REPLAY_OK "$log1"; then
  echo "QEMU crash recovery phase1 missed raw journal markers" >&2
  tail -n 500 "$log1" >&2 || true
  exit 1
fi
if grep -Eiq "$reject" "$log1"; then
  echo "QEMU crash recovery phase1 rejected pattern: $reject" >&2
  tail -n 500 "$log1" >&2 || true
  exit 1
fi

if ! run_phase2; then
  echo "QEMU crash recovery phase2 failed" >&2
  tail -n 500 "$log2" >&2 || true
  exit 1
fi
if grep -Eiq "$reject" "$log2"; then
  echo "QEMU crash recovery phase2 rejected pattern: $reject" >&2
  tail -n 500 "$log2" >&2 || true
  exit 1
fi
missing=()
for marker in ARGOSFS_QEMU_CRASH_RECOVERY_PHASE2_BEGIN ARGOSFS_CRASH_ROOT_MARKER_PHASE2_OK ARGOSFS_HARDKILL_ROOT_REBOOT_OK "$done_marker"; do
  grep -Fq "$marker" "$log2" || missing+=("$marker")
done
grep -Eq 'ARGOSFS_ROOT_MOUNT_PHASE2 .* fuse' "$log2" || missing+=("ARGOSFS_ROOT_MOUNT_PHASE2 fuse")
if [ "${#missing[@]}" -eq 0 ]; then
  echo "QEMU crash recovery test passed for $arch; artifacts=$artifacts"
  exit 0
fi

echo "QEMU crash recovery failed; missing markers: ${missing[*]}" >&2
tail -n 500 "$log2" >&2 || true
exit 1
