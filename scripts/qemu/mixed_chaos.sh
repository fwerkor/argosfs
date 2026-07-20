#!/usr/bin/env bash
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
. "$repo/scripts/qemu/lib/common.sh"
artifacts="${ARGOSFS_TEST_ARTIFACTS:-$repo/target/argosfs-test-artifacts/qemu-mixed-chaos}"
mkdir -p "$artifacts"
argosfs_qemu_select_arch
argosfs_qemu_require_binary

monitor="$artifacts/qemu-monitor.sock"
monitor_log="$artifacts/qemu-monitor.log"
log1="$artifacts/qemu-mixed-chaos-phase1-$arch.log"
log2="$artifacts/qemu-mixed-chaos-phase2-$arch.log"
commands1="$artifacts/qemu-mixed-chaos-phase1.commands"
commands2="$artifacts/qemu-mixed-chaos-phase2.commands"
reject="${ARGOSFS_QEMU_REJECT:-Kernel panic|Bad file descriptor|argosfs-initrd: emergency|Oops:|BUG:|segfault}"
timeout_s="${ARGOSFS_QEMU_TIMEOUT:-3000}"
console_timeout_s="${ARGOSFS_QEMU_CHAOS_CONSOLE_TIMEOUT:-600}"
worker_count="${ARGOSFS_QEMU_CHAOS_WORKERS:-6}"
file_count="${ARGOSFS_QEMU_CHAOS_FILES:-160}"
if [ "$file_count" -lt 150 ]; then
  echo "ARGOSFS_QEMU_CHAOS_FILES must be at least 150" >&2
  exit 2
fi
disk_size="${ARGOSFS_QEMU_CHAOS_DISK_SIZE:-256M}"
done_marker="ARGOSFS_QEMU_MIXED_CHAOS_DONE"

disks=()
for idx in 0 1 2 3 4 5; do
  disk="$artifacts/chaos-$idx.img"
  qemu-img create -f raw "$disk" "$disk_size" >/dev/null
  disks+=("$disk")
done

cat >"$commands1" <<CMDS
set -eu
echo ARGOSFS_QEMU_MIXED_CHAOS_PHASE1_BEGIN
awk '\$2=="/"{print "ARGOSFS_ROOT_MOUNT_PHASE1 " \$1 " " \$3 " " \$4; exit}' /proc/mounts
test -e /run/argosfs-root-active && echo ARGOSFS_CHAOS_ROOT_MARKER_PHASE1_OK
echo ARGOSFS_WAIT_CHAOS_HOTPLUG
for dev in /dev/vdb /dev/vdc /dev/vdd /dev/vde /dev/vdf /dev/vdg; do
  name="\${dev##*/}"
  for i in \$(seq 1 90); do [ -b "\$dev" ] && [ -e "/sys/class/block/\$name" ] && break; sleep 1; done
  test -b "\$dev"
  test -e "/sys/class/block/\$name"
done
echo ARGOSFS_CHAOS_BLOCK_DEVICES_OK
src=/root/argosfs-chaos-source
baseline=/tmp/argosfs-chaos-baseline
rm -rf "\$src" "\$baseline"
mkdir -p "\$src/data" "\$src/dev" "\$src/proc" "\$src/run" "\$src/sys" "\$baseline"
i=0
while [ "\$i" -lt "$file_count" ]; do
  printf 'chaos metadata file=%s generation=0\n' "\$i" >"\$src/data/meta-\$i.txt"
  dd if=/dev/zero of="\$src/data/blob-\$i.bin" bs=4096 count=4 2>/dev/null
  i=\$((i + 1))
done
printf 'mixed chaos persistent sentinel\n' >"\$src/sentinel.txt"
devs=/dev/vdb,/dev/vdc,/dev/vdd,/dev/vde,/dev/vdf
argosfs mkfs --backend raw --devices "\$devs" --k 3 --m 2 --chunk-size 65536 --compression zstd --force --pool-name mixed-chaos >/tmp/argosfs-chaos-mkfs.json
argosfs import-tree --backend raw --devices "\$devs" "\$src" /
argosfs export-tree --backend raw --devices "\$devs" "\$baseline"
cmp "\$src/sentinel.txt" "\$baseline/sentinel.txt"
cmp "\$src/data/meta-37.txt" "\$baseline/data/meta-37.txt"
cmp "\$src/data/blob-111.bin" "\$baseline/data/blob-111.bin"
echo ARGOSFS_CHAOS_BASELINE_OK
stop=/tmp/argosfs-chaos-stop
rm -f "\$stop"
chaos_worker() {
  id="\$1"
  round=0
  wdir="/root/argosfs-chaos-live/worker-\$id"
  mkdir -p "\$wdir"
  while [ ! -e "\$stop" ]; do
    d="\$wdir/round-\$round"
    mkdir -p "\$d/sub"
    printf 'worker=%s round=%s\n' "\$id" "\$round" >"\$d/payload.txt"
    cp "\$d/payload.txt" "\$d/copy.txt"
    chmod 600 "\$d/payload.txt"
    chmod 640 "\$d/payload.txt"
    mv "\$d/copy.txt" "\$d/sub/renamed.txt"
    ln -s ../payload.txt "\$d/sub/link.txt"
    cat "\$d/sub/link.txt" >/dev/null
    ln "\$d/payload.txt" "\$d/hardlink.txt" 2>/dev/null || true
    dd if=/dev/zero of="\$d/zeros.bin" bs=4096 count=2 2>/dev/null
    [ \$((round % 8)) -ne 0 ] || sync
    rm -rf "\$wdir/round-\$((round - 5))" 2>/dev/null || true
    round=\$((round + 1))
  done
}
id=1
while [ "\$id" -le "$worker_count" ]; do chaos_worker "\$id" & id=\$((id + 1)); done
sleep 3
echo ARGOSFS_CHAOS_WORKLOAD_STARTED
echo ARGOSFS_WAIT_CHAOS_UNPLUG
for i in \$(seq 1 90); do [ ! -e /sys/class/block/vdc ] && break; sleep 1; done
test ! -e /sys/class/block/vdc
echo ARGOSFS_CHAOS_DEVICE_LOSS_OBSERVED
survivors=/dev/vdb,/dev/vdd,/dev/vde,/dev/vdf
minimum=/dev/vdb,/dev/vdd,/dev/vdf
full=/dev/vdb,/dev/vdc,/dev/vdd,/dev/vde,/dev/vdf
argosfs list-devices --backend raw --devices "\$full" >/tmp/argosfs-chaos-devices-degraded.json
if argosfs preflight-root --backend raw --devices "\$full" --mode rw >/tmp/argosfs-chaos-preflight-rw.log 2>&1; then
  echo unexpected degraded read-write preflight success >&2
  exit 1
fi
argosfs preflight-root --backend raw --devices "\$minimum" --mode degraded-ro >/tmp/argosfs-chaos-preflight-ro.json
degraded=/tmp/argosfs-chaos-degraded
rm -rf "\$degraded"
argosfs export-tree --backend raw --devices "\$minimum" "\$degraded"
cmp "\$src/sentinel.txt" "\$degraded/sentinel.txt"
cmp "\$src/data/meta-83.txt" "\$degraded/data/meta-83.txt"
cmp "\$src/data/blob-149.bin" "\$degraded/data/blob-149.bin"
echo ARGOSFS_CHAOS_DEGRADED_READ_OK
: >"\$stop"
wait
echo ARGOSFS_CHAOS_WORKLOAD_STOPPED
argosfs replace-device --backend raw --devices "\$survivors" --old disk-0001 --new /dev/vdg --force >/tmp/argosfs-chaos-replace.json
repaired="\$survivors,/dev/vdg"
argosfs fsck --backend raw --devices "\$repaired" --repair --remove-orphans >/tmp/argosfs-chaos-fsck.json
argosfs scrub --backend raw --devices "\$repaired" >/tmp/argosfs-chaos-scrub.json
recovered=/tmp/argosfs-chaos-recovered
rm -rf "\$recovered"
argosfs export-tree --backend raw --devices "\$repaired" "\$recovered"
cmp "\$src/sentinel.txt" "\$recovered/sentinel.txt"
cmp "\$src/data/meta-129.txt" "\$recovered/data/meta-129.txt"
cmp "\$src/data/blob-73.bin" "\$recovered/data/blob-73.bin"
echo ARGOSFS_CHAOS_REPLACEMENT_REPAIR_OK
printf 'root baseline before hard kill\n' | dd of=/root/argosfs-chaos-root-marker.txt conv=fsync 2>/dev/null
echo ARGOSFS_CHAOS_READY_FOR_HARD_KILL
round=0
while true; do
  slot=\$((round % 4))
  dd if=/dev/zero of="/root/argosfs-chaos-live/dirty-\$slot.bin" bs=64K count=64 2>/dev/null
  round=\$((round + 1))
done
CMDS

cat >"$commands2" <<'CMDS'
set -eu
echo ARGOSFS_QEMU_MIXED_CHAOS_PHASE2_BEGIN
awk '$2=="/"{print "ARGOSFS_ROOT_MOUNT_PHASE2 " $1 " " $3 " " $4; exit}' /proc/mounts
test -e /run/argosfs-root-active && echo ARGOSFS_CHAOS_ROOT_MARKER_PHASE2_OK
grep -q 'root baseline before hard kill' /root/argosfs-chaos-root-marker.txt
grep -q 'mixed chaos persistent sentinel' /root/argosfs-chaos-source/sentinel.txt
echo ARGOSFS_CHAOS_ROOT_REPLAY_OK
echo ARGOSFS_WAIT_CHAOS_REATTACH
for dev in /dev/vdb /dev/vdc /dev/vdd /dev/vde /dev/vdf; do
  name="${dev##*/}"
  for i in $(seq 1 90); do [ -b "$dev" ] && [ -e "/sys/class/block/$name" ] && break; sleep 1; done
  test -b "$dev"
  test -e "/sys/class/block/$name"
done
devs=/dev/vdb,/dev/vdc,/dev/vdd,/dev/vde,/dev/vdf
argosfs list-devices --backend raw --devices "$devs" >/tmp/argosfs-chaos-devices-after-reboot.json
argosfs replay-journal --backend raw --devices "$devs" >/tmp/argosfs-chaos-journal-replay.json
argosfs fsck --backend raw --devices "$devs" --repair --remove-orphans >/tmp/argosfs-chaos-fsck-after-reboot.json
argosfs scrub --backend raw --devices "$devs" >/tmp/argosfs-chaos-scrub-after-reboot.json
out=/tmp/argosfs-chaos-after-reboot
rm -rf "$out"
argosfs export-tree --backend raw --devices "$devs" "$out"
cmp /root/argosfs-chaos-source/sentinel.txt "$out/sentinel.txt"
cmp /root/argosfs-chaos-source/data/meta-37.txt "$out/data/meta-37.txt"
cmp /root/argosfs-chaos-source/data/blob-111.bin "$out/data/blob-111.bin"
echo ARGOSFS_CHAOS_POOL_REPLAY_OK
mkdir -p /root/argosfs-chaos-after-recovery
printf 'post-recovery write\n' | dd of=/root/argosfs-chaos-after-recovery/payload.txt conv=fsync 2>/dev/null
grep -q 'post-recovery write' /root/argosfs-chaos-after-recovery/payload.txt
echo ARGOSFS_QEMU_MIXED_CHAOS_DONE
poweroff -f || reboot -f || halt -f
CMDS

qemu_device_add() {
  local prefix="$1" index="$2" path="$3"
  local bus_arg rom_arg
  argosfs_qemu_monitor_command "$monitor" \
    "drive_add 0 if=none,file=$path,format=raw,id=$prefix$index" "$monitor_log" || return
  bus_arg="$(argosfs_qemu_hotplug_bus_arg "$prefix" "$index")"
  rom_arg=""
  [ "$arch" != "arm64" ] || rom_arg=",romfile="
  argosfs_qemu_monitor_command "$monitor" \
    "device_add virtio-blk-pci,drive=$prefix$index,id=${prefix}disk$index${bus_arg}${rom_arg}" "$monitor_log" || return
}

qemu_device_del() {
  local prefix="$1" index="$2"
  argosfs_qemu_monitor_command "$monitor" "device_del ${prefix}disk$index" "$monitor_log" || return
  sleep 3
  argosfs_qemu_monitor_command "$monitor" "drive_del $prefix$index" "$monitor_log" "Device '[^']+' not found" || return
}

run_phase1_until_kill_marker() {
  rm -f "$monitor"
  argosfs_qemu_build_args
  argosfs_qemu_add_hotplug_ports 6 chaos
  qemu_args+=(-monitor "unix:$monitor,server,nowait")
  : >"$monitor_log"
  : >"$log1"
  feeder_status_file="$artifacts/mixed-phase1-feeder.status"
  rm -f "$feeder_status_file"
  set +e
  # QEMU output is intentionally polled while this pipeline appends to the log.
  # shellcheck disable=SC2094
  {
    (
      set -e
      argosfs_qemu_wait_console_prompt "$log1" 1 "$console_timeout_s" "$reject" "mixed-chaos phase1 console prompt"
      argosfs_qemu_stream_script "$commands1" 1 /tmp/argosfs-qemu-mixed-phase1.sh "$log1"
      argosfs_qemu_wait_log_marker "$log1" ARGOSFS_WAIT_CHAOS_HOTPLUG 300
      argosfs_qemu_wait_monitor "$monitor" 60
      idx=0
      for disk in "${disks[@]}"; do
        qemu_device_add chaos "$idx" "$disk"
        idx=$((idx + 1))
      done
      echo 0 >"$feeder_status_file"
    ) || echo "$?" >"$feeder_status_file"
  } | timeout "$timeout_s" "$qemu_bin" "${qemu_args[@]}" >"$log1" 2>&1 &
  qemu_pid=$!
  deadline=$((SECONDS + timeout_s))
  result=1
  unplugged=0
  while [ "$SECONDS" -lt "$deadline" ]; do
    if grep -Eiq "$reject" "$log1" 2>/dev/null; then result=2; break; fi
    if [ -s "$feeder_status_file" ] && [ "$(cat "$feeder_status_file")" -ne 0 ]; then result=4; break; fi
    if [ "$unplugged" -eq 0 ] && argosfs_qemu_log_has_marker "$log1" ARGOSFS_WAIT_CHAOS_UNPLUG; then
      if ! qemu_device_del chaos 1; then result=5; break; fi
      unplugged=1
    fi
    if argosfs_qemu_log_has_marker "$log1" ARGOSFS_CHAOS_READY_FOR_HARD_KILL; then result=0; break; fi
    if ! kill -0 "$qemu_pid" 2>/dev/null; then result=3; break; fi
    sleep 1
  done
  if kill -0 "$qemu_pid" 2>/dev/null; then argosfs_qemu_kill_tree "$qemu_pid"; fi
  wait "$qemu_pid" >/dev/null 2>&1 || true
  argosfs_qemu_wait_process_gone "$qemu_pid" 30 || true
  set -e
  return "$result"
}

run_phase2() {
  rm -f "$monitor"
  argosfs_qemu_build_args
  argosfs_qemu_add_hotplug_ports 5 recover
  qemu_args+=(-monitor "unix:$monitor,server,nowait")
  : >"$monitor_log"
  set +e
  # QEMU output is intentionally polled while this pipeline appends to the log.
  # shellcheck disable=SC2094
  (
    set -e
    argosfs_qemu_wait_console_prompt "$log2" 1 "$console_timeout_s" "$reject" "mixed-chaos phase2 console prompt"
    argosfs_qemu_stream_script "$commands2" 1 /tmp/argosfs-qemu-mixed-phase2.sh "$log2"
    argosfs_qemu_wait_log_marker "$log2" ARGOSFS_WAIT_CHAOS_REATTACH 300
    argosfs_qemu_wait_monitor "$monitor" 60
    qemu_device_add recover 0 "${disks[0]}"
    qemu_device_add recover 1 "${disks[2]}"
    qemu_device_add recover 2 "${disks[3]}"
    qemu_device_add recover 3 "${disks[4]}"
    qemu_device_add recover 4 "${disks[5]}"
  ) | timeout "$timeout_s" "$qemu_bin" "${qemu_args[@]}" >"$log2" 2>&1
  pipeline_status=("${PIPESTATUS[@]}")
  feeder_status="${pipeline_status[0]}"
  status="${pipeline_status[1]}"
  set -e
  [ "$feeder_status" -eq 0 ] || return "$feeder_status"
  return "$status"
}

if ! run_phase1_until_kill_marker; then
  echo "QEMU mixed chaos phase1 failed before hard kill" >&2
  tail -n 600 "$log1" >&2 || true
  exit 1
fi
for marker in ARGOSFS_CHAOS_BASELINE_OK ARGOSFS_CHAOS_WORKLOAD_STARTED ARGOSFS_CHAOS_DEVICE_LOSS_OBSERVED ARGOSFS_CHAOS_DEGRADED_READ_OK ARGOSFS_CHAOS_WORKLOAD_STOPPED ARGOSFS_CHAOS_REPLACEMENT_REPAIR_OK ARGOSFS_CHAOS_READY_FOR_HARD_KILL; do
  if ! argosfs_qemu_log_has_marker "$log1" "$marker"; then
    echo "QEMU mixed chaos phase1 missed marker: $marker" >&2
    tail -n 600 "$log1" >&2 || true
    exit 1
  fi
done
if grep -Eiq "$reject" "$log1"; then
  echo "QEMU mixed chaos phase1 rejected pattern: $reject" >&2
  tail -n 600 "$log1" >&2 || true
  exit 1
fi

if ! run_phase2; then
  echo "QEMU mixed chaos phase2 failed" >&2
  tail -n 600 "$log2" >&2 || true
  exit 1
fi
if grep -Eiq "$reject" "$log2"; then
  echo "QEMU mixed chaos phase2 rejected pattern: $reject" >&2
  tail -n 600 "$log2" >&2 || true
  exit 1
fi
missing=()
for marker in ARGOSFS_QEMU_MIXED_CHAOS_PHASE2_BEGIN ARGOSFS_CHAOS_ROOT_MARKER_PHASE2_OK ARGOSFS_CHAOS_ROOT_REPLAY_OK ARGOSFS_CHAOS_POOL_REPLAY_OK "$done_marker"; do
  argosfs_qemu_log_has_marker "$log2" "$marker" || missing+=("$marker")
done
argosfs_qemu_log_has_root_mount "$log2" ARGOSFS_ROOT_MOUNT_PHASE2 || missing+=("ARGOSFS_ROOT_MOUNT_PHASE2 fuse")
if [ "${#missing[@]}" -eq 0 ]; then
  echo "QEMU mixed chaos test passed for $arch; artifacts=$artifacts"
  exit 0
fi

echo "QEMU mixed chaos failed; missing markers: ${missing[*]}" >&2
tail -n 600 "$log2" >&2 || true
exit 1
