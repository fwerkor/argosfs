#!/usr/bin/env bash
set -euo pipefail

mode="quick"
out="paper-data/raw/qemu-rootfs.jsonl"
while [ "$#" -gt 0 ]; do
  case "$1" in
    --mode) shift; mode="$1" ;;
    --output) shift; out="$1" ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
  shift
done

mkdir -p "$(dirname "$out")"
work="$(dirname "$(dirname "$out")")/work/qemu-rootfs"
mkdir -p "$work"
: > "$out"

json_escape() {
  python3 -c 'import json,sys; print(json.dumps(sys.stdin.read())[1:-1])'
}

record() {
  local scenario="$1"
  local status="$2"
  local reason="$3"
  local log="${4:-}"
  printf '{"mode":"%s","scenario":"%s","status":"%s","reason":"%s","log":"%s","experiment_seed":"%s"}\n' \
    "$mode" "$scenario" "$status" "$(printf '%s' "$reason" | json_escape)" "$(printf '%s' "$log" | json_escape)" "${ARGOSFS_EXPERIMENT_SEED:-424242}" >> "$out"
}

if ! command -v qemu-system-x86_64 >/dev/null 2>&1; then
  for scenario in normal-boot clean-shutdown interrupted-write degraded-disk emergency-readonly; do
    record "$scenario" skipped "qemu-system-x86_64 unavailable"
  done
  exit 0
fi

kernel="${ARGOSFS_QEMU_KERNEL:-}"
initrd="${ARGOSFS_QEMU_INITRD:-}"
rootfs="${ARGOSFS_QEMU_ROOTFS:-}"
if [ -z "$kernel" ] || [ -z "$rootfs" ] || [ ! -e "$kernel" ] || [ ! -e "$rootfs" ]; then
  for scenario in normal-boot clean-shutdown interrupted-write degraded-disk emergency-readonly; do
    record "$scenario" skipped "set ARGOSFS_QEMU_KERNEL and ARGOSFS_QEMU_ROOTFS to run boot matrix"
  done
  exit 0
fi
if [ -n "$initrd" ] && [ ! -e "$initrd" ]; then
  for scenario in normal-boot clean-shutdown interrupted-write degraded-disk emergency-readonly; do
    record "$scenario" skipped "ARGOSFS_QEMU_INITRD does not exist"
  done
  exit 0
fi

scenarios="normal-boot clean-shutdown"
[ "$mode" = "full" ] && scenarios="$scenarios interrupted-write degraded-disk emergency-readonly"
for scenario in $scenarios; do
  log="$work/$scenario.log"
  append="${ARGOSFS_QEMU_APPEND:-console=ttyS0 rootwait argosfs.images=${ARGOSFS_QEMU_ROOTDEV:-/dev/vda} argosfs.mode=ro argosfs.experiment=$scenario}"
  qemu_args=(
    -m "${ARGOSFS_QEMU_MEM:-1024}" \
    -kernel "$kernel" \
    -drive "file=$rootfs,format=raw,if=virtio" \
    -append "$append" \
    -nographic \
    -no-reboot
  )
  [ -z "$initrd" ] || qemu_args+=(-initrd "$initrd")
  rc=0
  timeout "${ARGOSFS_QEMU_TIMEOUT:-60}" qemu-system-x86_64 "${qemu_args[@]}" >"$log" 2>&1 || rc=$?
  if grep -Eiq "${ARGOSFS_QEMU_REJECT:-Kernel panic|Bad file descriptor|argosfs-initrd: emergency}" "$log"; then
    status=failed
    reason="rejected boot failure marker found"
  elif grep -Eiq "${ARGOSFS_QEMU_EXPECT:-switch_root|Please press Enter to activate this console|procd}" "$log"; then
    status=passed
    reason="expected boot marker found"
  else
    status=failed
    reason="qemu exited with status $rc before expected boot marker"
  fi
  record "$scenario" "$status" "$reason" "$log"
done
