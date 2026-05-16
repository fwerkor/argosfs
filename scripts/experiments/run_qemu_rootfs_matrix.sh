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
rootfs="${ARGOSFS_QEMU_ROOTFS:-}"
if [ -z "$kernel" ] || [ -z "$rootfs" ] || [ ! -e "$kernel" ] || [ ! -e "$rootfs" ]; then
  for scenario in normal-boot clean-shutdown interrupted-write degraded-disk emergency-readonly; do
    record "$scenario" skipped "set ARGOSFS_QEMU_KERNEL and ARGOSFS_QEMU_ROOTFS to run boot matrix"
  done
  exit 0
fi

scenarios="normal-boot clean-shutdown"
[ "$mode" = "full" ] && scenarios="$scenarios interrupted-write degraded-disk emergency-readonly"
for scenario in $scenarios; do
  log="$work/$scenario.log"
  timeout "${ARGOSFS_QEMU_TIMEOUT:-60}" qemu-system-x86_64 \
    -m "${ARGOSFS_QEMU_MEM:-1024}" \
    -kernel "$kernel" \
    -drive "file=$rootfs,format=raw,if=virtio" \
    -append "console=ttyS0 argosfs.experiment=$scenario" \
    -nographic \
    -no-reboot >"$log" 2>&1 && status=passed || status=failed
  record "$scenario" "$status" "qemu exited with status $status" "$log"
done
