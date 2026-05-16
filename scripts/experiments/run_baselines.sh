#!/usr/bin/env bash
set -euo pipefail

mode="quick"
out="paper-data/raw/baselines.jsonl"
while [ "$#" -gt 0 ]; do
  case "$1" in
    --mode) shift; mode="$1" ;;
    --output) shift; out="$1" ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
  shift
done

mkdir -p "$(dirname "$out")"
work="$(dirname "$(dirname "$out")")/work/baselines"
mkdir -p "$work"
bin="${ARGOSFS_BIN:-target/release/argosfs}"
[ -x "$bin" ] || bin="target/debug/argosfs"
: > "$out"

json_escape() {
  python3 -c 'import json,sys; print(json.dumps(sys.stdin.read())[1:-1])'
}

record() {
  local baseline="$1"
  local status="$2"
  local reason="$3"
  local elapsed="${4:-0}"
  printf '{"mode":"%s","baseline":"%s","status":"%s","reason":"%s","elapsed_sec":%s,"experiment_seed":"%s"}\n' \
    "$mode" "$baseline" "$status" "$(printf '%s' "$reason" | json_escape)" "$elapsed" "${ARGOSFS_EXPERIMENT_SEED:-424242}" >> "$out"
}

start="$(python3 - <<'PY'
import time
print(time.perf_counter())
PY
)"
root="$work/argosfs-manual-volume"
rm -rf "$root"
"$bin" mkfs "$root" --force --disks 4 --k 2 --m 2 >/dev/null
printf 'baseline manual data\n' > "$work/input.txt"
"$bin" put "$root" "$work/input.txt" /input.txt >/dev/null
"$bin" fsck "$root" --repair --remove-orphans > "$work/argosfs-manual-fsck.json"
elapsed="$(python3 - "$start" <<'PY'
import sys, time
print(f"{time.perf_counter() - float(sys.argv[1]):.6f}")
PY
)"
record argosfs-manual passed "mkfs+put+fsck completed with local ArgosFS CLI" "$elapsed"

start="$(python3 - <<'PY'
import time
print(time.perf_counter())
PY
)"
root="$work/argosfs-autopilot-volume"
rm -rf "$root"
"$bin" mkfs "$root" --force --disks 6 --k 4 --m 2 >/dev/null
"$bin" put "$root" "$work/input.txt" /input.txt >/dev/null
"$bin" set-health "$root" disk-0001 --pending-sectors 24 --io-errors 40 >/dev/null
"$bin" autopilot "$root" --once > "$work/argosfs-autopilot.json"
elapsed="$(python3 - "$start" <<'PY'
import sys, time
print(f"{time.perf_counter() - float(sys.argv[1]):.6f}")
PY
)"
record argosfs-autopilot passed "set-health+autopilot completed with local ArgosFS CLI" "$elapsed"

if command -v btrfs >/dev/null 2>&1; then
  record btrfs-raid1 skipped "btrfs binary present, but loop-device/root setup is intentionally external to unprivileged quick runs"
else
  record btrfs-raid1 skipped "btrfs binary unavailable"
fi
if command -v zpool >/dev/null 2>&1; then
  record zfs-mirror skipped "zpool present, but pool creation requires caller-provided devices"
else
  record zfs-mirror skipped "zpool unavailable"
fi
if command -v mdadm >/dev/null 2>&1 && command -v lvm >/dev/null 2>&1; then
  record mdadm-lvm skipped "mdadm/lvm present, but block-device provisioning is external to this runner"
else
  record mdadm-lvm skipped "mdadm or lvm unavailable"
fi
if command -v mergerfs >/dev/null 2>&1 && command -v snapraid >/dev/null 2>&1; then
  record mergerfs-snapraid skipped "mergerfs/snapraid present, but parity sync requires caller-provided data roots"
else
  record mergerfs-snapraid skipped "mergerfs or snapraid unavailable"
fi
