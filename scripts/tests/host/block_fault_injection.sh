#!/usr/bin/env bash
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
artifacts="${ARGOSFS_TEST_ARTIFACTS:-$repo/target/argosfs-test-artifacts/block-fault-injection}"
required="${ARGOSFS_REQUIRE_BLOCK_FAULTS:-0}"
mkdir -p "$artifacts/logs" "$artifacts/exports"

fail_or_skip() {
  local message="$1"
  if [ "$required" = "1" ]; then
    echo "ERROR: $message" >&2
    exit 1
  fi
  echo "SKIP: $message" >&2
  exit 0
}

for command in dmsetup losetup blockdev sudo; do
  command -v "$command" >/dev/null 2>&1 || fail_or_skip "$command is unavailable"
done
sudo modprobe loop 2>/dev/null || true
sudo modprobe dm_mod 2>/dev/null || true
[ -e /dev/loop-control ] || fail_or_skip "/dev/loop-control is unavailable"
[ -e /dev/mapper/control ] || fail_or_skip "/dev/mapper/control is unavailable"
sudo dmsetup version >"$artifacts/logs/dmsetup-version.txt" 2>&1 || fail_or_skip "device-mapper control is unavailable"

cargo build --manifest-path "$repo/Cargo.toml" --bin argosfs --locked
argosfs="$repo/target/debug/argosfs"
work="$(mktemp -d "${TMPDIR:-/tmp}/argosfs-block-fault.XXXXXX")"
mkdir -p \
  "$work/src/data" \
  "$work/src/dev" \
  "$work/src/proc" \
  "$work/src/run" \
  "$work/src/sys"
loops=()
mapper_names=()
mappers=()
sectors=()

cleanup() {
  local code=$?
  set +e
  for name in "${mapper_names[@]}"; do
    sudo dmsetup remove --retry "$name" >/dev/null 2>&1 || sudo dmsetup remove -f "$name" >/dev/null 2>&1 || true
  done
  for loop in "${loops[@]}"; do
    sudo losetup -d "$loop" >/dev/null 2>&1 || true
  done
  if [ "${ARGOSFS_KEEP_BLOCK_FAULT_WORKDIR:-0}" = "1" ]; then
    echo "block fault workdir retained at $work" >&2
  else
    rm -rf "$work"
  fi
  exit "$code"
}
trap cleanup EXIT INT TERM

seed="${ARGOSFS_BLOCK_FAULT_SEED:-$(python3 - <<'PY'
import secrets
print(f"0x{secrets.randbits(64):016x}")
PY
)}"
run_tag="${GITHUB_RUN_ID:-$$}-${GITHUB_RUN_ATTEMPT:-1}"
run_tag="$(printf '%s' "$run_tag" | tr -c '[:alnum:]_-' '-')"

for index in 0 1 2; do
  backing="$work/backing-$index.img"
  truncate -s "${ARGOSFS_BLOCK_FAULT_DEVICE_SIZE:-256M}" "$backing"
  loop="$(sudo losetup --find --show "$backing")"
  loops+=("$loop")
  sector_count="$(sudo blockdev --getsz "$loop")"
  sectors+=("$sector_count")
  name="argosfs-ci-$run_tag-$index"
  mapper_names+=("$name")
  sudo dmsetup create "$name" --table "0 $sector_count linear $loop 0"
  mapper="/dev/mapper/$name"
  for _ in $(seq 1 50); do
    [ -b "$mapper" ] && break
    sleep 0.1
  done
  [ -b "$mapper" ] || fail_or_skip "device-mapper node was not created: $mapper"
  mappers+=("$mapper")
done

devs="$(IFS=,; echo "${mappers[*]}")"
cat >"$artifacts/metadata.json" <<EOF
{
  "seed": "$seed",
  "devices": ["${mappers[0]}", "${mappers[1]}", "${mappers[2]}"],
  "layout": "2+1",
  "device_size": "${ARGOSFS_BLOCK_FAULT_DEVICE_SIZE:-256M}",
  "commit": "${GITHUB_SHA:-$(git -C "$repo" rev-parse HEAD)}"
}
EOF

python3 - "$work/src/data" "$seed" <<'PY'
from pathlib import Path
import random
import sys
root = Path(sys.argv[1])
rng = random.Random(int(sys.argv[2], 0))
for index in range(96):
    size = 4096 + rng.randrange(128 * 1024)
    payload = bytes([index % 251]) * size if index % 3 == 0 else rng.randbytes(size)
    (root / f"payload-{index:03d}.bin").write_bytes(payload)
(root / "manifest.txt").write_text("block fault injection dataset\n", encoding="utf-8")
PY

sudo "$argosfs" mkfs --backend raw --devices "$devs" --k 2 --m 1 --chunk-size 32768 --compression zstd --force --pool-name block-fault-ci >"$artifacts/logs/mkfs.json"
sudo "$argosfs" import-tree --backend raw --devices "$devs" "$work/src" /
sudo "$argosfs" export-tree --backend raw --devices "$devs" "$artifacts/exports/baseline"
diff -qr "$work/src" "$artifacts/exports/baseline" >"$artifacts/logs/baseline.diff"

fault_index=1
fault_name="${mapper_names[$fault_index]}"
fault_sectors="${sectors[$fault_index]}"
sudo dmsetup suspend "$fault_name"
sudo dmsetup reload "$fault_name" --table "0 $fault_sectors error"
sudo dmsetup resume "$fault_name"
sudo dmsetup status "$fault_name" >"$artifacts/logs/dm-error-status.txt"

sudo "$argosfs" list-devices --backend raw --devices "$devs" >"$artifacts/logs/devices-during-eio.json"
python3 - "$artifacts/logs/devices-during-eio.json" <<'PY'
import json
import sys
statuses = {key: value.get("status") for key, value in json.load(open(sys.argv[1])).items()}
if "offline" not in statuses.values():
    raise SystemExit(f"EIO device was not marked offline: {statuses}")
PY
if sudo "$argosfs" preflight-root --backend raw --devices "$devs" --mode rw >"$artifacts/logs/preflight-rw-eio.log" 2>&1; then
  echo "read-write root preflight unexpectedly accepted an EIO device" >&2
  exit 1
fi
sudo "$argosfs" preflight-root --backend raw --devices "$devs" --mode degraded-ro >"$artifacts/logs/preflight-degraded-ro.json"

pids=()
for worker in 0 1 2 3; do
  (
    for round in 0 1; do
      out="$artifacts/exports/eio-worker-$worker-round-$round"
      sudo "$argosfs" export-tree --backend raw --devices "$devs" "$out"
      diff -qr "$work/src" "$out" >"$artifacts/logs/eio-worker-$worker-round-$round.diff"
    done
  ) >"$artifacts/logs/eio-worker-$worker.log" 2>&1 &
  pids+=("$!")
done
worker_failure=0
for pid in "${pids[@]}"; do
  wait "$pid" || worker_failure=1
done
if [ "$worker_failure" -ne 0 ]; then
  echo "concurrent degraded reads failed under injected EIO" >&2
  exit 1
fi

sudo dmsetup suspend "$fault_name"
sudo dmsetup reload "$fault_name" --table "0 $fault_sectors linear ${loops[$fault_index]} 0"
sudo dmsetup resume "$fault_name"
sudo blockdev --flushbufs "${mappers[$fault_index]}" || true
sudo "$argosfs" fsck --backend raw --devices "$devs" --repair --remove-orphans >"$artifacts/logs/fsck-after-eio.json"
sudo "$argosfs" scrub --backend raw --devices "$devs" >"$artifacts/logs/scrub-after-eio.json"

sudo "$argosfs" inspect-device --backend raw "${mappers[0]}" >"$artifacts/logs/inspect-corruption-target.json"
corrupt_offset="$(python3 - "$artifacts/logs/inspect-corruption-target.json" <<'PY'
import json
import sys
superblock = json.load(open(sys.argv[1]))["superblock"]
print(int(superblock["data"]["offset"]) + 4096)
PY
)"
python3 - "$work/corruption.bin" "$seed" <<'PY'
from pathlib import Path
import random
import sys
rng = random.Random(int(sys.argv[2], 0) ^ 0xC0FFEE)
Path(sys.argv[1]).write_bytes(bytes(rng.getrandbits(8) for _ in range(4096)))
PY
sudo blockdev --flushbufs "${mappers[0]}" || true
sudo dd if="$work/corruption.bin" of="${mappers[0]}" bs=1 seek="$corrupt_offset" count=4096 conv=notrunc,fsync status=none
sudo blockdev --flushbufs "${mappers[0]}" || true
sudo "$argosfs" scrub --backend raw --devices "$devs" >"$artifacts/logs/scrub-after-corruption.json"
python3 - "$artifacts/logs/scrub-after-corruption.json" <<'PY'
import json
import sys
report = json.load(open(sys.argv[1]))
if report.get("damaged_files", 0) < 1 or report.get("repaired_files", 0) < 1:
    raise SystemExit(f"controlled corruption was not detected and repaired: {report}")
if report.get("unrecoverable_files", 0) != 0:
    raise SystemExit(f"controlled single-device corruption became unrecoverable: {report}")
PY

sudo "$argosfs" fsck --backend raw --devices "$devs" --repair --remove-orphans >"$artifacts/logs/fsck-final.json"
sudo "$argosfs" verify-journal --backend raw --devices "$devs" >"$artifacts/logs/journal-final.json"
sudo "$argosfs" export-tree --backend raw --devices "$devs" "$artifacts/exports/final"
diff -qr "$work/src" "$artifacts/exports/final" >"$artifacts/logs/final.diff"
echo "ArgosFS block fault injection passed: seed=$seed artifacts=$artifacts"
