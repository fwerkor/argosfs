#!/usr/bin/env bash
# shellcheck disable=SC2024
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
profile="${1:-${ARGOSFS_FUSE_FAULT_PROFILE:-eio-read}}"
artifacts="${ARGOSFS_TEST_ARTIFACTS:-$repo/target/argosfs-test-artifacts/fuse-block-fault-$profile}"
required="${ARGOSFS_REQUIRE_FUSE_BLOCK_FAULTS:-0}"
seed="${ARGOSFS_FUSE_FAULT_SEED:-0xA2605F5}"
work=""
mount_pid=""
mounted=0
loops=()
mapper_names=()
mappers=()
sectors=()
pids=()

fail_or_skip() {
  local message="$1"
  if [ "$required" = "1" ]; then
    echo "ERROR: $message" >&2
    exit 1
  fi
  echo "SKIP: $message" >&2
  exit 0
}

case "$profile" in
  eio-read|eio-write|corruption|parity-limit) ;;
  *) echo "unknown FUSE block fault profile: $profile" >&2; exit 2 ;;
esac

for command in dmsetup losetup blockdev mountpoint sudo timeout; do
  command -v "$command" >/dev/null 2>&1 || fail_or_skip "$command is unavailable"
done
if command -v fusermount3 >/dev/null 2>&1; then
  fusermount="$(command -v fusermount3)"
elif command -v fusermount >/dev/null 2>&1; then
  fusermount="$(command -v fusermount)"
else
  fail_or_skip "fusermount3/fusermount is unavailable"
fi
[ -e /dev/fuse ] || fail_or_skip "/dev/fuse is unavailable"
sudo modprobe loop 2>/dev/null || true
sudo modprobe dm_mod 2>/dev/null || true
[ -e /dev/loop-control ] || fail_or_skip "/dev/loop-control is unavailable"
[ -e /dev/mapper/control ] || fail_or_skip "/dev/mapper/control is unavailable"
sudo dmsetup version >/dev/null 2>&1 || fail_or_skip "device-mapper control is unavailable"

rm -rf "$artifacts"
mkdir -p "$artifacts"/{logs,exports}
work="$(mktemp -d "${TMPDIR:-/tmp}/argosfs-fuse-block-fault.XXXXXX")"
mkdir -p "$work/src/data" "$work/mnt"

cleanup_mount() {
  set +e
  if [ "$mounted" -eq 1 ] && mountpoint -q "$work/mnt" 2>/dev/null; then
    sudo "$fusermount" -u "$work/mnt" >/dev/null 2>&1 || sudo umount "$work/mnt" >/dev/null 2>&1 || sudo "$fusermount" -uz "$work/mnt" >/dev/null 2>&1 || true
  fi
  mounted=0
  if [ -n "$mount_pid" ] && kill -0 "$mount_pid" >/dev/null 2>&1; then
    sudo kill "$mount_pid" >/dev/null 2>&1 || true
    wait "$mount_pid" >/dev/null 2>&1 || true
  fi
  mount_pid=""
  set -e
}

cleanup() {
  local code=$?
  set +e
  cleanup_mount
  for name in "${mapper_names[@]}"; do
    sudo dmsetup remove --retry "$name" >/dev/null 2>&1 || sudo dmsetup remove -f "$name" >/dev/null 2>&1 || true
  done
  for loop in "${loops[@]}"; do
    sudo losetup -d "$loop" >/dev/null 2>&1 || true
  done
  if [ "${ARGOSFS_KEEP_FUSE_FAULT_WORKDIR:-0}" = "1" ]; then
    echo "FUSE block fault workdir retained at $work" >&2
  else
    sudo rm -rf "$work"
  fi
  exit "$code"
}
trap cleanup EXIT INT TERM

cargo build --manifest-path "$repo/Cargo.toml" --bin argosfs --locked
argosfs="$repo/target/debug/argosfs"
run_tag="${GITHUB_RUN_ID:-$$}-${GITHUB_RUN_ATTEMPT:-1}-$profile"
run_tag="$(printf '%s' "$run_tag" | tr -c '[:alnum:]_-' '-')"

for index in 0 1 2 3 4; do
  backing="$work/backing-$index.img"
  truncate -s "${ARGOSFS_FUSE_FAULT_DEVICE_SIZE:-384M}" "$backing"
  loop="$(sudo losetup --find --show "$backing")"
  loops+=("$loop")
  sector_count="$(sudo blockdev --getsz "$loop")"
  sectors+=("$sector_count")
  name="argosfs-fuse-ci-$run_tag-$index"
  mapper_names+=("$name")
  sudo dmsetup create "$name" --table "0 $sector_count linear $loop 0"
  mapper="/dev/mapper/$name"
  for _ in $(seq 1 100); do
    [ -b "$mapper" ] && break
    sleep 0.05
  done
  [ -b "$mapper" ] || fail_or_skip "device-mapper node was not created: $mapper"
  mappers+=("$mapper")
done

devs="$(IFS=,; echo "${mappers[*]}")"
cat >"$artifacts/logs/metadata.json" <<EOF
{
  "profile": "$profile",
  "seed": "$seed",
  "layout": "3+2",
  "devices": ["${mappers[0]}", "${mappers[1]}", "${mappers[2]}", "${mappers[3]}", "${mappers[4]}"],
  "commit": "${GITHUB_SHA:-$(git -C "$repo" rev-parse HEAD)}"
}
EOF

python3 - "$work/src" "$seed" <<'PY'
from pathlib import Path
import random
import sys
root = Path(sys.argv[1])
rng = random.Random(int(sys.argv[2], 0))
(root / "data").mkdir(parents=True, exist_ok=True)
for index in range(192):
    size = 4096 + rng.randrange(192 * 1024)
    if index % 4 == 0:
        data = (f"argosfs-fuse-fault-{index:03d}\n".encode() * (size // 24 + 1))[:size]
    elif index % 4 == 1:
        data = bytes([index % 251]) * size
    else:
        data = rng.randbytes(size)
    (root / "data" / f"payload-{index:03d}.bin").write_bytes(data)
(root / "sentinel.txt").write_text("ArgosFS FUSE block fault sentinel\n", encoding="utf-8")
PY

sudo "$argosfs" mkfs --backend raw --devices "$devs" --k 3 --m 2 --chunk-size 65536 --compression zstd --force --pool-name "fuse-fault-$profile" >"$artifacts/logs/mkfs.json"
sudo "$argosfs" import-tree --backend raw --devices "$devs" "$work/src" /
sudo "$argosfs" export-tree --backend raw --devices "$devs" "$artifacts/exports/baseline"
diff -qr "$work/src" "$artifacts/exports/baseline" >"$artifacts/logs/baseline.diff"

start_mount() {
  local devices="$1" mode="$2" extra_option="${3:-}"
  local command=(sudo "$argosfs" mount-root --backend raw --devices "$devices" --target "$work/mnt" --mode "$mode" --foreground -o default_permissions)
  if [ -n "$extra_option" ]; then
    command+=(-o "$extra_option")
  fi
  : >"$artifacts/logs/mount-$profile.log"
  "${command[@]}" >"$artifacts/logs/mount-$profile.log" 2>&1 &
  mount_pid=$!
  for _ in $(seq 1 200); do
    if ! kill -0 "$mount_pid" >/dev/null 2>&1; then
      echo "mount process exited before readiness" >&2
      tail -n 200 "$artifacts/logs/mount-$profile.log" >&2 || true
      return 1
    fi
    if mountpoint -q "$work/mnt"; then
      mounted=1
      return 0
    fi
    sleep 0.1
  done
  echo "mount did not become ready" >&2
  return 1
}

stop_mount() {
  if [ "$mounted" -eq 1 ] && mountpoint -q "$work/mnt"; then
    sudo "$fusermount" -u "$work/mnt" >/dev/null 2>&1 || sudo umount "$work/mnt"
  fi
  mounted=0
  if [ -n "$mount_pid" ]; then
    wait "$mount_pid"
  fi
  mount_pid=""
}

set_error() {
  local index="$1"
  local name="${mapper_names[$index]}" count="${sectors[$index]}"
  sudo dmsetup suspend "$name"
  sudo dmsetup reload "$name" --table "0 $count error"
  sudo dmsetup resume "$name"
  sudo dmsetup status "$name" >"$artifacts/logs/dm-error-$index.txt"
}

restore_linear() {
  local index="$1"
  local name="${mapper_names[$index]}" count="${sectors[$index]}" loop="${loops[$index]}"
  sudo dmsetup suspend "$name"
  sudo dmsetup reload "$name" --table "0 $count linear $loop 0"
  sudo dmsetup resume "$name"
  sudo blockdev --flushbufs "${mappers[$index]}" || true
}

verify_all_files() {
  sudo python3 - "$work/src" "$work/mnt" <<'PY'
from pathlib import Path
import hashlib
import os
import sys
left = Path(sys.argv[1])
right = Path(sys.argv[2])
for source in sorted(left.rglob("*")):
    relative = source.relative_to(left)
    target = right / relative
    if source.is_dir():
        if not target.is_dir():
            raise SystemExit(f"missing directory: {relative}")
        continue
    if not target.is_file():
        raise SystemExit(f"missing file: {relative}")
    expected = hashlib.sha256(source.read_bytes()).digest()
    actual = hashlib.sha256(target.read_bytes()).digest()
    if expected != actual:
        raise SystemExit(f"content mismatch: {relative}")
print("all mounted files verified")
PY
}

final_offline_check() {
  sudo "$argosfs" fsck --backend raw --devices "$devs" --repair --remove-orphans >"$artifacts/logs/fsck-final.json"
  sudo "$argosfs" scrub --backend raw --devices "$devs" >"$artifacts/logs/scrub-final.json"
  sudo "$argosfs" verify-journal --backend raw --devices "$devs" >"$artifacts/logs/journal-final.json"
  sudo "$argosfs" export-tree --backend raw --devices "$devs" "$artifacts/exports/final"
  diff -qr "$work/src" "$artifacts/exports/final" >"$artifacts/logs/final.diff"
}

case "$profile" in
  eio-read)
    start_mount "$devs" rw
    set_error 1
    verify_all_files
    for worker in 0 1 2 3; do
      sudo sh -c "find '$work/mnt/data' -type f -print0 | xargs -0 sha256sum >/dev/null" >"$artifacts/logs/eio-read-worker-$worker.log" 2>&1 &
      pids[worker]=$!
    done
    for pid in "${pids[@]}"; do wait "$pid"; done
    kill -0 "$mount_pid"
    restore_linear 1
    stop_mount
    final_offline_check
    ;;

  eio-write)
    start_mount "$devs" rw
    set_error 2
    if sudo timeout 45 dd if=/dev/zero of="$work/mnt/fault-write.bin" bs=65536 count=8 conv=fsync status=none >"$artifacts/logs/eio-write.log" 2>&1; then
      echo "write unexpectedly succeeded while one required raw member returned EIO" >&2
      exit 1
    fi
    kill -0 "$mount_pid"
    verify_all_files
    restore_linear 2
    sudo rm -f "$work/mnt/fault-write.bin"
    sudo sync
    stop_mount
    final_offline_check
    ;;

  corruption)
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
rng = random.Random(int(sys.argv[2], 0) ^ 0xF053C0DE)
Path(sys.argv[1]).write_bytes(rng.randbytes(4096))
PY
    sudo dd if="$work/corruption.bin" of="${mappers[0]}" bs=1 seek="$corrupt_offset" count=4096 conv=notrunc,fsync status=none
    start_mount "$devs" rw
    verify_all_files
    stop_mount
    sudo "$argosfs" scrub --backend raw --devices "$devs" >"$artifacts/logs/scrub-after-corruption.json"
    python3 - "$artifacts/logs/scrub-after-corruption.json" <<'PY'
import json
import sys
report = json.load(open(sys.argv[1]))
if report.get("damaged_files", 0) < 1 or report.get("repaired_files", 0) < 1:
    raise SystemExit(f"corruption was not detected and repaired: {report}")
if report.get("unrecoverable_files", 0) != 0:
    raise SystemExit(f"single-device corruption became unrecoverable: {report}")
PY
    final_offline_check
    ;;

  parity-limit)
    minimum="${mappers[0]},${mappers[2]},${mappers[4]}"
    below_minimum="${mappers[0]},${mappers[2]}"
    sudo "$argosfs" preflight-root --backend raw --devices "$minimum" --mode degraded-ro >"$artifacts/logs/preflight-at-limit.json"
    if sudo "$argosfs" preflight-root --backend raw --devices "$below_minimum" --mode degraded-ro >"$artifacts/logs/preflight-below-limit.log" 2>&1; then
      echo "degraded root preflight unexpectedly accepted fewer than k devices" >&2
      exit 1
    fi
    start_mount "$minimum" degraded-ro ro
    verify_all_files
    if sudo touch "$work/mnt/readonly-write" >"$artifacts/logs/readonly-write.log" 2>&1; then
      echo "degraded read-only FUSE mount unexpectedly accepted a write" >&2
      exit 1
    fi
    stop_mount
    final_offline_check
    ;;
esac

echo "ArgosFS FUSE block fault profile passed: profile=$profile seed=$seed artifacts=$artifacts"
