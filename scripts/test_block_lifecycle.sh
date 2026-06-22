#!/usr/bin/env bash
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
artifacts="${ARGOSFS_TEST_ARTIFACTS:-$repo/target/argosfs-test-artifacts/block-lifecycle}"
rm -rf "$artifacts"
mkdir -p "$artifacts"/{src,out,logs}

cargo build --manifest-path "$repo/Cargo.toml" --bin argosfs --locked
argosfs="$repo/target/debug/argosfs"
images="$artifacts/disk0.img,$artifacts/disk1.img,$artifacts/disk2.img"
all_images="$images"

python3 - <<'PY' "$artifacts/src"
from pathlib import Path
import random
import sys
root = Path(sys.argv[1])
(root / "data").mkdir(parents=True, exist_ok=True)
rng = random.Random(0xA2605F5)
for idx in range(8):
    if idx % 2 == 0:
        payload = (f"argon-lifecycle-{idx}\n".encode() * 8192)
    else:
        payload = bytes(rng.getrandbits(8) for _ in range(128 * 1024))
    (root / "data" / f"file-{idx}.bin").write_bytes(payload)
PY

"$argosfs" mkfs --backend loop --images "$images" --k 2 --m 1 --image-size $((64 * 1024 * 1024)) --pool-name ci-block-lifecycle --force >"$artifacts/logs/mkfs.json"
"$argosfs" import-tree --backend loop --images "$all_images" "$artifacts/src" /
"$argosfs" list-devices --backend loop --images "$all_images" >"$artifacts/logs/devices-initial.json"
"$argosfs" fsck --backend loop --images "$all_images" >"$artifacts/logs/fsck-initial.json"

new_disk="$artifacts/disk3.img"
add_json="$artifacts/logs/add-device.json"
"$argosfs" add-device --backend loop --images "$all_images" --device "$new_disk" --image-size $((64 * 1024 * 1024)) --force >"$add_json"
all_images="$all_images,$new_disk"
new_id="$(python3 - <<'PY' "$add_json"
from pathlib import Path
import json
import sys
print(json.loads(Path(sys.argv[1]).read_text())["disk_id"])
PY
)"
test -n "$new_id"
"$argosfs" list-devices --backend loop --images "$all_images" >"$artifacts/logs/devices-after-add.json"
"$argosfs" scrub --backend loop --images "$all_images" >"$artifacts/logs/scrub-after-add.json"

"$argosfs" drain-device --backend loop --images "$all_images" --device disk-0000 >"$artifacts/logs/drain-disk-0000.json"
"$argosfs" remove-device --backend loop --images "$all_images" --device disk-0000 >"$artifacts/logs/remove-disk-0000.json"
"$argosfs" list-devices --backend loop --images "$all_images" >"$artifacts/logs/devices-after-remove.json"
"$argosfs" fsck --backend loop --images "$all_images" --repair --remove-orphans >"$artifacts/logs/fsck-after-remove.json"

replacement="$artifacts/disk4.img"
"$argosfs" replace-device --backend loop --images "$all_images" --old disk-0001 --new "$replacement" --image-size $((64 * 1024 * 1024)) --force >"$artifacts/logs/replace-disk-0001.json"
all_images="$all_images,$replacement"
"$argosfs" list-devices --backend loop --images "$all_images" >"$artifacts/logs/devices-after-replace.json"
"$argosfs" reshape --backend loop --images "$all_images" --k 2 --m 1 >"$artifacts/logs/reshape.json"
"$argosfs" fsck --backend loop --images "$all_images" --repair --remove-orphans >"$artifacts/logs/fsck-final.json"
"$argosfs" export-tree --backend loop --images "$all_images" "$artifacts/out"

diff -qr "$artifacts/src" "$artifacts/out"
python3 - <<'PY' "$artifacts/logs/devices-after-replace.json"
from pathlib import Path
import json
import sys
report = json.loads(Path(sys.argv[1]).read_text())
statuses = {disk_id: disk.get("status") for disk_id, disk in report.items()}
if statuses.get("disk-0000") != "removed":
    raise SystemExit(f"disk-0000 was not removed: {statuses}")
if statuses.get("disk-0001") != "removed":
    raise SystemExit(f"disk-0001 was not replaced/removed: {statuses}")
online = [disk_id for disk_id, status in statuses.items() if status == "online"]
if len(online) < 3:
    raise SystemExit(f"expected at least 3 online disks after lifecycle operations, got {online}")
print("block lifecycle metadata checks passed")
PY

echo "ArgosFS block lifecycle test passed; artifacts=$artifacts"
