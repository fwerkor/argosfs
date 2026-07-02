#!/usr/bin/env bash
set -euo pipefail

artifacts="${ARGOSFS_TEST_ARTIFACTS:?ARGOSFS_TEST_ARTIFACTS is required}"
bundle="${ARGOSFS_QEMU_BUNDLE_DIR:-$artifacts/qemu-bundle}"
manifest="${ARGOSFS_QEMU_MANIFEST:-$artifacts/qemu/qemu-artifacts.json}"
rm -rf "$bundle"
mkdir -p "$bundle"

python3 - <<'PY' "$manifest" "$bundle"
import json, shutil, sys
from pathlib import Path
manifest = Path(sys.argv[1]).resolve()
bundle = Path(sys.argv[2]).resolve()
data = json.loads(manifest.read_text(encoding="utf-8"))
entries = {"BUNDLE_ARCH": data.get("arch", ""), "BUNDLE_BOOT_MODE": data.get("boot_mode", "none")}

def copy_entry(key):
    src_value = data.get(key) or ""
    if not src_value:
        entries[f"BUNDLE_{key.upper()}"] = ""
        return
    src = Path(src_value)
    if not src.is_file():
        raise SystemExit(f"{key} does not exist: {src}")
    dst_name = {"kernel": "kernel" + (src.suffix if src.suffix else ""), "rootfs": "rootfs.img", "disk_image": "disk.img"}[key]
    shutil.copy2(src, bundle / dst_name)
    entries[f"BUNDLE_{key.upper()}"] = dst_name

for key in ("kernel", "rootfs", "disk_image"):
    copy_entry(key)
(bundle / "qemu-artifacts.json").write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
with (bundle / "bundle.env").open("w", encoding="utf-8") as f:
    for key, value in entries.items():
        f.write(f"{key}={value}\n")
print(json.dumps(entries, indent=2))
PY

echo "Packed QEMU bundle at $bundle"
