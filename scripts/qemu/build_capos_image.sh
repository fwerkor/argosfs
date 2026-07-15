#!/usr/bin/env bash
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
artifacts="${ARGOSFS_TEST_ARTIFACTS:-$repo/target/argosfs-test-artifacts/capos-full-image}"
arch="${ARGOSFS_QEMU_ARCH:-x86_64}"
capos_target="${ARGOSFS_CAPOS_BUILD_TARGET:-x86_64}"
make_jobs="${ARGOSFS_CAPOS_MAKE_JOBS:-2}"
make_target="${ARGOSFS_CAPOS_IMAGE_MAKE_TARGET:-world}"
require_bootable="${ARGOSFS_CAPOS_REQUIRE_BOOTABLE:-1}"

rm -rf "$artifacts"
mkdir -p "$artifacts"
artifacts="$(cd "$artifacts" && pwd)"

# Keep the full-image workflow aligned with CapOS' compressed arm64 EFI
# kernel path. The shared build helper still supports older CapOS refs, so patch
# only the generated CI config size at runtime instead of hard-coding a larger
# aarch64 boot partition for this workflow.
if [ "$capos_target" = "armsr_armv8" ]; then
	python3 - <<'PY'
from pathlib import Path
path = Path("scripts/qemu/capos_build.sh")
text = path.read_text()
old = "CONFIG_TARGET_KERNEL_PARTSIZE=128\n"
new = "CONFIG_TARGET_KERNEL_PARTSIZE=64\n"
if old not in text:
    raise SystemExit("expected armsr kernel partition override was not found")
path.write_text(text.replace(old, new, 1))
PY
fi

ARGOSFS_TEST_ARTIFACTS="$artifacts" \
ARGOSFS_CAPOS_FULL_COMPILE=1 \
ARGOSFS_CAPOS_TARGET_MATRIX="$capos_target" \
ARGOSFS_CAPOS_BUILD_TARGET="$capos_target" \
ARGOSFS_CAPOS_MAKE_JOBS="$make_jobs" \
ARGOSFS_CAPOS_MAKE_TARGET="$make_target" \
ARGOSFS_CAPOS_MAKE_V="${ARGOSFS_CAPOS_MAKE_V:-}" \
CAPOS_REPO="${CAPOS_REPO:-https://github.com/fwerkor/capos.git}" \
CAPOS_REF="${CAPOS_REF:-3903b2968a692fdc77e05f63eb3a1cfa9a739999}" \
CAPOS_LOCAL_SOURCE="${CAPOS_LOCAL_SOURCE:-}" \
"$repo/scripts/qemu/capos_build.sh"

require_args=()
if [ "$require_bootable" = "1" ]; then
	require_args+=(--require-bootable)
fi
python3 "$repo/scripts/qemu/discover_artifacts.py" \
	--artifacts "$artifacts" \
	--arch "$arch" \
	--output "$artifacts/qemu" \
	"${require_args[@]}"

echo "Full CapOS image build completed; artifacts=$artifacts"
