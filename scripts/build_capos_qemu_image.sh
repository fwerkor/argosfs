#!/usr/bin/env bash
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
artifacts="${ARGOSFS_TEST_ARTIFACTS:-$repo/target/argosfs-test-artifacts/capos-full-image}"
arch="${ARGOSFS_QEMU_ARCH:-x86_64}"
capos_target="${ARGOSFS_CAPOS_BUILD_TARGET:-x86_64}"
make_jobs="${ARGOSFS_CAPOS_MAKE_JOBS:-2}"
make_target="${ARGOSFS_CAPOS_IMAGE_MAKE_TARGET:-world}"
require_bootable="${ARGOSFS_CAPOS_REQUIRE_BOOTABLE:-1}"

rm -rf "$artifacts"
mkdir -p "$artifacts"

ARGOSFS_TEST_ARTIFACTS="$artifacts" \
ARGOSFS_CAPOS_FULL_COMPILE=1 \
ARGOSFS_CAPOS_TARGET_MATRIX="$capos_target" \
ARGOSFS_CAPOS_BUILD_TARGET="$capos_target" \
ARGOSFS_CAPOS_MAKE_JOBS="$make_jobs" \
ARGOSFS_CAPOS_MAKE_TARGET="$make_target" \
ARGOSFS_CAPOS_MAKE_V="${ARGOSFS_CAPOS_MAKE_V:-}" \
CAPOS_REPO="${CAPOS_REPO:-https://github.com/fwerkor/capos.git}" \
CAPOS_REF="${CAPOS_REF:-main}" \
CAPOS_LOCAL_SOURCE="${CAPOS_LOCAL_SOURCE:-}" \
"$repo/scripts/test_capos_build.sh"

require_args=()
if [ "$require_bootable" = "1" ]; then
	require_args+=(--require-bootable)
fi
python3 "$repo/scripts/discover_capos_qemu_artifacts.py" \
	--artifacts "$artifacts" \
	--arch "$arch" \
	--output "$artifacts/qemu" \
	"${require_args[@]}"

echo "Full CapOS image build completed; artifacts=$artifacts"
