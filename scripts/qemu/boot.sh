#!/usr/bin/env bash
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=scripts/qemu/lib/common.sh
. "$repo/scripts/qemu/lib/common.sh"
artifacts="${ARGOSFS_TEST_ARTIFACTS:-$repo/target/argosfs-test-artifacts/qemu-boot}"
mkdir -p "$artifacts"

argosfs_qemu_select_arch
argosfs_qemu_require_binary

log="$artifacts/qemu-boot-$arch.log"
expect="${ARGOSFS_QEMU_EXPECT:-switch_root|Please press Enter to activate this console|procd|ARGOSFS_ROOT_ACTIVE}"
reject="${ARGOSFS_QEMU_REJECT:-Kernel panic|Bad file descriptor|argosfs-initrd: emergency}"
timeout_s="${ARGOSFS_QEMU_TIMEOUT:-120}"
argosfs_qemu_build_args

status=0
timeout "$timeout_s" "$qemu_bin" "${qemu_args[@]}" >"$log" 2>&1 || status=$?
if grep -Eiq "$reject" "$log"; then
	echo "QEMU boot smoke failed; qemu status=$status; rejected pattern: $reject" >&2
	tail -n 200 "$log" >&2 || true
	exit 1
fi
if grep -Eiq "$expect" "$log"; then
	echo "QEMU boot smoke passed for $arch; artifacts=$artifacts"
	exit 0
fi

echo "QEMU boot smoke failed; qemu status=$status; expected pattern: $expect" >&2
tail -n 200 "$log" >&2 || true
exit 1
