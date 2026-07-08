#!/usr/bin/env bash
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=scripts/qemu/lib/common.sh
. "$repo/scripts/qemu/lib/common.sh"
artifacts="${ARGOSFS_TEST_ARTIFACTS:-$repo/target/argosfs-test-artifacts/qemu-ops}"
mkdir -p "$artifacts"

argosfs_qemu_select_arch
argosfs_qemu_require_binary

log="$artifacts/qemu-ops-$arch.log"
commands="$artifacts/qemu-ops.commands"
reject="${ARGOSFS_QEMU_REJECT:-Kernel panic|Bad file descriptor|argosfs-initrd: emergency}"
timeout_s="${ARGOSFS_QEMU_TIMEOUT:-240}"
login_delay_s="${ARGOSFS_QEMU_OPS_LOGIN_DELAY:-90}"
command_delay_s="${ARGOSFS_QEMU_OPS_COMMAND_DELAY:-1}"
done_marker="ARGOSFS_QEMU_OPS_DONE"

cat >"$commands" <<'CMDS'
echo ARGOSFS_QEMU_OPS_BEGIN
awk '$2=="/"{print "ARGOSFS_ROOT_MOUNT " $1 " " $3 " " $4; exit}' /proc/mounts
test -e /run/argosfs-root-active && echo ARGOSFS_MARKER_OK
test -r /etc/openwrt_release && . /etc/openwrt_release && echo "ARGOSFS_RELEASE ${DISTRIB_ID:-unknown} ${DISTRIB_RELEASE:-unknown}"
ls -ld / /etc /run /tmp
mkdir -p /tmp/argosfs-qemu-ops
printf 'argosfs-qemu-ops\n' >/tmp/argosfs-qemu-ops/payload.txt
cat /tmp/argosfs-qemu-ops/payload.txt
ln -sf payload.txt /tmp/argosfs-qemu-ops/link.txt
test "$(cat /tmp/argosfs-qemu-ops/link.txt)" = "argosfs-qemu-ops" && echo ARGOSFS_TMPFS_RW_OK
rm -f /tmp/argosfs-qemu-ops/link.txt /tmp/argosfs-qemu-ops/payload.txt
rmdir /tmp/argosfs-qemu-ops
sync
echo ARGOSFS_QEMU_OPS_DONE
poweroff -f || reboot -f || halt -f
CMDS

argosfs_qemu_build_args

set +e
(
	sleep "$login_delay_s"
	printf '\r'
	sleep "$command_delay_s"
	while IFS= read -r line; do
		printf '%s\r' "$line"
		sleep "$command_delay_s"
	done <"$commands"
) | timeout "$timeout_s" "$qemu_bin" "${qemu_args[@]}" >"$log" 2>&1
status=${PIPESTATUS[1]}
set -e

if grep -Eiq "$reject" "$log"; then
	echo "QEMU ops failed; qemu status=$status; rejected pattern: $reject" >&2
	tail -n 240 "$log" >&2 || true
	exit 1
fi

missing=()
for marker in ARGOSFS_QEMU_OPS_BEGIN ARGOSFS_MARKER_OK ARGOSFS_TMPFS_RW_OK "$done_marker"; do
	if ! grep -Fq "$marker" "$log"; then
		missing+=("$marker")
	fi
done
if ! grep -Eq 'ARGOSFS_ROOT_MOUNT .* fuse' "$log"; then
	missing+=("ARGOSFS_ROOT_MOUNT fuse")
fi

if [ "${#missing[@]}" -eq 0 ]; then
	echo "QEMU ops smoke passed for $arch; artifacts=$artifacts"
	exit 0
fi

echo "QEMU ops failed; qemu status=$status; missing markers: ${missing[*]}" >&2
tail -n 240 "$log" >&2 || true
exit 1
