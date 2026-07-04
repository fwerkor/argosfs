#!/usr/bin/env bash
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=scripts/lib/qemu_common.sh
. "$repo/scripts/lib/qemu_common.sh"
artifacts="${ARGOSFS_TEST_ARTIFACTS:-$repo/target/argosfs-test-artifacts/qemu-reboot}"
mkdir -p "$artifacts"

argosfs_qemu_select_arch
argosfs_qemu_require_binary

log="$artifacts/qemu-reboot-$arch.log"
commands1="$artifacts/qemu-reboot-phase1.commands"
commands2="$artifacts/qemu-reboot-phase2.commands"
reject="${ARGOSFS_QEMU_REJECT:-Kernel panic|Bad file descriptor|argosfs-initrd: emergency|Oops:|BUG:|segfault}"
timeout_s="${ARGOSFS_QEMU_TIMEOUT:-600}"
login_delay_s="${ARGOSFS_QEMU_REBOOT_LOGIN_DELAY:-140}"
login_delay_s="$(argosfs_qemu_adjust_login_delay "$login_delay_s")"
reboot_delay_s="${ARGOSFS_QEMU_REBOOT_DELAY:-140}"
reboot_delay_s="$(argosfs_qemu_adjust_login_delay "$reboot_delay_s")"
command_delay_s="${ARGOSFS_QEMU_REBOOT_COMMAND_DELAY:-1}"
done_marker="ARGOSFS_QEMU_REBOOT_DONE"

cat >"$commands1" <<'CMDS'
set -eu
echo ARGOSFS_QEMU_REBOOT_PHASE1_BEGIN
awk '$2=="/"{print "ARGOSFS_ROOT_MOUNT_PHASE1 " $1 " " $3 " " $4; exit}' /proc/mounts
test -e /run/argosfs-root-active && echo ARGOSFS_REBOOT_ROOT_MARKER_PHASE1_OK
mkdir -p /root/argosfs-reboot-ci
printf 'reboot persistent payload\n' >/root/argosfs-reboot-ci/persistent.txt
sha256sum /root/argosfs-reboot-ci/persistent.txt >/root/argosfs-reboot-ci/persistent.sha256
sync
echo ARGOSFS_REBOOT_REQUESTED
reboot -f
CMDS
cat >"$commands2" <<'CMDS'
set -eu
echo ARGOSFS_QEMU_REBOOT_PHASE2_BEGIN
awk '$2=="/"{print "ARGOSFS_ROOT_MOUNT_PHASE2 " $1 " " $3 " " $4; exit}' /proc/mounts
test -e /run/argosfs-root-active && echo ARGOSFS_REBOOT_ROOT_MARKER_PHASE2_OK
cd /root/argosfs-reboot-ci
sha256sum -c persistent.sha256
grep -q 'reboot persistent payload' persistent.txt
echo ARGOSFS_REBOOT_PERSISTENCE_OK
sync
echo ARGOSFS_QEMU_REBOOT_DONE
poweroff -f || reboot -f || halt -f
CMDS

export ARGOSFS_QEMU_NO_REBOOT=0
argosfs_qemu_build_args

send_command_file() {
	local file="$1"
	printf '\r' >&3
	sleep "$command_delay_s"
	while IFS= read -r line; do
		printf '%s\r' "$line" >&3
		sleep "$command_delay_s"
	done <"$file"
}

wait_for_log_count() {
	local pattern="$1"
	local min_count="$2"
	local wait_s="$3"
	local label="$4"
	local deadline=$((SECONDS + wait_s))
	while [ "$SECONDS" -lt "$deadline" ]; do
		if grep -Eiq "$reject" "$log" 2>/dev/null; then
			echo "QEMU reboot persistence failed while waiting for $label; rejected pattern: $reject" >&2
			return 2
		fi
		local count
		count="$(grep -Ec "$pattern" "$log" 2>/dev/null || true)"
		if [ "$count" -ge "$min_count" ]; then
			return 0
		fi
		sleep 1
	done
	echo "timed out waiting for $label in $log" >&2
	return 1
}

stdin_fifo="$artifacts/qemu-reboot-$arch.stdin"
rm -f "$stdin_fifo"
mkfifo "$stdin_fifo"
: >"$log"

set +e
timeout "$timeout_s" "$qemu_bin" "${qemu_args[@]}" <"$stdin_fifo" >"$log" 2>&1 &
qemu_pid=$!
exec 3>"$stdin_fifo"

wait_status=0
wait_for_log_count 'Please press Enter to activate this console\.' 1 "$login_delay_s" 'first login prompt' || wait_status=$?
if [ "$wait_status" -eq 0 ]; then
	send_command_file "$commands1"
	wait_for_log_count 'ARGOSFS_REBOOT_REQUESTED' 1 60 'phase1 reboot request' || wait_status=$?
fi
if [ "$wait_status" -eq 0 ]; then
	wait_for_log_count 'Please press Enter to activate this console\.' 2 "$reboot_delay_s" 'second login prompt' || wait_status=$?
fi
if [ "$wait_status" -eq 0 ]; then
	send_command_file "$commands2"
	wait_for_log_count "$done_marker" 1 120 'reboot persistence completion' || wait_status=$?
fi
exec 3>&-
if [ "$wait_status" -eq 0 ]; then
	# Give the guest a short window to honor poweroff before collecting status.
	for _ in $(seq 1 10); do
		if ! kill -0 "$qemu_pid" 2>/dev/null; then
			break
		fi
		sleep 1
	done
fi
if kill -0 "$qemu_pid" 2>/dev/null; then
	kill "$qemu_pid" 2>/dev/null || true
fi
wait "$qemu_pid"
status=$?
rm -f "$stdin_fifo"
if [ "$wait_status" -ne 0 ]; then
	status="$wait_status"
fi
set -e

if grep -Eiq "$reject" "$log"; then
	echo "QEMU reboot persistence failed; qemu status=$status; rejected pattern: $reject" >&2
	tail -n 360 "$log" >&2 || true
	exit 1
fi
missing=()
for marker in \
	ARGOSFS_QEMU_REBOOT_PHASE1_BEGIN \
	ARGOSFS_REBOOT_ROOT_MARKER_PHASE1_OK \
	ARGOSFS_REBOOT_REQUESTED \
	ARGOSFS_QEMU_REBOOT_PHASE2_BEGIN \
	ARGOSFS_REBOOT_ROOT_MARKER_PHASE2_OK \
	ARGOSFS_REBOOT_PERSISTENCE_OK \
	"$done_marker"; do
	if ! grep -Fq "$marker" "$log"; then
		missing+=("$marker")
	fi
done
if ! grep -Eq 'ARGOSFS_ROOT_MOUNT_PHASE1 .* fuse' "$log"; then
	missing+=("ARGOSFS_ROOT_MOUNT_PHASE1 fuse")
fi
if ! grep -Eq 'ARGOSFS_ROOT_MOUNT_PHASE2 .* fuse' "$log"; then
	missing+=("ARGOSFS_ROOT_MOUNT_PHASE2 fuse")
fi
if [ "${#missing[@]}" -eq 0 ]; then
	echo "QEMU reboot persistence test passed for $arch; artifacts=$artifacts"
	exit 0
fi

echo "QEMU reboot persistence failed; qemu status=$status; missing markers: ${missing[*]}" >&2
tail -n 360 "$log" >&2 || true
exit 1
