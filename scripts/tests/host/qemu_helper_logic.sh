#!/usr/bin/env bash
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
# shellcheck source=scripts/qemu/lib/common.sh
. "$repo/scripts/qemu/lib/common.sh"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
log="$tmp/serial.log"

cat >"$log" <<'EOF'
> echo ARGOSFS_EVENT_DONE
root@CapOS:~# echo ARGOSFS_EVENT_DONE
awk '$2=="/"{print "ARGOSFS_ROOT_MOUNT " $1 " " $3; exit}' /proc/mounts
EOF

if argosfs_qemu_log_has_marker "$log" ARGOSFS_EVENT_DONE; then
	echo "marker helper accepted uploaded command text" >&2
	exit 1
fi
if [ "$(argosfs_qemu_log_marker_count "$log" ARGOSFS_EVENT_DONE)" -ne 0 ]; then
	echo "marker counter accepted uploaded command text" >&2
	exit 1
fi
if argosfs_qemu_log_has_root_mount "$log"; then
	echo "root mount helper accepted an unevaluated command" >&2
	exit 1
fi

{
	printf 'ARGOSFS_EVENT_DONE\r\n'
	printf 'ARGOSFS_ROOT_MOUNT argosfs fuse.argosfs rw,relatime\r\n'
	printf 'ARGOSFS_STRESS_WORKER_1_DONE rounds=42\r\n'
} >>"$log"

argosfs_qemu_log_has_marker "$log" ARGOSFS_EVENT_DONE
[ "$(argosfs_qemu_log_marker_count "$log" ARGOSFS_EVENT_DONE)" -eq 1 ]
argosfs_qemu_log_has_root_mount "$log"
argosfs_qemu_log_has_marker_prefix "$log" ARGOSFS_STRESS_WORKER_1_DONE

printf 'QEMU helper marker tests passed\n'
