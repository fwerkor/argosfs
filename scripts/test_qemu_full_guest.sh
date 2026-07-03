#!/usr/bin/env bash
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=scripts/lib/qemu_common.sh
. "$repo/scripts/lib/qemu_common.sh"
artifacts="${ARGOSFS_TEST_ARTIFACTS:-$repo/target/argosfs-test-artifacts/qemu-full-guest}"
mkdir -p "$artifacts"

argosfs_qemu_select_arch
argosfs_qemu_require_binary

log="$artifacts/qemu-full-guest-$arch.log"
commands="$artifacts/qemu-full-guest.commands"
reject="${ARGOSFS_QEMU_REJECT:-Kernel panic|Bad file descriptor|argosfs-initrd: emergency|Oops:|BUG:|segfault}"
timeout_s="${ARGOSFS_QEMU_TIMEOUT:-360}"
login_delay_s="${ARGOSFS_QEMU_FULL_LOGIN_DELAY:-100}"
command_delay_s="${ARGOSFS_QEMU_FULL_COMMAND_DELAY:-1}"
done_marker="ARGOSFS_QEMU_FULL_GUEST_DONE"

cat >"$commands" <<'CMDS'
set -eu
echo ARGOSFS_QEMU_FULL_GUEST_BEGIN
awk '$2=="/"{print "ARGOSFS_ROOT_MOUNT " $1 " " $3 " " $4; exit}' /proc/mounts
test -e /run/argosfs-root-active && echo ARGOSFS_ROOT_MARKER_OK
command -v argosfs >/dev/null && echo ARGOSFS_BIN_OK
argosfs --help >/tmp/argosfs-help.txt && test -s /tmp/argosfs-help.txt && echo ARGOSFS_HELP_OK
test -r /etc/openwrt_release && . /etc/openwrt_release && echo "ARGOSFS_RELEASE ${DISTRIB_ID:-unknown} ${DISTRIB_RELEASE:-unknown}"
uname -a
mount
# Software and service operations that should not require network access.
if command -v apk >/dev/null; then apk info >/tmp/argosfs-pkg-list.txt && test -s /tmp/argosfs-pkg-list.txt && echo ARGOSFS_PKG_QUERY_OK; fi
if command -v opkg >/dev/null; then opkg list-installed >/tmp/argosfs-pkg-list.txt && test -s /tmp/argosfs-pkg-list.txt && echo ARGOSFS_PKG_QUERY_OK; fi
if command -v uci >/dev/null; then uci show system >/tmp/argosfs-uci-system.txt 2>/dev/null && echo ARGOSFS_UCI_QUERY_OK || true; fi
if [ -x /etc/init.d/network ]; then /etc/init.d/network enabled >/dev/null 2>&1 || true; /etc/init.d/network status >/tmp/argosfs-network-status.txt 2>&1 || true; echo ARGOSFS_SERVICE_QUERY_OK; fi
# Persistent root filesystem operations, not just tmpfs.
rootdir=/root/argosfs-ci-full
rm -rf "$rootdir"
mkdir -p "$rootdir/subdir"
printf 'alpha\n' >"$rootdir/file.txt"
printf 'beta\n' >>"$rootdir/file.txt"
test "$(wc -l <"$rootdir/file.txt")" -eq 2
cp "$rootdir/file.txt" "$rootdir/subdir/copy.txt"
ln -s ../file.txt "$rootdir/subdir/link.txt"
test "$(cat "$rootdir/subdir/link.txt")" = "alpha
beta"
chmod 600 "$rootdir/file.txt"
ls -l "$rootdir/file.txt" >/tmp/argosfs-file-ls.txt
mv "$rootdir/subdir/copy.txt" "$rootdir/subdir/renamed.txt"
dd if=/dev/zero of="$rootdir/sparse.bin" bs=4096 count=16 2>/dev/null
dd if=/dev/zero of="$rootdir/zeros.bin" bs=4096 count=16 2>/dev/null
sha256sum "$rootdir/file.txt" "$rootdir/zeros.bin" >/tmp/argosfs-root-sha256.txt
sync
echo ARGOSFS_ROOT_FILE_OPS_OK
# Exercise ArgosFS CLI inside the guest, including compression and encryption.
vol=/tmp/argosfs-guest-volume
src=/tmp/argosfs-guest-src
out=/tmp/argosfs-guest-out
rm -rf "$vol" "$src" "$out"
mkdir -p "$src" "$out"
printf 'compressible payload\n' >"$src/text.txt"
dd if=/dev/zero of="$src/zeros.bin" bs=4096 count=32 2>/dev/null
argosfs mkfs "$vol" --force --disks 4 --k 2 --m 1 --chunk-size 32768 --compression zstd >/tmp/argosfs-guest-mkfs.json
argosfs mkdir "$vol" /data --mode 755
argosfs put "$vol" "$src/text.txt" /data/text.txt
argosfs put "$vol" "$src/zeros.bin" /data/zeros.bin
argosfs get "$vol" /data/text.txt "$out/text.txt"
argosfs get "$vol" /data/zeros.bin "$out/zeros.bin"
cmp "$src/text.txt" "$out/text.txt"
cmp "$src/zeros.bin" "$out/zeros.bin"
argosfs enable-encryption "$vol" --passphrase ci-guest-key --reencrypt >/tmp/argosfs-guest-encrypt.json
ARGOSFS_KEY=ci-guest-key argosfs encryption-status "$vol" >/tmp/argosfs-guest-encryption-status.json
ARGOSFS_KEY=ci-guest-key argosfs scrub "$vol" >/tmp/argosfs-guest-scrub.json
ARGOSFS_KEY=ci-guest-key argosfs fsck "$vol" --repair --remove-orphans >/tmp/argosfs-guest-fsck.json
ARGOSFS_KEY=ci-guest-key argosfs verify-journal "$vol" >/tmp/argosfs-guest-journal.json
ARGOSFS_KEY=ci-guest-key argosfs health "$vol" --json >/tmp/argosfs-guest-health.json
grep -q '"enabled": true' /tmp/argosfs-guest-encryption-status.json
grep -q '"encrypted": true' "$vol/.argosfs/meta.json"
grep -Eq '"codec": "(zstd|lz4)"' "$vol/.argosfs/meta.json"
python3 - <<'PY' 2>/tmp/argosfs-python.err || awk '/"enabled": true/{ok=1} END{exit ok?0:1}' /tmp/argosfs-guest-encryption-status.json
import json
from pathlib import Path
status = json.loads(Path('/tmp/argosfs-guest-encryption-status.json').read_text())
assert status['enabled'] is True
assert int(status.get('encrypted_blocks', 0)) >= 1
meta = json.loads(Path('/tmp/argosfs-guest-volume/.argosfs/meta.json').read_text())
blocks = [b for inode in meta.get('inodes', {}).values() for b in inode.get('blocks', [])]
assert any(b.get('encrypted') for b in blocks)
assert any(b.get('codec') not in (None, 'none', 'None') and b.get('compressed_size', 0) < b.get('raw_size', 0) for b in blocks)
PY
echo ARGOSFS_GUEST_FEATURES_OK
# Save a persistence marker for the reboot test and leave rootdir for inspection after reboot.
printf 'persistent marker\n' > /root/argosfs-reboot-marker.txt
sync
echo ARGOSFS_QEMU_FULL_GUEST_DONE
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
	echo "QEMU full guest failed; qemu status=$status; rejected pattern: $reject" >&2
	tail -n 320 "$log" >&2 || true
	exit 1
fi
missing=()
for marker in \
	ARGOSFS_QEMU_FULL_GUEST_BEGIN \
	ARGOSFS_ROOT_MARKER_OK \
	ARGOSFS_BIN_OK \
	ARGOSFS_HELP_OK \
	ARGOSFS_ROOT_FILE_OPS_OK \
	ARGOSFS_GUEST_FEATURES_OK \
	"$done_marker"; do
	if ! grep -Fq "$marker" "$log"; then
		missing+=("$marker")
	fi
done
if ! grep -Eq 'ARGOSFS_ROOT_MOUNT .* fuse' "$log"; then
	missing+=("ARGOSFS_ROOT_MOUNT fuse")
fi
if [ "${#missing[@]}" -eq 0 ]; then
	echo "QEMU full guest test passed for $arch; artifacts=$artifacts"
	exit 0
fi

echo "QEMU full guest failed; qemu status=$status; missing markers: ${missing[*]}" >&2
tail -n 320 "$log" >&2 || true
exit 1
