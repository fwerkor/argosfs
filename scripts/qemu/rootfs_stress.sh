#!/usr/bin/env bash
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
. "$repo/scripts/qemu/lib/common.sh"
artifacts="${ARGOSFS_TEST_ARTIFACTS:-$repo/target/argosfs-test-artifacts/qemu-rootfs-stress}"
mkdir -p "$artifacts"
argosfs_qemu_select_arch
argosfs_qemu_require_binary

log="$artifacts/qemu-rootfs-stress-$arch.log"
commands="$artifacts/qemu-rootfs-stress.commands"
reject="${ARGOSFS_QEMU_REJECT:-Kernel panic|Bad file descriptor|argosfs-initrd: emergency|Oops:|BUG:|segfault|EXT4-fs error|I/O error|No space left on device}"
timeout_s="${ARGOSFS_QEMU_TIMEOUT:-2400}"
console_timeout_s="${ARGOSFS_QEMU_STRESS_CONSOLE_TIMEOUT:-600}"
stress_s="${ARGOSFS_QEMU_STRESS_SECONDS:-1800}"
workers="${ARGOSFS_QEMU_STRESS_WORKERS:-6}"
done_marker="ARGOSFS_QEMU_ROOTFS_STRESS_DONE"

cat >"$commands" <<CMDS
set -eu
echo ARGOSFS_QEMU_ROOTFS_STRESS_BEGIN
awk '\$2=="/"{print "ARGOSFS_ROOT_MOUNT " \$1 " " \$3 " " \$4; exit}' /proc/mounts
test -e /run/argosfs-root-active && echo ARGOSFS_ROOT_MARKER_OK
duration=$stress_s
workers=$workers
rootdir=/root/argosfs-rootfs-stress
rm -rf "\$rootdir"
mkdir -p "\$rootdir"
end=\$((\$(date +%s) + duration))
worker() {
  id="\$1"
  i=0
  wdir="\$rootdir/worker-\$id"
  mkdir -p "\$wdir"
  while [ "\$(date +%s)" -lt "\$end" ]; do
    d="\$wdir/round-\$i"
    mkdir -p "\$d/sub"
    printf 'worker=%s round=%s payload=%s\n' "\$id" "\$i" "\$(date +%s)" >"\$d/file.txt"
    cat "\$d/file.txt" >"\$d/copy.txt"
    dd if=/dev/zero of="\$d/zeros.bin" bs=4096 count=8 2>/dev/null
    printf 'append-%s-%s\n' "\$id" "\$i" >>"\$d/file.txt"
    mv "\$d/copy.txt" "\$d/sub/renamed.txt"
    ln -s ../file.txt "\$d/sub/link.txt"
    cat "\$d/sub/link.txt" >/dev/null
    ln "\$d/file.txt" "\$d/hardlink.txt" 2>/dev/null || true
    chmod 600 "\$d/file.txt"
    test -s "\$d/file.txt"
    sha256sum "\$d/file.txt" "\$d/zeros.bin" >"\$d/SHA256SUMS" 2>/dev/null || true
    if [ \$((i % 4)) -eq 0 ]; then sync; fi
    rm -rf "\$wdir/round-\$((i - 3))" 2>/dev/null || true
    i=\$((i + 1))
  done
  echo "ARGOSFS_STRESS_WORKER_\${id}_DONE rounds=\$i"
}
pids=""
id=1
while [ "\$id" -le "\$workers" ]; do
  worker "\$id" &
  pids="\$pids \$!"
  id=\$((id + 1))
done
worker_fail=0
for pid in \$pids; do
  wait "\$pid" || worker_fail=1
done
if [ "\$worker_fail" -eq 0 ]; then echo ARGOSFS_STRESS_WORKERS_OK; else echo ARGOSFS_STRESS_WORKERS_FAILED; exit 1; fi
find "\$rootdir" -type f | wc -l > /tmp/argosfs-rootfs-stress-file-count.txt
cat /tmp/argosfs-rootfs-stress-file-count.txt
sync
echo ARGOSFS_ROOTFS_STRESS_FILECOUNT_OK
echo ARGOSFS_QEMU_ROOTFS_STRESS_DONE
poweroff -f || reboot -f || halt -f
CMDS

argosfs_qemu_build_args
set +e
# QEMU output is intentionally polled while this pipeline appends to the log.
# shellcheck disable=SC2094
(
  set -e
  argosfs_qemu_wait_console_prompt "$log" 1 "$console_timeout_s" "$reject" "rootfs-stress console prompt"
  argosfs_qemu_stream_script "$commands" 1 /tmp/argosfs-qemu-rootfs-stress.sh "$log"
) | timeout "$timeout_s" "$qemu_bin" "${qemu_args[@]}" >"$log" 2>&1
pipeline_status=("${PIPESTATUS[@]}")
feeder_status="${pipeline_status[0]}"
status="${pipeline_status[1]}"
set -e

if [ "$feeder_status" -ne 0 ]; then
  echo "QEMU rootfs stress feeder failed; status=$feeder_status" >&2
  tail -n 420 "$log" >&2 || true
  exit 1
fi

if grep -Eiq "$reject" "$log"; then
  echo "QEMU rootfs stress failed; qemu status=$status; rejected pattern: $reject" >&2
  tail -n 420 "$log" >&2 || true
  exit 1
fi
missing=()
for marker in ARGOSFS_QEMU_ROOTFS_STRESS_BEGIN ARGOSFS_ROOT_MARKER_OK ARGOSFS_STRESS_WORKERS_OK ARGOSFS_ROOTFS_STRESS_FILECOUNT_OK "$done_marker"; do
  argosfs_qemu_log_has_marker "$log" "$marker" || missing+=("$marker")
done
argosfs_qemu_log_has_root_mount "$log" || missing+=("ARGOSFS_ROOT_MOUNT fuse")
for id in $(seq 1 "$workers"); do
  argosfs_qemu_log_has_marker_prefix "$log" "ARGOSFS_STRESS_WORKER_${id}_DONE" || missing+=("ARGOSFS_STRESS_WORKER_${id}_DONE")
done
if [ "${#missing[@]}" -eq 0 ]; then
  echo "QEMU rootfs stress test passed for $arch; artifacts=$artifacts"
  exit 0
fi

echo "QEMU rootfs stress failed; qemu status=$status; missing markers: ${missing[*]}" >&2
tail -n 420 "$log" >&2 || true
exit 1
