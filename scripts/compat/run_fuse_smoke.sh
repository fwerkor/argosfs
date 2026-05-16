#!/usr/bin/env bash
set -euo pipefail

root="${1:-/tmp/argosfs-fuse-smoke-volume}"
mountpoint="${2:-/tmp/argosfs-fuse-smoke-mount}"

if [ ! -e /dev/fuse ]; then
  echo '{"status":"skipped","reason":"/dev/fuse unavailable"}'
  exit 0
fi

rm -rf "$root" "$mountpoint"
mkdir -p "$mountpoint"
cargo build --release >/dev/null
target/release/argosfs mkfs "$root" --disks 4 --k 2 --m 2 --force >/dev/null
target/release/argosfs mount "$root" "$mountpoint" --foreground &
pid=$!
trap 'fusermount3 -u "$mountpoint" >/dev/null 2>&1 || true; kill "$pid" >/dev/null 2>&1 || true' EXIT

mounted=0
for _ in $(seq 1 50); do
  if ! kill -0 "$pid" >/dev/null 2>&1; then
    echo '{"status":"failed","suite":"fuse-smoke","reason":"mount process exited before readiness"}'
    exit 1
  fi
  if mountpoint -q "$mountpoint"; then
    mounted=1
    break
  fi
  sleep 0.1
done

if [ "$mounted" != 1 ]; then
  echo '{"status":"failed","suite":"fuse-smoke","reason":"mountpoint was not mounted"}'
  exit 1
fi

printf 'hello\n' > "$mountpoint/hello.txt"
chmod 600 "$mountpoint/hello.txt"
truncate -s 64 "$mountpoint/hello.txt"
cat "$mountpoint/hello.txt" >/dev/null
echo '{"status":"passed","suite":"fuse-smoke"}'
