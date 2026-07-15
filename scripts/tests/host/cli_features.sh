#!/usr/bin/env bash
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
artifacts="${ARGOSFS_TEST_ARTIFACTS:-$repo/target/argosfs-test-artifacts/cli-features}"
rm -rf "$artifacts"
mkdir -p "$artifacts"/{src,out,keys,logs}

cargo build --manifest-path "$repo/Cargo.toml" --bin argosfs --locked
argosfs="$repo/target/debug/argosfs"
volume="$artifacts/volume"
key_file="$artifacts/keys/argosfs.key"
printf 'argosfs-ci-feature-key\n' >"$key_file"
chmod 0600 "$key_file"

python3 - <<'PY' "$artifacts/src"
from pathlib import Path
import os
import random
import sys
root = Path(sys.argv[1])
(root / "small.txt").write_text("ArgosFS CLI feature test\n" * 32, encoding="utf-8")
(root / "compressible.bin").write_bytes((b"argosfs-compressible-block\n" * 2048))
rng = random.Random(0xA2605F5)
(root / "random.bin").write_bytes(bytes(rng.getrandbits(8) for _ in range(64 * 1024)))
PY

"$argosfs" mkfs "$volume" --force --disks 5 --k 3 --m 1 --chunk-size 32768 --compression zstd >"$artifacts/logs/mkfs.json"
"$argosfs" mkdir "$volume" /data --mode 755
"$argosfs" put "$volume" "$artifacts/src/small.txt" /data/small.txt
"$argosfs" put "$volume" "$artifacts/src/compressible.bin" /data/compressible.bin
"$argosfs" put "$volume" "$artifacts/src/random.bin" /data/random.bin
"$argosfs" ls "$volume" /data --json >"$artifacts/logs/ls-data.json"
"$argosfs" stat "$volume" /data/small.txt >"$artifacts/logs/stat-small.json"
"$argosfs" cat "$volume" /data/small.txt >"$artifacts/out/cat-small.txt"
"$argosfs" get "$volume" /data/random.bin "$artifacts/out/random.bin"
cmp "$artifacts/src/small.txt" "$artifacts/out/cat-small.txt"
cmp "$artifacts/src/random.bin" "$artifacts/out/random.bin"

"$argosfs" symlink "$volume" /data/small.txt /data/small.symlink
"$argosfs" cat "$volume" /data/small.symlink >"$artifacts/out/symlink-small.txt"
cmp "$artifacts/src/small.txt" "$artifacts/out/symlink-small.txt"
"$argosfs" rename "$volume" /data/small.symlink /data/small.renamed-link
"$argosfs" chmod "$volume" /data/small.txt 600
"$argosfs" truncate "$volume" /data/small.txt 12
"$argosfs" stat "$volume" /data/small.txt >"$artifacts/logs/stat-small-truncated.json"
"$argosfs" cat "$volume" /data/small.txt >"$artifacts/out/small-truncated.txt"
test "$(wc -c <"$artifacts/out/small-truncated.txt")" -eq 12
"$argosfs" rm "$volume" /data/small.renamed-link
"$argosfs" mknod "$volume" /data/compat.fifo --mode 010600 --rdev 0
"$argosfs" stat "$volume" /data/compat.fifo >"$artifacts/logs/stat-fifo.json"
"$argosfs" rm "$volume" /data/compat.fifo
"$argosfs" ls "$volume" /data >"$artifacts/logs/ls-data.txt"

extra_path="$artifacts/extra-disk"
extra_id="$("$argosfs" add-disk "$volume" --path "$extra_path" --tier cold --weight 0.75 --capacity-bytes 64MiB)"
test -n "$extra_id"
"$argosfs" probe-disks "$volume" "$extra_id" >"$artifacts/logs/probe-extra.json"
"$argosfs" set-health "$volume" "$extra_id" \
  --reallocated-sectors 2 --pending-sectors 1 --crc-errors 3 --io-errors 4 \
  --latency-ms 12.5 --wear-percent 20 --temperature-c 35
"$argosfs" mark-disk "$volume" "$extra_id" degraded
"$argosfs" health "$volume" >"$artifacts/logs/health-degraded.txt"
"$argosfs" mark-disk "$volume" "$extra_id" online
"$argosfs" rebalance "$volume" >"$artifacts/logs/rebalance.json"
"$argosfs" reshape "$volume" --k 3 --m 1 --max-files 1 >"$artifacts/logs/reshape.json"
"$argosfs" remove-disk "$volume" "$extra_id" >"$artifacts/logs/remove-extra.json"

"$argosfs" fsck "$volume" >"$artifacts/logs/fsck-readonly.json"
"$argosfs" autopilot "$volume" --once --dry-run >"$artifacts/logs/autopilot-dry-run.txt"
"$argosfs" autopilot "$volume" --once --explain --json >"$artifacts/logs/autopilot-explain.json"
"$argosfs" compact-journal "$volume" >"$artifacts/logs/compact-journal.json"

"$argosfs" snapshot "$volume" ci-snapshot >"$artifacts/logs/snapshot.txt"
"$argosfs" set-posix-acl "$volume" /data/random.bin 'user::rw-,group::r--,mask::r--,other::---'
"$argosfs" get-posix-acl "$volume" /data/random.bin >"$artifacts/logs/random.posix-acl"
"$argosfs" set-posix-acl "$volume" /data 'user::rwx,group::r-x,mask::r-x,other::---' --default-acl
"$argosfs" get-posix-acl "$volume" /data --default-acl >"$artifacts/logs/data.default-posix-acl"
cat >"$artifacts/logs/nfs4-acl.json" <<'JSON'
{"entries":[{"ace_type":"allow","principal":"EVERYONE@","flags":[],"permissions":["read"]}]}
JSON
"$argosfs" set-nfs4-acl "$volume" /data/random.bin "@$artifacts/logs/nfs4-acl.json"
"$argosfs" get-nfs4-acl "$volume" /data/random.bin >"$artifacts/logs/random.nfs4-acl.json"

"$argosfs" enable-encryption "$volume" --key-file "$key_file" --reencrypt >"$artifacts/logs/enable-encryption.json"
ARGOSFS_KEY_FILE="$key_file" "$argosfs" encryption-status "$volume" >"$artifacts/logs/encryption-status.json"
ARGOSFS_KEY_FILE="$key_file" "$argosfs" get "$volume" /data/compressible.bin "$artifacts/out/compressible.bin"
cmp "$artifacts/src/compressible.bin" "$artifacts/out/compressible.bin"
ARGOSFS_KEY_FILE="$key_file" "$argosfs" set-io-mode "$volume" --mode direct --direct-io --no-zero-copy --no-numa >"$artifacts/logs/io-mode-direct.json"
ARGOSFS_KEY_FILE="$key_file" "$argosfs" set-io-mode "$volume" --mode buffered >"$artifacts/logs/io-mode.json"
ARGOSFS_KEY_FILE="$key_file" "$argosfs" scrub "$volume" >"$artifacts/logs/scrub.json"
ARGOSFS_KEY_FILE="$key_file" "$argosfs" fsck "$volume" --repair --remove-orphans >"$artifacts/logs/fsck.json"
ARGOSFS_KEY_FILE="$key_file" "$argosfs" verify-journal "$volume" >"$artifacts/logs/verify-journal.json"
ARGOSFS_KEY_FILE="$key_file" "$argosfs" health "$volume" --json >"$artifacts/logs/health.json"

stdin_volume="$artifacts/stdin-volume"
"$argosfs" mkfs "$stdin_volume" --force --disks 1 --k 1 --m 0 --compression none >"$artifacts/logs/stdin-mkfs.json"
printf 'stdin-feature-key\n' | "$argosfs" enable-encryption "$stdin_volume" --passphrase-stdin >"$artifacts/logs/stdin-encryption.json"
"$argosfs" encryption-status "$stdin_volume" >"$artifacts/logs/stdin-encryption-status.json"
"$argosfs" refresh-smart "$volume" "$extra_id" >"$artifacts/logs/refresh-smart.json" 2>"$artifacts/logs/refresh-smart.err" || true
if "$argosfs" refresh-smart "$volume" missing-disk >"$artifacts/logs/refresh-smart-missing.json" 2>"$artifacts/logs/refresh-smart-missing.err"; then
  echo "refresh-smart unexpectedly succeeded for an unknown disk" >&2
  exit 1
fi

python3 - <<'PY' "$volume" "$artifacts/logs/encryption-status.json"
from pathlib import Path
import json
import sys
volume = Path(sys.argv[1])
status = json.loads(Path(sys.argv[2]).read_text())
if not status.get("enabled"):
    raise SystemExit("encryption did not become enabled")
if int(status.get("encrypted_blocks", 0)) < 1:
    raise SystemExit("no encrypted data blocks were reported")
meta = json.loads((volume / ".argosfs" / "meta.json").read_text())
blocks = [block for inode in meta.get("inodes", {}).values() for block in inode.get("blocks", [])]
if not any(block.get("encrypted") for block in blocks):
    raise SystemExit("metadata has no encrypted block")
if not any(block.get("codec") not in (None, "none", "None") and block.get("compressed_size", 0) < block.get("raw_size", 0) for block in blocks):
    raise SystemExit("metadata has no compressed block smaller than raw size")
print("feature metadata checks passed")
PY

echo "ArgosFS CLI feature test passed; artifacts=$artifacts"
