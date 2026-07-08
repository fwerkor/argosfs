#!/usr/bin/env bash
set -euo pipefail

if [ "$(id -u)" -ne 0 ] || [ -z "${ARGOSFS_RAW_TEST_DEVICES:-}" ]; then
	echo "SKIP: set ARGOSFS_RAW_TEST_DEVICES=/dev/...,/dev/... and run as root to test destructive raw backend" >&2
	exit 0
fi

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cargo build --manifest-path "$repo/Cargo.toml" --bin argosfs
"$repo/target/debug/argosfs" mkfs --backend raw --devices "$ARGOSFS_RAW_TEST_DEVICES" --k 1 --m 1 --pool-name capos-root "$@"
"$repo/target/debug/argosfs" scan --backend raw --devices "$ARGOSFS_RAW_TEST_DEVICES" --json
