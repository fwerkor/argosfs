#!/usr/bin/env bash
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ARGOSFS_TEST_ARTIFACTS="$repo/target/argosfs-test-artifacts/rootfs-smoke" \
	"$repo/scripts/test_initramfs_dry_run.sh"
