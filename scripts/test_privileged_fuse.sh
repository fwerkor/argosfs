#!/usr/bin/env bash
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [ ! -e /dev/fuse ]; then
	echo "SKIP: /dev/fuse is not available; privileged FUSE smoke test was not run" >&2
	exit 0
fi

"$repo/scripts/compat/run_mounted_fuse_compat.sh"
