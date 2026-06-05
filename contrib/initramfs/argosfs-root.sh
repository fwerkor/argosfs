#!/usr/bin/env bash
set -euo pipefail

exec "$(dirname "$0")/../capos/initramfs/argosfs-root.sh" "$@"
