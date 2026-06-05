#!/bin/sh
set -eu

exec "$(dirname "$0")/../capos/initramfs/argosfs-root.sh" "$@"
