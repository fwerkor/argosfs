#!/usr/bin/env bash
set -euo pipefail

if ! command -v qemu-system-x86_64 >/dev/null 2>&1; then
	echo "SKIP: qemu-system-x86_64 not found" >&2
	exit 0
fi

echo "SKIP: QEMU boot requires a CapOS kernel/initramfs artifact; run after CapOS image build with ARGOSFS_QEMU_KERNEL and ARGOSFS_QEMU_INITRD set" >&2
exit 0
