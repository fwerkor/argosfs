#!/usr/bin/env bash

argosfs_qemu_select_arch() {
	arch="${ARGOSFS_QEMU_ARCH:-x86_64}"
	case "$arch" in
		x86_64)
			qemu_bin="${ARGOSFS_QEMU_BIN:-qemu-system-x86_64}"
			machine="${ARGOSFS_QEMU_MACHINE:-pc}"
			cpu_args=()
			default_rootdev="/dev/vda"
			default_drive_if="virtio"
			;;
		aarch64|arm64)
			arch="arm64"
			qemu_bin="${ARGOSFS_QEMU_BIN:-qemu-system-aarch64}"
			machine="${ARGOSFS_QEMU_MACHINE:-virt}"
			cpu_args=(-cpu "${ARGOSFS_QEMU_CPU:-cortex-a57}")
			default_rootdev="/dev/vda"
			default_drive_if="virtio"
			;;
		riscv64)
			qemu_bin="${ARGOSFS_QEMU_BIN:-qemu-system-riscv64}"
			machine="${ARGOSFS_QEMU_MACHINE:-virt}"
			cpu_args=()
			default_rootdev="/dev/vda"
			default_drive_if="virtio"
			;;
		*)
			echo "unknown ARGOSFS_QEMU_ARCH=$arch" >&2
			exit 2
			;;
	esac
}

argosfs_qemu_require_binary() {
	if ! command -v "$qemu_bin" >/dev/null 2>&1; then
		echo "SKIP: $qemu_bin not found" >&2
		exit 0
	fi
}

argosfs_qemu_decompress_if_needed() {
	local input="$1"
	local outdir="$2"
	[ -n "$input" ] || return 0
	if [ ! -e "$input" ]; then
		echo "$input"
		return 0
	fi
	case "$input" in
		*.gz)
			mkdir -p "$outdir"
			local output="$outdir/$(basename "${input%.gz}")"
			if [ ! -e "$output" ] || [ "$input" -nt "$output" ]; then
				gzip -dc "$input" >"$output"
			fi
			echo "$output"
			;;
		*)
			echo "$input"
			;;
	esac
}

argosfs_qemu_build_args() {
	kernel="${ARGOSFS_QEMU_KERNEL:-}"
	rootfs="${ARGOSFS_QEMU_ROOTFS:-}"
	initrd="${ARGOSFS_QEMU_INITRD:-}"
	disk_image="${ARGOSFS_QEMU_DISK_IMAGE:-}"
	firmware_code="${ARGOSFS_QEMU_FIRMWARE_CODE:-}"
	firmware_vars="${ARGOSFS_QEMU_FIRMWARE_VARS:-}"
	qemu_scratch="${ARGOSFS_QEMU_SCRATCH:-$artifacts/qemu-scratch}"
	mkdir -p "$qemu_scratch"
	rootfs="$(argosfs_qemu_decompress_if_needed "$rootfs" "$qemu_scratch")"
	disk_image="$(argosfs_qemu_decompress_if_needed "$disk_image" "$qemu_scratch")"

	qemu_args=(
		-machine "$machine"
		-m "${ARGOSFS_QEMU_MEM:-1024}"
		"${cpu_args[@]}"
		-nographic
		-no-reboot
	)
	if [ -n "$firmware_code" ]; then
		if [ ! -e "$firmware_code" ]; then
			echo "ARGOSFS_QEMU_FIRMWARE_CODE does not exist: $firmware_code" >&2
			exit 1
		fi
		qemu_args+=(-drive "if=pflash,format=raw,readonly=on,file=$firmware_code")
		if [ -n "$firmware_vars" ]; then
			if [ ! -e "$firmware_vars" ]; then
				echo "ARGOSFS_QEMU_FIRMWARE_VARS does not exist: $firmware_vars" >&2
				exit 1
			fi
			qemu_args+=(-drive "if=pflash,format=raw,file=$firmware_vars")
		fi
	fi
	if [ -n "$kernel" ]; then
		if [ ! -e "$kernel" ]; then
			echo "ARGOSFS_QEMU_KERNEL does not exist: $kernel" >&2
			exit 1
		fi
		qemu_args+=(-kernel "$kernel")
		append="${ARGOSFS_QEMU_APPEND:-console=ttyS0 rootwait argosfs.images=${ARGOSFS_QEMU_ROOTDEV:-$default_rootdev} argosfs.mode=${ARGOSFS_QEMU_ROOT_MODE:-rw}}"
		qemu_args+=(-append "$append")
		if [ -n "$initrd" ]; then
			if [ ! -e "$initrd" ]; then
				echo "ARGOSFS_QEMU_INITRD does not exist: $initrd" >&2
				exit 1
			fi
			qemu_args+=(-initrd "$initrd")
		fi
		if [ -n "$rootfs" ]; then
			if [ ! -e "$rootfs" ]; then
				echo "ARGOSFS_QEMU_ROOTFS does not exist: $rootfs" >&2
				exit 1
			fi
			qemu_args+=(-drive "file=$rootfs,format=raw,if=${ARGOSFS_QEMU_DRIVE_IF:-$default_drive_if},id=rootdisk")
		fi
	elif [ -n "$disk_image" ]; then
		if [ ! -e "$disk_image" ]; then
			echo "ARGOSFS_QEMU_DISK_IMAGE does not exist: $disk_image" >&2
			exit 1
		fi
		qemu_args+=(-drive "file=$disk_image,format=raw,if=${ARGOSFS_QEMU_DRIVE_IF:-$default_drive_if},id=rootdisk")
	else
		echo "SKIP: QEMU requires ARGOSFS_QEMU_KERNEL or ARGOSFS_QEMU_DISK_IMAGE" >&2
		exit 0
	fi
}
