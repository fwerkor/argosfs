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
			local output
			output="$outdir/$(basename "${input%.gz}")"
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

argosfs_qemu_find_arm64_uefi() {
	local candidate
	for candidate in \
		/usr/share/qemu-efi-aarch64/QEMU_EFI.fd \
		/usr/share/edk2/aarch64/QEMU_EFI.fd \
		/usr/share/AAVMF/AAVMF_CODE.fd; do
		if [ -r "$candidate" ]; then
			echo "$candidate"
			return 0
		fi
	done
	return 1
}


argosfs_qemu_adjust_login_delay() {
	local delay="$1"
	if [ "${arch:-}" = "arm64" ] && [ "${delay:-0}" -lt "${ARGOSFS_QEMU_ARM64_MIN_LOGIN_DELAY:-220}" ]; then
		echo "${ARGOSFS_QEMU_ARM64_MIN_LOGIN_DELAY:-220}"
	else
		echo "$delay"
	fi
}

argosfs_qemu_kill_tree() {
	local pid="$1"
	[ -n "$pid" ] || return 0
	local child
	for child in $(pgrep -P "$pid" 2>/dev/null || true); do
		argosfs_qemu_kill_tree "$child"
	done
	kill -9 "$pid" 2>/dev/null || true
}

argosfs_qemu_wait_process_gone() {
	local pid="$1"
	local tries="${2:-30}"
	local i=0
	while [ "$i" -lt "$tries" ]; do
		if ! kill -0 "$pid" 2>/dev/null; then
			return 0
		fi
		sleep 1
		i=$((i + 1))
	done
	return 1
}

argosfs_qemu_add_hotplug_ports() {
	local count="$1"
	local prefix="$2"
	local index=0
	local slot

	[ "${arch:-}" = "arm64" ] || return 0
	while [ "$index" -lt "$count" ]; do
		slot=$((index + 2))
		qemu_args+=(
			-device "pcie-root-port,id=${prefix}port${index},chassis=${slot},slot=${slot}"
		)
		index=$((index + 1))
	done
}

argosfs_qemu_hotplug_bus_arg() {
	local prefix="$1"
	local index="$2"
	if [ "${arch:-}" = "arm64" ]; then
		printf ',bus=%sport%s' "$prefix" "$index"
	fi
}

argosfs_qemu_wait_log_marker() {
	local log="$1"
	local marker="$2"
	local timeout_s="${3:-120}"
	local deadline=$((SECONDS + timeout_s))

	while [ "$SECONDS" -lt "$deadline" ]; do
		if [ -f "$log" ] && awk -v marker="$marker" \
			'{ sub(/\r$/, ""); if ($0 == marker) found = 1 } END { exit !found }' "$log"; then
			return 0
		fi
		sleep 1
	done
	echo "timed out waiting for QEMU guest marker: $marker" >&2
	return 1
}

argosfs_qemu_stream_script() {
	local script="$1"
	local fd="${2:-1}"
	local remote="${3:-/tmp/argosfs-qemu-script.sh}"
	local log="${4:-}"
	local line_delay="${ARGOSFS_QEMU_SCRIPT_LINE_DELAY:-0.01}"
	local delimiter="ARGOSFS_QEMU_SCRIPT_EOF"
	local marker_id
	local shell_marker
	local upload_marker
	local deadline
	local line

	if grep -Fxq "$delimiter" "$script"; then
		echo "QEMU guest script contains reserved delimiter: $delimiter" >&2
		return 2
	fi
	marker_id="$(printf '%s' "$remote" | cksum | awk '{print $1}')"
	shell_marker="ARGOSFS_QEMU_SHELL_READY_$marker_id"
	upload_marker="ARGOSFS_QEMU_UPLOAD_READY_$marker_id"

	printf '\r' >&"$fd"
	if [ -n "$log" ]; then
		deadline=$((SECONDS + ${ARGOSFS_QEMU_SHELL_READY_TIMEOUT:-60}))
		while [ "$SECONDS" -lt "$deadline" ]; do
			if awk -v marker="$shell_marker" \
				'{ sub(/\r$/, ""); if ($0 == marker) found = 1 } END { exit !found }' "$log" 2>/dev/null; then
				break
			fi
			printf 'echo %s\r' "$shell_marker" >&"$fd"
			sleep 1
		done
		if ! awk -v marker="$shell_marker" \
			'{ sub(/\r$/, ""); if ($0 == marker) found = 1 } END { exit !found }' "$log" 2>/dev/null; then
			echo "timed out waiting for QEMU guest shell: $shell_marker" >&2
			return 1
		fi
	else
		sleep "${ARGOSFS_QEMU_SCRIPT_START_DELAY:-1}"
	fi

	printf 'stty -echo; echo %s\r' "$upload_marker" >&"$fd"
	if [ -n "$log" ]; then
		argosfs_qemu_wait_log_marker "$log" "$upload_marker" "${ARGOSFS_QEMU_SCRIPT_READY_TIMEOUT:-30}" || return $?
	else
		sleep "${ARGOSFS_QEMU_SCRIPT_STTY_DELAY:-0.2}"
	fi
	printf "cat >'%s' <<'%s'\r" "$remote" "$delimiter" >&"$fd"
	while IFS= read -r line || [ -n "$line" ]; do
		printf '%s\r' "$line" >&"$fd"
		sleep "$line_delay"
	done <"$script"
	printf '%s\r' "$delimiter" >&"$fd"
	printf "stty echo; sh '%s'\r" "$remote" >&"$fd"
}
argosfs_qemu_wait_console_prompt() {
	local log="$1"
	local min_count="${2:-1}"
	local timeout_s="${3:-120}"
	local reject="${4:-}"
	local label="${5:-QEMU console prompt}"
	local deadline=$((SECONDS + timeout_s))
	local count

	while [ "$SECONDS" -lt "$deadline" ]; do
		if [ -n "$reject" ] && grep -Eiq "$reject" "$log" 2>/dev/null; then
			echo "QEMU rejected while waiting for $label: $reject" >&2
			return 2
		fi
		count="$(grep -Fc 'Please press Enter to activate this console.' "$log" 2>/dev/null || true)"
		if [ "$count" -ge "$min_count" ]; then
			return 0
		fi
		sleep 1
	done
	echo "timed out waiting for $label in $log" >&2
	return 1
}

argosfs_qemu_monitor_command() {
	local monitor="$1"
	local command="$2"
	local monitor_log="$3"
	local attempt=1
	local response
	local status
	local allowed_error="${4:-}"

	while [ "$attempt" -le 3 ]; do
		if [ ! -S "$monitor" ]; then
			sleep 1
			attempt=$((attempt + 1))
			continue
		fi

		if response="$(printf '%s\n' "$command" | timeout 10 socat - "UNIX-CONNECT:$monitor" 2>&1)"; then
			status=0
		else
			status=$?
		fi
		{
			printf '>>> %s\n' "$command"
			printf '%s\n' "$response" | tail -c 8192
			printf '\n'
		} >>"$monitor_log"

		if [ "$status" -eq 0 ]; then
			if [ -n "$allowed_error" ] && printf '%s\n' "$response" | grep -Eiq "$allowed_error"; then
				return 0
			fi
			if ! printf '%s\n' "$response" | grep -Eiq \
				'Error:|unknown command|invalid parameter|not found|not supported|does not support hotplugging|already in use'; then
				return 0
			fi
		fi
		sleep 1
		attempt=$((attempt + 1))
	done

	echo "QEMU monitor command failed: $command" >&2
	tail -n 80 "$monitor_log" >&2 || true
	return 1
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
	)
	if [ "${ARGOSFS_QEMU_NET:-none}" = "none" ]; then
		qemu_args+=(-nic none)
	fi
	if [ "${ARGOSFS_QEMU_NO_REBOOT:-1}" = "1" ]; then
		qemu_args+=(-no-reboot)
	fi
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
	elif [ "$arch" = "arm64" ] && [ -z "$kernel" ] && [ -n "$disk_image" ]; then
		firmware_code="$(argosfs_qemu_find_arm64_uefi || true)"
		if [ -z "$firmware_code" ]; then
			echo "missing AArch64 UEFI firmware for disk-image boot" >&2
			exit 1
		fi
		qemu_args+=(-bios "$firmware_code")
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
			drive_if="${ARGOSFS_QEMU_DRIVE_IF:-$default_drive_if}"
			if [ "$arch" = "arm64" ] && [ "$drive_if" = "virtio" ]; then
				qemu_args+=(-drive "file=$rootfs,format=raw,if=none,id=rootdisk")
				qemu_args+=(-device "virtio-blk-pci,drive=rootdisk,romfile=")
			else
				qemu_args+=(-drive "file=$rootfs,format=raw,if=$drive_if,id=rootdisk")
			fi
		fi
	elif [ -n "$disk_image" ]; then
		if [ ! -e "$disk_image" ]; then
			echo "ARGOSFS_QEMU_DISK_IMAGE does not exist: $disk_image" >&2
			exit 1
		fi
		drive_if="${ARGOSFS_QEMU_DRIVE_IF:-$default_drive_if}"
		if [ "$arch" = "arm64" ] && [ "$drive_if" = "virtio" ]; then
			qemu_args+=(-drive "file=$disk_image,format=raw,if=none,id=rootdisk")
			qemu_args+=(-device "virtio-blk-pci,drive=rootdisk,romfile=")
		else
			qemu_args+=(-drive "file=$disk_image,format=raw,if=$drive_if,id=rootdisk")
		fi
	else
		echo "SKIP: QEMU requires ARGOSFS_QEMU_KERNEL or ARGOSFS_QEMU_DISK_IMAGE" >&2
		exit 0
	fi
}
