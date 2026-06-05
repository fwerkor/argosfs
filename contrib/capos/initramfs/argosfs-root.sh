#!/usr/bin/env bash
set -euo pipefail

log_file="${ARGOSFS_INITRD_LOG:-/run/argosfs-initrd.log}"
run_dir="${ARGOSFS_INITRD_RUN_DIR:-/run}"
sysroot="/sysroot"
mode="rw"
pool=""
devices=""
images=""
debug="0"
replay="auto"
fsck_mode="auto"
dry_run="0"
argosfs_bin="${ARGOSFS_BIN:-argosfs}"

log() {
	printf '%s\n' "argosfs-initrd: $*" | tee -a "$log_file" >/dev/null 2>&1 || true
}

emergency() {
	log "emergency: $*"
	if [ "$dry_run" = "1" ]; then
		return 1
	fi
	exec sh
}

parse_cmdline() {
	[ -r /proc/cmdline ] || return 0
	for arg in $(cat /proc/cmdline); do
		case "$arg" in
			argosfs.pool=*) pool="${arg#argosfs.pool=}" ;;
			argosfs.devices=*) devices="${arg#argosfs.devices=}" ;;
			argosfs.images=*) images="${arg#argosfs.images=}" ;;
			argosfs.mode=*) mode="${arg#argosfs.mode=}" ;;
			argosfs.root=*) sysroot="${arg#argosfs.root=}" ;;
			argosfs.debug=*) debug="${arg#argosfs.debug=}" ;;
			argosfs.replay=*) replay="${arg#argosfs.replay=}" ;;
			argosfs.fsck=*) fsck_mode="${arg#argosfs.fsck=}" ;;
		esac
	done
}

parse_args() {
	while [ "$#" -gt 0 ]; do
		case "$1" in
			--dry-run) dry_run="1"; shift ;;
			--images) images="$2"; shift 2 ;;
			--devices) devices="$2"; shift 2 ;;
			--pool) pool="$2"; shift 2 ;;
			--sysroot|--root) sysroot="$2"; shift 2 ;;
			--mode) mode="$2"; shift 2 ;;
			--argosfs-bin) argosfs_bin="$2"; shift 2 ;;
			--debug) debug="1"; shift ;;
			*) emergency "unknown argument $1" ;;
		esac
	done
}

backend_args() {
	if [ -n "$images" ]; then
		printf '%s\n' "--backend loop --images $images"
	elif [ -n "$devices" ]; then
		printf '%s\n' "--backend raw --devices $devices"
	else
		emergency "argosfs.devices or argosfs.images is required"
	fi
}

pool_args() {
	if [ -n "$pool" ]; then
		printf '%s\n' "--pool $pool"
	fi
}

main() {
	parse_cmdline
	parse_args "$@"
	[ "$debug" = "1" ] && set -x
	if [ "$dry_run" = "1" ] && [ -z "${ARGOSFS_INITRD_RUN_DIR:-}" ]; then
		run_dir="$sysroot/run"
	fi
	mkdir -p "$(dirname "$log_file")" "$run_dir" "$sysroot" /proc /sys /dev /run
	if [ "$dry_run" != "1" ]; then
		mountpoint -q /proc || mount -t proc proc /proc
		mountpoint -q /sys || mount -t sysfs sysfs /sys
		mountpoint -q /dev || mount -t devtmpfs devtmpfs /dev || true
		mountpoint -q /run || mount -t tmpfs tmpfs /run || true
		modprobe fuse 2>/dev/null || true
	fi

	args="$(backend_args)"
	pool_filter="$(pool_args)"
	log "scan $args pool=${pool:-auto} mode=$mode replay=$replay fsck=$fsck_mode"
	# shellcheck disable=SC2086
	"$argosfs_bin" scan $args --json >"$run_dir/argosfs-scan.json"
	if [ "$replay" != "none" ]; then
		# shellcheck disable=SC2086
		"$argosfs_bin" replay-journal $args $pool_filter >"$run_dir/argosfs-replay.json" || {
			[ "$mode" = "recovery" ] || emergency "journal replay failed"
		}
	fi
	if [ "$fsck_mode" != "skip" ]; then
		fsck_flags=""
		[ "$fsck_mode" = "force" ] && fsck_flags="--repair"
		# shellcheck disable=SC2086
		"$argosfs_bin" fsck $args $pool_filter $fsck_flags >"$run_dir/argosfs-fsck.json" || emergency "fsck failed"
	fi
	# shellcheck disable=SC2086
	"$argosfs_bin" preflight-root $args $pool_filter --mode "$mode" >"$run_dir/argosfs-preflight.json"
	if [ "$dry_run" = "1" ]; then
		log "dry-run complete"
		return 0
	fi
	mount_mode="$mode"
	[ "$mount_mode" = "recovery" ] && mount_mode="ro"
	# shellcheck disable=SC2086
	"$argosfs_bin" mount-root $args $pool_filter --target "$sysroot" --mode "$mount_mode" --foreground -o allow_other &
	for _ in $(seq 1 100); do
		[ -x "$sysroot/sbin/init" ] || [ -x "$sysroot/init" ] || [ -x "$sysroot/lib/systemd/systemd" ] && break
		sleep 0.1
	done
	[ -x "$sysroot/sbin/init" ] || [ -x "$sysroot/init" ] || [ -x "$sysroot/lib/systemd/systemd" ] || emergency "no init found in $sysroot"
	exec switch_root "$sysroot" /sbin/init
}

main "$@"
