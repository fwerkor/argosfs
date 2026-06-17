#!/bin/sh
set -eu

log_file="${ARGOSFS_INITRD_LOG:-/run/argosfs-initrd.log}"
run_dir="${ARGOSFS_INITRD_RUN_DIR:-/run}"
dev_root="${ARGOSFS_INITRD_DEV_ROOT:-/dev}"
sys_class_block="${ARGOSFS_INITRD_SYS_CLASS_BLOCK:-/sys/class/block}"
config_file="${ARGOSFS_INITRD_CONFIG:-/etc/argosfs/initramfs.conf}"
if [ -r "$config_file" ]; then
	# shellcheck disable=SC1090
	. "$config_file"
fi
sysroot="${ARGOSFS_DEFAULT_ROOT:-/sysroot}"
mode="${ARGOSFS_DEFAULT_MODE:-rw}"
pool=""
devices=""
images=""
debug="0"
replay="auto"
fsck_mode="auto"
dry_run="0"
auto_scan="${ARGOSFS_AUTOSCAN:-0}"
argosfs_bin="${ARGOSFS_BIN:-argosfs}"

log() {
	msg="argosfs-initrd: $*"
	printf '%s\n' "$msg" >>"$log_file" 2>/dev/null || true
	[ -w /dev/console ] && printf '%s\n' "$msg" >/dev/console 2>/dev/null || true
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
			argosfs.autoscan=*) auto_scan="${arg#argosfs.autoscan=}" ;;
		esac
	done
}

parse_args() {
	while [ "$#" -gt 0 ]; do
		case "$1" in
			--dry-run) dry_run="1"; shift ;;
			--images|--devices|--pool|--sysroot|--root|--mode|--argosfs-bin)
				[ "$#" -ge 2 ] || emergency "$1 requires a value"
				case "$1" in
					--images) images="$2" ;;
					--devices) devices="$2" ;;
					--pool) pool="$2" ;;
					--sysroot|--root) sysroot="$2" ;;
					--mode) mode="$2" ;;
					--argosfs-bin) argosfs_bin="$2" ;;
				esac
				shift 2
				;;
			--debug) debug="1"; shift ;;
			--autoscan) auto_scan="1"; shift ;;
			--no-autoscan) auto_scan="0"; shift ;;
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

resolve_by_partuuid() {
	want="$1"
	for uevent in "$sys_class_block"/*/uevent; do
		[ -r "$uevent" ] || continue
		devname=""
		partuuid=""
		while IFS='=' read -r key value; do
			case "$key" in
				DEVNAME) devname="$value" ;;
				PARTUUID) partuuid="$value" ;;
			esac
		done <"$uevent"
		[ "$partuuid" = "$want" ] || continue
		[ -n "$devname" ] || continue
		candidate="$dev_root/$devname"
		[ -e "$candidate" ] || continue
		printf '%s\n' "$candidate"
		return 0
	done
	return 1
}

part_number_from_partuuid() {
	partuuid="$1"
	case "$partuuid" in
		*-[0-9][0-9])
			partn="${partuuid##*-}"
			partn="${partn#0}"
			[ -n "$partn" ] || partn="0"
			printf '%s\n' "$partn"
			return 0
			;;
	esac
	return 1
}

resolve_by_part_number() {
	want="$1"
	match=""
	matches=0
	for uevent in "$sys_class_block"/*/uevent; do
		[ -r "$uevent" ] || continue
		devname=""
		devtype=""
		partn=""
		while IFS='=' read -r key value; do
			case "$key" in
				DEVNAME) devname="$value" ;;
				DEVTYPE) devtype="$value" ;;
				PARTN) partn="$value" ;;
			esac
		done <"$uevent"
		[ "$devtype" = "partition" ] || continue
		[ "$partn" = "$want" ] || continue
		[ -n "$devname" ] || continue
		candidate="$dev_root/$devname"
		[ -e "$candidate" ] || continue
		match="$candidate"
		matches=$((matches + 1))
	done
	[ "$matches" -eq 1 ] || return 1
	printf '%s\n' "$match"
}

resolve_device_path() {
	path="$1"
	[ -e "$path" ] && {
		printf '%s\n' "$path"
		return 0
	}
	case "$path" in
		/dev/disk/by-partuuid/*)
			partuuid="${path##*/}"
			if resolved="$(resolve_by_partuuid "$partuuid")"; then
				log "resolved $path to $resolved"
				printf '%s\n' "$resolved"
				return 0
			fi
			if partn="$(part_number_from_partuuid "$partuuid")" &&
				resolved="$(resolve_by_part_number "$partn")"; then
				log "resolved $path by partition number $partn to $resolved"
				printf '%s\n' "$resolved"
				return 0
			fi
			;;
	esac
	printf '%s\n' "$path"
}

resolve_device_list() {
	list="$1"
	resolved_list=""
	old_ifs="$IFS"
	IFS=,
	set -- $list
	IFS="$old_ifs"
	for path in "$@"; do
		[ -n "$path" ] || continue
		resolved_path="$(resolve_device_path "$path")"
		resolved_list="${resolved_list:+$resolved_list,}$resolved_path"
	done
	printf '%s\n' "$resolved_list"
}

append_csv_unique() {
	list="$1"
	value="$2"
	old_ifs="$IFS"
	IFS=,
	for item in $list; do
		IFS="$old_ifs"
		[ "$item" = "$value" ] && {
			printf '%s\n' "$list"
			return 0
		}
		IFS=,
	done
	IFS="$old_ifs"
	printf '%s\n' "${list:+$list,}$value"
}

candidate_is_ignored() {
	case "$1" in
		loop*|ram*|zram*|fd*|sr*) return 0 ;;
	esac
	return 1
}

list_block_candidates_by_type() {
	want_type="$1"
	for uevent in "$sys_class_block"/*/uevent; do
		[ -r "$uevent" ] || continue
		devname=""
		devtype=""
		while IFS='=' read -r key value; do
			case "$key" in
				DEVNAME) devname="$value" ;;
				DEVTYPE) devtype="$value" ;;
			esac
		done <"$uevent"
		[ "$devtype" = "$want_type" ] || continue
		[ -n "$devname" ] || continue
		candidate_is_ignored "$devname" && continue
		candidate="$dev_root/$devname"
		[ -e "$candidate" ] || continue
		printf '%s\n' "$candidate"
	done
}

scan_argosfs_candidate() {
	backend="$1"
	path="$2"
	out="$run_dir/argosfs-autoscan-$(basename "$path").json"
	case "$backend" in
		loop) "$argosfs_bin" scan --backend loop --images "$path" --json >"$out" 2>/dev/null ;;
		raw) "$argosfs_bin" scan --backend raw --devices "$path" --json >"$out" 2>/dev/null ;;
		*) return 1 ;;
	esac
	grep -q '"valid"[[:space:]]*:[[:space:]]*true' "$out"
}

discover_argosfs_backend() {
	backend="$1"
	discovered=""
	for devtype in partition disk; do
		while IFS= read -r candidate; do
			[ -n "$candidate" ] || continue
			if scan_argosfs_candidate "$backend" "$candidate"; then
				discovered="$(append_csv_unique "$discovered" "$candidate")"
			fi
		done <<EOF_CANDIDATES
$(list_block_candidates_by_type "$devtype")
EOF_CANDIDATES
		[ -n "$discovered" ] && break
	done
	printf '%s\n' "$discovered"
}

discover_argosfs_devices() {
	[ -z "$images" ] || return 0
	[ -z "$devices" ] || return 0
	[ "$auto_scan" = "1" ] || return 0
	images="$(discover_argosfs_backend loop)"
	if [ -n "$images" ]; then
		log "autoscan selected loop images $images"
		return 0
	fi
	devices="$(discover_argosfs_backend raw)"
	if [ -n "$devices" ]; then
		log "autoscan selected raw devices $devices"
		return 0
	fi
}

pool_args() {
	if [ -n "$pool" ]; then
		printf '%s\n' "--pool $pool"
	fi
}

resolve_argosfs_binary() {
	case "$argosfs_bin" in
		*/*)
			[ -x "$argosfs_bin" ] || emergency "argosfs binary is missing or not executable: $argosfs_bin"
			return 0
			;;
	esac
	resolved="$(command -v "$argosfs_bin" 2>/dev/null || true)"
	[ -n "$resolved" ] || emergency "argosfs binary not found in PATH: $argosfs_bin"
	argosfs_bin="$resolved"
}

is_mounted() {
	mount_target="$1"
	[ -r /proc/mounts ] || return 1
	while read -r _ mount_path _; do
		[ "$mount_path" = "$mount_target" ] && return 0
	done </proc/mounts
	return 1
}

mount_if_needed() {
	mount_target="$1"
	mount_fs_type="$2"
	mount_source="$3"
	is_mounted "$mount_target" ||
		mount -t "$mount_fs_type" "$mount_source" "$mount_target" ||
		is_mounted "$mount_target"
}

move_mount_or_mount() {
	move_source="$1"
	move_target="$2"
	move_fs_type="$3"
	move_fs_source="$4"
	tries=0
	mkdir -p "$move_target" 2>/dev/null || true
	while [ "$tries" -lt 10 ]; do
		is_mounted "$move_target" && return 0
		if is_mounted "$move_source"; then
			mount -o move "$move_source" "$move_target" 2>/dev/null ||
				mount --move "$move_source" "$move_target" 2>/dev/null ||
				true
			is_mounted "$move_target" && return 0
		else
			mount_if_needed "$move_target" "$move_fs_type" "$move_fs_source" && return 0
		fi
		tries=$((tries + 1))
		sleep 1
	done
	return 1
}

write_marker() {
	marker="$1"
	( : >"$marker" ) 2>/dev/null
}

dir_is_writable() {
	dir="$1"
	marker="$dir/.argosfs-write-test.$$"
	write_marker "$marker" || return 1
	rm -f "$marker" 2>/dev/null || true
}

create_dev_node() {
	node="$1"
	node_type="$2"
	major="$3"
	minor="$4"
	mode="$5"
	[ -e "$node" ] || mknod "$node" "$node_type" "$major" "$minor" 2>/dev/null || true
	chmod "$mode" "$node" 2>/dev/null || true
}

populate_block_device_nodes() {
	root="$1"
	for uevent in "$sys_class_block"/*/uevent; do
		[ -r "$uevent" ] || continue
		devname=""
		major=""
		minor=""
		while IFS='=' read -r key value; do
			case "$key" in
				DEVNAME) devname="$value" ;;
				MAJOR) major="$value" ;;
				MINOR) minor="$value" ;;
			esac
		done <"$uevent"
		[ -n "$devname" ] || continue
		[ -n "$major" ] || continue
		[ -n "$minor" ] || continue
		node="$root/$devname"
		[ -b "$node" ] && continue
		mkdir -p "$(dirname "$node")"
		rm -f "$node" 2>/dev/null || true
		mknod "$node" b "$major" "$minor" 2>/dev/null || true
		chmod 0600 "$node" 2>/dev/null || true
	done
}

populate_minimal_dev_nodes() {
	root="$1"
	mkdir -p "$root"
	create_dev_node "$root/console" c 5 1 0600
	create_dev_node "$root/tty" c 5 0 0666
	create_dev_node "$root/ttyS0" c 4 64 0660
	create_dev_node "$root/null" c 1 3 0666
	create_dev_node "$root/zero" c 1 5 0666
	create_dev_node "$root/random" c 1 8 0666
	create_dev_node "$root/urandom" c 1 9 0666
	create_dev_node "$root/fuse" c 10 229 0666
	populate_block_device_nodes "$root"
}

prepare_new_root_dev() {
	if is_mounted /dev; then
		move_mount_or_mount /dev "$sysroot/dev" devtmpfs devtmpfs || return 1
		return 0
	fi
	mkdir -p "$sysroot/dev"
	is_mounted "$sysroot/dev" ||
		mount -t devtmpfs devtmpfs "$sysroot/dev" 2>/dev/null ||
		mount -t tmpfs tmpfs "$sysroot/dev" 2>/dev/null ||
		true
	populate_minimal_dev_nodes "$sysroot/dev"
	[ -d "$sysroot/dev" ]
}

prepare_new_root_runtime_dirs() {
	mkdir -p "$sysroot/tmp" "$sysroot/run"
	chmod 1777 "$sysroot/tmp" 2>/dev/null || true

	mkdir -p "$sysroot/tmp/lock" "$sysroot/tmp/log" "$sysroot/tmp/run" \
		"$sysroot/tmp/state" "$sysroot/tmp/ubus" "$sysroot/var/run/ubus"
	chmod 0755 "$sysroot/tmp/run" "$sysroot/var/run" 2>/dev/null || true
	chmod 0755 "$sysroot/var/run/ubus" 2>/dev/null || true
	chown 81:81 "$sysroot/var/run/ubus" 2>/dev/null || true
}

mark_argosfs_root_active() {
	write_marker /run/argosfs-root-active || true
	write_marker "$sysroot/run/argosfs-root-active" ||
		emergency "failed to mark ArgosFS root active under /run"
}

prepare_new_root_run() {
	run_target="$sysroot/run"
	mkdir -p "$run_target" 2>/dev/null || true
	if is_mounted /run; then
		mount -o move /run "$run_target" 2>/dev/null ||
			mount --move /run "$run_target" 2>/dev/null ||
			true
	fi
	if ! dir_is_writable "$run_target"; then
		umount "$run_target" 2>/dev/null || umount -l "$run_target" 2>/dev/null || true
		mount -t tmpfs tmpfs "$run_target" 2>/dev/null || true
	fi
	dir_is_writable "$run_target"
}

require_new_root_mountpoint() {
	name="$1"
	[ -d "$sysroot/$name" ] || emergency "mounted ArgosFS root is missing /$name for switch_root"
}

prepare_switch_root_mounts() {
	if [ "$mount_mode" = "ro" ]; then
		require_new_root_mountpoint proc
		require_new_root_mountpoint sys
		require_new_root_mountpoint dev
		require_new_root_mountpoint run
	else
		mkdir -p "$sysroot/proc" "$sysroot/sys" "$sysroot/dev" "$sysroot/run"
		prepare_new_root_runtime_dirs
	fi
	prepare_new_root_dev || emergency "failed to prepare /dev"
	prepare_new_root_run || emergency "failed to hand off writable /run"
	mark_argosfs_root_active
	move_mount_or_mount /sys "$sysroot/sys" sysfs sysfs || emergency "failed to hand off /sys"
	move_mount_or_mount /proc "$sysroot/proc" proc proc || emergency "failed to hand off /proc"
}

ensure_block_device_nodes() {
	for uevent in "$sys_class_block"/*/uevent; do
		[ -r "$uevent" ] || continue
		devname=""
		major=""
		minor=""
		while IFS='=' read -r key value; do
			case "$key" in
				DEVNAME) devname="$value" ;;
				MAJOR) major="$value" ;;
				MINOR) minor="$value" ;;
			esac
		done <"$uevent"
		[ -n "$devname" ] || continue
		[ -n "$major" ] || continue
		[ -n "$minor" ] || continue
		node="$dev_root/$devname"
		[ -b "$node" ] && continue
		mkdir -p "$(dirname "$node")"
		rm -f "$node" 2>/dev/null || true
		mknod "$node" b "$major" "$minor" 2>/dev/null || true
		chmod 0600 "$node" 2>/dev/null || true
	done
}

ensure_fuse_device() {
	fuse_dev="$dev_root/fuse"
	[ -c "$fuse_dev" ] && return 0
	rm -f "$fuse_dev" 2>/dev/null || true
	if command -v mknod >/dev/null 2>&1; then
		mknod "$fuse_dev" c 10 229 2>/dev/null || true
		chmod 0666 "$fuse_dev" 2>/dev/null || true
	fi
	[ -c "$fuse_dev" ] || emergency "missing fuse device node at $fuse_dev"
	log "fuse device ready at $fuse_dev"
}

main() {
	parse_cmdline
	parse_args "$@"
	[ "$debug" = "1" ] && set -x
	resolve_argosfs_binary
	if [ "$dry_run" = "1" ] && [ -z "${ARGOSFS_INITRD_RUN_DIR:-}" ]; then
		run_dir="$sysroot/run"
	fi
	: "${ARGOSFS_L2_CACHE_BYTES:=0}"
	export ARGOSFS_L2_CACHE_BYTES
	mkdir -p "$(dirname "$log_file")" "$run_dir" "$sysroot" /proc /sys /dev /run
	if [ "$dry_run" != "1" ]; then
		mount_if_needed /proc proc proc || emergency "failed to mount /proc"
		mount_if_needed /sys sysfs sysfs || emergency "failed to mount /sys"
		mount_if_needed /dev devtmpfs devtmpfs || true
		mount_if_needed /run tmpfs tmpfs || true
		modprobe fuse 2>/dev/null || true
		ensure_block_device_nodes
		ensure_fuse_device
	fi

	[ -z "$images" ] || images="$(resolve_device_list "$images")"
	[ -z "$devices" ] || devices="$(resolve_device_list "$devices")"
	discover_argosfs_devices
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
	mount_log="$run_dir/argosfs-mount.log"
	rm -f "$mount_log"
	if command -v setsid >/dev/null 2>&1; then
		# shellcheck disable=SC2086
		setsid "$argosfs_bin" mount-root $args $pool_filter --target "$sysroot" --mode "$mount_mode" --foreground -o allow_other >"$mount_log" 2>&1 &
	else
		# shellcheck disable=SC2086
		"$argosfs_bin" mount-root $args $pool_filter --target "$sysroot" --mode "$mount_mode" --foreground -o allow_other >"$mount_log" 2>&1 &
	fi
	mount_pid="$!"
	tries=0
	while [ "$tries" -lt 30 ]; do
		[ -x "$sysroot/sbin/init" ] || [ -x "$sysroot/init" ] || [ -x "$sysroot/lib/systemd/systemd" ] && break
		if ! kill -0 "$mount_pid" 2>/dev/null; then
			mount_status=0
			wait "$mount_pid" || mount_status="$?"
			log "mount-root exited before init appeared status=$mount_status"
			if [ -s "$mount_log" ]; then
				while IFS= read -r line; do
					log "mount-root: $line"
				done <"$mount_log"
			fi
			umount "$sysroot" 2>/dev/null || umount -l "$sysroot" 2>/dev/null || true
			emergency "argosfs mount-root failed"
		fi
		tries=$((tries + 1))
		sleep 1
	done
	if ! [ -x "$sysroot/sbin/init" ] && ! [ -x "$sysroot/init" ] && ! [ -x "$sysroot/lib/systemd/systemd" ]; then
		log "mount-root did not expose init before timeout"
		kill "$mount_pid" 2>/dev/null || true
		wait "$mount_pid" 2>/dev/null || true
		umount "$sysroot" 2>/dev/null || umount -l "$sysroot" 2>/dev/null || true
		if [ -s "$mount_log" ]; then
			while IFS= read -r line; do
				log "mount-root: $line"
			done <"$mount_log"
		fi
		emergency "no init found in $sysroot"
	fi
	log "mounted ArgosFS root at $sysroot pid=$mount_pid"
	if [ "$mount_mode" = "ro" ]; then
		require_new_root_mountpoint run
	elif ! mkdir -p "$sysroot/run"; then
		if [ -s "$mount_log" ]; then
			while IFS= read -r line; do
				log "mount-root: $line"
			done <"$mount_log"
		fi
		kill "$mount_pid" 2>/dev/null || true
		wait "$mount_pid" 2>/dev/null || true
		umount "$sysroot" 2>/dev/null || umount -l "$sysroot" 2>/dev/null || true
		emergency "mounted ArgosFS root is not writable enough for switch_root"
	fi
	prepare_switch_root_mounts
	unset INITRAMFS
	exec switch_root "$sysroot" /sbin/init
}

main "$@"
