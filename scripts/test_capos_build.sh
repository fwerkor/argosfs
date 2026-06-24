#!/usr/bin/env bash
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
artifacts="${ARGOSFS_TEST_ARTIFACTS:-$repo/target/argosfs-test-artifacts/capos-build}"
capos_repo="${CAPOS_REPO:-https://github.com/fwerkor/capos.git}"
capos_ref="${CAPOS_REF:-af93e085759c8f4a9c522d6e6a9f4f0675fb3400}"
capos_local_source="${CAPOS_LOCAL_SOURCE:-}"
capos_full_compile="${ARGOSFS_CAPOS_FULL_COMPILE:-1}"
capos_make_jobs="${ARGOSFS_CAPOS_MAKE_JOBS:-$(nproc 2>/dev/null || echo 2)}"
capos_make_target="${ARGOSFS_CAPOS_MAKE_TARGET:-package/utils/argosfs/host/compile}"
capos_tools_target="${ARGOSFS_CAPOS_TOOLS_TARGET:-}"
capos_make_v="${ARGOSFS_CAPOS_MAKE_V:-}"
capos_log_stdout="${ARGOSFS_CAPOS_LOG_STDOUT:-full}"
capos_target_matrix="${ARGOSFS_CAPOS_TARGET_MATRIX:-x86_64,armsr_armv8}"
capos_build_target="${ARGOSFS_CAPOS_BUILD_TARGET:-x86_64}"
capos_dl_dir="${ARGOSFS_CAPOS_DL_DIR:-}"
system_pkg_config_libdir="$(
	env -u PKG_CONFIG_LIBDIR -u PKG_CONFIG_PATH -u PKG_CONFIG_SYSROOT_DIR \
		PATH=/usr/local/bin:/usr/bin:/bin \
		pkg-config --variable pc_path pkg-config
)"

rm -rf "$artifacts"
mkdir -p "$artifacts"
artifacts="$(cd "$artifacts" && pwd)"
mkdir -p "$artifacts/argosfs-src" "$artifacts/capos"

filter_capos_log_for_stdout() {
	awk '
		/^[[:space:]]*$/ { next }
		/(^|[[:space:]])(ERROR|Error|FAILED|failed|warning|Warning|No space left|No such file|permission denied|Permission denied)/ { print; fflush(); next }
		/^make(\[[0-9]+\])?: / { print; fflush(); next }
		/^make\[[0-9]+\]: / { print; fflush(); next }
		/^make -r / { print; fflush(); next }
		/^make: \*\*\*/ { print; fflush(); next }
		/^[[:space:]]+ERROR: / { print; fflush(); next }
		/(Downloaded|Downloading|Compiling|Finished)[[:space:]]/ { print; fflush(); next }
		/^\[[0-9]+\/[0-9]+\][[:space:]]+(Building|Linking|Generating|Install|Installing)/ { print; fflush(); next }
		/^[[:space:]]*(CC|CXX|LD|AR|INSTALL|CP|GEN|HOSTCC|HOSTLD|MODPOST)[[:space:]\[]/ { print; fflush(); next }
	'
}

run_logged() {
	local log="$1"
	shift
	mkdir -p "$(dirname "$log")"
	echo
	echo "==> $*"
	echo "    log: $log"
	set +e
	local status
	case "$capos_log_stdout" in
		periodic)
			"$repo/scripts/ci/run-with-log.sh" \
				"$log" "CapOS $(basename "$log" .log)" -- "$@"
			status="$?"
			;;
		full)
			"$@" 2>&1 | tee "$log"
			status="${PIPESTATUS[0]}"
			;;
		filtered)
			"$@" 2>&1 | tee "$log" | filter_capos_log_for_stdout
			status="${PIPESTATUS[0]}"
			;;
		none)
			"$@" >"$log" 2>&1
			status="$?"
			;;
		*)
			echo "unknown ARGOSFS_CAPOS_LOG_STDOUT mode: $capos_log_stdout" >&2
			status=2
			;;
	esac
	set -e
	return "$status"
}

fetch_capos_ref() {
	local ref="$1"
	git fetch --depth 1 origin "$ref" && return 0
	git fetch --depth 1 origin "refs/heads/$ref" && return 0
	git fetch --depth 1 origin "refs/tags/$ref" && return 0
	return 1
}

clone_capos_repo() {
	local dest="$1"
	local ref="$2"

	echo "Checking out CapOS ref $ref from $capos_repo"
	git init --initial-branch=main "$dest"
	(
		cd "$dest"
		git remote add origin "$capos_repo"
		fetch_capos_ref "$ref"
		git checkout --detach FETCH_HEAD
		git rev-parse HEAD | tee "$artifacts/capos-commit"
	)
}

rsync -a --delete \
	--exclude /.git \
	--exclude /target \
	--exclude /paper-data/runs \
	"$repo"/ "$artifacts/argosfs-src"/
if [ -n "$capos_local_source" ]; then
	rsync -a --delete \
		--exclude /.git \
		--exclude /build_dir \
		--exclude /staging_dir \
		--exclude /tmp \
		--exclude /dl \
		"$capos_local_source"/ "$artifacts/capos"/
	git -C "$capos_local_source" rev-parse HEAD >"$artifacts/capos-commit" 2>/dev/null || echo local-source >"$artifacts/capos-commit"
else
	clone_capos_repo "$artifacts/capos" "$capos_ref"
fi
if [ -n "$capos_dl_dir" ]; then
	mkdir -p "$capos_dl_dir"
	rm -rf "$artifacts/capos/dl"
	ln -s "$capos_dl_dir" "$artifacts/capos/dl"
fi

mkdir -p "$artifacts/capos/package/utils/argosfs/files"
cat >"$artifacts/capos/package/utils/argosfs/Makefile" <<'MAKEFILE'
include $(TOPDIR)/rules.mk

PKG_NAME:=argosfs
PKG_VERSION:=0.1.0
PKG_RELEASE:=1

PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=https://github.com/fwerkor/argosfs
PKG_SOURCE_VERSION:=main
PKG_MIRROR_HASH:=skip

ifeq ($(ARGOSFS_CI_LOCAL_SOURCE),1)
PKG_SKIP_DOWNLOAD:=1
PKG_SOURCE_URL:=
endif

PKG_MAINTAINER:=FWERKOR
PKG_LICENSE:=Apache-2.0
PKG_LICENSE_FILES:=LICENSE

PKG_BUILD_DEPENDS:=rust/host fuse3 argosfs/host
PKG_BUILD_PARALLEL:=1
HOST_BUILD_PARALLEL:=1

include $(INCLUDE_DIR)/host-build.mk
include $(INCLUDE_DIR)/package.mk
include $(TOPDIR)/feeds/packages/lang/rust/rust-package.mk

HOST_FUSE3_PKG_CONFIG_LIBDIR:=$(ARGOSFS_SYSTEM_PKG_CONFIG_LIBDIR)
ifeq ($(strip $(HOST_FUSE3_PKG_CONFIG_LIBDIR)),)
HOST_FUSE3_PKG_CONFIG_LIBDIR:=$(shell env -u PKG_CONFIG_LIBDIR -u PKG_CONFIG_PATH -u PKG_CONFIG_SYSROOT_DIR PATH=/usr/local/bin:/usr/bin:/bin pkg-config --variable pc_path pkg-config 2>/dev/null)
endif

CARGO_PKG_VARS += \
	PKG_CONFIG_ALLOW_CROSS=1 \
	PKG_CONFIG_SYSROOT_DIR=$(STAGING_DIR) \
	PKG_CONFIG_LIBDIR=$(STAGING_DIR)/usr/lib/pkgconfig:$(STAGING_DIR)/usr/share/pkgconfig \
	PKG_CONFIG_PATH=$(STAGING_DIR)/usr/lib/pkgconfig:$(STAGING_DIR)/usr/share/pkgconfig

define Package/argosfs
  SECTION:=utils
  CATEGORY:=Utilities
  SUBMENU:=Filesystem
  TITLE:=ArgosFS root filesystem daemon and tools
  URL:=https://github.com/fwerkor/argosfs
  DEPENDS:=$(RUST_ARCH_DEPENDS) +libfuse3 +fuse3-utils +kmod-fuse +libpthread
endef

define Package/argosfs/description
 ArgosFS userspace filesystem, raw/loop block backend tooling, and CapOS
 initramfs rootfs integration.
endef

define Build/Prepare
	rm -rf $(PKG_BUILD_DIR)
	mkdir -p $(dir $(PKG_BUILD_DIR))
	cp -a "$(ARGOSFS_LOCAL_SOURCE)" $(PKG_BUILD_DIR)
endef

define Host/Prepare
	rm -rf $(HOST_BUILD_DIR)
	mkdir -p $(dir $(HOST_BUILD_DIR))
	cp -a "$(ARGOSFS_LOCAL_SOURCE)" $(HOST_BUILD_DIR)
endef

define Host/Compile
	cd $(HOST_BUILD_DIR) && \
		PKG_CONFIG_ALLOW_CROSS=0 \
		PKG_CONFIG_LIBDIR="$(STAGING_DIR_HOSTPKG)/lib/pkgconfig:$(STAGING_DIR_HOST)/lib/pkgconfig:$(HOST_FUSE3_PKG_CONFIG_LIBDIR)" \
		CARGO_TARGET_DIR="$(HOST_BUILD_DIR)/target" \
		cargo build --bin argosfs --locked
endef

define Host/Install
	$(INSTALL_DIR) $(HOST_INSTALL_DIR)/bin
	$(INSTALL_BIN) $(HOST_BUILD_DIR)/target/debug/argosfs $(HOST_INSTALL_DIR)/bin/argosfs
endef

define Package/argosfs/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/bin/argosfs $(1)/usr/sbin/argosfs
	$(INSTALL_DIR) $(1)/lib/argosfs
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/contrib/capos/initramfs/argosfs-root.sh $(1)/lib/argosfs/argosfs-root.sh
	$(INSTALL_DIR) $(1)/lib/argosfs/initramfs-hooks
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/contrib/capos/initramfs/hooks/argosfs $(1)/lib/argosfs/initramfs-hooks/argosfs
	$(INSTALL_DIR) $(1)/lib/preinit
	$(INSTALL_BIN) ./files/05_argosfs_root $(1)/lib/preinit/05_argosfs_root
	$(INSTALL_BIN) ./files/79_argosfs_skip_mount_root $(1)/lib/preinit/79_argosfs_skip_mount_root
	$(INSTALL_BIN) ./files/81_argosfs_restore_preinit $(1)/lib/preinit/81_argosfs_restore_preinit
	$(INSTALL_DIR) $(1)/etc/argosfs
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/contrib/capos/mkinitramfs/argosfs.conf $(1)/etc/argosfs/initramfs.conf
	$(INSTALL_DIR) $(1)/lib/systemd/system
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/contrib/capos/systemd/argosfs-root.service $(1)/lib/systemd/system/
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/contrib/capos/systemd/argosfs-health.service $(1)/lib/systemd/system/
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/contrib/capos/systemd/argosfs-watchdog.service $(1)/lib/systemd/system/
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/contrib/capos/systemd/argosfs-recovery.target $(1)/lib/systemd/system/
endef

$(eval $(call HostBuild))
$(eval $(call BuildPackage,argosfs))
MAKEFILE
cat >"$artifacts/capos/package/utils/argosfs/files/05_argosfs_root" <<'SH'
#!/bin/sh

argosfs_cmdline_enabled() {
	for arg in $(cat /proc/cmdline 2>/dev/null); do
		case "$arg" in
			argosfs.images=*|argosfs.devices=*) return 0 ;;
			argosfs.autoscan=1) return 0 ;;
		esac
	done
	return 1
}

argosfs_root_enabled() {
	argosfs_cmdline_enabled && return 0
	[ -r /etc/argosfs/initramfs.conf ] || return 1
	. /etc/argosfs/initramfs.conf
	[ "${ARGOSFS_AUTOSCAN:-0}" = "1" ]
}

argosfs_mount_initramfs_root() {
	[ "$INITRAMFS" = "1" ] || return 0
	argosfs_root_enabled || return 0

	if [ ! -x /lib/argosfs/argosfs-root.sh ]; then
		echo "argosfs: /lib/argosfs/argosfs-root.sh is missing" >/dev/console
		exec sh
	fi

	exec /lib/argosfs/argosfs-root.sh
	echo "argosfs: root handoff failed" >/dev/console
	exec sh
}

boot_hook_add initramfs argosfs_mount_initramfs_root
SH
cat >"$artifacts/capos/package/utils/argosfs/files/79_argosfs_skip_mount_root" <<'SH'
#!/bin/sh

argosfs_mark_root_active() {
	[ -e /run/argosfs-root-active ] || return 0
	export ARGOSFS_ROOT_ACTIVE=1
	export INITRAMFS=1
}

argosfs_mark_root_active
SH
cat >"$artifacts/capos/package/utils/argosfs/files/81_argosfs_restore_preinit" <<'SH'
#!/bin/sh

argosfs_restore_regular_preinit() {
	[ "$ARGOSFS_ROOT_ACTIVE" = "1" ] || return 0
	unset INITRAMFS
}

argosfs_restore_regular_preinit
SH

(
	cd "$artifacts/capos"
	test -f include/package.mk
	test -f include/image.mk
	test -x scripts/feeds
	test -f package/utils/argosfs/Makefile
	grep -q 'PKG_SOURCE_URL:=https://github.com/fwerkor/argosfs' package/utils/argosfs/Makefile
	grep -q 'PKG_SOURCE_VERSION:=main' package/utils/argosfs/Makefile
	grep -q 'libfuse3' package/utils/argosfs/Makefile
	grep -q 'ARGOSFS_CI_LOCAL_SOURCE' package/utils/argosfs/Makefile
	grep -q 'define Image/mkfs/argosfs' include/image.mk
	grep -q -- '--defer-journal-flush' include/image.mk
	grep -q -- '--defer-metadata-commit' include/image.mk
	grep -q -- '--defer-data-flush' include/image.mk
)

write_capos_target_config() {
	local target="$1"
	case "$target" in
		x86_64)
			cat >.config <<'CONFIG'
CONFIG_TARGET_x86=y
CONFIG_TARGET_x86_64=y
CONFIG_TARGET_x86_64_DEVICE_generic=y
CONFIG_TARGET_ROOTFS_ARGOSFS=y
CONFIG_TARGET_ROOTFS_INITRAMFS=y
CONFIG_TARGET_IMAGES_GZIP=n
CONFIG_TARGET_ROOTFS_PARTSIZE=512
CONFIG_TARGET_KERNEL_PARTSIZE=64
CONFIG_GRUB_IMAGES=y
CONFIG_GRUB_EFI_IMAGES=y
CONFIG_GRUB_SERIAL=y
CONFIG_GRUB_BAUDRATE=115200
CONFIG_TARGET_SERIAL="ttyS0"
CONFIG_PACKAGE_argosfs=y
CONFIG_PACKAGE_libfuse3=y
CONFIG_PACKAGE_fuse3-utils=y
CONFIG_PACKAGE_kmod-fuse=y
CONFIG_DEVEL=y
CONFIG_SIGNED_PACKAGES=n
CONFIG_ALL_KMODS=n
CONFIG_ALL_NONSHARED=n
CONFIG
			;;
		armsr_armv8)
			cat >.config <<'CONFIG'
CONFIG_TARGET_armsr=y
CONFIG_TARGET_armsr_armv8=y
CONFIG_TARGET_armsr_armv8_DEVICE_generic=y
CONFIG_TARGET_ROOTFS_ARGOSFS=y
CONFIG_TARGET_ROOTFS_INITRAMFS=y
CONFIG_TARGET_IMAGES_GZIP=n
CONFIG_TARGET_ROOTFS_PARTSIZE=512
CONFIG_TARGET_KERNEL_PARTSIZE=64
CONFIG_GRUB_IMAGES=y
CONFIG_GRUB_EFI_IMAGES=y
CONFIG_GRUB_SERIAL=y
CONFIG_GRUB_BAUDRATE=115200
CONFIG_TARGET_SERIAL="ttyS0"
CONFIG_PACKAGE_argosfs=y
CONFIG_PACKAGE_libfuse3=y
CONFIG_PACKAGE_fuse3-utils=y
CONFIG_PACKAGE_kmod-fuse=y
CONFIG_DEVEL=y
CONFIG_SIGNED_PACKAGES=n
CONFIG_ALL_KMODS=n
CONFIG_ALL_NONSHARED=n
CONFIG
			;;
		riscv64_sifiveu)
			cat >.config <<'CONFIG'
CONFIG_TARGET_sifiveu=y
CONFIG_TARGET_sifiveu_generic=y
CONFIG_TARGET_sifiveu_generic_DEVICE_sifive_unmatched=y
CONFIG_TARGET_ROOTFS_ARGOSFS=y
CONFIG_TARGET_ROOTFS_INITRAMFS=y
CONFIG_TARGET_IMAGES_GZIP=n
CONFIG_TARGET_ROOTFS_PARTSIZE=512
CONFIG_TARGET_KERNEL_PARTSIZE=64
CONFIG_PACKAGE_argosfs=y
CONFIG_PACKAGE_libfuse3=y
CONFIG_PACKAGE_fuse3-utils=y
CONFIG_PACKAGE_kmod-fuse=y
CONFIG_DEVEL=y
CONFIG_SIGNED_PACKAGES=n
CONFIG_ALL_KMODS=n
CONFIG_ALL_NONSHARED=n
CONFIG
			;;
		*)
			echo "unknown CapOS target matrix entry: $target" >&2
			return 2
			;;
	esac
}

verify_capos_argosfs_config() {
	local target="$1"
	local log="$artifacts/capos-defconfig-$target.log"
	write_capos_target_config "$target"
	if ! run_logged "$log" make defconfig; then
		return 1
	fi
	for required in \
		CONFIG_TARGET_ROOTFS_ARGOSFS \
		CONFIG_TARGET_ROOTFS_INITRAMFS \
		CONFIG_PACKAGE_argosfs \
		CONFIG_PACKAGE_libfuse3 \
		CONFIG_PACKAGE_fuse3-utils \
		CONFIG_PACKAGE_kmod-fuse; do
		if ! grep -q "^$required=y$" .config; then
			echo "CapOS target $target missing required $required=y" >&2
			grep -En '^(CONFIG_TARGET_ROOTFS_|CONFIG_PACKAGE_(argosfs|libfuse3|fuse3-utils|kmod-fuse)=)' .config >&2 || true
			return 1
		fi
	done
	if grep -Eq '^CONFIG_TARGET_ROOTFS_(EXT4FS|SQUASHFS|EROFS|UBIFS|TARGZ|CPIOGZ)=y$' .config; then
		echo "CapOS target $target enabled a non-ArgosFS rootfs" >&2
		grep -En '^CONFIG_TARGET_ROOTFS_(ARGOSFS|EXT4FS|SQUASHFS|EROFS|UBIFS|TARGZ|CPIOGZ)=y$' .config >&2
		return 1
	fi
	cp .config "$artifacts/capos-config-$target"
	echo "CapOS target $target ArgosFS rootfs defconfig passed"
}

PKG_CONFIG_LIBDIR="$system_pkg_config_libdir" pkg-config --exists fuse3
cargo build --manifest-path "$artifacts/argosfs-src/Cargo.toml" --bin argosfs --locked
"$artifacts/argosfs-src/target/debug/argosfs" --help >/dev/null

if [ "$capos_full_compile" = "1" ]; then
	(
		cd "$artifacts/capos"
		if [ ! -f feeds/packages/lang/rust/rust-package.mk ]; then
			./scripts/feeds update -a
			./scripts/feeds install -a
		fi
		old_ifs="$IFS"
		IFS=,
		for target in $capos_target_matrix; do
			IFS="$old_ifs"
			verify_capos_argosfs_config "$target"
			IFS=,
		done
		IFS="$old_ifs"
		write_capos_target_config "$capos_build_target"
		run_logged "$artifacts/capos-defconfig-build-$capos_build_target.log" make defconfig
		make_args=()
		[ -z "$capos_make_v" ] || make_args+=("V=$capos_make_v")
		if [ -n "$capos_tools_target" ]; then
			if ! run_logged "$artifacts/capos-tools-build.log" make -j"$capos_make_jobs" "$capos_tools_target" "${make_args[@]}"; then
				exit 1
			fi
		else
			host_pkg_config="$(command -v pkg-config)"
			mkdir -p staging_dir/host/bin
			ln -sf "$host_pkg_config" staging_dir/host/bin/pkg-config
		fi
		if ! run_logged "$artifacts/capos-argosfs-build.log" \
			env ARGOSFS_CI_LOCAL_SOURCE=1 \
			ARGOSFS_LOCAL_SOURCE="$artifacts/argosfs-src" \
			ARGOSFS_SYSTEM_PKG_CONFIG_LIBDIR="$system_pkg_config_libdir" \
			make -j"$capos_make_jobs" "$capos_make_target" "${make_args[@]}"; then
			exit 1
		fi
		host_argosfs="staging_dir/hostpkg/bin/argosfs"
		if [ ! -x "$host_argosfs" ]; then
			host_argosfs="$(find build_dir/hostpkg -path '*/host-install/bin/argosfs' -type f -perm -111 | head -n 1)"
		fi
		test -n "$host_argosfs"
		test -x "$host_argosfs"
		"$host_argosfs" --help >/dev/null
	)
fi

echo "CapOS ArgosFS environment compile smoke passed; artifacts=$artifacts"
