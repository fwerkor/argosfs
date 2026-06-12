#!/usr/bin/env bash
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
artifacts="${ARGOSFS_TEST_ARTIFACTS:-$repo/target/argosfs-test-artifacts/capos-build}"
capos_repo="${CAPOS_REPO:-https://github.com/fwerkor/capos.git}"
capos_ref="${CAPOS_REF:-main}"
capos_full_compile="${ARGOSFS_CAPOS_FULL_COMPILE:-0}"
capos_make_jobs="${ARGOSFS_CAPOS_MAKE_JOBS:-2}"
capos_make_target="${ARGOSFS_CAPOS_MAKE_TARGET:-package/utils/argosfs/host/compile}"

rm -rf "$artifacts"
mkdir -p "$artifacts/argosfs-src" "$artifacts/capos"

git -C "$repo" archive HEAD | tar -x -C "$artifacts/argosfs-src"
git clone --depth 1 --branch "$capos_ref" "$capos_repo" "$artifacts/capos"

mkdir -p "$artifacts/capos/package/utils/argosfs/files"
cat >"$artifacts/capos/package/utils/argosfs/Makefile" <<'MAKEFILE'
include $(TOPDIR)/rules.mk

PKG_NAME:=argosfs
PKG_RELEASE:=ci

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

PKG_BUILD_PARALLEL:=1
HOST_BUILD_PARALLEL:=1

include $(INCLUDE_DIR)/host-build.mk
include $(INCLUDE_DIR)/package.mk

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
		PKG_CONFIG_LIBDIR="$(STAGING_DIR_HOSTPKG)/lib/pkgconfig:$(STAGING_DIR_HOST)/lib/pkgconfig:$$(env -u PKG_CONFIG_LIBDIR -u PKG_CONFIG_PATH PATH=/usr/local/bin:/usr/bin:/bin pkg-config --variable pc_path pkg-config 2>/dev/null)" \
		CARGO_TARGET_DIR="$(HOST_BUILD_DIR)/target" \
		cargo build --bin argosfs --locked
endef

define Host/Install
	$(INSTALL_DIR) $(HOST_INSTALL_DIR)/bin
	$(INSTALL_BIN) $(HOST_BUILD_DIR)/target/debug/argosfs $(HOST_INSTALL_DIR)/bin/argosfs
endef

define Package/argosfs/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(HOST_INSTALL_DIR)/bin/argosfs $(1)/usr/sbin/argosfs
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
)

pkg-config --exists fuse3
cargo build --manifest-path "$artifacts/argosfs-src/Cargo.toml" --bin argosfs --locked
"$artifacts/argosfs-src/target/debug/argosfs" --help >/dev/null

if [ "$capos_full_compile" = "1" ]; then
	(
		cd "$artifacts/capos"
		if [ ! -f feeds/packages/lang/rust/rust-package.mk ]; then
			./scripts/feeds update -a
			./scripts/feeds install -a
		fi
		cat >.config <<'CONFIG'
CONFIG_TARGET_x86=y
CONFIG_TARGET_x86_64=y
CONFIG_TARGET_x86_64_DEVICE_generic=y
CONFIG_PACKAGE_argosfs=y
CONFIG_PACKAGE_libfuse3=y
CONFIG_PACKAGE_fuse3-utils=y
CONFIG_PACKAGE_kmod-fuse=y
CONFIG_DEVEL=y
CONFIG_SIGNED_PACKAGES=n
CONFIG_ALL_KMODS=n
CONFIG_ALL_NONSHARED=n
CONFIG
		ARGOSFS_CI_LOCAL_SOURCE=1 \
			ARGOSFS_LOCAL_SOURCE="$artifacts/argosfs-src" \
			make -j"$capos_make_jobs" "$capos_make_target" V=s
		test -x staging_dir/hostpkg/bin/argosfs
		staging_dir/hostpkg/bin/argosfs --help >/dev/null
	)
fi

echo "CapOS ArgosFS environment compile smoke passed; artifacts=$artifacts"
