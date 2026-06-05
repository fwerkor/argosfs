#!/usr/bin/env bash
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
artifacts="${ARGOSFS_TEST_ARTIFACTS:-$repo/target/argosfs-test-artifacts/capos-build}"
capos_repo="${CAPOS_REPO:-https://github.com/fwerkor/capos.git}"
capos_ref="${CAPOS_REF:-main}"

rm -rf "$artifacts"
mkdir -p "$artifacts/argosfs-src" "$artifacts/capos"

git -C "$repo" archive HEAD | tar -x -C "$artifacts/argosfs-src"
git clone --depth 1 --branch "$capos_ref" "$capos_repo" "$artifacts/capos"

mkdir -p "$artifacts/capos/package/utils/argosfs"
cat >"$artifacts/capos/package/utils/argosfs/Makefile" <<'MAKEFILE'
include $(TOPDIR)/rules.mk

PKG_NAME:=argosfs
PKG_RELEASE:=ci

PKG_MAINTAINER:=FWERKOR
PKG_LICENSE:=Apache-2.0
PKG_LICENSE_FILES:=LICENSE
PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=https://github.com/fwerkor/argosfs
PKG_SOURCE_VERSION:=main

HOST_BUILD_DEPENDS:=rust/host
PKG_BUILD_PARALLEL:=1
HOST_BUILD_PARALLEL:=1
RUST_HOST_LOCKED:=1

include $(INCLUDE_DIR)/host-build.mk
include $(INCLUDE_DIR)/package.mk
include $(TOPDIR)/feeds/packages/lang/rust/rust-host-build.mk

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

define Host/Prepare
	rm -rf $(HOST_BUILD_DIR)
	mkdir -p $(dir $(HOST_BUILD_DIR))
	cp -a "$(ARGOSFS_LOCAL_SOURCE)" $(HOST_BUILD_DIR)
endef

define Package/argosfs/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(HOST_INSTALL_DIR)/bin/argosfs $(1)/usr/sbin/argosfs
endef

$(eval $(call RustBinHostBuild))
$(eval $(call HostBuild))
$(eval $(call BuildPackage,argosfs))
MAKEFILE

(
	cd "$artifacts/capos"
	test -f include/package.mk
	test -f include/image.mk
	test -x scripts/feeds
	test -f package/utils/argosfs/Makefile
	grep -q 'PKG_SOURCE_URL:=https://github.com/fwerkor/argosfs' package/utils/argosfs/Makefile
	grep -q 'PKG_SOURCE_VERSION:=main' package/utils/argosfs/Makefile
	grep -q 'libfuse3' package/utils/argosfs/Makefile
)

pkg-config --exists fuse3
cargo build --manifest-path "$artifacts/argosfs-src/Cargo.toml" --bin argosfs --locked
"$artifacts/argosfs-src/target/debug/argosfs" --help >/dev/null

echo "CapOS ArgosFS environment compile smoke passed; artifacts=$artifacts"
