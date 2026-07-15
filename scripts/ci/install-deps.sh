#!/usr/bin/env bash
set -euo pipefail

apt_get() {
	local attempt
	local max_attempts=4
	for ((attempt = 1; attempt <= max_attempts; attempt++)); do
		if sudo apt-get \
			-o Acquire::ForceIPv4=true \
			-o Acquire::Retries=5 \
			-o Acquire::http::Timeout=30 \
			-o Acquire::https::Timeout=30 \
			-o DPkg::Lock::Timeout=120 \
			"$@"; then
			return 0
		fi
		if ((attempt == max_attempts)); then
			return 1
		fi
		echo "warning: apt-get failed (attempt $attempt/$max_attempts); retrying" >&2
		sleep $((attempt * 10))
	done
}

apt_get update
apt_get install -y --no-install-recommends \
	acl \
	attr \
	autoconf \
	automake \
	bison \
	build-essential \
	clang \
	dmsetup \
	file \
	flex \
	fuse3 \
	g++ \
	gawk \
	gettext \
	git \
	libfuse3-dev \
	libncurses-dev \
	libssl-dev \
	pkg-config \
	python3 \
	rsync \
	smartmontools \
	socat \
	unzip \
	wget \
	zlib1g-dev

optional_packages=(
	gcc-multilib
	qemu-utils
)
case "${ARGOSFS_CI_QEMU_ARCH:-all}" in
	x86_64)
		optional_packages+=(qemu-system-x86)
		;;
	aarch64|arm64)
		optional_packages+=(qemu-efi-aarch64 qemu-system-arm)
		;;
	riscv64)
		optional_packages+=(qemu-system-misc)
		;;
	all)
		optional_packages+=(qemu-efi-aarch64 qemu-system-arm qemu-system-misc qemu-system-x86)
		;;
	*)
		echo "unknown ARGOSFS_CI_QEMU_ARCH=${ARGOSFS_CI_QEMU_ARCH}" >&2
		exit 2
		;;
esac
for package in "${optional_packages[@]}"; do
	if apt_get install -y --no-install-recommends "$package"; then
		continue
	fi
	echo "warning: optional CI package was unavailable on this runner: $package" >&2
done
