#!/usr/bin/env bash
set -euo pipefail

sudo apt-get update
sudo apt-get install -y --no-install-recommends \
	acl \
	attr \
	bison \
	build-essential \
	clang \
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
	qemu-efi-aarch64
	qemu-system-arm
	qemu-system-misc
	qemu-system-x86
	qemu-utils
)
for package in "${optional_packages[@]}"; do
	if sudo apt-get install -y --no-install-recommends "$package"; then
		continue
	fi
	echo "warning: optional CI package was unavailable on this runner: $package" >&2
done
