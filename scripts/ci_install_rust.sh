#!/usr/bin/env bash
set -euo pipefail

toolchain="${1:-stable}"
shift || true

components=()
for component in "$@"; do
	[ -n "$component" ] || continue
	components+=("$component")
done

have_toolchain() {
	command -v rustup >/dev/null 2>&1 || return 1
	rustup run "$toolchain" rustc --version >/dev/null 2>&1 || return 1
	local installed
	installed="$(rustup component list --toolchain "$toolchain" --installed 2>/dev/null || true)"
	local component
	for component in "${components[@]}"; do
		printf '%s\n' "$installed" | grep -Eq "^${component}(-|[[:space:]]|$)" || return 1
	done
	return 0
}

if have_toolchain; then
	rustup default "$toolchain"
	rustc --version
	cargo --version
	exit 0
fi

if ! command -v rustup >/dev/null 2>&1; then
	for attempt in 1 2 3 4 5; do
		if curl --proto '=https' --tlsv1.2 --retry 10 --retry-connrefused --location --silent --show-error --fail https://sh.rustup.rs | sh -s -- --default-toolchain none -y; then
			break
		fi
		if [ "$attempt" = "5" ]; then
			exit 1
		fi
		sleep $((attempt * 5))
	done
	export PATH="$HOME/.cargo/bin:$PATH"
fi

install_args=()
for component in "${components[@]}"; do
	install_args+=(--component "$component")
done

for attempt in 1 2 3 4 5; do
	if rustup toolchain install "$toolchain" --profile minimal --no-self-update "${install_args[@]}"; then
		rustup default "$toolchain"
		rustc --version
		cargo --version
		exit 0
	fi
	if have_toolchain; then
		rustup default "$toolchain"
		rustc --version
		cargo --version
		exit 0
	fi
	if [ "$attempt" = "5" ]; then
		exit 1
	fi
	sleep $((attempt * 5))
done
