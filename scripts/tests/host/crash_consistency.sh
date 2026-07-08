#!/usr/bin/env bash
set -euo pipefail

mode="${1:---unprivileged}"
repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
artifacts="$repo/target/argosfs-test-artifacts/crash-consistency"
mkdir -p "$artifacts"

case "$mode" in
	--unprivileged)
		cargo test --manifest-path "$repo/Cargo.toml" --all-targets --all-features \
			journal_replay_recovers_transaction_after_power_loss_point
		cargo test --manifest-path "$repo/Cargo.toml" --all-targets --all-features \
			metadata_copy_crash_points_recover_committed_transaction
		cargo test --manifest-path "$repo/Cargo.toml" --all-targets --all-features \
			loop_block_backend_round_trips_raw_extents_without_host_shards
		;;
	*)
		echo "unsupported mode: $mode" >&2
		exit 2
		;;
esac
echo "crash consistency dry-run passed; artifacts=$artifacts"
