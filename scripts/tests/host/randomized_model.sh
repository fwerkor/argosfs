#!/usr/bin/env bash
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
artifacts_root="${ARGOSFS_TEST_ARTIFACTS:-$repo/target/argosfs-test-artifacts/randomized-model}"
rm -rf "$artifacts_root"
mkdir -p "$artifacts_root"

profile="${ARGOSFS_CARGO_PROFILE:-debug}"
case "$profile" in
  debug)
    profile_args=()
    ;;
  release)
    profile_args=(--release)
    ;;
  *)
    echo "ERROR: ARGOSFS_CARGO_PROFILE must be debug or release, got: $profile" >&2
    exit 2
    ;;
esac
cargo build --manifest-path "$repo/Cargo.toml" --bin argosfs --locked "${profile_args[@]}"
argosfs="$repo/target/$profile/argosfs"

ops="${ARGOSFS_RANDOM_MODEL_OPS:-250}"
check_interval="${ARGOSFS_RANDOM_MODEL_CHECK_INTERVAL:-50}"
max_file_size="${ARGOSFS_RANDOM_MODEL_MAX_FILE_SIZE:-65536}"
seeds_csv="${ARGOSFS_RANDOM_MODEL_SEEDS:-0xA2605F5}"
disks="${ARGOSFS_RANDOM_MODEL_DISKS:-5}"
k="${ARGOSFS_RANDOM_MODEL_K:-3}"
m="${ARGOSFS_RANDOM_MODEL_M:-1}"
chunk_size="${ARGOSFS_RANDOM_MODEL_CHUNK_SIZE:-32768}"
compression="${ARGOSFS_RANDOM_MODEL_COMPRESSION:-zstd}"

IFS=',' read -r -a seeds <<<"$seeds_csv"
for seed in "${seeds[@]}"; do
	seed="$(printf '%s' "$seed" | tr -d '[:space:]')"
	[ -n "$seed" ] || continue
	safe_seed="$(printf '%s' "$seed" | tr -c '[:alnum:]_.-' '_')"
	python3 "$repo/scripts/tests/host/randomized_model.py" \
		--argosfs "$argosfs" \
		--artifacts "$artifacts_root/seed-$safe_seed" \
		--seed "$seed" \
		--ops "$ops" \
		--check-interval "$check_interval" \
		--max-file-size "$max_file_size" \
		--disks "$disks" \
		--k "$k" \
		--m "$m" \
		--chunk-size "$chunk_size" \
		--compression "$compression"
done

echo "ArgosFS randomized model test passed; artifacts=$artifacts_root"
