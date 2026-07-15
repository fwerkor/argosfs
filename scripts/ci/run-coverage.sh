#!/usr/bin/env bash
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo"

minimum_lines="${ARGOSFS_COVERAGE_MIN_LINES:-90}"
require_fuse="${ARGOSFS_COVERAGE_REQUIRE_FUSE:-0}"
artifacts="${ARGOSFS_COVERAGE_ARTIFACTS:-$repo/target/coverage}"
rm -rf "$artifacts"
mkdir -p "$artifacts"

if ! cargo llvm-cov --version >/dev/null 2>&1; then
  echo "ERROR: cargo-llvm-cov is required" >&2
  exit 2
fi

# External CLI and mounted-FUSE processes must use the same instrumentation
# environment as the Rust test binaries. The clean must happen after show-env,
# otherwise Cargo can reuse uninstrumented artifacts from the ordinary target.
eval "$(cargo llvm-cov show-env --sh)"
# cargo-llvm-cov defaults to an eight-file profile pool (`%8m`). This workflow
# launches the same test binaries repeatedly through the host scenario scripts;
# a bounded pool lets later filtered runs overwrite the initial full-test
# profiles. Use one profile per process/module so the final report is a union of
# every Cargo, CLI, and FUSE execution.
export LLVM_PROFILE_FILE="$repo/target/argosfs-%p-%m.profraw"
cargo llvm-cov clean --workspace

cargo test --all-targets --all-features -- --test-threads=1
cargo build --locked --bin argosfs
export ARGOSFS_BIN="$repo/target/debug/argosfs"

ARGOSFS_TEST_ARTIFACTS="$artifacts/cli-features" \
  scripts/tests/host/cli_features.sh
ARGOSFS_BIN="$ARGOSFS_BIN" \
  scripts/compat/run_deep_roundtrip.sh "$artifacts/deep-roundtrip"
ARGOSFS_TEST_ARTIFACTS="$artifacts/loop-backend" \
  scripts/tests/host/loop_backend.sh
ARGOSFS_TEST_ARTIFACTS="$artifacts/block-lifecycle" \
  scripts/tests/host/block_lifecycle.sh
ARGOSFS_TEST_ARTIFACTS="$artifacts/crash-consistency" \
  scripts/tests/host/crash_consistency.sh --unprivileged
ARGOSFS_TEST_ARTIFACTS="$artifacts/rootfs-smoke" \
  scripts/tests/host/rootfs_smoke.sh
ARGOSFS_RANDOM_MODEL_OPS="${ARGOSFS_COVERAGE_RANDOM_OPS:-80}" \
ARGOSFS_RANDOM_MODEL_SEEDS="${ARGOSFS_COVERAGE_RANDOM_SEEDS:-0xA2605F5}" \
ARGOSFS_TEST_ARTIFACTS="$artifacts/randomized-model" \
  scripts/tests/host/randomized_model.sh

if [ -c /dev/fuse ] && [ -r /dev/fuse ] && [ -w /dev/fuse ]; then
  ARGOSFS_COMPAT_WORKDIR="$artifacts/mounted-fuse" \
    scripts/tests/host/privileged_fuse.sh
  # GitHub's RUNNER_TEMP parent is not traversable by the nobody user. The
  # cross-user permission suite must live directly below a world-traversable
  # temporary directory, otherwise kernel default_permissions rejects every
  # access before it reaches the mounted filesystem.
  permission_work="${TMPDIR:-/tmp}/argosfs-coverage-permission-$$"
  rm -rf "$permission_work"
  ARGOSFS_PERMISSION_COMPAT_MODE=kernel \
  ARGOSFS_COMPAT_WORKDIR="$permission_work" \
    scripts/tests/host/permission_compat.sh
  if [ -n "${PJDFSTEST_ROOT:-}" ] && [ -d "$PJDFSTEST_ROOT/tests" ]; then
    ARGOSFS_COMPAT_WORKDIR="$artifacts/pjdfstest-work" \
      scripts/tests/host/pjdfstest_compat.sh "$artifacts/pjdfstest.jsonl"
  elif [ "$require_fuse" = "1" ]; then
    echo "ERROR: PJDFSTEST_ROOT is required for the coverage gate" >&2
    exit 1
  fi
elif [ "$require_fuse" = "1" ]; then
  echo "ERROR: readable and writable /dev/fuse is required for the coverage gate" >&2
  exit 1
else
  echo "WARNING: mounted FUSE coverage skipped because /dev/fuse is unavailable" >&2
fi

cargo llvm-cov report --lcov --output-path "$artifacts/lcov.info"
cargo llvm-cov report --summary-only \
  --fail-under-lines "$minimum_lines" | tee "$artifacts/summary.txt"
