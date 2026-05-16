#!/usr/bin/env bash
set -euo pipefail

mode="quick"
out="paper-data/runs/experiment-$(date +%Y%m%d-%H%M%S)"

while [ "$#" -gt 0 ]; do
  case "$1" in
    --quick) mode="quick" ;;
    --full) mode="full" ;;
    --output) shift; out="$1" ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
  shift
done

mkdir -p "$out/raw" "$out/processed" "$out/figures" "$out/tables" "$out/logs"
cargo build --release 2>&1 | tee "$out/logs/cargo-build.log"

seed="${ARGOSFS_EXPERIMENT_SEED:-424242}"
export ARGOSFS_EXPERIMENT_SEED="$seed"

python3 scripts/experiments/run_failure_matrix.py --mode "$mode" --output "$out/raw/failure-matrix.jsonl"
python3 scripts/experiments/run_workload_shift.py --mode "$mode" --output "$out/raw/workload-shift.csv"
python3 scripts/experiments/run_metadata_scalability.py --mode "$mode" --output "$out/raw/metadata-scalability.csv"
bash scripts/experiments/run_baselines.sh --mode "$mode" --output "$out/raw/baselines.jsonl"
bash scripts/experiments/run_qemu_rootfs_matrix.sh --mode "$mode" --output "$out/raw/qemu-rootfs.jsonl"
python3 scripts/experiments/summarize_results.py "$out/raw" "$out"

cat > "$out/manifest.json" <<EOF
{
  "mode": "$mode",
  "seed": "$seed",
  "argosfs_commit": "$(git rev-parse HEAD)",
  "kernel": "$(uname -srmo)",
  "output": "$out"
}
EOF

echo "$out"
