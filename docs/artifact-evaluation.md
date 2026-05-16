# Artifact Evaluation

## Requirements

- Linux with libfuse3, `/dev/fuse`, Python 3, Rust stable, `attr`, `acl`, and
  smartmontools
- optional: QEMU, pjdfstest, xfstests, Btrfs/ZFS/mdadm tools for full baselines

## Build

```bash
cargo build --release
cargo test
```

## Quick Reproduction

```bash
scripts/experiments/run_all.sh --quick --output paper-data/runs/ae-quick
python3 scripts/experiments/summarize_results.py paper-data/runs/ae-quick/raw paper-data/runs/ae-quick
```

Expected runtime is a few minutes on a laptop. Quick mode records deterministic
JSONL/CSV outputs and marks hardware- or root-required scenarios as skipped or
documented placeholders.

## Full Reproduction

```bash
scripts/experiments/run_all.sh --full --output paper-data/runs/ae-full
scripts/compat/run_fuse_smoke.sh
scripts/compat/run_mounted_fuse_compat.sh
scripts/compat/run_pjdfstest.sh paper-data/compat/pjdfstest.jsonl
```

Full mode is environment-sensitive. QEMU rootfs runs require a prepared root
image; external baselines require their respective kernel modules and tools.
FUSE compatibility scripts emit structured skipped records when the runner does
not expose usable FUSE support.

## Output Layout

- `raw/`: source JSONL/CSV measurements
- `processed/summary.json`: normalized experiment summary
- `tables/overview.csv`: table-ready counts
- `figures/`: plotting output location
- `manifest.json`: seed, commit, kernel, mode, and output path

Known limitations are preserved in the raw records rather than hidden. This
keeps quick-mode artifact evaluation reproducible while leaving full hardware
validation available to reviewers with suitable machines.
