# Performance report

The `Performance report` GitHub Actions workflow compares the loop-backed ArgosFS
FUSE frontend with an ext4 loop image on the same GitHub-hosted runner.

It runs three ArgosFS durability configurations:

- strict journal flushing,
- deferred journal flushing,
- batched metadata commits with deferred data flushing.

The report measures:

- sequential write throughput followed by `fsync`,
- sequential cached read throughput,
- small-file creation rate,
- small-file `stat` rate.

Pull requests and pushes to `main` use the quick workload with three repeated
measurements. The scheduled run uses the full workload with five repetitions.
Manual runs can select either workload and set the repetition count.

Each run writes a Markdown table to the GitHub job summary and uploads:

- `rootfs-perf.jsonl`, containing every raw measurement,
- `performance-summary.csv`, containing medians, ext4 ratios, and coefficients
  of variation,
- `performance-report.md`, containing the rendered report,
- `environment.txt`, containing runner and workload details.

Scenario order rotates between repetitions to reduce fixed ordering bias. The
reported values are medians, and every throughput metric is shown as a ratio to
the ext4 loop-image result collected on the same runner.

## Interpretation

The comparison is end-to-end. ArgosFS runs through FUSE and its own block,
metadata, and journal paths, while ext4 runs in the kernel. It therefore shows
user-visible overhead but does not isolate the cost of FUSE, journaling,
erasure coding, or metadata handling.

The small-file workload does not call `fsync` for every file, so ext4 may retain
more dirty state than strict ArgosFS. The sequential write workload does call
`fsync` before it is recorded.

GitHub-hosted runner hardware and load vary. The workflow reports sample
variation and deliberately does not enforce a performance threshold. Stable
regression gating would require a dedicated, pinned self-hosted runner and a
stored reference distribution.

Run the same benchmark locally with:

```bash
cargo build --release
python3 scripts/experiments/run_rootfs_perf.py \
  --mode quick \
  --iterations 3 \
  --require-all \
  --output target/rootfs-perf/rootfs-perf.jsonl
python3 scripts/experiments/render_rootfs_perf_report.py \
  target/rootfs-perf/rootfs-perf.jsonl \
  --markdown target/rootfs-perf/performance-report.md \
  --csv target/rootfs-perf/performance-summary.csv \
  --commit "$(git rev-parse HEAD)"
```

The ext4 scenario needs loop-device mount privileges. The script uses `sudo`
for ext4 mount, ownership transfer, and unmount when it is not already running
as root.
