# Metadata Scalability

The current metadata backend is a copy-on-write JSON store with hash-checked
metadata copies and a transaction journal. It is intentionally transparent for
research, but it is not the intended long-term scaling design.

## Current Mitigations

- read and readdir no longer create durable metadata transactions
- shard byte usage is maintained in metadata counters instead of hot-path scans
- range writes rewrite affected stripes instead of replacing the whole file
- cache L2 pruning uses an in-memory index after the initial scan

## Benchmark Entry Point

```bash
python3 scripts/experiments/run_metadata_scalability.py --mode quick --output paper-data/raw/metadata-scalability.csv
```

The benchmark records metadata size pressure against file count. It is a
baseline for a future page/B-tree metadata backend.

## Page/B-Tree Plan

1. Split inode, directory, xattr, disk, and shard indexes into fixed pages.
2. Journal page deltas for normal transactions.
3. Write full checkpoints periodically and after clean shutdown.
4. Compact old checkpoints once every newer delta chain has been verified.
5. Keep JSON export/import as a debugging and artifact-evaluation format.
