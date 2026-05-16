# Metadata Scalability

The current metadata backend is a copy-on-write JSON store with hash-checked
metadata copies and a transaction journal. It is intentionally transparent for
research, but it is not the intended long-term scaling design.

## Current Mitigations

- read and readdir no longer create durable metadata transactions
- shard byte usage is maintained in metadata counters instead of hot-path scans
- range writes rewrite affected stripes instead of replacing the whole file
- cache L2 pruning uses an in-memory index after the initial scan
- normal metadata transactions are journaled as metadata deltas; full metadata
  snapshots are limited to explicit checkpoint records

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

## Checkpointed Journal

`journal.jsonl` now separates transaction replay from full metadata snapshots.
`mkfs` writes an initial checkpoint record containing the complete `Metadata`
object. Later metadata commits write ordinary transaction records with the txid,
generation, action/details, previous record hash, previous metadata hash, final
metadata hash, and a JSON metadata delta from the previous metadata image to the
post-transaction image. These normal records do not store a full `metadata`
object.

Checkpoint records are written periodically using
`ARGOSFS_CHECKPOINT_INTERVAL_TXIDS` when set, or a conservative default of 128
txids. A checkpoint record stores the full post-transaction metadata and starts a
new replay base for following deltas.

Recovery validates the journal hash chain, loads the latest valid full metadata
checkpoint or old-style full-snapshot record, and replays valid delta records
after it while checking each resulting metadata hash. If a delta or journal
suffix is corrupt, recovery keeps the best valid metadata copy or checkpoint
instead of applying partial state.

This change removes per-transaction full snapshots from the journal. Metadata
copies are still rewritten after every committed transaction; reducing that write
frequency is a separate follow-up that needs stronger crash testing around the
copy update points.
