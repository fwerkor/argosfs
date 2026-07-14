# Raw and Loop Block Backend

ArgosFS supports three storage backends:

- `HostFsBackend`: compatibility and development mode. Shards are normal files
  under `.argosfs/devices/*/shards`.
- `LoopBlockBackend`: unprivileged block-semantics mode over fixed-size image
  files. Images are accessed only through `read_at`, `write_at`, `flush`, and
  capacity checks.
- `RawBlockBackend`: block-device mode for real devices or partitions. It uses
  the same raw layout as loop images and does not create ext4, XFS, btrfs, tar,
  sqlite, or a host directory tree inside the device.

## Layout

All multi-byte fields are explicitly little-endian. The current v1 layout is
4 KiB aligned:

```text
0                 protective header
4 KiB             primary superblock
64 KiB            device label
1 MiB             journal region
4 MiB             metadata region, two checkpoint slots
12 MiB            allocator region
16 MiB            data extent region
end - 1 MiB       backup superblock and backup label
```

The superblock records magic, format version, minimum compatible version,
endianness marker, pool UUID, device UUID, logical disk id, `k/m`, chunk size,
generation, clean state, feature flags, region descriptors, checksum algorithm,
alignment, label, and backup-superblock offset. A SHA-256 checksum covers the
encoded superblock with the checksum field zeroed.

Scan and open read the primary superblock first. If it fails checksum, magic, or
version validation, ArgosFS reads the backup superblock from the end-reserved
region. Duplicate device UUIDs, duplicate disk ids, mixed pool UUIDs, and disk
generation conflicts are rejected instead of guessed around.

## Metadata and Journal

Loop/raw metadata is persisted inside the raw metadata region, not in
`.argosfs/meta.json`. Each checkpoint stores a fixed header, metadata length,
metadata generation, SHA-256 of the logical JSON metadata payload, and a
page-indexed checksum tree for the checkpoint body. The index records each raw
metadata page offset, length, and SHA-256 digest, and the header commits the
index root hash after the body pages have been flushed. Two slots are written on
every member device, and readers still accept legacy single-payload checkpoints
for existing images.

The raw journal region stores length-prefixed JSON transaction records with an
entry checksum and an internal record hash. Records normally carry metadata
deltas and periodic full snapshots, so open can replay a newer committed state
when checkpoint copies are stale. Rw open marks member superblocks dirty. A
clean unmount writes fresh metadata checkpoint copies before marking the member
superblocks clean.

By default, data and journal writes are flushed at each metadata transaction.
Volumes created with `--defer-metadata-commit` instead use bounded group commit:
ordinary updates are accumulated in memory and persisted as one journal
transaction after either of these limits is reached:

- `--deferred-commit-interval-ms` (default `5000` milliseconds); or
- `--deferred-commit-max-transactions` (default `128` metadata transactions).

The FUSE mount owns the periodic timer, so an idle dirty filesystem cannot
remain uncommitted beyond the configured interval. A continuously busy
filesystem is also bounded by the transaction limit. `fsync`, `fdatasync`,
`O_SYNC`, `O_DSYNC`, explicit `ArgosFs::sync()`, and clean unmount bypass the
timer and synchronously commit the current group.

`--defer-journal-flush` avoids a separate device flush for every journal append.
With group commit, the complete group is appended and then flushed once across
the active members. `--defer-data-flush` is accepted only together with
`--defer-metadata-commit`; it batches shard flushes but still enforces the
ordering barrier that all referenced data becomes durable before the group
journal record is committed.

Raw extents replaced or deleted inside an uncommitted group remain reserved.
ArgosFS releases them only at the same durability boundary that commits the new
metadata, preventing a later write from overwriting data still referenced by
the last durable checkpoint. A crash can therefore lose at most the configured
group window, while recovery continues to use checksum-valid, quorum-supported
metadata and journal records. The strict default remains per-transaction data
and journal durability for volumes that do not opt into deferred commit.

## Data Extents

Host shards use `ShardLocation::HostPath`. Loop/raw shards use
`ShardLocation::RawExtent { disk_id, offset, length, generation }`. The extent
length is allocator-aligned; the logical shard size and checksum still cover
only the actual encoded shard bytes.

## Safety

Raw mkfs refuses existing ArgosFS signatures or common filesystem/partition
signatures unless `--force` is explicit. `scan` and `inspect-device` are
readonly. `fsck` is readonly unless repair flags are passed. Recovery mounts are
readonly by default.

Transaction audit reports include per-member raw journal status and a majority
quorum flag. This makes partial fanout, unreadable member journals, and member
tail corruption visible to preflight tooling instead of hiding them behind only
the aggregate invalid-entry count.

Crash injection for loop/raw can be driven with `ARGOSFS_CRASH_POINT` using
`before-data-write`, `after-data-write-before-flush`,
`after-data-flush-before-journal-commit`,
`after-journal-commit-before-metadata-commit`,
`after-metadata-commit-before-superblock-update`, or `during-replay`.
