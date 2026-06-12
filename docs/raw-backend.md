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
entry checksum and an internal record hash. Journal records carry full metadata
snapshots so open can replay a newer committed transaction if checkpoint copies
are stale. Rw open marks member superblocks dirty. `ArgosFs::sync()` writes
metadata checkpoints, flushes devices, and marks superblocks clean.

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

Crash injection for loop/raw can be driven with `ARGOSFS_CRASH_POINT` using
`before-data-write`, `after-data-write-before-flush`,
`after-data-flush-before-journal-commit`,
`after-journal-commit-before-metadata-commit`,
`after-metadata-commit-before-superblock-update`, or `during-replay`.
