# ArgosFS Architecture

ArgosFS follows the layered design described in `deep-research-report.md` and is
implemented as a Rust core with a real FUSE frontend.

## Layers

- Metadata service: JSON metadata committed with copy-on-write replacement,
  append-only journal records, audit log, and point-in-time metadata snapshots.
- Data plane: block compression, Reed-Solomon erasure coding, weighted
  placement, shard checksum verification, hard capacity enforcement, repair, and
  migration.
- Cache layer: process-local RAM LRU plus persistent L2 cache under the volume.
- Control plane: CLI operations for creation, reads/writes, health, rebalance,
  disk lifecycle, scrub/fsck, FUSE mounting, import/export, and benchmarks.
- Autopilot: disk probing, SMART refresh, periodic health scoring, failure
  prediction, disk draining, repair, rebalancing, tier classification, latency
  feedback, and cache maintenance.

## Data Path

Writes split a file into logical stripes of up to `k * chunk_size` bytes. Each
stripe is compressed, padded into `k` equal data shards, encoded into `m` parity
shards, checksummed, and placed on distinct online disks. Placement excludes
failed, draining, and capacity-exhausted disks. Reads verify shard checksums,
reconstruct missing/corrupt shards when enough data remains, verify the raw
stripe checksum, update per-disk latency EWMA, and populate RAM/L2 caches.

## Heterogeneous Disks

Each disk stores a probed class, backing block device, rotational flag, capacity,
measured read/write throughput, read/write latency EWMA, tier, and weight.
ArgosFS discovers these values from sysfs/statvfs plus a small local benchmark.
When `smartctl` is installed and a backing device is known, `refresh-smart` and
autopilot import SMART/NVMe health counters into the risk model.

## Failure Model

For a `k+m` layout, any `m` shard losses in one stripe can be recovered. Disk
failure is modeled as all shards on that disk becoming unavailable. The repair
path reconstructs missing shards and writes them to healthy replacement disks.

## Mounting

The FUSE frontend uses `fuser` and exposes inode-based Linux filesystem
operations. It supports the node types needed by a root filesystem: regular
files, directories, symlinks, hardlinks, character devices, block devices, FIFOs,
and sockets.
