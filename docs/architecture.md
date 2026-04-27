# ArgosFS Architecture

ArgosFS follows the layered design described in `deep-research-report.md` and is
implemented as a Rust core with a real FUSE frontend.

## Layers

- Metadata service: JSON metadata committed with copy-on-write replacement,
  append-only journal records, audit log, and point-in-time metadata snapshots.
- Data plane: block compression, optional authenticated encryption,
  Reed-Solomon erasure coding, weighted placement, shard checksum verification,
  hard capacity enforcement, repair, and migration.
- Cache layer: process-local RAM LRU plus persistent L2 cache under the volume.
- Control plane: CLI operations for creation, reads/writes, health, rebalance,
  disk lifecycle, scrub/fsck, FUSE mounting, import/export, ACLs, encryption,
  I/O policy, Prometheus metrics, and benchmarks.
- Autopilot: disk probing, SMART refresh, periodic health scoring, failure
  prediction, disk draining, repair, rebalancing, tier classification, latency
  feedback, and cache maintenance.

## Data Path

Writes split a file into logical stripes of up to `k * chunk_size` bytes. Each
stripe is compressed, encrypted when volume encryption is enabled, padded into
`k` equal data shards, encoded into `m` parity shards, checksummed, and placed
on distinct online disks. Placement excludes failed, draining, and
capacity-exhausted disks. Reads verify shard checksums, reconstruct
missing/corrupt shards when enough data remains, decrypt encrypted payloads,
verify the raw stripe checksum, update per-disk latency EWMA, and populate
RAM/L2 caches.

## Heterogeneous Disks

Each disk stores a probed class, backing block device, rotational flag, capacity,
measured read/write throughput, read/write latency EWMA, tier, and weight.
ArgosFS discovers these values from sysfs/statvfs plus a small local benchmark.
When `smartctl` is installed and a backing device is known, `refresh-smart` and
autopilot import SMART/NVMe health counters into the risk model.
If sysfs exposes `device/numa_node`, ArgosFS records the node and gives a small
placement preference to disks local to the current CPU node when NUMA awareness
is enabled.

## ACL and Security

ArgosFS stores POSIX ACLs on inodes and exposes the standard Linux
`system.posix_acl_access` and `system.posix_acl_default` xattrs using the kernel
binary xattr format. It also exposes readable ArgosFS text aliases for CLI and
debugging workflows. Default directory ACLs are inherited by new children.
NFSv4 ACLs are stored as JSON ACE lists under `system.argosfs.nfs4_acl`.

The FUSE daemon evaluates NFSv4 ACLs first, then POSIX ACLs, then Unix mode
bits. Root (`uid 0`) bypasses checks. Permission failures return `EACCES`.

## Advanced I/O and Metrics

Shard I/O can run in buffered, `O_DIRECT`, or `io_uring` mode. Direct and
io_uring paths intentionally fall back to buffered I/O when alignment,
filesystem, or kernel policy prevents the requested path. Reads can use mmap
for zero-copy staging before returning data to the reconstruction pipeline.

The Prometheus exporter serves `/metrics` and reports volume transaction IDs,
file counts, encryption state, io_uring availability, disk capacity, disk usage,
risk scores, online status, and latency EWMA values.

## Failure Model

For a `k+m` layout, any `m` shard losses in one stripe can be recovered. Disk
failure is modeled as all shards on that disk becoming unavailable. The repair
path reconstructs missing shards and writes them to healthy replacement disks.

## Mounting

The FUSE frontend uses `fuser` and exposes inode-based Linux filesystem
operations. It supports the node types needed by a root filesystem: regular
files, directories, symlinks, hardlinks, character devices, block devices, FIFOs,
and sockets.
