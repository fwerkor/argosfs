# ArgosFS

ArgosFS is a Rust implementation of a self-driving, erasure-coded Linux
filesystem designed from `deep-research-report.md`. It provides a real FUSE
mount frontend suitable for root filesystem experiments, plus a management CLI,
health autopilot, repair tooling, and retained validation data workflows.

ArgosFS is implemented in Rust for memory safety and future kernel-adjacent
reuse. The data plane uses mature crates rather than hand-rolled primitives:

- `reed-solomon-erasure` for configurable `k+m` Reed-Solomon layouts.
- `fuser`/libfuse3 for the Linux filesystem mount frontend.
- `zstd` and `lz4_flex` for transparent block compression.
- `chacha20poly1305` and `argon2` for built-in authenticated encryption.
- `io-uring`, `O_DIRECT`, and mmap-backed zero-copy reads for advanced I/O.
- `serde_json` with copy-on-write replacement for durable metadata commits.

## Implemented Features

- Real FUSE mount: `lookup`, `getattr`, `setattr`, `mknod`, `mkdir`, `unlink`,
  `rmdir`, `rename`, `link`, `symlink`, `readlink`, `open`, `read`, `write`,
  `statfs`, xattrs, `readdir`, `access`, `create`, and `fsync`.
- Rootfs-critical inode types: regular files, directories, symlinks, hardlinks,
  character devices, block devices, FIFOs, and sockets.
- POSIX ACL support through native Linux `system.posix_acl_access` and
  `system.posix_acl_default` xattrs, text ACL CLI helpers, inheritance from
  directory default ACLs, and daemon-side FUSE permission enforcement.
- NFSv4 ACL support through JSON ACLs stored as `system.argosfs.nfs4_acl`; NFSv4
  allow/deny ACEs are evaluated before POSIX ACLs and mode bits.
- Built-in per-stripe authenticated encryption using Argon2id-derived keys and
  XChaCha20-Poly1305. Missing or invalid keys fail reads/writes with `EACCES`.
- Reed-Solomon erasure coding with configurable `k+m` redundancy; layouts such
  as `4+2` tolerate two failed shards/disks per stripe.
- Per-shard SHA-256 verification and raw-stripe SHA-256 validation.
- Automatic read reconstruction, deferred self-heal when replacement capacity is
  unavailable, and `fsck`/`scrub` repair when enough online disks exist.
- Dynamic add-disk, drain/remove-disk, and weighted rebalance.
- Heterogeneous disk placement through weighted, tier-aware rendezvous hashing.
- Automatic disk probing for SSD/HDD/NVMe class, measured read/write
  performance, recommended tier, recommended weight, real capacity, and backing
  block device when sysfs exposes it.
- Hard capacity enforcement: disks with insufficient free ArgosFS shard capacity
  are excluded from placement, and shard writes fail with `ENOSPC` before
  exceeding the recorded capacity.
- Real SMART refresh through `smartctl -j -a` when a backing block device is
  available; SMART counters feed the same health and autopilot risk model.
- Dynamic I/O latency feedback: shard reads/writes update per-disk latency EWMA
  and observed throughput, and placement penalizes slow disks automatically.
- Advanced I/O policy controls: buffered I/O, `O_DIRECT` with safe buffered
  fallback for unaligned requests, `io_uring` with buffered fallback when the
  kernel denies setup, mmap zero-copy read staging, FUSE direct-I/O open flags,
  and NUMA-aware placement preference when sysfs exposes disk node locality.
- Transparent per-stripe compression with `zstd`, `lz4`, or `none`.
- Built-in Prometheus exporter at `/metrics`.
- Persistent metadata with copy-on-write JSON commits, journal, audit-friendly
  operation records, and named metadata snapshots.
- RAM + persistent L2 block cache.
- Health scoring from SMART-like counters, predicted failure detection, disk
  draining, repair, rebalancing, and `autopilot`.
- Root filesystem integration assets for initramfs and systemd.
- Comprehensive Rust tests and `paper-data/` validation output for later papers.

## Build

Install the required system packages:

```bash
sudo apt-get install -y build-essential pkg-config libfuse3-dev fuse3 smartmontools
curl https://sh.rustup.rs -sSf | sh -s -- -y --profile minimal
. "$HOME/.cargo/env"
```

Build and test:

```bash
cargo build
cargo test
```

## Quick Start

Create a `4+2` ArgosFS volume:

```bash
cargo run -- mkfs /var/lib/argosfs/root --disks 6 --k 4 --m 2 --compression zstd
```

Import a root tree:

```bash
sudo cargo run -- import-tree /var/lib/argosfs/root /path/to/rootfs /
```

Mount it:

```bash
sudo cargo run -- mount /var/lib/argosfs/root /mnt/argos-root --foreground
```

Use it like a normal filesystem:

```bash
sudo chroot /mnt/argos-root /bin/sh
```

Run repair and health automation:

```bash
cargo run -- fsck /var/lib/argosfs/root --repair --remove-orphans
cargo run -- health /var/lib/argosfs/root --json
cargo run -- autopilot /var/lib/argosfs/root --once
```

## CLI

```bash
argosfs mkfs ROOT --disks 6 --k 4 --m 2 --compression zstd
argosfs mount ROOT MOUNTPOINT --foreground -o allow_other
argosfs import-tree ROOT SOURCE_DIR /
argosfs export-tree ROOT DEST_DIR
argosfs put ROOT LOCAL_FILE /path/in/fs
argosfs get ROOT /path/in/fs LOCAL_FILE
argosfs cat ROOT /path/in/fs
argosfs mkdir ROOT /dir --mode 755
argosfs mknod ROOT /dev/null --mode 020666 --rdev 259
argosfs symlink ROOT /target /link
argosfs rename ROOT /old /new
argosfs chmod ROOT /path 644
argosfs truncate ROOT /path 0
argosfs add-disk ROOT --path /mnt/nvme0 --rebalance
argosfs add-disk ROOT --tier hot --weight 2.0 --capacity-bytes 1000000000000 --rebalance
argosfs probe-disks ROOT
argosfs refresh-smart ROOT
argosfs remove-disk ROOT disk-0003
argosfs mark-disk ROOT disk-0002 failed
argosfs set-health ROOT disk-0001 --pending-sectors 12 --latency-ms 140
argosfs fsck ROOT --repair --remove-orphans
argosfs scrub ROOT
argosfs rebalance ROOT
argosfs autopilot ROOT --interval 60
argosfs snapshot ROOT before-upgrade
argosfs enable-encryption ROOT --key-file /etc/argosfs.key --reencrypt
argosfs encryption-status ROOT
argosfs set-io-mode ROOT --mode io-uring
argosfs set-io-mode ROOT --mode direct --direct-io
argosfs prometheus ROOT --listen 127.0.0.1:9108
argosfs set-posix-acl ROOT /etc/shadow 'user::rw-,group::---,mask::---,other::---'
argosfs get-posix-acl ROOT /etc/shadow
argosfs set-nfs4-acl ROOT /srv/data @nfs4-acl.json
argosfs get-nfs4-acl ROOT /srv/data
```

`add-disk` defaults to automatic probing. Pass `--tier`, `--weight`, or
`--capacity-bytes` only when you want to override the probe result. Modes accept
decimal, octal (`755` or `0o755`), and hex (`0x...`) syntax.

Encryption reads the key from `ARGOSFS_KEY` or `ARGOSFS_KEY_FILE` during normal
operation. `enable-encryption --reencrypt` rewrites existing file stripes so
old data becomes encrypted at rest; new writes are encrypted immediately after
encryption is enabled. `set-io-mode` persists the data-plane policy in volume
metadata, and `--direct-io` also asks FUSE clients to use direct I/O handles.

## Root Filesystem Use

ArgosFS can be mounted as a Linux root filesystem through initramfs:

1. Build and install the static or dynamically linked `argosfs` binary into the
   initramfs image.
2. Include libfuse3 and `/dev/fuse` support.
3. Run `argosfs fsck ROOT --repair --remove-orphans`.
4. Mount with `argosfs mount ROOT /newroot --foreground`.
5. `switch_root /newroot /sbin/init`.

See `docs/rootfs.md`, `docs/boot.md`, and `contrib/` for templates.

## Validation Data

Run the retained validation workflow:

```bash
python3 scripts/run_full_validation.py --output paper-data/runs/manual
```

The run directory contains:

- deterministic input datasets,
- the generated ArgosFS volume,
- command logs,
- JSON health/fsck/autopilot/rebalance reports,
- CSV timing samples,
- a manifest with build, kernel, and ArgosFS configuration.

## Limitations

ArgosFS is a complete research filesystem project with a real FUSE frontend, but
it is not yet a production-certified kernel filesystem. The current metadata
store is a single-node COW JSON database. That makes experiments transparent and
auditable; a production version should replace it with a page/B-tree store and
add journal replay fuzzing, xfstests coverage, and long-duration power-failure
testing.
