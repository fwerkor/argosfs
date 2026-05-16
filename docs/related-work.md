# Related Work

## Self-Managing Storage

HP AutoRAID, Minerva, Hippodrome, Polus, and later self-* storage systems show
that storage layout can be tuned automatically from observations and workload
models. They establish the value of automation, but generally target arrays,
enterprise controllers, or provisioning workflows rather than a rootfs-capable
local FUSE filesystem with explicit safety gates.

## Automated Tiering

Octopus++, enterprise tiering engines, dm-cache, bcache, and Stratis-like stacks
move data across tiers or compose block devices. ArgosFS overlaps with those
systems in workload-aware placement, but places decisions at the file/shard
layer and exposes dry-run decision records for reproducible experiments.

## Local Multi-Disk Filesystems

Btrfs, ZFS, bcachefs, mdadm/LVM, mergerfs, SnapRAID, and Unraid-like layouts
cover mature parts of the design space: redundancy, snapshots, pooling, and
homelab-friendly disk aggregation. ArgosFS does not claim to replace their
production maturity. Its narrower novelty is:

```text
safety-constrained self-driving control for a rootfs-capable heterogeneous local multi-disk filesystem
```

## Autonomous Databases

Peloton, NoisePage, Tiresias, and self-driving DBMS work demonstrate closed-loop
physical design and resource management. ArgosFS borrows the inspectable
observe-plan-act framing but applies it to filesystem placement, repair, and
boot-critical safety.
