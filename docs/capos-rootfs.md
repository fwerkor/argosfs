# CapOS ArgosFS Root Filesystem

CapOS uses ArgosFS as the runtime `/` filesystem. `/boot` or the EFI System
Partition may remain a normal bootloader-readable filesystem; `/usr`, `/etc`,
`/var`, `/home`, `/srv`, `/opt`, and the rest of runtime `/` are imported into
an ArgosFS pool.

## Build Flow

The CapOS package definition references:

```text
https://github.com/fwerkor/argosfs
```

It does not use a local `../argosfs` path. CapOS adds `TARGET_ROOTFS_ARGOSFS`
and makes it the default rootfs image type, selecting `argosfs`, `kmod-fuse`,
`libfuse3`, and `fuse3-utils`.
The package source URL is the GitHub repository, not a local relative checkout.

The image builder creates a loop-backed ArgosFS pool and imports the prepared
CapOS root tree with build-time batching enabled by default:

```bash
argosfs mkfs --backend loop --images disk0.img --k 1 --m 0 \
  --defer-journal-flush --defer-metadata-commit --defer-data-flush \
  --deferred-commit-interval-ms 5000 \
  --deferred-commit-max-transactions 128
argosfs import-tree --backend loop --images disk0.img ROOT /
```

Bulk import commits once after the prepared tree has been copied. At runtime,
the same volume uses bounded group commit rather than an unbounded in-memory
batch: the FUSE frontend commits at least every five seconds or 128 metadata
transactions, whichever comes first. Application `fsync`/`fdatasync` and
synchronous opens remain immediate durability boundaries. Replaced extents are
not reused until their replacement metadata is durable.

The resulting rootfs still goes through the normal preflight/fsck boundary
before it is mounted.

The single-device image can evolve online into redundant layouts as devices are
added:

```bash
argosfs add-device --backend loop --images disk0.img --device disk1.img
argosfs reshape --backend loop --images disk0.img,disk1.img --k 1 --m 1
```

## initramfs Flow

`integrations/capos/initramfs/argosfs-root.sh`:

1. mounts `/proc`, `/sys`, `/dev`, and `/run`;
2. loads `fuse`;
3. parses `argosfs.pool`, `argosfs.devices`, `argosfs.images`,
   `argosfs.mode`, `argosfs.root`, `argosfs.debug`, `argosfs.replay`, and
   `argosfs.fsck`;
4. runs `argosfs scan`;
5. validates the requested `argosfs.pool` name or UUID on replay/fsck/preflight
   and mount commands;
6. replays the journal unless disabled;
7. runs pre-mount fsck according to policy;
8. runs `preflight-root`;
9. mounts ArgosFS at `/sysroot`;
10. verifies an init exists;
11. calls `switch_root` or drops to emergency shell on failure.

CI can validate the logic without privileges:

```bash
scripts/tests/host/initramfs_dry_run.sh
```

## Kernel Command Line

Example:

```text
argosfs.images=/boot/disk0.img argosfs.mode=rw argosfs.root=/sysroot argosfs.replay=auto argosfs.fsck=auto
```

For real block devices use `argosfs.devices=/dev/disk/by-id/...`.

## Recovery and Watchdog Assets

The repository provides CapOS-targeted systemd assets under
`integrations/capos/systemd/`. They prefer the shared
`/etc/argosfs/root-pool.json` selector and retain `ARGOSFS_BACKEND` plus
`ARGOSFS_DEVICES` as a compatibility fallback:

- `argosfs-root.service` verifies the opened root pool after switch-root.
- `argosfs-health.service` runs a readonly fsck health check.
- `argosfs-watchdog.service` periodically reruns readonly root preflight.
- `argosfs-recovery.target` isolates into emergency recovery mode.

Rootfs mode is conservative: plain `rw` is rejected when devices are missing;
use `degraded-ro` for readonly degraded boot or explicit `degraded-rw` when
operators accept the risk. `recovery` maps to a readonly mount. `preflight-root`
prints a machine-readable report before returning failure, including stable
issue codes and a recommended fallback mode for initramfs logs and watchdog
alerts.
