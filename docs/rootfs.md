# ArgosFS Root Filesystem Guide

ArgosFS supports two distinct deployment models:

- **Loop/raw pools** are the supported root-filesystem path. They use
  `mount-root`, root preflight, journal replay, and the initramfs integration.
- **Host volumes** store shards in ordinary directories and are intended for
  development and compatibility testing. They use the simpler `mount ROOT`
  command and host-only tools such as `autopilot` and `add-disk`.

Do not mix a positional host `ROOT` with loop/raw selectors. The CLI rejects
such combinations.

## Build a block-backed root pool

```bash
cargo build --release
sudo install -m 0755 target/release/argosfs /usr/local/sbin/argosfs
sudo install -d -m 0755 /etc/argosfs
```

Create `/etc/argosfs/root-pool.json`. Real deployments should use stable
`/dev/disk/by-id` paths:

```json
{
  "backend": "raw",
  "devices": [
    "/dev/disk/by-id/wwn-device-0",
    "/dev/disk/by-id/wwn-device-1",
    "/dev/disk/by-id/wwn-device-2"
  ],
  "pool": "system-root"
}
```

Format and populate the pool:

```bash
sudo argosfs mkfs --pool-config /etc/argosfs/root-pool.json \
  --k 2 --m 1 --compression zstd
sudo argosfs import-tree --pool-config /etc/argosfs/root-pool.json \
  /srv/rootfs /
sudo argosfs fsck --pool-config /etc/argosfs/root-pool.json \
  --repair --remove-orphans
sudo argosfs preflight-root --pool-config /etc/argosfs/root-pool.json \
  --mode rw --json
```

For image-based testing, set `backend` to `loop` and replace `devices` with an
`images` array. Relative image paths are resolved relative to the pool
configuration file.

`import-tree` preserves directories, regular files, symlinks, ownership,
permissions, hardlinks, xattrs, and special nodes where the caller has the
required privileges.

## Manual mount test

The imported tree must contain `/dev`, `/proc`, `/run`, and `/sys` directories
before normal root preflight succeeds.

```bash
sudo mkdir -p /mnt/argos-root
sudo argosfs preflight-root --pool-config /etc/argosfs/root-pool.json \
  --mode rw
sudo argosfs mount-root --pool-config /etc/argosfs/root-pool.json \
  --target /mnt/argos-root --mode rw --foreground
```

Run the mount command in a dedicated terminal or service, then enter the root:

```bash
sudo chroot /mnt/argos-root /bin/sh
```

## initramfs contract

An initramfs image must contain:

- the `argosfs` binary and libfuse3 runtime libraries;
- `/dev/fuse` support in the kernel and initramfs device tree;
- a stable way to discover all loop images or raw devices;
- the encryption key source when encryption is enabled;
- logic that replays, checks, preflights, mounts, and calls `switch_root`.

A generic block-backed flow is:

```bash
modprobe fuse || true
argosfs replay-journal --pool-config /etc/argosfs/root-pool.json
argosfs fsck --pool-config /etc/argosfs/root-pool.json \
  --repair --remove-orphans
argosfs preflight-root --pool-config /etc/argosfs/root-pool.json --mode rw
argosfs mount-root --pool-config /etc/argosfs/root-pool.json \
  --target /newroot --mode rw --foreground &
exec switch_root /newroot /sbin/init
```

CapOS uses the more complete discovery and emergency-recovery implementation in
`integrations/capos/initramfs/argosfs-root.sh`; see `docs/capos-rootfs.md`.

## Operations

Use the same pool selector for all block-backed operations:

```bash
argosfs inspect-pool --pool-config /etc/argosfs/root-pool.json
argosfs list-devices --pool-config /etc/argosfs/root-pool.json
argosfs fsck --pool-config /etc/argosfs/root-pool.json
argosfs scrub --pool-config /etc/argosfs/root-pool.json
argosfs verify-journal --pool-config /etc/argosfs/root-pool.json
```

`preflight-root` reports stable issue codes and a recommended fallback mode.
Plain `rw` fails closed when required devices are missing. Use `degraded-ro` for
a conservative degraded boot, or explicit `degraded-rw` only when the operator
accepts the additional risk.

## Host-backend compatibility mode

For local development without block images:

```bash
argosfs mkfs /var/lib/argosfs/dev-root --disks 1 --k 1 --m 0
argosfs import-tree /var/lib/argosfs/dev-root /srv/rootfs /
argosfs mount /var/lib/argosfs/dev-root /mnt/argos-root --foreground
```

Host-only storage automation uses `add-disk`, `probe-disks`, `refresh-smart`, and
`autopilot`. These commands are intentionally separate from block-pool device
lifecycle commands.
