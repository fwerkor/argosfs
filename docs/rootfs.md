# ArgosFS Root Filesystem Guide

This guide describes how to use ArgosFS as an experimental Linux root
filesystem.

## Build an ArgosFS Root

```bash
cargo build --release
sudo install -m 0755 target/release/argosfs /usr/local/sbin/argosfs
sudo argosfs mkfs /var/lib/argosfs/root --disks 6 --k 4 --m 2 --compression zstd
sudo argosfs import-tree /var/lib/argosfs/root /srv/rootfs /
sudo argosfs probe-disks /var/lib/argosfs/root
sudo argosfs refresh-smart /var/lib/argosfs/root || true
sudo argosfs set-io-mode /var/lib/argosfs/root --mode io-uring
sudo argosfs fsck /var/lib/argosfs/root --repair --remove-orphans
```

`import-tree` preserves directories, regular files, symlinks, ownership,
permissions, and special nodes where the caller has permission to read/create
them.

To encrypt the root filesystem at rest, create a key file in the initramfs trust
boundary and rewrite existing stripes:

```bash
sudo install -m 0600 /dev/stdin /etc/argosfs.key
sudo argosfs enable-encryption /var/lib/argosfs/root --key-file /etc/argosfs.key --reencrypt
```

## Manual Boot Test

```bash
sudo mkdir -p /mnt/argos-root
sudo argosfs mount /var/lib/argosfs/root /mnt/argos-root --foreground -o allow_other
sudo chroot /mnt/argos-root /bin/sh
```

## initramfs Contract

An initramfs image must contain:

- `/usr/local/sbin/argosfs`,
- libfuse3 runtime libraries,
- `/dev/fuse` support in the kernel,
- the ArgosFS volume root or a way to discover it,
- `ARGOSFS_KEY_FILE` or `ARGOSFS_KEY` when volume encryption is enabled,
- a small script that runs repair, mounts ArgosFS at `/newroot`, then calls
  `switch_root`.

Minimal flow:

```bash
modprobe fuse || true
export ARGOSFS_KEY_FILE=/etc/argosfs.key
argosfs fsck "$ARGOSFS_ROOT" --repair --remove-orphans
argosfs mount "$ARGOSFS_ROOT" /newroot --foreground -o allow_other &
exec switch_root /newroot /sbin/init
```

## Operational Notes

- Run `argosfs autopilot ROOT --interval 60` as a long-running service.
- Add replacement devices with `argosfs add-disk ROOT --path /mnt/device --rebalance`.
  The command automatically probes SSD/HDD/NVMe class, real capacity, measured
  performance, and recommended tier/weight unless overridden.
- Use `argosfs refresh-smart ROOT` when `smartctl` is available to import real
  SMART/NVMe health counters.
- Use `argosfs prometheus ROOT --listen 127.0.0.1:9108` for node-local
  Prometheus scraping.
- Use `argosfs set-posix-acl` and `argosfs set-nfs4-acl` to pre-seed rootfs ACL
  policy before booting the image.
- Mark bad devices with `argosfs mark-disk ROOT disk-XXXX failed`.
- Use `argosfs scrub ROOT` after unclean shutdowns or device replacement.
