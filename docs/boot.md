# Boot and Service Integration

ArgosFS is a Rust userspace filesystem with a FUSE mount frontend. The supported
root-filesystem path uses a loop/raw pool, root preflight, journal recovery, and
initramfs integration.

## Pool configuration

Keep the backend, device paths, and expected pool identity in one file rather
than repeating them in every service:

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

Store it as `/etc/argosfs/root-pool.json` in the initramfs trust boundary.

## Generic initramfs flow

1. Install the `argosfs` binary and libfuse3 runtime dependencies.
2. Load FUSE and make the selected devices available.
3. Replay and check the pool.
4. Run root preflight for the requested mode.
5. Mount at the new root and call `switch_root`.

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

The CapOS integration additionally supports device autoscan, kernel command-line
selection, recovery modes, emergency shells, and runtime mount preparation. See
`docs/capos-rootfs.md` and `integrations/capos/`.

## Host-backend autopilot example

`autopilot` currently operates on a host-backend volume directory. It is not the
root-pool selector used by `mount-root`:

```ini
[Unit]
Description=ArgosFS host-volume autopilot
After=local-fs.target

[Service]
Type=simple
ExecStart=/usr/local/sbin/argosfs autopilot /var/lib/argosfs/dev-volume --interval 60
Restart=always

[Install]
WantedBy=multi-user.target
```
