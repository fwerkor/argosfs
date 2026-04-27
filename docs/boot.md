# Boot and Service Integration

ArgosFS is a Rust userspace filesystem with a real FUSE mount frontend. Root
filesystem boot support uses the same pieces a production deployment needs: a
mount helper, a repair command, an autopilot service, and initramfs integration.

## systemd Example

```ini
[Unit]
Description=ArgosFS Autopilot
After=local-fs.target

[Service]
Type=simple
ExecStart=/usr/local/sbin/argosfs autopilot /var/lib/argosfs/root --interval 60
Restart=always

[Install]
WantedBy=multi-user.target
```

## initramfs Flow

1. Load Python runtime and the `argosfs` package into the image.
2. Run `argosfs fsck /argos-volume --repair`.
3. Run the selected mount frontend for `/argos-volume`.
4. Switch root to the mounted view.

```bash
modprobe fuse || true
argosfs probe-disks /argos-volume || true
argosfs refresh-smart /argos-volume || true
argosfs fsck /argos-volume --repair --remove-orphans
argosfs mount /argos-volume /newroot --foreground -o allow_other &
exec switch_root /newroot /sbin/init
```
