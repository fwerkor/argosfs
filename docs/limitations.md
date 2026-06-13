# Limitations

ArgosFS rootfs support is currently implemented as a FUSE filesystem, not a
Linux kernel filesystem. The initramfs must include the daemon, libfuse3 runtime
libraries, and kernel FUSE support. The daemon must be started before
`switch_root` and kept alive after handoff.

The loop/raw backend now uses real block offsets and raw metadata regions, but
the first production hardening pass is still needed before using it for
irreplaceable data. In particular:

- QEMU boot and destructive raw-device tests require a privileged environment.
- Performance is not expected to match mature kernel filesystems.
- Raw checkpoint bodies are page-indexed and hash-checked, but the logical
  metadata object is still serialized as JSON. Raw journal replay uses full
  metadata records in this version.
- Device replacement and rebalance are inherited from the host-era control path
  and should be exercised carefully for raw pools.
- Degraded readonly rootfs is covered for missing loop images. Degraded rw must
  be explicitly selected and still requires enough online placement capacity for
  new writes.
- The CapOS image rule emits a loop-backed ArgosFS root pool artifact for the
  image builder; target-specific boot media still needs to pass the resulting
  member images or raw devices through the kernel command line.

HostFsBackend remains supported for development and compatibility. It is not the
recommended CapOS rootfs backend.
