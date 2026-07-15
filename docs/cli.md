# Command-Line Interface

ArgosFS has two volume selection models:

- **Host backend:** pass the volume directory as the positional `ROOT` argument.
- **Loop/raw backend:** pass `--images`, `--devices`, or a reusable `--pool-config` file.

The CLI rejects mixed selectors instead of silently ignoring them. In particular:

- `ROOT` cannot be combined with loop/raw image or device selectors.
- `--images` and `--devices` are mutually exclusive.
- `--backend host` cannot be combined with `--images` or `--devices`.
- `--image-size` is valid only when creating a loop image.
- `--disks` is valid only when creating a host-backend volume.

When `--backend` is omitted, `--images` selects the loop backend and `--devices`
selects the raw backend.

## Reusable pool selector

A JSON pool configuration avoids repeating a long device list for every
operation:

```json
{
  "backend": "raw",
  "devices": [
    "/dev/disk/by-id/wwn-0x5000...001",
    "/dev/disk/by-id/wwn-0x5000...002",
    "/dev/disk/by-id/wwn-0x5000...003"
  ],
  "pool": "capos-root"
}
```

Use it with any block-backed management command:

```bash
argosfs inspect-pool --pool-config /etc/argosfs/root-pool.json
argosfs fsck --pool-config /etc/argosfs/root-pool.json --repair
argosfs mount-root --pool-config /etc/argosfs/root-pool.json --target /sysroot
```

Relative image or device paths are resolved relative to the directory containing
the JSON file. Direct command-line paths replace paths from the configuration
file. An explicit `--backend` overrides the configured backend, but incompatible
path types are rejected. An explicit `--pool` overrides the configured pool
identity.

The `pool` field is an identity check: ArgosFS refuses to operate when the opened
pool UUID or stored pool name does not match it.

## Sizes

Size arguments accept plain bytes and human-readable suffixes:

```text
64MiB  2GiB  1TiB  500MB  4_096KiB
```

Binary suffixes (`KiB`, `MiB`, `GiB`, `TiB`) use powers of 1024. Decimal suffixes
(`KB`, `MB`, `GB`, `TB`) use powers of 1000.

## Output contract

`--json` is a global option and can be placed before or after the subcommand.
Commands intended for direct listing, such as `health`, `scan`, and `ls`, use a
human-readable form by default and switch to JSON with `--json`.

Commands that historically emitted structured reports continue to emit JSON
when stdout is redirected, preserving scripts and CI artifacts. On an interactive
terminal, large health, fsck, journal, and root-preflight reports are summarized;
pass `--json` to print the complete report.

Commands such as `cat` write their payload directly. Mutating commands that do
not have a useful result follow normal Unix behavior and indicate success with a
zero exit status.

## Command discovery

```bash
argosfs --help
argosfs help mkfs
argosfs help mount-root
argosfs --version
```

Top-level help includes functional command groups while retaining the existing
command names for compatibility with service files and scripts.
