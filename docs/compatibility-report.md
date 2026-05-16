# Filesystem Compatibility Report

ArgosFS compatibility is tracked in stable, machine-readable outputs:

- `scripts/compat/run_fuse_smoke.sh` covers mounted read/write/chmod/truncate.
- `scripts/compat/run_mounted_fuse_compat.sh` covers real mounted-FUSE behavior
  through normal Unix syscalls.
- `scripts/compat/run_pjdfstest.sh` records pjdfstest subset status when the
  suite is available and skips cleanly otherwise.
- xfstests-style generic testing is documented for local privileged runs in
  `docs/testing.md`.

## Current Classification

| Area | Status | Notes |
| --- | --- | --- |
| lookup/getattr/read/write/create | passed | Covered by Rust integration tests and mounted FUSE scripts. |
| chmod/chown/truncate/utimens | passed/skipped by permission | Mounted checks validate chmod, truncate, utimens/stat, and permitted chown. |
| xattrs/ACLs | passed with limits | `user.*` and ArgosFS-managed `system.*` ACL names are supported; protected namespaces are rejected. |
| rename flags | passed/skipped by kernel | Mounted checks validate overwrite and `RENAME_NOREPLACE` when `renameat2` is available. |
| sticky directories | passed/skipped by uid support | Sticky bit setup is always checked; cross-user denial requires uid switching. |
| non-UTF-8 names | passed through mounted FUSE | Python bytes paths validate create, readdir, and read. |
| concurrent readers/writers | passed through mounted FUSE | Multiple processes read while writers append and fsync. |
| pjdfstest subset | optional local/CI artifact | The wrapper runs only on confirmed mountpoints and records pass/fail/skip JSONL. |
| xfstests full generic suite | local-run only | Full xfstests needs privileged scratch-device support unavailable in default CI. |

Unsupported cases should be linked to follow-up issues instead of being merged
into a generic failure bucket.
