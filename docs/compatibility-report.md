# Filesystem Compatibility Report

ArgosFS compatibility is tracked in stable, machine-readable outputs:

- `scripts/compat/run_fuse_smoke.sh` covers mounted read/write/chmod/truncate.
- `scripts/compat/run_pjdfstest.sh` records pjdfstest status when the suite is available.
- Future xfstests subsets should emit JSONL records under `paper-data/compat/`.

## Current Classification

| Area | Status | Notes |
| --- | --- | --- |
| lookup/getattr/read/write/create | passed | Covered by Rust integration tests and FUSE smoke script. |
| chmod/chown/truncate/utimens | passed | FUSE setattr now splits permission rules by operation. |
| xattrs/ACLs | passed with limits | `user.*` and ArgosFS-managed `system.*` ACL names are supported; protected namespaces are rejected. |
| rename flags | passed | `RENAME_NOREPLACE` and `RENAME_EXCHANGE` are handled; whiteout is rejected. |
| sticky directories | passed | Removal and replacement honor sticky directory owner rules. |
| non-UTF-8 names | passed through FUSE APIs | Names are stored with reversible byte encoding internally. |
| xfstests full generic suite | not yet investigated | Use the JSONL report path for selected future cases. |

Unsupported cases should be linked to follow-up issues instead of being merged
into a generic failure bucket.
