# Stripe-Level Updates

Range writes and truncation now preserve unaffected stripe records and rewrite
only the affected stripe window. This reduces write amplification for random
writes, appends, and truncates while keeping Reed-Solomon shard validation
unchanged.

The current implementation still reconstructs the file image before planning
the stripe rewrite. That keeps correctness simple and preserves encryption and
compression behavior.

FUSE mounts now have a first-stage per-inode writeback buffer. Small adjacent
or overlapping writes are merged in memory and flushed on read, getattr,
fsync/release, statfs, directory mutations, and daemon shutdown. Direct I/O and
large writes still bypass the buffer. The core `ArgosFs` API remains synchronous,
so CLI/import/export and the crash-test surface keep their existing semantics
while FUSE small-write workloads avoid encoding and committing every tiny chunk.
