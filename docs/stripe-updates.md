# Stripe-Level Updates

Range writes and truncation now preserve unaffected stripe records and rewrite
only the affected stripe window. This reduces write amplification for random
writes, appends, and truncates while keeping Reed-Solomon shard validation
unchanged.

The current implementation still reconstructs the file image before planning
the stripe rewrite. That keeps correctness simple and preserves encryption and
compression behavior. The next optimization step is a writeback buffer that
coalesces adjacent FUSE writes before encoding.
