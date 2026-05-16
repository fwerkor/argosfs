# Safety Invariants

ArgosFS mutation actions must preserve these invariants:

1. Committed file data keeps at least `k` recoverable shards per stripe.
2. Metadata transaction ids are monotonic and hash chained.
3. A failed or offline disk is never selected for new shard placement.
4. User capacity overrides are never replaced by later probes.
5. Colocated auto-probed disk directories share one backing capacity budget.
6. Boot-critical data is classified explicitly and prefers hot, diverse failure domains.
7. Sticky directories only allow removal by root, the directory owner, or the entry owner.
8. Protected xattr namespaces are denied unless ArgosFS has an explicit handler.
9. Autopilot mutation batches are followed by verification; failures downgrade future work.

Freeze or reduced-mode conditions include metadata conflicts, insufficient online
disks, failed verification, confirmed SMART uncertainty, and foreground latency
above the configured target.
