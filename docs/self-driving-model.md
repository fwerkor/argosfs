# Self-Driving Control Model

ArgosFS models autonomy as a bounded storage control loop:

```text
Observe -> Diagnose -> Plan -> Check Safety Invariants -> Act -> Verify -> Freeze or Downgrade
```

## Observations

- disk class, capacity source, backing filesystem identity, failure domain, and NUMA locality
- SMART parser type, last refresh time, observed SMART fields, and missing fields
- latency EWMA and observed throughput from foreground shard reads and writes
- capacity pressure from metadata-maintained shard byte counters
- inode workload score, storage tier, and boot-critical classification
- fsck, scrub, drain, and rebalance results

## Planner State

The autopilot stores persistent risk memory in `.argosfs/autopilot-state.json`.
Risk must be confirmed across runs unless it crosses the critical threshold.
Repeated failures move the planner into a reduced adaptive mode, which lowers
background work budgets.

## Actions

- probe disks without applying capacity overrides
- refresh SMART counters when `smartctl -j` is available
- drain predicted-failure disks after safety checks
- run incremental scrub
- run latency-throttled rebalance
- verify every mutation batch with fsck

## Explain Mode

`argosfs autopilot ROOT --dry-run --explain --json` emits decision records with
observations, candidate actions, rejected actions, safety checks, and expected
utility. Dry-run mode does not mutate metadata, shards, the journal, or
autopilot state.
