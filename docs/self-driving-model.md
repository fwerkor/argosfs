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

## Policy

User intent is kept separate from observed device state. If
`.argosfs/autopilot-policy.json` exists, `argosfs autopilot ROOT` loads it before
planning; `--policy PATH` can point at an explicit JSON policy file. Invalid
policy values fail closed before any maintenance action runs.

Example:

```json
{
  "mode": "safe",
  "max_drains_per_day": 1,
  "allow_degraded_boot": true,
  "background_io": {
    "max_read_mib_s": 50.0,
    "max_write_mib_s": 30.0,
    "target_foreground_p99_ms": 20.0,
    "pause_if_foreground_p99_ms": 80.0,
    "pause_if_loadavg_gt": 4.0
  },
  "placement": {
    "boot_critical_tier": "hot",
    "min_boot_copies": 2,
    "failure_domain_aware": true
  },
  "paths": {
    "boot_critical": ["/boot", "/etc", "/usr/lib/systemd", "/sbin", "/bin"],
    "cold_candidates": ["/var/cache", "/var/log/journal"]
  }
}
```

## Actions

- probe disks without applying capacity overrides
- refresh SMART counters when `smartctl -j` is available
- drain predicted-failure disks after safety checks
- run incremental scrub
- run policy-throttled scrub, drain, and rebalance under background I/O budgets
- verify every mutation batch with fsck

Background I/O controls apply per autopilot run. The planner combines configured
read/write MiB/s caps, observed foreground latency, optional load-average pause
thresholds, and the adaptive budget model to lower or pause scrub, drain, and
rebalance work. Each run records the chosen effective budget and pause reason in
`planner.background_io.throttle_decisions`, and the same JSON is appended to
`.argosfs/autopilot.jsonl`.

## Explain Mode

`argosfs autopilot ROOT --dry-run --explain --json` emits decision records with
observations, candidate actions, rejected actions, safety checks, and expected
utility. The output also includes the active policy and background I/O throttle
decisions. Dry-run mode does not mutate metadata, shards, the journal, or
autopilot state.
