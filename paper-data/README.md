# ArgosFS Paper Data

This directory is reserved for retained experiment artifacts used by the
ArgosFS validation workflow.

Recommended command:

```bash
python scripts/run_full_validation.py --output paper-data/runs/manual
```

Each run stores:

- deterministic input datasets,
- the generated ArgosFS volume,
- JSON summaries for recovery, rebalance, health, cache, and benchmark phases,
- ACL, encryption, advanced-I/O, and Prometheus behavior can be captured by
  adding CLI command logs beside the generated JSON summaries,
- CSV latency/throughput samples,
- a validation-only encryption key file when encryption is enabled for the run,
- a manifest with software and configuration details.

The directory is intentionally kept in the repository so later research writing
can refer to stable data locations instead of ad-hoc temporary files.
