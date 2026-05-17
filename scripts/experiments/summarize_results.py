#!/usr/bin/env python3
import csv
import json
import pathlib
import statistics
import sys


def read_jsonl(path):
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def main():
    raw = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else "paper-data/raw")
    out = pathlib.Path(sys.argv[2] if len(sys.argv) > 2 else "paper-data")
    processed = out / "processed"
    figures = out / "figures"
    tables = out / "tables"
    processed.mkdir(parents=True, exist_ok=True)
    figures.mkdir(parents=True, exist_ok=True)
    tables.mkdir(parents=True, exist_ok=True)

    summary = {
        "failure_matrix": read_jsonl(raw / "failure-matrix.jsonl"),
        "baselines": read_jsonl(raw / "baselines.jsonl"),
        "qemu_rootfs": read_jsonl(raw / "qemu-rootfs.jsonl"),
    }

    workload = raw / "workload-shift.csv"
    if workload.exists():
        with workload.open() as f:
            rows = list(csv.DictReader(f))
        hot = [float(row["hot_tier_fraction"]) for row in rows]
        p95 = [float(row["foreground_p95_ms"]) for row in rows]
        summary["workload_shift"] = {
            "samples": len(rows),
            "mean_hot_tier_fraction": statistics.fmean(hot) if hot else 0.0,
            "mean_foreground_p95_ms": statistics.fmean(p95) if p95 else 0.0,
        }

    metadata = raw / "metadata-scalability.csv"
    if metadata.exists():
        with metadata.open() as f:
            rows = list(csv.DictReader(f))
        summary["metadata_scalability"] = {
            "samples": len(rows),
            "max_files": max((int(row["files"]) for row in rows), default=0),
            "max_meta_bytes": max((int(row["meta_bytes"]) for row in rows), default=0),
        }

    (processed / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    with (tables / "overview.csv").open("w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["artifact", "records"])
        for key, value in summary.items():
            writer.writerow([key, len(value) if isinstance(value, list) else value.get("samples", 0)])

    with (tables / "failure-matrix.csv").open("w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["scenario", "runs", "passed", "failed"])
        scenarios = sorted({row["scenario"] for row in summary["failure_matrix"]})
        for scenario in scenarios:
            rows = [row for row in summary["failure_matrix"] if row["scenario"] == scenario]
            writer.writerow(
                [
                    scenario,
                    len(rows),
                    sum(1 for row in rows if row.get("status") == "passed"),
                    sum(1 for row in rows if row.get("status") == "failed"),
                ]
            )

    with (figures / "workload-shift.tsv").open("w", newline="") as f:
        writer = csv.writer(f, delimiter="\t")
        writer.writerow(["phase", "foreground_p95_ms", "hot_tier_fraction", "rebalance_files"])
        if workload.exists():
            with workload.open() as rows_f:
                for row in csv.DictReader(rows_f):
                    writer.writerow(
                        [
                            row["phase"],
                            row["foreground_p95_ms"],
                            row["hot_tier_fraction"],
                            row["rebalance_files"],
                        ]
                    )


if __name__ == "__main__":
    main()
