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
        summary["workload_shift"] = {
            "samples": len(rows),
            "mean_hot_tier_fraction": statistics.fmean(hot) if hot else 0.0,
        }

    (processed / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    with (tables / "overview.csv").open("w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["artifact", "records"])
        for key, value in summary.items():
            writer.writerow([key, len(value) if isinstance(value, list) else value.get("samples", 0)])

    (figures / "README.md").write_text(
        "Figures are generated from processed JSON/CSV by paper-specific plotting scripts.\n"
    )


if __name__ == "__main__":
    main()
