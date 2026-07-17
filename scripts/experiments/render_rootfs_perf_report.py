#!/usr/bin/env python3
"""Render repeated rootfs microbenchmarks as Markdown and CSV."""

from __future__ import annotations

import argparse
import csv
import json
import statistics
from collections import defaultdict
from pathlib import Path
from typing import Any

METRICS = (
    ("large_write_mib_s", "Large write", "MiB/s"),
    ("large_read_mib_s", "Large read", "MiB/s"),
    ("small_create_files_s", "Small create", "files/s"),
    ("small_stat_files_s", "Small stat", "files/s"),
)
SCENARIO_ORDER = (
    "argosfs-loop-fuse-strict",
    "argosfs-loop-fuse-deferred",
    "argosfs-loop-fuse-batched",
    "ext4-loop",
    "host-directory",
)
SCENARIO_LABELS = {
    "argosfs-loop-fuse-strict": "ArgosFS strict",
    "argosfs-loop-fuse-deferred": "ArgosFS deferred journal",
    "argosfs-loop-fuse-batched": "ArgosFS batched metadata/data",
    "ext4-loop": "ext4 loop baseline",
    "host-directory": "Runner host filesystem",
}


def read_records(path: Path) -> list[dict[str, Any]]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def median(values: list[float]) -> float:
    return statistics.median(values) if values else 0.0


def variation(values: list[float]) -> float:
    if len(values) < 2:
        return 0.0
    mean = statistics.fmean(values)
    return statistics.stdev(values) / mean * 100.0 if mean else 0.0


def format_value(value: float) -> str:
    if value >= 1000:
        return f"{value:,.0f}"
    if value >= 100:
        return f"{value:,.1f}"
    return f"{value:,.2f}"


def format_ratio(value: float, baseline: float) -> str:
    if not baseline:
        return "n/a"
    ratio = value / baseline
    if ratio < 0.01:
        return f"{ratio:.4f}x"
    if ratio < 0.1:
        return f"{ratio:.3f}x"
    return f"{ratio:.2f}x"


def ordered_scenarios(scenarios: set[str]) -> list[str]:
    known = [scenario for scenario in SCENARIO_ORDER if scenario in scenarios]
    return known + sorted(scenarios.difference(known))


def render_markdown(
    records: list[dict[str, Any]],
    aggregates: dict[str, dict[str, list[float]]],
    output: Path,
    commit: str,
) -> None:
    environment = next(
        (record for record in records if record.get("scenario") == "environment"), {}
    )
    baseline = {
        metric: median(aggregates["ext4-loop"][metric]) for metric, _, _ in METRICS
    }
    scenarios = ordered_scenarios(set(aggregates))
    mode = environment.get("mode", "unknown")
    iterations = environment.get(
        "iterations",
        max((int(record.get("iteration", 0)) for record in records), default=0),
    )

    lines = [
        "# ArgosFS performance report",
        "",
        f"- Commit: `{commit}`" if commit else "- Commit: unknown",
        f"- Mode: `{mode}`",
        f"- Requested iterations: {iterations}",
        f"- Workload: {environment.get('file_mib', 'unknown')} MiB sequential file; "
        f"{environment.get('small_files', 'unknown')} small files",
        f"- Runner: `{environment.get('platform', 'unknown')}`",
        f"- Kernel: `{environment.get('kernel', 'unknown')}`",
        f"- Logical CPUs: {environment.get('cpu_count', 'unknown')}",
        "",
        "All values are medians. Ratios use the ext4 loop-image result from the same runner; higher is better.",
        "",
        "| Filesystem mode | Samples | Large write | vs ext4 | Large read | vs ext4 | Small create | vs ext4 | Small stat | vs ext4 |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for scenario in scenarios:
        sample_count = len(aggregates[scenario][METRICS[0][0]])
        cells = [SCENARIO_LABELS.get(scenario, scenario), str(sample_count)]
        for metric, _, unit in METRICS:
            value = median(aggregates[scenario][metric])
            cells.extend(
                [f"{format_value(value)} {unit}", format_ratio(value, baseline[metric])]
            )
        lines.append("| " + " | ".join(cells) + " |")

    lines.extend(
        [
            "",
            "## Sample variability",
            "",
            "Coefficient of variation across iterations. Large values indicate runner noise or unstable behavior.",
            "",
            "| Filesystem mode | Large write | Large read | Small create | Small stat |",
            "|---|---:|---:|---:|---:|",
        ]
    )
    for scenario in scenarios:
        cells = [SCENARIO_LABELS.get(scenario, scenario)]
        cells.extend(
            f"{variation(aggregates[scenario][metric]):.1f}%"
            for metric, _, _ in METRICS
        )
        lines.append("| " + " | ".join(cells) + " |")

    non_passed = [
        record for record in records if record.get("status") not in {"passed", "info"}
    ]
    if non_passed:
        lines.extend(["", "## Incomplete samples", ""])
        for record in non_passed:
            lines.append(
                f"- Iteration {record.get('iteration', '?')}, `{record.get('scenario', 'unknown')}`: "
                f"{record.get('status', 'unknown')} — {record.get('reason', 'no reason')}"
            )

    lines.extend(
        [
            "",
            "## Interpretation limits",
            "",
            "ArgosFS is measured through its FUSE frontend over a loop-backed image; ext4 is a kernel filesystem over a loop-backed image. "
            "The comparison exposes end-to-end overhead but does not isolate FUSE, encoding, journaling, or metadata costs.",
            "",
            "GitHub-hosted runners vary between executions. This report is diagnostic and is intentionally not a performance regression gate.",
            "",
        ]
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text("\n".join(lines), encoding="utf-8")


def render_csv(
    aggregates: dict[str, dict[str, list[float]]],
    output: Path,
) -> None:
    baseline = {
        metric: median(aggregates["ext4-loop"][metric]) for metric, _, _ in METRICS
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.writer(stream)
        writer.writerow(
            [
                "scenario",
                "samples",
                *(
                    column
                    for metric, _, _ in METRICS
                    for column in (
                        f"{metric}_median",
                        f"{metric}_vs_ext4",
                        f"{metric}_cv_percent",
                    )
                ),
            ]
        )
        for scenario in ordered_scenarios(set(aggregates)):
            row: list[Any] = [scenario, len(aggregates[scenario][METRICS[0][0]])]
            for metric, _, _ in METRICS:
                value = median(aggregates[scenario][metric])
                row.extend(
                    [
                        value,
                        value / baseline[metric] if baseline[metric] else "",
                        variation(aggregates[scenario][metric]),
                    ]
                )
            writer.writerow(row)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("input", type=Path)
    parser.add_argument("--markdown", type=Path, required=True)
    parser.add_argument("--csv", type=Path, required=True)
    parser.add_argument("--commit", default="")
    args = parser.parse_args()

    records = read_records(args.input)
    aggregates: dict[str, dict[str, list[float]]] = defaultdict(
        lambda: defaultdict(list)
    )
    for record in records:
        if record.get("status") != "passed":
            continue
        scenario = str(record.get("scenario", "unknown"))
        for metric, _, _ in METRICS:
            if metric in record:
                aggregates[scenario][metric].append(float(record[metric]))

    if not aggregates.get("ext4-loop"):
        raise SystemExit("no successful ext4-loop sample was found")
    if not any(scenario.startswith("argosfs-") for scenario in aggregates):
        raise SystemExit("no successful ArgosFS sample was found")

    render_markdown(records, aggregates, args.markdown, args.commit)
    render_csv(aggregates, args.csv)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
