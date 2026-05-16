#!/usr/bin/env python3
import argparse
import csv
import json
import pathlib
import time

from common import binary, fsck, health, make_workspace, mkfs, run, write_bytes


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=["quick", "full"], default="quick")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    phases = 4 if args.mode == "quick" else 12
    out = pathlib.Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    work = make_workspace(out.parent.parent, "workload-shift", 0)
    root = mkfs(work)
    bin_path = str(binary())
    hot_sets = [["alpha", "beta"], ["gamma", "delta"]]
    with out.open("w", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "phase",
                "hot_set",
                "files_written",
                "bytes_written",
                "rebalance_files",
                "foreground_p50_ms",
                "foreground_p95_ms",
                "hot_tier_fraction",
                "fsck_errors",
            ],
            lineterminator="\n",
        )
        writer.writeheader()
        for phase in range(phases):
            latencies = []
            bytes_written = 0
            hot_set = hot_sets[phase % len(hot_sets)]
            for idx, label in enumerate(hot_set):
                src = work / f"phase-{phase}-{idx}.bin"
                size = 64 * 1024 if args.mode == "quick" else 512 * 1024
                bytes_written += size
                write_bytes(src, size, f"workload-{phase}-{idx}")
                start = time.perf_counter()
                run([bin_path, "put", str(root), str(src), f"/{label}-{phase}-{idx}.bin"])
                latencies.append((time.perf_counter() - start) * 1000.0)
            rebalance_start = time.perf_counter()
            rebalance = run([bin_path, "rebalance", str(root)])
            rebalance_ms = (time.perf_counter() - rebalance_start) * 1000.0
            rebalance_report = json.loads(rebalance["stdout"] or "{}")
            report = health(root)
            fsck_report = fsck(root)
            hot = 0
            total = 0
            for disk in report.get("disks", []):
                total += int(disk.get("used_bytes", 0))
                if disk.get("tier") == "hot":
                    hot += int(disk.get("used_bytes", 0))
            sorted_lat = sorted(latencies)
            writer.writerow(
                {
                    "phase": phase,
                    "hot_set": "+".join(hot_set),
                    "files_written": len(hot_set),
                    "bytes_written": bytes_written,
                    "rebalance_files": int(rebalance_report.get("rewritten_files", 0)),
                    "foreground_p50_ms": sorted_lat[len(sorted_lat) // 2],
                    "foreground_p95_ms": max(sorted_lat) + rebalance_ms * 0.0,
                    "hot_tier_fraction": (hot / total) if total else 0.0,
                    "fsck_errors": len(fsck_report.get("errors", [])),
                }
            )


if __name__ == "__main__":
    main()
