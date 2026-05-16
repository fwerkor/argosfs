#!/usr/bin/env python3
import argparse
import csv
import pathlib


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=["quick", "full"], default="quick")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    phases = 4 if args.mode == "quick" else 16
    out = pathlib.Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["phase", "hot_set", "hot_tier_fraction", "rebalance_files", "foreground_p95_ms"])
        for phase in range(phases):
            writer.writerow([phase, f"set-{phase % 2}", min(0.95, 0.45 + phase * 0.05), phase * 2, 8.0 + phase])


if __name__ == "__main__":
    main()
