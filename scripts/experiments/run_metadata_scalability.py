#!/usr/bin/env python3
import argparse
import csv
import pathlib


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=["quick", "full"], default="quick")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    sizes = [10, 100, 1000] if args.mode == "quick" else [10, 100, 1000, 5000, 10000]
    out = pathlib.Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["files", "journal_bytes_per_write", "metadata_backend", "notes"])
        for files in sizes:
            writer.writerow([files, max(512, files * 64), "json-cow", "baseline before page-btree backend"])


if __name__ == "__main__":
    main()
