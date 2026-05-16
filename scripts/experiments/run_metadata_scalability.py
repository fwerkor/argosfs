#!/usr/bin/env python3
import argparse
import csv
import pathlib
import time

from common import binary, fsck, load_meta, make_workspace, mkfs, run


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=["quick", "full"], default="quick")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    sizes = [5, 20, 50] if args.mode == "quick" else [10, 100, 500, 1000]
    out = pathlib.Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    bin_path = str(binary())
    with out.open("w", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "files",
                "create_sec",
                "ls_sec",
                "fsck_sec",
                "meta_bytes",
                "journal_bytes",
                "inodes",
                "metadata_backend",
                "fsck_errors",
            ],
            lineterminator="\n",
        )
        writer.writeheader()
        for files in sizes:
            work = make_workspace(out.parent.parent, "metadata", files)
            root = mkfs(work)
            src = work / "tiny.txt"
            src.write_text("metadata scalability row\n", encoding="utf-8")
            start = time.perf_counter()
            for idx in range(files):
                run([bin_path, "put", str(root), str(src), f"/f-{idx:06d}.txt"])
            create_sec = time.perf_counter() - start
            start = time.perf_counter()
            run([bin_path, "ls", str(root), "/", "--json"])
            ls_sec = time.perf_counter() - start
            start = time.perf_counter()
            fsck_report = fsck(root)
            fsck_sec = time.perf_counter() - start
            meta = load_meta(root)
            meta_path = root / ".argosfs" / "meta.json"
            journal_bytes = sum(path.stat().st_size for path in (root / ".argosfs").glob("journal*") if path.is_file())
            writer.writerow(
                {
                    "files": files,
                    "create_sec": create_sec,
                    "ls_sec": ls_sec,
                    "fsck_sec": fsck_sec,
                    "meta_bytes": meta_path.stat().st_size,
                    "journal_bytes": journal_bytes,
                    "inodes": len(meta.get("inodes", {})),
                    "metadata_backend": "json-cow",
                    "fsck_errors": len(fsck_report.get("errors", [])),
                }
            )


if __name__ == "__main__":
    main()
