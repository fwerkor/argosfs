#!/usr/bin/env python3
"""Generate or validate reproducible randomized-test seeds for GitHub Actions."""

from __future__ import annotations

import argparse
import json
import os
import re
import secrets
from datetime import datetime, timezone
from pathlib import Path

SEED_RE = re.compile(r"(?:0[xX][0-9a-fA-F]+|[0-9]+)")
MAX_SEEDS = 32


def parse_seed(value: str) -> int:
    value = value.strip()
    if not SEED_RE.fullmatch(value):
        raise ValueError(f"invalid seed: {value!r}")
    seed = int(value, 0)
    if not 0 <= seed <= (1 << 64) - 1:
        raise ValueError(f"seed is outside the unsigned 64-bit range: {value!r}")
    return seed


def explicit_seeds(raw: str) -> list[int]:
    seeds: list[int] = []
    seen: set[int] = set()
    for value in raw.split(","):
        if not value.strip():
            continue
        seed = parse_seed(value)
        if seed not in seen:
            seeds.append(seed)
            seen.add(seed)
    return seeds


def random_seeds(count: int) -> list[int]:
    seeds: list[int] = []
    seen: set[int] = set()
    while len(seeds) < count:
        seed = secrets.randbits(64)
        if seed not in seen:
            seeds.append(seed)
            seen.add(seed)
    return seeds


def seed_text(seed: int) -> str:
    return f"0x{seed:016x}"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--count", type=int, default=12)
    parser.add_argument("--seeds", default="", help="optional comma-separated replay seeds")
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--github-output", type=Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if not 1 <= args.count <= MAX_SEEDS:
        raise SystemExit(f"seed count must be between 1 and {MAX_SEEDS}")

    try:
        seeds = explicit_seeds(args.seeds)
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc

    source = "explicit"
    if not seeds:
        source = "cryptographic-random"
        seeds = random_seeds(args.count)
    if len(seeds) > MAX_SEEDS:
        raise SystemExit(f"at most {MAX_SEEDS} seeds are supported")

    serialized_seeds = [seed_text(seed) for seed in seeds]
    manifest = {
        "schema": 1,
        "source": source,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "repository": os.environ.get("GITHUB_REPOSITORY", ""),
        "workflow": os.environ.get("GITHUB_WORKFLOW", ""),
        "run_id": os.environ.get("GITHUB_RUN_ID", ""),
        "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT", ""),
        "commit": os.environ.get("GITHUB_SHA", ""),
        "count": len(serialized_seeds),
        "seeds": serialized_seeds,
    }
    args.manifest.parent.mkdir(parents=True, exist_ok=True)
    args.manifest.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    matrix_json = json.dumps(serialized_seeds, separators=(",", ":"))
    if args.github_output is not None:
        with args.github_output.open("a", encoding="utf-8") as output:
            output.write(f"seeds={matrix_json}\n")
            output.write(f"source={source}\n")
            output.write(f"count={len(serialized_seeds)}\n")

    print(f"Randomized seed source: {source}")
    print(f"Randomized seed matrix: {matrix_json}")
    print(f"Seed manifest: {args.manifest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
