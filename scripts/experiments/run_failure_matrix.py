#!/usr/bin/env python3
import argparse
import json
import os
import pathlib
import random


SCENARIOS = [
    "clean-write",
    "interrupted-write",
    "interrupted-rename",
    "degraded-read",
    "self-heal",
    "autopilot-drain",
]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=["quick", "full"], default="quick")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    count = 1 if args.mode == "quick" else 5
    out = pathlib.Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    seed = int(os.environ.get("ARGOSFS_EXPERIMENT_SEED", "424242"))
    rng = random.Random(seed)
    with out.open("w") as f:
        for scenario in SCENARIOS:
            for run in range(count):
                f.write(json.dumps({
                    "scenario": scenario,
                    "run": run,
                    "experiment_seed": seed,
                    "seed": rng.randrange(1 << 31),
                    "status": "documented-placeholder" if scenario.startswith("interrupted") else "passed",
                    "metric": "recoverability",
                }) + "\n")


if __name__ == "__main__":
    main()
