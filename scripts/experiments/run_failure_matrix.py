#!/usr/bin/env python3
import argparse
import json
import pathlib
import time

from common import (
    binary,
    common_record,
    corrupt_first_shard,
    fsck,
    health,
    make_workspace,
    mkfs,
    run,
    sha256,
    write_bytes,
)


SCENARIOS = [
    "clean-write",
    "interrupted-write",
    "interrupted-rename",
    "degraded-read",
    "self-heal",
    "autopilot-drain",
]


def command_count(start_count, steps):
    return len(steps) - start_count


def run_scenario(base, mode, scenario, run_id):
    work = make_workspace(base, scenario, run_id)
    root = mkfs(work, disks=7) if scenario == "autopilot-drain" else mkfs(work)
    bin_path = str(binary())
    steps = []
    started = time.perf_counter()

    src = work / "input.bin"
    expected = write_bytes(src, 256 * 1024 if mode == "quick" else 2 * 1024 * 1024, f"{scenario}-{run_id}")
    out = work / "output.bin"
    start_count = len(steps)

    if scenario == "clean-write":
        steps.append(run([bin_path, "put", str(root), str(src), "/data.bin"]))
        steps.append(run([bin_path, "get", str(root), "/data.bin", str(out)]))
        ok = sha256(out) == expected
        report = fsck(root)
        detail = {"sha256_ok": ok, "fsck_errors": report.get("errors", [])}
    elif scenario == "interrupted-write":
        old = work / "old.txt"
        new = work / "new.txt"
        old.write_text("before crash\n", encoding="utf-8")
        new.write_text("after crash\n", encoding="utf-8")
        steps.append(run([bin_path, "put", str(root), str(old), "/crash.txt"]))
        steps.append(
            run(
                [bin_path, "put", str(root), str(new), "/crash.txt"],
                env={"ARGOSFS_CRASH_POINT": "after-journal"},
                expect_failure=True,
            )
        )
        steps.append(run([bin_path, "verify-journal", str(root)]))
        steps.append(run([bin_path, "get", str(root), "/crash.txt", str(out)]))
        detail = {"replayed_contents": out.read_text(encoding="utf-8").strip(), "fsck": fsck(root, repair=True)}
        ok = "after crash" in detail["replayed_contents"]
    elif scenario == "interrupted-rename":
        a = work / "rename-a.txt"
        a.write_text("rename source\n", encoding="utf-8")
        steps.append(run([bin_path, "put", str(root), str(a), "/rename-a.txt"]))
        steps.append(
            run(
                [bin_path, "rename", str(root), "/rename-a.txt", "/rename-b.txt"],
                env={"ARGOSFS_CRASH_POINT": "after-journal"},
                expect_failure=True,
            )
        )
        steps.append(run([bin_path, "verify-journal", str(root)]))
        steps.append(run([bin_path, "get", str(root), "/rename-b.txt", str(out)]))
        ok = out.read_text(encoding="utf-8") == "rename source\n"
        detail = {"rename_replayed": ok, "fsck": fsck(root, repair=True)}
    elif scenario == "degraded-read":
        steps.append(run([bin_path, "put", str(root), str(src), "/data.bin"]))
        steps.append(run([bin_path, "mark-disk", str(root), "disk-0000", "failed"]))
        steps.append(run([bin_path, "get", str(root), "/data.bin", str(out)]))
        ok = sha256(out) == expected
        detail = {"sha256_ok": ok, "failed_disk": "disk-0000", "health": health(root)}
    elif scenario == "self-heal":
        steps.append(run([bin_path, "put", str(root), str(src), "/data.bin"]))
        corrupted = corrupt_first_shard(root)
        repair_report = fsck(root, repair=True)
        steps.append(run([bin_path, "get", str(root), "/data.bin", str(out)]))
        ok = sha256(out) == expected
        detail = {"sha256_ok": ok, "corrupted_shard": corrupted, "fsck": repair_report}
    elif scenario == "autopilot-drain":
        steps.append(run([bin_path, "put", str(root), str(src), "/data.bin"]))
        steps.append(run([bin_path, "set-health", str(root), "disk-0001", "--pending-sectors", "24", "--io-errors", "40"]))
        before = health(root)
        autopilot = run([bin_path, "autopilot", str(root), "--once", "--json"])
        steps.append(autopilot)
        autopilot_report = json.loads(autopilot["stdout"] or "{}")
        after = health(root)
        statuses = {disk["id"]: disk["status"] for disk in after.get("disks", [])}
        ok = statuses.get("disk-0001") in {"draining", "failed"} or any(
            action.get("action") in {"drain-predicted-failure", "skip-drain-predicted-failure"}
            for action in autopilot_report.get("actions", [])
        )
        detail = {
            "before": before,
            "after": after,
            "autopilot_actions": autopilot_report.get("actions", []),
            "target_disk_status": statuses.get("disk-0001"),
        }
    else:
        raise ValueError(scenario)

    return {
        **common_record("failure-matrix", mode, run_id),
        "scenario": scenario,
        "status": "passed" if ok else "failed",
        "duration_sec": time.perf_counter() - started,
        "commands": command_count(start_count, steps),
        "detail": detail,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=["quick", "full"], default="quick")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    count = 1 if args.mode == "quick" else 5
    out = pathlib.Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    base = out.parent.parent
    with out.open("w") as f:
        for scenario in SCENARIOS:
            for run in range(count):
                f.write(json.dumps(run_scenario(base, args.mode, scenario, run), sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
