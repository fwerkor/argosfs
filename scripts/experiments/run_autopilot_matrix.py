#!/usr/bin/env python3
"""Deterministic Autopilot evidence matrix for retained paper data."""

from __future__ import annotations

import argparse
import json
import pathlib
import time
from typing import Any

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
    "critical-drain",
    "insufficient-redundancy-observe",
    "confirmed-risk-drain",
    "cooldown-after-drain",
    "rebalance-empty-device",
    "scrub-repair-corruption",
]


def json_run(cmd: list[str], **kwargs: Any) -> dict[str, Any]:
    record = run(cmd, **kwargs)
    return json.loads(record["stdout"] or "{}")


def write_payloads(work: pathlib.Path, root: pathlib.Path, count: int, size: int, label: str) -> dict[str, str]:
    bin_path = str(binary())
    expected = {}
    for idx in range(count):
        src = work / f"input-{idx:03d}.bin"
        expected[f"/data-{idx:03d}.bin"] = write_bytes(src, size, f"{label}-{idx}")
        run([bin_path, "put", str(root), str(src), f"/data-{idx:03d}.bin"])
    return expected


def read_back_payloads(work: pathlib.Path, root: pathlib.Path, expected: dict[str, str]) -> bool:
    bin_path = str(binary())
    ok = True
    for path, digest in expected.items():
        out = work / ("readback" + path.replace("/", "-"))
        run([bin_path, "get", str(root), path, str(out)])
        ok = ok and sha256(out) == digest
    return ok


def action_names(report: dict[str, Any]) -> list[str]:
    return [action.get("action", "") for action in report.get("actions", [])]


def disk_statuses(report: dict[str, Any]) -> dict[str, str]:
    return {disk["id"]: disk["status"].lower() for disk in report.get("disks", [])}


def dry_run_decision(report: dict[str, Any], disk_id: str) -> dict[str, Any]:
    for decision in report.get("decisions", []):
        if decision.get("target") == disk_id:
            return decision
    return {}


def autopilot_once(root: pathlib.Path, *, env: dict[str, str] | None = None) -> dict[str, Any]:
    return json_run([str(binary()), "autopilot", str(root), "--once", "--json"], env=env)


def autopilot_dry_run(root: pathlib.Path, *, env: dict[str, str] | None = None) -> dict[str, Any]:
    return json_run([str(binary()), "autopilot", str(root), "--dry-run", "--json"], env=env)


def set_health(root: pathlib.Path, disk_id: str, *args: str) -> None:
    run([str(binary()), "set-health", str(root), disk_id, *args])


def run_scenario(base: pathlib.Path, mode: str, scenario: str, run_id: int) -> dict[str, Any]:
    work = make_workspace(base, "autopilot", run_id * 100 + SCENARIOS.index(scenario))
    size = 64 * 1024 if mode == "quick" else 512 * 1024
    files = 4 if mode == "quick" else 12
    started = time.perf_counter()
    detail: dict[str, Any] = {}
    ok = False

    if scenario == "critical-drain":
        root = mkfs(work, disks=7, k=4, m=2)
        expected = write_payloads(work, root, files, size, scenario)
        before = health(root)
        set_health(root, "disk-0001", "--pending-sectors", "24", "--io-errors", "40")
        plan = autopilot_dry_run(root)
        result = autopilot_once(root)
        after = health(root)
        fsck_report = fsck(root)
        ok = (
            "drain-predicted-failure" in action_names(result)
            and disk_statuses(after).get("disk-0001") == "degraded"
            and not fsck_report.get("errors")
            and read_back_payloads(work, root, expected)
        )
        detail = {"before": before, "dry_run": plan, "autopilot": result, "after": after, "fsck": fsck_report}

    elif scenario == "insufficient-redundancy-observe":
        root = mkfs(work, disks=6, k=4, m=2)
        write_payloads(work, root, files, size, scenario)
        set_health(root, "disk-0001", "--pending-sectors", "24", "--io-errors", "40")
        plan = autopilot_dry_run(root)
        decision = dry_run_decision(plan, "disk-0001")
        ok = (
            decision.get("chosen_action") == "observe"
            and not decision.get("safety_checks", {}).get("enough_online_disks", True)
            and any(item.get("reason") == "not enough online disks after drain" for item in decision.get("rejected_actions", []))
        )
        detail = {"dry_run": plan, "target_decision": decision, "health": health(root), "fsck": fsck(root)}

    elif scenario == "confirmed-risk-drain":
        root = mkfs(work, disks=7, k=4, m=2)
        expected = write_payloads(work, root, files, size, scenario)
        set_health(root, "disk-0001", "--pending-sectors", "8")
        first = autopilot_once(root)
        second = autopilot_once(root)
        after = health(root)
        fsck_report = fsck(root)
        ok = (
            "observe-predicted-failure" in action_names(first)
            and "drain-predicted-failure" in action_names(second)
            and disk_statuses(after).get("disk-0001") == "degraded"
            and not fsck_report.get("errors")
            and read_back_payloads(work, root, expected)
        )
        detail = {"first": first, "second": second, "after": after, "fsck": fsck_report}

    elif scenario == "cooldown-after-drain":
        root = mkfs(work, disks=8, k=4, m=2)
        write_payloads(work, root, files, size, scenario)
        set_health(root, "disk-0001", "--pending-sectors", "24", "--io-errors", "40")
        drained = autopilot_once(root)
        cooldown = autopilot_dry_run(root)
        decision = dry_run_decision(cooldown, "disk-0001")
        ok = (
            "drain-predicted-failure" in action_names(drained)
            and decision.get("chosen_action") == "observe"
            and any(item.get("reason") == "cooldown" for item in decision.get("rejected_actions", []))
        )
        detail = {"drained": drained, "cooldown_dry_run": cooldown, "target_decision": decision, "fsck": fsck(root)}

    elif scenario == "rebalance-empty-device":
        root = mkfs(work, disks=6, k=4, m=2)
        expected = write_payloads(work, root, files * 2, size, scenario)
        run([str(binary()), "add-disk", str(root)])
        before = health(root)
        result = autopilot_once(root)
        after = health(root)
        fsck_report = fsck(root)
        rebalance_actions = [action for action in result.get("actions", []) if action.get("action") == "rebalance-incremental"]
        ok = (
            bool(rebalance_actions)
            and sum(action.get("rewritten_files", 0) for action in rebalance_actions) > 0
            and not fsck_report.get("errors")
            and read_back_payloads(work, root, expected)
        )
        detail = {"before": before, "autopilot": result, "after": after, "fsck": fsck_report}

    elif scenario == "scrub-repair-corruption":
        root = mkfs(work, disks=6, k=4, m=2)
        expected = write_payloads(work, root, files, size, scenario)
        corrupted = corrupt_first_shard(root)
        result = autopilot_once(root, env={"ARGOSFS_DISABLE_L2_CACHE": "1"})
        after = health(root)
        fsck_report = fsck(root)
        scrub_actions = [action for action in result.get("actions", []) if action.get("action") == "scrub-incremental"]
        repaired = sum(action.get("report", {}).get("repaired_files", 0) for action in scrub_actions)
        ok = (
            repaired > 0
            and not fsck_report.get("errors")
            and read_back_payloads(work, root, expected)
        )
        detail = {
            "corrupted_shard": corrupted,
            "autopilot": result,
            "after": after,
            "fsck": fsck_report,
            "repaired_files": repaired,
        }

    else:
        raise ValueError(scenario)

    return {
        **common_record("autopilot-matrix", mode, run_id),
        "scenario": scenario,
        "status": "passed" if ok else "failed",
        "duration_sec": time.perf_counter() - started,
        "detail": detail,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=["quick", "full"], default="quick")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    count = 1 if args.mode == "quick" else 3
    out = pathlib.Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    base = out.parent.parent
    with out.open("w") as f:
        for scenario in SCENARIOS:
            for run_id in range(count):
                f.write(json.dumps(run_scenario(base, args.mode, scenario, run_id), sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
