#!/usr/bin/env python3
"""Shared helpers for ArgosFS paper experiments."""

from __future__ import annotations

import hashlib
import json
import os
import platform
import random
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any


REPO = Path(__file__).resolve().parents[2]


def seed() -> int:
    return int(os.environ.get("ARGOSFS_EXPERIMENT_SEED", "424242"))


def rng_for(label: str) -> random.Random:
    digest = hashlib.sha256(f"{seed()}:{label}".encode("utf-8")).digest()
    return random.Random(int.from_bytes(digest[:8], "big"))


def binary() -> Path:
    release = REPO / "target" / "release" / "argosfs"
    debug = REPO / "target" / "debug" / "argosfs"
    if release.exists():
        return release
    if debug.exists():
        return debug
    cargo = Path.home() / ".cargo" / "bin" / "cargo"
    subprocess.run([str(cargo if cargo.exists() else "cargo"), "build", "--release"], cwd=REPO, check=True)
    return release


def run(cmd: list[str], *, env: dict[str, str] | None = None, expect_failure: bool = False) -> dict[str, Any]:
    started = time.perf_counter()
    child_env = os.environ.copy()
    if env:
        child_env.update(env)
    proc = subprocess.run(cmd, cwd=REPO, text=True, capture_output=True, env=child_env)
    elapsed = time.perf_counter() - started
    record = {
        "cmd": cmd,
        "returncode": proc.returncode,
        "elapsed_sec": elapsed,
        "stdout": proc.stdout,
        "stderr": proc.stderr,
    }
    if expect_failure:
        if proc.returncode == 0:
            raise RuntimeError(f"command unexpectedly succeeded: {' '.join(cmd)}")
    elif proc.returncode != 0:
        raise RuntimeError(f"command failed: {' '.join(cmd)}\n{proc.stderr}")
    return record


def json_cmd(cmd: list[str], **kwargs: Any) -> tuple[dict[str, Any], dict[str, Any]]:
    record = run(cmd, **kwargs)
    return record, json.loads(record["stdout"] or "{}")


def make_workspace(base: Path, name: str, run_id: int) -> Path:
    work = base / "work" / f"{name}-{run_id}"
    if work.exists():
        shutil.rmtree(work)
    work.mkdir(parents=True)
    return work


def mkfs(work: Path, *, disks: int = 6, k: int = 4, m: int = 2) -> Path:
    root = work / "volume"
    run([str(binary()), "mkfs", str(root), "--force", "--disks", str(disks), "--k", str(k), "--m", str(m)])
    return root


def write_bytes(path: Path, size: int, label: str) -> str:
    data_rng = rng_for(label)
    data = bytes(data_rng.getrandbits(8) for _ in range(size))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return hashlib.sha256(data).hexdigest()


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def load_meta(root: Path) -> dict[str, Any]:
    return json.loads((root / ".argosfs" / "meta.json").read_text(encoding="utf-8"))


def corrupt_first_shard(root: Path) -> str:
    meta = load_meta(root)
    for inode in meta["inodes"].values():
        if inode.get("kind") == "file" and inode.get("blocks"):
            shard = inode["blocks"][0]["shards"][0]
            disk = meta["disks"][shard["disk_id"]]
            disk_path = Path(disk["path"])
            if not disk_path.is_absolute():
                disk_path = root / disk_path
            shard_path = disk_path / shard["relpath"]
            shard_path.write_bytes(b"argosfs-experiment-corruption")
            return str(shard_path)
    raise RuntimeError("no file shard found to corrupt")


def health(root: Path) -> dict[str, Any]:
    _, report = json_cmd([str(binary()), "health", str(root), "--json"])
    return report


def fsck(root: Path, *, repair: bool = False) -> dict[str, Any]:
    cmd = [str(binary()), "fsck", str(root)]
    if repair:
        cmd.extend(["--repair", "--remove-orphans"])
    _, report = json_cmd(cmd)
    return report


def common_record(name: str, mode: str, run_id: int) -> dict[str, Any]:
    return {
        "experiment": name,
        "mode": mode,
        "run": run_id,
        "experiment_seed": seed(),
        "platform": platform.platform(),
        "argosfs_binary": str(binary()),
    }

