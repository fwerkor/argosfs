#!/usr/bin/env python3
"""Run rootfs-oriented microbenchmarks against ArgosFS loop FUSE and baselines."""

from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Callable

from common import REPO, binary, seed


def run(cmd: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, cwd=REPO, text=True, capture_output=True, check=check)


def command(name: str) -> str | None:
    return shutil.which(name)


def emit(out: Path, record: dict[str, Any]) -> None:
    record.setdefault("seed", seed())
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, sort_keys=True) + "\n")


def skip(out: Path, mode: str, scenario: str, reason: str) -> None:
    emit(
        out,
        {
            "mode": mode,
            "scenario": scenario,
            "status": "skipped",
            "reason": reason,
        },
    )


def wait_for_mount(mountpoint: Path, proc: subprocess.Popen[str], attempts: int = 100) -> None:
    for _ in range(attempts):
        if proc.poll() is not None:
            raise RuntimeError(f"mount process exited early with status {proc.returncode}")
        if subprocess.run(["mountpoint", "-q", str(mountpoint)]).returncode == 0:
            return
        time.sleep(0.1)
    raise RuntimeError(f"mountpoint was not ready: {mountpoint}")


def unmount(mountpoint: Path) -> None:
    for cmd in (["fusermount3", "-u", str(mountpoint)], ["umount", str(mountpoint)]):
        if command(cmd[0]) and subprocess.run(cmd, capture_output=True).returncode == 0:
            return


def remove_path(path: Path) -> None:
    if command("mountpoint") and subprocess.run(
        ["mountpoint", "-q", str(path)], capture_output=True
    ).returncode == 0:
        unmount(path)
    if path.is_dir() and not path.is_symlink():
        shutil.rmtree(path)
    elif path.exists():
        path.unlink()


def write_large(path: Path, mib: int) -> tuple[float, str]:
    block = bytes((index % 251 for index in range(1024 * 1024)))
    started = time.perf_counter()
    with path.open("wb") as f:
        for _ in range(mib):
            f.write(block)
        f.flush()
        os.fsync(f.fileno())
    elapsed = time.perf_counter() - started
    return elapsed, "pattern-251"


def read_large(path: Path) -> float:
    started = time.perf_counter()
    with path.open("rb") as f:
        while f.read(1024 * 1024):
            pass
    return time.perf_counter() - started


def create_small_files(root: Path, count: int) -> float:
    small = root / "small"
    small.mkdir()
    payload = b"argosfs-rootfs-small-file\n" * 128
    started = time.perf_counter()
    for index in range(count):
        path = small / f"file-{index:05}.txt"
        with path.open("wb") as f:
            f.write(payload)
    return time.perf_counter() - started


def stat_small_files(root: Path) -> float:
    small = root / "small"
    started = time.perf_counter()
    for path in small.iterdir():
        path.stat()
    return time.perf_counter() - started


def workload(root: Path, *, file_mib: int, small_files: int) -> dict[str, Any]:
    root.mkdir(parents=True, exist_ok=True)
    large = root / "large.bin"
    write_sec, pattern = write_large(large, file_mib)
    read_sec = read_large(large)
    small_create_sec = create_small_files(root, small_files)
    stat_sec = stat_small_files(root)
    return {
        "file_mib": file_mib,
        "large_pattern": pattern,
        "large_write_sec": write_sec,
        "large_write_mib_s": file_mib / write_sec if write_sec else 0.0,
        "large_read_sec": read_sec,
        "large_read_mib_s": file_mib / read_sec if read_sec else 0.0,
        "small_files": small_files,
        "small_create_sec": small_create_sec,
        "small_create_files_s": small_files / small_create_sec if small_create_sec else 0.0,
        "small_stat_sec": stat_sec,
        "small_stat_files_s": small_files / stat_sec if stat_sec else 0.0,
    }


def run_host_directory(out: Path, mode: str, work: Path, file_mib: int, small_files: int) -> None:
    root = work / "host-directory"
    remove_path(root)
    started = time.perf_counter()
    metrics = workload(root, file_mib=file_mib, small_files=small_files)
    metrics.update(
        {
            "mode": mode,
            "scenario": "host-directory",
            "status": "passed",
            "elapsed_sec": time.perf_counter() - started,
            "reason": "regular directory baseline on the runner filesystem",
        }
    )
    emit(out, metrics)


def run_argosfs_loop(out: Path, mode: str, work: Path, file_mib: int, small_files: int) -> None:
    if not Path("/dev/fuse").exists():
        skip(out, mode, "argosfs-loop-fuse", "/dev/fuse unavailable")
        return
    for required in ("mountpoint", "fusermount3"):
        if not command(required):
            skip(out, mode, "argosfs-loop-fuse", f"{required} unavailable")
            return
    bin_path = binary()
    image = work / "argosfs-loop.img"
    mountpoint = work / "argosfs-mnt"
    remove_path(image)
    remove_path(mountpoint)
    mountpoint.mkdir(parents=True)
    image_size = 512 * 1024 * 1024 if mode == "full" else 128 * 1024 * 1024
    run(
        [
            str(bin_path),
            "mkfs",
            "--backend",
            "loop",
            "--images",
            str(image),
            "--image-size",
            str(image_size),
            "--pool-name",
            "capos-root",
            "--k",
            "1",
            "--m",
            "0",
            "--compression",
            "none",
            "--force",
        ]
    )
    proc = subprocess.Popen(
        [
            str(bin_path),
            "mount-root",
            "--backend",
            "loop",
            "--images",
            str(image),
            "--target",
            str(mountpoint),
            "--foreground",
        ],
        cwd=REPO,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    mounted = False
    started = time.perf_counter()
    try:
        wait_for_mount(mountpoint, proc)
        mounted = True
        metrics = workload(mountpoint, file_mib=file_mib, small_files=small_files)
        metrics.update(
            {
                "mode": mode,
                "scenario": "argosfs-loop-fuse",
                "status": "passed",
                "elapsed_sec": time.perf_counter() - started,
                "reason": "ArgosFS loop backend mounted through FUSE mount-root",
            }
        )
        emit(out, metrics)
    except Exception as err:
        stdout, stderr = proc.communicate(timeout=2) if proc.poll() is not None else ("", "")
        emit(
            out,
            {
                "mode": mode,
                "scenario": "argosfs-loop-fuse",
                "status": "failed",
                "reason": str(err),
                "stdout": stdout,
                "stderr": stderr,
            },
        )
    finally:
        if mounted:
            unmount(mountpoint)
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                proc.kill()


def run_ext4_loop(out: Path, mode: str, work: Path, file_mib: int, small_files: int) -> None:
    missing = [name for name in ("mkfs.ext4", "mount", "umount", "mountpoint") if not command(name)]
    if missing:
        skip(out, mode, "ext4-loop", f"missing commands: {','.join(missing)}")
        return
    image = work / "ext4.img"
    mountpoint = work / "ext4-mnt"
    remove_path(image)
    remove_path(mountpoint)
    mountpoint.mkdir(parents=True)
    image_size = 512 * 1024 * 1024 if mode == "full" else 128 * 1024 * 1024
    run(["truncate", "-s", str(image_size), str(image)])
    mkfs = run(["mkfs.ext4", "-F", "-q", str(image)], check=False)
    if mkfs.returncode != 0:
        skip(out, mode, "ext4-loop", f"mkfs.ext4 failed: {mkfs.stderr.strip()}")
        return
    mount = run(["mount", "-o", "loop", str(image), str(mountpoint)], check=False)
    if mount.returncode != 0:
        skip(out, mode, "ext4-loop", f"mount -o loop failed: {mount.stderr.strip()}")
        return
    started = time.perf_counter()
    try:
        metrics = workload(mountpoint, file_mib=file_mib, small_files=small_files)
        metrics.update(
            {
                "mode": mode,
                "scenario": "ext4-loop",
                "status": "passed",
                "elapsed_sec": time.perf_counter() - started,
                "reason": "ext4 loop image mounted on the same runner",
            }
        )
        emit(out, metrics)
    finally:
        subprocess.run(["umount", str(mountpoint)], capture_output=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=["quick", "full"], default="quick")
    parser.add_argument("--output", type=Path, default=Path("paper-data/raw/rootfs-perf.jsonl"))
    parser.add_argument("--workdir", type=Path)
    parser.add_argument("--keep-workdir", action="store_true")
    args = parser.parse_args()

    file_mib = 128 if args.mode == "full" else 16
    small_files = 2048 if args.mode == "full" else 256
    work = args.workdir or args.output.parent.parent / "work" / "rootfs-perf"
    if work.exists() and not args.keep_workdir:
        shutil.rmtree(work)
    work.mkdir(parents=True, exist_ok=True)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text("", encoding="utf-8")
    emit(
        args.output,
        {
            "mode": args.mode,
            "scenario": "environment",
            "status": "info",
            "platform": platform.platform(),
            "kernel": platform.release(),
            "python": sys.version.split()[0],
        },
    )

    scenarios: list[Callable[[Path, str, Path, int, int], None]] = [
        run_host_directory,
        run_argosfs_loop,
        run_ext4_loop,
    ]
    for scenario in scenarios:
        scenario(args.output, args.mode, work, file_mib, small_files)
    if not args.keep_workdir:
        shutil.rmtree(work, ignore_errors=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
