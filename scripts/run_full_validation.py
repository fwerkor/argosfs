#!/usr/bin/env python3
"""Run retained ArgosFS validation and write paper-ready artifacts."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import platform
import random
import shutil
import socket
import subprocess
import sys
import time
import urllib.request
from pathlib import Path


def run(cmd: list[str], cwd: Path, log_dir: Path, env: dict[str, str] | None = None) -> dict:
    started = time.perf_counter()
    child_env = os.environ.copy()
    if env:
        child_env.update(env)
    proc = subprocess.run(cmd, cwd=cwd, text=True, capture_output=True, env=child_env)
    elapsed = time.perf_counter() - started
    name = f"{int(time.time() * 1000)}-{'-'.join(Path(cmd[0]).name if i == 0 else safe(part) for i, part in enumerate(cmd[1:4]))}.log"
    log_path = log_dir / name
    log_path.write_text(
        json.dumps(
            {
                "cmd": cmd,
                "returncode": proc.returncode,
                "elapsed_sec": elapsed,
                "stdout": proc.stdout,
                "stderr": proc.stderr,
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    if proc.returncode != 0:
        raise RuntimeError(f"command failed: {' '.join(cmd)}\n{proc.stderr}")
    return {
        "cmd": cmd,
        "elapsed_sec": elapsed,
        "stdout": proc.stdout,
        "stderr": proc.stderr,
        "log": str(log_path),
        "env": sorted(env.keys()) if env else [],
    }


def safe(value: str) -> str:
    return "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in value)[:48]


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            chunk = f.read(1024 * 1024)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def make_dataset(dataset: Path) -> list[dict]:
    dataset.mkdir(parents=True, exist_ok=True)
    rng = random.Random(0xA2605F5)
    specs = [
        ("text-small.txt", b"ArgosFS validation text\n" * 64),
        ("zeros-1m.bin", b"\x00" * (1024 * 1024)),
        ("pattern-2m.bin", bytes((i % 251 for i in range(2 * 1024 * 1024)))),
        ("random-1m.bin", bytes(rng.getrandbits(8) for _ in range(1024 * 1024))),
    ]
    rows = []
    for name, data in specs:
        path = dataset / name
        path.write_bytes(data)
        rows.append({"name": name, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()})
    return rows


def load_meta(volume: Path) -> dict:
    return json.loads((volume / ".argosfs" / "meta.json").read_text(encoding="utf-8"))


def corrupt_first_shard(volume: Path) -> Path:
    meta = load_meta(volume)
    for inode in meta["inodes"].values():
        if inode.get("kind") == "file" and inode.get("blocks"):
            shard = inode["blocks"][0]["shards"][0]
            disk = meta["disks"][shard["disk_id"]]
            disk_path = Path(disk["path"])
            if not disk_path.is_absolute():
                disk_path = volume / disk_path
            shard_path = disk_path / shard["relpath"]
            shard_path.write_bytes(b"paper-data-corruption")
            return shard_path
    raise RuntimeError("no shard found to corrupt")


def free_tcp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def capture_prometheus(binary: Path, volume: Path, metrics: Path, env: dict[str, str]) -> dict:
    port = free_tcp_port()
    listen = f"127.0.0.1:{port}"
    proc = subprocess.Popen(
        [str(binary), "prometheus", str(volume), "--listen", listen],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env={**os.environ, **env},
    )
    started = time.perf_counter()
    try:
        body = ""
        for _ in range(30):
            try:
                with urllib.request.urlopen(f"http://{listen}/metrics", timeout=1) as response:
                    body = response.read().decode("utf-8")
                break
            except Exception:
                if proc.poll() is not None:
                    raise RuntimeError("Prometheus exporter exited before serving metrics")
                time.sleep(0.1)
        if not body:
            raise RuntimeError("Prometheus exporter did not answer before timeout")
        path = metrics / "prometheus.txt"
        path.write_text(body, encoding="utf-8")
        return {
            "cmd": [str(binary), "prometheus", str(volume), "--listen", listen],
            "elapsed_sec": time.perf_counter() - started,
            "output": str(path),
            "bytes": len(body.encode("utf-8")),
        }
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            proc.kill()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=Path("paper-data/runs/manual"))
    parser.add_argument("--keep-existing", action="store_true")
    args = parser.parse_args()

    repo = Path(__file__).resolve().parents[1]
    out = args.output.resolve()
    if out.exists() and not args.keep_existing:
        shutil.rmtree(out)
    (out / "logs").mkdir(parents=True, exist_ok=True)
    dataset = out / "datasets"
    volume = out / "volume"
    recovered = out / "recovered"
    metrics = out / "metrics"
    metrics.mkdir(parents=True, exist_ok=True)

    manifest = {
        "started_at": time.time(),
        "platform": platform.platform(),
        "python": sys.version,
        "repo": str(repo),
        "steps": [],
    }

    cargo = Path.home() / ".cargo" / "bin" / "cargo"
    cargo_cmd = str(cargo) if cargo.exists() else "cargo"
    manifest["steps"].append(run([cargo_cmd, "build"], repo, out / "logs"))
    binary = repo / "target" / "debug" / "argosfs"
    dataset_rows = make_dataset(dataset)
    (metrics / "datasets.json").write_text(json.dumps(dataset_rows, indent=2) + "\n", encoding="utf-8")
    key_file = metrics / "argosfs-validation.key"
    key_file.write_text("argosfs validation paper key\n", encoding="utf-8")
    key_file.chmod(0o600)
    secure_env = {"ARGOSFS_KEY_FILE": str(key_file)}

    manifest["steps"].append(
        run(
            [
                str(binary),
                "mkfs",
                str(volume),
                "--force",
                "--disks",
                "6",
                "--k",
                "4",
                "--m",
                "2",
                "--chunk-size",
                "65536",
                "--compression",
                "zstd",
            ],
            repo,
            out / "logs",
        )
    )
    manifest["steps"].append(run([str(binary), "mkdir", str(volume), "/data", "--mode", "755"], repo, out / "logs"))
    manifest["steps"].append(run([str(binary), "enable-encryption", str(volume), "--key-file", str(key_file)], repo, out / "logs"))
    manifest["steps"].append(run([str(binary), "set-io-mode", str(volume), "--mode", "io-uring"], repo, out / "logs"))

    samples = []
    for row in dataset_rows:
        src = dataset / row["name"]
        start = time.perf_counter()
        manifest["steps"].append(
            run(
                [str(binary), "put", str(volume), str(src), f"/data/{row['name']}"],
                repo,
                out / "logs",
                secure_env,
            )
        )
        put_sec = time.perf_counter() - start
        start = time.perf_counter()
        manifest["steps"].append(
            run(
                [str(binary), "get", str(volume), f"/data/{row['name']}", str(recovered / row["name"])],
                repo,
                out / "logs",
                secure_env,
            )
        )
        get_sec = time.perf_counter() - start
        samples.append(
            {
                "name": row["name"],
                "bytes": row["bytes"],
                "put_sec": put_sec,
                "get_sec": get_sec,
                "sha256_ok": sha256(recovered / row["name"]) == row["sha256"],
            }
        )

    with (metrics / "io_samples.csv").open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=["name", "bytes", "put_sec", "get_sec", "sha256_ok"],
            lineterminator="\n",
        )
        writer.writeheader()
        writer.writerows(samples)

    acl_json = metrics / "nfs4-acl.json"
    acl_json.write_text(
        json.dumps(
            {
                "entries": [
                    {
                        "ace_type": "allow",
                        "principal": "EVERYONE@",
                        "flags": [],
                        "permissions": ["read"],
                    }
                ]
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    manifest["steps"].append(
        run(
            [
                str(binary),
                "set-posix-acl",
                str(volume),
                "/data/text-small.txt",
                "user::rw-,group::r--,mask::r--,other::---",
            ],
            repo,
            out / "logs",
            secure_env,
        )
    )
    manifest["steps"].append(
        run(
            [str(binary), "set-nfs4-acl", str(volume), "/data/text-small.txt", f"@{acl_json}"],
            repo,
            out / "logs",
            secure_env,
        )
    )
    manifest["steps"].append(
        run([str(binary), "encryption-status", str(volume)], repo, out / "logs", secure_env)
    )

    corrupt_path = corrupt_first_shard(volume)
    manifest["corrupted_shard"] = str(corrupt_path)
    manifest["steps"].append(run([str(binary), "fsck", str(volume), "--repair", "--remove-orphans"], repo, out / "logs", secure_env))
    manifest["steps"].append(run([str(binary), "mark-disk", str(volume), "disk-0000", "failed"], repo, out / "logs", secure_env))
    manifest["steps"].append(run([str(binary), "add-disk", str(volume), "--rebalance"], repo, out / "logs", secure_env))
    manifest["steps"].append(run([str(binary), "set-health", str(volume), "disk-0001", "--pending-sectors", "12"], repo, out / "logs", secure_env))
    manifest["steps"].append(run([str(binary), "autopilot", str(volume), "--once"], repo, out / "logs", secure_env))
    manifest["steps"].append(run([str(binary), "health", str(volume), "--json"], repo, out / "logs", secure_env))
    manifest["steps"].append(capture_prometheus(binary, volume, metrics, secure_env))

    final_health = subprocess.check_output(
        [str(binary), "health", str(volume), "--json"],
        cwd=repo,
        text=True,
        env={**os.environ, **secure_env},
    )
    (metrics / "final_health.json").write_text(final_health, encoding="utf-8")
    final_fsck = subprocess.check_output(
        [str(binary), "fsck", str(volume), "--repair", "--remove-orphans"],
        cwd=repo,
        text=True,
        env={**os.environ, **secure_env},
    )
    (metrics / "final_fsck.json").write_text(final_fsck, encoding="utf-8")
    shutil.rmtree(volume / ".argosfs" / "cache", ignore_errors=True)

    manifest["finished_at"] = time.time()
    manifest["duration_sec"] = manifest["finished_at"] - manifest["started_at"]
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(out), "duration_sec": manifest["duration_sec"]}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
