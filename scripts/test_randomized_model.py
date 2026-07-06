#!/usr/bin/env python3
"""Randomized ArgosFS filesystem model test.

The test keeps a normal host directory as the reference model and applies the
same randomized operation stream to an ArgosFS volume through the CLI.  At fixed
intervals it exports the ArgosFS volume and compares file types, file contents,
symlink targets, and low permission bits against the reference tree.
"""

from __future__ import annotations

import argparse
import filecmp
import json
import os
import random
import shutil
import string
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

@dataclass(frozen=True)
class Entry:
    rel: str
    kind: str  # dir, file, symlink


def rel_to_argos(rel: str) -> str:
    return "/" if rel == "." else "/" + rel


def safe_name(rng: random.Random, prefix: str) -> str:
    alphabet = string.ascii_lowercase + string.digits
    return f"{prefix}-" + "".join(rng.choice(alphabet) for _ in range(8))


def run_cmd(cmd: list[str], log: Path, *, env: dict[str, str] | None = None, stdout_path: Path | None = None) -> None:
    log.parent.mkdir(parents=True, exist_ok=True)
    started = time.time()
    with log.open("a", encoding="utf-8") as fh:
        fh.write("\n$ " + " ".join(map(str, cmd)) + "\n")
        fh.flush()
        if stdout_path is None:
            proc = subprocess.run(cmd, stdout=fh, stderr=subprocess.STDOUT, text=True, env=env)
        else:
            with stdout_path.open("wb") as out:
                proc = subprocess.run(cmd, stdout=out, stderr=fh, env=env)
        fh.write(f"# exit={proc.returncode} duration={time.time() - started:.3f}s\n")
    if proc.returncode != 0:
        raise RuntimeError(f"command failed with exit {proc.returncode}: {' '.join(cmd)}; see {log}")


def relative_entries(root: Path) -> list[Entry]:
    entries: list[Entry] = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        base = Path(dirpath)
        # Deterministic traversal makes failures easier to reproduce.
        dirnames.sort()
        filenames.sort()
        rel_dir = base.relative_to(root)
        if str(rel_dir) != ".":
            entries.append(Entry(str(rel_dir), "dir"))
        for name in filenames:
            p = base / name
            rel = str(p.relative_to(root))
            if p.is_symlink():
                entries.append(Entry(rel, "symlink"))
            elif p.is_file():
                entries.append(Entry(rel, "file"))
            else:
                raise AssertionError(f"unsupported reference entry type: {p}")
        # Symlinked directories appear in dirnames. Keep them as symlink entries
        # and prevent os.walk from descending into them.
        for name in list(dirnames):
            p = base / name
            if p.is_symlink():
                entries.append(Entry(str(p.relative_to(root)), "symlink"))
                dirnames.remove(name)
    entries.sort(key=lambda e: e.rel)
    return entries


def entries_by_kind(root: Path, kind: str) -> list[str]:
    return [e.rel for e in relative_entries(root) if e.kind == kind]


def existing_dirs(root: Path) -> list[str]:
    return ["."] + entries_by_kind(root, "dir")


def existing_files(root: Path) -> list[str]:
    return entries_by_kind(root, "file")


def existing_files_or_links(root: Path) -> list[str]:
    return [e.rel for e in relative_entries(root) if e.kind in {"file", "symlink"}]


def choose_parent(root: Path, rng: random.Random) -> str:
    return rng.choice(existing_dirs(root))


def child_rel(parent: str, name: str) -> str:
    return name if parent == "." else f"{parent}/{name}"


def unused_child(root: Path, rng: random.Random, prefix: str, parent: str | None = None) -> str:
    for _ in range(200):
        p = choose_parent(root, rng) if parent is None else parent
        rel = child_rel(p, safe_name(rng, prefix))
        if not os.path.lexists(root / rel):
            return rel
    raise RuntimeError("could not allocate unused child path")


def random_payload(rng: random.Random, max_size: int) -> bytes:
    size = rng.randint(0, max_size)
    mode = rng.randrange(4)
    if mode == 0:
        return (f"argosfs-model-{rng.randrange(1 << 32)}\n".encode() * (size // 24 + 1))[:size]
    if mode == 1:
        return bytes([rng.randrange(256)]) * size
    return bytes(rng.getrandbits(8) for _ in range(size))


def file_mode(rng: random.Random) -> int:
    return rng.choice([0o600, 0o640, 0o644, 0o664])


def dir_mode(rng: random.Random) -> int:
    return rng.choice([0o700, 0o750, 0o755, 0o775])


def compare_trees(reference: Path, exported: Path) -> None:
    ref_entries = relative_entries(reference)
    out_entries = relative_entries(exported)
    ref_map = {e.rel: e.kind for e in ref_entries}
    out_map = {e.rel: e.kind for e in out_entries}
    if ref_map != out_map:
        missing = sorted(set(ref_map) - set(out_map))[:20]
        extra = sorted(set(out_map) - set(ref_map))[:20]
        type_mismatch = sorted(k for k in set(ref_map) & set(out_map) if ref_map[k] != out_map[k])[:20]
        raise AssertionError(f"tree mismatch: missing={missing} extra={extra} type_mismatch={type_mismatch}")
    for rel, kind in sorted(ref_map.items()):
        rp = reference / rel
        ep = exported / rel
        if kind == "file":
            if not filecmp.cmp(rp, ep, shallow=False):
                raise AssertionError(f"file content mismatch: {rel}")
        elif kind == "symlink":
            if os.readlink(rp) != os.readlink(ep):
                raise AssertionError(f"symlink target mismatch: {rel}: {os.readlink(rp)!r} != {os.readlink(ep)!r}")
        if kind in {"file", "dir"}:
            rmode = rp.lstat().st_mode & 0o777
            emode = ep.lstat().st_mode & 0o777
            if rmode != emode:
                raise AssertionError(f"mode mismatch: {rel}: {oct(rmode)} != {oct(emode)}")


def export_and_compare(argosfs: Path, volume: Path, reference: Path, artifacts: Path, index: int, log: Path) -> None:
    out = artifacts / "exports" / f"export-{index:05d}"
    if out.exists():
        shutil.rmtree(out)
    run_cmd([str(argosfs), "fsck", str(volume), "--repair", "--remove-orphans"], log)
    run_cmd([str(argosfs), "scrub", str(volume)], log)
    run_cmd([str(argosfs), "export-tree", str(volume), str(out)], log)
    compare_trees(reference, out)


def write_jsonl(path: Path, event: dict[str, object]) -> None:
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(event, sort_keys=True) + "\n")


def apply_operation(
    *,
    op_index: int,
    rng: random.Random,
    argosfs: Path,
    volume: Path,
    reference: Path,
    scratch: Path,
    log: Path,
    op_log: Path,
    max_file_size: int,
) -> None:
    files = existing_files(reference)
    file_or_links = existing_files_or_links(reference)
    dirs = existing_dirs(reference)
    # Weight operations toward mutations, with enough reads/stats to catch lookup
    # and symlink regressions.
    choices: list[str] = ["put", "put", "put", "mkdir", "rename", "rm", "truncate", "chmod", "symlink", "cat", "get", "stat", "ls"]
    if len(dirs) < 2:
        choices.extend(["mkdir", "put"])
    if not files:
        choices.extend(["put", "mkdir"])
    op = rng.choice(choices)

    event: dict[str, object] = {"op_index": op_index, "op": op}

    if op == "mkdir":
        rel = unused_child(reference, rng, "dir")
        mode = dir_mode(rng)
        run_cmd([str(argosfs), "mkdir", str(volume), rel_to_argos(rel), "--mode", format(mode, "o")], log)
        (reference / rel).mkdir()
        os.chmod(reference / rel, mode)
        event.update({"path": rel, "mode": oct(mode)})

    elif op == "put":
        # Sometimes overwrite an existing regular file, otherwise create a new one.
        rel = rng.choice(files) if files and rng.random() < 0.35 else unused_child(reference, rng, "file")
        payload = random_payload(rng, max_file_size)
        local = scratch / f"payload-{op_index:05d}.bin"
        local.write_bytes(payload)
        run_cmd([str(argosfs), "put", str(volume), str(local), rel_to_argos(rel)], log)
        (reference / rel).parent.mkdir(parents=True, exist_ok=True)
        (reference / rel).write_bytes(payload)
        event.update({"path": rel, "size": len(payload)})

    elif op == "rename" and file_or_links:
        src = rng.choice(file_or_links)
        dst = unused_child(reference, rng, "renamed")
        run_cmd([str(argosfs), "rename", str(volume), rel_to_argos(src), rel_to_argos(dst)], log)
        (reference / src).rename(reference / dst)
        event.update({"src": src, "dst": dst})

    elif op == "rm" and file_or_links:
        rel = rng.choice(file_or_links)
        run_cmd([str(argosfs), "rm", str(volume), rel_to_argos(rel)], log)
        (reference / rel).unlink()
        event.update({"path": rel})

    elif op == "truncate" and files:
        rel = rng.choice(files)
        old_size = (reference / rel).stat().st_size
        new_size = rng.randint(0, max(max_file_size, old_size + 1024))
        run_cmd([str(argosfs), "truncate", str(volume), rel_to_argos(rel), str(new_size)], log)
        with (reference / rel).open("r+b") as fh:
            fh.truncate(new_size)
        event.update({"path": rel, "old_size": old_size, "new_size": new_size})

    elif op == "chmod" and (files or len(dirs) > 1):
        candidates = files + [d for d in dirs if d != "."]
        rel = rng.choice(candidates)
        mode = dir_mode(rng) if (reference / rel).is_dir() else file_mode(rng)
        run_cmd([str(argosfs), "chmod", str(volume), rel_to_argos(rel), format(mode, "o")], log)
        os.chmod(reference / rel, mode)
        event.update({"path": rel, "mode": oct(mode)})

    elif op == "symlink" and files:
        target = rel_to_argos(rng.choice(files))
        link = unused_child(reference, rng, "link")
        run_cmd([str(argosfs), "symlink", str(volume), target, rel_to_argos(link)], log)
        os.symlink(target, reference / link)
        event.update({"target": target, "link": link})

    elif op == "cat" and files:
        rel = rng.choice(files)
        out = scratch / f"cat-{op_index:05d}.bin"
        run_cmd([str(argosfs), "cat", str(volume), rel_to_argos(rel)], log, stdout_path=out)
        if out.read_bytes() != (reference / rel).read_bytes():
            raise AssertionError(f"cat mismatch for {rel}")
        event.update({"path": rel})

    elif op == "get" and files:
        rel = rng.choice(files)
        out = scratch / f"get-{op_index:05d}.bin"
        run_cmd([str(argosfs), "get", str(volume), rel_to_argos(rel), str(out)], log)
        if out.read_bytes() != (reference / rel).read_bytes():
            raise AssertionError(f"get mismatch for {rel}")
        event.update({"path": rel})

    elif op == "stat" and (files or len(dirs) > 1):
        rel = rng.choice(files + [d for d in dirs if d != "."])
        out = scratch / f"stat-{op_index:05d}.json"
        run_cmd([str(argosfs), "stat", str(volume), rel_to_argos(rel)], log, stdout_path=out)
        if not out.read_bytes().strip():
            raise AssertionError(f"empty stat output for {rel}")
        event.update({"path": rel})

    else:
        # ls is also the fallback for operations whose preconditions were empty.
        rel = rng.choice(dirs)
        out = scratch / f"ls-{op_index:05d}.json"
        run_cmd([str(argosfs), "ls", str(volume), rel_to_argos(rel), "--json"], log, stdout_path=out)
        if not out.read_bytes().strip():
            raise AssertionError(f"empty ls output for {rel}")
        event.update({"path": rel})

    write_jsonl(op_log, event)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--argosfs", required=True, type=Path)
    parser.add_argument("--artifacts", required=True, type=Path)
    parser.add_argument("--seed", required=True, type=lambda value: int(value, 0))
    parser.add_argument("--ops", type=int, default=250)
    parser.add_argument("--check-interval", type=int, default=50)
    parser.add_argument("--max-file-size", type=int, default=65536)
    parser.add_argument("--disks", type=int, default=5)
    parser.add_argument("--k", type=int, default=3)
    parser.add_argument("--m", type=int, default=1)
    parser.add_argument("--chunk-size", type=int, default=32768)
    parser.add_argument("--compression", default="zstd")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    artifacts = args.artifacts
    if artifacts.exists():
        shutil.rmtree(artifacts)
    (artifacts / "logs").mkdir(parents=True, exist_ok=True)
    (artifacts / "scratch").mkdir(parents=True, exist_ok=True)
    reference = artifacts / "reference"
    reference.mkdir()
    volume = artifacts / "volume"
    log = artifacts / "logs" / "commands.log"
    op_log = artifacts / "logs" / "operations.jsonl"
    rng = random.Random(args.seed)

    run_cmd(
        [
            str(args.argosfs),
            "mkfs",
            str(volume),
            "--force",
            "--disks",
            str(args.disks),
            "--k",
            str(args.k),
            "--m",
            str(args.m),
            "--chunk-size",
            str(args.chunk_size),
            "--compression",
            args.compression,
        ],
        log,
    )

    metadata = {
        "seed": args.seed,
        "ops": args.ops,
        "check_interval": args.check_interval,
        "max_file_size": args.max_file_size,
        "disks": args.disks,
        "k": args.k,
        "m": args.m,
        "chunk_size": args.chunk_size,
        "compression": args.compression,
    }
    (artifacts / "logs" / "metadata.json").write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    try:
        for op_index in range(1, args.ops + 1):
            apply_operation(
                op_index=op_index,
                rng=rng,
                argosfs=args.argosfs,
                volume=volume,
                reference=reference,
                scratch=artifacts / "scratch",
                log=log,
                op_log=op_log,
                max_file_size=args.max_file_size,
            )
            if op_index % args.check_interval == 0:
                export_and_compare(args.argosfs, volume, reference, artifacts, op_index, log)
        export_and_compare(args.argosfs, volume, reference, artifacts, args.ops, log)
    except Exception as exc:  # noqa: BLE001 - report seed and preserve artifacts.
        print(f"ArgosFS randomized model failed: seed={args.seed} op_log={op_log} error={exc}", file=sys.stderr)
        raise

    print(f"ArgosFS randomized model passed: seed={args.seed} ops={args.ops} artifacts={artifacts}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
