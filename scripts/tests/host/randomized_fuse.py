#!/usr/bin/env python3
"""Randomized POSIX model test through a real ArgosFS FUSE mount."""

from __future__ import annotations

import argparse
import concurrent.futures
import errno
import filecmp
import json
import mmap
import os
import random
import shutil
import stat
import string
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

XATTR_NAME = b"user.argosfs.randomized"


@dataclass(frozen=True)
class Entry:
    rel: str
    kind: str


def write_jsonl(path: Path, value: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(value, sort_keys=True) + "\n")


def run_cmd(cmd: list[str], log: Path, *, check: bool = True) -> subprocess.CompletedProcess[bytes]:
    log.parent.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    with log.open("ab") as stream:
        stream.write(("\n$ " + " ".join(cmd) + "\n").encode())
        stream.flush()
        result = subprocess.run(cmd, stdout=stream, stderr=subprocess.STDOUT, check=False)
        stream.write(f"# exit={result.returncode} duration={time.monotonic() - started:.3f}s\n".encode())
    if check and result.returncode != 0:
        raise RuntimeError(f"command failed with exit {result.returncode}: {' '.join(cmd)}; see {log}")
    return result


def entries(root: Path) -> list[Entry]:
    result: list[Entry] = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        base = Path(dirpath)
        dirnames.sort()
        filenames.sort()
        rel_dir = base.relative_to(root)
        if str(rel_dir) != ".":
            result.append(Entry(str(rel_dir), "dir"))
        for name in filenames:
            path = base / name
            rel = str(path.relative_to(root))
            if path.is_symlink():
                result.append(Entry(rel, "symlink"))
            elif path.is_file():
                result.append(Entry(rel, "file"))
            else:
                raise AssertionError(f"unsupported entry type: {path}")
        for name in list(dirnames):
            path = base / name
            if path.is_symlink():
                result.append(Entry(str(path.relative_to(root)), "symlink"))
                dirnames.remove(name)
    return sorted(result, key=lambda item: item.rel)


def by_kind(root: Path, kind: str) -> list[str]:
    return [item.rel for item in entries(root) if item.kind == kind]


def existing_dirs(root: Path) -> list[str]:
    return ["."] + by_kind(root, "dir")


def safe_name(rng: random.Random, prefix: str) -> str:
    alphabet = string.ascii_lowercase + string.digits
    return f"{prefix}-" + "".join(rng.choice(alphabet) for _ in range(10))


def unused_path(root: Path, rng: random.Random, prefix: str, parent: str | None = None) -> str:
    for _ in range(500):
        selected_parent = parent if parent is not None else rng.choice(existing_dirs(root))
        rel = safe_name(rng, prefix) if selected_parent == "." else f"{selected_parent}/{safe_name(rng, prefix)}"
        if not os.path.lexists(root / rel):
            return rel
    raise RuntimeError("failed to allocate an unused path")


def payload(rng: random.Random, max_size: int, *, nonempty: bool = False) -> bytes:
    minimum = 1 if nonempty else 0
    size = rng.randint(minimum, max_size)
    mode = rng.randrange(4)
    if mode == 0:
        pattern = f"argosfs-fuse-{rng.randrange(1 << 32):08x}\n".encode()
        return (pattern * (size // len(pattern) + 1))[:size]
    if mode == 1:
        return bytes([rng.randrange(256)]) * size
    return rng.randbytes(size)


def xattrs(path: Path) -> dict[bytes, bytes]:
    try:
        names = os.listxattr(path, follow_symlinks=False)
    except OSError:
        return {}
    result: dict[bytes, bytes] = {}
    for name in names:
        encoded = os.fsencode(name)
        if not encoded.startswith(b"user."):
            continue
        result[encoded] = os.getxattr(path, encoded, follow_symlinks=False)
    return result


def hardlink_groups(root: Path, file_paths: list[str]) -> set[tuple[str, ...]]:
    groups: dict[tuple[int, int], list[str]] = {}
    for rel in file_paths:
        info = os.stat(root / rel, follow_symlinks=False)
        groups.setdefault((info.st_dev, info.st_ino), []).append(rel)
    return {tuple(sorted(group)) for group in groups.values() if len(group) > 1}


def compare_trees(reference: Path, candidate: Path) -> None:
    ref_entries = entries(reference)
    candidate_entries = entries(candidate)
    ref_map = {item.rel: item.kind for item in ref_entries}
    candidate_map = {item.rel: item.kind for item in candidate_entries}
    if ref_map != candidate_map:
        missing = sorted(set(ref_map) - set(candidate_map))[:30]
        extra = sorted(set(candidate_map) - set(ref_map))[:30]
        type_mismatch = sorted(
            rel for rel in set(ref_map) & set(candidate_map) if ref_map[rel] != candidate_map[rel]
        )[:30]
        raise AssertionError(
            f"tree mismatch: missing={missing} extra={extra} type_mismatch={type_mismatch}"
        )

    file_paths = sorted(rel for rel, kind in ref_map.items() if kind == "file")
    for rel, kind in sorted(ref_map.items()):
        left = reference / rel
        right = candidate / rel
        if kind == "file" and not filecmp.cmp(left, right, shallow=False):
            raise AssertionError(f"content mismatch: {rel}")
        if kind == "symlink" and os.readlink(left) != os.readlink(right):
            raise AssertionError(f"symlink mismatch: {rel}")
        if kind in {"file", "dir"}:
            left_mode = stat.S_IMODE(os.lstat(left).st_mode)
            right_mode = stat.S_IMODE(os.lstat(right).st_mode)
            if left_mode != right_mode:
                raise AssertionError(f"mode mismatch: {rel}: {oct(left_mode)} != {oct(right_mode)}")
            if xattrs(left) != xattrs(right):
                raise AssertionError(f"xattr mismatch: {rel}")

    if hardlink_groups(reference, file_paths) != hardlink_groups(candidate, file_paths):
        raise AssertionError("hardlink topology mismatch")


def apply_both(reference: Path, mounted: Path, action) -> None:
    action(reference)
    action(mounted)


def fsync_parent(path: Path) -> None:
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        try:
            os.fsync(fd)
        except OSError as error:
            if error.errno not in {errno.EINVAL, errno.ENOSYS, errno.EBADF}:
                raise
    finally:
        os.close(fd)


def concurrent_worker(root: Path, rel_dir: str, worker: int, chunks: list[bytes]) -> None:
    directory = root / rel_dir
    directory.mkdir(parents=True, exist_ok=True)
    temporary = directory / f"worker-{worker}.tmp"
    final = directory / f"worker-{worker}.bin"
    with temporary.open("wb", buffering=0) as stream:
        for chunk in chunks:
            stream.write(chunk)
        os.fsync(stream.fileno())
    os.replace(temporary, final)
    with final.open("r+b", buffering=0) as stream:
        stream.seek(worker * 17)
        stream.write(f"worker={worker}\n".encode())
        os.fsync(stream.fileno())
    fsync_parent(final)


def concurrent_burst(reference: Path, mounted: Path, op_index: int, rng: random.Random) -> dict[str, object]:
    rel_dir = f"parallel/round-{op_index:06d}"
    worker_chunks: list[list[bytes]] = []
    for worker in range(6):
        worker_chunks.append([rng.randbytes(256 + rng.randrange(2048)) for _ in range(12)])
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as executor:
        futures = [
            executor.submit(concurrent_worker, mounted, rel_dir, worker, worker_chunks[worker])
            for worker in range(6)
        ]
        for future in futures:
            future.result(timeout=90)
    for worker in range(6):
        concurrent_worker(reference, rel_dir, worker, worker_chunks[worker])
    return {"path": rel_dir, "workers": 6, "chunks_per_worker": 12}


def apply_operation(
    reference: Path,
    mounted: Path,
    rng: random.Random,
    op_index: int,
    max_file_size: int,
) -> dict[str, object]:
    files = by_kind(reference, "file")
    links = by_kind(reference, "symlink")
    dirs = existing_dirs(reference)
    empty_dirs = [
        rel
        for rel in dirs
        if rel != "." and not any((reference / rel).iterdir())
    ]
    choices = [
        "write", "write", "pwrite", "append", "mkdir", "rename", "unlink", "truncate",
        "chmod", "symlink", "hardlink", "xattr", "read", "stat", "open-rename",
        "open-unlink", "mmap", "parallel",
    ]
    if not files:
        choices.extend(["write"] * 8)
    if len(dirs) < 3:
        choices.extend(["mkdir"] * 4)
    operation = rng.choice(choices)
    event: dict[str, object] = {"op_index": op_index, "op": operation}

    if operation == "write":
        rel = rng.choice(files) if files and rng.random() < 0.4 else unused_path(reference, rng, "file")
        data = payload(rng, max_file_size)
        mode = rng.choice([0o600, 0o640, 0o644, 0o660, 0o664])
        def action(root: Path) -> None:
            path = root / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(path, os.O_CREAT | os.O_TRUNC | os.O_WRONLY, mode)
            try:
                view = memoryview(data)
                while view:
                    written = os.write(fd, view)
                    view = view[written:]
                os.fchmod(fd, mode)
                os.fsync(fd)
            finally:
                os.close(fd)
        apply_both(reference, mounted, action)
        event.update(path=rel, size=len(data), mode=oct(mode))

    elif operation == "pwrite" and files:
        rel = rng.choice(files)
        data = payload(rng, max(1, max_file_size // 8), nonempty=True)
        offset = rng.randrange(max_file_size * 2 + 1)
        def action(root: Path) -> None:
            fd = os.open(root / rel, os.O_RDWR)
            try:
                written = os.pwrite(fd, data, offset)
                if written != len(data):
                    raise AssertionError(f"short pwrite: {written} != {len(data)}")
                os.fsync(fd)
            finally:
                os.close(fd)
        apply_both(reference, mounted, action)
        event.update(path=rel, offset=offset, size=len(data))

    elif operation == "append" and files:
        rel = rng.choice(files)
        data = payload(rng, max(1, max_file_size // 8), nonempty=True)
        def action(root: Path) -> None:
            fd = os.open(root / rel, os.O_WRONLY | os.O_APPEND)
            try:
                if os.write(fd, data) != len(data):
                    raise AssertionError("short append")
                os.fdatasync(fd)
            finally:
                os.close(fd)
        apply_both(reference, mounted, action)
        event.update(path=rel, size=len(data))

    elif operation == "mkdir":
        rel = unused_path(reference, rng, "dir")
        mode = rng.choice([0o700, 0o750, 0o755, 0o770, 0o775])
        def action(root: Path) -> None:
            os.mkdir(root / rel, mode)
            os.chmod(root / rel, mode)
        apply_both(reference, mounted, action)
        event.update(path=rel, mode=oct(mode))

    elif operation == "rename" and (files or links):
        source = rng.choice(files + links)
        destination = unused_path(reference, rng, "renamed")
        def action(root: Path) -> None:
            os.rename(root / source, root / destination)
            fsync_parent(root / destination)
        apply_both(reference, mounted, action)
        event.update(source=source, destination=destination)

    elif operation == "unlink" and (files or links):
        rel = rng.choice(files + links)
        def action(root: Path) -> None:
            os.unlink(root / rel)
            fsync_parent(root / rel)
        apply_both(reference, mounted, action)
        event.update(path=rel)

    elif operation == "truncate" and files:
        rel = rng.choice(files)
        new_size = rng.randrange(max_file_size * 2 + 1)
        def action(root: Path) -> None:
            with (root / rel).open("r+b", buffering=0) as stream:
                os.ftruncate(stream.fileno(), new_size)
                os.fsync(stream.fileno())
        apply_both(reference, mounted, action)
        event.update(path=rel, size=new_size)

    elif operation == "chmod" and (files or len(dirs) > 1):
        rel = rng.choice(files + [path for path in dirs if path != "."])
        mode = rng.choice([0o600, 0o640, 0o644, 0o700, 0o750, 0o755, 0o775])
        apply_both(reference, mounted, lambda root: os.chmod(root / rel, mode))
        event.update(path=rel, mode=oct(mode))

    elif operation == "symlink" and files:
        target = rng.choice(files)
        link = unused_path(reference, rng, "symlink")
        relative_target = os.path.relpath(target, start=str(Path(link).parent))
        apply_both(reference, mounted, lambda root: os.symlink(relative_target, root / link))
        event.update(target=target, link=link)

    elif operation == "hardlink" and files:
        target = rng.choice(files)
        link = unused_path(reference, rng, "hardlink")
        apply_both(reference, mounted, lambda root: os.link(root / target, root / link))
        event.update(target=target, link=link)

    elif operation == "xattr" and (files or len(dirs) > 1):
        rel = rng.choice(files + [path for path in dirs if path != "."])
        value = rng.randbytes(1 + rng.randrange(128))
        def action(root: Path) -> None:
            os.setxattr(root / rel, XATTR_NAME, value, follow_symlinks=False)
            if os.getxattr(root / rel, XATTR_NAME, follow_symlinks=False) != value:
                raise AssertionError("xattr readback mismatch")
        apply_both(reference, mounted, action)
        event.update(path=rel, size=len(value))

    elif operation == "read" and files:
        rel = rng.choice(files)
        expected = (reference / rel).read_bytes()
        actual = (mounted / rel).read_bytes()
        if expected != actual:
            raise AssertionError(f"read mismatch: {rel}")
        event.update(path=rel, size=len(expected))

    elif operation == "stat" and (files or len(dirs) > 1):
        rel = rng.choice(files + [path for path in dirs if path != "."])
        left = os.lstat(reference / rel)
        right = os.lstat(mounted / rel)
        if stat.S_IFMT(left.st_mode) != stat.S_IFMT(right.st_mode) or left.st_size != right.st_size:
            raise AssertionError(f"stat mismatch: {rel}")
        list(os.scandir(mounted / rng.choice(dirs)))
        event.update(path=rel)

    elif operation == "open-rename" and files:
        source = rng.choice(files)
        destination = unused_path(reference, rng, "fd-renamed")
        suffix = rng.randbytes(1 + rng.randrange(256))
        def action(root: Path) -> None:
            fd = os.open(root / source, os.O_RDWR)
            try:
                os.rename(root / source, root / destination)
                os.lseek(fd, 0, os.SEEK_END)
                if os.write(fd, suffix) != len(suffix):
                    raise AssertionError("short fd write after rename")
                os.fsync(fd)
            finally:
                os.close(fd)
        apply_both(reference, mounted, action)
        event.update(source=source, destination=destination, size=len(suffix))

    elif operation == "open-unlink" and files:
        rel = rng.choice(files)
        def action(root: Path) -> None:
            fd = os.open(root / rel, os.O_RDONLY)
            try:
                before = os.read(fd, 4096)
                os.unlink(root / rel)
                os.lseek(fd, 0, os.SEEK_SET)
                after = os.read(fd, 4096)
                if before != after:
                    raise AssertionError("open fd content changed after unlink")
            finally:
                os.close(fd)
        apply_both(reference, mounted, action)
        event.update(path=rel)

    elif operation == "mmap" and files:
        candidates = [rel for rel in files if os.path.getsize(reference / rel) > 0]
        if candidates:
            rel = rng.choice(candidates)
            size = os.path.getsize(reference / rel)
            offset = rng.randrange(size)
            data = rng.randbytes(min(128, size - offset))
            def action(root: Path) -> None:
                with (root / rel).open("r+b", buffering=0) as stream:
                    with mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_WRITE) as mapping:
                        mapping[offset : offset + len(data)] = data
                        mapping.flush()
                    os.fsync(stream.fileno())
            apply_both(reference, mounted, action)
            event.update(path=rel, offset=offset, size=len(data))
        else:
            event.update(fallback="no-nonempty-file")

    elif operation == "parallel":
        event.update(concurrent_burst(reference, mounted, op_index, rng))

    elif empty_dirs:
        rel = rng.choice(empty_dirs)
        apply_both(reference, mounted, lambda root: os.rmdir(root / rel))
        event.update(op="rmdir", path=rel)

    else:
        list(os.scandir(mounted / rng.choice(dirs)))
        event.update(op="readdir")

    return event


class FuseMount:
    def __init__(self, args: argparse.Namespace, log: Path):
        self.args = args
        self.log = log
        self.process: subprocess.Popen[bytes] | None = None
        self.log_stream = None

    def start(self) -> None:
        if self.process is not None:
            raise RuntimeError("mount process is already running")
        self.args.mountpoint.mkdir(parents=True, exist_ok=True)
        command = [
            str(self.args.argosfs), "mount", str(self.args.volume), str(self.args.mountpoint),
            "--foreground", "-o", "default_permissions",
        ]
        self.log.parent.mkdir(parents=True, exist_ok=True)
        self.log_stream = self.log.open("ab")
        self.log_stream.write(("\n$ " + " ".join(command) + "\n").encode())
        self.log_stream.flush()
        self.process = subprocess.Popen(command, stdout=self.log_stream, stderr=subprocess.STDOUT)
        for _ in range(200):
            if self.process.poll() is not None:
                raise RuntimeError(f"FUSE mount exited before readiness with {self.process.returncode}; see {self.log}")
            result = subprocess.run(["mountpoint", "-q", str(self.args.mountpoint)], check=False)
            if result.returncode == 0:
                return
            time.sleep(0.1)
        raise RuntimeError(f"FUSE mount did not become ready: {self.args.mountpoint}")

    def stop(self) -> None:
        process = self.process
        if process is None:
            return
        result = subprocess.run([self.args.fusermount, "-u", str(self.args.mountpoint)], check=False)
        if result.returncode != 0:
            subprocess.run([self.args.fusermount, "-uz", str(self.args.mountpoint)], check=False)
        try:
            returncode = process.wait(timeout=30)
        except subprocess.TimeoutExpired:
            process.terminate()
            try:
                returncode = process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                returncode = process.wait(timeout=10)
        self.process = None
        if self.log_stream is not None:
            self.log_stream.write(f"# mount-exit={returncode}\n".encode())
            self.log_stream.close()
            self.log_stream = None
        if returncode != 0:
            raise RuntimeError(f"FUSE mount exited with {returncode}; see {self.log}")

    def abort(self) -> None:
        try:
            self.stop()
        except Exception as error:  # noqa: BLE001
            print(f"warning: failed to stop FUSE mount cleanly: {error}", file=sys.stderr)


def checkpoint(args: argparse.Namespace, mount: FuseMount, reference: Path, index: int, final: bool) -> None:
    os.sync()
    compare_trees(reference, args.mountpoint)
    mount.stop()
    run_cmd([str(args.argosfs), "fsck", str(args.volume), "--repair", "--remove-orphans"], args.command_log)
    run_cmd([str(args.argosfs), "scrub", str(args.volume)], args.command_log)
    run_cmd([str(args.argosfs), "verify-journal", str(args.volume)], args.command_log)
    exported = args.artifacts / "exports" / f"checkpoint-{index:06d}"
    if exported.exists():
        shutil.rmtree(exported)
    run_cmd([str(args.argosfs), "export-tree", str(args.volume), str(exported)], args.command_log)
    compare_trees(reference, exported)
    if not final:
        mount.start()
        compare_trees(reference, args.mountpoint)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--argosfs", required=True, type=Path)
    parser.add_argument("--artifacts", required=True, type=Path)
    parser.add_argument("--seed", required=True, type=lambda value: int(value, 0))
    parser.add_argument("--ops", type=int, default=1000)
    parser.add_argument("--checkpoint-interval", type=int, default=200)
    parser.add_argument("--max-file-size", type=int, default=131072)
    parser.add_argument("--fusermount", required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.ops < 1 or args.checkpoint_interval < 1 or args.max_file_size < 1:
        raise SystemExit("ops, checkpoint interval, and max file size must be positive")
    args.artifacts = args.artifacts.resolve()
    if args.artifacts.exists():
        shutil.rmtree(args.artifacts)
    args.artifacts.mkdir(parents=True)
    args.volume = args.artifacts / "volume"
    args.mountpoint = args.artifacts / "mnt"
    args.command_log = args.artifacts / "logs" / "commands.log"
    args.mount_log = args.artifacts / "logs" / "mount.log"
    operation_log = args.artifacts / "logs" / "operations.jsonl"
    reference = args.artifacts / "reference"
    reference.mkdir()
    rng = random.Random(args.seed)

    metadata = {
        "seed": args.seed,
        "ops": args.ops,
        "checkpoint_interval": args.checkpoint_interval,
        "max_file_size": args.max_file_size,
        "commit": os.environ.get("GITHUB_SHA", "local"),
    }
    (args.artifacts / "logs").mkdir(parents=True, exist_ok=True)
    (args.artifacts / "logs" / "metadata.json").write_text(
        json.dumps(metadata, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    run_cmd(
        [
            str(args.argosfs), "mkfs", str(args.volume), "--force", "--disks", "6",
            "--k", "4", "--m", "2", "--chunk-size", "65536", "--compression", "zstd",
        ],
        args.command_log,
    )
    mount = FuseMount(args, args.mount_log)
    try:
        mount.start()
        for op_index in range(1, args.ops + 1):
            event = apply_operation(reference, args.mountpoint, rng, op_index, args.max_file_size)
            write_jsonl(operation_log, event)
            if op_index % args.checkpoint_interval == 0:
                checkpoint(args, mount, reference, op_index, final=False)
        checkpoint(args, mount, reference, args.ops, final=True)
    except Exception as error:  # noqa: BLE001
        print(
            f"randomized FUSE model failed: seed={args.seed:#x} operation_log={operation_log} error={error}",
            file=sys.stderr,
        )
        raise
    finally:
        mount.abort()

    print(f"randomized FUSE model passed: seed={args.seed:#x} ops={args.ops} artifacts={args.artifacts}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
