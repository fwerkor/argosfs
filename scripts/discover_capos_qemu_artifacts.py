#!/usr/bin/env python3
from __future__ import annotations

import argparse
import gzip
import json
import os
import shutil
import stat
from pathlib import Path


def score(path: Path, tokens: list[str]) -> tuple[int, int, str]:
    name = path.name.lower()
    points = 0
    for idx, token in enumerate(tokens):
        if token and token in name:
            points += 100 - idx
    if name.endswith(".gz"):
        points -= 3
    return (-points, len(name), str(path))


def first(paths: list[Path], tokens: list[str]) -> Path | None:
    existing = [p for p in paths if p.is_file() and p.stat().st_size > 0]
    if not existing:
        return None
    return sorted(existing, key=lambda p: score(p, tokens))[0]


def maybe_decompress(path: Path | None, out_dir: Path) -> Path | None:
    if path is None:
        return None
    if path.suffix != ".gz":
        return path
    out_dir.mkdir(parents=True, exist_ok=True)
    out = out_dir / path.with_suffix("").name
    if not out.exists() or path.stat().st_mtime > out.stat().st_mtime:
        with gzip.open(path, "rb") as src, out.open("wb") as dst:
            shutil.copyfileobj(src, dst)
    return out


def emit_github_output(values: dict[str, str]) -> None:
    output = os.environ.get("GITHUB_OUTPUT")
    if not output:
        return
    with open(output, "a", encoding="utf-8") as f:
        for key, value in values.items():
            f.write(f"{key}={value}\n")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifacts", type=Path, required=True)
    parser.add_argument("--arch", required=True, choices=["x86_64", "arm64", "riscv64"])
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--require-bootable", action="store_true")
    args = parser.parse_args()

    root = args.artifacts.resolve()
    capos = root / "capos"
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=True)
    bin_targets = list((capos / "bin" / "targets").glob("**/*")) if (capos / "bin" / "targets").exists() else []
    build_targets = list((capos / "build_dir").glob("**/*")) if (capos / "build_dir").exists() else []

    kernels = [p for p in bin_targets + build_targets if p.is_file() and any(t in p.name.lower() for t in ["kernel", "bzimage", "image-initramfs", "vmlinuz"])]
    rootfses = [p for p in bin_targets if p.is_file() and "rootfs" in p.name.lower() and any(p.name.lower().endswith(s) for s in [".img", ".img.gz", ".bin", ".bin.gz"])]
    disks = [p for p in bin_targets if p.is_file() and any(t in p.name.lower() for t in ["combined", "sdcard", "efi"]) and any(p.name.lower().endswith(s) for s in [".img", ".img.gz", ".vmdk", ".vdi"])]

    if args.arch == "x86_64":
        kernel = first(kernels, ["initramfs", "generic-kernel", "kernel", "bzimage"])
        rootfs = first(rootfses, ["rootfs", "argosfs"])
        disk = first(disks, ["combined", "generic", "efi"])
    elif args.arch == "arm64":
        kernel = first(kernels, ["initramfs", "generic-kernel", "image"])
        rootfs = first(rootfses, ["rootfs", "argosfs"])
        disk = first(disks, ["combined-efi", "combined", "generic"])
        # arm64 now uses compressed EFI/GRUB kernels. Prefer the complete UEFI
        # disk image for QEMU so the same boot path is tested as release images,
        # instead of asking qemu -kernel to load a compressed kernel directly.
        if disk is not None:
            kernel = None
            rootfs = None
    else:
        kernel = first(kernels, ["initramfs", "image", "kernel"])
        rootfs = first(rootfses, ["rootfs", "argosfs"])
        disk = first(disks, ["sdcard", "sifive", "unmatched"])

    rootfs_raw = maybe_decompress(rootfs, out / "raw")
    disk_raw = maybe_decompress(disk, out / "raw")

    # Prefer direct kernel+rootfs for the existing serial-console harnesses. Fall
    # back to a complete disk image when a target only emits bootable disk images.
    boot_mode = "none"
    if kernel and rootfs_raw:
        boot_mode = "kernel-rootfs"
    elif disk_raw:
        boot_mode = "disk"

    manifest = {
        "arch": args.arch,
        "artifacts_root": str(root),
        "boot_mode": boot_mode,
        "kernel": str(kernel or ""),
        "rootfs": str(rootfs_raw or ""),
        "rootfs_source": str(rootfs or ""),
        "disk_image": str(disk_raw or ""),
        "disk_image_source": str(disk or ""),
        "candidate_counts": {
            "kernel": len(kernels),
            "rootfs": len(rootfses),
            "disk": len(disks),
        },
        "bin_targets": [str(p) for p in sorted(bin_targets) if p.is_file()][:300],
    }
    (out / "qemu-artifacts.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    env = {
        "boot_mode": boot_mode,
        "kernel": str(kernel or ""),
        "rootfs": str(rootfs_raw or ""),
        "disk_image": str(disk_raw or ""),
        "manifest": str(out / "qemu-artifacts.json"),
    }
    emit_github_output(env)
    print(json.dumps(manifest, indent=2))
    if args.require_bootable and boot_mode == "none":
        raise SystemExit("no bootable CapOS QEMU artifact was discovered")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
