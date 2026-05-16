#!/usr/bin/env bash
set -euo pipefail

mode="quick"
out="paper-data/raw/qemu-rootfs.jsonl"
while [ "$#" -gt 0 ]; do
  case "$1" in
    --mode) shift; mode="$1" ;;
    --output) shift; out="$1" ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
  shift
done

mkdir -p "$(dirname "$out")"
: > "$out"
for scenario in normal-boot clean-shutdown interrupted-write degraded-disk emergency-readonly; do
  status="not-run"
  command -v qemu-system-x86_64 >/dev/null 2>&1 && status="requires-rootfs-image"
  printf '{"mode":"%s","scenario":"%s","status":"%s","output":"jsonl"}\n' "$mode" "$scenario" "$status" >> "$out"
done
