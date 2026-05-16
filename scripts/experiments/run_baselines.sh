#!/usr/bin/env bash
set -euo pipefail

mode="quick"
out="paper-data/raw/baselines.jsonl"
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
for baseline in argosfs-autopilot argosfs-manual btrfs-raid1 zfs-mirror mdadm-lvm mergerfs-snapraid; do
  available=false
  case "$baseline" in
    argosfs-*) available=true ;;
  esac
  printf '{"mode":"%s","baseline":"%s","available":%s,"metric":"setup-documented"}\n' "$mode" "$baseline" "$available" >> "$out"
done
