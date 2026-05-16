#!/usr/bin/env bash
set -euo pipefail

mountpoint="${1:-/mnt/argosfs}"
out="${2:-paper-data/compat/pjdfstest.jsonl}"
mkdir -p "$(dirname "$out")"

if ! command -v prove >/dev/null 2>&1 || [ ! -d pjdfstest ]; then
  printf '{"suite":"pjdfstest","status":"skipped","reason":"pjdfstest checkout or prove unavailable"}\n' > "$out"
  cat "$out"
  exit 0
fi

(cd pjdfstest && prove -r tests) > "${out%.jsonl}.log" 2>&1 || status="failed"
status="${status:-passed}"
printf '{"suite":"pjdfstest","mountpoint":"%s","status":"%s","log":"%s"}\n' "$mountpoint" "$status" "${out%.jsonl}.log" > "$out"
cat "$out"
