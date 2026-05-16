#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
out="${ARGOSFS_PJDFSTEST_OUT:-paper-data/compat/pjdfstest.jsonl}"

json_escape() {
  local value="$1"
  value="${value//\\/\\\\}"
  value="${value//\"/\\\"}"
  value="${value//$'\n'/\\n}"
  printf '%s' "$value"
}

record() {
  local status="$1"
  local reason="$2"
  local mountpoint="${3:-}"
  local log="${4:-}"
  mkdir -p "$(dirname "$out")"
  printf '{"suite":"pjdfstest","status":"%s","reason":"%s","mountpoint":"%s","log":"%s"}\n' \
    "$status" "$(json_escape "$reason")" "$mountpoint" "$log" > "$out"
  cat "$out"
}

usage() {
  cat <<'EOF'
usage:
  scripts/compat/run_pjdfstest.sh [OUT]
  scripts/compat/run_pjdfstest.sh --mounted MOUNTPOINT [OUT]

Default mode creates and verifies a temporary ArgosFS FUSE mount before running
the documented pjdfstest subset. --mounted is for an already-mounted ArgosFS
directory and still requires mountpoint(1) to confirm the target.
EOF
}

run_on_mount() {
  local mountpoint="$1"
  local repo_root="$2"
  local tests_root="${PJDFSTEST_ROOT:-$repo_root/pjdfstest}"
  local tests_dir="$tests_root/tests"
  local status="passed"
  local selected=()
  local requested="${ARGOSFS_PJDFSTEST_TESTS:-chmod chown link mkdir open rename rmdir symlink truncate unlink utimensat}"
  local name
  local log="${out%.jsonl}.log"

  if ! command -v python3 >/dev/null 2>&1; then
    record skipped "python3 unavailable" "$mountpoint"
    return 0
  fi
  if ! command -v prove >/dev/null 2>&1; then
    record skipped "prove unavailable" "$mountpoint"
    return 0
  fi
  if [ ! -d "$tests_dir" ]; then
    record skipped "pjdfstest checkout unavailable; set PJDFSTEST_ROOT or clone pjdfstest at repo root" "$mountpoint"
    return 0
  fi
  if [ ! -d "$mountpoint" ]; then
    record failed "mountpoint is not a directory" "$mountpoint"
    return 1
  fi
  if ! mountpoint -q "$mountpoint"; then
    record failed "target is not an actual mounted filesystem" "$mountpoint"
    return 1
  fi

  for name in $requested; do
    if [ -e "$tests_dir/$name" ]; then
      selected+=("$tests_dir/$name")
    fi
  done
  if [ "${#selected[@]}" -eq 0 ]; then
    record failed "no requested pjdfstest subset entries found under $tests_dir" "$mountpoint"
    return 1
  fi

  mkdir -p "$(dirname "$out")"
  (
    cd "$mountpoint"
    prove -r "${selected[@]}"
  ) > "$log" 2>&1 || status="failed"

  record "$status" "subset: $requested" "$mountpoint" "$log"
  [ "$status" = "passed" ]
}

if [ "${1:-}" = "--help" ]; then
  usage
  exit 0
fi

if [ "${1:-}" = "--mounted" ]; then
  if [ "$#" -lt 2 ]; then
    usage >&2
    exit 2
  fi
  mountpoint="$2"
  if [ "$#" -ge 3 ]; then
    out="$3"
  fi
  run_on_mount "$mountpoint" "$repo_root"
  exit $?
fi

if [ "$#" -ge 1 ]; then
  out="$1"
fi

export ARGOSFS_COMPAT_SUITE="${ARGOSFS_COMPAT_SUITE:-pjdfstest}"
"$repo_root/scripts/compat/with_fuse_mount.sh" \
  bash -c '"$1" --mounted "$ARGOSFS_COMPAT_MOUNTPOINT" "$2"' _ "$0" "$out"
