#!/usr/bin/env bash
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
profile_dir="${ARGOSFS_COVERAGE_PROFILE_DIR:-$repo/target}"
quarantine_dir="${ARGOSFS_COVERAGE_QUARANTINE_DIR:-$profile_dir/corrupt-coverage-profiles}"

if [ ! -d "$profile_dir" ]; then
	echo "ERROR: coverage profile directory does not exist: $profile_dir" >&2
	exit 1
fi

sysroot="$(rustc --print sysroot)"
host="$(rustc -vV | sed -n 's/^host: //p')"
llvm_profdata="$sysroot/lib/rustlib/$host/bin/llvm-profdata"
if [ ! -x "$llvm_profdata" ]; then
	echo "ERROR: llvm-profdata is unavailable: $llvm_profdata" >&2
	exit 2
fi

scratch="$(mktemp "$profile_dir/.argosfs-profdata-check.XXXXXX")"
rm -f "$scratch"
trap 'rm -f "$scratch"' EXIT

valid=0
invalid=0
total=0
while IFS= read -r -d '' profile; do
	total=$((total + 1))
	rm -f "$scratch"
	if "$llvm_profdata" merge -sparse "$profile" -o "$scratch" >/dev/null 2>&1; then
		valid=$((valid + 1))
		continue
	fi

	invalid=$((invalid + 1))
	mkdir -p "$quarantine_dir"
	destination="$quarantine_dir/$(basename "$profile").corrupt"
	mv "$profile" "$destination"
	echo "WARNING: quarantined corrupt coverage profile: $destination" >&2
done < <(find "$profile_dir" -maxdepth 1 -type f -name 'argosfs-*.profraw' -print0)

if ((total == 0)); then
	echo "ERROR: no ArgosFS coverage profiles were produced in $profile_dir" >&2
	exit 1
fi
if ((valid == 0)); then
	echo "ERROR: all $total ArgosFS coverage profiles were corrupt" >&2
	exit 1
fi

printf 'coverage profiles: valid=%d quarantined=%d total=%d\n' "$valid" "$invalid" "$total"
