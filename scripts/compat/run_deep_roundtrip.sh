#!/usr/bin/env bash
set -euo pipefail

work="${1:-/tmp/argosfs-deep-roundtrip}"
root="$work/volume"
src="$work/source"
export1="$work/export1"
export2="$work/export2"
bin="${ARGOSFS_BIN:-target/release/argosfs}"

rm -rf "$work"
mkdir -p "$work"

cargo build --release >/dev/null
"$bin" mkfs "$root" --force --disks 6 --k 4 --m 2 >/dev/null

python3 - "$src" <<'PY'
import errno
import os
import stat
import sys

root = os.fsencode(sys.argv[1])
os.makedirs(root, exist_ok=True)

def p(*parts):
    return os.path.join(root, *parts)

names = {
    "nonutf8_dir": b"dir-\xff",
    "nonutf8_file": b"file-\xfe.txt",
    "prefix_nonutf8": b".argosfs-name-nonutf8-v3:literal",
    "prefix_utf8": b".argosfs-name-utf8-v3:literal",
    "old_v2_literal": b".argosfs-name-bytes-v2:ff",
    "link": b"link-\xfd",
}

os.mkdir(p(names["nonutf8_dir"]))
with open(p(names["nonutf8_dir"], names["nonutf8_file"]), "wb") as f:
    f.write(b"payload-\x00-\xff-\n")

for key in ["prefix_nonutf8", "prefix_utf8", "old_v2_literal"]:
    with open(p(names[key]), "wb") as f:
        f.write(key.encode())

target = os.path.join(b"..", names["nonutf8_dir"], names["nonutf8_file"])
os.symlink(target, p(names["nonutf8_dir"], names["link"]))

os.chmod(p(names["nonutf8_dir"], names["nonutf8_file"]), 0o755)
os.utime(p(names["nonutf8_dir"], names["nonutf8_file"]), ns=(1_700_000_001_123_456_789, 1_700_000_002_987_654_321), follow_symlinks=False)

try:
    os.setxattr(p(names["nonutf8_dir"], names["nonutf8_file"]), b"user.argosfs.deep", b"xattr-\x00-value", follow_symlinks=False)
    os.setxattr(p(names["prefix_nonutf8"]), b"user.argosfs.prefix", b"prefix-value", follow_symlinks=False)
except OSError as e:
    if e.errno not in (errno.EOPNOTSUPP, errno.ENOTSUP, errno.EPERM, errno.EACCES):
        raise
PY

"$bin" import-tree "$root" "$src" /
"$bin" export-tree "$root" "$export1"

python3 - "$src" "$export1" <<'PY'
import os
import stat
import sys

src = os.fsencode(sys.argv[1])
dst = os.fsencode(sys.argv[2])

def read_user_xattrs(path):
    out = {}
    try:
        names = os.listxattr(path, follow_symlinks=False)
    except OSError:
        return out
    for name in names:
        raw = os.fsencode(name)
        if raw.startswith(b"user.argosfs."):
            out[raw] = os.getxattr(path, name, follow_symlinks=False)
    return out

def snapshot(root):
    out = {}
    stack = [b""]
    while stack:
        rel = stack.pop()
        path = os.path.join(root, rel) if rel else root
        st = os.lstat(path)
        kind = stat.S_IFMT(st.st_mode)
        item = {
            "kind": kind,
            "mode": st.st_mode & 0o7777,
            "xattrs": read_user_xattrs(path),
        }
        if stat.S_ISREG(kind):
            with open(path, "rb") as f:
                item["data"] = f.read()
        elif stat.S_ISLNK(kind):
            item["target"] = os.readlink(path)
        elif stat.S_ISDIR(kind):
            for child in os.listdir(path):
                stack.append(os.path.join(rel, child) if rel else child)
        out[rel] = item
    return out

a = snapshot(src)
b = snapshot(dst)

if set(a) != set(b):
    missing = sorted(set(a) - set(b))
    extra = sorted(set(b) - set(a))
    raise SystemExit(f"path mismatch missing={missing!r} extra={extra!r}")

for rel in sorted(a):
    aa, bb = a[rel], b[rel]
    for key in ["kind", "data", "target", "xattrs"]:
        if aa.get(key) != bb.get(key):
            raise SystemExit(f"mismatch at {rel!r} key={key}: {aa.get(key)!r} != {bb.get(key)!r}")

print("import/export byte roundtrip: ok")
PY

# Path API literal-prefix regression checks.
printf 'prefix-via-cli\n' > "$work/local.txt"
"$bin" mkdir "$root" "/.argosfs-name-nonutf8-v3:cli-dir"
"$bin" put "$root" "$work/local.txt" "/.argosfs-name-nonutf8-v3:cli-dir/.argosfs-name-utf8-v3:file"
"$bin" rename "$root" \
  "/.argosfs-name-nonutf8-v3:cli-dir/.argosfs-name-utf8-v3:file" \
  "/.argosfs-name-nonutf8-v3:cli-dir/.argosfs-name-bytes-v2:ff"
"$bin" export-tree "$root" "$export2"

python3 - "$export2" <<'PY'
import os
import sys
root = os.fsencode(sys.argv[1])
expected = os.path.join(root, b".argosfs-name-nonutf8-v3:cli-dir", b".argosfs-name-bytes-v2:ff")
if not os.path.exists(expected):
    raise SystemExit(f"CLI prefix-literal export missing: {expected!r}")
with open(expected, "rb") as f:
    if f.read() != b"prefix-via-cli\n":
        raise SystemExit("CLI prefix-literal file content mismatch")
print("path API prefix literals: ok")
PY

# --json should be compact one-object one-line output.
"$bin" autopilot "$root" --dry-run --json > "$work/autopilot.json"
python3 - "$work/autopilot.json" <<'PY'
import json
import sys
text = open(sys.argv[1], "r", encoding="utf-8").read()
if text.count("\n") != 1:
    raise SystemExit("--json output is not one line")
json.loads(text)
print("autopilot --json: ok")
PY

# Optional FUSE smoke extension. Enable with ARGOSFS_DEEP_FUSE=1.
if [ "${ARGOSFS_DEEP_FUSE:-0}" = "1" ]; then
  mnt="$work/mnt"
  mkdir -p "$mnt"
  "$bin" mount "$root" "$mnt" --foreground &
  pid=$!
  trap 'fusermount3 -u "$mnt" >/dev/null 2>&1 || true; kill "$pid" >/dev/null 2>&1 || true' EXIT

  mounted=0
  for _ in $(seq 1 80); do
    if ! kill -0 "$pid" >/dev/null 2>&1; then
      echo "FUSE mount process exited early" >&2
      exit 1
    fi
    if mountpoint -q "$mnt"; then
      mounted=1
      break
    fi
    sleep 0.1
  done
  [ "$mounted" = 1 ] || { echo "FUSE mountpoint did not become ready" >&2; exit 1; }

  python3 - "$mnt" <<'PY'
import os
import sys
mnt = os.fsencode(sys.argv[1])
name = b"fuse-\xff"
path = os.path.join(mnt, name)
with open(path, "wb") as f:
    f.write(b"fuse-data")
if name not in os.listdir(mnt):
    raise SystemExit("non-UTF8 FUSE readdir did not round-trip")
os.symlink(name, os.path.join(mnt, b"fuse-link-\xfe"))
if os.readlink(os.path.join(mnt, b"fuse-link-\xfe")) != name:
    raise SystemExit("FUSE symlink target did not round-trip")
print("optional FUSE byte smoke: ok")
PY

  fusermount3 -u "$mnt"
  kill "$pid" >/dev/null 2>&1 || true
  trap - EXIT
fi

echo "deep roundtrip checks passed: $work"
