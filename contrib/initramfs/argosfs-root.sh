#!/bin/sh
set -eu

: "${ARGOSFS_ROOT:=/argos-volume}"
: "${ARGOSFS_NEWROOT:=/newroot}"

mkdir -p "$ARGOSFS_NEWROOT"
modprobe fuse 2>/dev/null || true

argosfs fsck "$ARGOSFS_ROOT" --repair --remove-orphans
argosfs mount "$ARGOSFS_ROOT" "$ARGOSFS_NEWROOT" --foreground -o allow_other &

tries=0
while [ "$tries" -lt 50 ]; do
    if [ -x "$ARGOSFS_NEWROOT/sbin/init" ] || [ -x "$ARGOSFS_NEWROOT/init" ]; then
        break
    fi
    tries=$((tries + 1))
    sleep 0.1
done

exec switch_root "$ARGOSFS_NEWROOT" /sbin/init
