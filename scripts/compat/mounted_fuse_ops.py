#!/usr/bin/env python3
import ctypes
import errno
import multiprocessing
import os
import pwd
import stat
import sys
import time


def log(status, check, message=""):
    print(
        f'{{"suite":"mounted-fuse-ops","status":"{status}",'
        f'"check":"{check}","message":"{message}"}}',
        flush=True,
    )


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def require_cross_user():
    return os.environ.get("ARGOSFS_REQUIRE_CROSS_USER", "0") == "1"


def nobody_identity():
    try:
        entry = pwd.getpwnam("nobody")
    except KeyError as exc:
        if require_cross_user():
            raise AssertionError("nobody user unavailable for mandatory cross-user checks") from exc
        return None
    return entry.pw_uid, entry.pw_gid


def run_as_identity(uid, gid, action, supplementary_groups=None):
    read_fd, write_fd = os.pipe()
    child = os.fork()
    if child == 0:
        os.close(read_fd)
        try:
            os.setgroups(supplementary_groups or [])
            os.setgid(gid)
            os.setuid(uid)
            action()
        except BaseException as exc:
            os.write(write_fd, repr(exc).encode("utf-8", "backslashreplace")[:4096])
            os._exit(1)
        os._exit(0)
    os.close(write_fd)
    message = b""
    while True:
        chunk = os.read(read_fd, 4096)
        if not chunk:
            break
        message += chunk
    os.close(read_fd)
    _, status_code = os.waitpid(child, 0)
    return status_code, message.decode("utf-8", "replace")


def require_identity_action(uid, gid, action, description, supplementary_groups=None):
    status_code, message = run_as_identity(uid, gid, action, supplementary_groups)
    require(
        os.WIFEXITED(status_code) and os.WEXITSTATUS(status_code) == 0,
        f"{description} failed for uid={uid} gid={gid}: {message}",
    )


def expect_permission_denied(action):
    try:
        action()
    except OSError as exc:
        if exc.errno in (errno.EACCES, errno.EPERM):
            return
        raise AssertionError(f"unexpected denial errno={exc.errno}") from exc
    raise AssertionError("operation unexpectedly succeeded")


def path(root, *parts):
    return os.path.join(root, *parts)


def check_file_io(root):
    p = path(root, b"io.bin")
    fd = os.open(p, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o640)
    try:
        require(os.write(fd, b"hello") == 5, "short write")
        os.lseek(fd, 0, os.SEEK_SET)
        require(os.read(fd, 5) == b"hello", "read-after-write mismatch")
        os.ftruncate(fd, 2)
        os.lseek(fd, 0, os.SEEK_SET)
        require(os.read(fd, 8) == b"he", "truncate shrink mismatch")
        os.ftruncate(fd, 8)
        os.lseek(fd, 0, os.SEEK_SET)
        require(os.read(fd, 8) == b"he\x00\x00\x00\x00\x00\x00", "truncate grow mismatch")
        os.fsync(fd)
    finally:
        os.close(fd)
    os.sync()
    log("passed", "create-read-write-truncate-fsync")


def check_metadata(root):
    p = path(root, b"metadata.txt")
    with open(p, "wb") as f:
        f.write(b"metadata")
    os.chmod(p, 0o600)
    st = os.stat(p)
    require(stat.S_IMODE(st.st_mode) == 0o600, f"chmod mode is {oct(stat.S_IMODE(st.st_mode))}")

    atime_ns = 1_700_000_101_123_456_789
    mtime_ns = 1_700_000_102_987_654_321
    os.utime(p, ns=(atime_ns, mtime_ns))
    st = os.stat(p)
    require(abs(st.st_mtime_ns - mtime_ns) < 1_000_000, f"mtime mismatch {st.st_mtime_ns} != {mtime_ns}")
    require(abs(st.st_atime_ns - atime_ns) < 1_000_000, "atime was not updated close to requested value")

    try:
        os.chown(p, os.getuid(), os.getgid())
        st = os.stat(p)
        require(st.st_uid == os.getuid() and st.st_gid == os.getgid(), "chown to current uid/gid mismatch")
        log("passed", "chown")
    except PermissionError:
        log("skipped", "chown", "current user is not permitted to chown")

    log("passed", "chmod-utimens-stat")


def check_xattrs(root):
    p = path(root, b"xattr.txt")
    with open(p, "wb") as f:
        f.write(b"xattrs")
    os.setxattr(p, b"user.argosfs.compat", b"value-\x00-bytes")
    require(os.getxattr(p, b"user.argosfs.compat") == b"value-\x00-bytes", "xattr value mismatch")
    require(b"user.argosfs.compat" in [os.fsencode(x) for x in os.listxattr(p)], "xattr missing from listxattr")
    log("passed", "xattrs")


def check_links(root):
    target = path(root, b"target.txt")
    with open(target, "wb") as f:
        f.write(b"link target")

    symlink = path(root, b"symlink")
    os.symlink(b"target.txt", symlink)
    require(os.readlink(symlink) == b"target.txt", "readlink mismatch")

    hardlink = path(root, b"hardlink.txt")
    os.link(target, hardlink)
    a = os.stat(target)
    b = os.stat(hardlink)
    require(a.st_ino == b.st_ino, f"hardlink inode mismatch {a.st_ino} != {b.st_ino}")
    require(a.st_nlink >= 2 and b.st_nlink >= 2, "hardlink count was not updated")
    log("passed", "symlink-readlink-hardlink-inode")


def check_non_utf8(root):
    name = b"name-\xff-\xfe.bin"
    p = path(root, name)
    with open(p, "wb") as f:
        f.write(b"bytes path")
    require(name in os.listdir(root), "non-UTF-8 filename missing from readdir")
    with open(p, "rb") as f:
        require(f.read() == b"bytes path", "non-UTF-8 filename read mismatch")
    log("passed", "non-utf8-filenames")


def renameat2_noreplace(src, dst):
    if not sys.platform.startswith("linux"):
        return errno.ENOSYS
    libc = ctypes.CDLL(None, use_errno=True)
    syscall = libc.syscall
    syscall.restype = ctypes.c_long
    syscall.argtypes = [ctypes.c_long, ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    SYS_renameat2 = 316 if ctypes.sizeof(ctypes.c_void_p) == 8 else 353
    ret = syscall(SYS_renameat2, -100, src, -100, dst, 1)
    if ret == 0:
        return 0
    return ctypes.get_errno()


def check_rename(root):
    src = path(root, b"rename-src")
    dst = path(root, b"rename-dst")
    with open(src, "wb") as f:
        f.write(b"src")
    with open(dst, "wb") as f:
        f.write(b"dst")
    os.rename(src, dst)
    with open(dst, "rb") as f:
        require(f.read() == b"src", "rename overwrite did not replace destination")

    nr_src = path(root, b"rename-noreplace-src")
    nr_dst = path(root, b"rename-noreplace-dst")
    with open(nr_src, "wb") as f:
        f.write(b"src")
    with open(nr_dst, "wb") as f:
        f.write(b"dst")
    err = renameat2_noreplace(nr_src, nr_dst)
    if err == errno.EEXIST:
        require(os.path.exists(nr_src), "RENAME_NOREPLACE removed source on EEXIST")
        with open(nr_dst, "rb") as f:
            require(f.read() == b"dst", "RENAME_NOREPLACE overwrote destination")
        log("passed", "rename-noreplace")
    elif err in (errno.ENOSYS, errno.EINVAL, errno.ENOTSUP, errno.EOPNOTSUPP):
        log("skipped", "rename-noreplace", f"renameat2 unsupported errno={err}")
    else:
        raise AssertionError(f"unexpected RENAME_NOREPLACE errno={err}")

    log("passed", "rename-overwrite")


def check_readdirplus_permission(root, identity=None, check_metadata=True):
    if os.geteuid() != 0:
        if require_cross_user():
            raise AssertionError("mandatory readdirplus permission check must run as root")
        log("skipped", "readdirplus-search-permission", "requires root to switch uid and gid")
        return
    if not require_cross_user():
        log("skipped", "readdirplus-search-permission", "requires an allow_other test mount")
        return
    identity = identity or nobody_identity()
    if identity is None:
        log("skipped", "readdirplus-search-permission", "nobody user unavailable")
        return
    nobody_uid, nobody_gid = identity

    readable = path(root, b"readable-no-search")
    os.mkdir(readable, 0o700)
    readable_child = path(readable, b"visible-name")
    with open(readable_child, "wb") as f:
        f.write(b"name")
    os.chown(readable, nobody_uid, nobody_gid)
    os.chmod(readable, 0o400)
    require_identity_action(
        nobody_uid,
        nobody_gid,
        lambda: require(os.listdir(readable) == [b"visible-name"], "directory listing mismatch"),
        "readable directory listing without search permission",
    )
    if not check_metadata:
        return

    time.sleep(5.1)

    def expect_scandir_metadata_denied():
        try:
            entries = list(os.scandir(readable))
        except PermissionError:
            return
        require(len(entries) == 1, "scandir entry count mismatch")
        expect_permission_denied(lambda: entries[0].stat(follow_symlinks=False))

    require_identity_action(
        nobody_uid,
        nobody_gid,
        expect_scandir_metadata_denied,
        "directory metadata denial without search permission",
    )
    log("passed", "readdirplus-search-permission")


def check_permission_enforcement(root):
    if os.geteuid() != 0:
        if require_cross_user():
            raise AssertionError("mandatory permission checks must run as root")
        log("skipped", "cross-user-permissions", "requires root to switch uid and gid")
        return
    if not require_cross_user():
        log("skipped", "cross-user-permissions", "requires an allow_other test mount")
        return
    identity = nobody_identity()
    if identity is None:
        log("skipped", "cross-user-permissions", "nobody user unavailable")
        return
    nobody_uid, nobody_gid = identity

    private = path(root, b"private-root.txt")
    with open(private, "wb") as f:
        f.write(b"private")
    os.chown(private, 0, 0)
    os.chmod(private, 0o600)
    require_identity_action(
        nobody_uid,
        nobody_gid,
        lambda: expect_permission_denied(lambda: open(private, "rb").close()),
        "other-user read denial on mode 0600",
    )
    require_identity_action(
        nobody_uid,
        nobody_gid,
        lambda: expect_permission_denied(lambda: open(private, "ab").close()),
        "other-user write denial on mode 0600",
    )

    os.chmod(private, 0o644)
    require_identity_action(
        nobody_uid,
        nobody_gid,
        lambda: require(open(private, "rb").read() == b"private", "public read content mismatch"),
        "other-user read on mode 0644",
    )
    require_identity_action(
        nobody_uid,
        nobody_gid,
        lambda: expect_permission_denied(lambda: open(private, "ab").close()),
        "other-user write denial on mode 0644",
    )

    os.chmod(private, 0o666)
    def append_public():
        with open(private, "ab") as f:
            f.write(b"-other")
    require_identity_action(nobody_uid, nobody_gid, append_public, "other-user write on mode 0666")
    require(open(private, "rb").read() == b"private-other", "cross-user append was not persisted")

    locked = path(root, b"locked-dir")
    os.mkdir(locked, 0o700)
    locked_file = path(locked, b"inside.txt")
    with open(locked_file, "wb") as f:
        f.write(b"inside")
    os.chmod(locked_file, 0o644)
    require_identity_action(
        nobody_uid,
        nobody_gid,
        lambda: expect_permission_denied(lambda: open(locked_file, "rb").close()),
        "directory search denial",
    )
    os.chmod(locked, 0o711)
    require_identity_action(
        nobody_uid,
        nobody_gid,
        lambda: require(open(locked_file, "rb").read() == b"inside", "search-enabled read mismatch"),
        "directory search permission",
    )

    inherited_gid = nobody_gid + 1 if nobody_gid < 2**32 - 1 else nobody_gid - 1
    inherited = path(root, b"setgid-dir")
    os.mkdir(inherited, 0o755)
    os.chown(inherited, 0, inherited_gid)
    os.chmod(inherited, 0o2777)
    inherited_file = path(inherited, b"child.txt")
    def create_in_setgid_dir():
        fd = os.open(inherited_file, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o664)
        os.write(fd, b"setgid")
        os.close(fd)
    require_identity_action(
        nobody_uid,
        nobody_gid,
        create_in_setgid_dir,
        "setgid directory create",
        [inherited_gid],
    )
    inherited_stat = os.stat(inherited_file)
    require(inherited_stat.st_uid == nobody_uid, "created file owner did not match request uid")
    require(inherited_stat.st_gid == inherited_gid, "setgid directory group was not inherited")
    os.chown(inherited_file, 0, inherited_gid)
    os.chmod(inherited_file, 0o620)
    def append_through_supplementary_group():
        with open(inherited_file, "ab") as f:
            f.write(b"-group")
    require_identity_action(
        nobody_uid,
        nobody_gid,
        append_through_supplementary_group,
        "supplementary-group writeback",
        [inherited_gid],
    )
    require(open(inherited_file, "rb").read() == b"setgid-group", "group writeback was not persisted")

    check_readdirplus_permission(root, identity, check_metadata=False)

    owned = path(root, b"owned-by-nobody.txt")
    with open(owned, "wb") as f:
        f.write(b"owned")
    os.chown(owned, nobody_uid, nobody_gid)
    os.chmod(owned, 0o600)
    def owner_update():
        with open(owned, "r+b") as f:
            require(f.read() == b"owned", "chowned file read mismatch")
            f.seek(0, os.SEEK_END)
            f.write(b"-updated")
    require_identity_action(nobody_uid, nobody_gid, owner_update, "chowned owner access")
    require(open(owned, "rb").read() == b"owned-updated", "chowned owner update was not persisted")

    truncate_open = path(root, b"truncate-open-handle.txt")
    with open(truncate_open, "wb") as f:
        f.write(b"truncate-me")
    os.chown(truncate_open, nobody_uid, nobody_gid)
    os.chmod(truncate_open, 0o600)
    def truncate_after_mode_change():
        fd = os.open(truncate_open, os.O_WRONLY)
        try:
            os.chmod(truncate_open, 0)
            os.ftruncate(fd, 3)
        finally:
            os.close(fd)
    require_identity_action(
        nobody_uid,
        nobody_gid,
        truncate_after_mode_change,
        "truncate through an already-open writable handle",
    )
    require(os.stat(truncate_open).st_size == 3, "open-handle truncate size mismatch")
    log("passed", "cross-user-permissions")


def check_sticky(root):
    sticky = path(root, b"sticky")
    os.mkdir(sticky, 0o777)
    os.chmod(sticky, 0o1777)
    require(stat.S_IMODE(os.stat(sticky).st_mode) == 0o1777, "sticky directory mode mismatch")

    if os.geteuid() != 0:
        if require_cross_user():
            raise AssertionError("mandatory sticky-directory check must run as root")
        log("skipped", "sticky-cross-user", "requires root to switch uid safely")
        return
    identity = nobody_identity()
    if identity is None:
        log("skipped", "sticky-cross-user", "nobody user unavailable")
        return
    nobody_uid, nobody_gid = identity

    victim = path(sticky, b"victim")
    with open(victim, "wb") as f:
        f.write(b"victim")
    os.chown(victim, 0, 0)
    require_identity_action(
        nobody_uid,
        nobody_gid,
        lambda: expect_permission_denied(lambda: os.unlink(victim)),
        "sticky cross-user unlink denial",
    )
    require(os.path.exists(victim), "sticky-directory victim disappeared after denied unlink")
    log("passed", "sticky-cross-user")


def writer(args):
    filename, byte, count = args
    with open(filename, "wb", buffering=0) as f:
        for _ in range(count):
            f.write(bytes([byte]) * 128)
        os.fsync(f.fileno())


def reader(args):
    filename, deadline = args
    while time.monotonic() < deadline:
        if os.path.exists(filename):
            with open(filename, "rb") as f:
                f.read()
        time.sleep(0.01)


def check_concurrency(root):
    seed = path(root, b"concurrent-seed.log")
    with open(seed, "wb") as f:
        f.write(b"seed" * 1024)
    deadline = time.monotonic() + 1
    with multiprocessing.Pool(processes=6) as pool:
        results = []
        for byte in range(4):
            results.append(pool.apply_async(writer, ((path(root, f"concurrent-{byte}.log".encode()), 65 + byte, 8),)))
        for _ in range(2):
            results.append(pool.apply_async(reader, ((seed, deadline),)))
        for result in results:
            result.get(timeout=20)
    for byte in range(4):
        p = path(root, f"concurrent-{byte}.log".encode())
        require(os.stat(p).st_size == 8 * 128, f"concurrent writer size mismatch for {p!r}")
    log("passed", "concurrent-readers-writers")


def main():
    if len(sys.argv) != 2:
        raise SystemExit(f"usage: {sys.argv[0]} MOUNTPOINT")
    root = os.fsencode(sys.argv[1])
    if not os.path.isdir(root):
        raise SystemExit("mountpoint is not a directory")

    checks = [
        check_file_io,
        check_metadata,
        check_xattrs,
        check_links,
        check_non_utf8,
        check_rename,
        check_permission_enforcement,
        check_sticky,
        check_concurrency,
    ]
    requested_check = os.environ.get("ARGOSFS_COMPAT_CHECK")
    if requested_check:
        available_checks = {
            "readdirplus-permissions": check_readdirplus_permission,
        }
        if requested_check not in available_checks:
            raise SystemExit(f"unknown ARGOSFS_COMPAT_CHECK: {requested_check}")
        checks = [available_checks[requested_check]]
    for check in checks:
        check(root)
    log("passed", "all")


if __name__ == "__main__":
    main()
