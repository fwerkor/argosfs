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


def check_sticky(root):
    sticky = path(root, b"sticky")
    os.mkdir(sticky, 0o777)
    os.chmod(sticky, 0o1777)
    require(stat.S_IMODE(os.stat(sticky).st_mode) == 0o1777, "sticky directory mode mismatch")

    if os.geteuid() != 0:
        log("skipped", "sticky-cross-user", "requires root to switch uid safely")
        return
    try:
        nobody = pwd.getpwnam("nobody").pw_uid
    except KeyError:
        log("skipped", "sticky-cross-user", "nobody user unavailable")
        return

    victim = path(sticky, b"victim")
    with open(victim, "wb") as f:
        f.write(b"victim")
    os.chown(victim, 0, os.getgid())

    child = os.fork()
    if child == 0:
        try:
            os.setuid(nobody)
            try:
                os.unlink(victim)
            except PermissionError:
                os._exit(0)
            os._exit(2)
        except BaseException:
            os._exit(3)
    _, status_code = os.waitpid(child, 0)
    require(os.WIFEXITED(status_code) and os.WEXITSTATUS(status_code) == 0, "sticky cross-user unlink was not denied")
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
            result.get(timeout=5)
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
        check_sticky,
        check_concurrency,
    ]
    for check in checks:
        check(root)
    log("passed", "all")


if __name__ == "__main__":
    main()
