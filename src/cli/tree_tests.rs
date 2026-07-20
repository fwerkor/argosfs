use super::*;
use crate::types::VolumeConfig;
use std::ffi::OsStr;
use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
use tempfile::tempdir;

fn volume() -> (tempfile::TempDir, ArgosFs) {
    let dir = tempdir().unwrap();
    let volume = ArgosFs::create(
        dir.path(),
        VolumeConfig {
            k: 1,
            m: 0,
            ..VolumeConfig::default()
        },
        1,
        false,
    )
    .unwrap();
    (dir, volume)
}

#[test]
fn path_and_time_helpers_normalize_edge_cases() {
    assert_eq!(normalize_dest("  a//b/../c  "), "/a/c");
    assert_eq!(normalize_dest(""), "/");
    assert_eq!(
        export_target_from_path_bytes(Path::new("/tmp/out"), b"/a//b"),
        PathBuf::from("/tmp/out/a/b")
    );
    assert_eq!(
        export_target_from_path_bytes(Path::new("/tmp/out"), b"relative"),
        PathBuf::from("/tmp/out/relative")
    );
    assert!(is_internal_export_xattr("system.argosfs.hidden"));
    assert!(!is_internal_export_xattr("user.visible"));

    let negative = timespec_from_f64(-2.5);
    assert_eq!(negative.tv_sec, 0);
    assert_eq!(negative.tv_nsec, 0);
    let normal = timespec_from_f64(3.25);
    assert_eq!(normal.tv_sec, 3);
    assert_eq!(normal.tv_nsec, 250_000_000);
    let rounded = timespec_from_f64(4.999_999_999_9);
    assert_eq!(rounded.tv_sec, 4);
    assert_eq!(rounded.tv_nsec, 999_999_999);
}

#[test]
fn c_path_rejects_embedded_nul_and_syscall_helpers_report_missing_paths() {
    use std::os::unix::ffi::OsStrExt;
    let bad = Path::new(OsStr::from_bytes(b"bad\0path"));
    assert!(c_path(bad).is_err());
    assert!(lchown_path(bad, 0, 0).is_err());
    assert!(set_times_nofollow(bad, 0.0, 0.0).is_err());
    assert!(write_xattr_nofollow(bad, "user.test", b"x").is_err());
    assert!(read_xattr(bad, "user.test").is_err());
    assert!(read_xattrs(bad).is_err());

    let dir = tempdir().unwrap();
    let missing = dir.path().join("missing");
    assert!(lchown_path(&missing, unsafe { libc::geteuid() }, unsafe {
        libc::getegid()
    })
    .is_err());
    assert!(set_times_nofollow(&missing, 0.0, 0.0).is_err());
    assert!(read_xattrs(&missing).is_err());
}

#[test]
fn xattr_helpers_round_trip_values_without_following_symlinks() {
    let dir = tempdir().unwrap();
    let file = dir.path().join("file");
    fs::write(&file, b"data").unwrap();
    write_xattr_nofollow(&file, "user.argosfs-test", b"value").unwrap();
    assert_eq!(read_xattr(&file, "user.argosfs-test").unwrap(), b"value");
    let attrs = read_xattrs(&file).unwrap();
    assert!(attrs
        .iter()
        .any(|(name, value)| name == "user.argosfs-test" && value == b"value"));
    assert!(read_xattr(&file, "user.missing").is_err());
    assert!(write_xattr_nofollow(&file, "bad\0name", b"x").is_err());
    assert!(read_xattr(&file, "bad\0name").is_err());

    let link = dir.path().join("link");
    symlink(&file, &link).unwrap();
    assert!(read_xattrs(&link).unwrap().is_empty());
}

#[test]
fn export_target_preparation_replaces_or_rejects_conflicting_types() {
    let dir = tempdir().unwrap();
    let target = dir.path().join("target");
    prepare_export_target(&target, &NodeKind::File).unwrap();

    fs::write(&target, b"old").unwrap();
    prepare_export_target(&target, &NodeKind::Directory).unwrap();
    assert!(!target.exists());

    fs::create_dir(&target).unwrap();
    prepare_export_target(&target, &NodeKind::Directory).unwrap();
    assert!(target.is_dir());
    for kind in [NodeKind::File, NodeKind::Symlink, NodeKind::Special] {
        assert!(prepare_export_target(&target, &kind).is_err());
    }
    fs::remove_dir(&target).unwrap();

    let link_target = dir.path().join("link-target");
    fs::write(&link_target, b"x").unwrap();
    symlink(&link_target, &target).unwrap();
    prepare_export_target(&target, &NodeKind::Directory).unwrap();
    assert!(!target.exists());
}

#[test]
fn virtual_directory_creation_is_idempotent_and_rejects_file_components() {
    let (_root, volume) = volume();
    ensure_virtual_dir(&volume, "/", 0o700).unwrap();
    ensure_virtual_dir(&volume, " /a//b/c ", 0o711).unwrap();
    assert_eq!(volume.attr_path("/a", true).unwrap().mode & 0o777, 0o755);
    assert_eq!(volume.attr_path("/a/b", true).unwrap().mode & 0o777, 0o755);
    assert_eq!(
        volume.attr_path("/a/b/c", true).unwrap().mode & 0o777,
        0o711
    );
    ensure_virtual_dir(&volume, "/a/b/c", 0o700).unwrap();

    volume.create_file_path("/file", 0o600).unwrap();
    assert!(ensure_virtual_dir(&volume, "/file/child", 0o755).is_err());
}

#[test]
fn import_tree_rejects_non_directories_and_conflicting_destination_types() {
    let (_root, volume) = volume();
    let source_root = tempdir().unwrap();
    let source_file = source_root.path().join("file");
    fs::write(&source_file, b"x").unwrap();
    assert!(import_tree(&volume, &source_file, "/").is_err());

    volume.create_file_path("/conflict", 0o600).unwrap();
    assert!(import_tree(&volume, source_root.path(), "/conflict/child").is_err());

    let nested = source_root.path().join("nested");
    fs::create_dir(&nested).unwrap();
    fs::write(nested.join("leaf"), b"payload").unwrap();
    volume.create_file_path("/dest/nested", 0o600).unwrap_err();
    ensure_virtual_dir(&volume, "/dest", 0o755).unwrap();
    volume.create_file_path("/dest/nested", 0o600).unwrap();
    assert!(import_tree(&volume, source_root.path(), "/dest").is_err());
}

#[test]
fn import_and_export_preserve_files_links_fifo_metadata_and_xattrs() {
    let (_root, volume) = volume();
    let source = tempdir().unwrap();
    let nested = source.path().join("nested");
    fs::create_dir(&nested).unwrap();
    fs::set_permissions(&nested, fs::Permissions::from_mode(0o751)).unwrap();

    let file = nested.join("file.bin");
    fs::write(&file, b"roundtrip payload").unwrap();
    fs::set_permissions(&file, fs::Permissions::from_mode(0o640)).unwrap();
    write_xattr_nofollow(&file, "user.argosfs-test", b"metadata").unwrap();
    let hardlink = nested.join("hardlink.bin");
    fs::hard_link(&file, &hardlink).unwrap();
    let symlink_path = source.path().join("link");
    symlink(Path::new("nested/file.bin"), &symlink_path).unwrap();
    let fifo = source.path().join("pipe");
    let c_fifo = CString::new(fifo.as_os_str().as_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(c_fifo.as_ptr(), 0o620) }, 0);

    import_tree(&volume, source.path(), "/imported").unwrap();
    let file_attr = volume
        .attr_path("/imported/nested/file.bin", false)
        .unwrap();
    let link_attr = volume
        .attr_path("/imported/nested/hardlink.bin", false)
        .unwrap();
    assert_eq!(file_attr.ino, link_attr.ino);
    assert_eq!(file_attr.nlink, 2);
    assert_eq!(
        volume.read_file("/imported/nested/file.bin", true).unwrap(),
        b"roundtrip payload"
    );
    assert_eq!(
        volume
            .getxattr_inode(file_attr.ino, "user.argosfs-test")
            .unwrap(),
        b"metadata"
    );
    assert_eq!(
        volume
            .readlink_inode_bytes(volume.resolve_path("/imported/link", false).unwrap())
            .unwrap(),
        b"nested/file.bin"
    );
    assert_eq!(
        volume.attr_path("/imported/pipe", false).unwrap().kind,
        NodeKind::Special
    );

    let output = tempdir().unwrap();
    fs::write(output.path().join("imported"), b"replace me").unwrap();
    export_tree(&volume, output.path()).unwrap();
    let exported = output.path().join("imported/nested/file.bin");
    assert_eq!(fs::read(&exported).unwrap(), b"roundtrip payload");
    assert_eq!(fs::metadata(&exported).unwrap().mode() & 0o777, 0o640);
    assert_eq!(
        read_xattr(&exported, "user.argosfs-test").unwrap(),
        b"metadata"
    );
    let exported_link = output.path().join("imported/nested/hardlink.bin");
    assert_eq!(
        fs::metadata(&exported).unwrap().ino(),
        fs::metadata(&exported_link).unwrap().ino()
    );
    assert_eq!(
        fs::read_link(output.path().join("imported/link")).unwrap(),
        PathBuf::from("nested/file.bin")
    );
    assert!(fs::symlink_metadata(output.path().join("imported/pipe"))
        .unwrap()
        .file_type()
        .is_fifo());
}

#[test]
fn export_replaces_existing_leaf_and_rejects_directory_conflicts() {
    let (_root, volume) = volume();
    volume.mkdir("/dir", 0o755).unwrap();
    volume.create_file_path("/dir/file", 0o600).unwrap();
    volume.write_file("/dir/file", b"new", 0o600).unwrap();

    let output = tempdir().unwrap();
    fs::create_dir_all(output.path().join("dir")).unwrap();
    fs::write(output.path().join("dir/file"), b"old").unwrap();
    export_tree(&volume, output.path()).unwrap();
    assert_eq!(fs::read(output.path().join("dir/file")).unwrap(), b"new");

    fs::remove_file(output.path().join("dir/file")).unwrap();
    fs::create_dir(output.path().join("dir/file")).unwrap();
    assert!(export_tree(&volume, output.path()).is_err());
}

#[test]
fn metadata_application_updates_times_owner_and_permissions() {
    let (_root, volume) = volume();
    let ino = volume.create_file_path("/file", 0o600).unwrap();
    let dir = tempdir().unwrap();
    let host = dir.path().join("host");
    fs::write(&host, b"data").unwrap();
    fs::set_permissions(&host, fs::Permissions::from_mode(0o654)).unwrap();
    write_xattr_nofollow(&host, "user.argosfs-test", b"x").unwrap();
    let metadata = fs::symlink_metadata(&host).unwrap();
    apply_import_metadata(&volume, &host, ino, &metadata).unwrap();
    let attr = volume.attr_inode(ino).unwrap();
    assert_eq!(attr.mode & 0o777, 0o654);
    assert_eq!(attr.uid, metadata.uid());
    assert_eq!(attr.gid, metadata.gid());
    assert_eq!(
        volume.getxattr_inode(ino, "user.argosfs-test").unwrap(),
        b"x"
    );

    let exported = dir.path().join("exported");
    fs::write(&exported, b"data").unwrap();
    apply_export_metadata(&volume, ino, &exported, &attr).unwrap();
    assert_eq!(fs::metadata(&exported).unwrap().mode() & 0o777, 0o654);
}
