use super::*;

#[test]
fn symlink_resolution_decodes_internal_targets_safely() {
    let tmp = TempDir::new().unwrap();
    let fs = ArgosFs::create(tmp.path(), config(2, 2), 4, false).unwrap();

    fs.write_file("/utf8-target", b"utf8", 0o644).unwrap();
    fs.symlink_path("/utf8-target", "/utf8-link").unwrap();
    assert_eq!(fs.read_file("/utf8-link", true).unwrap(), b"utf8");

    let raw_name = OsString::from_vec(vec![b'n', b'o', b'n', 0xff]);
    let raw_path = std::path::PathBuf::from("/").join(&raw_name);
    fs.create_file_at(1, &raw_name, 0o644).unwrap();
    let ino = fs.lookup(1, &raw_name).unwrap().ino;
    fs.write_inode_range(ino, 0, b"raw-target").unwrap();

    fs.symlink_at(1, OsStr::new("raw-link"), &raw_path).unwrap();
    let link_ino = fs.resolve_path("/raw-link", false).unwrap();
    assert_eq!(
        fs.readlink_inode_bytes(link_ino).unwrap(),
        raw_path.as_os_str().as_bytes()
    );

    assert_eq!(
        fs.read_file("/raw-link", true).unwrap_err().errno(),
        libc::EINVAL
    );
}

#[test]
fn create_entry_owner_can_come_from_fuse_request() {
    let tmp = TempDir::new().unwrap();
    let fs = ArgosFs::create(tmp.path(), config(2, 2), 4, false).unwrap();

    let file = fs
        .create_file_at_with_owner(1, OsStr::new("owned"), 0o640, 1234, 5678)
        .unwrap();
    assert_eq!(file.uid, 1234);
    assert_eq!(file.gid, 5678);
    assert_eq!(file.mode & 0o7777, 0o640);

    let dir = fs
        .mkdir_at_with_owner(1, OsStr::new("dir"), 0o750, 2345, 6789)
        .unwrap();
    assert_eq!(dir.uid, 2345);
    assert_eq!(dir.gid, 6789);

    let link = fs
        .symlink_at_with_owner(
            1,
            OsStr::new("link"),
            std::path::Path::new("/owned"),
            3456,
            7890,
        )
        .unwrap();
    assert_eq!(link.uid, 3456);
    assert_eq!(link.gid, 7890);
}

#[test]
fn invalid_entry_names_are_rejected_before_metadata_changes() {
    let tmp = TempDir::new().unwrap();
    let fs = ArgosFs::create(tmp.path(), config(2, 2), 4, false).unwrap();

    assert_eq!(
        fs.create_file_at(1, OsStr::new("."), 0o644)
            .unwrap_err()
            .errno(),
        libc::EINVAL
    );
    assert_eq!(
        fs.mkdir_at(1, OsStr::new("bad/name"), 0o755)
            .unwrap_err()
            .errno(),
        libc::EINVAL
    );
    assert_eq!(
        fs.symlink_at(1, OsStr::new(""), std::path::Path::new("/target"))
            .unwrap_err()
            .errno(),
        libc::EINVAL
    );
    assert!(fs.fsck(true, true).unwrap().errors.is_empty());
}

#[test]
fn entry_names_longer_than_name_max_are_rejected_consistently() {
    let tmp = TempDir::new().unwrap();
    let fs = ArgosFs::create(tmp.path(), config(2, 2), 4, false).unwrap();
    fs.write_file("/source", b"payload", 0o644).unwrap();
    let source = fs.resolve_path("/source", false).unwrap();
    let long_name = OsString::from("x".repeat(256));

    for err in [
        fs.create_file_at(1, &long_name, 0o644).unwrap_err(),
        fs.mkdir_at(1, &long_name, 0o755).unwrap_err(),
        fs.symlink_at(1, &long_name, std::path::Path::new("target"))
            .unwrap_err(),
        fs.link_at(source, 1, &long_name).unwrap_err(),
        fs.lookup(1, &long_name).unwrap_err(),
        fs.unlink_at_as(1, &long_name, 0).unwrap_err(),
        fs.rmdir_at_as(1, &long_name, 0).unwrap_err(),
        fs.rename_at(1, OsStr::new("source"), 1, &long_name)
            .unwrap_err(),
    ] {
        assert_eq!(err.errno(), libc::ENAMETOOLONG);
    }

    assert_eq!(fs.read_file("/source", false).unwrap(), b"payload");
    assert!(fs.fsck(true, true).unwrap().errors.is_empty());
}

#[test]
fn non_root_owner_can_select_a_supplementary_group() {
    let tmp = TempDir::new().unwrap();
    let fs = ArgosFs::create(tmp.path(), config(2, 2), 4, false).unwrap();
    let file = fs
        .create_file_at_with_owner(1, OsStr::new("owned"), 0o6755, 65534, 65533)
        .unwrap();

    let changed = fs
        .chown_inode_as(file.ino, Some(65534), Some(65532), 65534, &[65532, 65531])
        .unwrap();
    assert_eq!(changed.uid, 65534);
    assert_eq!(changed.gid, 65532);
    assert_eq!(changed.mode & (libc::S_ISUID | libc::S_ISGID), 0);

    assert_eq!(
        fs.chown_inode_as(file.ino, Some(65535), None, 65534, &[65532])
            .unwrap_err()
            .errno(),
        libc::EACCES
    );
    assert_eq!(
        fs.chown_inode_as(file.ino, None, Some(65530), 65534, &[65532])
            .unwrap_err()
            .errno(),
        libc::EACCES
    );

    let txid = fs.metadata_snapshot().txid;
    let unchanged = fs.chown_inode_as(file.ino, None, None, 12345, &[]).unwrap();
    assert_eq!(unchanged.uid, 65534);
    assert_eq!(unchanged.gid, 65532);
    assert_eq!(fs.metadata_snapshot().txid, txid);
}

#[test]
fn unlinking_a_hard_link_updates_the_surviving_inode_ctime() {
    let tmp = TempDir::new().unwrap();
    let fs = ArgosFs::create(tmp.path(), config(2, 2), 4, false).unwrap();
    fs.write_file("/source", b"payload", 0o644).unwrap();
    let ino = fs.resolve_path("/source", false).unwrap();
    fs.link_at(ino, 1, OsStr::new("alias")).unwrap();
    let before = fs.attr_inode(ino).unwrap();

    std::thread::sleep(std::time::Duration::from_millis(2));
    fs.unlink_at_as(1, OsStr::new("alias"), 0).unwrap();

    let after = fs.attr_inode(ino).unwrap();
    assert_eq!(after.nlink, 1);
    assert!(after.ctime > before.ctime);
}

#[test]
fn readdir_reports_real_parent_for_dotdot() {
    let tmp = TempDir::new().unwrap();
    let fs = ArgosFs::create(tmp.path(), config(2, 2), 4, false).unwrap();
    fs.mkdir("/parent", 0o755).unwrap();
    fs.mkdir("/parent/child", 0o755).unwrap();
    let parent = fs.resolve_path("/parent", false).unwrap();
    let child = fs.resolve_path("/parent/child", false).unwrap();

    let child_entries = fs.readdir(child).unwrap();
    assert_eq!(
        child_entries
            .iter()
            .find(|entry| entry.name == "..")
            .unwrap()
            .attr
            .ino,
        parent
    );

    let root_entries = fs.readdir(1).unwrap();
    assert_eq!(
        root_entries
            .iter()
            .find(|entry| entry.name == "..")
            .unwrap()
            .attr
            .ino,
        1
    );
}

#[test]
fn failed_pre_journal_commit_reloads_in_memory_metadata() {
    let _guard = env_lock();
    let tmp = TempDir::new().unwrap();
    let fs = ArgosFs::create(tmp.path(), config(2, 2), 4, false).unwrap();

    journal::set_thread_crash_point(Some("before-journal"));
    let err = fs.mkdir("/ghost", 0o755).unwrap_err();
    journal::set_thread_crash_point(None);

    assert!(matches!(
        err,
        ArgosError::InjectedCrash(point) if point == "before-journal"
    ));
    assert_eq!(
        fs.resolve_path("/ghost", false).unwrap_err().errno(),
        libc::ENOENT
    );

    let reopened = ArgosFs::open(tmp.path()).unwrap();
    assert_eq!(
        reopened.resolve_path("/ghost", false).unwrap_err().errno(),
        libc::ENOENT
    );
}

#[test]
fn read_and_readdir_do_not_commit_metadata_transactions() {
    let tmp = TempDir::new().unwrap();
    let fs = ArgosFs::create(tmp.path(), config(2, 2), 4, false).unwrap();
    fs.write_file("/file", b"payload", 0o644).unwrap();
    let ino = fs.resolve_path("/file", false).unwrap();
    let txid = fs.metadata_snapshot().txid;

    assert_eq!(fs.read_inode(ino, 0, 7, true).unwrap(), b"payload");
    assert_eq!(fs.readdir(1).unwrap().len(), 3);
    assert_eq!(fs.metadata_snapshot().txid, txid);
}

#[test]
fn non_utf8_directory_entries_round_trip_through_fuse_style_apis() {
    let tmp = TempDir::new().unwrap();
    let fs = ArgosFs::create(tmp.path(), config(2, 2), 4, false).unwrap();
    let raw = OsString::from_vec(vec![b'f', 0xff, b'x']);
    fs.create_file_at(1, &raw, 0o644).unwrap();

    let attr = fs.lookup(1, &raw).unwrap();
    let entries = fs.readdir(1).unwrap();
    let entry = entries
        .iter()
        .find(|entry| entry.attr.ino == attr.ino)
        .unwrap();
    assert_eq!(entry.name_bytes, raw.as_bytes());
    assert_eq!(entry.os_name().as_bytes(), raw.as_bytes());
}

#[test]
fn empty_files_report_zero_blocks_and_directories_reject_stream_writes() {
    let tmp = TempDir::new().unwrap();
    let fs = ArgosFs::create(tmp.path(), config(2, 2), 4, false).unwrap();

    let empty = fs.create_file_at(1, OsStr::new("empty"), 0o644).unwrap();
    assert_eq!(empty.size, 0);
    assert_eq!(empty.blocks, 0);

    fs.mkdir("/dir", 0o755).unwrap();
    assert_eq!(
        fs.write_file("/dir", b"not a file", 0o644)
            .unwrap_err()
            .errno(),
        libc::EISDIR
    );
}

#[test]
fn chmod_path_follows_final_symlink_like_posix_chmod() {
    let tmp = TempDir::new().unwrap();
    let fs = ArgosFs::create(tmp.path(), config(2, 2), 4, false).unwrap();
    fs.write_file("/target", b"mode", 0o644).unwrap();
    fs.symlink_path("/target", "/link").unwrap();

    fs.chmod_path("/link", 0o600).unwrap();

    assert_eq!(fs.attr_path("/target", false).unwrap().mode & 0o7777, 0o600);
    assert_eq!(fs.attr_path("/link", false).unwrap().mode & 0o7777, 0o777);
}

#[test]
fn mkfs_force_cleans_partial_system_directory() {
    let tmp = TempDir::new().unwrap();
    let partial = tmp.path().join(".argosfs");
    fs::create_dir_all(&partial).unwrap();
    fs::write(partial.join("stale"), b"stale").unwrap();

    let err = match ArgosFs::create(tmp.path(), config(2, 2), 4, false) {
        Ok(_) => panic!("mkfs unexpectedly accepted a partial .argosfs directory"),
        Err(err) => err,
    };
    assert_eq!(err.errno(), libc::EEXIST);

    let fs = ArgosFs::create(tmp.path(), config(2, 2), 4, true).unwrap();
    assert!(!tmp.path().join(".argosfs/stale").exists());
    assert_eq!(fs.health_report().disks.len(), 4);
}

#[test]
fn add_disk_rejects_duplicate_storage_path() {
    let tmp = TempDir::new().unwrap();
    let fs = ArgosFs::create(tmp.path(), config(2, 2), 4, false).unwrap();
    let existing = fs
        .metadata_snapshot()
        .disks
        .get("disk-0000")
        .unwrap()
        .path
        .clone();

    let err = fs
        .add_disk(
            Some(existing),
            Some(StorageTier::Warm),
            Some(1.0),
            Some(0),
            false,
        )
        .unwrap_err();
    assert_eq!(err.errno(), libc::EEXIST);
}

#[test]
fn rename_noop_and_replacement_keep_metadata_consistent() {
    let tmp = TempDir::new().unwrap();
    let fs = ArgosFs::create(tmp.path(), config(2, 2), 4, false).unwrap();

    fs.write_file("/a", b"alpha", 0o644).unwrap();
    let ino = fs.resolve_path("/a", false).unwrap();
    fs.rename_path("/a", "/a").unwrap();
    assert_eq!(fs.resolve_path("/a", false).unwrap(), ino);
    assert_eq!(fs.read_file("/a", true).unwrap(), b"alpha");

    fs.link_at(ino, 1, OsStr::new("b")).unwrap();
    fs.rename_path("/a", "/b").unwrap();
    assert_eq!(fs.read_file("/a", true).unwrap(), b"alpha");
    assert_eq!(fs.read_file("/b", true).unwrap(), b"alpha");
    assert_eq!(fs.attr_path("/a", false).unwrap().nlink, 2);

    fs.write_file("/c", b"charlie", 0o644).unwrap();
    fs.rename_path("/c", "/b").unwrap();
    assert_eq!(fs.read_file("/a", true).unwrap(), b"alpha");
    assert_eq!(fs.attr_path("/a", false).unwrap().nlink, 1);
    assert_eq!(fs.read_file("/b", true).unwrap(), b"charlie");
    assert!(fs.fsck(true, true).unwrap().errors.is_empty());
}

#[test]
fn rename_policy_supports_noreplace_exchange_and_sticky_checks() {
    let tmp = TempDir::new().unwrap();
    let fs = ArgosFs::create(tmp.path(), config(2, 2), 4, false).unwrap();
    fs.write_file("/a", b"alpha", 0o644).unwrap();
    fs.write_file("/b", b"beta", 0o644).unwrap();

    let err = fs
        .rename_at_with_policy(
            1,
            OsStr::new("a"),
            1,
            OsStr::new("b"),
            argosfs::volume::RenamePolicy {
                no_replace: true,
                exchange: false,
                uid: Some(0),
                preserve_replaced_inode: false,
            },
        )
        .unwrap_err();
    assert_eq!(err.errno(), libc::EEXIST);

    fs.rename_at_with_policy(
        1,
        OsStr::new("a"),
        1,
        OsStr::new("b"),
        argosfs::volume::RenamePolicy {
            no_replace: false,
            exchange: true,
            uid: Some(0),
            preserve_replaced_inode: false,
        },
    )
    .unwrap();
    assert_eq!(fs.read_file("/a", true).unwrap(), b"beta");
    assert_eq!(fs.read_file("/b", true).unwrap(), b"alpha");

    fs.mkdir("/tmp", libc::S_ISVTX | 0o777).unwrap();
    fs.create_file_at_with_owner(1, OsStr::new("owned"), 0o644, 1001, 1001)
        .unwrap();
    fs.rename_path("/owned", "/tmp/owned").unwrap();
    assert_eq!(
        fs.unlink_at_as(
            fs.resolve_path("/tmp", false).unwrap(),
            OsStr::new("owned"),
            2002
        )
        .unwrap_err()
        .errno(),
        libc::EACCES
    );
    fs.unlink_at_as(
        fs.resolve_path("/tmp", false).unwrap(),
        OsStr::new("owned"),
        1001,
    )
    .unwrap();
}

#[test]
fn rename_rejects_invalid_directory_and_type_transitions() {
    let tmp = TempDir::new().unwrap();
    let fs = ArgosFs::create(tmp.path(), config(2, 2), 4, false).unwrap();

    fs.mkdir("/dir", 0o755).unwrap();
    fs.mkdir("/dir/sub", 0o755).unwrap();
    fs.write_file("/file", b"payload", 0o644).unwrap();

    assert_eq!(
        fs.rename_path("/file", "/dir").unwrap_err().errno(),
        libc::EISDIR
    );
    assert_eq!(
        fs.rename_path("/dir", "/file").unwrap_err().errno(),
        libc::ENOTDIR
    );
    assert_eq!(
        fs.rename_path("/dir", "/dir/sub/moved")
            .unwrap_err()
            .errno(),
        libc::EINVAL
    );

    assert_eq!(fs.read_file("/file", true).unwrap(), b"payload");
    assert!(fs.resolve_path("/dir/sub", false).is_ok());
    assert!(fs.fsck(true, true).unwrap().errors.is_empty());
}

#[test]
fn link_at_rejects_missing_inode_without_directory_damage() {
    let tmp = TempDir::new().unwrap();
    let fs = ArgosFs::create(tmp.path(), config(2, 2), 4, false).unwrap();

    assert_eq!(
        fs.link_at(9999, 1, OsStr::new("bad")).unwrap_err().errno(),
        libc::ENOENT
    );
    assert!(fs.lookup(1, OsStr::new("bad")).is_err());
    assert!(fs.fsck(true, true).unwrap().errors.is_empty());
}

#[test]
fn range_write_propagates_read_errors_without_overwriting_existing_data() {
    let _env_guard = env_lock();
    let tmp = TempDir::new().unwrap();
    let fs = ArgosFs::create(tmp.path(), config(2, 2), 4, false).unwrap();
    let key = "range write keeps old encrypted data";

    fs.enable_encryption(key).unwrap();
    std::env::set_var("ARGOSFS_KEY", key);
    fs.write_file("/secret", b"original secret", 0o600).unwrap();
    let ino = fs.resolve_path("/secret", false).unwrap();

    std::env::remove_var("ARGOSFS_KEY");
    assert_eq!(
        fs.write_inode_range(ino, 0, b"new").unwrap_err().errno(),
        libc::EACCES
    );

    std::env::set_var("ARGOSFS_KEY", key);
    assert_eq!(fs.read_file("/secret", true).unwrap(), b"original secret");
    std::env::remove_var("ARGOSFS_KEY");
}

#[test]
fn unlinked_open_inode_survives_until_explicit_reap() {
    let tmp = TempDir::new().unwrap();
    let fs = ArgosFs::create(tmp.path(), config(1, 0), 1, false).unwrap();
    fs.write_file("/open-unlink", b"still-open", 0o644).unwrap();
    let ino = fs.resolve_path("/open-unlink", false).unwrap();

    fs.unlink_at_as_preserving_open(1, OsStr::new("open-unlink"), 0)
        .unwrap();
    assert!(fs.resolve_path("/open-unlink", false).is_err());
    assert_eq!(fs.attr_inode(ino).unwrap().nlink, 0);
    assert_eq!(fs.read_inode(ino, 0, 64, false).unwrap(), b"still-open");

    fs.reap_unlinked_inode(ino).unwrap();
    assert!(fs.attr_inode(ino).is_err());
}

#[test]
fn rename_replacement_can_preserve_open_target_inode() {
    let tmp = TempDir::new().unwrap();
    let fs = ArgosFs::create(tmp.path(), config(1, 0), 1, false).unwrap();
    fs.write_file("/source", b"source", 0o644).unwrap();
    fs.write_file("/target", b"open-target", 0o644).unwrap();
    let target_ino = fs.resolve_path("/target", false).unwrap();

    fs.rename_at_with_policy(
        1,
        OsStr::new("source"),
        1,
        OsStr::new("target"),
        argosfs::volume::RenamePolicy {
            preserve_replaced_inode: true,
            ..argosfs::volume::RenamePolicy::default()
        },
    )
    .unwrap();
    assert_eq!(fs.read_file("/target", false).unwrap(), b"source");
    assert_eq!(fs.attr_inode(target_ino).unwrap().nlink, 0);
    assert_eq!(
        fs.read_inode(target_ino, 0, 64, false).unwrap(),
        b"open-target"
    );

    fs.reap_unlinked_inode(target_ino).unwrap();
    assert!(fs.attr_inode(target_ino).is_err());
}
