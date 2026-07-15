use super::*;

#[test]
fn host_sync_drains_only_dirty_shard_set() {
    let tmp = tempfile::tempdir().unwrap();
    let fs = ArgosFs::create(
        tmp.path(),
        VolumeConfig {
            k: 1,
            m: 0,
            compression: Compression::None,
            ..VolumeConfig::default()
        },
        1,
        false,
    )
    .unwrap();

    fs.write_file("/dirty", b"dirty shard tracking", 0o644)
        .unwrap();
    assert!(!fs.dirty_host_shards.lock().is_empty());

    fs.sync().unwrap();

    assert!(fs.dirty_host_shards.lock().is_empty());
}

#[test]
fn data_operations_register_per_inode_locks() {
    let tmp = tempfile::tempdir().unwrap();
    let fs = ArgosFs::create(
        tmp.path(),
        VolumeConfig {
            k: 1,
            m: 0,
            compression: Compression::None,
            ..VolumeConfig::default()
        },
        1,
        false,
    )
    .unwrap();

    fs.write_file("/locked", b"abc", 0o644).unwrap();
    let ino = fs.resolve_path("/locked", true).unwrap();
    fs.write_inode_range(ino, 3, b"def").unwrap();
    fs.truncate_inode(ino, 4).unwrap();

    assert!(fs.inode_locks.lock().contains_key(&ino));
}

fn host_volume() -> (tempfile::TempDir, ArgosFs) {
    let dir = tempfile::tempdir().unwrap();
    let fs = ArgosFs::create(
        dir.path(),
        VolumeConfig {
            k: 1,
            m: 0,
            compression: Compression::None,
            chunk_size: 4096,
            ..VolumeConfig::default()
        },
        1,
        false,
    )
    .unwrap();
    (dir, fs)
}

#[test]
fn bulk_import_guards_restore_nested_thread_state() {
    assert!(!bulk_import_enabled());
    {
        let _outer = bulk_import_scope(true);
        assert!(bulk_import_enabled());
        {
            let _inner = bulk_import_scope(false);
            assert!(!bulk_import_enabled());
        }
        assert!(bulk_import_enabled());
    }
    assert!(!bulk_import_enabled());
}

#[test]
fn deferred_state_and_interval_distinguish_host_writable_and_readonly_block_backends() {
    let (_dir, host) = host_volume();
    assert!(host.deferred_commit_interval().is_none());
    assert!(!host.sync_deferred_if_dirty().unwrap());
    let host_state = DeferredCommitState::new(&host.metadata_snapshot());
    assert!(host_state.durable_metadata.is_none());
    assert_eq!(host_state.dirty_transactions, 0);
    assert!(host_state.pending_reclaims.is_empty());

    let dir = tempfile::tempdir().unwrap();
    let image = dir.path().join("deferred.img");
    let config = VolumeConfig {
        k: 1,
        m: 0,
        defer_metadata_commit: true,
        deferred_commit_interval_ms: 17,
        deferred_commit_max_transactions: 100,
        ..VolumeConfig::default()
    };
    let writable = ArgosFs::create_loop(
        std::slice::from_ref(&image),
        config,
        32 * 1024 * 1024,
        "deferred-tests",
        false,
    )
    .unwrap();
    assert_eq!(
        writable.deferred_commit_interval(),
        Some(Duration::from_millis(17))
    );
    writable.write_file("/dirty", b"data", 0o600).unwrap();
    assert!(writable.sync_deferred_if_dirty().unwrap());
    assert!(!writable.sync_deferred_if_dirty().unwrap());
    writable.mark_clean_unmount().unwrap();
    drop(writable);

    let readonly = ArgosFs::open_loop(std::slice::from_ref(&image), false).unwrap();
    assert!(readonly.deferred_commit_interval().is_none());
    assert!(!readonly.sync_deferred_if_dirty().unwrap());
    let meta = readonly.meta.read();
    assert!(readonly
        .ensure_block_backend_writable_locked(&meta)
        .is_err());
    assert!(readonly.active_block_backend_locked(&meta, false).is_ok());
}

#[test]
fn snapshots_validate_names_sanitize_paths_and_reject_duplicates() {
    let (_dir, fs) = host_volume();
    fs.write_file("/file", b"data", 0o600).unwrap();
    for invalid in ["", "   ", ".", ".."] {
        assert!(fs.snapshot(invalid).is_err());
    }
    let snapshot = fs.snapshot(" release / candidate ").unwrap();
    assert_eq!(snapshot.file_name().unwrap(), "release___candidate.json");
    assert!(snapshot.exists());
    assert!(fs.snapshot(" release / candidate ").is_err());
    let persisted: Metadata = serde_json::from_slice(&std::fs::read(snapshot).unwrap()).unwrap();
    assert_eq!(persisted.uuid, fs.metadata_snapshot().uuid);
    let report = ArgosFs::audit_transactions(fs.root()).unwrap();
    assert!(report.valid_entries > 0);
}

#[test]
fn path_iteration_and_file_windows_cover_nested_non_utf8_and_cursor_wrap() {
    use std::os::unix::ffi::OsStringExt;
    let (_dir, fs) = host_volume();
    let dir = fs.mkdir("/dir", 0o755).unwrap();
    let raw_name = std::ffi::OsString::from_vec(b"raw-\xff".to_vec());
    fs.create_file_at(dir, &raw_name, 0o600).unwrap();
    fs.write_file("/a", b"a", 0o600).unwrap();
    fs.write_file("/b", b"b", 0o600).unwrap();
    fs.write_file("/c", b"c", 0o600).unwrap();

    let byte_paths = fs.iter_path_bytes();
    assert!(byte_paths.iter().any(|(path, _)| path == b"/"));
    assert!(byte_paths.iter().any(|(path, _)| path == b"/dir/raw-\xff"));
    assert!(fs
        .iter_paths()
        .iter()
        .any(|(path, _)| path.contains("raw-")));

    assert!(fs.file_window(None, 0).is_empty());
    let all = fs.file_window(None, usize::MAX);
    assert_eq!(all.len(), 4);
    let first = fs.file_window(None, 2);
    assert_eq!(first.len(), 2);
    let after = fs.file_window(Some(first[1].0), 2);
    assert!(!after.is_empty());
    let wrapped = fs.file_window(Some(u64::MAX), 2);
    assert_eq!(wrapped.len(), 2);
}

#[test]
fn symlink_resolution_detects_loops_and_non_utf8_targets() {
    use std::os::unix::ffi::OsStringExt;
    let (_dir, fs) = host_volume();
    fs.symlink_path("/b", "/a").unwrap();
    fs.symlink_path("/a", "/b").unwrap();
    assert!(matches!(
        fs.resolve_path("/a", true),
        Err(ArgosError::Invalid(_))
    ));
    assert!(fs.resolve_path("/a", false).is_ok());

    let raw_target = std::ffi::OsString::from_vec(b"target-\xff".to_vec());
    fs.symlink_at(ROOT_INO, OsStr::new("raw-link"), Path::new(&raw_target))
        .unwrap();
    assert_eq!(
        fs.readlink_inode_bytes(fs.resolve_path("/raw-link", false).unwrap())
            .unwrap(),
        b"target-\xff"
    );
    assert!(fs.resolve_path("/raw-link", true).is_err());
}

#[test]
fn directory_helpers_find_parents_descendants_and_sticky_permissions() {
    let (_dir, fs) = host_volume();
    let parent = fs
        .mkdir_at_with_owner(ROOT_INO, OsStr::new("sticky"), 0o1777, 1000, 1000)
        .unwrap();
    let child = fs
        .create_file_at_with_owner(parent.ino, OsStr::new("child"), 0o600, 2000, 2000)
        .unwrap();
    let grandchild = fs
        .mkdir_at(parent.ino, OsStr::new("nested"), 0o755)
        .unwrap();
    let meta = fs.meta.read();
    assert_eq!(fs.parent_inode_locked(&meta, ROOT_INO).unwrap(), ROOT_INO);
    assert_eq!(
        fs.parent_inode_locked(&meta, child.ino).unwrap(),
        parent.ino
    );
    assert!(fs.parent_inode_locked(&meta, 9999).is_err());
    assert!(ArgosFs::directory_contains_inode(
        &meta, ROOT_INO, child.ino
    ));
    assert!(ArgosFs::directory_contains_inode(
        &meta,
        parent.ino,
        grandchild.ino
    ));
    assert!(!ArgosFs::directory_contains_inode(
        &meta, child.ino, parent.ino
    ));
    assert!(!ArgosFs::directory_contains_inode(&meta, 9999, child.ino));
    fs.check_sticky_locked(&meta, parent.ino, child.ino, None)
        .unwrap();
    fs.check_sticky_locked(&meta, parent.ino, child.ino, Some(0))
        .unwrap();
    fs.check_sticky_locked(&meta, parent.ino, child.ino, Some(1000))
        .unwrap();
    fs.check_sticky_locked(&meta, parent.ino, child.ino, Some(2000))
        .unwrap();
    assert!(fs
        .check_sticky_locked(&meta, parent.ino, child.ino, Some(3000))
        .is_err());
}

#[test]
fn inode_helpers_touch_allocate_paths_and_attributes() {
    let (_dir, fs) = host_volume();
    let mut meta = fs.meta.write();
    let next = meta.next_inode;
    assert_eq!(fs.alloc_inode_locked(&mut meta), next);
    assert_eq!(meta.next_inode, next + 1);
    let before = meta.inodes[&ROOT_INO].clone();
    fs.touch_inode_locked(&mut meta, ROOT_INO, true, false);
    assert!(meta.inodes[&ROOT_INO].mtime >= before.mtime);
    assert_eq!(meta.inodes[&ROOT_INO].ctime, before.ctime);
    fs.touch_inode_locked(&mut meta, ROOT_INO, false, true);
    assert!(meta.inodes[&ROOT_INO].ctime >= before.ctime);
    fs.touch_inode_locked(&mut meta, 9999, true, true);

    let disk_id = meta.disks.keys().next().unwrap().clone();
    let relpath = Path::new("shards/test.blk");
    let path = fs.shard_path_locked(&meta, &disk_id, relpath);
    assert!(path.ends_with(relpath));
    assert_eq!(
        fs.shard_path_if_disk_exists_locked(&meta, &disk_id, relpath),
        Some(path)
    );
    assert!(fs
        .shard_path_if_disk_exists_locked(&meta, "missing", relpath)
        .is_none());

    let inode = meta.inodes[&ROOT_INO].clone();
    let attr = ArgosFs::attr_from_inode(&inode, 4096);
    assert_eq!(attr.ino, ROOT_INO);
    assert_eq!(attr.blocks, 0);
    let mut file = inode;
    file.kind = NodeKind::File;
    file.size = 513;
    let attr = ArgosFs::attr_from_inode(&file, 4096);
    assert_eq!(attr.blocks, 2);
    assert_eq!(attr.blksize, 4096);
}

#[test]
fn transaction_error_classification_covers_committed_and_uncommitted_points() {
    for point in [
        "after-journal",
        "after-primary-metadata",
        "after-secondary-metadata",
        "after-compatible-metadata",
        "after-journal-commit-before-metadata-commit",
        "after-metadata-commit-before-superblock-update",
    ] {
        assert!(ArgosFs::transaction_error_is_committed(
            &ArgosError::InjectedCrash(point.to_string())
        ));
    }
    for error in [
        ArgosError::InjectedCrash("before-journal".to_string()),
        ArgosError::Invalid("x".to_string()),
        ArgosError::Conflict("x".to_string()),
    ] {
        assert!(!ArgosFs::transaction_error_is_committed(&error));
    }
}

#[test]
fn active_backend_helpers_cover_host_empty_and_loop_status_filtering() {
    let (_dir, host) = host_volume();
    let host_meta = host.meta.read();
    assert!(host
        .active_superblocks_locked(&host_meta)
        .unwrap()
        .is_empty());
    assert!(host.active_block_backend_locked(&host_meta, false).is_err());
    assert!(host.open_backend_covers_superblocks(&[]));
    drop(host_meta);

    let dir = tempfile::tempdir().unwrap();
    let images = [dir.path().join("a.img"), dir.path().join("b.img")];
    let loop_fs = ArgosFs::create_loop(
        &images,
        VolumeConfig {
            k: 1,
            m: 1,
            ..VolumeConfig::default()
        },
        32 * 1024 * 1024,
        "active-backend",
        false,
    )
    .unwrap();
    let mut meta = loop_fs.meta.write();
    assert!(loop_fs.open_backend_covers_superblocks(&loop_fs.raw_superblocks));
    assert_eq!(loop_fs.active_superblocks_locked(&meta).unwrap().len(), 2);
    let first = meta.disks.keys().next().unwrap().clone();
    meta.disks.get_mut(&first).unwrap().status = DiskStatus::Removed;
    assert_eq!(loop_fs.active_superblocks_locked(&meta).unwrap().len(), 1);
    assert_eq!(
        loop_fs
            .active_block_backend_locked(&meta, false)
            .unwrap()
            .list_devices()
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn dirty_host_sync_ignores_deleted_paths_and_keeps_failed_paths() {
    let (_dir, fs) = host_volume();
    let missing = fs.root.join("missing-shard");
    fs.mark_host_shard_dirty(missing);
    fs.sync_dirty_host_shards().unwrap();
    assert!(fs.dirty_host_shards.lock().is_empty());

    let unsyncable = PathBuf::from("/dev/null");
    fs.mark_host_shard_dirty(unsyncable.clone());
    assert!(fs.sync_dirty_host_shards().is_err());
    assert!(fs.dirty_host_shards.lock().contains(&unsyncable));
}

#[test]
fn volume_constructors_validate_layouts_force_recreation_and_backend_kinds() {
    let dir = tempfile::tempdir().unwrap();
    assert!(matches!(
        ArgosFs::create(
            dir.path().join("k-zero"),
            VolumeConfig {
                k: 0,
                m: 1,
                ..VolumeConfig::default()
            },
            1,
            false,
        ),
        Err(ArgosError::Invalid(_))
    ));
    assert!(matches!(
        ArgosFs::create(
            dir.path().join("too-few"),
            VolumeConfig {
                k: 2,
                m: 1,
                ..VolumeConfig::default()
            },
            2,
            false,
        ),
        Err(ArgosError::NotEnoughDisks { .. })
    ));
    let root = dir.path().join("host");
    let fs = ArgosFs::create(
        &root,
        VolumeConfig {
            k: 1,
            m: 0,
            chunk_size: 0,
            ..VolumeConfig::default()
        },
        1,
        false,
    )
    .unwrap();
    assert_eq!(
        fs.metadata_snapshot().config.chunk_size,
        VolumeConfig::default().chunk_size
    );
    drop(fs);
    assert!(matches!(
        ArgosFs::create(
            &root,
            VolumeConfig {
                k: 1,
                m: 0,
                ..VolumeConfig::default()
            },
            1,
            false
        ),
        Err(ArgosError::AlreadyExists(_))
    ));
    let recreated = ArgosFs::create(
        &root,
        VolumeConfig {
            k: 1,
            m: 0,
            ..VolumeConfig::default()
        },
        1,
        true,
    )
    .unwrap();
    let recreated_meta = recreated.metadata_snapshot();
    assert_eq!(recreated_meta.backend, BackendKind::Host);
    assert!(!recreated_meta.uuid.is_empty());

    assert!(matches!(
        ArgosFs::create_block_backend(
            BackendKind::Host,
            &[dir.path().join("unused-host-device")],
            VolumeConfig {
                k: 1,
                m: 0,
                ..VolumeConfig::default()
            },
            "host",
            false,
        ),
        Err(ArgosError::Unsupported(_))
    ));
    assert!(matches!(
        ArgosFs::create_block_backend(
            BackendKind::LoopBlock,
            &[],
            VolumeConfig {
                k: 0,
                m: 0,
                ..VolumeConfig::default()
            },
            "invalid",
            false,
        ),
        Err(ArgosError::Invalid(_))
    ));
    assert!(matches!(
        ArgosFs::create_block_backend(
            BackendKind::LoopBlock,
            &[],
            VolumeConfig {
                k: 1,
                m: 0,
                ..VolumeConfig::default()
            },
            "empty",
            false,
        ),
        Err(ArgosError::NotEnoughDisks { .. })
    ));

    let loop_image = dir.path().join("loop.img");
    let loop_fs = ArgosFs::create_loop(
        std::slice::from_ref(&loop_image),
        VolumeConfig {
            k: 1,
            m: 0,
            chunk_size: 0,
            ..VolumeConfig::default()
        },
        32 * 1024 * 1024,
        "loop",
        false,
    )
    .unwrap();
    loop_fs.mark_clean_unmount().unwrap();
    drop(loop_fs);
    assert!(ArgosFs::open_loop(std::slice::from_ref(&loop_image), false).is_ok());

    let raw_image = dir.path().join("raw.img");
    std::fs::File::create(&raw_image)
        .unwrap()
        .set_len(32 * 1024 * 1024)
        .unwrap();
    let raw_fs = ArgosFs::create_raw(
        std::slice::from_ref(&raw_image),
        VolumeConfig {
            k: 1,
            m: 0,
            ..VolumeConfig::default()
        },
        "raw",
        false,
    )
    .unwrap();
    raw_fs.mark_clean_unmount().unwrap();
    drop(raw_fs);
    assert!(ArgosFs::open_raw(std::slice::from_ref(&raw_image), false).is_ok());
}

#[test]
fn mknod_validates_rdev_types_inheritance_and_duplicates() {
    let (_dir, fs) = host_volume();
    assert!(matches!(
        fs.mknod_path("/regular-rdev", libc::S_IFREG | 0o600, 1),
        Err(ArgosError::Invalid(_))
    ));
    assert!(matches!(
        fs.mknod_path("/fifo-rdev", libc::S_IFIFO | 0o600, 1),
        Err(ArgosError::Invalid(_))
    ));
    assert!(matches!(
        fs.mknod_path("/socket-rdev", libc::S_IFSOCK | 0o600, 1),
        Err(ArgosError::Invalid(_))
    ));
    assert!(matches!(
        fs.mknod_path("/directory-mode", libc::S_IFDIR | 0o755, 0),
        Err(ArgosError::Unsupported(_))
    ));
    let regular = fs.mknod_path("/regular", 0o640, 0).unwrap();
    assert_eq!(
        fs.attr_inode(regular).unwrap().mode & libc::S_IFMT,
        libc::S_IFREG
    );
    assert!(fs.mknod_path("/regular", 0o640, 0).is_err());

    let parent = fs
        .mkdir_at_with_owner(ROOT_INO, OsStr::new("sgid"), 0o2775, 1000, 4242)
        .unwrap();
    let child = fs
        .mknod_at_with_owner(parent.ino, OsStr::new("child"), 0o600, 0, 1001, 9999)
        .unwrap();
    assert_eq!(child.gid, 4242);
}

#[test]
fn rename_covers_same_inode_exchange_cycles_cross_parent_and_type_conflicts() {
    let (_dir, fs) = host_volume();
    fs.write_file("/same-a", b"same", 0o600).unwrap();
    let same = fs.resolve_path("/same-a", true).unwrap();
    fs.link_at(same, ROOT_INO, OsStr::new("same-b")).unwrap();
    fs.rename_path("/same-a", "/same-b").unwrap();
    assert_eq!(fs.attr_path("/same-a", false).unwrap().ino, same);
    assert_eq!(fs.attr_path("/same-b", false).unwrap().ino, same);

    let a = fs.mkdir("/a", 0o755).unwrap();
    fs.mkdir("/a/b", 0o755).unwrap();
    assert!(fs
        .rename_at_with_policy(
            a,
            OsStr::new("b"),
            ROOT_INO,
            OsStr::new("a"),
            RenamePolicy {
                exchange: true,
                ..RenamePolicy::default()
            },
        )
        .is_err());

    let p1 = fs.mkdir("/p1", 0o755).unwrap();
    let p2 = fs.mkdir("/p2", 0o755).unwrap();
    fs.mkdir("/p1/d1", 0o755).unwrap();
    fs.mkdir("/p2/d2", 0o755).unwrap();
    let before_p1 = fs.attr_inode(p1).unwrap().nlink;
    let before_p2 = fs.attr_inode(p2).unwrap().nlink;
    fs.rename_at_with_policy(
        p1,
        OsStr::new("d1"),
        p2,
        OsStr::new("d2"),
        RenamePolicy {
            exchange: true,
            ..RenamePolicy::default()
        },
    )
    .unwrap();
    assert_eq!(fs.attr_inode(p1).unwrap().nlink, before_p1);
    assert_eq!(fs.attr_inode(p2).unwrap().nlink, before_p2);

    fs.mkdir("/nonempty", 0o755).unwrap();
    fs.write_file("/nonempty/child", b"x", 0o600).unwrap();
    fs.mkdir("/source-dir", 0o755).unwrap();
    assert!(fs.rename_path("/source-dir", "/nonempty").is_err());
    fs.write_file("/source-file", b"x", 0o600).unwrap();
    assert!(fs.rename_path("/source-file", "/nonempty").is_err());
    fs.mkdir("/empty-dir", 0o755).unwrap();
    fs.write_file("/another-file", b"x", 0o600).unwrap();
    assert!(fs.rename_path("/empty-dir", "/another-file").is_err());

    fs.write_file("/replace-old", b"old", 0o600).unwrap();
    fs.write_file("/replace-new", b"new", 0o600).unwrap();
    let old_ino = fs.resolve_path("/replace-old", true).unwrap();
    let new_ino = fs.resolve_path("/replace-new", true).unwrap();
    fs.rename_path("/replace-old", "/replace-new").unwrap();
    assert_eq!(fs.resolve_path("/replace-new", true).unwrap(), old_ino);
    assert!(fs.attr_inode(new_ino).is_err());

    fs.mkdir("/move-source", 0o755).unwrap();
    let left = fs.mkdir("/left", 0o755).unwrap();
    let right = fs.mkdir("/right", 0o755).unwrap();
    let left_links = fs.attr_inode(left).unwrap().nlink;
    let right_links = fs.attr_inode(right).unwrap().nlink;
    fs.rename_path("/move-source", "/right/moved").unwrap();
    assert_eq!(fs.attr_inode(left).unwrap().nlink, left_links);
    assert_eq!(fs.attr_inode(right).unwrap().nlink, right_links + 1);
}
