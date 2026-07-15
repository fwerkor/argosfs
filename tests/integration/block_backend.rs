use super::*;

#[test]
fn raw_superblock_builder_rejects_overflowing_layout_fields() {
    let err = argosfs::raw_store::superblock_for_device(
        uuid::Uuid::new_v4(),
        0,
        "disk-0000",
        usize::MAX,
        1,
        4096,
        64 * 1024 * 1024,
        "overflow-layout",
    )
    .unwrap_err();
    assert_eq!(err.errno(), libc::EINVAL);
}

#[test]
fn verify_journal_cli_supports_loop_backend() {
    let tmp = TempDir::new().unwrap();
    let images = loop_images(&tmp, 3);
    let fs = ArgosFs::create_loop(
        &images,
        config(2, 1),
        32 * 1024 * 1024,
        "verify-journal-cli",
        false,
    )
    .unwrap();
    fs.write_file("/payload", b"journal cli block backend", 0o644)
        .unwrap();
    fs.sync().unwrap();
    drop(fs);

    let image_list = images
        .iter()
        .map(|path| path.to_string_lossy())
        .collect::<Vec<_>>()
        .join(",");
    let output = Command::new(argosfs_binary())
        .args([
            "verify-journal",
            "--backend",
            "loop",
            "--images",
            &image_list,
            "--pool",
            "verify-journal-cli",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "verify-journal failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["invalid_entries"], 0);
    assert_eq!(report["double_write_mismatches"], 0);
}

#[test]
fn tree_transfer_cli_rejects_mismatched_pool_config() {
    let tmp = TempDir::new().unwrap();
    let images = loop_images(&tmp, 1);
    let fs = ArgosFs::create_loop(
        &images,
        config(1, 0),
        32 * 1024 * 1024,
        "actual-pool",
        false,
    )
    .unwrap();
    fs.write_file("/existing", b"existing", 0o644).unwrap();
    fs.sync().unwrap();
    drop(fs);

    let config_path = tmp.path().join("wrong-pool.json");
    fs::write(
        &config_path,
        serde_json::to_vec_pretty(&serde_json::json!({
            "backend": "loop",
            "images": images,
            "pool": "different-pool"
        }))
        .unwrap(),
    )
    .unwrap();
    let source = tmp.path().join("source");
    fs::create_dir(&source).unwrap();
    fs::write(source.join("sentinel"), b"must-not-import").unwrap();

    let import = Command::new(argosfs_binary())
        .arg("import-tree")
        .arg("--pool-config")
        .arg(&config_path)
        .arg(&source)
        .arg("/")
        .output()
        .unwrap();
    assert!(!import.status.success());
    assert!(String::from_utf8_lossy(&import.stderr).contains("different-pool"));

    let reopened = ArgosFs::open_loop(&images, false).unwrap();
    assert!(reopened.read_file("/sentinel", false).is_err());
    drop(reopened);

    let destination = tmp.path().join("export");
    let export = Command::new(argosfs_binary())
        .arg("export-tree")
        .arg("--pool-config")
        .arg(&config_path)
        .arg(&destination)
        .output()
        .unwrap();
    assert!(!export.status.success());
    assert!(String::from_utf8_lossy(&export.stderr).contains("different-pool"));
    assert!(!destination.exists());
}

#[test]
fn single_device_loop_rootfs_smoke_import_export() {
    let tmp = TempDir::new().unwrap();
    let images = loop_images(&tmp, 1);
    let fs =
        ArgosFs::create_loop(&images, config(1, 0), 32 * 1024 * 1024, "capos-root", false).unwrap();
    create_rootfs_mountpoints(&fs);
    fs.mkdir("/sbin", 0o755).unwrap();
    fs.write_file("/sbin/init", b"#!/bin/sh\nexit 0\n", 0o755)
        .unwrap();
    fs.mkdir("/etc", 0o755).unwrap();
    fs.write_file("/etc/os-release", b"NAME=CapOS\n", 0o644)
        .unwrap();
    assert!(
        argosfs::rootfs::preflight_volume(&fs, argosfs::rootfs::RootMountMode::ReadWrite)
            .unwrap()
            .ok
    );
    drop(fs);

    let reopened = ArgosFs::open_loop(&images, true).unwrap();
    assert!(reopened.fsck(false, false).unwrap().errors.is_empty());
    assert_eq!(
        reopened.read_file("/etc/os-release", true).unwrap(),
        b"NAME=CapOS\n"
    );
}

#[test]
fn raw_journal_replay_chains_from_bulk_checkpoint_for_rootfs_writes() {
    let _guard = env_lock();
    let tmp = TempDir::new().unwrap();
    let images = loop_images(&tmp, 1);
    let fs =
        ArgosFs::create_loop(&images, config(1, 0), 32 * 1024 * 1024, "capos-root", false).unwrap();
    create_rootfs_mountpoints(&fs);

    let _bulk_import = argosfs::volume::bulk_import_scope(true);
    fs.mkdir("/sbin", 0o755).unwrap();
    fs.write_file("/sbin/init", b"#!/bin/sh\nexit 0\n", 0o755)
        .unwrap();
    fs.sync().unwrap();

    let created = fs
        .create_file_at_with_owner(1, OsStr::new("etc-test"), 0o644, 0, 0)
        .unwrap();
    fs.write_inode_range(created.ino, 0, b"mounted-write")
        .unwrap();
    fs.sync().unwrap();
    drop(fs);

    let reopened = ArgosFs::open_loop(&images, false).unwrap();
    assert_eq!(
        reopened.read_file("/etc-test", true).unwrap(),
        b"mounted-write"
    );
    let report = reopened.transaction_report().unwrap();
    assert_eq!(report.invalid_entries, 0);
    assert!(report.errors.is_empty(), "{:?}", report.errors);
    assert!(
        argosfs::rootfs::preflight_volume(&reopened, argosfs::rootfs::RootMountMode::ReadWrite)
            .unwrap()
            .ok
    );
}

#[test]
fn loop_block_open_remaps_metadata_paths_to_current_devices() {
    let tmp = TempDir::new().unwrap();
    let original = tmp.path().join("original.img");
    let moved = tmp.path().join("moved.img");
    let original_images = vec![original.clone()];
    let fs = ArgosFs::create_loop(
        &original_images,
        config(1, 0),
        32 * 1024 * 1024,
        "capos-root",
        false,
    )
    .unwrap();
    fs.write_file("/booted-from-current-path", b"ok", 0o644)
        .unwrap();
    fs.sync().unwrap();
    drop(fs);

    fs::copy(&original, &moved).unwrap();
    fs::remove_file(&original).unwrap();
    let moved_images = vec![moved.clone()];
    let reopened = ArgosFs::open_loop(&moved_images, true).unwrap();
    assert_eq!(reopened.metadata_snapshot().disks["disk-0000"].path, moved);
    assert_eq!(
        reopened
            .read_file("/booted-from-current-path", true)
            .unwrap(),
        b"ok"
    );
    reopened.mkdir("/runtime-dir", 0o755).unwrap();
    reopened
        .write_file("/runtime-dir/created-after-remap", b"rw", 0o644)
        .unwrap();
    assert_eq!(
        reopened
            .read_file("/runtime-dir/created-after-remap", true)
            .unwrap(),
        b"rw"
    );
    reopened.sync().unwrap();
}

#[test]
fn reshape_single_to_redundant_resume_keeps_multilayout_readable() {
    let tmp = TempDir::new().unwrap();
    let mut images = loop_images(&tmp, 1);
    let fs =
        ArgosFs::create_loop(&images, config(1, 0), 32 * 1024 * 1024, "capos-root", false).unwrap();
    let a_payload = vec![b'a'; 20 * 1024];
    let b_payload = vec![b'b'; 20 * 1024];
    fs.write_file("/a", &a_payload, 0o644).unwrap();
    fs.write_file("/b", &b_payload, 0o644).unwrap();
    let old_layout = fs.metadata_snapshot().current_write_layout;

    let new_image = tmp.path().join("disk1.img");
    fs.add_block_device(new_image.clone(), 32 * 1024 * 1024, false)
        .unwrap();
    images.push(new_image);

    let start = fs.reshape_layout(1, 1, Some(0)).unwrap();
    assert!(!start.complete);
    assert_eq!(start.remaining_files, 2);
    assert_eq!(fs.read_file("/a", true).unwrap(), a_payload.as_slice());
    let meta = fs.metadata_snapshot();
    assert_eq!(meta.layouts[&old_layout].m, 0);
    assert_eq!(meta.layouts[&meta.current_write_layout].m, 1);
    assert!(meta.reshape.is_some());

    let step = fs.reshape_layout(1, 1, Some(1)).unwrap();
    assert!(!step.complete);
    assert_eq!(step.remaining_files, 1);
    assert_eq!(fs.read_file("/b", true).unwrap(), b_payload.as_slice());
    drop(fs);

    let resumed = ArgosFs::open_loop(&images, true).unwrap();
    let recovery = resumed.transaction_report().unwrap();
    assert_eq!(recovery.invalid_entries, 0, "{:#?}", recovery.errors);
    assert!(recovery.errors.is_empty(), "{:#?}", recovery.errors);
    let done = resumed.reshape_layout(1, 1, None).unwrap();
    assert!(done.complete);
    assert_eq!(done.remaining_files, 0);
    assert_eq!(resumed.read_file("/a", true).unwrap(), a_payload.as_slice());
    assert_eq!(resumed.read_file("/b", true).unwrap(), b_payload.as_slice());
    assert!(resumed.fsck(true, true).unwrap().errors.is_empty());
    let final_meta = resumed.metadata_snapshot();
    let target = final_meta.current_write_layout.clone();
    assert!(final_meta.reshape.is_none());
    for inode in final_meta
        .inodes
        .values()
        .filter(|inode| inode.kind == argosfs::types::NodeKind::File)
    {
        for block in &inode.blocks {
            assert_eq!(block.layout_id, target);
            assert_eq!(block.shards.len(), 2);
        }
    }
}

#[test]
fn reshape_crash_after_data_flush_keeps_old_layout_data_readable() {
    let _guard = env_lock();
    let tmp = TempDir::new().unwrap();
    let mut images = loop_images(&tmp, 1);
    let fs =
        ArgosFs::create_loop(&images, config(1, 0), 32 * 1024 * 1024, "capos-root", false).unwrap();
    let payload = vec![b'r'; 20 * 1024];
    fs.write_file("/payload", &payload, 0o644).unwrap();
    let new_image = tmp.path().join("disk1.img");
    fs.add_block_device(new_image.clone(), 32 * 1024 * 1024, false)
        .unwrap();
    images.push(new_image);
    fs.reshape_layout(1, 1, Some(0)).unwrap();

    journal::set_thread_crash_point(Some(
        argosfs::types::FaultPoint::AfterDataFlushBeforeJournalCommit.as_str(),
    ));
    let err = fs.reshape_layout(1, 1, Some(1)).unwrap_err();
    journal::set_thread_crash_point(None);
    assert_eq!(err.errno(), libc::EIO);
    drop(fs);

    let reopened = ArgosFs::open_loop(&images, true).unwrap();
    assert_eq!(
        reopened.read_file("/payload", true).unwrap(),
        payload.as_slice()
    );
    assert!(reopened.fsck(true, true).unwrap().errors.is_empty());
    let done = reopened.reshape_layout(1, 1, None).unwrap();
    assert!(done.complete);
}

#[test]
fn reshape_single_device_to_k4_m2_chain() {
    let tmp = TempDir::new().unwrap();
    let mut images = loop_images(&tmp, 1);
    let fs =
        ArgosFs::create_loop(&images, config(1, 0), 32 * 1024 * 1024, "capos-root", false).unwrap();
    fs.write_file("/chain", b"reshape-chain", 0o644).unwrap();

    let disk1 = tmp.path().join("disk1.img");
    fs.add_block_device(disk1.clone(), 32 * 1024 * 1024, false)
        .unwrap();
    images.push(disk1);
    assert!(fs.reshape_layout(1, 1, None).unwrap().complete);

    let disk2 = tmp.path().join("disk2.img");
    fs.add_block_device(disk2.clone(), 32 * 1024 * 1024, false)
        .unwrap();
    images.push(disk2);
    assert!(fs.reshape_layout(2, 1, None).unwrap().complete);

    for index in 3..6 {
        let image = tmp.path().join(format!("disk{index}.img"));
        fs.add_block_device(image.clone(), 32 * 1024 * 1024, false)
            .unwrap();
        images.push(image);
    }
    assert!(fs.reshape_layout(4, 2, None).unwrap().complete);
    assert_eq!(fs.read_file("/chain", true).unwrap(), b"reshape-chain");
    assert!(fs.fsck(true, true).unwrap().errors.is_empty());
    let meta = fs.metadata_snapshot();
    let layout = &meta.layouts[&meta.current_write_layout];
    assert_eq!((layout.k, layout.m), (4, 2));
    let ino = fs.resolve_path("/chain", true).unwrap();
    assert!(meta.inodes[&ino]
        .blocks
        .iter()
        .all(|block| block.shards.len() == 6));
}

#[test]
fn loop_block_backend_round_trips_raw_extents_without_host_shards() {
    let tmp = TempDir::new().unwrap();
    let images = loop_images(&tmp, 3);
    let fs =
        ArgosFs::create_loop(&images, config(2, 1), 32 * 1024 * 1024, "capos-root", false).unwrap();
    fs.write_file("/etc-os-release", b"NAME=CapOS\n", 0o644)
        .unwrap();

    let meta = fs.metadata_snapshot();
    assert_eq!(meta.backend, BackendKind::LoopBlock);
    let inode = meta
        .inodes
        .values()
        .find(|inode| inode.size == b"NAME=CapOS\n".len() as u64)
        .unwrap();
    let shard = &inode.blocks[0].shards[0];
    assert!(shard.relpath.as_os_str().is_empty());
    assert!(matches!(shard.location, Some(ShardLocation::RawExtent(_))));
    assert!(!tmp.path().join(".argosfs/meta.json").exists());
    fs.sync().unwrap();
    drop(fs);

    let reopened = ArgosFs::open_loop(&images, true).unwrap();
    assert_eq!(
        reopened.read_file("/etc-os-release", true).unwrap(),
        b"NAME=CapOS\n"
    );
    assert!(reopened.fsck(false, false).unwrap().errors.is_empty());
}

#[test]
fn loop_block_scan_inspect_and_repair_corrupt_extent() {
    let tmp = TempDir::new().unwrap();
    let images = loop_images(&tmp, 3);
    let fs =
        ArgosFs::create_loop(&images, config(2, 1), 32 * 1024 * 1024, "capos-root", false).unwrap();
    fs.write_file("/payload", b"abcdefghijklmnopqrstuvwxyz", 0o644)
        .unwrap();
    let meta = fs.metadata_snapshot();
    let inode = meta.inodes.values().find(|inode| inode.size == 26).unwrap();
    let shard = &inode.blocks[0].shards[0];
    let extent = match shard.location.as_ref().unwrap() {
        ShardLocation::RawExtent(extent) => extent.clone(),
        _ => panic!("loop shard should use raw extent"),
    };
    drop(fs);

    let scan = argosfs::scan::scan_images(&images);
    assert_eq!(scan.iter().filter(|device| device.valid).count(), 3);
    let (superblock, label) =
        argosfs::raw_store::inspect_device(BackendKind::LoopBlock, images[0].clone()).unwrap();
    assert_eq!(superblock.label, "capos-root");
    assert_eq!(label.label, "capos-root");

    let disk_index = extent
        .disk_id
        .strip_prefix("disk-")
        .unwrap()
        .parse::<usize>()
        .unwrap();
    let file = fs::OpenOptions::new()
        .write(true)
        .open(&images[disk_index])
        .unwrap();
    file.write_at(b"corrupt", extent.offset).unwrap();
    file.sync_all().unwrap();

    let fs = ArgosFs::open_loop(&images, true).unwrap();
    let report = fs.fsck(true, false).unwrap();
    assert_eq!(report.damaged_files, 1);
    assert_eq!(report.repaired_files, 1);
    assert_eq!(
        fs.read_file("/payload", true).unwrap(),
        b"abcdefghijklmnopqrstuvwxyz"
    );
}

#[test]
fn clean_state_tracks_mount_lifetime_and_generation() {
    let tmp = TempDir::new().unwrap();
    let images = loop_images(&tmp, 1);
    let fs =
        ArgosFs::create_loop(&images, config(1, 0), 32 * 1024 * 1024, "capos-root", false).unwrap();
    let (mounted, _) =
        argosfs::raw_store::inspect_device(BackendKind::LoopBlock, images[0].clone()).unwrap();
    assert!(!mounted.clean);

    fs.write_file("/payload", b"label-generation", 0o644)
        .unwrap();
    fs.sync().unwrap();
    let (after_sync, _) =
        argosfs::raw_store::inspect_device(BackendKind::LoopBlock, images[0].clone()).unwrap();
    assert!(!after_sync.clean);
    assert_eq!(after_sync.generation, mounted.generation);
    drop(fs);

    let (clean, clean_label) =
        argosfs::raw_store::inspect_device(BackendKind::LoopBlock, images[0].clone()).unwrap();
    assert!(clean.clean);
    assert!(clean.generation > after_sync.generation);
    assert_eq!(clean.generation, clean_label.generation);

    let reopened = ArgosFs::open_loop(&images, true).unwrap();
    let (remounted, remounted_label) =
        argosfs::raw_store::inspect_device(BackendKind::LoopBlock, images[0].clone()).unwrap();
    assert!(!remounted.clean);
    assert!(remounted.generation > clean.generation);
    assert_eq!(remounted.generation, remounted_label.generation);
    reopened.sync().unwrap();
    let (after_second_sync, _) =
        argosfs::raw_store::inspect_device(BackendKind::LoopBlock, images[0].clone()).unwrap();
    assert!(!after_second_sync.clean);
    assert_eq!(after_second_sync.generation, remounted.generation);
    drop(reopened);

    let (final_clean, final_label) =
        argosfs::raw_store::inspect_device(BackendKind::LoopBlock, images[0].clone()).unwrap();
    assert!(final_clean.clean);
    assert!(final_clean.generation > remounted.generation);
    assert_eq!(final_clean.generation, final_label.generation);
}

#[test]
fn loop_block_scan_and_inspect_recover_from_backup_superblock() {
    let tmp = TempDir::new().unwrap();
    let images = loop_images(&tmp, 3);
    let fs =
        ArgosFs::create_loop(&images, config(2, 1), 32 * 1024 * 1024, "capos-root", false).unwrap();
    fs.write_file("/payload", b"backup-superblock", 0o644)
        .unwrap();
    drop(fs);

    let file = fs::OpenOptions::new().write(true).open(&images[0]).unwrap();
    file.write_at(&vec![0u8; SUPERBLOCK_SIZE], PRIMARY_SUPERBLOCK_OFFSET)
        .unwrap();
    file.sync_all().unwrap();

    let scan = argosfs::scan::scan_images(&images);
    assert_eq!(scan[0].superblock_source.as_deref(), Some("backup"));
    assert!(scan[0].valid);
    let (superblock, label) =
        argosfs::raw_store::inspect_device(BackendKind::LoopBlock, images[0].clone()).unwrap();
    assert_eq!(superblock.disk_id, label.disk_id);

    let reopened = ArgosFs::open_loop(&images, false).unwrap();
    assert_eq!(
        reopened.read_file("/payload", true).unwrap(),
        b"backup-superblock"
    );
}

#[test]
fn loop_block_degraded_read_with_one_missing_image() {
    let tmp = TempDir::new().unwrap();
    let images = loop_images(&tmp, 3);
    let fs =
        ArgosFs::create_loop(&images, config(2, 1), 32 * 1024 * 1024, "capos-root", false).unwrap();
    fs.write_file("/payload", b"read-through-missing-disk", 0o644)
        .unwrap();
    drop(fs);

    let partial = images[..2].to_vec();
    let reopened = ArgosFs::open_loop(&partial, false).unwrap();
    let meta = reopened.metadata_snapshot();
    assert_eq!(meta.disks["disk-0002"].status, DiskStatus::Offline);
    assert_eq!(
        reopened.read_file("/payload", false).unwrap(),
        b"read-through-missing-disk"
    );
}

#[test]
fn rootfs_preflight_fails_closed_for_degraded_rw_default() {
    let tmp = TempDir::new().unwrap();
    let images = loop_images(&tmp, 3);
    let fs =
        ArgosFs::create_loop(&images, config(2, 1), 32 * 1024 * 1024, "capos-root", false).unwrap();
    create_rootfs_mountpoints(&fs);
    fs.write_file("/sbin-init", b"init", 0o755).unwrap();
    drop(fs);

    let partial = images[..2].to_vec();
    let reopened = ArgosFs::open_loop(&partial, false).unwrap();
    let report =
        argosfs::rootfs::preflight_report(&reopened, argosfs::rootfs::RootMountMode::ReadWrite);
    assert!(!report.ok);
    assert_eq!(report.recommended_mode, "degraded-ro");
    assert!(report
        .issues
        .iter()
        .any(|issue| issue.code == "degraded-rootfs-requires-explicit-mode"));
    let err =
        argosfs::rootfs::preflight_volume(&reopened, argosfs::rootfs::RootMountMode::ReadWrite)
            .unwrap_err();
    assert!(matches!(err, ArgosError::ReadonlyRequired(_)));
    assert!(argosfs::rootfs::preflight_volume(
        &reopened,
        argosfs::rootfs::RootMountMode::DegradedReadOnly,
    )
    .is_ok());
}

#[test]
fn rootfs_preflight_rejects_missing_switch_root_mountpoint() {
    let tmp = TempDir::new().unwrap();
    let images = loop_images(&tmp, 1);
    let fs =
        ArgosFs::create_loop(&images, config(1, 0), 32 * 1024 * 1024, "capos-root", false).unwrap();
    for path in ["/dev", "/proc", "/sys"] {
        fs.mkdir(path, 0o755).unwrap();
    }

    let report = argosfs::rootfs::preflight_report(&fs, argosfs::rootfs::RootMountMode::ReadOnly);
    assert!(!report.ok);
    assert!(!report.can_mount_readonly);
    assert!(report
        .issues
        .iter()
        .any(|issue| issue.code == "root-mountpoint-missing"
            && issue.message.contains("/run is missing")));
}

#[test]
fn rootfs_preflight_rejects_dirty_raw_pool_for_rw() {
    let tmp = TempDir::new().unwrap();
    let images = loop_images(&tmp, 1);
    let fs =
        ArgosFs::create_loop(&images, config(1, 0), 32 * 1024 * 1024, "capos-root", false).unwrap();
    create_rootfs_mountpoints(&fs);
    fs.mkdir("/sbin", 0o755).unwrap();
    fs.write_file("/sbin/init", b"init", 0o755).unwrap();
    fs.sync().unwrap();
    drop(fs);

    let dirty = ArgosFs::open_loop(&images, true).unwrap();
    std::mem::forget(dirty);

    let reopened = ArgosFs::open_loop(&images, false).unwrap();
    let report =
        argosfs::rootfs::preflight_report(&reopened, argosfs::rootfs::RootMountMode::ReadWrite);
    assert!(!report.ok);
    assert_eq!(report.recommended_mode, "recovery");
    assert!(report
        .issues
        .iter()
        .any(|issue| issue.code == "transaction-errors-block-rw"));
    let err =
        argosfs::rootfs::preflight_volume(&reopened, argosfs::rootfs::RootMountMode::ReadWrite)
            .unwrap_err();
    assert!(matches!(err, ArgosError::UnsafeMount(_)));
    assert!(
        argosfs::rootfs::preflight_volume(&reopened, argosfs::rootfs::RootMountMode::Recovery,)
            .is_ok()
    );
}

#[test]
fn loop_block_crash_after_data_flush_before_journal_keeps_old_data() {
    let tmp = TempDir::new().unwrap();
    let images = loop_images(&tmp, 3);
    let fs =
        ArgosFs::create_loop(&images, config(2, 1), 32 * 1024 * 1024, "capos-root", false).unwrap();
    fs.write_file("/crash", b"old", 0o644).unwrap();

    journal::set_thread_crash_point(Some(
        argosfs::types::FaultPoint::AfterDataFlushBeforeJournalCommit.as_str(),
    ));
    let err = fs
        .write_file("/crash", b"new-after-flush", 0o644)
        .unwrap_err();
    journal::set_thread_crash_point(None);
    assert_eq!(err.errno(), libc::EIO);
    drop(fs);

    let reopened = ArgosFs::open_loop(&images, true).unwrap();
    assert_eq!(reopened.read_file("/crash", true).unwrap(), b"old");
    assert!(reopened.fsck(true, true).unwrap().errors.is_empty());
}

#[test]
fn raw_journal_partial_tail_is_audited_and_data_remains_readable() {
    let tmp = TempDir::new().unwrap();
    let images = loop_images(&tmp, 1);
    let fs =
        ArgosFs::create_loop(&images, config(1, 0), 32 * 1024 * 1024, "capos-root", false).unwrap();
    fs.write_file("/journal-tail", b"valid-before-tail", 0o644)
        .unwrap();
    fs.sync().unwrap();
    drop(fs);

    let disk = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&images[0])
        .unwrap();
    let mut header = [0u8; 4096];
    disk.read_at(&mut header, JOURNAL_REGION_OFFSET).unwrap();
    let end = u64::from_le_bytes(header[24..32].try_into().unwrap());
    let mut bad = [0u8; 36];
    bad[..4].copy_from_slice(&128u32.to_le_bytes());
    disk.write_at(&bad, JOURNAL_REGION_OFFSET + end).unwrap();
    header[24..32].copy_from_slice(&(end + bad.len() as u64).to_le_bytes());
    disk.write_at(&header, JOURNAL_REGION_OFFSET).unwrap();
    disk.sync_all().unwrap();

    let reopened = ArgosFs::open_loop(&images, false).unwrap();
    assert_eq!(
        reopened.read_file("/journal-tail", true).unwrap(),
        b"valid-before-tail"
    );
    let report = reopened.transaction_report().unwrap();
    assert!(report.invalid_entries > 0);
    assert_eq!(report.raw_journal_quorum, Some(false));
    assert_eq!(report.raw_journal_members.len(), 1);
    assert!(report.raw_journal_members[0].invalid_entries > 0);
}

#[test]
fn raw_journal_member_reports_quorum_across_devices() {
    let tmp = TempDir::new().unwrap();
    let images = loop_images(&tmp, 3);
    let fs =
        ArgosFs::create_loop(&images, config(2, 1), 32 * 1024 * 1024, "capos-root", false).unwrap();
    fs.write_file("/quorum", b"journal quorum", 0o644).unwrap();
    fs.sync().unwrap();

    let report = fs.transaction_report().unwrap();

    assert_eq!(report.raw_journal_quorum, Some(true));
    assert_eq!(report.raw_journal_members.len(), 3);
    assert!(report
        .raw_journal_members
        .iter()
        .all(|member| member.readable && member.invalid_entries == 0));
    assert!(report
        .raw_journal_members
        .iter()
        .all(|member| member.last_valid_txid == report.last_valid_txid));
}

#[test]
fn raw_journal_rollover_keeps_one_quorum_across_mixed_members() {
    let tmp = TempDir::new().unwrap();
    let images = loop_images(&tmp, 4);
    let fs = ArgosFs::create_loop(
        &images,
        config(3, 1),
        32 * 1024 * 1024,
        "mixed-rollover",
        false,
    )
    .unwrap();
    fs.write_file("/before", b"committed", 0o644).unwrap();
    fs.sync().unwrap();
    let mut next = fs.metadata_snapshot();
    drop(fs);

    let superblocks = images
        .iter()
        .map(|path| {
            argosfs::raw_store::inspect_device(BackendKind::LoopBlock, path.clone())
                .unwrap()
                .0
        })
        .collect::<Vec<_>>();
    for (path, superblock) in images.iter().zip(&superblocks).take(2) {
        let disk = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .unwrap();
        let mut header = [0u8; 4096];
        disk.read_at(&mut header, superblock.journal.offset)
            .unwrap();
        header[24..32].copy_from_slice(&(superblock.journal.length - 1).to_le_bytes());
        disk.write_at(&header, superblock.journal.offset).unwrap();
        disk.sync_all().unwrap();
    }

    let previous_hash = next.integrity.meta_hash.clone();
    next.txid += 1;
    next.raw_pool.pool_name = "after-mixed-rollover".to_string();
    journal::prepare_metadata_integrity_with_previous(&mut next, previous_hash).unwrap();
    let devices = images
        .iter()
        .enumerate()
        .map(|(index, path)| (format!("disk-{index:04}"), path.clone()))
        .collect::<Vec<_>>();
    let backend = FileBlockBackend::open_with_ids(BackendKind::LoopBlock, devices, true).unwrap();
    argosfs::raw_store::append_transaction(
        &backend,
        &superblocks,
        &next,
        "mixed-rollover",
        serde_json::json!({}),
    )
    .unwrap();
    drop(backend);

    let reopened = ArgosFs::open_loop(&images, false).unwrap();
    assert_eq!(reopened.metadata_snapshot().txid, next.txid);
    assert_eq!(
        reopened.metadata_snapshot().raw_pool.pool_name,
        "after-mixed-rollover"
    );
    assert_eq!(
        reopened.transaction_report().unwrap().raw_journal_quorum,
        Some(true)
    );
}

#[test]
fn raw_journal_rollover_checkpoints_large_import_style_workloads() {
    let tmp = TempDir::new().unwrap();
    let images = loop_images(&tmp, 1);
    let fs =
        ArgosFs::create_loop(&images, config(1, 0), 32 * 1024 * 1024, "capos-root", false).unwrap();
    let mut meta = fs.metadata_snapshot();
    drop(fs);

    let devices = images
        .iter()
        .enumerate()
        .map(|(index, path)| (format!("disk-{index:04}"), path.clone()))
        .collect::<Vec<_>>();
    let backend = FileBlockBackend::open_with_ids(BackendKind::LoopBlock, devices, true).unwrap();
    let superblocks = images
        .iter()
        .map(|path| {
            argosfs::raw_store::inspect_device(BackendKind::LoopBlock, path.clone())
                .unwrap()
                .0
        })
        .collect::<Vec<_>>();

    const PAYLOAD_SIZE: usize = 384 * 1024;
    for index in 0..8 {
        let previous = meta.integrity.meta_hash.clone();
        meta.txid += 1;
        meta.inodes.get_mut(&1).unwrap().xattrs.insert(
            format!("user.rollover.{index:04}"),
            "x".repeat(PAYLOAD_SIZE),
        );
        journal::prepare_metadata_integrity_with_previous(&mut meta, previous).unwrap();
        argosfs::raw_store::append_transaction(
            &backend,
            &superblocks,
            &meta,
            "test-rollover",
            serde_json::json!({ "index": index }),
        )
        .unwrap();
    }

    let reopened = ArgosFs::open_loop(&images, false).unwrap();
    let reopened_meta = reopened.metadata_snapshot();
    assert_eq!(
        reopened_meta.inodes[&1].xattrs["user.rollover.0007"].len(),
        PAYLOAD_SIZE
    );
    assert!(reopened.fsck(true, true).unwrap().errors.is_empty());
}

#[test]
fn raw_primary_metadata_corruption_recovers_from_mirror_or_other_device() {
    let tmp = TempDir::new().unwrap();
    let images = loop_images(&tmp, 1);
    let fs =
        ArgosFs::create_loop(&images, config(1, 0), 32 * 1024 * 1024, "capos-root", false).unwrap();
    fs.write_file("/metadata", b"metadata-copy", 0o644).unwrap();
    fs.sync().unwrap();
    drop(fs);

    let disk = fs::OpenOptions::new().write(true).open(&images[0]).unwrap();
    disk.write_at(&[0x5au8; 128], METADATA_REGION_OFFSET + 4096)
        .unwrap();
    disk.sync_all().unwrap();

    let reopened = ArgosFs::open_loop(&images, false).unwrap();
    assert_eq!(
        reopened.read_file("/metadata", true).unwrap(),
        b"metadata-copy"
    );
    let report = reopened.transaction_report().unwrap();
    assert!(report
        .metadata_candidates
        .iter()
        .any(|candidate| candidate.present && !candidate.valid));
}

#[test]
fn raw_metadata_tree_checkpoint_spans_pages() {
    let tmp = TempDir::new().unwrap();
    let images = loop_images(&tmp, 1);
    let fs =
        ArgosFs::create_loop(&images, config(1, 0), 32 * 1024 * 1024, "capos-root", false).unwrap();
    for index in 0..4 {
        fs.setxattr_inode(
            1,
            &format!("user.metadata_tree.{index}"),
            &vec![index as u8; 4096],
        )
        .unwrap();
    }
    fs.sync().unwrap();
    drop(fs);

    let (superblock, _) =
        argosfs::raw_store::inspect_device(BackendKind::LoopBlock, images[0].clone()).unwrap();
    let slot_len = superblock.metadata.length / 2;
    let disk = std::fs::File::open(&images[0]).unwrap();
    let mut observed_page_count = 0;
    for slot in 0..2u64 {
        let mut header = [0u8; 4096];
        disk.read_at(&mut header, superblock.metadata.offset + slot * slot_len)
            .unwrap();
        assert_eq!(&header[..16], b"ARGOSFS-RAW-MD\0\0");
        let checkpoint_format = u32::from_le_bytes(header[20..24].try_into().unwrap());
        assert_eq!(checkpoint_format, 1);
        let page_size = u64::from_le_bytes(header[144..152].try_into().unwrap());
        let page_count = u64::from_le_bytes(header[152..160].try_into().unwrap());
        let index_len = u64::from_le_bytes(header[160..168].try_into().unwrap());
        assert_eq!(page_size, 4096);
        assert_eq!(index_len, page_count * 48);
        observed_page_count = observed_page_count.max(page_count);
    }
    assert!(observed_page_count > 1);

    let reopened = ArgosFs::open_loop(&images, false).unwrap();
    assert_eq!(
        reopened.getxattr_inode(1, "user.metadata_tree.3").unwrap(),
        vec![3u8; 4096]
    );
    assert!(reopened.fsck(true, true).unwrap().errors.is_empty());
}

#[test]
fn raw_deferred_journal_flush_persists_after_sync() {
    let tmp = TempDir::new().unwrap();
    let images = loop_images(&tmp, 1);
    let mut cfg = config(1, 0);
    cfg.defer_journal_flush = true;
    cfg.compression = Compression::None;
    let fs = ArgosFs::create_loop(&images, cfg, 32 * 1024 * 1024, "capos-root", false).unwrap();
    fs.write_file("/deferred", b"journal flush at sync", 0o644)
        .unwrap();
    fs.sync().unwrap();
    drop(fs);

    let reopened = ArgosFs::open_loop(&images, false).unwrap();
    assert_eq!(
        reopened.read_file("/deferred", true).unwrap(),
        b"journal flush at sync"
    );
    assert!(reopened.transaction_report().unwrap().errors.is_empty());
}

#[test]
fn raw_batched_metadata_commit_persists_after_sync() {
    let tmp = TempDir::new().unwrap();
    let images = loop_images(&tmp, 1);
    let mut cfg = config(1, 0);
    cfg.defer_journal_flush = true;
    cfg.defer_metadata_commit = true;
    cfg.defer_data_flush = true;
    cfg.compression = Compression::None;
    let fs = ArgosFs::create_loop(&images, cfg, 32 * 1024 * 1024, "capos-root", false).unwrap();
    for index in 0..16 {
        fs.write_file(
            &format!("/batched-{index:04}"),
            format!("batched-payload-{index:04}").as_bytes(),
            0o644,
        )
        .unwrap();
    }
    fs.sync().unwrap();
    drop(fs);

    let reopened = ArgosFs::open_loop(&images, false).unwrap();
    assert_eq!(
        reopened.read_file("/batched-0015", true).unwrap(),
        b"batched-payload-0015"
    );
    assert!(reopened.fsck(true, true).unwrap().errors.is_empty());
}

#[test]
fn raw_group_commit_reuses_open_device_after_path_disappears() {
    let tmp = TempDir::new().unwrap();
    let original = tmp.path().join("root.img");
    let moved = tmp.path().join("root-after-switch-root.img");
    let images = vec![original.clone()];
    let mut cfg = config(1, 0);
    cfg.defer_journal_flush = true;
    cfg.defer_metadata_commit = true;
    cfg.defer_data_flush = true;
    cfg.deferred_commit_interval_ms = 60_000;
    cfg.deferred_commit_max_transactions = 1_000;
    cfg.compression = Compression::None;
    let fs =
        ArgosFs::create_loop(&images, cfg, 32 * 1024 * 1024, "switch-root-handles", false).unwrap();
    fs.write_file("/before", &vec![b'b'; 2048], 0o644).unwrap();
    fs.sync().unwrap();

    std::fs::rename(&original, &moved).unwrap();
    fs.write_file("/after", &vec![b'a'; 2048], 0o644).unwrap();
    assert!(fs.sync_deferred_if_dirty().unwrap());
    assert!(fs.transaction_report().unwrap().errors.is_empty());
    drop(fs);

    let reopened = ArgosFs::open_loop(&[moved], false).unwrap();
    assert_eq!(
        reopened.read_file("/before", true).unwrap(),
        vec![b'b'; 2048]
    );
    assert_eq!(
        reopened.read_file("/after", true).unwrap(),
        vec![b'a'; 2048]
    );
    assert!(reopened.transaction_report().unwrap().errors.is_empty());
}

#[test]
fn raw_group_commit_batches_transactions_into_one_durable_record() {
    let tmp = TempDir::new().unwrap();
    let images = loop_images(&tmp, 1);
    let mut cfg = config(1, 0);
    cfg.defer_journal_flush = true;
    cfg.defer_metadata_commit = true;
    cfg.defer_data_flush = true;
    cfg.deferred_commit_interval_ms = 60_000;
    cfg.deferred_commit_max_transactions = 1_000;
    cfg.compression = Compression::None;
    let fs = ArgosFs::create_loop(&images, cfg, 32 * 1024 * 1024, "group-commit", false).unwrap();

    for index in 0..8 {
        fs.write_file(
            &format!("/batched-{index:04}"),
            &vec![index as u8; 2048],
            0o644,
        )
        .unwrap();
    }
    assert_eq!(raw_journal_records(&images[0]).len(), 1);

    let expected_txid = fs.metadata_snapshot().txid;
    fs.sync().unwrap();
    let records = raw_journal_records(&images[0]);
    assert_eq!(records.len(), 2);
    let group = records.last().unwrap();
    assert_eq!(group["action"], "group-commit");
    assert_eq!(group["txid"], expected_txid);
    assert_eq!(group["details"]["transactions"], 16);
    assert!(group.get("metadata").is_none());
    assert!(group.get("metadata_delta").is_some());

    drop(fs);
    let reopened = ArgosFs::open_loop(&images, false).unwrap();
    assert_eq!(
        reopened.read_file("/batched-0007", true).unwrap(),
        vec![7u8; 2048]
    );
}

#[test]
fn raw_group_commit_forces_at_transaction_limit() {
    let tmp = TempDir::new().unwrap();
    let images = loop_images(&tmp, 1);
    let mut cfg = config(1, 0);
    cfg.defer_journal_flush = true;
    cfg.defer_metadata_commit = true;
    cfg.defer_data_flush = true;
    cfg.deferred_commit_interval_ms = 60_000;
    cfg.deferred_commit_max_transactions = 4;
    cfg.compression = Compression::None;
    let fs = ArgosFs::create_loop(&images, cfg, 32 * 1024 * 1024, "group-limit", false).unwrap();

    fs.write_file("/one", &vec![1u8; 2048], 0o644).unwrap();
    assert_eq!(raw_journal_records(&images[0]).len(), 1);
    fs.write_file("/two", &vec![2u8; 2048], 0o644).unwrap();

    let records = raw_journal_records(&images[0]);
    assert_eq!(records.len(), 2);
    assert_eq!(records.last().unwrap()["action"], "group-commit");
    assert_eq!(records.last().unwrap()["details"]["transactions"], 4);
}

#[test]
fn raw_group_commit_limit_failure_is_reported_and_retryable() {
    let tmp = TempDir::new().unwrap();
    let images = loop_images(&tmp, 1);
    let mut cfg = config(1, 0);
    cfg.defer_journal_flush = true;
    cfg.defer_metadata_commit = true;
    cfg.defer_data_flush = true;
    cfg.deferred_commit_interval_ms = 60_000;
    cfg.deferred_commit_max_transactions = 2;
    cfg.compression = Compression::None;
    let fs = ArgosFs::create_loop(&images, cfg, 32 * 1024 * 1024, "group-retry", false).unwrap();

    let _crash = journal::thread_crash_point(
        argosfs::types::FaultPoint::AfterDataFlushBeforeJournalCommit.as_str(),
    );
    let err = fs
        .write_file("/retry", &vec![b'r'; 2048], 0o644)
        .unwrap_err();
    assert!(matches!(err, ArgosError::InjectedCrash(_)));
    drop(_crash);

    assert_eq!(raw_journal_records(&images[0]).len(), 1);
    fs.sync().unwrap();
    drop(fs);

    let reopened = ArgosFs::open_loop(&images, false).unwrap();
    assert_eq!(
        reopened.read_file("/retry", true).unwrap(),
        vec![b'r'; 2048]
    );
    assert_eq!(reopened.transaction_report().unwrap().invalid_entries, 0);
}

#[test]
fn raw_deferred_reclamation_does_not_reuse_last_durable_extent() {
    let tmp = TempDir::new().unwrap();
    let images = loop_images(&tmp, 1);
    let mut cfg = config(1, 0);
    cfg.defer_journal_flush = true;
    cfg.defer_metadata_commit = true;
    cfg.defer_data_flush = true;
    cfg.deferred_commit_interval_ms = 60_000;
    cfg.deferred_commit_max_transactions = 1_000;
    cfg.compression = Compression::None;
    let fs = ArgosFs::create_loop(&images, cfg, 32 * 1024 * 1024, "safe-reclaim", false).unwrap();

    let old = vec![b'a'; 2048];
    fs.write_file("/value", &old, 0o644).unwrap();
    fs.sync().unwrap();
    let value_ino = fs.resolve_path("/value", true).unwrap();
    let durable = fs.metadata_snapshot();
    let old_extent = match durable.inodes[&value_ino].blocks[0].shards[0]
        .location
        .as_ref()
        .unwrap()
    {
        ShardLocation::RawExtent(extent) => extent.clone(),
        other => panic!("expected raw extent, got {other:?}"),
    };

    fs.write_file("/value", &vec![b'b'; 2048], 0o644).unwrap();
    fs.write_file("/other", &vec![b'c'; 2048], 0o644).unwrap();
    let other_ino = fs.resolve_path("/other", true).unwrap();
    let pending = fs.metadata_snapshot();
    let other_extent = match pending.inodes[&other_ino].blocks[0].shards[0]
        .location
        .as_ref()
        .unwrap()
    {
        ShardLocation::RawExtent(extent) => extent.clone(),
        other => panic!("expected raw extent, got {other:?}"),
    };
    assert_ne!(other_extent.offset, old_extent.offset);
    assert!(!pending.raw_pool.allocators[&old_extent.disk_id]
        .free_extents
        .iter()
        .any(|extent| extent.offset == old_extent.offset));

    std::mem::forget(fs);
    let reopened = ArgosFs::open_loop(&images, false).unwrap();
    assert_eq!(reopened.read_file("/value", true).unwrap(), old);
    assert_eq!(
        reopened.resolve_path("/other", true).unwrap_err().errno(),
        libc::ENOENT
    );
}

#[test]
fn raw_group_commit_reclaims_old_extent_after_durability_boundary() {
    let tmp = TempDir::new().unwrap();
    let images = loop_images(&tmp, 1);
    let mut cfg = config(1, 0);
    cfg.defer_journal_flush = true;
    cfg.defer_metadata_commit = true;
    cfg.defer_data_flush = true;
    cfg.deferred_commit_interval_ms = 60_000;
    cfg.deferred_commit_max_transactions = 1_000;
    cfg.compression = Compression::None;
    let fs =
        ArgosFs::create_loop(&images, cfg, 32 * 1024 * 1024, "reclaim-boundary", false).unwrap();

    fs.write_file("/value", &vec![b'a'; 2048], 0o644).unwrap();
    fs.sync().unwrap();
    let ino = fs.resolve_path("/value", true).unwrap();
    let before = fs.metadata_snapshot();
    let old_extent = match before.inodes[&ino].blocks[0].shards[0]
        .location
        .as_ref()
        .unwrap()
    {
        ShardLocation::RawExtent(extent) => extent.clone(),
        other => panic!("expected raw extent, got {other:?}"),
    };

    fs.write_file("/value", &vec![b'b'; 2048], 0o644).unwrap();
    fs.sync().unwrap();
    let committed = fs.metadata_snapshot();
    assert!(committed.raw_pool.allocators[&old_extent.disk_id]
        .free_extents
        .iter()
        .any(|extent| extent.offset == old_extent.offset));
}

#[test]
fn deferred_commit_bounds_default_when_loading_legacy_config_json() {
    let mut value = serde_json::to_value(VolumeConfig::default()).unwrap();
    let object = value.as_object_mut().unwrap();
    object.remove("deferred_commit_interval_ms");
    object.remove("deferred_commit_max_transactions");
    let config: VolumeConfig = serde_json::from_value(value).unwrap();
    assert_eq!(
        config.deferred_commit_interval_ms,
        argosfs::types::DEFAULT_DEFERRED_COMMIT_INTERVAL_MS
    );
    assert_eq!(
        config.deferred_commit_max_transactions,
        argosfs::types::DEFAULT_DEFERRED_COMMIT_MAX_TRANSACTIONS
    );
}

#[test]
fn raw_deferred_data_flush_requires_batched_metadata_commit() {
    let tmp = TempDir::new().unwrap();
    let images = loop_images(&tmp, 1);
    let mut cfg = config(1, 0);
    cfg.defer_data_flush = true;
    let err = match ArgosFs::create_loop(&images, cfg, 32 * 1024 * 1024, "capos-root", false) {
        Ok(_) => panic!("defer-data-flush without batched metadata should fail"),
        Err(err) => err,
    };
    assert!(matches!(err, ArgosError::Invalid(message) if message.contains("defer-data-flush")));
}

#[test]
fn raw_hot_file_transactions_use_metadata_deltas() {
    let _guard = env_lock();
    let _interval = journal::thread_checkpoint_interval(1000);
    let tmp = TempDir::new().unwrap();
    let images = loop_images(&tmp, 1);
    let mut cfg = config(1, 0);
    cfg.compression = Compression::None;
    let fs = ArgosFs::create_loop(&images, cfg, 32 * 1024 * 1024, "capos-root", false).unwrap();
    for index in 0..8 {
        fs.write_file(
            &format!("/delta-{index:04}"),
            format!("payload-{index:04}").as_bytes(),
            0o644,
        )
        .unwrap();
    }
    drop(fs);

    let records = raw_journal_records(&images[0]);
    let hot_records = records
        .iter()
        .filter(|record| record["action"] == "mknod" || record["action"] == "write")
        .collect::<Vec<_>>();
    assert!(!hot_records.is_empty());
    assert!(hot_records
        .iter()
        .all(|record| record.get("metadata").is_none()));
    assert!(hot_records
        .iter()
        .all(|record| record.get("metadata_delta").is_some()));
}

#[test]
fn failed_multistripe_raw_write_rolls_back_allocator_state() {
    let tmp = TempDir::new().unwrap();
    let images = loop_images(&tmp, 1);
    let mut cfg = config(1, 0);
    cfg.chunk_size = 8 * 1024 * 1024;
    cfg.compression = Compression::None;
    let fs = ArgosFs::create_loop(&images, cfg, 32 * 1024 * 1024, "rollback", false).unwrap();
    let ino = fs.create_file_path("/victim", 0o600).unwrap();
    let before = fs.metadata_snapshot();
    let disk_id = before.disks.keys().next().unwrap().clone();
    let allocator_before = before.raw_pool.allocators[&disk_id].clone();

    assert!(fs
        .write_inode_range(ino, 0, &vec![b'x'; 16 * 1024 * 1024])
        .is_err());

    let after = fs.metadata_snapshot();
    assert_eq!(after.inodes[&ino].size, 0);
    assert_eq!(
        after.raw_pool.allocators[&disk_id].next_offset,
        allocator_before.next_offset
    );
    assert_eq!(
        after.raw_pool.allocators[&disk_id].free_extents,
        allocator_before.free_extents
    );
    assert_eq!(
        after.disks[&disk_id].used_bytes,
        before.disks[&disk_id].used_bytes
    );
}

#[test]
fn raw_allocator_inconsistency_is_reported_by_fsck() {
    let tmp = TempDir::new().unwrap();
    let images = loop_images(&tmp, 1);
    let fs =
        ArgosFs::create_loop(&images, config(1, 0), 32 * 1024 * 1024, "capos-root", false).unwrap();
    let payload = vec![b'a'; 20 * 1024];
    fs.write_file("/allocator", &payload, 0o644).unwrap();
    let mut meta = fs.metadata_snapshot();
    let inode = meta
        .inodes
        .values()
        .find(|inode| inode.size == payload.len() as u64)
        .unwrap();
    let extent = match inode.blocks[0].shards[0].location.as_ref().unwrap() {
        ShardLocation::RawExtent(extent) => extent.clone(),
        _ => panic!("expected raw extent"),
    };
    meta.raw_pool
        .allocators
        .get_mut(&extent.disk_id)
        .unwrap()
        .free_extents
        .push(RawFreeExtent {
            offset: extent.offset,
            length: extent.length,
        });
    meta.txid += 1;
    let previous = meta.integrity.meta_hash.clone();
    journal::prepare_metadata_integrity_with_previous(&mut meta, previous).unwrap();

    let devices = images
        .iter()
        .enumerate()
        .map(|(index, path)| (format!("disk-{index:04}"), path.clone()))
        .collect::<Vec<_>>();
    let backend = FileBlockBackend::open_with_ids(BackendKind::LoopBlock, devices, true).unwrap();
    let superblocks = images
        .iter()
        .map(|path| {
            argosfs::raw_store::inspect_device(BackendKind::LoopBlock, path.clone())
                .unwrap()
                .0
        })
        .collect::<Vec<_>>();
    argosfs::raw_store::append_transaction(
        &backend,
        &superblocks,
        &meta,
        "test-corrupt-allocator",
        serde_json::json!({}),
    )
    .unwrap();
    drop(fs);

    let reopened = ArgosFs::open_loop(&images, false).unwrap();
    let report = reopened.fsck(false, false).unwrap();
    assert!(report
        .errors
        .iter()
        .any(|error| error.contains("overlaps allocator free list")));
}

#[test]
fn loop_block_open_rejects_duplicate_disk_id_conflict() {
    let tmp = TempDir::new().unwrap();
    let images = loop_images(&tmp, 3);
    let fs =
        ArgosFs::create_loop(&images, config(2, 1), 32 * 1024 * 1024, "capos-root", false).unwrap();
    drop(fs);

    let mut bytes = vec![0u8; SUPERBLOCK_SIZE];
    let disk1 = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&images[1])
        .unwrap();
    disk1
        .read_at(&mut bytes, PRIMARY_SUPERBLOCK_OFFSET)
        .unwrap();
    let mut superblock = argosfs::raw_format::RawSuperblock::decode(&bytes).unwrap();
    superblock.disk_id = "disk-0000".to_string();
    disk1
        .write_at(&superblock.encode(), PRIMARY_SUPERBLOCK_OFFSET)
        .unwrap();
    disk1
        .write_at(&superblock.device_label().encode(), DEVICE_LABEL_OFFSET)
        .unwrap();
    disk1
        .write_at(&superblock.encode(), superblock.backup_superblock_offset)
        .unwrap();
    disk1.sync_all().unwrap();

    let err = match ArgosFs::open_loop(&images, false) {
        Ok(_) => panic!("duplicate disk id should be rejected"),
        Err(err) => err,
    };
    assert!(matches!(err, ArgosError::IncompatibleFormat(_)));
    assert!(err.to_string().contains("duplicate ArgosFS disk id"));
}

#[test]
fn loop_block_add_device_initializes_new_member() {
    let tmp = TempDir::new().unwrap();
    let mut images = loop_images(&tmp, 3);
    let fs =
        ArgosFs::create_loop(&images, config(2, 1), 32 * 1024 * 1024, "capos-root", false).unwrap();
    fs.write_file("/payload", b"before-add", 0o644).unwrap();
    let new_image = tmp.path().join("disk3.img");
    let disk_id = fs
        .add_block_device(new_image.clone(), 32 * 1024 * 1024, false)
        .unwrap();
    assert_eq!(disk_id, "disk-0003");
    drop(fs);

    images.push(new_image);
    let reopened = ArgosFs::open_loop(&images, false).unwrap();
    assert!(reopened.metadata_snapshot().disks.contains_key("disk-0003"));
    assert_eq!(
        reopened.read_file("/payload", false).unwrap(),
        b"before-add"
    );
    let scan = argosfs::scan::scan_images(&images);
    assert_eq!(scan.iter().filter(|device| device.valid).count(), 4);
}

#[test]
fn loop_block_cli_replace_device_rewrites_off_old_member() {
    let tmp = TempDir::new().unwrap();
    let images = loop_images(&tmp, 3);
    let fs =
        ArgosFs::create_loop(&images, config(2, 1), 32 * 1024 * 1024, "capos-root", false).unwrap();
    fs.write_file("/payload", b"before-replace", 0o644).unwrap();
    drop(fs);

    let new_image = tmp.path().join("disk3.img");
    let images_arg = images
        .iter()
        .map(|path| path.to_string_lossy())
        .collect::<Vec<_>>()
        .join(",");
    let status = Command::new(argosfs_binary())
        .arg("replace-device")
        .arg("--backend")
        .arg("loop")
        .arg("--images")
        .arg(images_arg)
        .arg("--old")
        .arg("disk-0002")
        .arg("--new")
        .arg(&new_image)
        .arg("--image-size")
        .arg((32 * 1024 * 1024).to_string())
        .status()
        .unwrap();
    assert!(status.success());

    let remaining = vec![images[0].clone(), images[1].clone(), new_image];
    let reopened = ArgosFs::open_loop(&remaining, false).unwrap();
    assert_eq!(
        reopened.read_file("/payload", false).unwrap(),
        b"before-replace"
    );
}

#[test]
fn repeated_loop_replacements_do_not_raise_quorum_with_removed_members() {
    let tmp = TempDir::new().unwrap();
    let mut active = loop_images(&tmp, 3);
    let fs =
        ArgosFs::create_loop(&active, config(2, 1), 32 * 1024 * 1024, "quorum", false).unwrap();
    fs.write_file("/payload", b"survives-replacements", 0o644)
        .unwrap();
    drop(fs);

    for index in 0..3 {
        let new_image = tmp.path().join(format!("replacement-{index}.img"));
        let images_arg = active
            .iter()
            .map(|path| path.to_string_lossy())
            .collect::<Vec<_>>()
            .join(",");
        let output = Command::new(argosfs_binary())
            .args([
                "replace-device",
                "--backend",
                "loop",
                "--images",
                &images_arg,
                "--old",
                &format!("disk-{index:04}"),
                "--new",
            ])
            .arg(&new_image)
            .args(["--image-size", &(32 * 1024 * 1024).to_string()])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "replacement {index} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        active.remove(0);
        active.push(new_image);
    }

    let reopened = ArgosFs::open_loop(&active, false).unwrap();
    assert_eq!(
        reopened.read_file("/payload", false).unwrap(),
        b"survives-replacements"
    );
    for index in 0..3 {
        assert_eq!(
            reopened.metadata_snapshot().disks[&format!("disk-{index:04}")].status,
            DiskStatus::Removed
        );
    }
}

#[test]
fn raw_recovery_ignores_unquorumed_metadata_and_journal_tail() {
    let tmp = TempDir::new().unwrap();
    let images = loop_images(&tmp, 3);
    let mut cfg = config(2, 1);
    cfg.compression = Compression::None;
    let fs = ArgosFs::create_loop(&images, cfg, 32 * 1024 * 1024, "quorum", false).unwrap();
    fs.write_file("/value", b"committed", 0o644).unwrap();
    fs.sync().unwrap();
    let committed = fs.metadata_snapshot();
    drop(fs);

    let mut uncommitted = committed.clone();
    uncommitted.raw_pool.pool_name = "unquorumed".to_string();
    uncommitted.txid += 1;
    let previous_hash = uncommitted.integrity.meta_hash.clone();
    journal::prepare_metadata_integrity_with_previous(&mut uncommitted, previous_hash).unwrap();

    let disk_id = "disk-0000".to_string();
    let backend = FileBlockBackend::open_with_ids(
        BackendKind::LoopBlock,
        vec![(disk_id, images[0].clone())],
        true,
    )
    .unwrap();
    let superblock = argosfs::raw_store::inspect_device(BackendKind::LoopBlock, images[0].clone())
        .unwrap()
        .0;
    argosfs::raw_store::append_transaction(
        &backend,
        std::slice::from_ref(&superblock),
        &uncommitted,
        "unquorumed-tail",
        serde_json::json!({}),
    )
    .unwrap();
    argosfs::raw_store::write_metadata_copies(
        &backend,
        std::slice::from_ref(&superblock),
        &uncommitted,
    )
    .unwrap();
    drop(backend);

    let reopened = ArgosFs::open_loop(&images, false).unwrap();
    assert_eq!(reopened.metadata_snapshot().txid, committed.txid);
    assert_eq!(reopened.metadata_snapshot().raw_pool.pool_name, "quorum");
    assert_eq!(reopened.read_file("/value", true).unwrap(), b"committed");
}

#[test]
fn raw_partial_fanout_crash_helper() {
    let Some(root) = std::env::var_os("ARGOSFS_TEST_PARTIAL_FANOUT_ROOT") else {
        return;
    };
    let root = std::path::PathBuf::from(root);
    let images = (0..3)
        .map(|index| root.join(format!("disk{index}.img")))
        .collect::<Vec<_>>();
    let fs = ArgosFs::open_loop(&images, true).unwrap();
    std::env::set_var(
        "ARGOSFS_CRASH_POINT",
        argosfs::types::FaultPoint::AfterPartialJournalFanout.as_str(),
    );
    std::env::set_var("ARGOSFS_CRASH_ABORT", "1");
    let _ = fs.write_file("/quorum-value", b"uncommitted-single-member", 0o644);
    panic!("partial journal fanout crash point did not abort");
}

#[test]
fn raw_recovery_ignores_journal_head_without_membership_quorum() {
    let _guard = env_lock();
    let tmp = TempDir::new().unwrap();
    let images = loop_images(&tmp, 3);
    let fs =
        ArgosFs::create_loop(&images, config(2, 1), 32 * 1024 * 1024, "capos-root", false).unwrap();
    fs.write_file("/quorum-value", b"committed-majority", 0o644)
        .unwrap();
    fs.sync().unwrap();
    drop(fs);

    let status = Command::new(std::env::current_exe().unwrap())
        .arg("--exact")
        .arg("block_backend::raw_partial_fanout_crash_helper")
        .arg("--nocapture")
        .env("ARGOSFS_TEST_PARTIAL_FANOUT_ROOT", tmp.path())
        .status()
        .unwrap();
    assert!(!status.success());

    let reopened = ArgosFs::open_loop(&images, false).unwrap();
    assert_eq!(
        reopened.read_file("/quorum-value", false).unwrap(),
        b"committed-majority"
    );
    assert_eq!(reopened.metadata_snapshot().txid, 2);
    assert_eq!(
        reopened.transaction_report().unwrap().raw_journal_quorum,
        Some(true)
    );
}

#[test]
fn committed_raw_replacement_persists_old_extent_reclamation() {
    let _guard = env_lock();
    let tmp = TempDir::new().unwrap();
    let images = loop_images(&tmp, 1);
    let mut cfg = config(1, 0);
    cfg.compression = Compression::None;
    let fs = ArgosFs::create_loop(&images, cfg, 32 * 1024 * 1024, "reclaim", false).unwrap();
    fs.write_file("/value", &vec![b'a'; 1024], 0o600).unwrap();
    fs.sync().unwrap();
    let before = fs.metadata_snapshot();
    let ino = fs.resolve_path("/value", false).unwrap();
    let old_extent = match before.inodes[&ino].blocks[0].shards[0]
        .location
        .as_ref()
        .unwrap()
    {
        ShardLocation::RawExtent(extent) => extent.clone(),
        _ => panic!("expected raw extent"),
    };

    let _crash = journal::thread_crash_point(
        argosfs::types::FaultPoint::AfterJournalCommitBeforeMetadataCommit.as_str(),
    );
    assert!(matches!(
        fs.write_file("/value", &vec![b'b'; 1024], 0o600)
            .unwrap_err(),
        ArgosError::InjectedCrash(_)
    ));
    drop(_crash);
    drop(fs);

    let reopened = ArgosFs::open_loop(&images, false).unwrap();
    assert_eq!(
        reopened.read_file("/value", false).unwrap(),
        vec![b'b'; 1024]
    );
    let allocator = &reopened.metadata_snapshot().raw_pool.allocators[&old_extent.disk_id];
    assert!(allocator.free_extents.iter().any(|free| {
        free.offset <= old_extent.offset
            && free.offset.saturating_add(free.length)
                >= old_extent.offset.saturating_add(old_extent.length)
    }));
}

#[test]
fn failed_raw_commit_restores_in_memory_metadata_before_returning() {
    let _guard = env_lock();
    let tmp = TempDir::new().unwrap();
    let images = loop_images(&tmp, 3);
    let fs =
        ArgosFs::create_loop(&images, config(2, 1), 32 * 1024 * 1024, "capos-root", false).unwrap();
    fs.write_file("/atomic-value", b"old", 0o644).unwrap();
    fs.sync().unwrap();

    let _crash =
        journal::thread_crash_point(argosfs::types::FaultPoint::AfterPartialJournalFanout.as_str());
    let err = fs
        .write_file("/atomic-value", b"must-not-survive", 0o644)
        .unwrap_err();
    assert!(matches!(err, ArgosError::InjectedCrash(_)));
    assert_eq!(fs.read_file("/atomic-value", false).unwrap(), b"old");

    fs.sync().unwrap();
    drop(fs);
    let reopened = ArgosFs::open_loop(&images, false).unwrap();
    assert_eq!(reopened.read_file("/atomic-value", false).unwrap(), b"old");
}

#[test]
fn raw_mkfs_rejects_luks_and_unknown_nonzero_data_without_force() {
    let tmp = TempDir::new().unwrap();
    let luks = tmp.path().join("luks.img");
    let unknown = tmp.path().join("unknown.img");
    for path in [&luks, &unknown] {
        let file = fs::File::create(path).unwrap();
        file.set_len(32 * 1024 * 1024).unwrap();
    }
    fs::OpenOptions::new()
        .write(true)
        .open(&luks)
        .unwrap()
        .write_at(b"LUKS\xba\xbe", 0)
        .unwrap();
    fs::OpenOptions::new()
        .write(true)
        .open(&unknown)
        .unwrap()
        .write_at(b"old-data", 1024 * 1024)
        .unwrap();

    for path in [&luks, &unknown] {
        let err =
            match ArgosFs::create_raw(std::slice::from_ref(path), config(1, 0), "safe-mkfs", false)
            {
                Ok(_) => panic!("raw mkfs unexpectedly overwrote {}", path.display()),
                Err(err) => err,
            };
        assert!(matches!(err, ArgosError::UnsafeMount(_)));
    }

    let forced = ArgosFs::create_raw(
        std::slice::from_ref(&luks),
        config(1, 0),
        "forced-mkfs",
        true,
    )
    .unwrap();
    drop(forced);
}

#[test]
fn raw_reshape_delta_post_journal_crash_helper() {
    let Some(root) = std::env::var_os("ARGOSFS_TEST_RESHAPE_DELTA_ROOT") else {
        return;
    };
    let root = std::path::PathBuf::from(root);
    let images = vec![root.join("disk0.img"), root.join("disk1.img")];
    let fs = ArgosFs::open_loop(&images, true).unwrap();
    std::env::set_var(
        "ARGOSFS_CRASH_POINT",
        argosfs::types::FaultPoint::AfterJournalCommitBeforeMetadataCommit.as_str(),
    );
    std::env::set_var("ARGOSFS_CRASH_ABORT", "1");
    let _ = fs.reshape_layout(1, 1, Some(1));
    panic!("post-journal reshape crash point did not abort");
}

#[test]
fn raw_reshape_replay_uses_only_durable_delta_bases() {
    let _guard = env_lock();
    let tmp = TempDir::new().unwrap();
    let mut images = vec![tmp.path().join("disk0.img")];
    let fs = ArgosFs::create_loop(
        &images,
        config(1, 0),
        32 * 1024 * 1024,
        "reshape-delta",
        false,
    )
    .unwrap();
    let a_payload = vec![b'a'; 20 * 1024];
    let b_payload = vec![b'b'; 20 * 1024];
    fs.write_file("/a", &a_payload, 0o644).unwrap();
    fs.write_file("/b", &b_payload, 0o644).unwrap();
    let new_image = tmp.path().join("disk1.img");
    fs.add_block_device(new_image.clone(), 32 * 1024 * 1024, false)
        .unwrap();
    images.push(new_image);
    fs.reshape_layout(1, 1, Some(0)).unwrap();
    assert_eq!(fs.read_file("/a", true).unwrap(), a_payload.as_slice());
    fs.mark_clean_unmount().unwrap();
    drop(fs);

    let status = Command::new(std::env::current_exe().unwrap())
        .arg("--exact")
        .arg("block_backend::raw_reshape_delta_post_journal_crash_helper")
        .arg("--nocapture")
        .env("ARGOSFS_TEST_RESHAPE_DELTA_ROOT", tmp.path())
        .status()
        .unwrap();
    assert!(!status.success());

    let reopened = ArgosFs::open_loop(&images, false).unwrap();
    let report = reopened.transaction_report().unwrap();
    assert_eq!(report.invalid_entries, 0, "{:#?}", report.errors);
    assert!(report.replayed);
    assert_eq!(reopened.metadata_snapshot().txid, 7);
    assert_eq!(reopened.read_file("/a", false).unwrap(), a_payload);
    assert_eq!(reopened.read_file("/b", false).unwrap(), b_payload);
}
