use super::*;
use std::sync::{Mutex as StdMutex, OnceLock};
use tempfile::tempdir;

fn env_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: OnceLock<StdMutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| StdMutex::new(())).lock().unwrap()
}

fn host_volume(disks: usize) -> (tempfile::TempDir, ArgosFs) {
    let dir = tempdir().unwrap();
    let fs = ArgosFs::create(
        dir.path(),
        VolumeConfig {
            k: 1,
            m: 0,
            ..VolumeConfig::default()
        },
        disks,
        false,
    )
    .unwrap();
    (dir, fs)
}

#[test]
fn io_policy_and_encryption_cover_empty_repeat_and_wrong_passphrases() {
    let _guard = env_lock();
    let (_dir, fs) = host_volume(1);
    fs.set_io_policy(IoMode::Direct, true, false, false)
        .unwrap();
    let policy = fs.io_policy();
    assert_eq!(policy.io_mode, IoMode::Direct);
    assert!(policy.direct_io);
    assert!(!policy.zero_copy);
    assert!(!policy.numa_aware);

    assert!(matches!(
        fs.enable_encryption(""),
        Err(ArgosError::Invalid(_))
    ));
    fs.enable_encryption("correct").unwrap();
    fs.enable_encryption("correct").unwrap();
    assert!(matches!(
        fs.enable_encryption("wrong"),
        Err(ArgosError::PermissionDenied(_))
    ));
    assert!(fs.health_report().encryption_enabled);
}

#[test]
fn add_disk_clamps_weight_tracks_capacity_and_rejects_duplicate_paths() {
    let (dir, fs) = host_volume(1);
    let path = dir.path().join("extra");
    let id = fs
        .add_disk(
            Some(path.clone()),
            Some(StorageTier::Cold),
            Some(0.0),
            Some(12345),
            false,
        )
        .unwrap();
    let meta = fs.metadata_snapshot();
    let disk = &meta.disks[&id];
    assert_eq!(disk.tier, StorageTier::Cold);
    assert_eq!(disk.weight, 0.01);
    assert_eq!(disk.capacity_bytes, 12345);
    assert_eq!(disk.capacity_source, CapacitySource::UserOverride);
    assert!(path.join("argosfs-disk.json").exists());
    assert!(matches!(
        fs.add_disk(Some(path), None, None, None, false),
        Err(ArgosError::AlreadyExists(_))
    ));

    let automatic = fs.add_disk(None, None, None, None, true).unwrap();
    assert!(fs.metadata_snapshot().disks.contains_key(&automatic));
}

#[test]
fn host_block_device_and_missing_disk_operations_report_expected_errors() {
    let (dir, fs) = host_volume(1);
    assert!(matches!(
        fs.add_block_device(dir.path().join("device.img"), 32 * 1024 * 1024, false),
        Err(ArgosError::Unsupported(_))
    ));
    assert!(matches!(
        fs.mark_disk("missing", DiskStatus::Offline),
        Err(ArgosError::NotFound(_))
    ));
    assert!(matches!(
        fs.set_disk_health("missing", HealthCounters::default()),
        Err(ArgosError::NotFound(_))
    ));
    assert!(matches!(
        fs.refresh_disk_probe(Some("missing")),
        Err(ArgosError::NotFound(_))
    ));
    assert!(matches!(
        fs.refresh_smart_health(Some("missing")),
        Err(ArgosError::NotFound(_))
    ));
    assert!(matches!(
        fs.drain_disk("missing"),
        Err(ArgosError::NotFound(_))
    ));
}

#[test]
fn health_probe_and_smart_refresh_cover_observation_and_all_failed_paths() {
    let (_dir, fs) = host_volume(1);
    let disk_id = fs.metadata_snapshot().disks.keys().next().unwrap().clone();
    fs.set_disk_health(
        &disk_id,
        HealthCounters {
            latency_ms: 12.5,
            temperature_c: 40.0,
            ..HealthCounters::default()
        },
    )
    .unwrap();
    let disk = &fs.metadata_snapshot().disks[&disk_id];
    assert_eq!(disk.read_latency_ewma_ms, 12.5);
    assert_eq!(disk.write_latency_ewma_ms, 12.5);
    assert_eq!(disk.health.temperature_c, 40.0);

    let before = fs.metadata_snapshot().disks[&disk_id].clone();
    let observed = fs.refresh_disk_probe_observations(Some(&disk_id)).unwrap();
    assert_eq!(observed.len(), 1);
    let after_observation = fs.metadata_snapshot().disks[&disk_id].clone();
    assert_eq!(after_observation.tier, before.tier);
    assert_eq!(after_observation.weight, before.weight);
    assert!(after_observation.io_samples > before.io_samples);
    assert_eq!(fs.refresh_disk_probe(None).unwrap().len(), 1);
    match fs.refresh_smart_health(Some(&disk_id)) {
        Ok(refreshed) => assert_eq!(refreshed.len(), 1),
        Err(ArgosError::Unsupported(_)) => {}
        Err(error) => panic!("unexpected SMART refresh error: {error}"),
    }
}

#[test]
fn drain_remove_rebalance_and_zero_budget_paths_cover_capacity_rules() {
    let (dir, fs) = host_volume(1);
    let original = fs.metadata_snapshot().disks.keys().next().unwrap().clone();
    assert!(matches!(
        fs.drain_disk(&original),
        Err(ArgosError::NotEnoughDisks { .. })
    ));
    let extra = fs
        .add_disk(
            Some(dir.path().join("extra-disk")),
            None,
            None,
            Some(64 * 1024 * 1024),
            false,
        )
        .unwrap();
    assert_eq!(fs.drain_disk(&extra).unwrap(), 0);
    assert_eq!(fs.remove_disk(&extra).unwrap(), 0);
    assert_eq!(
        fs.metadata_snapshot().disks[&extra].status,
        DiskStatus::Removed
    );

    assert_eq!(fs.rebalance_limited(0, Some(123)).unwrap(), (0, Some(123)));
    let (scrub, cursor) = fs.scrub_limited(0, Some(456));
    assert_eq!(scrub.files_checked, 0);
    assert_eq!(cursor, Some(456));
    assert_eq!(fs.rebalance().unwrap(), 0);
}

#[test]
fn reshape_validates_targets_completes_empty_layouts_and_resumes_matching_state() {
    let (dir, fs) = host_volume(1);
    assert!(matches!(
        fs.reshape_layout(0, 1, None),
        Err(ArgosError::Invalid(_))
    ));
    assert!(matches!(
        fs.reshape_layout(2, 1, None),
        Err(ArgosError::NotEnoughDisks { .. })
    ));
    let complete = fs.reshape_layout(1, 0, Some(0)).unwrap();
    assert!(complete.complete);
    assert_eq!(complete.remaining_files, 0);

    fs.write_file("/file", &vec![7u8; 8192], 0o600).unwrap();
    let extra1 = fs
        .add_disk(
            Some(dir.path().join("reshape-1")),
            None,
            None,
            Some(64 * 1024 * 1024),
            false,
        )
        .unwrap();
    let extra2 = fs
        .add_disk(
            Some(dir.path().join("reshape-2")),
            None,
            None,
            Some(64 * 1024 * 1024),
            false,
        )
        .unwrap();
    assert!(fs.metadata_snapshot().disks.contains_key(&extra1));
    assert!(fs.metadata_snapshot().disks.contains_key(&extra2));
    let partial = fs.reshape_layout(2, 1, Some(0)).unwrap();
    assert!(!partial.complete);
    assert!(partial.remaining_files > 0);
    let resumed = fs.reshape_layout(2, 1, Some(1)).unwrap();
    assert_eq!(resumed.reshape_id, partial.reshape_id);
    assert!(resumed.rewritten_files >= 1);
}

#[test]
fn fsck_reports_missing_directory_children_orphans_and_repairs_usage() {
    let (dir, fs) = host_volume(1);
    fs.write_file("/file", &vec![1u8; 8192], 0o600).unwrap();
    let disk_id = fs.metadata_snapshot().disks.keys().next().unwrap().clone();
    let disk_root = {
        let meta = fs.metadata_snapshot();
        relative_or_absolute(dir.path(), &meta.disks[&disk_id].path)
    };
    let orphan = disk_root.join("shards/orphan.blk");
    ensure_private_dir(orphan.parent().unwrap()).unwrap();
    std::fs::write(&orphan, b"orphan").unwrap();
    {
        let mut meta = fs.meta.write();
        meta.inodes
            .get_mut(&ROOT_INO)
            .unwrap()
            .entries
            .insert("missing".to_string(), 9999);
        meta.disks.get_mut(&disk_id).unwrap().used_bytes = u64::MAX;
    }
    let report = fs.fsck(false, false).unwrap();
    assert!(report
        .errors
        .iter()
        .any(|error| error.contains("missing inode")));
    assert_eq!(report.orphan_shards, 1);
    assert!(orphan.exists());

    let repaired = fs.fsck(true, true).unwrap();
    assert_eq!(repaired.removed_orphans, 1);
    assert!(!orphan.exists());
    assert_ne!(fs.metadata_snapshot().disks[&disk_id].used_bytes, u64::MAX);
    let scrubbed = fs.scrub().unwrap();
    assert!(scrubbed.files_checked >= 1);
}

#[test]
fn health_report_counts_all_inode_kinds_and_delay_parser_is_best_effort() {
    let _guard = env_lock();
    let (_dir, fs) = host_volume(1);
    fs.write_file("/file", b"data", 0o600).unwrap();
    fs.mkdir("/dir", 0o755).unwrap();
    fs.symlink_path("/file", "/link").unwrap();
    fs.mknod_path("/fifo", libc::S_IFIFO | 0o600, 0).unwrap();
    let report = fs.health_report();
    assert_eq!(report.files, 1);
    assert_eq!(report.directories, 2);
    assert_eq!(report.symlinks, 1);
    assert_eq!(report.specials, 1);
    assert_eq!(report.disks.len(), 1);

    for value in ["invalid", "0"] {
        std::env::set_var("ARGOSFS_TEST_MAINTENANCE_AFTER_READ_DELAY_MS", value);
        maintenance_after_read_delay();
    }
    std::env::remove_var("ARGOSFS_TEST_MAINTENANCE_AFTER_READ_DELAY_MS");
}
