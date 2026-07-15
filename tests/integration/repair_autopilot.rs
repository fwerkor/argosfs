use super::*;
use std::sync::Arc;
use std::thread;

#[test]
fn tolerates_two_disk_failures_and_repairs_after_replacement() {
    let tmp = TempDir::new().unwrap();
    let fs = ArgosFs::create(tmp.path(), config(3, 2), 5, false).unwrap();
    fs.mkdir("/var", 0o755).unwrap();
    let data = (0..20_000).map(|idx| (idx % 251) as u8).collect::<Vec<_>>();
    fs.write_file("/var/blob", &data, 0o644).unwrap();

    fs.mark_disk("disk-0000", DiskStatus::Failed).unwrap();
    fs.mark_disk("disk-0001", DiskStatus::Failed).unwrap();
    assert_eq!(fs.read_file("/var/blob", true).unwrap(), data);

    fs.add_disk(None, Some(StorageTier::Warm), Some(1.0), Some(0), false)
        .unwrap();
    fs.add_disk(None, Some(StorageTier::Warm), Some(1.0), Some(0), false)
        .unwrap();
    let report = fs.fsck(true, true).unwrap();
    assert_eq!(report.unrecoverable_files, 0);
    assert_eq!(fs.read_file("/var/blob", true).unwrap(), data);
}

#[test]
fn detects_corrupt_shard_and_scrubs() {
    let tmp = TempDir::new().unwrap();
    let fs = ArgosFs::create(tmp.path(), config(2, 2), 4, false).unwrap();
    fs.write_file("/file", b"abcdefghijklmnopqrstuvwxyz", 0o644)
        .unwrap();

    let meta = fs.metadata_snapshot();
    let inode = meta.inodes.values().find(|inode| inode.size == 26).unwrap();
    let shard = &inode.blocks[0].shards[0];
    fs::write(shard_abs(&fs, &shard.disk_id, &shard.relpath), b"corrupt").unwrap();

    let report = fs.fsck(true, true).unwrap();
    assert_eq!(report.damaged_files, 1);
    assert_eq!(report.repaired_files, 1);
    assert_eq!(
        fs.read_file("/file", true).unwrap(),
        b"abcdefghijklmnopqrstuvwxyz"
    );
}

#[test]
fn autopilot_scrub_reports_self_healed_files() {
    let tmp = TempDir::new().unwrap();
    let fs = ArgosFs::create(tmp.path(), config(2, 2), 4, false).unwrap();
    fs.write_file("/file", b"abcdefghijklmnopqrstuvwxyz", 0o644)
        .unwrap();

    let meta = fs.metadata_snapshot();
    let inode = meta.inodes.values().find(|inode| inode.size == 26).unwrap();
    let shard = &inode.blocks[0].shards[0];
    fs::write(shard_abs(&fs, &shard.disk_id, &shard.relpath), b"corrupt").unwrap();
    drop(fs);

    let fs = ArgosFs::open(tmp.path()).unwrap();
    let result = fs
        .autopilot_once_with_config(AutopilotConfig {
            probe_interval_sec: u64::MAX,
            smart_interval_sec: u64::MAX,
            scrub_interval_sec: 0,
            rebalance_interval_sec: u64::MAX,
            ..AutopilotConfig::default()
        })
        .unwrap();
    let scrub = result["actions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|action| action["action"] == "scrub-incremental")
        .unwrap();
    assert_eq!(scrub["report"]["damaged_files"], 1);
    assert_eq!(scrub["report"]["repaired_files"], 1);
    assert_eq!(
        fs.read_file("/file", true).unwrap(),
        b"abcdefghijklmnopqrstuvwxyz"
    );
}

#[test]
fn direct_io_detects_aligned_trailing_shard_garbage() {
    let tmp = TempDir::new().unwrap();
    let mut cfg = config(1, 1);
    cfg.chunk_size = 4096;
    cfg.compression = Compression::None;
    let fs = ArgosFs::create(tmp.path(), cfg, 2, false).unwrap();
    fs.set_io_policy(IoMode::Direct, true, false, true).unwrap();
    let payload = vec![7u8; 4096];
    fs.write_file("/file", &payload, 0o644).unwrap();

    let meta = fs.metadata_snapshot();
    let inode = meta
        .inodes
        .values()
        .find(|inode| inode.size == 4096)
        .unwrap();
    let shard = &inode.blocks[0].shards[0];
    let mut file = fs::OpenOptions::new()
        .append(true)
        .open(shard_abs(&fs, &shard.disk_id, &shard.relpath))
        .unwrap();
    file.write_all(&vec![9u8; 4096]).unwrap();
    file.sync_all().unwrap();

    let report = fs.fsck(true, true).unwrap();
    assert_eq!(report.damaged_files, 1);
    assert_eq!(report.repaired_files, 1);
    assert_eq!(fs.read_file("/file", true).unwrap(), payload);
}

#[test]
fn drain_remove_and_rebalance_keep_data_available() {
    let tmp = TempDir::new().unwrap();
    let fs = ArgosFs::create(tmp.path(), config(2, 2), 5, false).unwrap();
    fs.write_file("/a", b"alpha", 0o644).unwrap();
    fs.write_file("/b", b"beta", 0o644).unwrap();

    let rewritten = fs.remove_disk("disk-0000").unwrap();
    assert!(rewritten <= 2);
    assert_eq!(fs.read_file("/a", true).unwrap(), b"alpha");
    assert_eq!(fs.read_file("/b", true).unwrap(), b"beta");

    let moved = fs.rebalance().unwrap();
    assert_eq!(moved, 2);
    assert_eq!(fs.fsck(true, true).unwrap().unrecoverable_files, 0);
}

#[test]
fn autopilot_confirms_risk_before_draining_and_keeps_data_available() {
    let tmp = TempDir::new().unwrap();
    let fs = ArgosFs::create(tmp.path(), config(2, 2), 5, false).unwrap();
    fs.write_file("/a", b"alpha", 0o644).unwrap();
    fs.write_file("/b", b"beta", 0o644).unwrap();

    let mut health = fs
        .metadata_snapshot()
        .disks
        .get("disk-0001")
        .unwrap()
        .health
        .clone();
    health.pending_sectors = 12;
    fs.set_disk_health("disk-0001", health).unwrap();

    let autopilot = AutopilotConfig {
        probe_interval_sec: u64::MAX,
        smart_interval_sec: u64::MAX,
        scrub_interval_sec: u64::MAX,
        rebalance_interval_sec: u64::MAX,
        risk_confirmations: 2,
        ..AutopilotConfig::default()
    };

    let first = fs.autopilot_once_with_config(autopilot.clone()).unwrap();
    assert!(first["actions"].as_array().unwrap().iter().any(|action| {
        action["action"] == "observe-predicted-failure" && action["disk_id"] == "disk-0001"
    }));
    assert_eq!(
        fs.metadata_snapshot().disks["disk-0001"].status,
        DiskStatus::Online
    );

    let second = fs.autopilot_once_with_config(autopilot).unwrap();
    assert!(second["actions"].as_array().unwrap().iter().any(|action| {
        action["action"] == "drain-predicted-failure" && action["disk_id"] == "disk-0001"
    }));
    assert_eq!(
        fs.metadata_snapshot().disks["disk-0001"].status,
        DiskStatus::Degraded
    );
    assert_eq!(fs.read_file("/a", true).unwrap(), b"alpha");
    assert_eq!(fs.read_file("/b", true).unwrap(), b"beta");
}

#[test]
fn autopilot_rebalances_with_a_file_budget() {
    let tmp = TempDir::new().unwrap();
    let fs = ArgosFs::create(tmp.path(), config(2, 2), 5, false).unwrap();
    for index in 0..5 {
        fs.write_file(
            &format!("/file-{index}"),
            format!("payload-{index}").as_bytes(),
            0o644,
        )
        .unwrap();
    }
    fs.add_disk(None, Some(StorageTier::Warm), Some(1.0), Some(0), false)
        .unwrap();

    let result = fs
        .autopilot_once_with_config(AutopilotConfig {
            probe_interval_sec: u64::MAX,
            smart_interval_sec: u64::MAX,
            scrub_interval_sec: u64::MAX,
            rebalance_interval_sec: 0,
            rebalance_files_per_run: 2,
            rebalance_min_skew: 0.0,
            ..AutopilotConfig::default()
        })
        .unwrap();
    let rebalance = result["actions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|action| action["action"] == "rebalance-incremental")
        .unwrap();
    assert!(rebalance["rewritten_files"].as_u64().unwrap() <= 2);
}

#[test]
fn autopilot_dry_run_reports_policy_and_background_throttle() {
    let tmp = TempDir::new().unwrap();
    let fs = ArgosFs::create(tmp.path(), config(2, 2), 4, false).unwrap();

    let mut health = fs.metadata_snapshot().disks["disk-0000"].health.clone();
    health.latency_ms = 120.0;
    fs.set_disk_health("disk-0000", health).unwrap();

    let mut policy = AutopilotPolicy::default();
    policy.background_io.max_read_mib_s = Some(1.0);
    policy.background_io.max_write_mib_s = Some(1.0);
    policy.background_io.target_foreground_p99_ms = 50.0;

    let result = fs
        .autopilot_dry_run_with_config_and_policy(
            AutopilotConfig {
                probe_interval_sec: u64::MAX,
                smart_interval_sec: u64::MAX,
                scrub_interval_sec: u64::MAX,
                rebalance_interval_sec: 0,
                rebalance_min_skew: 0.0,
                rebalance_files_per_run: 8,
                ..AutopilotConfig::default()
            },
            policy,
        )
        .unwrap();

    assert_eq!(result["policy"]["background_io"]["max_read_mib_s"], 1.0);
    let decisions = result["planner"]["background_io"]["throttle_decisions"]
        .as_array()
        .unwrap();
    assert!(decisions.iter().any(|decision| {
        decision["action"] == "rebalance"
            && decision["requested_budget"].as_u64().unwrap() >= 8
            && decision["effective_budget"].as_u64().unwrap() <= 1
            && decision["max_foreground_latency_ms"].as_f64().unwrap() >= 120.0
    }));
}

#[test]
fn autopilot_policy_pauses_scrub_under_foreground_latency_pressure() {
    let tmp = TempDir::new().unwrap();
    let fs = ArgosFs::create(tmp.path(), config(2, 2), 4, false).unwrap();
    fs.write_file("/file", b"abcdefghijklmnopqrstuvwxyz", 0o644)
        .unwrap();

    let meta = fs.metadata_snapshot();
    let inode = meta.inodes.values().find(|inode| inode.size == 26).unwrap();
    let shard = &inode.blocks[0].shards[0];
    fs::write(shard_abs(&fs, &shard.disk_id, &shard.relpath), b"corrupt").unwrap();

    let mut health = fs.metadata_snapshot().disks["disk-0000"].health.clone();
    health.latency_ms = 100.0;
    fs.set_disk_health("disk-0000", health).unwrap();

    let mut policy = AutopilotPolicy::default();
    policy.background_io.target_foreground_p99_ms = 10.0;
    policy.background_io.pause_if_foreground_p99_ms = Some(25.0);

    let result = fs
        .autopilot_once_with_config_and_policy(
            AutopilotConfig {
                probe_interval_sec: u64::MAX,
                smart_interval_sec: u64::MAX,
                scrub_interval_sec: 0,
                rebalance_interval_sec: u64::MAX,
                ..AutopilotConfig::default()
            },
            policy,
        )
        .unwrap();

    let actions = result["actions"].as_array().unwrap();
    assert!(actions
        .iter()
        .any(|action| action["action"] == "scrub-paused"));
    assert!(!actions
        .iter()
        .any(|action| action["action"] == "scrub-incremental"));
    assert_eq!(fs.fsck(false, false).unwrap().damaged_files, 1);
}

#[test]
fn stale_metadata_commits_are_rejected_instead_of_overwriting_newer_state() {
    let tmp = TempDir::new().unwrap();
    let fs1 = ArgosFs::create(tmp.path(), config(2, 2), 4, false).unwrap();
    let fs2 = ArgosFs::open(tmp.path()).unwrap();

    fs1.write_file("/fresh", b"fresh", 0o644).unwrap();
    let err = fs2.write_file("/stale", b"stale", 0o644).unwrap_err();
    assert!(matches!(err, ArgosError::Conflict(_)));

    assert_eq!(fs2.read_file("/fresh", true).unwrap(), b"fresh");
    fs2.write_file("/after-conflict", b"ok", 0o644).unwrap();

    let reopened = ArgosFs::open(tmp.path()).unwrap();
    assert_eq!(reopened.read_file("/fresh", true).unwrap(), b"fresh");
    assert_eq!(reopened.read_file("/after-conflict", true).unwrap(), b"ok");
    assert!(matches!(
        reopened.read_file("/stale", true).unwrap_err(),
        ArgosError::NotFound(_)
    ));
}

#[test]
fn rebalance_does_not_overwrite_a_concurrent_committed_write() {
    let _guard = env_lock();
    let tmp = TempDir::new().unwrap();
    let mut cfg = config(1, 0);
    cfg.chunk_size = 1024 * 1024;
    cfg.compression = Compression::None;
    let fs = Arc::new(ArgosFs::create(tmp.path(), cfg, 1, false).unwrap());
    fs.write_file("/large", &vec![b'A'; 8 * 1024 * 1024], 0o666)
        .unwrap();
    let ino = fs.resolve_path("/large", false).unwrap();
    fs.add_disk(
        Some(tmp.path().join("second")),
        Some(StorageTier::Warm),
        Some(1.0),
        Some(64 * 1024 * 1024),
        false,
    )
    .unwrap();

    std::env::set_var("ARGOSFS_TEST_MAINTENANCE_AFTER_READ_DELAY_MS", "250");
    let rebalance_fs = Arc::clone(&fs);
    let rebalance = thread::spawn(move || rebalance_fs.rebalance());
    thread::sleep(std::time::Duration::from_millis(50));
    let writer_fs = Arc::clone(&fs);
    let writer = thread::spawn(move || writer_fs.write_inode_range(ino, 0, b"Z"));

    assert_eq!(rebalance.join().unwrap().unwrap(), 1);
    assert_eq!(writer.join().unwrap().unwrap(), 1);
    std::env::remove_var("ARGOSFS_TEST_MAINTENANCE_AFTER_READ_DELAY_MS");
    assert_eq!(fs.read_inode(ino, 0, 1, false).unwrap(), b"Z");
}

#[test]
fn fsck_orphan_scan_does_not_delete_a_concurrent_write() {
    let _guard = env_lock();
    let tmp = TempDir::new().unwrap();
    let mut cfg = config(1, 0);
    cfg.chunk_size = 1024 * 1024;
    cfg.compression = Compression::None;
    let fs = Arc::new(ArgosFs::create(tmp.path(), cfg, 1, false).unwrap());
    let ino = fs.create_file_path("/concurrent", 0o644).unwrap();
    let payload = vec![b'W'; 2 * 1024 * 1024];

    std::env::set_var("ARGOSFS_TEST_MAINTENANCE_AFTER_READ_DELAY_MS", "250");
    let fsck_fs = Arc::clone(&fs);
    let fsck = thread::spawn(move || fsck_fs.fsck(false, true));
    thread::sleep(std::time::Duration::from_millis(50));
    let writer_fs = Arc::clone(&fs);
    let expected = payload.clone();
    let writer = thread::spawn(move || writer_fs.write_inode_range(ino, 0, &expected));

    let report = fsck.join().unwrap().unwrap();
    assert_eq!(writer.join().unwrap().unwrap(), payload.len());
    std::env::remove_var("ARGOSFS_TEST_MAINTENANCE_AFTER_READ_DELAY_MS");

    assert_eq!(report.removed_orphans, 0);
    assert_eq!(fs.read_file("/concurrent", false).unwrap(), payload);
    assert!(fs
        .metadata_snapshot()
        .disks
        .values()
        .all(|disk| disk.used_bytes > 0));
}
