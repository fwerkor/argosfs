use super::*;
use crate::types::CapacitySource;
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::os::unix::ffi::OsStringExt;
use tempfile::tempdir;

fn disk() -> Disk {
    Disk {
        id: "disk-test".to_string(),
        path: "/tmp/argosfs-disk-test".into(),
        tier: StorageTier::Warm,
        weight: 1.0,
        status: DiskStatus::Online,
        capacity_bytes: 1_000,
        capacity_source: CapacitySource::UserOverride,
        used_bytes: 100,
        health: HealthCounters::default(),
        class: DiskClass::Unknown,
        backing_device: None,
        backing_fs_id: None,
        failure_domain: String::new(),
        sysfs_block: None,
        rotational: None,
        numa_node: None,
        read_latency_ewma_ms: 0.0,
        write_latency_ewma_ms: 0.0,
        observed_read_mib_s: 0.0,
        observed_write_mib_s: 0.0,
        io_samples: 0,
        last_probe: DiskProbe::default(),
        created_at: 0.0,
    }
}

fn inode(kind: NodeKind, size: u64) -> Inode {
    Inode {
        id: 2,
        kind,
        mode: 0o644,
        uid: 0,
        gid: 0,
        nlink: 1,
        size,
        rdev: 0,
        atime: 0.0,
        mtime: 0.0,
        ctime: 0.0,
        entries: BTreeMap::new(),
        target: None,
        inline_data: None,
        inline_sha256: String::new(),
        blocks: Vec::new(),
        xattrs: BTreeMap::new(),
        posix_acl_access: None,
        posix_acl_default: None,
        nfs4_acl: None,
        access_count: 0,
        write_count: 0,
        read_bytes: 0,
        write_bytes: 0,
        storage_class: StorageTier::Warm,
        boot_critical: false,
        workload_score: 0.0,
        last_accessed_at: 0.0,
        last_written_at: 0.0,
    }
}

#[test]
fn risk_report_combines_status_smart_and_capacity_signals() {
    let mut disk = disk();
    disk.status = DiskStatus::Failed;
    disk.used_bytes = 950;
    disk.health = HealthCounters {
        reallocated_sectors: 500,
        pending_sectors: 10,
        crc_errors: 600,
        io_errors: 50,
        latency_ms: 600.0,
        wear_percent: 95.0,
        temperature_c: 70.0,
        ..HealthCounters::default()
    };

    let report = risk_report(&disk, Path::new("/unused"));
    assert_eq!(report.risk_score, 1.0);
    assert!(report.predicted_failure);
    assert!(report.smart_stale);
    assert_eq!(report.available_bytes, 50);
    for reason in [
        "failed",
        "reallocated-sectors",
        "pending-sectors",
        "crc-errors",
        "io-errors",
        "high-latency",
        "wear",
        "temperature",
        "smart-stale-or-unavailable",
        "near-capacity",
    ] {
        assert!(report.reasons.iter().any(|item| item == reason));
    }
}

#[test]
fn risk_report_keeps_a_recent_healthy_disk_low_risk() {
    let mut disk = disk();
    disk.health.last_smart_refresh_at = now_f64();
    let report = risk_report(&disk, Path::new("/unused"));
    assert_eq!(report.risk_score, 0.0);
    assert!(!report.predicted_failure);
    assert!(!report.smart_stale);
    assert!(report.reasons.is_empty());

    disk.status = DiskStatus::Draining;
    assert_eq!(risk_report(&disk, Path::new("/unused")).risk_score, 0.35);
    disk.status = DiskStatus::Offline;
    assert_eq!(risk_report(&disk, Path::new("/unused")).risk_score, 1.0);
    disk.status = DiskStatus::Removed;
    assert_eq!(risk_report(&disk, Path::new("/unused")).risk_score, 0.0);
}

#[test]
fn inode_classifier_covers_hot_warm_and_cold_paths() {
    let mut directory = inode(NodeKind::Directory, 0);
    assert_eq!(classify_inode(&mut directory), StorageTier::Warm);

    let mut boot_file = inode(NodeKind::File, 16 * 1024 * 1024);
    boot_file.boot_critical = true;
    assert_eq!(classify_inode(&mut boot_file), StorageTier::Hot);

    let mut active_file = inode(NodeKind::File, 1024);
    active_file.access_count = 4;
    active_file.write_count = 3;
    active_file.last_accessed_at = now_f64();
    active_file.last_written_at = now_f64();
    assert_eq!(classify_inode(&mut active_file), StorageTier::Hot);

    let mut cold_file = inode(NodeKind::File, 2 * 1024 * 1024);
    assert_eq!(classify_inode(&mut cold_file), StorageTier::Cold);

    let mut warm_file = inode(NodeKind::File, 1024);
    warm_file.workload_score = 1.0;
    assert_eq!(classify_inode(&mut warm_file), StorageTier::Warm);
}

#[test]
fn path_probe_reports_capacity_and_optional_benchmark() {
    let dir = tempdir().unwrap();
    let probe = probe_disk_path(dir.path(), 4096);
    assert!(probe.capacity_bytes > 0);
    assert!(probe.available_bytes > 0);
    assert!(probe.measured_read_mib_s > 0.0);
    assert!(probe.measured_write_mib_s > 0.0);
    assert!(probe.measured_read_latency_ms > 0.0);
    assert!(probe.measured_write_latency_ms > 0.0);
    assert!(probe.recommended_weight >= 0.25);
    assert!(fs::read_dir(dir.path()).unwrap().all(|entry| {
        !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".argosfs-probe-")
    }));

    let missing = probe_disk_path(&dir.path().join("missing"), 4096);
    assert_eq!(missing.capacity_bytes, 0);
    assert_eq!(missing.recommended_weight, 1.0);
    assert_eq!(missing.recommended_tier, StorageTier::Warm);
}

#[test]
fn smart_json_parser_handles_nvme_and_failed_health() {
    let health = parse_smartctl_json(
        &disk(),
        br#"{
                "temperature":{"current":41},
                "smart_status":{"passed":false},
                "nvme_smart_health_information_log":{
                    "temperature":43,
                    "percentage_used":87,
                    "media_errors":12
                }
            }"#,
    )
    .unwrap();
    assert_eq!(health.temperature_c, 43.0);
    assert_eq!(health.wear_percent, 87.0);
    assert_eq!(health.io_errors, 100);
    assert_eq!(health.smart_device_type, "nvme");
    assert!(health
        .smart_fields_observed
        .contains(&"temperature_c".to_string()));
    assert!(health
        .smart_fields_missing
        .contains(&"crc_errors".to_string()));
    assert!(health.last_smart_refresh_at > 0.0);
}

#[test]
fn smart_json_parser_handles_ata_attributes_and_sparse_reports() {
    let mut disk = disk();
    disk.health.io_errors = 5;
    let health = parse_smartctl_json(
        &disk,
        br#"{
                "temperature":{"current":38},
                "ata_smart_attributes":{"table":[
                    {"name":"Reallocated_Sector_Ct","raw":{"value":7}},
                    {"name":"Reallocated_Event_Count","raw":{"value":9}},
                    {"name":"Current_Pending_Sector","raw":{"value":3}},
                    {"name":"UDMA_CRC_Error_Count","raw":{"value":11}},
                    {"name":"CRC_Error_Count","raw":13},
                    {"name":"Unrelated","raw":{"value":999}}
                ]}
            }"#,
    )
    .unwrap();
    assert_eq!(health.smart_device_type, "ata");
    assert_eq!(health.reallocated_sectors, 9);
    assert_eq!(health.pending_sectors, 3);
    assert_eq!(health.crc_errors, 13);
    assert_eq!(health.io_errors, 5);

    let sparse = parse_smartctl_json(&disk, br#"{}"#).unwrap();
    assert_eq!(sparse.smart_device_type, "unsupported");
    assert!(sparse.smart_fields_observed.is_empty());
    assert_eq!(sparse.smart_fields_missing.len(), 6);
    assert!(parse_smartctl_json(&disk, b"not-json").is_err());
}

#[test]
fn smart_refresh_rejects_disks_without_a_backing_device() {
    let err = refresh_smart(&disk()).unwrap_err();
    assert!(matches!(err, ArgosError::Unsupported(_)));
}

#[test]
fn block_class_and_numeric_file_helpers_cover_all_variants() {
    assert_eq!(classify_block("nvme0n1", Some(true)), DiskClass::Nvme);
    assert_eq!(classify_block("sda", Some(true)), DiskClass::Hdd);
    assert_eq!(classify_block("sda", Some(false)), DiskClass::Ssd);
    assert_eq!(classify_block("loop0", None), DiskClass::Unknown);

    let dir = tempdir().unwrap();
    let boolean = dir.path().join("bool");
    let unsigned = dir.path().join("u64");
    let signed = dir.path().join("i32");
    fs::write(&boolean, "1\n").unwrap();
    fs::write(&unsigned, "123\n").unwrap();
    fs::write(&signed, "-4\n").unwrap();
    assert_eq!(read_bool(&boolean), Some(true));
    assert_eq!(read_u64(&unsigned), Some(123));
    assert_eq!(read_i32(&signed), Some(-4));
    fs::write(&boolean, "invalid").unwrap();
    assert_eq!(read_bool(&boolean), None);
    assert_eq!(read_u64(&dir.path().join("missing")), None);
}

#[test]
fn statvfs_and_linux_device_number_helpers_are_checked() {
    let dir = tempdir().unwrap();
    let (capacity, available) = statvfs_capacity(dir.path()).unwrap();
    assert!(capacity > 0);
    assert!(available <= capacity);

    let invalid = OsString::from_vec(b"bad\0path".to_vec());
    assert!(matches!(
        statvfs_capacity(Path::new(&invalid)),
        Err(ArgosError::Invalid(_))
    ));

    let dev = libc::makedev(259, 7) as u64;
    assert_eq!(linux_major(dev), 259);
    assert_eq!(linux_minor(dev), 7);
}
