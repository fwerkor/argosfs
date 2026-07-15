use crate::error::{ArgosError, Result};
use crate::types::{
    Disk, DiskClass, DiskProbe, DiskStatus, HealthCounters, HealthDiskReport, Inode, NodeKind,
    StorageTier,
};
use crate::util::{ensure_dir, now_f64};
use serde_json::Value;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::Path;
use std::process::Command;
use std::time::Instant;

pub fn risk_report(disk: &Disk, _disk_path: &Path) -> HealthDiskReport {
    let used_bytes = disk.used_bytes;
    let available_bytes = disk.capacity_bytes.saturating_sub(used_bytes);
    let mut score = 0.0;
    let mut reasons = Vec::new();
    match disk.status {
        DiskStatus::Failed | DiskStatus::Offline => {
            score += 1.0;
            reasons.push(format!("{:?}", disk.status).to_ascii_lowercase());
        }
        DiskStatus::Degraded | DiskStatus::Draining => {
            score += 0.35;
            reasons.push(format!("{:?}", disk.status).to_ascii_lowercase());
        }
        DiskStatus::Online | DiskStatus::Removed => {}
    }
    if disk.health.reallocated_sectors > 0 {
        score += (disk.health.reallocated_sectors as f64 / 400.0).min(0.25);
        reasons.push("reallocated-sectors".to_string());
    }
    if disk.health.pending_sectors > 0 {
        score += (disk.health.pending_sectors as f64 / 100.0).min(0.25);
        reasons.push("pending-sectors".to_string());
    }
    if disk.health.crc_errors > 0 {
        score += (disk.health.crc_errors as f64 / 500.0).min(0.12);
        reasons.push("crc-errors".to_string());
    }
    if disk.health.io_errors > 0 {
        score += (disk.health.io_errors as f64 / 100.0).min(0.25);
        reasons.push("io-errors".to_string());
    }
    if disk.health.latency_ms > 50.0 {
        score += ((disk.health.latency_ms - 50.0) / 500.0).min(0.20);
        reasons.push("high-latency".to_string());
    }
    if disk.health.wear_percent > 80.0 {
        score += ((disk.health.wear_percent - 80.0) / 100.0).min(0.20);
        reasons.push("wear".to_string());
    }
    if disk.health.temperature_c > 55.0 {
        score += ((disk.health.temperature_c - 55.0) / 80.0).min(0.10);
        reasons.push("temperature".to_string());
    }
    let smart_stale = disk.health.last_smart_refresh_at <= 0.0
        || now_f64() - disk.health.last_smart_refresh_at > 24.0 * 60.0 * 60.0;
    if smart_stale {
        reasons.push("smart-stale-or-unavailable".to_string());
    }
    if disk.capacity_bytes > 0 && used_bytes as f64 / disk.capacity_bytes as f64 > 0.92 {
        score += 0.10;
        reasons.push("near-capacity".to_string());
    }
    let score = score.min(1.0);
    let predicted_failure = score >= 0.65
        || disk.health.pending_sectors >= 8
        || disk.health.io_errors >= 40
        || disk.status == DiskStatus::Failed;
    HealthDiskReport {
        id: disk.id.clone(),
        status: disk.status,
        tier: disk.tier,
        weight: disk.weight,
        used_bytes,
        capacity_bytes: disk.capacity_bytes,
        used_bytes_source: "metadata-counter".to_string(),
        capacity_source: disk.capacity_source,
        available_bytes,
        class: disk.class,
        backing_device: disk.backing_device.clone(),
        rotational: disk.rotational,
        numa_node: disk.numa_node,
        read_latency_ewma_ms: disk.read_latency_ewma_ms,
        write_latency_ewma_ms: disk.write_latency_ewma_ms,
        observed_read_mib_s: disk.observed_read_mib_s,
        observed_write_mib_s: disk.observed_write_mib_s,
        risk_score: score,
        predicted_failure,
        smart_stale,
        reasons,
        health: disk.health.clone(),
    }
}

pub fn classify_inode(inode: &mut Inode) -> StorageTier {
    if inode.kind != NodeKind::File {
        return StorageTier::Warm;
    }
    let now = now_f64();
    let read_age_hours =
        ((now - inode.last_accessed_at.max(inode.atime)).max(0.0) / 3600.0).min(720.0);
    let write_age_hours =
        ((now - inode.last_written_at.max(inode.mtime)).max(0.0) / 3600.0).min(720.0);
    let read_decay = 0.5_f64.powf(read_age_hours / 24.0);
    let write_decay = 0.5_f64.powf(write_age_hours / 24.0);
    let score = inode.workload_score * 0.70
        + inode.access_count as f64 * read_decay
        + inode.write_count as f64 * 2.0 * write_decay;
    inode.workload_score = score;
    let class =
        if inode.boot_critical || score >= 8.0 || (score >= 3.0 && inode.size <= 8 * 1024 * 1024) {
            StorageTier::Hot
        } else if score < 0.5 && inode.size >= 1024 * 1024 {
            StorageTier::Cold
        } else {
            StorageTier::Warm
        };
    inode.storage_class = class;
    class
}

pub fn probe_disk_path(path: &Path, benchmark_bytes: usize) -> DiskProbe {
    let mut probe = DiskProbe {
        recommended_weight: 1.0,
        recommended_tier: StorageTier::Warm,
        ..DiskProbe::default()
    };
    let metadata = fs::metadata(path).ok();
    let is_block_device = metadata
        .as_ref()
        .is_some_and(|metadata| metadata.file_type().is_block_device());
    if let Some(metadata) = metadata.as_ref() {
        let dev = if is_block_device {
            metadata.rdev()
        } else {
            metadata.dev()
        };
        if !is_block_device {
            probe.backing_fs_id = Some(format!("dev:{dev}"));
        }
        if let Some((block, backing)) = sysfs_block_from_dev(dev) {
            probe.sysfs_block = Some(block.clone());
            probe.backing_device = Some(backing);
            probe.rotational = read_bool(
                &Path::new("/sys/block")
                    .join(&block)
                    .join("queue/rotational"),
            );
            probe.numa_node = read_i32(
                &Path::new("/sys/block")
                    .join(&block)
                    .join("device/numa_node"),
            )
            .filter(|node| *node >= 0);
            probe.capacity_bytes = read_u64(&Path::new("/sys/block").join(&block).join("size"))
                .map(|sectors| sectors.saturating_mul(512))
                .unwrap_or(0);
            probe.class = classify_block(&block, probe.rotational);
        }
    }
    if !is_block_device {
        if let Ok((capacity, available)) = statvfs_capacity(path) {
            probe.capacity_bytes = capacity;
            probe.available_bytes = available;
        }
    }
    if benchmark_bytes > 0 && metadata.as_ref().is_some_and(|metadata| metadata.is_dir()) {
        if let Ok(result) = benchmark_path(path, benchmark_bytes) {
            probe.measured_write_mib_s = result.write_mib_s;
            probe.measured_read_mib_s = result.read_mib_s;
            probe.measured_write_latency_ms = result.write_latency_ms;
            probe.measured_read_latency_ms = result.read_latency_ms;
        }
    }
    let class_weight = match probe.class {
        DiskClass::Nvme => 4.0,
        DiskClass::Ssd => 2.5,
        DiskClass::Hdd => 1.0,
        DiskClass::Unknown => 1.0,
    };
    let measured = if probe.measured_read_mib_s > 0.0 || probe.measured_write_mib_s > 0.0 {
        ((probe.measured_read_mib_s + probe.measured_write_mib_s) / 2.0 / 180.0).clamp(0.5, 6.0)
    } else {
        class_weight
    };
    probe.recommended_weight = ((class_weight + measured) / 2.0).clamp(0.25, 8.0);
    probe.recommended_tier = match probe.class {
        DiskClass::Nvme | DiskClass::Ssd => StorageTier::Hot,
        DiskClass::Hdd => StorageTier::Cold,
        DiskClass::Unknown => {
            if probe.recommended_weight >= 2.0 {
                StorageTier::Hot
            } else {
                StorageTier::Warm
            }
        }
    };
    probe
}

pub fn refresh_smart(disk: &Disk) -> Result<HealthCounters> {
    let Some(device) = disk.backing_device.as_ref() else {
        return Err(ArgosError::Unsupported(format!(
            "disk {} has no probed backing device",
            disk.id
        )));
    };
    let output = Command::new("smartctl")
        .arg("-j")
        .arg("-a")
        .arg(device)
        .output()
        .map_err(|err| {
            if err.kind() == std::io::ErrorKind::NotFound {
                ArgosError::Unsupported("smartctl is not installed".to_string())
            } else {
                ArgosError::Io(err)
            }
        })?;
    if output.stdout.is_empty() {
        return Err(ArgosError::Unsupported(format!(
            "smartctl produced no JSON for {}",
            device.display()
        )));
    }
    parse_smartctl_json(disk, &output.stdout)
}

fn parse_smartctl_json(disk: &Disk, output: &[u8]) -> Result<HealthCounters> {
    let value: Value = serde_json::from_slice(output)?;
    let mut health = disk.health.clone();
    let mut observed = std::collections::BTreeSet::new();
    let device_type = if value
        .pointer("/nvme_smart_health_information_log")
        .is_some()
    {
        "nvme"
    } else if value.pointer("/ata_smart_attributes/table").is_some() {
        "ata"
    } else {
        "unsupported"
    };
    if let Some(temp) = value
        .pointer("/temperature/current")
        .and_then(Value::as_f64)
    {
        health.temperature_c = temp;
        observed.insert("temperature_c");
    }
    if let Some(temp) = value
        .pointer("/nvme_smart_health_information_log/temperature")
        .and_then(Value::as_f64)
    {
        health.temperature_c = temp;
        observed.insert("temperature_c");
    }
    if let Some(used) = value
        .pointer("/nvme_smart_health_information_log/percentage_used")
        .and_then(Value::as_f64)
    {
        health.wear_percent = used;
        observed.insert("wear_percent");
    }
    if let Some(errors) = value
        .pointer("/nvme_smart_health_information_log/media_errors")
        .and_then(Value::as_u64)
    {
        health.io_errors = health.io_errors.max(errors);
        observed.insert("io_errors");
    }
    if value
        .pointer("/smart_status/passed")
        .and_then(Value::as_bool)
        .is_some_and(|passed| !passed)
    {
        health.io_errors = health.io_errors.max(100);
        observed.insert("io_errors");
    }
    if let Some(table) = value
        .pointer("/ata_smart_attributes/table")
        .and_then(Value::as_array)
    {
        for row in table {
            let name = row.get("name").and_then(Value::as_str).unwrap_or_default();
            let raw = row
                .pointer("/raw/value")
                .and_then(Value::as_u64)
                .or_else(|| row.get("raw").and_then(Value::as_u64))
                .unwrap_or(0);
            match name {
                "Reallocated_Sector_Ct" | "Reallocated_Event_Count" => {
                    health.reallocated_sectors = health.reallocated_sectors.max(raw);
                    observed.insert("reallocated_sectors");
                }
                "Current_Pending_Sector" => {
                    health.pending_sectors = health.pending_sectors.max(raw);
                    observed.insert("pending_sectors");
                }
                "UDMA_CRC_Error_Count" | "CRC_Error_Count" => {
                    health.crc_errors = health.crc_errors.max(raw);
                    observed.insert("crc_errors");
                }
                _ => {}
            }
        }
    }
    let expected = [
        "temperature_c",
        "wear_percent",
        "io_errors",
        "reallocated_sectors",
        "pending_sectors",
        "crc_errors",
    ];
    health.last_smart_refresh_at = now_f64();
    health.smart_device_type = device_type.to_string();
    health.smart_fields_observed = observed.iter().map(|field| (*field).to_string()).collect();
    health.smart_fields_missing = expected
        .into_iter()
        .filter(|field| !observed.contains(field))
        .map(ToString::to_string)
        .collect();
    Ok(health)
}

#[derive(Clone, Copy)]
struct BenchResult {
    read_mib_s: f64,
    write_mib_s: f64,
    read_latency_ms: f64,
    write_latency_ms: f64,
}

fn benchmark_path(path: &Path, bytes: usize) -> Result<BenchResult> {
    ensure_dir(path)?;
    let probe_path = path.join(format!(
        ".argosfs-probe-{}-{}",
        std::process::id(),
        now_f64().to_bits()
    ));
    let payload = (0..bytes).map(|idx| (idx % 251) as u8).collect::<Vec<_>>();
    let start = Instant::now();
    {
        let mut file = File::create(&probe_path)?;
        file.write_all(&payload)?;
        file.sync_all()?;
    }
    let write_sec = start.elapsed().as_secs_f64().max(0.000_001);
    let start = Instant::now();
    let mut read_back = Vec::with_capacity(bytes);
    File::open(&probe_path)?.read_to_end(&mut read_back)?;
    let read_sec = start.elapsed().as_secs_f64().max(0.000_001);
    let _ = fs::remove_file(&probe_path);
    let mib = bytes as f64 / (1024.0 * 1024.0);
    Ok(BenchResult {
        read_mib_s: mib / read_sec,
        write_mib_s: mib / write_sec,
        read_latency_ms: read_sec * 1000.0,
        write_latency_ms: write_sec * 1000.0,
    })
}

fn sysfs_block_from_dev(dev: u64) -> Option<(String, std::path::PathBuf)> {
    let major = linux_major(dev);
    let minor = linux_minor(dev);
    let sys_dev = Path::new("/sys/dev/block").join(format!("{major}:{minor}"));
    let target = fs::read_link(&sys_dev).ok()?;
    let mut after_block = false;
    for component in target.components() {
        let text = component.as_os_str().to_string_lossy();
        if after_block {
            let block = text.to_string();
            return Some((block.clone(), Path::new("/dev").join(block)));
        }
        if text == "block" {
            after_block = true;
        }
    }
    None
}

fn classify_block(block: &str, rotational: Option<bool>) -> DiskClass {
    if block.starts_with("nvme") {
        DiskClass::Nvme
    } else if rotational == Some(true) {
        DiskClass::Hdd
    } else if rotational == Some(false) {
        DiskClass::Ssd
    } else {
        DiskClass::Unknown
    }
}

fn read_bool(path: &Path) -> Option<bool> {
    fs::read_to_string(path)
        .ok()
        .and_then(|value| value.trim().parse::<u8>().ok())
        .map(|value| value != 0)
}

fn read_u64(path: &Path) -> Option<u64> {
    fs::read_to_string(path)
        .ok()
        .and_then(|value| value.trim().parse::<u64>().ok())
}

fn read_i32(path: &Path) -> Option<i32> {
    fs::read_to_string(path)
        .ok()
        .and_then(|value| value.trim().parse::<i32>().ok())
}

fn statvfs_capacity(path: &Path) -> Result<(u64, u64)> {
    let c_path = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())
        .map_err(|err| ArgosError::Invalid(format!("invalid path for statvfs: {err}")))?;
    let mut stat = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    let rc = unsafe { libc::statvfs(c_path.as_ptr(), stat.as_mut_ptr()) };
    if rc != 0 {
        return Err(ArgosError::Io(std::io::Error::last_os_error()));
    }
    let stat = unsafe { stat.assume_init() };
    Ok((
        stat.f_blocks.saturating_mul(stat.f_frsize),
        stat.f_bavail.saturating_mul(stat.f_frsize),
    ))
}

fn linux_major(dev: u64) -> u64 {
    ((dev >> 8) & 0x0fff) | ((dev >> 32) & !0x0fff)
}

fn linux_minor(dev: u64) -> u64 {
    (dev & 0x00ff) | ((dev >> 12) & !0x00ff)
}

#[cfg(test)]
mod tests {
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
}
