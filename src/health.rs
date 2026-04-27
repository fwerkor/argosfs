use crate::error::{ArgosError, Result};
use crate::types::{
    Disk, DiskClass, DiskProbe, DiskStatus, HealthCounters, HealthDiskReport, Inode, NodeKind,
    StorageTier,
};
use crate::util::{directory_size, ensure_dir, now_f64};
use serde_json::Value;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::process::Command;
use std::time::Instant;

pub fn risk_report(disk: &Disk, disk_path: &Path) -> HealthDiskReport {
    let used_bytes = directory_size(&disk_path.join("shards"));
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
        reasons,
        health: disk.health.clone(),
    }
}

pub fn classify_inode(inode: &mut Inode) -> StorageTier {
    if inode.kind != NodeKind::File {
        return StorageTier::Warm;
    }
    let hotness = inode
        .access_count
        .saturating_add(inode.write_count.saturating_mul(2));
    let class = if hotness >= 8 || (hotness >= 3 && inode.size <= 8 * 1024 * 1024) {
        StorageTier::Hot
    } else if hotness == 0 && inode.size >= 1024 * 1024 {
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
    if let Ok(metadata) = fs::metadata(path) {
        let dev = metadata.dev();
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
    if probe.capacity_bytes == 0 {
        if let Ok((capacity, available)) = statvfs_capacity(path) {
            probe.capacity_bytes = capacity;
            probe.available_bytes = available;
        }
    } else if let Ok((_, available)) = statvfs_capacity(path) {
        probe.available_bytes = available;
    }
    if benchmark_bytes > 0 {
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
    let value: Value = serde_json::from_slice(&output.stdout)?;
    let mut health = disk.health.clone();
    if let Some(temp) = value
        .pointer("/temperature/current")
        .and_then(Value::as_f64)
    {
        health.temperature_c = temp;
    }
    if let Some(temp) = value
        .pointer("/nvme_smart_health_information_log/temperature")
        .and_then(Value::as_f64)
    {
        health.temperature_c = temp;
    }
    if let Some(used) = value
        .pointer("/nvme_smart_health_information_log/percentage_used")
        .and_then(Value::as_f64)
    {
        health.wear_percent = used;
    }
    if let Some(errors) = value
        .pointer("/nvme_smart_health_information_log/media_errors")
        .and_then(Value::as_u64)
    {
        health.io_errors = health.io_errors.max(errors);
    }
    if value
        .pointer("/smart_status/passed")
        .and_then(Value::as_bool)
        .is_some_and(|passed| !passed)
    {
        health.io_errors = health.io_errors.max(100);
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
                    health.reallocated_sectors = health.reallocated_sectors.max(raw)
                }
                "Current_Pending_Sector" => {
                    health.pending_sectors = health.pending_sectors.max(raw)
                }
                "UDMA_CRC_Error_Count" | "CRC_Error_Count" => {
                    health.crc_errors = health.crc_errors.max(raw)
                }
                _ => {}
            }
        }
    }
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
