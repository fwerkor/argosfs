use crate::backend::{FileBlockBackend, StorageBackend};
use crate::error::{ArgosError, Result};
use crate::journal;
use crate::raw_format::{
    align_down, RawDeviceLabel, RawSuperblock, BACKUP_REGION_SIZE, DEVICE_LABEL_OFFSET,
    DEVICE_LABEL_SIZE, PRIMARY_SUPERBLOCK_OFFSET, PROTECTIVE_HEADER_OFFSET, SUPERBLOCK_SIZE,
};
use crate::types::{BackendKind, FaultPoint, Metadata, MetadataCandidateReport, TransactionReport};
use crate::util::{now_f64, sha256_hex};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;
use uuid::Uuid;

const PROTECTIVE_MAGIC: &[u8; 16] = b"ARGOSFS-RAW-HD\0\0";
const METADATA_MAGIC: &[u8; 16] = b"ARGOSFS-RAW-MD\0\0";
const JOURNAL_MAGIC: &[u8; 16] = b"ARGOSFS-RAW-JN\0\0";
const RAW_STORE_VERSION: u32 = 1;
const RAW_HEADER_SIZE: usize = 4096;

#[derive(Clone)]
pub struct RawOpen {
    pub backend: Arc<dyn StorageBackend>,
    pub metadata: Metadata,
    pub report: TransactionReport,
    pub superblocks: Vec<RawSuperblock>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ScannedDevice {
    pub path: PathBuf,
    pub valid: bool,
    pub error: Option<String>,
    pub pool_uuid: Option<String>,
    pub device_uuid: Option<String>,
    pub disk_id: Option<String>,
    pub disk_index: Option<u32>,
    pub generation: Option<u64>,
    pub clean: Option<bool>,
    pub label: Option<String>,
    pub capacity: u64,
    pub superblock_source: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct RawJournalRecord {
    version: u32,
    time: f64,
    volume_uuid: String,
    txid: u64,
    generation: u64,
    action: String,
    details: serde_json::Value,
    meta_hash: String,
    metadata: Metadata,
    record_hash: String,
}

pub fn scan_paths(kind: BackendKind, paths: &[PathBuf]) -> Vec<ScannedDevice> {
    if kind == BackendKind::Host {
        return paths
            .iter()
            .map(|path| ScannedDevice {
                path: path.clone(),
                valid: false,
                error: Some("host backend is not scan-able as raw block".to_string()),
                pool_uuid: None,
                device_uuid: None,
                disk_id: None,
                disk_index: None,
                generation: None,
                clean: None,
                label: None,
                capacity: 0,
                superblock_source: None,
            })
            .collect();
    }
    paths.iter().map(|path| scan_one_path(kind, path)).collect()
}

pub fn initialize_pool(
    backend: Arc<dyn StorageBackend>,
    superblocks: &[RawSuperblock],
    metadata: &mut Metadata,
    force: bool,
) -> Result<()> {
    preflight_empty(&*backend, superblocks, force)?;
    for sb in superblocks {
        let device_id = sb.disk_id.clone();
        let mut header = [0u8; 4096];
        header[..16].copy_from_slice(PROTECTIVE_MAGIC);
        backend.write_at(&device_id, PROTECTIVE_HEADER_OFFSET, &header)?;
        backend.write_at(&device_id, PRIMARY_SUPERBLOCK_OFFSET, &sb.encode())?;
        backend.write_at(&device_id, DEVICE_LABEL_OFFSET, &sb.device_label().encode())?;
        backend.write_at(&device_id, sb.backup_superblock_offset, &sb.encode())?;
        backend.write_at(
            &device_id,
            sb.backup_superblock_offset + SUPERBLOCK_SIZE as u64,
            &sb.device_label().encode(),
        )?;
        initialize_journal_region(&*backend, &device_id, sb)?;
    }
    write_metadata_copies(&*backend, superblocks, metadata)?;
    append_journal(
        &*backend,
        superblocks,
        metadata,
        "mkfs",
        serde_json::json!({}),
    )?;
    backend.flush_all()
}

pub fn preflight_devices_empty(
    backend: &dyn StorageBackend,
    superblocks: &[RawSuperblock],
    force: bool,
) -> Result<()> {
    preflight_empty(backend, superblocks, force)
}

pub fn open_pool(kind: BackendKind, paths: &[PathBuf], write: bool) -> Result<RawOpen> {
    let scanned = scan_paths(kind, paths);
    let mut devices = Vec::new();
    let mut superblocks = Vec::new();
    let mut seen_device_uuid = std::collections::BTreeSet::new();
    let mut seen_disk_id = std::collections::BTreeMap::<String, (u64, Uuid)>::new();
    let mut pool_uuid: Option<Uuid> = None;
    let mut scan_errors = Vec::new();

    for item in scanned {
        if !item.valid {
            scan_errors.push(format!(
                "{}: {}",
                item.path.display(),
                item.error
                    .clone()
                    .unwrap_or_else(|| "not an ArgosFS device".to_string())
            ));
            continue;
        }
        let (sb, _) = superblock_from_path(kind, &item.path)?;
        if let Some(pool) = pool_uuid {
            if pool != sb.pool_uuid {
                return Err(ArgosError::IncompatibleFormat(
                    "devices belong to different ArgosFS pools".to_string(),
                ));
            }
        } else {
            pool_uuid = Some(sb.pool_uuid);
        }
        if !seen_device_uuid.insert(sb.device_uuid) {
            return Err(ArgosError::IncompatibleFormat(format!(
                "duplicate ArgosFS device UUID {}",
                sb.device_uuid
            )));
        }
        if let Some((generation, device_uuid)) =
            seen_disk_id.insert(sb.disk_id.clone(), (sb.generation, sb.device_uuid))
        {
            if generation != sb.generation {
                return Err(ArgosError::IncompatibleFormat(format!(
                    "generation conflict for disk id {}: {generation} vs {}",
                    sb.disk_id, sb.generation
                )));
            }
            return Err(ArgosError::IncompatibleFormat(format!(
                "duplicate ArgosFS disk id {} with device UUIDs {device_uuid} and {}",
                sb.disk_id, sb.device_uuid
            )));
        }
        devices.push((sb.disk_id.clone(), item.path));
        superblocks.push(sb);
    }
    if superblocks.is_empty() {
        return Err(ArgosError::MissingDevice(format!(
            "no readable ArgosFS devices found{}",
            if scan_errors.is_empty() {
                String::new()
            } else {
                format!(": {}", scan_errors.join("; "))
            }
        )));
    }

    let backend = Arc::new(FileBlockBackend::open_with_ids(kind, devices, write)?);
    let (mut metadata, mut report) = load_or_recover(&*backend, &superblocks)?;
    if metadata.backend != kind {
        return Err(ArgosError::IncompatibleFormat(format!(
            "metadata backend {:?} does not match requested {:?}",
            metadata.backend, kind
        )));
    }
    let present = superblocks
        .iter()
        .map(|sb| sb.disk_id.clone())
        .collect::<std::collections::BTreeSet<_>>();
    for (disk_id, disk) in &mut metadata.disks {
        if !present.contains(disk_id) {
            disk.status = crate::types::DiskStatus::Offline;
        }
    }
    if !scan_errors.is_empty() {
        report.errors.extend(scan_errors);
    }
    if write && superblocks.iter().any(|sb| !sb.clean) {
        report
            .errors
            .push("pool was not cleanly unmounted".to_string());
    }
    if write {
        write_superblock_clean_state(&*backend, &superblocks, false)?;
    }
    Ok(RawOpen {
        backend,
        metadata,
        report,
        superblocks,
    })
}

pub fn append_transaction(
    backend: &dyn StorageBackend,
    superblocks: &[RawSuperblock],
    metadata: &Metadata,
    action: &str,
    details: serde_json::Value,
) -> Result<()> {
    append_journal(backend, superblocks, metadata, action, details)?;
    journal::inject_crash(FaultPoint::AfterJournalCommitBeforeMetadataCommit.as_str())?;
    write_metadata_copies(backend, superblocks, metadata)?;
    journal::inject_crash(FaultPoint::AfterMetadataCommitBeforeSuperblockUpdate.as_str())?;
    Ok(())
}

pub fn write_metadata_copies(
    backend: &dyn StorageBackend,
    superblocks: &[RawSuperblock],
    metadata: &Metadata,
) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(metadata)?;
    let hash = sha256_hex(&bytes);
    for sb in superblocks {
        let slot_len = sb.metadata.length / 2;
        let slot = (metadata.txid % 2) * slot_len;
        let offset = sb.metadata.offset + slot;
        if bytes.len() as u64 + RAW_HEADER_SIZE as u64 > slot_len {
            return Err(ArgosError::DiskFull {
                disk_id: sb.disk_id.clone(),
                required: bytes.len() as u64,
                available: slot_len.saturating_sub(RAW_HEADER_SIZE as u64),
            });
        }
        let header = metadata_header(
            metadata.txid,
            metadata.integrity.generation,
            bytes.len(),
            &hash,
        );
        backend.write_at(&sb.disk_id, offset, &header)?;
        backend.write_at(&sb.disk_id, offset + RAW_HEADER_SIZE as u64, &bytes)?;
        backend.flush_device(&sb.disk_id)?;
        let mirror_slot = ((metadata.txid + 1) % 2) * slot_len;
        let mirror_offset = sb.metadata.offset + mirror_slot;
        backend.write_at(&sb.disk_id, mirror_offset, &header)?;
        backend.write_at(&sb.disk_id, mirror_offset + RAW_HEADER_SIZE as u64, &bytes)?;
        backend.flush_device(&sb.disk_id)?;
    }
    Ok(())
}

pub fn audit(
    backend: &dyn StorageBackend,
    superblocks: &[RawSuperblock],
) -> Result<TransactionReport> {
    let (_, report) = load_or_recover(backend, superblocks)?;
    Ok(report)
}

pub fn write_superblock_clean_state(
    backend: &dyn StorageBackend,
    superblocks: &[RawSuperblock],
    clean: bool,
) -> Result<()> {
    for sb in superblocks {
        let mut copy = sb.clone();
        copy.clean = clean;
        copy.generation = copy.generation.saturating_add(1);
        let now = now_f64().max(0.0) as u64;
        if clean {
            copy.last_clean_unmount_time = now;
        } else {
            copy.last_mount_time = now;
        }
        let encoded = copy.encode();
        backend.write_at(&copy.disk_id, PRIMARY_SUPERBLOCK_OFFSET, &encoded)?;
        backend.write_at(&copy.disk_id, copy.backup_superblock_offset, &encoded)?;
        backend.flush_device(&copy.disk_id)?;
    }
    Ok(())
}

fn preflight_empty(
    backend: &dyn StorageBackend,
    superblocks: &[RawSuperblock],
    force: bool,
) -> Result<()> {
    if force {
        return Ok(());
    }
    for sb in superblocks {
        let mut buf = vec![0u8; SUPERBLOCK_SIZE];
        if backend
            .read_at(&sb.disk_id, PRIMARY_SUPERBLOCK_OFFSET, &mut buf)
            .is_ok()
            && RawSuperblock::decode(&buf).is_ok()
        {
            return Err(ArgosError::AlreadyExists(format!(
                "{} already contains an ArgosFS raw superblock; pass --force to overwrite",
                sb.disk_id
            )));
        }
        let mut sig = vec![0u8; 128 * 1024];
        if backend.read_at(&sb.disk_id, 0, &mut sig).is_ok() && has_known_signature(&sig) {
            return Err(ArgosError::UnsafeMount(format!(
                "{} appears to contain an existing filesystem or partition table; pass --force to overwrite",
                sb.disk_id
            )));
        }
    }
    Ok(())
}

fn has_known_signature(bytes: &[u8]) -> bool {
    bytes.starts_with(b"hsqs")
        || bytes.get(0x438..0x43a) == Some(&[0x53, 0xef])
        || bytes.get(510..512) == Some(&[0x55, 0xaa])
        || bytes.starts_with(b"XFSB")
        || bytes
            .get(0x10040..0x10048)
            .is_some_and(|sig| sig == b"_BHRfS_M")
}

fn initialize_journal_region(
    backend: &dyn StorageBackend,
    device_id: &str,
    sb: &RawSuperblock,
) -> Result<()> {
    let mut header = [0u8; RAW_HEADER_SIZE];
    header[..16].copy_from_slice(JOURNAL_MAGIC);
    put_u32(&mut header, 16, RAW_STORE_VERSION);
    put_u64(&mut header, 24, RAW_HEADER_SIZE as u64);
    backend.write_at(&device_id.to_string(), sb.journal.offset, &header)
}

fn append_journal(
    backend: &dyn StorageBackend,
    superblocks: &[RawSuperblock],
    metadata: &Metadata,
    action: &str,
    details: serde_json::Value,
) -> Result<()> {
    let mut record = RawJournalRecord {
        version: RAW_STORE_VERSION,
        time: now_f64(),
        volume_uuid: metadata.uuid.clone(),
        txid: metadata.txid,
        generation: metadata.integrity.generation,
        action: action.to_string(),
        details,
        meta_hash: journal::canonical_metadata_hash(metadata)?,
        metadata: metadata.clone(),
        record_hash: String::new(),
    };
    record.record_hash = raw_record_hash(&record)?;
    let record_bytes = serde_json::to_vec(&record)?;
    let record_hash = sha256_hex(&record_bytes);
    let mut entry = Vec::with_capacity(4 + 32 + record_bytes.len());
    entry.extend_from_slice(&(record_bytes.len() as u32).to_le_bytes());
    let record_hash_bytes = hex::decode(record_hash)
        .map_err(|err| ArgosError::Invalid(format!("raw journal hash encode failed: {err}")))?;
    entry.extend_from_slice(&record_hash_bytes);
    entry.extend_from_slice(&record_bytes);
    for sb in superblocks {
        let mut header = vec![0u8; RAW_HEADER_SIZE];
        backend.read_at(&sb.disk_id, sb.journal.offset, &mut header)?;
        if &header[..16] != JOURNAL_MAGIC {
            initialize_journal_region(backend, &sb.disk_id, sb)?;
            backend.read_at(&sb.disk_id, sb.journal.offset, &mut header)?;
        }
        let write_offset = get_u64(&header, 24)?;
        let end = write_offset
            .checked_add(entry.len() as u64)
            .ok_or_else(|| ArgosError::Invalid("journal append overflow".to_string()))?;
        if end > sb.journal.length {
            return Err(ArgosError::DiskFull {
                disk_id: sb.disk_id.clone(),
                required: entry.len() as u64,
                available: sb.journal.length.saturating_sub(write_offset),
            });
        }
        backend.write_at(&sb.disk_id, sb.journal.offset + write_offset, &entry)?;
        put_u64(&mut header, 24, end);
        backend.write_at(&sb.disk_id, sb.journal.offset, &header)?;
        backend.flush_device(&sb.disk_id)?;
    }
    Ok(())
}

fn load_or_recover(
    backend: &dyn StorageBackend,
    superblocks: &[RawSuperblock],
) -> Result<(Metadata, TransactionReport)> {
    let mut candidates = Vec::new();
    for sb in superblocks {
        candidates.extend(read_metadata_candidates(backend, sb)?);
    }
    let mut report = TransactionReport::default();
    report.metadata_candidates = candidates
        .iter()
        .map(|(_, report)| report.clone())
        .collect();
    let mut best = candidates
        .into_iter()
        .filter_map(|(metadata, _)| metadata)
        .max_by(|left, right| {
            (left.txid, left.integrity.generation).cmp(&(right.txid, right.integrity.generation))
        });
    let journal_best = read_latest_journal_metadata(backend, superblocks, &mut report)?;
    if let Some(journal_meta) = journal_best {
        if best
            .as_ref()
            .map(|metadata| journal_meta.txid > metadata.txid)
            .unwrap_or(true)
        {
            report.replayed = true;
            best = Some(journal_meta);
        }
    }
    let Some(metadata) = best else {
        return Err(ArgosError::CorruptedMetadata(
            "no valid raw metadata checkpoint or journal record found".to_string(),
        ));
    };
    report.selected_metadata_source = "raw-metadata-or-journal".to_string();
    if report.replayed {
        journal::inject_crash(FaultPoint::DuringReplay.as_str())?;
        write_metadata_copies(backend, superblocks, &metadata)?;
    }
    Ok((metadata, report))
}

fn read_metadata_candidates(
    backend: &dyn StorageBackend,
    sb: &RawSuperblock,
) -> Result<Vec<(Option<Metadata>, MetadataCandidateReport)>> {
    let slot_len = sb.metadata.length / 2;
    let mut out = Vec::new();
    for slot in 0..2u64 {
        let offset = sb.metadata.offset + slot * slot_len;
        let mut header = vec![0u8; RAW_HEADER_SIZE];
        let mut report = MetadataCandidateReport {
            path: format!("{}:metadata-slot-{slot}", sb.disk_id),
            ..MetadataCandidateReport::default()
        };
        let metadata = match backend.read_at(&sb.disk_id, offset, &mut header) {
            Ok(()) if &header[..16] == METADATA_MAGIC => {
                report.present = true;
                let len = get_u64(&header, 32)? as usize;
                let stored_hash = get_fixed_hex(&header, 64, 64)?;
                if len == 0 || len as u64 > slot_len.saturating_sub(RAW_HEADER_SIZE as u64) {
                    report.error = Some("invalid raw metadata length".to_string());
                    None
                } else {
                    let mut bytes = vec![0u8; len];
                    match backend.read_at(&sb.disk_id, offset + RAW_HEADER_SIZE as u64, &mut bytes)
                    {
                        Ok(()) if sha256_hex(&bytes) == stored_hash => {
                            match serde_json::from_slice::<Metadata>(&bytes) {
                                Ok(metadata) => {
                                    report.valid = true;
                                    report.txid = metadata.txid;
                                    report.generation = metadata.integrity.generation;
                                    report.meta_hash = metadata.integrity.meta_hash.clone();
                                    Some(metadata)
                                }
                                Err(err) => {
                                    report.error = Some(err.to_string());
                                    None
                                }
                            }
                        }
                        Ok(()) => {
                            report.error = Some("raw metadata checksum mismatch".to_string());
                            None
                        }
                        Err(err) => {
                            report.error = Some(err.to_string());
                            None
                        }
                    }
                }
            }
            Ok(()) => None,
            Err(err) => {
                report.error = Some(err.to_string());
                None
            }
        };
        out.push((metadata, report));
    }
    Ok(out)
}

fn read_latest_journal_metadata(
    backend: &dyn StorageBackend,
    superblocks: &[RawSuperblock],
    report: &mut TransactionReport,
) -> Result<Option<Metadata>> {
    let mut best = None;
    for sb in superblocks {
        let mut header = vec![0u8; RAW_HEADER_SIZE];
        if backend
            .read_at(&sb.disk_id, sb.journal.offset, &mut header)
            .is_err()
            || &header[..16] != JOURNAL_MAGIC
        {
            continue;
        }
        let mut cursor = RAW_HEADER_SIZE as u64;
        let end = get_u64(&header, 24)?.min(sb.journal.length);
        while cursor + 36 <= end {
            let mut entry_header = [0u8; 36];
            if backend
                .read_at(&sb.disk_id, sb.journal.offset + cursor, &mut entry_header)
                .is_err()
            {
                report.invalid_entries += 1;
                break;
            }
            let len = u32::from_le_bytes(entry_header[..4].try_into().unwrap()) as usize;
            if len == 0 || cursor + 36 + len as u64 > end {
                report.invalid_entries += 1;
                break;
            }
            let mut bytes = vec![0u8; len];
            backend.read_at(&sb.disk_id, sb.journal.offset + cursor + 36, &mut bytes)?;
            if hex::encode(&entry_header[4..36]) != sha256_hex(&bytes) {
                report.invalid_entries += 1;
                break;
            }
            match serde_json::from_slice::<RawJournalRecord>(&bytes) {
                Ok(record) => {
                    if raw_record_hash(&record)? != record.record_hash {
                        report.invalid_entries += 1;
                        report.errors.push(format!(
                            "raw journal record at {}:{} has an invalid record hash",
                            sb.disk_id, cursor
                        ));
                        break;
                    }
                    report.valid_entries += 1;
                    report.last_valid_txid = report.last_valid_txid.max(record.txid);
                    report.last_valid_generation =
                        report.last_valid_generation.max(record.generation);
                    if best
                        .as_ref()
                        .map(|metadata: &Metadata| record.metadata.txid > metadata.txid)
                        .unwrap_or(true)
                    {
                        best = Some(record.metadata);
                    }
                }
                Err(err) => {
                    report.invalid_entries += 1;
                    report.errors.push(format!(
                        "raw journal record at {}:{} is invalid: {err}",
                        sb.disk_id, cursor
                    ));
                    break;
                }
            }
            cursor += 36 + len as u64;
        }
    }
    Ok(best)
}

fn metadata_header(txid: u64, generation: u64, len: usize, hash: &str) -> [u8; RAW_HEADER_SIZE] {
    let mut out = [0u8; RAW_HEADER_SIZE];
    out[..16].copy_from_slice(METADATA_MAGIC);
    put_u32(&mut out, 16, RAW_STORE_VERSION);
    put_u64(&mut out, 24, txid);
    put_u64(&mut out, 32, len as u64);
    put_fixed_str(&mut out, 64, 64, hash);
    put_u64(&mut out, 136, generation);
    out
}

fn raw_record_hash(record: &RawJournalRecord) -> Result<String> {
    Ok(sha256_hex(&serde_json::to_vec(&serde_json::json!({
        "version": record.version,
        "volume_uuid": record.volume_uuid,
        "txid": record.txid,
        "generation": record.generation,
        "action": record.action,
        "meta_hash": record.meta_hash,
    }))?))
}

#[allow(clippy::too_many_arguments)]
pub fn superblock_for_device(
    pool_uuid: Uuid,
    disk_index: usize,
    disk_id: &str,
    k: usize,
    m: usize,
    chunk_size: usize,
    capacity: u64,
    label: &str,
) -> Result<RawSuperblock> {
    RawSuperblock::new(
        pool_uuid,
        Uuid::new_v4(),
        disk_id.to_string(),
        disk_index as u32,
        k as u32,
        m as u32,
        chunk_size as u64,
        capacity,
        label.to_string(),
    )
}

pub fn inspect_device(kind: BackendKind, path: PathBuf) -> Result<(RawSuperblock, RawDeviceLabel)> {
    let backend = match kind {
        BackendKind::LoopBlock => FileBlockBackend::open_loop(std::slice::from_ref(&path), false)?,
        BackendKind::RawBlock => FileBlockBackend::open_raw(std::slice::from_ref(&path), false)?,
        BackendKind::Host => {
            return Err(ArgosError::Unsupported(
                "inspect-device is for loop/raw block backends".to_string(),
            ))
        }
    };
    let id = "disk-0000".to_string();
    let capacity = backend.capacity(&id)?;
    let mut sb = vec![0u8; SUPERBLOCK_SIZE];
    let mut label = vec![0u8; DEVICE_LABEL_SIZE];
    backend.read_at(&id, PRIMARY_SUPERBLOCK_OFFSET, &mut sb)?;
    backend.read_at(&id, DEVICE_LABEL_OFFSET, &mut label)?;
    let superblock = match RawSuperblock::decode(&sb) {
        Ok(superblock) => superblock,
        Err(primary_err) => {
            let mut backup = vec![0u8; SUPERBLOCK_SIZE];
            let backup_offset = backup_superblock_offset_for_capacity(capacity);
            backend.read_at(&id, backup_offset, &mut backup)?;
            RawSuperblock::decode(&backup).map_err(|backup_err| {
                ArgosError::IncompatibleFormat(format!(
                    "primary superblock failed ({primary_err}); backup superblock failed ({backup_err})"
                ))
            })?
        }
    };
    let label = RawDeviceLabel::decode(&label)?;
    validate_label_matches_superblock(&superblock, &label)?;
    Ok((superblock, label))
}

fn scan_one_path(kind: BackendKind, path: &PathBuf) -> ScannedDevice {
    let backend = match kind {
        BackendKind::LoopBlock => FileBlockBackend::open_loop(std::slice::from_ref(path), false),
        BackendKind::RawBlock => FileBlockBackend::open_raw(std::slice::from_ref(path), false),
        BackendKind::Host => unreachable!(),
    };
    let Ok(backend) = backend else {
        return ScannedDevice {
            path: path.clone(),
            valid: false,
            error: Some("failed to open block path".to_string()),
            pool_uuid: None,
            device_uuid: None,
            disk_id: None,
            disk_index: None,
            generation: None,
            clean: None,
            label: None,
            capacity: 0,
            superblock_source: None,
        };
    };
    let id = "disk-0000".to_string();
    let capacity = backend.capacity(&id).unwrap_or(0);
    match read_superblock_with_backup(&backend, &id, capacity) {
        Ok((sb, source)) => ScannedDevice {
            path: path.clone(),
            valid: true,
            error: None,
            pool_uuid: Some(sb.pool_uuid.to_string()),
            device_uuid: Some(sb.device_uuid.to_string()),
            disk_id: Some(sb.disk_id),
            disk_index: Some(sb.disk_index),
            generation: Some(sb.generation),
            clean: Some(sb.clean),
            label: Some(sb.label),
            capacity,
            superblock_source: Some(source.to_string()),
        },
        Err(err) => ScannedDevice {
            path: path.clone(),
            valid: false,
            error: Some(err.to_string()),
            pool_uuid: None,
            device_uuid: None,
            disk_id: None,
            disk_index: None,
            generation: None,
            clean: None,
            label: None,
            capacity,
            superblock_source: None,
        },
    }
}

fn superblock_from_path(
    kind: BackendKind,
    path: &PathBuf,
) -> Result<(RawSuperblock, &'static str)> {
    let backend = match kind {
        BackendKind::LoopBlock => FileBlockBackend::open_loop(std::slice::from_ref(path), false)?,
        BackendKind::RawBlock => FileBlockBackend::open_raw(std::slice::from_ref(path), false)?,
        BackendKind::Host => {
            return Err(ArgosError::Unsupported(
                "host backend has no raw superblock".to_string(),
            ))
        }
    };
    let id = "disk-0000".to_string();
    let capacity = backend.capacity(&id)?;
    read_superblock_with_backup(&backend, &id, capacity)
}

fn read_superblock_with_backup(
    backend: &dyn StorageBackend,
    device_id: &str,
    capacity: u64,
) -> Result<(RawSuperblock, &'static str)> {
    let mut primary = vec![0u8; SUPERBLOCK_SIZE];
    let primary_result = backend
        .read_at(
            &device_id.to_string(),
            PRIMARY_SUPERBLOCK_OFFSET,
            &mut primary,
        )
        .and_then(|()| RawSuperblock::decode(&primary));
    match primary_result {
        Ok(sb) => Ok((sb, "primary")),
        Err(primary_err) => {
            let mut backup = vec![0u8; SUPERBLOCK_SIZE];
            let backup_offset = backup_superblock_offset_for_capacity(capacity);
            backend
                .read_at(&device_id.to_string(), backup_offset, &mut backup)
                .and_then(|()| RawSuperblock::decode(&backup))
                .map(|sb| (sb, "backup"))
                .map_err(|backup_err| {
                    ArgosError::IncompatibleFormat(format!(
                        "primary superblock failed ({primary_err}); backup superblock failed ({backup_err})"
                    ))
                })
        }
    }
}

fn backup_superblock_offset_for_capacity(capacity: u64) -> u64 {
    align_down(capacity.saturating_sub(BACKUP_REGION_SIZE), 4096)
}

fn validate_label_matches_superblock(
    superblock: &RawSuperblock,
    label: &RawDeviceLabel,
) -> Result<()> {
    if superblock.pool_uuid != label.pool_uuid
        || superblock.device_uuid != label.device_uuid
        || superblock.disk_id != label.disk_id
        || superblock.disk_index != label.disk_index
        || superblock.generation != label.generation
    {
        return Err(ArgosError::CorruptedMetadata(
            "device label does not match raw superblock".to_string(),
        ));
    }
    Ok(())
}

fn put_u32(out: &mut [u8], offset: usize, value: u32) {
    out[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(out: &mut [u8], offset: usize, value: u64) {
    out[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn get_u64(bytes: &[u8], offset: usize) -> Result<u64> {
    let raw = bytes
        .get(offset..offset + 8)
        .ok_or_else(|| ArgosError::CorruptedMetadata("short raw-store u64".to_string()))?;
    Ok(u64::from_le_bytes(raw.try_into().unwrap()))
}

fn put_fixed_str(out: &mut [u8], offset: usize, len: usize, value: &str) {
    let raw = value.as_bytes();
    let copy_len = raw.len().min(len);
    out[offset..offset + copy_len].copy_from_slice(&raw[..copy_len]);
}

fn get_fixed_hex(bytes: &[u8], offset: usize, len: usize) -> Result<String> {
    let raw = bytes
        .get(offset..offset + len)
        .ok_or_else(|| ArgosError::CorruptedMetadata("short raw-store string".to_string()))?;
    let end = raw.iter().position(|byte| *byte == 0).unwrap_or(raw.len());
    std::str::from_utf8(&raw[..end])
        .map(str::to_string)
        .map_err(|err| ArgosError::CorruptedMetadata(err.to_string()))
}
