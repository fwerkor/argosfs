use crate::backend::{FileBlockBackend, StorageBackend};
use crate::error::{ArgosError, Result};
use crate::journal;
use crate::raw_format::{
    align_down, align_up, RawDeviceLabel, RawSuperblock, BACKUP_REGION_SIZE, DEVICE_LABEL_OFFSET,
    DEVICE_LABEL_SIZE, PRIMARY_SUPERBLOCK_OFFSET, PROTECTIVE_HEADER_OFFSET, SUPERBLOCK_SIZE,
};
use crate::types::{
    BackendKind, FaultPoint, Metadata, MetadataCandidateReport, RawJournalMemberReport,
    TransactionReport,
};
use crate::util::{now_f64, sha256_hex};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;
use uuid::Uuid;

const PROTECTIVE_MAGIC: &[u8; 16] = b"ARGOSFS-RAW-HD\0\0";
const METADATA_MAGIC: &[u8; 16] = b"ARGOSFS-RAW-MD\0\0";
const JOURNAL_MAGIC: &[u8; 16] = b"ARGOSFS-RAW-JN\0\0";
const RAW_STORE_VERSION: u32 = 1;
const RAW_HEADER_SIZE: usize = 4096;
const METADATA_FORMAT_LEGACY: u32 = 0;
const METADATA_FORMAT_TREE: u32 = 1;
const METADATA_PAGE_SIZE: usize = 4096;
const METADATA_INDEX_ENTRY_SIZE: usize = 48;
const HASH_HEX_LEN: usize = 64;
const HASH_BYTES_LEN: usize = 32;

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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    metadata: Option<Metadata>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    metadata_delta: Option<Vec<journal::MetadataDeltaOp>>,
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
        None,
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

    let present_paths = devices
        .iter()
        .cloned()
        .collect::<std::collections::BTreeMap<_, _>>();
    let backend = Arc::new(FileBlockBackend::open_with_ids(kind, devices, write)?);
    let (mut metadata, mut report) = load_or_recover(&*backend, &superblocks, write)?;
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
        if let Some(path) = present_paths.get(disk_id) {
            disk.path = path.clone();
        } else if !present.contains(disk_id) {
            disk.status = crate::types::DiskStatus::Offline;
        }
    }
    if !scan_errors.is_empty() {
        report.errors.extend(scan_errors);
    }
    if superblocks.iter().any(|sb| !sb.clean) {
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
    append_transaction_with_previous(backend, superblocks, metadata, None, action, details)
}

pub fn append_transaction_with_previous(
    backend: &dyn StorageBackend,
    superblocks: &[RawSuperblock],
    metadata: &Metadata,
    previous_metadata: Option<&Metadata>,
    action: &str,
    details: serde_json::Value,
) -> Result<()> {
    append_journal(
        backend,
        superblocks,
        metadata,
        previous_metadata,
        action,
        details,
    )?;
    journal::inject_crash(FaultPoint::AfterJournalCommitBeforeMetadataCommit.as_str())?;
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
        write_metadata_slot(backend, sb, offset, slot_len, metadata, &bytes, &hash)?;
        let mirror_slot = ((metadata.txid + 1) % 2) * slot_len;
        let mirror_offset = sb.metadata.offset + mirror_slot;
        write_metadata_slot(
            backend,
            sb,
            mirror_offset,
            slot_len,
            metadata,
            &bytes,
            &hash,
        )?;
    }
    Ok(())
}

fn write_metadata_slot(
    backend: &dyn StorageBackend,
    sb: &RawSuperblock,
    offset: u64,
    slot_len: u64,
    metadata: &Metadata,
    bytes: &[u8],
    hash: &str,
) -> Result<()> {
    let checkpoint = metadata_tree_checkpoint(
        &sb.disk_id,
        metadata.txid,
        metadata.integrity.generation,
        bytes,
        hash,
        slot_len,
    )?;
    for (relative_offset, data) in checkpoint.body_writes {
        backend.write_at(&sb.disk_id, offset + relative_offset, &data)?;
    }
    backend.flush_device(&sb.disk_id)?;
    backend.write_at(&sb.disk_id, offset, &checkpoint.header)?;
    backend.flush_device(&sb.disk_id)?;
    Ok(())
}

pub fn recover_metadata(
    backend: &dyn StorageBackend,
    superblocks: &[RawSuperblock],
) -> Result<Metadata> {
    load_or_recover(backend, superblocks, false).map(|(metadata, _)| metadata)
}

pub fn audit(
    backend: &dyn StorageBackend,
    superblocks: &[RawSuperblock],
) -> Result<TransactionReport> {
    let (_, mut report) = load_or_recover(backend, superblocks, false)?;
    if superblocks.iter().any(|sb| !sb.clean) {
        report
            .errors
            .push("pool was not cleanly unmounted".to_string());
    }
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
        let label = copy.device_label().encode();
        backend.write_at(&copy.disk_id, PRIMARY_SUPERBLOCK_OFFSET, &encoded)?;
        backend.write_at(&copy.disk_id, DEVICE_LABEL_OFFSET, &label)?;
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
    previous_metadata: Option<&Metadata>,
    action: &str,
    details: serde_json::Value,
) -> Result<()> {
    let write_checkpoint = previous_metadata.is_none()
        || metadata
            .txid
            .is_multiple_of(journal::checkpoint_interval_txids());
    let metadata_delta = if write_checkpoint {
        None
    } else {
        Some(journal::metadata_delta(
            previous_metadata.expect("checked above"),
            metadata,
        )?)
    };
    let mut record = RawJournalRecord {
        version: RAW_STORE_VERSION,
        time: now_f64(),
        volume_uuid: metadata.uuid.clone(),
        txid: metadata.txid,
        generation: metadata.integrity.generation,
        action: action.to_string(),
        details,
        meta_hash: journal::canonical_metadata_hash(metadata)?,
        metadata: if metadata_delta.is_some() {
            None
        } else {
            Some(metadata.clone())
        },
        metadata_delta,
        record_hash: String::new(),
    };
    record.record_hash = raw_record_hash(&record)?;
    let record_bytes = serde_json::to_vec(&record)?;
    let record_len = u32::try_from(record_bytes.len())
        .map_err(|_| ArgosError::Invalid("raw journal record is too large".to_string()))?;
    let record_hash = sha256_hex(&record_bytes);
    let mut entry = Vec::with_capacity(4 + 32 + record_bytes.len());
    entry.extend_from_slice(&record_len.to_le_bytes());
    let record_hash_bytes = hex::decode(record_hash)
        .map_err(|err| ArgosError::Invalid(format!("raw journal hash encode failed: {err}")))?;
    entry.extend_from_slice(&record_hash_bytes);
    entry.extend_from_slice(&record_bytes);

    let mut rollback_headers: Vec<(String, u64, Vec<u8>)> = Vec::new();
    let result = (|| -> Result<()> {
        for (index, sb) in superblocks.iter().enumerate() {
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
                checkpoint_and_reset_journal(backend, sb, metadata)?;
                continue;
            }
            rollback_headers.push((sb.disk_id.clone(), sb.journal.offset, header.clone()));
            backend.write_at(&sb.disk_id, sb.journal.offset + write_offset, &entry)?;
            put_u64(&mut header, 24, end);
            backend.write_at(&sb.disk_id, sb.journal.offset, &header)?;
            if !metadata.config.defer_journal_flush {
                backend.flush_device(&sb.disk_id)?;
            }
            if index + 1 < superblocks.len() {
                journal::inject_crash(FaultPoint::AfterPartialJournalFanout.as_str())?;
            }
        }
        Ok(())
    })();

    if result.is_err() {
        for (disk_id, journal_offset, header) in rollback_headers.into_iter().rev() {
            let _ = backend.write_at(&disk_id, journal_offset, &header);
            if !metadata.config.defer_journal_flush {
                let _ = backend.flush_device(&disk_id);
            }
        }
    }
    result
}

fn checkpoint_and_reset_journal(
    backend: &dyn StorageBackend,
    sb: &RawSuperblock,
    metadata: &Metadata,
) -> Result<()> {
    write_metadata_copies(backend, std::slice::from_ref(sb), metadata)?;
    initialize_journal_region(backend, &sb.disk_id, sb)?;
    backend.flush_device(&sb.disk_id)
}

fn load_or_recover(
    backend: &dyn StorageBackend,
    superblocks: &[RawSuperblock],
    checkpoint_replay: bool,
) -> Result<(Metadata, TransactionReport)> {
    let mut candidates = Vec::new();
    for sb in superblocks {
        candidates.extend(
            read_metadata_candidates(backend, sb)?
                .into_iter()
                .map(|(metadata, report)| (sb.disk_id.clone(), metadata, report)),
        );
    }
    let mut report = TransactionReport::default();
    report.metadata_candidates = candidates
        .iter()
        .map(|(_, _, report)| report.clone())
        .collect();
    let mut best = select_quorum_metadata_candidate(&candidates)?;
    let journal_best =
        read_latest_journal_metadata(backend, superblocks, &mut report, best.as_ref())?;
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
    if checkpoint_replay && report.replayed {
        journal::inject_crash(FaultPoint::DuringReplay.as_str())?;
        write_metadata_copies(backend, superblocks, &metadata)?;
    }
    Ok((metadata, report))
}

fn select_quorum_metadata_candidate(
    candidates: &[(String, Option<Metadata>, MetadataCandidateReport)],
) -> Result<Option<Metadata>> {
    let mut supported =
        BTreeMap::<(u64, u64, String), (Metadata, std::collections::BTreeSet<String>)>::new();
    for (disk_id, metadata, _) in candidates {
        let Some(metadata) = metadata else {
            continue;
        };
        let hash = metadata_hash_for_replay(metadata)?;
        supported
            .entry((metadata.txid, metadata.integrity.generation, hash))
            .or_insert_with(|| (metadata.clone(), std::collections::BTreeSet::new()))
            .1
            .insert(disk_id.clone());
    }
    Ok(supported
        .into_iter()
        .filter(|(_, (metadata, members))| members.len() >= metadata_quorum_requirement(metadata))
        .max_by_key(|((txid, generation, _), _)| (*txid, *generation))
        .map(|(_, (metadata, _))| metadata))
}

fn metadata_quorum_requirement(metadata: &Metadata) -> usize {
    metadata.disks.len().max(1) / 2 + 1
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
                match read_metadata_candidate(backend, sb, offset, slot_len, &header) {
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

fn read_metadata_candidate(
    backend: &dyn StorageBackend,
    sb: &RawSuperblock,
    offset: u64,
    slot_len: u64,
    header: &[u8],
) -> Result<Metadata> {
    match get_u32(header, 20)? {
        METADATA_FORMAT_LEGACY => {
            read_legacy_metadata_candidate(backend, sb, offset, slot_len, header)
        }
        METADATA_FORMAT_TREE => read_tree_metadata_candidate(backend, sb, offset, slot_len, header),
        format => Err(ArgosError::IncompatibleFormat(format!(
            "unsupported raw metadata checkpoint format {format}"
        ))),
    }
}

fn read_legacy_metadata_candidate(
    backend: &dyn StorageBackend,
    sb: &RawSuperblock,
    offset: u64,
    slot_len: u64,
    header: &[u8],
) -> Result<Metadata> {
    let len = checked_usize(get_u64(header, 32)?, "raw metadata length")?;
    let stored_hash = get_fixed_hex(header, 64, HASH_HEX_LEN)?;
    if len == 0 || len as u64 > slot_len.saturating_sub(RAW_HEADER_SIZE as u64) {
        return Err(ArgosError::CorruptedMetadata(
            "invalid raw metadata length".to_string(),
        ));
    }
    let mut bytes = vec![0u8; len];
    backend.read_at(&sb.disk_id, offset + RAW_HEADER_SIZE as u64, &mut bytes)?;
    if sha256_hex(&bytes) != stored_hash {
        return Err(ArgosError::Checksum(
            "raw metadata checksum mismatch".to_string(),
        ));
    }
    Ok(serde_json::from_slice::<Metadata>(&bytes)?)
}

fn read_tree_metadata_candidate(
    backend: &dyn StorageBackend,
    sb: &RawSuperblock,
    offset: u64,
    slot_len: u64,
    header: &[u8],
) -> Result<Metadata> {
    let len = checked_usize(get_u64(header, 32)?, "raw metadata length")?;
    let stored_hash = get_fixed_hex(header, 64, HASH_HEX_LEN)?;
    let page_size = checked_usize(get_u64(header, 144)?, "raw metadata page size")?;
    let page_count = checked_usize(get_u64(header, 152)?, "raw metadata page count")?;
    let index_len = checked_usize(get_u64(header, 160)?, "raw metadata index length")?;
    let index_hash = get_fixed_hex(header, 168, HASH_HEX_LEN)?;
    if len == 0 {
        return Err(ArgosError::CorruptedMetadata(
            "invalid raw metadata length".to_string(),
        ));
    }
    if page_size == 0 || page_size > 1024 * 1024 {
        return Err(ArgosError::CorruptedMetadata(
            "invalid raw metadata page size".to_string(),
        ));
    }
    let expected_pages = len.div_ceil(page_size);
    let expected_index_len = page_count
        .checked_mul(METADATA_INDEX_ENTRY_SIZE)
        .ok_or_else(|| ArgosError::CorruptedMetadata("raw metadata index overflows".to_string()))?;
    if page_count != expected_pages || index_len != expected_index_len {
        return Err(ArgosError::CorruptedMetadata(
            "invalid raw metadata page index".to_string(),
        ));
    }
    let index_end = (RAW_HEADER_SIZE as u64)
        .checked_add(index_len as u64)
        .ok_or_else(|| ArgosError::CorruptedMetadata("raw metadata index overflows".to_string()))?;
    if index_end > slot_len {
        return Err(ArgosError::CorruptedMetadata(
            "raw metadata index exceeds slot".to_string(),
        ));
    }
    let mut index = vec![0u8; index_len];
    backend.read_at(&sb.disk_id, offset + RAW_HEADER_SIZE as u64, &mut index)?;
    if sha256_hex(&index) != index_hash {
        return Err(ArgosError::Checksum(
            "raw metadata index checksum mismatch".to_string(),
        ));
    }
    let data_start = align_up(index_end, page_size as u64);
    let mut bytes = Vec::with_capacity(len);
    for page_index in 0..page_count {
        let entry_start = page_index * METADATA_INDEX_ENTRY_SIZE;
        let entry = &index[entry_start..entry_start + METADATA_INDEX_ENTRY_SIZE];
        let stored_page_hash = hex::encode(&entry[..HASH_BYTES_LEN]);
        let relative_offset = get_u64(entry, 32)?;
        let page_len = get_u32(entry, 40)? as usize;
        let expected_offset = (page_index as u64)
            .checked_mul(page_size as u64)
            .and_then(|delta| data_start.checked_add(delta))
            .ok_or_else(|| {
                ArgosError::CorruptedMetadata("raw metadata page offset overflows".to_string())
            })?;
        let end = relative_offset
            .checked_add(page_len as u64)
            .ok_or_else(|| {
                ArgosError::CorruptedMetadata("raw metadata page overflows".to_string())
            })?;
        if page_len == 0
            || page_len > page_size
            || relative_offset != expected_offset
            || end > slot_len
        {
            return Err(ArgosError::CorruptedMetadata(
                "invalid raw metadata page extent".to_string(),
            ));
        }
        let mut page = vec![0u8; page_len];
        backend.read_at(&sb.disk_id, offset + relative_offset, &mut page)?;
        if sha256_hex(&page) != stored_page_hash {
            return Err(ArgosError::Checksum(format!(
                "raw metadata page {page_index} checksum mismatch"
            )));
        }
        bytes.extend_from_slice(&page);
    }
    if bytes.len() != len || sha256_hex(&bytes) != stored_hash {
        return Err(ArgosError::Checksum(
            "raw metadata checksum mismatch".to_string(),
        ));
    }
    Ok(serde_json::from_slice::<Metadata>(&bytes)?)
}

fn read_latest_journal_metadata(
    backend: &dyn StorageBackend,
    superblocks: &[RawSuperblock],
    report: &mut TransactionReport,
    base_metadata: Option<&Metadata>,
) -> Result<Option<Metadata>> {
    let mut supported =
        BTreeMap::<(u64, u64, String), (Metadata, std::collections::BTreeSet<String>)>::new();
    let mut members = Vec::new();
    for sb in superblocks {
        let valid_before = report.valid_entries;
        let invalid_before = report.invalid_entries;
        let mut member = RawJournalMemberReport {
            disk_id: sb.disk_id.clone(),
            ..RawJournalMemberReport::default()
        };
        let mut latest = base_metadata.cloned();
        let mut member_candidates = BTreeMap::<(u64, u64, String), Metadata>::new();
        let mut header = vec![0u8; RAW_HEADER_SIZE];
        if let Err(err) = backend.read_at(&sb.disk_id, sb.journal.offset, &mut header) {
            member.error = Some(err.to_string());
            members.push(member);
            continue;
        }
        if &header[..16] != JOURNAL_MAGIC {
            member.error = Some("raw journal header magic mismatch".to_string());
            members.push(member);
            continue;
        }
        member.readable = true;
        let mut cursor = RAW_HEADER_SIZE as u64;
        let end = get_u64(&header, 24)?.min(sb.journal.length);
        member.journal_end = end;
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
                    member.last_valid_txid = record.txid;
                    member.last_valid_generation = record.generation;
                    member.last_valid_record_hash = record.record_hash.clone();
                    let candidate = if let Some(metadata) = record.metadata {
                        let metadata_hash = journal::canonical_metadata_hash(&metadata)?;
                        if metadata_hash != record.meta_hash {
                            report.invalid_entries += 1;
                            report.errors.push(format!(
                                "raw journal metadata at {}:{} has a metadata hash mismatch",
                                sb.disk_id, cursor
                            ));
                            break;
                        }
                        if !metadata.integrity.meta_hash.is_empty()
                            && metadata.integrity.meta_hash != metadata_hash
                        {
                            report.invalid_entries += 1;
                            report.errors.push(format!(
                                "raw journal metadata at {}:{} has an integrity hash mismatch",
                                sb.disk_id, cursor
                            ));
                            break;
                        }
                        if metadata.txid != record.txid
                            || metadata.integrity.generation != record.generation
                        {
                            report.invalid_entries += 1;
                            report.errors.push(format!(
                                "raw journal metadata at {}:{} has inconsistent txid/generation",
                                sb.disk_id, cursor
                            ));
                            break;
                        }
                        Some(metadata)
                    } else if let Some(delta) = record.metadata_delta.as_ref() {
                        let Some(base) = latest.as_ref() else {
                            report.invalid_entries += 1;
                            report.errors.push(format!(
                                "raw journal record at {}:{} lacks a metadata checkpoint base",
                                sb.disk_id, cursor
                            ));
                            break;
                        };
                        if record.txid <= base.txid {
                            cursor += 36 + len as u64;
                            continue;
                        }
                        let base_hash = metadata_hash_for_replay(base)?;
                        if let Some(previous_hash) = raw_record_previous_meta_hash(&record) {
                            if previous_hash != base_hash {
                                report.invalid_entries += 1;
                                report.errors.push(format!(
                                    "raw journal delta at {}:{} does not chain from selected metadata: previous_meta_hash={} selected_meta_hash={}",
                                    sb.disk_id, cursor, previous_hash, base_hash
                                ));
                                break;
                            }
                        }
                        match journal::apply_metadata_delta(base, delta) {
                            Ok(metadata) => {
                                let metadata_hash = journal::canonical_metadata_hash(&metadata)?;
                                if metadata_hash != record.meta_hash {
                                    report.invalid_entries += 1;
                                    report.errors.push(format!(
                                        "raw journal delta at {}:{} has a metadata hash mismatch",
                                        sb.disk_id, cursor
                                    ));
                                    break;
                                }
                                if metadata.txid != record.txid
                                    || metadata.integrity.generation != record.generation
                                {
                                    report.invalid_entries += 1;
                                    report.errors.push(format!(
                                        "raw journal delta at {}:{} has inconsistent txid/generation",
                                        sb.disk_id, cursor
                                    ));
                                    break;
                                }
                                Some(metadata)
                            }
                            Err(err) => {
                                report.invalid_entries += 1;
                                report.errors.push(format!(
                                    "raw journal delta at {}:{} is invalid: {err}",
                                    sb.disk_id, cursor
                                ));
                                break;
                            }
                        }
                    } else {
                        report.invalid_entries += 1;
                        report.errors.push(format!(
                            "raw journal record at {}:{} lacks a metadata checkpoint base",
                            sb.disk_id, cursor
                        ));
                        break;
                    };
                    let Some(candidate) = candidate else {
                        break;
                    };
                    if latest
                        .as_ref()
                        .map(|metadata| candidate.txid <= metadata.txid)
                        .unwrap_or(false)
                    {
                        cursor += 36 + len as u64;
                        continue;
                    }
                    let candidate_hash = metadata_hash_for_replay(&candidate)?;
                    member_candidates.insert(
                        (
                            candidate.txid,
                            candidate.integrity.generation,
                            candidate_hash,
                        ),
                        candidate.clone(),
                    );
                    latest = Some(candidate);
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
        member.valid_entries = report.valid_entries.saturating_sub(valid_before);
        member.invalid_entries = report.invalid_entries.saturating_sub(invalid_before);
        if member.invalid_entries == 0 {
            for (key, metadata) in member_candidates {
                supported
                    .entry(key)
                    .or_insert_with(|| (metadata, std::collections::BTreeSet::new()))
                    .1
                    .insert(sb.disk_id.clone());
            }
        }
        members.push(member);
    }
    let best = supported
        .into_iter()
        .filter(|(_, (metadata, member_ids))| {
            member_ids.len() >= metadata_quorum_requirement(metadata)
        })
        .max_by_key(|((txid, generation, _), _)| (*txid, *generation))
        .map(|(_, (metadata, _))| metadata);
    let total_members = base_metadata
        .map(|metadata| metadata.disks.len())
        .unwrap_or(superblocks.len())
        .max(superblocks.len());
    report.raw_journal_quorum = Some(raw_journal_quorum(&members, total_members) || best.is_some());
    report.raw_journal_members = members;
    Ok(best)
}

fn raw_journal_quorum(members: &[RawJournalMemberReport], total_members: usize) -> bool {
    if total_members == 0 {
        return true;
    }
    let required = total_members / 2 + 1;
    let mut counts: BTreeMap<(u64, u64, String), usize> = BTreeMap::new();
    for member in members {
        if !member.readable || member.invalid_entries > 0 {
            continue;
        }
        let key = (
            member.last_valid_txid,
            member.last_valid_generation,
            member.last_valid_record_hash.clone(),
        );
        let count = counts.entry(key).or_default();
        *count += 1;
        if *count >= required {
            return true;
        }
    }
    false
}

fn raw_record_previous_meta_hash(record: &RawJournalRecord) -> Option<&str> {
    record
        .details
        .get("previous_meta_hash")
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.is_empty())
}

fn metadata_hash_for_replay(metadata: &Metadata) -> Result<String> {
    if metadata.integrity.meta_hash.is_empty() {
        journal::canonical_metadata_hash(metadata)
    } else {
        Ok(metadata.integrity.meta_hash.clone())
    }
}

struct MetadataTreeCheckpoint {
    header: [u8; RAW_HEADER_SIZE],
    body_writes: Vec<(u64, Vec<u8>)>,
}

fn metadata_tree_checkpoint(
    disk_id: &str,
    txid: u64,
    generation: u64,
    bytes: &[u8],
    hash: &str,
    slot_len: u64,
) -> Result<MetadataTreeCheckpoint> {
    let page_count = bytes.len().div_ceil(METADATA_PAGE_SIZE);
    let index_len = page_count
        .checked_mul(METADATA_INDEX_ENTRY_SIZE)
        .ok_or_else(|| ArgosError::DiskFull {
            disk_id: disk_id.to_string(),
            required: bytes.len() as u64,
            available: slot_len,
        })?;
    let index_end = (RAW_HEADER_SIZE as u64)
        .checked_add(index_len as u64)
        .ok_or_else(|| ArgosError::DiskFull {
            disk_id: disk_id.to_string(),
            required: bytes.len() as u64,
            available: slot_len,
        })?;
    let data_start = align_up(index_end, METADATA_PAGE_SIZE as u64);
    let data_bytes = (page_count as u64)
        .checked_mul(METADATA_PAGE_SIZE as u64)
        .ok_or_else(|| ArgosError::DiskFull {
            disk_id: disk_id.to_string(),
            required: bytes.len() as u64,
            available: slot_len,
        })?;
    let data_end = data_start
        .checked_add(data_bytes)
        .ok_or_else(|| ArgosError::DiskFull {
            disk_id: disk_id.to_string(),
            required: bytes.len() as u64,
            available: slot_len,
        })?;
    if bytes.is_empty() || data_end > slot_len {
        return Err(ArgosError::DiskFull {
            disk_id: disk_id.to_string(),
            required: data_end.max(bytes.len() as u64),
            available: slot_len,
        });
    }

    let mut index = vec![0u8; index_len];
    let mut body_writes = Vec::with_capacity(page_count + 1);
    for page_index in 0..page_count {
        let start = page_index * METADATA_PAGE_SIZE;
        let end = (start + METADATA_PAGE_SIZE).min(bytes.len());
        let page = bytes[start..end].to_vec();
        let page_hash = hex::decode(sha256_hex(&page)).map_err(|err| {
            ArgosError::Invalid(format!("raw metadata page hash encode failed: {err}"))
        })?;
        if page_hash.len() != HASH_BYTES_LEN {
            return Err(ArgosError::Invalid(
                "raw metadata page hash has invalid length".to_string(),
            ));
        }
        let entry_start = page_index * METADATA_INDEX_ENTRY_SIZE;
        let entry = &mut index[entry_start..entry_start + METADATA_INDEX_ENTRY_SIZE];
        entry[..HASH_BYTES_LEN].copy_from_slice(&page_hash);
        let relative_offset = (page_index as u64)
            .checked_mul(METADATA_PAGE_SIZE as u64)
            .and_then(|delta| data_start.checked_add(delta))
            .ok_or_else(|| ArgosError::DiskFull {
                disk_id: disk_id.to_string(),
                required: bytes.len() as u64,
                available: slot_len,
            })?;
        put_u64(entry, 32, relative_offset);
        put_u32(entry, 40, page.len() as u32);
        body_writes.push((relative_offset, page));
    }
    let index_hash = sha256_hex(&index);
    body_writes.push((RAW_HEADER_SIZE as u64, index));

    let mut out = [0u8; RAW_HEADER_SIZE];
    out[..16].copy_from_slice(METADATA_MAGIC);
    put_u32(&mut out, 16, RAW_STORE_VERSION);
    put_u32(&mut out, 20, METADATA_FORMAT_TREE);
    put_u64(&mut out, 24, txid);
    put_u64(&mut out, 32, bytes.len() as u64);
    put_fixed_str(&mut out, 64, 64, hash);
    put_u64(&mut out, 136, generation);
    put_u64(&mut out, 144, METADATA_PAGE_SIZE as u64);
    put_u64(&mut out, 152, page_count as u64);
    put_u64(&mut out, 160, index_len as u64);
    put_fixed_str(&mut out, 168, HASH_HEX_LEN, &index_hash);
    Ok(MetadataTreeCheckpoint {
        header: out,
        body_writes,
    })
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
        Ok((sb, source)) => {
            let label_result = (|| {
                let mut label = vec![0u8; DEVICE_LABEL_SIZE];
                backend.read_at(&id, DEVICE_LABEL_OFFSET, &mut label)?;
                let label = RawDeviceLabel::decode(&label)?;
                validate_label_matches_superblock(&sb, &label)
            })();
            if let Err(err) = label_result {
                return ScannedDevice {
                    path: path.clone(),
                    valid: false,
                    error: Some(err.to_string()),
                    pool_uuid: Some(sb.pool_uuid.to_string()),
                    device_uuid: Some(sb.device_uuid.to_string()),
                    disk_id: Some(sb.disk_id),
                    disk_index: Some(sb.disk_index),
                    generation: Some(sb.generation),
                    clean: Some(sb.clean),
                    label: Some(sb.label),
                    capacity,
                    superblock_source: Some(source.to_string()),
                };
            }
            ScannedDevice {
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
            }
        }
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

fn get_u32(bytes: &[u8], offset: usize) -> Result<u32> {
    let raw = bytes
        .get(offset..offset + 4)
        .ok_or_else(|| ArgosError::CorruptedMetadata("short raw-store u32".to_string()))?;
    Ok(u32::from_le_bytes(raw.try_into().unwrap()))
}

fn checked_usize(value: u64, name: &str) -> Result<usize> {
    usize::try_from(value)
        .map_err(|_| ArgosError::CorruptedMetadata(format!("{name} does not fit usize")))
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
