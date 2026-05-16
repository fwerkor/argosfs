use crate::error::{ArgosError, Result};
use crate::types::{
    Metadata, MetadataCandidateReport, MetadataIntegrity, TransactionReport, FORMAT_VERSION,
};
use crate::util::{append_json_line, atomic_write, now_f64, read_to_vec, sha256_hex, FileLock};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::cell::RefCell;
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

const JOURNAL_VERSION: u32 = 1;
const PRIMARY_META: &str = "meta.primary.json";
const SECONDARY_META: &str = "meta.secondary.json";
const COMPAT_META: &str = "meta.json";

thread_local! {
    static THREAD_CRASH_POINT: RefCell<Option<String>> = const { RefCell::new(None) };
}

#[derive(Clone, Debug)]
pub struct RecoveredMetadata {
    pub metadata: Metadata,
    pub report: TransactionReport,
}

#[derive(Clone, Debug)]
struct MetadataCandidate {
    source: String,
    metadata: Option<Metadata>,
    report: MetadataCandidateReport,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct JournalRecord {
    #[serde(default)]
    pub version: u32,
    #[serde(default)]
    pub time: f64,
    #[serde(default)]
    pub volume_uuid: String,
    #[serde(default)]
    pub txid: u64,
    #[serde(default)]
    pub generation: u64,
    #[serde(default)]
    pub action: String,
    #[serde(default)]
    pub details: serde_json::Value,
    #[serde(default)]
    pub previous_record_hash: String,
    #[serde(default)]
    pub previous_meta_hash: String,
    #[serde(default)]
    pub meta_hash: String,
    #[serde(default)]
    pub metadata: Option<Metadata>,
    #[serde(default)]
    pub record_hash: String,
}

pub fn initialize_volume(root: &Path, meta: &mut Metadata, created_at: f64) -> Result<()> {
    prepare_metadata_integrity(meta, String::new())?;
    let record = build_record(
        meta,
        "mkfs",
        json!({"txid": meta.txid}),
        String::new(),
        created_at,
    )?;
    append_record(root, &record)?;
    write_metadata_copies(root, meta)?;
    Ok(())
}

pub fn load_or_recover(root: &Path) -> Result<RecoveredMetadata> {
    let mut candidates = read_metadata_candidates(root);
    let mut report = scan(root)?;
    report.metadata_candidates = candidates
        .iter()
        .map(|candidate| candidate.report.clone())
        .collect();
    report.double_write_mismatches = double_write_mismatches(&candidates);

    let mut best = candidates
        .iter_mut()
        .filter_map(|candidate| {
            candidate
                .metadata
                .take()
                .map(|metadata| (candidate.source.clone(), metadata))
        })
        .max_by(|left, right| metadata_order(&left.1).cmp(&metadata_order(&right.1)));

    if let Some(snapshot) = report_latest_snapshot(root)? {
        let snapshot_order = metadata_order(&snapshot);
        if best
            .as_ref()
            .map(|(_, metadata)| snapshot_order > metadata_order(metadata))
            .unwrap_or(true)
        {
            report.replayed = true;
            best = Some(("journal-replay".to_string(), snapshot));
        }
    }

    let Some((source, mut metadata)) = best else {
        return Err(ArgosError::Invalid(format!(
            "no valid metadata copy or replayable journal snapshot found: {}",
            serde_json::to_string(&report.metadata_candidates)?
        )));
    };
    ensure_integrity(&mut metadata)?;
    if metadata.format != FORMAT_VERSION {
        return Err(ArgosError::Invalid(format!(
            "unsupported format {}",
            metadata.format
        )));
    }
    report.selected_metadata_source = source;

    let needs_repair =
        report.replayed || report.double_write_mismatches > 0 || missing_or_invalid_copy(&report);
    if needs_repair {
        write_metadata_copies(root, &metadata)?;
    }

    Ok(RecoveredMetadata { metadata, report })
}

pub fn scan(root: &Path) -> Result<TransactionReport> {
    let mut report = TransactionReport::default();
    let mut previous_hash = String::new();
    let journal = journal_path(root);
    let Ok(text) = fs::read_to_string(&journal) else {
        return Ok(report);
    };
    for (line_no, raw) in text.lines().enumerate() {
        if raw.trim().is_empty() {
            continue;
        }
        let value = match serde_json::from_str::<serde_json::Value>(raw) {
            Ok(value) => value,
            Err(err) => {
                report.invalid_entries += 1;
                report
                    .errors
                    .push(format!("journal line {}: invalid JSON: {err}", line_no + 1));
                continue;
            }
        };
        let record = match serde_json::from_value::<JournalRecord>(value.clone()) {
            Ok(record) => record,
            Err(err) => {
                report.invalid_entries += 1;
                report.errors.push(format!(
                    "journal line {}: invalid record: {err}",
                    line_no + 1
                ));
                continue;
            }
        };
        if record.record_hash.is_empty() {
            report.valid_entries += 1;
            report.legacy_entries += 1;
            report.last_valid_txid = report.last_valid_txid.max(record.txid);
            continue;
        }
        let expected = record_hash_value(&value)?;
        if expected != record.record_hash {
            report.invalid_entries += 1;
            report.errors.push(format!(
                "journal line {}: record hash mismatch",
                line_no + 1
            ));
            continue;
        }
        if record.previous_record_hash != previous_hash {
            report.invalid_entries += 1;
            report.errors.push(format!(
                "journal line {}: previous record hash mismatch",
                line_no + 1
            ));
            continue;
        }
        if let Some(metadata_value) = value.get("metadata") {
            match canonical_metadata_hash_value(metadata_value) {
                Ok(hash) if hash == record.meta_hash => {
                    report.latest_snapshot_txid = record.txid;
                    report.latest_snapshot_generation = record.generation;
                }
                Ok(_) => {
                    report.invalid_entries += 1;
                    report.errors.push(format!(
                        "journal line {}: metadata snapshot hash mismatch",
                        line_no + 1
                    ));
                    continue;
                }
                Err(err) => {
                    report.invalid_entries += 1;
                    report
                        .errors
                        .push(format!("journal line {}: {err}", line_no + 1));
                    continue;
                }
            }
        }
        report.valid_entries += 1;
        report.last_valid_txid = record.txid;
        report.last_valid_generation = record.generation;
        report.last_valid_record_hash = record.record_hash.clone();
        previous_hash = record.record_hash;
    }
    Ok(report)
}

pub fn append_transaction(
    root: &Path,
    meta: &mut Metadata,
    action: &str,
    details: serde_json::Value,
) -> Result<()> {
    append_transaction_checked(root, meta, None, action, details)
}

pub fn append_transaction_checked(
    root: &Path,
    meta: &mut Metadata,
    expected_previous_txid: Option<u64>,
    action: &str,
    details: serde_json::Value,
) -> Result<()> {
    let _lock = FileLock::exclusive(&transaction_lock_path(root))?;
    if let Some(expected) = expected_previous_txid {
        if let Some(current) = latest_metadata_txid_unlocked(root)? {
            if current > expected {
                return Err(ArgosError::Conflict(format!(
                    "volume advanced from txid {expected} to {current}; reopen and retry"
                )));
            }
        }
    }
    inject_crash("before-journal")?;
    let previous_meta_hash = if meta.integrity.meta_hash.is_empty() {
        canonical_metadata_hash(meta)?
    } else {
        meta.integrity.meta_hash.clone()
    };
    prepare_metadata_integrity(meta, previous_meta_hash)?;
    let previous_record_hash = scan(root)?.last_valid_record_hash;
    let record = build_record(meta, action, details, previous_record_hash, now_f64())?;
    append_record(root, &record)?;
    inject_crash("after-journal")?;
    write_metadata_copies_with_injection(root, meta)
}

pub fn append_event(
    root: &Path,
    meta: &Metadata,
    action: &str,
    details: serde_json::Value,
) -> Result<()> {
    let _lock = FileLock::exclusive(&transaction_lock_path(root))?;
    let previous_record_hash = scan(root)?.last_valid_record_hash;
    let record = build_record(meta, action, details, previous_record_hash, now_f64())?;
    append_record(root, &record)
}

pub fn write_metadata_copies(root: &Path, meta: &Metadata) -> Result<()> {
    let system = root.join(".argosfs");
    let bytes = serde_json::to_vec_pretty(meta)?;
    atomic_write(&system.join(PRIMARY_META), &bytes)?;
    atomic_write(&system.join(SECONDARY_META), &bytes)?;
    atomic_write(&system.join(COMPAT_META), &bytes)?;
    Ok(())
}

pub fn canonical_metadata_hash(meta: &Metadata) -> Result<String> {
    let mut clone = meta.clone();
    clone.integrity = MetadataIntegrity::default();
    let persisted = serde_json::to_vec_pretty(&clone)?;
    let mut round_trip = serde_json::from_slice::<Metadata>(&persisted)?;
    round_trip.integrity = MetadataIntegrity::default();
    Ok(sha256_hex(&serde_json::to_vec_pretty(&round_trip)?))
}

pub fn inject_crash(point: &str) -> Result<()> {
    let thread_spec = THREAD_CRASH_POINT.with(|value| value.borrow().clone());
    let spec = match thread_spec {
        Some(spec) => spec,
        None => match std::env::var("ARGOSFS_CRASH_POINT") {
            Ok(spec) => spec,
            Err(_) => return Ok(()),
        },
    };
    if spec
        .split(',')
        .map(str::trim)
        .any(|wanted| wanted == point || wanted == "all")
    {
        if std::env::var("ARGOSFS_CRASH_ABORT").ok().as_deref() == Some("1") {
            std::process::abort();
        }
        return Err(ArgosError::InjectedCrash(point.to_string()));
    }
    Ok(())
}

pub fn set_thread_crash_point(point: Option<&str>) {
    THREAD_CRASH_POINT.with(|value| {
        *value.borrow_mut() = point.map(ToString::to_string);
    });
}

fn write_metadata_copies_with_injection(root: &Path, meta: &Metadata) -> Result<()> {
    let system = root.join(".argosfs");
    let bytes = serde_json::to_vec_pretty(meta)?;
    atomic_write(&system.join(PRIMARY_META), &bytes)?;
    inject_crash("after-primary-metadata")?;
    atomic_write(&system.join(SECONDARY_META), &bytes)?;
    inject_crash("after-secondary-metadata")?;
    atomic_write(&system.join(COMPAT_META), &bytes)?;
    inject_crash("after-compatible-metadata")?;
    Ok(())
}

fn prepare_metadata_integrity(meta: &mut Metadata, previous_meta_hash: String) -> Result<()> {
    meta.integrity.generation = meta.txid;
    meta.integrity.previous_meta_hash = previous_meta_hash;
    meta.integrity.meta_hash = canonical_metadata_hash(meta)?;
    Ok(())
}

fn ensure_integrity(meta: &mut Metadata) -> Result<()> {
    if meta.integrity.meta_hash.is_empty() {
        meta.integrity.generation = meta.txid;
        meta.integrity.previous_meta_hash = String::new();
        meta.integrity.meta_hash = canonical_metadata_hash(meta)?;
    }
    Ok(())
}

fn build_record(
    meta: &Metadata,
    action: &str,
    details: serde_json::Value,
    previous_record_hash: String,
    time: f64,
) -> Result<JournalRecord> {
    let mut record = JournalRecord {
        version: JOURNAL_VERSION,
        time,
        volume_uuid: meta.uuid.clone(),
        txid: meta.txid,
        generation: meta.integrity.generation,
        action: action.to_string(),
        details,
        previous_record_hash,
        previous_meta_hash: meta.integrity.previous_meta_hash.clone(),
        meta_hash: canonical_metadata_hash(meta)?,
        metadata: Some(meta.clone()),
        record_hash: String::new(),
    };
    record.record_hash = record_hash(&record)?;
    Ok(record)
}

fn record_hash(record: &JournalRecord) -> Result<String> {
    let mut clone = record.clone();
    clone.record_hash.clear();
    let persisted = serde_json::to_vec_pretty(&clone)?;
    let mut round_trip = serde_json::from_slice::<JournalRecord>(&persisted)?;
    round_trip.record_hash.clear();
    Ok(sha256_hex(&serde_json::to_vec_pretty(&round_trip)?))
}

fn record_hash_value(value: &serde_json::Value) -> Result<String> {
    let mut record = serde_json::from_value::<JournalRecord>(value.clone())?;
    record.record_hash.clear();
    record_hash(&record)
}

fn canonical_metadata_hash_bytes(bytes: &[u8]) -> Result<String> {
    let metadata = serde_json::from_slice::<Metadata>(bytes)?;
    canonical_metadata_hash(&metadata)
}

fn canonical_metadata_hash_value(value: &serde_json::Value) -> Result<String> {
    let metadata = serde_json::from_value::<Metadata>(value.clone())?;
    canonical_metadata_hash(&metadata)
}

fn append_record(root: &Path, record: &JournalRecord) -> Result<()> {
    append_json_line(&journal_path(root), record)
}

fn read_metadata_candidates(root: &Path) -> Vec<MetadataCandidate> {
    metadata_paths(root)
        .into_iter()
        .map(|(source, path)| read_candidate(source, path))
        .collect()
}

fn read_candidate(source: String, path: PathBuf) -> MetadataCandidate {
    let mut report = MetadataCandidateReport {
        path: path.display().to_string(),
        ..MetadataCandidateReport::default()
    };
    if !path.exists() {
        return MetadataCandidate {
            source,
            metadata: None,
            report,
        };
    }
    report.present = true;
    let metadata = match read_to_vec(&path).and_then(|bytes| {
        let hash = canonical_metadata_hash_bytes(&bytes)?;
        let mut metadata = serde_json::from_slice::<Metadata>(&bytes).map_err(ArgosError::Json)?;
        validate_metadata(&mut metadata, &hash)?;
        Ok(metadata)
    }) {
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
    };
    MetadataCandidate {
        source,
        metadata,
        report,
    }
}

fn validate_metadata(meta: &mut Metadata, computed: &str) -> Result<()> {
    if meta.format != FORMAT_VERSION {
        return Err(ArgosError::Invalid(format!(
            "unsupported format {}",
            meta.format
        )));
    }
    if meta.integrity.meta_hash.is_empty() {
        meta.integrity.generation = meta.txid;
        meta.integrity.meta_hash = computed.to_string();
        return Ok(());
    }
    if meta.integrity.meta_hash != computed {
        return Err(ArgosError::Invalid(format!(
            "metadata hash mismatch: stored={} computed={computed}",
            meta.integrity.meta_hash
        )));
    }
    Ok(())
}

fn report_latest_snapshot(root: &Path) -> Result<Option<Metadata>> {
    let journal = journal_path(root);
    let Ok(text) = fs::read_to_string(&journal) else {
        return Ok(None);
    };
    let mut previous_hash = String::new();
    let mut latest = None;
    for raw in text.lines() {
        let Ok(value) = serde_json::from_str::<serde_json::Value>(raw) else {
            continue;
        };
        let Ok(record) = serde_json::from_value::<JournalRecord>(value.clone()) else {
            continue;
        };
        if record.record_hash.is_empty() {
            continue;
        }
        if record_hash_value(&value)? != record.record_hash {
            continue;
        }
        if record.previous_record_hash != previous_hash {
            continue;
        }
        previous_hash = record.record_hash.clone();
        let Some(metadata_value) = value.get("metadata") else {
            continue;
        };
        if canonical_metadata_hash_value(metadata_value)? != record.meta_hash {
            continue;
        }
        let Some(mut metadata) = record.metadata else {
            continue;
        };
        ensure_integrity(&mut metadata)?;
        latest = Some(metadata);
    }
    Ok(latest)
}

fn latest_metadata_txid_unlocked(root: &Path) -> Result<Option<u64>> {
    let mut best = read_metadata_candidates(root)
        .into_iter()
        .filter_map(|candidate| candidate.metadata)
        .max_by(|left, right| metadata_order(left).cmp(&metadata_order(right)));
    if let Some(snapshot) = report_latest_snapshot(root)? {
        if best
            .as_ref()
            .map(|metadata| metadata_order(&snapshot) > metadata_order(metadata))
            .unwrap_or(true)
        {
            best = Some(snapshot);
        }
    }
    Ok(best.map(|metadata| metadata.txid))
}

fn metadata_paths(root: &Path) -> Vec<(String, PathBuf)> {
    let system = root.join(".argosfs");
    vec![
        ("compat".to_string(), system.join(COMPAT_META)),
        ("primary".to_string(), system.join(PRIMARY_META)),
        ("secondary".to_string(), system.join(SECONDARY_META)),
    ]
}

fn journal_path(root: &Path) -> PathBuf {
    root.join(".argosfs/journal.jsonl")
}

fn transaction_lock_path(root: &Path) -> PathBuf {
    root.join(".argosfs/tx.lock")
}

fn metadata_order(meta: &Metadata) -> (u64, u64) {
    (meta.txid, meta.integrity.generation)
}

fn double_write_mismatches(candidates: &[MetadataCandidate]) -> u64 {
    let mut hashes = BTreeSet::new();
    let mut present = 0u64;
    let mut invalid = 0u64;
    for candidate in candidates {
        if candidate.report.present {
            present += 1;
            if candidate.report.valid {
                hashes.insert(candidate.report.meta_hash.clone());
            } else {
                invalid += 1;
            }
        }
    }
    let divergent = if hashes.len() > 1 {
        hashes.len() as u64 - 1
    } else {
        0
    };
    invalid + divergent + u64::from(present > 0 && hashes.is_empty())
}

fn missing_or_invalid_copy(report: &TransactionReport) -> bool {
    report
        .metadata_candidates
        .iter()
        .any(|candidate| !candidate.present || !candidate.valid)
}
