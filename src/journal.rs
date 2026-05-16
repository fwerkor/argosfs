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
pub const DEFAULT_CHECKPOINT_INTERVAL_TXIDS: u64 = 128;
const CHECKPOINT_INTERVAL_ENV: &str = "ARGOSFS_CHECKPOINT_INTERVAL_TXIDS";
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

struct BuildRecordOptions {
    record_type: JournalRecordKind,
    action: String,
    details: serde_json::Value,
    previous_record_hash: String,
    time: f64,
    metadata: Option<Metadata>,
    metadata_delta: Option<Vec<MetadataDeltaOp>>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum JournalRecordKind {
    #[default]
    Transaction,
    Checkpoint,
    Event,
}

impl JournalRecordKind {
    fn is_transaction(kind: &Self) -> bool {
        matches!(kind, Self::Transaction)
    }

    fn is_checkpoint(&self) -> bool {
        matches!(self, Self::Checkpoint)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "op", rename_all = "kebab-case")]
pub enum MetadataDeltaOp {
    Add {
        path: String,
        value: serde_json::Value,
    },
    Remove {
        path: String,
    },
    Replace {
        path: String,
        value: serde_json::Value,
    },
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct JournalRecord {
    #[serde(default)]
    pub version: u32,
    #[serde(default, skip_serializing_if = "JournalRecordKind::is_transaction")]
    pub record_type: JournalRecordKind,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Metadata>,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata_delta: Option<Vec<MetadataDeltaOp>>,
    #[serde(default)]
    pub record_hash: String,
}

pub fn initialize_volume(root: &Path, meta: &mut Metadata, created_at: f64) -> Result<()> {
    prepare_metadata_integrity(meta, String::new())?;
    let record = build_record(
        meta,
        BuildRecordOptions {
            record_type: JournalRecordKind::Checkpoint,
            action: "mkfs".to_string(),
            details: json!({"txid": meta.txid}),
            previous_record_hash: String::new(),
            time: created_at,
            metadata: Some(meta.clone()),
            metadata_delta: None,
        },
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

    if let Some(replayed) = report_latest_recoverable_metadata(root)? {
        let snapshot_order = metadata_order(&replayed);
        if best
            .as_ref()
            .map(|(_, metadata)| snapshot_order > metadata_order(metadata))
            .unwrap_or(true)
        {
            report.replayed = true;
            best = Some(("journal-replay".to_string(), replayed));
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
        if !record_hash_is_valid(&value, &record)? {
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
        if let Some(metadata_value) = value.get("metadata").filter(|value| !value.is_null()) {
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
    let previous_metadata = latest_recoverable_metadata(root)?;
    let previous_meta_hash = if meta.integrity.meta_hash.is_empty() {
        canonical_metadata_hash(meta)?
    } else {
        meta.integrity.meta_hash.clone()
    };
    prepare_metadata_integrity(meta, previous_meta_hash)?;
    let previous_record_hash = scan(root)?.last_valid_record_hash;
    let should_checkpoint = should_write_checkpoint(root, meta.txid)?;
    let metadata_delta = if should_checkpoint {
        None
    } else {
        Some(metadata_delta(&previous_metadata, meta)?)
    };
    let record = build_record(
        meta,
        BuildRecordOptions {
            record_type: if should_checkpoint {
                JournalRecordKind::Checkpoint
            } else {
                JournalRecordKind::Transaction
            },
            action: action.to_string(),
            details,
            previous_record_hash,
            time: now_f64(),
            metadata: should_checkpoint.then(|| meta.clone()),
            metadata_delta,
        },
    )?;
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
    let record = build_record(
        meta,
        BuildRecordOptions {
            record_type: JournalRecordKind::Event,
            action: action.to_string(),
            details,
            previous_record_hash,
            time: now_f64(),
            metadata: None,
            metadata_delta: None,
        },
    )?;
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

fn build_record(meta: &Metadata, options: BuildRecordOptions) -> Result<JournalRecord> {
    let mut record = JournalRecord {
        version: JOURNAL_VERSION,
        record_type: options.record_type,
        time: options.time,
        volume_uuid: meta.uuid.clone(),
        txid: meta.txid,
        generation: meta.integrity.generation,
        action: options.action,
        details: options.details,
        previous_record_hash: options.previous_record_hash,
        previous_meta_hash: meta.integrity.previous_meta_hash.clone(),
        meta_hash: canonical_metadata_hash(meta)?,
        metadata: options.metadata,
        metadata_delta: options.metadata_delta,
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

fn record_hash_is_valid(value: &serde_json::Value, record: &JournalRecord) -> Result<bool> {
    Ok(record_hash_value(value)? == record.record_hash
        || legacy_record_hash_value(value).is_ok_and(|hash| hash == record.record_hash))
}

fn legacy_record_hash_value(value: &serde_json::Value) -> Result<String> {
    #[derive(Clone, Default, Deserialize, Serialize)]
    struct LegacyJournalRecord {
        #[serde(default)]
        version: u32,
        #[serde(default)]
        time: f64,
        #[serde(default)]
        volume_uuid: String,
        #[serde(default)]
        txid: u64,
        #[serde(default)]
        generation: u64,
        #[serde(default)]
        action: String,
        #[serde(default)]
        details: serde_json::Value,
        #[serde(default)]
        previous_record_hash: String,
        #[serde(default)]
        previous_meta_hash: String,
        #[serde(default)]
        meta_hash: String,
        #[serde(default)]
        metadata: Option<Metadata>,
        #[serde(default)]
        record_hash: String,
    }

    let mut record = serde_json::from_value::<LegacyJournalRecord>(value.clone())?;
    record.record_hash.clear();
    Ok(sha256_hex(&serde_json::to_vec_pretty(&record)?))
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

fn report_latest_recoverable_metadata(root: &Path) -> Result<Option<Metadata>> {
    let journal = journal_path(root);
    let Ok(text) = fs::read_to_string(&journal) else {
        return Ok(None);
    };
    let mut previous_hash = String::new();
    let mut latest: Option<Metadata> = None;
    let mut replay_failed = false;
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
        let Ok(valid_hash) = record_hash_is_valid(&value, &record) else {
            continue;
        };
        if !valid_hash {
            continue;
        }
        if record.previous_record_hash != previous_hash {
            continue;
        }
        previous_hash = record.record_hash.clone();
        let Some(metadata_value) = value.get("metadata").filter(|value| !value.is_null()) else {
            if replay_failed {
                continue;
            }
            if let (Some(base), Some(delta)) = (latest.as_ref(), record.metadata_delta.as_ref()) {
                if record.previous_meta_hash != base.integrity.meta_hash {
                    replay_failed = true;
                    continue;
                }
                let Ok(mut metadata) = apply_metadata_delta(base, delta) else {
                    replay_failed = true;
                    continue;
                };
                let Ok(meta_hash) = canonical_metadata_hash(&metadata) else {
                    replay_failed = true;
                    continue;
                };
                if meta_hash != record.meta_hash {
                    replay_failed = true;
                    continue;
                }
                if metadata.txid != record.txid
                    || metadata.integrity.generation != record.generation
                {
                    replay_failed = true;
                    continue;
                }
                if ensure_integrity(&mut metadata).is_err() {
                    replay_failed = true;
                    continue;
                }
                latest = Some(metadata);
            }
            continue;
        };
        let Ok(meta_hash) = canonical_metadata_hash_value(metadata_value) else {
            continue;
        };
        if meta_hash != record.meta_hash {
            continue;
        }
        let Some(mut metadata) = record.metadata else {
            continue;
        };
        ensure_integrity(&mut metadata)?;
        latest = Some(metadata);
        replay_failed = false;
    }
    Ok(latest)
}

fn latest_recoverable_metadata(root: &Path) -> Result<Metadata> {
    let mut best = read_metadata_candidates(root)
        .into_iter()
        .filter_map(|candidate| candidate.metadata)
        .max_by(|left, right| metadata_order(left).cmp(&metadata_order(right)));
    if let Some(replayed) = report_latest_recoverable_metadata(root)? {
        if best
            .as_ref()
            .map(|metadata| metadata_order(&replayed) > metadata_order(metadata))
            .unwrap_or(true)
        {
            best = Some(replayed);
        }
    }
    best.ok_or_else(|| ArgosError::Invalid("no recoverable metadata base found".to_string()))
}

fn latest_metadata_txid_unlocked(root: &Path) -> Result<Option<u64>> {
    let mut best = read_metadata_candidates(root)
        .into_iter()
        .filter_map(|candidate| candidate.metadata)
        .max_by(|left, right| metadata_order(left).cmp(&metadata_order(right)));
    if let Some(snapshot) = report_latest_recoverable_metadata(root)? {
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

fn should_write_checkpoint(root: &Path, txid: u64) -> Result<bool> {
    Ok(!has_valid_checkpoint(root)? || txid.is_multiple_of(checkpoint_interval_txids()))
}

pub fn checkpoint_interval_txids() -> u64 {
    std::env::var(CHECKPOINT_INTERVAL_ENV)
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(DEFAULT_CHECKPOINT_INTERVAL_TXIDS)
}

fn has_valid_checkpoint(root: &Path) -> Result<bool> {
    let journal = journal_path(root);
    let Ok(text) = fs::read_to_string(&journal) else {
        return Ok(false);
    };
    let mut previous_hash = String::new();
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
        let Ok(valid_hash) = record_hash_is_valid(&value, &record) else {
            continue;
        };
        if !valid_hash || record.previous_record_hash != previous_hash {
            continue;
        }
        previous_hash = record.record_hash.clone();
        if record.record_type.is_checkpoint() && record.metadata.is_some() {
            return Ok(true);
        }
    }
    Ok(false)
}

fn metadata_delta(previous: &Metadata, next: &Metadata) -> Result<Vec<MetadataDeltaOp>> {
    let previous = serde_json::to_value(previous)?;
    let next = serde_json::to_value(next)?;
    let mut ops = Vec::new();
    diff_json("", &previous, &next, &mut ops);
    Ok(ops)
}

fn apply_metadata_delta(previous: &Metadata, delta: &[MetadataDeltaOp]) -> Result<Metadata> {
    let mut value = serde_json::to_value(previous)?;
    for op in delta {
        apply_delta_op(&mut value, op)?;
    }
    let mut metadata = serde_json::from_value::<Metadata>(value)?;
    let hash = canonical_metadata_hash(&metadata)?;
    validate_metadata(&mut metadata, &hash)?;
    Ok(metadata)
}

fn diff_json(
    path: &str,
    previous: &serde_json::Value,
    next: &serde_json::Value,
    ops: &mut Vec<MetadataDeltaOp>,
) {
    match (previous, next) {
        (serde_json::Value::Object(left), serde_json::Value::Object(right)) => {
            for key in left.keys().filter(|key| !right.contains_key(*key)) {
                ops.push(MetadataDeltaOp::Remove {
                    path: push_json_pointer(path, key),
                });
            }
            for (key, right_value) in right {
                let child = push_json_pointer(path, key);
                if let Some(left_value) = left.get(key) {
                    diff_json(&child, left_value, right_value, ops);
                } else {
                    ops.push(MetadataDeltaOp::Add {
                        path: child,
                        value: right_value.clone(),
                    });
                }
            }
        }
        _ if previous != next => ops.push(MetadataDeltaOp::Replace {
            path: path.to_string(),
            value: next.clone(),
        }),
        _ => {}
    }
}

fn apply_delta_op(value: &mut serde_json::Value, op: &MetadataDeltaOp) -> Result<()> {
    match op {
        MetadataDeltaOp::Add { path, value: next } => set_json_pointer(value, path, next.clone()),
        MetadataDeltaOp::Replace { path, value: next } => {
            if path.is_empty() {
                *value = next.clone();
                Ok(())
            } else if get_json_pointer_mut(value, path).is_some() {
                set_json_pointer(value, path, next.clone())
            } else {
                Err(ArgosError::Invalid(format!(
                    "metadata delta replace target does not exist: {path}"
                )))
            }
        }
        MetadataDeltaOp::Remove { path } => remove_json_pointer(value, path),
    }
}

fn set_json_pointer(
    value: &mut serde_json::Value,
    path: &str,
    next: serde_json::Value,
) -> Result<()> {
    if path.is_empty() {
        *value = next;
        return Ok(());
    }
    let mut parts = json_pointer_tokens(path)?;
    let key = parts
        .pop()
        .ok_or_else(|| ArgosError::Invalid("empty metadata delta path".to_string()))?;
    let parent_path = json_pointer_from_tokens(&parts);
    let parent = get_json_pointer_mut(value, &parent_path).ok_or_else(|| {
        ArgosError::Invalid(format!(
            "metadata delta parent does not exist: {parent_path}"
        ))
    })?;
    match parent {
        serde_json::Value::Object(map) => {
            map.insert(key, next);
            Ok(())
        }
        serde_json::Value::Array(items) => {
            let index = key.parse::<usize>().map_err(|_| {
                ArgosError::Invalid(format!("metadata delta array index is invalid: {key}"))
            })?;
            if index > items.len() {
                return Err(ArgosError::Invalid(format!(
                    "metadata delta array index out of bounds: {index}"
                )));
            }
            if index == items.len() {
                items.push(next);
            } else {
                items[index] = next;
            }
            Ok(())
        }
        _ => Err(ArgosError::Invalid(format!(
            "metadata delta parent is not a container: {parent_path}"
        ))),
    }
}

fn remove_json_pointer(value: &mut serde_json::Value, path: &str) -> Result<()> {
    if path.is_empty() {
        *value = serde_json::Value::Null;
        return Ok(());
    }
    let mut parts = json_pointer_tokens(path)?;
    let key = parts
        .pop()
        .ok_or_else(|| ArgosError::Invalid("empty metadata delta path".to_string()))?;
    let parent_path = json_pointer_from_tokens(&parts);
    let parent = get_json_pointer_mut(value, &parent_path).ok_or_else(|| {
        ArgosError::Invalid(format!(
            "metadata delta parent does not exist: {parent_path}"
        ))
    })?;
    match parent {
        serde_json::Value::Object(map) => map.remove(&key).map(|_| ()).ok_or_else(|| {
            ArgosError::Invalid(format!(
                "metadata delta remove target does not exist: {path}"
            ))
        }),
        serde_json::Value::Array(items) => {
            let index = key.parse::<usize>().map_err(|_| {
                ArgosError::Invalid(format!("metadata delta array index is invalid: {key}"))
            })?;
            if index >= items.len() {
                return Err(ArgosError::Invalid(format!(
                    "metadata delta array index out of bounds: {index}"
                )));
            }
            items.remove(index);
            Ok(())
        }
        _ => Err(ArgosError::Invalid(format!(
            "metadata delta parent is not a container: {parent_path}"
        ))),
    }
}

fn get_json_pointer_mut<'a>(
    value: &'a mut serde_json::Value,
    path: &str,
) -> Option<&'a mut serde_json::Value> {
    if path.is_empty() {
        return Some(value);
    }
    value.pointer_mut(path)
}

fn push_json_pointer(path: &str, key: &str) -> String {
    let escaped = key.replace('~', "~0").replace('/', "~1");
    if path.is_empty() {
        format!("/{escaped}")
    } else {
        format!("{path}/{escaped}")
    }
}

fn json_pointer_tokens(path: &str) -> Result<Vec<String>> {
    if path.is_empty() {
        return Ok(Vec::new());
    }
    if !path.starts_with('/') {
        return Err(ArgosError::Invalid(format!(
            "metadata delta path is not a JSON pointer: {path}"
        )));
    }
    path.split('/')
        .skip(1)
        .map(|part| Ok(part.replace("~1", "/").replace("~0", "~")))
        .collect()
}

fn json_pointer_from_tokens(tokens: &[String]) -> String {
    tokens
        .iter()
        .fold(String::new(), |path, token| push_json_pointer(&path, token))
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
