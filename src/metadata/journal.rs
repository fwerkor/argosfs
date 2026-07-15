use crate::error::{ArgosError, Result};
use crate::types::{
    Metadata, MetadataCandidateReport, MetadataIntegrity, TransactionReport, FORMAT_VERSION,
};
use crate::util::{append_json_line, atomic_write, now_f64, read_to_vec, sha256_hex, FileLock};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::cell::{Cell, RefCell};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

const JOURNAL_VERSION: u32 = 1;
pub const DEFAULT_CHECKPOINT_INTERVAL_TXIDS: u64 = 128;
const CHECKPOINT_INTERVAL_ENV: &str = "ARGOSFS_CHECKPOINT_INTERVAL_TXIDS";
const JOURNAL_COMPACTION_ENV: &str = "ARGOSFS_DISABLE_JOURNAL_COMPACTION";
const PRIMARY_META: &str = "meta.primary.json";
const SECONDARY_META: &str = "meta.secondary.json";
const COMPAT_META: &str = "meta.json";

thread_local! {
    static THREAD_CRASH_POINT: RefCell<Option<String>> = const { RefCell::new(None) };
    static THREAD_CHECKPOINT_INTERVAL: Cell<Option<u64>> = const { Cell::new(None) };
    static THREAD_COMPACTION_DISABLED: Cell<Option<bool>> = const { Cell::new(None) };
}

pub struct ThreadCrashPointGuard {
    previous: Option<String>,
}

impl Drop for ThreadCrashPointGuard {
    fn drop(&mut self) {
        THREAD_CRASH_POINT.with(|value| {
            *value.borrow_mut() = self.previous.take();
        });
    }
}

pub struct ThreadCheckpointIntervalGuard {
    previous: Option<u64>,
}

impl Drop for ThreadCheckpointIntervalGuard {
    fn drop(&mut self) {
        THREAD_CHECKPOINT_INTERVAL.with(|value| value.set(self.previous));
    }
}

pub struct ThreadCompactionGuard {
    previous: Option<bool>,
}

impl Drop for ThreadCompactionGuard {
    fn drop(&mut self) {
        THREAD_COMPACTION_DISABLED.with(|value| value.set(self.previous));
    }
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
    let report = scan(root)?;
    let metadata_copy = latest_metadata_copy(root)?;
    let previous_metadata = match metadata_copy {
        Some(metadata) if metadata.txid >= report.last_valid_txid => metadata,
        _ => latest_recoverable_metadata(root)?,
    };
    if let Some(expected) = expected_previous_txid {
        if previous_metadata.txid > expected {
            return Err(ArgosError::Conflict(format!(
                "volume advanced from txid {expected} to {}; reopen and retry",
                previous_metadata.txid
            )));
        }
    }
    inject_crash("before-journal")?;
    let previous_meta_hash = if meta.integrity.meta_hash.is_empty() {
        canonical_metadata_hash(meta)?
    } else {
        meta.integrity.meta_hash.clone()
    };
    prepare_metadata_integrity(meta, previous_meta_hash)?;
    let previous_record_hash = report.last_valid_record_hash;
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
    write_metadata_copies_with_injection(root, meta)?;
    if should_checkpoint {
        // Journal compaction is maintenance work after the transaction is already
        // durable in the journal and in the metadata copies.  A compaction
        // failure must not turn a committed filesystem operation into a
        // user-visible failure; the uncompacted journal is still valid.
        let _ = compact_journal_unlocked(root);
    }
    Ok(())
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

pub fn compact_journal(root: &Path) -> Result<()> {
    let _lock = FileLock::exclusive(&transaction_lock_path(root))?;
    compact_journal_unlocked(root)
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

pub fn prepare_metadata_integrity_for_external_store(meta: &mut Metadata) -> Result<()> {
    prepare_metadata_integrity(meta, String::new())
}

pub fn prepare_metadata_integrity_with_previous(
    meta: &mut Metadata,
    previous_meta_hash: String,
) -> Result<()> {
    prepare_metadata_integrity(meta, previous_meta_hash)
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

pub fn thread_crash_point(point: &str) -> ThreadCrashPointGuard {
    let previous = THREAD_CRASH_POINT.with(|value| value.replace(Some(point.to_string())));
    ThreadCrashPointGuard { previous }
}

pub fn thread_checkpoint_interval(interval: u64) -> ThreadCheckpointIntervalGuard {
    let previous = THREAD_CHECKPOINT_INTERVAL.with(|value| value.replace(Some(interval.max(1))));
    ThreadCheckpointIntervalGuard { previous }
}

pub fn thread_journal_compaction_disabled(disabled: bool) -> ThreadCompactionGuard {
    let previous = THREAD_COMPACTION_DISABLED.with(|value| value.replace(Some(disabled)));
    ThreadCompactionGuard { previous }
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

fn compact_journal_unlocked(root: &Path) -> Result<()> {
    if journal_compaction_disabled() {
        return Ok(());
    }
    let journal = journal_path(root);
    let Ok(text) = fs::read_to_string(&journal) else {
        return Ok(());
    };
    let records = valid_journal_chain_records(&text)?;
    let Some(checkpoint_index) = records
        .iter()
        .rposition(|record| record.record_type.is_checkpoint() && record.metadata.is_some())
    else {
        return Ok(());
    };
    let mut compacted = records[checkpoint_index..].to_vec();
    let mut previous_hash = String::new();
    for record in &mut compacted {
        record.previous_record_hash = previous_hash;
        record.record_hash.clear();
        record.record_hash = record_hash(record)?;
        previous_hash = record.record_hash.clone();
    }

    let mut bytes = Vec::new();
    for record in &compacted {
        serde_json::to_writer(&mut bytes, record)?;
        bytes.push(b'\n');
    }
    atomic_write(&journal, &bytes)
}

fn valid_journal_chain_records(text: &str) -> Result<Vec<JournalRecord>> {
    let mut records = Vec::new();
    let mut previous_hash = String::new();
    for raw in text.lines() {
        if raw.trim().is_empty() {
            continue;
        }
        let Ok(value) = serde_json::from_str::<serde_json::Value>(raw) else {
            continue;
        };
        let Ok(record) = serde_json::from_value::<JournalRecord>(value.clone()) else {
            continue;
        };
        if record.record_hash.is_empty() {
            continue;
        }
        let valid_hash = match record_hash_is_valid(&value, &record) {
            Ok(valid) => valid,
            Err(_) => continue,
        };
        if !valid_hash || record.previous_record_hash != previous_hash {
            continue;
        }
        previous_hash = record.record_hash.clone();
        records.push(record);
    }
    Ok(records)
}

fn journal_compaction_disabled() -> bool {
    THREAD_COMPACTION_DISABLED
        .with(|value| value.get())
        .unwrap_or_else(|| {
            std::env::var(JOURNAL_COMPACTION_ENV)
                .ok()
                .is_some_and(|value| matches!(value.as_str(), "1" | "true" | "yes" | "on"))
        })
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
    let mut best = latest_metadata_copy(root)?;
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

fn latest_metadata_copy(root: &Path) -> Result<Option<Metadata>> {
    Ok(read_metadata_candidates(root)
        .into_iter()
        .filter_map(|candidate| candidate.metadata)
        .max_by(|left, right| metadata_order(left).cmp(&metadata_order(right))))
}

fn should_write_checkpoint(root: &Path, txid: u64) -> Result<bool> {
    Ok(!has_valid_checkpoint(root)? || txid.is_multiple_of(checkpoint_interval_txids()))
}

pub fn checkpoint_interval_txids() -> u64 {
    THREAD_CHECKPOINT_INTERVAL
        .with(|value| value.get())
        .unwrap_or_else(|| {
            std::env::var(CHECKPOINT_INTERVAL_ENV)
                .ok()
                .and_then(|value| value.parse::<u64>().ok())
                .filter(|value| *value > 0)
                .unwrap_or(DEFAULT_CHECKPOINT_INTERVAL_TXIDS)
        })
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

pub fn metadata_delta(previous: &Metadata, next: &Metadata) -> Result<Vec<MetadataDeltaOp>> {
    let previous = serde_json::to_value(previous)?;
    let next = serde_json::to_value(next)?;
    let mut ops = Vec::new();
    diff_json("", &previous, &next, &mut ops);
    Ok(ops)
}

pub fn apply_metadata_delta(previous: &Metadata, delta: &[MetadataDeltaOp]) -> Result<Metadata> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::VolumeConfig;
    use crate::volume::ArgosFs;
    use std::sync::{Mutex, OnceLock};
    use tempfile::tempdir;

    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(())).lock().unwrap()
    }

    fn volume() -> (tempfile::TempDir, ArgosFs) {
        let dir = tempdir().unwrap();
        let fs = ArgosFs::create(
            dir.path(),
            VolumeConfig {
                k: 1,
                m: 0,
                ..VolumeConfig::default()
            },
            1,
            false,
        )
        .unwrap();
        (dir, fs)
    }

    #[test]
    fn thread_guards_restore_crash_checkpoint_and_compaction_settings() {
        let _guard = env_lock();
        std::env::remove_var("ARGOSFS_CRASH_POINT");
        std::env::remove_var(CHECKPOINT_INTERVAL_ENV);
        std::env::remove_var(JOURNAL_COMPACTION_ENV);
        set_thread_crash_point(None);
        assert!(inject_crash("point").is_ok());
        {
            let _outer = thread_crash_point("other, point");
            assert!(matches!(
                inject_crash("point"),
                Err(ArgosError::InjectedCrash(_))
            ));
            {
                let _inner = thread_crash_point("all");
                assert!(inject_crash("anything").is_err());
            }
            assert!(inject_crash("anything").is_ok());
        }
        assert!(inject_crash("point").is_ok());

        assert_eq!(
            checkpoint_interval_txids(),
            DEFAULT_CHECKPOINT_INTERVAL_TXIDS
        );
        {
            let _outer = thread_checkpoint_interval(0);
            assert_eq!(checkpoint_interval_txids(), 1);
            {
                let _inner = thread_checkpoint_interval(7);
                assert_eq!(checkpoint_interval_txids(), 7);
            }
            assert_eq!(checkpoint_interval_txids(), 1);
        }
        std::env::set_var(CHECKPOINT_INTERVAL_ENV, "9");
        assert_eq!(checkpoint_interval_txids(), 9);
        std::env::set_var(CHECKPOINT_INTERVAL_ENV, "0");
        assert_eq!(
            checkpoint_interval_txids(),
            DEFAULT_CHECKPOINT_INTERVAL_TXIDS
        );
        std::env::set_var(CHECKPOINT_INTERVAL_ENV, "invalid");
        assert_eq!(
            checkpoint_interval_txids(),
            DEFAULT_CHECKPOINT_INTERVAL_TXIDS
        );

        assert!(!journal_compaction_disabled());
        {
            let _outer = thread_journal_compaction_disabled(true);
            assert!(journal_compaction_disabled());
            {
                let _inner = thread_journal_compaction_disabled(false);
                assert!(!journal_compaction_disabled());
            }
            assert!(journal_compaction_disabled());
        }
        for value in ["1", "true", "yes", "on"] {
            std::env::set_var(JOURNAL_COMPACTION_ENV, value);
            assert!(journal_compaction_disabled());
        }
        std::env::set_var(JOURNAL_COMPACTION_ENV, "false");
        assert!(!journal_compaction_disabled());
        std::env::remove_var("ARGOSFS_CRASH_POINT");
        std::env::remove_var(CHECKPOINT_INTERVAL_ENV);
        std::env::remove_var(JOURNAL_COMPACTION_ENV);
    }

    #[test]
    fn json_pointer_helpers_cover_object_array_root_and_invalid_paths() {
        let mut value = json!({"object": {"a/b": 1, "til~de": 2}, "array": [10, 20], "scalar": 1});
        assert_eq!(push_json_pointer("", "a/b~c"), "/a~1b~0c");
        assert_eq!(json_pointer_tokens("/a~1b~0c").unwrap(), ["a/b~c"]);
        assert_eq!(json_pointer_from_tokens(&["a/b~c".to_string()]), "/a~1b~0c");
        assert!(json_pointer_tokens("not-a-pointer").is_err());
        assert!(get_json_pointer_mut(&mut value, "").is_some());
        assert!(get_json_pointer_mut(&mut value, "/missing").is_none());

        set_json_pointer(&mut value, "/object/new", json!(3)).unwrap();
        set_json_pointer(&mut value, "/array/2", json!(30)).unwrap();
        set_json_pointer(&mut value, "/array/1", json!(21)).unwrap();
        assert_eq!(value["object"]["new"], 3);
        assert_eq!(value["array"], json!([10, 21, 30]));
        assert!(set_json_pointer(&mut value, "/array/bad", json!(0)).is_err());
        assert!(set_json_pointer(&mut value, "/array/99", json!(0)).is_err());
        assert!(set_json_pointer(&mut value, "/missing/child", json!(0)).is_err());
        assert!(set_json_pointer(&mut value, "/scalar/child", json!(0)).is_err());

        remove_json_pointer(&mut value, "/object/new").unwrap();
        remove_json_pointer(&mut value, "/array/0").unwrap();
        assert!(value["object"].get("new").is_none());
        assert_eq!(value["array"], json!([21, 30]));
        assert!(remove_json_pointer(&mut value, "/object/missing").is_err());
        assert!(remove_json_pointer(&mut value, "/array/bad").is_err());
        assert!(remove_json_pointer(&mut value, "/array/99").is_err());
        assert!(remove_json_pointer(&mut value, "/missing/child").is_err());
        assert!(remove_json_pointer(&mut value, "/scalar/child").is_err());

        let mut root = json!({"a": 1});
        set_json_pointer(&mut root, "", json!([1, 2])).unwrap();
        assert_eq!(root, json!([1, 2]));
        remove_json_pointer(&mut root, "").unwrap();
        assert!(root.is_null());
    }

    #[test]
    fn delta_ops_apply_add_replace_remove_and_report_missing_targets() {
        let mut value = json!({"object": {"old": 1}, "array": [1, 2]});
        apply_delta_op(
            &mut value,
            &MetadataDeltaOp::Add {
                path: "/object/new".to_string(),
                value: json!(2),
            },
        )
        .unwrap();
        apply_delta_op(
            &mut value,
            &MetadataDeltaOp::Replace {
                path: "/object/old".to_string(),
                value: json!(3),
            },
        )
        .unwrap();
        apply_delta_op(
            &mut value,
            &MetadataDeltaOp::Remove {
                path: "/array/0".to_string(),
            },
        )
        .unwrap();
        assert_eq!(value, json!({"object": {"old": 3, "new": 2}, "array": [2]}));
        assert!(apply_delta_op(
            &mut value,
            &MetadataDeltaOp::Replace {
                path: "/missing".to_string(),
                value: json!(0),
            }
        )
        .is_err());
        apply_delta_op(
            &mut value,
            &MetadataDeltaOp::Replace {
                path: String::new(),
                value: json!("root"),
            },
        )
        .unwrap();
        assert_eq!(value, json!("root"));
    }

    #[test]
    fn metadata_delta_round_trip_handles_add_remove_replace_and_escaped_keys() {
        let (_dir, fs) = volume();
        let previous = fs.metadata_snapshot();
        let mut next = previous.clone();
        next.txid += 1;
        next.config.fsname = "changed".to_string();
        let mut escaped_disk = next.disks.values().next().unwrap().clone();
        escaped_disk.id = "a/b~c".to_string();
        next.disks.insert("a/b~c".to_string(), escaped_disk);
        prepare_metadata_integrity_with_previous(&mut next, previous.integrity.meta_hash.clone())
            .unwrap();
        let delta = metadata_delta(&previous, &next).unwrap();
        assert!(!delta.is_empty());
        assert!(delta.iter().any(|op| match op {
            MetadataDeltaOp::Add { path, .. }
            | MetadataDeltaOp::Remove { path }
            | MetadataDeltaOp::Replace { path, .. } => path.contains("a~1b~0c"),
        }));
        let applied = apply_metadata_delta(&previous, &delta).unwrap();
        assert_eq!(applied.txid, next.txid);
        assert_eq!(applied.config.fsname, "changed");
        assert_eq!(applied.disks["a/b~c"].id, "a/b~c");
        assert_eq!(
            canonical_metadata_hash(&applied).unwrap(),
            canonical_metadata_hash(&next).unwrap()
        );

        assert!(apply_metadata_delta(
            &previous,
            &[MetadataDeltaOp::Replace {
                path: "/missing".to_string(),
                value: json!(1),
            }]
        )
        .is_err());
    }

    #[test]
    fn initialized_volume_scans_appends_events_transactions_and_conflicts() {
        let (dir, fs) = volume();
        let root = dir.path();
        let initial = scan(root).unwrap();
        assert_eq!(initial.valid_entries, 1);
        assert_eq!(initial.latest_snapshot_txid, fs.metadata_snapshot().txid);
        assert!(has_valid_checkpoint(root).unwrap());
        assert!(!should_write_checkpoint(root, 1).unwrap());

        let mut meta = fs.metadata_snapshot();
        append_event(root, &meta, "audit", json!({"ok": true})).unwrap();
        let after_event = scan(root).unwrap();
        assert_eq!(after_event.valid_entries, 2);
        assert_eq!(after_event.last_valid_txid, meta.txid);

        meta.txid += 1;
        prepare_metadata_integrity_with_previous(
            &mut meta,
            fs.metadata_snapshot().integrity.meta_hash.clone(),
        )
        .unwrap();
        let _interval = thread_checkpoint_interval(2);
        let _compact = thread_journal_compaction_disabled(true);
        let txid = meta.txid;
        append_transaction(root, &mut meta, "update", json!({"txid": txid})).unwrap();
        let report = scan(root).unwrap();
        assert_eq!(report.last_valid_txid, meta.txid);
        assert!(report.valid_entries >= 3);
        assert!(should_write_checkpoint(root, 2).unwrap());

        let mut stale = meta.clone();
        stale.txid += 1;
        assert!(matches!(
            append_transaction_checked(root, &mut stale, Some(0), "stale", json!({})),
            Err(ArgosError::Conflict(_))
        ));
    }

    #[test]
    fn scan_counts_invalid_json_records_hashes_chains_snapshots_and_legacy_lines() {
        let (dir, fs) = volume();
        let root = dir.path();
        let mut meta = fs.metadata_snapshot();
        meta.txid += 1;
        prepare_metadata_integrity_with_previous(
            &mut meta,
            fs.metadata_snapshot().integrity.meta_hash.clone(),
        )
        .unwrap();
        let valid = build_record(
            &meta,
            BuildRecordOptions {
                record_type: JournalRecordKind::Checkpoint,
                action: "valid".to_string(),
                details: json!({}),
                previous_record_hash: String::new(),
                time: 1.0,
                metadata: Some(meta.clone()),
                metadata_delta: None,
            },
        )
        .unwrap();
        let mut bad_hash = valid.clone();
        bad_hash.record_hash = "bad".to_string();
        let mut bad_chain = valid.clone();
        bad_chain.previous_record_hash = "wrong".to_string();
        bad_chain.record_hash = record_hash(&bad_chain).unwrap();
        let mut bad_snapshot = valid.clone();
        bad_snapshot.meta_hash = "wrong".to_string();
        bad_snapshot.record_hash = record_hash(&bad_snapshot).unwrap();
        let legacy = JournalRecord {
            txid: 99,
            action: "legacy".to_string(),
            ..JournalRecord::default()
        };
        let journal = journal_path(root);
        let mut bytes = b"not-json\n".to_vec();
        bytes.extend_from_slice(b"{\"txid\":\"bad\"}\n");
        for record in [&legacy, &bad_hash, &bad_chain, &bad_snapshot, &valid] {
            serde_json::to_writer(&mut bytes, record).unwrap();
            bytes.push(b'\n');
        }
        atomic_write(&journal, &bytes).unwrap();
        let report = scan(root).unwrap();
        assert_eq!(report.legacy_entries, 1);
        assert_eq!(report.valid_entries, 2);
        assert!(report.invalid_entries >= 4);
        assert!(report
            .errors
            .iter()
            .any(|error| error.contains("invalid JSON")));
        assert!(report
            .errors
            .iter()
            .any(|error| error.contains("invalid record")));
        assert!(report
            .errors
            .iter()
            .any(|error| error.contains("record hash mismatch")));
        assert!(report
            .errors
            .iter()
            .any(|error| error.contains("previous record hash mismatch")));
        assert!(report
            .errors
            .iter()
            .any(|error| error.contains("metadata snapshot hash mismatch")));
    }

    #[test]
    fn candidate_recovery_repairs_missing_corrupt_and_divergent_copies() {
        let (dir, fs) = volume();
        let root = dir.path();
        let system = root.join(".argosfs");
        let original = fs.metadata_snapshot();
        fs::write(system.join(PRIMARY_META), b"{").unwrap();
        fs::remove_file(system.join(SECONDARY_META)).unwrap();
        let recovered = load_or_recover(root).unwrap();
        assert_eq!(recovered.metadata.txid, original.txid);
        assert!(recovered
            .report
            .metadata_candidates
            .iter()
            .any(|item| !item.valid));
        assert!(recovered
            .report
            .metadata_candidates
            .iter()
            .any(|item| !item.present));
        assert!(recovered.report.double_write_mismatches > 0);
        for (_, path) in metadata_paths(root) {
            assert!(read_candidate("copy".to_string(), path).report.valid);
        }

        let mut divergent = original.clone();
        divergent.txid += 1;
        prepare_metadata_integrity_with_previous(
            &mut divergent,
            original.integrity.meta_hash.clone(),
        )
        .unwrap();
        atomic_write(
            &system.join(PRIMARY_META),
            &serde_json::to_vec_pretty(&divergent).unwrap(),
        )
        .unwrap();
        let candidates = read_metadata_candidates(root);
        assert!(double_write_mismatches(&candidates) > 0);
    }

    #[test]
    fn validation_hash_helpers_and_metadata_order_cover_legacy_and_mismatch_paths() {
        let (_dir, fs) = volume();
        let mut meta = fs.metadata_snapshot();
        let hash = canonical_metadata_hash(&meta).unwrap();
        assert_eq!(
            canonical_metadata_hash_bytes(&serde_json::to_vec(&meta).unwrap()).unwrap(),
            hash
        );
        assert_eq!(
            canonical_metadata_hash_value(&serde_json::to_value(&meta).unwrap()).unwrap(),
            hash
        );
        assert_eq!(
            metadata_order(&meta),
            (meta.txid, meta.integrity.generation)
        );

        let mut legacy = meta.clone();
        legacy.integrity = MetadataIntegrity::default();
        let legacy_hash = canonical_metadata_hash(&legacy).unwrap();
        validate_metadata(&mut legacy, &legacy_hash).unwrap();
        assert_eq!(legacy.integrity.meta_hash, legacy_hash);
        assert_eq!(legacy.integrity.generation, legacy.txid);

        meta.format = "unsupported-format".to_string();
        assert!(validate_metadata(&mut meta, &hash).is_err());
        meta.format = FORMAT_VERSION.to_string();
        meta.integrity.meta_hash = "wrong".to_string();
        assert!(validate_metadata(&mut meta, &hash).is_err());

        let mut empty = fs.metadata_snapshot();
        empty.integrity = MetadataIntegrity::default();
        ensure_integrity(&mut empty).unwrap();
        assert!(!empty.integrity.meta_hash.is_empty());
    }

    #[test]
    fn compaction_handles_missing_disabled_no_checkpoint_and_valid_checkpoint_chains() {
        let empty = tempdir().unwrap();
        compact_journal(empty.path()).unwrap();

        let (dir, fs) = volume();
        let root = dir.path();
        let original = fs::read_to_string(journal_path(root)).unwrap();
        {
            let _disabled = thread_journal_compaction_disabled(true);
            compact_journal(root).unwrap();
        }
        assert_eq!(fs::read_to_string(journal_path(root)).unwrap(), original);

        let mut event_only = fs.metadata_snapshot();
        let event = build_record(
            &event_only,
            BuildRecordOptions {
                record_type: JournalRecordKind::Event,
                action: "event".to_string(),
                details: json!({}),
                previous_record_hash: String::new(),
                time: 1.0,
                metadata: None,
                metadata_delta: None,
            },
        )
        .unwrap();
        let no_checkpoint = tempdir().unwrap();
        fs::create_dir_all(no_checkpoint.path().join(".argosfs")).unwrap();
        append_record(no_checkpoint.path(), &event).unwrap();
        compact_journal(no_checkpoint.path()).unwrap();
        assert_eq!(
            valid_journal_chain_records(
                &fs::read_to_string(journal_path(no_checkpoint.path())).unwrap()
            )
            .unwrap()
            .len(),
            1
        );

        event_only.txid += 1;
        prepare_metadata_integrity_with_previous(
            &mut event_only,
            fs.metadata_snapshot().integrity.meta_hash.clone(),
        )
        .unwrap();
        append_event(root, &event_only, "tail", json!({})).unwrap();
        compact_journal(root).unwrap();
        let records =
            valid_journal_chain_records(&fs::read_to_string(journal_path(root)).unwrap()).unwrap();
        assert!(!records.is_empty());
        assert!(records[0].record_type.is_checkpoint());
        assert!(records[0].previous_record_hash.is_empty());
    }

    #[test]
    fn valid_chain_filter_skips_blank_malformed_legacy_bad_hash_and_bad_links() {
        let (_dir, fs) = volume();
        let meta = fs.metadata_snapshot();
        let first = build_record(
            &meta,
            BuildRecordOptions {
                record_type: JournalRecordKind::Checkpoint,
                action: "first".to_string(),
                details: json!({}),
                previous_record_hash: String::new(),
                time: 1.0,
                metadata: Some(meta.clone()),
                metadata_delta: None,
            },
        )
        .unwrap();
        let second = build_record(
            &meta,
            BuildRecordOptions {
                record_type: JournalRecordKind::Event,
                action: "second".to_string(),
                details: json!({}),
                previous_record_hash: first.record_hash.clone(),
                time: 2.0,
                metadata: None,
                metadata_delta: None,
            },
        )
        .unwrap();
        let mut bad = second.clone();
        bad.record_hash = "bad".to_string();
        let mut wrong_link = second.clone();
        wrong_link.previous_record_hash = "wrong".to_string();
        wrong_link.record_hash = record_hash(&wrong_link).unwrap();
        let legacy = JournalRecord::default();
        let mut text = "\nnot-json\n[]\n".to_string();
        for record in [&legacy, &bad, &wrong_link, &first, &second] {
            text.push_str(&serde_json::to_string(record).unwrap());
            text.push('\n');
        }
        let records = valid_journal_chain_records(&text).unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].action, "first");
        assert_eq!(records[1].action, "second");
    }
}
