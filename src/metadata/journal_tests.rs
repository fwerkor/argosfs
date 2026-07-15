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
    prepare_metadata_integrity_with_previous(&mut divergent, original.integrity.meta_hash.clone())
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
