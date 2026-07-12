use super::*;

#[test]
fn journal_replay_recovers_transaction_after_power_loss_point() {
    let tmp = TempDir::new().unwrap();
    let fs = ArgosFs::create(tmp.path(), config(2, 2), 4, false).unwrap();
    fs.write_file("/crash", b"old", 0o644).unwrap();

    journal::set_thread_crash_point(Some("after-journal"));
    let err = fs
        .write_file("/crash", b"new-after-journal", 0o644)
        .unwrap_err();
    journal::set_thread_crash_point(None);
    assert_eq!(err.errno(), libc::EIO);
    drop(fs);

    let report = ArgosFs::audit_transactions(tmp.path()).unwrap();
    assert!(report.replayed);
    assert_eq!(report.invalid_entries, 0);

    let fs = ArgosFs::open(tmp.path()).unwrap();
    assert_eq!(fs.read_file("/crash", true).unwrap(), b"new-after-journal");
}

#[test]
fn normal_transactions_after_mkfs_are_delta_only_until_checkpoint() {
    let tmp = TempDir::new().unwrap();
    let fs = ArgosFs::create(tmp.path(), config(2, 2), 4, false).unwrap();
    fs.mkdir("/dir", 0o755).unwrap();
    fs.write_file("/dir/file.txt", b"delta journal", 0o644)
        .unwrap();
    drop(fs);

    let records = journal_records(tmp.path());
    assert_eq!(records[0]["record_type"], "checkpoint");
    assert!(records[0].get("metadata").is_some());

    for record in records.iter().skip(1) {
        assert_ne!(record["record_type"], "checkpoint");
        assert!(record.get("metadata").is_none());
        assert!(record.get("metadata_delta").is_some());
        assert!(record.get("meta_hash").is_some());
        assert!(record.get("previous_meta_hash").is_some());
        assert!(record.get("previous_record_hash").is_some());
    }
}

#[test]
fn checkpoint_record_is_written_at_configured_txid_interval() {
    let _guard = env_lock();
    let _interval = journal::thread_checkpoint_interval(4);
    let tmp = TempDir::new().unwrap();
    let fs = ArgosFs::create(tmp.path(), config(2, 2), 4, false).unwrap();
    let interval = journal::checkpoint_interval_txids();
    for index in 1..=interval {
        fs.mkdir(&format!("/dir-{index}"), 0o755).unwrap();
    }
    drop(fs);

    let records = journal_records(tmp.path());
    let checkpoint = records
        .iter()
        .find(|record| record["record_type"] == "checkpoint" && record["txid"] == interval)
        .expect("interval checkpoint exists");
    assert!(checkpoint.get("metadata").is_some());
}

#[test]
fn checkpoint_plus_deltas_reconstruct_latest_metadata_when_copies_are_behind() {
    let _guard = env_lock();
    let _interval = journal::thread_checkpoint_interval(4);
    let tmp = TempDir::new().unwrap();
    let fs = ArgosFs::create(tmp.path(), config(2, 2), 4, false).unwrap();
    let interval = journal::checkpoint_interval_txids();
    for index in 1..=interval {
        fs.mkdir(&format!("/checkpoint-base-{index}"), 0o755)
            .unwrap();
    }
    fs.write_file("/after-checkpoint-a", b"first delta", 0o644)
        .unwrap();
    fs.mkdir("/after-checkpoint-b", 0o755).unwrap();
    let expected_txid = fs.metadata_snapshot().txid;
    drop(fs);

    let records = journal_records(tmp.path());
    let checkpoint_metadata = records
        .iter()
        .find(|record| record["record_type"] == "checkpoint" && record["txid"] == interval)
        .and_then(|record| record.get("metadata"))
        .expect("checkpoint metadata");
    let checkpoint_bytes = serde_json::to_vec_pretty(checkpoint_metadata).unwrap();
    for name in ["meta.primary.json", "meta.secondary.json", "meta.json"] {
        fs::write(tmp.path().join(".argosfs").join(name), &checkpoint_bytes).unwrap();
    }

    let report = ArgosFs::audit_transactions(tmp.path()).unwrap();
    assert!(report.replayed);

    let fs = ArgosFs::open(tmp.path()).unwrap();
    assert_eq!(fs.metadata_snapshot().txid, expected_txid);
    assert_eq!(
        fs.read_file("/after-checkpoint-a", true).unwrap(),
        b"first delta"
    );
    assert!(fs.resolve_path("/after-checkpoint-b", false).is_ok());
}

#[test]
fn old_style_full_snapshot_journal_record_remains_recoverable() {
    #[derive(Serialize)]
    struct LegacyJournalRecord {
        version: u32,
        time: f64,
        volume_uuid: String,
        txid: u64,
        generation: u64,
        action: String,
        details: serde_json::Value,
        previous_record_hash: String,
        previous_meta_hash: String,
        meta_hash: String,
        metadata: Option<Metadata>,
        record_hash: String,
    }

    let tmp = TempDir::new().unwrap();
    let fs = ArgosFs::create(tmp.path(), config(2, 2), 4, false).unwrap();
    let uuid = fs.metadata_snapshot().uuid;
    drop(fs);

    let current = journal_records(tmp.path()).remove(0);
    let mut legacy = LegacyJournalRecord {
        version: current["version"].as_u64().unwrap() as u32,
        time: current["time"].as_f64().unwrap(),
        volume_uuid: current["volume_uuid"].as_str().unwrap().to_string(),
        txid: current["txid"].as_u64().unwrap(),
        generation: current["generation"].as_u64().unwrap(),
        action: current["action"].as_str().unwrap().to_string(),
        details: current["details"].clone(),
        previous_record_hash: current["previous_record_hash"]
            .as_str()
            .unwrap()
            .to_string(),
        previous_meta_hash: current["previous_meta_hash"].as_str().unwrap().to_string(),
        meta_hash: current["meta_hash"].as_str().unwrap().to_string(),
        metadata: Some(serde_json::from_value(current["metadata"].clone()).unwrap()),
        record_hash: String::new(),
    };
    legacy.record_hash = sha256_hex(&serde_json::to_vec_pretty(&legacy).unwrap());
    fs::write(
        tmp.path().join(".argosfs/journal.jsonl"),
        format!("{}\n", serde_json::to_string(&legacy).unwrap()),
    )
    .unwrap();
    for name in ["meta.primary.json", "meta.secondary.json", "meta.json"] {
        fs::remove_file(tmp.path().join(".argosfs").join(name)).unwrap();
    }

    let report = ArgosFs::audit_transactions(tmp.path()).unwrap();
    assert!(report.replayed);
    let fs = ArgosFs::open(tmp.path()).unwrap();
    assert_eq!(fs.metadata_snapshot().uuid, uuid);
}

#[test]
fn corrupt_delta_suffix_falls_back_to_checkpoint_state() {
    let _guard = env_lock();
    let _interval = journal::thread_checkpoint_interval(4);
    let tmp = TempDir::new().unwrap();
    let fs = ArgosFs::create(tmp.path(), config(2, 2), 4, false).unwrap();
    let interval = journal::checkpoint_interval_txids();
    for index in 1..=interval {
        fs.mkdir(&format!("/stable-{index}"), 0o755).unwrap();
    }
    fs.write_file("/lost-to-corrupt-delta", b"tail", 0o644)
        .unwrap();
    drop(fs);

    let mut records = journal_records(tmp.path());
    let checkpoint_metadata = records
        .iter()
        .find(|record| record["record_type"] == "checkpoint" && record["txid"] == interval)
        .and_then(|record| record.get("metadata"))
        .expect("checkpoint metadata")
        .clone();
    let delta = records
        .iter_mut()
        .find(|record| record["txid"] == interval + 1)
        .expect("post-checkpoint delta");
    delta["metadata_delta"] = serde_json::json!([]);
    let text = records
        .into_iter()
        .map(|record| serde_json::to_string(&record).unwrap())
        .collect::<Vec<_>>()
        .join("\n");
    fs::write(
        tmp.path().join(".argosfs/journal.jsonl"),
        format!("{text}\n"),
    )
    .unwrap();

    let checkpoint_bytes = serde_json::to_vec_pretty(&checkpoint_metadata).unwrap();
    for name in ["meta.primary.json", "meta.secondary.json", "meta.json"] {
        fs::write(tmp.path().join(".argosfs").join(name), &checkpoint_bytes).unwrap();
    }

    let report = ArgosFs::audit_transactions(tmp.path()).unwrap();
    assert!(report.invalid_entries >= 1);

    let fs = ArgosFs::open(tmp.path()).unwrap();
    assert!(fs
        .resolve_path(&format!("/stable-{interval}"), false)
        .is_ok());
    assert!(fs.resolve_path("/lost-to-corrupt-delta", false).is_err());
}

#[test]
fn ordinary_delta_journal_growth_stays_below_full_metadata_size_between_checkpoints() {
    let tmp = TempDir::new().unwrap();
    let fs = ArgosFs::create(tmp.path(), config(2, 2), 4, false).unwrap();
    for index in 1..64 {
        fs.mkdir(&format!("/size-{index}"), 0o755).unwrap();
    }
    drop(fs);

    let journal_text = fs::read_to_string(tmp.path().join(".argosfs/journal.jsonl")).unwrap();
    let max_delta_line = journal_text
        .lines()
        .filter(|line| line.contains(r#""metadata_delta""#))
        .map(str::len)
        .max()
        .expect("delta records exist");
    let metadata_size = fs::metadata(tmp.path().join(".argosfs/meta.primary.json"))
        .unwrap()
        .len() as usize;

    assert!(
        max_delta_line * 2 < metadata_size,
        "largest delta line {max_delta_line} should stay well below full metadata {metadata_size}"
    );
}

#[test]
fn checkpoint_compaction_bounds_host_journal_growth_and_preserves_replay() {
    let tmp = TempDir::new().unwrap();
    let _interval = journal::thread_checkpoint_interval(4);
    let fs = ArgosFs::create(tmp.path(), config(2, 2), 4, false).unwrap();

    for index in 1..11 {
        fs.mkdir(&format!("/compact-{index}"), 0o755).unwrap();
    }
    drop(fs);

    let journal_text = fs::read_to_string(tmp.path().join(".argosfs/journal.jsonl")).unwrap();
    let lines: Vec<&str> = journal_text.lines().collect();
    assert!(
        lines.len() <= 4,
        "compacted journal should only retain the latest checkpoint plus suffix, got {} lines",
        lines.len()
    );
    let first: serde_json::Value =
        serde_json::from_str(lines.first().expect("journal line")).unwrap();
    assert_eq!(first["record_type"], "checkpoint");
    assert_eq!(first["previous_record_hash"], "");
    assert!(first.get("metadata").is_some());

    let report = ArgosFs::audit_transactions(tmp.path()).unwrap();
    assert_eq!(report.invalid_entries, 0);
    assert!(report.latest_snapshot_txid >= 8);

    for name in ["meta.primary.json", "meta.secondary.json", "meta.json"] {
        fs::remove_file(tmp.path().join(".argosfs").join(name)).unwrap();
    }
    let reopened = ArgosFs::open(tmp.path()).unwrap();
    assert!(reopened.resolve_path("/compact-10", false).is_ok());
}

#[test]
fn manual_journal_compaction_rebases_hash_chain() {
    let tmp = TempDir::new().unwrap();
    let _interval = journal::thread_checkpoint_interval(4);
    let disable_compaction = journal::thread_journal_compaction_disabled(true);
    let fs = ArgosFs::create(tmp.path(), config(2, 2), 4, false).unwrap();

    for index in 1..10 {
        fs.mkdir(&format!("/manual-compact-{index}"), 0o755)
            .unwrap();
    }
    drop(fs);

    let before = fs::read_to_string(tmp.path().join(".argosfs/journal.jsonl")).unwrap();
    assert!(before.lines().count() > 4);

    drop(disable_compaction);
    journal::compact_journal(tmp.path()).unwrap();

    let after = fs::read_to_string(tmp.path().join(".argosfs/journal.jsonl")).unwrap();
    assert!(after.lines().count() <= 3);
    let report = ArgosFs::audit_transactions(tmp.path()).unwrap();
    assert_eq!(report.invalid_entries, 0);

    for name in ["meta.primary.json", "meta.secondary.json", "meta.json"] {
        fs::remove_file(tmp.path().join(".argosfs").join(name)).unwrap();
    }
    let reopened = ArgosFs::open(tmp.path()).unwrap();
    assert!(reopened.resolve_path("/manual-compact-9", false).is_ok());
}

#[test]
fn before_journal_write_failure_rolls_back_live_metadata() {
    let tmp = TempDir::new().unwrap();
    let fs = ArgosFs::create(tmp.path(), config(2, 2), 4, false).unwrap();
    fs.write_file("/crash", b"old", 0o644).unwrap();

    journal::set_thread_crash_point(Some("before-journal"));
    let err = fs
        .write_file("/crash", b"new-before-journal", 0o644)
        .unwrap_err();
    journal::set_thread_crash_point(None);
    assert_eq!(err.errno(), libc::EIO);
    assert_eq!(fs.read_file("/crash", true).unwrap(), b"old");
    assert!(fs.fsck(true, true).unwrap().errors.is_empty());
    drop(fs);

    let fs = ArgosFs::open(tmp.path()).unwrap();
    assert_eq!(fs.read_file("/crash", true).unwrap(), b"old");
}

#[test]
fn metadata_copy_crash_points_recover_committed_transaction() {
    for point in [
        "after-primary-metadata",
        "after-secondary-metadata",
        "after-compatible-metadata",
    ] {
        let tmp = TempDir::new().unwrap();
        let fs = ArgosFs::create(tmp.path(), config(2, 2), 4, false).unwrap();
        fs.write_file("/crash", b"old", 0o644).unwrap();

        journal::set_thread_crash_point(Some(point));
        let err = fs
            .write_file("/crash", format!("new-{point}").as_bytes(), 0o644)
            .unwrap_err();
        journal::set_thread_crash_point(None);
        assert_eq!(err.errno(), libc::EIO);
        drop(fs);

        let fs = ArgosFs::open(tmp.path()).unwrap();
        assert_eq!(
            fs.read_file("/crash", true).unwrap(),
            format!("new-{point}").as_bytes()
        );
        assert!(fs.fsck(true, true).unwrap().errors.is_empty());
    }
}

#[test]
fn double_write_metadata_detection_repairs_corrupt_copy() {
    let tmp = TempDir::new().unwrap();
    let fs = ArgosFs::create(tmp.path(), config(2, 2), 4, false).unwrap();
    fs.write_file("/safe", b"metadata mirrors", 0o644).unwrap();
    drop(fs);

    fs::write(tmp.path().join(".argosfs/meta.primary.json"), b"{not-json").unwrap();
    let report = ArgosFs::audit_transactions(tmp.path()).unwrap();
    assert!(report.double_write_mismatches >= 1);
    assert!(report
        .metadata_candidates
        .iter()
        .any(|candidate| candidate.present && !candidate.valid));

    let fs = ArgosFs::open(tmp.path()).unwrap();
    assert_eq!(fs.read_file("/safe", true).unwrap(), b"metadata mirrors");
    assert_eq!(
        ArgosFs::audit_transactions(tmp.path())
            .unwrap()
            .double_write_mismatches,
        0
    );
}

#[test]
fn transaction_verifier_flags_bad_journal_tail_without_losing_data() {
    let tmp = TempDir::new().unwrap();
    let fs = ArgosFs::create(tmp.path(), config(2, 2), 4, false).unwrap();
    fs.write_file("/journal", b"hash chain", 0o644).unwrap();
    drop(fs);

    let mut journal = fs::OpenOptions::new()
        .append(true)
        .open(tmp.path().join(".argosfs/journal.jsonl"))
        .unwrap();
    writeln!(journal, "{{bad-json").unwrap();
    journal.sync_all().unwrap();

    let report = ArgosFs::audit_transactions(tmp.path()).unwrap();
    assert!(report.invalid_entries >= 1);
    assert!(report.valid_entries >= 2);

    let fs = ArgosFs::open(tmp.path()).unwrap();
    assert_eq!(fs.read_file("/journal", true).unwrap(), b"hash chain");
}

#[test]
fn journal_replay_skips_invalid_snapshot_records() {
    let tmp = TempDir::new().unwrap();
    let fs = ArgosFs::create(tmp.path(), config(2, 2), 4, false).unwrap();
    fs.write_file("/journal", b"snapshot skip", 0o644).unwrap();
    drop(fs);

    let mut journal = fs::OpenOptions::new()
        .append(true)
        .open(tmp.path().join(".argosfs/journal.jsonl"))
        .unwrap();
    writeln!(
        journal,
        r#"{{"version":1,"txid":999,"metadata":{{"format":"broken"}},"record_hash":"bad"}}"#
    )
    .unwrap();
    journal.sync_all().unwrap();

    let fs = ArgosFs::open(tmp.path()).unwrap();
    assert_eq!(fs.read_file("/journal", true).unwrap(), b"snapshot skip");
}

#[test]
fn verify_journal_cli_exits_nonzero_for_invalid_journal() {
    let tmp = TempDir::new().unwrap();
    let fs = ArgosFs::create(tmp.path(), config(2, 2), 4, false).unwrap();
    fs.write_file("/journal", b"hash chain", 0o644).unwrap();
    drop(fs);

    let mut journal = fs::OpenOptions::new()
        .append(true)
        .open(tmp.path().join(".argosfs/journal.jsonl"))
        .unwrap();
    writeln!(journal, "{{bad-json").unwrap();
    journal.sync_all().unwrap();

    let status = Command::new(argosfs_binary())
        .arg("verify-journal")
        .arg(tmp.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(!status.success());
}
