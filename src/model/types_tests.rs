use super::*;

#[test]
fn enum_string_conversions_cover_aliases_and_errors() {
    let fault_points = [
        FaultPoint::BeforeDataWrite,
        FaultPoint::AfterDataWriteBeforeFlush,
        FaultPoint::AfterDataFlushBeforeJournalCommit,
        FaultPoint::AfterJournalCommitBeforeMetadataCommit,
        FaultPoint::AfterMetadataCommitBeforeSuperblockUpdate,
        FaultPoint::AfterPartialJournalFanout,
        FaultPoint::DuringReplay,
    ];
    assert_eq!(fault_points[0].as_str(), "before-data-write");
    assert_eq!(fault_points[1].as_str(), "after-data-write-before-flush");
    assert_eq!(
        fault_points[2].as_str(),
        "after-data-flush-before-journal-commit"
    );
    assert_eq!(
        fault_points[3].as_str(),
        "after-journal-commit-before-metadata-commit"
    );
    assert_eq!(
        fault_points[4].as_str(),
        "after-metadata-commit-before-superblock-update"
    );
    assert_eq!(fault_points[5].as_str(), "after-partial-journal-fanout");
    assert_eq!(fault_points[6].as_str(), "during-replay");

    for (raw, expected) in [
        ("host", BackendKind::Host),
        ("HOSTFS", BackendKind::Host),
        ("loop", BackendKind::LoopBlock),
        ("loop-block", BackendKind::LoopBlock),
        ("loopblock", BackendKind::LoopBlock),
        ("raw", BackendKind::RawBlock),
        ("raw-block", BackendKind::RawBlock),
        ("rawblock", BackendKind::RawBlock),
    ] {
        assert_eq!(raw.parse::<BackendKind>().unwrap(), expected);
    }
    assert!("bad".parse::<BackendKind>().is_err());
    assert_eq!(BackendKind::Host.as_str(), "host");
    assert_eq!(BackendKind::LoopBlock.as_str(), "loop");
    assert_eq!(BackendKind::RawBlock.as_str(), "raw");

    for codec in [Compression::None, Compression::Lz4, Compression::Zstd] {
        assert_eq!(codec.as_str().parse::<Compression>().unwrap(), codec);
    }
    assert!("brotli".parse::<Compression>().is_err());

    for (raw, tier) in [
        ("hot", StorageTier::Hot),
        ("warm", StorageTier::Warm),
        ("cold", StorageTier::Cold),
    ] {
        assert_eq!(raw.parse::<StorageTier>().unwrap(), tier);
    }
    assert!("archive".parse::<StorageTier>().is_err());

    for status in [
        DiskStatus::Online,
        DiskStatus::Degraded,
        DiskStatus::Draining,
        DiskStatus::Failed,
        DiskStatus::Offline,
        DiskStatus::Removed,
    ] {
        let raw = serde_json::to_string(&status).unwrap();
        assert_eq!(serde_json::from_str::<DiskStatus>(&raw).unwrap(), status);
        assert_eq!(raw.trim_matches('"').parse::<DiskStatus>().unwrap(), status);
    }
    assert!("missing".parse::<DiskStatus>().is_err());

    for (raw, expected) in [
        ("buffered", IoMode::Buffered),
        ("direct", IoMode::Direct),
        ("io-uring", IoMode::IoUring),
        ("iouring", IoMode::IoUring),
    ] {
        assert_eq!(raw.parse::<IoMode>().unwrap(), expected);
    }
    assert!("sync".parse::<IoMode>().is_err());
}

#[test]
fn defaults_and_legacy_deserialization_are_stable() {
    let config = VolumeConfig::default();
    assert_eq!(config.k, 4);
    assert_eq!(config.m, 2);
    assert_eq!(config.chunk_size, 256 * 1024);
    assert_eq!(config.compression, Compression::Zstd);
    assert_eq!(
        config.deferred_commit_interval_ms,
        DEFAULT_DEFERRED_COMMIT_INTERVAL_MS
    );
    assert_eq!(
        config.deferred_commit_max_transactions,
        DEFAULT_DEFERRED_COMMIT_MAX_TRANSACTIONS
    );
    assert!(config.zero_copy);
    assert!(config.numa_aware);

    let value = serde_json::json!({
        "k": 1,
        "m": 0,
        "chunk_size": 4096,
        "compression": "none",
        "compression_level": 0,
        "l2_cache_bytes": 0,
        "fsname": "legacy"
    });
    let legacy: VolumeConfig = serde_json::from_value(value).unwrap();
    assert_eq!(legacy.io_mode, IoMode::Buffered);
    assert_eq!(
        legacy.deferred_commit_interval_ms,
        DEFAULT_DEFERRED_COMMIT_INTERVAL_MS
    );
    assert_eq!(
        legacy.deferred_commit_max_transactions,
        DEFAULT_DEFERRED_COMMIT_MAX_TRANSACTIONS
    );

    let encryption = EncryptionConfig::default();
    assert!(!encryption.enabled);
    assert_eq!(encryption.kdf, "argon2id");
    assert!(encryption.salt_hex.is_empty());
}

#[test]
fn inline_inode_data_serializes_as_base64_and_rejects_invalid_text() {
    let inode = Inode {
        id: 2,
        kind: NodeKind::File,
        mode: 0o600,
        uid: 0,
        gid: 0,
        nlink: 1,
        size: 4,
        rdev: 0,
        atime: 0.0,
        mtime: 0.0,
        ctime: 0.0,
        entries: BTreeMap::new(),
        target: None,
        inline_data: Some(vec![0, 1, 2, 255]),
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
    };
    let encoded = serde_json::to_value(&inode).unwrap();
    assert_eq!(encoded["inline_data"], "AAEC/w==");
    let decoded: Inode = serde_json::from_value(encoded).unwrap();
    assert_eq!(decoded.inline_data, inode.inline_data);

    let mut invalid = serde_json::to_value(&inode).unwrap();
    invalid["inline_data"] = serde_json::Value::String("%%%".into());
    assert!(serde_json::from_value::<Inode>(invalid).is_err());

    let mut absent = serde_json::to_value(&inode).unwrap();
    absent.as_object_mut().unwrap().remove("inline_data");
    assert_eq!(
        serde_json::from_value::<Inode>(absent).unwrap().inline_data,
        None
    );
}
