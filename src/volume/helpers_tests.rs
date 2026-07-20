use super::*;
use std::sync::{Mutex as StdMutex, OnceLock};
use tempfile::tempdir;

fn env_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: OnceLock<StdMutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| StdMutex::new(())).lock().unwrap()
}

fn metadata() -> Metadata {
    let dir = tempdir().unwrap();
    ArgosFs::create(
        dir.path(),
        VolumeConfig {
            k: 1,
            m: 0,
            chunk_size: 4096,
            ..VolumeConfig::default()
        },
        1,
        false,
    )
    .unwrap()
    .metadata_snapshot()
}

fn shard(location: Option<ShardLocation>, size: usize) -> Shard {
    Shard {
        slot: 0,
        disk_id: "disk-0000".to_string(),
        location,
        relpath: PathBuf::from("shard.bin"),
        sha256: String::new(),
        checksum_block_size: 0,
        subblock_sha256: Vec::new(),
        size,
    }
}

fn block(offset: u64, size: usize) -> FileBlock {
    FileBlock {
        layout_id: DEFAULT_LAYOUT_ID.to_string(),
        stripe_id: format!("stripe-{offset}"),
        raw_offset: offset,
        raw_size: size,
        raw_sha256: String::new(),
        codec: Compression::None,
        encrypted: false,
        nonce_hex: String::new(),
        compressed_size: size,
        shard_size: size,
        shards: Vec::new(),
        storage_class: StorageTier::Warm,
    }
}

#[test]
fn canonicalization_and_directory_sync_are_best_effort() {
    let dir = tempdir().unwrap();
    let child = dir.path().join("child");
    fs::create_dir(&child).unwrap();
    assert_eq!(canonical_or_self(&child), fs::canonicalize(&child).unwrap());
    let missing = dir.path().join("missing");
    assert_eq!(canonical_or_self(&missing), missing);
    sync_directory(&child);
    sync_directory(&missing);
}

#[test]
fn loop_image_preparation_validates_inputs_and_force_semantics() {
    assert!(matches!(
        prepare_loop_images(&[], raw_format::MIN_DEVICE_BYTES, false),
        Err(ArgosError::Invalid(_))
    ));
    let dir = tempdir().unwrap();
    let path = dir.path().join("nested/image.bin");
    assert!(matches!(
        prepare_loop_images(
            std::slice::from_ref(&path),
            raw_format::MIN_DEVICE_BYTES - 1,
            false
        ),
        Err(ArgosError::Invalid(_))
    ));
    prepare_loop_images(
        std::slice::from_ref(&path),
        raw_format::MIN_DEVICE_BYTES,
        false,
    )
    .unwrap();
    assert_eq!(
        fs::metadata(&path).unwrap().len(),
        raw_format::MIN_DEVICE_BYTES
    );
    assert!(matches!(
        prepare_loop_images(
            std::slice::from_ref(&path),
            raw_format::MIN_DEVICE_BYTES,
            false
        ),
        Err(ArgosError::AlreadyExists(_))
    ));
    fs::write(&path, b"nonempty").unwrap();
    prepare_loop_images(
        std::slice::from_ref(&path),
        raw_format::MIN_DEVICE_BYTES * 2,
        true,
    )
    .unwrap();
    assert_eq!(
        fs::metadata(path).unwrap().len(),
        raw_format::MIN_DEVICE_BYTES * 2
    );
}

#[test]
fn block_cache_root_honors_override_and_path_fallbacks() {
    let _guard = env_lock();
    std::env::remove_var("ARGOSFS_BLOCK_CACHE_DIR");
    let path = PathBuf::from("/tmp/argosfs-device.img");
    assert_eq!(
        block_cache_root("uuid", &[path]),
        PathBuf::from("/tmp/.argosfs-block-cache/uuid")
    );
    assert_eq!(
        block_cache_root("uuid", &[]),
        std::env::temp_dir().join(".argosfs-block-cache/uuid")
    );
    std::env::set_var("ARGOSFS_BLOCK_CACHE_DIR", "/tmp/custom-cache");
    assert_eq!(
        block_cache_root("uuid", &[]),
        PathBuf::from("/tmp/custom-cache/uuid")
    );
    std::env::remove_var("ARGOSFS_BLOCK_CACHE_DIR");
}

#[test]
fn root_inode_uses_current_identity_and_boot_defaults() {
    let inode = root_inode(42.5);
    assert_eq!(inode.id, ROOT_INO);
    assert_eq!(inode.kind, NodeKind::Directory);
    assert_eq!(inode.mode, libc::S_IFDIR | 0o755);
    assert_eq!(inode.uid, current_uid());
    assert_eq!(inode.gid, current_gid());
    assert_eq!(inode.nlink, 2);
    assert!(inode.boot_critical);
    assert_eq!(inode.atime, 42.5);
    assert_eq!(inode.last_written_at, 42.5);
}

#[test]
fn commit_policy_rejects_unsafe_deferred_combinations() {
    let mut config = VolumeConfig {
        defer_data_flush: true,
        ..VolumeConfig::default()
    };
    assert!(validate_commit_policy(&config).is_err());

    config.defer_metadata_commit = true;
    config.deferred_commit_interval_ms = 0;
    assert!(validate_commit_policy(&config).is_err());
    config.deferred_commit_interval_ms = 1;
    config.deferred_commit_max_transactions = 0;
    assert!(validate_commit_policy(&config).is_err());
    config.deferred_commit_max_transactions = 1;
    validate_commit_policy(&config).unwrap();
}

#[test]
fn previous_snapshot_policy_distinguishes_host_and_deferred_block_backends() {
    let mut meta = metadata();
    meta.backend = BackendKind::Host;
    meta.config.defer_metadata_commit = true;
    assert!(commit_previous_snapshot(&meta).is_some());
    meta.backend = BackendKind::LoopBlock;
    assert!(commit_previous_snapshot(&meta).is_none());
    meta.config.defer_metadata_commit = false;
    assert!(commit_previous_snapshot(&meta).is_some());
}

#[test]
fn layout_normalization_and_lookup_repair_legacy_metadata() {
    let mut meta = metadata();
    let file = meta
        .inodes
        .values_mut()
        .find(|inode| inode.kind == NodeKind::Directory)
        .unwrap();
    file.blocks.push(FileBlock {
        layout_id: String::new(),
        ..block(0, 1)
    });
    meta.layouts.clear();
    meta.current_write_layout = "missing".to_string();
    normalize_metadata_layouts(&mut meta);
    assert!(meta.layouts.contains_key(DEFAULT_LAYOUT_ID));
    assert_eq!(meta.current_write_layout, DEFAULT_LAYOUT_ID);
    assert_eq!(
        meta.inodes.values().next().unwrap().blocks[0].layout_id,
        DEFAULT_LAYOUT_ID
    );
    assert_eq!(
        block_layout_id(&FileBlock {
            layout_id: String::new(),
            ..block(0, 1)
        }),
        DEFAULT_LAYOUT_ID
    );
    assert_eq!(block_layout_id(&block(0, 1)), DEFAULT_LAYOUT_ID);
    assert_eq!(layout_by_id(&meta, "").unwrap().id, DEFAULT_LAYOUT_ID);
    assert_eq!(current_write_layout(&meta).unwrap().id, DEFAULT_LAYOUT_ID);
    assert!(layout_by_id(&meta, "unknown").is_err());
}

#[test]
fn layout_insertion_ids_and_size_guards_cover_boundaries() {
    let mut meta = metadata();
    let existing = find_or_insert_layout_locked(&mut meta, 1, 0, 4096);
    assert_eq!(existing, DEFAULT_LAYOUT_ID);
    meta.layouts.insert(
        "layout-0007".to_string(),
        LayoutConfig {
            id: "layout-0007".to_string(),
            k: 2,
            m: 1,
            chunk_size: 8192,
            created_txid: 0,
            sealed: false,
        },
    );
    meta.layouts.insert(
        "layout-bad".to_string(),
        meta.layouts[DEFAULT_LAYOUT_ID].clone(),
    );
    assert_eq!(next_layout_id(&meta), "layout-0008");
    let inserted = find_or_insert_layout_locked(&mut meta, 3, 1, 16384);
    assert_eq!(inserted, "layout-0008");
    assert_eq!(meta.layouts[&inserted].created_txid, meta.txid + 1);
    assert_eq!(checked_layout_total(2, 1).unwrap(), 3);
    assert!(checked_layout_total(usize::MAX, 1).is_err());
    assert_eq!(layout_total(&meta.layouts[&inserted]).unwrap(), 4);
    assert_eq!(max_layout_total(&meta).unwrap(), 4);

    let valid = LayoutConfig {
        id: "valid".to_string(),
        k: 2,
        m: 1,
        chunk_size: 4096,
        created_txid: 0,
        sealed: false,
    };
    assert_eq!(layout_stripe_raw_size(&valid).unwrap(), 8192);
    let zero = LayoutConfig {
        k: 0,
        ..valid.clone()
    };
    assert!(layout_stripe_raw_size(&zero).is_err());
    let overflow = LayoutConfig {
        k: usize::MAX,
        chunk_size: 2,
        ..valid.clone()
    };
    assert!(layout_stripe_raw_size(&overflow).is_err());
    let oversized = LayoutConfig {
        k: 1,
        chunk_size: MAX_IN_MEMORY_IO_BYTES + 1,
        ..valid
    };
    assert!(matches!(
        layout_stripe_raw_size(&oversized),
        Err(ArgosError::FileTooLarge(_))
    ));
}

#[test]
fn zeroed_buffers_and_shard_accounting_cover_raw_and_host_storage() {
    assert_eq!(zeroed_io_buffer(8, "test").unwrap(), vec![0; 8]);
    assert!(matches!(
        zeroed_io_buffer(MAX_IN_MEMORY_IO_BYTES + 1, "test"),
        Err(ArgosError::FileTooLarge(_))
    ));
    assert_eq!(shard_accounted_size(&shard(None, 123)), 123);
    let extent = PhysicalExtent {
        disk_id: "disk-0000".to_string(),
        offset: 4096,
        length: 8192,
        generation: 1,
        flags: 0,
    };
    assert_eq!(
        shard_accounted_size(&shard(Some(ShardLocation::RawExtent(extent)), 123)),
        8192
    );
}

#[test]
fn shard_hashes_handle_empty_single_and_multiple_checksum_blocks() {
    assert!(shard_subblock_hashes(&[], "full").is_empty());
    assert_eq!(shard_subblock_hashes(b"small", "full"), ["full"]);
    let large = vec![7u8; SHARD_CHECKSUM_BLOCK_SIZE + 1];
    let hashes = shard_subblock_hashes(&large, "ignored");
    assert_eq!(hashes.len(), 2);
    assert_eq!(
        hashes[0],
        content_hash_hex(&large[..SHARD_CHECKSUM_BLOCK_SIZE])
    );
    assert_eq!(
        hashes[1],
        content_hash_hex(&large[SHARD_CHECKSUM_BLOCK_SIZE..])
    );
}

#[test]
fn exact_range_reader_reports_success_missing_and_short_reads() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("data.bin");
    fs::write(&path, b"0123456789").unwrap();
    let mut output = [0u8; 4];
    read_path_range_exact(&path, 3, &mut output).unwrap();
    assert_eq!(&output, b"3456");
    assert!(matches!(
        read_path_range_exact(&path, 9, &mut output),
        Err(ArgosError::Io(error)) if error.kind() == std::io::ErrorKind::UnexpectedEof
    ));
    assert!(matches!(
        read_path_range_exact(&dir.path().join("missing"), 0, &mut output),
        Err(ArgosError::Io(_))
    ));
}

#[test]
fn inline_payload_selection_setting_and_validation_cover_all_rejections() {
    let mut meta = metadata();
    meta.backend = BackendKind::LoopBlock;
    let payload = inline_payload_for(&meta, b"small").unwrap();
    assert_eq!(payload.0, b"small");
    assert!(inline_payload_for(&meta, b"").is_none());
    assert!(inline_payload_for(&meta, &vec![0; INLINE_DATA_MAX + 1]).is_none());
    meta.encryption.enabled = true;
    assert!(inline_payload_for(&meta, b"small").is_none());
    meta.encryption.enabled = false;
    meta.backend = BackendKind::Host;
    assert!(inline_payload_for(&meta, b"small").is_none());
    meta.backend = BackendKind::LoopBlock;
    meta.layouts.get_mut(DEFAULT_LAYOUT_ID).unwrap().m = 1;
    assert!(inline_payload_for(&meta, b"small").is_none());
    meta.layouts.clear();
    assert!(inline_payload_for(&meta, b"small").is_none());

    let mut inode = root_inode(0.0);
    inode.kind = NodeKind::File;
    inode.size = 5;
    set_inline_payload(
        &mut inode,
        Some((b"small".to_vec(), content_hash_hex(b"small"))),
    );
    assert_eq!(decode_inline_data(&inode).unwrap(), Some(b"small".to_vec()));
    inode.size = 4;
    assert!(decode_inline_data(&inode).is_err());
    inode.size = 5;
    inode.inline_sha256 = "bad".to_string();
    assert!(decode_inline_data(&inode).is_err());
    set_inline_payload(&mut inode, None);
    assert_eq!(decode_inline_data(&inode).unwrap(), None);
    assert!(inode.inline_sha256.is_empty());
}

#[test]
fn sparse_extent_seek_helpers_cover_inline_holes_merging_and_bounds() {
    let mut inode = root_inode(0.0);
    inode.kind = NodeKind::File;
    inode.size = 100;
    inode.inline_data = Some(vec![0; 100]);
    assert_eq!(seek_data(&inode, 20).unwrap(), 20);
    assert_eq!(seek_hole(&inode, 20).unwrap(), 100);
    assert!(seek_data(&inode, 100).is_err());
    assert_eq!(seek_hole(&inode, 100).unwrap(), 100);
    assert!(seek_hole(&inode, 101).is_err());

    inode.inline_data = None;
    inode.blocks = vec![block(10, 20), block(25, 20), block(70, 40), block(100, 0)];
    assert_eq!(inode_data_extents(&inode), vec![(10, 45), (70, 100)]);
    assert_eq!(seek_data(&inode, 0).unwrap(), 10);
    assert_eq!(seek_data(&inode, 20).unwrap(), 20);
    assert_eq!(seek_data(&inode, 50).unwrap(), 70);
    assert!(seek_data(&inode, 100).is_err());
    assert_eq!(seek_hole(&inode, 0).unwrap(), 0);
    assert_eq!(seek_hole(&inode, 20).unwrap(), 45);
    assert_eq!(seek_hole(&inode, 50).unwrap(), 50);
    assert_eq!(seek_hole(&inode, 80).unwrap(), 100);
}

#[test]
fn utility_helpers_generate_aad_and_update_latency_ewmas() {
    assert_eq!(encryption_aad("volume", "stripe"), b"volume:stripe");
    let mut latency = 0.0;
    let mut throughput = 0.0;
    update_latency_ewma(&mut latency, &mut throughput, 0.5, 1024 * 1024);
    assert_eq!(latency, 500.0);
    assert_eq!(throughput, 2.0);
    update_latency_ewma(&mut latency, &mut throughput, 0.25, 1024 * 1024);
    assert_eq!(latency, 450.0);
    assert!((throughput - 2.4).abs() < 1e-9);
    update_latency_ewma(&mut latency, &mut throughput, 0.0, 0);
    assert!(latency > 0.0);
    assert!((throughput - 2.4).abs() < 1e-9);
}

#[test]
fn recompute_usage_counts_raw_extents_and_normalizes_layouts() {
    let mut meta = metadata();
    let disk_id = meta.disks.keys().next().unwrap().clone();
    let inode = meta.inodes.values_mut().next().unwrap();
    inode.blocks.push(FileBlock {
        layout_id: String::new(),
        shards: vec![
            shard(None, 10),
            shard(
                Some(ShardLocation::RawExtent(PhysicalExtent {
                    disk_id: disk_id.clone(),
                    offset: 0,
                    length: 20,
                    generation: 1,
                    flags: 0,
                })),
                1,
            ),
        ],
        ..block(0, 30)
    });
    for shard in &mut inode.blocks[0].shards {
        shard.disk_id = disk_id.clone();
    }
    meta.disks.get_mut(&disk_id).unwrap().used_bytes = 999;
    recompute_disk_usage_from_metadata(&mut meta);
    assert_eq!(meta.disks[&disk_id].used_bytes, 30);
    assert_eq!(
        meta.inodes.values().next().unwrap().blocks[0].layout_id,
        DEFAULT_LAYOUT_ID
    );
}

#[test]
fn host_storage_permission_hardening_updates_existing_paths() {
    let dir = tempdir().unwrap();
    let mut meta = metadata();
    let system = dir.path().join(".argosfs");
    fs::create_dir_all(system.join("devices")).unwrap();
    fs::create_dir_all(system.join("snapshots")).unwrap();
    fs::create_dir_all(system.join("cache")).unwrap();
    for file in [
        "journal.jsonl",
        "meta.primary.json",
        "meta.secondary.json",
        "meta.json",
        "tx.lock",
        "autopilot.jsonl",
    ] {
        fs::write(system.join(file), b"x").unwrap();
    }
    let disk = meta.disks.values_mut().next().unwrap();
    disk.path = PathBuf::from("disk-root");
    fs::create_dir_all(dir.path().join("disk-root/shards")).unwrap();
    harden_host_storage_permissions(dir.path(), &meta).unwrap();
    use std::os::unix::fs::PermissionsExt as _;
    assert_eq!(
        fs::metadata(&system).unwrap().permissions().mode() & 0o777,
        0o700
    );
    assert_eq!(
        fs::metadata(system.join("journal.jsonl"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    assert_eq!(
        fs::metadata(dir.path().join("disk-root/shards"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
}
