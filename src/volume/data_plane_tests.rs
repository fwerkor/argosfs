use super::*;
use tempfile::tempdir;

fn host_volume(disks: usize) -> (tempfile::TempDir, ArgosFs) {
    let dir = tempdir().unwrap();
    let fs = ArgosFs::create(
        dir.path(),
        VolumeConfig {
            k: 1,
            m: 0,
            compression: Compression::None,
            chunk_size: 4096,
            ..VolumeConfig::default()
        },
        disks,
        false,
    )
    .unwrap();
    (dir, fs)
}

fn block_with_shard(disk_id: &str, data: &[u8], relpath: PathBuf) -> FileBlock {
    let hash = content_hash_hex(data);
    FileBlock {
        layout_id: DEFAULT_LAYOUT_ID.to_string(),
        stripe_id: "stripe-test".to_string(),
        raw_offset: 0,
        raw_size: data.len(),
        raw_sha256: hash.clone(),
        codec: Compression::None,
        encrypted: false,
        nonce_hex: String::new(),
        compressed_size: data.len(),
        shard_size: data.len(),
        shards: vec![Shard {
            slot: 0,
            disk_id: disk_id.to_string(),
            location: None,
            relpath,
            sha256: hash.clone(),
            checksum_block_size: SHARD_CHECKSUM_BLOCK_SIZE,
            subblock_sha256: shard_subblock_hashes(data, &hash),
            size: data.len(),
        }],
        storage_class: StorageTier::Warm,
    }
}

#[test]
fn range_geometry_and_inline_windows_validate_inode_types_and_bounds() {
    let (_dir, fs) = host_volume(1);
    fs.write_file("/file", b"inline", 0o600).unwrap();
    let file = fs.resolve_path("/file", true).unwrap();
    let directory = fs.mkdir("/dir", 0o755).unwrap();
    let mut meta = fs.meta.write();

    assert!(matches!(
        fs.range_update_geometry_locked(&meta, 9999),
        Err(ArgosError::NotFound(_))
    ));
    assert!(matches!(
        fs.range_update_geometry_locked(&meta, directory),
        Err(ArgosError::Unsupported(_))
    ));
    assert_eq!(
        fs.range_update_geometry_locked(&meta, file).unwrap(),
        (6, 4096)
    );
    assert!(fs
        .decode_inode_window_locked(&mut meta, file, 4, 4)
        .unwrap()
        .is_empty());
    assert_eq!(
        fs.decode_inode_window_locked(&mut meta, file, 2, 9)
            .unwrap(),
        b"line\0\0\0"
    );
    assert!(matches!(
        fs.decode_inode_window_locked(&mut meta, directory, 0, 1),
        Err(ArgosError::Unsupported(_))
    ));
    assert!(matches!(
        fs.decode_inode_window_locked(&mut meta, 9999, 0, 1),
        Err(ArgosError::NotFound(_))
    ));

    let inode = meta.inodes.get(&file).unwrap().clone();
    assert!(fs
        .decode_inode_range_from_inode_locked(&mut meta, &inode, 3, 3)
        .unwrap()
        .0
        .is_empty());
    let mut inline_inode = inode;
    inline_inode.blocks.clear();
    inline_inode.inline_data = Some(b"inline".to_vec());
    inline_inode.inline_sha256 = content_hash_hex(b"inline");
    inline_inode.size = 6;
    assert!(matches!(
        fs.decode_inode_range_from_inode_locked(&mut meta, &inline_inode, 0, 7),
        Err(ArgosError::Invalid(_))
    ));
}

#[test]
fn replacing_data_rejects_missing_directory_and_special_inodes() {
    let (_dir, fs) = host_volume(1);
    let directory = fs.mkdir("/dir", 0o755).unwrap();
    let special = fs.mknod_path("/fifo", libc::S_IFIFO | 0o600, 0).unwrap();
    for result in [
        fs.replace_inode_data(9999, b"x", "test", serde_json::json!({})),
        fs.replace_inode_data(directory, b"x", "test", serde_json::json!({})),
        fs.replace_inode_data(special, b"x", "test", serde_json::json!({})),
    ] {
        assert!(result.is_err());
    }
}

#[test]
fn disk_selection_respects_exclusions_status_capacity_and_domains() {
    let (_dir, fs) = host_volume(3);
    let mut meta = fs.meta.write();
    let ids = meta.disks.keys().cloned().collect::<Vec<_>>();
    for (index, disk) in meta.disks.values_mut().enumerate() {
        disk.capacity_source = CapacitySource::UserOverride;
        disk.capacity_bytes = 100;
        disk.used_bytes = 0;
        disk.failure_domain = format!("domain-{index}");
    }
    let excluded = BTreeSet::from([ids[0].clone()]);
    let selected = fs
        .choose_disks_locked(
            &meta,
            PlacementRequest {
                key: "key",
                count: 2,
                storage_class: StorageTier::Warm,
                boot_critical: false,
                exclude_disks: &excluded,
                required_bytes: 60,
            },
        )
        .unwrap();
    assert_eq!(selected.len(), 2);
    assert!(!selected.contains(&ids[0]));

    meta.disks.get_mut(&ids[1]).unwrap().status = DiskStatus::Offline;
    assert!(matches!(
        fs.choose_disks_locked(
            &meta,
            PlacementRequest {
                key: "key",
                count: 2,
                storage_class: StorageTier::Hot,
                boot_critical: true,
                exclude_disks: &excluded,
                required_bytes: 60,
            }
        ),
        Err(ArgosError::NotEnoughDisks { .. })
    ));

    meta.disks.get_mut(&ids[1]).unwrap().status = DiskStatus::Online;
    meta.disks.get_mut(&ids[2]).unwrap().used_bytes = 50;
    assert!(!fs.disk_has_capacity(&meta, &ids[2], &meta.disks[&ids[2]], 60));
    assert!(matches!(
        fs.ensure_disk_capacity_locked(&meta, &ids[2], 60),
        Err(ArgosError::DiskFull { available: 50, .. })
    ));
    assert!(matches!(
        fs.ensure_disk_capacity_locked(&meta, "missing", 1),
        Err(ArgosError::NotFound(_))
    ));
    meta.disks.get_mut(&ids[2]).unwrap().capacity_bytes = 0;
    assert!(fs.disk_has_capacity(&meta, &ids[2], &meta.disks[&ids[2]], u64::MAX));
    fs.ensure_disk_capacity_locked(&meta, &ids[2], u64::MAX)
        .unwrap();
}

#[test]
fn shared_auto_probe_capacity_uses_max_capacity_and_sum_usage() {
    let (_dir, fs) = host_volume(2);
    let mut meta = fs.meta.write();
    let ids = meta.disks.keys().cloned().collect::<Vec<_>>();
    for (index, id) in ids.iter().enumerate() {
        let disk = meta.disks.get_mut(id).unwrap();
        disk.capacity_source = CapacitySource::AutoProbe;
        disk.backing_fs_id = Some("shared".to_string());
        disk.capacity_bytes = if index == 0 { 100 } else { 150 };
        disk.used_bytes = if index == 0 { 20 } else { 30 };
    }
    let first = &meta.disks[&ids[0]];
    assert_eq!(fs.effective_capacity_bytes_locked(&meta, first), 150);
    assert_eq!(fs.effective_used_bytes_locked(&meta, first), 50);
    assert!(fs.disk_has_capacity(&meta, &ids[0], first, 100));
    assert!(!fs.disk_has_capacity(&meta, &ids[0], first, 101));

    let mut standalone = first.clone();
    standalone.backing_fs_id = None;
    standalone.capacity_bytes = 77;
    standalone.used_bytes = 11;
    assert_eq!(fs.effective_capacity_bytes_locked(&meta, &standalone), 77);
    assert_eq!(fs.effective_used_bytes_locked(&meta, &standalone), 11);
    standalone.capacity_source = CapacitySource::UserOverride;
    assert_eq!(fs.effective_capacity_bytes_locked(&meta, &standalone), 77);
    assert_eq!(fs.effective_used_bytes_locked(&meta, &standalone), 11);
}

#[test]
fn latency_updates_and_block_accounting_cover_deferred_and_missing_disks() {
    let (_dir, fs) = host_volume(1);
    let mut meta = fs.meta.write();
    let id = meta.disks.keys().next().unwrap().clone();
    let initial_samples = meta.disks[&id].io_samples;
    fs.update_read_latency_locked(&mut meta, &id, 1024 * 1024, 0.5);
    assert_eq!(meta.disks[&id].io_samples, initial_samples + 1);
    assert!(meta.disks[&id].read_latency_ewma_ms > 0.0);

    meta.config.defer_metadata_commit = true;
    fs.update_write_latency_locked(&mut meta, &id, 1, 0.5);
    assert_eq!(meta.disks[&id].io_samples, initial_samples + 1);
    fs.update_write_latency_locked(&mut meta, &id, SHARD_CHECKSUM_BLOCK_SIZE as u64, 0.5);
    assert_eq!(meta.disks[&id].io_samples, initial_samples + 2);
    fs.update_read_latency_locked(&mut meta, "missing", 1, 1.0);
    fs.update_write_latency_locked(&mut meta, "missing", SHARD_CHECKSUM_BLOCK_SIZE as u64, 1.0);

    let block = block_with_shard(&id, b"data", PathBuf::from("unused"));
    let before = meta.disks[&id].used_bytes;
    fs.account_blocks_locked(&mut meta, std::slice::from_ref(&block), true);
    assert_eq!(meta.disks[&id].used_bytes, before + 4);
    fs.account_blocks_locked(&mut meta, std::slice::from_ref(&block), false);
    assert_eq!(meta.disks[&id].used_bytes, before);
    let mut missing = block;
    missing.shards[0].disk_id = "missing".to_string();
    fs.account_blocks_locked(&mut meta, &[missing], true);
}

#[test]
fn shard_range_and_full_reads_validate_bounds_locations_and_deletion() {
    let (_dir, fs) = host_volume(1);
    let mut meta = fs.meta.write();
    let id = meta.disks.keys().next().unwrap().clone();
    let relpath = PathBuf::from("shards/range.bin");
    let path = fs.shard_path_locked(&meta, &id, &relpath);
    ensure_private_dir(path.parent().unwrap()).unwrap();
    fs::write(&path, b"0123456789").unwrap();
    let mut shard = Shard {
        slot: 0,
        disk_id: id.clone(),
        location: Some(ShardLocation::HostPath {
            disk_id: id.clone(),
            relpath: relpath.clone(),
        }),
        relpath: relpath.clone(),
        sha256: content_hash_hex(b"0123456789"),
        checksum_block_size: 0,
        subblock_sha256: Vec::new(),
        size: 10,
    };
    assert_eq!(fs.read_shard_locked(&meta, &shard).unwrap(), b"0123456789");
    assert_eq!(
        fs.read_shard_range_locked(&meta, &shard, 3, 4).unwrap(),
        b"3456"
    );
    assert!(matches!(
        fs.read_shard_range_locked(&meta, &shard, usize::MAX, 2),
        Err(ArgosError::Invalid(_))
    ));
    assert!(matches!(
        fs.read_shard_range_locked(&meta, &shard, 9, 2),
        Err(ArgosError::Invalid(_))
    ));

    shard.location = None;
    assert_eq!(fs.read_shard_locked(&meta, &shard).unwrap(), b"0123456789");
    assert_eq!(
        fs.read_shard_range_locked(&meta, &shard, 1, 2).unwrap(),
        b"12"
    );
    fs.delete_shard_locked(&mut meta, &shard).unwrap();
    assert!(!path.exists());
    fs.delete_shard_locked(&mut meta, &shard).unwrap();

    shard.disk_id = "missing".to_string();
    fs.delete_shard_locked(&mut meta, &shard).unwrap();
}

#[test]
fn single_shard_decoding_reports_missing_unavailable_and_checksum_failures() {
    let (_dir, fs) = host_volume(1);
    let mut meta = fs.meta.write();
    let id = meta.disks.keys().next().unwrap().clone();
    let relpath = PathBuf::from("shards/block.bin");
    let path = fs.shard_path_locked(&meta, &id, &relpath);
    ensure_private_dir(path.parent().unwrap()).unwrap();
    fs::write(&path, b"payload").unwrap();
    let mut block = block_with_shard(&id, b"payload", relpath);
    let mut damaged = Vec::new();
    assert_eq!(
        fs.decode_single_shard_block_locked(&mut meta, &block, &mut damaged, "cache-key")
            .unwrap(),
        b"payload"
    );

    block.shards.clear();
    assert!(matches!(
        fs.decode_single_shard_block_locked(&mut meta, &block, &mut damaged, "missing-slot"),
        Err(ArgosError::UnrecoverableStripe { .. })
    ));
    block = block_with_shard("missing", b"payload", PathBuf::from("unused"));
    assert!(matches!(
        fs.decode_single_shard_block_locked(&mut meta, &block, &mut damaged, "missing-disk"),
        Err(ArgosError::UnrecoverableStripe { .. })
    ));
    block = block_with_shard(&id, b"payload", PathBuf::from("shards/block.bin"));
    meta.disks.get_mut(&id).unwrap().status = DiskStatus::Offline;
    assert!(matches!(
        fs.decode_single_shard_block_locked(&mut meta, &block, &mut damaged, "offline"),
        Err(ArgosError::UnrecoverableStripe { .. })
    ));
    meta.disks.get_mut(&id).unwrap().status = DiskStatus::Online;
    block.raw_sha256 = content_hash_hex(b"wrong");
    assert!(matches!(
        fs.decode_single_shard_block_locked(&mut meta, &block, &mut damaged, "bad-hash"),
        Err(ArgosError::UnrecoverableStripe { .. })
    ));
    assert!(!damaged.is_empty());
}

#[test]
fn range_decode_shortcuts_and_metadata_validation_cover_fallbacks() {
    let (_dir, fs) = host_volume(1);
    let mut meta = fs.meta.write();
    let id = meta.disks.keys().next().unwrap().clone();
    let mut block = block_with_shard(&id, b"payload", PathBuf::from("unused"));
    let mut damaged = Vec::new();
    assert_eq!(
        fs.decode_block_range_locked(&mut meta, &block, 2, 2, &mut damaged)
            .unwrap(),
        Some(Vec::new())
    );
    block.encrypted = true;
    assert!(fs
        .decode_block_range_locked(&mut meta, &block, 0, 1, &mut damaged)
        .unwrap()
        .is_none());
    block.encrypted = false;
    block.codec = Compression::Zstd;
    assert!(fs
        .decode_block_range_locked(&mut meta, &block, 0, 1, &mut damaged)
        .unwrap()
        .is_none());
    block.codec = Compression::None;
    assert!(fs
        .decode_block_range_locked(&mut meta, &block, 0, block.raw_size + 1, &mut damaged)
        .unwrap()
        .is_none());
    block.shards.clear();
    assert!(matches!(
        fs.decode_block_range_locked(&mut meta, &block, 0, 1, &mut damaged),
        Err(ArgosError::UnrecoverableStripe { .. })
    ));
}

#[test]
fn encoding_empty_data_and_stripe_overflow_roll_back_metadata() {
    let (_dir, fs) = host_volume(1);
    let mut meta = fs.meta.write();
    assert!(fs
        .encode_data_locked(
            &mut meta,
            b"",
            0,
            StorageTier::Warm,
            false,
            &BTreeSet::new()
        )
        .unwrap()
        .is_empty());
    let before = meta.clone();
    meta.next_stripe = u64::MAX;
    let failed_state = meta.clone();
    assert!(matches!(
        fs.encode_data_locked(
            &mut meta,
            b"x",
            0,
            StorageTier::Warm,
            false,
            &BTreeSet::new()
        ),
        Err(ArgosError::Invalid(_))
    ));
    assert_eq!(meta.next_stripe, failed_state.next_stripe);
    *meta = before;
    let id = meta.disks.keys().next().unwrap().clone();
    let shard = fs
        .write_shard_locked(&mut meta, &id, "stripe-host", 0, b"host shard", None)
        .unwrap();
    assert_eq!(fs.read_shard_locked(&meta, &shard).unwrap(), b"host shard");
    fs.delete_shard_locked(&mut meta, &shard).unwrap();
}

fn configured_host_volume(config: VolumeConfig, disks: usize) -> (tempfile::TempDir, ArgosFs) {
    let dir = tempdir().unwrap();
    let fs = ArgosFs::create(dir.path(), config, disks, false).unwrap();
    (dir, fs)
}

#[test]
fn erasure_decode_tolerates_one_missing_shard_and_records_all_damage_classes() {
    let (_dir, fs) = configured_host_volume(
        VolumeConfig {
            k: 2,
            m: 1,
            compression: Compression::Zstd,
            compression_level: 3,
            chunk_size: 4096,
            ..VolumeConfig::default()
        },
        3,
    );
    let raw = b"erasure recovery payload".repeat(300);
    let mut meta = fs.meta.write();
    let mut blocks = fs
        .encode_data_locked(
            &mut meta,
            &raw,
            0,
            StorageTier::Warm,
            false,
            &BTreeSet::new(),
        )
        .unwrap();
    let mut block = blocks.remove(0);
    let removed = block.shards[0].clone();
    fs.delete_shard_locked(&mut meta, &removed).unwrap();
    let mut invalid_slot = block.shards[1].clone();
    invalid_slot.slot = 99;
    let mut missing_disk = block.shards[1].clone();
    missing_disk.disk_id = "missing-disk".to_string();
    block.shards.push(invalid_slot);
    block.shards.push(missing_disk);
    let mut damaged = Vec::new();
    let decoded = fs
        .decode_block_locked(&mut meta, &block, None, &mut damaged)
        .unwrap();
    assert_eq!(decoded, raw[..block.raw_size]);
    assert!(damaged.iter().any(|item| item.contains("invalid-slot")));
    assert!(damaged.iter().any(|item| item.contains("missing-disk")));
    assert!(damaged.iter().any(|item| item.contains("missing:")));

    let offline_id = block.shards[1].disk_id.clone();
    meta.disks.get_mut(&offline_id).unwrap().status = DiskStatus::Offline;
    fs.cache.remove(&format!(
        "{}:{}:{}",
        meta.uuid, block.stripe_id, block.raw_sha256
    ));
    let mut unavailable = Vec::new();
    assert!(matches!(
        fs.decode_block_locked(&mut meta, &block, None, &mut unavailable),
        Err(ArgosError::UnrecoverableStripe { .. })
    ));
    assert!(unavailable.iter().any(|item| item.contains("unavailable")));
}

#[test]
fn encrypted_blocks_require_a_valid_nonce_key_and_authenticated_payload() {
    let _env_guard = crypto::test_env_lock();
    let (_dir, fs) = host_volume(1);
    std::env::set_var("ARGOSFS_KEY", "coverage-secret");
    fs.enable_encryption("coverage-secret").unwrap();
    let raw = b"encrypted payload".repeat(100);
    let mut meta = fs.meta.write();
    let block = fs
        .encode_data_locked(
            &mut meta,
            &raw,
            0,
            StorageTier::Warm,
            false,
            &BTreeSet::new(),
        )
        .unwrap()
        .remove(0);
    assert!(block.encrypted);
    let key = fs.encryption_key_locked(&meta).unwrap();
    let mut damaged = Vec::new();
    assert_eq!(
        fs.decode_block_locked(&mut meta, &block, Some(&key), &mut damaged)
            .unwrap(),
        raw[..block.raw_size]
    );
    assert!(matches!(
        fs.decode_block_locked(&mut meta, &block, None, &mut Vec::new()),
        Err(ArgosError::PermissionDenied(_))
    ));
    let mut bad_nonce = block.clone();
    bad_nonce.nonce_hex = "zz".to_string();
    assert!(matches!(
        fs.decode_block_locked(&mut meta, &bad_nonce, Some(&key), &mut Vec::new()),
        Err(ArgosError::Invalid(_))
    ));
    let mut bad_key = key;
    bad_key[0] ^= 1;
    assert!(matches!(
        fs.decode_block_locked(&mut meta, &block, Some(&bad_key), &mut Vec::new()),
        Err(ArgosError::PermissionDenied(_))
    ));
    std::env::remove_var("ARGOSFS_KEY");
}

#[test]
fn inode_decode_rejects_size_mismatch_overflow_and_blocks_past_eof() {
    let (_dir, fs) = host_volume(1);
    let mut meta = fs.meta.write();
    let mut inode = meta.inodes[&ROOT_INO].clone();
    inode.kind = NodeKind::File;
    inode.id = 42;
    inode.inline_data = Some(b"abc".to_vec());
    inode.inline_sha256 = content_hash_hex(b"abc");
    inode.size = 2;
    assert!(fs.decode_inode_data_locked(&mut meta, &inode).is_err());

    inode.inline_data = None;
    inode.inline_sha256.clear();
    inode.size = 1;
    inode.blocks = vec![FileBlock {
        raw_offset: 1,
        raw_size: 1,
        raw_sha256: content_hash_hex(b"x"),
        compressed_size: 1,
        shard_size: 1,
        shards: Vec::new(),
        stripe_id: "past-eof".to_string(),
        layout_id: DEFAULT_LAYOUT_ID.to_string(),
        codec: Compression::None,
        encrypted: false,
        nonce_hex: String::new(),
        storage_class: StorageTier::Warm,
    }];
    assert!(fs.decode_inode_data_locked(&mut meta, &inode).is_err());

    inode.size = 8;
    inode.blocks[0].raw_offset = u64::MAX;
    assert!(fs
        .decode_inode_range_from_inode_locked(&mut meta, &inode, 0, 8)
        .is_err());
}

#[test]
fn range_decode_validates_metadata_missing_disks_status_checksums_and_read_errors() {
    let (_dir, fs) = host_volume(1);
    let mut meta = fs.meta.write();
    let disk_id = meta.disks.keys().next().unwrap().clone();
    let data = vec![7u8; SHARD_CHECKSUM_BLOCK_SIZE + 16];
    let relpath = PathBuf::from("shards/range-checksum.blk");
    let path = fs.shard_path_locked(&meta, &disk_id, &relpath);
    ensure_private_dir(path.parent().unwrap()).unwrap();
    fs::write(&path, &data).unwrap();
    let hash = content_hash_hex(&data);
    let mut block = FileBlock {
        layout_id: DEFAULT_LAYOUT_ID.to_string(),
        stripe_id: "range-checksum".to_string(),
        raw_offset: 0,
        raw_size: data.len(),
        raw_sha256: hash.clone(),
        codec: Compression::None,
        encrypted: false,
        nonce_hex: String::new(),
        compressed_size: data.len(),
        shard_size: data.len(),
        shards: vec![Shard {
            slot: 0,
            disk_id: disk_id.clone(),
            location: Some(ShardLocation::HostPath {
                disk_id: disk_id.clone(),
                relpath: relpath.clone(),
            }),
            relpath,
            sha256: hash.clone(),
            checksum_block_size: SHARD_CHECKSUM_BLOCK_SIZE,
            subblock_sha256: shard_subblock_hashes(&data, &hash),
            size: data.len(),
        }],
        storage_class: StorageTier::Warm,
    };
    let mut damaged = Vec::new();
    assert_eq!(
        fs.decode_block_range_locked(&mut meta, &block, 2, 10, &mut damaged)
            .unwrap()
            .unwrap(),
        data[2..10]
    );

    block.shards[0].subblock_sha256.pop();
    assert!(fs
        .decode_block_range_locked(&mut meta, &block, 0, 1, &mut Vec::new())
        .unwrap()
        .is_none());
    block.shards[0].subblock_sha256 = shard_subblock_hashes(&data, &hash);
    block.shards[0].subblock_sha256[0] = "bad".to_string();
    assert!(matches!(
        fs.decode_block_range_locked(&mut meta, &block, 0, 1, &mut Vec::new()),
        Err(ArgosError::UnrecoverableStripe { .. })
    ));
    block.shards[0].subblock_sha256 = shard_subblock_hashes(&data, &hash);

    let original_disk = block.shards[0].disk_id.clone();
    block.shards[0].disk_id = "missing".to_string();
    assert!(matches!(
        fs.decode_block_range_locked(&mut meta, &block, 0, 1, &mut Vec::new()),
        Err(ArgosError::UnrecoverableStripe { .. })
    ));
    block.shards[0].disk_id = original_disk.clone();
    meta.disks.get_mut(&original_disk).unwrap().status = DiskStatus::Failed;
    assert!(matches!(
        fs.decode_block_range_locked(&mut meta, &block, 0, 1, &mut Vec::new()),
        Err(ArgosError::UnrecoverableStripe { .. })
    ));
    meta.disks.get_mut(&original_disk).unwrap().status = DiskStatus::Online;
    fs::remove_file(fs.shard_path_locked(
        &meta,
        &original_disk,
        match block.shards[0].location.as_ref().unwrap() {
            ShardLocation::HostPath { relpath, .. } => relpath,
            _ => unreachable!(),
        },
    ))
    .unwrap();
    assert!(fs
        .decode_block_range_locked(&mut meta, &block, 0, 1, &mut Vec::new())
        .is_err());
}

#[test]
fn placement_scoring_covers_tiers_boot_critical_numa_and_shared_capacity_reservations() {
    let (_dir, fs) = host_volume(4);
    let mut meta = fs.meta.write();
    let ids = meta.disks.keys().cloned().collect::<Vec<_>>();
    for (index, id) in ids.iter().enumerate() {
        let disk = meta.disks.get_mut(id).unwrap();
        disk.tier = match index {
            0 => StorageTier::Hot,
            1 | 2 => StorageTier::Cold,
            _ => StorageTier::Warm,
        };
        disk.numa_node = Some(index as i32);
        disk.weight = if index == 0 { 0.0 } else { 1.0 };
        disk.capacity_source = CapacitySource::AutoProbe;
        disk.backing_fs_id = Some(if index < 2 { "shared" } else { "other" }.to_string());
        disk.capacity_bytes = 100;
        disk.used_bytes = 10;
        disk.failure_domain = if index < 2 { "same" } else { "other" }.to_string();
    }
    let hot = fs
        .choose_disks_locked(
            &meta,
            PlacementRequest {
                key: "hot",
                count: 2,
                storage_class: StorageTier::Hot,
                boot_critical: true,
                exclude_disks: &BTreeSet::new(),
                required_bytes: 40,
            },
        )
        .unwrap();
    assert_eq!(hot.len(), 2);
    let _bulk = bulk_import_scope(true);
    let cold = fs
        .choose_disks_locked(
            &meta,
            PlacementRequest {
                key: "cold",
                count: 2,
                storage_class: StorageTier::Cold,
                boot_critical: false,
                exclude_disks: &BTreeSet::new(),
                required_bytes: 40,
            },
        )
        .unwrap();
    assert_eq!(cold.len(), 2);
}
