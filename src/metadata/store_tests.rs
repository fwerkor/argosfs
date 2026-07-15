use super::*;
use std::path::PathBuf;

#[test]
fn paged_metadata_round_trips_json_metadata() {
    let metadata = sample_metadata();
    let paged = PagedMetadata::from_metadata_with_options(
        &metadata,
        PagedMetadataOptions {
            directory_entries_per_page: 1,
            xattrs_per_page: 1,
            file_blocks_per_page: 1,
        },
    )
    .unwrap();

    assert_eq!(
        paged
            .pages
            .keys()
            .filter(|key| key.kind == MetadataPageKind::Directory)
            .count(),
        2
    );
    assert_eq!(
        paged
            .pages
            .keys()
            .filter(|key| key.kind == MetadataPageKind::Xattr)
            .count(),
        2
    );
    assert_eq!(
        paged
            .pages
            .keys()
            .filter(|key| key.kind == MetadataPageKind::ShardIndex)
            .count(),
        2
    );

    let round_trip = paged.to_metadata().unwrap();
    assert_eq!(
        serde_json::to_value(&round_trip).unwrap(),
        serde_json::to_value(&metadata).unwrap()
    );
}

#[test]
fn page_delta_replays_changed_pages() {
    let before = sample_metadata();
    let mut after = before.clone();
    after.txid += 1;
    after.updated_at += 1.0;
    after.inodes.get_mut(&2).unwrap().xattrs.insert(
        "user.extra".to_string(),
        "only this xattr page should change".to_string(),
    );
    let options = PagedMetadataOptions {
        directory_entries_per_page: 1,
        xattrs_per_page: 1,
        file_blocks_per_page: 1,
    };
    let mut replayed = PagedMetadata::from_metadata_with_options(&before, options).unwrap();
    let next = PagedMetadata::from_metadata_with_options(&after, options).unwrap();
    let delta = metadata_page_delta(&replayed, &next);

    assert!(
            delta
                .iter()
                .any(|op| matches!(op, MetadataPageDeltaOp::Put { page } if page.key.kind == MetadataPageKind::Xattr))
        );
    replayed.apply_delta(&delta).unwrap();

    assert_eq!(
        serde_json::to_value(replayed.to_metadata().unwrap()).unwrap(),
        serde_json::to_value(after).unwrap()
    );
}

fn sample_metadata() -> Metadata {
    let created_at = 1_700_000_000.0;
    let mut disks = BTreeMap::new();
    disks.insert(
        "disk-0000".to_string(),
        Disk {
            id: "disk-0000".to_string(),
            path: PathBuf::from("/tmp/argosfs-disk-0000"),
            tier: StorageTier::Warm,
            weight: 1.0,
            status: DiskStatus::Online,
            capacity_bytes: 1024 * 1024 * 1024,
            capacity_source: CapacitySource::UserOverride,
            used_bytes: 4096,
            health: HealthCounters::default(),
            class: DiskClass::Ssd,
            backing_device: None,
            backing_fs_id: None,
            failure_domain: "fd-a".to_string(),
            sysfs_block: None,
            rotational: Some(false),
            numa_node: Some(0),
            read_latency_ewma_ms: 0.2,
            write_latency_ewma_ms: 0.4,
            observed_read_mib_s: 100.0,
            observed_write_mib_s: 80.0,
            io_samples: 4,
            last_probe: DiskProbe::default(),
            created_at,
        },
    );

    let block = FileBlock {
        layout_id: "layout-0000".to_string(),
        stripe_id: "stripe-0001".to_string(),
        raw_offset: 0,
        raw_size: 5,
        raw_sha256: "raw-hash".to_string(),
        codec: Compression::None,
        encrypted: false,
        nonce_hex: String::new(),
        compressed_size: 5,
        shard_size: 5,
        shards: vec![Shard {
            slot: 0,
            disk_id: "disk-0000".to_string(),
            location: Some(ShardLocation::HostPath {
                disk_id: "disk-0000".to_string(),
                relpath: PathBuf::from("shards/stripe-0001.0"),
            }),
            relpath: PathBuf::from("shards/stripe-0001.0"),
            sha256: "shard-hash".to_string(),
            checksum_block_size: 256 * 1024,
            subblock_sha256: vec!["subblock-hash".to_string()],
            size: 5,
        }],
        storage_class: StorageTier::Warm,
    };

    let mut root_entries = BTreeMap::new();
    root_entries.insert("alpha".to_string(), 2);
    root_entries.insert("beta".to_string(), 3);
    let root = Inode {
        id: 1,
        kind: NodeKind::Directory,
        mode: libc::S_IFDIR | 0o755,
        uid: 1000,
        gid: 1000,
        nlink: 2,
        size: 0,
        rdev: 0,
        atime: created_at,
        mtime: created_at,
        ctime: created_at,
        entries: root_entries,
        target: None,
        inline_data: None,
        inline_sha256: String::new(),
        blocks: Vec::new(),
        xattrs: BTreeMap::new(),
        posix_acl_access: None,
        posix_acl_default: None,
        nfs4_acl: None,
        access_count: 7,
        write_count: 1,
        read_bytes: 10,
        write_bytes: 0,
        storage_class: StorageTier::Warm,
        boot_critical: true,
        workload_score: 0.8,
        last_accessed_at: created_at,
        last_written_at: created_at,
    };

    let mut xattrs = BTreeMap::new();
    xattrs.insert("user.alpha".to_string(), "one".to_string());
    xattrs.insert("user.beta".to_string(), "two".to_string());
    let file = Inode {
        id: 2,
        kind: NodeKind::File,
        mode: libc::S_IFREG | 0o644,
        uid: 1000,
        gid: 1000,
        nlink: 1,
        size: 10,
        rdev: 0,
        atime: created_at,
        mtime: created_at + 1.0,
        ctime: created_at + 1.0,
        entries: BTreeMap::new(),
        target: None,
        inline_data: Some(b"hello".to_vec()),
        inline_sha256: "inline-hash".to_string(),
        blocks: vec![
            block.clone(),
            FileBlock {
                stripe_id: "stripe-0002".to_string(),
                raw_offset: 5,
                ..block
            },
        ],
        xattrs,
        posix_acl_access: Some(PosixAcl::default()),
        posix_acl_default: None,
        nfs4_acl: Some(Nfs4Acl::default()),
        access_count: 3,
        write_count: 2,
        read_bytes: 64,
        write_bytes: 10,
        storage_class: StorageTier::Hot,
        boot_critical: false,
        workload_score: 2.0,
        last_accessed_at: created_at + 2.0,
        last_written_at: created_at + 2.0,
    };
    let symlink = Inode {
        id: 3,
        kind: NodeKind::Symlink,
        mode: libc::S_IFLNK | 0o777,
        uid: 1000,
        gid: 1000,
        nlink: 1,
        size: 5,
        rdev: 0,
        atime: created_at,
        mtime: created_at,
        ctime: created_at,
        entries: BTreeMap::new(),
        target: Some("alpha".to_string()),
        inline_data: None,
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
        last_accessed_at: created_at,
        last_written_at: created_at,
    };

    let mut inodes = BTreeMap::new();
    inodes.insert(1, root);
    inodes.insert(2, file);
    inodes.insert(3, symlink);
    let mut layouts = BTreeMap::new();
    layouts.insert(
        "layout-0000".to_string(),
        LayoutConfig {
            id: "layout-0000".to_string(),
            k: 1,
            m: 0,
            chunk_size: 256 * 1024,
            created_txid: 0,
            sealed: false,
        },
    );

    Metadata {
        format: FORMAT_VERSION.to_string(),
        uuid: "metadata-store-test".to_string(),
        backend: BackendKind::Host,
        raw_pool: RawPoolMetadata::default(),
        created_at,
        updated_at: created_at + 3.0,
        txid: 9,
        next_inode: 4,
        next_stripe: 3,
        config: VolumeConfig {
            k: 1,
            m: 0,
            ..VolumeConfig::default()
        },
        layouts,
        current_write_layout: "layout-0000".to_string(),
        reshape: None,
        encryption: EncryptionConfig::default(),
        integrity: MetadataIntegrity::default(),
        disks,
        inodes,
    }
}

#[test]
fn paged_options_and_page_keys_validate_all_boundaries() {
    assert_eq!(
        PagedMetadataOptions::default().directory_entries_per_page,
        128
    );
    for options in [
        PagedMetadataOptions {
            directory_entries_per_page: 0,
            ..PagedMetadataOptions::default()
        },
        PagedMetadataOptions {
            xattrs_per_page: 0,
            ..PagedMetadataOptions::default()
        },
        PagedMetadataOptions {
            file_blocks_per_page: 0,
            ..PagedMetadataOptions::default()
        },
    ] {
        assert!(matches!(options.validate(), Err(ArgosError::Invalid(_))));
    }
    PagedMetadataOptions::default().validate().unwrap();

    assert_eq!(MetadataPageKey::header().kind, MetadataPageKind::Header);
    assert_eq!(MetadataPageKey::disk("disk").owner, "disk");
    assert_eq!(MetadataPageKey::inode(42).owner, "42");
    assert_eq!(MetadataPageKey::directory(42, 3).page, 3);
    assert_eq!(MetadataPageKey::xattr(42, 4).page, 4);
    assert_eq!(MetadataPageKey::shard_index(42, 5).page, 5);
    assert_eq!(chunked_pairs::<u8>(Vec::new(), 2), Vec::<Vec<u8>>::new());
    assert_eq!(chunked_pairs(vec![1, 2, 3], 2), vec![vec![1, 2], vec![3]]);
}

#[test]
fn metadata_pages_reject_key_body_and_hash_mismatches() {
    let metadata = sample_metadata();
    let header = MetadataPageBody::Header(MetadataHeaderPage::from(&metadata));
    assert!(MetadataPage::new(MetadataPageKey::inode(1), metadata.txid, header.clone()).is_err());

    let mut page = MetadataPage::new(MetadataPageKey::header(), metadata.txid, header).unwrap();
    page.body_hash = "bad".to_string();
    assert!(matches!(
        page.verify_hash(),
        Err(ArgosError::CorruptedMetadata(_))
    ));

    let disk = metadata.disks.values().next().unwrap().clone();
    let inode = metadata.inodes.values().next().unwrap().clone();
    let bodies = [
        (
            MetadataPageKey::header(),
            MetadataPageBody::Disk(disk.clone()),
        ),
        (
            MetadataPageKey::header(),
            MetadataPageBody::Inode(InodeCorePage::from(&inode)),
        ),
        (
            MetadataPageKey::directory(inode.id + 1, 0),
            MetadataPageBody::Directory(DirectoryPage {
                inode: inode.id,
                first_name: None,
                entries: Vec::new(),
            }),
        ),
        (
            MetadataPageKey::xattr(inode.id + 1, 0),
            MetadataPageBody::Xattr(XattrPage {
                inode: inode.id,
                first_name: None,
                xattrs: Vec::new(),
            }),
        ),
        (
            MetadataPageKey::shard_index(inode.id + 1, 0),
            MetadataPageBody::ShardIndex(ShardIndexPage {
                inode: inode.id,
                first_block: 0,
                blocks: Vec::new(),
            }),
        ),
    ];
    for (key, body) in bodies {
        assert!(validate_page_key(&key, &body).is_err());
    }
}

#[test]
fn paged_metadata_rejects_version_header_hash_and_reference_corruption() {
    let metadata = sample_metadata();
    let original = PagedMetadata::from_metadata(&metadata).unwrap();

    let mut bad_version = original.clone();
    bad_version.version += 1;
    assert!(matches!(
        bad_version.to_metadata(),
        Err(ArgosError::Invalid(_))
    ));

    let mut bad_options = original.clone();
    bad_options.options.file_blocks_per_page = 0;
    assert!(matches!(
        bad_options.to_metadata(),
        Err(ArgosError::Invalid(_))
    ));

    let mut missing_header = original.clone();
    missing_header.pages.remove(&MetadataPageKey::header());
    assert!(matches!(
        missing_header.to_metadata(),
        Err(ArgosError::CorruptedMetadata(_))
    ));

    let mut wrong_header_body = original.clone();
    let disk = metadata.disks.values().next().unwrap().clone();
    let header = wrong_header_body
        .pages
        .get_mut(&MetadataPageKey::header())
        .unwrap();
    header.body = MetadataPageBody::Disk(disk);
    header.body_hash = hash_page_body(&header.body).unwrap();
    assert!(matches!(
        wrong_header_body.to_metadata(),
        Err(ArgosError::CorruptedMetadata(_))
    ));

    let mut bad_hash = original.clone();
    bad_hash
        .pages
        .get_mut(&MetadataPageKey::header())
        .unwrap()
        .body_hash = "bad".to_string();
    assert!(matches!(
        bad_hash.to_metadata(),
        Err(ArgosError::CorruptedMetadata(_))
    ));

    let mut missing_directory_owner = original.clone();
    missing_directory_owner
        .pages
        .remove(&MetadataPageKey::inode(1));
    assert!(matches!(
        missing_directory_owner.to_metadata(),
        Err(ArgosError::CorruptedMetadata(message)) if message.contains("directory page")
    ));

    let mut missing_xattr_owner = original.clone();
    missing_xattr_owner.pages.remove(&MetadataPageKey::inode(2));
    missing_xattr_owner
        .pages
        .retain(|key, _| key.kind != MetadataPageKind::ShardIndex);
    assert!(matches!(
        missing_xattr_owner.to_metadata(),
        Err(ArgosError::CorruptedMetadata(message)) if message.contains("xattr page")
    ));

    let mut missing_shard_owner = original;
    missing_shard_owner.pages.remove(&MetadataPageKey::inode(2));
    missing_shard_owner
        .pages
        .retain(|key, _| key.kind != MetadataPageKind::Xattr);
    assert!(matches!(
        missing_shard_owner.to_metadata(),
        Err(ArgosError::CorruptedMetadata(message)) if message.contains("shard index page")
    ));
}

#[test]
fn page_put_apply_delta_and_store_trait_cover_insert_replace_delete_and_import() {
    let before = sample_metadata();
    let mut store = PagedMetadata::from_metadata(&before).unwrap();
    let header_key = MetadataPageKey::header();
    let mut replacement = store.pages[&header_key].clone();
    if let MetadataPageBody::Header(header) = &mut replacement.body {
        header.config.fsname = "replaced".to_string();
    }
    replacement.body_hash = hash_page_body(&replacement.body).unwrap();
    store.put_page(replacement.clone()).unwrap();
    assert_eq!(store.pages[&header_key].body_hash, replacement.body_hash);

    let mut invalid = replacement.clone();
    invalid.body_hash = "invalid".to_string();
    assert!(store.put_page(invalid).is_err());

    let disk_key = store
        .pages
        .keys()
        .find(|key| key.kind == MetadataPageKind::Disk)
        .unwrap()
        .clone();
    store
        .apply_delta(&[
            MetadataPageDeltaOp::Delete {
                key: disk_key.clone(),
            },
            MetadataPageDeltaOp::Put {
                page: Box::new(replacement),
            },
        ])
        .unwrap();
    assert!(!store.pages.contains_key(&disk_key));

    let mut imported = PagedMetadata {
        version: PAGED_METADATA_VERSION,
        options: PagedMetadataOptions::default(),
        pages: BTreeMap::new(),
    };
    imported.import_metadata(&before).unwrap();
    let exported = imported.export_metadata().unwrap();
    assert_eq!(
        serde_json::to_value(exported).unwrap(),
        serde_json::to_value(before).unwrap()
    );
}

#[test]
fn page_delta_reports_unchanged_deleted_added_and_changed_pages() {
    let metadata = sample_metadata();
    let before = PagedMetadata::from_metadata(&metadata).unwrap();
    assert!(metadata_page_delta(&before, &before).is_empty());

    let mut next = before.clone();
    let removed_key = next
        .pages
        .keys()
        .find(|key| key.kind == MetadataPageKind::Disk)
        .unwrap()
        .clone();
    next.pages.remove(&removed_key);
    let mut changed = next.pages[&MetadataPageKey::header()].clone();
    if let MetadataPageBody::Header(header) = &mut changed.body {
        header.updated_at += 1.0;
    }
    changed.body_hash = hash_page_body(&changed.body).unwrap();
    next.pages.insert(changed.key.clone(), changed);
    let added = MetadataPage::new(
        MetadataPageKey::disk("extra"),
        metadata.txid,
        MetadataPageBody::Disk(Disk {
            id: "extra".to_string(),
            ..metadata.disks.values().next().unwrap().clone()
        }),
    )
    .unwrap();
    next.pages.insert(added.key.clone(), added);

    let delta = metadata_page_delta(&before, &next);
    assert!(delta
        .iter()
        .any(|op| matches!(op, MetadataPageDeltaOp::Delete { key } if key == &removed_key)));
    assert!(delta.iter().any(|op| {
        matches!(op, MetadataPageDeltaOp::Put { page } if page.key == MetadataPageKey::header())
    }));
    assert!(delta.iter().any(|op| {
        matches!(op, MetadataPageDeltaOp::Put { page } if page.key == MetadataPageKey::disk("extra"))
    }));
}
