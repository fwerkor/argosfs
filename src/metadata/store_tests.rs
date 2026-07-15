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
