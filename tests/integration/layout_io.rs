use super::*;

#[test]
fn hard_link_does_not_require_source_read_permission() {
    let tmp = TempDir::new().unwrap();
    let fs = ArgosFs::create(tmp.path(), config(2, 2), 4, false).unwrap();

    let attr = fs
        .create_file_at_with_owner(1, OsStr::new("secret"), 0o000, 1234, 1234)
        .unwrap();
    fs.write_inode_range(attr.ino, 0, b"secret").unwrap();

    assert_eq!(
        fs.check_access_inode(attr.ino, 5678, 5678, libc::R_OK)
            .unwrap_err()
            .errno(),
        libc::EACCES
    );

    let linked = fs.link_at(attr.ino, 1, OsStr::new("secret-hard")).unwrap();
    assert_eq!(linked.ino, attr.ino);
    assert_eq!(fs.read_file("/secret-hard", true).unwrap(), b"secret");
}

#[test]
fn range_write_rewrites_only_affected_stripe_window() {
    let _guard = env_lock();
    let tmp = TempDir::new().unwrap();
    let mut cfg = config(2, 2);
    cfg.chunk_size = 4;
    let fs = ArgosFs::create(tmp.path(), cfg, 4, false).unwrap();

    let original = b"aaaabbbbccccddddeeeeffff";
    fs.write_file("/file", original, 0o644).unwrap();
    let before = fs.metadata_snapshot();
    let ino = fs.resolve_path("/file", true).unwrap();
    let before_blocks = before.inodes.get(&ino).unwrap().blocks.clone();
    assert!(before_blocks.len() >= 3);

    fs.write_inode_range(ino, 10, b"XX").unwrap();

    let after = fs.metadata_snapshot();
    let after_blocks = after.inodes.get(&ino).unwrap().blocks.clone();
    assert_eq!(after_blocks.len(), before_blocks.len());

    let unchanged_prefix = before_blocks
        .iter()
        .filter(|block| block.raw_offset < 8)
        .map(|block| block.stripe_id.clone())
        .collect::<Vec<_>>();
    let after_prefix = after_blocks
        .iter()
        .filter(|block| block.raw_offset < 8)
        .map(|block| block.stripe_id.clone())
        .collect::<Vec<_>>();
    assert_eq!(unchanged_prefix, after_prefix);

    let mut expected = original.to_vec();
    expected[10..12].copy_from_slice(b"XX");
    assert_eq!(fs.read_file("/file", true).unwrap(), expected);
}

#[test]
fn failed_multistripe_host_write_rolls_back_all_provisional_shards() {
    let tmp = TempDir::new().unwrap();
    let mut cfg = config(1, 0);
    cfg.chunk_size = 1024;
    cfg.compression = Compression::None;
    let fs = ArgosFs::create(tmp.path(), cfg, 1, false).unwrap();
    let ino = fs.create_file_path("/victim", 0o600).unwrap();
    let before = fs.metadata_snapshot();
    let next = before.next_stripe;
    let failing = format!("s{:016x}", next + 1);
    let blocker = tmp
        .path()
        .join(".argosfs/devices/disk-0000/shards")
        .join(&failing[failing.len() - 2..])
        .join(format!("{failing}.000.blk"));
    fs::create_dir_all(&blocker).unwrap();

    assert!(fs.write_inode_range(ino, 0, &vec![b'x'; 3 * 1024]).is_err());

    let after = fs.metadata_snapshot();
    assert_eq!(after.next_stripe, before.next_stripe);
    assert_eq!(
        after.disks["disk-0000"].used_bytes,
        before.disks["disk-0000"].used_bytes
    );
    assert_eq!(after.inodes[&ino].size, 0);
    let first = format!("s{next:016x}");
    let first_path = tmp
        .path()
        .join(".argosfs/devices/disk-0000/shards")
        .join(&first[first.len() - 2..])
        .join(format!("{first}.000.blk"));
    assert!(!first_path.exists());
}

#[test]
fn legacy_sha256_data_checksums_remain_readable() {
    let tmp = TempDir::new().unwrap();
    let mut cfg = config(1, 0);
    cfg.compression = Compression::None;
    let fs = ArgosFs::create(tmp.path(), cfg, 1, false).unwrap();
    let payload = b"legacy sha256 payload stays readable";
    fs.write_file("/legacy", payload, 0o644).unwrap();
    drop(fs);

    let primary = tmp.path().join(".argosfs/meta.primary.json");
    let mut meta: Metadata = serde_json::from_slice(&fs::read(&primary).unwrap()).unwrap();
    let root = meta.inodes.get(&1).unwrap();
    let file_ino = root.entries["legacy"];
    let legacy_hash = sha256_hex(payload);
    let inode = meta.inodes.get_mut(&file_ino).unwrap();
    assert_eq!(inode.blocks.len(), 1);
    inode.blocks[0].raw_sha256 = legacy_hash.clone();
    inode.blocks[0].shards[0].sha256 = legacy_hash.clone();
    inode.blocks[0].shards[0].subblock_sha256 = vec![legacy_hash];
    journal::prepare_metadata_integrity_for_external_store(&mut meta).unwrap();
    let bytes = serde_json::to_vec_pretty(&meta).unwrap();
    for name in ["meta.primary.json", "meta.secondary.json", "meta.json"] {
        fs::write(tmp.path().join(".argosfs").join(name), &bytes).unwrap();
    }

    let reopened = ArgosFs::open(tmp.path()).unwrap();
    assert_eq!(reopened.read_file("/legacy", true).unwrap(), payload);
    let report = reopened.fsck(false, false).unwrap();
    assert_eq!(report.checksum_errors, 0);
    assert_eq!(report.unrecoverable_files, 0);
}

#[test]
fn truncate_rewrites_only_tail_stripe_window() {
    let _guard = env_lock();
    let tmp = TempDir::new().unwrap();
    let mut cfg = config(2, 2);
    cfg.chunk_size = 4;
    let fs = ArgosFs::create(tmp.path(), cfg, 4, false).unwrap();

    fs.write_file("/file", b"aaaabbbbccccddddeeeeffff", 0o644)
        .unwrap();
    let ino = fs.resolve_path("/file", true).unwrap();
    let before_blocks = fs
        .metadata_snapshot()
        .inodes
        .get(&ino)
        .unwrap()
        .blocks
        .clone();

    fs.truncate_inode(ino, 10).unwrap();

    let after_blocks = fs
        .metadata_snapshot()
        .inodes
        .get(&ino)
        .unwrap()
        .blocks
        .clone();
    assert!(after_blocks.len() < before_blocks.len());
    assert_eq!(fs.read_file("/file", true).unwrap(), b"aaaabbbbcc");
}

#[test]
fn partial_read_accounts_only_requested_window() {
    let tmp = TempDir::new().unwrap();
    let mut cfg = config(1, 0);
    cfg.chunk_size = 4;
    cfg.compression = Compression::None;
    let fs = ArgosFs::create(tmp.path(), cfg, 1, false).unwrap();
    fs.write_file("/window", b"abcdefghijkl", 0o644).unwrap();
    let ino = fs.resolve_path("/window", true).unwrap();

    assert_eq!(fs.read_inode(ino, 4, 4, true).unwrap(), b"efgh");

    let inode = fs.metadata_snapshot().inodes[&ino].clone();
    assert_eq!(inode.access_count, 1);
    assert_eq!(inode.read_bytes, 4);
}

#[test]
fn zero_length_write_is_noop_and_does_not_extend() {
    let tmp = TempDir::new().unwrap();
    let fs = ArgosFs::create(tmp.path(), config(2, 2), 4, false).unwrap();
    fs.write_file("/file", b"abc", 0o644).unwrap();
    let ino = fs.resolve_path("/file", true).unwrap();
    let before = fs.attr_inode(ino).unwrap();
    let txid_before = fs.metadata_snapshot().txid;

    assert_eq!(fs.write_inode_range(ino, 1, b"").unwrap(), 0);
    assert_eq!(fs.read_file("/file", true).unwrap(), b"abc");
    let after_inside = fs.attr_inode(ino).unwrap();
    assert_eq!(after_inside.size, before.size);
    assert_eq!(after_inside.mtime, before.mtime);
    assert_eq!(fs.metadata_snapshot().txid, txid_before);

    assert_eq!(fs.write_inode_range(ino, 100, b"").unwrap(), 0);
    assert_eq!(fs.read_file("/file", true).unwrap(), b"abc");
    assert_eq!(fs.attr_inode(ino).unwrap().size, before.size);
    assert_eq!(fs.metadata_snapshot().txid, txid_before);
}

#[test]
fn sparse_write_beyond_eof_preserves_holes_and_offsets() {
    let tmp = TempDir::new().unwrap();
    let mut cfg = config(2, 2);
    cfg.chunk_size = 4;
    let fs = ArgosFs::create(tmp.path(), cfg, 4, false).unwrap();
    fs.write_file("/file", b"abc", 0o644).unwrap();
    let ino = fs.resolve_path("/file", true).unwrap();

    assert_eq!(fs.write_inode_range(ino, 20, b"XYZ").unwrap(), 3);
    let data = fs.read_file("/file", true).unwrap();
    assert_eq!(data.len(), 23);
    assert_eq!(&data[..3], b"abc");
    assert!(data[3..20].iter().all(|byte| *byte == 0));
    assert_eq!(&data[20..], b"XYZ");

    assert_eq!(fs.read_inode(ino, 18, 5, true).unwrap(), b"\0\0XYZ");
    assert_eq!(fs.seek_data_or_hole(ino, 0, libc::SEEK_DATA).unwrap(), 0);
    assert_eq!(fs.seek_data_or_hole(ino, 0, libc::SEEK_HOLE).unwrap(), 3);
    assert_eq!(fs.seek_data_or_hole(ino, 3, libc::SEEK_DATA).unwrap(), 16);
    assert_eq!(fs.seek_data_or_hole(ino, 3, libc::SEEK_HOLE).unwrap(), 3);
    assert_eq!(fs.seek_data_or_hole(ino, 16, libc::SEEK_DATA).unwrap(), 16);
    assert_eq!(fs.seek_data_or_hole(ino, 16, libc::SEEK_HOLE).unwrap(), 23);
    assert_eq!(fs.seek_data_or_hole(ino, 23, libc::SEEK_HOLE).unwrap(), 23);
    assert_eq!(
        fs.seek_data_or_hole(ino, 23, libc::SEEK_DATA)
            .unwrap_err()
            .errno(),
        libc::ENXIO
    );
}

#[test]
fn copy_inode_range_copies_requested_window() {
    let tmp = TempDir::new().unwrap();
    let fs = ArgosFs::create(tmp.path(), config(2, 2), 4, false).unwrap();
    fs.write_file("/src", b"abcdefghijklmnopqrstuvwxyz", 0o644)
        .unwrap();
    fs.write_file("/dst", b"0123456789", 0o644).unwrap();
    let src = fs.resolve_path("/src", true).unwrap();
    let dst = fs.resolve_path("/dst", true).unwrap();

    let copied = fs.copy_inode_range(src, 4, dst, 3, 8).unwrap();

    assert_eq!(copied, 8);
    assert_eq!(fs.read_file("/dst", true).unwrap(), b"012efghijkl");
}

#[test]
fn fallocate_extends_regular_file_with_zeroes() {
    let tmp = TempDir::new().unwrap();
    let fs = ArgosFs::create(tmp.path(), config(2, 2), 4, false).unwrap();
    fs.write_file("/alloc", b"abc", 0o644).unwrap();
    let ino = fs.resolve_path("/alloc", true).unwrap();

    fs.fallocate_inode(ino, 10, 4, 0).unwrap();

    let data = fs.read_file("/alloc", true).unwrap();
    assert_eq!(data.len(), 14);
    assert_eq!(&data[..3], b"abc");
    assert!(data[3..].iter().all(|byte| *byte == 0));
    assert_eq!(
        fs.fallocate_inode(ino, 0, 1, libc::FALLOC_FL_KEEP_SIZE)
            .unwrap_err()
            .errno(),
        libc::ENOTSUP
    );
}

#[test]
fn snapshot_names_are_rejected_or_protected_from_overwrite() {
    let tmp = TempDir::new().unwrap();
    let fs = ArgosFs::create(tmp.path(), config(2, 2), 4, false).unwrap();

    assert_eq!(fs.snapshot("   ").unwrap_err().errno(), libc::EINVAL);
    let first = fs.snapshot("daily").unwrap();
    assert!(first.exists());
    assert_eq!(fs.snapshot("daily").unwrap_err().errno(), libc::EEXIST);
}

#[test]
fn write_read_and_posix_metadata() {
    let tmp = TempDir::new().unwrap();
    let fs = ArgosFs::create(tmp.path(), config(2, 2), 4, false).unwrap();
    fs.mkdir("/etc", 0o755).unwrap();
    fs.write_file("/etc/motd", b"hello rootfs\n", 0o644)
        .unwrap();
    assert_eq!(fs.read_file("/etc/motd", true).unwrap(), b"hello rootfs\n");

    fs.symlink_path("/etc/motd", "/motd").unwrap();
    let link_ino = fs.resolve_path("/motd", false).unwrap();
    assert_eq!(fs.readlink_inode(link_ino).unwrap(), "/etc/motd");

    fs.mknod_path("/console", libc::S_IFCHR | 0o600, 5).unwrap();
    let attr = fs.attr_path("/console", false).unwrap();
    assert_eq!(attr.kind, argosfs::types::NodeKind::Special);
    assert_eq!(attr.rdev, 5);

    let ino = fs.resolve_path("/etc/motd", false).unwrap();
    fs.link_at(ino, 1, std::ffi::OsStr::new("motd-hard"))
        .unwrap();
    fs.truncate_path("/motd-hard", 5).unwrap();
    assert_eq!(fs.read_file("/etc/motd", true).unwrap(), b"hello");

    fs.setxattr_inode(ino, "user.paper", b"argon").unwrap();
    assert_eq!(fs.getxattr_inode(ino, "user.paper").unwrap(), b"argon");
}

#[test]
fn single_device_host_and_loop_support_m_zero_layouts() {
    let tmp = TempDir::new().unwrap();
    let host = tmp.path().join("host");
    let host_fs = ArgosFs::create(&host, config(1, 0), 1, false).unwrap();
    host_fs
        .write_file("/single", b"host-single", 0o644)
        .unwrap();
    let host_meta = host_fs.metadata_snapshot();
    assert_eq!(host_meta.config.k, 1);
    assert_eq!(host_meta.config.m, 0);
    assert_eq!(host_meta.current_write_layout, "layout-0000");
    assert_eq!(host_meta.layouts["layout-0000"].m, 0);
    let host_ino = host_fs.resolve_path("/single", true).unwrap();
    let host_block = &host_meta.inodes[&host_ino].blocks[0];
    assert_eq!(host_block.layout_id, "layout-0000");
    assert_eq!(host_block.shards.len(), 1);
    drop(host_fs);
    assert_eq!(
        ArgosFs::open(&host)
            .unwrap()
            .read_file("/single", true)
            .unwrap(),
        b"host-single"
    );

    let images = loop_images(&tmp, 1);
    let loop_fs =
        ArgosFs::create_loop(&images, config(1, 0), 32 * 1024 * 1024, "single", false).unwrap();
    let loop_payload = vec![b'l'; 20 * 1024];
    loop_fs
        .write_file("/loop-single", &loop_payload, 0o644)
        .unwrap();
    assert_eq!(
        loop_fs.read_file("/loop-single", true).unwrap(),
        loop_payload.as_slice()
    );
    assert!(loop_fs.fsck(false, false).unwrap().errors.is_empty());
    assert!(loop_fs.scrub().unwrap().errors.is_empty());
    let loop_meta = loop_fs.metadata_snapshot();
    let loop_ino = loop_fs.resolve_path("/loop-single", true).unwrap();
    let loop_block = &loop_meta.inodes[&loop_ino].blocks[0];
    assert_eq!(loop_block.layout_id, "layout-0000");
    assert_eq!(loop_block.shards.len(), 1);
    assert!(matches!(
        loop_block.shards[0].location,
        Some(ShardLocation::RawExtent(_))
    ));
    drop(loop_fs);
    let reopened = ArgosFs::open_loop(&images, true).unwrap();
    assert_eq!(
        reopened.read_file("/loop-single", true).unwrap(),
        loop_payload.as_slice()
    );
}

#[test]
fn single_device_loop_partial_read_uses_subblock_checksums() {
    let tmp = TempDir::new().unwrap();
    let images = loop_images(&tmp, 1);
    let mut cfg = config(1, 0);
    cfg.chunk_size = 1024 * 1024;
    cfg.compression = Compression::None;
    cfg.l2_cache_bytes = 0;
    let fs = ArgosFs::create_loop(&images, cfg, 32 * 1024 * 1024, "single-partial", false).unwrap();
    let payload = (0..1024 * 1024)
        .map(|index| (index % 251) as u8)
        .collect::<Vec<_>>();
    fs.write_file("/blob", &payload, 0o644).unwrap();
    fs.sync().unwrap();

    let meta = fs.metadata_snapshot();
    let ino = fs.resolve_path("/blob", true).unwrap();
    let block = meta.inodes[&ino].blocks[0].clone();
    let shard = block.shards[0].clone();
    assert_eq!(block.layout_id, meta.current_write_layout);
    assert_eq!(shard.size, payload.len());
    assert_eq!(shard.checksum_block_size, 256 * 1024);
    assert_eq!(shard.subblock_sha256.len(), 4);
    let extent = match shard.location.as_ref().unwrap() {
        ShardLocation::RawExtent(extent) => extent.clone(),
        other => panic!("unexpected shard location: {other:?}"),
    };
    drop(fs);

    let corrupt_offset = shard.checksum_block_size * 3 + 17;
    let image = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&images[0])
        .unwrap();
    image
        .write_at(
            &[payload[corrupt_offset] ^ 0xff],
            extent.offset + corrupt_offset as u64,
        )
        .unwrap();
    image.sync_all().unwrap();

    let reopened = ArgosFs::open_loop(&images, true).unwrap();
    let ino = reopened.resolve_path("/blob", true).unwrap();
    let good = reopened.read_inode(ino, 0, 4096, false).unwrap();
    assert_eq!(good, payload[..4096]);

    let err = reopened
        .read_inode(
            ino,
            (shard.checksum_block_size * 3 + 128) as u64,
            4096,
            false,
        )
        .unwrap_err();
    assert!(matches!(err, ArgosError::UnrecoverableStripe { .. }));
    assert!(!reopened.scrub().unwrap().errors.is_empty());
}

#[test]
fn single_device_loop_inlines_small_files_and_promotes_large_appends() {
    let tmp = TempDir::new().unwrap();
    let images = loop_images(&tmp, 1);
    let mut cfg = config(1, 0);
    cfg.compression = Compression::None;
    let fs = ArgosFs::create_loop(&images, cfg, 32 * 1024 * 1024, "inline-small", false).unwrap();
    let small = b"small CapOS config\n";
    fs.write_file("/etc-config", small, 0o644).unwrap();
    let ino = fs.resolve_path("/etc-config", true).unwrap();
    let meta = fs.metadata_snapshot();
    let inode = &meta.inodes[&ino];
    assert!(inode.blocks.is_empty());
    assert!(inode.inline_data.is_some());
    assert_eq!(inode.inline_sha256, content_hash_hex(small));
    assert_eq!(fs.read_file("/etc-config", true).unwrap(), small);
    assert!(fs.fsck(false, false).unwrap().errors.is_empty());
    fs.sync().unwrap();
    drop(fs);

    let reopened = ArgosFs::open_loop(&images, true).unwrap();
    assert_eq!(reopened.read_file("/etc-config", true).unwrap(), small);
    let ino = reopened.resolve_path("/etc-config", true).unwrap();
    let growth = vec![b'x'; 20 * 1024];
    reopened
        .write_inode_range(ino, small.len() as u64, &growth)
        .unwrap();
    let meta = reopened.metadata_snapshot();
    let inode = &meta.inodes[&ino];
    assert!(inode.inline_data.is_none());
    assert!(!inode.blocks.is_empty());
    assert_eq!(inode.size, (small.len() + growth.len()) as u64);
    assert!(reopened.fsck(false, false).unwrap().errors.is_empty());
}
