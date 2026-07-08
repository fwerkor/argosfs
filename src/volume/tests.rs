use super::*;

#[test]
fn host_sync_drains_only_dirty_shard_set() {
    let tmp = tempfile::tempdir().unwrap();
    let fs = ArgosFs::create(
        tmp.path(),
        VolumeConfig {
            k: 1,
            m: 0,
            compression: Compression::None,
            ..VolumeConfig::default()
        },
        1,
        false,
    )
    .unwrap();

    fs.write_file("/dirty", b"dirty shard tracking", 0o644)
        .unwrap();
    assert!(!fs.dirty_host_shards.lock().is_empty());

    fs.sync().unwrap();

    assert!(fs.dirty_host_shards.lock().is_empty());
}

#[test]
fn data_operations_register_per_inode_locks() {
    let tmp = tempfile::tempdir().unwrap();
    let fs = ArgosFs::create(
        tmp.path(),
        VolumeConfig {
            k: 1,
            m: 0,
            compression: Compression::None,
            ..VolumeConfig::default()
        },
        1,
        false,
    )
    .unwrap();

    fs.write_file("/locked", b"abc", 0o644).unwrap();
    let ino = fs.resolve_path("/locked", true).unwrap();
    fs.write_inode_range(ino, 3, b"def").unwrap();
    fs.truncate_inode(ino, 4).unwrap();

    assert!(fs.inode_locks.lock().contains_key(&ino));
}
