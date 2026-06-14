use argosfs::types::{Compression, DiskStatus, IoMode, VolumeConfig};
use argosfs::{ArgosError, ArgosFs};
use std::sync::{Mutex, OnceLock};
use tempfile::TempDir;

fn config(k: usize, m: usize) -> VolumeConfig {
    VolumeConfig {
        k,
        m,
        chunk_size: 1024,
        compression: Compression::Lz4,
        compression_level: 0,
        l2_cache_bytes: 0,
        fsname: "argosfs-regression".to_string(),
        ..VolumeConfig::default()
    }
}

fn loop_images(tmp: &TempDir, count: usize) -> Vec<std::path::PathBuf> {
    (0..count)
        .map(|index| tmp.path().join(format!("disk{index}.img")))
        .collect()
}

fn env_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(())).lock().unwrap()
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8(bytes.to_vec()).unwrap()
}

#[test]
fn loop_write_failure_rolls_back_raw_allocator() {
    let _guard = env_lock();
    let tmp = TempDir::new().unwrap();
    let images = loop_images(&tmp, 1);
    let fs =
        ArgosFs::create_loop(&images, config(1, 0), 32 * 1024 * 1024, "rollback", false).unwrap();
    let before = fs.metadata_snapshot();
    let disk_id = before.disks.keys().next().unwrap().clone();
    let before_allocator = before.raw_pool.allocators.get(&disk_id).unwrap().clone();

    let key = text(&[
        65, 82, 71, 79, 83, 70, 83, 95, 67, 82, 65, 83, 72, 95, 80, 79, 73, 78, 84,
    ]);
    let point = text(&[
        98, 101, 102, 111, 114, 101, 45, 100, 97, 116, 97, 45, 119, 114, 105, 116, 101,
    ]);
    std::env::set_var(&key, &point);
    let payload = vec![b'x'; 20 * 1024];
    let result = fs.write_file("/interrupted", &payload, 0o644);
    std::env::remove_var(&key);

    let err = result.unwrap_err();
    assert!(format!("{err}").contains(&point));
    let after = fs.metadata_snapshot();
    let after_allocator = after.raw_pool.allocators.get(&disk_id).unwrap();
    assert_eq!(after_allocator.next_offset, before_allocator.next_offset);
    assert_eq!(after_allocator.free_extents, before_allocator.free_extents);
}

#[test]
fn readonly_loop_open_rejects_metadata_and_data_mutations() {
    let tmp = TempDir::new().unwrap();
    let images = loop_images(&tmp, 1);
    let fs =
        ArgosFs::create_loop(&images, config(1, 0), 32 * 1024 * 1024, "readonly", false).unwrap();
    fs.write_file("/existing", b"existing data", 0o644).unwrap();
    let disk_id = fs.metadata_snapshot().disks.keys().next().unwrap().clone();
    drop(fs);

    let reopened = ArgosFs::open_loop(&images, false).unwrap();
    let before = reopened.metadata_snapshot();

    assert!(matches!(
        reopened
            .mark_disk(&disk_id, DiskStatus::Degraded)
            .unwrap_err(),
        ArgosError::ReadonlyRequired(_)
    ));
    assert!(matches!(
        reopened.mkdir("/should-not-exist", 0o755).unwrap_err(),
        ArgosError::ReadonlyRequired(_)
    ));
    assert!(matches!(
        reopened
            .write_file("/existing", b"changed", 0o644)
            .unwrap_err(),
        ArgosError::ReadonlyRequired(_)
    ));

    let after = reopened.metadata_snapshot();
    assert_eq!(after.disks[&disk_id].status, before.disks[&disk_id].status);
    assert_eq!(
        after.raw_pool.allocators[&disk_id].next_offset,
        before.raw_pool.allocators[&disk_id].next_offset
    );
    assert_eq!(
        after.raw_pool.allocators[&disk_id].free_extents,
        before.raw_pool.allocators[&disk_id].free_extents
    );
    assert_eq!(after.inodes[&1].entries.get("should-not-exist"), None);
    assert_eq!(
        reopened.read_file("/existing", true).unwrap(),
        b"existing data"
    );
}
#[test]
fn readonly_loop_sync_is_rejected() {
    let tmp = TempDir::new().unwrap();
    let images = loop_images(&tmp, 1);
    let fs = ArgosFs::create_loop(
        &images,
        config(1, 0),
        32 * 1024 * 1024,
        "readonly-sync",
        false,
    )
    .unwrap();
    fs.write_file("/existing", b"existing data", 0o644).unwrap();
    drop(fs);

    let reopened = ArgosFs::open_loop(&images, false).unwrap();
    assert!(matches!(
        reopened.sync().unwrap_err(),
        ArgosError::ReadonlyRequired(_)
    ));
}

#[test]
fn readonly_loop_failed_metadata_updates_do_not_mutate_memory_or_persist() {
    let tmp = TempDir::new().unwrap();
    let images = loop_images(&tmp, 1);
    let fs = ArgosFs::create_loop(
        &images,
        config(1, 0),
        32 * 1024 * 1024,
        "readonly-metadata",
        false,
    )
    .unwrap();
    fs.write_file("/existing", b"existing data", 0o644).unwrap();
    let ino = fs.resolve_path("/existing", true).unwrap();
    drop(fs);

    let reopened = ArgosFs::open_loop(&images, false).unwrap();
    let before = reopened.metadata_snapshot();
    assert_eq!(before.config.io_mode, IoMode::Buffered);
    assert_eq!(reopened.attr_inode(ino).unwrap().mode & 0o777, 0o644);

    assert!(matches!(
        reopened
            .set_io_policy(IoMode::Direct, true, false, false)
            .unwrap_err(),
        ArgosError::ReadonlyRequired(_)
    ));
    assert!(matches!(
        reopened.chmod_inode(ino, 0o600).unwrap_err(),
        ArgosError::ReadonlyRequired(_)
    ));
    assert!(matches!(
        reopened.sync().unwrap_err(),
        ArgosError::ReadonlyRequired(_)
    ));

    let after = reopened.metadata_snapshot();
    assert_eq!(after.config.io_mode, before.config.io_mode);
    assert_eq!(after.inodes[&ino].mode & 0o777, 0o644);
    drop(reopened);

    let reopened_again = ArgosFs::open_loop(&images, false).unwrap();
    assert_eq!(reopened_again.io_policy().io_mode, IoMode::Buffered);
    assert_eq!(reopened_again.attr_inode(ino).unwrap().mode & 0o777, 0o644);
}
