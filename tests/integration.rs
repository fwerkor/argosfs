use argosfs::acl;
use argosfs::journal;
use argosfs::types::{Compression, DiskStatus, IoMode, StorageTier, VolumeConfig};
use argosfs::ArgosFs;
use std::ffi::OsStr;
use std::fs;
use std::io::Write;
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
        fsname: "argosfs-test".to_string(),
        ..VolumeConfig::default()
    }
}

fn shard_abs(fs: &ArgosFs, disk_id: &str, rel: &std::path::Path) -> std::path::PathBuf {
    let meta = fs.metadata_snapshot();
    let disk = meta.disks.get(disk_id).unwrap();
    if disk.path.is_absolute() {
        disk.path.join(rel)
    } else {
        fs.root().join(&disk.path).join(rel)
    }
}

fn env_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(())).lock().unwrap()
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
fn create_entry_owner_can_come_from_fuse_request() {
    let tmp = TempDir::new().unwrap();
    let fs = ArgosFs::create(tmp.path(), config(2, 2), 4, false).unwrap();

    let file = fs
        .create_file_at_with_owner(1, OsStr::new("owned"), 0o640, 1234, 5678)
        .unwrap();
    assert_eq!(file.uid, 1234);
    assert_eq!(file.gid, 5678);
    assert_eq!(file.mode & 0o7777, 0o640);

    let dir = fs
        .mkdir_at_with_owner(1, OsStr::new("dir"), 0o750, 2345, 6789)
        .unwrap();
    assert_eq!(dir.uid, 2345);
    assert_eq!(dir.gid, 6789);

    let link = fs
        .symlink_at_with_owner(
            1,
            OsStr::new("link"),
            std::path::Path::new("/owned"),
            3456,
            7890,
        )
        .unwrap();
    assert_eq!(link.uid, 3456);
    assert_eq!(link.gid, 7890);
}

#[test]
fn rename_noop_and_replacement_keep_metadata_consistent() {
    let tmp = TempDir::new().unwrap();
    let fs = ArgosFs::create(tmp.path(), config(2, 2), 4, false).unwrap();

    fs.write_file("/a", b"alpha", 0o644).unwrap();
    let ino = fs.resolve_path("/a", false).unwrap();
    fs.rename_path("/a", "/a").unwrap();
    assert_eq!(fs.resolve_path("/a", false).unwrap(), ino);
    assert_eq!(fs.read_file("/a", true).unwrap(), b"alpha");

    fs.link_at(ino, 1, OsStr::new("b")).unwrap();
    fs.rename_path("/a", "/b").unwrap();
    assert_eq!(fs.read_file("/a", true).unwrap(), b"alpha");
    assert_eq!(fs.read_file("/b", true).unwrap(), b"alpha");
    assert_eq!(fs.attr_path("/a", false).unwrap().nlink, 2);

    fs.write_file("/c", b"charlie", 0o644).unwrap();
    fs.rename_path("/c", "/b").unwrap();
    assert_eq!(fs.read_file("/a", true).unwrap(), b"alpha");
    assert_eq!(fs.attr_path("/a", false).unwrap().nlink, 1);
    assert_eq!(fs.read_file("/b", true).unwrap(), b"charlie");
    assert!(fs.fsck(true, true).unwrap().errors.is_empty());
}

#[test]
fn rename_rejects_invalid_directory_and_type_transitions() {
    let tmp = TempDir::new().unwrap();
    let fs = ArgosFs::create(tmp.path(), config(2, 2), 4, false).unwrap();

    fs.mkdir("/dir", 0o755).unwrap();
    fs.mkdir("/dir/sub", 0o755).unwrap();
    fs.write_file("/file", b"payload", 0o644).unwrap();

    assert_eq!(
        fs.rename_path("/file", "/dir").unwrap_err().errno(),
        libc::EISDIR
    );
    assert_eq!(
        fs.rename_path("/dir", "/file").unwrap_err().errno(),
        libc::ENOTDIR
    );
    assert_eq!(
        fs.rename_path("/dir", "/dir/sub/moved")
            .unwrap_err()
            .errno(),
        libc::EINVAL
    );

    assert_eq!(fs.read_file("/file", true).unwrap(), b"payload");
    assert!(fs.resolve_path("/dir/sub", false).is_ok());
    assert!(fs.fsck(true, true).unwrap().errors.is_empty());
}

#[test]
fn link_at_rejects_missing_inode_without_directory_damage() {
    let tmp = TempDir::new().unwrap();
    let fs = ArgosFs::create(tmp.path(), config(2, 2), 4, false).unwrap();

    assert_eq!(
        fs.link_at(9999, 1, OsStr::new("bad")).unwrap_err().errno(),
        libc::ENOENT
    );
    assert!(fs.lookup(1, OsStr::new("bad")).is_err());
    assert!(fs.fsck(true, true).unwrap().errors.is_empty());
}

#[test]
fn range_write_propagates_read_errors_without_overwriting_existing_data() {
    let _env_guard = env_lock();
    let tmp = TempDir::new().unwrap();
    let fs = ArgosFs::create(tmp.path(), config(2, 2), 4, false).unwrap();
    let key = "range write keeps old encrypted data";

    fs.enable_encryption(key).unwrap();
    std::env::set_var("ARGOSFS_KEY", key);
    fs.write_file("/secret", b"original secret", 0o600).unwrap();
    let ino = fs.resolve_path("/secret", false).unwrap();

    std::env::remove_var("ARGOSFS_KEY");
    assert_eq!(
        fs.write_inode_range(ino, 0, b"new").unwrap_err().errno(),
        libc::EACCES
    );

    std::env::set_var("ARGOSFS_KEY", key);
    assert_eq!(fs.read_file("/secret", true).unwrap(), b"original secret");
    std::env::remove_var("ARGOSFS_KEY");
}

#[test]
fn tolerates_two_disk_failures_and_repairs_after_replacement() {
    let tmp = TempDir::new().unwrap();
    let fs = ArgosFs::create(tmp.path(), config(3, 2), 5, false).unwrap();
    fs.mkdir("/var", 0o755).unwrap();
    let data = (0..20_000).map(|idx| (idx % 251) as u8).collect::<Vec<_>>();
    fs.write_file("/var/blob", &data, 0o644).unwrap();

    fs.mark_disk("disk-0000", DiskStatus::Failed).unwrap();
    fs.mark_disk("disk-0001", DiskStatus::Failed).unwrap();
    assert_eq!(fs.read_file("/var/blob", true).unwrap(), data);

    fs.add_disk(None, Some(StorageTier::Warm), Some(1.0), Some(0), false)
        .unwrap();
    fs.add_disk(None, Some(StorageTier::Warm), Some(1.0), Some(0), false)
        .unwrap();
    let report = fs.fsck(true, true).unwrap();
    assert_eq!(report.unrecoverable_files, 0);
    assert_eq!(fs.read_file("/var/blob", true).unwrap(), data);
}

#[test]
fn detects_corrupt_shard_and_scrubs() {
    let tmp = TempDir::new().unwrap();
    let fs = ArgosFs::create(tmp.path(), config(2, 2), 4, false).unwrap();
    fs.write_file("/file", b"abcdefghijklmnopqrstuvwxyz", 0o644)
        .unwrap();

    let meta = fs.metadata_snapshot();
    let inode = meta.inodes.values().find(|inode| inode.size == 26).unwrap();
    let shard = &inode.blocks[0].shards[0];
    fs::write(shard_abs(&fs, &shard.disk_id, &shard.relpath), b"corrupt").unwrap();

    let report = fs.fsck(true, true).unwrap();
    assert_eq!(report.damaged_files, 1);
    assert_eq!(report.repaired_files, 1);
    assert_eq!(
        fs.read_file("/file", true).unwrap(),
        b"abcdefghijklmnopqrstuvwxyz"
    );
}

#[test]
fn drain_remove_and_rebalance_keep_data_available() {
    let tmp = TempDir::new().unwrap();
    let fs = ArgosFs::create(tmp.path(), config(2, 2), 5, false).unwrap();
    fs.write_file("/a", b"alpha", 0o644).unwrap();
    fs.write_file("/b", b"beta", 0o644).unwrap();

    let rewritten = fs.remove_disk("disk-0000").unwrap();
    assert!(rewritten <= 2);
    assert_eq!(fs.read_file("/a", true).unwrap(), b"alpha");
    assert_eq!(fs.read_file("/b", true).unwrap(), b"beta");

    let moved = fs.rebalance().unwrap();
    assert_eq!(moved, 2);
    assert_eq!(fs.fsck(true, true).unwrap().unrecoverable_files, 0);
}

#[test]
fn importable_special_metadata_matches_unix_expectations() {
    let tmp = TempDir::new().unwrap();
    let fs = ArgosFs::create(tmp.path(), config(2, 2), 4, false).unwrap();
    fs.mkdir("/dev", 0o755).unwrap();
    fs.mknod_path("/dev/fifo", libc::S_IFIFO | 0o644, 0)
        .unwrap();
    let attr = fs.attr_path("/dev/fifo", false).unwrap();
    assert_eq!(attr.mode & libc::S_IFMT, libc::S_IFIFO);
}

#[test]
fn auto_probe_latency_feedback_and_hard_capacity_limit() {
    let tmp = TempDir::new().unwrap();
    let fs = ArgosFs::create(tmp.path(), config(1, 1), 2, false).unwrap();
    let report = fs.health_report();
    assert_eq!(report.disks.len(), 2);
    assert!(report.disks.iter().all(|disk| disk.capacity_bytes > 0));
    assert!(report.disks.iter().all(|disk| disk.weight > 0.0));

    fs.write_file("/latency", b"latency sample", 0o644).unwrap();
    let report = fs.health_report();
    assert!(report
        .disks
        .iter()
        .any(|disk| disk.read_latency_ewma_ms > 0.0 || disk.write_latency_ewma_ms > 0.0));

    fs.mark_disk("disk-0000", DiskStatus::Failed).unwrap();
    fs.mark_disk("disk-0001", DiskStatus::Failed).unwrap();
    fs.add_disk(None, Some(StorageTier::Warm), Some(1.0), Some(8), false)
        .unwrap();
    fs.add_disk(None, Some(StorageTier::Warm), Some(1.0), Some(8), false)
        .unwrap();
    let err = fs
        .write_file("/too-large", b"this cannot fit", 0o644)
        .unwrap_err();
    assert_eq!(err.errno(), libc::ENOSPC);
}

#[test]
fn posix_and_nfs4_acl_are_enforced_and_exposed_as_xattrs() {
    let tmp = TempDir::new().unwrap();
    let fs = ArgosFs::create(tmp.path(), config(2, 2), 4, false).unwrap();
    fs.write_file("/secure", b"acl", 0o640).unwrap();

    let acl_value =
        acl::parse_posix_acl("user::rw-,user:1234:---,group::---,mask::---,other::---").unwrap();
    fs.set_posix_acl_path("/secure", false, acl_value.clone())
        .unwrap();
    let ino = fs.resolve_path("/secure", false).unwrap();
    assert_eq!(
        fs.check_access_inode(ino, 1234, 1234, libc::R_OK)
            .unwrap_err()
            .errno(),
        libc::EACCES
    );

    let encoded = acl::posix_acl_to_xattr(&acl_value);
    fs.setxattr_inode(ino, acl::POSIX_ACL_ACCESS_XATTR, &encoded)
        .unwrap();
    assert_eq!(
        fs.getxattr_inode(ino, acl::POSIX_ACL_ACCESS_XATTR).unwrap(),
        encoded
    );
    assert!(String::from_utf8(
        fs.getxattr_inode(ino, acl::ARGOS_POSIX_ACL_ACCESS_XATTR)
            .unwrap()
    )
    .unwrap()
    .contains("user:1234:---"));

    fs.set_nfs4_acl_path(
        "/secure",
        acl::parse_nfs4_acl_json(
            r#"{"entries":[{"ace_type":"deny","principal":"EVERYONE@","flags":[],"permissions":["read"]}]}"#,
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        fs.check_access_inode(ino, 9999, 9999, libc::R_OK)
            .unwrap_err()
            .errno(),
        libc::EACCES
    );
}

#[test]
fn encryption_requires_key_and_encrypts_shards_at_rest() {
    let _env_guard = env_lock();
    let tmp = TempDir::new().unwrap();
    let fs = ArgosFs::create(tmp.path(), config(2, 2), 4, false).unwrap();
    let key = "correct horse battery staple";
    fs.enable_encryption(key).unwrap();
    std::env::set_var("ARGOSFS_KEY", key);
    fs.write_file("/secret", b"paper-grade secret payload", 0o600)
        .unwrap();
    std::env::remove_var("ARGOSFS_KEY");

    assert_eq!(
        fs.read_file("/secret", true).unwrap_err().errno(),
        libc::EACCES
    );
    std::env::set_var("ARGOSFS_KEY", key);
    assert_eq!(
        fs.read_file("/secret", true).unwrap(),
        b"paper-grade secret payload"
    );

    let meta = fs.metadata_snapshot();
    let inode = meta.inodes.values().find(|inode| inode.size > 0).unwrap();
    assert!(inode.blocks.iter().all(|block| block.encrypted));
    let shard = &inode.blocks[0].shards[0];
    let shard_bytes = fs::read(shard_abs(&fs, &shard.disk_id, &shard.relpath)).unwrap();
    assert!(!shard_bytes
        .windows("paper-grade secret payload".len())
        .any(|window| window == b"paper-grade secret payload"));
    std::env::remove_var("ARGOSFS_KEY");
}

#[test]
fn advanced_io_policy_and_prometheus_metrics_are_live() {
    let tmp = TempDir::new().unwrap();
    let fs = ArgosFs::create(tmp.path(), config(2, 2), 4, false).unwrap();
    fs.set_io_policy(IoMode::Direct, true, true, true).unwrap();
    assert_eq!(fs.metadata_snapshot().config.io_mode, IoMode::Direct);
    fs.write_file("/direct", b"direct mode falls back safely", 0o644)
        .unwrap();
    assert_eq!(
        fs.read_file("/direct", true).unwrap(),
        b"direct mode falls back safely"
    );

    fs.set_io_policy(IoMode::IoUring, false, true, true)
        .unwrap();
    fs.write_file("/uring", b"uring mode falls back safely", 0o644)
        .unwrap();
    assert_eq!(
        fs.read_file("/uring", true).unwrap(),
        b"uring mode falls back safely"
    );

    let report = fs.health_report();
    assert_eq!(report.io_mode, IoMode::IoUring);
    let metrics = argosfs::metrics::render(&fs);
    assert!(metrics.contains("argosfs_txid"));
    assert!(metrics.contains("argosfs_disk_read_latency_ms"));
    assert!(metrics.contains("argosfs_io_uring_available"));
}

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
