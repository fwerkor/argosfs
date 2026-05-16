use argosfs::acl;
use argosfs::cache::BlockCache;
use argosfs::crypto;
use argosfs::journal;
use argosfs::types::{Compression, DiskStatus, IoMode, StorageTier, VolumeConfig};
use argosfs::util::{directory_size, sha256_hex};
use argosfs::{ArgosError, ArgosFs, AutopilotConfig};
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::Write;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::process::{Command, Stdio};
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

fn argosfs_binary() -> String {
    std::env::var("CARGO_BIN_EXE_argosfs").unwrap_or_else(|_| {
        let mut path = std::env::current_exe().unwrap();
        path.pop();
        if path.ends_with("deps") {
            path.pop();
        }
        path.push("argosfs");
        path.to_string_lossy().to_string()
    })
}

fn tree_contains_bytes(root: &std::path::Path, needle: &[u8]) -> bool {
    root.exists()
        && walkdir::WalkDir::new(root)
            .into_iter()
            .filter_map(|entry| entry.ok())
            .filter(|entry| entry.file_type().is_file())
            .any(|entry| {
                fs::read(entry.path())
                    .is_ok_and(|data| data.windows(needle.len()).any(|window| window == needle))
            })
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
fn symlink_resolution_decodes_internal_targets_safely() {
    let tmp = TempDir::new().unwrap();
    let fs = ArgosFs::create(tmp.path(), config(2, 2), 4, false).unwrap();

    fs.write_file("/utf8-target", b"utf8", 0o644).unwrap();
    fs.symlink_path("/utf8-target", "/utf8-link").unwrap();
    assert_eq!(fs.read_file("/utf8-link", true).unwrap(), b"utf8");

    let raw_name = OsString::from_vec(vec![b'n', b'o', b'n', 0xff]);
    let raw_path = std::path::PathBuf::from("/").join(&raw_name);
    fs.create_file_at(1, &raw_name, 0o644).unwrap();
    let ino = fs.lookup(1, &raw_name).unwrap().ino;
    fs.write_inode_range(ino, 0, b"raw-target").unwrap();

    fs.symlink_at(1, OsStr::new("raw-link"), &raw_path).unwrap();
    let link_ino = fs.resolve_path("/raw-link", false).unwrap();
    assert_eq!(
        fs.readlink_inode_bytes(link_ino).unwrap(),
        raw_path.as_os_str().as_bytes()
    );

    assert_eq!(
        fs.read_file("/raw-link", true).unwrap_err().errno(),
        libc::EINVAL
    );
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
fn invalid_entry_names_are_rejected_before_metadata_changes() {
    let tmp = TempDir::new().unwrap();
    let fs = ArgosFs::create(tmp.path(), config(2, 2), 4, false).unwrap();

    assert_eq!(
        fs.create_file_at(1, OsStr::new("."), 0o644)
            .unwrap_err()
            .errno(),
        libc::EINVAL
    );
    assert_eq!(
        fs.mkdir_at(1, OsStr::new("bad/name"), 0o755)
            .unwrap_err()
            .errno(),
        libc::EINVAL
    );
    assert_eq!(
        fs.symlink_at(1, OsStr::new(""), std::path::Path::new("/target"))
            .unwrap_err()
            .errno(),
        libc::EINVAL
    );
    assert!(fs.fsck(true, true).unwrap().errors.is_empty());
}

#[test]
fn readdir_reports_real_parent_for_dotdot() {
    let tmp = TempDir::new().unwrap();
    let fs = ArgosFs::create(tmp.path(), config(2, 2), 4, false).unwrap();
    fs.mkdir("/parent", 0o755).unwrap();
    fs.mkdir("/parent/child", 0o755).unwrap();
    let parent = fs.resolve_path("/parent", false).unwrap();
    let child = fs.resolve_path("/parent/child", false).unwrap();

    let child_entries = fs.readdir(child).unwrap();
    assert_eq!(
        child_entries
            .iter()
            .find(|entry| entry.name == "..")
            .unwrap()
            .attr
            .ino,
        parent
    );

    let root_entries = fs.readdir(1).unwrap();
    assert_eq!(
        root_entries
            .iter()
            .find(|entry| entry.name == "..")
            .unwrap()
            .attr
            .ino,
        1
    );
}

#[test]
fn failed_pre_journal_commit_reloads_in_memory_metadata() {
    let _guard = env_lock();
    let tmp = TempDir::new().unwrap();
    let fs = ArgosFs::create(tmp.path(), config(2, 2), 4, false).unwrap();

    journal::set_thread_crash_point(Some("before-journal"));
    let err = fs.mkdir("/ghost", 0o755).unwrap_err();
    journal::set_thread_crash_point(None);

    assert!(matches!(
        err,
        ArgosError::InjectedCrash(point) if point == "before-journal"
    ));
    assert_eq!(
        fs.resolve_path("/ghost", false).unwrap_err().errno(),
        libc::ENOENT
    );

    let reopened = ArgosFs::open(tmp.path()).unwrap();
    assert_eq!(
        reopened.resolve_path("/ghost", false).unwrap_err().errno(),
        libc::ENOENT
    );
}

#[test]
fn read_and_readdir_do_not_commit_metadata_transactions() {
    let tmp = TempDir::new().unwrap();
    let fs = ArgosFs::create(tmp.path(), config(2, 2), 4, false).unwrap();
    fs.write_file("/file", b"payload", 0o644).unwrap();
    let ino = fs.resolve_path("/file", false).unwrap();
    let txid = fs.metadata_snapshot().txid;

    assert_eq!(fs.read_inode(ino, 0, 7, true).unwrap(), b"payload");
    assert_eq!(fs.readdir(1).unwrap().len(), 3);
    assert_eq!(fs.metadata_snapshot().txid, txid);
}

#[test]
fn non_utf8_directory_entries_round_trip_through_fuse_style_apis() {
    let tmp = TempDir::new().unwrap();
    let fs = ArgosFs::create(tmp.path(), config(2, 2), 4, false).unwrap();
    let raw = OsString::from_vec(vec![b'f', 0xff, b'x']);
    fs.create_file_at(1, &raw, 0o644).unwrap();

    let attr = fs.lookup(1, &raw).unwrap();
    let entries = fs.readdir(1).unwrap();
    let entry = entries
        .iter()
        .find(|entry| entry.attr.ino == attr.ino)
        .unwrap();
    assert_eq!(entry.name_bytes, raw.as_bytes());
    assert_eq!(entry.os_name().as_bytes(), raw.as_bytes());
}

#[test]
fn empty_files_report_zero_blocks_and_directories_reject_stream_writes() {
    let tmp = TempDir::new().unwrap();
    let fs = ArgosFs::create(tmp.path(), config(2, 2), 4, false).unwrap();

    let empty = fs.create_file_at(1, OsStr::new("empty"), 0o644).unwrap();
    assert_eq!(empty.size, 0);
    assert_eq!(empty.blocks, 0);

    fs.mkdir("/dir", 0o755).unwrap();
    assert_eq!(
        fs.write_file("/dir", b"not a file", 0o644)
            .unwrap_err()
            .errno(),
        libc::EISDIR
    );
}

#[test]
fn chmod_path_follows_final_symlink_like_posix_chmod() {
    let tmp = TempDir::new().unwrap();
    let fs = ArgosFs::create(tmp.path(), config(2, 2), 4, false).unwrap();
    fs.write_file("/target", b"mode", 0o644).unwrap();
    fs.symlink_path("/target", "/link").unwrap();

    fs.chmod_path("/link", 0o600).unwrap();

    assert_eq!(fs.attr_path("/target", false).unwrap().mode & 0o7777, 0o600);
    assert_eq!(fs.attr_path("/link", false).unwrap().mode & 0o7777, 0o777);
}

#[test]
fn mkfs_force_cleans_partial_system_directory() {
    let tmp = TempDir::new().unwrap();
    let partial = tmp.path().join(".argosfs");
    fs::create_dir_all(&partial).unwrap();
    fs::write(partial.join("stale"), b"stale").unwrap();

    let err = match ArgosFs::create(tmp.path(), config(2, 2), 4, false) {
        Ok(_) => panic!("mkfs unexpectedly accepted a partial .argosfs directory"),
        Err(err) => err,
    };
    assert_eq!(err.errno(), libc::EEXIST);

    let fs = ArgosFs::create(tmp.path(), config(2, 2), 4, true).unwrap();
    assert!(!tmp.path().join(".argosfs/stale").exists());
    assert_eq!(fs.health_report().disks.len(), 4);
}

#[test]
fn add_disk_rejects_duplicate_storage_path() {
    let tmp = TempDir::new().unwrap();
    let fs = ArgosFs::create(tmp.path(), config(2, 2), 4, false).unwrap();
    let existing = fs
        .metadata_snapshot()
        .disks
        .get("disk-0000")
        .unwrap()
        .path
        .clone();

    let err = fs
        .add_disk(
            Some(existing),
            Some(StorageTier::Warm),
            Some(1.0),
            Some(0),
            false,
        )
        .unwrap_err();
    assert_eq!(err.errno(), libc::EEXIST);
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
fn rename_policy_supports_noreplace_exchange_and_sticky_checks() {
    let tmp = TempDir::new().unwrap();
    let fs = ArgosFs::create(tmp.path(), config(2, 2), 4, false).unwrap();
    fs.write_file("/a", b"alpha", 0o644).unwrap();
    fs.write_file("/b", b"beta", 0o644).unwrap();

    let err = fs
        .rename_at_with_policy(
            1,
            OsStr::new("a"),
            1,
            OsStr::new("b"),
            argosfs::volume::RenamePolicy {
                no_replace: true,
                exchange: false,
                uid: Some(0),
            },
        )
        .unwrap_err();
    assert_eq!(err.errno(), libc::EEXIST);

    fs.rename_at_with_policy(
        1,
        OsStr::new("a"),
        1,
        OsStr::new("b"),
        argosfs::volume::RenamePolicy {
            no_replace: false,
            exchange: true,
            uid: Some(0),
        },
    )
    .unwrap();
    assert_eq!(fs.read_file("/a", true).unwrap(), b"beta");
    assert_eq!(fs.read_file("/b", true).unwrap(), b"alpha");

    fs.mkdir("/tmp", libc::S_ISVTX | 0o777).unwrap();
    fs.create_file_at_with_owner(1, OsStr::new("owned"), 0o644, 1001, 1001)
        .unwrap();
    fs.rename_path("/owned", "/tmp/owned").unwrap();
    assert_eq!(
        fs.unlink_at_as(
            fs.resolve_path("/tmp", false).unwrap(),
            OsStr::new("owned"),
            2002
        )
        .unwrap_err()
        .errno(),
        libc::EACCES
    );
    fs.unlink_at_as(
        fs.resolve_path("/tmp", false).unwrap(),
        OsStr::new("owned"),
        1001,
    )
    .unwrap();
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
fn direct_io_detects_aligned_trailing_shard_garbage() {
    let tmp = TempDir::new().unwrap();
    let mut cfg = config(1, 1);
    cfg.chunk_size = 4096;
    cfg.compression = Compression::None;
    let fs = ArgosFs::create(tmp.path(), cfg, 2, false).unwrap();
    fs.set_io_policy(IoMode::Direct, true, false, true).unwrap();
    let payload = vec![7u8; 4096];
    fs.write_file("/file", &payload, 0o644).unwrap();

    let meta = fs.metadata_snapshot();
    let inode = meta
        .inodes
        .values()
        .find(|inode| inode.size == 4096)
        .unwrap();
    let shard = &inode.blocks[0].shards[0];
    let mut file = fs::OpenOptions::new()
        .append(true)
        .open(shard_abs(&fs, &shard.disk_id, &shard.relpath))
        .unwrap();
    file.write_all(&vec![9u8; 4096]).unwrap();
    file.sync_all().unwrap();

    let report = fs.fsck(true, true).unwrap();
    assert_eq!(report.damaged_files, 1);
    assert_eq!(report.repaired_files, 1);
    assert_eq!(fs.read_file("/file", true).unwrap(), payload);
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
fn autopilot_confirms_risk_before_draining_and_keeps_data_available() {
    let tmp = TempDir::new().unwrap();
    let fs = ArgosFs::create(tmp.path(), config(2, 2), 5, false).unwrap();
    fs.write_file("/a", b"alpha", 0o644).unwrap();
    fs.write_file("/b", b"beta", 0o644).unwrap();

    let mut health = fs
        .metadata_snapshot()
        .disks
        .get("disk-0001")
        .unwrap()
        .health
        .clone();
    health.pending_sectors = 12;
    fs.set_disk_health("disk-0001", health).unwrap();

    let autopilot = AutopilotConfig {
        probe_interval_sec: u64::MAX,
        smart_interval_sec: u64::MAX,
        scrub_interval_sec: u64::MAX,
        rebalance_interval_sec: u64::MAX,
        risk_confirmations: 2,
        ..AutopilotConfig::default()
    };

    let first = fs.autopilot_once_with_config(autopilot.clone()).unwrap();
    assert!(first["actions"].as_array().unwrap().iter().any(|action| {
        action["action"] == "observe-predicted-failure" && action["disk_id"] == "disk-0001"
    }));
    assert_eq!(
        fs.metadata_snapshot().disks["disk-0001"].status,
        DiskStatus::Online
    );

    let second = fs.autopilot_once_with_config(autopilot).unwrap();
    assert!(second["actions"].as_array().unwrap().iter().any(|action| {
        action["action"] == "drain-predicted-failure" && action["disk_id"] == "disk-0001"
    }));
    assert_eq!(
        fs.metadata_snapshot().disks["disk-0001"].status,
        DiskStatus::Degraded
    );
    assert_eq!(fs.read_file("/a", true).unwrap(), b"alpha");
    assert_eq!(fs.read_file("/b", true).unwrap(), b"beta");
}

#[test]
fn autopilot_rebalances_with_a_file_budget() {
    let tmp = TempDir::new().unwrap();
    let fs = ArgosFs::create(tmp.path(), config(2, 2), 5, false).unwrap();
    for index in 0..5 {
        fs.write_file(
            &format!("/file-{index}"),
            format!("payload-{index}").as_bytes(),
            0o644,
        )
        .unwrap();
    }
    fs.add_disk(None, Some(StorageTier::Warm), Some(1.0), Some(0), false)
        .unwrap();

    let result = fs
        .autopilot_once_with_config(AutopilotConfig {
            probe_interval_sec: u64::MAX,
            smart_interval_sec: u64::MAX,
            scrub_interval_sec: u64::MAX,
            rebalance_interval_sec: 0,
            rebalance_files_per_run: 2,
            rebalance_min_skew: 0.0,
            ..AutopilotConfig::default()
        })
        .unwrap();
    let rebalance = result["actions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|action| action["action"] == "rebalance-incremental")
        .unwrap();
    assert!(rebalance["rewritten_files"].as_u64().unwrap() <= 2);
}

#[test]
fn stale_metadata_commits_are_rejected_instead_of_overwriting_newer_state() {
    let tmp = TempDir::new().unwrap();
    let fs1 = ArgosFs::create(tmp.path(), config(2, 2), 4, false).unwrap();
    let fs2 = ArgosFs::open(tmp.path()).unwrap();

    fs1.write_file("/fresh", b"fresh", 0o644).unwrap();
    let err = fs2.write_file("/stale", b"stale", 0o644).unwrap_err();
    assert!(matches!(err, ArgosError::Conflict(_)));

    assert_eq!(fs2.read_file("/fresh", true).unwrap(), b"fresh");
    fs2.write_file("/after-conflict", b"ok", 0o644).unwrap();

    let reopened = ArgosFs::open(tmp.path()).unwrap();
    assert_eq!(reopened.read_file("/fresh", true).unwrap(), b"fresh");
    assert_eq!(reopened.read_file("/after-conflict", true).unwrap(), b"ok");
    assert!(matches!(
        reopened.read_file("/stale", true).unwrap_err(),
        ArgosError::NotFound(_)
    ));
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
fn oversized_stripe_config_returns_error_instead_of_panicking() {
    let tmp = TempDir::new().unwrap();
    let mut cfg = config(2, 1);
    cfg.chunk_size = usize::MAX;
    let fs = ArgosFs::create(tmp.path(), cfg, 3, false).unwrap();

    let err = fs.write_file("/oversized", b"x", 0o644).unwrap_err();
    assert_eq!(err.errno(), libc::EINVAL);
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
fn xattr_namespaces_are_explicitly_enforced() {
    let tmp = TempDir::new().unwrap();
    let fs = ArgosFs::create(tmp.path(), config(2, 2), 4, false).unwrap();
    fs.write_file("/file", b"xattr", 0o644).unwrap();
    let ino = fs.resolve_path("/file", false).unwrap();

    fs.setxattr_inode(ino, "user.ok", b"1").unwrap();
    assert_eq!(fs.getxattr_inode(ino, "user.ok").unwrap(), b"1");
    assert_eq!(
        fs.setxattr_inode(ino, "trusted.nope", b"1")
            .unwrap_err()
            .errno(),
        libc::EACCES
    );
    assert_eq!(
        fs.setxattr_inode(ino, "system.unknown", b"1")
            .unwrap_err()
            .errno(),
        libc::ENOTSUP
    );
    fs.setxattr_inode(ino, "system.argosfs.boot_critical", b"true")
        .unwrap();
    assert!(fs.metadata_snapshot().inodes[&ino].boot_critical);
}

#[test]
fn posix_acl_parser_rejects_malformed_entries() {
    assert!(acl::parse_posix_acl("user::r-q").is_err());
    assert!(acl::parse_posix_acl("mask:7:rwx").is_err());
    assert!(acl::parse_posix_acl("other:99:---").is_err());

    let mut encoded = Vec::new();
    encoded.extend_from_slice(&0x0002u32.to_le_bytes());
    encoded.extend_from_slice(&0x02u16.to_le_bytes());
    encoded.extend_from_slice(&0o7u16.to_le_bytes());
    encoded.extend_from_slice(&u32::MAX.to_le_bytes());
    assert!(acl::parse_posix_acl_xattr(&encoded).is_err());
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
fn encrypted_reads_do_not_persist_plaintext_in_l2_cache() {
    let _env_guard = env_lock();
    let tmp = TempDir::new().unwrap();
    let mut cfg = config(2, 2);
    cfg.l2_cache_bytes = 1024 * 1024;
    let fs = ArgosFs::create(tmp.path(), cfg, 4, false).unwrap();
    let key = "cache safety key";
    let payload = b"argosfs encrypted payload must not be cached in plaintext";

    fs.enable_encryption(key).unwrap();
    std::env::set_var("ARGOSFS_KEY", key);
    fs.write_file("/secret", payload, 0o600).unwrap();
    assert_eq!(fs.read_file("/secret", true).unwrap(), payload);
    std::env::remove_var("ARGOSFS_KEY");

    assert!(!tree_contains_bytes(
        &tmp.path().join(".argosfs/cache/l2"),
        payload
    ));
}

#[test]
fn reencrypt_removes_old_plaintext_l2_cache_entries() {
    let _env_guard = env_lock();
    let tmp = TempDir::new().unwrap();
    let mut cfg = config(2, 2);
    cfg.l2_cache_bytes = 1024 * 1024;
    let fs = ArgosFs::create(tmp.path(), cfg, 4, false).unwrap();
    let payload = b"plaintext cached before encryption";

    fs.write_file("/plain", payload, 0o600).unwrap();
    assert_eq!(fs.read_file("/plain", true).unwrap(), payload);
    assert!(tree_contains_bytes(
        &tmp.path().join(".argosfs/cache/l2"),
        payload
    ));

    let key = "reencrypt cache cleanup key";
    fs.enable_encryption(key).unwrap();
    std::env::set_var("ARGOSFS_KEY", key);
    fs.rebalance().unwrap();
    std::env::remove_var("ARGOSFS_KEY");

    assert!(!tree_contains_bytes(
        &tmp.path().join(".argosfs/cache/l2"),
        payload
    ));
}

#[test]
fn key_files_accept_crlf_line_endings() {
    let _env_guard = env_lock();
    let tmp = TempDir::new().unwrap();
    let key_file = tmp.path().join("key");
    fs::write(&key_file, b"secret\r\n").unwrap();

    std::env::set_var("ARGOSFS_KEY_FILE", &key_file);
    assert_eq!(crypto::passphrase_from_env().unwrap().unwrap(), "secret");
    std::env::remove_var("ARGOSFS_KEY_FILE");
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
    assert_eq!(metrics.matches("# HELP argosfs_disk_used_bytes").count(), 1);
}

#[test]
fn l2_cache_enforces_limit_and_evicts_bad_entries() {
    let tmp = TempDir::new().unwrap();
    let cache = BlockCache::new(tmp.path(), 0, 6);
    cache.put("a", b"1234").unwrap();
    cache.put("b", b"5678").unwrap();
    assert!(directory_size(tmp.path()) <= 6);

    let corrupt_root = tmp.path().join("corrupt");
    let cache = BlockCache::new(&corrupt_root, 16, 128);
    cache.put("bad", b"stale").unwrap();
    assert!(cache.get("bad", Some(&sha256_hex(b"fresh"))).is_none());
    assert_eq!(cache.stats()["memory_items"], serde_json::json!(0));
    assert_eq!(directory_size(&corrupt_root), 0);
}

#[test]
fn l2_cache_hit_refreshes_prune_recency_without_rewriting_file() {
    let tmp = TempDir::new().unwrap();

    {
        let cache = BlockCache::new(tmp.path(), 0, 8);
        cache.put("old-hot", b"1111").unwrap();
        cache.put("old-cold", b"2222").unwrap();
    }

    let cache = BlockCache::new(tmp.path(), 4, 8);
    assert_eq!(
        cache.get("old-hot", Some(&sha256_hex(b"1111"))).unwrap(),
        b"1111"
    );
    assert_eq!(cache.stats()["l2_hits"].as_u64().unwrap(), 1);

    cache.put("new", b"3333").unwrap();

    assert_eq!(
        cache.get("old-hot", Some(&sha256_hex(b"1111"))).unwrap(),
        b"1111"
    );
    assert!(cache.get("old-cold", Some(&sha256_hex(b"2222"))).is_none());
}

#[test]
fn l2_cache_hit_promotes_to_memory_without_rewriting_l2() {
    let tmp = TempDir::new().unwrap();
    let cache = BlockCache::new(tmp.path(), 4, 1024);
    cache.put("block", b"data").unwrap();
    drop(cache);
    let cache = BlockCache::new(tmp.path(), 4, 1024);
    assert_eq!(
        cache.get("block", Some(&sha256_hex(b"data"))).unwrap(),
        b"data"
    );
    assert_eq!(cache.stats()["l2_hits"].as_u64().unwrap(), 1);
    assert_eq!(cache.stats()["l2_writes"].as_u64().unwrap(), 0);
}

#[test]
fn user_capacity_override_survives_disk_probe_refresh() {
    let tmp = TempDir::new().unwrap();
    let fs = ArgosFs::create(tmp.path(), config(1, 1), 2, false).unwrap();
    fs.add_disk(None, Some(StorageTier::Warm), Some(1.0), Some(12345), false)
        .unwrap();
    fs.refresh_disk_probe(Some("disk-0002")).unwrap();
    let disk = fs.metadata_snapshot().disks["disk-0002"].clone();
    assert_eq!(disk.capacity_bytes, 12345);
    assert_eq!(
        disk.capacity_source,
        argosfs::types::CapacitySource::UserOverride
    );
}

#[test]
fn export_tree_replaces_existing_leaf_symlink_without_following_it() {
    let tmp = TempDir::new().unwrap();
    let volume = tmp.path().join("volume");
    let export = tmp.path().join("export");
    let outside = tmp.path().join("outside.txt");
    let binary = argosfs_binary();

    let fs = ArgosFs::create(&volume, config(2, 2), 4, false).unwrap();
    fs.mkdir("/data", 0o755).unwrap();
    fs.write_file("/data/file.txt", b"inside export", 0o644)
        .unwrap();
    drop(fs);

    fs::create_dir_all(export.join("data")).unwrap();
    fs::write(&outside, b"outside sentinel").unwrap();
    std::os::unix::fs::symlink(&outside, export.join("data/file.txt")).unwrap();

    let status = Command::new(binary)
        .arg("export-tree")
        .arg(&volume)
        .arg(&export)
        .status()
        .unwrap();
    assert!(status.success());
    assert_eq!(fs::read(&outside).unwrap(), b"outside sentinel");
    assert_eq!(
        fs::read(export.join("data/file.txt")).unwrap(),
        b"inside export"
    );
}

#[test]
fn import_tree_creates_nested_destination_directories() {
    let tmp = TempDir::new().unwrap();
    let volume = tmp.path().join("volume");
    let source = tmp.path().join("source");
    let binary = argosfs_binary();

    ArgosFs::create(&volume, config(2, 2), 4, false).unwrap();
    fs::create_dir_all(&source).unwrap();
    fs::write(source.join("file.txt"), b"nested import").unwrap();

    let status = Command::new(binary)
        .arg("import-tree")
        .arg(&volume)
        .arg(&source)
        .arg("/nested/dest")
        .status()
        .unwrap();
    assert!(status.success());

    let fs = ArgosFs::open(&volume).unwrap();
    assert_eq!(
        fs.read_file("/nested/dest/file.txt", true).unwrap(),
        b"nested import"
    );
}

#[test]
fn import_tree_canonicalizes_dotdot_destination_components() {
    let tmp = TempDir::new().unwrap();
    let volume = tmp.path().join("volume");
    let source = tmp.path().join("source");
    let binary = argosfs_binary();

    ArgosFs::create(&volume, config(2, 2), 4, false).unwrap();
    fs::create_dir_all(&source).unwrap();
    fs::write(source.join("file.txt"), b"clean import").unwrap();

    let status = Command::new(binary)
        .arg("import-tree")
        .arg(&volume)
        .arg(&source)
        .arg("/nested/../clean/./dest/")
        .status()
        .unwrap();
    assert!(status.success());

    let fs = ArgosFs::open(&volume).unwrap();
    assert_eq!(
        fs.read_file("/clean/dest/file.txt", true).unwrap(),
        b"clean import"
    );
    assert!(fs.resolve_path("/nested", false).is_err());
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
