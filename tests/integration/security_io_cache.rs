use super::*;

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
    assert!(cache
        .get("bad", Some(&content_hash_hex(b"fresh")))
        .is_none());
    assert_eq!(cache.stats()["memory_items"], serde_json::json!(0));
    assert_eq!(directory_size(&corrupt_root), 0);
}

#[test]
fn l2_cache_write_failure_does_not_break_memory_cache() {
    let tmp = TempDir::new().unwrap();
    let blocked_root = tmp.path().join("not-a-directory");
    fs::write(&blocked_root, b"file blocks cache directory creation").unwrap();
    let cache = BlockCache::new(&blocked_root, 16, 1024);

    cache.put("block", b"data").unwrap();

    assert_eq!(
        cache
            .get("block", Some(&content_hash_hex(b"data")))
            .unwrap(),
        b"data"
    );
    assert_eq!(cache.stats()["l2_errors"].as_u64().unwrap(), 1);
    assert_eq!(cache.stats()["l2_writes"].as_u64().unwrap(), 0);
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
        cache
            .get("old-hot", Some(&content_hash_hex(b"1111")))
            .unwrap(),
        b"1111"
    );
    assert_eq!(cache.stats()["l2_hits"].as_u64().unwrap(), 1);

    cache.put("new", b"3333").unwrap();

    assert_eq!(
        cache
            .get("old-hot", Some(&content_hash_hex(b"1111")))
            .unwrap(),
        b"1111"
    );
    assert!(cache
        .get("old-cold", Some(&content_hash_hex(b"2222")))
        .is_none());
}

#[test]
fn l2_cache_hit_promotes_to_memory_without_rewriting_l2() {
    let tmp = TempDir::new().unwrap();
    let cache = BlockCache::new(tmp.path(), 4, 1024);
    cache.put("block", b"data").unwrap();
    drop(cache);
    let cache = BlockCache::new(tmp.path(), 4, 1024);
    assert_eq!(
        cache
            .get("block", Some(&content_hash_hex(b"data")))
            .unwrap(),
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
fn matching_posix_acl_group_does_not_fall_through_to_other() {
    let tmp = TempDir::new().unwrap();
    let fs = ArgosFs::create(tmp.path(), config(1, 0), 1, false).unwrap();
    let attr = fs
        .create_file_at_with_owner(1, OsStr::new("group-acl"), 0o604, 0, 0)
        .unwrap();
    fs.set_posix_acl_path(
        "/group-acl",
        false,
        acl::parse_posix_acl("user::rw-,group::---,group:1000:---,mask::rwx,other::r--").unwrap(),
    )
    .unwrap();

    assert_eq!(
        fs.check_access_inode(attr.ino, 2000, 1000, libc::R_OK)
            .unwrap_err()
            .errno(),
        libc::EACCES
    );
}

#[test]
fn root_execute_check_requires_an_execute_bit_for_regular_files() {
    let tmp = TempDir::new().unwrap();
    let fs = ArgosFs::create(tmp.path(), config(1, 0), 1, false).unwrap();
    let file = fs
        .create_file_at_with_owner(1, OsStr::new("not-executable"), 0o600, 1000, 1000)
        .unwrap();
    assert_eq!(
        fs.check_access_inode(file.ino, 0, 0, libc::X_OK)
            .unwrap_err()
            .errno(),
        libc::EACCES
    );
    fs.mkdir("/searchable-by-root", 0o000).unwrap();
    let dir = fs.resolve_path("/searchable-by-root", false).unwrap();
    fs.check_access_inode(dir, 0, 0, libc::X_OK).unwrap();
}

#[test]
fn chmod_updates_effective_posix_acl_permissions() {
    let tmp = TempDir::new().unwrap();
    let fs = ArgosFs::create(tmp.path(), config(1, 0), 1, false).unwrap();
    let attr = fs
        .create_file_at_with_owner(1, OsStr::new("chmod-acl"), 0o600, 1000, 1000)
        .unwrap();
    fs.set_posix_acl_path(
        "/chmod-acl",
        false,
        acl::parse_posix_acl("user::rw-,group::---,mask::---,other::---").unwrap(),
    )
    .unwrap();
    fs.check_access_inode(attr.ino, 1000, 1000, libc::R_OK)
        .unwrap();

    fs.chmod_inode(attr.ino, 0).unwrap();
    assert_eq!(
        fs.check_access_inode(attr.ino, 1000, 1000, libc::R_OK)
            .unwrap_err()
            .errno(),
        libc::EACCES
    );
}

#[test]
fn inherited_default_acl_is_restricted_by_creation_mode() {
    let tmp = TempDir::new().unwrap();
    let fs = ArgosFs::create(tmp.path(), config(1, 0), 1, false).unwrap();
    fs.mkdir("/parent", 0o777).unwrap();
    fs.set_posix_acl_path(
        "/parent",
        true,
        acl::parse_posix_acl("user::rwx,user:2000:rwx,group::rwx,mask::rwx,other::rwx").unwrap(),
    )
    .unwrap();
    let parent = fs.resolve_path("/parent", false).unwrap();
    let child = fs
        .create_file_at_with_owner(parent, OsStr::new("private"), 0o600, 1000, 1000)
        .unwrap();

    assert_eq!(child.mode & 0o777, 0o600);
    assert_eq!(
        fs.check_access_inode(child.ino, 2000, 2000, libc::R_OK)
            .unwrap_err()
            .errno(),
        libc::EACCES
    );
}

#[test]
fn content_and_owner_changes_clear_setid_bits() {
    let tmp = TempDir::new().unwrap();
    let fs = ArgosFs::create(tmp.path(), config(1, 0), 1, false).unwrap();
    let attr = fs
        .create_file_at_with_owner(1, OsStr::new("setid"), 0o6755, 0, 0)
        .unwrap();
    fs.set_posix_acl_path(
        "/setid",
        false,
        acl::parse_posix_acl("user::rwx,user:1000:rw-,group::r-x,mask::rwx,other::r-x").unwrap(),
    )
    .unwrap();

    fs.write_inode_range_as(attr.ino, 0, b"replacement", 1000, 1000)
        .unwrap();
    assert_eq!(fs.attr_inode(attr.ino).unwrap().mode & 0o6000, 0);

    fs.chmod_inode(attr.ino, 0o6755).unwrap();
    fs.truncate_inode_as(attr.ino, 1).unwrap();
    assert_eq!(fs.attr_inode(attr.ino).unwrap().mode & 0o6000, 0);

    fs.chmod_inode(attr.ino, 0o6755).unwrap();
    fs.chown_inode(attr.ino, Some(1234), Some(1234)).unwrap();
    assert_eq!(fs.attr_inode(attr.ino).unwrap().mode & 0o6000, 0);
}

#[test]
fn supplementary_groups_are_used_for_mode_and_acl_checks() {
    let tmp = TempDir::new().unwrap();
    let fs = ArgosFs::create(tmp.path(), config(1, 0), 1, false).unwrap();
    let mode_file = fs
        .create_file_at_with_owner(1, OsStr::new("mode-group"), 0o640, 1000, 2000)
        .unwrap();
    fs.check_access_inode_with_groups(mode_file.ino, 3000, &[3000, 2000], libc::R_OK)
        .unwrap();

    let acl_file = fs
        .create_file_at_with_owner(1, OsStr::new("acl-group"), 0o600, 1000, 1000)
        .unwrap();
    fs.set_posix_acl_path(
        "/acl-group",
        false,
        acl::parse_posix_acl("user::rw-,group::---,group:2000:r--,mask::r--,other::---").unwrap(),
    )
    .unwrap();
    fs.check_access_inode_with_groups(acl_file.ino, 3000, &[3000, 2000], libc::R_OK)
        .unwrap();
}
