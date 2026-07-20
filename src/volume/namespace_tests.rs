use super::*;
use std::ffi::OsStr;
use std::os::unix::ffi::OsStringExt;
use tempfile::tempdir;

fn volume() -> (tempfile::TempDir, ArgosFs) {
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
        1,
        false,
    )
    .unwrap();
    (dir, fs)
}

#[test]
fn entry_names_round_trip_utf8_reserved_prefixes_and_non_utf8_bytes() {
    for invalid in ["", ".", "..", "a/b", "a\0b"] {
        assert!(validate_entry_name(invalid).is_err());
        assert!(entry_name_from_str(invalid).is_err());
    }
    assert!(matches!(
        validate_entry_name_bytes(&vec![b'x'; 256]),
        Err(ArgosError::NameTooLong(_))
    ));
    for invalid in [
        b"".as_slice(),
        b".".as_slice(),
        b"..".as_slice(),
        b"a/b",
        b"a\0b",
    ] {
        assert!(validate_entry_name_bytes(invalid).is_err());
    }

    assert_eq!(entry_name_from_str("normal").unwrap(), "normal");
    let reserved = format!("{NON_UTF8_NAME_PREFIX}literal");
    let encoded_reserved = entry_name_from_str(&reserved).unwrap();
    assert!(encoded_reserved.starts_with(ESCAPED_UTF8_NAME_PREFIX));
    assert_eq!(
        decode_entry_name_bytes(&encoded_reserved),
        reserved.as_bytes()
    );

    let bytes = b"name-\xff";
    let non_utf8 = std::ffi::OsString::from_vec(bytes.to_vec());
    let encoded = entry_name_from_os(&non_utf8).unwrap();
    assert!(encoded.starts_with(NON_UTF8_NAME_PREFIX));
    assert_eq!(decode_entry_name_bytes(&encoded), bytes);
    assert_eq!(display_entry_name(bytes), "name-�");
    assert_eq!(decode_entry_name_bytes("plain"), b"plain");
    assert_eq!(
        decode_entry_name_bytes(&format!("{NON_UTF8_NAME_PREFIX}not-hex")),
        format!("{NON_UTF8_NAME_PREFIX}not-hex").as_bytes()
    );
}

#[test]
fn symlink_targets_round_trip_non_utf8_and_invalid_encoded_text_falls_back() {
    let target = Path::new("relative/target");
    assert_eq!(encode_symlink_target(target), "relative/target");
    assert_eq!(
        decode_symlink_target_bytes("relative/target"),
        b"relative/target"
    );

    let raw = std::ffi::OsString::from_vec(b"target-\xff".to_vec());
    let encoded = encode_symlink_target(Path::new(&raw));
    assert!(encoded.starts_with(NON_UTF8_SYMLINK_TARGET_PREFIX));
    assert_eq!(decode_symlink_target_bytes(&encoded), b"target-\xff");
    let invalid = format!("{NON_UTF8_SYMLINK_TARGET_PREFIX}bad-hex");
    assert_eq!(decode_symlink_target_bytes(&invalid), invalid.as_bytes());
}

#[test]
fn xattr_namespace_validation_covers_every_linux_namespace() {
    assert_eq!(xattr_namespace("user.key").unwrap(), XattrNamespace::User);
    assert_eq!(
        xattr_namespace("trusted.key").unwrap(),
        XattrNamespace::Trusted
    );
    assert_eq!(
        xattr_namespace("security.key").unwrap(),
        XattrNamespace::Security
    );
    assert_eq!(
        xattr_namespace("system.key").unwrap(),
        XattrNamespace::System
    );
    assert_eq!(
        xattr_namespace("system.argosfs.key").unwrap(),
        XattrNamespace::ArgosSystem
    );
    for invalid in ["", "plain", "user.bad\0name"] {
        assert!(xattr_namespace(invalid).is_err());
    }
    assert!(validate_xattr_write("user.key").is_ok());
    assert!(matches!(
        validate_xattr_write("trusted.key"),
        Err(ArgosError::PermissionDenied(_))
    ));
    assert!(matches!(
        validate_xattr_write("security.key"),
        Err(ArgosError::PermissionDenied(_))
    ));
    assert!(matches!(
        validate_xattr_write("system.key"),
        Err(ArgosError::Unsupported(_))
    ));
    assert!(matches!(
        validate_xattr_write("system.argosfs.private"),
        Err(ArgosError::Unsupported(_))
    ));
    for readable in ["user.key", "trusted.key", "security.key", "system.key"] {
        assert!(validate_xattr_read(readable).is_ok());
    }
    assert!(validate_xattr_read("system.argosfs.private").is_err());
    for known in [
        acl::POSIX_ACL_ACCESS_XATTR,
        acl::POSIX_ACL_DEFAULT_XATTR,
        acl::ARGOS_POSIX_ACL_ACCESS_XATTR,
        acl::ARGOS_POSIX_ACL_DEFAULT_XATTR,
        acl::NFS4_ACL_XATTR,
        BOOT_CRITICAL_XATTR,
    ] {
        assert!(is_known_system_xattr(known));
        assert!(validate_xattr_write(known).is_ok());
        assert!(validate_xattr_read(known).is_ok());
    }
    assert!(!is_known_system_xattr("system.unknown"));
    for name in ["boot", "etc", "bin", "sbin", "lib", "lib64", "usr", "init"] {
        assert!(boot_critical_name(name));
    }
    assert!(!boot_critical_name("home"));
}

#[test]
fn seek_copy_and_fallocate_cover_success_and_invalid_ranges() {
    let (_dir, fs) = volume();
    fs.write_file("/src", b"abcdefghij", 0o600).unwrap();
    fs.write_file("/dst", b"0123456789", 0o600).unwrap();
    let src = fs.resolve_path("/src", true).unwrap();
    let dst = fs.resolve_path("/dst", true).unwrap();
    let directory = fs.mkdir("/dir", 0o755).unwrap();
    let special = fs.mknod_path("/fifo", libc::S_IFIFO | 0o600, 0).unwrap();

    assert_eq!(fs.seek_data_or_hole(src, 0, libc::SEEK_DATA).unwrap(), 0);
    assert_eq!(fs.seek_data_or_hole(src, 2, libc::SEEK_HOLE).unwrap(), 10);
    assert!(fs.seek_data_or_hole(src, 0, 12345).is_err());
    assert!(fs.seek_data_or_hole(directory, 0, libc::SEEK_DATA).is_err());
    assert!(fs.seek_data_or_hole(9999, 0, libc::SEEK_DATA).is_err());

    assert_eq!(fs.copy_inode_range(src, 2, dst, 4, 4).unwrap(), 4);
    assert_eq!(fs.read_file("/dst", true).unwrap(), b"0123cdef89");
    assert_eq!(fs.copy_inode_range(src, 0, dst, 0, 0).unwrap(), 0);
    assert_eq!(fs.copy_inode_range(src, 100, dst, 0, 4).unwrap(), 0);
    assert!(fs.copy_inode_range(src, 0, src, 2, 5).is_err());
    assert!(fs.copy_inode_range(src, u64::MAX, src, 0, 2).is_err());
    assert!(fs.copy_inode_range(src, 0, src, u64::MAX, 2).is_err());
    assert!(fs.copy_inode_range(directory, 0, dst, 0, 1).is_err());
    assert!(fs.copy_inode_range(src, 0, directory, 0, 1).is_err());

    assert!(fs
        .fallocate_inode(src, 0, 1, libc::FALLOC_FL_KEEP_SIZE)
        .is_err());
    assert!(fs.fallocate_inode(src, 0, 0, 0).is_err());
    assert!(fs.fallocate_inode(src, u64::MAX, 2, 0).is_err());
    assert!(matches!(
        fs.fallocate_inode(directory, 0, 1, 0),
        Err(ArgosError::IsDirectory(_))
    ));
    assert!(fs.fallocate_inode(special, 0, 1, 0).is_err());
    fs.fallocate_inode(src, 0, 20, 0).unwrap();
    assert_eq!(fs.attr_inode(src).unwrap().size, 20);
    fs.fallocate_inode(src, 0, 5, 0).unwrap();
}

#[test]
fn writes_and_truncates_cover_permissions_sparse_gaps_and_setid_clearing() {
    let (_dir, fs) = volume();
    let file = fs
        .create_file_at_with_owner(ROOT_INO, OsStr::new("owned"), 0o6750, 1000, 2000)
        .unwrap();
    assert!(matches!(
        fs.write_inode_range_as(file.ino, 0, b"x", 3000, 3000),
        Err(ArgosError::PermissionDenied(_))
    ));
    assert_eq!(
        fs.write_inode_range_as(file.ino, 0, b"abc", 1000, 2000)
            .unwrap(),
        3
    );
    assert_eq!(fs.attr_inode(file.ino).unwrap().mode & 0o6000, 0);
    assert_eq!(fs.write_inode_range(file.ino, 10, b"z").unwrap(), 1);
    assert_eq!(
        fs.read_inode(file.ino, 0, 32, true).unwrap(),
        b"abc\0\0\0\0\0\0\0z"
    );
    assert_eq!(fs.write_inode_range(file.ino, 0, b"").unwrap(), 0);
    fs.truncate_inode(file.ino, 11).unwrap();
    fs.truncate_inode(file.ino, 4).unwrap();
    assert_eq!(fs.read_inode(file.ino, 0, 32, true).unwrap(), b"abc\0");
    fs.truncate_inode(file.ino, 12).unwrap();
    assert_eq!(fs.attr_inode(file.ino).unwrap().size, 12);
    assert_eq!(fs.read_inode(file.ino, 4, 8, true).unwrap(), vec![0; 8]);
    assert!(fs.truncate_inode(ROOT_INO, 0).is_err());
    assert!(fs.truncate_inode(9999, 0).is_err());
}

#[test]
fn directory_link_unlink_and_rename_type_rules_are_enforced() {
    let (_dir, fs) = volume();
    let a = fs.mkdir("/a", 0o755).unwrap();
    let b = fs.mkdir("/b", 0o755).unwrap();
    let file = fs.create_file_path("/a/file", 0o600).unwrap();
    fs.write_inode_range(file, 0, b"data").unwrap();
    assert!(fs.link_at(a, b, OsStr::new("dir-link")).is_err());
    assert!(fs.link_at(9999, b, OsStr::new("missing")).is_err());
    fs.link_at(file, b, OsStr::new("hard")).unwrap();
    assert_eq!(fs.attr_inode(file).unwrap().nlink, 2);
    assert!(fs.link_at(file, b, OsStr::new("hard")).is_err());

    assert!(fs.rmdir_path("/a").is_err());
    assert!(fs.unlink_path("/a").is_err());
    assert!(fs.rmdir_path("/a/file").is_err());
    fs.unlink_path("/a/file").unwrap();
    assert_eq!(fs.attr_inode(file).unwrap().nlink, 1);
    fs.unlink_at_as_preserving_open(b, OsStr::new("hard"), current_uid())
        .unwrap();
    assert!(fs.attr_inode(file).is_ok());
    fs.reap_unlinked_inode(file).unwrap();
    assert!(fs.attr_inode(file).is_err());
    fs.rmdir_path("/a").unwrap();

    fs.write_file("/b/one", b"1", 0o600).unwrap();
    fs.write_file("/b/two", b"2", 0o600).unwrap();
    assert!(fs
        .rename_at_with_policy(
            b,
            OsStr::new("one"),
            b,
            OsStr::new("two"),
            RenamePolicy {
                no_replace: true,
                ..RenamePolicy::default()
            },
        )
        .is_err());
    fs.rename_at_with_policy(
        b,
        OsStr::new("one"),
        b,
        OsStr::new("two"),
        RenamePolicy {
            exchange: true,
            ..RenamePolicy::default()
        },
    )
    .unwrap();
    assert_eq!(fs.read_file("/b/one", true).unwrap(), b"2");
    assert_eq!(fs.read_file("/b/two", true).unwrap(), b"1");
    assert!(fs.rename_path("/b/missing", "/b/new").is_err());
}

#[test]
fn symlink_and_readdir_cover_following_raw_bytes_and_errors() {
    let (_dir, fs) = volume();
    let directory = fs.mkdir("/dir", 0o755).unwrap();
    fs.write_file("/target", b"data", 0o600).unwrap();
    fs.symlink_path("../target", "/dir/link").unwrap();
    let link = fs.resolve_path("/dir/link", false).unwrap();
    assert_eq!(fs.readlink_inode(link).unwrap(), "../target");
    assert_eq!(fs.read_inode(link, 0, 1024, false).unwrap(), b"../target");
    assert_eq!(
        fs.resolve_path("/dir/link", true).unwrap(),
        fs.resolve_path("/target", true).unwrap()
    );
    assert!(fs.readlink_inode(ROOT_INO).is_err());
    assert!(fs.readlink_inode(9999).is_err());
    assert!(fs.symlink_path("x", "/dir/link").is_err());

    let entries = fs.readdir(directory).unwrap();
    assert!(entries.iter().any(|entry| entry.name == "."));
    assert!(entries.iter().any(|entry| entry.name == ".."));
    assert!(entries.iter().any(|entry| entry.name == "link"));
    assert!(fs.readdir(link).is_err());
    assert!(fs.lookup(directory, OsStr::new("missing")).is_err());
    assert!(fs.lookup(9999, OsStr::new("missing")).is_err());
}

#[test]
fn chmod_chown_utimens_and_access_enforce_owner_and_group_rules() {
    let (_dir, fs) = volume();
    let file = fs
        .create_file_at_with_owner(ROOT_INO, OsStr::new("owned"), 0o640, 1000, 2000)
        .unwrap();
    assert!(fs.chmod_inode_as(file.ino, 0o600, 3000, &[3000]).is_err());
    let attr = fs.chmod_inode_as(file.ino, 0o2640, 1000, &[3000]).unwrap();
    assert_eq!(attr.mode & libc::S_ISGID, 0);
    let attr = fs.chmod_inode_as(file.ino, 0o2640, 1000, &[2000]).unwrap();
    assert_ne!(attr.mode & libc::S_ISGID, 0);
    assert!(fs
        .chown_inode_as(file.ino, Some(1001), None, 1000, &[2000])
        .is_err());
    assert!(fs
        .chown_inode_as(file.ino, None, Some(3000), 1000, &[2000])
        .is_err());
    assert!(fs
        .chown_inode_as(file.ino, None, Some(2000), 3000, &[2000])
        .is_err());
    let unchanged = fs.chown_inode(file.ino, None, None).unwrap();
    assert_eq!(unchanged.uid, 1000);
    let changed = fs
        .chown_inode_as(file.ino, None, Some(3000), 0, &[])
        .unwrap();
    assert_eq!(changed.gid, 3000);
    assert_eq!(changed.mode & 0o6000, 0);
    let timed = fs.utimens_inode(file.ino, 10.5, 20.25).unwrap();
    assert_eq!(timed.atime, 10.5);
    assert_eq!(timed.mtime, 20.25);
    assert!(fs.utimens_inode(9999, 0.0, 0.0).is_err());

    fs.chmod_inode(file.ino, 0o640).unwrap();
    fs.check_access_inode(file.ino, 1000, 3000, libc::R_OK | libc::W_OK)
        .unwrap();
    fs.check_access_inode_with_groups(file.ino, 4000, &[3000], libc::R_OK)
        .unwrap();
    assert!(fs
        .check_access_inode_with_groups(file.ino, 4000, &[4000], libc::R_OK)
        .is_err());
    assert!(fs.check_access_inode(9999, 0, 0, libc::R_OK).is_err());
}

#[test]
fn xattr_and_acl_lifecycle_covers_special_names_invalid_values_and_removal() {
    let (_dir, fs) = volume();
    let file = fs.create_file_path("/file", 0o600).unwrap();
    let _directory = fs.mkdir("/dir", 0o755).unwrap();
    fs.setxattr_inode(file, "user.key", b"value").unwrap();
    assert_eq!(fs.getxattr_inode(file, "user.key").unwrap(), b"value");
    assert!(fs
        .listxattr_inode(file)
        .unwrap()
        .contains(&"user.key".to_string()));
    fs.removexattr_inode(file, "user.key").unwrap();
    assert!(fs.removexattr_inode(file, "user.key").is_err());
    assert!(fs.setxattr_inode(file, "trusted.key", b"x").is_err());
    assert!(fs.getxattr_inode(file, "system.argosfs.private").is_err());
    assert!(fs.setxattr_inode(9999, "user.key", b"x").is_err());
    assert!(fs.listxattr_inode(9999).is_err());

    fs.setxattr_inode(file, BOOT_CRITICAL_XATTR, b"yes")
        .unwrap();
    assert_eq!(fs.getxattr_inode(file, BOOT_CRITICAL_XATTR).unwrap(), b"1");
    assert_eq!(fs.attr_inode(file).unwrap().kind, NodeKind::File);
    fs.removexattr_inode(file, BOOT_CRITICAL_XATTR).unwrap();
    assert!(fs.getxattr_inode(file, BOOT_CRITICAL_XATTR).is_err());

    let access = acl::parse_posix_acl("user::rw-,group::r--,other::---").unwrap();
    fs.set_posix_acl_path("/file", false, access.clone())
        .unwrap();
    assert_eq!(fs.get_posix_acl_path("/file", false).unwrap(), Some(access));
    assert!(fs
        .set_posix_acl_path("/file", true, PosixAcl::default())
        .is_err());
    let default_acl = acl::parse_posix_acl("user::rwx,group::r-x,other::---").unwrap();
    fs.set_posix_acl_path("/dir", true, default_acl.clone())
        .unwrap();
    assert_eq!(
        fs.get_posix_acl_path("/dir", true).unwrap(),
        Some(default_acl)
    );

    let nfs4 = Nfs4Acl {
        entries: vec![Nfs4Ace {
            ace_type: Nfs4AceType::Allow,
            principal: "EVERYONE@".to_string(),
            permissions: vec!["read".to_string()],
            flags: Vec::new(),
        }],
    };
    fs.set_nfs4_acl_path("/file", nfs4.clone()).unwrap();
    assert_eq!(
        fs.get_nfs4_acl_path("/file")
            .unwrap()
            .unwrap()
            .entries
            .len(),
        1
    );
    fs.removexattr_inode(file, acl::NFS4_ACL_XATTR).unwrap();
    assert!(fs.getxattr_inode(file, acl::NFS4_ACL_XATTR).is_err());

    {
        let mut meta = fs.meta.write();
        meta.inodes
            .get_mut(&file)
            .unwrap()
            .xattrs
            .insert("user.badhex".to_string(), "zz".to_string());
    }
    assert!(fs.getxattr_inode(file, "user.badhex").is_err());
}
