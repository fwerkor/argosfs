use super::*;
use std::collections::BTreeMap;

fn inode(kind: NodeKind, mode: u32, uid: u32, gid: u32) -> Inode {
    Inode {
        id: 2,
        kind,
        mode,
        uid,
        gid,
        nlink: 1,
        size: 0,
        rdev: 0,
        atime: 0.0,
        mtime: 0.0,
        ctime: 0.0,
        entries: BTreeMap::new(),
        target: None,
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
        storage_class: crate::types::StorageTier::Warm,
        boot_critical: false,
        workload_score: 0.0,
        last_accessed_at: 0.0,
        last_written_at: 0.0,
    }
}

#[test]
fn textual_and_binary_posix_acl_round_trip() {
    let acl =
        parse_posix_acl("user::rwx,user:1001:r--,group::r-x,group:2002:-w-,mask::rwx,other::---")
            .unwrap();
    let formatted = format_posix_acl(&acl);
    assert_eq!(
        formatted,
        "user::rwx,user:1001:r--,group::r-x,group:2002:-w-,mask::rwx,other::---"
    );
    assert_eq!(parse_posix_acl(&formatted).unwrap(), acl);
    let binary = posix_acl_to_xattr(&acl);
    assert_eq!(parse_posix_acl_xattr(&binary).unwrap(), acl);
    assert_eq!(parse_posix_acl_xattr(formatted.as_bytes()).unwrap(), acl);
    assert!(is_empty_posix_acl_xattr(&[]));
    assert!(is_empty_posix_acl_xattr(
        &POSIX_ACL_XATTR_VERSION.to_le_bytes()
    ));
    assert!(!is_empty_posix_acl_xattr(&binary));
}

#[test]
fn acl_parser_rejects_tags_ids_permissions_duplicates_and_missing_entries() {
    for invalid in [
        "user::rwx,group::r-x",
        "bad::rwx,group::r-x,other::---",
        "user:not-a-number:rwx,group::r-x,other::---",
        "user::rw,group::r-x,other::---",
        "user::rwa,group::r-x,other::---",
        "user:1000:rwx,group::r-x,other::---",
        "user::rwx,group:1000:r-x,other::---",
        "user::rwx,user::r--,group::r-x,other::---",
        "user::rwx,group::r-x,group::r--,other::---",
        "user::rwx,group::r-x,mask::rwx,mask::r--,other::---",
        "user::rwx,user:1000:r--,group::r-x,other::---",
        "user::rwx,user:1000:r--,user:1000:rw-,group::r-x,mask::rwx,other::---",
        "user::rwx,group::r-x,group:1000:r--,group:1000:rw-,mask::rwx,other::---",
    ] {
        assert!(parse_posix_acl(invalid).is_err(), "{invalid}");
    }
}

#[test]
fn binary_acl_parser_rejects_bad_lengths_tags_permissions_and_ids() {
    assert!(parse_posix_acl_binary(&[2, 0, 0]).is_err());
    assert!(parse_posix_acl_binary(&[2, 0, 0, 0, 1]).is_err());

    fn record(tag: u16, perms: u16, id: u32) -> Vec<u8> {
        let mut out = POSIX_ACL_XATTR_VERSION.to_le_bytes().to_vec();
        out.extend_from_slice(&tag.to_le_bytes());
        out.extend_from_slice(&perms.to_le_bytes());
        out.extend_from_slice(&id.to_le_bytes());
        out
    }
    assert!(parse_posix_acl_binary(&record(0xffff, 7, ACL_UNDEFINED_ID)).is_err());
    assert!(parse_posix_acl_binary(&record(ACL_USER_OBJ_TAG, 8, ACL_UNDEFINED_ID)).is_err());
    assert!(parse_posix_acl_binary(&record(ACL_USER_TAG, 7, ACL_UNDEFINED_ID)).is_err());
    assert!(parse_posix_acl_binary(&record(ACL_OTHER_TAG, 7, 1)).is_err());
}

#[test]
fn nfs4_json_handles_empty_valid_and_invalid_specs() {
    assert!(parse_nfs4_acl_json(" ").unwrap().entries.is_empty());
    let acl = Nfs4Acl {
        entries: vec![Nfs4Ace {
            ace_type: Nfs4AceType::Allow,
            principal: "EVERYONE@".to_string(),
            permissions: vec!["read".to_string()],
            flags: Vec::new(),
        }],
    };
    let json = nfs4_to_json(&acl).unwrap();
    assert_eq!(parse_nfs4_acl_json(&json).unwrap().entries.len(), 1);
    assert!(parse_nfs4_acl_json("{").is_err());
}

#[test]
fn mode_access_handles_owner_group_other_root_and_zero_masks() {
    let file = inode(NodeKind::File, 0o640, 1000, 2000);
    assert!(evaluate_access(&file, 1000, 9999, libc::R_OK | libc::W_OK));
    assert!(!evaluate_access(&file, 1000, 9999, libc::X_OK));
    assert!(evaluate_access(&file, 3000, 2000, libc::R_OK));
    assert!(!evaluate_access(&file, 3000, 2000, libc::W_OK));
    assert!(!evaluate_access(&file, 3000, 4000, libc::R_OK));
    assert!(evaluate_access(&file, 3000, 4000, 0));
    assert!(evaluate_access(&file, 0, 0, libc::R_OK | libc::W_OK));
    assert!(!evaluate_access(&file, 0, 0, libc::X_OK));

    let directory = inode(NodeKind::Directory, 0o600, 1000, 2000);
    assert!(evaluate_access(&directory, 0, 0, libc::X_OK));
    let executable = inode(NodeKind::File, 0o001, 1000, 2000);
    assert!(evaluate_access(&executable, 0, 0, libc::X_OK));
}

#[test]
fn posix_acl_evaluation_covers_named_user_groups_mask_and_other() {
    let mut file = inode(NodeKind::File, 0o000, 1000, 2000);
    file.posix_acl_access = Some(
        parse_posix_acl("user::rw-,user:3000:rwx,group::r--,group:4000:-w-,mask::rw-,other::--x")
            .unwrap(),
    );
    assert!(evaluate_access_with_groups(
        &file,
        1000,
        &[],
        libc::R_OK | libc::W_OK
    ));
    assert!(!evaluate_access_with_groups(&file, 1000, &[], libc::X_OK));
    assert!(evaluate_access_with_groups(
        &file,
        3000,
        &[],
        libc::R_OK | libc::W_OK
    ));
    assert!(!evaluate_access_with_groups(&file, 3000, &[], libc::X_OK));
    assert!(evaluate_access_with_groups(
        &file,
        5000,
        &[2000],
        libc::R_OK
    ));
    assert!(evaluate_access_with_groups(
        &file,
        5000,
        &[4000],
        libc::W_OK
    ));
    assert!(evaluate_access_with_groups(
        &file,
        5000,
        &[2000, 4000],
        libc::R_OK | libc::W_OK
    ));
    assert!(evaluate_access_with_groups(
        &file,
        5000,
        &[5000],
        libc::X_OK
    ));
    assert!(!evaluate_access_with_groups(
        &file,
        5000,
        &[5000],
        libc::R_OK
    ));
}

#[test]
fn nfs4_evaluation_covers_ordering_principals_permissions_and_fallback() {
    let mut file = inode(NodeKind::File, 0o004, 1000, 2000);
    file.nfs4_acl = Some(Nfs4Acl::default());
    assert!(evaluate_access(&file, 3000, 4000, libc::R_OK));

    file.nfs4_acl = Some(Nfs4Acl {
        entries: vec![
            Nfs4Ace {
                ace_type: Nfs4AceType::Allow,
                principal: "OWNER@".to_string(),
                permissions: vec!["read-data".to_string(), "write-data".to_string()],
                flags: vec!["inherit-only".to_string()],
            },
            Nfs4Ace {
                ace_type: Nfs4AceType::Deny,
                principal: "uid:3000".to_string(),
                permissions: vec!["write".to_string()],
                flags: Vec::new(),
            },
            Nfs4Ace {
                ace_type: Nfs4AceType::Allow,
                principal: "GROUP@".to_string(),
                permissions: vec!["list-directory".to_string()],
                flags: Vec::new(),
            },
            Nfs4Ace {
                ace_type: Nfs4AceType::Allow,
                principal: "gid:4000".to_string(),
                permissions: vec!["append-data".to_string(), "execute".to_string()],
                flags: Vec::new(),
            },
            Nfs4Ace {
                ace_type: Nfs4AceType::Allow,
                principal: "EVERYONE@".to_string(),
                permissions: vec!["r".to_string(), "unknown".to_string()],
                flags: Vec::new(),
            },
        ],
    });
    assert!(!evaluate_access_with_groups(
        &file,
        3000,
        &[4000],
        libc::W_OK
    ));
    assert!(evaluate_access_with_groups(
        &file,
        5000,
        &[2000],
        libc::R_OK
    ));
    assert!(evaluate_access_with_groups(
        &file,
        5000,
        &[4000],
        libc::W_OK | libc::X_OK
    ));
    assert!(!evaluate_access_with_groups(
        &file,
        5000,
        &[5000],
        libc::X_OK
    ));
}

#[test]
fn inherited_acl_and_mode_updates_preserve_extended_entries() {
    let acl = parse_posix_acl("user::rwx,user:3000:rwx,group::rwx,mask::rwx,other::rwx").unwrap();
    let mut parent = inode(NodeKind::Directory, 0o777, 1000, 2000);
    parent.posix_acl_default = Some(acl.clone());
    assert_eq!(inherited_directory_acl(&parent), Some(acl.clone()));
    let inherited = inherited_access_acl(&parent, 0o640).unwrap();
    assert_eq!(
        format_posix_acl(&inherited),
        "user::rw-,user:3000:rwx,group::rwx,mask::r--,other::---"
    );
    assert_eq!(
        mode_from_access_acl(&inherited, libc::S_IFREG | 0o777),
        libc::S_IFREG | 0o640
    );

    let file = inode(NodeKind::File, 0o777, 1000, 2000);
    assert!(inherited_directory_acl(&file).is_none());
    assert!(inherited_access_acl(&file, 0o600).is_none());

    let mut minimal = parse_posix_acl("user::rwx,group::rwx,other::rwx").unwrap();
    apply_mode_to_access_acl(&mut minimal, 0o751);
    assert_eq!(
        format_posix_acl(&minimal),
        "user::rwx,group::r-x,other::--x"
    );
    assert_eq!(mode_from_access_acl(&minimal, 0), 0o751);
}

#[test]
fn mode_reconstruction_uses_current_bits_when_acl_entries_are_missing() {
    let acl = PosixAcl {
        entries: Vec::new(),
    };
    assert_eq!(
        mode_from_access_acl(&acl, libc::S_IFREG | 0o654),
        libc::S_IFREG | 0o654
    );
}

#[test]
fn permission_bit_helpers_cover_every_combination() {
    for (text, bits) in [
        ("---", 0),
        ("r--", ACL_READ),
        ("-w-", ACL_WRITE),
        ("--x", ACL_EXECUTE),
        ("rwx", ACL_READ | ACL_WRITE | ACL_EXECUTE),
    ] {
        assert_eq!(parse_perm_bits(text).unwrap(), bits);
        assert_eq!(format_perm_bits(bits), text);
    }
}
