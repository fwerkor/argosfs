use crate::error::{ArgosError, Result};
use crate::types::{
    Inode, Nfs4Ace, Nfs4AceType, Nfs4Acl, NodeKind, PosixAcl, PosixAclEntry, PosixAclTag,
};
use std::collections::BTreeSet;

pub const ACL_READ: u16 = 0b100;
pub const ACL_WRITE: u16 = 0b010;
pub const ACL_EXECUTE: u16 = 0b001;
pub const POSIX_ACL_ACCESS_XATTR: &str = "system.posix_acl_access";
pub const POSIX_ACL_DEFAULT_XATTR: &str = "system.posix_acl_default";
pub const ARGOS_POSIX_ACL_ACCESS_XATTR: &str = "system.argosfs.posix_acl_access";
pub const ARGOS_POSIX_ACL_DEFAULT_XATTR: &str = "system.argosfs.posix_acl_default";
pub const NFS4_ACL_XATTR: &str = "system.argosfs.nfs4_acl";

const POSIX_ACL_XATTR_VERSION: u32 = 0x0002;
const ACL_USER_OBJ_TAG: u16 = 0x01;
const ACL_USER_TAG: u16 = 0x02;
const ACL_GROUP_OBJ_TAG: u16 = 0x04;
const ACL_GROUP_TAG: u16 = 0x08;
const ACL_MASK_TAG: u16 = 0x10;
const ACL_OTHER_TAG: u16 = 0x20;
const ACL_UNDEFINED_ID: u32 = u32::MAX;

pub fn parse_posix_acl(spec: &str) -> Result<PosixAcl> {
    let mut entries = Vec::new();
    for raw in spec
        .split(',')
        .map(str::trim)
        .filter(|part| !part.is_empty())
    {
        let parts = raw.split(':').collect::<Vec<_>>();
        if parts.len() != 3 {
            return Err(ArgosError::Invalid(format!(
                "invalid POSIX ACL entry: {raw}"
            )));
        }
        let tag = match parts[0] {
            "u" | "user" if parts[1].is_empty() => PosixAclTag::UserObj,
            "u" | "user" => PosixAclTag::User,
            "g" | "group" if parts[1].is_empty() => PosixAclTag::GroupObj,
            "g" | "group" => PosixAclTag::Group,
            "m" | "mask" => PosixAclTag::Mask,
            "o" | "other" => PosixAclTag::Other,
            other => {
                return Err(ArgosError::Invalid(format!(
                    "invalid POSIX ACL tag: {other}"
                )))
            }
        };
        let id = if parts[1].is_empty() {
            None
        } else {
            Some(
                parts[1]
                    .parse::<u32>()
                    .map_err(|err| ArgosError::Invalid(format!("invalid ACL id: {err}")))?,
            )
        };
        validate_acl_id(&tag, id)?;
        entries.push(PosixAclEntry {
            tag,
            id,
            perms: parse_perm_bits(parts[2])?,
        });
    }
    let acl = PosixAcl { entries };
    validate_posix_acl(&acl)?;
    Ok(acl)
}

pub fn format_posix_acl(acl: &PosixAcl) -> String {
    acl.entries
        .iter()
        .map(|entry| {
            let tag = match entry.tag {
                PosixAclTag::UserObj | PosixAclTag::User => "user",
                PosixAclTag::GroupObj | PosixAclTag::Group => "group",
                PosixAclTag::Mask => "mask",
                PosixAclTag::Other => "other",
            };
            let id = entry.id.map(|id| id.to_string()).unwrap_or_default();
            format!("{tag}:{id}:{}", format_perm_bits(entry.perms))
        })
        .collect::<Vec<_>>()
        .join(",")
}

pub fn parse_posix_acl_xattr(value: &[u8]) -> Result<PosixAcl> {
    if value.len() >= 4 {
        let version = u32::from_le_bytes([value[0], value[1], value[2], value[3]]);
        if version == POSIX_ACL_XATTR_VERSION {
            return parse_posix_acl_binary(value);
        }
    }
    let text = std::str::from_utf8(value)
        .map_err(|err| ArgosError::Invalid(format!("invalid POSIX ACL text: {err}")))?;
    parse_posix_acl(text)
}

pub(crate) fn is_empty_posix_acl_xattr(value: &[u8]) -> bool {
    value.is_empty() || value == POSIX_ACL_XATTR_VERSION.to_le_bytes()
}

pub fn posix_acl_to_xattr(acl: &PosixAcl) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + acl.entries.len() * 8);
    out.extend_from_slice(&POSIX_ACL_XATTR_VERSION.to_le_bytes());
    for entry in &acl.entries {
        let tag = match entry.tag {
            PosixAclTag::UserObj => ACL_USER_OBJ_TAG,
            PosixAclTag::User => ACL_USER_TAG,
            PosixAclTag::GroupObj => ACL_GROUP_OBJ_TAG,
            PosixAclTag::Group => ACL_GROUP_TAG,
            PosixAclTag::Mask => ACL_MASK_TAG,
            PosixAclTag::Other => ACL_OTHER_TAG,
        };
        out.extend_from_slice(&tag.to_le_bytes());
        out.extend_from_slice(&entry.perms.to_le_bytes());
        out.extend_from_slice(&entry.id.unwrap_or(ACL_UNDEFINED_ID).to_le_bytes());
    }
    out
}

pub fn parse_nfs4_acl_json(spec: &str) -> Result<Nfs4Acl> {
    if spec.trim().is_empty() {
        return Ok(Nfs4Acl::default());
    }
    serde_json::from_str::<Nfs4Acl>(spec).map_err(ArgosError::Json)
}

fn parse_posix_acl_binary(value: &[u8]) -> Result<PosixAcl> {
    if value.len() < 4 || !(value.len() - 4).is_multiple_of(8) {
        return Err(ArgosError::Invalid(
            "invalid POSIX ACL xattr length".to_string(),
        ));
    }
    let mut entries = Vec::new();
    for chunk in value[4..].chunks_exact(8) {
        let raw_tag = u16::from_le_bytes([chunk[0], chunk[1]]);
        let raw_perms = u16::from_le_bytes([chunk[2], chunk[3]]);
        if raw_perms & !0o7 != 0 {
            return Err(ArgosError::Invalid(format!(
                "invalid POSIX ACL xattr perms: {raw_perms:o}"
            )));
        }
        let perms = raw_perms;
        let raw_id = u32::from_le_bytes([chunk[4], chunk[5], chunk[6], chunk[7]]);
        let tag = match raw_tag {
            ACL_USER_OBJ_TAG => PosixAclTag::UserObj,
            ACL_USER_TAG => PosixAclTag::User,
            ACL_GROUP_OBJ_TAG => PosixAclTag::GroupObj,
            ACL_GROUP_TAG => PosixAclTag::Group,
            ACL_MASK_TAG => PosixAclTag::Mask,
            ACL_OTHER_TAG => PosixAclTag::Other,
            other => {
                return Err(ArgosError::Invalid(format!(
                    "invalid POSIX ACL xattr tag: {other}"
                )))
            }
        };
        let id = (raw_id != ACL_UNDEFINED_ID).then_some(raw_id);
        validate_acl_id(&tag, id)?;
        entries.push(PosixAclEntry { tag, id, perms });
    }
    let acl = PosixAcl { entries };
    validate_posix_acl(&acl)?;
    Ok(acl)
}

pub fn validate_posix_acl(acl: &PosixAcl) -> Result<()> {
    let mut user_obj = 0usize;
    let mut group_obj = 0usize;
    let mut mask = 0usize;
    let mut other = 0usize;
    let mut named_users = BTreeSet::new();
    let mut named_groups = BTreeSet::new();

    for entry in &acl.entries {
        if entry.perms & !0o7 != 0 {
            return Err(ArgosError::Invalid(format!(
                "invalid POSIX ACL permissions: {:o}",
                entry.perms
            )));
        }
        validate_acl_id(&entry.tag, entry.id)?;
        match entry.tag {
            PosixAclTag::UserObj => user_obj += 1,
            PosixAclTag::User => {
                let Some(id) = entry.id else {
                    return Err(ArgosError::Invalid(
                        "named POSIX ACL user entries require an id".to_string(),
                    ));
                };
                if !named_users.insert(id) {
                    return Err(ArgosError::Invalid(format!(
                        "duplicate POSIX ACL user entry: {id}"
                    )));
                }
            }
            PosixAclTag::GroupObj => group_obj += 1,
            PosixAclTag::Group => {
                let Some(id) = entry.id else {
                    return Err(ArgosError::Invalid(
                        "named POSIX ACL group entries require an id".to_string(),
                    ));
                };
                if !named_groups.insert(id) {
                    return Err(ArgosError::Invalid(format!(
                        "duplicate POSIX ACL group entry: {id}"
                    )));
                }
            }
            PosixAclTag::Mask => mask += 1,
            PosixAclTag::Other => other += 1,
        }
    }

    for (name, count) in [
        ("owner user", user_obj),
        ("owner group", group_obj),
        ("other", other),
    ] {
        if count != 1 {
            return Err(ArgosError::Invalid(format!(
                "POSIX ACL requires exactly one {name} entry"
            )));
        }
    }
    if mask > 1 {
        return Err(ArgosError::Invalid(
            "POSIX ACL permits at most one mask entry".to_string(),
        ));
    }
    if (!named_users.is_empty() || !named_groups.is_empty()) && mask != 1 {
        return Err(ArgosError::Invalid(
            "extended POSIX ACL entries require a mask".to_string(),
        ));
    }
    Ok(())
}

pub fn nfs4_to_json(acl: &Nfs4Acl) -> Result<String> {
    serde_json::to_string_pretty(acl).map_err(ArgosError::Json)
}

pub fn evaluate_access(inode: &Inode, uid: u32, gid: u32, mask: i32) -> bool {
    evaluate_access_with_groups(inode, uid, &[gid], mask)
}

pub fn evaluate_access_with_groups(inode: &Inode, uid: u32, gids: &[u32], mask: i32) -> bool {
    let requested = (((mask & libc::R_OK) != 0) as u16 * ACL_READ)
        | (((mask & libc::W_OK) != 0) as u16 * ACL_WRITE)
        | (((mask & libc::X_OK) != 0) as u16 * ACL_EXECUTE);
    if requested == 0 {
        return true;
    }
    if uid == 0 {
        return requested & ACL_EXECUTE == 0
            || inode.kind == NodeKind::Directory
            || inode.mode & 0o111 != 0;
    }
    if let Some(nfs4) = &inode.nfs4_acl {
        if let Some(allowed) = evaluate_nfs4(nfs4, inode, uid, gids, requested) {
            return allowed;
        }
    }
    if let Some(acl) = &inode.posix_acl_access {
        return evaluate_posix(acl, inode, uid, gids, requested);
    }
    evaluate_mode(inode, uid, gids, requested)
}

pub fn inherited_directory_acl(parent: &Inode) -> Option<PosixAcl> {
    if parent.kind == NodeKind::Directory {
        parent.posix_acl_default.clone()
    } else {
        None
    }
}

pub fn inherited_access_acl(parent: &Inode, mode: u32) -> Option<PosixAcl> {
    let mut acl = inherited_directory_acl(parent)?;
    apply_mode_to_access_acl(&mut acl, mode);
    Some(acl)
}

pub fn apply_mode_to_access_acl(acl: &mut PosixAcl, mode: u32) {
    let owner = ((mode >> 6) & 0o7) as u16;
    let group = ((mode >> 3) & 0o7) as u16;
    let other = (mode & 0o7) as u16;
    let has_mask = acl
        .entries
        .iter()
        .any(|entry| entry.tag == PosixAclTag::Mask);
    for entry in &mut acl.entries {
        match entry.tag {
            PosixAclTag::UserObj => entry.perms = owner,
            PosixAclTag::Mask => entry.perms = group,
            PosixAclTag::GroupObj if !has_mask => entry.perms = group,
            PosixAclTag::Other => entry.perms = other,
            _ => {}
        }
    }
}

pub fn mode_from_access_acl(acl: &PosixAcl, current_mode: u32) -> u32 {
    let owner = acl
        .entries
        .iter()
        .find(|entry| entry.tag == PosixAclTag::UserObj)
        .map(|entry| entry.perms as u32)
        .unwrap_or((current_mode >> 6) & 0o7);
    let group = acl
        .entries
        .iter()
        .find(|entry| entry.tag == PosixAclTag::Mask)
        .or_else(|| {
            acl.entries
                .iter()
                .find(|entry| entry.tag == PosixAclTag::GroupObj)
        })
        .map(|entry| entry.perms as u32)
        .unwrap_or((current_mode >> 3) & 0o7);
    let other = acl
        .entries
        .iter()
        .find(|entry| entry.tag == PosixAclTag::Other)
        .map(|entry| entry.perms as u32)
        .unwrap_or(current_mode & 0o7);
    (current_mode & !0o777) | (owner << 6) | (group << 3) | other
}

fn evaluate_posix(acl: &PosixAcl, inode: &Inode, uid: u32, gids: &[u32], requested: u16) -> bool {
    let mask = acl
        .entries
        .iter()
        .find(|entry| entry.tag == PosixAclTag::Mask)
        .map(|entry| entry.perms)
        .unwrap_or(ACL_READ | ACL_WRITE | ACL_EXECUTE);
    if uid == inode.uid {
        let perms = acl
            .entries
            .iter()
            .find(|entry| entry.tag == PosixAclTag::UserObj)
            .map(|entry| entry.perms)
            .unwrap_or(((inode.mode >> 6) & 0o7) as u16);
        return perms & requested == requested;
    }
    if let Some(entry) = acl
        .entries
        .iter()
        .find(|entry| entry.tag == PosixAclTag::User && entry.id == Some(uid))
    {
        return (entry.perms & mask) & requested == requested;
    }
    let mut group_matched = false;
    let mut group_perms = 0u16;
    if gids.contains(&inode.gid) {
        group_matched = true;
        group_perms |= acl
            .entries
            .iter()
            .find(|entry| entry.tag == PosixAclTag::GroupObj)
            .map(|entry| entry.perms)
            .unwrap_or(((inode.mode >> 3) & 0o7) as u16);
    }
    for entry in acl.entries.iter().filter(|entry| {
        entry.tag == PosixAclTag::Group && entry.id.is_some_and(|group| gids.contains(&group))
    }) {
        group_matched = true;
        group_perms |= entry.perms;
    }
    if group_matched {
        return (group_perms & mask) & requested == requested;
    }
    let other = acl
        .entries
        .iter()
        .find(|entry| entry.tag == PosixAclTag::Other)
        .map(|entry| entry.perms)
        .unwrap_or((inode.mode & 0o7) as u16);
    other & requested == requested
}

fn evaluate_mode(inode: &Inode, uid: u32, gids: &[u32], requested: u16) -> bool {
    let shift = if uid == inode.uid {
        6
    } else if gids.contains(&inode.gid) {
        3
    } else {
        0
    };
    let perms = ((inode.mode >> shift) & 0o7) as u16;
    perms & requested == requested
}

fn evaluate_nfs4(
    acl: &Nfs4Acl,
    inode: &Inode,
    uid: u32,
    gids: &[u32],
    requested: u16,
) -> Option<bool> {
    if acl.entries.is_empty() {
        return None;
    }
    let mut remaining = requested;
    for ace in &acl.entries {
        if ace.flags.iter().any(|flag| flag == "inherit-only")
            || !nfs4_principal_matches(ace, inode, uid, gids)
        {
            continue;
        }
        let affected = nfs4_perm_bits(ace) & remaining;
        if affected == 0 {
            continue;
        }
        match ace.ace_type {
            Nfs4AceType::Deny => return Some(false),
            Nfs4AceType::Allow => {
                remaining &= !affected;
                if remaining == 0 {
                    return Some(true);
                }
            }
        }
    }
    Some(false)
}

fn nfs4_principal_matches(ace: &Nfs4Ace, inode: &Inode, uid: u32, gids: &[u32]) -> bool {
    let principal = ace.principal.as_str();
    principal == "EVERYONE@"
        || (principal == "OWNER@" && uid == inode.uid)
        || (principal == "GROUP@" && gids.contains(&inode.gid))
        || principal == format!("uid:{uid}")
        || gids.iter().any(|gid| principal == format!("gid:{gid}"))
}

fn nfs4_perm_bits(ace: &Nfs4Ace) -> u16 {
    ace.permissions.iter().fold(0u16, |mut acc, perm| {
        match perm.as_str() {
            "r" | "read" | "read-data" | "list-directory" => acc |= ACL_READ,
            "w" | "write" | "write-data" | "append-data" | "add-file" | "add-subdirectory" => {
                acc |= ACL_WRITE
            }
            "x" | "execute" => acc |= ACL_EXECUTE,
            _ => {}
        }
        acc
    })
}

fn parse_perm_bits(value: &str) -> Result<u16> {
    let chars = value.chars().collect::<Vec<_>>();
    if chars.len() != 3 {
        return Err(ArgosError::Invalid(format!(
            "invalid permission bits: {value}"
        )));
    }
    if !matches!(chars[0], 'r' | '-')
        || !matches!(chars[1], 'w' | '-')
        || !matches!(chars[2], 'x' | '-')
    {
        return Err(ArgosError::Invalid(format!(
            "invalid permission bits: {value}"
        )));
    }
    Ok(((matches!(chars[0], 'r') as u16) * ACL_READ)
        | ((matches!(chars[1], 'w') as u16) * ACL_WRITE)
        | ((matches!(chars[2], 'x') as u16) * ACL_EXECUTE))
}

fn validate_acl_id(tag: &PosixAclTag, id: Option<u32>) -> Result<()> {
    match (tag, id) {
        (PosixAclTag::User | PosixAclTag::Group, None) => Err(ArgosError::Invalid(
            "named POSIX ACL user/group entries require an id".to_string(),
        )),
        (
            PosixAclTag::UserObj | PosixAclTag::GroupObj | PosixAclTag::Mask | PosixAclTag::Other,
            Some(_),
        ) => Err(ArgosError::Invalid(
            "POSIX ACL owner/group/mask/other entries must not carry an id".to_string(),
        )),
        _ => Ok(()),
    }
}

fn format_perm_bits(bits: u16) -> String {
    format!(
        "{}{}{}",
        if bits & ACL_READ != 0 { 'r' } else { '-' },
        if bits & ACL_WRITE != 0 { 'w' } else { '-' },
        if bits & ACL_EXECUTE != 0 { 'x' } else { '-' },
    )
}

#[cfg(test)]
mod tests {
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
        let acl = parse_posix_acl(
            "user::rwx,user:1001:r--,group::r-x,group:2002:-w-,mask::rwx,other::---",
        )
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
            parse_posix_acl(
                "user::rw-,user:3000:rwx,group::r--,group:4000:-w-,mask::rw-,other::--x",
            )
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
        let acl =
            parse_posix_acl("user::rwx,user:3000:rwx,group::rwx,mask::rwx,other::rwx").unwrap();
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
}
