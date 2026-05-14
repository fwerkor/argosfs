use crate::error::{ArgosError, Result};
use crate::types::{
    Inode, Nfs4Ace, Nfs4AceType, Nfs4Acl, NodeKind, PosixAcl, PosixAclEntry, PosixAclTag,
};

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
    Ok(PosixAcl { entries })
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
    if value.is_empty() {
        return Ok(PosixAcl::default());
    }
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
    Ok(PosixAcl { entries })
}

pub fn nfs4_to_json(acl: &Nfs4Acl) -> Result<String> {
    serde_json::to_string_pretty(acl).map_err(ArgosError::Json)
}

pub fn evaluate_access(inode: &Inode, uid: u32, gid: u32, mask: i32) -> bool {
    if uid == 0 {
        return true;
    }
    let requested = (((mask & libc::R_OK) != 0) as u16 * ACL_READ)
        | (((mask & libc::W_OK) != 0) as u16 * ACL_WRITE)
        | (((mask & libc::X_OK) != 0) as u16 * ACL_EXECUTE);
    if requested == 0 {
        return true;
    }
    if let Some(nfs4) = &inode.nfs4_acl {
        if let Some(allowed) = evaluate_nfs4(nfs4, uid, gid, requested) {
            return allowed;
        }
    }
    if let Some(acl) = &inode.posix_acl_access {
        return evaluate_posix(acl, inode, uid, gid, requested);
    }
    evaluate_mode(inode, uid, gid, requested)
}

pub fn inherited_directory_acl(parent: &Inode) -> Option<PosixAcl> {
    if parent.kind == NodeKind::Directory {
        parent.posix_acl_default.clone()
    } else {
        None
    }
}

fn evaluate_posix(acl: &PosixAcl, inode: &Inode, uid: u32, gid: u32, requested: u16) -> bool {
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
    if gid == inode.gid {
        let perms = acl
            .entries
            .iter()
            .find(|entry| entry.tag == PosixAclTag::GroupObj)
            .map(|entry| entry.perms)
            .unwrap_or(((inode.mode >> 3) & 0o7) as u16);
        return (perms & mask) & requested == requested;
    }
    if acl
        .entries
        .iter()
        .filter(|entry| entry.tag == PosixAclTag::Group && entry.id == Some(gid))
        .any(|entry| (entry.perms & mask) & requested == requested)
    {
        return true;
    }
    let other = acl
        .entries
        .iter()
        .find(|entry| entry.tag == PosixAclTag::Other)
        .map(|entry| entry.perms)
        .unwrap_or((inode.mode & 0o7) as u16);
    other & requested == requested
}

fn evaluate_mode(inode: &Inode, uid: u32, gid: u32, requested: u16) -> bool {
    let shift = if uid == inode.uid {
        6
    } else if gid == inode.gid {
        3
    } else {
        0
    };
    let perms = ((inode.mode >> shift) & 0o7) as u16;
    perms & requested == requested
}

fn evaluate_nfs4(acl: &Nfs4Acl, uid: u32, gid: u32, requested: u16) -> Option<bool> {
    if acl.entries.is_empty() {
        return None;
    }
    let mut allowed = 0u16;
    for ace in &acl.entries {
        if !nfs4_principal_matches(ace, uid, gid) {
            continue;
        }
        let perms = nfs4_perm_bits(ace);
        if perms & requested == 0 {
            continue;
        }
        match ace.ace_type {
            Nfs4AceType::Deny => return Some(false),
            Nfs4AceType::Allow => allowed |= perms,
        }
    }
    Some(allowed & requested == requested)
}

fn nfs4_principal_matches(ace: &Nfs4Ace, uid: u32, gid: u32) -> bool {
    let p = ace.principal.as_str();
    p == "EVERYONE@" || p == format!("uid:{uid}") || p == format!("gid:{gid}")
}

fn nfs4_perm_bits(ace: &Nfs4Ace) -> u16 {
    ace.permissions.iter().fold(0u16, |mut acc, perm| {
        match perm.as_str() {
            "r" | "read" | "read-data" => acc |= ACL_READ,
            "w" | "write" | "write-data" | "append-data" => acc |= ACL_WRITE,
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
