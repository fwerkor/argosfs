use crate::types::{InodeId, NodeKind};
use std::ffi::OsString;
use std::os::unix::ffi::OsStringExt;

#[derive(Clone, Debug, serde::Serialize)]
pub struct NodeAttr {
    pub ino: InodeId,
    pub kind: NodeKind,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub nlink: u32,
    pub size: u64,
    pub rdev: u64,
    pub atime: f64,
    pub mtime: f64,
    pub ctime: f64,
    pub blocks: u64,
    pub blksize: u32,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct DirEntry {
    pub name: String,
    pub name_bytes: Vec<u8>,
    pub attr: NodeAttr,
}

impl DirEntry {
    pub fn os_name(&self) -> OsString {
        OsString::from_vec(self.name_bytes.clone())
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct RenamePolicy {
    pub no_replace: bool,
    pub exchange: bool,
    pub uid: Option<u32>,
    pub preserve_replaced_inode: bool,
}
