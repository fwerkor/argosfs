use crate::error::{ArgosError, Result};
use crate::types::NodeKind;
use crate::volume::{ArgosFs, NodeAttr};
use fuser::{
    FileAttr, FileType, Filesystem, KernelConfig, MountOption, ReplyAttr, ReplyCreate, ReplyData,
    ReplyDirectory, ReplyEmpty, ReplyEntry, ReplyOpen, ReplyStatfs, ReplyWrite, ReplyXattr,
    Request, TimeOrNow,
};
use std::ffi::OsStr;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const TTL: Duration = Duration::from_secs(1);
const FOPEN_DIRECT_IO: u32 = 1;

pub struct ArgosFuse {
    volume: ArgosFs,
}

impl ArgosFuse {
    pub fn new(volume: ArgosFs) -> Self {
        Self { volume }
    }

    fn require_access(&self, req: &Request<'_>, ino: u64, mask: i32) -> Result<()> {
        self.volume
            .check_access_inode(ino, req.uid(), req.gid(), mask)
    }

    fn open_reply_flags(&self) -> u32 {
        if self.volume.io_policy().direct_io {
            FOPEN_DIRECT_IO
        } else {
            0
        }
    }
}

pub fn mount(
    volume_root: impl AsRef<Path>,
    mountpoint: impl AsRef<Path>,
    _foreground: bool,
    options: Vec<String>,
) -> Result<()> {
    let volume = ArgosFs::open(volume_root)?;
    let mut mount_options = vec![
        MountOption::FSName("argosfs".to_string()),
        MountOption::Subtype("argosfs".to_string()),
    ];
    for option in options {
        mount_options.push(MountOption::CUSTOM(option));
    }
    fuser::mount2(ArgosFuse::new(volume), mountpoint, &mount_options).map_err(ArgosError::Io)
}

impl Filesystem for ArgosFuse {
    fn init(
        &mut self,
        _req: &Request<'_>,
        config: &mut KernelConfig,
    ) -> std::result::Result<(), libc::c_int> {
        let _ = config;
        Ok(())
    }

    fn lookup(&mut self, req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEntry) {
        match self
            .require_access(req, parent, libc::X_OK)
            .and_then(|()| self.volume.lookup(parent, name))
        {
            Ok(attr) => reply.entry(&TTL, &to_file_attr(&attr), 0),
            Err(err) => reply.error(err.errno()),
        }
    }

    fn getattr(&mut self, _req: &Request<'_>, ino: u64, reply: ReplyAttr) {
        match self.volume.attr_inode(ino) {
            Ok(attr) => reply.attr(&TTL, &to_file_attr(&attr)),
            Err(err) => reply.error(err.errno()),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn setattr(
        &mut self,
        req: &Request<'_>,
        ino: u64,
        mode: Option<u32>,
        uid: Option<u32>,
        gid: Option<u32>,
        size: Option<u64>,
        atime: Option<TimeOrNow>,
        mtime: Option<TimeOrNow>,
        _ctime: Option<SystemTime>,
        _fh: Option<u64>,
        _crtime: Option<SystemTime>,
        _chgtime: Option<SystemTime>,
        _bkuptime: Option<SystemTime>,
        _flags: Option<u32>,
        reply: ReplyAttr,
    ) {
        let result = (|| -> Result<NodeAttr> {
            if mode.is_some()
                || uid.is_some()
                || gid.is_some()
                || size.is_some()
                || atime.is_some()
                || mtime.is_some()
            {
                self.require_access(req, ino, libc::W_OK)?;
            }
            let mut attr = self.volume.attr_inode(ino)?;
            if let Some(mode) = mode {
                attr = self.volume.chmod_inode(ino, mode)?;
            }
            if uid.is_some() || gid.is_some() {
                attr = self.volume.chown_inode(ino, uid, gid)?;
            }
            if let Some(size) = size {
                self.volume.truncate_inode(ino, size)?;
                attr = self.volume.attr_inode(ino)?;
            }
            if atime.is_some() || mtime.is_some() {
                let current = self.volume.attr_inode(ino)?;
                let atime = atime.map(time_or_now).unwrap_or(current.atime);
                let mtime = mtime.map(time_or_now).unwrap_or(current.mtime);
                attr = self.volume.utimens_inode(ino, atime, mtime)?;
            }
            Ok(attr)
        })();
        match result {
            Ok(attr) => reply.attr(&TTL, &to_file_attr(&attr)),
            Err(err) => reply.error(err.errno()),
        }
    }

    fn readlink(&mut self, _req: &Request<'_>, ino: u64, reply: ReplyData) {
        match self.volume.readlink_inode(ino) {
            Ok(target) => reply.data(target.as_bytes()),
            Err(err) => reply.error(err.errno()),
        }
    }

    fn mknod(
        &mut self,
        req: &Request<'_>,
        parent: u64,
        name: &OsStr,
        mode: u32,
        umask: u32,
        rdev: u32,
        reply: ReplyEntry,
    ) {
        match self
            .require_access(req, parent, libc::W_OK | libc::X_OK)
            .and_then(|()| {
                self.volume.mknod_at_with_owner(
                    parent,
                    name,
                    mode & !umask,
                    rdev,
                    req.uid(),
                    req.gid(),
                )
            }) {
            Ok(attr) => reply.entry(&TTL, &to_file_attr(&attr), 0),
            Err(err) => reply.error(err.errno()),
        }
    }

    fn mkdir(
        &mut self,
        req: &Request<'_>,
        parent: u64,
        name: &OsStr,
        mode: u32,
        umask: u32,
        reply: ReplyEntry,
    ) {
        match self
            .require_access(req, parent, libc::W_OK | libc::X_OK)
            .and_then(|()| {
                self.volume
                    .mkdir_at_with_owner(parent, name, mode & !umask, req.uid(), req.gid())
            }) {
            Ok(attr) => reply.entry(&TTL, &to_file_attr(&attr), 0),
            Err(err) => reply.error(err.errno()),
        }
    }

    fn unlink(&mut self, req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        match self
            .require_access(req, parent, libc::W_OK | libc::X_OK)
            .and_then(|()| self.volume.unlink_at(parent, name))
        {
            Ok(()) => reply.ok(),
            Err(err) => reply.error(err.errno()),
        }
    }

    fn rmdir(&mut self, req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        match self
            .require_access(req, parent, libc::W_OK | libc::X_OK)
            .and_then(|()| self.volume.rmdir_at(parent, name))
        {
            Ok(()) => reply.ok(),
            Err(err) => reply.error(err.errno()),
        }
    }

    fn symlink(
        &mut self,
        req: &Request<'_>,
        parent: u64,
        name: &OsStr,
        link: &Path,
        reply: ReplyEntry,
    ) {
        match self
            .require_access(req, parent, libc::W_OK | libc::X_OK)
            .and_then(|()| {
                self.volume
                    .symlink_at_with_owner(parent, name, link, req.uid(), req.gid())
            }) {
            Ok(attr) => reply.entry(&TTL, &to_file_attr(&attr), 0),
            Err(err) => reply.error(err.errno()),
        }
    }

    fn rename(
        &mut self,
        req: &Request<'_>,
        parent: u64,
        name: &OsStr,
        newparent: u64,
        newname: &OsStr,
        flags: u32,
        reply: ReplyEmpty,
    ) {
        if flags != 0 {
            reply.error(libc::EINVAL);
            return;
        }
        let result = self
            .require_access(req, parent, libc::W_OK | libc::X_OK)
            .and_then(|()| self.require_access(req, newparent, libc::W_OK | libc::X_OK))
            .and_then(|()| self.volume.rename_at(parent, name, newparent, newname));
        match result {
            Ok(()) => reply.ok(),
            Err(err) => reply.error(err.errno()),
        }
    }

    fn link(
        &mut self,
        req: &Request<'_>,
        ino: u64,
        newparent: u64,
        newname: &OsStr,
        reply: ReplyEntry,
    ) {
        match self
            .require_access(req, ino, libc::R_OK)
            .and_then(|()| self.require_access(req, newparent, libc::W_OK | libc::X_OK))
            .and_then(|()| self.volume.link_at(ino, newparent, newname))
        {
            Ok(attr) => reply.entry(&TTL, &to_file_attr(&attr), 0),
            Err(err) => reply.error(err.errno()),
        }
    }

    fn open(&mut self, req: &Request<'_>, ino: u64, flags: i32, reply: ReplyOpen) {
        let result = (|| -> Result<NodeAttr> {
            self.require_access(req, ino, open_mask(flags))?;
            let mut attr = self.volume.attr_inode(ino)?;
            if attr.kind != NodeKind::File {
                return Err(ArgosError::IsDirectory(format!("inode {ino}")));
            }
            if flags & libc::O_TRUNC != 0 {
                self.volume.truncate_inode(ino, 0)?;
                attr = self.volume.attr_inode(ino)?;
            }
            Ok(attr)
        })();
        match result {
            Ok(_) => reply.opened(ino, self.open_reply_flags()),
            Err(err) => reply.error(err.errno()),
        }
    }

    fn read(
        &mut self,
        req: &Request<'_>,
        ino: u64,
        _fh: u64,
        offset: i64,
        size: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: ReplyData,
    ) {
        if offset < 0 {
            reply.error(libc::EINVAL);
            return;
        }
        match self.require_access(req, ino, libc::R_OK).and_then(|()| {
            self.volume
                .read_inode(ino, offset as u64, size as usize, true)
        }) {
            Ok(data) => reply.data(&data),
            Err(err) => reply.error(err.errno()),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn write(
        &mut self,
        req: &Request<'_>,
        ino: u64,
        _fh: u64,
        offset: i64,
        data: &[u8],
        _write_flags: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: ReplyWrite,
    ) {
        if offset < 0 {
            reply.error(libc::EINVAL);
            return;
        }
        match self
            .require_access(req, ino, libc::W_OK)
            .and_then(|()| self.volume.write_inode_range(ino, offset as u64, data))
        {
            Ok(written) => reply.written(written as u32),
            Err(err) => reply.error(err.errno()),
        }
    }

    fn statfs(&mut self, _req: &Request<'_>, _ino: u64, reply: ReplyStatfs) {
        let meta = self.volume.metadata_snapshot();
        let block = meta.config.chunk_size as u64;
        let raw_capacity: u64 = meta
            .disks
            .values()
            .filter(|disk| disk.status != crate::types::DiskStatus::Removed)
            .map(|disk| disk.capacity_bytes)
            .sum();
        let logical_used: u64 = meta
            .inodes
            .values()
            .filter(|inode| inode.kind == NodeKind::File)
            .map(|inode| inode.size)
            .sum();
        let usable = if raw_capacity > 0 {
            raw_capacity.saturating_mul(meta.config.k as u64)
                / (meta.config.k + meta.config.m) as u64
        } else {
            1024 * 1024 * 1024 * 1024
        };
        let free = usable.saturating_sub(logical_used);
        reply.statfs(
            usable / block,
            free / block,
            free / block,
            meta.inodes.len() as u64 + 1_000_000,
            1_000_000,
            block as u32,
            255,
            block as u32,
        );
    }

    fn release(
        &mut self,
        _req: &Request<'_>,
        _ino: u64,
        _fh: u64,
        _flags: i32,
        _lock_owner: Option<u64>,
        _flush: bool,
        reply: ReplyEmpty,
    ) {
        reply.ok();
    }

    fn fsync(
        &mut self,
        _req: &Request<'_>,
        _ino: u64,
        _fh: u64,
        _datasync: bool,
        reply: ReplyEmpty,
    ) {
        reply.ok();
    }

    fn setxattr(
        &mut self,
        req: &Request<'_>,
        ino: u64,
        name: &OsStr,
        value: &[u8],
        _flags: i32,
        _position: u32,
        reply: ReplyEmpty,
    ) {
        match self.require_access(req, ino, libc::W_OK).and_then(|()| {
            self.volume
                .setxattr_inode(ino, &name.to_string_lossy(), value)
        }) {
            Ok(()) => reply.ok(),
            Err(err) => reply.error(err.errno()),
        }
    }

    fn getxattr(
        &mut self,
        req: &Request<'_>,
        ino: u64,
        name: &OsStr,
        size: u32,
        reply: ReplyXattr,
    ) {
        match self
            .require_access(req, ino, libc::R_OK)
            .and_then(|()| self.volume.getxattr_inode(ino, &name.to_string_lossy()))
        {
            Ok(value) if size == 0 => reply.size(value.len() as u32),
            Ok(value) if value.len() <= size as usize => reply.data(&value),
            Ok(_) => reply.error(libc::ERANGE),
            Err(err) => reply.error(err.errno()),
        }
    }

    fn listxattr(&mut self, req: &Request<'_>, ino: u64, size: u32, reply: ReplyXattr) {
        match self
            .require_access(req, ino, libc::R_OK)
            .and_then(|()| self.volume.listxattr_inode(ino))
        {
            Ok(names) => {
                let data = names
                    .into_iter()
                    .flat_map(|name| {
                        let mut bytes = name.into_bytes();
                        bytes.push(0);
                        bytes
                    })
                    .collect::<Vec<_>>();
                if size == 0 {
                    reply.size(data.len() as u32);
                } else if data.len() <= size as usize {
                    reply.data(&data);
                } else {
                    reply.error(libc::ERANGE);
                }
            }
            Err(err) => reply.error(err.errno()),
        }
    }

    fn removexattr(&mut self, req: &Request<'_>, ino: u64, name: &OsStr, reply: ReplyEmpty) {
        match self
            .require_access(req, ino, libc::W_OK)
            .and_then(|()| self.volume.removexattr_inode(ino, &name.to_string_lossy()))
        {
            Ok(()) => reply.ok(),
            Err(err) => reply.error(err.errno()),
        }
    }

    fn access(&mut self, req: &Request<'_>, ino: u64, mask: i32, reply: ReplyEmpty) {
        match self.require_access(req, ino, mask) {
            Ok(()) => reply.ok(),
            Err(err) => reply.error(err.errno()),
        }
    }

    fn create(
        &mut self,
        req: &Request<'_>,
        parent: u64,
        name: &OsStr,
        mode: u32,
        umask: u32,
        _flags: i32,
        reply: ReplyCreate,
    ) {
        match self
            .require_access(req, parent, libc::W_OK | libc::X_OK)
            .and_then(|()| {
                self.volume.create_file_at_with_owner(
                    parent,
                    name,
                    mode & !umask,
                    req.uid(),
                    req.gid(),
                )
            }) {
            Ok(attr) => reply.created(
                &TTL,
                &to_file_attr(&attr),
                0,
                attr.ino,
                self.open_reply_flags(),
            ),
            Err(err) => reply.error(err.errno()),
        }
    }

    fn readdir(
        &mut self,
        req: &Request<'_>,
        ino: u64,
        _fh: u64,
        offset: i64,
        mut reply: ReplyDirectory,
    ) {
        match self
            .require_access(req, ino, libc::R_OK | libc::X_OK)
            .and_then(|()| self.volume.readdir(ino))
        {
            Ok(entries) => {
                for (idx, entry) in entries.into_iter().enumerate().skip(offset.max(0) as usize) {
                    let full = reply.add(
                        entry.attr.ino,
                        (idx + 1) as i64,
                        file_type_from_attr(&entry.attr),
                        entry.name,
                    );
                    if full {
                        break;
                    }
                }
                reply.ok();
            }
            Err(err) => reply.error(err.errno()),
        }
    }
}

fn to_file_attr(attr: &NodeAttr) -> FileAttr {
    FileAttr {
        ino: attr.ino,
        size: attr.size,
        blocks: attr.blocks,
        atime: f64_to_system_time(attr.atime),
        mtime: f64_to_system_time(attr.mtime),
        ctime: f64_to_system_time(attr.ctime),
        crtime: f64_to_system_time(attr.ctime),
        kind: file_type_from_attr(attr),
        perm: (attr.mode & 0o7777) as u16,
        nlink: attr.nlink,
        uid: attr.uid,
        gid: attr.gid,
        rdev: attr.rdev,
        blksize: attr.blksize,
        flags: 0,
    }
}

fn file_type_from_attr(attr: &NodeAttr) -> FileType {
    match attr.kind {
        NodeKind::Directory => FileType::Directory,
        NodeKind::File => FileType::RegularFile,
        NodeKind::Symlink => FileType::Symlink,
        NodeKind::Special => match attr.mode & libc::S_IFMT {
            value if value == libc::S_IFCHR => FileType::CharDevice,
            value if value == libc::S_IFBLK => FileType::BlockDevice,
            value if value == libc::S_IFIFO => FileType::NamedPipe,
            value if value == libc::S_IFSOCK => FileType::Socket,
            _ => FileType::RegularFile,
        },
    }
}

fn f64_to_system_time(value: f64) -> SystemTime {
    if value <= 0.0 {
        UNIX_EPOCH
    } else {
        UNIX_EPOCH + Duration::from_secs_f64(value)
    }
}

fn time_or_now(value: TimeOrNow) -> f64 {
    match value {
        TimeOrNow::SpecificTime(time) => time
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs_f64(),
        TimeOrNow::Now => SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs_f64(),
    }
}

fn open_mask(flags: i32) -> i32 {
    let mut mask = match flags & libc::O_ACCMODE {
        libc::O_RDONLY => libc::R_OK,
        libc::O_WRONLY => libc::W_OK,
        libc::O_RDWR => libc::R_OK | libc::W_OK,
        _ => libc::R_OK,
    };
    if flags & libc::O_TRUNC != 0 {
        mask |= libc::W_OK;
    }
    mask
}
