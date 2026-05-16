use crate::error::{ArgosError, Result};
use crate::types::{CapacitySource, DiskStatus, NodeKind};
use crate::volume::{ArgosFs, NodeAttr, RenamePolicy};
use fuser::{
    AccessFlags, BsdFileFlags, Config, Errno, FileAttr, FileHandle, FileType, Filesystem,
    FopenFlags, Generation, INodeNo, KernelConfig, LockOwner, MountOption, OpenFlags, RenameFlags,
    ReplyAttr, ReplyCreate, ReplyData, ReplyDirectory, ReplyEmpty, ReplyEntry, ReplyOpen,
    ReplyStatfs, ReplyWrite, ReplyXattr, Request, TimeOrNow, WriteFlags,
};
use std::ffi::OsStr;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const TTL: Duration = Duration::from_secs(1);

pub struct ArgosFuse {
    volume: ArgosFs,
}

impl ArgosFuse {
    pub fn new(volume: ArgosFs) -> Self {
        Self { volume }
    }

    fn require_access(&self, req: &Request, ino: INodeNo, mask: i32) -> Result<()> {
        self.volume
            .check_access_inode(ino.0, req.uid(), req.gid(), mask)
    }

    fn open_reply_flags(&self) -> FopenFlags {
        if self.volume.io_policy().direct_io {
            FopenFlags::FOPEN_DIRECT_IO
        } else {
            FopenFlags::empty()
        }
    }
}

pub fn mount(
    volume_root: impl AsRef<Path>,
    mountpoint: impl AsRef<Path>,
    foreground: bool,
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
    if !foreground {
        eprintln!(
            "argosfs mount runs in the foreground; --foreground is accepted for CLI compatibility"
        );
    }
    let mut config = Config::default();
    config.mount_options = mount_options;
    fuser::mount2(ArgosFuse::new(volume), mountpoint, &config).map_err(ArgosError::Io)
}

impl Filesystem for ArgosFuse {
    fn init(
        &mut self,
        _req: &Request,
        config: &mut KernelConfig,
    ) -> std::result::Result<(), std::io::Error> {
        let _ = config;
        Ok(())
    }

    fn lookup(&self, req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEntry) {
        match self
            .require_access(req, parent, libc::X_OK)
            .and_then(|()| self.volume.lookup(parent.0, name))
        {
            Ok(attr) => reply.entry(&TTL, &to_file_attr(&attr), Generation(0)),
            Err(err) => reply.error(errno(&err)),
        }
    }

    fn getattr(&self, _req: &Request, ino: INodeNo, _fh: Option<FileHandle>, reply: ReplyAttr) {
        match self.volume.attr_inode(ino.0) {
            Ok(attr) => reply.attr(&TTL, &to_file_attr(&attr)),
            Err(err) => reply.error(errno(&err)),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn setattr(
        &self,
        req: &Request,
        ino: INodeNo,
        mode: Option<u32>,
        uid: Option<u32>,
        gid: Option<u32>,
        size: Option<u64>,
        atime: Option<TimeOrNow>,
        mtime: Option<TimeOrNow>,
        _ctime: Option<SystemTime>,
        _fh: Option<FileHandle>,
        _crtime: Option<SystemTime>,
        _chgtime: Option<SystemTime>,
        _bkuptime: Option<SystemTime>,
        _flags: Option<BsdFileFlags>,
        reply: ReplyAttr,
    ) {
        let result = (|| -> Result<NodeAttr> {
            let current = self.volume.attr_inode(ino.0)?;
            if mode.is_some() && req.uid() != 0 && req.uid() != current.uid {
                return Err(ArgosError::PermissionDenied(
                    "chmod requires file ownership or root".to_string(),
                ));
            }
            if (uid.is_some() || gid.is_some()) && req.uid() != 0 {
                return Err(ArgosError::PermissionDenied(
                    "chown requires root".to_string(),
                ));
            }
            if size.is_some() {
                self.require_access(req, ino, libc::W_OK)?;
            }
            if atime.is_some() || mtime.is_some() {
                let owner_or_root = req.uid() == 0 || req.uid() == current.uid;
                if !owner_or_root && (is_specific_time(&atime) || is_specific_time(&mtime)) {
                    return Err(ArgosError::PermissionDenied(
                        "setting explicit timestamps requires ownership or root".to_string(),
                    ));
                }
                if !owner_or_root {
                    self.require_access(req, ino, libc::W_OK)?;
                }
            }
            let ino = ino.0;
            let mut attr = current;
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
            Err(err) => reply.error(errno(&err)),
        }
    }

    fn readlink(&self, _req: &Request, ino: INodeNo, reply: ReplyData) {
        match self.volume.readlink_inode_bytes(ino.0) {
            Ok(target) => reply.data(&target),
            Err(err) => reply.error(errno(&err)),
        }
    }

    fn mknod(
        &self,
        req: &Request,
        parent: INodeNo,
        name: &OsStr,
        mode: u32,
        umask: u32,
        rdev: u32,
        reply: ReplyEntry,
    ) {
        let file_type = mode & libc::S_IFMT;
        if matches!(file_type, value if value == libc::S_IFCHR || value == libc::S_IFBLK)
            && req.uid() != 0
        {
            reply.error(Errno::EACCES);
            return;
        }
        match self
            .require_access(req, parent, libc::W_OK | libc::X_OK)
            .and_then(|()| {
                self.volume.mknod_at_with_owner(
                    parent.0,
                    name,
                    mode & !umask,
                    rdev as u64,
                    req.uid(),
                    req.gid(),
                )
            }) {
            Ok(attr) => reply.entry(&TTL, &to_file_attr(&attr), Generation(0)),
            Err(err) => reply.error(errno(&err)),
        }
    }

    fn mkdir(
        &self,
        req: &Request,
        parent: INodeNo,
        name: &OsStr,
        mode: u32,
        umask: u32,
        reply: ReplyEntry,
    ) {
        match self
            .require_access(req, parent, libc::W_OK | libc::X_OK)
            .and_then(|()| {
                self.volume
                    .mkdir_at_with_owner(parent.0, name, mode & !umask, req.uid(), req.gid())
            }) {
            Ok(attr) => reply.entry(&TTL, &to_file_attr(&attr), Generation(0)),
            Err(err) => reply.error(errno(&err)),
        }
    }

    fn unlink(&self, req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        match self
            .require_access(req, parent, libc::W_OK | libc::X_OK)
            .and_then(|()| self.volume.unlink_at_as(parent.0, name, req.uid()))
        {
            Ok(()) => reply.ok(),
            Err(err) => reply.error(errno(&err)),
        }
    }

    fn rmdir(&self, req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        match self
            .require_access(req, parent, libc::W_OK | libc::X_OK)
            .and_then(|()| self.volume.rmdir_at_as(parent.0, name, req.uid()))
        {
            Ok(()) => reply.ok(),
            Err(err) => reply.error(errno(&err)),
        }
    }

    fn symlink(
        &self,
        req: &Request,
        parent: INodeNo,
        name: &OsStr,
        link: &Path,
        reply: ReplyEntry,
    ) {
        match self
            .require_access(req, parent, libc::W_OK | libc::X_OK)
            .and_then(|()| {
                self.volume
                    .symlink_at_with_owner(parent.0, name, link, req.uid(), req.gid())
            }) {
            Ok(attr) => reply.entry(&TTL, &to_file_attr(&attr), Generation(0)),
            Err(err) => reply.error(errno(&err)),
        }
    }

    fn rename(
        &self,
        req: &Request,
        parent: INodeNo,
        name: &OsStr,
        newparent: INodeNo,
        newname: &OsStr,
        flags: RenameFlags,
        reply: ReplyEmpty,
    ) {
        let supported_flags = RenameFlags::RENAME_NOREPLACE
            | RenameFlags::RENAME_EXCHANGE
            | RenameFlags::RENAME_WHITEOUT;
        if flags.bits() & !supported_flags.bits() != 0
            || flags.contains(RenameFlags::RENAME_WHITEOUT)
            || flags.contains(RenameFlags::RENAME_NOREPLACE)
                && flags.contains(RenameFlags::RENAME_EXCHANGE)
        {
            reply.error(Errno::EINVAL);
            return;
        }
        let policy = RenamePolicy {
            no_replace: flags.contains(RenameFlags::RENAME_NOREPLACE),
            exchange: flags.contains(RenameFlags::RENAME_EXCHANGE),
            uid: Some(req.uid()),
        };
        let result = self
            .require_access(req, parent, libc::W_OK | libc::X_OK)
            .and_then(|()| self.require_access(req, newparent, libc::W_OK | libc::X_OK))
            .and_then(|()| {
                self.volume
                    .rename_at_with_policy(parent.0, name, newparent.0, newname, policy)
            });
        match result {
            Ok(()) => reply.ok(),
            Err(err) => reply.error(errno(&err)),
        }
    }

    fn link(
        &self,
        req: &Request,
        ino: INodeNo,
        newparent: INodeNo,
        newname: &OsStr,
        reply: ReplyEntry,
    ) {
        match self
            .require_access(req, newparent, libc::W_OK | libc::X_OK)
            .and_then(|()| self.volume.link_at(ino.0, newparent.0, newname))
        {
            Ok(attr) => reply.entry(&TTL, &to_file_attr(&attr), Generation(0)),
            Err(err) => reply.error(errno(&err)),
        }
    }

    fn open(&self, req: &Request, ino: INodeNo, flags: OpenFlags, reply: ReplyOpen) {
        let result = (|| -> Result<NodeAttr> {
            self.require_access(req, ino, open_mask(flags))?;
            let mut attr = self.volume.attr_inode(ino.0)?;
            if attr.kind != NodeKind::File {
                return Err(ArgosError::IsDirectory(format!("inode {ino}")));
            }
            if flags.0 & libc::O_TRUNC != 0 {
                self.volume.truncate_inode(ino.0, 0)?;
                attr = self.volume.attr_inode(ino.0)?;
            }
            Ok(attr)
        })();
        match result {
            Ok(_) => reply.opened(FileHandle(ino.0), self.open_reply_flags()),
            Err(err) => reply.error(errno(&err)),
        }
    }

    fn read(
        &self,
        req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        offset: u64,
        size: u32,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        reply: ReplyData,
    ) {
        match self
            .require_access(req, ino, libc::R_OK)
            .and_then(|()| self.volume.read_inode(ino.0, offset, size as usize, true))
        {
            Ok(data) => reply.data(&data),
            Err(err) => reply.error(errno(&err)),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn write(
        &self,
        req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        offset: u64,
        data: &[u8],
        _write_flags: WriteFlags,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        reply: ReplyWrite,
    ) {
        match self
            .require_access(req, ino, libc::W_OK)
            .and_then(|()| self.volume.write_inode_range(ino.0, offset, data))
        {
            Ok(written) => reply.written(written as u32),
            Err(err) => reply.error(errno(&err)),
        }
    }

    fn statfs(&self, _req: &Request, _ino: INodeNo, reply: ReplyStatfs) {
        let meta = self.volume.metadata_snapshot();
        let block = meta.config.chunk_size as u64;
        let (explicit_capacity, grouped_capacity) = meta
            .disks
            .values()
            .filter(|disk| disk.status == DiskStatus::Online)
            .fold(
                (0u64, std::collections::BTreeMap::<String, u64>::new()),
                |mut acc, disk| {
                    if disk.capacity_source == CapacitySource::UserOverride {
                        acc.0 = acc.0.saturating_add(disk.capacity_bytes);
                    } else if let Some(fs_id) = disk.backing_fs_id.as_ref() {
                        let entry = acc.1.entry(fs_id.clone()).or_default();
                        *entry = (*entry).max(disk.capacity_bytes);
                    } else {
                        acc.0 = acc.0.saturating_add(disk.capacity_bytes);
                    }
                    acc
                },
            );
        let raw_capacity = explicit_capacity.saturating_add(grouped_capacity.values().sum::<u64>());
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
        &self,
        _req: &Request,
        _ino: INodeNo,
        _fh: FileHandle,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        _flush: bool,
        reply: ReplyEmpty,
    ) {
        reply.ok();
    }

    fn fsync(
        &self,
        _req: &Request,
        _ino: INodeNo,
        _fh: FileHandle,
        _datasync: bool,
        reply: ReplyEmpty,
    ) {
        match self.volume.sync() {
            Ok(()) => reply.ok(),
            Err(err) => reply.error(errno(&err)),
        }
    }

    fn setxattr(
        &self,
        req: &Request,
        ino: INodeNo,
        name: &OsStr,
        value: &[u8],
        flags: i32,
        _position: u32,
        reply: ReplyEmpty,
    ) {
        let result = (|| -> Result<()> {
            let supported = libc::XATTR_CREATE | libc::XATTR_REPLACE;
            if flags & !supported != 0
                || flags & libc::XATTR_CREATE != 0 && flags & libc::XATTR_REPLACE != 0
            {
                return Err(ArgosError::Invalid(format!(
                    "unsupported setxattr flags {flags:#x}"
                )));
            }

            self.require_access(req, ino, libc::W_OK)?;
            let name = name.to_string_lossy();
            let exists = self.volume.getxattr_inode(ino.0, &name).is_ok();

            if flags & libc::XATTR_CREATE != 0 && exists {
                return Err(ArgosError::AlreadyExists(format!("xattr {name}")));
            }
            if flags & libc::XATTR_REPLACE != 0 && !exists {
                return Err(ArgosError::NotFound(format!("xattr {name}")));
            }

            self.volume.setxattr_inode(ino.0, &name, value)
        })();

        match result {
            Ok(()) => reply.ok(),
            Err(err) => reply.error(errno(&err)),
        }
    }

    fn getxattr(&self, req: &Request, ino: INodeNo, name: &OsStr, size: u32, reply: ReplyXattr) {
        match self
            .require_access(req, ino, libc::R_OK)
            .and_then(|()| self.volume.getxattr_inode(ino.0, &name.to_string_lossy()))
        {
            Ok(value) if size == 0 => reply.size(value.len() as u32),
            Ok(value) if value.len() <= size as usize => reply.data(&value),
            Ok(_) => reply.error(Errno::ERANGE),
            Err(err) => reply.error(errno(&err)),
        }
    }

    fn listxattr(&self, req: &Request, ino: INodeNo, size: u32, reply: ReplyXattr) {
        match self
            .require_access(req, ino, libc::R_OK)
            .and_then(|()| self.volume.listxattr_inode(ino.0))
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
                    reply.error(Errno::ERANGE);
                }
            }
            Err(err) => reply.error(errno(&err)),
        }
    }

    fn removexattr(&self, req: &Request, ino: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        match self.require_access(req, ino, libc::W_OK).and_then(|()| {
            self.volume
                .removexattr_inode(ino.0, &name.to_string_lossy())
        }) {
            Ok(()) => reply.ok(),
            Err(err) => reply.error(errno(&err)),
        }
    }

    fn access(&self, req: &Request, ino: INodeNo, mask: AccessFlags, reply: ReplyEmpty) {
        match self.require_access(req, ino, mask.bits()) {
            Ok(()) => reply.ok(),
            Err(err) => reply.error(errno(&err)),
        }
    }

    fn create(
        &self,
        req: &Request,
        parent: INodeNo,
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
                    parent.0,
                    name,
                    mode & !umask,
                    req.uid(),
                    req.gid(),
                )
            }) {
            Ok(attr) => reply.created(
                &TTL,
                &to_file_attr(&attr),
                Generation(0),
                FileHandle(attr.ino),
                self.open_reply_flags(),
            ),
            Err(err) => reply.error(errno(&err)),
        }
    }

    fn readdir(
        &self,
        req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        offset: u64,
        mut reply: ReplyDirectory,
    ) {
        match self
            .require_access(req, ino, libc::R_OK | libc::X_OK)
            .and_then(|()| self.volume.readdir(ino.0))
        {
            Ok(entries) => {
                for (idx, entry) in entries.into_iter().enumerate().skip(offset as usize) {
                    let full = reply.add(
                        INodeNo(entry.attr.ino),
                        (idx + 1) as u64,
                        file_type_from_attr(&entry.attr),
                        entry.os_name(),
                    );
                    if full {
                        break;
                    }
                }
                reply.ok();
            }
            Err(err) => reply.error(errno(&err)),
        }
    }
}

fn to_file_attr(attr: &NodeAttr) -> FileAttr {
    FileAttr {
        ino: INodeNo(attr.ino),
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
        rdev: attr.rdev as u32,
        blksize: attr.blksize,
        flags: 0,
    }
}

fn errno(err: &ArgosError) -> Errno {
    Errno::from_i32(err.errno())
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

fn is_specific_time(value: &Option<TimeOrNow>) -> bool {
    matches!(value, Some(TimeOrNow::SpecificTime(_)))
}

fn open_mask(flags: OpenFlags) -> i32 {
    let mut mask = match flags.0 & libc::O_ACCMODE {
        libc::O_RDONLY => libc::R_OK,
        libc::O_WRONLY => libc::W_OK,
        libc::O_RDWR => libc::R_OK | libc::W_OK,
        _ => libc::R_OK,
    };
    if flags.0 & libc::O_TRUNC != 0 {
        mask |= libc::W_OK;
    }
    mask
}
