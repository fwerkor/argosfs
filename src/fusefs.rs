use crate::acl;
use crate::error::{ArgosError, Result};
use crate::types::{CapacitySource, DiskStatus, InodeId, NodeKind};
use crate::volume::{ArgosFs, NodeAttr, RenamePolicy};
use fuser::{
    AccessFlags, BsdFileFlags, Config, Errno, FileAttr, FileHandle, FileType, Filesystem,
    FopenFlags, Generation, INodeNo, InitFlags, KernelConfig, LockOwner, MountOption, OpenFlags,
    RenameFlags, ReplyAttr, ReplyCreate, ReplyData, ReplyDirectory, ReplyDirectoryPlus, ReplyEmpty,
    ReplyEntry, ReplyOpen, ReplyStatfs, ReplyWrite, ReplyXattr, Request, SessionACL, TimeOrNow,
    WriteFlags,
};
use parking_lot::Mutex;
use std::collections::BTreeMap;
use std::ffi::{CString, OsStr};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const TTL: Duration = Duration::from_secs(5);
const FUSE_WRITEBACK_MAX_BYTES: usize = 1024 * 1024;

pub struct ArgosFuse {
    volume: ArgosFs,
    writeback: Mutex<FuseWriteback>,
}

#[derive(Clone, Debug)]
struct DirtyExtent {
    offset: u64,
    data: Vec<u8>,
}

impl DirtyExtent {
    fn end(&self) -> Option<u64> {
        self.offset.checked_add(self.data.len() as u64)
    }

    fn try_merge(&mut self, offset: u64, data: &[u8], max_bytes: usize) -> bool {
        let Some(existing_end) = self.end() else {
            return false;
        };
        let Some(new_end) = offset.checked_add(data.len() as u64) else {
            return false;
        };
        if offset > existing_end || self.offset > new_end {
            return false;
        }
        let merged_start = self.offset.min(offset);
        let merged_end = existing_end.max(new_end);
        let merged_len = match usize::try_from(merged_end.saturating_sub(merged_start)) {
            Ok(len) if len <= max_bytes => len,
            _ => return false,
        };
        let mut merged = vec![0; merged_len];
        let old_start = (self.offset - merged_start) as usize;
        merged[old_start..old_start + self.data.len()].copy_from_slice(&self.data);
        let new_start = (offset - merged_start) as usize;
        merged[new_start..new_start + data.len()].copy_from_slice(data);
        self.offset = merged_start;
        self.data = merged;
        true
    }
}

#[derive(Default)]
struct FuseWriteback {
    dirty: BTreeMap<InodeId, DirtyExtent>,
}

impl ArgosFuse {
    pub fn new(volume: ArgosFs) -> Self {
        Self {
            volume,
            writeback: Mutex::new(FuseWriteback::default()),
        }
    }

    fn require_access(&self, req: &Request, ino: INodeNo, mask: i32) -> Result<()> {
        self.volume
            .check_access_inode(ino.0, req.uid(), req.gid(), mask)
    }

    fn open_reply_flags(&self, write_open: bool) -> FopenFlags {
        let mut flags = FopenFlags::empty();
        if self.volume.io_policy().direct_io {
            flags |= FopenFlags::FOPEN_DIRECT_IO;
        }
        if write_open {
            flags |= FopenFlags::FOPEN_NOFLUSH;
        } else if !self.volume.io_policy().direct_io {
            flags |= FopenFlags::FOPEN_KEEP_CACHE;
        }
        flags
    }

    fn require_xattr_write_access(&self, req: &Request, ino: INodeNo, name: &str) -> Result<()> {
        if name.starts_with("user.") {
            return self.require_access(req, ino, libc::W_OK);
        }
        if is_owner_managed_xattr(name) {
            let attr = self.volume.attr_inode(ino.0)?;
            if req.uid() == 0 || req.uid() == attr.uid {
                return Ok(());
            }
            return Err(ArgosError::PermissionDenied(format!(
                "xattr {name} requires file ownership or root"
            )));
        }
        if name.starts_with("trusted.")
            || name.starts_with("security.")
            || name.starts_with("system.argosfs.")
            || name.starts_with("system.")
        {
            if req.uid() == 0 {
                return Ok(());
            }
            return Err(ArgosError::PermissionDenied(format!(
                "xattr namespace requires root: {name}"
            )));
        }
        self.require_access(req, ino, libc::W_OK)
    }

    fn require_writeback_access(&self, req: &Request, ino: INodeNo) -> Result<()> {
        self.require_access(req, ino, libc::W_OK)?;
        let attr = self.volume.attr_inode(ino.0)?;
        if attr.kind != NodeKind::File {
            return Err(ArgosError::IsDirectory(format!("inode {ino}")));
        }
        Ok(())
    }

    fn queue_writeback(&self, ino: InodeId, offset: u64, data: &[u8]) -> bool {
        if data.len() > FUSE_WRITEBACK_MAX_BYTES {
            return false;
        }
        let mut writeback = self.writeback.lock();
        if let Some(dirty) = writeback.dirty.get_mut(&ino) {
            return dirty.try_merge(offset, data, FUSE_WRITEBACK_MAX_BYTES);
        }
        writeback.dirty.insert(
            ino,
            DirtyExtent {
                offset,
                data: data.to_vec(),
            },
        );
        true
    }

    fn flush_inode_writeback(&self, ino: InodeId) -> Result<()> {
        let mut writeback = self.writeback.lock();
        let Some(dirty) = writeback.dirty.remove(&ino) else {
            return Ok(());
        };
        match self
            .volume
            .write_inode_range(ino, dirty.offset, dirty.data.as_slice())
        {
            Ok(written) if written == dirty.data.len() => Ok(()),
            Ok(written) => {
                writeback.dirty.insert(ino, dirty);
                Err(ArgosError::Invalid(format!(
                    "short writeback flush for inode {ino}: wrote {written} bytes"
                )))
            }
            Err(err) => {
                writeback.dirty.insert(ino, dirty);
                Err(err)
            }
        }
    }

    fn flush_all_writeback(&self) -> Result<()> {
        loop {
            let next = self.writeback.lock().dirty.keys().next().copied();
            let Some(ino) = next else {
                return Ok(());
            };
            self.flush_inode_writeback(ino)?;
        }
    }
}

impl Drop for ArgosFuse {
    fn drop(&mut self) {
        let _ = self.flush_all_writeback();
        let _ = self.volume.sync();
    }
}

pub fn mount(
    volume_root: impl AsRef<Path>,
    mountpoint: impl AsRef<Path>,
    foreground: bool,
    options: Vec<String>,
) -> Result<()> {
    let volume = ArgosFs::open(volume_root)?;
    mount_volume(volume, mountpoint, foreground, options)
}

pub fn mount_volume(
    volume: ArgosFs,
    mountpoint: impl AsRef<Path>,
    foreground: bool,
    options: Vec<String>,
) -> Result<()> {
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
    let config = mount_config(mount_options);
    fuser::mount2(ArgosFuse::new(volume), mountpoint, &config).map_err(ArgosError::Io)
}

fn mount_config(options: Vec<MountOption>) -> Config {
    let mut config = Config::default();
    for option in options {
        match option {
            MountOption::CUSTOM(ref value) if value == "allow_other" => {
                config.acl = SessionACL::All;
            }
            MountOption::CUSTOM(ref value) if value == "allow_root" => {
                if config.acl != SessionACL::All {
                    config.acl = SessionACL::RootAndOwner;
                }
            }
            other => config.mount_options.push(normalize_mount_option(other)),
        }
    }
    config
}

fn normalize_mount_option(option: MountOption) -> MountOption {
    match option {
        MountOption::CUSTOM(value) => match value.as_str() {
            "auto_unmount" => MountOption::AutoUnmount,
            "default_permissions" => MountOption::DefaultPermissions,
            "dev" => MountOption::Dev,
            "nodev" => MountOption::NoDev,
            "suid" => MountOption::Suid,
            "nosuid" => MountOption::NoSuid,
            "ro" => MountOption::RO,
            "rw" => MountOption::RW,
            "exec" => MountOption::Exec,
            "noexec" => MountOption::NoExec,
            "atime" => MountOption::Atime,
            "noatime" => MountOption::NoAtime,
            "dirsync" => MountOption::DirSync,
            "sync" => MountOption::Sync,
            "async" => MountOption::Async,
            _ if value.starts_with("fsname=") => MountOption::FSName(value[7..].to_string()),
            _ if value.starts_with("subtype=") => MountOption::Subtype(value[8..].to_string()),
            _ => MountOption::CUSTOM(value),
        },
        other => other,
    }
}

impl Filesystem for ArgosFuse {
    fn init(
        &mut self,
        _req: &Request,
        config: &mut KernelConfig,
    ) -> std::result::Result<(), std::io::Error> {
        let _ = config.set_max_write(1024 * 1024);
        let _ = config.set_max_readahead(1024 * 1024);
        let _ = config.set_max_background(64);
        let _ = config.set_congestion_threshold(48);
        let _ = config
            .add_capabilities(InitFlags::FUSE_PARALLEL_DIROPS | InitFlags::FUSE_READDIRPLUS_AUTO);
        Ok(())
    }

    fn lookup(&self, req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEntry) {
        if let Err(err) = self.flush_all_writeback() {
            reply.error(errno(&err));
            return;
        }
        match self
            .require_access(req, parent, libc::X_OK)
            .and_then(|()| self.volume.lookup(parent.0, name))
        {
            Ok(attr) => reply.entry(&TTL, &to_file_attr(&attr), Generation(0)),
            Err(err) => reply.error(errno(&err)),
        }
    }

    fn getattr(&self, _req: &Request, ino: INodeNo, _fh: Option<FileHandle>, reply: ReplyAttr) {
        if let Err(err) = self.flush_inode_writeback(ino.0) {
            reply.error(errno(&err));
            return;
        }
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
        if let Err(err) = self.flush_inode_writeback(ino.0) {
            reply.error(errno(&err));
            return;
        }
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
        if let Err(err) = self.flush_inode_writeback(ino.0) {
            reply.error(errno(&err));
            return;
        }
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
        if let Err(err) = self.flush_all_writeback() {
            reply.error(errno(&err));
            return;
        }
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
        if let Err(err) = self.flush_all_writeback() {
            reply.error(errno(&err));
            return;
        }
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
        if let Err(err) = self.flush_all_writeback() {
            reply.error(errno(&err));
            return;
        }
        match self
            .require_access(req, parent, libc::W_OK | libc::X_OK)
            .and_then(|()| self.volume.unlink_at_as(parent.0, name, req.uid()))
        {
            Ok(()) => reply.ok(),
            Err(err) => reply.error(errno(&err)),
        }
    }

    fn rmdir(&self, req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        if let Err(err) = self.flush_all_writeback() {
            reply.error(errno(&err));
            return;
        }
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
        if let Err(err) = self.flush_all_writeback() {
            reply.error(errno(&err));
            return;
        }
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
        if let Err(err) = self.flush_all_writeback() {
            reply.error(errno(&err));
            return;
        }
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
        if let Err(err) = self.flush_all_writeback() {
            reply.error(errno(&err));
            return;
        }
        match self
            .require_access(req, newparent, libc::W_OK | libc::X_OK)
            .and_then(|()| self.volume.link_at(ino.0, newparent.0, newname))
        {
            Ok(attr) => reply.entry(&TTL, &to_file_attr(&attr), Generation(0)),
            Err(err) => reply.error(errno(&err)),
        }
    }

    fn open(&self, req: &Request, ino: INodeNo, flags: OpenFlags, reply: ReplyOpen) {
        if flags.0 & libc::O_TRUNC != 0 {
            if let Err(err) = self.flush_inode_writeback(ino.0) {
                reply.error(errno(&err));
                return;
            }
        }
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
            Ok(_) => reply.opened(
                FileHandle(ino.0),
                self.open_reply_flags(flags.0 & (libc::O_WRONLY | libc::O_RDWR) != 0),
            ),
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
        if let Err(err) = self.flush_inode_writeback(ino.0) {
            reply.error(errno(&err));
            return;
        }
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
        if data.is_empty() {
            reply.written(0);
            return;
        }
        let direct = self.volume.io_policy().direct_io || data.len() > FUSE_WRITEBACK_MAX_BYTES;
        let result = if direct {
            self.flush_inode_writeback(ino.0).and_then(|()| {
                self.volume
                    .write_inode_range_as(ino.0, offset, data, req.uid(), req.gid())
            })
        } else {
            self.require_writeback_access(req, ino).and_then(|()| {
                if self.queue_writeback(ino.0, offset, data) {
                    Ok(data.len())
                } else {
                    self.flush_inode_writeback(ino.0)?;
                    if self.queue_writeback(ino.0, offset, data) {
                        Ok(data.len())
                    } else {
                        self.volume
                            .write_inode_range_as(ino.0, offset, data, req.uid(), req.gid())
                    }
                }
            })
        };
        match result {
            Ok(written) => reply.written(written as u32),
            Err(err) => reply.error(errno(&err)),
        }
    }

    fn statfs(&self, _req: &Request, _ino: INodeNo, reply: ReplyStatfs) {
        if let Err(err) = self.flush_all_writeback() {
            reply.error(errno(&err));
            return;
        }
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
        let (raw_capacity, raw_free) = if raw_capacity > 0 {
            (raw_capacity, 0)
        } else {
            fallback_statfs_capacity(
                self.volume.root(),
                meta.disks.values().map(|disk| {
                    if disk.path.is_absolute() {
                        disk.path.clone()
                    } else {
                        self.volume.root().join(&disk.path)
                    }
                }),
            )
        };
        let usable = raw_capacity.saturating_mul(meta.config.k as u64)
            / (meta.config.k + meta.config.m) as u64;
        let free = if raw_free > 0 {
            raw_free.saturating_mul(meta.config.k as u64) / (meta.config.k + meta.config.m) as u64
        } else {
            usable.saturating_sub(logical_used)
        };
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
        match self.flush_inode_writeback(_ino.0) {
            Ok(()) => reply.ok(),
            Err(err) => reply.error(errno(&err)),
        }
    }

    fn fsync(
        &self,
        _req: &Request,
        _ino: INodeNo,
        _fh: FileHandle,
        _datasync: bool,
        reply: ReplyEmpty,
    ) {
        match self
            .flush_inode_writeback(_ino.0)
            .and_then(|()| self.volume.sync())
        {
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
        position: u32,
        reply: ReplyEmpty,
    ) {
        if let Err(err) = self.flush_inode_writeback(ino.0) {
            reply.error(errno(&err));
            return;
        }
        let result = (|| -> Result<()> {
            if position != 0 {
                return Err(ArgosError::Invalid(format!(
                    "unsupported setxattr position {position}"
                )));
            }

            let supported = libc::XATTR_CREATE | libc::XATTR_REPLACE;
            if flags & !supported != 0
                || flags & libc::XATTR_CREATE != 0 && flags & libc::XATTR_REPLACE != 0
            {
                return Err(ArgosError::Invalid(format!(
                    "unsupported setxattr flags {flags:#x}"
                )));
            }

            let name = xattr_name(name)?;
            self.require_xattr_write_access(req, ino, name)?;
            let exists = self.volume.getxattr_inode(ino.0, name).is_ok();

            if flags & libc::XATTR_CREATE != 0 && exists {
                return Err(ArgosError::AlreadyExists(format!("xattr {name}")));
            }
            if flags & libc::XATTR_REPLACE != 0 && !exists {
                return Err(ArgosError::NotFound(format!("xattr {name}")));
            }

            self.volume.setxattr_inode(ino.0, name, value)
        })();

        match result {
            Ok(()) => reply.ok(),
            Err(err) => reply.error(errno(&err)),
        }
    }

    fn getxattr(&self, req: &Request, ino: INodeNo, name: &OsStr, size: u32, reply: ReplyXattr) {
        if let Err(err) = self.flush_inode_writeback(ino.0) {
            reply.error(errno(&err));
            return;
        }
        let result = self
            .require_access(req, ino, libc::R_OK)
            .and_then(|()| self.volume.getxattr_inode(ino.0, xattr_name(name)?));
        match result {
            Ok(value) if size == 0 => reply.size(value.len() as u32),
            Ok(value) if value.len() <= size as usize => reply.data(&value),
            Ok(_) => reply.error(Errno::ERANGE),
            Err(err) => reply.error(xattr_errno(&err)),
        }
    }

    fn listxattr(&self, req: &Request, ino: INodeNo, size: u32, reply: ReplyXattr) {
        if let Err(err) = self.flush_inode_writeback(ino.0) {
            reply.error(errno(&err));
            return;
        }
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
        if let Err(err) = self.flush_inode_writeback(ino.0) {
            reply.error(errno(&err));
            return;
        }
        let result = (|| {
            let name = xattr_name(name)?;
            self.require_xattr_write_access(req, ino, name)?;
            self.volume.removexattr_inode(ino.0, name)
        })();
        match result {
            Ok(()) => reply.ok(),
            Err(err) => reply.error(xattr_errno(&err)),
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
        if let Err(err) = self.flush_all_writeback() {
            reply.error(errno(&err));
            return;
        }
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
                self.open_reply_flags(true),
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
        if let Err(err) = self.flush_all_writeback() {
            reply.error(errno(&err));
            return;
        }
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

    fn readdirplus(
        &self,
        req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        offset: u64,
        mut reply: ReplyDirectoryPlus,
    ) {
        if let Err(err) = self.flush_all_writeback() {
            reply.error(errno(&err));
            return;
        }
        match self
            .require_access(req, ino, libc::R_OK | libc::X_OK)
            .and_then(|()| self.volume.readdir(ino.0))
        {
            Ok(entries) => {
                for (idx, entry) in entries.into_iter().enumerate().skip(offset as usize) {
                    let attr = to_file_attr(&entry.attr);
                    let full = reply.add(
                        INodeNo(entry.attr.ino),
                        (idx + 1) as u64,
                        entry.os_name(),
                        &TTL,
                        &attr,
                        Generation(0),
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

fn is_owner_managed_xattr(name: &str) -> bool {
    matches!(
        name,
        acl::POSIX_ACL_ACCESS_XATTR
            | acl::POSIX_ACL_DEFAULT_XATTR
            | acl::ARGOS_POSIX_ACL_ACCESS_XATTR
            | acl::ARGOS_POSIX_ACL_DEFAULT_XATTR
    )
}

fn fallback_statfs_capacity(root: &Path, paths: impl IntoIterator<Item = PathBuf>) -> (u64, u64) {
    let mut capacity = 0u64;
    let mut free = 0u64;
    let mut seen = std::collections::BTreeSet::new();
    for path in std::iter::once(root.to_path_buf()).chain(paths) {
        let Some((fs_id, blocks, available)) = statvfs_capacity(&path) else {
            continue;
        };
        if seen.insert(fs_id) {
            capacity = capacity.saturating_add(blocks);
            free = free.saturating_add(available);
        }
    }
    (capacity, free)
}

fn statvfs_capacity(path: &Path) -> Option<(String, u64, u64)> {
    let c_path = CString::new(path.as_os_str().as_bytes()).ok()?;
    let mut stat = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    let rc = unsafe { libc::statvfs(c_path.as_ptr(), stat.as_mut_ptr()) };
    if rc != 0 {
        return None;
    }
    let stat = unsafe { stat.assume_init() };
    let block_size = stat.f_frsize.max(stat.f_bsize);
    let fs_id = format!("{}:{}", stat.f_fsid, block_size);
    Some((
        fs_id,
        stat.f_blocks.saturating_mul(block_size),
        stat.f_bavail.saturating_mul(block_size),
    ))
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

fn xattr_errno(err: &ArgosError) -> Errno {
    match err {
        ArgosError::NotFound(_) => Errno::NO_XATTR,
        _ => errno(err),
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

fn xattr_name(name: &OsStr) -> Result<&str> {
    name.to_str()
        .ok_or_else(|| ArgosError::Invalid("non-UTF-8 xattr names are unsupported".to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::VolumeConfig;

    #[test]
    fn allow_other_sets_fuser_session_acl() {
        let config = mount_config(vec![
            MountOption::FSName("argosfs".to_string()),
            MountOption::Subtype("argosfs".to_string()),
            MountOption::CUSTOM("allow_other".to_string()),
            MountOption::CUSTOM("default_permissions".to_string()),
        ]);

        assert_eq!(config.acl, SessionACL::All);
        assert!(config
            .mount_options
            .contains(&MountOption::DefaultPermissions));
        assert!(!config
            .mount_options
            .contains(&MountOption::CUSTOM("allow_other".to_string())));
    }

    #[test]
    fn allow_other_wins_over_allow_root() {
        let config = mount_config(vec![
            MountOption::CUSTOM("allow_root".to_string()),
            MountOption::CUSTOM("allow_other".to_string()),
        ]);

        assert_eq!(config.acl, SessionACL::All);
    }

    #[test]
    fn missing_xattr_maps_to_enodata() {
        let err = ArgosError::NotFound("xattr security.selinux".to_string());
        assert_eq!(xattr_errno(&err).code(), Errno::NO_XATTR.code());
    }

    #[test]
    fn dirty_extent_merges_adjacent_and_overlapping_writes() {
        let mut dirty = DirtyExtent {
            offset: 10,
            data: b"abcd".to_vec(),
        };

        assert!(dirty.try_merge(14, b"ef", 16));
        assert_eq!(dirty.offset, 10);
        assert_eq!(dirty.data, b"abcdef");

        assert!(dirty.try_merge(12, b"XY", 16));
        assert_eq!(dirty.offset, 10);
        assert_eq!(dirty.data, b"abXYef");
    }

    #[test]
    fn dirty_extent_rejects_gaps_and_oversized_merges() {
        let mut dirty = DirtyExtent {
            offset: 10,
            data: b"abcd".to_vec(),
        };

        assert!(!dirty.try_merge(15, b"z", 16));
        assert_eq!(dirty.offset, 10);
        assert_eq!(dirty.data, b"abcd");

        assert!(!dirty.try_merge(14, b"efgh", 6));
        assert_eq!(dirty.offset, 10);
        assert_eq!(dirty.data, b"abcd");
    }

    #[test]
    fn fuse_writeback_flushes_merged_extent_to_volume() {
        let tmp = tempfile::tempdir().unwrap();
        let volume = ArgosFs::create(
            tmp.path(),
            VolumeConfig {
                k: 1,
                m: 0,
                ..VolumeConfig::default()
            },
            1,
            false,
        )
        .unwrap();
        let ino = volume.create_file_path("/buffered", 0o644).unwrap();
        let fuse = ArgosFuse::new(volume.clone());

        assert!(fuse.queue_writeback(ino, 0, b"hello"));
        assert!(fuse.queue_writeback(ino, 5, b" world"));
        assert_eq!(volume.read_file("/buffered", true).unwrap(), b"");

        fuse.flush_inode_writeback(ino).unwrap();

        assert_eq!(volume.read_file("/buffered", true).unwrap(), b"hello world");
        assert!(fuse.writeback.lock().dirty.is_empty());
    }
}
