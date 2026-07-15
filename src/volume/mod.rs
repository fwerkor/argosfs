use crate::acl;
use crate::advanced_io;
use crate::allocator;
use crate::autopilot::{plan_background_io, AutopilotMode, AutopilotPolicy, BackgroundIoPolicy};
use crate::backend::{FileBlockBackend, HostFsBackend, StorageBackend};
use crate::cache::BlockCache;
use crate::compression::{compress, decompress};
use crate::crypto;
use crate::erasure::RsCodec;
use crate::error::{ArgosError, Result};
use crate::health::{classify_inode, probe_disk_path, refresh_smart, risk_report};
pub use crate::inode_ops::{DirEntry, NodeAttr, RenamePolicy};
use crate::journal;
use crate::raw_format::{self, RawSuperblock};
use crate::raw_store;
use crate::types::*;
use crate::util::{
    append_json_line, atomic_write, clean_path, content_hash_hex, content_hash_matches, ensure_dir,
    ensure_private_dir, now_f64, parent_name, relative_or_absolute, split_path, stable_u01,
};
use parking_lot::{Mutex, RwLock};
use serde_json::json;
use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use uuid::Uuid;

thread_local! {
    static THREAD_BULK_IMPORT_MODE: Cell<Option<bool>> = const { Cell::new(None) };
}

pub struct BulkImportModeGuard {
    previous: Option<bool>,
}

impl Drop for BulkImportModeGuard {
    fn drop(&mut self) {
        THREAD_BULK_IMPORT_MODE.with(|value| value.set(self.previous));
    }
}

pub fn bulk_import_scope(enabled: bool) -> BulkImportModeGuard {
    let previous = THREAD_BULK_IMPORT_MODE.with(|value| value.replace(Some(enabled)));
    BulkImportModeGuard { previous }
}

fn bulk_import_enabled() -> bool {
    THREAD_BULK_IMPORT_MODE
        .with(|value| value.get())
        .unwrap_or_else(|| std::env::var_os("ARGOSFS_BULK_IMPORT_COMMIT").is_some())
}

const ROOT_INO: InodeId = 1;
const NON_UTF8_NAME_PREFIX: &str = ".argosfs-name-nonutf8-v3:";
const ESCAPED_UTF8_NAME_PREFIX: &str = ".argosfs-name-utf8-v3:";
const LEGACY_NON_UTF8_NAME_PREFIX: &str = "\0argosfs-name-hex:";
const NON_UTF8_SYMLINK_TARGET_PREFIX: &str = "\0argosfs-symlink-target-hex:";
const BOOT_CRITICAL_XATTR: &str = "system.argosfs.boot_critical";
const DEFAULT_LAYOUT_ID: &str = "layout-0000";
const SHARD_CHECKSUM_BLOCK_SIZE: usize = 256 * 1024;
const INLINE_DATA_MAX: usize = 512;
const MAX_IN_MEMORY_IO_BYTES: usize = 256 * 1024 * 1024;

mod autopilot;
mod data_plane;
mod helpers;
mod maintenance;
mod namespace;
#[cfg(test)]
mod tests;

pub use autopilot::{AutopilotConfig, ReshapeReport};
use helpers::*;
use namespace::*;

#[derive(Clone, Debug)]
struct DeferredCommitState {
    durable_metadata: Option<Metadata>,
    dirty_transactions: u64,
    dirty_since: Option<Instant>,
    pending_reclaims: Vec<FileBlock>,
    last_error: Option<String>,
}

impl DeferredCommitState {
    fn new(meta: &Metadata) -> Self {
        Self {
            durable_metadata: (meta.backend != BackendKind::Host).then(|| meta.clone()),
            dirty_transactions: 0,
            dirty_since: None,
            pending_reclaims: Vec::new(),
            last_error: None,
        }
    }
}

#[derive(Clone)]
pub struct ArgosFs {
    root: Arc<PathBuf>,
    backend: Arc<dyn StorageBackend>,
    backend_writable: bool,
    raw_superblocks: Arc<Vec<RawSuperblock>>,
    meta: Arc<RwLock<Metadata>>,
    deferred_commit: Arc<Mutex<DeferredCommitState>>,
    dirty_host_shards: Arc<Mutex<BTreeSet<PathBuf>>>,
    inode_locks: Arc<Mutex<BTreeMap<InodeId, Arc<Mutex<()>>>>>,
    cache: Arc<BlockCache>,
}

impl Drop for ArgosFs {
    fn drop(&mut self) {
        if !self.backend_writable || Arc::strong_count(&self.meta) != 1 {
            return;
        }
        if self.meta.read().backend != BackendKind::Host {
            let _ = self.mark_clean_unmount();
        }
    }
}

#[derive(Clone, Debug)]
struct PlacementRequest<'a> {
    key: &'a str,
    count: usize,
    storage_class: StorageTier,
    boot_critical: bool,
    exclude_disks: &'a BTreeSet<String>,
    required_bytes: u64,
}

#[derive(Clone)]
struct ShardIntegrity {
    sha256: String,
    checksum_block_size: usize,
    subblock_sha256: Vec<String>,
}

impl ArgosFs {
    pub fn create(
        root: impl AsRef<Path>,
        mut config: VolumeConfig,
        disk_count: usize,
        force: bool,
    ) -> Result<Self> {
        if config.k == 0 {
            return Err(ArgosError::Invalid("k must be positive".to_string()));
        }
        if disk_count < config.k + config.m {
            return Err(ArgosError::NotEnoughDisks {
                need: config.k + config.m,
                have: disk_count,
            });
        }
        if config.chunk_size == 0 {
            config.chunk_size = VolumeConfig::default().chunk_size;
        }
        validate_commit_policy(&config)?;
        let _ = RsCodec::new(config.k, config.m)?;
        let root = root.as_ref().to_path_buf();
        let system = root.join(".argosfs");
        if force && system.exists() {
            fs::remove_dir_all(&system)?;
        }
        ensure_dir(&root)?;
        if system.exists() {
            return Err(ArgosError::AlreadyExists(root.display().to_string()));
        }
        ensure_private_dir(&system)?;
        ensure_private_dir(&system.join("devices"))?;
        ensure_private_dir(&system.join("snapshots"))?;
        ensure_private_dir(&system.join("cache"))?;
        let uuid = Uuid::new_v4().to_string();
        let created_at = now_f64();
        let mut disks = BTreeMap::new();
        for index in 0..disk_count {
            let id = format!("disk-{index:04}");
            let path = PathBuf::from(format!(".argosfs/devices/{id}"));
            let disk_root = root.join(&path);
            ensure_private_dir(&disk_root)?;
            ensure_private_dir(&disk_root.join("shards"))?;
            atomic_write(
                &disk_root.join("argosfs-disk.json"),
                serde_json::to_vec_pretty(&json!({
                    "format": FORMAT_VERSION,
                    "volume_uuid": uuid,
                    "disk_id": id,
                    "created_at": created_at
                }))?
                .as_slice(),
            )?;
            let probe = probe_disk_path(&disk_root, 1024 * 1024);
            disks.insert(
                id.clone(),
                Disk {
                    id,
                    path,
                    tier: probe.recommended_tier,
                    weight: probe.recommended_weight,
                    status: DiskStatus::Online,
                    capacity_bytes: probe.capacity_bytes,
                    capacity_source: CapacitySource::AutoProbe,
                    used_bytes: 0,
                    health: HealthCounters {
                        temperature_c: 30.0,
                        ..HealthCounters::default()
                    },
                    class: probe.class,
                    backing_device: probe.backing_device.clone(),
                    backing_fs_id: probe.backing_fs_id.clone(),
                    failure_domain: probe
                        .backing_fs_id
                        .clone()
                        .unwrap_or_else(|| format!("disk-{index:04}")),
                    sysfs_block: probe.sysfs_block.clone(),
                    rotational: probe.rotational,
                    numa_node: probe.numa_node,
                    read_latency_ewma_ms: probe.measured_read_latency_ms,
                    write_latency_ewma_ms: probe.measured_write_latency_ms,
                    observed_read_mib_s: probe.measured_read_mib_s,
                    observed_write_mib_s: probe.measured_write_mib_s,
                    io_samples: u64::from(
                        probe.measured_read_mib_s > 0.0 || probe.measured_write_mib_s > 0.0,
                    ),
                    last_probe: probe,
                    created_at,
                },
            );
        }
        let root_inode = Inode {
            id: ROOT_INO,
            kind: NodeKind::Directory,
            mode: libc::S_IFDIR | 0o755,
            uid: current_uid(),
            gid: current_gid(),
            nlink: 2,
            size: 0,
            rdev: 0,
            atime: created_at,
            mtime: created_at,
            ctime: created_at,
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
            storage_class: StorageTier::Warm,
            boot_critical: true,
            workload_score: 0.0,
            last_accessed_at: created_at,
            last_written_at: created_at,
        };
        let mut inodes = BTreeMap::new();
        inodes.insert(ROOT_INO, root_inode);
        let meta = Metadata {
            format: FORMAT_VERSION.to_string(),
            uuid,
            backend: BackendKind::Host,
            raw_pool: RawPoolMetadata::default(),
            created_at,
            updated_at: created_at,
            txid: 0,
            next_inode: ROOT_INO + 1,
            next_stripe: 1,
            config,
            layouts: BTreeMap::new(),
            current_write_layout: String::new(),
            reshape: None,
            encryption: EncryptionConfig::default(),
            integrity: MetadataIntegrity::default(),
            disks,
            inodes,
        };
        let mut meta = meta;
        normalize_metadata_layouts(&mut meta);
        journal::initialize_volume(&root, &mut meta, created_at)?;
        Self::open(root)
    }

    pub fn open(root: impl AsRef<Path>) -> Result<Self> {
        let root = root.as_ref().to_path_buf();
        let recovered = journal::load_or_recover(&root)?;
        let mut meta = recovered.metadata;
        meta.backend = BackendKind::Host;
        normalize_metadata_layouts(&mut meta);
        recompute_disk_usage_from_metadata(&mut meta);
        if meta.format != FORMAT_VERSION {
            return Err(ArgosError::Invalid(format!(
                "unsupported format {}",
                meta.format
            )));
        }
        let _ = RsCodec::new(meta.config.k, meta.config.m)?;
        harden_host_storage_permissions(&root, &meta)?;
        let cache = BlockCache::new(
            root.join(".argosfs/cache/l2"),
            64 * 1024 * 1024,
            meta.config.l2_cache_bytes,
        );
        Ok(Self {
            backend: Arc::new(HostFsBackend::new(&root)),
            backend_writable: true,
            raw_superblocks: Arc::new(Vec::new()),
            root: Arc::new(root),
            deferred_commit: Arc::new(Mutex::new(DeferredCommitState::new(&meta))),
            meta: Arc::new(RwLock::new(meta)),
            dirty_host_shards: Arc::new(Mutex::new(BTreeSet::new())),
            inode_locks: Arc::new(Mutex::new(BTreeMap::new())),
            cache: Arc::new(cache),
        })
    }

    pub fn create_loop(
        images: &[PathBuf],
        config: VolumeConfig,
        image_size: u64,
        pool_name: &str,
        force: bool,
    ) -> Result<Self> {
        prepare_loop_images(images, image_size, force)?;
        Self::create_block_backend(BackendKind::LoopBlock, images, config, pool_name, force)
    }

    pub fn create_raw(
        devices: &[PathBuf],
        config: VolumeConfig,
        pool_name: &str,
        force: bool,
    ) -> Result<Self> {
        Self::create_block_backend(BackendKind::RawBlock, devices, config, pool_name, force)
    }

    pub fn open_loop(images: &[PathBuf], write: bool) -> Result<Self> {
        Self::open_block_backend(BackendKind::LoopBlock, images, write)
    }

    pub fn open_raw(devices: &[PathBuf], write: bool) -> Result<Self> {
        Self::open_block_backend(BackendKind::RawBlock, devices, write)
    }

    fn create_block_backend(
        kind: BackendKind,
        paths: &[PathBuf],
        mut config: VolumeConfig,
        pool_name: &str,
        force: bool,
    ) -> Result<Self> {
        if config.k == 0 {
            return Err(ArgosError::Invalid("k must be positive".to_string()));
        }
        if paths.len() < config.k + config.m {
            return Err(ArgosError::NotEnoughDisks {
                need: config.k + config.m,
                have: paths.len(),
            });
        }
        if config.chunk_size == 0 {
            config.chunk_size = VolumeConfig::default().chunk_size;
        }
        validate_commit_policy(&config)?;
        let backend_file = match kind {
            BackendKind::LoopBlock => FileBlockBackend::open_loop(paths, true)?,
            BackendKind::RawBlock => FileBlockBackend::open_raw(paths, true)?,
            BackendKind::Host => {
                return Err(ArgosError::Unsupported(
                    "create_block_backend requires loop or raw backend".to_string(),
                ))
            }
        };
        let pool_uuid = Uuid::new_v4();
        let created_at = now_f64();
        let mut superblocks = Vec::new();
        let mut disks = BTreeMap::new();
        let mut allocators = BTreeMap::new();
        for (index, info) in backend_file.list_devices()?.into_iter().enumerate() {
            let id = format!("disk-{index:04}");
            let sb = raw_store::superblock_for_device(
                pool_uuid,
                index,
                &id,
                config.k,
                config.m,
                config.chunk_size,
                info.capacity,
                pool_name,
            )?;
            let allocator = allocator::init_allocator(
                sb.data.offset,
                sb.data.length,
                raw_format::RAW_BLOCK_SIZE,
            );
            allocators.insert(id.clone(), allocator);
            disks.insert(
                id.clone(),
                Disk {
                    id,
                    path: info.path,
                    tier: StorageTier::Warm,
                    weight: 1.0,
                    status: DiskStatus::Online,
                    capacity_bytes: info.capacity,
                    capacity_source: CapacitySource::UserOverride,
                    used_bytes: 0,
                    health: HealthCounters {
                        temperature_c: 30.0,
                        ..HealthCounters::default()
                    },
                    class: DiskClass::Unknown,
                    backing_device: None,
                    backing_fs_id: None,
                    failure_domain: format!("raw-device-{index:04}"),
                    sysfs_block: None,
                    rotational: None,
                    numa_node: None,
                    read_latency_ewma_ms: 0.0,
                    write_latency_ewma_ms: 0.0,
                    observed_read_mib_s: 0.0,
                    observed_write_mib_s: 0.0,
                    io_samples: 0,
                    last_probe: DiskProbe::default(),
                    created_at,
                },
            );
            superblocks.push(sb);
        }
        let root_inode = root_inode(created_at);
        let mut inodes = BTreeMap::new();
        inodes.insert(ROOT_INO, root_inode);
        let mut meta = Metadata {
            format: FORMAT_VERSION.to_string(),
            uuid: pool_uuid.to_string(),
            backend: kind,
            raw_pool: RawPoolMetadata {
                pool_name: pool_name.to_string(),
                format_version: RAW_FORMAT_VERSION,
                clean: true,
                dirty_since_txid: 0,
                mount_generation: 1,
                allocators,
            },
            created_at,
            updated_at: created_at,
            txid: 0,
            next_inode: ROOT_INO + 1,
            next_stripe: 1,
            config,
            layouts: BTreeMap::new(),
            current_write_layout: String::new(),
            reshape: None,
            encryption: EncryptionConfig::default(),
            integrity: MetadataIntegrity::default(),
            disks,
            inodes,
        };
        normalize_metadata_layouts(&mut meta);
        journal::prepare_metadata_integrity_for_external_store(&mut meta)?;
        let backend: Arc<dyn StorageBackend> = Arc::new(backend_file);
        raw_store::initialize_pool(backend.clone(), &superblocks, &mut meta, force)?;
        raw_store::write_superblock_clean_state(&*backend, &superblocks, false)?;
        Self::from_block_parts(paths, backend, true, superblocks, meta)
    }

    fn open_block_backend(kind: BackendKind, paths: &[PathBuf], write: bool) -> Result<Self> {
        let opened = raw_store::open_pool(kind, paths, write)?;
        let mut meta = opened.metadata;
        normalize_metadata_layouts(&mut meta);
        recompute_disk_usage_from_metadata(&mut meta);
        Self::from_block_parts(paths, opened.backend, write, opened.superblocks, meta)
    }

    fn from_block_parts(
        paths: &[PathBuf],
        backend: Arc<dyn StorageBackend>,
        backend_writable: bool,
        superblocks: Vec<RawSuperblock>,
        meta: Metadata,
    ) -> Result<Self> {
        if meta.format != FORMAT_VERSION {
            return Err(ArgosError::Invalid(format!(
                "unsupported format {}",
                meta.format
            )));
        }
        let _ = RsCodec::new(meta.config.k, meta.config.m)?;
        let cache_root = block_cache_root(&meta.uuid, paths);
        let cache = BlockCache::new(cache_root, 64 * 1024 * 1024, meta.config.l2_cache_bytes);
        let root = paths
            .first()
            .and_then(|path| path.parent())
            .map(Path::to_path_buf)
            .unwrap_or_else(std::env::temp_dir);
        Ok(Self {
            root: Arc::new(root),
            backend,
            backend_writable,
            raw_superblocks: Arc::new(superblocks),
            deferred_commit: Arc::new(Mutex::new(DeferredCommitState::new(&meta))),
            meta: Arc::new(RwLock::new(meta)),
            dirty_host_shards: Arc::new(Mutex::new(BTreeSet::new())),
            inode_locks: Arc::new(Mutex::new(BTreeMap::new())),
            cache: Arc::new(cache),
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn metadata_snapshot(&self) -> Metadata {
        self.meta.read().clone()
    }

    pub fn transaction_report(&self) -> Result<TransactionReport> {
        let meta = self.meta.read();
        if meta.backend != BackendKind::Host {
            let superblocks = self.active_superblocks_locked(&meta)?;
            if self.open_backend_covers_superblocks(&superblocks) {
                return raw_store::audit(&*self.backend, &superblocks);
            }
            let backend = self.active_block_backend_locked(&meta, false)?;
            return raw_store::audit(&backend, &superblocks);
        }
        journal::scan(&self.root)
    }

    pub fn deferred_commit_interval(&self) -> Option<Duration> {
        let meta = self.meta.read();
        (self.backend_writable
            && meta.backend != BackendKind::Host
            && meta.config.defer_metadata_commit)
            .then(|| Duration::from_millis(meta.config.deferred_commit_interval_ms))
    }

    pub fn sync_deferred_if_dirty(&self) -> Result<bool> {
        if !self.backend_writable || self.deferred_commit.lock().dirty_transactions == 0 {
            return Ok(false);
        }
        self.sync()?;
        Ok(true)
    }

    pub fn sync(&self) -> Result<()> {
        let mut meta = self.meta.write();
        if meta.backend != BackendKind::Host {
            self.ensure_block_backend_writable_locked(&meta)?;
            if bulk_import_enabled() || meta.config.defer_metadata_commit {
                self.commit_deferred_locked(&mut meta, bulk_import_enabled())?;
                return Ok(());
            }
            let superblocks = self.active_superblocks_locked(&meta)?;
            if self.open_backend_covers_superblocks(&superblocks) {
                raw_store::write_metadata_copies(&*self.backend, &superblocks, &meta)?;
                self.backend.flush_all()?;
            } else {
                let backend = self.active_block_backend_locked(&meta, true)?;
                raw_store::write_metadata_copies(&backend, &superblocks, &meta)?;
                backend.flush_all()?;
            }
            return Ok(());
        }

        self.sync_dirty_host_shards()?;

        for path in [
            self.root.join(".argosfs/journal.jsonl"),
            self.root.join(".argosfs/meta.primary.json"),
            self.root.join(".argosfs/meta.secondary.json"),
            self.root.join(".argosfs/meta.json"),
        ] {
            if let Ok(file) = fs::File::open(&path) {
                file.sync_all()?;
            }
        }
        sync_directory(&self.root.join(".argosfs"));
        for disk in meta.disks.values() {
            let disk_root = relative_or_absolute(&self.root, &disk.path);
            sync_directory(&disk_root);
            sync_directory(&disk_root.join("shards"));
        }
        Ok(())
    }

    pub fn mark_clean_unmount(&self) -> Result<()> {
        self.sync()?;
        let meta = self.meta.read();
        if meta.backend == BackendKind::Host {
            return Ok(());
        }
        self.ensure_block_backend_writable_locked(&meta)?;
        let superblocks = self.active_superblocks_locked(&meta)?;
        let mark_clean = |backend: &dyn StorageBackend| -> Result<()> {
            if meta.config.defer_metadata_commit {
                raw_store::write_metadata_copies(backend, &superblocks, &meta)?;
                backend.flush_all()?;
            }
            raw_store::write_superblock_clean_state(backend, &superblocks, true)?;
            backend.flush_all()
        };
        if self.open_backend_covers_superblocks(&superblocks) {
            mark_clean(&*self.backend)
        } else {
            let backend = self.active_block_backend_locked(&meta, true)?;
            mark_clean(&backend)
        }
    }

    fn sync_dirty_host_shards(&self) -> Result<()> {
        let shard_paths = {
            let mut dirty = self.dirty_host_shards.lock();
            std::mem::take(&mut *dirty)
        };
        let mut failed = BTreeSet::new();
        let mut first_error = None;
        for path in shard_paths {
            match fs::File::open(&path).and_then(|file| file.sync_all()) {
                Ok(()) => {}
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                Err(err) => {
                    failed.insert(path);
                    if first_error.is_none() {
                        first_error = Some(err);
                    }
                }
            }
        }
        if !failed.is_empty() {
            self.dirty_host_shards.lock().extend(failed);
        }
        if let Some(err) = first_error {
            return Err(ArgosError::Io(err));
        }
        Ok(())
    }

    fn mark_host_shard_dirty(&self, path: PathBuf) {
        self.dirty_host_shards.lock().insert(path);
    }

    fn inode_lock(&self, ino: InodeId) -> Arc<Mutex<()>> {
        self.inode_locks
            .lock()
            .entry(ino)
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone()
    }

    pub fn audit_transactions(root: impl AsRef<Path>) -> Result<TransactionReport> {
        journal::load_or_recover(root.as_ref()).map(|recovered| recovered.report)
    }

    pub fn snapshot(&self, name: &str) -> Result<PathBuf> {
        let meta = self.meta.read();
        let trimmed = name.trim();
        if trimmed.is_empty() {
            return Err(ArgosError::Invalid(
                "snapshot name must not be empty".to_string(),
            ));
        }
        let safe: String = trimmed
            .chars()
            .map(|ch| {
                if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-') {
                    ch
                } else {
                    '_'
                }
            })
            .collect();
        if safe == "." || safe == ".." {
            return Err(ArgosError::Invalid(format!(
                "invalid snapshot name: {trimmed:?}"
            )));
        }
        let path = self
            .root
            .join(".argosfs/snapshots")
            .join(format!("{safe}.json"));
        if path.exists() {
            return Err(ArgosError::AlreadyExists(format!(
                "snapshot {}",
                path.display()
            )));
        }
        atomic_write(&path, serde_json::to_vec_pretty(&*meta)?.as_slice())?;
        self.journal_locked(&meta, "snapshot", json!({"name": trimmed, "path": path}))?;
        Ok(path)
    }

    pub fn iter_paths(&self) -> Vec<(String, InodeId)> {
        self.iter_path_bytes()
            .into_iter()
            .map(|(path, ino)| (String::from_utf8_lossy(&path).to_string(), ino))
            .collect()
    }

    pub fn iter_path_bytes(&self) -> Vec<(Vec<u8>, InodeId)> {
        let meta = self.meta.read();
        let mut out = vec![(b"/".to_vec(), ROOT_INO)];

        fn walk(meta: &Metadata, out: &mut Vec<(Vec<u8>, InodeId)>, prefix: &[u8], ino: InodeId) {
            if let Some(inode) = meta.inodes.get(&ino) {
                if inode.kind != NodeKind::Directory {
                    return;
                }
                for (name, child) in inode.entries.iter() {
                    let name_bytes = decode_entry_name_bytes(name);
                    let mut path = Vec::new();
                    if prefix == b"/" {
                        path.push(b'/');
                        path.extend_from_slice(&name_bytes);
                    } else {
                        path.extend_from_slice(prefix);
                        path.push(b'/');
                        path.extend_from_slice(&name_bytes);
                    }
                    out.push((path.clone(), *child));
                    walk(meta, out, &path, *child);
                }
            }
        }

        walk(&meta, &mut out, b"/", ROOT_INO);
        out
    }

    fn file_window(&self, cursor: Option<InodeId>, max_files: usize) -> Vec<(InodeId, Inode)> {
        let meta = self.meta.read();
        let files = meta
            .inodes
            .iter()
            .filter_map(|(ino, inode)| {
                (inode.kind == NodeKind::File).then_some((*ino, inode.clone()))
            })
            .collect::<Vec<_>>();
        if files.is_empty() || max_files == 0 {
            return Vec::new();
        }
        if max_files == usize::MAX {
            return files;
        }
        let start = cursor
            .and_then(|cursor| files.iter().position(|(ino, _)| *ino > cursor))
            .unwrap_or(0);
        files
            .iter()
            .cycle()
            .skip(start)
            .take(max_files.min(files.len()))
            .cloned()
            .collect()
    }

    fn mkdir_locked(
        &self,
        meta: &mut Metadata,
        parent: InodeId,
        name: &str,
        mode: u32,
        uid: u32,
        gid: u32,
    ) -> Result<InodeId> {
        self.ensure_block_backend_writable_locked(meta)?;
        validate_entry_name(name)?;
        if self
            .dir_inode_locked(meta, parent)?
            .entries
            .contains_key(name)
        {
            return Err(ArgosError::AlreadyExists(name.to_string()));
        }
        let now = now_f64();
        let ino = self.alloc_inode_locked(meta);
        let inherited_default_acl = meta
            .inodes
            .get(&parent)
            .and_then(acl::inherited_directory_acl);
        let inherited_access_acl = meta
            .inodes
            .get(&parent)
            .and_then(|parent| acl::inherited_access_acl(parent, mode));
        let inode = Inode {
            id: ino,
            kind: NodeKind::Directory,
            mode: libc::S_IFDIR | (mode & 0o7777),
            uid,
            gid,
            nlink: 2,
            size: 0,
            rdev: 0,
            atime: now,
            mtime: now,
            ctime: now,
            entries: BTreeMap::new(),
            target: None,
            inline_data: None,
            inline_sha256: String::new(),
            blocks: Vec::new(),
            xattrs: BTreeMap::new(),
            posix_acl_access: inherited_access_acl,
            posix_acl_default: inherited_default_acl,
            nfs4_acl: None,
            access_count: 0,
            write_count: 0,
            read_bytes: 0,
            write_bytes: 0,
            storage_class: StorageTier::Warm,
            boot_critical: boot_critical_name(name),
            workload_score: 0.0,
            last_accessed_at: now,
            last_written_at: now,
        };
        meta.inodes.insert(ino, inode);
        self.dir_inode_mut_locked(meta, parent)?
            .entries
            .insert(name.to_string(), ino);
        if let Some(parent_inode) = meta.inodes.get_mut(&parent) {
            parent_inode.nlink = parent_inode.nlink.saturating_add(1);
        }
        self.touch_inode_locked(meta, parent, true, true);
        self.commit_locked(
            meta,
            "mkdir",
            json!({"parent": parent, "name": name, "inode": ino}),
        )?;
        Ok(ino)
    }

    #[allow(clippy::too_many_arguments)]
    fn mknod_locked(
        &self,
        meta: &mut Metadata,
        parent: InodeId,
        name: &str,
        mode: u32,
        rdev: u64,
        uid: u32,
        gid: u32,
    ) -> Result<InodeId> {
        self.ensure_block_backend_writable_locked(meta)?;
        validate_entry_name(name)?;
        if self
            .dir_inode_locked(meta, parent)?
            .entries
            .contains_key(name)
        {
            return Err(ArgosError::AlreadyExists(name.to_string()));
        }
        let rollback = commit_previous_snapshot(meta);
        let file_type = mode & libc::S_IFMT;
        let kind = if file_type == libc::S_IFREG || file_type == 0 {
            if rdev != 0 {
                return Err(ArgosError::Invalid(
                    "regular files must not carry an rdev".to_string(),
                ));
            }
            NodeKind::File
        } else if file_type == libc::S_IFCHR
            || file_type == libc::S_IFBLK
            || file_type == libc::S_IFIFO
            || file_type == libc::S_IFSOCK
        {
            if matches!(file_type, value if value == libc::S_IFIFO || value == libc::S_IFSOCK)
                && rdev != 0
            {
                return Err(ArgosError::Invalid(
                    "fifo and socket nodes must not carry an rdev".to_string(),
                ));
            }
            NodeKind::Special
        } else {
            return Err(ArgosError::Unsupported(format!(
                "unsupported mknod mode {mode:o}"
            )));
        };
        let now = now_f64();
        let ino = self.alloc_inode_locked(meta);
        let inherited_acl = meta
            .inodes
            .get(&parent)
            .and_then(|parent| acl::inherited_access_acl(parent, mode));
        let normalized_mode = if kind == NodeKind::File && file_type == 0 {
            libc::S_IFREG | (mode & 0o7777)
        } else {
            file_type | (mode & 0o7777)
        };
        let inode = Inode {
            id: ino,
            kind,
            mode: normalized_mode,
            uid,
            gid,
            nlink: 1,
            size: 0,
            rdev,
            atime: now,
            mtime: now,
            ctime: now,
            entries: BTreeMap::new(),
            target: None,
            inline_data: None,
            inline_sha256: String::new(),
            blocks: Vec::new(),
            xattrs: BTreeMap::new(),
            posix_acl_access: inherited_acl,
            posix_acl_default: None,
            nfs4_acl: None,
            access_count: 0,
            write_count: 0,
            read_bytes: 0,
            write_bytes: 0,
            storage_class: StorageTier::Warm,
            boot_critical: boot_critical_name(name),
            workload_score: 0.0,
            last_accessed_at: now,
            last_written_at: now,
        };
        meta.inodes.insert(ino, inode);
        self.dir_inode_mut_locked(meta, parent)?
            .entries
            .insert(name.to_string(), ino);
        self.touch_inode_locked(meta, parent, true, true);
        if let Err(err) = self.commit_locked_with_previous(
            meta,
            rollback.as_ref(),
            "mknod",
            json!({"parent": parent, "name": name, "inode": ino, "mode": mode, "rdev": rdev}),
        ) {
            if !Self::transaction_error_is_committed(&err)
                && !matches!(err, ArgosError::Conflict(_))
            {
                if let Some(rollback) = rollback {
                    *meta = rollback;
                }
            }
            return Err(err);
        }
        Ok(ino)
    }

    fn unlink_locked(
        &self,
        meta: &mut Metadata,
        parent: InodeId,
        name: &str,
        dir: bool,
        uid: Option<u32>,
        preserve_unlinked: bool,
    ) -> Result<()> {
        validate_entry_name(name)?;
        let child = *self
            .dir_inode_locked(meta, parent)?
            .entries
            .get(name)
            .ok_or_else(|| ArgosError::NotFound(name.to_string()))?;
        let child_inode = meta
            .inodes
            .get(&child)
            .ok_or_else(|| ArgosError::NotFound(format!("inode {child}")))?
            .clone();
        self.check_sticky_locked(meta, parent, child, uid)?;
        self.ensure_block_backend_writable_locked(meta)?;
        if dir {
            if child_inode.kind != NodeKind::Directory {
                return Err(ArgosError::NotDirectory(name.to_string()));
            }
            if !child_inode.entries.is_empty() {
                return Err(ArgosError::DirectoryNotEmpty(name.to_string()));
            }
        } else if child_inode.kind == NodeKind::Directory {
            return Err(ArgosError::IsDirectory(name.to_string()));
        }
        self.dir_inode_mut_locked(meta, parent)?
            .entries
            .remove(name);
        self.touch_inode_locked(meta, parent, true, true);
        let mut blocks_to_delete = Vec::new();
        if child_inode.kind == NodeKind::Directory {
            if let Some(parent_inode) = meta.inodes.get_mut(&parent) {
                parent_inode.nlink = parent_inode.nlink.saturating_sub(1).max(2);
            }
            meta.inodes.remove(&child);
        } else if let Some(live) = meta.inodes.get_mut(&child) {
            live.nlink = live.nlink.saturating_sub(1);
            live.ctime = now_f64();
            if live.nlink == 0 && !preserve_unlinked {
                blocks_to_delete = live.blocks.clone();
                meta.inodes.remove(&child);
            }
        }
        self.stage_block_reclamation_locked(meta, &blocks_to_delete);
        self.commit_locked(
            meta,
            if dir { "rmdir" } else { "unlink" },
            json!({"parent": parent, "name": name, "inode": child}),
        )?;
        self.finish_block_reclamation_locked(meta, &blocks_to_delete);
        Ok(())
    }

    pub fn reap_unlinked_inode(&self, ino: InodeId) -> Result<()> {
        let mut meta = self.meta.write();
        self.ensure_block_backend_writable_locked(&meta)?;
        let Some(inode) = meta.inodes.get(&ino).cloned() else {
            return Ok(());
        };
        if inode.nlink != 0 {
            return Ok(());
        }
        let blocks = inode.blocks.clone();
        meta.inodes.remove(&ino);
        self.stage_block_reclamation_locked(&mut meta, &blocks);
        self.commit_locked(&mut meta, "orphan-reap", json!({"inode": ino}))?;
        self.finish_block_reclamation_locked(&mut meta, &blocks);
        Ok(())
    }

    fn rename_locked(
        &self,
        meta: &mut Metadata,
        old_parent: InodeId,
        old_name: &str,
        new_parent: InodeId,
        new_name: &str,
        policy: RenamePolicy,
    ) -> Result<()> {
        validate_entry_name(old_name)?;
        validate_entry_name(new_name)?;
        if policy.no_replace && policy.exchange {
            return Err(ArgosError::Invalid(
                "RENAME_NOREPLACE and RENAME_EXCHANGE cannot be combined".to_string(),
            ));
        }
        if old_parent == new_parent && old_name == new_name && !policy.exchange {
            return Ok(());
        }
        let child = *self
            .dir_inode_locked(meta, old_parent)?
            .entries
            .get(old_name)
            .ok_or_else(|| ArgosError::NotFound(old_name.to_string()))?;
        let child_inode = meta
            .inodes
            .get(&child)
            .ok_or_else(|| ArgosError::NotFound(format!("inode {child}")))?
            .clone();
        let child_is_dir = child_inode.kind == NodeKind::Directory;
        self.dir_inode_locked(meta, new_parent)?;
        self.check_sticky_locked(meta, old_parent, child, policy.uid)?;
        if child_is_dir && Self::directory_contains_inode(meta, child, new_parent) {
            return Err(ArgosError::Invalid(
                "cannot move a directory into itself".to_string(),
            ));
        }
        let existing = self
            .dir_inode_locked(meta, new_parent)?
            .entries
            .get(new_name)
            .copied();
        if policy.no_replace && existing.is_some() {
            return Err(ArgosError::AlreadyExists(new_name.to_string()));
        }
        if existing == Some(child) && !policy.exchange {
            return Ok(());
        }
        self.ensure_block_backend_writable_locked(meta)?;
        if policy.exchange {
            let existing = existing.ok_or_else(|| ArgosError::NotFound(new_name.to_string()))?;
            self.check_sticky_locked(meta, new_parent, existing, policy.uid)?;
            let existing_inode = meta
                .inodes
                .get(&existing)
                .ok_or_else(|| ArgosError::NotFound(format!("inode {existing}")))?
                .clone();
            if existing_inode.kind == NodeKind::Directory
                && Self::directory_contains_inode(meta, existing, old_parent)
            {
                return Err(ArgosError::Invalid(
                    "cannot exchange a directory into itself".to_string(),
                ));
            }
            self.dir_inode_mut_locked(meta, old_parent)?
                .entries
                .insert(old_name.to_string(), existing);
            self.dir_inode_mut_locked(meta, new_parent)?
                .entries
                .insert(new_name.to_string(), child);
            if old_parent != new_parent {
                if child_is_dir {
                    if let Some(parent_inode) = meta.inodes.get_mut(&old_parent) {
                        parent_inode.nlink = parent_inode.nlink.saturating_sub(1).max(2);
                    }
                    if let Some(parent_inode) = meta.inodes.get_mut(&new_parent) {
                        parent_inode.nlink = parent_inode.nlink.saturating_add(1);
                    }
                }
                if existing_inode.kind == NodeKind::Directory {
                    if let Some(parent_inode) = meta.inodes.get_mut(&new_parent) {
                        parent_inode.nlink = parent_inode.nlink.saturating_sub(1).max(2);
                    }
                    if let Some(parent_inode) = meta.inodes.get_mut(&old_parent) {
                        parent_inode.nlink = parent_inode.nlink.saturating_add(1);
                    }
                }
            }
            self.touch_inode_locked(meta, old_parent, true, true);
            self.touch_inode_locked(meta, new_parent, true, true);
            self.touch_inode_locked(meta, child, false, true);
            self.touch_inode_locked(meta, existing, false, true);
            self.commit_locked(
                meta,
                "rename-exchange",
                json!({"old_parent": old_parent, "old_name": old_name, "new_parent": new_parent, "new_name": new_name, "inode": child, "exchanged_inode": existing}),
            )?;
            return Ok(());
        }
        let existing_inode = if let Some(existing) = existing {
            self.check_sticky_locked(meta, new_parent, existing, policy.uid)?;
            let inode = meta
                .inodes
                .get(&existing)
                .ok_or_else(|| ArgosError::NotFound(format!("inode {existing}")))?
                .clone();
            match (&child_inode.kind, &inode.kind) {
                (NodeKind::Directory, NodeKind::Directory) if !inode.entries.is_empty() => {
                    return Err(ArgosError::DirectoryNotEmpty(new_name.to_string()));
                }
                (NodeKind::Directory, NodeKind::Directory) => {}
                (NodeKind::Directory, _) => {
                    return Err(ArgosError::NotDirectory(new_name.to_string()));
                }
                (_, NodeKind::Directory) => {
                    return Err(ArgosError::IsDirectory(new_name.to_string()));
                }
                _ => {}
            }
            Some((existing, inode))
        } else {
            None
        };
        let mut blocks_to_delete = Vec::new();
        if let Some((existing, existing_inode)) = existing_inode {
            self.dir_inode_mut_locked(meta, new_parent)?
                .entries
                .remove(new_name);
            if existing_inode.kind == NodeKind::Directory {
                meta.inodes.remove(&existing);
                if let Some(parent_inode) = meta.inodes.get_mut(&new_parent) {
                    parent_inode.nlink = parent_inode.nlink.saturating_sub(1).max(2);
                }
            } else if let Some(live) = meta.inodes.get_mut(&existing) {
                live.nlink = live.nlink.saturating_sub(1);
                live.ctime = now_f64();
                if live.nlink == 0 && !policy.preserve_replaced_inode {
                    blocks_to_delete = live.blocks.clone();
                    meta.inodes.remove(&existing);
                }
            }
        }
        self.stage_block_reclamation_locked(meta, &blocks_to_delete);
        self.dir_inode_mut_locked(meta, old_parent)?
            .entries
            .remove(old_name);
        self.dir_inode_mut_locked(meta, new_parent)?
            .entries
            .insert(new_name.to_string(), child);
        if child_is_dir && old_parent != new_parent {
            if let Some(parent_inode) = meta.inodes.get_mut(&old_parent) {
                parent_inode.nlink = parent_inode.nlink.saturating_sub(1).max(2);
            }
            if let Some(parent_inode) = meta.inodes.get_mut(&new_parent) {
                parent_inode.nlink = parent_inode.nlink.saturating_add(1);
            }
        }
        self.touch_inode_locked(meta, old_parent, true, true);
        self.touch_inode_locked(meta, new_parent, true, true);
        self.touch_inode_locked(meta, child, false, true);
        self.commit_locked(
            meta,
            "rename",
            json!({"old_parent": old_parent, "old_name": old_name, "new_parent": new_parent, "new_name": new_name, "inode": child}),
        )?;
        self.finish_block_reclamation_locked(meta, &blocks_to_delete);
        Ok(())
    }

    fn resolve_path_locked(
        &self,
        meta: &Metadata,
        path: &str,
        follow_final: bool,
        limit: u32,
    ) -> Result<InodeId> {
        if limit == 0 {
            return Err(ArgosError::Invalid("too many symbolic links".to_string()));
        }
        let clean = clean_path(path);
        if clean == "/" {
            return Ok(ROOT_INO);
        }
        let mut current = ROOT_INO;
        let parts = split_path(&clean);
        let mut prefix: Vec<String> = Vec::new();
        for (idx, part) in parts.iter().enumerate() {
            let inode = self.dir_inode_locked(meta, current)?;
            let part_key = entry_name_from_str(part)?;
            let next = *inode
                .entries
                .get(part_key.as_str())
                .ok_or_else(|| ArgosError::NotFound(clean.clone()))?;
            let child = meta
                .inodes
                .get(&next)
                .ok_or_else(|| ArgosError::NotFound(format!("inode {next}")))?;
            let final_component = idx + 1 == parts.len();
            if child.kind == NodeKind::Symlink && (follow_final || !final_component) {
                let target_bytes =
                    decode_symlink_target_bytes(child.target.as_deref().unwrap_or_default());
                let target = std::str::from_utf8(&target_bytes).map_err(|_| {
                    ArgosError::Invalid(
                        "non-UTF-8 symlink targets cannot be followed by string path APIs"
                            .to_string(),
                    )
                })?;
                let rest = parts[idx + 1..].join("/");
                let new_path = if target.starts_with('/') {
                    if rest.is_empty() {
                        target.to_string()
                    } else {
                        format!("{target}/{rest}")
                    }
                } else {
                    let base = if prefix.is_empty() {
                        "/".to_string()
                    } else {
                        format!("/{}", prefix.join("/"))
                    };
                    if rest.is_empty() {
                        clean_path(&format!("{base}/{target}"))
                    } else {
                        clean_path(&format!("{base}/{target}/{rest}"))
                    }
                };
                return self.resolve_path_locked(meta, &new_path, true, limit - 1);
            }
            current = next;
            prefix.push(part.clone());
        }
        Ok(current)
    }

    fn dir_inode_locked<'a>(&self, meta: &'a Metadata, ino: InodeId) -> Result<&'a Inode> {
        let inode = meta
            .inodes
            .get(&ino)
            .ok_or_else(|| ArgosError::NotFound(format!("inode {ino}")))?;
        if inode.kind != NodeKind::Directory {
            return Err(ArgosError::NotDirectory(format!("inode {ino}")));
        }
        Ok(inode)
    }

    fn dir_inode_mut_locked<'a>(
        &self,
        meta: &'a mut Metadata,
        ino: InodeId,
    ) -> Result<&'a mut Inode> {
        let inode = meta
            .inodes
            .get_mut(&ino)
            .ok_or_else(|| ArgosError::NotFound(format!("inode {ino}")))?;
        if inode.kind != NodeKind::Directory {
            return Err(ArgosError::NotDirectory(format!("inode {ino}")));
        }
        Ok(inode)
    }

    fn parent_inode_locked(&self, meta: &Metadata, ino: InodeId) -> Result<InodeId> {
        if ino == ROOT_INO {
            return Ok(ROOT_INO);
        }
        meta.inodes
            .iter()
            .find_map(|(parent, inode)| {
                (inode.kind == NodeKind::Directory
                    && inode.entries.values().any(|child| *child == ino))
                .then_some(*parent)
            })
            .ok_or_else(|| ArgosError::NotFound(format!("parent of inode {ino}")))
    }

    fn directory_contains_inode(meta: &Metadata, ancestor: InodeId, needle: InodeId) -> bool {
        if ancestor == needle {
            return true;
        }
        let Some(inode) = meta.inodes.get(&ancestor) else {
            return false;
        };
        if inode.kind != NodeKind::Directory {
            return false;
        }
        inode
            .entries
            .values()
            .any(|child| Self::directory_contains_inode(meta, *child, needle))
    }

    fn check_sticky_locked(
        &self,
        meta: &Metadata,
        parent: InodeId,
        child: InodeId,
        uid: Option<u32>,
    ) -> Result<()> {
        let Some(uid) = uid else {
            return Ok(());
        };
        if uid == 0 {
            return Ok(());
        }
        let parent_inode = self.dir_inode_locked(meta, parent)?;
        if parent_inode.mode & libc::S_ISVTX == 0 {
            return Ok(());
        }
        let child_inode = meta
            .inodes
            .get(&child)
            .ok_or_else(|| ArgosError::NotFound(format!("inode {child}")))?;
        if uid == parent_inode.uid || uid == child_inode.uid {
            Ok(())
        } else {
            Err(ArgosError::PermissionDenied(format!(
                "sticky directory denies uid {uid} removing inode {child}"
            )))
        }
    }

    fn touch_inode_locked(&self, meta: &mut Metadata, ino: InodeId, mtime: bool, ctime: bool) {
        if let Some(inode) = meta.inodes.get_mut(&ino) {
            let now = now_f64();
            if mtime {
                inode.mtime = now;
            }
            if ctime {
                inode.ctime = now;
            }
        }
    }

    fn alloc_inode_locked(&self, meta: &mut Metadata) -> InodeId {
        let ino = meta.next_inode;
        meta.next_inode += 1;
        ino
    }

    fn shard_path_locked(&self, meta: &Metadata, disk_id: &str, relpath: &Path) -> PathBuf {
        let disk = meta.disks.get(disk_id).expect("disk metadata exists");
        relative_or_absolute(&self.root, &disk.path).join(relpath)
    }

    fn shard_path_if_disk_exists_locked(
        &self,
        meta: &Metadata,
        disk_id: &str,
        relpath: &Path,
    ) -> Option<PathBuf> {
        let disk = meta.disks.get(disk_id)?;
        Some(relative_or_absolute(&self.root, &disk.path).join(relpath))
    }

    fn encryption_key_locked(&self, meta: &Metadata) -> Result<[u8; 32]> {
        let passphrase = crypto::passphrase_from_env()?.ok_or_else(|| {
            ArgosError::PermissionDenied(
                "set ARGOSFS_KEY or ARGOSFS_KEY_FILE to access encrypted ArgosFS data".to_string(),
            )
        })?;
        crypto::derive_key_for_config(&meta.encryption, &passphrase, meta.uuid.as_bytes())
    }

    fn ensure_block_backend_writable_locked(&self, meta: &Metadata) -> Result<()> {
        if meta.backend != BackendKind::Host && !self.backend_writable {
            return Err(ArgosError::ReadonlyRequired(
                "block pool was opened read-only".to_string(),
            ));
        }
        Ok(())
    }

    fn transaction_error_is_committed(err: &ArgosError) -> bool {
        matches!(
            err,
            ArgosError::InjectedCrash(point)
                if matches!(
                    point.as_str(),
                    "after-journal"
                        | "after-primary-metadata"
                        | "after-secondary-metadata"
                        | "after-compatible-metadata"
                        | "after-journal-commit-before-metadata-commit"
                        | "after-metadata-commit-before-superblock-update"
                )
        )
    }

    fn note_deferred_transaction_locked(&self, meta: &mut Metadata) -> Result<()> {
        let should_commit = {
            let mut state = self.deferred_commit.lock();
            if state.dirty_transactions == 0 {
                state.dirty_since = Some(Instant::now());
            }
            state.dirty_transactions = state.dirty_transactions.saturating_add(1);
            let age_due = state.dirty_since.is_some_and(|since| {
                since.elapsed() >= Duration::from_millis(meta.config.deferred_commit_interval_ms)
            });
            !bulk_import_enabled()
                && (state.dirty_transactions >= meta.config.deferred_commit_max_transactions
                    || age_due)
        };
        if should_commit {
            self.commit_deferred_locked(meta, false)?;
        }
        Ok(())
    }

    fn commit_deferred_locked(&self, meta: &mut Metadata, checkpoint: bool) -> Result<bool> {
        self.ensure_block_backend_writable_locked(meta)?;
        let mut state = self.deferred_commit.lock();
        if state.dirty_transactions == 0 && state.pending_reclaims.is_empty() {
            return Ok(false);
        }

        let previous = state
            .durable_metadata
            .clone()
            .unwrap_or_else(|| meta.clone());
        let before_commit = meta.clone();
        let dirty_transactions = state.dirty_transactions;
        let previous_meta_hash = if previous.integrity.meta_hash.is_empty() {
            journal::canonical_metadata_hash(&previous)?
        } else {
            previous.integrity.meta_hash.clone()
        };

        let result = (|| -> Result<()> {
            for block in &state.pending_reclaims {
                self.account_blocks_locked(meta, std::slice::from_ref(block), false);
                self.delete_blocks_locked(meta, std::slice::from_ref(block));
            }
            journal::prepare_metadata_integrity_with_previous(meta, previous_meta_hash.clone())?;
            let superblocks = self.active_superblocks_locked(meta)?;
            let commit = |backend: &dyn StorageBackend| -> Result<()> {
                if meta.config.defer_data_flush || bulk_import_enabled() {
                    backend.flush_all()?;
                    journal::inject_crash(FaultPoint::AfterDataFlushBeforeJournalCommit.as_str())?;
                }
                if checkpoint {
                    raw_store::write_metadata_copies(backend, &superblocks, meta)?;
                } else {
                    raw_store::append_transaction_with_previous(
                        backend,
                        &superblocks,
                        meta,
                        Some(&previous),
                        "group-commit",
                        json!({
                            "transactions": dirty_transactions,
                            "previous_txid": previous.txid,
                            "txid": meta.txid,
                        }),
                    )?;
                }
                backend.flush_all()
            };
            if self.open_backend_covers_superblocks(&superblocks) {
                commit(&*self.backend)
            } else {
                let backend = self.active_block_backend_locked(meta, true)?;
                commit(&backend)
            }
        })();

        match result {
            Ok(()) => {
                state.durable_metadata = Some(meta.clone());
                state.dirty_transactions = 0;
                state.dirty_since = None;
                state.pending_reclaims.clear();
                state.last_error = None;
                Ok(true)
            }
            Err(err)
                if !meta.config.defer_journal_flush
                    && Self::transaction_error_is_committed(&err) =>
            {
                state.durable_metadata = Some(meta.clone());
                state.dirty_transactions = 0;
                state.dirty_since = None;
                state.pending_reclaims.clear();
                state.last_error = Some(err.to_string());
                Err(err)
            }
            Err(err) => {
                *meta = before_commit;
                state.last_error = Some(err.to_string());
                Err(err)
            }
        }
    }

    fn commit_locked(
        &self,
        meta: &mut Metadata,
        action: &str,
        details: serde_json::Value,
    ) -> Result<()> {
        self.commit_locked_with_previous(meta, None, action, details)
    }

    fn commit_locked_with_previous(
        &self,
        meta: &mut Metadata,
        previous_metadata: Option<&Metadata>,
        action: &str,
        details: serde_json::Value,
    ) -> Result<()> {
        self.ensure_block_backend_writable_locked(meta)?;
        if meta.backend != BackendKind::Host
            && (bulk_import_enabled() || meta.config.defer_metadata_commit)
        {
            meta.txid += 1;
            meta.updated_at = now_f64();
            self.note_deferred_transaction_locked(meta)?;
            return Ok(());
        }
        let previous_meta_hash = if meta.integrity.meta_hash.is_empty() {
            journal::canonical_metadata_hash(meta)?
        } else {
            meta.integrity.meta_hash.clone()
        };
        let previous_txid = meta.txid;
        meta.txid += 1;
        meta.updated_at = now_f64();
        if meta.backend != BackendKind::Host {
            journal::prepare_metadata_integrity_with_previous(meta, previous_meta_hash.clone())?;
            if bulk_import_enabled() {
                return Ok(());
            }
            let superblocks = self.active_superblocks_locked(meta)?;
            let replay_previous = match previous_metadata {
                Some(previous)
                    if journal::canonical_metadata_hash(previous)? == previous_meta_hash =>
                {
                    Some(previous)
                }
                _ => None,
            };
            let details = json!({"txid": meta.txid, "previous_meta_hash": previous_meta_hash, "details": details});
            let result = if self.open_backend_covers_superblocks(&superblocks) {
                match replay_previous {
                    Some(previous) => raw_store::append_transaction_with_previous(
                        &*self.backend,
                        &superblocks,
                        meta,
                        Some(previous),
                        action,
                        details,
                    ),
                    None => raw_store::append_transaction(
                        &*self.backend,
                        &superblocks,
                        meta,
                        action,
                        details,
                    ),
                }
            } else {
                let backend = self.active_block_backend_locked(meta, true)?;
                match replay_previous {
                    Some(previous) => raw_store::append_transaction_with_previous(
                        &backend,
                        &superblocks,
                        meta,
                        Some(previous),
                        action,
                        details,
                    ),
                    None => {
                        raw_store::append_transaction(&backend, &superblocks, meta, action, details)
                    }
                }
            };
            if let Err(commit_err) = result {
                let should_restore = !Self::transaction_error_is_committed(&commit_err)
                    && (previous_metadata.is_none()
                        || matches!(commit_err, ArgosError::Conflict(_)));
                if should_restore {
                    if let Err(recovery_err) = self.restore_raw_metadata_locked(meta, &superblocks)
                    {
                        return Err(ArgosError::CorruptedMetadata(format!(
                            "raw transaction failed ({commit_err}) and metadata rollback failed ({recovery_err})"
                        )));
                    }
                }
                return Err(commit_err);
            }
            return Ok(());
        }
        let result = journal::append_transaction_checked(
            &self.root,
            meta,
            Some(previous_txid),
            action,
            json!({"txid": meta.txid, "previous_meta_hash": previous_meta_hash, "details": details}),
        );

        if let Err(commit_err) = &result {
            if !Self::transaction_error_is_committed(commit_err) {
                let recovered = journal::load_or_recover(&self.root).map_err(|recovery_err| {
                    ArgosError::CorruptedMetadata(format!(
                        "host transaction failed ({commit_err}) and metadata rollback failed ({recovery_err})"
                    ))
                })?;
                *meta = recovered.metadata;
                recompute_disk_usage_from_metadata(meta);
            }
        }

        result
    }

    fn restore_raw_metadata_locked(
        &self,
        meta: &mut Metadata,
        superblocks: &[RawSuperblock],
    ) -> Result<()> {
        let recovered = if self.open_backend_covers_superblocks(superblocks) {
            raw_store::recover_metadata(&*self.backend, superblocks)?
        } else {
            let backend = self.active_block_backend_locked(meta, false)?;
            raw_store::recover_metadata(&backend, superblocks)?
        };
        *meta = recovered;
        recompute_disk_usage_from_metadata(meta);
        Ok(())
    }

    fn journal_locked(
        &self,
        meta: &Metadata,
        action: &str,
        details: serde_json::Value,
    ) -> Result<()> {
        self.ensure_block_backend_writable_locked(meta)?;
        if meta.backend != BackendKind::Host {
            let superblocks = self.active_superblocks_locked(meta)?;
            if self.open_backend_covers_superblocks(&superblocks) {
                return raw_store::append_transaction(
                    &*self.backend,
                    &superblocks,
                    meta,
                    action,
                    details,
                );
            }
            let backend = self.active_block_backend_locked(meta, true)?;
            return raw_store::append_transaction(&backend, &superblocks, meta, action, details);
        }
        journal::append_event(&self.root, meta, action, details)
    }

    fn open_backend_covers_superblocks(&self, superblocks: &[RawSuperblock]) -> bool {
        let Ok(devices) = self.backend.list_devices() else {
            return false;
        };
        let opened = devices
            .into_iter()
            .map(|device| device.device_id)
            .collect::<BTreeSet<_>>();
        superblocks.iter().all(|sb| opened.contains(&sb.disk_id))
    }

    fn active_superblocks_locked(&self, meta: &Metadata) -> Result<Vec<RawSuperblock>> {
        if meta.backend == BackendKind::Host {
            return Ok(Vec::new());
        }
        let mut superblocks = self
            .raw_superblocks
            .iter()
            .filter(|sb| {
                meta.disks.get(&sb.disk_id).is_none_or(|disk| {
                    matches!(
                        disk.status,
                        DiskStatus::Online | DiskStatus::Degraded | DiskStatus::Draining
                    )
                })
            })
            .cloned()
            .collect::<Vec<_>>();
        let mut seen = superblocks
            .iter()
            .map(|sb| sb.disk_id.clone())
            .collect::<BTreeSet<_>>();
        for (disk_id, disk) in &meta.disks {
            if seen.contains(disk_id)
                || !matches!(
                    disk.status,
                    DiskStatus::Online | DiskStatus::Degraded | DiskStatus::Draining
                )
            {
                continue;
            }
            let (superblock, _) = raw_store::inspect_device(meta.backend, disk.path.clone())?;
            seen.insert(superblock.disk_id.clone());
            superblocks.push(superblock);
        }
        Ok(superblocks)
    }

    fn active_block_backend_locked(
        &self,
        meta: &Metadata,
        write: bool,
    ) -> Result<FileBlockBackend> {
        if meta.backend == BackendKind::Host {
            return Err(ArgosError::Unsupported(
                "host backend has no block device set".to_string(),
            ));
        }
        let devices = meta
            .disks
            .iter()
            .filter(|(_, disk)| {
                matches!(
                    disk.status,
                    DiskStatus::Online | DiskStatus::Degraded | DiskStatus::Draining
                )
            })
            .map(|(disk_id, disk)| (disk_id.clone(), disk.path.clone()))
            .collect::<Vec<_>>();
        FileBlockBackend::open_with_ids(meta.backend, devices, write)
    }

    fn attr_from_inode(inode: &Inode, chunk_size: usize) -> NodeAttr {
        NodeAttr {
            ino: inode.id,
            kind: inode.kind.clone(),
            mode: inode.mode,
            uid: inode.uid,
            gid: inode.gid,
            nlink: inode.nlink,
            size: inode.size,
            rdev: inode.rdev,
            atime: inode.atime,
            mtime: inode.mtime,
            ctime: inode.ctime,
            blocks: if inode.kind == NodeKind::File {
                inode.size.div_ceil(512)
            } else {
                0
            },
            blksize: u32::try_from(chunk_size).unwrap_or(u32::MAX),
        }
    }
}
