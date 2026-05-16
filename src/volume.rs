use crate::acl;
use crate::advanced_io;
use crate::cache::BlockCache;
use crate::compression::{compress, decompress};
use crate::crypto;
use crate::erasure::RsCodec;
use crate::error::{ArgosError, Result};
use crate::health::{classify_inode, probe_disk_path, refresh_smart, risk_report};
use crate::journal;
use crate::types::*;
use crate::util::{
    append_json_line, atomic_write, clean_path, ensure_dir, now_f64, parent_name,
    relative_or_absolute, sha256_hex, split_path, stable_u01,
};
use parking_lot::Mutex;
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::fs;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use uuid::Uuid;

const ROOT_INO: InodeId = 1;
const NON_UTF8_NAME_PREFIX: &str = ".argosfs-name-nonutf8-v3:";
const ESCAPED_UTF8_NAME_PREFIX: &str = ".argosfs-name-utf8-v3:";
const LEGACY_NON_UTF8_NAME_PREFIX: &str = "\0argosfs-name-hex:";
const BOOT_CRITICAL_XATTR: &str = "system.argosfs.boot_critical";

#[derive(Clone)]
pub struct ArgosFs {
    root: Arc<PathBuf>,
    meta: Arc<Mutex<Metadata>>,
    rs: Arc<RsCodec>,
    cache: Arc<BlockCache>,
}

#[derive(Clone, Debug)]
pub struct AutopilotConfig {
    pub probe_interval_sec: u64,
    pub smart_interval_sec: u64,
    pub scrub_interval_sec: u64,
    pub rebalance_interval_sec: u64,
    pub drain_cooldown_sec: u64,
    pub failed_action_cooldown_sec: u64,
    pub risk_confirmations: u64,
    pub scrub_files_per_run: usize,
    pub rebalance_files_per_run: usize,
    pub rebalance_min_skew: f64,
    pub critical_risk_score: f64,
    pub max_drains_per_run: usize,
    pub foreground_latency_target_ms: f64,
}

impl Default for AutopilotConfig {
    fn default() -> Self {
        Self {
            probe_interval_sec: 60 * 60,
            smart_interval_sec: 10 * 60,
            scrub_interval_sec: 5 * 60,
            rebalance_interval_sec: 10 * 60,
            drain_cooldown_sec: 30 * 60,
            failed_action_cooldown_sec: 10 * 60,
            risk_confirmations: 2,
            scrub_files_per_run: 128,
            rebalance_files_per_run: 32,
            rebalance_min_skew: 0.08,
            critical_risk_score: 0.85,
            max_drains_per_run: 1,
            foreground_latency_target_ms: 75.0,
        }
    }
}

#[derive(Clone, Debug, Default, serde::Deserialize, serde::Serialize)]
struct AutopilotState {
    #[serde(default = "autopilot_state_version")]
    version: u32,
    #[serde(default)]
    runs: u64,
    #[serde(default)]
    last_run_at: f64,
    #[serde(default)]
    last_probe_at: f64,
    #[serde(default)]
    last_smart_at: f64,
    #[serde(default)]
    last_scrub_at: f64,
    #[serde(default)]
    last_rebalance_at: f64,
    #[serde(default)]
    scrub_cursor: Option<InodeId>,
    #[serde(default)]
    rebalance_cursor: Option<InodeId>,
    #[serde(default)]
    disks: BTreeMap<String, AutopilotDiskState>,
    #[serde(default)]
    action_stats: BTreeMap<String, AutopilotActionStats>,
}

#[derive(Clone, Debug, Default, serde::Deserialize, serde::Serialize)]
struct AutopilotDiskState {
    #[serde(default)]
    risk_streak: u64,
    #[serde(default)]
    healthy_streak: u64,
    #[serde(default)]
    last_risk_score: f64,
    #[serde(default)]
    last_predicted_failure: bool,
    #[serde(default)]
    last_drain_attempt_at: f64,
    #[serde(default)]
    next_action_after: f64,
    #[serde(default)]
    last_action: String,
}

#[derive(Clone, Debug, Default, serde::Deserialize, serde::Serialize)]
struct AutopilotActionStats {
    #[serde(default)]
    runs: u64,
    #[serde(default)]
    successes: u64,
    #[serde(default)]
    failures: u64,
    #[serde(default)]
    rewritten_files: u64,
    #[serde(default)]
    repaired_files: u64,
    #[serde(default)]
    utility_ewma: f64,
}

fn autopilot_state_version() -> u32 {
    2
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct NodeAttr {
    pub ino: InodeId,
    pub kind: NodeKind,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub nlink: u32,
    pub size: u64,
    pub rdev: u32,
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
}

struct PlacementRequest<'a> {
    key: &'a str,
    count: usize,
    storage_class: StorageTier,
    boot_critical: bool,
    exclude_disks: &'a BTreeSet<String>,
    required_bytes: u64,
}

impl ArgosFs {
    pub fn create(
        root: impl AsRef<Path>,
        mut config: VolumeConfig,
        disk_count: usize,
        force: bool,
    ) -> Result<Self> {
        if config.k == 0 || config.m == 0 {
            return Err(ArgosError::Invalid("k and m must be positive".to_string()));
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
        ensure_dir(&system.join("devices"))?;
        ensure_dir(&system.join("snapshots"))?;
        ensure_dir(&system.join("cache"))?;
        let uuid = Uuid::new_v4().to_string();
        let created_at = now_f64();
        let mut disks = BTreeMap::new();
        for index in 0..disk_count {
            let id = format!("disk-{index:04}");
            let path = PathBuf::from(format!(".argosfs/devices/{id}"));
            let disk_root = root.join(&path);
            ensure_dir(&disk_root.join("shards"))?;
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
            created_at,
            updated_at: created_at,
            txid: 0,
            next_inode: ROOT_INO + 1,
            next_stripe: 1,
            config,
            encryption: EncryptionConfig::default(),
            integrity: MetadataIntegrity::default(),
            disks,
            inodes,
        };
        let mut meta = meta;
        journal::initialize_volume(&root, &mut meta, created_at)?;
        Self::open(root)
    }

    pub fn open(root: impl AsRef<Path>) -> Result<Self> {
        let root = root.as_ref().to_path_buf();
        let recovered = journal::load_or_recover(&root)?;
        let mut meta = recovered.metadata;
        recompute_disk_usage_from_metadata(&mut meta);
        if meta.format != FORMAT_VERSION {
            return Err(ArgosError::Invalid(format!(
                "unsupported format {}",
                meta.format
            )));
        }
        let rs = RsCodec::new(meta.config.k, meta.config.m)?;
        let cache = BlockCache::new(
            root.join(".argosfs/cache/l2"),
            64 * 1024 * 1024,
            meta.config.l2_cache_bytes,
        );
        Ok(Self {
            root: Arc::new(root),
            meta: Arc::new(Mutex::new(meta)),
            rs: Arc::new(rs),
            cache: Arc::new(cache),
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn metadata_snapshot(&self) -> Metadata {
        self.meta.lock().clone()
    }

    pub fn transaction_report(&self) -> Result<TransactionReport> {
        journal::scan(&self.root)
    }

    pub fn sync(&self) -> Result<()> {
        let meta = self.meta.lock();

        let mut shard_paths = BTreeSet::new();
        for inode in meta.inodes.values() {
            for block in &inode.blocks {
                for shard in &block.shards {
                    if let Some(path) =
                        self.shard_path_if_disk_exists_locked(&meta, &shard.disk_id, &shard.relpath)
                    {
                        shard_paths.insert(path);
                    }
                }
            }
        }
        for path in shard_paths {
            if let Ok(file) = fs::File::open(&path) {
                file.sync_all()?;
            }
        }

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

    pub fn audit_transactions(root: impl AsRef<Path>) -> Result<TransactionReport> {
        journal::load_or_recover(root.as_ref()).map(|recovered| recovered.report)
    }

    pub fn snapshot(&self, name: &str) -> Result<PathBuf> {
        let meta = self.meta.lock();
        let safe: String = name
            .chars()
            .map(|ch| {
                if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-') {
                    ch
                } else {
                    '_'
                }
            })
            .collect();
        let path = self
            .root
            .join(".argosfs/snapshots")
            .join(format!("{safe}.json"));
        atomic_write(&path, serde_json::to_vec_pretty(&*meta)?.as_slice())?;
        self.journal_locked(&meta, "snapshot", json!({"name": name, "path": path}))?;
        Ok(path)
    }

    pub fn resolve_path(&self, path: &str, follow_final: bool) -> Result<InodeId> {
        let meta = self.meta.lock();
        self.resolve_path_locked(&meta, path, follow_final, 40)
    }

    pub fn attr_path(&self, path: &str, follow_final: bool) -> Result<NodeAttr> {
        let ino = self.resolve_path(path, follow_final)?;
        self.attr_inode(ino)
    }

    pub fn attr_inode(&self, ino: InodeId) -> Result<NodeAttr> {
        let meta = self.meta.lock();
        let inode = meta
            .inodes
            .get(&ino)
            .ok_or_else(|| ArgosError::NotFound(format!("inode {ino}")))?;
        Ok(Self::attr_from_inode(inode, meta.config.chunk_size))
    }

    pub fn lookup(&self, parent: InodeId, name: &OsStr) -> Result<NodeAttr> {
        let meta = self.meta.lock();
        let parent_inode = self.dir_inode_locked(&meta, parent)?;
        let name = entry_name_from_os(name)?;
        let child = parent_inode
            .entries
            .get(name.as_str())
            .ok_or_else(|| ArgosError::NotFound(name.clone()))?;
        let inode = meta
            .inodes
            .get(child)
            .ok_or_else(|| ArgosError::NotFound(child.to_string()))?;
        Ok(Self::attr_from_inode(inode, meta.config.chunk_size))
    }

    pub fn mkdir(&self, path: &str, mode: u32) -> Result<InodeId> {
        let (parent, name) = parent_name(path)?;
        let mut meta = self.meta.lock();
        let parent_ino = self.resolve_path_locked(&meta, &parent, true, 40)?;
        self.mkdir_locked(
            &mut meta,
            parent_ino,
            &name,
            mode,
            current_uid(),
            current_gid(),
        )
    }

    pub fn mkdir_at(&self, parent: InodeId, name: &OsStr, mode: u32) -> Result<NodeAttr> {
        self.mkdir_at_with_owner(parent, name, mode, current_uid(), current_gid())
    }

    pub fn mkdir_at_with_owner(
        &self,
        parent: InodeId,
        name: &OsStr,
        mode: u32,
        uid: u32,
        gid: u32,
    ) -> Result<NodeAttr> {
        let name = entry_name_from_os(name)?;
        let mut meta = self.meta.lock();
        let ino = self.mkdir_locked(&mut meta, parent, &name, mode, uid, gid)?;
        let inode = meta.inodes.get(&ino).unwrap();
        Ok(Self::attr_from_inode(inode, meta.config.chunk_size))
    }

    pub fn mknod_path(&self, path: &str, mode: u32, rdev: u32) -> Result<InodeId> {
        let (parent, name) = parent_name(path)?;
        let mut meta = self.meta.lock();
        let parent_ino = self.resolve_path_locked(&meta, &parent, true, 40)?;
        self.mknod_locked(
            &mut meta,
            parent_ino,
            &name,
            mode,
            rdev,
            current_uid(),
            current_gid(),
        )
    }

    pub fn mknod_at(
        &self,
        parent: InodeId,
        name: &OsStr,
        mode: u32,
        rdev: u32,
    ) -> Result<NodeAttr> {
        self.mknod_at_with_owner(parent, name, mode, rdev, current_uid(), current_gid())
    }

    pub fn mknod_at_with_owner(
        &self,
        parent: InodeId,
        name: &OsStr,
        mode: u32,
        rdev: u32,
        uid: u32,
        gid: u32,
    ) -> Result<NodeAttr> {
        let name = entry_name_from_os(name)?;
        let mut meta = self.meta.lock();
        let ino = self.mknod_locked(&mut meta, parent, &name, mode, rdev, uid, gid)?;
        let inode = meta.inodes.get(&ino).unwrap();
        Ok(Self::attr_from_inode(inode, meta.config.chunk_size))
    }

    pub fn create_file_path(&self, path: &str, mode: u32) -> Result<InodeId> {
        let (parent, name) = parent_name(path)?;
        let mut meta = self.meta.lock();
        let parent_ino = self.resolve_path_locked(&meta, &parent, true, 40)?;
        self.mknod_locked(
            &mut meta,
            parent_ino,
            &name,
            libc::S_IFREG | (mode & 0o7777),
            0,
            current_uid(),
            current_gid(),
        )
    }

    pub fn create_file_at(&self, parent: InodeId, name: &OsStr, mode: u32) -> Result<NodeAttr> {
        self.create_file_at_with_owner(parent, name, mode, current_uid(), current_gid())
    }

    pub fn create_file_at_with_owner(
        &self,
        parent: InodeId,
        name: &OsStr,
        mode: u32,
        uid: u32,
        gid: u32,
    ) -> Result<NodeAttr> {
        let name = entry_name_from_os(name)?;
        let mut meta = self.meta.lock();
        let ino = self.mknod_locked(
            &mut meta,
            parent,
            &name,
            libc::S_IFREG | (mode & 0o7777),
            0,
            uid,
            gid,
        )?;
        let inode = meta.inodes.get(&ino).unwrap();
        Ok(Self::attr_from_inode(inode, meta.config.chunk_size))
    }

    pub fn write_file(&self, path: &str, data: &[u8], mode: u32) -> Result<()> {
        let clean = clean_path(path);
        let ino = match self.resolve_path(&clean, true) {
            Ok(ino) => ino,
            Err(ArgosError::NotFound(_)) => self.create_file_path(&clean, mode)?,
            Err(err) => return Err(err),
        };
        self.replace_inode_data(ino, data, "write", json!({"path": clean}))
    }

    pub fn read_file(&self, path: &str, repair: bool) -> Result<Vec<u8>> {
        let ino = self.resolve_path(path, true)?;
        self.read_inode(ino, 0, u64::MAX as usize, repair)
    }

    pub fn read_inode(
        &self,
        ino: InodeId,
        offset: u64,
        size: usize,
        repair: bool,
    ) -> Result<Vec<u8>> {
        let mut meta = self.meta.lock();
        let inode = meta
            .inodes
            .get(&ino)
            .ok_or_else(|| ArgosError::NotFound(format!("inode {ino}")))?
            .clone();
        match inode.kind {
            NodeKind::Directory => return Err(ArgosError::IsDirectory(format!("inode {ino}"))),
            NodeKind::Symlink => return Ok(inode.target.unwrap_or_default().into_bytes()),
            NodeKind::Special => {
                return Err(ArgosError::Unsupported(format!(
                    "special inode {ino} has no data stream"
                )))
            }
            NodeKind::File => {}
        }
        let (data, damaged) = self.decode_inode_data_locked(&mut meta, &inode)?;
        if repair && !damaged.is_empty() {
            drop(inode);
            let repair_result = self.replace_inode_data_locked(
                &mut meta,
                ino,
                &data,
                "self-heal",
                json!({"damaged": damaged}),
                true,
                &BTreeSet::new(),
            );
            if let Err(err) = repair_result {
                self.journal_locked(
                    &meta,
                    "self-heal-deferred",
                    json!({"inode": ino, "error": err.to_string()}),
                )?;
            }
        } else if let Some(live) = meta.inodes.get_mut(&ino) {
            live.access_count = live.access_count.saturating_add(1);
            live.read_bytes = live.read_bytes.saturating_add(data.len() as u64);
            live.last_accessed_at = now_f64();
            live.workload_score = live.workload_score * 0.98 + 1.0;
        }
        let start = offset.min(data.len() as u64) as usize;
        let end = start.saturating_add(size).min(data.len());
        Ok(data[start..end].to_vec())
    }

    pub fn write_inode_range(&self, ino: InodeId, offset: u64, data: &[u8]) -> Result<usize> {
        let current = self.read_inode(ino, 0, u64::MAX as usize, true)?;
        let start = usize::try_from(offset)
            .map_err(|_| ArgosError::Invalid("write offset is too large".to_string()))?;
        let end = start
            .checked_add(data.len())
            .ok_or_else(|| ArgosError::Invalid("write range is too large".to_string()))?;
        let mut updated = current;
        if start > updated.len() {
            updated.resize(start, 0);
        }
        if end > updated.len() {
            updated.resize(end, 0);
        }
        updated[start..end].copy_from_slice(data);
        let mut meta = self.meta.lock();
        self.rewrite_inode_data_from_image_locked(
            &mut meta,
            ino,
            &updated,
            start,
            end,
            data.len() as u64,
            "write-range",
            json!({"inode": ino, "offset": offset, "bytes": data.len(), "rewrite": "stripe-range"}),
        )?;
        Ok(data.len())
    }

    pub fn truncate_path(&self, path: &str, size: u64) -> Result<()> {
        let ino = self.resolve_path(path, true)?;
        self.truncate_inode(ino, size)
    }

    pub fn truncate_inode(&self, ino: InodeId, size: u64) -> Result<()> {
        let mut data = self.read_inode(ino, 0, u64::MAX as usize, true)?;
        let requested_size = size;
        let size = usize::try_from(requested_size)
            .map_err(|_| ArgosError::Invalid("truncate size is too large".to_string()))?;
        data.resize(size, 0);
        let changed_start = size.min(
            self.attr_inode(ino)
                .map(|attr| attr.size as usize)
                .unwrap_or(size),
        );
        let mut meta = self.meta.lock();
        self.rewrite_inode_data_from_image_locked(
            &mut meta,
            ino,
            &data,
            changed_start,
            size,
            0,
            "truncate",
            json!({"inode": ino, "size": requested_size, "rewrite": "stripe-range"}),
        )
    }

    pub fn readdir(&self, ino: InodeId) -> Result<Vec<DirEntry>> {
        let meta = self.meta.lock();
        let chunk = meta.config.chunk_size;
        let inode = self.dir_inode_locked(&meta, ino)?.clone();
        let parent_ino = self.parent_inode_locked(&meta, ino)?;
        let mut entries = Vec::new();
        entries.push(DirEntry {
            name: ".".to_string(),
            name_bytes: b".".to_vec(),
            attr: Self::attr_from_inode(meta.inodes.get(&ino).unwrap(), chunk),
        });
        entries.push(DirEntry {
            name: "..".to_string(),
            name_bytes: b"..".to_vec(),
            attr: Self::attr_from_inode(meta.inodes.get(&parent_ino).unwrap(), chunk),
        });
        for (name, child) in inode.entries {
            if let Some(child_inode) = meta.inodes.get(&child) {
                let name_bytes = decode_entry_name_bytes(&name);
                entries.push(DirEntry {
                    name: display_entry_name(&name_bytes),
                    name_bytes,
                    attr: Self::attr_from_inode(child_inode, chunk),
                });
            }
        }
        Ok(entries)
    }

    pub fn unlink_path(&self, path: &str) -> Result<()> {
        let (parent, name) = parent_name(path)?;
        let mut meta = self.meta.lock();
        let parent_ino = self.resolve_path_locked(&meta, &parent, true, 40)?;
        self.unlink_locked(&mut meta, parent_ino, &name, false, Some(current_uid()))
    }

    pub fn unlink_at(&self, parent: InodeId, name: &OsStr) -> Result<()> {
        self.unlink_at_as(parent, name, current_uid())
    }

    pub fn unlink_at_as(&self, parent: InodeId, name: &OsStr, uid: u32) -> Result<()> {
        let name = entry_name_from_os(name)?;
        let mut meta = self.meta.lock();
        self.unlink_locked(&mut meta, parent, &name, false, Some(uid))
    }

    pub fn rmdir_path(&self, path: &str) -> Result<()> {
        let (parent, name) = parent_name(path)?;
        let mut meta = self.meta.lock();
        let parent_ino = self.resolve_path_locked(&meta, &parent, true, 40)?;
        self.unlink_locked(&mut meta, parent_ino, &name, true, Some(current_uid()))
    }

    pub fn rmdir_at(&self, parent: InodeId, name: &OsStr) -> Result<()> {
        self.rmdir_at_as(parent, name, current_uid())
    }

    pub fn rmdir_at_as(&self, parent: InodeId, name: &OsStr, uid: u32) -> Result<()> {
        let name = entry_name_from_os(name)?;
        let mut meta = self.meta.lock();
        self.unlink_locked(&mut meta, parent, &name, true, Some(uid))
    }

    pub fn rename_path(&self, old: &str, new: &str) -> Result<()> {
        let (old_parent, old_name) = parent_name(old)?;
        let (new_parent, new_name) = parent_name(new)?;
        let mut meta = self.meta.lock();
        let old_parent = self.resolve_path_locked(&meta, &old_parent, true, 40)?;
        let new_parent = self.resolve_path_locked(&meta, &new_parent, true, 40)?;
        self.rename_locked(
            &mut meta,
            old_parent,
            &old_name,
            new_parent,
            &new_name,
            RenamePolicy {
                uid: Some(current_uid()),
                ..RenamePolicy::default()
            },
        )
    }

    pub fn rename_at(
        &self,
        old_parent: InodeId,
        old_name: &OsStr,
        new_parent: InodeId,
        new_name: &OsStr,
    ) -> Result<()> {
        self.rename_at_with_policy(
            old_parent,
            old_name,
            new_parent,
            new_name,
            RenamePolicy::default(),
        )
    }

    pub fn rename_at_with_policy(
        &self,
        old_parent: InodeId,
        old_name: &OsStr,
        new_parent: InodeId,
        new_name: &OsStr,
        policy: RenamePolicy,
    ) -> Result<()> {
        let old_name = entry_name_from_os(old_name)?;
        let new_name = entry_name_from_os(new_name)?;
        let mut meta = self.meta.lock();
        self.rename_locked(
            &mut meta, old_parent, &old_name, new_parent, &new_name, policy,
        )
    }

    pub fn symlink_at(&self, parent: InodeId, name: &OsStr, target: &Path) -> Result<NodeAttr> {
        self.symlink_at_with_owner(parent, name, target, current_uid(), current_gid())
    }

    pub fn symlink_at_with_owner(
        &self,
        parent: InodeId,
        name: &OsStr,
        target: &Path,
        uid: u32,
        gid: u32,
    ) -> Result<NodeAttr> {
        let name = entry_name_from_os(name)?;
        let mut meta = self.meta.lock();
        let now = now_f64();
        if self
            .dir_inode_locked(&meta, parent)?
            .entries
            .contains_key(&name)
        {
            return Err(ArgosError::AlreadyExists(name));
        }
        let ino = self.alloc_inode_locked(&mut meta);
        let inherited_acl = meta
            .inodes
            .get(&parent)
            .and_then(acl::inherited_directory_acl);
        let target_string = target.to_string_lossy().to_string();
        let inode = Inode {
            id: ino,
            kind: NodeKind::Symlink,
            mode: libc::S_IFLNK | 0o777,
            uid,
            gid,
            nlink: 1,
            size: target_string.len() as u64,
            rdev: 0,
            atime: now,
            mtime: now,
            ctime: now,
            entries: BTreeMap::new(),
            target: Some(target_string.clone()),
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
            boot_critical: boot_critical_name(&name),
            workload_score: 0.0,
            last_accessed_at: now,
            last_written_at: now,
        };
        meta.inodes.insert(ino, inode);
        self.dir_inode_mut_locked(&mut meta, parent)?
            .entries
            .insert(name.clone(), ino);
        self.touch_inode_locked(&mut meta, parent, true, true);
        self.commit_locked(
            &mut meta,
            "symlink",
            json!({"parent": parent, "name": name, "target": target_string, "inode": ino}),
        )?;
        Ok(Self::attr_from_inode(
            meta.inodes.get(&ino).unwrap(),
            meta.config.chunk_size,
        ))
    }

    pub fn symlink_path(&self, target: &str, link_name: &str) -> Result<()> {
        let (parent, name) = parent_name(link_name)?;
        let parent_ino = self.resolve_path(&parent, true)?;
        self.symlink_at(parent_ino, OsStr::new(&name), Path::new(target))?;
        Ok(())
    }

    pub fn readlink_inode(&self, ino: InodeId) -> Result<String> {
        let meta = self.meta.lock();
        let inode = meta
            .inodes
            .get(&ino)
            .ok_or_else(|| ArgosError::NotFound(format!("inode {ino}")))?;
        if inode.kind != NodeKind::Symlink {
            return Err(ArgosError::Invalid("not a symbolic link".to_string()));
        }
        Ok(inode.target.clone().unwrap_or_default())
    }

    pub fn link_at(&self, ino: InodeId, new_parent: InodeId, new_name: &OsStr) -> Result<NodeAttr> {
        let name = entry_name_from_os(new_name)?;
        let mut meta = self.meta.lock();
        let inode_kind = meta
            .inodes
            .get(&ino)
            .ok_or_else(|| ArgosError::NotFound(format!("inode {ino}")))?
            .kind
            .clone();
        if self
            .dir_inode_locked(&meta, new_parent)?
            .entries
            .contains_key(&name)
        {
            return Err(ArgosError::AlreadyExists(name));
        }
        if inode_kind == NodeKind::Directory {
            return Err(ArgosError::Unsupported(
                "cannot hard link a directory".to_string(),
            ));
        }
        self.dir_inode_mut_locked(&mut meta, new_parent)?
            .entries
            .insert(name.clone(), ino);
        if let Some(inode) = meta.inodes.get_mut(&ino) {
            inode.nlink = inode.nlink.saturating_add(1);
            inode.ctime = now_f64();
        }
        self.touch_inode_locked(&mut meta, new_parent, true, true);
        self.commit_locked(
            &mut meta,
            "link",
            json!({"inode": ino, "new_parent": new_parent, "name": name}),
        )?;
        Ok(Self::attr_from_inode(
            meta.inodes
                .get(&ino)
                .ok_or_else(|| ArgosError::NotFound(format!("inode {ino}")))?,
            meta.config.chunk_size,
        ))
    }

    pub fn chmod_inode(&self, ino: InodeId, mode: u32) -> Result<NodeAttr> {
        let mut meta = self.meta.lock();
        let inode = meta
            .inodes
            .get_mut(&ino)
            .ok_or_else(|| ArgosError::NotFound(format!("inode {ino}")))?;
        inode.mode = (inode.mode & !0o7777) | (mode & 0o7777);
        inode.ctime = now_f64();
        self.commit_locked(
            &mut meta,
            "chmod",
            json!({"inode": ino, "mode": mode & 0o7777}),
        )?;
        Ok(Self::attr_from_inode(
            meta.inodes.get(&ino).unwrap(),
            meta.config.chunk_size,
        ))
    }

    pub fn chmod_path(&self, path: &str, mode: u32) -> Result<()> {
        let ino = self.resolve_path(path, true)?;
        self.chmod_inode(ino, mode)?;
        Ok(())
    }

    pub fn chown_inode(
        &self,
        ino: InodeId,
        uid: Option<u32>,
        gid: Option<u32>,
    ) -> Result<NodeAttr> {
        let mut meta = self.meta.lock();
        let inode = meta
            .inodes
            .get_mut(&ino)
            .ok_or_else(|| ArgosError::NotFound(format!("inode {ino}")))?;
        if let Some(uid) = uid {
            inode.uid = uid;
        }
        if let Some(gid) = gid {
            inode.gid = gid;
        }
        inode.ctime = now_f64();
        self.commit_locked(
            &mut meta,
            "chown",
            json!({"inode": ino, "uid": uid, "gid": gid}),
        )?;
        Ok(Self::attr_from_inode(
            meta.inodes.get(&ino).unwrap(),
            meta.config.chunk_size,
        ))
    }

    pub fn utimens_inode(&self, ino: InodeId, atime: f64, mtime: f64) -> Result<NodeAttr> {
        let mut meta = self.meta.lock();
        let inode = meta
            .inodes
            .get_mut(&ino)
            .ok_or_else(|| ArgosError::NotFound(format!("inode {ino}")))?;
        inode.atime = atime;
        inode.mtime = mtime;
        inode.ctime = now_f64();
        self.commit_locked(
            &mut meta,
            "utimens",
            json!({"inode": ino, "atime": atime, "mtime": mtime}),
        )?;
        Ok(Self::attr_from_inode(
            meta.inodes.get(&ino).unwrap(),
            meta.config.chunk_size,
        ))
    }

    pub fn setxattr_inode(&self, ino: InodeId, name: &str, value: &[u8]) -> Result<()> {
        validate_xattr_write(name)?;
        let mut meta = self.meta.lock();
        let inode = meta
            .inodes
            .get_mut(&ino)
            .ok_or_else(|| ArgosError::NotFound(format!("inode {ino}")))?;
        match name {
            acl::POSIX_ACL_ACCESS_XATTR | acl::ARGOS_POSIX_ACL_ACCESS_XATTR => {
                inode.posix_acl_access = Some(acl::parse_posix_acl_xattr(value)?);
            }
            acl::POSIX_ACL_DEFAULT_XATTR | acl::ARGOS_POSIX_ACL_DEFAULT_XATTR => {
                if inode.kind != NodeKind::Directory {
                    return Err(ArgosError::Invalid(
                        "default ACL can only be set on directories".to_string(),
                    ));
                }
                inode.posix_acl_default = Some(acl::parse_posix_acl_xattr(value)?);
            }
            acl::NFS4_ACL_XATTR => {
                let text = std::str::from_utf8(value)
                    .map_err(|err| ArgosError::Invalid(format!("invalid NFSv4 ACL JSON: {err}")))?;
                inode.nfs4_acl = Some(acl::parse_nfs4_acl_json(text)?);
            }
            BOOT_CRITICAL_XATTR => {
                let text = std::str::from_utf8(value).map_err(|err| {
                    ArgosError::Invalid(format!("invalid boot-critical flag: {err}"))
                })?;
                inode.boot_critical = matches!(text.trim(), "1" | "true" | "yes" | "on");
                if inode.boot_critical {
                    inode.storage_class = StorageTier::Hot;
                }
            }
            _ => {
                inode.xattrs.insert(name.to_string(), hex::encode(value));
            }
        }
        inode.ctime = now_f64();
        self.commit_locked(
            &mut meta,
            "setxattr",
            json!({"inode": ino, "name": name, "bytes": value.len()}),
        )
    }

    pub fn getxattr_inode(&self, ino: InodeId, name: &str) -> Result<Vec<u8>> {
        validate_xattr_read(name)?;
        let meta = self.meta.lock();
        let inode = meta
            .inodes
            .get(&ino)
            .ok_or_else(|| ArgosError::NotFound(format!("inode {ino}")))?;
        match name {
            acl::POSIX_ACL_ACCESS_XATTR => {
                let acl = inode
                    .posix_acl_access
                    .as_ref()
                    .ok_or_else(|| ArgosError::NotFound(format!("xattr {name}")))?;
                return Ok(acl::posix_acl_to_xattr(acl));
            }
            acl::POSIX_ACL_DEFAULT_XATTR => {
                let acl = inode
                    .posix_acl_default
                    .as_ref()
                    .ok_or_else(|| ArgosError::NotFound(format!("xattr {name}")))?;
                return Ok(acl::posix_acl_to_xattr(acl));
            }
            acl::ARGOS_POSIX_ACL_ACCESS_XATTR => {
                let acl = inode
                    .posix_acl_access
                    .as_ref()
                    .ok_or_else(|| ArgosError::NotFound(format!("xattr {name}")))?;
                return Ok(acl::format_posix_acl(acl).into_bytes());
            }
            acl::ARGOS_POSIX_ACL_DEFAULT_XATTR => {
                let acl = inode
                    .posix_acl_default
                    .as_ref()
                    .ok_or_else(|| ArgosError::NotFound(format!("xattr {name}")))?;
                return Ok(acl::format_posix_acl(acl).into_bytes());
            }
            acl::NFS4_ACL_XATTR => {
                let acl = inode
                    .nfs4_acl
                    .as_ref()
                    .ok_or_else(|| ArgosError::NotFound(format!("xattr {name}")))?;
                return Ok(acl::nfs4_to_json(acl)?.into_bytes());
            }
            BOOT_CRITICAL_XATTR => {
                if inode.boot_critical {
                    return Ok(b"1".to_vec());
                }
                return Err(ArgosError::NotFound(format!("xattr {name}")));
            }
            _ => {}
        }
        let value = inode
            .xattrs
            .get(name)
            .ok_or_else(|| ArgosError::NotFound(format!("xattr {name}")))?;
        hex::decode(value).map_err(|err| ArgosError::Invalid(format!("invalid xattr hex: {err}")))
    }

    pub fn listxattr_inode(&self, ino: InodeId) -> Result<Vec<String>> {
        let meta = self.meta.lock();
        let inode = meta
            .inodes
            .get(&ino)
            .ok_or_else(|| ArgosError::NotFound(format!("inode {ino}")))?;
        let mut names = inode
            .xattrs
            .keys()
            .filter(|name| {
                xattr_namespace(name).is_ok_and(|namespace| namespace == XattrNamespace::User)
            })
            .cloned()
            .collect::<BTreeSet<_>>();
        if inode.posix_acl_access.is_some() {
            names.insert(acl::POSIX_ACL_ACCESS_XATTR.to_string());
            names.insert(acl::ARGOS_POSIX_ACL_ACCESS_XATTR.to_string());
        }
        if inode.posix_acl_default.is_some() {
            names.insert(acl::POSIX_ACL_DEFAULT_XATTR.to_string());
            names.insert(acl::ARGOS_POSIX_ACL_DEFAULT_XATTR.to_string());
        }
        if inode.nfs4_acl.is_some() {
            names.insert(acl::NFS4_ACL_XATTR.to_string());
        }
        if inode.boot_critical {
            names.insert(BOOT_CRITICAL_XATTR.to_string());
        }
        Ok(names.into_iter().collect())
    }

    pub fn removexattr_inode(&self, ino: InodeId, name: &str) -> Result<()> {
        validate_xattr_write(name)?;
        let mut meta = self.meta.lock();
        let inode = meta
            .inodes
            .get_mut(&ino)
            .ok_or_else(|| ArgosError::NotFound(format!("inode {ino}")))?;
        let removed = match name {
            acl::POSIX_ACL_ACCESS_XATTR | acl::ARGOS_POSIX_ACL_ACCESS_XATTR => {
                inode.posix_acl_access.take().is_some()
            }
            acl::POSIX_ACL_DEFAULT_XATTR | acl::ARGOS_POSIX_ACL_DEFAULT_XATTR => {
                inode.posix_acl_default.take().is_some()
            }
            acl::NFS4_ACL_XATTR => inode.nfs4_acl.take().is_some(),
            BOOT_CRITICAL_XATTR => {
                let was_set = inode.boot_critical;
                inode.boot_critical = false;
                was_set
            }
            _ => inode.xattrs.remove(name).is_some(),
        };
        if !removed {
            return Err(ArgosError::NotFound(format!("xattr {name}")));
        }
        inode.ctime = now_f64();
        self.commit_locked(
            &mut meta,
            "removexattr",
            json!({"inode": ino, "name": name}),
        )
    }

    pub fn set_posix_acl_path(
        &self,
        path: &str,
        default_acl: bool,
        acl_value: PosixAcl,
    ) -> Result<()> {
        let ino = self.resolve_path(path, false)?;
        let mut meta = self.meta.lock();
        let inode = meta
            .inodes
            .get_mut(&ino)
            .ok_or_else(|| ArgosError::NotFound(format!("inode {ino}")))?;
        if default_acl && inode.kind != NodeKind::Directory {
            return Err(ArgosError::Invalid(
                "default ACL can only be set on directories".to_string(),
            ));
        }
        if default_acl {
            inode.posix_acl_default = Some(acl_value);
        } else {
            inode.posix_acl_access = Some(acl_value);
        }
        inode.ctime = now_f64();
        self.commit_locked(
            &mut meta,
            "set-posix-acl",
            json!({"inode": ino, "path": path, "default": default_acl}),
        )
    }

    pub fn get_posix_acl_path(&self, path: &str, default_acl: bool) -> Result<Option<PosixAcl>> {
        let ino = self.resolve_path(path, false)?;
        let meta = self.meta.lock();
        let inode = meta
            .inodes
            .get(&ino)
            .ok_or_else(|| ArgosError::NotFound(format!("inode {ino}")))?;
        Ok(if default_acl {
            inode.posix_acl_default.clone()
        } else {
            inode.posix_acl_access.clone()
        })
    }

    pub fn set_nfs4_acl_path(&self, path: &str, acl_value: Nfs4Acl) -> Result<()> {
        let ino = self.resolve_path(path, false)?;
        let mut meta = self.meta.lock();
        let inode = meta
            .inodes
            .get_mut(&ino)
            .ok_or_else(|| ArgosError::NotFound(format!("inode {ino}")))?;
        inode.nfs4_acl = Some(acl_value);
        inode.ctime = now_f64();
        self.commit_locked(
            &mut meta,
            "set-nfs4-acl",
            json!({"inode": ino, "path": path}),
        )
    }

    pub fn get_nfs4_acl_path(&self, path: &str) -> Result<Option<Nfs4Acl>> {
        let ino = self.resolve_path(path, false)?;
        let meta = self.meta.lock();
        let inode = meta
            .inodes
            .get(&ino)
            .ok_or_else(|| ArgosError::NotFound(format!("inode {ino}")))?;
        Ok(inode.nfs4_acl.clone())
    }

    pub fn check_access_inode(&self, ino: InodeId, uid: u32, gid: u32, mask: i32) -> Result<()> {
        let meta = self.meta.lock();
        let inode = meta
            .inodes
            .get(&ino)
            .ok_or_else(|| ArgosError::NotFound(format!("inode {ino}")))?;
        if acl::evaluate_access(inode, uid, gid, mask) {
            Ok(())
        } else {
            Err(ArgosError::PermissionDenied(format!(
                "uid {uid} gid {gid} mask {mask:o} inode {ino}"
            )))
        }
    }

    pub fn set_io_policy(
        &self,
        mode: IoMode,
        direct_io: bool,
        zero_copy: bool,
        numa_aware: bool,
    ) -> Result<()> {
        let mut meta = self.meta.lock();
        meta.config.io_mode = mode;
        meta.config.direct_io = direct_io;
        meta.config.zero_copy = zero_copy;
        meta.config.numa_aware = numa_aware;
        self.commit_locked(
            &mut meta,
            "set-io-policy",
            json!({
                "io_mode": mode,
                "direct_io": direct_io,
                "zero_copy": zero_copy,
                "numa_aware": numa_aware
            }),
        )
    }

    pub fn io_policy(&self) -> VolumeConfig {
        self.meta.lock().config.clone()
    }

    pub fn enable_encryption(&self, passphrase: &str) -> Result<()> {
        if passphrase.is_empty() {
            return Err(ArgosError::Invalid(
                "encryption passphrase must not be empty".to_string(),
            ));
        }
        let mut meta = self.meta.lock();
        if meta.encryption.enabled {
            let _ =
                crypto::derive_key_for_config(&meta.encryption, passphrase, meta.uuid.as_bytes())?;
        } else {
            meta.encryption = crypto::new_encryption_config(passphrase, meta.uuid.as_bytes())?;
            self.commit_locked(&mut meta, "enable-encryption", json!({}))?;
        }
        Ok(())
    }

    pub fn add_disk(
        &self,
        path: Option<PathBuf>,
        tier: Option<StorageTier>,
        weight: Option<f64>,
        capacity_bytes: Option<u64>,
        rebalance: bool,
    ) -> Result<String> {
        let mut meta = self.meta.lock();
        let next = meta
            .disks
            .keys()
            .filter_map(|id| id.strip_prefix("disk-")?.parse::<usize>().ok())
            .max()
            .map(|value| value + 1)
            .unwrap_or(0);
        let id = format!("disk-{next:04}");
        let stored = path.unwrap_or_else(|| PathBuf::from(format!(".argosfs/devices/{id}")));
        let disk_root = relative_or_absolute(&self.root, &stored);
        ensure_dir(&disk_root.join("shards"))?;
        let disk_root_canonical = canonical_or_self(&disk_root);
        if meta.disks.values().any(|disk| {
            canonical_or_self(&relative_or_absolute(&self.root, &disk.path)) == disk_root_canonical
        }) {
            return Err(ArgosError::AlreadyExists(format!(
                "disk path {}",
                disk_root.display()
            )));
        }
        let probe = probe_disk_path(&disk_root, 1024 * 1024);
        let final_tier = tier.unwrap_or(probe.recommended_tier);
        let final_weight = weight.unwrap_or(probe.recommended_weight).max(0.01);
        let final_capacity = capacity_bytes.unwrap_or(probe.capacity_bytes);
        let capacity_source = if capacity_bytes.is_some() {
            CapacitySource::UserOverride
        } else {
            CapacitySource::AutoProbe
        };
        atomic_write(
            &disk_root.join("argosfs-disk.json"),
            serde_json::to_vec_pretty(&json!({
                "format": FORMAT_VERSION,
                "volume_uuid": meta.uuid,
                "disk_id": id,
                "created_at": now_f64()
            }))?
            .as_slice(),
        )?;
        let id_for_disk = id.clone();
        meta.disks.insert(
            id.clone(),
            Disk {
                id: id_for_disk,
                path: stored,
                tier: final_tier,
                weight: final_weight,
                status: DiskStatus::Online,
                capacity_bytes: final_capacity,
                capacity_source,
                used_bytes: 0,
                health: HealthCounters::default(),
                class: probe.class,
                backing_device: probe.backing_device.clone(),
                backing_fs_id: probe.backing_fs_id.clone(),
                failure_domain: probe.backing_fs_id.clone().unwrap_or_else(|| id.clone()),
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
                created_at: now_f64(),
            },
        );
        self.commit_locked(
            &mut meta,
            "add-disk",
            json!({"disk_id": id, "tier": final_tier, "weight": final_weight, "capacity_bytes": final_capacity}),
        )?;
        drop(meta);
        if rebalance {
            self.rebalance()?;
        }
        Ok(id)
    }

    pub fn mark_disk(&self, disk_id: &str, status: DiskStatus) -> Result<()> {
        let mut meta = self.meta.lock();
        let disk = meta
            .disks
            .get_mut(disk_id)
            .ok_or_else(|| ArgosError::NotFound(disk_id.to_string()))?;
        disk.status = status;
        self.commit_locked(
            &mut meta,
            "mark-disk",
            json!({"disk_id": disk_id, "status": status}),
        )
    }

    pub fn set_disk_health(&self, disk_id: &str, values: HealthCounters) -> Result<()> {
        let mut meta = self.meta.lock();
        let disk = meta
            .disks
            .get_mut(disk_id)
            .ok_or_else(|| ArgosError::NotFound(disk_id.to_string()))?;
        disk.health = values;
        self.commit_locked(&mut meta, "set-health", json!({"disk_id": disk_id}))
    }

    pub fn refresh_disk_probe(&self, disk_id: Option<&str>) -> Result<Vec<DiskProbe>> {
        self.refresh_disk_probe_with_policy(disk_id, true)
    }

    fn refresh_disk_probe_observations(&self, disk_id: Option<&str>) -> Result<Vec<DiskProbe>> {
        self.refresh_disk_probe_with_policy(disk_id, false)
    }

    fn refresh_disk_probe_with_policy(
        &self,
        disk_id: Option<&str>,
        apply_recommendations: bool,
    ) -> Result<Vec<DiskProbe>> {
        let targets = {
            let meta = self.meta.lock();
            meta.disks
                .keys()
                .filter(|id| disk_id.map(|wanted| wanted == id.as_str()).unwrap_or(true))
                .cloned()
                .collect::<Vec<_>>()
        };
        if targets.is_empty() {
            return Err(ArgosError::NotFound(
                disk_id.unwrap_or("no disks").to_string(),
            ));
        }
        let mut probes = Vec::new();
        let mut meta = self.meta.lock();
        for id in targets {
            let disk_path = {
                let disk = meta
                    .disks
                    .get(&id)
                    .ok_or_else(|| ArgosError::NotFound(id.clone()))?;
                relative_or_absolute(&self.root, &disk.path)
            };
            let probe = probe_disk_path(&disk_path, 1024 * 1024);
            if let Some(disk) = meta.disks.get_mut(&id) {
                disk.class = probe.class;
                disk.backing_device = probe.backing_device.clone();
                disk.backing_fs_id = probe.backing_fs_id.clone();
                disk.failure_domain = probe
                    .backing_fs_id
                    .clone()
                    .unwrap_or_else(|| disk.id.clone());
                disk.sysfs_block = probe.sysfs_block.clone();
                disk.rotational = probe.rotational;
                disk.numa_node = probe.numa_node;
                if disk.capacity_source == CapacitySource::AutoProbe {
                    disk.capacity_bytes = probe.capacity_bytes;
                }
                if apply_recommendations {
                    disk.weight = probe.recommended_weight;
                    disk.tier = probe.recommended_tier;
                }
                disk.read_latency_ewma_ms = probe.measured_read_latency_ms;
                disk.write_latency_ewma_ms = probe.measured_write_latency_ms;
                disk.observed_read_mib_s = probe.measured_read_mib_s;
                disk.observed_write_mib_s = probe.measured_write_mib_s;
                disk.io_samples = disk.io_samples.saturating_add(1);
                disk.last_probe = probe.clone();
            }
            probes.push(probe);
        }
        self.commit_locked(
            &mut meta,
            "refresh-probe",
            json!({"disk_id": disk_id, "count": probes.len()}),
        )?;
        Ok(probes)
    }

    pub fn refresh_smart_health(
        &self,
        disk_id: Option<&str>,
    ) -> Result<Vec<(String, HealthCounters)>> {
        let targets = {
            let meta = self.meta.lock();
            meta.disks
                .iter()
                .filter(|(id, _)| disk_id.map(|wanted| wanted == id.as_str()).unwrap_or(true))
                .map(|(id, disk)| (id.clone(), disk.clone()))
                .collect::<Vec<_>>()
        };
        if targets.is_empty() {
            return Err(ArgosError::NotFound(
                disk_id.unwrap_or("no disks").to_string(),
            ));
        }
        let mut updates = Vec::new();
        let mut errors = Vec::new();
        for (id, disk) in targets {
            match refresh_smart(&disk) {
                Ok(health) => updates.push((id, health)),
                Err(err) => errors.push(json!({"disk_id": id, "error": err.to_string()})),
            }
        }
        if updates.is_empty() && !errors.is_empty() {
            return Err(ArgosError::Unsupported(format!(
                "SMART refresh failed for all selected disks: {}",
                serde_json::to_string(&errors)?
            )));
        }
        let mut meta = self.meta.lock();
        for (id, health) in &updates {
            if let Some(disk) = meta.disks.get_mut(id) {
                disk.health = health.clone();
            }
        }
        self.commit_locked(
            &mut meta,
            "refresh-smart",
            json!({"disk_id": disk_id, "count": updates.len(), "errors": errors}),
        )?;
        Ok(updates)
    }

    pub fn drain_disk(&self, disk_id: &str) -> Result<u64> {
        {
            let mut meta = self.meta.lock();
            if !meta.disks.contains_key(disk_id) {
                return Err(ArgosError::NotFound(disk_id.to_string()));
            }
            let have = meta
                .disks
                .iter()
                .filter(|(id, disk)| id.as_str() != disk_id && disk.status == DiskStatus::Online)
                .count();
            let need = self.rs.total();
            if have < need {
                return Err(ArgosError::NotEnoughDisks { need, have });
            }
            let disk = meta
                .disks
                .get_mut(disk_id)
                .ok_or_else(|| ArgosError::NotFound(disk_id.to_string()))?;
            disk.status = DiskStatus::Draining;
            self.commit_locked(&mut meta, "drain-start", json!({"disk_id": disk_id}))?;
        }
        let targets = {
            let meta = self.meta.lock();
            meta.inodes
                .iter()
                .filter_map(|(ino, inode)| {
                    if inode.kind == NodeKind::File
                        && inode
                            .blocks
                            .iter()
                            .any(|block| block.shards.iter().any(|shard| shard.disk_id == disk_id))
                    {
                        Some(*ino)
                    } else {
                        None
                    }
                })
                .collect::<Vec<_>>()
        };
        let mut rewritten = 0;
        let mut exclude = BTreeSet::new();
        exclude.insert(disk_id.to_string());
        for ino in targets {
            let data = self.read_inode(ino, 0, u64::MAX as usize, false)?;
            let mut meta = self.meta.lock();
            self.replace_inode_data_locked(
                &mut meta,
                ino,
                &data,
                "drain-rewrite",
                json!({"disk_id": disk_id}),
                true,
                &exclude,
            )?;
            rewritten += 1;
        }
        let mut meta = self.meta.lock();
        self.commit_locked(
            &mut meta,
            "drain-done",
            json!({"disk_id": disk_id, "rewritten_files": rewritten}),
        )?;
        Ok(rewritten)
    }

    pub fn remove_disk(&self, disk_id: &str) -> Result<u64> {
        let rewritten = self.drain_disk(disk_id)?;
        let mut meta = self.meta.lock();
        let disk = meta
            .disks
            .get_mut(disk_id)
            .ok_or_else(|| ArgosError::NotFound(disk_id.to_string()))?;
        disk.status = DiskStatus::Removed;
        self.commit_locked(
            &mut meta,
            "remove-disk",
            json!({"disk_id": disk_id, "rewritten_files": rewritten}),
        )?;
        Ok(rewritten)
    }

    pub fn rebalance(&self) -> Result<u64> {
        self.rebalance_limited(usize::MAX, None)
            .map(|(rewritten, _)| rewritten)
    }

    fn rebalance_limited(
        &self,
        max_files: usize,
        cursor: Option<InodeId>,
    ) -> Result<(u64, Option<InodeId>)> {
        if max_files == 0 {
            return Ok((0, cursor));
        }
        let targets = self
            .file_window(cursor, max_files)
            .into_iter()
            .map(|(ino, _)| ino)
            .collect::<Vec<_>>();
        let mut rewritten = 0;
        let mut next_cursor = cursor;
        for ino in targets {
            let data = self.read_inode(ino, 0, u64::MAX as usize, true)?;
            let mut meta = self.meta.lock();
            if let Some(inode) = meta.inodes.get_mut(&ino) {
                classify_inode(inode);
            }
            self.replace_inode_data_locked(
                &mut meta,
                ino,
                &data,
                "rebalance-rewrite",
                json!({"inode": ino}),
                true,
                &BTreeSet::new(),
            )?;
            rewritten += 1;
            next_cursor = Some(ino);
        }
        let mut meta = self.meta.lock();
        self.commit_locked(
            &mut meta,
            "rebalance-done",
            json!({"rewritten_files": rewritten}),
        )?;
        Ok((rewritten, next_cursor))
    }

    fn scrub_limited(
        &self,
        max_files: usize,
        cursor: Option<InodeId>,
    ) -> (FsckReport, Option<InodeId>) {
        let mut report = FsckReport::default();
        if max_files == 0 {
            return (report, cursor);
        }
        let mut next_cursor = cursor;
        for (ino, _) in self.file_window(cursor, max_files) {
            report.files_checked += 1;
            match self.read_inode(ino, 0, u64::MAX as usize, true) {
                Ok(_) => {}
                Err(err) => {
                    report.unrecoverable_files += 1;
                    report.errors.push(format!("inode {ino}: {err}"));
                }
            }
            next_cursor = Some(ino);
        }
        (report, next_cursor)
    }

    pub fn health_report(&self) -> HealthReport {
        let meta = self.meta.lock();
        let disks = meta
            .disks
            .values()
            .map(|disk| risk_report(disk, &relative_or_absolute(&self.root, &disk.path)))
            .collect();
        HealthReport {
            volume_uuid: meta.uuid.clone(),
            txid: meta.txid,
            files: meta
                .inodes
                .values()
                .filter(|inode| inode.kind == NodeKind::File)
                .count(),
            directories: meta
                .inodes
                .values()
                .filter(|inode| inode.kind == NodeKind::Directory)
                .count(),
            symlinks: meta
                .inodes
                .values()
                .filter(|inode| inode.kind == NodeKind::Symlink)
                .count(),
            specials: meta
                .inodes
                .values()
                .filter(|inode| inode.kind == NodeKind::Special)
                .count(),
            disks,
            cache: self.cache.stats(),
            io_mode: meta.config.io_mode,
            encryption_enabled: meta.encryption.enabled,
        }
    }

    pub fn fsck(&self, repair: bool, remove_orphans: bool) -> Result<FsckReport> {
        let mut report = FsckReport::default();
        let inodes = self.metadata_snapshot().inodes;
        for (ino, inode) in inodes {
            match inode.kind {
                NodeKind::Directory => {
                    report.directories_checked += 1;
                    for child in inode.entries.values() {
                        if !self.metadata_snapshot().inodes.contains_key(child) {
                            report
                                .errors
                                .push(format!("directory {ino} references missing inode {child}"));
                        }
                    }
                }
                NodeKind::File => {
                    report.files_checked += 1;
                    let mut damaged = false;
                    for block in &inode.blocks {
                        for shard in &block.shards {
                            let meta = self.meta.lock();
                            let Some(path) = self.shard_path_if_disk_exists_locked(
                                &meta,
                                &shard.disk_id,
                                &shard.relpath,
                            ) else {
                                drop(meta);
                                report.missing_shards += 1;
                                damaged = true;
                                continue;
                            };
                            let io_mode = meta.config.io_mode;
                            let zero_copy = meta.config.zero_copy;
                            drop(meta);
                            match advanced_io::read_all(&path, shard.size, io_mode, zero_copy) {
                                Ok(data) => {
                                    if sha256_hex(&data) != shard.sha256 {
                                        report.checksum_errors += 1;
                                        damaged = true;
                                    }
                                }
                                Err(_) => {
                                    report.missing_shards += 1;
                                    damaged = true;
                                }
                            }
                        }
                    }
                    match self.read_inode(ino, 0, u64::MAX as usize, false) {
                        Ok(data) => {
                            if damaged {
                                report.damaged_files += 1;
                                if repair {
                                    self.replace_inode_data(
                                        ino,
                                        &data,
                                        "fsck-repair",
                                        json!({"inode": ino}),
                                    )?;
                                    report.repaired_files += 1;
                                }
                            }
                        }
                        Err(err) => {
                            report.unrecoverable_files += 1;
                            report.errors.push(format!("inode {ino}: {err}"));
                        }
                    }
                }
                NodeKind::Symlink | NodeKind::Special => {}
            }
        }
        let refs = self.referenced_shards();
        let mut referenced_usage = BTreeMap::<String, u64>::new();
        {
            let meta = self.metadata_snapshot();
            for inode in meta.inodes.values() {
                for block in &inode.blocks {
                    for shard in &block.shards {
                        *referenced_usage.entry(shard.disk_id.clone()).or_default() +=
                            shard.size as u64;
                    }
                }
            }
        }
        let meta = self.metadata_snapshot();
        for (disk_id, disk) in meta.disks {
            let disk_root = relative_or_absolute(&self.root, &disk.path);
            let shard_root = disk_root.join("shards");
            if !shard_root.exists() {
                continue;
            }
            for entry in walkdir::WalkDir::new(&shard_root)
                .into_iter()
                .filter_map(|entry| entry.ok())
            {
                if !entry.file_type().is_file() {
                    continue;
                }
                let rel = entry.path().strip_prefix(&disk_root).unwrap().to_path_buf();
                if !refs.contains(&(disk_id.clone(), rel.clone())) {
                    report.orphan_shards += 1;
                    if remove_orphans {
                        fs::remove_file(entry.path())?;
                        report.removed_orphans += 1;
                    }
                }
            }
        }
        if repair || remove_orphans {
            let mut meta = self.meta.lock();
            for (disk_id, disk) in meta.disks.iter_mut() {
                disk.used_bytes = referenced_usage.get(disk_id).copied().unwrap_or(0);
            }
            self.commit_locked(&mut meta, "fsck", json!({"report": report}))?;
        }
        Ok(report)
    }

    pub fn scrub(&self) -> Result<FsckReport> {
        self.fsck(true, true)
    }

    pub fn autopilot_once(&self) -> Result<serde_json::Value> {
        self.autopilot_once_with_config(AutopilotConfig::default())
    }

    pub fn autopilot_once_with_config(&self, config: AutopilotConfig) -> Result<serde_json::Value> {
        let now = now_f64();
        let (mut state, state_warning) = self.load_autopilot_state();
        state.version = autopilot_state_version();
        state.runs = state.runs.saturating_add(1);
        state.last_run_at = now;

        let mut actions = Vec::new();
        let mut stop_mutations = false;
        if let Some(warning) = state_warning {
            actions.push(json!({"action": "autopilot-state-reset", "error": warning}));
        }

        if autopilot_due(state.last_probe_at, config.probe_interval_sec, now) {
            match self.refresh_disk_probe_observations(None) {
                Ok(probes) => {
                    state.last_probe_at = now;
                    record_autopilot_action(&mut state, "probe", true, 0.2, 0, 0);
                    actions.push(
                        json!({"action": "probe", "disks": probes.len(), "mode": "observe-only"}),
                    );
                }
                Err(err) => {
                    stop_mutations |= matches!(err, ArgosError::Conflict(_));
                    record_autopilot_action(&mut state, "probe", false, -1.0, 0, 0);
                    actions.push(json!({"action": "probe-skipped", "error": err.to_string()}));
                }
            }
        }

        if !stop_mutations && autopilot_due(state.last_smart_at, config.smart_interval_sec, now) {
            match self.refresh_smart_health(None) {
                Ok(updates) => {
                    state.last_smart_at = now;
                    record_autopilot_action(&mut state, "smart", true, updates.len() as f64, 0, 0);
                    actions
                        .push(json!({"action": "smart-refresh", "updated_disks": updates.len()}));
                }
                Err(err) => {
                    stop_mutations |= matches!(err, ArgosError::Conflict(_));
                    record_autopilot_action(&mut state, "smart", false, -0.2, 0, 0);
                    actions
                        .push(json!({"action": "smart-refresh-skipped", "error": err.to_string()}));
                }
            }
        }

        let mut report = self.health_report();
        update_autopilot_risk_memory(&mut state, &report, now);

        if !stop_mutations {
            let mut drains = 0usize;
            for disk in report
                .disks
                .iter()
                .filter(|disk| disk.predicted_failure && disk.status == DiskStatus::Online)
            {
                let decision = state
                    .disks
                    .get(&disk.id)
                    .map(|disk_state| autopilot_drain_decision(disk, disk_state, now, &config))
                    .unwrap_or(AutopilotDrainDecision::Observe);
                match decision {
                    AutopilotDrainDecision::Drain if drains < config.max_drains_per_run => {
                        drains += 1;
                        if let Some(disk_state) = state.disks.get_mut(&disk.id) {
                            disk_state.last_drain_attempt_at = now;
                        }
                        match self.drain_disk(&disk.id) {
                            Ok(rewritten) => match self.mark_disk(&disk.id, DiskStatus::Degraded) {
                                Ok(()) => {
                                    if let Some(disk_state) = state.disks.get_mut(&disk.id) {
                                        disk_state.next_action_after =
                                            now + config.drain_cooldown_sec as f64;
                                        disk_state.last_action = "drained".to_string();
                                    }
                                    record_autopilot_action(
                                        &mut state,
                                        "drain",
                                        true,
                                        4.0 + disk.risk_score * 6.0,
                                        rewritten,
                                        0,
                                    );
                                    actions.push(json!({"action": "drain-predicted-failure", "disk_id": disk.id, "rewritten_files": rewritten, "risk": disk.risk_score, "confirmations": state.disks.get(&disk.id).map(|disk| disk.risk_streak).unwrap_or_default()}));
                                }
                                Err(err) => {
                                    stop_mutations |= matches!(err, ArgosError::Conflict(_));
                                    record_autopilot_action(
                                        &mut state, "drain", false, -2.0, rewritten, 0,
                                    );
                                    actions.push(json!({"action": "drain-mark-degraded-failed", "disk_id": disk.id, "rewritten_files": rewritten, "error": err.to_string()}));
                                }
                            },
                            Err(err) => {
                                if let Some(disk_state) = state.disks.get_mut(&disk.id) {
                                    disk_state.next_action_after =
                                        now + config.failed_action_cooldown_sec as f64;
                                    disk_state.last_action = "drain-deferred".to_string();
                                }
                                stop_mutations |= matches!(err, ArgosError::Conflict(_));
                                record_autopilot_action(&mut state, "drain", false, -1.5, 0, 0);
                                actions.push(json!({"action": "skip-drain-predicted-failure", "disk_id": disk.id, "risk": disk.risk_score, "error": err.to_string()}));
                            }
                        }
                    }
                    AutopilotDrainDecision::Drain => {
                        actions.push(json!({"action": "defer-drain-budget", "disk_id": disk.id, "risk": disk.risk_score}));
                    }
                    AutopilotDrainDecision::Cooldown => {
                        actions.push(json!({"action": "defer-drain-cooldown", "disk_id": disk.id, "risk": disk.risk_score}));
                    }
                    AutopilotDrainDecision::Observe => {
                        actions.push(json!({"action": "observe-predicted-failure", "disk_id": disk.id, "risk": disk.risk_score, "confirmations": state.disks.get(&disk.id).map(|disk| disk.risk_streak).unwrap_or_default()}));
                    }
                }
            }
            if drains > 0 {
                report = self.health_report();
            }
        }

        if !stop_mutations && autopilot_due(state.last_scrub_at, config.scrub_interval_sec, now) {
            let scrub_budget = latency_throttled_budget(
                config.scrub_files_per_run,
                &report,
                config.foreground_latency_target_ms,
            );
            let (fsck, cursor) = self.scrub_limited(scrub_budget, state.scrub_cursor);
            let repaired = fsck.repaired_files;
            let utility = fsck.repaired_files as f64 * 3.0
                - fsck.unrecoverable_files as f64 * 5.0
                - fsck.errors.len() as f64;
            state.scrub_cursor = cursor;
            state.last_scrub_at = now;
            record_autopilot_action(
                &mut state,
                "scrub",
                fsck.errors.is_empty(),
                utility,
                0,
                repaired,
            );
            actions.push(json!({"action": "scrub-incremental", "budget_files": scrub_budget, "requested_budget_files": config.scrub_files_per_run, "cursor": state.scrub_cursor, "report": fsck}));
        }

        let skew = autopilot_rebalance_skew(&report);
        if !stop_mutations
            && autopilot_due(state.last_rebalance_at, config.rebalance_interval_sec, now)
            && skew >= config.rebalance_min_skew
        {
            let budget = latency_throttled_budget(
                adaptive_autopilot_budget(
                    config.rebalance_files_per_run,
                    state.action_stats.get("rebalance"),
                ),
                &report,
                config.foreground_latency_target_ms,
            );
            match self.rebalance_limited(budget, state.rebalance_cursor) {
                Ok((rewritten, cursor)) => {
                    state.rebalance_cursor = cursor;
                    state.last_rebalance_at = now;
                    record_autopilot_action(
                        &mut state,
                        "rebalance",
                        true,
                        skew * 10.0 - rewritten as f64 * 0.02,
                        rewritten,
                        0,
                    );
                    actions.push(json!({"action": "rebalance-incremental", "budget_files": budget, "requested_budget_files": config.rebalance_files_per_run, "rewritten_files": rewritten, "cursor": state.rebalance_cursor, "skew": skew}));
                }
                Err(err) => {
                    stop_mutations |= matches!(err, ArgosError::Conflict(_));
                    state.last_rebalance_at = now;
                    record_autopilot_action(&mut state, "rebalance", false, -2.0, 0, 0);
                    actions.push(json!({"action": "rebalance-skipped", "budget_files": budget, "skew": skew, "error": err.to_string()}));
                }
            }
        } else if !stop_mutations {
            actions.push(json!({"action": "rebalance-not-needed", "skew": skew, "threshold": config.rebalance_min_skew}));
        }

        let verification = self.fsck(false, false);
        match &verification {
            Ok(report) if report.errors.is_empty() && report.unrecoverable_files == 0 => {
                actions.push(json!({"action": "verify-actions", "result": "ok"}));
            }
            Ok(report) => {
                actions.push(
                    json!({"action": "verify-actions", "result": "failed", "report": report}),
                );
                record_autopilot_action(&mut state, "verify", false, -4.0, 0, 0);
            }
            Err(err) => {
                actions.push(json!({"action": "verify-actions", "result": "error", "error": err.to_string()}));
                record_autopilot_action(&mut state, "verify", false, -4.0, 0, 0);
            }
        }
        let health = self.health_report();
        let adaptive_mode = adaptive_autopilot_mode(&state);
        let result = json!({
            "actions": actions.clone(),
            "health": health,
            "planner": {
                "state_version": state.version,
                "runs": state.runs,
                "adaptive_mode": adaptive_mode,
                "scrub_cursor": state.scrub_cursor,
                "rebalance_cursor": state.rebalance_cursor,
                "stopped_for_conflict": stop_mutations
            }
        });
        self.save_autopilot_state(&state)?;
        append_json_line(&self.root.join(".argosfs/autopilot.jsonl"), &result)?;
        let meta = self.meta.lock();
        self.journal_locked(&meta, "autopilot", json!({"actions": actions}))?;
        Ok(result)
    }

    pub fn autopilot_dry_run(&self) -> Result<serde_json::Value> {
        self.autopilot_dry_run_with_config(AutopilotConfig::default())
    }

    pub fn autopilot_dry_run_with_config(
        &self,
        config: AutopilotConfig,
    ) -> Result<serde_json::Value> {
        let now = now_f64();
        let (mut state, state_warning) = self.load_autopilot_state();
        let report = self.health_report();
        update_autopilot_risk_memory(&mut state, &report, now);
        let online = report
            .disks
            .iter()
            .filter(|disk| disk.status == DiskStatus::Online)
            .count();
        let mut decisions = Vec::new();
        for disk in &report.disks {
            let disk_state = state.disks.get(&disk.id).cloned().unwrap_or_default();
            let drain_decision = autopilot_drain_decision(disk, &disk_state, now, &config);
            let enough_online_disks = online.saturating_sub(1) >= self.rs.total();
            let chosen_action = if disk.predicted_failure
                && disk.status == DiskStatus::Online
                && enough_online_disks
                && drain_decision == AutopilotDrainDecision::Drain
            {
                "drain"
            } else {
                "observe"
            };
            let rejected_actions = if !enough_online_disks {
                vec![json!({"action": "drain", "reason": "not enough online disks after drain"})]
            } else if drain_decision == AutopilotDrainDecision::Cooldown {
                vec![json!({"action": "drain", "reason": "cooldown"})]
            } else if !disk.predicted_failure {
                vec![json!({"action": "drain", "reason": "risk below threshold"})]
            } else {
                Vec::new()
            };
            decisions.push(json!({
                "target": disk.id,
                "chosen_action": chosen_action,
                "candidates": [
                    {"action": "observe", "score": 0.2},
                    {"action": "drain", "score": if disk.predicted_failure { 4.0 + disk.risk_score * 6.0 } else { -1.0 }}
                ],
                "rejected_actions": rejected_actions,
                "safety_checks": {
                    "enough_online_disks": enough_online_disks,
                    "metadata_conflict": false,
                    "boot_critical_safe": enough_online_disks
                },
                "expected_utility": if chosen_action == "drain" { 4.0 + disk.risk_score * 6.0 } else { 0.2 },
                "observations": {
                    "risk_score": disk.risk_score,
                    "predicted_failure": disk.predicted_failure,
                    "smart_fields_observed": disk.health.smart_fields_observed.clone(),
                    "smart_fields_missing": disk.health.smart_fields_missing.clone(),
                    "smart_stale": disk.smart_stale
                }
            }));
        }
        let skew = autopilot_rebalance_skew(&report);
        let rebalance_budget = latency_throttled_budget(
            adaptive_autopilot_budget(
                config.rebalance_files_per_run,
                state.action_stats.get("rebalance"),
            ),
            &report,
            config.foreground_latency_target_ms,
        );
        Ok(json!({
            "dry_run": true,
            "mutated": false,
            "state_warning": state_warning,
            "decisions": decisions,
            "planner": {
                "state_version": autopilot_state_version(),
                "adaptive_mode": adaptive_autopilot_mode(&state),
                "rebalance": {
                    "skew": skew,
                    "threshold": config.rebalance_min_skew,
                    "would_run": skew >= config.rebalance_min_skew,
                    "budget_files": rebalance_budget
                }
            },
            "health": report
        }))
    }

    fn load_autopilot_state(&self) -> (AutopilotState, Option<String>) {
        let path = self.root.join(".argosfs/autopilot-state.json");
        if !path.exists() {
            let state = AutopilotState {
                version: autopilot_state_version(),
                ..AutopilotState::default()
            };
            return (state, None);
        }
        match fs::read(&path).map_err(ArgosError::Io).and_then(|bytes| {
            serde_json::from_slice::<AutopilotState>(&bytes).map_err(ArgosError::Json)
        }) {
            Ok(mut state) => {
                state.version = autopilot_state_version();
                (state, None)
            }
            Err(err) => {
                let state = AutopilotState {
                    version: autopilot_state_version(),
                    ..AutopilotState::default()
                };
                (state, Some(err.to_string()))
            }
        }
    }

    fn save_autopilot_state(&self, state: &AutopilotState) -> Result<()> {
        atomic_write(
            &self.root.join(".argosfs/autopilot-state.json"),
            serde_json::to_vec_pretty(state)?.as_slice(),
        )
    }

    pub fn iter_paths(&self) -> Vec<(String, InodeId)> {
        let meta = self.meta.lock();
        let mut out = vec![("/".to_string(), ROOT_INO)];
        fn walk(meta: &Metadata, out: &mut Vec<(String, InodeId)>, prefix: &str, ino: InodeId) {
            if let Some(inode) = meta.inodes.get(&ino) {
                if inode.kind != NodeKind::Directory {
                    return;
                }
                for (name, child) in inode.entries.iter() {
                    let path = if prefix == "/" {
                        format!("/{name}")
                    } else {
                        format!("{prefix}/{name}")
                    };
                    out.push((path.clone(), *child));
                    walk(meta, out, &path, *child);
                }
            }
        }
        walk(&meta, &mut out, "/", ROOT_INO);
        out
    }

    fn file_window(&self, cursor: Option<InodeId>, max_files: usize) -> Vec<(InodeId, Inode)> {
        let meta = self.meta.lock();
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
        let inherited_acl = meta
            .inodes
            .get(&parent)
            .and_then(acl::inherited_directory_acl);
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
            blocks: Vec::new(),
            xattrs: BTreeMap::new(),
            posix_acl_access: inherited_acl.clone(),
            posix_acl_default: inherited_acl,
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
        rdev: u32,
        uid: u32,
        gid: u32,
    ) -> Result<InodeId> {
        validate_entry_name(name)?;
        if self
            .dir_inode_locked(meta, parent)?
            .entries
            .contains_key(name)
        {
            return Err(ArgosError::AlreadyExists(name.to_string()));
        }
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
            .and_then(acl::inherited_directory_acl);
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
        self.commit_locked(
            meta,
            "mknod",
            json!({"parent": parent, "name": name, "inode": ino, "mode": mode, "rdev": rdev}),
        )?;
        Ok(ino)
    }

    fn unlink_locked(
        &self,
        meta: &mut Metadata,
        parent: InodeId,
        name: &str,
        dir: bool,
        uid: Option<u32>,
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
            if live.nlink == 0 {
                blocks_to_delete = live.blocks.clone();
                meta.inodes.remove(&child);
            }
        }
        self.account_blocks_locked(meta, &blocks_to_delete, false);
        self.commit_locked(
            meta,
            if dir { "rmdir" } else { "unlink" },
            json!({"parent": parent, "name": name, "inode": child}),
        )?;
        self.delete_blocks_locked(meta, &blocks_to_delete);
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
                if live.nlink == 0 {
                    blocks_to_delete = live.blocks.clone();
                    meta.inodes.remove(&existing);
                }
            }
        }
        self.account_blocks_locked(meta, &blocks_to_delete, false);
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
        self.delete_blocks_locked(meta, &blocks_to_delete);
        Ok(())
    }

    fn replace_inode_data(
        &self,
        ino: InodeId,
        data: &[u8],
        action: &str,
        details: serde_json::Value,
    ) -> Result<()> {
        let mut meta = self.meta.lock();
        self.replace_inode_data_locked(
            &mut meta,
            ino,
            data,
            action,
            details,
            false,
            &BTreeSet::new(),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn replace_inode_data_locked(
        &self,
        meta: &mut Metadata,
        ino: InodeId,
        data: &[u8],
        action: &str,
        details: serde_json::Value,
        preserve_mtime: bool,
        exclude_disks: &BTreeSet<String>,
    ) -> Result<()> {
        let rollback = meta.clone();
        let (storage_class, boot_critical) = {
            let inode = meta
                .inodes
                .get(&ino)
                .ok_or_else(|| ArgosError::NotFound(format!("inode {ino}")))?;
            match inode.kind {
                NodeKind::File => {}
                NodeKind::Directory => {
                    return Err(ArgosError::IsDirectory(format!("inode {ino}")));
                }
                NodeKind::Symlink | NodeKind::Special => {
                    return Err(ArgosError::Unsupported("not a regular file".to_string()));
                }
            }
            (inode.storage_class, inode.boot_critical)
        };
        let old_blocks = meta.inodes.get(&ino).unwrap().blocks.clone();
        let new_blocks =
            self.encode_data_locked(meta, data, 0, storage_class, boot_critical, exclude_disks)?;
        let new_blocks_for_cleanup = new_blocks.clone();
        let now = now_f64();
        let inode = meta.inodes.get_mut(&ino).unwrap();
        inode.blocks = new_blocks;
        inode.size = data.len() as u64;
        inode.write_count = inode.write_count.saturating_add(1);
        inode.write_bytes = inode.write_bytes.saturating_add(data.len() as u64);
        inode.last_written_at = now;
        inode.workload_score = inode.workload_score * 0.90 + 2.0;
        if !preserve_mtime {
            inode.mtime = now;
        }
        inode.ctime = now;
        self.account_blocks_locked(meta, &old_blocks, false);
        if let Err(err) = self.commit_locked(meta, action, details) {
            if matches!(&err, ArgosError::Conflict(_))
                || matches!(&err, ArgosError::InjectedCrash(point) if point == "before-journal")
            {
                *meta = rollback;
                self.delete_blocks_locked(meta, &new_blocks_for_cleanup);
            }
            return Err(err);
        }
        self.delete_blocks_locked(meta, &old_blocks);
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn rewrite_inode_data_from_image_locked(
        &self,
        meta: &mut Metadata,
        ino: InodeId,
        data: &[u8],
        changed_start: usize,
        changed_end: usize,
        logical_write_bytes: u64,
        action: &str,
        details: serde_json::Value,
    ) -> Result<()> {
        let rollback = meta.clone();
        let stripe_raw_size = meta
            .config
            .chunk_size
            .checked_mul(meta.config.k)
            .ok_or_else(|| ArgosError::Invalid("stripe size overflow".to_string()))?;
        if stripe_raw_size == 0 {
            return Err(ArgosError::Invalid(
                "stripe size must be positive".to_string(),
            ));
        }
        let (old_size, storage_class, boot_critical, old_blocks) = {
            let inode = meta
                .inodes
                .get(&ino)
                .ok_or_else(|| ArgosError::NotFound(format!("inode {ino}")))?;
            if inode.kind != NodeKind::File {
                return Err(ArgosError::Unsupported(
                    "range updates require a regular file".to_string(),
                ));
            }
            (
                usize::try_from(inode.size)
                    .map_err(|_| ArgosError::Invalid("inode size is too large".to_string()))?,
                inode.storage_class,
                inode.boot_critical,
                inode.blocks.clone(),
            )
        };
        let new_size = data.len();
        let first_changed = changed_start.min(new_size.max(old_size));
        let affected_start = (first_changed / stripe_raw_size) * stripe_raw_size;
        let mut affected_end = changed_end.max(changed_start).min(new_size);
        if new_size != old_size {
            affected_end = new_size;
        } else if affected_end > affected_start {
            affected_end = affected_end.div_ceil(stripe_raw_size) * stripe_raw_size;
            affected_end = affected_end.min(new_size);
        }
        if affected_end < affected_start {
            affected_end = affected_start;
        }
        let preserve_suffix = new_size == old_size;
        let mut merged = Vec::new();
        let mut replaced = Vec::new();
        for block in old_blocks {
            let block_start = block.raw_offset;
            let block_end = block.raw_offset.saturating_add(block.raw_size as u64);
            if block_end <= affected_start as u64
                || (preserve_suffix && block_start >= affected_end as u64)
            {
                merged.push(block);
            } else {
                replaced.push(block);
            }
        }
        let mut written_blocks = Vec::new();
        if affected_start < affected_end {
            let new_blocks = self.encode_data_locked(
                meta,
                &data[affected_start..affected_end],
                affected_start as u64,
                storage_class,
                boot_critical,
                &BTreeSet::new(),
            )?;
            written_blocks = new_blocks.clone();
            merged.extend(new_blocks);
        }
        merged.sort_by_key(|block| block.raw_offset);
        let now = now_f64();
        let inode = meta.inodes.get_mut(&ino).unwrap();
        inode.blocks = merged;
        inode.size = new_size as u64;
        inode.write_count = inode.write_count.saturating_add(1);
        inode.write_bytes = inode.write_bytes.saturating_add(logical_write_bytes);
        inode.last_written_at = now;
        inode.workload_score = inode.workload_score * 0.90 + 2.0;
        inode.mtime = now;
        inode.ctime = now;
        self.account_blocks_locked(meta, &replaced, false);
        if let Err(err) = self.commit_locked(meta, action, details) {
            if matches!(&err, ArgosError::Conflict(_))
                || matches!(&err, ArgosError::InjectedCrash(point) if point == "before-journal")
            {
                *meta = rollback;
                self.delete_blocks_locked(meta, &written_blocks);
            }
            return Err(err);
        }
        self.delete_blocks_locked(meta, &replaced);
        Ok(())
    }

    fn decode_inode_data_locked(
        &self,
        meta: &mut Metadata,
        inode: &Inode,
    ) -> Result<(Vec<u8>, Vec<String>)> {
        let mut out = Vec::new();
        let mut damaged = Vec::new();
        let decrypt_key = if inode.blocks.iter().any(|block| block.encrypted) {
            Some(self.encryption_key_locked(meta)?)
        } else {
            None
        };
        for block in &inode.blocks {
            let cache_key = format!("{}:{}:{}", meta.uuid, block.stripe_id, block.raw_sha256);
            if block.encrypted {
                self.cache.remove(&cache_key);
            } else if let Some(raw) = self.cache.get(&cache_key, Some(&block.raw_sha256)) {
                out.extend(raw);
                continue;
            }
            let mut shards: Vec<Option<Vec<u8>>> = vec![None; self.rs.total()];
            for shard in &block.shards {
                let Some(disk) = meta.disks.get(&shard.disk_id) else {
                    damaged.push(format!("{}:missing-disk", shard.disk_id));
                    continue;
                };
                if matches!(
                    disk.status,
                    DiskStatus::Failed | DiskStatus::Offline | DiskStatus::Removed
                ) {
                    damaged.push(format!("{}:unavailable", shard.disk_id));
                    continue;
                }
                let path = self.shard_path_locked(meta, &shard.disk_id, &shard.relpath);
                let start = std::time::Instant::now();
                match advanced_io::read_all(
                    &path,
                    shard.size,
                    meta.config.io_mode,
                    meta.config.zero_copy,
                ) {
                    Ok(data) => {
                        self.update_read_latency_locked(
                            meta,
                            &shard.disk_id,
                            data.len() as u64,
                            start.elapsed().as_secs_f64(),
                        );
                        if data.len() == shard.size && sha256_hex(&data) == shard.sha256 {
                            shards[shard.slot] = Some(data);
                        } else {
                            damaged.push(format!("{}:checksum:{}", shard.disk_id, shard.slot));
                        }
                    }
                    Err(_) => {
                        self.update_read_latency_locked(
                            meta,
                            &shard.disk_id,
                            0,
                            start.elapsed().as_secs_f64(),
                        );
                        damaged.push(format!("{}:missing:{}", shard.disk_id, shard.slot));
                    }
                }
            }
            let present = shards.iter().filter(|shard| shard.is_some()).count();
            if present < meta.config.k {
                return Err(ArgosError::UnrecoverableStripe {
                    stripe_id: block.stripe_id.clone(),
                    reason: format!("only {present} shards available, need {}", meta.config.k),
                });
            }
            let reconstructed = self.rs.reconstruct(shards)?;
            let compressed: Vec<u8> = reconstructed
                .iter()
                .take(meta.config.k)
                .flat_map(|shard| shard.iter().copied())
                .take(block.compressed_size)
                .collect();
            let compressed = if block.encrypted {
                let nonce = hex::decode(&block.nonce_hex).map_err(|err| {
                    ArgosError::Invalid(format!("invalid encrypted block nonce: {err}"))
                })?;
                let key = decrypt_key.as_ref().ok_or_else(|| {
                    ArgosError::PermissionDenied("missing ArgosFS encryption key".to_string())
                })?;
                crypto::decrypt_with_key(
                    key,
                    &nonce,
                    &compressed,
                    &encryption_aad(&meta.uuid, &block.stripe_id),
                )?
            } else {
                compressed
            };
            let raw = decompress(&compressed, block.codec)?;
            if raw.len() != block.raw_size || sha256_hex(&raw) != block.raw_sha256 {
                return Err(ArgosError::UnrecoverableStripe {
                    stripe_id: block.stripe_id.clone(),
                    reason: "raw checksum mismatch".to_string(),
                });
            }
            if !block.encrypted {
                self.cache.put(&cache_key, &raw)?;
            }
            out.extend(raw);
        }
        let logical_size = usize::try_from(inode.size)
            .map_err(|_| ArgosError::Invalid("inode logical size is too large".to_string()))?;
        out.truncate(logical_size);
        Ok((out, damaged))
    }

    fn encode_data_locked(
        &self,
        meta: &mut Metadata,
        data: &[u8],
        base_offset: u64,
        storage_class: StorageTier,
        boot_critical: bool,
        exclude_disks: &BTreeSet<String>,
    ) -> Result<Vec<FileBlock>> {
        let mut blocks = Vec::new();
        let stripe_raw_size = meta
            .config
            .chunk_size
            .checked_mul(meta.config.k)
            .ok_or_else(|| ArgosError::Invalid("stripe size overflow".to_string()))?;
        if stripe_raw_size == 0 {
            return Err(ArgosError::Invalid(
                "stripe size must be positive".to_string(),
            ));
        }
        if data.is_empty() {
            return Ok(blocks);
        }
        let encrypt_key = if meta.encryption.enabled {
            Some(self.encryption_key_locked(meta)?)
        } else {
            None
        };
        for (index, raw) in data.chunks(stripe_raw_size).enumerate() {
            let stripe_id = format!("s{:016x}", meta.next_stripe);
            meta.next_stripe = meta
                .next_stripe
                .checked_add(1)
                .ok_or_else(|| ArgosError::Invalid("stripe id overflow".to_string()))?;
            let compressed = compress(raw, meta.config.compression, meta.config.compression_level)?;
            let (payload, encrypted, nonce_hex) = if let Some(key) = encrypt_key.as_ref() {
                let (nonce, ciphertext) = crypto::encrypt_with_key(
                    key,
                    &compressed,
                    &encryption_aad(&meta.uuid, &stripe_id),
                )?;
                (ciphertext, true, hex::encode(nonce))
            } else {
                (compressed, false, String::new())
            };
            let shard_size = payload.len().max(1).div_ceil(meta.config.k);
            let mut padded = payload.clone();
            let padded_len = shard_size
                .checked_mul(meta.config.k)
                .ok_or_else(|| ArgosError::Invalid("encoded shard size overflow".to_string()))?;
            padded.resize(padded_len, 0);
            let data_shards = padded
                .chunks(shard_size)
                .map(|chunk| chunk.to_vec())
                .collect::<Vec<_>>();
            let encoded = self.rs.encode(&data_shards)?;
            let placements = self.choose_disks_locked(
                meta,
                PlacementRequest {
                    key: &stripe_id,
                    count: self.rs.total(),
                    storage_class,
                    boot_critical,
                    exclude_disks,
                    required_bytes: shard_size as u64,
                },
            )?;
            let mut shards = Vec::new();
            for (slot, shard_data) in encoded.iter().enumerate() {
                match self.write_shard_locked(meta, &placements[slot], &stripe_id, slot, shard_data)
                {
                    Ok(shard) => shards.push(shard),
                    Err(err) => {
                        for shard in &shards {
                            if let Some(path) = self.shard_path_if_disk_exists_locked(
                                meta,
                                &shard.disk_id,
                                &shard.relpath,
                            ) {
                                let _ = fs::remove_file(path);
                            }
                        }
                        for shard in &shards {
                            if let Some(disk) = meta.disks.get_mut(&shard.disk_id) {
                                disk.used_bytes = disk.used_bytes.saturating_sub(shard.size as u64);
                            }
                        }
                        return Err(err);
                    }
                }
            }
            let raw_offset = index
                .checked_mul(stripe_raw_size)
                .and_then(|offset| u64::try_from(offset).ok())
                .and_then(|offset| base_offset.checked_add(offset))
                .ok_or_else(|| ArgosError::Invalid("raw block offset overflow".to_string()))?;
            blocks.push(FileBlock {
                stripe_id,
                raw_offset,
                raw_size: raw.len(),
                raw_sha256: sha256_hex(raw),
                codec: meta.config.compression,
                encrypted,
                nonce_hex,
                compressed_size: payload.len(),
                shard_size,
                shards,
                storage_class,
            });
        }
        Ok(blocks)
    }

    fn write_shard_locked(
        &self,
        meta: &mut Metadata,
        disk_id: &str,
        stripe_id: &str,
        slot: usize,
        data: &[u8],
    ) -> Result<Shard> {
        let subdir = &stripe_id[stripe_id.len().saturating_sub(2)..];
        let relpath = PathBuf::from(format!("shards/{subdir}/{stripe_id}.{slot:03}.blk"));
        let path = self.shard_path_locked(meta, disk_id, &relpath);
        if let Some(parent) = path.parent() {
            ensure_dir(parent)?;
        }
        self.ensure_disk_capacity_locked(meta, disk_id, data.len() as u64)?;
        let start = std::time::Instant::now();
        advanced_io::write_all(&path, data, meta.config.io_mode)?;
        if let Some(parent) = path.parent() {
            sync_directory(parent);
            if let Some(grandparent) = parent.parent() {
                sync_directory(grandparent);
            }
        }
        if let Some(disk) = meta.disks.get_mut(disk_id) {
            disk.used_bytes = disk.used_bytes.saturating_add(data.len() as u64);
        }
        self.update_write_latency_locked(
            meta,
            disk_id,
            data.len() as u64,
            start.elapsed().as_secs_f64(),
        );
        Ok(Shard {
            slot,
            disk_id: disk_id.to_string(),
            relpath,
            sha256: sha256_hex(data),
            size: data.len(),
        })
    }

    fn choose_disks_locked(
        &self,
        meta: &Metadata,
        request: PlacementRequest<'_>,
    ) -> Result<Vec<String>> {
        let mut scored = Vec::new();
        let local_numa = meta
            .config
            .numa_aware
            .then(advanced_io::current_numa_node)
            .flatten();
        for (disk_id, disk) in &meta.disks {
            if request.exclude_disks.contains(disk_id) || disk.status != DiskStatus::Online {
                continue;
            }
            let disk_path = relative_or_absolute(&self.root, &disk.path);
            if !disk_path.join("shards").exists() {
                continue;
            }
            if !self.disk_has_capacity(meta, disk_id, disk, request.required_bytes) {
                continue;
            }
            let tier_bonus = match (request.storage_class, disk.tier) {
                (StorageTier::Hot, StorageTier::Hot) => 2.5,
                (StorageTier::Hot, StorageTier::Cold) => 0.45,
                (StorageTier::Cold, StorageTier::Cold) => 2.2,
                (StorageTier::Cold, StorageTier::Hot) => 0.55,
                _ => 1.0,
            };
            let u = stable_u01(&[&meta.uuid, request.key, disk_id]);
            let latency_penalty = 1.0
                + ((disk.read_latency_ewma_ms + disk.write_latency_ewma_ms) / 2.0 / 20.0).min(4.0);
            let mut score = (-u.ln() * latency_penalty) / (disk.weight.max(0.01) * tier_bonus);
            if let (Some(local), Some(remote)) = (local_numa, disk.numa_node) {
                if local == remote {
                    score *= 0.90;
                } else {
                    score *= 1.10;
                }
            }
            if disk.capacity_bytes > 0 {
                let used = self.effective_used_bytes_locked(meta, disk);
                let capacity = self.effective_capacity_bytes_locked(meta, disk);
                if capacity > 0 {
                    score += (used as f64 / capacity as f64).min(2.0);
                }
            }
            if request.boot_critical && disk.tier == StorageTier::Cold {
                score *= 1.35;
            }
            scored.push((score, disk_id.clone()));
        }
        if scored.len() < request.count {
            return Err(ArgosError::NotEnoughDisks {
                need: request.count,
                have: scored.len(),
            });
        }
        scored.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap_or(std::cmp::Ordering::Equal));

        let mut selected = Vec::new();
        let mut domains = BTreeSet::new();
        let mut reserved_by_capacity_group = BTreeMap::<String, u64>::new();

        let capacity_group = |disk: &Disk| -> String {
            if disk.capacity_source == CapacitySource::AutoProbe {
                if let Some(fs_id) = disk.backing_fs_id.as_deref() {
                    return format!("fs:{fs_id}");
                }
            }
            format!("disk:{}", disk.id)
        };

        let can_reserve = |reservations: &BTreeMap<String, u64>, disk: &Disk| -> bool {
            let capacity = self.effective_capacity_bytes_locked(meta, disk);
            if capacity == 0 {
                return true;
            }
            let used = self.effective_used_bytes_locked(meta, disk);
            let reserved = reservations
                .get(&capacity_group(disk))
                .copied()
                .unwrap_or(0);
            used.saturating_add(reserved)
                .saturating_add(request.required_bytes)
                <= capacity
        };

        let reserve = |reservations: &mut BTreeMap<String, u64>, disk: &Disk| {
            let capacity = self.effective_capacity_bytes_locked(meta, disk);
            if capacity != 0 {
                let group = capacity_group(disk);
                *reservations.entry(group).or_default() = reservations
                    .get(&capacity_group(disk))
                    .copied()
                    .unwrap_or(0)
                    .saturating_add(request.required_bytes);
            }
        };

        for (_, id) in &scored {
            let Some(disk) = meta.disks.get(id) else {
                continue;
            };
            if !can_reserve(&reserved_by_capacity_group, disk) {
                continue;
            }
            let domain = disk.failure_domain.as_str();
            if domains.insert(domain.to_string()) {
                selected.push(id.clone());
                reserve(&mut reserved_by_capacity_group, disk);
                if selected.len() == request.count {
                    return Ok(selected);
                }
            }
        }

        for (_, id) in scored {
            if selected.contains(&id) {
                continue;
            }
            let Some(disk) = meta.disks.get(&id) else {
                continue;
            };
            if !can_reserve(&reserved_by_capacity_group, disk) {
                continue;
            }
            selected.push(id);
            reserve(&mut reserved_by_capacity_group, disk);
            if selected.len() == request.count {
                return Ok(selected);
            }
        }

        Err(ArgosError::NotEnoughDisks {
            need: request.count,
            have: selected.len(),
        })
    }

    fn disk_has_capacity(
        &self,
        meta: &Metadata,
        _disk_id: &str,
        disk: &Disk,
        required_bytes: u64,
    ) -> bool {
        let capacity = self.effective_capacity_bytes_locked(meta, disk);
        if capacity == 0 {
            return true;
        }
        let used = self.effective_used_bytes_locked(meta, disk);
        used.saturating_add(required_bytes) <= capacity
    }

    fn ensure_disk_capacity_locked(
        &self,
        meta: &Metadata,
        disk_id: &str,
        required_bytes: u64,
    ) -> Result<()> {
        let disk = meta
            .disks
            .get(disk_id)
            .ok_or_else(|| ArgosError::NotFound(disk_id.to_string()))?;
        let capacity = self.effective_capacity_bytes_locked(meta, disk);
        if capacity == 0 {
            return Ok(());
        }
        let used = self.effective_used_bytes_locked(meta, disk);
        if used.saturating_add(required_bytes) > capacity {
            return Err(ArgosError::DiskFull {
                disk_id: disk_id.to_string(),
                required: required_bytes,
                available: capacity.saturating_sub(used),
            });
        }
        Ok(())
    }

    fn update_read_latency_locked(
        &self,
        meta: &mut Metadata,
        disk_id: &str,
        bytes: u64,
        seconds: f64,
    ) {
        if let Some(disk) = meta.disks.get_mut(disk_id) {
            update_latency_ewma(
                &mut disk.read_latency_ewma_ms,
                &mut disk.observed_read_mib_s,
                seconds,
                bytes,
            );
            disk.io_samples = disk.io_samples.saturating_add(1);
            disk.health.latency_ms = ((disk.read_latency_ewma_ms + disk.write_latency_ewma_ms)
                / 2.0)
                .max(disk.health.latency_ms);
        }
    }

    fn update_write_latency_locked(
        &self,
        meta: &mut Metadata,
        disk_id: &str,
        bytes: u64,
        seconds: f64,
    ) {
        if let Some(disk) = meta.disks.get_mut(disk_id) {
            update_latency_ewma(
                &mut disk.write_latency_ewma_ms,
                &mut disk.observed_write_mib_s,
                seconds,
                bytes,
            );
            disk.io_samples = disk.io_samples.saturating_add(1);
            disk.health.latency_ms = ((disk.read_latency_ewma_ms + disk.write_latency_ewma_ms)
                / 2.0)
                .max(disk.health.latency_ms);
        }
    }

    fn delete_blocks_locked(&self, meta: &Metadata, blocks: &[FileBlock]) {
        for block in blocks {
            self.cache.remove(&format!(
                "{}:{}:{}",
                meta.uuid, block.stripe_id, block.raw_sha256
            ));
            for shard in &block.shards {
                if let Some(path) =
                    self.shard_path_if_disk_exists_locked(meta, &shard.disk_id, &shard.relpath)
                {
                    let _ = fs::remove_file(path);
                }
            }
        }
    }

    fn account_blocks_locked(&self, meta: &mut Metadata, blocks: &[FileBlock], add: bool) {
        for shard in blocks.iter().flat_map(|block| block.shards.iter()) {
            if let Some(disk) = meta.disks.get_mut(&shard.disk_id) {
                if add {
                    disk.used_bytes = disk.used_bytes.saturating_add(shard.size as u64);
                } else {
                    disk.used_bytes = disk.used_bytes.saturating_sub(shard.size as u64);
                }
            }
        }
    }

    fn effective_capacity_bytes_locked(&self, meta: &Metadata, disk: &Disk) -> u64 {
        if disk.capacity_source == CapacitySource::UserOverride {
            return disk.capacity_bytes;
        }
        let Some(fs_id) = disk.backing_fs_id.as_deref() else {
            return disk.capacity_bytes;
        };
        meta.disks
            .values()
            .filter(|candidate| {
                candidate.capacity_source == CapacitySource::AutoProbe
                    && candidate.backing_fs_id.as_deref() == Some(fs_id)
                    && candidate.status == DiskStatus::Online
            })
            .map(|candidate| candidate.capacity_bytes)
            .max()
            .unwrap_or(disk.capacity_bytes)
    }

    fn effective_used_bytes_locked(&self, meta: &Metadata, disk: &Disk) -> u64 {
        if disk.capacity_source == CapacitySource::UserOverride {
            return disk.used_bytes;
        }
        let Some(fs_id) = disk.backing_fs_id.as_deref() else {
            return disk.used_bytes;
        };
        meta.disks
            .values()
            .filter(|candidate| {
                candidate.capacity_source == CapacitySource::AutoProbe
                    && candidate.backing_fs_id.as_deref() == Some(fs_id)
            })
            .map(|candidate| candidate.used_bytes)
            .sum()
    }

    fn referenced_shards(&self) -> BTreeSet<(String, PathBuf)> {
        let meta = self.meta.lock();
        let mut refs = BTreeSet::new();
        for inode in meta.inodes.values() {
            for block in &inode.blocks {
                for shard in &block.shards {
                    refs.insert((shard.disk_id.clone(), shard.relpath.clone()));
                }
            }
        }
        refs
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
            let next = *inode
                .entries
                .get(part)
                .ok_or_else(|| ArgosError::NotFound(clean.clone()))?;
            let child = meta
                .inodes
                .get(&next)
                .ok_or_else(|| ArgosError::NotFound(format!("inode {next}")))?;
            let final_component = idx + 1 == parts.len();
            if child.kind == NodeKind::Symlink && (follow_final || !final_component) {
                let target = child.target.clone().unwrap_or_default();
                let rest = parts[idx + 1..].join("/");
                let new_path = if target.starts_with('/') {
                    if rest.is_empty() {
                        target
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

    fn commit_locked(
        &self,
        meta: &mut Metadata,
        action: &str,
        details: serde_json::Value,
    ) -> Result<()> {
        let previous_meta_hash = if meta.integrity.meta_hash.is_empty() {
            journal::canonical_metadata_hash(meta)?
        } else {
            meta.integrity.meta_hash.clone()
        };
        let previous_txid = meta.txid;
        let previous_updated_at = meta.updated_at;
        let previous_integrity = meta.integrity.clone();
        meta.txid += 1;
        meta.updated_at = now_f64();
        let result = journal::append_transaction_checked(
            &self.root,
            meta,
            Some(previous_txid),
            action,
            json!({"txid": meta.txid, "previous_meta_hash": previous_meta_hash, "details": details}),
        );
        let rollback_commit = match &result {
            Err(ArgosError::Conflict(_)) => true,
            Err(ArgosError::InjectedCrash(point)) if point == "before-journal" => true,
            _ => false,
        };
        if rollback_commit {
            meta.txid = previous_txid;
            meta.updated_at = previous_updated_at;
            meta.integrity = previous_integrity;
        }
        result
    }

    fn journal_locked(
        &self,
        meta: &Metadata,
        action: &str,
        details: serde_json::Value,
    ) -> Result<()> {
        journal::append_event(&self.root, meta, action, details)
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AutopilotDrainDecision {
    Observe,
    Cooldown,
    Drain,
}

fn autopilot_due(last_at: f64, interval_sec: u64, now: f64) -> bool {
    interval_sec != u64::MAX && (last_at <= 0.0 || now - last_at >= interval_sec as f64)
}

fn update_autopilot_risk_memory(state: &mut AutopilotState, report: &HealthReport, now: f64) {
    for disk in &report.disks {
        let disk_state = state.disks.entry(disk.id.clone()).or_default();
        if disk.predicted_failure {
            disk_state.risk_streak = disk_state.risk_streak.saturating_add(1);
            disk_state.healthy_streak = 0;
        } else {
            disk_state.healthy_streak = disk_state.healthy_streak.saturating_add(1);
            if disk_state.healthy_streak >= 2 {
                disk_state.risk_streak = 0;
                disk_state.next_action_after = disk_state.next_action_after.min(now);
            }
        }
        disk_state.last_risk_score = disk.risk_score;
        disk_state.last_predicted_failure = disk.predicted_failure;
    }
}

fn autopilot_drain_decision(
    disk: &HealthDiskReport,
    state: &AutopilotDiskState,
    now: f64,
    config: &AutopilotConfig,
) -> AutopilotDrainDecision {
    if now < state.next_action_after {
        return AutopilotDrainDecision::Cooldown;
    }
    let critical = disk.risk_score >= config.critical_risk_score || disk.health.io_errors >= 40;
    let confirmed = state.risk_streak >= config.risk_confirmations;
    if critical || confirmed {
        AutopilotDrainDecision::Drain
    } else {
        AutopilotDrainDecision::Observe
    }
}

fn autopilot_rebalance_skew(report: &HealthReport) -> f64 {
    let mut min_ratio = f64::INFINITY;
    let mut max_ratio = 0.0f64;
    let mut min_used = u64::MAX;
    let mut max_used = 0u64;
    let mut total_used = 0u64;
    let mut count = 0usize;
    for disk in report
        .disks
        .iter()
        .filter(|disk| disk.status == DiskStatus::Online)
    {
        let ratio = if disk.capacity_bytes > 0 {
            disk.used_bytes as f64 / disk.capacity_bytes as f64
        } else {
            disk.used_bytes as f64
        };
        min_ratio = min_ratio.min(ratio);
        max_ratio = max_ratio.max(ratio);
        min_used = min_used.min(disk.used_bytes);
        max_used = max_used.max(disk.used_bytes);
        total_used = total_used.saturating_add(disk.used_bytes);
        count += 1;
    }
    if count < 2 || !min_ratio.is_finite() {
        0.0
    } else {
        let capacity_ratio_skew = max_ratio - min_ratio;
        let avg_used = total_used as f64 / count as f64;
        let relative_used_skew = if avg_used > 0.0 {
            (max_used.saturating_sub(min_used) as f64 / avg_used).min(1.0)
        } else {
            0.0
        };
        capacity_ratio_skew.max(relative_used_skew)
    }
}

fn adaptive_autopilot_budget(base: usize, stats: Option<&AutopilotActionStats>) -> usize {
    if base == 0 {
        return 0;
    }
    let multiplier = match stats.map(|stats| stats.utility_ewma) {
        Some(utility) if utility > 3.0 => 2.0,
        Some(utility) if utility < -0.5 => 0.5,
        _ => 1.0,
    };
    ((base as f64 * multiplier).round() as usize).clamp(1, base.saturating_mul(4).max(1))
}

fn latency_throttled_budget(base: usize, report: &HealthReport, target_ms: f64) -> usize {
    if base <= 1 || target_ms <= 0.0 {
        return base;
    }
    let max_latency = report
        .disks
        .iter()
        .filter(|disk| disk.status == DiskStatus::Online)
        .map(|disk| disk.read_latency_ewma_ms.max(disk.write_latency_ewma_ms))
        .fold(0.0_f64, f64::max);
    if max_latency > target_ms * 2.0 {
        1
    } else if max_latency > target_ms {
        (base / 2).max(1)
    } else {
        base
    }
}

fn adaptive_autopilot_mode(state: &AutopilotState) -> &'static str {
    let failures: u64 = state
        .action_stats
        .values()
        .map(|stats| stats.failures)
        .sum();
    let successes: u64 = state
        .action_stats
        .values()
        .map(|stats| stats.successes)
        .sum();
    if failures > successes && failures >= 2 {
        "reduced"
    } else {
        "normal"
    }
}

fn record_autopilot_action(
    state: &mut AutopilotState,
    action: &str,
    success: bool,
    utility: f64,
    rewritten_files: u64,
    repaired_files: u64,
) {
    let stats = state.action_stats.entry(action.to_string()).or_default();
    stats.runs = stats.runs.saturating_add(1);
    if success {
        stats.successes = stats.successes.saturating_add(1);
    } else {
        stats.failures = stats.failures.saturating_add(1);
    }
    stats.rewritten_files = stats.rewritten_files.saturating_add(rewritten_files);
    stats.repaired_files = stats.repaired_files.saturating_add(repaired_files);
    stats.utility_ewma = if stats.runs == 1 {
        utility
    } else {
        stats.utility_ewma * 0.85 + utility * 0.15
    };
}

fn entry_name_from_os(name: &OsStr) -> Result<String> {
    let bytes = name.as_bytes();
    validate_entry_name_bytes(bytes)?;
    if let Some(name) = name.to_str() {
        validate_entry_name(name)?;
        if name.starts_with(NON_UTF8_NAME_PREFIX) || name.starts_with(ESCAPED_UTF8_NAME_PREFIX) {
            return Ok(format!("{ESCAPED_UTF8_NAME_PREFIX}{}", hex::encode(bytes)));
        }
        return Ok(name.to_string());
    }
    Ok(format!("{NON_UTF8_NAME_PREFIX}{}", hex::encode(bytes)))
}

fn validate_entry_name(name: &str) -> Result<()> {
    if name.is_empty() || name == "." || name == ".." {
        return Err(ArgosError::Invalid(format!("invalid entry name: {name:?}")));
    }
    if name.contains('/') || name.contains('\0') {
        return Err(ArgosError::Invalid(format!("invalid entry name: {name:?}")));
    }
    Ok(())
}

fn validate_entry_name_bytes(name: &[u8]) -> Result<()> {
    if name.is_empty() || name == b"." || name == b".." {
        return Err(ArgosError::Invalid("invalid entry name bytes".to_string()));
    }
    if name.iter().any(|byte| *byte == b'/' || *byte == 0) {
        return Err(ArgosError::Invalid("invalid entry name bytes".to_string()));
    }
    Ok(())
}

fn decode_entry_name_bytes(name: &str) -> Vec<u8> {
    for prefix in [
        ESCAPED_UTF8_NAME_PREFIX,
        NON_UTF8_NAME_PREFIX,
        LEGACY_NON_UTF8_NAME_PREFIX,
    ] {
        if let Some(encoded) = name.strip_prefix(prefix) {
            return hex::decode(encoded).unwrap_or_else(|_| name.as_bytes().to_vec());
        }
    }
    name.as_bytes().to_vec()
}

fn display_entry_name(bytes: &[u8]) -> String {
    String::from_utf8(bytes.to_vec()).unwrap_or_else(|_| String::from_utf8_lossy(bytes).to_string())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum XattrNamespace {
    User,
    Trusted,
    Security,
    System,
    ArgosSystem,
}

fn xattr_namespace(name: &str) -> Result<XattrNamespace> {
    if name.is_empty() || name.as_bytes().contains(&0) {
        return Err(ArgosError::Invalid(format!("invalid xattr name: {name:?}")));
    }
    if name.starts_with("user.") {
        Ok(XattrNamespace::User)
    } else if name.starts_with("trusted.") {
        Ok(XattrNamespace::Trusted)
    } else if name.starts_with("security.") {
        Ok(XattrNamespace::Security)
    } else if name.starts_with("system.argosfs.") {
        Ok(XattrNamespace::ArgosSystem)
    } else if name.starts_with("system.") {
        Ok(XattrNamespace::System)
    } else {
        Err(ArgosError::Invalid(format!(
            "xattr {name:?} must use a Linux namespace prefix"
        )))
    }
}

fn validate_xattr_write(name: &str) -> Result<()> {
    if is_known_system_xattr(name) {
        return Ok(());
    }
    match xattr_namespace(name)? {
        XattrNamespace::User => Ok(()),
        XattrNamespace::Trusted | XattrNamespace::Security => Err(ArgosError::PermissionDenied(
            format!("xattr namespace is protected: {name}"),
        )),
        XattrNamespace::System | XattrNamespace::ArgosSystem => Err(ArgosError::Unsupported(
            format!("unsupported system xattr: {name}"),
        )),
    }
}

fn validate_xattr_read(name: &str) -> Result<()> {
    if is_known_system_xattr(name) {
        return Ok(());
    }
    match xattr_namespace(name)? {
        XattrNamespace::User => Ok(()),
        XattrNamespace::Trusted | XattrNamespace::Security => Err(ArgosError::PermissionDenied(
            format!("xattr namespace is protected: {name}"),
        )),
        XattrNamespace::System | XattrNamespace::ArgosSystem => Err(ArgosError::Unsupported(
            format!("unsupported system xattr: {name}"),
        )),
    }
}

fn is_known_system_xattr(name: &str) -> bool {
    matches!(
        name,
        acl::POSIX_ACL_ACCESS_XATTR
            | acl::POSIX_ACL_DEFAULT_XATTR
            | acl::ARGOS_POSIX_ACL_ACCESS_XATTR
            | acl::ARGOS_POSIX_ACL_DEFAULT_XATTR
            | acl::NFS4_ACL_XATTR
            | BOOT_CRITICAL_XATTR
    )
}

fn boot_critical_name(name: &str) -> bool {
    matches!(
        name,
        "boot" | "etc" | "bin" | "sbin" | "lib" | "lib64" | "usr" | "init"
    )
}

fn canonical_or_self(path: &Path) -> PathBuf {
    fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}

fn sync_directory(path: &Path) {
    if let Ok(dir) = fs::File::open(path) {
        let _ = dir.sync_all();
    }
}

fn recompute_disk_usage_from_metadata(meta: &mut Metadata) {
    let mut referenced_usage = BTreeMap::<String, u64>::new();
    for inode in meta.inodes.values() {
        for block in &inode.blocks {
            for shard in &block.shards {
                *referenced_usage.entry(shard.disk_id.clone()).or_default() += shard.size as u64;
            }
        }
    }
    for (disk_id, disk) in meta.disks.iter_mut() {
        disk.used_bytes = referenced_usage.get(disk_id).copied().unwrap_or(0);
    }
}

fn encryption_aad(volume_uuid: &str, stripe_id: &str) -> Vec<u8> {
    format!("{volume_uuid}:{stripe_id}").into_bytes()
}

fn current_uid() -> u32 {
    unsafe { libc::geteuid() }
}

fn current_gid() -> u32 {
    unsafe { libc::getegid() }
}

fn update_latency_ewma(ewma_ms: &mut f64, throughput_mib_s: &mut f64, seconds: f64, bytes: u64) {
    let sample_ms = (seconds.max(0.000_001)) * 1000.0;
    if *ewma_ms <= 0.0 {
        *ewma_ms = sample_ms;
    } else {
        *ewma_ms = *ewma_ms * 0.80 + sample_ms * 0.20;
    }
    if bytes > 0 {
        let sample_mib_s = bytes as f64 / (1024.0 * 1024.0) / seconds.max(0.000_001);
        if *throughput_mib_s <= 0.0 {
            *throughput_mib_s = sample_mib_s;
        } else {
            *throughput_mib_s = *throughput_mib_s * 0.80 + sample_mib_s * 0.20;
        }
    }
}
