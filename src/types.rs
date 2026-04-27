use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;

pub const FORMAT_VERSION: &str = "argosfs-rust-v1";
pub type InodeId = u64;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Compression {
    None,
    Lz4,
    Zstd,
}

impl Compression {
    pub fn as_str(self) -> &'static str {
        match self {
            Compression::None => "none",
            Compression::Lz4 => "lz4",
            Compression::Zstd => "zstd",
        }
    }
}

impl std::str::FromStr for Compression {
    type Err = String;

    fn from_str(value: &str) -> std::result::Result<Self, Self::Err> {
        match value.to_ascii_lowercase().as_str() {
            "none" => Ok(Self::None),
            "lz4" => Ok(Self::Lz4),
            "zstd" => Ok(Self::Zstd),
            other => Err(format!("unknown compression codec: {other}")),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum StorageTier {
    Hot,
    Warm,
    Cold,
}

impl Default for StorageTier {
    fn default() -> Self {
        Self::Warm
    }
}

impl std::str::FromStr for StorageTier {
    type Err = String;

    fn from_str(value: &str) -> std::result::Result<Self, Self::Err> {
        match value.to_ascii_lowercase().as_str() {
            "hot" => Ok(Self::Hot),
            "warm" => Ok(Self::Warm),
            "cold" => Ok(Self::Cold),
            other => Err(format!("unknown tier: {other}")),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum DiskStatus {
    Online,
    Degraded,
    Draining,
    Failed,
    Offline,
    Removed,
}

impl Default for DiskStatus {
    fn default() -> Self {
        Self::Online
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum DiskClass {
    Hdd,
    Ssd,
    Nvme,
    #[default]
    Unknown,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum IoMode {
    #[default]
    Buffered,
    Direct,
    IoUring,
}

impl std::str::FromStr for IoMode {
    type Err = String;

    fn from_str(value: &str) -> std::result::Result<Self, Self::Err> {
        match value.to_ascii_lowercase().as_str() {
            "buffered" => Ok(Self::Buffered),
            "direct" => Ok(Self::Direct),
            "io-uring" | "iouring" => Ok(Self::IoUring),
            other => Err(format!("unknown I/O mode: {other}")),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PosixAclTag {
    UserObj,
    User,
    GroupObj,
    Group,
    Mask,
    Other,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PosixAclEntry {
    pub tag: PosixAclTag,
    pub id: Option<u32>,
    pub perms: u16,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct PosixAcl {
    pub entries: Vec<PosixAclEntry>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Nfs4AceType {
    Allow,
    Deny,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Nfs4Ace {
    pub ace_type: Nfs4AceType,
    pub principal: String,
    pub flags: Vec<String>,
    pub permissions: Vec<String>,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Nfs4Acl {
    pub entries: Vec<Nfs4Ace>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct EncryptionConfig {
    pub enabled: bool,
    pub kdf: String,
    pub salt_hex: String,
    pub key_check_nonce_hex: String,
    pub key_check_ciphertext_hex: String,
}

impl Default for EncryptionConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            kdf: "argon2id".to_string(),
            salt_hex: String::new(),
            key_check_nonce_hex: String::new(),
            key_check_ciphertext_hex: String::new(),
        }
    }
}

impl std::str::FromStr for DiskStatus {
    type Err = String;

    fn from_str(value: &str) -> std::result::Result<Self, Self::Err> {
        match value.to_ascii_lowercase().as_str() {
            "online" => Ok(Self::Online),
            "degraded" => Ok(Self::Degraded),
            "draining" => Ok(Self::Draining),
            "failed" => Ok(Self::Failed),
            "offline" => Ok(Self::Offline),
            "removed" => Ok(Self::Removed),
            other => Err(format!("unknown disk status: {other}")),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct VolumeConfig {
    pub k: usize,
    pub m: usize,
    pub chunk_size: usize,
    pub compression: Compression,
    pub compression_level: i32,
    pub l2_cache_bytes: u64,
    pub fsname: String,
    #[serde(default)]
    pub io_mode: IoMode,
    #[serde(default)]
    pub direct_io: bool,
    #[serde(default)]
    pub zero_copy: bool,
    #[serde(default)]
    pub numa_aware: bool,
}

impl Default for VolumeConfig {
    fn default() -> Self {
        Self {
            k: 4,
            m: 2,
            chunk_size: 256 * 1024,
            compression: Compression::Zstd,
            compression_level: 3,
            l2_cache_bytes: 4 * 1024 * 1024 * 1024,
            fsname: "argosfs".to_string(),
            io_mode: IoMode::Buffered,
            direct_io: false,
            zero_copy: true,
            numa_aware: true,
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct HealthCounters {
    pub reallocated_sectors: u64,
    pub pending_sectors: u64,
    pub crc_errors: u64,
    pub io_errors: u64,
    pub latency_ms: f64,
    pub wear_percent: f64,
    pub temperature_c: f64,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct DiskProbe {
    pub class: DiskClass,
    pub backing_device: Option<PathBuf>,
    pub sysfs_block: Option<String>,
    pub rotational: Option<bool>,
    pub numa_node: Option<i32>,
    pub capacity_bytes: u64,
    pub available_bytes: u64,
    pub measured_read_mib_s: f64,
    pub measured_write_mib_s: f64,
    pub measured_read_latency_ms: f64,
    pub measured_write_latency_ms: f64,
    pub recommended_weight: f64,
    pub recommended_tier: StorageTier,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Disk {
    pub id: String,
    pub path: PathBuf,
    pub tier: StorageTier,
    pub weight: f64,
    pub status: DiskStatus,
    pub capacity_bytes: u64,
    pub health: HealthCounters,
    #[serde(default)]
    pub class: DiskClass,
    #[serde(default)]
    pub backing_device: Option<PathBuf>,
    #[serde(default)]
    pub sysfs_block: Option<String>,
    #[serde(default)]
    pub rotational: Option<bool>,
    #[serde(default)]
    pub numa_node: Option<i32>,
    #[serde(default)]
    pub read_latency_ewma_ms: f64,
    #[serde(default)]
    pub write_latency_ewma_ms: f64,
    #[serde(default)]
    pub observed_read_mib_s: f64,
    #[serde(default)]
    pub observed_write_mib_s: f64,
    #[serde(default)]
    pub io_samples: u64,
    #[serde(default)]
    pub last_probe: DiskProbe,
    pub created_at: f64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Shard {
    pub slot: usize,
    pub disk_id: String,
    pub relpath: PathBuf,
    pub sha256: String,
    pub size: usize,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FileBlock {
    pub stripe_id: String,
    pub raw_offset: u64,
    pub raw_size: usize,
    pub raw_sha256: String,
    pub codec: Compression,
    #[serde(default)]
    pub encrypted: bool,
    #[serde(default)]
    pub nonce_hex: String,
    pub compressed_size: usize,
    pub shard_size: usize,
    pub shards: Vec<Shard>,
    pub storage_class: StorageTier,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum NodeKind {
    File,
    Directory,
    Symlink,
    Special,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Inode {
    pub id: InodeId,
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
    pub entries: BTreeMap<String, InodeId>,
    pub target: Option<String>,
    pub blocks: Vec<FileBlock>,
    pub xattrs: BTreeMap<String, String>,
    #[serde(default)]
    pub posix_acl_access: Option<PosixAcl>,
    #[serde(default)]
    pub posix_acl_default: Option<PosixAcl>,
    #[serde(default)]
    pub nfs4_acl: Option<Nfs4Acl>,
    pub access_count: u64,
    pub write_count: u64,
    pub read_bytes: u64,
    pub write_bytes: u64,
    pub storage_class: StorageTier,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Metadata {
    pub format: String,
    pub uuid: String,
    pub created_at: f64,
    pub updated_at: f64,
    pub txid: u64,
    pub next_inode: InodeId,
    pub next_stripe: u64,
    pub config: VolumeConfig,
    #[serde(default)]
    pub encryption: EncryptionConfig,
    pub disks: BTreeMap<String, Disk>,
    pub inodes: BTreeMap<InodeId, Inode>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct HealthDiskReport {
    pub id: String,
    pub status: DiskStatus,
    pub tier: StorageTier,
    pub weight: f64,
    pub used_bytes: u64,
    pub capacity_bytes: u64,
    pub available_bytes: u64,
    pub class: DiskClass,
    pub backing_device: Option<PathBuf>,
    pub rotational: Option<bool>,
    pub numa_node: Option<i32>,
    pub read_latency_ewma_ms: f64,
    pub write_latency_ewma_ms: f64,
    pub observed_read_mib_s: f64,
    pub observed_write_mib_s: f64,
    pub risk_score: f64,
    pub predicted_failure: bool,
    pub reasons: Vec<String>,
    pub health: HealthCounters,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct HealthReport {
    pub volume_uuid: String,
    pub txid: u64,
    pub files: usize,
    pub directories: usize,
    pub symlinks: usize,
    pub specials: usize,
    pub disks: Vec<HealthDiskReport>,
    pub cache: BTreeMap<String, serde_json::Value>,
    pub io_mode: IoMode,
    pub encryption_enabled: bool,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct FsckReport {
    pub files_checked: u64,
    pub directories_checked: u64,
    pub damaged_files: u64,
    pub repaired_files: u64,
    pub unrecoverable_files: u64,
    pub missing_shards: u64,
    pub checksum_errors: u64,
    pub orphan_shards: u64,
    pub removed_orphans: u64,
    pub errors: Vec<String>,
}
