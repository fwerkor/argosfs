use crate::error::{ArgosError, Result};
use crate::types::*;
use crate::util::sha256_hex;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub const PAGED_METADATA_VERSION: u32 = 1;
pub const DEFAULT_DIRECTORY_ENTRIES_PER_PAGE: usize = 128;
pub const DEFAULT_XATTRS_PER_PAGE: usize = 64;
pub const DEFAULT_FILE_BLOCKS_PER_PAGE: usize = 32;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PagedMetadataOptions {
    pub directory_entries_per_page: usize,
    pub xattrs_per_page: usize,
    pub file_blocks_per_page: usize,
}

impl Default for PagedMetadataOptions {
    fn default() -> Self {
        Self {
            directory_entries_per_page: DEFAULT_DIRECTORY_ENTRIES_PER_PAGE,
            xattrs_per_page: DEFAULT_XATTRS_PER_PAGE,
            file_blocks_per_page: DEFAULT_FILE_BLOCKS_PER_PAGE,
        }
    }
}

impl PagedMetadataOptions {
    pub fn validate(self) -> Result<()> {
        if self.directory_entries_per_page == 0 {
            return Err(ArgosError::Invalid(
                "directory page size must be positive".to_string(),
            ));
        }
        if self.xattrs_per_page == 0 {
            return Err(ArgosError::Invalid(
                "xattr page size must be positive".to_string(),
            ));
        }
        if self.file_blocks_per_page == 0 {
            return Err(ArgosError::Invalid(
                "file block page size must be positive".to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum MetadataPageKind {
    Header,
    Disk,
    Inode,
    Directory,
    Xattr,
    ShardIndex,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct MetadataPageKey {
    pub kind: MetadataPageKind,
    pub owner: String,
    pub page: u64,
}

impl MetadataPageKey {
    pub fn header() -> Self {
        Self {
            kind: MetadataPageKind::Header,
            owner: String::new(),
            page: 0,
        }
    }

    pub fn disk(disk_id: &str) -> Self {
        Self {
            kind: MetadataPageKind::Disk,
            owner: disk_id.to_string(),
            page: 0,
        }
    }

    pub fn inode(ino: InodeId) -> Self {
        Self {
            kind: MetadataPageKind::Inode,
            owner: ino.to_string(),
            page: 0,
        }
    }

    pub fn directory(ino: InodeId, page: u64) -> Self {
        Self {
            kind: MetadataPageKind::Directory,
            owner: ino.to_string(),
            page,
        }
    }

    pub fn xattr(ino: InodeId, page: u64) -> Self {
        Self {
            kind: MetadataPageKind::Xattr,
            owner: ino.to_string(),
            page,
        }
    }

    pub fn shard_index(ino: InodeId, page: u64) -> Self {
        Self {
            kind: MetadataPageKind::ShardIndex,
            owner: ino.to_string(),
            page,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct MetadataHeaderPage {
    pub format: String,
    pub uuid: String,
    #[serde(default)]
    pub backend: BackendKind,
    #[serde(default)]
    pub raw_pool: RawPoolMetadata,
    pub created_at: f64,
    pub updated_at: f64,
    pub txid: u64,
    pub next_inode: InodeId,
    pub next_stripe: u64,
    pub config: VolumeConfig,
    #[serde(default)]
    pub layouts: BTreeMap<String, LayoutConfig>,
    #[serde(default)]
    pub current_write_layout: String,
    #[serde(default)]
    pub reshape: Option<ReshapeState>,
    #[serde(default)]
    pub encryption: EncryptionConfig,
    #[serde(default)]
    pub integrity: MetadataIntegrity,
}

impl From<&Metadata> for MetadataHeaderPage {
    fn from(meta: &Metadata) -> Self {
        Self {
            format: meta.format.clone(),
            uuid: meta.uuid.clone(),
            backend: meta.backend,
            raw_pool: meta.raw_pool.clone(),
            created_at: meta.created_at,
            updated_at: meta.updated_at,
            txid: meta.txid,
            next_inode: meta.next_inode,
            next_stripe: meta.next_stripe,
            config: meta.config.clone(),
            layouts: meta.layouts.clone(),
            current_write_layout: meta.current_write_layout.clone(),
            reshape: meta.reshape.clone(),
            encryption: meta.encryption.clone(),
            integrity: meta.integrity.clone(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct InodeCorePage {
    pub id: InodeId,
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
    pub target: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inline_data: Option<Vec<u8>>,
    #[serde(default)]
    pub inline_sha256: String,
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
    #[serde(default)]
    pub boot_critical: bool,
    #[serde(default)]
    pub workload_score: f64,
    #[serde(default)]
    pub last_accessed_at: f64,
    #[serde(default)]
    pub last_written_at: f64,
}

impl From<&Inode> for InodeCorePage {
    fn from(inode: &Inode) -> Self {
        Self {
            id: inode.id,
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
            target: inode.target.clone(),
            inline_data: inode.inline_data.clone(),
            inline_sha256: inode.inline_sha256.clone(),
            posix_acl_access: inode.posix_acl_access.clone(),
            posix_acl_default: inode.posix_acl_default.clone(),
            nfs4_acl: inode.nfs4_acl.clone(),
            access_count: inode.access_count,
            write_count: inode.write_count,
            read_bytes: inode.read_bytes,
            write_bytes: inode.write_bytes,
            storage_class: inode.storage_class,
            boot_critical: inode.boot_critical,
            workload_score: inode.workload_score,
            last_accessed_at: inode.last_accessed_at,
            last_written_at: inode.last_written_at,
        }
    }
}

impl InodeCorePage {
    fn into_inode(
        self,
        entries: BTreeMap<String, InodeId>,
        xattrs: BTreeMap<String, String>,
        blocks: Vec<FileBlock>,
    ) -> Inode {
        Inode {
            id: self.id,
            kind: self.kind,
            mode: self.mode,
            uid: self.uid,
            gid: self.gid,
            nlink: self.nlink,
            size: self.size,
            rdev: self.rdev,
            atime: self.atime,
            mtime: self.mtime,
            ctime: self.ctime,
            entries,
            target: self.target,
            inline_data: self.inline_data,
            inline_sha256: self.inline_sha256,
            blocks,
            xattrs,
            posix_acl_access: self.posix_acl_access,
            posix_acl_default: self.posix_acl_default,
            nfs4_acl: self.nfs4_acl,
            access_count: self.access_count,
            write_count: self.write_count,
            read_bytes: self.read_bytes,
            write_bytes: self.write_bytes,
            storage_class: self.storage_class,
            boot_critical: self.boot_critical,
            workload_score: self.workload_score,
            last_accessed_at: self.last_accessed_at,
            last_written_at: self.last_written_at,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DirectoryPage {
    pub inode: InodeId,
    pub first_name: Option<String>,
    pub entries: Vec<(String, InodeId)>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct XattrPage {
    pub inode: InodeId,
    pub first_name: Option<String>,
    pub xattrs: Vec<(String, String)>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ShardIndexPage {
    pub inode: InodeId,
    pub first_block: u64,
    pub blocks: Vec<FileBlock>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum MetadataPageBody {
    Header(MetadataHeaderPage),
    Disk(Disk),
    Inode(InodeCorePage),
    Directory(DirectoryPage),
    Xattr(XattrPage),
    ShardIndex(ShardIndexPage),
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct MetadataPage {
    pub key: MetadataPageKey,
    pub txid: u64,
    pub body_hash: String,
    pub body: MetadataPageBody,
}

impl MetadataPage {
    pub fn new(key: MetadataPageKey, txid: u64, body: MetadataPageBody) -> Result<Self> {
        validate_page_key(&key, &body)?;
        let body_hash = hash_page_body(&body)?;
        Ok(Self {
            key,
            txid,
            body_hash,
            body,
        })
    }

    pub fn verify_hash(&self) -> Result<()> {
        let computed = hash_page_body(&self.body)?;
        if computed != self.body_hash {
            return Err(ArgosError::CorruptedMetadata(format!(
                "metadata page hash mismatch: owner={} kind={:?} page={} stored={} computed={computed}",
                self.key.owner, self.key.kind, self.key.page, self.body_hash
            )));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PagedMetadata {
    pub version: u32,
    pub options: PagedMetadataOptions,
    pub pages: BTreeMap<MetadataPageKey, MetadataPage>,
}

impl PagedMetadata {
    pub fn from_metadata(meta: &Metadata) -> Result<Self> {
        Self::from_metadata_with_options(meta, PagedMetadataOptions::default())
    }

    pub fn from_metadata_with_options(
        meta: &Metadata,
        options: PagedMetadataOptions,
    ) -> Result<Self> {
        options.validate()?;
        let mut store = Self {
            version: PAGED_METADATA_VERSION,
            options,
            pages: BTreeMap::new(),
        };
        store.put_page(MetadataPage::new(
            MetadataPageKey::header(),
            meta.txid,
            MetadataPageBody::Header(MetadataHeaderPage::from(meta)),
        )?)?;
        for disk in meta.disks.values() {
            store.put_page(MetadataPage::new(
                MetadataPageKey::disk(&disk.id),
                meta.txid,
                MetadataPageBody::Disk(disk.clone()),
            )?)?;
        }
        for inode in meta.inodes.values() {
            store.put_page(MetadataPage::new(
                MetadataPageKey::inode(inode.id),
                meta.txid,
                MetadataPageBody::Inode(InodeCorePage::from(inode)),
            )?)?;
            for (page, chunk) in chunked_pairs(
                inode
                    .entries
                    .iter()
                    .map(|(name, ino)| (name.clone(), *ino))
                    .collect(),
                options.directory_entries_per_page,
            )
            .into_iter()
            .enumerate()
            {
                store.put_page(MetadataPage::new(
                    MetadataPageKey::directory(inode.id, page as u64),
                    meta.txid,
                    MetadataPageBody::Directory(DirectoryPage {
                        inode: inode.id,
                        first_name: chunk.first().map(|(name, _)| name.clone()),
                        entries: chunk,
                    }),
                )?)?;
            }
            for (page, chunk) in chunked_pairs(
                inode
                    .xattrs
                    .iter()
                    .map(|(name, value)| (name.clone(), value.clone()))
                    .collect(),
                options.xattrs_per_page,
            )
            .into_iter()
            .enumerate()
            {
                store.put_page(MetadataPage::new(
                    MetadataPageKey::xattr(inode.id, page as u64),
                    meta.txid,
                    MetadataPageBody::Xattr(XattrPage {
                        inode: inode.id,
                        first_name: chunk.first().map(|(name, _)| name.clone()),
                        xattrs: chunk,
                    }),
                )?)?;
            }
            for (page, chunk) in inode
                .blocks
                .chunks(options.file_blocks_per_page)
                .enumerate()
            {
                store.put_page(MetadataPage::new(
                    MetadataPageKey::shard_index(inode.id, page as u64),
                    meta.txid,
                    MetadataPageBody::ShardIndex(ShardIndexPage {
                        inode: inode.id,
                        first_block: page as u64 * options.file_blocks_per_page as u64,
                        blocks: chunk.to_vec(),
                    }),
                )?)?;
            }
        }
        Ok(store)
    }

    pub fn to_metadata(&self) -> Result<Metadata> {
        if self.version != PAGED_METADATA_VERSION {
            return Err(ArgosError::Invalid(format!(
                "unsupported paged metadata version {}",
                self.version
            )));
        }
        self.options.validate()?;
        for page in self.pages.values() {
            page.verify_hash()?;
        }
        let header = match &self
            .pages
            .get(&MetadataPageKey::header())
            .ok_or_else(|| {
                ArgosError::CorruptedMetadata("paged metadata is missing header".to_string())
            })?
            .body
        {
            MetadataPageBody::Header(header) => header.clone(),
            _ => {
                return Err(ArgosError::CorruptedMetadata(
                    "paged metadata header key contains non-header body".to_string(),
                ))
            }
        };

        let mut disks = BTreeMap::new();
        let mut cores = BTreeMap::new();
        let mut entries: BTreeMap<InodeId, BTreeMap<String, InodeId>> = BTreeMap::new();
        let mut xattrs: BTreeMap<InodeId, BTreeMap<String, String>> = BTreeMap::new();
        let mut blocks: BTreeMap<InodeId, Vec<FileBlock>> = BTreeMap::new();
        let mut seen_page_keys = BTreeSet::new();
        for page in self.pages.values() {
            validate_page_key(&page.key, &page.body)?;
            if !seen_page_keys.insert(page.key.clone()) {
                return Err(ArgosError::CorruptedMetadata(format!(
                    "duplicate metadata page key: {:?}",
                    page.key
                )));
            }
            match &page.body {
                MetadataPageBody::Header(_) => {}
                MetadataPageBody::Disk(disk) => {
                    disks.insert(disk.id.clone(), disk.clone());
                }
                MetadataPageBody::Inode(core) => {
                    cores.insert(core.id, core.clone());
                }
                MetadataPageBody::Directory(directory) => {
                    let inode_entries = entries.entry(directory.inode).or_default();
                    for (name, ino) in &directory.entries {
                        inode_entries.insert(name.clone(), *ino);
                    }
                }
                MetadataPageBody::Xattr(xattr_page) => {
                    let inode_xattrs = xattrs.entry(xattr_page.inode).or_default();
                    for (name, value) in &xattr_page.xattrs {
                        inode_xattrs.insert(name.clone(), value.clone());
                    }
                }
                MetadataPageBody::ShardIndex(shard_index) => {
                    blocks
                        .entry(shard_index.inode)
                        .or_default()
                        .extend(shard_index.blocks.clone());
                }
            }
        }
        let mut inodes = BTreeMap::new();
        for (ino, core) in cores {
            inodes.insert(
                ino,
                core.into_inode(
                    entries.remove(&ino).unwrap_or_default(),
                    xattrs.remove(&ino).unwrap_or_default(),
                    blocks.remove(&ino).unwrap_or_default(),
                ),
            );
        }
        if let Some(ino) = entries.keys().next() {
            return Err(ArgosError::CorruptedMetadata(format!(
                "directory page references missing inode {ino}"
            )));
        }
        if let Some(ino) = xattrs.keys().next() {
            return Err(ArgosError::CorruptedMetadata(format!(
                "xattr page references missing inode {ino}"
            )));
        }
        if let Some(ino) = blocks.keys().next() {
            return Err(ArgosError::CorruptedMetadata(format!(
                "shard index page references missing inode {ino}"
            )));
        }

        Ok(Metadata {
            format: header.format,
            uuid: header.uuid,
            backend: header.backend,
            raw_pool: header.raw_pool,
            created_at: header.created_at,
            updated_at: header.updated_at,
            txid: header.txid,
            next_inode: header.next_inode,
            next_stripe: header.next_stripe,
            config: header.config,
            layouts: header.layouts,
            current_write_layout: header.current_write_layout,
            reshape: header.reshape,
            encryption: header.encryption,
            integrity: header.integrity,
            disks,
            inodes,
        })
    }

    pub fn put_page(&mut self, page: MetadataPage) -> Result<()> {
        page.verify_hash()?;
        validate_page_key(&page.key, &page.body)?;
        self.pages.insert(page.key.clone(), page);
        Ok(())
    }

    pub fn apply_delta(&mut self, delta: &[MetadataPageDeltaOp]) -> Result<()> {
        for op in delta {
            match op {
                MetadataPageDeltaOp::Put { page } => self.put_page(page.clone())?,
                MetadataPageDeltaOp::Delete { key } => {
                    self.pages.remove(key);
                }
            }
        }
        Ok(())
    }
}

pub trait MetadataStore {
    fn export_metadata(&self) -> Result<Metadata>;
    fn import_metadata(&mut self, metadata: &Metadata) -> Result<()>;
}

impl MetadataStore for PagedMetadata {
    fn export_metadata(&self) -> Result<Metadata> {
        self.to_metadata()
    }

    fn import_metadata(&mut self, metadata: &Metadata) -> Result<()> {
        *self = Self::from_metadata_with_options(metadata, self.options)?;
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "op", rename_all = "kebab-case")]
pub enum MetadataPageDeltaOp {
    Put { page: MetadataPage },
    Delete { key: MetadataPageKey },
}

pub fn metadata_page_delta(
    previous: &PagedMetadata,
    next: &PagedMetadata,
) -> Vec<MetadataPageDeltaOp> {
    let mut delta = Vec::new();
    for key in previous.pages.keys() {
        if !next.pages.contains_key(key) {
            delta.push(MetadataPageDeltaOp::Delete { key: key.clone() });
        }
    }
    for (key, page) in &next.pages {
        let changed = previous
            .pages
            .get(key)
            .map(|previous_page| previous_page.body_hash != page.body_hash)
            .unwrap_or(true);
        if changed {
            delta.push(MetadataPageDeltaOp::Put { page: page.clone() });
        }
    }
    delta
}

fn hash_page_body(body: &MetadataPageBody) -> Result<String> {
    Ok(sha256_hex(&serde_json::to_vec(body)?))
}

fn validate_page_key(key: &MetadataPageKey, body: &MetadataPageBody) -> Result<()> {
    let expected = match body {
        MetadataPageBody::Header(_) => MetadataPageKey::header(),
        MetadataPageBody::Disk(disk) => MetadataPageKey::disk(&disk.id),
        MetadataPageBody::Inode(inode) => MetadataPageKey::inode(inode.id),
        MetadataPageBody::Directory(directory) => {
            MetadataPageKey::directory(directory.inode, key.page)
        }
        MetadataPageBody::Xattr(xattr) => MetadataPageKey::xattr(xattr.inode, key.page),
        MetadataPageBody::ShardIndex(shard_index) => {
            MetadataPageKey::shard_index(shard_index.inode, key.page)
        }
    };
    if *key != expected {
        return Err(ArgosError::CorruptedMetadata(format!(
            "metadata page key/body mismatch: key={key:?} expected={expected:?}"
        )));
    }
    Ok(())
}

fn chunked_pairs<T: Clone>(items: Vec<T>, page_size: usize) -> Vec<Vec<T>> {
    items
        .chunks(page_size)
        .map(|chunk| chunk.to_vec())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn paged_metadata_round_trips_json_metadata() {
        let metadata = sample_metadata();
        let paged = PagedMetadata::from_metadata_with_options(
            &metadata,
            PagedMetadataOptions {
                directory_entries_per_page: 1,
                xattrs_per_page: 1,
                file_blocks_per_page: 1,
            },
        )
        .unwrap();

        assert_eq!(
            paged
                .pages
                .keys()
                .filter(|key| key.kind == MetadataPageKind::Directory)
                .count(),
            2
        );
        assert_eq!(
            paged
                .pages
                .keys()
                .filter(|key| key.kind == MetadataPageKind::Xattr)
                .count(),
            2
        );
        assert_eq!(
            paged
                .pages
                .keys()
                .filter(|key| key.kind == MetadataPageKind::ShardIndex)
                .count(),
            2
        );

        let round_trip = paged.to_metadata().unwrap();
        assert_eq!(
            serde_json::to_value(&round_trip).unwrap(),
            serde_json::to_value(&metadata).unwrap()
        );
    }

    #[test]
    fn page_delta_replays_changed_pages() {
        let before = sample_metadata();
        let mut after = before.clone();
        after.txid += 1;
        after.updated_at += 1.0;
        after.inodes.get_mut(&2).unwrap().xattrs.insert(
            "user.extra".to_string(),
            "only this xattr page should change".to_string(),
        );
        let options = PagedMetadataOptions {
            directory_entries_per_page: 1,
            xattrs_per_page: 1,
            file_blocks_per_page: 1,
        };
        let mut replayed = PagedMetadata::from_metadata_with_options(&before, options).unwrap();
        let next = PagedMetadata::from_metadata_with_options(&after, options).unwrap();
        let delta = metadata_page_delta(&replayed, &next);

        assert!(
            delta
                .iter()
                .any(|op| matches!(op, MetadataPageDeltaOp::Put { page } if page.key.kind == MetadataPageKind::Xattr))
        );
        replayed.apply_delta(&delta).unwrap();

        assert_eq!(
            serde_json::to_value(replayed.to_metadata().unwrap()).unwrap(),
            serde_json::to_value(after).unwrap()
        );
    }

    fn sample_metadata() -> Metadata {
        let created_at = 1_700_000_000.0;
        let mut disks = BTreeMap::new();
        disks.insert(
            "disk-0000".to_string(),
            Disk {
                id: "disk-0000".to_string(),
                path: PathBuf::from("/tmp/argosfs-disk-0000"),
                tier: StorageTier::Warm,
                weight: 1.0,
                status: DiskStatus::Online,
                capacity_bytes: 1024 * 1024 * 1024,
                capacity_source: CapacitySource::UserOverride,
                used_bytes: 4096,
                health: HealthCounters::default(),
                class: DiskClass::Ssd,
                backing_device: None,
                backing_fs_id: None,
                failure_domain: "fd-a".to_string(),
                sysfs_block: None,
                rotational: Some(false),
                numa_node: Some(0),
                read_latency_ewma_ms: 0.2,
                write_latency_ewma_ms: 0.4,
                observed_read_mib_s: 100.0,
                observed_write_mib_s: 80.0,
                io_samples: 4,
                last_probe: DiskProbe::default(),
                created_at,
            },
        );

        let block = FileBlock {
            layout_id: "layout-0000".to_string(),
            stripe_id: "stripe-0001".to_string(),
            raw_offset: 0,
            raw_size: 5,
            raw_sha256: "raw-hash".to_string(),
            codec: Compression::None,
            encrypted: false,
            nonce_hex: String::new(),
            compressed_size: 5,
            shard_size: 5,
            shards: vec![Shard {
                slot: 0,
                disk_id: "disk-0000".to_string(),
                location: Some(ShardLocation::HostPath {
                    disk_id: "disk-0000".to_string(),
                    relpath: PathBuf::from("shards/stripe-0001.0"),
                }),
                relpath: PathBuf::from("shards/stripe-0001.0"),
                sha256: "shard-hash".to_string(),
                checksum_block_size: 256 * 1024,
                subblock_sha256: vec!["subblock-hash".to_string()],
                size: 5,
            }],
            storage_class: StorageTier::Warm,
        };

        let mut root_entries = BTreeMap::new();
        root_entries.insert("alpha".to_string(), 2);
        root_entries.insert("beta".to_string(), 3);
        let root = Inode {
            id: 1,
            kind: NodeKind::Directory,
            mode: libc::S_IFDIR | 0o755,
            uid: 1000,
            gid: 1000,
            nlink: 2,
            size: 0,
            rdev: 0,
            atime: created_at,
            mtime: created_at,
            ctime: created_at,
            entries: root_entries,
            target: None,
            inline_data: None,
            inline_sha256: String::new(),
            blocks: Vec::new(),
            xattrs: BTreeMap::new(),
            posix_acl_access: None,
            posix_acl_default: None,
            nfs4_acl: None,
            access_count: 7,
            write_count: 1,
            read_bytes: 10,
            write_bytes: 0,
            storage_class: StorageTier::Warm,
            boot_critical: true,
            workload_score: 0.8,
            last_accessed_at: created_at,
            last_written_at: created_at,
        };

        let mut xattrs = BTreeMap::new();
        xattrs.insert("user.alpha".to_string(), "one".to_string());
        xattrs.insert("user.beta".to_string(), "two".to_string());
        let file = Inode {
            id: 2,
            kind: NodeKind::File,
            mode: libc::S_IFREG | 0o644,
            uid: 1000,
            gid: 1000,
            nlink: 1,
            size: 10,
            rdev: 0,
            atime: created_at,
            mtime: created_at + 1.0,
            ctime: created_at + 1.0,
            entries: BTreeMap::new(),
            target: None,
            inline_data: Some(b"hello".to_vec()),
            inline_sha256: "inline-hash".to_string(),
            blocks: vec![
                block.clone(),
                FileBlock {
                    stripe_id: "stripe-0002".to_string(),
                    raw_offset: 5,
                    ..block
                },
            ],
            xattrs,
            posix_acl_access: Some(PosixAcl::default()),
            posix_acl_default: None,
            nfs4_acl: Some(Nfs4Acl::default()),
            access_count: 3,
            write_count: 2,
            read_bytes: 64,
            write_bytes: 10,
            storage_class: StorageTier::Hot,
            boot_critical: false,
            workload_score: 2.0,
            last_accessed_at: created_at + 2.0,
            last_written_at: created_at + 2.0,
        };
        let symlink = Inode {
            id: 3,
            kind: NodeKind::Symlink,
            mode: libc::S_IFLNK | 0o777,
            uid: 1000,
            gid: 1000,
            nlink: 1,
            size: 5,
            rdev: 0,
            atime: created_at,
            mtime: created_at,
            ctime: created_at,
            entries: BTreeMap::new(),
            target: Some("alpha".to_string()),
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
            boot_critical: false,
            workload_score: 0.0,
            last_accessed_at: created_at,
            last_written_at: created_at,
        };

        let mut inodes = BTreeMap::new();
        inodes.insert(1, root);
        inodes.insert(2, file);
        inodes.insert(3, symlink);
        let mut layouts = BTreeMap::new();
        layouts.insert(
            "layout-0000".to_string(),
            LayoutConfig {
                id: "layout-0000".to_string(),
                k: 1,
                m: 0,
                chunk_size: 256 * 1024,
                created_txid: 0,
                sealed: false,
            },
        );

        Metadata {
            format: FORMAT_VERSION.to_string(),
            uuid: "metadata-store-test".to_string(),
            backend: BackendKind::Host,
            raw_pool: RawPoolMetadata::default(),
            created_at,
            updated_at: created_at + 3.0,
            txid: 9,
            next_inode: 4,
            next_stripe: 3,
            config: VolumeConfig {
                k: 1,
                m: 0,
                ..VolumeConfig::default()
            },
            layouts,
            current_write_layout: "layout-0000".to_string(),
            reshape: None,
            encryption: EncryptionConfig::default(),
            integrity: MetadataIntegrity::default(),
            disks,
            inodes,
        }
    }
}
