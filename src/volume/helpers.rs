use super::*;
use std::os::unix::fs::PermissionsExt;

pub(super) fn canonical_or_self(path: &Path) -> PathBuf {
    fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}

pub(super) fn harden_host_storage_permissions(root: &Path, meta: &Metadata) -> Result<()> {
    let system = root.join(".argosfs");
    ensure_private_dir(&system)?;
    for directory in ["devices", "snapshots", "cache"] {
        let path = system.join(directory);
        if path.exists() {
            ensure_private_dir(&path)?;
        }
    }
    for file in [
        "journal.jsonl",
        "meta.primary.json",
        "meta.secondary.json",
        "meta.json",
        "tx.lock",
        "autopilot.jsonl",
    ] {
        let path = system.join(file);
        if path.exists() {
            fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
        }
    }
    for disk in meta.disks.values() {
        let disk_root = relative_or_absolute(root, &disk.path);
        if disk_root.exists() {
            ensure_private_dir(&disk_root)?;
            let shards = disk_root.join("shards");
            if shards.exists() {
                ensure_private_dir(&shards)?;
            }
        }
    }
    Ok(())
}

pub(super) fn prepare_loop_images(paths: &[PathBuf], image_size: u64, force: bool) -> Result<()> {
    if paths.is_empty() {
        return Err(ArgosError::Invalid(
            "at least one loop image is required".to_string(),
        ));
    }
    if image_size < raw_format::MIN_DEVICE_BYTES {
        return Err(ArgosError::Invalid(format!(
            "loop image size must be at least {} bytes",
            raw_format::MIN_DEVICE_BYTES
        )));
    }
    for path in paths {
        if path.exists() && !force && fs::metadata(path)?.len() > 0 {
            return Err(ArgosError::AlreadyExists(format!(
                "{} exists and is non-empty; pass --force to overwrite",
                path.display()
            )));
        }
        if let Some(parent) = path.parent() {
            ensure_dir(parent)?;
        }
        let file = fs::OpenOptions::new()
            .create(true)
            .truncate(force)
            .read(true)
            .write(true)
            .open(path)?;
        file.set_len(image_size)?;
        file.sync_all()?;
    }
    Ok(())
}

pub(super) fn block_cache_root(volume_uuid: &str, paths: &[PathBuf]) -> PathBuf {
    if let Some(root) = std::env::var_os("ARGOSFS_BLOCK_CACHE_DIR") {
        return PathBuf::from(root).join(volume_uuid);
    }
    let mut root = paths
        .first()
        .and_then(|path| path.parent())
        .map(Path::to_path_buf)
        .unwrap_or_else(std::env::temp_dir);
    root.push(".argosfs-block-cache");
    root.push(volume_uuid);
    root
}

pub(super) fn root_inode(created_at: f64) -> Inode {
    Inode {
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
    }
}

pub(super) fn sync_directory(path: &Path) {
    if let Ok(dir) = fs::File::open(path) {
        let _ = dir.sync_all();
    }
}

pub(super) fn recompute_disk_usage_from_metadata(meta: &mut Metadata) {
    normalize_metadata_layouts(meta);
    let mut referenced_usage = BTreeMap::<String, u64>::new();
    for inode in meta.inodes.values() {
        for block in &inode.blocks {
            for shard in &block.shards {
                *referenced_usage.entry(shard.disk_id.clone()).or_default() +=
                    shard_accounted_size(shard);
            }
        }
    }
    for (disk_id, disk) in meta.disks.iter_mut() {
        disk.used_bytes = referenced_usage.get(disk_id).copied().unwrap_or(0);
    }
}

pub(super) fn validate_commit_policy(config: &VolumeConfig) -> Result<()> {
    if config.defer_data_flush && !config.defer_metadata_commit {
        return Err(ArgosError::Invalid(
            "defer-data-flush requires defer-metadata-commit".to_string(),
        ));
    }
    if config.defer_metadata_commit && config.deferred_commit_interval_ms == 0 {
        return Err(ArgosError::Invalid(
            "deferred-commit-interval-ms must be positive when metadata commits are deferred"
                .to_string(),
        ));
    }
    if config.defer_metadata_commit && config.deferred_commit_max_transactions == 0 {
        return Err(ArgosError::Invalid(
            "deferred-commit-max-transactions must be positive when metadata commits are deferred"
                .to_string(),
        ));
    }
    Ok(())
}

pub(super) fn commit_previous_snapshot(meta: &Metadata) -> Option<Metadata> {
    if meta.backend != BackendKind::Host && meta.config.defer_metadata_commit {
        None
    } else {
        Some(meta.clone())
    }
}

pub(super) fn normalize_metadata_layouts(meta: &mut Metadata) {
    if !meta.layouts.contains_key(DEFAULT_LAYOUT_ID) {
        meta.layouts.insert(
            DEFAULT_LAYOUT_ID.to_string(),
            LayoutConfig {
                id: DEFAULT_LAYOUT_ID.to_string(),
                k: meta.config.k,
                m: meta.config.m,
                chunk_size: meta.config.chunk_size,
                created_txid: 0,
                sealed: false,
            },
        );
    }
    if meta.current_write_layout.is_empty()
        || !meta.layouts.contains_key(&meta.current_write_layout)
    {
        meta.current_write_layout = DEFAULT_LAYOUT_ID.to_string();
    }
    for inode in meta.inodes.values_mut() {
        for block in &mut inode.blocks {
            if block.layout_id.is_empty() {
                block.layout_id = DEFAULT_LAYOUT_ID.to_string();
            }
        }
    }
}

pub(super) fn block_layout_id(block: &FileBlock) -> &str {
    if block.layout_id.is_empty() {
        DEFAULT_LAYOUT_ID
    } else {
        &block.layout_id
    }
}

pub(super) fn layout_by_id(meta: &Metadata, layout_id: &str) -> Result<LayoutConfig> {
    let id = if layout_id.is_empty() {
        DEFAULT_LAYOUT_ID
    } else {
        layout_id
    };
    meta.layouts
        .get(id)
        .cloned()
        .ok_or_else(|| ArgosError::Invalid(format!("unknown layout {id}")))
}

pub(super) fn current_write_layout(meta: &Metadata) -> Result<LayoutConfig> {
    layout_by_id(meta, &meta.current_write_layout)
}

pub(super) fn find_or_insert_layout_locked(
    meta: &mut Metadata,
    k: usize,
    m: usize,
    chunk_size: usize,
) -> String {
    if let Some((id, _)) = meta
        .layouts
        .iter()
        .find(|(_, layout)| layout.k == k && layout.m == m && layout.chunk_size == chunk_size)
    {
        return id.clone();
    }
    let id = next_layout_id(meta);
    meta.layouts.insert(
        id.clone(),
        LayoutConfig {
            id: id.clone(),
            k,
            m,
            chunk_size,
            created_txid: meta.txid + 1,
            sealed: false,
        },
    );
    id
}

pub(super) fn next_layout_id(meta: &Metadata) -> String {
    let next = meta
        .layouts
        .keys()
        .filter_map(|id| id.strip_prefix("layout-")?.parse::<u64>().ok())
        .max()
        .map(|value| value + 1)
        .unwrap_or(0);
    format!("layout-{next:04}")
}

pub(super) fn checked_layout_total(k: usize, m: usize) -> Result<usize> {
    k.checked_add(m)
        .ok_or_else(|| ArgosError::Invalid("layout shard count overflow".to_string()))
}

pub(super) fn layout_total(layout: &LayoutConfig) -> Result<usize> {
    checked_layout_total(layout.k, layout.m)
}

pub(super) fn max_layout_total(meta: &Metadata) -> Result<usize> {
    let configured = checked_layout_total(meta.config.k, meta.config.m)?;
    meta.layouts
        .values()
        .try_fold(configured, |maximum, layout| {
            Ok(maximum.max(layout_total(layout)?))
        })
}

pub(super) fn layout_stripe_raw_size(layout: &LayoutConfig) -> Result<usize> {
    let stripe_raw_size = layout
        .chunk_size
        .checked_mul(layout.k)
        .ok_or_else(|| ArgosError::Invalid("stripe size overflow".to_string()))?;
    if stripe_raw_size == 0 {
        return Err(ArgosError::Invalid(
            "stripe size must be positive".to_string(),
        ));
    }
    if stripe_raw_size > MAX_IN_MEMORY_IO_BYTES {
        return Err(ArgosError::FileTooLarge(format!(
            "stripe size {stripe_raw_size} exceeds the in-memory safety limit {MAX_IN_MEMORY_IO_BYTES}"
        )));
    }
    Ok(stripe_raw_size)
}

pub(super) fn zeroed_io_buffer(length: usize, context: &str) -> Result<Vec<u8>> {
    if length > MAX_IN_MEMORY_IO_BYTES {
        return Err(ArgosError::FileTooLarge(format!(
            "{context} requires {length} bytes, limit is {MAX_IN_MEMORY_IO_BYTES}"
        )));
    }
    let mut buffer = Vec::new();
    buffer
        .try_reserve_exact(length)
        .map_err(|_| ArgosError::Io(std::io::Error::from_raw_os_error(libc::ENOMEM)))?;
    buffer.resize(length, 0);
    Ok(buffer)
}

pub(super) fn shard_accounted_size(shard: &Shard) -> u64 {
    match shard.location.as_ref() {
        Some(ShardLocation::RawExtent(extent)) => extent.length,
        _ => shard.size as u64,
    }
}

pub(super) fn shard_subblock_hashes(data: &[u8], full_hash: &str) -> Vec<String> {
    if data.is_empty() {
        return Vec::new();
    }
    if data.len() <= SHARD_CHECKSUM_BLOCK_SIZE {
        return vec![full_hash.to_string()];
    }
    data.chunks(SHARD_CHECKSUM_BLOCK_SIZE)
        .map(content_hash_hex)
        .collect()
}

pub(super) fn read_path_range_exact(path: &Path, offset: u64, mut buf: &mut [u8]) -> Result<()> {
    let file = fs::File::open(path)?;
    let mut cursor = offset;
    while !buf.is_empty() {
        let read = file.read_at(buf, cursor)?;
        if read == 0 {
            return Err(ArgosError::Io(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                format!("short read on {} at offset {cursor}", path.display()),
            )));
        }
        cursor = cursor.saturating_add(read as u64);
        let (_, rest) = buf.split_at_mut(read);
        buf = rest;
    }
    Ok(())
}

pub(super) fn inline_payload_for(meta: &Metadata, data: &[u8]) -> Option<(Vec<u8>, String)> {
    if data.is_empty() || data.len() > INLINE_DATA_MAX || meta.encryption.enabled {
        return None;
    }
    let layout = meta.layouts.get(&meta.current_write_layout)?;
    if meta.backend == BackendKind::Host || layout.k != 1 || layout.m != 0 {
        return None;
    }
    Some((data.to_vec(), content_hash_hex(data)))
}

pub(super) fn set_inline_payload(inode: &mut Inode, payload: Option<(Vec<u8>, String)>) {
    if let Some((data, sha256)) = payload {
        inode.inline_data = Some(data);
        inode.inline_sha256 = sha256;
    } else {
        inode.inline_data = None;
        inode.inline_sha256.clear();
    }
}

pub(super) fn decode_inline_data(inode: &Inode) -> Result<Option<Vec<u8>>> {
    let Some(data) = inode.inline_data.as_ref() else {
        return Ok(None);
    };
    if data.len() as u64 != inode.size {
        return Err(ArgosError::Invalid(format!(
            "inline inode {} length {} does not match inode size {}",
            inode.id,
            data.len(),
            inode.size
        )));
    }
    if !content_hash_matches(data, &inode.inline_sha256) {
        return Err(ArgosError::Invalid(format!(
            "inline inode {} checksum mismatch",
            inode.id
        )));
    }
    Ok(Some(data.clone()))
}

pub(super) fn seek_data(inode: &Inode, offset: u64) -> Result<u64> {
    if offset >= inode.size {
        return Err(ArgosError::NoData(format!(
            "SEEK_DATA offset {offset} is beyond inode {} size {}",
            inode.id, inode.size
        )));
    }
    if inode.inline_data.is_some() {
        return Ok(offset);
    }
    let extents = inode_data_extents(inode);
    for (start, end) in extents {
        if offset < start {
            return Ok(start);
        }
        if offset < end {
            return Ok(offset);
        }
    }
    Err(ArgosError::NoData(format!(
        "no data after offset {offset} in inode {}",
        inode.id
    )))
}

pub(super) fn seek_hole(inode: &Inode, offset: u64) -> Result<u64> {
    if offset > inode.size {
        return Err(ArgosError::NoData(format!(
            "SEEK_HOLE offset {offset} is beyond inode {} size {}",
            inode.id, inode.size
        )));
    }
    if offset == inode.size {
        return Ok(offset);
    }
    if inode.inline_data.is_some() {
        return Ok(inode.size);
    }
    let extents = inode_data_extents(inode);
    let mut cursor = offset;
    for (start, end) in extents {
        if cursor < start {
            return Ok(cursor);
        }
        if cursor < end {
            cursor = end;
        }
    }
    Ok(cursor.min(inode.size))
}

pub(super) fn inode_data_extents(inode: &Inode) -> Vec<(u64, u64)> {
    let mut extents = inode
        .blocks
        .iter()
        .filter_map(|block| {
            let start = block.raw_offset.min(inode.size);
            let end = block
                .raw_offset
                .saturating_add(block.raw_size as u64)
                .min(inode.size);
            (end > start).then_some((start, end))
        })
        .collect::<Vec<_>>();
    extents.sort_by_key(|(start, _)| *start);
    let mut merged: Vec<(u64, u64)> = Vec::new();
    for (start, end) in extents {
        if let Some((_, previous_end)) = merged.last_mut() {
            if start <= *previous_end {
                *previous_end = (*previous_end).max(end);
                continue;
            }
        }
        merged.push((start, end));
    }
    merged
}

pub(super) fn encryption_aad(volume_uuid: &str, stripe_id: &str) -> Vec<u8> {
    format!("{volume_uuid}:{stripe_id}").into_bytes()
}

pub(super) fn current_uid() -> u32 {
    unsafe { libc::geteuid() }
}

pub(super) fn current_gid() -> u32 {
    unsafe { libc::getegid() }
}

pub(super) fn update_latency_ewma(
    ewma_ms: &mut f64,
    throughput_mib_s: &mut f64,
    seconds: f64,
    bytes: u64,
) {
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex as StdMutex, OnceLock};
    use tempfile::tempdir;

    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: OnceLock<StdMutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| StdMutex::new(())).lock().unwrap()
    }

    fn metadata() -> Metadata {
        let dir = tempdir().unwrap();
        ArgosFs::create(
            dir.path(),
            VolumeConfig {
                k: 1,
                m: 0,
                chunk_size: 4096,
                ..VolumeConfig::default()
            },
            1,
            false,
        )
        .unwrap()
        .metadata_snapshot()
    }

    fn shard(location: Option<ShardLocation>, size: usize) -> Shard {
        Shard {
            slot: 0,
            disk_id: "disk-0000".to_string(),
            location,
            relpath: PathBuf::from("shard.bin"),
            sha256: String::new(),
            checksum_block_size: 0,
            subblock_sha256: Vec::new(),
            size,
        }
    }

    fn block(offset: u64, size: usize) -> FileBlock {
        FileBlock {
            layout_id: DEFAULT_LAYOUT_ID.to_string(),
            stripe_id: format!("stripe-{offset}"),
            raw_offset: offset,
            raw_size: size,
            raw_sha256: String::new(),
            codec: Compression::None,
            encrypted: false,
            nonce_hex: String::new(),
            compressed_size: size,
            shard_size: size,
            shards: Vec::new(),
            storage_class: StorageTier::Warm,
        }
    }

    #[test]
    fn canonicalization_and_directory_sync_are_best_effort() {
        let dir = tempdir().unwrap();
        let child = dir.path().join("child");
        fs::create_dir(&child).unwrap();
        assert_eq!(canonical_or_self(&child), fs::canonicalize(&child).unwrap());
        let missing = dir.path().join("missing");
        assert_eq!(canonical_or_self(&missing), missing);
        sync_directory(&child);
        sync_directory(&missing);
    }

    #[test]
    fn loop_image_preparation_validates_inputs_and_force_semantics() {
        assert!(matches!(
            prepare_loop_images(&[], raw_format::MIN_DEVICE_BYTES, false),
            Err(ArgosError::Invalid(_))
        ));
        let dir = tempdir().unwrap();
        let path = dir.path().join("nested/image.bin");
        assert!(matches!(
            prepare_loop_images(
                std::slice::from_ref(&path),
                raw_format::MIN_DEVICE_BYTES - 1,
                false
            ),
            Err(ArgosError::Invalid(_))
        ));
        prepare_loop_images(
            std::slice::from_ref(&path),
            raw_format::MIN_DEVICE_BYTES,
            false,
        )
        .unwrap();
        assert_eq!(
            fs::metadata(&path).unwrap().len(),
            raw_format::MIN_DEVICE_BYTES
        );
        assert!(matches!(
            prepare_loop_images(
                std::slice::from_ref(&path),
                raw_format::MIN_DEVICE_BYTES,
                false
            ),
            Err(ArgosError::AlreadyExists(_))
        ));
        fs::write(&path, b"nonempty").unwrap();
        prepare_loop_images(
            std::slice::from_ref(&path),
            raw_format::MIN_DEVICE_BYTES * 2,
            true,
        )
        .unwrap();
        assert_eq!(
            fs::metadata(path).unwrap().len(),
            raw_format::MIN_DEVICE_BYTES * 2
        );
    }

    #[test]
    fn block_cache_root_honors_override_and_path_fallbacks() {
        let _guard = env_lock();
        std::env::remove_var("ARGOSFS_BLOCK_CACHE_DIR");
        let path = PathBuf::from("/tmp/argosfs-device.img");
        assert_eq!(
            block_cache_root("uuid", &[path]),
            PathBuf::from("/tmp/.argosfs-block-cache/uuid")
        );
        assert_eq!(
            block_cache_root("uuid", &[]),
            std::env::temp_dir().join(".argosfs-block-cache/uuid")
        );
        std::env::set_var("ARGOSFS_BLOCK_CACHE_DIR", "/tmp/custom-cache");
        assert_eq!(
            block_cache_root("uuid", &[]),
            PathBuf::from("/tmp/custom-cache/uuid")
        );
        std::env::remove_var("ARGOSFS_BLOCK_CACHE_DIR");
    }

    #[test]
    fn root_inode_uses_current_identity_and_boot_defaults() {
        let inode = root_inode(42.5);
        assert_eq!(inode.id, ROOT_INO);
        assert_eq!(inode.kind, NodeKind::Directory);
        assert_eq!(inode.mode, libc::S_IFDIR | 0o755);
        assert_eq!(inode.uid, current_uid());
        assert_eq!(inode.gid, current_gid());
        assert_eq!(inode.nlink, 2);
        assert!(inode.boot_critical);
        assert_eq!(inode.atime, 42.5);
        assert_eq!(inode.last_written_at, 42.5);
    }

    #[test]
    fn commit_policy_rejects_unsafe_deferred_combinations() {
        let mut config = VolumeConfig {
            defer_data_flush: true,
            ..VolumeConfig::default()
        };
        assert!(validate_commit_policy(&config).is_err());

        config.defer_metadata_commit = true;
        config.deferred_commit_interval_ms = 0;
        assert!(validate_commit_policy(&config).is_err());
        config.deferred_commit_interval_ms = 1;
        config.deferred_commit_max_transactions = 0;
        assert!(validate_commit_policy(&config).is_err());
        config.deferred_commit_max_transactions = 1;
        validate_commit_policy(&config).unwrap();
    }

    #[test]
    fn previous_snapshot_policy_distinguishes_host_and_deferred_block_backends() {
        let mut meta = metadata();
        meta.backend = BackendKind::Host;
        meta.config.defer_metadata_commit = true;
        assert!(commit_previous_snapshot(&meta).is_some());
        meta.backend = BackendKind::LoopBlock;
        assert!(commit_previous_snapshot(&meta).is_none());
        meta.config.defer_metadata_commit = false;
        assert!(commit_previous_snapshot(&meta).is_some());
    }

    #[test]
    fn layout_normalization_and_lookup_repair_legacy_metadata() {
        let mut meta = metadata();
        let file = meta
            .inodes
            .values_mut()
            .find(|inode| inode.kind == NodeKind::Directory)
            .unwrap();
        file.blocks.push(FileBlock {
            layout_id: String::new(),
            ..block(0, 1)
        });
        meta.layouts.clear();
        meta.current_write_layout = "missing".to_string();
        normalize_metadata_layouts(&mut meta);
        assert!(meta.layouts.contains_key(DEFAULT_LAYOUT_ID));
        assert_eq!(meta.current_write_layout, DEFAULT_LAYOUT_ID);
        assert_eq!(
            meta.inodes.values().next().unwrap().blocks[0].layout_id,
            DEFAULT_LAYOUT_ID
        );
        assert_eq!(
            block_layout_id(&FileBlock {
                layout_id: String::new(),
                ..block(0, 1)
            }),
            DEFAULT_LAYOUT_ID
        );
        assert_eq!(block_layout_id(&block(0, 1)), DEFAULT_LAYOUT_ID);
        assert_eq!(layout_by_id(&meta, "").unwrap().id, DEFAULT_LAYOUT_ID);
        assert_eq!(current_write_layout(&meta).unwrap().id, DEFAULT_LAYOUT_ID);
        assert!(layout_by_id(&meta, "unknown").is_err());
    }

    #[test]
    fn layout_insertion_ids_and_size_guards_cover_boundaries() {
        let mut meta = metadata();
        let existing = find_or_insert_layout_locked(&mut meta, 1, 0, 4096);
        assert_eq!(existing, DEFAULT_LAYOUT_ID);
        meta.layouts.insert(
            "layout-0007".to_string(),
            LayoutConfig {
                id: "layout-0007".to_string(),
                k: 2,
                m: 1,
                chunk_size: 8192,
                created_txid: 0,
                sealed: false,
            },
        );
        meta.layouts.insert(
            "layout-bad".to_string(),
            meta.layouts[DEFAULT_LAYOUT_ID].clone(),
        );
        assert_eq!(next_layout_id(&meta), "layout-0008");
        let inserted = find_or_insert_layout_locked(&mut meta, 3, 1, 16384);
        assert_eq!(inserted, "layout-0008");
        assert_eq!(meta.layouts[&inserted].created_txid, meta.txid + 1);
        assert_eq!(checked_layout_total(2, 1).unwrap(), 3);
        assert!(checked_layout_total(usize::MAX, 1).is_err());
        assert_eq!(layout_total(&meta.layouts[&inserted]).unwrap(), 4);
        assert_eq!(max_layout_total(&meta).unwrap(), 4);

        let valid = LayoutConfig {
            id: "valid".to_string(),
            k: 2,
            m: 1,
            chunk_size: 4096,
            created_txid: 0,
            sealed: false,
        };
        assert_eq!(layout_stripe_raw_size(&valid).unwrap(), 8192);
        let zero = LayoutConfig {
            k: 0,
            ..valid.clone()
        };
        assert!(layout_stripe_raw_size(&zero).is_err());
        let overflow = LayoutConfig {
            k: usize::MAX,
            chunk_size: 2,
            ..valid.clone()
        };
        assert!(layout_stripe_raw_size(&overflow).is_err());
        let oversized = LayoutConfig {
            k: 1,
            chunk_size: MAX_IN_MEMORY_IO_BYTES + 1,
            ..valid
        };
        assert!(matches!(
            layout_stripe_raw_size(&oversized),
            Err(ArgosError::FileTooLarge(_))
        ));
    }

    #[test]
    fn zeroed_buffers_and_shard_accounting_cover_raw_and_host_storage() {
        assert_eq!(zeroed_io_buffer(8, "test").unwrap(), vec![0; 8]);
        assert!(matches!(
            zeroed_io_buffer(MAX_IN_MEMORY_IO_BYTES + 1, "test"),
            Err(ArgosError::FileTooLarge(_))
        ));
        assert_eq!(shard_accounted_size(&shard(None, 123)), 123);
        let extent = PhysicalExtent {
            disk_id: "disk-0000".to_string(),
            offset: 4096,
            length: 8192,
            generation: 1,
            flags: 0,
        };
        assert_eq!(
            shard_accounted_size(&shard(Some(ShardLocation::RawExtent(extent)), 123)),
            8192
        );
    }

    #[test]
    fn shard_hashes_handle_empty_single_and_multiple_checksum_blocks() {
        assert!(shard_subblock_hashes(&[], "full").is_empty());
        assert_eq!(shard_subblock_hashes(b"small", "full"), ["full"]);
        let large = vec![7u8; SHARD_CHECKSUM_BLOCK_SIZE + 1];
        let hashes = shard_subblock_hashes(&large, "ignored");
        assert_eq!(hashes.len(), 2);
        assert_eq!(
            hashes[0],
            content_hash_hex(&large[..SHARD_CHECKSUM_BLOCK_SIZE])
        );
        assert_eq!(
            hashes[1],
            content_hash_hex(&large[SHARD_CHECKSUM_BLOCK_SIZE..])
        );
    }

    #[test]
    fn exact_range_reader_reports_success_missing_and_short_reads() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("data.bin");
        fs::write(&path, b"0123456789").unwrap();
        let mut output = [0u8; 4];
        read_path_range_exact(&path, 3, &mut output).unwrap();
        assert_eq!(&output, b"3456");
        assert!(matches!(
            read_path_range_exact(&path, 9, &mut output),
            Err(ArgosError::Io(error)) if error.kind() == std::io::ErrorKind::UnexpectedEof
        ));
        assert!(matches!(
            read_path_range_exact(&dir.path().join("missing"), 0, &mut output),
            Err(ArgosError::Io(_))
        ));
    }

    #[test]
    fn inline_payload_selection_setting_and_validation_cover_all_rejections() {
        let mut meta = metadata();
        meta.backend = BackendKind::LoopBlock;
        let payload = inline_payload_for(&meta, b"small").unwrap();
        assert_eq!(payload.0, b"small");
        assert!(inline_payload_for(&meta, b"").is_none());
        assert!(inline_payload_for(&meta, &vec![0; INLINE_DATA_MAX + 1]).is_none());
        meta.encryption.enabled = true;
        assert!(inline_payload_for(&meta, b"small").is_none());
        meta.encryption.enabled = false;
        meta.backend = BackendKind::Host;
        assert!(inline_payload_for(&meta, b"small").is_none());
        meta.backend = BackendKind::LoopBlock;
        meta.layouts.get_mut(DEFAULT_LAYOUT_ID).unwrap().m = 1;
        assert!(inline_payload_for(&meta, b"small").is_none());
        meta.layouts.clear();
        assert!(inline_payload_for(&meta, b"small").is_none());

        let mut inode = root_inode(0.0);
        inode.kind = NodeKind::File;
        inode.size = 5;
        set_inline_payload(
            &mut inode,
            Some((b"small".to_vec(), content_hash_hex(b"small"))),
        );
        assert_eq!(decode_inline_data(&inode).unwrap(), Some(b"small".to_vec()));
        inode.size = 4;
        assert!(decode_inline_data(&inode).is_err());
        inode.size = 5;
        inode.inline_sha256 = "bad".to_string();
        assert!(decode_inline_data(&inode).is_err());
        set_inline_payload(&mut inode, None);
        assert_eq!(decode_inline_data(&inode).unwrap(), None);
        assert!(inode.inline_sha256.is_empty());
    }

    #[test]
    fn sparse_extent_seek_helpers_cover_inline_holes_merging_and_bounds() {
        let mut inode = root_inode(0.0);
        inode.kind = NodeKind::File;
        inode.size = 100;
        inode.inline_data = Some(vec![0; 100]);
        assert_eq!(seek_data(&inode, 20).unwrap(), 20);
        assert_eq!(seek_hole(&inode, 20).unwrap(), 100);
        assert!(seek_data(&inode, 100).is_err());
        assert_eq!(seek_hole(&inode, 100).unwrap(), 100);
        assert!(seek_hole(&inode, 101).is_err());

        inode.inline_data = None;
        inode.blocks = vec![block(10, 20), block(25, 20), block(70, 40), block(100, 0)];
        assert_eq!(inode_data_extents(&inode), vec![(10, 45), (70, 100)]);
        assert_eq!(seek_data(&inode, 0).unwrap(), 10);
        assert_eq!(seek_data(&inode, 20).unwrap(), 20);
        assert_eq!(seek_data(&inode, 50).unwrap(), 70);
        assert!(seek_data(&inode, 100).is_err());
        assert_eq!(seek_hole(&inode, 0).unwrap(), 0);
        assert_eq!(seek_hole(&inode, 20).unwrap(), 45);
        assert_eq!(seek_hole(&inode, 50).unwrap(), 50);
        assert_eq!(seek_hole(&inode, 80).unwrap(), 100);
    }

    #[test]
    fn utility_helpers_generate_aad_and_update_latency_ewmas() {
        assert_eq!(encryption_aad("volume", "stripe"), b"volume:stripe");
        let mut latency = 0.0;
        let mut throughput = 0.0;
        update_latency_ewma(&mut latency, &mut throughput, 0.5, 1024 * 1024);
        assert_eq!(latency, 500.0);
        assert_eq!(throughput, 2.0);
        update_latency_ewma(&mut latency, &mut throughput, 0.25, 1024 * 1024);
        assert_eq!(latency, 450.0);
        assert!((throughput - 2.4).abs() < 1e-9);
        update_latency_ewma(&mut latency, &mut throughput, 0.0, 0);
        assert!(latency > 0.0);
        assert!((throughput - 2.4).abs() < 1e-9);
    }

    #[test]
    fn recompute_usage_counts_raw_extents_and_normalizes_layouts() {
        let mut meta = metadata();
        let disk_id = meta.disks.keys().next().unwrap().clone();
        let inode = meta.inodes.values_mut().next().unwrap();
        inode.blocks.push(FileBlock {
            layout_id: String::new(),
            shards: vec![
                shard(None, 10),
                shard(
                    Some(ShardLocation::RawExtent(PhysicalExtent {
                        disk_id: disk_id.clone(),
                        offset: 0,
                        length: 20,
                        generation: 1,
                        flags: 0,
                    })),
                    1,
                ),
            ],
            ..block(0, 30)
        });
        for shard in &mut inode.blocks[0].shards {
            shard.disk_id = disk_id.clone();
        }
        meta.disks.get_mut(&disk_id).unwrap().used_bytes = 999;
        recompute_disk_usage_from_metadata(&mut meta);
        assert_eq!(meta.disks[&disk_id].used_bytes, 30);
        assert_eq!(
            meta.inodes.values().next().unwrap().blocks[0].layout_id,
            DEFAULT_LAYOUT_ID
        );
    }

    #[test]
    fn host_storage_permission_hardening_updates_existing_paths() {
        let dir = tempdir().unwrap();
        let mut meta = metadata();
        let system = dir.path().join(".argosfs");
        fs::create_dir_all(system.join("devices")).unwrap();
        fs::create_dir_all(system.join("snapshots")).unwrap();
        fs::create_dir_all(system.join("cache")).unwrap();
        for file in [
            "journal.jsonl",
            "meta.primary.json",
            "meta.secondary.json",
            "meta.json",
            "tx.lock",
            "autopilot.jsonl",
        ] {
            fs::write(system.join(file), b"x").unwrap();
        }
        let disk = meta.disks.values_mut().next().unwrap();
        disk.path = PathBuf::from("disk-root");
        fs::create_dir_all(dir.path().join("disk-root/shards")).unwrap();
        harden_host_storage_permissions(dir.path(), &meta).unwrap();
        use std::os::unix::fs::PermissionsExt as _;
        assert_eq!(
            fs::metadata(&system).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(system.join("journal.jsonl"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert_eq!(
            fs::metadata(dir.path().join("disk-root/shards"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
    }
}
