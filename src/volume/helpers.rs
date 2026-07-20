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
#[path = "helpers_tests.rs"]
mod tests;
