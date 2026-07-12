use super::*;

impl ArgosFs {
    pub(super) fn replace_inode_data(
        &self,
        ino: InodeId,
        data: &[u8],
        action: &str,
        details: serde_json::Value,
    ) -> Result<()> {
        let inode_lock = self.inode_lock(ino);
        let _inode_guard = inode_lock.lock();
        let mut meta = self.meta.write();
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
    pub(super) fn replace_inode_data_locked(
        &self,
        meta: &mut Metadata,
        ino: InodeId,
        data: &[u8],
        action: &str,
        details: serde_json::Value,
        preserve_mtime: bool,
        exclude_disks: &BTreeSet<String>,
    ) -> Result<()> {
        self.ensure_block_backend_writable_locked(meta)?;
        let rollback = commit_previous_snapshot(meta);
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
        let inline_payload = inline_payload_for(meta, data);
        let new_blocks = if inline_payload.is_some() {
            Vec::new()
        } else {
            self.encode_data_locked(meta, data, 0, storage_class, boot_critical, exclude_disks)?
        };
        let new_blocks_for_cleanup = new_blocks.clone();
        let now = now_f64();
        let inode = meta.inodes.get_mut(&ino).unwrap();
        inode.blocks = new_blocks;
        set_inline_payload(inode, inline_payload);
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
        if let Err(err) = self.commit_locked_with_previous(meta, rollback.as_ref(), action, details)
        {
            if !Self::transaction_error_is_committed(&err) {
                if matches!(err, ArgosError::Conflict(_)) {
                    if meta.backend == BackendKind::Host {
                        self.delete_blocks_locked(meta, &new_blocks_for_cleanup);
                    }
                } else {
                    self.delete_blocks_locked(meta, &new_blocks_for_cleanup);
                    if let Some(rollback) = rollback {
                        *meta = rollback;
                    }
                }
            }
            return Err(err);
        }
        self.delete_blocks_locked(meta, &old_blocks);
        Ok(())
    }

    pub(super) fn range_update_geometry_locked(
        &self,
        meta: &Metadata,
        ino: InodeId,
    ) -> Result<(usize, usize)> {
        let inode = meta
            .inodes
            .get(&ino)
            .ok_or_else(|| ArgosError::NotFound(format!("inode {ino}")))?;
        if inode.kind != NodeKind::File {
            return Err(ArgosError::Unsupported(
                "range updates require a regular file".to_string(),
            ));
        }
        let old_size = usize::try_from(inode.size)
            .map_err(|_| ArgosError::Invalid("inode size is too large".to_string()))?;
        let layout = current_write_layout(meta)?;
        let stripe_raw_size = layout_stripe_raw_size(&layout)?;
        Ok((old_size, stripe_raw_size))
    }

    pub(super) fn decode_inode_window_locked(
        &self,
        meta: &mut Metadata,
        ino: InodeId,
        start: usize,
        end: usize,
    ) -> Result<Vec<u8>> {
        if end <= start {
            return Ok(Vec::new());
        }
        let inode = meta
            .inodes
            .get(&ino)
            .ok_or_else(|| ArgosError::NotFound(format!("inode {ino}")))?
            .clone();
        if inode.kind != NodeKind::File {
            return Err(ArgosError::Unsupported(
                "range updates require a regular file".to_string(),
            ));
        }
        if let Some(inline) = decode_inline_data(&inode)? {
            let mut out = vec![0u8; end - start];
            let copy_end = end.min(inline.len());
            if copy_end > start {
                out[..copy_end - start].copy_from_slice(&inline[start..copy_end]);
            }
            return Ok(out);
        }

        self.decode_inode_range_from_inode_locked(meta, &inode, start, end)
            .map(|(data, _)| data)
    }

    pub(super) fn decode_inode_range_from_inode_locked(
        &self,
        meta: &mut Metadata,
        inode: &Inode,
        start: usize,
        end: usize,
    ) -> Result<(Vec<u8>, Vec<String>)> {
        if end <= start {
            return Ok((Vec::new(), Vec::new()));
        }
        if let Some(inline) = decode_inline_data(inode)? {
            if end > inline.len() {
                return Err(ArgosError::Invalid(format!(
                    "inline inode {} size is smaller than requested range",
                    inode.id
                )));
            }
            return Ok((inline[start..end].to_vec(), Vec::new()));
        }
        let mut out = vec![0u8; end - start];
        let decrypt_key = if inode.blocks.iter().any(|block| block.encrypted) {
            Some(self.encryption_key_locked(meta)?)
        } else {
            None
        };
        let mut damaged = Vec::new();
        for block in &inode.blocks {
            let block_start = usize::try_from(block.raw_offset).map_err(|_| {
                ArgosError::Invalid(format!("block {} raw offset is too large", block.stripe_id))
            })?;
            let block_end = block_start.checked_add(block.raw_size).ok_or_else(|| {
                ArgosError::Invalid(format!("block {} raw range overflow", block.stripe_id))
            })?;
            if block_end <= start || block_start >= end {
                continue;
            }
            let copy_start = block_start.max(start);
            let copy_end = block_end.min(end);
            if copy_end > copy_start {
                let dst_start = copy_start - start;
                let len = copy_end - copy_start;
                if let Some(raw) = self.decode_block_range_locked(
                    meta,
                    block,
                    copy_start - block_start,
                    copy_end - block_start,
                    &mut damaged,
                )? {
                    out[dst_start..dst_start + len].copy_from_slice(&raw);
                } else {
                    let raw =
                        self.decode_block_locked(meta, block, decrypt_key.as_ref(), &mut damaged)?;
                    let src_start = copy_start - block_start;
                    out[dst_start..dst_start + len]
                        .copy_from_slice(&raw[src_start..src_start + len]);
                }
            }
        }
        Ok((out, damaged))
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn rewrite_inode_window_locked(
        &self,
        meta: &mut Metadata,
        ino: InodeId,
        affected_start: usize,
        affected_end: usize,
        new_size: usize,
        window: &[u8],
        logical_write_bytes: u64,
        clear_setid: bool,
        action: &str,
        details: serde_json::Value,
    ) -> Result<()> {
        let rollback = commit_previous_snapshot(meta);
        let (storage_class, boot_critical, old_blocks) = {
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
                inode.storage_class,
                inode.boot_critical,
                inode.blocks.clone(),
            )
        };

        let mut merged = Vec::new();
        let mut replaced = Vec::new();
        for block in old_blocks {
            let block_start = block.raw_offset as usize;
            let block_end = block_start.saturating_add(block.raw_size);
            if block_end <= affected_start || block_start >= affected_end {
                if block_start < new_size {
                    merged.push(block);
                } else {
                    replaced.push(block);
                }
            } else {
                replaced.push(block);
            }
        }

        let inline_payload = if affected_start == 0 && window.len() == new_size {
            inline_payload_for(meta, window)
        } else {
            None
        };
        let written_blocks = if inline_payload.is_some() {
            Vec::new()
        } else if !window.is_empty() {
            self.encode_data_locked(
                meta,
                window,
                affected_start as u64,
                storage_class,
                boot_critical,
                &BTreeSet::new(),
            )?
        } else {
            Vec::new()
        };
        merged.extend(written_blocks.clone());
        merged.sort_by_key(|block| block.raw_offset);

        let now = now_f64();
        let inode = meta.inodes.get_mut(&ino).unwrap();
        inode.blocks = merged;
        set_inline_payload(inode, inline_payload);
        inode.size = new_size as u64;
        inode.write_count = inode.write_count.saturating_add(1);
        inode.write_bytes = inode.write_bytes.saturating_add(logical_write_bytes);
        inode.last_written_at = now;
        inode.workload_score = inode.workload_score * 0.90 + 2.0;
        inode.mtime = now;
        inode.ctime = now;
        if clear_setid {
            inode.mode &= !(libc::S_ISUID | libc::S_ISGID);
        }

        self.account_blocks_locked(meta, &replaced, false);
        if let Err(err) = self.commit_locked_with_previous(meta, rollback.as_ref(), action, details)
        {
            if !Self::transaction_error_is_committed(&err) {
                if matches!(err, ArgosError::Conflict(_)) {
                    if meta.backend == BackendKind::Host {
                        self.delete_blocks_locked(meta, &written_blocks);
                    }
                } else {
                    self.delete_blocks_locked(meta, &written_blocks);
                    if let Some(rollback) = rollback {
                        *meta = rollback;
                    }
                }
            }
            return Err(err);
        }
        self.delete_blocks_locked(meta, &replaced);
        Ok(())
    }

    pub(super) fn decode_inode_data_locked(
        &self,
        meta: &mut Metadata,
        inode: &Inode,
    ) -> Result<(Vec<u8>, Vec<String>)> {
        let logical_size = usize::try_from(inode.size)
            .map_err(|_| ArgosError::Invalid("inode logical size is too large".to_string()))?;
        if let Some(inline) = decode_inline_data(inode)? {
            if inline.len() != logical_size {
                return Err(ArgosError::Invalid(format!(
                    "inline inode {} size mismatch",
                    inode.id
                )));
            }
            return Ok((inline, Vec::new()));
        }
        let mut out = vec![0u8; logical_size];
        let mut damaged = Vec::new();
        let decrypt_key = if inode.blocks.iter().any(|block| block.encrypted) {
            Some(self.encryption_key_locked(meta)?)
        } else {
            None
        };
        for block in &inode.blocks {
            let raw = self.decode_block_locked(meta, block, decrypt_key.as_ref(), &mut damaged)?;
            let block_start = usize::try_from(block.raw_offset).map_err(|_| {
                ArgosError::Invalid(format!("block {} raw offset is too large", block.stripe_id))
            })?;
            let block_end = block_start.checked_add(raw.len()).ok_or_else(|| {
                ArgosError::Invalid(format!("block {} raw range overflow", block.stripe_id))
            })?;
            if block_end > logical_size {
                return Err(ArgosError::Invalid(format!(
                    "block {} extends past inode size",
                    block.stripe_id
                )));
            }
            out[block_start..block_end].copy_from_slice(&raw);
        }
        Ok((out, damaged))
    }

    pub(super) fn decode_block_locked(
        &self,
        meta: &mut Metadata,
        block: &FileBlock,
        decrypt_key: Option<&[u8; 32]>,
        damaged: &mut Vec<String>,
    ) -> Result<Vec<u8>> {
        let cache_key = format!("{}:{}:{}", meta.uuid, block.stripe_id, block.raw_sha256);
        if block.encrypted {
            self.cache.remove(&cache_key);
        } else if let Some(raw) = self.cache.get(&cache_key, Some(&block.raw_sha256)) {
            if raw.len() == block.raw_size {
                return Ok(raw);
            }
            self.cache.remove(&cache_key);
        }
        let layout = layout_by_id(meta, block_layout_id(block))?;
        if layout.k == 1 && layout.m == 0 && !block.encrypted && block.codec == Compression::None {
            return self.decode_single_shard_block_locked(meta, block, damaged, &cache_key);
        }
        let codec = RsCodec::new(layout.k, layout.m)?;
        let mut shards: Vec<Option<Vec<u8>>> = vec![None; layout_total(&layout)];
        for shard in &block.shards {
            if shard.slot >= shards.len() {
                damaged.push(format!("{}:invalid-slot:{}", shard.disk_id, shard.slot));
                continue;
            }
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
            let start = std::time::Instant::now();
            match self.read_shard_locked(meta, shard) {
                Ok(data) => {
                    self.update_read_latency_locked(
                        meta,
                        &shard.disk_id,
                        data.len() as u64,
                        start.elapsed().as_secs_f64(),
                    );
                    if data.len() == shard.size && content_hash_matches(&data, &shard.sha256) {
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
        if present < layout.k {
            return Err(ArgosError::UnrecoverableStripe {
                stripe_id: block.stripe_id.clone(),
                reason: format!("only {present} shards available, need {}", layout.k),
            });
        }
        let reconstructed = codec.reconstruct(shards)?;
        let compressed: Vec<u8> = reconstructed
            .iter()
            .take(layout.k)
            .flat_map(|shard| shard.iter().copied())
            .take(block.compressed_size)
            .collect();
        let compressed = if block.encrypted {
            let nonce = hex::decode(&block.nonce_hex).map_err(|err| {
                ArgosError::Invalid(format!("invalid encrypted block nonce: {err}"))
            })?;
            let key = decrypt_key.ok_or_else(|| {
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
        if raw.len() != block.raw_size || !content_hash_matches(&raw, &block.raw_sha256) {
            return Err(ArgosError::UnrecoverableStripe {
                stripe_id: block.stripe_id.clone(),
                reason: "raw checksum mismatch".to_string(),
            });
        }
        if !block.encrypted {
            self.cache.put(&cache_key, &raw)?;
        }
        Ok(raw)
    }

    pub(super) fn decode_block_range_locked(
        &self,
        meta: &mut Metadata,
        block: &FileBlock,
        start: usize,
        end: usize,
        damaged: &mut Vec<String>,
    ) -> Result<Option<Vec<u8>>> {
        if start >= end {
            return Ok(Some(Vec::new()));
        }
        if block.encrypted || block.codec != Compression::None || end > block.raw_size {
            return Ok(None);
        }
        let layout = layout_by_id(meta, block_layout_id(block))?;
        if layout.k != 1 || layout.m != 0 {
            return Ok(None);
        }
        let Some(shard) = block.shards.iter().find(|shard| shard.slot == 0) else {
            damaged.push("single-shard:missing-slot-0".to_string());
            return Err(ArgosError::UnrecoverableStripe {
                stripe_id: block.stripe_id.clone(),
                reason: "single-device block has no shard 0".to_string(),
            });
        };
        if shard.size != block.raw_size
            || shard.sha256 != block.raw_sha256
            || shard.checksum_block_size == 0
            || shard.subblock_sha256.is_empty()
        {
            return Ok(None);
        }
        let checksum_block_size = shard.checksum_block_size;
        let expected_checksums = shard.size.div_ceil(checksum_block_size);
        if shard.subblock_sha256.len() != expected_checksums {
            return Ok(None);
        }
        let Some(disk) = meta.disks.get(&shard.disk_id) else {
            damaged.push(format!("{}:missing-disk", shard.disk_id));
            return Err(ArgosError::UnrecoverableStripe {
                stripe_id: block.stripe_id.clone(),
                reason: "single-device block references a missing disk".to_string(),
            });
        };
        if matches!(
            disk.status,
            DiskStatus::Failed | DiskStatus::Offline | DiskStatus::Removed
        ) {
            damaged.push(format!("{}:unavailable", shard.disk_id));
            return Err(ArgosError::UnrecoverableStripe {
                stripe_id: block.stripe_id.clone(),
                reason: "single-device shard is unavailable".to_string(),
            });
        }

        let verify_start = (start / checksum_block_size) * checksum_block_size;
        let verify_end = end.div_ceil(checksum_block_size) * checksum_block_size;
        let verify_end = verify_end.min(shard.size);
        let start_time = std::time::Instant::now();
        let data = match self.read_shard_range_locked(
            meta,
            shard,
            verify_start,
            verify_end.saturating_sub(verify_start),
        ) {
            Ok(data) => data,
            Err(err) => {
                self.update_read_latency_locked(
                    meta,
                    &shard.disk_id,
                    0,
                    start_time.elapsed().as_secs_f64(),
                );
                damaged.push(format!("{}:missing-range:{}", shard.disk_id, shard.slot));
                return Err(err);
            }
        };
        self.update_read_latency_locked(
            meta,
            &shard.disk_id,
            data.len() as u64,
            start_time.elapsed().as_secs_f64(),
        );

        let first_checksum = verify_start / checksum_block_size;
        let last_checksum = verify_end.div_ceil(checksum_block_size);
        for checksum_index in first_checksum..last_checksum {
            let absolute_start = checksum_index * checksum_block_size;
            let absolute_end = absolute_start
                .saturating_add(checksum_block_size)
                .min(shard.size);
            let relative_start = absolute_start.saturating_sub(verify_start);
            let relative_end = absolute_end.saturating_sub(verify_start);
            if relative_end > data.len()
                || !content_hash_matches(
                    &data[relative_start..relative_end],
                    &shard.subblock_sha256[checksum_index],
                )
            {
                damaged.push(format!(
                    "{}:subblock-checksum:{}:{}",
                    shard.disk_id, shard.slot, checksum_index
                ));
                return Err(ArgosError::UnrecoverableStripe {
                    stripe_id: block.stripe_id.clone(),
                    reason: "single-device subblock checksum mismatch".to_string(),
                });
            }
        }

        let local_start = start - verify_start;
        let local_end = end - verify_start;
        Ok(Some(data[local_start..local_end].to_vec()))
    }

    pub(super) fn decode_single_shard_block_locked(
        &self,
        meta: &mut Metadata,
        block: &FileBlock,
        damaged: &mut Vec<String>,
        cache_key: &str,
    ) -> Result<Vec<u8>> {
        let Some(shard) = block.shards.iter().find(|shard| shard.slot == 0) else {
            damaged.push("single-shard:missing-slot-0".to_string());
            return Err(ArgosError::UnrecoverableStripe {
                stripe_id: block.stripe_id.clone(),
                reason: "single-device block has no shard 0".to_string(),
            });
        };
        let Some(disk) = meta.disks.get(&shard.disk_id) else {
            damaged.push(format!("{}:missing-disk", shard.disk_id));
            return Err(ArgosError::UnrecoverableStripe {
                stripe_id: block.stripe_id.clone(),
                reason: "single-device block references a missing disk".to_string(),
            });
        };
        if matches!(
            disk.status,
            DiskStatus::Failed | DiskStatus::Offline | DiskStatus::Removed
        ) {
            damaged.push(format!("{}:unavailable", shard.disk_id));
            return Err(ArgosError::UnrecoverableStripe {
                stripe_id: block.stripe_id.clone(),
                reason: "single-device shard is unavailable".to_string(),
            });
        }
        let start = std::time::Instant::now();
        let data = match self.read_shard_locked(meta, shard) {
            Ok(data) => data,
            Err(err) => {
                self.update_read_latency_locked(
                    meta,
                    &shard.disk_id,
                    0,
                    start.elapsed().as_secs_f64(),
                );
                damaged.push(format!("{}:missing:{}", shard.disk_id, shard.slot));
                return Err(err);
            }
        };
        self.update_read_latency_locked(
            meta,
            &shard.disk_id,
            data.len() as u64,
            start.elapsed().as_secs_f64(),
        );
        if data.len() != shard.size
            || data.len() != block.raw_size
            || !content_hash_matches(&data, &shard.sha256)
            || !content_hash_matches(&data, &block.raw_sha256)
        {
            damaged.push(format!("{}:checksum:{}", shard.disk_id, shard.slot));
            return Err(ArgosError::UnrecoverableStripe {
                stripe_id: block.stripe_id.clone(),
                reason: "single-device raw checksum mismatch".to_string(),
            });
        }
        self.cache.put(cache_key, &data)?;
        Ok(data)
    }

    pub(super) fn encode_data_locked(
        &self,
        meta: &mut Metadata,
        data: &[u8],
        base_offset: u64,
        storage_class: StorageTier,
        boot_critical: bool,
        exclude_disks: &BTreeSet<String>,
    ) -> Result<Vec<FileBlock>> {
        let mut blocks = Vec::new();
        let layout = current_write_layout(meta)?;
        let stripe_raw_size = layout_stripe_raw_size(&layout)?;
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
            let raw_sha256 = content_hash_hex(raw);
            if layout.k == 1
                && layout.m == 0
                && encrypt_key.is_none()
                && meta.config.compression == Compression::None
            {
                let shard_size = raw.len().max(1);
                let placements = self.choose_disks_locked(
                    meta,
                    PlacementRequest {
                        key: &stripe_id,
                        count: 1,
                        storage_class,
                        boot_critical,
                        exclude_disks,
                        required_bytes: shard_size as u64,
                    },
                )?;
                let integrity = ShardIntegrity {
                    sha256: raw_sha256.clone(),
                    checksum_block_size: SHARD_CHECKSUM_BLOCK_SIZE,
                    subblock_sha256: shard_subblock_hashes(raw, &raw_sha256),
                };
                let shard = self.write_shard_locked(
                    meta,
                    &placements[0],
                    &stripe_id,
                    0,
                    raw,
                    Some(&integrity),
                )?;
                let raw_offset = index
                    .checked_mul(stripe_raw_size)
                    .and_then(|offset| u64::try_from(offset).ok())
                    .and_then(|offset| base_offset.checked_add(offset))
                    .ok_or_else(|| ArgosError::Invalid("raw block offset overflow".to_string()))?;
                blocks.push(FileBlock {
                    layout_id: layout.id.clone(),
                    stripe_id,
                    raw_offset,
                    raw_size: raw.len(),
                    raw_sha256,
                    codec: Compression::None,
                    encrypted: false,
                    nonce_hex: String::new(),
                    compressed_size: raw.len(),
                    shard_size,
                    shards: vec![shard],
                    storage_class,
                });
                continue;
            }
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
            let (shard_size, encoded) = if layout.k == 1 && layout.m == 0 {
                (payload.len().max(1), vec![payload.clone()])
            } else {
                let codec = RsCodec::new(layout.k, layout.m)?;
                let shard_size = payload.len().max(1).div_ceil(layout.k);
                let mut padded = payload.clone();
                let padded_len = shard_size.checked_mul(layout.k).ok_or_else(|| {
                    ArgosError::Invalid("encoded shard size overflow".to_string())
                })?;
                padded.resize(padded_len, 0);
                let data_shards = padded
                    .chunks(shard_size)
                    .map(|chunk| chunk.to_vec())
                    .collect::<Vec<_>>();
                (shard_size, codec.encode(&data_shards)?)
            };
            let single_raw_shard_integrity = if layout.k == 1
                && layout.m == 0
                && !encrypted
                && meta.config.compression == Compression::None
            {
                Some(ShardIntegrity {
                    sha256: raw_sha256.clone(),
                    checksum_block_size: SHARD_CHECKSUM_BLOCK_SIZE,
                    subblock_sha256: shard_subblock_hashes(raw, &raw_sha256),
                })
            } else {
                None
            };
            let placements = self.choose_disks_locked(
                meta,
                PlacementRequest {
                    key: &stripe_id,
                    count: layout_total(&layout),
                    storage_class,
                    boot_critical,
                    exclude_disks,
                    required_bytes: shard_size as u64,
                },
            )?;
            let mut shards = Vec::new();
            for (slot, shard_data) in encoded.iter().enumerate() {
                let integrity = if slot == 0 {
                    single_raw_shard_integrity.as_ref()
                } else {
                    None
                };
                match self.write_shard_locked(
                    meta,
                    &placements[slot],
                    &stripe_id,
                    slot,
                    shard_data,
                    integrity,
                ) {
                    Ok(shard) => shards.push(shard),
                    Err(err) => {
                        for shard in &shards {
                            let _ = self.delete_shard_locked(meta, shard);
                        }
                        for shard in &shards {
                            if let Some(disk) = meta.disks.get_mut(&shard.disk_id) {
                                disk.used_bytes =
                                    disk.used_bytes.saturating_sub(shard_accounted_size(shard));
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
                layout_id: layout.id.clone(),
                stripe_id,
                raw_offset,
                raw_size: raw.len(),
                raw_sha256,
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

    pub(super) fn write_shard_locked(
        &self,
        meta: &mut Metadata,
        disk_id: &str,
        stripe_id: &str,
        slot: usize,
        data: &[u8],
        integrity: Option<&ShardIntegrity>,
    ) -> Result<Shard> {
        let sha256 = integrity
            .map(|integrity| integrity.sha256.clone())
            .unwrap_or_else(|| content_hash_hex(data));
        let checksum_block_size = integrity
            .map(|integrity| integrity.checksum_block_size)
            .unwrap_or_default();
        let subblock_sha256 = integrity
            .map(|integrity| integrity.subblock_sha256.clone())
            .unwrap_or_default();
        if meta.backend != BackendKind::Host {
            self.ensure_block_backend_writable_locked(meta)?;
            self.ensure_disk_capacity_locked(meta, disk_id, data.len() as u64)?;
            let allocator = meta
                .raw_pool
                .allocators
                .get_mut(disk_id)
                .ok_or_else(|| ArgosError::MissingDevice(disk_id.to_string()))?;
            let extent = allocator::allocate(allocator, disk_id, data.len() as u64, meta.txid + 1)?;
            let start = std::time::Instant::now();
            let write_result = (|| -> Result<()> {
                journal::inject_crash(FaultPoint::BeforeDataWrite.as_str())?;
                self.backend_write_at_locked(meta, disk_id, extent.offset, data)?;
                journal::inject_crash(FaultPoint::AfterDataWriteBeforeFlush.as_str())?;
                if !bulk_import_enabled() && !meta.config.defer_data_flush {
                    self.backend_flush_locked(meta, disk_id)?;
                    journal::inject_crash(FaultPoint::AfterDataFlushBeforeJournalCommit.as_str())?;
                }
                Ok(())
            })();
            if let Err(err) = write_result {
                if let Some(allocator) = meta.raw_pool.allocators.get_mut(disk_id) {
                    if extent.offset.saturating_add(extent.length) == allocator.next_offset {
                        allocator.next_offset = extent.offset;
                    } else {
                        let _ = allocator::free(allocator, &extent);
                    }
                }
                return Err(err);
            }
            if let Some(disk) = meta.disks.get_mut(disk_id) {
                disk.used_bytes = disk.used_bytes.saturating_add(extent.length);
            }
            self.update_write_latency_locked(
                meta,
                disk_id,
                data.len() as u64,
                start.elapsed().as_secs_f64(),
            );
            return Ok(Shard {
                slot,
                disk_id: disk_id.to_string(),
                location: Some(ShardLocation::RawExtent(extent)),
                relpath: PathBuf::new(),
                sha256,
                checksum_block_size,
                subblock_sha256,
                size: data.len(),
            });
        }
        let subdir = &stripe_id[stripe_id.len().saturating_sub(2)..];
        let relpath = PathBuf::from(format!("shards/{subdir}/{stripe_id}.{slot:03}.blk"));
        let path = self.shard_path_locked(meta, disk_id, &relpath);
        if let Some(parent) = path.parent() {
            ensure_dir(parent)?;
        }
        self.ensure_disk_capacity_locked(meta, disk_id, data.len() as u64)?;
        let start = std::time::Instant::now();
        advanced_io::write_all(&path, data, meta.config.io_mode)?;
        self.mark_host_shard_dirty(path.clone());
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
            location: Some(ShardLocation::HostPath {
                disk_id: disk_id.to_string(),
                relpath: relpath.clone(),
            }),
            relpath,
            sha256,
            checksum_block_size,
            subblock_sha256,
            size: data.len(),
        })
    }

    pub(super) fn choose_disks_locked(
        &self,
        meta: &Metadata,
        request: PlacementRequest<'_>,
    ) -> Result<Vec<String>> {
        if request.count == 1 {
            let mut only = None;
            let mut eligible = 0usize;
            for (disk_id, disk) in &meta.disks {
                if request.exclude_disks.contains(disk_id) || disk.status != DiskStatus::Online {
                    continue;
                }
                if meta.backend == BackendKind::Host {
                    let disk_path = relative_or_absolute(&self.root, &disk.path);
                    if !disk_path.join("shards").exists() {
                        continue;
                    }
                }
                if !self.disk_has_capacity(meta, disk_id, disk, request.required_bytes) {
                    continue;
                }
                eligible += 1;
                only = Some(disk_id.clone());
                if eligible > 1 {
                    break;
                }
            }
            if eligible == 1 {
                return Ok(vec![only.expect("eligible disk id")]);
            }
        }
        let mut scored = Vec::new();
        let local_numa = if bulk_import_enabled() {
            None
        } else {
            meta.config
                .numa_aware
                .then(advanced_io::current_numa_node)
                .flatten()
        };
        for (disk_id, disk) in &meta.disks {
            if request.exclude_disks.contains(disk_id) || disk.status != DiskStatus::Online {
                continue;
            }
            if meta.backend == BackendKind::Host {
                let disk_path = relative_or_absolute(&self.root, &disk.path);
                if !disk_path.join("shards").exists() {
                    continue;
                }
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
                let current = reservations.get(&group).copied().unwrap_or(0);
                reservations.insert(group, current.saturating_add(request.required_bytes));
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

    pub(super) fn disk_has_capacity(
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

    pub(super) fn ensure_disk_capacity_locked(
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

    pub(super) fn update_read_latency_locked(
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

    pub(super) fn update_write_latency_locked(
        &self,
        meta: &mut Metadata,
        disk_id: &str,
        bytes: u64,
        seconds: f64,
    ) {
        if meta.config.defer_metadata_commit && bytes < SHARD_CHECKSUM_BLOCK_SIZE as u64 {
            return;
        }
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

    pub(super) fn delete_blocks_locked(&self, meta: &mut Metadata, blocks: &[FileBlock]) {
        for block in blocks {
            self.cache.remove(&format!(
                "{}:{}:{}",
                meta.uuid, block.stripe_id, block.raw_sha256
            ));
            for shard in &block.shards {
                let _ = self.delete_shard_locked(meta, shard);
            }
        }
    }

    pub(super) fn read_shard_locked(&self, meta: &Metadata, shard: &Shard) -> Result<Vec<u8>> {
        match shard.location.as_ref() {
            Some(ShardLocation::RawExtent(extent)) => {
                let mut data = vec![0u8; shard.size];
                self.backend_read_at_locked(meta, &extent.disk_id, extent.offset, &mut data)?;
                Ok(data)
            }
            Some(ShardLocation::HostPath { disk_id, relpath }) => advanced_io::read_all(
                &self.shard_path_locked(meta, disk_id, relpath),
                shard.size,
                meta.config.io_mode,
                meta.config.zero_copy,
            ),
            None => advanced_io::read_all(
                &self.shard_path_locked(meta, &shard.disk_id, &shard.relpath),
                shard.size,
                meta.config.io_mode,
                meta.config.zero_copy,
            ),
        }
    }

    pub(super) fn read_shard_range_locked(
        &self,
        meta: &Metadata,
        shard: &Shard,
        offset: usize,
        len: usize,
    ) -> Result<Vec<u8>> {
        let end = offset
            .checked_add(len)
            .ok_or_else(|| ArgosError::Invalid("shard read range overflow".to_string()))?;
        if end > shard.size {
            return Err(ArgosError::Invalid(format!(
                "shard range {offset}..{end} exceeds shard size {}",
                shard.size
            )));
        }
        let mut data = vec![0u8; len];
        match shard.location.as_ref() {
            Some(ShardLocation::RawExtent(extent)) => {
                let absolute = extent
                    .offset
                    .checked_add(offset as u64)
                    .ok_or_else(|| ArgosError::Invalid("raw extent read overflow".to_string()))?;
                self.backend_read_at_locked(meta, &extent.disk_id, absolute, &mut data)?;
            }
            Some(ShardLocation::HostPath { disk_id, relpath }) => {
                read_path_range_exact(
                    &self.shard_path_locked(meta, disk_id, relpath),
                    offset as u64,
                    &mut data,
                )?;
            }
            None => {
                read_path_range_exact(
                    &self.shard_path_locked(meta, &shard.disk_id, &shard.relpath),
                    offset as u64,
                    &mut data,
                )?;
            }
        }
        Ok(data)
    }

    pub(super) fn delete_shard_locked(&self, meta: &mut Metadata, shard: &Shard) -> Result<()> {
        match shard.location.as_ref() {
            Some(ShardLocation::RawExtent(extent)) => {
                if let Some(allocator) = meta.raw_pool.allocators.get_mut(&extent.disk_id) {
                    allocator::free(allocator, extent)?;
                }
                Ok(())
            }
            Some(ShardLocation::HostPath { disk_id, relpath }) => {
                if let Some(path) = self.shard_path_if_disk_exists_locked(meta, disk_id, relpath) {
                    let _ = fs::remove_file(path);
                }
                Ok(())
            }
            None => {
                if let Some(path) =
                    self.shard_path_if_disk_exists_locked(meta, &shard.disk_id, &shard.relpath)
                {
                    let _ = fs::remove_file(path);
                }
                Ok(())
            }
        }
    }

    pub(super) fn backend_read_at_locked(
        &self,
        meta: &Metadata,
        disk_id: &str,
        offset: u64,
        buf: &mut [u8],
    ) -> Result<()> {
        match self.backend.read_at(&disk_id.to_string(), offset, buf) {
            Err(ArgosError::MissingDevice(_)) if meta.backend != BackendKind::Host => {
                let backend = self.single_device_backend_locked(meta, disk_id, false)?;
                backend.read_at(&disk_id.to_string(), offset, buf)
            }
            other => other,
        }
    }

    pub(super) fn backend_write_at_locked(
        &self,
        meta: &Metadata,
        disk_id: &str,
        offset: u64,
        data: &[u8],
    ) -> Result<()> {
        match self.backend.write_at(&disk_id.to_string(), offset, data) {
            Err(ArgosError::MissingDevice(_)) if meta.backend != BackendKind::Host => {
                let backend = self.single_device_backend_locked(meta, disk_id, true)?;
                backend.write_at(&disk_id.to_string(), offset, data)
            }
            other => other,
        }
    }

    pub(super) fn backend_flush_locked(&self, meta: &Metadata, disk_id: &str) -> Result<()> {
        match self.backend.flush_device(&disk_id.to_string()) {
            Err(ArgosError::MissingDevice(_)) if meta.backend != BackendKind::Host => {
                let backend = self.single_device_backend_locked(meta, disk_id, true)?;
                backend.flush_device(&disk_id.to_string())
            }
            other => other,
        }
    }

    pub(super) fn single_device_backend_locked(
        &self,
        meta: &Metadata,
        disk_id: &str,
        write: bool,
    ) -> Result<FileBlockBackend> {
        let disk = meta
            .disks
            .get(disk_id)
            .ok_or_else(|| ArgosError::MissingDevice(disk_id.to_string()))?;
        FileBlockBackend::open_with_ids(
            meta.backend,
            vec![(disk_id.to_string(), disk.path.clone())],
            write,
        )
    }

    pub(super) fn account_blocks_locked(
        &self,
        meta: &mut Metadata,
        blocks: &[FileBlock],
        add: bool,
    ) {
        for shard in blocks.iter().flat_map(|block| block.shards.iter()) {
            if let Some(disk) = meta.disks.get_mut(&shard.disk_id) {
                let accounted = shard_accounted_size(shard);
                if add {
                    disk.used_bytes = disk.used_bytes.saturating_add(accounted);
                } else {
                    disk.used_bytes = disk.used_bytes.saturating_sub(accounted);
                }
            }
        }
    }

    pub(super) fn effective_capacity_bytes_locked(&self, meta: &Metadata, disk: &Disk) -> u64 {
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
            })
            .map(|candidate| candidate.capacity_bytes)
            .max()
            .unwrap_or(disk.capacity_bytes)
    }

    pub(super) fn effective_used_bytes_locked(&self, meta: &Metadata, disk: &Disk) -> u64 {
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

    pub(super) fn referenced_shards(&self) -> BTreeSet<(String, PathBuf)> {
        let meta = self.meta.read();
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
}
