use super::*;

impl ArgosFs {
    pub fn resolve_path(&self, path: &str, follow_final: bool) -> Result<InodeId> {
        let meta = self.meta.read();
        self.resolve_path_locked(&meta, path, follow_final, 40)
    }

    pub fn attr_path(&self, path: &str, follow_final: bool) -> Result<NodeAttr> {
        let ino = self.resolve_path(path, follow_final)?;
        self.attr_inode(ino)
    }

    pub fn attr_inode(&self, ino: InodeId) -> Result<NodeAttr> {
        let meta = self.meta.read();
        let inode = meta
            .inodes
            .get(&ino)
            .ok_or_else(|| ArgosError::NotFound(format!("inode {ino}")))?;
        Ok(Self::attr_from_inode(inode, meta.config.chunk_size))
    }

    pub fn lookup(&self, parent: InodeId, name: &OsStr) -> Result<NodeAttr> {
        let meta = self.meta.read();
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
        let name = entry_name_from_str(&name)?;
        let mut meta = self.meta.write();
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
        let mut meta = self.meta.write();
        let ino = self.mkdir_locked(&mut meta, parent, &name, mode, uid, gid)?;
        let inode = meta.inodes.get(&ino).unwrap();
        Ok(Self::attr_from_inode(inode, meta.config.chunk_size))
    }

    pub fn mknod_path(&self, path: &str, mode: u32, rdev: u64) -> Result<InodeId> {
        let (parent, name) = parent_name(path)?;
        let name = entry_name_from_str(&name)?;
        let mut meta = self.meta.write();
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
        rdev: u64,
    ) -> Result<NodeAttr> {
        self.mknod_at_with_owner(parent, name, mode, rdev, current_uid(), current_gid())
    }

    pub fn mknod_at_with_owner(
        &self,
        parent: InodeId,
        name: &OsStr,
        mode: u32,
        rdev: u64,
        uid: u32,
        gid: u32,
    ) -> Result<NodeAttr> {
        let name = entry_name_from_os(name)?;
        let mut meta = self.meta.write();
        let ino = self.mknod_locked(&mut meta, parent, &name, mode, rdev, uid, gid)?;
        let inode = meta.inodes.get(&ino).unwrap();
        Ok(Self::attr_from_inode(inode, meta.config.chunk_size))
    }

    pub fn create_file_path(&self, path: &str, mode: u32) -> Result<InodeId> {
        let (parent, name) = parent_name(path)?;
        let name = entry_name_from_str(&name)?;
        let mut meta = self.meta.write();
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
        let mut meta = self.meta.write();
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
        self.read_inode_with_damage_report(ino, offset, size, repair)
            .map(|(data, _, _)| data)
    }

    pub fn seek_data_or_hole(&self, ino: InodeId, offset: u64, whence: i32) -> Result<u64> {
        let meta = self.meta.read();
        let inode = meta
            .inodes
            .get(&ino)
            .ok_or_else(|| ArgosError::NotFound(format!("inode {ino}")))?;
        if inode.kind != NodeKind::File {
            return Err(ArgosError::Unsupported(format!(
                "lseek data/hole requires a regular file: inode {ino}"
            )));
        }
        match whence {
            libc::SEEK_DATA => seek_data(inode, offset),
            libc::SEEK_HOLE => seek_hole(inode, offset),
            other => Err(ArgosError::Invalid(format!(
                "unsupported lseek whence {other}"
            ))),
        }
    }

    pub fn copy_inode_range(
        &self,
        src_ino: InodeId,
        src_offset: u64,
        dst_ino: InodeId,
        dst_offset: u64,
        len: u64,
    ) -> Result<usize> {
        self.copy_inode_range_checked(src_ino, src_offset, dst_ino, dst_offset, len, false)
    }

    pub fn copy_inode_range_as(
        &self,
        src_ino: InodeId,
        src_offset: u64,
        dst_ino: InodeId,
        dst_offset: u64,
        len: u64,
    ) -> Result<usize> {
        self.copy_inode_range_checked(src_ino, src_offset, dst_ino, dst_offset, len, true)
    }

    fn copy_inode_range_checked(
        &self,
        src_ino: InodeId,
        src_offset: u64,
        dst_ino: InodeId,
        dst_offset: u64,
        len: u64,
        clear_setid: bool,
    ) -> Result<usize> {
        let len = usize::try_from(len)
            .map_err(|_| ArgosError::Invalid("copy_file_range length is too large".to_string()))?;
        if len == 0 {
            return Ok(0);
        }
        if src_ino == dst_ino {
            let src_end = src_offset
                .checked_add(len as u64)
                .ok_or_else(|| ArgosError::Invalid("copy source range overflow".to_string()))?;
            let dst_end = dst_offset.checked_add(len as u64).ok_or_else(|| {
                ArgosError::Invalid("copy destination range overflow".to_string())
            })?;
            if src_offset < dst_end && dst_offset < src_end {
                return Err(ArgosError::Invalid(
                    "overlapping same-file copy_file_range is unsupported".to_string(),
                ));
            }
        }

        const COPY_CHUNK_BYTES: usize = 1024 * 1024;
        let mut copied = 0usize;
        while copied < len {
            let chunk_len = (len - copied).min(COPY_CHUNK_BYTES);
            let source = src_offset
                .checked_add(copied as u64)
                .ok_or_else(|| ArgosError::Invalid("copy source offset overflow".to_string()))?;
            let destination = dst_offset.checked_add(copied as u64).ok_or_else(|| {
                ArgosError::Invalid("copy destination offset overflow".to_string())
            })?;
            let data = self.read_inode(src_ino, source, chunk_len, true)?;
            if data.is_empty() {
                break;
            }
            match self.write_inode_range_checked(dst_ino, destination, &data, None, clear_setid) {
                Ok(written) => copied = copied.saturating_add(written),
                Err(_) if copied > 0 => return Ok(copied),
                Err(err) => return Err(err),
            }
            if data.len() < chunk_len {
                break;
            }
        }
        Ok(copied)
    }

    pub fn fallocate_inode(&self, ino: InodeId, offset: u64, length: u64, mode: i32) -> Result<()> {
        self.fallocate_inode_checked(ino, offset, length, mode, false)
    }

    pub fn fallocate_inode_as(
        &self,
        ino: InodeId,
        offset: u64,
        length: u64,
        mode: i32,
    ) -> Result<()> {
        self.fallocate_inode_checked(ino, offset, length, mode, true)
    }

    fn fallocate_inode_checked(
        &self,
        ino: InodeId,
        offset: u64,
        length: u64,
        mode: i32,
        clear_setid: bool,
    ) -> Result<()> {
        if mode != 0 {
            return Err(ArgosError::Unsupported(format!(
                "unsupported fallocate mode {mode:#x}"
            )));
        }
        let end = offset
            .checked_add(length)
            .ok_or_else(|| ArgosError::Invalid("fallocate range overflow".to_string()))?;
        let size = {
            let meta = self.meta.read();
            let inode = meta
                .inodes
                .get(&ino)
                .ok_or_else(|| ArgosError::NotFound(format!("inode {ino}")))?;
            match inode.kind {
                NodeKind::Directory => return Err(ArgosError::IsDirectory(format!("inode {ino}"))),
                NodeKind::File => inode.size,
                NodeKind::Symlink | NodeKind::Special => {
                    return Err(ArgosError::Unsupported(format!(
                        "fallocate requires a regular file: inode {ino}"
                    )))
                }
            }
        };
        if end > size {
            self.truncate_inode_checked(ino, end, clear_setid)?;
        }
        Ok(())
    }

    pub(super) fn read_inode_with_damage_report(
        &self,
        ino: InodeId,
        offset: u64,
        size: usize,
        repair: bool,
    ) -> Result<(Vec<u8>, Vec<String>, bool)> {
        let mut meta = self.meta.write();
        let inode = meta
            .inodes
            .get(&ino)
            .ok_or_else(|| ArgosError::NotFound(format!("inode {ino}")))?
            .clone();
        match inode.kind {
            NodeKind::Directory => return Err(ArgosError::IsDirectory(format!("inode {ino}"))),
            NodeKind::Symlink => {
                return Ok((
                    decode_symlink_target_bytes(inode.target.as_deref().unwrap_or_default()),
                    Vec::new(),
                    false,
                ));
            }
            NodeKind::Special => {
                return Err(ArgosError::Unsupported(format!(
                    "special inode {ino} has no data stream"
                )))
            }
            NodeKind::File => {}
        }
        let logical_size = usize::try_from(inode.size)
            .map_err(|_| ArgosError::Invalid("inode logical size is too large".to_string()))?;
        let start = offset.min(logical_size as u64) as usize;
        let end = start.saturating_add(size).min(logical_size);
        let (mut data, mut damaged) =
            self.decode_inode_range_from_inode_locked(&mut meta, &inode, start, end)?;
        let mut repaired = false;
        if repair && !damaged.is_empty() {
            let mut repair_damaged = damaged.clone();
            let (full, full_damaged) = self.decode_inode_data_locked(&mut meta, &inode)?;
            for entry in full_damaged {
                if !repair_damaged.contains(&entry) {
                    repair_damaged.push(entry);
                }
            }
            damaged = repair_damaged;
            let repair_result = self.replace_inode_data_locked(
                &mut meta,
                ino,
                &full,
                "self-heal",
                json!({"damaged": damaged}),
                true,
                &BTreeSet::new(),
            );
            match repair_result {
                Ok(()) => {
                    repaired = true;
                    data = full[start..end].to_vec();
                }
                Err(err) => {
                    data = full[start..end].to_vec();
                    if self.ensure_block_backend_writable_locked(&meta).is_ok() {
                        self.journal_locked(
                            &meta,
                            "self-heal-deferred",
                            json!({"inode": ino, "error": err.to_string()}),
                        )?;
                    }
                }
            }
        } else if let Some(live) = meta.inodes.get_mut(&ino) {
            live.access_count = live.access_count.saturating_add(1);
            live.read_bytes = live.read_bytes.saturating_add(data.len() as u64);
            live.last_accessed_at = now_f64();
            live.workload_score = live.workload_score * 0.98 + 1.0;
        }
        Ok((data, damaged, repaired))
    }

    pub fn write_inode_range(&self, ino: InodeId, offset: u64, data: &[u8]) -> Result<usize> {
        self.write_inode_range_checked(ino, offset, data, None, false)
    }

    pub fn write_inode_range_as(
        &self,
        ino: InodeId,
        offset: u64,
        data: &[u8],
        uid: u32,
        gid: u32,
    ) -> Result<usize> {
        self.write_inode_range_checked(ino, offset, data, Some((uid, gid)), true)
    }

    pub(super) fn write_inode_range_checked(
        &self,
        ino: InodeId,
        offset: u64,
        data: &[u8],
        access: Option<(u32, u32)>,
        clear_setid: bool,
    ) -> Result<usize> {
        let start = usize::try_from(offset)
            .map_err(|_| ArgosError::Invalid("write offset is too large".to_string()))?;
        let end = start
            .checked_add(data.len())
            .ok_or_else(|| ArgosError::Invalid("write range is too large".to_string()))?;

        let inode_lock = self.inode_lock(ino);
        let _inode_guard = inode_lock.lock();
        let mut meta = self.meta.write();
        if let Some((uid, gid)) = access {
            let inode = meta
                .inodes
                .get(&ino)
                .ok_or_else(|| ArgosError::NotFound(format!("inode {ino}")))?;
            if !acl::evaluate_access(inode, uid, gid, libc::W_OK) {
                return Err(ArgosError::PermissionDenied(format!(
                    "uid {uid} gid {gid} mask {:o} inode {ino}",
                    libc::W_OK
                )));
            }
        }
        let (old_size, stripe_raw_size) = self.range_update_geometry_locked(&meta, ino)?;
        if data.is_empty() {
            return Ok(0);
        }
        if start == old_size && start % stripe_raw_size == 0 {
            self.append_inode_data_locked(&mut meta, ino, start, data, clear_setid)?;
            return Ok(data.len());
        }
        let new_size = old_size.max(end);
        let affected_start = (start / stripe_raw_size) * stripe_raw_size;
        let affected_end = end
            .div_ceil(stripe_raw_size)
            .saturating_mul(stripe_raw_size)
            .min(new_size);

        let mut window =
            self.decode_inode_window_locked(&mut meta, ino, affected_start, affected_end)?;
        if start > old_size && old_size > affected_start {
            let gap_start = old_size - affected_start;
            let gap_end = start - affected_start;
            window[gap_start..gap_end].fill(0);
        }
        if end > affected_end {
            return Err(ArgosError::Invalid(
                "write affected window overflow".to_string(),
            ));
        }
        let local_start = start - affected_start;
        let local_end = local_start + data.len();
        if local_end > window.len() {
            window.resize(local_end, 0);
        }
        window[local_start..local_end].copy_from_slice(data);
        window.truncate(affected_end.saturating_sub(affected_start));

        self.rewrite_inode_window_locked(
            &mut meta,
            ino,
            affected_start,
            affected_end,
            new_size,
            &window,
            data.len() as u64,
            clear_setid,
            "write-range",
            json!({"inode": ino, "offset": offset, "bytes": data.len(), "rewrite": "stripe-window-local"}),
        )?;
        Ok(data.len())
    }

    pub(super) fn append_inode_data_locked(
        &self,
        meta: &mut Metadata,
        ino: InodeId,
        offset: usize,
        data: &[u8],
        clear_setid: bool,
    ) -> Result<()> {
        let rollback = commit_previous_snapshot(meta);
        let (storage_class, boot_critical, existing_inline, had_blocks) = {
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
                decode_inline_data(inode)?,
                !inode.blocks.is_empty(),
            )
        };
        let full_inline_data = if let Some(mut inline) = existing_inline {
            if offset != inline.len() {
                return Err(ArgosError::Invalid(format!(
                    "append offset {offset} does not match inline size {}",
                    inline.len()
                )));
            }
            inline.extend_from_slice(data);
            Some(inline)
        } else if !had_blocks && offset == 0 && inline_payload_for(meta, data).is_some() {
            Some(data.to_vec())
        } else {
            None
        };
        let (written_blocks, inline_payload, new_size) =
            if let Some(full_data) = full_inline_data.as_ref() {
                let inline_payload = inline_payload_for(meta, full_data);
                let blocks = if inline_payload.is_some() {
                    Vec::new()
                } else {
                    self.encode_data_locked(
                        meta,
                        full_data,
                        0,
                        storage_class,
                        boot_critical,
                        &BTreeSet::new(),
                    )?
                };
                (blocks, inline_payload, full_data.len())
            } else {
                let blocks = self.encode_data_locked(
                    meta,
                    data,
                    offset as u64,
                    storage_class,
                    boot_critical,
                    &BTreeSet::new(),
                )?;
                let new_size = offset
                    .checked_add(data.len())
                    .ok_or_else(|| ArgosError::Invalid("append size overflow".to_string()))?;
                (blocks, None, new_size)
            };
        let now = now_f64();
        let inode = meta.inodes.get_mut(&ino).unwrap();
        if full_inline_data.is_some() {
            inode.blocks = written_blocks.clone();
        } else {
            inode.blocks.extend(written_blocks.clone());
        }
        inode.blocks.sort_by_key(|block| block.raw_offset);
        set_inline_payload(inode, inline_payload);
        inode.size = new_size as u64;
        inode.write_count = inode.write_count.saturating_add(1);
        inode.write_bytes = inode.write_bytes.saturating_add(data.len() as u64);
        inode.last_written_at = now;
        inode.workload_score = inode.workload_score * 0.90 + 2.0;
        inode.mtime = now;
        inode.ctime = now;
        if clear_setid {
            inode.mode &= !(libc::S_ISUID | libc::S_ISGID);
        }

        if let Err(err) = self.commit_locked_with_previous(
            meta,
            rollback.as_ref(),
            "write-range",
            json!({"inode": ino, "offset": offset, "bytes": data.len(), "rewrite": "aligned-eof-append"}),
        ) {
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
        Ok(())
    }

    pub fn truncate_path(&self, path: &str, size: u64) -> Result<()> {
        let ino = self.resolve_path(path, true)?;
        self.truncate_inode(ino, size)
    }

    pub fn truncate_inode(&self, ino: InodeId, size: u64) -> Result<()> {
        self.truncate_inode_checked(ino, size, false)
    }

    pub fn truncate_inode_as(&self, ino: InodeId, size: u64) -> Result<()> {
        self.truncate_inode_checked(ino, size, true)
    }

    fn truncate_inode_checked(&self, ino: InodeId, size: u64, clear_setid: bool) -> Result<()> {
        let requested_size = size;
        let new_size = usize::try_from(requested_size)
            .map_err(|_| ArgosError::Invalid("truncate size is too large".to_string()))?;

        let inode_lock = self.inode_lock(ino);
        let _inode_guard = inode_lock.lock();
        let mut meta = self.meta.write();
        let (old_size, stripe_raw_size) = self.range_update_geometry_locked(&meta, ino)?;

        if new_size == old_size {
            return Ok(());
        }

        if new_size > old_size {
            let inline = {
                let inode = meta
                    .inodes
                    .get(&ino)
                    .ok_or_else(|| ArgosError::NotFound(format!("inode {ino}")))?;
                decode_inline_data(inode)?
            };
            let (affected_start, affected_end, window) = if let Some(inline) = inline {
                (0, old_size, inline)
            } else {
                (old_size, old_size, Vec::new())
            };
            return self.rewrite_inode_window_locked(
                &mut meta,
                ino,
                affected_start,
                affected_end,
                new_size,
                &window,
                0,
                clear_setid,
                "truncate",
                json!({"inode": ino, "size": requested_size, "rewrite": "sparse-extend"}),
            );
        }

        let affected_start = (new_size / stripe_raw_size) * stripe_raw_size;
        let affected_end = new_size;
        let window = if affected_start < affected_end {
            self.decode_inode_window_locked(&mut meta, ino, affected_start, affected_end)?
        } else {
            Vec::new()
        };

        self.rewrite_inode_window_locked(
            &mut meta,
            ino,
            affected_start,
            affected_end,
            new_size,
            &window,
            0,
            clear_setid,
            "truncate",
            json!({"inode": ino, "size": requested_size, "rewrite": "stripe-window-local"}),
        )
    }

    pub fn readdir(&self, ino: InodeId) -> Result<Vec<DirEntry>> {
        let meta = self.meta.read();
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
        let name = entry_name_from_str(&name)?;
        let mut meta = self.meta.write();
        let parent_ino = self.resolve_path_locked(&meta, &parent, true, 40)?;
        self.unlink_locked(
            &mut meta,
            parent_ino,
            &name,
            false,
            Some(current_uid()),
            false,
        )
    }

    pub fn unlink_at(&self, parent: InodeId, name: &OsStr) -> Result<()> {
        self.unlink_at_as(parent, name, current_uid())
    }

    pub fn unlink_at_as(&self, parent: InodeId, name: &OsStr, uid: u32) -> Result<()> {
        let name = entry_name_from_os(name)?;
        let mut meta = self.meta.write();
        self.unlink_locked(&mut meta, parent, &name, false, Some(uid), false)
    }

    pub fn unlink_at_as_preserving_open(
        &self,
        parent: InodeId,
        name: &OsStr,
        uid: u32,
    ) -> Result<()> {
        let name = entry_name_from_os(name)?;
        let mut meta = self.meta.write();
        self.unlink_locked(&mut meta, parent, &name, false, Some(uid), true)
    }

    pub fn rmdir_path(&self, path: &str) -> Result<()> {
        let (parent, name) = parent_name(path)?;
        let name = entry_name_from_str(&name)?;
        let mut meta = self.meta.write();
        let parent_ino = self.resolve_path_locked(&meta, &parent, true, 40)?;
        self.unlink_locked(
            &mut meta,
            parent_ino,
            &name,
            true,
            Some(current_uid()),
            false,
        )
    }

    pub fn rmdir_at(&self, parent: InodeId, name: &OsStr) -> Result<()> {
        self.rmdir_at_as(parent, name, current_uid())
    }

    pub fn rmdir_at_as(&self, parent: InodeId, name: &OsStr, uid: u32) -> Result<()> {
        let name = entry_name_from_os(name)?;
        let mut meta = self.meta.write();
        self.unlink_locked(&mut meta, parent, &name, true, Some(uid), false)
    }

    pub fn rename_path(&self, old: &str, new: &str) -> Result<()> {
        let (old_parent, old_name) = parent_name(old)?;
        let (new_parent, new_name) = parent_name(new)?;
        let old_name = entry_name_from_str(&old_name)?;
        let new_name = entry_name_from_str(&new_name)?;
        let mut meta = self.meta.write();
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
        let mut meta = self.meta.write();
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
        let mut meta = self.meta.write();
        self.ensure_block_backend_writable_locked(&meta)?;
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
            .and_then(|parent| acl::inherited_access_acl(parent, 0o777));
        let target_string = encode_symlink_target(target);
        let target_size = decode_symlink_target_bytes(&target_string).len() as u64;
        let inode = Inode {
            id: ino,
            kind: NodeKind::Symlink,
            mode: libc::S_IFLNK | 0o777,
            uid,
            gid,
            nlink: 1,
            size: target_size,
            rdev: 0,
            atime: now,
            mtime: now,
            ctime: now,
            entries: BTreeMap::new(),
            target: Some(target_string.clone()),
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
        let bytes = self.readlink_inode_bytes(ino)?;
        Ok(String::from_utf8_lossy(&bytes).to_string())
    }

    pub fn readlink_inode_bytes(&self, ino: InodeId) -> Result<Vec<u8>> {
        let meta = self.meta.read();
        let inode = meta
            .inodes
            .get(&ino)
            .ok_or_else(|| ArgosError::NotFound(format!("inode {ino}")))?;
        if inode.kind != NodeKind::Symlink {
            return Err(ArgosError::Invalid("not a symbolic link".to_string()));
        }
        Ok(decode_symlink_target_bytes(
            inode.target.as_deref().unwrap_or_default(),
        ))
    }

    pub fn link_at(&self, ino: InodeId, new_parent: InodeId, new_name: &OsStr) -> Result<NodeAttr> {
        let name = entry_name_from_os(new_name)?;
        let mut meta = self.meta.write();
        self.ensure_block_backend_writable_locked(&meta)?;
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
        self.chmod_inode_checked(ino, mode, None)
    }

    pub fn chmod_inode_as(
        &self,
        ino: InodeId,
        mode: u32,
        uid: u32,
        gids: &[u32],
    ) -> Result<NodeAttr> {
        self.chmod_inode_checked(ino, mode, Some((uid, gids)))
    }

    fn chmod_inode_checked(
        &self,
        ino: InodeId,
        mode: u32,
        caller: Option<(u32, &[u32])>,
    ) -> Result<NodeAttr> {
        let mut meta = self.meta.write();
        self.ensure_block_backend_writable_locked(&meta)?;
        let inode = meta
            .inodes
            .get_mut(&ino)
            .ok_or_else(|| ArgosError::NotFound(format!("inode {ino}")))?;
        let mut effective_mode = mode & 0o7777;
        if let Some((uid, gids)) = caller {
            if uid != 0 && uid != inode.uid {
                return Err(ArgosError::PermissionDenied(
                    "chmod requires file ownership or root".to_string(),
                ));
            }
            if uid != 0 && effective_mode & libc::S_ISGID != 0 && !gids.contains(&inode.gid) {
                effective_mode &= !libc::S_ISGID;
            }
        }
        inode.mode = (inode.mode & !0o7777) | effective_mode;
        if let Some(access_acl) = inode.posix_acl_access.as_mut() {
            acl::apply_mode_to_access_acl(access_acl, effective_mode);
        }
        inode.ctime = now_f64();
        self.commit_locked(
            &mut meta,
            "chmod",
            json!({"inode": ino, "mode": effective_mode}),
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
        let mut meta = self.meta.write();
        self.ensure_block_backend_writable_locked(&meta)?;
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
        inode.mode &= !(libc::S_ISUID | libc::S_ISGID);
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
        let mut meta = self.meta.write();
        self.ensure_block_backend_writable_locked(&meta)?;
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
        self.setxattr_inode_unchecked(ino, name, value)
    }

    pub fn importxattr_inode(&self, ino: InodeId, name: &str, value: &[u8]) -> Result<()> {
        xattr_namespace(name)?;
        self.setxattr_inode_unchecked(ino, name, value)
    }

    pub(super) fn setxattr_inode_unchecked(
        &self,
        ino: InodeId,
        name: &str,
        value: &[u8],
    ) -> Result<()> {
        let mut meta = self.meta.write();
        self.ensure_block_backend_writable_locked(&meta)?;
        let inode = meta
            .inodes
            .get_mut(&ino)
            .ok_or_else(|| ArgosError::NotFound(format!("inode {ino}")))?;
        match name {
            acl::POSIX_ACL_ACCESS_XATTR | acl::ARGOS_POSIX_ACL_ACCESS_XATTR => {
                let access_acl = acl::parse_posix_acl_xattr(value)?;
                inode.mode = acl::mode_from_access_acl(&access_acl, inode.mode);
                inode.posix_acl_access = Some(access_acl);
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
        let meta = self.meta.read();
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
        let meta = self.meta.read();
        let inode = meta
            .inodes
            .get(&ino)
            .ok_or_else(|| ArgosError::NotFound(format!("inode {ino}")))?;
        let mut names = inode
            .xattrs
            .keys()
            .filter(|name| xattr_namespace(name).is_ok())
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
        let mut meta = self.meta.write();
        self.ensure_block_backend_writable_locked(&meta)?;
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
        let mut meta = self.meta.write();
        self.ensure_block_backend_writable_locked(&meta)?;
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
            inode.mode = acl::mode_from_access_acl(&acl_value, inode.mode);
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
        let meta = self.meta.read();
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
        let mut meta = self.meta.write();
        self.ensure_block_backend_writable_locked(&meta)?;
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
        let meta = self.meta.read();
        let inode = meta
            .inodes
            .get(&ino)
            .ok_or_else(|| ArgosError::NotFound(format!("inode {ino}")))?;
        Ok(inode.nfs4_acl.clone())
    }

    pub fn check_access_inode(&self, ino: InodeId, uid: u32, gid: u32, mask: i32) -> Result<()> {
        self.check_access_inode_with_groups(ino, uid, &[gid], mask)
    }

    pub fn check_access_inode_with_groups(
        &self,
        ino: InodeId,
        uid: u32,
        gids: &[u32],
        mask: i32,
    ) -> Result<()> {
        let meta = self.meta.read();
        let inode = meta
            .inodes
            .get(&ino)
            .ok_or_else(|| ArgosError::NotFound(format!("inode {ino}")))?;
        if acl::evaluate_access_with_groups(inode, uid, gids, mask) {
            Ok(())
        } else {
            Err(ArgosError::PermissionDenied(format!(
                "uid {uid} gids {gids:?} mask {mask:o} inode {ino}"
            )))
        }
    }
}

pub(super) fn entry_name_from_os(name: &OsStr) -> Result<String> {
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

pub(super) fn entry_name_from_str(name: &str) -> Result<String> {
    entry_name_from_os(OsStr::new(name))
}

pub(super) fn validate_entry_name(name: &str) -> Result<()> {
    if name.is_empty() || name == "." || name == ".." {
        return Err(ArgosError::Invalid(format!("invalid entry name: {name:?}")));
    }
    if name.contains('/') || name.contains('\0') {
        return Err(ArgosError::Invalid(format!("invalid entry name: {name:?}")));
    }
    Ok(())
}

pub(super) fn validate_entry_name_bytes(name: &[u8]) -> Result<()> {
    if name.is_empty() || name == b"." || name == b".." {
        return Err(ArgosError::Invalid("invalid entry name bytes".to_string()));
    }
    if name.iter().any(|byte| *byte == b'/' || *byte == 0) {
        return Err(ArgosError::Invalid("invalid entry name bytes".to_string()));
    }
    Ok(())
}

pub(super) fn decode_entry_name_bytes(name: &str) -> Vec<u8> {
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

pub(super) fn display_entry_name(bytes: &[u8]) -> String {
    String::from_utf8(bytes.to_vec()).unwrap_or_else(|_| String::from_utf8_lossy(bytes).to_string())
}

pub(super) fn encode_symlink_target(target: &Path) -> String {
    let bytes = target.as_os_str().as_bytes();
    if let Some(target) = target.to_str() {
        return target.to_string();
    }
    format!("{NON_UTF8_SYMLINK_TARGET_PREFIX}{}", hex::encode(bytes))
}

pub(super) fn decode_symlink_target_bytes(target: &str) -> Vec<u8> {
    target
        .strip_prefix(NON_UTF8_SYMLINK_TARGET_PREFIX)
        .and_then(|encoded| hex::decode(encoded).ok())
        .unwrap_or_else(|| target.as_bytes().to_vec())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum XattrNamespace {
    User,
    Trusted,
    Security,
    System,
    ArgosSystem,
}

pub(super) fn xattr_namespace(name: &str) -> Result<XattrNamespace> {
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

pub(super) fn validate_xattr_write(name: &str) -> Result<()> {
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

pub(super) fn validate_xattr_read(name: &str) -> Result<()> {
    if is_known_system_xattr(name) {
        return Ok(());
    }
    match xattr_namespace(name)? {
        XattrNamespace::User
        | XattrNamespace::Trusted
        | XattrNamespace::Security
        | XattrNamespace::System => Ok(()),
        XattrNamespace::ArgosSystem => Err(ArgosError::Unsupported(format!(
            "unsupported ArgosFS-internal xattr: {name}"
        ))),
    }
}

pub(super) fn is_known_system_xattr(name: &str) -> bool {
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

pub(super) fn boot_critical_name(name: &str) -> bool {
    matches!(
        name,
        "boot" | "etc" | "bin" | "sbin" | "lib" | "lib64" | "usr" | "init"
    )
}
