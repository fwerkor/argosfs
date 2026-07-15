use super::*;

impl ArgosFs {
    pub fn set_io_policy(
        &self,
        mode: IoMode,
        direct_io: bool,
        zero_copy: bool,
        numa_aware: bool,
    ) -> Result<()> {
        let mut meta = self.meta.write();
        self.ensure_block_backend_writable_locked(&meta)?;
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
        self.meta.read().config.clone()
    }

    pub fn enable_encryption(&self, passphrase: &str) -> Result<()> {
        if passphrase.is_empty() {
            return Err(ArgosError::Invalid(
                "encryption passphrase must not be empty".to_string(),
            ));
        }
        let mut meta = self.meta.write();
        self.ensure_block_backend_writable_locked(&meta)?;
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
        let mut meta = self.meta.write();
        self.ensure_block_backend_writable_locked(&meta)?;
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
        ensure_private_dir(&disk_root)?;
        ensure_private_dir(&disk_root.join("shards"))?;
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

    pub fn add_block_device(&self, path: PathBuf, image_size: u64, force: bool) -> Result<String> {
        let kind = self.metadata_snapshot().backend;
        if kind == BackendKind::Host {
            return Err(ArgosError::Unsupported(
                "add-device is only for loop/raw block pools; use add-disk for host volumes"
                    .to_string(),
            ));
        }
        if kind == BackendKind::LoopBlock {
            prepare_loop_images(std::slice::from_ref(&path), image_size, force)?;
        }
        let new_backend_file = match kind {
            BackendKind::LoopBlock => {
                FileBlockBackend::open_loop(std::slice::from_ref(&path), true)?
            }
            BackendKind::RawBlock => FileBlockBackend::open_raw(std::slice::from_ref(&path), true)?,
            BackendKind::Host => unreachable!(),
        };
        let info = new_backend_file
            .list_devices()?
            .into_iter()
            .next()
            .ok_or_else(|| ArgosError::MissingDevice(path.display().to_string()))?;
        let mut meta = self.meta.write();
        self.ensure_block_backend_writable_locked(&meta)?;
        let next = meta
            .disks
            .keys()
            .filter_map(|id| id.strip_prefix("disk-")?.parse::<usize>().ok())
            .max()
            .map(|value| value + 1)
            .unwrap_or(0);
        let id = format!("disk-{next:04}");
        let pool_uuid = Uuid::parse_str(&meta.uuid)
            .map_err(|err| ArgosError::Invalid(format!("invalid pool UUID: {err}")))?;
        let layout = current_write_layout(&meta)?;
        let sb = raw_store::superblock_for_device(
            pool_uuid,
            next,
            &id,
            layout.k,
            layout.m,
            meta.config.chunk_size,
            info.capacity,
            &meta.raw_pool.pool_name,
        )?;
        let new_backend_with_id =
            FileBlockBackend::open_with_ids(kind, vec![(id.clone(), path.clone())], true)?;
        raw_store::preflight_devices_empty(&new_backend_with_id, std::slice::from_ref(&sb), force)?;

        let created_at = now_f64();
        meta.raw_pool.allocators.insert(
            id.clone(),
            allocator::init_allocator(sb.data.offset, sb.data.length, raw_format::RAW_BLOCK_SIZE),
        );
        meta.disks.insert(
            id.clone(),
            Disk {
                id: id.clone(),
                path: info.path,
                tier: StorageTier::Warm,
                weight: 1.0,
                status: DiskStatus::Online,
                capacity_bytes: info.capacity,
                capacity_source: CapacitySource::UserOverride,
                used_bytes: 0,
                health: HealthCounters::default(),
                class: DiskClass::Unknown,
                backing_device: None,
                backing_fs_id: None,
                failure_domain: format!("raw-device-{next:04}"),
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
        let mut bootstrap_metadata = meta.clone();
        let previous_meta_hash = bootstrap_metadata.integrity.meta_hash.clone();
        journal::prepare_metadata_integrity_with_previous(
            &mut bootstrap_metadata,
            previous_meta_hash,
        )?;
        raw_store::initialize_pool(
            Arc::new(new_backend_with_id),
            std::slice::from_ref(&sb),
            &mut bootstrap_metadata,
            true,
        )?;
        self.commit_locked(
            &mut meta,
            "add-device",
            json!({"disk_id": id, "path": path, "backend": kind.as_str()}),
        )?;
        Ok(id)
    }

    pub fn mark_disk(&self, disk_id: &str, status: DiskStatus) -> Result<()> {
        let mut meta = self.meta.write();
        self.ensure_block_backend_writable_locked(&meta)?;
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
        let mut meta = self.meta.write();
        self.ensure_block_backend_writable_locked(&meta)?;
        let disk = meta
            .disks
            .get_mut(disk_id)
            .ok_or_else(|| ArgosError::NotFound(disk_id.to_string()))?;
        if values.latency_ms > 0.0 {
            disk.read_latency_ewma_ms = values.latency_ms;
            disk.write_latency_ewma_ms = values.latency_ms;
        }
        disk.health = values;
        self.commit_locked(&mut meta, "set-health", json!({"disk_id": disk_id}))
    }

    pub fn refresh_disk_probe(&self, disk_id: Option<&str>) -> Result<Vec<DiskProbe>> {
        self.refresh_disk_probe_with_policy(disk_id, true)
    }

    pub(super) fn refresh_disk_probe_observations(
        &self,
        disk_id: Option<&str>,
    ) -> Result<Vec<DiskProbe>> {
        self.refresh_disk_probe_with_policy(disk_id, false)
    }

    pub(super) fn refresh_disk_probe_with_policy(
        &self,
        disk_id: Option<&str>,
        apply_recommendations: bool,
    ) -> Result<Vec<DiskProbe>> {
        let targets = {
            let meta = self.meta.read();
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
        {
            let meta = self.meta.read();
            self.ensure_block_backend_writable_locked(&meta)?;
        }
        let mut probes = Vec::new();
        let mut meta = self.meta.write();
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
            let meta = self.meta.read();
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
        {
            let meta = self.meta.read();
            self.ensure_block_backend_writable_locked(&meta)?;
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
        let mut meta = self.meta.write();
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
            let mut meta = self.meta.write();
            self.ensure_block_backend_writable_locked(&meta)?;
            if !meta.disks.contains_key(disk_id) {
                return Err(ArgosError::NotFound(disk_id.to_string()));
            }
            let have = meta
                .disks
                .iter()
                .filter(|(id, disk)| id.as_str() != disk_id && disk.status == DiskStatus::Online)
                .count();
            let need = max_layout_total(&meta)?;
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
            let meta = self.meta.read();
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
            let inode_lock = self.inode_lock(ino);
            let _inode_guard = inode_lock.lock();
            let data = self.read_inode(ino, 0, u64::MAX as usize, false)?;
            maintenance_after_read_delay();
            let mut meta = self.meta.write();
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
        let mut meta = self.meta.write();
        self.commit_locked(
            &mut meta,
            "drain-done",
            json!({"disk_id": disk_id, "rewritten_files": rewritten}),
        )?;
        Ok(rewritten)
    }

    pub fn remove_disk(&self, disk_id: &str) -> Result<u64> {
        let rewritten = self.drain_disk(disk_id)?;
        let mut meta = self.meta.write();
        self.ensure_block_backend_writable_locked(&meta)?;
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

    pub fn reshape_layout(
        &self,
        target_k: usize,
        target_m: usize,
        max_files: Option<usize>,
    ) -> Result<ReshapeReport> {
        if target_k == 0 {
            return Err(ArgosError::Invalid("target k must be positive".to_string()));
        }
        let max_files = max_files.unwrap_or(usize::MAX);
        let (reshape_id, target_layout) = {
            let mut meta = self.meta.write();
            self.ensure_block_backend_writable_locked(&meta)?;
            normalize_metadata_layouts(&mut meta);
            let have = meta
                .disks
                .values()
                .filter(|disk| disk.status == DiskStatus::Online)
                .count();
            let need = checked_layout_total(target_k, target_m)?;
            if have < need {
                return Err(ArgosError::NotEnoughDisks { need, have });
            }
            let _ = RsCodec::new(target_k, target_m)?;
            let chunk_size = meta.config.chunk_size;
            let target_layout =
                find_or_insert_layout_locked(&mut meta, target_k, target_m, chunk_size);
            let restart = meta
                .reshape
                .as_ref()
                .map(|state| state.target_layout != target_layout)
                .unwrap_or(true);
            if restart {
                let from_layouts = meta
                    .inodes
                    .values()
                    .flat_map(|inode| inode.blocks.iter())
                    .map(|block| block_layout_id(block).to_string())
                    .filter(|layout| layout != &target_layout)
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .collect::<Vec<_>>();
                let reshape_id = format!("reshape-{:016x}", meta.txid + 1);
                meta.current_write_layout = target_layout.clone();
                meta.config.k = target_k;
                meta.config.m = target_m;
                meta.reshape = Some(ReshapeState {
                    id: reshape_id.clone(),
                    target_layout: target_layout.clone(),
                    from_layouts,
                    cursor: None,
                    rewritten_files: 0,
                    complete: false,
                });
                self.commit_locked(
                    &mut meta,
                    "reshape-start",
                    json!({"target_layout": target_layout.clone(), "k": target_k, "m": target_m}),
                )?;
                (reshape_id, meta.current_write_layout.clone())
            } else {
                let state = meta.reshape.as_ref().expect("reshape state exists").clone();
                meta.current_write_layout = state.target_layout.clone();
                let layout = layout_by_id(&meta, &state.target_layout)?;
                meta.config.k = layout.k;
                meta.config.m = layout.m;
                (state.id.clone(), state.target_layout.clone())
            }
        };

        let mut rewritten_now = 0u64;
        while rewritten_now < max_files as u64 {
            let Some(ino) = self.next_reshape_inode(&target_layout) else {
                break;
            };
            let inode_lock = self.inode_lock(ino);
            let _inode_guard = inode_lock.lock();
            let data = self.read_inode(ino, 0, u64::MAX as usize, true)?;
            maintenance_after_read_delay();
            let mut meta = self.meta.write();
            self.replace_inode_data_locked(
                &mut meta,
                ino,
                &data,
                "reshape-rewrite",
                json!({"inode": ino, "target_layout": target_layout.clone()}),
                true,
                &BTreeSet::new(),
            )?;
            if let Some(state) = meta.reshape.as_mut() {
                if state.target_layout == target_layout {
                    state.cursor = Some(ino);
                    state.rewritten_files = state.rewritten_files.saturating_add(1);
                }
            }
            self.commit_locked(
                &mut meta,
                "reshape-progress",
                json!({"inode": ino, "target_layout": target_layout.clone()}),
            )?;
            rewritten_now = rewritten_now.saturating_add(1);
        }

        let remaining = self.reshape_remaining_files(&target_layout);
        let mut meta = self.meta.write();
        let (state_rewritten, complete) = if remaining == 0 {
            let state_rewritten = meta
                .reshape
                .as_ref()
                .map(|state| state.rewritten_files)
                .unwrap_or(rewritten_now);
            for (layout_id, layout) in &mut meta.layouts {
                if layout_id != &target_layout {
                    layout.sealed = true;
                }
            }
            if let Some(state) = meta.reshape.as_mut() {
                state.complete = true;
            }
            self.commit_locked(
                &mut meta,
                "reshape-complete",
                json!({"target_layout": target_layout.clone(), "rewritten_files": state_rewritten}),
            )?;
            meta.reshape = None;
            self.commit_locked(
                &mut meta,
                "reshape-state-clear",
                json!({"target_layout": target_layout.clone()}),
            )?;
            (state_rewritten, true)
        } else {
            (
                meta.reshape
                    .as_ref()
                    .map(|state| state.rewritten_files)
                    .unwrap_or(rewritten_now),
                false,
            )
        };
        let layout = layout_by_id(&meta, &target_layout)?;
        Ok(ReshapeReport {
            reshape_id,
            target_layout,
            target_k: layout.k,
            target_m: layout.m,
            rewritten_files: state_rewritten,
            remaining_files: remaining as u64,
            complete,
        })
    }

    pub(super) fn next_reshape_inode(&self, target_layout: &str) -> Option<InodeId> {
        let meta = self.meta.read();
        meta.inodes.iter().find_map(|(ino, inode)| {
            (inode.kind == NodeKind::File
                && inode
                    .blocks
                    .iter()
                    .any(|block| block_layout_id(block) != target_layout))
            .then_some(*ino)
        })
    }

    pub(super) fn reshape_remaining_files(&self, target_layout: &str) -> usize {
        let meta = self.meta.read();
        meta.inodes
            .values()
            .filter(|inode| {
                inode.kind == NodeKind::File
                    && inode
                        .blocks
                        .iter()
                        .any(|block| block_layout_id(block) != target_layout)
            })
            .count()
    }

    pub(super) fn rebalance_limited(
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
        {
            let meta = self.meta.read();
            self.ensure_block_backend_writable_locked(&meta)?;
        }
        let mut rewritten = 0;
        let mut next_cursor = cursor;
        for ino in targets {
            let inode_lock = self.inode_lock(ino);
            let _inode_guard = inode_lock.lock();
            let data = self.read_inode(ino, 0, u64::MAX as usize, true)?;
            maintenance_after_read_delay();
            let mut meta = self.meta.write();
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
        let mut meta = self.meta.write();
        self.commit_locked(
            &mut meta,
            "rebalance-done",
            json!({"rewritten_files": rewritten}),
        )?;
        Ok((rewritten, next_cursor))
    }

    pub(super) fn scrub_limited(
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
            let inode_lock = self.inode_lock(ino);
            let _inode_guard = inode_lock.lock();
            report.files_checked += 1;
            match self.read_inode_with_damage_report(ino, 0, u64::MAX as usize, true) {
                Ok((_, damaged, repaired)) => {
                    if !damaged.is_empty() {
                        report.damaged_files += 1;
                        report.checksum_errors += damaged
                            .iter()
                            .filter(|entry| entry.contains(":checksum:"))
                            .count() as u64;
                        report.missing_shards += damaged
                            .iter()
                            .filter(|entry| {
                                entry.contains(":missing:")
                                    || entry.contains(":missing-disk")
                                    || entry.contains(":unavailable")
                            })
                            .count() as u64;
                        if repaired {
                            report.repaired_files += 1;
                        }
                    }
                }
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
        let meta = self.meta.read();
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
                    let inode_lock = self.inode_lock(ino);
                    let _inode_guard = inode_lock.lock();
                    report.files_checked += 1;
                    let mut damaged = false;
                    for block in &inode.blocks {
                        for shard in &block.shards {
                            let meta = self.meta.read();
                            match self.read_shard_locked(&meta, shard) {
                                Ok(data) => {
                                    if !content_hash_matches(&data, &shard.sha256) {
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
                                    maintenance_after_read_delay();
                                    let mut meta = self.meta.write();
                                    self.replace_inode_data_locked(
                                        &mut meta,
                                        ino,
                                        &data,
                                        "fsck-repair",
                                        json!({"inode": ino}),
                                        false,
                                        &BTreeSet::new(),
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
        let meta = self.meta.read();
        let refs = meta
            .inodes
            .values()
            .flat_map(|inode| inode.blocks.iter())
            .flat_map(|block| block.shards.iter())
            .map(|shard| (shard.disk_id.clone(), shard.relpath.clone()))
            .collect::<BTreeSet<_>>();
        if meta.backend == BackendKind::Host {
            maintenance_after_read_delay();
            for (disk_id, disk) in &meta.disks {
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
        } else {
            for (disk_id, allocator_state) in &meta.raw_pool.allocators {
                let extents = meta
                    .inodes
                    .values()
                    .flat_map(|inode| inode.blocks.iter())
                    .flat_map(|block| block.shards.iter())
                    .filter_map(|shard| match shard.location.as_ref() {
                        Some(ShardLocation::RawExtent(extent)) if &extent.disk_id == disk_id => {
                            Some(extent.clone())
                        }
                        _ => None,
                    })
                    .collect::<Vec<_>>();
                if let Err(err) = allocator::validate_allocations(allocator_state, extents) {
                    report.errors.push(err.to_string());
                }
            }
        }
        drop(meta);
        if repair || remove_orphans {
            let mut meta = self.meta.write();
            let mut referenced_usage = BTreeMap::<String, u64>::new();
            for shard in meta
                .inodes
                .values()
                .flat_map(|inode| inode.blocks.iter())
                .flat_map(|block| block.shards.iter())
            {
                let current = referenced_usage
                    .get(&shard.disk_id)
                    .copied()
                    .unwrap_or(0u64);
                referenced_usage.insert(
                    shard.disk_id.clone(),
                    current.saturating_add(shard_accounted_size(shard)),
                );
            }
            let mut metadata_changed = report.removed_orphans > 0;
            for (disk_id, disk) in meta.disks.iter_mut() {
                let used_bytes = referenced_usage.get(disk_id).copied().unwrap_or(0);
                if disk.used_bytes != used_bytes {
                    disk.used_bytes = used_bytes;
                    metadata_changed = true;
                }
            }
            if metadata_changed {
                self.commit_locked(&mut meta, "fsck", json!({"report": report}))?;
            }
        }
        Ok(report)
    }

    pub fn scrub(&self) -> Result<FsckReport> {
        self.fsck(true, true)
    }
}

fn maintenance_after_read_delay() {
    #[cfg(debug_assertions)]
    if let Ok(value) = std::env::var("ARGOSFS_TEST_MAINTENANCE_AFTER_READ_DELAY_MS") {
        if let Ok(milliseconds) = value.parse::<u64>() {
            if milliseconds > 0 {
                std::thread::sleep(std::time::Duration::from_millis(milliseconds));
            }
        }
    }
}

#[cfg(test)]
#[path = "maintenance_tests.rs"]
mod tests;
