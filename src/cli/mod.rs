use crate::acl;
use crate::crypto;
use crate::fusefs;
use crate::journal;
use crate::metrics;
use crate::rootfs::{self, RootMountMode};
use crate::scan;
use crate::types::{
    BackendKind, Compression, DiskStatus, FsckReport, HealthReport, IoMode, NodeKind, StorageTier,
    TransactionReport, VolumeConfig, DEFAULT_DEFERRED_COMMIT_INTERVAL_MS,
    DEFAULT_DEFERRED_COMMIT_MAX_TRANSACTIONS,
};
use crate::util::clean_path;
use crate::volume::NodeAttr;
use crate::{ArgosError, ArgosFs, AutopilotPolicy};
use anyhow::{bail, Context, Result};
use clap::{Args, Parser, Subcommand};
use std::collections::BTreeMap;
use std::ffi::CString;
use std::fs;
use std::io::{self, IsTerminal, Read};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Duration;

const DEFAULT_LOOP_IMAGE_SIZE: u64 = 64 * 1024 * 1024;

mod commands;
mod tree;

use commands::Command;
use tree::{export_tree, import_tree};

#[derive(Parser)]
#[command(name = "argosfs", version, arg_required_else_help = true)]
#[command(about = "ArgosFS self-driving erasure-coded root filesystem")]
#[command(after_help = "Command groups:
  Setup and discovery: mkfs, scan, inspect-device, inspect-pool, list-devices
  Root filesystem: mount-root, preflight-root, replay-journal, mount-recovery
  Device lifecycle: add-device, drain-device, replace-device, remove-device, reshape
  Maintenance: health, fsck, scrub, rebalance, autopilot, verify-journal
  File and security tools: import-tree, export-tree, put/get/ls/stat, ACL and encryption commands

Use `argosfs help <COMMAND>` for command-specific options. Block-backed commands can reuse a JSON selector with `--pool-config FILE`.")]
struct Cli {
    /// Emit machine-readable JSON where the command supports structured output.
    #[arg(long, global = true)]
    json: bool,

    #[command(subcommand)]
    command: Command,
}

pub fn run() -> Result<()> {
    let Cli { command, json } = Cli::parse();
    match command {
        Command::Mkfs {
            root,
            storage,
            image_size,
            pool_name,
            disks,
            k,
            m,
            chunk_size,
            compression,
            compression_level,
            defer_journal_flush,
            defer_metadata_commit,
            defer_data_flush,
            deferred_commit_interval_ms,
            deferred_commit_max_transactions,
            force,
        } => {
            let storage = storage.resolve(BackendKind::Host)?;
            validate_root_backend(root.as_deref(), storage.backend)?;
            let config = VolumeConfig {
                k,
                m,
                chunk_size,
                compression,
                compression_level,
                defer_journal_flush,
                defer_metadata_commit,
                defer_data_flush,
                deferred_commit_interval_ms,
                deferred_commit_max_transactions,
                ..VolumeConfig::default()
            };
            let fs = match storage.backend {
                BackendKind::Host => {
                    reject_option(image_size.is_some(), "--image-size", BackendKind::Host)?;
                    reject_option(
                        pool_name.is_some() || storage.pool.is_some(),
                        "--pool-name/pool config identity",
                        BackendKind::Host,
                    )?;
                    let root = root.context("host mkfs requires ROOT")?;
                    ArgosFs::create(root, config, disks.unwrap_or(6), force)?
                }
                BackendKind::LoopBlock => {
                    reject_option(disks.is_some(), "--disks", BackendKind::LoopBlock)?;
                    let paths = require_paths(
                        storage.images,
                        "loop mkfs requires --images or --pool-config",
                    )?;
                    let pool_name = pool_name
                        .or(storage.pool)
                        .unwrap_or_else(|| "argosfs-root".to_string());
                    ArgosFs::create_loop(
                        &paths,
                        config,
                        image_size.unwrap_or(DEFAULT_LOOP_IMAGE_SIZE),
                        &pool_name,
                        force,
                    )?
                }
                BackendKind::RawBlock => {
                    reject_option(disks.is_some(), "--disks", BackendKind::RawBlock)?;
                    reject_option(image_size.is_some(), "--image-size", BackendKind::RawBlock)?;
                    let paths = require_paths(
                        storage.devices,
                        "raw mkfs requires --devices or --pool-config",
                    )?;
                    let pool_name = pool_name
                        .or(storage.pool)
                        .unwrap_or_else(|| "argosfs-root".to_string());
                    ArgosFs::create_raw(&paths, config, &pool_name, force)?
                }
            };
            print_health_report(&fs.health_report(), json, true)?;
        }
        Command::Scan { storage } => {
            let storage = storage.resolve(BackendKind::LoopBlock)?;
            let paths = backend_paths(storage.backend, storage.images, storage.devices)?;
            let report = match storage.backend {
                BackendKind::LoopBlock => scan::scan_images(&paths),
                BackendKind::RawBlock => scan::scan_devices(&paths),
                BackendKind::Host => bail!("scan is only supported for loop/raw backends"),
            };
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                for device in report {
                    println!(
                        "{} valid={} pool={} disk={} generation={} clean={}{}",
                        device.path.display(),
                        device.valid,
                        device.pool_uuid.unwrap_or_else(|| "-".to_string()),
                        device.disk_id.unwrap_or_else(|| "-".to_string()),
                        device
                            .generation
                            .map(|value| value.to_string())
                            .unwrap_or_else(|| "-".to_string()),
                        device
                            .clean
                            .map(|value| value.to_string())
                            .unwrap_or_else(|| "-".to_string()),
                        device
                            .error
                            .map(|err| format!(" error={err}"))
                            .unwrap_or_default()
                    );
                }
            }
        }
        Command::InspectDevice { path, backend } => {
            let (superblock, label) = crate::raw_store::inspect_device(backend, path)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "superblock": {
                        "pool_uuid": superblock.pool_uuid.to_string(),
                        "device_uuid": superblock.device_uuid.to_string(),
                        "disk_id": superblock.disk_id,
                        "disk_index": superblock.disk_index,
                        "k": superblock.k,
                        "m": superblock.m,
                        "chunk_size": superblock.chunk_size,
                        "generation": superblock.generation,
                        "clean": superblock.clean,
                        "journal": {"offset": superblock.journal.offset, "length": superblock.journal.length},
                        "metadata": {"offset": superblock.metadata.offset, "length": superblock.metadata.length},
                        "allocator": {"offset": superblock.allocator.offset, "length": superblock.allocator.length},
                        "data": {"offset": superblock.data.offset, "length": superblock.data.length},
                        "backup_superblock_offset": superblock.backup_superblock_offset,
                        "label": superblock.label
                    },
                    "label": {
                        "pool_uuid": label.pool_uuid.to_string(),
                        "device_uuid": label.device_uuid.to_string(),
                        "disk_id": label.disk_id,
                        "disk_index": label.disk_index,
                        "generation": label.generation,
                        "label": label.label
                    }
                }))?
            );
        }
        Command::InspectPool { storage } => {
            let storage = storage.resolve(BackendKind::LoopBlock)?;
            let fs = open_backend(
                None,
                storage.backend,
                storage.images,
                storage.devices,
                false,
            )?;
            validate_requested_pool(&fs, storage.pool.as_deref())?;
            print_health_report(&fs.health_report(), json, true)?;
        }
        Command::ListDevices { storage } => {
            let storage = storage.resolve(BackendKind::LoopBlock)?;
            let fs = open_backend(
                None,
                storage.backend,
                storage.images,
                storage.devices,
                false,
            )?;
            validate_requested_pool(&fs, storage.pool.as_deref())?;
            println!(
                "{}",
                serde_json::to_string_pretty(&fs.metadata_snapshot().disks)?
            );
        }
        Command::AddDevice {
            storage,
            device,
            image_size,
            force,
        } => {
            let storage = storage.resolve(BackendKind::LoopBlock)?;
            let image_size = block_image_size(storage.backend, image_size)?;
            let fs = open_backend(None, storage.backend, storage.images, storage.devices, true)?;
            validate_requested_pool(&fs, storage.pool.as_deref())?;
            let disk_id = fs.add_block_device(device, image_size, force)?;
            fs.sync()?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({"disk_id": disk_id}))?
            );
        }
        Command::DrainDevice { storage, device } => {
            let storage = storage.resolve(BackendKind::LoopBlock)?;
            let fs = open_backend(None, storage.backend, storage.images, storage.devices, true)?;
            validate_requested_pool(&fs, storage.pool.as_deref())?;
            let rewritten = fs.drain_disk(&device)?;
            fs.sync()?;
            println!(
                "{}",
                serde_json::to_string_pretty(
                    &serde_json::json!({"disk_id": device, "rewritten_files": rewritten})
                )?
            );
        }
        Command::ReplaceDevice {
            storage,
            old,
            new,
            image_size,
            force,
        } => {
            let storage = storage.resolve(BackendKind::LoopBlock)?;
            let backend = storage.backend;
            let pool = storage.pool;
            let mut images = storage.images;
            let mut devices = storage.devices;
            let image_size = block_image_size(backend, image_size)?;
            let fs = open_backend(None, backend, images.clone(), devices.clone(), true)?;
            validate_requested_pool(&fs, pool.as_deref())?;
            let new_id = fs.add_block_device(new.clone(), image_size, force)?;
            fs.sync()?;
            drop(fs);
            match backend {
                BackendKind::LoopBlock => images.push(new),
                BackendKind::RawBlock => devices.push(new),
                BackendKind::Host => bail!("replace-device is only supported for loop/raw pools"),
            }
            let fs = open_backend(None, backend, images, devices, true)?;
            validate_requested_pool(&fs, pool.as_deref())?;
            let rewritten = fs.remove_disk(&old)?;
            fs.sync()?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "old_disk_id": old,
                    "new_disk_id": new_id,
                    "rewritten_files": rewritten
                }))?
            );
        }
        Command::RemoveDevice { storage, device } => {
            let storage = storage.resolve(BackendKind::LoopBlock)?;
            let fs = open_backend(None, storage.backend, storage.images, storage.devices, true)?;
            validate_requested_pool(&fs, storage.pool.as_deref())?;
            let rewritten = fs.remove_disk(&device)?;
            fs.sync()?;
            println!(
                "{}",
                serde_json::to_string_pretty(
                    &serde_json::json!({"disk_id": device, "rewritten_files": rewritten})
                )?
            );
        }
        Command::Mount {
            root,
            mountpoint,
            foreground,
            option,
        } => {
            fusefs::mount(root, mountpoint, foreground, option)?;
        }
        Command::MountRoot {
            storage,
            target,
            mode,
            foreground,
            option,
        } => {
            let storage = storage.resolve(BackendKind::LoopBlock)?;
            let backend = storage.backend;
            let images = storage.images;
            let devices = storage.devices;
            let pool = storage.pool;
            let write = matches!(
                mode,
                RootMountMode::ReadWrite | RootMountMode::DegradedReadWrite
            );
            if write {
                let preflight_fs =
                    open_backend(None, backend, images.clone(), devices.clone(), false)?;
                validate_requested_pool(&preflight_fs, pool.as_deref())?;
                rootfs::preflight_volume(&preflight_fs, mode)?;
                let fs = open_backend(None, backend, images, devices, true)?;
                validate_requested_pool(&fs, pool.as_deref())?;
                fusefs::mount_volume(fs, target, foreground, root_mount_options(option))?;
            } else {
                let fs = open_backend(None, backend, images, devices, false)?;
                validate_requested_pool(&fs, pool.as_deref())?;
                rootfs::preflight_volume(&fs, mode)?;
                fusefs::mount_volume(fs, target, foreground, root_mount_options(option))?;
            }
        }
        Command::PreflightRoot { storage, mode } => {
            let storage = storage.resolve(BackendKind::LoopBlock)?;
            let fs = open_backend(
                None,
                storage.backend,
                storage.images,
                storage.devices,
                false,
            )?;
            validate_requested_pool(&fs, storage.pool.as_deref())?;
            let report = rootfs::preflight_report(&fs, mode);
            print_preflight_report(&report, json)?;
            if !report.ok {
                bail!("root preflight failed: {}", report.errors.join("; "));
            }
        }
        Command::ReplayJournal { storage } => {
            let storage = storage.resolve(BackendKind::LoopBlock)?;
            let fs = open_backend(None, storage.backend, storage.images, storage.devices, true)?;
            validate_requested_pool(&fs, storage.pool.as_deref())?;
            let report = fs.transaction_report()?;
            fs.sync()?;
            print_transaction_report(&report, json)?;
        }
        Command::MountRecovery { storage, target } => {
            let storage = storage.resolve(BackendKind::LoopBlock)?;
            let fs = open_backend(
                None,
                storage.backend,
                storage.images,
                storage.devices,
                false,
            )?;
            validate_requested_pool(&fs, storage.pool.as_deref())?;
            rootfs::preflight_volume(&fs, RootMountMode::Recovery)?;
            fusefs::mount_volume(fs, target, true, root_mount_options(vec!["ro".to_string()]))?;
        }
        Command::Put { root, local, path } => {
            let fs = ArgosFs::open(root)?;
            let data = fs::read(&local).with_context(|| format!("read {}", local.display()))?;
            let mode = fs::metadata(&local)
                .map(|m| m.permissions().mode() & 0o7777)
                .unwrap_or(0o644);
            fs.write_file(&path, &data, mode)?;
        }
        Command::Get { root, path, local } => {
            let fs = ArgosFs::open(root)?;
            let data = fs.read_file(&path, true)?;
            if let Some(parent) = local.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::write(local, data)?;
        }
        Command::Cat { root, path } => {
            let fs = ArgosFs::open(root)?;
            let file_bytes = fs.read_file(&path, true)?;
            io::copy(&mut file_bytes.as_slice(), &mut io::stdout().lock())?;
        }
        Command::Ls { root, path } => {
            let fs = ArgosFs::open(root)?;
            let ino = fs.resolve_path(&path, true)?;
            let entries = fs.readdir(ino)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&entries)?);
            } else {
                for entry in entries
                    .into_iter()
                    .filter(|entry| entry.name != "." && entry.name != "..")
                {
                    println!(
                        "{}\t{}\t{:o}\t{}",
                        entry.attr.ino,
                        kind_name(&entry.attr.kind),
                        entry.attr.mode,
                        entry.name
                    );
                }
            }
        }
        Command::Stat { root, path } => {
            let fs = ArgosFs::open(root)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&fs.attr_path(&path, false)?)?
            );
        }
        Command::Rm { root, path } => {
            let fs = ArgosFs::open(root)?;
            match fs.unlink_path(&path) {
                Ok(()) => {}
                Err(ArgosError::IsDirectory(_)) => fs.rmdir_path(&path)?,
                Err(err) => return Err(err.into()),
            }
        }
        Command::Mkdir { root, path, mode } => {
            ArgosFs::open(root)?.mkdir(&path, mode)?;
        }
        Command::Mknod {
            root,
            path,
            mode,
            rdev,
        } => {
            ArgosFs::open(root)?.mknod_path(&path, mode, rdev)?;
        }
        Command::Symlink { root, target, link } => {
            ArgosFs::open(root)?.symlink_path(&target, &link)?;
        }
        Command::Rename { root, old, new } => {
            ArgosFs::open(root)?.rename_path(&old, &new)?;
        }
        Command::Chmod { root, path, mode } => {
            ArgosFs::open(root)?.chmod_path(&path, mode)?;
        }
        Command::Truncate { root, path, size } => {
            ArgosFs::open(root)?.truncate_path(&path, size)?;
        }
        Command::ImportTree { storage, args } => {
            let storage = storage.resolve(BackendKind::Host)?;
            let backend = storage.backend;
            let pool = storage.pool;
            let (root, source, dest) = import_args(backend, args)?;
            validate_root_backend(root.as_deref(), backend)?;
            let fs = open_backend(root, backend, storage.images, storage.devices, true)?;
            validate_requested_pool(&fs, pool.as_deref())?;
            let _bulk_import =
                (backend != BackendKind::Host).then(|| crate::volume::bulk_import_scope(true));
            let import_result = import_tree(&fs, &source, &dest);
            let sync_result = if import_result.is_ok() {
                fs.sync()
            } else {
                Ok(())
            };
            import_result?;
            sync_result?;
        }
        Command::ExportTree { storage, args } => {
            let storage = storage.resolve(BackendKind::Host)?;
            let backend = storage.backend;
            let pool = storage.pool;
            let (root, dest) = export_args(backend, args)?;
            validate_root_backend(root.as_deref(), backend)?;
            let fs = open_backend(root, backend, storage.images, storage.devices, false)?;
            validate_requested_pool(&fs, pool.as_deref())?;
            export_tree(&fs, &dest)?;
        }
        Command::AddDisk {
            root,
            path,
            tier,
            weight,
            capacity_bytes,
            rebalance,
        } => {
            let id =
                ArgosFs::open(root)?.add_disk(path, tier, weight, capacity_bytes, rebalance)?;
            println!("{id}");
        }
        Command::ProbeDisks { root, disk_id } => {
            let probes = ArgosFs::open(root)?.refresh_disk_probe(disk_id.as_deref())?;
            println!("{}", serde_json::to_string_pretty(&probes)?);
        }
        Command::RefreshSmart { root, disk_id } => {
            let updates = ArgosFs::open(root)?.refresh_smart_health(disk_id.as_deref())?;
            println!("{}", serde_json::to_string_pretty(&updates)?);
        }
        Command::RemoveDisk { root, disk_id } => {
            let rewritten = ArgosFs::open(root)?.remove_disk(&disk_id)?;
            println!(
                "{}",
                serde_json::to_string_pretty(
                    &serde_json::json!({"disk_id": disk_id, "rewritten_files": rewritten})
                )?
            );
        }
        Command::MarkDisk {
            root,
            disk_id,
            status,
        } => {
            ArgosFs::open(root)?.mark_disk(&disk_id, status)?;
        }
        Command::SetHealth {
            root,
            disk_id,
            reallocated_sectors,
            pending_sectors,
            crc_errors,
            io_errors,
            latency_ms,
            wear_percent,
            temperature_c,
        } => {
            let fs = ArgosFs::open(root)?;
            let meta = fs.metadata_snapshot();
            let mut health = meta
                .disks
                .get(&disk_id)
                .map(|disk| disk.health.clone())
                .with_context(|| format!("unknown disk {disk_id}"))?;
            if let Some(value) = reallocated_sectors {
                health.reallocated_sectors = value;
            }
            if let Some(value) = pending_sectors {
                health.pending_sectors = value;
            }
            if let Some(value) = crc_errors {
                health.crc_errors = value;
            }
            if let Some(value) = io_errors {
                health.io_errors = value;
            }
            if let Some(value) = latency_ms {
                health.latency_ms = value;
            }
            if let Some(value) = wear_percent {
                health.wear_percent = value;
            }
            if let Some(value) = temperature_c {
                health.temperature_c = value;
            }
            fs.set_disk_health(&disk_id, health)?;
        }
        Command::Health { root } => {
            let report = ArgosFs::open(root)?.health_report();
            print_health_report(&report, json, false)?;
        }
        Command::Fsck {
            root,
            storage,
            repair,
            remove_orphans,
        } => {
            let default_backend = if root.is_some() {
                BackendKind::Host
            } else {
                BackendKind::LoopBlock
            };
            let storage = storage.resolve(default_backend)?;
            validate_root_backend(root.as_deref(), storage.backend)?;
            let fs = open_backend(
                root,
                storage.backend,
                storage.images,
                storage.devices,
                repair || remove_orphans,
            )?;
            validate_requested_pool(&fs, storage.pool.as_deref())?;
            let report = fs.fsck(repair, remove_orphans)?;
            if repair || remove_orphans {
                fs.sync()?;
            }
            print_fsck_report(&report, json)?;
        }
        Command::Scrub { root, storage } => {
            let default_backend = if root.is_some() {
                BackendKind::Host
            } else {
                BackendKind::LoopBlock
            };
            let storage = storage.resolve(default_backend)?;
            validate_root_backend(root.as_deref(), storage.backend)?;
            let fs = open_backend(root, storage.backend, storage.images, storage.devices, true)?;
            validate_requested_pool(&fs, storage.pool.as_deref())?;
            let report = fs.scrub()?;
            fs.sync()?;
            print_fsck_report(&report, json)?;
        }
        Command::Rebalance { root } => {
            let rewritten = ArgosFs::open(root)?.rebalance()?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({"rewritten_files": rewritten}))?
            );
        }
        Command::Reshape {
            root,
            storage,
            k,
            m,
            max_files,
        } => {
            let default_backend = if root.is_some() {
                BackendKind::Host
            } else {
                BackendKind::LoopBlock
            };
            let storage = storage.resolve(default_backend)?;
            validate_root_backend(root.as_deref(), storage.backend)?;
            let fs = open_backend(root, storage.backend, storage.images, storage.devices, true)?;
            validate_requested_pool(&fs, storage.pool.as_deref())?;
            let report = fs.reshape_layout(k, m, max_files)?;
            fs.sync()?;
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        Command::Autopilot {
            root,
            policy,
            once,
            dry_run,
            explain,
            interval,
        } => loop {
            let fs = ArgosFs::open(&root)?;
            let autopilot_policy = load_autopilot_policy(&root, policy.as_deref())?;
            let report = if dry_run || explain {
                fs.autopilot_dry_run_with_policy(autopilot_policy)?
            } else {
                fs.autopilot_once_with_policy(autopilot_policy)?
            };
            print_autopilot_report(&report, json)?;
            if once {
                break;
            }
            if dry_run || explain {
                break;
            }
            thread::sleep(Duration::from_secs(interval));
        },
        Command::Snapshot { root, name } => {
            let path = ArgosFs::open(root)?.snapshot(&name)?;
            println!("{}", path.display());
        }
        Command::EnableEncryption {
            root,
            passphrase,
            key_file,
            passphrase_stdin,
            reencrypt,
        } => {
            let passphrase = load_passphrase(passphrase, key_file, passphrase_stdin)?;
            let fs = ArgosFs::open(root)?;
            fs.enable_encryption(&passphrase)?;
            std::env::set_var("ARGOSFS_KEY", &passphrase);
            let rewritten = if reencrypt { fs.rebalance()? } else { 0 };
            println!(
                "{}",
                serde_json::to_string_pretty(
                    &serde_json::json!({"encryption_enabled": true, "rewritten_files": rewritten})
                )?
            );
        }
        Command::EncryptionStatus { root } => {
            let meta = ArgosFs::open(root)?.metadata_snapshot();
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "enabled": meta.encryption.enabled,
                    "kdf": meta.encryption.kdf,
                    "encrypted_blocks": meta
                        .inodes
                        .values()
                        .flat_map(|inode| inode.blocks.iter())
                        .filter(|block| block.encrypted)
                        .count()
                }))?
            );
        }
        Command::SetIoMode {
            root,
            mode,
            direct_io,
            no_zero_copy,
            no_numa,
        } => {
            let fs = ArgosFs::open(root)?;
            fs.set_io_policy(
                mode,
                direct_io || mode == IoMode::Direct,
                !no_zero_copy,
                !no_numa,
            )?;
            println!(
                "{}",
                serde_json::to_string_pretty(&fs.metadata_snapshot().config)?
            );
        }
        Command::Prometheus { root, listen } => {
            let fs = ArgosFs::open(root)?;
            metrics::serve(fs, &listen)?;
        }
        Command::SetPosixAcl {
            root,
            path,
            acl,
            default_acl,
        } => {
            let fs = ArgosFs::open(root)?;
            fs.set_posix_acl_path(&path, default_acl, acl::parse_posix_acl(&acl)?)?;
        }
        Command::GetPosixAcl {
            root,
            path,
            default_acl,
        } => {
            let fs = ArgosFs::open(root)?;
            let acl = fs
                .get_posix_acl_path(&path, default_acl)?
                .unwrap_or_default();
            println!("{}", acl::format_posix_acl(&acl));
        }
        Command::SetNfs4Acl {
            root,
            path,
            acl_json,
        } => {
            let fs = ArgosFs::open(root)?;
            let acl_json = load_inline_or_file(&acl_json)?;
            fs.set_nfs4_acl_path(&path, acl::parse_nfs4_acl_json(&acl_json)?)?;
        }
        Command::GetNfs4Acl { root, path } => {
            let fs = ArgosFs::open(root)?;
            let acl = fs.get_nfs4_acl_path(&path)?.unwrap_or_default();
            println!("{}", acl::nfs4_to_json(&acl)?);
        }
        Command::VerifyJournal { root, storage } => {
            let default_backend = if root.is_some() {
                BackendKind::Host
            } else {
                BackendKind::LoopBlock
            };
            let storage = storage.resolve(default_backend)?;
            validate_root_backend(root.as_deref(), storage.backend)?;
            let fs = open_backend(
                root,
                storage.backend,
                storage.images,
                storage.devices,
                false,
            )?;
            validate_requested_pool(&fs, storage.pool.as_deref())?;
            let report = fs.transaction_report()?;
            print_transaction_report(&report, json)?;
            if report.invalid_entries > 0 || report.double_write_mismatches > 0 {
                bail!(
                    "journal verification failed: invalid_entries={} double_write_mismatches={}",
                    report.invalid_entries,
                    report.double_write_mismatches
                );
            }
        }
        Command::CompactJournal { root } => {
            journal::compact_journal(&root)?;
            let report = ArgosFs::audit_transactions(root)?;
            print_transaction_report(&report, json)?;
            if report.invalid_entries > 0 || report.double_write_mismatches > 0 {
                bail!(
                    "journal verification failed after compaction: invalid_entries={} double_write_mismatches={}",
                    report.invalid_entries,
                    report.double_write_mismatches
                );
            }
        }
    }
    Ok(())
}

fn require_paths(paths: Vec<PathBuf>, message: &str) -> Result<Vec<PathBuf>> {
    if paths.is_empty() {
        bail!("{message}");
    }
    Ok(paths)
}

fn load_autopilot_policy(root: &Path, requested: Option<&Path>) -> Result<AutopilotPolicy> {
    if let Some(path) = requested {
        return Ok(AutopilotPolicy::load_json(path)?);
    }
    let default_path = AutopilotPolicy::default_path(root);
    Ok(AutopilotPolicy::load_optional_json(&default_path)?.unwrap_or_default())
}

fn backend_paths(
    backend: BackendKind,
    images: Vec<PathBuf>,
    devices: Vec<PathBuf>,
) -> Result<Vec<PathBuf>> {
    match backend {
        BackendKind::Host => bail!("host backend uses a volume ROOT, not --images/--devices"),
        BackendKind::LoopBlock => require_paths(images, "loop backend requires --images"),
        BackendKind::RawBlock => {
            if devices.is_empty() {
                let discovered = scan::discover_raw_devices();
                if discovered.is_empty() {
                    bail!("raw scan found no /dev/disk/by-id or /dev/disk/by-uuid candidates; pass --devices explicitly");
                }
                Ok(discovered)
            } else {
                Ok(devices)
            }
        }
    }
}

fn open_backend(
    root: Option<PathBuf>,
    backend: BackendKind,
    images: Vec<PathBuf>,
    devices: Vec<PathBuf>,
    write: bool,
) -> Result<ArgosFs> {
    Ok(match backend {
        BackendKind::Host => ArgosFs::open(root.context("host backend requires ROOT")?)?,
        BackendKind::LoopBlock => ArgosFs::open_loop(
            &require_paths(images, "loop backend requires --images")?,
            write,
        )?,
        BackendKind::RawBlock => ArgosFs::open_raw(
            &require_paths(devices, "raw backend requires --devices")?,
            write,
        )?,
    })
}

fn import_args(
    backend: BackendKind,
    args: Vec<PathBuf>,
) -> Result<(Option<PathBuf>, PathBuf, String)> {
    match backend {
        BackendKind::Host => {
            if args.len() < 2 || args.len() > 3 {
                bail!("host import-tree syntax: import-tree ROOT SOURCE [DEST]");
            }
            let dest = args
                .get(2)
                .map(|path| path_to_cli_string(path))
                .unwrap_or_else(|| "/".to_string());
            Ok((Some(args[0].clone()), args[1].clone(), dest))
        }
        BackendKind::LoopBlock | BackendKind::RawBlock => {
            if args.is_empty() || args.len() > 2 {
                bail!("block import-tree syntax: import-tree --backend loop|raw --images/--devices SOURCE [DEST]");
            }
            let dest = args
                .get(1)
                .map(|path| path_to_cli_string(path))
                .unwrap_or_else(|| "/".to_string());
            Ok((None, args[0].clone(), dest))
        }
    }
}

fn export_args(backend: BackendKind, args: Vec<PathBuf>) -> Result<(Option<PathBuf>, PathBuf)> {
    match backend {
        BackendKind::Host => {
            if args.len() != 2 {
                bail!("host export-tree syntax: export-tree ROOT DEST");
            }
            Ok((Some(args[0].clone()), args[1].clone()))
        }
        BackendKind::LoopBlock | BackendKind::RawBlock => {
            if args.len() != 1 {
                bail!("block export-tree syntax: export-tree --backend loop|raw --images/--devices DEST");
            }
            Ok((None, args[0].clone()))
        }
    }
}

fn path_to_cli_string(path: &Path) -> String {
    path.as_os_str().to_string_lossy().to_string()
}

fn validate_requested_pool(fs: &ArgosFs, pool: Option<&str>) -> Result<()> {
    let Some(pool) = pool else {
        return Ok(());
    };
    let meta = fs.metadata_snapshot();
    if meta.uuid == pool || meta.raw_pool.pool_name == pool {
        Ok(())
    } else {
        bail!(
            "opened ArgosFS pool is {} ({}) but --pool requested {pool}",
            meta.uuid,
            meta.raw_pool.pool_name
        )
    }
}

fn root_mount_options(mut options: Vec<String>) -> Vec<String> {
    let has_acl = options
        .iter()
        .any(|option| option == "allow_other" || option == "allow_root");
    if !has_acl {
        options.push("allow_other".to_string());
    }
    options
}

fn load_passphrase(
    passphrase: Option<String>,
    key_file: Option<PathBuf>,
    passphrase_stdin: bool,
) -> Result<String> {
    if passphrase.is_some() as u8 + key_file.is_some() as u8 + passphrase_stdin as u8 > 1 {
        bail!("choose only one of --passphrase, --key-file, or --passphrase-stdin");
    }
    if let Some(passphrase) = passphrase {
        eprintln!("warning: --passphrase is visible in argv and shell history; prefer --key-file or --passphrase-stdin");
        return Ok(passphrase);
    }
    if let Some(path) = key_file {
        return Ok(fs::read_to_string(path)?
            .trim_end_matches(['\r', '\n'])
            .to_string());
    }
    if passphrase_stdin {
        let mut passphrase = String::new();
        io::stdin().read_to_string(&mut passphrase)?;
        return Ok(passphrase.trim_end_matches(['\r', '\n']).to_string());
    }
    crypto::passphrase_from_env()?
        .context("provide --key-file, --passphrase-stdin, ARGOSFS_KEY, ARGOSFS_KEY_FILE, or testing-only --passphrase")
}

fn load_inline_or_file(value: &str) -> Result<String> {
    if let Some(path) = value.strip_prefix('@') {
        Ok(fs::read_to_string(path)?)
    } else {
        Ok(value.to_string())
    }
}

fn kind_name(kind: &NodeKind) -> &'static str {
    match kind {
        NodeKind::File => "file",
        NodeKind::Directory => "dir",
        NodeKind::Symlink => "symlink",
        NodeKind::Special => "special",
    }
}

fn print_autopilot_report(report: &serde_json::Value, explicit_json: bool) -> Result<()> {
    if explicit_json {
        println!("{}", serde_json::to_string(report)?);
        return Ok(());
    }
    if !io::stdout().is_terminal() {
        println!("{}", serde_json::to_string_pretty(report)?);
        return Ok(());
    }

    for line in autopilot_summary_lines(report) {
        println!("{line}");
    }
    Ok(())
}

fn autopilot_summary_lines(report: &serde_json::Value) -> Vec<String> {
    let health = report.get("health").unwrap_or(&serde_json::Value::Null);
    let volume = health
        .get("volume_uuid")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("unknown");
    let txid = health
        .get("txid")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or_default();
    let adaptive_mode = report
        .pointer("/planner/adaptive_mode")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("unknown");
    let stopped = report
        .pointer("/planner/stopped_for_conflict")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);

    if let Some(decisions) = report
        .get("decisions")
        .and_then(serde_json::Value::as_array)
    {
        let mut lines = vec![format!(
            "autopilot volume={volume} txid={txid} decisions={} mode={adaptive_mode} stopped_for_conflict={stopped}",
            decisions.len()
        )];
        for decision in decisions {
            let target = decision
                .get("target")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("unknown");
            let action = decision
                .get("chosen_action")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("unknown");
            let utility = decision
                .get("expected_utility")
                .and_then(serde_json::Value::as_f64);
            let rejected = decision
                .get("rejected_actions")
                .and_then(serde_json::Value::as_array)
                .map(Vec::as_slice)
                .unwrap_or(&[]);
            let mut line = match utility {
                Some(utility) => format!("  {target}: {action} (expected_utility={utility:.2})"),
                None => format!("  {target}: {action}"),
            };
            if let Some(first_rejection) = rejected.first() {
                let rejected_action = first_rejection
                    .get("action")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("candidate");
                let reason = first_rejection
                    .get("reason")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("rejected by policy");
                line.push_str(&format!("; {rejected_action} rejected: {reason}"));
                if rejected.len() > 1 {
                    line.push_str(&format!(" (+{} more)", rejected.len() - 1));
                }
            }
            lines.push(line);
        }
        return lines;
    }

    let actions = report
        .get("actions")
        .and_then(serde_json::Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or(&[]);
    let mut lines = vec![format!(
        "autopilot volume={volume} txid={txid} actions={} mode={adaptive_mode} stopped_for_conflict={stopped}",
        actions.len()
    )];
    for action in actions {
        let name = action
            .get("action")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("unknown");
        let detail = action
            .get("error")
            .or_else(|| action.get("reason"))
            .and_then(serde_json::Value::as_str);
        lines.push(match detail {
            Some(detail) => format!("  {name}: {detail}"),
            None => format!("  {name}"),
        });
    }
    lines
}

fn structured_json_requested(explicit_json: bool) -> bool {
    explicit_json || !io::stdout().is_terminal()
}

fn print_health_report(
    report: &HealthReport,
    explicit_json: bool,
    json_when_redirected: bool,
) -> Result<()> {
    if explicit_json || (json_when_redirected && !io::stdout().is_terminal()) {
        println!("{}", serde_json::to_string_pretty(report)?);
        return Ok(());
    }
    println!(
        "volume {}: txid={} files={} directories={} devices={} io={:?} encryption={}",
        report.volume_uuid,
        report.txid,
        report.files,
        report.directories,
        report.disks.len(),
        report.io_mode,
        report.encryption_enabled
    );
    for disk in &report.disks {
        println!(
            "  {} status={:?} tier={:?} used={}/{} risk={:.2} predicted_failure={}",
            disk.id,
            disk.status,
            disk.tier,
            disk.used_bytes,
            disk.capacity_bytes,
            disk.risk_score,
            disk.predicted_failure
        );
    }
    Ok(())
}

fn print_fsck_report(report: &FsckReport, explicit_json: bool) -> Result<()> {
    if structured_json_requested(explicit_json) {
        println!("{}", serde_json::to_string_pretty(report)?);
        return Ok(());
    }
    println!(
        "checked files={} directories={} damaged={} repaired={} unrecoverable={} missing_shards={} checksum_errors={} orphans={}",
        report.files_checked,
        report.directories_checked,
        report.damaged_files,
        report.repaired_files,
        report.unrecoverable_files,
        report.missing_shards,
        report.checksum_errors,
        report.orphan_shards
    );
    for error in &report.errors {
        eprintln!("error: {error}");
    }
    Ok(())
}

fn print_transaction_report(report: &TransactionReport, explicit_json: bool) -> Result<()> {
    if structured_json_requested(explicit_json) {
        println!("{}", serde_json::to_string_pretty(report)?);
        return Ok(());
    }
    println!(
        "journal valid={} invalid={} last_txid={} generation={} replayed={} metadata_source={} quorum={}",
        report.valid_entries,
        report.invalid_entries,
        report.last_valid_txid,
        report.last_valid_generation,
        report.replayed,
        report.selected_metadata_source,
        report
            .raw_journal_quorum
            .map(|value| value.to_string())
            .unwrap_or_else(|| "n/a".to_string())
    );
    for error in &report.errors {
        eprintln!("error: {error}");
    }
    Ok(())
}

fn print_preflight_report(report: &rootfs::RootPreflightReport, explicit_json: bool) -> Result<()> {
    if structured_json_requested(explicit_json) {
        println!("{}", serde_json::to_string_pretty(report)?);
        return Ok(());
    }
    println!(
        "preflight ok={} backend={:?} mode={} available={}/{} degraded={} recommended_mode={}",
        report.ok,
        report.backend,
        report.mode,
        report.available_devices,
        report.total_devices,
        report.degraded,
        report.recommended_mode
    );
    for issue in &report.issues {
        println!("  {} [{}] {}", issue.severity, issue.code, issue.message);
    }
    Ok(())
}

fn validate_root_backend(root: Option<&Path>, backend: BackendKind) -> Result<()> {
    match (backend, root) {
        (BackendKind::Host, None) => bail!(
            "host backend requires ROOT; use --images, --devices, or --pool-config for a block-backed volume"
        ),
        (BackendKind::LoopBlock | BackendKind::RawBlock, Some(_)) => bail!(
            "ROOT is only valid for the host backend and cannot be combined with a loop/raw selector"
        ),
        _ => Ok(()),
    }
}

fn reject_option(present: bool, option: &str, backend: BackendKind) -> Result<()> {
    if present {
        bail!("{option} is not valid for the {} backend", backend.as_str());
    }
    Ok(())
}

fn block_image_size(backend: BackendKind, requested: Option<u64>) -> Result<u64> {
    match backend {
        BackendKind::LoopBlock => Ok(requested.unwrap_or(DEFAULT_LOOP_IMAGE_SIZE)),
        BackendKind::RawBlock => {
            reject_option(requested.is_some(), "--image-size", backend)?;
            Ok(0)
        }
        BackendKind::Host => bail!("device lifecycle commands require the loop or raw backend"),
    }
}

fn parse_byte_size_u64(value: &str) -> std::result::Result<u64, String> {
    let value = value.trim();
    if value.is_empty() {
        return Err("size cannot be empty".to_string());
    }
    let split = value
        .find(|ch: char| !ch.is_ascii_digit() && ch != '_')
        .unwrap_or(value.len());
    let number = value[..split].replace('_', "");
    if number.is_empty() {
        return Err(format!("invalid size: {value}"));
    }
    let suffix = value[split..].trim().to_ascii_lowercase();
    let multiplier = match suffix.as_str() {
        "" | "b" => 1,
        "k" | "kb" => 1_000,
        "m" | "mb" => 1_000_000,
        "g" | "gb" => 1_000_000_000,
        "t" | "tb" => 1_000_000_000_000,
        "ki" | "kib" => 1_u64 << 10,
        "mi" | "mib" => 1_u64 << 20,
        "gi" | "gib" => 1_u64 << 30,
        "ti" | "tib" => 1_u64 << 40,
        _ => {
            return Err(format!(
                "unknown size suffix {suffix:?}; use bytes, KiB, MiB, GiB, TiB, KB, MB, GB, or TB"
            ))
        }
    };
    number
        .parse::<u64>()
        .map_err(|err| format!("invalid size {value:?}: {err}"))?
        .checked_mul(multiplier)
        .ok_or_else(|| format!("size {value:?} is too large"))
}

fn parse_byte_size_usize(value: &str) -> std::result::Result<usize, String> {
    let parsed = parse_byte_size_u64(value)?;
    usize::try_from(parsed).map_err(|_| format!("size {value:?} does not fit this platform"))
}

fn parse_u32_auto(value: &str) -> std::result::Result<u32, String> {
    let trimmed = value.trim();
    if let Some(rest) = trimmed.strip_prefix("0o") {
        u32::from_str_radix(rest, 8).map_err(|err| err.to_string())
    } else if let Some(rest) = trimmed.strip_prefix("0x") {
        u32::from_str_radix(rest, 16).map_err(|err| err.to_string())
    } else if trimmed.chars().all(|ch| matches!(ch, '0'..='7')) && trimmed.len() >= 3 {
        u32::from_str_radix(trimmed, 8).map_err(|err| err.to_string())
    } else {
        trimmed.parse::<u32>().map_err(|err| err.to_string())
    }
}

fn parse_u64_auto(value: &str) -> std::result::Result<u64, String> {
    let trimmed = value.trim();
    if let Some(rest) = trimmed.strip_prefix("0o") {
        u64::from_str_radix(rest, 8).map_err(|err| err.to_string())
    } else if let Some(rest) = trimmed.strip_prefix("0x") {
        u64::from_str_radix(rest, 16).map_err(|err| err.to_string())
    } else if trimmed.chars().all(|ch| matches!(ch, '0'..='7')) && trimmed.len() >= 3 {
        u64::from_str_radix(trimmed, 8).map_err(|err| err.to_string())
    } else {
        trimmed.parse::<u64>().map_err(|err| err.to_string())
    }
}

#[cfg(test)]
mod tests;
