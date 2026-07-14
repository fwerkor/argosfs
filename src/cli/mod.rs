use crate::acl;
use crate::crypto;
use crate::fusefs;
use crate::journal;
use crate::metrics;
use crate::rootfs::{self, RootMountMode};
use crate::scan;
use crate::types::{
    BackendKind, Compression, DiskStatus, IoMode, NodeKind, StorageTier, VolumeConfig,
};
use crate::util::clean_path;
use crate::volume::NodeAttr;
use crate::{ArgosError, ArgosFs, AutopilotPolicy};
use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use std::collections::BTreeMap;
use std::ffi::CString;
use std::fs;
use std::io::{self, Read};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Duration;

mod commands;
mod tree;

use commands::Command;
use tree::{export_tree, import_tree};

#[derive(Parser)]
#[command(name = "argosfs")]
#[command(about = "ArgosFS self-driving erasure-coded root filesystem")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

pub fn run() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Mkfs {
            root,
            backend,
            images,
            devices,
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
            force,
        } => {
            let config = VolumeConfig {
                k,
                m,
                chunk_size,
                compression,
                compression_level,
                defer_journal_flush,
                defer_metadata_commit,
                defer_data_flush,
                ..VolumeConfig::default()
            };
            let fs = match backend {
                BackendKind::Host => {
                    let root = root.context("host mkfs requires ROOT")?;
                    ArgosFs::create(root, config, disks, force)?
                }
                BackendKind::LoopBlock => {
                    let paths = require_paths(images, "loop mkfs requires --images")?;
                    ArgosFs::create_loop(&paths, config, image_size, &pool_name, force)?
                }
                BackendKind::RawBlock => {
                    let paths = require_paths(devices, "raw mkfs requires --devices")?;
                    ArgosFs::create_raw(&paths, config, &pool_name, force)?
                }
            };
            println!("{}", serde_json::to_string_pretty(&fs.health_report())?);
        }
        Command::Scan {
            backend,
            images,
            devices,
            json,
        } => {
            let paths = backend_paths(backend, images, devices)?;
            let report = match backend {
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
        Command::InspectPool {
            backend,
            images,
            devices,
            pool,
        } => {
            let fs = open_backend(None, backend, images, devices, false)?;
            validate_requested_pool(&fs, pool.as_deref())?;
            println!("{}", serde_json::to_string_pretty(&fs.health_report())?);
        }
        Command::ListDevices {
            backend,
            images,
            devices,
            pool,
        } => {
            let fs = open_backend(None, backend, images, devices, false)?;
            validate_requested_pool(&fs, pool.as_deref())?;
            println!(
                "{}",
                serde_json::to_string_pretty(&fs.metadata_snapshot().disks)?
            );
        }
        Command::AddDevice {
            backend,
            images,
            devices,
            pool,
            device,
            image_size,
            force,
        } => {
            let fs = open_backend(None, backend, images, devices, true)?;
            validate_requested_pool(&fs, pool.as_deref())?;
            let disk_id = fs.add_block_device(device, image_size, force)?;
            fs.sync()?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({"disk_id": disk_id}))?
            );
        }
        Command::DrainDevice {
            backend,
            images,
            devices,
            pool,
            device,
        } => {
            let fs = open_backend(None, backend, images, devices, true)?;
            validate_requested_pool(&fs, pool.as_deref())?;
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
            backend,
            mut images,
            mut devices,
            pool,
            old,
            new,
            image_size,
            force,
        } => {
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
        Command::RemoveDevice {
            backend,
            images,
            devices,
            pool,
            device,
        } => {
            let fs = open_backend(None, backend, images, devices, true)?;
            validate_requested_pool(&fs, pool.as_deref())?;
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
            backend,
            images,
            devices,
            pool,
            target,
            mode,
            foreground,
            option,
        } => {
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
        Command::PreflightRoot {
            backend,
            images,
            devices,
            pool,
            mode,
        } => {
            let fs = open_backend(None, backend, images, devices, false)?;
            validate_requested_pool(&fs, pool.as_deref())?;
            let report = rootfs::preflight_report(&fs, mode);
            println!("{}", serde_json::to_string_pretty(&report)?);
            if !report.ok {
                bail!("root preflight failed: {}", report.errors.join("; "));
            }
        }
        Command::ReplayJournal {
            backend,
            images,
            devices,
            pool,
        } => {
            let fs = open_backend(None, backend, images, devices, true)?;
            validate_requested_pool(&fs, pool.as_deref())?;
            let report = fs.transaction_report()?;
            fs.sync()?;
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        Command::MountRecovery {
            backend,
            images,
            devices,
            pool,
            target,
        } => {
            let fs = open_backend(None, backend, images, devices, false)?;
            validate_requested_pool(&fs, pool.as_deref())?;
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
        Command::Ls { root, path, json } => {
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
        Command::ImportTree {
            backend,
            images,
            devices,
            args,
        } => {
            let (root, source, dest) = import_args(backend, args)?;
            let fs = open_backend(root, backend, images, devices, true)?;
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
        Command::ExportTree {
            backend,
            images,
            devices,
            args,
        } => {
            let (root, dest) = export_args(backend, args)?;
            let fs = open_backend(root, backend, images, devices, false)?;
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
        Command::Health { root, json } => {
            let report = ArgosFs::open(root)?.health_report();
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("volume {} txid {}", report.volume_uuid, report.txid);
                for disk in report.disks {
                    println!(
                        "{} {:?} {:?} used={} risk={:.2} predicted={} {:?}",
                        disk.id,
                        disk.status,
                        disk.tier,
                        disk.used_bytes,
                        disk.risk_score,
                        disk.predicted_failure,
                        disk.reasons
                    );
                }
            }
        }
        Command::Fsck {
            root,
            backend,
            images,
            devices,
            pool,
            repair,
            remove_orphans,
        } => {
            let fs = open_backend(root, backend, images, devices, repair || remove_orphans)?;
            validate_requested_pool(&fs, pool.as_deref())?;
            let report = fs.fsck(repair, remove_orphans)?;
            if repair || remove_orphans {
                fs.sync()?;
            }
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        Command::Scrub {
            root,
            backend,
            images,
            devices,
            pool,
        } => {
            let fs = open_backend(root, backend, images, devices, true)?;
            validate_requested_pool(&fs, pool.as_deref())?;
            let report = fs.scrub()?;
            fs.sync()?;
            println!("{}", serde_json::to_string_pretty(&report)?);
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
            backend,
            images,
            devices,
            pool,
            k,
            m,
            max_files,
        } => {
            let fs = open_backend(root, backend, images, devices, true)?;
            validate_requested_pool(&fs, pool.as_deref())?;
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
            json,
            interval,
        } => loop {
            let fs = ArgosFs::open(&root)?;
            let autopilot_policy = load_autopilot_policy(&root, policy.as_deref())?;
            let report = if dry_run || explain {
                fs.autopilot_dry_run_with_policy(autopilot_policy)?
            } else {
                fs.autopilot_once_with_policy(autopilot_policy)?
            };
            if json {
                println!("{}", serde_json::to_string(&report)?);
            } else {
                println!("{}", serde_json::to_string_pretty(&report)?);
            }
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
        Command::VerifyJournal {
            root,
            backend,
            images,
            devices,
            pool,
        } => {
            let fs = open_backend(root, backend, images, devices, false)?;
            validate_requested_pool(&fs, pool.as_deref())?;
            let report = fs.transaction_report()?;
            println!("{}", serde_json::to_string_pretty(&report)?);
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
            println!("{}", serde_json::to_string_pretty(&report)?);
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
