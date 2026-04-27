use anyhow::{bail, Context, Result};
use argosfs::acl;
use argosfs::crypto;
use argosfs::fusefs;
use argosfs::metrics;
use argosfs::types::{Compression, DiskStatus, IoMode, StorageTier, VolumeConfig};
use argosfs::ArgosFs;
use clap::{Parser, Subcommand};
use std::ffi::CString;
use std::fs;
use std::io::{self, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Duration;

#[derive(Parser)]
#[command(name = "argosfs")]
#[command(about = "ArgosFS self-driving erasure-coded root filesystem")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Mkfs {
        root: PathBuf,
        #[arg(long, default_value_t = 6)]
        disks: usize,
        #[arg(long, default_value_t = 4)]
        k: usize,
        #[arg(long, default_value_t = 2)]
        m: usize,
        #[arg(long, default_value_t = 256 * 1024)]
        chunk_size: usize,
        #[arg(long, default_value = "zstd")]
        compression: Compression,
        #[arg(long, default_value_t = 3)]
        compression_level: i32,
        #[arg(long)]
        force: bool,
    },
    Mount {
        root: PathBuf,
        mountpoint: PathBuf,
        #[arg(long)]
        foreground: bool,
        #[arg(short = 'o', long = "option")]
        option: Vec<String>,
    },
    Put {
        root: PathBuf,
        local: PathBuf,
        path: String,
    },
    Get {
        root: PathBuf,
        path: String,
        local: PathBuf,
    },
    Cat {
        root: PathBuf,
        path: String,
    },
    Ls {
        root: PathBuf,
        #[arg(default_value = "/")]
        path: String,
        #[arg(long)]
        json: bool,
    },
    Stat {
        root: PathBuf,
        path: String,
    },
    Rm {
        root: PathBuf,
        path: String,
    },
    Mkdir {
        root: PathBuf,
        path: String,
        #[arg(long, default_value = "755", value_parser = parse_u32_auto)]
        mode: u32,
    },
    Mknod {
        root: PathBuf,
        path: String,
        #[arg(long, value_parser = parse_u32_auto)]
        mode: u32,
        #[arg(long, default_value = "0", value_parser = parse_u32_auto)]
        rdev: u32,
    },
    Symlink {
        root: PathBuf,
        target: String,
        link: String,
    },
    Rename {
        root: PathBuf,
        old: String,
        new: String,
    },
    Chmod {
        root: PathBuf,
        path: String,
        #[arg(value_parser = parse_u32_auto)]
        mode: u32,
    },
    Truncate {
        root: PathBuf,
        path: String,
        size: u64,
    },
    ImportTree {
        root: PathBuf,
        source: PathBuf,
        #[arg(default_value = "/")]
        dest: String,
    },
    ExportTree {
        root: PathBuf,
        dest: PathBuf,
    },
    AddDisk {
        root: PathBuf,
        #[arg(long)]
        path: Option<PathBuf>,
        #[arg(long)]
        tier: Option<StorageTier>,
        #[arg(long)]
        weight: Option<f64>,
        #[arg(long)]
        capacity_bytes: Option<u64>,
        #[arg(long)]
        rebalance: bool,
    },
    ProbeDisks {
        root: PathBuf,
        disk_id: Option<String>,
    },
    RefreshSmart {
        root: PathBuf,
        disk_id: Option<String>,
    },
    RemoveDisk {
        root: PathBuf,
        disk_id: String,
    },
    MarkDisk {
        root: PathBuf,
        disk_id: String,
        status: DiskStatus,
    },
    SetHealth {
        root: PathBuf,
        disk_id: String,
        #[arg(long)]
        reallocated_sectors: Option<u64>,
        #[arg(long)]
        pending_sectors: Option<u64>,
        #[arg(long)]
        crc_errors: Option<u64>,
        #[arg(long)]
        io_errors: Option<u64>,
        #[arg(long)]
        latency_ms: Option<f64>,
        #[arg(long)]
        wear_percent: Option<f64>,
        #[arg(long)]
        temperature_c: Option<f64>,
    },
    Health {
        root: PathBuf,
        #[arg(long)]
        json: bool,
    },
    Fsck {
        root: PathBuf,
        #[arg(long)]
        repair: bool,
        #[arg(long)]
        remove_orphans: bool,
    },
    Scrub {
        root: PathBuf,
    },
    Rebalance {
        root: PathBuf,
    },
    Autopilot {
        root: PathBuf,
        #[arg(long)]
        once: bool,
        #[arg(long, default_value_t = 60)]
        interval: u64,
    },
    Snapshot {
        root: PathBuf,
        name: String,
    },
    EnableEncryption {
        root: PathBuf,
        #[arg(long)]
        passphrase: Option<String>,
        #[arg(long)]
        key_file: Option<PathBuf>,
        #[arg(long)]
        reencrypt: bool,
    },
    EncryptionStatus {
        root: PathBuf,
    },
    SetIoMode {
        root: PathBuf,
        #[arg(long, default_value = "buffered")]
        mode: IoMode,
        #[arg(long)]
        direct_io: bool,
        #[arg(long)]
        no_zero_copy: bool,
        #[arg(long)]
        no_numa: bool,
    },
    Prometheus {
        root: PathBuf,
        #[arg(long, default_value = "127.0.0.1:9108")]
        listen: String,
    },
    SetPosixAcl {
        root: PathBuf,
        path: String,
        acl: String,
        #[arg(long)]
        default_acl: bool,
    },
    GetPosixAcl {
        root: PathBuf,
        path: String,
        #[arg(long)]
        default_acl: bool,
    },
    SetNfs4Acl {
        root: PathBuf,
        path: String,
        acl_json: String,
    },
    GetNfs4Acl {
        root: PathBuf,
        path: String,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Mkfs {
            root,
            disks,
            k,
            m,
            chunk_size,
            compression,
            compression_level,
            force,
        } => {
            let config = VolumeConfig {
                k,
                m,
                chunk_size,
                compression,
                compression_level,
                ..VolumeConfig::default()
            };
            let fs = ArgosFs::create(root, config, disks, force)?;
            println!("{}", serde_json::to_string_pretty(&fs.health_report())?);
        }
        Command::Mount {
            root,
            mountpoint,
            foreground,
            option,
        } => {
            fusefs::mount(root, mountpoint, foreground, option)?;
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
            io::stdout().write_all(&fs.read_file(&path, true)?)?;
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
                Err(_) => fs.rmdir_path(&path)?,
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
        Command::ImportTree { root, source, dest } => {
            let fs = ArgosFs::open(root)?;
            import_tree(&fs, &source, &dest)?;
        }
        Command::ExportTree { root, dest } => {
            let fs = ArgosFs::open(root)?;
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
            repair,
            remove_orphans,
        } => {
            let report = ArgosFs::open(root)?.fsck(repair, remove_orphans)?;
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        Command::Scrub { root } => {
            let report = ArgosFs::open(root)?.scrub()?;
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        Command::Rebalance { root } => {
            let rewritten = ArgosFs::open(root)?.rebalance()?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({"rewritten_files": rewritten}))?
            );
        }
        Command::Autopilot {
            root,
            once,
            interval,
        } => {
            let fs = ArgosFs::open(root)?;
            loop {
                println!("{}", serde_json::to_string_pretty(&fs.autopilot_once()?)?);
                if once {
                    break;
                }
                thread::sleep(Duration::from_secs(interval));
            }
        }
        Command::Snapshot { root, name } => {
            let path = ArgosFs::open(root)?.snapshot(&name)?;
            println!("{}", path.display());
        }
        Command::EnableEncryption {
            root,
            passphrase,
            key_file,
            reencrypt,
        } => {
            let passphrase = load_passphrase(passphrase, key_file)?;
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
    }
    Ok(())
}

fn load_passphrase(passphrase: Option<String>, key_file: Option<PathBuf>) -> Result<String> {
    if let Some(passphrase) = passphrase {
        return Ok(passphrase);
    }
    if let Some(path) = key_file {
        return Ok(fs::read_to_string(path)?.trim_end_matches('\n').to_string());
    }
    crypto::passphrase_from_env()?
        .context("provide --passphrase, --key-file, ARGOSFS_KEY, or ARGOSFS_KEY_FILE")
}

fn load_inline_or_file(value: &str) -> Result<String> {
    if let Some(path) = value.strip_prefix('@') {
        Ok(fs::read_to_string(path)?)
    } else {
        Ok(value.to_string())
    }
}

fn import_tree(volume: &ArgosFs, source: &Path, dest: &str) -> Result<()> {
    if !source.is_dir() {
        bail!("source must be a directory: {}", source.display());
    }
    let dest = normalize_dest(dest);
    if dest != "/" {
        let _ = volume.mkdir(&dest, 0o755);
    }
    for entry in walkdir::WalkDir::new(source)
        .follow_links(false)
        .sort_by_file_name()
    {
        let entry = entry?;
        let path = entry.path();
        if path == source {
            continue;
        }
        let rel = path.strip_prefix(source)?;
        let virtual_path = if dest == "/" {
            format!("/{}", rel.to_string_lossy())
        } else {
            format!("{}/{}", dest.trim_end_matches('/'), rel.to_string_lossy())
        };
        let meta = fs::symlink_metadata(path)?;
        let ft = meta.file_type();
        let mode = meta.mode();
        if ft.is_dir() {
            let _ = volume.mkdir(&virtual_path, mode & 0o7777);
        } else if ft.is_file() {
            volume.write_file(&virtual_path, &fs::read(path)?, mode & 0o7777)?;
            let ino = volume.resolve_path(&virtual_path, false)?;
            let _ = volume.chown_inode(ino, Some(meta.uid()), Some(meta.gid()));
        } else if ft.is_symlink() {
            let target = fs::read_link(path)?;
            volume.symlink_path(&target.to_string_lossy(), &virtual_path)?;
        } else if ft.is_char_device() || ft.is_block_device() || ft.is_fifo() || ft.is_socket() {
            volume.mknod_path(&virtual_path, mode, meta.rdev() as u32)?;
        }
    }
    Ok(())
}

fn export_tree(volume: &ArgosFs, dest: &Path) -> Result<()> {
    fs::create_dir_all(dest)?;
    let mut paths = volume.iter_paths();
    paths.sort_by_key(|(path, _)| path.matches('/').count());
    for (path, ino) in paths {
        if path == "/" {
            continue;
        }
        let attr = volume.attr_inode(ino)?;
        let target = dest.join(path.trim_start_matches('/'));
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent)?;
        }
        match attr.kind {
            argosfs::types::NodeKind::Directory => {
                fs::create_dir_all(&target)?;
                fs::set_permissions(&target, fs::Permissions::from_mode(attr.mode & 0o7777))?;
            }
            argosfs::types::NodeKind::File => {
                fs::write(&target, volume.read_inode(ino, 0, u64::MAX as usize, true)?)?;
                fs::set_permissions(&target, fs::Permissions::from_mode(attr.mode & 0o7777))?;
            }
            argosfs::types::NodeKind::Symlink => {
                let link = volume.readlink_inode(ino)?;
                let _ = std::os::unix::fs::symlink(link, &target);
            }
            argosfs::types::NodeKind::Special => {
                let c_path = CString::new(target.as_os_str().as_bytes())?;
                let rc = unsafe {
                    libc::mknod(
                        c_path.as_ptr(),
                        attr.mode as libc::mode_t,
                        attr.rdev as libc::dev_t,
                    )
                };
                if rc != 0 {
                    return Err(io::Error::last_os_error())
                        .with_context(|| format!("mknod {}", target.display()));
                }
            }
        }
    }
    Ok(())
}

fn normalize_dest(dest: &str) -> String {
    let mut value = dest.trim().to_string();
    if value.is_empty() {
        value = "/".to_string();
    }
    if !value.starts_with('/') {
        value.insert(0, '/');
    }
    while value.len() > 1 && value.ends_with('/') {
        value.pop();
    }
    value
}

fn kind_name(kind: &argosfs::types::NodeKind) -> &'static str {
    match kind {
        argosfs::types::NodeKind::File => "file",
        argosfs::types::NodeKind::Directory => "dir",
        argosfs::types::NodeKind::Symlink => "symlink",
        argosfs::types::NodeKind::Special => "special",
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
