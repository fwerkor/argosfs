use argosfs::acl;
use argosfs::backend::FileBlockBackend;
use argosfs::cache::BlockCache;
use argosfs::crypto;
use argosfs::journal;
use argosfs::raw_format::{
    DEVICE_LABEL_OFFSET, JOURNAL_REGION_OFFSET, METADATA_REGION_OFFSET, PRIMARY_SUPERBLOCK_OFFSET,
    SUPERBLOCK_SIZE,
};
use argosfs::types::{
    BackendKind, Compression, DiskStatus, IoMode, Metadata, RawFreeExtent, ShardLocation,
    StorageTier, VolumeConfig,
};
use argosfs::util::{content_hash_hex, directory_size, sha256_hex};
use argosfs::{ArgosError, ArgosFs, AutopilotConfig, AutopilotPolicy};
use serde::Serialize;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::Write;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::FileExt;
use std::process::{Command, Stdio};
use std::sync::{Mutex, OnceLock};
use tempfile::TempDir;

fn config(k: usize, m: usize) -> VolumeConfig {
    VolumeConfig {
        k,
        m,
        chunk_size: 1024,
        compression: Compression::Lz4,
        compression_level: 0,
        l2_cache_bytes: 0,
        fsname: "argosfs-test".to_string(),
        ..VolumeConfig::default()
    }
}

fn loop_images(tmp: &TempDir, count: usize) -> Vec<std::path::PathBuf> {
    (0..count)
        .map(|index| tmp.path().join(format!("disk{index}.img")))
        .collect()
}

fn create_rootfs_mountpoints(fs: &ArgosFs) {
    for path in ["/dev", "/proc", "/run", "/sys"] {
        fs.mkdir(path, 0o755).unwrap();
    }
}

fn shard_abs(fs: &ArgosFs, disk_id: &str, rel: &std::path::Path) -> std::path::PathBuf {
    let meta = fs.metadata_snapshot();
    let disk = meta.disks.get(disk_id).unwrap();
    if disk.path.is_absolute() {
        disk.path.join(rel)
    } else {
        fs.root().join(&disk.path).join(rel)
    }
}

fn env_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn argosfs_binary() -> String {
    std::env::var("CARGO_BIN_EXE_argosfs").unwrap_or_else(|_| {
        let mut path = std::env::current_exe().unwrap();
        path.pop();
        if path.ends_with("deps") {
            path.pop();
        }
        path.push("argosfs");
        path.to_string_lossy().to_string()
    })
}

fn tree_contains_bytes(root: &std::path::Path, needle: &[u8]) -> bool {
    root.exists()
        && walkdir::WalkDir::new(root)
            .into_iter()
            .filter_map(|entry| entry.ok())
            .filter(|entry| entry.file_type().is_file())
            .any(|entry| {
                fs::read(entry.path())
                    .is_ok_and(|data| data.windows(needle.len()).any(|window| window == needle))
            })
}

fn journal_records(root: &std::path::Path) -> Vec<serde_json::Value> {
    fs::read_to_string(root.join(".argosfs/journal.jsonl"))
        .unwrap()
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

fn raw_journal_records(image: &std::path::Path) -> Vec<serde_json::Value> {
    let (superblock, _) =
        argosfs::raw_store::inspect_device(BackendKind::LoopBlock, image.to_path_buf()).unwrap();
    let disk = std::fs::File::open(image).unwrap();
    let mut header = [0u8; 4096];
    disk.read_at(&mut header, superblock.journal.offset)
        .unwrap();
    let end = u64::from_le_bytes(header[24..32].try_into().unwrap());
    let mut cursor = 4096u64;
    let mut records = Vec::new();
    while cursor + 36 <= end {
        let mut entry_header = [0u8; 36];
        disk.read_at(&mut entry_header, superblock.journal.offset + cursor)
            .unwrap();
        let len = u32::from_le_bytes(entry_header[..4].try_into().unwrap()) as usize;
        if len == 0 || cursor + 36 + len as u64 > end {
            break;
        }
        let mut bytes = vec![0u8; len];
        disk.read_at(&mut bytes, superblock.journal.offset + cursor + 36)
            .unwrap();
        records.push(serde_json::from_slice(&bytes).unwrap());
        cursor += 36 + len as u64;
    }
    records
}

#[path = "integration/block_backend.rs"]
mod block_backend;
#[path = "integration/journal.rs"]
mod journal_tests;
#[path = "integration/layout_io.rs"]
mod layout_io;
#[path = "integration/namespace.rs"]
mod namespace;
#[path = "integration/repair_autopilot.rs"]
mod repair_autopilot;
#[path = "integration/security_io_cache.rs"]
mod security_io_cache;
