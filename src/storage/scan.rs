use crate::raw_store::{scan_paths, ScannedDevice};
use crate::types::BackendKind;
use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

pub fn scan_images(paths: &[PathBuf]) -> Vec<ScannedDevice> {
    scan_paths(BackendKind::LoopBlock, paths)
}

pub fn scan_devices(paths: &[PathBuf]) -> Vec<ScannedDevice> {
    scan_paths(BackendKind::RawBlock, paths)
}

pub fn discover_raw_devices() -> Vec<PathBuf> {
    discover_devices_in_roots([
        PathBuf::from("/dev/disk/by-id"),
        PathBuf::from("/dev/disk/by-uuid"),
    ])
}

fn discover_devices_in_roots(roots: impl IntoIterator<Item = PathBuf>) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut seen = BTreeSet::new();
    for root in roots {
        let Ok(entries) = fs::read_dir(root) else {
            continue;
        };
        for entry in entries.filter_map(|entry| entry.ok()) {
            let path = entry.path();
            let key = fs::canonicalize(&path).unwrap_or_else(|_| path.clone());
            if seen.insert(key) {
                out.push(path);
            }
        }
    }
    out
}

#[cfg(test)]
#[path = "scan_tests.rs"]
mod tests;
