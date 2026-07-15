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
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;
    use tempfile::tempdir;

    #[test]
    fn discovery_deduplicates_aliases_and_keeps_broken_links() {
        let dir = tempdir().unwrap();
        let by_id = dir.path().join("by-id");
        let by_uuid = dir.path().join("by-uuid");
        fs::create_dir_all(&by_id).unwrap();
        fs::create_dir_all(&by_uuid).unwrap();
        let device = dir.path().join("device.img");
        fs::write(&device, b"device").unwrap();
        symlink(&device, by_id.join("disk-a")).unwrap();
        symlink(&device, by_uuid.join("uuid-a")).unwrap();
        symlink(dir.path().join("missing"), by_id.join("broken")).unwrap();

        let found = discover_devices_in_roots([by_id, by_uuid, dir.path().join("absent-root")]);
        assert_eq!(found.len(), 2);
        assert!(found.iter().any(|path| path.ends_with("disk-a")));
        assert!(found.iter().any(|path| path.ends_with("broken")));
    }

    #[test]
    fn image_and_raw_scanners_report_invalid_inputs() {
        let dir = tempdir().unwrap();
        let image = dir.path().join("invalid.img");
        let missing = dir.path().join("missing.img");
        fs::write(&image, b"not-an-argosfs-device").unwrap();
        let paths = vec![image.clone(), missing.clone()];

        let images = scan_images(&paths);
        let devices = scan_devices(&paths);
        assert_eq!(images.len(), 2);
        assert_eq!(devices.len(), 2);
        assert_eq!(images[0].path, image);
        assert_eq!(devices[1].path, missing);
        assert!(images.iter().all(|entry| !entry.valid));
        assert!(devices.iter().all(|entry| !entry.valid));
    }
}
