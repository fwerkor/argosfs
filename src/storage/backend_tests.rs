use super::*;
use std::io::Write as _;
use tempfile::{tempdir, NamedTempFile};

#[test]
fn host_backend_reports_its_intentionally_limited_capabilities() {
    let backend = HostFsBackend::new("/tmp/argosfs-host-backend");
    let id = "unused".to_string();
    assert_eq!(backend.backend_kind(), BackendKind::Host);
    assert!(backend.list_devices().unwrap().is_empty());
    assert!(matches!(
        backend.read_at(&id, 0, &mut [0u8; 1]),
        Err(ArgosError::Unsupported(_))
    ));
    assert!(matches!(
        backend.write_at(&id, 0, b"x"),
        Err(ArgosError::Unsupported(_))
    ));
    backend.flush_device(&id).unwrap();
    backend.flush_all().unwrap();
    assert!(matches!(
        backend.capacity(&id),
        Err(ArgosError::Unsupported(_))
    ));
    assert_eq!(backend.device_status(&id).unwrap(), DiskStatus::Online);
    let capabilities = backend.capabilities();
    assert!(!capabilities.direct_io);
    assert!(capabilities.fallocate);
    assert!(!capabilities.discard);
}

fn image(size: u64) -> NamedTempFile {
    let file = NamedTempFile::new().unwrap();
    file.as_file().set_len(size).unwrap();
    file
}

#[test]
fn loop_backend_lists_reads_writes_flushes_and_reports_capacity() {
    let first = image(8192);
    let second = image(4096);
    let paths = vec![first.path().to_path_buf(), second.path().to_path_buf()];
    let backend = FileBlockBackend::open_loop(&paths, true).unwrap();
    assert_eq!(backend.backend_kind(), BackendKind::LoopBlock);
    assert_eq!(backend.paths(), paths);
    let devices = backend.list_devices().unwrap();
    assert_eq!(devices.len(), 2);
    assert_eq!(devices[0].device_id, "disk-0000");
    assert_eq!(devices[0].capacity, 8192);
    assert_eq!(devices[0].status, DiskStatus::Online);

    let id = "disk-0000".to_string();
    backend.write_at(&id, 1024, b"backend payload").unwrap();
    backend.flush_device(&id).unwrap();
    backend.flush_all().unwrap();
    let mut output = vec![0; b"backend payload".len()];
    backend.read_at(&id, 1024, &mut output).unwrap();
    assert_eq!(output, b"backend payload");
    assert_eq!(backend.capacity(&id).unwrap(), 8192);
    assert_eq!(backend.device_status(&id).unwrap(), DiskStatus::Online);
    let capabilities = backend.capabilities();
    assert!(capabilities.fallocate);
    assert!(!capabilities.discard);
}

#[test]
fn explicit_ids_and_raw_capabilities_are_preserved() {
    let file = image(4096);
    let backend = FileBlockBackend::open_with_ids(
        BackendKind::RawBlock,
        vec![("member-a".to_string(), file.path().to_path_buf())],
        true,
    )
    .unwrap();
    assert_eq!(backend.backend_kind(), BackendKind::RawBlock);
    assert_eq!(backend.list_devices().unwrap()[0].device_id, "member-a");
    assert!(backend.capabilities().discard);

    let raw = FileBlockBackend::open_raw(&[file.path().to_path_buf()], false).unwrap();
    assert_eq!(raw.backend_kind(), BackendKind::RawBlock);
    assert!(raw.capabilities().discard);
}

#[test]
fn file_backend_reports_missing_full_overflow_and_short_read_errors() {
    let file = image(16);
    let backend = FileBlockBackend::open_loop(&[file.path().to_path_buf()], true).unwrap();
    let id = "disk-0000".to_string();
    let missing = "missing".to_string();
    assert!(matches!(
        backend.capacity(&missing),
        Err(ArgosError::MissingDevice(_))
    ));
    assert!(matches!(
        backend.write_at(&id, 15, b"xx"),
        Err(ArgosError::DiskFull { .. })
    ));
    assert!(matches!(
        backend.write_at(&id, u64::MAX, b"xx"),
        Err(ArgosError::Invalid(_))
    ));
    assert!(matches!(
        backend.read_at(&id, 16, &mut [0u8; 1]),
        Err(ArgosError::Io(error)) if error.kind() == std::io::ErrorKind::UnexpectedEof
    ));
    assert!(matches!(
        backend.flush_device(&missing),
        Err(ArgosError::MissingDevice(_))
    ));
    assert!(matches!(
        backend.device_status(&missing),
        Err(ArgosError::MissingDevice(_))
    ));
}

#[test]
fn readonly_backend_rejects_writes_at_the_os_boundary() {
    let file = image(4096);
    let backend = FileBlockBackend::open_loop(&[file.path().to_path_buf()], false).unwrap();
    let id = "disk-0000".to_string();
    assert!(matches!(
        backend.write_at(&id, 0, b"x"),
        Err(ArgosError::Io(_))
    ));
}

#[test]
fn capacity_detection_handles_regular_empty_and_nonempty_files() {
    let mut nonempty = NamedTempFile::new().unwrap();
    nonempty.write_all(b"12345678").unwrap();
    nonempty.flush().unwrap();
    assert_eq!(detect_capacity(nonempty.as_file_mut()).unwrap(), 8);

    let mut empty = NamedTempFile::new().unwrap();
    assert_eq!(detect_capacity(empty.as_file_mut()).unwrap(), 0);
    assert_eq!(block_device_capacity(empty.as_file()).unwrap(), None);
}

#[test]
fn opening_missing_devices_returns_io_errors() {
    let dir = tempdir().unwrap();
    let missing = dir.path().join("missing.img");
    assert!(matches!(
        FileBlockBackend::open_loop(&[missing], false),
        Err(ArgosError::Io(_))
    ));
}
