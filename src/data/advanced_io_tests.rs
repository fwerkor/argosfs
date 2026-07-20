use super::*;
use tempfile::tempdir;

#[test]
fn buffered_and_mmap_round_trips_include_empty_files() {
    let dir = tempdir().unwrap();
    let file = dir.path().join("nested/data.bin");
    let payload = b"advanced io payload";
    write_all(&file, payload, IoMode::Buffered).unwrap();
    assert_eq!(
        read_all(&file, payload.len(), IoMode::Buffered, false).unwrap(),
        payload
    );
    assert_eq!(
        read_all(&file, payload.len(), IoMode::Buffered, true).unwrap(),
        payload
    );

    let empty = dir.path().join("empty.bin");
    write_all(&empty, b"", IoMode::Buffered).unwrap();
    assert!(read_all(&empty, 0, IoMode::Buffered, true)
        .unwrap()
        .is_empty());
}

#[test]
fn direct_mode_round_trips_aligned_data_or_falls_back_safely() {
    let dir = tempdir().unwrap();
    let file = dir.path().join("direct.bin");
    let data = vec![0x5a; ALIGN * 2];
    write_all(&file, &data, IoMode::Direct).unwrap();
    assert_eq!(
        read_all(&file, data.len(), IoMode::Direct, false).unwrap(),
        data
    );
    assert!(matches!(
        write_direct(&file, b"unaligned"),
        Err(ArgosError::Unsupported(_))
    ));
    assert!(matches!(
        write_direct(&file, b""),
        Err(ArgosError::Unsupported(_))
    ));
}

#[test]
fn direct_reads_validate_alignment_and_size_before_allocating() {
    let dir = tempdir().unwrap();
    let empty = dir.path().join("empty.bin");
    File::create(&empty).unwrap();
    assert!(matches!(
        read_direct(&empty, 0),
        Err(ArgosError::Unsupported(_))
    ));
    assert!(matches!(
        read_direct(&empty, 3),
        Err(ArgosError::Unsupported(_))
    ));
    assert!(matches!(
        read_direct(&empty, MAX_SHARD_IO_BYTES + 1),
        Err(ArgosError::FileTooLarge(_))
    ));
    assert!(matches!(
        read_iouring(&empty, MAX_SHARD_IO_BYTES + 1),
        Err(ArgosError::FileTooLarge(_))
    ));
}

#[test]
fn mmap_reader_rejects_oversized_sparse_shards() {
    let dir = tempdir().unwrap();
    let file = dir.path().join("huge.bin");
    File::create(&file)
        .unwrap()
        .set_len((MAX_SHARD_IO_BYTES + 1) as u64)
        .unwrap();
    assert!(matches!(
        read_mmap_or_buffered(&file, false),
        Err(ArgosError::FileTooLarge(_))
    ));
}

#[test]
fn aligned_buffer_exposes_mutable_and_immutable_views() {
    let mut buffer = AlignedBuf::new(ALIGN).unwrap();
    assert_eq!((buffer.ptr as usize) % ALIGN, 0);
    buffer.as_mut_slice()[..4].copy_from_slice(b"test");
    assert_eq!(&buffer.as_slice()[..4], b"test");
}

#[test]
fn cpu_list_parser_accepts_ranges_singletons_and_bad_fields() {
    assert!(cpu_list_contains("0-3,8,10-12", 0));
    assert!(cpu_list_contains("0-3,8,10-12", 8));
    assert!(cpu_list_contains("0-3,8,10-12", 11));
    assert!(!cpu_list_contains("0-3,8,10-12", 9));
    assert!(!cpu_list_contains("bad-3,also-bad", 1));
    assert!(!cpu_list_contains("3-bad", 3));
    let _ = current_numa_node();
    let _ = io_uring_available();
}

#[test]
fn io_uring_mode_always_has_a_buffered_fallback() {
    let dir = tempdir().unwrap();
    let file = dir.path().join("uring.bin");
    let payload = b"fallback payload";
    write_all(&file, payload, IoMode::IoUring).unwrap();
    assert_eq!(
        read_all(&file, payload.len(), IoMode::IoUring, true).unwrap(),
        payload
    );
}

#[test]
fn direct_helpers_cover_empty_missing_directory_and_short_file_paths() {
    let dir = tempdir().unwrap();
    let empty = dir.path().join("empty-direct.bin");
    assert!(write_iouring(&empty, b"").is_ok() || empty.exists());
    if empty.exists() {
        assert!(read_iouring(&empty, 0).unwrap_or_default().is_empty());
    }
    let missing = dir.path().join("missing");
    assert!(read_iouring(&missing, 1).is_err());
    assert!(read_direct(&missing, ALIGN).is_err());
    assert!(read_mmap_or_buffered(&missing, false).is_err());
    assert!(write_buffered(dir.path(), b"x").is_err());
    assert!(write_direct(dir.path(), &vec![0; ALIGN]).is_err());

    let short = dir.path().join("short.bin");
    fs::write(&short, b"short").unwrap();
    assert!(matches!(
        read_direct(&short, 5),
        Err(ArgosError::Unsupported(_)) | Err(ArgosError::Io(_))
    ));
    assert_eq!(
        read_all(&short, ALIGN, IoMode::Direct, false).unwrap(),
        b"short"
    );
}

#[test]
fn aligned_buffer_supports_zero_length_and_cpu_lists_ignore_whitespace() {
    let buffer = AlignedBuf::new(0).unwrap();
    assert!(buffer.as_slice().is_empty());
    assert!(cpu_list_contains(" 0-2, 4 ", 1));
    assert!(cpu_list_contains(" 0-2, 4 ", 4));
    assert!(!cpu_list_contains(" 0-2, 4 ", 3));
}
