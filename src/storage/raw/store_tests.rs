use super::*;
use crate::raw_format::MIN_DEVICE_BYTES;
use crate::types::{Disk, MetadataIntegrity, VolumeConfig};
use crate::volume::ArgosFs;
use std::fs;
use std::path::Path;
use tempfile::tempdir;

fn metadata() -> Metadata {
    let dir = tempdir().unwrap();
    ArgosFs::create(
        dir.path(),
        VolumeConfig {
            k: 1,
            m: 0,
            ..VolumeConfig::default()
        },
        1,
        false,
    )
    .unwrap()
    .metadata_snapshot()
}

fn loop_image(dir: &Path, name: &str) -> PathBuf {
    let path = dir.join(name);
    fs::File::create(&path)
        .unwrap()
        .set_len(MIN_DEVICE_BYTES)
        .unwrap();
    path
}

fn create_loop_pool(dir: &Path, name: &str) -> (PathBuf, ArgosFs) {
    let image = dir.join(format!("{name}.img"));
    let fs = ArgosFs::create_loop(
        std::slice::from_ref(&image),
        VolumeConfig {
            k: 1,
            m: 0,
            chunk_size: 4096,
            ..VolumeConfig::default()
        },
        MIN_DEVICE_BYTES,
        name,
        false,
    )
    .unwrap();
    (image, fs)
}

#[test]
fn scan_paths_rejects_host_missing_and_unformatted_devices() {
    let dir = tempdir().unwrap();
    let missing = dir.path().join("missing.img");
    let host = scan_paths(BackendKind::Host, std::slice::from_ref(&missing));
    assert_eq!(host.len(), 1);
    assert!(!host[0].valid);
    assert!(host[0].error.as_deref().unwrap().contains("not scan-able"));

    let absent = scan_paths(BackendKind::LoopBlock, std::slice::from_ref(&missing));
    assert!(!absent[0].valid);
    assert!(absent[0]
        .error
        .as_deref()
        .unwrap()
        .contains("failed to open"));

    let blank = loop_image(dir.path(), "blank.img");
    let scanned = scan_paths(BackendKind::LoopBlock, &[blank]);
    assert!(!scanned[0].valid);
    assert_eq!(scanned[0].capacity, MIN_DEVICE_BYTES);
    assert!(scanned[0].pool_uuid.is_none());
}

#[test]
fn known_signature_detection_covers_filesystems_partition_tables_and_swap() {
    let mut head = vec![0u8; 0x10050];
    let tail = vec![0u8; 65536];
    for (offset, signature) in [
        (0usize, b"hsqs".as_slice()),
        (0, b"XFSB"),
        (0, b"LUKS\xba\xbe"),
        (3, b"NTFS    "),
        (3, b"EXFAT   "),
        (512, b"EFI PART"),
        (512, b"LABELONE"),
        (0x438, &[0x53, 0xef]),
        (1024, &0xF2F5_2010u32.to_le_bytes()),
        (4096, &0xA92B_4EFCu32.to_le_bytes()),
        (0x10040, b"_BHRfS_M"),
    ] {
        head.fill(0);
        head[offset..offset + signature.len()].copy_from_slice(signature);
        assert!(has_known_signature(&head, &tail), "offset={offset}");
    }
    head.fill(0);
    head[4096 - 10..4096].copy_from_slice(b"SWAPSPACE2");
    assert!(contains_swap_signature(&head));
    assert!(has_known_signature(&head, &tail));

    let mut tail_signature = tail.clone();
    tail_signature[100..108].copy_from_slice(b"EFI PART");
    assert!(has_known_signature(&vec![0; 0x10050], &tail_signature));
    tail_signature.fill(0);
    tail_signature[200..204].copy_from_slice(&0xA92B_4EFCu32.to_le_bytes());
    assert!(has_known_signature(&vec![0; 0x10050], &tail_signature));
    assert!(!has_known_signature(&vec![0; 0x10050], &tail));
    assert!(!contains_swap_signature(&[0; 100]));
}

#[test]
fn raw_journal_quorum_ignores_unreadable_and_invalid_members() {
    assert!(raw_journal_quorum(&[], 0));
    let member = |readable, invalid, txid, hash: &str| RawJournalMemberReport {
        readable,
        invalid_entries: invalid,
        last_valid_txid: txid,
        last_valid_generation: txid,
        last_valid_record_hash: hash.to_string(),
        ..RawJournalMemberReport::default()
    };
    let members = vec![
        member(true, 0, 2, "same"),
        member(true, 0, 2, "same"),
        member(true, 0, 3, "different"),
    ];
    assert!(raw_journal_quorum(&members, 3));
    assert!(!raw_journal_quorum(&members[..1], 3));
    assert!(!raw_journal_quorum(
        &[member(false, 0, 2, "same"), member(true, 1, 2, "same")],
        2
    ));
}

#[test]
fn record_hash_and_previous_metadata_hash_are_stable_and_optional() {
    let meta = metadata();
    let mut record = RawJournalRecord {
        version: RAW_STORE_VERSION,
        time: 1.0,
        volume_uuid: meta.uuid.clone(),
        txid: meta.txid,
        generation: meta.integrity.generation,
        action: "write".to_string(),
        details: serde_json::json!({"previous_meta_hash": "previous", "extra": 1}),
        meta_hash: journal::canonical_metadata_hash(&meta).unwrap(),
        metadata: Some(meta.clone()),
        metadata_delta: None,
        record_hash: String::new(),
    };
    let first = raw_record_hash(&record).unwrap();
    record.time = 99.0;
    record.details["extra"] = serde_json::json!(2);
    record.metadata = None;
    assert_eq!(raw_record_hash(&record).unwrap(), first);
    assert_eq!(raw_record_previous_meta_hash(&record), Some("previous"));
    record.details = serde_json::json!({"previous_meta_hash": ""});
    assert_eq!(raw_record_previous_meta_hash(&record), None);
    record.details = serde_json::json!({});
    assert_eq!(raw_record_previous_meta_hash(&record), None);

    let mut legacy = meta.clone();
    legacy.integrity = MetadataIntegrity::default();
    assert_eq!(
        metadata_hash_for_replay(&legacy).unwrap(),
        journal::canonical_metadata_hash(&legacy).unwrap()
    );
    assert_eq!(
        metadata_hash_for_replay(&meta).unwrap(),
        meta.integrity.meta_hash
    );
}

#[test]
fn metadata_tree_checkpoint_covers_pages_headers_and_capacity_errors() {
    let bytes = vec![0x5a; METADATA_PAGE_SIZE * 2 + 17];
    let hash = sha256_hex(&bytes);
    let checkpoint = metadata_tree_checkpoint("disk", 7, 8, &bytes, &hash, 64 * 1024).unwrap();
    assert_eq!(&checkpoint.header[..16], METADATA_MAGIC);
    assert_eq!(
        get_u32(&checkpoint.header, 20).unwrap(),
        METADATA_FORMAT_TREE
    );
    assert_eq!(get_u64(&checkpoint.header, 24).unwrap(), 7);
    assert_eq!(get_u64(&checkpoint.header, 32).unwrap(), bytes.len() as u64);
    assert_eq!(get_u64(&checkpoint.header, 136).unwrap(), 8);
    assert_eq!(get_u64(&checkpoint.header, 152).unwrap(), 3);
    assert_eq!(checkpoint.body_writes.len(), 4);
    assert!(checkpoint
        .body_writes
        .iter()
        .any(|(offset, data)| *offset == RAW_HEADER_SIZE as u64
            && data.len() == 3 * METADATA_INDEX_ENTRY_SIZE));
    assert!(matches!(
        metadata_tree_checkpoint("disk", 0, 0, &[], &sha256_hex(&[]), 64 * 1024),
        Err(ArgosError::DiskFull { .. })
    ));
    assert!(matches!(
        metadata_tree_checkpoint("disk", 0, 0, &bytes, &hash, 4096),
        Err(ArgosError::DiskFull { .. })
    ));
}

#[test]
fn quorum_selection_uses_distinct_devices_and_highest_supported_generation() {
    let first = metadata();
    let mut second = first.clone();
    second.txid += 1;
    second.integrity.generation = second.txid;
    second.integrity.meta_hash = journal::canonical_metadata_hash(&second).unwrap();
    let report = MetadataCandidateReport::default();
    let candidates = vec![
        ("a".to_string(), Some(first.clone()), report.clone()),
        ("b".to_string(), Some(first.clone()), report.clone()),
        ("a".to_string(), Some(second.clone()), report.clone()),
        ("b".to_string(), Some(second.clone()), report.clone()),
        ("c".to_string(), None, report),
    ];
    let selected = select_quorum_metadata_candidate(&candidates)
        .unwrap()
        .unwrap();
    assert_eq!(selected.txid, second.txid);
    assert_eq!(metadata_quorum_requirement(&selected), 1);

    let mut multi = selected.clone();
    let template: Disk = multi.disks.values().next().unwrap().clone();
    for index in 1..4 {
        let mut disk = template.clone();
        disk.id = format!("disk-{index}");
        disk.status = if index == 3 {
            DiskStatus::Removed
        } else {
            DiskStatus::Online
        };
        multi.disks.insert(disk.id.clone(), disk);
    }
    assert_eq!(metadata_quorum_requirement(&multi), 2);
    assert!(select_quorum_metadata_candidate(&[(
        "a".to_string(),
        Some(multi),
        MetadataCandidateReport::default()
    )])
    .unwrap()
    .is_none());
}

#[test]
fn superblock_constructor_and_label_validation_cover_conversions_and_mismatches() {
    let pool = Uuid::new_v4();
    let sb =
        superblock_for_device(pool, 0, "disk-0000", 1, 0, 4096, MIN_DEVICE_BYTES, "pool").unwrap();
    validate_label_matches_superblock(&sb, &sb.device_label()).unwrap();
    assert!(superblock_for_device(
        pool,
        u32::MAX as usize + 1,
        "disk",
        1,
        0,
        4096,
        MIN_DEVICE_BYTES,
        "pool"
    )
    .is_err());
    assert!(superblock_for_device(
        pool,
        0,
        "disk",
        u32::MAX as usize + 1,
        0,
        4096,
        MIN_DEVICE_BYTES,
        "pool"
    )
    .is_err());
    assert!(superblock_for_device(
        pool,
        0,
        "disk",
        1,
        u32::MAX as usize + 1,
        4096,
        MIN_DEVICE_BYTES,
        "pool"
    )
    .is_err());

    let mut label = sb.device_label();
    label.pool_uuid = Uuid::new_v4();
    assert!(validate_label_matches_superblock(&sb, &label).is_err());
    label = sb.device_label();
    label.device_uuid = Uuid::new_v4();
    assert!(validate_label_matches_superblock(&sb, &label).is_err());
    label = sb.device_label();
    label.disk_id = "other".to_string();
    assert!(validate_label_matches_superblock(&sb, &label).is_err());
    label = sb.device_label();
    label.disk_index += 1;
    assert!(validate_label_matches_superblock(&sb, &label).is_err());
}

#[test]
fn binary_helpers_and_backup_offset_handle_short_utf8_and_saturation() {
    let mut bytes = [0u8; 32];
    put_u32(&mut bytes, 0, 0x12345678);
    put_u64(&mut bytes, 8, 0x0102030405060708);
    put_fixed_str(&mut bytes, 16, 8, "abcdef");
    assert_eq!(get_u32(&bytes, 0).unwrap(), 0x12345678);
    assert_eq!(get_u64(&bytes, 8).unwrap(), 0x0102030405060708);
    assert_eq!(get_fixed_hex(&bytes, 16, 8).unwrap(), "abcdef");
    assert!(get_u32(&bytes[..3], 0).is_err());
    assert!(get_u64(&bytes[..7], 0).is_err());
    assert!(get_fixed_hex(&bytes[..3], 0, 4).is_err());
    assert!(get_fixed_hex(&[0xff, 0], 0, 2).is_err());
    assert_eq!(checked_usize(7, "value").unwrap(), 7);
    assert_eq!(backup_superblock_offset_for_capacity(0), 0);
    assert_eq!(
        backup_superblock_offset_for_capacity(MIN_DEVICE_BYTES) % 4096,
        0
    );
}

#[test]
fn loop_pool_lifecycle_scans_inspects_audits_and_uses_backup_superblock() {
    let dir = tempdir().unwrap();
    let (image, fs) = create_loop_pool(dir.path(), "lifecycle");
    fs.write_file("/file", b"payload", 0o600).unwrap();
    fs.sync().unwrap();
    let initial = scan_paths(BackendKind::LoopBlock, std::slice::from_ref(&image));
    assert!(initial[0].valid);
    assert_eq!(initial[0].superblock_source.as_deref(), Some("primary"));
    let (sb, label) = inspect_device(BackendKind::LoopBlock, image.clone()).unwrap();
    validate_label_matches_superblock(&sb, &label).unwrap();
    assert!(inspect_device(BackendKind::Host, image.clone()).is_err());
    assert!(superblock_from_path(BackendKind::Host, &image).is_err());
    let opened = open_pool(BackendKind::LoopBlock, std::slice::from_ref(&image), false).unwrap();
    assert_eq!(opened.metadata.backend, BackendKind::LoopBlock);
    assert!(!opened.superblocks.is_empty());
    let report = audit(&*opened.backend, &opened.superblocks).unwrap();
    assert!(report.raw_journal_quorum.is_some());
    preflight_devices_empty(&*opened.backend, &opened.superblocks, true).unwrap();
    assert!(preflight_devices_empty(&*opened.backend, &opened.superblocks, false).is_err());

    let backend = FileBlockBackend::open_loop(std::slice::from_ref(&image), true).unwrap();
    backend
        .write_at(
            &"disk-0000".to_string(),
            PRIMARY_SUPERBLOCK_OFFSET,
            &[0; SUPERBLOCK_SIZE],
        )
        .unwrap();
    backend.flush_all().unwrap();
    let scanned = scan_paths(BackendKind::LoopBlock, std::slice::from_ref(&image));
    assert!(scanned[0].valid);
    assert_eq!(scanned[0].superblock_source.as_deref(), Some("backup"));
    let (_, source) = read_superblock_with_backup(&backend, "disk-0000", MIN_DEVICE_BYTES).unwrap();
    assert_eq!(source, "backup");
    let (backup_sb, backup_label) = inspect_device(BackendKind::LoopBlock, image.clone()).unwrap();
    validate_label_matches_superblock(&backup_sb, &backup_label).unwrap();
    backend
        .write_at(
            &"disk-0000".to_string(),
            sb.backup_superblock_offset,
            &[0; SUPERBLOCK_SIZE],
        )
        .unwrap();
    backend.flush_all().unwrap();
    assert!(inspect_device(BackendKind::LoopBlock, image.clone()).is_err());
}

#[test]
fn open_pool_rejects_empty_duplicate_and_mixed_pool_device_sets() {
    let dir = tempdir().unwrap();
    let missing = dir.path().join("missing.img");
    assert!(matches!(
        open_pool(BackendKind::LoopBlock, &[missing], false),
        Err(ArgosError::MissingDevice(_))
    ));

    let (first, first_fs) = create_loop_pool(dir.path(), "first");
    first_fs.mark_clean_unmount().unwrap();
    drop(first_fs);
    assert!(open_pool(
        BackendKind::LoopBlock,
        &[first.clone(), first.clone()],
        false
    )
    .is_err());

    let (second, second_fs) = create_loop_pool(dir.path(), "second");
    second_fs.mark_clean_unmount().unwrap();
    drop(second_fs);
    assert!(open_pool(BackendKind::LoopBlock, &[first, second], false).is_err());
}

#[test]
fn clean_state_updates_generation_and_mount_timestamps() {
    let dir = tempdir().unwrap();
    let (image, fs) = create_loop_pool(dir.path(), "clean-state");
    let (before, _) = superblock_from_path(BackendKind::LoopBlock, &image).unwrap();
    let backend = FileBlockBackend::open_loop(std::slice::from_ref(&image), true).unwrap();
    write_superblock_clean_state(&backend, std::slice::from_ref(&before), true).unwrap();
    let (clean, _) = superblock_from_path(BackendKind::LoopBlock, &image).unwrap();
    assert!(clean.clean);
    assert!(clean.generation > before.generation);
    assert!(clean.last_clean_unmount_time > 0);
    write_superblock_clean_state(&backend, std::slice::from_ref(&clean), false).unwrap();
    let (dirty, _) = superblock_from_path(BackendKind::LoopBlock, &image).unwrap();
    assert!(!dirty.clean);
    assert!(dirty.last_mount_time > 0);
    drop(fs);
}
