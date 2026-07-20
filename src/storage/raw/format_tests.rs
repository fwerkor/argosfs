use super::*;

#[test]
fn superblock_round_trips_and_detects_corruption() {
    let sb = RawSuperblock::new(
        Uuid::new_v4(),
        Uuid::new_v4(),
        "disk-0000".to_string(),
        0,
        2,
        1,
        262_144,
        64 * 1024 * 1024,
        "capos-root".to_string(),
    )
    .unwrap();
    let mut encoded = sb.encode();
    assert_eq!(RawSuperblock::decode(&encoded).unwrap(), sb);
    encoded[400] ^= 0x55;
    assert!(matches!(
        RawSuperblock::decode(&encoded).unwrap_err(),
        ArgosError::Checksum(_)
    ));
}

#[test]
fn superblock_rejects_unknown_required_features_and_overlapping_regions() {
    let mut sb = RawSuperblock::new(
        Uuid::new_v4(),
        Uuid::new_v4(),
        "disk-0000".to_string(),
        0,
        2,
        1,
        262_144,
        64 * 1024 * 1024,
        "capos-root".to_string(),
    )
    .unwrap();
    sb.required_feature_flags = 1;
    assert!(matches!(
        RawSuperblock::decode(&sb.encode()).unwrap_err(),
        ArgosError::IncompatibleFormat(_)
    ));

    sb.required_feature_flags = 0;
    sb.metadata.offset = sb.journal.offset;
    assert!(matches!(
        RawSuperblock::decode(&sb.encode()).unwrap_err(),
        ArgosError::IncompatibleFormat(_)
    ));
}

#[test]
fn superblock_layout_must_fit_the_opened_device() {
    let sb = RawSuperblock::new(
        Uuid::new_v4(),
        Uuid::new_v4(),
        "disk-0000".to_string(),
        0,
        2,
        1,
        262_144,
        64 * 1024 * 1024,
        "capos-root".to_string(),
    )
    .unwrap();
    sb.validate_device_capacity(64 * 1024 * 1024).unwrap();
    assert!(matches!(
        sb.validate_device_capacity(32 * 1024 * 1024).unwrap_err(),
        ArgosError::IncompatibleFormat(_)
    ));
}

#[test]
fn superblock_constructor_rejects_unencodable_fields() {
    let create = |disk_id: &str, k: u32, m: u32, chunk_size: u64, label: &str| {
        RawSuperblock::new(
            Uuid::new_v4(),
            Uuid::new_v4(),
            disk_id.to_string(),
            0,
            k,
            m,
            chunk_size,
            64 * 1024 * 1024,
            label.to_string(),
        )
    };

    assert!(create("disk-0000", 0, 1, 4096, "pool").is_err());
    assert!(create("disk-0000", 1, 0, 0, "pool").is_err());
    assert!(create(&"d".repeat(64), 1, 0, 4096, "pool").is_err());
    assert!(create("disk-0000", 1, 0, 4096, &"p".repeat(128)).is_err());
}

#[test]
fn label_round_trips_and_rejects_bad_magic() {
    let label = RawDeviceLabel {
        pool_uuid: Uuid::new_v4(),
        device_uuid: Uuid::new_v4(),
        disk_id: "disk-0001".to_string(),
        disk_index: 1,
        generation: 42,
        label: "capos-root".to_string(),
    };
    let mut encoded = label.encode();
    assert_eq!(RawDeviceLabel::decode(&encoded).unwrap(), label);
    encoded[0] = 0;
    assert!(matches!(
        RawDeviceLabel::decode(&encoded).unwrap_err(),
        ArgosError::IncompatibleFormat(_)
    ));
}

fn resign_superblock(bytes: &mut [u8; SUPERBLOCK_SIZE]) {
    let checksum = checksum_with_zeroed_field(bytes, 224, 32);
    bytes[224..256].copy_from_slice(&checksum);
}

fn resign_label(bytes: &mut [u8; DEVICE_LABEL_SIZE]) {
    let checksum = checksum_with_zeroed_field(bytes, 96, 32);
    bytes[96..128].copy_from_slice(&checksum);
}

fn sample_superblock() -> RawSuperblock {
    RawSuperblock::new(
        Uuid::new_v4(),
        Uuid::new_v4(),
        "disk-0000".to_string(),
        0,
        2,
        1,
        262_144,
        256 * 1024 * 1024,
        "capos-root".to_string(),
    )
    .unwrap()
}

#[test]
fn constructor_and_large_layout_cover_capacity_and_overflow_edges() {
    let create = |capacity, k, m| {
        RawSuperblock::new(
            Uuid::new_v4(),
            Uuid::new_v4(),
            "disk".to_string(),
            0,
            k,
            m,
            4096,
            capacity,
            "pool".to_string(),
        )
    };
    assert!(create(MIN_DEVICE_BYTES - 1, 1, 0).is_err());
    assert!(create(64 * 1024 * 1024, u32::MAX, 1).is_err());
    let small = create(64 * 1024 * 1024, 1, 0).unwrap();
    assert_eq!(small.journal.length, JOURNAL_REGION_SIZE);
    assert_eq!(small.metadata.length, METADATA_REGION_SIZE);
    let large = create(LARGE_LAYOUT_MIN_DEVICE_BYTES, 1, 0).unwrap();
    assert_eq!(large.journal.length, LARGE_JOURNAL_REGION_SIZE);
    assert_eq!(large.metadata.length, LARGE_METADATA_REGION_SIZE);
    assert_eq!(large.device_label().disk_id, "disk");
}

#[test]
fn superblock_decode_rejects_header_and_geometry_variants() {
    let original = sample_superblock().encode();
    assert!(RawSuperblock::decode(&original[..SUPERBLOCK_SIZE - 1]).is_err());

    let mut bytes = original;
    bytes[..16].fill(0);
    assert!(matches!(
        RawSuperblock::decode(&bytes),
        Err(ArgosError::IncompatibleFormat(_))
    ));

    for mutate in [
        |bytes: &mut [u8; SUPERBLOCK_SIZE]| put_u32(bytes, 16, RAW_FORMAT_VERSION + 1),
        |bytes: &mut [u8; SUPERBLOCK_SIZE]| put_u32(bytes, 20, RAW_FORMAT_VERSION + 1),
        |bytes: &mut [u8; SUPERBLOCK_SIZE]| put_u32(bytes, 24, 0),
        |bytes: &mut [u8; SUPERBLOCK_SIZE]| put_u32(bytes, 56, 8192),
        |bytes: &mut [u8; SUPERBLOCK_SIZE]| put_u32(bytes, 60, 0),
        |bytes: &mut [u8; SUPERBLOCK_SIZE]| put_u32(bytes, 60, 1000),
        |bytes: &mut [u8; SUPERBLOCK_SIZE]| put_u32(bytes, 60, 8192),
        |bytes: &mut [u8; SUPERBLOCK_SIZE]| put_u32(bytes, 100, 0),
        |bytes: &mut [u8; SUPERBLOCK_SIZE]| put_u64(bytes, 112, 0),
    ] {
        let mut bytes = original;
        mutate(&mut bytes);
        resign_superblock(&mut bytes);
        assert!(RawSuperblock::decode(&bytes).is_err());
    }
}

#[test]
fn superblock_decode_rejects_invalid_regions_and_backup_alignment() {
    let original = sample_superblock().encode();
    for mutate in [
        |bytes: &mut [u8; SUPERBLOCK_SIZE]| {
            put_region(
                bytes,
                128,
                RawRegion {
                    offset: 1,
                    length: 4096,
                },
            )
        },
        |bytes: &mut [u8; SUPERBLOCK_SIZE]| {
            put_region(
                bytes,
                128,
                RawRegion {
                    offset: JOURNAL_REGION_OFFSET,
                    length: 0,
                },
            )
        },
        |bytes: &mut [u8; SUPERBLOCK_SIZE]| {
            put_region(
                bytes,
                128,
                RawRegion {
                    offset: u64::MAX - 4095,
                    length: 8192,
                },
            )
        },
        |bytes: &mut [u8; SUPERBLOCK_SIZE]| {
            put_region(
                bytes,
                144,
                RawRegion {
                    offset: JOURNAL_REGION_OFFSET,
                    length: 4096,
                },
            )
        },
        |bytes: &mut [u8; SUPERBLOCK_SIZE]| {
            put_region(
                bytes,
                160,
                RawRegion {
                    offset: METADATA_REGION_OFFSET,
                    length: 4096,
                },
            )
        },
        |bytes: &mut [u8; SUPERBLOCK_SIZE]| {
            put_region(
                bytes,
                176,
                RawRegion {
                    offset: ALLOCATOR_REGION_OFFSET,
                    length: 4096,
                },
            )
        },
        |bytes: &mut [u8; SUPERBLOCK_SIZE]| put_u64(bytes, 192, DATA_REGION_OFFSET + 1),
    ] {
        let mut bytes = original;
        mutate(&mut bytes);
        resign_superblock(&mut bytes);
        assert!(RawSuperblock::decode(&bytes).is_err());
    }
}

#[test]
fn capacity_validation_checks_backup_and_each_region_end() {
    let base = sample_superblock();
    let capacity = 256 * 1024 * 1024;
    base.validate_device_capacity(capacity).unwrap();

    let mut bad = base.clone();
    bad.backup_superblock_offset = u64::MAX;
    assert!(bad.validate_device_capacity(capacity).is_err());
    bad = base.clone();
    bad.backup_superblock_offset = capacity;
    assert!(bad.validate_device_capacity(capacity).is_err());
    for region_name in ["journal", "metadata", "allocator", "data"] {
        let mut bad = base.clone();
        let region = match region_name {
            "journal" => &mut bad.journal,
            "metadata" => &mut bad.metadata,
            "allocator" => &mut bad.allocator,
            _ => &mut bad.data,
        };
        region.offset = capacity - 4096;
        region.length = 8192;
        assert!(
            bad.validate_device_capacity(capacity).is_err(),
            "{region_name}"
        );

        let mut overflow = base.clone();
        let region = match region_name {
            "journal" => &mut overflow.journal,
            "metadata" => &mut overflow.metadata,
            "allocator" => &mut overflow.allocator,
            _ => &mut overflow.data,
        };
        region.offset = u64::MAX - 4095;
        region.length = 8192;
        assert!(
            overflow.validate_device_capacity(capacity).is_err(),
            "{region_name}"
        );
    }
}

#[test]
fn device_label_decode_rejects_size_version_endian_checksum_and_utf8() {
    let label = sample_superblock().device_label();
    let original = label.encode();
    assert!(RawDeviceLabel::decode(&original[..DEVICE_LABEL_SIZE - 1]).is_err());

    for mutate in [
        |bytes: &mut [u8; DEVICE_LABEL_SIZE]| put_u32(bytes, 16, RAW_FORMAT_VERSION + 1),
        |bytes: &mut [u8; DEVICE_LABEL_SIZE]| put_u32(bytes, 20, 0),
    ] {
        let mut bytes = original;
        mutate(&mut bytes);
        resign_label(&mut bytes);
        assert!(RawDeviceLabel::decode(&bytes).is_err());
    }
    let mut checksum = original;
    checksum[400] ^= 1;
    assert!(matches!(
        RawDeviceLabel::decode(&checksum),
        Err(ArgosError::Checksum(_))
    ));

    let mut invalid_utf8 = original;
    invalid_utf8[128] = 0xff;
    invalid_utf8[129] = 0;
    resign_label(&mut invalid_utf8);
    assert!(matches!(
        RawDeviceLabel::decode(&invalid_utf8),
        Err(ArgosError::CorruptedMetadata(_))
    ));
}

#[test]
fn alignment_and_binary_field_helpers_cover_zero_short_and_saturation() {
    assert_eq!(align_up(7, 0), 7);
    assert_eq!(align_up(7, 4), 8);
    assert_eq!(align_up(u64::MAX, 4096), u64::MAX);
    assert_eq!(align_down(7, 0), 7);
    assert_eq!(align_down(7, 4), 4);

    assert!(get_u32(&[0; 3], 0).is_err());
    assert!(get_u64(&[0; 7], 0).is_err());
    assert!(uuid_from(&[0; 15], 0).is_err());
    assert!(get_fixed_str(&[0; 3], 0, 4).is_err());
    assert_eq!(get_fixed_str(b"abc\0tail", 0, 8).unwrap(), "abc");
    assert!(get_fixed_str(&[0xff, 0], 0, 2).is_err());

    let mut fixed = [0u8; 5];
    put_fixed_str(&mut fixed, 0, 5, "too-long-value");
    assert_eq!(&fixed, b"too-\0");
}
