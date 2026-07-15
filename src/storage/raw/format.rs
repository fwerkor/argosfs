use crate::error::{ArgosError, Result};
use crate::types::RAW_FORMAT_VERSION;
use sha2::{Digest, Sha256};
use uuid::Uuid;

pub const PROTECTIVE_HEADER_OFFSET: u64 = 0;
pub const PRIMARY_SUPERBLOCK_OFFSET: u64 = 4 * 1024;
pub const DEVICE_LABEL_OFFSET: u64 = 64 * 1024;
pub const JOURNAL_REGION_OFFSET: u64 = 1024 * 1024;
pub const JOURNAL_REGION_SIZE: u64 = 2 * 1024 * 1024;
pub const METADATA_REGION_OFFSET: u64 = 4 * 1024 * 1024;
pub const METADATA_REGION_SIZE: u64 = 8 * 1024 * 1024;
pub const ALLOCATOR_REGION_OFFSET: u64 = 12 * 1024 * 1024;
pub const ALLOCATOR_REGION_SIZE: u64 = 4 * 1024 * 1024;
pub const DATA_REGION_OFFSET: u64 = 16 * 1024 * 1024;
pub const BACKUP_REGION_SIZE: u64 = 1024 * 1024;
const LARGE_LAYOUT_MIN_DEVICE_BYTES: u64 = 128 * 1024 * 1024;
const LARGE_JOURNAL_REGION_SIZE: u64 = 8 * 1024 * 1024;
const LARGE_METADATA_REGION_SIZE: u64 = 64 * 1024 * 1024;
pub const SUPERBLOCK_SIZE: usize = 4096;
pub const DEVICE_LABEL_SIZE: usize = 4096;
pub const MIN_DEVICE_BYTES: u64 = 20 * 1024 * 1024;
pub const RAW_BLOCK_SIZE: u64 = 4096;
pub const RAW_SUPER_MAGIC: &[u8; 16] = b"ARGOSFS-RAW-SB\0\0";
pub const RAW_LABEL_MAGIC: &[u8; 16] = b"ARGOSFS-RAW-LB\0\0";
pub const ENDIAN_MARKER: u32 = 0x1234_5678;
const SUPPORTED_REQUIRED_FEATURE_FLAGS: u64 = 0;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RawRegion {
    pub offset: u64,
    pub length: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RawSuperblock {
    pub pool_uuid: Uuid,
    pub device_uuid: Uuid,
    pub disk_id: String,
    pub disk_index: u32,
    pub k: u32,
    pub m: u32,
    pub chunk_size: u64,
    pub generation: u64,
    pub clean: bool,
    pub feature_flags: u64,
    pub required_feature_flags: u64,
    pub block_size: u32,
    pub sector_size: u32,
    pub journal: RawRegion,
    pub metadata: RawRegion,
    pub allocator: RawRegion,
    pub data: RawRegion,
    pub backup_superblock_offset: u64,
    pub label: String,
    pub last_mount_time: u64,
    pub last_clean_unmount_time: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RawDeviceLabel {
    pub pool_uuid: Uuid,
    pub device_uuid: Uuid,
    pub disk_id: String,
    pub disk_index: u32,
    pub generation: u64,
    pub label: String,
}

impl RawSuperblock {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        pool_uuid: Uuid,
        device_uuid: Uuid,
        disk_id: String,
        disk_index: u32,
        k: u32,
        m: u32,
        chunk_size: u64,
        capacity: u64,
        label: String,
    ) -> Result<Self> {
        if k == 0 || k.checked_add(m).is_none() || chunk_size == 0 {
            return Err(ArgosError::Invalid(
                "invalid raw erasure layout or chunk size".to_string(),
            ));
        }
        if disk_id.is_empty() || disk_id.len() >= 64 {
            return Err(ArgosError::Invalid(
                "raw disk id must contain between 1 and 63 bytes".to_string(),
            ));
        }
        if label.len() >= 128 {
            return Err(ArgosError::Invalid(
                "raw pool label must contain at most 127 bytes".to_string(),
            ));
        }
        if capacity < MIN_DEVICE_BYTES {
            return Err(ArgosError::Invalid(format!(
                "device too small for raw ArgosFS layout: {capacity} bytes, need at least {MIN_DEVICE_BYTES}"
            )));
        }
        let regions = raw_regions_for_capacity(capacity);
        let backup_superblock_offset =
            align_down(capacity.saturating_sub(BACKUP_REGION_SIZE), 4096);
        let data_end = backup_superblock_offset;
        if data_end <= regions.data.offset {
            return Err(ArgosError::Invalid(
                "device has no usable data region after metadata layout".to_string(),
            ));
        }
        Ok(Self {
            pool_uuid,
            device_uuid,
            disk_id,
            disk_index,
            k,
            m,
            chunk_size,
            generation: 1,
            clean: true,
            feature_flags: 0,
            required_feature_flags: 0,
            block_size: RAW_BLOCK_SIZE as u32,
            sector_size: 512,
            journal: regions.journal,
            metadata: regions.metadata,
            allocator: regions.allocator,
            data: RawRegion {
                offset: regions.data.offset,
                length: data_end - regions.data.offset,
            },
            backup_superblock_offset,
            label,
            last_mount_time: 0,
            last_clean_unmount_time: 0,
        })
    }

    pub fn device_label(&self) -> RawDeviceLabel {
        RawDeviceLabel {
            pool_uuid: self.pool_uuid,
            device_uuid: self.device_uuid,
            disk_id: self.disk_id.clone(),
            disk_index: self.disk_index,
            generation: self.generation,
            label: self.label.clone(),
        }
    }

    pub fn encode(&self) -> [u8; SUPERBLOCK_SIZE] {
        let mut out = [0u8; SUPERBLOCK_SIZE];
        out[..16].copy_from_slice(RAW_SUPER_MAGIC);
        put_u32(&mut out, 16, RAW_FORMAT_VERSION);
        put_u32(&mut out, 20, 1);
        put_u32(&mut out, 24, ENDIAN_MARKER);
        put_u64(&mut out, 32, self.generation);
        put_u64(&mut out, 40, self.feature_flags);
        put_u64(&mut out, 48, self.required_feature_flags);
        put_u32(&mut out, 56, self.block_size);
        put_u32(&mut out, 60, self.sector_size);
        out[64..80].copy_from_slice(self.pool_uuid.as_bytes());
        out[80..96].copy_from_slice(self.device_uuid.as_bytes());
        put_u32(&mut out, 96, self.disk_index);
        put_u32(&mut out, 100, self.k);
        put_u32(&mut out, 104, self.m);
        put_u32(&mut out, 108, u32::from(self.clean));
        put_u64(&mut out, 112, self.chunk_size);
        put_region(&mut out, 128, self.journal);
        put_region(&mut out, 144, self.metadata);
        put_region(&mut out, 160, self.allocator);
        put_region(&mut out, 176, self.data);
        put_u64(&mut out, 192, self.backup_superblock_offset);
        put_u64(&mut out, 200, self.last_mount_time);
        put_u64(&mut out, 208, self.last_clean_unmount_time);
        put_fixed_str(&mut out, 256, 64, &self.disk_id);
        put_fixed_str(&mut out, 320, 128, &self.label);
        let checksum = checksum_with_zeroed_field(&out, 224, 32);
        out[224..256].copy_from_slice(&checksum);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < SUPERBLOCK_SIZE {
            return Err(ArgosError::IncompatibleFormat(
                "superblock buffer is too small".to_string(),
            ));
        }
        if &bytes[..16] != RAW_SUPER_MAGIC {
            return Err(ArgosError::IncompatibleFormat(
                "missing ArgosFS raw superblock magic".to_string(),
            ));
        }
        let version = get_u32(bytes, 16)?;
        if version != RAW_FORMAT_VERSION {
            return Err(ArgosError::IncompatibleFormat(format!(
                "unsupported raw format version {version}"
            )));
        }
        if get_u32(bytes, 20)? > RAW_FORMAT_VERSION {
            return Err(ArgosError::IncompatibleFormat(format!(
                "minimum compatible version {} is newer than this binary",
                get_u32(bytes, 20)?
            )));
        }
        if get_u32(bytes, 24)? != ENDIAN_MARKER {
            return Err(ArgosError::IncompatibleFormat(
                "endianness marker mismatch".to_string(),
            ));
        }
        let expected = checksum_with_zeroed_field(&bytes[..SUPERBLOCK_SIZE], 224, 32);
        if expected.as_slice() != &bytes[224..256] {
            return Err(ArgosError::Checksum(
                "raw superblock checksum mismatch".to_string(),
            ));
        }
        let required_feature_flags = get_u64(bytes, 48)?;
        let unsupported = required_feature_flags & !SUPPORTED_REQUIRED_FEATURE_FLAGS;
        if unsupported != 0 {
            return Err(ArgosError::IncompatibleFormat(format!(
                "unsupported required raw feature flags 0x{unsupported:x}"
            )));
        }
        let block_size = get_u32(bytes, 56)?;
        let sector_size = get_u32(bytes, 60)?;
        let k = get_u32(bytes, 100)?;
        let m = get_u32(bytes, 104)?;
        let chunk_size = get_u64(bytes, 112)?;
        if block_size != RAW_BLOCK_SIZE as u32 {
            return Err(ArgosError::IncompatibleFormat(format!(
                "unsupported raw block size {block_size}"
            )));
        }
        if sector_size == 0 || !sector_size.is_power_of_two() || block_size % sector_size != 0 {
            return Err(ArgosError::IncompatibleFormat(format!(
                "invalid raw sector size {sector_size} for block size {block_size}"
            )));
        }
        if k == 0 || k.checked_add(m).is_none() || chunk_size == 0 {
            return Err(ArgosError::IncompatibleFormat(
                "invalid raw erasure layout or chunk size".to_string(),
            ));
        }
        let journal = get_region(bytes, 128)?;
        let metadata = get_region(bytes, 144)?;
        let allocator = get_region(bytes, 160)?;
        let data = get_region(bytes, 176)?;
        validate_region("journal", journal)?;
        validate_region("metadata", metadata)?;
        validate_region("allocator", allocator)?;
        validate_region("data", data)?;
        let backup_superblock_offset = get_u64(bytes, 192)?;
        validate_region_order(journal, metadata, allocator, data, backup_superblock_offset)?;
        Ok(Self {
            pool_uuid: uuid_from(bytes, 64)?,
            device_uuid: uuid_from(bytes, 80)?,
            disk_id: get_fixed_str(bytes, 256, 64)?,
            disk_index: get_u32(bytes, 96)?,
            k,
            m,
            chunk_size,
            generation: get_u64(bytes, 32)?,
            clean: get_u32(bytes, 108)? != 0,
            feature_flags: get_u64(bytes, 40)?,
            required_feature_flags,
            block_size,
            sector_size,
            journal,
            metadata,
            allocator,
            data,
            backup_superblock_offset,
            label: get_fixed_str(bytes, 320, 128)?,
            last_mount_time: get_u64(bytes, 200)?,
            last_clean_unmount_time: get_u64(bytes, 208)?,
        })
    }

    pub fn validate_device_capacity(&self, capacity: u64) -> Result<()> {
        let backup_end = self
            .backup_superblock_offset
            .checked_add((SUPERBLOCK_SIZE + DEVICE_LABEL_SIZE) as u64)
            .ok_or_else(|| {
                ArgosError::IncompatibleFormat("backup superblock range overflow".to_string())
            })?;
        if backup_end > capacity {
            return Err(ArgosError::IncompatibleFormat(format!(
                "raw layout backup offset {} does not fit device capacity {capacity}",
                self.backup_superblock_offset
            )));
        }
        for (name, region) in [
            ("journal", self.journal),
            ("metadata", self.metadata),
            ("allocator", self.allocator),
            ("data", self.data),
        ] {
            let end = region
                .offset
                .checked_add(region.length)
                .ok_or_else(|| ArgosError::IncompatibleFormat(format!("{name} region overflow")))?;
            if end > capacity {
                return Err(ArgosError::IncompatibleFormat(format!(
                    "{name} region ends at {end}, beyond device capacity {capacity}"
                )));
            }
        }
        Ok(())
    }
}

fn validate_region_order(
    journal: RawRegion,
    metadata: RawRegion,
    allocator: RawRegion,
    data: RawRegion,
    backup_superblock_offset: u64,
) -> Result<()> {
    let end = |name: &str, region: RawRegion| {
        region
            .offset
            .checked_add(region.length)
            .ok_or_else(|| ArgosError::IncompatibleFormat(format!("{name} region overflow")))
    };
    if journal.offset < DEVICE_LABEL_OFFSET + DEVICE_LABEL_SIZE as u64
        || end("journal", journal)? > metadata.offset
        || end("metadata", metadata)? > allocator.offset
        || end("allocator", allocator)? > data.offset
        || end("data", data)? > backup_superblock_offset
        || !backup_superblock_offset.is_multiple_of(RAW_BLOCK_SIZE)
    {
        return Err(ArgosError::IncompatibleFormat(
            "raw superblock regions overlap or are out of order".to_string(),
        ));
    }
    Ok(())
}

struct RawLayoutRegions {
    journal: RawRegion,
    metadata: RawRegion,
    allocator: RawRegion,
    data: RawRegion,
}

fn raw_regions_for_capacity(capacity: u64) -> RawLayoutRegions {
    if capacity >= LARGE_LAYOUT_MIN_DEVICE_BYTES {
        let journal = RawRegion {
            offset: JOURNAL_REGION_OFFSET,
            length: LARGE_JOURNAL_REGION_SIZE,
        };
        let metadata = RawRegion {
            offset: journal.offset + journal.length,
            length: LARGE_METADATA_REGION_SIZE,
        };
        let allocator = RawRegion {
            offset: metadata.offset + metadata.length,
            length: ALLOCATOR_REGION_SIZE,
        };
        let data = RawRegion {
            offset: allocator.offset + allocator.length,
            length: 0,
        };
        return RawLayoutRegions {
            journal,
            metadata,
            allocator,
            data,
        };
    }
    RawLayoutRegions {
        journal: RawRegion {
            offset: JOURNAL_REGION_OFFSET,
            length: JOURNAL_REGION_SIZE,
        },
        metadata: RawRegion {
            offset: METADATA_REGION_OFFSET,
            length: METADATA_REGION_SIZE,
        },
        allocator: RawRegion {
            offset: ALLOCATOR_REGION_OFFSET,
            length: ALLOCATOR_REGION_SIZE,
        },
        data: RawRegion {
            offset: DATA_REGION_OFFSET,
            length: 0,
        },
    }
}

impl RawDeviceLabel {
    pub fn encode(&self) -> [u8; DEVICE_LABEL_SIZE] {
        let mut out = [0u8; DEVICE_LABEL_SIZE];
        out[..16].copy_from_slice(RAW_LABEL_MAGIC);
        put_u32(&mut out, 16, RAW_FORMAT_VERSION);
        put_u32(&mut out, 20, ENDIAN_MARKER);
        out[32..48].copy_from_slice(self.pool_uuid.as_bytes());
        out[48..64].copy_from_slice(self.device_uuid.as_bytes());
        put_u32(&mut out, 64, self.disk_index);
        put_u64(&mut out, 72, self.generation);
        put_fixed_str(&mut out, 128, 64, &self.disk_id);
        put_fixed_str(&mut out, 192, 128, &self.label);
        let checksum = checksum_with_zeroed_field(&out, 96, 32);
        out[96..128].copy_from_slice(&checksum);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < DEVICE_LABEL_SIZE {
            return Err(ArgosError::IncompatibleFormat(
                "device label buffer is too small".to_string(),
            ));
        }
        if &bytes[..16] != RAW_LABEL_MAGIC {
            return Err(ArgosError::IncompatibleFormat(
                "missing ArgosFS raw label magic".to_string(),
            ));
        }
        if get_u32(bytes, 16)? != RAW_FORMAT_VERSION || get_u32(bytes, 20)? != ENDIAN_MARKER {
            return Err(ArgosError::IncompatibleFormat(
                "unsupported raw label version or endian marker".to_string(),
            ));
        }
        let expected = checksum_with_zeroed_field(&bytes[..DEVICE_LABEL_SIZE], 96, 32);
        if expected.as_slice() != &bytes[96..128] {
            return Err(ArgosError::Checksum(
                "raw device label checksum mismatch".to_string(),
            ));
        }
        Ok(Self {
            pool_uuid: uuid_from(bytes, 32)?,
            device_uuid: uuid_from(bytes, 48)?,
            disk_id: get_fixed_str(bytes, 128, 64)?,
            disk_index: get_u32(bytes, 64)?,
            generation: get_u64(bytes, 72)?,
            label: get_fixed_str(bytes, 192, 128)?,
        })
    }
}

pub fn align_up(value: u64, alignment: u64) -> u64 {
    if alignment == 0 {
        value
    } else {
        value.div_ceil(alignment).saturating_mul(alignment)
    }
}

pub fn align_down(value: u64, alignment: u64) -> u64 {
    value
        .checked_div(alignment)
        .map(|blocks| blocks.saturating_mul(alignment))
        .unwrap_or(value)
}

fn validate_region(name: &str, region: RawRegion) -> Result<()> {
    if !region.offset.is_multiple_of(4096)
        || !region.length.is_multiple_of(4096)
        || region.length == 0
    {
        return Err(ArgosError::Invalid(format!(
            "{name} region must be non-empty and 4 KiB aligned"
        )));
    }
    region
        .offset
        .checked_add(region.length)
        .ok_or_else(|| ArgosError::Invalid(format!("{name} region overflows")))?;
    Ok(())
}

fn checksum_with_zeroed_field(bytes: &[u8], offset: usize, len: usize) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(&bytes[..offset]);
    hasher.update(vec![0u8; len]);
    hasher.update(&bytes[offset + len..]);
    hasher.finalize().into()
}

fn put_region(out: &mut [u8], offset: usize, region: RawRegion) {
    put_u64(out, offset, region.offset);
    put_u64(out, offset + 8, region.length);
}

fn get_region(bytes: &[u8], offset: usize) -> Result<RawRegion> {
    Ok(RawRegion {
        offset: get_u64(bytes, offset)?,
        length: get_u64(bytes, offset + 8)?,
    })
}

fn put_u32(out: &mut [u8], offset: usize, value: u32) {
    out[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(out: &mut [u8], offset: usize, value: u64) {
    out[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn get_u32(bytes: &[u8], offset: usize) -> Result<u32> {
    let raw = bytes
        .get(offset..offset + 4)
        .ok_or_else(|| ArgosError::CorruptedMetadata("short u32 field".to_string()))?;
    Ok(u32::from_le_bytes(raw.try_into().unwrap()))
}

fn get_u64(bytes: &[u8], offset: usize) -> Result<u64> {
    let raw = bytes
        .get(offset..offset + 8)
        .ok_or_else(|| ArgosError::CorruptedMetadata("short u64 field".to_string()))?;
    Ok(u64::from_le_bytes(raw.try_into().unwrap()))
}

fn uuid_from(bytes: &[u8], offset: usize) -> Result<Uuid> {
    let raw = bytes
        .get(offset..offset + 16)
        .ok_or_else(|| ArgosError::CorruptedMetadata("short UUID field".to_string()))?;
    Uuid::from_slice(raw).map_err(|err| ArgosError::CorruptedMetadata(err.to_string()))
}

fn put_fixed_str(out: &mut [u8], offset: usize, len: usize, value: &str) {
    let raw = value.as_bytes();
    let copy_len = raw.len().min(len.saturating_sub(1));
    out[offset..offset + copy_len].copy_from_slice(&raw[..copy_len]);
}

fn get_fixed_str(bytes: &[u8], offset: usize, len: usize) -> Result<String> {
    let raw = bytes
        .get(offset..offset + len)
        .ok_or_else(|| ArgosError::CorruptedMetadata("short string field".to_string()))?;
    let end = raw.iter().position(|byte| *byte == 0).unwrap_or(raw.len());
    std::str::from_utf8(&raw[..end])
        .map(str::to_string)
        .map_err(|err| ArgosError::CorruptedMetadata(err.to_string()))
}

#[cfg(test)]
mod tests {
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
}
