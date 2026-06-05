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
pub const SUPERBLOCK_SIZE: usize = 4096;
pub const DEVICE_LABEL_SIZE: usize = 4096;
pub const MIN_DEVICE_BYTES: u64 = 20 * 1024 * 1024;
pub const RAW_BLOCK_SIZE: u64 = 4096;
pub const RAW_SUPER_MAGIC: &[u8; 16] = b"ARGOSFS-RAW-SB\0\0";
pub const RAW_LABEL_MAGIC: &[u8; 16] = b"ARGOSFS-RAW-LB\0\0";
pub const ENDIAN_MARKER: u32 = 0x1234_5678;

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
        if capacity < MIN_DEVICE_BYTES {
            return Err(ArgosError::Invalid(format!(
                "device too small for raw ArgosFS layout: {capacity} bytes, need at least {MIN_DEVICE_BYTES}"
            )));
        }
        let backup_superblock_offset =
            align_down(capacity.saturating_sub(BACKUP_REGION_SIZE), 4096);
        let data_end = backup_superblock_offset;
        if data_end <= DATA_REGION_OFFSET {
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
                length: data_end - DATA_REGION_OFFSET,
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
        let journal = get_region(bytes, 128)?;
        let metadata = get_region(bytes, 144)?;
        let allocator = get_region(bytes, 160)?;
        let data = get_region(bytes, 176)?;
        validate_region("journal", journal)?;
        validate_region("metadata", metadata)?;
        validate_region("allocator", allocator)?;
        validate_region("data", data)?;
        Ok(Self {
            pool_uuid: uuid_from(bytes, 64)?,
            device_uuid: uuid_from(bytes, 80)?,
            disk_id: get_fixed_str(bytes, 256, 64)?,
            disk_index: get_u32(bytes, 96)?,
            k: get_u32(bytes, 100)?,
            m: get_u32(bytes, 104)?,
            chunk_size: get_u64(bytes, 112)?,
            generation: get_u64(bytes, 32)?,
            clean: get_u32(bytes, 108)? != 0,
            feature_flags: get_u64(bytes, 40)?,
            required_feature_flags: get_u64(bytes, 48)?,
            block_size: get_u32(bytes, 56)?,
            sector_size: get_u32(bytes, 60)?,
            journal,
            metadata,
            allocator,
            data,
            backup_superblock_offset: get_u64(bytes, 192)?,
            label: get_fixed_str(bytes, 320, 128)?,
            last_mount_time: get_u64(bytes, 200)?,
            last_clean_unmount_time: get_u64(bytes, 208)?,
        })
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
}
