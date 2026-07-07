use crate::error::{ArgosError, Result};
use crate::types::Compression;

pub fn compress(data: &[u8], codec: Compression, level: i32) -> Result<Vec<u8>> {
    match codec {
        Compression::None => Ok(data.to_vec()),
        Compression::Lz4 => Ok(lz4_flex::compress_prepend_size(data)),
        Compression::Zstd => zstd::bulk::compress(data, level).map_err(ArgosError::Io),
    }
}

pub fn decompress(data: &[u8], codec: Compression) -> Result<Vec<u8>> {
    match codec {
        Compression::None => Ok(data.to_vec()),
        Compression::Lz4 => lz4_flex::decompress_size_prepended(data)
            .map_err(|err| ArgosError::Invalid(format!("lz4 decompression failed: {err}"))),
        Compression::Zstd => zstd::stream::decode_all(data)
            .map_err(|err| ArgosError::Invalid(format!("zstd decompression failed: {err}"))),
    }
}
