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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_codec_round_trips_and_invalid_streams_fail() {
        let data = b"compressible payload ".repeat(128);
        for codec in [Compression::None, Compression::Lz4, Compression::Zstd] {
            let compressed = compress(&data, codec, 3).unwrap();
            let decoded = decompress(&compressed, codec).unwrap();
            assert_eq!(decoded, data);
        }
        assert_eq!(decompress(b"plain", Compression::None).unwrap(), b"plain");
        assert!(matches!(
            decompress(b"invalid", Compression::Lz4),
            Err(ArgosError::Invalid(_))
        ));
        assert!(matches!(
            decompress(b"invalid", Compression::Zstd),
            Err(ArgosError::Invalid(_))
        ));
    }
}
