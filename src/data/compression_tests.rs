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
