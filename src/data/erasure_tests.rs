use super::*;

#[test]
fn codec_rejects_zero_data_shards() {
    assert!(matches!(RsCodec::new(0, 1), Err(ArgosError::Invalid(_))));
}

#[test]
fn no_parity_layout_round_trips_and_rejects_missing_shards() {
    let codec = RsCodec::new(2, 0).unwrap();
    assert_eq!(codec.total(), 2);
    let data = vec![b"aaaa".to_vec(), b"bbbb".to_vec()];
    assert_eq!(codec.encode(&data).unwrap(), data);
    assert_eq!(
        codec
            .reconstruct(vec![Some(b"aaaa".to_vec()), Some(b"bbbb".to_vec())])
            .unwrap(),
        data
    );
    assert!(matches!(
        codec.reconstruct(vec![Some(b"aaaa".to_vec()), None]),
        Err(ArgosError::Erasure(_))
    ));
}

#[test]
fn parity_layout_reconstructs_data_and_parity() {
    let codec = RsCodec::new(2, 1).unwrap();
    let original = vec![b"aaaa".to_vec(), b"bbbb".to_vec()];
    let encoded = codec.encode(&original).unwrap();
    assert_eq!(encoded.len(), 3);
    let mut missing_data = encoded.iter().cloned().map(Some).collect::<Vec<_>>();
    missing_data[0] = None;
    assert_eq!(codec.reconstruct(missing_data).unwrap(), encoded);
    let mut missing_parity = encoded.iter().cloned().map(Some).collect::<Vec<_>>();
    missing_parity[2] = None;
    assert_eq!(codec.reconstruct(missing_parity).unwrap(), encoded);
}

#[test]
fn codec_validates_counts_and_shard_sizes() {
    let codec = RsCodec::new(2, 1).unwrap();
    assert!(matches!(
        codec.encode(&[vec![1]]),
        Err(ArgosError::Invalid(_))
    ));
    assert!(matches!(
        codec.encode(&[vec![1], vec![1, 2]]),
        Err(ArgosError::Invalid(_))
    ));
    assert!(matches!(
        codec.reconstruct(vec![Some(vec![1]), Some(vec![1])]),
        Err(ArgosError::Invalid(_))
    ));
    assert!(matches!(
        codec.reconstruct(vec![Some(vec![1]), None, None]),
        Err(ArgosError::Erasure(_))
    ));
}

#[test]
fn codec_rejects_an_overflowing_shard_count() {
    assert!(matches!(
        RsCodec::new(usize::MAX, 1),
        Err(ArgosError::Invalid(_))
    ));
}
