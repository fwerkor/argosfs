use crate::error::{ArgosError, Result};
use erase::galois_8::ReedSolomon;

pub struct RsCodec {
    inner: Option<ReedSolomon>,
    k: usize,
    m: usize,
    total: usize,
}

impl RsCodec {
    pub fn new(k: usize, m: usize) -> Result<Self> {
        if k == 0 {
            return Err(ArgosError::Invalid("k must be positive".to_string()));
        }
        let total = k
            .checked_add(m)
            .ok_or_else(|| ArgosError::Invalid("erasure shard count overflow".to_string()))?;
        let inner = if m == 0 {
            None
        } else {
            Some(ReedSolomon::new(k, m).map_err(|err| ArgosError::Erasure(err.to_string()))?)
        };
        Ok(Self { inner, k, m, total })
    }

    pub fn total(&self) -> usize {
        self.total
    }

    pub fn encode(&self, data_shards: &[Vec<u8>]) -> Result<Vec<Vec<u8>>> {
        if data_shards.len() != self.k {
            return Err(ArgosError::Invalid(format!(
                "expected {} data shards, got {}",
                self.k,
                data_shards.len()
            )));
        }
        let shard_size = data_shards.first().map(Vec::len).unwrap_or(0);
        if data_shards.iter().any(|shard| shard.len() != shard_size) {
            return Err(ArgosError::Invalid(
                "data shards must have equal size".to_string(),
            ));
        }
        let mut shards = data_shards.to_vec();
        if self.m == 0 {
            return Ok(shards);
        }
        shards.extend((0..self.m).map(|_| vec![0u8; shard_size]));
        self.inner
            .as_ref()
            .expect("m > 0 codec has Reed-Solomon inner")
            .encode(&mut shards)
            .map_err(|err| ArgosError::Erasure(err.to_string()))?;
        Ok(shards)
    }

    pub fn reconstruct(&self, shards: Vec<Option<Vec<u8>>>) -> Result<Vec<Vec<u8>>> {
        if shards.len() != self.total() {
            return Err(ArgosError::Invalid(format!(
                "expected {} shards, got {}",
                self.total(),
                shards.len()
            )));
        }
        let mut refs: Vec<Option<Vec<u8>>> = shards;
        if self.m == 0 {
            if refs.iter().any(Option::is_none) {
                return Err(ArgosError::Erasure(
                    "layout has no parity shards for reconstruction".to_string(),
                ));
            }
        } else {
            self.inner
                .as_ref()
                .expect("m > 0 codec has Reed-Solomon inner")
                .reconstruct(&mut refs)
                .map_err(|err| ArgosError::Erasure(err.to_string()))?;
        }
        refs.into_iter()
            .map(|shard| {
                shard.ok_or_else(|| {
                    ArgosError::Erasure("reconstruction left a missing shard".to_string())
                })
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
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
}
