use crate::error::{ArgosError, Result};
use reed_solomon_erasure::galois_8::ReedSolomon;

pub struct RsCodec {
    inner: ReedSolomon,
    k: usize,
    m: usize,
}

impl RsCodec {
    pub fn new(k: usize, m: usize) -> Result<Self> {
        let inner = ReedSolomon::new(k, m).map_err(|err| ArgosError::Erasure(err.to_string()))?;
        Ok(Self { inner, k, m })
    }

    pub fn total(&self) -> usize {
        self.k + self.m
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
        shards.extend((0..self.m).map(|_| vec![0u8; shard_size]));
        self.inner
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
        self.inner
            .reconstruct(&mut refs)
            .map_err(|err| ArgosError::Erasure(err.to_string()))?;
        refs.into_iter()
            .map(|shard| {
                shard.ok_or_else(|| {
                    ArgosError::Erasure("reconstruction left a missing shard".to_string())
                })
            })
            .collect()
    }
}
