use crate::error::Result;
use crate::util::{atomic_write, ensure_dir, sha256_hex};
use parking_lot::Mutex;
use serde_json::json;
use std::collections::{BTreeMap, VecDeque};
use std::path::{Path, PathBuf};

#[derive(Default)]
struct CacheInner {
    bytes: usize,
    items: BTreeMap<String, Vec<u8>>,
    order: VecDeque<String>,
    hits: u64,
    misses: u64,
    l2_hits: u64,
    l2_writes: u64,
}

pub struct BlockCache {
    root: PathBuf,
    memory_limit: usize,
    l2_limit: u64,
    inner: Mutex<CacheInner>,
}

impl BlockCache {
    pub fn new(root: impl AsRef<Path>, memory_limit: usize, l2_limit: u64) -> Self {
        let root = root.as_ref().to_path_buf();
        let _ = ensure_dir(&root);
        Self {
            root,
            memory_limit,
            l2_limit,
            inner: Mutex::new(CacheInner::default()),
        }
    }

    pub fn get(&self, key: &str, expected_sha: Option<&str>) -> Option<Vec<u8>> {
        let mut inner = self.inner.lock();
        if let Some(value) = inner.items.get(key).cloned() {
            if expected_sha
                .map(|sha| sha == sha256_hex(&value))
                .unwrap_or(true)
            {
                inner.hits += 1;
                inner.order.retain(|candidate| candidate != key);
                inner.order.push_back(key.to_string());
                return Some(value);
            }
        }
        drop(inner);
        if self.l2_limit > 0 {
            let path = self.l2_path(key);
            if let Ok(value) = std::fs::read(&path) {
                if expected_sha
                    .map(|sha| sha == sha256_hex(&value))
                    .unwrap_or(true)
                {
                    let mut inner = self.inner.lock();
                    inner.l2_hits += 1;
                    drop(inner);
                    let _ = self.put(key, &value);
                    return Some(value);
                }
            }
        }
        let mut inner = self.inner.lock();
        inner.misses += 1;
        None
    }

    pub fn put(&self, key: &str, data: &[u8]) -> Result<()> {
        {
            let mut inner = self.inner.lock();
            if self.memory_limit > 0 {
                if let Some(old) = inner.items.remove(key) {
                    inner.bytes = inner.bytes.saturating_sub(old.len());
                    inner.order.retain(|candidate| candidate != key);
                }
                inner.items.insert(key.to_string(), data.to_vec());
                inner.order.push_back(key.to_string());
                inner.bytes += data.len();
                while inner.bytes > self.memory_limit {
                    if let Some(oldest) = inner.order.pop_front() {
                        if let Some(value) = inner.items.remove(&oldest) {
                            inner.bytes = inner.bytes.saturating_sub(value.len());
                        }
                    } else {
                        break;
                    }
                }
            }
        }
        if self.l2_limit > 0 {
            let path = self.l2_path(key);
            atomic_write(&path, data)?;
            let mut inner = self.inner.lock();
            inner.l2_writes += 1;
        }
        Ok(())
    }

    pub fn invalidate_prefix(&self, prefix: &str) {
        let mut inner = self.inner.lock();
        let keys: Vec<String> = inner
            .items
            .keys()
            .filter(|key| key.starts_with(prefix))
            .cloned()
            .collect();
        for key in keys {
            if let Some(value) = inner.items.remove(&key) {
                inner.bytes = inner.bytes.saturating_sub(value.len());
            }
            inner.order.retain(|candidate| candidate != &key);
        }
    }

    pub fn stats(&self) -> BTreeMap<String, serde_json::Value> {
        let inner = self.inner.lock();
        let total = inner.hits + inner.misses + inner.l2_hits;
        BTreeMap::from([
            ("memory_items".to_string(), json!(inner.items.len())),
            ("memory_bytes".to_string(), json!(inner.bytes)),
            ("hits".to_string(), json!(inner.hits)),
            ("misses".to_string(), json!(inner.misses)),
            ("l2_hits".to_string(), json!(inner.l2_hits)),
            ("l2_writes".to_string(), json!(inner.l2_writes)),
            (
                "hit_ratio".to_string(),
                json!(if total == 0 {
                    0.0
                } else {
                    (inner.hits + inner.l2_hits) as f64 / total as f64
                }),
            ),
        ])
    }

    fn l2_path(&self, key: &str) -> PathBuf {
        let digest = sha256_hex(key.as_bytes());
        self.root.join(&digest[..2]).join(format!("{digest}.blk"))
    }
}
