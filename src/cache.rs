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
    l2_loaded: bool,
    l2_bytes: u64,
    l2_index: BTreeMap<PathBuf, L2Entry>,
    l2_clock: u64,
    hits: u64,
    misses: u64,
    l2_hits: u64,
    l2_writes: u64,
}

#[derive(Clone, Copy, Default)]
struct L2Entry {
    size: u64,
    touched: u64,
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
            } else if let Some(old) = inner.items.remove(key) {
                inner.bytes = inner.bytes.saturating_sub(old.len());
                inner.order.retain(|candidate| candidate != key);
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
                    self.put_memory_only(key, &value);
                    return Some(value);
                } else {
                    let _ = std::fs::remove_file(&path);
                    let mut inner = self.inner.lock();
                    if let Some(entry) = inner.l2_index.remove(&path) {
                        inner.l2_bytes = inner.l2_bytes.saturating_sub(entry.size);
                    }
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
            self.load_l2_index()?;
            let path = self.l2_path(key);
            atomic_write(&path, data)?;
            let mut inner = self.inner.lock();
            inner.l2_clock = inner.l2_clock.saturating_add(1);
            let touched = inner.l2_clock;
            let old = inner.l2_index.insert(
                path,
                L2Entry {
                    size: data.len() as u64,
                    touched,
                },
            );
            if let Some(old) = old {
                inner.l2_bytes = inner.l2_bytes.saturating_sub(old.size);
            }
            inner.l2_bytes = inner.l2_bytes.saturating_add(data.len() as u64);
            inner.l2_writes += 1;
            drop(inner);
            self.prune_l2()?;
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

    pub fn remove(&self, key: &str) {
        let mut inner = self.inner.lock();
        if let Some(value) = inner.items.remove(key) {
            inner.bytes = inner.bytes.saturating_sub(value.len());
        }
        inner.order.retain(|candidate| candidate != key);
        drop(inner);
        if self.l2_limit > 0 {
            let path = self.l2_path(key);
            let _ = std::fs::remove_file(&path);
            let mut inner = self.inner.lock();
            if let Some(entry) = inner.l2_index.remove(&path) {
                inner.l2_bytes = inner.l2_bytes.saturating_sub(entry.size);
            }
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
            ("l2_bytes".to_string(), json!(inner.l2_bytes)),
            ("l2_items".to_string(), json!(inner.l2_index.len())),
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

    fn put_memory_only(&self, key: &str, data: &[u8]) {
        let mut inner = self.inner.lock();
        Self::put_memory_only_locked(&mut inner, self.memory_limit, key, data);
    }

    fn put_memory_only_locked(inner: &mut CacheInner, memory_limit: usize, key: &str, data: &[u8]) {
        if memory_limit == 0 {
            return;
        }
        if let Some(old) = inner.items.remove(key) {
            inner.bytes = inner.bytes.saturating_sub(old.len());
            inner.order.retain(|candidate| candidate != key);
        }
        inner.items.insert(key.to_string(), data.to_vec());
        inner.order.push_back(key.to_string());
        inner.bytes += data.len();
        while inner.bytes > memory_limit {
            if let Some(oldest) = inner.order.pop_front() {
                if let Some(value) = inner.items.remove(&oldest) {
                    inner.bytes = inner.bytes.saturating_sub(value.len());
                }
            } else {
                break;
            }
        }
    }

    fn load_l2_index(&self) -> Result<()> {
        let mut inner = self.inner.lock();
        if inner.l2_loaded {
            return Ok(());
        }
        let mut index = BTreeMap::new();
        let mut total = 0u64;
        let mut clock = 0u64;
        for entry in walkdir::WalkDir::new(&self.root)
            .min_depth(1)
            .into_iter()
            .filter_map(|entry| entry.ok())
        {
            if !entry.file_type().is_file() {
                continue;
            }
            let Ok(metadata) = entry.metadata() else {
                continue;
            };
            clock = clock.saturating_add(1);
            let size = metadata.len();
            total = total.saturating_add(size);
            index.insert(
                entry.path().to_path_buf(),
                L2Entry {
                    size,
                    touched: metadata
                        .modified()
                        .ok()
                        .and_then(|time| time.elapsed().ok())
                        .map(|elapsed| u64::MAX.saturating_sub(elapsed.as_secs()))
                        .unwrap_or(clock),
                },
            );
        }
        inner.l2_loaded = true;
        inner.l2_index = index;
        inner.l2_bytes = total;
        inner.l2_clock = clock.max(inner.l2_clock);
        Ok(())
    }

    fn prune_l2(&self) -> Result<()> {
        self.load_l2_index()?;
        let mut inner = self.inner.lock();
        if inner.l2_bytes <= self.l2_limit {
            return Ok(());
        }
        let mut files = inner
            .l2_index
            .iter()
            .map(|(path, entry)| (entry.touched, path.clone(), entry.size))
            .collect::<Vec<_>>();
        files.sort_by(|left, right| left.0.cmp(&right.0).then_with(|| left.1.cmp(&right.1)));
        for (_, path, len) in files {
            if inner.l2_bytes <= self.l2_limit {
                break;
            }
            match std::fs::remove_file(&path) {
                Ok(()) => {
                    inner.l2_bytes = inner.l2_bytes.saturating_sub(len);
                    inner.l2_index.remove(&path);
                }
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                    inner.l2_bytes = inner.l2_bytes.saturating_sub(len);
                    inner.l2_index.remove(&path);
                }
                Err(err) => return Err(err.into()),
            }
        }
        Ok(())
    }
}
