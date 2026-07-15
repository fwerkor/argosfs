use super::*;
use std::sync::{Mutex as StdMutex, OnceLock};
use tempfile::tempdir;

fn env_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: OnceLock<StdMutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| StdMutex::new(())).lock().unwrap()
}

#[test]
fn memory_cache_evicts_replaces_invalidates_and_reports_stats() {
    let dir = tempdir().unwrap();
    let cache = BlockCache::new(dir.path(), 6, 0);
    assert_eq!(cache.stats()["hit_ratio"], 0.0);
    cache.put("a:1", b"aaa").unwrap();
    cache.put("a:2", b"bbb").unwrap();
    assert_eq!(cache.get("a:1", None).unwrap(), b"aaa");
    cache.put("a:3", b"cccc").unwrap();
    assert!(cache.get("a:2", None).is_none());
    assert_eq!(cache.get("a:3", None).unwrap(), b"cccc");

    cache.put("a:3", b"cc").unwrap();
    assert_eq!(cache.get("a:3", None).unwrap(), b"cc");
    cache.put("b:1", b"zz").unwrap();
    cache.invalidate_prefix("a:");
    assert!(cache.get("a:1", None).is_none());
    assert!(cache.get("a:3", None).is_none());
    assert_eq!(cache.get("b:1", None).unwrap(), b"zz");
    cache.remove("b:1");
    cache.remove("missing");
    assert!(cache.get("b:1", None).is_none());

    let stats = cache.stats();
    assert!(stats["hits"].as_u64().unwrap() >= 4);
    assert!(stats["misses"].as_u64().unwrap() >= 4);
    assert!(stats["hit_ratio"].as_f64().unwrap() > 0.0);
}

#[test]
fn checksum_mismatch_removes_memory_and_l2_entries() {
    let dir = tempdir().unwrap();
    let cache = BlockCache::new(dir.path(), 1024, 1024);
    cache.put("key", b"value").unwrap();
    let l2_path = cache.l2_path("key");
    assert!(l2_path.exists());
    assert!(cache.get("key", Some(&sha256_hex(b"wrong"))).is_none());
    assert!(!l2_path.exists());
    let stats = cache.stats();
    assert_eq!(stats["memory_items"], 0);
    assert_eq!(stats["l2_items"], 0);
}

#[test]
fn l2_index_loads_existing_files_and_prunes_oldest_entries() {
    let dir = tempdir().unwrap();
    let cache = BlockCache::new(dir.path(), 0, 5);
    let first = cache.l2_path("first");
    let second = cache.l2_path("second");
    atomic_write(&first, b"1111").unwrap();
    std::thread::sleep(std::time::Duration::from_millis(5));
    atomic_write(&second, b"2222").unwrap();
    cache.load_l2_index().unwrap();
    assert_eq!(cache.stats()["l2_items"], 2);
    cache.prune_l2().unwrap();
    let remaining = [first.exists(), second.exists()]
        .into_iter()
        .filter(|present| *present)
        .count();
    assert_eq!(remaining, 1);
    assert!(cache.stats()["l2_bytes"].as_u64().unwrap() <= 5);
    cache.prune_l2().unwrap();
}

#[test]
fn l2_hits_promote_to_memory_and_remove_cleans_index() {
    let dir = tempdir().unwrap();
    let writer = BlockCache::new(dir.path(), 0, 1024);
    writer.put("key", b"payload").unwrap();
    let cache = BlockCache::new(dir.path(), 1024, 1024);
    assert_eq!(cache.get("key", None).unwrap(), b"payload");
    assert_eq!(cache.get("key", None).unwrap(), b"payload");
    let stats = cache.stats();
    assert_eq!(stats["l2_hits"], 1);
    assert_eq!(stats["hits"], 1);
    assert_eq!(stats["memory_items"], 1);
    cache.remove("key");
    assert!(cache.get("key", None).is_none());
}

#[test]
fn configured_l2_limit_honors_disable_override_and_invalid_values() {
    let _guard = env_lock();
    std::env::remove_var("ARGOSFS_DISABLE_L2_CACHE");
    std::env::remove_var("ARGOSFS_L2_CACHE_BYTES");
    assert_eq!(configured_l2_limit(123), 123);
    std::env::set_var("ARGOSFS_L2_CACHE_BYTES", "456");
    assert_eq!(configured_l2_limit(123), 456);
    std::env::set_var("ARGOSFS_L2_CACHE_BYTES", "invalid");
    assert_eq!(configured_l2_limit(123), 123);
    std::env::set_var("ARGOSFS_DISABLE_L2_CACHE", "1");
    assert_eq!(configured_l2_limit(123), 0);
    std::env::remove_var("ARGOSFS_DISABLE_L2_CACHE");
    std::env::remove_var("ARGOSFS_L2_CACHE_BYTES");
}
