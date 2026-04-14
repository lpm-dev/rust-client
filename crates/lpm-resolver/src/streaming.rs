//! Phase 36: Shared streaming prefetch cache for install-path batch/resolve overlap.
//!
//! Populated concurrently by the batch producer task in `install.rs`.
//! Read by the resolver's provider via non-blocking lookups.
//!
//! Not used for non-install callers (`lpm resolve`, `lpm why`, etc.) —
//! those continue to use provider-internal batching as their fetch mechanism.

use crate::provider::CachedPackageInfo;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};

/// Shared streaming prefetch cache for install-path batch/resolve overlap.
///
/// Thread-safe: the producer writes sequentially from a single task,
/// while the resolver reads from a `spawn_blocking` thread via
/// `ensure_cached()` and the batch-decision points.
///
/// Uses `parking_lot::RwLock<HashMap>` rather than `DashMap` because
/// `parking_lot` is already a workspace dependency and the access pattern
/// is simple (single sequential writer, concurrent readers).
pub struct StreamingPrefetch {
    cache: RwLock<HashMap<String, CachedPackageInfo>>,
    /// Set to `true` when the producer has finished (success or error).
    done: AtomicBool,
    /// Set to `true` if the producer encountered an error before completing.
    errored: AtomicBool,
}

impl StreamingPrefetch {
    pub fn new() -> Self {
        Self {
            cache: RwLock::new(HashMap::new()),
            done: AtomicBool::new(false),
            errored: AtomicBool::new(false),
        }
    }

    /// Insert a pre-parsed entry. Called by the producer task in `install.rs`.
    pub fn insert(&self, name: String, info: CachedPackageInfo) {
        self.cache.write().insert(name, info);
    }

    /// Non-blocking lookup. Returns `None` if the entry hasn't arrived yet
    /// or was never part of the batch. Callers must handle both cases
    /// (fall through to provider batching or individual fetch).
    pub fn get(&self, name: &str) -> Option<CachedPackageInfo> {
        let _prof = crate::profile::streaming_lookup::start();
        let info = self.cache.read().get(name).cloned();
        crate::profile::record_streaming_lookup(info.is_some());
        info
    }

    /// Check if a name is present without cloning the value.
    pub fn contains(&self, name: &str) -> bool {
        self.cache.read().contains_key(name)
    }

    /// Check whether all names in the given set are present.
    /// Used by the root-set-ready barrier in `install.rs`.
    pub fn contains_all(&self, names: &[String]) -> bool {
        let cache = self.cache.read();
        names.iter().all(|n| cache.contains_key(n))
    }

    /// Mark the stream as complete (success).
    pub fn mark_done(&self) {
        self.done.store(true, Ordering::Release);
    }

    /// Mark the stream as failed. Also sets `done` so consumers
    /// stop expecting more entries.
    pub fn mark_errored(&self) {
        self.errored.store(true, Ordering::Release);
        self.done.store(true, Ordering::Release);
    }

    /// Whether the producer has finished (success or error).
    pub fn is_done(&self) -> bool {
        self.done.load(Ordering::Acquire)
    }

    /// Whether the producer encountered an error.
    pub fn has_errored(&self) -> bool {
        self.errored.load(Ordering::Acquire)
    }

    /// Number of entries currently in the cache.
    pub fn len(&self) -> usize {
        self.cache.read().len()
    }

    /// Whether the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.cache.read().is_empty()
    }
}

impl Default for StreamingPrefetch {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::npm_version::NpmVersion;

    fn dummy_info() -> CachedPackageInfo {
        CachedPackageInfo {
            versions: vec![NpmVersion::new(1, 0, 0)],
            deps: HashMap::new(),
            peer_deps: HashMap::new(),
            optional_dep_names: HashMap::new(),
            platform: HashMap::new(),
            dist: HashMap::new(),
        }
    }

    #[test]
    fn insert_and_get() {
        let sp = StreamingPrefetch::new();
        assert!(sp.get("lodash").is_none());
        assert!(!sp.contains("lodash"));

        sp.insert("lodash".to_string(), dummy_info());
        assert!(sp.contains("lodash"));
        assert!(sp.get("lodash").is_some());
        assert_eq!(sp.len(), 1);
    }

    #[test]
    fn contains_all() {
        let sp = StreamingPrefetch::new();
        let names = vec!["a".to_string(), "b".to_string(), "c".to_string()];

        assert!(!sp.contains_all(&names));

        sp.insert("a".to_string(), dummy_info());
        sp.insert("b".to_string(), dummy_info());
        assert!(!sp.contains_all(&names));

        sp.insert("c".to_string(), dummy_info());
        assert!(sp.contains_all(&names));
    }

    #[test]
    fn done_and_error_flags() {
        let sp = StreamingPrefetch::new();
        assert!(!sp.is_done());
        assert!(!sp.has_errored());

        sp.mark_done();
        assert!(sp.is_done());
        assert!(!sp.has_errored());
    }

    #[test]
    fn mark_errored_sets_done() {
        let sp = StreamingPrefetch::new();
        sp.mark_errored();
        assert!(sp.is_done());
        assert!(sp.has_errored());
    }

    #[test]
    fn empty_default() {
        let sp = StreamingPrefetch::default();
        assert!(sp.is_empty());
        assert_eq!(sp.len(), 0);
    }
}
