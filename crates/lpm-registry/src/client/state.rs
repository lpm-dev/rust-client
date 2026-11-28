use super::*;

pub(super) struct MetadataMemoryEntry<T> {
    pub(super) value: Arc<T>,
    pub(super) expires_at: std::time::Instant,
}

pub(super) type MetadataMemoryCache =
    Arc<std::sync::Mutex<HashMap<String, MetadataMemoryEntry<PackageMetadata>>>>;
pub(super) type ReleaseTimeMemoryCache =
    Arc<std::sync::Mutex<HashMap<String, MetadataMemoryEntry<ReleaseTimeMetadata>>>>;
pub(super) type MetadataRouteOverrides =
    Arc<std::sync::Mutex<HashMap<String, crate::route::RouteMode>>>;
#[derive(Clone, Copy)]
pub(super) enum MetadataCommandCachePolicy {
    StoreUntil(std::time::Instant),
    NoStore,
}
pub(super) type MetadataCommandCachePolicies =
    Arc<std::sync::Mutex<HashMap<String, MetadataCommandCachePolicy>>>;
pub(super) const MAX_NPMRC_TLS_CLIENT_SETS: usize = 64;
const HTTP_CLIENTS_PER_TLS_SET: u64 = 3;

#[derive(Debug)]
pub(super) struct TlsMaterialBudget {
    used: std::sync::atomic::AtomicU64,
    global_root_bytes: u64,
    global_identity_bytes: std::sync::atomic::AtomicU64,
    read_lock: std::sync::Mutex<()>,
}

impl TlsMaterialBudget {
    pub(super) fn new(initial_bytes: u64) -> Result<Self, LpmError> {
        Self::new_with_retained_source(initial_bytes, 0)
    }

    pub(super) fn new_with_retained_source(
        initial_bytes: u64,
        retained_source_bytes: u64,
    ) -> Result<Self, LpmError> {
        let retained_bytes = initial_bytes
            .checked_mul(HTTP_CLIENTS_PER_TLS_SET)
            .and_then(|bytes| bytes.checked_add(retained_source_bytes))
            .ok_or_else(|| LpmError::Cert("global npmrc TLS material size overflow".into()))?;
        if retained_bytes > lpm_common::TLS_MATERIAL_AGGREGATE_CAP_BYTES {
            return Err(LpmError::Cert(format!(
                "effective npmrc TLS material requires approximately {retained_bytes} retained bytes, exceeding the {}-byte aggregate limit",
                lpm_common::TLS_MATERIAL_AGGREGATE_CAP_BYTES
            )));
        }
        Ok(Self {
            used: std::sync::atomic::AtomicU64::new(retained_bytes),
            global_root_bytes: initial_bytes,
            global_identity_bytes: std::sync::atomic::AtomicU64::new(0),
            read_lock: std::sync::Mutex::new(()),
        })
    }

    pub(super) fn reserve(&self, additional_bytes: u64, context: &str) -> Result<(), LpmError> {
        let _read_guard = self
            .read_lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        self.reserve_locked(additional_bytes, context)
    }

    fn reserve_locked(&self, additional_bytes: u64, context: &str) -> Result<(), LpmError> {
        use std::sync::atomic::Ordering;
        let mut used = self.used.load(Ordering::Relaxed);
        loop {
            let total = used
                .checked_add(additional_bytes)
                .ok_or_else(|| LpmError::Cert(format!("{context}: TLS material size overflow")))?;
            if total > lpm_common::TLS_MATERIAL_AGGREGATE_CAP_BYTES {
                return Err(LpmError::Cert(format!(
                    "{context}: effective npmrc TLS material would require {total} bytes, exceeding the {}-byte aggregate limit",
                    lpm_common::TLS_MATERIAL_AGGREGATE_CAP_BYTES
                )));
            }
            match self
                .used
                .compare_exchange_weak(used, total, Ordering::AcqRel, Ordering::Relaxed)
            {
                Ok(_) => return Ok(()),
                Err(actual) => used = actual,
            }
        }
    }

    pub(super) fn read_material<'a>(
        &'a self,
        path: &std::path::Path,
        context: &str,
    ) -> Result<(Vec<u8>, std::fs::Metadata, TlsMaterialReservation<'a>), LpmError> {
        use std::sync::atomic::Ordering;

        let _read_guard = self
            .read_lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let used = self.used.load(Ordering::Acquire);
        let available = lpm_common::TLS_MATERIAL_AGGREGATE_CAP_BYTES.saturating_sub(used);
        let read_limit = available.min(lpm_common::TLS_MATERIAL_FILE_SIZE_CAP_BYTES);
        let (bytes, metadata) = lpm_common::read_regular_file_capped_with_metadata(
            path, read_limit,
        )
        .map_err(|error| {
            if matches!(error, lpm_common::BoundedReadError::TooLarge { .. })
                && read_limit < lpm_common::TLS_MATERIAL_FILE_SIZE_CAP_BYTES
            {
                LpmError::Cert(format!(
                    "{context}: TLS material would exceed the {}-byte aggregate limit",
                    lpm_common::TLS_MATERIAL_AGGREGATE_CAP_BYTES
                ))
            } else {
                LpmError::Cert(format!("{context}: {error}"))
            }
        })?;
        let reserved_bytes = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        self.reserve_locked(reserved_bytes, context)?;
        Ok((
            bytes,
            metadata,
            TlsMaterialReservation {
                budget: self,
                bytes: reserved_bytes,
                committed: false,
            },
        ))
    }

    pub(super) fn reserve_client_set(
        &self,
        origin_root_bytes: u64,
        per_origin_identity_bytes: Option<u64>,
        context: &str,
    ) -> Result<u64, LpmError> {
        use std::sync::atomic::Ordering;

        let identity_bytes = per_origin_identity_bytes
            .unwrap_or_else(|| self.global_identity_bytes.load(Ordering::Acquire));
        let retained_bytes = self
            .global_root_bytes
            .checked_add(origin_root_bytes)
            .and_then(|bytes| bytes.checked_add(identity_bytes))
            .and_then(|bytes| bytes.checked_mul(HTTP_CLIENTS_PER_TLS_SET))
            .ok_or_else(|| LpmError::Cert(format!("{context}: TLS material size overflow")))?;
        self.reserve(retained_bytes, context)?;
        Ok(retained_bytes)
    }

    pub(super) fn set_global_identity_bytes(&self, bytes: u64) -> Result<(), LpmError> {
        use std::sync::atomic::Ordering;

        self.global_identity_bytes
            .compare_exchange(0, bytes, Ordering::AcqRel, Ordering::Acquire)
            .map(|_| ())
            .map_err(|_| LpmError::Cert("global npmrc TLS identity was initialized twice".into()))
    }

    pub(super) fn reserve_temporary(
        &self,
        bytes: u64,
        context: &str,
    ) -> Result<TlsMaterialReservation<'_>, LpmError> {
        self.reserve(bytes, context)?;
        Ok(TlsMaterialReservation {
            budget: self,
            bytes,
            committed: false,
        })
    }

    pub(super) fn release(&self, bytes: u64) {
        use std::sync::atomic::Ordering;

        self.used.fetch_sub(bytes, Ordering::AcqRel);
    }
}

pub(super) struct TlsMaterialReservation<'a> {
    budget: &'a TlsMaterialBudget,
    bytes: u64,
    committed: bool,
}

impl TlsMaterialReservation<'_> {
    pub(super) fn commit(mut self) {
        self.committed = true;
    }
}

impl Drop for TlsMaterialReservation<'_> {
    fn drop(&mut self) {
        if !self.committed {
            self.budget.release(self.bytes);
        }
    }
}

#[cfg(test)]
mod tls_material_budget_tests {
    use super::*;

    #[test]
    fn replacing_per_origin_identity_is_not_charged_for_the_global_identity() {
        let global_identity_bytes = 4 * 1024 * 1024;
        let budget = TlsMaterialBudget::new_with_retained_source(
            0,
            global_identity_bytes * HTTP_CLIENTS_PER_TLS_SET,
        )
        .unwrap();
        budget
            .set_global_identity_bytes(global_identity_bytes)
            .unwrap();

        let reserved = budget
            .reserve_client_set(0, Some(1024 * 1024), "replacing identity")
            .expect("the replacement identity must fit within the remaining budget");

        assert_eq!(reserved, 3 * 1024 * 1024);
    }
}

/// Aggregate capacity retained by one file-backed compressed archive.
#[derive(Debug)]
pub struct CompressedTarballSpoolReservation {
    pub(super) permit: tokio::sync::OwnedSemaphorePermit,
    pub(super) reserved_bytes: u64,
}

impl CompressedTarballSpoolReservation {
    /// Reject a spool that would retain more bytes than it reserved.
    pub fn ensure_size(&self, bytes: u64) -> Result<(), LpmError> {
        if bytes > self.reserved_bytes {
            return Err(LpmError::Registry(format!(
                "compressed tarball exceeded its reserved spool size ({bytes} bytes > {} bytes reserved)",
                self.reserved_bytes
            )));
        }
        Ok(())
    }

    pub(super) fn retain_bytes(&mut self, bytes: u64) -> Result<(), LpmError> {
        self.ensure_size(bytes)?;
        let retained_permits = super::tarball::compressed_tarball_spool_permits(bytes);
        let excess = self.permit.num_permits().saturating_sub(retained_permits);
        if excess > 0 {
            drop(self.permit.split(excess));
        }
        self.reserved_bytes = bytes;
        Ok(())
    }
}

/// Result of a verified tarball download. The tarball is spooled to a temp file
/// on disk — only the SRI hash and byte count are kept in memory.
#[derive(Debug)]
pub struct DownloadedTarball {
    /// Temp file containing the raw compressed tarball. Deleted on drop.
    pub file: tempfile::NamedTempFile,
    /// Verified SRI in the declaration's algorithm, or SHA-512 for TOFU.
    pub sri: String,
    /// Canonical SHA-512 SRI used for content-addressed object storage.
    pub sha512_sri: String,
    /// Compressed size in bytes.
    pub compressed_size: u64,
    _spool_reservation: CompressedTarballSpoolReservation,
}

// A Drop implementation prevents disjoint closure capture from separating the
// temporary file from its budget when a blocking consumer outlives its waiter.
impl Drop for DownloadedTarball {
    fn drop(&mut self) {}
}

impl DownloadedTarball {
    /// Build a file-backed archive while retaining its aggregate spool budget.
    pub fn new(
        file: tempfile::NamedTempFile,
        sri: String,
        sha512_sri: String,
        compressed_size: u64,
        mut spool_reservation: CompressedTarballSpoolReservation,
    ) -> Result<Self, LpmError> {
        spool_reservation.retain_bytes(compressed_size)?;
        Ok(Self {
            file,
            sri,
            sha512_sri,
            compressed_size,
            _spool_reservation: spool_reservation,
        })
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct PackageMetadataFetchTimings {
    /// The selected version came from the full-history representation.
    pub selected_from_history: bool,
    pub cache_hit: bool,
    pub not_modified: bool,
    pub cache_age_seconds: Option<u64>,
    pub cache_read_ms: u128,
    pub validator_read_ms: u128,
    pub http_ms: u128,
    pub body_read_ms: u128,
    pub json_decode_ms: u128,
    pub cache_after_304_ms: u128,
    pub cache_write_dispatch_ms: u128,
    pub body_bytes: u64,
}

impl PackageMetadataFetchTimings {
    pub(super) fn add_attempt(&mut self, earlier: &Self) {
        self.cache_read_ms += earlier.cache_read_ms;
        self.validator_read_ms += earlier.validator_read_ms;
        self.http_ms += earlier.http_ms;
        self.body_read_ms += earlier.body_read_ms;
        self.json_decode_ms += earlier.json_decode_ms;
        self.cache_after_304_ms += earlier.cache_after_304_ms;
        self.cache_write_dispatch_ms += earlier.cache_write_dispatch_ms;
        self.body_bytes += earlier.body_bytes;
    }

    /// Merge an attempt that overlapped this one. Transfer intervals overlap in
    /// wall time, so they keep the longer interval; local work and bytes add.
    pub(super) fn add_concurrent_attempt(&mut self, overlapping: &Self) {
        self.cache_read_ms += overlapping.cache_read_ms;
        self.validator_read_ms += overlapping.validator_read_ms;
        self.http_ms = self.http_ms.max(overlapping.http_ms);
        self.body_read_ms = self.body_read_ms.max(overlapping.body_read_ms);
        self.json_decode_ms += overlapping.json_decode_ms;
        self.cache_after_304_ms += overlapping.cache_after_304_ms;
        self.cache_write_dispatch_ms += overlapping.cache_write_dispatch_ms;
        self.body_bytes += overlapping.body_bytes;
    }
}

/// Failure together with the measured work from all attempted metadata sources.
#[derive(Debug, thiserror::Error)]
#[error("{error}")]
pub struct PackageMetadataFetchError {
    #[source]
    pub error: LpmError,
    pub timings: PackageMetadataFetchTimings,
}

#[derive(Debug)]
pub struct TimedPackageMetadata {
    pub metadata: PackageMetadata,
    pub timings: PackageMetadataFetchTimings,
}

/// Resolver metadata with independent version and platform-field coverage.
#[derive(Debug)]
pub struct TimedPreferredMetadata {
    pub fetched: TimedPackageMetadata,
    /// False when only manifests selected by a preference are available.
    pub versions_complete: bool,
    /// True when every retained manifest came from a full version document.
    pub platform_metadata_complete: bool,
}

/// Resolver metadata answered by a document or by its stored projection.
#[derive(Debug)]
pub struct TimedPreferredResolution<P> {
    pub metadata: super::ResolutionMetadata<P>,
    pub timings: PackageMetadataFetchTimings,
    /// False when only manifests selected by a preference are available.
    pub versions_complete: bool,
    /// True when every retained manifest came from a full version document.
    pub platform_metadata_complete: bool,
}

impl From<TimedPreferredResolution<super::NoProjection>> for TimedPreferredMetadata {
    fn from(resolution: TimedPreferredResolution<super::NoProjection>) -> Self {
        Self {
            fetched: TimedPackageMetadata {
                metadata: resolution.metadata.into_document(),
                timings: resolution.timings,
            },
            versions_complete: resolution.versions_complete,
            platform_metadata_complete: resolution.platform_metadata_complete,
        }
    }
}

/// Direct npm package history answered by a document or by its stored projection.
#[derive(Debug)]
pub struct TimedDirectResolution<P> {
    pub metadata: super::ResolutionMetadata<P>,
    /// Slot for writing or upgrading the cached projection bound to this document.
    pub projection_slot: Option<super::ProjectionSlot>,
    pub timings: PackageMetadataFetchTimings,
}

#[derive(Debug)]
pub struct TimedReleaseTimeMetadata {
    pub metadata: Arc<ReleaseTimeMetadata>,
    pub timings: PackageMetadataFetchTimings,
}

/// Magic-verified cache content: ETag + raw data bytes ready for deserialization.
#[cfg(test)]
pub(super) struct CacheContent {
    pub(super) etag: Option<String>,
    pub(super) fresh_for: std::time::Duration,
    pub(super) data: Vec<u8>,
}

/// Magic-verified cache validator used for conditional metadata requests.
pub(super) struct CacheValidator {
    pub(super) etag: Option<String>,
    pub(super) age_seconds: Option<u64>,
}

pub(super) struct MetadataCacheEntry<T> {
    pub(super) value: T,
    pub(super) etag: Option<String>,
    pub(super) remaining_freshness: std::time::Duration,
}

#[derive(Default)]
pub(super) struct MetadataCacheOperationState {
    pub(super) pending_projection: Option<super::projection::PendingProjection>,
}

pub(super) struct MetadataCacheMutation {
    pub(super) revision: std::sync::atomic::AtomicU64,
    pub(super) content_revision: std::sync::atomic::AtomicU64,
    pub(super) completed_revision: std::sync::atomic::AtomicU64,
    pub(super) completed_content_revision: std::sync::atomic::AtomicU64,
    pub(super) published_revision: std::sync::atomic::AtomicU64,
    pub(super) projection_revision: std::sync::atomic::AtomicU64,
    pub(super) operation: std::sync::Mutex<MetadataCacheOperationState>,
}

impl MetadataCacheMutation {
    pub(super) fn new() -> Self {
        Self {
            revision: std::sync::atomic::AtomicU64::new(0),
            content_revision: std::sync::atomic::AtomicU64::new(0),
            completed_revision: std::sync::atomic::AtomicU64::new(0),
            completed_content_revision: std::sync::atomic::AtomicU64::new(0),
            published_revision: std::sync::atomic::AtomicU64::new(0),
            projection_revision: std::sync::atomic::AtomicU64::new(0),
            operation: std::sync::Mutex::new(MetadataCacheOperationState::default()),
        }
    }
}

/// Observability for [`RegistryClient::parallel_fetch_npm_manifests`].
///
/// Surfaced to the BFS walker so `timing.resolve.streaming_bfs` can
/// report adaptive-backoff events without the walker interpreting
/// individual per-request errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FanOutStats {
    /// Concurrency ceiling the call started with (after flooring).
    pub initial_concurrency: usize,
    /// Concurrency ceiling at call completion — lower than `initial` iff
    /// halve-on-429 fired.
    pub final_concurrency: usize,
    /// Number of 429 observations that triggered a pool halving.
    pub halve_events: usize,
}

/// Tracks in-flight asynchronous metadata cache writes without retaining
/// completed `JoinHandle`s across long-lived clients.
#[derive(Default)]
pub(super) struct PendingCacheWrites {
    active: std::sync::atomic::AtomicUsize,
    drained: tokio::sync::Notify,
}

pub(super) struct PendingCacheWriteGuard {
    tracker: Arc<PendingCacheWrites>,
}

impl PendingCacheWrites {
    pub(super) fn enter(self: &Arc<Self>) -> PendingCacheWriteGuard {
        self.active
            .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
        PendingCacheWriteGuard {
            tracker: Arc::clone(self),
        }
    }

    pub(super) async fn flush(&self) {
        loop {
            let notified = self.drained.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.active.load(std::sync::atomic::Ordering::Acquire) == 0 {
                return;
            }
            notified.await;
        }
    }
}

impl Drop for PendingCacheWriteGuard {
    fn drop(&mut self) {
        if self
            .tracker
            .active
            .fetch_sub(1, std::sync::atomic::Ordering::AcqRel)
            == 1
        {
            self.tracker.drained.notify_waiters();
        }
    }
}

pub(super) struct WeakEntryMap<K, V> {
    entries: HashMap<K, std::sync::Weak<V>>,
    prune_at: usize,
    misses_since_prune: usize,
    #[cfg(test)]
    prune_count: usize,
}

impl<K, V> WeakEntryMap<K, V>
where
    K: Eq + std::hash::Hash,
{
    pub(super) fn new() -> Self {
        Self {
            entries: HashMap::new(),
            prune_at: 64,
            misses_since_prune: 0,
            #[cfg(test)]
            prune_count: 0,
        }
    }

    pub(super) fn get_or_insert<Q>(&mut self, key: &Q, create: impl FnOnce() -> Arc<V>) -> Arc<V>
    where
        K: std::borrow::Borrow<Q>,
        Q: Eq + std::hash::Hash + ToOwned<Owned = K> + ?Sized,
    {
        if let Some(existing) = self.entries.get(key).and_then(std::sync::Weak::upgrade) {
            return existing;
        }
        if self.entries.len() >= self.prune_at || self.misses_since_prune >= self.prune_at {
            self.entries.retain(|_, weak| weak.strong_count() > 0);
            self.misses_since_prune = 0;
            self.prune_at = self.entries.len().saturating_mul(2).max(64);
            if self.entries.capacity() > self.prune_at.saturating_mul(4) {
                self.entries.shrink_to(self.prune_at);
            }
            #[cfg(test)]
            {
                self.prune_count += 1;
            }
        }
        self.misses_since_prune = self.misses_since_prune.saturating_add(1);
        let value = create();
        self.entries.insert(key.to_owned(), Arc::downgrade(&value));
        value
    }

    #[cfg(test)]
    pub(super) fn len(&self) -> usize {
        self.entries.len()
    }

    #[cfg(test)]
    pub(super) fn insert(&mut self, key: K, value: std::sync::Weak<V>) {
        self.entries.insert(key, value);
    }

    #[cfg(test)]
    pub(super) fn prune_count(&self) -> usize {
        self.prune_count
    }
}

/// Client for communicating with the LPM registry.
pub struct RegistryClient {
    /// Bundle of HTTP clients keyed by origin. Default client + eager +
    /// lazy per-origin clients all live behind one `Arc<HttpClients>` so
    /// cloning the registry client is one ref-bump and per-origin pool
    /// fragmentation is contained.
    pub(super) http: Arc<HttpClients>,
    /// Base URL of the LPM registry (default: https://lpm.dev).
    pub(super) base_url: String,
    /// Base URL of the direct npm registry fallback.
    pub(super) npm_registry_url: String,
    /// Origin that serves requests addressed to `npm_registry_url`, which
    /// keeps its identity in lockfiles and routing.
    pub(super) npm_transport_url: Option<String>,
    /// Bearer token for authenticated requests. None for anonymous.
    /// Wrapped in `SecretString` to prevent accidental logging/display (S5).
    pub(super) token: Option<SecretString>,
    /// Path to the metadata cache directory. None disables caching.
    pub(super) cache_dir: Option<std::path::PathBuf>,
    /// Count + waiter notification for in-flight `spawn_blocking` cache writes.
    pub(super) pending_cache_writes: Arc<PendingCacheWrites>,
    /// Byte budget held by queued asynchronous metadata-cache buffers.
    /// Cache writes are best-effort and are skipped when a cold metadata
    /// burst would exceed this bound.
    pub(super) pending_cache_write_bytes: Arc<tokio::sync::Semaphore>,
    pub(super) metadata_cache_mutations:
        Arc<std::sync::Mutex<WeakEntryMap<std::path::PathBuf, MetadataCacheMutation>>>,
    /// Optional command-scoped immutable packument cache. Recursive
    /// workspace installs enable it on client clones so independent
    /// importer resolvers can reuse one parsed registry response without
    /// sharing resolver state.
    pub(super) history_cache: Arc<super::history_cache::HistoryCache>,
    pub(super) metadata_memory_cache: Option<MetadataMemoryCache>,
    pub(super) release_time_memory_cache: Option<ReleaseTimeMemoryCache>,
    pub(super) metadata_route_overrides: Option<MetadataRouteOverrides>,
    pub(super) metadata_command_cache_policies: Option<MetadataCommandCachePolicies>,
    /// When set, `write_metadata_cache` runs the file write inline on the
    /// calling thread instead of spawning it onto
    /// `tokio::task::spawn_blocking`. Used by mock-server tests where
    /// "first fetch caches; second fetch is a hit" is the unit being
    /// verified — those tests would otherwise race the spawned write
    /// against the next read. Off by default; production never sets it.
    pub(super) synchronous_cache_writes: bool,
    /// Allow insecure HTTP connections to non-localhost registries (--insecure flag).
    pub(super) allow_insecure: bool,
    /// Shared `SessionManager` for lazy-refresh-aware request auth.
    /// Stored here so that per-method `AuthPosture` plumbing can fetch
    /// the current token / trigger silent refresh without the caller
    /// threading a session in.
    pub(super) session: Option<Arc<SessionManager>>,
    pub(super) package_read_recovery: Arc<tokio::sync::Mutex<bool>>,
    /// Process-local cache for registry package-signing keys, keyed by
    /// registry URL plus auth/mTLS principal.
    pub(super) registry_signing_keys_cache:
        Arc<tokio::sync::Mutex<HashMap<String, Vec<RegistrySigningKey>>>>,
    /// Precomputed ASCII-serialized origin of `base_url`.
    /// Avoids re-parsing + re-allocating on every `is_configured_origin` call.
    pub(super) base_url_origin: String,
    /// Precomputed ASCII-serialized origin of `npm_registry_url`.
    pub(super) npm_registry_url_origin: String,
    /// Whether Worker-routed metadata requests should ask reqwest for HTTP/3.
    pub(super) worker_metadata_http3_enabled: bool,
    /// Lazily-built HTTP/3-capable client for Worker-routed metadata.
    pub(super) worker_metadata_http3_client: Arc<tokio::sync::Mutex<Option<reqwest::Client>>>,
}

// ============================================================================
// Per-origin HTTP client cache
// ============================================================================

/// Two configuration-equivalent HTTP clients paired with an opaque
/// fingerprint of their TLS identity.
///
/// `client` handles the general registry waterfall. The separate policy
/// metadata client keeps large, late release-time responses off that
/// connection pool so HTTP/2 flow control does not serialize unrelated
/// abbreviated packuments.
///
/// `identity_fp` is `Some(<16-hex>)` when the client uses a client
/// certificate (per-origin or global) and `None` for clients with no
/// mTLS identity. The fingerprint feeds the metadata cache key via
/// [`principal_fingerprint`] so a re-issued or rotated client cert
/// invalidates the cache cleanly — same URL + same auth + new
/// identity = different cache namespace.
#[derive(Clone)]
pub(super) struct CachedClient {
    pub(super) client: reqwest::Client,
    /// Redirect-disabled clients for large policy/release-time packuments, each
    /// with its own connection pool. Never empty.
    pub(super) policy_metadata_lanes: Arc<[reqwest::Client]>,
    /// Redirect-disabled clients that carry registry requests in turn, each
    /// with its own connection pool. Never empty.
    pub(super) request_lanes: Arc<[reqwest::Client]>,
    /// Redirect-disabled client without a read timeout, for requests that
    /// move a tarball.
    pub(super) transfer_client: reqwest::Client,
    pub(super) identity_fp: Option<Arc<str>>,
}

/// The client set for origins without TLS configuration of their own. A
/// registry client without TLS overrides builds only the exact client pool
/// each request uses, so short or single-RPC commands do not construct all
/// HTTP clients up front.
pub(super) struct LazyDefaultClient {
    proxy_warning: std::sync::Once,
    client: std::sync::OnceLock<reqwest::Client>,
    policy_metadata_lanes: std::sync::OnceLock<Arc<[std::sync::OnceLock<reqwest::Client>]>>,
    request_lanes: std::sync::OnceLock<Arc<[std::sync::OnceLock<reqwest::Client>]>>,
    transfer_client: std::sync::OnceLock<reqwest::Client>,
}

impl LazyDefaultClient {
    fn new() -> Self {
        Self {
            proxy_warning: std::sync::Once::new(),
            client: std::sync::OnceLock::new(),
            policy_metadata_lanes: std::sync::OnceLock::new(),
            request_lanes: std::sync::OnceLock::new(),
            transfer_client: std::sync::OnceLock::new(),
        }
    }

    fn build(&self, pool: super::http::ClientPool) -> reqwest::Client {
        self.proxy_warning
            .call_once(RegistryClient::warn_env_proxy_if_set);
        RegistryClient::build_default_pool_client(pool)
    }

    fn general(&self) -> &reqwest::Client {
        self.client
            .get_or_init(|| self.build(super::http::ClientPool::General))
    }

    fn select(&self, pool: super::http::ClientPool) -> reqwest::Client {
        match pool {
            super::http::ClientPool::General => self.general().clone(),
            super::http::ClientPool::PolicyMetadata(lane) => {
                let lanes = self.policy_metadata_lanes.get_or_init(|| {
                    let count = super::http::policy_metadata_lane_count(
                        std::env::var("LPM_HTTP").ok().as_deref(),
                    );
                    (0..count)
                        .map(|_| std::sync::OnceLock::new())
                        .collect::<Vec<_>>()
                        .into()
                });
                lanes[lane % lanes.len()]
                    .get_or_init(|| self.build(super::http::ClientPool::PolicyMetadata(lane)))
                    .clone()
            }
            super::http::ClientPool::ManualRedirect(lane) => {
                let lanes = self.request_lanes.get_or_init(|| {
                    let count =
                        super::http::request_lane_count(std::env::var("LPM_HTTP").ok().as_deref());
                    (0..count)
                        .map(|_| std::sync::OnceLock::new())
                        .collect::<Vec<_>>()
                        .into()
                });
                lanes[lane % lanes.len()]
                    .get_or_init(|| self.build(super::http::ClientPool::ManualRedirect(lane)))
                    .clone()
            }
            super::http::ClientPool::Transfer => self
                .transfer_client
                .get_or_init(|| self.build(super::http::ClientPool::Transfer))
                .clone(),
        }
    }

    #[cfg(test)]
    fn is_built(&self) -> bool {
        self.client.get().is_some()
            || self
                .policy_metadata_lanes
                .get()
                .is_some_and(|lanes| lanes.iter().any(|slot| slot.get().is_some()))
            || self.transfer_client.get().is_some()
            || self
                .request_lanes
                .get()
                .is_some_and(|lanes| lanes.iter().any(|slot| slot.get().is_some()))
    }
}

pub(super) enum DefaultClient {
    Built(Box<CachedClient>),
    Lazy(Box<LazyDefaultClient>),
}

impl DefaultClient {
    pub(super) fn built(client: CachedClient) -> Self {
        Self::Built(Box::new(client))
    }

    pub(super) fn on_first_use() -> Self {
        Self::Lazy(Box::new(LazyDefaultClient::new()))
    }

    pub(super) fn general(&self) -> &reqwest::Client {
        match self {
            Self::Built(client) => &client.client,
            Self::Lazy(lazy) => lazy.general(),
        }
    }

    pub(super) fn select(&self, pool: super::http::ClientPool) -> reqwest::Client {
        match self {
            Self::Built(client) => super::http::select_pool(client, pool),
            Self::Lazy(lazy) => lazy.select(pool),
        }
    }

    /// The identity fingerprint, without building a client set that would
    /// carry none.
    pub(super) fn identity_fp(&self) -> Option<&str> {
        match self {
            Self::Built(client) => client.identity_fp.as_deref(),
            Self::Lazy(_) => None,
        }
    }

    #[cfg(test)]
    pub(super) fn is_built(&self) -> bool {
        match self {
            Self::Built(_) => true,
            Self::Lazy(lazy) => lazy.is_built(),
        }
    }
}

#[cfg(test)]
mod lazy_default_client_tests {
    use super::*;

    #[test]
    fn lazy_default_client_builds_only_the_requested_pool() {
        let default = DefaultClient::on_first_use();
        assert!(!default.is_built());

        let _ = default.select(super::super::http::ClientPool::General);
        assert!(default.is_built());
        let DefaultClient::Lazy(lazy) = &default else {
            panic!("expected lazy default client");
        };
        assert!(lazy.client.get().is_some());
        assert!(lazy.policy_metadata_lanes.get().is_none());
        assert!(lazy.request_lanes.get().is_none());
        assert!(lazy.transfer_client.get().is_none());

        let _ = default.select(super::super::http::ClientPool::ManualRedirect(0));
        let lanes = lazy.request_lanes.get().expect("request lanes initialized");
        let built_lanes = lanes.iter().filter(|slot| slot.get().is_some()).count();
        assert_eq!(built_lanes, 1);
        assert!(lazy.policy_metadata_lanes.get().is_none());
        assert!(lazy.transfer_client.get().is_none());

        let _ = default.select(super::super::http::ClientPool::PolicyMetadata(0));
        let policy_lanes = lazy
            .policy_metadata_lanes
            .get()
            .expect("policy metadata lanes initialized");
        let built_policy_lanes = policy_lanes
            .iter()
            .filter(|slot| slot.get().is_some())
            .count();
        assert_eq!(built_policy_lanes, 1);
        let _ = default.select(super::super::http::ClientPool::PolicyMetadata(1));
        if policy_lanes.len() > 1 {
            let built_policy_lanes = policy_lanes
                .iter()
                .filter(|slot| slot.get().is_some())
                .count();
            assert_eq!(built_policy_lanes, 2);
        }
    }

    #[test]
    fn weak_entry_map_prunes_dead_entries_after_burst_during_in_place_reuse() {
        let mut map: WeakEntryMap<String, usize> = WeakEntryMap::new();
        {
            let mut live = Vec::with_capacity(200);
            for i in 0..200 {
                live.push(map.get_or_insert(&format!("burst-{i}"), || Arc::new(i)));
            }
            assert_eq!(map.len(), 200);
        }
        // All 200 burst entries are now dead, while `prune_at` is elevated above 200.
        // Repeatedly replacing a small set of keys in-place must still trigger pruning.
        for round in 0..300 {
            let key = format!("burst-{}", round % 4);
            let _ = map.get_or_insert(&key, || Arc::new(round));
        }
        assert!(
            map.len() <= 64,
            "dead burst keys must be pruned during repeated in-place reuse (remaining={})",
            map.len()
        );
    }
}

pub(super) struct LazyIdentityMaterial {
    pub(super) cert_pem: Arc<Vec<u8>>,
    pub(super) fingerprint: Arc<str>,
}

pub(super) struct LazyIdentityCert {
    pub(super) certfile: crate::npmrc::TaggedPath,
    pub(super) material: std::sync::OnceLock<Result<LazyIdentityMaterial, Arc<str>>>,
}

/// Bundle of HTTP clients keyed by origin. One [`RegistryClient`] holds
/// one of these via `Arc<>` so the per-origin clients survive
/// `clone_with_config` and ride along every request the
/// resolver/installer issues.
///
/// **Three tiers:**
///
/// 1. `default` — used for any origin not in `eager` or `lazy`. Built
///    with the global TLS surface (extra_roots, global identity,
///    strict_ssl).
/// 2. `eager` — pre-built clients for origins this invocation provably
///    reaches. Computed by T4's effective_registry_origins from the
///    explicit top-level request set + the route table. Read-only
///    after `with_tls_overrides_for` returns; lookups don't lock.
/// 3. `lazy` — clients built on first request to a previously-unseen
///    origin (tarball CDN that differs from the metadata host, etc.).
///    A per-origin async cell provides single-flight without serializing
///    independent origins.
///
/// Explicit non-default ports are separate origins. A portless npmrc
/// key never widens TLS state to an explicitly different port.
pub struct HttpClients {
    pub(super) default: DefaultClient,
    pub(super) eager: HashMap<OriginKey, CachedClient>,
    pub(super) lazy: HashMap<OriginKey, tokio::sync::OnceCell<Result<CachedClient, Arc<str>>>>,
    pub(super) built_client_sets: std::sync::atomic::AtomicUsize,
    /// Snapshot of the TLS overrides used to build `default` and
    /// `eager`. Held here so lazy builds can construct matching
    /// per-origin clients on demand.
    pub(super) tls_overrides: Arc<TlsOverrides>,
    /// Shared passphrase provider — one instance across all per-origin
    /// builds (eager + lazy). The inner `PassphraseCache` memoizes
    /// across calls; a fresh provider per build would defeat it.
    pub(super) passphrase: Arc<dyn PassphraseProvider>,
    /// Reusable global identity for per-origin clients that inherit it.
    pub(super) global_identity: Option<Arc<LoadedIdentity>>,
    pub(super) tls_material_budget: Arc<TlsMaterialBudget>,
    pub(super) per_origin_identity_certs: HashMap<OriginKey, LazyIdentityCert>,
    pub(super) next_request_lane: std::sync::atomic::AtomicUsize,
    pub(super) next_policy_metadata_lane: std::sync::atomic::AtomicUsize,
}
