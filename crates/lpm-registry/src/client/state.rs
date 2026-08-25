use super::*;

pub(super) type MetadataMemoryCache = Arc<std::sync::Mutex<HashMap<String, Arc<PackageMetadata>>>>;
pub(super) type ReleaseTimeMemoryCache =
    Arc<std::sync::Mutex<HashMap<String, Arc<ReleaseTimeMetadata>>>>;
pub(super) type MetadataRouteOverrides =
    Arc<std::sync::Mutex<HashMap<String, crate::route::RouteMode>>>;
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

#[derive(Debug)]
pub struct TimedPackageMetadata {
    pub metadata: PackageMetadata,
    pub timings: PackageMetadataFetchTimings,
}

#[derive(Debug)]
pub struct TimedReleaseTimeMetadata {
    pub metadata: ReleaseTimeMetadata,
    pub timings: PackageMetadataFetchTimings,
}

/// Magic-verified cache content: ETag + raw data bytes ready for deserialization.
pub(super) struct CacheContent {
    #[cfg(test)]
    pub(super) etag: Option<String>,
    pub(super) data: Vec<u8>,
}

/// Magic-verified cache validator used for conditional metadata requests.
pub(super) struct CacheValidator {
    pub(super) etag: Option<String>,
    pub(super) age_seconds: Option<u64>,
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
    /// Bearer token for authenticated requests. None for anonymous.
    /// Wrapped in `SecretString` to prevent accidental logging/display (S5).
    pub(super) token: Option<SecretString>,
    /// Path to the metadata cache directory. None disables caching.
    pub(super) cache_dir: Option<std::path::PathBuf>,
    /// Handles for in-flight `spawn_blocking` cache writes. Production
    /// callers never observe this (the writes are fire-and-forget and the
    /// handles drop on `RegistryClient::drop`). Tests call
    /// [`Self::flush_pending_cache_writes`] to deterministically await all
    /// pending writes before reading the cache back. The push is one
    /// `Mutex` acquire + `Vec` push per write — sub-µs vs the ms-scale
    /// `std::fs::write` it tracks.
    pub(super) pending_cache_writes: Arc<std::sync::Mutex<Vec<tokio::task::JoinHandle<()>>>>,
    /// Byte budget held by queued asynchronous metadata-cache buffers.
    /// Cache writes are best-effort and are skipped when a cold metadata
    /// burst would exceed this bound.
    pub(super) pending_cache_write_bytes: Arc<tokio::sync::Semaphore>,
    /// Optional command-scoped immutable packument cache. Recursive
    /// workspace installs enable it on client clones so independent
    /// importer resolvers can reuse one parsed registry response without
    /// sharing resolver state.
    pub(super) metadata_memory_cache: Option<MetadataMemoryCache>,
    pub(super) release_time_memory_cache: Option<ReleaseTimeMemoryCache>,
    pub(super) metadata_route_overrides: Option<MetadataRouteOverrides>,
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
    pub(super) policy_metadata_client: reqwest::Client,
    pub(super) manual_redirect_client: reqwest::Client,
    pub(super) identity_fp: Option<Arc<str>>,
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
    pub(super) default: CachedClient,
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
}
