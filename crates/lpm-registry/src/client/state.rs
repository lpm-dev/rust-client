use super::*;

/// Result of a verified tarball download. The tarball is spooled to a temp file
/// on disk — only the SRI hash and byte count are kept in memory.
#[derive(Debug)]
pub struct DownloadedTarball {
    /// Temp file containing the raw compressed tarball. Deleted on drop.
    pub file: tempfile::NamedTempFile,
    /// SRI hash computed during download (e.g., "sha512-...").
    pub sri: String,
    /// Compressed size in bytes.
    pub compressed_size: u64,
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

/// A cached HTTP client paired with an opaque fingerprint of the
/// TLS identity it was built with.
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
    pub(super) identity_fp: Option<Arc<str>>,
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
///    Single-flight per origin via the tokio mutex: concurrent callers
///    for the same new origin queue on the lock, second sees the
///    entry inserted by the first.
///
/// **Fallback rule** for both eager and lazy: try `(host, Some(port))`
/// first, fall back to `(host, None)` so an `.npmrc` entry without an
/// explicit port covers any port for that host. Mirrors
/// [`OriginKey`]'s scheme-agnostic auth lookup.
pub struct HttpClients {
    pub(super) default: CachedClient,
    pub(super) eager: HashMap<OriginKey, CachedClient>,
    pub(super) lazy: tokio::sync::Mutex<HashMap<OriginKey, CachedClient>>,
    /// Snapshot of the TLS overrides used to build `default` and
    /// `eager`. Held here so lazy builds can construct matching
    /// per-origin clients on demand.
    pub(super) tls_overrides: Arc<TlsOverrides>,
    /// Shared passphrase provider — one instance across all per-origin
    /// builds (eager + lazy). The inner `PassphraseCache` memoizes
    /// across calls; a fresh provider per build would defeat it.
    pub(super) passphrase: Arc<dyn PassphraseProvider>,
    /// Pre-computed identity fingerprints for every origin that has
    /// per-origin TLS configured. Populated at `with_tls_overrides_for`
    /// time by reading + hashing each origin's certfile (or inheriting
    /// the global identity_fp when the origin has per-origin cafile but
    /// no own identity).
    ///
    /// Cache-key composition is sync and runs BEFORE any actual dispatch.
    /// For lazy-target origins (those configured in `tls.per_origin` but
    /// not in the eager set), the lazy client hasn't been built yet — so
    /// consulting the lazy map at cache-key-compose time misses, and the
    /// key would fall back to the default client's identity_fp. That means
    /// a rotated per-origin cert wouldn't change the cache namespace,
    /// leaking entries across principals on lazy origins. Pre-computation
    /// keeps `identity_fp_for_url` sync while honoring the actual identity
    /// each origin will use at request time.
    ///
    /// Cert read failures here are non-fatal — the entry stays absent and
    /// the lazy build will surface a cited error if/when the origin is
    /// actually reached.
    pub(super) per_origin_identity_fps: HashMap<OriginKey, Arc<str>>,
}
