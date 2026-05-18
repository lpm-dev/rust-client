//! Registry HTTP client.
//!
//! Handles communication with the LPM registry at `lpm.dev`.
//! Publish, token, and OIDC operations are implemented in publish.rs, npmrc.rs, oidc.rs.
//! Uses ETag conditional requests and MessagePack binary cache.

use crate::npmrc::{OriginKey, OriginTlsOverrides, TaggedRoot, TlsOverrides};
use crate::tls_identity::{EnvThenTtyPassphrase, PassphraseProvider, load_identity};
use crate::types::*;
use lpm_auth::{RefreshPolicy, SessionManager};
use lpm_common::{DEFAULT_REGISTRY_URL, LpmError, LpmRoot, NPM_REGISTRY_URL, PackageName};
use secrecy::{ExposeSecret, SecretString};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

/// Per-request auth posture.
///
/// Every public request method on `RegistryClient` is annotated with
/// one of these so the recovery layer (`execute_with_recovery`) can
/// decide whether to attach a bearer at all and whether to attempt a
/// silent refresh on 401.
///
/// - **AnonymousOnly**: never attach a bearer. Used for endpoints that
///   are universally public (npm fallback, health checks).
/// - **AnonymousPreferred**: never attach a bearer even when stored.
///   Used for endpoints that *may* accept auth but the fast path is
///   anonymous (search, public info reads). Avoids needless refresh
///   storms when an old token sits on disk.
/// - **AuthRequired**: attach the bearer if present; on 401, perform
///   a single silent refresh + retry for refresh-backed sessions.
///   Used for install / download / metadata for `@lpm.dev` packages,
///   publish, token management, account-scoped reads.
/// - **SessionRequired**: same as `AuthRequired` for transport, but
///   the **calling command** must additionally check that the
///   `SessionManager` source is `StoredSession`. Used for tunnel,
///   env pairing, and other features that require a real interactive
///   login (not `LPM_TOKEN`/`--token`/CI tokens).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthPosture {
    AnonymousOnly,
    AnonymousPreferred,
    AuthRequired,
    SessionRequired,
}

impl AuthPosture {
    /// Whether this posture attaches a bearer when one is available.
    pub fn attaches_bearer(self) -> bool {
        matches!(
            self,
            AuthPosture::AuthRequired | AuthPosture::SessionRequired
        )
    }

    /// Whether this posture allows a silent refresh + retry on 401.
    pub fn allows_recovery(self) -> bool {
        matches!(
            self,
            AuthPosture::AuthRequired | AuthPosture::SessionRequired
        )
    }
}

/// Maximum number of retries for transient failures.
const MAX_RETRIES: u32 = 3;

/// Base delay for exponential backoff (1 second).
const RETRY_BASE_DELAY: Duration = Duration::from_secs(1);

/// Maximum backoff delay (10 seconds).
const RETRY_MAX_DELAY: Duration = Duration::from_secs(10);

/// Maximum time to establish a TCP + TLS connection.
///
/// Kept conservative — connecting is trivially fast on healthy networks,
/// and anything that exceeds 10 s on connect is usually a DNS or route
/// problem better surfaced quickly than hidden under the body-read
/// window.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Maximum time between successful reads from the response body.
///
/// Replaces a wall-clock `.timeout(30s)` which killed entire requests
/// even when bytes were still flowing. On large NDJSON responses the
/// server can legitimately take 30+ seconds to stream the full body;
/// a wall-clock timer fires mid-body and surfaces as a body-read error.
///
/// `read_timeout` fires ONLY when no bytes arrive for the full window.
/// Healthy streams reset the timer on each successful chunk, so a
/// 5-minute streaming response completes fine as long as chunks keep
/// landing. Hung/stalled servers still get interrupted.
const READ_TIMEOUT: Duration = Duration::from_secs(30);

/// Metadata cache TTL (5 minutes).
const METADATA_CACHE_TTL: std::time::Duration = std::time::Duration::from_secs(300);

/// Max bytes accepted from a single on-disk metadata cache entry.
///
/// The cache lives under `~/.lpm/cache/metadata/` (the trust boundary
/// documented above the magic constant); but a same-user process that
/// can plant a multi-GB file there would force every fresh-path read
/// to allocate it before serde even noticed the bytes were nonsense.
/// 100 MB matches the on-the-wire `MAX_METADATA_BYTES` cap so a
/// legitimate worst-case packument always round-trips through the
/// cache, while pathological files collapse to a cache miss before
/// any decode work happens.
const METADATA_CACHE_FILE_CAP: u64 = 100 * 1024 * 1024;

/// Magic header for the manifest cache file format. Replaces the
/// per-payload HMAC-SHA256 that used to run on every write. The cache
/// lives at `~/.lpm/cache/metadata/` inside the user's home; if an
/// attacker can write there they own the install anyway, so signing
/// the bytes adds no real security boundary.
///
/// On format change, bump the trailing version number — old cache
/// entries fail the magic match and are silently treated as misses.
///
/// V3 bump: custom-registry support means a single package name can
/// be served by multiple distinct registries (e.g., `react` from
/// `registry.npmjs.org` vs an internal mirror). `get_npm_metadata_from`
/// keys per-host (`npm:<host>:<name>`); the magic bump invalidates
/// pre-V3 caches in one shot rather than letting two key formats
/// co-exist with the same magic.
const METADATA_CACHE_MAGIC: &[u8] = b"LPM-MD-V3\n";

/// Apply an `.npmrc`-derived credential to a request builder.
///
/// Re-verifies that the auth's origin is compatible with the destination
/// URL before attaching the `Authorization` header. A mismatch hard-fails
/// with `LpmError::Registry` rather than silently dropping the auth or
/// leaking the token cross-origin. Anonymous (`auth = None`) is a no-op.
///
/// Used by both metadata fetches (`get_npm_metadata_from`) and tarball
/// downloads (`download_tarball_*_with_auth`) so the auth-scope
/// invariant is enforced uniformly across every request that carries
/// an npmrc credential.
fn apply_npmrc_auth(
    req: reqwest::RequestBuilder,
    url: &str,
    auth: Option<&crate::npmrc::RegistryAuth>,
) -> Result<reqwest::RequestBuilder, LpmError> {
    use secrecy::ExposeSecret;
    let Some(a) = auth else {
        return Ok(req);
    };
    let dest = crate::npmrc::OriginKey::from_request_url(url).ok_or_else(|| {
        LpmError::Registry(format!("invalid URL '{url}' — must be http(s) with a host"))
    })?;
    if !a.matches_destination(&dest) {
        return Err(LpmError::Registry(format!(
            "auth/destination origin mismatch: credential scoped to {} but request targets {dest} (this is an lpm bug — please report)",
            a.origin()
        )));
    }
    let req = match a {
        crate::npmrc::RegistryAuth::Bearer { token, .. } => {
            req.header("Authorization", format!("Bearer {}", token.expose_secret()))
        }
        crate::npmrc::RegistryAuth::Basic { credential, .. } => req.header(
            "Authorization",
            format!("Basic {}", credential.expose_secret()),
        ),
    };
    Ok(req)
}

/// Compute a stable opaque fingerprint for a `RegistryAuth` credential
/// PLUS the TLS client identity's cert PEM.
///
/// **Combinatorics:** the cache namespace is `(auth, identity)`-pair
/// scoped, not auth-only. Same URL + same auth + DIFFERENT identity
/// (e.g., user re-issued their client cert) → different cache
/// namespace. Without this, a private registry that varies content
/// per client identity could leak data across principals on the same
/// machine.
///
/// **Output shape:**
/// - Auth `None` + identity `None` → `"anon"` (canonical empty).
/// - Anything else → `"principal-<16hex>"`, where `<16hex>` is the
///   first 16 hex chars of `SHA-256(tagged_inputs)`. Variant tags
///   (`b:` Bearer, `a:` Basic, `i:` Identity) prevent shape
///   collisions across input kinds.
///
/// **Why hashes, not raw secrets:** the cache key flows through
/// `tracing::debug!` calls and may surface in stack traces / panic
/// messages. SHA-256 truncation reveals nothing about the credential
/// or cert while staying deterministic enough for warm-hit reuse
/// across calls with the same principal.
fn principal_fingerprint(
    auth: Option<&crate::npmrc::RegistryAuth>,
    identity_fp: Option<&str>,
) -> String {
    use secrecy::ExposeSecret;
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    let mut tagged = false;
    match auth {
        None => {}
        Some(crate::npmrc::RegistryAuth::Bearer { token, .. }) => {
            hasher.update(b"b:");
            hasher.update(token.expose_secret().as_bytes());
            tagged = true;
        }
        Some(crate::npmrc::RegistryAuth::Basic { credential, .. }) => {
            hasher.update(b"a:");
            hasher.update(credential.expose_secret().as_bytes());
            tagged = true;
        }
    }
    if let Some(fp) = identity_fp {
        hasher.update(b"i:");
        hasher.update(fp.as_bytes());
        tagged = true;
    }
    if !tagged {
        return "anon".to_string();
    }
    let hash = format!("{:x}", hasher.finalize());
    format!("principal-{}", &hash[..16])
}

/// SHA-256 truncated fingerprint of a cert PEM blob — used as the
/// `identity_fp` input to [`principal_fingerprint`]. Hashing happens
/// once at client-build time; the resulting `Arc<str>` rides along
/// the cached client and feeds every cache-key composition for
/// requests that route to it.
fn cert_pem_fingerprint(pem: &[u8]) -> Arc<str> {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(pem);
    let hash = format!("{:x}", hasher.finalize());
    Arc::from(&hash[..16])
}

/// Maximum compressed tarball size (500 MB). Enforced during download to prevent
/// malicious registries from exhausting memory or disk before extraction even starts.
/// Extraction-time limits (5 GB total, 500 MB per file) remain as a second defense.
pub const MAX_COMPRESSED_TARBALL_SIZE: u64 = 500 * 1024 * 1024;

/// Hard cap on the number of bytes we will buffer from a single metadata
/// response body. Real packuments — even for the largest npm packages
/// like `react` or `lodash` — top out at ~10-20 MB; LPM requests the
/// abbreviated packument format (`application/vnd.npm.install-v1+json`)
/// which trims further. 100 MB is several×-headroom over any
/// legitimate metadata response and orders of magnitude below a
/// memory-exhaustion attack from a compromised mirror or MITM.
const MAX_METADATA_BYTES: usize = 100 * 1024 * 1024;

/// Hard cap for non-metadata API responses (whoami, token check,
/// quality/skills, tunnel domain ops, publish ack, error bodies).
/// These payloads are kilobytes in practice; 10 MB gives several
/// orders of magnitude of headroom over the legitimate envelope and
/// stops a hostile / compromised mirror from OOM-ing the CLI on a
/// path that never needed metadata-sized buffers.
const MAX_API_RESPONSE_BYTES: usize = 10 * 1024 * 1024;

/// Drain a response body with a two-stage size cap.
///
/// Stage 1 (pre-stream): refuse when the server's declared
/// `Content-Length` exceeds `cap` — no bytes are allocated for a
/// hostile-declared-length response.
///
/// Stage 2 (mid-stream): for chunked / undeclared-length responses,
/// accumulate `bytes_stream()` chunks into a bounded `Vec` and abort
/// the moment another chunk would cross `cap`. Closing the response
/// at that point drops the underlying connection.
async fn read_capped_body(
    response: reqwest::Response,
    cap: usize,
    context: &str,
) -> Result<Vec<u8>, LpmError> {
    use futures::StreamExt;

    if let Some(declared) = response.content_length()
        && declared as usize > cap
    {
        return Err(LpmError::Registry(format!(
            "{context}: declared body length {declared} exceeds cap {cap}"
        )));
    }

    let mut buf: Vec<u8> = Vec::with_capacity(std::cmp::min(64 * 1024, cap));
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk =
            chunk.map_err(|e| LpmError::Registry(format!("{context}: body read error: {e}")))?;
        if buf.len().saturating_add(chunk.len()) > cap {
            return Err(LpmError::Registry(format!(
                "{context}: streamed body exceeded cap {cap}"
            )));
        }
        buf.extend_from_slice(&chunk);
    }
    Ok(buf)
}

/// Read a metadata-shaped JSON response with the metadata cap.
///
/// Wraps [`read_capped_body`] with the metadata-tier ceiling and
/// `serde_json::from_slice`. Lets the metadata path share one
/// streaming-cap implementation with the smaller-tier API path.
async fn parse_capped_metadata<T: serde::de::DeserializeOwned>(
    response: reqwest::Response,
    context: &str,
) -> Result<T, LpmError> {
    let buf = read_capped_body(response, MAX_METADATA_BYTES, context).await?;
    serde_json::from_slice(&buf)
        .map_err(|e| LpmError::Registry(format!("{context}: failed to parse JSON: {e}")))
}

/// Read a non-metadata JSON response (whoami, token check, etc.) with
/// the smaller API-tier cap. Exposed for callers outside this module
/// (e.g., the `token` command, the `dlx` resolver) that operate on a
/// raw `reqwest::Response` returned by [`RegistryClient::post_json_raw`]
/// and would otherwise reach for `.json()` directly.
pub async fn parse_capped_api_json<T: serde::de::DeserializeOwned>(
    response: reqwest::Response,
    context: &str,
) -> Result<T, LpmError> {
    let buf = read_capped_body(response, MAX_API_RESPONSE_BYTES, context).await?;
    serde_json::from_slice(&buf)
        .map_err(|e| LpmError::Registry(format!("{context}: failed to parse JSON: {e}")))
}

/// Read an error-body response as UTF-8 text under the API-tier cap.
///
/// Returns the empty string on cap-overflow or read errors so the
/// caller can still construct a typed error variant — the previous
/// `response.text().await.unwrap_or_default()` shape is preserved
/// but the buffer is now bounded.
async fn read_capped_error_text(response: reqwest::Response) -> String {
    match read_capped_body(response, MAX_API_RESPONSE_BYTES, "error body").await {
        Ok(buf) => String::from_utf8_lossy(&buf).into_owned(),
        Err(_) => String::new(),
    }
}

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
struct CacheContent {
    etag: Option<String>,
    data: Vec<u8>,
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
    http: Arc<HttpClients>,
    /// Base URL of the LPM registry (default: https://lpm.dev).
    base_url: String,
    /// Base URL of the direct npm registry fallback.
    npm_registry_url: String,
    /// Bearer token for authenticated requests. None for anonymous.
    /// Wrapped in `SecretString` to prevent accidental logging/display (S5).
    token: Option<SecretString>,
    /// Path to the metadata cache directory. None disables caching.
    cache_dir: Option<std::path::PathBuf>,
    /// Handles for in-flight `spawn_blocking` cache writes. Production
    /// callers never observe this (the writes are fire-and-forget and the
    /// handles drop on `RegistryClient::drop`). Tests call
    /// [`Self::flush_pending_cache_writes`] to deterministically await all
    /// pending writes before reading the cache back. The push is one
    /// `Mutex` acquire + `Vec` push per write — sub-µs vs the ms-scale
    /// `std::fs::write` it tracks.
    pending_cache_writes: Arc<std::sync::Mutex<Vec<tokio::task::JoinHandle<()>>>>,
    /// When set, `write_metadata_cache` runs the file write inline on the
    /// calling thread instead of spawning it onto
    /// `tokio::task::spawn_blocking`. Used by mock-server tests where
    /// "first fetch caches; second fetch is a hit" is the unit being
    /// verified — those tests would otherwise race the spawned write
    /// against the next read. Off by default; production never sets it.
    synchronous_cache_writes: bool,
    /// Allow insecure HTTP connections to non-localhost registries (--insecure flag).
    allow_insecure: bool,
    /// Shared `SessionManager` for lazy-refresh-aware request auth.
    /// Stored here so that per-method `AuthPosture` plumbing can fetch
    /// the current token / trigger silent refresh without the caller
    /// threading a session in.
    session: Option<Arc<SessionManager>>,
    /// Precomputed ASCII-serialized origin of `base_url`.
    /// Avoids re-parsing + re-allocating on every `is_configured_origin` call.
    base_url_origin: String,
    /// Precomputed ASCII-serialized origin of `npm_registry_url`.
    npm_registry_url_origin: String,
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
struct CachedClient {
    client: reqwest::Client,
    identity_fp: Option<Arc<str>>,
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
    default: CachedClient,
    eager: HashMap<OriginKey, CachedClient>,
    lazy: tokio::sync::Mutex<HashMap<OriginKey, CachedClient>>,
    /// Snapshot of the TLS overrides used to build `default` and
    /// `eager`. Held here so lazy builds can construct matching
    /// per-origin clients on demand.
    tls_overrides: Arc<TlsOverrides>,
    /// Shared passphrase provider — one instance across all per-origin
    /// builds (eager + lazy). The inner `PassphraseCache` memoizes
    /// across calls; a fresh provider per build would defeat it.
    passphrase: Arc<dyn PassphraseProvider>,
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
    per_origin_identity_fps: HashMap<OriginKey, Arc<str>>,
}

impl std::fmt::Debug for HttpClients {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpClients")
            .field(
                "eager_origins",
                &self.eager.keys().map(|k| k.to_string()).collect::<Vec<_>>(),
            )
            .field("tls_overrides", &self.tls_overrides)
            .finish_non_exhaustive()
    }
}

impl HttpClients {
    /// Render a one-line summary of TLS overrides actually applied this
    /// invocation. Returns `None` when nothing is in effect (default-only,
    /// no global identity, no eager per-origin clients) so callers can
    /// suppress the line cleanly.
    ///
    /// **Effective-only.** Configured-but-unreached per-origin TLS
    /// (entries in `tls_overrides.per_origin` for origins NOT in the
    /// eager set) is deliberately excluded — it might still fire later
    /// via the lazy path, and reporting it eagerly would imply a failure
    /// precondition that doesn't actually exist. The `strict-ssl=false`
    /// security warning is rendered separately by `install.rs` / `add.rs`;
    /// this summary covers extra roots, mTLS identity, and per-origin TLS
    /// only.
    pub fn render_effective_tls_summary(&self) -> Option<String> {
        let global_roots = self.tls_overrides.extra_roots.len();
        let global_identity = self.tls_overrides.identity_certfile.is_some()
            && self.tls_overrides.identity_keyfile.is_some();
        let per_origin_count = self.eager.len();
        if global_roots == 0 && !global_identity && per_origin_count == 0 {
            return None;
        }
        let mut parts: Vec<String> = Vec::new();
        if global_roots > 0 {
            parts.push(format!(
                "{global_roots} extra root certificate{}",
                if global_roots == 1 { "" } else { "s" }
            ));
        }
        if global_identity {
            parts.push("global mTLS identity".to_string());
        }
        if per_origin_count > 0 {
            // Sort origins for deterministic rendering — install logs
            // diff cleanly between runs.
            let mut origins: Vec<String> = self.eager.keys().map(|o| o.to_string()).collect();
            origins.sort();
            parts.push(format!("per-origin TLS for {}", origins.join(", ")));
        }
        Some(format!("TLS overrides active: {}", parts.join("; ")))
    }

    /// Build an `HttpClients` whose `default` is the supplied client
    /// and whose eager/lazy maps are empty. Used by [`RegistryClient::new`]
    /// before any `.npmrc` is loaded.
    fn from_default_client(default: reqwest::Client) -> Arc<Self> {
        Arc::new(Self {
            default: CachedClient {
                client: default,
                identity_fp: None,
            },
            eager: HashMap::new(),
            lazy: tokio::sync::Mutex::new(HashMap::new()),
            tls_overrides: Arc::new(TlsOverrides::default()),
            passphrase: Arc::new(EnvThenTtyPassphrase::new()),
            per_origin_identity_fps: HashMap::new(),
        })
    }

    /// Look up a cached client for `url` without lazy-building.
    /// Returns the eager-built per-origin entry if one exists, else
    /// the default. Sync, infallible — suitable for hot paths.
    fn cached_for_url_no_build(&self, url: &str) -> &CachedClient {
        let Some(origin) = OriginKey::from_request_url(url) else {
            return &self.default;
        };
        if let Some(c) = self.eager.get(&origin) {
            return c;
        }
        let any_port = OriginKey {
            host_lower: origin.host_lower,
            port: None,
        };
        if let Some(c) = self.eager.get(&any_port) {
            return c;
        }
        &self.default
    }

    /// Public-API variant returning the underlying `reqwest::Client`.
    /// Kept for callers that don't care about the cached fingerprint
    /// (the retry executors, request-builder helpers, tests).
    pub fn for_url_no_build(&self, url: &str) -> &reqwest::Client {
        &self.cached_for_url_no_build(url).client
    }

    /// Identity fingerprint for the client that would handle a request
    /// to `url`, consulting eager + the pre-computed lazy-target map +
    /// default fallback.
    ///
    /// Used by metadata cache-key composition: the fingerprint is
    /// included in the namespace so a re-issued client cert invalidates
    /// cached entries cleanly.
    ///
    /// Resolution order:
    /// 1. **Eager hit** (port-exact then port-none) — return that
    ///    client's `identity_fp`.
    /// 2. **Pre-computed lazy-target fp** (port-exact then port-none) —
    ///    same fallback rule. The map was populated at
    ///    `with_tls_overrides_for` time by hashing every configured
    ///    per-origin certfile (read-and-hash is non-fatal). Origins with
    ///    per-origin cafile only (no own identity) inherit the global
    ///    identity_fp at populate time.
    /// 3. **Default** — the global identity_fp on the default client.
    ///
    /// Sync. Pre-computation keeps this sync-safe: lazy-only origins
    /// were previously identity-blind because cache-key composition runs
    /// BEFORE the actual lazy dispatch.
    pub fn identity_fp_for_url(&self, url: &str) -> Option<&str> {
        let Some(origin) = OriginKey::from_request_url(url) else {
            return self.default.identity_fp.as_deref();
        };
        // Tier 1: eager hit.
        if let Some(c) = self.eager.get(&origin) {
            return c.identity_fp.as_deref();
        }
        let any_port = OriginKey {
            host_lower: origin.host_lower.clone(),
            port: None,
        };
        if let Some(c) = self.eager.get(&any_port) {
            return c.identity_fp.as_deref();
        }
        // Tier 2: pre-computed lazy-target fp.
        if let Some(fp) = self.per_origin_identity_fps.get(&origin) {
            return Some(fp.as_ref());
        }
        if let Some(fp) = self.per_origin_identity_fps.get(&any_port) {
            return Some(fp.as_ref());
        }
        // Tier 3: default client's fp (global identity, if any).
        self.default.identity_fp.as_deref()
    }

    /// Look up (or lazily build) a client for `url`. Returns the eager
    /// or lazy per-origin client if one exists OR can be constructed
    /// for an origin that has per-origin TLS configuration; otherwise
    /// returns the default.
    ///
    /// Async + fallible because lazy build can perform IO (read
    /// per-origin cafile, decrypt PKCS#8 keyfile via the passphrase
    /// provider). For origins guaranteed to be eager-built, prefer
    /// [`Self::for_url_no_build`] — it's sync and infallible.
    ///
    /// Single-flight: while the build is in flight, concurrent callers
    /// queue on `lazy.lock()`. The second caller observes the
    /// just-inserted entry and skips the build.
    pub async fn for_url(&self, url: &str) -> Result<reqwest::Client, LpmError> {
        let Some(origin) = OriginKey::from_request_url(url) else {
            return Ok(self.default.client.clone());
        };
        if let Some(c) = self.eager.get(&origin) {
            return Ok(c.client.clone());
        }
        let any_port = OriginKey {
            host_lower: origin.host_lower.clone(),
            port: None,
        };
        if let Some(c) = self.eager.get(&any_port) {
            return Ok(c.client.clone());
        }
        // Fast path: no per-origin TLS configured at all → the lazy map is
        // guaranteed empty and the build below would no-op to default. Skip
        // the tokio mutex entirely. This is the common case for installs
        // with no .npmrc per-origin TLS (default public-registry traffic),
        // where many concurrent metadata fetches would otherwise serialize
        // briefly on `lazy.lock().await`.
        if self.tls_overrides.per_origin.is_empty() {
            return Ok(self.default.client.clone());
        }
        let mut guard = self.lazy.lock().await;
        if let Some(c) = guard.get(&origin) {
            return Ok(c.client.clone());
        }
        if let Some(c) = guard.get(&any_port) {
            return Ok(c.client.clone());
        }
        // No client cached. Look up per-origin TLS for this origin.
        let per_origin_tls = self
            .tls_overrides
            .per_origin
            .get(&origin)
            .or_else(|| self.tls_overrides.per_origin.get(&any_port));
        let Some(per_origin_tls) = per_origin_tls else {
            // No per-origin TLS → use default client.
            return Ok(self.default.client.clone());
        };
        // Build under lock — single-flight per origin.
        let cached = build_per_origin_http_client(
            &self.tls_overrides,
            per_origin_tls,
            &origin,
            self.passphrase.as_ref(),
        )?;
        let out = cached.client.clone();
        guard.insert(origin, cached);
        Ok(out)
    }
}

/// Build a `reqwest::Client` for a specific origin, layering its
/// per-origin TLS overrides on top of the global TLS surface.
///
/// Composition rules:
///
/// - **Trust roots**: global `extra_roots` PLUS this origin's
///   `cafiles` (additive — both are valid). Per-origin `cafile=` is
///   read here; IO failures surface with cited source/line.
/// - **Identity**: per-origin `(certfile, keyfile)` REPLACES the
///   global identity for this origin. Per-origin XOR validation fires
///   here, so a half-configured per-origin identity only fails the
///   install if THIS origin is actually built.
/// - **strict-ssl**: global only. Per-origin strict-ssl is not
///   supported in v1; the parser warns if used per-origin.
///
/// Caller is responsible for caching the returned client. The
/// passphrase provider is shared across all per-origin builds so its
/// inner `PassphraseCache` memoizes across calls.
fn build_per_origin_http_client(
    global: &TlsOverrides,
    per_origin: &OriginTlsOverrides,
    origin: &OriginKey,
    passphrase: &dyn PassphraseProvider,
) -> Result<CachedClient, LpmError> {
    // Compose extra roots: global + per-origin (additive).
    // Per-origin cafiles are deferred-read; do the IO here.
    let mut all_roots: Vec<TaggedRoot> = global.extra_roots.clone();
    for cafile in &per_origin.cafiles {
        let resolved = cafile.resolve();
        let bytes = std::fs::read(&resolved).map_err(|e| {
            tracing::debug!(
                resolved_path = %resolved.display(),
                source = %cafile.source,
                line = cafile.line,
                error = %e,
                "per-origin cafile read failed",
            );
            LpmError::Cert(format!(
                "{}:{}: failed to read per-origin cafile for {origin}: {e}",
                cafile.source, cafile.line,
            ))
        })?;
        if !contains_pem_certificate_block_inline(&bytes) {
            return Err(LpmError::Cert(format!(
                "{}:{}: per-origin cafile for {origin} contains no '-----BEGIN CERTIFICATE-----' block",
                cafile.source, cafile.line,
            )));
        }
        all_roots.push(TaggedRoot {
            pem_bytes: bytes,
            source: cafile.source.clone(),
            line: cafile.line,
        });
    }

    // Resolve identity. Per-origin replaces global; per-origin
    // XOR validation fires here (only fatal when this origin is built).
    // The `LoadedIdentity` carries cert PEM bytes alongside the
    // `reqwest::Identity` so we can fingerprint without re-reading.
    let loaded: Option<crate::tls_identity::LoadedIdentity> = match (
        per_origin.certfile.as_ref(),
        per_origin.keyfile.as_ref(),
    ) {
        (Some(cert), Some(key)) => Some(load_identity(cert, key, passphrase)?),
        (Some(cert), None) => {
            return Err(LpmError::Cert(format!(
                "{}:{}: per-origin certfile is set for {origin} but matching keyfile is missing across all merged layers — both must be set or both absent",
                cert.source, cert.line
            )));
        }
        (None, Some(key)) => {
            return Err(LpmError::Cert(format!(
                "{}:{}: per-origin keyfile is set for {origin} but matching certfile is missing across all merged layers — both must be set or both absent",
                key.source, key.line
            )));
        }
        // No per-origin identity → inherit global (if any).
        (None, None) => match (
            global.identity_certfile.as_ref(),
            global.identity_keyfile.as_ref(),
        ) {
            (Some(cert), Some(key)) => Some(load_identity(cert, key, passphrase)?),
            // Global XOR is finalize-time fatal; if we got here
            // with half-set, finalize would have aborted upstream.
            // Treat as "no identity" defensively.
            _ => None,
        },
    };

    // Hash the cert PEM once so cache-key composition doesn't re-read
    // or re-hash on every request.
    let identity_fp = loaded.as_ref().map(|l| cert_pem_fingerprint(&l.cert_pem));
    let identity = loaded.map(|l| l.identity);

    // Synthesize a per-origin TlsOverrides view: combined
    // roots + global strict_ssl. Per-origin map cleared (this is a
    // single-origin client — no further dispatch lives below it).
    let synthetic = TlsOverrides {
        extra_roots: all_roots,
        strict_ssl: global.strict_ssl.clone(),
        identity_certfile: None,
        identity_keyfile: None,
        per_origin: HashMap::new(),
    };
    let client = RegistryClient::build_http_client_with_tls_and_identity(
        CONNECT_TIMEOUT,
        READ_TIMEOUT,
        &synthetic,
        identity,
    )?;
    Ok(CachedClient {
        client,
        identity_fp,
    })
}

/// Inline PEM marker check — duplicates the parser-time helper in
/// `npmrc.rs` since that one is private. Kept private here too;
/// the duplication is one byte-search per per-origin cafile build,
/// which is negligible.
fn contains_pem_certificate_block_inline(bytes: &[u8]) -> bool {
    const MARKER: &[u8] = b"-----BEGIN CERTIFICATE-----";
    bytes.windows(MARKER.len()).any(|w| w == MARKER)
}

impl RegistryClient {
    /// Compute the ASCII-serialized origin of a URL string.
    /// Returns an empty string for malformed or opaque URLs so the
    /// precomputed fields are always valid (but will never match).
    fn url_origin(url: &str) -> String {
        reqwest::Url::parse(url)
            .map(|u| u.origin().ascii_serialization())
            .unwrap_or_default()
    }

    fn deserialize_cached_metadata(data: &[u8]) -> Option<PackageMetadata> {
        rmp_serde::from_slice(data)
            .or_else(|_| serde_json::from_slice(data))
            .ok()
    }

    /// Build the underlying `reqwest::Client` with the configured timeout:
    /// connect-phase cap + per-read idle cap, no whole-request wall-clock
    /// timeout.
    ///
    /// Factored out of `new()` so tests can construct clients with short
    /// timeouts against a local fake server, keeping prod defaults
    /// uniform and easy to update in one place.
    ///
    /// `LPM_HTTP=h1-pool` builds the client with `http1_only()` + a
    /// 64-connection idle pool + TCP keepalive. Benchmarks showed this is
    /// statistically significantly slower than HTTP/2 default (h1-pool-64:
    /// −11.5%, h1-pool-256: −8.9% on n=30 cold installs). Kept as an
    /// opt-in for network-regime debugging without rewriting this branch.
    fn build_http_client(connect_timeout: Duration, read_timeout: Duration) -> reqwest::Client {
        Self::build_http_client_with_tls(connect_timeout, read_timeout, &TlsOverrides::default())
            .expect("default TLS config never fails to build")
    }

    /// Build the underlying `reqwest::Client` with optional `.npmrc`-derived
    /// TLS overrides applied:
    ///
    /// - `extra_roots` from `cafile=` / `ca=` are attached via
    ///   [`reqwest::ClientBuilder::add_root_certificate`]. They are
    ///   **additive** to the system trust store, never a replacement —
    ///   so a corporate-CA-trusted client still validates public
    ///   registries normally.
    /// - `strict_ssl == Some(false)` flips
    ///   [`reqwest::ClientBuilder::danger_accept_invalid_certs(true)`].
    ///   This is process-wide on the resulting client; install.rs gates
    ///   it behind a loud install-start warning so a typo can't
    ///   silently turn off verification.
    ///
    /// Any PEM that fails [`reqwest::Certificate::from_pem`] (despite
    /// passing the parse-time marker check) surfaces as
    /// `LpmError::Cert(...)` with the contributing source/line so the
    /// user can find the offending `.npmrc` line.
    fn build_http_client_with_tls(
        connect_timeout: Duration,
        read_timeout: Duration,
        tls: &TlsOverrides,
    ) -> Result<reqwest::Client, LpmError> {
        // Resolve the global identity inline so call sites that don't
        // thread per-origin TLS still pick up `certfile=`/`keyfile=` from
        // `~/.npmrc` correctly. The XOR contract is enforced at
        // `NpmrcConfig::finalize`, so by the time we get here, either both
        // are present or neither.
        let global_identity = match (
            tls.identity_certfile.as_ref(),
            tls.identity_keyfile.as_ref(),
        ) {
            (Some(cert), Some(key)) => {
                let pp = EnvThenTtyPassphrase::new();
                Some(load_identity(cert, key, &pp)?.identity)
            }
            _ => None,
        };
        Self::build_http_client_with_tls_and_identity(
            connect_timeout,
            read_timeout,
            tls,
            global_identity,
        )
    }

    /// Variant of `build_http_client_with_tls` that takes a pre-resolved
    /// [`reqwest::Identity`].
    ///
    /// Used by the per-origin client builder (`build_per_origin_http_client`)
    /// which resolves the effective identity for each origin (per-origin
    /// overrides global) before calling here. The wrapping
    /// `build_http_client_with_tls` handles the global-identity case
    /// inline so prior call sites continue to work.
    fn build_http_client_with_tls_and_identity(
        connect_timeout: Duration,
        read_timeout: Duration,
        tls: &TlsOverrides,
        identity: Option<reqwest::Identity>,
    ) -> Result<reqwest::Client, LpmError> {
        let mut b = reqwest::Client::builder()
            .connect_timeout(connect_timeout)
            .read_timeout(read_timeout)
            // Cap redirect chains explicitly. reqwest's default is also
            // `Policy::limited(10)` plus per-redirect cross-origin
            // sensitive-header stripping (`Authorization`, `Cookie`,
            // `Proxy-Authorization`). Setting the policy here pins the
            // contract in code: a future builder edit that swaps in a
            // `Policy::none()` or a custom non-stripping policy is
            // visible in review, not implicit via "whichever default
            // reqwest ships this week". The cross-origin strip closes
            // the leak window where a compromised registry could
            // 30x to `attacker.example` and have the npmrc bearer
            // follow.
            .redirect(reqwest::redirect::Policy::limited(10))
            .user_agent(format!("lpm-rs/{}", env!("CARGO_PKG_VERSION")));
        if std::env::var("LPM_HTTP").as_deref() == Ok("h1-pool") {
            b = b
                .http1_only()
                .pool_max_idle_per_host(64)
                .pool_idle_timeout(Duration::from_secs(120))
                .tcp_keepalive(Duration::from_secs(60))
                .tcp_nodelay(true);
        }
        for root in &tls.extra_roots {
            // Pre-validate before `from_pem`: reqwest's rustls-tls
            // `from_pem` is permissive (stores raw bytes; validation
            // happens at `.build()` time) and the build-time error
            // can't tell us WHICH root caused it. Validating per-root
            // up front lets us cite source/line on the common failure
            // modes (truncated body, non-base64, empty cert).
            validate_pem_root(&root.pem_bytes, &root.source, root.line)?;
            let cert = reqwest::Certificate::from_pem(&root.pem_bytes).map_err(|e| {
                LpmError::Cert(format!(
                    "npmrc cafile/ca at {}:{}: failed to parse PEM: {e}",
                    root.source, root.line
                ))
            })?;
            b = b.add_root_certificate(cert);
        }
        if let Some(tagged) = tls.strict_ssl.as_ref()
            && !tagged.value
        {
            b = b.danger_accept_invalid_certs(true);
        }
        if let Some(id) = identity {
            b = b.identity(id);
        }
        b.build()
            .map_err(|e| LpmError::Cert(format!("HTTP client build failed: {e}")))
    }

    /// Create a new registry client with default settings.
    pub fn new() -> Self {
        // L25: reqwest honours HTTPS_PROXY / HTTP_PROXY / ALL_PROXY by
        // default. A compromised CI runner or shell rc that exports
        // these can silently route every registry request — including
        // the bearer-bearing publish/auth flows — through an
        // attacker proxy. We don't disable the env-proxy support
        // (legitimate corporate proxies depend on it) but we DO log
        // a one-shot warn so operators can spot unexpected proxy
        // contamination. Logged at warn level so default tracing
        // surfaces it; fires once per process per construction.
        for var in [
            "HTTPS_PROXY",
            "https_proxy",
            "HTTP_PROXY",
            "http_proxy",
            "ALL_PROXY",
        ] {
            if let Ok(val) = std::env::var(var)
                && !val.trim().is_empty()
            {
                tracing::warn!(
                    env_var = var,
                    proxy = %val,
                    "registry HTTP client will route through proxy from env; \
                     confirm this is expected (the LPM bearer goes via this proxy)",
                );
                break;
            }
        }
        let default_client = Self::build_http_client(CONNECT_TIMEOUT, READ_TIMEOUT);
        let http = HttpClients::from_default_client(default_client);

        // Initialize metadata cache at ~/.lpm/cache/metadata/ via LpmRoot.
        // `None` here is a graceful degradation: if we can't even resolve a
        // home directory (no $HOME, no $USERPROFILE, no $LPM_HOME), the
        // registry client falls back to memory-only caching for this
        // process. That is strictly better than failing construction.
        let cache_dir = LpmRoot::from_env().ok().map(|root| {
            let dir = root.cache_metadata();
            if let Err(e) = std::fs::create_dir_all(&dir) {
                tracing::warn!("failed to create metadata cache directory: {}", e);
            }
            dir
        });

        RegistryClient {
            http,
            base_url: DEFAULT_REGISTRY_URL.to_string(),
            npm_registry_url: NPM_REGISTRY_URL.to_string(),
            token: None,
            cache_dir,
            pending_cache_writes: Arc::new(std::sync::Mutex::new(Vec::new())),
            synchronous_cache_writes: false,
            allow_insecure: false,
            session: None,
            base_url_origin: Self::url_origin(DEFAULT_REGISTRY_URL),
            npm_registry_url_origin: Self::url_origin(NPM_REGISTRY_URL),
        }
    }

    /// Get the current base URL.
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Get the configured direct-npm registry URL (default
    /// `https://registry.npmjs.org`). Exposed so install/add can pass it
    /// to [`crate::route::RouteTable::effective_registry_origins`] when
    /// computing the request-aware eager set.
    pub fn npm_registry_url(&self) -> &str {
        &self.npm_registry_url
    }

    /// Render a one-line install-start summary of TLS overrides actually
    /// applied this invocation. Delegates to
    /// [`HttpClients::render_effective_tls_summary`]; see that method's
    /// doc for the effective-only rationale.
    pub fn render_effective_tls_summary(&self) -> Option<String> {
        self.http.render_effective_tls_summary()
    }

    /// Read access to the underlying [`HttpClients`] bundle. Exposed
    /// primarily for integration tests that need pointer-identity
    /// assertions on the dispatch path (`for_url_no_build`'s borrow).
    /// Production code should use the higher-level request methods on
    /// [`RegistryClient`]; this accessor is intentionally read-only.
    pub fn http(&self) -> &HttpClients {
        &self.http
    }

    /// Returns true if the URL's origin matches one of the origins this
    /// client is configured to talk to (the LPM `base_url` or the npm
    /// `npm_registry_url`). Used by [`evaluate_cached_url`] as the origin
    /// gate on lockfile-stored tarball URLs: a rebased URL from an older
    /// `LPM_REGISTRY_URL` mismatches and falls through to on-demand lookup
    /// against the current mirror.
    ///
    /// Opaque origins (`file://`, `data:`, etc.) never match because
    /// `base_url` / `npm_registry_url` are always tuple origins
    /// (https or http(localhost)). Malformed URLs return `false`.
    pub fn is_configured_origin(&self, url: &str) -> bool {
        let Ok(parsed) = reqwest::Url::parse(url) else {
            return false;
        };
        let parsed_origin = parsed.origin().ascii_serialization();
        parsed_origin == self.base_url_origin || parsed_origin == self.npm_registry_url_origin
    }

    /// Set the registry base URL.
    ///
    /// Stores the URL for later validation. Non-localhost HTTP URLs are rejected
    /// at request time unless `--insecure` is set via [`with_insecure`].
    pub fn with_base_url(mut self, url: impl Into<String>) -> Self {
        self.base_url = url.into();
        self.base_url_origin = Self::url_origin(&self.base_url);
        self
    }

    /// Override the npm registry URL (default: `https://registry.npmjs.org`).
    ///
    /// Used by cross-crate tests to point a mocked registry at the walker
    /// via `UpstreamRoute::NpmDirect` without round-tripping the real
    /// npmjs.
    pub fn with_npm_registry_url(mut self, url: impl Into<String>) -> Self {
        self.npm_registry_url = url.into();
        self.npm_registry_url_origin = Self::url_origin(&self.npm_registry_url);
        self
    }

    /// Override the on-disk metadata cache directory.
    ///
    /// The default is `~/.lpm/cache/metadata/`, which is shared across
    /// every `RegistryClient` instance in the process (and all
    /// processes, since it's file-system-persistent). That sharing
    /// causes test cross-contamination: one walker test's metadata
    /// writes bleed into later tests that use the same package names.
    /// Tests should call this with a unique tempdir per test to
    /// isolate.
    ///
    /// Pass `None` to disable disk caching entirely (all reads miss,
    /// all writes are no-ops).
    pub fn with_cache_dir(mut self, dir: Option<std::path::PathBuf>) -> Self {
        self.cache_dir = dir;
        self
    }

    /// Allow insecure HTTP connections to non-localhost registries.
    /// Required when using `--insecure` CLI flag.
    pub fn with_insecure(mut self, allow: bool) -> Self {
        self.allow_insecure = allow;
        self
    }

    /// Apply `.npmrc`-derived TLS overrides to this client.
    ///
    /// Rebuilds the inner default `reqwest::Client` with `cafile`/`ca`
    /// extra roots attached, `strict-ssl=false` honored, and global
    /// `certfile`/`keyfile` mTLS identity attached.
    ///
    /// Builds only the DEFAULT client. To also pre-build per-origin clients
    /// for the origins this invocation provably reaches, use
    /// [`Self::with_tls_overrides_for`] (the route-table-aware variant)
    /// instead. `with_tls_overrides` remains for callers that don't need
    /// per-origin pre-building.
    ///
    /// Fast path: with `TlsOverrides::default()` (no `.npmrc`, or one
    /// that says nothing about TLS), this returns `self` unchanged.
    ///
    /// **Orthogonal to `--insecure`.** That flag widens scheme acceptance
    /// (HTTP non-localhost); this widens cert verification.
    pub fn with_tls_overrides(self, tls: &TlsOverrides) -> Result<Self, LpmError> {
        // Empty effective set → no eager per-origin clients. Δ1 default.
        self.with_tls_overrides_for(tls, &[])
    }

    /// Apply `.npmrc`-derived TLS overrides AND eagerly build per-origin
    /// clients for the supplied set of origins.
    ///
    /// `eager_origins` is the request-aware effective-origin set computed
    /// from the top-level package request + the route table. Origins not
    /// in the set, but with per-origin TLS configured, build lazily on
    /// first use via [`HttpClients::for_url`].
    ///
    /// **Eager-build failure semantics.** If any of the supplied origins
    /// has per-origin TLS configured AND its identity load (encrypted
    /// PKCS#8 decryption, file IO, etc.) fails, this method returns
    /// `Err(LpmError::Cert(...))` with the cited source/line. Origins NOT
    /// in `eager_origins` (transitive scopes, tarball CDNs) are not touched
    /// here — half-configured per-origin TLS for unreached origins does not
    /// abort the install.
    pub fn with_tls_overrides_for(
        mut self,
        tls: &TlsOverrides,
        eager_origins: &[OriginKey],
    ) -> Result<Self, LpmError> {
        let needs_rebuild = !tls.extra_roots.is_empty()
            || matches!(tls.strict_ssl.as_ref(), Some(t) if !t.value)
            || tls.identity_certfile.is_some()
            || tls.identity_keyfile.is_some()
            || !tls.per_origin.is_empty();
        if !needs_rebuild && eager_origins.is_empty() {
            return Ok(self);
        }
        // Reuse the existing passphrase provider so its inner cache
        // (built up across previous calls) survives into the new
        // HttpClients. First-build path falls back to a fresh provider.
        let passphrase = Arc::clone(&self.http.passphrase);

        // Resolve the GLOBAL identity (if any) once here so we can
        // both attach it to the default client AND fingerprint the
        // cert PEM for cache-key composition. A default-routed URL
        // carries the global identity in its cache namespace, so
        // re-issued global certs invalidate cleanly. Global XOR was
        // enforced at finalize.
        let global_loaded = match (
            tls.identity_certfile.as_ref(),
            tls.identity_keyfile.as_ref(),
        ) {
            (Some(cert), Some(key)) => Some(load_identity(cert, key, passphrase.as_ref())?),
            _ => None,
        };
        let default_identity_fp = global_loaded
            .as_ref()
            .map(|l| cert_pem_fingerprint(&l.cert_pem));
        let default_identity = global_loaded.map(|l| l.identity);
        let default_reqwest_client = Self::build_http_client_with_tls_and_identity(
            CONNECT_TIMEOUT,
            READ_TIMEOUT,
            tls,
            default_identity,
        )?;
        let default_cached = CachedClient {
            client: default_reqwest_client,
            identity_fp: default_identity_fp,
        };
        // Eager per-origin builds — only for origins in the supplied set
        // that ALSO have per-origin TLS configured.
        let mut eager_map = HashMap::new();
        for origin in eager_origins {
            // Look up per-origin TLS using the same (host, Some(port))
            // → (host, None) fallback as the auth path.
            let any_port = OriginKey {
                host_lower: origin.host_lower.clone(),
                port: None,
            };
            let per_origin_tls = tls
                .per_origin
                .get(origin)
                .or_else(|| tls.per_origin.get(&any_port));
            let Some(per_origin_tls) = per_origin_tls else {
                continue;
            };
            let cached =
                build_per_origin_http_client(tls, per_origin_tls, origin, passphrase.as_ref())?;
            eager_map.insert(origin.clone(), cached);
        }
        // Pre-compute identity fingerprints for every configured per-origin
        // TLS entry so cache-key composition (sync, runs BEFORE lazy
        // dispatch) can answer correctly for lazy-target origins. Origins
        // with their own certfile: hash that cert. Origins with per-origin
        // cafile but no own identity: inherit the global identity_fp.
        // Cert read failures here are non-fatal — the entry stays absent
        // and the lazy build will surface a cited error if and when the
        // origin is actually reached.
        let mut per_origin_identity_fps: HashMap<OriginKey, Arc<str>> = HashMap::new();
        for (origin, per_origin) in &tls.per_origin {
            let fp = if let Some(cert) = &per_origin.certfile {
                match std::fs::read(cert.resolve()) {
                    Ok(bytes) => Some(cert_pem_fingerprint(&bytes)),
                    Err(_) => None,
                }
            } else {
                // No own identity → inherits global. Carry the global
                // fp into the per-origin map so the lookup tier-2 hit
                // returns it (else tier-3 default would catch it,
                // but only when no other entry exists — having it in
                // tier-2 keeps the resolution rule uniform).
                default_cached.identity_fp.clone()
            };
            if let Some(fp) = fp {
                per_origin_identity_fps.insert(origin.clone(), fp);
            }
        }
        let http = Arc::new(HttpClients {
            default: default_cached,
            eager: eager_map,
            lazy: tokio::sync::Mutex::new(HashMap::new()),
            tls_overrides: Arc::new(tls.clone()),
            passphrase,
            per_origin_identity_fps,
        });
        self.http = http;
        Ok(self)
    }

    /// Whether `--insecure` is enabled on this client.
    ///
    /// Exposed so free functions composing URL-safety gates
    /// (e.g. [`evaluate_cached_url`]) can honor the same carve-out the
    /// method-based guards on `download_tarball*` apply. Visibility-
    /// only accessor; the field itself stays private.
    pub fn allow_insecure(&self) -> bool {
        self.allow_insecure
    }

    /// Validate the base URL scheme. Returns an error if the URL is not
    /// one of: HTTPS, HTTP to localhost, or HTTP anywhere with
    /// `--insecure` set.
    ///
    /// Called before the first request, not in the builder, so the client
    /// can be constructed in any order.
    ///
    /// `--insecure` is narrow by design: it widens the carve-out to HTTP
    /// specifically, never to `file://`, `ftp://`, `data:`, or any other
    /// non-HTTPS scheme. The `is_http_url` clause in the allowed-set
    /// (rather than `!is_https_url`) is what enforces that.
    pub fn validate_base_url(&self) -> Result<(), LpmError> {
        let url = self.base_url.as_str();
        let allowed =
            is_https_url(url) || is_localhost_url(url) || (self.allow_insecure && is_http_url(url));
        if !allowed {
            return Err(LpmError::Registry(format!(
                "registry URL '{}' uses insecure transport. Use HTTPS, or pass --insecure to allow HTTP non-localhost.",
                self.base_url
            )));
        }
        // L6: when `--insecure` is the path that admitted an HTTP
        // non-loopback URL, surface the DNS-rebinding window
        // explicitly. The string-based scheme check happens HERE; the
        // actual TCP connect happens later inside reqwest with a
        // fresh DNS resolve. An attacker whose DNS server returns
        // 127.0.0.1 (or another internal IP) on the second resolve
        // can steer the request to a different host than the one
        // the URL named. We can't fix the rebinding window cheaply
        // without forking reqwest's connector (would need a resolve-
        // once + connect-to-IP pattern), but we CAN surface the
        // trust posture so operators see they're agreeing to it.
        if self.allow_insecure && is_http_url(url) && !is_localhost_url(url) {
            tracing::warn!(
                target: "lpm_registry::client",
                base_url = %url,
                "--insecure HTTP non-loopback registry: there is a DNS-rebinding window between this URL validation and the eventual TCP connect. Use HTTPS to anchor the trust to a TLS cert rather than DNS"
            );
        }
        Ok(())
    }

    /// Validate a tarball URL's scheme. Allows HTTPS, localhost HTTP
    /// (loopback carve-out for development), and — only when
    /// `--insecure` is set — non-localhost HTTP. `file://`, `ftp://`,
    /// `data:`, and every other non-HTTPS non-HTTP scheme remain
    /// rejected regardless of the flag.
    ///
    /// Shared by all three tarball download paths so the scheme gate
    /// stays symmetric across in-memory, streaming, and file-spool
    /// variants. The [`evaluate_cached_url`] gate mirrors this same
    /// predicate set on the lockfile-read path.
    fn check_tarball_url_scheme(&self, url: &str) -> Result<(), LpmError> {
        let allowed =
            is_https_url(url) || is_localhost_url(url) || (self.allow_insecure && is_http_url(url));
        if !allowed {
            return Err(LpmError::Registry(format!(
                "tarball URL must use HTTPS (got: {}). Pass --insecure to allow HTTP non-localhost.",
                if url.len() > 80 { &url[..80] } else { url }
            )));
        }
        Ok(())
    }

    /// Set the bearer token for authenticated requests.
    ///
    /// The token is stored as a `SecretString` (S5) — it will not appear
    /// in `Debug` output and is zeroized on drop.
    pub fn with_token(mut self, token: impl Into<String>) -> Self {
        self.token = Some(SecretString::from(token.into()));
        self
    }

    /// Attach the shared `SessionManager` so request methods can fetch a
    /// token / trigger silent refresh on demand. Idempotent — subsequent
    /// calls replace the prior session reference.
    pub fn with_session(mut self, session: Arc<SessionManager>) -> Self {
        self.session = Some(session);
        self
    }

    /// Read access to the attached session (for callers that need to
    /// consult source/posture without going through request methods —
    /// e.g., the `tunnel` command checks this before connecting).
    pub fn session(&self) -> Option<&Arc<SessionManager>> {
        self.session.as_ref()
    }

    /// Create a new client sharing the same HTTP connection pool.
    /// Reuses the inner `reqwest::Client` (which is `Arc`-wrapped internally)
    /// so all clones share TCP/TLS connections via HTTP/2 multiplexing.
    pub fn clone_with_config(&self) -> Self {
        Self {
            http: self.http.clone(), // Arc clone — shares connection pool
            base_url: self.base_url.clone(),
            npm_registry_url: self.npm_registry_url.clone(),
            token: self.token.clone(),
            cache_dir: self.cache_dir.clone(),
            // Share the pending-writes tracker so flush() drains writes
            // queued by ANY clone of this client.
            pending_cache_writes: Arc::clone(&self.pending_cache_writes),
            synchronous_cache_writes: self.synchronous_cache_writes,
            allow_insecure: self.allow_insecure,
            session: self.session.clone(),
            base_url_origin: self.base_url_origin.clone(),
            npm_registry_url_origin: self.npm_registry_url_origin.clone(),
        }
    }

    /// Force `write_metadata_cache` to run the blocking file write
    /// inline on the calling thread instead of spawning it onto
    /// `tokio::task::spawn_blocking`. See the field doc on
    /// `synchronous_cache_writes` for the test motivation. Production
    /// MUST NOT call this — losing the spawn_blocking is intentional.
    /// `#[cfg(test)]`-gated so the method (and the otherwise-unused-in-prod
    /// field) doesn't trip dead-code warnings.
    #[cfg(test)]
    pub(crate) fn with_synchronous_cache_writes(mut self, sync: bool) -> Self {
        self.synchronous_cache_writes = sync;
        self
    }

    /// Fetch metadata for multiple packages in a single HTTP request.
    ///
    /// Calls: POST /api/registry/batch-metadata
    /// Returns a map of package_name → PackageMetadata.
    ///
    /// This is the key optimization for cold installs — instead of 70+
    /// individual HTTP requests, we batch everything into 1-3 requests.
    pub async fn batch_metadata(
        &self,
        package_names: &[String],
    ) -> Result<std::collections::HashMap<String, PackageMetadata>, LpmError> {
        self.batch_metadata_inner(package_names, false).await
    }

    /// Batch fetch with deep transitive resolution.
    /// The server recursively discovers and fetches transitive deps (up to 3 levels),
    /// returning ALL metadata in a single response. This turns 3 sequential batch
    /// calls into 1 round-trip.
    pub async fn batch_metadata_deep(
        &self,
        package_names: &[String],
    ) -> Result<std::collections::HashMap<String, PackageMetadata>, LpmError> {
        self.batch_metadata_inner(package_names, true).await
    }

    async fn batch_metadata_inner(
        &self,
        package_names: &[String],
        deep: bool,
    ) -> Result<std::collections::HashMap<String, PackageMetadata>, LpmError> {
        if package_names.is_empty() {
            return Ok(std::collections::HashMap::new());
        }

        let url = format!("{}/api/registry/batch-metadata", self.base_url);
        let body = serde_json::json!({ "packages": package_names, "deep": deep });

        // Wall-clock the entire RPC (request + parse). Metadata fetches
        // dominate `resolve_ms` on cold installs; the timer feeds
        // `crate::timing::record_rpc` so the resolver can surface the
        // bound in `--json` as `timing.resolve.metadata_rpc_ms`.
        let rpc_start = std::time::Instant::now();

        // Posture: AuthRequired. Batch metadata may include `@lpm.dev`
        // packages whose metadata is auth-gated; on 401 the recovery
        // wrapper lazily refreshes and re-runs the entire closure
        // (request + parse) once.
        let result = self
            .execute_with_recovery(AuthPosture::AuthRequired, || async {
                let mut req = self
                    .http
                    .for_url(&url)
                    .await?
                    .post(&url)
                    .header("Accept", "application/x-ndjson")
                    .json(&body);
                if let Some(bearer) = self.current_bearer(AuthPosture::AuthRequired) {
                    req = req.bearer_auth(bearer);
                }
                let response = self.send_with_retry(req).await?;

                let content_type = response
                    .headers()
                    .get("content-type")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("")
                    .to_string();

                if content_type.contains("application/x-ndjson") {
                    self.parse_ndjson_batch(response).await
                } else {
                    self.parse_json_batch(response).await
                }
            })
            .await;

        // Record even on error — a timed-out RPC contributed to the
        // observed wall-clock just as much as a successful one, and
        // the caller will surface the error elsewhere.
        crate::timing::record_rpc(rpc_start.elapsed());
        result
    }

    /// Parse an NDJSON batch response. Each line is:
    /// `{"name":"lodash","metadata":{...}}\n`. Returns the
    /// fully-populated map.
    async fn parse_ndjson_batch(
        &self,
        response: reqwest::Response,
    ) -> Result<std::collections::HashMap<String, PackageMetadata>, LpmError> {
        let mut map = std::collections::HashMap::new();
        let mut buffer = Vec::new();
        // Avoid quadratic `\n` scan. Each time reqwest gives us a fresh
        // chunk we append to `buffer` and then look for a newline to frame
        // the next NDJSON line. Scanning from offset 0 on every chunk
        // grows triangularly; `scan_from` tracks the first unscanned byte
        // so total scan work is O(total bytes) instead of
        // O(chunks × buffer_size).
        let mut scan_from: usize = 0;
        let mut json_parse_ns: u128 = 0;
        let mut cache_write_ns: u128 = 0;

        // Read chunks from the response body and parse complete lines.
        //
        // `reqwest::Error`'s top-level Display is the kind only (e.g.
        // "error decoding response body"). The actual fault lives in the
        // `source()` chain from hyper. Walk the chain explicitly so the
        // warn log is diagnostic and not just the opaque top-level string.
        //
        // M60: cap the total bytes accumulated from the NDJSON stream
        // at the same `MAX_METADATA_BYTES` ceiling the single-package
        // metadata path uses. A hostile Worker / poisoned base URL
        // could otherwise stream one giant line (or unbounded
        // whitespace) and exhaust install memory before the JSON
        // parser noticed the line was malformed.
        if let Some(declared) = response.content_length()
            && declared as usize > MAX_METADATA_BYTES
        {
            return Err(LpmError::Registry(format!(
                "NDJSON batch: declared body length {declared} exceeds cap {MAX_METADATA_BYTES}"
            )));
        }
        let mut response = response;
        let mut bytes_read: u64 = 0;
        let mut chunks_read: u64 = 0;
        loop {
            match response.chunk().await {
                Ok(None) => break,
                Ok(Some(chunk)) => {
                    chunks_read += 1;
                    bytes_read += chunk.len() as u64;
                    if (bytes_read as usize) > MAX_METADATA_BYTES {
                        return Err(LpmError::Registry(format!(
                            "NDJSON batch: streamed body exceeded cap {MAX_METADATA_BYTES} \
                             (after {chunks_read} chunks)"
                        )));
                    }
                    buffer.extend_from_slice(&chunk);
                }
                Err(e) => {
                    let chain: Vec<String> =
                        std::iter::successors(Some(&e as &dyn std::error::Error), |e| e.source())
                            .map(|e| e.to_string())
                            .collect();
                    return Err(LpmError::Registry(format!(
                        "NDJSON read error after {chunks_read} chunks / {bytes_read} bytes (parse: {:.1}ms, cache_write: {:.1}ms): {} cause(s): {}",
                        json_parse_ns as f64 / 1_000_000.0,
                        cache_write_ns as f64 / 1_000_000.0,
                        chain.len(),
                        chain.join(" <- "),
                    )));
                }
            }
            // Process all complete lines in the buffer. Only scan the
            // new bytes — `scan_from` marks the first byte we haven't
            // inspected yet. See the top-of-function comment for the
            // quadratic-scan story this avoids.
            loop {
                let search_slice = &buffer[scan_from..];
                let Some(rel_pos) = search_slice.iter().position(|&b| b == b'\n') else {
                    // No newline in the unscanned region; everything up
                    // to `buffer.len()` is scanned. Pick up from here on
                    // the next chunk.
                    scan_from = buffer.len();
                    break;
                };
                let newline_pos = scan_from + rel_pos;

                let line = std::str::from_utf8(&buffer[..newline_pos])
                    .map_err(|e| LpmError::Registry(format!("NDJSON UTF-8 error: {e}")))?;
                if !line.is_empty() {
                    // Parse directly into typed struct, avoiding the
                    // intermediate Value + clone that doubled parse cost.
                    #[derive(serde::Deserialize)]
                    struct NdjsonEntry {
                        name: String,
                        metadata: PackageMetadata,
                    }
                    let parse_start = std::time::Instant::now();
                    let parsed: Option<NdjsonEntry> = serde_json::from_str(line).ok();
                    json_parse_ns += parse_start.elapsed().as_nanos();
                    let parsed = parsed.map(|e| (e.name, e.metadata));

                    if let Some((name, meta)) = parsed {
                        if meta.name != name
                            && !meta.versions.values().any(|version| version.name == name)
                        {
                            buffer.drain(..newline_pos + 1);
                            scan_from = 0;
                            continue;
                        }

                        let cache_key = if name.starts_with("@lpm.dev/") {
                            format!("lpm:{name}")
                        } else {
                            format!("npm:{name}")
                        };
                        let write_start = std::time::Instant::now();
                        self.write_metadata_cache(&cache_key, &meta, None);
                        cache_write_ns += write_start.elapsed().as_nanos();
                        map.insert(name, meta);
                    }
                }
                buffer.drain(..newline_pos + 1);
                // Bytes shifted left by `newline_pos + 1`; everything
                // remaining is unscanned, so restart from 0.
                scan_from = 0;
            }
        }

        // Handle final line in buffer (no trailing newline)
        if buffer.iter().any(|byte| !byte.is_ascii_whitespace())
            && let Ok(line) = std::str::from_utf8(&buffer)
        {
            #[derive(serde::Deserialize)]
            struct NdjsonEntry {
                name: String,
                metadata: PackageMetadata,
            }
            let parse_start = std::time::Instant::now();
            let parsed: Option<NdjsonEntry> = serde_json::from_str(line).ok();
            json_parse_ns += parse_start.elapsed().as_nanos();

            if let Some(entry) = parsed {
                let name = entry.name;
                let meta = entry.metadata;
                if meta.name != name && !meta.versions.values().any(|version| version.name == name)
                {
                    tracing::debug!(
                        "skipping NDJSON metadata entry with mismatched package name: requested {name}, metadata {}",
                        meta.name
                    );
                } else {
                    let cache_key = if name.starts_with("@lpm.dev/") {
                        format!("lpm:{name}")
                    } else {
                        format!("npm:{name}")
                    };
                    let write_start = std::time::Instant::now();
                    self.write_metadata_cache(&cache_key, &meta, None);
                    cache_write_ns += write_start.elapsed().as_nanos();
                    map.insert(name, meta);
                }
            }
        }

        tracing::debug!(
            "batch metadata (NDJSON): received {} — json_parse: {:.2}ms, cache_write: {:.2}ms",
            map.len(),
            json_parse_ns as f64 / 1_000_000.0,
            cache_write_ns as f64 / 1_000_000.0,
        );

        // Feed the locally-accumulated parse time into the resolver-visible
        // `parse_ndjson_ms` counter. Cache-write is intentionally NOT
        // reported here: it's disk I/O, not parse CPU.
        crate::timing::record_parse(std::time::Duration::from_nanos(json_parse_ns as u64));

        Ok(map)
    }

    /// Parse a legacy JSON batch response: `{ "packages": { "name": {...} } }`
    async fn parse_json_batch(
        &self,
        response: reqwest::Response,
    ) -> Result<std::collections::HashMap<String, PackageMetadata>, LpmError> {
        let result: serde_json::Value = parse_capped_metadata(response, "batch metadata").await?;

        let packages_obj = result
            .get("packages")
            .and_then(|p| p.as_object())
            .ok_or_else(|| LpmError::Registry("batch response missing packages".into()))?;

        let mut map = std::collections::HashMap::new();
        for (name, meta_value) in packages_obj {
            if let Ok(meta) = serde_json::from_value::<PackageMetadata>(meta_value.clone()) {
                if meta.name != *name
                    && !meta.versions.values().any(|version| version.name == *name)
                {
                    continue;
                }

                let cache_key = if name.starts_with("@lpm.dev/") {
                    format!("lpm:{name}")
                } else {
                    format!("npm:{name}")
                };
                self.write_metadata_cache(&cache_key, &meta, None);
                map.insert(name.clone(), meta);
            }
        }

        tracing::debug!(
            "batch metadata (JSON): requested {}, received {}",
            packages_obj.len(),
            map.len()
        );
        Ok(map)
    }

    // ─── Package Endpoints ──────────────────────────────────────────

    /// Fetch full metadata for an LPM package.
    ///
    /// Calls: GET /api/registry/@lpm.dev/owner.package-name
    ///
    /// Uses a two-tier caching strategy:
    /// 1. **TTL hit** — If cache is fresh (< 5 min), return immediately without HTTP.
    /// 2. **Conditional request** — If cache is stale but has an ETag, send
    ///    `If-None-Match`. A 304 response revalidates the cache without transferring data.
    /// 3. **Full fetch** — Otherwise fetch fresh data and cache it with the server's ETag.
    pub async fn get_package_metadata(
        &self,
        name: &PackageName,
    ) -> Result<PackageMetadata, LpmError> {
        let cache_key = format!("lpm:{}", name.scoped());

        // Tier 1: TTL-based cache hit (fast path, no HTTP)
        if let Some((cached, _etag)) = self.read_metadata_cache(&cache_key) {
            tracing::debug!("metadata cache hit: {}", name.scoped());
            return Ok(cached);
        }

        // npm registries expect raw scoped names in the path:
        // /api/registry/@lpm.dev/owner.package (NOT percent-encoded)
        let url = format!("{}/api/registry/{}", self.base_url, name.scoped());

        // Time the network portion only. TTL cache hits above return
        // before this point, so the RPC counter never double-counts them.
        let rpc_start = std::time::Instant::now();

        // Posture: AuthRequired. `@lpm.dev` package metadata may be
        // gated; on 401 the recovery wrapper performs one silent
        // refresh + retry. The closure re-reads ETag + bearer each
        // attempt so the rotated token is used on retry.
        let result = self
            .execute_with_recovery(AuthPosture::AuthRequired, || async {
                let cache_content = self.read_cache_content(&cache_key);
                let mut req = self.build_get(&url).await?;
                if let Some(etag) = cache_content.as_ref().and_then(|c| c.etag.as_deref()) {
                    req = req.header("If-None-Match", etag);
                }

                let mut response = self.send_with_retry(req).await?;

                if response.status() == reqwest::StatusCode::NOT_MODIFIED {
                    if let Some(path) = self.cache_path(&cache_key) {
                        let _ = filetime::set_file_mtime(&path, filetime::FileTime::now());
                    }
                    if let Some(content) = cache_content
                        && let Some(meta) = Self::deserialize_cached_metadata(&content.data)
                    {
                        tracing::debug!("metadata cache revalidated (304): {}", name.scoped());
                        return Ok(meta);
                    }
                    response = self.send_with_retry(self.build_get(&url).await?).await?;
                }

                let etag = response
                    .headers()
                    .get("etag")
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.to_string());

                let metadata: PackageMetadata =
                    parse_capped_metadata(response, &format!("get_package_metadata {url}")).await?;

                self.write_metadata_cache(&cache_key, &metadata, etag.as_deref());
                Ok(metadata)
            })
            .await;

        crate::timing::record_rpc(rpc_start.elapsed());
        result
    }

    /// Fetch metadata for an npm package from the upstream npm registry.
    ///
    /// First tries via LPM's upstream proxy (if enabled), then falls back
    /// to the public npm registry at registry.npmjs.org when the proxy misses.
    ///
    /// Supports ETag conditional requests for both proxy and direct npm paths.
    pub async fn get_npm_package_metadata(&self, name: &str) -> Result<PackageMetadata, LpmError> {
        let cache_key = format!("npm:{name}");

        // Tier 1: TTL-based cache hit
        if let Some((cached, _etag)) = self.read_metadata_cache(&cache_key) {
            tracing::debug!("metadata cache hit: npm:{name}");
            return Ok(cached);
        }

        // Past this point the call WILL hit a registry (proxy or upstream).
        // `record_rpc` fires in each tier's exit path (success or error)
        // so the counter captures real network time, not cache fast-paths.
        let rpc_start = std::time::Instant::now();
        // Macro closing over `rpc_start` so every exit path bumps the
        // counter exactly once before returning. Mirrors the existing
        // `execute_with_recovery` wrap on `get_package_metadata`.
        macro_rules! finish {
            ($expr:expr) => {{
                let r = $expr;
                crate::timing::record_rpc(rpc_start.elapsed());
                r
            }};
        }

        // Tier 2: Try LPM upstream proxy with conditional request
        let proxy_url = format!("{}/api/registry/{}", self.base_url, name);
        let cache_content = self.read_cache_content(&cache_key);

        let mut req = self.build_get(&proxy_url).await?;
        if let Some(etag) = cache_content.as_ref().and_then(|c| c.etag.as_deref()) {
            req = req.header("If-None-Match", etag);
        }

        match self.send_with_retry(req).await {
            Ok(mut response) => {
                if response.status() == reqwest::StatusCode::NOT_MODIFIED {
                    // Revalidated — touch file and deserialize from already-read data
                    if let Some(path) = self.cache_path(&cache_key) {
                        let _ = filetime::set_file_mtime(&path, filetime::FileTime::now());
                    }
                    if let Some(content) = cache_content
                        && let Some(meta) = Self::deserialize_cached_metadata(&content.data)
                    {
                        tracing::debug!("metadata cache revalidated (304): npm:{name}");
                        return Ok(meta);
                    }
                    response = self
                        .send_with_retry(self.build_get(&proxy_url).await?)
                        .await?;
                }

                if response.status().is_success() {
                    let etag = response
                        .headers()
                        .get("etag")
                        .and_then(|v| v.to_str().ok())
                        .map(|s| s.to_string());

                    if let Ok(metadata) = parse_capped_metadata::<PackageMetadata>(
                        response,
                        &format!("get_npm_package_metadata (proxy) {name}"),
                    )
                    .await
                    {
                        // Verify we got the right package (not a routing error)
                        if metadata.name == name
                            || metadata.versions.values().any(|v| v.name == name)
                        {
                            tracing::debug!("fetched {name} via LPM upstream proxy");
                            self.write_metadata_cache(&cache_key, &metadata, etag.as_deref());
                            return finish!(Ok(metadata));
                        }

                        return finish!(Err(LpmError::Registry(format!(
                            "proxy returned metadata for unexpected package '{}' when requesting '{name}'",
                            metadata.name
                        ))));
                    }
                }
            }
            Err(LpmError::NotFound(_)) => {
                tracing::debug!("npm metadata miss via LPM upstream proxy: {name}");
            }
            Err(LpmError::AuthRequired) => {
                // Proxy returned 401/403 for a bare npm package — expected
                // when the user isn't logged in. Fall through to the public
                // npm registry which doesn't need auth.
                tracing::debug!(
                    "npm proxy auth required for {name}, falling back to public registry"
                );
            }
            Err(error) => return finish!(Err(error)),
        }

        // Tier 3: Fall back to public npm registry (no auth needed)
        // Use abbreviated packument to reduce payload by 50-90%
        let npm_url = format!("{}/{}", self.npm_registry_url, name);
        tracing::debug!("fetching {name} from npm registry");
        let response = match self
            .send_with_retry(
                self.http
                    .for_url(&npm_url)
                    .await?
                    .get(&npm_url)
                    .header("Accept", "application/vnd.npm.install-v1+json"),
            )
            .await
        {
            Ok(r) => r,
            Err(e) => return finish!(Err(e)),
        };
        let metadata_res = parse_capped_metadata::<PackageMetadata>(
            response,
            &format!("get_npm_package_metadata (direct) {name}"),
        )
        .await;
        let metadata = match metadata_res {
            Ok(m) => m,
            Err(e) => return finish!(Err(e)),
        };
        self.write_metadata_cache(&cache_key, &metadata, None);
        finish!(Ok(metadata))
    }

    /// Fetch npm package metadata direct from `registry.npmjs.org`,
    /// skipping the LPM Worker proxy tier entirely.
    ///
    /// Used when running in [`RouteMode::Direct`](crate::RouteMode::Direct):
    /// bypassing the Worker is the whole point, so we must NOT fall back
    /// to it on a miss. The TTL cache is preserved so warm installs and
    /// previously-seen packages stay cache-fast.
    pub async fn get_npm_metadata_direct(&self, name: &str) -> Result<PackageMetadata, LpmError> {
        let cache_key = format!("npm:{name}");

        // Tier 1: TTL+HMAC cache hit (same as `get_npm_package_metadata`).
        if let Some((cached, _etag)) = self.read_metadata_cache(&cache_key) {
            tracing::debug!("metadata cache hit (direct): npm:{name}");
            return Ok(cached);
        }

        let rpc_start = std::time::Instant::now();
        macro_rules! finish {
            ($expr:expr) => {{
                let r = $expr;
                crate::timing::record_rpc(rpc_start.elapsed());
                r
            }};
        }

        // Go straight to the public npm registry. Abbreviated packument
        // format reduces payload by 50-90%, matching what the proxy-fallback
        // tier in `get_npm_package_metadata` uses.
        let npm_url = format!("{}/{}", self.npm_registry_url, name);
        tracing::debug!("fetching {name} direct from npm registry");
        let response = match self
            .send_with_retry(
                self.http
                    .for_url(&npm_url)
                    .await?
                    .get(&npm_url)
                    .header("Accept", "application/vnd.npm.install-v1+json"),
            )
            .await
        {
            Ok(r) => r,
            Err(e) => return finish!(Err(e)),
        };
        let metadata = match parse_capped_metadata::<PackageMetadata>(
            response,
            &format!("get_npm_metadata_direct {name}"),
        )
        .await
        {
            Ok(m) => m,
            Err(e) => return finish!(Err(e)),
        };
        self.write_metadata_cache(&cache_key, &metadata, None);
        finish!(Ok(metadata))
    }

    /// Fetch npm metadata honoring an explicit upstream route.
    ///
    /// [`UpstreamRoute::LpmWorker`] → full three-tier chain via
    /// [`Self::get_npm_package_metadata`] (cache → proxy → direct
    /// fallback).
    /// [`UpstreamRoute::NpmDirect`] → cache + direct npm only, skipping
    /// the Worker hop.
    /// [`UpstreamRoute::Custom`] → fetch from a `.npmrc`-declared registry
    /// via [`Self::get_npm_metadata_from`].
    ///
    /// Single entry point for the BFS walker and the provider's
    /// escape-hatch path so routing policy lives in one place.
    pub async fn get_npm_metadata_routed(
        &self,
        name: &str,
        route: crate::UpstreamRoute,
    ) -> Result<PackageMetadata, LpmError> {
        match route {
            crate::UpstreamRoute::LpmWorker => self.get_npm_package_metadata(name).await,
            crate::UpstreamRoute::NpmDirect => self.get_npm_metadata_direct(name).await,
            crate::UpstreamRoute::Custom { target, auth } => {
                self.get_npm_metadata_from(&target.base_url, name, auth.as_ref())
                    .await
            }
        }
    }

    /// Fetch only the fields required for install-time blocked-set metadata
    /// capture: `time[version]` (→ `published_at`) and
    /// `versions[v]._behavioralTags` (→ `behavioral_tags{,_hash}`).
    ///
    /// **On cache hit** the registry blob is deserialized into the minimal
    /// [`BlockedSetPackageMeta`] struct, skipping allocation of all other
    /// `VersionMetadata` fields (deps, devDeps, readme, etc.). For a 51-package
    /// install this eliminates ~90% of the rmp_serde string allocations that
    /// [`get_npm_metadata_routed`] would otherwise produce.
    ///
    /// **On cache miss** this falls back to [`get_npm_metadata_routed`] (full
    /// fetch + cache write), then projects the result down to the minimal type
    /// without a second deserialization pass.
    ///
    /// **Custom routes** (`UpstreamRoute::Custom`) use a principal-fingerprint
    /// cache key that is computed inside [`get_npm_metadata_from`] and is not
    /// reproducible here — those routes skip the fast path and go straight to
    /// the full fetch + projection.
    pub async fn get_npm_blocked_set_meta(
        &self,
        name: &str,
        route: crate::UpstreamRoute,
    ) -> Option<crate::types::BlockedSetPackageMeta> {
        // Fast path for standard npm routes whose cache key is `npm:{name}`.
        // Custom routes use a principal-fingerprint key we can't reproduce here.
        let is_standard_route = matches!(
            route,
            crate::UpstreamRoute::LpmWorker | crate::UpstreamRoute::NpmDirect
        );
        if is_standard_route {
            let cache_key = format!("npm:{name}");
            if let Some((meta, _)) =
                self.read_metadata_cache_as::<crate::types::BlockedSetPackageMeta>(&cache_key)
            {
                tracing::debug!("blocked-set meta cache hit (minimal): {name}");
                return Some(meta);
            }
        }

        // Cache miss or custom route: fetch full metadata (writes cache),
        // then project to the minimal type without re-deserializing.
        let full = self.get_npm_metadata_routed(name, route).await.ok()?;
        Some(crate::types::BlockedSetPackageMeta {
            time: full.time,
            versions: full
                .versions
                .into_iter()
                .map(|(k, v)| {
                    (
                        k,
                        crate::types::BlockedSetVersionMeta {
                            behavioral_tags: v.behavioral_tags,
                        },
                    )
                })
                .collect(),
        })
    }

    /// Fetch npm-style abbreviated metadata from an arbitrary registry,
    /// optionally attaching origin-scoped auth.
    ///
    /// Generalizes [`Self::get_npm_metadata_direct`] so `.npmrc`-
    /// declared private/internal registries are first-class fetch
    /// targets. The same connection pool is reused (reqwest keys its
    /// pool by origin, so multiple destinations don't multiply TLS
    /// handshakes).
    ///
    /// ## Auth attachment
    ///
    /// When `auth` is `Some`, the request bears `Authorization: Bearer`
    /// or `Authorization: Basic` per the credential's variant. The
    /// caller (`RouteTable::route_for_package`) is responsible for
    /// pairing auth with the right `target`. Defense-in-depth: this
    /// method **re-verifies** that the auth's origin matches the
    /// destination URL's origin via `OriginKey::from_request_url`
    /// before sending, returning `LpmError::Internal` on mismatch
    /// (which should never trigger in correctly-built calls but
    /// hard-fails rather than leaking a token if it does).
    ///
    /// ## Cache key
    ///
    /// `npm:<host>:<name>` — host derived from `base_url`. This
    /// deliberately differs from the bare `npm:<name>` keys used by
    /// `get_npm_metadata_direct` / `get_npm_package_metadata`, which
    /// both serve content from the same npm.org logical source. Custom
    /// registries serve potentially-different content under the same
    /// name, so they must namespace per origin to avoid cross-
    /// contamination.
    ///
    /// ## What this does NOT do
    ///
    /// - HTTP→HTTPS upgrade or `--insecure` enforcement: the existing
    ///   `is_https_url` / `is_localhost_url` logic governs that
    ///   elsewhere; callers passing an `http://` URL must satisfy that
    ///   gate themselves.
    /// - Tier 2 (Worker) fallback: custom registries are by definition
    ///   not the LPM Worker; falling back would leak a private package
    ///   name to a public registry. Cache miss → direct fetch only.
    pub async fn get_npm_metadata_from(
        &self,
        base_url: &str,
        name: &str,
        auth: Option<&crate::npmrc::RegistryAuth>,
    ) -> Result<PackageMetadata, LpmError> {
        let url = format!("{base_url}/{name}");

        // Parse destination origin once; used for both the cache key
        // and the auth-origin defensive check.
        let dest_origin = crate::npmrc::OriginKey::from_request_url(&url).ok_or_else(|| {
            LpmError::Registry(format!(
                "invalid registry URL '{url}' — must be http(s) with a host"
            ))
        })?;

        // Origin-mismatch defense lives in `apply_npmrc_auth` below;
        // we still parse `dest_origin` here because we need
        // `host_lower` for the cache key namespace.
        let _ = &dest_origin;

        // Cache key namespace: `npm:<auth_fingerprint>:<url>`.
        //
        // Earlier drafts keyed on (host) only, then (host, port), then
        // full URL. Each step closed a real collision class but the
        // last left a worse hole: the cache was **auth-blind**. A
        // successful fetch under credential A populated the cache, and
        // a later fetch for the same URL under credential B (or none)
        // read A's response without proving its own access. For
        // private registries that vary packument content per token
        // that's a direct auth-bypass; even for token-gated registries
        // that serve identical content per token, it still leaks the
        // existence of private versions to other principals on the
        // same machine.
        //
        // Including the auth fingerprint partitions the cache per
        // principal. Identical credentials → identical fingerprint →
        // warm hits across calls. Different credentials → distinct
        // namespaces. `anon` is the canonical no-auth namespace.
        // The fingerprint is a SHA-256 truncation, so debug logs of
        // the cache key never expose raw tokens. Re-issued client certs
        // invalidate cache cleanly even when URL + auth are unchanged.
        let cache_key = format!(
            "npm:{}:{url}",
            principal_fingerprint(auth, self.http.identity_fp_for_url(&url))
        );

        // Tier 1: TTL+magic cache hit.
        if let Some((cached, _etag)) = self.read_metadata_cache(&cache_key) {
            tracing::debug!("metadata cache hit (custom)");
            return Ok(cached);
        }

        let rpc_start = std::time::Instant::now();
        macro_rules! finish {
            ($expr:expr) => {{
                let r = $expr;
                crate::timing::record_rpc(rpc_start.elapsed());
                r
            }};
        }

        tracing::debug!("fetching {name} from custom registry {base_url}");
        let req = self
            .http
            .for_url(&url)
            .await?
            .get(&url)
            .header("Accept", "application/vnd.npm.install-v1+json");
        // `apply_npmrc_auth` does the origin-mismatch defensive check
        // and attaches Bearer/Basic. Anonymous = no-op.
        let req = apply_npmrc_auth(req, &url, auth)?;

        let response = match self.send_with_retry(req).await {
            Ok(r) => r,
            Err(e) => return finish!(Err(e)),
        };
        let metadata = match parse_capped_metadata::<PackageMetadata>(
            response,
            &format!("get_npm_metadata_from {name} @ {base_url}"),
        )
        .await
        {
            Ok(m) => m,
            Err(e) => return finish!(Err(e)),
        };
        self.write_metadata_cache(&cache_key, &metadata, None);
        finish!(Ok(metadata))
    }

    /// Fan-out npm metadata fetches at `max_concurrency`, direct to
    /// `registry.npmjs.org`, with **halve-on-429** adaptive back-pressure.
    ///
    /// Returned vector is in input order; each entry is a per-package
    /// `Result`. Per-package failures do NOT abort the batch — matches
    /// bun/pnpm semantics and lets the walker log + continue.
    ///
    /// ## Halve-on-429
    ///
    /// If any in-flight request surfaces [`LpmError::RateLimited`], the
    /// effective concurrency is halved for the remainder of this call.
    /// Floor is 4. This is a one-way ratchet per call; the next
    /// `parallel_fetch_npm_manifests` invocation starts fresh.
    ///
    /// Implementation: halving combines two mechanisms to handle both
    /// partial and full saturation:
    ///
    /// 1. **Immediate forget** — the 429-observing task synchronously
    ///    `forget()`s as many permits as are currently free in the
    ///    semaphore. If the pool is fully saturated, this forgets zero.
    /// 2. **Deferred forget** — any shortfall is recorded in a shared
    ///    `forget_debt` counter. Every task, as it completes, checks the
    ///    debt and — if non-zero — forgets its own permit (returning
    ///    nothing to the pool) and decrements the debt. Over the next
    ///    few task completions the pool shrinks to the halved size.
    ///
    /// This fixes the silent-no-op under full saturation: when every
    /// permit is checked out, `try_acquire_owned` returns zero, so the
    /// old code registered a halve event without actually halving. The
    /// debt-on-completion path ensures the ceiling genuinely moves.
    ///
    /// `halve_events` counts only calls that registered debt + forgets
    /// — it is only incremented when either an immediate forget or a
    /// debt-add actually happened, so stats cannot claim halving when
    /// no effective reduction occurred.
    ///
    /// Rationale: `send_with_retry` already handles per-request 429s
    /// with `Retry-After`. What `send_with_retry` can't do is reduce
    /// the batch's aggregate pressure on npm — that needs batch-level
    /// knowledge.
    ///
    /// Returned [`FanOutStats`] surfaces the halve events so callers
    /// can record them in observability without interpreting errors.
    pub async fn parallel_fetch_npm_manifests(
        self: &Arc<Self>,
        names: &[String],
        max_concurrency: usize,
    ) -> (
        Vec<(String, Result<PackageMetadata, LpmError>)>,
        FanOutStats,
    ) {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use tokio::sync::Semaphore;

        const CONCURRENCY_FLOOR: usize = 4;

        let initial = max_concurrency.max(CONCURRENCY_FLOOR);
        let semaphore = Arc::new(Semaphore::new(initial));
        // Tracks the current effective ceiling (initial minus forgotten
        // permits, whether forgotten immediately or via debt).
        let current_ceiling = Arc::new(AtomicUsize::new(initial));
        // Permits still owed to the halving mechanism. Task completions
        // consume debt before returning their permit to the pool.
        let forget_debt = Arc::new(AtomicUsize::new(0));
        let halve_events = Arc::new(AtomicUsize::new(0));

        let mut futures = Vec::with_capacity(names.len());
        for (idx, name) in names.iter().enumerate() {
            let sem = semaphore.clone();
            let ceiling = current_ceiling.clone();
            let debt = forget_debt.clone();
            let halves = halve_events.clone();
            let client = self.clone();
            let name = name.clone();
            futures.push(tokio::spawn(async move {
                // `acquire_owned` returns a permit that auto-releases on
                // drop UNLESS we call `forget()` (used for halve-on-429).
                let permit = match sem.clone().acquire_owned().await {
                    Ok(p) => p,
                    Err(_) => {
                        return (
                            idx,
                            name,
                            Err(LpmError::Network(
                                "fanout semaphore closed before fetch".into(),
                            )),
                        );
                    }
                };

                let result = client.get_npm_metadata_direct(&name).await;

                if matches!(result, Err(LpmError::RateLimited { .. })) {
                    // Atomically claim a halving step against `ceiling`
                    // via a CAS loop. Without this, two concurrent 429s
                    // can both read `current=8` before either decrements,
                    // both enqueue `want_forget=4` of debt, and the 8
                    // subsequent completions drive effective pool to 0 —
                    // below the floor. CAS on the ceiling is the only
                    // way to make "decide how much to halve" atomic WRT
                    // other 429-handlers; a CAS on debt alone can't help
                    // because each handler's `want_forget` is computed
                    // from a stale ceiling.
                    //
                    // Loop ends in one of two states:
                    //   - We committed the decrement: ceiling is now
                    //     `current - want_forget`. We own `want_forget`
                    //     permits to forget (via immediate `try_acquire`
                    //     + deferred debt); the pool physical size
                    //     catches up as completions pay debt.
                    //   - Ceiling dropped to/below floor before we won
                    //     the CAS: nothing more to halve. Exit without
                    //     adding debt (another handler did our work).
                    loop {
                        let current = ceiling.load(Ordering::SeqCst);
                        if current <= CONCURRENCY_FLOOR {
                            break; // at floor; nothing more to halve
                        }
                        let want_forget = (current / 2).min(current - CONCURRENCY_FLOOR);
                        let new_ceiling = current - want_forget;
                        if ceiling
                            .compare_exchange(
                                current,
                                new_ceiling,
                                Ordering::SeqCst,
                                Ordering::SeqCst,
                            )
                            .is_err()
                        {
                            continue; // another handler moved ceiling; retry
                        }

                        // We own `want_forget` permits to remove. Split
                        // between immediate forgets (pool has free
                        // permits right now) and deferred debt (saturated;
                        // next task completions forget their permits).
                        let mut forgot_now = 0usize;
                        while forgot_now < want_forget {
                            match sem.clone().try_acquire_owned() {
                                Ok(p) => {
                                    p.forget();
                                    forgot_now += 1;
                                }
                                Err(_) => break,
                            }
                        }
                        let shortfall = want_forget - forgot_now;
                        if shortfall > 0 {
                            debt.fetch_add(shortfall, Ordering::SeqCst);
                        }
                        halves.fetch_add(1, Ordering::SeqCst);
                        tracing::debug!(
                            "parallel_fetch_npm_manifests: halving after 429 on {name} \
                             (immediate={forgot_now}, deferred_debt={shortfall}, \
                             ceiling {current}→{new_ceiling})"
                        );
                        break;
                    }
                }

                // Task completion: pay down any outstanding forget debt
                // by forgetting our own permit instead of returning it.
                // CAS loop avoids double-decrement races when several
                // completions race on the same debt.
                let mut paid_debt = false;
                loop {
                    let d = debt.load(Ordering::SeqCst);
                    if d == 0 {
                        break;
                    }
                    match debt.compare_exchange(d, d - 1, Ordering::SeqCst, Ordering::SeqCst) {
                        Ok(_) => {
                            paid_debt = true;
                            break;
                        }
                        Err(_) => continue, // raced; retry
                    }
                }
                if paid_debt {
                    // Forget our own permit to satisfy the debt. Ceiling
                    // was already decremented at CAS time in the
                    // halve-step above — do NOT decrement again here or
                    // the ceiling lags behind reality by (debt paid).
                    permit.forget();
                } else {
                    drop(permit);
                }

                (idx, name, result)
            }));
        }

        let mut results: Vec<(usize, String, Result<PackageMetadata, LpmError>)> =
            Vec::with_capacity(names.len());
        for fut in futures {
            match fut.await {
                Ok(entry) => results.push(entry),
                Err(join_err) => {
                    results.push((
                        0,
                        String::new(),
                        Err(LpmError::Network(format!(
                            "fanout task panicked: {join_err}"
                        ))),
                    ));
                }
            }
        }
        results.sort_by_key(|(idx, _, _)| *idx);
        let out: Vec<(String, Result<PackageMetadata, LpmError>)> =
            results.into_iter().map(|(_, n, r)| (n, r)).collect();

        let stats = FanOutStats {
            initial_concurrency: initial,
            final_concurrency: current_ceiling.load(Ordering::SeqCst),
            halve_events: halve_events.load(Ordering::SeqCst),
        };
        (out, stats)
    }

    /// Download a tarball as raw bytes.
    ///
    /// The URL comes from `VersionMetadata.dist.tarball`.
    ///
    /// Only HTTPS URLs are allowed (with exceptions for localhost/127.0.0.1/[::1]
    /// during development, or when `allow_insecure` is set via `--insecure`).
    /// This prevents supply-chain attacks where a compromised lockfile or
    /// registry response redirects downloads to a malicious HTTP server.
    ///
    /// Note: This method buffers the entire tarball in memory. For install flows,
    /// prefer `download_tarball_to_file()` which spools to disk with bounded memory.
    pub async fn download_tarball(&self, url: &str) -> Result<Vec<u8>, LpmError> {
        self.check_tarball_url_scheme(url)?;

        let response = self.send_with_retry(self.build_get(url).await?).await?;

        let bytes = response
            .bytes()
            .await
            .map_err(|e| LpmError::Network(format!("failed to read tarball bytes: {e}")))?;

        Ok(bytes.to_vec())
    }

    /// Download a tarball to a temp file, computing SHA-512 as chunks arrive.
    ///
    /// Returns a `DownloadedTarball` containing the temp file path, SRI hash,
    /// and compressed byte count. The tarball is never fully buffered in memory —
    /// each network chunk (~64KB) is written to disk and fed to the hasher, keeping
    /// peak memory bounded regardless of package size.
    ///
    /// Enforces `MAX_COMPRESSED_TARBALL_SIZE` (500 MB) during download.
    /// The temp file is created with restrictive permissions (0600) and is deleted
    /// when the `DownloadedTarball` is dropped.
    pub async fn download_tarball_to_file(&self, url: &str) -> Result<DownloadedTarball, LpmError> {
        self.download_tarball_to_file_with_limit(url, MAX_COMPRESSED_TARBALL_SIZE)
            .await
    }

    /// Download a tarball using an `.npmrc`-derived credential.
    ///
    /// Distinct from [`Self::download_tarball_to_file`] in two ways:
    /// 1. Attaches the supplied `auth` (origin-checked) instead of the
    ///    LPM session bearer that `build_get` would supply. The LPM
    ///    bearer is for `lpm.dev`; sending it to a `.npmrc`-declared
    ///    custom registry would leak the token cross-origin.
    /// 2. When `auth` is `None`, the request goes anonymous — no LPM
    ///    bearer attached either.
    ///
    /// Same temp-file + SRI shape as `download_tarball_to_file`. The
    /// caller is responsible for routing to the correct method
    /// (this one for npm-style tarballs; `download_tarball_to_file`
    /// for LPM tarballs that need the session bearer).
    pub async fn download_tarball_to_file_with_auth(
        &self,
        url: &str,
        auth: Option<&crate::npmrc::RegistryAuth>,
    ) -> Result<DownloadedTarball, LpmError> {
        self.download_tarball_to_file_with_auth_and_limit(url, auth, MAX_COMPRESSED_TARBALL_SIZE)
            .await
    }

    async fn download_tarball_to_file_with_auth_and_limit(
        &self,
        url: &str,
        auth: Option<&crate::npmrc::RegistryAuth>,
        max_compressed_size: u64,
    ) -> Result<DownloadedTarball, LpmError> {
        self.check_tarball_url_scheme(url)?;
        let req = self.http.for_url(url).await?.get(url);
        let req = apply_npmrc_auth(req, url, auth)?;
        let mut response = self.send_with_retry(req).await?;

        if let Some(content_length) = response.content_length()
            && content_length > max_compressed_size
        {
            return Err(LpmError::Registry(format!(
                "tarball Content-Length exceeds maximum compressed size ({} bytes > {} bytes limit)",
                content_length, max_compressed_size
            )));
        }

        use base64::Engine;
        use sha2::{Digest, Sha512};

        let mut hasher = Sha512::new();
        let mut temp_file = tempfile::NamedTempFile::new().map_err(|e| {
            LpmError::Io(std::io::Error::other(format!(
                "failed to create temp file for tarball: {e}"
            )))
        })?;

        // Set restrictive permissions — untrusted data until hash verified.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = temp_file
                .as_file()
                .set_permissions(std::fs::Permissions::from_mode(0o600));
        }

        let mut compressed_size: u64 = 0;
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|e| LpmError::Network(format!("failed to read tarball chunk: {e}")))?
        {
            compressed_size += chunk.len() as u64;
            if compressed_size > max_compressed_size {
                return Err(LpmError::Registry(format!(
                    "tarball exceeds maximum compressed size ({} bytes > {} bytes limit)",
                    compressed_size, max_compressed_size
                )));
            }
            hasher.update(&chunk);
            write_tarball_chunk(&mut temp_file, &chunk)?;
        }

        flush_tarball_file(&mut temp_file)?;

        let hash = hasher.finalize();
        let sri = format!(
            "sha512-{}",
            base64::engine::general_purpose::STANDARD.encode(hash)
        );

        Ok(DownloadedTarball {
            file: temp_file,
            sri,
            compressed_size,
        })
    }

    /// Streaming variant of [`Self::download_tarball_to_file_with_auth`].
    /// Same auth semantics; returns the raw `reqwest::Response` for the
    /// caller to drain via `.bytes_stream()`. Mirrors
    /// `download_tarball_streaming` shape exactly except for the auth
    /// pathway.
    pub async fn download_tarball_streaming_with_auth(
        &self,
        url: &str,
        auth: Option<&crate::npmrc::RegistryAuth>,
    ) -> Result<reqwest::Response, LpmError> {
        self.check_tarball_url_scheme(url)?;
        let req = self.http.for_url(url).await?.get(url);
        let req = apply_npmrc_auth(req, url, auth)?;
        let response = self.send_with_retry(req).await?;

        if let Some(content_length) = response.content_length()
            && content_length > MAX_COMPRESSED_TARBALL_SIZE
        {
            return Err(LpmError::Registry(format!(
                "tarball Content-Length exceeds maximum compressed size ({} bytes > {} bytes limit)",
                content_length, MAX_COMPRESSED_TARBALL_SIZE
            )));
        }
        Ok(response)
    }

    /// Download a tarball to a temp file with a custom size limit.
    ///
    /// `download_tarball_to_file()` uses the default `MAX_COMPRESSED_TARBALL_SIZE` (500 MB).
    /// This variant is exposed for testing the rejection path with smaller limits.
    pub async fn download_tarball_to_file_with_limit(
        &self,
        url: &str,
        max_compressed_size: u64,
    ) -> Result<DownloadedTarball, LpmError> {
        self.check_tarball_url_scheme(url)?;

        let mut response = self.send_with_retry(self.build_get(url).await?).await?;

        if let Some(content_length) = response.content_length()
            && content_length > max_compressed_size
        {
            return Err(LpmError::Registry(format!(
                "tarball Content-Length exceeds maximum compressed size ({} bytes > {} bytes limit)",
                content_length, max_compressed_size
            )));
        }

        use base64::Engine;
        use sha2::{Digest, Sha512};

        let mut hasher = Sha512::new();
        let mut temp_file = tempfile::NamedTempFile::new().map_err(|e| {
            LpmError::Io(std::io::Error::other(format!(
                "failed to create temp file for tarball: {e}"
            )))
        })?;

        // Set restrictive permissions — untrusted data until hash verified
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = temp_file
                .as_file()
                .set_permissions(std::fs::Permissions::from_mode(0o600));
        }

        let mut compressed_size: u64 = 0;

        // Stream chunks to disk + hasher — bounded memory regardless of package size
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|e| LpmError::Network(format!("failed to read tarball chunk: {e}")))?
        {
            compressed_size += chunk.len() as u64;
            if compressed_size > max_compressed_size {
                // Clean up temp file (dropped automatically) and reject
                return Err(LpmError::Registry(format!(
                    "tarball exceeds maximum compressed size ({} bytes > {} bytes limit)",
                    compressed_size, max_compressed_size
                )));
            }
            hasher.update(&chunk);
            write_tarball_chunk(&mut temp_file, &chunk)?;
        }

        // Flush to ensure all data is on disk before verification
        flush_tarball_file(&mut temp_file)?;

        let hash = hasher.finalize();
        let sri = format!(
            "sha512-{}",
            base64::engine::general_purpose::STANDARD.encode(hash)
        );

        Ok(DownloadedTarball {
            file: temp_file,
            sri,
            compressed_size,
        })
    }

    /// Streaming tarball download — low-allocation fast path.
    ///
    /// Returns the validated [`reqwest::Response`] with its body left intact
    /// for the caller to drain via `.bytes_stream()`. No temp file spool,
    /// no in-memory buffering: the caller pipes response bytes directly
    /// into a hashing extractor writing into the store's staging directory,
    /// all on a `spawn_blocking` worker via `tokio_util::io::StreamReader`
    /// + `tokio::io::SyncIoBridge`.
    ///
    /// Validation performed before returning:
    /// - URL scheme (HTTPS or localhost)
    /// - HTTP status (404 → `LpmError::NotFound`; other non-2xx →
    ///   `LpmError::Registry`)
    /// - `Content-Length` against `MAX_COMPRESSED_TARBALL_SIZE` when the
    ///   server declares one (streaming size enforcement is the caller's
    ///   responsibility — we can't check it here without consuming the
    ///   body).
    /// - Auth + retry via `send_with_retry`, identical to
    ///   `download_tarball_to_file_with_limit`.
    ///
    /// The retry window closes at `send_with_retry`'s return: mid-stream
    /// failures surface to the caller as `LpmError::Network`; cleanup of
    /// the partial staging directory is the store's responsibility (see
    /// `lpm_store::PackageStore::stream_and_store_package`).
    pub async fn download_tarball_streaming(
        &self,
        url: &str,
    ) -> Result<reqwest::Response, LpmError> {
        self.check_tarball_url_scheme(url)?;

        let response = self.send_with_retry(self.build_get(url).await?).await?;

        if let Some(content_length) = response.content_length()
            && content_length > MAX_COMPRESSED_TARBALL_SIZE
        {
            return Err(LpmError::Registry(format!(
                "tarball Content-Length exceeds maximum compressed size ({} bytes > {} bytes limit)",
                content_length, MAX_COMPRESSED_TARBALL_SIZE
            )));
        }

        Ok(response)
    }

    /// File-spool tarball download with `.npmrc` Custom-route auth.
    ///
    /// Custom-route destinations (private/corp registries declared in
    /// `.npmrc`) ride the auth-aware download so the npmrc credential
    /// reaches the destination origin and the LPM session bearer is NOT
    /// leaked. All other routes (LpmWorker, NpmDirect) use the no-auth
    /// method.
    ///
    /// File-spool variant — bounded memory via
    /// [`MAX_COMPRESSED_TARBALL_SIZE`] (500 MB). The streaming sibling
    /// [`Self::download_tarball_streaming_routed`] is preferable when the
    /// consumer can stream-extract.
    pub async fn download_tarball_routed(
        &self,
        route_table: &crate::route::RouteTable,
        name: &str,
        url: &str,
    ) -> Result<DownloadedTarball, LpmError> {
        if matches!(
            route_table.route_for_package(name),
            crate::route::UpstreamRoute::Custom { .. }
        ) {
            let auth = route_table.auth_for_url(url);
            self.download_tarball_to_file_with_auth(url, auth).await
        } else {
            self.download_tarball_to_file(url).await
        }
    }

    /// Streaming variant of [`Self::download_tarball_routed`]. Same
    /// Custom-vs-non-Custom split.
    ///
    /// M66: for the non-Custom path (LpmWorker / NpmDirect), the
    /// fresh `dist.tarball` URL's origin is verified against
    /// `is_configured_origin` before the body is read. Pre-fix, no
    /// origin gate applied to fresh URLs — a freshly-fetched metadata
    /// response from a compromised mirror could point `dist.tarball`
    /// at `https://evil.cdn/<pkg>.tgz` and pass the pipeline-level
    /// scheme check unchallenged. The shape check (`/-/` + `.tgz`)
    /// that `evaluate_cached_url` applies to LOCKFILE-cached URLs is
    /// intentionally NOT applied here: a fresh packument from the
    /// configured registry is allowed to use any path shape the
    /// registry serves (some private registries and test mocks use
    /// flat `/tarballs/<name>-<ver>.tgz` instead of npm's canonical
    /// `/<pkg>/-/<pkg>-<ver>.tgz`). The origin check alone defends
    /// against the M66 mirror-redirect shape.
    ///
    /// The Custom route path is exempt because its npmrc-declared
    /// target origin is intentionally outside the `(base_url,
    /// npm_registry_url)` pair `is_configured_origin` knows about;
    /// the H2 auth-mismatch gate on `apply_npmrc_auth` already
    /// enforces destination/credential parity for that flow.
    pub async fn download_tarball_streaming_routed(
        &self,
        route_table: &crate::route::RouteTable,
        name: &str,
        url: &str,
    ) -> Result<reqwest::Response, LpmError> {
        if matches!(
            route_table.route_for_package(name),
            crate::route::UpstreamRoute::Custom { .. }
        ) {
            let auth = route_table.auth_for_url(url);
            self.download_tarball_streaming_with_auth(url, auth).await
        } else {
            if !self.is_configured_origin(url) {
                return Err(LpmError::Registry(format!(
                    "tarball URL refused — fresh dist.tarball origin is not in the configured \
                     set (likely poisoned mirror or metadata tamper): {url}"
                )));
            }
            self.download_tarball_streaming(url).await
        }
    }

    /// Download a tarball and compute its SHA-512 hash, returning bytes in memory.
    ///
    /// **Deprecated in favor of `download_tarball_to_file()`** which uses bounded
    /// memory. This variant is kept for backward compatibility with callers that
    /// need the raw bytes (e.g., `lpm publish` verification).
    pub async fn download_tarball_with_hash(
        &self,
        url: &str,
    ) -> Result<(Vec<u8>, String), LpmError> {
        let downloaded = self.download_tarball_to_file(url).await?;
        let data = std::fs::read(downloaded.file.path()).map_err(|e| {
            LpmError::Io(std::io::Error::new(
                e.kind(),
                format!("failed to read downloaded tarball: {e}"),
            ))
        })?;
        Ok((data, downloaded.sri))
    }

    /// Download a tarball from an arbitrary URL and verify its content
    /// against an optionally-supplied SRI integrity hash.
    ///
    /// - `expected_integrity = Some("sha…-…")` — the downloaded tarball's
    ///   content is verified against the declared hash. The verification is
    ///   algorithm-aware: the expected SRI is parsed for its algorithm
    ///   prefix, the tarball is re-hashed with that algorithm if it differs
    ///   from the streaming download's default sha512, and the raw hash
    ///   bytes are compared. Both `sha256-…` and `sha512-…` work natively.
    ///   Mismatch returns [`LpmError::IntegrityMismatch`] with `actual` in
    ///   the same algorithm the caller declared.
    /// - `expected_integrity = None` — trust-on-first-use. Returns the
    ///   bytes plus the computed sha512 SRI; caller is responsible for
    ///   recording it in the lockfile so subsequent installs verify.
    ///
    /// All scheme + auth + redirect handling is inherited from
    /// [`Self::download_tarball_with_hash`]. This is the non-registry-
    /// routed path: the URL points directly at the tarball, NOT at a
    /// packument.
    pub async fn download_tarball_with_integrity(
        &self,
        url: &str,
        expected_integrity: Option<&str>,
    ) -> Result<(Vec<u8>, String), LpmError> {
        use lpm_common::integrity::{HashAlgorithm, Integrity};

        let (data, computed_sha512_sri) = self.download_tarball_with_hash(url).await?;

        let Some(expected) = expected_integrity else {
            // Trust-on-first-use: return the streaming sha512 hash.
            return Ok((data, computed_sha512_sri));
        };

        // Parse the declared SRI to learn its algorithm. Then re-hash (or
        // reuse the existing sha512) as appropriate and compare raw hash
        // bytes. String comparison breaks for sha256 declarations against
        // the streaming sha512 hash.
        let expected_int = Integrity::parse(expected)?;
        let actual_int = match expected_int.algorithm {
            HashAlgorithm::Sha512 => {
                // Reuse the streaming sha512 we already have —
                // re-hashing 100 MB just to bytes-compare when we
                // already have a string SRI would be wasteful.
                Integrity::parse(&computed_sha512_sri)?
            }
            HashAlgorithm::Sha256 => {
                // Re-hash with sha256. O(n) extra cost, but only
                // when the caller's algorithm differs from the
                // streaming default — rare.
                Integrity::from_bytes(HashAlgorithm::Sha256, &data)
            }
        };
        if expected_int.hash != actual_int.hash {
            return Err(LpmError::IntegrityMismatch {
                expected: expected.to_string(),
                actual: actual_int.to_string(),
            });
        }
        // Match — return the SRI in the same algorithm the caller
        // declared so downstream record-keeping stays algorithm-
        // consistent.
        Ok((data, actual_int.to_string()))
    }

    // ─── Discovery Endpoints ────────────────────────────────────────

    /// Search packages.
    ///
    /// Posture: `AnonymousPreferred` — public discovery endpoint, no
    /// bearer attached even when stored.
    ///
    /// Calls: GET /api/search/packages?q=...&limit=...&mode=semantic
    pub async fn search_packages(
        &self,
        query: &str,
        limit: u32,
    ) -> Result<SearchResponse, LpmError> {
        let url = format!(
            "{}/api/search/packages?q={}&limit={}&mode=semantic",
            self.base_url,
            urlencoding::encode(query),
            limit.min(20)
        );
        self.get_json_anon(&url, AuthPosture::AnonymousPreferred)
            .await
    }

    /// Search owners (users and organizations).
    ///
    /// Posture: `AnonymousPreferred` — public discovery endpoint.
    ///
    /// Calls: GET /api/search/owners?q=...&limit=...
    pub async fn search_owners(
        &self,
        query: &str,
        limit: u32,
    ) -> Result<OwnerSearchResponse, LpmError> {
        let url = format!(
            "{}/api/search/owners?q={}&limit={}",
            self.base_url,
            urlencoding::encode(query),
            limit.min(10)
        );
        self.get_json_anon(&url, AuthPosture::AnonymousPreferred)
            .await
    }

    /// Check if a package name is available.
    ///
    /// Posture: `AuthRequired` — the original docstring noted "prevents
    /// enumeration", which means the server gates this endpoint.
    /// Wrapped in `execute_with_recovery` so a stale stored session
    /// self-heals.
    ///
    /// Calls: GET /api/registry/check-name?name=owner.package-name
    pub async fn check_name(&self, name: &str) -> Result<CheckNameResponse, LpmError> {
        let url = format!(
            "{}/api/registry/check-name?name={}",
            self.base_url,
            urlencoding::encode(name)
        );
        self.execute_with_recovery(AuthPosture::AuthRequired, || self.get_json(&url))
            .await
    }

    // ─── Auth Endpoints ─────────────────────────────────────────────

    /// Get current user info.
    ///
    /// Posture: `AuthRequired`. On 401 with a refresh-backed session,
    /// `execute_with_recovery` performs one silent refresh + retry.
    ///
    /// Calls: GET /api/registry/-/whoami
    pub async fn whoami(&self) -> Result<WhoamiResponse, LpmError> {
        let url = format!("{}/api/registry/-/whoami", self.base_url);
        self.execute_with_recovery(AuthPosture::AuthRequired, || self.get_json(&url))
            .await
    }

    /// Validate the current token.
    ///
    /// Posture: `AuthRequired`.
    ///
    /// Calls: GET /api/registry/cli/check
    pub async fn check_token(&self) -> Result<TokenCheckResponse, LpmError> {
        let url = format!("{}/api/registry/cli/check", self.base_url);
        self.execute_with_recovery(AuthPosture::AuthRequired, || self.get_json(&url))
            .await
    }

    /// Revoke the current token on the server.
    ///
    /// Posture: `AuthRequired`. The bearer is re-resolved inside the
    /// recovery closure so that, on a 401 → refresh → retry, the
    /// rotated token is sent on the second attempt.
    ///
    /// Calls: POST /api/registry/tokens/revoke
    pub async fn revoke_token(&self) -> Result<(), LpmError> {
        let url = format!("{}/api/registry/tokens/revoke", self.base_url);

        self.execute_with_recovery(AuthPosture::AuthRequired, || async {
            let bearer = self
                .current_bearer(AuthPosture::AuthRequired)
                .ok_or_else(|| LpmError::Registry("no token to revoke".to_string()))?;
            let body = serde_json::json!({ "token": bearer });
            let req = self
                .http
                .for_url(&url)
                .await?
                .post(&url)
                .bearer_auth(&bearer)
                .json(&body);
            let response = self.send_with_retry(req).await?;
            if response.status().is_success() {
                Ok(())
            } else {
                Err(LpmError::Registry(format!(
                    "token revocation failed: {}",
                    response.status()
                )))
            }
        })
        .await
    }

    /// Publish a package to the registry.
    ///
    /// Posture: `AuthRequired`. Wrapped in `execute_with_recovery`
    /// so a stale access token on a refresh-backed session triggers
    /// one silent refresh + retry of the entire publish (audit fix
    /// #3). The bespoke S4 500-handling inside `send_publish_safe`
    /// is preserved because it lives inside the closure and runs on
    /// each attempt.
    ///
    /// Calls: PUT /api/registry/{encoded_name}
    /// Optional `otp` header for 2FA-enabled users.
    ///
    /// Uses publish-safe retry logic (S4): does NOT retry on HTTP 500
    /// (the server may have stored the version before crashing). Only retries
    /// on gateway errors (502/503/504) and network-level failures.
    ///
    /// Timeout is scaled based on tarball size (S3): 60s + 2s per MB, cap 600s.
    pub async fn publish_package(
        &self,
        encoded_name: &str,
        payload: &serde_json::Value,
        otp: Option<&str>,
        tarball_size_bytes: usize,
    ) -> Result<serde_json::Value, LpmError> {
        let url = format!("{}/api/registry/{}", self.base_url, encoded_name);

        // S3: Scale timeout based on tarball size
        let tarball_mb = tarball_size_bytes as u64 / (1024 * 1024);
        let timeout_secs = std::cmp::min(60 + tarball_mb * 2, 600);
        let publish_client = reqwest::Client::builder()
            .timeout(Duration::from_secs(timeout_secs))
            // Same redirect-policy pin as the main client builder:
            // explicit Policy::limited so a future edit can't silently
            // expand the chain or drop the cross-origin Authorization
            // strip that reqwest applies by default.
            .redirect(reqwest::redirect::Policy::limited(10))
            .user_agent(format!("lpm-rs/{}", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|e| LpmError::Network(format!("failed to build publish client: {e}")))?;

        self.execute_with_recovery(AuthPosture::AuthRequired, || async {
            let mut req = publish_client.put(&url).json(payload);
            if let Some(bearer) = self.current_bearer(AuthPosture::AuthRequired) {
                req = req.bearer_auth(bearer);
            }
            if let Some(code) = otp {
                req = req.header("x-otp", code);
            }

            // S4: Publish-safe send — no retry on 500, only on gateway errors
            let response = self.send_publish_safe(req, encoded_name).await?;
            let status = response.status();
            let body: serde_json::Value =
                parse_capped_api_json(response, "publish response").await?;

            if status.is_success() {
                Ok(body)
            } else {
                let error_msg = body
                    .get("error")
                    .and_then(|e| e.as_str())
                    .unwrap_or("unknown error");
                let code = body.get("code").and_then(|c| c.as_str()).unwrap_or("");

                Err(LpmError::Registry(format!(
                    "publish failed ({}): {} {}",
                    status,
                    error_msg,
                    if code.is_empty() {
                        String::new()
                    } else {
                        format!("[{code}]")
                    }
                )))
            }
        })
        .await
    }

    // ─── Intelligence Endpoints ─────────────────────────────────────

    /// Get quality report for a package.
    ///
    /// Posture: `AnonymousPreferred` — public read; bearer not attached.
    ///
    /// Calls: GET /api/registry/quality?name=owner.package-name
    pub async fn get_quality(&self, name: &str) -> Result<QualityResponse, LpmError> {
        let url = format!(
            "{}/api/registry/quality?name={}",
            self.base_url,
            urlencoding::encode(name)
        );
        self.get_json_anon(&url, AuthPosture::AnonymousPreferred)
            .await
    }

    /// Get Agent Skills for a package.
    ///
    /// Posture: `AnonymousPreferred`.
    ///
    /// Calls: GET /api/registry/skills?name=owner.package-name
    pub async fn get_skills(
        &self,
        name: &str,
        version: Option<&str>,
    ) -> Result<SkillsResponse, LpmError> {
        let mut url = format!(
            "{}/api/registry/skills?name={}",
            self.base_url,
            urlencoding::encode(name)
        );
        if let Some(v) = version {
            url.push_str(&format!("&version={}", urlencoding::encode(v)));
        }
        self.get_json_anon(&url, AuthPosture::AnonymousPreferred)
            .await
    }

    /// Get API documentation for a package.
    ///
    /// Posture: `AnonymousPreferred`.
    ///
    /// Calls: GET /api/registry/api-docs?name=owner.package-name
    pub async fn get_api_docs(
        &self,
        name: &str,
        version: Option<&str>,
    ) -> Result<ApiDocsResponse, LpmError> {
        let mut url = format!(
            "{}/api/registry/api-docs?name={}",
            self.base_url,
            urlencoding::encode(name)
        );
        if let Some(v) = version {
            url.push_str(&format!("&version={}", urlencoding::encode(v)));
        }
        self.get_json_anon(&url, AuthPosture::AnonymousPreferred)
            .await
    }

    /// Get LLM context for a package.
    ///
    /// Posture: `AnonymousPreferred`.
    ///
    /// Calls: GET /api/registry/llm-context?name=owner.package-name
    pub async fn get_llm_context(
        &self,
        name: &str,
        version: Option<&str>,
    ) -> Result<LlmContextResponse, LpmError> {
        let mut url = format!(
            "{}/api/registry/llm-context?name={}",
            self.base_url,
            urlencoding::encode(name)
        );
        if let Some(v) = version {
            url.push_str(&format!("&version={}", urlencoding::encode(v)));
        }
        self.get_json_anon(&url, AuthPosture::AnonymousPreferred)
            .await
    }

    // ─── Revenue Endpoints ──────────────────────────────────────────

    /// Get Pool revenue stats for the current user.
    ///
    /// Posture: `AuthRequired` (account-scoped data). Wrapped in
    /// `execute_with_recovery` so a stale stored session self-heals.
    ///
    /// Calls: GET /api/registry/pool/stats
    pub async fn get_pool_stats(&self) -> Result<PoolStatsResponse, LpmError> {
        let url = format!("{}/api/registry/pool/stats", self.base_url);
        self.execute_with_recovery(AuthPosture::AuthRequired, || self.get_json(&url))
            .await
    }

    /// Get Marketplace earnings for the current user.
    ///
    /// Posture: `AuthRequired` (account-scoped data). Same recovery
    /// contract as `get_pool_stats`.
    ///
    /// Calls: GET /api/registry/marketplace/earnings
    pub async fn get_marketplace_earnings(&self) -> Result<MarketplaceEarningsResponse, LpmError> {
        let url = format!("{}/api/registry/marketplace/earnings", self.base_url);
        self.execute_with_recovery(AuthPosture::AuthRequired, || self.get_json(&url))
            .await
    }

    // ─── Health ─────────────────────────────────────────────────────

    /// Check registry health.
    ///
    /// Posture: `AnonymousOnly` — health endpoint is universally
    /// public and must never carry a bearer.
    ///
    /// Calls: GET /api/registry/health
    pub async fn health_check(&self) -> Result<bool, LpmError> {
        let url = format!("{}/api/registry/health", self.base_url);
        let response = self
            .send_with_retry(
                self.build_get_with_posture(&url, AuthPosture::AnonymousOnly)
                    .await?,
            )
            .await?;
        Ok(response.status().is_success())
    }

    // ─── Tunnel Endpoints ──────────────────────────────────────────

    /// List claimed tunnel domains.
    ///
    /// Posture: `SessionRequired`. Wrapped in `execute_with_recovery`
    /// so stale-access-token cases still self-heal for refresh-backed
    /// sessions.
    ///
    /// Calls: GET /api/tunnel/domains or GET /api/tunnel/domains?org=slug
    pub async fn tunnel_list(&self, org_slug: Option<&str>) -> Result<serde_json::Value, LpmError> {
        let url = if let Some(slug) = org_slug {
            format!(
                "{}/api/tunnel/domains?org={}",
                self.base_url,
                urlencoding::encode(slug)
            )
        } else {
            format!("{}/api/tunnel/domains", self.base_url)
        };
        self.execute_with_recovery(AuthPosture::SessionRequired, || self.get_json(&url))
            .await
    }

    /// Claim a tunnel domain.
    ///
    /// Posture: `SessionRequired`. Same recovery contract as
    /// `tunnel_list` (audit fix #3).
    ///
    /// Calls: POST /api/tunnel/domains
    /// Body: { domain: "acme-api.lpm.llc", org?: "acmecorp" }
    pub async fn tunnel_claim(
        &self,
        domain: &str,
        org_slug: Option<&str>,
    ) -> Result<serde_json::Value, LpmError> {
        let url = format!("{}/api/tunnel/domains", self.base_url);
        let mut body = serde_json::json!({ "domain": domain });
        if let Some(slug) = org_slug {
            body["org"] = serde_json::Value::String(slug.to_string());
        }
        self.execute_with_recovery(AuthPosture::SessionRequired, || async {
            let response = self.post_json_raw(&url, &body).await?;
            let status = response.status();
            let data: serde_json::Value =
                parse_capped_api_json(response, "tunnel claim response").await?;

            if !status.is_success() {
                let error = data["error"].as_str().unwrap_or("Unknown error");
                return Err(LpmError::Tunnel(error.to_string()));
            }

            Ok(data)
        })
        .await
    }

    /// Release a claimed tunnel domain.
    ///
    /// Posture: `SessionRequired`. Same recovery contract as
    /// `tunnel_list` (audit fix #3).
    ///
    /// Calls: DELETE /api/tunnel/domains/{domain}
    pub async fn tunnel_unclaim(
        &self,
        domain: &str,
        org_slug: Option<&str>,
    ) -> Result<serde_json::Value, LpmError> {
        let url = if let Some(slug) = org_slug {
            format!(
                "{}/api/tunnel/domains/{}?org={}",
                self.base_url,
                urlencoding::encode(domain),
                urlencoding::encode(slug)
            )
        } else {
            format!(
                "{}/api/tunnel/domains/{}",
                self.base_url,
                urlencoding::encode(domain)
            )
        };
        self.execute_with_recovery(AuthPosture::SessionRequired, || async {
            let mut req = self.http.for_url(&url).await?.delete(&url);
            if let Some(bearer) = self.current_bearer(AuthPosture::SessionRequired) {
                req = req.bearer_auth(bearer);
            }
            let response = self.send_with_retry(req).await?;
            let status = response.status();
            let data: serde_json::Value =
                parse_capped_api_json(response, "tunnel unclaim response").await?;

            if !status.is_success() {
                let error = data["error"].as_str().unwrap_or("Unknown error");
                return Err(LpmError::Tunnel(error.to_string()));
            }

            Ok(data)
        })
        .await
    }

    /// List available tunnel base domains.
    ///
    /// Posture: `AnonymousPreferred` — endpoint is documented public.
    /// No bearer attached, no recovery on 401.
    ///
    /// Calls: GET /api/tunnel/domains/available
    pub async fn tunnel_available_domains(&self) -> Result<serde_json::Value, LpmError> {
        let url = format!("{}/api/tunnel/domains/available", self.base_url);
        self.get_json_anon(&url, AuthPosture::AnonymousPreferred)
            .await
    }

    /// Look up a specific tunnel domain claim.
    ///
    /// Posture: `SessionRequired` (the response includes
    /// `ownedByYou` which depends on the caller's identity). Same
    /// recovery contract as `tunnel_list` (audit fix #3).
    ///
    /// Calls: GET /api/tunnel/domains/{domain}
    pub async fn tunnel_domain_lookup(&self, domain: &str) -> Result<serde_json::Value, LpmError> {
        let url = format!(
            "{}/api/tunnel/domains/{}",
            self.base_url,
            urlencoding::encode(domain)
        );
        self.execute_with_recovery(AuthPosture::SessionRequired, || self.get_json(&url))
            .await
    }

    // ─── Metadata Cache ──────────────────────────────────────────────

    fn cache_path(&self, key: &str) -> Option<std::path::PathBuf> {
        let dir = self.cache_dir.as_ref()?;
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(key.as_bytes());
        let hash = format!("{:x}", hasher.finalize());
        Some(dir.join(&hash[..16]))
    }

    /// Invalidate a cached metadata entry served by the LPM Worker
    /// (`@lpm.dev/*`) or by direct npm.org (built-in `npm:{name}`).
    ///
    /// Used when a tarball download returns 404 — the cached metadata
    /// likely references an unpublished version. Deleting the cache
    /// forces a fresh fetch on the next request.
    ///
    /// **Limitation:** custom-registry metadata (served by
    /// `get_npm_metadata_from`) is keyed by
    /// `npm:<auth_fingerprint>:<full_url>` — neither the URL nor the
    /// auth is recoverable from `package_name` alone, so this method
    /// cannot invalidate those entries. Callers on the custom-registry
    /// path MUST use [`Self::invalidate_custom_metadata_cache`] instead.
    pub fn invalidate_metadata_cache(&self, package_name: &str) {
        let cache_key = if package_name.starts_with("@lpm.dev/") {
            format!("lpm:{package_name}")
        } else {
            format!("npm:{package_name}")
        };
        if let Some(path) = self.cache_path(&cache_key)
            && path.exists()
        {
            let _ = std::fs::remove_file(&path);
            tracing::debug!("invalidated metadata cache for {package_name}");
        }
    }

    /// Invalidate a cached custom-registry metadata entry.
    ///
    /// `base_url` and `auth` MUST match exactly the values that were
    /// passed to [`Self::get_npm_metadata_from`] when the entry was
    /// written; the cache key is host- and path- and auth-fingerprint-
    /// derived, so a name-only call (like
    /// [`Self::invalidate_metadata_cache`]) cannot reach these entries.
    pub fn invalidate_custom_metadata_cache(
        &self,
        base_url: &str,
        name: &str,
        auth: Option<&crate::npmrc::RegistryAuth>,
    ) {
        let url = format!("{base_url}/{name}");
        let cache_key = format!(
            "npm:{}:{url}",
            principal_fingerprint(auth, self.http.identity_fp_for_url(&url))
        );
        if let Some(path) = self.cache_path(&cache_key)
            && path.exists()
        {
            let _ = std::fs::remove_file(&path);
            tracing::debug!("invalidated custom metadata cache for {name} at {base_url}");
        }
    }

    /// Lightweight check: is there a fresh metadata cache entry for this package?
    ///
    /// Only does a `stat()` syscall — no file read, no HMAC verification,
    /// no deserialization. Used by the resolver's batch-prefetch logic to
    /// skip HTTP requests for packages already on disk from a prior batch.
    pub fn is_metadata_fresh(&self, package_name: &str) -> bool {
        let cache_key = if package_name.starts_with("@lpm.dev/") {
            format!("lpm:{package_name}")
        } else {
            format!("npm:{package_name}")
        };
        let Some(path) = self.cache_path(&cache_key) else {
            return false;
        };
        let Ok(meta) = path.metadata() else {
            return false;
        };
        let Ok(modified) = meta.modified() else {
            return false;
        };
        let Ok(age) = std::time::SystemTime::now().duration_since(modified) else {
            return false;
        };
        age < METADATA_CACHE_TTL
    }

    /// Read cached metadata if it exists, is within TTL, and starts with
    /// the expected magic header.
    ///
    /// Returns `(PackageMetadata, Option<etag>)`. The ETag (if present) can be
    /// sent as `If-None-Match` on the next request to enable 304 responses.
    ///
    /// Cache format (v3): `LPM-MD-V3\n{ETag}\n{binary_data}`
    /// - Bytes 0..MAGIC.len(): magic header (ends in `\n`)
    /// - After magic, up to next `\n`: ETag string (empty if absent)
    /// - Remainder: MessagePack-serialized PackageMetadata (with JSON fallback for migration)
    ///
    /// Old cache files written in the `HMAC\nETag\ndata` format fail the
    /// magic check and are silently treated as misses — the next fetch
    /// rewrites the entry in the new format.
    fn read_metadata_cache(&self, key: &str) -> Option<(PackageMetadata, Option<String>)> {
        self.read_metadata_cache_as(key)
    }

    /// Generic variant of [`Self::read_metadata_cache`]: deserializes the cached
    /// metadata bytes into any `T: DeserializeOwned` instead of always
    /// allocating a full [`PackageMetadata`].
    ///
    /// Callers that need only a subset of fields (e.g., the blocked-set capture
    /// path) can pass a minimal struct so serde skips allocating unneeded fields.
    ///
    /// **Streaming deserialization**: uses `BufReader<File>` + `rmp_serde::decode::from_read`
    /// instead of `fs::read` to avoid allocating a `Vec<u8>` for the full file
    /// content (~68 KB × N packages on every blocked-set capture call). Old caches
    /// in JSON or positional-array msgpack format trigger a cache miss here (returns
    /// `None`) and are rewritten in named-format msgpack on the next fetch.
    fn read_metadata_cache_as<T: serde::de::DeserializeOwned>(
        &self,
        key: &str,
    ) -> Option<(T, Option<String>)> {
        use std::io::{BufRead as _, Read as _};

        let path = self.cache_path(key)?;
        if !path.exists() {
            return None;
        }

        // Check TTL based on file modification time AND enforce a
        // hard size cap before any bytes are buffered. Same-user
        // attacker who plants a multi-GB cache file no longer gets
        // a free `Vec<u8>` allocation on every install start.
        let meta = path.metadata().ok()?;
        let modified = meta.modified().ok()?;
        let age = std::time::SystemTime::now().duration_since(modified).ok()?;
        if age > METADATA_CACHE_TTL {
            return None;
        }
        if meta.len() > METADATA_CACHE_FILE_CAP {
            tracing::warn!(
                path = %path.display(),
                size = meta.len(),
                cap = METADATA_CACHE_FILE_CAP,
                "metadata cache entry exceeds size cap — treating as miss"
            );
            return None;
        }

        // Open with a buffered reader — avoids allocating the full file into
        // a Vec<u8> before deserialization.
        let file = std::fs::File::open(&path).ok()?;
        // Bound the decoder's read window so a cache file that grows
        // between the metadata check and the open() (race with another
        // writer) still can't exceed the cap.
        let mut reader =
            std::io::BufReader::new(std::io::Read::take(file, METADATA_CACHE_FILE_CAP));

        // Validate magic prefix (METADATA_CACHE_MAGIC includes a trailing \n)
        let mut magic = [0u8; METADATA_CACHE_MAGIC.len()];
        reader.read_exact(&mut magic).ok()?;
        if magic != *METADATA_CACHE_MAGIC {
            return None;
        }

        // Read ETag line (terminated by \n; empty string means no ETag)
        let mut etag_line = String::with_capacity(64);
        reader.read_line(&mut etag_line).ok()?;
        let etag_str = etag_line.trim_end_matches('\n');
        let etag = if etag_str.is_empty() {
            None
        } else {
            Some(etag_str.to_string())
        };

        // Stream-deserialize the named-format msgpack data.
        // For old (positional-array or JSON) caches this returns Err → None,
        // triggering a cache miss and a re-fetch that rewrites in named format.
        let metadata: T = rmp_serde::decode::from_read(&mut reader).ok()?;

        Some((metadata, etag))
    }

    /// Read the ETag and raw data bytes from a cached entry without
    /// deserializing.
    ///
    /// Returns `(Option<etag>, raw_data_bytes)`. The data bytes can be
    /// deserialized by the caller on a 304 response, avoiding a second file
    /// read. Does NOT check TTL — used for conditional requests where the
    /// cache may be stale.
    fn read_cache_content(&self, key: &str) -> Option<CacheContent> {
        let path = self.cache_path(key)?;
        if !path.exists() {
            return None;
        }

        // Reject oversized cache files before any bytes hit memory.
        // Same boundary as `read_metadata_cache_as`; complements its
        // TTL-only check on the stale-conditional-request path.
        let file_size = path.metadata().ok()?.len();
        if file_size > METADATA_CACHE_FILE_CAP {
            tracing::warn!(
                path = %path.display(),
                size = file_size,
                cap = METADATA_CACHE_FILE_CAP,
                "metadata cache entry exceeds size cap — treating as miss"
            );
            return None;
        }

        let content = std::fs::read(&path).ok()?;
        let (etag_bytes, data) = parse_cached_metadata_blob(&content)?;

        let etag = std::str::from_utf8(etag_bytes)
            .ok()
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string());

        Some(CacheContent {
            etag,
            data: data.to_vec(),
        })
    }

    /// Write metadata to cache with a magic-header marker and optional ETag.
    ///
    /// Serializes to MessagePack (binary, ~40-60% smaller than JSON).
    /// Falls back to JSON if MessagePack serialization fails.
    ///
    /// Serialization runs on the calling thread (CPU-fast), but the
    /// blocking `std::fs::write` is dispatched onto tokio's
    /// `spawn_blocking` pool so it never stalls a runtime worker. Falls
    /// back to in-place sync write when no tokio runtime is available
    /// (unit tests).
    fn write_metadata_cache(&self, key: &str, metadata: &PackageMetadata, etag: Option<&str>) {
        let Some(path) = self.cache_path(key) else {
            return;
        };

        // Serialize: prefer MessagePack (map/named format so partial-struct
        // deserialization works — e.g., `BlockedSetPackageMeta` reads only
        // `time` + `versions._behavioralTags`), fall back to JSON.
        // Named format adds ~10% size vs. array format but the cache files
        // are small (≤30 KB) so the delta is negligible.
        let data = match rmp_serde::to_vec_named(metadata) {
            Ok(d) => d,
            Err(e) => {
                tracing::warn!(
                    "MessagePack serialization failed for {key}, falling back to JSON: {e}"
                );
                serde_json::to_vec(metadata).unwrap_or_default()
            }
        };
        if data.is_empty() {
            return;
        }

        let etag_str = etag.unwrap_or("");

        // Build: MAGIC ETag\ndata. The magic constant ends with `\n` so the
        // ETag line begins immediately after it.
        let mut content =
            Vec::with_capacity(METADATA_CACHE_MAGIC.len() + etag_str.len() + 1 + data.len());
        content.extend_from_slice(METADATA_CACHE_MAGIC);
        content.extend_from_slice(etag_str.as_bytes());
        content.push(b'\n');
        content.extend_from_slice(&data);

        let key_owned = key.to_string();
        // Sync path: no runtime available, OR caller explicitly opted
        // into synchronous writes (test helpers verifying cache-hit
        // behavior — see `with_synchronous_cache_writes` docs).
        let runtime_handle = tokio::runtime::Handle::try_current();
        if self.synchronous_cache_writes || runtime_handle.is_err() {
            if let Err(e) = std::fs::write(&path, &content) {
                tracing::warn!("failed to write metadata cache for {key_owned}: {e}");
            }
            return;
        }
        // Async context: dispatch the blocking write to spawn_blocking.
        // The handle is recorded on `pending_cache_writes` so tests can
        // deterministically await completion via
        // `flush_pending_cache_writes()`. Production callers ignore it.
        let handle = runtime_handle.unwrap();
        let join = handle.spawn_blocking(move || {
            if let Err(e) = std::fs::write(&path, &content) {
                tracing::warn!("failed to write metadata cache for {key_owned}: {e}");
            }
        });
        if let Ok(mut pending) = self.pending_cache_writes.lock() {
            pending.push(join);
        }
    }

    /// Drain and await every pending fire-and-forget metadata cache
    /// write spawned by this client (or any clone sharing its
    /// `pending_cache_writes` tracker).
    ///
    /// Production callers don't need this — the writes are best-effort
    /// and the handles drop with the client. Tests call this between
    /// "fetch metadata" and "expect cache hit" so they observe the
    /// post-write state deterministically. The Mutex is poisoned-tolerant
    /// (we treat poison as "no work to flush") because losing track of a
    /// pending write is strictly less bad than panicking the test runner.
    pub async fn flush_pending_cache_writes(&self) {
        let drained: Vec<_> = match self.pending_cache_writes.lock() {
            Ok(mut pending) => std::mem::take(&mut *pending),
            Err(_) => return,
        };
        for h in drained {
            // Ignore JoinError — the inner closure already logs failures
            // via `tracing::warn!`; nothing actionable on this side.
            let _ = h.await;
        }
    }

    // ─── Internal: HTTP transport with retry ────────────────────────

    /// POST JSON with auth, returning the raw response (for callers that need status/headers).
    pub async fn post_json_raw(
        &self,
        url: &str,
        body: &serde_json::Value,
    ) -> Result<reqwest::Response, LpmError> {
        let mut req = self.http.for_url(url).await?.post(url).json(body);
        if let Some(bearer) = self.current_bearer(AuthPosture::AuthRequired) {
            req = req.bearer_auth(bearer);
        }
        self.send_with_retry(req).await
    }

    /// Build a GET request with auth headers (defaults to `AuthRequired`
    /// posture). Use `build_get_with_posture` for explicit control.
    ///
    /// Async + fallible because the underlying client dispatch may
    /// lazy-build a per-origin client (and that build can fail with a
    /// cited cert error).
    async fn build_get(&self, url: &str) -> Result<reqwest::RequestBuilder, LpmError> {
        self.build_get_with_posture(url, AuthPosture::AuthRequired)
            .await
    }

    /// Build a GET request honoring the caller's auth posture.
    ///
    /// `AnonymousOnly` and `AnonymousPreferred` postures must NOT attach
    /// the bearer even when one is stored; `current_bearer` already returns
    /// `None` for those postures.
    ///
    /// Async + fallible (see [`Self::build_get`]).
    async fn build_get_with_posture(
        &self,
        url: &str,
        posture: AuthPosture,
    ) -> Result<reqwest::RequestBuilder, LpmError> {
        let mut req = self.http.for_url(url).await?.get(url);
        if let Some(bearer) = self.current_bearer(posture) {
            req = req.bearer_auth(bearer);
        }
        Ok(req)
    }

    /// Generic GET → deserialize JSON helper at a specified posture.
    /// Use for methods that should not attach the bearer
    /// (`AnonymousOnly` / `AnonymousPreferred`).
    async fn get_json_anon<T: serde::de::DeserializeOwned>(
        &self,
        url: &str,
        posture: AuthPosture,
    ) -> Result<T, LpmError> {
        debug_assert!(
            !posture.attaches_bearer(),
            "get_json_anon must only be called with anonymous postures; \
             use get_json + execute_with_recovery for AuthRequired/SessionRequired"
        );
        let response = self
            .send_with_retry(self.build_get_with_posture(url, posture).await?)
            .await?;
        parse_capped_api_json(response, &format!("response from {url}")).await
    }

    /// Resolve the bearer to attach for a given posture.
    ///
    /// - `AnonymousOnly` / `AnonymousPreferred`: returns `None` even if a
    ///   token is stored. Anonymous endpoints stay anonymous.
    /// - `AuthRequired` / `SessionRequired`: returns the live bearer from
    ///   `SessionManager` if one is attached, otherwise the legacy
    ///   `self.token` (kept for tests and callers that build the client
    ///   without a session). `SessionManager` is the source of truth —
    ///   after a silent refresh rotation, this method returns the
    ///   rotated value automatically.
    ///
    /// **Never returns `Some("")`.** Empty tokens are filtered so
    /// downstream `bearer_auth(empty)` calls cannot produce
    /// `Authorization: Bearer ` (empty value) headers.
    fn current_bearer(&self, posture: AuthPosture) -> Option<String> {
        if !posture.attaches_bearer() {
            return None;
        }
        // Use the lazy variant so keychain classification fires on the
        // first actual network request, not at process startup. Warm /
        // offline / fully-cached runs skip the ~50 ms macOS Keychain IPC
        // entirely because this method is never reached.
        if let Some(session) = &self.session
            && let Some(b) = session.current_bearer_lazy()
            && !b.is_empty()
        {
            return Some(b);
        }
        self.token
            .as_ref()
            .map(|s| s.expose_secret().to_string())
            .filter(|s| !s.is_empty())
    }

    /// Execute an HTTP-bearing operation, handling lazy refresh on 401
    /// for refresh-backed sessions.
    ///
    /// Contract:
    /// 0. **Proactive pass.** If posture allows recovery AND the
    ///    session source is refresh-eligible AND we already know the
    ///    cached state needs help (empty-secret placeholder OR local
    ///    expiry metadata says past TTL), attempt a silent refresh
    ///    BEFORE the first request. Refresh failure here is
    ///    best-effort — the request still runs and may succeed
    ///    (e.g., when the server clock skew lets the access token
    ///    work despite local metadata claiming otherwise).
    /// 1. Run `op()` once. Closure reads bearer via `current_bearer`,
    ///    which sees any rotated token from the proactive pass.
    /// 2. If it returns `LpmError::AuthRequired` AND the posture
    ///    allows recovery AND the session source is refreshable,
    ///    attempt one silent refresh (reactive pass).
    /// 3. On refresh success, run `op()` again.
    /// 4. On refresh failure, return `LpmError::SessionExpired`.
    ///
    /// Never loops. Never refreshes for explicit/env/CI/legacy/
    /// non-session sources. The fuse on `provider.rs::batch_disabled`
    /// only ever sees post-recovery 401s — transient 401s are absorbed
    /// here.
    ///
    /// **Why both proactive AND reactive?** The reactive pass alone
    /// requires the server to return 401 to trigger refresh. Mock
    /// registries and proxies that return 404/403 for "no bearer
    /// where one was needed" wouldn't trigger it, leaving the
    /// refresh-only-state recovery contract untestable end-to-end.
    /// The proactive pass closes that gap by acting on local state
    /// the client already knows (empty cache or expired metadata),
    /// matching the symmetric `bearer_string_for` contract used by
    /// non-RegistryClient callers.
    async fn execute_with_recovery<F, T, Fut>(
        &self,
        posture: AuthPosture,
        op: F,
    ) -> Result<T, LpmError>
    where
        F: Fn() -> Fut,
        Fut: std::future::Future<Output = Result<T, LpmError>>,
    {
        // Proactive pass.
        if posture.allows_recovery()
            && let Some(session) = &self.session
            && let Some(source) = session.current_source()
            && source.refresh_policy() == RefreshPolicy::IfRefreshable
        {
            // Three triggers, all "we already know the cache can't be
            // trusted":
            //   - empty-secret placeholder (refresh-only state)
            //   - local expiry metadata says past TTL
            //   - local expiry metadata file is corrupted (can't tell
            //     whether the cache is valid → ask the server)
            //
            // Fresh-login case is preserved: login.rs writes valid
            // expiry metadata on success, so the metadata-missing
            // path stays optimistic (no refresh fired).
            let needs_proactive = !session.has_token()
                || lpm_auth::is_session_access_token_expired(session.registry_url())
                || lpm_auth::session_metadata_corrupted();
            if needs_proactive {
                // Best-effort: ignore errors. The reactive pass below
                // catches a doomed refresh via the eventual 401.
                let _ = session.refresh_now().await;
            }
        }

        let first = op().await;
        match first {
            Err(LpmError::AuthRequired) if posture.allows_recovery() => {
                let Some(session) = &self.session else {
                    return Err(LpmError::AuthRequired);
                };
                let Some(source) = session.current_source() else {
                    return Err(LpmError::AuthRequired);
                };
                if source.refresh_policy() != RefreshPolicy::IfRefreshable {
                    return Err(LpmError::AuthRequired);
                }

                match session.refresh_now().await {
                    Ok(_rotated) => {
                        // Re-run; the closure re-reads `current_bearer`,
                        // which now returns the rotated value via the
                        // session cache.
                        op().await
                    }
                    Err(LpmError::SessionExpired) => Err(LpmError::SessionExpired),
                    Err(other) => Err(other),
                }
            }
            other => other,
        }
    }

    /// Generic GET → deserialize JSON helper (with auth).
    async fn get_json<T: serde::de::DeserializeOwned>(&self, url: &str) -> Result<T, LpmError> {
        let response = self.send_with_retry(self.build_get(url).await?).await?;
        parse_capped_api_json(response, &format!("response from {url}")).await
    }

    /// Send a publish request with safe retry logic (S4).
    ///
    /// Unlike `send_with_retry`, this does NOT retry on HTTP 500 because
    /// the server may have stored the version before returning an error.
    /// On 500: checks if the version already exists — if so, treats as success.
    /// Only retries on: 502, 503, 504 (gateway errors) and network failures.
    async fn send_publish_safe(
        &self,
        request_builder: reqwest::RequestBuilder,
        encoded_name: &str,
    ) -> Result<reqwest::Response, LpmError> {
        self.validate_base_url()?;

        let request = request_builder
            .build()
            .map_err(|e| LpmError::Network(format!("failed to build request: {e}")))?;

        let mut last_error = None;

        for attempt in 0..=MAX_RETRIES {
            let req = request.try_clone().ok_or_else(|| {
                LpmError::Network("request body cannot be retried (not cloneable)".into())
            })?;

            // Route via the request's URL so a per-origin client (eager
            // hit OR lazy build) handles its own TLS context. Lazy build
            // fires for transitive registry / CDN origins that surface
            // from resolved metadata after the eager set was computed.
            let client_for_req = self.http.for_url(req.url().as_str()).await?;
            match client_for_req.execute(req).await {
                Ok(response) => {
                    let status = response.status().as_u16();

                    match status {
                        200..=299 | 304 => return Ok(response),

                        // Non-retryable client errors — fail immediately
                        401 => return Err(LpmError::AuthRequired),
                        403 => {
                            let body = read_capped_error_text(response).await;
                            return Err(LpmError::Forbidden(body));
                        }
                        404 => {
                            let body = read_capped_error_text(response).await;
                            return Err(LpmError::NotFound(body));
                        }

                        // S4: 500 — do NOT retry. Server may have stored the version.
                        // Check if the version now exists on the registry.
                        500 => {
                            let body_text = read_capped_error_text(response).await;
                            tracing::warn!("publish got HTTP 500 — checking if version was stored");

                            // Check if the version exists by GETting the package
                            let check_url =
                                format!("{}/api/registry/{}", self.base_url, encoded_name);
                            // `build_get` is fallible here; on cert load
                            // failure for the recovery probe origin,
                            // we can't verify whether the publish
                            // succeeded server-side. Treat as not-OK
                            // (don't fall through to the retry-as-success
                            // branch) and let the outer loop continue.
                            let probe = match self.build_get(&check_url).await {
                                Ok(req) => self.send_with_retry(req).await,
                                Err(_) => Err(LpmError::Network(
                                    "publish recovery probe failed to build (TLS)".into(),
                                )),
                            };
                            if let Ok(check_resp) = probe
                                && check_resp.status().is_success()
                            {
                                // Version was stored despite the 500 — treat as success.
                                // Return a synthetic success response.
                                tracing::info!("version exists after 500 — treating as success");
                                return Ok(check_resp);
                            }

                            return Err(LpmError::Http {
                                status: 500,
                                message: body_text,
                            });
                        }

                        // Rate limit — respect Retry-After
                        429 => {
                            let retry_after = parse_retry_after(&response);
                            last_error = Some(LpmError::RateLimited {
                                retry_after_secs: retry_after,
                            });
                            if attempt < MAX_RETRIES {
                                // Honor the test-only backoff override so
                                // 429-flood retry-exhaustion tests don't
                                // hang on the server-supplied Retry-After.
                                let delay = backoff_override()
                                    .unwrap_or_else(|| Duration::from_secs(retry_after));
                                tokio::time::sleep(delay).await;
                                continue;
                            }
                        }

                        // Retryable gateway errors only (NOT 500)
                        502..=504 => {
                            let body = read_capped_error_text(response).await;
                            last_error = Some(LpmError::Http {
                                status,
                                message: body,
                            });
                            if attempt < MAX_RETRIES {
                                let delay = backoff_delay(attempt);
                                tokio::time::sleep(delay).await;
                                continue;
                            }
                        }

                        // Other errors — fail immediately
                        _ => {
                            let body = read_capped_error_text(response).await;
                            return Err(LpmError::Http {
                                status,
                                message: body,
                            });
                        }
                    }
                }
                Err(e) => {
                    // Network-level errors are retryable
                    last_error = Some(LpmError::Network(e.to_string()));
                    if attempt < MAX_RETRIES {
                        let delay = backoff_delay(attempt);
                        tokio::time::sleep(delay).await;
                        continue;
                    }
                }
            }
        }

        Err(last_error.unwrap_or_else(|| LpmError::Network("publish failed after retries".into())))
    }

    /// Send a request with retry logic for transient failures.
    ///
    /// Retries on: 408 (timeout), 429 (rate limit), 500, 502, 503, 504.
    /// Uses exponential backoff with jitter.
    /// Non-retryable errors (401, 403, 404, 422) fail immediately.
    async fn send_with_retry(
        &self,
        request_builder: reqwest::RequestBuilder,
    ) -> Result<reqwest::Response, LpmError> {
        // Reject insecure non-localhost HTTP before making any request
        self.validate_base_url()?;

        // Clone the request for potential retries.
        // reqwest::RequestBuilder can only be sent once, so we need to rebuild.
        // We use try_clone() on the built request.
        let request = request_builder
            .build()
            .map_err(|e| LpmError::Network(format!("failed to build request: {e}")))?;

        let mut last_error = None;

        for attempt in 0..=MAX_RETRIES {
            let req = request.try_clone().ok_or_else(|| {
                LpmError::Network("request body cannot be retried (not cloneable)".into())
            })?;

            let client_for_req = self.http.for_url(req.url().as_str()).await?;
            match client_for_req.execute(req).await {
                Ok(response) => {
                    let status = response.status().as_u16();

                    match status {
                        200..=299 | 304 => return Ok(response),

                        // Non-retryable errors — fail immediately
                        401 => return Err(LpmError::AuthRequired),
                        403 => {
                            let body = read_capped_error_text(response).await;
                            return Err(LpmError::Forbidden(body));
                        }
                        404 => {
                            let body = read_capped_error_text(response).await;
                            return Err(LpmError::NotFound(body));
                        }

                        // Retryable: rate limit
                        429 => {
                            let retry_after = parse_retry_after(&response);
                            last_error = Some(LpmError::RateLimited {
                                retry_after_secs: retry_after,
                            });
                            if attempt < MAX_RETRIES {
                                // Honor the test-only backoff override here
                                // too — see the sibling site in publish-path.
                                let delay = backoff_override()
                                    .unwrap_or_else(|| Duration::from_secs(retry_after));
                                tokio::time::sleep(delay).await;
                                continue;
                            }
                        }

                        // Retryable: server errors and timeouts
                        408 | 500 | 502 | 503 | 504 => {
                            let body = read_capped_error_text(response).await;
                            last_error = Some(LpmError::Http {
                                status,
                                message: body,
                            });
                            if attempt < MAX_RETRIES {
                                let delay = backoff_delay(attempt);
                                tokio::time::sleep(delay).await;
                                continue;
                            }
                        }

                        // Other errors — fail immediately
                        _ => {
                            let body = read_capped_error_text(response).await;
                            return Err(LpmError::Http {
                                status,
                                message: body,
                            });
                        }
                    }
                }
                Err(e) => {
                    // Network-level errors (DNS, connection refused, timeout) are retryable
                    last_error = Some(LpmError::Network(e.to_string()));
                    if attempt < MAX_RETRIES {
                        let delay = backoff_delay(attempt);
                        tokio::time::sleep(delay).await;
                        continue;
                    }
                }
            }
        }

        Err(last_error.unwrap_or_else(|| LpmError::Network("request failed after retries".into())))
    }
}

impl Default for RegistryClient {
    fn default() -> Self {
        Self::new()
    }
}

/// Check if a URL points to a localhost address.
///
/// Used by `evaluate_cached_url` and tarball download guards to compose
/// URL-safety checks.
pub fn is_localhost_url(url: &str) -> bool {
    let Ok(parsed) = reqwest::Url::parse(url) else {
        return false;
    };

    if parsed.scheme() != "http" {
        return false;
    }

    let Some(host) = parsed.host_str() else {
        return false;
    };

    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }

    let normalized_host = host.trim_start_matches('[').trim_end_matches(']');
    normalized_host
        .parse::<std::net::IpAddr>()
        .map(is_loopback_ip)
        .unwrap_or(false)
}

/// Loopback check that handles both native loopback (`127.0.0.0/8`,
/// `::1`) and the IPv4-mapped IPv6 shape (`::ffff:127.0.0.1`).
/// Rust's `IpAddr::is_loopback` only flags the native forms, so an
/// `http://[::ffff:127.0.0.1]/foo` URL would otherwise sneak past
/// the localhost gate and through HTTPS-required code paths.
fn is_loopback_ip(addr: std::net::IpAddr) -> bool {
    match addr {
        std::net::IpAddr::V4(v4) => v4.is_loopback(),
        std::net::IpAddr::V6(v6) => {
            v6.is_loopback() || v6.to_ipv4_mapped().is_some_and(|v4| v4.is_loopback())
        }
    }
}

/// Check if a URL uses the HTTPS scheme.
pub fn is_https_url(url: &str) -> bool {
    reqwest::Url::parse(url)
        .map(|parsed| parsed.scheme() == "https")
        .unwrap_or(false)
}

/// Pre-validate a PEM root before handing it to
/// `reqwest::Certificate::from_pem`. Reqwest's rustls-tls `from_pem` is
/// permissive (stores raw bytes; cryptographic validation happens at
/// `.build()` time), and a `.build()` failure can't tell us WHICH root
/// caused it. This function fails fast on the common shape mistakes —
/// non-UTF-8 bytes, missing markers, empty or non-base64 body — and
/// cites the contributing source/line so the user can find the
/// offending `.npmrc` line.
///
/// **Multi-block bundles:** every `BEGIN..END` pair in the buffer is
/// validated. Common shape: a corporate cafile with `[root, intermediate]`
/// concatenated. If block 2 is malformed, we fail at validation rather
/// than letting the build-time error swallow the source context.
///
/// Returning `Ok(())` does NOT guarantee the certs are cryptographically
/// valid (that's still a `.build()`-time concern). It only guarantees
/// "every block is shaped like a PEM cert with a non-empty base64 body."
///
/// Pairs with [`contains_pem_certificate_block`] in `npmrc.rs`, which
/// performs the cheaper "any BEGIN marker present" parser-time check at
/// config-load.
fn validate_pem_root(pem_bytes: &[u8], source: &str, line: usize) -> Result<(), LpmError> {
    use base64::Engine as _;
    let text = std::str::from_utf8(pem_bytes).map_err(|e| {
        LpmError::Cert(format!(
            "npmrc cafile/ca at {source}:{line}: PEM is not valid UTF-8: {e}"
        ))
    })?;
    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    const END: &str = "-----END CERTIFICATE-----";
    if !text.contains(BEGIN) {
        return Err(LpmError::Cert(format!(
            "npmrc cafile/ca at {source}:{line}: no '{BEGIN}' marker"
        )));
    }
    let mut cursor = text;
    let mut block_no: usize = 0;
    while let Some(begin_off) = cursor.find(BEGIN) {
        block_no += 1;
        let after_begin = &cursor[begin_off + BEGIN.len()..];
        let end_off = after_begin.find(END).ok_or_else(|| {
            LpmError::Cert(format!(
                "npmrc cafile/ca at {source}:{line} block #{block_no}: no '{END}' marker"
            ))
        })?;
        let body: String = after_begin[..end_off]
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect();
        if body.is_empty() {
            return Err(LpmError::Cert(format!(
                "npmrc cafile/ca at {source}:{line} block #{block_no}: empty certificate body"
            )));
        }
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(&body)
            .map_err(|e| {
                LpmError::Cert(format!(
                    "npmrc cafile/ca at {source}:{line} block #{block_no}: certificate body is not valid base64: {e}"
                ))
            })?;
        if decoded.is_empty() {
            return Err(LpmError::Cert(format!(
                "npmrc cafile/ca at {source}:{line} block #{block_no}: certificate body decodes to zero bytes"
            )));
        }
        cursor = &after_begin[end_off + END.len()..];
    }
    Ok(())
}

/// Check if a URL uses the HTTP scheme.
///
/// Paired with [`is_https_url`] and [`is_localhost_url`] so the
/// `--insecure` carve-out can specifically widen the scheme gate
/// to plain HTTP — not to `file://`, `ftp://`, `data:`, or any
/// other non-HTTPS scheme. See
/// [`RegistryClient::check_tarball_url_scheme`] for the enforcement site.
pub fn is_http_url(url: &str) -> bool {
    reqwest::Url::parse(url)
        .map(|parsed| parsed.scheme() == "http")
        .unwrap_or(false)
}

/// Outcome of [`evaluate_cached_url`] — gate on lockfile-stored tarball
/// URLs before they're dispatched to the fetch pipeline. A dedicated
/// variant per rejection reason so callers can emit targeted telemetry
/// (`tarball_url_origin_mismatch_count` vs `_shape_mismatch_count`)
/// without re-running the checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateDecision {
    /// URL passes scheme + shape + origin; safe to reuse.
    Accepted,
    /// Neither HTTPS nor `http://localhost`. The writer should
    /// never emit a scheme-rejected URL, so a non-zero counter
    /// here signals a corrupt lockfile.
    RejectedScheme,
    /// Path doesn't match a canonical tarball shape (`/-/` segment
    /// AND `.tgz` suffix). Blocks the H1 auth-token leak: a
    /// tampered lockfile pointing at `/api/admin/foo.tgz` would
    /// otherwise attach the bearer to a non-registry endpoint.
    /// Non-zero counter = BUG signal — investigate the writer.
    RejectedShape,
    /// URL's origin is not in the set this client is configured
    /// to talk to (`{base_url, npm_registry_url}`). Expected to
    /// be non-zero after `LPM_REGISTRY_URL` switches: stored
    /// `@lpm.dev/*` URLs mismatch the new origin → fall through
    /// to on-demand lookup against the mirror.
    RejectedOrigin,
}

/// Gate a lockfile-stored tarball URL before reusing it on the fetch
/// path. Combines scheme, shape, and origin checks with a distinct
/// `GateDecision` per rejection reason so callers can bump the right
/// telemetry counter.
///
/// The shape check requires both `.tgz` suffix AND a `/-/` path segment.
/// Both LPM (`/api/registry/{scope}/{pkg}/-/...`) and npm (`/{pkg}/-/...`)
/// emit URLs in this shape; attacker-crafted `.tgz`-suffixed admin paths
/// like `/api/admin/foo.tgz` lack the `/-/` segment and are rejected
/// before the bearer is attached.
pub fn evaluate_cached_url(url: &str, client: &RegistryClient) -> GateDecision {
    // Scheme — mirrors `RegistryClient::check_tarball_url_scheme` so
    // the lockfile-read gate stays symmetric with the tarball-download
    // guards. `--insecure` specifically widens the carve-out to HTTP,
    // never to `file://`, `ftp://`, `data:`, etc.
    let scheme_ok =
        is_https_url(url) || is_localhost_url(url) || (client.allow_insecure() && is_http_url(url));
    if !scheme_ok {
        return GateDecision::RejectedScheme;
    }

    // Shape — `/-/` segment AND `.tgz` suffix. First-draft used
    // suffix-only which a 3rd-pass audit proved bypassable by
    // crafting `/api/admin/foo.tgz`; the `/-/` segment is only
    // ever emitted by the registry tarball route.
    let Ok(parsed) = reqwest::Url::parse(url) else {
        return GateDecision::RejectedShape;
    };
    let path = parsed.path();
    if !path.ends_with(".tgz") || !path.contains("/-/") {
        return GateDecision::RejectedShape;
    }

    // Origin — must match one of the origins this client talks to.
    // After `LPM_REGISTRY_URL` is switched to a mirror, stored
    // `@lpm.dev/*` URLs naturally mismatch and fall through to
    // on-demand lookup against the new origin. The writeback trigger
    // picks up the fresh URLs and rewrites the lockfile so the second
    // install short-circuits.
    if !client.is_configured_origin(url) {
        return GateDecision::RejectedOrigin;
    }

    GateDecision::Accepted
}

/// Parse `Retry-After` header from a 429 response.
/// Returns seconds to wait. Falls back to 1 second if header is missing/unparseable.
fn parse_retry_after(response: &reqwest::Response) -> u64 {
    response
        .headers()
        .get("retry-after")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(1)
}

fn write_tarball_chunk(writer: &mut impl std::io::Write, chunk: &[u8]) -> Result<(), LpmError> {
    writer.write_all(chunk).map_err(|e| {
        LpmError::Io(std::io::Error::new(
            e.kind(),
            format!("failed to write tarball chunk to temp file: {e}"),
        ))
    })
}

fn flush_tarball_file(writer: &mut impl std::io::Write) -> Result<(), LpmError> {
    writer.flush().map_err(|e| {
        LpmError::Io(std::io::Error::new(
            e.kind(),
            format!("failed to flush tarball temp file: {e}"),
        ))
    })
}

/// Exponential backoff with capped delay.
/// attempt 0 → 1s, attempt 1 → 2s, attempt 2 → 4s, capped at 10s.
///
/// **Test-only override** ([`backoff_override`]): when
/// `LPM_RETRY_BACKOFF_MS_OVERRIDE` is set AND we're in a debug build OR
/// `LPM_TEST_MODE=1` is set, the override value (in ms) is returned
/// instead of the exponential schedule. Production retry policy is
/// immune — the env is silently ignored under release builds without
/// the explicit `LPM_TEST_MODE=1` opt-in.
fn backoff_delay(attempt: u32) -> Duration {
    if let Some(d) = backoff_override() {
        return d;
    }
    let delay = RETRY_BASE_DELAY * 2u32.pow(attempt);
    delay.min(RETRY_MAX_DELAY)
}

/// Test-only retry-backoff override knob.
///
/// Returns `Some(Duration::from_millis(N))` when ALL three conditions
/// hold:
///
/// 1. `LPM_RETRY_BACKOFF_MS_OVERRIDE` env var is set to a parseable u64.
/// 2. The build is `debug_assertions` (i.e., `cargo build` /
///    `cargo test` / `cargo nextest`) OR `LPM_TEST_MODE=1`.
/// 3. The parsed value fits a `Duration::from_millis(...)` (always
///    true for u64).
///
/// Returns `None` otherwise — production retry policy untouched.
///
/// Used by retry-exhaustion tests to shrink the default 1+2+4+8s
/// schedule into ~10ms so the test fits in the suite's <5s determinism
/// budget.
///
/// Also consulted by the 429 `Retry-After` sleep — without that, a
/// 429-flood test would still hang on the server-supplied
/// `Retry-After` header.
fn backoff_override() -> Option<Duration> {
    let allowed = cfg!(debug_assertions)
        || std::env::var("LPM_TEST_MODE")
            .ok()
            .as_deref()
            .map(|v| v == "1")
            .unwrap_or(false);
    if !allowed {
        return None;
    }
    std::env::var("LPM_RETRY_BACKOFF_MS_OVERRIDE")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .map(Duration::from_millis)
}

/// Parse a cached metadata blob.
///
/// Validates the magic header, then locates the ETag line terminator and
/// returns `(etag_bytes, payload_bytes)` borrowed from the input. Returns
/// `None` on any shape mismatch (wrong magic, missing ETag terminator,
/// truncated payload). Old-format cache entries fail the magic check here
/// and are silently re-fetched.
fn parse_cached_metadata_blob(content: &[u8]) -> Option<(&[u8], &[u8])> {
    if content.len() < METADATA_CACHE_MAGIC.len() {
        return None;
    }
    if !content.starts_with(METADATA_CACHE_MAGIC) {
        return None;
    }
    let after_magic = &content[METADATA_CACHE_MAGIC.len()..];
    let nl_offset = after_magic.iter().position(|&b| b == b'\n')?;
    Some((&after_magic[..nl_offset], &after_magic[nl_offset + 1..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_delay_exponential() {
        assert_eq!(backoff_delay(0), Duration::from_secs(1));
        assert_eq!(backoff_delay(1), Duration::from_secs(2));
        assert_eq!(backoff_delay(2), Duration::from_secs(4));
    }

    #[test]
    fn backoff_delay_capped() {
        assert_eq!(backoff_delay(5), RETRY_MAX_DELAY);
        assert_eq!(backoff_delay(10), RETRY_MAX_DELAY);
    }

    #[tokio::test]
    async fn download_tarball_allows_https() {
        // We can't actually download, but we can verify HTTPS URLs pass validation.
        // The request will fail at the network level, not at URL validation.
        let client = RegistryClient::new();
        let result = client
            .download_tarball("https://registry.npmjs.org/express/-/express-4.22.1.tgz")
            .await;
        // Should NOT be a "must use HTTPS" error — it may fail for other reasons (network)
        if let Err(ref e) = result {
            let msg = e.to_string();
            assert!(
                !msg.contains("tarball URL must use HTTPS"),
                "HTTPS URL should be accepted"
            );
        }
    }

    #[tokio::test]
    async fn download_tarball_rejects_http_without_insecure() {
        let client = RegistryClient::new();
        let result = client.download_tarball("http://evil.com/malware.tgz").await;
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("tarball URL must use HTTPS"),
            "HTTP URL should be rejected: {msg}"
        );
        assert!(
            msg.contains("--insecure"),
            "error should hint at --insecure flag: {msg}"
        );
    }

    #[tokio::test]
    async fn download_tarball_rejects_file_scheme() {
        let client = RegistryClient::new();
        let result = client.download_tarball("file:///etc/passwd").await;
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("tarball URL must use HTTPS"),
            "file:// URL should be rejected: {msg}"
        );
    }

    #[tokio::test]
    async fn download_tarball_allows_localhost() {
        let client = RegistryClient::new();
        let result = client
            .download_tarball("http://localhost:3000/pkg.tgz")
            .await;
        // Should NOT be a "must use HTTPS" error
        if let Err(ref e) = result {
            let msg = e.to_string();
            assert!(
                !msg.contains("tarball URL must use HTTPS"),
                "localhost URL should be accepted: {msg}"
            );
        }
    }

    #[tokio::test]
    async fn download_tarball_allows_loopback_ipv4() {
        let client = RegistryClient::new();
        let result = client
            .download_tarball("http://127.0.0.1:3000/pkg.tgz")
            .await;
        if let Err(ref e) = result {
            let msg = e.to_string();
            assert!(
                !msg.contains("tarball URL must use HTTPS"),
                "127.0.0.1 URL should be accepted: {msg}"
            );
        }
    }

    #[tokio::test]
    async fn download_tarball_allows_loopback_ipv6() {
        let client = RegistryClient::new();
        let result = client.download_tarball("http://[::1]:3000/pkg.tgz").await;
        if let Err(ref e) = result {
            let msg = e.to_string();
            assert!(
                !msg.contains("tarball URL must use HTTPS"),
                "[::1] URL should be accepted: {msg}"
            );
        }
    }

    // ── download_tarball_with_integrity ───────────────────────────────────────
    // Wiremock binds to 127.0.0.1 (a loopback host), so the existing
    // tarball scheme guard accepts plain `http://` per
    // download_tarball_allows_loopback_ipv4.

    #[tokio::test]
    async fn download_tarball_with_integrity_trust_on_first_use() {
        use lpm_common::integrity::{HashAlgorithm, Integrity};
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let body = b"hello tarball content for trust-on-first-use";

        Mock::given(method("GET"))
            .and(path("/foo.tgz"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(body.to_vec()))
            .mount(&server)
            .await;

        let client = RegistryClient::new();
        let url = format!("{}/foo.tgz", server.uri());
        let (data, sri) = client
            .download_tarball_with_integrity(&url, None)
            .await
            .expect("trust-on-first-use must succeed");

        assert_eq!(data.as_slice(), body);
        // The returned SRI is canonical sha512 form computed from
        // the bytes — assert against an independent computation so
        // a regression in the streaming hasher would surface here.
        let expected = Integrity::from_bytes(HashAlgorithm::Sha512, body).to_string();
        assert_eq!(sri, expected);
    }

    #[tokio::test]
    async fn download_tarball_with_integrity_match_succeeds() {
        use lpm_common::integrity::{HashAlgorithm, Integrity};
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let body = b"matching-integrity content";
        let expected_sri = Integrity::from_bytes(HashAlgorithm::Sha512, body).to_string();

        Mock::given(method("GET"))
            .and(path("/foo.tgz"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(body.to_vec()))
            .mount(&server)
            .await;

        let client = RegistryClient::new();
        let url = format!("{}/foo.tgz", server.uri());
        let (data, sri) = client
            .download_tarball_with_integrity(&url, Some(&expected_sri))
            .await
            .expect("matching SRI must succeed");

        assert_eq!(data.as_slice(), body);
        assert_eq!(sri, expected_sri);
    }

    // ── algorithm-aware SRI verification ─────────────────────────────────────
    // String equality on the SRI breaks when the declared algorithm differs
    // from the streaming hasher's algorithm. The verifier re-hashes with the
    // declared algorithm before comparing raw bytes.

    #[tokio::test]
    async fn download_tarball_with_integrity_sha256_match_succeeds() {
        use lpm_common::integrity::{HashAlgorithm, Integrity};
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let body = b"sha256-declared content";
        let expected_sri = Integrity::from_bytes(HashAlgorithm::Sha256, body).to_string();
        assert!(
            expected_sri.starts_with("sha256-"),
            "test fixture must declare sha256: {expected_sri}"
        );

        Mock::given(method("GET"))
            .and(path("/foo.tgz"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(body.to_vec()))
            .mount(&server)
            .await;

        let client = RegistryClient::new();
        let url = format!("{}/foo.tgz", server.uri());
        let (data, sri) = client
            .download_tarball_with_integrity(&url, Some(&expected_sri))
            .await
            .expect("sha256 match must succeed");

        assert_eq!(data.as_slice(), body);
        // Returned SRI is in the algorithm the caller declared.
        assert_eq!(sri, expected_sri);
        assert!(sri.starts_with("sha256-"));
    }

    #[tokio::test]
    async fn download_tarball_with_integrity_sha256_mismatch_returns_sha256_actual() {
        use lpm_common::integrity::{HashAlgorithm, Integrity};
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let body = b"actual content not matching declared hash";
        // Valid sha256 SRI of *different* content — the algo-aware
        // verifier parses, recomputes with sha256, and surfaces
        // mismatch with `actual` in the same algorithm.
        let wrong_sha256 =
            Integrity::from_bytes(HashAlgorithm::Sha256, b"wrong content bytes").to_string();

        Mock::given(method("GET"))
            .and(path("/foo.tgz"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(body.to_vec()))
            .mount(&server)
            .await;

        let client = RegistryClient::new();
        let url = format!("{}/foo.tgz", server.uri());
        let result = client
            .download_tarball_with_integrity(&url, Some(&wrong_sha256))
            .await;

        match result {
            Err(LpmError::IntegrityMismatch { expected, actual }) => {
                assert_eq!(expected, wrong_sha256);
                // Diagnostic surfaces the actual in the SAME algorithm
                // the user declared — they can compare bytes-vs-bytes
                // without recomputing.
                assert!(
                    actual.starts_with("sha256-"),
                    "actual must be in declared algorithm for direct comparison: {actual}"
                );
                assert_ne!(actual, wrong_sha256);
            }
            other => panic!("expected IntegrityMismatch, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn download_tarball_with_integrity_mismatch_returns_error() {
        use lpm_common::integrity::{HashAlgorithm, Integrity};
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let body = b"some content";
        // The algo-aware path parses the expected SRI before comparing,
        // so use a valid sha512 SRI of *different* bytes — the realistic
        // threat model (lockfile/manifest drifted, content changed).
        let wrong_sri = Integrity::from_bytes(
            HashAlgorithm::Sha512,
            b"different content bytes; declared hash will not match",
        )
        .to_string();

        Mock::given(method("GET"))
            .and(path("/foo.tgz"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(body.to_vec()))
            .mount(&server)
            .await;

        let client = RegistryClient::new();
        let url = format!("{}/foo.tgz", server.uri());
        let result = client
            .download_tarball_with_integrity(&url, Some(&wrong_sri))
            .await;

        match result {
            Err(LpmError::IntegrityMismatch { expected, actual }) => {
                assert_eq!(expected, wrong_sri);
                assert!(
                    actual.starts_with("sha512-"),
                    "actual SRI must surface so users can update their lockfile: {actual:?}"
                );
                assert_ne!(actual, wrong_sri);
            }
            other => panic!("expected IntegrityMismatch, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn download_tarball_with_integrity_inherits_scheme_guard() {
        // Reusing download_tarball_with_hash → download_tarball_to_file
        // means the scheme guard fires for non-loopback http://.
        // This locks that inheritance — a regression that bypassed
        // the guard would let a tarball dep fetch from
        // `http://evil.com/...` silently.
        let client = RegistryClient::new();
        let result = client
            .download_tarball_with_integrity("http://evil.example.com/x.tgz", None)
            .await;
        match result {
            Err(LpmError::Registry(msg)) => {
                assert!(
                    msg.contains("tarball URL must use HTTPS"),
                    "scheme guard should reject non-loopback http: {msg}"
                );
            }
            // Some build envs map the scheme guard through other
            // error variants — accept any Err that mentions HTTPS.
            Err(other) => {
                let msg = other.to_string();
                assert!(
                    msg.contains("HTTPS") || msg.contains("https"),
                    "expected scheme-guard error mentioning HTTPS, got {msg}"
                );
            }
            Ok(_) => panic!("non-loopback http:// must be rejected"),
        }
    }

    // ─── Metadata Cache Tests ──────────────────────────────────────

    /// Helper: create a RegistryClient with a temporary cache directory.
    fn client_with_temp_cache() -> (RegistryClient, tempfile::TempDir) {
        let tmp = tempfile::tempdir().expect("failed to create temp dir");
        let mut client = RegistryClient::new();
        client.cache_dir = Some(tmp.path().to_path_buf());
        (client, tmp)
    }

    /// Helper: build a minimal PackageMetadata for testing.
    fn test_metadata(name: &str) -> PackageMetadata {
        PackageMetadata {
            name: name.to_string(),
            description: Some("test package".to_string()),
            dist_tags: {
                let mut m = std::collections::HashMap::new();
                m.insert("latest".to_string(), "1.0.0".to_string());
                m
            },
            versions: std::collections::HashMap::new(),
            time: std::collections::HashMap::new(),
            downloads: Some(42),
            distribution_mode: None,
            package_type: None,
            latest_version: Some("1.0.0".to_string()),
            ecosystem: None,
        }
    }

    #[test]
    fn cache_roundtrip_with_etag() {
        let (client, _tmp) = client_with_temp_cache();
        let meta = test_metadata("@lpm.dev/test.pkg");
        let etag = "\"abc123\"";

        client.write_metadata_cache("test-key", &meta, Some(etag));
        let result = client.read_metadata_cache("test-key");

        assert!(result.is_some(), "cache read should succeed");
        let (read_meta, read_etag) = result.unwrap();
        assert_eq!(read_meta.name, "@lpm.dev/test.pkg");
        assert_eq!(read_etag.as_deref(), Some("\"abc123\""));
    }

    #[test]
    fn cache_roundtrip_without_etag() {
        let (client, _tmp) = client_with_temp_cache();
        let meta = test_metadata("@lpm.dev/test.no-etag");

        client.write_metadata_cache("no-etag-key", &meta, None);
        let result = client.read_metadata_cache("no-etag-key");

        assert!(result.is_some(), "cache read should succeed without etag");
        let (read_meta, read_etag) = result.unwrap();
        assert_eq!(read_meta.name, "@lpm.dev/test.no-etag");
        assert!(read_etag.is_none(), "etag should be None when not stored");
    }

    #[test]
    fn cache_survives_new_client_process_boundary() {
        let (writer, _tmp) = client_with_temp_cache();
        let meta = test_metadata("@lpm.dev/test.restart");

        writer.write_metadata_cache("restart-key", &meta, Some("\"restart-etag\""));

        let mut reader = RegistryClient::new();
        reader.cache_dir = writer.cache_dir.clone();

        let result = reader.read_metadata_cache("restart-key");

        assert!(
            result.is_some(),
            "cache entries should remain readable across fresh client instances"
        );
        let (read_meta, read_etag) = result.unwrap();
        assert_eq!(read_meta.name, "@lpm.dev/test.restart");
        assert_eq!(read_etag.as_deref(), Some("\"restart-etag\""));
    }

    /// Pre-magic-header caches were written in `HMAC\nETag\ndata` shape.
    /// After dropping HMAC the reader expects the `LPM-MD-V2\n` magic header
    /// instead, so any leftover old-format entry on disk fails the magic check
    /// and is treated as a cache miss (forcing a fresh fetch that rewrites the
    /// entry in the new format). This test pins that behavior.
    #[test]
    fn old_format_cache_treated_as_miss() {
        let (client, _tmp) = client_with_temp_cache();

        // Synthesize an old-format entry: 64-char hex HMAC line + JSON
        // payload. The exact HMAC bytes don't matter — the new reader
        // never reaches HMAC verification because the magic check at the
        // top fails first.
        if let Some(path) = client.cache_path("old-format-key") {
            let json_data = r#"{"name":"old","versions":{}}"#;
            let fake_hmac = "0".repeat(64);
            let old_content = format!("{fake_hmac}\n{json_data}");
            std::fs::write(&path, old_content).unwrap();
        }

        let result = client.read_metadata_cache("old-format-key");
        assert!(
            result.is_none(),
            "old HMAC-format cache must be treated as a miss after the magic-header switch"
        );
    }

    /// Corrupt cache (bytes tampered, no valid magic). We no longer detect
    /// arbitrary content tampering, but we DO reject anything that doesn't
    /// begin with the magic header.
    #[test]
    fn cache_miss_on_truncated_or_unmagic_content() {
        let (client, _tmp) = client_with_temp_cache();
        if let Some(path) = client.cache_path("garbage-key") {
            std::fs::write(&path, b"not-a-real-cache-file").unwrap();
        }
        assert!(
            client.read_metadata_cache("garbage-key").is_none(),
            "non-magic content must be rejected"
        );

        // Truncated magic — header started but never finished.
        if let Some(path) = client.cache_path("trunc-key") {
            std::fs::write(&path, b"LPM-MD").unwrap();
        }
        assert!(
            client.read_metadata_cache("trunc-key").is_none(),
            "truncated magic must be rejected"
        );
    }

    #[test]
    fn read_cache_content_returns_etag_and_data() {
        let (client, _tmp) = client_with_temp_cache();
        let meta = test_metadata("@lpm.dev/test.etag-read");

        client.write_metadata_cache("etag-read-key", &meta, Some("W/\"xyz789\""));
        let content = client.read_cache_content("etag-read-key");
        assert!(content.is_some(), "cache content should be present");
        let content = content.unwrap();
        assert_eq!(content.etag.as_deref(), Some("W/\"xyz789\""));
        // Verify the data can be deserialized
        let deserialized: PackageMetadata = rmp_serde::from_slice(&content.data)
            .or_else(|_| serde_json::from_slice(&content.data))
            .expect("data should deserialize");
        assert_eq!(deserialized.name, "@lpm.dev/test.etag-read");
    }

    #[test]
    fn read_cache_content_returns_none_etag_when_no_etag() {
        let (client, _tmp) = client_with_temp_cache();
        let meta = test_metadata("@lpm.dev/test.no-etag-read");

        client.write_metadata_cache("no-etag-read-key", &meta, None);
        let content = client.read_cache_content("no-etag-read-key");
        assert!(
            content.is_some(),
            "cache content should be present even without etag"
        );
        assert!(content.unwrap().etag.is_none());
    }

    // `cache_miss_on_tampered_data` was removed when HMAC was dropped. We no
    // longer detect arbitrary payload tampering; we only reject content that
    // lacks the magic header. The `cache_miss_on_truncated_or_unmagic_content`
    // test above pins the remaining contract.

    #[test]
    fn cache_miss_on_nonexistent_key() {
        let (client, _tmp) = client_with_temp_cache();
        let result = client.read_metadata_cache("nonexistent-key");
        assert!(result.is_none());
    }

    #[test]
    fn messagepack_roundtrip_preserves_all_fields() {
        let (client, _tmp) = client_with_temp_cache();
        let mut meta = test_metadata("@lpm.dev/test.fields");
        meta.description = Some("A test package with fields".to_string());
        meta.downloads = Some(9999);
        meta.distribution_mode = Some("pool".to_string());
        meta.ecosystem = Some("node".to_string());

        client.write_metadata_cache("fields-key", &meta, Some("\"v1\""));
        let (read_meta, _) = client.read_metadata_cache("fields-key").unwrap();

        assert_eq!(read_meta.name, meta.name);
        assert_eq!(read_meta.description, meta.description);
        assert_eq!(read_meta.downloads, meta.downloads);
        assert_eq!(read_meta.distribution_mode, meta.distribution_mode);
        assert_eq!(read_meta.ecosystem, meta.ecosystem);
        assert_eq!(
            read_meta.dist_tags.get("latest"),
            Some(&"1.0.0".to_string())
        );
    }

    // Integration tests — require network. Run with: cargo test -p lpm-registry -- --ignored

    #[tokio::test]
    #[ignore = "requires network — run with --ignored"]
    async fn health_check_succeeds() {
        let client = RegistryClient::new();
        let healthy = client.health_check().await.unwrap();
        assert!(healthy);
    }

    #[tokio::test]
    #[ignore = "requires network + auth — run with --ignored"]
    async fn fetch_package_metadata() {
        let token = std::env::var("LPM_TOKEN").expect("LPM_TOKEN env var required");
        let client = RegistryClient::new().with_token(token);
        let name = PackageName::parse("@lpm.dev/tolgaergin.blocks").unwrap();
        let metadata = client.get_package_metadata(&name).await.unwrap();

        assert_eq!(metadata.name, "@lpm.dev/tolgaergin.blocks");
        assert!(metadata.latest_version_tag().is_some());
        assert!(!metadata.versions.is_empty());
    }

    #[tokio::test]
    #[ignore = "requires network — run with --ignored"]
    async fn nonexistent_package_returns_error() {
        let client = RegistryClient::new();
        let name =
            PackageName::parse("@lpm.dev/nonexistent-user.nonexistent-package-12345").unwrap();
        let result = client.get_package_metadata(&name).await;
        assert!(result.is_err());
    }

    // ─── Base URL Validation Tests ─────────────────────────────────

    #[test]
    fn validate_base_url_rejects_http_non_localhost() {
        let client = RegistryClient::new().with_base_url("http://evil.com");
        let result = client.validate_base_url();
        assert!(result.is_err(), "HTTP non-localhost should be rejected");
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("insecure"),
            "error should mention insecure: {msg}"
        );
    }

    #[test]
    fn validate_base_url_allows_http_localhost() {
        let client = RegistryClient::new().with_base_url("http://localhost:3000");
        assert!(
            client.validate_base_url().is_ok(),
            "HTTP localhost should be allowed"
        );
    }

    #[test]
    fn validate_base_url_allows_http_127() {
        let client = RegistryClient::new().with_base_url("http://127.0.0.1:3000");
        assert!(
            client.validate_base_url().is_ok(),
            "HTTP 127.0.0.1 should be allowed"
        );
    }

    #[test]
    fn validate_base_url_allows_http_ipv6_loopback() {
        let client = RegistryClient::new().with_base_url("http://[::1]:3000");
        assert!(
            client.validate_base_url().is_ok(),
            "HTTP [::1] should be allowed"
        );
    }

    #[test]
    fn validate_base_url_rejects_localhost_prefix_attack_domain() {
        let client = RegistryClient::new().with_base_url("http://localhost.evil.com:3000");
        let result = client.validate_base_url();
        assert!(
            result.is_err(),
            "attacker-controlled localhost prefix domain should be rejected"
        );
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("insecure"),
            "error should mention insecure transport: {msg}"
        );
    }

    #[test]
    fn validate_base_url_allows_https() {
        let client = RegistryClient::new().with_base_url("https://lpm.dev");
        assert!(
            client.validate_base_url().is_ok(),
            "HTTPS should always be allowed"
        );
    }

    #[test]
    fn validate_base_url_allows_insecure_override() {
        let client = RegistryClient::new()
            .with_base_url("http://evil.com")
            .with_insecure(true);
        assert!(
            client.validate_base_url().is_ok(),
            "HTTP non-localhost with --insecure should be allowed"
        );
    }

    #[test]
    fn validate_base_url_rejects_file_scheme_even_with_insecure() {
        // `--insecure` is narrow: it widens to HTTP only, never to
        // `file://`. A `file://` base URL with the flag set must still
        // be rejected — otherwise a misconfigured tool could read
        // arbitrary local paths as if they were a registry.
        let client = RegistryClient::new()
            .with_base_url("file:///etc/passwd")
            .with_insecure(true);
        let result = client.validate_base_url();
        assert!(
            result.is_err(),
            "file:// must be rejected even with --insecure"
        );
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("insecure"),
            "error should mention insecure transport: {msg}"
        );
    }

    #[test]
    fn validate_base_url_rejects_non_http_schemes_even_with_insecure() {
        // Parity with the tarball-path gate: only HTTPS, localhost HTTP,
        // and (with --insecure) HTTP everywhere are valid. `ftp://`,
        // `data:`, `javascript:` etc. stay rejected regardless.
        for url in [
            "ftp://mirror.example.com/",
            "data:text/plain,hello",
            "javascript:alert(1)",
        ] {
            let client = RegistryClient::new().with_base_url(url).with_insecure(true);
            assert!(
                client.validate_base_url().is_err(),
                "{url} must be rejected even with --insecure"
            );
        }
    }

    // ── check_tarball_url_scheme — hermetic unit tests for the
    //    shared scheme guard used by all three tarball download
    //    methods. Testing the helper directly keeps the tests
    //    fast and network-free; the method-level integration
    //    tests below exercise delegation (reject path short-
    //    circuits before any network call).
    #[test]
    fn check_tarball_url_scheme_allows_https() {
        let client = RegistryClient::new();
        assert!(
            client
                .check_tarball_url_scheme("https://lpm.dev/pkg/-/pkg-1.0.0.tgz")
                .is_ok()
        );
    }

    #[test]
    fn check_tarball_url_scheme_allows_localhost_http() {
        let client = RegistryClient::new();
        for url in [
            "http://localhost:3000/pkg/-/pkg-1.0.0.tgz",
            "http://127.0.0.1:3000/pkg/-/pkg-1.0.0.tgz",
            "http://[::1]:3000/pkg/-/pkg-1.0.0.tgz",
        ] {
            assert!(
                client.check_tarball_url_scheme(url).is_ok(),
                "loopback HTTP should always be allowed: {url}"
            );
        }
    }

    #[test]
    fn check_tarball_url_scheme_rejects_http_non_localhost_without_insecure() {
        let client = RegistryClient::new();
        let result = client.check_tarball_url_scheme("http://evil.com/pkg.tgz");
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("tarball URL must use HTTPS"),
            "error should name the requirement: {msg}"
        );
        assert!(
            msg.contains("--insecure"),
            "error should hint at --insecure flag: {msg}"
        );
    }

    #[test]
    fn check_tarball_url_scheme_allows_http_non_localhost_with_insecure() {
        // Directly exercises the new `--insecure` carve-out without
        // making a real HTTP request. The flag opts into HTTP
        // explicitly, so the guard must accept it.
        let client = RegistryClient::new().with_insecure(true);
        assert!(
            client
                .check_tarball_url_scheme("http://mirror.example/pkg/-/pkg-1.0.0.tgz")
                .is_ok()
        );
    }

    #[test]
    fn check_tarball_url_scheme_rejects_file_even_with_insecure() {
        // `--insecure` is HTTP-only by contract (see `--insecure` help text in
        // lpm-cli and the doc comment on `check_tarball_url_scheme`). `file://`
        // must remain rejected even with the flag set, or a tampered lockfile
        // could steer the installer at arbitrary local files.
        let client = RegistryClient::new().with_insecure(true);
        let result = client.check_tarball_url_scheme("file:///etc/passwd");
        assert!(
            result.is_err(),
            "file:// must be rejected even with --insecure"
        );
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("tarball URL must use HTTPS"),
            "error should name the requirement: {msg}"
        );
    }

    #[test]
    fn check_tarball_url_scheme_rejects_non_http_schemes_even_with_insecure() {
        // Same contract guard as the file:// case, extended to the
        // other non-HTTP schemes an attacker-controlled lockfile or
        // metadata response could try to sneak through.
        let client = RegistryClient::new().with_insecure(true);
        for url in [
            "ftp://mirror.example.com/pkg.tgz",
            "data:application/octet-stream,AAAA",
            "javascript:fetch('/admin')",
            "gopher://evil.com/pkg.tgz",
        ] {
            assert!(
                client.check_tarball_url_scheme(url).is_err(),
                "{url} must be rejected even with --insecure"
            );
        }
    }

    #[test]
    fn is_http_url_cases() {
        assert!(is_http_url("http://evil.com/pkg.tgz"));
        assert!(is_http_url("http://localhost:3000/pkg.tgz"));
        assert!(!is_http_url("https://lpm.dev/pkg.tgz"));
        assert!(!is_http_url("file:///etc/passwd"));
        assert!(!is_http_url("ftp://mirror.example/pkg.tgz"));
        assert!(!is_http_url("not a url"));
    }

    #[test]
    fn is_localhost_url_cases() {
        assert!(is_localhost_url("http://localhost:3000"));
        assert!(is_localhost_url("http://localhost"));
        assert!(is_localhost_url("http://127.0.0.1:3000"));
        assert!(is_localhost_url("http://[::1]:3000"));
        assert!(!is_localhost_url("http://localhost.evil.com:3000"));
        assert!(!is_localhost_url("http://127.0.0.1.evil.com:3000"));
        assert!(!is_localhost_url("http://[::1].evil.com:3000"));
        assert!(!is_localhost_url("http://evil.com"));
        assert!(!is_localhost_url("https://lpm.dev"));
    }

    /// L5: IPv4-mapped IPv6 (`::ffff:127.0.0.1`) is loopback per the
    /// human reading but Rust's `IpAddr::is_loopback` only flags the
    /// native v4 (`127.0.0.0/8`) and v6 (`::1`) forms. Without the
    /// mapped-v4 unwrap, an `http://[::ffff:127.0.0.1]/foo` URL would
    /// sneak past the localhost gate. Pins the mapped-form handling.
    #[test]
    fn is_localhost_url_recognises_ipv4_mapped_ipv6_loopback() {
        assert!(
            is_localhost_url("http://[::ffff:127.0.0.1]:3000"),
            "IPv4-mapped IPv6 loopback must be recognised",
        );
        assert!(
            is_localhost_url("http://[::ffff:127.1.2.3]:3000"),
            "any IPv4-mapped address in 127.0.0.0/8 is loopback",
        );
        // And the negative: a mapped non-loopback v4 is NOT loopback.
        assert!(
            !is_localhost_url("http://[::ffff:8.8.8.8]:3000"),
            "mapped public IPv4 must not be treated as loopback",
        );
    }

    /// Whole 127.0.0.0/8 block is loopback per the IPv4 spec; spot-
    /// check a non-127.0.0.1 address inside the block to confirm the
    /// gate doesn't accidentally pin only the canonical address.
    #[test]
    fn is_localhost_url_accepts_full_127_block() {
        assert!(is_localhost_url("http://127.42.42.42:3000"));
        assert!(is_localhost_url("http://127.255.255.254:3000"));
    }

    // ─── Mock HTTP Tests for ETag/304 Flow ───────────────────────────

    /// Helper: create a RegistryClient pointed at a mock server with temp cache.
    ///
    /// These mock-server tests verify "first fetch caches; second fetch is a
    /// hit" round-trips, which depend on the cache write landing before the
    /// next read. We flip `synchronous_cache_writes` so the test doesn't race
    /// the spawn_blocking write against its own next request. Production-shape
    /// behavior (spawn_blocking, fire-and-forget) is exercised by the
    /// integration suite.
    fn client_with_mock_server(server_uri: &str) -> (RegistryClient, tempfile::TempDir) {
        let tmp = tempfile::tempdir().expect("failed to create temp dir");
        let mut client = RegistryClient::new()
            .with_base_url(server_uri)
            .with_synchronous_cache_writes(true);
        client.cache_dir = Some(tmp.path().to_path_buf());
        (client, tmp)
    }

    // ── evaluate_cached_url gate ─────────────────────────────────────────────

    #[test]
    fn gate_accepts_canonical_lpm_tarball_url() {
        let client = RegistryClient::new().with_base_url("https://lpm.dev");
        // Canonical LPM tarball path: /api/registry/{scope}/{pkg}/-/...tgz
        let url = "https://lpm.dev/api/registry/@scope/pkg/-/pkg-1.0.0.tgz";
        assert_eq!(evaluate_cached_url(url, &client), GateDecision::Accepted);
    }

    #[test]
    fn gate_accepts_canonical_npm_tarball_url() {
        let client = RegistryClient::new();
        // Default `npm_registry_url` is `https://registry.npmjs.org`.
        let url = "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz";
        assert_eq!(evaluate_cached_url(url, &client), GateDecision::Accepted);
    }

    #[test]
    fn gate_rejects_non_https_non_localhost_without_insecure() {
        let client = RegistryClient::new().with_base_url("https://lpm.dev");
        // HTTP (non-localhost) — scheme check fires first.
        let url = "http://evil.com/pkg/-/pkg-1.0.0.tgz";
        assert_eq!(
            evaluate_cached_url(url, &client),
            GateDecision::RejectedScheme
        );
    }

    #[test]
    fn gate_accepts_http_with_insecure() {
        // `--insecure` widens the scheme carve-out so lockfile-cached
        // HTTP tarball URLs can be reused when the user explicitly
        // opted into insecure transport. Shape + origin gates still
        // fire — here the base URL is the mirror's HTTP origin so
        // `is_configured_origin` returns true.
        let client = RegistryClient::new()
            .with_base_url("http://mirror.internal")
            .with_insecure(true);
        let url = "http://mirror.internal/pkg/-/pkg-1.0.0.tgz";
        assert_eq!(evaluate_cached_url(url, &client), GateDecision::Accepted);
    }

    #[test]
    fn gate_rejects_file_scheme_even_with_insecure() {
        // `--insecure` is HTTP-only by contract, never `file://`. A tampered
        // lockfile that stashed a `file:///etc/passwd` URL must be rejected
        // regardless of the flag state, before the bearer token is attached.
        let client = RegistryClient::new()
            .with_base_url("https://lpm.dev")
            .with_insecure(true);
        assert_eq!(
            evaluate_cached_url("file:///etc/passwd", &client),
            GateDecision::RejectedScheme
        );
    }

    #[test]
    fn gate_rejects_wrong_suffix() {
        let client = RegistryClient::new().with_base_url("https://lpm.dev");
        // HTTPS + correct origin + `/-/` segment — but not `.tgz`.
        let url = "https://lpm.dev/api/registry/@scope/pkg/-/pkg-1.0.0.zip";
        assert_eq!(
            evaluate_cached_url(url, &client),
            GateDecision::RejectedShape
        );
    }

    #[test]
    fn gate_rejects_admin_style_path_without_dash_segment() {
        // H1 auth-token leak defense: `.tgz` suffix alone isn't enough
        // — the `/-/` segment requirement is what rules out attacker-
        // crafted `/api/admin/foo.tgz` paths.
        let client = RegistryClient::new().with_base_url("https://lpm.dev");
        let url = "https://lpm.dev/api/admin/foo.tgz";
        assert_eq!(
            evaluate_cached_url(url, &client),
            GateDecision::RejectedShape
        );
    }

    #[test]
    fn gate_rejects_origin_mismatch_after_registry_switch() {
        // User switches `LPM_REGISTRY_URL` to a mirror. Stored
        // `@lpm.dev/*` URLs now mismatch the configured origin and
        // fall through to on-demand lookup.
        let client = RegistryClient::new().with_base_url("http://localhost:9999");
        let url = "https://lpm.dev/api/registry/@scope/pkg/-/pkg-1.0.0.tgz";
        assert_eq!(
            evaluate_cached_url(url, &client),
            GateDecision::RejectedOrigin
        );
    }

    #[test]
    fn gate_allows_localhost_registry() {
        // Dev workflow — HTTP to localhost is explicitly permitted
        // (same carve-out `download_tarball_to_file` has pre-flight).
        let client = RegistryClient::new().with_base_url("http://localhost:3000");
        let url = "http://localhost:3000/api/registry/@scope/pkg/-/pkg-1.0.0.tgz";
        assert_eq!(evaluate_cached_url(url, &client), GateDecision::Accepted);
    }

    #[test]
    fn gate_rejects_malformed_url() {
        let client = RegistryClient::new();
        assert_eq!(
            evaluate_cached_url("not a url", &client),
            GateDecision::RejectedScheme,
        );
    }

    /// Helper: build a JSON response body for PackageMetadata.
    fn test_metadata_json(name: &str) -> String {
        serde_json::json!({
            "name": name,
            "description": "test package",
            "dist-tags": { "latest": "1.0.0" },
            "versions": {
                "1.0.0": {
                    "name": name,
                    "version": "1.0.0",
                    "dist": {
                        "tarball": "https://example.com/pkg-1.0.0.tgz",
                        "integrity": "sha512-test"
                    },
                    "dependencies": {}
                }
            }
        })
        .to_string()
    }

    #[tokio::test]
    async fn etag_304_revalidation_lpm_metadata() {
        use wiremock::matchers::{header, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let (client, _tmp) = client_with_mock_server(&server.uri());

        let pkg_name = "@lpm.dev/test.etag-pkg";
        let body = test_metadata_json(pkg_name);

        // First request: server returns 200 + ETag + body
        Mock::given(method("GET"))
            .and(path("/api/registry/@lpm.dev/test.etag-pkg"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(&body)
                    .append_header("ETag", "\"v1-abc123\""),
            )
            .expect(1)
            .mount(&server)
            .await;

        let name = PackageName::parse(pkg_name).unwrap();
        let result = client.get_package_metadata(&name).await;
        assert!(result.is_ok(), "first fetch should succeed");
        let meta = result.unwrap();
        assert_eq!(meta.name, pkg_name);

        // Expire the cache by setting mtime to 10 minutes ago
        if let Some(cache_path) = client.cache_path(&format!("lpm:{pkg_name}")) {
            let past = filetime::FileTime::from_unix_time(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs() as i64
                    - 600,
                0,
            );
            filetime::set_file_mtime(&cache_path, past).unwrap();
        }

        // Reset mocks for second request
        server.reset().await;

        // Second request: server sees If-None-Match, returns 304
        Mock::given(method("GET"))
            .and(path("/api/registry/@lpm.dev/test.etag-pkg"))
            .and(header("If-None-Match", "\"v1-abc123\""))
            .respond_with(ResponseTemplate::new(304))
            .expect(1)
            .mount(&server)
            .await;

        let result2 = client.get_package_metadata(&name).await;
        assert!(result2.is_ok(), "304 revalidation should succeed");
        let meta2 = result2.unwrap();
        assert_eq!(meta2.name, pkg_name, "should return cached metadata on 304");
    }

    #[tokio::test]
    async fn etag_updated_on_new_response() {
        use wiremock::matchers::{header, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let (client, _tmp) = client_with_mock_server(&server.uri());

        let pkg_name = "@lpm.dev/test.etag-update";
        let body_v1 = test_metadata_json(pkg_name);

        // First request: returns with ETag v1
        Mock::given(method("GET"))
            .and(path("/api/registry/@lpm.dev/test.etag-update"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(&body_v1)
                    .append_header("ETag", "\"v1\""),
            )
            .expect(1)
            .mount(&server)
            .await;

        let name = PackageName::parse(pkg_name).unwrap();
        client.get_package_metadata(&name).await.unwrap();

        // Expire cache
        if let Some(cache_path) = client.cache_path(&format!("lpm:{pkg_name}")) {
            let past = filetime::FileTime::from_unix_time(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs() as i64
                    - 600,
                0,
            );
            filetime::set_file_mtime(&cache_path, past).unwrap();
        }

        server.reset().await;

        // Second request: server rejects old ETag, returns new data + new ETag
        let body_v2 = serde_json::json!({
            "name": pkg_name,
            "description": "updated package",
            "latestVersion": "2.0.0",
            "dist-tags": { "latest": "2.0.0" },
            "versions": {
                "2.0.0": {
                    "name": pkg_name,
                    "version": "2.0.0",
                    "dist": {
                        "tarball": "https://example.com/pkg-2.0.0.tgz",
                        "integrity": "sha512-test2"
                    },
                    "dependencies": {}
                }
            }
        })
        .to_string();

        Mock::given(method("GET"))
            .and(path("/api/registry/@lpm.dev/test.etag-update"))
            .and(header("If-None-Match", "\"v1\""))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(&body_v2)
                    .append_header("ETag", "\"v2\""),
            )
            .expect(1)
            .mount(&server)
            .await;

        let meta2 = client.get_package_metadata(&name).await.unwrap();
        assert_eq!(
            meta2.latest_version.as_deref(),
            Some("2.0.0"),
            "should return new metadata after ETag change"
        );

        // Verify cache now has v2 ETag
        let content = client.read_cache_content(&format!("lpm:{pkg_name}"));
        assert!(content.is_some());
        assert_eq!(
            content.unwrap().etag.as_deref(),
            Some("\"v2\""),
            "cache should store the new ETag"
        );
    }

    #[tokio::test]
    async fn ttl_cache_hit_skips_http() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let (client, _tmp) = client_with_mock_server(&server.uri());

        let pkg_name = "@lpm.dev/test.ttl-hit";
        let body = test_metadata_json(pkg_name);

        // First request: normal 200
        Mock::given(method("GET"))
            .and(path("/api/registry/@lpm.dev/test.ttl-hit"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(&body)
                    .append_header("ETag", "\"fresh\""),
            )
            .expect(1) // MUST be called exactly once
            .mount(&server)
            .await;

        let name = PackageName::parse(pkg_name).unwrap();
        client.get_package_metadata(&name).await.unwrap();

        // Second request within TTL — should NOT hit the server (expect(1) enforces this)
        let result2 = client.get_package_metadata(&name).await;
        assert!(result2.is_ok(), "TTL cache hit should return immediately");
        assert_eq!(result2.unwrap().name, pkg_name);
    }

    #[tokio::test]
    async fn npm_metadata_etag_304_revalidation() {
        use wiremock::matchers::{header, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let (client, _tmp) = client_with_mock_server(&server.uri());

        let npm_name = "express";
        let body = test_metadata_json(npm_name);

        // First request via proxy path: 200 + ETag
        Mock::given(method("GET"))
            .and(path("/api/registry/express"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(&body)
                    .append_header("ETag", "\"npm-v1\""),
            )
            .expect(1)
            .mount(&server)
            .await;

        let result = client.get_npm_package_metadata(npm_name).await;
        assert!(result.is_ok());

        // Expire cache
        if let Some(cache_path) = client.cache_path(&format!("npm:{npm_name}")) {
            let past = filetime::FileTime::from_unix_time(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs() as i64
                    - 600,
                0,
            );
            filetime::set_file_mtime(&cache_path, past).unwrap();
        }

        server.reset().await;

        // Second request: If-None-Match → 304
        Mock::given(method("GET"))
            .and(path("/api/registry/express"))
            .and(header("If-None-Match", "\"npm-v1\""))
            .respond_with(ResponseTemplate::new(304))
            .expect(1)
            .mount(&server)
            .await;

        let result2 = client.get_npm_package_metadata(npm_name).await;
        assert!(result2.is_ok(), "npm 304 revalidation should succeed");
        assert_eq!(result2.unwrap().name, npm_name);
    }

    #[tokio::test]
    async fn npm_proxy_miss_falls_back_to_direct_npm_registry() {
        use wiremock::matchers::{header, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let proxy_server = MockServer::start().await;
        let npm_server = MockServer::start().await;
        let tmp = tempfile::tempdir().expect("failed to create temp dir");

        let npm_name = "express-proxy-miss";
        let mut client = RegistryClient::new()
            .with_base_url(proxy_server.uri())
            .with_npm_registry_url(npm_server.uri())
            .with_synchronous_cache_writes(true);
        client.cache_dir = Some(tmp.path().to_path_buf());

        Mock::given(method("GET"))
            .and(path("/api/registry/express-proxy-miss"))
            .respond_with(ResponseTemplate::new(404).set_body_string("proxy miss"))
            .expect(1)
            .mount(&proxy_server)
            .await;

        Mock::given(method("GET"))
            .and(path("/express-proxy-miss"))
            .and(header("accept", "application/vnd.npm.install-v1+json"))
            .respond_with(ResponseTemplate::new(200).set_body_string(test_metadata_json(npm_name)))
            .expect(1)
            .mount(&npm_server)
            .await;

        let result = client.get_npm_package_metadata(npm_name).await;
        assert!(
            result.is_ok(),
            "proxy miss should fall back to direct npm registry"
        );
        assert_eq!(result.unwrap().name, npm_name);

        let cached = client
            .read_cache_content(&format!("npm:{npm_name}"))
            .expect("fallback result should be cached");
        let metadata = RegistryClient::deserialize_cached_metadata(&cached.data)
            .expect("cached fallback metadata should deserialize");
        assert_eq!(metadata.name, npm_name);
    }

    #[tokio::test]
    async fn npm_proxy_wrong_package_body_returns_registry_error_without_fallback() {
        use wiremock::matchers::{header, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let proxy_server = MockServer::start().await;
        let npm_server = MockServer::start().await;
        let tmp = tempfile::tempdir().expect("failed to create temp dir");

        let npm_name = "express-proxy-wrong-body";
        let mut client = RegistryClient::new()
            .with_base_url(proxy_server.uri())
            .with_npm_registry_url(npm_server.uri());
        client.cache_dir = Some(tmp.path().to_path_buf());

        Mock::given(method("GET"))
            .and(path("/api/registry/express-proxy-wrong-body"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(test_metadata_json("some-other-package"))
                    .append_header("ETag", "\"proxy-v1\""),
            )
            .expect(1)
            .mount(&proxy_server)
            .await;

        Mock::given(method("GET"))
            .and(path("/express-proxy-wrong-body"))
            .and(header("accept", "application/vnd.npm.install-v1+json"))
            .respond_with(ResponseTemplate::new(200).set_body_string(test_metadata_json(npm_name)))
            .expect(0)
            .mount(&npm_server)
            .await;

        let result = client.get_npm_package_metadata(npm_name).await;
        assert!(matches!(
            result,
            Err(LpmError::Registry(message))
                if message.contains("unexpected package")
                    && message.contains("some-other-package")
                    && message.contains(npm_name)
        ));

        assert!(
            client
                .read_cache_content(&format!("npm:{npm_name}"))
                .is_none(),
            "wrong-package proxy bodies should not be cached"
        );
    }

    #[tokio::test]
    async fn etag_304_with_undecodable_cached_payload_refetches_lpm_metadata() {
        use std::sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        };
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let (client, _tmp) = client_with_mock_server(&server.uri());

        let pkg_name = "@lpm.dev/test.etag-refetch";
        let name = PackageName::parse(pkg_name).unwrap();

        Mock::given(method("GET"))
            .and(path("/api/registry/@lpm.dev/test.etag-refetch"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(test_metadata_json(pkg_name))
                    .append_header("ETag", "\"v1\""),
            )
            .expect(1)
            .mount(&server)
            .await;

        client.get_package_metadata(&name).await.unwrap();

        let cache_path = client
            .cache_path(&format!("lpm:{pkg_name}"))
            .expect("cache path should exist");
        // Synthesize a magic-valid but undeserializable cache entry.
        // Magic passes → ETag extracted → payload fails msgpack/JSON decode
        // → caller drops the cached payload and refetches.
        let corrupted_data = b"not-valid-metadata";
        let mut corrupted_content = Vec::new();
        corrupted_content.extend_from_slice(METADATA_CACHE_MAGIC);
        corrupted_content.extend_from_slice(b"\"v1\"");
        corrupted_content.push(b'\n');
        corrupted_content.extend_from_slice(corrupted_data);
        std::fs::write(&cache_path, corrupted_content).unwrap();

        let past = filetime::FileTime::from_unix_time(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64
                - 600,
            0,
        );
        filetime::set_file_mtime(&cache_path, past).unwrap();

        server.reset().await;

        let request_count = Arc::new(AtomicUsize::new(0));
        let request_count_for_responder = Arc::clone(&request_count);
        let refreshed_body = serde_json::json!({
            "name": pkg_name,
            "description": "refetched package",
            "latestVersion": "2.0.0",
            "dist-tags": { "latest": "2.0.0" },
            "versions": {
                "2.0.0": {
                    "name": pkg_name,
                    "version": "2.0.0",
                    "dist": {
                        "tarball": "https://example.com/pkg-2.0.0.tgz",
                        "integrity": "sha512-refetched"
                    },
                    "dependencies": {}
                }
            }
        })
        .to_string();

        Mock::given(method("GET"))
            .and(path("/api/registry/@lpm.dev/test.etag-refetch"))
            .respond_with(move |request: &wiremock::Request| {
                let attempt = request_count_for_responder.fetch_add(1, Ordering::SeqCst);
                if attempt == 0 {
                    assert_eq!(
                        request
                            .headers
                            .get("if-none-match")
                            .and_then(|value| value.to_str().ok()),
                        Some("\"v1\"")
                    );
                    ResponseTemplate::new(304)
                } else {
                    assert!(request.headers.get("if-none-match").is_none());
                    ResponseTemplate::new(200)
                        .set_body_string(refreshed_body.clone())
                        .append_header("ETag", "\"v2\"")
                }
            })
            .expect(2)
            .mount(&server)
            .await;

        let refreshed = client.get_package_metadata(&name).await.unwrap();
        assert_eq!(refreshed.latest_version.as_deref(), Some("2.0.0"));
        assert_eq!(request_count.load(Ordering::SeqCst), 2);
        assert_eq!(
            client
                .read_cache_content(&format!("lpm:{pkg_name}"))
                .unwrap()
                .etag
                .as_deref(),
            Some("\"v2\"")
        );
    }

    #[tokio::test]
    async fn npm_etag_304_with_undecodable_cached_payload_refetches_proxy_metadata() {
        use std::sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        };
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let (client, _tmp) = client_with_mock_server(&server.uri());

        let npm_name = "express-refetch";

        Mock::given(method("GET"))
            .and(path("/api/registry/express-refetch"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(test_metadata_json(npm_name))
                    .append_header("ETag", "\"npm-v1\""),
            )
            .expect(1)
            .mount(&server)
            .await;

        client.get_npm_package_metadata(npm_name).await.unwrap();

        let cache_path = client
            .cache_path(&format!("npm:{npm_name}"))
            .expect("npm cache path should exist");
        // Same shape as the matching synthesizer above (magic + ETag +
        // undeserializable bytes) applied to the npm proxy path.
        let corrupted_data = b"not-valid-npm-metadata";
        let mut corrupted_content = Vec::new();
        corrupted_content.extend_from_slice(METADATA_CACHE_MAGIC);
        corrupted_content.extend_from_slice(b"\"npm-v1\"");
        corrupted_content.push(b'\n');
        corrupted_content.extend_from_slice(corrupted_data);
        std::fs::write(&cache_path, corrupted_content).unwrap();

        let past = filetime::FileTime::from_unix_time(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64
                - 600,
            0,
        );
        filetime::set_file_mtime(&cache_path, past).unwrap();

        server.reset().await;

        let request_count = Arc::new(AtomicUsize::new(0));
        let request_count_for_responder = Arc::clone(&request_count);
        let refreshed_body = serde_json::json!({
            "name": npm_name,
            "description": "refetched proxy package",
            "dist-tags": { "latest": "2.0.0" },
            "versions": {
                "2.0.0": {
                    "name": npm_name,
                    "version": "2.0.0",
                    "dist": {
                        "tarball": "https://example.com/pkg-2.0.0.tgz",
                        "integrity": "sha512-refetched"
                    },
                    "dependencies": {}
                }
            }
        })
        .to_string();

        Mock::given(method("GET"))
            .and(path("/api/registry/express-refetch"))
            .respond_with(move |request: &wiremock::Request| {
                let attempt = request_count_for_responder.fetch_add(1, Ordering::SeqCst);
                if attempt == 0 {
                    assert_eq!(
                        request
                            .headers
                            .get("if-none-match")
                            .and_then(|value| value.to_str().ok()),
                        Some("\"npm-v1\"")
                    );
                    ResponseTemplate::new(304)
                } else {
                    assert!(request.headers.get("if-none-match").is_none());
                    ResponseTemplate::new(200)
                        .set_body_string(refreshed_body.clone())
                        .append_header("ETag", "\"npm-v2\"")
                }
            })
            .expect(2)
            .mount(&server)
            .await;

        let refreshed = client.get_npm_package_metadata(npm_name).await.unwrap();
        assert_eq!(refreshed.name, npm_name);
        assert_eq!(request_count.load(Ordering::SeqCst), 2);
        assert_eq!(
            client
                .read_cache_content(&format!("npm:{npm_name}"))
                .unwrap()
                .etag
                .as_deref(),
            Some("\"npm-v2\"")
        );
    }

    #[tokio::test]
    async fn etag_revalidation_retries_429_and_keeps_conditional_header() {
        use std::sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        };
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let (client, _tmp) = client_with_mock_server(&server.uri());

        let pkg_name = "@lpm.dev/test.etag-retry-429";
        let name = PackageName::parse(pkg_name).unwrap();

        Mock::given(method("GET"))
            .and(path("/api/registry/@lpm.dev/test.etag-retry-429"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(test_metadata_json(pkg_name))
                    .append_header("ETag", "\"v1\""),
            )
            .expect(1)
            .mount(&server)
            .await;

        client.get_package_metadata(&name).await.unwrap();

        if let Some(cache_path) = client.cache_path(&format!("lpm:{pkg_name}")) {
            let past = filetime::FileTime::from_unix_time(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs() as i64
                    - 600,
                0,
            );
            filetime::set_file_mtime(&cache_path, past).unwrap();
        }

        server.reset().await;

        let request_count = Arc::new(AtomicUsize::new(0));
        let request_count_for_responder = Arc::clone(&request_count);
        let refreshed_body = serde_json::json!({
            "name": pkg_name,
            "description": "revalidated after 429",
            "latestVersion": "2.0.0",
            "dist-tags": { "latest": "2.0.0" },
            "versions": {
                "2.0.0": {
                    "name": pkg_name,
                    "version": "2.0.0",
                    "dist": {
                        "tarball": "https://example.com/pkg-2.0.0.tgz",
                        "integrity": "sha512-retry"
                    },
                    "dependencies": {}
                }
            }
        })
        .to_string();

        Mock::given(method("GET"))
            .and(path("/api/registry/@lpm.dev/test.etag-retry-429"))
            .respond_with(move |request: &wiremock::Request| {
                assert_eq!(
                    request
                        .headers
                        .get("if-none-match")
                        .and_then(|value| value.to_str().ok()),
                    Some("\"v1\"")
                );

                let attempt = request_count_for_responder.fetch_add(1, Ordering::SeqCst);
                if attempt == 0 {
                    ResponseTemplate::new(429).append_header("retry-after", "0")
                } else {
                    ResponseTemplate::new(200)
                        .set_body_string(refreshed_body.clone())
                        .append_header("ETag", "\"v2\"")
                }
            })
            .expect(2)
            .mount(&server)
            .await;

        let refreshed = client.get_package_metadata(&name).await.unwrap();
        assert_eq!(refreshed.latest_version.as_deref(), Some("2.0.0"));
        assert_eq!(request_count.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn npm_etag_revalidation_retries_503_and_keeps_conditional_header() {
        use std::sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        };
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let (client, _tmp) = client_with_mock_server(&server.uri());

        let npm_name = "express-retry-503";

        Mock::given(method("GET"))
            .and(path("/api/registry/express-retry-503"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(test_metadata_json(npm_name))
                    .append_header("ETag", "\"npm-v1\""),
            )
            .expect(1)
            .mount(&server)
            .await;

        client.get_npm_package_metadata(npm_name).await.unwrap();

        if let Some(cache_path) = client.cache_path(&format!("npm:{npm_name}")) {
            let past = filetime::FileTime::from_unix_time(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs() as i64
                    - 600,
                0,
            );
            filetime::set_file_mtime(&cache_path, past).unwrap();
        }

        server.reset().await;

        let request_count = Arc::new(AtomicUsize::new(0));
        let request_count_for_responder = Arc::clone(&request_count);
        let refreshed_body = serde_json::json!({
            "name": npm_name,
            "description": "proxy revalidated after 503",
            "dist-tags": { "latest": "2.0.0" },
            "versions": {
                "2.0.0": {
                    "name": npm_name,
                    "version": "2.0.0",
                    "dist": {
                        "tarball": "https://example.com/pkg-2.0.0.tgz",
                        "integrity": "sha512-retry"
                    },
                    "dependencies": {}
                }
            }
        })
        .to_string();

        Mock::given(method("GET"))
            .and(path("/api/registry/express-retry-503"))
            .respond_with(move |request: &wiremock::Request| {
                assert_eq!(
                    request
                        .headers
                        .get("if-none-match")
                        .and_then(|value| value.to_str().ok()),
                    Some("\"npm-v1\"")
                );

                let attempt = request_count_for_responder.fetch_add(1, Ordering::SeqCst);
                if attempt == 0 {
                    ResponseTemplate::new(503).set_body_string("temporary metadata outage")
                } else {
                    ResponseTemplate::new(200)
                        .set_body_string(refreshed_body.clone())
                        .append_header("ETag", "\"npm-v2\"")
                }
            })
            .expect(2)
            .mount(&server)
            .await;

        let refreshed = client.get_npm_package_metadata(npm_name).await.unwrap();
        assert_eq!(refreshed.name, npm_name);
        assert_eq!(request_count.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn npm_etag_revalidation_exhausts_429_and_returns_rate_limited() {
        use std::sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        };
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let (client, _tmp) = client_with_mock_server(&server.uri());

        let npm_name = "express-rate-limited";

        Mock::given(method("GET"))
            .and(path("/api/registry/express-rate-limited"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(test_metadata_json(npm_name))
                    .append_header("ETag", "\"npm-v1\""),
            )
            .expect(1)
            .mount(&server)
            .await;

        client.get_npm_package_metadata(npm_name).await.unwrap();

        if let Some(cache_path) = client.cache_path(&format!("npm:{npm_name}")) {
            let past = filetime::FileTime::from_unix_time(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs() as i64
                    - 600,
                0,
            );
            filetime::set_file_mtime(&cache_path, past).unwrap();
        }

        server.reset().await;

        let request_count = Arc::new(AtomicUsize::new(0));
        let request_count_for_responder = Arc::clone(&request_count);

        Mock::given(method("GET"))
            .and(path("/api/registry/express-rate-limited"))
            .respond_with(move |request: &wiremock::Request| {
                assert_eq!(
                    request
                        .headers
                        .get("if-none-match")
                        .and_then(|value| value.to_str().ok()),
                    Some("\"npm-v1\"")
                );
                request_count_for_responder.fetch_add(1, Ordering::SeqCst);
                ResponseTemplate::new(429).append_header("retry-after", "0")
            })
            .expect((MAX_RETRIES + 1) as u64)
            .mount(&server)
            .await;

        let result = client.get_npm_package_metadata(npm_name).await;
        match result {
            Err(LpmError::RateLimited { retry_after_secs }) => {
                assert_eq!(retry_after_secs, 0);
            }
            other => panic!("expected final rate-limit error, got {other:?}"),
        }

        assert_eq!(
            request_count.load(Ordering::SeqCst),
            (MAX_RETRIES + 1) as usize
        );
    }

    #[tokio::test]
    async fn npm_etag_revalidation_exhausts_503_and_returns_http_error() {
        use std::sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        };
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let (client, _tmp) = client_with_mock_server(&server.uri());

        let npm_name = "express-http-503";

        Mock::given(method("GET"))
            .and(path("/api/registry/express-http-503"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(test_metadata_json(npm_name))
                    .append_header("ETag", "\"npm-v1\""),
            )
            .expect(1)
            .mount(&server)
            .await;

        client.get_npm_package_metadata(npm_name).await.unwrap();

        if let Some(cache_path) = client.cache_path(&format!("npm:{npm_name}")) {
            let past = filetime::FileTime::from_unix_time(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs() as i64
                    - 600,
                0,
            );
            filetime::set_file_mtime(&cache_path, past).unwrap();
        }

        server.reset().await;

        let request_count = Arc::new(AtomicUsize::new(0));
        let request_count_for_responder = Arc::clone(&request_count);

        Mock::given(method("GET"))
            .and(path("/api/registry/express-http-503"))
            .respond_with(move |request: &wiremock::Request| {
                assert_eq!(
                    request
                        .headers
                        .get("if-none-match")
                        .and_then(|value| value.to_str().ok()),
                    Some("\"npm-v1\"")
                );
                request_count_for_responder.fetch_add(1, Ordering::SeqCst);
                ResponseTemplate::new(503).set_body_string("temporary proxy metadata outage")
            })
            .expect((MAX_RETRIES + 1) as u64)
            .mount(&server)
            .await;

        let result = client.get_npm_package_metadata(npm_name).await;
        match result {
            Err(LpmError::Http { status, message }) => {
                assert_eq!(status, 503);
                assert!(message.contains("temporary proxy metadata outage"));
            }
            other => panic!("expected final http error, got {other:?}"),
        }

        assert_eq!(
            request_count.load(Ordering::SeqCst),
            (MAX_RETRIES + 1) as usize
        );
    }

    #[tokio::test]
    async fn etag_revalidation_exhausts_429_and_returns_rate_limited() {
        use std::sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        };
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let (client, _tmp) = client_with_mock_server(&server.uri());

        let pkg_name = "@lpm.dev/test.etag-rate-limited";
        let name = PackageName::parse(pkg_name).unwrap();

        Mock::given(method("GET"))
            .and(path("/api/registry/@lpm.dev/test.etag-rate-limited"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(test_metadata_json(pkg_name))
                    .append_header("ETag", "\"v1\""),
            )
            .expect(1)
            .mount(&server)
            .await;

        client.get_package_metadata(&name).await.unwrap();

        if let Some(cache_path) = client.cache_path(&format!("lpm:{pkg_name}")) {
            let past = filetime::FileTime::from_unix_time(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs() as i64
                    - 600,
                0,
            );
            filetime::set_file_mtime(&cache_path, past).unwrap();
        }

        server.reset().await;

        let request_count = Arc::new(AtomicUsize::new(0));
        let request_count_for_responder = Arc::clone(&request_count);

        Mock::given(method("GET"))
            .and(path("/api/registry/@lpm.dev/test.etag-rate-limited"))
            .respond_with(move |request: &wiremock::Request| {
                assert_eq!(
                    request
                        .headers
                        .get("if-none-match")
                        .and_then(|value| value.to_str().ok()),
                    Some("\"v1\"")
                );
                request_count_for_responder.fetch_add(1, Ordering::SeqCst);
                ResponseTemplate::new(429).append_header("retry-after", "0")
            })
            .expect((MAX_RETRIES + 1) as u64)
            .mount(&server)
            .await;

        let result = client.get_package_metadata(&name).await;
        match result {
            Err(LpmError::RateLimited { retry_after_secs }) => {
                assert_eq!(retry_after_secs, 0);
            }
            other => panic!("expected final rate-limit error, got {other:?}"),
        }

        assert_eq!(
            request_count.load(Ordering::SeqCst),
            (MAX_RETRIES + 1) as usize
        );
    }

    #[tokio::test]
    async fn etag_revalidation_exhausts_503_and_returns_http_error() {
        use std::sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        };
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let (client, _tmp) = client_with_mock_server(&server.uri());

        let pkg_name = "@lpm.dev/test.etag-http-503";
        let name = PackageName::parse(pkg_name).unwrap();

        Mock::given(method("GET"))
            .and(path("/api/registry/@lpm.dev/test.etag-http-503"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(test_metadata_json(pkg_name))
                    .append_header("ETag", "\"v1\""),
            )
            .expect(1)
            .mount(&server)
            .await;

        client.get_package_metadata(&name).await.unwrap();

        if let Some(cache_path) = client.cache_path(&format!("lpm:{pkg_name}")) {
            let past = filetime::FileTime::from_unix_time(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs() as i64
                    - 600,
                0,
            );
            filetime::set_file_mtime(&cache_path, past).unwrap();
        }

        server.reset().await;

        let request_count = Arc::new(AtomicUsize::new(0));
        let request_count_for_responder = Arc::clone(&request_count);

        Mock::given(method("GET"))
            .and(path("/api/registry/@lpm.dev/test.etag-http-503"))
            .respond_with(move |request: &wiremock::Request| {
                assert_eq!(
                    request
                        .headers
                        .get("if-none-match")
                        .and_then(|value| value.to_str().ok()),
                    Some("\"v1\"")
                );
                request_count_for_responder.fetch_add(1, Ordering::SeqCst);
                ResponseTemplate::new(503).set_body_string("temporary metadata outage")
            })
            .expect((MAX_RETRIES + 1) as u64)
            .mount(&server)
            .await;

        let result = client.get_package_metadata(&name).await;
        match result {
            Err(LpmError::Http { status, message }) => {
                assert_eq!(status, 503);
                assert!(message.contains("temporary metadata outage"));
            }
            other => panic!("expected final http error, got {other:?}"),
        }

        assert_eq!(
            request_count.load(Ordering::SeqCst),
            (MAX_RETRIES + 1) as usize
        );
    }

    #[tokio::test]
    async fn whoami_maps_401_to_auth_required() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let (client, _tmp) = client_with_mock_server(&server.uri());

        Mock::given(method("GET"))
            .and(path("/api/registry/-/whoami"))
            .respond_with(ResponseTemplate::new(401).set_body_string("expired"))
            .expect(1)
            .mount(&server)
            .await;

        let result = client.whoami().await;
        assert!(matches!(result, Err(LpmError::AuthRequired)));
    }

    #[tokio::test]
    async fn whoami_maps_403_to_forbidden_with_body() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let (client, _tmp) = client_with_mock_server(&server.uri());

        Mock::given(method("GET"))
            .and(path("/api/registry/-/whoami"))
            .respond_with(ResponseTemplate::new(403).set_body_string("forbidden-body"))
            .expect(1)
            .mount(&server)
            .await;

        let result = client.whoami().await;
        assert!(matches!(result, Err(LpmError::Forbidden(body)) if body == "forbidden-body"));
    }

    #[tokio::test]
    async fn whoami_maps_404_to_not_found_with_body() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let (client, _tmp) = client_with_mock_server(&server.uri());

        Mock::given(method("GET"))
            .and(path("/api/registry/-/whoami"))
            .respond_with(ResponseTemplate::new(404).set_body_string("missing-user"))
            .expect(1)
            .mount(&server)
            .await;

        let result = client.whoami().await;
        assert!(matches!(result, Err(LpmError::NotFound(body)) if body == "missing-user"));
    }

    #[tokio::test]
    async fn whoami_returns_parse_error_on_malformed_json() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let (client, _tmp) = client_with_mock_server(&server.uri());

        Mock::given(method("GET"))
            .and(path("/api/registry/-/whoami"))
            .respond_with(ResponseTemplate::new(200).set_body_string("{not-json"))
            .expect(1)
            .mount(&server)
            .await;

        let result = client.whoami().await;
        assert!(
            matches!(result, Err(LpmError::Registry(message)) if message.contains("failed to parse JSON"))
        );
    }

    #[tokio::test]
    async fn whoami_retries_429_and_sends_bearer_auth_header() {
        use wiremock::matchers::{header, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let (client, _tmp) = client_with_mock_server(&server.uri());
        let client = client.with_token("test-auth-token");

        Mock::given(method("GET"))
            .and(path("/api/registry/-/whoami"))
            .and(header("authorization", "Bearer test-auth-token"))
            .respond_with(ResponseTemplate::new(429).append_header("retry-after", "0"))
            .expect(4)
            .mount(&server)
            .await;

        let result = client.whoami().await;
        assert!(matches!(
            result,
            Err(LpmError::RateLimited {
                retry_after_secs: 0
            })
        ));
    }

    #[tokio::test]
    async fn whoami_retries_500_then_succeeds_after_backoff() {
        use std::sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        };
        use std::time::Instant;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

        #[derive(Clone)]
        struct WhoamiRetryResponder {
            calls: Arc<AtomicUsize>,
        }

        impl Respond for WhoamiRetryResponder {
            fn respond(&self, _request: &Request) -> ResponseTemplate {
                let call_index = self.calls.fetch_add(1, Ordering::SeqCst);
                if call_index == 0 {
                    ResponseTemplate::new(500).set_body_string("transient upstream failure")
                } else {
                    ResponseTemplate::new(200).set_body_json(serde_json::json!({
                        "username": "retry-user"
                    }))
                }
            }
        }

        let server = MockServer::start().await;
        let (client, _tmp) = client_with_mock_server(&server.uri());
        let calls = Arc::new(AtomicUsize::new(0));

        Mock::given(method("GET"))
            .and(path("/api/registry/-/whoami"))
            .respond_with(WhoamiRetryResponder {
                calls: Arc::clone(&calls),
            })
            .expect(2)
            .mount(&server)
            .await;

        let started_at = Instant::now();
        let result = client
            .whoami()
            .await
            .expect("whoami should succeed after retry");

        assert_eq!(result.username.as_deref(), Some("retry-user"));
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert!(
            started_at.elapsed() >= backoff_delay(0),
            "retryable 500 should incur at least one backoff interval"
        );
    }

    #[tokio::test]
    async fn revoke_token_sends_bearer_auth_header_and_token_body() {
        use wiremock::matchers::{body_string_contains, header, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let (client, _tmp) = client_with_mock_server(&server.uri());
        let client = client.with_token("revoke-me-token");

        Mock::given(method("POST"))
            .and(path("/api/registry/tokens/revoke"))
            .and(header("authorization", "Bearer revoke-me-token"))
            .and(body_string_contains("\"token\":\"revoke-me-token\""))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&server)
            .await;

        client
            .revoke_token()
            .await
            .expect("revoke_token should succeed with auth header and token body");
    }

    #[tokio::test]
    async fn publish_package_treats_500_with_existing_version_as_success() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let (client, _tmp) = client_with_mock_server(&server.uri());
        let encoded_name = "@lpm.dev/test.publish-safe";

        Mock::given(method("PUT"))
            .respond_with(ResponseTemplate::new(500).set_body_string("publish boom"))
            .expect(1)
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path("/api/registry/@lpm.dev/test.publish-safe"))
            .respond_with(
                ResponseTemplate::new(200).set_body_string(test_metadata_json(encoded_name)),
            )
            .expect(1)
            .mount(&server)
            .await;

        let result = client
            .publish_package(
                encoded_name,
                &serde_json::json!({ "name": encoded_name }),
                None,
                0,
            )
            .await
            .expect("publish should succeed when version exists after 500");

        assert_eq!(result["name"], encoded_name);
    }

    #[tokio::test]
    async fn check_name_returns_parse_error_on_malformed_json() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let (client, _tmp) = client_with_mock_server(&server.uri());
        let client = client.with_token("check-name-token");

        Mock::given(method("GET"))
            .and(path("/api/registry/check-name"))
            .respond_with(ResponseTemplate::new(200).set_body_string("{not-json"))
            .expect(1)
            .mount(&server)
            .await;

        let result = client.check_name("owner.package-name").await;

        assert!(matches!(
            result,
            Err(LpmError::Registry(message))
                if message.contains("failed to parse JSON")
                    && message.contains("/api/registry/check-name?name=owner.package-name")
        ));
    }

    #[tokio::test]
    async fn publish_package_returns_http_500_when_version_missing_after_500() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let (client, _tmp) = client_with_mock_server(&server.uri());
        let encoded_name = "@lpm.dev/test.publish-missing";

        Mock::given(method("PUT"))
            .and(path("/api/registry/@lpm.dev/test.publish-missing"))
            .respond_with(ResponseTemplate::new(500).set_body_string("publish boom"))
            .expect(1)
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path("/api/registry/@lpm.dev/test.publish-missing"))
            .respond_with(ResponseTemplate::new(404))
            .expect(1)
            .mount(&server)
            .await;

        let result = client
            .publish_package(
                encoded_name,
                &serde_json::json!({ "name": encoded_name }),
                None,
                0,
            )
            .await;

        assert!(matches!(
            result,
            Err(LpmError::Http { status: 500, message }) if message == "publish boom"
        ));
    }

    #[tokio::test]
    async fn batch_metadata_json_keeps_valid_entries_when_some_are_malformed() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let (client, _tmp) = client_with_mock_server(&server.uri());
        let valid_name = "express";
        let valid_metadata: serde_json::Value =
            serde_json::from_str(&test_metadata_json(valid_name)).expect("valid metadata json");

        Mock::given(method("POST"))
            .and(path("/api/registry/batch-metadata"))
            .respond_with(
                ResponseTemplate::new(200)
                    .append_header("content-type", "application/json")
                    .set_body_json(serde_json::json!({
                        "packages": {
                            valid_name: valid_metadata,
                            "broken-package": {
                                "description": "missing required name"
                            }
                        }
                    })),
            )
            .expect(1)
            .mount(&server)
            .await;

        let result = client
            .batch_metadata(&[valid_name.to_string(), "broken-package".to_string()])
            .await
            .expect("partial JSON batch response should still succeed");

        assert_eq!(result.len(), 1);
        assert_eq!(result[valid_name].name, valid_name);
        assert!(!result.contains_key("broken-package"));
    }

    #[tokio::test]
    async fn batch_metadata_sends_bearer_auth_header_when_token_is_present() {
        use wiremock::matchers::{body_string_contains, header, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let (client, _tmp) = client_with_mock_server(&server.uri());
        let client = client.with_token("batch-auth-token");
        let valid_name = "express";
        let valid_metadata: serde_json::Value =
            serde_json::from_str(&test_metadata_json(valid_name)).expect("valid metadata json");

        Mock::given(method("POST"))
            .and(path("/api/registry/batch-metadata"))
            .and(header("authorization", "Bearer batch-auth-token"))
            .and(body_string_contains("\"packages\":[\"express\"]"))
            .respond_with(
                ResponseTemplate::new(200)
                    .append_header("content-type", "application/json")
                    .set_body_json(serde_json::json!({
                        "packages": {
                            valid_name: valid_metadata,
                        }
                    })),
            )
            .expect(1)
            .mount(&server)
            .await;

        let result = client
            .batch_metadata(&[valid_name.to_string()])
            .await
            .expect("batch metadata should succeed with bearer auth header");

        assert_eq!(result.len(), 1);
        assert_eq!(result[valid_name].name, valid_name);
    }

    #[tokio::test]
    async fn batch_metadata_omits_auth_header_when_token_is_absent() {
        use wiremock::matchers::{body_string_contains, method, path};
        use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

        #[derive(Clone)]
        struct RejectAuthHeaderResponder {
            response_body: serde_json::Value,
        }

        impl Respond for RejectAuthHeaderResponder {
            fn respond(&self, request: &Request) -> ResponseTemplate {
                if request.headers.contains_key("authorization") {
                    ResponseTemplate::new(400).set_body_string("unexpected authorization header")
                } else {
                    ResponseTemplate::new(200)
                        .append_header("content-type", "application/json")
                        .set_body_json(self.response_body.clone())
                }
            }
        }

        let server = MockServer::start().await;
        let (client, _tmp) = client_with_mock_server(&server.uri());
        let valid_name = "express";
        let valid_metadata: serde_json::Value =
            serde_json::from_str(&test_metadata_json(valid_name)).expect("valid metadata json");

        Mock::given(method("POST"))
            .and(path("/api/registry/batch-metadata"))
            .and(body_string_contains("\"packages\":[\"express\"]"))
            .respond_with(RejectAuthHeaderResponder {
                response_body: serde_json::json!({
                    "packages": {
                        valid_name: valid_metadata,
                    }
                }),
            })
            .expect(1)
            .mount(&server)
            .await;

        let result = client
            .batch_metadata(&[valid_name.to_string()])
            .await
            .expect("anonymous batch metadata should not send an authorization header");

        assert_eq!(result.len(), 1);
        assert_eq!(result[valid_name].name, valid_name);
    }

    #[tokio::test]
    async fn batch_metadata_json_missing_packages_field_returns_parse_error() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let (client, _tmp) = client_with_mock_server(&server.uri());

        Mock::given(method("POST"))
            .and(path("/api/registry/batch-metadata"))
            .respond_with(
                ResponseTemplate::new(200)
                    .append_header("content-type", "application/json")
                    .set_body_json(serde_json::json!({
                        "status": "ok"
                    })),
            )
            .expect(1)
            .mount(&server)
            .await;

        let result = client.batch_metadata(&["express".to_string()]).await;

        assert!(matches!(
            result,
            Err(LpmError::Registry(message)) if message == "batch response missing packages"
        ));
    }

    #[tokio::test]
    async fn batch_metadata_json_skips_mismatched_package_identity_and_does_not_cache_it() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let (client, _tmp) = client_with_mock_server(&server.uri());
        let requested_name = "express";
        let wrong_name = "lodash";
        let wrong_metadata: serde_json::Value =
            serde_json::from_str(&test_metadata_json(wrong_name)).expect("valid metadata json");

        Mock::given(method("POST"))
            .and(path("/api/registry/batch-metadata"))
            .respond_with(
                ResponseTemplate::new(200)
                    .append_header("content-type", "application/json")
                    .set_body_json(serde_json::json!({
                        "packages": {
                            requested_name: wrong_metadata,
                        }
                    })),
            )
            .expect(1)
            .mount(&server)
            .await;

        let result = client
            .batch_metadata(&[requested_name.to_string()])
            .await
            .expect("mismatched JSON batch entries should be ignored, not fail the whole batch");

        assert!(
            result.is_empty(),
            "mismatched metadata should not be returned"
        );
        assert!(
            client
                .read_metadata_cache(&format!("npm:{requested_name}"))
                .is_none(),
            "mismatched metadata should not poison the requested package cache"
        );
    }

    #[tokio::test]
    async fn batch_metadata_ndjson_keeps_valid_entries_when_some_lines_are_malformed() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let (client, _tmp) = client_with_mock_server(&server.uri());
        let valid_name = "lodash";
        let valid_metadata: serde_json::Value =
            serde_json::from_str(&test_metadata_json(valid_name)).expect("valid metadata json");
        let ndjson_body = format!(
            "{}\n{}\n{}\n",
            serde_json::json!({
                "name": valid_name,
                "metadata": valid_metadata,
            }),
            serde_json::json!({
                "name": "broken-line",
                "metadata": {
                    "description": "missing required name"
                }
            }),
            "{not-json"
        );

        Mock::given(method("POST"))
            .and(path("/api/registry/batch-metadata"))
            .respond_with(
                ResponseTemplate::new(200).set_body_raw(ndjson_body, "application/x-ndjson"),
            )
            .expect(1)
            .mount(&server)
            .await;

        let result = client
            .batch_metadata(&[valid_name.to_string(), "broken-line".to_string()])
            .await
            .expect("partial NDJSON batch response should still succeed");

        assert_eq!(result.len(), 1);
        assert_eq!(result[valid_name].name, valid_name);
        assert!(!result.contains_key("broken-line"));
    }

    #[tokio::test]
    async fn batch_metadata_ndjson_parses_final_line_without_trailing_newline() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let (client, _tmp) = client_with_mock_server(&server.uri());
        let valid_name = "chalk";
        let valid_metadata: serde_json::Value =
            serde_json::from_str(&test_metadata_json(valid_name)).expect("valid metadata json");
        let ndjson_body = serde_json::json!({
            "name": valid_name,
            "metadata": valid_metadata,
        })
        .to_string();

        Mock::given(method("POST"))
            .and(path("/api/registry/batch-metadata"))
            .respond_with(
                ResponseTemplate::new(200).set_body_raw(ndjson_body, "application/x-ndjson"),
            )
            .expect(1)
            .mount(&server)
            .await;

        let result = client
            .batch_metadata(&[valid_name.to_string()])
            .await
            .expect("NDJSON batch without trailing newline should still parse final line");

        assert_eq!(result.len(), 1);
        assert_eq!(result[valid_name].name, valid_name);
    }

    #[tokio::test]
    async fn batch_metadata_ndjson_parses_line_split_across_http_chunks() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;
        use tokio::time::{Duration, sleep};

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = vec![0u8; 4096];
            let _ = stream.read(&mut request).await.unwrap();

            let metadata_json = test_metadata_json("kleur");
            let line = format!("{{\"name\":\"kleur\",\"metadata\":{metadata_json}}}\n");
            let split_at = line.find("\"metadata\"").unwrap();
            let chunks = [
                &line[..split_at],
                &line[split_at..split_at + 17],
                &line[split_at + 17..],
            ];

            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: application/x-ndjson\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
                )
                .await
                .unwrap();

            for chunk in chunks {
                let header = format!("{:X}\r\n", chunk.len());
                stream.write_all(header.as_bytes()).await.unwrap();
                stream.write_all(chunk.as_bytes()).await.unwrap();
                stream.write_all(b"\r\n").await.unwrap();
                stream.flush().await.unwrap();
                sleep(Duration::from_millis(10)).await;
            }

            stream.write_all(b"0\r\n\r\n").await.unwrap();
            stream.flush().await.unwrap();
        });

        let (client, _tmp) = client_with_mock_server(&format!("http://{address}"));
        let result = client
            .batch_metadata(&["kleur".to_string()])
            .await
            .expect("NDJSON parser should handle lines split across chunk boundaries");

        assert_eq!(result.len(), 1);
        assert_eq!(result["kleur"].name, "kleur");
        assert!(
            client.read_metadata_cache("npm:kleur").is_some(),
            "chunk-split NDJSON entries should still warm the metadata cache"
        );

        server.await.unwrap();
    }

    #[tokio::test]
    async fn batch_metadata_ndjson_parses_utf8_split_across_http_chunks() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;
        use tokio::time::{Duration, sleep};

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = vec![0u8; 4096];
            let _ = stream.read(&mut request).await.unwrap();

            let mut metadata: serde_json::Value =
                serde_json::from_str(&test_metadata_json("kleur")).unwrap();
            metadata["description"] = serde_json::json!("snowman ☃ package");
            let line = serde_json::json!({
                "name": "kleur",
                "metadata": metadata,
            })
            .to_string()
                + "\n";
            let bytes = line.as_bytes();
            let split_start = bytes
                .windows("☃".len())
                .position(|window| window == "☃".as_bytes())
                .unwrap();
            let chunks = [
                &bytes[..split_start + 1],
                &bytes[split_start + 1..split_start + 2],
                &bytes[split_start + 2..],
            ];

            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: application/x-ndjson\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
                )
                .await
                .unwrap();

            for chunk in chunks {
                let header = format!("{:X}\r\n", chunk.len());
                stream.write_all(header.as_bytes()).await.unwrap();
                stream.write_all(chunk).await.unwrap();
                stream.write_all(b"\r\n").await.unwrap();
                stream.flush().await.unwrap();
                sleep(Duration::from_millis(10)).await;
            }

            stream.write_all(b"0\r\n\r\n").await.unwrap();
            stream.flush().await.unwrap();
        });

        let (client, _tmp) = client_with_mock_server(&format!("http://{address}"));
        let result = client
            .batch_metadata(&["kleur".to_string()])
            .await
            .expect("NDJSON parser should handle UTF-8 sequences split across chunk boundaries");

        assert_eq!(result.len(), 1);
        assert_eq!(result["kleur"].name, "kleur");
        assert_eq!(
            result["kleur"].description.as_deref(),
            Some("snowman ☃ package")
        );

        server.await.unwrap();
    }

    #[tokio::test]
    async fn batch_metadata_ndjson_ignores_truncated_final_line_after_valid_entries() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let (client, _tmp) = client_with_mock_server(&server.uri());
        let valid_name = "kleur";
        let valid_metadata: serde_json::Value =
            serde_json::from_str(&test_metadata_json(valid_name)).expect("valid metadata json");
        let ndjson_body = format!(
            "{}\n{{\"name\":\"broken-final\",\"metadata\":",
            serde_json::json!({
                "name": valid_name,
                "metadata": valid_metadata,
            })
        );

        Mock::given(method("POST"))
            .and(path("/api/registry/batch-metadata"))
            .respond_with(
                ResponseTemplate::new(200).set_body_raw(ndjson_body, "application/x-ndjson"),
            )
            .expect(1)
            .mount(&server)
            .await;

        let result = client
            .batch_metadata(&[valid_name.to_string(), "broken-final".to_string()])
            .await
            .expect("truncated trailing NDJSON should preserve already parsed metadata");

        assert_eq!(result.len(), 1);
        assert_eq!(result[valid_name].name, valid_name);
        assert!(!result.contains_key("broken-final"));
    }

    #[tokio::test]
    async fn batch_metadata_ndjson_skips_mismatched_package_identity_and_does_not_cache_it() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let (client, _tmp) = client_with_mock_server(&server.uri());
        let requested_name = "express";
        let wrong_name = "lodash";
        let wrong_metadata: serde_json::Value =
            serde_json::from_str(&test_metadata_json(wrong_name)).expect("valid metadata json");
        let ndjson_body = serde_json::json!({
            "name": requested_name,
            "metadata": wrong_metadata,
        })
        .to_string();

        Mock::given(method("POST"))
            .and(path("/api/registry/batch-metadata"))
            .respond_with(
                ResponseTemplate::new(200).set_body_raw(ndjson_body, "application/x-ndjson"),
            )
            .expect(1)
            .mount(&server)
            .await;

        let result = client
            .batch_metadata(&[requested_name.to_string()])
            .await
            .expect("mismatched NDJSON entries should be ignored, not fail the whole batch");

        assert!(
            result.is_empty(),
            "mismatched metadata should not be returned"
        );
        assert!(
            client
                .read_metadata_cache(&format!("npm:{requested_name}"))
                .is_none(),
            "mismatched metadata should not poison the requested package cache"
        );
    }

    #[tokio::test]
    async fn batch_metadata_json_truncated_body_returns_parse_error() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let (client, _tmp) = client_with_mock_server(&server.uri());

        Mock::given(method("POST"))
            .and(path("/api/registry/batch-metadata"))
            .respond_with(
                ResponseTemplate::new(200)
                    .append_header("content-type", "application/json")
                    .set_body_raw("{\"packages\":{\"express\":", "application/json"),
            )
            .expect(1)
            .mount(&server)
            .await;

        let result = client.batch_metadata(&["express".to_string()]).await;

        assert!(matches!(
            result,
            Err(LpmError::Registry(message)) if message.contains("batch metadata") && message.contains("failed to parse JSON")
        ));
    }

    // `constant_time_hmac_rejects_tampered_cache` was removed when HMAC was
    // dropped. The replacement contract — reject entries that don't begin with
    // `METADATA_CACHE_MAGIC` — is covered by
    // `cache_miss_on_truncated_or_unmagic_content` above.

    // ─── Bounded-memory download tests ───────────────────────────────

    #[tokio::test]
    async fn download_to_file_streams_and_hashes() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let (client, _tmp) = client_with_mock_server(&server.uri());

        // Small "tarball" body (doesn't need to be valid gzip for this test)
        let body = b"fake-tarball-content-for-hash-test";

        Mock::given(method("GET"))
            .and(path("/tarball/pkg-1.0.0.tgz"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(body.to_vec()))
            .expect(1)
            .mount(&server)
            .await;

        let url = format!("{}/tarball/pkg-1.0.0.tgz", server.uri());
        let downloaded = client.download_tarball_to_file(&url).await.unwrap();

        // Verify file exists and has correct size
        assert_eq!(downloaded.compressed_size, body.len() as u64);

        // Verify file content matches
        let file_content = std::fs::read(downloaded.file.path()).unwrap();
        assert_eq!(file_content, body);

        // Verify SRI hash is correct
        use base64::Engine;
        use sha2::{Digest, Sha512};
        let mut hasher = Sha512::new();
        hasher.update(body);
        let expected_sri = format!(
            "sha512-{}",
            base64::engine::general_purpose::STANDARD.encode(hasher.finalize())
        );
        assert_eq!(downloaded.sri, expected_sri);
    }

    #[tokio::test]
    async fn download_to_file_rejects_oversized_tarball() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let (client, _tmp) = client_with_mock_server(&server.uri());

        // Send 2KB body but set limit to 1KB — exercises the real rejection path
        let body = vec![0u8; 2048];

        Mock::given(method("GET"))
            .and(path("/tarball/oversized.tgz"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(body))
            .expect(1)
            .mount(&server)
            .await;

        let url = format!("{}/tarball/oversized.tgz", server.uri());
        let result = client.download_tarball_to_file_with_limit(&url, 1024).await;

        assert!(result.is_err(), "oversized tarball should be rejected");
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("exceeds maximum compressed size"),
            "error should mention size limit: {msg}"
        );
        assert!(
            msg.contains("1024"),
            "error should mention the limit value: {msg}"
        );
    }

    #[tokio::test]
    async fn download_to_file_rejects_oversized_content_length_before_streaming() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let (client, _tmp) = client_with_mock_server(&server.uri());
        let body = vec![7u8; 2048];

        Mock::given(method("GET"))
            .and(path("/tarball/header-oversized.tgz"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(body))
            .expect(1)
            .mount(&server)
            .await;

        let url = format!("{}/tarball/header-oversized.tgz", server.uri());
        let result = client.download_tarball_to_file_with_limit(&url, 1024).await;

        assert!(
            result.is_err(),
            "oversized content-length should be rejected before streaming"
        );
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("Content-Length"),
            "error should mention Content-Length preflight enforcement: {msg}"
        );
        assert!(
            msg.contains("2048"),
            "error should mention the announced size: {msg}"
        );
        assert!(
            msg.contains("1024"),
            "error should mention the configured limit: {msg}"
        );
    }

    #[tokio::test]
    async fn download_to_file_maps_404_to_not_found_with_body() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let (client, _tmp) = client_with_mock_server(&server.uri());

        Mock::given(method("GET"))
            .and(path("/tarball/missing.tgz"))
            .respond_with(ResponseTemplate::new(404).set_body_string("missing tarball"))
            .expect(1)
            .mount(&server)
            .await;

        let url = format!("{}/tarball/missing.tgz", server.uri());
        let result = client.download_tarball_to_file(&url).await;

        assert!(matches!(result, Err(LpmError::NotFound(body)) if body == "missing tarball"));
    }

    #[tokio::test]
    async fn download_to_file_retries_429_and_sends_bearer_auth_header() {
        use wiremock::matchers::{header, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let (client, _tmp) = client_with_mock_server(&server.uri());
        let client = client.with_token("download-auth-token");

        Mock::given(method("GET"))
            .and(path("/tarball/rate-limited.tgz"))
            .and(header("authorization", "Bearer download-auth-token"))
            .respond_with(ResponseTemplate::new(429).append_header("retry-after", "0"))
            .expect(4)
            .mount(&server)
            .await;

        let url = format!("{}/tarball/rate-limited.tgz", server.uri());
        let result = client.download_tarball_to_file(&url).await;

        assert!(matches!(
            result,
            Err(LpmError::RateLimited {
                retry_after_secs: 0
            })
        ));
    }

    #[tokio::test]
    async fn download_to_file_retries_503_then_succeeds() {
        use std::sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        };
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

        #[derive(Clone)]
        struct DownloadRetryResponder {
            calls: Arc<AtomicUsize>,
        }

        impl Respond for DownloadRetryResponder {
            fn respond(&self, _request: &Request) -> ResponseTemplate {
                let call_index = self.calls.fetch_add(1, Ordering::SeqCst);
                if call_index == 0 {
                    ResponseTemplate::new(503).set_body_string("temporary tarball outage")
                } else {
                    ResponseTemplate::new(200).set_body_bytes(b"retry-success-body".to_vec())
                }
            }
        }

        let server = MockServer::start().await;
        let (client, _tmp) = client_with_mock_server(&server.uri());
        let calls = Arc::new(AtomicUsize::new(0));

        Mock::given(method("GET"))
            .and(path("/tarball/retry-503.tgz"))
            .respond_with(DownloadRetryResponder {
                calls: Arc::clone(&calls),
            })
            .expect(2)
            .mount(&server)
            .await;

        let url = format!("{}/tarball/retry-503.tgz", server.uri());
        let downloaded = client
            .download_tarball_to_file(&url)
            .await
            .expect("download should succeed after retrying 503");

        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(
            downloaded.compressed_size,
            b"retry-success-body".len() as u64
        );
        let file_content = std::fs::read(downloaded.file.path()).unwrap();
        assert_eq!(file_content, b"retry-success-body");
    }

    #[tokio::test]
    async fn download_to_file_retries_500_then_succeeds() {
        use std::sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        };
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

        #[derive(Clone)]
        struct Download500RetryResponder {
            calls: Arc<AtomicUsize>,
        }

        impl Respond for Download500RetryResponder {
            fn respond(&self, _request: &Request) -> ResponseTemplate {
                let call_index = self.calls.fetch_add(1, Ordering::SeqCst);
                if call_index == 0 {
                    ResponseTemplate::new(500).set_body_string("temporary tarball 500")
                } else {
                    ResponseTemplate::new(200).set_body_bytes(b"retry-500-success".to_vec())
                }
            }
        }

        let server = MockServer::start().await;
        let (client, _tmp) = client_with_mock_server(&server.uri());
        let calls = Arc::new(AtomicUsize::new(0));

        Mock::given(method("GET"))
            .and(path("/tarball/retry-500.tgz"))
            .respond_with(Download500RetryResponder {
                calls: Arc::clone(&calls),
            })
            .expect(2)
            .mount(&server)
            .await;

        let url = format!("{}/tarball/retry-500.tgz", server.uri());
        let downloaded = client
            .download_tarball_to_file(&url)
            .await
            .expect("download should succeed after retrying a transient 500");

        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(
            downloaded.compressed_size,
            b"retry-500-success".len() as u64
        );
        let file_content = std::fs::read(downloaded.file.path()).unwrap();
        assert_eq!(file_content, b"retry-500-success");
    }

    #[tokio::test]
    async fn download_to_file_surfaces_chunk_read_failures() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("failed to bind raw http test server");
        let addr = listener
            .local_addr()
            .expect("raw http test server should have a local addr");

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener
                .accept()
                .await
                .expect("raw http test server should accept a request");

            let mut request_buf = [0u8; 1024];
            let _ = stream.read(&mut request_buf).await;

            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n5\r\nhello\r\nZZZ\r\n",
                )
                .await
                .expect("raw http test server should write malformed chunked body");
            let _ = stream.shutdown().await;
        });

        let client = RegistryClient::new();
        let url = format!("http://127.0.0.1:{}/tarball/broken-chunks.tgz", addr.port());
        let result = client.download_tarball_to_file(&url).await;

        server
            .await
            .expect("raw http test server task should complete cleanly");

        assert!(
            result.is_err(),
            "broken chunked bodies should fail the download"
        );
        let message = result.unwrap_err().to_string();
        assert!(
            message.contains("failed to read tarball chunk"),
            "chunked transfer parse errors should surface as tarball chunk read failures: {message}"
        );
    }

    #[tokio::test]
    async fn download_to_file_surfaces_truncated_content_length_interruptions() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("failed to bind raw http interruption server");
        let addr = listener
            .local_addr()
            .expect("interruption server should have a local addr");

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener
                .accept()
                .await
                .expect("interruption server should accept a request");

            let mut request_buf = [0u8; 1024];
            let _ = stream.read(&mut request_buf).await;

            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\nConnection: close\r\n\r\nhello",
                )
                .await
                .expect("interruption server should write partial body");
            let _ = stream.shutdown().await;
        });

        let client = RegistryClient::new();
        let url = format!(
            "http://127.0.0.1:{}/tarball/truncated-body.tgz",
            addr.port()
        );
        let result = client.download_tarball_to_file(&url).await;

        server
            .await
            .expect("interruption server task should complete cleanly");

        assert!(
            result.is_err(),
            "truncated content-length bodies should fail the download"
        );
        let message = result.unwrap_err().to_string();
        assert!(
            message.contains("failed to read tarball chunk"),
            "mid-body interruptions should surface as tarball chunk read failures: {message}"
        );
    }

    #[test]
    fn write_tarball_chunk_maps_io_failures() {
        struct FailingWriter;

        impl std::io::Write for FailingWriter {
            fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "disk full in test",
                ))
            }

            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let result = write_tarball_chunk(&mut FailingWriter, b"chunk-data");

        assert!(matches!(
            result,
            Err(LpmError::Io(error))
                if error.kind() == std::io::ErrorKind::PermissionDenied
                    && error
                        .to_string()
                        .contains("failed to write tarball chunk to temp file: disk full in test")
        ));
    }

    #[test]
    fn flush_tarball_file_maps_io_failures() {
        struct FlushFailingWriter;

        impl std::io::Write for FlushFailingWriter {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                Ok(buf.len())
            }

            fn flush(&mut self) -> std::io::Result<()> {
                Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "flush failed in test",
                ))
            }
        }

        let result = flush_tarball_file(&mut FlushFailingWriter);

        assert!(matches!(
            result,
            Err(LpmError::Io(error))
                if error.kind() == std::io::ErrorKind::BrokenPipe
                    && error
                        .to_string()
                        .contains("failed to flush tarball temp file: flush failed in test")
        ));
    }

    #[tokio::test]
    async fn download_to_file_accepts_within_limit() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let (client, _tmp) = client_with_mock_server(&server.uri());

        let body = vec![0u8; 512];

        Mock::given(method("GET"))
            .and(path("/tarball/small.tgz"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(body))
            .expect(1)
            .mount(&server)
            .await;

        let url = format!("{}/tarball/small.tgz", server.uri());
        let result = client.download_tarball_to_file_with_limit(&url, 1024).await;

        assert!(result.is_ok(), "tarball within limit should succeed");
        assert_eq!(result.unwrap().compressed_size, 512);
    }

    #[tokio::test]
    async fn download_to_file_temp_file_cleaned_on_drop() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let (client, _tmp) = client_with_mock_server(&server.uri());

        Mock::given(method("GET"))
            .and(path("/tarball/cleanup.tgz"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"data".to_vec()))
            .expect(1)
            .mount(&server)
            .await;

        let url = format!("{}/tarball/cleanup.tgz", server.uri());
        let temp_path;
        {
            let downloaded = client.download_tarball_to_file(&url).await.unwrap();
            temp_path = downloaded.file.path().to_path_buf();
            assert!(temp_path.exists(), "temp file should exist during download");
        }
        // DownloadedTarball dropped — NamedTempFile auto-deletes
        assert!(
            !temp_path.exists(),
            "temp file should be cleaned up after drop"
        );
    }

    #[tokio::test]
    async fn download_to_file_hash_mismatch_detected_by_caller() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let (client, _tmp) = client_with_mock_server(&server.uri());

        Mock::given(method("GET"))
            .and(path("/tarball/tampered.tgz"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"real-content".to_vec()))
            .expect(1)
            .mount(&server)
            .await;

        let url = format!("{}/tarball/tampered.tgz", server.uri());
        let downloaded = client.download_tarball_to_file(&url).await.unwrap();

        // The download itself always succeeds — hash mismatch is detected by
        // the caller comparing downloaded.sri against expected integrity.
        let wrong_integrity = "sha512-AAAAAAAAAA==";
        assert_ne!(
            downloaded.sri, wrong_integrity,
            "hash should not match tampered expectation"
        );
    }

    #[tokio::test]
    async fn download_to_file_rejects_http_non_localhost_without_insecure() {
        let client = RegistryClient::new();
        let result = client
            .download_tarball_to_file("http://evil.com/pkg.tgz")
            .await;
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("HTTPS"), "should mention HTTPS requirement");
        assert!(
            msg.contains("--insecure"),
            "error should hint at --insecure flag: {msg}"
        );
    }

    #[tokio::test]
    async fn download_tarball_streaming_rejects_http_without_insecure() {
        let client = RegistryClient::new();
        let result = client
            .download_tarball_streaming("http://evil.com/pkg.tgz")
            .await;
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("HTTPS"), "should mention HTTPS requirement");
        assert!(
            msg.contains("--insecure"),
            "error should hint at --insecure flag: {msg}"
        );
    }

    #[tokio::test]
    async fn download_to_file_rejects_localhost_prefix_attack_domain() {
        let client = RegistryClient::new();
        let result = client
            .download_tarball_to_file("http://localhost.evil.com/pkg.tgz")
            .await;
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("HTTPS"), "should mention HTTPS requirement");
    }

    // ─── AuthPosture + recovery contract ─────────────────────────────────────

    #[test]
    fn auth_posture_attaches_bearer_only_for_auth_or_session() {
        assert!(!AuthPosture::AnonymousOnly.attaches_bearer());
        assert!(!AuthPosture::AnonymousPreferred.attaches_bearer());
        assert!(AuthPosture::AuthRequired.attaches_bearer());
        assert!(AuthPosture::SessionRequired.attaches_bearer());
    }

    #[test]
    fn auth_posture_allows_recovery_only_for_auth_or_session() {
        assert!(!AuthPosture::AnonymousOnly.allows_recovery());
        assert!(!AuthPosture::AnonymousPreferred.allows_recovery());
        assert!(AuthPosture::AuthRequired.allows_recovery());
        assert!(AuthPosture::SessionRequired.allows_recovery());
    }

    #[test]
    fn current_bearer_returns_none_for_anonymous_postures_even_with_token() {
        let client = RegistryClient::new().with_token("real-token");
        assert!(
            client.current_bearer(AuthPosture::AnonymousOnly).is_none(),
            "AnonymousOnly must never attach a bearer"
        );
        assert!(
            client
                .current_bearer(AuthPosture::AnonymousPreferred)
                .is_none(),
            "AnonymousPreferred must never attach a bearer"
        );
    }

    #[test]
    fn current_bearer_returns_token_for_auth_required_when_set() {
        let client = RegistryClient::new().with_token("real-token");
        assert_eq!(
            client.current_bearer(AuthPosture::AuthRequired),
            Some("real-token".to_string())
        );
        assert_eq!(
            client.current_bearer(AuthPosture::SessionRequired),
            Some("real-token".to_string())
        );
    }

    #[test]
    fn current_bearer_filters_empty_token() {
        // Empty bearer must never be sent — `current_bearer` returns
        // None even if `with_token("")` was called.
        let client = RegistryClient::new().with_token("");
        assert!(client.current_bearer(AuthPosture::AuthRequired).is_none());
    }

    #[tokio::test]
    async fn execute_with_recovery_propagates_success_unchanged() {
        let client = RegistryClient::new();
        let count = std::sync::atomic::AtomicU32::new(0);
        let result = client
            .execute_with_recovery(AuthPosture::AuthRequired, || async {
                count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Ok::<_, LpmError>(42u32)
            })
            .await;
        assert_eq!(result.unwrap(), 42);
        assert_eq!(count.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn execute_with_recovery_does_not_retry_anonymous_postures() {
        let client = RegistryClient::new();
        let count = std::sync::atomic::AtomicU32::new(0);
        let result = client
            .execute_with_recovery(AuthPosture::AnonymousPreferred, || async {
                count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Err::<u32, _>(LpmError::AuthRequired)
            })
            .await;
        assert!(matches!(result, Err(LpmError::AuthRequired)));
        // Anonymous postures never retry — exactly one attempt.
        assert_eq!(count.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn execute_with_recovery_does_not_retry_when_no_session() {
        let client = RegistryClient::new().with_token("static-token");
        let count = std::sync::atomic::AtomicU32::new(0);
        let result = client
            .execute_with_recovery(AuthPosture::AuthRequired, || async {
                count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Err::<u32, _>(LpmError::AuthRequired)
            })
            .await;
        assert!(matches!(result, Err(LpmError::AuthRequired)));
        // No session attached → no refresh is even attempted.
        assert_eq!(count.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    /// Wire-layer empty-bearer regression: no request must ever send
    /// `Authorization: Bearer ` (empty value) headers. `with_token("")`
    /// followed by an actual HTTP request must NOT surface an Authorization
    /// header on the wire.
    #[tokio::test]
    async fn empty_bearer_never_appears_on_the_wire() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/registry/-/whoami"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": "u_test",
                "username": "test",
                "scope": "user",
                "scopes": ["registry:read"],
            })))
            .mount(&server)
            .await;

        // The pathological case: a caller threaded `unwrap_or_default()`
        // on a missing token and seeded the client with `""`.
        // `current_bearer` must filter this so `bearer_auth("")` is
        // never called.
        let client = RegistryClient::new()
            .with_base_url(server.uri())
            .with_token("");

        let _ = client.whoami().await; // outcome not the point — header is

        let received = server.received_requests().await.unwrap();
        assert_eq!(received.len(), 1, "exactly one request expected");
        let auth_header = received[0].headers.get("authorization");
        assert!(
            auth_header.is_none(),
            "with_token(\"\") must NOT produce an Authorization header on the wire — \
             pre-fix, this site sent literal `Authorization: Bearer ` (empty value), \
             which the server logs as a malformed-auth attempt. Got: {auth_header:?}"
        );
    }

    // ─── streaming NDJSON body timeout ────────────────────────────────────────
    //
    // `RegistryClient::new` uses `.connect_timeout() + .read_timeout()` rather
    // than `.timeout()`. `.timeout()` is a wall-clock cap over the entire
    // request+response cycle including body read, which fires mid-body on large
    // NDJSON responses from slow servers. `.read_timeout()` is a per-read idle
    // timer that resets on each successful chunk, so a slow-but-progressing
    // stream completes cleanly; a genuinely stalled server still gets
    // interrupted.
    //
    // The regression test below drives a slow streaming mock server through a
    // client configured with a 500 ms read_timeout + 500 ms connect_timeout.
    // Each chunk arrives within ~300 ms so the read_timeout never fires, but
    // the aggregate response time exceeds both timeouts by 6×.

    /// Bind a localhost TCP listener, return `(url, join_handle)`. The
    /// spawned task accepts ONE connection, reads until end-of-headers,
    /// and writes a chunked-encoded NDJSON response. Lines are emitted
    /// every `chunk_interval`; total stream time is
    /// `chunk_interval * line_count`.
    async fn slow_streaming_ndjson_server(
        packages: Vec<String>,
        chunk_interval: std::time::Duration,
    ) -> (String, tokio::task::JoinHandle<()>) {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind listener");
        let addr = listener.local_addr().expect("addr");
        let base_url = format!("http://{addr}");

        let handle = tokio::spawn(async move {
            let (stream, _peer) = listener.accept().await.expect("accept");
            let (read_half, mut write_half) = stream.into_split();

            // Skim the request line + headers until the blank line. We
            // don't validate — just need to clear the buffer so the
            // server appears HTTP-compliant.
            let mut reader = BufReader::new(read_half);
            let mut line = String::new();
            while reader
                .read_line(&mut line)
                .await
                .expect("read request line")
                > 0
            {
                let is_blank = line == "\r\n" || line == "\n";
                line.clear();
                if is_blank {
                    break;
                }
            }

            // Status + headers.
            write_half
                .write_all(
                    b"HTTP/1.1 200 OK\r\n\
                      Content-Type: application/x-ndjson\r\n\
                      Transfer-Encoding: chunked\r\n\r\n",
                )
                .await
                .expect("write status+headers");
            write_half.flush().await.expect("flush headers");

            // Stream one NDJSON line per chunk, sleeping between.
            for name in packages {
                let body = serde_json::json!({
                    "name": &name,
                    "metadata": {
                        "name": &name,
                        "description": "test package",
                        "dist-tags": { "latest": "1.0.0" },
                        "versions": {
                            "1.0.0": {
                                "name": &name,
                                "version": "1.0.0",
                                "dist": {
                                    "tarball": "https://example.com/pkg-1.0.0.tgz",
                                    "integrity": "sha512-test"
                                },
                                "dependencies": {}
                            }
                        }
                    }
                })
                .to_string();
                let line = format!("{body}\n");
                let chunk = format!("{:x}\r\n{}\r\n", line.len(), line);
                write_half
                    .write_all(chunk.as_bytes())
                    .await
                    .expect("write chunk");
                write_half.flush().await.expect("flush chunk");
                tokio::time::sleep(chunk_interval).await;
            }

            // Terminating zero-length chunk + trailing CRLF.
            write_half
                .write_all(b"0\r\n\r\n")
                .await
                .expect("write terminator");
            write_half.flush().await.expect("flush terminator");
        });

        (base_url, handle)
    }

    #[tokio::test]
    async fn batch_metadata_deep_tolerates_slow_streaming_body_under_read_timeout() {
        // Client scoped tight: connect_timeout = read_timeout = 500 ms.
        // Any individual chunk gap > 500 ms would trip read_timeout and
        // fail the test — the stream server intentionally stays under
        // that bound by sending every 300 ms.
        let tmp = tempfile::tempdir().expect("temp dir");
        let short = std::time::Duration::from_millis(500);
        let http_default = RegistryClient::build_http_client(short, short);

        // Stream 4 NDJSON lines at 200 ms apart → 800 ms wall-clock
        // total. That's ~1.6× the 500 ms window a wall-clock
        // `.timeout()` would have enforced. With `read_timeout`, the
        // per-chunk window resets on each chunk so the full body arrives
        // intact. Kept short so the test itself stays under 1 s.
        let packages: Vec<String> = (0..4).map(|i| format!("slow-pkg-{i}")).collect();
        let (base_url, server_handle) =
            slow_streaming_ndjson_server(packages.clone(), std::time::Duration::from_millis(200))
                .await;

        let mut client = RegistryClient::new().with_base_url(&base_url);
        // `http` is `Arc<HttpClients>`. Wrap the short-timeout default
        // client in a fresh HttpClients shell.
        client.http = HttpClients::from_default_client(http_default);
        client.cache_dir = Some(tmp.path().to_path_buf());

        let started = std::time::Instant::now();
        let result = client.batch_metadata_deep(&packages).await;
        let elapsed = started.elapsed();

        server_handle.await.expect("server task completed");

        assert!(
            result.is_ok(),
            "slow-but-progressing stream must succeed with read_timeout; got {:?} after {elapsed:?}",
            result.err(),
        );
        let map = result.unwrap();
        assert_eq!(
            map.len(),
            4,
            "all 4 NDJSON entries should parse; got {}",
            map.len()
        );
        assert!(
            elapsed >= std::time::Duration::from_millis(700),
            "stream should take ~800 ms total (4 chunks × 200 ms); \
             got {elapsed:?}. If this is fast, the test isn't actually \
             exercising the long-stream case the fix targets."
        );
    }

    #[tokio::test]
    async fn batch_metadata_deep_fails_under_old_wallclock_timeout() {
        // Regression guard written in reverse: same slow streaming server the
        // happy-path test uses, but the client is built with `.timeout()` — a
        // wall-clock cap. The stream takes ~3 s total, the wall-clock is 500 ms,
        // so the request dies mid-body with a reqwest body decode error sourced
        // from `operation timed out`. This test deliberately invokes the reqwest
        // builder directly with the old API shape so the wire-level failure mode
        // stays visible: if someone re-introduces `.timeout(N)` on the prod
        // builder, this test is the spec that says "that path fails for
        // legitimately slow streams."
        let tmp = tempfile::tempdir().expect("temp dir");
        let old_style_http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_millis(500))
            .build()
            .expect("build client");

        // 4 chunks × 200 ms = 800 ms total stream, exceeding the
        // 500 ms wall-clock timeout by ~300 ms.
        let packages: Vec<String> = (0..4).map(|i| format!("wallclock-pkg-{i}")).collect();
        let (base_url, server_handle) =
            slow_streaming_ndjson_server(packages.clone(), std::time::Duration::from_millis(200))
                .await;

        let mut client = RegistryClient::new().with_base_url(&base_url);
        // Wrap the wall-clock-timeout client in HttpClients.
        client.http = HttpClients::from_default_client(old_style_http);
        client.cache_dir = Some(tmp.path().to_path_buf());

        let result = client.batch_metadata_deep(&packages).await;

        // Abort the server task — the client died mid-stream so the
        // server's `write_half.flush()` will return `BrokenPipe` on
        // some chunk. Abort prevents the spawned task from panicking
        // into the test harness with a misleading "write chunk" error
        // that looks like a test assertion failure.
        server_handle.abort();

        match result {
            Ok(map) => panic!(
                "wall-clock `.timeout()` should abort mid-body; \
                 instead got a successful map of {} entries. If this test \
                 now passes, either the reqwest API changed semantics \
                 (unlikely — `.timeout()` is still wall-clock in 0.12) \
                 or the streaming server finished faster than expected; \
                 re-check the timings.",
                map.len(),
            ),
            Err(LpmError::Registry(msg)) => {
                assert!(
                    msg.contains("timed out") || msg.contains("timeout"),
                    "error should mention the timeout, but was: {msg}"
                );
            }
            Err(other) => panic!("expected Registry timeout error, got {other:?}"),
        }
    }

    // ─── direct-tier fetch + parallel fan-out ─────────────────────────────────

    #[tokio::test]
    async fn get_npm_metadata_direct_skips_proxy_tier_entirely() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        // Two mock servers: proxy (= base_url, LPM Worker) and direct
        // npm registry. direct-tier fetch must hit ONLY the npm server.
        // If the implementation ever silently falls back through the
        // proxy tier, the proxy server's `expect(0)` will fail.
        let proxy_server = MockServer::start().await;
        let npm_server = MockServer::start().await;

        let pkg = "lodash";
        let body = test_metadata_json(pkg);

        // Proxy mock configured to fail the test if hit. `expect(0)` is
        // verified when the server is dropped.
        Mock::given(method("GET"))
            .and(path(format!("/api/registry/{pkg}")))
            .respond_with(ResponseTemplate::new(200).set_body_string(&body))
            .expect(0)
            .mount(&proxy_server)
            .await;

        Mock::given(method("GET"))
            .and(path(format!("/{pkg}")))
            .respond_with(ResponseTemplate::new(200).set_body_string(&body))
            .expect(1)
            .mount(&npm_server)
            .await;

        let tmp = tempfile::tempdir().expect("tmp");
        let mut client = RegistryClient::new()
            .with_base_url(proxy_server.uri())
            .with_npm_registry_url(npm_server.uri());
        client.cache_dir = Some(tmp.path().to_path_buf());

        let got = client
            .get_npm_metadata_direct(pkg)
            .await
            .expect("direct fetch should succeed");
        assert_eq!(got.name, pkg);
        // expectations verified when mocks are dropped — proxy must
        // have received 0 calls.
    }

    #[tokio::test]
    async fn parallel_fetch_preserves_input_order_across_varying_latencies() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let npm_server = MockServer::start().await;
        let proxy_server = MockServer::start().await;

        // Six packages. Configure inverted per-response delays so
        // package `aaa` (first input) is the slowest response — if the
        // fan-out returned in completion order, `aaa` would end up last.
        let names: Vec<String> = ["aaa", "bbb", "ccc", "ddd", "eee", "fff"]
            .into_iter()
            .map(String::from)
            .collect();

        for (i, name) in names.iter().enumerate() {
            let body = test_metadata_json(name);
            let delay = std::time::Duration::from_millis(50 * (names.len() - i) as u64);
            Mock::given(method("GET"))
                .and(path(format!("/{name}")))
                .respond_with(
                    ResponseTemplate::new(200)
                        .set_body_string(&body)
                        .set_delay(delay),
                )
                .mount(&npm_server)
                .await;
        }

        let tmp = tempfile::tempdir().expect("tmp");
        let mut client = RegistryClient::new()
            .with_base_url(proxy_server.uri())
            .with_npm_registry_url(npm_server.uri());
        client.cache_dir = Some(tmp.path().to_path_buf());
        let client = Arc::new(client);

        let (results, stats) = client.parallel_fetch_npm_manifests(&names, 6).await;

        assert_eq!(results.len(), names.len());
        for (input_name, (out_name, out_result)) in names.iter().zip(results.iter()) {
            assert_eq!(
                input_name, out_name,
                "fan-out must return entries in input order regardless of completion order"
            );
            assert!(
                out_result.is_ok(),
                "all {input_name} fetches should succeed; got {out_result:?}"
            );
        }
        assert_eq!(stats.halve_events, 0, "no 429s, no halving");
        assert_eq!(
            stats.final_concurrency, stats.initial_concurrency,
            "clean run must not shrink the pool"
        );
    }

    #[tokio::test]
    async fn parallel_fetch_per_entry_failures_do_not_abort_batch() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let npm_server = MockServer::start().await;
        let proxy_server = MockServer::start().await;

        // One name 404s, the rest succeed. The whole batch must still
        // return; the 404 surfaces as a per-entry Err, not a batch abort.
        Mock::given(method("GET"))
            .and(path("/exists-one"))
            .respond_with(
                ResponseTemplate::new(200).set_body_string(test_metadata_json("exists-one")),
            )
            .mount(&npm_server)
            .await;
        Mock::given(method("GET"))
            .and(path("/missing"))
            .respond_with(ResponseTemplate::new(404).set_body_string("not found"))
            .mount(&npm_server)
            .await;
        Mock::given(method("GET"))
            .and(path("/exists-two"))
            .respond_with(
                ResponseTemplate::new(200).set_body_string(test_metadata_json("exists-two")),
            )
            .mount(&npm_server)
            .await;

        let names = vec![
            "exists-one".to_string(),
            "missing".to_string(),
            "exists-two".to_string(),
        ];
        let tmp = tempfile::tempdir().expect("tmp");
        let mut client = RegistryClient::new()
            .with_base_url(proxy_server.uri())
            .with_npm_registry_url(npm_server.uri());
        client.cache_dir = Some(tmp.path().to_path_buf());
        let client = Arc::new(client);

        let (results, _stats) = client.parallel_fetch_npm_manifests(&names, 8).await;

        assert_eq!(results.len(), 3);
        assert!(results[0].1.is_ok(), "exists-one should succeed");
        match &results[1].1 {
            Err(LpmError::NotFound(_)) => {}
            other => panic!("missing should surface 404 as NotFound, got {other:?}"),
        }
        assert!(results[2].1.is_ok(), "exists-two should succeed");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn halve_on_429_ratchets_even_under_full_saturation() {
        // Regression test for the halve-on-429 ratchet bug: if the
        // implementation only forgets permits
        // it can `try_acquire_owned` synchronously, a fully-saturated
        // pool registers a halve event without any actual reduction —
        // the pool stays at `initial_concurrency`.
        //
        // The fix adds a deferred-forget debt counter paid by the next
        // task completions. This test pins the saturated moment by
        // making pkg-0 return a fast 429 while pkg-1..pkg-7 return
        // very slow 200s. When pkg-0's task enters the halving block,
        // the other 7 tasks are provably blocked inside send_with_retry
        // holding their permits — so immediate `try_acquire_owned`
        // forgets ZERO permits, and the whole halve must come from
        // the deferred-debt path.
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let npm_server = MockServer::start().await;
        let proxy_server = MockServer::start().await;

        // pkg-0: fast 429. MAX_RETRIES=3 inside send_with_retry, with
        // Retry-After=0 → ~4 attempts, no sleep between them; surfaces
        // RateLimited quickly.
        Mock::given(method("GET"))
            .and(path("/pkg-0"))
            .respond_with(ResponseTemplate::new(429).append_header("Retry-After", "0"))
            .mount(&npm_server)
            .await;

        // pkg-1..pkg-7: slow 200s. The 2-second delay ensures they are
        // STILL IN-FLIGHT when pkg-0's task enters the halving code,
        // forcing every permit to be held and the `try_acquire_owned`
        // path to forget zero.
        for i in 1..8 {
            let name = format!("pkg-{i}");
            Mock::given(method("GET"))
                .and(path(format!("/{name}")))
                .respond_with(
                    ResponseTemplate::new(200)
                        .set_body_string(test_metadata_json(&name))
                        .set_delay(std::time::Duration::from_secs(2)),
                )
                .mount(&npm_server)
                .await;
        }

        let names: Vec<String> = (0..8).map(|i| format!("pkg-{i}")).collect();
        let tmp = tempfile::tempdir().expect("tmp");
        let mut client = RegistryClient::new()
            .with_base_url(proxy_server.uri())
            .with_npm_registry_url(npm_server.uri());
        client.cache_dir = Some(tmp.path().to_path_buf());
        let client = Arc::new(client);

        // initial=8 matches names.len() so every task immediately acquires
        // a permit — no permits sit idle. When pkg-0's 429 fires, every
        // other permit is held by a task still in its 2s delay.
        let (results, stats) = client.parallel_fetch_npm_manifests(&names, 8).await;

        // pkg-0 RateLimited; the rest successful.
        assert_eq!(results.len(), 8);
        match &results[0].1 {
            Err(LpmError::RateLimited { .. }) => {}
            other => panic!("pkg-0 should surface RateLimited; got {other:?}"),
        }
        for (i, (name, r)) in results.iter().enumerate().skip(1) {
            assert!(
                r.is_ok(),
                "pkg-{i} ({name}) should have succeeded; got {r:?}"
            );
        }

        // The core assertion: halving actually happened under a scenario
        // where the synchronous `try_acquire_owned` path could only have
        // forgotten ZERO permits. Any final_concurrency < initial proves
        // the deferred-debt path is carrying its weight.
        assert!(
            stats.final_concurrency < stats.initial_concurrency,
            "halve-on-429 must actually reduce final concurrency under saturation; \
             got initial={}, final={}, halve_events={}",
            stats.initial_concurrency,
            stats.final_concurrency,
            stats.halve_events,
        );
        assert_eq!(
            stats.halve_events, 1,
            "exactly one halve event should be recorded (got {})",
            stats.halve_events,
        );
        // Floor respected.
        assert!(
            stats.final_concurrency >= 4,
            "final concurrency must not drop below the floor of 4 (got {})",
            stats.final_concurrency,
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn halve_on_429_multi_concurrent_races_respect_floor() {
        // Reviewer regression for the multi-429 ratchet race: when N
        // concurrent tasks all observe 429 before any of them decrements
        // the ceiling, the old logic had each task independently compute
        // `want_forget` against the stale `current=8`, each enqueue 4
        // into debt, and the 8 subsequent completions drive effective
        // pool to 0 — below the floor of 4.
        //
        // Fix: CAS on `current_ceiling` at halving time, so at most one
        // handler per ceiling transition wins the halving decision.
        // Others see the new lower ceiling (or `<= floor`) and back off.
        //
        // This test forces the race by (a) saturating the pool with 8
        // in-flight requests, (b) delaying every 429 response by the
        // same amount so all 8 tasks enter the halving block within a
        // tight window. Under the broken algorithm the pool shrinks
        // past the floor; the fix holds it at >= floor.
        use wiremock::matchers::{method, path_regex};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let npm_server = MockServer::start().await;
        let proxy_server = MockServer::start().await;

        // Every request: slow 429. Uniform 300ms delay keeps the 8
        // tasks' `RateLimited` surfacings bunched, maximising the race
        // window on the halving block.
        Mock::given(method("GET"))
            .and(path_regex(r"^/race-\d+$"))
            .respond_with(
                ResponseTemplate::new(429)
                    .append_header("Retry-After", "0")
                    .set_delay(std::time::Duration::from_millis(300)),
            )
            .mount(&npm_server)
            .await;

        let names: Vec<String> = (0..8).map(|i| format!("race-{i}")).collect();
        let tmp = tempfile::tempdir().expect("tmp");
        let mut client = RegistryClient::new()
            .with_base_url(proxy_server.uri())
            .with_npm_registry_url(npm_server.uri());
        client.cache_dir = Some(tmp.path().to_path_buf());
        let client = Arc::new(client);

        let (_results, stats) = client.parallel_fetch_npm_manifests(&names, 8).await;

        // The core assertion: concurrent 429s must NOT drive final
        // ceiling below the floor. With the broken logic this goes to
        // 0; with the CAS fix it stops at 4.
        assert!(
            stats.final_concurrency >= 4,
            "multi-429 race must respect floor; got initial={} final={} halve_events={}",
            stats.initial_concurrency,
            stats.final_concurrency,
            stats.halve_events,
        );
        // With initial=8 and floor=4, exactly one halve step is
        // possible (8→4). More than one means a handler halved past
        // the floor.
        assert_eq!(
            stats.halve_events, 1,
            "with floor=4 and initial=8 only a single halve step is \
             representable; got {}",
            stats.halve_events,
        );
    }

    /// Pin the cross-client cache roundtrip on the magic-header format. Two
    /// separate clients pointing at the same directory must read each other's
    /// writes — the invariant is the actual user-visible contract.
    ///
    /// Synchronous `#[test]` (not `#[tokio::test]`): inside a non-runtime
    /// context `write_metadata_cache` falls through to the sync path, so the
    /// read on the next line sees the write deterministically. The async-runtime
    /// path is exercised by the integration suite.
    #[test]
    fn with_cache_dir_some_path_roundtrips_across_clients() {
        let tmp = tempfile::tempdir().expect("tmp");
        let cache_path = tmp.path().to_path_buf();

        // Client A writes a synthetic metadata entry into tmp.
        let client_a = RegistryClient::new().with_cache_dir(Some(cache_path.clone()));
        let pkg_name = "with-cache-dir-roundtrip";
        let metadata: PackageMetadata =
            serde_json::from_str(&test_metadata_json(pkg_name)).expect("parse test metadata");
        client_a.write_metadata_cache(&format!("npm:{pkg_name}"), &metadata, None);

        // Fresh client B pointed at the same dir reads it back.
        let client_b = RegistryClient::new().with_cache_dir(Some(cache_path.clone()));
        let (cached, _etag) = client_b
            .read_metadata_cache(&format!("npm:{pkg_name}"))
            .expect("fresh client with same cache_dir must read back the prior write");
        assert_eq!(
            cached.name, pkg_name,
            "round-tripped cache entry must preserve the package name"
        );
    }

    /// M62: a cache file larger than METADATA_CACHE_FILE_CAP is
    /// treated as a miss. The on-disk cache directory is the user's
    /// home so this gate doesn't change the trust model — it just
    /// prevents a pathological/hostile file from forcing every
    /// install start to allocate a multi-GB `Vec<u8>` before serde
    /// even notices the bytes are garbage.
    #[test]
    fn oversized_metadata_cache_file_collapses_to_miss() {
        let tmp = tempfile::tempdir().expect("tmp");
        let cache_dir = tmp.path().to_path_buf();
        let client = RegistryClient::new().with_cache_dir(Some(cache_dir.clone()));

        let pkg_name = "oversized-cache-file";
        let key = format!("npm:{pkg_name}");

        // Write a small valid entry first so the path exists.
        let metadata: PackageMetadata =
            serde_json::from_str(&test_metadata_json(pkg_name)).expect("parse test metadata");
        client.write_metadata_cache(&key, &metadata, None);
        let cache_file = client
            .cache_path(&key)
            .expect("cache_path resolves when cache_dir is configured");
        assert!(cache_file.exists(), "cache write must land on disk");

        // Truncate the file and pad it past the cap. We use the magic
        // header prefix so the rejection isn't simply due to a missing
        // magic byte — we want to prove the size check fires before
        // the magic comparison.
        let mut padding = METADATA_CACHE_MAGIC.to_vec();
        padding.extend(b"\n"); // empty ETag line
        padding.resize((METADATA_CACHE_FILE_CAP + 1024) as usize, b'x');
        std::fs::write(&cache_file, &padding).expect("rewrite cache file oversized");

        // Read must return None (cache miss).
        let result = client.read_metadata_cache(&key);
        assert!(
            result.is_none(),
            "oversized cache file must collapse to a miss"
        );

        // Same posture on the stale-conditional read path.
        let content = client.read_cache_content(&key);
        assert!(
            content.is_none(),
            "read_cache_content must also refuse oversized files"
        );
    }

    // ── get_npm_metadata_from ──────────────────────────────────────────────────

    /// Helper: build a RegistryAuth::Bearer scoped to the wiremock
    /// server's origin. Encapsulates the URL parsing test code does
    /// over and over.
    fn bearer_for(server_uri: &str, token: &str) -> crate::npmrc::RegistryAuth {
        let origin = crate::npmrc::OriginKey::from_request_url(&format!("{server_uri}/_"))
            .expect("mock server URI must parse");
        crate::npmrc::RegistryAuth::Bearer {
            origin,
            token: SecretString::from(token.to_string()),
        }
    }

    fn basic_for(server_uri: &str, b64: &str) -> crate::npmrc::RegistryAuth {
        let origin = crate::npmrc::OriginKey::from_request_url(&format!("{server_uri}/_"))
            .expect("mock server URI must parse");
        crate::npmrc::RegistryAuth::Basic {
            origin,
            credential: SecretString::from(b64.to_string()),
        }
    }

    #[tokio::test]
    async fn get_npm_metadata_from_attaches_bearer_auth() {
        use wiremock::matchers::{header, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/some-pkg"))
            .and(header("Authorization", "Bearer SECRET-TOKEN-123"))
            .and(header("Accept", "application/vnd.npm.install-v1+json"))
            .respond_with(
                ResponseTemplate::new(200).set_body_string(test_metadata_json("some-pkg")),
            )
            .expect(1)
            .mount(&server)
            .await;

        let (client, _tmp) = client_with_mock_server(&server.uri());
        let auth = bearer_for(&server.uri(), "SECRET-TOKEN-123");
        let meta = client
            .get_npm_metadata_from(&server.uri(), "some-pkg", Some(&auth))
            .await
            .expect("auth-attached fetch should succeed");
        assert_eq!(meta.name, "some-pkg");
    }

    #[tokio::test]
    async fn get_npm_metadata_from_attaches_basic_auth() {
        use wiremock::matchers::{header, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/some-pkg"))
            .and(header("Authorization", "Basic dXNlcjpwYXNz"))
            .respond_with(
                ResponseTemplate::new(200).set_body_string(test_metadata_json("some-pkg")),
            )
            .expect(1)
            .mount(&server)
            .await;

        let (client, _tmp) = client_with_mock_server(&server.uri());
        let auth = basic_for(&server.uri(), "dXNlcjpwYXNz");
        let meta = client
            .get_npm_metadata_from(&server.uri(), "some-pkg", Some(&auth))
            .await
            .expect("Basic auth fetch should succeed");
        assert_eq!(meta.name, "some-pkg");
    }

    #[tokio::test]
    async fn get_npm_metadata_from_no_auth_sends_anonymous() {
        // No Authorization header sent when auth is None. We assert
        // the absence by setting up TWO mocks: the matched-no-auth one
        // returns 200; if the request had any Authorization header,
        // wiremock would route nowhere and 404.
        use wiremock::matchers::{header_exists, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        // Reject any request that DOES carry Authorization.
        Mock::given(method("GET"))
            .and(path("/some-pkg"))
            .and(header_exists("Authorization"))
            .respond_with(ResponseTemplate::new(401))
            .expect(0) // never matched
            .mount(&server)
            .await;
        // Accept the no-auth request.
        Mock::given(method("GET"))
            .and(path("/some-pkg"))
            .respond_with(
                ResponseTemplate::new(200).set_body_string(test_metadata_json("some-pkg")),
            )
            .mount(&server)
            .await;

        let (client, _tmp) = client_with_mock_server(&server.uri());
        let meta = client
            .get_npm_metadata_from(&server.uri(), "some-pkg", None)
            .await
            .expect("anonymous fetch should succeed");
        assert_eq!(meta.name, "some-pkg");
    }

    #[tokio::test]
    async fn get_npm_metadata_from_origin_mismatch_returns_error() {
        // S2 defense: auth scoped to origin A, request to origin B.
        // The fetch site MUST refuse to send and surface a clear error
        // — no network call is made.
        use wiremock::MockServer;

        let server = MockServer::start().await;
        let (client, _tmp) = client_with_mock_server(&server.uri());

        // Auth scoped to a DIFFERENT host than the server.
        let auth = bearer_for("https://attacker.example", "STOLEN");

        let result = client
            .get_npm_metadata_from(&server.uri(), "some-pkg", Some(&auth))
            .await;

        match result {
            Err(LpmError::Registry(msg)) => {
                assert!(
                    msg.contains("origin mismatch"),
                    "error must mention origin mismatch: {msg}"
                );
            }
            other => panic!("expected origin-mismatch Registry error, got {other:?}"),
        }
        // Bonus: the mock server received NO request, since we hard-
        // failed before the network. wiremock's default is "no
        // expectations set ⇒ no requests required", so this is
        // implicit — we just don't assert any mock was matched.
    }

    #[tokio::test]
    async fn get_npm_metadata_from_uses_host_keyed_cache() {
        // Two distinct registries serving the same package name must
        // not collide in the cache.
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let registry_a = MockServer::start().await;
        let registry_b = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/colliding-name"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(test_metadata_json_with_version("colliding-name", "1.0.0")),
            )
            .mount(&registry_a)
            .await;
        Mock::given(method("GET"))
            .and(path("/colliding-name"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(test_metadata_json_with_version("colliding-name", "9.9.9")),
            )
            .mount(&registry_b)
            .await;

        let (client, _tmp) = client_with_mock_server(&registry_a.uri());

        let meta_a = client
            .get_npm_metadata_from(&registry_a.uri(), "colliding-name", None)
            .await
            .unwrap();
        let meta_b = client
            .get_npm_metadata_from(&registry_b.uri(), "colliding-name", None)
            .await
            .unwrap();

        // Each registry's response is preserved — no cross-talk.
        assert_eq!(meta_a.latest_version.as_deref(), Some("1.0.0"));
        assert_eq!(meta_b.latest_version.as_deref(), Some("9.9.9"));
    }

    #[tokio::test]
    async fn get_npm_metadata_from_distinguishes_path_prefixed_registries_on_same_origin() {
        // Two npm-compatible registries on the same host:port but
        // different path prefixes — e.g., GitLab npm Package Registry
        // (`/api/v4/projects/<id>/packages/npm`). Earlier drafts keyed
        // the cache on (host, port); this test pins the regression.
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        // Project 1 path serves "1.0.0".
        Mock::given(method("GET"))
            .and(path("/api/v4/projects/1/packages/npm/colliding-name"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(test_metadata_json_with_version("colliding-name", "1.0.0")),
            )
            .mount(&server)
            .await;
        // Project 2 path serves "2.0.0".
        Mock::given(method("GET"))
            .and(path("/api/v4/projects/2/packages/npm/colliding-name"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(test_metadata_json_with_version("colliding-name", "2.0.0")),
            )
            .mount(&server)
            .await;

        let (client, _tmp) = client_with_mock_server(&server.uri());
        let base_a = format!("{}/api/v4/projects/1/packages/npm", server.uri());
        let base_b = format!("{}/api/v4/projects/2/packages/npm", server.uri());
        let meta_a = client
            .get_npm_metadata_from(&base_a, "colliding-name", None)
            .await
            .unwrap();
        let meta_b = client
            .get_npm_metadata_from(&base_b, "colliding-name", None)
            .await
            .unwrap();
        assert_eq!(
            meta_a.latest_version.as_deref(),
            Some("1.0.0"),
            "project 1 must see its own version"
        );
        assert_eq!(
            meta_b.latest_version.as_deref(),
            Some("2.0.0"),
            "project 2 must NOT inherit project 1's cache entry"
        );
    }

    #[tokio::test]
    async fn cache_partitions_per_auth_principal() {
        // The cache key includes an auth fingerprint so a fetch under
        // credential A cannot warm a cache entry that credential B (or
        // anonymous) would read without proving its own access.
        // Same URL + different tokens = distinct cache entries; each
        // principal's request hits the network even when another's
        // already populated the URL.
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        // Two responses for the SAME URL — the test infrastructure can
        // pick which based on token, but we use simple matchers and
        // count requests instead. The key assertion is: each principal
        // hits the network on its first call, even though the URL is
        // identical.
        Mock::given(method("GET"))
            .and(path("/private-pkg"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(test_metadata_json_with_version("private-pkg", "1.0.0")),
            )
            .expect(2) // CRITICAL: both principals must hit the network
            .mount(&server)
            .await;

        let (client, _tmp) = client_with_mock_server(&server.uri());
        let auth_a = bearer_for(&server.uri(), "TOKEN-A");
        let auth_b = bearer_for(&server.uri(), "TOKEN-B");

        // Principal A populates the cache.
        client
            .get_npm_metadata_from(&server.uri(), "private-pkg", Some(&auth_a))
            .await
            .unwrap();
        // Principal B must NOT see A's cached entry.
        client
            .get_npm_metadata_from(&server.uri(), "private-pkg", Some(&auth_b))
            .await
            .unwrap();
        // wiremock's `.expect(2)` enforces that both fetches hit the
        // network (verified at server drop). If the cache had served
        // B from A's entry, only 1 request would have arrived.
    }

    #[tokio::test]
    async fn cache_warm_hit_with_same_auth() {
        // Defense-in-depth for the partitioning: identical credentials
        // MUST still produce a warm hit. Otherwise we've replaced one
        // bug with another (denying every warm hit on auth'd requests).
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/private-pkg"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(test_metadata_json_with_version("private-pkg", "1.0.0")),
            )
            .expect(1) // exactly one network fetch despite two calls
            .mount(&server)
            .await;

        let (client, _tmp) = client_with_mock_server(&server.uri());
        let auth = bearer_for(&server.uri(), "TOKEN-A");
        // First call: miss → fetch.
        client
            .get_npm_metadata_from(&server.uri(), "private-pkg", Some(&auth))
            .await
            .unwrap();
        // Second call same auth: warm hit.
        client
            .get_npm_metadata_from(&server.uri(), "private-pkg", Some(&auth))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn cache_anon_does_not_serve_to_authed_or_vice_versa() {
        // The most dangerous case: an anonymous fetch warming the cache
        // for a URL that requires auth. Or an authed fetch making the
        // anonymous principal think the URL is reachable. Both must
        // miss across the auth/no-auth boundary.
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/private-pkg"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(test_metadata_json_with_version("private-pkg", "1.0.0")),
            )
            .expect(2)
            .mount(&server)
            .await;

        let (client, _tmp) = client_with_mock_server(&server.uri());
        // First: anonymous.
        client
            .get_npm_metadata_from(&server.uri(), "private-pkg", None)
            .await
            .unwrap();
        // Second: authed. Must hit the network — anonymous's cache
        // entry doesn't satisfy us.
        let auth = bearer_for(&server.uri(), "TOKEN-X");
        client
            .get_npm_metadata_from(&server.uri(), "private-pkg", Some(&auth))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn invalidate_custom_metadata_cache_removes_authed_entry() {
        // The legacy `invalidate_metadata_cache(name)` can't reach
        // custom-registry entries whose key includes URL and auth fingerprint.
        // Test: write a custom-registry entry, invalidate via the new method,
        // confirm next read misses.
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/some-pkg"))
            .respond_with(
                ResponseTemplate::new(200).set_body_string(test_metadata_json("some-pkg")),
            )
            .expect(2) // 1st write, 2nd post-invalidation refetch
            .mount(&server)
            .await;

        let (client, _tmp) = client_with_mock_server(&server.uri());
        let auth = bearer_for(&server.uri(), "TOKEN-X");

        // Populate.
        client
            .get_npm_metadata_from(&server.uri(), "some-pkg", Some(&auth))
            .await
            .unwrap();

        // Legacy name-only invalidate must NOT find the custom entry —
        // otherwise the new method is redundant.
        client.invalidate_metadata_cache("some-pkg");
        // After legacy invalidate: still cached (warm hit).
        // We can't directly assert "1 network fetch so far" without
        // restructuring, so we rely on the `.expect(2)` total at end.

        // New method WITH the URL+auth must invalidate.
        client.invalidate_custom_metadata_cache(&server.uri(), "some-pkg", Some(&auth));
        // Next call: miss → fetch.
        client
            .get_npm_metadata_from(&server.uri(), "some-pkg", Some(&auth))
            .await
            .unwrap();
    }

    // ── tarball auth ──────────────────────────────────────────────────────────

    #[tokio::test]
    async fn download_tarball_with_auth_attaches_bearer() {
        // A custom-registry tarball download must carry the `.npmrc`
        // Authorization header. The auth-aware download method attaches the
        // Bearer token to the request.
        use wiremock::matchers::{header, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/foo/-/foo-1.0.0.tgz"))
            .and(header("Authorization", "Bearer SECRET-TOKEN"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"fake-tarball-bytes"))
            .expect(1)
            .mount(&server)
            .await;

        let (client, _tmp) = client_with_mock_server(&server.uri());
        let auth = bearer_for(&server.uri(), "SECRET-TOKEN");
        let url = format!("{}/foo/-/foo-1.0.0.tgz", server.uri());
        let downloaded = client
            .download_tarball_to_file_with_auth(&url, Some(&auth))
            .await
            .expect("auth-attached tarball download must succeed");
        assert_eq!(downloaded.compressed_size, 18); // "fake-tarball-bytes".len()
    }

    #[tokio::test]
    async fn download_tarball_with_auth_anon_when_none() {
        // No npmrc auth for this URL → request goes anonymous (no
        // Authorization header). Importantly, the LPM session bearer
        // is NOT leaked — that's the bug the new method exists to
        // prevent.
        use wiremock::matchers::{header_exists, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        // Reject any request that DOES carry Authorization.
        Mock::given(method("GET"))
            .and(path("/foo/-/foo-1.0.0.tgz"))
            .and(header_exists("Authorization"))
            .respond_with(ResponseTemplate::new(401))
            .expect(0)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/foo/-/foo-1.0.0.tgz"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"x"))
            .mount(&server)
            .await;

        // Even if the client has a session bearer, the auth-aware path
        // must NOT attach it.
        let (client, _tmp) = client_with_mock_server(&server.uri());
        let client = client.with_token("LPM-SESSION-BEARER");
        let url = format!("{}/foo/-/foo-1.0.0.tgz", server.uri());
        client
            .download_tarball_to_file_with_auth(&url, None)
            .await
            .expect("anonymous download must succeed");
    }

    #[tokio::test]
    async fn download_tarball_with_auth_origin_mismatch_returns_error() {
        // S2 defense parity with `get_npm_metadata_from`: auth scoped
        // to origin A, request to origin B → hard-fail before the
        // network. The auth-mismatch must surface as Registry error,
        // not silently drop or leak.
        use wiremock::MockServer;

        let server = MockServer::start().await;
        let (client, _tmp) = client_with_mock_server(&server.uri());
        let auth = bearer_for("https://attacker.example", "STOLEN");
        let url = format!("{}/foo/-/foo-1.0.0.tgz", server.uri());

        let result = client
            .download_tarball_to_file_with_auth(&url, Some(&auth))
            .await;
        match result {
            Err(LpmError::Registry(msg)) => {
                assert!(
                    msg.contains("origin mismatch"),
                    "error must mention origin mismatch: {msg}"
                );
            }
            other => panic!("expected origin-mismatch Registry error, got {other:?}"),
        }
    }

    /// Helper for the host-keyed cache test — needs a `latestVersion`
    /// field for round-trip comparison (the default `test_metadata_json`
    /// builder is light; this one parameterizes the version).
    fn test_metadata_json_with_version(name: &str, version: &str) -> String {
        serde_json::json!({
            "name": name,
            "description": "test",
            "latestVersion": version,
            "dist-tags": { "latest": version },
            "versions": {
                version: {
                    "name": name,
                    "version": version,
                    "dist": {
                        "tarball": format!("https://example.com/{name}-{version}.tgz"),
                        "integrity": "sha512-test"
                    },
                    "dependencies": {}
                }
            }
        })
        .to_string()
    }

    // ---- with_tls_overrides + build_http_client_with_tls ----

    use crate::npmrc::{TaggedBool, TaggedRoot};

    fn rcgen_pem() -> Vec<u8> {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
            .expect("rcgen self-signed cert");
        cert.cert.pem().into_bytes()
    }

    /// Test helper: wrap a `reqwest::Client` in a `CachedClient` with
    /// no identity fingerprint. The dispatch tests don't exercise
    /// principal_fingerprint (that's its own test), so identity_fp
    /// stays None.
    fn cached(client: reqwest::Client) -> CachedClient {
        CachedClient {
            client,
            identity_fp: None,
        }
    }

    #[test]
    fn with_tls_overrides_default_is_noop() {
        // No extra roots, no strict_ssl set → no rebuild, no error.
        let client = RegistryClient::new();
        assert!(
            client.with_tls_overrides(&TlsOverrides::default()).is_ok(),
            "default TLS overrides must be a no-op"
        );
    }

    #[test]
    fn with_tls_overrides_explicit_strict_ssl_true_is_noop() {
        // `strict-ssl=true` is the default — explicitly setting it to
        // true should not force a rebuild.
        let tls = TlsOverrides {
            extra_roots: Vec::new(),
            strict_ssl: Some(TaggedBool {
                value: true,
                source: "test".into(),
                line: 1,
            }),
            ..Default::default()
        };
        let client = RegistryClient::new();
        assert!(client.with_tls_overrides(&tls).is_ok());
    }

    #[test]
    fn with_tls_overrides_with_valid_pem_builds_ok() {
        let pem = rcgen_pem();
        let tls = TlsOverrides {
            extra_roots: vec![TaggedRoot {
                pem_bytes: pem,
                source: "test:.npmrc".into(),
                line: 1,
            }],
            strict_ssl: None,
            ..Default::default()
        };
        let client = RegistryClient::new();
        assert!(client.with_tls_overrides(&tls).is_ok());
    }

    #[test]
    fn with_tls_overrides_with_malformed_pem_returns_err_with_source() {
        // Bytes that fail `reqwest::Certificate::from_pem`. The error
        // must cite the contributing source/line so the user can find
        // the offending `.npmrc` line, not just see "TLS broke".
        //
        // Note: reqwest's `from_pem` is permissive about the BODY
        // content as long as the BEGIN/END markers are present
        // (validation happens later in `.build()`). To exercise the
        // source-citing path on `from_pem` itself, we pass bytes with
        // no PEM marker at all — these would never reach the builder
        // through the normal parser (the parse-time `contains_pem_certificate_block`
        // check rejects them), but a direct caller of `with_tls_overrides`
        // with hand-built `TaggedRoot` (or a future PEM source we don't
        // marker-check) would.
        let no_marker = b"this is plainly not a PEM file".to_vec();
        let tls = TlsOverrides {
            extra_roots: vec![TaggedRoot {
                pem_bytes: no_marker,
                source: "/Users/me/.npmrc".into(),
                line: 7,
            }],
            strict_ssl: None,
            ..Default::default()
        };
        let client = RegistryClient::new();
        match client.with_tls_overrides(&tls) {
            Ok(_) => panic!("expected Err for malformed PEM, got Ok"),
            Err(LpmError::Cert(msg)) => {
                assert!(
                    msg.contains("/Users/me/.npmrc:7"),
                    "error must cite source:line — got: {msg}"
                );
                assert!(
                    msg.contains("npmrc cafile/ca"),
                    "error must identify the npmrc origin — got: {msg}"
                );
            }
            Err(other) => panic!("expected Cert error, got: {other}"),
        }
    }

    #[test]
    fn with_tls_overrides_strict_ssl_false_builds_ok() {
        let tls = TlsOverrides {
            extra_roots: Vec::new(),
            strict_ssl: Some(TaggedBool {
                value: false,
                source: "test".into(),
                line: 1,
            }),
            ..Default::default()
        };
        let client = RegistryClient::new();
        assert!(client.with_tls_overrides(&tls).is_ok());
    }

    #[test]
    fn with_tls_overrides_combined_pem_and_strict_ssl_builds_ok() {
        // Both knobs at once — install.rs's worst-case combined-overrides
        // path. Builder must accept both without conflict.
        let pem = rcgen_pem();
        let tls = TlsOverrides {
            extra_roots: vec![TaggedRoot {
                pem_bytes: pem,
                source: "test".into(),
                line: 1,
            }],
            strict_ssl: Some(TaggedBool {
                value: false,
                source: "test".into(),
                line: 2,
            }),
            ..Default::default()
        };
        let client = RegistryClient::new();
        assert!(client.with_tls_overrides(&tls).is_ok());
    }

    #[test]
    fn validate_pem_root_catches_malformed_second_block_in_multi_cert_bundle() {
        // Regression — pre-fix `validate_pem_root` only validated the
        // FIRST cert block in a PEM. A common cafile shape (root + intermediate
        // bundle, multi-CERT) where block 1 was valid but block 2 was malformed
        // would slip through validation and surface as a generic
        // "HTTP client build failed: builder error" without source citation.
        // Now every block is validated; the offending block's offset is cited.
        let valid = rcgen_pem();
        let mut bundle = Vec::with_capacity(valid.len() * 2 + 256);
        bundle.extend_from_slice(&valid);
        bundle.extend_from_slice(
            b"\n-----BEGIN CERTIFICATE-----\n@@@ not base64 @@@\n-----END CERTIFICATE-----\n",
        );
        let tls = TlsOverrides {
            extra_roots: vec![TaggedRoot {
                pem_bytes: bundle,
                source: "/Users/me/.npmrc".into(),
                line: 12,
            }],
            strict_ssl: None,
            ..Default::default()
        };
        let client = RegistryClient::new();
        match client.with_tls_overrides(&tls) {
            Ok(_) => panic!("malformed 2nd block must fail validation, got Ok"),
            Err(LpmError::Cert(msg)) => {
                assert!(
                    msg.contains("/Users/me/.npmrc:12"),
                    "error must cite source:line — got: {msg}"
                );
                assert!(
                    msg.contains("not valid base64"),
                    "error must explain the failure mode — got: {msg}"
                );
            }
            Err(other) => panic!("expected Cert error, got: {other}"),
        }
    }

    #[test]
    fn validate_pem_root_accepts_valid_multi_cert_bundle() {
        // Positive case for the loop: a root + intermediate where BOTH
        // are valid PEM blocks must pass. Two distinct rcgen certs
        // concatenated with a separator newline.
        let mut bundle = rcgen_pem();
        bundle.push(b'\n');
        bundle.extend_from_slice(&rcgen_pem());
        let tls = TlsOverrides {
            extra_roots: vec![TaggedRoot {
                pem_bytes: bundle,
                source: "test".into(),
                line: 1,
            }],
            strict_ssl: None,
            ..Default::default()
        };
        let client = RegistryClient::new();
        assert!(
            client.with_tls_overrides(&tls).is_ok(),
            "two valid concatenated cert blocks must pass"
        );
    }

    // ---- HttpClients dispatch ----

    /// Default + empty eager + empty lazy → every URL routes to default.
    #[test]
    fn http_clients_default_only_returns_default_for_every_url() {
        let client = RegistryClient::new();
        // Two distinct origins, both fall through to default since no
        // per-origin TLS is configured.
        let c1 = client
            .http
            .for_url_no_build("https://registry.npmjs.org/react");
        let c2 = client.http.for_url_no_build("https://corp.internal/lib");
        // Pointer equality on `&reqwest::Client` is the precise check —
        // both must point to the SAME default client, not equivalent
        // copies. (`Arc`-internal so equality of the underlying Arc
        // pointers is what we want.)
        assert!(std::ptr::eq(c1, c2), "every URL must route to default");
    }

    /// Eager hit: if the eager map has an entry for this origin, the
    /// dispatcher returns that client, NOT the default. This is the
    /// load-bearing test for `with_tls_overrides_for` per-origin
    /// pre-build.
    #[test]
    fn http_clients_eager_hit_overrides_default() {
        // Build with a per-origin cafile entry (deferred-read; no
        // actual file IO since we'll synthesize the eager entry).
        let pem = rcgen_pem();
        // Synthesize an HttpClients directly so the test doesn't need
        // a real .npmrc parse (the eager build path needs file IO,
        // which we exercise in the integration test for mTLS proper).
        let default = RegistryClient::build_http_client(CONNECT_TIMEOUT, READ_TIMEOUT);
        let per_origin_client = reqwest::Client::builder()
            .add_root_certificate(reqwest::Certificate::from_pem(&pem).expect("rcgen pem"))
            .build()
            .expect("client build");
        let origin = OriginKey {
            host_lower: "corp.internal".into(),
            port: None,
        };
        let mut eager = HashMap::new();
        eager.insert(origin.clone(), cached(per_origin_client.clone()));
        let http = Arc::new(HttpClients {
            default: cached(default.clone()),
            eager,
            lazy: tokio::sync::Mutex::new(HashMap::new()),
            tls_overrides: Arc::new(TlsOverrides::default()),
            passphrase: Arc::new(crate::tls_identity::EnvThenTtyPassphrase::new()),
            per_origin_identity_fps: HashMap::new(),
        });
        let mut client = RegistryClient::new();
        client.http = http;
        // Eager origin → per_origin_client (NOT default).
        let picked = client
            .http
            .for_url_no_build("https://corp.internal:443/foo");
        // Different origin → default.
        let other = client.http.for_url_no_build("https://other.example/bar");
        // Pointer-eq each against the source it should match.
        // `for_url_no_build` returns `&reqwest::Client` (the .client
        // field of CachedClient), so pierce CachedClient on the rhs.
        assert!(
            std::ptr::eq(picked, &client.http.eager.get(&origin).unwrap().client),
            "eager origin must dispatch to its registered client"
        );
        assert!(
            std::ptr::eq(other, &client.http.default.client),
            "non-eager origin must dispatch to default"
        );
    }

    /// Port fallback: an eager entry with `port: None` must match
    /// requests on any port for that host. Mirrors auth_for_url's
    /// match rule.
    #[test]
    fn http_clients_eager_port_none_matches_any_port() {
        let default = RegistryClient::build_http_client(CONNECT_TIMEOUT, READ_TIMEOUT);
        let pem = rcgen_pem();
        let per_origin_client = reqwest::Client::builder()
            .add_root_certificate(reqwest::Certificate::from_pem(&pem).expect("rcgen pem"))
            .build()
            .expect("client build");
        // Insert with port: None.
        let key_no_port = OriginKey {
            host_lower: "host.internal".into(),
            port: None,
        };
        let mut eager = HashMap::new();
        eager.insert(key_no_port.clone(), cached(per_origin_client));
        let http = Arc::new(HttpClients {
            default: cached(default),
            eager,
            lazy: tokio::sync::Mutex::new(HashMap::new()),
            tls_overrides: Arc::new(TlsOverrides::default()),
            passphrase: Arc::new(crate::tls_identity::EnvThenTtyPassphrase::new()),
            per_origin_identity_fps: HashMap::new(),
        });
        let mut client = RegistryClient::new();
        client.http = http;
        // Both 443 (default https) and 8443 must hit the no-port entry.
        let picked_443 = client.http.for_url_no_build("https://host.internal/foo");
        let picked_8443 = client
            .http
            .for_url_no_build("https://host.internal:8443/bar");
        let stored = &client.http.eager.get(&key_no_port).unwrap().client;
        assert!(std::ptr::eq(picked_443, stored));
        assert!(std::ptr::eq(picked_8443, stored));
    }

    /// Lazy build: an origin with per-origin TLS configured but NOT
    /// in the eager set should be lazy-built on first request, then
    /// cached.
    #[tokio::test]
    async fn http_clients_lazy_builds_and_memoizes() {
        // Synthesize TlsOverrides with a per-origin cafile pointing
        // at a real PEM file, but don't pre-build the eager client.
        let pem = rcgen_pem();
        let dir = tempfile::tempdir().expect("tempdir");
        let ca_path = dir.path().join("ca.pem");
        std::fs::write(&ca_path, &pem).unwrap();
        let origin = OriginKey {
            host_lower: "lazy.internal".into(),
            port: None,
        };
        let mut per_origin_map = HashMap::new();
        per_origin_map.insert(
            origin.clone(),
            crate::npmrc::OriginTlsOverrides {
                cafiles: vec![crate::npmrc::TaggedPath {
                    path: ca_path,
                    source: "test".into(),
                    line: 1,
                    source_dir: None,
                }],
                certfile: None,
                keyfile: None,
            },
        );
        let tls = TlsOverrides {
            per_origin: per_origin_map,
            ..Default::default()
        };
        let default = RegistryClient::build_http_client(CONNECT_TIMEOUT, READ_TIMEOUT);
        let http = Arc::new(HttpClients {
            default: cached(default),
            eager: HashMap::new(),
            lazy: tokio::sync::Mutex::new(HashMap::new()),
            tls_overrides: Arc::new(tls),
            passphrase: Arc::new(crate::tls_identity::EnvThenTtyPassphrase::new()),
            per_origin_identity_fps: HashMap::new(),
        });
        // First call must build + insert.
        let c1 = http.for_url("https://lazy.internal/pkg").await.expect("ok");
        // Second call must hit the lazy cache (not rebuild).
        let c2 = http
            .for_url("https://lazy.internal/other")
            .await
            .expect("ok");
        // Same origin → same cached entry. The dispatcher inserts
        // under the URL's concrete-port origin (`Some(443)` for
        // HTTPS), not the configured port-None entry — both calls
        // produce the same key, so the second call's `guard.get`
        // hits without rebuild. Verify the lazy map has exactly one
        // entry, keyed by the concrete-port origin.
        let concrete_port_key = OriginKey {
            host_lower: "lazy.internal".into(),
            port: Some(443),
        };
        let map = http.lazy.lock().await;
        assert_eq!(map.len(), 1, "lazy map must contain exactly one entry");
        assert!(
            map.contains_key(&concrete_port_key),
            "lazy entry must be keyed by the URL's concrete-port origin (got keys: {:?})",
            map.keys().map(|k| k.to_string()).collect::<Vec<_>>()
        );
        // The originally-configured port-None origin is the per_origin
        // TLS lookup key, not the lazy cache key — the dispatcher's
        // (host, Some(port)) → (host, None) fallback bridges the two.
        // Reference but unused: prevents the unused-binding warning.
        let _ = origin;
        // Sanity: both returned clients are usable Client values.
        let _ = (c1, c2);
    }

    /// No per-origin TLS configured → lazy lookup falls through to
    /// default without building anything.
    #[tokio::test]
    async fn http_clients_no_per_origin_tls_falls_through_to_default() {
        let default = RegistryClient::build_http_client(CONNECT_TIMEOUT, READ_TIMEOUT);
        let http = Arc::new(HttpClients {
            default: cached(default.clone()),
            eager: HashMap::new(),
            lazy: tokio::sync::Mutex::new(HashMap::new()),
            tls_overrides: Arc::new(TlsOverrides::default()),
            passphrase: Arc::new(crate::tls_identity::EnvThenTtyPassphrase::new()),
            per_origin_identity_fps: HashMap::new(),
        });
        let _ = http
            .for_url("https://anywhere.example/foo")
            .await
            .expect("ok");
        // Lazy map must remain empty (no per-origin TLS to build).
        let map = http.lazy.lock().await;
        assert!(map.is_empty());
    }

    /// Per-origin half-config (certfile alone, no keyfile) for a
    /// reached origin must surface a cited error per Δ2 scoping.
    #[tokio::test]
    async fn http_clients_per_origin_certfile_xor_is_fatal_at_build() {
        let dir = tempfile::tempdir().unwrap();
        let cert_path = dir.path().join("cert.pem");
        std::fs::write(
            &cert_path,
            "-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----\n",
        )
        .unwrap();
        let origin = OriginKey {
            host_lower: "halfconf.internal".into(),
            port: None,
        };
        let mut per_origin_map = HashMap::new();
        per_origin_map.insert(
            origin.clone(),
            crate::npmrc::OriginTlsOverrides {
                cafiles: vec![],
                certfile: Some(crate::npmrc::TaggedPath {
                    path: cert_path,
                    source: "test:.npmrc".into(),
                    line: 7,
                    source_dir: None,
                }),
                keyfile: None,
            },
        );
        let tls = TlsOverrides {
            per_origin: per_origin_map,
            ..Default::default()
        };
        let default = RegistryClient::build_http_client(CONNECT_TIMEOUT, READ_TIMEOUT);
        let http = Arc::new(HttpClients {
            default: cached(default),
            eager: HashMap::new(),
            lazy: tokio::sync::Mutex::new(HashMap::new()),
            tls_overrides: Arc::new(tls),
            passphrase: Arc::new(crate::tls_identity::EnvThenTtyPassphrase::new()),
            per_origin_identity_fps: HashMap::new(),
        });
        let result = http.for_url("https://halfconf.internal/foo").await;
        match result {
            Err(LpmError::Cert(msg)) => {
                assert!(msg.contains("test:.npmrc:7"), "msg: {msg}");
                assert!(msg.contains("certfile"), "msg: {msg}");
                assert!(msg.contains("keyfile"), "msg: {msg}");
                assert!(msg.contains("halfconf.internal"), "msg: {msg}");
            }
            other => panic!("expected Cert error, got: {other:?}"),
        }
    }

    /// Configured-but-unreached half-config for a different origin
    /// must NOT abort an unrelated build (Δ1 + Δ2 scoping).
    #[tokio::test]
    async fn http_clients_unreached_half_config_does_not_break_unrelated_lookup() {
        let dir = tempfile::tempdir().unwrap();
        let cert_path = dir.path().join("cert.pem");
        std::fs::write(
            &cert_path,
            "-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----\n",
        )
        .unwrap();
        let unreached_origin = OriginKey {
            host_lower: "unused.internal".into(),
            port: None,
        };
        let mut per_origin_map = HashMap::new();
        per_origin_map.insert(
            unreached_origin,
            crate::npmrc::OriginTlsOverrides {
                cafiles: vec![],
                certfile: Some(crate::npmrc::TaggedPath {
                    path: cert_path,
                    source: "test:.npmrc".into(),
                    line: 7,
                    source_dir: None,
                }),
                keyfile: None,
            },
        );
        let tls = TlsOverrides {
            per_origin: per_origin_map,
            ..Default::default()
        };
        let default = RegistryClient::build_http_client(CONNECT_TIMEOUT, READ_TIMEOUT);
        let http = Arc::new(HttpClients {
            default: cached(default),
            eager: HashMap::new(),
            lazy: tokio::sync::Mutex::new(HashMap::new()),
            tls_overrides: Arc::new(tls),
            passphrase: Arc::new(crate::tls_identity::EnvThenTtyPassphrase::new()),
            per_origin_identity_fps: HashMap::new(),
        });
        // Request to a DIFFERENT origin must succeed (lookup → default).
        let _ = http
            .for_url("https://different.example/foo")
            .await
            .expect("unrelated lookup must not fail on unreached half-config");
    }

    /// The lazy per-origin dispatch path must fire from production request
    /// flows, not only from explicit `for_url` calls in tests.
    ///
    /// Verifies that `download_tarball_to_file_with_auth` (a production entry
    /// point going through `for_url(...).await?`) triggers a lazy build for an
    /// origin that is configured in `tls_overrides.per_origin` but NOT in the
    /// eager set. Without this, the path fell through to the default client,
    /// ignoring per-origin TLS for transitive scopes / CDN origins.
    #[tokio::test]
    async fn production_tarball_path_triggers_lazy_build_for_per_origin_tls() {
        // Synthesize a per-origin TLS config for a host that's NOT in
        // the eager set. Use a self-signed CA so the per-origin client
        // build works (we never actually connect — the test fails
        // before that on URL scheme / DNS, which is fine; we're
        // verifying that the LAZY MAP gets populated).
        let pem = rcgen_pem();
        let dir = tempfile::tempdir().expect("tempdir");
        let ca_path = dir.path().join("ca.pem");
        std::fs::write(&ca_path, &pem).unwrap();
        let origin = OriginKey {
            host_lower: "lazy-target.invalid".into(),
            port: None,
        };
        let mut per_origin_map = HashMap::new();
        per_origin_map.insert(
            origin.clone(),
            crate::npmrc::OriginTlsOverrides {
                cafiles: vec![crate::npmrc::TaggedPath {
                    path: ca_path,
                    source: "test".into(),
                    line: 1,
                    source_dir: None,
                }],
                certfile: None,
                keyfile: None,
            },
        );
        let tls = TlsOverrides {
            per_origin: per_origin_map,
            ..Default::default()
        };
        // Build via the real entry point — empty eager_origins so the
        // origin can ONLY surface via lazy. This is the exact shape
        // T4's request-aware effective set will produce for transitive
        // origins.
        let client = RegistryClient::new()
            .with_tls_overrides_for(&tls, &[])
            .expect("build ok");
        // Sanity: eager is empty.
        assert!(client.http.eager.is_empty());
        // Trigger a tarball download. The connection will fail (host
        // is .invalid + no listener), but the lazy build of the
        // per-origin client must happen BEFORE the network attempt.
        // We don't care about the request outcome — only that the
        // lazy map gets populated.
        let url = "https://lazy-target.invalid/foo/-/foo-1.0.0.tgz";
        let _ = client.download_tarball_to_file_with_auth(url, None).await;
        // Verify: lazy map now contains an entry for the URL's
        // concrete-port origin (per-origin lookup with port=None
        // fallback hit; insertion key is the URL's resolved origin).
        let lazy = client.http.lazy.lock().await;
        let concrete_port_key = OriginKey {
            host_lower: "lazy-target.invalid".into(),
            port: Some(443),
        };
        assert_eq!(
            lazy.len(),
            1,
            "lazy map must be populated by production tarball path; got: {:?}",
            lazy.keys().map(|k| k.to_string()).collect::<Vec<_>>()
        );
        assert!(
            lazy.contains_key(&concrete_port_key),
            "lazy entry must be keyed by URL's concrete-port origin"
        );
    }

    // ---- principal_fingerprint (auth + identity) ----

    #[test]
    fn principal_fingerprint_anon_when_no_auth_no_identity() {
        let fp = principal_fingerprint(None, None);
        assert_eq!(fp, "anon");
    }

    #[test]
    fn principal_fingerprint_changes_with_identity_alone() {
        // Same auth (none), different identity hash → different fingerprint.
        // Re-issued client cert must invalidate cache cleanly.
        let fp_a = principal_fingerprint(None, Some("aaaaaaaaaaaaaaaa"));
        let fp_b = principal_fingerprint(None, Some("bbbbbbbbbbbbbbbb"));
        assert_ne!(fp_a, fp_b);
        assert!(fp_a.starts_with("principal-"));
        assert!(fp_b.starts_with("principal-"));
    }

    #[test]
    fn principal_fingerprint_changes_with_auth_alone() {
        use crate::npmrc::{OriginKey, RegistryAuth};
        let bearer_a = RegistryAuth::Bearer {
            origin: OriginKey {
                host_lower: "x".into(),
                port: None,
            },
            token: SecretString::from("token-a".to_string()),
        };
        let bearer_b = RegistryAuth::Bearer {
            origin: OriginKey {
                host_lower: "x".into(),
                port: None,
            },
            token: SecretString::from("token-b".to_string()),
        };
        let fp_a = principal_fingerprint(Some(&bearer_a), None);
        let fp_b = principal_fingerprint(Some(&bearer_b), None);
        assert_ne!(fp_a, fp_b);
    }

    #[test]
    fn principal_fingerprint_auth_plus_identity_differs_from_auth_alone() {
        // The auth + identity composition is non-trivial: same auth
        // with vs. without an identity hash MUST produce distinct
        // fingerprints, otherwise a client that re-issues a cert
        // would still hit the old cache entry under the same auth.
        use crate::npmrc::{OriginKey, RegistryAuth};
        let bearer = RegistryAuth::Bearer {
            origin: OriginKey {
                host_lower: "x".into(),
                port: None,
            },
            token: SecretString::from("tok".to_string()),
        };
        let fp_no_id = principal_fingerprint(Some(&bearer), None);
        let fp_with_id = principal_fingerprint(Some(&bearer), Some("ffffffffffffffff"));
        assert_ne!(fp_no_id, fp_with_id);
    }

    #[test]
    fn cert_pem_fingerprint_is_deterministic_and_truncated() {
        let pem = b"-----BEGIN CERTIFICATE-----\nABCD\n-----END CERTIFICATE-----\n";
        let fp1 = cert_pem_fingerprint(pem);
        let fp2 = cert_pem_fingerprint(pem);
        assert_eq!(&*fp1, &*fp2);
        assert_eq!(fp1.len(), 16);
        // Different bytes → different fingerprint.
        let other = b"-----BEGIN CERTIFICATE-----\nEFGH\n-----END CERTIFICATE-----\n";
        let fp_other = cert_pem_fingerprint(other);
        assert_ne!(&*fp1, &*fp_other);
    }

    /// Lazy-target per-origin TLS origins (those configured but NOT in the
    /// eager set) must report a non-default identity_fp BEFORE the lazy build
    /// fires. Without this, `identity_fp_for_url` only consults the eager +
    /// default maps, so a rotated cert on a lazy origin reuses the old cache
    /// namespace. `with_tls_overrides_for` pre-computes an identity_fp for
    /// every configured per-origin TLS entry.
    ///
    /// Test shape: build a client with per-origin certfile configured for
    /// `lazy.internal` with an empty eager set. Verify `identity_fp_for_url`
    /// returns a fingerprint (not None / not the default's fp). Rotate the cert
    /// and verify the fp changes.
    #[test]
    fn lazy_target_origin_identity_fp_namespaces_cache_pre_dispatch() {
        let dir = tempfile::tempdir().unwrap();
        let cert_path = dir.path().join("client.pem");
        let key_path = dir.path().join("client.key");

        // First identity.
        let cert_a =
            rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).expect("rcgen a");
        std::fs::write(&cert_path, cert_a.cert.pem()).unwrap();
        std::fs::write(&key_path, cert_a.key_pair.serialize_pem()).unwrap();

        let origin = OriginKey {
            host_lower: "lazy.internal".into(),
            port: None,
        };
        let mut per_origin_map = HashMap::new();
        per_origin_map.insert(
            origin.clone(),
            crate::npmrc::OriginTlsOverrides {
                cafiles: vec![],
                certfile: Some(crate::npmrc::TaggedPath {
                    path: cert_path.clone(),
                    source: "test".into(),
                    line: 1,
                    source_dir: None,
                }),
                keyfile: Some(crate::npmrc::TaggedPath {
                    path: key_path.clone(),
                    source: "test".into(),
                    line: 2,
                    source_dir: None,
                }),
            },
        );
        let tls_a = TlsOverrides {
            per_origin: per_origin_map.clone(),
            ..Default::default()
        };
        // CRUCIAL: pass empty eager_origins — origin is lazy-only.
        let client_a = RegistryClient::new()
            .with_tls_overrides_for(&tls_a, &[])
            .expect("build a");
        // Pre-fix this would have been None / default-fp; post-fix
        // it MUST be a real fingerprint of cert_a's PEM.
        let fp_a = client_a
            .http
            .identity_fp_for_url("https://lazy.internal/foo")
            .expect("lazy-target origin must report a non-default fp");
        assert_eq!(fp_a.len(), 16);

        // Rotate the cert: write a DIFFERENT cert+key pair to the
        // same paths, rebuild HttpClients. fp must change.
        let cert_b =
            rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).expect("rcgen b");
        std::fs::write(&cert_path, cert_b.cert.pem()).unwrap();
        std::fs::write(&key_path, cert_b.key_pair.serialize_pem()).unwrap();
        let tls_b = TlsOverrides {
            per_origin: per_origin_map,
            ..Default::default()
        };
        let client_b = RegistryClient::new()
            .with_tls_overrides_for(&tls_b, &[])
            .expect("build b");
        let fp_b = client_b
            .http
            .identity_fp_for_url("https://lazy.internal/foo")
            .expect("after rotation, lazy-target fp still present");
        assert_ne!(
            fp_a, fp_b,
            "rotated cert must change cache namespace for lazy-target origin"
        );
    }

    /// End-to-end: a client built with a per-origin cert via the real
    /// `with_tls_overrides_for` entry point reports its identity_fp
    /// for URLs targeting that origin. The fingerprint is then what
    /// `principal_fingerprint` consumes for cache-key namespacing.
    #[test]
    fn http_clients_identity_fp_for_url_reflects_per_origin_cert() {
        // Generate a matching cert+key pair (same signing_key). Using
        // separate `rcgen_pem()` calls for cert and key would produce
        // a mismatched pair that fails `Identity::from_pem`.
        let cert_with_key =
            rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).expect("rcgen");
        let cert_pem_str = cert_with_key.cert.pem();
        let key_pem_str = cert_with_key.key_pair.serialize_pem();
        let dir = tempfile::tempdir().unwrap();
        let cert_path = dir.path().join("client.pem");
        std::fs::write(&cert_path, &cert_pem_str).unwrap();
        let key_path = dir.path().join("client.key");
        std::fs::write(&key_path, &key_pem_str).unwrap();
        let origin = OriginKey {
            host_lower: "corp.internal".into(),
            port: None,
        };
        let mut per_origin_map = HashMap::new();
        per_origin_map.insert(
            origin.clone(),
            crate::npmrc::OriginTlsOverrides {
                cafiles: vec![],
                certfile: Some(crate::npmrc::TaggedPath {
                    path: cert_path,
                    source: "test".into(),
                    line: 1,
                    source_dir: None,
                }),
                keyfile: Some(crate::npmrc::TaggedPath {
                    path: key_path,
                    source: "test".into(),
                    line: 2,
                    source_dir: None,
                }),
            },
        );
        let tls = TlsOverrides {
            per_origin: per_origin_map,
            ..Default::default()
        };
        let client = RegistryClient::new()
            .with_tls_overrides_for(&tls, std::slice::from_ref(&origin))
            .expect("build ok");
        // URL targeting the eager origin → fp present.
        let fp = client.http.identity_fp_for_url("https://corp.internal/foo");
        assert!(fp.is_some(), "per-origin client must carry an identity_fp");
        assert_eq!(fp.unwrap().len(), 16);
        // URL for an unrelated origin (default-routed, no global
        // identity configured) → fp None.
        let fp_other = client.http.identity_fp_for_url("https://other.example/bar");
        assert!(
            fp_other.is_none(),
            "default client without global identity must have None fp"
        );
    }

    // ---- effective TLS summary line ----

    #[test]
    fn render_effective_tls_summary_returns_none_when_default_only() {
        let client = RegistryClient::new();
        assert!(client.render_effective_tls_summary().is_none());
    }

    #[test]
    fn render_effective_tls_summary_reports_global_extra_roots() {
        let pem = rcgen_pem();
        let tls = TlsOverrides {
            extra_roots: vec![TaggedRoot {
                pem_bytes: pem,
                source: "test".into(),
                line: 1,
            }],
            ..Default::default()
        };
        let client = RegistryClient::new()
            .with_tls_overrides_for(&tls, &[])
            .expect("build ok");
        let summary = client.render_effective_tls_summary().expect("summary");
        assert!(
            summary.contains("1 extra root certificate"),
            "got: {summary}"
        );
        assert!(
            !summary.contains("extra root certificates "),
            "must singularize"
        );
    }

    #[test]
    fn render_effective_tls_summary_pluralizes_extra_roots() {
        let mut bundle = rcgen_pem();
        bundle.push(b'\n');
        bundle.extend_from_slice(&rcgen_pem());
        let tls = TlsOverrides {
            extra_roots: vec![
                TaggedRoot {
                    pem_bytes: rcgen_pem(),
                    source: "a".into(),
                    line: 1,
                },
                TaggedRoot {
                    pem_bytes: rcgen_pem(),
                    source: "b".into(),
                    line: 2,
                },
            ],
            ..Default::default()
        };
        let client = RegistryClient::new()
            .with_tls_overrides_for(&tls, &[])
            .expect("build ok");
        let summary = client.render_effective_tls_summary().expect("summary");
        assert!(
            summary.contains("2 extra root certificates"),
            "got: {summary}"
        );
    }

    /// Configured-but-unreached per-origin TLS must NOT appear in the
    /// summary. This is the core "effective-only" contract — we don't
    /// imply CI failure preconditions for origins that might or might
    /// not be hit via the lazy path later.
    #[test]
    fn render_effective_tls_summary_omits_unreached_per_origin_overrides() {
        let pem = rcgen_pem();
        let dir = tempfile::tempdir().unwrap();
        let ca_path = dir.path().join("ca.pem");
        std::fs::write(&ca_path, &pem).unwrap();
        // Configure per-origin TLS for `unused.internal`...
        let unused = OriginKey {
            host_lower: "unused.internal".into(),
            port: None,
        };
        let mut per_origin_map = HashMap::new();
        per_origin_map.insert(
            unused,
            crate::npmrc::OriginTlsOverrides {
                cafiles: vec![crate::npmrc::TaggedPath {
                    path: ca_path,
                    source: "test".into(),
                    line: 1,
                    source_dir: None,
                }],
                certfile: None,
                keyfile: None,
            },
        );
        let tls = TlsOverrides {
            per_origin: per_origin_map,
            ..Default::default()
        };
        // ...but pass empty eager_origins (effective set is empty).
        let client = RegistryClient::new()
            .with_tls_overrides_for(&tls, &[])
            .expect("build ok");
        // Nothing was eager-built and no global surface → None.
        assert!(
            client.render_effective_tls_summary().is_none(),
            "configured-but-unreached origin must not appear in summary"
        );
    }

    /// When an origin IS in the effective set + has per-origin TLS
    /// configured, its origin string appears in the summary.
    #[test]
    fn render_effective_tls_summary_lists_eager_per_origin_clients() {
        let pem = rcgen_pem();
        let dir = tempfile::tempdir().unwrap();
        let ca_path = dir.path().join("ca.pem");
        std::fs::write(&ca_path, &pem).unwrap();
        let origin = OriginKey {
            host_lower: "corp.internal".into(),
            port: None,
        };
        let mut per_origin_map = HashMap::new();
        per_origin_map.insert(
            origin.clone(),
            crate::npmrc::OriginTlsOverrides {
                cafiles: vec![crate::npmrc::TaggedPath {
                    path: ca_path,
                    source: "test".into(),
                    line: 1,
                    source_dir: None,
                }],
                certfile: None,
                keyfile: None,
            },
        );
        let tls = TlsOverrides {
            per_origin: per_origin_map,
            ..Default::default()
        };
        let client = RegistryClient::new()
            .with_tls_overrides_for(&tls, std::slice::from_ref(&origin))
            .expect("build ok");
        let summary = client.render_effective_tls_summary().expect("summary");
        assert!(
            summary.contains("per-origin TLS for //corp.internal/"),
            "got: {summary}"
        );
    }

    /// `with_tls_overrides_for` eager-builds clients for the supplied
    /// origin set when those origins have per-origin TLS configured.
    /// Verified by spot-checking the eager map.
    #[test]
    fn with_tls_overrides_for_eager_builds_only_supplied_origins() {
        // Two origins configured; we'll only ask for one.
        let pem = rcgen_pem();
        let dir = tempfile::tempdir().unwrap();
        let ca1 = dir.path().join("ca1.pem");
        let ca2 = dir.path().join("ca2.pem");
        std::fs::write(&ca1, &pem).unwrap();
        std::fs::write(&ca2, &pem).unwrap();
        let origin1 = OriginKey {
            host_lower: "wanted.internal".into(),
            port: None,
        };
        let origin2 = OriginKey {
            host_lower: "ignored.internal".into(),
            port: None,
        };
        let mut per_origin_map = HashMap::new();
        per_origin_map.insert(
            origin1.clone(),
            crate::npmrc::OriginTlsOverrides {
                cafiles: vec![crate::npmrc::TaggedPath {
                    path: ca1,
                    source: "test".into(),
                    line: 1,
                    source_dir: None,
                }],
                certfile: None,
                keyfile: None,
            },
        );
        per_origin_map.insert(
            origin2.clone(),
            crate::npmrc::OriginTlsOverrides {
                cafiles: vec![crate::npmrc::TaggedPath {
                    path: ca2,
                    source: "test".into(),
                    line: 2,
                    source_dir: None,
                }],
                certfile: None,
                keyfile: None,
            },
        );
        let tls = TlsOverrides {
            per_origin: per_origin_map,
            ..Default::default()
        };
        let client = RegistryClient::new()
            .with_tls_overrides_for(&tls, std::slice::from_ref(&origin1))
            .expect("eager build ok");
        // Only origin1 was eager-built.
        assert!(client.http.eager.contains_key(&origin1));
        assert!(!client.http.eager.contains_key(&origin2));
    }

    /// `parse_capped_metadata` rejects responses whose declared
    /// `Content-Length` exceeds `MAX_METADATA_BYTES` — before any
    /// body bytes are buffered. Bypasses hyper by writing the response
    /// preamble on a raw TCP socket so the declared-vs-actual framing
    /// discrepancy doesn't trip wiremock's mock-server panic guard
    /// (same trick the sigstore body-cap test uses).
    #[tokio::test]
    async fn parse_capped_metadata_rejects_declared_oversized_content_length() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let declared = MAX_METADATA_BYTES + 1;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener.accept().await {
                let mut buf = [0u8; 1024];
                let _ = socket.read(&mut buf).await;
                let resp = format!(
                    "HTTP/1.1 200 OK\r\n\
                     Content-Length: {declared}\r\n\
                     Content-Type: application/json\r\n\
                     Connection: close\r\n\
                     \r\n",
                );
                let _ = socket.write_all(resp.as_bytes()).await;
                let _ = socket.shutdown().await;
            }
        });

        let response = reqwest::get(format!("http://{addr}/"))
            .await
            .expect("connect should succeed");
        let result: Result<serde_json::Value, _> =
            parse_capped_metadata(response, "oversized-test").await;
        let err = result.expect_err("oversized Content-Length must reject pre-stream");
        let msg = format!("{err}");
        assert!(
            msg.contains("declared body length"),
            "expected pre-stream rejection, got: {msg}"
        );
    }

    /// Streaming case: server doesn't declare Content-Length so the
    /// pre-stream check passes, but the accumulated chunks cross the
    /// cap. wiremock serves the full body just over a small cap — we
    /// can't realistically stream 100 MB in a unit test, so this
    /// exercise uses the streaming arm through a small-cap helper that
    /// parse_capped_metadata wraps internally would require exposing.
    /// Instead we send a smaller body and rely on the pre-stream
    /// check on Content-Length. The streaming-cap arm is exercised by
    /// the sigstore L1 tests in `crate::sigstore`; the implementation
    /// shape is the same.
    #[tokio::test]
    async fn parse_capped_metadata_accepts_response_under_cap() {
        use wiremock::matchers::{method, path as match_path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let body = serde_json::json!({"name":"@scope/p","versions":{"1.0.0":{"name":"@scope/p","version":"1.0.0"}}});
        Mock::given(method("GET"))
            .and(match_path("/p"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&body))
            .mount(&server)
            .await;

        let response = reqwest::get(format!("{}/p", server.uri()))
            .await
            .expect("connect");
        let parsed: serde_json::Value = parse_capped_metadata(response, "under-cap-test")
            .await
            .expect("under-cap response must parse");
        assert_eq!(parsed["name"], "@scope/p");
    }

    /// Non-metadata API responses share the streaming-cap helper with
    /// metadata reads but cap at `MAX_API_RESPONSE_BYTES` (10 MB), one
    /// order of magnitude below the metadata tier. A whoami / token /
    /// publish-ack response that declares more than that must reject
    /// before any body bytes are buffered.
    #[tokio::test]
    async fn parse_capped_api_json_rejects_oversized_declared_length() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let declared = MAX_API_RESPONSE_BYTES + 1;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener.accept().await {
                let mut buf = [0u8; 1024];
                let _ = socket.read(&mut buf).await;
                let resp = format!(
                    "HTTP/1.1 200 OK\r\n\
                     Content-Length: {declared}\r\n\
                     Content-Type: application/json\r\n\
                     Connection: close\r\n\
                     \r\n",
                );
                let _ = socket.write_all(resp.as_bytes()).await;
                let _ = socket.shutdown().await;
            }
        });

        let response = reqwest::get(format!("http://{addr}/"))
            .await
            .expect("connect");
        let result: Result<serde_json::Value, _> =
            parse_capped_api_json(response, "api-cap-test").await;
        let err = result.expect_err("oversized Content-Length must reject pre-stream");
        let msg = format!("{err}");
        assert!(
            msg.contains("declared body length"),
            "expected pre-stream rejection, got: {msg}"
        );
    }

    /// Error-body reader has the same cap. A bogus 4xx with a hostile
    /// Content-Length must not exhaust CLI memory. The reader returns
    /// the empty string on cap-overflow so the typed error variant
    /// the caller wraps still gets a usable message.
    #[tokio::test]
    async fn read_capped_error_text_rejects_oversized_declared_length() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let declared = MAX_API_RESPONSE_BYTES + 1;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener.accept().await {
                let mut buf = [0u8; 1024];
                let _ = socket.read(&mut buf).await;
                let resp = format!(
                    "HTTP/1.1 503 Service Unavailable\r\n\
                     Content-Length: {declared}\r\n\
                     Content-Type: text/plain\r\n\
                     Connection: close\r\n\
                     \r\n",
                );
                let _ = socket.write_all(resp.as_bytes()).await;
                let _ = socket.shutdown().await;
            }
        });

        let response = reqwest::get(format!("http://{addr}/"))
            .await
            .expect("connect");
        let body = read_capped_error_text(response).await;
        assert_eq!(
            body, "",
            "cap-overflow on the error body must collapse to empty string, got {body:?}"
        );
    }

    /// reqwest's `Policy::limited` (the policy we pin on every
    /// `build_http_client_*` call) strips `Authorization`,
    /// `Cookie`, and `Proxy-Authorization` from the request that
    /// follows a cross-origin redirect. Pinning the property in a
    /// behavioural test guarantees the bearer-leak hazard from a
    /// compromised registry that 30x's to an attacker host stays
    /// closed even if a future builder edit removes the explicit
    /// `.redirect(Policy::limited(10))` call.
    #[tokio::test]
    async fn cross_host_redirect_strips_authorization_header() {
        use wiremock::matchers::{header_exists, method, path as match_path};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        use wiremock::{Request, Respond};

        // Server B captures whatever the client sends after the redirect.
        let server_b = MockServer::start().await;

        // A 302 from A to B is built dynamically so the redirect target
        // matches whatever ephemeral port the test runtime picked.
        struct RedirectTo(String);
        impl Respond for RedirectTo {
            fn respond(&self, _req: &Request) -> ResponseTemplate {
                ResponseTemplate::new(302).append_header("Location", self.0.as_str())
            }
        }

        let server_a = MockServer::start().await;
        let b_target = format!("{}/landing", server_b.uri());
        Mock::given(method("GET"))
            .and(match_path("/hop"))
            .respond_with(RedirectTo(b_target))
            .expect(1)
            .mount(&server_a)
            .await;

        // Server B: any GET to `/landing` must NOT carry an
        // `Authorization` header. `header_exists` is the negative
        // matcher — by asserting an `expect(0)` mock on this shape
        // we'd silently pass even if no request arrived, so we set
        // up TWO mocks and let the harness count.
        let bearer_hit = Mock::given(method("GET"))
            .and(match_path("/landing"))
            .and(header_exists("authorization"))
            .respond_with(ResponseTemplate::new(200).set_body_string("LEAKED"))
            .expect(0)
            .named("authorization-should-NOT-leak");
        let clean_hit = Mock::given(method("GET"))
            .and(match_path("/landing"))
            .respond_with(ResponseTemplate::new(200).set_body_string("OK"))
            .expect(1)
            .named("post-redirect-request-without-authorization");
        server_b.register(bearer_hit).await;
        server_b.register(clean_hit).await;

        let client = RegistryClient::build_http_client_with_tls(
            CONNECT_TIMEOUT,
            READ_TIMEOUT,
            &TlsOverrides::default(),
        )
        .expect("default TLS config builds");

        let body = client
            .get(format!("{}/hop", server_a.uri()))
            .bearer_auth("secret-bearer-token")
            .send()
            .await
            .expect("redirect chain should resolve")
            .text()
            .await
            .expect("body");
        assert_eq!(
            body, "OK",
            "post-redirect response must come from the no-auth mock; got {body:?}"
        );

        // wiremock asserts `expect(N)` counts on Drop; force the check
        // explicitly so the failure mode is loud and immediate.
        server_a.verify().await;
        server_b.verify().await;
    }
}
