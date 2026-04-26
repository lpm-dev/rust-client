//! Registry HTTP client.
//!
//! Handles communication with the LPM registry at `lpm.dev`.
//!
//! Phase 4 features (publish, token, OIDC) — implemented in publish.rs, npmrc.rs, oidc.rs.
//! Phase 18: ETag conditional requests + MessagePack binary cache (replacing JSON).
//! Remaining: 2FA header injection, batched metadata.
//! ETag/304 revalidation, MessagePack cache, HMAC-signed cache entries (constant-time verified).

use crate::types::*;
use lpm_auth::{RefreshPolicy, SessionManager};
use lpm_common::{DEFAULT_REGISTRY_URL, LpmError, LpmRoot, NPM_REGISTRY_URL, PackageName};
use secrecy::{ExposeSecret, SecretString};
use std::sync::Arc;
use std::time::Duration;

/// Phase 35: per-request auth posture.
///
/// Every public request method on `RegistryClient` is annotated with
/// one of these so the recovery layer (`execute_with_recovery`) can
/// decide whether to attach a bearer at all and whether to attempt a
/// silent refresh on 401.
///
/// The posture rules in §9 of the Phase 35 plan:
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
/// **Phase 42.** Replaces the old wall-clock `.timeout(30s)` which used to
/// kill entire requests even when bytes were still flowing. On the
/// decision-gate fixture (~54 direct deps, 66 MB deep NDJSON response)
/// the server legitimately takes 30 + seconds to stream the full body;
/// the wall-clock timer fired mid-body at ~51 MB / 7 500 chunks and
/// surfaced as `error decoding response body <- request or response
/// body error <- operation timed out`, forcing the install to fall
/// back to sequential resolution on every cold install above ~40
/// roots.
///
/// `read_timeout` fires ONLY when no bytes arrive for the full window.
/// Healthy streams reset the timer on each successful chunk, so a
/// 5-minute streaming response completes fine as long as chunks keep
/// landing. Hung/stalled servers still get interrupted.
const READ_TIMEOUT: Duration = Duration::from_secs(30);

/// Metadata cache TTL (5 minutes).
const METADATA_CACHE_TTL: std::time::Duration = std::time::Duration::from_secs(300);

/// File storing the metadata cache HMAC key.
const CACHE_SIGNING_KEY_FILE: &str = ".cache-signing-key";

/// Maximum compressed tarball size (500 MB). Enforced during download to prevent
/// malicious registries from exhausting memory or disk before extraction even starts.
/// Extraction-time limits (5 GB total, 500 MB per file) remain as a second defense.
pub const MAX_COMPRESSED_TARBALL_SIZE: u64 = 500 * 1024 * 1024;

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

/// HMAC-verified cache content: ETag + raw data bytes ready for deserialization.
struct CacheContent {
    etag: Option<String>,
    data: Vec<u8>,
}

/// Observability for [`RegistryClient::parallel_fetch_npm_manifests`].
///
/// Surfaced up to the Phase 49 BFS walker so `timing.resolve.streaming_bfs`
/// can report adaptive-backoff events without the walker interpreting
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
    http: reqwest::Client,
    /// Base URL of the LPM registry (default: https://lpm.dev).
    base_url: String,
    /// Base URL of the direct npm registry fallback.
    npm_registry_url: String,
    /// Bearer token for authenticated requests. None for anonymous.
    /// Wrapped in `SecretString` to prevent accidental logging/display (S5).
    token: Option<SecretString>,
    /// Path to the metadata cache directory. None disables caching.
    cache_dir: Option<std::path::PathBuf>,
    /// Persistent local HMAC key for signing metadata cache entries.
    /// Reused across CLI invocations so on-disk cache entries remain readable.
    cache_signing_key: [u8; 32],
    /// Allow insecure HTTP connections to non-localhost registries (--insecure flag).
    allow_insecure: bool,
    /// Phase 35: shared `SessionManager` for lazy-refresh-aware request
    /// auth. Stored here so that the per-method `AuthPosture` plumbing
    /// in Phase 35 Step 4 can fetch the current token / trigger silent
    /// refresh without the caller threading a session in.
    ///
    /// Step 3 wires this in but request methods do not consult it yet —
    /// they keep using `self.token`. Step 4 layers on the posture-aware
    /// dispatch and the 401 → refresh → retry path.
    session: Option<Arc<SessionManager>>,
}

impl RegistryClient {
    fn deserialize_cached_metadata(data: &[u8]) -> Option<PackageMetadata> {
        rmp_serde::from_slice(data)
            .or_else(|_| serde_json::from_slice(data))
            .ok()
    }

    /// Build the underlying `reqwest::Client` with the Phase-42 timeout
    /// configuration: connect-phase cap + per-read idle cap, no
    /// whole-request wall-clock timeout.
    ///
    /// Factored out of `new()` so tests can construct clients with short
    /// timeouts against a local fake server, keeping prod defaults
    /// uniform and easy to update in one place.
    ///
    /// **Phase 55 W1 — h1-pool transport probe (REFUTED).** When
    /// `LPM_HTTP=h1-pool` is set, the client is built with
    /// `http1_only()` + a 64-connection idle pool (matching bun's
    /// `default_max_simultaneous_requests_for_bun_install`) + TCP
    /// keepalive. The hypothesis was that bun's 64-socket-h1.1
    /// architecture bypasses some per-h2-connection flow-control
    /// throttle.
    ///
    /// **Empirical bench refuted this on `bench/fixture-large` (n=30
    /// cold-equal-footing, stream-greedy):**
    ///
    ///   h2-default   median=4273 ms  stdev=254 ms  (b5056a1 baseline)
    ///   h1-pool-64   median=4766 ms  stdev=430 ms  (-11.5 %, t=-4.57)
    ///   h1-pool-256  median=4651 ms  stdev=405 ms  ( -8.9 %, t=-3.46)
    ///
    /// Both h1-pool variants are **statistically significantly slower
    /// than h2-default**. The TLS handshake overhead per new
    /// connection + TCP slow-start tax outweigh any per-connection
    /// flow-control benefit at this scale. Default stays HTTP/2.
    /// Bun's speed advantage is NOT in HTTP/1 vs HTTP/2 transport.
    /// Kept as opt-in so future debugging on different network
    /// regimes (CDN routing changes, server-side h2 throttle policy
    /// changes) can A/B without rewriting this branch.
    fn build_http_client(connect_timeout: Duration, read_timeout: Duration) -> reqwest::Client {
        let mut b = reqwest::Client::builder()
            .connect_timeout(connect_timeout)
            .read_timeout(read_timeout)
            .user_agent(format!("lpm-rs/{}", env!("CARGO_PKG_VERSION")));
        if std::env::var("LPM_HTTP").as_deref() == Ok("h1-pool") {
            b = b
                .http1_only()
                .pool_max_idle_per_host(64)
                .pool_idle_timeout(Duration::from_secs(120))
                .tcp_keepalive(Duration::from_secs(60))
                .tcp_nodelay(true);
        }
        b.build().expect("failed to build HTTP client")
    }

    /// Create a new registry client with default settings.
    pub fn new() -> Self {
        let http = Self::build_http_client(CONNECT_TIMEOUT, READ_TIMEOUT);

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

        let cache_signing_key = load_or_create_cache_signing_key(cache_dir.as_deref());

        RegistryClient {
            http,
            base_url: DEFAULT_REGISTRY_URL.to_string(),
            npm_registry_url: NPM_REGISTRY_URL.to_string(),
            token: None,
            cache_dir,
            cache_signing_key,
            allow_insecure: false,
            session: None,
        }
    }

    /// Get the current base URL.
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Phase 43 — returns true if the URL's origin matches one of
    /// the origins this client is configured to talk to (the LPM
    /// `base_url` or the npm `npm_registry_url`). Used by
    /// [`evaluate_cached_url`] as the origin gate on lockfile-stored
    /// tarball URLs: a rebased URL from an older `LPM_REGISTRY_URL`
    /// mismatches and falls through to on-demand lookup against the
    /// current mirror.
    ///
    /// Opaque origins (`file://`, `data:`, etc.) never match because
    /// `base_url` / `npm_registry_url` are always tuple origins
    /// (https or http(localhost)). Malformed URLs return `false`.
    pub fn is_configured_origin(&self, url: &str) -> bool {
        let Ok(parsed) = reqwest::Url::parse(url) else {
            return false;
        };
        let parsed_origin = parsed.origin().ascii_serialization();
        [&self.base_url, &self.npm_registry_url]
            .iter()
            .any(|configured| {
                reqwest::Url::parse(configured)
                    .map(|u| u.origin().ascii_serialization() == parsed_origin)
                    .unwrap_or(false)
            })
    }

    /// Set the registry base URL.
    ///
    /// Stores the URL for later validation. Non-localhost HTTP URLs are rejected
    /// at request time unless `--insecure` is set via [`with_insecure`].
    pub fn with_base_url(mut self, url: impl Into<String>) -> Self {
        self.base_url = url.into();
        self
    }

    /// Override the npm registry URL (default: `https://registry.npmjs.org`).
    ///
    /// Cross-crate test use + future custom-mirror support. Phase 49's
    /// walker tests depend on this to point a mocked registry at the
    /// walker via `UpstreamRoute::NpmDirect` without round-tripping the
    /// real npmjs. The W4 memory flagged this setter as test-only, but
    /// the concern there was lockfile multi-registry correctness, not
    /// setter visibility — promoting to `pub` is orthogonal.
    pub fn with_npm_registry_url(mut self, url: impl Into<String>) -> Self {
        self.npm_registry_url = url.into();
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
    ///
    /// **Also re-derives the HMAC signing key** from the new directory
    /// via [`load_or_create_cache_signing_key`]. Without this, a
    /// caller pointing the client at a fresh tempdir would write
    /// entries signed by the ORIGINAL directory's key, so any other
    /// client later reading from that tempdir would fail HMAC
    /// verification (or worse, succeed against a key that's no
    /// longer controlled by the code path that wrote the entry).
    /// For `None`, the key is regenerated as a throwaway — unused
    /// since the cache-path helpers short-circuit on `None`, but
    /// keeps the invariant "`cache_dir` fully determines
    /// `cache_signing_key`."
    pub fn with_cache_dir(mut self, dir: Option<std::path::PathBuf>) -> Self {
        self.cache_signing_key = load_or_create_cache_signing_key(dir.as_deref());
        self.cache_dir = dir;
        self
    }

    /// Allow insecure HTTP connections to non-localhost registries.
    /// Required when using `--insecure` CLI flag.
    pub fn with_insecure(mut self, allow: bool) -> Self {
        self.allow_insecure = allow;
        self
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
    /// variants. The Phase 43 [`evaluate_cached_url`] gate mirrors
    /// this same predicate set on the lockfile-read path.
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

    /// Phase 35: attach the shared `SessionManager` so request methods
    /// can fetch a token / trigger silent refresh on demand. Idempotent
    /// — subsequent calls replace the prior session reference. Step 3
    /// only stores this; Step 4 makes request methods consult it.
    pub fn with_session(mut self, session: Arc<SessionManager>) -> Self {
        self.session = Some(session);
        self
    }

    /// Phase 35: read access to the attached session (for callers that
    /// need to consult source/posture without going through request
    /// methods — e.g., the `tunnel` command checks this before
    /// connecting).
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
            cache_signing_key: self.cache_signing_key,
            allow_insecure: self.allow_insecure,
            session: self.session.clone(),
        }
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

        // Phase 40 P3a — wall-clock the entire RPC (request + parse).
        // Metadata fetches dominate `resolve_ms` on cold installs; the
        // timer feeds `crate::timing::record_rpc` so the resolver can
        // surface the bound in `--json` as
        // `timing.resolve.metadata_rpc_ms`.
        let rpc_start = std::time::Instant::now();

        // Posture: AuthRequired. Batch metadata may include `@lpm.dev`
        // packages whose metadata is auth-gated; on 401 the recovery
        // wrapper lazily refreshes and re-runs the entire closure
        // (request + parse) once.
        let result = self
            .execute_with_recovery(AuthPosture::AuthRequired, || async {
                let mut req = self
                    .http
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
    /// fully-populated map. Phase 49: the old streaming-channel
    /// emission path (`tx: Option<Sender>`) was retired along with
    /// `batch_metadata_deep_streaming` — the walker's own
    /// `spec_tx.send` feeds the speculation dispatcher now.
    async fn parse_ndjson_batch(
        &self,
        response: reqwest::Response,
    ) -> Result<std::collections::HashMap<String, PackageMetadata>, LpmError> {
        let mut map = std::collections::HashMap::new();
        let mut buffer = Vec::new();
        // **Phase 42 fix — avoid quadratic `\n` scan.** Each time reqwest
        // gives us a fresh chunk we append to `buffer` and then look for a
        // newline to frame the next NDJSON line. The pre-fix code scanned
        // the whole buffer from offset 0 on every chunk, so with ~30
        // chunks per 200 KB line the scan cost per line grew triangularly
        // (1×9 KB + 2×9 KB + … + 30×9 KB ≈ 4 MB per line). Across ~365
        // lines in the decision-gate response that's ~1.5 GB of re-scan.
        // At the measured ~74 MB/s `iter().position` throughput that alone
        // burned ~21 s of the ~40 s `initial_batch_ms` — the "5× ingestion
        // tax" versus raw reqwest drain (which completes in ~7 s).
        //
        // `scan_from` tracks the first byte we haven't inspected for a
        // newline yet. After each chunk it resumes from there; after a
        // drain (line consumed) the remaining buffer shifted to position
        // 0 so `scan_from` resets to 0 too. Total scan work becomes
        // O(total bytes) instead of O(chunks × buffer_size).
        let mut scan_from: usize = 0;
        // Phase 34.4: measure NDJSON parse and cache write separately
        let mut json_parse_ns: u128 = 0;
        let mut cache_write_ns: u128 = 0;

        // Read chunks from the response body and parse complete lines.
        //
        // **Phase 42 diagnostic.** `reqwest::Error`'s top-level Display is
        // the kind only (e.g. "error decoding response body"). The actual
        // fault — premature-EOF vs HTTP/2 RST_STREAM vs chunked-encoding
        // malform — lives in the `source()` chain that bubbles from hyper.
        // Walk the chain explicitly so the warn log is diagnostic,
        // otherwise every failure surfaces as the same opaque string and
        // we can't tell which layer reported it.
        let mut response = response;
        let mut bytes_read: u64 = 0;
        let mut chunks_read: u64 = 0;
        loop {
            match response.chunk().await {
                Ok(None) => break,
                Ok(Some(chunk)) => {
                    chunks_read += 1;
                    bytes_read += chunk.len() as u64;
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
                    // Phase 34.5: parse directly into typed struct, avoiding
                    // the intermediate Value + clone that doubled parse cost.
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

        // Phase 40 P3a — feed the locally-accumulated parse time into
        // the resolver-visible `parse_ndjson_ms` counter. Cache-write
        // is intentionally NOT reported here: it's disk I/O, not
        // parse CPU, and mixing the two would make the P3d lever
        // (slim the batch response) look less valuable than it is.
        crate::timing::record_parse(std::time::Duration::from_nanos(json_parse_ns as u64));

        Ok(map)
    }

    /// Parse a legacy JSON batch response: `{ "packages": { "name": {...} } }`
    async fn parse_json_batch(
        &self,
        response: reqwest::Response,
    ) -> Result<std::collections::HashMap<String, PackageMetadata>, LpmError> {
        let result: serde_json::Value = response
            .json()
            .await
            .map_err(|e| LpmError::Registry(format!("batch metadata parse error: {e}")))?;

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

        // Phase 40 P3a — time the network portion only. TTL cache
        // hits above return before this point, so the RPC counter
        // never double-counts them.
        let rpc_start = std::time::Instant::now();

        // Posture: AuthRequired. `@lpm.dev` package metadata may be
        // gated; on 401 the recovery wrapper performs one silent
        // refresh + retry. The closure re-reads ETag + bearer each
        // attempt so the rotated token is used on retry.
        let result = self
            .execute_with_recovery(AuthPosture::AuthRequired, || async {
                let cache_content = self.read_cache_content(&cache_key);
                let mut req = self.build_get(&url);
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
                    response = self.send_with_retry(self.build_get(&url)).await?;
                }

                let etag = response
                    .headers()
                    .get("etag")
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.to_string());

                let metadata: PackageMetadata = response.json().await.map_err(|e| {
                    LpmError::Registry(format!("failed to parse response from {url}: {e}"))
                })?;

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

        // Phase 40 P3a — past this point the call WILL hit a registry
        // (proxy or upstream). `record_rpc` fires in each tier's exit
        // path (success or error) so the counter captures real
        // network time, not cache fast-paths.
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

        let mut req = self.build_get(&proxy_url);
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
                    response = self.send_with_retry(self.build_get(&proxy_url)).await?;
                }

                if response.status().is_success() {
                    let etag = response
                        .headers()
                        .get("etag")
                        .and_then(|v| v.to_str().ok())
                        .map(|s| s.to_string());

                    if let Ok(metadata) = response.json::<PackageMetadata>().await {
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
                // Phase 34.5: proxy returned 401/403 for a bare npm package.
                // This is expected when the user isn't logged in — fall through
                // to the public npm registry which doesn't need auth.
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
                    .get(&npm_url)
                    .header("Accept", "application/vnd.npm.install-v1+json"),
            )
            .await
        {
            Ok(r) => r,
            Err(e) => return finish!(Err(e)),
        };
        let metadata_res = response.json::<PackageMetadata>().await.map_err(|e| {
            LpmError::Registry(format!("failed to parse npm metadata for {name}: {e}"))
        });
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
    /// Used by Phase 49's BFS walker when running in
    /// [`RouteMode::Direct`](crate::RouteMode::Direct): bypassing the
    /// Worker is the whole point, so we must NOT fall back to it on a
    /// miss. Tier 1 (TTL + HMAC cache) is preserved so warm installs and
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
                    .get(&npm_url)
                    .header("Accept", "application/vnd.npm.install-v1+json"),
            )
            .await
        {
            Ok(r) => r,
            Err(e) => return finish!(Err(e)),
        };
        let metadata = match response.json::<PackageMetadata>().await {
            Ok(m) => m,
            Err(e) => {
                return finish!(Err(LpmError::Registry(format!(
                    "failed to parse npm metadata for {name}: {e}"
                ))));
            }
        };
        self.write_metadata_cache(&cache_key, &metadata, None);
        finish!(Ok(metadata))
    }

    /// Fetch npm metadata honoring an explicit upstream route.
    ///
    /// [`UpstreamRoute::LpmWorker`] → full three-tier chain via
    /// [`Self::get_npm_package_metadata`] (cache → proxy → direct fallback).
    /// [`UpstreamRoute::NpmDirect`] → cache + direct npm only, skipping the
    /// Worker hop (Phase 49 default behavior for npm packages).
    ///
    /// This is the single entry point the Phase 49 BFS walker and the
    /// provider's escape-hatch path use, so routing policy lives in one
    /// place.
    pub async fn get_npm_metadata_routed(
        &self,
        name: &str,
        route: crate::UpstreamRoute,
    ) -> Result<PackageMetadata, LpmError> {
        match route {
            crate::UpstreamRoute::LpmWorker => self.get_npm_package_metadata(name).await,
            crate::UpstreamRoute::NpmDirect => self.get_npm_metadata_direct(name).await,
        }
    }

    /// Fan-out npm metadata fetches at `max_concurrency`, direct to
    /// `registry.npmjs.org`, with **halve-on-429** adaptive back-pressure.
    ///
    /// Returned vector is in input order; each entry is a per-package
    /// `Result`. Per-package failures do NOT abort the batch — matches
    /// bun/pnpm semantics and lets the Phase 49 walker log + continue
    /// (preplan §7.1).
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

        let response = self.send_with_retry(self.build_get(url)).await?;

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

        let mut response = self.send_with_retry(self.build_get(url)).await?;

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

    /// Streaming tarball download — Phase 38 P1 fast path.
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

        let response = self.send_with_retry(self.build_get(url)).await?;

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

    // ─── Discovery Endpoints ────────────────────────────────────────

    /// Search packages.
    ///
    /// Posture: `AnonymousPreferred` — public discovery endpoint, no
    /// bearer attached even when stored (plan §9.2).
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
            let req = self.http.post(&url).bearer_auth(&bearer).json(&body);
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
            let body: serde_json::Value = response.json().await.map_err(|e| {
                LpmError::Registry(format!("failed to parse publish response: {e}"))
            })?;

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
    /// Posture: `AuthRequired` (account-scoped data). GPT audit fix
    /// (post-Step-5): pre-fix this went through plain `get_json`,
    /// which inherits `current_bearer` but does not refresh on 401.
    /// A stored session with an expired access token would surface
    /// `AuthRequired` instead of self-healing.
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
    /// contract as `get_pool_stats` — GPT audit fix (post-Step-5).
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
            .send_with_retry(self.build_get_with_posture(&url, AuthPosture::AnonymousOnly))
            .await?;
        Ok(response.status().is_success())
    }

    // ─── Tunnel Endpoints ──────────────────────────────────────────

    /// List claimed tunnel domains.
    ///
    /// Posture: `SessionRequired`. Wrapped in `execute_with_recovery`
    /// so the post-Phase-35 stale-access-token case still self-heals
    /// for refresh-backed sessions (audit fix #3).
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
            let data: serde_json::Value = response
                .json()
                .await
                .map_err(|e| LpmError::Registry(format!("failed to parse response: {e}")))?;

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
            let mut req = self.http.delete(&url);
            if let Some(bearer) = self.current_bearer(AuthPosture::SessionRequired) {
                req = req.bearer_auth(bearer);
            }
            let response = self.send_with_retry(req).await?;
            let status = response.status();
            let data: serde_json::Value = response
                .json()
                .await
                .map_err(|e| LpmError::Registry(format!("failed to parse response: {e}")))?;

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

    /// Cache key → filename hash. Uses a fast hash for flat file structure.
    fn cache_path(&self, key: &str) -> Option<std::path::PathBuf> {
        let dir = self.cache_dir.as_ref()?;
        // Simple hash: use first 16 hex chars of SHA-256
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(key.as_bytes());
        let hash = format!("{:x}", hasher.finalize());
        Some(dir.join(&hash[..16]))
    }

    /// Invalidate a cached metadata entry.
    ///
    /// Used when a tarball download returns 404 — the cached metadata likely
    /// references an unpublished version. Deleting the cache forces a fresh
    /// fetch on the next request.
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

    /// Compute HMAC-SHA256 hex digest over the given data using the per-process signing key.
    fn compute_cache_hmac(&self, data: &[u8]) -> String {
        use hmac::{Hmac, Mac};
        type HmacSha256 = Hmac<sha2::Sha256>;
        let mut mac = HmacSha256::new_from_slice(&self.cache_signing_key)
            .expect("HMAC key length is always valid (32 bytes)");
        mac.update(data);
        hex::encode(mac.finalize().into_bytes())
    }

    /// Verify HMAC-SHA256 using constant-time comparison (via `subtle` crate).
    ///
    /// Prevents timing side-channel attacks on cache HMAC verification.
    fn verify_cache_hmac(&self, data: &[u8], expected_hex: &[u8]) -> bool {
        use hmac::{Hmac, Mac};
        type HmacSha256 = Hmac<sha2::Sha256>;
        let mut mac = HmacSha256::new_from_slice(&self.cache_signing_key)
            .expect("HMAC key length is always valid (32 bytes)");
        mac.update(data);
        let Ok(expected_bytes) = hex::decode(expected_hex) else {
            return false;
        };
        // verify_slice uses subtle::ConstantTimeEq internally
        mac.verify_slice(&expected_bytes).is_ok()
    }

    /// Read cached metadata if it exists, is within TTL, and has a valid HMAC.
    ///
    /// Returns `(PackageMetadata, Option<etag>)`. The ETag (if present) can be
    /// sent as `If-None-Match` on the next request to enable 304 responses.
    ///
    /// Cache format (v2): `{HMAC_hex}\n{ETag}\n{binary_data}`
    /// - Line 1: HMAC-SHA256 hex of the binary data (integrity)
    /// - Line 2: ETag string (empty if server didn't send one)
    /// - Line 3+: MessagePack-serialized PackageMetadata (with JSON fallback for migration)
    fn read_metadata_cache(&self, key: &str) -> Option<(PackageMetadata, Option<String>)> {
        let path = self.cache_path(key)?;
        if !path.exists() {
            return None;
        }

        // Check TTL based on file modification time
        let modified = path.metadata().ok()?.modified().ok()?;
        let age = std::time::SystemTime::now().duration_since(modified).ok()?;
        if age > METADATA_CACHE_TTL {
            return None;
        }

        // Read raw bytes — format is: HMAC\nETag\ndata (all binary-safe)
        let content = std::fs::read(&path).ok()?;

        // Find first newline (end of HMAC hex)
        let first_nl = content.iter().position(|&b| b == b'\n')?;
        // Find second newline (end of ETag)
        let second_nl = content[first_nl + 1..]
            .iter()
            .position(|&b| b == b'\n')
            .map(|pos| first_nl + 1 + pos)?;

        let hmac_hex = &content[..first_nl];
        let etag_bytes = &content[first_nl + 1..second_nl];
        let data = &content[second_nl + 1..];

        // Verify HMAC (constant-time) — if it doesn't match, the entry is tampered or old format
        if !self.verify_cache_hmac(data, hmac_hex) {
            return None;
        }

        // Deserialize: try MessagePack first, fall back to JSON for migration from v1 caches
        let metadata: PackageMetadata = rmp_serde::from_slice(data)
            .or_else(|_| serde_json::from_slice(data))
            .ok()?;

        let etag = std::str::from_utf8(etag_bytes)
            .ok()
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string());

        Some((metadata, etag))
    }

    /// Read the ETag and HMAC-verified data bytes from a cached entry without deserializing.
    ///
    /// Returns `(Option<etag>, verified_data_bytes)`. The data bytes can be deserialized
    /// by the caller on a 304 response, avoiding a second file read.
    /// Does NOT check TTL — used for conditional requests where the cache may be stale.
    fn read_cache_content(&self, key: &str) -> Option<CacheContent> {
        let path = self.cache_path(key)?;
        if !path.exists() {
            return None;
        }

        let content = std::fs::read(&path).ok()?;
        let first_nl = content.iter().position(|&b| b == b'\n')?;
        let second_nl = content[first_nl + 1..]
            .iter()
            .position(|&b| b == b'\n')
            .map(|pos| first_nl + 1 + pos)?;

        // Verify HMAC (constant-time) before trusting the content
        let data = &content[second_nl + 1..];
        if !self.verify_cache_hmac(data, &content[..first_nl]) {
            return None;
        }

        let etag = std::str::from_utf8(&content[first_nl + 1..second_nl])
            .ok()
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string());

        Some(CacheContent {
            etag,
            data: data.to_vec(),
        })
    }

    /// Write metadata to cache with HMAC signing and optional ETag.
    ///
    /// Serializes to MessagePack (binary, ~40-60% smaller than JSON).
    /// Falls back to JSON if MessagePack serialization fails.
    fn write_metadata_cache(&self, key: &str, metadata: &PackageMetadata, etag: Option<&str>) {
        if let Some(path) = self.cache_path(key) {
            // Serialize: prefer MessagePack, fall back to JSON
            let data = match rmp_serde::to_vec(metadata) {
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

            let hmac_hex = self.compute_cache_hmac(&data);
            let etag_str = etag.unwrap_or("");

            // Build: HMAC\nETag\ndata
            let mut content =
                Vec::with_capacity(hmac_hex.len() + 1 + etag_str.len() + 1 + data.len());
            content.extend_from_slice(hmac_hex.as_bytes());
            content.push(b'\n');
            content.extend_from_slice(etag_str.as_bytes());
            content.push(b'\n');
            content.extend_from_slice(&data);

            if let Err(e) = std::fs::write(&path, &content) {
                tracing::warn!("failed to write metadata cache for {}: {}", key, e);
            }
        }
    }

    // ─── Internal: HTTP transport with retry ────────────────────────

    /// POST JSON with auth, returning the raw response (for callers that need status/headers).
    pub async fn post_json_raw(
        &self,
        url: &str,
        body: &serde_json::Value,
    ) -> Result<reqwest::Response, LpmError> {
        let mut req = self.http.post(url).json(body);
        if let Some(bearer) = self.current_bearer(AuthPosture::AuthRequired) {
            req = req.bearer_auth(bearer);
        }
        self.send_with_retry(req).await
    }

    /// Build a GET request with auth headers (legacy entry point —
    /// defaults to `AuthRequired` posture, attaching the bearer when
    /// available). Use `build_get_with_posture` for explicit control.
    fn build_get(&self, url: &str) -> reqwest::RequestBuilder {
        self.build_get_with_posture(url, AuthPosture::AuthRequired)
    }

    /// Build a GET request honoring the caller's auth posture.
    ///
    /// GPT audit fix #3 (post-Step-5): the `AnonymousOnly` and
    /// `AnonymousPreferred` postures must NOT attach the bearer even
    /// when one is stored — see plan §9.2. `current_bearer` already
    /// returns `None` for those postures, so this just wires the
    /// caller's choice through.
    fn build_get_with_posture(&self, url: &str, posture: AuthPosture) -> reqwest::RequestBuilder {
        let mut req = self.http.get(url);
        if let Some(bearer) = self.current_bearer(posture) {
            req = req.bearer_auth(bearer);
        }
        req
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
            .send_with_retry(self.build_get_with_posture(url, posture))
            .await?;
        response
            .json()
            .await
            .map_err(|e| LpmError::Registry(format!("failed to parse response from {url}: {e}")))
    }

    /// Phase 35: resolve the bearer to attach for a given posture.
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
        // Phase 45 P2 — use the lazy variant here so keychain
        // classification fires on the first actual network request,
        // not at process startup. Warm / offline / fully-cached runs
        // skip the ~50 ms macOS Keychain IPC entirely because this
        // method is never reached.
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

    /// Phase 35: execute an HTTP-bearing operation, handling lazy
    /// refresh on 401 for refresh-backed sessions.
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
        let response = self.send_with_retry(self.build_get(url)).await?;
        response
            .json()
            .await
            .map_err(|e| LpmError::Registry(format!("failed to parse response from {url}: {e}")))
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

            match self.http.execute(req).await {
                Ok(response) => {
                    let status = response.status().as_u16();

                    match status {
                        200..=299 | 304 => return Ok(response),

                        // Non-retryable client errors — fail immediately
                        401 => return Err(LpmError::AuthRequired),
                        403 => {
                            let body = response.text().await.unwrap_or_default();
                            return Err(LpmError::Forbidden(body));
                        }
                        404 => {
                            let body = response.text().await.unwrap_or_default();
                            return Err(LpmError::NotFound(body));
                        }

                        // S4: 500 — do NOT retry. Server may have stored the version.
                        // Check if the version now exists on the registry.
                        500 => {
                            let body_text = response.text().await.unwrap_or_default();
                            tracing::warn!("publish got HTTP 500 — checking if version was stored");

                            // Check if the version exists by GETting the package
                            let check_url =
                                format!("{}/api/registry/{}", self.base_url, encoded_name);
                            if let Ok(check_resp) =
                                self.send_with_retry(self.build_get(&check_url)).await
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
                                tokio::time::sleep(Duration::from_secs(retry_after)).await;
                                continue;
                            }
                        }

                        // Retryable gateway errors only (NOT 500)
                        502..=504 => {
                            let body = response.text().await.unwrap_or_default();
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
                            let body = response.text().await.unwrap_or_default();
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

            match self.http.execute(req).await {
                Ok(response) => {
                    let status = response.status().as_u16();

                    match status {
                        200..=299 | 304 => return Ok(response),

                        // Non-retryable errors — fail immediately
                        401 => return Err(LpmError::AuthRequired),
                        403 => {
                            let body = response.text().await.unwrap_or_default();
                            return Err(LpmError::Forbidden(body));
                        }
                        404 => {
                            let body = response.text().await.unwrap_or_default();
                            return Err(LpmError::NotFound(body));
                        }

                        // Retryable: rate limit
                        429 => {
                            let retry_after = parse_retry_after(&response);
                            last_error = Some(LpmError::RateLimited {
                                retry_after_secs: retry_after,
                            });
                            if attempt < MAX_RETRIES {
                                tokio::time::sleep(Duration::from_secs(retry_after)).await;
                                continue;
                            }
                        }

                        // Retryable: server errors and timeouts
                        408 | 500 | 502 | 503 | 504 => {
                            let body = response.text().await.unwrap_or_default();
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
                            let body = response.text().await.unwrap_or_default();
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
/// Phase 43 — promoted from private to `pub` so `evaluate_cached_url`
/// (and anyone else composing URL-safety checks) can reuse the same
/// predicate `download_tarball_to_file` enforces pre-flight.
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
        .map(|ip| ip.is_loopback())
        .unwrap_or(false)
}

/// Check if a URL uses the HTTPS scheme.
///
/// Phase 43 — promoted from private to `pub` for the same reason
/// as [`is_localhost_url`]: composable scheme-safety gate for
/// lockfile-cached URLs.
pub fn is_https_url(url: &str) -> bool {
    reqwest::Url::parse(url)
        .map(|parsed| parsed.scheme() == "https")
        .unwrap_or(false)
}

/// Check if a URL uses the HTTP scheme.
///
/// Paired with [`is_https_url`] and [`is_localhost_url`] so the
/// `--insecure` carve-out can specifically widen the scheme gate
/// to plain HTTP — not to `file://`, `ftp://`, `data:`, or any
/// other non-HTTPS scheme. See
/// [`RegistryClient::check_tarball_url_scheme`] for the enforcement
/// site.
pub fn is_http_url(url: &str) -> bool {
    reqwest::Url::parse(url)
        .map(|parsed| parsed.scheme() == "http")
        .unwrap_or(false)
}

/// Outcome of [`evaluate_cached_url`] — Phase 43 gate on lockfile-
/// stored tarball URLs before they're dispatched to the fetch
/// pipeline. A dedicated variant per rejection reason so callers
/// can emit targeted telemetry (`tarball_url_origin_mismatch_count`
/// vs `_shape_mismatch_count`) without re-running the checks.
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

/// Phase 43 — gate a lockfile-stored tarball URL before reusing it
/// on the fetch path. Combines scheme, shape, and origin checks
/// with a distinct `GateDecision` per rejection reason so callers
/// can bump the right telemetry counter.
///
/// The shape check requires both `.tgz` suffix AND a `/-/` path
/// segment. Both LPM (`/api/registry/{scope}/{pkg}/-/...`) and
/// npm (`/{pkg}/-/...`) emit URLs in this shape; attacker-crafted
/// `.tgz`-suffixed admin paths like `/api/admin/foo.tgz` lack the
/// `/-/` segment and are rejected before the bearer is attached.
/// See phase-43 design doc §P43-2 for the full threat model.
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
    // on-demand lookup against the new origin. The generalized
    // writeback trigger (P43-2 Change 3) picks up the fresh URLs
    // and rewrites the lockfile so the second install short-
    // circuits.
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
fn backoff_delay(attempt: u32) -> Duration {
    let delay = RETRY_BASE_DELAY * 2u32.pow(attempt);
    delay.min(RETRY_MAX_DELAY)
}

fn generate_cache_signing_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    use rand::RngCore;
    rand::thread_rng().fill_bytes(&mut key);
    key
}

fn read_cache_signing_key(path: &std::path::Path) -> Option<[u8; 32]> {
    let encoded = std::fs::read_to_string(path).ok()?;
    let decoded = hex::decode(encoded.trim()).ok()?;
    if decoded.len() != 32 {
        return None;
    }

    let mut key = [0u8; 32];
    key.copy_from_slice(&decoded);
    Some(key)
}

fn write_cache_signing_key(
    path: &std::path::Path,
    key: &[u8; 32],
    create_new: bool,
) -> Result<(), std::io::Error> {
    use std::fs::OpenOptions;
    use std::io::Write;

    let mut options = OpenOptions::new();
    options.write(true);
    if create_new {
        options.create_new(true);
    } else {
        options.create(true).truncate(true);
    }

    let mut file = options.open(path)?;
    file.write_all(hex::encode(key).as_bytes())?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }

    Ok(())
}

fn load_or_create_cache_signing_key(cache_dir: Option<&std::path::Path>) -> [u8; 32] {
    let Some(cache_dir) = cache_dir else {
        return generate_cache_signing_key();
    };

    let key_path = cache_dir.join(CACHE_SIGNING_KEY_FILE);

    if let Some(key) = read_cache_signing_key(&key_path) {
        return key;
    }

    let key = generate_cache_signing_key();

    if key_path.exists() {
        if let Err(error) = write_cache_signing_key(&key_path, &key, false) {
            tracing::warn!(
                "failed to repair metadata cache signing key {}: {}",
                key_path.display(),
                error
            );
            return key;
        }
        return read_cache_signing_key(&key_path).unwrap_or(key);
    }

    match write_cache_signing_key(&key_path, &key, true) {
        Ok(()) => key,
        Err(error) => {
            if let Some(existing) = read_cache_signing_key(&key_path) {
                return existing;
            }

            tracing::warn!(
                "failed to persist metadata cache signing key {}: {}",
                key_path.display(),
                error
            );
            key
        }
    }
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

    // ─── Metadata Cache Tests ──────────────────────────────────────

    /// Helper: create a RegistryClient with a temporary cache directory.
    fn client_with_temp_cache() -> (RegistryClient, tempfile::TempDir) {
        let tmp = tempfile::tempdir().expect("failed to create temp dir");
        let mut client = RegistryClient::new();
        client.cache_dir = Some(tmp.path().to_path_buf());
        client.cache_signing_key = load_or_create_cache_signing_key(client.cache_dir.as_deref());
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
        reader.cache_signing_key = load_or_create_cache_signing_key(reader.cache_dir.as_deref());

        let result = reader.read_metadata_cache("restart-key");

        assert!(
            result.is_some(),
            "cache entries should remain readable across fresh client instances"
        );
        let (read_meta, read_etag) = result.unwrap();
        assert_eq!(read_meta.name, "@lpm.dev/test.restart");
        assert_eq!(read_etag.as_deref(), Some("\"restart-etag\""));
    }

    #[test]
    fn old_format_cache_treated_as_miss() {
        let (client, _tmp) = client_with_temp_cache();

        // Write old format directly: HMAC\nJSON (no ETag line)
        if let Some(path) = client.cache_path("old-format-key") {
            let json_data = r#"{"name":"old","versions":{}}"#;
            use hmac::{Hmac, Mac};
            type HmacSha256 = Hmac<sha2::Sha256>;
            let mut mac = HmacSha256::new_from_slice(&client.cache_signing_key).unwrap();
            mac.update(json_data.as_bytes());
            let hmac_hex = hex::encode(mac.finalize().into_bytes());
            let old_content = format!("{hmac_hex}\n{json_data}");
            std::fs::write(&path, old_content).unwrap();
        }

        // New reader expects HMAC\nETag\ndata — the old format has HMAC\nJSON.
        // The HMAC was computed over the JSON string, but the new reader splits
        // at the second newline and computes HMAC over the remainder. Since the
        // splits are different, the HMAC won't match → treated as cache miss.
        let result = client.read_metadata_cache("old-format-key");
        assert!(
            result.is_none(),
            "old format should be treated as cache miss"
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

    #[test]
    fn cache_miss_on_tampered_data() {
        let (client, _tmp) = client_with_temp_cache();
        let meta = test_metadata("@lpm.dev/test.tampered");

        client.write_metadata_cache("tamper-key", &meta, Some("\"etag\""));

        // Tamper with the cached file
        if let Some(path) = client.cache_path("tamper-key") {
            let mut content = std::fs::read(&path).unwrap();
            // Flip a byte in the data portion (after the second newline)
            if let Some(last) = content.last_mut() {
                *last ^= 0xFF;
            }
            std::fs::write(&path, &content).unwrap();
        }

        let result = client.read_metadata_cache("tamper-key");
        assert!(result.is_none(), "tampered cache should be a miss");
    }

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
        // Finding 1 regression guard: `--insecure` is HTTP-only by
        // contract (see `--insecure` help text in lpm-cli and the
        // doc comment on `check_tarball_url_scheme`). `file://` must
        // remain rejected even with the flag set, or a tampered
        // lockfile could steer the installer at arbitrary local
        // files.
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

    // ─── Mock HTTP Tests for ETag/304 Flow ───────────────────────────

    /// Helper: create a RegistryClient pointed at a mock server with temp cache.
    fn client_with_mock_server(server_uri: &str) -> (RegistryClient, tempfile::TempDir) {
        let tmp = tempfile::tempdir().expect("failed to create temp dir");
        let mut client = RegistryClient::new().with_base_url(server_uri);
        client.cache_dir = Some(tmp.path().to_path_buf());
        (client, tmp)
    }

    // ── Phase 43: evaluate_cached_url gate ───────────────────────────────

    #[test]
    fn phase43_gate_accepts_canonical_lpm_tarball_url() {
        let client = RegistryClient::new().with_base_url("https://lpm.dev");
        // Canonical LPM tarball path: /api/registry/{scope}/{pkg}/-/...tgz
        let url = "https://lpm.dev/api/registry/@scope/pkg/-/pkg-1.0.0.tgz";
        assert_eq!(evaluate_cached_url(url, &client), GateDecision::Accepted);
    }

    #[test]
    fn phase43_gate_accepts_canonical_npm_tarball_url() {
        let client = RegistryClient::new();
        // Default `npm_registry_url` is `https://registry.npmjs.org`.
        let url = "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz";
        assert_eq!(evaluate_cached_url(url, &client), GateDecision::Accepted);
    }

    #[test]
    fn phase43_gate_rejects_non_https_non_localhost_without_insecure() {
        let client = RegistryClient::new().with_base_url("https://lpm.dev");
        // HTTP (non-localhost) — scheme check fires first.
        let url = "http://evil.com/pkg/-/pkg-1.0.0.tgz";
        assert_eq!(
            evaluate_cached_url(url, &client),
            GateDecision::RejectedScheme
        );
    }

    #[test]
    fn phase43_gate_accepts_http_with_insecure() {
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
    fn phase43_gate_rejects_file_scheme_even_with_insecure() {
        // Finding 1 regression guard at the gate layer: `--insecure`
        // is HTTP-only by contract, never `file://`. A tampered
        // lockfile that stashed a `file:///etc/passwd` URL must be
        // rejected regardless of the flag state, before the bearer
        // token is attached.
        let client = RegistryClient::new()
            .with_base_url("https://lpm.dev")
            .with_insecure(true);
        assert_eq!(
            evaluate_cached_url("file:///etc/passwd", &client),
            GateDecision::RejectedScheme
        );
    }

    #[test]
    fn phase43_gate_rejects_wrong_suffix() {
        let client = RegistryClient::new().with_base_url("https://lpm.dev");
        // HTTPS + correct origin + `/-/` segment — but not `.tgz`.
        let url = "https://lpm.dev/api/registry/@scope/pkg/-/pkg-1.0.0.zip";
        assert_eq!(
            evaluate_cached_url(url, &client),
            GateDecision::RejectedShape
        );
    }

    #[test]
    fn phase43_gate_rejects_admin_style_path_without_dash_segment() {
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
    fn phase43_gate_rejects_origin_mismatch_after_registry_switch() {
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
    fn phase43_gate_allows_localhost_registry() {
        // Dev workflow — HTTP to localhost is explicitly permitted
        // (same carve-out `download_tarball_to_file` has pre-flight).
        let client = RegistryClient::new().with_base_url("http://localhost:3000");
        let url = "http://localhost:3000/api/registry/@scope/pkg/-/pkg-1.0.0.tgz";
        assert_eq!(evaluate_cached_url(url, &client), GateDecision::Accepted);
    }

    #[test]
    fn phase43_gate_rejects_malformed_url() {
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
            .with_npm_registry_url(npm_server.uri());
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
        let corrupted_data = b"not-valid-metadata";
        let corrupted_hmac = client.compute_cache_hmac(corrupted_data);
        let mut corrupted_content = Vec::new();
        corrupted_content.extend_from_slice(corrupted_hmac.as_bytes());
        corrupted_content.push(b'\n');
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
        let corrupted_data = b"not-valid-npm-metadata";
        let corrupted_hmac = client.compute_cache_hmac(corrupted_data);
        let mut corrupted_content = Vec::new();
        corrupted_content.extend_from_slice(corrupted_hmac.as_bytes());
        corrupted_content.push(b'\n');
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
            matches!(result, Err(LpmError::Registry(message)) if message.contains("failed to parse response"))
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
                if message.contains("failed to parse response from")
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
            Err(LpmError::Registry(message)) if message.contains("batch metadata parse error")
        ));
    }

    #[tokio::test]
    async fn constant_time_hmac_rejects_tampered_cache() {
        let (client, _tmp) = client_with_temp_cache();
        let meta = test_metadata("@lpm.dev/test.hmac-ct");

        client.write_metadata_cache("hmac-ct-key", &meta, Some("\"etag\""));

        // Tamper with the HMAC hex (first line of cache file)
        if let Some(path) = client.cache_path("hmac-ct-key") {
            let mut tampered = std::fs::read(&path).unwrap();
            // Flip a byte in the HMAC hex portion
            tampered[0] ^= 0x01;
            std::fs::write(&path, &tampered).unwrap();
        }

        let result = client.read_metadata_cache("hmac-ct-key");
        assert!(
            result.is_none(),
            "constant-time HMAC verification should reject tampered HMAC"
        );

        let content = client.read_cache_content("hmac-ct-key");
        assert!(
            content.is_none(),
            "constant-time HMAC in read_cache_content should also reject"
        );
    }

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

    // ─── Phase 35 Step 4: AuthPosture + recovery contract ─────────────

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
            "AnonymousPreferred must never attach a bearer (Phase 35 §3.2 / §9.2)"
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
        // None even if `with_token("")` was called. This is the
        // Phase 35 regression test for the `unwrap_or_default()`
        // empty-bearer defect at install.rs:1494/:1530 (Step 6).
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

    /// **Phase 35 Step 8 — wire-layer empty-bearer regression.**
    ///
    /// The plan §12.2 #5 mandates a regression that asserts no
    /// request ever sends `Authorization: Bearer ` (empty value)
    /// headers. Pre-Phase-35, `install.rs:1494/:1530` did
    /// `with_token(get_token().unwrap_or_default())`, which produced
    /// exactly that. This test pins the contract end-to-end —
    /// `with_token("")` followed by an actual HTTP request must NOT
    /// surface an Authorization header on the wire.
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

    // ─── Phase 42: streaming NDJSON body timeout ──────────────────────
    //
    // Pre-fix, `RegistryClient::new` configured `.timeout(30s)` on the
    // reqwest client — a wall-clock cap covering the entire request +
    // response cycle, including body read. On the decision-gate fixture
    // (54 direct deps, ~66 MB deep NDJSON response) the server
    // legitimately takes 30+ seconds to stream the body, so the timer
    // fired mid-body at ~51 MB / 7 500 chunks and every cold install
    // logged `WARN batch prefetch failed, falling back to sequential
    // resolution (slower): registry error: NDJSON read error ...
    // error decoding response body <- request or response body error
    // <- operation timed out`, forcing the install pipeline to drop
    // the Phase 38 streaming-speculation path on every fixture above
    // ~40 roots.
    //
    // The fix replaces `.timeout()` with `.connect_timeout() +
    // .read_timeout()`. `read_timeout` is a per-read idle timer that
    // resets on each successful chunk, so a slow-but-progressing stream
    // completes cleanly; a genuinely stalled server still gets
    // interrupted.
    //
    // This regression test drives a 3-second slow streaming mock
    // server through a client configured with a 500 ms read_timeout +
    // 500 ms connect_timeout. Each chunk arrives within ~300 ms so
    // the read_timeout never fires; the aggregate response time
    // exceeds both timeouts by 6×. Pre-fix (with `.timeout(500ms)`),
    // this test would hang for 500 ms and abort with a reqwest
    // timeout error. Post-fix it succeeds because the wall-clock cap
    // is gone.

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
        let http = RegistryClient::build_http_client(short, short);

        // Stream 4 NDJSON lines at 200 ms apart → 800 ms wall-clock
        // total. That's ~1.6× the 500 ms window a wall-clock
        // `.timeout()` would have enforced. With the Phase-42
        // `read_timeout`, the per-chunk window resets on each chunk
        // so the full body arrives intact. Kept short so the test
        // itself stays under 1 s.
        let packages: Vec<String> = (0..4).map(|i| format!("slow-pkg-{i}")).collect();
        let (base_url, server_handle) =
            slow_streaming_ndjson_server(packages.clone(), std::time::Duration::from_millis(200))
                .await;

        let mut client = RegistryClient::new().with_base_url(&base_url);
        client.http = http;
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
        // This is the bug's regression fixture written in reverse: same
        // slow streaming server the happy-path test uses, but the client
        // is built with the PRE-Phase-42 configuration (`.timeout()` —
        // a wall-clock cap). The stream takes ~3 s total, the wall-clock
        // is 500 ms, so the request dies mid-body with a reqwest body
        // decode error sourced from `operation timed out`. This test
        // does NOT call `RegistryClient::build_http_client` — it
        // deliberately invokes the reqwest builder directly with the
        // old API shape so the wire-level failure mode stays visible
        // as a regression guard: if someone re-introduces
        // `.timeout(N)` on the prod builder, this test is the spec
        // that says "that path fails for legitimately slow streams."
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
        client.http = old_style_http;
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
                "pre-Phase-42 wall-clock timeout should abort mid-body; \
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

    // ─── Phase 49 — direct-tier fetch + parallel fan-out ─────────────────

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
        // Regression test for the Phase 49 halve-on-429 ratchet bug
        // flagged by review: if the implementation only forgets permits
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

    /// Phase 49 — pins the public `with_cache_dir(Some(path))` path.
    /// Reviewer's residual note on `a6d2493`: the key re-derivation
    /// fix restored the `cache_dir` ↔ `cache_signing_key` coupling,
    /// but `with_cache_dir(Some(...))` itself had no focused test.
    /// This test writes a metadata entry with a tmp-dir-backed client,
    /// then spins up a DIFFERENT client pointed at the same tmp dir
    /// and reads the entry back. If the HMAC signing key is NOT
    /// derived from the directory (the bug this public API almost
    /// shipped), the second read fails verification and returns
    /// `None`. Passing requires: both clients re-derive the same key
    /// from the sidecar file in `tmp`.
    #[tokio::test]
    async fn with_cache_dir_some_path_roundtrips_across_clients() {
        let tmp = tempfile::tempdir().expect("tmp");
        let cache_path = tmp.path().to_path_buf();

        // Build client A pointed at tmp. Cache some synthetic metadata.
        let client_a = RegistryClient::new().with_cache_dir(Some(cache_path.clone()));
        let pkg_name = "with-cache-dir-roundtrip";
        let metadata: PackageMetadata =
            serde_json::from_str(&test_metadata_json(pkg_name)).expect("parse test metadata");
        client_a.write_metadata_cache(&format!("npm:{pkg_name}"), &metadata, None);

        // The signing-key sidecar MUST be in the tmp dir (not in the
        // default `~/.lpm/cache/metadata/`).
        assert!(
            cache_path.join(CACHE_SIGNING_KEY_FILE).exists(),
            "with_cache_dir(Some(tmp)) must persist the signing key sidecar in tmp"
        );

        // Build a fresh client B pointed at the same tmp dir.
        // `load_or_create_cache_signing_key` MUST re-derive the same
        // key from the sidecar; otherwise HMAC verification fails
        // and `read_metadata_cache` returns None.
        let client_b = RegistryClient::new().with_cache_dir(Some(cache_path.clone()));
        let (cached, _etag) = client_b
            .read_metadata_cache(&format!("npm:{pkg_name}"))
            .expect("fresh client with same cache_dir must HMAC-verify the prior write");
        assert_eq!(
            cached.name, pkg_name,
            "round-tripped cache entry must preserve the package name"
        );
    }
}
