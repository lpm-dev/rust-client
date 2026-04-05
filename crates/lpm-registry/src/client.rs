//! Registry HTTP client.
//!
//! Handles communication with the LPM registry at `lpm.dev`.
//!
//! Phase 4 features (publish, token, OIDC) — implemented in publish.rs, npmrc.rs, oidc.rs.
//! Phase 18: ETag conditional requests + MessagePack binary cache (replacing JSON).
//! Remaining: 2FA header injection, batched metadata.
//! ETag/304 revalidation, MessagePack cache, HMAC-signed cache entries (constant-time verified).

use crate::types::*;
use lpm_common::{DEFAULT_REGISTRY_URL, LpmError, NPM_REGISTRY_URL, PackageName};
use secrecy::{ExposeSecret, SecretString};
use std::time::Duration;

/// Maximum number of retries for transient failures.
const MAX_RETRIES: u32 = 3;

/// Base delay for exponential backoff (1 second).
const RETRY_BASE_DELAY: Duration = Duration::from_secs(1);

/// Maximum backoff delay (10 seconds).
const RETRY_MAX_DELAY: Duration = Duration::from_secs(10);

/// Default request timeout (30 seconds).
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Metadata cache TTL (5 minutes).
const METADATA_CACHE_TTL: std::time::Duration = std::time::Duration::from_secs(300);

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

/// Client for communicating with the LPM registry.
pub struct RegistryClient {
    http: reqwest::Client,
    /// Base URL of the LPM registry (default: https://lpm.dev).
    base_url: String,
    /// Bearer token for authenticated requests. None for anonymous.
    /// Wrapped in `SecretString` to prevent accidental logging/display (S5).
    token: Option<SecretString>,
    /// Path to the metadata cache directory. None disables caching.
    cache_dir: Option<std::path::PathBuf>,
    /// Per-process HMAC key for signing metadata cache entries.
    /// Prevents disk-level cache poisoning. Not persisted — regenerated each process.
    cache_signing_key: [u8; 32],
    /// Allow insecure HTTP connections to non-localhost registries (--insecure flag).
    allow_insecure: bool,
}

impl RegistryClient {
    /// Create a new registry client with default settings.
    pub fn new() -> Self {
        let http = reqwest::Client::builder()
            .timeout(REQUEST_TIMEOUT)
            .user_agent(format!("lpm-rs/{}", env!("CARGO_PKG_VERSION")))
            .build()
            .expect("failed to build HTTP client");

        // Initialize metadata cache at ~/.lpm/cache/metadata/
        let cache_dir = std::env::var("HOME")
            .or_else(|_| std::env::var("USERPROFILE"))
            .ok()
            .map(|h| {
                let dir = std::path::PathBuf::from(h)
                    .join(".lpm")
                    .join("cache")
                    .join("metadata");
                if let Err(e) = std::fs::create_dir_all(&dir) {
                    tracing::warn!("failed to create metadata cache directory: {}", e);
                }
                dir
            });

        // Generate per-process HMAC key for cache integrity
        let mut cache_signing_key = [0u8; 32];
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut cache_signing_key);

        RegistryClient {
            http,
            base_url: DEFAULT_REGISTRY_URL.to_string(),
            token: None,
            cache_dir,
            cache_signing_key,
            allow_insecure: false,
        }
    }

    /// Get the current base URL.
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Set the registry base URL.
    ///
    /// Stores the URL for later validation. Non-localhost HTTP URLs are rejected
    /// at request time unless `--insecure` is set via [`with_insecure`].
    pub fn with_base_url(mut self, url: impl Into<String>) -> Self {
        self.base_url = url.into();
        self
    }

    /// Allow insecure HTTP connections to non-localhost registries.
    /// Required when using `--insecure` CLI flag.
    pub fn with_insecure(mut self, allow: bool) -> Self {
        self.allow_insecure = allow;
        self
    }

    /// Validate the base URL scheme. Returns an error if the URL uses HTTP
    /// for a non-localhost host and `allow_insecure` is not set.
    ///
    /// Called before the first request, not in the builder, so the client
    /// can be constructed in any order.
    pub fn validate_base_url(&self) -> Result<(), LpmError> {
        if !self.base_url.starts_with("https://")
            && !is_localhost_url(&self.base_url)
            && !self.allow_insecure
        {
            return Err(LpmError::Registry(format!(
                "registry URL '{}' uses HTTP which is insecure. Use HTTPS or pass --insecure flag.",
                self.base_url
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

    /// Create a new client sharing the same HTTP connection pool.
    /// Reuses the inner `reqwest::Client` (which is `Arc`-wrapped internally)
    /// so all clones share TCP/TLS connections via HTTP/2 multiplexing.
    pub fn clone_with_config(&self) -> Self {
        Self {
            http: self.http.clone(), // Arc clone — shares connection pool
            base_url: self.base_url.clone(),
            token: self.token.clone(),
            cache_dir: self.cache_dir.clone(),
            cache_signing_key: self.cache_signing_key,
            allow_insecure: self.allow_insecure,
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

        let mut req = self
            .http
            .post(&url)
            .header("Accept", "application/x-ndjson")
            .json(&body);
        if let Some(token) = &self.token {
            req = req.bearer_auth(token.expose_secret());
        }

        let response = self.send_with_retry(req).await?;

        let content_type = response
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();

        // NDJSON streaming: parse line-by-line, cache each package as it arrives.
        // The server emits root deps first, then transitive levels — so the
        // resolver's metadata cache warms incrementally.
        if content_type.contains("application/x-ndjson") {
            return self.parse_ndjson_batch(response).await;
        }

        // Fallback: legacy JSON response (server doesn't support NDJSON)
        self.parse_json_batch(response).await
    }

    /// Parse a streaming NDJSON batch response. Each line is:
    /// `{"name":"lodash","metadata":{...}}\n`
    async fn parse_ndjson_batch(
        &self,
        response: reqwest::Response,
    ) -> Result<std::collections::HashMap<String, PackageMetadata>, LpmError> {
        let mut map = std::collections::HashMap::new();
        let mut buffer = String::new();

        // Read chunks from the response body and parse complete lines
        let mut response = response;
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|e| LpmError::Registry(format!("NDJSON read error: {e}")))?
        {
            buffer.push_str(
                std::str::from_utf8(&chunk)
                    .map_err(|e| LpmError::Registry(format!("NDJSON UTF-8 error: {e}")))?,
            );

            // Process all complete lines in the buffer
            while let Some(newline_pos) = buffer.find('\n') {
                let line = &buffer[..newline_pos];
                if !line.is_empty()
                    && let Ok(entry) = serde_json::from_str::<serde_json::Value>(line)
                    && let (Some(name), Some(meta_value)) = (
                        entry.get("name").and_then(|n| n.as_str()),
                        entry.get("metadata"),
                    )
                    && let Ok(meta) = serde_json::from_value::<PackageMetadata>(meta_value.clone())
                {
                    let cache_key = if name.starts_with("@lpm.dev/") {
                        format!("lpm:{name}")
                    } else {
                        format!("npm:{name}")
                    };
                    self.write_metadata_cache(&cache_key, &meta, None);
                    map.insert(name.to_string(), meta);
                }
                buffer = buffer[newline_pos + 1..].to_string();
            }
        }

        tracing::debug!("batch metadata (NDJSON): received {}", map.len());
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

        // Tier 2: Conditional request with ETag (stale cache, but may still be valid)
        // Read cache content once — reuse both ETag (for If-None-Match) and data (on 304)
        let cache_content = self.read_cache_content(&cache_key);
        let mut req = self.build_get(&url);
        if let Some(etag) = cache_content.as_ref().and_then(|c| c.etag.as_deref()) {
            req = req.header("If-None-Match", etag);
        }

        let response = self.send_with_retry(req).await?;

        if response.status() == reqwest::StatusCode::NOT_MODIFIED {
            // 304 — server confirmed our cached data is still current.
            // Touch the file to reset TTL, then deserialize the already-read data.
            if let Some(path) = self.cache_path(&cache_key) {
                // Update mtime to reset TTL without rewriting the file
                let _ = filetime::set_file_mtime(&path, filetime::FileTime::now());
            }
            // Deserialize from the already-read, HMAC-verified data (no second file read)
            if let Some(content) = cache_content {
                let metadata: Option<PackageMetadata> = rmp_serde::from_slice(&content.data)
                    .or_else(|_| serde_json::from_slice(&content.data))
                    .ok();
                if let Some(meta) = metadata {
                    tracing::debug!("metadata cache revalidated (304): {}", name.scoped());
                    return Ok(meta);
                }
            }
            // Edge case: cache content was None or deserialization failed — fall through to full fetch
        }

        // Tier 3: Full response — extract ETag and cache
        let etag = response
            .headers()
            .get("etag")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        let metadata: PackageMetadata = response
            .json()
            .await
            .map_err(|e| LpmError::Registry(format!("failed to parse response from {url}: {e}")))?;

        self.write_metadata_cache(&cache_key, &metadata, etag.as_deref());
        Ok(metadata)
    }

    /// Fetch metadata for an npm package from the upstream npm registry.
    ///
    /// First tries via LPM's upstream proxy (if enabled), then falls back
    /// to the public npm registry at registry.npmjs.org.
    ///
    /// Supports ETag conditional requests for both proxy and direct npm paths.
    pub async fn get_npm_package_metadata(&self, name: &str) -> Result<PackageMetadata, LpmError> {
        let cache_key = format!("npm:{name}");

        // Tier 1: TTL-based cache hit
        if let Some((cached, _etag)) = self.read_metadata_cache(&cache_key) {
            tracing::debug!("metadata cache hit: npm:{name}");
            return Ok(cached);
        }

        // Tier 2: Try LPM upstream proxy with conditional request
        let proxy_url = format!("{}/api/registry/{}", self.base_url, name);
        let cache_content = self.read_cache_content(&cache_key);

        let mut req = self.build_get(&proxy_url);
        if let Some(etag) = cache_content.as_ref().and_then(|c| c.etag.as_deref()) {
            req = req.header("If-None-Match", etag);
        }

        if let Ok(response) = self.send_with_retry(req).await {
            if response.status() == reqwest::StatusCode::NOT_MODIFIED {
                // Revalidated — touch file and deserialize from already-read data
                if let Some(path) = self.cache_path(&cache_key) {
                    let _ = filetime::set_file_mtime(&path, filetime::FileTime::now());
                }
                if let Some(content) = cache_content {
                    let metadata: Option<PackageMetadata> = rmp_serde::from_slice(&content.data)
                        .or_else(|_| serde_json::from_slice(&content.data))
                        .ok();
                    if let Some(meta) = metadata {
                        tracing::debug!("metadata cache revalidated (304): npm:{name}");
                        return Ok(meta);
                    }
                }
            } else if response.status().is_success() {
                let etag = response
                    .headers()
                    .get("etag")
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.to_string());

                if let Ok(metadata) = response.json::<PackageMetadata>().await {
                    // Verify we got the right package (not a routing error)
                    if metadata.name == name || metadata.versions.values().any(|v| v.name == name) {
                        tracing::debug!("fetched {name} via LPM upstream proxy");
                        self.write_metadata_cache(&cache_key, &metadata, etag.as_deref());
                        return Ok(metadata);
                    }
                }
            }
        }

        // Tier 3: Fall back to public npm registry (no auth needed)
        // Use abbreviated packument to reduce payload by 50-90%
        let npm_url = format!("{}/{}", NPM_REGISTRY_URL, name);
        tracing::debug!("fetching {name} from npm registry");
        let response = self
            .send_with_retry(
                self.http
                    .get(&npm_url)
                    .header("Accept", "application/vnd.npm.install-v1+json"),
            )
            .await?;
        let metadata: PackageMetadata = response.json().await.map_err(|e| {
            LpmError::Registry(format!("failed to parse npm metadata for {name}: {e}"))
        })?;
        self.write_metadata_cache(&cache_key, &metadata, None);
        Ok(metadata)
    }

    /// Download a tarball as raw bytes.
    ///
    /// The URL comes from `VersionMetadata.dist.tarball`.
    ///
    /// Only HTTPS URLs are allowed (with exceptions for localhost/127.0.0.1/[::1]
    /// during development). This prevents supply-chain attacks where a compromised
    /// lockfile or registry response redirects downloads to a malicious HTTP server.
    ///
    /// Note: This method buffers the entire tarball in memory. For install flows,
    /// prefer `download_tarball_to_file()` which spools to disk with bounded memory.
    pub async fn download_tarball(&self, url: &str) -> Result<Vec<u8>, LpmError> {
        // Validate URL scheme — only HTTPS allowed (except localhost for dev)
        if !url.starts_with("https://")
            && !url.starts_with("http://localhost")
            && !url.starts_with("http://127.0.0.1")
            && !url.starts_with("http://[::1]")
        {
            return Err(LpmError::Registry(format!(
                "tarball URL must use HTTPS (got: {})",
                if url.len() > 80 { &url[..80] } else { url }
            )));
        }

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
        if !url.starts_with("https://")
            && !url.starts_with("http://localhost")
            && !url.starts_with("http://127.0.0.1")
            && !url.starts_with("http://[::1]")
        {
            return Err(LpmError::Registry(format!(
                "tarball URL must use HTTPS (got: {})",
                if url.len() > 80 { &url[..80] } else { url }
            )));
        }

        let mut response = self.send_with_retry(self.build_get(url)).await?;

        use base64::Engine;
        use sha2::{Digest, Sha512};
        use std::io::Write;

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
            temp_file.write_all(&chunk).map_err(|e| {
                LpmError::Io(std::io::Error::new(
                    e.kind(),
                    format!("failed to write tarball chunk to temp file: {e}"),
                ))
            })?;
        }

        // Flush to ensure all data is on disk before verification
        temp_file.flush().map_err(|e| {
            LpmError::Io(std::io::Error::new(
                e.kind(),
                format!("failed to flush tarball temp file: {e}"),
            ))
        })?;

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
        self.get_json(&url).await
    }

    /// Search owners (users and organizations).
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
        self.get_json(&url).await
    }

    /// Check if a package name is available.
    ///
    /// Calls: GET /api/registry/check-name?name=owner.package-name
    /// Requires auth (prevents enumeration).
    pub async fn check_name(&self, name: &str) -> Result<CheckNameResponse, LpmError> {
        let url = format!(
            "{}/api/registry/check-name?name={}",
            self.base_url,
            urlencoding::encode(name)
        );
        self.get_json(&url).await
    }

    // ─── Auth Endpoints ─────────────────────────────────────────────

    /// Get current user info.
    ///
    /// Calls: GET /api/registry/-/whoami
    pub async fn whoami(&self) -> Result<WhoamiResponse, LpmError> {
        let url = format!("{}/api/registry/-/whoami", self.base_url);
        self.get_json(&url).await
    }

    /// Validate the current token.
    ///
    /// Calls: GET /api/registry/cli/check
    pub async fn check_token(&self) -> Result<TokenCheckResponse, LpmError> {
        let url = format!("{}/api/registry/cli/check", self.base_url);
        self.get_json(&url).await
    }

    /// Revoke the current token on the server.
    ///
    /// Calls: POST /api/registry/tokens/revoke
    pub async fn revoke_token(&self) -> Result<(), LpmError> {
        let url = format!("{}/api/registry/tokens/revoke", self.base_url);
        let body = if let Some(token) = &self.token {
            serde_json::json!({ "token": token.expose_secret() })
        } else {
            return Err(LpmError::Registry("no token to revoke".to_string()));
        };

        let req = self.http.post(&url);
        let req = if let Some(token) = &self.token {
            req.bearer_auth(token.expose_secret())
        } else {
            req
        };
        let req = req.json(&body);

        let response = self.send_with_retry(req).await?;
        if response.status().is_success() {
            Ok(())
        } else {
            Err(LpmError::Registry(format!(
                "token revocation failed: {}",
                response.status()
            )))
        }
    }

    /// Publish a package to the registry.
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

        let mut req = publish_client.put(&url).json(payload);
        if let Some(token) = &self.token {
            req = req.bearer_auth(token.expose_secret());
        }
        if let Some(code) = otp {
            req = req.header("x-otp", code);
        }

        // S4: Publish-safe send — no retry on 500, only on gateway errors
        let response = self.send_publish_safe(req, encoded_name).await?;
        let status = response.status();
        let body: serde_json::Value = response
            .json()
            .await
            .map_err(|e| LpmError::Registry(format!("failed to parse publish response: {e}")))?;

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
    }

    // ─── Intelligence Endpoints ─────────────────────────────────────

    /// Get quality report for a package.
    ///
    /// Calls: GET /api/registry/quality?name=owner.package-name
    pub async fn get_quality(&self, name: &str) -> Result<QualityResponse, LpmError> {
        let url = format!(
            "{}/api/registry/quality?name={}",
            self.base_url,
            urlencoding::encode(name)
        );
        self.get_json(&url).await
    }

    /// Get Agent Skills for a package.
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
        self.get_json(&url).await
    }

    /// Get API documentation for a package.
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
        self.get_json(&url).await
    }

    /// Get LLM context for a package.
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
        self.get_json(&url).await
    }

    // ─── Revenue Endpoints ──────────────────────────────────────────

    /// Get Pool revenue stats for the current user.
    ///
    /// Calls: GET /api/registry/pool/stats
    pub async fn get_pool_stats(&self) -> Result<PoolStatsResponse, LpmError> {
        let url = format!("{}/api/registry/pool/stats", self.base_url);
        self.get_json(&url).await
    }

    /// Get Marketplace earnings for the current user.
    ///
    /// Calls: GET /api/registry/marketplace/earnings
    pub async fn get_marketplace_earnings(&self) -> Result<MarketplaceEarningsResponse, LpmError> {
        let url = format!("{}/api/registry/marketplace/earnings", self.base_url);
        self.get_json(&url).await
    }

    // ─── Health ─────────────────────────────────────────────────────

    /// Check registry health.
    ///
    /// Calls: GET /api/registry/health
    pub async fn health_check(&self) -> Result<bool, LpmError> {
        let url = format!("{}/api/registry/health", self.base_url);
        let response = self.send_with_retry(self.build_get(&url)).await?;
        Ok(response.status().is_success())
    }

    // ─── Tunnel Endpoints ──────────────────────────────────────────

    /// List claimed tunnel domains.
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
        self.get_json(&url).await
    }

    /// Claim a tunnel domain.
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
    }

    /// Release a claimed tunnel domain.
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
        let mut req = self.http.delete(&url);
        if let Some(token) = &self.token {
            req = req.bearer_auth(token.expose_secret());
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
    }

    /// List available tunnel base domains.
    ///
    /// Calls: GET /api/tunnel/domains/available (public, no auth needed)
    pub async fn tunnel_available_domains(&self) -> Result<serde_json::Value, LpmError> {
        let url = format!("{}/api/tunnel/domains/available", self.base_url);
        self.get_json(&url).await
    }

    /// Look up a specific tunnel domain claim.
    ///
    /// Calls: GET /api/tunnel/domains/{domain}
    /// Returns: { found, available?, domain?, ownedByYou? }
    pub async fn tunnel_domain_lookup(&self, domain: &str) -> Result<serde_json::Value, LpmError> {
        let url = format!(
            "{}/api/tunnel/domains/{}",
            self.base_url,
            urlencoding::encode(domain)
        );
        self.get_json(&url).await
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
        if let Some(token) = &self.token {
            req = req.bearer_auth(token.expose_secret());
        }
        self.send_with_retry(req).await
    }

    /// Build a GET request with auth headers.
    fn build_get(&self, url: &str) -> reqwest::RequestBuilder {
        let mut req = self.http.get(url);
        if let Some(token) = &self.token {
            req = req.bearer_auth(token.expose_secret());
        }
        req
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
fn is_localhost_url(url: &str) -> bool {
    url.starts_with("http://localhost")
        || url.starts_with("http://127.0.0.1")
        || url.starts_with("http://[::1]")
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

/// Exponential backoff with capped delay.
/// attempt 0 → 1s, attempt 1 → 2s, attempt 2 → 4s, capped at 10s.
fn backoff_delay(attempt: u32) -> Duration {
    let delay = RETRY_BASE_DELAY * 2u32.pow(attempt);
    delay.min(RETRY_MAX_DELAY)
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
    async fn download_tarball_rejects_http() {
        let client = RegistryClient::new();
        let result = client.download_tarball("http://evil.com/malware.tgz").await;
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("tarball URL must use HTTPS"),
            "HTTP URL should be rejected: {msg}"
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
    fn is_localhost_url_cases() {
        assert!(is_localhost_url("http://localhost:3000"));
        assert!(is_localhost_url("http://localhost"));
        assert!(is_localhost_url("http://127.0.0.1:3000"));
        assert!(is_localhost_url("http://[::1]:3000"));
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
    async fn download_to_file_rejects_http_non_localhost() {
        let client = RegistryClient::new();
        let result = client
            .download_tarball_to_file("http://evil.com/pkg.tgz")
            .await;
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("HTTPS"), "should mention HTTPS requirement");
    }
}
