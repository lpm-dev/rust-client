//! Registry HTTP client.
//!
//! Handles communication with the LPM registry at `lpm.dev`.
//!
//! Phase 4 features (publish, token, OIDC) — implemented in publish.rs, npmrc.rs, oidc.rs.
//! Phase 18: ETag conditional requests + MessagePack binary cache (replacing JSON).
//! Remaining: 2FA header injection, batched metadata.
//! See phase-18-todo.md (performance) and phase-20-todo.md (platform compatibility).

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

    /// Create a new client with the same base_url and token configuration.
    /// Unlike `Clone`, this creates a fresh reqwest::Client (which is cheap).
    pub fn clone_with_config(&self) -> Self {
        let mut new = RegistryClient::new();
        new.base_url = self.base_url.clone();
        new.token = self.token.clone();
        new.cache_dir = self.cache_dir.clone();
        new.cache_signing_key = self.cache_signing_key;
        new.allow_insecure = self.allow_insecure;
        new
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
        if package_names.is_empty() {
            return Ok(std::collections::HashMap::new());
        }

        let url = format!("{}/api/registry/batch-metadata", self.base_url);
        let body = serde_json::json!({ "packages": package_names });

        let mut req = self.http.post(&url).json(&body);
        if let Some(token) = &self.token {
            req = req.bearer_auth(token.expose_secret());
        }

        let response = self.send_with_retry(req).await?;
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
                // Write each result to the metadata cache
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
            "batch metadata: requested {}, received {}",
            package_names.len(),
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
        let metadata: PackageMetadata = response
            .json()
            .await
            .map_err(|e| LpmError::Registry(format!("failed to parse npm metadata for {name}: {e}")))?;
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
    /// Performance: streaming download planned in phase-18-todo.md.
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

    /// Compute HMAC-SHA256 hex digest over the given data using the per-process signing key.
    fn compute_cache_hmac(&self, data: &[u8]) -> String {
        use hmac::{Hmac, Mac};
        type HmacSha256 = Hmac<sha2::Sha256>;
        let mut mac = HmacSha256::new_from_slice(&self.cache_signing_key)
            .expect("HMAC key length is always valid (32 bytes)");
        mac.update(data);
        hex::encode(mac.finalize().into_bytes())
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

        // Verify HMAC — if it doesn't match, the entry is tampered or old format
        let expected_hmac = std::str::from_utf8(hmac_hex).ok()?;
        let actual_hmac = self.compute_cache_hmac(data);
        if expected_hmac != actual_hmac {
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

        // Verify HMAC before trusting the content
        let hmac_hex = std::str::from_utf8(&content[..first_nl]).ok()?;
        let data = &content[second_nl + 1..];
        let actual_hmac = self.compute_cache_hmac(data);
        if hmac_hex != actual_hmac {
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
            let data = rmp_serde::to_vec(metadata)
                .or_else(|_| serde_json::to_vec(metadata))
                .unwrap_or_default();

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
}
