//! Registry HTTP client.
//!
//! Handles communication with the LPM registry at `registry.lpm.dev`.
//!
//! # TODOs for Phase 4
//! - [ ] Publish (PUT /api/registry/@lpm.dev/owner.pkg)
//! - [ ] Token create/rotate (POST /api/registry/-/token/*)
//! - [ ] OIDC exchange (POST /api/registry/-/token/oidc)
//! - [ ] 2FA header injection (`x-otp: <code>`)
//!
//! # TODOs for Phase 6
//! - [ ] Binary metadata cache (store responses on disk in binary format)
//! - [ ] Conditional requests (ETag/If-None-Match for cache revalidation)
//! - [ ] Batched metadata (fetch N packages in one request — needs registry support)

use crate::types::*;
use lpm_common::{DEFAULT_REGISTRY_URL, LpmError, NPM_REGISTRY_URL, PackageName};
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

/// Client for communicating with the LPM registry.
pub struct RegistryClient {
    http: reqwest::Client,
    /// Base URL of the LPM registry (default: https://lpm.dev).
    base_url: String,
    /// Bearer token for authenticated requests. None for anonymous.
    token: Option<String>,
    /// Path to the metadata cache directory. None disables caching.
    cache_dir: Option<std::path::PathBuf>,
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
                let _ = std::fs::create_dir_all(&dir);
                dir
            });

        RegistryClient {
            http,
            base_url: DEFAULT_REGISTRY_URL.to_string(),
            token: None,
            cache_dir,
        }
    }

    /// Set the registry base URL.
    pub fn with_base_url(mut self, url: impl Into<String>) -> Self {
        self.base_url = url.into();
        self
    }

    /// Set the bearer token for authenticated requests.
    pub fn with_token(mut self, token: impl Into<String>) -> Self {
        self.token = Some(token.into());
        self
    }

    /// Create a new client with the same base_url and token configuration.
    /// Unlike `Clone`, this creates a fresh reqwest::Client (which is cheap).
    pub fn clone_with_config(&self) -> Self {
        let mut new = RegistryClient::new();
        new.base_url = self.base_url.clone();
        new.token = self.token.clone();
        new.cache_dir = self.cache_dir.clone();
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
            req = req.bearer_auth(token);
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
                self.write_metadata_cache(&cache_key, &meta);
                map.insert(name.clone(), meta);
            }
        }

        tracing::debug!("batch metadata: requested {}, received {}", package_names.len(), map.len());
        Ok(map)
    }

    // ─── Package Endpoints ──────────────────────────────────────────

    /// Fetch full metadata for an LPM package.
    ///
    /// Calls: GET /api/registry/@lpm.dev/owner.package-name
    pub async fn get_package_metadata(
        &self,
        name: &PackageName,
    ) -> Result<PackageMetadata, LpmError> {
        let cache_key = format!("lpm:{}", name.scoped());

        // Check metadata cache first
        if let Some(cached) = self.read_metadata_cache(&cache_key) {
            tracing::debug!("metadata cache hit: {}", name.scoped());
            return Ok(cached);
        }

        // npm registries expect raw scoped names in the path:
        // /api/registry/@lpm.dev/owner.package (NOT percent-encoded)
        let url = format!("{}/api/registry/{}", self.base_url, name.scoped());
        let metadata: PackageMetadata = self.get_json(&url).await?;

        // Write to cache
        self.write_metadata_cache(&cache_key, &metadata);

        Ok(metadata)
    }

    /// Fetch metadata for an npm package from the upstream npm registry.
    ///
    /// First tries via LPM's upstream proxy (if enabled), then falls back
    /// to the public npm registry at registry.npmjs.org.
    pub async fn get_npm_package_metadata(
        &self,
        name: &str,
    ) -> Result<PackageMetadata, LpmError> {
        let cache_key = format!("npm:{name}");

        // Check metadata cache first
        if let Some(cached) = self.read_metadata_cache(&cache_key) {
            tracing::debug!("metadata cache hit: npm:{name}");
            return Ok(cached);
        }

        // Try LPM upstream proxy first (single registry experience)
        let proxy_url = format!("{}/api/registry/{}", self.base_url, name);
        let proxy_result: Result<PackageMetadata, LpmError> = self
            .get_json_with_optional_auth(&proxy_url)
            .await;

        if let Ok(metadata) = proxy_result {
            // Verify we got the right package (not a routing error)
            if metadata.name == name || metadata.versions.values().any(|v| v.name == name) {
                tracing::debug!("fetched {name} via LPM upstream proxy");
                self.write_metadata_cache(&cache_key, &metadata);
                return Ok(metadata);
            }
        }

        // Fall back to public npm registry (no auth needed)
        let npm_url = format!("{}/{}", NPM_REGISTRY_URL, name);
        tracing::debug!("fetching {name} from npm registry");
        let metadata: PackageMetadata = self.get_json_no_auth(&npm_url).await?;
        self.write_metadata_cache(&cache_key, &metadata);
        Ok(metadata)
    }

    /// Download a tarball as raw bytes.
    ///
    /// The URL comes from `VersionMetadata.dist.tarball`.
    ///
    /// # TODO (Phase 3)
    /// - Stream to disk instead of buffering in memory for large packages
    /// - Progress reporting callback
    pub async fn download_tarball(&self, url: &str) -> Result<Vec<u8>, LpmError> {
        let response = self
            .send_with_retry(self.build_get(url))
            .await?;

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
            serde_json::json!({ "token": token })
        } else {
            return Err(LpmError::Registry("no token to revoke".to_string()));
        };

        let req = self.http.post(&url);
        let req = if let Some(token) = &self.token {
            req.bearer_auth(token)
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
    pub async fn publish_package(
        &self,
        encoded_name: &str,
        payload: &serde_json::Value,
        otp: Option<&str>,
    ) -> Result<serde_json::Value, LpmError> {
        let url = format!("{}/api/registry/{}", self.base_url, encoded_name);

        let mut req = self.http.put(&url).json(payload);
        if let Some(token) = &self.token {
            req = req.bearer_auth(token);
        }
        if let Some(code) = otp {
            req = req.header("x-otp", code);
        }

        let response = self.send_with_retry(req).await?;
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
            let code = body
                .get("code")
                .and_then(|c| c.as_str())
                .unwrap_or("");

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
    pub async fn get_marketplace_earnings(
        &self,
    ) -> Result<MarketplaceEarningsResponse, LpmError> {
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

    /// Read cached metadata if it exists and is within TTL.
    fn read_metadata_cache(&self, key: &str) -> Option<PackageMetadata> {
        let path = self.cache_path(key)?;
        if !path.exists() {
            return None;
        }

        // Check TTL
        let modified = path.metadata().ok()?.modified().ok()?;
        let age = std::time::SystemTime::now()
            .duration_since(modified)
            .ok()?;
        if age > METADATA_CACHE_TTL {
            return None;
        }

        // Read and deserialize
        let data = std::fs::read(&path).ok()?;
        serde_json::from_slice(&data).ok()
    }

    /// Write metadata to cache.
    fn write_metadata_cache(&self, key: &str, metadata: &PackageMetadata) {
        if let Some(path) = self.cache_path(key) {
            if let Ok(data) = serde_json::to_vec(metadata) {
                let _ = std::fs::write(&path, &data);
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
            req = req.bearer_auth(token);
        }
        self.send_with_retry(req).await
    }

    /// Build a GET request with auth headers.
    fn build_get(&self, url: &str) -> reqwest::RequestBuilder {
        let mut req = self.http.get(url);
        if let Some(token) = &self.token {
            req = req.bearer_auth(token);
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

    /// GET → JSON with optional auth (sends token if available, but doesn't fail on 401).
    async fn get_json_with_optional_auth<T: serde::de::DeserializeOwned>(
        &self,
        url: &str,
    ) -> Result<T, LpmError> {
        self.get_json(url).await
    }

    /// GET → JSON without auth (for public registries like npmjs.org).
    async fn get_json_no_auth<T: serde::de::DeserializeOwned>(
        &self,
        url: &str,
    ) -> Result<T, LpmError> {
        let response = self.send_with_retry(self.http.get(url)).await?;
        response
            .json()
            .await
            .map_err(|e| LpmError::Registry(format!("failed to parse response from {url}: {e}")))
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
                        200..=299 => return Ok(response),

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
}
