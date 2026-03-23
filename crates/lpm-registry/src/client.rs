//! Registry HTTP client.
//!
//! Handles communication with the LPM registry at `registry.lpm.dev`.
//!
//! # Current state (Phase 0)
//! Basic HTTP client that can fetch package metadata and check registry health.
//! Auth is bearer-token-only. No retry logic, no caching.
//!
//! # TODOs for Phase 1
//! - [ ] Retry with exponential backoff for transient failures (408, 429, 5xx)
//! - [ ] Parse `Retry-After` header on 429 responses
//! - [ ] Configurable request timeout (default: 30s)
//! - [ ] Connection keep-alive tuning
//! - [ ] Streaming tarball download (don't buffer in memory)
//! - [ ] All GET endpoints (search, whoami, quality, skills, etc.)
//! - [ ] Token validation endpoint (GET /api/registry/cli/check)
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

use crate::types::PackageMetadata;
use lpm_common::{DEFAULT_REGISTRY_URL, LpmError, PackageName};

/// Client for communicating with the LPM registry.
pub struct RegistryClient {
    http: reqwest::Client,
    /// Base URL of the LPM registry (default: https://lpm.dev).
    base_url: String,
    /// Bearer token for authenticated requests. None for anonymous.
    token: Option<String>,
}

impl RegistryClient {
    /// Create a new registry client with default settings.
    pub fn new() -> Self {
        RegistryClient {
            http: reqwest::Client::new(),
            base_url: DEFAULT_REGISTRY_URL.to_string(),
            token: None,
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

    /// Fetch full metadata for an LPM package.
    ///
    /// Calls: GET /api/registry/@lpm.dev/owner.package-name
    ///
    /// Returns npm-compatible package metadata with LPM extensions.
    pub async fn get_package_metadata(
        &self,
        name: &PackageName,
    ) -> Result<PackageMetadata, LpmError> {
        let url = format!(
            "{}/api/registry/{}",
            self.base_url,
            name.url_encoded()
        );

        let mut request = self.http.get(&url);

        if let Some(token) = &self.token {
            request = request.bearer_auth(token);
        }

        let response = request.send().await.map_err(|e| {
            LpmError::Network(format!("failed to fetch metadata for {name}: {e}"))
        })?;

        let status = response.status().as_u16();

        match status {
            200 => {}
            401 => return Err(LpmError::AuthRequired),
            403 => {
                return Err(LpmError::Forbidden(format!(
                    "no access to package {name}"
                )));
            }
            404 => return Err(LpmError::NotFound(format!("package {name} not found"))),
            429 => {
                // TODO (Phase 1): Parse Retry-After header
                return Err(LpmError::RateLimited {
                    retry_after_secs: 1,
                });
            }
            _ => {
                let body = response
                    .text()
                    .await
                    .unwrap_or_else(|_| "unable to read response body".into());
                return Err(LpmError::Http {
                    status,
                    message: body,
                });
            }
        }

        let metadata: PackageMetadata = response.json().await.map_err(|e| {
            LpmError::Registry(format!("failed to parse metadata for {name}: {e}"))
        })?;

        Ok(metadata)
    }

    /// Download a tarball as raw bytes.
    ///
    /// The URL comes from `VersionMetadata.dist.tarball`.
    ///
    /// # TODO (Phase 1)
    /// - Stream to disk instead of buffering in memory
    /// - Verify integrity hash during download
    /// - Progress reporting callback
    pub async fn download_tarball(&self, url: &str) -> Result<Vec<u8>, LpmError> {
        let mut request = self.http.get(url);

        if let Some(token) = &self.token {
            request = request.bearer_auth(token);
        }

        let response = request
            .send()
            .await
            .map_err(|e| LpmError::Network(format!("failed to download tarball: {e}")))?;

        let status = response.status().as_u16();
        if status != 200 {
            return Err(LpmError::Http {
                status,
                message: format!("tarball download failed: HTTP {status}"),
            });
        }

        let bytes = response
            .bytes()
            .await
            .map_err(|e| LpmError::Network(format!("failed to read tarball bytes: {e}")))?;

        Ok(bytes.to_vec())
    }

    /// Check registry health.
    ///
    /// Calls: GET /api/registry/health
    pub async fn health_check(&self) -> Result<bool, LpmError> {
        let url = format!("{}/api/registry/health", self.base_url);

        let response = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(|e| LpmError::Network(format!("health check failed: {e}")))?;

        Ok(response.status().is_success())
    }
}

impl Default for RegistryClient {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // These tests hit the real registry. They're integration tests that verify
    // our types match the actual API responses. Run with:
    //   cargo test --package lpm-registry -- --ignored
    //
    // They require network access and the registry to be up.

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
        // This test requires a valid token and a real package.
        // Set LPM_TOKEN env var before running.
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
    async fn nonexistent_package_returns_not_found() {
        let client = RegistryClient::new();
        let name =
            PackageName::parse("@lpm.dev/nonexistent-user.nonexistent-package-12345").unwrap();
        let result = client.get_package_metadata(&name).await;

        assert!(matches!(result, Err(LpmError::NotFound(_)) | Err(LpmError::AuthRequired)));
    }
}
