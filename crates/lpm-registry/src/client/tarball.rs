use super::*;

/// Maximum compressed tarball size (500 MB). Enforced during download to prevent
/// malicious registries from exhausting memory or disk before extraction even starts.
/// Extraction-time limits (5 GB total, 500 MB per file) remain as a second defense.
pub const MAX_COMPRESSED_TARBALL_SIZE: u64 = 500 * 1024 * 1024;

impl RegistryClient {
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

    pub(super) async fn download_tarball_to_file_with_auth_and_limit(
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

    /// File-spool tarball download with route-appropriate auth.
    ///
    /// Custom-route destinations attach their `.npmrc` credential when
    /// one matches the tarball origin. `@lpm.dev/*` packages keep the
    /// LPM session bearer. Public npm tarballs, including npm packages
    /// whose metadata came through the Worker proxy, go anonymous so the
    /// LPM session bearer is not sent cross-origin.
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
        match route_table.route_for_package(name) {
            crate::route::UpstreamRoute::Custom { .. } => {
                let auth = route_table.auth_for_url(url);
                self.download_tarball_to_file_with_auth(url, auth).await
            }
            crate::route::UpstreamRoute::LpmWorker if name.starts_with("@lpm.dev/") => {
                self.download_tarball_to_file(url).await
            }
            crate::route::UpstreamRoute::LpmWorker | crate::route::UpstreamRoute::NpmDirect => {
                self.download_tarball_to_file_with_auth(url, None).await
            }
        }
    }

    pub(super) fn ensure_configured_tarball_origin(&self, url: &str) -> Result<(), LpmError> {
        if self.is_configured_origin(url) {
            Ok(())
        } else {
            Err(LpmError::Registry(format!(
                "tarball URL refused — fresh dist.tarball origin is not in the configured \
                 set (likely poisoned mirror or metadata tamper): {url}"
            )))
        }
    }

    /// Streaming variant of [`Self::download_tarball_routed`].
    ///
    /// For the non-Custom path, the fresh `dist.tarball` URL's origin
    /// is verified against `is_configured_origin` before the body is
    /// read. The shape check (`/-/` + `.tgz`) that
    /// `evaluate_cached_url` applies to lockfile-cached URLs is
    /// intentionally not applied here: a fresh packument from the
    /// configured registry is allowed to use any path shape the
    /// registry serves. The origin check alone prevents a compromised
    /// mirror from redirecting the tarball to an unrelated host.
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
        match route_table.route_for_package(name) {
            crate::route::UpstreamRoute::Custom { .. } => {
                let auth = route_table.auth_for_url(url);
                self.download_tarball_streaming_with_auth(url, auth).await
            }
            crate::route::UpstreamRoute::LpmWorker if name.starts_with("@lpm.dev/") => {
                self.ensure_configured_tarball_origin(url)?;
                self.download_tarball_streaming(url).await
            }
            crate::route::UpstreamRoute::LpmWorker | crate::route::UpstreamRoute::NpmDirect => {
                self.ensure_configured_tarball_origin(url)?;
                self.download_tarball_streaming_with_auth(url, None).await
            }
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
    ///   bytes are compared. `sha1-…`, `sha256-…`, and `sha512-…` work natively.
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
            HashAlgorithm::Sha1 => Integrity::from_bytes(HashAlgorithm::Sha1, &data),
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
}

pub(super) fn write_tarball_chunk(
    writer: &mut impl std::io::Write,
    chunk: &[u8],
) -> Result<(), LpmError> {
    writer.write_all(chunk).map_err(|e| {
        LpmError::Io(std::io::Error::new(
            e.kind(),
            format!("failed to write tarball chunk to temp file: {e}"),
        ))
    })
}

pub(super) fn flush_tarball_file(writer: &mut impl std::io::Write) -> Result<(), LpmError> {
    writer.flush().map_err(|e| {
        LpmError::Io(std::io::Error::new(
            e.kind(),
            format!("failed to flush tarball temp file: {e}"),
        ))
    })
}
