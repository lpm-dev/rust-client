use super::*;

#[derive(Clone, Copy, PartialEq, Eq)]
enum ClientPool {
    General,
    PolicyMetadata,
    ManualRedirect,
}

/// Maximum time to establish a TCP + TLS connection.
///
/// Kept conservative — connecting is trivially fast on healthy networks,
/// and anything that exceeds 10 s on connect is usually a DNS or route
/// problem better surfaced quickly than hidden under the body-read
/// window.
pub(super) const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

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
pub(super) const READ_TIMEOUT: Duration = Duration::from_secs(30);

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

    /// Test helper whose logical pools share the supplied client's
    /// underlying connection pool.
    #[cfg(test)]
    pub(super) fn from_default_client(default: reqwest::Client) -> Arc<Self> {
        let manual_redirect = lpm_http::client_builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("build redirect-disabled test client");
        Self::from_default_clients(default.clone(), default, manual_redirect)
    }

    /// Build an `HttpClients` with separate general and policy metadata
    /// connection pools and empty eager/lazy maps.
    pub(super) fn from_default_clients(
        default: reqwest::Client,
        policy_metadata: reqwest::Client,
        manual_redirect: reqwest::Client,
    ) -> Arc<Self> {
        Arc::new(Self {
            default: CachedClient {
                client: default,
                policy_metadata_client: policy_metadata,
                manual_redirect_client: manual_redirect,
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
        self.for_url_pool(url, ClientPool::General).await
    }

    /// Resolve the configuration-equivalent client from the dedicated
    /// policy metadata connection pool.
    pub async fn for_policy_metadata_url(&self, url: &str) -> Result<reqwest::Client, LpmError> {
        self.for_url_pool(url, ClientPool::PolicyMetadata).await
    }

    /// Resolve a redirect-disabled client for one explicit redirect hop.
    pub async fn for_manual_redirect_url(&self, url: &str) -> Result<reqwest::Client, LpmError> {
        self.for_url_pool(url, ClientPool::ManualRedirect).await
    }

    async fn for_url_pool(&self, url: &str, pool: ClientPool) -> Result<reqwest::Client, LpmError> {
        let select = |cached: &CachedClient| match pool {
            ClientPool::General => cached.client.clone(),
            ClientPool::PolicyMetadata => cached.policy_metadata_client.clone(),
            ClientPool::ManualRedirect => cached.manual_redirect_client.clone(),
        };
        let Some(origin) = OriginKey::from_request_url(url) else {
            return Ok(select(&self.default));
        };
        if let Some(c) = self.eager.get(&origin) {
            return Ok(select(c));
        }
        let any_port = OriginKey {
            host_lower: origin.host_lower.clone(),
            port: None,
        };
        if let Some(c) = self.eager.get(&any_port) {
            return Ok(select(c));
        }
        // Fast path: no per-origin TLS configured at all → the lazy map is
        // guaranteed empty and the build below would no-op to default. Skip
        // the tokio mutex entirely. This is the common case for installs
        // with no .npmrc per-origin TLS (default public-registry traffic),
        // where many concurrent metadata fetches would otherwise serialize
        // briefly on `lazy.lock().await`.
        if self.tls_overrides.per_origin.is_empty() {
            return Ok(select(&self.default));
        }
        let mut guard = self.lazy.lock().await;
        if let Some(c) = guard.get(&origin) {
            return Ok(select(c));
        }
        if let Some(c) = guard.get(&any_port) {
            return Ok(select(c));
        }
        // No client cached. Look up per-origin TLS for this origin.
        let per_origin_tls = self
            .tls_overrides
            .per_origin
            .get(&origin)
            .or_else(|| self.tls_overrides.per_origin.get(&any_port));
        let Some(per_origin_tls) = per_origin_tls else {
            // No per-origin TLS → use default client.
            return Ok(select(&self.default));
        };
        // Build under lock — single-flight per origin.
        let cached = build_per_origin_http_client(
            &self.tls_overrides,
            per_origin_tls,
            &origin,
            self.passphrase.as_ref(),
        )?;
        let out = select(&cached);
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
pub(super) fn build_per_origin_http_client(
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
        let bytes =
            lpm_common::read_file_capped(&resolved, lpm_common::TLS_MATERIAL_FILE_SIZE_CAP_BYTES)
                .map_err(|e| {
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
        identity.clone(),
    )?;
    let policy_metadata_client = RegistryClient::build_http_client_with_tls_and_identity(
        CONNECT_TIMEOUT,
        READ_TIMEOUT,
        &synthetic,
        identity.clone(),
    )?;
    let manual_redirect_client =
        RegistryClient::build_manual_redirect_http_client_with_tls_and_identity(
            CONNECT_TIMEOUT,
            READ_TIMEOUT,
            &synthetic,
            identity,
        )?;
    Ok(CachedClient {
        client,
        policy_metadata_client,
        manual_redirect_client,
        identity_fp,
    })
}

impl lpm_http::ReplayableHttpClientProvider for HttpClients {
    type Error = LpmError;

    fn client_for_url(
        &self,
        url: &reqwest::Url,
    ) -> impl std::future::Future<Output = Result<reqwest::Client, Self::Error>> + Send {
        self.for_manual_redirect_url(url.as_str())
    }
}

/// Inline PEM marker check — duplicates the parser-time helper in
/// `npmrc.rs` since that one is private. Kept private here too;
/// the duplication is one byte-search per per-origin cafile build,
/// which is negligible.
fn contains_pem_certificate_block_inline(bytes: &[u8]) -> bool {
    const MARKER: &[u8] = b"-----BEGIN CERTIFICATE-----";
    bytes.windows(MARKER.len()).any(|w| w == MARKER)
}
