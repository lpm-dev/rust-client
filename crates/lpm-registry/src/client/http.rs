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
            lazy: HashMap::new(),
            built_client_sets: std::sync::atomic::AtomicUsize::new(0),
            tls_overrides: Arc::new(TlsOverrides::default()),
            passphrase: Arc::new(EnvThenTtyPassphrase::new()),
            global_identity: None,
            tls_material_budget: Arc::new(TlsMaterialBudget::new(0).expect("zero TLS budget")),
            per_origin_identity_certs: HashMap::new(),
        })
    }

    /// Look up a cached client for `url` without lazy-building.
    /// Returns the eager-built per-origin entry if one exists, else
    /// the default. Sync, infallible — suitable for hot paths.
    fn cached_for_url_no_build(&self, url: &str) -> &CachedClient {
        let Some(origin) = OriginKey::from_request_url(url) else {
            return &self.default;
        };
        self.cached_for_origin_no_build(&origin)
    }

    fn cached_for_origin_no_build(&self, origin: &OriginKey) -> &CachedClient {
        if let Some(c) = self.eager.get(origin) {
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
        self.identity_fp_for_origin(&origin)
    }

    pub(super) fn identity_fp_for_destination(
        &self,
        destination: &RequestDestination,
    ) -> Option<&str> {
        self.identity_fp_for_origin(destination.origin())
    }

    fn identity_fp_for_origin(&self, origin: &OriginKey) -> Option<&str> {
        if let Some(c) = self.eager.get(origin) {
            return c.identity_fp.as_deref();
        }
        if let Some(material) = self.lazy_identity_material(origin) {
            return Some(match material {
                Ok(material) => material.fingerprint.as_ref(),
                Err(_) => "identity-unavailable",
            });
        }
        self.default.identity_fp.as_deref()
    }

    fn lazy_identity_material(
        &self,
        origin: &OriginKey,
    ) -> Option<Result<&LazyIdentityMaterial, &Arc<str>>> {
        let lazy = self.per_origin_identity_certs.get(origin)?;
        Some(
            lazy.material
                .get_or_init(|| {
                    let resolved = lazy.certfile.resolve();
                    let context = format!(
                        "{}:{}: failed to read per-origin certfile for {origin}",
                        lazy.certfile.source, lazy.certfile.line
                    );
                    let (bytes, _, reservation) = self
                        .tls_material_budget
                        .read_material(&resolved, &context)
                        .map_err(|error| Arc::from(error.to_string()))?;
                    let cert_pem = Arc::new(bytes);
                    let material = LazyIdentityMaterial {
                        fingerprint: cert_pem_fingerprint(cert_pem.as_ref()),
                        cert_pem,
                    };
                    reservation.commit();
                    Ok(material)
                })
                .as_ref(),
        )
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
    /// Single-flight is keyed by origin, so matching callers share one build
    /// while unrelated origins can build independently.
    pub async fn for_url(&self, url: &str) -> Result<reqwest::Client, LpmError> {
        self.for_url_pool(url, ClientPool::General).await
    }

    pub(super) async fn for_destination(
        &self,
        destination: &RequestDestination,
    ) -> Result<reqwest::Client, LpmError> {
        self.for_origin_pool(destination.origin(), ClientPool::General)
            .await
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
        let Some(origin) = OriginKey::from_request_url(url) else {
            return Ok(self.select_pool_client(&self.default, pool));
        };
        self.for_origin_pool(&origin, pool).await
    }

    fn select_pool_client(&self, cached: &CachedClient, pool: ClientPool) -> reqwest::Client {
        match pool {
            ClientPool::General => cached.client.clone(),
            ClientPool::PolicyMetadata => cached.policy_metadata_client.clone(),
            ClientPool::ManualRedirect => cached.manual_redirect_client.clone(),
        }
    }

    async fn for_origin_pool(
        &self,
        origin: &OriginKey,
        pool: ClientPool,
    ) -> Result<reqwest::Client, LpmError> {
        let select = |cached: &CachedClient| match pool {
            ClientPool::General => cached.client.clone(),
            ClientPool::PolicyMetadata => cached.policy_metadata_client.clone(),
            ClientPool::ManualRedirect => cached.manual_redirect_client.clone(),
        };
        if let Some(c) = self.eager.get(origin) {
            return Ok(select(c));
        }
        let Some(per_origin_tls) = self.tls_overrides.per_origin.get(origin) else {
            return Ok(select(&self.default));
        };
        let preloaded_cert_pem = match self.lazy_identity_material(origin) {
            Some(Ok(material)) => Some(Arc::clone(&material.cert_pem)),
            Some(Err(error)) => return Err(LpmError::Cert(error.to_string())),
            None => None,
        };
        let cell = self
            .lazy
            .get(origin)
            .expect("every non-eager TLS origin has a lazy cell");
        let cached = cell
            .get_or_init(|| {
                let global = Arc::clone(&self.tls_overrides);
                let per_origin_tls = per_origin_tls.clone();
                let origin = origin.clone();
                let passphrase = Arc::clone(&self.passphrase);
                let global_identity = self.global_identity.clone();
                let material_budget = Arc::clone(&self.tls_material_budget);
                async move {
                    use std::sync::atomic::Ordering;

                    if self
                        .built_client_sets
                        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |used| {
                            (used < MAX_NPMRC_TLS_CLIENT_SETS).then_some(used + 1)
                        })
                        .is_err()
                    {
                        return Err(Arc::from(format!(
                            "npmrc per-origin TLS client-set limit of {MAX_NPMRC_TLS_CLIENT_SETS} reached while building {origin}"
                        )));
                    }
                    let result = tokio::task::spawn_blocking(move || {
                        build_per_origin_http_client(
                            global.as_ref(),
                            &per_origin_tls,
                            &origin,
                            passphrase.as_ref(),
                            global_identity.as_deref(),
                            preloaded_cert_pem.as_ref(),
                            material_budget.as_ref(),
                        )
                    })
                    .await
                    .map_err(|error| LpmError::Cert(format!("per-origin TLS client build task failed: {error}")))
                    .and_then(|result| result);
                    if result.is_err() {
                        self.built_client_sets.fetch_sub(1, Ordering::AcqRel);
                    }
                    result.map_err(|error| Arc::from(error.to_string()))
                }
            })
            .await;
        match cached {
            Ok(cached) => Ok(select(cached)),
            Err(error) => Err(LpmError::Cert(error.to_string())),
        }
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
    global_identity: Option<&LoadedIdentity>,
    preloaded_cert_pem: Option<&Arc<Vec<u8>>>,
    material_budget: &TlsMaterialBudget,
) -> Result<CachedClient, LpmError> {
    // Compose extra roots: global + per-origin (additive).
    // Per-origin cafiles are deferred-read; do the IO here.
    let mut all_roots: Vec<TaggedRoot> = global.extra_roots.clone();
    let mut origin_root_bytes = 0_u64;
    let mut source_material_reservations = Vec::new();
    for cafile in &per_origin.cafiles {
        let resolved = cafile.resolve();
        let context = format!(
            "{}:{}: failed to read per-origin cafile for {origin}",
            cafile.source, cafile.line
        );
        let (bytes, _, reservation) = material_budget.read_material(&resolved, &context)?;
        origin_root_bytes = origin_root_bytes
            .checked_add(u64::try_from(bytes.len()).unwrap_or(u64::MAX))
            .ok_or_else(|| {
                LpmError::Cert(format!("per-origin TLS material overflow for {origin}"))
            })?;
        if !contains_pem_certificate_block_inline(&bytes) {
            return Err(LpmError::Cert(format!(
                "{}:{}: per-origin cafile for {origin} contains no '-----BEGIN CERTIFICATE-----' block",
                cafile.source, cafile.line,
            )));
        }
        all_roots.push(TaggedRoot {
            pem_bytes: Arc::new(bytes),
            source: cafile.source.clone(),
            line: cafile.line,
        });
        source_material_reservations.push(reservation);
    }

    // Resolve identity. Per-origin replaces global; per-origin
    // XOR validation fires here (only fatal when this origin is built).
    // The `LoadedIdentity` carries cert PEM bytes alongside the
    // `reqwest::Identity` so we can fingerprint without re-reading.
    let loaded: Option<crate::tls_identity::LoadedIdentity> = match (
        per_origin.certfile.as_ref(),
        per_origin.keyfile.as_ref(),
    ) {
        (Some(cert), Some(key)) => {
            let key_path = key.resolve();
            let key_context = format!(
                "{}:{}: failed to read keyfile {}",
                key.source,
                key.line,
                key_path.display()
            );
            let (key_bytes, key_metadata, key_reservation) =
                material_budget.read_material(&key_path, &key_context)?;
            source_material_reservations.push(key_reservation);

            let cert_pem = match preloaded_cert_pem {
                Some(cert_pem) => Arc::clone(cert_pem),
                None => {
                    let cert_path = cert.resolve();
                    let cert_context = format!(
                        "{}:{}: failed to read certfile {}",
                        cert.source,
                        cert.line,
                        cert_path.display()
                    );
                    let (cert_bytes, _, cert_reservation) =
                        material_budget.read_material(&cert_path, &cert_context)?;
                    source_material_reservations.push(cert_reservation);
                    Arc::new(cert_bytes)
                }
            };
            let identity_context = format!("per-origin TLS identity for {origin}");
            let (loaded, bundle_reservation) = load_identity_with_material_and_reservation(
                cert,
                cert_pem,
                key,
                key_bytes,
                key_metadata,
                passphrase,
                |bytes| material_budget.reserve_temporary(bytes, &identity_context),
            )?;
            source_material_reservations.push(bundle_reservation);
            Some(loaded)
        }
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
        (None, None) => global_identity.cloned(),
    };
    let per_origin_identity_bytes = per_origin
        .certfile
        .as_ref()
        .and_then(|_| loaded.as_ref().map(|identity| identity.material_bytes));

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
    let context = format!("per-origin TLS for {origin}");
    let reserved_bytes = material_budget.reserve_client_set(
        origin_root_bytes,
        per_origin_identity_bytes,
        &context,
    )?;
    let clients = RegistryClient::build_http_client_set_with_tls_and_identity(
        CONNECT_TIMEOUT,
        READ_TIMEOUT,
        &synthetic,
        identity,
    );
    let (client, policy_metadata_client, manual_redirect_client) = match clients {
        Ok(clients) => clients,
        Err(error) => {
            material_budget.release(reserved_bytes);
            return Err(error);
        }
    };
    drop(source_material_reservations);
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
