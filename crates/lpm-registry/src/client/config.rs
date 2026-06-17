use super::*;

#[derive(Clone, Copy, Eq, PartialEq)]
enum HttpTransportMode {
    Default,
    WorkerMetadataHttp3,
}

impl RegistryClient {
    pub(super) fn worker_metadata_http3_enabled_from_env() -> bool {
        Self::worker_metadata_http3_enabled_for_lpm_http(std::env::var("LPM_HTTP").ok().as_deref())
    }

    pub(super) fn worker_metadata_http3_enabled_for_lpm_http(mode: Option<&str>) -> bool {
        if !cfg!(feature = "experimental-http3") {
            return false;
        }
        !matches!(
            mode.filter(|value| !value.is_empty()),
            Some("default" | "h2-worker" | "h1-pool")
        )
    }

    /// Compute the ASCII-serialized origin of a URL string.
    /// Returns an empty string for malformed or opaque URLs so the
    /// precomputed fields are always valid (but will never match).
    pub(super) fn url_origin(url: &str) -> String {
        reqwest::Url::parse(url)
            .map(|u| u.origin().ascii_serialization())
            .unwrap_or_default()
    }

    #[cfg(test)]
    pub(super) fn deserialize_cached_metadata(data: &[u8]) -> Option<PackageMetadata> {
        Self::deserialize_cached_metadata_as(data)
    }

    pub(super) fn deserialize_cached_metadata_as<T: serde::de::DeserializeOwned>(
        data: &[u8],
    ) -> Option<T> {
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
    pub(super) fn build_http_client(
        connect_timeout: Duration,
        read_timeout: Duration,
    ) -> reqwest::Client {
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
    pub(super) fn build_http_client_with_tls(
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
    pub(super) fn build_http_client_with_tls_and_identity(
        connect_timeout: Duration,
        read_timeout: Duration,
        tls: &TlsOverrides,
        identity: Option<reqwest::Identity>,
    ) -> Result<reqwest::Client, LpmError> {
        Self::build_http_client_with_tls_identity_and_transport(
            connect_timeout,
            read_timeout,
            tls,
            identity,
            HttpTransportMode::Default,
        )
    }

    fn build_http_client_with_tls_identity_and_transport(
        connect_timeout: Duration,
        read_timeout: Duration,
        tls: &TlsOverrides,
        identity: Option<reqwest::Identity>,
        transport: HttpTransportMode,
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
        if transport == HttpTransportMode::WorkerMetadataHttp3 {
            b = Self::apply_http3_prior_knowledge(b);
        } else if std::env::var("LPM_HTTP").as_deref() == Ok("h1-pool") {
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
        b.build().map_err(|e| {
            let chain: Vec<String> =
                std::iter::successors(Some(&e as &dyn std::error::Error), |err| err.source())
                    .map(|err| err.to_string())
                    .collect();
            LpmError::Cert(format!("HTTP client build failed: {}", chain.join(" <- ")))
        })
    }

    #[cfg(feature = "experimental-http3")]
    fn apply_http3_prior_knowledge(b: reqwest::ClientBuilder) -> reqwest::ClientBuilder {
        b.http3_prior_knowledge()
    }

    #[cfg(not(feature = "experimental-http3"))]
    fn apply_http3_prior_knowledge(b: reqwest::ClientBuilder) -> reqwest::ClientBuilder {
        b
    }

    #[cfg(feature = "experimental-http3")]
    pub(super) fn build_worker_metadata_http3_client_with_tls(
        tls: &TlsOverrides,
    ) -> Result<reqwest::Client, LpmError> {
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
        Self::build_http_client_with_tls_identity_and_transport(
            CONNECT_TIMEOUT,
            READ_TIMEOUT,
            tls,
            global_identity,
            HttpTransportMode::WorkerMetadataHttp3,
        )
    }

    /// Create a new registry client with default settings.
    pub fn new() -> Self {
        // reqwest honours HTTPS_PROXY / HTTP_PROXY / ALL_PROXY by
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
            registry_signing_keys_cache: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            base_url_origin: Self::url_origin(DEFAULT_REGISTRY_URL),
            npm_registry_url_origin: Self::url_origin(NPM_REGISTRY_URL),
            worker_metadata_http3_enabled: Self::worker_metadata_http3_enabled_from_env(),
            worker_metadata_http3_client: Arc::new(tokio::sync::Mutex::new(None)),
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
        let default_identity = global_loaded.as_ref().map(|l| l.identity.clone());
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
        self.worker_metadata_http3_client = Arc::new(tokio::sync::Mutex::new(None));
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
        // When `--insecure` is the path that admitted an HTTP
        // non-loopback URL, surface the DNS-rebinding window
        // explicitly. The string-based scheme check happens here; the
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
    pub(super) fn check_tarball_url_scheme(&self, url: &str) -> Result<(), LpmError> {
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
            registry_signing_keys_cache: Arc::clone(&self.registry_signing_keys_cache),
            base_url_origin: self.base_url_origin.clone(),
            npm_registry_url_origin: self.npm_registry_url_origin.clone(),
            worker_metadata_http3_enabled: self.worker_metadata_http3_enabled,
            worker_metadata_http3_client: Arc::clone(&self.worker_metadata_http3_client),
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

    #[cfg(test)]
    pub(crate) fn with_worker_metadata_http3_enabled(mut self, enabled: bool) -> Self {
        self.worker_metadata_http3_enabled = enabled;
        self.worker_metadata_http3_client = Arc::new(tokio::sync::Mutex::new(None));
        self
    }
}

impl Default for RegistryClient {
    fn default() -> Self {
        Self::new()
    }
}
