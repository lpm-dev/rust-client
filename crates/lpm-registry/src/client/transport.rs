use super::error_body::{AnswerFacts, RegistryOrigin, registry_refusal, unauthorized};
use super::*;
use lpm_common::RegistryKind;

mod error_redaction;
use error_redaction::{
    answer_facts, read_error_text_redacting, read_request_error_text, redact_credentials,
};

pub(super) enum PublishSafeResponse {
    Response(reqwest::Response),
    Recovered(serde_json::Value),
}

enum PublishReconciliation {
    Missing,
    Matched(serde_json::Value),
}

fn ambiguous_publish_reconciliation_error(error: LpmError) -> LpmError {
    LpmError::Registry(format!(
        "publish outcome is ambiguous and could not be reconciled: {error}. Inspect the registry before retrying"
    ))
}

/// Maximum number of retries for transient failures.
pub(super) const MAX_RETRIES: u32 = 3;

/// Base delay for exponential backoff (1 second).
pub(super) const RETRY_BASE_DELAY: Duration = Duration::from_secs(1);

/// Maximum backoff delay (10 seconds).
pub(super) const RETRY_MAX_DELAY: Duration = Duration::from_secs(10);

/// The longest rate-limit wait a request sits out, once. A registry that asks
/// for longer is told to the user with its wait instead of stalling them.
pub(super) const RATE_LIMIT_LONGEST_WAIT: Duration = Duration::from_secs(60);

const RETRY_ERROR_BODY_TIMEOUT: Duration = Duration::from_millis(500);

impl RegistryClient {
    // ─── Internal: HTTP transport with retry ────────────────────────

    /// POST JSON with auth, returning the raw response (for callers that need status/headers).
    pub async fn post_json_raw(
        &self,
        url: &str,
        body: &serde_json::Value,
    ) -> Result<reqwest::Response, LpmError> {
        let mut req = self.http.for_url(url).await?.post(url).json(body);
        if let Some(bearer) = self.current_bearer(AuthPosture::AuthRequired)? {
            req = req.bearer_auth(bearer);
        }
        self.send_with_retry(req).await
    }

    /// POST JSON with auth and, for a request that needs the account's
    /// second factor, its proof, refreshing once when a plain bearer
    /// rejection is safe to retry. Says the CLI can wait for a browser
    /// approval, which the registry then asks for as
    /// `LpmError::BrowserApprovalRequired` naming `operation`.
    ///
    /// Second-factor challenges remain command errors and never trigger a
    /// refresh. Returns the bearer from the successful attempt, including
    /// any automatic refresh.
    pub async fn post_json_with_second_factor_and_bearer(
        &self,
        url: &str,
        body: &serde_json::Value,
        proof: Option<SecondFactorProof<'_>>,
        command: &'static str,
        operation: &'static str,
    ) -> Result<(serde_json::Value, SecretString), LpmError> {
        self.execute_with_recovery(AuthPosture::AuthRequired, || async {
            let mut request = self
                .http
                .for_url(url)
                .await?
                .post(url)
                .json(body)
                .header(super::second_factor::BROWSER_APPROVAL_SUPPORT_HEADER, "1");
            let bearer = SecretString::from(
                self.current_bearer(AuthPosture::AuthRequired)?
                    .ok_or(LpmError::AuthRequired)?,
            );
            request = request.bearer_auth(bearer.expose_secret());
            if let Some(proof) = proof {
                let (header, value) = proof.header();
                request = request.header(header, value);
            }
            let request = build_request(request)?;
            let sent = request.headers().clone();
            let response = self.send_built_once_preserving_status(request).await?;
            let status = response.status();
            // A refusal keeps its status and code, and a proxy's HTML page
            // reads as what it is rather than as unparseable JSON.
            if !status.is_success() {
                let origin = self.registry_origin(response.url());
                let facts = answer_facts(response.headers(), &sent);
                let body = read_error_text_redacting(response, &sent).await;
                if status == reqwest::StatusCode::UNAUTHORIZED {
                    return Err(second_factor_or_unauthorized(
                        &facts, &body, &origin, command, operation,
                    ));
                }
                return Err(registry_refusal(status.as_u16(), &facts, &body, &origin));
            }
            let parsed = parse_capped_api_json::<serde_json::Value>(
                response,
                &format!("{operation} response"),
            )
            .await?;
            Ok((parsed, bearer))
        })
        .await
    }

    /// POST JSON once and preserve every HTTP status for the caller.
    ///
    /// Use this for idempotent, recoverable mutations whose caller must
    /// distinguish a bounded 4xx rejection from an ambiguous transport or
    /// server failure. Network failures are returned without an automatic
    /// retry so the caller's durable recovery record remains authoritative.
    pub async fn post_json_raw_status(
        &self,
        url: &str,
        body: &serde_json::Value,
    ) -> Result<reqwest::Response, LpmError> {
        let request = self.post_json_request(url, body).await?;
        self.send_built_once_preserving_status(request).await
    }

    /// A POST of `body` as JSON to `url`, with the bearer.
    async fn post_json_request(
        &self,
        url: &str,
        body: &serde_json::Value,
    ) -> Result<reqwest::Request, LpmError> {
        let mut request = self.http.for_url(url).await?.post(url).json(body);
        if let Some(bearer) = self.current_bearer(AuthPosture::AuthRequired)? {
            request = request.bearer_auth(bearer);
        }
        build_request(request)
    }

    pub(super) async fn send_once_preserving_status(
        &self,
        request: reqwest::RequestBuilder,
    ) -> Result<reqwest::Response, LpmError> {
        self.send_built_once_preserving_status(build_request(request)?)
            .await
    }

    pub(super) async fn send_built_once_preserving_status(
        &self,
        mut request: reqwest::Request,
    ) -> Result<reqwest::Response, LpmError> {
        self.validate_base_url()?;
        self.route_to_npm_transport(&mut request);
        self.http
            .for_url(request.url().as_str())
            .await?
            .execute(request)
            .await
            .map_err(|error| LpmError::Network(lpm_http::error_chain(&error)))
    }

    /// Issue one anonymous health request without install-grade retries.
    /// Diagnostic callers apply their own whole-operation deadline.
    pub async fn diagnostic_health_check_once(&self) -> Result<bool, LpmError> {
        let raw_url = format!("{}/api/registry/health", self.base_url);
        let mut parsed = reqwest::Url::parse(&raw_url)
            .map_err(|error| LpmError::Network(format!("invalid registry health URL: {error}")))?;
        parsed
            .set_username("")
            .map_err(|_| LpmError::Network("registry health URL cannot contain userinfo".into()))?;
        parsed
            .set_password(None)
            .map_err(|_| LpmError::Network("registry health URL cannot contain userinfo".into()))?;
        let url = parsed.to_string();
        let request = self
            .build_get_with_posture(&url, AuthPosture::AnonymousOnly)
            .await?;
        Ok(self
            .send_once_preserving_status(request)
            .await?
            .status()
            .is_success())
    }

    /// POST JSON once, refresh on a bearer 401, then retry the operation once.
    /// Every non-401 HTTP status remains available to the caller.
    pub async fn post_json_raw_status_with_recovery(
        &self,
        url: &str,
        body: &serde_json::Value,
    ) -> Result<reqwest::Response, LpmError> {
        self.execute_with_recovery(AuthPosture::AuthRequired, || async {
            let request = self.post_json_request(url, body).await?;
            let sent = request.headers().clone();
            let response = self.send_built_once_preserving_status(request).await?;
            if response.status() == reqwest::StatusCode::UNAUTHORIZED {
                let origin = self.registry_origin(response.url());
                let facts = answer_facts(response.headers(), &sent);
                let body = read_error_text_redacting(response, &sent).await;
                return Err(unauthorized(&facts, &body, &origin));
            }
            Ok(response)
        })
        .await
    }

    /// Build a GET request with auth headers (defaults to `AuthRequired`
    /// posture). Use `build_get_with_posture` for explicit control.
    ///
    /// Async + fallible because the underlying client dispatch may
    /// lazy-build a per-origin client (and that build can fail with a
    /// cited cert error).
    pub(super) async fn build_get(&self, url: &str) -> Result<reqwest::RequestBuilder, LpmError> {
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
    pub(super) async fn build_get_with_posture(
        &self,
        url: &str,
        posture: AuthPosture,
    ) -> Result<reqwest::RequestBuilder, LpmError> {
        let mut req = self.http.for_url(url).await?.get(url);
        if let Some(bearer) = self.current_bearer(posture)? {
            req = req.bearer_auth(bearer);
        }
        Ok(req)
    }

    /// Generic GET → deserialize JSON helper at a specified posture.
    /// Use for methods that should not attach the bearer
    /// (`AnonymousOnly` / `AnonymousPreferred`).
    pub(super) async fn get_json_anon<T: serde::de::DeserializeOwned>(
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
    pub(super) fn current_bearer(&self, posture: AuthPosture) -> Result<Option<String>, LpmError> {
        if !posture.attaches_bearer() {
            return Ok(None);
        }
        // Use the lazy variant so keychain classification fires on the
        // first actual network request, not at process startup. Warm /
        // offline / fully-cached runs skip the ~50 ms macOS Keychain IPC
        // entirely because this method is never reached.
        if let Some(session) = &self.session
            && let Some(b) = session.current_bearer_lazy()?
            && !b.is_empty()
        {
            return Ok(Some(b));
        }
        Ok(self
            .token
            .as_ref()
            .map(|s| s.expose_secret().to_string())
            .filter(|s| !s.is_empty()))
    }

    pub(super) async fn recover_package_read_session(
        &self,
        rejected_bearer: Option<&str>,
    ) -> Result<bool, LpmError> {
        let Some(session) = &self.session else {
            return Ok(false);
        };
        let mut attempted = self.package_read_recovery.lock().await;
        if self.current_bearer(AuthPosture::PackageRead)?.as_deref() != rejected_bearer {
            return Ok(true);
        }
        if *attempted {
            return Ok(false);
        }
        if !session
            .current_source()?
            .is_some_and(|source| source.refresh_policy() == RefreshPolicy::IfRefreshable)
        {
            return Ok(false);
        }
        *attempted = true;
        match session.refresh_now().await {
            Ok(_) => Ok(true),
            Err(error) if error.is_credential_storage_failure() => Err(error),
            Err(_) => Ok(false),
        }
    }

    pub(super) async fn execute_with_package_access_recovery<F, T, Fut>(
        &self,
        op: F,
    ) -> Result<T, LpmError>
    where
        F: Fn() -> Fut,
        Fut: std::future::Future<Output = Result<T, LpmError>>,
    {
        let rejected_bearer = self.current_bearer(AuthPosture::PackageRead)?;
        let attempts = std::sync::atomic::AtomicUsize::new(0);
        match self
            .execute_with_recovery(AuthPosture::PackageRead, || {
                attempts.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                op()
            })
            .await
        {
            Err(error)
                if error.is_not_found()
                    || error.is_forbidden()
                    || matches!(
                        error,
                        LpmError::PackageInstallDenied { .. }
                            | LpmError::Http {
                                status: 403 | 404,
                                ..
                            }
                    ) =>
            {
                if attempts.load(std::sync::atomic::Ordering::Relaxed) == 1
                    && self
                        .recover_package_read_session(rejected_bearer.as_deref())
                        .await?
                {
                    op().await
                } else {
                    Err(error)
                }
            }
            result => result,
        }
    }

    /// Execute an HTTP-bearing operation, handling lazy refresh on 401
    /// for refresh-backed sessions.
    ///
    /// Contract:
    /// 0. **Proactive pass.** If posture allows recovery AND the
    ///    session source is refresh-eligible AND we already know the
    ///    cached state needs help (empty-secret placeholder OR local
    ///    expiry metadata says past TTL), attempt a silent refresh before the
    ///    first request. Network and server failures here are best-effort
    ///    because the existing access token may still work. Credential-storage
    ///    failures are returned because continuing could use partially
    ///    persisted rotated state.
    /// 1. Run `op()` once. Closure reads bearer via `current_bearer`,
    ///    which sees any rotated token from the proactive pass.
    /// 2. If it returns `LpmError::AuthRequired` AND the posture
    ///    allows recovery AND the session source is refreshable,
    ///    attempt one silent refresh (reactive pass).
    /// 3. On refresh success, run `op()` again.
    /// 4. On refresh failure, return `LpmError::SessionExpired`.
    ///
    /// Never loops. Never refreshes for explicit/env/CI/confirmed-legacy
    /// sources. The fuse on `provider.rs::batch_disabled` only ever sees
    /// post-recovery 401s — transient 401s are absorbed here.
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
    pub(super) async fn execute_with_recovery<F, T, Fut>(
        &self,
        posture: AuthPosture,
        op: F,
    ) -> Result<T, LpmError>
    where
        F: Fn() -> Fut,
        Fut: std::future::Future<Output = Result<T, LpmError>>,
    {
        // Proactive pass.
        if posture != AuthPosture::PackageRead
            && posture.allows_recovery()
            && let Some(session) = &self.session
            && let Some(source) = session.current_source()?
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
            let needs_proactive = !session.has_token()?
                || lpm_auth::is_session_access_token_expired(session.registry_url())
                || lpm_auth::session_metadata_corrupted();
            if needs_proactive
                && let Err(error) = session.refresh_now().await
                && error.is_credential_storage_failure()
            {
                return Err(error);
            }
        }

        let first = op().await;
        match first {
            Err(LpmError::AuthRequired) if posture.allows_recovery() => {
                let Some(session) = &self.session else {
                    return Err(LpmError::AuthRequired);
                };
                let Some(source) = session.current_source()? else {
                    return Err(LpmError::AuthRequired);
                };
                if matches!(
                    source,
                    lpm_auth::TokenSource::EnvVar | lpm_auth::TokenSource::CiToken
                ) {
                    return Err(LpmError::EnvTokenRejected);
                }
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
    pub(super) async fn get_json<T: serde::de::DeserializeOwned>(
        &self,
        url: &str,
    ) -> Result<T, LpmError> {
        let response = self.send_with_retry(self.build_get(url).await?).await?;
        parse_capped_api_json(response, &format!("response from {url}")).await
    }

    /// Send a publish request with safe retry logic (S4).
    ///
    /// Unlike `send_with_retry`, this reconciles every ambiguous response
    /// against the exact artifact integrity before it can replay the body.
    pub(super) async fn send_publish_safe<F>(
        &self,
        mut request_factory: F,
        payload: &lpm_http::ReplayableRequestBody,
        bearer: Option<&str>,
        encoded_name: &str,
        published_version: &str,
        published_integrity: &str,
    ) -> Result<PublishSafeResponse, LpmError>
    where
        F: FnMut() -> Result<reqwest::RequestBuilder, LpmError>,
    {
        self.validate_base_url()?;

        let mut last_error = None;
        let mut waited_long = false;

        for attempt in 0..=MAX_RETRIES {
            let req = request_factory()?
                .build()
                .map_err(|e| LpmError::Network(format!("failed to build request: {e}")))?;
            let headers = req.headers().clone();

            let transfer = super::http::TransferClientProvider(self.http.as_ref());
            match lpm_http::send_with_replayable_redirects(&transfer, req, Some(payload)).await {
                Ok(response) => {
                    let status = response.status().as_u16();
                    if matches!(status, 200..=299 | 304) {
                        return Ok(PublishSafeResponse::Response(response));
                    }
                    let facts = AnswerFacts::from_headers(response.headers(), |text| {
                        redact_credentials(text, &headers);
                        if let Some(secret) = bearer
                            && let std::borrow::Cow::Owned(redacted) =
                                lpm_common::redact_exact_secret(text, secret)
                        {
                            *text = redacted;
                        }
                    });
                    let origin = self.registry_origin(response.url());

                    match status {
                        // Non-retryable client errors — fail immediately
                        401 => {
                            let body = read_publish_error_text(response, &headers, bearer).await;
                            return Err(second_factor_or_unauthorized(
                                &facts,
                                &body,
                                &origin,
                                "lpm publish",
                                "publish",
                            ));
                        }
                        403 => {
                            let body = read_publish_error_text(response, &headers, bearer).await;
                            if publish_refusal_is_version_exists(&body, published_version) {
                                return Err(version_exists_error(published_version));
                            }
                            return Err(registry_refusal(status, &facts, &body, &origin));
                        }
                        404 => {
                            let body = read_publish_error_text(response, &headers, bearer).await;
                            return Err(registry_refusal(status, &facts, &body, &origin));
                        }

                        // S4: 500 — do NOT retry. Server may have stored the version.
                        // Check if the version now exists on the registry.
                        500 => {
                            let body_text =
                                read_publish_error_text(response, &headers, bearer).await;
                            tracing::warn!("publish got HTTP 500 — checking if version was stored");

                            match self
                                .reconcile_publish_artifact(
                                    encoded_name,
                                    published_version,
                                    published_integrity,
                                )
                                .await
                                .map_err(ambiguous_publish_reconciliation_error)?
                            {
                                PublishReconciliation::Matched(metadata) => {
                                    tracing::info!(
                                        version = published_version,
                                        "published artifact integrity matched after HTTP 500"
                                    );
                                    return Ok(PublishSafeResponse::Recovered(metadata));
                                }
                                PublishReconciliation::Missing => {}
                            }

                            return Err(registry_refusal(status, &facts, &body_text, &origin));
                        }

                        // Rate limit — respect Retry-After
                        429 => {
                            if attempt < MAX_RETRIES
                                && let Some(wait) = rate_limit_wait(&facts, &mut waited_long)
                            {
                                // Honor the test-only backoff override so
                                // 429-flood retry-exhaustion tests don't
                                // hang on the server-supplied Retry-After.
                                tokio::time::sleep(backoff_override().unwrap_or(wait)).await;
                                continue;
                            }
                            let body = read_publish_error_text(response, &headers, bearer).await;
                            last_error = Some(registry_refusal(status, &facts, &body, &origin));
                            break;
                        }

                        // Retryable gateway errors only (NOT 500)
                        502..=504 => {
                            let body = read_publish_error_text(response, &headers, bearer).await;
                            last_error = Some(registry_refusal(status, &facts, &body, &origin));
                            match self
                                .reconcile_publish_artifact(
                                    encoded_name,
                                    published_version,
                                    published_integrity,
                                )
                                .await
                                .map_err(ambiguous_publish_reconciliation_error)?
                            {
                                PublishReconciliation::Matched(metadata) => {
                                    tracing::info!(
                                        version = published_version,
                                        status,
                                        "published artifact integrity matched after gateway error"
                                    );
                                    return Ok(PublishSafeResponse::Recovered(metadata));
                                }
                                PublishReconciliation::Missing => {}
                            }
                            if attempt < MAX_RETRIES {
                                let delay = backoff_delay(attempt);
                                tokio::time::sleep(delay).await;
                                continue;
                            }
                        }

                        // Other errors — fail immediately
                        _ => {
                            let body = read_publish_error_text(response, &headers, bearer).await;
                            return Err(registry_refusal(status, &facts, &body, &origin));
                        }
                    }
                }
                Err(lpm_http::ReplayableRequestError::Client(error)) => return Err(error),
                Err(lpm_http::ReplayableRequestError::Request(error)) => {
                    last_error = Some(LpmError::Network(
                        lpm_http::display_error(&error).to_string(),
                    ));
                    match self
                        .reconcile_publish_artifact(
                            encoded_name,
                            published_version,
                            published_integrity,
                        )
                        .await
                    {
                        Ok(PublishReconciliation::Matched(metadata)) => {
                            tracing::info!(
                                version = published_version,
                                "published artifact integrity matched after network error"
                            );
                            return Ok(PublishSafeResponse::Recovered(metadata));
                        }
                        Ok(PublishReconciliation::Missing) => {}
                        Err(probe_error) => {
                            return Err(ambiguous_publish_reconciliation_error(probe_error));
                        }
                    }
                    if attempt < MAX_RETRIES {
                        let delay = backoff_delay(attempt);
                        tokio::time::sleep(delay).await;
                        continue;
                    }
                }
                Err(error) => return Err(LpmError::Network(error.to_string())),
            }
        }

        Err(last_error.unwrap_or_else(|| LpmError::Network("publish failed after retries".into())))
    }

    async fn reconcile_publish_artifact(
        &self,
        encoded_name: &str,
        published_version: &str,
        published_integrity: &str,
    ) -> Result<PublishReconciliation, LpmError> {
        let check_url = format!("{}/api/registry/{}", self.base_url, encoded_name);
        let request = self.build_get(&check_url).await.map_err(|error| {
            LpmError::Registry(format!(
                "publish recovery probe could not be built: {error}"
            ))
        })?;
        let response = match self.send_with_retry(request).await {
            Ok(response) => response,
            Err(error) if error.is_not_found() => return Ok(PublishReconciliation::Missing),
            Err(error) => {
                return Err(LpmError::Registry(format!(
                    "publish recovery probe failed: {error}"
                )));
            }
        };
        let metadata =
            parse_capped_api_json::<serde_json::Value>(response, "publish recovery metadata")
                .await?;
        let Some(version) = metadata
            .get("versions")
            .and_then(serde_json::Value::as_object)
            .and_then(|versions| versions.get(published_version))
        else {
            return Ok(PublishReconciliation::Missing);
        };
        let stored_integrity = version
            .get("dist")
            .and_then(|dist| dist.get("integrity"))
            .and_then(serde_json::Value::as_str);
        if stored_integrity == Some(published_integrity) {
            return Ok(PublishReconciliation::Matched(metadata));
        }
        Err(LpmError::Registry(format!(
            "version {published_version} exists after an ambiguous publish response, but its stored integrity {} does not match the attempted artifact integrity {published_integrity}; inspect the registry before retrying",
            stored_integrity.unwrap_or("<missing>")
        )))
    }

    /// Send a request with retry logic for transient failures.
    ///
    /// Retries on: 408 (timeout), 429 (rate limit), 500, 502, 503, 504.
    /// Uses exponential backoff with jitter.
    /// Non-retryable errors (401, 403, 404, 422) fail immediately.
    pub(super) async fn send_with_retry(
        &self,
        request_builder: reqwest::RequestBuilder,
    ) -> Result<reqwest::Response, LpmError> {
        self.send_with_retry_with_npmrc_auth(request_builder, None)
            .await
    }

    pub(super) async fn send_with_retry_with_npmrc_auth(
        &self,
        request_builder: reqwest::RequestBuilder,
        auth: Option<&crate::npmrc::RegistryAuth>,
    ) -> Result<reqwest::Response, LpmError> {
        // Reject insecure non-localhost HTTP before making any request
        self.validate_base_url()?;

        // Clone the request for potential retries.
        // reqwest::RequestBuilder can only be sent once, so we need to rebuild.
        // We use try_clone() on the built request.
        let request = request_builder
            .build()
            .map_err(|e| LpmError::Network(format!("failed to build request: {e}")))?;

        self.send_request_with_retry_and_npmrc_auth(request, None, auth)
            .await
    }

    pub(super) async fn send_request_with_retry_and_npmrc_auth(
        &self,
        request: reqwest::Request,
        client_override: Option<reqwest::Client>,
        auth: Option<&crate::npmrc::RegistryAuth>,
    ) -> Result<reqwest::Response, LpmError> {
        self.send_request_with_retry_and_client_provider(
            request,
            client_override,
            auth,
            self.http.as_ref(),
            FailedAnswer::Error,
        )
        .await
        .and_then(Answered::into_response)
    }

    /// Sends a request as [`send_with_retry`](Self::send_with_retry) does,
    /// retrying a timeout, a rate limit, a server error or a network
    /// failure, but hands back any other answer, and the last one retried,
    /// with its status, and its body with the request's credentials
    /// redacted.
    pub(super) async fn send_with_retry_keeping_status(
        &self,
        request_builder: reqwest::RequestBuilder,
    ) -> Result<Answered, LpmError> {
        self.validate_base_url()?;
        let request = request_builder
            .build()
            .map_err(|e| LpmError::Network(format!("failed to build request: {e}")))?;
        self.send_request_with_retry_and_client_provider(
            request,
            None,
            None,
            self.http.as_ref(),
            FailedAnswer::Response,
        )
        .await
    }

    #[tracing::instrument(
        target = "lpm_install_timeline",
        level = "trace",
        name = "http_request",
        skip_all
    )]
    pub(super) async fn send_request_with_retry_and_client_provider<P>(
        &self,
        request: reqwest::Request,
        client_override: Option<reqwest::Client>,
        auth: Option<&crate::npmrc::RegistryAuth>,
        provider: &P,
        failed: FailedAnswer,
    ) -> Result<Answered, LpmError>
    where
        P: lpm_http::ReplayableHttpClientProvider<Error = LpmError> + Sync,
    {
        let mut request = request;
        let routed_to_npm_transport = self.route_to_npm_transport(&mut request);
        self.validate_base_url()?;
        self.validate_request_url(request.url())?;

        let mut last_error = None;
        let mut waited_long = false;
        let can_reselect_redirect_clients = request.try_clone().is_some();

        for attempt in 0..=MAX_RETRIES {
            tracing::event!(name: "request_attempt", target: "lpm_install_timeline", tracing::Level::TRACE, attempt = attempt as u64);
            let req = request.try_clone().ok_or_else(|| {
                LpmError::Network("request body cannot be retried (not cloneable)".into())
            })?;

            let response = if let Some(client) = client_override.as_ref() {
                client
                    .execute(req)
                    .await
                    .map_err(|error| LpmError::Network(lpm_http::error_chain(&error)))
            } else if can_reselect_redirect_clients {
                let authorization_allowed = |url: &reqwest::Url| {
                    auth.is_none_or(|credential| credential.matches_destination(url))
                };
                let authorization_scope = auth.map(|_| {
                    &authorization_allowed as &(dyn Fn(&reqwest::Url) -> bool + Send + Sync)
                });
                match lpm_http::send_with_replayable_redirects_and_authorization_scope(
                    provider,
                    req,
                    None,
                    authorization_scope,
                )
                .await
                {
                    Ok(response) => Ok(response),
                    Err(lpm_http::ReplayableRequestError::Client(error)) => return Err(error),
                    Err(lpm_http::ReplayableRequestError::Request(error)) => {
                        Err(LpmError::Network(lpm_http::error_chain(&error)))
                    }
                    Err(error) => return Err(LpmError::Network(error.to_string())),
                }
            } else {
                self.http
                    .for_url(req.url().as_str())
                    .await?
                    .execute(req)
                    .await
                    .map_err(|error| LpmError::Network(lpm_http::error_chain(&error)))
            };
            match response {
                Ok(response) => {
                    let status = response.status().as_u16();
                    tracing::event!(name: "headers_observed", target: "lpm_install_timeline", tracing::Level::TRACE, attempt = attempt as u64, status = u64::from(status));
                    if matches!(status, 200..=299 | 304) {
                        return Ok(Answered::Success(response));
                    }
                    let retried = matches!(status, 408 | 429 | 500 | 502 | 503 | 504)
                        && attempt < MAX_RETRIES;
                    let facts = answer_facts(response.headers(), request.headers());
                    let origin =
                        self.answer_origin(&request, response.url(), routed_to_npm_transport);
                    if failed == FailedAnswer::Response && !retried {
                        return Ok(Answered::Failed(FailedResponse {
                            status,
                            body: read_request_error_text(response, &request).await,
                            facts,
                            origin,
                        }));
                    }

                    match status {
                        // Non-retryable errors — fail immediately
                        401 => {
                            let body = read_request_error_text(response, &request).await;
                            return Err(unauthorized(&facts, &body, &origin));
                        }
                        // Retryable: rate limit
                        429 => {
                            if attempt < MAX_RETRIES
                                && let Some(wait) = rate_limit_wait(&facts, &mut waited_long)
                            {
                                // Honor the test-only backoff override here
                                // too — see the sibling site in publish-path.
                                let delay = backoff_override().unwrap_or(wait);
                                tracing::event!(name: "backoff_start", target: "lpm_install_timeline", tracing::Level::TRACE, attempt = attempt as u64);
                                tokio::time::sleep(delay).await;
                                tracing::event!(name: "backoff_end", target: "lpm_install_timeline", tracing::Level::TRACE, attempt = attempt as u64);
                                continue;
                            }
                            // Read only once the limit stands, for what it says.
                            let body = tokio::time::timeout(
                                RETRY_ERROR_BODY_TIMEOUT,
                                read_request_error_text(response, &request),
                            )
                            .await
                            .unwrap_or_default();
                            last_error = Some(registry_refusal(status, &facts, &body, &origin));
                            break;
                        }

                        // Retryable: server errors and timeouts
                        408 | 500 | 502 | 503 | 504 => {
                            let body = tokio::time::timeout(
                                RETRY_ERROR_BODY_TIMEOUT,
                                read_request_error_text(response, &request),
                            )
                            .await
                            .unwrap_or_default();
                            last_error = Some(registry_refusal(status, &facts, &body, &origin));
                            if attempt < MAX_RETRIES {
                                let delay = backoff_delay(attempt);
                                tracing::event!(name: "backoff_start", target: "lpm_install_timeline", tracing::Level::TRACE, attempt = attempt as u64);
                                tokio::time::sleep(delay).await;
                                tracing::event!(name: "backoff_end", target: "lpm_install_timeline", tracing::Level::TRACE, attempt = attempt as u64);
                                continue;
                            }
                        }

                        // Other errors — fail immediately
                        _ => {
                            let body = read_request_error_text(response, &request).await;
                            return Err(registry_refusal(status, &facts, &body, &origin));
                        }
                    }
                }
                Err(error) => {
                    tracing::event!(name: "request_failed", target: "lpm_install_timeline", tracing::Level::TRACE, attempt = attempt as u64);
                    // Network-level errors (DNS, connection refused, timeout) are retryable
                    last_error = Some(error);
                    if attempt < MAX_RETRIES {
                        let delay = backoff_delay(attempt);
                        tracing::event!(name: "backoff_start", target: "lpm_install_timeline", tracing::Level::TRACE, attempt = attempt as u64);
                        tokio::time::sleep(delay).await;
                        tracing::event!(name: "backoff_end", target: "lpm_install_timeline", tracing::Level::TRACE, attempt = attempt as u64);
                        continue;
                    }
                }
            }
        }

        Err(last_error.unwrap_or_else(|| LpmError::Network("request failed after retries".into())))
    }

    /// Points a request for npm's registry at the configured npm transport,
    /// and says whether it did.
    fn route_to_npm_transport(&self, request: &mut reqwest::Request) -> bool {
        let Some(url) = self.npm_transport_url_for(request.url()) else {
            return false;
        };
        *request.url_mut() = url;
        true
    }

    /// Which registry answered `request`: the host a redirect ended at, or,
    /// for a request routed to the npm transport, npm's registry, which the
    /// transport stands in for.
    fn answer_origin(
        &self,
        request: &reqwest::Request,
        answered: &reqwest::Url,
        routed_to_npm_transport: bool,
    ) -> RegistryOrigin {
        if routed_to_npm_transport && answered.origin() == request.url().origin() {
            return RegistryOrigin {
                origin: reqwest::Url::parse(&self.npm_registry_url).map_or_else(
                    |_| self.npm_registry_url.trim_end_matches('/').to_owned(),
                    |url| url.origin().ascii_serialization(),
                ),
                kind: RegistryKind::Npm,
            };
        }
        self.registry_origin(answered)
    }

    fn npm_transport_url_for(&self, url: &reqwest::Url) -> Option<reqwest::Url> {
        let transport = self.npm_transport_url.as_deref()?;
        let rest = url
            .as_str()
            .strip_prefix(self.npm_registry_url.trim_end_matches('/'))?;
        if !(rest.is_empty() || rest.starts_with(['/', '?'])) {
            return None;
        }
        reqwest::Url::parse(&format!("{}{rest}", transport.trim_end_matches('/'))).ok()
    }
}

/// Whether a publish's 403 says the Registry has the version: by its
/// `VERSION_EXISTS` code, or by the exact message registries that predate the
/// code send.
pub(super) fn publish_refusal_is_version_exists(body: &str, version: &str) -> bool {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(body) else {
        return false;
    };
    let field = |name: &str| value.get(name).and_then(serde_json::Value::as_str);
    field("code") == Some("VERSION_EXISTS")
        || field("error")
            == Some(
                format!("Version {version} already exists. You cannot overwrite versions.")
                    .as_str(),
            )
}

/// The error a registry's failed answer to a request that sent `sent` is:
/// a 401 as [`unauthorized`] reads it, any other as [`registry_refusal`]
/// does, with the request's credentials redacted from what it says.
pub(super) async fn answer_refusal(
    origin: &RegistryOrigin,
    response: reqwest::Response,
    sent: &reqwest::header::HeaderMap,
) -> LpmError {
    let status = response.status().as_u16();
    let facts = answer_facts(response.headers(), sent);
    let body = read_error_text_redacting(response, sent).await;
    if status == 401 {
        return unauthorized(&facts, &body, origin);
    }
    registry_refusal(status, &facts, &body, origin)
}

pub(super) fn build_request(
    request: reqwest::RequestBuilder,
) -> Result<reqwest::Request, LpmError> {
    request
        .build()
        .map_err(|error| LpmError::Network(format!("failed to build request: {error}")))
}

/// How long to sit out a 429 before retrying, or None when the wait it asks
/// for is the user's to hear about. Waits up to the backoff cap are retried
/// as often as any failure; one longer wait, up to a minute, once, so a
/// registry pacing a burst doesn't fail an install it would have served.
fn rate_limit_wait(facts: &AnswerFacts, waited_long: &mut bool) -> Option<Duration> {
    let wanted = Duration::from_secs(facts.retry_after_secs.unwrap_or(1));
    if wanted <= RETRY_MAX_DELAY {
        return Some(wanted);
    }
    if *waited_long || wanted > RATE_LIMIT_LONGEST_WAIT {
        return None;
    }
    *waited_long = true;
    tracing::info!(
        "the registry rate-limited this request; waiting {}s as it asked",
        wanted.as_secs()
    );
    Some(wanted)
}

/// What a 401 that may be a second-factor challenge is: the challenge or
/// refused proof it names, or else what any 401 from that registry is.
fn second_factor_or_unauthorized(
    facts: &AnswerFacts,
    body: &str,
    origin: &RegistryOrigin,
    command: &'static str,
    operation: &str,
) -> LpmError {
    let challenge = serde_json::from_str::<serde_json::Value>(body).map(|json| {
        super::second_factor::second_factor_unauthorized_error(&json, command, operation)
    });
    match challenge {
        Ok(LpmError::AuthRequired) | Err(_) => unauthorized(facts, body, origin),
        Ok(error) => error,
    }
}

/// A publish refused because the Registry has the version.
pub(super) fn version_exists_error(version: &str) -> LpmError {
    LpmError::Registry(format!(
        "Version {version} already exists. Verify the existing release in the registry if an earlier publish was interrupted. To publish different contents, choose a new version."
    ))
}

/// What a publish's 401 is: the registry asking for the second factor as a
/// browser approval or a code, a code or approval it refused, or the
/// credential itself. A refused approval isn't the credential's fault, so
/// it must not end as `AuthRequired`, which refreshes the session and
/// publishes again with the same spent token.
async fn read_publish_error_text(
    response: reqwest::Response,
    headers: &reqwest::header::HeaderMap,
    bearer: Option<&str>,
) -> String {
    let body = read_error_text_redacting(response, headers).await;
    match bearer {
        Some(secret) => lpm_common::redact_exact_secret(&body, secret).into_owned(),
        None => body,
    }
}

impl RegistryClient {
    /// Which registry `url` is: the LPM registry, npm's, or another.
    pub(super) fn registry_origin(&self, url: &reqwest::Url) -> RegistryOrigin {
        RegistryOrigin::of(url, &self.base_url, &self.npm_registry_url)
    }
}

/// The headers of a refusal the LPM registry gave, kept beside it outside
/// the retry loop.
pub(super) struct LpmRefusalHeaders<'a> {
    pub(super) retry_after_secs: Option<u64>,
    pub(super) request_id: Option<&'a str>,
    pub(super) notice: Option<&'a str>,
}

/// The error the LPM registry's refusal is, from its status, body and
/// headers, for an answer read outside the retry loop.
pub(super) fn lpm_refusal(
    status: u16,
    body: &str,
    headers: LpmRefusalHeaders<'_>,
    registry: &str,
) -> LpmError {
    let origin = RegistryOrigin {
        origin: reqwest::Url::parse(registry).map_or_else(
            |_| registry.trim_end_matches('/').to_owned(),
            |url| url.origin().ascii_serialization(),
        ),
        kind: RegistryKind::Lpm,
    };
    let facts = AnswerFacts {
        content_type: None,
        retry_after_secs: headers.retry_after_secs,
        request_id: headers.request_id.map(str::to_owned),
        notice: headers.notice.map(str::to_owned),
    };
    if status == 401 {
        return unauthorized(&facts, body, &origin);
    }
    registry_refusal(status, &facts, body, &origin)
}

/// What the retry loop hands back for an answer that isn't a success.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum FailedAnswer {
    /// An error: a 401 as `AuthRequired`, any other as
    /// [`registry_refusal`] makes it.
    Error,
    /// [`Answered::Failed`]: one that isn't retried, and the last one that
    /// was.
    Response,
}

/// The retry loop's answer.
#[derive(Debug)]
pub(super) enum Answered {
    Success(reqwest::Response),
    /// An answer that isn't a success, which only [`FailedAnswer::Response`]
    /// hands back.
    Failed(FailedResponse),
}

impl Answered {
    /// The success, or the error a failed answer is.
    pub(super) fn into_response(self) -> Result<reqwest::Response, LpmError> {
        match self {
            Self::Success(response) => Ok(response),
            Self::Failed(failed) => Err(failed.into_error()),
        }
    }
}

/// An answer that isn't a success, read: its status, what its headers say,
/// which registry gave it, and its body, capped, with the request's
/// credentials redacted, as a server can echo them.
#[derive(Debug)]
pub(super) struct FailedResponse {
    pub(super) status: u16,
    pub(super) body: String,
    pub(super) facts: AnswerFacts,
    pub(super) origin: RegistryOrigin,
}

impl FailedResponse {
    /// The error this answer is: a 401 as [`unauthorized`] reads it, any
    /// other as [`registry_refusal`] does.
    pub(super) fn into_error(self) -> LpmError {
        if self.status == 401 {
            return unauthorized(&self.facts, &self.body, &self.origin);
        }
        registry_refusal(self.status, &self.facts, &self.body, &self.origin)
    }
}

/// The seconds a 429's `Retry-After` asks to wait, in seconds or as an HTTP
/// date, for a change that isn't retried and reports the wait instead.
pub(super) fn retry_after_seconds(response: &reqwest::Response) -> u64 {
    response
        .headers()
        .get("retry-after")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| super::error_body::retry_after_secs(value, std::time::SystemTime::now()))
        .unwrap_or(1)
}

/// Exponential backoff with capped delay.
/// attempt 0 → 1s, attempt 1 → 2s, attempt 2 → 4s, capped at 10s.
///
/// **Test-only override** ([`backoff_override`]): when
/// `LPM_RETRY_BACKOFF_MS_OVERRIDE` is set AND we're in a debug build,
/// the override value (in ms) is returned instead of the exponential
/// schedule. Production retry policy is immune.
pub(super) fn backoff_delay(attempt: u32) -> Duration {
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
///    `cargo test` / `cargo nextest`).
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
pub(super) fn backoff_override() -> Option<Duration> {
    if !cfg!(debug_assertions) {
        return None;
    }
    std::env::var("LPM_RETRY_BACKOFF_MS_OVERRIDE")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .map(Duration::from_millis)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;
    use std::sync::{Mutex, OnceLock};

    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(())).lock().unwrap()
    }

    struct ScopedEnv {
        previous: Vec<(&'static str, Option<OsString>)>,
    }

    impl ScopedEnv {
        fn set(vars: &[(&'static str, &str)]) -> Self {
            let previous = vars
                .iter()
                .map(|(key, _)| (*key, std::env::var_os(key)))
                .collect();
            for (key, value) in vars {
                unsafe {
                    std::env::set_var(key, value);
                }
            }
            Self { previous }
        }
    }

    impl Drop for ScopedEnv {
        fn drop(&mut self) {
            for (key, value) in self.previous.iter().rev() {
                unsafe {
                    match value {
                        Some(value) => std::env::set_var(key, value),
                        None => std::env::remove_var(key),
                    }
                }
            }
        }
    }

    #[cfg(not(debug_assertions))]
    #[test]
    fn lpm_test_mode_does_not_enable_backoff_override_in_release_builds() {
        let _lock = env_lock();
        let _env = ScopedEnv::set(&[
            ("LPM_TEST_MODE", "1"),
            ("LPM_RETRY_BACKOFF_MS_OVERRIDE", "10"),
        ]);

        assert_eq!(backoff_override(), None);
    }

    #[cfg(debug_assertions)]
    #[test]
    fn backoff_override_honors_retry_override_in_debug_builds() {
        let _lock = env_lock();
        let _env = ScopedEnv::set(&[("LPM_RETRY_BACKOFF_MS_OVERRIDE", "10")]);

        assert_eq!(backoff_override(), Some(Duration::from_millis(10)));
    }

    #[test]
    fn a_rate_limit_is_sat_out_up_to_a_minute_once() {
        let facts = |secs| AnswerFacts {
            retry_after_secs: Some(secs),
            ..AnswerFacts::default()
        };
        let mut waited_long = false;
        assert_eq!(
            rate_limit_wait(&facts(5), &mut waited_long),
            Some(Duration::from_secs(5))
        );
        assert!(!waited_long);
        assert_eq!(
            rate_limit_wait(&facts(45), &mut waited_long),
            Some(Duration::from_secs(45))
        );
        assert!(waited_long);
        assert_eq!(rate_limit_wait(&facts(45), &mut waited_long), None);
        assert_eq!(
            rate_limit_wait(&facts(10), &mut waited_long),
            Some(Duration::from_secs(10))
        );
        assert_eq!(rate_limit_wait(&facts(61), &mut false), None);
        assert_eq!(
            rate_limit_wait(&AnswerFacts::default(), &mut false),
            Some(Duration::from_secs(1))
        );
    }

    #[test]
    fn one_long_rate_limit_wait_is_sat_out_and_a_second_is_reported() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let _lock = env_lock();
        let _env = ScopedEnv::set(&[("LPM_RETRY_BACKOFF_MS_OVERRIDE", "1")]);
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let server = MockServer::start().await;
            Mock::given(method("GET"))
                .and(path("/paced-once"))
                .respond_with(ResponseTemplate::new(429).insert_header("retry-after", "30"))
                .up_to_n_times(1)
                .expect(1)
                .mount(&server)
                .await;
            Mock::given(method("GET"))
                .and(path("/paced-once"))
                .respond_with(ResponseTemplate::new(200).set_body_string("{}"))
                .expect(1)
                .mount(&server)
                .await;
            Mock::given(method("GET"))
                .and(path("/paced-twice"))
                .respond_with(ResponseTemplate::new(429).insert_header("retry-after", "30"))
                .expect(2)
                .mount(&server)
                .await;
            let client = RegistryClient::new().with_base_url(server.uri());

            let once = client
                .send_with_retry(
                    client
                        .build_get(&format!("{}/paced-once", server.uri()))
                        .await
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(once.status(), reqwest::StatusCode::OK);

            let twice = client
                .send_with_retry(
                    client
                        .build_get(&format!("{}/paced-twice", server.uri()))
                        .await
                        .unwrap(),
                )
                .await
                .unwrap_err();
            assert!(
                matches!(
                    twice,
                    LpmError::RateLimited {
                        retry_after_secs: 30
                    }
                ),
                "{twice:?}"
            );
            server.verify().await;
        });
    }
}
