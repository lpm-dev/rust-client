use super::*;

/// Maximum number of retries for transient failures.
pub(super) const MAX_RETRIES: u32 = 3;

/// Base delay for exponential backoff (1 second).
pub(super) const RETRY_BASE_DELAY: Duration = Duration::from_secs(1);

/// Maximum backoff delay (10 seconds).
pub(super) const RETRY_MAX_DELAY: Duration = Duration::from_secs(10);

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

    /// POST JSON with auth and an optional MFA code, refreshing once when a
    /// plain bearer rejection is safe to retry.
    ///
    /// Valid OTP challenges remain command errors and never trigger refresh.
    pub async fn post_json_with_otp_recovery(
        &self,
        url: &str,
        body: &serde_json::Value,
        otp: Option<&str>,
        command: &'static str,
        operation: &'static str,
    ) -> Result<serde_json::Value, LpmError> {
        self.execute_with_recovery(AuthPosture::AuthRequired, || async {
            let mut request = self.http.for_url(url).await?.post(url).json(body);
            if let Some(bearer) = self.current_bearer(AuthPosture::AuthRequired)? {
                request = request.bearer_auth(bearer);
            }
            if let Some(otp) = otp {
                request = request.header("x-otp", otp);
            }
            let response = self.send_once_preserving_status(request).await?;
            let status = response.status();
            let parsed = parse_capped_api_json::<serde_json::Value>(
                response,
                &format!("{operation} response"),
            )
            .await;
            if status == reqwest::StatusCode::UNAUTHORIZED {
                if let Ok(body) = &parsed {
                    match body.get("code").and_then(serde_json::Value::as_str) {
                        Some("OTP_REQUIRED") => return Err(LpmError::OtpRequired { command }),
                        Some("OTP_INVALID") => return Err(LpmError::OtpInvalid { command }),
                        _ => {}
                    }
                }
                return Err(LpmError::AuthRequired);
            }
            let parsed = parsed?;
            if !status.is_success() {
                let error = parsed
                    .get("error")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("unknown error");
                return Err(LpmError::Registry(format!("{operation} failed: {error}")));
            }
            Ok(parsed)
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
        let mut request = self.http.for_url(url).await?.post(url).json(body);
        if let Some(bearer) = self.current_bearer(AuthPosture::AuthRequired)? {
            request = request.bearer_auth(bearer);
        }
        self.send_once_preserving_status(request).await
    }

    async fn send_once_preserving_status(
        &self,
        request: reqwest::RequestBuilder,
    ) -> Result<reqwest::Response, LpmError> {
        self.validate_base_url()?;
        let request = request
            .build()
            .map_err(|error| LpmError::Network(format!("failed to build request: {error}")))?;
        self.http
            .for_url(request.url().as_str())
            .await?
            .execute(request)
            .await
            .map_err(|error| LpmError::Network(lpm_http::error_chain(&error)))
    }

    /// POST JSON once, refresh on a bearer 401, then retry the operation once.
    /// Every non-401 HTTP status remains available to the caller.
    pub async fn post_json_raw_status_with_recovery(
        &self,
        url: &str,
        body: &serde_json::Value,
    ) -> Result<reqwest::Response, LpmError> {
        self.execute_with_recovery(AuthPosture::AuthRequired, || async {
            let response = self.post_json_raw_status(url, body).await?;
            if response.status() == reqwest::StatusCode::UNAUTHORIZED {
                return Err(LpmError::AuthRequired);
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
        if posture.allows_recovery()
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
                && let Err(error @ LpmError::CredentialStorage(_)) = session.refresh_now().await
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
    /// Unlike `send_with_retry`, this does NOT retry on HTTP 500 because
    /// the server may have stored the version before returning an error.
    /// On 500: checks if the version already exists — if so, treats as success.
    /// Only retries on: 502, 503, 504 (gateway errors) and network failures.
    pub(super) async fn send_publish_safe(
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

            // Route via the request's URL so a per-origin client (eager
            // hit OR lazy build) handles its own TLS context. Lazy build
            // fires for transitive registry / CDN origins that surface
            // from resolved metadata after the eager set was computed.
            let client_for_req = self.http.for_url(req.url().as_str()).await?;
            match client_for_req.execute(req).await {
                Ok(response) => {
                    let status = response.status().as_u16();

                    match status {
                        200..=299 | 304 => return Ok(response),

                        // Non-retryable client errors — fail immediately
                        401 => return Err(LpmError::AuthRequired),
                        403 => {
                            let body = read_capped_error_text(response).await;
                            return Err(forbidden_error_from_body(body));
                        }
                        404 => {
                            let body = read_capped_error_text(response).await;
                            return Err(LpmError::NotFound(body));
                        }

                        // S4: 500 — do NOT retry. Server may have stored the version.
                        // Check if the version now exists on the registry.
                        500 => {
                            let body_text = read_capped_error_text(response).await;
                            tracing::warn!("publish got HTTP 500 — checking if version was stored");

                            // Check if the version exists by GETting the package
                            let check_url =
                                format!("{}/api/registry/{}", self.base_url, encoded_name);
                            // `build_get` is fallible here; on cert load
                            // failure for the recovery probe origin,
                            // we can't verify whether the publish
                            // succeeded server-side. Treat as not-OK
                            // (don't fall through to the retry-as-success
                            // branch) and let the outer loop continue.
                            let probe = match self.build_get(&check_url).await {
                                Ok(req) => self.send_with_retry(req).await,
                                Err(_) => Err(LpmError::Network(
                                    "publish recovery probe failed to build (TLS)".into(),
                                )),
                            };
                            if let Ok(check_resp) = probe
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
                                // Honor the test-only backoff override so
                                // 429-flood retry-exhaustion tests don't
                                // hang on the server-supplied Retry-After.
                                let delay = backoff_override()
                                    .unwrap_or_else(|| Duration::from_secs(retry_after));
                                tokio::time::sleep(delay).await;
                                continue;
                            }
                        }

                        // Retryable gateway errors only (NOT 500)
                        502..=504 => {
                            let body = read_capped_error_text(response).await;
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
                            let body = read_capped_error_text(response).await;
                            return Err(LpmError::Http {
                                status,
                                message: body,
                            });
                        }
                    }
                }
                Err(e) => {
                    if lpm_http::is_https_downgrade(&e) {
                        return Err(LpmError::Network(lpm_http::error_chain(&e)));
                    }
                    // Network-level errors are retryable
                    last_error = Some(LpmError::Network(lpm_http::display_error(&e).to_string()));
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
    pub(super) async fn send_with_retry(
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

        self.send_request_with_retry(request, None).await
    }

    pub(super) async fn send_request_with_retry(
        &self,
        request: reqwest::Request,
        client_override: Option<reqwest::Client>,
    ) -> Result<reqwest::Response, LpmError> {
        self.validate_base_url()?;

        let mut last_error = None;

        for attempt in 0..=MAX_RETRIES {
            let req = request.try_clone().ok_or_else(|| {
                LpmError::Network("request body cannot be retried (not cloneable)".into())
            })?;

            let client_for_req = match client_override.as_ref() {
                Some(client) => client.clone(),
                None => self.http.for_url(req.url().as_str()).await?,
            };
            match client_for_req.execute(req).await {
                Ok(response) => {
                    let status = response.status().as_u16();

                    match status {
                        200..=299 | 304 => return Ok(response),

                        // Non-retryable errors — fail immediately
                        401 => return Err(LpmError::AuthRequired),
                        403 => {
                            let body = read_capped_error_text(response).await;
                            return Err(forbidden_error_from_body(body));
                        }
                        404 => {
                            let body = read_capped_error_text(response).await;
                            return Err(LpmError::NotFound(body));
                        }

                        // Retryable: rate limit
                        429 => {
                            let retry_after = parse_retry_after(&response);
                            last_error = Some(LpmError::RateLimited {
                                retry_after_secs: retry_after,
                            });
                            if attempt < MAX_RETRIES {
                                // Honor the test-only backoff override here
                                // too — see the sibling site in publish-path.
                                let delay = backoff_override()
                                    .unwrap_or_else(|| Duration::from_secs(retry_after));
                                tokio::time::sleep(delay).await;
                                continue;
                            }
                        }

                        // Retryable: server errors and timeouts
                        408 | 500 | 502 | 503 | 504 => {
                            let body = read_capped_error_text(response).await;
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
                            let body = read_capped_error_text(response).await;
                            return Err(LpmError::Http {
                                status,
                                message: body,
                            });
                        }
                    }
                }
                Err(e) => {
                    if lpm_http::is_https_downgrade(&e) {
                        return Err(LpmError::Network(lpm_http::error_chain(&e)));
                    }
                    // Network-level errors (DNS, connection refused, timeout) are retryable
                    last_error = Some(LpmError::Network(lpm_http::error_chain(&e)));
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

/// Parse `Retry-After` header from a 429 response.
/// Returns seconds to wait. Falls back to 1 second if header is missing/unparseable.
pub(super) fn parse_retry_after(response: &reqwest::Response) -> u64 {
    response
        .headers()
        .get("retry-after")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok())
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
}
