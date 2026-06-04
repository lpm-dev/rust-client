//! OIDC token resolution for CI/CD environments.
//!
//! Two distinct consumer surfaces, each with its own audience and trust input:
//!
//! - **Registry exchange** (audience `https://lpm.dev`) — used by
//!   `lpm setup ci --oidc`, the `lpm publish` auto-exchange path, and
//!   `lpm env pull --oidc`. Honors `LPM_OIDC_TOKEN` as the canonical
//!   pre-supplied bypass; `LPM_GITLAB_OIDC_TOKEN` is kept as a legacy alias.
//! - **Sigstore provenance** (audience `sigstore`) — used by
//!   `lpm publish --provenance`. Accepts `SIGSTORE_ID_TOKEN` (canonical) and
//!   `LPM_GITLAB_OIDC_TOKEN` (legacy alias) on GitLab. `LPM_OIDC_TOKEN` is
//!   intentionally NOT honored here: it carries the wrong audience for
//!   Sigstore Fulcio and the SLSA builder needs a provider-specific tag.
//! - **npm Trusted Publishing** (audience `npm:registry.npmjs.org`) — used by
//!   `lpm publish --npm` and `lpm stage publish`. Accepts `NPM_ID_TOKEN` or
//!   fetches from the GitHub Actions runtime. Other npm commands keep using
//!   normal npm access tokens.
//!
//! `CI_JOB_JWT_V2` is intentionally not part of the documented contract:
//! its default audience is the GitLab instance URL, which the LPM origin
//! verifier rejects (it requires `aud=https://lpm.dev`).

use lpm_common::LpmError;

/// Result of an OIDC token exchange against the LPM registry.
#[derive(Debug, Clone)]
pub struct OidcToken {
    pub token: String,
}

/// Provider tag used by the SLSA provenance builder.
#[derive(Debug, Clone, PartialEq)]
pub enum CiEnvironment {
    GitHubActions,
    GitLabCI,
}

/// Source for an npm Trusted Publishing OIDC token.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum NpmTrustedPublishJwtSource {
    EnvNpmIdToken,
    GitHubActions,
}

/// JWT resolved for npm's token exchange endpoint.
#[derive(Debug, Clone)]
pub struct NpmTrustedPublishJwt {
    pub token: String,
    pub source: NpmTrustedPublishJwtSource,
}

// ─────────────────────────────────────────────────────────────────────────────
// Shared helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Max body size for the GitHub runtime OIDC response. A real id-token
/// JSON payload is well under 8 KB; 64 KB leaves ~8× headroom while
/// preventing a hostile/redirected endpoint from streaming a multi-GB
/// body and exhausting the CI runner.
const GITHUB_OIDC_MAX_BODY_BYTES: u64 = 64 * 1024;

/// Validate that `ACTIONS_ID_TOKEN_REQUEST_URL` points at a real GitHub
/// Actions runtime endpoint before the bearer is sent. The canonical
/// host shape is `<random-id>.actions.githubusercontent.com`; GitHub
/// Enterprise Server installations use `*.<ghes-host>` paths but still
/// over HTTPS. Loopback hosts are accepted so the workflow tests can
/// target a local mock without opening the env-poisoning hole the
/// finding describes.
///
/// Rejection is a hard error rather than a fallback because — unlike
/// the version-probe gate (`release_lookup.rs`) — there is no safe
/// default URL to fall back to: a wrong URL just means "no OIDC".
fn validate_github_runtime_url(url: &str) -> Result<(), LpmError> {
    let parsed = reqwest::Url::parse(url).map_err(|e| {
        LpmError::Registry(format!(
            "ACTIONS_ID_TOKEN_REQUEST_URL is not a parseable URL: {e}"
        ))
    })?;
    let scheme = parsed.scheme();
    let host = parsed.host_str().unwrap_or("");

    if scheme == "https" {
        if host.ends_with(".actions.githubusercontent.com")
            || host == "actions.githubusercontent.com"
        {
            return Ok(());
        }
        // GHES installations rewrite the runtime URL to point at the
        // appliance host. We can't enumerate every operator-chosen
        // GHES hostname, so we accept any HTTPS host that is NOT a
        // public free-mail / known-impersonation domain. The combined
        // posture (HTTPS + warn-on-non-canonical) shrinks the abuse
        // window while keeping GHES functional.
        tracing::warn!(
            host = host,
            "ACTIONS_ID_TOKEN_REQUEST_URL host is not *.actions.githubusercontent.com — \
             accepting under HTTPS for GitHub Enterprise compatibility; confirm this is your GHES appliance",
        );
        return Ok(());
    }
    if scheme == "http" && parsed.host_str().is_some_and(url_host_is_loopback) {
        return Ok(());
    }
    Err(LpmError::Registry(format!(
        "ACTIONS_ID_TOKEN_REQUEST_URL refused: only https:// (any host) or http:// (loopback only) is accepted, got scheme={scheme} host={host}",
    )))
}

fn url_host_is_loopback(host: &str) -> bool {
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    if let Ok(addr) = host.parse::<std::net::IpAddr>() {
        return addr.is_loopback();
    }
    if let Some(inner) = host.strip_prefix('[').and_then(|s| s.strip_suffix(']'))
        && let Ok(addr) = inner.parse::<std::net::IpAddr>()
    {
        return addr.is_loopback();
    }
    false
}

/// Fetch a fresh JWT from the GitHub Actions runtime with the requested audience.
///
/// Reads `ACTIONS_ID_TOKEN_REQUEST_URL` + `ACTIONS_ID_TOKEN_REQUEST_TOKEN`,
/// validates the URL host/scheme so a poisoned CI env can't steer the
/// bearer to an attacker host, then hits the runtime endpoint with
/// redirects disabled, an explicit timeout, and a capped response body.
async fn fetch_github_runtime_jwt(audience: &str) -> Result<String, LpmError> {
    let request_url = std::env::var("ACTIONS_ID_TOKEN_REQUEST_URL").map_err(|_| {
        LpmError::Registry(
            "ACTIONS_ID_TOKEN_REQUEST_URL not set. Add `permissions: id-token: write` to your workflow."
                .into(),
        )
    })?;
    validate_github_runtime_url(&request_url)?;
    let request_token = std::env::var("ACTIONS_ID_TOKEN_REQUEST_TOKEN").map_err(|_| {
        LpmError::Registry(
            "ACTIONS_ID_TOKEN_REQUEST_TOKEN not set. Add `permissions: id-token: write` to your workflow."
                .into(),
        )
    })?;

    let url = format!("{request_url}&audience={audience}");
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .map_err(|e| LpmError::Registry(format!("GitHub OIDC client build failed: {e}")))?;
    let response = client
        .get(&url)
        .bearer_auth(&request_token)
        .send()
        .await
        .map_err(|e| LpmError::Registry(format!("GitHub OIDC fetch failed: {e}")))?;

    if !response.status().is_success() {
        return Err(LpmError::Registry(format!(
            "GitHub OIDC fetch failed ({})",
            response.status()
        )));
    }

    if let Some(declared) = response.content_length()
        && declared > GITHUB_OIDC_MAX_BODY_BYTES
    {
        return Err(LpmError::Registry(format!(
            "GitHub OIDC response exceeds {} B cap (declared {declared} B)",
            GITHUB_OIDC_MAX_BODY_BYTES
        )));
    }

    let mut bytes = Vec::<u8>::with_capacity(8 * 1024);
    let mut stream = response.bytes_stream();
    use futures::StreamExt;
    while let Some(chunk) = stream.next().await {
        let chunk =
            chunk.map_err(|e| LpmError::Registry(format!("GitHub OIDC body read failed: {e}")))?;
        if bytes.len() as u64 + chunk.len() as u64 > GITHUB_OIDC_MAX_BODY_BYTES {
            return Err(LpmError::Registry(format!(
                "GitHub OIDC response exceeds {} B cap mid-stream",
                GITHUB_OIDC_MAX_BODY_BYTES
            )));
        }
        bytes.extend_from_slice(&chunk);
    }

    let body: serde_json::Value = serde_json::from_slice(&bytes)
        .map_err(|e| LpmError::Registry(format!("GitHub OIDC parse error: {e}")))?;

    body.get("value")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| LpmError::Registry("GitHub OIDC response missing 'value' field".into()))
}

fn github_runtime_signal_present() -> bool {
    std::env::var("ACTIONS_ID_TOKEN_REQUEST_URL").is_ok()
        && std::env::var("ACTIONS_ID_TOKEN_REQUEST_TOKEN").is_ok()
}

/// Diagnose a half-configured GitHub Actions runtime — exactly one of the two
/// runtime vars set. Returns a hint string when the asymmetry is present, or
/// `None` when the signal is fully present, fully absent, or the lone present
/// var is empty (which can't be distinguished from "not set" via `is_ok`,
/// but is unusual enough that the generic message is fine).
fn github_partial_runtime_hint() -> Option<&'static str> {
    let url = std::env::var("ACTIONS_ID_TOKEN_REQUEST_URL").is_ok();
    let token = std::env::var("ACTIONS_ID_TOKEN_REQUEST_TOKEN").is_ok();
    match (url, token) {
        (true, false) => Some(
            "Detected ACTIONS_ID_TOKEN_REQUEST_URL but ACTIONS_ID_TOKEN_REQUEST_TOKEN is missing — \
             the GitHub Actions runtime needs both. Add `permissions: id-token: write` to the job.",
        ),
        (false, true) => Some(
            "Detected ACTIONS_ID_TOKEN_REQUEST_TOKEN but ACTIONS_ID_TOKEN_REQUEST_URL is missing — \
             the GitHub Actions runtime needs both. Add `permissions: id-token: write` to the job.",
        ),
        _ => None,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// npm Trusted Publishing (audience: npm:registry.npmjs.org)
// ─────────────────────────────────────────────────────────────────────────────

pub const NPM_TRUSTED_PUBLISH_AUDIENCE: &str = "npm:registry.npmjs.org";

pub fn npm_trusted_publish_jwt_available() -> bool {
    std::env::var("NPM_ID_TOKEN").is_ok_and(|token| !token.trim().is_empty())
        || github_runtime_signal_present()
}

pub async fn resolve_npm_trusted_publish_jwt() -> Result<NpmTrustedPublishJwt, LpmError> {
    if let Ok(token) = std::env::var("NPM_ID_TOKEN")
        && !token.trim().is_empty()
    {
        return Ok(NpmTrustedPublishJwt {
            token,
            source: NpmTrustedPublishJwtSource::EnvNpmIdToken,
        });
    }
    if github_runtime_signal_present() {
        return Ok(NpmTrustedPublishJwt {
            token: fetch_github_runtime_jwt(NPM_TRUSTED_PUBLISH_AUDIENCE).await?,
            source: NpmTrustedPublishJwtSource::GitHubActions,
        });
    }

    let base = "no OIDC signal found for npm Trusted Publishing. Set NPM_ID_TOKEN \
                with audience `npm:registry.npmjs.org`, or run inside GitHub Actions \
                with `permissions: id-token: write`.";
    Err(LpmError::Registry(match github_partial_runtime_hint() {
        Some(hint) => format!("{base} {hint}"),
        None => base.to_string(),
    }))
}

// ─────────────────────────────────────────────────────────────────────────────
// Registry exchange (audience: https://lpm.dev)
// ─────────────────────────────────────────────────────────────────────────────

/// Cheap synchronous gate: does the environment carry any signal we could use
/// to attempt registry-side OIDC exchange?
///
/// True if `LPM_OIDC_TOKEN`, the GitHub Actions runtime vars, or the legacy
/// `LPM_GITLAB_OIDC_TOKEN` is present. Lets callers skip the exchange entirely
/// when there is nothing to try.
pub fn registry_exchange_jwt_available() -> bool {
    std::env::var("LPM_OIDC_TOKEN").is_ok()
        || github_runtime_signal_present()
        || std::env::var("LPM_GITLAB_OIDC_TOKEN").is_ok()
}

/// Resolve a JWT for registry-side OIDC exchange (audience `https://lpm.dev`).
///
/// Precedence:
/// 1. `LPM_OIDC_TOKEN` — canonical pre-supplied bypass. Matches the
///    `id_tokens.LPM_OIDC_TOKEN` snippet emitted by `lpm ci setup gitlab`.
/// 2. GitHub Actions runtime — fetched fresh with audience `https://lpm.dev`.
/// 3. `LPM_GITLAB_OIDC_TOKEN` — legacy alias kept for back-compat.
///
/// The bypass wins over the GitHub runtime so self-hosted runners that mirror
/// GitHub's env vars but supply their own JWT can opt out of the runtime fetch
/// by setting `LPM_OIDC_TOKEN` explicitly.
pub async fn resolve_registry_exchange_jwt() -> Result<String, LpmError> {
    if let Ok(token) = std::env::var("LPM_OIDC_TOKEN") {
        return Ok(token);
    }
    if github_runtime_signal_present() {
        return fetch_github_runtime_jwt("https://lpm.dev").await;
    }
    if let Ok(token) = std::env::var("LPM_GITLAB_OIDC_TOKEN") {
        return Ok(token);
    }
    let base = "no OIDC signal found for registry exchange. Set LPM_OIDC_TOKEN \
                (canonical) or run inside GitHub Actions with `permissions: id-token: write`. \
                GitLab CI: mint LPM_OIDC_TOKEN via `id_tokens` with `aud: https://lpm.dev`.";
    Err(LpmError::Registry(match github_partial_runtime_hint() {
        Some(hint) => format!("{base} {hint}"),
        None => base.to_string(),
    }))
}

/// Exchange a CI OIDC token for an LPM session token.
pub async fn exchange_oidc_token(
    registry_url: &str,
    package_name: Option<&str>,
    scope: &str,
) -> Result<OidcToken, LpmError> {
    let jwt = resolve_registry_exchange_jwt().await?;

    let url = format!("{}/api/registry/-/token/oidc?scope={}", registry_url, scope);
    let mut body = serde_json::json!({ "token": jwt });
    if let Some(pkg) = package_name {
        body["package"] = serde_json::json!(pkg);
    }

    let response = reqwest::Client::new()
        .post(&url)
        .json(&body)
        .send()
        .await
        .map_err(|e| LpmError::Registry(format!("OIDC exchange failed: {e}")))?;

    if !response.status().is_success() {
        let status = response.status();
        let text = response
            .text()
            .await
            .unwrap_or_else(|_| "unknown".to_string());
        return Err(LpmError::Registry(format!(
            "OIDC exchange failed ({status}): {text}"
        )));
    }

    let result: serde_json::Value = response
        .json()
        .await
        .map_err(|e| LpmError::Registry(format!("OIDC response parse error: {e}")))?;

    let token = result
        .get("token")
        .and_then(|v| v.as_str())
        .ok_or_else(|| LpmError::Registry("OIDC response missing token".into()))?
        .to_string();

    Ok(OidcToken { token })
}

// ─────────────────────────────────────────────────────────────────────────────
// Provenance (audience: sigstore)
// ─────────────────────────────────────────────────────────────────────────────

/// Resolve the provider tag and a Sigstore-audience JWT for `lpm publish --provenance`.
///
/// GitHub Actions: fetches a fresh runtime JWT with audience `sigstore`.
/// GitLab CI: accepts `SIGSTORE_ID_TOKEN` (canonical, minted via `id_tokens`
/// with `aud: sigstore`) or `LPM_GITLAB_OIDC_TOKEN` (legacy alias).
///
/// `LPM_OIDC_TOKEN` is intentionally NOT honored here: its audience is
/// `https://lpm.dev`, which Fulcio rejects.
pub async fn resolve_provenance_jwt() -> Result<(CiEnvironment, String), LpmError> {
    if github_runtime_signal_present() {
        let jwt = fetch_github_runtime_jwt("sigstore").await?;
        return Ok((CiEnvironment::GitHubActions, jwt));
    }
    if let Ok(jwt) = std::env::var("SIGSTORE_ID_TOKEN") {
        return Ok((CiEnvironment::GitLabCI, jwt));
    }
    if let Ok(jwt) = std::env::var("LPM_GITLAB_OIDC_TOKEN") {
        return Ok((CiEnvironment::GitLabCI, jwt));
    }
    let base = "--provenance requires a CI environment with a Sigstore-audience OIDC token. \
                GitHub Actions: enable `permissions: id-token: write`. \
                GitLab CI: mint SIGSTORE_ID_TOKEN via `id_tokens` with `aud: sigstore`.";
    Err(LpmError::Registry(match github_partial_runtime_hint() {
        Some(hint) => format!("{base} {hint}"),
        None => base.to_string(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_env::ScopedEnv;
    use std::ffi::OsString;

    /// Env vars we touch across these tests. Cleared at the start of each scope
    /// so leftover state from the surrounding shell can't leak in.
    const ALL_VARS: &[&str] = &[
        "LPM_OIDC_TOKEN",
        "LPM_GITLAB_OIDC_TOKEN",
        "NPM_ID_TOKEN",
        "SIGSTORE_ID_TOKEN",
        "ACTIONS_ID_TOKEN_REQUEST_URL",
        "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
        "GITLAB_CI",
        "CI_JOB_JWT_V2",
    ];

    fn scoped(set: &[(&'static str, &str)]) -> ScopedEnv {
        let pairs: Vec<(&'static str, Option<OsString>)> = ALL_VARS
            .iter()
            .map(|k| (*k, None))
            .chain(set.iter().map(|(k, v)| (*k, Some(OsString::from(*v)))))
            .collect();
        ScopedEnv::update(pairs)
    }

    // ─── registry_exchange_jwt_available ─────────────────────────────────

    #[test]
    fn registry_signal_lpm_oidc_token() {
        let _e = scoped(&[("LPM_OIDC_TOKEN", "jwt")]);
        assert!(registry_exchange_jwt_available());
    }

    #[test]
    fn registry_signal_github_runtime() {
        let _e = scoped(&[
            ("ACTIONS_ID_TOKEN_REQUEST_URL", "https://example.com"),
            ("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "tok"),
        ]);
        assert!(registry_exchange_jwt_available());
    }

    #[test]
    fn registry_signal_legacy_gitlab() {
        let _e = scoped(&[("LPM_GITLAB_OIDC_TOKEN", "jwt")]);
        assert!(registry_exchange_jwt_available());
    }

    #[test]
    fn registry_signal_none() {
        let _e = scoped(&[]);
        assert!(!registry_exchange_jwt_available());
    }

    #[test]
    fn registry_signal_does_not_count_ci_job_jwt_v2() {
        // CI_JOB_JWT_V2 has the wrong audience for the LPM origin verifier;
        // it must not silently pass the gate.
        let _e = scoped(&[("CI_JOB_JWT_V2", "some-token"), ("GITLAB_CI", "true")]);
        assert!(!registry_exchange_jwt_available());
    }

    // ─── resolve_registry_exchange_jwt ───────────────────────────────────

    #[tokio::test]
    async fn resolve_registry_bypass_returns_lpm_oidc_token_verbatim() {
        let _e = scoped(&[("LPM_OIDC_TOKEN", "supplied-jwt")]);
        let jwt = resolve_registry_exchange_jwt().await.unwrap();
        assert_eq!(jwt, "supplied-jwt");
    }

    #[tokio::test]
    async fn resolve_registry_bypass_wins_over_github_runtime() {
        // If both are set, the explicit bypass wins — self-hosted runners that
        // mirror GH env vars but supply their own JWT must be able to opt out
        // of the runtime fetch.
        let _e = scoped(&[
            ("LPM_OIDC_TOKEN", "supplied-jwt"),
            // Bogus URL — would fail if we actually tried to fetch.
            ("ACTIONS_ID_TOKEN_REQUEST_URL", "http://127.0.0.1:1/"),
            ("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "tok"),
        ]);
        let jwt = resolve_registry_exchange_jwt().await.unwrap();
        assert_eq!(jwt, "supplied-jwt");
    }

    #[tokio::test]
    async fn resolve_registry_legacy_gitlab_alias() {
        let _e = scoped(&[("LPM_GITLAB_OIDC_TOKEN", "legacy-jwt")]);
        let jwt = resolve_registry_exchange_jwt().await.unwrap();
        assert_eq!(jwt, "legacy-jwt");
    }

    #[tokio::test]
    async fn resolve_registry_no_signals_errors_with_named_vars() {
        let _e = scoped(&[]);
        let err = resolve_registry_exchange_jwt().await.unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("LPM_OIDC_TOKEN"),
            "error must name LPM_OIDC_TOKEN: {msg}"
        );
        assert!(
            msg.contains("GitHub Actions"),
            "error must name GitHub Actions: {msg}"
        );
        assert!(
            msg.contains("aud: https://lpm.dev"),
            "error must document the GitLab audience: {msg}"
        );
    }

    // ─── npm Trusted Publishing ─────────────────────────────────────────

    #[test]
    fn npm_trusted_publish_signal_uses_npm_id_token() {
        let _e = scoped(&[("NPM_ID_TOKEN", "npm-jwt")]);
        assert!(npm_trusted_publish_jwt_available());
    }

    #[test]
    fn npm_trusted_publish_signal_ignores_lpm_oidc_tokens() {
        let _e = scoped(&[
            ("LPM_OIDC_TOKEN", "lpm-jwt"),
            ("LPM_GITLAB_OIDC_TOKEN", "legacy-lpm-jwt"),
            ("SIGSTORE_ID_TOKEN", "sigstore-jwt"),
        ]);
        assert!(!npm_trusted_publish_jwt_available());
    }

    #[tokio::test]
    async fn resolve_npm_trusted_publish_env_token_wins_over_github_runtime() {
        let _e = scoped(&[
            ("NPM_ID_TOKEN", "npm-id-token"),
            ("ACTIONS_ID_TOKEN_REQUEST_URL", "http://127.0.0.1:1/oidc"),
            ("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "github-runtime-token"),
        ]);
        let jwt = resolve_npm_trusted_publish_jwt().await.unwrap();
        assert_eq!(jwt.token, "npm-id-token");
        assert_eq!(jwt.source, NpmTrustedPublishJwtSource::EnvNpmIdToken);
    }

    #[tokio::test]
    async fn resolve_npm_trusted_publish_no_signals_errors_with_audience() {
        let _e = scoped(&[]);
        let err = resolve_npm_trusted_publish_jwt().await.unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("NPM_ID_TOKEN"),
            "error must name NPM_ID_TOKEN: {msg}"
        );
        assert!(
            msg.contains("npm:registry.npmjs.org"),
            "error must document npm audience: {msg}"
        );
    }

    // ─── resolve_provenance_jwt ──────────────────────────────────────────

    #[tokio::test]
    async fn resolve_provenance_lpm_oidc_token_does_not_trigger() {
        // LPM_OIDC_TOKEN must NOT drive provenance — wrong audience for Fulcio.
        let _e = scoped(&[("LPM_OIDC_TOKEN", "registry-jwt")]);
        let err = resolve_provenance_jwt().await.unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("--provenance"),
            "error must mention --provenance: {msg}"
        );
        assert!(
            msg.contains("SIGSTORE_ID_TOKEN"),
            "error must name SIGSTORE_ID_TOKEN: {msg}"
        );
    }

    #[tokio::test]
    async fn resolve_provenance_gitlab_sigstore_id_token() {
        let _e = scoped(&[("SIGSTORE_ID_TOKEN", "sigstore-jwt")]);
        let (ci, jwt) = resolve_provenance_jwt().await.unwrap();
        assert_eq!(ci, CiEnvironment::GitLabCI);
        assert_eq!(jwt, "sigstore-jwt");
    }

    #[tokio::test]
    async fn resolve_provenance_gitlab_legacy_alias() {
        let _e = scoped(&[("LPM_GITLAB_OIDC_TOKEN", "legacy-jwt")]);
        let (ci, jwt) = resolve_provenance_jwt().await.unwrap();
        assert_eq!(ci, CiEnvironment::GitLabCI);
        assert_eq!(jwt, "legacy-jwt");
    }

    #[tokio::test]
    async fn resolve_provenance_sigstore_token_wins_over_legacy() {
        let _e = scoped(&[
            ("SIGSTORE_ID_TOKEN", "sigstore-jwt"),
            ("LPM_GITLAB_OIDC_TOKEN", "legacy-jwt"),
        ]);
        let (_, jwt) = resolve_provenance_jwt().await.unwrap();
        assert_eq!(jwt, "sigstore-jwt");
    }

    #[tokio::test]
    async fn resolve_provenance_no_signals_errors() {
        let _e = scoped(&[]);
        let err = resolve_provenance_jwt().await.unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("--provenance"));
        assert!(msg.contains("SIGSTORE_ID_TOKEN"));
        assert!(msg.contains("GitHub Actions"));
        assert!(msg.contains("aud: sigstore"));
    }

    // ─── partial-signal diagnostics ──────────────────────────────────────

    #[tokio::test]
    async fn resolve_registry_partial_url_only_includes_named_var_hint() {
        let _e = scoped(&[("ACTIONS_ID_TOKEN_REQUEST_URL", "https://example/oidc")]);
        let err = resolve_registry_exchange_jwt().await.unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("ACTIONS_ID_TOKEN_REQUEST_TOKEN is missing"),
            "partial-signal hint must name the missing token var: {msg}"
        );
        assert!(
            msg.contains("permissions: id-token: write"),
            "hint must point at the workflow fix: {msg}"
        );
    }

    #[tokio::test]
    async fn resolve_registry_partial_token_only_includes_named_var_hint() {
        let _e = scoped(&[("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "tok")]);
        let err = resolve_registry_exchange_jwt().await.unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("ACTIONS_ID_TOKEN_REQUEST_URL is missing"),
            "partial-signal hint must name the missing URL var: {msg}"
        );
    }

    #[tokio::test]
    async fn resolve_provenance_partial_token_only_includes_named_var_hint() {
        let _e = scoped(&[("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "tok")]);
        let err = resolve_provenance_jwt().await.unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("--provenance"),
            "provenance error must lead with the flag: {msg}"
        );
        assert!(
            msg.contains("ACTIONS_ID_TOKEN_REQUEST_URL is missing"),
            "partial-signal hint must surface on provenance too: {msg}"
        );
    }

    #[tokio::test]
    async fn resolve_registry_no_partial_signal_no_hint() {
        // With zero GH vars, the partial hint must NOT appear.
        let _e = scoped(&[]);
        let err = resolve_registry_exchange_jwt().await.unwrap_err();
        let msg = format!("{err}");
        assert!(
            !msg.contains("Detected ACTIONS_ID_TOKEN_REQUEST"),
            "no partial signal should mean no partial hint: {msg}"
        );
    }

    #[tokio::test]
    async fn resolve_provenance_ignores_ci_job_jwt_v2() {
        let _e = scoped(&[
            ("CI_JOB_JWT_V2", "wrong-audience-jwt"),
            ("GITLAB_CI", "true"),
        ]);
        let err = resolve_provenance_jwt().await.unwrap_err();
        assert!(format!("{err}").contains("--provenance"));
    }

    // ─── M35: ACTIONS_ID_TOKEN_REQUEST_URL host/scheme gating ────────────

    #[test]
    fn github_runtime_url_accepts_canonical_https_host() {
        assert!(validate_github_runtime_url(
            "https://abc123.actions.githubusercontent.com/_apis/distributedtask/hubs/Actions/oidc/abc?api-version=2.0"
        ).is_ok());
        assert!(
            validate_github_runtime_url(
                "https://actions.githubusercontent.com/path?api-version=2.0"
            )
            .is_ok()
        );
    }

    #[test]
    fn github_runtime_url_accepts_https_non_canonical_for_ghes() {
        // GitHub Enterprise Server installations rewrite the URL host
        // to their appliance; we accept any HTTPS host with a warn.
        assert!(validate_github_runtime_url("https://ghes.corp.example/_apis/oidc/abc").is_ok());
    }

    #[test]
    fn github_runtime_url_rejects_plain_http_non_loopback() {
        let err = validate_github_runtime_url("http://attacker.example/_apis/oidc/abc")
            .expect_err("plain http non-loopback must refuse");
        let msg = format!("{err}");
        assert!(
            msg.contains("refused") && msg.contains("scheme=http"),
            "error must label the failure: {msg}"
        );
    }

    #[test]
    fn github_runtime_url_accepts_http_for_loopback() {
        // Workflow tests target a local mock — must still work.
        assert!(validate_github_runtime_url("http://127.0.0.1:8080/oidc").is_ok());
        assert!(validate_github_runtime_url("http://localhost:9090/oidc").is_ok());
        assert!(validate_github_runtime_url("http://[::1]:8080/oidc").is_ok());
    }

    #[test]
    fn github_runtime_url_rejects_other_schemes() {
        assert!(validate_github_runtime_url("ftp://example.com/oidc").is_err());
        assert!(validate_github_runtime_url("file:///etc/passwd").is_err());
        assert!(validate_github_runtime_url("javascript:alert(1)").is_err());
        assert!(validate_github_runtime_url("not a url").is_err());
    }
}
