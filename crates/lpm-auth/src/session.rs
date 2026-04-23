//! `SessionManager` — Phase 35 lazy auth orchestrator.
//!
//! `SessionManager` is constructed once at CLI startup with **no
//! network calls** (only local keychain / encrypted file reads). It
//! classifies the effective token by source and refreshes lazily, only
//! when an auth-required operation actually needs it, and only for
//! refresh-backed stored sessions.
//!
//! See `DOCS/new-features/37-rust-client-RUNNER-VISION-phase35-claude.md`
//! for the full design.

use lpm_common::LpmError;
use secrecy::{ExposeSecret, SecretString};
use std::sync::RwLock;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use tokio::sync::Mutex;

use crate::{
    clear_refresh_token, clear_token, get_refresh_token, get_token, set_refresh_token,
    set_session_access_token_expiry, set_token,
};

/// Where the current effective token came from.
///
/// Refresh eligibility, "session-required" semantics, and the user-facing
/// re-login message all depend on this. Classification is determined
/// once at `SessionManager::new` time and never changes for a given
/// process — a refresh rotates the secret value but the source stays
/// `StoredSession`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenSource {
    /// Provided via `--token <value>` on the command line.
    ExplicitFlag,
    /// Read from the `LPM_TOKEN` environment variable.
    EnvVar,
    /// Loaded from local storage with a refresh token alongside it.
    /// This is the only source eligible for silent refresh.
    StoredSession,
    /// Loaded from local storage without a refresh token (pre-Phase-35
    /// login, or a session whose refresh token was cleared). Cannot be
    /// silently refreshed.
    StoredLegacy,
    /// Issued by a CI / OIDC token exchange. Never refreshed.
    CiToken,
}

impl TokenSource {
    /// Whether this source can be silently refreshed when the access
    /// token expires.
    pub fn refresh_policy(self) -> RefreshPolicy {
        match self {
            TokenSource::StoredSession => RefreshPolicy::IfRefreshable,
            TokenSource::ExplicitFlag
            | TokenSource::EnvVar
            | TokenSource::StoredLegacy
            | TokenSource::CiToken => RefreshPolicy::Never,
        }
    }

    /// Whether this source satisfies a `SessionRequired` operation.
    pub fn is_session_backed(self) -> bool {
        matches!(self, TokenSource::StoredSession)
    }

    /// Short human-readable label for diagnostics.
    pub fn label(self) -> &'static str {
        match self {
            TokenSource::ExplicitFlag => "--token",
            TokenSource::EnvVar => "LPM_TOKEN",
            TokenSource::StoredSession => "stored session",
            TokenSource::StoredLegacy => "stored legacy token",
            TokenSource::CiToken => "CI token",
        }
    }
}

/// Refresh eligibility for a given token source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefreshPolicy {
    /// The source must never trigger a silent refresh on 401.
    Never,
    /// The source may be silently refreshed if a refresh token is
    /// available and the network call succeeds.
    IfRefreshable,
}

/// What a caller needs from `SessionManager::token_for`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthRequirement {
    /// Anonymous use is allowed. `token_for` returns `Ok(None)`.
    /// Callers on truly anonymous endpoints should not call
    /// `token_for` at all; this variant exists for endpoints that may
    /// optionally enrich a request when a token is naturally present.
    AnonymousAllowed,
    /// Any token is acceptable. Returns `Err(AuthRequired)` if no
    /// token is available.
    TokenRequired,
    /// Only a refresh-backed stored session satisfies this. Explicit /
    /// env / CI / legacy tokens fail with `SessionExpired`.
    SessionRequired,
}

/// Lazy session orchestrator — loaded once at startup, refreshed only
/// when an auth-required operation actually needs it.
pub struct SessionManager {
    registry_url: String,
    /// Effective token + its source. `RwLock` so concurrent readers
    /// don't block on the (rare) refresh path.
    cached: RwLock<Option<CachedToken>>,
    /// Phase 45 P2 — `true` once the keychain has been consulted (or
    /// skipped because env/flag already produced a token). Until this
    /// flips, reads that depend on the full classification must call
    /// [`Self::ensure_classified`] first. The full classification
    /// includes both the keychain and the refresh-only recovery
    /// placeholder. Eager reads intended only for the startup bridge
    /// path (`current_bearer_for_bridge`) surface whatever's already
    /// cached without forcing classification, so the ~50 ms macOS
    /// Keychain IPC round-trip never runs on commands that don't
    /// touch the network (warm `lpm install` being the canonical
    /// case).
    classified: AtomicBool,
    /// Serializes the keychain classification so two concurrent reads
    /// don't both fire the Keychain IPC. Short-held (only across the
    /// `classify_keychain_sources` body), so it doesn't serialize the
    /// hot paths after classification completes.
    classify_lock: std::sync::Mutex<()>,
    /// Bumped on every successful silent refresh. Concurrent
    /// `refresh_now` callers snapshot this BEFORE acquiring
    /// `refresh_lock`; if the counter advances while they wait, a
    /// peer rotated the token and they return the cached value
    /// without making a redundant HTTP call.
    refresh_generation: AtomicU64,
    /// Single-flight gate around the refresh HTTP call. The lock is
    /// held only across the network round-trip; readers stay on the
    /// `RwLock`.
    refresh_lock: Mutex<()>,
    /// HTTP client used for silent refresh. Constructed lazily on
    /// first refresh attempt (no startup cost when refresh never
    /// happens).
    http: tokio::sync::OnceCell<reqwest::Client>,
}

#[derive(Clone)]
struct CachedToken {
    secret: SecretString,
    source: TokenSource,
}

impl SessionManager {
    /// Build a session manager from a registry URL and any
    /// `--token <value>` flag passed on the command line. Reads
    /// `LPM_TOKEN` and stored session state from local sources only —
    /// no network calls.
    ///
    /// `explicit_flag_token` should be the value the user explicitly
    /// passed via `--token`, *not* including the env-var fallback.
    /// SessionManager itself reads `LPM_TOKEN` so that the source can
    /// be classified correctly.
    pub fn new(registry_url: impl Into<String>, explicit_flag_token: Option<String>) -> Self {
        let registry_url = registry_url.into();
        // Phase 45 P2 — eager classification is limited to env/flag.
        // Keychain reads are deferred to `ensure_classified`, called on
        // the first method that actually needs the cached value. On
        // macOS the keychain IPC costs ~50 ms; skipping it on commands
        // that never touch the network (warm `lpm install` from cache,
        // offline lookups, read-only queries) is pure win.
        let eager = classify_eager_sources(explicit_flag_token);
        let classified = AtomicBool::new(eager.is_some());
        Self {
            registry_url,
            cached: RwLock::new(eager),
            classified,
            classify_lock: std::sync::Mutex::new(()),
            refresh_generation: AtomicU64::new(0),
            refresh_lock: Mutex::new(()),
            http: tokio::sync::OnceCell::new(),
        }
    }

    /// Phase 45 P2 — resolve the keychain portion of the classification
    /// if it hasn't run yet. Idempotent; all but the first call are
    /// atomic-load-only. Safe to call from either blocking or async
    /// contexts: the keychain IPC itself is synchronous blocking on
    /// macOS (subprocess to `/usr/bin/security` in the fallback path)
    /// which is the cost we're amortizing away from startup — running
    /// it here instead of at `new()` ensures it fires at most once, and
    /// only when a read actually depends on the answer.
    fn ensure_classified(&self) {
        if self.classified.load(Ordering::Acquire) {
            return;
        }
        // Serialize the actual keychain call so parallel readers don't
        // both spawn the `security` subprocess. Short-held.
        let _guard = self.classify_lock.lock().unwrap_or_else(|e| e.into_inner());
        if self.classified.load(Ordering::Acquire) {
            return; // peer finished while we waited.
        }
        if let Some(resolved) = classify_keychain_sources(&self.registry_url)
            && let Ok(mut guard) = self.cached.write()
        {
            *guard = Some(resolved);
        }
        self.classified.store(true, Ordering::Release);
    }

    /// The registry URL this session is bound to.
    pub fn registry_url(&self) -> &str {
        &self.registry_url
    }

    /// Returns the source of the currently cached token, if any.
    /// Useful for diagnostics and dispatch logic that needs to know
    /// e.g. whether to allow `tunnel start`.
    ///
    /// Phase 45 P2 — triggers lazy keychain classification on first
    /// call. Callers that specifically want "cached-only, no work"
    /// semantics should use [`Self::current_source_peek`].
    pub fn current_source(&self) -> Option<TokenSource> {
        self.ensure_classified();
        self.cached
            .read()
            .ok()
            .and_then(|g| g.as_ref().map(|c| c.source))
    }

    /// Phase 45 P2 — cached-only variant of [`Self::current_source`].
    /// Returns whatever the eager classification produced without
    /// triggering the keychain IPC. Suitable for diagnostics or
    /// fast-lane checks where "not yet known" is an acceptable answer.
    pub fn current_source_peek(&self) -> Option<TokenSource> {
        self.cached
            .read()
            .ok()
            .and_then(|g| g.as_ref().map(|c| c.source))
    }

    /// Acquire a usable bearer for the given requirement.
    ///
    /// Designed for command sites that build their own HTTP client
    /// (env sync, swift registry login, tunnel handshake) and so do
    /// not benefit from `RegistryClient::execute_with_recovery`'s
    /// 401 → refresh → retry path. Encapsulates two things:
    ///
    /// 1. The `ExposeSecret` boundary, so command code stays free of
    ///    `secrecy` imports.
    /// 2. The refresh-only-state case (audit fix #1): if the cached
    ///    access token is empty but the source is refresh-eligible
    ///    (a `StoredSession` placeholder seeded from the on-disk
    ///    refresh token), this method performs one silent refresh
    ///    and returns the rotated bearer.
    ///
    /// Returns `LpmError::SessionExpired` for `SessionRequired` when
    /// the source isn't `StoredSession`; `LpmError::AuthRequired`
    /// for other unmet requirements.
    pub async fn bearer_string_for(
        &self,
        requirement: AuthRequirement,
    ) -> Result<String, LpmError> {
        // Fast path: cache hit + token still locally believed valid.
        //
        // GPT audit fix #1 (post-Step-5): pre-fix this path returned
        // any non-empty cached bearer immediately, including ones
        // we already knew were expired from local metadata. Command
        // sites that build their own HTTP client (env sync, swift
        // registry, tunnel handshake) do not get
        // `RegistryClient::execute_with_recovery`'s 401-retry, so a
        // known-stale bearer would surface as a hard auth failure
        // on the first call — exactly the regression Phase 35 was
        // supposed to avoid for stored sessions.
        //
        // Now: if the source is refresh-eligible AND
        // `is_session_access_token_expired` reports the local expiry
        // metadata says the token is already past its TTL, fall
        // through to the refresh path before returning.
        //
        // No-metadata case stays optimistic — the metadata is only
        // populated after a refresh, so a fresh login has no expiry
        // record and we trust the cache. The first 401 in that path
        // is handled by `execute_with_recovery` for `RegistryClient`
        // callers, and will surface as `AuthRequired` for the
        // self-built HTTP clients (which Phase 35 accepts as the
        // tail-case cost — the first stale-token call after the
        // expiry metadata gets recorded does the right thing).
        if let Ok(Some(secret)) = self.token_for(requirement).await {
            let needs_proactive_refresh = self
                .current_source()
                .map(|s| s.refresh_policy() == RefreshPolicy::IfRefreshable)
                .unwrap_or(false)
                && crate::is_session_access_token_expired(&self.registry_url);

            if !needs_proactive_refresh {
                return Ok(secret.expose_secret().to_string());
            }
            // Fall through to refresh path below.
        }

        // Refresh-only state OR known-expired access token: do the
        // silent exchange and return the rotated bearer.
        if let Some(source) = self.current_source()
            && source.refresh_policy() == RefreshPolicy::IfRefreshable
            && (requirement == AuthRequirement::TokenRequired
                || requirement == AuthRequirement::SessionRequired
                || requirement == AuthRequirement::AnonymousAllowed)
        {
            let rotated = self.refresh_now().await?;
            return Ok(rotated.expose_secret().to_string());
        }

        match requirement {
            AuthRequirement::SessionRequired => Err(LpmError::SessionExpired),
            _ => Err(LpmError::AuthRequired),
        }
    }

    /// **Step-3 transition bridge — do not introduce new callers.**
    /// Exposes the cached bearer as a plain `String` so `main.rs` can
    /// seed `RegistryClient::with_token` while Step 4 is still in
    /// flight. Step 4 plumbs the secret directly through the
    /// `AuthPosture`-aware request methods, at which point this method
    /// is removed.
    ///
    /// Phase 45 P2 — cached-only semantics: NEVER triggers keychain
    /// classification. When the eager path finds an env/flag token,
    /// this returns it; when it doesn't, this returns `None` and the
    /// caller leaves the legacy `with_token` bridge empty. The
    /// session-aware request path
    /// ([`Self::current_bearer_lazy`]) is the one that actually
    /// resolves the keychain at request time.
    pub fn current_bearer_for_bridge(&self) -> Option<String> {
        self.cached
            .read()
            .ok()
            .and_then(|g| g.as_ref().map(|c| c.secret.expose_secret().to_string()))
            .filter(|s| !s.is_empty())
    }

    /// Phase 45 P2 — resolve the bearer at actual request time,
    /// triggering the keychain IPC on first call if necessary.
    ///
    /// Used by `RegistryClient::current_bearer` to get the live
    /// bearer without paying keychain cost at startup. Returns `None`
    /// if no token source is available (env, flag, or keychain).
    pub fn current_bearer_lazy(&self) -> Option<String> {
        self.ensure_classified();
        self.cached
            .read()
            .ok()
            .and_then(|g| g.as_ref().map(|c| c.secret.expose_secret().to_string()))
            .filter(|s| !s.is_empty())
    }

    /// Whether a non-empty token is currently cached.
    ///
    /// Phase 45 P2 — triggers lazy keychain classification. Callers
    /// that need the "is it available right now, without touching
    /// the keychain" answer should use [`Self::has_token_peek`].
    pub fn has_token(&self) -> bool {
        self.ensure_classified();
        self.cached
            .read()
            .ok()
            .and_then(|g| g.as_ref().map(|c| !c.secret.expose_secret().is_empty()))
            .unwrap_or(false)
    }

    /// Phase 45 P2 — cached-only variant of [`Self::has_token`].
    /// Returns whether a non-empty token is in the cache *right now*
    /// without triggering keychain classification.
    pub fn has_token_peek(&self) -> bool {
        self.cached
            .read()
            .ok()
            .and_then(|g| g.as_ref().map(|c| !c.secret.expose_secret().is_empty()))
            .unwrap_or(false)
    }

    /// Resolve the appropriate token for a given requirement.
    ///
    /// **Never returns `Some("")`** — an empty token is reported as
    /// `Ok(None)` for `AnonymousAllowed` or as `Err(AuthRequired)` for
    /// `TokenRequired` / `SessionRequired`. This makes it impossible
    /// to send `Authorization: Bearer ` (empty bearer) headers.
    pub async fn token_for(
        &self,
        requirement: AuthRequirement,
    ) -> Result<Option<SecretString>, LpmError> {
        // Phase 45 P2 — token_for is the canonical "I need a bearer
        // to make a request" entry point, so this is where deferred
        // keychain classification fires. First call pays the macOS
        // Keychain IPC; subsequent calls are cache hits.
        self.ensure_classified();
        let cached = self.cached.read().ok().and_then(|g| g.clone());

        match requirement {
            AuthRequirement::AnonymousAllowed => Ok(cached.and_then(non_empty)),
            AuthRequirement::TokenRequired => match cached.and_then(non_empty) {
                Some(secret) => Ok(Some(secret)),
                None => Err(LpmError::AuthRequired),
            },
            AuthRequirement::SessionRequired => match cached.and_then(session_only) {
                Some(secret) => Ok(Some(secret)),
                None => Err(LpmError::SessionExpired),
            },
        }
    }

    /// Force a silent refresh of the access token using the stored
    /// refresh token. Single-flight: concurrent callers wait on the
    /// same network round-trip and observe the rotated token.
    ///
    /// Returns the rotated access token on success. Returns
    /// `LpmError::SessionExpired` if the cached source is not
    /// refreshable, the refresh token is missing, or the server
    /// rejects the refresh.
    pub async fn refresh_now(&self) -> Result<SecretString, LpmError> {
        // Source must be refresh-eligible.
        let source = self.current_source().ok_or(LpmError::SessionExpired)?;
        if source.refresh_policy() != RefreshPolicy::IfRefreshable {
            return Err(LpmError::SessionExpired);
        }

        // Snapshot the rotation generation BEFORE taking the lock.
        // If it advances while we wait, a peer rotated for us and we
        // can return their result without an extra HTTP call.
        let gen_before = self.refresh_generation.load(Ordering::Acquire);

        // Single-flight: serialize concurrent refresh attempts.
        let _guard = self.refresh_lock.lock().await;

        if self.refresh_generation.load(Ordering::Acquire) != gen_before
            && let Some(cached) = self.cached.read().ok().and_then(|g| g.clone())
            && cached.source.refresh_policy() == RefreshPolicy::IfRefreshable
            && !cached.secret.expose_secret().is_empty()
        {
            return Ok(cached.secret);
        }

        let new_token = self.do_silent_refresh().await?;
        let secret = SecretString::from(new_token.clone());

        // Persist + cache the rotated token. The source stays
        // StoredSession — refresh rotates the secret, not the source.
        if let Err(e) = set_token(&self.registry_url, &new_token) {
            tracing::warn!(
                "refreshed token obtained but failed to persist: {e}. Session may require re-login."
            );
        }
        if let Ok(mut guard) = self.cached.write() {
            *guard = Some(CachedToken {
                secret: secret.clone(),
                source: TokenSource::StoredSession,
            });
        }
        self.refresh_generation.fetch_add(1, Ordering::AcqRel);

        Ok(secret)
    }

    /// Clear the local stored session state (access + refresh + expiry
    /// metadata) and drop the in-memory cache. Used when the server
    /// authoritatively rejects the session.
    pub fn clear_session(&self) {
        let _ = clear_token(&self.registry_url);
        clear_refresh_token(&self.registry_url);
        if let Ok(mut guard) = self.cached.write() {
            *guard = None;
        }
    }

    /// Perform the HTTP silent-refresh round-trip. Called inside the
    /// single-flight lock; never called directly from outside.
    async fn do_silent_refresh(&self) -> Result<String, LpmError> {
        let refresh_token =
            get_refresh_token(&self.registry_url).ok_or(LpmError::SessionExpired)?;

        let device_fingerprint = compute_device_fingerprint();
        let refresh_url = format!("{}/api/cli/refresh", self.registry_url);

        let http = self
            .http
            .get_or_try_init(|| async {
                reqwest::Client::builder()
                    .timeout(std::time::Duration::from_secs(10))
                    .build()
                    .map_err(|e| LpmError::Network(format!("refresh client init: {e}")))
            })
            .await?;

        let resp = http
            .post(&refresh_url)
            .json(&serde_json::json!({
                "refreshToken": refresh_token,
                "deviceFingerprint": device_fingerprint,
            }))
            .send()
            .await
            .map_err(|e| LpmError::Network(format!("silent refresh: {e}")))?;

        if !resp.status().is_success() {
            tracing::debug!("silent refresh failed: {}", resp.status());
            // Phase 35 audit fix #2.
            //
            // 401 = refresh token authoritatively rejected
            // (revoked / replay-killed / 90-day inactivity cleanup).
            // We must wipe ALL local session state — access token,
            // refresh token, expiry metadata, and the in-memory
            // cache — otherwise the dead access token stays cached
            // and every subsequent command keeps replaying it,
            // each one re-entering this same failure loop.
            //
            // Pre-fix the code only cleared the refresh token, so a
            // user with a revoked session would keep sending the
            // dead bearer until manual `lpm logout`.
            //
            // 5xx and network errors are transient — keep state
            // intact so the next attempt can recover.
            if resp.status() == reqwest::StatusCode::UNAUTHORIZED {
                self.clear_session();
            }
            return Err(LpmError::SessionExpired);
        }

        let data: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| LpmError::Registry(format!("refresh response parse: {e}")))?;

        let new_token = data["token"]
            .as_str()
            .ok_or_else(|| LpmError::Registry("refresh response missing token".into()))?
            .to_string();

        if let Some(rt) = data["refreshToken"].as_str() {
            set_refresh_token(&self.registry_url, rt);
        }
        if let Some(ea) = data["expiresAt"].as_str() {
            set_session_access_token_expiry(&self.registry_url, ea);
        }

        Ok(new_token)
    }
}

/// Phase 45 P2 — eager classification: env var + explicit `--token`
/// flag only. These sources are free (memory reads), so there's no
/// reason to defer them. Keychain reads live in
/// [`classify_keychain_sources`] behind the lazy gate.
///
/// Returns `Some(...)` iff one of the eager sources is populated.
fn classify_eager_sources(explicit_flag_token: Option<String>) -> Option<CachedToken> {
    if let Some(tok) = explicit_flag_token.filter(|t| !t.is_empty()) {
        return Some(CachedToken {
            secret: SecretString::from(tok),
            source: TokenSource::ExplicitFlag,
        });
    }

    if let Ok(tok) = std::env::var("LPM_TOKEN")
        && !tok.is_empty()
    {
        let source = if is_ci_token_env() {
            TokenSource::CiToken
        } else {
            TokenSource::EnvVar
        };
        return Some(CachedToken {
            secret: SecretString::from(tok),
            source,
        });
    }

    None
}

/// Phase 45 P2 — deferred keychain classification. Runs at most once
/// per `SessionManager`, gated by `classified` + `classify_lock` in
/// `ensure_classified`. Performs the macOS Keychain IPC (or its
/// equivalent on Linux / Windows) which is the ~50 ms per-command
/// tax we're amortizing away from startup.
///
/// Preserves the refresh-only recovery placeholder from the original
/// `classify_initial_token` — if only a refresh token is present
/// (access token wiped, keychain reset, etc.), we seed an empty
/// `StoredSession` placeholder so `refresh_now` can rotate it on the
/// next auth-required request.
fn classify_keychain_sources(registry_url: &str) -> Option<CachedToken> {
    if let Some(tok) = get_token(registry_url).filter(|t| !t.is_empty()) {
        let source = if get_refresh_token(registry_url).is_some() {
            TokenSource::StoredSession
        } else {
            TokenSource::StoredLegacy
        };
        return Some(CachedToken {
            secret: SecretString::from(tok),
            source,
        });
    }

    // Phase 35 audit fix #1: refresh-token-only recovery.
    //
    // Pre-Phase-35, `main.rs` had an explicit branch that called
    // `try_silent_refresh` when the access token was missing but a
    // refresh token was present, so a still-valid stored session
    // could self-heal. Without this branch, a user whose access
    // token was wiped (keychain reset, store corruption, manual
    // edit) but whose refresh token survives would be unable to
    // recover — `current_source()` would be `None` and `refresh_now`
    // would short-circuit to `SessionExpired`.
    //
    // Restore that path lazily: if there's a refresh token, seed the
    // cache with an *empty* `StoredSession` placeholder. The first
    // auth-required request hits 401 (no bearer attached because
    // `current_bearer` filters empty), `execute_with_recovery` sees
    // an `IfRefreshable` source and calls `refresh_now`, which reads
    // the refresh token from disk and exchanges it. The retry then
    // attaches the rotated access token.
    if get_refresh_token(registry_url).is_some() {
        return Some(CachedToken {
            secret: SecretString::from(String::new()),
            source: TokenSource::StoredSession,
        });
    }

    None
}

/// Heuristic: a token in `LPM_TOKEN` was minted by CI when the
/// surrounding environment looks like a CI runner with an OIDC issuer.
/// Conservative — only flips to `CiToken` for known CI OIDC contexts;
/// otherwise stays `EnvVar` so the table-driven refresh policy is the
/// same (`Never`).
fn is_ci_token_env() -> bool {
    let ci = std::env::var("CI")
        .ok()
        .is_some_and(|v| v == "true" || v == "1");
    let has_oidc = std::env::var("ACTIONS_ID_TOKEN_REQUEST_TOKEN").is_ok()
        || std::env::var("CI_JOB_JWT_V2").is_ok()
        || std::env::var("BITBUCKET_STEP_OIDC_TOKEN").is_ok();
    ci && has_oidc
}

/// Same fingerprint shape as the legacy `try_silent_refresh` so the
/// server treats refreshes from this client as continuous with prior
/// logins.
fn compute_device_fingerprint() -> String {
    use sha2::{Digest, Sha256};
    let hostname = std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .unwrap_or_else(|_| "unknown".to_string());
    let username = std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "unknown".to_string());
    hex::encode(Sha256::digest(
        format!("{hostname}:{username}:lpm-cli").as_bytes(),
    ))
}

/// Drop tokens whose secret value is the empty string. Empty bearer
/// headers are worse than no header at all — `token_for` must never
/// surface them.
fn non_empty(c: CachedToken) -> Option<SecretString> {
    if c.secret.expose_secret().is_empty() {
        None
    } else {
        Some(c.secret)
    }
}

/// Filter `non_empty` plus `source.is_session_backed()`.
fn session_only(c: CachedToken) -> Option<SecretString> {
    if c.source.is_session_backed() && !c.secret.expose_secret().is_empty() {
        Some(c.secret)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refresh_policy_table() {
        assert_eq!(
            TokenSource::ExplicitFlag.refresh_policy(),
            RefreshPolicy::Never
        );
        assert_eq!(TokenSource::EnvVar.refresh_policy(), RefreshPolicy::Never);
        assert_eq!(TokenSource::CiToken.refresh_policy(), RefreshPolicy::Never);
        assert_eq!(
            TokenSource::StoredLegacy.refresh_policy(),
            RefreshPolicy::Never
        );
        assert_eq!(
            TokenSource::StoredSession.refresh_policy(),
            RefreshPolicy::IfRefreshable
        );
    }

    #[test]
    fn session_backed_table() {
        assert!(TokenSource::StoredSession.is_session_backed());
        assert!(!TokenSource::ExplicitFlag.is_session_backed());
        assert!(!TokenSource::EnvVar.is_session_backed());
        assert!(!TokenSource::StoredLegacy.is_session_backed());
        assert!(!TokenSource::CiToken.is_session_backed());
    }

    /// Build a SessionManager directly from a `CachedToken` for tests
    /// that don't want to touch the keychain or env. Bypasses
    /// `classify_initial_token` so each test can pick its source.
    fn manager_with(source: TokenSource, token: &str) -> SessionManager {
        // Phase 45 P2 — tests set classified=true so ensure_classified
        // short-circuits and the pre-seeded `cached` value stands.
        SessionManager {
            registry_url: "https://example.invalid".into(),
            cached: RwLock::new(Some(CachedToken {
                secret: SecretString::from(token.to_string()),
                source,
            })),
            classified: AtomicBool::new(true),
            classify_lock: std::sync::Mutex::new(()),
            refresh_generation: AtomicU64::new(0),
            refresh_lock: Mutex::new(()),
            http: tokio::sync::OnceCell::new(),
        }
    }

    fn manager_empty() -> SessionManager {
        SessionManager {
            registry_url: "https://example.invalid".into(),
            cached: RwLock::new(None),
            classified: AtomicBool::new(true),
            classify_lock: std::sync::Mutex::new(()),
            refresh_generation: AtomicU64::new(0),
            refresh_lock: Mutex::new(()),
            http: tokio::sync::OnceCell::new(),
        }
    }

    #[tokio::test]
    async fn anonymous_allowed_returns_none_when_empty() {
        let mgr = manager_empty();
        let res = mgr.token_for(AuthRequirement::AnonymousAllowed).await;
        assert!(matches!(res, Ok(None)));
    }

    #[tokio::test]
    async fn token_required_errs_when_empty() {
        let mgr = manager_empty();
        let res = mgr.token_for(AuthRequirement::TokenRequired).await;
        assert!(matches!(res, Err(LpmError::AuthRequired)));
    }

    #[tokio::test]
    async fn session_required_errs_for_explicit_flag() {
        let mgr = manager_with(TokenSource::ExplicitFlag, "explicit-tok");
        let res = mgr.token_for(AuthRequirement::SessionRequired).await;
        assert!(matches!(res, Err(LpmError::SessionExpired)));
    }

    #[tokio::test]
    async fn session_required_errs_for_env_var() {
        let mgr = manager_with(TokenSource::EnvVar, "env-tok");
        let res = mgr.token_for(AuthRequirement::SessionRequired).await;
        assert!(matches!(res, Err(LpmError::SessionExpired)));
    }

    #[tokio::test]
    async fn session_required_errs_for_legacy() {
        let mgr = manager_with(TokenSource::StoredLegacy, "legacy-tok");
        let res = mgr.token_for(AuthRequirement::SessionRequired).await;
        assert!(matches!(res, Err(LpmError::SessionExpired)));
    }

    #[tokio::test]
    async fn session_required_errs_for_ci_token() {
        let mgr = manager_with(TokenSource::CiToken, "ci-tok");
        let res = mgr.token_for(AuthRequirement::SessionRequired).await;
        assert!(matches!(res, Err(LpmError::SessionExpired)));
    }

    #[tokio::test]
    async fn session_required_ok_for_stored_session() {
        let mgr = manager_with(TokenSource::StoredSession, "session-tok");
        let res = mgr.token_for(AuthRequirement::SessionRequired).await;
        let secret = res.expect("session source should satisfy SessionRequired");
        assert_eq!(secret.unwrap().expose_secret(), "session-tok");
    }

    #[tokio::test]
    async fn token_required_ok_for_any_source() {
        for source in [
            TokenSource::ExplicitFlag,
            TokenSource::EnvVar,
            TokenSource::StoredSession,
            TokenSource::StoredLegacy,
            TokenSource::CiToken,
        ] {
            let mgr = manager_with(source, "tok");
            let res = mgr.token_for(AuthRequirement::TokenRequired).await;
            let secret = res.expect("any source satisfies TokenRequired");
            assert_eq!(secret.unwrap().expose_secret(), "tok");
        }
    }

    #[tokio::test]
    async fn empty_token_value_yields_none_or_auth_required() {
        // Empty tokens must never surface as Some("") — the cached
        // value is filtered. Build a manager with an empty secret
        // through the public constructor by simulating an env source.
        let mgr = manager_with(TokenSource::EnvVar, "");

        assert!(matches!(
            mgr.token_for(AuthRequirement::AnonymousAllowed).await,
            Ok(None)
        ));
        assert!(matches!(
            mgr.token_for(AuthRequirement::TokenRequired).await,
            Err(LpmError::AuthRequired)
        ));
        assert!(matches!(
            mgr.token_for(AuthRequirement::SessionRequired).await,
            Err(LpmError::SessionExpired)
        ));
    }

    #[tokio::test]
    async fn refresh_rejects_non_session_sources() {
        for source in [
            TokenSource::ExplicitFlag,
            TokenSource::EnvVar,
            TokenSource::CiToken,
            TokenSource::StoredLegacy,
        ] {
            let mgr = manager_with(source, "tok");
            let res = mgr.refresh_now().await;
            assert!(
                matches!(res, Err(LpmError::SessionExpired)),
                "refresh_now must refuse {source:?}"
            );
        }
    }

    #[tokio::test]
    async fn refresh_rejects_when_no_cached_token() {
        let mgr = manager_empty();
        assert!(matches!(
            mgr.refresh_now().await,
            Err(LpmError::SessionExpired)
        ));
    }

    #[test]
    fn current_source_observable() {
        let mgr = manager_with(TokenSource::StoredSession, "tok");
        assert_eq!(mgr.current_source(), Some(TokenSource::StoredSession));

        let empty = manager_empty();
        assert_eq!(empty.current_source(), None);
    }

    #[test]
    fn has_token_reflects_cache() {
        assert!(manager_with(TokenSource::StoredSession, "tok").has_token());
        assert!(!manager_with(TokenSource::EnvVar, "").has_token());
        assert!(!manager_empty().has_token());
    }

    /// Phase 45 P2 — lazy keychain classification.
    ///
    /// When `SessionManager::new` is called with no explicit token and
    /// no `LPM_TOKEN` env var, the eager path returns `None` and the
    /// classification bit stays `false`. `current_bearer_for_bridge`
    /// (the startup-only peek) must NOT trigger keychain
    /// classification; callers that need the answer for an actual
    /// request (e.g. `current_bearer_lazy`, `has_token`, `token_for`)
    /// must.
    /// Build a scoped env that makes the keychain path a safe no-op:
    /// LPM_FORCE_FILE_AUTH=1 causes `get_token` / `get_refresh_token`
    /// to skip the keychain, and an isolated HOME keeps file-auth
    /// writes off the host. Mirrors `refresh_http_tests::isolate_test_env`
    /// but lives in this module for use by the Phase 45 P2 tests.
    fn phase45_isolate() -> (tempfile::TempDir, crate::test_env::ScopedEnv) {
        let tempdir = tempfile::tempdir().expect("create test home tempdir");
        let scoped = crate::test_env::ScopedEnv::set([
            ("HOME", tempdir.path().as_os_str().to_owned()),
            ("LPM_FORCE_FILE_AUTH", "1".into()),
            ("LPM_TEST_FAST_SCRYPT", "1".into()),
        ]);
        (tempdir, scoped)
    }

    #[test]
    fn phase45_p2_bridge_peek_does_not_classify() {
        let _env = phase45_isolate();
        let mgr = SessionManager::new("https://example.invalid", None);
        // Sanity: isolated env means no tokens anywhere, so the eager
        // classification returned None.
        assert_eq!(mgr.current_source_peek(), None);
        // The bridge peek must not flip classified. After calling it,
        // a peer that calls a lazy method will still see the bit as
        // false and run `classify_keychain_sources`.
        let _ = mgr.current_bearer_for_bridge();
        assert!(
            !mgr.classified.load(Ordering::Acquire),
            "current_bearer_for_bridge must not trigger keychain classification"
        );
    }

    #[test]
    fn phase45_p2_lazy_bearer_triggers_classification() {
        let _env = phase45_isolate();
        let mgr = SessionManager::new("https://example.invalid", None);
        assert!(!mgr.classified.load(Ordering::Acquire));
        // Calling the lazy variant must run ensure_classified once.
        let _ = mgr.current_bearer_lazy();
        assert!(
            mgr.classified.load(Ordering::Acquire),
            "current_bearer_lazy must trigger classification"
        );
        // Idempotent — a second call stays on the atomic-load fast path.
        let _ = mgr.current_bearer_lazy();
        assert!(mgr.classified.load(Ordering::Acquire));
    }

    #[test]
    fn phase45_p2_eager_env_token_classifies_immediately() {
        // When LPM_TOKEN is set, eager classification should succeed
        // and `classified` should start as `true` — the keychain never
        // needs to be consulted.
        let tempdir = tempfile::tempdir().unwrap();
        let _scoped = crate::test_env::ScopedEnv::set([
            ("HOME", tempdir.path().as_os_str().to_owned()),
            ("LPM_FORCE_FILE_AUTH", "1".into()),
            ("LPM_TOKEN", "env-token-value".into()),
        ]);
        let mgr = SessionManager::new("https://example.invalid", None);
        assert!(
            mgr.classified.load(Ordering::Acquire),
            "LPM_TOKEN in env must produce eager-classified state"
        );
        assert_eq!(mgr.current_source_peek(), Some(TokenSource::EnvVar));
    }

    #[test]
    fn phase45_p2_explicit_flag_bypasses_keychain() {
        let _env = phase45_isolate();
        let mgr = SessionManager::new(
            "https://example.invalid",
            Some("flag-token-value".to_string()),
        );
        assert!(
            mgr.classified.load(Ordering::Acquire),
            "--token value must produce eager-classified state"
        );
        assert_eq!(mgr.current_source_peek(), Some(TokenSource::ExplicitFlag));
        // The bridge peek surfaces the flag bearer synchronously.
        assert_eq!(
            mgr.current_bearer_for_bridge().as_deref(),
            Some("flag-token-value")
        );
    }

    /// Phase 35 audit fix #1: refresh-only-state recovery.
    ///
    /// When the access token is missing but the refresh token is
    /// still present, the manager must classify as `StoredSession`
    /// with an empty placeholder secret so `current_source()`
    /// returns `Some(StoredSession)` and `refresh_now()` is allowed
    /// to attempt the exchange.
    #[tokio::test]
    async fn refresh_only_state_classifies_as_stored_session_with_empty_secret() {
        // Use a synthetic CachedToken to verify the contract that
        // `classify_initial_token` is required to produce. Validating
        // the helper directly would touch keychain/disk; this asserts
        // the post-classification state instead.
        let mgr = manager_with(TokenSource::StoredSession, "");
        assert_eq!(
            mgr.current_source(),
            Some(TokenSource::StoredSession),
            "refresh-only state must observably be StoredSession so refresh_now can proceed"
        );
        assert!(
            !mgr.has_token(),
            "refresh-only state must not surface a usable bearer until refresh succeeds"
        );
        // Anonymous-allowed lookups return None (no bearer to enrich
        // with) — bridge skips `with_token` and the request goes out
        // anonymous, which the registry will 401, triggering the
        // recovery path.
        let res = mgr.token_for(AuthRequirement::AnonymousAllowed).await;
        assert!(matches!(res, Ok(None)));
    }
}

#[cfg(test)]
mod refresh_http_tests {
    //! Integration-shaped tests for the silent-refresh HTTP round-trip.
    //!
    //! These tests stand up a real `wiremock` server, so they verify
    //! the request shape, single-flight behavior, and the rotated
    //! refresh-token persistence path end-to-end.

    use super::*;
    use std::sync::Arc;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// **GPT audit fix #4 (post-Step-5).** Per-test isolation guard.
    ///
    /// Pre-fix, `manager_for` wrote refresh tokens directly to the
    /// real OS keychain, which (a) prompted the user for keychain
    /// access on macOS during `cargo test`, (b) cross-contaminated
    /// state between parallel test runs, and (c) made the suite fail
    /// without `--test-threads=1`. Now each test gets:
    ///
    /// - A unique `HOME` pointing at a fresh tempdir, so the
    ///   encrypted-file fallback path lands in its own directory.
    /// - `LPM_FORCE_FILE_AUTH=1`, which makes the storage layer
    ///   skip the keychain entirely.
    /// - `LPM_TEST_FAST_SCRYPT=1`, which uses cheap scrypt params
    ///   so encryption/decryption stays fast under nextest.
    ///
    /// `ScopedEnv` uses a global mutex internally, so concurrent
    /// tests serialize through env mutations rather than racing on
    /// the real keychain. The tempdir + scoped env are both held in
    /// the returned guard for the duration of the test.
    struct IsolatedTestEnv {
        _tempdir: tempfile::TempDir,
        _scoped_env: crate::test_env::ScopedEnv,
    }

    fn isolate_test_env() -> IsolatedTestEnv {
        let tempdir = tempfile::tempdir().expect("create test home tempdir");
        let scoped = crate::test_env::ScopedEnv::set([
            ("HOME", tempdir.path().as_os_str().to_owned()),
            ("LPM_FORCE_FILE_AUTH", "1".into()),
            ("LPM_TEST_FAST_SCRYPT", "1".into()),
        ]);
        IsolatedTestEnv {
            _tempdir: tempdir,
            _scoped_env: scoped,
        }
    }

    /// Build a manager pointed at the wiremock server, pre-loaded with
    /// a `StoredSession` source whose refresh token is in *real* local
    /// encrypted-file storage scoped to the server URL — so the round
    /// trip exercises the full persistence path.
    ///
    /// **Caller must hold an `IsolatedTestEnv` guard for the duration
    /// of the test** so the writes land in a per-test temp HOME and
    /// don't escape into the user's keychain.
    fn manager_for(server_url: &str) -> SessionManager {
        crate::set_refresh_token(server_url, "rt-original");

        // Phase 45 P2 — classified=true so the pre-seeded `cached`
        // StoredSession value is authoritative without triggering
        // `classify_keychain_sources` (which would overwrite from
        // the keychain the test doesn't want to touch).
        SessionManager {
            registry_url: server_url.to_string(),
            cached: RwLock::new(Some(CachedToken {
                secret: SecretString::from("at-stale".to_string()),
                source: TokenSource::StoredSession,
            })),
            classified: AtomicBool::new(true),
            classify_lock: std::sync::Mutex::new(()),
            refresh_generation: AtomicU64::new(0),
            refresh_lock: Mutex::new(()),
            http: tokio::sync::OnceCell::new(),
        }
    }

    #[tokio::test]
    async fn refresh_succeeds_and_rotates_secret() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/cli/refresh"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "token": "at-rotated",
                "refreshToken": "rt-rotated",
                "expiresAt": "2099-01-01T00:00:00Z",
            })))
            .mount(&server)
            .await;

        let _isolated = isolate_test_env();
        let mgr = manager_for(&server.uri());
        let new_token = mgr.refresh_now().await.expect("refresh should succeed");
        assert_eq!(new_token.expose_secret(), "at-rotated");
        // Cache is updated.
        let cached = mgr.token_for(AuthRequirement::TokenRequired).await.unwrap();
        assert_eq!(cached.unwrap().expose_secret(), "at-rotated");
    }

    /// Phase 35 audit fix #2: a 401 from `/api/cli/refresh` must wipe
    /// **both** the refresh token AND the cached access token, so
    /// subsequent commands don't keep replaying a dead bearer.
    /// Pre-fix the access token survived, causing a permanent
    /// auth-loop until the user ran `lpm logout` manually.
    #[tokio::test]
    async fn refresh_401_clears_refresh_token_and_returns_session_expired() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/cli/refresh"))
            .respond_with(ResponseTemplate::new(401))
            .mount(&server)
            .await;

        let _isolated = isolate_test_env();
        let mgr = manager_for(&server.uri());
        // Pre-fix invariant: cache holds the stale "at-stale" bearer
        // before the refresh attempt.
        assert!(
            mgr.has_token(),
            "cache should hold the stale bearer pre-call"
        );

        let res = mgr.refresh_now().await;
        assert!(matches!(res, Err(LpmError::SessionExpired)));
        // Refresh token was cleared so subsequent refreshes don't loop.
        assert!(crate::get_refresh_token(&server.uri()).is_none());
        // Audit fix #2: cached access token AND its in-memory cache
        // are both wiped, so the next request goes out anonymous
        // instead of replaying a dead bearer.
        assert!(
            !mgr.has_token(),
            "in-memory cache must be cleared after authoritative refresh failure"
        );
        assert_eq!(
            mgr.current_source(),
            None,
            "source must be cleared after authoritative refresh failure"
        );
        assert!(
            crate::get_token(&server.uri()).is_none(),
            "persisted access token must be cleared after authoritative refresh failure"
        );
    }

    #[tokio::test]
    async fn refresh_500_keeps_refresh_token() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/cli/refresh"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;

        let _isolated = isolate_test_env();
        let mgr = manager_for(&server.uri());
        let res = mgr.refresh_now().await;
        assert!(matches!(res, Err(LpmError::SessionExpired)));
        // 5xx is transient — we keep ALL local state so the next
        // attempt can recover. Counterpart to the 401 wipe assertion
        // above: only authoritative rejections clear state.
        assert!(crate::get_refresh_token(&server.uri()).is_some());
        assert!(
            mgr.has_token(),
            "transient 5xx must leave the cached bearer in place"
        );
        assert_eq!(mgr.current_source(), Some(TokenSource::StoredSession));
    }

    #[tokio::test]
    async fn concurrent_refreshes_are_single_flight() {
        let server = MockServer::start().await;
        // Use a slow response so concurrent callers actually pile up
        // on the lock.
        Mock::given(method("POST"))
            .and(path("/api/cli/refresh"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_delay(std::time::Duration::from_millis(150))
                    .set_body_json(serde_json::json!({
                        "token": "at-rotated",
                        "refreshToken": "rt-rotated",
                    })),
            )
            .expect(1) // ← assertion: server hit exactly once
            .mount(&server)
            .await;

        let _isolated = isolate_test_env();
        let mgr = Arc::new(manager_for(&server.uri()));
        let mut handles = Vec::new();
        for _ in 0..8 {
            let m = mgr.clone();
            handles.push(tokio::spawn(async move { m.refresh_now().await }));
        }
        for h in handles {
            let result = h.await.unwrap().expect("each task sees the rotated token");
            assert_eq!(result.expose_secret(), "at-rotated");
        }
        // Mock's `.expect(1)` is verified on drop of `server`.
    }

    /// **GPT audit fix #1 (post-Step-5).** When the cached access
    /// token is non-empty but the local expiry metadata says it's
    /// past its TTL, `bearer_string_for` must do the silent refresh
    /// rather than return a known-stale bearer.
    ///
    /// This is the critical regression path for env / swift-registry /
    /// setup callers that build their own HTTP client and so don't
    /// get `RegistryClient::execute_with_recovery` for free. Pre-fix,
    /// they would have surfaced "auth required" on the first call
    /// after the access token expired locally — exactly the
    /// re-login friction Phase 35 was designed to eliminate.
    #[tokio::test]
    async fn bearer_string_for_proactively_refreshes_when_local_metadata_says_expired() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/cli/refresh"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "token": "at-rotated",
                "refreshToken": "rt-rotated",
                "expiresAt": "2099-01-01T00:00:00Z",
            })))
            .expect(1) // exactly one refresh
            .mount(&server)
            .await;

        let _isolated = isolate_test_env();
        let mgr = manager_for(&server.uri());
        // Mark the cached access token as already-expired locally.
        crate::set_session_access_token_expiry(&server.uri(), "2026-04-08T00:00:00Z");
        assert!(crate::is_session_access_token_expired(&server.uri()));

        let bearer = mgr
            .bearer_string_for(AuthRequirement::TokenRequired)
            .await
            .expect("known-stale token should refresh, not surface as Err");
        assert_eq!(
            bearer, "at-rotated",
            "must return the rotated bearer, not the stale 'at-stale' from the cache"
        );
        // Mock's `.expect(1)` verifies the refresh happened.
    }

    /// Counterpart: when no expiry metadata is recorded (fresh login,
    /// pre-Phase-35 install), the cached bearer is trusted — we
    /// don't refresh proactively without evidence.
    #[tokio::test]
    async fn bearer_string_for_does_not_refresh_when_no_expiry_metadata() {
        let server = MockServer::start().await;
        // No mock for `/api/cli/refresh` — would panic if called.

        let _isolated = isolate_test_env();
        let mgr = manager_for(&server.uri());
        // Explicitly clear any expiry metadata so the optimistic path
        // is exercised.
        crate::clear_token_expiry(&server.uri());

        let bearer = mgr
            .bearer_string_for(AuthRequirement::TokenRequired)
            .await
            .expect("optimistic path returns cached bearer");
        assert_eq!(
            bearer, "at-stale",
            "no metadata = no refresh; the cached bearer is returned as-is"
        );
    }
}
