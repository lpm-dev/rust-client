//! Release version lookup with on-disk cache.
//!
//! Two consumers share this module:
//! - `update_check` — background banner refresh (24h success TTL).
//! - `commands::self_update` — user-facing update command (10m success TTL).
//!
//! Both read and write the same file (`~/.lpm/update-check.json`) so an
//! explicit `lpm self-update` doubles as a banner refresh.
//!
//! Two probe sources are tried in order:
//!
//! 1. **npm registry** (`registry.npmjs.org/@lpm-registry/cli/latest`) —
//!    anonymous, no rate limit in practice, used by every install
//!    channel. The npm `latest` dist-tag stays in lockstep with our
//!    GitHub Releases, so version reporting is identical regardless of
//!    how the user installed `lpm`.
//! 2. **GitHub Releases** — fallback only, when npm is unreachable. The
//!    primary problem this fixes: every channel used to share a single
//!    60 req/hr unauthenticated GitHub IP bucket and rate-limit each
//!    other.
//!
//! Each probe sends `If-None-Match` from a per-source cached etag
//! (304 → reuse cached version). The GitHub probe additionally honours
//! `GITHUB_TOKEN` / `GH_TOKEN` (60→5000 req/hr) and maps 403 +
//! `x-ratelimit-remaining: 0` to a typed rate-limit error carrying the
//! reset epoch from `x-ratelimit-reset`. Any failure stamps
//! `last_failure_check` so the staleness gate backs off offline /
//! rate-limited callers instead of forking a doomed background child on
//! every invocation.

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const NPM_REGISTRY_URL_DEFAULT: &str = "https://registry.npmjs.org/@lpm-registry/cli/latest";
const GITHUB_RELEASES_URL_DEFAULT: &str =
    "https://api.github.com/repos/lpm-dev/rust-client/releases/latest";

/// Template for the "release by tag" endpoint. `{tag}` is substituted
/// at call time (raw, no encoding — version strings are restricted to
/// semver characters by the caller's earlier validation). The
/// `LPM_GITHUB_RELEASE_BY_TAG_URL_OVERRIDE` env var, when set, is the
/// full template (must contain `{tag}`); tests point it at wiremock.
const GITHUB_RELEASE_BY_TAG_URL_DEFAULT: &str =
    "https://api.github.com/repos/lpm-dev/rust-client/releases/tags/v{tag}";

/// Template for release-asset download URLs. `{tag}` and `{file}` are
/// substituted at call time. The `LPM_GITHUB_RELEASE_DOWNLOAD_URL_OVERRIDE`
/// env var, when set, is the full template (must contain both
/// placeholders); tests point it at a wiremock-backed loopback server.
const GITHUB_RELEASE_DOWNLOAD_URL_DEFAULT: &str =
    "https://github.com/lpm-dev/rust-client/releases/download/v{tag}/{file}";

const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Resolve the npm registry endpoint. Honours
/// `LPM_NPM_REGISTRY_URL_OVERRIDE` so tests (and users behind a private
/// npm mirror) can redirect the probe without a binary rebuild.
///
/// Override values are gated by [`accept_override`]: HTTPS is always
/// accepted, plain HTTP only when the host is a loopback address (test
/// servers, local mirrors). The override is logged at `warn` level
/// whenever it fires so an operator scanning logs can spot an
/// attacker-controlled redirect of the self-update version probe.
fn npm_registry_url() -> String {
    resolve_release_url("LPM_NPM_REGISTRY_URL_OVERRIDE", NPM_REGISTRY_URL_DEFAULT)
}

/// Resolve the GitHub Releases endpoint. Honours
/// `LPM_GITHUB_RELEASES_URL_OVERRIDE` for tests. Same gating + logging
/// contract as [`npm_registry_url`].
fn github_releases_url() -> String {
    resolve_release_url(
        "LPM_GITHUB_RELEASES_URL_OVERRIDE",
        GITHUB_RELEASES_URL_DEFAULT,
    )
}

/// Shared override-resolution path. Reads `env_var`, validates the
/// scheme/host combination, and falls back to `default_url` on absent
/// or rejected values.
///
/// The H9 finding: env vars `LPM_NPM_REGISTRY_URL_OVERRIDE` and
/// `LPM_GITHUB_RELEASES_URL_OVERRIDE` are honoured unconditionally,
/// so any actor who can write env vars (compromised CI runner,
/// dotfile pollution, malicious wrapper script) can steer the self-
/// update version probe to an attacker host. Combined with the lack
/// of binary signature verification on the standalone update channel
/// (C2), this becomes one half of an RCE chain.
///
/// We can't outright remove the override (tests + legitimate private-
/// mirror users depend on it) but we can shrink its abuse window:
/// require HTTPS for any non-loopback host (so a plain `http://evil.com`
/// is rejected), and log a `warn` whenever the override fires so the
/// operator has audit visibility.
fn resolve_release_url(env_var: &str, default_url: &str) -> String {
    let raw = match std::env::var(env_var).ok().filter(|s| !s.is_empty()) {
        Some(v) => v,
        None => return default_url.to_string(),
    };
    if accept_override(&raw) {
        tracing::warn!(
            env_var = env_var,
            override_url = %raw,
            "release-lookup endpoint override honoured — confirm this is expected",
        );
        return raw;
    }
    tracing::warn!(
        env_var = env_var,
        override_url = %raw,
        "rejecting release-lookup endpoint override: plain HTTP non-loopback URL; \
         falling back to default — set the override to an https:// URL to use a private mirror",
    );
    default_url.to_string()
}

/// Accept an override URL if it's HTTPS (any host) or HTTP pointed at
/// a loopback address (tests + local dev mirrors). Anything else
/// (HTTP non-loopback, unsupported scheme, malformed URL) is refused.
fn accept_override(url: &str) -> bool {
    let parsed = match reqwest::Url::parse(url) {
        Ok(u) => u,
        Err(_) => return false,
    };
    match parsed.scheme() {
        "https" => true,
        "http" => parsed.host_str().is_some_and(is_loopback_host),
        _ => false,
    }
}

/// Loopback host detection covering the cases we actually see in tests
/// and on dev machines: `localhost`, the IPv4 loopback block
/// `127.0.0.0/8`, and the IPv6 loopback `::1`.
fn is_loopback_host(host: &str) -> bool {
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    if let Ok(addr) = host.parse::<std::net::IpAddr>() {
        return addr.is_loopback();
    }
    // `[::1]` shape — strip brackets and retry.
    if let Some(inner) = host.strip_prefix('[').and_then(|s| s.strip_suffix(']'))
        && let Ok(addr) = inner.parse::<std::net::IpAddr>()
    {
        return addr.is_loopback();
    }
    false
}

/// Cache file shape. All fields beyond `latest` / `last_check` are
/// optional so the original `{latest, lastCheck}` JSON written by the
/// pre-refactor banner deserialises cleanly into the new struct.
#[derive(Debug, Default, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct UpdateCache {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub latest: String,

    /// Unix seconds of the last successful network probe.
    #[serde(rename = "lastCheck", default)]
    pub last_check: u64,

    /// Unix seconds of the last network probe that did NOT update
    /// `last_check` (network error, 403, etc.). Drives the failure
    /// backoff so stale `last_check` doesn't make every invocation
    /// spawn a fresh refresh child.
    #[serde(rename = "lastFailureCheck", default, skip_serializing_if = "is_zero")]
    pub last_failure_check: u64,

    /// Cached `ETag` from the most recent successful GitHub Releases
    /// response. Sent as `If-None-Match` on the next GitHub probe so a
    /// 304 reuses the stored `latest` without re-downloading the JSON.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub etag: String,

    /// Cached `ETag` from the most recent successful npm registry
    /// response. Tracked separately from `etag` because npm and GitHub
    /// generate etags from independent storage backends — sending an
    /// npm-shaped etag to GitHub (or vice versa) would either be
    /// ignored or yield a spurious 304 against the wrong body.
    #[serde(rename = "npmEtag", default, skip_serializing_if = "String::is_empty")]
    pub npm_etag: String,
}

fn is_zero(v: &u64) -> bool {
    *v == 0
}

/// Result of a network probe.
#[derive(Debug, PartialEq)]
pub enum FetchOutcome {
    /// Server returned a fresh release; cache was updated.
    Fresh { version: String },
    /// Server returned 304; cached version is still current.
    NotModified { version: String },
}

/// Typed error variants for the network probe so callers can render
/// useful UX (rate-limit reset time, transport vs HTTP, etc.) without
/// pattern-matching on error strings.
#[derive(Debug)]
pub enum LookupError {
    /// HTTP transport failure (DNS, TCP, TLS, timeout).
    Transport(String),
    /// GitHub primary-rate-limit hit. `reset_at` is the unix-epoch
    /// second from `x-ratelimit-reset` if the server provided it.
    RateLimited { reset_at: Option<u64> },
    /// Non-success HTTP status that isn't a recognised rate limit.
    HttpStatus { status: u16, body_excerpt: String },
    /// Response body present but `tag_name` missing or invalid.
    MalformedResponse(String),
    /// Endpoint returned 404 (release tag does not exist on GitHub).
    /// Distinct from `HttpStatus` so callers can branch cleanly on
    /// "no such release" vs other server errors.
    NotFound(String),
}

impl std::fmt::Display for LookupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Body framing concerns:
        // - `LookupError` is shared by the npm and GitHub probe paths,
        //   so source-specific wording ("GitHub API …") only appears
        //   on variants that can ONLY come from the GitHub leg
        //   (`RateLimited`). Source-agnostic variants stay neutral.
        // - The `GITHUB_TOKEN` / `GH_TOKEN` remediation hint that used
        //   to live here moved into the wrapping
        //   `LpmError::SelfUpdateRateLimited` diagnostic help text. Repeating
        //   it here would print the same instruction twice on screen.
        match self {
            Self::Transport(msg) => write!(f, "network error: {msg}"),
            Self::RateLimited { reset_at } => match reset_at {
                Some(epoch) => {
                    write!(
                        f,
                        "GitHub API rate limit hit. {}",
                        format_reset_hint(*epoch)
                    )
                }
                None => write!(f, "GitHub API rate limit hit"),
            },
            Self::HttpStatus {
                status,
                body_excerpt,
            } => {
                if body_excerpt.is_empty() {
                    write!(f, "release lookup returned HTTP {status}")
                } else {
                    write!(f, "release lookup returned HTTP {status}: {body_excerpt}")
                }
            }
            Self::MalformedResponse(msg) => write!(f, "malformed release-lookup response: {msg}"),
            Self::NotFound(msg) => write!(f, "release not found: {msg}"),
        }
    }
}

/// Render `x-ratelimit-reset` (unix epoch) as a "try again in N min/sec"
/// hint relative to the current wall clock.
fn format_reset_hint(reset_at: u64) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    if reset_at <= now {
        return "Try again now".to_string();
    }
    let seconds = reset_at - now;
    if seconds < 60 {
        format!("Try again in {seconds} seconds")
    } else {
        let minutes = seconds.div_ceil(60);
        format!(
            "Try again in {minutes} minute{}",
            if minutes == 1 { "" } else { "s" }
        )
    }
}

// ---------------------------------------------------------------------
// Cache I/O — path-injectable for tests
// ---------------------------------------------------------------------

/// Default cache path: `~/.lpm/update-check.json`. `None` only when
/// `dirs::home_dir()` itself returns `None` (extremely rare).
pub fn default_cache_path() -> Option<PathBuf> {
    dirs::home_dir().map(|h| h.join(".lpm").join("update-check.json"))
}

/// Read-only cache load. Returns `None` if the file is missing or
/// malformed; both states are equivalent to "no cached data" for
/// staleness logic. Backwards-compatible with the legacy
/// `{latest, lastCheck}` JSON that pre-refactor `update_check.rs` wrote.
pub fn read_cache_at(path: &Path) -> Option<UpdateCache> {
    let content = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&content).ok()
}

/// Atomic write via `<path>.tmp` + rename. Best-effort directory
/// creation. Errors are returned so the caller can decide whether to
/// surface them — banner path swallows, self-update path may want to
/// log on failure.
pub fn write_cache_at(path: &Path, cache: &UpdateCache) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let json = serde_json::to_string(cache)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, json)?;
    if let Err(e) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    Ok(())
}

/// Best-effort cache delete. Used after a successful upgrade through a
/// channel where the post-upgrade version is unknown (Homebrew).
pub fn clear_cache_at(path: &Path) {
    let _ = std::fs::remove_file(path);
}

// ---------------------------------------------------------------------
// Staleness with separate success / failure TTLs + jitter
// ---------------------------------------------------------------------

/// Did the last probe (success OR failure) happen long enough ago that
/// we should make another network call?
///
/// `success_ttl` gates "we know the latest version, but it might be old".
/// `failure_ttl` gates "we tried recently and it didn't work" — separate
/// so a transient outage doesn't pin the cache forever AND so a
/// rate-limited / offline user doesn't fork a fresh refresh child on
/// every invocation.
///
/// `jitter_seed` is XORed into the failure_ttl bucket per call. Pass
/// the cache `last_failure_check` value (or `0`) — we only need the
/// fanout property, not cryptographic randomness.
pub fn is_stale(
    cache: Option<&UpdateCache>,
    now_secs: u64,
    success_ttl: Duration,
    failure_ttl: Duration,
) -> bool {
    let Some(cache) = cache else {
        return true;
    };

    if cache.last_check == 0 && cache.last_failure_check == 0 {
        return true;
    }

    let success_fresh =
        cache.last_check > 0 && now_secs.saturating_sub(cache.last_check) < success_ttl.as_secs();
    if success_fresh {
        return false;
    }

    if cache.last_failure_check > 0 {
        let jitter = jitter_seconds(cache.last_failure_check, failure_ttl);
        let effective_ttl = failure_ttl.as_secs().saturating_add(jitter);
        let failure_fresh = now_secs.saturating_sub(cache.last_failure_check) < effective_ttl;
        if failure_fresh {
            return false;
        }
    }

    true
}

/// Deterministic 0..=10% jitter on a TTL window. Same input → same
/// output (no crate dep on `rand`). Goal is to spread retry storms
/// across many machines that all started failing at the same minute,
/// not unpredictability.
fn jitter_seconds(seed: u64, ttl: Duration) -> u64 {
    let span = ttl.as_secs() / 10;
    if span == 0 {
        return 0;
    }
    // xorshift64* — fast, good enough for fanout.
    let mut s = seed.wrapping_add(0x9E37_79B9_7F4A_7C15);
    s ^= s >> 12;
    s ^= s << 25;
    s ^= s >> 27;
    let v = s.wrapping_mul(0x2545_F491_4F6C_DD1D);
    v % (span + 1)
}

// ---------------------------------------------------------------------
// Network probe
// ---------------------------------------------------------------------

/// Read GitHub auth token from env. `GITHUB_TOKEN` first (CI standard),
/// `GH_TOKEN` second (`gh` CLI convention). Empty values treated as
/// absent so `unset GITHUB_TOKEN; export GITHUB_TOKEN=""` doesn't poison
/// the request with a bogus header.
fn github_token() -> Option<String> {
    std::env::var("GITHUB_TOKEN")
        .or_else(|_| std::env::var("GH_TOKEN"))
        .ok()
        .filter(|t| !t.is_empty())
}

/// Which release source we're probing. Drives both the etag slot in
/// the cache and the version-extraction shape of the response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Source {
    Npm,
    GitHub,
}

/// Pull the version string out of the parsed JSON for a given source.
///
/// Split out as a pure function so the parsing contract is unit-testable
/// without spinning up wiremock — the failure modes here (missing field,
/// empty value, non-string type) historically cause silent regressions
/// when a registry tweaks its response shape.
fn extract_version(source: Source, body: &serde_json::Value) -> Result<String, LookupError> {
    match source {
        Source::Npm => match body.get("version").and_then(|v| v.as_str()) {
            Some(v) if !v.is_empty() => Ok(v.to_string()),
            _ => Err(LookupError::MalformedResponse(
                "missing version on npm registry response".into(),
            )),
        },
        Source::GitHub => match body.get("tag_name").and_then(|v| v.as_str()) {
            Some(t) if !t.is_empty() => Ok(t.strip_prefix('v').unwrap_or(t).to_string()),
            _ => Err(LookupError::MalformedResponse(
                "missing tag_name on github releases response".into(),
            )),
        },
    }
}

/// Try the npm registry first, fall back to GitHub Releases. The
/// foreground command and the background banner refresh both call this.
///
/// Cascade rules:
/// - npm success → return immediately, GitHub never contacted.
/// - npm transport / HTTP failure → try GitHub. If GitHub succeeds, the
///   user sees a successful update check.
/// - both legs fail → return the **more actionable** of the two errors:
///   GitHub's `RateLimited` (carries a structured reset hint and pairs
///   with the `LpmError::SelfUpdateRateLimited` UX wrapper) wins over
///   the generic npm transport / HTTP failure. Without this rule the
///   rate-limit surface that ships in this PR was unreachable end-to-end:
///   the only way the GitHub-only `RateLimited` variant gets constructed
///   is the fallback leg, and the cascade would always pin the npm error
///   instead. Anything else (npm transport vs GitHub HTTP 5xx, etc.)
///   defaults to the npm error since npm is the primary path.
/// - npm `MalformedResponse` → also fall back to GitHub. A malformed
///   primary shouldn't block updates if the fallback works.
pub async fn probe_release(cache: &mut UpdateCache) -> Result<FetchOutcome, LookupError> {
    let npm_err = match probe_one(Source::Npm, cache).await {
        Ok(outcome) => return Ok(outcome),
        Err(e) => e,
    };

    match probe_one(Source::GitHub, cache).await {
        Ok(outcome) => Ok(outcome),
        Err(gh_err) => Err(prefer_more_actionable(npm_err, gh_err)),
    }
}

/// Pick the error that's more useful to surface to the user when both
/// probe legs failed. Split out so the policy is unit-testable without
/// wiremock and so the rule itself is named for future readers.
fn prefer_more_actionable(npm_err: LookupError, gh_err: LookupError) -> LookupError {
    // RateLimited is GitHub-only and carries a typed reset hint plus a
    // dedicated `LpmError::SelfUpdateRateLimited` wrapper with help
    // text. It's strictly more actionable than the npm-side
    // alternatives we'd otherwise return, so it wins.
    if matches!(gh_err, LookupError::RateLimited { .. }) {
        return gh_err;
    }
    npm_err
}

/// Probe a single release source. On success, mutates `cache` with the
/// fresh version + the per-source etag + bumps `last_check`. On 304,
/// just bumps `last_check` (cached version stays). On any failure,
/// bumps `last_failure_check` and returns the typed error.
///
/// Caller is responsible for persisting the cache via `write_cache_at`.
async fn probe_one(source: Source, cache: &mut UpdateCache) -> Result<FetchOutcome, LookupError> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let client = lpm_http::client_builder()
        .timeout(REQUEST_TIMEOUT)
        .build()
        .map_err(|e| {
            cache.last_failure_check = now;
            LookupError::Transport(format!("failed to build HTTP client: {e}"))
        })?;

    let url = match source {
        Source::Npm => npm_registry_url(),
        Source::GitHub => github_releases_url(),
    };

    let mut req = client.get(&url).header("User-Agent", "lpm-cli");

    let cached_etag = match source {
        Source::Npm => cache.npm_etag.clone(),
        Source::GitHub => cache.etag.clone(),
    };

    match source {
        Source::Npm => {
            req = req.header("Accept", "application/json");
        }
        Source::GitHub => {
            req = req.header("Accept", "application/vnd.github.v3+json");
            if let Some(token) = github_token() {
                req = req.header("Authorization", format!("Bearer {token}"));
            }
        }
    }

    if !cached_etag.is_empty() {
        req = req.header("If-None-Match", &cached_etag);
    }

    let resp = match req.send().await {
        Ok(r) => r,
        Err(e) => {
            cache.last_failure_check = now;
            return Err(LookupError::Transport(
                lpm_http::display_error(&e).to_string(),
            ));
        }
    };

    let status = resp.status();

    // 304 Not Modified: cache stays valid, just bump the timestamp.
    if status.as_u16() == 304 && !cache.latest.is_empty() {
        cache.last_check = now;
        return Ok(FetchOutcome::NotModified {
            version: cache.latest.clone(),
        });
    }

    // 403 with primary rate limit (GitHub-specific) — npm doesn't gate
    // anonymous reads this way, so the rate-limit detection is scoped
    // to the GitHub path.
    if source == Source::GitHub
        && status.as_u16() == 403
        && resp
            .headers()
            .get("x-ratelimit-remaining")
            .and_then(|v| v.to_str().ok())
            == Some("0")
    {
        let reset_at = resp
            .headers()
            .get("x-ratelimit-reset")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<u64>().ok());
        cache.last_failure_check = now;
        return Err(LookupError::RateLimited { reset_at });
    }

    if !status.is_success() {
        // Best-effort body excerpt for diagnostics; ignore body errors.
        let body = resp.text().await.unwrap_or_default();
        let excerpt: String = body.chars().take(200).collect();
        cache.last_failure_check = now;
        return Err(LookupError::HttpStatus {
            status: status.as_u16(),
            body_excerpt: excerpt,
        });
    }

    // Capture etag BEFORE consuming the body.
    let etag = resp
        .headers()
        .get("etag")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .unwrap_or_default();

    let body: serde_json::Value = match resp.json().await {
        Ok(v) => v,
        Err(e) => {
            cache.last_failure_check = now;
            return Err(LookupError::MalformedResponse(format!(
                "body not JSON: {e}"
            )));
        }
    };

    let version = match extract_version(source, &body) {
        Ok(v) => v,
        Err(e) => {
            cache.last_failure_check = now;
            return Err(e);
        }
    };

    cache.latest = version.clone();
    cache.last_check = now;
    cache.last_failure_check = 0;
    match source {
        Source::Npm => cache.npm_etag = etag,
        Source::GitHub => cache.etag = etag,
    }

    Ok(FetchOutcome::Fresh { version })
}

// ---------------------------------------------------------------------
// Release-by-tag metadata (standalone self-update replay-window anchor)
// ---------------------------------------------------------------------

/// Resolve the "release by tag" endpoint with the same override gating
/// as the latest-release path. The default URL templates `{tag}`,
/// which the caller substitutes after override resolution so the
/// override env var can carry its own `{tag}` placeholder (wiremock
/// tests typically set it to `http://127.0.0.1:<port>/releases/tags/v{tag}`).
fn github_release_by_tag_url(version: &str) -> String {
    let template = resolve_release_url(
        "LPM_GITHUB_RELEASE_BY_TAG_URL_OVERRIDE",
        GITHUB_RELEASE_BY_TAG_URL_DEFAULT,
    );
    template.replace("{tag}", version)
}

/// Resolve a release-asset download URL with `{tag}` and `{file}`
/// substitution after override gating. Public so the standalone
/// self-update path (which downloads the manifest, the bundle, and
/// the platform binary from this base) shares the override hook.
pub fn github_release_download_url(version: &str, file: &str) -> String {
    let template = resolve_release_url(
        "LPM_GITHUB_RELEASE_DOWNLOAD_URL_OVERRIDE",
        GITHUB_RELEASE_DOWNLOAD_URL_DEFAULT,
    );
    template.replace("{tag}", version).replace("{file}", file)
}

/// Fetch the `published_at` ISO-8601 timestamp for a specific release tag.
///
/// Used by the standalone self-update path to anchor the Sigstore-bundle
/// replay-window check against the actual release publication time,
/// decoupled from the npm-first version probe. Runs only on the
/// standalone arm — npm/Homebrew/cargo arms have their own integrity
/// stories and don't need a window anchor.
///
/// Failure shapes: `NotFound` for 404 (tag does not exist),
/// `MalformedResponse` for missing/non-string/unparseable `published_at`,
/// `RateLimited` / `HttpStatus` / `Transport` for the underlying network
/// failures (kept identical to `probe_one`'s shape so the wrapping
/// `LpmError::SelfUpdate` mapping at the call site stays uniform).
pub async fn fetch_github_release_published_at(
    version: &str,
) -> Result<chrono::DateTime<chrono::Utc>, LookupError> {
    let url = github_release_by_tag_url(version);

    let client = lpm_http::client_builder()
        .timeout(REQUEST_TIMEOUT)
        .build()
        .map_err(|e| LookupError::Transport(format!("failed to build HTTP client: {e}")))?;

    let mut req = client
        .get(&url)
        .header("User-Agent", "lpm-cli")
        .header("Accept", "application/vnd.github.v3+json");
    if let Some(token) = github_token() {
        req = req.header("Authorization", format!("Bearer {token}"));
    }

    let resp = req
        .send()
        .await
        .map_err(|e| LookupError::Transport(lpm_http::display_error(&e).to_string()))?;

    let status = resp.status();

    if status.as_u16() == 404 {
        return Err(LookupError::NotFound(format!(
            "GitHub has no release at tag v{version}"
        )));
    }

    if status.as_u16() == 403
        && resp
            .headers()
            .get("x-ratelimit-remaining")
            .and_then(|v| v.to_str().ok())
            == Some("0")
    {
        let reset_at = resp
            .headers()
            .get("x-ratelimit-reset")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<u64>().ok());
        return Err(LookupError::RateLimited { reset_at });
    }

    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        let excerpt: String = body.chars().take(200).collect();
        return Err(LookupError::HttpStatus {
            status: status.as_u16(),
            body_excerpt: excerpt,
        });
    }

    let body: serde_json::Value = resp.json().await.map_err(|e| {
        LookupError::MalformedResponse(format!("release-by-tag body not JSON: {e}"))
    })?;

    let published_at_str = body
        .get("published_at")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            LookupError::MalformedResponse(format!(
                "release v{version} response missing string `published_at`"
            ))
        })?;

    chrono::DateTime::parse_from_rfc3339(published_at_str)
        .map(|dt| dt.with_timezone(&chrono::Utc))
        .map_err(|e| {
            LookupError::MalformedResponse(format!(
                "release v{version} `published_at` not RFC 3339: {e}"
            ))
        })
}

// ---------------------------------------------------------------------
// Semver comparison
// ---------------------------------------------------------------------

/// `true` if `a` is strictly newer than `b`, using full npm-compatible
/// semver ordering (prerelease suffixes included). Backed by
/// `lpm_semver::Version`, which delegates to `node-semver`.
///
/// Unparseable inputs return `false` rather than panicking. GitHub
/// controls our release tag namespace, so a malformed `tag_name` would
/// signal infrastructure breakage — falling back to "not newer" keeps
/// us from auto-installing nonsense versions in that case.
pub fn is_newer_semver(a: &str, b: &str) -> bool {
    match (lpm_semver::Version::parse(a), lpm_semver::Version::parse(b)) {
        (Ok(va), Ok(vb)) => va > vb,
        _ => false,
    }
}

// ---------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn now_secs() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    #[test]
    fn read_missing_cache_returns_none() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("update-check.json");
        assert!(read_cache_at(&path).is_none());
    }

    #[test]
    fn legacy_cache_format_loads_with_defaults() {
        // The pre-refactor banner wrote `{latest, lastCheck}` only.
        // The new typed struct must accept that shape with zero values
        // for the new fields.
        let dir = tempdir().unwrap();
        let path = dir.path().join("update-check.json");
        let legacy = serde_json::json!({
            "latest": "0.24.0",
            "lastCheck": 1_700_000_000u64,
        });
        std::fs::write(&path, legacy.to_string()).unwrap();

        let cache = read_cache_at(&path).expect("legacy cache must load");
        assert_eq!(cache.latest, "0.24.0");
        assert_eq!(cache.last_check, 1_700_000_000);
        assert_eq!(cache.last_failure_check, 0);
        assert_eq!(cache.etag, "");
    }

    #[test]
    fn write_then_read_round_trips() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("update-check.json");
        let cache = UpdateCache {
            latest: "0.25.0".into(),
            last_check: 1_700_000_000,
            last_failure_check: 0,
            etag: "W/\"abc123\"".into(),
            npm_etag: "\"npm-xyz789\"".into(),
        };
        write_cache_at(&path, &cache).unwrap();
        let loaded = read_cache_at(&path).unwrap();
        assert_eq!(loaded, cache);
    }

    /// Per-source etags are persisted separately. Mixing them would
    /// produce spurious 304s when the wrong endpoint receives the wrong
    /// `If-None-Match`.
    #[test]
    fn npm_and_github_etags_round_trip_independently() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("update-check.json");
        let cache = UpdateCache {
            latest: "0.25.0".into(),
            last_check: 1_700_000_000,
            etag: "github-etag".into(),
            npm_etag: "npm-etag".into(),
            ..Default::default()
        };
        write_cache_at(&path, &cache).unwrap();
        let raw = std::fs::read_to_string(&path).unwrap();
        // Field name visibility: legacy `etag` for GitHub, `npmEtag`
        // for npm. Locks the on-disk shape so a future struct rename
        // doesn't silently break older cache files.
        assert!(raw.contains("\"etag\":\"github-etag\""), "raw: {raw}");
        assert!(raw.contains("\"npmEtag\":\"npm-etag\""), "raw: {raw}");
        let loaded = read_cache_at(&path).unwrap();
        assert_eq!(loaded.etag, "github-etag");
        assert_eq!(loaded.npm_etag, "npm-etag");
    }

    #[test]
    fn write_omits_zero_failure_field() {
        // last_failure_check=0 should not be serialised, keeping the
        // happy-path on-disk shape clean and forward-compatible with
        // any reader that still expects only the legacy fields.
        let dir = tempdir().unwrap();
        let path = dir.path().join("update-check.json");
        write_cache_at(
            &path,
            &UpdateCache {
                latest: "0.25.0".into(),
                last_check: 1_700_000_000,
                last_failure_check: 0,
                etag: String::new(),
                npm_etag: String::new(),
            },
        )
        .unwrap();
        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(!raw.contains("lastFailureCheck"), "raw: {raw}");
        assert!(!raw.contains("etag"), "raw: {raw}");
        assert!(!raw.contains("npmEtag"), "raw: {raw}");
    }

    #[test]
    fn clear_cache_removes_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("update-check.json");
        write_cache_at(&path, &UpdateCache::default()).unwrap();
        assert!(path.exists());
        clear_cache_at(&path);
        assert!(!path.exists());
        // idempotent
        clear_cache_at(&path);
    }

    #[test]
    fn is_stale_with_no_cache() {
        assert!(is_stale(
            None,
            now_secs(),
            Duration::from_secs(600),
            Duration::from_secs(3600),
        ));
    }

    #[test]
    fn is_stale_with_zero_timestamps() {
        let cache = UpdateCache::default();
        assert!(is_stale(
            Some(&cache),
            now_secs(),
            Duration::from_secs(600),
            Duration::from_secs(3600),
        ));
    }

    #[test]
    fn is_fresh_within_success_ttl() {
        let now = now_secs();
        let cache = UpdateCache {
            latest: "0.25.0".into(),
            last_check: now - 60,
            ..Default::default()
        };
        assert!(!is_stale(
            Some(&cache),
            now,
            Duration::from_secs(600),
            Duration::from_secs(3600),
        ));
    }

    #[test]
    fn is_stale_past_success_ttl() {
        let now = now_secs();
        let cache = UpdateCache {
            latest: "0.25.0".into(),
            last_check: now - 700,
            ..Default::default()
        };
        assert!(is_stale(
            Some(&cache),
            now,
            Duration::from_secs(600),
            Duration::from_secs(3600),
        ));
    }

    #[test]
    fn failure_backoff_suppresses_immediate_retry() {
        // A failure 5 minutes ago + 1h failure_ttl = NOT stale.
        // This is the scenario that fixes the "every invocation forks
        // a doomed background child" loop.
        let now = now_secs();
        let cache = UpdateCache {
            last_failure_check: now - 300,
            ..Default::default()
        };
        assert!(!is_stale(
            Some(&cache),
            now,
            Duration::from_secs(600),
            Duration::from_secs(3600),
        ));
    }

    #[test]
    fn failure_backoff_lapses_after_failure_ttl() {
        // Past the failure TTL (+ max jitter) → caller may probe again.
        let now = now_secs();
        let cache = UpdateCache {
            last_failure_check: now - 4500, // 1h15m, exceeds 1h + 6m max jitter
            ..Default::default()
        };
        assert!(is_stale(
            Some(&cache),
            now,
            Duration::from_secs(600),
            Duration::from_secs(3600),
        ));
    }

    #[test]
    fn success_fresh_overrides_failure_stale() {
        // If the success window is current, a stale failure timestamp
        // must NOT cause a redundant probe.
        let now = now_secs();
        let cache = UpdateCache {
            latest: "0.25.0".into(),
            last_check: now - 60,
            last_failure_check: now - 86_400,
            ..Default::default()
        };
        assert!(!is_stale(
            Some(&cache),
            now,
            Duration::from_secs(600),
            Duration::from_secs(3600),
        ));
    }

    #[test]
    fn jitter_is_bounded_to_ten_percent() {
        let ttl = Duration::from_secs(3600);
        for seed in [0u64, 1, 42, 1_700_000_000, u64::MAX] {
            let j = jitter_seconds(seed, ttl);
            assert!(j <= 360, "jitter {j} exceeded 10% of {}", ttl.as_secs());
        }
    }

    #[test]
    fn jitter_is_deterministic_per_seed() {
        let ttl = Duration::from_secs(3600);
        assert_eq!(jitter_seconds(12345, ttl), jitter_seconds(12345, ttl));
    }

    #[test]
    fn jitter_zero_for_short_ttl() {
        // TTL < 10 seconds → integer division gives span=0 → no jitter.
        assert_eq!(jitter_seconds(42, Duration::from_secs(5)), 0);
    }

    #[test]
    fn is_newer_semver_basic() {
        assert!(is_newer_semver("1.0.1", "1.0.0"));
        assert!(is_newer_semver("0.25.0", "0.24.99"));
        assert!(!is_newer_semver("1.0.0", "1.0.0"));
        assert!(!is_newer_semver("0.9.9", "1.0.0"));
    }

    #[test]
    fn is_newer_semver_handles_prerelease_correctly() {
        // npm semver: a stable release is newer than its matching
        // prerelease, and a prerelease is older than its stable.
        // Locks the contract so a future swap of the comparator
        // backend doesn't silently regress to tuple-only comparison.
        assert!(is_newer_semver("0.25.0", "0.25.0-rc.1"));
        assert!(!is_newer_semver("0.25.0-rc.1", "0.25.0"));
        assert!(is_newer_semver("0.25.1", "0.25.0-rc.1"));
        // Prerelease ordering within the same MAJOR.MINOR.PATCH:
        // rc.2 > rc.1, alpha < beta, etc.
        assert!(is_newer_semver("1.0.0-rc.2", "1.0.0-rc.1"));
        assert!(is_newer_semver("1.0.0-beta", "1.0.0-alpha"));
    }

    #[test]
    fn is_newer_semver_unparseable_returns_false() {
        // GitHub controls the tag namespace, so if a malformed tag
        // ever arrives we'd rather refuse to upgrade than guess.
        assert!(!is_newer_semver("not-a-version", "0.25.0"));
        assert!(!is_newer_semver("0.25.0", "not-a-version"));
        assert!(!is_newer_semver("nightly-2026-05-03", "0.25.0"));
    }

    #[test]
    fn format_reset_hint_in_future() {
        let now = now_secs();
        let hint = format_reset_hint(now + 90);
        assert!(hint.contains("minute"), "hint: {hint}");
    }

    #[test]
    fn format_reset_hint_under_minute() {
        let now = now_secs();
        let hint = format_reset_hint(now + 30);
        assert!(hint.contains("seconds"), "hint: {hint}");
    }

    #[test]
    fn format_reset_hint_in_past_says_now() {
        let now = now_secs();
        let hint = format_reset_hint(now.saturating_sub(60));
        assert_eq!(hint, "Try again now");
    }

    #[test]
    fn lookup_error_display_includes_reset_hint() {
        let now = now_secs();
        let err = LookupError::RateLimited {
            reset_at: Some(now + 600),
        };
        let s = err.to_string();
        assert!(s.contains("rate limit"), "msg: {s}");
        assert!(s.contains("Try again in"), "msg: {s}");
        // GITHUB_TOKEN guidance must NOT live in the LookupError body
        // any more — it's owned by the wrapping
        // `LpmError::SelfUpdateRateLimited` diagnostic help text.
        // Duplicating it here would double-print on screen.
        assert!(
            !s.contains("GITHUB_TOKEN"),
            "GITHUB_TOKEN hint must not duplicate the wrapper's help: {s}"
        );
        assert!(
            !s.contains("GH_TOKEN"),
            "GH_TOKEN hint must not duplicate the wrapper's help: {s}"
        );
    }

    #[test]
    fn lookup_error_display_without_reset_hint() {
        let s = LookupError::RateLimited { reset_at: None }.to_string();
        assert!(s.contains("rate limit"));
        assert!(!s.contains("Try again in"));
        assert!(!s.contains("GITHUB_TOKEN"));
    }

    /// Rendered body must not carry stray tab characters from the
    /// previous multi-line continuation. The pre-cleanup body had a
    /// hard-tab indent inside the format string that surfaced as
    /// `…minutes.\t\t\t\t Set GITHUB_TOKEN…` in the user's terminal.
    #[test]
    fn lookup_error_display_has_no_stray_whitespace_artifacts() {
        let now = now_secs();
        let with_reset = LookupError::RateLimited {
            reset_at: Some(now + 600),
        }
        .to_string();
        assert!(
            !with_reset.contains('\t'),
            "tab leaked into body: {with_reset:?}"
        );
        // Also: no double spaces from concatenation gone wrong.
        assert!(
            !with_reset.contains("  "),
            "double space leaked into body: {with_reset:?}"
        );
    }

    #[test]
    fn lookup_error_display_http_status_with_excerpt() {
        let s = LookupError::HttpStatus {
            status: 502,
            body_excerpt: "bad gateway".into(),
        }
        .to_string();
        assert!(s.contains("502"));
        assert!(s.contains("bad gateway"));
        // Source-agnostic wording: `HttpStatus` can come from either
        // the npm or GitHub probe leg, so the body must NOT pre-blame
        // GitHub. The pre-cleanup wording attributed every HTTP error
        // to "GitHub API" which lied for npm-leg failures.
        assert!(
            !s.contains("GitHub"),
            "HttpStatus body must stay source-agnostic: {s}"
        );
    }

    /// Same source-neutrality contract for `MalformedResponse` — both
    /// probe legs construct it on parse failure, so the body must not
    /// pre-blame either.
    #[test]
    fn lookup_error_display_malformed_is_source_agnostic() {
        let s = LookupError::MalformedResponse("missing version".into()).to_string();
        assert!(
            !s.contains("GitHub") && !s.contains("npm"),
            "MalformedResponse body must stay source-agnostic: {s}"
        );
        assert!(s.contains("missing version"));
    }

    /// npm registry response: extract `version`. Shape is `{ "name":
    /// "@lpm-registry/cli", "version": "0.37.0", ... }`.
    #[test]
    fn extract_version_npm_happy_path() {
        let body = serde_json::json!({
            "name": "@lpm-registry/cli",
            "version": "0.37.0",
        });
        let v = extract_version(Source::Npm, &body).unwrap();
        assert_eq!(v, "0.37.0");
    }

    /// npm responses have a bare numeric version (no `v` prefix). The
    /// strip-prefix branch is GitHub-only — verify we don't accidentally
    /// strip the leading digit.
    #[test]
    fn extract_version_npm_does_not_strip_v_prefix() {
        let body = serde_json::json!({ "version": "v0.37.0" });
        let v = extract_version(Source::Npm, &body).unwrap();
        assert_eq!(v, "v0.37.0", "npm version field is verbatim");
    }

    #[test]
    fn extract_version_npm_missing_field_errors() {
        let body = serde_json::json!({ "name": "@lpm-registry/cli" });
        assert!(matches!(
            extract_version(Source::Npm, &body),
            Err(LookupError::MalformedResponse(_))
        ));
    }

    #[test]
    fn extract_version_npm_empty_field_errors() {
        let body = serde_json::json!({ "version": "" });
        assert!(matches!(
            extract_version(Source::Npm, &body),
            Err(LookupError::MalformedResponse(_))
        ));
    }

    /// GitHub Releases response: extract `tag_name` and strip the `v`
    /// prefix to match the user-facing semver.
    #[test]
    fn extract_version_github_strips_v_prefix() {
        let body = serde_json::json!({ "tag_name": "v0.37.0" });
        let v = extract_version(Source::GitHub, &body).unwrap();
        assert_eq!(v, "0.37.0");
    }

    #[test]
    fn extract_version_github_without_v_prefix() {
        let body = serde_json::json!({ "tag_name": "0.37.0" });
        let v = extract_version(Source::GitHub, &body).unwrap();
        assert_eq!(v, "0.37.0");
    }

    #[test]
    fn extract_version_github_missing_field_errors() {
        let body = serde_json::json!({});
        assert!(matches!(
            extract_version(Source::GitHub, &body),
            Err(LookupError::MalformedResponse(_))
        ));
    }

    /// `LPM_NPM_REGISTRY_URL_OVERRIDE` lets tests and private-mirror
    /// users redirect the probe. Empty string is treated as unset to
    /// avoid blowing away the default if a script does
    /// `export LPM_NPM_REGISTRY_URL_OVERRIDE=` on accident.
    ///
    /// Routes through the same `acquire_env_override_lock` as the
    /// async wiremock tests so plain `cargo test` (parallel by default)
    /// doesn't race this against them — without the lock, concurrent
    /// tests can hit the real GitHub rate limit through env-var
    /// bleed-through.
    #[test]
    fn npm_registry_url_respects_override_env_var() {
        let _restore = acquire_env_override_lock();
        // SAFETY: lock held for the lifetime of `_restore`.
        unsafe { std::env::set_var(NPM_OVERRIDE_KEY, "http://localhost:9999/foo") };
        assert_eq!(npm_registry_url(), "http://localhost:9999/foo");
        unsafe { std::env::set_var(NPM_OVERRIDE_KEY, "") };
        assert_eq!(
            npm_registry_url(),
            NPM_REGISTRY_URL_DEFAULT,
            "empty override falls back to default"
        );
        // `_restore`'s Drop runs at end of scope and rewinds env state.
    }

    /// End-to-end cascade test: when the npm primary returns a fresh
    /// version, GitHub is never contacted. Counts requests against a
    /// wiremock instance to prove it.
    #[tokio::test]
    async fn probe_release_uses_npm_primary_when_healthy() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let npm = MockServer::start().await;
        let gh = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/@lpm-registry/cli/latest"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({ "version": "9.9.9" })),
            )
            .expect(1)
            .mount(&npm)
            .await;

        // GitHub mock with `expect(0)` makes wiremock fail on drop if
        // it ever receives a request — proves the cascade short-circuits.
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(500))
            .expect(0)
            .mount(&gh)
            .await;

        let npm_url = format!("{}/@lpm-registry/cli/latest", npm.uri());
        let gh_url = format!("{}/repos/lpm-dev/rust-client/releases/latest", gh.uri());
        with_env_overrides(&npm_url, &gh_url, async {
            let mut cache = UpdateCache::default();
            let outcome = probe_release(&mut cache).await.expect("npm probe ok");
            assert_eq!(
                outcome,
                FetchOutcome::Fresh {
                    version: "9.9.9".into()
                }
            );
            assert_eq!(cache.latest, "9.9.9");
            assert_ne!(cache.last_check, 0);
            assert_eq!(cache.last_failure_check, 0);
        })
        .await;
    }

    /// End-to-end cascade test: when the npm primary fails (e.g. 503),
    /// GitHub is contacted and a successful fallback response wins.
    #[tokio::test]
    async fn probe_release_falls_back_to_github_on_npm_failure() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let npm = MockServer::start().await;
        let gh = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/@lpm-registry/cli/latest"))
            .respond_with(ResponseTemplate::new(503))
            .expect(1)
            .mount(&npm)
            .await;

        Mock::given(method("GET"))
            .and(path("/repos/lpm-dev/rust-client/releases/latest"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({ "tag_name": "v8.8.8" })),
            )
            .expect(1)
            .mount(&gh)
            .await;

        let npm_url = format!("{}/@lpm-registry/cli/latest", npm.uri());
        let gh_url = format!("{}/repos/lpm-dev/rust-client/releases/latest", gh.uri());
        with_env_overrides(&npm_url, &gh_url, async {
            let mut cache = UpdateCache::default();
            let outcome = probe_release(&mut cache).await.expect("github fallback ok");
            assert_eq!(
                outcome,
                FetchOutcome::Fresh {
                    version: "8.8.8".into()
                }
            );
            assert_eq!(cache.latest, "8.8.8");
            // last_failure_check must end at 0: the cascade succeeded
            // overall, even though the npm leg of it bumped the
            // failure timestamp before the GitHub leg cleared it.
            assert_eq!(cache.last_failure_check, 0);
        })
        .await;
    }

    /// End-to-end cascade test: when both probes fail with non-rate-limit
    /// errors, the npm error is reported (it's the primary path).
    #[tokio::test]
    async fn probe_release_reports_npm_error_when_both_fail() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let npm = MockServer::start().await;
        let gh = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/@lpm-registry/cli/latest"))
            .respond_with(ResponseTemplate::new(503).set_body_string("npm down"))
            .mount(&npm)
            .await;

        Mock::given(method("GET"))
            .and(path("/repos/lpm-dev/rust-client/releases/latest"))
            .respond_with(ResponseTemplate::new(500).set_body_string("gh down"))
            .mount(&gh)
            .await;

        let npm_url = format!("{}/@lpm-registry/cli/latest", npm.uri());
        let gh_url = format!("{}/repos/lpm-dev/rust-client/releases/latest", gh.uri());
        with_env_overrides(&npm_url, &gh_url, async {
            let mut cache = UpdateCache::default();
            let err = probe_release(&mut cache).await.expect_err("both legs fail");
            // Primary error wins. The npm 503 body excerpt should
            // appear, not the GitHub 500 body.
            let s = err.to_string();
            assert!(s.contains("503"), "expected primary npm error: {s}");
        })
        .await;
    }

    /// Cascade reachability for `LookupError::RateLimited`: when npm
    /// fails (any non-rate-limit reason) AND GitHub returns a 403 with
    /// `x-ratelimit-remaining: 0`, the user must see the GitHub
    /// rate-limit error — NOT the generic npm error. Without this
    /// preference rule the entire `SelfUpdateRateLimited` UX surface
    /// ships dead: the only way `RateLimited` gets constructed is the
    /// GitHub leg, and the npm-error-wins cascade would shadow it on
    /// every two-leg failure that hits a rate limit on the fallback.
    #[tokio::test]
    async fn probe_release_surfaces_github_rate_limit_over_npm_failure() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let npm = MockServer::start().await;
        let gh = MockServer::start().await;

        // npm leg: generic 503 — could equally be transport error or
        // 5xx, none carry a structured remediation.
        Mock::given(method("GET"))
            .and(path("/@lpm-registry/cli/latest"))
            .respond_with(ResponseTemplate::new(503).set_body_string("npm temporarily down"))
            .mount(&npm)
            .await;

        // GitHub leg: 403 with the primary-rate-limit headers so the
        // wrapper surfaces `LpmError::SelfUpdateRateLimited` with
        // GITHUB_TOKEN help text — the payoff of running the cascade
        // in this order.
        let reset_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            + 600;
        let reset_at_header = reset_at.to_string();
        Mock::given(method("GET"))
            .and(path("/repos/lpm-dev/rust-client/releases/latest"))
            .respond_with(
                ResponseTemplate::new(403)
                    .insert_header("x-ratelimit-remaining", "0")
                    .insert_header("x-ratelimit-reset", reset_at_header.as_str())
                    .set_body_string("rate limited"),
            )
            .mount(&gh)
            .await;

        let npm_url = format!("{}/@lpm-registry/cli/latest", npm.uri());
        let gh_url = format!("{}/repos/lpm-dev/rust-client/releases/latest", gh.uri());
        with_env_overrides(&npm_url, &gh_url, async {
            let mut cache = UpdateCache::default();
            let err = probe_release(&mut cache).await.expect_err("both legs fail");
            assert!(
                matches!(err, LookupError::RateLimited { .. }),
                "expected RateLimited to win the cascade, got {err:?}"
            );
            let LookupError::RateLimited { reset_at: got } = err else {
                unreachable!()
            };
            assert_eq!(
                got,
                Some(reset_at),
                "x-ratelimit-reset must round-trip from the GitHub leg"
            );
        })
        .await;
    }

    /// Pure unit test for the cascade preference rule. Locks the
    /// "RateLimited wins, otherwise npm wins" policy independently of
    /// the wiremock end-to-end so a future refactor that inverts the
    /// rule fails this small focused test first.
    #[test]
    fn prefer_more_actionable_picks_github_rate_limit_over_npm_error() {
        let npm = LookupError::HttpStatus {
            status: 503,
            body_excerpt: "npm down".into(),
        };
        let gh = LookupError::RateLimited {
            reset_at: Some(1_700_000_600),
        };
        let chosen = prefer_more_actionable(npm, gh);
        assert!(matches!(chosen, LookupError::RateLimited { .. }));
    }

    #[test]
    fn prefer_more_actionable_picks_npm_when_github_is_not_rate_limited() {
        let npm = LookupError::Transport("npm dns failed".into());
        let gh = LookupError::HttpStatus {
            status: 500,
            body_excerpt: "gh down".into(),
        };
        let chosen = prefer_more_actionable(npm, gh);
        // npm is the primary; non-rate-limit GitHub failure does not
        // displace it.
        let s = chosen.to_string();
        assert!(s.contains("npm dns failed"), "expected npm error: {s}");
    }

    // ─── Env-override test isolation ─────────────────────────────────
    //
    // The `with_env_overrides` async helper AND the sync
    // `npm_registry_url_respects_override_env_var` test both mutate
    // the same process-global override env vars
    // (`LPM_NPM_REGISTRY_URL_OVERRIDE` /
    // `LPM_GITHUB_RELEASES_URL_OVERRIDE`). Under default `cargo test`
    // parallelism these races caused flakes — when two wiremock tests
    // ran concurrently they could swap each other's URLs mid-probe and
    // hit the real registries. The GitHub release probe can reproduce
    // rate-limit bleed-through in exactly this shape.
    //
    // Lock is a plain `std::sync::Mutex<()>` (held across `.await` in
    // async tests) because `#[tokio::test]` defaults to the
    // current-thread runtime — there's no work-stealing scheduler that
    // could move the future across threads while the guard is held.
    // The `unwrap_or_else(into_inner)` shape ignores poison: if a test
    // panics while holding the lock, downstream tests still serialize
    // correctly; the guarded `()` carries no state to corrupt.

    const NPM_OVERRIDE_KEY: &str = "LPM_NPM_REGISTRY_URL_OVERRIDE";
    const GH_OVERRIDE_KEY: &str = "LPM_GITHUB_RELEASES_URL_OVERRIDE";

    fn env_override_lock() -> &'static std::sync::Mutex<()> {
        static LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
        LOCK.get_or_init(|| std::sync::Mutex::new(()))
    }

    /// RAII guard that restores the override env vars on drop.
    /// Restores fire on normal scope exit AND on panic, so a failing
    /// test doesn't pollute env state for the next test in line.
    /// Captured previous values are stored verbatim — `None` means
    /// "was unset", `Some(v)` means "was `v`".
    struct EnvOverrideGuard {
        npm_prev: Option<String>,
        gh_prev: Option<String>,
        _lock: std::sync::MutexGuard<'static, ()>,
    }

    impl Drop for EnvOverrideGuard {
        fn drop(&mut self) {
            // SAFETY: env mutation is unsafe in 2024 edition; serialised
            // via `_lock` so no other thread can observe a half-restored
            // pair.
            unsafe {
                match &self.npm_prev {
                    Some(v) => std::env::set_var(NPM_OVERRIDE_KEY, v),
                    None => std::env::remove_var(NPM_OVERRIDE_KEY),
                }
                match &self.gh_prev {
                    Some(v) => std::env::set_var(GH_OVERRIDE_KEY, v),
                    None => std::env::remove_var(GH_OVERRIDE_KEY),
                }
            }
        }
    }

    /// Acquire the global env-override lock and snapshot the current
    /// values. The returned guard restores both vars when dropped.
    fn acquire_env_override_lock() -> EnvOverrideGuard {
        let lock = env_override_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        EnvOverrideGuard {
            npm_prev: std::env::var(NPM_OVERRIDE_KEY).ok(),
            gh_prev: std::env::var(GH_OVERRIDE_KEY).ok(),
            _lock: lock,
        }
    }

    /// Helper: set npm + GitHub URL overrides for the duration of an
    /// async block. Lock-isolated and panic-safe via
    /// [`EnvOverrideGuard`].
    async fn with_env_overrides<F>(npm_url: &str, gh_url: &str, fut: F)
    where
        F: std::future::Future<Output = ()>,
    {
        let _restore = acquire_env_override_lock();
        // SAFETY: lock held for the lifetime of `_restore`.
        unsafe {
            std::env::set_var(NPM_OVERRIDE_KEY, npm_url);
            std::env::set_var(GH_OVERRIDE_KEY, gh_url);
        }
        fut.await;
        // `_restore`'s Drop runs at end of scope and rewinds env state.
    }

    #[test]
    fn lookup_error_display_http_status_no_excerpt() {
        let s = LookupError::HttpStatus {
            status: 500,
            body_excerpt: String::new(),
        }
        .to_string();
        assert!(s.contains("500"));
        assert!(!s.contains(": "), "no trailing colon when body empty: {s}");
    }

    // ── Override gating (H9) ──────────────────────────────

    /// HTTPS override on any host is accepted — covers legitimate
    /// private-mirror configurations like
    /// `https://npm.internal.example.com/@lpm-registry/cli/latest`.
    #[test]
    fn accept_override_allows_https_any_host() {
        assert!(accept_override("https://npm.internal.example.com/x"));
        assert!(accept_override(
            "https://registry.npmjs.org/@lpm-registry/cli/latest"
        ));
    }

    /// Plain-HTTP override on a non-loopback host is the H9 attack
    /// shape — a compromised env var redirects the version probe to
    /// an attacker-controlled server, which combined with the lack
    /// of binary signature verification on the standalone update
    /// channel (C2) becomes an RCE chain. Reject.
    #[test]
    fn accept_override_rejects_http_non_loopback() {
        assert!(!accept_override("http://attacker.example/x"));
        assert!(!accept_override("http://npm.internal.example.com/y"));
    }

    /// HTTP loopback URLs are accepted — wiremock binds to
    /// `127.0.0.1:PORT` and the rest of this module's tests depend
    /// on the carve-out. `localhost`, `127.0.0.1`, and IPv6 `[::1]`
    /// all qualify.
    #[test]
    fn accept_override_allows_http_loopback() {
        assert!(accept_override("http://127.0.0.1:9999/foo"));
        assert!(accept_override("http://localhost:8080/x"));
        assert!(accept_override("http://[::1]:8080/x"));
        // Any address in the 127.0.0.0/8 block.
        assert!(accept_override("http://127.255.255.254/y"));
    }

    #[test]
    fn accept_override_rejects_unsupported_schemes_and_malformed() {
        assert!(!accept_override("ftp://localhost/x"));
        assert!(!accept_override("file:///tmp/foo"));
        assert!(!accept_override("not a url"));
        assert!(!accept_override(""));
    }

    /// End-to-end through `resolve_release_url`: a rejected override
    /// falls back to the default URL (and emits a `warn` log; we
    /// don't capture tracing in this unit test but the assertion
    /// proves the fallback path is taken).
    #[test]
    fn resolve_release_url_falls_back_to_default_on_rejected_override() {
        let _restore = acquire_env_override_lock();
        // SAFETY: lock held for the lifetime of `_restore`.
        unsafe {
            std::env::set_var(NPM_OVERRIDE_KEY, "http://attacker.example/x");
        }
        assert_eq!(
            resolve_release_url(NPM_OVERRIDE_KEY, NPM_REGISTRY_URL_DEFAULT),
            NPM_REGISTRY_URL_DEFAULT,
            "non-loopback HTTP override must NOT steer the lookup",
        );
        unsafe { std::env::remove_var(NPM_OVERRIDE_KEY) };
    }

    /// And the positive path: an accepted override IS used.
    #[test]
    fn resolve_release_url_honors_accepted_override() {
        let _restore = acquire_env_override_lock();
        // SAFETY: lock held for the lifetime of `_restore`.
        unsafe {
            std::env::set_var(NPM_OVERRIDE_KEY, "https://npm.internal.example.com/x");
        }
        assert_eq!(
            resolve_release_url(NPM_OVERRIDE_KEY, NPM_REGISTRY_URL_DEFAULT),
            "https://npm.internal.example.com/x",
            "HTTPS override must steer the lookup",
        );
        unsafe { std::env::remove_var(NPM_OVERRIDE_KEY) };
    }

    // ── fetch_github_release_published_at ─────────────────────────

    const RELEASE_BY_TAG_OVERRIDE_KEY: &str = "LPM_GITHUB_RELEASE_BY_TAG_URL_OVERRIDE";

    /// Drop guard that restores `LPM_GITHUB_RELEASE_BY_TAG_URL_OVERRIDE`
    /// to whatever value (or absence) preceded the test. Uses the same
    /// `env_override_lock` as the older NPM/GH overrides because all
    /// release-lookup tests need to serialise env mutation.
    struct ReleaseByTagOverrideGuard {
        prev: Option<String>,
        _lock: std::sync::MutexGuard<'static, ()>,
    }

    impl Drop for ReleaseByTagOverrideGuard {
        fn drop(&mut self) {
            unsafe {
                match &self.prev {
                    Some(v) => std::env::set_var(RELEASE_BY_TAG_OVERRIDE_KEY, v),
                    None => std::env::remove_var(RELEASE_BY_TAG_OVERRIDE_KEY),
                }
            }
        }
    }

    async fn with_release_by_tag_override<F>(template: &str, fut: F)
    where
        F: std::future::Future<Output = ()>,
    {
        let lock = env_override_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let guard = ReleaseByTagOverrideGuard {
            prev: std::env::var(RELEASE_BY_TAG_OVERRIDE_KEY).ok(),
            _lock: lock,
        };
        unsafe { std::env::set_var(RELEASE_BY_TAG_OVERRIDE_KEY, template) };
        fut.await;
        drop(guard);
    }

    #[tokio::test]
    async fn fetch_github_release_published_at_parses_timestamp() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/releases/tags/v0.42.0"))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "tag_name": "v0.42.0",
                    "published_at": "2026-05-10T12:34:56Z",
                })),
            )
            .mount(&server)
            .await;

        let template = format!("{}/releases/tags/v{{tag}}", server.uri());
        with_release_by_tag_override(&template, async {
            let parsed = fetch_github_release_published_at("0.42.0")
                .await
                .expect("must parse");
            assert_eq!(parsed.to_rfc3339(), "2026-05-10T12:34:56+00:00");
        })
        .await;
    }

    #[tokio::test]
    async fn fetch_github_release_published_at_errors_on_404() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/releases/tags/v9.9.9"))
            .respond_with(wiremock::ResponseTemplate::new(404))
            .mount(&server)
            .await;

        let template = format!("{}/releases/tags/v{{tag}}", server.uri());
        with_release_by_tag_override(&template, async {
            let err = fetch_github_release_published_at("9.9.9")
                .await
                .expect_err("404 must surface");
            assert!(
                matches!(err, LookupError::NotFound(_)),
                "expected NotFound, got: {err:?}"
            );
        })
        .await;
    }

    #[tokio::test]
    async fn fetch_github_release_published_at_errors_on_missing_field() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/releases/tags/v0.42.0"))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "tag_name": "v0.42.0",
                })),
            )
            .mount(&server)
            .await;

        let template = format!("{}/releases/tags/v{{tag}}", server.uri());
        with_release_by_tag_override(&template, async {
            let err = fetch_github_release_published_at("0.42.0")
                .await
                .expect_err("missing published_at must surface");
            match err {
                LookupError::MalformedResponse(msg) => {
                    assert!(msg.contains("published_at"), "msg: {msg}");
                }
                other => panic!("wrong variant: {other:?}"),
            }
        })
        .await;
    }

    #[tokio::test]
    async fn fetch_github_release_published_at_errors_on_malformed_timestamp() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/releases/tags/v0.42.0"))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "tag_name": "v0.42.0",
                    "published_at": "not-a-date",
                })),
            )
            .mount(&server)
            .await;

        let template = format!("{}/releases/tags/v{{tag}}", server.uri());
        with_release_by_tag_override(&template, async {
            let err = fetch_github_release_published_at("0.42.0")
                .await
                .expect_err("malformed timestamp must surface");
            match err {
                LookupError::MalformedResponse(msg) => {
                    assert!(msg.contains("not RFC 3339"), "msg: {msg}");
                }
                other => panic!("wrong variant: {other:?}"),
            }
        })
        .await;
    }
}
