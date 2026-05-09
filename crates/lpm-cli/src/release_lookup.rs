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
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Resolve the npm registry endpoint. Honours
/// `LPM_NPM_REGISTRY_URL_OVERRIDE` so tests (and users behind a private
/// npm mirror) can redirect the probe without a binary rebuild.
fn npm_registry_url() -> String {
    std::env::var("LPM_NPM_REGISTRY_URL_OVERRIDE")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| NPM_REGISTRY_URL_DEFAULT.to_string())
}

/// Resolve the GitHub Releases endpoint. Honours
/// `LPM_GITHUB_RELEASES_URL_OVERRIDE` for tests.
fn github_releases_url() -> String {
    std::env::var("LPM_GITHUB_RELEASES_URL_OVERRIDE")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| GITHUB_RELEASES_URL_DEFAULT.to_string())
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
}

impl std::fmt::Display for LookupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Transport(msg) => write!(f, "network error: {msg}"),
            Self::RateLimited { reset_at } => match reset_at {
                Some(epoch) => write!(
                    f,
                    "GitHub API rate limit hit. {}. \
					 Set GITHUB_TOKEN or GH_TOKEN for 5000 req/hr (vs 60 unauthenticated).",
                    format_reset_hint(*epoch)
                ),
                None => write!(
                    f,
                    "GitHub API rate limit hit. \
					 Set GITHUB_TOKEN or GH_TOKEN for 5000 req/hr (vs 60 unauthenticated)."
                ),
            },
            Self::HttpStatus {
                status,
                body_excerpt,
            } => {
                if body_excerpt.is_empty() {
                    write!(f, "GitHub API returned HTTP {status}")
                } else {
                    write!(f, "GitHub API returned HTTP {status}: {body_excerpt}")
                }
            }
            Self::MalformedResponse(msg) => write!(f, "malformed GitHub response: {msg}"),
        }
    }
}

/// Public form of `format_reset_hint` used by callers building the body
/// of a `LpmError::SelfUpdateRateLimited` message. The user-visible
/// shape is identical to the inline `Display` rendering — drift between
/// the two would confuse anyone comparing CLI output across versions.
pub fn format_rate_limit_summary(reset_at: u64) -> String {
    format!("GitHub fallback rate-limited. {}", format_reset_hint(reset_at))
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
///   user sees a successful update check; if both fail, the npm error
///   is reported (it's the primary path and the more actionable one for
///   most users — github failures often need a token).
/// - npm `MalformedResponse` → also fall back to GitHub. A malformed
///   primary shouldn't block updates if the fallback works.
pub async fn probe_release(cache: &mut UpdateCache) -> Result<FetchOutcome, LookupError> {
    let npm_err = match probe_one(Source::Npm, cache).await {
        Ok(outcome) => return Ok(outcome),
        Err(e) => e,
    };

    match probe_one(Source::GitHub, cache).await {
        Ok(outcome) => Ok(outcome),
        Err(_gh_err) => Err(npm_err),
    }
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

    let client = reqwest::Client::builder()
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
            return Err(LookupError::Transport(e.to_string()));
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
        assert!(s.contains("GITHUB_TOKEN"), "msg: {s}");
    }

    #[test]
    fn lookup_error_display_without_reset_hint() {
        let s = LookupError::RateLimited { reset_at: None }.to_string();
        assert!(s.contains("rate limit"));
        assert!(!s.contains("Try again in"));
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
    #[test]
    fn npm_registry_url_respects_override_env_var() {
        // Locking behavior, not concrete env state — use temp_env if it
        // gets flaky, but for now this is a single-threaded check that
        // also restores the original value.
        let key = "LPM_NPM_REGISTRY_URL_OVERRIDE";
        let prev = std::env::var(key).ok();
        // SAFETY: tests in this module run single-threaded under nextest
        // because they each share the process env.
        unsafe { std::env::set_var(key, "http://localhost:9999/foo") };
        assert_eq!(npm_registry_url(), "http://localhost:9999/foo");
        unsafe { std::env::set_var(key, "") };
        assert_eq!(
            npm_registry_url(),
            NPM_REGISTRY_URL_DEFAULT,
            "empty override falls back to default"
        );
        match prev {
            Some(v) => unsafe { std::env::set_var(key, v) },
            None => unsafe { std::env::remove_var(key) },
        }
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
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({ "version": "9.9.9" })),
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
            let outcome = probe_release(&mut cache)
                .await
                .expect("github fallback ok");
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

    /// End-to-end cascade test: when both probes fail, the npm error is
    /// reported (it's the primary path).
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
            let err = probe_release(&mut cache)
                .await
                .expect_err("both legs fail");
            // Primary error wins. The npm 503 body excerpt should
            // appear, not the GitHub 500 body.
            let s = err.to_string();
            assert!(s.contains("503"), "expected primary npm error: {s}");
        })
        .await;
    }

    /// Helper: set npm + GitHub URL overrides for the duration of an
    /// async block, then restore. Single-threaded by construction —
    /// callers must not run two of these in parallel.
    async fn with_env_overrides<F>(npm_url: &str, gh_url: &str, fut: F)
    where
        F: std::future::Future<Output = ()>,
    {
        let npm_key = "LPM_NPM_REGISTRY_URL_OVERRIDE";
        let gh_key = "LPM_GITHUB_RELEASES_URL_OVERRIDE";
        let prev_npm = std::env::var(npm_key).ok();
        let prev_gh = std::env::var(gh_key).ok();
        unsafe {
            std::env::set_var(npm_key, npm_url);
            std::env::set_var(gh_key, gh_url);
        }
        fut.await;
        unsafe {
            match prev_npm {
                Some(v) => std::env::set_var(npm_key, v),
                None => std::env::remove_var(npm_key),
            }
            match prev_gh {
                Some(v) => std::env::set_var(gh_key, v),
                None => std::env::remove_var(gh_key),
            }
        }
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
}
