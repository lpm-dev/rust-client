//! Shared GitHub Releases lookup with on-disk cache.
//!
//! Two consumers share this module:
//! - `update_check` — background banner refresh (24h success TTL).
//! - `commands::self_update` — user-facing update command (10m success TTL).
//!
//! Both read and write the same file (`~/.lpm/update-check.json`) so an
//! explicit `lpm self-update` doubles as a banner refresh.
//!
//! Network calls go through a single helper that:
//! - Sends `If-None-Match` from the cached etag (304 → reuse cached version).
//! - Honours `GITHUB_TOKEN` / `GH_TOKEN` (60→5000 req/hr).
//! - Maps 403 + `x-ratelimit-remaining: 0` to a typed rate-limit error
//!   carrying the reset epoch from `x-ratelimit-reset`.
//! - Stamps `last_failure_check` on every failed attempt so the staleness
//!   gate backs off offline / rate-limited callers instead of forking a
//!   doomed background child on every invocation.

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const GITHUB_RELEASES_URL: &str =
    "https://api.github.com/repos/lpm-dev/rust-client/releases/latest";
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

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

    /// Cached `ETag` from the most recent successful response.
    /// Sent as `If-None-Match` on the next probe so a 304 reuses the
    /// stored `latest` without re-downloading the JSON.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub etag: String,
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

/// Probe GitHub Releases. On success, mutates `cache` with the fresh
/// version + new etag + bumps `last_check`. On 304, just bumps
/// `last_check` (cached version stays). On any failure, bumps
/// `last_failure_check` and returns the typed error.
///
/// Caller is responsible for persisting the cache via `write_cache_at`.
pub async fn probe_github(cache: &mut UpdateCache) -> Result<FetchOutcome, LookupError> {
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

    let mut req = client
        .get(GITHUB_RELEASES_URL)
        .header("User-Agent", "lpm-cli")
        .header("Accept", "application/vnd.github.v3+json");

    if !cache.etag.is_empty() {
        req = req.header("If-None-Match", &cache.etag);
    }
    if let Some(token) = github_token() {
        req = req.header("Authorization", format!("Bearer {token}"));
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

    // 403 with primary rate limit: parse reset hint before returning.
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

    let tag = match body.get("tag_name").and_then(|v| v.as_str()) {
        Some(t) if !t.is_empty() => t,
        _ => {
            cache.last_failure_check = now;
            return Err(LookupError::MalformedResponse("missing tag_name".into()));
        }
    };
    let version = tag.strip_prefix('v').unwrap_or(tag).to_string();

    cache.latest = version.clone();
    cache.last_check = now;
    cache.last_failure_check = 0;
    cache.etag = etag;

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
        };
        write_cache_at(&path, &cache).unwrap();
        let loaded = read_cache_at(&path).unwrap();
        assert_eq!(loaded, cache);
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
            },
        )
        .unwrap();
        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(!raw.contains("lastFailureCheck"), "raw: {raw}");
        assert!(!raw.contains("etag"), "raw: {raw}");
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
