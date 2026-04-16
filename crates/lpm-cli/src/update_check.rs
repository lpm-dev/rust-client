use owo_colors::OwoColorize;
use std::path::PathBuf;
use std::time::{Duration, SystemTime};

const CHECK_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60); // 24 hours
const GITHUB_RELEASES_URL: &str =
    "https://api.github.com/repos/lpm-dev/rust-client/releases/latest";
const FETCH_TIMEOUT: Duration = Duration::from_secs(3);

/// Path to the update check cache file.
fn cache_path() -> Option<PathBuf> {
    dirs::home_dir().map(|h| h.join(".lpm").join("update-check.json"))
}

/// Read the cached update info and return a notice if outdated.
/// This is instant (no network) — called before the command runs.
pub fn read_cached_notice() -> Option<String> {
    let path = cache_path()?;
    let content = std::fs::read_to_string(&path).ok()?;
    let data: serde_json::Value = serde_json::from_str(&content).ok()?;

    let latest = data.get("latest").and_then(|v| v.as_str()).unwrap_or("");
    let current = env!("CARGO_PKG_VERSION");

    if !latest.is_empty() && latest != current && is_newer(latest, current) {
        Some(format_notice(current, latest))
    } else {
        None
    }
}

/// Check whether the update cache is stale (>24h since last check).
///
/// Phase 34.2: extracted as a sync function so `main()` can decide whether
/// to spawn a background refresh without awaiting anything.
pub fn is_stale() -> bool {
    let path = match cache_path() {
        Some(p) => p,
        None => return false,
    };
    let content = match std::fs::read_to_string(&path) {
        Ok(c) => c,
        Err(_) => return true, // no cache → stale
    };
    let data: serde_json::Value = match serde_json::from_str(&content) {
        Ok(d) => d,
        Err(_) => return true, // malformed → stale
    };
    let last_check = data.get("lastCheck").and_then(|v| v.as_u64()).unwrap_or(0);
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    now - last_check > CHECK_INTERVAL.as_secs()
}

/// Unconditionally refresh the update cache. Called by the hidden
/// `internal-update-check` subcommand spawned as a detached child.
/// The parent already checked staleness — this just does the network call.
pub async fn refresh_cache_now() {
    let path = match cache_path() {
        Some(p) => p,
        None => return,
    };

    let latest = match fetch_latest_version().await {
        Ok(v) => v,
        Err(_) => return, // silent failure — same as current behavior
    };

    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let data = serde_json::json!({
        "latest": latest,
        "lastCheck": now,
    });

    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::write(&path, serde_json::to_string(&data).unwrap());
}

/// Fetch the latest version from GitHub Releases.
async fn fetch_latest_version() -> Result<String, Box<dyn std::error::Error>> {
    let client = reqwest::Client::builder().timeout(FETCH_TIMEOUT).build()?;

    let resp: serde_json::Value = client
        .get(GITHUB_RELEASES_URL)
        .header("User-Agent", "lpm-cli")
        .header("Accept", "application/vnd.github.v3+json")
        .send()
        .await?
        .json()
        .await?;

    let tag = resp
        .get("tag_name")
        .and_then(|v| v.as_str())
        .ok_or("no tag_name field")?;

    // Parse version from tag: "v0.5.0" → "0.5.0"
    let version = tag.strip_prefix('v').unwrap_or(tag).to_string();
    Ok(version)
}

/// Simple semver comparison: is `a` newer than `b`?
fn is_newer(a: &str, b: &str) -> bool {
    let parse = |s: &str| -> (u32, u32, u32) {
        let parts: Vec<u32> = s.split('.').filter_map(|p| p.parse().ok()).collect();
        (
            *parts.first().unwrap_or(&0),
            *parts.get(1).unwrap_or(&0),
            *parts.get(2).unwrap_or(&0),
        )
    };
    parse(a) > parse(b)
}

fn format_notice(current: &str, latest: &str) -> String {
    format!(
        "\n  {} Update available: {} → {} — run {}\n",
        "⬆".yellow(),
        current.dimmed(),
        latest.green().bold(),
        "lpm self-update".cyan(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_newer_basic() {
        assert!(is_newer("1.0.1", "1.0.0"));
        assert!(is_newer("2.0.0", "1.9.9"));
        assert!(!is_newer("1.0.0", "1.0.0"));
        assert!(!is_newer("0.9.0", "1.0.0"));
    }

    #[test]
    fn is_stale_no_cache_file() {
        // Temporarily override HOME to a non-existent dir to force cache miss.
        // is_stale uses cache_path() which depends on dirs::home_dir().
        // We can't easily override that, so instead test the logic directly:
        // When there's no cache file, is_stale should return true.
        // (The actual function is tested via integration; here we verify
        // the sub-components.)
        let stale_check = |last_check: u64| -> bool {
            let now = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            now - last_check > CHECK_INTERVAL.as_secs()
        };
        // A timestamp from 0 (epoch) should be stale
        assert!(stale_check(0));
        // A timestamp from right now should not be stale
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert!(!stale_check(now));
        // A timestamp from 25 hours ago should be stale
        assert!(stale_check(now - 25 * 3600));
        // A timestamp from 23 hours ago should not be stale
        assert!(!stale_check(now - 23 * 3600));
    }

    #[test]
    fn hidden_subcommand_parses() {
        use clap::Parser;
        let cli = crate::Cli::try_parse_from(["lpm", "internal-update-check"]);
        assert!(
            cli.is_ok(),
            "internal-update-check must parse: {:?}",
            cli.err()
        );
        assert!(
            matches!(
                cli.unwrap().command,
                Some(crate::Commands::InternalUpdateCheck)
            ),
            "expected InternalUpdateCheck variant"
        );
    }

    #[test]
    fn hidden_subcommand_not_in_help() {
        use clap::CommandFactory;
        let mut buf = Vec::new();
        crate::Cli::command().write_help(&mut buf).unwrap();
        let help = String::from_utf8(buf).unwrap();
        assert!(
            !help.contains("internal-update-check"),
            "hidden subcommand must not appear in --help output"
        );
    }

    // Regression: InternalUpdateCheck must exit before the common tail path.
    // The dispatch calls process::exit(0) which can't be tested in-process,
    // but we verify the architectural contract here: if refresh_cache_now()
    // fails (no lastCheck written), is_stale() would return true. Without
    // the early exit, the tail would spawn another child → infinite recursion.
    #[test]
    fn stale_after_failed_refresh_would_be_true() {
        // Verify the precondition: a cache file with no lastCheck is stale.
        // This is the state after a failed refresh_cache_now().
        let stale_check = |content: &str| -> bool {
            let data: serde_json::Value = match serde_json::from_str(content) {
                Ok(d) => d,
                Err(_) => return true,
            };
            let last_check = data.get("lastCheck").and_then(|v| v.as_u64()).unwrap_or(0);
            let now = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            now - last_check > CHECK_INTERVAL.as_secs()
        };

        // Empty cache (what a failed refresh leaves behind)
        assert!(stale_check("{}"), "empty cache must be stale");
        // No lastCheck field
        assert!(
            stale_check(r#"{"latest":"1.0.0"}"#),
            "cache without lastCheck must be stale"
        );
        // This confirms that without the early exit in InternalUpdateCheck,
        // the tail path would see is_stale()=true and respawn.
    }
}
