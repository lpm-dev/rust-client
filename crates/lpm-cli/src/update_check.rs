//! Background update banner — checks once a day, prints a one-line
//! "update available" notice on the next CLI invocation.
//!
//! All shared state (cache file, network probe, semver compare) lives
//! in [`crate::release_lookup`]. This module is just the banner-policy
//! layer: 24h success TTL, 1h failure backoff (with jitter), and the
//! coloured notice formatter.

use crate::release_lookup::{
    default_cache_path, is_newer_semver, is_stale as base_is_stale, probe_release, read_cache_at,
    write_cache_at,
};
use owo_colors::OwoColorize;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Don't probe more than once a day on the success path.
const SUCCESS_TTL: Duration = Duration::from_secs(24 * 60 * 60);

/// On failure, back off for an hour (+ ≤10% jitter) before letting the
/// next invocation fork another refresh child.
const FAILURE_BACKOFF: Duration = Duration::from_secs(60 * 60);

/// Read the cached update info and return a notice if outdated.
/// This is instant (no network) — called before the command runs.
pub fn read_cached_notice() -> Option<String> {
    let path = default_cache_path()?;
    let cache = read_cache_at(&path)?;
    let current = env!("CARGO_PKG_VERSION");
    if !cache.latest.is_empty()
        && cache.latest != current
        && is_newer_semver(&cache.latest, current)
    {
        Some(format_notice(current, &cache.latest))
    } else {
        None
    }
}

/// Has enough time passed since the last probe (success OR failure)
/// that we should fork the background refresh?
///
/// The failure-backoff arm is what stops the offline / rate-limited
/// loop where every `lpm` invocation forked a fresh doomed child.
pub fn is_stale() -> bool {
    let path = match default_cache_path() {
        Some(p) => p,
        None => return false,
    };
    let cache = read_cache_at(&path);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    base_is_stale(cache.as_ref(), now, SUCCESS_TTL, FAILURE_BACKOFF)
}

/// Unconditionally refresh the update cache. Called by the hidden
/// `internal-update-check` subcommand spawned as a detached child.
/// The parent already checked staleness — this just does the network
/// call and persists the result (success OR failure).
pub async fn refresh_cache_now() {
    let path = match default_cache_path() {
        Some(p) => p,
        None => return,
    };

    let mut cache = read_cache_at(&path).unwrap_or_default();
    // `probe_release` mutates `cache` in-place on every outcome:
    // fresh / not-modified bumps `last_check`; failure bumps
    // `last_failure_check`. Either way, persist so the next
    // invocation's staleness gate sees the new state.
    //
    // npm registry is the primary source; GitHub Releases is the
    // fallback. See `release_lookup::probe_release` for cascade rules.
    let _ = probe_release(&mut cache).await;
    let _ = write_cache_at(&path, &cache);
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
    use crate::release_lookup;
    use crate::release_lookup::UpdateCache;

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

    /// Regression: refresh_cache_now must persist the cache even on
    /// network failure, so is_stale() backs off instead of forking
    /// another doomed child on the next invocation. Modeled here by
    /// checking the on-disk staleness contract directly.
    #[test]
    fn cache_with_recent_failure_is_not_stale() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let cache = UpdateCache {
            last_failure_check: now - 60,
            ..Default::default()
        };
        assert!(!release_lookup::is_stale(
            Some(&cache),
            now,
            SUCCESS_TTL,
            FAILURE_BACKOFF,
        ));
    }

    #[test]
    fn notice_appears_only_when_strictly_newer() {
        // Direct check of the comparator branch the banner uses.
        assert!(is_newer_semver("99.0.0", env!("CARGO_PKG_VERSION")));
        assert!(!is_newer_semver(env!("CARGO_PKG_VERSION"), "99.0.0"));
    }
}
