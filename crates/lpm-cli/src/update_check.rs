//! Background update banner — checks once a day, prints a one-line
//! "update available" notice on the next CLI invocation.
//!
//! All shared state (cache file, network probe, semver compare) lives
//! in [`crate::release_lookup`]. This module is just the banner-policy
//! layer: 24h success TTL, 1h failure backoff (with jitter), and the
//! coloured notice formatter.

use crate::commands::self_update::{canonical_account_home, try_acquire_self_update_lock};
use crate::release_channel::ReleaseChannel;
use crate::release_lookup::{
    UpdateCache, default_cache_path, is_newer_semver, is_stale as base_is_stale, probe_release,
    read_cache_at, write_cache_at,
};
use lpm_common::color::Painted;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Don't probe more than once a day on the success path.
const SUCCESS_TTL: Duration = Duration::from_secs(24 * 60 * 60);

/// On failure, back off for an hour (+ ≤10% jitter) before letting the
/// next invocation fork another refresh child.
const FAILURE_BACKOFF: Duration = Duration::from_secs(60 * 60);

/// Read the cached update info and return a notice if outdated.
/// This is instant (no network) — called before the command runs.
pub fn read_cached_notice() -> Option<String> {
    UpdateCheckSnapshot::load().cached_notice()
}

pub struct UpdateCheckSnapshot {
    disabled: bool,
    cache: Option<UpdateCache>,
    now: u64,
    channel: ReleaseChannel,
    current: &'static str,
}

impl UpdateCheckSnapshot {
    pub fn load() -> Self {
        let disabled = update_checks_disabled();
        let cache = (!disabled)
            .then(default_cache_path)
            .flatten()
            .and_then(|path| read_cache_at(&path));
        Self {
            disabled,
            cache,
            now: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            channel: ReleaseChannel::from_installed_version(crate::build_version::version()),
            current: crate::build_version::version(),
        }
    }

    pub fn cached_notice(&self) -> Option<String> {
        if self.disabled {
            return None;
        }
        let latest = self.cache.as_ref()?.latest_for(self.channel);
        if !latest.is_empty() && latest != self.current && is_newer_semver(latest, self.current) {
            Some(format_notice(self.current, latest))
        } else {
            None
        }
    }

    pub fn should_spawn_background_check(&self) -> bool {
        !self.disabled
            && base_is_stale(
                self.cache.as_ref(),
                self.channel,
                self.now,
                SUCCESS_TTL,
                FAILURE_BACKOFF,
            )
    }
}

#[inline]
fn update_checks_disabled() -> bool {
    std::env::var_os("LPM_NO_UPDATE_CHECK").is_some()
}

/// Unconditionally refresh the update cache. Called by the hidden
/// `internal-update-check` subcommand spawned as a detached child.
/// The parent already checked staleness — this just does the network
/// call and persists the result (success OR failure).
pub async fn refresh_cache_now() {
    let account_home = match canonical_account_home() {
        Ok(home) => home,
        Err(_) => return,
    };
    let Some(mut refresh) = prepare_background_refresh(&account_home) else {
        return;
    };

    let channel = ReleaseChannel::from_installed_version(crate::build_version::version());
    // `probe_release` mutates `cache` in-place on every outcome:
    // fresh / not-modified bumps `last_check`; failure bumps
    // `last_failure_check`. Either way, persist so the next
    // invocation's staleness gate sees the new state.
    //
    // npm registry is the primary source; GitHub Releases is the
    // fallback. See `release_lookup::probe_release` for cascade rules.
    let _ = probe_release(channel, &mut refresh.cache).await;
    let _ = write_cache_at(&refresh.path, &refresh.cache);
}

struct BackgroundRefresh {
    path: std::path::PathBuf,
    cache: crate::release_lookup::UpdateCache,
    _operation_lock: lpm_common::SingleFileExclusiveLockHandle,
}

fn prepare_background_refresh(account_home: &Path) -> Option<BackgroundRefresh> {
    let operation_lock = try_acquire_self_update_lock(account_home).ok().flatten()?;
    let path = account_home.join(".lpm").join("update-check.json");
    let cache = read_cache_at(&path).unwrap_or_default();
    Some(BackgroundRefresh {
        path,
        cache,
        _operation_lock: operation_lock,
    })
}

fn format_notice(current: &str, latest: &str) -> String {
    let current = lpm_common::sanitize_terminal_inline(current);
    let latest = lpm_common::sanitize_terminal_inline(latest);
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
    fn update_notice_versions_cannot_inject_terminal_rows_or_controls() {
        let hostile = "safe\nFORGED\rrewritten\u{8}\u{1b}]52;c;AAAA\u{7}\u{0090}hidden\u{009c}end";
        let notice = format_notice(hostile, hostile);

        assert_eq!(notice.matches('\n').count(), 2, "{notice:?}");
        assert!(!notice.contains("\u{1b}]52"), "{notice:?}");
        assert!(!notice.contains(['\r', '\u{8}', '\u{7}']), "{notice:?}");
        assert!(!notice.contains("hidden"), "{notice:?}");
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
            ReleaseChannel::Stable,
            now,
            SUCCESS_TTL,
            FAILURE_BACKOFF,
        ));
    }

    #[test]
    fn notice_appears_only_when_strictly_newer() {
        // Direct check of the comparator branch the banner uses.
        assert!(is_newer_semver("99.0.0", crate::build_version::version()));
        assert!(!is_newer_semver(crate::build_version::version(), "99.0.0"));
    }

    #[test]
    fn background_refresh_skips_while_self_update_owns_the_operation_lock() {
        let account_home = tempfile::tempdir().unwrap();
        let account_home = std::fs::canonicalize(account_home.path()).unwrap();
        let _self_update_lock =
            crate::commands::self_update::acquire_self_update_lock(&account_home).unwrap();

        assert!(prepare_background_refresh(&account_home).is_none());
    }

    #[test]
    fn background_refresh_preserves_the_other_release_channel_fields() {
        let account_home = tempfile::tempdir().unwrap();
        let account_home = std::fs::canonicalize(account_home.path()).unwrap();
        let cache_path = account_home.join(".lpm").join("update-check.json");
        std::fs::create_dir_all(cache_path.parent().unwrap()).unwrap();
        std::fs::write(
            &cache_path,
            serde_json::to_vec(&serde_json::json!({
                "latest": "0.74.1",
                "lastCheck": 1_700_000_000_u64,
                "nightly": {
                    "latest": "0.75.0-nightly.20260817.1.abcdef0",
                    "lastCheck": 1_700_000_100_u64,
                    "npmEtag": "n1"
                }
            }))
            .unwrap(),
        )
        .unwrap();

        let mut refresh = prepare_background_refresh(&account_home).unwrap();
        refresh
            .cache
            .record_success_for(ReleaseChannel::Stable, "0.74.2".into(), 1_700_000_200);
        write_cache_at(&refresh.path, &refresh.cache).unwrap();
        drop(refresh);
        let persisted = read_cache_at(&cache_path).unwrap();
        let persisted_json = serde_json::to_value(&persisted).unwrap();

        assert_eq!(
            persisted.latest_for(ReleaseChannel::Nightly),
            "0.75.0-nightly.20260817.1.abcdef0"
        );
        assert_eq!(
            persisted_json.pointer("/nightly/npmEtag"),
            Some(&"n1".into())
        );
    }
}
