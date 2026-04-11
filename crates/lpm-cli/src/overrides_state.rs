//! **Phase 32 Phase 5 — `<project_dir>/.lpm/overrides-state.json` persistence layer.**
//!
//! Mirrors the [`crate::build_state`] pattern for the override apply
//! trace. The state file persists three things across installs:
//!
//! 1. The deterministic **fingerprint** of the parsed override set, so
//!    the lockfile fast path can be invalidated when the user edits
//!    `lpm.overrides` / `overrides` / `resolutions` between runs. Without
//!    this, the lockfile would silently shadow override changes.
//! 2. The list of **parsed entries**, so introspection commands can
//!    read what was declared without re-parsing `package.json`.
//! 3. The list of **applied hits**, so `lpm graph --why` can decorate
//!    paths with the override that touched them.
//!
//! ## Location
//!
//! `<project_dir>/.lpm/overrides-state.json`. Same convention as
//! `build-state.json` and `install-hash` — next to `package.json`,
//! survives `rm -rf node_modules`.
//!
//! ## Schema versioning
//!
//! [`OVERRIDES_STATE_VERSION`] is bumped on every breaking change.
//! Readers return `None` (and the install pipeline treats the absent
//! state as "first run") on a version mismatch — forward-compat is
//! never read state files newer than what we know how to parse.
//!
//! ## Atomic writes
//!
//! [`write_state`] writes to a sibling tempfile and renames into place,
//! mirroring the [`crate::build_state`] writer. A crash mid-write
//! leaves the previous state file intact rather than producing a
//! partially-written file the reader chokes on.

use lpm_common::LpmError;
use lpm_resolver::{
    NpmRangeMatcher, OverrideEntry, OverrideHit, OverrideSelector, OverrideSet, OverrideSource,
    OverrideTarget,
};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Schema version for the on-disk state file. Bump on breaking changes.
pub const OVERRIDES_STATE_VERSION: u32 = 1;

/// Filename inside `<project_dir>/.lpm/`.
pub const OVERRIDES_STATE_FILENAME: &str = "overrides-state.json";

/// Top-level shape of `overrides-state.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OverridesState {
    /// Bumped on every breaking change to this struct or to its
    /// nested types. Readers compare against [`OVERRIDES_STATE_VERSION`]
    /// and treat any mismatch as "no state".
    pub state_version: u32,
    /// Deterministic SHA-256 fingerprint over the parsed override set
    /// (see [`OverrideSet::fingerprint`]). Used by the install pipeline
    /// to invalidate the lockfile fast path when overrides change.
    pub fingerprint: String,
    /// RFC 3339 timestamp of when this state file was written.
    pub captured_at: String,
    /// Every parsed entry in deterministic order. Survives across
    /// installs even when the lockfile fast path is taken — that's
    /// what makes the fingerprint comparison meaningful.
    pub parsed: Vec<ParsedEntry>,
    /// Every override applied during the most recent fresh resolution.
    /// On lockfile-fast-path installs we preserve the previous trace
    /// rather than overwriting it with an empty list (the previous
    /// trace is still accurate — nothing got re-resolved).
    pub applied: Vec<OverrideHit>,
}

/// On-disk shape of one parsed override entry. Mirrors
/// [`OverrideEntry`] but uses owned strings for the selector + target
/// so we can serialize without depending on the resolver's internal
/// types.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParsedEntry {
    pub raw_key: String,
    pub source: OverrideSource,
    pub selector: SelectorView,
    pub target: String,
}

/// Serialization-friendly view of [`OverrideSelector`].
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SelectorView {
    Name {
        name: String,
    },
    NameRange {
        name: String,
        range: String,
    },
    Path {
        parent: String,
        name: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        range: Option<String>,
    },
}

impl ParsedEntry {
    fn from_entry(e: &OverrideEntry) -> Self {
        let selector = match &e.selector {
            OverrideSelector::Name { name } => SelectorView::Name { name: name.clone() },
            OverrideSelector::NameRange { name, range } => SelectorView::NameRange {
                name: name.clone(),
                range: range.raw().to_string(),
            },
            OverrideSelector::Path {
                parent,
                name,
                range,
            } => SelectorView::Path {
                parent: parent.clone(),
                name: name.clone(),
                range: range.as_ref().map(|r| r.raw().to_string()),
            },
        };
        ParsedEntry {
            raw_key: e.raw_key.clone(),
            source: e.source,
            selector,
            target: e.target.raw().to_string(),
        }
    }
}

impl OverridesState {
    /// Build a fresh state object from the parsed overrides + the
    /// runtime apply trace.
    pub fn capture(set: &OverrideSet, applied: Vec<OverrideHit>) -> Self {
        let parsed: Vec<ParsedEntry> = set.entries().map(ParsedEntry::from_entry).collect();
        OverridesState {
            state_version: OVERRIDES_STATE_VERSION,
            fingerprint: set.fingerprint().to_string(),
            captured_at: rfc3339_now(),
            parsed,
            applied,
        }
    }

    /// Build a state object that preserves the previous apply trace.
    /// Used by the lockfile fast path: we want the fingerprint and the
    /// parsed entries to match the *current* `package.json`, but the
    /// applied list to remain whatever the most-recent fresh resolution
    /// recorded (since nothing was re-resolved this time).
    pub fn capture_preserving_applied(
        set: &OverrideSet,
        previous_applied: Vec<OverrideHit>,
    ) -> Self {
        OverridesState {
            state_version: OVERRIDES_STATE_VERSION,
            fingerprint: set.fingerprint().to_string(),
            captured_at: rfc3339_now(),
            parsed: set.entries().map(ParsedEntry::from_entry).collect(),
            applied: previous_applied,
        }
    }

    /// Reconstruct an [`OverrideSet`] from the persisted parsed list.
    /// Used by the install pipeline to compare the current parse to
    /// the previously-persisted parse without re-reading
    /// `package.json`. Returns `None` if any entry fails to round-trip
    /// (e.g., a state file from a newer version with new selector
    /// kinds we don't recognize).
    pub fn rebuild_set(&self) -> Option<OverrideSet> {
        // We don't have a public constructor for OverrideSet that takes
        // already-parsed entries (intentional — `parse()` is the single
        // validation gate). Round-trip via raw maps so the resolver
        // re-validates whatever we persisted. Any drift between persist
        // and reload surfaces here as None and triggers a re-parse from
        // `package.json`.
        use std::collections::HashMap;

        let mut lpm = HashMap::new();
        let mut npm = HashMap::new();
        let mut yarn = HashMap::new();

        for entry in &self.parsed {
            let target_dst = match entry.source {
                OverrideSource::LpmOverrides => &mut lpm,
                OverrideSource::Overrides => &mut npm,
                OverrideSource::Resolutions => &mut yarn,
            };
            target_dst.insert(entry.raw_key.clone(), entry.target.clone());
        }

        OverrideSet::parse(&lpm, &npm, &yarn).ok()
    }
}

/// Return the path to the state file inside `<project_dir>/.lpm/`.
pub fn state_path(project_dir: &Path) -> PathBuf {
    project_dir.join(".lpm").join(OVERRIDES_STATE_FILENAME)
}

/// Read the persisted state if it exists and matches the current
/// schema version. Returns `None` for missing files, parse failures,
/// or version mismatches — the caller treats all three as "first run".
pub fn read_state(project_dir: &Path) -> Option<OverridesState> {
    let path = state_path(project_dir);
    let content = std::fs::read_to_string(&path).ok()?;
    let state: OverridesState = serde_json::from_str(&content).ok()?;
    if state.state_version != OVERRIDES_STATE_VERSION {
        tracing::debug!(
            "overrides-state.json version mismatch: got {}, expected {}",
            state.state_version,
            OVERRIDES_STATE_VERSION
        );
        return None;
    }
    Some(state)
}

/// Atomically write the state file to `<project_dir>/.lpm/`. Creates
/// the `.lpm/` directory if it doesn't exist. The write goes to a
/// sibling tempfile and renames into place so a crash mid-write leaves
/// the previous state intact.
pub fn write_state(project_dir: &Path, state: &OverridesState) -> Result<(), LpmError> {
    let lpm_dir = project_dir.join(".lpm");
    std::fs::create_dir_all(&lpm_dir).map_err(LpmError::Io)?;

    let final_path = lpm_dir.join(OVERRIDES_STATE_FILENAME);
    let tmp_path = lpm_dir.join(format!("{OVERRIDES_STATE_FILENAME}.tmp"));

    let json = serde_json::to_string_pretty(state)
        .map_err(|e| LpmError::Script(format!("failed to serialize overrides state: {e}")))?;

    std::fs::write(&tmp_path, json.as_bytes()).map_err(LpmError::Io)?;
    if let Err(e) = std::fs::rename(&tmp_path, &final_path) {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(LpmError::Io(e));
    }
    Ok(())
}

/// Delete the state file if it exists. Used when the user removes all
/// overrides from `package.json` — we don't want to leave a stale
/// state file behind that would confuse `lpm graph --why`.
pub fn delete_state(project_dir: &Path) -> Result<(), LpmError> {
    let path = state_path(project_dir);
    if path.exists() {
        std::fs::remove_file(&path).map_err(LpmError::Io)?;
    }
    Ok(())
}

/// RFC 3339 timestamp for `captured_at`. Uses the same format as
/// `build_state.rs` so the two state files are visually consistent.
fn rfc3339_now() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // Use a tiny built-in formatter so we don't pull in chrono just
    // for one timestamp. Format: `YYYY-MM-DDTHH:MM:SSZ`.
    format_rfc3339(secs)
}

/// Convert a Unix epoch second count into a `YYYY-MM-DDTHH:MM:SSZ`
/// string.
///
/// Roughly equivalent to `chrono::DateTime<Utc>::from_timestamp` plus
/// `to_rfc3339_opts(SecondsFormat::Secs, true)` but with no dependency.
/// Handles years 1970..=2099, which is sufficient for a state file
/// timestamp.
fn format_rfc3339(epoch_secs: u64) -> String {
    const SECS_PER_DAY: u64 = 86_400;
    let days = epoch_secs / SECS_PER_DAY;
    let time_of_day = epoch_secs % SECS_PER_DAY;
    let h = (time_of_day / 3600) as u32;
    let m = ((time_of_day % 3600) / 60) as u32;
    let s = (time_of_day % 60) as u32;

    // Civil-from-days algorithm (Howard Hinnant). Anchor: 1970-01-01.
    let z = days as i64 + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m_civil = if mp < 10 { mp + 3 } else { mp - 9 };
    let y_civil = if m_civil <= 2 { y + 1 } else { y };

    format!("{y_civil:04}-{m_civil:02}-{d:02}T{h:02}:{m:02}:{s:02}Z")
}

#[allow(dead_code)] // referenced in doctests + future Phase 5.x compaction
fn _force_use_of_npm_range_matcher(_: NpmRangeMatcher) {}

#[allow(dead_code)] // referenced in doctests + future Phase 5.x compaction
fn _force_use_of_override_target(_: OverrideTarget) {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn map(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn capture_records_parsed_entries_and_fingerprint() {
        let set = OverrideSet::parse(
            &map(&[("foo", "^2.0.0"), ("baz>qar@1", "2.0.0")]),
            &map(&[]),
            &map(&[]),
        )
        .unwrap();
        let state = OverridesState::capture(&set, vec![]);
        assert_eq!(state.state_version, OVERRIDES_STATE_VERSION);
        assert_eq!(state.fingerprint, set.fingerprint());
        assert_eq!(state.parsed.len(), 2);
        assert!(state.applied.is_empty());
    }

    #[test]
    fn rebuild_set_round_trips_to_same_fingerprint() {
        let set = OverrideSet::parse(
            &map(&[
                ("foo", "^2.0.0"),
                ("baz>qar@1", "2.0.0"),
                ("bar@<1.0.0", "1.0.0"),
            ]),
            &map(&[]),
            &map(&[]),
        )
        .unwrap();
        let state = OverridesState::capture(&set, vec![]);
        let rebuilt = state.rebuild_set().expect("round-trip should succeed");
        assert_eq!(rebuilt.fingerprint(), set.fingerprint());
    }

    #[test]
    fn write_then_read_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let set = OverrideSet::parse(&map(&[("foo", "1.0.0")]), &map(&[]), &map(&[])).unwrap();
        let state = OverridesState::capture(&set, vec![]);

        write_state(dir.path(), &state).unwrap();
        let read_back = read_state(dir.path()).unwrap();
        assert_eq!(read_back.fingerprint, state.fingerprint);
        assert_eq!(read_back.parsed.len(), 1);
    }

    #[test]
    fn read_state_returns_none_on_version_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        let lpm_dir = dir.path().join(".lpm");
        std::fs::create_dir_all(&lpm_dir).unwrap();
        std::fs::write(
            lpm_dir.join(OVERRIDES_STATE_FILENAME),
            r#"{"state_version":999,"fingerprint":"sha256-x","captured_at":"2026-04-11T00:00:00Z","parsed":[],"applied":[]}"#,
        )
        .unwrap();
        assert!(read_state(dir.path()).is_none());
    }

    #[test]
    fn delete_state_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        // Deletion of a non-existent file is fine.
        delete_state(dir.path()).unwrap();
        // Write then delete.
        let set = OverrideSet::parse(&map(&[("foo", "1.0.0")]), &map(&[]), &map(&[])).unwrap();
        write_state(dir.path(), &OverridesState::capture(&set, vec![])).unwrap();
        delete_state(dir.path()).unwrap();
        assert!(read_state(dir.path()).is_none());
    }

    #[test]
    fn format_rfc3339_known_epoch() {
        // 1970-01-01T00:00:00Z
        assert_eq!(format_rfc3339(0), "1970-01-01T00:00:00Z");
        // 2000-01-01T00:00:00Z = 946684800
        assert_eq!(format_rfc3339(946_684_800), "2000-01-01T00:00:00Z");
        // 2026-04-11T12:34:56Z = 1775910896 (verified via macOS `date`)
        assert_eq!(format_rfc3339(1_775_910_896), "2026-04-11T12:34:56Z");
    }
}
