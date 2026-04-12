//! **Phase 32 Phase 6 — `<project_dir>/.lpm/patch-state.json` persistence layer.**
//!
//! Mirrors the [`crate::overrides_state`] pattern (Phase 5) for the
//! `lpm patch` apply trace. The state file persists three things across
//! installs:
//!
//! 1. The deterministic **fingerprint** of the parsed
//!    `lpm.patchedDependencies` map, so the lockfile fast path can be
//!    invalidated when the user edits the patch set between runs. Without
//!    this, the lockfile would silently shadow patch changes and the
//!    install would skip the apply pass.
//! 2. The list of **parsed entries**, so introspection commands can
//!    read what was declared without re-parsing `package.json`.
//! 3. The list of **applied hits**, so `lpm graph --why <pkg>` can
//!    decorate the matching package with patch provenance.
//!
//! ## Location
//!
//! `<project_dir>/.lpm/patch-state.json`. Same convention as
//! `build-state.json`, `overrides-state.json`, and `install-hash` —
//! next to `package.json`, survives `rm -rf node_modules`.
//!
//! ## Schema versioning
//!
//! [`PATCH_STATE_VERSION`] is bumped on every breaking change. Readers
//! return `None` (and the install pipeline treats the absent state as
//! "first run") on a version mismatch — forward-compat is never read
//! state files newer than what we know how to parse.
//!
//! ## Atomic writes
//!
//! [`write_state`] writes to a sibling tempfile and renames into place,
//! mirroring the [`crate::overrides_state`] writer. A crash mid-write
//! leaves the previous state file intact.

use lpm_common::LpmError;
use lpm_workspace::PatchedDependencyEntry;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Schema version for the on-disk state file. Bump on breaking changes.
pub const PATCH_STATE_VERSION: u32 = 1;

/// Filename inside `<project_dir>/.lpm/`.
pub const PATCH_STATE_FILENAME: &str = "patch-state.json";

/// Top-level shape of `patch-state.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatchState {
    /// Bumped on every breaking change to this struct or to its
    /// nested types. Readers compare against [`PATCH_STATE_VERSION`]
    /// and treat any mismatch as "no state".
    pub state_version: u32,

    /// Deterministic SHA-256 fingerprint over the parsed
    /// `patched_dependencies` map. Used by the install pipeline to
    /// invalidate the lockfile fast path when patches change.
    pub fingerprint: String,

    /// RFC 3339 timestamp of when this state file was written.
    pub captured_at: String,

    /// Every parsed entry in deterministic order. Survives across
    /// installs even when the lockfile fast path is taken — that's
    /// what makes the fingerprint comparison meaningful.
    pub parsed: Vec<ParsedPatchEntry>,

    /// Every patch applied during the most recent install pass. Unlike
    /// `overrides_state.applied`, this list is rewritten on every
    /// install (even on the lockfile fast path) because the patch
    /// engine runs unconditionally after linking.
    pub applied: Vec<AppliedPatchHit>,
}

/// On-disk shape of one parsed `lpm.patchedDependencies` entry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ParsedPatchEntry {
    /// The raw selector key as it appears in `package.json` (e.g.
    /// `"lodash@4.17.21"` or `"@types/node@20.10.0"`).
    pub raw_key: String,

    /// Package name parsed out of `raw_key`.
    pub name: String,

    /// Exact version parsed out of `raw_key`.
    pub version: String,

    /// Project-dir-relative path to the patch file.
    pub path: String,

    /// SRI integrity hash of the store baseline the patch was authored
    /// against. Drift from this value during install is a hard error.
    pub original_integrity: String,
}

/// On-disk shape of one applied patch hit. Mirrors `AppliedPatch` from
/// the patch engine but uses owned strings + project-dir-relative
/// paths so the file is portable across machines.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AppliedPatchHit {
    pub raw_key: String,
    pub name: String,
    pub version: String,
    pub patch_path: String,
    /// SRI integrity hash of the store baseline this patch was
    /// authored against. Mirrors
    /// `lpm.patchedDependencies[<key>].originalIntegrity` and the
    /// install-pipeline `apply_patch` baseline.
    ///
    /// **Backward compat:** declared as `Option<String>` with serde
    /// default so state files written before the audit fix
    /// (2026-04-12) — which lacked this field — still parse cleanly.
    /// Readers that find `None` should treat the integrity as "not
    /// recorded" rather than degrading the user experience.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub original_integrity: Option<String>,
    /// Every physical destination the patch was applied to (one per
    /// `MaterializedPackage` in the linker's report). Stored as
    /// project-dir-relative paths.
    pub locations: Vec<String>,
    pub files_modified: usize,
    pub files_added: usize,
    pub files_deleted: usize,
}

impl PatchState {
    /// Build a fresh state object from the current parsed
    /// `lpm.patchedDependencies` and the per-install apply trace.
    pub fn capture(
        patches: &HashMap<String, PatchedDependencyEntry>,
        applied: Vec<AppliedPatchHit>,
    ) -> Self {
        let parsed = parse_entries(patches);
        PatchState {
            state_version: PATCH_STATE_VERSION,
            fingerprint: compute_fingerprint(patches),
            captured_at: rfc3339_now(),
            parsed,
            applied,
        }
    }
}

/// Parse the raw `lpm.patchedDependencies` map into a sorted, validated
/// list of [`ParsedPatchEntry`]. Sorting is by `raw_key` so the on-disk
/// representation is deterministic regardless of HashMap iteration
/// order. Phase 6 accepts only `name@exact-version` keys; range
/// selectors are deferred to Phase 6.1 — see
/// [`crate::patch_engine::parse_patch_key`] for the canonical parser
/// (this function tolerates invalid keys by skipping them so the state
/// file never blocks introspection of an otherwise-malformed manifest).
pub fn parse_entries(patches: &HashMap<String, PatchedDependencyEntry>) -> Vec<ParsedPatchEntry> {
    let mut keys: Vec<&String> = patches.keys().collect();
    keys.sort();
    keys.into_iter()
        .filter_map(|raw_key| {
            // Use the same `name@version` split shape the patch engine
            // uses, but tolerate parse failures here so a malformed
            // entry doesn't poison the state file. The install
            // pipeline's stricter parser will surface the error.
            let (name, version) = split_key(raw_key)?;
            let entry = patches.get(raw_key)?;
            Some(ParsedPatchEntry {
                raw_key: raw_key.clone(),
                name,
                version,
                path: entry.path.clone(),
                original_integrity: entry.original_integrity.clone(),
            })
        })
        .collect()
}

fn split_key(raw: &str) -> Option<(String, String)> {
    // Scoped names start with `@` and contain a literal `/`, so the
    // `@version` separator is the LAST `@` in the key.
    let at = raw.rfind('@')?;
    if at == 0 {
        return None;
    }
    let name = &raw[..at];
    let version = &raw[at + 1..];
    if name.is_empty() || version.is_empty() {
        return None;
    }
    Some((name.to_string(), version.to_string()))
}

/// Deterministic fingerprint over the parsed
/// `lpm.patchedDependencies` map. Used by the install pipeline to
/// detect drift between the on-disk state file and the current
/// `package.json`. Format: `sha256-<hex>`.
///
/// The hash is order-independent: keys are sorted before hashing, and
/// each `(key, path, originalIntegrity)` triple is fed in with explicit
/// byte separators to prevent collision via concatenation.
pub fn compute_fingerprint(patches: &HashMap<String, PatchedDependencyEntry>) -> String {
    let mut keys: Vec<&String> = patches.keys().collect();
    keys.sort();

    let mut hasher = Sha256::new();
    for k in keys {
        let v = &patches[k];
        hasher.update(k.as_bytes());
        hasher.update(b"\x00");
        hasher.update(v.path.as_bytes());
        hasher.update(b"\x00");
        hasher.update(v.original_integrity.as_bytes());
        // Record terminator — different byte from the field separator
        // so adversarially-crafted strings can't fake the boundary.
        hasher.update(b"\x01");
    }
    format!("sha256-{:x}", hasher.finalize())
}

/// Return the path to the state file inside `<project_dir>/.lpm/`.
pub fn state_path(project_dir: &Path) -> PathBuf {
    project_dir.join(".lpm").join(PATCH_STATE_FILENAME)
}

/// Read the persisted state if it exists and matches the current
/// schema version. Returns `None` for missing files, parse failures,
/// or version mismatches — the caller treats all three as "first run".
pub fn read_state(project_dir: &Path) -> Option<PatchState> {
    let path = state_path(project_dir);
    let content = std::fs::read_to_string(&path).ok()?;
    let state: PatchState = serde_json::from_str(&content).ok()?;
    if state.state_version != PATCH_STATE_VERSION {
        tracing::debug!(
            "patch-state.json version mismatch: got {}, expected {}",
            state.state_version,
            PATCH_STATE_VERSION
        );
        return None;
    }
    Some(state)
}

/// Atomically write the state file to `<project_dir>/.lpm/`. Creates
/// the `.lpm/` directory if it doesn't exist. The write goes to a
/// sibling tempfile and renames into place so a crash mid-write leaves
/// the previous state intact.
pub fn write_state(project_dir: &Path, state: &PatchState) -> Result<(), LpmError> {
    let lpm_dir = project_dir.join(".lpm");
    std::fs::create_dir_all(&lpm_dir).map_err(LpmError::Io)?;

    let final_path = lpm_dir.join(PATCH_STATE_FILENAME);
    let tmp_path = lpm_dir.join(format!("{PATCH_STATE_FILENAME}.tmp"));

    let json = serde_json::to_string_pretty(state)
        .map_err(|e| LpmError::Script(format!("failed to serialize patch state: {e}")))?;

    std::fs::write(&tmp_path, json.as_bytes()).map_err(LpmError::Io)?;
    if let Err(e) = std::fs::rename(&tmp_path, &final_path) {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(LpmError::Io(e));
    }
    Ok(())
}

/// Delete the state file if it exists. Used when the user removes all
/// patches from `package.json` — we don't want to leave a stale state
/// file behind that would confuse `lpm graph --why`.
pub fn delete_state(project_dir: &Path) -> Result<(), LpmError> {
    let path = state_path(project_dir);
    if path.exists() {
        std::fs::remove_file(&path).map_err(LpmError::Io)?;
    }
    Ok(())
}

/// RFC 3339 timestamp for `captured_at`. Uses the same tiny formatter
/// as `overrides_state.rs` so we don't pull in chrono just for one
/// timestamp.
fn rfc3339_now() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format_rfc3339(secs)
}

/// Convert a Unix epoch second count into a `YYYY-MM-DDTHH:MM:SSZ`
/// string. Mirror of the helper in `overrides_state.rs`. Handles years
/// 1970..=2099.
fn format_rfc3339(epoch_secs: u64) -> String {
    const SECS_PER_DAY: u64 = 86_400;
    let days = epoch_secs / SECS_PER_DAY;
    let time_of_day = epoch_secs % SECS_PER_DAY;
    let h = (time_of_day / 3600) as u32;
    let m = ((time_of_day % 3600) / 60) as u32;
    let s = (time_of_day % 60) as u32;

    // Civil-from-days algorithm (Howard Hinnant).
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

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(path: &str, integrity: &str) -> PatchedDependencyEntry {
        PatchedDependencyEntry {
            path: path.to_string(),
            original_integrity: integrity.to_string(),
        }
    }

    fn map(pairs: &[(&str, PatchedDependencyEntry)]) -> HashMap<String, PatchedDependencyEntry> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), v.clone()))
            .collect()
    }

    // ── Fingerprint contracts ────────────────────────────────────────

    #[test]
    fn fingerprint_is_deterministic() {
        let m1 = map(&[(
            "lodash@4.17.21",
            entry("patches/lodash@4.17.21.patch", "sha512-abc"),
        )]);
        let m2 = map(&[(
            "lodash@4.17.21",
            entry("patches/lodash@4.17.21.patch", "sha512-abc"),
        )]);
        assert_eq!(compute_fingerprint(&m1), compute_fingerprint(&m2));
    }

    #[test]
    fn fingerprint_is_key_order_independent() {
        // HashMap iteration order is randomized; the fingerprint MUST
        // not depend on it. Sort happens inside compute_fingerprint.
        let m1 = map(&[
            ("a@1.0.0", entry("patches/a.patch", "sha512-aa")),
            ("b@1.0.0", entry("patches/b.patch", "sha512-bb")),
        ]);
        let m2 = map(&[
            ("b@1.0.0", entry("patches/b.patch", "sha512-bb")),
            ("a@1.0.0", entry("patches/a.patch", "sha512-aa")),
        ]);
        assert_eq!(compute_fingerprint(&m1), compute_fingerprint(&m2));
    }

    #[test]
    fn fingerprint_changes_on_path_change() {
        let m1 = map(&[("lodash@4.17.21", entry("patches/v1.patch", "sha512-aa"))]);
        let m2 = map(&[("lodash@4.17.21", entry("patches/v2.patch", "sha512-aa"))]);
        assert_ne!(
            compute_fingerprint(&m1),
            compute_fingerprint(&m2),
            "moving the patch file must invalidate the fingerprint"
        );
    }

    #[test]
    fn fingerprint_changes_on_integrity_rotation() {
        let m1 = map(&[(
            "lodash@4.17.21",
            entry("patches/lodash.patch", "sha512-old"),
        )]);
        let m2 = map(&[(
            "lodash@4.17.21",
            entry("patches/lodash.patch", "sha512-new"),
        )]);
        assert_ne!(
            compute_fingerprint(&m1),
            compute_fingerprint(&m2),
            "rotating the integrity baseline must invalidate the fingerprint"
        );
    }

    #[test]
    fn fingerprint_changes_when_entry_added() {
        let m1 = map(&[("a@1.0.0", entry("patches/a.patch", "sha512-aa"))]);
        let m2 = map(&[
            ("a@1.0.0", entry("patches/a.patch", "sha512-aa")),
            ("b@1.0.0", entry("patches/b.patch", "sha512-bb")),
        ]);
        assert_ne!(compute_fingerprint(&m1), compute_fingerprint(&m2));
    }

    #[test]
    fn fingerprint_byte_separator_prevents_collision() {
        // Two different maps that would collide under naive
        // concatenation: ("ab","")<sep>("","cd") vs ("a","b")<sep>("c","d")
        // — etc. The explicit byte separators in compute_fingerprint
        // prevent this. We assert two semantically distinct maps with
        // shared substrings produce distinct fingerprints.
        let m1 = map(&[("foobar@1.0.0", entry("patches/x.patch", ""))]);
        let m2 = map(&[("foo@bar1.0.0", entry("patches/x.patch", ""))]);
        // (m2's key isn't a valid patch key, but split_key tolerance
        // is irrelevant — the fingerprint hashes raw bytes only.)
        assert_ne!(compute_fingerprint(&m1), compute_fingerprint(&m2));
    }

    // ── Parsed entry contracts ───────────────────────────────────────

    #[test]
    fn parse_entries_splits_unscoped_name() {
        let m = map(&[(
            "lodash@4.17.21",
            entry("patches/lodash@4.17.21.patch", "sha512-aa"),
        )]);
        let parsed = parse_entries(&m);
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].name, "lodash");
        assert_eq!(parsed[0].version, "4.17.21");
        assert_eq!(parsed[0].raw_key, "lodash@4.17.21");
    }

    #[test]
    fn parse_entries_splits_scoped_name_at_last_at() {
        // Scoped names contain a literal `/` and start with `@`.
        // The version separator is the LAST `@`, not the first.
        let m = map(&[(
            "@types/node@20.10.0",
            entry("patches/at.patch", "sha512-bb"),
        )]);
        let parsed = parse_entries(&m);
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].name, "@types/node");
        assert_eq!(parsed[0].version, "20.10.0");
    }

    #[test]
    fn parse_entries_skips_malformed_keys_silently() {
        let m = map(&[
            ("ok@1.0.0", entry("patches/ok.patch", "sha512-aa")),
            ("missing-version", entry("patches/bad.patch", "sha512-bb")),
            ("@only-scope", entry("patches/bad2.patch", "sha512-cc")),
        ]);
        let parsed = parse_entries(&m);
        // Only the well-formed key survives.
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].name, "ok");
    }

    #[test]
    fn parse_entries_is_sorted_by_raw_key() {
        let m = map(&[
            ("zeta@1.0.0", entry("patches/z.patch", "sha512-zz")),
            ("alpha@1.0.0", entry("patches/a.patch", "sha512-aa")),
            ("mike@1.0.0", entry("patches/m.patch", "sha512-mm")),
        ]);
        let parsed = parse_entries(&m);
        let keys: Vec<&str> = parsed.iter().map(|p| p.raw_key.as_str()).collect();
        assert_eq!(keys, vec!["alpha@1.0.0", "mike@1.0.0", "zeta@1.0.0"]);
    }

    // ── Persistence contracts (mirror of overrides_state) ────────────

    #[test]
    fn write_then_read_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let m = map(&[("lodash@4.17.21", entry("patches/lodash.patch", "sha512-aa"))]);
        let state = PatchState::capture(&m, vec![]);
        write_state(dir.path(), &state).unwrap();

        let read_back = read_state(dir.path()).expect("state file should round-trip");
        assert_eq!(read_back.fingerprint, state.fingerprint);
        assert_eq!(read_back.parsed.len(), 1);
        assert_eq!(read_back.parsed[0].name, "lodash");
    }

    #[test]
    fn read_state_returns_none_when_missing() {
        let dir = tempfile::tempdir().unwrap();
        assert!(read_state(dir.path()).is_none());
    }

    #[test]
    fn read_state_returns_none_on_version_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        let lpm_dir = dir.path().join(".lpm");
        std::fs::create_dir_all(&lpm_dir).unwrap();
        std::fs::write(
            lpm_dir.join(PATCH_STATE_FILENAME),
            r#"{"state_version":999,"fingerprint":"sha256-x","captured_at":"2026-04-12T00:00:00Z","parsed":[],"applied":[]}"#,
        )
        .unwrap();
        assert!(
            read_state(dir.path()).is_none(),
            "version mismatch must read as None"
        );
    }

    #[test]
    fn read_state_returns_none_on_garbage_content() {
        let dir = tempfile::tempdir().unwrap();
        let lpm_dir = dir.path().join(".lpm");
        std::fs::create_dir_all(&lpm_dir).unwrap();
        std::fs::write(lpm_dir.join(PATCH_STATE_FILENAME), "this is not json").unwrap();
        assert!(read_state(dir.path()).is_none());
    }

    #[test]
    fn delete_state_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        // Deletion of a non-existent file is fine.
        delete_state(dir.path()).unwrap();
        // Write then delete.
        let m = map(&[("lodash@4.17.21", entry("patches/lodash.patch", "sha512-aa"))]);
        write_state(dir.path(), &PatchState::capture(&m, vec![])).unwrap();
        delete_state(dir.path()).unwrap();
        assert!(read_state(dir.path()).is_none());
    }

    // ── Format helpers ───────────────────────────────────────────────

    #[test]
    fn format_rfc3339_known_epoch() {
        assert_eq!(format_rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(format_rfc3339(946_684_800), "2000-01-01T00:00:00Z");
    }
}
