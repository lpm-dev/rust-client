//! Local record of the last install's patch applications,
//! `<project_dir>/.lpm/patch-state.json`, read by `lpm graph --why` to
//! decorate patched packages.
//!
//! The file is never committed and installs never consult it: `lpm.lock`
//! records the patch set a resolution used (`patches` plus the importer's
//! `patches_fingerprint`), so a fresh clone installs the same way as the
//! checkout that wrote the lockfile.
//!
//! [`PATCH_STATE_VERSION`] is bumped on every breaking change; readers
//! treat other versions as absent. [`write_state`] replaces the file
//! atomically.

use lpm_common::LpmError;
use lpm_lockfile::{LockfilePatch, LockfilePatches};
use lpm_workspace::PatchedDependencyEntry;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};

/// Schema version for the on-disk state file. Bump on breaking changes.
pub const PATCH_STATE_VERSION: u32 = 2;

/// Filename inside `<project_dir>/.lpm/`.
pub const PATCH_STATE_FILENAME: &str = "patch-state.json";

/// Top-level shape of `patch-state.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatchState {
    /// Compared against [`PATCH_STATE_VERSION`]; any other value reads as
    /// no state.
    pub state_version: u32,

    /// RFC 3339 timestamp of when this state file was written.
    pub captured_at: String,

    /// Every patch applied by the most recent install that did patch work.
    pub applied: Vec<AppliedPatchHit>,
}

/// On-disk shape of one applied patch hit. Mirrors `AppliedPatch` from
/// the patch engine with owned strings.
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
    /// default so state files written before this field existed still
    /// parse cleanly.
    /// Readers that find `None` should treat the integrity as "not
    /// recorded" rather than degrading the user experience.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub original_integrity: Option<String>,
    /// Every physical destination the patch was applied to (one per
    /// `MaterializedPackage` in the linker's report): relative to the
    /// project when inside it, absolute otherwise (store link trees).
    pub locations: Vec<String>,
    pub files_modified: usize,
    pub files_added: usize,
    pub files_deleted: usize,
}

impl PatchState {
    /// Build a fresh state object from an install's apply trace.
    pub fn capture(applied: Vec<AppliedPatchHit>) -> Self {
        PatchState {
            state_version: PATCH_STATE_VERSION,
            captured_at: rfc3339_now(),
            applied,
        }
    }
}

/// Deterministic fingerprint over the parsed `lpm.patchedDependencies`
/// map, recorded as the lockfile importer's `patches_fingerprint`.
/// Format: `sha256-<hex>`.
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

/// Full SHA-256 digest for a project-relative patch file.
pub fn patch_file_sha256(project_dir: &Path, rel_path: &str) -> Result<String, LpmError> {
    crate::patch_fs::patch_artifact_sha256(project_dir, rel_path)
}

/// Build lockfile patch records from the current manifest declarations.
///
/// The map key is the manifest's exact `name@version` selector. The
/// patch engine parser is intentionally reused here so `lpm.lock`
/// never records a patch selector the installer could not replay.
pub fn lockfile_patches_from_manifest(
    project_dir: &Path,
    patches: &HashMap<String, PatchedDependencyEntry>,
) -> Result<LockfilePatches, LpmError> {
    if patches.is_empty() {
        return Ok(BTreeMap::new());
    }

    let mut out = LockfilePatches::new();
    let mut keys: Vec<&String> = patches.keys().collect();
    keys.sort();
    for key in keys {
        crate::patch_engine::parse_patch_key(key)?;
        let entry = &patches[key];
        out.insert(
            key.clone(),
            LockfilePatch {
                path: entry.path.clone(),
                sha256: patch_file_sha256(project_dir, &entry.path)?,
                original_integrity: entry.original_integrity.clone(),
            },
        );
    }
    Ok(out)
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
    let bytes = lpm_common::read_capped_state_file(&path, lpm_common::STATE_FILE_SIZE_CAP_BYTES)
        .ok()
        .flatten()?;
    let state: PatchState = serde_json::from_slice(&bytes).ok()?;
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
/// the `.lpm/` directory if it doesn't exist. A crash before replacement
/// leaves the previous state intact.
pub fn write_state(project_dir: &Path, state: &PatchState) -> Result<(), LpmError> {
    let lpm_dir = lpm_common::ensure_project_state_dir(project_dir)?;

    let json = serde_json::to_string_pretty(state)
        .map_err(|e| LpmError::Script(format!("failed to serialize patch state: {e}")))?;

    let final_path = lpm_dir.join(PATCH_STATE_FILENAME);
    lpm_common::write_file_atomic(&final_path, json.as_bytes()).map_err(LpmError::Io)
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
        .map_or(0, |d| d.as_secs());
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
        // m2's key isn't a valid patch key; the fingerprint hashes raw
        // bytes only.
        assert_ne!(compute_fingerprint(&m1), compute_fingerprint(&m2));
    }

    #[test]
    fn patch_file_sha256_rejects_parent_escape() {
        let root = tempfile::tempdir().unwrap();
        let project = root.path().join("project");
        std::fs::create_dir_all(&project).unwrap();
        std::fs::write(root.path().join("outside.patch"), "secret").unwrap();

        let error = patch_file_sha256(&project, "../outside.patch").unwrap_err();
        assert!(format!("{error}").contains("project-relative"));
    }

    #[cfg(unix)]
    #[test]
    fn patch_file_sha256_rejects_symlinked_patch_file() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().unwrap();
        let project = root.path().join("project");
        std::fs::create_dir_all(project.join("patches")).unwrap();
        let outside = root.path().join("outside.patch");
        std::fs::write(&outside, "secret").unwrap();
        symlink(&outside, project.join("patches/link.patch")).unwrap();

        let error = patch_file_sha256(&project, "patches/link.patch").unwrap_err();
        assert!(format!("{error}").contains("symbolic link"));
    }

    // ── Persistence contracts (mirror of overrides_state) ────────────

    #[test]
    fn write_then_read_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let hit = AppliedPatchHit {
            raw_key: "lodash@4.17.21".into(),
            name: "lodash".into(),
            version: "4.17.21".into(),
            patch_path: "patches/lodash.patch".into(),
            original_integrity: Some("sha512-aa".into()),
            locations: vec!["node_modules/lodash".into()],
            files_modified: 1,
            files_added: 0,
            files_deleted: 0,
        };
        write_state(dir.path(), &PatchState::capture(vec![hit.clone()])).unwrap();

        let read_back = read_state(dir.path()).expect("state file should round-trip");
        assert_eq!(read_back.applied, vec![hit]);
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
            r#"{"state_version":999,"captured_at":"T00:00:00Z","applied":[]}"#,
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
        write_state(dir.path(), &PatchState::capture(vec![])).unwrap();
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
