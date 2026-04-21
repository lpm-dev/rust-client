//! Phase 46 P1 — `.lpm/trust-snapshot.json` persistence and diff.
//!
//! Every successful `lpm install` writes a snapshot of the current
//! `package.json > lpm > trustedDependencies` into
//! `<project_dir>/.lpm/trust-snapshot.json`. At the start of the next
//! install, the diff against this snapshot surfaces **new trust
//! bindings** — entries that appeared in the manifest since the last
//! install but were not personally approved on this machine (see plan
//! §4.2 for the motivating scenario: a "bump dep" PR that silently
//! adds a `trustedDependencies` entry gets flagged instead of slipping
//! past code review).
//!
//! ## Why a separate file from `build-state.json`
//!
//! `build-state.json` snapshots the *blocked set* (packages whose
//! scripts were NOT covered by approvals) for suppression of the
//! post-install banner. `trust-snapshot.json` snapshots the
//! *approvals themselves* for detection of additions. The two files
//! have independent lifecycles (build-state invalidates on install
//! changes; trust-snapshot only on manifest changes), different
//! schemas, and different consumer concerns. Colocating them in
//! `.lpm/` keeps them next to `package.json` and behind the existing
//! `.gitignore` convention for `.lpm/`.
//!
//! ## Schema stability
//!
//! Same policy as `build-state.json` (see `BUILD_STATE_VERSION`
//! comment): bump only on breaking changes. Optional field additions
//! default to `None` and silently pass through older readers, so
//! `SCHEMA_VERSION = 1` should suffice for all of Phase 46.

use lpm_common::LpmError;
use lpm_workspace::TrustedDependencies;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Current trust-snapshot schema version.
///
/// Bump only on **breaking** changes (field type change, removal,
/// semantic change). Additions of `Option<T>` fields do not warrant a
/// bump — the struct has no `deny_unknown_fields` attribute, so older
/// readers silently drop newer fields and newer readers default
/// missing fields to `None`. Same policy as `BUILD_STATE_VERSION`.
pub const SCHEMA_VERSION: u32 = 1;

/// Filename inside `<project_dir>/.lpm/`.
pub const FILENAME: &str = "trust-snapshot.json";

/// One binding captured in the snapshot.
///
/// Minimal 2-field projection of `TrustedDependencyBinding`. We do
/// NOT capture Phase 46 audit fields (`approved_by`,
/// `approved_by_model_exact`, etc.) here — those belong to the
/// manifest's audit trail, not to the "did-the-set-change" diff.
/// Keeping the snapshot payload lean also means reader / writer
/// churn stays minimal across future binding-schema extensions.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotEntry {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub integrity: Option<String>,
    #[serde(
        default,
        rename = "scriptHash",
        skip_serializing_if = "Option::is_none"
    )]
    pub script_hash: Option<String>,
}

/// Top-level shape of `.lpm/trust-snapshot.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustSnapshot {
    pub schema_version: u32,
    /// RFC 3339 timestamp of the install that wrote this snapshot.
    /// Used by the `lpm trust diff` command for "added since <date>"
    /// messaging, not by the diff-computation logic itself.
    pub captured_at: String,
    /// Bindings keyed by `"name@version"` in deterministic
    /// lexicographic order (thanks to `BTreeMap`), so JSON on-disk
    /// is diff-stable across installs that don't change the set.
    pub bindings: BTreeMap<String, SnapshotEntry>,
}

impl TrustSnapshot {
    /// Project the current `package.json > lpm > trustedDependencies`
    /// into snapshot shape.
    ///
    /// **Keying:** the snapshot uses the raw map key from
    /// `TrustedDependencies::Rich` (format `"name@version"`, per
    /// `TrustedDependencies::rich_key`) so the diff is
    /// version-granular. Legacy bare-name entries use the bare name
    /// as-is (no `@version`) and project to an empty binding — same
    /// semantic the strict gate assigns them (`LegacyNameOnly`).
    ///
    /// Note we pattern-match on the enum directly rather than calling
    /// `TrustedDependencies::iter`: the public `iter` normalizes the
    /// key to the name-portion only (stripping `@version`), which
    /// would collapse all versions of the same package into one
    /// snapshot key and defeat version-granular diff.
    ///
    /// The returned snapshot's `captured_at` is set to NOW. Callers
    /// are expected to persist it via [`write_snapshot`] after a
    /// successful install; the timestamp is the write-time marker,
    /// not the read-time.
    pub fn capture_current(td: &TrustedDependencies) -> Self {
        let mut bindings: BTreeMap<String, SnapshotEntry> = BTreeMap::new();
        match td {
            TrustedDependencies::Legacy(names) => {
                for name in names {
                    bindings.insert(name.clone(), SnapshotEntry::default());
                }
            }
            TrustedDependencies::Rich(map) => {
                for (key, binding) in map.iter() {
                    bindings.insert(
                        key.clone(),
                        SnapshotEntry {
                            integrity: binding.integrity.clone(),
                            script_hash: binding.script_hash.clone(),
                        },
                    );
                }
            }
        }
        Self {
            schema_version: SCHEMA_VERSION,
            captured_at: current_rfc3339(),
            bindings,
        }
    }

    /// Diff `current` against `previous`, returning the keys present
    /// in current but NOT in previous, sorted lexicographically.
    ///
    /// `previous == None` (first install, missing file, version
    /// mismatch, or malformed file) means "nothing to diff against"
    /// — returns an empty vec. First-time installs do not trigger
    /// the new-bindings notice: no prior snapshot means no user-
    /// visible "change" to surface.
    ///
    /// Note: we deliberately do NOT flag removals or binding changes
    /// here. The diff exists to catch silent *additions* from a
    /// poisoned PR (plan §4.2); removals are user-initiated via
    /// `lpm trust prune` (chunk C) and binding changes are already
    /// handled by the `BindingDrift` path in the install pipeline.
    pub fn diff_additions(&self, previous: Option<&TrustSnapshot>) -> Vec<String> {
        let Some(prev) = previous else {
            return Vec::new();
        };
        self.bindings
            .keys()
            .filter(|k| !prev.bindings.contains_key(*k))
            .cloned()
            .collect()
    }
}

/// Current wall-clock time as RFC 3339 string. Matches the
/// `chrono::Utc::now().to_rfc3339()` pattern used by
/// `build_state::current_rfc3339` — lpm-cli uses `chrono` for
/// timestamps; `time` is only a transitive dep via lpm-security.
fn current_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339()
}

/// Absolute path to `<project_dir>/.lpm/trust-snapshot.json`.
pub fn snapshot_path(project_dir: &Path) -> PathBuf {
    project_dir.join(".lpm").join(FILENAME)
}

/// Read the trust snapshot from disk.
///
/// Returns `None` (treated as "no prior state" by callers) if:
/// - the file is missing
/// - the file fails JSON parse
/// - the `schema_version` is newer than [`SCHEMA_VERSION`]
///
/// Older `schema_version` values are accepted — the optional-field
/// additions policy (see [`SCHEMA_VERSION`] doc) guarantees parse
/// compatibility.
pub fn read_snapshot(project_dir: &Path) -> Option<TrustSnapshot> {
    let path = snapshot_path(project_dir);
    let content = std::fs::read_to_string(&path).ok()?;
    let snap: TrustSnapshot = serde_json::from_str(&content).ok()?;
    if snap.schema_version > SCHEMA_VERSION {
        tracing::debug!(
            "trust-snapshot.json is newer than this binary supports \
             (got v{}, max v{}) — treating as missing",
            snap.schema_version,
            SCHEMA_VERSION,
        );
        return None;
    }
    Some(snap)
}

/// Atomically write the snapshot to
/// `<project_dir>/.lpm/trust-snapshot.json`. Writes to a temp file
/// alongside the target and renames; a crash between write and rename
/// preserves the previous snapshot rather than producing a truncated
/// file.
pub fn write_snapshot(project_dir: &Path, snap: &TrustSnapshot) -> Result<(), LpmError> {
    let path = snapshot_path(project_dir);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(LpmError::Io)?;
    }

    let body = serde_json::to_string_pretty(snap)
        .map_err(|e| LpmError::Registry(format!("failed to serialize trust-snapshot: {e}")))?;

    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, body).map_err(LpmError::Io)?;
    std::fs::rename(&tmp, &path).map_err(LpmError::Io)?;
    Ok(())
}

/// Format the new-bindings notice per plan §4.2.
///
/// Empty input returns `None` so the caller can skip printing. When
/// non-empty, the returned string is ready to pass to
/// `output::info` (multi-line; no leading / trailing newlines).
pub fn format_new_bindings_notice(additions: &[String]) -> Option<String> {
    if additions.is_empty() {
        return None;
    }
    let mut out = String::from("Manifest trust bindings changed since last install:\n");
    for key in additions {
        out.push_str(&format!("    + {key}\n"));
    }
    out.push_str("  Run `lpm trust diff` to inspect before scripts run.");
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use lpm_workspace::TrustedDependencyBinding;
    use std::collections::HashMap;
    use tempfile::tempdir;

    fn rich_td(entries: &[(&str, Option<&str>, Option<&str>)]) -> TrustedDependencies {
        let mut map: HashMap<String, TrustedDependencyBinding> = HashMap::new();
        for (key, integrity, script_hash) in entries {
            map.insert(
                (*key).to_string(),
                TrustedDependencyBinding {
                    integrity: integrity.map(String::from),
                    script_hash: script_hash.map(String::from),
                    ..Default::default()
                },
            );
        }
        TrustedDependencies::Rich(map)
    }

    // ── capture_current ────────────────────────────────────────────

    #[test]
    fn capture_empty_produces_empty_snapshot() {
        let td = TrustedDependencies::default();
        let snap = TrustSnapshot::capture_current(&td);
        assert_eq!(snap.schema_version, SCHEMA_VERSION);
        assert!(snap.bindings.is_empty());
        assert!(!snap.captured_at.is_empty(), "captured_at populated");
    }

    #[test]
    fn capture_rich_bindings_projects_fields() {
        let td = rich_td(&[
            ("esbuild@0.25.1", Some("sha512-e"), Some("sha256-es")),
            ("sharp@0.33.0", None, Some("sha256-sh")),
        ]);
        let snap = TrustSnapshot::capture_current(&td);
        assert_eq!(snap.bindings.len(), 2);
        let e = snap.bindings.get("esbuild@0.25.1").unwrap();
        assert_eq!(e.integrity.as_deref(), Some("sha512-e"));
        assert_eq!(e.script_hash.as_deref(), Some("sha256-es"));
        let s = snap.bindings.get("sharp@0.33.0").unwrap();
        assert_eq!(s.integrity, None);
        assert_eq!(s.script_hash.as_deref(), Some("sha256-sh"));
    }

    #[test]
    fn capture_legacy_bare_names_keep_name_only_key() {
        // Legacy `trustedDependencies: ["esbuild", "sharp"]` projects
        // to bindings with empty binding payloads. The `name@version`
        // key semantic follows `TrustedDependencies::iter()`; legacy
        // entries iterate as `(name, None)` and we use the bare name
        // as the key for the snapshot.
        let td = TrustedDependencies::Legacy(vec!["esbuild".to_string(), "sharp".to_string()]);
        let snap = TrustSnapshot::capture_current(&td);
        assert_eq!(snap.bindings.len(), 2);
        for key in ["esbuild", "sharp"] {
            let e = snap
                .bindings
                .get(key)
                .unwrap_or_else(|| panic!("missing bare-name key {key}"));
            assert!(e.integrity.is_none() && e.script_hash.is_none());
        }
    }

    // ── diff_additions ─────────────────────────────────────────────

    #[test]
    fn diff_no_previous_returns_empty() {
        // First install: no snapshot file → no "added since" noise.
        let current = TrustSnapshot::capture_current(&rich_td(&[(
            "esbuild@0.25.1",
            Some("sha512-e"),
            Some("sha256-es"),
        )]));
        assert!(current.diff_additions(None).is_empty());
    }

    #[test]
    fn diff_detects_additions_only() {
        // The motivating case: previous snapshot has one entry; new
        // manifest has two. The second one is the "silent addition."
        let previous = TrustSnapshot::capture_current(&rich_td(&[(
            "esbuild@0.25.1",
            Some("sha512-e"),
            Some("sha256-es"),
        )]));
        let current = TrustSnapshot::capture_current(&rich_td(&[
            ("esbuild@0.25.1", Some("sha512-e"), Some("sha256-es")),
            ("plain-crypto-js@1.0.0", None, None),
        ]));
        let adds = current.diff_additions(Some(&previous));
        assert_eq!(adds, vec!["plain-crypto-js@1.0.0".to_string()]);
    }

    #[test]
    fn diff_ignores_removals() {
        // A package removed from the manifest is not "new to the
        // user"; don't surface it. Only additions matter for the
        // poisoned-PR scenario.
        let previous = TrustSnapshot::capture_current(&rich_td(&[
            ("esbuild@0.25.1", Some("sha512-e"), Some("sha256-es")),
            ("sharp@0.33.0", None, Some("sha256-sh")),
        ]));
        let current = TrustSnapshot::capture_current(&rich_td(&[(
            "esbuild@0.25.1",
            Some("sha512-e"),
            Some("sha256-es"),
        )]));
        assert!(current.diff_additions(Some(&previous)).is_empty());
    }

    #[test]
    fn diff_ignores_binding_changes_on_same_key() {
        // Same key present in both snapshots but with different
        // binding values is NOT an "addition." Binding-change
        // detection is the job of `BindingDrift` in the install
        // pipeline, not this snapshot diff.
        let previous = TrustSnapshot::capture_current(&rich_td(&[(
            "esbuild@0.25.1",
            Some("sha512-old"),
            Some("sha256-old"),
        )]));
        let current = TrustSnapshot::capture_current(&rich_td(&[(
            "esbuild@0.25.1",
            Some("sha512-new"),
            Some("sha256-new"),
        )]));
        assert!(current.diff_additions(Some(&previous)).is_empty());
    }

    #[test]
    fn diff_multiple_additions_are_sorted() {
        // BTreeMap keys iterate in order, so the returned vec is
        // naturally sorted. Pin this invariant because downstream
        // rendering (`format_new_bindings_notice`) relies on it for
        // stable output.
        let previous = TrustSnapshot::capture_current(&TrustedDependencies::default());
        let current = TrustSnapshot::capture_current(&rich_td(&[
            ("zzz@1.0.0", None, None),
            ("aaa@1.0.0", None, None),
            ("mmm@1.0.0", None, None),
        ]));
        let adds = current.diff_additions(Some(&previous));
        assert_eq!(
            adds,
            vec![
                "aaa@1.0.0".to_string(),
                "mmm@1.0.0".to_string(),
                "zzz@1.0.0".to_string()
            ],
        );
    }

    // ── format_new_bindings_notice ─────────────────────────────────

    #[test]
    fn format_empty_returns_none() {
        assert!(format_new_bindings_notice(&[]).is_none());
    }

    #[test]
    fn format_renders_list_with_lpm_trust_diff_cta() {
        let n = format_new_bindings_notice(&[
            "plain-crypto-js@1.0.0".to_string(),
            "axios@1.14.1".to_string(),
        ])
        .unwrap();
        assert!(n.contains("Manifest trust bindings changed since last install"));
        assert!(n.contains("+ plain-crypto-js@1.0.0"));
        assert!(n.contains("+ axios@1.14.1"));
        assert!(n.contains("lpm trust diff"));
    }

    // ── read / write round-trip ────────────────────────────────────

    #[test]
    fn write_then_read_round_trip() {
        let dir = tempdir().unwrap();
        let td = rich_td(&[("esbuild@0.25.1", Some("sha512-e"), Some("sha256-es"))]);
        let snap = TrustSnapshot::capture_current(&td);

        write_snapshot(dir.path(), &snap).unwrap();
        let read = read_snapshot(dir.path()).expect("read back");

        assert_eq!(read.schema_version, snap.schema_version);
        assert_eq!(read.bindings.len(), snap.bindings.len());
        let e = read.bindings.get("esbuild@0.25.1").unwrap();
        assert_eq!(e.integrity.as_deref(), Some("sha512-e"));
    }

    #[test]
    fn read_missing_file_returns_none() {
        let dir = tempdir().unwrap();
        assert!(read_snapshot(dir.path()).is_none());
    }

    #[test]
    fn read_malformed_json_returns_none() {
        let dir = tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join(".lpm")).unwrap();
        std::fs::write(snapshot_path(dir.path()), "{not valid json").unwrap();
        assert!(read_snapshot(dir.path()).is_none());
    }

    #[test]
    fn read_newer_schema_version_returns_none() {
        // Future v2 binary wrote this file; current v1 binary must
        // decline to interpret v2 semantics with v1 types.
        let dir = tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join(".lpm")).unwrap();
        let future = format!(
            r#"{{"schema_version": {}, "captured_at": "2027-01-01T00:00:00Z", "bindings": {{}}}}"#,
            SCHEMA_VERSION + 1,
        );
        std::fs::write(snapshot_path(dir.path()), future).unwrap();
        assert!(read_snapshot(dir.path()).is_none());
    }

    #[test]
    fn write_is_atomic_no_tmp_file_left_behind() {
        let dir = tempdir().unwrap();
        let snap = TrustSnapshot::capture_current(&TrustedDependencies::default());
        write_snapshot(dir.path(), &snap).unwrap();

        // No `.json.tmp` leaked alongside the real file.
        let tmp = snapshot_path(dir.path()).with_extension("json.tmp");
        assert!(!tmp.exists(), "atomic write must not leak tmp file");
    }

    // ── end-to-end: install N writes, install N+1 diffs ───────────

    #[test]
    fn install_n_writes_snapshot_install_n_plus_1_detects_addition() {
        // Simulates the audit-prescribed flow:
        //   1. User runs install with manifest M1.
        //   2. Snapshot is written with M1's bindings.
        //   3. A poisoned PR adds "axios@1.14.1" to the manifest.
        //   4. User runs install with manifest M2. Before the install
        //      modifies anything, the diff surfaces axios@1.14.1.
        let dir = tempdir().unwrap();

        // Install N: snapshot M1 = {esbuild@0.25.1}.
        let m1 = rich_td(&[("esbuild@0.25.1", Some("sha512-e"), Some("sha256-es"))]);
        let snap_n = TrustSnapshot::capture_current(&m1);
        write_snapshot(dir.path(), &snap_n).unwrap();

        // Install N+1: read the prior snapshot and diff against the
        // new manifest M2 = {esbuild@0.25.1, axios@1.14.1}.
        let prior = read_snapshot(dir.path()).expect("snapshot N readable");
        let m2 = rich_td(&[
            ("esbuild@0.25.1", Some("sha512-e"), Some("sha256-es")),
            ("axios@1.14.1", None, None),
        ]);
        let snap_n_plus_1 = TrustSnapshot::capture_current(&m2);
        let adds = snap_n_plus_1.diff_additions(Some(&prior));

        assert_eq!(
            adds,
            vec!["axios@1.14.1".to_string()],
            "silent manifest addition MUST be flagged on the next install \
             (audit-prescribed end-to-end regression)"
        );

        // And the rendered notice names the CTA to inspect.
        let notice = format_new_bindings_notice(&adds).expect("non-empty");
        assert!(notice.contains("axios@1.14.1"));
        assert!(notice.contains("lpm trust diff"));
    }
}
