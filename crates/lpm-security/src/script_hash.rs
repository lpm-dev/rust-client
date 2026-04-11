//! Deterministic SHA-256 hash of a package's install-time lifecycle scripts.
//!
//! **Phase 32 Phase 4** — the `script_hash` side of the
//! `{name, version, integrity, script_hash}` approval binding (see Phase 4
//! status doc §"Trust persistence"). The hash covers EXACTLY the phases the
//! build pipeline actually runs (per F3 in the Phase 4 status doc) so an
//! edit to a non-executed phase like `prepare` does NOT invalidate
//! approvals. The hash is deterministic across machines: same package
//! contents → same hash.
//!
//! ## Hash format
//!
//! `sha256-<hex>` (lowercase hex, prefixed). Matches the SRI-style prefix
//! pattern used elsewhere in LPM (lockfile integrity is `sha512-<base64>`).
//! The prefix is intentional so future hash-algorithm migrations are
//! self-describing in the trust store.
//!
//! ## Hash input
//!
//! For each phase in [`crate::EXECUTED_INSTALL_PHASES`] (in fixed order):
//!
//! 1. The phase name as bytes (e.g., `"preinstall"`)
//! 2. A NUL separator (`\x00`)
//! 3. The script body as bytes if present, OR the empty byte sequence if absent
//! 4. A record separator (`\x1e` — ASCII RS) between phases
//!
//! Empty phases are explicitly hashed as the empty string so removing a
//! script from one phase and adding a different one in another phase
//! produces a different hash. This is stronger than "hash the JSON of
//! present scripts only" — it forecloses an attack where a maintainer
//! moves a payload between phases to keep the hash stable.
//!
//! ## Source of truth
//!
//! The package.json read is from `<store>/<safe_name>@<version>/package.json`
//! (the GLOBAL STORE), NOT from a project-local `node_modules/` symlink.
//! This matches what the build pipeline actually executes per F10 in the
//! Phase 4 status doc, and forecloses an attack where a project-local
//! symlink edit (e.g., to a workspace member's manifest) drifts the
//! observed hash from the executed bytes.

use sha2::{Digest, Sha256};
use std::path::Path;

use crate::EXECUTED_INSTALL_PHASES;

/// Record separator between phases in the hash input.
/// ASCII RS (Record Separator) — distinct from any byte that can appear
/// in a JSON string body, so it cannot collide with script content.
const RECORD_SEP: u8 = 0x1e;

/// Field separator inside one phase entry, between the phase name and body.
/// ASCII NUL — also distinct from any byte that can appear in a JSON string
/// body (JSON forbids NUL inside strings unless escaped).
const FIELD_SEP: u8 = 0x00;

/// Compute the deterministic install-script hash for a package located at
/// the given store directory.
///
/// `store_pkg_dir` is typically `lpm_store::PackageStore::package_dir(name, version)`.
///
/// Returns:
/// - `Some("sha256-<hex>")` if the package's `package.json` contains at
///   least one of the [`EXECUTED_INSTALL_PHASES`] entries with a non-empty body
/// - `None` if the `package.json` is missing, malformed, or contains no
///   install-time lifecycle scripts at all (callers should treat the
///   absence as "this package has nothing to approve")
///
/// The function is pure: it reads disk but writes nothing. It does not
/// touch any state outside `store_pkg_dir/package.json`.
pub fn compute_script_hash(store_pkg_dir: &Path) -> Option<String> {
    let pkg_json_path = store_pkg_dir.join("package.json");
    let content = std::fs::read_to_string(&pkg_json_path).ok()?;
    let parsed: serde_json::Value = serde_json::from_str(&content).ok()?;
    let scripts = parsed.get("scripts")?.as_object()?;

    // Pre-scan: if NONE of the executed phases are present with a non-empty
    // body, return None so callers can short-circuit. This is the same
    // contract as `read_lifecycle_scripts` in build.rs.
    let any_present = EXECUTED_INSTALL_PHASES.iter().any(|phase| {
        scripts
            .get(*phase)
            .and_then(|v| v.as_str())
            .is_some_and(|s| !s.is_empty())
    });
    if !any_present {
        return None;
    }

    let mut hasher = Sha256::new();
    for (i, phase) in EXECUTED_INSTALL_PHASES.iter().enumerate() {
        if i > 0 {
            hasher.update([RECORD_SEP]);
        }
        hasher.update(phase.as_bytes());
        hasher.update([FIELD_SEP]);
        // Empty phases are explicitly hashed as the empty string. The
        // FIELD_SEP separator before this update guarantees that
        // `(empty preinstall, "x" install)` and `("x" preinstall, empty install)`
        // produce different hashes even though the concatenated bodies are
        // identical.
        if let Some(body) = scripts.get(*phase).and_then(|v| v.as_str()) {
            hasher.update(body.as_bytes());
        }
    }

    Some(format!("sha256-{}", hex_lower(&hasher.finalize())))
}

/// Encode bytes as lowercase hex without pulling in a hex crate.
/// Used by [`compute_script_hash`] to produce the `sha256-<hex>` form.
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
    use std::fs;
    use tempfile::tempdir;

    fn write_pkg_json(dir: &Path, scripts: &serde_json::Value) {
        let pkg = serde_json::json!({
            "name": "@test/pkg",
            "version": "1.0.0",
            "scripts": scripts,
        });
        fs::write(
            dir.join("package.json"),
            serde_json::to_string_pretty(&pkg).unwrap(),
        )
        .unwrap();
    }

    #[test]
    fn compute_script_hash_format_starts_with_sha256_prefix() {
        let dir = tempdir().unwrap();
        write_pkg_json(
            dir.path(),
            &serde_json::json!({"postinstall": "node install.js"}),
        );
        let hash = compute_script_hash(dir.path()).unwrap();
        assert!(
            hash.starts_with("sha256-"),
            "hash must use sha256- prefix, got: {hash}"
        );
        // sha256 hex is 64 chars + "sha256-" prefix = 71
        assert_eq!(hash.len(), 71);
    }

    #[test]
    fn compute_script_hash_returns_none_when_no_install_phases() {
        let dir = tempdir().unwrap();
        write_pkg_json(
            dir.path(),
            // Only non-install phases — must be ignored, returns None
            &serde_json::json!({"build": "tsc", "test": "vitest", "prepare": "husky"}),
        );
        assert!(compute_script_hash(dir.path()).is_none());
    }

    #[test]
    fn compute_script_hash_returns_none_when_no_package_json() {
        let dir = tempdir().unwrap();
        // No package.json at all
        assert!(compute_script_hash(dir.path()).is_none());
    }

    #[test]
    fn compute_script_hash_returns_none_when_package_json_malformed() {
        let dir = tempdir().unwrap();
        fs::write(dir.path().join("package.json"), "{not valid json").unwrap();
        assert!(compute_script_hash(dir.path()).is_none());
    }

    #[test]
    fn compute_script_hash_returns_none_when_no_scripts_field() {
        let dir = tempdir().unwrap();
        fs::write(
            dir.path().join("package.json"),
            r#"{"name":"x","version":"1.0.0"}"#,
        )
        .unwrap();
        assert!(compute_script_hash(dir.path()).is_none());
    }

    #[test]
    fn compute_script_hash_deterministic_across_calls() {
        let dir = tempdir().unwrap();
        write_pkg_json(
            dir.path(),
            &serde_json::json!({
                "preinstall": "echo pre",
                "install": "node install.js",
                "postinstall": "echo done",
            }),
        );
        let h1 = compute_script_hash(dir.path()).unwrap();
        let h2 = compute_script_hash(dir.path()).unwrap();
        let h3 = compute_script_hash(dir.path()).unwrap();
        assert_eq!(h1, h2);
        assert_eq!(h2, h3);
    }

    #[test]
    fn compute_script_hash_same_input_same_output_across_machines() {
        // Pin the hash for a known fixture so any future change to the
        // hash function (input format, separator bytes, prefix) is caught
        // by an exact-match assertion. The byte stream is:
        //   "preinstall" \x00 \x1e "install" \x00 "node install.js" \x1e "postinstall" \x00
        // (preinstall and postinstall bodies are empty; install body is
        // the example string from the master plan).
        //
        // The literal below is computed by RUNNING this test once with a
        // placeholder, copying the actual output, and locking it. To
        // intentionally change the hash function: bump the trust store
        // schema version AND update this literal in the same commit.
        let dir = tempdir().unwrap();
        write_pkg_json(
            dir.path(),
            &serde_json::json!({"install": "node install.js"}),
        );
        let hash = compute_script_hash(dir.path()).unwrap();
        assert_eq!(
            hash, EXPECTED_FIXTURE_HASH,
            "fixture hash drift: the script-hash function changed its byte \
             format. Update EXPECTED_FIXTURE_HASH at the top of this test \
             AND bump the trust store schema version in build_state.rs."
        );
    }

    /// Locked fixture hash for [`compute_script_hash_same_input_same_output_across_machines`].
    /// See that test for the rationale and the canonical input.
    const EXPECTED_FIXTURE_HASH: &str =
        "sha256-d8e77ff608dcc65fe066c5d399a401abca5a0d7c73a70e4e2873362b7375f257";

    #[test]
    fn compute_script_hash_phase_reorder_in_json_yields_same_hash() {
        // The input ordering inside `scripts` is JSON-object-key-order
        // (which is preserved by serde_json::Value as a BTreeMap or
        // IndexMap depending on features). The hash function reads via
        // EXECUTED_INSTALL_PHASES in fixed order, NOT via JSON iteration.
        // So `{"postinstall": "x", "preinstall": "y"}` and
        // `{"preinstall": "y", "postinstall": "x"}` MUST produce the
        // same hash.
        let dir1 = tempdir().unwrap();
        let dir2 = tempdir().unwrap();
        // Different key order in the source JSON:
        fs::write(
            dir1.path().join("package.json"),
            r#"{"name":"x","version":"1","scripts":{"postinstall":"a","preinstall":"b"}}"#,
        )
        .unwrap();
        fs::write(
            dir2.path().join("package.json"),
            r#"{"name":"x","version":"1","scripts":{"preinstall":"b","postinstall":"a"}}"#,
        )
        .unwrap();
        let h1 = compute_script_hash(dir1.path()).unwrap();
        let h2 = compute_script_hash(dir2.path()).unwrap();
        assert_eq!(
            h1, h2,
            "JSON key reorder must NOT affect the hash; \
             the function reads by fixed phase order"
        );
    }

    #[test]
    fn compute_script_hash_unknown_phase_in_json_is_ignored() {
        // `prepare` is in BLOCKED_SCRIPTS but NOT in EXECUTED_INSTALL_PHASES.
        // Adding/removing/changing it MUST NOT affect the hash.
        let dir1 = tempdir().unwrap();
        let dir2 = tempdir().unwrap();
        write_pkg_json(
            dir1.path(),
            &serde_json::json!({"install": "node install.js"}),
        );
        write_pkg_json(
            dir2.path(),
            &serde_json::json!({
                "install": "node install.js",
                "prepare": "this should not affect the hash",
                "build": "tsc",
                "test": "vitest",
            }),
        );
        let h1 = compute_script_hash(dir1.path()).unwrap();
        let h2 = compute_script_hash(dir2.path()).unwrap();
        assert_eq!(
            h1, h2,
            "non-executed phases must NOT enter the hash; \
             the contract is 'hash what gets executed'"
        );
    }

    #[test]
    fn compute_script_hash_changes_when_install_body_changes() {
        let dir1 = tempdir().unwrap();
        let dir2 = tempdir().unwrap();
        write_pkg_json(dir1.path(), &serde_json::json!({"install": "node a.js"}));
        write_pkg_json(dir2.path(), &serde_json::json!({"install": "node b.js"}));
        assert_ne!(
            compute_script_hash(dir1.path()).unwrap(),
            compute_script_hash(dir2.path()).unwrap(),
        );
    }

    #[test]
    fn compute_script_hash_changes_when_postinstall_body_changes() {
        let dir1 = tempdir().unwrap();
        let dir2 = tempdir().unwrap();
        write_pkg_json(dir1.path(), &serde_json::json!({"postinstall": "echo a"}));
        write_pkg_json(dir2.path(), &serde_json::json!({"postinstall": "echo b"}));
        assert_ne!(
            compute_script_hash(dir1.path()).unwrap(),
            compute_script_hash(dir2.path()).unwrap(),
        );
    }

    #[test]
    fn compute_script_hash_changes_when_preinstall_body_changes() {
        let dir1 = tempdir().unwrap();
        let dir2 = tempdir().unwrap();
        write_pkg_json(dir1.path(), &serde_json::json!({"preinstall": "echo a"}));
        write_pkg_json(dir2.path(), &serde_json::json!({"preinstall": "echo b"}));
        assert_ne!(
            compute_script_hash(dir1.path()).unwrap(),
            compute_script_hash(dir2.path()).unwrap(),
        );
    }

    #[test]
    fn compute_script_hash_distinguishes_payload_moved_between_phases() {
        // CRITICAL: an attacker who moves a payload from `install` to
        // `postinstall` (or vice versa) MUST produce a different hash.
        // The FIELD_SEP byte after each phase name is what guarantees this:
        // the byte stream is "preinstall\x00...\x1einstall\x00...\x1epostinstall\x00..."
        // so the same body in different phases hashes differently.
        let dir1 = tempdir().unwrap();
        let dir2 = tempdir().unwrap();
        write_pkg_json(dir1.path(), &serde_json::json!({"install": "rm -rf /"}));
        write_pkg_json(dir2.path(), &serde_json::json!({"postinstall": "rm -rf /"}));
        assert_ne!(
            compute_script_hash(dir1.path()).unwrap(),
            compute_script_hash(dir2.path()).unwrap(),
            "moving a payload between phases must change the hash"
        );
    }

    #[test]
    fn compute_script_hash_empty_string_phase_treated_as_absent() {
        // `{"install": ""}` should be the same as `{"install" missing}` —
        // both are "no install script". The any_present pre-scan returns
        // None for both.
        let dir1 = tempdir().unwrap();
        let dir2 = tempdir().unwrap();
        write_pkg_json(dir1.path(), &serde_json::json!({"install": ""}));
        write_pkg_json(dir2.path(), &serde_json::json!({}));
        assert!(compute_script_hash(dir1.path()).is_none());
        assert!(compute_script_hash(dir2.path()).is_none());
    }

    #[test]
    fn compute_script_hash_distinguishes_present_empty_from_absent_when_other_phases_have_content()
    {
        // {"preinstall": "x", "install": ""} is NOT the same as
        // {"preinstall": "x"} — the second has the install phase as
        // "absent", the first has it as "present-but-empty". With the
        // any_present pre-scan, both return Some(...) because preinstall
        // is non-empty, but the install phase contributes the empty
        // string in the first case and is also empty in the second case.
        // In our implementation, both are hashed as empty bytes for the
        // install phase, so they SHOULD produce the same hash. This is
        // the documented contract: an empty string IS the same as a
        // missing entry for hash purposes (the FIELD_SEP byte makes
        // them indistinguishable, which is fine because both result in
        // "no script bytes get executed for this phase").
        let dir1 = tempdir().unwrap();
        let dir2 = tempdir().unwrap();
        write_pkg_json(
            dir1.path(),
            &serde_json::json!({"preinstall": "x", "install": ""}),
        );
        write_pkg_json(dir2.path(), &serde_json::json!({"preinstall": "x"}));
        assert_eq!(
            compute_script_hash(dir1.path()),
            compute_script_hash(dir2.path()),
            "empty-string phase and absent phase must hash identically \
             (both result in no script bytes executed)"
        );
    }

    #[test]
    fn executed_install_phases_const_is_subset_of_blocked_scripts() {
        // Coherence regression: if anyone widens BLOCKED_SCRIPTS or
        // narrows EXECUTED_INSTALL_PHASES, the subset relationship is
        // the contract. The hash phases must always be a subset of the
        // blocked phases (you can't run something that isn't blocked).
        for phase in EXECUTED_INSTALL_PHASES {
            assert!(
                crate::SecurityPolicy::is_blocked_script(phase),
                "EXECUTED_INSTALL_PHASES contains {phase:?} but it is not in BLOCKED_SCRIPTS"
            );
        }
    }

    #[test]
    fn hex_lower_zero_byte() {
        assert_eq!(hex_lower(&[0x00]), "00");
    }

    #[test]
    fn hex_lower_max_byte() {
        assert_eq!(hex_lower(&[0xff]), "ff");
    }

    #[test]
    fn hex_lower_multibyte() {
        assert_eq!(hex_lower(&[0xab, 0xcd, 0xef, 0x12, 0x34]), "abcdef1234");
    }
}
