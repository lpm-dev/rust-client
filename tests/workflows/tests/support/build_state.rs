//! Shared fixture helpers for `.lpm/build-state.json` seeding.
//!
//! ## Why this exists (finding D from the #72/#73/#76 review)
//!
//! Three historical fixture writers in this tree hand-wrote a
//! synthetic `"script_hash": "sha256-fixture-script-hash"` into
//! build-state.json:
//!
//! - `tests/approve_scripts.rs::write_blocked_build_state`
//! - `tests/approve_scripts.rs::write_global_install_blocked_state`
//! - `tests/install_global_security.rs::write_global_install_blocked_state`
//!
//! Those tests are currently safe because none of them invoke
//! `lpm rebuild` afterward — `compute_script_hash` is only consulted
//! by the rebuild trust gate, and approve-scripts itself propagates
//! whatever string the fixture wrote. But the finding #75 retraction
//! exposed the latent footgun: the moment any test combines
//! "synthetic build-state.json" with "live rebuild step," rebuild
//! recomputes the real hash from disk, observes the mismatch, and
//! filters the package out as `TrustMatch::BindingDrift`. The
//! symptom looks like "rebuild ignores trustedDependencies" — pure
//! mis-diagnosis fuel.
//!
//! The helpers below replace all three writers with one shape that
//! computes the **real** `script_hash` via
//! `lpm_security::script_hash::compute_script_hash`. New tests that
//! add a rebuild step now inherit correct hash semantics for free,
//! and finding #75's misdiagnosis pattern cannot repeat.
//!
//! ## What the helpers do
//!
//! Both helpers stage a minimal store-dir entry under
//! `<project>/.lpm/store/v1/<name>@<version>/` containing a
//! `package.json` with a `postinstall` script, then compute the
//! script_hash from that staged content and write the build-state.json
//! row referencing it. The store entry is the same shape rebuild walks
//! to recompute the hash, so the two stay in lockstep.

use super::TempProject;
use std::path::{Path, PathBuf};

/// Minimal store-dir layout for one fake postinstall-emitting package.
/// Mirrors what `lpm install` would have left in the store after a
/// successful download + extract. Only the `package.json` + a
/// non-empty `.integrity` file are needed for the rebuild-side
/// rehash + integrity-skip dance.
fn stage_minimal_store_entry(store_dir: &Path) -> String {
    std::fs::create_dir_all(store_dir)
        .unwrap_or_else(|e| panic!("failed to create store entry {}: {e}", store_dir.display()));
    let pkg_json_content = serde_json::json!({
        "name": store_dir.file_name().and_then(|n| n.to_str()).unwrap_or("fixture-pkg"),
        "version": "1.0.0",
        "scripts": { "postinstall": "echo lpm-fixture-postinstall" },
    });
    std::fs::write(
        store_dir.join("package.json"),
        serde_json::to_vec(&pkg_json_content).unwrap(),
    )
    .unwrap();
    std::fs::write(store_dir.join(".integrity"), "sha512-fixture-skip-verify").unwrap();
    lpm_security::script_hash::compute_script_hash(store_dir)
        .expect("the staged postinstall body is non-empty, so compute_script_hash must return Some")
}

/// Seed `<project>/.lpm/build-state.json` with one blocked entry whose
/// `script_hash` matches the real value `compute_script_hash` would
/// produce against the project's store dir. The store entry is staged
/// as a side effect under `<project>/.lpm/store/v1/<name>@<version>/`
/// so `rebuild` can recompute the same hash on demand.
///
/// Use this in any approve-scripts / rebuild fixture. The function
/// returns the computed hash so callers can assert on it directly
/// (e.g. propagating through `trustedDependencies` bindings).
pub fn seed_blocked_build_state_with_real_hash(
    project: &TempProject,
    name: &str,
    version: &str,
) -> String {
    let store_dir = project
        .store_dir()
        .join("v1")
        .join(format!("{name}@{version}"));
    let real_hash = stage_minimal_store_entry(&store_dir);
    let body = format!(
        r#"{{
    "state_version": 1,
    "blocked_set_fingerprint": "sha256-fixture-stable",
    "captured_at": "2026-04-22T00:00:00Z",
    "blocked_packages": [
        {{
            "name": "{name}",
            "version": "{version}",
            "integrity": "sha512-fixture-skip-verify",
            "script_hash": "{real_hash}",
            "phases_present": ["postinstall"],
            "binding_drift": false,
            "static_tier": "green",
            "published_at": "2026-04-22T00:00:00Z"
        }}
    ]
}}"#
    );
    project.write_file(".lpm/build-state.json", &body);
    real_hash
}

/// Global-install variant. Seeds the per-install build-state.json
/// under `<home>/.lpm/global/installs/<top_level>@<v>/.lpm/` with a
/// blocked entry whose `script_hash` is the real value computed
/// against a staged store entry under the same path. The aggregator
/// `approve-scripts --global` walks this file to populate the global
/// blocked set.
///
/// Default tier is `"green"` — matching what a fresh capture would
/// write for a benign postinstall body. Workflow tests that need to
/// exercise the M75 tier gate use [`seed_global_install_blocked_state_with_tier`]
/// to pin a specific static tier (or omit the field for legacy state).
///
/// Returns the per-install `.lpm/` dir path so callers can write
/// additional fixture state alongside (e.g. trusted-dependencies.json).
pub fn seed_global_install_blocked_state_with_real_hash(
    project: &TempProject,
    top_level: &str,
    top_level_version: &str,
    blocked_name: &str,
    blocked_version: &str,
) -> PathBuf {
    seed_global_install_blocked_state_with_tier(
        project,
        top_level,
        top_level_version,
        blocked_name,
        blocked_version,
        Some("green"),
    )
}

/// Same as [`seed_global_install_blocked_state_with_real_hash`] but
/// takes an explicit `tier` so workflow tests can exercise the M75
/// tier gate. Pass `Some("amber" | "amber-llm" | "red" | "green")` to
/// pin a specific tier in the build-state JSON, or `None` to omit the
/// `static_tier` field entirely (legacy / pre-classification state).
pub fn seed_global_install_blocked_state_with_tier(
    project: &TempProject,
    top_level: &str,
    top_level_version: &str,
    blocked_name: &str,
    blocked_version: &str,
    tier: Option<&str>,
) -> PathBuf {
    let install_root = project
        .home()
        .join(".lpm")
        .join("global")
        .join("installs")
        .join(format!("{top_level}@{top_level_version}"));
    let install_store_dir = install_root
        .join("store")
        .join(format!("{blocked_name}@{blocked_version}"));
    let real_hash = stage_minimal_store_entry(&install_store_dir);
    let install_lpm = install_root.join(".lpm");
    std::fs::create_dir_all(&install_lpm).unwrap();
    let tier_line = match tier {
        Some(t) => format!(",\n            \"static_tier\": \"{t}\""),
        None => String::new(),
    };
    let body = format!(
        r#"{{
    "state_version": 1,
    "blocked_set_fingerprint": "sha256-fixture-stable",
    "captured_at": "2026-04-22T00:00:00Z",
    "blocked_packages": [
        {{
            "name": "{blocked_name}",
            "version": "{blocked_version}",
            "integrity": "sha512-fixture-skip-verify",
            "script_hash": "{real_hash}",
            "phases_present": ["postinstall"],
            "binding_drift": false{tier_line}
        }}
    ]
}}"#
    );
    std::fs::write(install_lpm.join("build-state.json"), body).unwrap();
    install_lpm
}
