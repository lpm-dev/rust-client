//! Phase 48 P0 end-to-end round-trip: offline install honors the
//! capability gate + approve-scripts persists a capability_hash
//! that subsequent enforcement accepts.
//!
//! This test exercises the real `lpm-rs` binary against a mock
//! registry, covering the `run_link_and_finish` offline path
//! (install.rs:4062) plus the approve-scripts discovery + write
//! paths, over file-backed `.lpm/build-state.json` + `package.json`
//! state transitions.
//!
//! Closes the validation gap the reviewer flagged in the final
//! audit pass: the helper-level invariants were already covered by
//! unit tests, but the subprocess-level offline command path + its
//! file-backed state transitions were not.
//!
//! # Scenario
//!
//! 1. Install a scripted package online (populates store + lockfile
//!    + initial blocked-set capture).
//! 2. Author a rich strict approval for the package's script hash
//!    in `package.json > lpm > trustedDependencies` (no
//!    `capabilityHash` — pre-sub-slice-6d shape).
//! 3. Author a widening `package.json > lpm > scripts > passEnv`
//!    declaration. The package is now strict-matched on script
//!    hash but widens capability beyond the user floor.
//! 4. Run `lpm install --offline` → exercises
//!    `run_link_and_finish`. The fix pins: build-state.json MUST
//!    include the package so approve-scripts has something to
//!    surface. (Before the fix, the strict-only filter dropped
//!    it silently and `lpm build` later skipped with
//!    `CapabilityNotApproved` — no user-visible remediation
//!    path.)
//! 5. `lpm approve-scripts --list --json` must show the package
//!    (discovery-side filter honors capability gate).
//! 6. `lpm approve-scripts --yes` must write a `capabilityHash`
//!    onto the binding (6d write-path).
//! 7. One more `lpm install --offline` must produce an empty
//!    blocked set — the persisted `capabilityHash` satisfies the
//!    enforcement layer, confirming the round-trip is byte-for-
//!    byte consistent (hash written = hash enforced).

mod support;

use std::io::Write;
use support::mock_registry::MockRegistry;
use support::{TempProject, lpm_with_registry};

/// Build a gzipped tarball for a mock package that declares a
/// `postinstall` script. The script body never actually executes
/// in this test (`lpm install` doesn't auto-run lifecycle scripts;
/// it would take an explicit `lpm build` / `lpm rebuild` for that,
/// which this test doesn't invoke), so the script payload is just
/// a no-op marker string.
fn make_scripted_tarball(name: &str, version: &str) -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());

    let pkg_json = serde_json::json!({
        "name": name,
        "version": version,
        "main": "index.js",
        "scripts": {
            // Minimal benign script body. Never runs during this
            // test — we exercise approve-scripts not rebuild.
            // `tsc` is in the static classifier's green allow-
            // list (see lpm-security::static_gate), so
            // `approve-scripts --yes` does not refuse bulk-
            // approval. Never actually executes in this test;
            // classification is syntactic.
            "postinstall": "tsc"
        }
    });
    let body = serde_json::to_vec(&pkg_json).unwrap();
    let mut header = tar::Header::new_gnu();
    header.set_path("package/package.json").unwrap();
    header.set_size(body.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    builder.append(&header, &body[..]).unwrap();

    let idx = b"module.exports = {};";
    let mut header = tar::Header::new_gnu();
    header.set_path("package/index.js").unwrap();
    header.set_size(idx.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    builder.append(&header, &idx[..]).unwrap();

    let raw = builder.into_inner().unwrap();
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    gz.write_all(&raw).unwrap();
    gz.finish().unwrap()
}

#[tokio::test]
async fn offline_install_capability_round_trip_end_to_end() {
    // ── Mock registry with a scripted package ──
    let mock = MockRegistry::start().await;
    let tarball = make_scripted_tarball("phase48-roundtrip", "1.0.0");
    mock.with_package("phase48-roundtrip", "1.0.0", &tarball)
        .await;

    let batch_meta = serde_json::json!({
        "name": "phase48-roundtrip",
        "dist-tags": { "latest": "1.0.0" },
        "versions": {
            "1.0.0": {
                "name": "phase48-roundtrip",
                "version": "1.0.0",
                "dist": {
                    "tarball": format!("{}/tarballs/phase48-roundtrip-1.0.0.tgz", mock.url()),
                    "integrity": "sha512-placeholder"
                },
                "scripts": { "postinstall": "tsc" },
                "dependencies": {}
            }
        },
        "time": { "1.0.0": "2025-01-01T00:00:00.000Z" }
    });
    mock.with_batch_metadata(vec![batch_meta]).await;

    let project = TempProject::empty(
        r#"{
            "name": "offline-cap-roundtrip",
            "version": "1.0.0",
            "dependencies": { "phase48-roundtrip": "^1.0.0" }
        }"#,
    );

    // ── First install online ──
    lpm_with_registry(&project, &mock.url())
        .args([
            "install",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .assert()
        .success();

    // After the first install, the package is blocked (unapproved).
    // Grab the script_hash the install recorded so we can craft a
    // matching strict binding below.
    let bs_path = project.path().join(".lpm/build-state.json");
    let bs: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(&bs_path).expect("build-state.json after first install"),
    )
    .expect("build-state.json parses");
    assert_eq!(
        bs["blocked_packages"]
            .as_array()
            .map(|a| a.len())
            .unwrap_or(0),
        1,
        "initial install should block the unapproved scripted package: {bs:#}"
    );
    let script_hash = bs["blocked_packages"][0]["script_hash"]
        .as_str()
        .expect("script_hash recorded")
        .to_string();

    // ── Author a rich strict approval (no capabilityHash) + a
    //    widening `passEnv` declaration ──
    //
    // This is the Phase 48 P0 reviewer's High-finding scenario:
    // strict script-hash trust would pass, but the capability
    // gate (added in sub-slice 6c) should still block. The
    // pre-fix offline path would have silently dropped this row
    // from build-state.json.
    let rewritten_pkg = serde_json::json!({
        "name": "offline-cap-roundtrip",
        "version": "1.0.0",
        "dependencies": { "phase48-roundtrip": "^1.0.0" },
        "lpm": {
            "trustedDependencies": {
                "phase48-roundtrip@1.0.0": { "scriptHash": script_hash }
            },
            "scripts": { "passEnv": ["SSH_AUTH_SOCK"] }
        }
    });
    std::fs::write(
        project.path().join("package.json"),
        serde_json::to_string_pretty(&rewritten_pkg).unwrap(),
    )
    .unwrap();

    // Drop node_modules so the next install actually re-links.
    let nm = project.path().join("node_modules");
    if nm.exists() {
        std::fs::remove_dir_all(&nm).unwrap();
    }

    // ── OFFLINE install ── (exercises `run_link_and_finish`)
    lpm_with_registry(&project, &mock.url())
        .args([
            "install",
            "--offline",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .assert()
        .success();

    // ── 1) Capture-side: blocked set must include the widened
    //       package even though the script hash matches strict ──
    let bs: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(&bs_path).expect("build-state.json after offline install"),
    )
    .expect("build-state.json parses");
    let blocked = bs["blocked_packages"]
        .as_array()
        .expect("blocked_packages array");
    assert_eq!(
        blocked.len(),
        1,
        "capability-widening package MUST land in blocked_packages despite strict match — \
         reviewer's High finding. Before the offline-path fix, `run_link_and_finish` \
         hardcoded baseline capability defaults and the row was silently dropped. \
         Full build-state: {bs:#}"
    );
    assert_eq!(blocked[0]["name"], "phase48-roundtrip");
    assert_eq!(
        blocked[0]["binding_drift"], true,
        "capture flags this as drift so approve-scripts renders 'previously approved, please re-review'"
    );

    // ── 2) Discovery-side: approve-scripts --list --json shows
    //       the package ──
    let out = lpm_with_registry(&project, &mock.url())
        .args(["approve-scripts", "--list", "--json"])
        .output()
        .expect("approve-scripts --list run");
    assert!(
        out.status.success(),
        "approve-scripts --list failed: stdout={:?}, stderr={:?}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    let listing: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("approve-scripts --list --json output");
    // The --list --json envelope uses "blocked" for the listing
    // (see approve_scripts.rs:1127). Older shapes also existed —
    // we match the current wire contract.
    let listed = listing["blocked"]
        .as_array()
        .expect("`blocked` array in --list --json output");
    assert!(
        listed.iter().any(|p| p["name"] == "phase48-roundtrip"),
        "approve-scripts --list must surface the capability-widened package — \
         reviewer's Medium finding (the discovery filter needed to consult \
         the capability gate, not just the strict match). Full listing: {listing:#}"
    );

    // ── 3) Write-path: approve-scripts --yes persists capabilityHash ──
    lpm_with_registry(&project, &mock.url())
        .args(["approve-scripts", "--yes"])
        .assert()
        .success();
    let pkg_json: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(project.path().join("package.json")).unwrap(),
    )
    .unwrap();
    let binding = &pkg_json["lpm"]["trustedDependencies"]["phase48-roundtrip@1.0.0"];
    let cap_hash = binding["capabilityHash"].as_str().expect(
        "approve-scripts MUST persist capabilityHash for a widening approval \
         (sub-slice 6d write-path contract)",
    );
    assert!(
        cap_hash.starts_with("sha256-"),
        "capabilityHash must be sha256-<hex> SRI form; got {cap_hash:?}"
    );

    // ── 4) Round-trip: third install must produce an empty
    //       blocked set — the persisted hash satisfies the
    //       enforcement layer ──
    //
    // This is the load-bearing invariant for the whole lane:
    // hash written by approve-scripts == hash enforced by
    // evaluate_trust. If the install flow parses / hashes /
    // persists differently than enforcement does, this
    // assertion fires as a mismatch.
    lpm_with_registry(&project, &mock.url())
        .args([
            "install",
            "--offline",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .assert()
        .success();
    let bs: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&bs_path).unwrap()).unwrap();
    assert_eq!(
        bs["blocked_packages"]
            .as_array()
            .map(|a| a.len())
            .unwrap_or(0),
        0,
        "after approve-scripts persisted the capabilityHash, the next \
         offline install's blocked set must be empty — proves the \
         written hash matches the enforced hash byte-for-byte. \
         Full build-state: {bs:#}"
    );
}
