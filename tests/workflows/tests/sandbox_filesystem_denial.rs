//! End-to-end contract: the install-time sandbox denies writes to a
//! path outside its allow-list, and the install surfaces that failure
//! truthfully.
//!
//! Scope (explicit): **filesystem write denial only.** This test
//! exercises the sandbox property that IS enforced today —
//! Seatbelt's `(deny default)` + narrow `(allow file-write* ...)` on
//! macOS; landlock V1's path-based write rules on Linux. Both
//! platforms agree: writes to the project root itself (NOT inside
//! `node_modules` / `.husky` / `.lpm`) go to the deny path.
//!
//! Outbound-network denial is **not** in scope here. The current
//! sandbox unconditionally allows network (Seatbelt:
//! `(allow network*)`; landlock V1: no network rules at all —
//! filesystem-only). Phase 46.1 will implement network denial and
//! ship its own end-to-end test as the locked deliverable. Naming
//! this file `sandbox_filesystem_denial` instead of
//! `sandbox_network_denial` keeps that gap visible.
//!
//! ## What this proves
//!
//! The install pipeline correctly catches a sandbox enforcement
//! failure, surfaces it truthfully in stderr, doesn't write the
//! `.lpm-built` success marker, and the disallowed side-effect
//! (the forbidden file) is absent on disk afterward. Three
//! assertions only — no scope creep.
//!
//! ## Why the path choice
//!
//! The synthetic package's `postinstall: "node install.js"` runs
//! `install.js`, which attempts to write to a path passed via
//! `LPM_TEST_FORBIDDEN_PATH` env var. The path is located OUTSIDE
//! every sandbox allow-list entry, observable from the rule layout:
//!
//! - macOS ([seatbelt.rs:158-173]): `file-write*` is the union of
//!   `package_dir`, `project_node_modules`, `project_husky`,
//!   `project_lpm`, a few home-cache subpaths, the literal `/tmp`
//!   subpath, the `tmpdir` ($TMPDIR) subpath, `/dev/null`, and
//!   `/dev/tty`.
//! - Linux ([landlock_rules.rs:99-122]): `ReadWrite` rules are
//!   `package_dir`, `project_dir/node_modules`, `project_dir/
//!   .husky`, `project_dir/.lpm`, home-cache subpaths, literal
//!   `/tmp`, `tmpdir`, and the two /dev literals.
//!
//! Picking a forbidden path that satisfies all these constraints —
//! outside `/tmp`, outside `$TMPDIR`, outside `TempProject`'s
//! project/home tree — is harder than it looks. `TempProject`'s
//! standard helpers create dirs via `tempfile::tempdir()`, which
//! roots under `$TMPDIR` on macOS (`/var/folders/...`) and `/tmp`
//! on Linux. So `<project>/forbidden.txt` is ALREADY inside the
//! sandbox's tmpdir + `/tmp` allow path on either platform —
//! attempting it would silently bypass denial via the existing
//! tmpdir rule.
//!
//! The robust answer: create the forbidden-path parent under the
//! TEST PROCESS's REAL `$HOME` (not TempProject's overridden HOME),
//! via `tempfile::Builder::tempdir_in($HOME)`. On every supported
//! platform (developer macOS, Linux CI, macOS CI), `$HOME` lives
//! outside `/tmp` and outside `$TMPDIR`. TempProject's overridden
//! HOME inside `$TMPDIR` keeps its sandbox allow-list entries
//! (home_cache etc.) elsewhere, so they don't accidentally cover
//! this path either. The tempdir cleans up on drop, leaving no
//! breadcrumbs in the developer's HOME.

mod support;

use std::path::PathBuf;

use support::mock_registry::{MockRegistry, make_tarball_from_pkg_json};
use support::{TempProject, lpm_with_registry};

// ─── Test constants ────────────────────────────────────────────────────

const DEP_NAME: &str = "synthetic-fs-denial-dep";
const DEP_VERSION: &str = "1.0.0";
/// The lifecycle script runs `node install.js`. `install.js` reads
/// `LPM_TEST_FORBIDDEN_PATH` from the env and attempts one
/// `writeFileSync`. The env var passes through
/// `build_sanitized_env` unchanged — it doesn't match any of the
/// stripped credential patterns (`*_SECRET`, `*_PASSWORD`,
/// `*_KEY`, `*_PRIVATE_KEY`, or the explicit token list at
/// `rebuild.rs:93-104`).
///
/// No try/catch in the script: a sandbox denial throws `EACCES` or
/// similar, the node process exits non-zero, the build pipeline
/// records the failure, and `.lpm-built` is NOT written. If the
/// sandbox FAILED to deny, the write would succeed, the script
/// would exit 0, `.lpm-built` would be created, AND the forbidden
/// file would exist on disk — caught by assertions 2 and 3.
const INSTALL_JS_BODY: &[u8] = br#"
const fs = require('fs');
const target = process.env.LPM_TEST_FORBIDDEN_PATH;
if (!target) {
    console.error('LPM_TEST_FORBIDDEN_PATH unset; test harness misconfigured');
    process.exit(2);
}
// Deliberately no try/catch -- a sandbox denial must propagate as
// non-zero exit so the install pipeline observes the failure.
fs.writeFileSync(target, 'sandbox-bypass-evidence');
console.error('UNEXPECTED: write to ' + target + ' succeeded');
"#;

// ─── Fixture builders ──────────────────────────────────────────────────

/// Build a tarball whose `postinstall` runs `node install.js`. The
/// `node install.js` form is classified as `Amber` (reserved
/// binary-fetcher basename) by L1, but this test runs under
/// `--policy=allow` so the trust gate is bypassed — every scripted
/// package executes regardless of tier. That isolates the test to
/// "sandbox enforcement at install time," independent of the
/// triage gate.
fn build_fs_denial_tarball() -> Vec<u8> {
    let pkg_json = serde_json::json!({
        "name": DEP_NAME,
        "version": DEP_VERSION,
        "scripts": {
            "postinstall": "node install.js",
        }
    });
    make_tarball_from_pkg_json(pkg_json, &[("install.js", INSTALL_JS_BODY)])
}

/// Project manifest depending on the synthetic dep. No
/// `scriptPolicy` setting — the test passes `--policy=allow` on the
/// CLI for the same effect with the additional guarantee that
/// `auto_build_attempted` widens (the Allow policy alone fires
/// auto-build per Phase 57). Picking the CLI flag rather than the
/// manifest key is cosmetic — both routes converge at
/// `ScriptPolicy::Allow` after `resolve_script_policy`.
fn project_manifest() -> String {
    format!(
        r#"{{
    "name": "sandbox-fs-denial-fixture",
    "version": "1.0.0",
    "dependencies": {{
        "{DEP_NAME}": "^{DEP_VERSION}"
    }}
}}
"#
    )
}

/// Mount metadata + tarball for the synthetic dep on the mock
/// registry. Same shape as `triage_install_lifecycle.rs`:
/// per-package metadata + batch metadata (the install pipeline
/// fetches the latter first). `time[version]` is far in the past
/// so the L3 cooldown gate doesn't fire — this test is pinned on
/// sandbox enforcement, not cooldown side effects.
async fn mount_fs_denial_dep(mock: &MockRegistry, tarball: &[u8]) {
    mock.with_package(DEP_NAME, DEP_VERSION, tarball).await;
    let tarball_url = format!("{}/tarballs/{DEP_NAME}-{DEP_VERSION}.tgz", mock.url());
    let integrity = support::mock_registry::compute_integrity(tarball);
    let version_owned = DEP_VERSION.to_string();
    let mut versions = serde_json::Map::new();
    versions.insert(
        version_owned.clone(),
        serde_json::json!({
            "name": DEP_NAME,
            "version": DEP_VERSION,
            "dist": {
                "tarball": tarball_url,
                "integrity": integrity,
            },
            "dependencies": {}
        }),
    );
    let mut time = serde_json::Map::new();
    time.insert(
        version_owned,
        serde_json::Value::String("2024-01-01T00:00:00.000Z".to_string()),
    );
    mock.with_batch_metadata(vec![serde_json::json!({
        "name": DEP_NAME,
        "dist-tags": { "latest": DEP_VERSION },
        "versions": serde_json::Value::Object(versions),
        "time": serde_json::Value::Object(time),
    })])
    .await;
}

// ─── Observability helpers ─────────────────────────────────────────────

/// Path to the build-pipeline `.lpm-built` marker for the synthetic
/// dep. Written ONLY when the lifecycle script exits 0; absence
/// after a sandbox denial is the proof that the build pipeline saw
/// the failure and refused to mint a success marker.
fn lpm_built_marker(project: &TempProject) -> PathBuf {
    let safe = DEP_NAME.replace(['/', '\\'], "+");
    project
        .store_dir()
        .join("v1")
        .join(format!("{safe}@{DEP_VERSION}"))
        .join(".lpm-built")
}

/// Strip ANSI color codes so assertions don't fight terminal
/// styling. Same helper shape as `rebuild.rs`.
fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' && chars.peek() == Some(&'[') {
            chars.next();
            for cc in chars.by_ref() {
                let cb = cc as u32;
                if (0x40..=0x7e).contains(&cb) {
                    break;
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// `true` if `node` is on PATH. The synthetic postinstall is `node
/// install.js`, so without node we can't exercise the spawn path
/// at all — soft-pass the test rather than fail on environment.
fn node_available() -> bool {
    std::process::Command::new("node")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

// ─── Contract — filesystem write denial at install time ───────────────

/// Synthetic package's postinstall attempts a write to a path the
/// sandbox's `file-write*` allow list does not cover. The sandbox
/// MUST deny the write, the build pipeline MUST observe the script
/// failure, AND the forbidden file MUST NOT appear on disk.
///
/// Three assertions, no scope creep:
///   1. Install surfaces the script failure truthfully in stderr
///      (the existing `output::warn("Auto-build failed: ...")` path,
///      OR the rebuild pipeline's per-package error surface).
///   2. `.lpm-built` marker is absent for the synthetic dep.
///   3. The forbidden file is absent at `<project>/forbidden.txt`.
///
/// Unix-only for the same reason `triage_install_lifecycle.rs`
/// guards `claude-cli` mock setup behind `#[cfg(unix)]`: the
/// sandbox + lifecycle-script pipeline doesn't ship a Windows
/// backend in Phase 46 P5 (see `lpm-sandbox/src/lib.rs:20` —
/// Windows is deferred to Phase 46.1 D10). A Windows test would
/// be pinning a not-yet-implemented contract — exactly the
/// failure mode this test file is named to avoid.
#[cfg(unix)]
#[tokio::test]
async fn postinstall_write_outside_allow_list_is_denied_marker_absent_file_absent() {
    if !node_available() {
        // Soft-pass: this test is fundamentally about a Node-spawned
        // script hitting the sandbox. Without `node` on PATH the
        // spawn step never runs and there's nothing to gate.
        // Mirroring the `rebuild.rs` precedent (e.g.
        // `rebuild_triage_default_build_points_at_approve_scripts_for_blocked`
        // skips its spawn-side assertion under the same condition).
        eprintln!("skipping: node not on PATH");
        return;
    }

    let mock = MockRegistry::start().await;
    let tarball = build_fs_denial_tarball();
    mount_fs_denial_dep(&mock, &tarball).await;

    let project = TempProject::empty(&project_manifest());

    // The forbidden path's parent has to be outside `/tmp` AND
    // outside `$TMPDIR` AND outside TempProject's project/home tree
    // -- otherwise it falls under the sandbox's literal `/tmp`
    // allow, the `tmpdir` subpath allow, or one of the project /
    // home-cache subpaths. The only stable parent satisfying all
    // three is the TEST PROCESS's REAL `$HOME`. TempProject's
    // overridden HOME (for the lpm subprocess) is in $TMPDIR; the
    // sandbox's home_cache / home_node_gyp / home_npm rules
    // therefore point INSIDE $TMPDIR, well away from this real-HOME
    // tempdir. Cleans up automatically on drop.
    let real_home = std::env::var_os("HOME").expect(
        "HOME must be set for this test to choose a forbidden path outside `/tmp` / `$TMPDIR`",
    );
    let forbidden_parent = tempfile::Builder::new()
        .prefix("lpm-fs-denial-")
        .tempdir_in(&real_home)
        .expect("create forbidden-parent tempdir under real HOME");
    let forbidden_path = forbidden_parent.path().join("forbidden.txt");
    assert!(
        !forbidden_path.exists(),
        "forbidden path must not pre-exist: {}",
        forbidden_path.display(),
    );

    let out = lpm_with_registry(&project, &mock.url())
        // `--policy=allow` bypasses the triage gate so the amber
        // tier doesn't block execution — the test isolates SANDBOX
        // enforcement from TRIAGE gating. Allow also fires auto-
        // build automatically (Phase 57), so we don't need
        // `--auto-build` to widen the rebuild path.
        .args(["install", "--policy=allow"])
        .env("LPM_TEST_FORBIDDEN_PATH", &forbidden_path)
        .output()
        .expect("spawn lpm install");
    let stderr = strip_ansi(&String::from_utf8_lossy(&out.stderr));
    let stdout = strip_ansi(&String::from_utf8_lossy(&out.stdout));

    // ── Assertion 1: install surfaces the failure truthfully. ──
    //
    // The install pipeline wraps auto-build failures in a soft
    // `output::warn("Auto-build failed: ...")` (`install.rs:6920`),
    // so the install exit code is still 0 — that's the existing
    // contract this test is NOT trying to change. What we DO
    // require is that the failure is VISIBLE somewhere in the
    // user-facing output, with at least one signal from each of
    // the two layers that observe it:
    //
    //   (a) The OS-level sandbox denial: EPERM (macOS Seatbelt) or
    //       EACCES (Linux landlock) appears in the script's stderr.
    //       This proves the SANDBOX actually denied the write
    //       rather than something else upstream killing the
    //       script.
    //   (b) The install-pipeline-level acknowledgement: a
    //       per-package "postinstall failed" surface or an
    //       aggregate "Auto-build failed" / "package(s) failed to
    //       build" line. This proves the build runner observed
    //       the script's non-zero exit and surfaced it rather
    //       than silently treating the package as successfully
    //       built.
    //
    // Requiring BOTH catches two distinct regressions:
    //   - (a) only: sandbox denied but install reported success →
    //     user has no signal the package needs review.
    //   - (b) only: install reported failure but cause was not
    //     sandbox enforcement → could be a transient network
    //     error, OOM, etc. — test would be giving false confidence
    //     in sandbox containment.
    let combined = format!("{stderr}\n{stdout}");
    let signals_sandbox_denial = combined.contains("EPERM")
        || combined.contains("EACCES")
        || combined.contains("operation not permitted")
        || combined.contains("Operation not permitted");
    assert!(
        signals_sandbox_denial,
        "install output must contain the OS-level sandbox-denial signal (EPERM / EACCES / \
         'operation not permitted'). Without it, the script failure could have any cause; \
         this test is asserting SANDBOX enforcement specifically.\nstderr:\n{stderr}\nstdout:\n{stdout}"
    );
    let signals_install_acknowledgement = combined.contains("postinstall failed")
        || combined.contains("Auto-build failed")
        || combined.contains("failed to build");
    assert!(
        signals_install_acknowledgement,
        "install must observe the script failure and surface it in user-facing output \
         (per-package 'postinstall failed' line OR aggregate 'Auto-build failed' / \
         'failed to build'). A silent success here is a contract regression — the user \
         would have no signal the package needs review.\nstderr:\n{stderr}\nstdout:\n{stdout}"
    );

    // ── Assertion 2: `.lpm-built` marker is absent. ──
    //
    // The marker is written by the build pipeline ONLY on a
    // successful (exit 0) lifecycle-script spawn. A sandbox-denied
    // write inside install.js throws unhandled EACCES → node exits
    // non-zero → no marker. If the marker exists, either the
    // sandbox failed to deny (regression), or the build pipeline
    // wrote the marker without observing the script's exit code
    // (a different, equally bad regression).
    let marker = lpm_built_marker(&project);
    assert!(
        !marker.exists(),
        ".lpm-built marker MUST be absent after a sandbox-denied lifecycle script; \
         found at {}\nstderr:\n{stderr}",
        marker.display(),
    );

    // ── Assertion 3: the forbidden file is absent on disk. ──
    //
    // The strongest signal: if the sandbox bypassed denial, the
    // file would exist with the bytes `sandbox-bypass-evidence`.
    // Belt-and-suspenders alongside assertion 2 — even if the
    // build pipeline incorrectly wrote `.lpm-built` AND the
    // sandbox correctly blocked, this assertion catches the
    // first failure path. Conversely, even if `.lpm-built` is
    // correctly absent but the sandbox somehow let the write
    // through, this assertion catches THAT failure path.
    assert!(
        !forbidden_path.exists(),
        "SANDBOX BYPASS: the lifecycle script wrote to {} despite the sandbox's \
         file-write* allow list excluding the project root. This is a real \
         security regression. stderr:\n{stderr}",
        forbidden_path.display(),
    );
}
