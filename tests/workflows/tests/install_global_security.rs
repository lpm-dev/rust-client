//! Workflow tests for `lpm install -g` security parity.
//!
//! Pins the user-facing CLI contracts for global install security:
//!
//! - The validator no longer rejects `--allow-new`, `--min-release-age`,
//!   `--ignore-provenance-drift`, or `--ignore-provenance-drift-all`
//!   on `-g`. (The previous error string `"not supported on lpm install
//!   -g"` is gone; flags pass parse + validation and reach the install
//!   pipeline. The validator-only tests below still stop at parse +
//!   validation; separate async workflow tests later in this file pin
//!   real `install -g` behavior against a mock registry.)
//!
//! - `lpm install -g pkg --policy=allow` and friends are no longer
//!   silently dropped at the dispatcher. Forwarding through to
//!   `install_global::run` is unit-tested in `crates/lpm-cli`; here we
//!   pin the CLI surface (parse + validator do not reject the
//!   combination).
//!
//! - End-to-end global-install coverage exists for the two highest-risk
//!   shipped gates: release-age cooldown (`--min-release-age`,
//!   `--allow-new`) and provenance drift
//!   (`--ignore-provenance-drift`, `--ignore-provenance-drift-all`),
//!   plus the allow-policy auto-build path. Those tests drive the real binary
//!   through `install -g` against a wiremock registry and assert on the
//!   actual success/block outcomes, not just the validator surface.
//!
//! - The shared `--policy` clap help text mentions the global rerun
//!   caveat (`lpm uninstall -g <pkg> && lpm install -g <pkg>` after
//!   approval, until `lpm rebuild --global` ships).
//!
//! - `approve-scripts --global --yes --dry-run --json` omits
//!   `next_step`; the live JSON path carries `next_step.origins` so
//!   agents can compute the reinstall command set without parsing prose.

mod support;

use support::assertions;
use support::build_state::seed_global_install_blocked_state_with_tier;
use support::mock_registry::{MockRegistry, compute_integrity, make_tarball_from_pkg_json};
use support::{
    TempProject, configure_fake_node, lpm, lpm_with_registry, write_npm_firewall_global_config,
};

const GLOBAL_E2E_PKG: &str = "@lpm.dev/acme.global-tool";
const GLOBAL_E2E_COMMAND: &str = "acme-global-tool";
const GLOBAL_E2E_APPROVED_VERSION: &str = "1.0.0";
const GLOBAL_E2E_CANDIDATE_VERSION: &str = "1.0.1";
const GLOBAL_E2E_PUBLISHER: &str = "github:acme/global-tool";
const GLOBAL_E2E_WORKFLOW_PATH: &str = ".github/workflows/publish.yml";
const GLOBAL_NPM_FIREWALL_PKG: &str = "global-firewall-tool";

/// ISO-8601 UTC timestamp `n_secs` ago. Mirrors the release-age helper in
/// `install.rs`; kept local so this workflow test is standalone.
fn iso8601_n_secs_ago(n_secs: i64) -> String {
    use chrono::SecondsFormat;
    let dt = chrono::Utc::now() - chrono::Duration::seconds(n_secs);
    dt.to_rfc3339_opts(SecondsFormat::Millis, true)
}

/// Small executable tarball accepted by `lpm install -g`.
///
/// Global installs reject libraries with no `bin`, so the cooldown / drift
/// success-path tests need a package that can fully commit. The body is never
/// executed during install; it only needs to exist so bin discovery succeeds.
fn make_global_tool_tarball(version: &str) -> Vec<u8> {
    let pkg_json = serde_json::json!({
        "name": GLOBAL_E2E_PKG,
        "version": version,
        "main": "index.js",
        "bin": {
            GLOBAL_E2E_COMMAND: "bin/acme-global-tool.js"
        }
    });
    make_tarball_from_pkg_json(
        pkg_json,
        &[(
            "bin/acme-global-tool.js",
            br#"#!/usr/bin/env node
console.log('acme-global-tool');
"#,
        )],
    )
}

/// Same executable fixture shape as [`make_global_tool_tarball`], but with a
/// deterministic `postinstall`. Used to prove that `install -g --policy=allow`
/// doesn't just resolve and link the package — it actually runs the lifecycle
/// script pipeline during the auto-build phase.
fn make_global_scripted_tool_tarball(version: &str) -> Vec<u8> {
    let pkg_json = serde_json::json!({
        "name": GLOBAL_E2E_PKG,
        "version": version,
        "main": "index.js",
        "bin": {
            GLOBAL_E2E_COMMAND: "bin/acme-global-tool.js"
        },
        "scripts": {
            "postinstall": "node build.js"
        }
    });
    make_tarball_from_pkg_json(
        pkg_json,
        &[
            (
                "bin/acme-global-tool.js",
                br#"#!/usr/bin/env node
console.log('acme-global-tool');
"#,
            ),
            (
                "build.js",
                br#"process.exit(0);
"#,
            ),
        ],
    )
}

/// Mount metadata + tarball for the global install security fixture with a caller-
/// supplied publication timestamp. No `dist.attestations` field is emitted;
/// this lets the drift tests drive the "approved present -> candidate absent"
/// path end-to-end without needing a separate attestation endpoint.
async fn mount_global_tool_version(mock: &MockRegistry, version: &str, published_at: &str) {
    let tarball = make_global_tool_tarball(version);
    mock.with_package_published_at(GLOBAL_E2E_PKG, version, &tarball, published_at)
        .await;
    mock.with_batch_metadata(vec![serde_json::json!({
        "name": GLOBAL_E2E_PKG,
        "dist-tags": { "latest": version },
        "versions": {
            version: {
                "name": GLOBAL_E2E_PKG,
                "version": version,
                "dist": {
                    "tarball": format!(
                        "{}/tarballs/{GLOBAL_E2E_PKG}/-/{GLOBAL_E2E_PKG}-{version}.tgz",
                        mock.url()
                    ),
                    "integrity": compute_integrity(&tarball),
                },
                "dependencies": {}
            }
        },
        "time": { version: published_at }
    })])
    .await;
}

/// Mount the executable fixture with a postinstall script. Publication time is
/// caller-controlled so the same package can be used for both allow-policy and
/// cooldown-adjacent tests if needed.
async fn mount_global_scripted_tool_version(
    mock: &MockRegistry,
    version: &str,
    published_at: &str,
) {
    let tarball = make_global_scripted_tool_tarball(version);
    mock.with_package_published_at(GLOBAL_E2E_PKG, version, &tarball, published_at)
        .await;
    mock.with_batch_metadata(vec![serde_json::json!({
        "name": GLOBAL_E2E_PKG,
        "dist-tags": { "latest": version },
        "versions": {
            version: {
                "name": GLOBAL_E2E_PKG,
                "version": version,
                "dist": {
                    "tarball": format!(
                        "{}/tarballs/{GLOBAL_E2E_PKG}/-/{GLOBAL_E2E_PKG}-{version}.tgz",
                        mock.url()
                    ),
                    "integrity": compute_integrity(&tarball),
                },
                "dependencies": {}
            }
        },
        "time": { version: published_at }
    })])
    .await;
}

/// Tests that require actual lifecycle spawn skip if `node` is absent rather
/// than failing in stripped-down environments.
fn node_available() -> bool {
    std::process::Command::new("node")
        .arg("--version")
        .output()
        .is_ok_and(|out| out.status.success())
}

/// Seed `~/.lpm/global/trusted-dependencies.json` with an approval snapshot for
/// `GLOBAL_E2E_PKG@1.0.0`. This mirrors the project-scope provenance tests but
/// uses the machine-global trust file that `install -g` projects into the
/// synthesized manifest.
fn write_global_trust_with_approval(project: &TempProject) {
    let global_root = project.home().join(".lpm").join("global");
    std::fs::create_dir_all(&global_root).unwrap();
    let trust = serde_json::json!({
        "schema_version": 1,
        "trusted": {
            format!("{GLOBAL_E2E_PKG}@{GLOBAL_E2E_APPROVED_VERSION}"): {
                "integrity": "sha512-placeholder",
                "scriptHash": "sha256-placeholder",
                "provenanceAtApproval": {
                    "present": true,
                    "publisher": GLOBAL_E2E_PUBLISHER,
                    "workflowPath": GLOBAL_E2E_WORKFLOW_PATH,
                    "workflowRef": "refs/tags/v1.0.0"
                }
            }
        }
    });
    std::fs::write(
        global_root.join("trusted-dependencies.json"),
        format!("{}\n", serde_json::to_string_pretty(&trust).unwrap()),
    )
    .unwrap();
}

fn assert_cooldown_blocked(out: &std::process::Output) {
    assert!(
        !out.status.success(),
        "global install must fail with a cooldown block; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        combined.contains("blocked by minimumReleaseAge")
            || combined.contains("published too recently"),
        "output must name the cooldown block; got:\n{combined}"
    );
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
    assert_eq!(
        envelope["error"]["project_root"],
        serde_json::Value::Null,
        "global approval requirements must not masquerade as project-scoped; got {envelope}",
    );
    assert!(
        envelope["error"]["suggested_command"]
            .as_str()
            .is_some_and(|command| command.contains("--global")),
        "global approval envelope must suggest a --global unlock; got {envelope}",
    );
    assert!(
        envelope["next_steps"][0]["command"]
            .as_str()
            .is_some_and(|command| command.contains("--global")),
        "global approval envelope must expose a top-level --global next step; got {envelope}",
    );
}

/// Seed a global manifest + per-install build-state so
/// `approve-scripts --global --yes` has rows to act on. The
/// build-state row's `script_hash` is the real
/// `compute_script_hash`-derived value (finding D); the manifest is
/// the minimal `lpm_global::write_for` shape inlined here because no
/// shared helper exists for the manifest side.
fn seed_global_manifest_and_blocked_state(
    project: &TempProject,
    top_level: &str,
    top_level_version: &str,
    blocked_name: &str,
    blocked_version: &str,
) {
    seed_global_manifest_and_blocked_state_with_tier(
        project,
        top_level,
        top_level_version,
        blocked_name,
        blocked_version,
        Some("green"),
    );
}

/// Same as [`seed_global_manifest_and_blocked_state`] but pins an
/// explicit `static_tier` on the blocked row. Used by the M75 tier-gate
/// workflow tests below. `None` omits the field entirely (pre-
/// classification legacy state).
fn seed_global_manifest_and_blocked_state_with_tier(
    project: &TempProject,
    top_level: &str,
    top_level_version: &str,
    blocked_name: &str,
    blocked_version: &str,
    tier: Option<&str>,
) {
    let global_root = project.home().join(".lpm").join("global");
    std::fs::create_dir_all(&global_root).unwrap();
    let toml = format!(
        r#"schema_version = 1

[packages.{top_level}]
saved_spec = "^1"
resolved = "{top_level_version}"
integrity = "sha512-fixture-top-level"
source = "upstream-npm"
installed_at = "2026-04-22T00:00:00Z"
root = "installs/{top_level}@{top_level_version}"
commands = []
"#
    );
    std::fs::write(global_root.join("manifest.toml"), toml).unwrap();
    seed_global_install_blocked_state_with_tier(
        project,
        top_level,
        top_level_version,
        blocked_name,
        blocked_version,
        tier,
    );
}

/// Run the global install command surface with a flag combination
/// that previously hard-errored at the validator. The install will
/// likely fail later (no real registry, no real package), but the
/// validator's "not supported on `lpm install -g`" string must NOT
/// appear in stderr — that was the bug this test pins.
fn assert_validator_no_longer_rejects(args: &[&str]) {
    let project = TempProject::empty(r#"{ "name": "global-security-test", "version": "0.0.0" }"#);
    let out = lpm(&project)
        .args(args)
        .output()
        .expect("spawn lpm install");
    let stderr = String::from_utf8_lossy(&out.stderr);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        !stderr.contains("not supported on `lpm install -g`")
            && !stdout.contains("not supported on `lpm install -g`"),
        "validator must no longer reject {args:?} on `-g`. \
         stderr:\n{stderr}\nstdout:\n{stdout}"
    );
}

#[test]
fn install_global_validator_accepts_allow_new_flag() {
    assert_validator_no_longer_rejects(&["install", "-g", "global-security-stub", "--allow-new"]);
}

#[test]
fn install_global_validator_accepts_min_release_age_flag() {
    assert_validator_no_longer_rejects(&[
        "install",
        "-g",
        "global-security-stub",
        "--min-release-age=72h",
    ]);
}

#[test]
fn install_global_validator_accepts_ignore_provenance_drift_flag() {
    assert_validator_no_longer_rejects(&[
        "install",
        "-g",
        "global-security-stub",
        "--ignore-provenance-drift",
        "axios",
    ]);
}

#[test]
fn install_global_validator_accepts_ignore_provenance_drift_all_flag() {
    assert_validator_no_longer_rejects(&[
        "install",
        "-g",
        "global-security-stub",
        "--ignore-provenance-drift-all",
    ]);
}

#[test]
fn install_global_validator_accepts_policy_allow_flag() {
    assert_validator_no_longer_rejects(&[
        "install",
        "-g",
        "global-security-stub",
        "--policy=allow",
    ]);
}

#[test]
fn install_global_validator_accepts_triage_plus_auto_build() {
    assert_validator_no_longer_rejects(&[
        "install",
        "-g",
        "global-security-stub",
        "--triage",
        "--auto-build",
    ]);
}

#[test]
fn install_global_validator_accepts_yolo_flag() {
    assert_validator_no_longer_rejects(&["install", "-g", "global-security-stub", "--yolo"]);
}

/// `-y` is genuinely project-scoped on `-g`. The validator must
/// still reject it. Negative companion to the positive tests above.
#[test]
fn install_global_validator_still_rejects_yes_flag() {
    let project = TempProject::empty(r#"{ "name": "global-security-test", "version": "0.0.0" }"#);
    let out = lpm(&project)
        .args(["install", "-g", "global-security-stub", "-y"])
        .output()
        .expect("spawn lpm install");
    let stderr = String::from_utf8_lossy(&out.stderr);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let combined = format!("{stderr}\n{stdout}");
    assert!(
        combined.contains("project") && combined.contains("scoped"),
        "`-y` must still hard-error on `-g` (genuinely project-only). \
         stderr:\n{stderr}\nstdout:\n{stdout}"
    );
}

/// `lpm install --help` mentions the rerun caveat for global installs.
/// This hint must ship in real CLI strings, not just plan docs.
#[test]
fn install_help_mentions_global_rerun_caveat() {
    let project = TempProject::empty(r#"{ "name": "global-security-test", "version": "0.0.0" }"#);
    let out = lpm(&project)
        .args(["install", "--help"])
        .output()
        .expect("spawn lpm install --help");
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    assert!(
        combined.contains("rebuild --global"),
        "help must reference `lpm rebuild --global` as a planned \
         follow-up. output:\n{combined}"
    );
    assert!(
        combined.contains("install -g") || combined.contains("lpm install -g"),
        "help must scope the caveat to `-g` installs. output:\n{combined}"
    );
}

/// Real `install -g` block path: a 1h-old executable package must be rejected
/// when the caller raises the cooldown to 72h.
#[tokio::test]
async fn install_global_min_release_age_cli_override_blocks_fresh_package() {
    let project = TempProject::empty(r#"{ "name": "global-security-test", "version": "0.0.0" }"#);
    let mock = MockRegistry::start().await;
    mount_global_tool_version(
        &mock,
        GLOBAL_E2E_CANDIDATE_VERSION,
        &iso8601_n_secs_ago(3_600),
    )
    .await;

    let out = lpm_with_registry(&project, &mock.url())
        .args(["install", "-g", GLOBAL_E2E_PKG, "--min-release-age=72h"])
        .output()
        .expect("spawn lpm install -g with min-release-age override");

    assert_cooldown_blocked(&out);
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        combined.contains("259200"),
        "output must render the effective 72h=259200s window; got:\n{combined}"
    );
}

#[tokio::test]
async fn install_global_shows_firewall_active_badge_when_public_npm_verdicts_are_checked() {
    let project = TempProject::empty(r#"{ "name": "global-firewall-test", "version": "0.0.0" }"#);
    let mock = MockRegistry::start().await;
    mock.with_manifest_package(
        serde_json::json!({
            "name": GLOBAL_NPM_FIREWALL_PKG,
            "version": "1.0.0",
            "bin": {
                "global-firewall-tool": "bin/global-firewall-tool.js"
            }
        }),
        &[(
            "bin/global-firewall-tool.js",
            br#"#!/usr/bin/env node
console.log('global-firewall-tool');
"#,
        )],
    )
    .await;
    mock.with_npm_firewall_block(GLOBAL_NPM_FIREWALL_PKG, "1.0.0")
        .await;
    write_npm_firewall_global_config(&project, "monitor");

    let spec = format!("{GLOBAL_NPM_FIREWALL_PKG}@1.0.0");
    let out = lpm_with_registry(&project, &mock.url())
        .args(["install", "-g", &spec])
        .output()
        .expect("spawn lpm install -g with firewall monitor");

    assert!(
        out.status.success(),
        "monitor-mode firewall global install must continue\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        combined.contains("LPM Firewall active"),
        "firewall-active global install must show the badge; got:\n{combined}"
    );
    let store_root = project.home().join(".lpm/store");
    assert!(
        store_root.join("v2/links").is_dir(),
        "successful global installs must use the default v2 virtual store"
    );
    assert!(
        !store_root.join("v3").exists(),
        "default global installs must not activate the experimental v3 store"
    );
}

#[tokio::test]
async fn install_global_no_engine_strict_accepts_incompatible_dependency_with_warning_policy() {
    const PACKAGE: &str = "@lpm.dev/acme.global-engine-tool";

    let project = TempProject::empty(r#"{ "name": "global-engine-test", "version": "0.0.0" }"#);
    let mock = MockRegistry::start().await;
    mock.with_manifest_package(
        serde_json::json!({
            "name": PACKAGE,
            "version": "1.0.0",
            "engines": { "node": ">=999.0.0" },
            "bin": { "global-engine-tool": "bin/global-engine-tool.js" }
        }),
        &[(
            "bin/global-engine-tool.js",
            br#"#!/usr/bin/env node
console.log('global-engine-tool');
"#,
        )],
    )
    .await;

    let mut command = lpm_with_registry(&project, &mock.url());
    configure_fake_node(&mut command, &project, "20.0.0");
    let output = command
        .args(["install", "-g", PACKAGE, "--no-engine-strict"])
        .output()
        .expect("run warning-only global dependency-engine install");

    assert!(
        output.status.success(),
        "--no-engine-strict must reach the synthesized global install\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

/// `install -g --allow-new` is a guarded global cooldown bypass. The
/// workflow tier asserts the non-interactive JSON approval boundary.
#[tokio::test]
async fn install_global_allow_new_requires_security_approval() {
    let project = TempProject::empty(r#"{ "name": "global-security-test", "version": "0.0.0" }"#);
    let mock = MockRegistry::start().await;
    mount_global_tool_version(
        &mock,
        GLOBAL_E2E_CANDIDATE_VERSION,
        &iso8601_n_secs_ago(3_600),
    )
    .await;

    let out = lpm_with_registry(&project, &mock.url())
        .args([
            "--json",
            "install",
            "-g",
            GLOBAL_E2E_PKG,
            "--allow-new",
            "--min-release-age=72h",
        ])
        .output()
        .expect("spawn lpm install -g with allow-new");

    assert_security_approval_scope(&out, "cooldown-bypass");
}

/// A hand-edited global trust file is guarded before `install -g` can
/// use it as a provenance reference.
#[tokio::test]
async fn install_global_direct_trust_requires_security_approval_before_drift_gate() {
    let project = TempProject::empty(r#"{ "name": "global-security-test", "version": "0.0.0" }"#);
    write_global_trust_with_approval(&project);
    let mock = MockRegistry::start().await;
    mount_global_tool_version(
        &mock,
        GLOBAL_E2E_CANDIDATE_VERSION,
        &iso8601_n_secs_ago(172_800),
    )
    .await;

    let out = lpm_with_registry(&project, &mock.url())
        .args(["--json", "install", "-g", GLOBAL_E2E_PKG])
        .output()
        .expect("spawn lpm install -g with approved provenance reference");

    assert_security_approval_scope(&out, "trust-bulk-approve");
}

/// `install -g --ignore-provenance-drift <pkg>` is a guarded global
/// provenance bypass.
#[tokio::test]
async fn install_global_ignore_provenance_drift_per_package_requires_security_approval() {
    let project = TempProject::empty(r#"{ "name": "global-security-test", "version": "0.0.0" }"#);
    let mock = MockRegistry::start().await;
    mount_global_tool_version(
        &mock,
        GLOBAL_E2E_CANDIDATE_VERSION,
        &iso8601_n_secs_ago(172_800),
    )
    .await;

    let out = lpm_with_registry(&project, &mock.url())
        .args([
            "--json",
            "install",
            "-g",
            GLOBAL_E2E_PKG,
            "--ignore-provenance-drift",
            GLOBAL_E2E_PKG,
        ])
        .output()
        .expect("spawn lpm install -g with provenance-drift waiver");

    assert_security_approval_scope(&out, "provenance-ignore-drift");
}

/// `install -g --ignore-provenance-drift-all` is guarded separately
/// from the per-package form.
#[tokio::test]
async fn install_global_ignore_provenance_drift_all_requires_security_approval() {
    let project = TempProject::empty(r#"{ "name": "global-security-test", "version": "0.0.0" }"#);
    let mock = MockRegistry::start().await;
    mount_global_tool_version(
        &mock,
        GLOBAL_E2E_CANDIDATE_VERSION,
        &iso8601_n_secs_ago(172_800),
    )
    .await;

    let out = lpm_with_registry(&project, &mock.url())
        .args([
            "--json",
            "install",
            "-g",
            GLOBAL_E2E_PKG,
            "--ignore-provenance-drift-all",
        ])
        .output()
        .expect("spawn lpm install -g with blanket provenance waiver");

    assert_security_approval_scope(&out, "provenance-ignore-drift");
}

/// `install -g --policy=allow` is a guarded global script execution
/// request. Without approval, JSON mode must stop deterministically.
#[tokio::test]
async fn install_global_policy_allow_requires_security_approval() {
    if !node_available() {
        eprintln!(
            "skipping install_global_policy_allow_requires_security_approval: node not available"
        );
        return;
    }

    let project = TempProject::empty(r#"{ "name": "global-security-test", "version": "0.0.0" }"#);
    let mock = MockRegistry::start().await;
    mount_global_scripted_tool_version(
        &mock,
        GLOBAL_E2E_CANDIDATE_VERSION,
        &iso8601_n_secs_ago(172_800),
    )
    .await;

    let out = lpm_with_registry(&project, &mock.url())
        .args(["--json", "install", "-g", GLOBAL_E2E_PKG, "--policy=allow"])
        .output()
        .expect("spawn lpm install -g with --policy=allow");

    assert_security_approval_scope(&out, "scripts-allow");
}

/// `approve-scripts --global --yes --dry-run --json` must NOT emit a
/// `next_step` follow-up plan. Under `--dry-run` no trust mutation
/// happened, so directing automation to reinstall globals would point
/// it at an action that cannot succeed yet — the trust store is
/// unchanged. Pinned to prevent regressing back to the unconditional
/// emit that the round-3 audit flagged.
#[test]
fn approve_scripts_global_yes_dry_run_json_omits_next_step() {
    let project = TempProject::empty(r#"{ "name": "global-security-test", "version": "0.0.0" }"#);
    seed_global_manifest_and_blocked_state(&project, "eslint", "9.24.0", "esbuild", "0.25.1");

    let out = lpm(&project)
        .args([
            "--json",
            "approve-scripts",
            "--global",
            "--yes",
            "--dry-run",
        ])
        .output()
        .expect("spawn lpm approve-scripts --global --yes --dry-run");
    assert!(
        out.status.success(),
        "approve-scripts --global --yes --dry-run --json must exit 0; \
         stderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let parsed: serde_json::Value =
        serde_json::from_str(String::from_utf8_lossy(&out.stdout).trim())
            .expect("valid JSON envelope on stdout");
    assert_eq!(parsed.get("dry_run").and_then(|v| v.as_bool()), Some(true));
    assert!(
        parsed.get("next_step").is_none(),
        "dry-run envelope must NOT carry next_step (no mutation occurred); \
         envelope={parsed}"
    );
}

/// `approve-scripts --global --yes --json` is a live global trust
/// mutation. Without native approval it should return the global unlock
/// remediation rather than writing trust state.
#[test]
fn approve_scripts_global_yes_live_json_requires_security_approval() {
    let project = TempProject::empty(r#"{ "name": "global-security-test", "version": "0.0.0" }"#);
    seed_global_manifest_and_blocked_state(&project, "eslint", "9.24.0", "esbuild", "0.25.1");

    let out = lpm(&project)
        .args(["--json", "approve-scripts", "--global", "--yes"])
        .output()
        .expect("spawn lpm approve-scripts --global --yes");
    assert_security_approval_scope(&out, "trust-bulk-approve");
}

// ── M75: tier gate parity for global bulk approval ──────────────────
//
// Pre-fix, `lpm approve-scripts --global --yes` wrote aggregate rows
// straight into `~/.lpm/global/trusted-dependencies.json` without the
// non-green tier check the project `--yes` gate enforces. A malicious
// global dependency with an amber / amber-llm / red lifecycle script
// could be globally approved through the bulk path even though the
// project `--yes` path would refuse the same classification.

/// `--global --yes` MUST refuse to bulk-approve any aggregate row
/// classified outside the green tier. Pinned with `amber`, matching
/// the project `yes_gate_refuses_single_amber` unit-test contract.
#[test]
fn approve_scripts_global_yes_refuses_amber_tier() {
    let project = TempProject::empty(r#"{ "name": "global-security-test", "version": "0.0.0" }"#);
    seed_global_manifest_and_blocked_state_with_tier(
        &project,
        "eslint",
        "9.24.0",
        "esbuild",
        "0.25.1",
        Some("amber"),
    );

    let out = lpm(&project)
        .args(["--json", "approve-scripts", "--global", "--yes"])
        .output()
        .expect("spawn lpm approve-scripts --global --yes");
    assert!(
        !out.status.success(),
        "approve-scripts --global --yes must exit non-zero when an aggregate row is amber; \
         stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    // The refusal message threads through main.rs's JSON error wrapper.
    // Substring-match on the stable `--yes refuses` prefix + the
    // refused package + the global redirect prose.
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        combined.contains("--yes refuses"),
        "refusal must carry the stable `--yes refuses` prefix; got:\n{combined}"
    );
    assert!(
        combined.contains("esbuild@0.25.1"),
        "refusal must name the offending package; got:\n{combined}"
    );
    assert!(
        combined.contains("approve-scripts --global"),
        "global redirect must mention --global; got:\n{combined}"
    );
    // Trust file must be UNTOUCHED on refusal — no aggregate row should
    // have made it into ~/.lpm/global/trusted-dependencies.json.
    let trust_path = project
        .home()
        .join(".lpm")
        .join("global")
        .join("trusted-dependencies.json");
    assert!(
        !trust_path.exists(),
        "trust file must not be written when --yes is refused; found {}",
        trust_path.display()
    );
}

/// `--global --yes` with all-green rows is still a live trust write and
/// therefore requires global approval.
#[test]
fn approve_scripts_global_yes_green_tier_requires_security_approval() {
    let project = TempProject::empty(r#"{ "name": "global-security-test", "version": "0.0.0" }"#);
    seed_global_manifest_and_blocked_state_with_tier(
        &project,
        "eslint",
        "9.24.0",
        "esbuild",
        "0.25.1",
        Some("green"),
    );

    let out = lpm(&project)
        .args(["--json", "approve-scripts", "--global", "--yes"])
        .output()
        .expect("spawn lpm approve-scripts --global --yes");
    assert_security_approval_scope(&out, "trust-bulk-approve");
    let trust_path = project
        .home()
        .join(".lpm")
        .join("global")
        .join("trusted-dependencies.json");
    assert!(
        !trust_path.exists(),
        "trust file must not be written without approval; found {}",
        trust_path.display()
    );
}

// ── M76: uninstall trust-prune workflow tests ───────────────────────
//
// Pre-fix, `~/.lpm/global/trusted-dependencies.json` survived uninstall
// and `synthesize_pkg_json` re-projected every entry into every new
// global install. An approval originally made for one top-level global
// remained after that global was removed and could authorize the same
// transitive name@version in an unrelated future global install.
//
// The fix is reachability-aware: prune trust entries reachable only
// through the uninstalling install's tree (computed from per-install
// lockfiles). Workflow tests drive the live binary against seeded
// fixtures (manifest + install roots + lockfiles + trust file).

/// Write a `~/.lpm/global/manifest.toml` claiming `pkga@1.0.0` and a
/// corresponding install root with a minimal but lockfile-parseable
/// `lpm.lock` containing `(name, version)` pairs the M76 helper will
/// see when walking the reachability tree.
fn seed_global_install_with_lockfile(
    project: &TempProject,
    top_level: &str,
    top_level_version: &str,
    deps: &[(&str, &str)],
) {
    let global_root = project.home().join(".lpm").join("global");
    let install_root = global_root
        .join("installs")
        .join(format!("{top_level}@{top_level_version}"));
    std::fs::create_dir_all(install_root.join("node_modules").join(".bin")).unwrap();
    let mut body = String::from("[metadata]\nlockfile-version = 2\n");
    for (name, version) in deps {
        body.push_str(&format!(
            "\n[[packages]]\nname = \"{name}\"\nversion = \"{version}\"\n"
        ));
    }
    std::fs::write(install_root.join("lpm.lock"), body).unwrap();
}

/// Append a `[packages.<top_level>]` row to the existing global
/// manifest (or create the manifest if absent). Caller seeds the
/// install root separately via `seed_global_install_with_lockfile`.
fn append_global_manifest_row(project: &TempProject, top_level: &str, top_level_version: &str) {
    let global_root = project.home().join(".lpm").join("global");
    std::fs::create_dir_all(&global_root).unwrap();
    let manifest_path = global_root.join("manifest.toml");
    let prior = std::fs::read_to_string(&manifest_path).unwrap_or_default();
    let body = if prior.is_empty() {
        format!(
            r#"schema_version = 1

[packages.{top_level}]
saved_spec = "^1"
resolved = "{top_level_version}"
integrity = "sha512-fixture-{top_level}"
source = "upstream-npm"
installed_at = "2026-04-22T00:00:00Z"
root = "installs/{top_level}@{top_level_version}"
commands = []
"#
        )
    } else {
        format!(
            "{prior}\n[packages.{top_level}]\nsaved_spec = \"^1\"\nresolved = \"{top_level_version}\"\nintegrity = \"sha512-fixture-{top_level}\"\nsource = \"upstream-npm\"\ninstalled_at = \"2026-04-22T00:00:00Z\"\nroot = \"installs/{top_level}@{top_level_version}\"\ncommands = []\n"
        )
    };
    std::fs::write(manifest_path, body).unwrap();
}

/// Seed `~/.lpm/global/trusted-dependencies.json` with the given
/// `(name, version)` entries (no provenance / integrity / scriptHash —
/// the trust-prune logic is keyed by `name@version` regardless).
fn seed_global_trust(project: &TempProject, entries: &[(&str, &str)]) {
    let global_root = project.home().join(".lpm").join("global");
    std::fs::create_dir_all(&global_root).unwrap();
    let mut map = serde_json::Map::new();
    for (name, version) in entries {
        map.insert(format!("{name}@{version}"), serde_json::json!({}));
    }
    let body = serde_json::json!({
        "schema_version": 1,
        "trusted": serde_json::Value::Object(map),
    });
    std::fs::write(
        global_root.join("trusted-dependencies.json"),
        serde_json::to_string_pretty(&body).unwrap(),
    )
    .unwrap();
}

/// Read the global trust file and return the set of keys present.
fn read_global_trust_keys(project: &TempProject) -> Vec<String> {
    let path = project
        .home()
        .join(".lpm")
        .join("global")
        .join("trusted-dependencies.json");
    let body = std::fs::read_to_string(&path).unwrap_or_default();
    if body.is_empty() {
        return Vec::new();
    }
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    v.get("trusted")
        .and_then(|t| t.as_object())
        .map(|m| m.keys().cloned().collect())
        .unwrap_or_default()
}

/// Uninstalling the only global drops every trust entry reachable
/// through its tree.
#[test]
fn uninstall_prunes_trust_entries_unique_to_this_install() {
    let project = TempProject::empty(r#"{ "name": "global-security-test", "version": "0.0.0" }"#);
    append_global_manifest_row(&project, "pkga", "1.0.0");
    seed_global_install_with_lockfile(&project, "pkga", "1.0.0", &[("lodash", "4.17.21")]);
    seed_global_trust(&project, &[("lodash", "4.17.21")]);

    let out = lpm(&project)
        .args(["--json", "uninstall", "-g", "pkga"])
        .output()
        .expect("spawn lpm uninstall -g");
    assert!(
        out.status.success(),
        "uninstall must succeed; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    let parsed: serde_json::Value =
        serde_json::from_str(String::from_utf8_lossy(&out.stdout).trim())
            .expect("valid JSON envelope on stdout");
    // pkga@1.0.0 (top-level) + lodash@4.17.21 = 2 in prune set, but
    // only lodash@4.17.21 was in the trust file, so the count of
    // entries actually removed is 1.
    assert_eq!(
        parsed.get("trust_entries_pruned").and_then(|v| v.as_u64()),
        Some(1),
        "envelope must report `trust_entries_pruned` count; got {parsed}"
    );
    let keys = read_global_trust_keys(&project);
    assert!(
        !keys.iter().any(|k| k == "lodash@4.17.21"),
        "lodash trust entry must be pruned; remaining keys: {keys:?}"
    );
}

/// A trust entry reachable through ANOTHER remaining global install's
/// tree must survive — the sibling install's reinstall still needs it.
#[test]
fn uninstall_keeps_trust_entries_reachable_through_other_installs() {
    let project = TempProject::empty(r#"{ "name": "global-security-test", "version": "0.0.0" }"#);
    append_global_manifest_row(&project, "pkga", "1.0.0");
    append_global_manifest_row(&project, "pkgb", "1.0.0");
    seed_global_install_with_lockfile(&project, "pkga", "1.0.0", &[("lodash", "4.17.21")]);
    seed_global_install_with_lockfile(&project, "pkgb", "1.0.0", &[("lodash", "4.17.21")]);
    seed_global_trust(&project, &[("lodash", "4.17.21")]);

    let out = lpm(&project)
        .args(["--json", "uninstall", "-g", "pkga"])
        .output()
        .expect("spawn lpm uninstall -g");
    assert!(
        out.status.success(),
        "uninstall must succeed; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    let parsed: serde_json::Value =
        serde_json::from_str(String::from_utf8_lossy(&out.stdout).trim())
            .expect("valid JSON envelope on stdout");
    // lodash is reachable via pkgb — not prunable. pkga@1.0.0
    // (top-level) is unique to this install but it ISN'T in the trust
    // file, so `trust_entries_pruned` is 0.
    assert_eq!(
        parsed.get("trust_entries_pruned").and_then(|v| v.as_u64()),
        Some(0),
        "lodash reachable via pkgb must survive; got {parsed}"
    );
    let keys = read_global_trust_keys(&project);
    assert!(
        keys.iter().any(|k| k == "lodash@4.17.21"),
        "lodash trust entry must SURVIVE; remaining keys: {keys:?}"
    );
}

/// If a sibling install's lockfile is missing / unreadable, the
/// prune set collapses to empty (conservative fail-safe). Uninstall
/// still succeeds; the trust file is untouched.
#[test]
fn uninstall_fail_safe_when_other_install_lockfile_missing() {
    let project = TempProject::empty(r#"{ "name": "global-security-test", "version": "0.0.0" }"#);
    append_global_manifest_row(&project, "pkga", "1.0.0");
    append_global_manifest_row(&project, "pkgb", "1.0.0");
    seed_global_install_with_lockfile(&project, "pkga", "1.0.0", &[("lodash", "4.17.21")]);
    // Seed pkgb's install root WITHOUT a lockfile — the fail-safe path.
    let pkgb_install_root = project
        .home()
        .join(".lpm")
        .join("global")
        .join("installs")
        .join("pkgb@1.0.0");
    std::fs::create_dir_all(pkgb_install_root.join("node_modules").join(".bin")).unwrap();
    seed_global_trust(&project, &[("lodash", "4.17.21")]);

    let out = lpm(&project)
        .args(["--json", "uninstall", "-g", "pkga"])
        .output()
        .expect("spawn lpm uninstall -g");
    assert!(
        out.status.success(),
        "uninstall must succeed even when sibling lockfile is unreadable; \
         stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    let parsed: serde_json::Value =
        serde_json::from_str(String::from_utf8_lossy(&out.stdout).trim())
            .expect("valid JSON envelope on stdout");
    assert_eq!(
        parsed.get("trust_entries_pruned").and_then(|v| v.as_u64()),
        Some(0),
        "fail-safe must result in zero entries pruned; got {parsed}"
    );
    let keys = read_global_trust_keys(&project);
    assert!(
        keys.iter().any(|k| k == "lodash@4.17.21"),
        "lodash trust entry must survive the fail-safe; remaining keys: {keys:?}"
    );
}

/// Pre-classification legacy state still attempts a live global trust
/// write, so workflow coverage stops at the approval boundary.
#[test]
fn approve_scripts_global_yes_none_tier_legacy_state_requires_security_approval() {
    let project = TempProject::empty(r#"{ "name": "global-security-test", "version": "0.0.0" }"#);
    seed_global_manifest_and_blocked_state_with_tier(
        &project, "eslint", "9.24.0", "esbuild", "0.25.1",
        None, // omit static_tier — legacy / pre-P2 state
    );

    let out = lpm(&project)
        .args(["--json", "approve-scripts", "--global", "--yes"])
        .output()
        .expect("spawn lpm approve-scripts --global --yes");
    assert_security_approval_scope(&out, "trust-bulk-approve");
}
