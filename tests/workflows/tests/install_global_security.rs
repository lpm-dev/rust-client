//! Workflow tests for Phase 68 — `lpm install -g` security parity.
//!
//! Pins the user-facing CLI contracts that landed in Phase 68:
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

use support::build_state::seed_global_install_blocked_state_with_real_hash;
use support::mock_registry::{MockRegistry, compute_integrity, make_tarball_from_pkg_json};
use support::{TempProject, lpm, lpm_with_registry};

const GLOBAL_E2E_PKG: &str = "@lpm.dev/acme.global-tool";
const GLOBAL_E2E_COMMAND: &str = "acme-global-tool";
const GLOBAL_E2E_APPROVED_VERSION: &str = "1.0.0";
const GLOBAL_E2E_CANDIDATE_VERSION: &str = "1.0.1";
const GLOBAL_E2E_PUBLISHER: &str = "github:acme/global-tool";
const GLOBAL_E2E_WORKFLOW_PATH: &str = ".github/workflows/publish.yml";

/// ISO-8601 UTC timestamp `n_secs` ago. Mirrors the release-age helper in
/// `install.rs`; kept local so the Phase 68 workflow test is standalone.
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

/// Mount metadata + tarball for the Phase 68 executable fixture with a caller-
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

/// The allow-policy test proves real lifecycle execution by checking for this
/// marker in the v1 store entry. Workflow tests pin `LPM_STORE_VERSION=v1` in
/// `support::lpm()`, so this path is deterministic.
fn global_store_pkg_dir(project: &TempProject, version: &str) -> std::path::PathBuf {
    let safe = GLOBAL_E2E_PKG.replace(['/', '\\'], "+");
    project
        .store_dir()
        .join("v1")
        .join(format!("{safe}@{version}"))
}

/// Tests that require actual lifecycle spawn skip if `node` is absent rather
/// than failing in stripped-down environments.
fn node_available() -> bool {
    std::process::Command::new("node")
        .arg("--version")
        .output()
        .map(|out| out.status.success())
        .unwrap_or(false)
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

fn assert_cooldown_not_blocked(out: &std::process::Output) {
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !combined.contains("blocked by minimumReleaseAge")
            && !combined.contains("published too recently"),
        "cooldown must not fire but the block message appeared; got:\n{combined}"
    );
}

fn drift_block_message_present(out: &std::process::Output) -> bool {
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    combined.contains("blocked by provenance drift")
        || combined.contains("package(s) blocked by provenance drift")
}

fn assert_drift_blocked(out: &std::process::Output) {
    assert!(
        !out.status.success(),
        "global install must fail with a drift block; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        drift_block_message_present(out),
        "output must name the drift block; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

fn assert_global_install_json_success(
    project: &TempProject,
    out: &std::process::Output,
    expected_version: &str,
) {
    assert!(
        out.status.success(),
        "global install must exit 0; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let parsed: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
        panic!(
            "stdout must be valid JSON: {e}\nstdout:\n{}",
            String::from_utf8_lossy(&out.stdout)
        )
    });
    assert_eq!(parsed["success"], serde_json::json!(true));
    assert_eq!(parsed["package"], serde_json::json!(GLOBAL_E2E_PKG));
    assert_eq!(parsed["version"], serde_json::json!(expected_version));
    let commands = parsed["commands"]
        .as_array()
        .expect("commands must be an array in the global install JSON envelope");
    assert!(
        commands
            .iter()
            .any(|value| value.as_str() == Some(GLOBAL_E2E_COMMAND)),
        "commands must include the discovered bin `{GLOBAL_E2E_COMMAND}`; envelope={parsed}"
    );
    assert!(
        project
            .home()
            .join(".lpm")
            .join("global")
            .join("manifest.toml")
            .exists(),
        "successful global install must write ~/.lpm/global/manifest.toml"
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
    seed_global_install_blocked_state_with_real_hash(
        project,
        top_level,
        top_level_version,
        blocked_name,
        blocked_version,
    );
}

/// Run the global install command surface with a flag combination
/// that previously hard-errored at the validator. The install will
/// likely fail later (no real registry, no real package), but the
/// validator's "not supported on `lpm install -g`" string must NOT
/// appear in stderr — that's the bug Phase 68 fixed.
fn assert_validator_no_longer_rejects(args: &[&str]) {
    let project = TempProject::empty(r#"{ "name": "phase68", "version": "0.0.0" }"#);
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
    assert_validator_no_longer_rejects(&["install", "-g", "phase68-stub", "--allow-new"]);
}

#[test]
fn install_global_validator_accepts_min_release_age_flag() {
    assert_validator_no_longer_rejects(&["install", "-g", "phase68-stub", "--min-release-age=72h"]);
}

#[test]
fn install_global_validator_accepts_ignore_provenance_drift_flag() {
    assert_validator_no_longer_rejects(&[
        "install",
        "-g",
        "phase68-stub",
        "--ignore-provenance-drift",
        "axios",
    ]);
}

#[test]
fn install_global_validator_accepts_ignore_provenance_drift_all_flag() {
    assert_validator_no_longer_rejects(&[
        "install",
        "-g",
        "phase68-stub",
        "--ignore-provenance-drift-all",
    ]);
}

#[test]
fn install_global_validator_accepts_policy_allow_flag() {
    assert_validator_no_longer_rejects(&["install", "-g", "phase68-stub", "--policy=allow"]);
}

#[test]
fn install_global_validator_accepts_triage_plus_auto_build() {
    assert_validator_no_longer_rejects(&[
        "install",
        "-g",
        "phase68-stub",
        "--triage",
        "--auto-build",
    ]);
}

#[test]
fn install_global_validator_accepts_yolo_flag() {
    assert_validator_no_longer_rejects(&["install", "-g", "phase68-stub", "--yolo"]);
}

/// `-y` is genuinely project-scoped on `-g`. The validator must
/// still reject it. Negative companion to the positive tests above.
#[test]
fn install_global_validator_still_rejects_yes_flag() {
    let project = TempProject::empty(r#"{ "name": "phase68", "version": "0.0.0" }"#);
    let out = lpm(&project)
        .args(["install", "-g", "phase68-stub", "-y"])
        .output()
        .expect("spawn lpm install");
    let stderr = String::from_utf8_lossy(&out.stderr);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stderr.contains("project-scoped") || stdout.contains("project-scoped"),
        "`-y` must still hard-error on `-g` (genuinely project-only). \
         stderr:\n{stderr}\nstdout:\n{stdout}"
    );
}

/// `lpm install --help` mentions the rerun caveat for global installs.
/// Pinned by the round-2 audit's open question — this hint must ship
/// in real CLI strings, not just plan docs.
#[test]
fn install_help_mentions_global_rerun_caveat() {
    let project = TempProject::empty(r#"{ "name": "phase68", "version": "0.0.0" }"#);
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
    let project = TempProject::empty(r#"{ "name": "phase68", "version": "0.0.0" }"#);
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

/// Real `install -g` success path: `--allow-new` must bypass the cooldown and
/// let the executable package fully commit into `~/.lpm/global`.
#[tokio::test]
async fn install_global_allow_new_bypasses_min_release_age_end_to_end() {
    let project = TempProject::empty(r#"{ "name": "phase68", "version": "0.0.0" }"#);
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

    assert_cooldown_not_blocked(&out);
    assert_global_install_json_success(&project, &out, GLOBAL_E2E_CANDIDATE_VERSION);
}

/// Real `install -g` drift block: the global trust file records an approved
/// provenance snapshot for v1.0.0, while the candidate v1.0.1 has no
/// attestation field at all. The install must stop on the "provenance dropped"
/// path just like the project-scope workflow does.
#[tokio::test]
async fn install_global_drift_blocks_when_approved_attestation_dropped() {
    let project = TempProject::empty(r#"{ "name": "phase68", "version": "0.0.0" }"#);
    write_global_trust_with_approval(&project);
    let mock = MockRegistry::start().await;
    mount_global_tool_version(
        &mock,
        GLOBAL_E2E_CANDIDATE_VERSION,
        &iso8601_n_secs_ago(172_800),
    )
    .await;

    let out = lpm_with_registry(&project, &mock.url())
        .args(["install", "-g", GLOBAL_E2E_PKG])
        .output()
        .expect("spawn lpm install -g with approved provenance reference");

    assert_drift_blocked(&out);
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        combined.contains("provenance dropped"),
        "block message must name the 'provenance dropped' verdict; got:\n{combined}"
    );
}

/// Real `install -g` drift-waive path: the same approved-present ->
/// candidate-absent scenario must succeed when the package is explicitly
/// listed in `--ignore-provenance-drift`.
#[tokio::test]
async fn install_global_ignore_provenance_drift_per_package_unblocks() {
    let project = TempProject::empty(r#"{ "name": "phase68", "version": "0.0.0" }"#);
    write_global_trust_with_approval(&project);
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

    assert!(
        !drift_block_message_present(&out),
        "drift block message must not appear once the package is waived; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert_global_install_json_success(&project, &out, GLOBAL_E2E_CANDIDATE_VERSION);
}

/// Blanket waiver end-to-end: `--ignore-provenance-drift-all` must bypass the
/// same approved-present -> candidate-absent block and surface the explicit
/// blanket-waive advisory.
#[tokio::test]
async fn install_global_ignore_provenance_drift_all_unblocks() {
    let project = TempProject::empty(r#"{ "name": "phase68", "version": "0.0.0" }"#);
    write_global_trust_with_approval(&project);
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

    assert!(
        !drift_block_message_present(&out),
        "drift block message must not appear once all drift checks are waived; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        combined.contains("waived for this install by --ignore-provenance-drift-all"),
        "blanket-waive advisory must be visible to the user; got:\n{combined}"
    );
    assert_global_install_json_success(&project, &out, GLOBAL_E2E_CANDIDATE_VERSION);
}

/// Real policy/auto-build path: `install -g --policy=allow` must not just wire
/// the flag through `run_with_options` — it must actually execute the package's
/// lifecycle-script pipeline during install. The rebuild layer's canonical
/// success proof is the `.lpm-built` marker under the store entry.
#[tokio::test]
async fn install_global_policy_allow_runs_postinstall_end_to_end() {
    if !node_available() {
        eprintln!(
            "skipping install_global_policy_allow_runs_postinstall_end_to_end: node not available"
        );
        return;
    }

    let project = TempProject::empty(r#"{ "name": "phase68", "version": "0.0.0" }"#);
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

    assert_global_install_json_success(&project, &out, GLOBAL_E2E_CANDIDATE_VERSION);

    let store_dir = global_store_pkg_dir(&project, GLOBAL_E2E_CANDIDATE_VERSION);
    assert!(
        store_dir.join(".lpm-built").exists(),
        "allow-policy install must mark the package as built under the global store entry, proving the auto-build pipeline ran successfully"
    );
}

/// `approve-scripts --global --yes --dry-run --json` must NOT emit a
/// `next_step` follow-up plan. Under `--dry-run` no trust mutation
/// happened, so directing automation to reinstall globals would point
/// it at an action that cannot succeed yet — the trust store is
/// unchanged. Pinned to prevent regressing back to the unconditional
/// emit that the round-3 audit flagged.
#[test]
fn approve_scripts_global_yes_dry_run_json_omits_next_step() {
    let project = TempProject::empty(r#"{ "name": "phase68", "version": "0.0.0" }"#);
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

/// `approve-scripts --global --yes --json` (live, no `--dry-run`)
/// carries the structured `next_step.origins` field. Pinned by
/// round-3 finding (h): banners must enumerate the top-level
/// globally-installed origins, not the approved row's own name.
#[test]
fn approve_scripts_global_yes_live_json_carries_next_step_origins() {
    let project = TempProject::empty(r#"{ "name": "phase68", "version": "0.0.0" }"#);
    seed_global_manifest_and_blocked_state(&project, "eslint", "9.24.0", "esbuild", "0.25.1");

    let out = lpm(&project)
        .args(["--json", "approve-scripts", "--global", "--yes"])
        .output()
        .expect("spawn lpm approve-scripts --global --yes");
    assert!(
        out.status.success(),
        "approve-scripts --global --yes --json must exit 0; \
         stderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let parsed: serde_json::Value =
        serde_json::from_str(String::from_utf8_lossy(&out.stdout).trim())
            .expect("valid JSON envelope on stdout");
    assert_eq!(parsed.get("dry_run").and_then(|v| v.as_bool()), Some(false));

    let next_step = parsed
        .get("next_step")
        .expect("live envelope must carry `next_step` (Phase 68)");
    assert_eq!(
        next_step.get("kind").and_then(|v| v.as_str()),
        Some("reinstall_globals"),
        "next_step.kind must be `reinstall_globals`",
    );
    let origins = next_step
        .get("origins")
        .and_then(|v| v.as_array())
        .expect("next_step.origins must be an array");
    let names: Vec<&str> = origins.iter().filter_map(|v| v.as_str()).collect();
    // The top-level global is `eslint` (NOT the blocked transitive
    // `esbuild`). Phase 68 §banner contract: enumerate origins, not
    // row names.
    assert!(
        names.contains(&"eslint"),
        "origins must include the top-level global `eslint`. names={names:?}"
    );
    assert!(
        !names.contains(&"esbuild"),
        "origins must NOT include the approved row's name (`esbuild`) — \
         it's a transitive blocked package, not a top-level global. names={names:?}"
    );
}
