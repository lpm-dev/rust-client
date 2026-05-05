//! Workflow tests for `lpm audit`.
//!
//! Covers the security-critical command's main paths: discovery, OSV
//! vulnerability scan, fail-on policy gating, and JSON envelope shape.
//! All OSV interactions go through `MockRegistry::with_osv_querybatch`
//! via the `LPM_OSV_URL` env hook so tests never reach `api.osv.dev`.

mod support;

use support::mock_registry::{MockRegistry, make_tarball};
use support::{TempProject, lpm_with_registry};

/// Run `lpm audit` against `project`, with OSV calls redirected at
/// `mock`'s `/v1/querybatch` endpoint. Returns the full Output so the
/// caller can assert exit code, stdout, and stderr.
fn run_audit(
    project: &TempProject,
    mock: &MockRegistry,
    extra_args: &[&str],
) -> std::process::Output {
    let osv_url = format!("{}/v1/querybatch", mock.url());
    let mut cmd = lpm_with_registry(project, &mock.url());
    cmd.env("LPM_OSV_URL", &osv_url);
    cmd.arg("audit");
    for arg in extra_args {
        cmd.arg(arg);
    }
    cmd.output().expect("failed to spawn lpm audit")
}

/// Mount `pkg@1.0.0` on the mock registry and install it into `project`.
/// Returns the original tarball bytes (callers don't need them yet but
/// the future-OSV-helper-per-package shape may).
async fn install_one(project: &TempProject, mock: &MockRegistry, pkg: &str) {
    let tarball = make_tarball(pkg, "1.0.0");
    mock.with_package(pkg, "1.0.0", &tarball).await;
    mock.with_batch_metadata(vec![serde_json::json!({
        "name": pkg,
        "dist-tags": { "latest": "1.0.0" },
        "versions": {
            "1.0.0": {
                "name": pkg,
                "version": "1.0.0",
                "dist": {
                    "tarball": format!("{}/tarballs/{pkg}-1.0.0.tgz", mock.url()),
                    "integrity": support::mock_registry::compute_integrity(&tarball),
                },
                "dependencies": {}
            }
        },
        "time": { "1.0.0": "2025-01-01T00:00:00.000Z" }
    })])
    .await;

    lpm_with_registry(project, &mock.url())
        .args([
            "install",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .assert()
        .success();
}

// ─── Discovery + happy paths ────────────────────────────────────────────

/// An lpm.lock with zero packages is a legitimate "I've installed and
/// have no deps" state. Audit must exit cleanly with a "no packages"
/// signal rather than crash on the empty-set edge.
#[tokio::test]
async fn audit_empty_lockfile_reports_no_packages_and_exits_zero() {
    let project = TempProject::empty(r#"{"name":"empty-audit","version":"1.0.0"}"#);
    project.write_file(
        "lpm.lock",
        "[metadata]\nlockfile-version = 1\nresolved-with = \"greedy-fusion\"\n",
    );

    let mock = MockRegistry::start().await;
    mock.with_osv_querybatch(vec![]).await;

    let out = run_audit(&project, &mock, &[]);
    assert!(
        out.status.success(),
        "audit on a zero-package lockfile must exit 0; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        combined.to_lowercase().contains("no packages"),
        "expected 'no packages' wording on the empty-lockfile path; got:\n{combined}"
    );
}

/// A project with one clean dep and an OSV response carrying zero vulns
/// must exit 0 — nothing to fail on.
#[tokio::test]
async fn audit_clean_dep_with_empty_osv_response_exits_zero() {
    let project = TempProject::empty(
        r#"{"name":"clean-audit","version":"1.0.0","dependencies":{"clean-pkg":"^1.0.0"}}"#,
    );
    let mock = MockRegistry::start().await;
    install_one(&project, &mock, "clean-pkg").await;

    // OSV returns an empty `vulns` array for the single query slot — no
    // findings, no failure.
    mock.with_osv_querybatch(vec![vec![]]).await;

    let out = run_audit(&project, &mock, &[]);
    assert!(
        out.status.success(),
        "audit on a clean project with no OSV hits must exit 0; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
}

// ─── Fail-on policies ───────────────────────────────────────────────────

/// Default policy (`--fail-on=all` implicit) treats any OSV vulnerability
/// as an exit-1 trigger. Pre-fix regressions in the policy switch would
/// silently swallow the vuln and exit 0.
#[tokio::test]
async fn audit_high_vuln_under_default_policy_exits_nonzero() {
    let project = TempProject::empty(
        r#"{"name":"vuln-audit","version":"1.0.0","dependencies":{"vuln-pkg":"^1.0.0"}}"#,
    );
    let mock = MockRegistry::start().await;
    install_one(&project, &mock, "vuln-pkg").await;

    mock.with_osv_querybatch(vec![vec![MockRegistry::osv_vuln(
        "GHSA-xxxx-yyyy-zzzz",
        "Severe arbitrary code execution in vuln-pkg",
        "8.5", // CVSS 8.5 → HIGH
    )]])
    .await;

    let out = run_audit(&project, &mock, &[]);
    assert!(
        !out.status.success(),
        "audit must exit non-zero when an OSV vuln is present under default policy; \
         stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
}

/// `--fail-on=vuln` explicitly scopes the failure trigger to confirmed
/// vulnerabilities. With a vuln present, this policy fires.
#[tokio::test]
async fn audit_fail_on_vuln_triggers_when_vulnerability_present() {
    let project = TempProject::empty(
        r#"{"name":"vuln-policy","version":"1.0.0","dependencies":{"vuln-pkg":"^1.0.0"}}"#,
    );
    let mock = MockRegistry::start().await;
    install_one(&project, &mock, "vuln-pkg").await;

    mock.with_osv_querybatch(vec![vec![MockRegistry::osv_vuln(
        "GHSA-aaaa-bbbb-cccc",
        "RCE",
        "9.1", // CRITICAL
    )]])
    .await;

    let out = run_audit(&project, &mock, &["--fail-on=vuln"]);
    assert!(
        !out.status.success(),
        "--fail-on=vuln must trigger when an OSV vuln is present; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
}

/// `--fail-on=behavior` only triggers on critical/high BEHAVIORAL flags
/// (eval, child_process, obfuscation, etc.). An OSV vuln alone — with
/// no behavioral findings — must not fire this policy.
#[tokio::test]
async fn audit_fail_on_behavior_does_not_trigger_on_vuln_alone() {
    let project = TempProject::empty(
        r#"{"name":"behavior-policy","version":"1.0.0","dependencies":{"clean-pkg":"^1.0.0"}}"#,
    );
    let mock = MockRegistry::start().await;
    install_one(&project, &mock, "clean-pkg").await;

    // OSV returns a HIGH vuln — but the package itself has no
    // behavioral flags (the test tarball is minimal `module.exports = {}`).
    // `--fail-on=behavior` must scope to behavioral signals only and
    // therefore exit 0 here.
    mock.with_osv_querybatch(vec![vec![MockRegistry::osv_vuln(
        "GHSA-only-osv",
        "Vuln",
        "7.5",
    )]])
    .await;

    let out = run_audit(&project, &mock, &["--fail-on=behavior"]);
    assert!(
        out.status.success(),
        "--fail-on=behavior must NOT fire on OSV-only findings; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
}

// ─── JSON contract ──────────────────────────────────────────────────────

/// `audit --json` envelope shape is locked via insta. Catches silent
/// breaks of the dashboard / CI integrations that consume this output.
///
/// Captured fields: `success`, `manager`, `scanned`, `vulnerabilities[]`
/// (with `package`, `version`, `id`, `summary`, `severity`), `counts`,
/// `packages[]`. Dynamic test-port URLs aren't in the audit envelope,
/// so no redactions are needed.
#[tokio::test]
async fn audit_json_envelope_with_one_vuln_matches_snapshot() {
    let project = TempProject::empty(
        r#"{"name":"json-audit","version":"1.0.0","dependencies":{"snap-pkg":"^1.0.0"}}"#,
    );
    let mock = MockRegistry::start().await;
    install_one(&project, &mock, "snap-pkg").await;

    mock.with_osv_querybatch(vec![vec![MockRegistry::osv_vuln(
        "GHSA-snap-1234",
        "Snapshot fixture vuln",
        "7.5",
    )]])
    .await;

    let osv_url = format!("{}/v1/querybatch", mock.url());
    let out = lpm_with_registry(&project, &mock.url())
        .env("LPM_OSV_URL", &osv_url)
        .args(["audit", "--json"])
        .output()
        .expect("failed to spawn lpm audit --json");

    // `audit` exits non-zero on findings under default policy. The JSON
    // envelope is still emitted on stdout — verify by parsing.
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let envelope: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("audit --json stdout must be valid JSON: {e}\n---\n{stdout}"));

    insta::assert_json_snapshot!("audit_json_envelope_one_vuln", envelope);
}
