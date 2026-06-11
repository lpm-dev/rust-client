//! Workflow tests for `lpm audit`.
//!
//! Covers the security-critical command's main paths: discovery, OSV
//! vulnerability scan, fail-on policy gating, and JSON envelope shape.
//! All OSV interactions go through `MockRegistry::with_osv_querybatch`
//! via the `LPM_OSV_URL` env hook so tests never reach `api.osv.dev`.

mod support;

use support::mock_registry::{
    MockRegistry, RegistrySigningFixture, make_tarball, make_tarball_from_pkg_json,
};
use support::{TempProject, lpm, lpm_with_registry};

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

#[test]
fn audit_help_lists_fail_on_policies_on_separate_lines() {
    let project = TempProject::empty(r#"{"name":"audit-help","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args(["audit", "--help"])
        .output()
        .expect("failed to run lpm audit --help");
    assert!(
        output.status.success(),
        "audit --help must exit successfully"
    );

    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    assert!(
        combined.contains("CI exit code policy: what triggers a non-zero exit code."),
        "expected fail-on policy intro in help output; got:\n{combined}"
    );
    assert!(
        combined.contains("vuln     — only confirmed vulnerabilities (OSV/registry)\n"),
        "expected vuln policy on its own help line; got:\n{combined}"
    );
    assert!(
        combined.contains("behavior — only critical/high behavioral flags\n"),
        "expected behavior policy on its own help line; got:\n{combined}"
    );
    assert!(
        combined.contains("secrets  — only hardcoded secret findings from --secrets mode\n"),
        "expected secrets policy on its own help line; got:\n{combined}"
    );
    assert!(
        combined.contains("all      — vulnerabilities, behavioral flags, or secrets (default)"),
        "expected all policy on its own help line; got:\n{combined}"
    );
    assert!(
        !combined.contains("vuln     — only confirmed vulnerabilities (OSV/registry) behavior —"),
        "fail-on policies must not collapse into one run-on line; got:\n{combined}"
    );
}

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

fn run_audit_json(
    project: &TempProject,
    mock: &MockRegistry,
    extra_args: &[&str],
) -> std::process::Output {
    let osv_url = format!("{}/v1/querybatch", mock.url());
    let mut cmd = lpm_with_registry(project, &mock.url());
    cmd.env("LPM_OSV_URL", &osv_url);
    cmd.arg("--json");
    cmd.arg("audit");
    for arg in extra_args {
        cmd.arg(arg);
    }
    cmd.output().expect("failed to spawn lpm audit --json")
}

/// Mount `pkg@1.0.0` on the mock registry and install it into `project`.
/// Returns the original tarball bytes (callers don't need them yet but
/// the future-OSV-helper-per-package shape may).
async fn install_one(project: &TempProject, mock: &MockRegistry, pkg: &str) {
    install_one_with_pkg_json(
        project,
        mock,
        pkg,
        serde_json::json!({
            "name": pkg,
            "version": "1.0.0",
            "license": "MIT",
            "main": "index.js"
        }),
    )
    .await;
}

async fn install_one_private_no_license(project: &TempProject, mock: &MockRegistry, pkg: &str) {
    install_one_with_pkg_json(
        project,
        mock,
        pkg,
        serde_json::json!({
            "name": pkg,
            "version": "1.0.0",
            "private": true,
            "main": "index.js"
        }),
    )
    .await;
}

async fn install_one_with_pkg_json(
    project: &TempProject,
    mock: &MockRegistry,
    pkg: &str,
    pkg_json: serde_json::Value,
) {
    let tarball = make_tarball_from_pkg_json(pkg_json, &[]);
    mock.with_package(pkg, "1.0.0", &tarball).await;
    mock.with_batch_metadata(vec![serde_json::json!({
        "name": pkg,
        "dist-tags": { "latest": "1.0.0" },
        "versions": {
            "1.0.0": {
                "name": pkg,
                "version": "1.0.0",
                "dist": {
                    "tarball": format!("{}/tarballs/{pkg}/-/{pkg}-1.0.0.tgz", mock.url()),
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

async fn install_signature_fixture_project(
    project: &TempProject,
    mock: &MockRegistry,
    include_unsigned: bool,
) {
    project.write_file(".npmrc", &format!("registry={}\n", mock.url()));

    let signer = RegistrySigningFixture::new();
    mock.with_registry_signing_keys(&signer).await;

    let signed_tarball = make_tarball("signed-pkg", "1.0.0");
    let signed_metadata =
        mock.signed_package_metadata("signed-pkg", "1.0.0", &signed_tarball, &signer);
    mock.with_package_metadata(
        "signed-pkg",
        "1.0.0",
        &signed_tarball,
        signed_metadata.clone(),
    )
    .await;

    let mut batch = vec![signed_metadata];
    if include_unsigned {
        let unsigned_tarball = make_tarball("unsigned-pkg", "1.0.0");
        let unsigned_metadata = mock.package_metadata("unsigned-pkg", "1.0.0", &unsigned_tarball);
        mock.with_package_metadata(
            "unsigned-pkg",
            "1.0.0",
            &unsigned_tarball,
            unsigned_metadata.clone(),
        )
        .await;
        batch.push(unsigned_metadata);
    }

    mock.with_batch_metadata(batch).await;

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

#[tokio::test]
async fn audit_signatures_json_reports_verified_and_not_verified_packages() {
    let project = TempProject::empty(
        r#"{
            "name":"audit-signatures",
            "version":"1.0.0",
            "dependencies":{
                "signed-pkg":"1.0.0",
                "unsigned-pkg":"1.0.0"
            }
        }"#,
    );
    let mock = MockRegistry::start().await;
    install_signature_fixture_project(&project, &mock, true).await;

    let out = run_audit_json(&project, &mock, &["signatures"]);
    assert!(
        !out.status.success(),
        "audit signatures must exit non-zero when any registry package is not verified; \
         stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );

    let envelope: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
        panic!(
            "audit signatures --json must emit JSON: {e}\nstdout:\n{}",
            String::from_utf8_lossy(&out.stdout)
        )
    });
    assert_eq!(envelope["success"], serde_json::json!(false));
    assert_eq!(envelope["scanned"], serde_json::json!(2));
    assert_eq!(envelope["verified"], serde_json::json!(1));
    assert_eq!(envelope["not_verified"], serde_json::json!(1));
    assert_eq!(envelope["skipped"], serde_json::json!(0));

    let packages = envelope["packages"]
        .as_array()
        .expect("packages must be an array");
    assert!(
        packages.iter().any(|pkg| {
            pkg["name"] == "signed-pkg" && pkg["version"] == "1.0.0" && pkg["status"] == "verified"
        }),
        "signed package must be reported as verified: {envelope}",
    );
    assert!(
        packages.iter().any(|pkg| {
            pkg["name"] == "unsigned-pkg"
                && pkg["version"] == "1.0.0"
                && pkg["status"] == "not_verified"
                && pkg["reason"] == "missing_signatures"
        }),
        "unsigned package must be reported as not_verified with missing_signatures: {envelope}",
    );
}

#[tokio::test]
async fn audit_signatures_human_reports_slim_summary_and_failed_rows() {
    let project = TempProject::empty(
        r#"{
            "name":"audit-signatures-human",
            "version":"1.0.0",
            "dependencies":{
                "signed-pkg":"1.0.0",
                "unsigned-pkg":"1.0.0"
            }
        }"#,
    );
    let mock = MockRegistry::start().await;
    install_signature_fixture_project(&project, &mock, true).await;

    let out = run_audit(&project, &mock, &["signatures"]);
    assert!(
        !out.status.success(),
        "audit signatures must exit non-zero when any registry package is not verified; \
         stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );

    let stdout = strip_ansi(&String::from_utf8_lossy(&out.stdout));
    let stderr = strip_ansi(&String::from_utf8_lossy(&out.stderr));
    assert!(
        stdout.trim().is_empty(),
        "human audit signatures output must stay on stderr; stdout:\n{stdout}\nstderr:\n{stderr}",
    );
    assert!(
        stderr.contains("! Registry signatures · 1 verified · 1 not verified")
            && stderr.contains("unsigned-pkg@1.0.0")
            && stderr.contains("missing dist.signatures"),
        "audit signatures must use slim summary plus failed rows, got:\n{stderr}",
    );
}

#[tokio::test]
async fn audit_signatures_verified_tree_exits_zero() {
    let project = TempProject::empty(
        r#"{
            "name":"audit-signatures-clean",
            "version":"1.0.0",
            "dependencies":{"signed-pkg":"1.0.0"}
        }"#,
    );
    let mock = MockRegistry::start().await;
    install_signature_fixture_project(&project, &mock, false).await;

    let out = run_audit(&project, &mock, &["signatures"]);
    assert!(
        out.status.success(),
        "audit signatures must exit zero when all registry packages verify; \
         stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    let stderr = strip_ansi(&String::from_utf8_lossy(&out.stderr));
    assert!(
        stderr.contains("✓ Registry signatures verified · 1 verified"),
        "clean audit signatures must use slim success summary, got:\n{stderr}",
    );
}

async fn install_vulnerable_direct_dep_with_fixed_version(
    project: &TempProject,
    mock: &MockRegistry,
) {
    let vulnerable = make_tarball_from_pkg_json(
        serde_json::json!({
            "name": "vuln-pkg",
            "version": "1.0.0",
            "license": "MIT",
            "main": "index.js"
        }),
        &[],
    );
    let fixed = make_tarball_from_pkg_json(
        serde_json::json!({
            "name": "vuln-pkg",
            "version": "1.0.1",
            "license": "MIT",
            "main": "index.js"
        }),
        &[],
    );
    mock.with_full_package_metadata(
        "vuln-pkg",
        "1.0.1",
        &[
            ("1.0.0", serde_json::json!({}), Some(vulnerable)),
            ("1.0.1", serde_json::json!({}), Some(fixed)),
        ],
    )
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

    mark_lockfile_package_as_public_npm(project, "vuln-pkg");
}

fn mark_lockfile_package_as_public_npm(project: &TempProject, package: &str) {
    let lockfile_path = project.path().join("lpm.lock");
    let mut lockfile =
        lpm_lockfile::Lockfile::read_from_file(&lockfile_path).expect("read lpm.lock fixture");
    for locked in &mut lockfile.packages {
        if locked.name == package {
            locked.source = Some("registry+https://registry.npmjs.org".to_string());
        }
    }
    lockfile
        .write_all(&lockfile_path)
        .expect("write lpm.lock fixture");
}

fn osv_fixed_vuln(id: &str, package: &str, fixed: &str) -> serde_json::Value {
    serde_json::json!({
        "id": id,
        "summary": "test vulnerability",
        "severity": [{ "type": "CVSS_V3", "score": "9.8" }],
        "affected": [{
            "package": { "ecosystem": "npm", "name": package },
            "ranges": [{
                "type": "SEMVER",
                "events": [
                    { "introduced": "0" },
                    { "fixed": fixed }
                ]
            }]
        }]
    })
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
        "[metadata]\nlockfile-version = 2\nresolved-with = \"greedy-fusion\"\n",
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
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("! No packages found to audit"),
        "empty audit must use a slim warning, got:\n{stderr}",
    );
    assert!(
        !stderr.contains('●') && !stderr.contains('◇'),
        "empty audit must not use cliclack spinner glyphs, got:\n{stderr}",
    );
}

#[tokio::test]
async fn audit_empty_lockfile_json_reports_zero_package_envelope() {
    let project = TempProject::empty(r#"{"name":"empty-audit-json","version":"1.0.0"}"#);
    project.write_file(
        "lpm.lock",
        "[metadata]\nlockfile-version = 2\nresolved-with = \"greedy-fusion\"\n",
    );

    let mock = MockRegistry::start().await;
    mock.with_osv_querybatch(vec![]).await;

    let out = run_audit_json(&project, &mock, &[]);
    assert!(
        out.status.success(),
        "audit --json on a zero-package lockfile must exit 0; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.trim().is_empty(),
        "audit --json empty-lockfile path must not emit human warnings, got:\n{stderr}"
    );

    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let envelope: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("audit --json must emit a JSON object: {e}\n---\n{stdout}"));
    assert_eq!(envelope["success"], serde_json::json!(true));
    assert_eq!(envelope["manager"], serde_json::json!("lpm"));
    assert_eq!(envelope["scanned"], serde_json::json!(0));
    assert_eq!(envelope["checked_lpm"], serde_json::json!(0));
    assert_eq!(envelope["packages"], serde_json::json!([]));
    assert_eq!(envelope["vulnerabilities"], serde_json::json!([]));
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

    let stdout = strip_ansi(&String::from_utf8_lossy(&out.stdout));
    let stderr = strip_ansi(&String::from_utf8_lossy(&out.stderr));
    assert!(
        stdout.trim().is_empty(),
        "human audit output must stay on stderr; stdout:\n{stdout}\nstderr:\n{stderr}",
    );
    assert!(
        stderr.contains("✓ Analyzed 1 package · lpm.lock")
            && stderr.contains("✓ Checked against OSV database")
            && stderr.contains("✓ No issues found · 1 scanned"),
        "clean audit must use the slim compact summary, got:\n{stderr}",
    );
    assert!(
        !stderr.contains("Scanning 1 package")
            && !stderr.contains("lockfile")
            && !stderr.contains("Run lpm audit --json"),
        "clean audit must not render the old verbose body, got:\n{stderr}",
    );
}

// ─── Fix ───────────────────────────────────────────────────────────────

#[tokio::test]
async fn audit_fix_dry_run_reports_direct_dependency_fix_without_mutating_files() {
    let project = TempProject::empty(
        r#"{"name":"audit-fix-dry-run","version":"1.0.0","dependencies":{"vuln-pkg":"1.0.0"}}"#,
    );
    let mock = MockRegistry::start().await;
    install_vulnerable_direct_dep_with_fixed_version(&project, &mock).await;
    mock.with_osv_querybatch(vec![vec![osv_fixed_vuln(
        "GHSA-test-dry",
        "vuln-pkg",
        "1.0.1",
    )]])
    .await;

    let out = run_audit_json(&project, &mock, &["fix", "--dry-run"]);
    assert!(
        out.status.success(),
        "audit fix --dry-run must exit 0\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    let envelope: serde_json::Value = serde_json::from_slice(&out.stdout)
        .unwrap_or_else(|e| panic!("audit fix --json must emit JSON: {e}"));
    assert_eq!(envelope["dry_run"], serde_json::json!(true));
    assert_eq!(envelope["planned"], serde_json::json!(1));
    assert_eq!(envelope["fixed"], serde_json::json!(0));
    assert_eq!(
        envelope["packages"][0]["name"],
        serde_json::json!("vuln-pkg")
    );
    assert_eq!(envelope["packages"][0]["to"], serde_json::json!("1.0.1"));

    let package_json: serde_json::Value =
        serde_json::from_str(&project.read_file("package.json")).expect("parse package.json");
    assert_eq!(
        package_json["dependencies"]["vuln-pkg"],
        serde_json::json!("1.0.0"),
        "dry-run must not mutate package.json",
    );
}

#[tokio::test]
async fn audit_fix_updates_vulnerable_direct_dependency_and_reinstalls_lockfile() {
    let project = TempProject::empty(
        r#"{"name":"audit-fix-apply","version":"1.0.0","dependencies":{"vuln-pkg":"1.0.0"}}"#,
    );
    let mock = MockRegistry::start().await;
    install_vulnerable_direct_dep_with_fixed_version(&project, &mock).await;
    mock.with_osv_querybatch(vec![vec![osv_fixed_vuln(
        "GHSA-test-apply",
        "vuln-pkg",
        "1.0.1",
    )]])
    .await;

    let out = run_audit_json(&project, &mock, &["fix"]);
    assert!(
        out.status.success(),
        "audit fix must exit 0\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    let envelope: serde_json::Value = serde_json::from_slice(&out.stdout)
        .unwrap_or_else(|e| panic!("audit fix --json must emit JSON: {e}"));
    assert_eq!(envelope["fixed"], serde_json::json!(1));
    assert_eq!(envelope["packages"][0]["to"], serde_json::json!("1.0.1"));

    let package_json: serde_json::Value =
        serde_json::from_str(&project.read_file("package.json")).expect("parse package.json");
    assert_eq!(
        package_json["dependencies"]["vuln-pkg"],
        serde_json::json!("1.0.1"),
        "audit fix must write the patched range to package.json",
    );

    let lockfile = lpm_lockfile::Lockfile::read_fast(&project.path().join("lpm.lock"))
        .expect("read updated lpm.lock");
    let pkg = lockfile
        .find_package("vuln-pkg")
        .expect("vuln-pkg must remain installed");
    assert_eq!(pkg.version, "1.0.1");
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

    let stdout = strip_ansi(&String::from_utf8_lossy(&out.stdout));
    let stderr = strip_ansi(&String::from_utf8_lossy(&out.stderr));
    assert!(
        stdout.trim().is_empty(),
        "human audit findings must stay on stderr; stdout:\n{stdout}\nstderr:\n{stderr}",
    );
    assert!(
        stderr.contains("Vulnerabilities")
            && !stderr.contains("Vulnerabilities (OSV)")
            && stderr.contains("! vuln-pkg@1.0.0  GHSA-xxxx-yyyy-zzzz  severity high"),
        "vulnerability section must match the slim audit contract, got:\n{stderr}",
    );
    assert!(
        !stderr.contains("vulnerability details"),
        "audit must not print the old standalone OSV details hint, got:\n{stderr}",
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

// ─── Fail-on policies × behavior-tag triggers ──────────────────────────
//
// The earlier cases pin OSV-side policy gating. These cases pin the
// BEHAVIORAL side: a package whose source contains `eval()` (high) or
// obfuscated patterns (critical) must drive the policy switch the same
// way an OSV vuln drives the vuln side. Behavioral findings come from
// the client-side scanner in `lpm-security::behavioral`; node_modules
// is seeded directly so no install / registry-batch round-trip is
// involved.

/// Seed a node_modules package with eval() in its source — triggers
/// the high-severity behavior bucket.
fn seed_eval_package(project: &TempProject, name: &str) {
    seed_node_modules_package(
        project,
        name,
        &[(
            "index.js",
            "module.exports = function (src) { return eval(src) }\n",
        )],
    );
}

/// Seed a node_modules package with deliberately-obfuscated source —
/// hex-escaped string literals + `_0xAAAA` variable names match the
/// `lpm-security` obfuscation heuristic (see supply_chain::detect_obfuscation).
fn seed_obfuscated_package(project: &TempProject, name: &str) {
    seed_node_modules_package(
        project,
        name,
        &[(
            "index.js",
            "var _0x1a2b = \"\\x48\\x65\\x6c\\x6c\\x6f\";\nvar _0x3c4d = _0x1a2b;\nmodule.exports = _0x3c4d;\n",
        )],
    );
}

/// Wire `lpm audit` with `LPM_OSV_URL` pointed at a mock returning no
/// vulns, so the test isolates the behavior-tag policy path.
fn run_audit_no_osv(
    project: &TempProject,
    mock: &MockRegistry,
    extra_args: &[&str],
) -> std::process::Output {
    let osv_url = format!("{}/v1/querybatch", mock.url());
    let mut cmd = lpm(project);
    cmd.env("LPM_OSV_URL", &osv_url);
    cmd.arg("audit");
    for arg in extra_args {
        cmd.arg(arg);
    }
    cmd.output().expect("failed to spawn lpm audit")
}

/// `--fail-on=behavior` must fire on a HIGH-severity behavioral finding
/// like eval(). Pins the positive case for the `Behavior` arm of
/// `FailPolicy` (audit/mod.rs::should_fail).
#[tokio::test]
async fn audit_fail_on_behavior_triggers_on_local_eval_finding() {
    let project = TempProject::empty(r#"{"name":"eval-host","version":"1.0.0"}"#);
    seed_eval_package(&project, "eval-pkg");

    let mock = MockRegistry::start().await;
    // Audit will query OSV for non-@lpm.dev packages; return empty so
    // the only failure trigger is the behavioral finding.
    mock.with_osv_querybatch(vec![vec![]]).await;

    let out = run_audit_no_osv(&project, &mock, &["--fail-on=behavior"]);
    assert!(
        !out.status.success(),
        "--fail-on=behavior must fire when eval() is detected; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
}

/// `--fail-on=behavior` must also fire on CRITICAL behavioral findings
/// (obfuscation / protestware / high-entropy strings). Critical and
/// high go through different branches of `should_fail`; this case
/// pins the critical branch.
#[tokio::test]
async fn audit_fail_on_behavior_triggers_on_local_obfuscation_finding() {
    let project = TempProject::empty(r#"{"name":"obfu-host","version":"1.0.0"}"#);
    seed_obfuscated_package(&project, "obfu-pkg");

    let mock = MockRegistry::start().await;
    mock.with_osv_querybatch(vec![vec![]]).await;

    let out = run_audit_no_osv(&project, &mock, &["--fail-on=behavior"]);
    assert!(
        !out.status.success(),
        "--fail-on=behavior must fire when obfuscation is detected; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
}

/// Default policy (no `--fail-on` flag) is `FailPolicy::All` but with a
/// documented backward-compat carve-out: HIGH behavioral findings only
/// trigger failure when `--fail-on` is EXPLICITLY specified. This pins
/// that carve-out — a project with eval() but no `--fail-on` arg must
/// still exit 0.
///
/// See audit/mod.rs::should_fail (`FailPolicy::All` arm, `fail_on.is_some()`
/// branch) for the contract.
#[tokio::test]
async fn audit_default_policy_does_not_trigger_on_high_behavior_alone() {
    let project = TempProject::empty(r#"{"name":"eval-default","version":"1.0.0"}"#);
    seed_eval_package(&project, "eval-pkg");

    let mock = MockRegistry::start().await;
    mock.with_osv_querybatch(vec![vec![]]).await;

    let out = run_audit_no_osv(&project, &mock, &[]);
    assert!(
        out.status.success(),
        "default (no --fail-on) policy must NOT fire on high-behavior alone (backward compat); \
         stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
}

/// Explicit `--fail-on=all` flips the backward-compat carve-out off —
/// HIGH behavioral findings now count as failure triggers. Pairs with
/// the test above to fence the documented difference between
/// "default-all" and "explicit-all".
#[tokio::test]
async fn audit_fail_on_all_explicit_triggers_on_high_behavior() {
    let project = TempProject::empty(r#"{"name":"eval-all","version":"1.0.0"}"#);
    seed_eval_package(&project, "eval-pkg");

    let mock = MockRegistry::start().await;
    mock.with_osv_querybatch(vec![vec![]]).await;

    let out = run_audit_no_osv(&project, &mock, &["--fail-on=all"]);
    assert!(
        !out.status.success(),
        "--fail-on=all (explicit) must fire on high-behavior findings; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
}

/// `--fail-on=vuln` is the inverse-of-behavior policy: behavioral
/// findings alone must NOT trigger exit non-zero. Pins the negative
/// case for the `Vuln` arm of `FailPolicy`.
#[tokio::test]
async fn audit_fail_on_vuln_does_not_trigger_on_behavior_alone() {
    let project = TempProject::empty(r#"{"name":"vuln-policy-behavior","version":"1.0.0"}"#);
    seed_eval_package(&project, "eval-pkg");

    let mock = MockRegistry::start().await;
    mock.with_osv_querybatch(vec![vec![]]).await;

    let out = run_audit_no_osv(&project, &mock, &["--fail-on=vuln"]);
    assert!(
        out.status.success(),
        "--fail-on=vuln must NOT fire on behavioral findings alone; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
}

#[tokio::test]
async fn audit_private_package_without_license_does_not_emit_no_license_flag() {
    let project = TempProject::empty(
        r#"{"name":"private-audit","version":"1.0.0","dependencies":{"private-pkg":"^1.0.0"}}"#,
    );
    let mock = MockRegistry::start().await;
    install_one_private_no_license(&project, &mock, "private-pkg").await;
    mock.with_osv_querybatch(vec![vec![]]).await;

    let out = run_audit(&project, &mock, &["--json"]);
    assert!(
        out.status.success(),
        "private package without a license should not fail audit by itself; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );

    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let envelope: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("audit --json stdout must be valid JSON: {e}\n---\n{stdout}"));

    assert_eq!(envelope["counts"]["info"], serde_json::json!(0));
    assert_eq!(envelope["packages"], serde_json::json!([]));
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

// ─── `audit --secrets` (hardcoded-secret scanner) ────────────────────
//
// `audit --secrets` walks `node_modules/` and scans each package for
// API keys, tokens, etc. The pattern list lives in
// `crates/lpm-security/src/behavioral/secrets.rs`; tests below use a
// handful of well-known recognizable shapes (Stripe live `sk_live_…`,
// AWS access key `AKIA…`). No mock registry needed — secrets are
// scanned locally from `node_modules/`.

fn seed_node_modules_package(project: &TempProject, name: &str, files: &[(&str, &str)]) {
    project.write_file(
        &format!("node_modules/{name}/package.json"),
        &format!(r#"{{"name":"{name}","version":"1.0.0"}}"#),
    );
    for (file, content) in files {
        project.write_file(&format!("node_modules/{name}/{file}"), content);
    }
}

#[test]
fn audit_secrets_on_clean_node_modules_reports_no_findings_and_exits_zero() {
    let project = TempProject::empty(r#"{"name":"clean","version":"1.0.0"}"#);
    seed_node_modules_package(
        &project,
        "clean-pkg",
        &[("index.js", "module.exports = function () { return 42 }\n")],
    );

    let out = lpm(&project)
        .args(["audit", "--secrets"])
        .output()
        .expect("failed to run lpm audit --secrets");

    assert!(
        out.status.success(),
        "no findings → exit 0, got: {}\nstderr: {}",
        out.status,
        String::from_utf8_lossy(&out.stderr),
    );

    let stdout = strip_ansi(&String::from_utf8_lossy(&out.stdout));
    let stderr = strip_ansi(&String::from_utf8_lossy(&out.stderr));
    assert!(
        stdout.trim().is_empty()
            && stderr.contains("Scanned")
            && stderr.contains("✓ no hardcoded secrets found"),
        "human output must indicate the scan ran cleanly, got:\nstdout:\n{stdout}\nstderr:\n{stderr}",
    );
    assert!(
        !stderr.contains('●') && !stderr.contains('◇'),
        "audit secrets must not use cliclack spinner glyphs, got:\n{stderr}",
    );
}

#[test]
fn audit_secrets_detects_stripe_live_key_in_node_modules() {
    let project = TempProject::empty(r#"{"name":"secrets","version":"1.0.0"}"#);
    // Synthetic Stripe live-key shape — built from non-adjacent pieces
    // so this source file doesn't trip GitHub Secret Scanning's
    // Stripe-partner regex on push. The runtime fixture on disk still
    // matches `sk_live_` + 20+ alphanumerics, which is what the
    // detector under test needs to find. Don't inline the literal
    // again — push protection will reject the commit on a fresh push.
    let stripe_key_fixture = format!(
        "sk_{kind}_{hex}",
        kind = "live",
        hex = "0123456789abcdef0123456789ABCDEF",
    );
    let config_js =
        format!("const STRIPE_KEY = '{stripe_key_fixture}';\nmodule.exports = STRIPE_KEY;\n");
    seed_node_modules_package(&project, "leaky-pkg", &[("config.js", config_js.as_str())]);

    let out = lpm(&project)
        .args(["audit", "--secrets"])
        .output()
        .expect("failed to run lpm audit --secrets");

    assert!(
        !out.status.success(),
        "default audit --secrets policy must exit non-zero when secrets are found\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );

    let stdout = strip_ansi(&String::from_utf8_lossy(&out.stdout));
    let stderr = strip_ansi(&String::from_utf8_lossy(&out.stderr));
    assert!(
        stdout.trim().is_empty(),
        "human audit secrets output must stay on stderr; stdout:\n{stdout}\nstderr:\n{stderr}",
    );
    assert!(
        stderr.contains("leaky-pkg"),
        "human output must list the offending package, got:\n{stderr}",
    );
    assert!(
        stderr.contains("Stripe live")
            || stderr.contains("stripe_live_secret")
            || stderr.contains("critical"),
        "human output must mention the detected pattern, got:\n{stderr}",
    );
}

#[test]
fn audit_secrets_json_envelope_carries_findings_array() {
    let project = TempProject::empty(r#"{"name":"secrets-json","version":"1.0.0"}"#);
    seed_node_modules_package(
        &project,
        "leaky-pkg",
        &[(
            "index.js",
            // AWS access key ID pattern: `AKIA` + 16 uppercase alphanumerics.
            "const AWS = { accessKey: 'AKIAIOSFODNN7EXAMPLE' };\nmodule.exports = AWS;\n",
        )],
    );

    let out = lpm(&project)
        .args(["--json", "audit", "--secrets"])
        .output()
        .expect("failed to run lpm audit --secrets --json");
    assert!(
        !out.status.success(),
        "default audit --secrets --json policy must exit non-zero when findings exist"
    );

    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let envelope: serde_json::Value = serde_json::from_str(&stdout).unwrap_or_else(|e| {
        panic!("audit --secrets --json must be valid JSON: {e}\n---\n{stdout}")
    });

    assert_eq!(envelope["success"], serde_json::json!(true));
    assert!(
        envelope["packagesScanned"].as_u64().is_some(),
        "envelope must carry packagesScanned: {envelope}"
    );
    assert_eq!(
        envelope["packagesWithSecrets"],
        serde_json::json!(1),
        "exactly one package must be flagged: {envelope}"
    );

    let findings = envelope["findings"]
        .as_array()
        .expect("findings must be an array");
    assert_eq!(
        findings.len(),
        1,
        "exactly one finding expected: {envelope}"
    );
    assert_eq!(findings[0]["package"], serde_json::json!("leaky-pkg"));

    let matches = findings[0]["matches"]
        .as_array()
        .expect("matches must be an array");
    assert!(
        !matches.is_empty(),
        "at least one match per flagged package: {envelope}"
    );
    assert!(
        matches[0]["pattern"].is_string(),
        "each match must carry pattern + severity: {envelope}"
    );
}

#[test]
fn audit_secrets_fail_on_vuln_does_not_trigger_on_secret_finding() {
    let project = TempProject::empty(r#"{"name":"secrets-vuln-policy","version":"1.0.0"}"#);
    seed_node_modules_package(
        &project,
        "leaky-pkg",
        &[(
            "index.js",
            "const AWS = { accessKey: 'AKIAIOSFODNN7EXAMPLE' };\nmodule.exports = AWS;\n",
        )],
    );

    let out = lpm(&project)
        .args(["audit", "--secrets", "--fail-on=vuln"])
        .output()
        .expect("failed to run lpm audit --secrets --fail-on=vuln");

    assert!(
        out.status.success(),
        "--fail-on=vuln must not trigger on secret findings alone\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
}

#[test]
fn audit_secrets_fail_on_secrets_triggers_on_secret_finding() {
    let project = TempProject::empty(r#"{"name":"secrets-policy","version":"1.0.0"}"#);
    seed_node_modules_package(
        &project,
        "leaky-pkg",
        &[(
            "index.js",
            "const AWS = { accessKey: 'AKIAIOSFODNN7EXAMPLE' };\nmodule.exports = AWS;\n",
        )],
    );

    let out = lpm(&project)
        .args(["audit", "--secrets", "--fail-on=secrets"])
        .output()
        .expect("failed to run lpm audit --secrets --fail-on=secrets");

    assert!(
        !out.status.success(),
        "--fail-on=secrets must trigger on secret findings\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
}

#[test]
fn audit_secrets_without_node_modules_fails_with_helpful_error() {
    let project = TempProject::empty(r#"{"name":"no-nm","version":"1.0.0"}"#);

    let out = lpm(&project)
        .args(["audit", "--secrets"])
        .output()
        .expect("failed to run lpm audit --secrets");

    assert!(
        !out.status.success(),
        "missing node_modules must exit non-zero",
    );

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("node_modules") || stderr.contains("lpm install"),
        "stderr must guide the user, got:\n{stderr}",
    );
}
