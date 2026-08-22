//! Workflow tests for `lpm audit`.
//!
//! Covers the security-critical command's main paths: discovery, OSV
//! vulnerability scan, fail-on policy gating, and JSON envelope shape.
//! All OSV interactions go through `MockRegistry::with_osv_querybatch`
//! via the `LPM_OSV_URL` env hook so tests never reach `api.osv.dev`.

mod support;

use support::mock_registry::{
    MockRegistry, RegistrySigningFixture, compute_integrity, make_tarball,
    make_tarball_from_pkg_json, make_tarball_with_files,
};
use support::{
    TempProject, lpm, lpm_spawnable_with_registry, lpm_with_registry, lpm_with_registry_and_npm,
};
use wiremock::matchers::{body_json, method, path};
use wiremock::{Mock, ResponseTemplate};

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

fn run_audit_with_npm(
    project: &TempProject,
    mock: &MockRegistry,
    extra_args: &[&str],
    json: bool,
) -> std::process::Output {
    let osv_url = format!("{}/v1/querybatch", mock.url());
    let mut cmd = lpm_with_registry_and_npm(project, &mock.url());
    cmd.env("LPM_OSV_URL", &osv_url);
    if json {
        cmd.arg("--json");
    }
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

async fn mount_registry_advisory(mock: &MockRegistry, package: &str, summary: &str) {
    let ndjson = format!(
        "{}\n",
        serde_json::json!({
            "name": package,
            "metadata": {
                "name": package,
                "dist-tags": {"latest": "1.0.0"},
                "versions": {
                    "1.0.0": {
                        "name": package,
                        "version": "1.0.0",
                        "dependencies": {},
                        "_vulnerabilities": [{
                            "id": "REGISTRY-ESCAPE",
                            "summary": summary,
                            "severity": "high"
                        }]
                    }
                }
            }
        })
    );
    Mock::given(method("POST"))
        .and(path("/api/registry/batch-metadata"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(ndjson, "application/x-ndjson"))
        .with_priority(1)
        .mount(mock.server())
        .await;
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

    lpm_with_registry_and_npm(project, &mock.url())
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

    let out = run_audit_with_npm(&project, &mock, &["signatures"], true);
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

    let out = run_audit_with_npm(&project, &mock, &["signatures"], false);
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
    let requests_before = mock.server().received_requests().await.unwrap().len();

    let out = run_audit_with_npm(&project, &mock, &["signatures"], false);
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
    let requests = mock.server().received_requests().await.unwrap();
    assert!(
        requests[requests_before..].iter().all(|request| {
            request.method != wiremock::http::Method::GET || request.url.path() != "/signed-pkg"
        }),
        "audit signatures must use persisted lockfile evidence without hydrating package metadata"
    );
}

#[tokio::test]
async fn audit_signatures_does_not_skip_foreign_lpm_scope_from_an_npm_registry() {
    let project = TempProject::empty(r#"{"name":"foreign-lpm-scope","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    project.write_file(".npmrc", &format!("registry={}\n", mock.url()));

    let package = "@lpm.dev/dependency-confusion";
    let tarball = make_tarball(package, "1.0.0");
    mock.with_package(package, "1.0.0", &tarball).await;
    project.write_file(
        "package-lock.json",
        &format!(
            r#"{{
  "name": "foreign-lpm-scope",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "packages": {{
    "": {{"name": "foreign-lpm-scope", "version": "1.0.0"}},
    "node_modules/@lpm.dev/dependency-confusion": {{
      "version": "1.0.0",
      "resolved": "{}/tarballs/@lpm.dev/dependency-confusion/-/dependency-confusion-1.0.0.tgz",
      "integrity": "{}"
    }}
  }}
}}"#,
            mock.url(),
            compute_integrity(&tarball)
        ),
    );

    let output = lpm(&project)
        .args(["--json", "audit", "signatures"])
        .output()
        .expect("run audit signatures for a foreign @lpm.dev package");

    assert!(
        !output.status.success(),
        "unsigned foreign @lpm.dev package must fail verification; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let envelope: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(envelope["scanned"], 1);
    assert_eq!(envelope["skipped"], 0);
    assert_eq!(envelope["not_verified"], 1);
    assert_eq!(envelope["packages"][0]["reason"], "missing_signatures");
}

#[tokio::test]
async fn audit_signatures_never_contacts_an_unconfigured_lockfile_origin() {
    let project = TempProject::empty(r#"{"name":"foreign-origin","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    project.write_file(
        "package-lock.json",
        &format!(
            r#"{{
  "name": "foreign-origin",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "packages": {{
    "node_modules/private-package": {{
      "version": "1.0.0",
      "resolved": "{}/private-package/-/private-package-1.0.0.tgz",
      "integrity": "sha512-test"
    }}
  }}
}}"#,
            mock.url()
        ),
    );

    let output = lpm(&project)
        .args(["--json", "audit", "signatures"])
        .output()
        .expect("run signature audit with an unconfigured foreign origin");

    assert!(
        output.status.success(),
        "unconfigured tarball origin must be treated as non-registry; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let envelope: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(envelope["scanned"], 1);
    assert_eq!(envelope["skipped"], 1);
    assert!(
        mock.server().received_requests().await.unwrap().is_empty(),
        "a lockfile-controlled origin must not receive metadata or signing-key requests"
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
    if !lockfile.workspace_packages.is_empty()
        || lockfile.importers.keys().any(|importer| importer != ".")
    {
        let importers = lockfile.importers.keys().cloned().collect::<Vec<_>>();
        for importer in importers {
            let mut projection = lockfile.project_importer(&importer).unwrap();
            let roots = projection
                .root_resolutions
                .iter()
                .map(|(local_name, root)| {
                    (
                        local_name.clone(),
                        root.package.clone(),
                        root.version.clone(),
                    )
                })
                .collect::<Vec<_>>();
            let mut changed = false;
            for locked in &mut projection.packages {
                if locked.name == package {
                    locked.source = Some("registry+https://registry.npmjs.org".to_string());
                    changed = true;
                }
            }
            if changed {
                let roots = roots
                    .iter()
                    .map(|(local_name, package_name, version)| {
                        (local_name.as_str(), package_name.as_str(), version.as_str())
                    })
                    .collect::<Vec<_>>();
                support::finalize_exact_lockfile_fixture(&mut projection, &roots);
                lockfile.replace_importer(&importer, projection).unwrap();
            }
        }
    } else {
        let roots = lockfile
            .root_resolutions
            .iter()
            .map(|(local_name, root)| {
                (
                    local_name.clone(),
                    root.package.clone(),
                    root.version.clone(),
                )
            })
            .collect::<Vec<_>>();
        for locked in &mut lockfile.packages {
            if locked.name == package {
                locked.source = Some("registry+https://registry.npmjs.org".to_string());
            }
        }
        let roots = roots
            .iter()
            .map(|(local_name, package_name, version)| {
                (local_name.as_str(), package_name.as_str(), version.as_str())
            })
            .collect::<Vec<_>>();
        support::finalize_exact_lockfile_fixture(&mut lockfile, &roots);
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
async fn audit_info_only_dep_with_empty_osv_response_exits_zero() {
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
            && stderr.contains("Behavioral metadata")
            && stderr.contains("✓ No security issues found · 1 scanned")
            && stderr.contains("1 metadata signal"),
        "Info-only audit must distinguish metadata from security issues, got:\n{stderr}",
    );
    assert!(
        !stderr.contains("Scanning 1 package")
            && !stderr.contains("lockfile")
            && !stderr.contains("Run lpm audit --json"),
        "clean audit must not render the old verbose body, got:\n{stderr}",
    );
}

#[tokio::test]
async fn audit_pnpm_v6_discovers_populated_registry_inventory() {
    let project = TempProject::empty(r#"{"name":"pnpm-v6-audit","version":"1.0.0"}"#);
    project.write_file(
        "pnpm-lock.yaml",
        r#"lockfileVersion: '6.0'
packages:
  /once@1.0.0:
    resolution:
      integrity: sha512-once
      tarball: https://registry.npmjs.org/once/-/once-1.0.0.tgz
"#,
    );
    let mock = MockRegistry::start().await;
    mock.with_osv_querybatch(vec![vec![]]).await;

    let output = run_audit_json(&project, &mock, &[]);

    assert!(
        output.status.success(),
        "pnpm v6 audit must succeed for an empty OSV result; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let envelope: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(envelope["manager"], "pnpm");
    assert_eq!(envelope["scanned"], 1);
}

#[tokio::test]
async fn audit_registry_advisory_sanitizes_human_output_and_preserves_json_value() {
    let package = "@lpm.dev/test.audit-terminal-boundary";
    let summary = "safe advisory\nFORGED-LINE\rrewritten\u{8}\u{1b}[2J\u{1b}]52;c;AAAA\u{7}\u{0090}hidden\u{009c}end";
    let project = TempProject::empty(&format!(
        r#"{{"name":"audit-terminal-boundary","version":"1.0.0","dependencies":{{"{package}":"1.0.0"}}}}"#
    ));
    let mock = MockRegistry::start().await;
    install_one(&project, &mock, package).await;
    mount_registry_advisory(&mock, package, summary).await;
    mock.with_osv_querybatch(vec![vec![]]).await;

    let osv_url = format!("{}/v1/querybatch", mock.url());
    let mut human_command = lpm_with_registry(&project, &mock.url());
    human_command
        .env("LPM_OSV_URL", &osv_url)
        .env_remove("NO_COLOR")
        .env("FORCE_COLOR", "1")
        .arg("audit");
    let human = human_command
        .output()
        .expect("failed to spawn colored lpm audit");
    assert!(!human.status.success(), "high advisory must fail audit");
    let rendered = format!(
        "{}{}",
        String::from_utf8_lossy(&human.stdout),
        String::from_utf8_lossy(&human.stderr)
    );
    assert!(
        rendered.contains("safe advisory?FORGED-LINE?rewritten?end"),
        "safe advisory text must remain visible without injected lines; got:\n{rendered}"
    );
    assert!(
        rendered.contains("\u{1b}["),
        "forced LPM styling must remain present; got:\n{rendered}"
    );
    for attacker_fragment in [
        "\u{1b}[2J",
        "\u{1b}]52;c;AAAA",
        "\u{7}",
        "\u{8}",
        "\r",
        "\u{0090}",
        "\u{009c}",
        "hidden",
    ] {
        assert!(
            !rendered.contains(attacker_fragment),
            "human output retained attacker fragment {attacker_fragment:?}:\n{rendered}"
        );
    }

    let json = run_audit_json(&project, &mock, &[]);
    assert!(!json.status.success(), "high advisory must fail JSON audit");
    assert!(json.stderr.is_empty(), "JSON audit must not write stderr");
    let envelope: serde_json::Value = serde_json::from_slice(&json.stdout)
        .unwrap_or_else(|error| panic!("audit JSON must parse: {error}"));
    assert_eq!(
        envelope["packages"][0]["issues"][0]["message"],
        format!("REGISTRY-ESCAPE — {summary}")
    );
}

#[tokio::test]
async fn audit_hydrates_sparse_querybatch_advisories_before_filtering() {
    let project = TempProject::empty(
        r#"{"name":"sparse-osv","version":"1.0.0","dependencies":{"vuln-pkg":"1.0.0"}}"#,
    );
    let mock = MockRegistry::start().await;
    install_one(&project, &mock, "vuln-pkg").await;

    Mock::given(method("POST"))
        .and(path("/v1/querybatch"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "results": [{"vulns": [{"id": "GHSA-sparse", "modified": "2026-07-18T00:00:00Z"}]}]
        })))
        .mount(mock.server())
        .await;
    Mock::given(method("GET"))
        .and(path("/v1/vulns/GHSA-sparse"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": "GHSA-sparse",
            "summary": "hydrated advisory",
            "database_specific": {"severity": "MODERATE"},
            "affected": [{
                "package": {"ecosystem": "npm", "name": "vuln-pkg"},
                "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.0.1"}]}]
            }]
        })))
        .mount(mock.server())
        .await;

    let out = run_audit_json(&project, &mock, &["--level", "moderate"]);
    assert!(
        out.stderr.is_empty(),
        "JSON audit must not emit human/log noise on stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !out.status.success(),
        "hydrated moderate vulnerability must fail the default audit policy\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    let envelope: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(envelope["vulnerabilities"][0]["id"], "GHSA-sparse");
    assert_eq!(
        envelope["vulnerabilities"][0]["summary"],
        "hydrated advisory"
    );
    assert_eq!(envelope["vulnerabilities"][0]["severity"], "MODERATE");
}

#[tokio::test]
async fn audit_still_sparse_hydrated_advisory_fails_closed_before_level_filtering() {
    let project = TempProject::empty(
        r#"{"name":"still-sparse-osv","version":"1.0.0","dependencies":{"vuln-pkg":"1.0.0"}}"#,
    );
    let mock = MockRegistry::start().await;
    install_one(&project, &mock, "vuln-pkg").await;

    Mock::given(method("POST"))
        .and(path("/v1/querybatch"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "results": [{"vulns": [{"id": "GHSA-still-sparse"}]}]
        })))
        .mount(mock.server())
        .await;
    Mock::given(method("GET"))
        .and(path("/v1/vulns/GHSA-still-sparse"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": "GHSA-still-sparse",
            "summary": "detail endpoint remained incomplete"
        })))
        .mount(mock.server())
        .await;

    let out = run_audit_json(&project, &mock, &["--level", "info"]);
    assert!(
        !out.status.success(),
        "an advisory that remains incomplete after hydration must fail closed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    assert!(out.stderr.is_empty());
    let envelope: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(envelope["osv_degraded"], true);
    assert!(
        envelope["osv_degraded_reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("remained incomplete")),
        "unexpected degraded reason: {envelope:#}"
    );
}

#[tokio::test]
async fn audit_malformed_hydrated_severity_fails_closed_before_level_filtering() {
    let project = TempProject::empty(
        r#"{"name":"malformed-osv-severity","version":"1.0.0","dependencies":{"vuln-pkg":"1.0.0"}}"#,
    );
    let mock = MockRegistry::start().await;
    install_one(&project, &mock, "vuln-pkg").await;

    Mock::given(method("POST"))
        .and(path("/v1/querybatch"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "results": [{"vulns": [{"id": "GHSA-malformed-severity"}]}]
        })))
        .mount(mock.server())
        .await;
    Mock::given(method("GET"))
        .and(path("/v1/vulns/GHSA-malformed-severity"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": "GHSA-malformed-severity",
            "summary": "detail endpoint returned unusable severity data",
            "severity": [{"type": "CVSS_V3", "score": "not-a-cvss-score"}],
            "database_specific": {"severity": "urgent"},
            "affected": [{
                "package": {"ecosystem": "npm", "name": "vuln-pkg"},
                "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.0.1"}]}]
            }]
        })))
        .mount(mock.server())
        .await;

    let out = run_audit_json(&project, &mock, &["--level", "info"]);
    assert!(
        !out.status.success(),
        "an advisory with unusable hydrated severity must fail closed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    assert!(out.stderr.is_empty());
    let envelope: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(envelope["osv_degraded"], true);
    assert!(
        envelope["osv_degraded_reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("remained incomplete")),
        "unexpected degraded reason: {envelope:#}"
    );
}

#[tokio::test]
async fn audit_osv_outage_exits_nonzero_without_clean_summary() {
    let project = TempProject::empty(
        r#"{"name":"osv-outage","version":"1.0.0","dependencies":{"clean-pkg":"1.0.0"}}"#,
    );
    let mock = MockRegistry::start().await;
    install_one(&project, &mock, "clean-pkg").await;
    Mock::given(method("POST"))
        .and(path("/v1/querybatch"))
        .respond_with(ResponseTemplate::new(503).set_body_string("maintenance"))
        .mount(mock.server())
        .await;

    let out = run_audit(&project, &mock, &[]);
    let stderr = strip_ansi(&String::from_utf8_lossy(&out.stderr));
    assert!(
        !out.status.success(),
        "an incomplete vulnerability scan must exit nonzero: {stderr}"
    );
    assert!(stderr.contains("vulnerability scan incomplete"));
    assert!(
        !stderr.contains("No issues found"),
        "degraded audit must never print a clean summary: {stderr}"
    );

    let json_out = run_audit_json(&project, &mock, &[]);
    assert!(!json_out.status.success());
    assert!(
        json_out.stderr.is_empty(),
        "JSON degraded audit must keep stderr empty: {}",
        String::from_utf8_lossy(&json_out.stderr)
    );
    let envelope: serde_json::Value = serde_json::from_slice(&json_out.stdout).unwrap();
    assert_eq!(envelope["success"], false);
    assert_eq!(envelope["osv_degraded"], true);
}

#[tokio::test]
async fn audit_rejects_osv_batch_response_with_missing_result_slots() {
    let project = TempProject::empty(
        r#"{"name":"osv-cardinality","version":"1.0.0","dependencies":{"clean-pkg":"1.0.0"}}"#,
    );
    let mock = MockRegistry::start().await;
    install_one(&project, &mock, "clean-pkg").await;
    Mock::given(method("POST"))
        .and(path("/v1/querybatch"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"results": []})))
        .mount(mock.server())
        .await;

    let out = run_audit_json(&project, &mock, &[]);
    assert!(!out.status.success());
    assert!(out.stderr.is_empty());
    let envelope: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(envelope["success"], false);
    assert_eq!(envelope["osv_degraded"], true);
    assert!(
        envelope["osv_degraded_reason"]
            .as_str()
            .unwrap()
            .contains("cardinality mismatch")
    );
}

#[tokio::test]
async fn audit_lpm_metadata_failure_exits_nonzero() {
    let package = "@lpm.dev/test.audit-metadata-error";
    let project = TempProject::empty(&format!(
        r#"{{"name":"metadata-error","version":"1.0.0","dependencies":{{"{package}":"1.0.0"}}}}"#
    ));
    let mock = MockRegistry::start().await;
    install_one(&project, &mock, package).await;
    Mock::given(method("POST"))
        .and(path("/api/registry/batch-metadata"))
        .respond_with(ResponseTemplate::new(503).set_body_string("registry unavailable"))
        .with_priority(1)
        .mount(mock.server())
        .await;

    let out = run_audit_json(&project, &mock, &[]);
    assert!(
        !out.status.success(),
        "registry metadata failure must fail closed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    assert!(out.stderr.is_empty());
    let error: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(error["success"], false);
}

#[tokio::test]
async fn audit_lpm_missing_installed_metadata_does_not_fall_back_to_latest() {
    let package = "@lpm.dev/test.audit-missing-version";
    let project = TempProject::empty(&format!(
        r#"{{"name":"metadata-missing","version":"1.0.0","dependencies":{{"{package}":"1.0.0"}}}}"#
    ));
    let mock = MockRegistry::start().await;
    install_one(&project, &mock, package).await;
    let ndjson = format!(
        "{}\n",
        serde_json::json!({
            "name": package,
            "metadata": {
                "name": package,
                "dist-tags": {"latest": "2.0.0"},
                "versions": {"2.0.0": {"name": package, "version": "2.0.0"}}
            }
        })
    );
    Mock::given(method("POST"))
        .and(path("/api/registry/batch-metadata"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(ndjson, "application/x-ndjson"))
        .with_priority(1)
        .mount(mock.server())
        .await;

    let out = run_audit_json(&project, &mock, &[]);
    assert!(
        !out.status.success(),
        "missing exact installed metadata must fail closed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    assert!(out.stderr.is_empty());
    let error: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(error["success"], false);
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

#[tokio::test]
async fn workspace_member_audit_fix_preserves_the_sibling_root_lockfile_projection() {
    let project = TempProject::empty(
        r#"{
  "name": "audit-fix-workspace",
  "version": "1.0.0",
  "private": true,
  "workspaces": ["packages/*"]
}"#,
    );
    project.write_file(
        "packages/app/package.json",
        r#"{"name":"audit-app","version":"1.0.0","private":true,"dependencies":{"vuln-pkg":"1.0.0"}}"#,
    );
    project.write_file(
        "packages/sibling/package.json",
        r#"{"name":"audit-sibling","version":"1.0.0","private":true}"#,
    );

    let mock = MockRegistry::start().await;
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
    let app_dir = project.path().join("packages/app");
    lpm_with_registry(&project, &mock.url())
        .current_dir(&app_dir)
        .args([
            "install",
            "--no-recursive",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .assert()
        .success();
    mark_lockfile_package_as_public_npm(&project, "vuln-pkg");

    let lockfile_path = project.path().join("lpm.lock");
    let mut root_lockfile = lpm_lockfile::Lockfile::read_fast(&lockfile_path).unwrap();
    let mut sibling_projection = lpm_lockfile::Lockfile::new();
    sibling_projection.patches.insert(
        "sibling@1.0.0".into(),
        lpm_lockfile::LockfilePatch {
            path: "patches/sibling.patch".into(),
            sha256: "sha256-sibling".into(),
            original_integrity: "sha512-sibling".into(),
        },
    );
    root_lockfile
        .absorb_importer("packages/sibling", sibling_projection)
        .unwrap();
    root_lockfile.write_all(&lockfile_path).unwrap();
    let sibling_before = root_lockfile.project_importer("packages/sibling").unwrap();

    mock.with_osv_querybatch(vec![vec![osv_fixed_vuln(
        "GHSA-workspace-fix",
        "vuln-pkg",
        "1.0.1",
    )]])
    .await;
    let requests_before = mock.server().received_requests().await.unwrap().len();
    let mut command = lpm_with_registry(&project, &mock.url());
    command.current_dir(&app_dir);
    command.env("LPM_OSV_URL", format!("{}/v1/querybatch", mock.url()));
    let output = command
        .args(["--json", "audit", "fix"])
        .output()
        .expect("apply audit fix from workspace member");
    assert!(
        output.status.success(),
        "workspace audit fix failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let requests = mock.server().received_requests().await.unwrap();
    assert!(
        requests[requests_before..].iter().any(|request| {
            request.url.path() == "/v1/querybatch"
                && String::from_utf8_lossy(&request.body).contains("\"version\":\"1.0.1\"")
        }),
        "workspace audit-fix verification must scan the staged importer projection"
    );

    let updated = lpm_lockfile::Lockfile::read_fast(&lockfile_path).unwrap();
    assert_eq!(
        updated
            .project_importer("packages/app")
            .unwrap()
            .find_package("vuln-pkg")
            .map(|package| package.version.as_str()),
        Some("1.0.1")
    );
    assert_eq!(
        updated.project_importer("packages/sibling").unwrap(),
        sibling_before
    );
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&project.read_file("packages/app/package.json"))
            .unwrap()["dependencies"]["vuln-pkg"],
        "1.0.1"
    );
    assert!(!app_dir.join("lpm.lock").exists());
    assert!(!app_dir.join("lpm.lockb").exists());
}

#[tokio::test]
async fn audit_fix_apply_installs_the_exact_version_reported_by_dry_run() {
    let project = TempProject::empty(
        r#"{"name":"audit-fix-exact-target","version":"1.0.0","dependencies":{"vuln-pkg":"1.0.0"}}"#,
    );
    let mock = MockRegistry::start().await;
    let vulnerable = make_tarball("vuln-pkg", "1.0.0");
    let fixed = make_tarball("vuln-pkg", "1.0.1");
    let newer_major = make_tarball("vuln-pkg", "3.0.0");
    mock.with_full_package_metadata(
        "vuln-pkg",
        "3.0.0",
        &[
            ("1.0.0", serde_json::json!({}), Some(vulnerable)),
            ("1.0.1", serde_json::json!({}), Some(fixed)),
            ("3.0.0", serde_json::json!({}), Some(newer_major)),
        ],
    )
    .await;
    lpm_with_registry(&project, &mock.url())
        .args([
            "install",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .assert()
        .success();
    mark_lockfile_package_as_public_npm(&project, "vuln-pkg");
    project.write_file(
        "package.json",
        r#"{"name":"audit-fix-exact-target","version":"1.0.0","dependencies":{"vuln-pkg":"*"}}"#,
    );
    mock.with_osv_querybatch(vec![vec![osv_fixed_vuln(
        "GHSA-exact-target",
        "vuln-pkg",
        "1.0.1",
    )]])
    .await;

    let out = run_audit_json(&project, &mock, &["fix"]);
    assert!(
        out.status.success(),
        "audit fix must apply the planned target\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    let envelope: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(envelope["packages"][0]["to"], "1.0.1");
    let manifest: serde_json::Value =
        serde_json::from_str(&project.read_file("package.json")).unwrap();
    assert_eq!(manifest["dependencies"]["vuln-pkg"], "1.0.1");
    let lockfile = lpm_lockfile::Lockfile::read_fast(&project.path().join("lpm.lock")).unwrap();
    assert_eq!(lockfile.find_package("vuln-pkg").unwrap().version, "1.0.1");
}

#[tokio::test]
async fn audit_fix_aborts_without_overwriting_manifest_edits_made_during_planning() {
    let project = TempProject::empty(
        r#"{"name":"audit-fix-manifest-drift","version":"1.0.0","dependencies":{"vuln-pkg":"1.0.0"}}"#,
    );
    let mock = MockRegistry::start().await;
    install_vulnerable_direct_dep_with_fixed_version(&project, &mock).await;
    Mock::given(method("POST"))
        .and(path("/v1/querybatch"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_delay(std::time::Duration::from_millis(750))
                .set_body_json(serde_json::json!({
                    "results": [{"vulns": [osv_fixed_vuln(
                        "GHSA-manifest-drift",
                        "vuln-pkg",
                        "1.0.1"
                    )]}]
                })),
        )
        .mount(mock.server())
        .await;

    let mut command = lpm_spawnable_with_registry(&project, &mock.url());
    command.env("LPM_OSV_URL", format!("{}/v1/querybatch", mock.url()));
    command.args(["--json", "audit", "fix"]);
    let child = command.spawn().unwrap();

    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        let planning_started = mock
            .server()
            .received_requests()
            .await
            .unwrap()
            .iter()
            .any(|request| request.url.path() == "/v1/querybatch");
        if planning_started {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "audit fix never reached OSV planning"
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }

    let edited_manifest = r#"{"name":"audit-fix-manifest-drift","version":"1.0.0","description":"external edit","dependencies":{"vuln-pkg":"1.0.0"}}"#;
    project.write_file("package.json", edited_manifest);
    let out = child.wait_with_output().unwrap();

    assert!(
        !out.status.success(),
        "audit fix must abort when package.json changes during planning\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    assert_eq!(project.read_file("package.json"), edited_manifest);
}

#[tokio::test]
async fn audit_fix_aborts_when_the_lockfile_changes_during_planning() {
    let project = TempProject::empty(
        r#"{"name":"audit-fix-lockfile-drift","version":"1.0.0","dependencies":{"vuln-pkg":"1.0.0"}}"#,
    );
    let mock = MockRegistry::start().await;
    install_vulnerable_direct_dep_with_fixed_version(&project, &mock).await;
    Mock::given(method("POST"))
        .and(path("/v1/querybatch"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_delay(std::time::Duration::from_millis(750))
                .set_body_json(serde_json::json!({
                    "results": [{"vulns": [osv_fixed_vuln(
                        "GHSA-lockfile-drift",
                        "vuln-pkg",
                        "1.0.1"
                    )]}]
                })),
        )
        .mount(mock.server())
        .await;

    let original_manifest = project.read_file("package.json");
    let mut command = lpm_spawnable_with_registry(&project, &mock.url());
    command.env("LPM_OSV_URL", format!("{}/v1/querybatch", mock.url()));
    command.args(["--json", "audit", "fix"]);
    let child = command.spawn().unwrap();

    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        let planning_started = mock
            .server()
            .received_requests()
            .await
            .unwrap()
            .iter()
            .any(|request| request.url.path() == "/v1/querybatch");
        if planning_started {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "audit fix never reached OSV planning"
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }

    let lockfile_path = project.path().join("lpm.lock");
    let mut replacement = lpm_lockfile::Lockfile::read_fast(&lockfile_path).unwrap();
    replacement.packages[0].integrity = Some(support::VALID_TEST_INTEGRITY.to_string());
    replacement.write_all(&lockfile_path).unwrap();
    let replacement_bytes = std::fs::read(&lockfile_path).unwrap();
    let output = child.wait_with_output().unwrap();

    assert!(
        !output.status.success(),
        "audit fix must abort when lpm.lock changes during planning; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(project.read_file("package.json"), original_manifest);
    assert_eq!(std::fs::read(&lockfile_path).unwrap(), replacement_bytes);
}

#[tokio::test]
async fn audit_fix_preserves_a_lockfile_replaced_after_workspace_capture() {
    let project = TempProject::empty(
        r#"{"name":"audit-fix-late-lockfile-drift","version":"1.0.0","dependencies":{"vuln-pkg":"1.0.0"}}"#,
    );
    let mock = MockRegistry::start().await;
    install_vulnerable_direct_dep_with_fixed_version(&project, &mock).await;
    Mock::given(method("POST"))
        .and(path("/v1/querybatch"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "results": [{"vulns": [osv_fixed_vuln(
                "GHSA-late-lockfile-drift",
                "vuln-pkg",
                "1.0.1"
            )]}]
        })))
        .mount(mock.server())
        .await;

    let original_manifest = project.read_file("package.json");
    let marker = project.path().join("audit-fix-snapshot-ready");
    let resume = marker.with_extension("resume");
    let mut command = lpm_spawnable_with_registry(&project, &mock.url());
    command.env("LPM_OSV_URL", format!("{}/v1/querybatch", mock.url()));
    command.env("LPM_TEST_PAUSE_BEFORE_AUDIT_FIX_SNAPSHOT", &marker);
    command.args(["--json", "audit", "fix"]);
    let child = command.spawn().unwrap();

    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
    while !marker.exists() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "audit fix never reached the transaction snapshot"
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }

    let lockfile_path = project.path().join("lpm.lock");
    let mut replacement = lpm_lockfile::Lockfile::read_fast(&lockfile_path).unwrap();
    replacement.packages[0].integrity = Some(support::VALID_TEST_INTEGRITY.to_string());
    replacement.write_all(&lockfile_path).unwrap();
    let replacement_bytes = std::fs::read(&lockfile_path).unwrap();
    std::fs::write(&resume, b"resume").unwrap();
    let output = child.wait_with_output().unwrap();

    assert!(
        !output.status.success(),
        "audit fix must reject late lpm.lock replacement; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(project.read_file("package.json"), original_manifest);
    assert_eq!(std::fs::read(&lockfile_path).unwrap(), replacement_bytes);
}

#[tokio::test]
async fn audit_fix_json_remains_one_document_when_nested_install_applies_overrides() {
    let project = TempProject::empty(
        r#"{
            "name":"audit-fix-json-override",
            "version":"1.0.0",
            "dependencies":{"vuln-pkg":"1.0.0"},
            "lpm":{"overrides":{"helper-pkg":"1.0.1"}}
        }"#,
    );
    let mock = MockRegistry::start().await;
    let vulnerable = make_tarball("vuln-pkg", "1.0.0");
    let fixed = make_tarball("vuln-pkg", "1.0.1");
    mock.with_full_package_metadata(
        "vuln-pkg",
        "1.0.1",
        &[
            (
                "1.0.0",
                serde_json::json!({"helper-pkg": "^1.0.0"}),
                Some(vulnerable),
            ),
            (
                "1.0.1",
                serde_json::json!({"helper-pkg": "^1.0.0"}),
                Some(fixed),
            ),
        ],
    )
    .await;
    mock.with_full_package_metadata(
        "helper-pkg",
        "1.0.1",
        &[
            (
                "1.0.0",
                serde_json::json!({}),
                Some(make_tarball("helper-pkg", "1.0.0")),
            ),
            (
                "1.0.1",
                serde_json::json!({}),
                Some(make_tarball("helper-pkg", "1.0.1")),
            ),
        ],
    )
    .await;
    lpm_with_registry(&project, &mock.url())
        .args([
            "install",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .assert()
        .success();
    mark_lockfile_package_as_public_npm(&project, "vuln-pkg");
    mock.with_osv_querybatch(vec![
        vec![],
        vec![osv_fixed_vuln("GHSA-json-override", "vuln-pkg", "1.0.1")],
    ])
    .await;

    let out = run_audit_json(&project, &mock, &["fix"]);
    assert!(
        out.status.success(),
        "audit fix with overrides must succeed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    assert!(out.stderr.is_empty());
    let envelope: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap_or_else(|error| {
        panic!(
            "audit fix JSON must remain one document: {error}\nstdout:\n{}",
            String::from_utf8_lossy(&out.stdout)
        )
    });
    assert_eq!(envelope["fixed"], 1);
}

#[tokio::test]
async fn audit_fix_updates_optional_dependency_remediation() {
    let project = TempProject::empty(
        r#"{"name":"audit-fix-optional","version":"1.0.0","dependencies":{"vuln-pkg":"1.0.0"},"optionalDependencies":{"vuln-pkg":"1.0.0"}}"#,
    );
    let mock = MockRegistry::start().await;
    install_vulnerable_direct_dep_with_fixed_version(&project, &mock).await;
    let installed = lpm_lockfile::Lockfile::read_fast(&project.path().join("lpm.lock")).unwrap();
    assert!(
        installed
            .packages
            .iter()
            .any(|package| package.name == "vuln-pkg")
    );
    mock.with_osv_querybatch(vec![vec![osv_fixed_vuln(
        "GHSA-optional",
        "vuln-pkg",
        "1.0.1",
    )]])
    .await;

    let out = run_audit_json(&project, &mock, &["fix"]);
    assert!(out.status.success());
    let envelope: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(envelope["planned"], 1, "{envelope:#}");
    assert_eq!(envelope["fixed"], 1);
    assert_eq!(envelope["packages"][0]["name"], "vuln-pkg");
    let package_json: serde_json::Value =
        serde_json::from_str(&project.read_file("package.json")).unwrap();
    assert_eq!(package_json["optionalDependencies"]["vuln-pkg"], "1.0.1");
    assert_eq!(package_json["dependencies"]["vuln-pkg"], "1.0.1");
}

#[tokio::test]
async fn audit_fix_preserves_npm_alias_identity_and_protocol() {
    let project = TempProject::empty(
        r#"{"name":"audit-fix-alias","version":"1.0.0","dependencies":{"local-vuln":"npm:vuln-pkg@1.0.0"}}"#,
    );
    let mock = MockRegistry::start().await;
    install_vulnerable_direct_dep_with_fixed_version(&project, &mock).await;
    mock.with_osv_querybatch(vec![vec![osv_fixed_vuln(
        "GHSA-alias",
        "vuln-pkg",
        "1.0.1",
    )]])
    .await;

    let out = run_audit_json(&project, &mock, &["fix", "--dry-run"]);
    assert!(out.status.success());
    let envelope: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(envelope["planned"], 1);
    assert_eq!(envelope["packages"][0]["name"], "local-vuln");
    assert_eq!(envelope["packages"][0]["new_range"], "npm:vuln-pkg@1.0.1");
}

#[tokio::test]
async fn audit_fix_chooses_patch_on_installed_maintained_line() {
    let project = TempProject::empty(
        r#"{"name":"audit-fix-release-line","version":"1.0.0","dependencies":{"vuln-pkg":"1.0.0"}}"#,
    );
    let mock = MockRegistry::start().await;
    let v100 = make_tarball("vuln-pkg", "1.0.0");
    let v101 = make_tarball("vuln-pkg", "1.0.1");
    let v201 = make_tarball("vuln-pkg", "2.0.1");
    mock.with_full_package_metadata(
        "vuln-pkg",
        "2.0.1",
        &[
            ("1.0.0", serde_json::json!({}), Some(v100)),
            ("1.0.1", serde_json::json!({}), Some(v101)),
            ("2.0.1", serde_json::json!({}), Some(v201)),
        ],
    )
    .await;
    lpm_with_registry(&project, &mock.url())
        .args([
            "install",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .assert()
        .success();
    mark_lockfile_package_as_public_npm(&project, "vuln-pkg");
    mock.with_osv_querybatch(vec![vec![serde_json::json!({
        "id": "GHSA-release-lines",
        "summary": "maintained release lines",
        "severity": [{"type": "CVSS_V3", "score": "8.0"}],
        "affected": [{
            "package": {"ecosystem": "npm", "name": "vuln-pkg"},
            "ranges": [
                {"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.0.1"}]},
                {"type": "SEMVER", "events": [{"introduced": "2.0.0"}, {"fixed": "2.0.1"}]}
            ]
        }]
    })]])
    .await;

    let out = run_audit_json(&project, &mock, &["fix", "--dry-run"]);
    assert!(out.status.success());
    let envelope: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(envelope["packages"][0]["to"], "1.0.1");
}

#[tokio::test]
async fn audit_fix_does_not_apply_transitive_version_advisory_to_safe_direct_instance() {
    let project = TempProject::empty(
        r#"{"name":"audit-fix-instance","version":"1.0.0","dependencies":{"vuln-pkg":"2.0.0"}}"#,
    );
    let mock = MockRegistry::start().await;
    let v100 = make_tarball("vuln-pkg", "1.0.0");
    let v101 = make_tarball("vuln-pkg", "1.0.1");
    let v200 = make_tarball("vuln-pkg", "2.0.0");
    mock.with_full_package_metadata(
        "vuln-pkg",
        "2.0.0",
        &[
            ("1.0.0", serde_json::json!({}), Some(v100)),
            ("1.0.1", serde_json::json!({}), Some(v101)),
            ("2.0.0", serde_json::json!({}), Some(v200)),
        ],
    )
    .await;
    lpm_with_registry(&project, &mock.url())
        .args([
            "install",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .assert()
        .success();
    mark_lockfile_package_as_public_npm(&project, "vuln-pkg");
    let lockfile_path = project.path().join("lpm.lock");
    let mut lockfile = lpm_lockfile::Lockfile::read_fast(&lockfile_path).unwrap();
    let mut transitive = lockfile.packages[0].clone();
    transitive.version = "1.0.0".to_string();
    transitive.instance_id = Some(lpm_common::PackageInstanceId::derive(
        &transitive.name,
        &transitive.version,
        transitive.source.as_deref().unwrap_or("registry+unknown"),
        "fixture/transitive-vulnerable-instance",
    ));
    lockfile.add_package(transitive);
    for package in &mut lockfile.packages {
        package.instance_id = None;
        package.dependency_targets.clear();
        package.peer_targets.clear();
    }
    for root in lockfile.root_resolutions.values_mut() {
        root.instance_id = None;
    }
    lockfile.metadata.lockfile_version = 12;
    lockfile.write_all(&lockfile_path).unwrap();
    mock.with_osv_querybatch(vec![
        vec![],
        vec![osv_fixed_vuln("GHSA-transitive", "vuln-pkg", "1.0.1")],
    ])
    .await;

    let out = run_audit_json(&project, &mock, &["fix", "--dry-run"]);
    assert!(out.status.success());
    let envelope: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(envelope["planned"], 0);
    assert_eq!(envelope["skipped"], serde_json::json!([]));
}

#[tokio::test]
async fn audit_fix_does_not_fetch_remediation_metadata_for_clean_direct_dependencies() {
    let project = TempProject::empty(
        r#"{"name":"audit-fix-clean-direct","version":"1.0.0","dependencies":{"clean-pkg":"1.0.0","vuln-pkg":"1.0.0"}}"#,
    );
    let mock = MockRegistry::start().await;
    mock.with_full_package_metadata(
        "clean-pkg",
        "1.0.0",
        &[(
            "1.0.0",
            serde_json::json!({}),
            Some(make_tarball("clean-pkg", "1.0.0")),
        )],
    )
    .await;
    install_vulnerable_direct_dep_with_fixed_version(&project, &mock).await;
    mark_lockfile_package_as_public_npm(&project, "clean-pkg");
    let _ = std::fs::remove_dir_all(project.cache_dir().join("metadata"));
    mock.with_osv_querybatch(vec![
        vec![],
        vec![osv_fixed_vuln("GHSA-vulnerable", "vuln-pkg", "1.0.1")],
    ])
    .await;
    let requests_before = mock.server().received_requests().await.unwrap().len();

    let out = run_audit_json(&project, &mock, &["fix", "--dry-run"]);
    assert!(
        out.status.success(),
        "dry-run must plan the vulnerable package\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    let envelope: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(envelope["planned"], 1, "{envelope:#}");
    let requests = mock.server().received_requests().await.unwrap();
    assert!(
        requests[requests_before..]
            .iter()
            .all(|request| request.url.path() != "/api/registry/clean-pkg"),
        "audit fix must not fetch remediation metadata for a package with no advisory"
    );
}

#[tokio::test]
async fn audit_fix_fails_when_vulnerable_direct_dependency_has_ambiguous_source() {
    let project = TempProject::empty(
        r#"{"name":"audit-fix-source-ambiguity","version":"1.0.0","dependencies":{"vuln-pkg":"1.0.0"}}"#,
    );
    let mock = MockRegistry::start().await;
    install_vulnerable_direct_dep_with_fixed_version(&project, &mock).await;
    let lockfile_path = project.path().join("lpm.lock");
    let mut lockfile = lpm_lockfile::Lockfile::read_fast(&lockfile_path).unwrap();
    let mut local_fork = lockfile.find_package("vuln-pkg").unwrap().clone();
    local_fork.source = Some("directory+../local-vuln-pkg".to_string());
    local_fork.instance_id = Some(lpm_common::PackageInstanceId::derive(
        &local_fork.name,
        &local_fork.version,
        local_fork.source.as_deref().expect("local source"),
        "fixture/local-vulnerable-fork",
    ));
    local_fork.integrity = None;
    local_fork.tarball = None;
    lockfile.add_package(local_fork);
    for package in &mut lockfile.packages {
        package.instance_id = None;
        package.dependency_targets.clear();
        package.peer_targets.clear();
        package.manifest_fingerprint = None;
    }
    for root in lockfile.root_resolutions.values_mut() {
        root.instance_id = None;
    }
    lockfile.metadata.lockfile_version = 10;
    lockfile.write_all(&lockfile_path).unwrap();
    let _ = std::fs::remove_dir_all(project.cache_dir().join("metadata"));
    mock.with_osv_querybatch(vec![vec![osv_fixed_vuln(
        "GHSA-source-ambiguity",
        "vuln-pkg",
        "1.0.1",
    )]])
    .await;
    let requests_before = mock.server().received_requests().await.unwrap().len();

    let out = run_audit_json(&project, &mock, &["fix", "--dry-run"]);
    assert!(
        !out.status.success(),
        "audit fix must fail when a vulnerable direct dependency cannot be resolved safely\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    let envelope: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(envelope["success"], false, "{envelope:#}");
    assert_eq!(envelope["planned"], 0, "{envelope:#}");
    assert!(
        envelope["skipped"][0]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("ambiguous lockfile instances")),
        "unexpected skip reason: {envelope:#}"
    );
    let requests = mock.server().received_requests().await.unwrap();
    assert!(
        requests[requests_before..]
            .iter()
            .all(|request| request.url.path() != "/api/registry/vuln-pkg"),
        "source-ambiguous packages must not be disclosed to a metadata endpoint"
    );
}

#[tokio::test]
async fn audit_fix_plans_lpm_registry_advisory_remediation() {
    let package = "@lpm.dev/test.audit-fix";
    let project = TempProject::empty(&format!(
        r#"{{"name":"audit-fix-lpm","version":"1.0.0","dependencies":{{"{package}":"1.0.0"}}}}"#
    ));
    let mock = MockRegistry::start().await;
    let vulnerable = make_tarball(package, "1.0.0");
    let fixed = make_tarball(package, "1.0.1");
    let metadata = serde_json::json!({
        "name": package,
        "dist-tags": {"latest": "1.0.1"},
        "versions": {
            "1.0.0": {
                "name": package,
                "version": "1.0.0",
                "dist": {
                    "tarball": format!("{}{}", mock.url(), MockRegistry::tarball_path(package, "1.0.0")),
                    "integrity": support::mock_registry::compute_integrity(&vulnerable)
                },
                "_vulnerabilities": [{"id": "LPM-ADV-1", "summary": "test", "severity": "high"}]
            },
            "1.0.1": {
                "name": package,
                "version": "1.0.1",
                "dist": {
                    "tarball": format!("{}{}", mock.url(), MockRegistry::tarball_path(package, "1.0.1")),
                    "integrity": support::mock_registry::compute_integrity(&fixed)
                }
            }
        }
    });
    mock.with_package_metadata_and_tarballs(
        package,
        metadata,
        &[("1.0.0", vulnerable), ("1.0.1", fixed)],
    )
    .await;
    lpm_with_registry(&project, &mock.url())
        .args([
            "install",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .assert()
        .success();

    let out = run_audit_json(&project, &mock, &["fix", "--dry-run"]);
    assert!(out.status.success());
    let envelope: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(envelope["planned"], 1);
    assert_eq!(envelope["packages"][0]["to"], "1.0.1");
    assert_eq!(envelope["packages"][0]["vulnerabilities"][0], "LPM-ADV-1");
}

#[tokio::test]
async fn audit_fix_rolls_back_when_installed_target_remains_vulnerable() {
    let project = TempProject::empty(
        r#"{"name":"audit-fix-verify","version":"1.0.0","dependencies":{"vuln-pkg":"1.0.0"}}"#,
    );
    let mock = MockRegistry::start().await;
    install_vulnerable_direct_dep_with_fixed_version(&project, &mock).await;
    let initial_query = serde_json::json!({
        "queries": [{"package": {"name": "vuln-pkg", "ecosystem": "npm"}, "version": "1.0.0"}]
    });
    Mock::given(method("POST"))
        .and(path("/v1/querybatch"))
        .and(body_json(&initial_query))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "results": [{"vulns": [osv_fixed_vuln("GHSA-initial", "vuln-pkg", "1.0.1")]}]
        })))
        .mount(mock.server())
        .await;
    let verify_query = serde_json::json!({
        "queries": [{"package": {"name": "vuln-pkg", "ecosystem": "npm"}, "version": "1.0.1"}]
    });
    Mock::given(method("POST"))
        .and(path("/v1/querybatch"))
        .and(body_json(&verify_query))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "results": [{"vulns": [osv_fixed_vuln("GHSA-residual", "vuln-pkg", "1.0.2")]}]
        })))
        .mount(mock.server())
        .await;
    let original_manifest = project.read_file("package.json");
    let original_lockfile = std::fs::read(project.path().join("lpm.lock")).unwrap();

    let out = run_audit_json(&project, &mock, &["fix"]);
    assert!(
        !out.status.success(),
        "verification must reject a still-vulnerable installed target\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    assert_eq!(project.read_file("package.json"), original_manifest);
    assert_eq!(
        std::fs::read(project.path().join("lpm.lock")).unwrap(),
        original_lockfile
    );
}

#[tokio::test]
async fn audit_fix_plans_before_waiting_for_the_project_install_transaction_lock() {
    let project = TempProject::empty(
        r#"{"name":"audit-fix-lock","version":"1.0.0","dependencies":{"vuln-pkg":"1.0.0"}}"#,
    );
    let mock = MockRegistry::start().await;
    install_vulnerable_direct_dep_with_fixed_version(&project, &mock).await;
    mock.with_osv_querybatch(vec![vec![osv_fixed_vuln("GHSA-lock", "vuln-pkg", "1.0.1")]])
        .await;
    let lock = lpm_common::acquire_exclusive_lock(lpm_common::project_install_lock(project.path()))
        .unwrap();
    let requests_before = mock.server().received_requests().await.unwrap().len();
    let mut command = lpm_spawnable_with_registry(&project, &mock.url());
    command.env("LPM_OSV_URL", format!("{}/v1/querybatch", mock.url()));
    command.args(["--json", "audit", "fix"]);
    let mut child = command.spawn().unwrap();

    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        if mock.server().received_requests().await.unwrap().len() > requests_before {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "audit fix did not begin read-only planning while the mutation lock was held"
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert!(
        child.try_wait().unwrap().is_none(),
        "audit fix must wait before mutating while another install transaction holds the project lock"
    );

    drop(lock);
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "audit fix must continue after the lock is released\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
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
        "vuln-pkg",
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
        "vuln-pkg",
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

#[tokio::test]
async fn audit_fail_on_vuln_respects_high_threshold_for_direct_command() {
    let project = TempProject::empty(
        r#"{"name":"high-vuln-policy","version":"1.0.0","dependencies":{"vuln-pkg":"^1.0.0"}}"#,
    );
    let mock = MockRegistry::start().await;
    install_one(&project, &mock, "vuln-pkg").await;
    mock.with_osv_querybatch(vec![vec![MockRegistry::osv_vuln(
        "GHSA-high-direct",
        "vuln-pkg",
        "High severity fixture",
        "8.5",
    )]])
    .await;

    let output = run_audit(&project, &mock, &["--level", "high", "--fail-on", "vuln"]);

    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("GHSA-high-direct"));
}

#[tokio::test]
async fn audit_high_threshold_ignores_moderate_vulnerability() {
    let project = TempProject::empty(
        r#"{"name":"moderate-vuln-policy","version":"1.0.0","dependencies":{"vuln-pkg":"^1.0.0"}}"#,
    );
    let mock = MockRegistry::start().await;
    install_one(&project, &mock, "vuln-pkg").await;
    mock.with_osv_querybatch(vec![vec![MockRegistry::osv_vuln(
        "GHSA-moderate-direct",
        "vuln-pkg",
        "Moderate severity fixture",
        "5.5",
    )]])
    .await;

    let output = run_audit(&project, &mock, &["--level", "high", "--fail-on", "vuln"]);

    assert!(output.status.success());
    assert!(!String::from_utf8_lossy(&output.stderr).contains("GHSA-moderate-direct"));
}

#[tokio::test]
async fn run_preserves_audit_fail_on_vuln_exit_status() {
    let binary = assert_cmd::cargo::cargo_bin("lpm-rs");
    let script = format!("\"{}\" audit --level high --fail-on vuln", binary.display());
    let project = TempProject::empty(
        &serde_json::json!({
            "name": "run-vuln-policy",
            "version": "1.0.0",
            "dependencies": { "vuln-pkg": "^1.0.0" },
            "scripts": { "security:audit": script }
        })
        .to_string(),
    );
    let mock = MockRegistry::start().await;
    install_one(&project, &mock, "vuln-pkg").await;
    mock.with_osv_querybatch(vec![vec![MockRegistry::osv_vuln(
        "GHSA-high-run",
        "vuln-pkg",
        "High severity fixture",
        "9.1",
    )]])
    .await;
    let osv_url = format!("{}/v1/querybatch", mock.url());

    let output = lpm(&project)
        .env("LPM_OSV_URL", osv_url)
        .args(["run", "security:audit"])
        .output()
        .expect("run audit package script");

    assert_eq!(output.status.code(), Some(1));
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(combined.contains("GHSA-high-run"));
    assert!(!combined.contains("security:audit · success"));
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
        "clean-pkg",
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

/// Seed a node_modules package with high-confidence obfuscated source.
fn seed_high_confidence_obfuscated_package(project: &TempProject, name: &str) {
    seed_node_modules_package(
        project,
        name,
        &[(
            "index.js",
            "var _0x1a2b=[\"\\x48\",\"\\x65\",\"\\x6c\",\"\\x6c\",\"\\x6f\"];\nfunction _0x3c4d(_0x5e6f) { return _0x1a2b[_0x5e6f]; }\nmodule.exports = _0x3c4d(0x1);\n",
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

#[tokio::test]
async fn audit_reports_info_behavioral_metadata_without_failing() {
    let project = TempProject::empty(r#"{"name":"info-host","version":"1.0.0"}"#);
    seed_node_modules_package(
        &project,
        "info-pkg",
        &[(
            "index.js",
            "module.exports = process.env.NODE_ENV;\nconst docs = 'https://example.com/docs';\n",
        )],
    );
    project.write_file(
        "node_modules/info-pkg/package.json",
        r#"{"name":"info-pkg","version":"1.0.0","license":"MIT"}"#,
    );
    let mock = MockRegistry::start().await;
    mock.with_osv_querybatch(vec![vec![]]).await;

    let output = run_audit_no_osv(&project, &mock, &[]);

    assert!(
        output.status.success(),
        "Info metadata must not fail audit\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("environment-variable access"),
        "{combined}"
    );
    assert!(combined.contains("URL literals"), "{combined}");
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
/// (obfuscation or protestware). Critical and
/// high go through different branches of `should_fail`; this case
/// pins the critical branch.
#[tokio::test]
async fn audit_fail_on_behavior_triggers_on_local_high_confidence_obfuscation() {
    let project = TempProject::empty(r#"{"name":"obfu-host","version":"1.0.0"}"#);
    seed_high_confidence_obfuscated_package(&project, "obfu-pkg");

    let mock = MockRegistry::start().await;
    mock.with_osv_querybatch(vec![vec![]]).await;

    let out = run_audit_no_osv(&project, &mock, &["--fail-on=behavior"]);
    assert!(
        !out.status.success(),
        "--fail-on=behavior must fire on high-confidence obfuscation; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
}

#[tokio::test]
async fn audit_human_output_shows_local_critical_finding_for_lpm_package() {
    let mock = MockRegistry::start().await;
    let package = "@lpm.dev/test.local-critical";
    let tarball = make_tarball_with_files(
        package,
        "1.0.0",
        &[(
            "index.js",
            b"while (true) { value = value.replace('a', 'b'); }\n",
        )],
    );
    let metadata = serde_json::json!({
        "name": package,
        "dist-tags": {"latest": "1.0.0"},
        "versions": {
            "1.0.0": {
                "name": package,
                "version": "1.0.0",
                "dist": {
                    "tarball": format!(
                        "{}{}",
                        mock.url(),
                        MockRegistry::tarball_path(package, "1.0.0")
                    ),
                    "integrity": compute_integrity(&tarball)
                }
            }
        }
    });
    mock.with_package_metadata_and_tarballs(package, metadata, &[("1.0.0", tarball)])
        .await;
    let project = TempProject::empty(&format!(
        r#"{{"name":"local-critical-host","version":"1.0.0","dependencies":{{"{package}":"1.0.0"}}}}"#
    ));

    let install = lpm_with_registry(&project, &mock.url())
        .args([
            "install",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("failed to install local Critical fixture");
    assert!(
        install.status.success(),
        "fixture install failed: {}",
        String::from_utf8_lossy(&install.stderr)
    );

    let output = run_audit(&project, &mock, &[]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !output.status.success(),
        "Critical audit must exit non-zero"
    );
    assert!(
        stderr.contains("CRITICAL") && stderr.contains("protestware") && stderr.contains(package),
        "local LPM Critical finding must be visible in human output: {stderr}"
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

    assert_eq!(envelope["counts"]["moderate"], serde_json::json!(0));
    assert!(
        envelope["packages"]
            .as_array()
            .expect("packages array")
            .iter()
            .flat_map(|package| { package["issues"].as_array().expect("package issues").iter() })
            .all(|issue| issue["message"] != "no license")
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
        "snap-pkg",
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

#[cfg(unix)]
#[test]
fn audit_secrets_scans_symlinked_package_content() {
    use std::os::unix::fs::symlink;

    let project = TempProject::empty(r#"{"name":"symlinked-secrets","version":"1.0.0"}"#);
    let package_dir = project
        .path()
        .join("node_modules/.pnpm/linked@1.0.0/node_modules/linked");
    std::fs::create_dir_all(&package_dir).unwrap();
    std::fs::write(
        package_dir.join("package.json"),
        r#"{"name":"linked","version":"1.0.0"}"#,
    )
    .unwrap();
    std::fs::write(
        package_dir.join("config.js"),
        "const AWS = 'AKIAIOSFODNN7EXAMPLE';\n",
    )
    .unwrap();
    symlink(&package_dir, project.path().join("node_modules/linked")).unwrap();

    let output = lpm(&project)
        .args(["audit", "--secrets"])
        .output()
        .expect("failed to run lpm audit --secrets");
    let stderr = strip_ansi(&String::from_utf8_lossy(&output.stderr));

    assert!(
        !output.status.success() && stderr.contains("linked"),
        "symlinked installed packages must be scanned\nstdout: {}\nstderr: {stderr}",
        String::from_utf8_lossy(&output.stdout),
    );
}

#[cfg(unix)]
#[test]
fn audit_secrets_rejects_package_links_outside_approved_roots() {
    use std::os::unix::fs::symlink;

    let project = TempProject::empty(r#"{"name":"external-secrets","version":"1.0.0"}"#);
    let external = tempfile::tempdir().unwrap();
    std::fs::write(
        external.path().join("package.json"),
        r#"{"name":"external","version":"1.0.0"}"#,
    )
    .unwrap();
    std::fs::write(
        external.path().join("config.js"),
        "const AWS = 'AKIAIOSFODNN7EXAMPLE';\n",
    )
    .unwrap();
    std::fs::create_dir_all(project.path().join("node_modules")).unwrap();
    symlink(
        external.path(),
        project.path().join("node_modules/external"),
    )
    .unwrap();

    let output = lpm(&project)
        .args(["audit", "--secrets"])
        .output()
        .expect("failed to run lpm audit --secrets");
    let stderr = strip_ansi(&String::from_utf8_lossy(&output.stderr));

    assert!(
        !output.status.success() && stderr.contains("outside approved package roots"),
        "external package links must fail closed\nstdout: {}\nstderr: {stderr}",
        String::from_utf8_lossy(&output.stdout),
    );
}

#[test]
fn audit_secrets_scans_nested_transitive_package_content() {
    let project = TempProject::empty(r#"{"name":"nested-secrets","version":"1.0.0"}"#);
    seed_node_modules_package(
        &project,
        "parent",
        &[("index.js", "module.exports = {};\n")],
    );
    seed_node_modules_package(
        &project,
        "parent/node_modules/child",
        &[("config.js", "const AWS = 'AKIAIOSFODNN7EXAMPLE';\n")],
    );

    let output = lpm(&project)
        .args(["audit", "--secrets"])
        .output()
        .expect("failed to run lpm audit --secrets");
    let stderr = strip_ansi(&String::from_utf8_lossy(&output.stderr));

    assert!(
        !output.status.success() && stderr.contains("child"),
        "nested installed packages must be scanned\nstdout: {}\nstderr: {stderr}",
        String::from_utf8_lossy(&output.stdout),
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
