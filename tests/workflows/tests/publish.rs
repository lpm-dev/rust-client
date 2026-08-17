//! Workflow tests for `lpm publish`.
//!
//! Tests dry-run, quality check, error cases, and mock registry publish.

mod support;

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD as BASE64, URL_SAFE_NO_PAD};
use sha2::{Digest, Sha512};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use support::assertions::parse_json_output;
use support::mock_registry::MockRegistry;
use support::{TempProject, lpm, lpm_with_registry};
use wiremock::matchers::{header, method, path, path_regex, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

const NPM_ID_TOKEN: &str = "publish-oidc-id-token";
const OIDC_NPM_TOKEN: &str = "publish-oidc-exchanged-token";
const CUSTOM_REGISTRY_TOKEN: &str = "publish-custom-registry-token";
const SIGSTORE_PEM_CERT_LEAF: &str =
    "-----BEGIN CERTIFICATE-----\nYWJj\n-----END CERTIFICATE-----\n";
const SIGSTORE_PEM_CERT_ROOT: &str =
    "-----BEGIN CERTIFICATE-----\nZGVm\n-----END CERTIFICATE-----\n";

fn authored_skills_project(name: &str) -> TempProject {
    let project = TempProject::empty(&format!(
        r#"{{
  "name": "{name}",
  "version": "1.0.0",
  "description": "Publish preparation integrity fixture",
  "main": "index.js",
  "license": "MIT",
  "files": ["index.js"]
}}"#
    ));
    project.write_file("index.js", "module.exports = {}");
    project.write_file(
        ".lpm/skills/usage.md",
        concat!(
            "---\n",
            "name: usage\n",
            "description: Complete package usage guidance\n",
            "---\n",
            "# Usage\n\n",
            "Use this package through its documented public API. This guidance includes ",
            "enough detail for an agent to follow the supported workflow safely.\n",
        ),
    );
    project
}

fn snapshot_project_files(root: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    fn visit(root: &Path, dir: &Path, snapshot: &mut BTreeMap<PathBuf, Vec<u8>>) {
        let mut entries = std::fs::read_dir(dir)
            .expect("read project directory")
            .collect::<Result<Vec<_>, _>>()
            .expect("read project entries");
        entries.sort_by_key(std::fs::DirEntry::file_name);

        for entry in entries {
            let path = entry.path();
            let file_type = entry.file_type().expect("read project entry type");
            if file_type.is_dir() {
                visit(root, &path, snapshot);
            } else if file_type.is_file() {
                let relative = path
                    .strip_prefix(root)
                    .expect("project entry must remain below root")
                    .to_path_buf();
                snapshot.insert(relative, std::fs::read(path).expect("read project file"));
            }
        }
    }

    let mut snapshot = BTreeMap::new();
    visit(root, root, &mut snapshot);
    snapshot
}

fn unsigned_sigstore_jwt(payload: serde_json::Value) -> String {
    let header_b64 = URL_SAFE_NO_PAD.encode(br#"{"alg":"RS256","typ":"JWT"}"#);
    let payload_b64 =
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).expect("serialize JWT payload"));
    let sig_b64 = URL_SAFE_NO_PAD.encode(b"workflow-test-signature");
    format!("{header_b64}.{payload_b64}.{sig_b64}")
}

async fn mount_sigstore_publish_mocks(server: &MockServer) {
    Mock::given(method("POST"))
        .and(path("/api/v2/signingCert"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(
            format!("{SIGSTORE_PEM_CERT_LEAF}{SIGSTORE_PEM_CERT_ROOT}").into_bytes(),
            "application/pem-certificate-chain",
        ))
        .expect(1)
        .mount(server)
        .await;

    Mock::given(method("POST"))
        .and(path("/api/v1/log/entries"))
        .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
            "uuid": {
                "logIndex": 123,
                "integratedTime": 1700000000_i64,
                "logID": "workflow-test-log",
                "body": BASE64.encode(b"workflow-test-canonicalized-body"),
                "verification": {
                    "inclusionPromise": {
                        "signedEntryTimestamp": BASE64.encode(b"workflow-test-set")
                    },
                    "inclusionProof": {
                        "checkpoint": "rekor.sigstore.dev - 1\n124\nabc=\n\n",
                        "hashes": ["aa", "bb"],
                        "logIndex": 123,
                        "rootHash": "rootabc",
                        "treeSize": 124
                    }
                }
            }
        })))
        .expect(1)
        .mount(server)
        .await;
}

// ─── Dry Run ─────────────────────────────────────────────────────

#[test]
fn publish_dry_run_validates_package() {
    let project = TempProject::empty(
        r#"{
        "name": "@lpm.dev/testuser.test-pkg",
        "version": "1.0.0",
        "description": "A test package for workflow tests",
        "main": "index.js",
        "license": "MIT"
    }"#,
    );

    // Create a minimal source file
    project.write_file("index.js", "module.exports = {}");

    let output = lpm(&project)
        .args(["publish", "--dry-run", "--yes"])
        .output()
        .expect("failed to run lpm publish --dry-run");

    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    // Dry run may succeed or fail (no auth), but should show package info
    assert!(
        combined.contains("test-pkg") || combined.contains("dry") || combined.contains("preview"),
        "expected package info or dry-run indicator in output, got:\n{combined}"
    );
}

#[tokio::test]
async fn publish_dry_run_with_authored_skills_leaves_project_files_unchanged() {
    let mock = MockRegistry::start().await;
    let project = authored_skills_project("@lpm.dev/testuser.read-only-dry-run");
    let before = snapshot_project_files(project.path());

    let output = lpm_with_registry(&project, &mock.url())
        .args(["--json", "publish", "--dry-run", "--yes", "--lpm"])
        .output()
        .expect("run publish dry-run with authored skills");

    assert!(
        output.status.success(),
        "publish dry-run must succeed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    assert_eq!(
        snapshot_project_files(project.path()),
        before,
        "publish dry-run must not modify project files"
    );
    let json = parse_json_output(&output.stdout);
    assert_eq!(
        json["files"],
        serde_json::json!(3),
        "prepared file manifest must contain package.json, index.js, and the authored skill"
    );
}

#[test]
fn publish_check_with_authored_skills_leaves_project_files_unchanged() {
    let project = authored_skills_project("@lpm.dev/testuser.read-only-check");
    let before = snapshot_project_files(project.path());

    let output = lpm(&project)
        .args(["--json", "publish", "--check", "--lpm"])
        .output()
        .expect("run publish check with authored skills");

    assert!(
        output.status.success(),
        "publish check must succeed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    assert_eq!(
        snapshot_project_files(project.path()),
        before,
        "publish check must not modify project files"
    );
}

// ─── Missing package.json ────────────────────────────────────────

#[test]
fn publish_without_package_json_fails() {
    let dir = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();

    let mut cmd = assert_cmd::Command::cargo_bin("lpm-rs").unwrap();
    cmd.current_dir(dir.path());
    cmd.env("HOME", home.path());
    cmd.env("LPM_HOME", home.path().join(".lpm"));
    cmd.env("NO_COLOR", "1");
    cmd.env("LPM_NO_UPDATE_CHECK", "1");
    cmd.env("LPM_DISABLE_TELEMETRY", "1");
    cmd.env("LPM_FORCE_FILE_AUTH", "1");
    cmd.env("LPM_TEST_FAST_SCRYPT", "1");
    cmd.env("LPM_FORCE_FILE_VAULT", "1");
    cmd.env("LPM_DISABLE_HOST_CLI_AUTH", "1");
    cmd.env(
        "LPM_SECURITY_POLICY_PATH",
        home.path().join(".lpm/security-policy.toml"),
    );
    cmd.env_remove("LPM_TOKEN");

    let output = cmd
        .args(["publish", "--dry-run", "--yes"])
        .output()
        .expect("failed to run lpm publish");

    assert!(!output.status.success());

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("package.json") || stderr.contains("not found"),
        "expected error about missing package.json, got:\n{stderr}"
    );
}

#[test]
fn publish_secret_scan_human_failure_uses_stderr_only() {
    let project = TempProject::empty(
        r#"{
        "name": "@lpm.dev/testuser.secret-pkg",
        "version": "1.0.0",
        "description": "Contains a secret fixture",
        "main": "index.js",
        "license": "MIT"
    }"#,
    );
    project.write_file(
        "index.js",
        r#"const password = "not-a-real-secret-fixture";"#,
    );

    let output = lpm(&project)
        .args(["publish", "--dry-run", "--yes", "--lpm"])
        .output()
        .expect("failed to run lpm publish");

    assert!(!output.status.success(), "secret scan must block publish");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        stdout.trim().is_empty(),
        "human secret-scan failure must not write to stdout, got:\n{stdout}"
    );
    assert!(
        stderr.contains("! Secret scan found")
            && stderr.contains("✗ Publish blocked. Remove secrets before publishing.")
            && stderr.contains("hint If these are false positives, use --allow-secrets."),
        "expected slim stderr secret-scan failure, got:\n{stderr}"
    );
    assert!(
        !stderr.contains("Registry error") && !stderr.contains("Error:"),
        "command-owned failure should not be followed by framework diagnostics:\n{stderr}"
    );
}

#[test]
fn publish_secret_scan_json_failure_emits_single_envelope() {
    let project = TempProject::empty(
        r#"{
        "name": "@lpm.dev/testuser.secret-json-pkg",
        "version": "1.0.0",
        "description": "Contains a secret fixture",
        "main": "index.js",
        "license": "MIT"
    }"#,
    );
    project.write_file(
        "index.js",
        r#"const password = "not-a-real-json-secret-fixture";"#,
    );

    let output = lpm(&project)
        .args(["--json", "publish", "--dry-run", "--yes", "--lpm"])
        .output()
        .expect("failed to run lpm publish --json");

    assert!(!output.status.success(), "secret scan must block publish");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let json: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("stdout should be one JSON object");

    assert_eq!(json["success"], serde_json::json!(false));
    assert_eq!(json["error"], "secret_scan_failed");
    assert_eq!(json["matches"][0]["pattern"], "generic_password");
    assert!(
        stderr.trim().is_empty(),
        "JSON secret-scan failure must not add human diagnostics, got:\n{stderr}"
    );
}

#[test]
fn publish_blocks_gitignored_secret_when_files_explicitly_selects_it() {
    let project = TempProject::empty(
        r#"{
  "name": "selected-gitignored-secret",
  "version": "1.0.0",
  "files": ["ignored-secret.js"]
}"#,
    );
    std::fs::create_dir(project.path().join(".git")).expect("create git metadata directory");
    project.write_file(".gitignore", "ignored-secret.js\n");
    project.write_file(
        "ignored-secret.js",
        r#"const password = "not-a-real-selected-secret";"#,
    );

    let output = lpm(&project)
        .args(["publish", "--dry-run", "--yes", "--npm"])
        .output()
        .expect("run publish with selected gitignored secret");

    assert!(
        !output.status.success(),
        "selected secret must block publish"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("ignored-secret.js") && stderr.contains("generic_password"),
        "secret result must preserve the selected path and pattern:\n{stderr}"
    );
}

#[test]
fn publish_ignores_secret_outside_final_tarball_file_set() {
    let project = TempProject::empty(
        r#"{
  "name": "unselected-secret",
  "version": "1.0.0",
  "files": ["index.js"]
}"#,
    );
    project.write_file("index.js", "module.exports = {}");
    project.write_file(
        "not-published.js",
        r#"const password = "not-a-real-unselected-secret";"#,
    );

    let output = lpm(&project)
        .args(["publish", "--dry-run", "--yes", "--npm"])
        .output()
        .expect("run publish with an unselected secret");

    assert!(
        output.status.success(),
        "a secret outside the tarball must not block publish\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

#[test]
fn publish_blocks_gitignored_blocked_filename_when_files_selects_it() {
    let project = TempProject::empty(
        r#"{
  "name": "selected-blocked-filename",
  "version": "1.0.0",
  "files": ["credentials.json"]
}"#,
    );
    std::fs::create_dir(project.path().join(".git")).expect("create git metadata directory");
    project.write_file(".gitignore", "credentials.json\n");
    project.write_file("credentials.json", "{}");

    let output = lpm(&project)
        .args(["publish", "--dry-run", "--yes", "--npm"])
        .output()
        .expect("run publish with selected blocked filename");

    assert!(
        !output.status.success(),
        "a selected blocked filename must block publish"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("credentials.json") && stderr.contains("blocked_file"),
        "blocked-file result must preserve the selected path and pattern:\n{stderr}"
    );
}

#[test]
fn publish_allow_secrets_bypasses_selected_file_scan() {
    let project = TempProject::empty(
        r#"{
  "name": "allow-selected-secret",
  "version": "1.0.0",
  "files": ["index.js"]
}"#,
    );
    project.write_file(
        "index.js",
        r#"const password = "not-a-real-allowed-secret";"#,
    );

    let output = lpm(&project)
        .args(["publish", "--dry-run", "--yes", "--npm", "--allow-secrets"])
        .output()
        .expect("run publish with allow-secrets");

    assert!(
        output.status.success(),
        "--allow-secrets must retain its bypass behavior\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

#[test]
fn publish_scans_manifest_bytes_after_lpm_target_name_rewrite() {
    let project = TempProject::empty(
        r#"{
  "name": "source-package",
  "version": "1.0.0",
  "description": "sk_liv\u0065_FAKEFAKEFAKEFAKEFAKE",
  "files": ["index.js"]
}"#,
    );
    project.write_file("index.js", "module.exports = {}");
    project.write_file(
        "lpm.json",
        r#"{"publish":{"lpm":{"name":"@lpm.dev/testuser.rewritten-secret"}}}"#,
    );

    let output = lpm(&project)
        .args(["publish", "--dry-run", "--yes", "--lpm"])
        .output()
        .expect("run publish with target-specific name rewrite");

    assert!(
        !output.status.success(),
        "a secret materialized by the final manifest rewrite must block publish\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("stripe_live_secret"),
        "the final rewritten manifest secret must be reported:\n{stderr}"
    );
}

#[test]
fn publish_scans_manifest_bytes_after_npm_target_name_rewrite() {
    let project = TempProject::empty(
        r#"{
  "name": "source-package",
  "version": "1.0.0",
  "description": "sk_liv\u0065_FAKEFAKEFAKEFAKEFAKE",
  "files": ["index.js"]
}"#,
    );
    project.write_file("index.js", "module.exports = {}");
    project.write_file(
        "lpm.json",
        r#"{"publish":{"npm":{"name":"renamed-package"}}}"#,
    );

    let output = lpm(&project)
        .args(["publish", "--dry-run", "--yes", "--npm"])
        .output()
        .expect("run npm publish with target-specific name rewrite");

    assert!(
        !output.status.success(),
        "a secret materialized by the final npm manifest rewrite must block publish\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("stripe_live_secret"),
        "the final npm manifest secret must be reported:\n{stderr}"
    );
}

#[test]
fn publish_scans_selected_javascript_larger_than_two_mib() {
    let project = TempProject::empty(
        r#"{
  "name": "large-selected-secret",
  "version": "1.0.0",
  "files": ["bundle.js"]
}"#,
    );
    let mut bundle = "x".repeat(2 * 1024 * 1024);
    bundle.push_str("\nconst token = \"");
    bundle.push_str("sk_live_");
    bundle.push_str("FAKEFAKEFAKEFAKEFAKE\";\n");
    project.write_file("bundle.js", &bundle);

    let output = lpm(&project)
        .args(["publish", "--dry-run", "--yes", "--npm"])
        .output()
        .expect("run publish with a large selected JavaScript bundle");

    assert!(
        !output.status.success(),
        "a selected scannable file larger than 2 MiB must not bypass the publish scan\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("bundle.js") && stderr.contains("stripe_live_secret"),
        "the large selected file and secret must be reported:\n{stderr}"
    );
}

#[test]
fn publish_check_help_describes_local_preparation_and_validation() {
    let project = TempProject::empty(r#"{"name":"help-contract","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args(["publish", "--help"])
        .output()
        .expect("run publish help");

    assert!(output.status.success(), "publish help must succeed");
    let help = String::from_utf8_lossy(&output.stdout)
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    assert!(
        help.contains(
            "Prepare and validate locally without publishing: pack files, validate skills and \
             provenance files, run quality checks, and scan for secrets"
        ),
        "publish --check help must describe its local validation contract:\n{help}"
    );
    assert!(
        !help.contains("Only show quality report"),
        "publish --check help must not claim it only runs quality checks:\n{help}"
    );
}

// ─── Missing Required Fields ─────────────────────────────────────

#[test]
fn publish_without_name_fails() {
    let project = TempProject::empty(
        r#"{
        "version": "1.0.0",
        "description": "No name field"
    }"#,
    );

    project.write_file("index.js", "module.exports = {}");

    let output = lpm(&project)
        .args(["publish", "--dry-run", "--yes"])
        .output()
        .expect("failed to run lpm publish");

    assert!(
        !output.status.success(),
        "publish should fail without a name field"
    );
}

// ─── Publish Target Flags ────────────────────────────────────────

#[test]
fn publish_accepts_target_flags() {
    let project = TempProject::empty(
        r#"{
        "name": "@lpm.dev/testuser.flag-test",
        "version": "1.0.0",
        "description": "Testing target flags",
        "main": "index.js",
        "license": "MIT"
    }"#,
    );

    project.write_file("index.js", "module.exports = {}");

    // --lpm flag should be accepted (even if it fails for auth reasons)
    let output = lpm(&project)
        .args(["publish", "--dry-run", "--yes", "--lpm"])
        .output()
        .expect("failed to run lpm publish with --lpm");

    // We just verify the flag is accepted (not an "unknown argument" error)
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("unexpected argument") && !stderr.contains("unrecognized"),
        "--lpm flag should be recognized, got:\n{stderr}"
    );
}

// ─── Quality Check Only ──────────────────────────────────────────

#[test]
fn publish_check_mode_shows_quality() {
    let project = TempProject::empty(
        r#"{
        "name": "@lpm.dev/testuser.quality-test",
        "version": "1.0.0",
        "description": "Testing --check mode",
        "main": "index.js",
        "license": "MIT",
        "repository": {
            "type": "git",
            "url": "https://github.com/test/test"
        }
    }"#,
    );

    project.write_file("index.js", "module.exports = {}");
    project.write_file("README.md", "# Quality Test\n\nA test package.");

    let output = lpm(&project)
        .args(["publish", "--check"])
        .output()
        .expect("failed to run lpm publish --check");

    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    // --check should show quality report
    assert!(
        combined.contains("quality") || combined.contains("score") || combined.contains("Quality"),
        "expected quality report in --check output, got:\n{combined}"
    );
}

#[test]
fn publish_check_npm_json_emits_success_object_without_lpm_quality() {
    let project = TempProject::empty(
        r#"{
        "name": "npm-check-json-pkg",
        "version": "1.0.0",
        "description": "npm-only check JSON should stay object-shaped",
        "main": "index.js",
        "license": "MIT"
    }"#,
    );
    project.write_file("index.js", "module.exports = {}");

    let output = lpm(&project)
        .args(["--json", "publish", "--check", "--npm"])
        .output()
        .expect("failed to run lpm publish --check --npm --json");

    assert!(
        output.status.success(),
        "npm-only publish check must succeed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let envelope: serde_json::Value = serde_json::from_str(&stdout).unwrap_or_else(|e| {
        panic!("publish --check --npm --json must be valid JSON: {e}\n---\n{stdout}")
    });
    let envelope = envelope
        .as_object()
        .unwrap_or_else(|| panic!("publish check JSON must be an object, got: {envelope:#}"));

    assert_eq!(envelope.get("success"), Some(&serde_json::json!(true)));
    assert_eq!(envelope.get("check"), Some(&serde_json::json!(true)));
    assert_eq!(envelope.get("quality"), Some(&serde_json::Value::Null));
}

fn assert_npm_publish_check_rejected(
    package_json: &str,
    lpm_json: Option<&str>,
    expected_error: &str,
) {
    let project = TempProject::empty(package_json);
    project.write_file("index.js", "module.exports = {};");
    if let Some(lpm_json) = lpm_json {
        project.write_file("lpm.json", lpm_json);
    }

    let output = lpm(&project)
        .args(["--json", "publish", "--check", "--npm"])
        .output()
        .expect("run npm publish check with invalid configuration");

    assert!(
        !output.status.success(),
        "invalid npm publish configuration must fail\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let envelope = parse_json_output(&output.stdout);
    let error = envelope["error"]
        .as_str()
        .unwrap_or_else(|| panic!("publish check error must be a string: {envelope:#}"));
    assert!(
        error.contains(expected_error),
        "publish check error must contain {expected_error:?}: {envelope:#}",
    );
}

#[test]
fn publish_check_npm_ignores_unselected_registry_access_config() {
    let project = TempProject::empty(
        r#"{
  "name": "selected-npm-target",
  "version": "1.0.0",
  "main": "index.js"
}"#,
    );
    project.write_file("index.js", "module.exports = {};");
    project.write_file(
        "lpm.json",
        r#"{"publish":{"github":{"access":"stale-value"},"gitlab":{"access":"stale-value"}}}"#,
    );

    let output = lpm(&project)
        .args(["--json", "publish", "--check", "--npm"])
        .output()
        .expect("run npm publish check with unselected registry settings");

    assert!(
        output.status.success(),
        "unselected registry settings must not block explicit npm target\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

#[test]
fn publish_check_rejects_non_loopback_http_gitlab_registry() {
    let project = TempProject::empty(
        r#"{
  "name": "@scope/invalid-gitlab-registry",
  "version": "1.0.0",
  "main": "index.js"
}"#,
    );
    project.write_file("index.js", "module.exports = {};");
    project.write_file(
        "lpm.json",
        r#"{"publish":{"gitlab":{"projectId":"7","registry":"http://gitlab.example.test"}}}"#,
    );

    let output = lpm(&project)
        .args(["--json", "publish", "--check", "--gitlab"])
        .output()
        .expect("run GitLab publish check with an insecure registry");

    assert!(!output.status.success());
    let envelope = parse_json_output(&output.stdout);
    assert!(
        envelope["error"]
            .as_str()
            .is_some_and(|error| error.contains("publish.gitlab.registry")),
        "GitLab registry error must identify the invalid setting: {envelope:#}",
    );
}

#[test]
fn publish_check_rejects_blank_gitlab_project_id() {
    let project = TempProject::empty(
        r#"{
  "name": "@scope/blank-gitlab-project",
  "version": "1.0.0",
  "main": "index.js"
}"#,
    );
    project.write_file("index.js", "module.exports = {};");
    project.write_file("lpm.json", r#"{"publish":{"gitlab":{"projectId":"   "}}}"#);

    let output = lpm(&project)
        .args(["--json", "publish", "--check", "--gitlab"])
        .output()
        .expect("run GitLab publish check with a blank project ID");

    assert!(!output.status.success());
    let envelope = parse_json_output(&output.stdout);
    assert!(
        envelope["error"]
            .as_str()
            .is_some_and(|error| error.contains("projectId")),
        "GitLab project ID error must identify the invalid setting: {envelope:#}",
    );
}

#[test]
fn publish_check_rejects_invalid_package_version() {
    assert_npm_publish_check_rejected(
        r#"{
  "name": "invalid-version-pkg",
  "version": "latest",
  "main": "index.js"
}"#,
        None,
        "semantic version",
    );
}

#[test]
fn publish_check_rejects_noncanonical_package_versions() {
    for version in ["v1.2.3", "01.2.3", "1.2.3-alpha.01"] {
        assert_npm_publish_check_rejected(
            &format!(
                r#"{{
  "name": "noncanonical-version-pkg",
  "version": "{version}",
  "main": "index.js"
}}"#
            ),
            None,
            "semantic version",
        );
    }
}

#[test]
fn publish_check_accepts_leading_zeroes_in_build_metadata() {
    let project = TempProject::empty(
        r#"{
  "name": "canonical-build-metadata",
  "version": "1.2.3+001",
  "main": "index.js"
}"#,
    );
    project.write_file("index.js", "module.exports = {};");

    let output = lpm(&project)
        .args(["--json", "publish", "--check", "--npm"])
        .output()
        .expect("run publish check with canonical build metadata");

    assert!(output.status.success(), "{output:?}");
}

#[test]
fn publish_check_rejects_private_package() {
    assert_npm_publish_check_rejected(
        r#"{
  "name": "private-package",
  "version": "1.0.0",
  "private": true,
  "main": "index.js"
}"#,
        None,
        "marked as private",
    );
}

#[test]
fn publish_check_rejects_restricted_unscoped_npm_package() {
    assert_npm_publish_check_rejected(
        r#"{
  "name": "unscoped-restricted-package",
  "version": "1.0.0",
  "main": "index.js"
}"#,
        Some(r#"{"publish":{"npm":{"access":"restricted"}}}"#),
        "unscoped",
    );
}

#[test]
fn publish_check_requires_explicit_tag_for_prerelease() {
    assert_npm_publish_check_rejected(
        r#"{
  "name": "implicit-prerelease-tag",
  "version": "1.0.0-beta.1",
  "main": "index.js"
}"#,
        None,
        "explicit publish.npm.tag",
    );
}

#[test]
fn publish_check_accepts_explicit_tag_for_prerelease() {
    let project = TempProject::empty(
        r#"{
  "name": "explicit-prerelease-tag",
  "version": "1.0.0-beta.1",
  "main": "index.js"
}"#,
    );
    project.write_file("index.js", "module.exports = {};");
    project.write_file("lpm.json", r#"{"publish":{"npm":{"tag":"beta"}}}"#);

    let output = lpm(&project)
        .args(["--json", "publish", "--check", "--npm"])
        .output()
        .expect("run prerelease publish check with an explicit tag");

    assert!(output.status.success(), "{output:?}");
}

#[test]
fn publish_check_github_ignores_overridden_npm_name_and_access() {
    let project = TempProject::empty(
        r#"{
  "name": "github-overrides-npm-fallbacks",
  "version": "1.0.0",
  "main": "index.js"
}"#,
    );
    project.write_file("index.js", "module.exports = {};");
    project.write_file(
        "lpm.json",
        r#"{"publish":{"npm":{"name":"@/stale","access":"stale","tag":"next"},"github":{"name":"@scope/pkg","access":"public"}}}"#,
    );

    let output = lpm(&project)
        .args(["--json", "publish", "--check", "--github"])
        .output()
        .expect("run GitHub publish check with overridden npm fallbacks");

    assert!(output.status.success(), "{output:?}");
}

#[test]
fn publish_check_rejects_invalid_configured_npm_name() {
    assert_npm_publish_check_rejected(
        r#"{
  "name": "valid-package-name",
  "version": "1.0.0",
  "main": "index.js"
}"#,
        Some(r#"{"publish":{"npm":{"name":"@/pkg"}}}"#),
        "npm package scope cannot be empty",
    );
}

#[test]
fn publish_check_rejects_invalid_npm_access() {
    assert_npm_publish_check_rejected(
        r#"{
  "name": "invalid-access-pkg",
  "version": "1.0.0",
  "main": "index.js"
}"#,
        Some(r#"{"publish":{"npm":{"access":"private"}}}"#),
        "publish.npm.access",
    );
}

#[test]
fn publish_check_rejects_semver_shaped_npm_tag() {
    assert_npm_publish_check_rejected(
        r#"{
  "name": "invalid-tag-pkg",
  "version": "1.0.0",
  "main": "index.js"
}"#,
        Some(r#"{"publish":{"npm":{"tag":"1.2.3"}}}"#),
        "publish.npm.tag",
    );
}

#[test]
fn publish_check_rejects_non_loopback_http_npm_registry() {
    assert_npm_publish_check_rejected(
        r#"{
  "name": "invalid-registry-pkg",
  "version": "1.0.0",
  "main": "index.js"
}"#,
        Some(r#"{"publish":{"npm":{"registry":"http://packages.example.test/npm"}}}"#),
        "publish.npm.registry",
    );
}

#[test]
fn publish_check_rejects_invalid_lpm_package_identity() {
    let project = TempProject::empty(
        r#"{
  "name": "@lpm.dev/owner.",
  "version": "1.0.0",
  "main": "index.js"
}"#,
    );
    project.write_file("index.js", "module.exports = {};");

    let output = lpm(&project)
        .args(["--json", "publish", "--check", "--lpm"])
        .output()
        .expect("run LPM publish check with an invalid package identity");

    assert!(!output.status.success());
    let envelope = parse_json_output(&output.stdout);
    assert!(
        envelope["error"]
            .as_str()
            .is_some_and(|error| error.contains("invalid package name")),
        "publish check must reject the invalid LPM identity: {envelope:#}",
    );
}

// ─── Mock Registry Publish ───────────────────────────────────────

#[tokio::test]
async fn publish_to_mock_registry_succeeds() {
    let mock = MockRegistry::start().await;
    mock.with_publish_endpoint().await;
    // The publish flow also calls whoami to verify auth
    mock.with_whoami("testuser", "test@example.com").await;

    let project = TempProject::empty(
        r#"{
        "name": "@lpm.dev/testuser.mock-publish",
        "version": "1.0.0",
        "description": "A test package for mock publish",
        "main": "index.js",
        "license": "MIT"
    }"#,
    );

    project.write_file("index.js", "module.exports = { hello: 'world' }");
    project.write_file("README.md", "# Mock Publish Test\n\nA package.");

    let output = lpm_with_registry(&project, &mock.url())
        .args(["publish", "--yes", "--token", "test-token-123", "--lpm"])
        .output()
        .expect("failed to run lpm publish");

    assert!(
        output.status.success(),
        "mock publish should succeed when the registry accepts the upload\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    let combined = format!("{stdout}{stderr}");
    assert!(
        combined.contains("Done · published @lpm.dev/testuser.mock-publish@1.0.0"),
        "expected publish success output, got:\n{combined}"
    );
    assert!(
        combined.contains("✓ Secret scan passed")
            && combined.contains("✓ Quality score:")
            && combined.contains("› Uploading tarball to lpm.dev")
            && combined.contains("target     @lpm.dev/testuser.mock-publish@1.0.0"),
        "publish human output should use the slim contract, got:\n{combined}"
    );
    assert!(
        !combined.contains("Packing tarball")
            && !combined.contains("Publishing as")
            && !combined.contains("Uploading..."),
        "publish human output should not include old chatter, got:\n{combined}"
    );
}

#[tokio::test]
async fn publish_wait_json_reports_upload_and_active_publication_states() {
    const PACKAGE_NAME: &str = "@lpm.dev/testuser.wait-json";
    const VERSION: &str = "1.0.0";
    let mock = MockRegistry::start().await;
    mock.with_whoami("testuser", "test@example.com").await;
    Mock::given(method("PUT"))
        .and(path_regex("/api/registry/.*"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "success": true,
            "publicationStatus": "pending_review",
            "currentLatestVersion": "0.9.0",
        })))
        .expect(1)
        .mount(mock.server())
        .await;
    Mock::given(method("GET"))
        .and(path("/api/registry/-/package/publication-status"))
        .and(query_param("name", PACKAGE_NAME))
        .and(query_param("version", VERSION))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "name": PACKAGE_NAME,
            "version": VERSION,
            "status": "active",
            "reviewStatus": "approved",
            "currentLatestVersion": VERSION,
        })))
        .expect(1)
        .mount(mock.server())
        .await;

    let project = TempProject::empty(&format!(
        r#"{{
		"name": "{PACKAGE_NAME}",
		"version": "{VERSION}",
		"description": "Publication wait JSON contract fixture",
		"main": "index.js",
		"license": "MIT"
	}}"#,
    ));
    project.write_file("index.js", "module.exports = {};");

    let output = lpm_with_registry(&project, &mock.url())
        .args([
            "--json",
            "publish",
            "--yes",
            "--token",
            "test-token-123",
            "--lpm",
            "--wait",
        ])
        .output()
        .expect("run lpm publish --wait --json");

    assert!(
        output.status.success(),
        "publication wait must succeed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let mut json = parse_json_output(&output.stdout);
    json["results"][0]["duration_ms"] = serde_json::json!(0);
    insta::assert_json_snapshot!(json, @r###"
    {
      "success": true,
      "results": [
        {
          "registry": "lpm",
          "success": true,
          "error": null,
          "publication_status": "active",
          "current_latest_version": "1.0.0",
          "publication_wait": {
            "success": true,
            "status": "active",
            "current_latest_version": "1.0.0",
            "error": null
          },
          "duration_ms": 0
        }
      ]
    }
    "###);
}

#[tokio::test]
async fn publish_json_fails_when_upload_response_reports_rejected_publication() {
    const PACKAGE_NAME: &str = "@lpm.dev/testuser.rejected-json";
    let mock = MockRegistry::start().await;
    mock.with_whoami("testuser", "test@example.com").await;
    Mock::given(method("PUT"))
        .and(path_regex("/api/registry/.*"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "success": true,
            "publicationStatus": "rejected",
            "currentLatestVersion": "0.9.0",
        })))
        .expect(1)
        .mount(mock.server())
        .await;

    let project = TempProject::empty(&format!(
        r#"{{
  "name": "{PACKAGE_NAME}",
  "version": "1.0.0",
  "description": "Rejected publication JSON contract fixture",
  "main": "index.js",
  "license": "MIT"
}}"#,
    ));
    project.write_file("index.js", "module.exports = {};");

    let output = lpm_with_registry(&project, &mock.url())
        .args([
            "--json",
            "publish",
            "--yes",
            "--token",
            "test-token-123",
            "--lpm",
        ])
        .output()
        .expect("run lpm publish --json for a rejected publication");

    assert!(
        !output.status.success(),
        "a known rejected publication must fail the command"
    );
    let mut json = parse_json_output(&output.stdout);
    json["results"][0]["duration_ms"] = serde_json::json!(0);
    insta::assert_json_snapshot!(json, @r###"
    {
      "success": false,
      "results": [
        {
          "registry": "lpm",
          "success": true,
          "error": null,
          "publication_status": "rejected",
          "current_latest_version": "0.9.0",
          "duration_ms": 0
        }
      ]
    }
    "###);
}

#[tokio::test]
async fn publish_wait_does_not_poll_after_upload_reports_terminal_rejection() {
    const PACKAGE_NAME: &str = "@lpm.dev/testuser.rejected-wait";
    let mock = MockRegistry::start().await;
    mock.with_whoami("testuser", "test@example.com").await;
    Mock::given(method("PUT"))
        .and(path_regex("/api/registry/.*"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "success": true,
            "publicationStatus": "rejected",
            "currentLatestVersion": "0.9.0",
        })))
        .expect(1)
        .mount(mock.server())
        .await;

    let project = TempProject::empty(&format!(
        r#"{{
  "name": "{PACKAGE_NAME}",
  "version": "1.0.0",
  "description": "Rejected publication wait fixture",
  "main": "index.js",
  "license": "MIT"
}}"#,
    ));
    project.write_file("index.js", "module.exports = {};");

    let output = lpm_with_registry(&project, &mock.url())
        .args([
            "publish",
            "--yes",
            "--token",
            "test-token-123",
            "--lpm",
            "--wait",
        ])
        .output()
        .expect("run lpm publish --wait for a rejected publication");

    assert!(
        !output.status.success(),
        "a known rejected publication must fail without polling"
    );
    let status_requests = mock
        .server()
        .received_requests()
        .await
        .unwrap()
        .into_iter()
        .filter(|request| request.url.path() == "/api/registry/-/package/publication-status")
        .count();
    assert_eq!(status_requests, 0);
}

#[tokio::test]
async fn publish_wait_accepts_an_authoritative_active_upload_without_polling() {
    const PACKAGE_NAME: &str = "@lpm.dev/testuser.wait-already-active";
    const VERSION: &str = "1.0.0";
    let mock = MockRegistry::start().await;
    mock.with_whoami("testuser", "test@example.com").await;
    Mock::given(method("PUT"))
        .and(path_regex("/api/registry/.*"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "success": true,
            "publicationStatus": "active",
            "currentLatestVersion": VERSION,
        })))
        .expect(1)
        .mount(mock.server())
        .await;

    let project = TempProject::empty(&format!(
        r#"{{
  "name": "{PACKAGE_NAME}",
  "version": "{VERSION}",
  "description": "Already-active publication wait fixture",
  "main": "index.js",
  "license": "MIT"
}}"#,
    ));
    project.write_file("index.js", "module.exports = {};");

    let output = lpm_with_registry(&project, &mock.url())
        .args([
            "publish",
            "--yes",
            "--token",
            "test-token-123",
            "--lpm",
            "--wait",
        ])
        .output()
        .expect("run lpm publish --wait for an already-active version");

    assert!(
        output.status.success(),
        "an authoritative active upload must satisfy --wait\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let status_requests = mock
        .server()
        .received_requests()
        .await
        .unwrap()
        .into_iter()
        .filter(|request| request.url.path() == "/api/registry/-/package/publication-status")
        .count();
    assert_eq!(status_requests, 0);
}

#[tokio::test]
async fn publish_wait_failure_keeps_retry_guidance_for_other_failed_targets() {
    const PACKAGE_NAME: &str = "@lpm.dev/testuser.wait-with-github-failure";
    let mock = MockRegistry::start().await;
    mock.with_whoami("testuser", "test@example.com").await;
    Mock::given(method("PUT"))
        .and(path_regex("/api/registry/.*"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "success": true,
            "publicationStatus": "pending_review",
            "currentLatestVersion": null,
        })))
        .expect(1)
        .mount(mock.server())
        .await;
    Mock::given(method("GET"))
        .and(path("/api/registry/-/package/publication-status"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "name": PACKAGE_NAME,
            "version": "1.0.0",
            "status": "rejected",
            "reviewStatus": "rejected",
            "currentLatestVersion": null,
        })))
        .expect(1)
        .mount(mock.server())
        .await;
    let project = TempProject::empty(&format!(
        r#"{{
  "name": "{PACKAGE_NAME}",
  "version": "1.0.0",
  "description": "Combined publication and target failure fixture",
  "main": "index.js",
  "license": "MIT"
}}"#,
    ));
    project.write_file("index.js", "module.exports = {};");
    project.write_file(
        "lpm.json",
        r#"{"publish":{"github":{"name":"@testuser/wait-with-github-failure"}}}"#,
    );

    let output = lpm_with_registry(&project, &mock.url())
        .args([
            "publish",
            "--yes",
            "--token",
            "test-token-123",
            "--lpm",
            "--github",
            "--wait",
        ])
        .output()
        .expect("run publish with a failed wait and failed GitHub target");
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    assert!(
        !output.status.success(),
        "combined failures must fail the command"
    );
    assert!(
        combined.contains("Retry: lpm publish --github"),
        "the independently failed GitHub upload needs scoped retry guidance:\n{combined}",
    );
    assert!(
        !combined.contains("Retry: lpm publish --lpm"),
        "the successfully uploaded immutable LPM version must not be republished:\n{combined}",
    );
}

#[tokio::test]
async fn lpm_name_override_is_used_for_the_uploaded_route_and_payload() {
    const RESOLVED_NAME: &str = "@lpm.dev/testuser.resolved-upload";
    let mock = MockRegistry::start().await;
    mock.with_whoami("testuser", "test@example.com").await;
    Mock::given(method("PUT"))
        .and(path_regex("/api/registry/.*"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "success": true,
            "message": "Package published"
        })))
        .expect(1)
        .mount(mock.server())
        .await;
    let project = TempProject::empty(
        r#"{
        "name": "source-package",
        "version": "1.0.0",
        "description": "A package with a resolved LPM.dev publication name",
        "main": "index.js",
        "license": "MIT"
    }"#,
    );
    project.write_file("index.js", "module.exports = {}");
    project.write_file(
        "lpm.json",
        &format!(r#"{{"publish":{{"lpm":{{"name":"{RESOLVED_NAME}"}}}}}}"#),
    );

    let output = lpm_with_registry(&project, &mock.url())
        .args(["publish", "--yes", "--token", "test-token-123", "--lpm"])
        .output()
        .expect("publish with a resolved LPM.dev name");

    assert!(
        output.status.success(),
        "resolved-name publish failed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let requests = mock.server().received_requests().await.unwrap();
    let upload = requests
        .iter()
        .find(|request| request.method.as_str() == "PUT")
        .expect("publish must send one Registry PUT");
    assert_eq!(
        upload.url.path(),
        "/api/registry/%40lpm.dev%2Ftestuser.resolved-upload"
    );
    let payload: serde_json::Value = serde_json::from_slice(&upload.body).unwrap();
    assert_eq!(payload["_id"], RESOLVED_NAME);
    assert_eq!(payload["name"], RESOLVED_NAME);
}

#[tokio::test]
async fn real_publish_with_authored_skills_persists_effective_manifest_and_notice() {
    let mock = MockRegistry::start().await;
    mock.with_publish_endpoint().await;
    mock.with_whoami("testuser", "test@example.com").await;
    let project = authored_skills_project("@lpm.dev/testuser.real-skills");

    let output = lpm_with_registry(&project, &mock.url())
        .args(["publish", "--yes", "--token", "test-token-123", "--lpm"])
        .output()
        .expect("run real publish with authored skills");

    assert!(
        output.status.success(),
        "real publish must succeed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let package_json: serde_json::Value =
        serde_json::from_str(&project.read_file("package.json")).expect("parse package.json");
    assert_eq!(
        package_json["files"],
        serde_json::json!(["index.js", ".lpm/skills"])
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    assert!(
        combined.contains(
            "Added \".lpm/skills\" to package.json \"files\" — skills would be excluded otherwise"
        ),
        "real publish must retain the manifest update notice:\n{combined}"
    );
}

#[tokio::test]
async fn publish_rewrites_catalog_dependency_in_uploaded_tarball() {
    use base64::Engine;

    let mock = MockRegistry::start().await;
    mock.with_publish_endpoint().await;
    mock.with_whoami("testuser", "test@example.com").await;

    let project = TempProject::empty(
        r#"{
        "name": "catalog-publish-workspace",
        "version": "1.0.0",
        "private": true
    }"#,
    );

    project.write_file(
        "pnpm-workspace.yaml",
        r#"packages:
  - "packages/*"
catalog:
  ms: ^2.1.3
"#,
    );
    project.write_file(
        "packages/lib/package.json",
        r#"{
        "name": "@lpm.dev/testuser.catalog-publish",
        "version": "1.0.0",
        "description": "Catalog publish rewrite test",
        "main": "index.js",
        "license": "MIT",
        "dependencies": {
            "ms": "catalog:"
        }
    }"#,
    );
    project.write_file("packages/lib/index.js", "module.exports = require(\"ms\")");

    let mut cmd = lpm_with_registry(&project, &mock.url());
    cmd.current_dir(project.path().join("packages/lib"));
    let output = cmd
        .args(["publish", "--yes", "--token", "test-token-123", "--lpm"])
        .output()
        .expect("failed to run lpm publish for catalog workspace member");

    assert!(
        output.status.success(),
        "catalog-backed publish must succeed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let requests = mock
        .server()
        .received_requests()
        .await
        .expect("wiremock request log must be available");
    let publish_request = requests
        .iter()
        .find(|request| request.method.as_str() == "PUT")
        .unwrap_or_else(|| {
            panic!(
                "expected a publish PUT request, got {} request(s)",
                requests.len()
            )
        });

    let payload: serde_json::Value = serde_json::from_slice(&publish_request.body)
        .expect("publish request body must be valid JSON");
    let attachment = payload["_attachments"]
        .as_object()
        .and_then(|attachments| attachments.values().next())
        .unwrap_or_else(|| panic!("publish payload must contain one tarball attachment"));
    let tarball_data = base64::engine::general_purpose::STANDARD
        .decode(
            attachment["data"]
                .as_str()
                .expect("tarball attachment must be base64 text"),
        )
        .expect("tarball attachment must decode from base64");

    let published_package_json = extract_uploaded_package_json(&tarball_data);
    assert_eq!(
        published_package_json["dependencies"]["ms"],
        serde_json::json!("^2.1.3"),
        "published tarball must rewrite catalog: to the workspace catalog range"
    );
    assert!(
        !published_package_json.to_string().contains("catalog:"),
        "published tarball manifest must not leak catalog: references\n{}",
        serde_json::to_string_pretty(&published_package_json)
            .expect("published manifest must serialize")
    );
}

#[tokio::test]
async fn publish_npm_uses_trusted_publishing_token_exchange() {
    let mock = MockRegistry::start().await;
    let package = "oidc-publish-pkg";
    Mock::given(method("POST"))
        .and(path(format!(
            "/-/npm/v1/oidc/token/exchange/package/{package}"
        )))
        .and(header("authorization", format!("Bearer {NPM_ID_TOKEN}")))
        .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
            "token_type": "oidc",
            "token": OIDC_NPM_TOKEN,
        })))
        .mount(mock.server())
        .await;
    Mock::given(method("PUT"))
        .and(path(format!("/{package}")))
        .and(header("authorization", format!("Bearer {OIDC_NPM_TOKEN}")))
        .and(header("npm-command", "publish"))
        .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({})))
        .mount(mock.server())
        .await;

    let project = TempProject::empty(
        r#"{
        "name": "oidc-publish-pkg",
        "version": "1.0.0",
        "description": "npm Trusted Publishing workflow test",
        "main": "index.js",
        "license": "MIT"
    }"#,
    );
    project.write_file("index.js", "module.exports = {}");
    project.write_file(
        "lpm.json",
        &format!(
            r#"{{"publish":{{"npm":{{"registry":"{}","access":"public"}}}}}}"#,
            mock.url()
        ),
    );

    let output = lpm(&project)
        .env("NPM_ID_TOKEN", NPM_ID_TOKEN)
        .args(["--json", "publish", "--npm", "--yes"])
        .output()
        .expect("failed to run lpm publish --npm with npm OIDC");

    assert!(
        output.status.success(),
        "npm publish must succeed with Trusted Publishing\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let envelope: serde_json::Value = serde_json::from_str(stdout.trim())
        .unwrap_or_else(|e| panic!("publish JSON output must be valid JSON: {e}\n---\n{stdout}"));
    assert_eq!(envelope["success"], serde_json::json!(true));
    assert_eq!(envelope["results"][0]["registry"], serde_json::json!("npm"));
    assert_eq!(envelope["results"][0]["auth"], serde_json::json!("oidc"));
}

#[tokio::test]
async fn publish_npm_generated_provenance_attaches_sigstore_bundle_to_registry_put() {
    let mock = MockRegistry::start().await;
    let sigstore = MockServer::start().await;
    mount_sigstore_publish_mocks(&sigstore).await;
    let package = "generated-provenance-pkg";
    let registry_token = "generated-provenance-token";
    Mock::given(method("PUT"))
        .and(path(format!("/{package}")))
        .and(header("authorization", format!("Bearer {registry_token}")))
        .and(header("npm-command", "publish"))
        .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({})))
        .mount(mock.server())
        .await;

    let project = TempProject::empty(&format!(
        r#"{{
        "name": "{package}",
        "version": "1.0.0",
        "description": "generated npm provenance workflow test",
        "main": "index.js",
        "license": "MIT"
    }}"#
    ));
    project.write_file("index.js", "module.exports = {}");
    project.write_file(
        "lpm.json",
        &format!(
            r#"{{"publish":{{"npm":{{"registry":"{}","access":"public"}}}}}}"#,
            mock.url()
        ),
    );

    let login = lpm(&project)
        .args([
            "--json",
            "login",
            "--login-registry",
            &mock.url(),
            "--token",
            registry_token,
        ])
        .output()
        .expect("failed to store custom registry token");
    assert!(
        login.status.success(),
        "custom registry login must succeed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&login.stdout),
        String::from_utf8_lossy(&login.stderr),
    );

    let sigstore_jwt = unsigned_sigstore_jwt(serde_json::json!({
        "iss": "https://gitlab.com",
        "sub": "project_path:owner/repo:ref_type:branch:ref:main",
        "aud": "sigstore"
    }));

    let output = lpm(&project)
        .env("LPM_INTERNAL_TEST_SIGSTORE_FULCIO_URL", sigstore.uri())
        .env("LPM_INTERNAL_TEST_SIGSTORE_REKOR_URL", sigstore.uri())
        .env("SIGSTORE_ID_TOKEN", sigstore_jwt)
        .env("CI", "true")
        .env("GITLAB_CI", "true")
        .env("CI_PROJECT_URL", "https://gitlab.com/owner/repo")
        .env("CI_PROJECT_PATH", "owner/repo")
        .env("CI_COMMIT_SHA", "fedcba9876543210")
        .env("CI_CONFIG_PATH", ".gitlab-ci.yml")
        .env("CI_JOB_ID", "456")
        .env("CI_JOB_NAME", "publish")
        .env("CI_JOB_URL", "https://gitlab.com/owner/repo/-/jobs/456")
        .env("CI_PIPELINE_ID", "123")
        .env("CI_RUNNER_ID", "789")
        .env("CI_RUNNER_DESCRIPTION", "shared-runner")
        .env("CI_RUNNER_EXECUTABLE_ARCH", "linux/amd64")
        .env("CI_SERVER_URL", "https://gitlab.com")
        .args(["--json", "publish", "--npm", "--provenance", "--yes"])
        .output()
        .expect("failed to run lpm publish --npm --provenance");

    assert!(
        output.status.success(),
        "npm publish with generated provenance must succeed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let requests = mock
        .server()
        .received_requests()
        .await
        .expect("wiremock request log must be available");
    let publish_request = requests
        .iter()
        .find(|request| request.method.as_str() == "PUT")
        .unwrap_or_else(|| panic!("expected npm publish PUT request, got {}", requests.len()));
    let payload: serde_json::Value =
        serde_json::from_slice(&publish_request.body).expect("publish payload must be JSON");

    let attachments = payload["_attachments"]
        .as_object()
        .unwrap_or_else(|| panic!("publish payload must include attachments: {payload:#}"));
    let tarball_name = format!("{package}-1.0.0.tgz");
    let tarball_attachment = attachments
        .get(&tarball_name)
        .unwrap_or_else(|| panic!("publish payload must include {tarball_name}: {payload:#}"));
    let tarball_data = BASE64
        .decode(
            tarball_attachment["data"]
                .as_str()
                .expect("tarball attachment must carry base64 data"),
        )
        .expect("tarball attachment data must decode");
    let tarball_sha512 = hex::encode(Sha512::digest(&tarball_data));

    let sigstore_name = format!("{package}-1.0.0.sigstore");
    let sigstore_attachment = attachments
        .get(&sigstore_name)
        .unwrap_or_else(|| panic!("publish payload must include {sigstore_name}: {payload:#}"));
    assert_eq!(
        sigstore_attachment["content_type"],
        "application/vnd.dev.sigstore.bundle+json;version=0.2"
    );
    let bundle: serde_json::Value = serde_json::from_str(
        sigstore_attachment["data"]
            .as_str()
            .expect("sigstore attachment must carry bundle JSON"),
    )
    .expect("sigstore attachment data must parse as JSON");
    let statement_bytes = BASE64
        .decode(
            bundle["dsseEnvelope"]["payload"]
                .as_str()
                .expect("DSSE envelope must carry a payload"),
        )
        .expect("DSSE payload must decode");
    let statement: serde_json::Value =
        serde_json::from_slice(&statement_bytes).expect("DSSE payload must be JSON");

    assert_eq!(
        bundle["dsseEnvelope"]["payloadType"],
        "application/vnd.in-toto+json"
    );
    assert_eq!(
        statement["subject"][0]["name"],
        format!("pkg:npm/{package}@1.0.0")
    );
    assert_eq!(statement["subject"][0]["digest"]["sha512"], tarball_sha512);
    assert_eq!(
        bundle["verificationMaterial"]["tlogEntries"][0]["logIndex"],
        "123"
    );
    assert_eq!(
        payload["versions"]["1.0.0"]["_npmProvenanceAttestations"]["dsseEnvelope"]["payload"],
        bundle["dsseEnvelope"]["payload"]
    );
}

#[tokio::test]
async fn publish_npm_repo_configured_custom_registry_uses_registry_scoped_token() {
    let mock = MockRegistry::start().await;
    let package = "repo-custom-publish-pkg";
    Mock::given(method("PUT"))
        .and(path(format!("/{package}")))
        .and(header(
            "authorization",
            format!("Bearer {CUSTOM_REGISTRY_TOKEN}"),
        ))
        .and(header("npm-command", "publish"))
        .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({})))
        .mount(mock.server())
        .await;

    let project = TempProject::empty(&format!(
        r#"{{
        "name": "{package}",
        "version": "1.0.0",
        "description": "Repo-configured custom npm publish registry",
        "main": "index.js",
        "license": "MIT"
    }}"#
    ));
    project.write_file("index.js", "module.exports = {}");
    project.write_file(
        "lpm.json",
        &format!(r#"{{"publish":{{"npm":{{"registry":"{}"}}}}}}"#, mock.url()),
    );

    let login = lpm(&project)
        .args([
            "--json",
            "login",
            "--login-registry",
            &mock.url(),
            "--token",
            CUSTOM_REGISTRY_TOKEN,
        ])
        .output()
        .expect("failed to store custom registry token");
    assert!(
        login.status.success(),
        "custom registry login must succeed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&login.stdout),
        String::from_utf8_lossy(&login.stderr),
    );

    let output = lpm(&project)
        .env("NPM_TOKEN", "ambient-npm-token")
        .args(["--json", "publish", "--npm", "--yes"])
        .output()
        .expect("failed to run lpm publish --npm with custom registry token");

    assert!(
        output.status.success(),
        "npm publish to repo-configured custom registry must use registry-scoped token\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

#[tokio::test]
async fn publish_npm_repo_configured_custom_registry_refuses_ambient_npm_token() {
    let mock = MockRegistry::start().await;
    let package = "repo-custom-publish-no-scoped-token";
    let project = TempProject::empty(&format!(
        r#"{{
        "name": "{package}",
        "version": "1.0.0",
        "description": "Repo-configured custom npm publish registry",
        "main": "index.js",
        "license": "MIT"
    }}"#
    ));
    project.write_file("index.js", "module.exports = {}");
    project.write_file(
        "lpm.json",
        &format!(r#"{{"publish":{{"npm":{{"registry":"{}"}}}}}}"#, mock.url()),
    );

    let output = lpm(&project)
        .env("NPM_TOKEN", "ambient-npm-token")
        .args(["publish", "--npm", "--yes"])
        .output()
        .expect("failed to run lpm publish --npm with ambient token");

    assert!(
        !output.status.success(),
        "repo-configured custom npm registry must reject ambient NPM_TOKEN"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("registry-scoped token") && stderr.contains("lpm login --login-registry"),
        "error must direct the user to scoped custom-registry auth, got:\n{stderr}"
    );
    let requests = mock
        .server()
        .received_requests()
        .await
        .expect("wiremock request log must be available");
    assert!(
        requests.is_empty(),
        "ambient NPM_TOKEN must be rejected before contacting custom registry; got {} request(s)",
        requests.len()
    );
}

#[tokio::test]
async fn publish_npm_json_upload_failure_emits_single_result_document() {
    let mock = MockRegistry::start().await;
    let package = "json-upload-failure-pkg";
    Mock::given(method("PUT"))
        .and(path(format!("/{package}")))
        .and(header(
            "authorization",
            format!("Bearer {CUSTOM_REGISTRY_TOKEN}"),
        ))
        .and(header("npm-command", "publish"))
        .respond_with(ResponseTemplate::new(500).set_body_json(serde_json::json!({
            "error": "server_error",
            "message": "forced publish failure",
        })))
        .mount(mock.server())
        .await;

    let project = TempProject::empty(&format!(
        r#"{{
        "name": "{package}",
        "version": "1.0.0",
        "description": "npm publish JSON upload failure",
        "main": "index.js",
        "license": "MIT"
    }}"#
    ));
    project.write_file("index.js", "module.exports = {}");
    project.write_file(
        "lpm.json",
        &format!(r#"{{"publish":{{"npm":{{"registry":"{}"}}}}}}"#, mock.url()),
    );

    let login = lpm(&project)
        .args([
            "--json",
            "login",
            "--login-registry",
            &mock.url(),
            "--token",
            CUSTOM_REGISTRY_TOKEN,
        ])
        .output()
        .expect("failed to store custom registry token");
    assert!(
        login.status.success(),
        "custom registry login must succeed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&login.stdout),
        String::from_utf8_lossy(&login.stderr),
    );

    let output = lpm(&project)
        .args(["--json", "publish", "--npm", "--yes"])
        .output()
        .expect("failed to run lpm publish --npm --json");

    assert!(
        !output.status.success(),
        "failed npm publish must return a non-zero status"
    );
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr);
    let documents = serde_json::Deserializer::from_str(&stdout)
        .into_iter::<serde_json::Value>()
        .collect::<Result<Vec<_>, _>>()
        .unwrap_or_else(|e| panic!("stdout must contain JSON documents only: {e}\n---\n{stdout}"));
    assert_eq!(
        documents.len(),
        1,
        "publish --json must emit exactly one JSON document on target failure\n{stdout}"
    );

    let envelope = &documents[0];
    assert_eq!(envelope["success"], serde_json::json!(false));
    let results = envelope["results"]
        .as_array()
        .unwrap_or_else(|| panic!("publish JSON results must be an array: {envelope:#}"));
    assert_eq!(results.len(), 1, "expected one npm result: {envelope:#}");
    assert_eq!(results[0]["registry"], serde_json::json!("npm"));
    assert_eq!(results[0]["success"], serde_json::json!(false));
    assert!(
        results[0]["error"]
            .as_str()
            .is_some_and(|error| error.contains("server_error")),
        "target failure should be captured in the result envelope: {envelope:#}"
    );
    assert!(
        !stderr.contains("one or more publish targets failed")
            && !stderr.contains("registry error"),
        "publish --json target failure must not emit a second framework diagnostic, got:\n{stderr}"
    );
}

#[tokio::test]
async fn publish_npm_provenance_restricted_access_fails_before_registry_contact() {
    let mock = MockRegistry::start().await;
    let package = "@scope/restricted-provenance-pkg";
    let project = TempProject::empty(&format!(
        r#"{{
        "name": "{package}",
        "version": "1.0.0",
        "description": "Restricted npm provenance precondition",
        "main": "index.js",
        "license": "MIT"
    }}"#
    ));
    project.write_file("index.js", "module.exports = {}");
    project.write_file(
        "lpm.json",
        &format!(
            r#"{{"publish":{{"npm":{{"registry":"{}","access":"restricted"}}}}}}"#,
            mock.url()
        ),
    );

    let output = lpm(&project)
        .env("NPM_ID_TOKEN", NPM_ID_TOKEN)
        .args(["publish", "--npm", "--provenance", "--yes"])
        .output()
        .expect("failed to run lpm publish --npm --provenance");

    assert!(
        !output.status.success(),
        "restricted npm provenance must fail before publish"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("npm provenance requires public access") && stderr.contains(package),
        "expected public-access provenance error, got:\n{stderr}"
    );
    let requests = mock
        .server()
        .received_requests()
        .await
        .expect("wiremock request log must be available");
    assert!(
        requests.is_empty(),
        "restricted provenance precondition must fail before contacting npm registry; got {} request(s)",
        requests.len()
    );
}

#[test]
fn publish_provenance_file_rejects_lpm_target_before_validation() {
    let project = TempProject::empty(
        r#"{
        "name": "@lpm.dev/testuser.file-provenance",
        "version": "1.0.0",
        "description": "Mixed target provenance-file precondition",
        "main": "index.js",
        "license": "MIT"
    }"#,
    );
    project.write_file("index.js", "module.exports = {}");
    project.write_file(
        "lpm.json",
        r#"{"publish":{"npm":{"name":"@scope/file-provenance"}}}"#,
    );

    let output = lpm(&project)
        .args([
            "publish",
            "--lpm",
            "--npm",
            "--provenance-file",
            "bundle.sigstore",
            "--yes",
        ])
        .output()
        .expect("failed to run lpm publish with mixed targets and provenance file");

    assert!(
        !output.status.success(),
        "provenance-file must reject mixed LPM targets"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("--provenance-file is only supported for npm-compatible publish targets"),
        "expected provenance-file target error, got:\n{stderr}"
    );
    assert!(
        !stderr.contains("Secret scan"),
        "target compatibility must fail before publish validation, got:\n{stderr}"
    );
}

#[tokio::test]
async fn publish_provenance_file_restricted_access_fails_before_file_validation() {
    let mock = MockRegistry::start().await;
    let package = "@scope/restricted-file-provenance-pkg";
    let project = TempProject::empty(&format!(
        r#"{{
        "name": "{package}",
        "version": "1.0.0",
        "description": "Restricted npm file provenance precondition",
        "main": "index.js",
        "license": "MIT"
    }}"#
    ));
    project.write_file("index.js", "module.exports = {}");
    project.write_file(
        "lpm.json",
        &format!(
            r#"{{"publish":{{"npm":{{"registry":"{}","access":"restricted"}}}}}}"#,
            mock.url()
        ),
    );

    let output = lpm(&project)
        .args([
            "publish",
            "--npm",
            "--provenance-file",
            "missing.sigstore",
            "--yes",
        ])
        .output()
        .expect("failed to run lpm publish --npm --provenance-file");

    assert!(
        !output.status.success(),
        "restricted npm file provenance must fail before publish"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("npm provenance requires public access") && stderr.contains(package),
        "expected public-access provenance error, got:\n{stderr}"
    );
    assert!(
        !stderr.contains("missing.sigstore"),
        "restricted access must fail before file validation, got:\n{stderr}"
    );
    let requests = mock
        .server()
        .received_requests()
        .await
        .expect("wiremock request log must be available");
    assert!(
        requests.is_empty(),
        "restricted file-provenance precondition must fail before contacting npm registry; got {} request(s)",
        requests.len()
    );
}

#[tokio::test]
async fn publish_provenance_file_invalid_json_fails_before_npm_auth() {
    let mock = MockRegistry::start().await;
    let package = "invalid-file-provenance-pkg";
    let project = TempProject::empty(&format!(
        r#"{{
        "name": "{package}",
        "version": "1.0.0",
        "description": "Invalid provenance-file preflight",
        "main": "index.js",
        "license": "MIT"
    }}"#
    ));
    project.write_file("index.js", "module.exports = {}");
    project.write_file("bundle.sigstore", "not json");
    project.write_file(
        "lpm.json",
        &format!(r#"{{"publish":{{"npm":{{"registry":"{}"}}}}}}"#, mock.url()),
    );

    let output = lpm(&project)
        .env("NPM_ID_TOKEN", NPM_ID_TOKEN)
        .args([
            "publish",
            "--npm",
            "--provenance-file",
            "bundle.sigstore",
            "--yes",
        ])
        .output()
        .expect("failed to run lpm publish --npm --provenance-file");

    assert!(
        !output.status.success(),
        "invalid provenance file must fail before npm auth"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let combined = format!("{stdout}{stderr}");
    assert!(
        combined.contains("invalid provenance file"),
        "expected provenance file parse error, got:\n{combined}"
    );
    let requests = mock
        .server()
        .received_requests()
        .await
        .expect("wiremock request log must be available");
    assert!(
        requests.is_empty(),
        "invalid provenance file must fail before contacting npm registry; got {} request(s)",
        requests.len()
    );
}

#[tokio::test]
async fn publish_check_provenance_file_invalid_json_fails_before_success() {
    let mock = MockRegistry::start().await;
    let package = "check-invalid-file-provenance-pkg";
    let project = TempProject::empty(&format!(
        r#"{{
        "name": "{package}",
        "version": "1.0.0",
        "description": "Invalid provenance-file check preflight",
        "main": "index.js",
        "license": "MIT"
    }}"#
    ));
    project.write_file("index.js", "module.exports = {}");
    project.write_file("bundle.sigstore", "not json");
    project.write_file(
        "lpm.json",
        &format!(r#"{{"publish":{{"npm":{{"registry":"{}"}}}}}}"#, mock.url()),
    );

    let output = lpm(&project)
        .args([
            "--json",
            "publish",
            "--check",
            "--npm",
            "--provenance-file",
            "bundle.sigstore",
        ])
        .output()
        .expect("failed to run lpm publish --check --provenance-file");

    assert!(
        !output.status.success(),
        "publish --check must validate provenance files before returning success"
    );
    let envelope = parse_json_output(&output.stdout);
    assert_eq!(envelope["success"], serde_json::json!(false));
    assert_eq!(envelope["error_code"], serde_json::json!("registry"));
    assert!(
        envelope["error"]
            .as_str()
            .is_some_and(|error| error.contains("invalid provenance file")),
        "expected JSON provenance file parse error, got:\n{}",
        serde_json::to_string_pretty(&envelope).unwrap()
    );
    let requests = mock
        .server()
        .received_requests()
        .await
        .expect("wiremock request log must be available");
    assert!(
        requests.is_empty(),
        "invalid provenance file in --check must fail before contacting npm registry; got {} request(s)",
        requests.len()
    );
}

// ─── Multi-target flags ──────────────────────────────────────────

#[test]
fn publish_multi_target_flags_accepted() {
    let project = TempProject::empty(
        r#"{
        "name": "@lpm.dev/testuser.multi-target",
        "version": "1.0.0",
        "description": "Multi-target test",
        "main": "index.js",
        "license": "MIT"
    }"#,
    );

    project.write_file("index.js", "module.exports = {}");

    // --lpm --npm should both be accepted
    let output = lpm(&project)
        .args(["publish", "--dry-run", "--yes", "--lpm", "--npm"])
        .output()
        .expect("failed to run lpm publish with multi-target");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("unexpected argument") && !stderr.contains("unrecognized"),
        "--lpm --npm flags should be recognized, got:\n{stderr}"
    );
}

#[test]
fn publish_custom_registry_dry_run_json_redacts_registry_path() {
    let project = TempProject::empty(
        r#"{
        "name": "custom-publish-pkg",
        "version": "1.2.3",
        "description": "Custom registry dry-run test",
        "main": "index.js",
        "license": "MIT"
    }"#,
    );

    project.write_file("index.js", "module.exports = {}");

    let registry_url = "https://packages.example.test/npm";
    let output = lpm(&project)
        .args([
            "publish",
            "--publish-registry",
            registry_url,
            "--dry-run",
            "--yes",
            "--json",
        ])
        .output()
        .expect("failed to run lpm publish --publish-registry --dry-run --json");

    assert!(
        output.status.success(),
        "custom registry dry-run must succeed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let envelope: serde_json::Value = serde_json::from_str(&stdout).unwrap_or_else(|e| {
        panic!("publish --publish-registry --json must be valid JSON: {e}\n---\n{stdout}")
    });

    assert_eq!(envelope["success"], serde_json::json!(true));
    assert_eq!(envelope["dry_run"], serde_json::json!(true));
    assert_eq!(envelope["name"], serde_json::json!("custom-publish-pkg"));
    assert_eq!(envelope["version"], serde_json::json!("1.2.3"));

    let targets = envelope["targets"]
        .as_array()
        .expect("targets must be an array");
    assert_eq!(targets.len(), 1, "custom dry-run should resolve one target");
    assert_eq!(
        targets[0]["registry"],
        serde_json::json!("https://packages.example.test")
    );
    assert_eq!(targets[0]["name"], serde_json::json!("custom-publish-pkg"));
}

#[test]
fn publish_custom_registry_dry_run_rejects_http_cli_url() {
    let project = TempProject::empty(
        r#"{
        "name": "custom-http-publish-pkg",
        "version": "1.2.3",
        "description": "Custom registry HTTP dry-run test",
        "main": "index.js",
        "license": "MIT"
    }"#,
    );

    project.write_file("index.js", "module.exports = {}");

    let output = lpm(&project)
        .args([
            "--json",
            "publish",
            "--publish-registry",
            "http://packages.example.test/npm",
            "--dry-run",
            "--yes",
        ])
        .output()
        .expect("failed to run lpm publish --publish-registry http:// --dry-run --json");

    assert!(
        !output.status.success(),
        "publish dry-run must reject insecure custom registry URLs:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let envelope: serde_json::Value = serde_json::from_str(&stdout).unwrap_or_else(|e| {
        panic!("publish HTTP registry rejection must be valid JSON: {e}\n---\n{stdout}")
    });
    assert_eq!(envelope["success"], serde_json::json!(false));
    assert!(
        envelope["error"].as_str().is_some_and(|error| {
            error.contains("http://packages.example.test")
                && !error.contains("http://packages.example.test/npm")
                && error.contains("HTTPS")
        }),
        "HTTP registry rejection must name the safe origin and HTTPS requirement: {envelope:#}",
    );
}

// ─── --github / --gitlab provider flags ───────────────────────────────
//
// The github/gitlab targets eventually hit GitHub Packages and GitLab
// Packages. Workflow tests cover the dry-run plan envelope only (the
// target enum is resolved without doing any network).

#[test]
fn publish_github_dry_run_resolves_github_target_in_json_envelope() {
    let project = TempProject::empty(
        r#"{
        "name": "@my-org/gh-pkg",
        "version": "1.0.0",
        "description": "GitHub Packages dry-run target",
        "main": "index.js",
        "license": "MIT"
    }"#,
    );
    project.write_file("index.js", "module.exports = {}");

    let output = lpm(&project)
        .args(["--json", "publish", "--dry-run", "--yes", "--github"])
        .output()
        .expect("failed to run lpm publish --github --dry-run");

    assert!(
        output.status.success(),
        "publish --github --dry-run --json must succeed\nstderr: {}",
        String::from_utf8_lossy(&output.stderr),
    );

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let envelope: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("publish --json must be valid JSON: {e}\n---\n{stdout}"));

    assert_eq!(envelope["dry_run"], serde_json::json!(true));
    let targets = envelope["targets"]
        .as_array()
        .expect("targets must be an array");
    assert!(
        targets
            .iter()
            .any(|t| t["registry"] == serde_json::json!("github")),
        "--github must surface a target with registry=github, got: {targets:?}",
    );
}

#[test]
fn publish_gitlab_dry_run_resolves_gitlab_target_in_json_envelope() {
    let project = TempProject::empty(
        r#"{
        "name": "@my-org/gl-pkg",
        "version": "1.0.0",
        "description": "GitLab Packages dry-run target",
        "main": "index.js",
        "license": "MIT"
    }"#,
    );
    project.write_file("index.js", "module.exports = {}");
    // GitLab Packages requires a numeric project ID in lpm.json so the
    // upload URL can be constructed; without it, dry-run fails-fast with
    // a clear configuration error.
    project.write_file(
        "lpm.json",
        r#"{ "publish": { "gitlab": { "projectId": "12345" } } }"#,
    );

    let output = lpm(&project)
        .args(["--json", "publish", "--dry-run", "--yes", "--gitlab"])
        .output()
        .expect("failed to run lpm publish --gitlab --dry-run");

    assert!(
        output.status.success(),
        "publish --gitlab --dry-run --json must succeed\nstderr: {}",
        String::from_utf8_lossy(&output.stderr),
    );

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let envelope: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("publish --json must be valid JSON: {e}\n---\n{stdout}"));

    let targets = envelope["targets"]
        .as_array()
        .expect("targets must be an array");
    assert!(
        targets
            .iter()
            .any(|t| t["registry"] == serde_json::json!("gitlab")),
        "--gitlab must surface a target with registry=gitlab, got: {targets:?}",
    );
}

#[test]
fn publish_npm_dry_run_resolves_npm_target_in_json_envelope() {
    let project = TempProject::empty(
        r#"{
        "name": "@my-org/npm-pkg",
        "version": "1.0.0",
        "description": "npm Packages dry-run target",
        "main": "index.js",
        "license": "MIT"
    }"#,
    );
    project.write_file("index.js", "module.exports = {}");

    let output = lpm(&project)
        .args(["--json", "publish", "--dry-run", "--yes", "--npm"])
        .output()
        .expect("failed to run lpm publish --npm --dry-run");

    assert!(
        output.status.success(),
        "publish --npm --dry-run --json must succeed\nstderr: {}",
        String::from_utf8_lossy(&output.stderr),
    );

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let envelope: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("publish --json must be valid JSON: {e}\n---\n{stdout}"));

    assert_eq!(envelope["dry_run"], serde_json::json!(true));
    let targets = envelope["targets"]
        .as_array()
        .expect("targets must be an array");
    assert!(
        targets
            .iter()
            .any(|t| t["registry"] == serde_json::json!("npm")),
        "--npm must surface a target with registry=npm, got: {targets:?}",
    );
}

#[test]
fn publish_github_and_gitlab_together_yields_two_targets() {
    let project = TempProject::empty(
        r#"{
        "name": "@my-org/multi-pkg",
        "version": "1.0.0",
        "description": "Multi-provider dry-run",
        "main": "index.js",
        "license": "MIT"
    }"#,
    );
    project.write_file("index.js", "module.exports = {}");
    project.write_file(
        "lpm.json",
        r#"{ "publish": { "gitlab": { "projectId": "12345" } } }"#,
    );

    let output = lpm(&project)
        .args([
            "--json",
            "publish",
            "--dry-run",
            "--yes",
            "--github",
            "--gitlab",
        ])
        .output()
        .expect("failed to run lpm publish --github --gitlab --dry-run");

    assert!(
        output.status.success(),
        "multi-provider dry-run must succeed"
    );

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let envelope: serde_json::Value = serde_json::from_str(&stdout).unwrap();

    let target_registries: Vec<&str> = envelope["targets"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|t| t["registry"].as_str())
        .collect();
    assert!(
        target_registries.contains(&"github") && target_registries.contains(&"gitlab"),
        "both providers must appear in the targets array, got: {target_registries:?}",
    );
}

fn extract_uploaded_package_json(tarball_data: &[u8]) -> serde_json::Value {
    use std::io::Read;

    let mut decoder = flate2::read::GzDecoder::new(tarball_data);
    let mut tar_data = Vec::new();
    decoder
        .read_to_end(&mut tar_data)
        .expect("published tarball must decompress");

    let mut archive = tar::Archive::new(tar_data.as_slice());
    for entry in archive
        .entries()
        .expect("published tarball must list entries")
    {
        let mut entry = entry.expect("published tarball entry must read");
        if entry
            .path()
            .expect("published tarball entry path must read")
            .to_string_lossy()
            == "package/package.json"
        {
            let mut content = String::new();
            entry
                .read_to_string(&mut content)
                .expect("published package.json must read");
            return serde_json::from_str(&content).expect("published package.json must parse");
        }
    }

    panic!("published tarball missing package/package.json");
}
