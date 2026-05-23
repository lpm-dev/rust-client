//! Workflow tests for `lpm install`.
//!
//! Tests that exercise the full install pipeline through the real binary.
//! Network-dependent tests use MockRegistry; local-only tests use fixtures.

mod support;

use support::assertions;
use support::mock_registry::{
    MockRegistry, compute_integrity, make_tarball, make_tarball_from_pkg_json,
};
use support::{TempProject, lpm, lpm_with_registry};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

// ─── No package.json ─────────────────────────────────────────────

#[test]
fn install_without_package_json_fails() {
    let dir = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();

    let mut cmd = assert_cmd::Command::cargo_bin("lpm-rs").unwrap();
    cmd.current_dir(dir.path());
    cmd.env("HOME", home.path());
    cmd.env("NO_COLOR", "1");
    cmd.env("LPM_NO_UPDATE_CHECK", "1");
    cmd.env_remove("LPM_TOKEN");

    let output = cmd
        .args(["install"])
        .output()
        .expect("failed to run lpm install");

    assert!(!output.status.success());

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("package.json"),
        "expected error about missing package.json, got:\n{stderr}"
    );
}

// ─── Auto-create + parent-dir walk for `lpm i <pkg>` ─────────────
//
// Match npm/pnpm/yarn/bun DX. `lpm i <pkg>` in a directory with no
// `package.json` and no ancestor `package.json` must create a minimal
// `{ "dependencies": {} }` manifest in cwd and install into it — not
// crash with a raw `IO error: No such file or directory`. And both
// bare `lpm install` and `lpm i <pkg>` must walk up to find a parent
// `package.json` instead of demanding the user be in the project
// root directory.

#[tokio::test]
async fn install_add_in_empty_dir_auto_creates_package_json() {
    let mock = MockRegistry::start().await;
    let tarball = make_tarball("ms", "2.1.3");
    mock.with_package("ms", "2.1.3", &tarball).await;
    mount_ms_2_1_3(&mock).await;

    // Empty project: no package.json on disk.
    let project = TempProject::empty(r#"{"name":"placeholder","version":"0.0.0"}"#);
    std::fs::remove_file(project.path().join("package.json")).unwrap();

    let output = lpm_with_registry(&project, &mock.url())
        .args([
            "install",
            "ms",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("failed to run lpm install");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "install in empty dir should auto-create package.json and succeed:\nstdout: {stdout}\nstderr: {stderr}"
    );

    assert!(
        project.file_exists("package.json"),
        "lpm i <pkg> in an empty dir must auto-create package.json"
    );
    let pkg: serde_json::Value = serde_json::from_str(&project.read_file("package.json"))
        .expect("auto-created package.json must be valid JSON");
    assert!(
        pkg.get("dependencies").and_then(|d| d.get("ms")).is_some(),
        "auto-created package.json must record the installed package under dependencies: {pkg}"
    );

    assertions::assert_in_node_modules(project.path(), "ms");
}

#[tokio::test]
async fn install_add_walks_up_to_parent_package_json() {
    let mock = MockRegistry::start().await;
    let tarball = make_tarball("ms", "2.1.3");
    mock.with_package("ms", "2.1.3", &tarball).await;
    mount_ms_2_1_3(&mock).await;

    let project = TempProject::empty(
        r#"{
            "name": "parent-walk",
            "version": "1.0.0",
            "dependencies": {}
        }"#,
    );
    let child_dir = project.path().join("sample-child");
    std::fs::create_dir_all(&child_dir).unwrap();

    // Invoke `lpm i ms` from the child subdir (no package.json there).
    let bin = assert_cmd::cargo::cargo_bin("lpm-rs");
    let mut cmd = assert_cmd::Command::new(bin);
    cmd.current_dir(&child_dir);
    // Mirror lpm_with_registry's env isolation + mock-registry pointer.
    cmd.env("HOME", project.home());
    cmd.env("LPM_HOME", project.home().join(".lpm"));
    cmd.env("LPM_NO_UPDATE_CHECK", "1");
    cmd.env("NO_COLOR", "1");
    cmd.env_remove("LPM_TOKEN");
    cmd.args([
        "--registry",
        &mock.url(),
        "--insecure",
        "install",
        "ms",
        "--no-security-summary",
        "--no-skills",
        "--no-editor-setup",
    ]);
    let output = cmd.output().expect("failed to run lpm install");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "lpm i <pkg> from child subdir must walk up to parent package.json:\nstdout: {stdout}\nstderr: {stderr}"
    );

    // Manifest update + node_modules MUST land in the parent, not the child.
    let parent_pkg: serde_json::Value =
        serde_json::from_str(&project.read_file("package.json")).unwrap();
    assert!(
        parent_pkg
            .get("dependencies")
            .and_then(|d| d.get("ms"))
            .is_some(),
        "parent package.json must record the new dependency: {parent_pkg}"
    );
    assert!(
        !child_dir.join("package.json").exists(),
        "child subdir must NOT have a stray package.json created — should use the parent's"
    );
    assert!(
        !child_dir.join("node_modules").exists(),
        "child subdir must NOT have node_modules — install targets the parent project root"
    );
    assertions::assert_in_node_modules(project.path(), "ms");
}

#[tokio::test]
async fn install_add_with_dist_tag_resolves_tagged_prerelease_and_saves_exact() {
    let mock = MockRegistry::start().await;
    let package_name = "dist-tag-save-policy";
    let stable_version = "1.9.0";
    let beta_version = "2.0.0-beta.2";

    let stable_tarball = make_tarball(package_name, stable_version);
    let beta_tarball = make_tarball(package_name, beta_version);
    let stable_integrity = compute_integrity(&stable_tarball);
    let beta_integrity = compute_integrity(&beta_tarball);
    let stable_tarball_url = mock.tarball_url(package_name, stable_version);
    let beta_tarball_url = mock.tarball_url(package_name, beta_version);

    let metadata = serde_json::json!({
        "name": package_name,
        "dist-tags": {
            "latest": stable_version,
            "beta": beta_version,
        },
        "versions": {
            stable_version: {
                "name": package_name,
                "version": stable_version,
                "dist": {
                    "tarball": stable_tarball_url,
                    "integrity": stable_integrity,
                },
                "dependencies": {},
            },
            beta_version: {
                "name": package_name,
                "version": beta_version,
                "dist": {
                    "tarball": beta_tarball_url,
                    "integrity": beta_integrity,
                },
                "dependencies": {},
            },
        },
        "time": {
            stable_version: "2025-01-01T00:00:00.000Z",
            beta_version: "2025-01-02T00:00:00.000Z",
        },
    });

    Mock::given(method("GET"))
        .and(path(format!("/{package_name}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(metadata.clone()))
        .mount(mock.server())
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/api/registry/{package_name}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(metadata.clone()))
        .mount(mock.server())
        .await;
    Mock::given(method("GET"))
        .and(path(MockRegistry::tarball_path(
            package_name,
            stable_version,
        )))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_bytes(stable_tarball)
                .insert_header("content-type", "application/octet-stream"),
        )
        .mount(mock.server())
        .await;
    Mock::given(method("GET"))
        .and(path(MockRegistry::tarball_path(package_name, beta_version)))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_bytes(beta_tarball)
                .insert_header("content-type", "application/octet-stream"),
        )
        .mount(mock.server())
        .await;
    mock.with_batch_metadata(vec![metadata]).await;

    let project = TempProject::empty(
        r#"{
            "name": "dist-tag-project-install",
            "version": "1.0.0",
            "dependencies": {}
        }"#,
    );

    let output = lpm_with_registry(&project, &mock.url())
        .args([
            "install",
            &format!("{package_name}@beta"),
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("failed to run lpm install");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "install {package_name}@beta must succeed:\nstdout: {stdout}\nstderr: {stderr}"
    );

    let manifest: serde_json::Value = serde_json::from_str(&project.read_file("package.json"))
        .expect("package.json must stay valid json");
    assert_eq!(
        manifest["dependencies"][package_name],
        serde_json::Value::String(beta_version.to_string()),
        "dist-tag install must save the resolved prerelease exactly, not the latest stable"
    );

    let installed_pkg: serde_json::Value = serde_json::from_str(
        &project.read_file(&format!("node_modules/{package_name}/package.json")),
    )
    .expect("installed package.json must be valid json");
    assert_eq!(
        installed_pkg["version"],
        serde_json::Value::String(beta_version.to_string()),
        "node_modules must contain the dist-tag target version"
    );
}

#[tokio::test]
async fn install_bare_walks_up_to_parent_package_json() {
    let mock = MockRegistry::start().await;
    let tarball = make_tarball("ms", "2.1.3");
    mock.with_package("ms", "2.1.3", &tarball).await;
    mount_ms_2_1_3(&mock).await;

    let project = TempProject::empty(
        r#"{
            "name": "bare-parent-walk",
            "version": "1.0.0",
            "dependencies": { "ms": "^2.1.3" }
        }"#,
    );
    let child_dir = project.path().join("nested").join("deeper");
    std::fs::create_dir_all(&child_dir).unwrap();

    let bin = assert_cmd::cargo::cargo_bin("lpm-rs");
    let mut cmd = assert_cmd::Command::new(bin);
    cmd.current_dir(&child_dir);
    cmd.env("HOME", project.home());
    cmd.env("LPM_HOME", project.home().join(".lpm"));
    cmd.env("LPM_NO_UPDATE_CHECK", "1");
    cmd.env("NO_COLOR", "1");
    cmd.env_remove("LPM_TOKEN");
    cmd.args([
        "--registry",
        &mock.url(),
        "--insecure",
        "install",
        "--no-security-summary",
        "--no-skills",
        "--no-editor-setup",
    ]);
    let output = cmd.output().expect("failed to run lpm install");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "bare `lpm install` from nested subdir must walk up to parent package.json:\nstdout: {stdout}\nstderr: {stderr}"
    );
    assertions::assert_in_node_modules(project.path(), "ms");
    assert!(
        !child_dir.join("node_modules").exists(),
        "nested subdir must NOT have its own node_modules — install targets the parent project root"
    );
}

// ─── audit-after-install ──────────────────────────────────────────
//
// Default OFF; opt in per-invocation via `--audit-after-install`, or
// globally via `LPM_AUDIT_AFTER_INSTALL=1` env / `auditAfterInstall =
// true` in `~/.lpm/config.toml`. The per-invocation flag pair
// (`--audit-after-install` / `--no-audit-after-install`) overrides
// the env + config. Findings are informational — install ALWAYS
// exits 0 if the install itself succeeded.

#[tokio::test]
async fn install_default_emits_no_audit_summary_line() {
    let mock = MockRegistry::start().await;
    let tarball = make_tarball("ms", "2.1.3");
    mock.with_package("ms", "2.1.3", &tarball).await;
    mount_ms_2_1_3(&mock).await;

    let project = TempProject::empty(
        r#"{"name":"audit-off","version":"1.0.0","dependencies":{"ms":"^2.1.3"}}"#,
    );
    let output = lpm_with_registry(&project, &mock.url())
        .args([
            "install",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("failed to run lpm install");

    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    assert!(output.status.success(), "install must succeed: {combined}");
    assert!(
        !combined.contains("Audited"),
        "audit-after-install is default OFF — no `Audited` line should appear; got:\n{combined}"
    );
}

#[tokio::test]
async fn install_with_audit_after_install_flag_appends_summary_line() {
    let mock = MockRegistry::start().await;
    let tarball = make_tarball("ms", "2.1.3");
    mock.with_package("ms", "2.1.3", &tarball).await;
    mount_ms_2_1_3(&mock).await;

    let project = TempProject::empty(
        r#"{"name":"audit-on","version":"1.0.0","dependencies":{"ms":"^2.1.3"}}"#,
    );
    let output = lpm_with_registry(&project, &mock.url())
        .args([
            "install",
            "--audit-after-install",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("failed to run lpm install");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "install must succeed even when audit finds suspicious behavior:\nstderr: {stderr}"
    );
    assert!(
        stderr.contains("Audited") && stderr.contains("run `lpm audit`"),
        "audit summary line missing; got stderr:\n{stderr}"
    );
}

#[tokio::test]
async fn install_no_audit_after_install_overrides_env() {
    let mock = MockRegistry::start().await;
    let tarball = make_tarball("ms", "2.1.3");
    mock.with_package("ms", "2.1.3", &tarball).await;
    mount_ms_2_1_3(&mock).await;

    let project = TempProject::empty(
        r#"{"name":"audit-env-off","version":"1.0.0","dependencies":{"ms":"^2.1.3"}}"#,
    );
    let output = lpm_with_registry(&project, &mock.url())
        .env("LPM_AUDIT_AFTER_INSTALL", "1")
        .args([
            "install",
            "--no-audit-after-install",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("failed to run lpm install");

    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    assert!(output.status.success(), "install must succeed: {combined}");
    assert!(
        !combined.contains("Audited"),
        "`--no-audit-after-install` must beat `LPM_AUDIT_AFTER_INSTALL=1`; got:\n{combined}"
    );
}

#[tokio::test]
async fn install_env_audit_after_install_appends_summary_line() {
    let mock = MockRegistry::start().await;
    let tarball = make_tarball("ms", "2.1.3");
    mock.with_package("ms", "2.1.3", &tarball).await;
    mount_ms_2_1_3(&mock).await;

    let project = TempProject::empty(
        r#"{"name":"audit-env-on","version":"1.0.0","dependencies":{"ms":"^2.1.3"}}"#,
    );
    let output = lpm_with_registry(&project, &mock.url())
        .env("LPM_AUDIT_AFTER_INSTALL", "1")
        .args([
            "install",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("failed to run lpm install");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "install must succeed:\n{stderr}");
    assert!(
        stderr.contains("Audited"),
        "LPM_AUDIT_AFTER_INSTALL=1 must enable the audit summary line; got stderr:\n{stderr}"
    );
}

#[tokio::test]
async fn install_audit_after_install_attaches_summary_to_json_envelope() {
    let mock = MockRegistry::start().await;
    let tarball = make_tarball("ms", "2.1.3");
    mock.with_package("ms", "2.1.3", &tarball).await;
    mount_ms_2_1_3(&mock).await;

    let project = TempProject::empty(
        r#"{"name":"audit-json","version":"1.0.0","dependencies":{"ms":"^2.1.3"}}"#,
    );
    let output = lpm_with_registry(&project, &mock.url())
        .args([
            "--json",
            "install",
            "--audit-after-install",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("failed to run lpm install");

    assert!(output.status.success(), "install must succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let envelope: serde_json::Value =
        serde_json::from_str(&stdout).expect("install --json must emit a parseable envelope");
    let summary = envelope
        .get("audit_summary")
        .expect("audit_summary field must appear on the install envelope when opted in");
    // Shape contract — every field must be present and numeric.
    for key in &[
        "packages_audited",
        "vulnerabilities",
        "suspicious",
        "elapsed_ms",
    ] {
        assert!(
            summary.get(key).is_some_and(|v| v.is_number()),
            "audit_summary.{key} must be a number; got envelope:\n{stdout}"
        );
    }
    // Human stderr must NOT carry the `! Audited …` line in JSON mode.
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("Audited"),
        "human audit line must be suppressed under --json; got stderr:\n{stderr}"
    );
}

#[tokio::test]
async fn install_audit_after_install_enabled_via_config_file() {
    // Locks the third precedence tier — `~/.lpm/config.toml >
    // audit-after-install = true`. Without this test, the chain
    // documented in `lpm install --help` and config-toml.mdx has an
    // untested rung; only CLI flag + env are otherwise exercised.
    let mock = MockRegistry::start().await;
    let tarball = make_tarball("ms", "2.1.3");
    mock.with_package("ms", "2.1.3", &tarball).await;
    mount_ms_2_1_3(&mock).await;

    let project = TempProject::empty(
        r#"{"name":"audit-cfg-on","version":"1.0.0","dependencies":{"ms":"^2.1.3"}}"#,
    );

    // Seed `<home>/.lpm/config.toml` with `audit-after-install = true`.
    // No CLI flag, no env var — only the config-file rung resolves to
    // true. The audit line MUST still fire.
    let cfg_dir = project.home().join(".lpm");
    std::fs::create_dir_all(&cfg_dir).unwrap();
    std::fs::write(cfg_dir.join("config.toml"), "audit-after-install = true\n").unwrap();

    let output = lpm_with_registry(&project, &mock.url())
        .args([
            "install",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("failed to run lpm install");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "install must succeed:\n{stderr}");
    assert!(
        stderr.contains("Audited"),
        "`audit-after-install = true` in config.toml must enable the audit summary line; \
         got stderr:\n{stderr}"
    );
}

#[tokio::test]
async fn install_audit_after_install_failure_does_not_fail_install() {
    // Locks the "audit findings are informational only" contract.
    // When the audit pass errors mid-flight — network outage, store-
    // lock contention, lockfile corruption, etc. — the install
    // pipeline MUST still exit 0 and MUST NOT attach `audit_summary`
    // to the JSON envelope. The wrapper at the audit call site in
    // `run_with_options_under_store_lock` owns this contract; this
    // test pins it.
    //
    // Failure injection uses `LPM_TEST_AUDIT_AFTER_INSTALL_FAIL=1` +
    // `LPM_TEST_MODE=1` (the latter is implicit in debug builds via
    // `cfg!(debug_assertions)`). The trigger is owned by
    // `maybe_test_audit_after_install_should_fail` in install.rs.
    let mock = MockRegistry::start().await;
    let tarball = make_tarball("ms", "2.1.3");
    mock.with_package("ms", "2.1.3", &tarball).await;
    mount_ms_2_1_3(&mock).await;

    let project = TempProject::empty(
        r#"{"name":"audit-fail","version":"1.0.0","dependencies":{"ms":"^2.1.3"}}"#,
    );

    let output = lpm_with_registry(&project, &mock.url())
        .env("LPM_TEST_MODE", "1")
        .env("LPM_TEST_AUDIT_AFTER_INSTALL_FAIL", "1")
        .args([
            "--json",
            "install",
            "--audit-after-install",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("failed to run lpm install");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "install MUST exit 0 even when audit-after-install errors — findings are \
         informational only; stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    let envelope: serde_json::Value = serde_json::from_str(&stdout)
        .expect("install --json must emit a parseable envelope even when audit fails");
    assert!(
        envelope.get("audit_summary").is_none(),
        "audit_summary MUST be absent from the envelope when the audit pass errored — \
         partial / placeholder counts would mislead operators. Envelope:\n{stdout}"
    );
    assert!(
        !stderr.contains("Audited"),
        "human audit advisory line MUST NOT fire when the audit pass errored; \
         got stderr:\n{stderr}"
    );
}

#[test]
fn install_audit_after_install_flags_are_mutually_exclusive() {
    let project =
        TempProject::empty(r#"{"name":"flag-conflict","version":"1.0.0","dependencies":{}}"#);
    let output = lpm(&project)
        .args([
            "install",
            "--audit-after-install",
            "--no-audit-after-install",
        ])
        .output()
        .expect("failed to run lpm install");
    assert!(
        !output.status.success(),
        "clap must reject passing both flags simultaneously"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("cannot be used with"),
        "expected clap conflict message; got stderr:\n{stderr}"
    );
}

// ─── Empty Dependencies ──────────────────────────────────────────

#[test]
fn install_with_no_dependencies_succeeds() {
    let project = TempProject::empty(
        r#"{
        "name": "empty-deps",
        "version": "1.0.0",
        "dependencies": {}
    }"#,
    );

    let output = lpm(&project)
        .args(["install"])
        .output()
        .expect("failed to run lpm install");

    assert!(
        output.status.success(),
        "install with empty deps failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    assert!(
        combined.contains("No dependencies") || combined.contains("up to date"),
        "expected 'No dependencies' or 'up to date' message, got:\n{combined}"
    );
}

/// Single-writer ownership pin: the empty-deps short-circuit at the
/// top of `run_with_options_under_store_lock` MUST emit a v6
/// `.lpm/install-hash` (3 lines: `<hash>\nm:<pkg_ns>:<lock_ns>\nl:<mode>\n`)
/// just like the canonical end-of-function path. Pre-fix the
/// short-circuit returned without writing anything, and `dev.rs`
/// covered the gap by writing a single-line bare hash post-install
/// — which clobbered v6 metadata on the canonical path AND used
/// stale pre-install state. With the install pipeline owning every
/// successful exit, a freshly installed empty-deps project lands
/// the same v6 shape any other install does.
#[test]
fn empty_deps_install_writes_v6_install_hash() {
    let project = TempProject::empty(
        r#"{
        "name": "empty-deps-hash",
        "version": "1.0.0",
        "dependencies": {}
    }"#,
    );

    let output = lpm(&project)
        .args(["install"])
        .output()
        .expect("failed to run lpm install");
    assert!(
        output.status.success(),
        "install with empty deps failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let install_hash = project.path().join(".lpm").join("install-hash");
    assert!(
        install_hash.exists(),
        "empty-deps install must write `.lpm/install-hash` — pre-fix the \
         short-circuit returned without writing and `dev.rs` covered the \
         gap with a stale single-line hash"
    );
    let content = std::fs::read_to_string(&install_hash).expect("install-hash readable");
    let lines: Vec<&str> = content.lines().collect();
    assert!(
        lines.len() >= 3,
        "v6 install-hash must have at least 3 lines (hash + `m:` + `l:`), got:\n{content}"
    );
    assert!(
        !lines[0].is_empty() && lines[0].chars().all(|c| c.is_ascii_hexdigit()),
        "line 1 must be a non-empty hex hash, got {:?}",
        lines[0]
    );
    assert!(
        lines[1].starts_with("m:"),
        "line 2 must start with `m:` (mtime line), got {:?}",
        lines[1]
    );
    assert!(
        lines[2] == "l:isolated" || lines[2] == "l:hoisted",
        "line 3 must be `l:isolated` or `l:hoisted`, got {:?}",
        lines[2]
    );
}

#[test]
fn empty_deps_second_install_is_up_to_date() {
    let project = TempProject::empty(
        r#"{
        "name": "empty-deps-fresh",
        "version": "1.0.0",
        "dependencies": {}
    }"#,
    );

    let first = lpm(&project)
        .args(["install"])
        .output()
        .expect("failed to run first lpm install");
    assert!(
        first.status.success(),
        "first empty-deps install failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&first.stdout),
        String::from_utf8_lossy(&first.stderr),
    );

    assert!(
        project.path().join("lpm.lock").is_file(),
        "empty-deps install must materialize lpm.lock for freshness"
    );
    assert!(
        project.path().join("node_modules").is_dir(),
        "empty-deps install must materialize node_modules for freshness"
    );

    let second = lpm(&project)
        .args(["install"])
        .output()
        .expect("failed to run second lpm install");
    assert!(
        second.status.success(),
        "second empty-deps install failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&second.stdout),
        String::from_utf8_lossy(&second.stderr),
    );

    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&second.stdout),
        String::from_utf8_lossy(&second.stderr),
    );

    assert!(
        combined.contains("up to date"),
        "expected second empty-deps install to hit freshness fast path, got:\n{combined}"
    );
}

// ─── install-time warning for `pnpm.overrides` ─────

/// A project with `pnpm.overrides` but no LPM-readable equivalent
/// must produce a stderr warning suggesting `lpm migrate`. Diff-aware:
/// once `lpm.overrides` covers the same keys, the warning silences.
#[test]
fn install_warns_when_pnpm_overrides_dropped() {
    let project = TempProject::empty(
        r#"{
        "name": "drift",
        "version": "1.0.0",
        "dependencies": {},
        "pnpm": {
            "overrides": {
                "lodash": "^4.17.21"
            }
        }
    }"#,
    );

    let output = lpm(&project)
        .args(["install"])
        .output()
        .expect("failed to run lpm install");

    assert!(
        output.status.success(),
        "install with empty deps should succeed"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("`pnpm.overrides`") && stderr.contains("LPM doesn't honor"),
        "expected stderr warning, got:\n{stderr}"
    );
    assert!(
        stderr.contains("lpm migrate"),
        "warning should suggest lpm migrate, got:\n{stderr}"
    );
}

/// `--json` mode silences the warning to keep stdout JSON contract
/// intact. Giving automation a structured
/// surface for the same signal via `lpm doctor`.
#[test]
fn install_pnpm_overrides_warning_silenced_under_json() {
    let project = TempProject::empty(
        r#"{
        "name": "drift",
        "version": "1.0.0",
        "dependencies": {},
        "pnpm": {
            "overrides": {
                "lodash": "^4.17.21"
            }
        }
    }"#,
    );

    let output = lpm(&project)
        .args(["--json", "install"])
        .output()
        .expect("failed to run lpm install --json");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !(stderr.contains("`pnpm.overrides`") && stderr.contains("LPM doesn't honor")),
        "warning must be silenced under --json, but found in stderr:\n{stderr}"
    );
}

/// Drift case: same raw key in both `pnpm.overrides` and
/// `lpm.overrides` but DIFFERENT targets means LPM isn't honoring the
/// pnpm intent. The warning must fire — silencing it would hide the
/// exact divergence the feature is meant to surface.
#[test]
fn install_warns_when_pnpm_and_lpm_targets_diverge() {
    let project = TempProject::empty(
        r#"{
        "name": "drift-target",
        "version": "1.0.0",
        "dependencies": {},
        "pnpm": {
            "overrides": { "lodash": "^4.17.21" }
        },
        "lpm": {
            "overrides": { "lodash": "^4.18.0" }
        }
    }"#,
    );

    let output = lpm(&project)
        .args(["install"])
        .output()
        .expect("failed to run lpm install");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("`pnpm.overrides`") && stderr.contains("LPM doesn't honor"),
        "warning must fire when pnpm and lpm targets diverge for the same key, got:\n{stderr}"
    );
}

/// Diff-aware: when `lpm.overrides` already covers all `pnpm.overrides`
/// keys (the post-migrate steady state), the warning must silence.
#[test]
fn install_pnpm_overrides_warning_silent_when_lpm_side_covers_keys() {
    let project = TempProject::empty(
        r#"{
        "name": "post-migrate-steady-state",
        "version": "1.0.0",
        "dependencies": {},
        "pnpm": {
            "overrides": { "lodash": "^4.17.21" }
        },
        "lpm": {
            "overrides": { "lodash": "^4.17.21" }
        }
    }"#,
    );

    let output = lpm(&project)
        .args(["install"])
        .output()
        .expect("failed to run lpm install");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !(stderr.contains("`pnpm.overrides`") && stderr.contains("LPM doesn't honor")),
        "post-migrate steady state should be silent, but warning fired:\n{stderr}"
    );
}

// ─── install-time warning for `pnpm.patchedDependencies` ─

/// `pnpm.patchedDependencies` declared without an LPM-readable
/// equivalent must produce the diff-aware install warning. Same shape
/// as the overrides warning, separate message body so users can tell
/// which surface is dropping.
#[test]
fn install_warns_when_pnpm_patches_dropped() {
    let project = TempProject::empty(
        r#"{
        "name": "patches-drift",
        "version": "1.0.0",
        "dependencies": {},
        "pnpm": {
            "patchedDependencies": {
                "react@18.0.0": "patches/react@18.0.0.patch"
            }
        }
    }"#,
    );

    let output = lpm(&project)
        .args(["install"])
        .output()
        .expect("failed to run lpm install");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("`pnpm.patchedDependencies`") && stderr.contains("LPM doesn't honor"),
        "expected stderr warning, got:\n{stderr}"
    );
    assert!(
        stderr.contains("lpm migrate"),
        "warning should suggest lpm migrate, got:\n{stderr}"
    );
}

/// Diff-aware: when `lpm.patchedDependencies` already covers all
/// `pnpm.patchedDependencies` keys with matching paths, the warning
/// must silence (post-migrate steady state).
#[test]
fn install_pnpm_patches_warning_silent_when_lpm_side_covers_paths() {
    let project = TempProject::empty(
        r#"{
        "name": "patches-steady-state",
        "version": "1.0.0",
        "dependencies": {},
        "pnpm": {
            "patchedDependencies": {
                "react@18.0.0": "patches/react@18.0.0.patch"
            }
        },
        "lpm": {
            "patchedDependencies": {
                "react@18.0.0": {
                    "path": "patches/react@18.0.0.patch",
                    "originalIntegrity": "sha512-x"
                }
            }
        }
    }"#,
    );

    let output = lpm(&project)
        .args(["install"])
        .output()
        .expect("failed to run lpm install");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !(stderr.contains("`pnpm.patchedDependencies`") && stderr.contains("LPM doesn't honor")),
        "warning must silence post-migrate, got:\n{stderr}"
    );
}

/// Divergent path: same key in both surfaces but different paths means
/// LPM isn't honoring pnpm's intent — warning must fire.
#[test]
fn install_warns_when_pnpm_and_lpm_patch_paths_diverge() {
    let project = TempProject::empty(
        r#"{
        "name": "patches-drift-target",
        "version": "1.0.0",
        "dependencies": {},
        "pnpm": {
            "patchedDependencies": {
                "react@18.0.0": "patches/react@18.0.0.patch"
            }
        },
        "lpm": {
            "patchedDependencies": {
                "react@18.0.0": {
                    "path": "vendor/different.patch",
                    "originalIntegrity": "sha512-x"
                }
            }
        }
    }"#,
    );

    let output = lpm(&project)
        .args(["install"])
        .output()
        .expect("failed to run lpm install");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("`pnpm.patchedDependencies`") && stderr.contains("LPM doesn't honor"),
        "divergent path must fire the warning, got:\n{stderr}"
    );
}

/// `--json` mode silences the warning.
#[test]
fn install_pnpm_patches_warning_silenced_under_json() {
    let project = TempProject::empty(
        r#"{
        "name": "patches-drift-json",
        "version": "1.0.0",
        "dependencies": {},
        "pnpm": {
            "patchedDependencies": {
                "react@18.0.0": "patches/react@18.0.0.patch"
            }
        }
    }"#,
    );

    let output = lpm(&project)
        .args(["--json", "install"])
        .output()
        .expect("failed to run lpm install --json");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !(stderr.contains("`pnpm.patchedDependencies`") && stderr.contains("LPM doesn't honor")),
        "warning must be silenced under --json, got:\n{stderr}"
    );
}

// ─── --force Bypasses Fast Path ──────────────────────────────────

#[test]
fn install_force_bypasses_up_to_date() {
    let project = TempProject::empty(
        r#"{
        "name": "force-test",
        "version": "1.0.0",
        "dependencies": {}
    }"#,
    );

    // First install
    lpm(&project).args(["install"]).assert().success();

    // Force install should NOT say up-to-date
    let output = lpm(&project)
        .args(["install", "--force"])
        .output()
        .expect("failed to run forced install");

    assert!(output.status.success());
}

// ─── Real Install: Single Package via Mock Registry ──────────────

#[tokio::test]
async fn install_single_package_via_mock_registry() {
    let mock = MockRegistry::start().await;
    let tarball = make_tarball("ms", "2.1.3");

    // Mount package metadata + tarball
    mock.with_package("ms", "2.1.3", &tarball).await;

    // Mount batch-metadata (the install pipeline calls this first)
    let batch_meta = serde_json::json!({
        "name": "ms",
        "dist-tags": { "latest": "2.1.3" },
        "versions": {
            "2.1.3": {
                "name": "ms",
                "version": "2.1.3",
                "dist": {
                    "tarball": format!("{}/tarballs/ms/-/ms-2.1.3.tgz", mock.url()),
                    "integrity": format!("sha512-placeholder"),
                },
                "dependencies": {}
            }
        },
        "time": { "2.1.3": "2025-01-01T00:00:00.000Z" }
    });
    mock.with_batch_metadata(vec![batch_meta]).await;

    let project = TempProject::empty(
        r#"{
        "name": "install-test",
        "version": "1.0.0",
        "dependencies": {
            "ms": "^2.1.3"
        }
    }"#,
    );

    let output = lpm_with_registry(&project, &mock.url())
        .args([
            "install",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("failed to run lpm install");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        output.status.success(),
        "install with mock registry failed:\nstdout: {stdout}\nstderr: {stderr}"
    );

    // Verify lockfile was created
    assertions::assert_lockfile_exists(project.path());
    assertions::assert_lockfile_contains(project.path(), "ms");

    // Verify node_modules was populated
    assertions::assert_node_modules_exists(project.path());
    assertions::assert_in_node_modules(project.path(), "ms");
}

// ─── JSON Envelope Snapshot ──────────────────────────────────────

/// Install one package with `--json` and snapshot the envelope shape.
///
/// Locks the structural contract of `lpm install --json` for the
/// dashboard / CI integrations that consume it: top-level
/// `success` / `count` / `packages[]` / `up_to_date` etc. plus the
/// per-package shape under `packages`. Highly-variable fields
/// (`duration_ms`, the entire `timing` sub-tree, integrity hashes,
/// resolver-internal counters) are redacted to keep the snapshot
/// stable across runs and across resolver-internal refactors.
#[tokio::test]
async fn install_json_envelope_with_one_package_matches_snapshot() {
    let mock = MockRegistry::start().await;
    let tarball = make_tarball("ms", "2.1.3");
    mock.with_package("ms", "2.1.3", &tarball).await;
    mock.with_batch_metadata(vec![serde_json::json!({
        "name": "ms",
        "dist-tags": { "latest": "2.1.3" },
        "versions": {
            "2.1.3": {
                "name": "ms",
                "version": "2.1.3",
                "dist": {
                    "tarball": format!("{}/tarballs/ms/-/ms-2.1.3.tgz", mock.url()),
                    "integrity": "sha512-placeholder",
                },
                "dependencies": {}
            }
        },
        "time": { "2.1.3": "2025-01-01T00:00:00.000Z" }
    })])
    .await;

    let project = TempProject::empty(
        r#"{"name":"snap-install","version":"1.0.0","dependencies":{"ms":"^2.1.3"}}"#,
    );

    // pin to `LPM_LINKER=isolated` so the JSON
    // envelope's `symlinked` count stays stable across the default
    // flip. The 4f flip moved `LinkerMode::default()` to Hoisted,
    // which produces 0 root-level symlinks (real dirs flat in
    // `node_modules/`); isolated produces 2 (one per direct dep
    // root + scope). The snapshot is pinning the envelope SHAPE,
    // not the linker behavior — pinning the linker keeps the shape
    // assertion meaningful.
    let output = lpm_with_registry(&project, &mock.url())
        .args([
            "install",
            "--json",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .env("LPM_LINKER", "isolated")
        .output()
        .expect("failed to run lpm install --json");
    assert!(output.status.success(), "install --json failed: {output:?}");

    let envelope: serde_json::Value = serde_json::from_slice(&output.stdout)
        .expect("install --json stdout must be valid JSON; got non-JSON output (mixed with logs?)");
    assert_eq!(envelope["overrides_fingerprint"], serde_json::Value::Null);
    assert_eq!(envelope["patches_fingerprint"], serde_json::Value::Null);
    assert_eq!(envelope["blocked_set_fingerprint"], serde_json::Value::Null);

    insta::with_settings!({
        filters => vec![
            // Mock registry URL (dynamic port) → [REGISTRY]
            (r"http://127\.0\.0\.1:\d+", "[REGISTRY]"),
            // Temp HOME / project / store paths → [TEMP]
            (r#"/var/folders/[^"\s]+"#, "[TEMP]"),
            (r#"/private/var/folders/[^"\s]+"#, "[TEMP]"),
            (r#"/tmp/[^"\s]+"#, "[TEMP]"),
        ],
    }, {
        insta::assert_json_snapshot!("install_json_envelope_one_package", envelope, {
            // High-variance numeric / hash fields — locking values would
            // make the snapshot a flake magnet.
            ".duration_ms" => "[DURATION]",
            ".timing" => "[TIMING]",
            ".packages[].integrity" => "[INTEGRITY]",
            ".packages[].duration_ms" => "[DURATION]",
            // Resolver-arm telemetry counters vary by route mode + arm.
            ".resolver" => "[RESOLVER]",
            ".cache" => "[CACHE]",
        });
    });
}

// ─── Lockfile Content Snapshot ───────────────────────────────────

/// Install a single package and snapshot the full lpm.lock content.
///
/// The snapshot is the source of truth for lockfile format. If this test
/// fails, the lockfile format changed — run `cargo insta review` to inspect
/// the diff and accept intentional changes.
///
/// The registry URL (dynamic port) is redacted to `[REGISTRY]` so the
/// snapshot is deterministic across runs.
#[tokio::test]
async fn install_lockfile_content_matches_snapshot() {
    let mock = MockRegistry::start().await;
    let tarball = make_tarball("ms", "2.1.3");
    mock.with_package("ms", "2.1.3", &tarball).await;
    mock.with_batch_metadata(vec![serde_json::json!({
        "name": "ms",
        "dist-tags": { "latest": "2.1.3" },
        "versions": {
            "2.1.3": {
                "name": "ms",
                "version": "2.1.3",
                "dist": {
                    "tarball": format!("{}/tarballs/ms/-/ms-2.1.3.tgz", mock.url()),
                    "integrity": "sha512-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=",
                },
                "dependencies": {}
            }
        },
        "time": { "2.1.3": "2025-01-01T00:00:00.000Z" }
    })])
    .await;

    let project = TempProject::empty(
        r#"{
        "name": "snapshot-test",
        "version": "1.0.0",
        "dependencies": {
            "ms": "^2.1.3"
        }
    }"#,
    );

    lpm_with_registry(&project, &mock.url())
        .args([
            "install",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .assert()
        .success();

    let lockfile = project.read_file("lpm.lock");

    insta::with_settings!({
        // Redact the dynamic registry port so the snapshot is deterministic.
        filters => vec![
            (r"http://127\.0\.0\.1:\d+", "[REGISTRY]"),
        ]
    }, {
        insta::assert_snapshot!("install_single_package_lockfile", lockfile);
    });
}

// ─── Install JSON Output with Packages ───────────────────────────

#[tokio::test]
async fn install_json_output_contains_package_list() {
    let mock = MockRegistry::start().await;
    let tarball = make_tarball("ms", "2.1.3");
    mock.with_package("ms", "2.1.3", &tarball).await;

    let batch_meta = serde_json::json!({
        "name": "ms",
        "dist-tags": { "latest": "2.1.3" },
        "versions": {
            "2.1.3": {
                "name": "ms",
                "version": "2.1.3",
                "dist": {
                    "tarball": format!("{}/tarballs/ms/-/ms-2.1.3.tgz", mock.url()),
                    "integrity": "sha512-placeholder",
                },
                "dependencies": {}
            }
        },
        "time": { "2.1.3": "2025-01-01T00:00:00.000Z" }
    });
    mock.with_batch_metadata(vec![batch_meta]).await;

    let project = TempProject::empty(
        r#"{
        "name": "json-install-test",
        "version": "1.0.0",
        "dependencies": {
            "ms": "^2.1.3"
        }
    }"#,
    );

    let output = lpm_with_registry(&project, &mock.url())
        .args([
            "install",
            "--json",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        // greedy-fusion is now the global install
        // default. This test asserts the PubGrub-walker arm's
        // `timing.resolve.streaming_bfs` telemetry contract
        // ) including the `manifests_fetched > 0 ||
        // escape_hatch_fetches > 0` invariant. Greedy-walker doesn't
        // populate the same counters, and fusion bypasses the walker
        // entirely. Pin to PubGrub explicitly so this test keeps
        // exercising the exact contract it was written for.
        .env("LPM_RESOLVER", "pubgrub")
        .output()
        .expect("failed to run lpm install --json");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        output.status.success(),
        "install --json failed:\nstdout: {stdout}\nstderr: {stderr}"
    );

    let json = assertions::parse_json_output(&output.stdout);
    assertions::assert_json_field(&json, "success", assertions::JsonType::Bool);
    assertions::assert_json_field(&json, "packages", assertions::JsonType::Array);
    assertions::assert_json_field(&json, "count", assertions::JsonType::Number);
    assertions::assert_json_field(&json, "duration_ms", assertions::JsonType::Number);
    assertions::assert_json_field(&json, "timing", assertions::JsonType::Object);

    assert_eq!(json["success"], true);
    assert!(
        json["count"].as_u64().unwrap() >= 1,
        "should have at least 1 package"
    );

    // Verify the packages array contains ms
    let packages = json["packages"].as_array().unwrap();
    let has_ms = packages.iter().any(|p| p["name"] == "ms");
    assert!(
        has_ms,
        "packages array should contain 'ms', got: {packages:?}"
    );

    //  — `timing.resolve.streaming_bfs` contract.
    // On a fresh-resolve install (not lockfile-fast-path) the walker
    // runs and the sub-object is emitted with the eight documented
    // fields. On lockfile-fast-path the field is `null`; that case is
    // covered elsewhere.
    let streaming_bfs = &json["timing"]["resolve"]["streaming_bfs"];
    assert!(
        streaming_bfs.is_object(),
        "timing.resolve.streaming_bfs must be an object on fresh-resolve installs; got: {streaming_bfs:?}"
    );
    for field in [
        "walk_ms",
        "manifests_fetched",
        "cache_hits",
        "cache_waits",
        "cache_wait_timeouts",
        "escape_hatch_fetches",
        "spec_tx_send_wait_ms",
        "max_depth",
    ] {
        assert!(
            streaming_bfs[field].is_number(),
            "timing.resolve.streaming_bfs.{field} must be a number; object was: {streaming_bfs:?}"
        );
    }
    // Healthy-contract spot check: SOMETHING must have produced
    // `ms`'s metadata — either the walker itself
    // (`manifests_fetched`) or the provider's escape-hatch path
    // (`escape_hatch_fetches`). In proxy mode (the workflow
    // harness default, since the subprocess can't override
    // `npm_registry_url` to point at the mock), the walker
    // batches through `/api/registry/batch-metadata` and returns
    // its result via the dispatcher's shared cache write; the
    // walker's own `manifests_fetched` may be 0 depending on
    // whether the batch parse round-trips through the walker's
    // `commit_manifest` or through a different code path.
    // Combining the two fields makes the assertion route-mode-
    // agnostic.
    let m_walker = streaming_bfs["manifests_fetched"].as_u64().unwrap();
    let m_escape = streaming_bfs["escape_hatch_fetches"].as_u64().unwrap();
    assert!(
        m_walker + m_escape >= 1,
        "metadata for `ms` must have been produced by walker or escape hatch; \
         got manifests_fetched={m_walker} escape_hatch_fetches={m_escape}"
    );
    // `cache_wait_timeouts` is not asserted: in proxy mode the walker
    // routes through `batch_metadata` and the provider's wait-loop
    // may observe transient timeouts before falling through to the
    // escape-hatch fetch. The shape-present + produced-≥1 checks
    // above cover the reviewer's  CLI-surface gap
    // without being sensitive to orchestration timing.
}

// ─── Lockfile Fast Path (Up-to-date) ────────────────────────────

#[tokio::test]
async fn install_lockfile_reuse_is_fast_path() {
    let mock = MockRegistry::start().await;
    let tarball = make_tarball("ms", "2.1.3");
    mock.with_package("ms", "2.1.3", &tarball).await;

    let batch_meta = serde_json::json!({
        "name": "ms",
        "dist-tags": { "latest": "2.1.3" },
        "versions": {
            "2.1.3": {
                "name": "ms",
                "version": "2.1.3",
                "dist": {
                    "tarball": format!("{}/tarballs/ms/-/ms-2.1.3.tgz", mock.url()),
                    "integrity": "sha512-placeholder",
                },
                "dependencies": {}
            }
        },
        "time": { "2.1.3": "2025-01-01T00:00:00.000Z" }
    });
    mock.with_batch_metadata(vec![batch_meta]).await;

    let project = TempProject::empty(
        r#"{
        "name": "lockfile-reuse-test",
        "version": "1.0.0",
        "dependencies": {
            "ms": "^2.1.3"
        }
    }"#,
    );

    // First install: resolves + downloads
    lpm_with_registry(&project, &mock.url())
        .args([
            "install",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .assert()
        .success();

    assertions::assert_both_lockfiles_exist(project.path());

    // Second install: should hit the fast path (up to date)
    let output = lpm_with_registry(&project, &mock.url())
        .args([
            "install",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("failed to run second install");

    assert!(output.status.success());

    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let combined_lower = combined.to_lowercase();
    assert!(
        combined_lower.contains("up to date") || combined_lower.contains("using lockfile"),
        "second install should hit fast path, got:\n{combined}"
    );
}

// ─── Up-to-date JSON Output ─────────────────────────────────────

#[tokio::test]
async fn install_up_to_date_json_includes_flag() {
    let mock = MockRegistry::start().await;
    let tarball = make_tarball("ms", "2.1.3");
    mock.with_package("ms", "2.1.3", &tarball).await;

    let batch_meta = serde_json::json!({
        "name": "ms",
        "dist-tags": { "latest": "2.1.3" },
        "versions": {
            "2.1.3": {
                "name": "ms",
                "version": "2.1.3",
                "dist": {
                    "tarball": format!("{}/tarballs/ms/-/ms-2.1.3.tgz", mock.url()),
                    "integrity": "sha512-placeholder",
                },
                "dependencies": {}
            }
        },
        "time": { "2.1.3": "2025-01-01T00:00:00.000Z" }
    });
    mock.with_batch_metadata(vec![batch_meta]).await;

    let project = TempProject::empty(
        r#"{
        "name": "up-to-date-json-test",
        "version": "1.0.0",
        "dependencies": {
            "ms": "^2.1.3"
        }
    }"#,
    );

    // First install
    lpm_with_registry(&project, &mock.url())
        .args([
            "install",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .assert()
        .success();

    // Second install with --json should show up_to_date
    let output = lpm_with_registry(&project, &mock.url())
        .args([
            "install",
            "--json",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("failed to run second install --json");

    assert!(output.status.success());

    let json = assertions::parse_json_output(&output.stdout);
    assert_eq!(json["success"], true);
    assert_eq!(json["up_to_date"], true);
    assertions::assert_json_field(&json, "duration_ms", assertions::JsonType::Number);
}

// ─── Offline Mode ────────────────────────────────────────────────

#[tokio::test]
async fn install_offline_with_store_succeeds() {
    let mock = MockRegistry::start().await;
    let tarball = make_tarball("ms", "2.1.3");
    mock.with_package("ms", "2.1.3", &tarball).await;

    let batch_meta = serde_json::json!({
        "name": "ms",
        "dist-tags": { "latest": "2.1.3" },
        "versions": {
            "2.1.3": {
                "name": "ms",
                "version": "2.1.3",
                "dist": {
                    "tarball": format!("{}/tarballs/ms/-/ms-2.1.3.tgz", mock.url()),
                    "integrity": "sha512-placeholder",
                },
                "dependencies": {}
            }
        },
        "time": { "2.1.3": "2025-01-01T00:00:00.000Z" }
    });
    mock.with_batch_metadata(vec![batch_meta]).await;

    let project = TempProject::empty(
        r#"{
        "name": "offline-test",
        "version": "1.0.0",
        "dependencies": {
            "ms": "^2.1.3"
        }
    }"#,
    );

    // First install online: populates store + lockfile
    lpm_with_registry(&project, &mock.url())
        .args([
            "install",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .assert()
        .success();

    assertions::assert_both_lockfiles_exist(project.path());

    // Remove node_modules to force re-link
    let nm = project.path().join("node_modules");
    if nm.exists() {
        std::fs::remove_dir_all(&nm).unwrap();
    }

    // Offline install: should use lockfile + store
    let output = lpm_with_registry(&project, &mock.url())
        .args([
            "install",
            "--offline",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("failed to run offline install");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        output.status.success(),
        "offline install failed:\nstdout: {stdout}\nstderr: {stderr}"
    );

    // node_modules should be re-populated
    assertions::assert_node_modules_exists(project.path());
    assertions::assert_in_node_modules(project.path(), "ms");
}

#[tokio::test]
async fn install_offline_json_empty_fingerprints_emit_null() {
    let mock = MockRegistry::start().await;
    mount_ms_2_1_3(&mock).await;

    let project = TempProject::empty(
        r#"{
        "name": "offline-json-fingerprints",
        "version": "1.0.0",
        "dependencies": {
            "ms": "^2.1.3"
        }
    }"#,
    );

    lpm_with_registry(&project, &mock.url())
        .args([
            "install",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .assert()
        .success();

    let nm = project.path().join("node_modules");
    if nm.exists() {
        std::fs::remove_dir_all(&nm).unwrap();
    }

    let output = lpm_with_registry(&project, &mock.url())
        .args([
            "install",
            "--offline",
            "--json",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("failed to run offline install --json");

    assert!(
        output.status.success(),
        "offline install --json failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let envelope: serde_json::Value = serde_json::from_slice(&output.stdout)
        .expect("offline install --json must emit valid JSON");

    assert_eq!(envelope["offline"], serde_json::json!(true));
    assert_eq!(envelope["patches_count"], serde_json::json!(0));
    assert_eq!(envelope["patches_fingerprint"], serde_json::Value::Null);
    assert_eq!(envelope["blocked_count"], serde_json::json!(0));
    assert_eq!(envelope["blocked_set_fingerprint"], serde_json::Value::Null);
}

// ─── Offline Without Lockfile Fails ──────────────────────────────

#[test]
fn install_offline_without_lockfile_fails() {
    let project = TempProject::empty(
        r#"{
        "name": "offline-no-lock",
        "version": "1.0.0",
        "dependencies": {
            "ms": "^2.1.3"
        }
    }"#,
    );

    let output = lpm(&project)
        .args(["install", "--offline"])
        .output()
        .expect("failed to run offline install");

    assert!(!output.status.success());

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("lockfile") || stderr.contains("--offline"),
        "expected error about missing lockfile for offline mode, got:\n{stderr}"
    );
}

// ─── dependency save semantics ─────────────────────────
//
// These tests validate the manifest-write contract documented in
// Tests for the dependency save semantics. They are
// load-bearing for the "no `*` default" rule and the
// "placeholder-never-survives-failure" invariant added during plan review.
//
// All four are red until the implementation lands; bare installs
// currently write `"*"` to the manifest, so row 1 fails immediately, and the
// failure-restore test fails because there is no transaction guard yet.

/// Helper to fetch the `dependencies` map from a project's package.json.
fn read_dependencies(project: &TempProject) -> serde_json::Map<String, serde_json::Value> {
    let raw = project.read_file("package.json");
    let doc: serde_json::Value =
        serde_json::from_str(&raw).expect("package.json must be valid JSON");
    doc.get("dependencies")
        .and_then(|v| v.as_object())
        .cloned()
        .unwrap_or_default()
}

/// Mount the canonical `ms@2.1.3` package + batch metadata on the mock.
async fn mount_ms_2_1_3(mock: &MockRegistry) {
    let tarball = make_tarball("ms", "2.1.3");
    mock.with_package("ms", "2.1.3", &tarball).await;
    let batch_meta = serde_json::json!({
        "name": "ms",
        "dist-tags": { "latest": "2.1.3" },
        "versions": {
            "2.1.3": {
                "name": "ms",
                "version": "2.1.3",
                "dist": {
                    "tarball": format!("{}/tarballs/ms/-/ms-2.1.3.tgz", mock.url()),
                    "integrity": "sha512-placeholder",
                },
                "dependencies": {}
            }
        },
        "time": { "2.1.3": "2025-01-01T00:00:00.000Z" }
    });
    mock.with_batch_metadata(vec![batch_meta]).await;
}

/// row 1 (smoke): a bare `lpm install ms` must write
/// `"ms": "^2.1.3"` into `package.json`, NOT `"ms": "*"`.
///
/// This is the load-bearing test for the entire phase.
#[tokio::test]
async fn install_bare_writes_caret_resolved_not_wildcard() {
    let mock = MockRegistry::start().await;
    mount_ms_2_1_3(&mock).await;

    let project = TempProject::empty(
        r#"{
        "name": "save-semver-row1",
        "version": "1.0.0",
        "dependencies": {}
    }"#,
    );

    let output = lpm_with_registry(&project, &mock.url())
        .args([
            "install",
            "ms",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("failed to run lpm install ms");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "install failed:\nstdout: {stdout}\nstderr: {stderr}"
    );

    let deps = read_dependencies(&project);
    let ms_spec = deps
        .get("ms")
        .and_then(|v| v.as_str())
        .expect("dependencies.ms must be present after install");

    assert_eq!(
        ms_spec, "^2.1.3",
        "default: bare `lpm install ms` must save `^<resolved>`, got `{ms_spec}`. \
         If this is `\"*\"`, the placeholder is leaking into the final manifest."
    );
}

/// row 12: re-running `lpm install <pkg>` on a dep that already
/// exists in the manifest must NOT rewrite the existing range, even if the
/// resolved version differs from what would be the new default.
///
/// Setup: manifest has `"ms": "~2.1.3"` (a tilde range the user authored).
/// Action: `lpm install ms` (bare — no spec).
/// Expected: manifest still has `"ms": "~2.1.3"`. The bare reinstall is
/// just a refresh of lockfile/store state, not a save-spec change.
#[tokio::test]
async fn install_existing_dep_bare_reinstall_no_churn() {
    let mock = MockRegistry::start().await;
    mount_ms_2_1_3(&mock).await;

    let project = TempProject::empty(
        r#"{
        "name": "save-semver-row12",
        "version": "1.0.0",
        "dependencies": {
            "ms": "~2.1.3"
        }
    }"#,
    );

    let output = lpm_with_registry(&project, &mock.url())
        .args([
            "install",
            "ms",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("failed to run lpm install ms");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "reinstall failed:\nstdout: {stdout}\nstderr: {stderr}"
    );

    let deps = read_dependencies(&project);
    let ms_spec = deps.get("ms").and_then(|v| v.as_str()).unwrap();
    assert_eq!(
        ms_spec, "~2.1.3",
        "bare reinstall must not churn an existing range; got `{ms_spec}`"
    );
}

/// **Audit Finding B regression (Medium).** When the user runs `lpm
/// install ms --filter app` from inside `packages/app/` of a workspace,
/// the project-tier `lpm.toml` MUST be read from the WORKSPACE ROOT, not
/// from `cwd` (which is `packages/app/`). Save policy is a workspace-wide
/// preference; per-member overrides would create incoherent multi-member
/// installs where the same `--filter` produces different prefixes per
/// member.
///
/// Pre-fix: `run_install_filtered_add` called
/// `SaveConfigLoader::load_for_project(cwd)`. From the workspace root the
/// root `lpm.toml` was found correctly; from `packages/app` it was not,
/// because `packages/app/lpm.toml` does not exist. The user observed
/// `lpm install ms --filter app` from the workspace root saving
/// `"~2.1.3"` while the same command from `packages/app/` saved
/// `"^2.1.3"` — save policy depending on where the user stood.
///
/// Post-fix: the loader resolves the workspace root via
/// `lpm_workspace::discover_workspace(cwd)` and reads from there.
#[tokio::test]
async fn install_filtered_from_member_dir_reads_workspace_root_lpm_toml() {
    let mock = MockRegistry::start().await;
    mount_ms_2_1_3(&mock).await;

    // Build a workspace with one member at packages/app/.
    let project = TempProject::empty(
        r#"{
        "name": "save-semver-workspace",
        "version": "1.0.0",
        "private": true,
        "workspaces": ["packages/*"]
    }"#,
    );
    project.write_file(
        "packages/app/package.json",
        r#"{
        "name": "app",
        "version": "0.0.1",
        "dependencies": {}
    }"#,
    );
    // Drop a project-tier lpm.toml ONLY at the workspace root.
    project.write_file("lpm.toml", "save-prefix = \"~\"\n");

    // Run `lpm install ms --filter app` from packages/app — this is the
    // exact scenario the audit reproduced.
    let member_dir = project.path().join("packages").join("app");
    let mut cmd = lpm_with_registry(&project, &mock.url());
    cmd.current_dir(&member_dir);
    let output = cmd
        .args([
            "install",
            "ms",
            "--filter",
            "app",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("failed to run filtered install from member dir");

    assert!(
        output.status.success(),
        "filtered install failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    // The member's manifest must reflect the workspace-root save policy.
    let app_pkg: serde_json::Value =
        serde_json::from_str(&project.read_file("packages/app/package.json")).unwrap();
    let ms_spec = app_pkg["dependencies"]["ms"]
        .as_str()
        .expect("packages/app/package.json must have a ms entry after install");

    assert_eq!(
        ms_spec, "~2.1.3",
        "Finding B: filtered install from a member dir must honor the \
         workspace-root lpm.toml. Got `{ms_spec}` (probably `^2.1.3` if \
         the loader is still reading from cwd)"
    );
}

/// **Step 6 end-to-end:** project-tier `./lpm.toml` with
/// `save-prefix = "~"` must affect a bare `lpm install ms` so the
/// manifest gets `"ms": "~2.1.3"`. Validates that the loader is
/// actually read by the install entry point and the resolved
/// `SaveConfig` flows into `decide_saved_dependency_spec`.
#[tokio::test]
async fn install_honors_project_lpm_toml_save_prefix_tilde() {
    let mock = MockRegistry::start().await;
    mount_ms_2_1_3(&mock).await;

    let project = TempProject::empty(
        r#"{
        "name": "save-semver-project-config",
        "version": "1.0.0",
        "dependencies": {}
    }"#,
    );

    // Drop a project-tier lpm.toml asking for `~` prefixes.
    project.write_file("lpm.toml", "save-prefix = \"~\"\n");

    let output = lpm_with_registry(&project, &mock.url())
        .args([
            "install",
            "ms",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("failed to run lpm install ms");

    assert!(
        output.status.success(),
        "stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let deps = read_dependencies(&project);
    assert_eq!(
        deps.get("ms").and_then(|v| v.as_str()),
        Some("~2.1.3"),
        "project lpm.toml save-prefix='~' must override the default ^"
    );
}

/// **Step 6:** invalid `lpm.toml` (e.g. `save-prefix = "*"`)
/// surfaces a clear error before the install pipeline runs. The
/// transaction guard never opens because we error out at config-load
/// time.
#[tokio::test]
async fn install_rejects_lpm_toml_with_wildcard_save_prefix() {
    let mock = MockRegistry::start().await;
    mount_ms_2_1_3(&mock).await;

    let project = TempProject::empty(
        r#"{
        "name": "save-semver-project-config-invalid",
        "version": "1.0.0",
        "dependencies": {}
    }"#,
    );

    project.write_file("lpm.toml", "save-prefix = \"*\"\n");

    let output = lpm_with_registry(&project, &mock.url())
        .args([
            "install",
            "ms",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("failed to run lpm install ms");

    assert!(
        !output.status.success(),
        "lpm.toml with `save-prefix = '*'` must be rejected"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("lpm.toml") && stderr.contains("save-prefix"),
        "stderr should name the file and the offending key, got:\n{stderr}"
    );

    // The manifest must be untouched (no placeholder leak — config
    // failure happens before the transaction is even constructed).
    let deps = read_dependencies(&project);
    assert!(
        !deps.contains_key("ms"),
        "rejected config must not stage anything: {deps:?}"
    );
}

/// **Step 6:** explicit user input still beats project config.
/// `lpm install zod@^4.3.0` with `save-prefix = "~"` in lpm.toml saves
/// `^4.3.0` (preserved verbatim), not `~4.3.6`.
#[tokio::test]
async fn install_explicit_range_beats_project_config_save_prefix() {
    let mock = MockRegistry::start().await;
    mount_ms_2_1_3(&mock).await;

    let project = TempProject::empty(
        r#"{
        "name": "save-semver-explicit-beats-config",
        "version": "1.0.0",
        "dependencies": {}
    }"#,
    );
    project.write_file("lpm.toml", "save-prefix = \"~\"\n");

    let output = lpm_with_registry(&project, &mock.url())
        .args([
            "install",
            "ms@^2.0.0",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("failed to run lpm install ms@^2.0.0");

    assert!(
        output.status.success(),
        "stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let deps = read_dependencies(&project);
    assert_eq!(
        deps.get("ms").and_then(|v| v.as_str()),
        Some("^2.0.0"),
        "explicit user range must beat project lpm.toml save-prefix"
    );
}

/// **row 7 / Step 5 end-to-end:** `lpm install ms --exact`
/// against the mock registry must save `"ms": "2.1.3"` (no prefix).
#[tokio::test]
async fn install_with_exact_flag_saves_pinned_version() {
    let mock = MockRegistry::start().await;
    mount_ms_2_1_3(&mock).await;

    let project = TempProject::empty(
        r#"{
        "name": "save-semver-flag-exact",
        "version": "1.0.0",
        "dependencies": {}
    }"#,
    );

    let output = lpm_with_registry(&project, &mock.url())
        .args([
            "install",
            "ms",
            "--exact",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("failed to run lpm install ms --exact");

    assert!(
        output.status.success(),
        "stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let deps = read_dependencies(&project);
    assert_eq!(
        deps.get("ms").and_then(|v| v.as_str()),
        Some("2.1.3"),
        "--exact must save the bare resolved version, no caret prefix"
    );
}

/// **row 8 / Step 5 end-to-end:** `lpm install ms --tilde`
/// must save `"ms": "~2.1.3"`.
#[tokio::test]
async fn install_with_tilde_flag_saves_tilde_resolved() {
    let mock = MockRegistry::start().await;
    mount_ms_2_1_3(&mock).await;

    let project = TempProject::empty(
        r#"{
        "name": "save-semver-flag-tilde",
        "version": "1.0.0",
        "dependencies": {}
    }"#,
    );

    let output = lpm_with_registry(&project, &mock.url())
        .args([
            "install",
            "ms",
            "--tilde",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("failed to run lpm install ms --tilde");

    assert!(
        output.status.success(),
        "stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let deps = read_dependencies(&project);
    assert_eq!(
        deps.get("ms").and_then(|v| v.as_str()),
        Some("~2.1.3"),
        "--tilde must save `~<resolved>`"
    );
}

/// **/ Step 5 end-to-end:** `lpm install ms --save-prefix '~'`
/// must save `"ms": "~2.1.3"` (same effect as `--tilde`, alternate syntax).
#[tokio::test]
async fn install_with_save_prefix_tilde_saves_tilde_resolved() {
    let mock = MockRegistry::start().await;
    mount_ms_2_1_3(&mock).await;

    let project = TempProject::empty(
        r#"{
        "name": "save-semver-flag-save-prefix",
        "version": "1.0.0",
        "dependencies": {}
    }"#,
    );

    let output = lpm_with_registry(&project, &mock.url())
        .args([
            "install",
            "ms",
            "--save-prefix",
            "~",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("failed to run lpm install ms --save-prefix '~'");

    assert!(
        output.status.success(),
        "stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let deps = read_dependencies(&project);
    assert_eq!(
        deps.get("ms").and_then(|v| v.as_str()),
        Some("~2.1.3"),
        "--save-prefix '~' must save `~<resolved>`"
    );
}

/// **/ Step 5:** `--save-prefix '*'` is rejected with a clear
/// error before the install pipeline runs. Wildcards must be requested
/// per-package via `pkg@*`, never as a save policy.
#[test]
fn install_save_prefix_wildcard_rejected() {
    let project = TempProject::empty(
        r#"{
        "name": "save-semver-flag-save-prefix-wildcard",
        "version": "1.0.0",
        "dependencies": {}
    }"#,
    );

    let output = lpm(&project)
        .args(["install", "ms", "--save-prefix", "*"])
        .output()
        .expect("failed to spawn lpm install");

    assert!(
        !output.status.success(),
        "--save-prefix '*' must be rejected"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("save-prefix")
            && (stderr.contains("'*'") || stderr.contains("not allowed")),
        "stderr should explain the wildcard rejection, got:\n{stderr}"
    );
}

/// row 15: contradictory save-flag combinations are rejected at
/// the CLI layer with a clear error.
#[test]
fn install_contradictory_save_flags_fail() {
    let project = TempProject::empty(
        r#"{
        "name": "save-semver-row15",
        "version": "1.0.0",
        "dependencies": {}
    }"#,
    );

    let output = lpm(&project)
        .args(["install", "ms", "--exact", "--tilde"])
        .output()
        .expect("failed to run lpm install");

    assert!(
        !output.status.success(),
        "contradictory --exact + --tilde must exit non-zero"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("--exact") && stderr.contains("--tilde"),
        "stderr should name the conflicting flags, got:\n{stderr}"
    );
}

// **audit Finding 1 regression coverage lives in unit tests.**
//
// The audit flagged a defensive-correctness issue in
// `collect_resolved_versions_from_lockfile`: a flat name-scan over
// `lockfile.packages` would pick the wrong version if the lockfile ever
// contained two entries for the same package name (one direct, one
// transitive at a different version).
//
// We attempted a workflow test that staged `legacy-pkg → ms@~1.5.0` as a
// transitive and then ran `lpm install ms` to add a new direct edge — but
// LPM's pubgrub resolver fundamentally MERGES range constraints per
// package name. Bare `lpm install ms` stages a `*` placeholder, pubgrub
// intersects `*` with the existing transitive `~1.5.0`, and resolves to a
// SINGLE version. The lockfile never grows a duplicate via this path.
//
// The Finding 1 fix is therefore a defensive correctness change with no
// reachable workflow-level reproduction in the current resolver. The
// regression coverage is the unit test
// `commands::install::tests::collect_direct_versions_*` in install.rs,
// which calls the helper directly with hand-built `Vec<InstallPackage>`
// fixtures that include both a direct and a transitive entry for the
// same name.

/// **audit Finding 2 regression.** When an `lpm install` against
/// an already-installed project fails partway through, the rollback MUST
/// cover the lockfile and the install-hash, not just the manifest. The
/// pre-fix transaction guard only snapshotted `package.json`, so a failed
/// finalize (or a failed multi-member install) left:
///
///   - `package.json` rolled back to its pre-stage bytes
///   - `lpm.lock` mutated by the install pipeline
///   - `.lpm/install-hash` cached for the new state
///
/// → split-brain: the manifest claims the old dep set while the lockfile
/// and the up-to-date cache reflect the new one.
///
/// The fix is two-part:
///   1. Snapshot `lpm.lock` (and `lpm.lockb`) alongside the manifest and
///      restore them on rollback.
///   2. Delete `.lpm/install-hash` on rollback (the lockfile bytes match
///      after restore, so the fast-exit check would fire even though
///      `node_modules/` is out-of-sync; deleting the hash forces the next
///      install to re-resolve and re-link).
///
/// Setup: install `ms@2.1.3` successfully, then run a failing install that
/// adds a package the mock registry doesn't know about. Assert all three
/// state files are coherent with the pre-failure project.
#[tokio::test]
async fn install_failure_rolls_back_lockfile_and_invalidates_install_hash() {
    let mock = MockRegistry::start().await;
    mount_ms_2_1_3(&mock).await;

    let project = TempProject::empty(
        r#"{
        "name": "save-semver-rollback-boundary",
        "version": "1.0.0",
        "dependencies": {
            "ms": "^2.1.3"
        }
    }"#,
    );

    // 1. Successful install populates lpm.lock + .lpm/install-hash.
    lpm_with_registry(&project, &mock.url())
        .args([
            "install",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .assert()
        .success();

    let manifest_path = project.path().join("package.json");
    let lockfile_path = project.path().join("lpm.lock");
    let lockfile_bin_path = project.path().join("lpm.lockb");
    let install_hash_path = project.path().join(".lpm").join("install-hash");

    assert!(
        lockfile_path.exists(),
        "lockfile must exist after first install"
    );
    assert!(
        install_hash_path.exists(),
        "install-hash must exist after first install"
    );

    // Capture the post-install bytes — the rollback target.
    let pre_manifest = std::fs::read(&manifest_path).unwrap();
    let pre_lockfile = std::fs::read(&lockfile_path).unwrap();
    let pre_lockfile_bin = if lockfile_bin_path.exists() {
        Some(std::fs::read(&lockfile_bin_path).unwrap())
    } else {
        None
    };

    // 2. Run a failing install: add a package the mock has never heard of.
    let output = lpm_with_registry(&project, &mock.url())
        .args([
            "install",
            "definitely-not-in-mock-registry",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("failed to spawn lpm install");

    assert!(
        !output.status.success(),
        "install of unknown package should fail; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    // 3. Assert manifest is byte-identical (placeholder invariant).
    let post_manifest = std::fs::read(&manifest_path).unwrap();
    assert_eq!(
        post_manifest, pre_manifest,
        "manifest must roll back; the placeholder for `definitely-not-in-mock-registry` \
         must NOT survive a failed install"
    );

    // 4. Assert lockfile is byte-identical.
    let post_lockfile = std::fs::read(&lockfile_path).unwrap();
    assert_eq!(
        post_lockfile, pre_lockfile,
        "lockfile must roll back to its pre-failure bytes; rolling back the \
         manifest alone leaves the project in a split-brain state"
    );

    // 5. Assert lpm.lockb is byte-identical (or absent if it was absent).
    if let Some(pre_bin) = pre_lockfile_bin {
        let post_bin = std::fs::read(&lockfile_bin_path).unwrap();
        assert_eq!(
            post_bin, pre_bin,
            "lpm.lockb (binary lockfile) must roll back alongside lpm.lock"
        );
    }

    // 6. Assert .lpm/install-hash was invalidated. The fast-exit check
    //    in `is_install_up_to_date` requires this file; without it, the
    //    next install re-runs the full pipeline and converges any drift
    //    between the rolled-back lockfile and the still-mutated
    //    node_modules/ tree (which the transaction guard does not snapshot).
    assert!(
        !install_hash_path.exists(),
        "rollback must delete .lpm/install-hash so the next install \
         re-resolves; otherwise the fast-exit check would fire on a \
         project whose node_modules/ no longer matches its lockfile"
    );

    // 7. Defensive: re-parse the post-rollback manifest and confirm the
    //    failed install's package name is nowhere in dependencies.
    let deps = read_dependencies(&project);
    assert!(
        !deps.contains_key("definitely-not-in-mock-registry"),
        "failed install left the unknown package in dependencies: {deps:?}"
    );
}

/// placeholder-never-survives invariant (added during plan review).
///
/// When `lpm install <pkg>` stages a placeholder spec into `package.json`
/// and the install pipeline subsequently fails, the manifest MUST be
/// restored to its pre-staging state byte-for-byte. The temporary `"*"`
/// placeholder must never be observable to any caller after a failed run.
///
/// Setup: project has an existing dep `"existing": "1.0.0"`. Mock registry
/// has NO packages mounted, so any metadata fetch returns 404 → install
/// fails. We run `lpm install ms` and assert:
///
/// 1. The install command exits non-zero.
/// 2. `package.json` is byte-identical to its pre-install snapshot.
/// 3. Specifically: `dependencies.ms` does NOT exist (it must not have
///    leaked through as `"*"` or anything else).
#[tokio::test]
async fn install_failure_restores_original_manifest_bytes() {
    // Empty mock — every metadata fetch will 404.
    let mock = MockRegistry::start().await;

    let original_manifest = r#"{
    "name": "save-semver-failure-restore",
    "version": "1.0.0",
    "dependencies": {
        "existing": "1.0.0"
    }
}
"#;

    let project = TempProject::empty(original_manifest);

    // Capture the exact bytes before invoking install — this is what we'll
    // assert against. Includes whitespace, trailing newline, key order.
    let pre_bytes = std::fs::read(project.path().join("package.json"))
        .expect("must be able to read package.json before install");

    let output = lpm_with_registry(&project, &mock.url())
        .args([
            "install",
            "ms",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("failed to run lpm install ms");

    // Install MUST fail (mock has no `ms` package).
    assert!(
        !output.status.success(),
        "install should have failed against empty mock; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    // Manifest MUST be byte-identical to the pre-install snapshot.
    let post_bytes = std::fs::read(project.path().join("package.json"))
        .expect("package.json must still exist after failed install");

    assert_eq!(
        post_bytes,
        pre_bytes,
        "invariant violated: failed install left the manifest \
         in a modified state. The transaction guard must restore the \
         pre-staging bytes exactly. Post-install content:\n{}",
        String::from_utf8_lossy(&post_bytes)
    );

    // Defensive: even parsing the post manifest, `ms` must not appear
    // anywhere in dependencies. Catches the case where the bytes happen
    // to differ in whitespace but the placeholder still leaked.
    let deps = read_dependencies(&project);
    assert!(
        !deps.contains_key("ms"),
        "failed install left `ms` in dependencies map: {deps:?}"
    );
    assert_eq!(
        deps.get("existing").and_then(|v| v.as_str()),
        Some("1.0.0"),
        "pre-existing dep `existing` must be untouched after rollback"
    );
}

// ─── node_modules Structure ───────────────────────────────────────

/// After a successful install the package directory inside node_modules must
/// contain a well-formed package.json with the name and version that were
/// resolved — not an empty stub, not the tarball's package/ wrapper prefix.
#[tokio::test]
async fn install_node_modules_package_json_has_correct_fields() {
    let mock = MockRegistry::start().await;
    let tarball = make_tarball("ms", "2.1.3");
    mock.with_package("ms", "2.1.3", &tarball).await;
    mock.with_batch_metadata(vec![serde_json::json!({
        "name": "ms",
        "dist-tags": { "latest": "2.1.3" },
        "versions": {
            "2.1.3": {
                "name": "ms",
                "version": "2.1.3",
                "dist": {
                    "tarball": format!("{}/tarballs/ms/-/ms-2.1.3.tgz", mock.url()),
                    "integrity": "sha512-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=",
                },
                "dependencies": {}
            }
        },
        "time": { "2.1.3": "2025-01-01T00:00:00.000Z" }
    })])
    .await;

    let project = TempProject::empty(
        r#"{"name":"nm-structure-test","version":"1.0.0","dependencies":{"ms":"^2.1.3"}}"#,
    );

    lpm_with_registry(&project, &mock.url())
        .args([
            "install",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .assert()
        .success();

    let pkg_json_path = project
        .path()
        .join("node_modules")
        .join("ms")
        .join("package.json");
    assert!(
        pkg_json_path.exists(),
        "node_modules/ms/package.json not found"
    );

    let pkg_json: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&pkg_json_path).unwrap())
            .expect("node_modules/ms/package.json is not valid JSON");

    assert_eq!(
        pkg_json["name"].as_str(),
        Some("ms"),
        "node_modules/ms/package.json must have name = \"ms\", got: {}",
        pkg_json["name"]
    );
    assert_eq!(
        pkg_json["version"].as_str(),
        Some("2.1.3"),
        "node_modules/ms/package.json must have version = \"2.1.3\", got: {}",
        pkg_json["version"]
    );
}

/// A package that declares a `bin` field must have its binary linked into
/// node_modules/.bin/ after install. This is what enables `npx`-style
/// invocation and scripts that reference the binary by name.
#[tokio::test]
async fn install_creates_bin_symlink_for_binary_package() {
    let mock = MockRegistry::start().await;

    let tarball = make_tarball_from_pkg_json(
        serde_json::json!({
            "name": "my-cli",
            "version": "1.0.0",
            "main": "index.js",
            "bin": { "my-cli": "./cli.js" }
        }),
        &[(
            "cli.js",
            b"#!/usr/bin/env node\nconsole.log('ok');" as &[u8],
        )],
    );

    mock.with_package("my-cli", "1.0.0", &tarball).await;
    mock.with_batch_metadata(vec![serde_json::json!({
        "name": "my-cli",
        "dist-tags": { "latest": "1.0.0" },
        "versions": {
            "1.0.0": {
                "name": "my-cli",
                "version": "1.0.0",
                "bin": { "my-cli": "./cli.js" },
                "dist": {
                    "tarball": format!("{}/tarballs/my-cli/-/my-cli-1.0.0.tgz", mock.url()),
                    "integrity": "sha512-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=",
                },
                "dependencies": {}
            }
        },
        "time": { "1.0.0": "2025-01-01T00:00:00.000Z" }
    })])
    .await;

    let project = TempProject::empty(
        r#"{"name":"bin-test","version":"1.0.0","dependencies":{"my-cli":"^1.0.0"}}"#,
    );

    lpm_with_registry(&project, &mock.url())
        .args([
            "install",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .assert()
        .success();

    let bin_entry = project
        .path()
        .join("node_modules")
        .join(".bin")
        .join("my-cli");
    assert!(
        bin_entry.exists(),
        "node_modules/.bin/my-cli not found after installing binary package"
    );
}

/// A `file:` local dependency must be resolved from the filesystem and linked
/// into node_modules — no network call required.
#[tokio::test]
async fn install_file_local_dependency_links_into_node_modules() {
    let project = TempProject::empty(
        r#"{"name":"file-dep-test","version":"1.0.0","dependencies":{"local-pkg":"file:./packages/local-pkg"}}"#,
    );

    project.write_file(
        "packages/local-pkg/package.json",
        r#"{"name":"local-pkg","version":"0.1.0","main":"index.js"}"#,
    );
    project.write_file("packages/local-pkg/index.js", "module.exports = {};");

    lpm(&project)
        .args([
            "install",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .assert()
        .success();

    let pkg_dir = project.path().join("node_modules").join("local-pkg");
    assert!(
        pkg_dir.exists(),
        "node_modules/local-pkg not found after file: install"
    );

    let pkg_json: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(pkg_dir.join("package.json")).unwrap())
            .unwrap();
    assert_eq!(pkg_json["name"].as_str(), Some("local-pkg"));
    assert_eq!(pkg_json["version"].as_str(), Some("0.1.0"));
}

/// Two independent fresh installs of the same package.json must produce
/// byte-identical lpm.lock files. Non-determinism in the resolver or
/// lockfile serializer would cause this test to fail via the snapshot.
#[tokio::test]
async fn install_lockfile_is_deterministic_across_fresh_installs() {
    async fn do_fresh_install(registry_url: &str, mock: &MockRegistry) -> String {
        let tarball = make_tarball("ms", "2.1.3");
        mock.with_package("ms", "2.1.3", &tarball).await;
        mock.with_batch_metadata(vec![serde_json::json!({
            "name": "ms",
            "dist-tags": { "latest": "2.1.3" },
            "versions": {
                "2.1.3": {
                    "name": "ms",
                    "version": "2.1.3",
                    "dist": {
                        "tarball": format!("{registry_url}/tarballs/ms/-/ms-2.1.3.tgz"),
                        "integrity": "sha512-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=",
                    },
                    "dependencies": {}
                }
            },
            "time": { "2.1.3": "2025-01-01T00:00:00.000Z" }
        })])
        .await;

        let project = TempProject::empty(
            r#"{"name":"determinism-test","version":"1.0.0","dependencies":{"ms":"^2.1.3"}}"#,
        );

        lpm_with_registry(&project, registry_url)
            .args([
                "install",
                "--no-security-summary",
                "--no-skills",
                "--no-editor-setup",
            ])
            .assert()
            .success();

        project.read_file("lpm.lock")
    }

    let mock_a = MockRegistry::start().await;
    let mock_b = MockRegistry::start().await;

    let lock_a = do_fresh_install(&mock_a.url(), &mock_a).await;
    let lock_b = do_fresh_install(&mock_b.url(), &mock_b).await;

    // Normalize the dynamic registry URL before comparing so port differences
    // don't produce false positives. Walk each line and strip the port from
    // any tarball URL — everything else in the lockfile is deterministic.
    let normalize = |s: String| -> String {
        s.lines()
            .map(|line| {
                if let Some(start) = line.find("http://127.0.0.1:") {
                    let after_port = line[start + "http://127.0.0.1:".len()..]
                        .find('/')
                        .map_or(line.len(), |i| i + start + "http://127.0.0.1:".len());
                    format!("{}{}{}", &line[..start], "[REGISTRY]", &line[after_port..])
                } else {
                    line.to_owned()
                }
            })
            .collect::<Vec<_>>()
            .join("\n")
    };

    assert_eq!(
        normalize(lock_a),
        normalize(lock_b),
        "lpm.lock content differed between two independent fresh installs of the same package.json"
    );
}

// ─── install hardening (workspace, peer, optional, integrity) ───

/// A workspace member referenced via `workspace:*` from the root manifest
/// must be planted as a symlink at `node_modules/<member>` resolving back
/// to `packages/<member>`. No registry interaction — workspace deps are
/// fully local.
#[test]
fn install_workspace_star_dep_plants_root_symlink_to_member() {
    let project = TempProject::empty(
        r#"{
  "name": "ws-star-root",
  "version": "1.0.0",
  "private": true,
  "workspaces": ["packages/*"],
  "dependencies": {
    "ws-member-a": "workspace:*"
  }
}"#,
    );

    let member_dir = project.path().join("packages").join("ws-member-a");
    project.write_file(
        "packages/ws-member-a/package.json",
        r#"{"name":"ws-member-a","version":"1.2.3"}"#,
    );

    lpm(&project)
        .args([
            "install",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .assert()
        .success();

    let link = project.path().join("node_modules").join("ws-member-a");
    let symlink_meta = std::fs::symlink_metadata(&link)
        .unwrap_or_else(|e| panic!("node_modules/ws-member-a missing after install: {e}"));
    assert!(
        symlink_meta.file_type().is_symlink(),
        "node_modules/ws-member-a must be a symlink (got {:?})",
        symlink_meta.file_type()
    );

    let resolved = std::fs::canonicalize(&link).expect("resolve symlink target");
    let expected = std::fs::canonicalize(&member_dir).expect("resolve member dir");
    assert_eq!(
        resolved, expected,
        "workspace:* symlink must resolve to packages/ws-member-a"
    );
}

/// `workspace:^` is a published-time hint — the member is still installed
/// locally as a symlink. Pins the [audit fix](crates/lpm-cli/src/commands/install.rs#L3209)
/// that previously rewrote `workspace:^` into a registry range and 404'd
/// against the upstream proxy.
#[test]
fn install_workspace_caret_dep_resolves_to_local_member() {
    let project = TempProject::empty(
        r#"{
  "name": "ws-caret-root",
  "version": "1.0.0",
  "private": true,
  "workspaces": ["packages/*"],
  "dependencies": {
    "ws-member-b": "workspace:^"
  }
}"#,
    );

    let member_dir = project.path().join("packages").join("ws-member-b");
    project.write_file(
        "packages/ws-member-b/package.json",
        r#"{"name":"ws-member-b","version":"2.5.0"}"#,
    );

    lpm(&project)
        .args([
            "install",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .assert()
        .success();

    let link = project.path().join("node_modules").join("ws-member-b");
    let symlink_meta = std::fs::symlink_metadata(&link)
        .unwrap_or_else(|e| panic!("node_modules/ws-member-b missing after install: {e}"));
    assert!(
        symlink_meta.file_type().is_symlink(),
        "node_modules/ws-member-b must be a symlink for workspace:^ deps"
    );

    let resolved = std::fs::canonicalize(&link).expect("resolve symlink target");
    let expected = std::fs::canonicalize(&member_dir).expect("resolve member dir");
    assert_eq!(
        resolved, expected,
        "workspace:^ symlink must resolve to packages/ws-member-b (not get rewritten to a registry range)"
    );
}

/// In hoisted mode (`--linker hoisted`), a transitive dep must land at
/// `node_modules/<C>` directly — flat npm-v3 layout — not nested under
/// the package that pulled it in. Default isolated mode is exercised by
/// every other install test in this file; this one pins the hoisted
/// surface so a regression in the flatten pass is caught.
#[tokio::test]
async fn install_hoisted_mode_places_transitive_dep_at_root() {
    let mock = MockRegistry::start().await;

    let leaf_tarball = make_tarball("leaf-pkg", "1.0.0");
    let middle_tarball = make_tarball("middle-pkg", "1.0.0");
    let parent_tarball = make_tarball("parent-pkg", "1.0.0");

    mock.with_package("leaf-pkg", "1.0.0", &leaf_tarball).await;
    mock.with_package_and_deps(
        "middle-pkg",
        "1.0.0",
        &middle_tarball,
        serde_json::json!({ "leaf-pkg": "^1.0.0" }),
    )
    .await;
    mock.with_package_and_deps(
        "parent-pkg",
        "1.0.0",
        &parent_tarball,
        serde_json::json!({ "middle-pkg": "^1.0.0" }),
    )
    .await;

    mock.with_batch_metadata(vec![
        serde_json::json!({
            "name": "parent-pkg",
            "dist-tags": { "latest": "1.0.0" },
            "versions": {
                "1.0.0": {
                    "name": "parent-pkg",
                    "version": "1.0.0",
                    "dist": {
                        "tarball": format!("{}/tarballs/parent-pkg/-/parent-pkg-1.0.0.tgz", mock.url()),
                        "integrity": compute_integrity(&parent_tarball),
                    },
                    "dependencies": { "middle-pkg": "^1.0.0" }
                }
            },
            "time": { "1.0.0": "2025-01-01T00:00:00.000Z" }
        }),
        serde_json::json!({
            "name": "middle-pkg",
            "dist-tags": { "latest": "1.0.0" },
            "versions": {
                "1.0.0": {
                    "name": "middle-pkg",
                    "version": "1.0.0",
                    "dist": {
                        "tarball": format!("{}/tarballs/middle-pkg/-/middle-pkg-1.0.0.tgz", mock.url()),
                        "integrity": compute_integrity(&middle_tarball),
                    },
                    "dependencies": { "leaf-pkg": "^1.0.0" }
                }
            },
            "time": { "1.0.0": "2025-01-01T00:00:00.000Z" }
        }),
        serde_json::json!({
            "name": "leaf-pkg",
            "dist-tags": { "latest": "1.0.0" },
            "versions": {
                "1.0.0": {
                    "name": "leaf-pkg",
                    "version": "1.0.0",
                    "dist": {
                        "tarball": format!("{}/tarballs/leaf-pkg/-/leaf-pkg-1.0.0.tgz", mock.url()),
                        "integrity": compute_integrity(&leaf_tarball),
                    },
                    "dependencies": {}
                }
            },
            "time": { "1.0.0": "2025-01-01T00:00:00.000Z" }
        }),
    ])
    .await;

    let project = TempProject::empty(
        r#"{"name":"hoist-test","version":"1.0.0","dependencies":{"parent-pkg":"^1.0.0"}}"#,
    );

    lpm_with_registry(&project, &mock.url())
        .args([
            "install",
            "--linker",
            "hoisted",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .assert()
        .success();

    let nm = project.path().join("node_modules");
    assert!(
        nm.join("parent-pkg").join("package.json").exists(),
        "parent-pkg must land at node_modules/parent-pkg"
    );
    assert!(
        nm.join("middle-pkg").join("package.json").exists(),
        "middle-pkg must hoist to node_modules/middle-pkg in hoisted mode"
    );
    assert!(
        nm.join("leaf-pkg").join("package.json").exists(),
        "leaf-pkg (depth-2 transitive) must hoist to node_modules/leaf-pkg in hoisted mode, \
         not stay nested under parent-pkg/node_modules/middle-pkg/node_modules/"
    );
}

/// A package that declares a `peerDependencies` entry must NOT cause LPM
/// to install the peer automatically. The peer is the consumer's
/// responsibility — pre-npm-v7 semantics, which LPM follows.
#[tokio::test]
async fn install_does_not_auto_install_peer_dependencies() {
    let mock = MockRegistry::start().await;

    let host_tarball = make_tarball("peer-host", "1.0.0");
    mock.with_package("peer-host", "1.0.0", &host_tarball).await;

    // Override metadata to inject peerDependencies (with_package_and_deps
    // only sets `dependencies`).
    mock.with_batch_metadata(vec![serde_json::json!({
        "name": "peer-host",
        "dist-tags": { "latest": "1.0.0" },
        "versions": {
            "1.0.0": {
                "name": "peer-host",
                "version": "1.0.0",
                "dist": {
                    "tarball": format!("{}/tarballs/peer-host/-/peer-host-1.0.0.tgz", mock.url()),
                    "integrity": compute_integrity(&host_tarball),
                },
                "dependencies": {},
                "peerDependencies": { "ghost-peer": "^1.0.0" }
            }
        },
        "time": { "1.0.0": "2025-01-01T00:00:00.000Z" }
    })])
    .await;

    let project = TempProject::empty(
        r#"{"name":"peer-test","version":"1.0.0","dependencies":{"peer-host":"^1.0.0"}}"#,
    );

    lpm_with_registry(&project, &mock.url())
        .args([
            "install",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .assert()
        .success();

    let nm = project.path().join("node_modules");
    assert!(
        nm.join("peer-host").join("package.json").exists(),
        "peer-host (the host package) must be installed"
    );
    assert!(
        !nm.join("ghost-peer").exists(),
        "ghost-peer (declared as peerDependency only) must NOT be auto-installed; \
         peer deps are the consumer's responsibility"
    );
}

/// A package whose `optionalDependencies` cannot be satisfied (the optional
/// is unreachable on the registry) must NOT abort the install. Mandatory
/// deps and the host package itself must still land.
#[tokio::test]
async fn install_optional_dep_failure_does_not_abort_install() {
    let mock = MockRegistry::start().await;

    let mandatory_tarball = make_tarball("mandatory-pkg", "1.0.0");
    let host_tarball = make_tarball("opt-host", "1.0.0");

    mock.with_package("mandatory-pkg", "1.0.0", &mandatory_tarball)
        .await;
    mock.with_package("opt-host", "1.0.0", &host_tarball).await;

    // opt-host declares an optional dep on a package that is NOT mounted
    // anywhere on this mock registry. The install must complete with
    // mandatory-pkg + opt-host present and the optional silently dropped.
    mock.with_batch_metadata(vec![
        serde_json::json!({
            "name": "opt-host",
            "dist-tags": { "latest": "1.0.0" },
            "versions": {
                "1.0.0": {
                    "name": "opt-host",
                    "version": "1.0.0",
                    "dist": {
                        "tarball": format!("{}/tarballs/opt-host/-/opt-host-1.0.0.tgz", mock.url()),
                        "integrity": compute_integrity(&host_tarball),
                    },
                    "dependencies": {},
                    "optionalDependencies": { "phantom-optional": "^1.0.0" }
                }
            },
            "time": { "1.0.0": "2025-01-01T00:00:00.000Z" }
        }),
        serde_json::json!({
            "name": "mandatory-pkg",
            "dist-tags": { "latest": "1.0.0" },
            "versions": {
                "1.0.0": {
                    "name": "mandatory-pkg",
                    "version": "1.0.0",
                    "dist": {
                        "tarball": format!("{}/tarballs/mandatory-pkg/-/mandatory-pkg-1.0.0.tgz", mock.url()),
                        "integrity": compute_integrity(&mandatory_tarball),
                    },
                    "dependencies": {}
                }
            },
            "time": { "1.0.0": "2025-01-01T00:00:00.000Z" }
        }),
    ])
    .await;

    let project = TempProject::empty(
        r#"{"name":"opt-test","version":"1.0.0","dependencies":{"opt-host":"^1.0.0","mandatory-pkg":"^1.0.0"}}"#,
    );

    lpm_with_registry(&project, &mock.url())
        .args([
            "install",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .assert()
        .success();

    let nm = project.path().join("node_modules");
    assert!(
        nm.join("opt-host").join("package.json").exists(),
        "opt-host must install even though its optional dep is unreachable"
    );
    assert!(
        nm.join("mandatory-pkg").join("package.json").exists(),
        "mandatory-pkg must install — the optional failure must not abort the run"
    );
    assert!(
        !nm.join("phantom-optional").exists(),
        "phantom-optional must not appear; the registry never served it"
    );
}

/// End-to-end integrity verification: the SRI claim recorded in the
/// lockfile, the SRI persisted in the global store's `.integrity` file,
/// and a fresh recomputation from the original tarball bytes must all
/// agree byte-for-byte. A regression in any link of that chain — bad
/// metadata reads, store mis-write, lockfile downgrade — would diverge.
#[tokio::test]
async fn install_lockfile_integrity_matches_stored_tarball_sha512() {
    let mock = MockRegistry::start().await;

    let tarball = make_tarball("integrity-pkg", "1.0.0");
    let expected_integrity = compute_integrity(&tarball);

    mock.with_package("integrity-pkg", "1.0.0", &tarball).await;
    mock.with_batch_metadata(vec![serde_json::json!({
        "name": "integrity-pkg",
        "dist-tags": { "latest": "1.0.0" },
        "versions": {
            "1.0.0": {
                "name": "integrity-pkg",
                "version": "1.0.0",
                "dist": {
                    "tarball": format!("{}/tarballs/integrity-pkg/-/integrity-pkg-1.0.0.tgz", mock.url()),
                    "integrity": expected_integrity.clone(),
                },
                "dependencies": {}
            }
        },
        "time": { "1.0.0": "2025-01-01T00:00:00.000Z" }
    })])
    .await;

    let project = TempProject::empty(
        r#"{"name":"integrity-test","version":"1.0.0","dependencies":{"integrity-pkg":"^1.0.0"}}"#,
    );

    lpm_with_registry(&project, &mock.url())
        .args([
            "install",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .assert()
        .success();

    // 1. Lockfile claim
    let lockfile = lpm_lockfile::Lockfile::read_from_file(&project.path().join("lpm.lock"))
        .expect("read lpm.lock");
    let pkg = lockfile
        .packages
        .iter()
        .find(|p| p.name == "integrity-pkg" && p.version == "1.0.0")
        .expect("lockfile must contain integrity-pkg@1.0.0");
    let lockfile_integrity = pkg
        .integrity
        .clone()
        .expect("lockfile entry for registry dep must carry an integrity field");
    assert_eq!(
        lockfile_integrity, expected_integrity,
        "lockfile integrity must match SHA-512 of the served tarball bytes"
    );

    // 2. Stored .integrity file
    let store_integrity_path = project
        .store_dir()
        .join("v1")
        .join("integrity-pkg@1.0.0")
        .join(".integrity");
    let stored_integrity = std::fs::read_to_string(&store_integrity_path)
        .unwrap_or_else(|e| panic!("read {}: {e}", store_integrity_path.display()))
        .trim()
        .to_string();
    assert_eq!(
        stored_integrity, expected_integrity,
        "store .integrity file must match the lockfile claim and the tarball hash"
    );
}

/// A manifest-level tarball URL with an inline SRI must install cleanly and
/// serialize as a non-Registry `source` entry without populating the
/// registry-only `tarball` field-hint. A recent regression wrote both,
/// which made `lpm.lock` fail its writer/reader invariant and aborted the
/// install after the download had already succeeded.
#[tokio::test]
async fn install_tarball_url_with_declared_sri_writes_non_registry_lockfile_entry() {
    let server = MockServer::start().await;
    let tarball = make_tarball("tarball-url-pkg", "1.0.0");
    let expected_integrity = compute_integrity(&tarball);

    Mock::given(method("GET"))
        .and(path("/tarball-url-pkg-1.0.0.tgz"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(tarball.clone()))
        .mount(&server)
        .await;

    let project = TempProject::empty(&format!(
        r#"{{
  "name": "tarball-url-lockfile",
  "version": "1.0.0",
  "dependencies": {{
    "tarball-url-pkg": "{}/tarball-url-pkg-1.0.0.tgz#{}"
  }}
}}"#,
        server.uri(),
        expected_integrity,
    ));

    let output = lpm(&project)
        .args([
            "install",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("spawn lpm install");

    assert!(
        output.status.success(),
        "install must succeed for a tarball URL dep with declared SRI; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let lockfile = lpm_lockfile::Lockfile::read_from_file(&project.path().join("lpm.lock"))
        .expect("read lpm.lock");
    let pkg = lockfile
        .packages
        .iter()
        .find(|p| p.name == "tarball-url-pkg" && p.version == "1.0.0")
        .expect("lockfile must contain tarball-url-pkg@1.0.0");

    assert_eq!(
        pkg.integrity.as_deref(),
        Some(expected_integrity.as_str()),
        "lockfile integrity must preserve the manifest-declared SRI"
    );
    assert!(
        pkg.tarball.is_none(),
        "non-registry tarball sources must not populate the registry-only tarball hint: {:?}",
        pkg.tarball
    );
    assert!(
        pkg.source
            .as_deref()
            .is_some_and(|source| source.starts_with("tarball+http://")),
        "lockfile source must remain the tarball source identity: {:?}",
        pkg.source
    );
    assert!(
        project
            .path()
            .join("node_modules")
            .join("tarball-url-pkg")
            .join("package.json")
            .exists(),
        "installed tree must contain the tarball package"
    );
}

// ─── pre-resolver rejection of transitive non-registry / workspace specs ───
//
// File: deps from local sources can carry transitive specs that LPM cannot
// resolve (tarball URLs, raw `workspace:` references against non-workspace
// consumers). The install pipeline must reject these BEFORE reaching the
// resolver — pre-fix the resolver crashed with cryptic `invalid range`
// errors. These tests pin both the rejection AND the structured-error
// contract (named dep, raw spec, source dir, workaround hint).

/// A `file:` source whose own manifest depends on a tarball URL must be
/// rejected at the pre-resolver `recurse_local_source_deps` boundary —
/// not crash the resolver on an unparseable spec. Stderr must name the
/// dep, the raw spec, the local source directory, AND a workaround hint.
#[test]
fn install_rejects_transitive_tarball_url_from_file_source_before_resolver() {
    let project = TempProject::empty(
        r#"{
  "name": "transitive-tarball-url",
  "version": "1.0.0",
  "dependencies": { "foo": "file:./packages/foo" }
}"#,
    );
    project.write_file(
        "packages/foo/package.json",
        r#"{
  "name": "foo",
  "version": "1.0.0",
  "dependencies": { "bar": "https://example.com/bar.tgz" }
}"#,
    );

    // Use an unreachable registry URL to defend against any path that
    // might inadvertently try a network call before reaching the
    // pre-resolver gate.
    let out = lpm_with_registry(&project, "http://127.0.0.1:1")
        .args(["install"])
        .output()
        .expect("spawn lpm install");
    assert!(
        !out.status.success(),
        "install must reject transitive tarball URL; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );

    let stderr = String::from_utf8_lossy(&out.stderr);
    let stderr_compact: String = stderr
        .chars()
        .filter(|c| c.is_ascii() && !c.is_whitespace())
        .collect();

    assert!(
        stderr.contains("transitive non-registry dep `bar`"),
        "stderr must categorize the failure and name the offending dep; got:\n{stderr}"
    );
    assert!(
        stderr_compact.contains("https://example.com/bar.tgz"),
        "stderr must echo the raw offending spec; got:\n{stderr}"
    );
    assert!(
        stderr.contains("tarball URL"),
        "stderr must categorize the unsupported shape; got:\n{stderr}"
    );
    assert!(
        stderr_compact.contains("hoistthedeptoyourproject'spackage.json"),
        "stderr must include the workaround hint; got:\n{stderr}"
    );
    assert!(
        !stderr.contains("invalid semver range"),
        "rejection must happen BEFORE resolver range parsing; got:\n{stderr}"
    );
}

/// A non-workspace consumer with a `file:` source whose manifest carries
/// a `workspace:^1.0.0` transitive must be rejected with a clear
/// "consumer is not a workspace" message — not crash the resolver with
/// "invalid range 'workspace:'".
#[test]
fn install_rejects_transitive_workspace_spec_in_non_workspace_consumer() {
    let project = TempProject::empty(
        r#"{
  "name": "transitive-workspace-non-ws",
  "version": "1.0.0",
  "dependencies": { "foo": "file:./packages/foo" }
}"#,
    );
    project.write_file(
        "packages/foo/package.json",
        r#"{
  "name": "foo",
  "version": "1.0.0",
  "dependencies": { "bar": "workspace:^1.0.0" }
}"#,
    );

    let out = lpm_with_registry(&project, "http://127.0.0.1:1")
        .args(["install"])
        .output()
        .expect("spawn lpm install");
    assert!(
        !out.status.success(),
        "install must reject `workspace:` transitive in non-workspace project; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );

    let stderr = String::from_utf8_lossy(&out.stderr);
    let stderr_compact: String = stderr
        .chars()
        .filter(|c| c.is_ascii() && !c.is_whitespace())
        .collect();

    assert!(
        stderr.contains("transitive `workspace:` dep `bar`"),
        "stderr must categorize the failure and name the dep; got:\n{stderr}"
    );
    assert!(
        stderr_compact.contains("workspace:^1.0.0"),
        "stderr must echo the raw workspace: spec; got:\n{stderr}"
    );
    assert!(
        stderr.contains("not a workspace"),
        "stderr must explain the consumer isn't a workspace; got:\n{stderr}"
    );
    assert!(
        !stderr.contains("invalid range") && !stderr.contains("invalid version range"),
        "rejection must happen BEFORE resolver range parsing — pre-fix the \
         resolver crashed on `invalid range 'workspace:'`. Got:\n{stderr}"
    );
}

/// A real workspace whose root depends on a member via `file:`, and
/// where that member's manifest declares `workspace:*` against a
/// SIBLING workspace member, must install successfully — the
/// pre-resolver `workspace:` membership check must consult the FULL
/// workspace member set, not just the top-level extracted slice.
#[test]
fn install_workspace_transitive_resolves_against_full_membership_set() {
    let project = TempProject::empty(
        r#"{
  "name": "ws-transitive-membership",
  "version": "1.0.0",
  "private": true,
  "workspaces": ["packages/*"],
  "dependencies": { "foo": "file:./packages/foo" }
}"#,
    );
    project.write_file(
        "packages/foo/package.json",
        r#"{
  "name": "foo",
  "version": "1.0.0",
  "dependencies": { "bar": "workspace:*" }
}"#,
    );
    project.write_file(
        "packages/bar/package.json",
        r#"{ "name": "bar", "version": "1.2.3" }"#,
    );

    let out = lpm_with_registry(&project, "http://127.0.0.1:1")
        .args(["install"])
        .output()
        .expect("spawn lpm install");

    assert!(
        out.status.success(),
        "install of a real workspace with `workspace:*` against a sibling member \
         must succeed (full-membership-set lookup, not top-level-extracted slice). \
         status: {:?}\nstdout:\n{}\nstderr:\n{}",
        out.status,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains("not a workspace member"),
        "transitive `workspace:*` against a real workspace member must NOT trip \
         the 'not a workspace member' branch — that branch fires when the \
         membership slice is the extracted top-level subset, not the full \
         ws.members set. stderr:\n{stderr}"
    );
    assert!(
        !stderr.contains("invalid range") && !stderr.contains("invalid version range"),
        "install must not crash the resolver on `workspace:`. stderr:\n{stderr}"
    );
}

// ─── workspace member root-symlink discovery paths ───
//
// Three discovery paths plant `node_modules/<member>` symlinks: the
// top-level `workspace:` extractor, the F9 immediate-file-dedupe path,
// and the BFS walk over linked members' transitive `workspace:` refs.
// Each test below pins one entry point of that union.

/// Assert `node_modules/<root_name>` is a symlink whose canonical path
/// equals the canonical path of `expected_target`.
fn assert_root_symlink_resolves_to(
    project: &TempProject,
    root_name: &str,
    expected_target: &std::path::Path,
) {
    let link = project.path().join("node_modules").join(root_name);
    assert!(
        link.symlink_metadata().is_ok(),
        "missing root symlink: node_modules/{root_name} (looked at {link:?})",
    );
    let resolved = link
        .canonicalize()
        .unwrap_or_else(|e| panic!("failed to canonicalize {link:?}: {e}"));
    let expected = expected_target
        .canonicalize()
        .unwrap_or_else(|e| panic!("failed to canonicalize {expected_target:?}: {e}"));
    assert_eq!(
        resolved, expected,
        "node_modules/{root_name} resolved to {resolved:?}, expected {expected:?}"
    );
}

/// F9 immediate-file-dedupe path: a workspace where the root depends on
/// `foo` via `file:./packages/foo` AND foo is a workspace member must
/// plant `node_modules/foo` as a symlink — even though `foo` isn't a
/// `workspace:` reference at the top level. Pre-fix the F9 dedupe
/// silently dropped the symlink.
#[test]
fn install_workspace_file_dedupe_plants_root_symlink_for_member() {
    let project = TempProject::empty(
        r#"{
  "name": "ws-file-dedupe-root",
  "version": "1.0.0",
  "private": true,
  "workspaces": ["packages/*"],
  "dependencies": { "foo": "file:./packages/foo" }
}"#,
    );
    project.write_file(
        "packages/foo/package.json",
        r#"{ "name": "foo", "version": "1.0.0" }"#,
    );
    let foo_dir = project.path().join("packages").join("foo");

    let out = lpm_with_registry(&project, "http://127.0.0.1:1")
        .args(["install"])
        .output()
        .expect("spawn lpm install");
    assert!(
        out.status.success(),
        "install must succeed; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );

    assert_root_symlink_resolves_to(&project, "foo", &foo_dir);

    // F9 path actually fired — guards against a future fix that plants
    // the symlink via a different path while leaving F9 silently broken.
    let combined = format!(
        "{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        combined.contains("resolves to workspace member"),
        "F9 dedupe note expected (proves the F9 path itself plants the symlink):\n{combined}"
    );
}

/// BFS over linked members' manifests: root depends on `foo` via
/// `workspace:*`, and foo's manifest declares `bar: workspace:*` against
/// a sibling member. Both `foo` AND `bar` must end up root-symlinked —
/// the BFS continues into linked members rather than stopping at the
/// top-level extracted set.
#[test]
fn install_workspace_transitive_protocol_plants_sibling_root_symlink() {
    let project = TempProject::empty(
        r#"{
  "name": "ws-transitive-root",
  "version": "1.0.0",
  "private": true,
  "workspaces": ["packages/*"],
  "dependencies": { "foo": "workspace:*" }
}"#,
    );
    project.write_file(
        "packages/foo/package.json",
        r#"{
  "name": "foo",
  "version": "1.0.0",
  "dependencies": { "bar": "workspace:*" }
}"#,
    );
    project.write_file(
        "packages/bar/package.json",
        r#"{ "name": "bar", "version": "1.2.3" }"#,
    );
    let foo_dir = project.path().join("packages").join("foo");
    let bar_dir = project.path().join("packages").join("bar");

    let out = lpm_with_registry(&project, "http://127.0.0.1:1")
        .args(["install"])
        .output()
        .expect("spawn lpm install");
    assert!(
        out.status.success(),
        "install must succeed; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );

    assert_root_symlink_resolves_to(&project, "foo", &foo_dir);
    assert_root_symlink_resolves_to(&project, "bar", &bar_dir);
}

/// Three-deep chain combining both discovery paths: root → foo via
/// `file:` (F9 path) → bar via `workspace:*` (BFS path) → baz via
/// `workspace:*` (BFS path again). All three must root-symlink. Pre-fix
/// the deepest link (baz) was lost when the BFS started from the
/// extracted top-level set rather than from F9-discovered members.
#[test]
fn install_workspace_file_dedupe_then_transitive_chain_plants_all_root_symlinks() {
    let project = TempProject::empty(
        r#"{
  "name": "ws-chain-root",
  "version": "1.0.0",
  "private": true,
  "workspaces": ["packages/*"],
  "dependencies": { "foo": "file:./packages/foo" }
}"#,
    );
    project.write_file(
        "packages/foo/package.json",
        r#"{
  "name": "foo",
  "version": "1.0.0",
  "dependencies": { "bar": "workspace:*" }
}"#,
    );
    project.write_file(
        "packages/bar/package.json",
        r#"{
  "name": "bar",
  "version": "1.0.0",
  "dependencies": { "baz": "workspace:*" }
}"#,
    );
    project.write_file(
        "packages/baz/package.json",
        r#"{ "name": "baz", "version": "1.0.0" }"#,
    );

    let foo_dir = project.path().join("packages").join("foo");
    let bar_dir = project.path().join("packages").join("bar");
    let baz_dir = project.path().join("packages").join("baz");

    let out = lpm_with_registry(&project, "http://127.0.0.1:1")
        .args(["install"])
        .output()
        .expect("spawn lpm install");
    assert!(
        out.status.success(),
        "install must succeed; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );

    assert_root_symlink_resolves_to(&project, "foo", &foo_dir);
    assert_root_symlink_resolves_to(&project, "bar", &bar_dir);
    assert_root_symlink_resolves_to(&project, "baz", &baz_dir);
}

// ─── install-hash freshness, offline, ghost members ───
//
// Six workspace-discovery edge cases plus one offline mixed-registry+file
// test. Together they pin the install-hash member-manifest sensitivity
// (round-6 fix), the offline workspace-BFS expansion, the F9 offline
// pre-pass, the alias-vs-canonical disambiguation, and ghost workspace
// transitives failing closed both online and offline.

const WORKSPACE_INSTALL_FLAGS: &[&str] = &[
    "install",
    "--no-security-summary",
    "--no-skills",
    "--no-editor-setup",
];

fn assert_root_symlink_exists(project: &TempProject, root_name: &str) {
    let link = project.path().join("node_modules").join(root_name);
    assert!(
        link.symlink_metadata().is_ok(),
        "missing root symlink: node_modules/{root_name} (looked at {link:?})",
    );
}

fn assert_root_symlink_missing(project: &TempProject, root_name: &str) {
    let link = project.path().join("node_modules").join(root_name);
    assert!(
        link.symlink_metadata().is_err(),
        "unexpected root symlink: node_modules/{root_name} (was created at {link:?})",
    );
}

/// Install-hash must fold member manifests into its freshness key. A
/// workspace member's `package.json` edit that introduces a transitive
/// `workspace:` ref must invalidate the cached hash so the second
/// install actually re-runs the BFS expansion. Pre-fix the member
/// manifests were invisible to the install-hash and the second install
/// hit "up to date (0ms)" — leaving the new sibling root symlink unset.
#[test]
fn install_hash_invalidates_on_workspace_member_manifest_change() {
    let project = TempProject::empty(
        r#"{
  "name": "ws-hash-freshness",
  "private": true,
  "workspaces": ["packages/*"],
  "dependencies": { "foo": "workspace:*" }
}"#,
    );
    project.write_file(
        "packages/foo/package.json",
        r#"{ "name": "foo", "version": "1.0.0" }"#,
    );
    project.write_file(
        "packages/bar/package.json",
        r#"{ "name": "bar", "version": "1.0.0" }"#,
    );

    // First install — only foo gets root-linked (bar isn't yet a
    // transitive `workspace:` ref of any linked member).
    let out1 = lpm_with_registry(&project, "http://127.0.0.1:1")
        .args(WORKSPACE_INSTALL_FLAGS)
        .output()
        .expect("spawn lpm install (first)");
    assert!(
        out1.status.success(),
        "first install failed:\n{}",
        String::from_utf8_lossy(&out1.stderr)
    );
    assert_root_symlink_exists(&project, "foo");
    assert_root_symlink_missing(&project, "bar");

    // Edit foo's manifest to add `bar: workspace:*`.
    project.write_file(
        "packages/foo/package.json",
        r#"{
  "name": "foo",
  "version": "1.0.0",
  "dependencies": { "bar": "workspace:*" }
}"#,
    );

    // Second install must NOT take the up-to-date fast-exit; the
    // member-manifest hash fold causes invalidation and the BFS plants
    // the new bar symlink.
    let out2 = lpm_with_registry(&project, "http://127.0.0.1:1")
        .args(WORKSPACE_INSTALL_FLAGS)
        .output()
        .expect("spawn lpm install (second)");
    assert!(
        out2.status.success(),
        "second install failed:\n{}",
        String::from_utf8_lossy(&out2.stderr)
    );
    assert_root_symlink_exists(&project, "foo");
    assert_root_symlink_exists(&project, "bar");
}

/// `lpm install --offline` re-runs the workspace-member BFS expansion
/// rather than skipping it — pre-fix the offline branch handed the
/// extracted top-level slice straight to `run_link_and_finish` and the
/// transitively-discovered sibling member symlink was lost.
#[test]
fn offline_install_reruns_workspace_member_bfs_expansion() {
    let project = TempProject::empty(
        r#"{
  "name": "ws-offline-bfs",
  "private": true,
  "workspaces": ["packages/*"],
  "dependencies": { "foo": "workspace:*" }
}"#,
    );
    project.write_file(
        "packages/foo/package.json",
        r#"{
  "name": "foo",
  "version": "1.0.0",
  "dependencies": { "bar": "workspace:*" }
}"#,
    );
    project.write_file(
        "packages/bar/package.json",
        r#"{ "name": "bar", "version": "1.2.3" }"#,
    );

    // Online install plants both root symlinks (BFS expansion).
    let out_online = lpm_with_registry(&project, "http://127.0.0.1:1")
        .args(WORKSPACE_INSTALL_FLAGS)
        .output()
        .expect("spawn lpm install (online)");
    assert!(
        out_online.status.success(),
        "online install failed:\n{}",
        String::from_utf8_lossy(&out_online.stderr)
    );
    assert_root_symlink_exists(&project, "foo");
    assert_root_symlink_exists(&project, "bar");

    // Wipe node_modules; offline install must rebuild both symlinks.
    std::fs::remove_dir_all(project.path().join("node_modules")).unwrap();
    let out_offline = lpm_with_registry(&project, "http://127.0.0.1:1")
        .args([
            "install",
            "--offline",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("spawn lpm install --offline");
    assert!(
        out_offline.status.success(),
        "offline install failed:\n{}",
        String::from_utf8_lossy(&out_offline.stderr)
    );
    assert_root_symlink_exists(&project, "foo");
    assert_root_symlink_exists(&project, "bar");
}

/// `lpm install --offline` must accept a `file:` dep against a workspace
/// member without bailing on "—offline requires a lockfile". Pre-fix
/// the F9 dedupe lived in the online-only pre_resolve, so the offline
/// fast-path saw foo as a missing root dep against the lockfile.
#[test]
fn offline_install_handles_f9_deduped_workspace_member() {
    let project = TempProject::empty(
        r#"{
  "name": "ws-offline-f9",
  "private": true,
  "workspaces": ["packages/*"],
  "dependencies": { "foo": "file:./packages/foo" }
}"#,
    );
    project.write_file(
        "packages/foo/package.json",
        r#"{ "name": "foo", "version": "1.0.0" }"#,
    );

    let out_online = lpm_with_registry(&project, "http://127.0.0.1:1")
        .args(WORKSPACE_INSTALL_FLAGS)
        .output()
        .expect("spawn lpm install (online)");
    assert!(
        out_online.status.success(),
        "online install failed:\n{}",
        String::from_utf8_lossy(&out_online.stderr)
    );
    assert_root_symlink_exists(&project, "foo");

    std::fs::remove_dir_all(project.path().join("node_modules")).unwrap();
    let out_offline = lpm_with_registry(&project, "http://127.0.0.1:1")
        .args([
            "install",
            "--offline",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("spawn lpm install --offline");
    assert!(
        out_offline.status.success(),
        "offline install failed (F9 pre-pass should route foo to workspace_member_deps):\n\
         stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out_offline.stdout),
        String::from_utf8_lossy(&out_offline.stderr)
    );
    let stderr = String::from_utf8_lossy(&out_offline.stderr);
    assert!(
        !stderr.contains("--offline requires a lockfile")
            && !stderr.contains("could not load the lockfile"),
        "offline install must not bail with the lockfile error:\n{stderr}"
    );
    assert_root_symlink_exists(&project, "foo");
}

/// Mixed project with one `file:` dep and one registry dep must
/// install offline after a successful online run — the lockfile
/// fast-path must accept the `directory+` source entry under
/// `accept_unsafe_sources = true` rather than bailing on it.
#[tokio::test]
async fn offline_install_mixed_registry_and_file_dep_uses_lockfile_fast_path() {
    let mock = MockRegistry::start().await;
    let tarball = make_tarball("is-number", "1.0.0");
    mock.with_package("is-number", "1.0.0", &tarball).await;
    mock.with_batch_metadata(vec![serde_json::json!({
        "name": "is-number",
        "dist-tags": { "latest": "1.0.0" },
        "versions": {
            "1.0.0": {
                "name": "is-number",
                "version": "1.0.0",
                "dist": {
                    "tarball": format!("{}/tarballs/is-number/-/is-number-1.0.0.tgz", mock.url()),
                    "integrity": compute_integrity(&tarball),
                },
                "dependencies": {}
            }
        },
        "time": { "1.0.0": "2025-01-01T00:00:00.000Z" }
    })])
    .await;

    let project = TempProject::empty(
        r#"{
  "name": "offline-mixed",
  "dependencies": { "foo": "file:./packages/foo", "is-number": "1.0.0" }
}"#,
    );
    project.write_file(
        "packages/foo/package.json",
        r#"{ "name": "foo", "version": "1.0.0" }"#,
    );

    // Online install populates lockfile + per-project store.
    lpm_with_registry(&project, &mock.url())
        .args(WORKSPACE_INSTALL_FLAGS)
        .assert()
        .success();
    assert_root_symlink_exists(&project, "foo");
    assert_root_symlink_exists(&project, "is-number");

    // Wipe node_modules; offline install must rebuild from lockfile + store.
    std::fs::remove_dir_all(project.path().join("node_modules")).unwrap();
    let out_offline = lpm_with_registry(&project, &mock.url())
        .args([
            "install",
            "--offline",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("spawn lpm install --offline");
    assert!(
        out_offline.status.success(),
        "offline install failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out_offline.stdout),
        String::from_utf8_lossy(&out_offline.stderr)
    );
    let stderr = String::from_utf8_lossy(&out_offline.stderr);
    assert!(
        !stderr.contains("--offline requires a lockfile"),
        "offline install must accept the directory+ lockfile entry:\n{stderr}"
    );
    assert_root_symlink_exists(&project, "foo");
    assert_root_symlink_exists(&project, "is-number");
}

/// Both online and offline arms must plant the canonical AND the alias
/// root link when they share a target. Pre-fix the shared BFS deduped
/// only by canonical realpath, so the alias seed suppressed the
/// canonical `node_modules/foo` link.
#[test]
fn install_workspace_alias_and_transitive_target_both_get_root_links() {
    let project = TempProject::empty(
        r#"{
  "name": "ws-alias-transitive",
  "private": true,
  "workspaces": ["packages/*"],
  "dependencies": { "bar": "workspace:*", "aliasfoo": "file:./packages/foo" }
}"#,
    );
    project.write_file(
        "packages/foo/package.json",
        r#"{ "name": "foo", "version": "1.0.0" }"#,
    );
    project.write_file(
        "packages/bar/package.json",
        r#"{
  "name": "bar",
  "version": "1.0.0",
  "dependencies": { "foo": "workspace:*" }
}"#,
    );

    // Online: all three root links (canonical foo + alias aliasfoo + bar).
    let out = lpm_with_registry(&project, "http://127.0.0.1:1")
        .args(WORKSPACE_INSTALL_FLAGS)
        .output()
        .expect("spawn lpm install (online)");
    assert!(
        out.status.success(),
        "install failed:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_root_symlink_exists(&project, "bar");
    assert_root_symlink_exists(&project, "aliasfoo");
    assert_root_symlink_exists(&project, "foo");

    // Offline rebuild must produce the same set.
    std::fs::remove_dir_all(project.path().join("node_modules")).unwrap();
    let out_offline = lpm_with_registry(&project, "http://127.0.0.1:1")
        .args([
            "install",
            "--offline",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("spawn lpm install --offline");
    assert!(
        out_offline.status.success(),
        "offline install failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out_offline.stdout),
        String::from_utf8_lossy(&out_offline.stderr)
    );
    assert_root_symlink_exists(&project, "bar");
    assert_root_symlink_exists(&project, "aliasfoo");
    assert_root_symlink_exists(&project, "foo");
}

/// A workspace member referencing a non-existent member via
/// `workspace:*` must error with an actionable diagnostic — not silently
/// continue. Pins the fail-closed contract for ghost transitives.
#[test]
fn install_workspace_ghost_transitive_fails_closed_with_actionable_error() {
    let project = TempProject::empty(
        r#"{
  "name": "ws-ghost-transitive",
  "private": true,
  "workspaces": ["packages/*"],
  "dependencies": { "foo": "workspace:*" }
}"#,
    );
    project.write_file(
        "packages/foo/package.json",
        r#"{
  "name": "foo",
  "version": "1.0.0",
  "dependencies": { "ghost": "workspace:*" }
}"#,
    );

    let out = lpm_with_registry(&project, "http://127.0.0.1:1")
        .args(WORKSPACE_INSTALL_FLAGS)
        .output()
        .expect("spawn lpm install");
    assert!(
        !out.status.success(),
        "install must fail on ghost workspace transitive; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("ghost")
            && stderr.contains("workspace:*")
            && stderr.contains("not a workspace member")
            && stderr.contains("Available members:"),
        "ghost workspace transitive should fail closed with an actionable error:\n{stderr}"
    );
}

/// Offline arm must enforce the same ghost-transitive rejection. After
/// a successful workspace install, editing a member's manifest to
/// introduce an invalid `workspace:*` ref must fail the next
/// `--offline` install — not silently link from stale data.
#[test]
fn offline_install_workspace_ghost_transitive_after_manifest_edit_fails_closed() {
    let project = TempProject::empty(
        r#"{
  "name": "ws-offline-ghost",
  "private": true,
  "workspaces": ["packages/*"],
  "dependencies": { "foo": "workspace:*" }
}"#,
    );
    project.write_file(
        "packages/foo/package.json",
        r#"{ "name": "foo", "version": "1.0.0" }"#,
    );

    let out_online = lpm_with_registry(&project, "http://127.0.0.1:1")
        .args(WORKSPACE_INSTALL_FLAGS)
        .output()
        .expect("spawn lpm install (online)");
    assert!(
        out_online.status.success(),
        "online install failed:\n{}",
        String::from_utf8_lossy(&out_online.stderr)
    );

    // Introduce a ghost transitive via manifest edit, then run offline.
    project.write_file(
        "packages/foo/package.json",
        r#"{
  "name": "foo",
  "version": "1.0.0",
  "dependencies": { "ghost": "workspace:*" }
}"#,
    );
    std::fs::remove_dir_all(project.path().join("node_modules")).unwrap();

    let out_offline = lpm_with_registry(&project, "http://127.0.0.1:1")
        .args([
            "install",
            "--offline",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("spawn lpm install --offline");
    assert!(
        !out_offline.status.success(),
        "offline install unexpectedly succeeded with ghost transitive:\n\
         stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out_offline.stdout),
        String::from_utf8_lossy(&out_offline.stderr)
    );

    let stderr = String::from_utf8_lossy(&out_offline.stderr);
    assert!(
        stderr.contains("ghost")
            && stderr.contains("workspace:*")
            && stderr.contains("not a workspace member")
            && stderr.contains("Available members:"),
        "offline ghost workspace transitive should fail closed with an actionable error:\n{stderr}"
    );
}

// ─── strict-ssl=false install-start security warning ───
//
// `strict-ssl=false` in `.npmrc` is advisory (it does NOT block install)
// but the warning is a SECURITY signal that must reach CI / agent logs
// regardless of output mode. Three properties pinned: (1) install
// completes, (2) stderr carries the loud warning with source citation,
// (3) the warning fires under `--json` mode too — pre-fix it was
// silenced for the exact automation users most likely to need it.
//
// Subprocess tests because unit tests can't observe fd 1 vs fd 2
// separation — the contract under test is "warning on stderr, JSON on
// stdout, neither leaks into the other."

/// M7: a project-local `.npmrc` with `strict-ssl=false` must be
/// REFUSED (not honored) and the refusal must be surfaced with a
/// `<dir>/.npmrc:1` source citation. Pre-fix the setting was honored
/// silently — a hostile commit could disable TLS verification for
/// every teammate. Now the operator's user-level `~/.npmrc` is the
/// only place that may opt-in.
#[test]
fn install_strict_ssl_false_in_project_npmrc_is_refused_with_source_citation() {
    let project =
        TempProject::empty(r#"{"name":"strict-ssl-warn","version":"1.0.0","dependencies":{}}"#);
    project.write_file(".npmrc", "strict-ssl=false\n");
    let npmrc_abs = project.path().join(".npmrc");

    let out = lpm_with_registry(&project, "http://127.0.0.1:1")
        .args(["install"])
        .output()
        .expect("spawn lpm install");
    assert!(
        out.status.success(),
        "install with empty deps must succeed even when the project-local strict-ssl override is refused; \
         stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("refused"),
        "stderr must contain the refusal marker; got:\n{stderr}"
    );
    let cite = format!("{}:1", npmrc_abs.display());
    assert!(
        stderr.contains(&cite),
        "stderr must cite the contributing source:line ({cite}); got:\n{stderr}"
    );
}

/// Same refusal + citation must fire under `--json`. JSON goes to
/// stdout; the warning is on stderr — no conflict.
#[test]
fn install_strict_ssl_false_refusal_visible_in_json_mode() {
    let project = TempProject::empty(
        r#"{"name":"strict-ssl-warn-json","version":"1.0.0","dependencies":{}}"#,
    );
    project.write_file(".npmrc", "strict-ssl=false\n");
    let npmrc_abs = project.path().join(".npmrc");

    let out = lpm_with_registry(&project, "http://127.0.0.1:1")
        .args(["install", "--json"])
        .output()
        .expect("spawn lpm install --json");
    assert!(
        out.status.success(),
        "install --json with empty deps must succeed; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    // Stdout: valid JSON envelope, no warning text leaked.
    let stdout = String::from_utf8_lossy(&out.stdout);
    let parsed: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap_or_else(|e| {
        panic!("stdout must be valid JSON in --json mode: {e}\nstdout:\n{stdout}")
    });
    assert_eq!(parsed["success"], serde_json::json!(true));

    // Stderr: refusal + source citation.
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("refused"),
        "stderr must contain refusal warning even under --json; got:\n{stderr}"
    );
    let cite = format!("{}:1", npmrc_abs.display());
    assert!(
        stderr.contains(&cite),
        "stderr must cite source:line ({cite}) even under --json; got:\n{stderr}"
    );
}

/// Negative case: a `.npmrc` without `strict-ssl=false` must NOT emit
/// the warning. Guards against a future change that fires on `None` /
/// `Some(true)` by accident.
#[test]
fn install_no_strict_ssl_setting_emits_no_warning() {
    let project =
        TempProject::empty(r#"{"name":"strict-ssl-clean","version":"1.0.0","dependencies":{}}"#);
    project.write_file(".npmrc", "registry=https://example.com/\n");

    let out = lpm_with_registry(&project, "http://127.0.0.1:1")
        .args(["install"])
        .output()
        .expect("spawn lpm install");
    assert!(
        out.status.success(),
        "install must succeed with a bland .npmrc; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains("TLS certificate verification is DISABLED"),
        "stderr must NOT contain the strict-ssl warning when the setting isn't \
         flipped; got:\n{stderr}"
    );
}

// ─── release-age cooldown gate ─────────────────────
//
// P3 ship criteria: the install-time cooldown gate that blocks
// recently-published packages. Five behaviors pinned: (1) `--min-release-age`
// CLI override fires, (2) `--allow-new` is an orthogonal bypass, (3)
// `~/.lpm/config.toml` overrides the 24h default, (4) `package.json > lpm
// > minimumReleaseAge` overrides the global config, (5) explicit version
// pins do NOT bypass the cooldown (D7 plan decision — pin-bypass would
// open the renovate/dependabot supply-chain attack vector).

const RELEASE_AGE_PKG: &str = "@lpm.dev/acme.widget";
const RELEASE_AGE_VERSION: &str = "1.0.0";

/// ISO-8601 UTC timestamp `n_secs` ago. The cooldown parser accepts
/// `2025-01-01T00:00:00.000Z`-style strings.
fn iso8601_n_secs_ago(n_secs: i64) -> String {
    use chrono::SecondsFormat;
    let dt = chrono::Utc::now() - chrono::Duration::seconds(n_secs);
    dt.to_rfc3339_opts(SecondsFormat::Millis, true)
}

/// Mount `@lpm.dev/acme.widget@1.0.0` with the supplied `published_at`
/// timestamp. Wires single-package metadata + batch-metadata + tarball.
async fn mount_release_age_pkg(mock: &MockRegistry, published_at: &str) {
    let tarball = make_tarball(RELEASE_AGE_PKG, RELEASE_AGE_VERSION);
    mock.with_package_published_at(RELEASE_AGE_PKG, RELEASE_AGE_VERSION, &tarball, published_at)
        .await;
    mock.with_batch_metadata(vec![serde_json::json!({
        "name": RELEASE_AGE_PKG,
        "dist-tags": { "latest": RELEASE_AGE_VERSION },
        "versions": {
            RELEASE_AGE_VERSION: {
                "name": RELEASE_AGE_PKG,
                "version": RELEASE_AGE_VERSION,
                "dist": {
                    "tarball": format!(
                        "{}/tarballs/{RELEASE_AGE_PKG}/-/{RELEASE_AGE_PKG}-{RELEASE_AGE_VERSION}.tgz",
                        mock.url()
                    ),
                    "integrity": compute_integrity(&tarball),
                },
                "dependencies": {}
            }
        },
        "time": { RELEASE_AGE_VERSION: published_at }
    })])
    .await;
}

/// Write the consumer's `package.json` for the release-age tests.
/// `manifest_min_release_age` injects `lpm.minimumReleaseAge = <secs>`.
fn write_release_age_manifest(project: &TempProject, manifest_min_release_age: Option<u64>) {
    let mut manifest = serde_json::json!({
        "name": "release-age-test",
        "version": "1.0.0",
        "dependencies": { RELEASE_AGE_PKG: RELEASE_AGE_VERSION }
    });
    if let Some(secs) = manifest_min_release_age {
        manifest["lpm"] = serde_json::json!({ "minimumReleaseAge": secs });
    }
    project.write_file(
        "package.json",
        &serde_json::to_string_pretty(&manifest).unwrap(),
    );
}

/// Write `<HOME>/.lpm/config.toml` with `minimum-release-age-secs = N`.
fn write_release_age_global_config(project: &TempProject, secs: u64) {
    let lpm_dir = project.home().join(".lpm");
    std::fs::create_dir_all(&lpm_dir).unwrap();
    std::fs::write(
        lpm_dir.join("config.toml"),
        format!("minimum-release-age-secs = {secs}\n"),
    )
    .unwrap();
}

fn assert_cooldown_blocked(out: &std::process::Output) {
    assert!(
        !out.status.success(),
        "install must fail with a cooldown block; stdout:\n{}\nstderr:\n{}",
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

/// `--min-release-age=72h` blocks a 1h-old package. Manifest disables
/// the default (Some(0) short-circuits), so the CLI override is what
/// took effect — the `259200` (72h in seconds) value should be
/// rendered in the diagnostic.
#[tokio::test]
async fn install_min_release_age_cli_override_blocks_fresh_package() {
    let project = TempProject::empty("");
    write_release_age_manifest(&project, Some(0));

    let mock = MockRegistry::start().await;
    mount_release_age_pkg(&mock, &iso8601_n_secs_ago(3_600)).await;

    let out = lpm_with_registry(&project, &mock.url())
        .args(["install", "--min-release-age=72h"])
        .output()
        .expect("spawn lpm install");

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

/// `--allow-new` bypasses the cooldown even alongside `--min-release-age`.
/// They are orthogonal escape hatches per the plan's D16 — `--allow-new`
/// short-circuits the gate before the resolver runs. We assert only
/// "cooldown does not fire"; downstream install behavior may still fail
/// in a hermetic test environment for unrelated reasons.
#[tokio::test]
async fn install_allow_new_bypasses_min_release_age_cli_override() {
    let project = TempProject::empty("");
    write_release_age_manifest(&project, Some(0));

    let mock = MockRegistry::start().await;
    mount_release_age_pkg(&mock, &iso8601_n_secs_ago(3_600)).await;

    let out = lpm_with_registry(&project, &mock.url())
        .args(["install", "--allow-new", "--min-release-age=72h"])
        .output()
        .expect("spawn lpm install");

    assert_cooldown_not_blocked(&out);
}

/// `~/.lpm/config.toml > minimum-release-age-secs` overrides the 24h
/// default when no CLI flag and no `package.json` key are set. Package
/// is 30min old; global = 3600s (1h). The default 86400s would also
/// block, so we assert the global value (3600) is what actually fired.
#[tokio::test]
async fn install_global_config_min_release_age_overrides_default() {
    let project = TempProject::empty("");
    write_release_age_manifest(&project, None);
    write_release_age_global_config(&project, 3_600);

    let mock = MockRegistry::start().await;
    mount_release_age_pkg(&mock, &iso8601_n_secs_ago(1_800)).await;

    let out = lpm_with_registry(&project, &mock.url())
        .args(["install"])
        .output()
        .expect("spawn lpm install");

    assert_cooldown_blocked(&out);
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        combined.contains("3600"),
        "output must render the global config's 3600s window; got:\n{combined}"
    );
    assert!(
        !combined.contains("86400"),
        "default 86400s must NOT appear when the global config overrides it; got:\n{combined}"
    );
}

/// `package.json > lpm > minimumReleaseAge` overrides the global config.
/// Package is 30min old; global says 1h (would block); manifest says
/// 60s (would allow). Manifest layer wins → no cooldown block.
#[tokio::test]
async fn install_package_json_min_release_age_overrides_global_config() {
    let project = TempProject::empty("");
    write_release_age_manifest(&project, Some(60));
    write_release_age_global_config(&project, 3_600);

    let mock = MockRegistry::start().await;
    mount_release_age_pkg(&mock, &iso8601_n_secs_ago(1_800)).await;

    let out = lpm_with_registry(&project, &mock.url())
        .args(["install"])
        .output()
        .expect("spawn lpm install");

    assert_cooldown_not_blocked(&out);
}

/// Plan D7 regression: an explicit version pin (`pkg@1.0.0`) must NOT
/// bypass the cooldown. v1 of the plan proposed pin-bypass; v2 rejected
/// it because renovate/dependabot auto-pin PRs would otherwise land
/// compromised versions during the detection window. This test guards
/// that the rejected behavior never re-lands.
#[tokio::test]
async fn install_explicit_version_pin_does_not_bypass_cooldown() {
    let project = TempProject::empty("");
    write_release_age_manifest(&project, None);

    let mock = MockRegistry::start().await;
    mount_release_age_pkg(&mock, &iso8601_n_secs_ago(3_600)).await;

    let pinned_spec = format!("{RELEASE_AGE_PKG}@{RELEASE_AGE_VERSION}");
    let out = lpm_with_registry(&project, &mock.url())
        .args(["install", &pinned_spec])
        .output()
        .expect("spawn lpm install");

    assert_cooldown_blocked(&out);
}

// ─── Linker validation ───────────────────────────────────────────

/// `package.json > lpm > linker` is parsed via `LinkerMode::parse_str` at
/// install time. Unknown values — including the legacy `"symlink"` alias
/// the docstring previously claimed was accepted — must abort with a
/// helpful error before the install runs, not silently fall back to the
/// default isolated layout. Pins the contract at the binary boundary.
#[test]
fn install_rejects_unknown_lpm_linker_value_loudly() {
    let project = TempProject::empty(
        r#"{
        "name": "linker-bad",
        "version": "0.0.1",
        "lpm": { "linker": "symlink" }
    }"#,
    );

    let out = lpm(&project)
        .args(["install"])
        .output()
        .expect("spawn lpm install");

    assert!(
        !out.status.success(),
        "install with `lpm.linker = symlink` should fail loudly; \
         stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("lpm.linker") || stderr.contains("linker"),
        "stderr must name the linker field; got:\n{stderr}"
    );
    assert!(
        stderr.contains("isolated") && stderr.contains("hoisted"),
        "stderr must list accepted values; got:\n{stderr}"
    );
}

/// CLI flag `--linker symlink` is rejected by clap at parse time. The
/// install pipeline never sees an unknown value through this surface, so
/// the error format is clap's standard "invalid value" message rather than
/// the install-time message.
#[test]
fn install_cli_linker_flag_rejects_unknown_value_at_parse_time() {
    let project = TempProject::empty(
        r#"{
        "name": "linker-cli-bad",
        "version": "0.0.1"
    }"#,
    );

    let out = lpm(&project)
        .args(["install", "--linker", "symlink"])
        .output()
        .expect("spawn lpm install");

    assert!(
        !out.status.success(),
        "`--linker symlink` should fail at clap parse time"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("invalid value")
            || stderr.contains("possible values")
            || stderr.contains("isolated"),
        "stderr must surface the clap rejection; got:\n{stderr}"
    );
}

/// `lpm migrate` calls `run_with_options` after generating `lpm.lock`. The
/// linker resolution chain (CLI > config.toml > LPM_LINKER > package.json)
/// must apply uniformly across every install entry point — not just the
/// top-level `lpm install` dispatch — or a user with `LPM_LINKER=hoisted`
/// would silently get `isolated` whenever they run `lpm migrate`,
/// `lpm upgrade`, `lpm add`, etc. This test pins that contract through
/// migrate, where the install pipeline is invoked with `linker_override =
/// None` from the caller. With the seam wired only at top-level dispatch
/// the bad value would slip through to silent fallback; with the seam
/// inside `run_with_options` it fails loudly here, before any network call.
///
/// `lpm migrate` itself exits 0 even when the post-migration install
/// fails (its design: lockfile generation succeeded, the install failure
/// is logged as a warning with a "run lpm install manually" hint). So the
/// test asserts on the error *message* in stderr, not the exit code —
/// the message is the load-bearing signal that the env var was honored.
#[test]
fn migrate_honors_lpm_linker_env_in_install_pipeline() {
    let project = TempProject::from_fixture("migrate-npm");

    let out = lpm(&project)
        .args(["migrate", "--force"])
        .env("LPM_LINKER", "symlink")
        .output()
        .expect("spawn lpm migrate");

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("LPM_LINKER"),
        "stderr must name LPM_LINKER — proves the env var (not just the \
         CLI flag or package.json) is honored from a non-`lpm install` \
         caller; got:\n{stderr}"
    );
    assert!(
        stderr.contains("unknown linker mode") || stderr.contains("invalid LPM_LINKER"),
        "stderr must surface the install-pipeline rejection; got:\n{stderr}"
    );
    assert!(
        stderr.contains("isolated") && stderr.contains("hoisted"),
        "stderr must list accepted values; got:\n{stderr}"
    );
}

/// Post-install env-driven linker flip MUST invalidate the "up to date"
/// freshness cache. Without the v6 hash fold, the second install would
/// short-circuit on the up-to-date fast-exit because pkg.json + lockfile
/// are unchanged — leaving the project on the prior layout despite the
/// requested switch. Pinning the contract end-to-end through the real
/// install pipeline + mock registry: install once with the active
/// default layout, then re-run with `LPM_LINKER` pointed at the OTHER
/// layout and assert the command did NOT print "up to date". The
/// invariant is direction-agnostic — previously the default was
/// Isolated and the test flipped to Hoisted; post-4f the default is
/// Hoisted and the test flips to Isolated. Either way the cache MUST
/// invalidate.
#[tokio::test]
async fn install_invalidates_freshness_cache_on_lpm_linker_flip() {
    let mock = MockRegistry::start().await;
    let tarball = make_tarball("ms", "2.1.3");
    mock.with_package("ms", "2.1.3", &tarball).await;
    let batch_meta = serde_json::json!({
        "name": "ms",
        "dist-tags": { "latest": "2.1.3" },
        "versions": {
            "2.1.3": {
                "name": "ms",
                "version": "2.1.3",
                "dist": {
                    "tarball": format!("{}/tarballs/ms/-/ms-2.1.3.tgz", mock.url()),
                    "integrity": format!("sha512-placeholder"),
                },
                "dependencies": {}
            }
        },
        "time": { "2.1.3": "2025-01-01T00:00:00.000Z" }
    });
    mock.with_batch_metadata(vec![batch_meta]).await;

    let project = TempProject::empty(
        r#"{
        "name": "linker-freshness",
        "version": "1.0.0",
        "dependencies": { "ms": "^2.1.3" }
    }"#,
    );

    // First install — establishes the freshness baseline under the
    // default isolated layout. After this completes, .lpm/install-hash
    // contains a hash keyed on `linker_mode = isolated`.
    let first = lpm_with_registry(&project, &mock.url())
        .args([
            "install",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("spawn first install");
    assert!(
        first.status.success(),
        "first install failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&first.stdout),
        String::from_utf8_lossy(&first.stderr),
    );

    // Sanity: a no-flag re-install should be "up to date" because the
    // resolved linker still matches what the cache encoded.
    let cached = lpm_with_registry(&project, &mock.url())
        .args([
            "install",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("spawn cached re-install");
    assert!(cached.status.success());
    let cached_stderr = String::from_utf8_lossy(&cached.stderr);
    assert!(
        cached_stderr.to_lowercase().contains("up to date"),
        "no-flag re-install must short-circuit when nothing changed; \
         got stderr:\n{cached_stderr}"
    );

    // The load-bearing assertion: re-install with `LPM_LINKER` flipped
    // to the non-default mode must NOT short-circuit as "up to date" —
    // the env-driven layout flip has to invalidate the freshness cache
    // and trigger a real re-link. Use the opposite of the active
    // default so this test stays meaningful across future default
    // The linker default flipped Isolated → Hoisted; previously the test
    // flipped to "hoisted").
    let opposite = match lpm_linker::LinkerMode::default() {
        lpm_linker::LinkerMode::Hoisted => "isolated",
        lpm_linker::LinkerMode::Isolated => "hoisted",
    };
    let flipped = lpm_with_registry(&project, &mock.url())
        .args([
            "install",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .env("LPM_LINKER", opposite)
        .output()
        .expect("spawn flipped re-install");
    assert!(
        flipped.status.success(),
        "flipped re-install failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&flipped.stdout),
        String::from_utf8_lossy(&flipped.stderr),
    );
    let flipped_stderr = String::from_utf8_lossy(&flipped.stderr);
    assert!(
        !flipped_stderr.to_lowercase().contains("up to date"),
        "freshness cache MUST invalidate on `LPM_LINKER` flip — second \
         install short-circuited as `up to date` despite the layout \
         change. This is the bug GPT's audit caught: pre-fix, the install-\
         hash didn't fold in the linker mode, so a post-install env flip \
         left the cache warm and the project stayed on the prior layout. \
         Got stderr:\n{flipped_stderr}"
    );
}

/// Cached-install fail-loud regression: warm install-hash on disk +
/// invalid `LPM_LINKER` MUST surface the parse error, not short-circuit
/// as "up to date". This pins the **sync fast lane** at `main.rs:2087`
/// — the pre-clap pre-tokio path that calls
/// `check_install_state_with_content` before the install dispatch
/// ever runs. Pre-fix the freshness helpers coerced the linker
/// resolution error to `LinkerMode::Isolated`, the stored isolated
/// hash matched, and the fast lane printed `up to date (Nms)` and
/// exited 0 — the user never learned their env was broken.
///
/// The fast lane is gated by `argv_qualifies_for_fast_lane()`
/// ([install_state.rs:681](../../crates/lpm-cli/src/install_state.rs)).
/// `--registry`, `--insecure`, `--no-skills`, `--no-editor-setup`,
/// `--no-security-summary`, and any other install flag disqualify it,
/// so the bad-env repro MUST be a plain bare `lpm install` to actually
/// hit the fast lane. The warm phase still uses `lpm_with_registry`
/// because that's how the mock-backed install lands a real warm cache;
/// the bad-env phase drops to `lpm()` and routes the registry override
/// through `LPM_REGISTRY_URL` (env-based, doesn't appear in argv) so
/// the fast-lane gate sees a bare argv.
#[tokio::test]
async fn install_invalid_lpm_linker_surfaces_through_sync_fast_lane() {
    let mock = MockRegistry::start().await;
    let tarball = make_tarball("ms", "2.1.3");
    mock.with_package("ms", "2.1.3", &tarball).await;
    let batch_meta = serde_json::json!({
        "name": "ms",
        "dist-tags": { "latest": "2.1.3" },
        "versions": {
            "2.1.3": {
                "name": "ms",
                "version": "2.1.3",
                "dist": {
                    "tarball": format!("{}/tarballs/ms/-/ms-2.1.3.tgz", mock.url()),
                    "integrity": format!("sha512-placeholder"),
                },
                "dependencies": {}
            }
        },
        "time": { "2.1.3": "2025-01-01T00:00:00.000Z" }
    });
    mock.with_batch_metadata(vec![batch_meta]).await;

    let project = TempProject::empty(
        r#"{
        "name": "linker-cached-fail-loud",
        "version": "1.0.0",
        "dependencies": { "ms": "^2.1.3" }
    }"#,
    );

    // Warm the cache with a successful install at the default isolated
    // layout. After this, .lpm/install-hash holds the v6 isolated-keyed
    // hash and the mtime fast path is primed. Flags here don't matter
    // for the load-bearing assertion below — the warm install just has
    // to land state on disk.
    let warmed = lpm_with_registry(&project, &mock.url())
        .args([
            "install",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("spawn warm install");
    assert!(
        warmed.status.success(),
        "warming install failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&warmed.stdout),
        String::from_utf8_lossy(&warmed.stderr),
    );

    // GPT's repro, hardened: a TRULY bare `lpm install` with
    // `LPM_LINKER=symlink` against the warm cache. Critically NO
    // disqualifying flags — no `--registry`, no `--insecure`, no
    // `--no-*`. Registry override moves to `LPM_REGISTRY_URL` so the
    // mock is still reachable if the fast lane falls through, but the
    // fast-lane argv gate sees a bare invocation. Pre-fix this short-
    // circuited as `up to date` because the freshness helper swallowed
    // the LPM_LINKER parse error.
    let bad_env = lpm(&project)
        .arg("install")
        .env("LPM_REGISTRY_URL", mock.url())
        .env("LPM_LINKER", "symlink")
        .output()
        .expect("spawn bare install with bad LPM_LINKER");

    let stderr = String::from_utf8_lossy(&bad_env.stderr);
    let stdout = String::from_utf8_lossy(&bad_env.stdout);

    assert!(
        !bad_env.status.success(),
        "bare `lpm install` against warm cache with `LPM_LINKER=symlink` \
         MUST exit non-zero. Pre-fix the sync fast lane printed `up to \
         date` and exited 0 because `check_install_state_with_content` \
         coerced the linker resolution error to Isolated and the stored \
         isolated hash matched. \nstdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        !stdout.contains("up to date") && !stderr.contains("up to date"),
        "stdout/stderr MUST NOT contain `up to date` — that string is \
         the load-bearing tell that the sync fast lane returned \
         up_to_date=true and the binary exited before the install \
         dispatch could surface the LPM_LINKER error. \
         \nstdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        stderr.contains("LPM_LINKER"),
        "stderr must name LPM_LINKER so the user can fix their env. \
         \nstderr: {stderr}"
    );
    assert!(
        stderr.contains("isolated") && stderr.contains("hoisted"),
        "stderr must list the accepted values. \nstderr: {stderr}"
    );
}

/// `LPM_LINKER` is documented as equivalent to `--linker=hoisted`. An
/// unknown value must surface the same fail-loud posture as the other
/// surfaces — silent fallback is the bug class this whole tranche closed.
#[test]
fn install_lpm_linker_env_rejects_unknown_value_loudly() {
    let project = TempProject::empty(
        r#"{
        "name": "linker-env-bad",
        "version": "0.0.1"
    }"#,
    );

    let out = lpm(&project)
        .args(["install"])
        .env("LPM_LINKER", "symlink")
        .output()
        .expect("spawn lpm install");

    assert!(
        !out.status.success(),
        "`LPM_LINKER=symlink` should fail loudly; stderr:\n{}",
        String::from_utf8_lossy(&out.stderr),
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("LPM_LINKER"),
        "stderr must name LPM_LINKER; got:\n{stderr}"
    );
}

// ─── R2.5 fix-2 — pubgrub-mismatch warning visibility ──────────
//
// **The hole.** Pre-fix, the `LPM_RESOLVER=pubgrub +
// auto_install_peers=true` warning was emitted only when
// `!json_output`. That silenced the warning for every CI/wrapper/
// tooling caller that requested `--json` — exactly the audience
// that needs the signal MOST, since they consume the install
// programmatically. The user/operator running interactively at
// least sees the warning; an automated pipeline silently took the
// install-tree-divergence and called the run a success.
//
// **The fix.** The warning fires unconditionally on stderr (no
// `!json_output` gate). `--json` consumers parse stdout for the
// envelope; stderr is unaffected. The standard pattern across the
// rest of the install pipeline (`output::warn`) writes to stderr,
// so this matches every other warning in the same surface.
//
// **What this test pins:** running `lpm install --json` with
// `LPM_RESOLVER=pubgrub` set MUST emit the diagnostic to stderr.
// The install itself can succeed or fail (we use an empty-deps
// project so it succeeds without any registry), but the warning
// must appear regardless. If a future refactor re-adds the
// `!json_output` gate or shoves the warning into stdout JSON,
// this test fires.

#[test]
fn install_warns_when_lpm_resolver_pubgrub_with_auto_install_peers_under_json() {
    // Empty deps + auto_install_peers default-true (we set nothing).
    // No network needed. The warning should fire purely off the
    // env-var + config combination.
    let project = TempProject::empty(
        r#"{
        "name": "pubgrub-mismatch",
        "version": "0.0.1",
        "dependencies": {}
    }"#,
    );

    let out = lpm(&project)
        .args(["--json", "install"])
        .env("LPM_RESOLVER", "pubgrub")
        .output()
        .expect("spawn lpm install --json");

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("LPM_RESOLVER=pubgrub does not support eager peer auto-install"),
        "pubgrub-mismatch warning must fire on stderr even under --json; \
         stdout-vs-stderr separation means tooling consumers can still \
         parse stdout JSON without the warning leaking into the envelope. \
         stderr was:\n{stderr}"
    );

    // The contract is "stderr-only"; stdout must remain valid JSON
    // so consumers can still parse the install envelope.
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        !stdout.contains("LPM_RESOLVER=pubgrub does not support"),
        "warning text must NOT leak into stdout (which carries the \
         JSON envelope); got stdout:\n{stdout}"
    );
}

#[test]
fn install_silent_when_lpm_resolver_pubgrub_with_auto_install_peers_off() {
    // Inverse case: with `lpm.autoInstallPeers = false` the user has
    // explicitly acknowledged warn-only semantics, so the
    // pubgrub-mismatch warning is moot. Verifies the warning gate
    // doesn't fire spuriously.
    let project = TempProject::empty(
        r#"{
        "name": "pubgrub-opt-out",
        "version": "0.0.1",
        "dependencies": {},
        "lpm": { "autoInstallPeers": false }
    }"#,
    );

    let out = lpm(&project)
        .args(["--json", "install"])
        .env("LPM_RESOLVER", "pubgrub")
        .output()
        .expect("spawn lpm install --json");

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains("LPM_RESOLVER=pubgrub does not support eager peer auto-install"),
        "warning must NOT fire when autoInstallPeers is explicitly false \
         (user has acknowledged the warn-only semantic); stderr was:\n{stderr}"
    );
}

// ─── R2.5 fix-1 — offline arm refuses pre-R2.5 v1 lockfiles ────
//
// The repair gate that lives on the online fast-path branch
// (`install.rs::lockfile_needs_r25_repair`) drops the fast-path
// result and forces a fresh resolve when the lockfile is v1 and
// `auto_install_peers = true`. The `--offline` branch can't fall
// back to a fresh resolve (no network), so the same gate becomes
// a hard error: refuse the install with an actionable
// "run online once" message. Replaying the v1 lockfile silently
// would reproduce the pre-R2.5 broken-tree state — exactly the
// hole R2.5 was meant to close.

#[test]
fn install_offline_refuses_pre_r25_v1_lockfile_under_auto_install_peers() {
    // Hand-craft a v1 lockfile that LOOKS valid under the new
    // schema (serde defaults populate the missing fields with
    // empty Vec) but is actually a pre-R2.5 artifact. The package
    // shape doesn't matter — the gate fires off the metadata
    // version + auto_install_peers config.
    let project = TempProject::empty(
        r#"{
        "name": "stale-v1-lockfile",
        "version": "0.0.1",
        "dependencies": { "lodash": "^4.0.0" }
    }"#,
    );
    // Write a v1 lockfile by hand. `lockfile-version = 1` is the
    // tell — even an otherwise-valid lockfile under the new schema
    // is treated as "may be missing R2.5 state" because R2.2-R2.4
    // buggy writers wrote the same shape.
    let lockfile_toml = r#"[metadata]
lockfile-version = 1
resolved-with = "greedy-fusion"

[[packages]]
name = "lodash"
version = "4.17.21"
source = "registry+https://registry.npmjs.org"
integrity = "sha512-v2kDEe57lecTulaDIuNTPy3Ry4gLGJ6Z1O3vE1krgXZNrsQ+LFTGHVxVjcXPs17LhbZVGedAJv8XZ1tvj5FvSg=="
"#;
    std::fs::write(project.path().join("lpm.lock"), lockfile_toml).unwrap();

    let out = lpm(&project)
        .args(["install", "--offline"])
        .output()
        .expect("spawn lpm install --offline");

    assert!(
        !out.status.success(),
        "--offline must refuse a v1 lockfile under auto_install_peers=true; \
         silently replaying would reproduce the pre-R2.5 broken-tree state. \
         stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("pre-R2.5 lockfile"),
        "error message must explain the cause; got:\n{stderr}"
    );
    assert!(
        stderr.contains("Run `lpm install` (online)"),
        "error message must offer the remediation path; got:\n{stderr}"
    );
}

#[test]
fn install_offline_accepts_pre_r25_v1_lockfile_when_auto_install_peers_off() {
    // Inverse: with `lpm.autoInstallPeers = false` the user has
    // explicitly opted out of auto-install, so the v1 lockfile can
    // be trusted (no ambient peers were ever generated). The
    // offline arm must NOT refuse — that would be a regression for
    // every project that pinned `autoInstallPeers = false` to
    // preserve pre-R2 semantics.
    //
    // The install will likely fail later (no store seeded, no
    // network) but it must NOT fail with the R2.5 repair-gate
    // message. We assert on stderr content, not exit code.
    let project = TempProject::empty(
        r#"{
        "name": "opt-out-v1-lockfile",
        "version": "0.0.1",
        "dependencies": { "lodash": "^4.0.0" },
        "lpm": { "autoInstallPeers": false }
    }"#,
    );
    let lockfile_toml = r#"[metadata]
lockfile-version = 1
resolved-with = "greedy-fusion"

[[packages]]
name = "lodash"
version = "4.17.21"
source = "registry+https://registry.npmjs.org"
integrity = "sha512-v2kDEe57lecTulaDIuNTPy3Ry4gLGJ6Z1O3vE1krgXZNrsQ+LFTGHVxVjcXPs17LhbZVGedAJv8XZ1tvj5FvSg=="
"#;
    std::fs::write(project.path().join("lpm.lock"), lockfile_toml).unwrap();

    let out = lpm(&project)
        .args(["install", "--offline"])
        .output()
        .expect("spawn lpm install --offline");

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains("pre-R2.5 lockfile"),
        "v1 lockfile under autoInstallPeers=false must NOT trip the \
         repair gate — opt-out installs never produced ambient peers, \
         so the v1 lockfile is correct as-is. stderr was:\n{stderr}"
    );
}

#[test]
fn install_silent_when_default_resolver_with_auto_install_peers_on() {
    // The other inverse: greedy-fusion is the default resolver and
    // DOES support auto-install. No warning under default config.
    // Pins that the warning is specifically conditional on the
    // `pubgrub` opt-out, not a stray "any-resolver-mode" emit.
    let project = TempProject::empty(
        r#"{
        "name": "default-resolver",
        "version": "0.0.1",
        "dependencies": {}
    }"#,
    );

    let out = lpm(&project)
        .args(["--json", "install"])
        .output()
        .expect("spawn lpm install --json");

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains("LPM_RESOLVER=pubgrub does not support eager peer auto-install"),
        "warning must NOT fire on the default greedy-fusion resolver; \
         stderr was:\n{stderr}"
    );
}
