//! Workflow tests for `lpm outdated`.
//!
//! `lpm outdated` checks `package.json` dependencies against the
//! registry's latest tag. By default it covers both `@lpm.dev/*` and
//! npm packages; `--registry-only lpm` preserves the narrower
//! LPM-only scan for callers that want it.

mod support;

use support::mock_registry::{MockRegistry, make_tarball};
use support::{TempProject, lpm_with_registry};

/// Mount metadata for one `@lpm.dev/*` package on the mock so
/// `client.get_package_metadata` resolves to a known latest tag.
async fn mount_lpm_package_latest(mock: &MockRegistry, name: &str, latest_version: &str) {
    let tarball = make_tarball(name, latest_version);
    mock.with_package(name, latest_version, &tarball).await;
}

/// Write a minimal lpm.lock containing one package entry. Lets these
/// tests exercise the outdated logic in isolation from the full install
/// pipeline.
fn write_minimal_lockfile(project: &TempProject, name: &str, version: &str) {
    project.write_file(
        "lpm.lock",
        &format!(
            "[metadata]\nlockfile-version = 2\nresolved-with = \"greedy-fusion\"\n\n\
             [[packages]]\nname = \"{name}\"\nversion = \"{version}\"\n\
             source = \"registry+https://lpm.dev\"\n",
        ),
    );
}

// ─── Error + edge paths ─────────────────────────────────────────────────

#[tokio::test]
async fn outdated_without_package_json_fails_clearly() {
    // tempfile dir with no package.json.
    let dir = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();

    let mut cmd = assert_cmd::Command::cargo_bin("lpm-rs").unwrap();
    cmd.current_dir(dir.path())
        .env("HOME", home.path())
        .env("NO_COLOR", "1")
        .env("LPM_NO_UPDATE_CHECK", "1")
        .env_remove("LPM_TOKEN");

    let out = cmd.args(["outdated"]).output().expect("spawn lpm outdated");
    assert!(
        !out.status.success(),
        "outdated must fail with no package.json"
    );

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.to_lowercase().contains("package.json"),
        "stderr should mention package.json; got:\n{stderr}"
    );
}

#[tokio::test]
async fn outdated_empty_deps_emits_empty_json_envelope() {
    let project = TempProject::empty(r#"{"name":"empty-outdated","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;

    let out = lpm_with_registry(&project, &mock.url())
        .args(["outdated", "--json"])
        .output()
        .expect("spawn lpm outdated --json");
    assert!(out.status.success());

    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let envelope: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("outdated --json must be valid JSON: {e}\n---\n{stdout}"));

    assert_eq!(envelope["success"], serde_json::json!(true));
    assert_eq!(envelope["count"], serde_json::json!(0));
    assert_eq!(envelope["outdated_count"], serde_json::json!(0));
    assert_eq!(envelope["packages"], serde_json::json!([]));
}

// ─── Behavior contracts ─────────────────────────────────────────────────

/// A pure-npm project should now surface outdated packages in the
/// default report instead of returning a false-clean zero-count
/// envelope.
#[tokio::test]
async fn outdated_reports_non_lpm_packages_by_default() {
    let project = TempProject::empty(
        r#"{"name":"npm-only","version":"1.0.0","dependencies":{"ms":"^2.1.3"}}"#,
    );
    write_minimal_lockfile(&project, "ms", "2.1.3");

    let mock = MockRegistry::start().await;
    mock.with_package("ms", "9.9.9", &make_tarball("ms", "9.9.9"))
        .await;

    let out = lpm_with_registry(&project, &mock.url())
        .args(["outdated", "--json"])
        .output()
        .expect("spawn lpm outdated --json");
    assert!(
        out.status.success(),
        "outdated should exit 0 on npm-only project"
    );

    let envelope: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("valid JSON envelope");
    assert_eq!(
        envelope["count"],
        serde_json::json!(1),
        "npm dependencies should now be included in outdated results; got envelope: {envelope:#}"
    );
    assert_eq!(envelope["outdated_count"], serde_json::json!(1));

    let entry = &envelope["packages"][0];
    assert_eq!(entry["name"], serde_json::json!("ms"));
    assert_eq!(entry["current"], serde_json::json!("2.1.3"));
    assert_eq!(entry["wanted"], serde_json::json!("^2.1.3"));
    assert_eq!(entry["latest"], serde_json::json!("9.9.9"));
    assert_eq!(entry["outdated"], serde_json::json!(true));
}

/// `--registry-only lpm` keeps the previous LPM-only scope for users
/// who explicitly want to ignore npm dependencies in the report.
#[tokio::test]
async fn outdated_registry_only_lpm_skips_non_lpm_packages() {
    let project = TempProject::empty(
        r#"{"name":"npm-only","version":"1.0.0","dependencies":{"ms":"^2.1.3"}}"#,
    );
    write_minimal_lockfile(&project, "ms", "2.1.3");

    let mock = MockRegistry::start().await;
    mock.with_package("ms", "9.9.9", &make_tarball("ms", "9.9.9"))
        .await;

    let out = lpm_with_registry(&project, &mock.url())
        .args(["outdated", "--json", "--registry-only", "lpm"])
        .output()
        .expect("spawn lpm outdated --json --registry-only lpm");
    assert!(
        out.status.success(),
        "outdated should still exit 0 when narrowed to LPM-only coverage"
    );

    let envelope: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("valid JSON envelope");
    assert_eq!(envelope["count"], serde_json::json!(0));
    assert_eq!(envelope["outdated_count"], serde_json::json!(0));
}

#[tokio::test]
async fn outdated_reports_newer_version_for_outdated_lpm_dep() {
    let pkg = "@lpm.dev/owner.outdated-pkg";
    let project = TempProject::empty(&format!(
        r#"{{"name":"outdated-test","version":"1.0.0","dependencies":{{"{pkg}":"^1.0.0"}}}}"#
    ));
    write_minimal_lockfile(&project, pkg, "1.0.0");

    let mock = MockRegistry::start().await;
    mount_lpm_package_latest(&mock, pkg, "2.5.0").await;

    let out = lpm_with_registry(&project, &mock.url())
        .args(["outdated", "--json"])
        .output()
        .expect("spawn lpm outdated --json");
    assert!(
        out.status.success(),
        "outdated exits 0 even when packages are outdated"
    );

    let envelope: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("valid JSON envelope");
    assert_eq!(envelope["count"], serde_json::json!(1));
    assert_eq!(envelope["outdated_count"], serde_json::json!(1));

    let entry = &envelope["packages"][0];
    assert_eq!(entry["name"], serde_json::json!(pkg));
    assert_eq!(entry["current"], serde_json::json!("1.0.0"));
    assert_eq!(entry["wanted"], serde_json::json!("^1.0.0"));
    assert_eq!(entry["latest"], serde_json::json!("2.5.0"));
    assert_eq!(entry["outdated"], serde_json::json!(true));
}

#[tokio::test]
async fn outdated_reports_zero_when_installed_matches_latest() {
    let pkg = "@lpm.dev/owner.up-to-date-pkg";
    let project = TempProject::empty(&format!(
        r#"{{"name":"current-test","version":"1.0.0","dependencies":{{"{pkg}":"^1.0.0"}}}}"#
    ));
    write_minimal_lockfile(&project, pkg, "1.4.2");

    let mock = MockRegistry::start().await;
    mount_lpm_package_latest(&mock, pkg, "1.4.2").await;

    let out = lpm_with_registry(&project, &mock.url())
        .args(["outdated", "--json"])
        .output()
        .expect("spawn lpm outdated --json");
    assert!(out.status.success());

    let envelope: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("valid JSON envelope");
    assert_eq!(envelope["count"], serde_json::json!(1));
    assert_eq!(
        envelope["outdated_count"],
        serde_json::json!(0),
        "outdated_count must be 0 when current == latest"
    );

    let entry = &envelope["packages"][0];
    assert_eq!(entry["outdated"], serde_json::json!(false));
    assert_eq!(entry["current"], serde_json::json!("1.4.2"));
    assert_eq!(entry["latest"], serde_json::json!("1.4.2"));
}

// ─── JSON contract snapshot ─────────────────────────────────────────────

#[tokio::test]
async fn outdated_json_envelope_with_one_outdated_pkg_matches_snapshot() {
    let pkg = "@lpm.dev/owner.snap-outdated";
    let project = TempProject::empty(&format!(
        r#"{{"name":"snap-test","version":"1.0.0","dependencies":{{"{pkg}":"^1.0.0"}}}}"#
    ));
    write_minimal_lockfile(&project, pkg, "1.0.0");

    let mock = MockRegistry::start().await;
    mount_lpm_package_latest(&mock, pkg, "2.0.0").await;

    let out = lpm_with_registry(&project, &mock.url())
        .args(["outdated", "--json"])
        .output()
        .expect("spawn lpm outdated --json");
    assert!(out.status.success());

    let envelope: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("valid JSON envelope");
    insta::assert_json_snapshot!("outdated_json_envelope_one_outdated", envelope);
}
