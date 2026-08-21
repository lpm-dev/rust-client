//! Workflow tests for `lpm outdated`.
//!
//! `lpm outdated` checks `package.json` dependencies against the
//! registry's latest tag. By default it covers both `@lpm.dev/*` and
//! npm packages; `--registry-only lpm` preserves the narrower
//! LPM-only scan for callers that want it.

mod support;

use support::mock_registry::{MockRegistry, make_tarball};
use support::{TempProject, lpm, lpm_with_registry};
use wiremock::matchers::{method, path, path_regex, query_param};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

#[derive(Clone)]
struct RecordDelayedOutdatedMetadataStart {
    starts: std::sync::Arc<std::sync::Mutex<Vec<std::time::Instant>>>,
    delay: std::time::Duration,
}

impl Respond for RecordDelayedOutdatedMetadataStart {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        self.starts
            .lock()
            .expect("record outdated metadata request start")
            .push(std::time::Instant::now());
        let name = request
            .url
            .path()
            .strip_prefix("/api/registry/")
            .unwrap_or_default();
        ResponseTemplate::new(200)
            .set_delay(self.delay)
            .set_body_json(serde_json::json!({
                "name": name,
                "dist-tags": { "latest": "1.1.0" },
                "versions": {
                    "1.0.0": { "name": name, "version": "1.0.0" },
                    "1.1.0": { "name": name, "version": "1.1.0" }
                },
                "time": {
                    "1.0.0": "2025-01-01T00:00:00.000Z",
                    "1.1.0": "2025-01-01T00:00:00.000Z"
                }
            }))
    }
}

fn iso8601_n_secs_ago(n_secs: i64) -> String {
    use chrono::SecondsFormat;
    let dt = chrono::Utc::now() - chrono::Duration::seconds(n_secs);
    dt.to_rfc3339_opts(SecondsFormat::Millis, true)
}

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
    write_minimal_lockfile_with_source(project, name, version, "registry+https://lpm.dev");
}

/// Write a minimal lpm.lock with an explicit source URL so source-gated
/// metadata lookups can be exercised directly.
fn write_minimal_lockfile_with_source(
    project: &TempProject,
    name: &str,
    version: &str,
    source: &str,
) {
    project.write_file(
        "lpm.lock",
        &format!(
            "[metadata]\nlockfile-version = 2\nresolved-with = \"greedy-fusion\"\n\n\
             [[packages]]\nname = \"{name}\"\nversion = \"{version}\"\n\
             source = \"{source}\"\n",
        ),
    );
}

#[test]
fn outdated_rejects_invalid_lpm_dependency_names() {
    let invalid_name = "@lpm.dev/invalid name";
    let project = TempProject::empty(&format!(
        r#"{{"name":"invalid-outdated","version":"1.0.0","dependencies":{{"{invalid_name}":"^1.0.0"}}}}"#
    ));

    let out = lpm(&project)
        .args(["outdated", "--json"])
        .output()
        .expect("spawn outdated with invalid dependency name");
    assert!(
        !out.status.success(),
        "invalid dependency must fail outdated"
    );

    let envelope: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("valid JSON failure envelope");
    assert!(
        envelope["error"]
            .as_str()
            .is_some_and(|message| message.contains(invalid_name)),
        "error must name the invalid dependency: {envelope}",
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
        .env("LPM_HOME", home.path().join(".lpm"))
        .env("NO_COLOR", "1")
        .env("LPM_NO_UPDATE_CHECK", "1")
        .env("LPM_DISABLE_TELEMETRY", "1")
        .env("LPM_FORCE_FILE_AUTH", "1")
        .env("LPM_TEST_FAST_SCRYPT", "1")
        .env("LPM_FORCE_FILE_VAULT", "1")
        .env("LPM_DISABLE_HOST_CLI_AUTH", "1")
        .env(
            "LPM_SECURITY_POLICY_PATH",
            home.path().join(".lpm/security-policy.toml"),
        )
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

#[test]
fn outdated_rejects_a_corrupt_project_lockfile() {
    let project = TempProject::empty(
        r#"{"name":"corrupt-lock-outdated","version":"1.0.0","dependencies":{"@lpm.dev/acme.corrupt":"^1.0.0"}}"#,
    );
    project.write_file("lpm.lock", "this is not a lockfile");

    let out = lpm(&project)
        .args(["outdated", "--json"])
        .output()
        .expect("spawn outdated with corrupt lockfile");

    assert!(!out.status.success());
    let envelope: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("valid JSON error envelope");
    assert!(
        envelope["error"]
            .as_str()
            .is_some_and(|error| error.contains("failed to read project lockfile")),
        "error should identify the corrupt lockfile: {envelope:#}",
    );
}

// ─── Behavior contracts ─────────────────────────────────────────────────

/// A pure-npm project should now surface outdated packages in the
/// default report instead of returning a false-clean zero-count
/// envelope.
///
/// The lockfile must record `registry+https://registry.npmjs.org`
/// before the privacy gate forwards the name to public npm. Sources
/// without public npm or LPM-proxy attribution are skipped instead.
#[tokio::test]
async fn outdated_reports_non_lpm_packages_by_default() {
    let project = TempProject::empty(
        r#"{"name":"npm-only","version":"1.0.0","dependencies":{"ms":"^2.1.3"}}"#,
    );
    write_minimal_lockfile_with_source(
        &project,
        "ms",
        "2.1.3",
        "registry+https://registry.npmjs.org/",
    );

    let mock = MockRegistry::start().await;
    mock.with_full_package_metadata(
        "ms",
        "9.9.9",
        &[
            (
                "2.1.3",
                serde_json::json!({}),
                Some(make_tarball("ms", "2.1.3")),
            ),
            (
                "2.9.9",
                serde_json::json!({}),
                Some(make_tarball("ms", "2.9.9")),
            ),
            (
                "9.9.9",
                serde_json::json!({}),
                Some(make_tarball("ms", "9.9.9")),
            ),
        ],
    )
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
    assert_eq!(envelope["schema_version"], serde_json::json!(2));
    assert_eq!(
        envelope["count"],
        serde_json::json!(1),
        "npm dependencies should now be included in outdated results; got envelope: {envelope:#}"
    );
    assert_eq!(envelope["outdated_count"], serde_json::json!(1));

    let entry = &envelope["packages"][0];
    assert_eq!(entry["name"], serde_json::json!("ms"));
    assert_eq!(entry["current"], serde_json::json!("2.1.3"));
    assert_eq!(entry["wanted"], serde_json::json!("2.9.9"));
    assert_eq!(entry["latest"], serde_json::json!("9.9.9"));
    assert_eq!(entry["section"], serde_json::json!("dependencies"));
    assert_eq!(entry["outdated"], serde_json::json!(true));
}

#[tokio::test]
async fn outdated_resolves_npm_aliases_through_their_canonical_package() {
    let project = TempProject::empty(
        r#"{"name":"alias-outdated","version":"1.0.0","dependencies":{"strip-ansi-cjs":"npm:strip-ansi@^6.0.0"}}"#,
    );
    let mut lockfile = lpm_lockfile::Lockfile::new();
    lockfile
        .root_aliases
        .insert("strip-ansi-cjs".to_string(), "strip-ansi".to_string());
    lockfile.add_package(lpm_lockfile::LockedPackage {
        name: "strip-ansi".to_string(),
        version: "6.0.0".to_string(),
        source: Some("registry+https://registry.npmjs.org".to_string()),
        dependencies: vec!["strip-ansi@5.0.0".to_string()],
        ..Default::default()
    });
    lockfile.add_package(lpm_lockfile::LockedPackage {
        name: "strip-ansi".to_string(),
        version: "5.0.0".to_string(),
        source: Some("registry+https://lpm.dev".to_string()),
        ..Default::default()
    });
    support::finalize_exact_lockfile_fixture(
        &mut lockfile,
        &[("strip-ansi-cjs", "strip-ansi", "6.0.0")],
    );
    lockfile
        .write_to_file(&project.path().join("lpm.lock"))
        .expect("write alias lockfile");

    let mock = MockRegistry::start().await;
    mock.with_full_package_metadata(
        "strip-ansi",
        "6.1.0",
        &[
            (
                "6.0.0",
                serde_json::json!({}),
                Some(make_tarball("strip-ansi", "6.0.0")),
            ),
            (
                "6.1.0",
                serde_json::json!({}),
                Some(make_tarball("strip-ansi", "6.1.0")),
            ),
        ],
    )
    .await;

    let out = lpm_with_registry(&project, &mock.url())
        .args(["outdated", "--json"])
        .output()
        .expect("spawn outdated for npm alias");
    assert!(
        out.status.success(),
        "alias lookup must succeed; stdout: {} stderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );

    let envelope: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("valid outdated envelope");
    assert_eq!(
        envelope["packages"][0],
        serde_json::json!({
            "name": "strip-ansi-cjs",
            "current": "6.0.0",
            "wanted": "6.1.0",
            "wanted_range": "npm:strip-ansi@^6.0.0",
            "latest": "6.1.0",
            "section": "dependencies",
            "outdated": true,
        }),
    );
    let received_paths = mock
        .server()
        .received_requests()
        .await
        .expect("wiremock recorded requests")
        .into_iter()
        .map(|request| request.url.path().to_string())
        .collect::<Vec<_>>();
    assert!(received_paths.iter().any(|path| path == "/strip-ansi"));
    assert!(
        !received_paths
            .iter()
            .any(|path| path == "/api/registry/strip-ansi"),
        "the same-name transitive source must not override the exact public root: {received_paths:?}"
    );
}

#[tokio::test]
async fn outdated_treats_fresh_latest_as_up_to_date_when_current_version_is_mature() {
    let package = "@lpm.dev/owner.cooldown-outdated";
    let project = TempProject::empty(&format!(
        r#"{{"name":"outdated-release-age","version":"1.0.0","dependencies":{{"{package}":"^1.0.0"}},"lpm":{{"minimumReleaseAge":86400}}}}"#,
    ));
    write_minimal_lockfile(&project, package, "1.0.0");

    let mock = MockRegistry::start().await;
    let v1_0_0 = make_tarball(package, "1.0.0");
    let v1_1_0 = make_tarball(package, "1.1.0");
    let metadata = serde_json::json!({
        "name": package,
        "dist-tags": { "latest": "1.1.0" },
        "modified": iso8601_n_secs_ago(3_600),
        "versions": {
            "1.0.0": {
                "name": package,
                "version": "1.0.0",
                "dist": {
                    "tarball": mock.tarball_url(package, "1.0.0"),
                    "integrity": support::mock_registry::compute_integrity(&v1_0_0),
                },
                "dependencies": {}
            },
            "1.1.0": {
                "name": package,
                "version": "1.1.0",
                "dist": {
                    "tarball": mock.tarball_url(package, "1.1.0"),
                    "integrity": support::mock_registry::compute_integrity(&v1_1_0),
                },
                "dependencies": {}
            }
        },
        "time": {
            "1.0.0": iso8601_n_secs_ago(3 * 86_400),
            "1.1.0": iso8601_n_secs_ago(3_600)
        }
    });
    mock.with_package_metadata_and_tarballs(
        package,
        metadata,
        &[("1.0.0", v1_0_0), ("1.1.0", v1_1_0)],
    )
    .await;

    let out = lpm_with_registry(&project, &mock.url())
        .args(["outdated", "--json"])
        .output()
        .expect("spawn lpm outdated --json");
    assert!(
        out.status.success(),
        "outdated should succeed when the only newer version is still inside minimumReleaseAge\nstderr: {}",
        String::from_utf8_lossy(&out.stderr),
    );

    let envelope: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("valid JSON envelope");
    assert_eq!(envelope["outdated_count"], serde_json::json!(0));
    let entry = &envelope["packages"][0];
    assert_eq!(entry["wanted"], serde_json::json!("1.0.0"));
    assert_eq!(entry["latest"], serde_json::json!("1.0.0"));
    assert_eq!(entry["outdated"], serde_json::json!(false));
}

#[tokio::test]
async fn outdated_hydrates_missing_release_times_before_reporting() {
    let package = "@lpm.dev/owner.hydrated-outdated";
    let project = TempProject::empty(&format!(
        r#"{{"name":"hydrated-outdated","version":"1.0.0","dependencies":{{"{package}":"^1.0.0"}},"lpm":{{"minimumReleaseAge":86400}}}}"#,
    ));
    write_minimal_lockfile(&project, package, "1.0.0");

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("/api/registry/{package}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "name": package,
            "dist-tags": { "latest": "1.1.0" },
            "modified": iso8601_n_secs_ago(3_600),
            "versions": {
                "1.0.0": { "name": package, "version": "1.0.0" },
                "1.1.0": { "name": package, "version": "1.1.0" }
            }
        })))
        .with_priority(2)
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/api/registry/{package}")))
        .and(query_param("release_times", "1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "name": package,
            "time": {
                "1.0.0": iso8601_n_secs_ago(3 * 86_400),
                "1.1.0": iso8601_n_secs_ago(3_600)
            }
        })))
        .with_priority(1)
        .expect(1)
        .mount(&server)
        .await;

    let output = lpm_with_registry(&project, &server.uri())
        .args(["outdated", "--json"])
        .output()
        .expect("run outdated with hydrated release times");
    assert!(
        output.status.success(),
        "release-time hydration should produce a clean report\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let envelope: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("valid outdated envelope");
    assert_eq!(envelope["outdated_count"], serde_json::json!(0));
    assert_eq!(
        envelope["packages"][0]["latest"],
        serde_json::json!("1.0.0")
    );
}

#[tokio::test]
async fn outdated_reports_npm_packages_installed_through_configured_lpm_registry() {
    let project = TempProject::empty(
        r#"{"name":"proxy-installed","version":"1.0.0","dependencies":{"ms":"2.1.3"}}"#,
    );

    let mock = MockRegistry::start().await;
    mock.with_full_package_metadata(
        "ms",
        "2.1.4",
        &[
            (
                "2.1.3",
                serde_json::json!({}),
                Some(make_tarball("ms", "2.1.3")),
            ),
            (
                "2.1.4",
                serde_json::json!({}),
                Some(make_tarball("ms", "2.1.4")),
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

    let out = lpm_with_registry(&project, &mock.url())
        .args(["outdated", "--json"])
        .output()
        .expect("spawn lpm outdated --json");
    assert!(
        out.status.success(),
        "outdated should include npm packages previously resolved through the configured LPM registry\nstderr: {}",
        String::from_utf8_lossy(&out.stderr),
    );

    let envelope: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("valid JSON envelope");
    assert_eq!(
        envelope["count"],
        serde_json::json!(1),
        "configured-registry npm package should be checked; lockfile:\n{}\n\nenvelope:\n{envelope:#}",
        project.read_file("lpm.lock"),
    );
    assert_eq!(envelope["outdated_count"], serde_json::json!(1));
    assert_eq!(envelope["packages"][0]["name"], serde_json::json!("ms"));
    assert_eq!(
        envelope["packages"][0]["current"],
        serde_json::json!("2.1.3")
    );
    assert_eq!(
        envelope["packages"][0]["latest"],
        serde_json::json!("2.1.4")
    );
    assert!(
        envelope.get("skipped_private").is_none(),
        "configured-registry npm packages must not be reported as private skips: {envelope:#}",
    );
}

#[tokio::test]
async fn outdated_includes_dev_dependencies_by_default() {
    let project = TempProject::empty(
        r#"{"name":"dev-only","version":"1.0.0","devDependencies":{"vite":"^5.0.0"}}"#,
    );
    write_minimal_lockfile_with_source(
        &project,
        "vite",
        "5.0.0",
        "registry+https://registry.npmjs.org/",
    );

    let mock = MockRegistry::start().await;
    mock.with_full_package_metadata(
        "vite",
        "6.0.0",
        &[
            (
                "5.0.0",
                serde_json::json!({}),
                Some(make_tarball("vite", "5.0.0")),
            ),
            (
                "5.9.1",
                serde_json::json!({}),
                Some(make_tarball("vite", "5.9.1")),
            ),
            (
                "6.0.0",
                serde_json::json!({}),
                Some(make_tarball("vite", "6.0.0")),
            ),
        ],
    )
    .await;

    let out = lpm_with_registry(&project, &mock.url())
        .args(["outdated", "--json"])
        .output()
        .expect("spawn lpm outdated --json");
    assert!(
        out.status.success(),
        "outdated should exit 0 for a devDependencies-only project"
    );

    let envelope: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("valid JSON envelope");
    assert_eq!(envelope["schema_version"], serde_json::json!(2));
    assert_eq!(envelope["count"], serde_json::json!(1));
    assert_eq!(envelope["outdated_count"], serde_json::json!(1));

    let entry = &envelope["packages"][0];
    assert_eq!(entry["name"], serde_json::json!("vite"));
    assert_eq!(entry["current"], serde_json::json!("5.0.0"));
    assert_eq!(entry["wanted"], serde_json::json!("5.9.1"));
    assert_eq!(entry["latest"], serde_json::json!("6.0.0"));
    assert_eq!(entry["section"], serde_json::json!("devDependencies"));
    assert_eq!(entry["outdated"], serde_json::json!(true));
}

/// `--registry-only lpm` keeps the previous LPM-only scope for users
/// who explicitly want to ignore npm dependencies in the report.
#[tokio::test]
async fn outdated_registry_only_lpm_skips_non_lpm_packages() {
    let project = TempProject::empty(
        r#"{"name":"npm-only","version":"1.0.0","dependencies":{"ms":"^2.1.3"}}"#,
    );
    write_minimal_lockfile_with_source(
        &project,
        "ms",
        "2.1.3",
        "registry+https://registry.npmjs.org/",
    );

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

/// A project whose lockfile lacks public npm or LPM-proxy attribution
/// must not have its package names forwarded to public npm. The dep is
/// reported under `skipped_private` and is absent from `packages`.
#[tokio::test]
async fn outdated_skips_private_named_packages_without_npm_public_source() {
    let project = TempProject::empty(
        r#"{"name":"private-named","version":"1.0.0","dependencies":{"ms":"^2.1.3"}}"#,
    );
    write_minimal_lockfile_with_source(&project, "ms", "2.1.3", "registry+https://lpm.dev");

    let mock = MockRegistry::start().await;
    mock.with_package("ms", "9.9.9", &make_tarball("ms", "9.9.9"))
        .await;

    let out = lpm_with_registry(&project, &mock.url())
        .args(["outdated", "--json"])
        .output()
        .expect("spawn lpm outdated --json");
    assert!(out.status.success());

    let envelope: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("valid JSON envelope");
    assert_eq!(
        envelope["count"],
        serde_json::json!(0),
        "private-named dep must not be folded into outdated count; got envelope: {envelope:#}"
    );
    assert_eq!(envelope["skipped_private"], serde_json::json!(["ms"]));
    assert!(
        envelope["skipped_private_reason"].is_string(),
        "skipped_private_reason must surface the explanation to operators"
    );
}

#[tokio::test]
async fn outdated_metadata_lookup_failure_exits_nonzero_in_json_mode() {
    let pkg = "@lpm.dev/owner.missing-outdated";
    let project = TempProject::empty(&format!(
        r#"{{"name":"lookup-failure","version":"1.0.0","dependencies":{{"{pkg}":"^1.0.0"}}}}"#
    ));
    write_minimal_lockfile(&project, pkg, "1.0.0");

    let mock = MockRegistry::start().await;

    let out = lpm_with_registry(&project, &mock.url())
        .args(["outdated", "--json"])
        .output()
        .expect("spawn lpm outdated --json");

    assert!(
        !out.status.success(),
        "metadata lookup failures must not be reported as a clean outdated result\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );

    let envelope: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("valid JSON failure envelope");
    assert_eq!(envelope["success"], serde_json::json!(false));
    assert_eq!(envelope["unresolved_count"], serde_json::json!(1));
    assert_eq!(envelope["unresolved"][0]["name"], serde_json::json!(pkg));
}

#[tokio::test]
async fn outdated_reports_newer_version_for_outdated_lpm_dep() {
    let pkg = "@lpm.dev/owner.outdated-pkg";
    let project = TempProject::empty(&format!(
        r#"{{"name":"outdated-test","version":"1.0.0","dependencies":{{"{pkg}":"^1.0.0"}}}}"#
    ));
    write_minimal_lockfile(&project, pkg, "1.0.0");

    let mock = MockRegistry::start().await;
    mock.with_full_package_metadata(
        pkg,
        "2.5.0",
        &[
            (
                "1.0.0",
                serde_json::json!({}),
                Some(make_tarball(pkg, "1.0.0")),
            ),
            (
                "1.8.9",
                serde_json::json!({}),
                Some(make_tarball(pkg, "1.8.9")),
            ),
            (
                "2.5.0",
                serde_json::json!({}),
                Some(make_tarball(pkg, "2.5.0")),
            ),
        ],
    )
    .await;

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
    assert_eq!(envelope["schema_version"], serde_json::json!(2));
    assert_eq!(envelope["count"], serde_json::json!(1));
    assert_eq!(envelope["outdated_count"], serde_json::json!(1));

    let entry = &envelope["packages"][0];
    assert_eq!(entry["name"], serde_json::json!(pkg));
    assert_eq!(entry["current"], serde_json::json!("1.0.0"));
    assert_eq!(entry["wanted"], serde_json::json!("1.8.9"));
    assert_eq!(entry["latest"], serde_json::json!("2.5.0"));
    assert_eq!(entry["section"], serde_json::json!("dependencies"));
    assert_eq!(entry["outdated"], serde_json::json!(true));
}

#[tokio::test]
async fn outdated_human_output_uses_slim_completion() {
    let pkg = "@lpm.dev/owner.human-outdated";
    let project = TempProject::empty(&format!(
        r#"{{"name":"outdated-human","version":"1.0.0","dependencies":{{"{pkg}":"^1.0.0"}}}}"#
    ));
    write_minimal_lockfile(&project, pkg, "1.0.0");

    let mock = MockRegistry::start().await;
    mock.with_full_package_metadata(
        pkg,
        "2.0.0",
        &[
            (
                "1.0.0",
                serde_json::json!({}),
                Some(make_tarball(pkg, "1.0.0")),
            ),
            (
                "1.5.0",
                serde_json::json!({}),
                Some(make_tarball(pkg, "1.5.0")),
            ),
            (
                "2.0.0",
                serde_json::json!({}),
                Some(make_tarball(pkg, "2.0.0")),
            ),
        ],
    )
    .await;

    let output = lpm_with_registry(&project, &mock.url())
        .args(["outdated"])
        .output()
        .expect("spawn lpm outdated");

    assert!(
        output.status.success(),
        "outdated should exit 0 even when packages are outdated\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Section")
            && stdout.contains("Package")
            && stdout.contains(pkg)
            && stdout.contains("1.0.0")
            && stdout.contains("1.5.0")
            && stdout.contains("2.0.0"),
        "outdated table must render to stdout, got:\n{stdout}",
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("✓ Found 1 outdated package"),
        "outdated must report a slim completion line, got:\n{stderr}",
    );
    assert!(
        !stderr.contains('●') && !stderr.contains('│') && !stderr.contains('◇'),
        "outdated must not use cliclack gutter output, got:\n{stderr}",
    );
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

#[tokio::test]
async fn outdated_does_not_report_an_installed_version_above_the_registry_latest() {
    let package = "@lpm.dev/owner.registry-rollback";
    let project = TempProject::empty(&format!(
        r#"{{"name":"registry-rollback","version":"1.0.0","dependencies":{{"{package}":"^2.0.0"}}}}"#,
    ));
    write_minimal_lockfile(&project, package, "2.0.0");

    let mock = MockRegistry::start().await;
    mount_lpm_package_latest(&mock, package, "1.9.0").await;

    let out = lpm_with_registry(&project, &mock.url())
        .args(["outdated", "--json"])
        .output()
        .expect("spawn outdated for registry rollback");
    assert!(
        out.status.success(),
        "registry rollback should remain a successful status check\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );

    let envelope: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("valid outdated envelope");
    assert_eq!(envelope["outdated_count"], serde_json::json!(0));
    assert_eq!(
        envelope["packages"][0]["current"],
        serde_json::json!("2.0.0")
    );
    assert_eq!(
        envelope["packages"][0]["latest"],
        serde_json::json!("1.9.0")
    );
    assert_eq!(
        envelope["packages"][0]["outdated"],
        serde_json::json!(false)
    );
}

#[tokio::test]
async fn outdated_rejects_a_latest_tag_that_points_to_a_missing_version() {
    let package = "@lpm.dev/owner.dangling-latest";
    let project = TempProject::empty(&format!(
        r#"{{"name":"dangling-latest","version":"1.0.0","dependencies":{{"{package}":"^1.0.0"}}}}"#,
    ));
    write_minimal_lockfile(&project, package, "1.0.0");

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("/api/registry/{package}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "name": package,
            "dist-tags": { "latest": "2.0.0" },
            "versions": {
                "1.0.0": { "name": package, "version": "1.0.0" }
            },
            "time": { "1.0.0": "2025-01-01T00:00:00.000Z" }
        })))
        .mount(&server)
        .await;

    let out = lpm_with_registry(&project, &server.uri())
        .args(["outdated", "--json"])
        .output()
        .expect("spawn outdated for dangling latest tag");
    assert!(
        !out.status.success(),
        "dangling registry tags must not produce a clean report\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    let envelope: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("valid outdated failure envelope");
    assert_eq!(envelope["success"], serde_json::json!(false));
    assert!(
        envelope["unresolved"][0]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("points to missing version '2.0.0'")),
        "failure should identify the dangling tag: {envelope:#}",
    );
}

#[tokio::test]
async fn outdated_runs_metadata_lookups_in_bounded_parallel_waves() {
    const PACKAGE_COUNT: usize = 8;
    let mut manifest_dependencies = serde_json::Map::with_capacity(PACKAGE_COUNT);
    let mut lockfile =
        String::from("[metadata]\nlockfile-version = 2\nresolved-with = \"greedy-fusion\"\n");
    for index in 0..PACKAGE_COUNT {
        let name = format!("@lpm.dev/owner.bounded-{index}");
        manifest_dependencies.insert(name.clone(), serde_json::json!("^1.0.0"));
        lockfile.push_str(&format!(
            "\n[[packages]]\nname = \"{name}\"\nversion = \"1.0.0\"\nsource = \"registry+https://lpm.dev\"\n"
        ));
    }
    let project = TempProject::empty(
        &serde_json::to_string(&serde_json::json!({
            "name": "bounded-outdated",
            "version": "1.0.0",
            "dependencies": manifest_dependencies,
        }))
        .unwrap(),
    );
    project.write_file("lpm.lock", &lockfile);

    let server = MockServer::start().await;
    let starts = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    Mock::given(method("GET"))
        .and(path_regex(
            r"^/api/registry/@lpm\.dev/owner\.bounded-[0-9]+$",
        ))
        .respond_with(RecordDelayedOutdatedMetadataStart {
            starts: std::sync::Arc::clone(&starts),
            delay: std::time::Duration::from_millis(250),
        })
        .mount(&server)
        .await;

    let out = lpm_with_registry(&project, &server.uri())
        .args(["outdated", "--json"])
        .output()
        .expect("spawn bounded outdated check");
    assert!(
        out.status.success(),
        "bounded outdated check should succeed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    let starts = starts.lock().expect("read metadata request starts");
    assert_eq!(starts.len(), PACKAGE_COUNT);
    let first = *starts.iter().min().unwrap();
    let mut offsets = starts
        .iter()
        .map(|start| start.duration_since(first))
        .collect::<Vec<_>>();
    offsets.sort();
    assert!(
        offsets[3] < std::time::Duration::from_millis(150),
        "the first four bounded slots did not start together: {offsets:?}"
    );
    assert!(
        offsets[4] >= std::time::Duration::from_millis(200),
        "more than four metadata requests ran in the first wave: {offsets:?}"
    );
    assert!(
        offsets[7] < std::time::Duration::from_millis(450),
        "the bounded scheduler did not refill promptly for the second wave: {offsets:?}"
    );
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
    mock.with_full_package_metadata(
        pkg,
        "2.0.0",
        &[
            (
                "1.0.0",
                serde_json::json!({}),
                Some(make_tarball(pkg, "1.0.0")),
            ),
            (
                "1.6.0",
                serde_json::json!({}),
                Some(make_tarball(pkg, "1.6.0")),
            ),
            (
                "2.0.0",
                serde_json::json!({}),
                Some(make_tarball(pkg, "2.0.0")),
            ),
        ],
    )
    .await;

    let out = lpm_with_registry(&project, &mock.url())
        .args(["outdated", "--json"])
        .output()
        .expect("spawn lpm outdated --json");
    assert!(out.status.success());

    let envelope: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("valid JSON envelope");
    insta::assert_json_snapshot!("outdated_json_envelope_one_outdated", envelope);
}
