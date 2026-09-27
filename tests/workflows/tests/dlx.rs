mod support;

use lpm_common::LpmRoot;
use std::time::{Duration, SystemTime};
use support::mock_registry::{MockRegistry, compute_integrity, make_tarball_from_pkg_json};
use support::{TempProject, lpm, lpm_with_registry, write_npm_firewall_global_config};

fn seed_lockfile_identity(
    root: &std::path::Path,
    package_name: &str,
    version: &str,
    integrity: &str,
) {
    let mut lockfile = lpm_lockfile::Lockfile::new();
    lockfile.add_package(lpm_lockfile::LockedPackage {
        instance_id: Some(lpm_common::PackageInstanceId::derive(
            package_name,
            version,
            "registry+unknown",
            "fixture/dlx-root",
        )),
        dependency_targets: std::collections::BTreeMap::new(),
        peer_targets: std::collections::BTreeMap::new(),
        name: package_name.to_string(),
        version: version.to_string(),
        integrity: Some(integrity.to_string()),
        ..Default::default()
    });
    support::finalize_exact_lockfile_fixture(
        &mut lockfile,
        &[(package_name, package_name, version)],
    );
    lockfile
        .write_to_file(&root.join(lpm_lockfile::LOCKFILE_NAME))
        .expect("failed to seed dlx cache lockfile");
}

fn make_dlx_tool_tarball(name: &str, version: &str) -> Vec<u8> {
    let body = format!("#!/usr/bin/env node\nconsole.log('version:{version}');\n").into_bytes();
    make_tarball_from_pkg_json(
        serde_json::json!({
            "name": name,
            "version": version,
            "bin": {
                name: "bin/tool.js"
            }
        }),
        &[("bin/tool.js", body.as_slice())],
    )
}

fn iso8601_n_secs_ago(n_secs: i64) -> String {
    use chrono::SecondsFormat;

    let dt = chrono::Utc::now() - chrono::Duration::seconds(n_secs);
    dt.to_rfc3339_opts(SecondsFormat::Millis, true)
}

async fn mount_dlx_tool_versions(mock: &MockRegistry, name: &str) {
    let v1 = make_dlx_tool_tarball(name, "1.0.0");
    let v2 = make_dlx_tool_tarball(name, "2.0.0");

    mock.with_full_package_metadata(
        name,
        "2.0.0",
        &[
            ("1.0.0", serde_json::json!({}), Some(v1)),
            ("2.0.0", serde_json::json!({}), Some(v2)),
        ],
    )
    .await;
}

async fn mount_published_dlx_tool(
    mock: &MockRegistry,
    name: &str,
    version: &str,
    published_at: &str,
) {
    let tarball = make_dlx_tool_tarball(name, version);
    let integrity = compute_integrity(&tarball);

    mock.with_package_published_at(name, version, &tarball, published_at)
        .await;
    mock.with_batch_metadata(vec![serde_json::json!({
        "name": name,
        "dist-tags": { "latest": version },
        "versions": {
            version: {
                "name": name,
                "version": version,
                "dist": {
                    "tarball": mock.tarball_url(name, version),
                    "integrity": integrity,
                },
                "dependencies": {}
            }
        },
        "time": { version: published_at }
    })])
    .await;
}

/// `lpm --json dlx <malformed-spec>` surfaces the resolver error as a
/// parseable JSON envelope on stdout. The malformed-range form (`@@@`)
/// fails inside the resolver's range parser without making any network
/// calls — fastest envelope-shape contract for `lpm dlx`. The
/// happy-path cache-hit case (below) verifies execution; this test
/// verifies the failure surface is machine-readable.
#[test]
fn dlx_malformed_spec_under_json_emits_error_envelope_on_stdout() {
    let project = TempProject::empty(r#"{"name":"dlx-malformed","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args(["--json", "dlx", "@@@"])
        .output()
        .expect("failed to run lpm --json dlx @@@");

    let envelope: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(envelope["success"], serde_json::json!(false));
    assert!(
        envelope["error"]
            .as_str()
            .is_some_and(|s| s.contains("range") || s.contains("invalid")),
        "error must reference the malformed range, got: {envelope}",
    );
}

#[tokio::test]
async fn dlx_cache_hit_executes_cached_binary_without_extending_ttl() {
    let project = TempProject::empty(r#"{"name":"dlx-test","version":"1.0.0"}"#);
    let spec = "npm-check-updates@1.0.0";
    let mock = MockRegistry::start().await;
    let tarball = make_tarball_from_pkg_json(
        serde_json::json!({"name":"npm-check-updates","version":"1.0.0","bin":{"ncu":"build/cli.js"}}),
        &[("build/cli.js", b"#!/usr/bin/env node\nconsole.log('cwd:'+process.cwd());console.log('args:'+process.argv.slice(2).join(' '));")],
    );
    let integrity = compute_integrity(&tarball);
    mock.with_package_published_at(
        "npm-check-updates",
        "1.0.0",
        &tarball,
        &iso8601_n_secs_ago(72 * 3600),
    )
    .await;
    let first = lpm_with_registry(&project, &mock.url())
        .args(["dlx", spec])
        .output()
        .unwrap();
    assert_dlx_success(&first);
    let root = LpmRoot::from_dir(project.home().join(".lpm"));
    let cache_dir = lpm_runner::dlx::dlx_cache_dir_at(&root, spec);
    let package_json = cache_dir.join("package.json");
    let before = SystemTime::now() - Duration::from_secs(60);
    let file = std::fs::OpenOptions::new()
        .write(true)
        .open(&package_json)
        .expect("seeded package.json must exist");
    file.set_modified(before)
        .expect("failed to backdate package.json");

    let output = lpm_with_registry(&project, &mock.url())
        .args(["dlx", spec, "--", "--loud", "hello"])
        .output()
        .expect("failed to run lpm dlx");

    assert!(
        output.status.success(),
        "lpm dlx failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let expected_cwd = project
        .path()
        .canonicalize()
        .expect("project path must canonicalize");
    let reported_cwd = stdout
        .lines()
        .find_map(|line| line.strip_prefix("cwd:"))
        .expect("cached dlx binary must report its working directory");
    let reported_cwd = std::path::Path::new(reported_cwd)
        .canonicalize()
        .expect("reported working directory must canonicalize");
    assert_eq!(
        reported_cwd, expected_cwd,
        "dlx must execute from the caller project directory; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("args:--loud hello"),
        "dlx must forward extra args to the cached binary, got:\n{stdout}"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("› Resolving npm-check-updates@1.0.0"),
        "dlx should show slim resolve phase for the target package; stderr:\n{stderr}"
    );
    assert!(
        stderr.contains("› Reusing dlx cache entry (fresh)"),
        "dlx should mark the fresh cache-hit path; stderr:\n{stderr}"
    );
    assert!(
        stderr.contains("Resolved npm-check-updates@1.0.0"),
        "dlx should print the cached package identity; stderr:\n{stderr}"
    );
    assert!(
        stderr.contains(&integrity),
        "dlx should print the cached package integrity; stderr:\n{stderr}"
    );

    let after = std::fs::metadata(&package_json)
        .expect("package.json must still exist")
        .modified()
        .expect("package.json mtime must be readable");
    assert_eq!(
        after, before,
        "cache hits must not extend the 24h dlx TTL without revalidation"
    );
}

#[tokio::test]
async fn dlx_bare_package_uses_project_lockfile_version_before_registry_latest() {
    let project = TempProject::empty(
        r#"{"name":"dlx-lockfile-project","version":"1.0.0","dependencies":{"dlx-lock-tool":"1.0.0"}}"#,
    );
    let mock = MockRegistry::start().await;
    mount_dlx_tool_versions(&mock, "dlx-lock-tool").await;

    let install = lpm_with_registry(&project, &mock.url())
        .args(["install"])
        .output()
        .expect("failed to install locked dlx fixture");
    assert!(
        install.status.success(),
        "fixture install failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&install.stdout),
        String::from_utf8_lossy(&install.stderr),
    );

    let dlx = lpm_with_registry(&project, &mock.url())
        .args(["dlx", "dlx-lock-tool"])
        .output()
        .expect("failed to run lpm dlx dlx-lock-tool");
    assert!(
        dlx.status.success(),
        "dlx failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&dlx.stdout),
        String::from_utf8_lossy(&dlx.stderr),
    );

    let stdout = String::from_utf8_lossy(&dlx.stdout);
    assert!(
        stdout.contains("version:1.0.0"),
        "dlx should execute the version already selected by the project lockfile, got:\n{stdout}"
    );
    assert!(
        !stdout.contains("version:2.0.0"),
        "dlx must not jump to registry latest when the project lockfile has the package, got:\n{stdout}"
    );

    let stderr = String::from_utf8_lossy(&dlx.stderr);
    assert!(
        stderr.contains("Resolved dlx-lock-tool@1.0.0"),
        "dlx should print the lockfile-selected package identity; stderr:\n{stderr}"
    );
    assert!(
        stderr.contains("sha512-"),
        "dlx should print the lockfile-selected package integrity; stderr:\n{stderr}"
    );
}

#[tokio::test]
async fn dlx_cache_install_shows_firewall_active_badge_when_public_npm_verdicts_are_checked() {
    let project = TempProject::empty(r#"{"name":"dlx-firewall","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    mount_published_dlx_tool(
        &mock,
        "dlx-firewall-tool",
        "1.0.0",
        &iso8601_n_secs_ago(172_800),
    )
    .await;
    mock.with_npm_firewall_block("dlx-firewall-tool", "1.0.0")
        .await;
    write_npm_firewall_global_config(&project, "monitor");

    let output = lpm_with_registry(&project, &mock.url())
        .args(["dlx", "dlx-firewall-tool@1.0.0"])
        .output()
        .expect("failed to run lpm dlx with firewall monitor");

    assert!(
        output.status.success(),
        "monitor-mode firewall dlx must continue\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("Installing 1 package - 🔥 LPM Firewall active"),
        "firewall-active dlx cache install must show the badge; got:\n{combined}"
    );
}

#[tokio::test]
async fn dlx_applies_project_release_age_policy_and_guards_min_release_age_override() {
    let project = TempProject::empty(
        r#"{"name":"dlx-release-age","version":"1.0.0","lpm":{"minimumReleaseAge":259200}}"#,
    );
    support::write_signed_release_age_exclusion_posture(&project, &[]);
    let mock = MockRegistry::start().await;
    let published_at = iso8601_n_secs_ago(48 * 3600);
    mount_published_dlx_tool(&mock, "dlx-fresh-tool", "1.0.0", &published_at).await;

    let blocked = lpm_with_registry(&project, &mock.url())
        .args(["dlx", "dlx-fresh-tool"])
        .output()
        .expect("failed to run lpm dlx against cooldown fixture");
    assert!(
        !blocked.status.success(),
        "dlx should apply the caller project's minimumReleaseAge; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&blocked.stdout),
        String::from_utf8_lossy(&blocked.stderr),
    );
    let blocked_stderr = String::from_utf8_lossy(&blocked.stderr);
    assert!(
        blocked_stderr.contains("minimumReleaseAge")
            || blocked_stderr.contains("published too recently"),
        "cooldown failure should be visible in stderr, got:\n{blocked_stderr}"
    );

    let override_blocked = lpm_with_registry(&project, &mock.url())
        .args(["--json", "dlx", "--min-release-age=0", "dlx-fresh-tool"])
        .output()
        .expect("failed to run lpm dlx with release-age override");
    let envelope = support::assertions::assert_security_approval_required(&override_blocked);
    assert!(
        envelope["error"]["requested_scopes"]
            .as_array()
            .is_some_and(|scopes| scopes.iter().any(|scope| scope == "cooldown-bypass")),
        "dlx override must use the same guarded cooldown-bypass scope as install; got {envelope}",
    );

    let allow_new_blocked = lpm_with_registry(&project, &mock.url())
        .args(["--json", "dlx", "--allow-new", "dlx-fresh-tool"])
        .output()
        .expect("failed to run lpm dlx with --allow-new");
    let envelope = support::assertions::assert_security_approval_required(&allow_new_blocked);
    assert!(
        envelope["error"]["requested_scopes"]
            .as_array()
            .is_some_and(|scopes| scopes.iter().any(|scope| scope == "cooldown-bypass")),
        "dlx --allow-new must use the same guarded cooldown-bypass scope as install; got {envelope}",
    );
}

fn assert_dlx_success(output: &std::process::Output) {
    assert!(
        output.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[tokio::test]
async fn dlx_rejects_registry_integrity_that_differs_from_the_project_lock() {
    let project = TempProject::empty(r#"{"name":"dlx-identity","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    mount_dlx_tool_versions(&mock, "dlx-identity-tool").await;
    seed_lockfile_identity(
        project.path(),
        "dlx-identity-tool",
        "1.0.0",
        support::VALID_TEST_INTEGRITY,
    );
    let output = lpm_with_registry(&project, &mock.url())
        .args(["dlx", "dlx-identity-tool"])
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "a different registry artifact ran: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert!(!String::from_utf8_lossy(&output.stdout).contains("version:"));
    assert!(String::from_utf8_lossy(&output.stderr).contains("integrity"));
}

#[tokio::test]
async fn dlx_warm_cache_obeys_changed_release_age_and_guarded_overrides() {
    let project = TempProject::empty(r#"{"name":"dlx-policy","version":"1.0.0"}"#);
    support::write_signed_release_age_exclusion_posture(&project, &[]);
    let mock = MockRegistry::start().await;
    mount_published_dlx_tool(
        &mock,
        "dlx-policy-tool",
        "1.0.0",
        &iso8601_n_secs_ago(48 * 3600),
    )
    .await;
    let first = lpm_with_registry(&project, &mock.url())
        .args(["dlx", "dlx-policy-tool"])
        .output()
        .unwrap();
    assert_dlx_success(&first);
    let guarded = lpm_with_registry(&project, &mock.url())
        .args(["--json", "dlx", "--min-release-age=0", "dlx-policy-tool"])
        .output()
        .unwrap();
    support::assertions::assert_security_approval_required(&guarded);
    project.write_file(
        "package.json",
        r#"{"name":"dlx-policy","version":"1.0.0","lpm":{"minimumReleaseAge":259200}}"#,
    );
    let stricter = lpm_with_registry(&project, &mock.url())
        .args(["dlx", "dlx-policy-tool"])
        .output()
        .unwrap();
    assert!(
        !stricter.status.success(),
        "warm cache bypassed release age"
    );
    assert!(!String::from_utf8_lossy(&stricter.stdout).contains("version:"));
}

#[tokio::test]
async fn dlx_subdirectory_inherits_project_release_age_without_changing_cwd() {
    let project = TempProject::empty(
        r#"{"name":"dlx-nested","version":"1.0.0","lpm":{"minimumReleaseAge":259200}}"#,
    );
    project.write_file("src/nested/.keep", "");
    support::write_signed_release_age_exclusion_posture(&project, &[]);
    let mock = MockRegistry::start().await;
    mount_published_dlx_tool(
        &mock,
        "dlx-nested-tool",
        "1.0.0",
        &iso8601_n_secs_ago(48 * 3600),
    )
    .await;
    let output = lpm_with_registry(&project, &mock.url())
        .current_dir(project.path().join("src/nested"))
        .args(["dlx", "dlx-nested-tool"])
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "subdirectory bypassed owning policy"
    );
    assert!(!String::from_utf8_lossy(&output.stdout).contains("version:"));
}

#[tokio::test]
async fn dlx_refresh_resolves_and_reports_the_new_registry_version() {
    let project = TempProject::empty(r#"{"name":"dlx-refresh","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    mount_published_dlx_tool(
        &mock,
        "dlx-refresh-tool",
        "1.0.0",
        &iso8601_n_secs_ago(72 * 3600),
    )
    .await;
    let first = lpm_with_registry(&project, &mock.url())
        .args(["dlx", "dlx-refresh-tool"])
        .output()
        .unwrap();
    assert_dlx_success(&first);
    mock.server().reset().await;
    mount_published_dlx_tool(
        &mock,
        "dlx-refresh-tool",
        "2.0.0",
        &iso8601_n_secs_ago(72 * 3600),
    )
    .await;
    let refreshed = lpm_with_registry(&project, &mock.url())
        .args(["dlx", "--refresh", "dlx-refresh-tool"])
        .output()
        .unwrap();
    assert_dlx_success(&refreshed);
    assert!(
        String::from_utf8_lossy(&refreshed.stdout).contains("version:2.0.0"),
        "old binary ran: {}",
        String::from_utf8_lossy(&refreshed.stdout)
    );
    assert!(
        String::from_utf8_lossy(&refreshed.stderr).contains("Resolved dlx-refresh-tool@2.0.0"),
        "old identity displayed: {}",
        String::from_utf8_lossy(&refreshed.stderr)
    );
}

#[tokio::test]
async fn dlx_failed_refresh_preserves_the_previous_entry_and_install_time() {
    let project = TempProject::empty(r#"{"name":"dlx-refresh-failure","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    mount_published_dlx_tool(
        &mock,
        "dlx-refresh-failure-tool",
        "1.0.0",
        &iso8601_n_secs_ago(72 * 3600),
    )
    .await;
    let first = lpm_with_registry(&project, &mock.url())
        .args(["dlx", "dlx-refresh-failure-tool"])
        .output()
        .unwrap();
    assert_dlx_success(&first);
    let root = LpmRoot::from_dir(project.home().join(".lpm"));
    let entry = lpm_runner::dlx::dlx_cache_dir_at(&root, "dlx-refresh-failure-tool");
    let marker = entry.join("package.json");
    let bytes = std::fs::read(&marker).unwrap();
    let modified = std::fs::metadata(&marker).unwrap().modified().unwrap();
    mock.server().reset().await;
    let refreshed = lpm_with_registry(&project, &mock.url())
        .args(["dlx", "--refresh", "dlx-refresh-failure-tool"])
        .output()
        .unwrap();
    assert!(
        !refreshed.status.success(),
        "failed registry refresh reused the prior install"
    );
    assert!(!String::from_utf8_lossy(&refreshed.stdout).contains("version:"));
    assert_eq!(std::fs::read(&marker).unwrap(), bytes);
    assert_eq!(
        std::fs::metadata(&marker).unwrap().modified().unwrap(),
        modified
    );
}

#[tokio::test]
async fn dlx_uses_the_callers_authenticated_registry_from_a_subdirectory() {
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, ResponseTemplate};
    let project = TempProject::empty(r#"{"name":"dlx-npmrc","version":"1.0.0"}"#);
    project.write_file("src/nested/.keep", "");
    let mock = MockRegistry::start().await;
    let name = "dlx-npmrc-tool";
    let tarball = make_dlx_tool_tarball(name, "1.0.0");
    let tarball_path = format!("/{name}/-/{name}-1.0.0.tgz");
    let metadata = serde_json::json!({"name":name,"dist-tags":{"latest":"1.0.0"},"versions":{"1.0.0":{"name":name,"version":"1.0.0","dist":{"tarball":format!("{}{tarball_path}",mock.url()),"integrity":compute_integrity(&tarball)},"dependencies":{}}},"time":{"1.0.0":iso8601_n_secs_ago(72*3600)}});
    Mock::given(method("GET"))
        .and(path(format!("/{name}")))
        .and(header("Authorization", "Bearer dlx-fixture-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(metadata))
        .mount(mock.server())
        .await;
    Mock::given(method("GET"))
        .and(path(tarball_path))
        .and(header("Authorization", "Bearer dlx-fixture-token"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(tarball))
        .mount(mock.server())
        .await;
    project.write_private_file(
        ".npmrc",
        &format!(
            "registry={}/\n//{}/:_authToken=dlx-fixture-token\n",
            mock.url(),
            mock.url().trim_start_matches("http://")
        ),
    );
    let output = lpm(&project)
        .env_remove("LPM_TOKEN")
        .current_dir(project.path().join("src/nested"))
        .args(["dlx", name])
        .output()
        .unwrap();
    assert_dlx_success(&output);
    let requests = mock.server().received_requests().await.unwrap();
    assert!(requests.len() >= 2);
    for request in requests {
        assert_eq!(
            request
                .headers
                .get("authorization")
                .map(|h| h.to_str().unwrap()),
            Some("Bearer dlx-fixture-token")
        );
    }
}

#[tokio::test]
async fn dlx_uses_the_exact_project_root_and_resolves_explicit_tags_separately() {
    let project = TempProject::empty(
        r#"{"name":"dlx-root-selection","version":"1.0.0","dependencies":{"dlx-root-tool":"1.0.0"}}"#,
    );
    let mock = MockRegistry::start().await;
    mount_dlx_tool_versions(&mock, "dlx-root-tool").await;
    let installed = lpm_with_registry(&project, &mock.url())
        .arg("install")
        .output()
        .unwrap();
    assert_dlx_success(&installed);
    let lock_path = project.path().join(lpm_lockfile::LOCKFILE_NAME);
    let mut lock = lpm_lockfile::Lockfile::read_fast(&lock_path).unwrap();
    let mut transitive = lock
        .packages
        .iter()
        .find(|p| p.name == "dlx-root-tool")
        .unwrap()
        .clone();
    transitive.version = "2.0.0".into();
    transitive.integrity = Some(compute_integrity(&make_dlx_tool_tarball(
        "dlx-root-tool",
        "2.0.0",
    )));
    transitive.instance_id = Some(lpm_common::PackageInstanceId::derive(
        "dlx-root-tool",
        "2.0.0",
        "registry+unknown",
        "fixture/transitive",
    ));
    let root_package = lock
        .packages
        .iter_mut()
        .find(|p| p.name == "dlx-root-tool")
        .unwrap();
    root_package.dependencies.push("dlx-root-tool@2.0.0".into());
    root_package
        .dependency_targets
        .insert("dlx-root-tool".into(), transitive.instance_id.unwrap());
    lock.add_package(transitive);
    lock.write_to_file(&lock_path).unwrap();
    let bare = lpm_with_registry(&project, &mock.url())
        .args(["dlx", "dlx-root-tool"])
        .output()
        .unwrap();
    assert_dlx_success(&bare);
    assert!(
        String::from_utf8_lossy(&bare.stdout).contains("version:1.0.0"),
        "selected a transitive identity: {}",
        String::from_utf8_lossy(&bare.stdout)
    );
    let tagged = lpm_with_registry(&project, &mock.url())
        .args(["dlx", "dlx-root-tool@latest"])
        .output()
        .unwrap();
    assert_dlx_success(&tagged);
    assert!(String::from_utf8_lossy(&tagged.stdout).contains("version:2.0.0"));
}

#[tokio::test]
async fn dlx_warm_cache_does_not_cross_registry_routes() {
    let project = TempProject::empty(r#"{"name":"dlx-route-change","version":"1.0.0"}"#);
    let first_registry = MockRegistry::start().await;
    let second_registry = MockRegistry::start().await;
    mount_published_dlx_tool(
        &first_registry,
        "dlx-route-tool",
        "1.0.0",
        &iso8601_n_secs_ago(72 * 3600),
    )
    .await;
    mount_published_dlx_tool(
        &second_registry,
        "dlx-route-tool",
        "2.0.0",
        &iso8601_n_secs_ago(72 * 3600),
    )
    .await;
    let first = lpm_with_registry(&project, &first_registry.url())
        .args(["dlx", "dlx-route-tool"])
        .output()
        .unwrap();
    assert_dlx_success(&first);
    let second = lpm_with_registry(&project, &second_registry.url())
        .args(["dlx", "dlx-route-tool"])
        .output()
        .unwrap();
    assert_dlx_success(&second);
    assert!(
        String::from_utf8_lossy(&second.stdout).contains("version:2.0.0"),
        "reused package from another registry: {}",
        String::from_utf8_lossy(&second.stdout)
    );
}

#[tokio::test]
async fn dlx_explicit_latest_does_not_reuse_an_older_project_lock_selection() {
    let project = TempProject::empty(
        r#"{"name":"dlx-explicit-tag","version":"1.0.0","dependencies":{"dlx-tag-tool":"1.0.0"}}"#,
    );
    let mock = MockRegistry::start().await;
    mount_dlx_tool_versions(&mock, "dlx-tag-tool").await;
    let installed = lpm_with_registry(&project, &mock.url())
        .arg("install")
        .output()
        .unwrap();
    assert_dlx_success(&installed);
    let tagged = lpm_with_registry(&project, &mock.url())
        .args(["dlx", "dlx-tag-tool@latest"])
        .output()
        .unwrap();
    assert_dlx_success(&tagged);
    assert!(
        String::from_utf8_lossy(&tagged.stdout).contains("version:2.0.0"),
        "explicit tag reused old project selection: {}",
        String::from_utf8_lossy(&tagged.stdout)
    );
}

#[tokio::test]
async fn dlx_does_not_apply_unrelated_project_patch_configuration() {
    let project = TempProject::empty(
        r#"{"name":"dlx-project-patches","version":"1.0.0","lpm":{"patchedDependencies":{"project-only@1.0.0":{"path":"patches/project.patch","originalIntegrity":"sha512-fixture"}}}}"#,
    );
    project.write_file("patches/project.patch", "diff --git a/index.js b/index.js\n--- a/index.js\n+++ b/index.js\n@@ -1 +1 @@\n-old\n+new\n");
    let mock = MockRegistry::start().await;
    mount_published_dlx_tool(
        &mock,
        "dlx-independent-tool",
        "1.0.0",
        &iso8601_n_secs_ago(72 * 3600),
    )
    .await;
    let before = std::fs::read(project.path().join("package.json")).unwrap();
    let output = lpm_with_registry(&project, &mock.url())
        .args(["dlx", "dlx-independent-tool"])
        .output()
        .unwrap();
    assert_dlx_success(&output);
    assert_eq!(
        std::fs::read(project.path().join("package.json")).unwrap(),
        before
    );
    assert!(!project.path().join("node_modules").exists());
    assert!(!project.path().join("lpm.lock").exists());
}

#[tokio::test]
async fn dlx_json_reserves_stdout_for_the_child() {
    let project = TempProject::empty(r#"{"name":"dlx-json","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    mount_published_dlx_tool(
        &mock,
        "dlx-json-tool",
        "1.0.0",
        &iso8601_n_secs_ago(72 * 3600),
    )
    .await;
    let output = lpm_with_registry(&project, &mock.url())
        .args(["--json", "dlx", "dlx-json-tool"])
        .output()
        .unwrap();
    assert_dlx_success(&output);
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        "version:1.0.0"
    );
}

#[tokio::test]
async fn dlx_selects_the_valid_bin_when_metadata_contains_invalid_names() {
    let project = TempProject::empty(r#"{"name":"dlx-bin-names","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    let tarball = make_tarball_from_pkg_json(
        serde_json::json!({"name":"dlx-bin-tool","version":"1.0.0","bin":{"valid-command":"tool.js","../invalid":"tool.js"}}),
        &[("tool.js", b"#!/usr/bin/env node\nconsole.log('VALID_BIN');")],
    );
    mock.with_package_published_at(
        "dlx-bin-tool",
        "1.0.0",
        &tarball,
        &iso8601_n_secs_ago(72 * 3600),
    )
    .await;
    let output = lpm_with_registry(&project, &mock.url())
        .args(["dlx", "dlx-bin-tool"])
        .output()
        .unwrap();
    assert_dlx_success(&output);
    assert!(String::from_utf8_lossy(&output.stdout).contains("VALID_BIN"));
}

async fn mount_lifetime_tool(mock: &MockRegistry, name: &str) {
    let script = b"#!/usr/bin/env node\nconst fs=require('fs');const [ready,release]=process.argv.slice(2);if(!ready){console.log('READY');}else{fs.writeFileSync(ready,'ready');const start=Date.now();const timer=setInterval(()=>{if(fs.existsSync(release)||Date.now()-start>10000){clearInterval(timer);try{fs.readFileSync(__filename);console.log('RUN_OK')}catch(e){console.error(e.message);process.exitCode=31;} }},20);}";
    let tarball = make_tarball_from_pkg_json(
        serde_json::json!({"name":name,"version":"1.0.0","bin":{name:"tool.js"}}),
        &[("tool.js", script)],
    );
    mock.with_package_published_at(name, "1.0.0", &tarball, &iso8601_n_secs_ago(72 * 3600))
        .await;
}

fn wait_for_marker(path: &std::path::Path, child: &mut std::process::Child) {
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while !path.exists() {
        assert!(
            child.try_wait().unwrap().is_none(),
            "tool exited before readiness"
        );
        if std::time::Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("tool did not become ready");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[tokio::test]
async fn dlx_active_entry_survives_expiry_sweep_and_cache_cleanup() {
    let project = TempProject::empty(r#"{"name":"dlx-active-cache","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    mount_lifetime_tool(&mock, "dlx-active-tool").await;
    mount_lifetime_tool(&mock, "dlx-other-tool").await;
    let ready = project.path().join("ready");
    let release = project.path().join("release");
    let mut command = support::lpm_spawnable_with_registry(&project, &mock.url());
    command
        .args(["dlx", "dlx-active-tool", "--"])
        .arg(&ready)
        .arg(&release);
    let mut child = command
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    wait_for_marker(&ready, &mut child);
    let root = LpmRoot::from_dir(project.home().join(".lpm"));
    let entry = lpm_runner::dlx::dlx_cache_dir_at(&root, "dlx-active-tool");
    std::fs::OpenOptions::new()
        .write(true)
        .open(entry.join("package.json"))
        .unwrap()
        .set_modified(SystemTime::now() - Duration::from_secs(48 * 3600))
        .unwrap();
    let other = lpm_with_registry(&project, &mock.url())
        .args(["dlx", "dlx-other-tool"])
        .output()
        .unwrap();
    let survived_sweep = entry.exists();
    let cleaned = lpm(&project)
        .args(["--json", "cache", "clean", "dlx"])
        .output()
        .unwrap();
    let survived_clean = entry.exists();
    std::fs::write(&release, "done").unwrap();
    let output = child.wait_with_output().unwrap();
    assert_dlx_success(&other);
    assert!(
        survived_sweep,
        "another dlx invocation swept an active installation"
    );
    assert!(
        !cleaned.status.success() && survived_clean,
        "cache clean removed an active installation"
    );
    assert_dlx_success(&output);
    assert!(String::from_utf8_lossy(&output.stdout).contains("RUN_OK"));
    let after = lpm(&project)
        .args(["cache", "clean", "dlx"])
        .output()
        .unwrap();
    assert_dlx_success(&after);
    assert!(!entry.exists());
}

#[tokio::test]
async fn dlx_refresh_waits_until_the_current_execution_finishes() {
    let project = TempProject::empty(r#"{"name":"dlx-refresh-active","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    mount_lifetime_tool(&mock, "dlx-refresh-active-tool").await;
    let ready = project.path().join("ready");
    let release = project.path().join("release");
    let mut command = support::lpm_spawnable_with_registry(&project, &mock.url());
    command
        .args(["dlx", "dlx-refresh-active-tool", "--"])
        .arg(&ready)
        .arg(&release);
    let mut child = command
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    wait_for_marker(&ready, &mut child);
    let mut refresh = support::lpm_spawnable_with_registry(&project, &mock.url());
    refresh.args(["dlx", "--refresh", "dlx-refresh-active-tool"]);
    let mut refresh = refresh
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    std::thread::sleep(Duration::from_secs(1));
    let completed_while_active = refresh.try_wait().unwrap().is_some();
    std::fs::write(&release, "done").unwrap();
    let first = child.wait_with_output().unwrap();
    let second = refresh.wait_with_output().unwrap();
    assert!(
        !completed_while_active,
        "refresh replaced an installation still in use"
    );
    assert_dlx_success(&first);
    assert_dlx_success(&second);
    assert!(String::from_utf8_lossy(&first.stdout).contains("RUN_OK"));
}

#[tokio::test]
async fn dlx_checks_locked_integrity_before_dependency_scripts_can_run() {
    let project = TempProject::empty(
        r#"{"name":"dlx-script-identity","version":"1.0.0","lpm":{"scriptPolicy":"allow"}}"#,
    );
    project.write_file("lpm.toml", "[sandbox]\nmode = \"none\"\n");
    support::write_signed_unlock_for(&project, project.path(), &["scripts-allow", "sandbox-none"]);
    let mock = MockRegistry::start().await;
    project.write_file(".npmrc", &format!("registry={}/\n", mock.url()));
    let package = serde_json::json!({"name":"dlx-script-identity-tool","version":"1.0.0","bin":{"dlx-script-identity-tool":"tool.js"},"scripts":{"postinstall":"node build.js"}});
    mock.with_manifest_package(
        package,
        &[
            ("tool.js", b"#!/usr/bin/env node\nconsole.log('TOOL_RAN');"),
            (
                "build.js",
                b"console.log('UNEXPECTED_LIFECYCLE_EXECUTION');",
            ),
        ],
    )
    .await;
    seed_lockfile_identity(
        project.path(),
        "dlx-script-identity-tool",
        "1.0.0",
        support::VALID_TEST_INTEGRITY,
    );
    let output = lpm_with_registry(&project, &mock.url())
        .args(["dlx", "dlx-script-identity-tool"])
        .output()
        .unwrap();
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !output.status.success(),
        "mismatched artifact ran: {combined}"
    );
    assert!(
        combined.contains("integrity"),
        "wrong rejection: {combined}"
    );
    assert!(
        !combined.contains("UNEXPECTED_LIFECYCLE_EXECUTION"),
        "lifecycle ran before identity rejection: {combined}"
    );
}

#[tokio::test]
async fn dlx_preserves_locked_registry_source_even_for_identical_tarballs() {
    let project = TempProject::empty(
        r#"{"name":"dlx-locked-route","version":"1.0.0","dependencies":{"dlx-source-tool":"1.0.0"}}"#,
    );
    let first = MockRegistry::start().await;
    let second = MockRegistry::start().await;
    for registry in [&first, &second] {
        mount_published_dlx_tool(
            registry,
            "dlx-source-tool",
            "1.0.0",
            &iso8601_n_secs_ago(72 * 3600),
        )
        .await;
    }
    project.write_file(".npmrc", &format!("registry={}/\n", first.url()));
    let installed = lpm_with_registry(&project, &first.url())
        .args(["install"])
        .output()
        .unwrap();
    assert_dlx_success(&installed);
    project.write_file(".npmrc", &format!("registry={}/\n", second.url()));
    let output = lpm_with_registry(&project, &second.url())
        .args(["dlx", "dlx-source-tool"])
        .output()
        .unwrap();
    assert!(!output.status.success(), "changed source was accepted");
    assert!(!String::from_utf8_lossy(&output.stdout).contains("version:"));
    assert!(String::from_utf8_lossy(&output.stderr).contains("source"));
}

#[tokio::test]
async fn dlx_enforces_dependency_engines_outside_a_project() {
    let project = TempProject::empty(r#"{"name":"dlx-no-project","version":"1.0.0"}"#);
    std::fs::remove_file(project.path().join("package.json")).unwrap();
    let mock = MockRegistry::start().await;
    project.write_file(".npmrc", &format!("registry={}/\n", mock.url()));
    mock.with_manifest_package(serde_json::json!({"name":"dlx-engines-tool","version":"1.0.0","engines":{"node":">=9999.0.0"},"bin":{"dlx-engines-tool":"tool.js"}}), &[("tool.js",b"#!/usr/bin/env node\nconsole.log('UNEXPECTED_EXECUTION');")]).await;
    let output = support::lpm_with_registry(&project, &mock.url())
        .args(["dlx", "dlx-engines-tool"])
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "dependency engine strictness disappeared without a caller manifest"
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("9999"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[tokio::test]
async fn dlx_json_keeps_install_script_output_off_stdout() {
    let project = TempProject::empty(
        r#"{"name":"dlx-script-json","version":"1.0.0","lpm":{"scriptPolicy":"allow"}}"#,
    );
    project.write_file("lpm.toml", "[sandbox]\nmode = \"none\"\n");
    support::write_signed_unlock_for(&project, project.path(), &["scripts-allow", "sandbox-none"]);
    let mock = MockRegistry::start().await;
    project.write_file(".npmrc", &format!("registry={}/\n", mock.url()));
    mock.with_manifest_package(serde_json::json!({"name":"dlx-json-script-tool","version":"1.0.0","bin":{"dlx-json-script-tool":"tool.js"},"scripts":{"postinstall":"node build.js"}}), &[
        ("tool.js",b"#!/usr/bin/env node\nconsole.log(JSON.stringify({child:true}));"),
        ("build.js",b"console.log('INSTALL_SCRIPT_RAN');"),
    ]).await;
    let output = lpm_with_registry(&project, &mock.url())
        .args(["--json", "dlx", "dlx-json-script-tool"])
        .output()
        .unwrap();
    assert_dlx_success(&output);
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "preparation polluted child stdout: {error}: {}",
            String::from_utf8_lossy(&output.stdout)
        )
    });
    assert_eq!(value, serde_json::json!({"child":true}));
    assert!(String::from_utf8_lossy(&output.stderr).contains("INSTALL_SCRIPT_RAN"));
}

#[cfg(unix)]
#[tokio::test]
async fn dlx_stop_signal_terminates_the_tool_before_releasing_its_cache_lock() {
    use std::os::unix::process::CommandExt;
    let project = TempProject::empty(r#"{"name":"dlx-stop","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    mock.with_manifest_package(serde_json::json!({"name":"dlx-stop-tool","version":"1.0.0","bin":{"dlx-stop-tool":"tool.js"}}), &[("tool.js",b"#!/usr/bin/env node\nconst fs=require('fs'),ready=process.argv[2];fs.writeFileSync(ready+'.tmp',String(process.pid));fs.renameSync(ready+'.tmp',ready);setTimeout(()=>{},20000);")]).await;
    let ready = project.path().join("ready");
    let mut command = support::lpm_spawnable_with_registry(&project, &mock.url());
    command
        .args(["dlx", "dlx-stop-tool", "--"])
        .arg(&ready)
        .process_group(0)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    let mut child = command.spawn().unwrap();
    let group = child.id() as i32;
    wait_for_marker(&ready, &mut child);
    let tool_pid = std::fs::read_to_string(&ready)
        .unwrap()
        .parse::<i32>()
        .unwrap();
    // SAFETY: both identifiers belong to the isolated process group created above.
    unsafe {
        libc::kill(group, libc::SIGTERM);
    }
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    while std::time::Instant::now() < deadline {
        // SAFETY: signal zero only inspects the recorded fixture process.
        if unsafe { libc::kill(tool_pid, 0) } != 0 {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    // SAFETY: cleanup targets only our isolated fixture group.
    let alive = unsafe { libc::kill(tool_pid, 0) } == 0;
    // SAFETY: this process group was created only for this fixture.
    unsafe {
        libc::kill(-group, libc::SIGKILL);
    }
    let _ = child.wait();
    assert!(!alive, "dlx exited while its cached tool remained active");
    let clean = lpm(&project)
        .args(["cache", "clean", "dlx"])
        .output()
        .unwrap();
    assert_dlx_success(&clean);
}

#[tokio::test]
async fn dlx_rejects_packages_without_a_usable_executable_before_cache_promotion() {
    for missing_target in [false, true] {
        let project = TempProject::empty(r#"{"name":"dlx-no-bin","version":"1.0.0"}"#);
        let mock = MockRegistry::start().await;
        let mut manifest = serde_json::json!({"name":"dlx-no-bin-tool","version":"1.0.0"});
        if missing_target {
            manifest["bin"] = serde_json::json!({"tool":"missing.js"});
        }
        mock.with_manifest_package(manifest, &[]).await;
        let output = support::lpm_with_registry(&project, &mock.url())
            .args(["dlx", "dlx-no-bin-tool"])
            .timeout(Duration::from_secs(8))
            .output()
            .unwrap();
        assert!(
            output.status.code().is_some_and(|code| code != 0),
            "unusable package did not report a bounded error: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let root = LpmRoot::from_dir(project.home().join(".lpm"));
        assert!(
            !lpm_runner::dlx::dlx_cache_dir_at(&root, "dlx-no-bin-tool").exists(),
            "unusable installation was promoted"
        );
    }
}

#[tokio::test]
async fn dlx_refresh_preserves_the_previous_executable_when_the_replacement_has_no_bin() {
    let project = TempProject::empty(r#"{"name":"dlx-no-bin-refresh","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    mount_published_dlx_tool(
        &mock,
        "dlx-refresh-bin-tool",
        "1.0.0",
        &iso8601_n_secs_ago(72 * 3600),
    )
    .await;
    let first = support::lpm_with_registry(&project, &mock.url())
        .args(["dlx", "dlx-refresh-bin-tool"])
        .output()
        .unwrap();
    assert_dlx_success(&first);
    let root = LpmRoot::from_dir(project.home().join(".lpm"));
    let entry = lpm_runner::dlx::dlx_cache_dir_at(&root, "dlx-refresh-bin-tool");
    let marker = entry.join("package.json");
    let before = std::fs::read(&marker).unwrap();
    let modified = std::fs::metadata(&marker).unwrap().modified().unwrap();
    mock.server().reset().await;
    mock.with_manifest_package(
        serde_json::json!({"name":"dlx-refresh-bin-tool","version":"2.0.0"}),
        &[],
    )
    .await;
    let output = support::lpm_with_registry(&project, &mock.url())
        .args(["dlx", "--refresh", "dlx-refresh-bin-tool"])
        .timeout(Duration::from_secs(8))
        .output()
        .unwrap();
    assert!(
        output.status.code().is_some_and(|code| code != 0),
        "refresh did not report a bounded error"
    );
    assert_eq!(std::fs::read(&marker).unwrap(), before);
    assert_eq!(
        std::fs::metadata(&marker).unwrap().modified().unwrap(),
        modified
    );
    assert!(
        entry
            .join("node_modules/dlx-refresh-bin-tool/bin/tool.js")
            .is_file()
    );
}

#[cfg(unix)]
fn write_dlx_node_probe(directory: &std::path::Path, version: &str) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::create_dir_all(directory).unwrap();
    let file = directory.join("node");
    std::fs::write(&file, format!("#!/bin/sh\nif [ \"$1\" = '--version' ]; then echo 'v{version}'; else echo 'TOOL_RAN'; fi\n")).unwrap();
    std::fs::set_permissions(file, std::fs::Permissions::from_mode(0o755)).unwrap();
}

#[cfg(unix)]
#[tokio::test]
async fn dlx_checks_engines_against_the_callers_node_before_first_execution() {
    let project = TempProject::empty(r#"{"name":"dlx-caller-engine","version":"1.0.0"}"#);
    write_dlx_node_probe(&project.path().join("node_modules/.bin"), "0.1.0");
    let mock = MockRegistry::start().await;
    mock.with_manifest_package(serde_json::json!({"name":"dlx-caller-engine-tool","version":"1.0.0","engines":{"node":">=20"},"bin":{"tool":"tool.js"}}), &[("tool.js", b"#!/usr/bin/env node\nconsole.log('TOOL_RAN');")]).await;
    let output = support::lpm_with_registry(&project, &mock.url())
        .args(["dlx", "dlx-caller-engine-tool"])
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "incompatible caller Node executed the tool"
    );
    assert!(!String::from_utf8_lossy(&output.stdout).contains("TOOL_RAN"));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("0.1.0"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[cfg(unix)]
#[tokio::test]
async fn dlx_rechecks_dependency_engines_when_a_warm_cache_uses_another_node() {
    let project = TempProject::empty(r#"{"name":"dlx-warm-engine","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    mock.with_manifest_package(serde_json::json!({"name":"dlx-warm-engine-tool","version":"1.0.0","engines":{"node":">=20"},"bin":{"tool":"tool.js"}}), &[("tool.js", b"#!/usr/bin/env node\nconsole.log('TOOL_RAN');")]).await;
    let paths = [project.path().join("node22"), project.path().join("node16")];
    for (directory, version) in paths.iter().zip(["22.0.0", "16.0.0"]) {
        write_dlx_node_probe(directory, version);
    }
    for (index, directory) in paths.iter().enumerate() {
        let mut entries = vec![directory.clone()];
        entries.extend(std::env::split_paths(&std::env::var_os("PATH").unwrap()));
        let output = support::lpm_with_registry(&project, &mock.url())
            .env("PATH", std::env::join_paths(entries).unwrap())
            .args(["dlx", "dlx-warm-engine-tool"])
            .output()
            .unwrap();
        if index == 0 {
            assert_dlx_success(&output);
        } else {
            assert!(
                !output.status.success(),
                "warm cache skipped its dependency engine checks"
            );
            assert!(!String::from_utf8_lossy(&output.stdout).contains("TOOL_RAN"));
            assert!(String::from_utf8_lossy(&output.stderr).contains("16.0.0"));
        }
    }
}

#[tokio::test]
async fn dlx_store_files_survive_pruning_during_execution_and_warm_reuse() {
    let project = TempProject::empty(r#"{"name":"dlx-prune","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    mount_lifetime_tool(&mock, "dlx-prune-tool").await;
    let ready = project.path().join("ready");
    let release = project.path().join("release");
    let mut child = support::lpm_spawnable_with_registry(&project, &mock.url())
        .args(["dlx", "dlx-prune-tool", "--"])
        .arg(&ready)
        .arg(&release)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    wait_for_marker(&ready, &mut child);
    let mut prune = support::lpm_spawnable(&project)
        .args(["cache", "prune", "--apply"])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    std::thread::sleep(Duration::from_millis(300));
    let waited_for_execution = prune.try_wait().unwrap().is_none();
    std::fs::write(&release, "done").unwrap();
    let output = child.wait_with_output().unwrap();
    let pruned = prune.wait_with_output().unwrap();
    assert_dlx_success(&output);
    assert_dlx_success(&pruned);
    assert!(
        waited_for_execution,
        "store pruning ran while the tool still used its files"
    );
    let warm = lpm_with_registry(&project, &mock.url())
        .args(["dlx", "dlx-prune-tool"])
        .output()
        .unwrap();
    assert_dlx_success(&warm);
    assert!(
        String::from_utf8_lossy(&warm.stderr).contains("Reusing dlx cache entry"),
        "pruning removed the cached tool: {}",
        String::from_utf8_lossy(&warm.stderr)
    );
}

#[tokio::test]
async fn dlx_rechecks_authorization_after_waiting_for_the_cache_entry() {
    let project = TempProject::empty(
        r#"{"name":"dlx-revoked","version":"1.0.0","lpm":{"scriptPolicy":"allow"}}"#,
    );
    support::write_signed_unlock(&project, &["scripts-allow"]);
    let mock = MockRegistry::start().await;
    mount_published_dlx_tool(
        &mock,
        "dlx-revoked-tool",
        "1.0.0",
        &iso8601_n_secs_ago(72 * 3600),
    )
    .await;
    let first = lpm_with_registry(&project, &mock.url())
        .args(["dlx", "dlx-revoked-tool"])
        .output()
        .unwrap();
    assert_dlx_success(&first);
    let root = LpmRoot::from_dir(project.home().join(".lpm"));
    let lock = root.cache_dlx().join(".entry-locks").join(format!(
        "{}.lock",
        lpm_runner::dlx::deterministic_hash("dlx-revoked-tool")
    ));
    let guard = lpm_common::acquire_exclusive_lock(lock).unwrap();
    let stderr = project.path().join("waiting.stderr");
    let mut child = support::lpm_spawnable_with_registry(&project, &mock.url())
        .args(["dlx", "dlx-revoked-tool"])
        .stdout(std::process::Stdio::piped())
        .stderr(std::fs::File::create(&stderr).unwrap())
        .spawn()
        .unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while !std::fs::read_to_string(&stderr)
        .unwrap()
        .contains("Resolving")
    {
        if child.try_wait().unwrap().is_some() || std::time::Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("command did not reach the cache wait");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    lpm(&project)
        .args(["security", "lock", "scripts-allow", "--project"])
        .arg(project.path())
        .assert()
        .success();
    drop(guard);
    let output = child.wait_with_output().unwrap();
    assert!(
        !output.status.success(),
        "revoked authorization was used after the cache wait"
    );
    assert!(!String::from_utf8_lossy(&output.stdout).contains("version:1.0.0"));
}

#[tokio::test]
async fn dlx_preserves_caller_policy_when_the_experimental_installer_is_enabled() {
    let project = TempProject::empty(r#"{"name":"dlx-experimental-caller","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    mount_published_dlx_tool(
        &mock,
        "dlx-experimental-tool",
        "1.0.0",
        &iso8601_n_secs_ago(72 * 3600),
    )
    .await;
    let output = lpm_with_registry(&project, &mock.url())
        .env("LPM_EXPERIMENTAL_INSTALLER_SPIKE", "1")
        .args(["dlx", "dlx-experimental-tool"])
        .output()
        .unwrap();
    assert_dlx_success(&output);
}

#[cfg(unix)]
#[tokio::test]
async fn dlx_engine_checks_distinguish_installed_and_skipped_optional_dependencies() {
    for optional_installed in [false, true] {
        let project = TempProject::empty(r#"{"name":"dlx-optional-engine","version":"1.0.0"}"#);
        let mock = MockRegistry::start().await;
        mock.with_manifest_package(serde_json::json!({"name":"dlx-optional-engine-tool","version":"1.0.0","engines":{"node":">=16"},"optionalDependencies":{"dlx-optional-engine-dep":"1.0.0"},"bin":{"tool":"tool.js"}}), &[("tool.js", b"#!/usr/bin/env node\nconsole.log('TOOL_RAN');")]).await;
        let required = if optional_installed { ">=22" } else { ">=9999" };
        mock.with_manifest_package(serde_json::json!({"name":"dlx-optional-engine-dep","version":"1.0.0","engines":{"node":required}}), &[("index.js", b"module.exports=1;")]).await;
        for (index, version) in ["22.0.0", "16.0.0"].iter().enumerate() {
            let directory = project.path().join(format!("node-{index}"));
            write_dlx_node_probe(&directory, version);
            let mut entries = vec![directory];
            entries.extend(std::env::split_paths(&std::env::var_os("PATH").unwrap()));
            let output = support::lpm_with_registry(&project, &mock.url())
                .env("PATH", std::env::join_paths(entries).unwrap())
                .args(["dlx", "dlx-optional-engine-tool"])
                .output()
                .unwrap();
            if optional_installed && index == 1 {
                assert!(
                    !output.status.success(),
                    "installed optional dependency escaped its engine constraint"
                );
                assert!(!String::from_utf8_lossy(&output.stdout).contains("TOOL_RAN"));
                assert!(
                    String::from_utf8_lossy(&output.stderr).contains("dlx-optional-engine-dep")
                );
            } else {
                assert_dlx_success(&output);
            }
        }
    }
}
