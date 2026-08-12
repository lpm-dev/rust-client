mod support;

use lpm_common::LpmRoot;
use std::time::{Duration, SystemTime};
use support::mock_registry::{MockRegistry, compute_integrity, make_tarball_from_pkg_json};
use support::{TempProject, lpm, lpm_with_registry, write_npm_firewall_global_config};

fn seed_dlx_cache(
    project: &TempProject,
    spec: &str,
    package_name: &str,
    installed_package_json: &str,
) -> std::path::PathBuf {
    let root = LpmRoot::from_dir(project.home().join(".lpm"));
    let cache_dir = lpm_runner::dlx::dlx_cache_dir_at(&root, spec);
    let bin_dir = cache_dir.join("node_modules").join(".bin");
    let package_dir = cache_dir.join("node_modules").join(package_name);
    std::fs::create_dir_all(&bin_dir).expect("failed to create dlx bin dir");
    std::fs::create_dir_all(&package_dir).expect("failed to create installed package dir");
    std::fs::write(cache_dir.join("package.json"), r#"{"private":true}"#)
        .expect("failed to seed dlx package.json");
    std::fs::write(package_dir.join("package.json"), installed_package_json)
        .expect("failed to seed installed package.json");
    seed_lockfile_identity(
        &cache_dir,
        package_name,
        "1.0.0",
        support::VALID_TEST_INTEGRITY,
    );
    cache_dir
}

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

#[cfg(unix)]
fn make_executable(path: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt;

    let mut perms = std::fs::metadata(path)
        .expect("script must exist")
        .permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(path, perms).expect("failed to mark script executable");
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

    // dlx prints a human-output banner ("Installing dependencies for
    // ...") before the envelope; use parse_json_output's first-{ scan.
    let envelope = support::assertions::parse_json_output(&output.stdout);
    assert_eq!(envelope["success"], serde_json::json!(false));
    assert!(
        envelope["error"]
            .as_str()
            .is_some_and(|s| s.contains("range") || s.contains("invalid")),
        "error must reference the malformed range, got: {envelope}",
    );
}

#[test]
fn dlx_cache_hit_executes_cached_binary_without_extending_ttl() {
    let project = TempProject::empty(r#"{"name":"dlx-test","version":"1.0.0"}"#);
    let spec = "npm-check-updates@1.0.0";
    let cache_dir = seed_dlx_cache(
        &project,
        spec,
        "npm-check-updates",
        r#"{"name":"npm-check-updates","bin":{"ncu":"./build/cli.js"}}"#,
    );
    let bin_path = cache_dir.join("node_modules").join(".bin").join("ncu");

    std::fs::write(
        &bin_path,
        "#!/bin/sh\nprintf 'cwd:%s\\nargs:%s\\n' \"$PWD\" \"$*\"\n",
    )
    .expect("failed to write cached dlx binary");
    #[cfg(unix)]
    make_executable(&bin_path);

    let package_json = cache_dir.join("package.json");
    let before = SystemTime::now() - Duration::from_secs(60);
    let file = std::fs::OpenOptions::new()
        .write(true)
        .open(&package_json)
        .expect("seeded package.json must exist");
    file.set_modified(before)
        .expect("failed to backdate package.json");

    let output = lpm(&project)
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
    assert!(
        stdout.contains(&format!("cwd:{}", expected_cwd.display())),
        "dlx must execute from the caller project directory, got:\n{stdout}"
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
        stderr.contains(support::VALID_TEST_INTEGRITY),
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
