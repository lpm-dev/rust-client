//! Workflow tests for `lpm install`.
//!
//! Tests that exercise the full install pipeline through the real binary.
//! Network-dependent tests use MockRegistry; local-only tests use fixtures.

mod support;

use support::assertions;
use support::mock_registry::{
    MockRegistry, RegistrySigningFixture, compute_integrity, make_tarball,
    make_tarball_from_pkg_json, make_tarball_with_files,
};
use support::{
    TempProject, configure_fake_node, lpm, lpm_v1, lpm_v1_with_registry, lpm_with_registry,
    project_bin_path, write_repeated_file, write_signed_unlock,
};
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn read_project_lockfile(project: &TempProject, relative: &str) -> lpm_lockfile::Lockfile {
    lpm_lockfile::Lockfile::read_for_project(&project.path().join(relative))
        .unwrap_or_else(|error| panic!("read lockfile projection for {relative:?}: {error}"))
        .lockfile
}

fn find_v3_blob_with_contents(project: &TempProject, expected: &[u8]) -> std::path::PathBuf {
    let blobs_root = project.home().join(".lpm/store/v3/blobs/blake3");
    for shard in std::fs::read_dir(&blobs_root)
        .unwrap_or_else(|error| panic!("read CAS blob root {}: {error}", blobs_root.display()))
    {
        let shard = shard.expect("read CAS blob shard entry").path();
        if !shard.is_dir() {
            continue;
        }
        for entry in std::fs::read_dir(&shard)
            .unwrap_or_else(|error| panic!("read CAS blob shard {}: {error}", shard.display()))
        {
            let path = entry.expect("read CAS blob entry").path();
            if path.is_file() && std::fs::read(&path).is_ok_and(|bytes| bytes == expected) {
                return path;
            }
        }
    }
    panic!(
        "v3 CAS blob with {} expected bytes was not found under {}",
        expected.len(),
        blobs_root.display()
    );
}

// ─── No package.json ─────────────────────────────────────────────

#[test]
fn install_without_package_json_fails() {
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

#[test]
fn install_without_dependencies_uses_slim_status_output() {
    let project = TempProject::empty(r#"{"name":"empty-install","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args([
            "install",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("failed to run lpm install");

    assert!(
        output.status.success(),
        "empty install should succeed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("✓ No dependencies to install"),
        "empty install should use the slim success glyph; got:\n{stderr}"
    );
    assert!(
        !stderr.contains('│') && !stderr.contains('◇'),
        "empty install status must not use cliclack's boxed gutter; got:\n{stderr}"
    );
}

#[test]
fn install_rejects_malformed_global_config() {
    let project = TempProject::empty(r#"{"name":"malformed-config","version":"1.0.0"}"#);
    let lpm_dir = project.home().join(".lpm");
    std::fs::create_dir_all(&lpm_dir).unwrap();
    std::fs::write(
        lpm_dir.join("config.toml"),
        "[firewall\nmode = \"enforce\"\n",
    )
    .unwrap();

    let output = lpm(&project)
        .args([
            "install",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("failed to run lpm install");

    assert!(
        !output.status.success(),
        "malformed global config must fail install\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("config parse error"),
        "install must surface the config parse error; got:\n{stderr}"
    );
}

#[tokio::test]
async fn install_rejects_oversized_project_config_before_registry_access() {
    let mock = MockRegistry::start().await;
    let project = TempProject::empty(
        r#"{
        "name": "oversized-project-config",
        "version": "1.0.0",
        "dependencies": {
            "oversized-guard-fixture": "1.0.0"
        }
    }"#,
    );
    let path = project.path().join("lpm.toml");
    write_repeated_file(
        &path,
        b"save-prefix = \"^\"\n#",
        b'a',
        lpm_common::CONFIG_FILE_SIZE_CAP_BYTES + 1,
        b"\n",
    );

    let output = lpm_with_registry(&project, &mock.url())
        .args([
            "install",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("run install with oversized project config");

    assert!(
        !output.status.success(),
        "oversized project config must fail install\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(&path.display().to_string())
            && stderr.contains("16777216-byte limit")
            && !stderr.contains("save-prefix"),
        "error must identify only the oversized file and limit; got:\n{stderr}"
    );
    let requests = mock
        .server()
        .received_requests()
        .await
        .expect("wiremock request log must be available");
    assert!(
        requests.is_empty(),
        "oversized project config must fail before registry access; requests={requests:?}"
    );
}

#[tokio::test]
async fn install_rejects_oversized_global_config_before_registry_access() {
    let mock = MockRegistry::start().await;
    let project = TempProject::empty(
        r#"{
        "name": "oversized-global-config",
        "version": "1.0.0",
        "dependencies": {"global-config-fixture": "1.0.0"}
    }"#,
    );
    let lpm_dir = project.home().join(".lpm");
    std::fs::create_dir_all(&lpm_dir).unwrap();
    let path = lpm_dir.join("config.toml");
    write_repeated_file(
        &path,
        b"save-prefix = \"^\"\n#",
        b'a',
        lpm_common::CONFIG_FILE_SIZE_CAP_BYTES + 1,
        b"\n",
    );

    let output = lpm_with_registry(&project, &mock.url())
        .args([
            "install",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("run install with oversized global config");

    assert!(
        !output.status.success(),
        "oversized global config must fail"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(&path.display().to_string()) && stderr.contains("16777216-byte limit"),
        "error must identify global config and limit; got:\n{stderr}"
    );
    assert!(
        mock.server()
            .received_requests()
            .await
            .expect("wiremock requests")
            .is_empty(),
        "global config failure must precede registry access"
    );
}

#[tokio::test]
async fn install_rejects_oversized_project_npmrc_before_registry_access() {
    let mock = MockRegistry::start().await;
    let project = TempProject::empty(
        r#"{
        "name": "oversized-npmrc",
        "version": "1.0.0",
        "dependencies": {"npmrc-fixture": "1.0.0"}
    }"#,
    );
    let path = project.path().join(".npmrc");
    let prefix = format!("registry={}\n#", mock.url());
    write_repeated_file(
        &path,
        prefix.as_bytes(),
        b'a',
        lpm_common::NPMRC_FILE_SIZE_CAP_BYTES + 1,
        b"\n",
    );

    let output = lpm_with_registry(&project, &mock.url())
        .args([
            "install",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("run install with oversized project .npmrc");

    assert!(!output.status.success(), "oversized .npmrc must fail");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(&path.display().to_string()) && stderr.contains("1048576-byte limit"),
        "error must identify .npmrc and limit; got:\n{stderr}"
    );
    assert!(
        mock.server()
            .received_requests()
            .await
            .expect("wiremock requests")
            .is_empty(),
        ".npmrc failure must precede registry access"
    );
}

#[tokio::test]
async fn install_rejects_oversized_package_manifest_before_registry_access() {
    let mock = MockRegistry::start().await;
    let project = TempProject::empty(r#"{"name":"placeholder","version":"1.0.0"}"#);
    let path = project.path().join("package.json");
    write_repeated_file(
        &path,
        br#"{"name":"oversized-package","version":"1.0.0","dependencies":{"manifest-fixture":"1.0.0"},"padding":""#,
        b'a',
        lpm_common::CONFIG_FILE_SIZE_CAP_BYTES + 1,
        br#""}"#,
    );

    let output = lpm_with_registry(&project, &mock.url())
        .args([
            "install",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("run install with oversized package.json");

    assert!(!output.status.success(), "oversized package.json must fail");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(&path.display().to_string()) && stderr.contains("16777216-byte limit"),
        "error must identify package.json and limit; got:\n{stderr}"
    );
    assert!(
        mock.server()
            .received_requests()
            .await
            .expect("wiremock requests")
            .is_empty(),
        "manifest failure must precede registry access"
    );
}

#[tokio::test]
async fn install_rejects_oversized_pnpm_workspace_manifest_before_registry_access() {
    let mock = MockRegistry::start().await;
    let project = TempProject::empty(
        r#"{
        "name": "oversized-workspace",
        "version": "1.0.0",
        "dependencies": {"workspace-fixture": "1.0.0"}
    }"#,
    );
    let path = project.path().join("pnpm-workspace.yaml");
    write_repeated_file(
        &path,
        b"packages:\n  - 'packages/*'\n#",
        b'a',
        lpm_common::CONFIG_FILE_SIZE_CAP_BYTES + 1,
        b"\n",
    );

    let output = lpm_with_registry(&project, &mock.url())
        .args([
            "install",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("run install with oversized pnpm-workspace.yaml");

    assert!(
        !output.status.success(),
        "oversized pnpm-workspace.yaml must fail"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(&path.display().to_string()) && stderr.contains("16777216-byte limit"),
        "error must identify workspace manifest and limit; got:\n{stderr}"
    );
    assert!(
        mock.server()
            .received_requests()
            .await
            .expect("wiremock requests")
            .is_empty(),
        "workspace manifest failure must precede registry access"
    );
}

#[test]
fn install_accepts_project_config_exactly_at_the_limit() {
    let project = TempProject::empty(r#"{"name":"max-config","version":"1.0.0"}"#);
    write_repeated_file(
        &project.path().join("lpm.toml"),
        b"save-prefix = \"^\"\n#",
        b'a',
        lpm_common::CONFIG_FILE_SIZE_CAP_BYTES,
        b"\n",
    );

    let output = lpm(&project)
        .args([
            "install",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("run install with maximum-size project config");

    assert!(
        output.status.success(),
        "config exactly at cap must remain compatible\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[tokio::test]
async fn install_fast_lane_rejects_malformed_firewall_config() {
    let mock = MockRegistry::start().await;
    mount_ms_2_1_3(&mock).await;

    let project = TempProject::empty(
        r#"{
        "name": "firewall-fast-lane-config",
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

    let lpm_dir = project.home().join(".lpm");
    std::fs::create_dir_all(&lpm_dir).unwrap();
    std::fs::write(lpm_dir.join("config.toml"), "firewall = \"enforce\"\n").unwrap();

    let output = lpm(&project)
        .arg("install")
        .env("LPM_REGISTRY_URL", mock.url())
        .output()
        .expect("failed to run bare install");

    assert!(
        !output.status.success(),
        "bare warm-cache install must reject malformed firewall config\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !combined.contains("up to date"),
        "fast lane must not exit as up to date when firewall config is malformed; got:\n{combined}"
    );
    assert!(
        combined.contains("`[firewall]` must be a TOML table"),
        "error must name the malformed firewall table; got:\n{combined}"
    );
}

#[tokio::test]
async fn bare_install_runs_root_project_lifecycle_scripts_in_order() {
    let mock = MockRegistry::start().await;
    mount_ms_2_1_3(&mock).await;

    let project = TempProject::empty(
        r#"{
            "name": "root-lifecycle-install",
            "version": "1.0.0",
            "dependencies": { "ms": "^2.1.3" },
            "scripts": {
                "pnpm:devPreinstall": "node record-root-lifecycle.js pnpm:devPreinstall",
                "preinstall": "node record-root-lifecycle.js preinstall",
                "install": "node record-root-lifecycle.js install",
                "postinstall": "node record-root-lifecycle.js postinstall",
                "preprepare": "node record-root-lifecycle.js preprepare",
                "prepare": "node record-root-lifecycle.js prepare",
                "postprepare": "node record-root-lifecycle.js postprepare"
            }
        }"#,
    );
    project.write_file(
        "record-root-lifecycle.js",
        r#"const fs = require('fs');
const phase = process.argv[2];
const event = process.env.npm_lifecycle_event || 'missing-event';
const pkg = process.env.npm_package_name || 'missing-package';
const marker = fs.existsSync('node_modules/ms/package.json') ? 'has-ms' : 'no-ms';
fs.appendFileSync('root-lifecycle.log', `${phase}:${event}:${pkg}:${marker}\n`);
"#,
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

    assert!(
        output.status.success(),
        "bare install with root lifecycle scripts should succeed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        project.read_file("root-lifecycle.log"),
        "pnpm:devPreinstall:pnpm:devPreinstall:root-lifecycle-install:no-ms\n\
         preinstall:preinstall:root-lifecycle-install:has-ms\n\
         install:install:root-lifecycle-install:has-ms\n\
         postinstall:postinstall:root-lifecycle-install:has-ms\n\
         preprepare:preprepare:root-lifecycle-install:has-ms\n\
         prepare:prepare:root-lifecycle-install:has-ms\n\
         postprepare:postprepare:root-lifecycle-install:has-ms\n",
        "root lifecycle scripts must run once in the agreed install order"
    );
}

#[tokio::test]
async fn install_add_does_not_run_root_prepare_lifecycle() {
    let mock = MockRegistry::start().await;
    mount_ms_2_1_3(&mock).await;

    let project = TempProject::empty(
        r#"{
            "name": "root-lifecycle-add",
            "version": "1.0.0",
            "scripts": {
                "prepare": "node record-root-lifecycle.js prepare"
            }
        }"#,
    );
    project.write_file(
        "record-root-lifecycle.js",
        r#"require('fs').appendFileSync('root-lifecycle.log', `${process.argv[2]}\n`);"#,
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

    assert!(
        output.status.success(),
        "installing a package should succeed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !project.file_exists("root-lifecycle.log"),
        "root prepare must not auto-run for `lpm install <pkg>`"
    );
}

#[test]
fn install_resolver_phase_colors_registry_host_when_color_is_forced() {
    let project = TempProject::empty(r#"{"name":"empty-install","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args([
            "--color=always",
            "install",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("failed to run lpm install");

    assert!(
        output.status.success(),
        "empty install should succeed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Resolving dependencies from")
            && stderr.contains("\u{1b}[33m")
            && stderr.contains("\u{1b}[39m"),
        "resolver phase must color the registry host under --color=always, got:\n{stderr}"
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
    cmd.env("LPM_DISABLE_TELEMETRY", "1");
    cmd.env("LPM_FORCE_FILE_AUTH", "1");
    cmd.env("LPM_TEST_FAST_SCRYPT", "1");
    cmd.env("LPM_FORCE_FILE_VAULT", "1");
    cmd.env("LPM_DISABLE_HOST_CLI_AUTH", "1");
    cmd.env(
        "LPM_SECURITY_POLICY_PATH",
        project.home().join(".lpm/security-policy.toml"),
    );
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

async fn assert_install_range_prefers_satisfying_latest_dist_tag(resolver: Option<&str>) {
    let mock = MockRegistry::start().await;
    let package_name = "dist-tag-range-preference";
    let latest_version = "1.0.0-next.25";
    let higher_version = "1.0.0-next.28";
    let latest_tarball = make_tarball(package_name, latest_version);
    let higher_tarball = make_tarball(package_name, higher_version);
    let metadata = serde_json::json!({
        "name": package_name,
        "dist-tags": {
            "latest": latest_version,
            "next": higher_version,
        },
        "modified": "2025-01-02T00:00:00.000Z",
        "versions": {
            latest_version: {
                "name": package_name,
                "version": latest_version,
                "dist": {
                    "tarball": mock.tarball_url(package_name, latest_version),
                    "integrity": compute_integrity(&latest_tarball),
                },
                "dependencies": {},
            },
            higher_version: {
                "name": package_name,
                "version": higher_version,
                "dist": {
                    "tarball": mock.tarball_url(package_name, higher_version),
                    "integrity": compute_integrity(&higher_tarball),
                },
                "dependencies": {},
            },
        },
        "time": {
            latest_version: "2025-01-01T00:00:00.000Z",
            higher_version: "2025-01-02T00:00:00.000Z",
        },
    });
    mock.with_package_metadata_and_tarballs(
        package_name,
        metadata.clone(),
        &[
            (latest_version, latest_tarball),
            (higher_version, higher_tarball),
        ],
    )
    .await;
    mock.with_batch_metadata(vec![metadata]).await;

    let project = TempProject::empty(&format!(
        r#"{{
            "name": "dist-tag-range-project",
            "version": "1.0.0",
            "dependencies": {{ "{package_name}": "^1.0.0-next.25" }}
        }}"#,
    ));
    project.write_file(".npmrc", &format!("registry={}\n", mock.url()));
    let mut command = lpm_with_registry(&project, &mock.url());
    command.args([
        "install",
        "--no-security-summary",
        "--no-skills",
        "--no-editor-setup",
    ]);
    if let Some(resolver) = resolver {
        command.env("LPM_RESOLVER", resolver);
    }

    let output = command.output().expect("run range install");

    assert!(
        output.status.success(),
        "range install must succeed; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let installed: serde_json::Value = serde_json::from_str(
        &project.read_file(&format!("node_modules/{package_name}/package.json")),
    )
    .expect("installed package.json must parse");
    assert_eq!(installed["version"], serde_json::json!(latest_version));
}

#[tokio::test]
async fn install_range_prefers_satisfying_latest_dist_tag_over_higher_prerelease() {
    assert_install_range_prefers_satisfying_latest_dist_tag(None).await;
}

#[tokio::test]
async fn install_pubgrub_range_prefers_satisfying_latest_dist_tag_over_higher_prerelease() {
    assert_install_range_prefers_satisfying_latest_dist_tag(Some("pubgrub")).await;
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
    cmd.env("LPM_DISABLE_TELEMETRY", "1");
    cmd.env("LPM_FORCE_FILE_AUTH", "1");
    cmd.env("LPM_TEST_FAST_SCRYPT", "1");
    cmd.env("LPM_FORCE_FILE_VAULT", "1");
    cmd.env("LPM_DISABLE_HOST_CLI_AUTH", "1");
    cmd.env(
        "LPM_SECURITY_POLICY_PATH",
        project.home().join(".lpm/security-policy.toml"),
    );
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
async fn install_osv_outage_suppresses_audit_after_install_summary() {
    let mock = MockRegistry::start().await;
    let tarball = make_tarball("ms", "2.1.3");
    mock.with_package("ms", "2.1.3", &tarball).await;
    mount_ms_2_1_3(&mock).await;
    Mock::given(method("POST"))
        .and(path("/v1/querybatch"))
        .respond_with(ResponseTemplate::new(503).set_body_string("maintenance"))
        .mount(mock.server())
        .await;

    let project = TempProject::empty(
        r#"{"name":"audit-outage","version":"1.0.0","dependencies":{"ms":"^2.1.3"}}"#,
    );
    let output = lpm_with_registry(&project, &mock.url())
        .env("LPM_OSV_URL", format!("{}/v1/querybatch", mock.url()))
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
        "audit-after-install outage must not fail a successful install: {stderr}"
    );
    assert!(
        !stderr.contains("Audited"),
        "incomplete audit must not emit zero-vulnerability summary: {stderr}"
    );
    assert!(
        stderr.contains("audit-after-install failed"),
        "audit outage should remain visible to operators: {stderr}"
    );
}

#[tokio::test]
async fn install_audit_after_install_counts_lpm_registry_advisories() {
    let mock = MockRegistry::start().await;
    let package = "@lpm.dev/test.audit-after-install";
    let tarball = make_tarball(package, "1.0.0");
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
                },
                "_vulnerabilities": [{
                    "id": "LPM-ADV-INSTALL",
                    "summary": "test advisory",
                    "severity": "high"
                }]
            }
        }
    });
    mock.with_package_metadata_and_tarballs(package, metadata, &[("1.0.0", tarball)])
        .await;

    let project = TempProject::empty(&format!(
        r#"{{"name":"audit-lpm-advisory","version":"1.0.0","dependencies":{{"{package}":"1.0.0"}}}}"#
    ));
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
    assert!(output.status.success(), "install must succeed: {stderr}");
    assert!(
        stderr.contains("1 vulnerability"),
        "LPM registry advisory must be included in the install audit count: {stderr}"
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

#[cfg(debug_assertions)]
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
    // Failure injection uses `LPM_TEST_AUDIT_AFTER_INSTALL_FAIL=1`,
    // honored only by debug builds. The trigger is owned by
    // `maybe_test_audit_after_install_should_fail` in install.rs.
    let mock = MockRegistry::start().await;
    let tarball = make_tarball("ms", "2.1.3");
    mock.with_package("ms", "2.1.3", &tarball).await;
    mount_ms_2_1_3(&mock).await;

    let project = TempProject::empty(
        r#"{"name":"audit-fail","version":"1.0.0","dependencies":{"ms":"^2.1.3"}}"#,
    );

    let output = lpm_with_registry(&project, &mock.url())
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
        "parse layer must reject passing both flags simultaneously"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("cannot be used with"),
        "expected parse conflict message; got stderr:\n{stderr}"
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

#[test]
fn bare_install_with_importer_snapshot_stays_fresh_without_binary_lockfile() {
    let project = TempProject::empty(
        r#"{
        "name": "empty-deps-lockb-refresh",
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
        !project.file_exists("lpm.lockb"),
        "importer state is not representable in the current binary lockfile format"
    );

    let second = lpm(&project)
        .args(["install"])
        .output()
        .expect("failed to run second lpm install");
    assert!(
        second.status.success(),
        "second install failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&second.stdout),
        String::from_utf8_lossy(&second.stderr),
    );
    assert!(
        !project.file_exists("lpm.lockb"),
        "a fresh TOML-only install must not create a lossy binary sidecar"
    );
    let second_output = format!(
        "{}{}",
        String::from_utf8_lossy(&second.stdout),
        String::from_utf8_lossy(&second.stderr)
    );
    assert!(
        second_output.contains("up to date"),
        "the missing unsupported sidecar must not invalidate freshness:\n{second_output}"
    );

    let doctor = lpm(&project)
        .args(["doctor"])
        .output()
        .expect("failed to run lpm doctor");
    let doctor_output = format!(
        "{}{}",
        String::from_utf8_lossy(&doctor.stdout),
        String::from_utf8_lossy(&doctor.stderr)
    );
    assert!(
        !doctor_output.contains("lpm.lockb missing"),
        "doctor must not request a sidecar that cannot represent importer state:\n{doctor_output}"
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
        stderr
            .lines()
            .any(|line| line.starts_with("! ") && line.contains("`pnpm.overrides`")),
        "manifest compatibility warning must use a slim warning line, got:\n{stderr}"
    );
    assert!(
        stderr
            .lines()
            .any(|line| line.contains("fix:") && line.contains("lpm migrate")),
        "manifest compatibility warning must include a slim fix detail row, got:\n{stderr}"
    );
    assert!(
        !stderr.contains("warning:"),
        "manifest compatibility warning must not use the legacy warning label, got:\n{stderr}"
    );
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
/// (`duration_ms`, integrity hashes, resolver-internal counters) are
/// redacted to keep the snapshot stable across runs and across
/// resolver-internal refactors.
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
                    "integrity": compute_integrity(&tarball),
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
    assert_eq!(envelope["schema_version"], serde_json::json!(2));
    assert!(
        envelope.get("timing").is_none(),
        "default install --json must omit opt-in timing diagnostics; got {envelope:#}"
    );
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
            ".packages[].integrity" => "[INTEGRITY]",
            ".packages[].duration_ms" => "[DURATION]",
            // Resolver-arm telemetry counters vary by route mode + arm.
            ".resolver" => "[RESOLVER]",
            ".cache" => "[CACHE]",
        });
    });
}

#[tokio::test]
async fn install_json_timing_flag_exposes_waterfall_without_detail() {
    let mock = MockRegistry::start().await;
    mount_ms_2_1_3(&mock).await;

    let project = TempProject::empty(
        r#"{"name":"timing-flag-install","version":"1.0.0","dependencies":{"ms":"^2.1.3"}}"#,
    );
    let output = lpm_with_registry(&project, &mock.url())
        .args([
            "install",
            "--json",
            "--timing",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("failed to run lpm install --json --timing");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "install --json --timing failed:\nstdout: {stdout}\nstderr: {stderr}"
    );
    let envelope: serde_json::Value =
        serde_json::from_str(&stdout).expect("install --json --timing must emit parseable JSON");

    assert_eq!(envelope["schema_version"], serde_json::json!(2));
    assert!(
        envelope["timing"]["waterfall"].is_object(),
        "--timing must emit timing.waterfall; got {envelope:#}"
    );
    assert_eq!(envelope["timing"]["scope"], "target");
    assert_eq!(envelope["timing"]["work_is_cumulative"], false);
    assert_eq!(envelope["timing"]["phase_aggregation"], "target_wall_clock");
    assert_eq!(envelope["timing"]["waterfall"]["commit_wait_ms"], 0);
    assert_eq!(
        envelope["timing"]["waterfall"]["pre_fetch_ms"],
        envelope["timing"]["waterfall"]["post_resolve_work_ms"]
    );
    assert_eq!(envelope["counts"]["scope"], "target");
    assert_eq!(
        envelope["counts"]["store_reuse_may_include_same_command_population"],
        true
    );
    assert!(
        envelope["counts"]["linker_entry_created_count"].is_number(),
        "counts must distinguish linker entry creation from project links: {envelope:#}"
    );
    assert!(
        envelope["timing"].get("detail").is_none(),
        "--timing alone must not emit timing.detail; got {envelope:#}"
    );
}

#[tokio::test]
async fn install_json_timing_env_exposes_waterfall_without_detail() {
    let mock = MockRegistry::start().await;
    mount_ms_2_1_3(&mock).await;

    let project = TempProject::empty(
        r#"{"name":"timing-env-install","version":"1.0.0","dependencies":{"ms":"^2.1.3"}}"#,
    );
    let output = lpm_with_registry(&project, &mock.url())
        .env("LPM_TIMING", "1")
        .args([
            "install",
            "--json",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("failed to run LPM_TIMING=1 lpm install --json");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "LPM_TIMING=1 install --json failed:\nstdout: {stdout}\nstderr: {stderr}"
    );
    let envelope: serde_json::Value = serde_json::from_str(&stdout)
        .expect("LPM_TIMING=1 install --json must emit parseable JSON");

    assert_eq!(envelope["schema_version"], serde_json::json!(2));
    assert!(
        envelope["timing"]["waterfall"].is_object(),
        "LPM_TIMING=1 must emit timing.waterfall; got {envelope:#}"
    );
    assert!(
        envelope["timing"].get("detail").is_none(),
        "LPM_TIMING=1 must not emit timing.detail; got {envelope:#}"
    );
}

#[tokio::test]
async fn install_json_timing_detail_env_exposes_install_substage_probes() {
    let mock = MockRegistry::start().await;
    mount_ms_2_1_3(&mock).await;

    let project = TempProject::empty(
        r#"{"name":"timing-detail-install","version":"1.0.0","dependencies":{"ms":"^2.1.3"}}"#,
    );
    let output = lpm_with_registry(&project, &mock.url())
        .env("LPM_TIMING_DETAIL", "1")
        .args([
            "install",
            "--json",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("failed to run lpm install --json");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "install --json failed:\nstdout: {stdout}\nstderr: {stderr}"
    );
    let envelope: serde_json::Value =
        serde_json::from_str(&stdout).expect("install --json must emit parseable JSON");

    let detail = envelope["timing"]["detail"]
        .as_object()
        .unwrap_or_else(|| panic!("LPM_TIMING_DETAIL=1 must emit timing.detail; got {envelope:#}"));
    assert!(
        envelope["timing"]["waterfall"].get("detail").is_none(),
        "detail belongs under timing.detail, not timing.waterfall.detail; got {envelope:#}"
    );
    assert!(detail.get("setup").is_some(), "missing detail.setup");
    assert!(detail.get("fetch").is_some(), "missing detail.fetch");
    assert!(detail.get("link").is_some(), "missing detail.link");
    assert!(detail.get("tail").is_some(), "missing detail.tail");
    assert!(
        detail.get("trace").is_none(),
        "trace-only package rankings must stay out of LPM_TIMING_DETAIL=1"
    );

    let metadata = detail["metadata"]
        .as_array()
        .unwrap_or_else(|| panic!("detail.metadata must be an array; got {detail:#?}"));
    assert!(
        metadata.iter().any(|entry| entry["purpose"] == "resolve"),
        "metadata detail must include resolve attribution; got {metadata:#?}"
    );
    for field in [
        "rpc_ms",
        "rpc_count",
        "cache_hit_count",
        "cache_miss_count",
        "request_count",
        "unique_package_count",
        "duplicate_request_count",
    ] {
        assert!(
            metadata.iter().all(|entry| entry[field].is_number()),
            "metadata entries must expose numeric {field}; got {metadata:#?}"
        );
    }

    let tail = detail["tail"]
        .as_object()
        .unwrap_or_else(|| panic!("detail.tail must be an object; got {detail:#?}"));
    for field in [
        "blocked_metadata_ms",
        "trust_snapshot_ms",
        "lockfile_write_ms",
        "lockfile_write_count",
        "build_state_write_ms",
        "build_state_write_count",
        "audit_after_install_ms",
        "other_ms",
    ] {
        assert!(
            tail.get(field).is_some_and(serde_json::Value::is_number),
            "detail.tail.{field} must be numeric; got {tail:#?}"
        );
    }

    assert!(
        detail["resolve"]["policy"]["release_age"].is_object(),
        "detail.resolve.policy.release_age must be an object"
    );
    assert!(
        detail["resolve"]["policy"]["trust"].is_object(),
        "detail.resolve.policy.trust must be an object"
    );
    for field in ["wall_ms", "initial_batch_ms", "other_ms"] {
        assert!(
            detail["resolve"][field].is_number(),
            "detail.resolve.{field} must be numeric; got {detail:#?}"
        );
    }
    assert!(
        detail["resolve"]["metadata"].is_object(),
        "detail.resolve.metadata must summarize resolve metadata counters; got {detail:#?}"
    );
    assert!(
        detail["resolve"].get("metadata_fetch").is_none(),
        "trace-only metadata fetch package attribution must stay out of LPM_TIMING_DETAIL=1"
    );
    assert!(
        detail["resolve"]["scheduler"].is_object(),
        "detail.resolve.scheduler must expose resolver wait/fanout counters; got {detail:#?}"
    );
    let peer = &detail["resolve"]["peer"];
    for field in [
        "non_empty_pass_count",
        "requirement_count",
        "unique_requirement_count",
        "repeated_requirement_count",
        "group_count",
        "already_satisfied_group_count",
        "classified_group_count",
        "skipped_opt_out_group_count",
        "resolution_cache_hit_count",
        "resolution_cache_miss_count",
        "manifest_lookup_count",
        "manifest_wait_ms",
        "processing_ms",
        "synthesized_edge_count",
        "edge_visits_per_allocated_node",
    ] {
        assert!(
            peer[field].is_number(),
            "detail.resolve.peer.{field} must be numeric; got {peer:#?}"
        );
    }
    assert_eq!(peer["scope"], "resolver_pass");
    assert_eq!(peer["work_is_cumulative"], true);
    assert_eq!(peer["processing_excludes_manifest_wait"], true);
    insta::assert_json_snapshot!("install_json_timing_peer_resolution", peer);
    let dispatcher_contract = serde_json::json!({
        "summary": envelope["timing"]["resolve"]["dispatcher"],
        "detail": detail["resolve"]["scheduler"]["dispatcher"],
    });
    assert_eq!(
        envelope["timing"]["resolve"]["metadata_dispatcher"],
        dispatcher_contract["summary"]
    );
    assert_eq!(
        detail["resolve"]["scheduler"]["metadata_dispatcher"],
        dispatcher_contract["detail"]
    );
    for surface in ["summary", "detail"] {
        let dispatcher = &dispatcher_contract[surface];
        for field in [
            "rpc_count",
            "configured_fanout",
            "inflight_high_water",
            "active_fetch_high_water",
            "pending_high_water",
            "semaphore_wait_count",
            "semaphore_wait_ms",
            "parked_max_depth",
            "tarball_dispatched",
            "selected_version_event_count",
            "peer_prefetch_count",
        ] {
            assert!(
                dispatcher[field].is_number(),
                "{surface} dispatcher field {field} must be numeric; got {dispatcher:#?}"
            );
        }
        assert_eq!(
            dispatcher["inflight_high_water"], dispatcher["active_fetch_high_water"],
            "{surface} compatibility alias must match active fetch high-water",
        );
        assert_eq!(dispatcher["scope"], "resolver_pass");
        assert_eq!(dispatcher["kind"], "metadata");
        assert_eq!(dispatcher["concurrency_scope"], "resolver_pass");
        assert_eq!(dispatcher["tarball_downloads_included"], false);
    }
    insta::assert_json_snapshot!("install_json_timing_dispatcher_concurrency", dispatcher_contract, {
        ".summary.rpc_count" => "[COUNT]",
        ".summary.configured_fanout" => "[COUNT]",
        ".summary.inflight_high_water" => "[COUNT]",
        ".summary.active_fetch_high_water" => "[COUNT]",
        ".summary.pending_high_water" => "[COUNT]",
        ".summary.semaphore_wait_count" => "[COUNT]",
        ".summary.semaphore_wait_ms" => "[DURATION]",
        ".summary.parked_max_depth" => "[COUNT]",
        ".summary.tarball_dispatched" => "[COUNT]",
        ".summary.selected_version_event_count" => "[COUNT]",
        ".summary.peer_prefetch_count" => "[COUNT]",
        ".detail.rpc_count" => "[COUNT]",
        ".detail.configured_fanout" => "[COUNT]",
        ".detail.inflight_high_water" => "[COUNT]",
        ".detail.active_fetch_high_water" => "[COUNT]",
        ".detail.pending_high_water" => "[COUNT]",
        ".detail.semaphore_wait_count" => "[COUNT]",
        ".detail.semaphore_wait_ms" => "[DURATION]",
        ".detail.parked_max_depth" => "[COUNT]",
        ".detail.tarball_dispatched" => "[COUNT]",
        ".detail.selected_version_event_count" => "[COUNT]",
        ".detail.peer_prefetch_count" => "[COUNT]",
    });
    assert!(
        detail["resolve"]["cpu"].is_object(),
        "detail.resolve.cpu must expose parser/resolver CPU counters; got {detail:#?}"
    );
    assert!(
        metadata
            .iter()
            .all(|entry| entry.get("top_duplicate_packages").is_none()),
        "trace-only duplicate package rankings must stay out of LPM_TIMING_DETAIL=1"
    );
    let fetch = detail["fetch"]
        .as_object()
        .unwrap_or_else(|| panic!("detail.fetch must be an object; got {detail:#?}"));
    assert!(
        fetch["stage"].is_object(),
        "detail.fetch.stage must expose fetch-stage wall attribution; got {fetch:#?}"
    );
    assert!(
        fetch["counts"].is_object(),
        "detail.fetch.counts must expose cache/download/link dispatch counters; got {fetch:#?}"
    );
    assert!(
        fetch["classification"].is_object(),
        "detail.fetch.classification must expose cache-classification branch timing; got {fetch:#?}"
    );
    assert!(
        fetch["breakdown"].is_object(),
        "detail.fetch.breakdown must retain the per-download breakdown; got {fetch:#?}"
    );
    assert!(
        fetch["v2_reusable_validation"].is_object(),
        "detail.fetch.v2_reusable_validation must expose reusable-object validation counters; got {fetch:#?}"
    );
    assert!(
        fetch["overlap"].is_object(),
        "detail.fetch.overlap must expose early fetch overlap counters; got {fetch:#?}"
    );
    for field in [
        "selected_count",
        "dispatched_count",
        "completed_count",
        "cache_hit_count",
        "failed_count",
        "skipped_platform_count",
        "skipped_auth_count",
        "skipped_optional_count",
        "skipped_engine_count",
        "task_sum_ms",
        "task_max_ms",
        "drain_ms",
    ] {
        assert!(
            fetch["overlap"][field].is_number(),
            "detail.fetch.overlap.{field} must be numeric; got {fetch:#?}"
        );
    }
    assert!(
        fetch["overlap"]["breakdown"].is_object(),
        "detail.fetch.overlap.breakdown must expose early fetch task attribution; got {fetch:#?}"
    );
    for field in ["task_count", "task_sum_ms", "task_max_ms"] {
        assert!(
            fetch["overlap"]["breakdown"][field].is_number(),
            "detail.fetch.overlap.breakdown.{field} must be numeric; got {fetch:#?}"
        );
    }
    for field in ["task_count", "task_sum_ms", "task_max_ms"] {
        assert!(
            fetch["breakdown"][field].is_number(),
            "detail.fetch.breakdown.{field} must be numeric; got {fetch:#?}"
        );
    }
    for field in [
        "wall_ms",
        "plan_ms",
        "v2_reusable_prevalidate_ms",
        "cache_classify_ms",
        "policy_gate_ms",
        "download_wall_ms",
        "other_ms",
    ] {
        assert!(
            fetch["stage"][field].is_number(),
            "detail.fetch.stage.{field} must be numeric; got {fetch:#?}"
        );
    }
    for field in [
        "wall_ms",
        "local_source_ms",
        "v2_reusable_hit_ms",
        "v1_to_v2_translate_ms",
        "v1_cache_hit_ms",
        "download_candidate_ms",
        "link_dispatch_ms",
        "other_ms",
    ] {
        assert!(
            fetch["classification"][field].is_number(),
            "detail.fetch.classification.{field} must be numeric; got {fetch:#?}"
        );
    }
    for field in [
        "package_count",
        "cached_count",
        "download_candidate_count",
        "v2_reusable_candidate_count",
        "v2_reusable_hit_count",
        "v2_reusable_concurrency",
        "local_source_count",
        "v1_cache_hit_count",
        "v1_to_v2_translate_count",
        "v1_to_v2_translate_failure_count",
        "link_dispatch_count",
    ] {
        assert!(
            fetch["counts"][field].is_number(),
            "detail.fetch.counts.{field} must be numeric; got {fetch:#?}"
        );
    }
    for field in [
        "checked_count",
        "hit_count",
        "miss_count",
        "total_ms",
        "max_check_ms",
        "missing_count",
        "complete_check_ms",
        "object_sidecar_read_count",
        "object_sidecar_read_ms",
        "snapshot_read_count",
        "snapshot_read_ms",
        "snapshot_hit_count",
        "snapshot_miss_count",
        "metadata_hash_count",
        "metadata_hash_ms",
        "full_hash_count",
        "full_hash_ms",
        "removed_count",
        "remove_ms",
    ] {
        assert!(
            fetch["v2_reusable_validation"][field].is_number(),
            "detail.fetch.v2_reusable_validation.{field} must be numeric; got {fetch:#?}"
        );
    }
    let link = detail["link"]
        .as_object()
        .unwrap_or_else(|| panic!("detail.link must be an object; got {detail:#?}"));
    assert!(
        link["v2_one"].is_object(),
        "detail.link.v2_one must expose event-driven v2 link task counters; got {link:#?}"
    );
    for field in [
        "task_count",
        "freshly_populated_count",
        "reused_entry_count",
        "task_sum_ms",
        "task_max_ms",
        "await_ms",
    ] {
        assert!(
            link["v2_one"][field].is_number(),
            "detail.link.v2_one.{field} must be numeric; got {link:#?}"
        );
    }
    assert!(
        detail["security"]["registry_signatures"].is_object(),
        "detail.security.registry_signatures must be an object"
    );
    assert!(
        detail["security"]["provenance"].is_object(),
        "detail.security.provenance must be an object"
    );
    let speculative = envelope["timing"]["speculative"]
        .as_object()
        .unwrap_or_else(|| panic!("timing.speculative must be an object; got {envelope:#?}"));
    for field in [
        "dispatched",
        "completed",
        "failed",
        "completed_before_fetch",
        "consumed_by_fetch",
        "duplicated_with_fetch",
        "wasted",
    ] {
        assert!(
            speculative
                .get(field)
                .is_some_and(serde_json::Value::is_number),
            "timing.speculative.{field} must be numeric; got {speculative:#?}"
        );
    }
}

#[tokio::test]
async fn install_fetch_overlap_threshold_one_keeps_install_output_authoritative() {
    let mock = MockRegistry::start().await;
    mount_ms_2_1_3(&mock).await;

    let project = TempProject::empty(
        r#"{"name":"fetch-overlap-install","version":"1.0.0","dependencies":{"ms":"^2.1.3"}}"#,
    );
    let output = lpm_with_registry(&project, &mock.url())
        .env("LPM_STORE_VERSION", "v2")
        .env("LPM_TIMING_DETAIL", "1")
        .env("LPM_FETCH_OVERLAP_MIN_SELECTED", "1")
        .args([
            "install",
            "--json",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("failed to run lpm install --json");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "install --json failed:\nstdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        project.file_exists("node_modules/ms/package.json"),
        "install output must still be driven by the final resolved package graph"
    );

    let envelope: serde_json::Value =
        serde_json::from_str(&stdout).expect("install --json must emit parseable JSON");
    let overlap = envelope["timing"]["detail"]["fetch"]["overlap"]
        .as_object()
        .unwrap_or_else(|| panic!("timing.detail.fetch.overlap missing; got {envelope:#}"));
    assert!(
        overlap["selected_count"]
            .as_u64()
            .is_some_and(|count| count >= 1),
        "forced overlap admission should observe at least one resolver selection; got {overlap:#?}"
    );
    assert!(
        overlap["dispatched_count"]
            .as_u64()
            .is_some_and(|count| count >= 1),
        "forced overlap admission should dispatch at least one early fetch; got {overlap:#?}"
    );
    assert_eq!(
        overlap["failed_count"].as_u64(),
        Some(0),
        "early fetch overlap must fall back cleanly without task failures; got {overlap:#?}"
    );

    let downloaded = envelope["downloaded"]
        .as_u64()
        .unwrap_or_else(|| panic!("downloaded must be numeric; got {envelope:#}"));
    let cached = envelope["cached"]
        .as_u64()
        .unwrap_or_else(|| panic!("cached must be numeric; got {envelope:#}"));
    let package_count = envelope["count"]
        .as_u64()
        .unwrap_or_else(|| panic!("count must be numeric; got {envelope:#}"));
    let fetch_breakdown = &envelope["timing"]["fetch_breakdown"];
    let detail_breakdown = &envelope["timing"]["detail"]["fetch"]["breakdown"];
    let overlap_breakdown = &envelope["timing"]["detail"]["fetch"]["overlap"]["breakdown"];
    assert_eq!(
        cached + downloaded,
        package_count,
        "cache/download counts must partition final install graph; got {envelope:#}"
    );
    assert_eq!(
        fetch_breakdown["task_count"].as_u64(),
        Some(downloaded),
        "top-level fetch breakdown must describe authoritative fetch tasks only; got {envelope:#}"
    );
    assert_eq!(
        detail_breakdown["task_count"].as_u64(),
        Some(downloaded),
        "detail fetch breakdown must mirror authoritative fetch task count; got {envelope:#}"
    );
    assert_eq!(
        overlap_breakdown["task_count"].as_u64(),
        overlap["completed_count"].as_u64(),
        "overlap breakdown must carry early fetch task timings separately; got {envelope:#}"
    );
}

#[tokio::test]
async fn install_experimental_spike_replays_frozen_lockfile_and_emits_json() {
    let mock = MockRegistry::start().await;
    mount_ms_2_1_3(&mock).await;

    let project = TempProject::empty(
        r#"{"name":"spike-lockfile-replay","version":"1.0.0","dependencies":{"ms":"^2.1.3"}}"#,
    );

    let lockfile_output = lpm_with_registry(&project, &mock.url())
        .env("LPM_STORE_VERSION", "v2")
        .args([
            "install",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("failed to create lockfile fixture");
    assert!(
        lockfile_output.status.success(),
        "initial install must create a reusable lockfile\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&lockfile_output.stdout),
        String::from_utf8_lossy(&lockfile_output.stderr)
    );
    assertions::assert_lockfile_exists(project.path());
    std::fs::remove_dir_all(project.path().join("node_modules"))
        .expect("remove node_modules before frozen lockfile replay");

    let output = lpm_with_registry(&project, &mock.url())
        .env("LPM_STORE_VERSION", "v2")
        .env("LPM_EXPERIMENTAL_INSTALLER_SPIKE", "1")
        .env("LPM_INSTALLER_SPIKE_BENCHMARK_ONLY", "1")
        .env("LPM_INSTALLER_SPIKE_GRAPH", "lockfile")
        .args([
            "install",
            "--json",
            "--timing",
            "--frozen-lockfile",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("failed to run experimental installer spike");

    assert!(
        output.status.success(),
        "experimental lockfile replay should succeed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let envelope: serde_json::Value = serde_json::from_str(&stdout).unwrap_or_else(|e| {
        panic!("experimental install --json must emit valid JSON: {e}\n---\n{stdout}")
    });
    assert_eq!(envelope["success"], serde_json::json!(true));
    assert_eq!(
        envelope["experimental"],
        serde_json::json!("installer-spike")
    );
    assert_eq!(
        envelope["timing"]["experimental_installer_spike"]["graph_source"],
        serde_json::json!("lockfile")
    );
    assert!(
        project.file_exists("node_modules/ms/package.json"),
        "experimental lockfile replay must install package contents"
    );
}

#[tokio::test]
async fn install_experimental_spike_live_graph_requires_benchmark_ack() {
    let mock = MockRegistry::start().await;
    mount_ms_2_1_3(&mock).await;

    let project = TempProject::empty(
        r#"{"name":"spike-live-env-rejected","version":"1.0.0","dependencies":{"ms":"^2.1.3"}}"#,
    );

    let output = lpm_with_registry(&project, &mock.url())
        .env("LPM_STORE_VERSION", "v2")
        .env("LPM_EXPERIMENTAL_INSTALLER_SPIKE", "1")
        .env("LPM_INSTALLER_SPIKE_PARITY", "deny")
        .args([
            "install",
            "--json",
            "--timing",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("failed to run unsupported experimental installer spike");

    assert!(
        !output.status.success(),
        "unsupported experimental shape must fail instead of falling back to normal install\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{stdout}\n{stderr}");
    assert!(
        combined.contains("experimental installer spike is limited to benchmark installs")
            && combined.contains("set LPM_INSTALLER_SPIKE_BENCHMARK_ONLY=1")
            && !combined.contains("set LPM_INSTALLER_SPIKE_PARITY=deny")
            && !combined.contains("set LPM_INSTALLER_SPIKE_GRAPH=lockfile")
            && !combined.contains("use a frozen lockfile install"),
        "unsupported live experimental shape must report only the missing live benchmark gate; got:\n{combined}"
    );
    assert!(
        !project.file_exists("node_modules/ms/package.json"),
        "unsupported experimental shape must not silently perform a normal install"
    );
}

#[tokio::test]
async fn install_experimental_spike_live_graph_requires_parity_deny() {
    let mock = MockRegistry::start().await;
    mount_ms_2_1_3(&mock).await;

    let project = TempProject::empty(
        r#"{"name":"spike-live-parity-rejected","version":"1.0.0","dependencies":{"ms":"^2.1.3"}}"#,
    );

    let output = lpm_with_registry(&project, &mock.url())
        .env("LPM_STORE_VERSION", "v2")
        .env("LPM_EXPERIMENTAL_INSTALLER_SPIKE", "1")
        .env("LPM_INSTALLER_SPIKE_BENCHMARK_ONLY", "1")
        .args([
            "install",
            "--json",
            "--timing",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("failed to run unsupported experimental installer spike");

    assert!(
        !output.status.success(),
        "live experimental shape without parity deny must fail instead of benchmarking an unchecked graph\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{stdout}\n{stderr}");
    assert!(
        combined.contains("set LPM_INSTALLER_SPIKE_PARITY=deny for live graph parity"),
        "unsupported live experimental shape must report the missing parity gate; got:\n{combined}"
    );
    assert!(
        !project.file_exists("node_modules/ms/package.json"),
        "unsupported experimental shape must not silently perform a normal install"
    );
}

#[tokio::test]
async fn install_experimental_spike_lockfile_graph_requires_lockfile_gates() {
    let mock = MockRegistry::start().await;
    mount_ms_2_1_3(&mock).await;

    let project = TempProject::empty(
        r#"{"name":"spike-lockfile-env-rejected","version":"1.0.0","dependencies":{"ms":"^2.1.3"}}"#,
    );

    let output = lpm_with_registry(&project, &mock.url())
        .env("LPM_STORE_VERSION", "v2")
        .env("LPM_EXPERIMENTAL_INSTALLER_SPIKE", "1")
        .env("LPM_INSTALLER_SPIKE_GRAPH", "lockfile")
        .env("LPM_INSTALLER_SPIKE_PARITY", "deny")
        .args([
            "install",
            "--json",
            "--timing",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("failed to run unsupported experimental installer spike");

    assert!(
        !output.status.success(),
        "unsupported experimental lockfile shape must fail instead of falling back to normal install\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{stdout}\n{stderr}");
    assert!(
        combined.contains("experimental installer spike is limited to benchmark installs")
            && combined.contains("set LPM_INSTALLER_SPIKE_BENCHMARK_ONLY=1")
            && combined.contains("use lockfile parity or disable parity")
            && combined.contains("use a frozen lockfile install"),
        "unsupported lockfile experimental shape must report lockfile-specific gates; got:\n{combined}"
    );
    assert!(
        !project.file_exists("node_modules/ms/package.json"),
        "unsupported experimental shape must not silently perform a normal install"
    );
}

#[tokio::test]
async fn install_experimental_spike_live_graph_does_not_write_install_hash() {
    let mock = MockRegistry::start().await;
    mount_ms_2_1_3(&mock).await;

    let project = TempProject::empty(
        r#"{"name":"spike-live-no-install-hash","version":"1.0.0","dependencies":{"ms":"^2.1.3"}}"#,
    );

    let output = lpm_with_registry(&project, &mock.url())
        .env("LPM_STORE_VERSION", "v2")
        .env("LPM_EXPERIMENTAL_INSTALLER_SPIKE", "1")
        .env("LPM_INSTALLER_SPIKE_BENCHMARK_ONLY", "1")
        .env("LPM_INSTALLER_SPIKE_PARITY", "deny")
        .args([
            "install",
            "--json",
            "--timing",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("failed to run experimental installer spike");

    assert!(
        output.status.success(),
        "experimental live install should succeed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        project.file_exists("node_modules/ms/package.json"),
        "experimental live install must install package contents"
    );
    assert!(
        !project.file_exists(".lpm/install-hash"),
        "experimental benchmark-only install must not seed the normal freshness cache"
    );
}

#[tokio::test]
async fn install_experimental_spike_live_graph_applies_patched_dependencies() {
    let mock = MockRegistry::start().await;
    let tarball = make_tarball("ms", "2.1.3");
    let integrity = compute_integrity(&tarball);
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
                    "integrity": &integrity,
                },
                "dependencies": {}
            }
        },
        "time": { "2.1.3": "2025-01-01T00:00:00.000Z" }
    })])
    .await;

    let project = TempProject::empty(
        &serde_json::json!({
            "name": "spike-live-patched-dependency",
            "version": "1.0.0",
            "dependencies": {
                "ms": "2.1.3"
            },
            "lpm": {
                "patchedDependencies": {
                    "ms@2.1.3": {
                        "path": "patches/ms@2.1.3.patch",
                        "originalIntegrity": &integrity,
                    }
                }
            }
        })
        .to_string(),
    );
    project.write_file(
        "patches/ms@2.1.3.patch",
        "diff --git a/lpm-patch-proof.js b/lpm-patch-proof.js\n\
         new file mode 100644\n\
         --- /dev/null\n\
         +++ b/lpm-patch-proof.js\n\
         @@ -0,0 +1 @@\n\
         +module.exports = 'patched-by-spike-test';\n",
    );

    let output = lpm_with_registry(&project, &mock.url())
        .env("LPM_STORE_VERSION", "v2")
        .env("LPM_EXPERIMENTAL_INSTALLER_SPIKE", "1")
        .env("LPM_INSTALLER_SPIKE_BENCHMARK_ONLY", "1")
        .env("LPM_INSTALLER_SPIKE_GRAPH", "resolve-worklist")
        .env("LPM_INSTALLER_SPIKE_PARITY", "deny")
        .env("LPM_INSTALLER_SPIKE_EXACT_DOC", "1")
        .args([
            "install",
            "--json",
            "--timing",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("failed to run experimental installer spike");

    assert!(
        output.status.success(),
        "experimental live install with patched dependency should succeed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let envelope: serde_json::Value = serde_json::from_str(&stdout).unwrap_or_else(|e| {
        panic!("experimental install --json must emit valid JSON: {e}\n---\n{stdout}")
    });
    assert_eq!(
        envelope["experimental"],
        serde_json::json!("installer-spike")
    );
    assert_eq!(envelope["patches_count"], serde_json::json!(1));
    assert_eq!(
        envelope["timing"]["experimental_installer_spike"]["parity"]["matches"],
        serde_json::json!(true)
    );
    let applied = envelope["applied_patches"]
        .as_array()
        .unwrap_or_else(|| panic!("applied_patches must be an array; got {envelope:#}"));
    assert_eq!(applied.len(), 1);
    assert_eq!(applied[0]["name"], serde_json::json!("ms"));
    assert_eq!(applied[0]["files_added"], serde_json::json!(1));
    assert!(
        project.file_exists(".lpm/patch-state.json"),
        "patched spike install must persist patch-state.json"
    );

    let require_patch = std::process::Command::new("node")
        .current_dir(project.path())
        .arg("-e")
        .arg("process.stdout.write(require('ms/lpm-patch-proof'))")
        .output()
        .expect("run patched dependency require");
    assert!(
        require_patch.status.success(),
        "patched dependency require should succeed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&require_patch.stdout),
        String::from_utf8_lossy(&require_patch.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&require_patch.stdout),
        "patched-by-spike-test"
    );
}

#[tokio::test]
async fn install_experimental_spike_live_graph_preserves_platform_skipped_optional_descendants() {
    let mock = MockRegistry::start().await;
    mock.with_manifest_package(
        serde_json::json!({
            "name": "optional-platform-parent",
            "version": "1.0.0",
            "optionalDependencies": {
                "optional-wasm-child": "1.0.0"
            }
        }),
        &[],
    )
    .await;
    mock.with_manifest_package(
        serde_json::json!({
            "name": "optional-wasm-child",
            "version": "1.0.0",
            "cpu": ["wasm32"],
            "dependencies": {
                "optional-runtime": "1.0.0"
            }
        }),
        &[],
    )
    .await;
    mock.with_manifest_package(
        serde_json::json!({
            "name": "optional-runtime",
            "version": "1.0.0",
            "dependencies": {
                "tslib": "1.0.0"
            }
        }),
        &[],
    )
    .await;
    mock.with_manifest_package(
        serde_json::json!({
            "name": "tslib",
            "version": "1.0.0"
        }),
        &[],
    )
    .await;

    let project = TempProject::empty(
        r#"{
            "name": "spike-live-platform-skipped-optional-descendants",
            "version": "1.0.0",
            "dependencies": {
                "optional-platform-parent": "1.0.0"
            }
        }"#,
    );

    let output = lpm_with_registry(&project, &mock.url())
        .env("LPM_STORE_VERSION", "v2")
        .env("LPM_EXPERIMENTAL_INSTALLER_SPIKE", "1")
        .env("LPM_INSTALLER_SPIKE_BENCHMARK_ONLY", "1")
        .env("LPM_INSTALLER_SPIKE_PARITY", "deny")
        .args([
            "install",
            "--json",
            "--timing",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("failed to run experimental installer spike");

    assert!(
        output.status.success(),
        "experimental live install must preserve descendants of platform-skipped optional packages under parity deny\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let envelope: serde_json::Value = serde_json::from_str(&stdout).unwrap_or_else(|e| {
        panic!("experimental install --json must emit valid JSON: {e}\n---\n{stdout}")
    });
    let parity = &envelope["timing"]["experimental_installer_spike"]["parity"];
    assert_eq!(parity["matches"], serde_json::json!(true));
    assert_eq!(parity["candidate_count"], serde_json::json!(3));
    assert_eq!(parity["baseline_count"], serde_json::json!(3));

    let package_names: std::collections::HashSet<&str> = envelope["packages"]
        .as_array()
        .expect("packages must be an array")
        .iter()
        .filter_map(|package| package["name"].as_str())
        .collect();
    assert!(package_names.contains("optional-platform-parent"));
    assert!(package_names.contains("optional-runtime"));
    assert!(package_names.contains("tslib"));
    assert!(!package_names.contains("optional-wasm-child"));
}

#[tokio::test]
async fn install_experimental_spike_live_graph_accepts_overrides_with_parity_deny() {
    let mock = MockRegistry::start().await;
    mock.with_full_package_metadata(
        "lodash",
        "4.17.21",
        &[
            (
                "4.17.20",
                serde_json::json!({}),
                Some(make_tarball("lodash", "4.17.20")),
            ),
            (
                "4.17.21",
                serde_json::json!({}),
                Some(make_tarball("lodash", "4.17.21")),
            ),
        ],
    )
    .await;

    let project = TempProject::empty(
        r#"{
            "name": "spike-live-overrides",
            "version": "1.0.0",
            "dependencies": { "lodash": "^4.0.0" },
            "lpm": { "overrides": { "lodash": "4.17.20" } }
        }"#,
    );

    let output = lpm_with_registry(&project, &mock.url())
        .env("LPM_STORE_VERSION", "v2")
        .env("LPM_EXPERIMENTAL_INSTALLER_SPIKE", "1")
        .env("LPM_INSTALLER_SPIKE_BENCHMARK_ONLY", "1")
        .env("LPM_INSTALLER_SPIKE_PARITY", "deny")
        .args([
            "install",
            "--json",
            "--timing",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("failed to run experimental installer spike");

    assert!(
        output.status.success(),
        "experimental live install with overrides should succeed under parity deny\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let installed_package_json = project.read_file("node_modules/lodash/package.json");
    let installed_package: serde_json::Value = serde_json::from_str(&installed_package_json)
        .expect("installed lodash package.json must parse");
    assert_eq!(
        installed_package["version"],
        serde_json::json!("4.17.20"),
        "override must force the selected version instead of latest satisfying"
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let envelope: serde_json::Value = serde_json::from_str(&stdout).unwrap_or_else(|e| {
        panic!("experimental install --json must emit valid JSON: {e}\n---\n{stdout}")
    });
    let parity = &envelope["timing"]["experimental_installer_spike"]["parity"];
    assert_eq!(parity["enabled"], serde_json::json!(true));
    assert_eq!(parity["matches"], serde_json::json!(true));
    assert_eq!(parity["candidate_count"], serde_json::json!(1));
    assert_eq!(parity["baseline_count"], serde_json::json!(1));
}

#[tokio::test]
async fn install_experimental_spike_live_graph_links_file_source_with_transitive_registry_dep() {
    let mock = MockRegistry::start().await;
    mock.with_manifest_package(
        serde_json::json!({
            "name": "dep-fn",
            "version": "1.0.0",
            "main": "index.js"
        }),
        &[("index.js", b"module.exports = () => 'dep-ok';\n")],
    )
    .await;

    let project = TempProject::empty(
        r#"{
  "name": "spike-live-file-source",
  "version": "1.0.0",
  "dependencies": {
    "local-pkg": "file:./packages/local-pkg"
  }
}"#,
    );
    project.write_file(
        "packages/local-pkg/package.json",
        r#"{
  "name": "local-pkg",
  "version": "0.1.0",
  "main": "index.js",
  "dependencies": {
    "dep-fn": "1.0.0"
  }
}"#,
    );
    project.write_file(
        "packages/local-pkg/index.js",
        "module.exports = require('dep-fn')();\n",
    );

    let output = lpm_with_registry(&project, &mock.url())
        .env("LPM_STORE_VERSION", "v2")
        .env("LPM_EXPERIMENTAL_INSTALLER_SPIKE", "1")
        .env("LPM_INSTALLER_SPIKE_BENCHMARK_ONLY", "1")
        .env("LPM_INSTALLER_SPIKE_PARITY", "deny")
        .args([
            "install",
            "--json",
            "--timing",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("failed to run experimental installer spike");

    assert!(
        output.status.success(),
        "experimental live install with file: source should succeed under parity deny\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let envelope: serde_json::Value = serde_json::from_str(&stdout).unwrap_or_else(|e| {
        panic!("experimental install --json must emit valid JSON: {e}\n---\n{stdout}")
    });
    let parity = &envelope["timing"]["experimental_installer_spike"]["parity"];
    assert_eq!(parity["matches"], serde_json::json!(true));
    assert_eq!(parity["candidate_count"], serde_json::json!(2));
    assert_eq!(parity["baseline_count"], serde_json::json!(2));

    let require_local = std::process::Command::new("node")
        .current_dir(project.path())
        .arg("-e")
        .arg("process.stdout.write(String(require('local-pkg')))")
        .output()
        .expect("run local source require");
    assert!(
        require_local.status.success(),
        "local source require should resolve its registry transitive\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&require_local.stdout),
        String::from_utf8_lossy(&require_local.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&require_local.stdout), "dep-ok");
}

#[tokio::test]
async fn install_experimental_spike_live_graph_links_workspace_member_source_without_persisting_lockfile()
 {
    let project = TempProject::empty(
        r#"{
  "name": "spike-live-workspace-source",
  "version": "1.0.0",
  "private": true,
  "workspaces": ["packages/*"],
  "dependencies": {
    "ws-member-a": "workspace:*"
  }
}"#,
    );
    project.write_file(
        "packages/ws-member-a/package.json",
        r#"{"name":"ws-member-a","version":"1.2.3","main":"index.js"}"#,
    );
    project.write_file(
        "packages/ws-member-a/index.js",
        "module.exports = 'workspace-ok';\n",
    );

    let output = lpm(&project)
        .env("LPM_STORE_VERSION", "v2")
        .env("LPM_EXPERIMENTAL_INSTALLER_SPIKE", "1")
        .env("LPM_INSTALLER_SPIKE_BENCHMARK_ONLY", "1")
        .env("LPM_INSTALLER_SPIKE_PARITY", "deny")
        .args([
            "install",
            "--no-recursive",
            "--json",
            "--timing",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("failed to run experimental installer spike");

    assert!(
        output.status.success(),
        "experimental live install with workspace:* source should succeed under parity deny\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let envelope: serde_json::Value = serde_json::from_str(&stdout).unwrap_or_else(|e| {
        panic!("experimental install --json must emit valid JSON: {e}\n---\n{stdout}")
    });
    let parity = &envelope["timing"]["experimental_installer_spike"]["parity"];
    assert_eq!(parity["matches"], serde_json::json!(true));
    assert_eq!(parity["candidate_count"], serde_json::json!(1));
    assert_eq!(parity["baseline_count"], serde_json::json!(1));
    assert!(
        !project.file_exists("lpm.lock"),
        "experimental benchmark-only install must not persist a workspace lockfile"
    );

    let require_member = std::process::Command::new("node")
        .current_dir(project.path())
        .arg("-e")
        .arg("process.stdout.write(require('ws-member-a'))")
        .output()
        .expect("run workspace member require");
    assert!(
        require_member.status.success(),
        "workspace member require should succeed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&require_member.stdout),
        String::from_utf8_lossy(&require_member.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&require_member.stdout),
        "workspace-ok"
    );
}

#[tokio::test]
async fn install_experimental_spike_live_graph_rejects_frozen_lockfile_invocation() {
    let mock = MockRegistry::start().await;
    mount_ms_2_1_3(&mock).await;

    let project = TempProject::empty(
        r#"{"name":"spike-live-frozen-rejected","version":"1.0.0","dependencies":{"ms":"^2.1.3"}}"#,
    );

    let lockfile_output = lpm_with_registry(&project, &mock.url())
        .env("LPM_STORE_VERSION", "v2")
        .args([
            "install",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("failed to seed lockfile before frozen experimental rejection");
    assert!(
        lockfile_output.status.success(),
        "lockfile seed install should succeed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&lockfile_output.stdout),
        String::from_utf8_lossy(&lockfile_output.stderr)
    );
    assertions::assert_lockfile_exists(project.path());
    std::fs::remove_dir_all(project.path().join("node_modules"))
        .expect("remove node_modules before frozen live graph rejection");

    let output = lpm_with_registry(&project, &mock.url())
        .env("LPM_STORE_VERSION", "v2")
        .env("LPM_EXPERIMENTAL_INSTALLER_SPIKE", "1")
        .env("LPM_INSTALLER_SPIKE_BENCHMARK_ONLY", "1")
        .env("LPM_INSTALLER_SPIKE_PARITY", "deny")
        .args([
            "install",
            "--json",
            "--frozen-lockfile",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("failed to run unsupported experimental installer spike");

    assert!(
        !output.status.success(),
        "frozen live experimental shape must fail instead of fresh-resolving\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{stdout}\n{stderr}");
    assert!(
        combined.contains("set LPM_INSTALLER_SPIKE_GRAPH=lockfile for frozen installs"),
        "unsupported frozen live experimental shape must report the graph mismatch; got:\n{combined}"
    );
    assert!(
        !project.file_exists("node_modules/ms/package.json"),
        "unsupported experimental shape must not silently perform a normal install"
    );
}

#[tokio::test]
async fn install_json_timing_detail_trace_exposes_slow_package_buckets() {
    let mock = MockRegistry::start().await;
    mount_ms_2_1_3(&mock).await;

    let project = TempProject::empty(
        r#"{"name":"timing-trace-install","version":"1.0.0","dependencies":{"ms":"^2.1.3"}}"#,
    );
    project.write_file(".npmrc", &format!("registry={}\n", mock.url()));
    let output = lpm_with_registry(&project, &mock.url())
        .env("LPM_TIMING_DETAIL", "trace")
        .args([
            "install",
            "--json",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("failed to run lpm install --json");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "install --json failed:\nstdout: {stdout}\nstderr: {stderr}"
    );
    let envelope: serde_json::Value =
        serde_json::from_str(&stdout).expect("install --json must emit parseable JSON");
    let slow_packages = &envelope["timing"]["detail"]["trace"]["slow_packages"];
    assert!(
        slow_packages.is_object(),
        "LPM_TIMING_DETAIL=trace must emit slow package buckets; got {envelope:#}"
    );
    for bucket in [
        "tarball_http",
        "extract",
        "security",
        "finalize",
        "link_v2_one",
        "provenance_verify",
    ] {
        assert!(
            slow_packages[bucket].is_array(),
            "slow package bucket {bucket} must be an array; got {slow_packages:#}"
        );
    }
    let fetch_tasks = &slow_packages["fetch_tasks"];
    assert!(
        fetch_tasks.is_object(),
        "slow package trace must include fetch task attribution buckets; got {slow_packages:#}"
    );
    for bucket in ["by_total", "by_extract", "by_security", "by_finalize"] {
        assert!(
            fetch_tasks[bucket].is_array(),
            "fetch task bucket {bucket} must be an array; got {fetch_tasks:#}"
        );
    }
    if let Some(row) = fetch_tasks["by_total"]
        .as_array()
        .and_then(|rows| rows.first())
    {
        for field in [
            "package",
            "task_total_ms",
            "queue_wait_ms",
            "url_lookup_ms",
            "download_ms",
            "integrity_ms",
            "extract_ms",
            "security_ms",
            "source_scan_ns",
            "finalize_permit_wait_ms",
            "finalize_ms",
            "finalize_tree_integrity_ms",
            "finalize_integrity_write_ms",
            "finalize_rename_ms",
            "finalize_collision_recovery_ms",
            "file_count",
            "dir_count",
            "symlink_count",
            "unpacked_bytes",
        ] {
            assert!(
                row.get(field).is_some(),
                "fetch task trace row must include {field}; got {row:#}"
            );
        }
    }
    let source_scan = &envelope["timing"]["fetch_breakdown"]["source_scan"];
    for field in ["sum_ns", "max_ns"] {
        assert!(
            source_scan[field].as_u64().is_some(),
            "timing.fetch_breakdown.source_scan.{field} must be numeric; got {source_scan:#}"
        );
    }
    let metadata = envelope["timing"]["detail"]["metadata"]
        .as_array()
        .unwrap_or_else(|| panic!("detail.metadata must be an array; got {envelope:#}"));
    assert!(
        metadata
            .iter()
            .all(|entry| entry["top_duplicate_packages"].is_array()),
        "LPM_TIMING_DETAIL=trace must emit duplicate metadata package buckets; got {metadata:#?}"
    );
    let metadata_fetch = &envelope["timing"]["detail"]["resolve"]["metadata_fetch"];
    assert!(
        metadata_fetch.is_object(),
        "LPM_TIMING_DETAIL=trace must emit per-package metadata fetch attribution; got {envelope:#}"
    );
    assert_eq!(
        metadata_fetch["scope"], "per_package_metadata_fetches",
        "metadata_fetch scope must make batch exclusion explicit; got {metadata_fetch:#}"
    );
    assert_eq!(
        metadata_fetch["batch_fetches_included"], false,
        "metadata_fetch must make batch exclusion explicit; got {metadata_fetch:#}"
    );
    assert!(
        metadata_fetch["calls"]
            .as_u64()
            .is_some_and(|calls| calls > 0),
        "metadata_fetch.calls must count traced metadata fetches; got {metadata_fetch:#}"
    );
    assert!(
        ["npm_direct", "lpm_worker", "custom", "lpm"]
            .iter()
            .any(|route| metadata_fetch["routes"][route]
                .as_u64()
                .is_some_and(|calls| calls > 0)),
        "metadata_fetch.routes must count at least one traced metadata fetch route; got {metadata_fetch:#}"
    );
    let by_total = metadata_fetch["top_slow_packages"]["by_total"]
        .as_array()
        .unwrap_or_else(|| {
            panic!(
                "metadata_fetch.top_slow_packages.by_total must be an array; got {metadata_fetch:#}"
            )
        });
    if let Some(row) = by_total.first() {
        for field in [
            "package",
            "route",
            "total_ms",
            "raw_fetch_ms",
            "http_ms",
            "body_read_ms",
            "json_decode_ms",
            "cache_info_parse_ms",
            "body_bytes",
            "version_count",
        ] {
            assert!(
                row.get(field).is_some(),
                "metadata fetch trace row must include {field}; got {row:#}"
            );
        }
    }
    let resolver_substages = &envelope["timing"]["detail"]["resolve"]["substages"];
    assert_eq!(resolver_substages["scope"], "resolver_pass");
    assert_eq!(resolver_substages["work_is_cumulative"], true);
    insta::assert_json_snapshot!("install_json_timing_resolver_substages", resolver_substages, {
        ".tree_policy_ms" => "[DURATION]",
        ".policy_hydration_ms" => "[DURATION]",
        ".manifest_wait_ms" => "[DURATION]",
        ".edge_expansion_ms" => "[DURATION]",
        ".graph_finalization_ms" => "[DURATION]",
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
                    "integrity": compute_integrity(&tarball),
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
                    "integrity": compute_integrity(&tarball),
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
            "--timing",
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

    let http_versions = &json["timing"]["resolve"]["metadata_http_versions"];
    assert!(
        http_versions.is_object(),
        "timing.resolve.metadata_http_versions must be an object; got: {http_versions:?}"
    );
    let mut metadata_response_count = 0u64;
    for field in [
        "http_09", "http_10", "http_11", "http_2", "http_3", "unknown",
    ] {
        let count = http_versions[field].as_u64().unwrap_or_else(|| {
            panic!(
                "timing.resolve.metadata_http_versions.{field} must be a number; object was: {http_versions:?}"
            )
        });
        metadata_response_count += count;
    }
    assert!(
        metadata_response_count >= 1,
        "fresh install must count at least one package-metadata HTTP response; \
         object was: {http_versions:?}"
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
    // above cover the CLI-surface gap without being sensitive to orchestration
    // timing.
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

    assertions::assert_lockfile_exists(project.path());

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

    // Second install with --json should show up_to_date and still honor
    // env-gated setup-only timing detail on the true fast-exit path.
    let output = lpm_with_registry(&project, &mock.url())
        .env("LPM_TIMING_DETAIL", "trace")
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
    assert_eq!(json["schema_version"], serde_json::json!(2));
    assert_eq!(json["success"], true);
    assert_eq!(json["up_to_date"], true);
    assertions::assert_json_field(&json, "duration_ms", assertions::JsonType::Number);
    assert!(
        json["timing"]["waterfall"].is_object(),
        "up-to-date --json must still emit timing.waterfall; got {json:#}"
    );
    assert_eq!(
        json["timing"]["waterfall"]["total_ms"], json["timing"]["total_ms"],
        "fast-path waterfall total must match timing.total_ms"
    );
    assert!(
        json["timing"]["detail"]["setup"].is_object(),
        "up-to-date detail must include setup timing; got {json:#}"
    );
    assert!(
        json["timing"]["detail"]["trace"]["slow_packages"].is_object(),
        "trace mode must include empty slow-package buckets on the fast path; got {json:#}"
    );
}

#[tokio::test]
async fn install_fast_lane_json_omits_timing_by_default() {
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
                    "integrity": compute_integrity(&tarball),
                },
                "dependencies": {}
            }
        },
        "time": { "2.1.3": "2025-01-01T00:00:00.000Z" }
    });
    mock.with_batch_metadata(vec![batch_meta]).await;

    let project = TempProject::empty(
        r#"{
        "name": "fast-lane-json-lean-test",
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

    let output = lpm_with_registry(&project, &mock.url())
        .args(["install", "--json"])
        .output()
        .expect("failed to run fast-lane install --json");
    assert!(
        output.status.success(),
        "fast-lane install --json failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let json = assertions::parse_json_output(&output.stdout);
    assert_eq!(json["schema_version"], serde_json::json!(2));
    assert_eq!(json["success"], serde_json::json!(true));
    assert_eq!(json["up_to_date"], serde_json::json!(true));
    assertions::assert_json_field(&json, "duration_ms", assertions::JsonType::Number);
    assert!(
        json.get("timing").is_none(),
        "fast-lane install --json must omit timing by default; got {json:#}"
    );
}

#[tokio::test]
async fn warm_install_with_direct_bin_dep_is_up_to_date() {
    let mock = MockRegistry::start().await;
    let tarball = make_tarball_from_pkg_json(
        serde_json::json!({
            "name": "tool",
            "version": "1.0.0",
            "bin": { "tool": "bin/tool.js" },
            "dependencies": { "helper": "1.0.0" }
        }),
        &[("bin/tool.js", b"#!/usr/bin/env node\n")],
    );
    mock.with_package("tool", "1.0.0", &tarball).await;
    mock.with_manifest_package(
        serde_json::json!({
            "name": "helper",
            "version": "1.0.0",
            "main": "index.js"
        }),
        &[("index.js", b"module.exports = 'helper';\n")],
    )
    .await;
    let batch_meta = serde_json::json!({
        "name": "tool",
        "dist-tags": { "latest": "1.0.0" },
        "versions": {
            "1.0.0": {
                "name": "tool",
                "version": "1.0.0",
                "bin": { "tool": "bin/tool.js" },
                "dist": {
                    "tarball": format!("{}/tarballs/tool/-/tool-1.0.0.tgz", mock.url()),
                    "integrity": "sha512-placeholder",
                },
                "dependencies": { "helper": "1.0.0" }
            }
        },
        "time": { "1.0.0": "2025-01-01T00:00:00.000Z" }
    });
    mock.with_batch_metadata(vec![batch_meta]).await;

    let project = TempProject::empty(
        r#"{
        "name": "warm-bin-fast-exit",
        "version": "1.0.0",
        "dependencies": { "tool": "^1.0.0" }
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

    let output = lpm_with_registry(&project, &mock.url())
        .args([
            "install",
            "--json",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("failed to run warm install --json");
    assert!(output.status.success());
    let json = assertions::parse_json_output(&output.stdout);
    assert_eq!(
        json["up_to_date"], true,
        "a warm install with a direct bin dep must fast-exit; got {json:#}"
    );
    assert!(
        project
            .path()
            .join("node_modules")
            .join(".bin")
            .join("tool")
            .exists(),
        "tool's bin shim must exist after a plain install"
    );
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

    assertions::assert_lockfile_exists(project.path());

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
async fn install_offline_firewall_monitor_relinks_and_reports_offline_skip_json() {
    let project = warm_public_npm_lockfile_project_for_offline_firewall("monitor").await;

    let output = lpm_with_registry(&project, "http://127.0.0.1:1")
        .env("LPM_NPM_ROUTE", "direct")
        .args([
            "install",
            "--offline",
            "--json",
            "--timing",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("failed to run offline install with firewall monitor");

    assert!(
        output.status.success(),
        "monitor-mode firewall must not block offline lockfile replay\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let envelope = assertions::parse_json_output(&output.stdout);
    assert_eq!(envelope["offline"], serde_json::json!(true));
    assert_eq!(envelope["timing"]["firewall"]["mode"], "monitor");
    assert_eq!(
        envelope["timing"]["firewall"]["lookup_mode"],
        "package_only"
    );
    assert_eq!(envelope["timing"]["firewall"]["checked_count"], 1);
    assert_eq!(envelope["timing"]["firewall"]["offline_skipped"], true);
    assert_eq!(envelope["security"]["firewall"]["mode"], "monitor");
    assertions::assert_in_node_modules(project.path(), "ms");
}

#[tokio::test]
async fn install_package_shows_firewall_active_badge_when_public_npm_verdicts_are_checked() {
    let mock = MockRegistry::start().await;
    let tarball = make_tarball("firewall-install", "1.0.0");
    mock.with_package("firewall-install", "1.0.0", &tarball)
        .await;
    mock.with_npm_firewall_block("firewall-install", "1.0.0")
        .await;

    let project = TempProject::empty(
        r#"{
        "name": "firewall-install-badge",
        "version": "1.0.0"
    }"#,
    );
    write_npm_firewall_global_config(&project, "monitor");

    let output = lpm_with_registry(&project, &mock.url())
        .args([
            "install",
            "firewall-install@1.0.0",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("failed to run install with firewall monitor");

    assert!(
        output.status.success(),
        "monitor-mode firewall install must continue\nstdout: {}\nstderr: {}",
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
        "firewall-active install must show the badge; got:\n{combined}"
    );
}

#[tokio::test]
async fn install_package_omits_firewall_badge_when_firewall_is_off() {
    let mock = MockRegistry::start().await;
    let tarball = make_tarball("plain-install", "1.0.0");
    mock.with_package("plain-install", "1.0.0", &tarball).await;

    let project = TempProject::empty(
        r#"{
        "name": "plain-install-badge",
        "version": "1.0.0"
    }"#,
    );

    let output = lpm_with_registry(&project, &mock.url())
        .args([
            "install",
            "plain-install@1.0.0",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("failed to run install with firewall off");

    assert!(
        output.status.success(),
        "firewall-off install must succeed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("Installing 1 package"),
        "install must still show the normal install phase; got:\n{combined}"
    );
    assert!(
        !combined.contains("LPM Firewall active"),
        "firewall-off install must not show the firewall badge; got:\n{combined}"
    );
}

#[tokio::test]
async fn install_offline_firewall_enforce_fails_closed_before_linking() {
    let project = warm_public_npm_lockfile_project_for_offline_firewall("enforce").await;

    let output = lpm_with_registry(&project, "http://127.0.0.1:1")
        .env("LPM_NPM_ROUTE", "direct")
        .args([
            "install",
            "--offline",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("failed to run offline install with firewall enforce");

    assert!(
        !output.status.success(),
        "enforce-mode firewall must fail closed offline\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("npm firewall verdict preflight requires network access"),
        "offline enforce failure must explain the firewall network requirement; got:\n{combined}"
    );
    assert!(
        !project.path().join("node_modules").exists(),
        "offline enforce must fail before recreating node_modules"
    );
}

#[tokio::test]
async fn install_offline_firewall_enforce_uses_public_lockfile_source_when_npmrc_drifts() {
    let project = warm_public_npm_lockfile_project_for_offline_firewall("enforce").await;
    project.write_file(".npmrc", "registry=https://npm.internal.example.com/\n");

    let output = lpm_with_registry(&project, "http://127.0.0.1:1")
        .args([
            "install",
            "--offline",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("failed to run offline install with drifted npmrc");

    assert!(
        !output.status.success(),
        "offline enforce must still check public lockfile source when .npmrc drifts\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("npm firewall verdict preflight requires network access"),
        "offline enforce failure must come from firewall preflight; got:\n{combined}"
    );
    assert!(
        !project.path().join("node_modules").exists(),
        "offline enforce must fail before recreating node_modules"
    );
}

#[tokio::test]
async fn install_offline_with_default_v2_store_relinks_from_object_store() {
    let mock = MockRegistry::start().await;
    let tarball = make_tarball("is-number", "7.0.0");
    mock.with_package("is-number", "7.0.0", &tarball).await;

    let project = TempProject::empty(
        r#"{
        "name": "offline-v2-store",
        "version": "1.0.0",
        "dependencies": {
            "is-number": "7.0.0"
        }
    }"#,
    );

    let online = lpm_with_registry(&project, &mock.url())
        .env_remove("LPM_STORE_VERSION")
        .args([
            "install",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("failed to run online v2 install");
    assert!(
        online.status.success(),
        "online v2 install failed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&online.stdout),
        String::from_utf8_lossy(&online.stderr)
    );

    let nm = project.path().join("node_modules");
    if nm.exists() {
        std::fs::remove_dir_all(&nm).unwrap();
    }

    let offline = lpm_with_registry(&project, "http://127.0.0.1:1")
        .env_remove("LPM_STORE_VERSION")
        .args([
            "install",
            "--offline",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("failed to run offline v2 install");

    assert!(
        offline.status.success(),
        "offline v2 install must reuse the default object store\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&offline.stdout),
        String::from_utf8_lossy(&offline.stderr)
    );
    assertions::assert_in_node_modules(project.path(), "is-number");
    assert!(
        project.home().join(".lpm/store/v2").is_dir(),
        "default online and offline installs must populate the v2 store"
    );
    assert!(
        !project.home().join(".lpm/store/v1").exists(),
        "default online and offline installs must not write the v1 store"
    );
    assert!(
        !project.home().join(".lpm/store/v3").exists(),
        "default online and offline installs must not activate the experimental v3 store"
    );
}

#[tokio::test]
async fn install_explicit_v3_lazily_migrates_v2_object_offline_without_rewriting_lockfiles() {
    let mock = MockRegistry::start().await;
    let tarball = make_tarball("is-number", "7.0.0");
    mock.with_package("is-number", "7.0.0", &tarball).await;
    let project = TempProject::empty(
        r#"{
        "name": "offline-v2-to-v3-migration",
        "version": "1.0.0",
        "dependencies": {
            "is-number": "7.0.0"
        }
    }"#,
    );

    let seeded = lpm_with_registry(&project, &mock.url())
        .env("LPM_STORE_VERSION", "v2")
        .args([
            "install",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("failed to seed the v2 store");
    assert!(
        seeded.status.success(),
        "v2 seed install failed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&seeded.stdout),
        String::from_utf8_lossy(&seeded.stderr)
    );

    let sri = compute_integrity(&tarball);
    let v2_store = lpm_store::v2::Store::at(project.home().join(".lpm/store/v2"));
    let v2_object = v2_store.paths().object_dir(&sri).unwrap();
    let v2_bytes = std::fs::read(v2_object.join("index.js")).expect("read seeded v2 object");
    let lock_before = std::fs::read(project.path().join("lpm.lock")).expect("read lpm.lock");
    let lockb_before = std::fs::read(project.path().join("lpm.lockb")).ok();
    let requests_before = mock.tarball_request_count("is-number", "7.0.0").await;
    assert_eq!(requests_before, 1, "v2 seed must download one tarball");

    let migrated = lpm_with_registry(&project, "http://127.0.0.1:1")
        .env("LPM_STORE_VERSION", "v3")
        .args([
            "install",
            "--offline",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("run offline v2-to-v3 migration");
    assert!(
        migrated.status.success(),
        "explicit v3 install must migrate the v2 object without network access\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&migrated.stdout),
        String::from_utf8_lossy(&migrated.stderr)
    );

    let v3_store = lpm_store::v2::Store::at(project.home().join(".lpm/store/v3"));
    let v3_object = v3_store.paths().object_dir(&sri).unwrap();
    assert_eq!(
        std::fs::read(v3_object.join("index.js")).expect("read migrated v3 object"),
        v2_bytes,
        "lazy migration must preserve extracted package bytes"
    );
    assert_eq!(
        std::fs::read(v2_object.join("index.js")).expect("read retained v2 object"),
        v2_bytes,
        "lazy migration must not mutate the v2 store"
    );
    assert_eq!(
        mock.tarball_request_count("is-number", "7.0.0").await,
        requests_before,
        "lazy migration must not redownload the tarball"
    );
    assert_eq!(
        std::fs::read(project.path().join("lpm.lock")).expect("read migrated lpm.lock"),
        lock_before,
        "v2-to-v3 migration must keep lpm.lock byte-identical"
    );
    assert_eq!(
        std::fs::read(project.path().join("lpm.lockb")).ok(),
        lockb_before,
        "v2-to-v3 migration must keep a supported lpm.lockb byte-identical and preserve absence when importer metadata requires TOML"
    );
    assertions::assert_in_node_modules(project.path(), "is-number");
}

#[tokio::test]
async fn install_default_v2_lazily_migrates_v3_object_offline_without_rewriting_lockfiles() {
    let mock = MockRegistry::start().await;
    let tarball = make_tarball("is-number", "7.0.0");
    mock.with_package("is-number", "7.0.0", &tarball).await;
    let project = TempProject::empty(
        r#"{
        "name": "offline-v3-to-v2-migration",
        "version": "1.0.0",
        "dependencies": {
            "is-number": "7.0.0"
        }
    }"#,
    );

    let seeded = lpm_with_registry(&project, &mock.url())
        .env("LPM_STORE_VERSION", "v3")
        .args([
            "install",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("failed to seed the v3 store");
    assert!(
        seeded.status.success(),
        "v3 seed install failed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&seeded.stdout),
        String::from_utf8_lossy(&seeded.stderr)
    );

    let sri = compute_integrity(&tarball);
    let v3_store = lpm_store::v2::Store::at(project.home().join(".lpm/store/v3"));
    let v3_object = v3_store.paths().object_dir(&sri).unwrap();
    let v3_bytes = std::fs::read(v3_object.join("index.js")).expect("read seeded v3 object");
    let lock_before = std::fs::read(project.path().join("lpm.lock")).expect("read lpm.lock");
    let lockb_before = std::fs::read(project.path().join("lpm.lockb")).ok();
    let requests_before = mock.tarball_request_count("is-number", "7.0.0").await;
    assert_eq!(requests_before, 1, "v3 seed must download one tarball");

    let migrated = lpm_with_registry(&project, "http://127.0.0.1:1")
        .env_remove("LPM_STORE_VERSION")
        .args([
            "install",
            "--offline",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("run offline v3-to-v2 migration");
    assert!(
        migrated.status.success(),
        "default v2 install must migrate the v3 object without network access\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&migrated.stdout),
        String::from_utf8_lossy(&migrated.stderr)
    );

    let v2_store = lpm_store::v2::Store::at(project.home().join(".lpm/store/v2"));
    let v2_object = v2_store.paths().object_dir(&sri).unwrap();
    assert_eq!(
        std::fs::read(v2_object.join("index.js")).expect("read migrated v2 object"),
        v3_bytes,
        "rollback migration must preserve extracted package bytes"
    );
    assert_eq!(
        std::fs::read(v3_object.join("index.js")).expect("read retained v3 object"),
        v3_bytes,
        "rollback migration must not mutate the v3 store"
    );
    assert_eq!(
        mock.tarball_request_count("is-number", "7.0.0").await,
        requests_before,
        "rollback migration must not redownload the tarball"
    );
    assert_eq!(
        std::fs::read(project.path().join("lpm.lock")).expect("read migrated lpm.lock"),
        lock_before,
        "v3-to-v2 migration must keep lpm.lock byte-identical"
    );
    assert_eq!(
        std::fs::read(project.path().join("lpm.lockb")).ok(),
        lockb_before,
        "v3-to-v2 migration must keep a supported lpm.lockb byte-identical and preserve absence when importer metadata requires TOML"
    );
    assertions::assert_in_node_modules(project.path(), "is-number");
}

#[tokio::test]
async fn store_verify_deep_detects_same_size_v3_blob_tampering() {
    let mock = MockRegistry::start().await;
    let clean_bytes = b"same-size-clean";
    let tarball =
        make_tarball_with_files("cas-deep-verify", "1.0.0", &[("payload.bin", clean_bytes)]);
    mock.with_package("cas-deep-verify", "1.0.0", &tarball)
        .await;
    let project = TempProject::empty(
        r#"{
        "name": "cas-deep-verify-project",
        "version": "1.0.0",
        "dependencies": {
            "cas-deep-verify": "1.0.0"
        }
    }"#,
    );

    let installed = lpm_with_registry(&project, &mock.url())
        .env("LPM_STORE_VERSION", "v3")
        .args([
            "install",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("install v3 deep-verification fixture");
    assert!(
        installed.status.success(),
        "v3 fixture install failed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&installed.stdout),
        String::from_utf8_lossy(&installed.stderr)
    );

    let blob = find_v3_blob_with_contents(&project, clean_bytes);
    std::fs::write(&blob, b"same-size-dirty").expect("tamper v3 CAS blob");
    let verified = lpm(&project)
        .args(["--json", "store", "verify", "--deep"])
        .output()
        .expect("run deep store verification");
    assert!(
        !verified.status.success(),
        "deep verification must reject same-size CAS tampering\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&verified.stdout),
        String::from_utf8_lossy(&verified.stderr)
    );
    let envelope: serde_json::Value =
        serde_json::from_slice(&verified.stdout).expect("deep verification failure must emit JSON");
    assert_eq!(envelope["success"], serde_json::json!(false));
    assert_eq!(
        envelope["cas"]["blob_integrity_recomputed"],
        serde_json::json!(true)
    );
    assert!(
        envelope["issues"]
            .as_array()
            .expect("issues must be an array")
            .iter()
            .filter_map(serde_json::Value::as_str)
            .any(|issue| issue.contains("v3 CAS") && issue.contains("failed integrity validation")),
        "deep verification must identify the corrupt CAS blob: {envelope}"
    );
}

#[tokio::test]
async fn cache_prune_keeps_shared_v3_blob_until_its_last_package_reference_is_removed() {
    let mock = MockRegistry::start().await;
    let shared_bytes = b"shared-cas-payload";
    let first_tarball =
        make_tarball_with_files("cas-first", "1.0.0", &[("shared.bin", shared_bytes)]);
    let second_tarball =
        make_tarball_with_files("cas-second", "1.0.0", &[("shared.bin", shared_bytes)]);
    mock.with_package("cas-first", "1.0.0", &first_tarball)
        .await;
    mock.with_package("cas-second", "1.0.0", &second_tarball)
        .await;
    let project = TempProject::empty(
        r#"{
        "name": "cas-last-reference-project",
        "version": "1.0.0",
        "dependencies": {
            "cas-first": "1.0.0",
            "cas-second": "1.0.0"
        }
    }"#,
    );

    let initial = lpm_with_registry(&project, &mock.url())
        .env("LPM_STORE_VERSION", "v3")
        .args([
            "install",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("install shared CAS fixture");
    assert!(
        initial.status.success(),
        "shared CAS fixture install failed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&initial.stdout),
        String::from_utf8_lossy(&initial.stderr)
    );
    let shared_blob = find_v3_blob_with_contents(&project, shared_bytes);

    project.write_file(
        "package.json",
        r#"{
        "name": "cas-last-reference-project",
        "version": "1.0.0",
        "dependencies": {
            "cas-second": "1.0.0"
        }
    }"#,
    );
    std::fs::remove_dir_all(project.path().join("node_modules"))
        .expect("remove prior links before relinking one package");
    let one_reference = lpm_with_registry(&project, &mock.url())
        .env("LPM_STORE_VERSION", "v3")
        .args([
            "install",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("remove the first package reference");
    assert!(
        one_reference.status.success(),
        "install after removing first reference failed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&one_reference.stdout),
        String::from_utf8_lossy(&one_reference.stderr)
    );
    let first_prune = lpm(&project)
        .args([
            "cache",
            "prune",
            "--apply",
            "--project",
            project.path().to_str().expect("project path must be UTF-8"),
            "--json",
        ])
        .output()
        .expect("prune after removing first reference");
    assert!(
        first_prune.status.success(),
        "first-reference prune failed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&first_prune.stdout),
        String::from_utf8_lossy(&first_prune.stderr)
    );
    assert!(
        shared_blob.is_file(),
        "a blob shared by a reachable package must survive prune"
    );

    project.write_file(
        "package.json",
        r#"{
        "name": "cas-last-reference-project",
        "version": "1.0.0",
        "dependencies": {}
    }"#,
    );
    std::fs::remove_dir_all(project.path().join("node_modules"))
        .expect("remove prior links before relinking an empty project");
    let no_references = lpm_with_registry(&project, &mock.url())
        .env("LPM_STORE_VERSION", "v3")
        .args([
            "install",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("remove the last package reference");
    assert!(
        no_references.status.success(),
        "install after removing last reference failed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&no_references.stdout),
        String::from_utf8_lossy(&no_references.stderr)
    );
    let last_prune = lpm(&project)
        .args([
            "cache",
            "prune",
            "--apply",
            "--project",
            project.path().to_str().expect("project path must be UTF-8"),
            "--json",
        ])
        .output()
        .expect("prune after removing last reference");
    assert!(
        last_prune.status.success(),
        "last-reference prune failed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&last_prune.stdout),
        String::from_utf8_lossy(&last_prune.stderr)
    );
    assert!(
        !shared_blob.exists(),
        "the shared blob must be deleted after its last package reference is removed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&last_prune.stdout),
        String::from_utf8_lossy(&last_prune.stderr)
    );
}

#[tokio::test]
async fn install_reenable_source_analysis_backfills_v2_cache_without_tarball_redownload() {
    let mock = MockRegistry::start().await;
    let tarball = make_tarball_with_files(
        "source-analysis-backfill",
        "1.0.0",
        &[("behavior.js", b"eval('source-analysis-backfill')")],
    );
    mock.with_package("source-analysis-backfill", "1.0.0", &tarball)
        .await;
    let project = TempProject::empty(
        r#"{
        "name": "source-analysis-backfill-project",
        "version": "1.0.0",
        "dependencies": {
            "source-analysis-backfill": "1.0.0"
        }
    }"#,
    );
    let config_path = project.home().join(".lpm/config.toml");
    std::fs::create_dir_all(config_path.parent().unwrap()).unwrap();
    std::fs::write(&config_path, "install-time-source-analysis = false\n").unwrap();
    write_signed_unlock(&project, &["source-analysis-disable"]);

    let disabled = lpm_with_registry(&project, &mock.url())
        .env("LPM_STORE_VERSION", "v2")
        .args([
            "install",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("failed to install with source analysis disabled");
    assert!(
        disabled.status.success(),
        "disabled source-analysis install failed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&disabled.stdout),
        String::from_utf8_lossy(&disabled.stderr)
    );

    let sri = compute_integrity(&tarball);
    let v2_store = lpm_store::v2::Store::at_with_policies(
        project.home().join(".lpm/store/v2"),
        lpm_store::v2::ObjectIntegrityPolicy::Source,
        lpm_store::SecurityAnalysisPolicy::Disabled,
    );
    let object_dir = v2_store.paths().object_dir(&sri).unwrap();
    assert!(
        !object_dir.join(".lpm-security.json").exists(),
        "disabled install must not create an analysis cache"
    );
    let initial_tarball_requests = mock
        .tarball_request_count("source-analysis-backfill", "1.0.0")
        .await;
    assert_eq!(initial_tarball_requests, 1);

    std::fs::write(&config_path, "install-time-source-analysis = true\n").unwrap();
    let enabled = lpm_with_registry(&project, &mock.url())
        .env("LPM_STORE_VERSION", "v2")
        .args([
            "install",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("failed to reinstall after enabling source analysis");
    assert!(
        enabled.status.success(),
        "re-enabled source-analysis install failed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&enabled.stdout),
        String::from_utf8_lossy(&enabled.stderr)
    );
    assert_eq!(
        mock.tarball_request_count("source-analysis-backfill", "1.0.0")
            .await,
        initial_tarball_requests,
        "re-enabling source analysis must reuse extracted bytes"
    );
    let analysis = lpm_security::behavioral::read_cached_analysis(&object_dir)
        .expect("re-enabled install must backfill a current cache");
    assert_eq!(analysis.version, lpm_security::behavioral::SCHEMA_VERSION);
    assert!(analysis.source.eval);
}

#[tokio::test]
async fn install_disabled_lpm_insights_skips_enrichment_request_but_keeps_local_findings() {
    let mock = MockRegistry::start().await;
    let tarball = make_tarball_with_files(
        "@lpm.dev/local-findings",
        "1.0.0",
        &[("behavior.js", b"eval('local-finding')")],
    );
    mock.with_package("@lpm.dev/local-findings", "1.0.0", &tarball)
        .await;
    let project = TempProject::empty(
        r#"{
        "name": "disabled-lpm-insights-project",
        "version": "1.0.0",
        "dependencies": {
            "@lpm.dev/local-findings": "1.0.0"
        }
    }"#,
    );
    let config_path = project.home().join(".lpm/config.toml");
    std::fs::create_dir_all(config_path.parent().unwrap()).unwrap();
    std::fs::write(&config_path, "fetch-lpm-security-insights = false\n").unwrap();

    let output = lpm_with_registry(&project, &mock.url())
        .env("LPM_STORE_VERSION", "v2")
        .args(["install", "--no-skills", "--no-editor-setup"])
        .output()
        .expect("failed to install with LPM insights disabled");
    assert!(
        output.status.success(),
        "install with LPM insights disabled failed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("eval()"),
        "local behavioral findings must remain in the install summary; stderr:\n{stderr}"
    );

    let batch_requests = mock
        .server()
        .received_requests()
        .await
        .expect("wiremock request log must be available")
        .into_iter()
        .filter(|request| request.url.path() == "/api/registry/batch-metadata")
        .count();
    assert_eq!(
        batch_requests, 1,
        "disabled LPM insights must leave only the resolver batch request"
    );
}

#[tokio::test]
async fn install_v2_tree_integrity_cache_hit_repairs_tampered_object_before_linking() {
    let mock = MockRegistry::start().await;
    let tarball = make_tarball("is-number", "7.0.0");
    mock.with_package("is-number", "7.0.0", &tarball).await;

    let project = TempProject::empty(
        r#"{
        "name": "v2-cache-integrity",
        "version": "1.0.0",
        "dependencies": {
            "is-number": "7.0.0"
        }
    }"#,
    );

    let first = lpm_with_registry(&project, &mock.url())
        .env("LPM_STORE_VERSION", "v2")
        .env("LPM_V2_OBJECT_INTEGRITY", "tree")
        .args([
            "install",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("failed to run first v2 install");
    assert!(
        first.status.success(),
        "first v2 install failed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&first.stdout),
        String::from_utf8_lossy(&first.stderr)
    );

    let sri = compute_integrity(&tarball);
    let v2_store = lpm_store::v2::Store::at(project.home().join(".lpm/store/v2"));
    let object_dir = v2_store.paths().object_dir(&sri).unwrap();
    let index_js = object_dir.join("index.js");
    assert!(
        index_js.is_file(),
        "warm v2 object should contain package index.js at {}",
        index_js.display()
    );
    std::fs::write(&index_js, b"module.exports = 'tampered';").unwrap();

    let nm = project.path().join("node_modules");
    if nm.exists() {
        std::fs::remove_dir_all(&nm).unwrap();
    }

    let second = lpm_with_registry(&project, &mock.url())
        .env("LPM_STORE_VERSION", "v2")
        .env("LPM_V2_OBJECT_INTEGRITY", "tree")
        .args([
            "install",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("failed to run second v2 install");
    assert!(
        second.status.success(),
        "second v2 install must refetch and repair a tampered object\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&second.stdout),
        String::from_utf8_lossy(&second.stderr)
    );

    assert_eq!(std::fs::read(&index_js).unwrap(), b"module.exports = {};");
    assert_eq!(
        std::fs::read(project.path().join("node_modules/is-number/index.js")).unwrap(),
        b"module.exports = {};"
    );
}

#[tokio::test]
async fn install_source_policy_migrates_legacy_tree_link_entry_without_stale_warning() {
    let mock = MockRegistry::start().await;
    let tarball = make_tarball("is-number", "7.0.0");
    mock.with_package("is-number", "7.0.0", &tarball).await;

    let project = TempProject::empty(
        r#"{
        "name": "v2-link-warning-migration",
        "version": "1.0.0",
        "dependencies": {
            "is-number": "7.0.0"
        }
    }"#,
    );

    let legacy = lpm_with_registry(&project, &mock.url())
        .env("LPM_STORE_VERSION", "v2")
        .env("LPM_V2_OBJECT_INTEGRITY", "tree")
        .args([
            "install",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("failed to seed legacy tree-mode v2 install");
    assert!(
        legacy.status.success(),
        "legacy tree-mode v2 install failed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&legacy.stdout),
        String::from_utf8_lossy(&legacy.stderr)
    );
    let sri = compute_integrity(&tarball);
    let v2_store = lpm_store::v2::Store::at_with_object_integrity_policy(
        project.home().join(".lpm/store/v2"),
        lpm_store::v2::ObjectIntegrityPolicy::Tree,
    );
    assert!(
        v2_store.reusable_object(&sri).unwrap().is_some(),
        "seeded tree-mode object must be reusable before source-policy migration"
    );

    let nm = project.path().join("node_modules");
    if nm.exists() {
        std::fs::remove_dir_all(&nm).unwrap();
    }

    let migrated = lpm_with_registry(&project, &mock.url())
        .env("LPM_STORE_VERSION", "v2")
        .env("LPM_V2_OBJECT_INTEGRITY", "source")
        .args([
            "install",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("failed to migrate legacy tree-mode v2 link entry");
    let stdout = String::from_utf8_lossy(&migrated.stdout);
    let stderr = String::from_utf8_lossy(&migrated.stderr);
    assert!(
        migrated.status.success(),
        "source-mode v2 install should migrate the legacy link entry\nstdout: {stdout}\nstderr: {stderr}"
    );
    for warning in [
        "v2 store: treating object as unusable",
        "v2 store: removing incomplete or unverifiable object",
        "v2 store: incomplete or stale link entry",
    ] {
        assert!(
            !stderr.contains(warning),
            "legacy migration must stay out of user-facing v2 store warnings\nmatched: {warning}\nstdout: {stdout}\nstderr: {stderr}"
        );
    }
    assertions::assert_in_node_modules(project.path(), "is-number");
}

#[tokio::test]
async fn install_tree_policy_migrates_snapshotful_source_object_without_refetch_or_stale_warning() {
    let mock = MockRegistry::start().await;
    let tarball = make_tarball("is-number", "7.0.0");
    mock.with_package("is-number", "7.0.0", &tarball).await;

    let project = TempProject::empty(
        r#"{
        "name": "v2-source-to-tree-migration",
        "version": "1.0.0",
        "dependencies": {
            "is-number": "7.0.0"
        }
    }"#,
    );

    let source = lpm_with_registry(&project, &mock.url())
        .env("LPM_STORE_VERSION", "v2")
        .env("LPM_V2_OBJECT_INTEGRITY", "source")
        .args([
            "install",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("failed to seed source-mode v2 install");
    assert!(
        source.status.success(),
        "source-mode v2 install failed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&source.stdout),
        String::from_utf8_lossy(&source.stderr)
    );
    let seed_tarball_requests = mock.tarball_request_count("is-number", "7.0.0").await;
    assert_eq!(
        seed_tarball_requests, 1,
        "source-mode seed should download the package exactly once"
    );
    let sri = compute_integrity(&tarball);
    let v2_store = lpm_store::v2::Store::at_with_object_integrity_policy(
        project.home().join(".lpm/store/v2"),
        lpm_store::v2::ObjectIntegrityPolicy::Source,
    );
    let object_dir = v2_store.paths().object_dir(&sri).unwrap();
    let object_snapshot = object_dir.join(".lpm-tree-snapshot.json");
    assert!(
        v2_store.reusable_object(&sri).unwrap().is_some(),
        "seeded source-mode object must be reusable before tree-policy migration"
    );
    assert!(
        object_snapshot.is_file(),
        "source-mode objects must carry a tree baseline for later tree-policy migration"
    );

    let nm = project.path().join("node_modules");
    if nm.exists() {
        std::fs::remove_dir_all(&nm).unwrap();
    }

    let migrated = lpm_with_registry(&project, &mock.url())
        .env("LPM_STORE_VERSION", "v2")
        .env("LPM_V2_OBJECT_INTEGRITY", "tree")
        .args([
            "install",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("failed to migrate source-mode v2 link entry");
    let stdout = String::from_utf8_lossy(&migrated.stdout);
    let stderr = String::from_utf8_lossy(&migrated.stderr);
    assert!(
        migrated.status.success(),
        "tree-mode v2 install should migrate the source link entry\nstdout: {stdout}\nstderr: {stderr}"
    );
    assert_eq!(
        mock.tarball_request_count("is-number", "7.0.0").await,
        seed_tarball_requests,
        "snapshotful source-to-tree migration must reuse the existing object without refetching"
    );
    for warning in [
        "v2 store: treating object as unusable",
        "v2 store: removing incomplete or unverifiable object",
        "v2 store: incomplete or stale link entry",
    ] {
        assert!(
            !stderr.contains(warning),
            "source-to-tree migration must stay out of user-facing v2 store warnings\nmatched: {warning}\nstdout: {stdout}\nstderr: {stderr}"
        );
    }
    assertions::assert_in_node_modules(project.path(), "is-number");
}

#[tokio::test]
async fn install_tree_policy_refetches_snapshotless_source_object_without_stale_warning() {
    let mock = MockRegistry::start().await;
    let tarball = make_tarball("is-number", "7.0.0");
    mock.with_package("is-number", "7.0.0", &tarball).await;

    let project = TempProject::empty(
        r#"{
        "name": "v2-snapshotless-source-to-tree-migration",
        "version": "1.0.0",
        "dependencies": {
            "is-number": "7.0.0"
        }
    }"#,
    );

    let source = lpm_with_registry(&project, &mock.url())
        .env("LPM_STORE_VERSION", "v2")
        .env("LPM_V2_OBJECT_INTEGRITY", "source")
        .args([
            "install",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("failed to seed source-mode v2 install");
    assert!(
        source.status.success(),
        "source-mode v2 install failed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&source.stdout),
        String::from_utf8_lossy(&source.stderr)
    );
    let seed_tarball_requests = mock.tarball_request_count("is-number", "7.0.0").await;
    assert_eq!(
        seed_tarball_requests, 1,
        "source-mode seed should download the package exactly once"
    );
    let sri = compute_integrity(&tarball);
    let v2_store = lpm_store::v2::Store::at_with_object_integrity_policy(
        project.home().join(".lpm/store/v2"),
        lpm_store::v2::ObjectIntegrityPolicy::Source,
    );
    let object_dir = v2_store.paths().object_dir(&sri).unwrap();
    let object_snapshot = object_dir.join(".lpm-tree-snapshot.json");
    std::fs::remove_file(&object_snapshot).unwrap();
    assert!(
        v2_store.reusable_object(&sri).unwrap().is_some(),
        "seeded snapshotless source-mode object must still satisfy source policy"
    );
    assert!(
        !object_snapshot.exists(),
        "test setup must simulate the legacy snapshotless source-object shape"
    );

    let nm = project.path().join("node_modules");
    if nm.exists() {
        std::fs::remove_dir_all(&nm).unwrap();
    }

    let migrated = lpm_with_registry(&project, &mock.url())
        .env("LPM_STORE_VERSION", "v2")
        .env("LPM_V2_OBJECT_INTEGRITY", "tree")
        .args([
            "install",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("failed to repair snapshotless source-mode v2 object");
    let stdout = String::from_utf8_lossy(&migrated.stdout);
    let stderr = String::from_utf8_lossy(&migrated.stderr);
    assert!(
        migrated.status.success(),
        "tree-mode v2 install should repair the snapshotless source object\nstdout: {stdout}\nstderr: {stderr}"
    );
    assert_eq!(
        mock.tarball_request_count("is-number", "7.0.0").await,
        seed_tarball_requests + 1,
        "snapshotless source objects need fresh tarball bytes before tree-policy reuse"
    );
    for warning in [
        "v2 store: treating object as unusable",
        "v2 store: removing incomplete or unverifiable object",
        "v2 store: incomplete or stale link entry",
    ] {
        assert!(
            !stderr.contains(warning),
            "snapshotless source repair must stay out of user-facing v2 store warnings\nmatched: {warning}\nstdout: {stdout}\nstderr: {stderr}"
        );
    }
    assertions::assert_in_node_modules(project.path(), "is-number");
    assert!(
        object_snapshot.is_file(),
        "fresh repair must restore the tree snapshot baseline"
    );
}

#[tokio::test]
async fn install_without_harness_overrides_uses_shipped_v2_layout() {
    let mock = MockRegistry::start().await;
    let tarball = make_tarball("is-number", "7.0.0");
    mock.with_package("is-number", "7.0.0", &tarball).await;

    let project = TempProject::empty(
        r#"{
        "name": "default-v2-layout",
        "version": "1.0.0",
        "dependencies": {
            "is-number": "7.0.0"
        }
    }"#,
    );

    let output = lpm_with_registry(&project, &mock.url())
        .env_remove("LPM_STORE_VERSION")
        .env_remove("LPM_NPM_ROUTE")
        .args([
            "install",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("failed to run install with shipped defaults");

    assert!(
        output.status.success(),
        "default install should succeed with the shipped v2 layout\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let package_path = project.path().join("node_modules/is-number");
    assertions::assert_in_node_modules(project.path(), "is-number");
    let metadata = std::fs::symlink_metadata(&package_path)
        .expect("installed package should have filesystem metadata");
    assert!(
        metadata.file_type().is_symlink(),
        "shipped default layout should expose root packages as virtual-store symlinks, not v1 real dirs"
    );
    assert!(
        !project.path().join(".lpm/wrappers").exists(),
        "shipped v2 layout should not create project-local v1 wrappers"
    );
    assert!(
        !project.path().join(".lpm/hoisted").exists(),
        "shipped v2 layout should not create project-local v1 hoisted state"
    );
    assert!(
        !project.home().join(".lpm/store/v1").exists(),
        "shipped v2 layout should not populate the v1 store"
    );
    assert!(
        project.home().join(".lpm/store/v2").is_dir(),
        "shipped v2 layout should populate the v2 store"
    );
    assert!(
        !project.home().join(".lpm/store/v3").exists(),
        "shipped v2 layout should not populate the experimental v3 store"
    );
}

#[tokio::test]
async fn install_with_explicit_v1_uses_v1_store_and_isolated_linker() {
    let mock = MockRegistry::start().await;
    let tarball = make_tarball("is-number", "7.0.0");
    mock.with_package("is-number", "7.0.0", &tarball).await;

    let project = TempProject::empty(
        r#"{
        "name": "explicit-v1-layout",
        "version": "1.0.0",
        "dependencies": {
            "is-number": "7.0.0"
        }
    }"#,
    );

    let output = lpm_v1_with_registry(&project, &mock.url())
        .args([
            "install",
            "--linker",
            "isolated",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("failed to run explicit v1 install");

    assert!(
        output.status.success(),
        "explicit v1 install should succeed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        project
            .home()
            .join(".lpm/store/v1/is-number@7.0.0/package.json")
            .is_file(),
        "explicit v1 install must populate the v1 package store"
    );
    assert!(
        project
            .path()
            .join(".lpm/wrappers/is-number@7.0.0/node_modules/is-number/package.json")
            .is_file(),
        "explicit v1 isolated install must populate the matching wrapper layout"
    );
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

#[tokio::test]
async fn bare_add_persists_finalized_manifest_in_lockfile_and_stays_up_to_date() {
    let mock = MockRegistry::start().await;
    mount_ms_2_1_3(&mock).await;
    let project = TempProject::empty(
        r#"{
  "name": "bare-add-lockfile-reconciliation",
  "version": "1.0.0",
  "dependencies": {}
}"#,
    );

    let add = lpm_with_registry(&project, &mock.url())
        .args([
            "install",
            "ms",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("run bare package add");
    assert!(
        add.status.success(),
        "bare package add should succeed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&add.stdout),
        String::from_utf8_lossy(&add.stderr),
    );

    let manifest_dependencies = read_dependencies(&project);
    assert_eq!(
        manifest_dependencies
            .get("ms")
            .and_then(|value| value.as_str()),
        Some("^2.1.3"),
        "bare add should finalize the saved dependency range",
    );

    let lockfile =
        lpm_lockfile::Lockfile::read_from_file(&project.path().join(lpm_lockfile::LOCKFILE_NAME))
            .expect("read lockfile after bare add");
    let importer = lockfile
        .importers
        .get(".")
        .expect("bare add should persist the root importer");
    assert_eq!(
        importer.dependencies.get("ms").map(String::as_str),
        Some("^2.1.3"),
        "lockfile importer must match the finalized package.json before add commits",
    );
    let lockfile_before = project.read_file(lpm_lockfile::LOCKFILE_NAME);

    let reinstall = lpm_with_registry(&project, &mock.url())
        .args([
            "install",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("run immediate install after bare add");
    assert!(
        reinstall.status.success(),
        "immediate install should succeed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&reinstall.stdout),
        String::from_utf8_lossy(&reinstall.stderr),
    );
    let combined = format!(
        "{}\n{}",
        String::from_utf8_lossy(&reinstall.stdout),
        String::from_utf8_lossy(&reinstall.stderr),
    );
    assert!(
        combined.to_lowercase().contains("up to date"),
        "the finalized add state should hit the freshness fast path:\n{combined}",
    );
    assert!(
        !combined.contains("Upgraded lpm.lockb"),
        "an importer reconciliation must never be reported as a binary format upgrade:\n{combined}",
    );
    assert_eq!(
        project.read_file(lpm_lockfile::LOCKFILE_NAME),
        lockfile_before,
        "an immediate install must not rewrite an already-current lockfile",
    );
}

#[tokio::test]
async fn npm_only_install_reports_cached_behavioral_security_findings() {
    let mock = MockRegistry::start().await;
    let tarball = make_tarball_with_files(
        "local-security-finding",
        "1.0.0",
        &[(
            "danger.js",
            b"module.exports = eval(process.env.LPM_INPUT);\n",
        )],
    );
    mock.with_package("local-security-finding", "1.0.0", &tarball)
        .await;
    let project = TempProject::empty(
        r#"{
  "name": "npm-only-security-summary",
  "version": "1.0.0",
  "lpm": {
    "strictDeps": "loose"
  },
  "dependencies": {
    "local-security-finding": "1.0.0"
  }
}"#,
    );

    let output = lpm_with_registry(&project, &mock.url())
        .args(["install", "--no-skills", "--no-editor-setup"])
        .output()
        .expect("run npm-only install with a behavioral finding");
    assert!(
        output.status.success(),
        "npm-only install should succeed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let combined = format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    assert!(
        combined.contains("Security summary") && combined.to_lowercase().contains("eval"),
        "local cached analysis must be summarized without an @lpm.dev dependency:\n{combined}",
    );
}

async fn mount_registry_version(
    mock: &MockRegistry,
    name: &str,
    version: &str,
    dependencies: serde_json::Value,
) -> serde_json::Value {
    let tarball = make_tarball_from_pkg_json(
        serde_json::json!({
            "name": name,
            "version": version,
            "dependencies": dependencies,
        }),
        &[],
    );
    let integrity = compute_integrity(&tarball);
    mock.with_package_and_deps(name, version, &tarball, dependencies.clone())
        .await;
    serde_json::json!({
        "name": name,
        "version": version,
        "dist": {
            "tarball": format!("{}/tarballs/{name}/-/{name}-{version}.tgz", mock.url()),
            "integrity": integrity,
        },
        "dependencies": dependencies,
    })
}

fn packument(name: &str, latest: &str, versions: Vec<serde_json::Value>) -> serde_json::Value {
    let mut versions_map = serde_json::Map::new();
    let mut time_map = serde_json::Map::new();
    for version in versions {
        let version_str = version["version"]
            .as_str()
            .expect("packument versions must have a version string")
            .to_string();
        versions_map.insert(version_str.clone(), version);
        time_map.insert(version_str, serde_json::json!("2025-01-01T00:00:00.000Z"));
    }
    serde_json::json!({
        "name": name,
        "dist-tags": { "latest": latest },
        "versions": versions_map,
        "time": time_map,
    })
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

#[tokio::test]
async fn install_add_with_transitive_same_name_keeps_only_the_new_direct_version() {
    let mock = MockRegistry::start().await;

    let kit_v1 = mount_registry_version(
        &mock,
        "kit",
        "1.0.0",
        serde_json::json!({ "chalk": "4.1.2" }),
    )
    .await;
    let chalk_v4 = make_tarball_from_pkg_json(
        serde_json::json!({
            "name": "chalk",
            "version": "4.1.2",
            "dependencies": {},
        }),
        &[],
    );
    let chalk_v5 = make_tarball_from_pkg_json(
        serde_json::json!({
            "name": "chalk",
            "version": "5.0.0",
            "dependencies": {},
        }),
        &[],
    );
    mock.with_full_package_metadata(
        "chalk",
        "5.0.0",
        &[
            ("4.1.2", serde_json::json!({}), Some(chalk_v4)),
            ("5.0.0", serde_json::json!({}), Some(chalk_v5)),
        ],
    )
    .await;

    mock.with_batch_metadata(vec![packument("kit", "1.0.0", vec![kit_v1])])
        .await;

    let project = TempProject::empty(
        r#"{
        "name": "direct-vs-transitive-name-collision",
        "version": "1.0.0",
        "dependencies": {
            "kit": "^1.0.0"
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

    let output = lpm_with_registry(&project, &mock.url())
        .args([
            "install",
            "chalk",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("failed to run lpm install add-path for direct/transitive name collision");

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "install add-path must succeed:\nstdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        !stderr.contains("appears as a direct dep more than once"),
        "install must not misclassify the transitive chalk as a second direct dep:\n{stderr}"
    );
    assert!(
        stderr.matches("+ chalk@").count() == 1,
        "added-list must contain exactly one chalk entry:\n{stderr}"
    );
    assert!(
        stderr.contains("+ chalk@5.0.0"),
        "added-list must keep the newly added direct chalk version:\n{stderr}"
    );
    assert!(
        !stderr.contains("+ chalk@4.1.2"),
        "added-list must not surface the transitive chalk version as direct:\n{stderr}"
    );
    let manifest: serde_json::Value =
        serde_json::from_str(&project.read_file("package.json")).expect("package.json parses");
    assert_eq!(
        manifest["dependencies"]["chalk"],
        serde_json::json!("^5.0.0"),
        "bare direct add must save the newly requested latest version, not the existing transitive version"
    );
}

#[tokio::test]
async fn uninstall_then_reinstall_same_packages_reports_only_readded_direct_deps() {
    let mock = MockRegistry::start().await;

    let alpha_v1 = mount_registry_version(&mock, "alpha", "1.0.0", serde_json::json!({})).await;
    let beta_v1 = mount_registry_version(&mock, "beta", "1.0.0", serde_json::json!({})).await;
    let gamma_v1 = mount_registry_version(&mock, "gamma", "1.0.0", serde_json::json!({})).await;

    mock.with_batch_metadata(vec![
        packument("alpha", "1.0.0", vec![alpha_v1]),
        packument("beta", "1.0.0", vec![beta_v1]),
        packument("gamma", "1.0.0", vec![gamma_v1]),
    ])
    .await;

    let project = TempProject::empty(
        r#"{
        "name": "reinstall-only-removed-direct-deps",
        "version": "1.0.0",
        "dependencies": {
            "alpha": "^1.0.0",
            "beta": "^1.0.0",
            "gamma": "^1.0.0"
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

    let uninstall = lpm(&project)
        .args(["uninstall", "alpha", "beta"])
        .output()
        .expect("failed to run lpm uninstall for round-trip regression test");
    assert!(
        uninstall.status.success(),
        "uninstall must succeed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&uninstall.stdout),
        String::from_utf8_lossy(&uninstall.stderr)
    );
    assert!(
        project.file_exists("lpm.lock"),
        "uninstall must preserve lpm.lock so a follow-up add can diff against the prior install"
    );

    let reinstall = lpm_with_registry(&project, &mock.url())
        .args([
            "install",
            "alpha",
            "beta",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("failed to re-add previously removed deps");

    let stderr = String::from_utf8_lossy(&reinstall.stderr);
    let stdout = String::from_utf8_lossy(&reinstall.stdout);
    assert!(
        reinstall.status.success(),
        "reinstall must succeed:\nstdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        stderr.contains("› Installing 2 packages"),
        "reinstall phase must report only the requested packages:\n{stderr}"
    );
    assert!(
        stderr.contains("+ alpha@1.0.0") && stderr.contains("+ beta@1.0.0"),
        "reinstall must surface only the re-added direct deps:\n{stderr}"
    );
    assert!(
        !stderr.contains("+ gamma@1.0.0"),
        "reinstall must not report unchanged direct deps as added:\n{stderr}"
    );
    assert!(
        stderr.contains("✓ Done · added 2 packages in "),
        "reinstall completion line must report only the requested packages:\n{stderr}"
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

/// When the user runs `lpm install ms --filter app` from inside
/// `packages/app/` of a workspace,
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

#[tokio::test]
async fn install_filtered_strict_catalog_mismatch_fails_before_member_side_effects() {
    let mock = MockRegistry::start().await;
    mock.with_full_package_metadata(
        "is-positive",
        "1.0.0",
        &[
            (
                "1.0.0",
                serde_json::json!({}),
                Some(make_tarball("is-positive", "1.0.0")),
            ),
            (
                "2.0.0",
                serde_json::json!({}),
                Some(make_tarball("is-positive", "2.0.0")),
            ),
        ],
    )
    .await;

    let project = TempProject::empty(
        r#"{
        "name": "catalog-filter-workspace",
        "version": "1.0.0",
        "private": true,
        "lpm": {
            "catalogMode": "strict"
        }
    }"#,
    );
    project.write_file(
        "pnpm-workspace.yaml",
        r#"packages:
  - "packages/*"
catalog:
  is-positive: ^1.0.0
"#,
    );
    project.write_file(
        "packages/app/package.json",
        r#"{
        "name": "app",
        "version": "1.0.0"
    }"#,
    );

    let output = lpm_with_registry(&project, &mock.url())
        .args([
            "install",
            "is-positive@2.0.0",
            "--filter",
            "app",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("failed to run filtered install with strict catalog mismatch");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !output.status.success(),
        "filtered strict catalog mismatch must fail:\nstdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        stderr.contains("catalogMode strict")
            && stderr.contains("is-positive@2.0.0")
            && stderr.contains("catalog:^1.0.0"),
        "filtered strict mismatch error must name the requested and catalog specs:\nstdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        !stderr.contains("Installing 1 package") && !stderr.contains("+ is-positive@2.0.0"),
        "filtered strict catalog mismatch must fail before install progress output:\nstdout: {stdout}\nstderr: {stderr}"
    );

    let app_pkg: serde_json::Value =
        serde_json::from_str(&project.read_file("packages/app/package.json")).unwrap();
    assert!(
        app_pkg
            .get("dependencies")
            .and_then(|deps| deps.get("is-positive"))
            .is_none(),
        "failed filtered strict install must roll back the targeted member manifest: {app_pkg}"
    );
    assert!(
        !project.file_exists("packages/app/lpm.lock")
            && !project.file_exists("packages/app/lpm.lockb"),
        "filtered strict catalog mismatch must not leave member lockfiles behind"
    );
    assert!(
        !project.file_exists("packages/app/node_modules")
            && !project.file_exists("packages/app/node_modules/is-positive"),
        "filtered strict catalog mismatch must not materialize member node_modules"
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

// **Direct-version regression coverage lives in unit tests.**
//
// `collect_resolved_versions_from_lockfile` had a defensive-correctness issue:
// a flat name-scan over `lockfile.packages` would pick the wrong version if
// the lockfile ever contained two entries for the same package name (one direct,
// one transitive at a different version).
//
// We attempted a workflow test that staged `legacy-pkg → ms@~1.5.0` as a
// transitive and then ran `lpm install ms` to add a new direct edge — but
// LPM's pubgrub resolver fundamentally MERGES range constraints per
// package name. Bare `lpm install ms` stages a `*` placeholder, pubgrub
// intersects `*` with the existing transitive `~1.5.0`, and resolves to a
// SINGLE version. The lockfile never grows a duplicate via this path.
//
// The fix is therefore a defensive correctness change with no reachable
// workflow-level reproduction in the current resolver. The
// regression coverage is the unit test
// `commands::install::tests::collect_direct_versions_*` in install.rs,
// which calls the helper directly with hand-built `Vec<InstallPackage>`
// fixtures that include both a direct and a transitive entry for the
// same name.

/// When an `lpm install` against an already-installed project fails
/// partway through, the rollback MUST
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
                    "integrity": compute_integrity(&tarball),
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
                    "integrity": compute_integrity(&tarball),
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

    let bin_entry = project_bin_path(&project, "my-cli");
    assert!(
        bin_entry.exists(),
        "{} not found after installing binary package",
        bin_entry.display()
    );
}

#[tokio::test]
async fn install_v2_bin_shim_resolves_project_context_from_transitive_runtime() {
    let mock = MockRegistry::start().await;

    mock.with_manifest_package(
        serde_json::json!({
            "name": "framework-cli",
            "version": "1.0.0",
            "bin": { "framework-cli": "bin/framework-cli.js" },
            "dependencies": {
                "framework-plugin": "1.0.0"
            }
        }),
        &[(
            "bin/framework-cli.js",
            br#"#!/usr/bin/env node
require('framework-plugin').run();
"#,
        )],
    )
    .await;
    mock.with_manifest_package(
        serde_json::json!({
            "name": "framework-plugin",
            "version": "1.0.0",
            "main": "index.js",
            "dependencies": {
                "framework-runtime": "1.0.0",
                "runtime-helper": "1.0.0"
            }
        }),
        &[(
            "index.js",
            br#"exports.run = () => require('framework-runtime').run();
"#,
        )],
    )
    .await;
    mock.with_manifest_package(
        serde_json::json!({
            "name": "framework-runtime",
            "version": "1.0.0",
            "main": "index.js"
        }),
        &[(
            "index.js",
            br#"exports.run = () => console.log(require('runtime-helper').message);
"#,
        )],
    )
    .await;
    mock.with_manifest_package(
        serde_json::json!({
            "name": "runtime-helper",
            "version": "1.0.0",
            "main": "index.js"
        }),
        &[(
            "index.js",
            br#"exports.message = 'v2-compat-ok';
"#,
        )],
    )
    .await;

    let project = TempProject::empty(
        r#"{
  "name": "v2-bin-context",
  "version": "1.0.0",
  "dependencies": {
    "framework-cli": "1.0.0",
    "framework-plugin": "1.0.0",
    "runtime-helper": "1.0.0"
  }
}"#,
    );

    let install = lpm_with_registry(&project, &mock.url())
        .env("LPM_STORE_VERSION", "v2")
        .args([
            "install",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("failed to run v2 install for bin compatibility layout");
    assert!(
        install.status.success(),
        "v2 install should succeed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&install.stdout),
        String::from_utf8_lossy(&install.stderr),
    );

    let bin_path = project_bin_path(&project, "framework-cli");
    let output = std::process::Command::new(&bin_path)
        .output()
        .unwrap_or_else(|e| panic!("failed to execute {}: {e}", bin_path.display()));

    assert!(
        output.status.success(),
        "directly executing v2 project bin must resolve project context from a transitive runtime\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        "v2-compat-ok"
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

#[tokio::test]
async fn install_v2_links_same_name_version_edges_to_their_declared_sources() {
    let mock = MockRegistry::start().await;
    mock.with_manifest_package(
        serde_json::json!({
            "name": "react",
            "version": "19.0.0",
            "main": "index.js"
        }),
        &[("index.js", b"module.exports = 'registry-react';\n")],
    )
    .await;

    let project = TempProject::empty(
        r#"{
  "name": "source-identity-v2",
  "version": "1.0.0",
  "dependencies": {
    "react": "19.0.0",
    "consumer": "file:./packages/consumer"
  }
}"#,
    );
    project.write_file(
        "packages/react-fork/package.json",
        r#"{
  "name": "react",
  "version": "19.0.0",
  "main": "index.js"
}"#,
    );
    project.write_file(
        "packages/react-fork/index.js",
        "module.exports = 'local-react';\n",
    );
    let react_fork_path = project.path().join("packages/react-fork");
    let consumer_pkg = serde_json::json!({
        "name": "consumer",
        "version": "1.0.0",
        "main": "index.js",
        "dependencies": {
            "react": format!("file:{}", react_fork_path.display())
        }
    });
    project.write_file(
        "packages/consumer/package.json",
        &serde_json::to_string_pretty(&consumer_pkg).unwrap(),
    );
    project.write_file(
        "packages/consumer/index.js",
        "module.exports = require('react');\n",
    );

    let output = lpm_with_registry(&project, &mock.url())
        .env("LPM_STORE_VERSION", "v2")
        .args([
            "install",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("failed to run source identity v2 install");

    assert!(
        output.status.success(),
        "v2 install must allow registry and file: react@19.0.0 in one graph\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let root_react = std::process::Command::new("node")
        .current_dir(project.path())
        .arg("-e")
        .arg("process.stdout.write(require('react'))")
        .output()
        .expect("run root react require");
    assert!(
        root_react.status.success(),
        "root react require failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&root_react.stdout),
        String::from_utf8_lossy(&root_react.stderr),
    );
    assert_eq!(
        String::from_utf8_lossy(&root_react.stdout),
        "registry-react",
        "root dependency must resolve to the registry react package",
    );

    let consumer_realpath =
        std::fs::canonicalize(project.path().join("node_modules").join("consumer"))
            .expect("consumer symlink should resolve");
    let consumer_sibling_react = consumer_realpath
        .parent()
        .expect("consumer package should have parent node_modules dir")
        .join("react")
        .join("index.js");
    assert_eq!(
        std::fs::read_to_string(&consumer_sibling_react)
            .expect("consumer link entry should contain a react sibling"),
        "module.exports = 'local-react';\n",
        "consumer link entry's react sibling must point at the file: react package",
    );

    let nested_react = std::process::Command::new("node")
        .current_dir(project.path())
        .arg("-e")
        .arg("process.stdout.write(require('consumer'))")
        .output()
        .expect("run consumer require");
    assert!(
        nested_react.status.success(),
        "consumer require failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&nested_react.stdout),
        String::from_utf8_lossy(&nested_react.stderr),
    );
    assert_eq!(
        String::from_utf8_lossy(&nested_react.stdout),
        "local-react",
        "consumer's react edge must resolve to its file: react package",
    );
}

#[tokio::test]
async fn warm_v2_lockfile_peer_install_resolves_peer_after_relink() {
    let mock = MockRegistry::start().await;
    mock.with_manifest_package(
        serde_json::json!({
            "name": "react",
            "version": "18.3.1"
        }),
        &[],
    )
    .await;
    mock.with_manifest_package(
        serde_json::json!({
            "name": "peer-consumer",
            "version": "1.0.0",
            "main": "index.js",
            "peerDependencies": {
                "react": "^18.0.0"
            }
        }),
        &[(
            "index.js",
            b"module.exports = require('react/package.json').version;\n",
        )],
    )
    .await;

    let project = TempProject::empty(
        r#"{
  "name": "warm-v2-peer-relink",
  "version": "1.0.0",
  "dependencies": {
    "peer-consumer": "1.0.0",
    "react": "18.3.1"
  }
}"#,
    );

    let cold = lpm_with_registry(&project, &mock.url())
        .env("LPM_STORE_VERSION", "v2")
        .args([
            "install",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("failed to run cold v2 install");
    assert!(
        cold.status.success(),
        "cold v2 install should succeed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&cold.stdout),
        String::from_utf8_lossy(&cold.stderr),
    );

    let lockfile =
        lpm_lockfile::Lockfile::read_from_file(&project.path().join(lpm_lockfile::LOCKFILE_NAME))
            .expect("lockfile should parse after cold install");
    assert_eq!(
        lockfile.metadata.lockfile_version,
        lpm_lockfile::LOCKFILE_VERSION,
        "cold install should write current lockfile schema",
    );
    let consumer = lockfile
        .packages
        .iter()
        .find(|pkg| pkg.name == "peer-consumer")
        .expect("lockfile should contain peer-consumer");
    assert_eq!(
        consumer.peers,
        vec!["react@18.3.1".to_string()],
        "lockfile must persist resolved peer context for warm v2 linking",
    );

    std::fs::remove_dir_all(project.path().join("node_modules"))
        .expect("remove node_modules before warm relink");

    let warm = lpm_with_registry(&project, &mock.url())
        .env("LPM_STORE_VERSION", "v2")
        .args([
            "--json",
            "install",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("failed to run warm v2 install");
    assert!(
        warm.status.success(),
        "warm v2 install should succeed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&warm.stdout),
        String::from_utf8_lossy(&warm.stderr),
    );
    let warm_json: serde_json::Value =
        serde_json::from_slice(&warm.stdout).expect("warm install should emit JSON");
    assert_eq!(
        warm_json["used_lockfile"].as_bool(),
        Some(true),
        "second install should use the lockfile fast path",
    );

    let runtime = std::process::Command::new("node")
        .current_dir(project.path())
        .arg("-e")
        .arg("process.stdout.write(require('peer-consumer'))")
        .output()
        .expect("run peer consumer require after warm relink");
    assert!(
        runtime.status.success(),
        "peer consumer should resolve react after warm v2 relink\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&runtime.stdout),
        String::from_utf8_lossy(&runtime.stderr),
    );
    assert_eq!(
        String::from_utf8_lossy(&runtime.stdout),
        "18.3.1",
        "warm v2 relink must preserve peer resolution",
    );
}

#[tokio::test]
async fn warm_v2_lockfile_install_preserves_blocked_metadata_when_registry_unavailable() {
    const PUBLISHED_AT: &str = "2025-01-01T00:00:00.000Z";

    fn blocked_published_at(project: &TempProject, package_name: &str) -> Option<String> {
        let state: serde_json::Value =
            serde_json::from_str(&project.read_file(".lpm/build-state.json"))
                .expect("build-state.json should parse as JSON");
        state["blocked_packages"]
            .as_array()
            .expect("blocked_packages should be an array")
            .iter()
            .find(|pkg| pkg["name"].as_str() == Some(package_name))
            .and_then(|pkg| pkg["published_at"].as_str())
            .map(ToString::to_string)
    }

    let mock = MockRegistry::start().await;
    mock.with_manifest_package(
        serde_json::json!({
            "name": "scripted-meta",
            "version": "1.0.0",
            "scripts": {
                "postinstall": "node postinstall.js"
            }
        }),
        &[(
            "postinstall.js",
            b"require('fs').writeFileSync('scripted-meta-built.txt', 'ok');\n",
        )],
    )
    .await;

    let project = TempProject::empty(
        r#"{
  "name": "warm-v2-blocked-metadata",
  "version": "1.0.0",
  "dependencies": {
    "scripted-meta": "1.0.0"
  }
}"#,
    );
    let registry_url = mock.url();

    let cold = lpm_with_registry(&project, &registry_url)
        .env("LPM_STORE_VERSION", "v2")
        .args([
            "install",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("failed to run cold v2 install");
    assert!(
        cold.status.success(),
        "cold v2 install should succeed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&cold.stdout),
        String::from_utf8_lossy(&cold.stderr),
    );
    assert_eq!(
        blocked_published_at(&project, "scripted-meta").as_deref(),
        Some(PUBLISHED_AT),
        "cold install should enrich the blocked set from registry metadata",
    );

    std::fs::remove_dir_all(project.path().join("node_modules"))
        .expect("remove node_modules before warm relink");
    drop(mock);

    let warm = lpm_with_registry(&project, &registry_url)
        .env("LPM_STORE_VERSION", "v2")
        .args([
            "--json",
            "install",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("failed to run warm v2 install");
    assert!(
        warm.status.success(),
        "warm v2 install should succeed from the lockfile and store without registry metadata\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&warm.stdout),
        String::from_utf8_lossy(&warm.stderr),
    );
    let warm_json: serde_json::Value =
        serde_json::from_slice(&warm.stdout).expect("warm install should emit JSON");
    assert_eq!(
        warm_json["used_lockfile"].as_bool(),
        Some(true),
        "second install should use the lockfile fast path",
    );
    assert_eq!(
        blocked_published_at(&project, "scripted-meta").as_deref(),
        Some(PUBLISHED_AT),
        "warm lockfile install should replay prior blocked-set metadata",
    );
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
                        "integrity": compute_integrity(&tarball),
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
fn store_v1_rollback_workspace_star_dep_links_member_source() {
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

    lpm_v1(&project)
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

#[test]
fn install_workspace_star_dep_accepts_member_without_version() {
    let project = TempProject::empty(
        r#"{
  "name": "ws-versionless-root",
  "version": "1.0.0",
  "private": true,
  "workspaces": ["packages/*"],
  "dependencies": {
    "no-ver": "workspace:*"
  }
}"#,
    );

    project.write_file("packages/no-ver/package.json", r#"{"name":"no-ver"}"#);

    lpm(&project)
        .args([
            "install",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .env("LPM_STORE_VERSION", "v2")
        .assert()
        .success();

    let link = project.path().join("node_modules/no-ver");
    assert!(
        std::fs::symlink_metadata(&link)
            .expect("versionless workspace member must be linked")
            .file_type()
            .is_symlink(),
        "v2 must materialize the versionless workspace member through its link store",
    );
    let resolved = std::fs::canonicalize(link).expect("resolve versionless workspace member link");
    assert!(
        resolved.to_string_lossy().contains("no-ver@0.0.0"),
        "versionless workspace members must retain the workspace discovery default"
    );
}

/// `workspace:^` is a published-time hint — the member is still installed
/// locally as a symlink. Pre-fix, install rewrote `workspace:^` into a
/// registry range and 404'd against the upstream proxy.
#[test]
fn store_v1_rollback_workspace_caret_dep_links_member_source() {
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

    lpm_v1(&project)
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

#[tokio::test]
async fn install_direct_workspace_dep_installs_member_registry_deps_under_v2_store() {
    let project = TempProject::empty(
        r#"{
  "name": "ws-direct-root-runtime",
  "version": "1.0.0",
  "private": true,
  "workspaces": ["packages/*"],
  "dependencies": {
    "foo": "workspace:*"
  }
}"#,
    );

    project.write_file(
        "packages/foo/package.json",
        r#"{
  "name": "foo",
  "version": "1.0.0",
  "main": "index.js",
  "dependencies": {
    "external-leaf": "1.0.0"
  }
}"#,
    );
    project.write_file(
        "packages/foo/index.js",
        r#"module.exports = require("external-leaf")
"#,
    );

    let mock = MockRegistry::start().await;
    mock.with_manifest_package(
        serde_json::json!({
            "name": "external-leaf",
            "version": "1.0.0"
        }),
        &[("index.js", b"module.exports = 'from-registry'\n")],
    )
    .await;

    let mut cmd = lpm_with_registry(&project, &mock.url());
    cmd.env("LPM_STORE_VERSION", "v2");
    let output = cmd
        .args([
            "install",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("failed to run direct workspace install under v2 store");

    assert!(
        output.status.success(),
        "v2 install should succeed for a direct workspace dep with registry transitives\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let foo_link = project.path().join("node_modules").join("foo");
    let foo_meta = std::fs::symlink_metadata(&foo_link)
        .unwrap_or_else(|e| panic!("node_modules/foo missing after v2 install: {e}"));
    assert!(
        foo_meta.file_type().is_symlink(),
        "node_modules/foo must still be materialized as a symlink under v2"
    );

    let runtime = std::process::Command::new("node")
        .current_dir(project.path())
        .arg("-e")
        .arg("process.stdout.write(require('foo'))")
        .output()
        .expect("spawn node runtime check");

    assert!(
        runtime.status.success(),
        "direct workspace member should resolve its registry child after install\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&runtime.stdout),
        String::from_utf8_lossy(&runtime.stderr),
    );
    assert_eq!(
        String::from_utf8_lossy(&runtime.stdout),
        "from-registry",
        "runtime should resolve foo through its installed registry dependency",
    );
}

#[tokio::test]
async fn install_direct_workspace_dep_resolves_workspace_child_under_v2_store() {
    let project = TempProject::empty(
        r#"{
  "name": "ws-direct-workspace-child-root",
  "version": "1.0.0",
  "private": true,
  "workspaces": ["packages/*"],
  "dependencies": {
    "foo": "workspace:*"
  }
}"#,
    );

    project.write_file(
        "packages/foo/package.json",
        r#"{
  "name": "foo",
  "version": "1.0.0",
  "main": "index.js",
  "dependencies": {
    "bar": "workspace:*"
  }
}"#,
    );
    project.write_file(
        "packages/foo/index.js",
        r#"module.exports = require("bar")
"#,
    );
    project.write_file(
        "packages/bar/package.json",
        r#"{
  "name": "bar",
  "version": "1.0.0",
  "main": "index.js"
}"#,
    );
    project.write_file("packages/bar/index.js", "module.exports = 'from-bar'\n");

    let mut cmd = lpm(&project);
    cmd.env("LPM_STORE_VERSION", "v2");
    let output = cmd
        .args([
            "install",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("failed to run direct workspace install under v2 store");

    assert!(
        output.status.success(),
        "v2 install should succeed for a direct workspace dep with a workspace child\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let runtime = std::process::Command::new("node")
        .current_dir(project.path())
        .arg("-e")
        .arg("process.stdout.write(require('foo'))")
        .output()
        .expect("spawn node runtime check");

    assert!(
        runtime.status.success(),
        "direct workspace member should resolve its workspace child from the v2 link store\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&runtime.stdout),
        String::from_utf8_lossy(&runtime.stderr),
    );
    assert_eq!(
        String::from_utf8_lossy(&runtime.stdout),
        "from-bar",
        "runtime should resolve foo through its workspace dependency",
    );
}

#[tokio::test]
async fn install_registry_reentry_to_workspace_cycle_dedupes_v2_link_target() {
    let project = TempProject::empty(
        r#"{
  "name": "ws-registry-reentry-cycle-root",
  "version": "1.0.0",
  "private": true,
  "workspaces": ["apps/*", "packages/*"]
}"#,
    );
    project.write_file(
        "apps/app/package.json",
        r#"{
  "name": "workspace-reentry-app",
  "version": "1.0.0",
  "private": true,
  "dependencies": {
    "@smoke/cycle-a": "workspace:*",
    "external-reentry": "1.0.0"
  }
}"#,
    );
    project.write_file(
        "apps/app/index.js",
        r#"const cycleA = require("@smoke/cycle-a")
const external = require("external-reentry")
process.stdout.write(`${cycleA.name}:${cycleA.peer}:${external}`)
"#,
    );
    project.write_file(
        "packages/cycle-a/package.json",
        r#"{
  "name": "@smoke/cycle-a",
  "version": "1.0.0",
  "main": "index.js",
  "dependencies": {
    "@smoke/cycle-b": "workspace:*"
  }
}"#,
    );
    project.write_file(
        "packages/cycle-a/index.js",
        r#"exports.name = "cycle-a"
exports.peer = require("@smoke/cycle-b").name
"#,
    );
    project.write_file(
        "packages/cycle-b/package.json",
        r#"{
  "name": "@smoke/cycle-b",
  "version": "1.0.0",
  "main": "index.js",
  "dependencies": {
    "@smoke/cycle-a": "workspace:*"
  }
}"#,
    );
    project.write_file(
        "packages/cycle-b/index.js",
        r#"exports.name = "cycle-b"
exports.peer = require("@smoke/cycle-a").name
"#,
    );

    let mock = MockRegistry::start().await;
    mock.with_manifest_package(
        serde_json::json!({
            "name": "external-reentry",
            "version": "1.0.0",
            "dependencies": {
                "@smoke/cycle-b": "1.0.0"
            }
        }),
        &[(
            "index.js",
            b"module.exports = require('@smoke/cycle-b').name\n",
        )],
    )
    .await;

    let app_dir = project.path().join("apps").join("app");
    let mut cmd = lpm_with_registry(&project, &mock.url());
    cmd.current_dir(&app_dir);
    cmd.env("LPM_STORE_VERSION", "v2");
    let output = cmd
        .args([
            "install",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("failed to run v2 install with registry re-entry cycle");

    assert!(
        output.status.success(),
        "v2 install should dedupe a workspace package reached through both direct workspace and registry re-entry paths\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let runtime = std::process::Command::new("node")
        .current_dir(&app_dir)
        .arg("index.js")
        .output()
        .expect("spawn node runtime check");

    assert!(
        runtime.status.success(),
        "workspace cycle should remain resolvable after registry re-entry\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&runtime.stdout),
        String::from_utf8_lossy(&runtime.stderr),
    );
    assert_eq!(
        String::from_utf8_lossy(&runtime.stdout),
        "cycle-a:cycle-b:cycle-b",
        "runtime should resolve both the direct workspace cycle and registry re-entry",
    );
}

/// In hoisted mode (`--linker hoisted`), a transitive dep must land at
/// `node_modules/<C>` directly — flat npm-v3 layout — not nested under
/// the package that pulled it in. Default isolated mode is exercised by
/// every other install test in this file; this one pins the hoisted
/// surface so a regression in the flatten pass is caught.
#[tokio::test]
async fn store_v1_rollback_hoisted_mode_places_transitive_dep_at_root() {
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

    lpm_v1_with_registry(&project, &mock.url())
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

/// A package that declares a required `peerDependencies` entry gets that
/// peer auto-installed by default, matching npm v7+ behavior.
#[tokio::test]
async fn install_auto_installs_required_peer_dependencies_by_default() {
    let mock = MockRegistry::start().await;

    let peer_host_manifest = serde_json::json!({
        "name": "peer-host",
        "version": "1.0.0",
        "peerDependencies": { "ghost-peer": "^1.0.0" }
    });
    mock.with_manifest_package(peer_host_manifest, &[]).await;
    let peer_tarball = make_tarball("ghost-peer", "1.0.0");
    mock.with_package("ghost-peer", "1.0.0", &peer_tarball)
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
        nm.join("ghost-peer").join("package.json").exists(),
        "ghost-peer (declared as a required peer) must be auto-installed by default"
    );

    let lockfile = project.read_file("lpm.lock");
    assert!(
        lockfile.contains("ambient-peer-installs = [\"ghost-peer\"]"),
        "auto-installed peer must be persisted for warm installs:\n{lockfile}"
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

async fn run_transitive_dependency_failure_case(resolver: Option<&str>, parent_optional: bool) {
    let mock = MockRegistry::start().await;
    let host_manifest = if parent_optional {
        serde_json::json!({
            "name": "failure-host",
            "version": "1.0.0",
            "optionalDependencies": { "failure-parent": "1.0.0" }
        })
    } else {
        serde_json::json!({
            "name": "failure-host",
            "version": "1.0.0",
            "dependencies": { "failure-parent": "1.0.0" }
        })
    };
    mock.with_manifest_package(host_manifest, &[]).await;
    mock.with_manifest_package(
        serde_json::json!({
            "name": "failure-parent",
            "version": "1.0.0",
            "dependencies": { "missing-required-child": "1.0.0" }
        }),
        &[],
    )
    .await;

    let project = TempProject::empty(
        r#"{"name":"transitive-failure","version":"1.0.0","dependencies":{"failure-host":"1.0.0"}}"#,
    );
    let mut command = lpm_with_registry(&project, &mock.url());
    command.args([
        "install",
        "--no-security-summary",
        "--no-skills",
        "--no-editor-setup",
    ]);
    if let Some(resolver) = resolver {
        command.env("LPM_RESOLVER", resolver);
    }
    let output = command.output().expect("run transitive failure install");

    if parent_optional {
        assert!(
            output.status.success(),
            "required child failure below an optional parent must be skipped\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
        let node_modules = project.path().join("node_modules");
        assert!(
            node_modules.join("failure-host").exists()
                && !node_modules.join("missing-required-child").exists()
                && !node_modules
                    .join("failure-host/node_modules/missing-required-child")
                    .exists(),
            "the required host must remain installed while the failed optional subtree is omitted",
        );
    } else {
        assert!(
            !output.status.success(),
            "required child failure below a required parent must fail installation"
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("missing-required-child"),
            "failure must identify the unavailable required child; got:\n{stderr}"
        );
    }
}

#[tokio::test]
async fn greedy_skips_required_failure_below_optional_parent() {
    run_transitive_dependency_failure_case(None, true).await;
}

#[tokio::test]
async fn pubgrub_skips_required_failure_below_optional_parent() {
    run_transitive_dependency_failure_case(Some("pubgrub"), true).await;
}

#[tokio::test]
async fn greedy_propagates_required_failure_below_required_parent() {
    run_transitive_dependency_failure_case(None, false).await;
}

#[tokio::test]
async fn pubgrub_propagates_required_failure_below_required_parent() {
    run_transitive_dependency_failure_case(Some("pubgrub"), false).await;
}

#[tokio::test]
async fn pubgrub_keeps_shared_descendant_failure_fatal_when_any_path_is_required() {
    let mock = MockRegistry::start().await;
    mock.with_full_package_metadata(
        "required-host",
        "2.0.0",
        &[
            (
                "1.0.0",
                serde_json::json!({ "shared-failure-parent": "1.0.0" }),
                Some(make_tarball("required-host", "1.0.0")),
            ),
            (
                "2.0.0",
                serde_json::json!({ "shared-failure-parent": "1.0.0" }),
                Some(make_tarball("required-host", "2.0.0")),
            ),
        ],
    )
    .await;
    mock.with_manifest_package(
        serde_json::json!({
            "name": "optional-host",
            "version": "1.0.0",
            "optionalDependencies": { "shared-failure-parent": "1.0.0" }
        }),
        &[],
    )
    .await;
    mock.with_manifest_package(
        serde_json::json!({
            "name": "shared-failure-parent",
            "version": "1.0.0",
            "dependencies": { "missing-shared-child": "1.0.0" }
        }),
        &[],
    )
    .await;

    let project = TempProject::empty(
        r#"{
            "name":"shared-transitive-failure",
            "version":"1.0.0",
            "dependencies":{
                "optional-host":"1.0.0",
                "required-host":"1.0.0"
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
        .env("LPM_RESOLVER", "pubgrub")
        .output()
        .expect("run shared-path PubGrub failure install");

    assert!(
        !output.status.success(),
        "a required path to the shared parent must keep its child failure fatal"
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("missing-shared-child"),
        "failure must identify the missing descendant"
    );
}

async fn mount_required_incompatible_engine(mock: &MockRegistry) {
    mock.with_manifest_package(
        serde_json::json!({
            "name": "incompatible-engine",
            "version": "1.0.0",
            "engines": { "node": ">=999.0.0" }
        }),
        &[],
    )
    .await;
}

fn dependency_engine_install_command(
    project: &TempProject,
    registry_url: &str,
) -> assert_cmd::Command {
    let mut command = lpm_with_registry(project, registry_url);
    configure_fake_node(&mut command, project, "20.0.0");
    command.args([
        "install",
        "--no-security-summary",
        "--no-skills",
        "--no-editor-setup",
    ]);
    command
}

#[tokio::test]
async fn fresh_strict_install_rejects_required_dependency_with_incompatible_node_engine() {
    let mock = MockRegistry::start().await;
    mount_required_incompatible_engine(&mock).await;
    let project = TempProject::empty(
        r#"{"name":"engine-strict","version":"1.0.0","dependencies":{"incompatible-engine":"1.0.0"}}"#,
    );

    let output = dependency_engine_install_command(&project, &mock.url())
        .output()
        .expect("run strict dependency-engine install");

    assert!(
        !output.status.success(),
        "strict install must reject an incompatible required dependency"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("incompatible-engine@1.0.0") && stderr.contains(">=999.0.0"),
        "engine mismatch must identify the dependency and required range; got:\n{stderr}"
    );
}

#[tokio::test]
async fn fresh_non_strict_install_warns_and_accepts_incompatible_dependency_engine() {
    let mock = MockRegistry::start().await;
    mount_required_incompatible_engine(&mock).await;
    let project = TempProject::empty(
        r#"{"name":"engine-soft","version":"1.0.0","lpm":{"engineStrict":false},"dependencies":{"incompatible-engine":"1.0.0"}}"#,
    );

    let output = dependency_engine_install_command(&project, &mock.url())
        .output()
        .expect("run non-strict dependency-engine install");

    assert!(
        output.status.success(),
        "non-strict install must accept an incompatible dependency\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("incompatible-engine@1.0.0") && stderr.contains("engine-strict disabled"),
        "non-strict install must warn about the ignored mismatch; got:\n{stderr}"
    );
    assert!(
        project
            .path()
            .join("node_modules/incompatible-engine")
            .exists()
    );
}

#[tokio::test]
async fn frozen_strict_install_revalidates_dependency_engine_from_lockfile() {
    let mock = MockRegistry::start().await;
    mount_required_incompatible_engine(&mock).await;
    let project = TempProject::empty(
        r#"{"name":"engine-frozen","version":"1.0.0","lpm":{"engineStrict":false},"dependencies":{"incompatible-engine":"1.0.0"}}"#,
    );

    dependency_engine_install_command(&project, &mock.url())
        .assert()
        .success();
    let lockfile = project.read_file("lpm.lock");
    assert!(
        lockfile.contains("node-engine = \">=999.0.0\""),
        "lockfile must retain dependency engine constraints for replay:\n{lockfile}"
    );

    project.write_file(
        "package.json",
        r#"{"name":"engine-frozen","version":"1.0.0","lpm":{"engineStrict":true},"dependencies":{"incompatible-engine":"1.0.0"}}"#,
    );
    let _ = std::fs::remove_dir_all(project.path().join("node_modules"));
    let _ = std::fs::remove_file(project.path().join(".lpm/install-hash"));

    let mut command = dependency_engine_install_command(&project, &mock.url());
    command.arg("--frozen-lockfile");
    let output = command
        .output()
        .expect("run frozen strict dependency-engine install");
    assert!(
        !output.status.success(),
        "frozen strict install must reject the locked incompatible dependency"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("incompatible-engine@1.0.0") && stderr.contains(">=999.0.0"),
        "frozen mismatch must come from persisted engine metadata; got:\n{stderr}"
    );
}

#[tokio::test]
async fn warm_install_revalidates_dependency_engine_when_effective_node_changes() {
    let mock = MockRegistry::start().await;
    mock.with_manifest_package(
        serde_json::json!({
            "name": "node-20-only",
            "version": "1.0.0",
            "engines": { "node": ">=20 <21" }
        }),
        &[],
    )
    .await;
    let project = TempProject::empty(
        r#"{"name":"engine-warm","version":"1.0.0","dependencies":{"node-20-only":"1.0.0"}}"#,
    );

    let mut first = dependency_engine_install_command(&project, &mock.url());
    configure_fake_node(&mut first, &project, "20.0.0");
    first.assert().success();

    let mut second = dependency_engine_install_command(&project, &mock.url());
    configure_fake_node(&mut second, &project, "22.0.0");
    let output = second
        .output()
        .expect("run warm install after effective Node change");

    assert!(
        !output.status.success(),
        "warm install must not use an install-state hit after the effective Node version changes"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("node-20-only@1.0.0") && stderr.contains(">=20 <21"),
        "warm mismatch must be revalidated from lockfile engine metadata; got:\n{stderr}"
    );
}

#[tokio::test]
async fn strict_install_skips_incompatible_required_descendant_below_optional_parent() {
    let mock = MockRegistry::start().await;
    mock.with_manifest_package(
        serde_json::json!({
            "name": "engine-host",
            "version": "1.0.0",
            "optionalDependencies": { "engine-optional-parent": "1.0.0" }
        }),
        &[],
    )
    .await;
    mock.with_manifest_package(
        serde_json::json!({
            "name": "engine-optional-parent",
            "version": "1.0.0",
            "dependencies": { "incompatible-engine": "1.0.0" }
        }),
        &[],
    )
    .await;
    mount_required_incompatible_engine(&mock).await;
    let project = TempProject::empty(
        r#"{"name":"engine-optional","version":"1.0.0","dependencies":{"engine-host":"1.0.0"}}"#,
    );

    let output = dependency_engine_install_command(&project, &mock.url())
        .output()
        .expect("run optional dependency-engine install");
    assert!(
        output.status.success(),
        "incompatible dependency below an optional parent must be skipped\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let node_modules = project.path().join("node_modules");
    assert!(node_modules.join("engine-host").exists());
    assert!(
        !node_modules.join("incompatible-engine").exists()
            && !node_modules
                .join("engine-host/node_modules/incompatible-engine")
                .exists()
    );
}

#[test]
fn strict_install_skips_incompatible_optional_file_dependency_from_local_source() {
    let project = TempProject::empty(
        r#"{
            "name":"local-engine-optional",
            "version":"1.0.0",
            "dependencies":{"local-host":"file:./packages/local-host"}
        }"#,
    );
    project.write_file(
        "packages/local-host/package.json",
        r#"{
            "name":"local-host",
            "version":"1.0.0",
            "optionalDependencies":{"local-native":"file:../local-native"}
        }"#,
    );
    project.write_file(
        "packages/local-native/package.json",
        r#"{
            "name":"local-native",
            "version":"1.0.0",
            "engines":{"node":">=999.0.0"}
        }"#,
    );

    let mut command = lpm(&project);
    configure_fake_node(&mut command, &project, "20.0.0");
    let output = command
        .args([
            "install",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("run local optional dependency-engine install");

    assert!(
        output.status.success(),
        "incompatible optional file dependency must be skipped\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    assert!(project.path().join("node_modules/local-host").exists());
}

#[test]
fn install_accepts_versionless_transitive_link_dependency() {
    let project = TempProject::empty(
        r#"{
            "name":"versionless-link-consumer",
            "version":"1.0.0",
            "dependencies":{"local-parent":"file:./packages/local-parent"}
        }"#,
    );
    project.write_file(
        "packages/local-parent/package.json",
        r#"{
            "name":"local-parent",
            "version":"1.0.0",
            "dependencies":{"local-child":"link:../local-child"}
        }"#,
    );
    project.write_file(
        "packages/local-child/package.json",
        r#"{"name":"local-child","main":"index.js"}"#,
    );
    project.write_file(
        "packages/local-child/index.js",
        "module.exports = 'linked';\n",
    );

    let output = lpm(&project)
        .args([
            "install",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("install versionless transitive link dependency");

    assert!(
        output.status.success(),
        "a local link package may omit version\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let lockfile = lpm_lockfile::Lockfile::read_from_file(&project.path().join("lpm.lock"))
        .expect("read lockfile after versionless link install");
    assert!(
        lockfile
            .packages
            .iter()
            .any(|package| package.name == "local-child" && package.version == "0.0.0"),
        "versionless local links must use the same 0.0.0 identity as versionless workspace members",
    );
}

#[test]
fn install_does_not_auto_install_optional_peer_from_local_dependency() {
    let project = TempProject::empty(
        r#"{
            "name":"optional-local-peer-consumer",
            "version":"1.0.0",
            "dependencies":{"local-peer-host":"file:./packages/local-peer-host"}
        }"#,
    );
    project.write_file(
        "packages/local-peer-host/package.json",
        r#"{
            "name":"local-peer-host",
            "version":"1.0.0",
            "peerDependencies":{"foobar":"0.0.0"},
            "peerDependenciesMeta":{"foobar":{"optional":true}}
        }"#,
    );

    let output = lpm(&project)
        .args([
            "install",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("install local dependency with an absent optional peer");

    assert!(
        output.status.success(),
        "an absent optional peer must not trigger registry resolution\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let lockfile = lpm_lockfile::Lockfile::read_from_file(&project.path().join("lpm.lock"))
        .expect("read lockfile after optional peer install");
    assert!(
        lockfile
            .packages
            .iter()
            .all(|package| package.name != "foobar"),
        "optional peer must remain absent when the consumer does not provide it",
    );
}

#[tokio::test]
async fn optional_local_engine_skip_preserves_required_registry_package_with_same_identity() {
    let mock = MockRegistry::start().await;
    mock.with_manifest_package(
        serde_json::json!({
            "name": "registry-host",
            "version": "1.0.0",
            "main": "index.js",
            "dependencies": { "foo": "1.0.0" }
        }),
        &[("index.js", b"module.exports = require('foo');\n")],
    )
    .await;
    mock.with_manifest_package(
        serde_json::json!({
            "name": "foo",
            "version": "1.0.0",
            "main": "index.js"
        }),
        &[("index.js", b"module.exports = 'registry-foo';\n")],
    )
    .await;

    let project = TempProject::empty(
        r#"{
            "name":"source-aware-engine-skip",
            "version":"1.0.0",
            "dependencies":{
                "local-host":"file:./packages/local-host",
                "registry-host":"1.0.0"
            }
        }"#,
    );
    project.write_file(
        "packages/local-host/package.json",
        r#"{
            "name":"local-host",
            "version":"1.0.0",
            "optionalDependencies":{"local-foo":"file:../local-foo"}
        }"#,
    );
    project.write_file(
        "packages/local-foo/package.json",
        r#"{
            "name":"foo",
            "version":"1.0.0",
            "engines":{"node":">=999.0.0"}
        }"#,
    );

    let output = dependency_engine_install_command(&project, &mock.url())
        .output()
        .expect("run source-aware dependency-engine install");
    assert!(
        output.status.success(),
        "skipping the optional local foo must preserve required registry foo\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let runtime = std::process::Command::new("node")
        .current_dir(project.path())
        .args(["-e", "process.stdout.write(require('registry-host'))"])
        .output()
        .expect("require registry host after source-aware engine skip");
    assert!(
        runtime.status.success() && String::from_utf8_lossy(&runtime.stdout) == "registry-foo",
        "required registry foo must remain installed and linked\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&runtime.stdout),
        String::from_utf8_lossy(&runtime.stderr),
    );
}

async fn run_optional_registry_dependency_from_local_source_case(resolver: Option<&str>) {
    let mock = MockRegistry::start().await;
    mock.with_manifest_package(
        serde_json::json!({
            "name": "optional-registry-native",
            "version": "1.0.0",
            "engines": { "node": ">=999.0.0" }
        }),
        &[],
    )
    .await;
    let project = TempProject::empty(
        r#"{
            "name":"optional-registry-from-local-source",
            "version":"1.0.0",
            "dependencies":{"local-host":"file:./packages/local-host"}
        }"#,
    );
    project.write_file(
        "packages/local-host/package.json",
        r#"{
            "name":"local-host",
            "version":"1.0.0",
            "optionalDependencies":{"optional-registry-native":"1.0.0"}
        }"#,
    );

    let mut command = dependency_engine_install_command(&project, &mock.url());
    if let Some(resolver) = resolver {
        command.env("LPM_RESOLVER", resolver);
    }
    let output = command
        .output()
        .expect("run optional registry dependency from local source install");
    assert!(
        output.status.success(),
        "an incompatible optional registry child of a local source must be skipped\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    assert!(project.path().join("node_modules/local-host").exists());
    assert!(
        !project
            .path()
            .join("node_modules/optional-registry-native")
            .exists()
    );
}

#[tokio::test]
async fn greedy_skips_incompatible_optional_registry_dependency_from_local_source() {
    run_optional_registry_dependency_from_local_source_case(None).await;
}

#[tokio::test]
async fn pubgrub_skips_incompatible_optional_registry_dependency_from_local_source() {
    run_optional_registry_dependency_from_local_source_case(Some("pubgrub")).await;
}

async fn run_missing_optional_registry_dependency_from_local_source_case(resolver: Option<&str>) {
    let mock = MockRegistry::start().await;
    let project = TempProject::empty(
        r#"{
            "name":"missing-optional-registry-from-local-source",
            "version":"1.0.0",
            "dependencies":{"local-host":"file:./packages/local-host"}
        }"#,
    );
    project.write_file(
        "packages/local-host/package.json",
        r#"{
            "name":"local-host",
            "version":"1.0.0",
            "optionalDependencies":{"missing-optional-registry":"1.0.0"}
        }"#,
    );

    let mut command = dependency_engine_install_command(&project, &mock.url());
    if let Some(resolver) = resolver {
        command.env("LPM_RESOLVER", resolver);
    }
    let output = command
        .output()
        .expect("run missing optional registry dependency from local source install");
    assert!(
        output.status.success(),
        "an unavailable optional registry child of a local source must be skipped\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    assert!(project.path().join("node_modules/local-host").exists());
}

#[tokio::test]
async fn greedy_skips_missing_optional_registry_dependency_from_local_source() {
    run_missing_optional_registry_dependency_from_local_source_case(None).await;
}

#[tokio::test]
async fn pubgrub_skips_missing_optional_registry_dependency_from_local_source() {
    run_missing_optional_registry_dependency_from_local_source_case(Some("pubgrub")).await;
}

#[tokio::test]
async fn experimental_resolver_skips_missing_optional_registry_dependency_from_local_source() {
    let mock = MockRegistry::start().await;
    let project = TempProject::empty(
        r#"{
            "name":"missing-optional-registry-experimental",
            "version":"1.0.0",
            "dependencies":{"local-host":"file:./packages/local-host"}
        }"#,
    );
    project.write_file(
        "packages/local-host/package.json",
        r#"{
            "name":"local-host",
            "version":"1.0.0",
            "optionalDependencies":{"missing-optional-registry":"1.0.0"}
        }"#,
    );

    let mut command = lpm_with_registry(&project, &mock.url());
    configure_fake_node(&mut command, &project, "20.0.0");
    let output = command
        .env("LPM_STORE_VERSION", "v2")
        .env("LPM_EXPERIMENTAL_INSTALLER_SPIKE", "1")
        .env("LPM_INSTALLER_SPIKE_BENCHMARK_ONLY", "1")
        .env("LPM_INSTALLER_SPIKE_GRAPH", "resolve-worklist")
        .env("LPM_INSTALLER_SPIKE_PARITY", "deny")
        .args([
            "install",
            "--json",
            "--timing",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("run experimental optional metadata failure install");

    assert!(
        output.status.success(),
        "the experimental resolver must skip unavailable optional metadata\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

#[test]
fn strict_install_skips_incompatible_optional_workspace_dependency_from_local_source() {
    let project = TempProject::empty(
        r#"{
            "name":"optional-workspace-from-local-source",
            "version":"1.0.0",
            "private":true,
            "workspaces":["packages/*"],
            "dependencies":{"local-host":"file:./vendor/local-host"}
        }"#,
    );
    project.write_file(
        "vendor/local-host/package.json",
        r#"{
            "name":"local-host",
            "version":"1.0.0",
            "optionalDependencies":{"workspace-native":"workspace:*"}
        }"#,
    );
    project.write_file(
        "packages/workspace-native/package.json",
        r#"{
            "name":"workspace-native",
            "version":"1.0.0",
            "engines":{"node":">=999.0.0"}
        }"#,
    );

    let mut command = lpm(&project);
    configure_fake_node(&mut command, &project, "20.0.0");
    let output = command
        .args([
            "install",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("run optional workspace dependency from local source install");

    assert!(
        output.status.success(),
        "an incompatible optional workspace child of a local source must be skipped\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    assert!(project.path().join("node_modules/local-host").exists());
    assert!(
        !project
            .path()
            .join("node_modules/workspace-native")
            .exists(),
        "a skipped optional workspace child must not leave a root symlink",
    );
}

#[test]
fn optional_local_parent_engine_skip_prunes_required_workspace_descendant_link() {
    let project = TempProject::empty(
        r#"{
            "name":"optional-local-workspace-descendant",
            "version":"1.0.0",
            "private":true,
            "workspaces":["packages/*"],
            "dependencies":{"local-host":"file:./vendor/local-host"}
        }"#,
    );
    project.write_file(
        "vendor/local-host/package.json",
        r#"{
            "name":"local-host",
            "version":"1.0.0",
            "optionalDependencies":{"optional-parent":"file:../optional-parent"}
        }"#,
    );
    project.write_file(
        "vendor/optional-parent/package.json",
        r#"{
            "name":"optional-parent",
            "version":"1.0.0",
            "engines":{"node":">=999.0.0"},
            "dependencies":{"workspace-child":"workspace:*"}
        }"#,
    );
    project.write_file(
        "packages/workspace-child/package.json",
        r#"{"name":"workspace-child","version":"1.0.0"}"#,
    );

    let mut command = lpm(&project);
    configure_fake_node(&mut command, &project, "20.0.0");
    let output = command
        .args([
            "install",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("run inherited optional workspace descendant install");

    assert!(
        output.status.success(),
        "an incompatible optional local parent must be skippable\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let node_modules = project.path().join("node_modules");
    assert!(!node_modules.join("optional-parent").exists());
    assert!(
        !node_modules.join("workspace-child").exists(),
        "a required workspace edge below a skipped optional parent must not leave a root link",
    );
}

#[test]
fn v1_store_rejects_required_workspace_member_with_incompatible_node_engine() {
    let project = TempProject::empty(
        r#"{
            "name":"v1-workspace-engine-strict",
            "version":"1.0.0",
            "private":true,
            "workspaces":["packages/*"],
            "dependencies":{"workspace-native":"workspace:*"}
        }"#,
    );
    project.write_file(
        "packages/workspace-native/package.json",
        r#"{
            "name":"workspace-native",
            "version":"1.0.0",
            "engines":{"node":">=999.0.0"}
        }"#,
    );

    let mut command = lpm_v1(&project);
    configure_fake_node(&mut command, &project, "20.0.0");
    let output = command
        .args([
            "install",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("run v1 workspace dependency-engine install");

    assert!(
        !output.status.success(),
        "v1 must reject the same required workspace engine mismatch as v2"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("workspace-native@1.0.0") && stderr.contains(">=999.0.0"),
        "v1 workspace mismatch must identify the member and range; got:\n{stderr}",
    );
}

#[test]
fn optional_dependency_overrides_duplicate_required_local_source_dependency() {
    let project = TempProject::empty(
        r#"{
            "name":"optional-local-override",
            "version":"1.0.0",
            "dependencies":{"local-host":"file:./packages/local-host"}
        }"#,
    );
    project.write_file(
        "packages/local-host/package.json",
        r#"{
            "name":"local-host",
            "version":"1.0.0",
            "dependencies":{"local-native":"file:../local-native"},
            "optionalDependencies":{"local-native":"file:../local-native"}
        }"#,
    );
    project.write_file(
        "packages/local-native/package.json",
        r#"{
            "name":"local-native",
            "version":"1.0.0",
            "engines":{"node":">=999.0.0"}
        }"#,
    );

    let mut command = lpm(&project);
    configure_fake_node(&mut command, &project, "20.0.0");
    let output = command
        .args([
            "install",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("run duplicate local dependency override install");

    assert!(
        output.status.success(),
        "optionalDependencies must override a duplicate dependencies entry\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    assert!(project.path().join("node_modules/local-host").exists());
}

#[tokio::test]
async fn strict_install_does_not_fetch_descendant_orphaned_by_optional_engine_skip() {
    let mock = MockRegistry::start().await;
    mock.with_manifest_package(
        serde_json::json!({
            "name": "orphan-host",
            "version": "1.0.0",
            "optionalDependencies": { "incompatible-optional-parent": "1.0.0" }
        }),
        &[],
    )
    .await;
    mock.with_manifest_package(
        serde_json::json!({
            "name": "incompatible-optional-parent",
            "version": "1.0.0",
            "engines": { "node": ">=999.0.0" },
            "dependencies": { "orphan-leaf": "1.0.0" }
        }),
        &[],
    )
    .await;
    mock.with_manifest_package(
        serde_json::json!({
            "name": "orphan-leaf",
            "version": "1.0.0"
        }),
        &[],
    )
    .await;
    Mock::given(method("GET"))
        .and(path(MockRegistry::tarball_path("orphan-leaf", "1.0.0")))
        .respond_with(ResponseTemplate::new(500))
        .with_priority(1)
        .mount(mock.server())
        .await;

    let project = TempProject::empty(
        r#"{
            "name":"engine-orphan-pruning",
            "version":"1.0.0",
            "dependencies":{"orphan-host":"1.0.0"}
        }"#,
    );
    let output = dependency_engine_install_command(&project, &mock.url())
        .env("LPM_RESOLVER", "pubgrub")
        .output()
        .expect("run orphan-pruning dependency-engine install");

    assert!(
        output.status.success(),
        "descendant orphaned by an optional engine skip must not be fetched\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let node_modules = project.path().join("node_modules");
    assert!(node_modules.join("orphan-host").exists());
    assert!(!node_modules.join("incompatible-optional-parent").exists());
    assert!(!node_modules.join("orphan-leaf").exists());
}

#[tokio::test]
async fn greedy_fusion_does_not_prefetch_optional_graph_before_engine_pruning() {
    let mock = MockRegistry::start().await;
    mock.with_manifest_package(
        serde_json::json!({
            "name": "overlap-host",
            "version": "1.0.0",
            "optionalDependencies": { "overlap-incompatible-parent": "1.0.0" }
        }),
        &[],
    )
    .await;
    mock.with_manifest_package(
        serde_json::json!({
            "name": "overlap-incompatible-parent",
            "version": "1.0.0",
            "engines": { "node": ">=999.0.0" },
            "dependencies": { "overlap-orphan-leaf": "1.0.0" }
        }),
        &[],
    )
    .await;
    mock.with_manifest_package(
        serde_json::json!({
            "name": "overlap-orphan-leaf",
            "version": "1.0.0"
        }),
        &[],
    )
    .await;
    let project = TempProject::empty(
        r#"{
            "name":"engine-overlap-pruning",
            "version":"1.0.0",
            "dependencies":{"overlap-host":"1.0.0"}
        }"#,
    );

    let output = dependency_engine_install_command(&project, &mock.url())
        .env("LPM_FETCH_OVERLAP_MIN_SELECTED", "1")
        .output()
        .expect("run greedy-fusion overlap dependency-engine install");
    assert!(
        output.status.success(),
        "engine-pruned optional graph must not fail install\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let requests = mock
        .server()
        .received_requests()
        .await
        .expect("wiremock request log must be available");
    let orphan_tarball = MockRegistry::tarball_path("overlap-orphan-leaf", "1.0.0");
    let orphan_tarball_hits: Vec<_> = requests
        .iter()
        .filter(|request| request.url.path() == orphan_tarball)
        .map(|request| request.url.path().to_string())
        .collect();
    assert!(
        orphan_tarball_hits.is_empty(),
        "greedy-fusion must not materialize descendants that engine pruning will orphan; hits={orphan_tarball_hits:?}",
    );
}

#[tokio::test]
async fn install_optional_platform_dep_selects_newest_then_skips_current_host() {
    let mock = MockRegistry::start().await;

    let host_pkg = serde_json::json!({
        "name": "platform-host",
        "version": "1.0.0",
        "optionalDependencies": {
            "platform-native": "^1.0.0"
        }
    });
    mock.with_manifest_package(host_pkg, &[]).await;

    let native_110 = serde_json::json!({
        "name": "platform-native",
        "version": "1.1.0",
        "os": ["__lpm_no_such_os__"]
    });
    let native_100 = serde_json::json!({
        "name": "platform-native",
        "version": "1.0.0"
    });
    let native_110_tarball = make_tarball_from_pkg_json(native_110.clone(), &[]);
    let native_100_tarball = make_tarball_from_pkg_json(native_100, &[]);
    let native_110_integrity = compute_integrity(&native_110_tarball);
    let native_100_integrity = compute_integrity(&native_100_tarball);
    let native_metadata = serde_json::json!({
        "name": "platform-native",
        "dist-tags": { "latest": "1.1.0" },
        "versions": {
            "1.1.0": {
                "name": "platform-native",
                "version": "1.1.0",
                "os": ["__lpm_no_such_os__"],
                "dist": {
                    "tarball": mock.tarball_url("platform-native", "1.1.0"),
                    "integrity": native_110_integrity,
                },
                "dependencies": {}
            },
            "1.0.0": {
                "name": "platform-native",
                "version": "1.0.0",
                "dist": {
                    "tarball": mock.tarball_url("platform-native", "1.0.0"),
                    "integrity": native_100_integrity,
                },
                "dependencies": {}
            }
        },
        "time": {
            "1.1.0": "2025-01-01T00:00:00.000Z",
            "1.0.0": "2025-01-01T00:00:00.000Z"
        }
    });
    Mock::given(method("GET"))
        .and(path("/api/registry/platform-native"))
        .respond_with(ResponseTemplate::new(200).set_body_json(native_metadata.clone()))
        .mount(mock.server())
        .await;
    Mock::given(method("GET"))
        .and(path("/platform-native"))
        .respond_with(ResponseTemplate::new(200).set_body_json(native_metadata.clone()))
        .mount(mock.server())
        .await;
    Mock::given(method("GET"))
        .and(path(MockRegistry::tarball_path("platform-native", "1.1.0")))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(native_110_tarball))
        .mount(mock.server())
        .await;
    Mock::given(method("GET"))
        .and(path(MockRegistry::tarball_path("platform-native", "1.0.0")))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(native_100_tarball))
        .mount(mock.server())
        .await;
    mock.with_batch_metadata(vec![native_metadata]).await;

    let project = TempProject::empty(
        r#"{
        "name": "platform-parity",
        "version": "1.0.0",
        "dependencies": {
            "platform-host": "1.0.0"
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
        .expect("failed to run platform parity install");
    assert!(
        output.status.success(),
        "install should skip incompatible optional package after selecting it\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let nm = project.path().join("node_modules");
    assert!(
        nm.join("platform-host").exists(),
        "host package must install"
    );
    assert!(
        !nm.join("platform-native").exists(),
        "incompatible optional package must not be linked on this host"
    );

    let lock = project.read_file("lpm.lock");
    assert!(
        lock.contains("name = \"platform-native\"")
            && lock.contains("version = \"1.1.0\"")
            && lock.contains("os = [\"__lpm_no_such_os__\"]")
            && lock.contains("optional = true"),
        "lockfile must preserve the semver-selected incompatible optional package for other hosts:\n{lock}"
    );
}

#[tokio::test]
async fn install_prod_omits_dev_dependencies_from_disk_but_keeps_lockfile_entries() {
    let mock = MockRegistry::start().await;
    let prod_tarball = make_tarball("prod-only", "1.0.0");
    let dev_tarball = make_tarball("dev-only", "1.0.0");
    mock.with_package("prod-only", "1.0.0", &prod_tarball).await;
    mock.with_package("dev-only", "1.0.0", &dev_tarball).await;

    let project = TempProject::empty(
        r#"{
        "name": "omit-dev",
        "version": "1.0.0",
        "dependencies": { "prod-only": "1.0.0" },
        "devDependencies": { "dev-only": "1.0.0" }
    }"#,
    );

    lpm_with_registry(&project, &mock.url())
        .args([
            "install",
            "--prod",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .assert()
        .success();

    assertions::assert_in_node_modules(project.path(), "prod-only");
    assert!(
        !project.path().join("node_modules/dev-only").exists(),
        "dev dependency must be omitted from the physical install"
    );
    let lockfile = project.read_file("lpm.lock");
    assert!(
        lockfile.contains("name = \"dev-only\""),
        "omit dev should still persist the resolved dev dependency in the lockfile:\n{lockfile}"
    );

    std::fs::remove_dir_all(project.path().join("node_modules")).unwrap();
    lpm_with_registry(&project, &mock.url())
        .args([
            "install",
            "--offline",
            "--omit=dev",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .assert()
        .success();

    assertions::assert_in_node_modules(project.path(), "prod-only");
    assert!(
        !project.path().join("node_modules/dev-only").exists(),
        "warm offline omit dev must not relink the dev dependency"
    );
}

#[tokio::test]
async fn install_omit_dev_after_full_install_does_not_use_up_to_date_fast_path() {
    let mock = MockRegistry::start().await;
    let prod_tarball = make_tarball("prod-only", "1.0.0");
    let dev_tarball = make_tarball("dev-only", "1.0.0");
    mock.with_package("prod-only", "1.0.0", &prod_tarball).await;
    mock.with_package("dev-only", "1.0.0", &dev_tarball).await;

    let project = TempProject::empty(
        r#"{
        "name": "omit-dev-after-full-install",
        "version": "1.0.0",
        "dependencies": { "prod-only": "1.0.0" },
        "devDependencies": { "dev-only": "1.0.0" }
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

    assertions::assert_in_node_modules(project.path(), "prod-only");
    assertions::assert_in_node_modules(project.path(), "dev-only");

    let output = lpm_with_registry(&project, &mock.url())
        .args([
            "install",
            "--omit=dev",
            "--json",
            "--timing",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("failed to run second lpm install --omit=dev");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "omit-dev reinstall after a full install failed:\nstdout: {}\nstderr: {stderr}",
        String::from_utf8_lossy(&output.stdout)
    );

    let json = assertions::parse_json_output(&output.stdout);
    assert_ne!(
        json["up_to_date"],
        serde_json::json!(true),
        "omit-dev reinstall must not take the up-to-date fast path:\n{json:#}\n{stderr}"
    );
    assertions::assert_in_node_modules(project.path(), "prod-only");
    assert!(
        !project.path().join("node_modules/dev-only").exists(),
        "omit-dev reinstall must prune the previously linked dev dependency"
    );
}

#[tokio::test]
async fn install_omit_dev_does_not_prefetch_dev_only_packages() {
    let mock = MockRegistry::start().await;
    let dev_tarball = make_tarball("dev-only", "1.0.0");
    mock.with_package("dev-only", "1.0.0", &dev_tarball).await;

    let project = TempProject::empty(
        r#"{
        "name": "omit-dev-overlap",
        "version": "1.0.0",
        "devDependencies": { "dev-only": "1.0.0" }
    }"#,
    );

    let output = lpm_with_registry(&project, &mock.url())
        .env("LPM_STORE_VERSION", "v2")
        .env("LPM_TIMING_DETAIL", "1")
        .env("LPM_FETCH_OVERLAP_MIN_SELECTED", "1")
        .args([
            "install",
            "--omit=dev",
            "--json",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("failed to run lpm install --json --omit=dev");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "omit dev install failed:\nstdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        !project.path().join("node_modules/dev-only").exists(),
        "dev-only package must not be linked into an omit-dev install"
    );
    let lockfile = project.read_file("lpm.lock");
    assert!(
        lockfile.contains("name = \"dev-only\""),
        "omit dev should still resolve dev-only for lockfile parity:\n{lockfile}"
    );

    let envelope: serde_json::Value =
        serde_json::from_str(&stdout).expect("install --json must emit parseable JSON");
    assert_eq!(envelope["count"].as_u64(), Some(0), "got {envelope:#}");
    assert_eq!(envelope["downloaded"].as_u64(), Some(0), "got {envelope:#}");
    assert_eq!(envelope["cached"].as_u64(), Some(0), "got {envelope:#}");
    let overlap = &envelope["timing"]["detail"]["fetch"]["overlap"];
    assert_eq!(
        overlap["dispatched_count"].as_u64(),
        Some(0),
        "omit-dev installs must not overlap-fetch packages later removed from the final graph; got {envelope:#}"
    );
    let speculative = &envelope["timing"]["speculative"];
    assert_eq!(
        speculative["dispatched"].as_u64(),
        Some(0),
        "omit-dev installs must not speculatively fetch packages later removed from the final graph; got {envelope:#}"
    );

    let requests = mock
        .server()
        .received_requests()
        .await
        .expect("wiremock request log must be available");
    let dev_tarball_path = MockRegistry::tarball_path("dev-only", "1.0.0");
    let dev_tarball_hits: Vec<_> = requests
        .iter()
        .filter(|request| request.url.path() == dev_tarball_path)
        .map(|request| request.url.path().to_string())
        .collect();
    assert!(
        dev_tarball_hits.is_empty(),
        "omit-dev install must not prefetch dev-only tarballs; hits={dev_tarball_hits:?}\nstdout: {stdout}\nstderr: {stderr}"
    );
}

#[tokio::test]
async fn install_fetch_overlap_skips_auth_bearing_custom_registry_tarballs() {
    let mock = MockRegistry::start().await;
    let tarball = make_tarball("private-pkg", "1.0.0");
    mock.with_package("private-pkg", "1.0.0", &tarball).await;

    let registry_url = mock.url();
    let registry_host = registry_url
        .strip_prefix("http://")
        .or_else(|| registry_url.strip_prefix("https://"))
        .expect("mock registry URL must include a scheme");
    let project = TempProject::empty(
        r#"{
        "name": "auth-overlap",
        "version": "1.0.0",
        "dependencies": { "private-pkg": "1.0.0" }
    }"#,
    );
    project.write_file(
        ".npmrc",
        &format!(
            "registry={registry_url}/\n//{registry_host}/:_authToken=test-token\nalways-auth=true\n"
        ),
    );

    let output = lpm_with_registry(&project, &registry_url)
        .env("LPM_STORE_VERSION", "v2")
        .env("LPM_TIMING_DETAIL", "1")
        .env("LPM_FETCH_OVERLAP_MIN_SELECTED", "1")
        .args([
            "install",
            "--json",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("failed to run lpm install --json");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "auth custom-registry install failed:\nstdout: {stdout}\nstderr: {stderr}"
    );

    let envelope: serde_json::Value =
        serde_json::from_str(&stdout).expect("install --json must emit parseable JSON");
    let overlap = &envelope["timing"]["detail"]["fetch"]["overlap"];
    assert!(
        overlap["selected_count"]
            .as_u64()
            .is_some_and(|count| count >= 1),
        "forced overlap admission should observe the selected private package; got {envelope:#}"
    );
    assert_eq!(
        overlap["dispatched_count"].as_u64(),
        Some(0),
        "auth-bearing custom registries must not dispatch credentialed early fetch tasks; got {envelope:#}"
    );
    assert_eq!(
        overlap["skipped_auth_count"].as_u64(),
        Some(1),
        "auth-bearing custom registry selections must be attributed as overlap auth skips; got {envelope:#}"
    );

    let requests = mock
        .server()
        .received_requests()
        .await
        .expect("wiremock request log must be available");
    let tarball_path = MockRegistry::tarball_path("private-pkg", "1.0.0");
    let tarball_hits = requests
        .iter()
        .filter(|request| request.url.path() == tarball_path)
        .count();
    assert_eq!(
        tarball_hits, 1,
        "only the authoritative fetch should request the private tarball; stdout: {stdout}\nstderr: {stderr}"
    );
}

/// End-to-end integrity verification: the SRI claim recorded in the
/// lockfile, the integrity-addressed global v2 object, and a fresh
/// recomputation from the original tarball bytes must agree. A regression in
/// any link of that chain would diverge.
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

    // 2. Integrity-keyed v2 object
    let store = lpm_store::v2::Store::at(project.store_dir().join("v2"));
    let stored_object = store
        .reusable_object_dir(&expected_integrity)
        .expect("validate the v2 object")
        .expect("the expected integrity must address a reusable v2 object");
    assert!(
        stored_object.join("package.json").is_file(),
        "integrity-keyed v2 object must contain the installed package"
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

#[tokio::test]
async fn install_github_dependency_at_commit_writes_replayable_lockfile_entry() {
    const COMMIT: &str = "779219540f66cecaa159da32b3b8936697ba10a7";

    let github = MockServer::start().await;
    let archive = make_tarball_with_files(
        "wa-sqlite",
        "1.0.9",
        &[("index.js", b"module.exports = 'github-ok';\n")],
    );
    let archive_integrity = compute_integrity(&archive);
    Mock::given(method("GET"))
        .and(path(format!("/rhashimoto/wa-sqlite/tar.gz/{COMMIT}")))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(archive))
        .expect(1)
        .mount(&github)
        .await;

    let project = TempProject::empty(&format!(
        r#"{{
  "name": "github-dependency-install",
  "version": "1.0.0",
  "dependencies": {{
    "wa-sqlite": "github:rhashimoto/wa-sqlite#{COMMIT}"
  }}
}}"#,
    ));

    let output = lpm(&project)
        .env("LPM_GITHUB_CODELOAD_BASE_URL", github.uri())
        .args([
            "install",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("run GitHub dependency install");

    assert!(
        output.status.success(),
        "GitHub dependency install must succeed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    assert_eq!(
        project.read_file("node_modules/wa-sqlite/index.js"),
        "module.exports = 'github-ok';\n"
    );

    let lockfile = project.read_file("lpm.lock");
    assert!(lockfile.contains(&format!(
        "source = \"git+https://github.com/rhashimoto/wa-sqlite.git#{COMMIT}\""
    )));
    assert!(lockfile.contains("integrity = \"sha512-"));

    let object_dir = lpm_store::v2::StoreV2Paths::at(project.store_dir().join("v2"))
        .object_dir(&archive_integrity)
        .expect("Git archive integrity should address the v2 object");
    assert!(object_dir.join(".lpm-security.json").is_file());
}

#[tokio::test]
async fn recursive_workspace_install_and_offline_replay_preserve_member_github_dependency() {
    const COMMIT: &str = "779219540f66cecaa159da32b3b8936697ba10a7";

    let registry = MockRegistry::start().await;
    registry
        .with_manifest_package(
            serde_json::json!({
                "name": "git-child",
                "version": "1.0.0"
            }),
            &[],
        )
        .await;

    let github = MockServer::start().await;
    let archive = make_tarball_from_pkg_json(
        serde_json::json!({
            "name": "wa-sqlite",
            "version": "1.0.9",
            "dependencies": { "git-child": "1.0.0" }
        }),
        &[],
    );
    Mock::given(method("GET"))
        .and(path(format!("/rhashimoto/wa-sqlite/tar.gz/{COMMIT}")))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(archive))
        .mount(&github)
        .await;

    let project = TempProject::empty(
        r#"{
  "name": "workspace-github-root",
  "private": true,
  "workspaces": ["packages/*"],
  "dependencies": { "workspace-editor": "workspace:*" }
}"#,
    );
    project.write_file(".npmrc", &format!("registry={}\n", registry.url()));
    project.write_file(
        "packages/editor/package.json",
        &format!(
            r#"{{
  "name": "workspace-editor",
  "version": "1.0.0",
  "dependencies": {{
    "wa-sqlite": "github:rhashimoto/wa-sqlite#{COMMIT}"
  }}
}}"#,
        ),
    );

    let output = lpm_with_registry(&project, &registry.url())
        .env("LPM_GITHUB_CODELOAD_BASE_URL", github.uri())
        .args([
            "install",
            "--recursive",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("run recursive workspace GitHub dependency install");
    assert!(
        output.status.success(),
        "recursive workspace GitHub dependency install must succeed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let lockfile = read_project_lockfile(&project, "");
    let git_package = lockfile
        .packages
        .iter()
        .find(|package| package.name == "wa-sqlite")
        .expect("workspace root lockfile should contain the GitHub dependency");
    assert_eq!(
        git_package.dependencies,
        vec!["git-child@1.0.0"],
        "GitHub package registry dependencies must remain in its locked graph",
    );
    let member = lockfile
        .packages
        .iter()
        .find(|package| package.name == "workspace-editor")
        .expect("workspace root lockfile should contain the workspace member");
    assert!(
        member
            .dependencies
            .iter()
            .any(|dependency| dependency.starts_with("wa-sqlite@g-")),
        "workspace member must point at the commit-pinned GitHub source: {:?}",
        member.dependencies,
    );
    assert!(
        !project.path().join("node_modules/wa-sqlite").exists(),
        "a member-only GitHub dependency must not become a workspace-root dependency",
    );

    let github_requests_before_replay = github
        .received_requests()
        .await
        .expect("read GitHub requests")
        .len();
    for relative in [
        "node_modules",
        ".lpm",
        "packages/editor/node_modules",
        "packages/editor/.lpm",
    ] {
        let path = project.path().join(relative);
        if path.exists() {
            std::fs::remove_dir_all(path).expect("remove materialized workspace install state");
        }
    }

    let replay = lpm_with_registry(&project, &registry.url())
        .env("LPM_GITHUB_CODELOAD_BASE_URL", github.uri())
        .args([
            "install",
            "--recursive",
            "--frozen-lockfile",
            "--offline",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("run frozen offline recursive workspace GitHub replay");
    assert!(
        replay.status.success(),
        "frozen offline recursive workspace GitHub replay must succeed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&replay.stdout),
        String::from_utf8_lossy(&replay.stderr),
    );
    assert_eq!(
        github
            .received_requests()
            .await
            .expect("read GitHub requests after replay")
            .len(),
        github_requests_before_replay,
        "offline replay must not contact GitHub",
    );
}

#[tokio::test]
async fn install_github_dependency_at_branch_locks_resolved_commit() {
    const COMMIT: &str = "779219540f66cecaa159da32b3b8936697ba10a7";

    let github = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/repos/rhashimoto/wa-sqlite/commits/main"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "sha": COMMIT
        })))
        .expect(1)
        .mount(&github)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/rhashimoto/wa-sqlite/tar.gz/{COMMIT}")))
        .respond_with(
            ResponseTemplate::new(200).set_body_bytes(make_tarball_with_files(
                "wa-sqlite",
                "1.0.9",
                &[("index.js", b"module.exports = 'branch-ok';\n")],
            )),
        )
        .expect(1)
        .mount(&github)
        .await;

    let project = TempProject::empty(
        r#"{
  "name": "github-branch-install",
  "version": "1.0.0",
  "dependencies": {
    "wa-sqlite": "github:rhashimoto/wa-sqlite#main"
  }
}"#,
    );
    let output = lpm(&project)
        .env("LPM_GITHUB_API_BASE_URL", github.uri())
        .env("LPM_GITHUB_CODELOAD_BASE_URL", github.uri())
        .args([
            "install",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("run GitHub branch dependency install");

    assert!(
        output.status.success(),
        "GitHub branch dependency install must succeed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let lockfile = project.read_file("lpm.lock");
    assert!(lockfile.contains(&format!(
        "source = \"git+https://github.com/rhashimoto/wa-sqlite.git#{COMMIT}\""
    )));
    assert!(lockfile.contains("wa-sqlite = \"github:rhashimoto/wa-sqlite#main\""));
}

#[test]
fn install_github_dependency_rejects_credentials_without_disclosure() {
    const SECRET: &str = "credential-that-must-not-leak";
    const COMMIT: &str = "779219540f66cecaa159da32b3b8936697ba10a7";

    let project = TempProject::empty(&format!(
        r#"{{
  "name": "github-credential-rejection",
  "version": "1.0.0",
  "dependencies": {{
    "wa-sqlite": "git+https://user:{SECRET}@github.com/rhashimoto/wa-sqlite.git#{COMMIT}"
  }}
}}"#,
    ));
    let output = lpm(&project)
        .args([
            "install",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("run credential-bearing GitHub dependency install");

    assert!(!output.status.success());
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!combined.contains(SECRET));
    assert!(!project.file_exists("lpm.lock"));
}

#[tokio::test]
async fn install_github_dependency_refuses_archive_redirect() {
    const COMMIT: &str = "779219540f66cecaa159da32b3b8936697ba10a7";

    let external = MockServer::start().await;
    let github = MockServer::start().await;
    let external_url = format!("{}/archive.tgz", external.uri());
    Mock::given(method("GET"))
        .and(path(format!("/rhashimoto/wa-sqlite/tar.gz/{COMMIT}")))
        .respond_with(ResponseTemplate::new(302).insert_header("Location", external_url.as_str()))
        .expect(1)
        .mount(&github)
        .await;

    let project = TempProject::empty(&format!(
        r#"{{
  "name": "github-redirect-rejection",
  "version": "1.0.0",
  "dependencies": {{
    "wa-sqlite": "github:rhashimoto/wa-sqlite#{COMMIT}"
  }}
}}"#,
    ));
    let output = lpm(&project)
        .env("LPM_GITHUB_CODELOAD_BASE_URL", github.uri())
        .args([
            "install",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("run redirected GitHub dependency install");

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("unexpected redirect"));
    assert!(
        external
            .received_requests()
            .await
            .expect("read external request log")
            .is_empty()
    );
}

#[tokio::test]
async fn install_github_dependency_rejects_oversized_archive_before_reading_body() {
    const COMMIT: &str = "779219540f66cecaa159da32b3b8936697ba10a7";

    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind raw GitHub server");
    let address = listener.local_addr().expect("read raw GitHub address");
    let server = std::thread::spawn(move || {
        use std::io::{Read, Write};

        let (mut stream, _) = listener.accept().expect("accept GitHub archive request");
        let mut request = [0u8; 4096];
        let _ = stream.read(&mut request);
        let declared = lpm_registry::MAX_COMPRESSED_TARBALL_SIZE + 1;
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Length: {declared}\r\nConnection: close\r\n\r\n"
        )
        .expect("write oversized GitHub response headers");
    });

    let project = TempProject::empty(&format!(
        r#"{{
  "name": "github-oversized-archive",
  "version": "1.0.0",
  "dependencies": {{
    "wa-sqlite": "github:rhashimoto/wa-sqlite#{COMMIT}"
  }}
}}"#,
    ));
    let output = lpm(&project)
        .env("LPM_GITHUB_CODELOAD_BASE_URL", format!("http://{address}"))
        .args([
            "install",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("run oversized GitHub dependency install");
    server.join().expect("join raw GitHub server");

    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("response size limit"),
        "oversized archive rejection must identify the size limit; stderr: {}",
        String::from_utf8_lossy(&output.stderr),
    );
    assert!(!project.file_exists("lpm.lock"));
}

#[tokio::test]
async fn install_github_dependency_replays_frozen_lockfile_offline() {
    const COMMIT: &str = "779219540f66cecaa159da32b3b8936697ba10a7";

    let github = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("/rhashimoto/wa-sqlite/tar.gz/{COMMIT}")))
        .respond_with(
            ResponseTemplate::new(200).set_body_bytes(make_tarball_with_files(
                "wa-sqlite",
                "1.0.9",
                &[("index.js", b"module.exports = 'offline-ok';\n")],
            )),
        )
        .expect(1)
        .mount(&github)
        .await;

    let project = TempProject::empty(&format!(
        r#"{{
  "name": "github-offline-replay",
  "version": "1.0.0",
  "dependencies": {{
    "wa-sqlite": "github:rhashimoto/wa-sqlite#{COMMIT}"
  }}
}}"#,
    ));
    let first = lpm(&project)
        .env("LPM_GITHUB_CODELOAD_BASE_URL", github.uri())
        .args([
            "install",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("run initial GitHub dependency install");
    assert!(first.status.success());
    let first_lockfile = project.read_file("lpm.lock");
    std::fs::remove_dir_all(project.path().join("node_modules"))
        .expect("remove node_modules before offline replay");

    let replay = lpm(&project)
        .env("LPM_GITHUB_CODELOAD_BASE_URL", github.uri())
        .args([
            "install",
            "--offline",
            "--frozen-lockfile",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("run frozen offline GitHub replay");

    assert!(
        replay.status.success(),
        "frozen offline replay must succeed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&replay.stdout),
        String::from_utf8_lossy(&replay.stderr),
    );
    assert_eq!(project.read_file("lpm.lock"), first_lockfile);
    assert_eq!(
        project.read_file("node_modules/wa-sqlite/index.js"),
        "module.exports = 'offline-ok';\n"
    );
}

#[tokio::test]
async fn install_github_dependency_fails_offline_when_store_is_missing() {
    const COMMIT: &str = "779219540f66cecaa159da32b3b8936697ba10a7";

    let github = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("/rhashimoto/wa-sqlite/tar.gz/{COMMIT}")))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(make_tarball("wa-sqlite", "1.0.9")))
        .expect(1)
        .mount(&github)
        .await;
    let project = TempProject::empty(&format!(
        r#"{{
  "name": "github-offline-missing-store",
  "version": "1.0.0",
  "dependencies": {{
    "wa-sqlite": "github:rhashimoto/wa-sqlite#{COMMIT}"
  }}
}}"#,
    ));
    let first = lpm(&project)
        .env("LPM_GITHUB_CODELOAD_BASE_URL", github.uri())
        .args([
            "install",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("run initial GitHub dependency install");
    assert!(first.status.success());
    std::fs::remove_dir_all(project.path().join("node_modules"))
        .expect("remove node_modules before missing-store replay");
    std::fs::remove_dir_all(project.store_dir().join("v2"))
        .expect("remove isolated v2 store before missing-store replay");

    let replay = lpm(&project)
        .env("LPM_GITHUB_CODELOAD_BASE_URL", github.uri())
        .args([
            "install",
            "--offline",
            "--frozen-lockfile",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("run frozen offline GitHub replay without store");

    assert!(!replay.status.success());
    assert!(String::from_utf8_lossy(&replay.stderr).contains("offline"));
}

#[tokio::test]
async fn install_github_dependencies_keep_two_commits_of_same_package_distinct() {
    const FIRST_COMMIT: &str = "1111111111111111111111111111111111111111";
    const SECOND_COMMIT: &str = "2222222222222222222222222222222222222222";

    let github = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("/owner/shared/tar.gz/{FIRST_COMMIT}")))
        .respond_with(
            ResponseTemplate::new(200).set_body_bytes(make_tarball_with_files(
                "shared-package",
                "1.0.0",
                &[("index.js", b"module.exports = 'first';\n")],
            )),
        )
        .expect(1)
        .mount(&github)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/owner/shared/tar.gz/{SECOND_COMMIT}")))
        .respond_with(
            ResponseTemplate::new(200).set_body_bytes(make_tarball_with_files(
                "shared-package",
                "1.0.0",
                &[("index.js", b"module.exports = 'second';\n")],
            )),
        )
        .expect(1)
        .mount(&github)
        .await;

    let project = TempProject::empty(&format!(
        r#"{{
  "name": "github-distinct-commits",
  "version": "1.0.0",
  "dependencies": {{
    "first": "github:owner/shared#{FIRST_COMMIT}",
    "second": "github:owner/shared#{SECOND_COMMIT}"
  }}
}}"#,
    ));
    let output = lpm(&project)
        .env("LPM_GITHUB_CODELOAD_BASE_URL", github.uri())
        .args([
            "install",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("install two commits of one GitHub package");

    assert!(
        output.status.success(),
        "both commits must install\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    assert_eq!(
        project.read_file("node_modules/first/index.js"),
        "module.exports = 'first';\n"
    );
    assert_eq!(
        project.read_file("node_modules/second/index.js"),
        "module.exports = 'second';\n"
    );
    let lockfile = project.read_file("lpm.lock");
    assert!(lockfile.contains(&format!("shared.git#{FIRST_COMMIT}")));
    assert!(lockfile.contains(&format!("shared.git#{SECOND_COMMIT}")));
}

#[tokio::test]
async fn install_github_dependency_writes_deterministic_lockfile_bytes() {
    const COMMIT: &str = "779219540f66cecaa159da32b3b8936697ba10a7";

    let github = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("/rhashimoto/wa-sqlite/tar.gz/{COMMIT}")))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(make_tarball("wa-sqlite", "1.0.9")))
        .expect(2)
        .mount(&github)
        .await;
    let manifest = format!(
        r#"{{
  "name": "github-deterministic-lockfile",
  "version": "1.0.0",
  "dependencies": {{
    "wa-sqlite": "github:rhashimoto/wa-sqlite#{COMMIT}"
  }}
}}"#,
    );
    let first = TempProject::empty(&manifest);
    let second = TempProject::empty(&manifest);

    for project in [&first, &second] {
        let output = lpm(project)
            .env("LPM_GITHUB_CODELOAD_BASE_URL", github.uri())
            .args([
                "install",
                "--no-security-summary",
                "--no-skills",
                "--no-editor-setup",
            ])
            .output()
            .expect("install deterministic GitHub dependency fixture");
        assert!(
            output.status.success(),
            "fixture install must succeed\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
    }

    assert_eq!(first.read_file("lpm.lock"), second.read_file("lpm.lock"));
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
        stderr_compact.contains("publishorvendorthenesteddependencyinstead"),
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

#[test]
fn install_workspace_accepts_utf8_bom_prefixed_member_manifest() {
    let project = TempProject::empty(
        r#"{
  "name": "bom-workspace",
  "version": "1.0.0",
  "private": true,
  "workspaces": ["packages/*"]
}"#,
    );
    project.write_file(
        "packages/bom-member/package.json",
        "\u{feff}{\"name\":\"bom-member\",\"version\":\"1.0.0\"}",
    );

    let output = lpm(&project)
        .args([
            "install",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("run recursive workspace install");

    assert!(
        output.status.success(),
        "recursive install must accept a BOM-prefixed member manifest\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
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

    let root_link = project.path().join("node_modules/foo");
    assert!(
        root_link
            .symlink_metadata()
            .expect("file-deduped workspace member must be linked")
            .file_type()
            .is_symlink(),
        "file-deduped workspace member must be a root symlink"
    );
    let resolved = root_link
        .canonicalize()
        .expect("resolve file-deduped workspace member");
    let links_root = project
        .store_dir()
        .join("v2/links")
        .canonicalize()
        .expect("resolve v2 links root");
    assert!(
        resolved.starts_with(links_root),
        "default v2 install must materialize the workspace source graph in the v2 link store; got {resolved:?}"
    );

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
fn store_v1_rollback_workspace_transitives_link_member_sources_at_root() {
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

    let out = lpm_v1_with_registry(&project, "http://127.0.0.1:1")
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

#[tokio::test]
async fn install_registry_transitive_keeps_registry_and_workspace_instances_separate() {
    let project = TempProject::empty(
        r#"{
  "name": "workspace-external-reentry-root",
  "version": "1.0.0",
  "private": true,
  "workspaces": ["apps/*", "packages/*"]
}"#,
    );
    project.write_file(
        "apps/app/package.json",
        r#"{
  "name": "@smoke/app",
  "version": "1.0.0",
  "dependencies": {
    "@smoke/cycle-a": "workspace:*",
    "external-reentry": "1.0.0"
  }
}"#,
    );
    project.write_file(
        "packages/cycle-a/package.json",
        r#"{
  "name": "@smoke/cycle-a",
  "version": "1.0.0",
  "dependencies": { "@smoke/cycle-b": "workspace:*" }
}"#,
    );
    project.write_file(
        "packages/cycle-a/index.js",
        "module.exports = require('@smoke/cycle-b').name;\n",
    );
    project.write_file(
        "packages/cycle-b/package.json",
        r#"{
  "name": "@smoke/cycle-b",
  "version": "1.0.0",
  "dependencies": { "@smoke/cycle-a": "workspace:*" }
}"#,
    );
    project.write_file(
        "packages/cycle-b/index.js",
        "exports.name = 'workspace-cycle-b';\n",
    );

    let mock = MockRegistry::start().await;
    mock.with_manifest_package(
        serde_json::json!({
            "name": "external-reentry",
            "version": "1.0.0",
            "dependencies": {
                "@smoke/cycle-b": "1.0.0"
            }
        }),
        &[(
            "index.js",
            b"module.exports = require('@smoke/cycle-b').name;\n",
        )],
    )
    .await;
    mock.with_manifest_package(
        serde_json::json!({
            "name": "@smoke/cycle-b",
            "version": "1.0.0",
            "main": "index.js"
        }),
        &[("index.js", b"exports.name = 'registry-cycle-b';\n")],
    )
    .await;

    let mut cmd = lpm_with_registry(&project, &mock.url());
    cmd.current_dir(project.path().join("apps/app"));
    let output = cmd
        .args([
            "install",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("failed to run workspace external re-entry install");

    assert!(
        output.status.success(),
        "install should keep registry and workspace instances separate\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let app_dir = project.path().join("apps/app");
    let cycle_b_link = app_dir.join("node_modules/@smoke/cycle-b");
    let cycle_b_resolved = cycle_b_link
        .canonicalize()
        .unwrap_or_else(|e| panic!("failed to resolve {}: {e}", cycle_b_link.display()));
    let cycle_b_expected = project
        .path()
        .join("packages/cycle-b")
        .canonicalize()
        .expect("resolve workspace cycle-b package");
    assert_eq!(
        cycle_b_resolved, cycle_b_expected,
        "the explicit workspace dependency must still link the local member",
    );

    let runtime = std::process::Command::new("node")
        .args([
            "-e",
            "process.stdout.write(`${require('@smoke/cycle-a')}:${require('external-reentry')}`)",
        ])
        .current_dir(&app_dir)
        .output()
        .expect("run mixed registry and workspace source graph");
    assert!(
        runtime.status.success(),
        "mixed source graph must load\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&runtime.stdout),
        String::from_utf8_lossy(&runtime.stderr),
    );
    assert_eq!(
        String::from_utf8_lossy(&runtime.stdout),
        "workspace-cycle-b:registry-cycle-b",
    );

    let requests = mock
        .server()
        .received_requests()
        .await
        .expect("wiremock request log must be available");
    let cycle_b_requested = requests
        .iter()
        .any(|request| request.url.path().contains("cycle-b"));
    assert!(
        cycle_b_requested,
        "the registry package's dependency must be fetched from the registry\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

async fn assert_registry_transitive_uses_registry_when_workspace_version_does_not_match(
    pubgrub: bool,
) {
    let project = TempProject::empty(
        r#"{
  "name": "workspace-version-mismatch-root",
  "version": "1.0.0",
  "private": true,
  "workspaces": ["apps/*", "packages/*"]
}"#,
    );
    project.write_file(
        "apps/app/package.json",
        r#"{
  "name": "@smoke/app",
  "version": "1.0.0",
  "dependencies": { "external-consumer": "1.0.0" }
}"#,
    );
    project.write_file(
        "packages/shared/package.json",
        r#"{
  "name": "@smoke/shared",
  "version": "2.0.0",
  "main": "index.js"
}"#,
    );
    project.write_file(
        "packages/shared/index.js",
        "module.exports = 'workspace-v2';\n",
    );

    let mock = MockRegistry::start().await;
    mock.with_manifest_package(
        serde_json::json!({
            "name": "external-consumer",
            "version": "1.0.0",
            "main": "index.js",
            "dependencies": { "@smoke/shared": "^1.0.0" }
        }),
        &[("index.js", b"module.exports = require('@smoke/shared');\n")],
    )
    .await;
    mock.with_manifest_package(
        serde_json::json!({
            "name": "@smoke/shared",
            "version": "1.0.0",
            "main": "index.js"
        }),
        &[("index.js", b"module.exports = 'registry-v1';\n")],
    )
    .await;

    let mut cmd = lpm_with_registry(&project, &mock.url());
    cmd.current_dir(project.path().join("apps/app"));
    if pubgrub {
        cmd.env("LPM_RESOLVER", "pubgrub");
        cmd.env("LPM_GREEDY_FUSION", "0");
    }
    let output = cmd
        .args([
            "install",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("run install with a nonmatching workspace package version");

    assert!(
        output.status.success(),
        "registry transitive must resolve a published version when the local workspace member does not satisfy its range\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let runtime = std::process::Command::new("node")
        .args(["-e", "process.stdout.write(require('external-consumer'))"])
        .current_dir(project.path().join("apps/app"))
        .output()
        .expect("run installed registry consumer");
    assert!(
        runtime.status.success(),
        "installed registry consumer must load\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&runtime.stdout),
        String::from_utf8_lossy(&runtime.stderr),
    );
    assert_eq!(String::from_utf8_lossy(&runtime.stdout), "registry-v1");
}

#[tokio::test]
async fn install_registry_transitive_uses_registry_when_workspace_version_does_not_match() {
    assert_registry_transitive_uses_registry_when_workspace_version_does_not_match(false).await;
}

#[tokio::test]
async fn install_pubgrub_registry_transitive_uses_registry_when_workspace_version_does_not_match() {
    assert_registry_transitive_uses_registry_when_workspace_version_does_not_match(true).await;
}

#[tokio::test]
async fn install_registry_transitive_uses_registry_when_workspace_version_matches() {
    let project = TempProject::empty(
        r#"{
  "name": "workspace-source-boundary-root",
  "version": "1.0.0",
  "private": true,
  "workspaces": ["apps/*", "packages/*"]
}"#,
    );
    project.write_file(
        "apps/app/package.json",
        r#"{
  "name": "@smoke/app",
  "version": "1.0.0",
  "dependencies": { "external-consumer": "1.0.0" }
}"#,
    );
    project.write_file(
        "packages/shared/package.json",
        r#"{
  "name": "@smoke/shared",
  "version": "1.0.0",
  "main": "index.js"
}"#,
    );
    project.write_file(
        "packages/shared/index.js",
        "module.exports = 'workspace-v1';\n",
    );

    let mock = MockRegistry::start().await;
    mock.with_manifest_package(
        serde_json::json!({
            "name": "external-consumer",
            "version": "1.0.0",
            "main": "index.js",
            "dependencies": { "@smoke/shared": "1.0.0" }
        }),
        &[("index.js", b"module.exports = require('@smoke/shared');\n")],
    )
    .await;
    mock.with_manifest_package(
        serde_json::json!({
            "name": "@smoke/shared",
            "version": "1.0.0",
            "main": "index.js"
        }),
        &[("index.js", b"module.exports = 'registry-v1';\n")],
    )
    .await;

    let mut cmd = lpm_with_registry(&project, &mock.url());
    cmd.current_dir(project.path().join("apps/app"));
    let output = cmd
        .args([
            "install",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("install registry consumer beside same-version workspace member");

    assert!(
        output.status.success(),
        "registry transitive install must succeed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let runtime = std::process::Command::new("node")
        .args(["-e", "process.stdout.write(require('external-consumer'))"])
        .current_dir(project.path().join("apps/app"))
        .output()
        .expect("run installed registry consumer");
    assert!(
        runtime.status.success(),
        "installed registry consumer must load\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&runtime.stdout),
        String::from_utf8_lossy(&runtime.stderr),
    );
    assert_eq!(String::from_utf8_lossy(&runtime.stdout), "registry-v1");
}

#[tokio::test]
async fn install_registry_transitive_keeps_registry_and_workspace_instances_separate_under_v2_store()
 {
    let project = TempProject::empty(
        r#"{
  "name": "workspace-external-reentry-root",
  "version": "1.0.0",
  "private": true,
  "workspaces": ["apps/*", "packages/*"]
}"#,
    );
    project.write_file(
        "apps/app/package.json",
        r#"{
  "name": "@smoke/app",
  "version": "1.0.0",
  "dependencies": {
    "@smoke/cycle-a": "workspace:*",
    "external-reentry": "1.0.0"
  }
}"#,
    );
    project.write_file(
        "packages/cycle-a/package.json",
        r#"{
  "name": "@smoke/cycle-a",
  "version": "1.0.0",
  "dependencies": { "@smoke/cycle-b": "workspace:*" }
}"#,
    );
    project.write_file(
        "packages/cycle-a/index.js",
        "module.exports = require('@smoke/cycle-b').name;\n",
    );
    project.write_file(
        "packages/cycle-b/package.json",
        r#"{
  "name": "@smoke/cycle-b",
  "version": "1.0.0",
  "dependencies": { "@smoke/cycle-a": "workspace:*" }
}"#,
    );
    project.write_file(
        "packages/cycle-b/index.js",
        "exports.name = 'workspace-cycle-b';\n",
    );

    let mock = MockRegistry::start().await;
    mock.with_manifest_package(
        serde_json::json!({
            "name": "external-reentry",
            "version": "1.0.0",
            "dependencies": {
                "@smoke/cycle-b": "1.0.0"
            }
        }),
        &[(
            "index.js",
            b"module.exports = require('@smoke/cycle-b').name;\n",
        )],
    )
    .await;
    mock.with_manifest_package(
        serde_json::json!({
            "name": "@smoke/cycle-b",
            "version": "1.0.0",
            "main": "index.js"
        }),
        &[("index.js", b"exports.name = 'registry-cycle-b';\n")],
    )
    .await;

    let mut cmd = lpm_with_registry(&project, &mock.url());
    cmd.env("LPM_STORE_VERSION", "v2");
    cmd.current_dir(project.path().join("apps/app"));
    let output = cmd
        .args([
            "install",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("failed to run workspace external re-entry install under v2 store");

    assert!(
        output.status.success(),
        "v2 install should keep registry and workspace instances separate\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let app_dir = project.path().join("apps/app");
    let cycle_b_link = app_dir.join("node_modules/@smoke/cycle-b");
    let cycle_b_resolved = cycle_b_link
        .canonicalize()
        .unwrap_or_else(|e| panic!("failed to resolve {}: {e}", cycle_b_link.display()));
    let cycle_b_expected = project
        .path()
        .join("packages/cycle-b")
        .canonicalize()
        .expect("resolve workspace cycle-b package");
    assert_eq!(
        cycle_b_resolved, cycle_b_expected,
        "v2 install must still root-link the workspace member for direct workspace consumers",
    );

    let runtime = std::process::Command::new("node")
        .args([
            "-e",
            "process.stdout.write(`${require('@smoke/cycle-a')}:${require('external-reentry')}`)",
        ])
        .current_dir(&app_dir)
        .output()
        .expect("run mixed registry and workspace source graph under v2");
    assert!(
        runtime.status.success(),
        "mixed v2 source graph must load\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&runtime.stdout),
        String::from_utf8_lossy(&runtime.stderr),
    );
    assert_eq!(
        String::from_utf8_lossy(&runtime.stdout),
        "workspace-cycle-b:registry-cycle-b",
    );

    let requests = mock
        .server()
        .received_requests()
        .await
        .expect("wiremock request log must be available");
    let cycle_b_requested = requests
        .iter()
        .any(|request| request.url.path().contains("cycle-b"));
    assert!(
        cycle_b_requested,
        "the registry package's v2 dependency must be fetched from the registry\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

#[test]
fn install_workspace_self_dependency_fails_without_writing_artifacts() {
    let project = TempProject::empty(
        r#"{
  "name": "workspace-self-loop-root",
  "version": "1.0.0",
  "private": true,
  "workspaces": ["packages/*"]
}"#,
    );
    project.write_file(
        "packages/self-loop/package.json",
        r#"{
  "name": "@smoke/self-loop",
  "version": "1.0.0",
  "dependencies": {
    "@smoke/self-loop": "workspace:*"
  }
}"#,
    );

    let mut cmd = lpm(&project);
    cmd.current_dir(project.path().join("packages/self-loop"));
    let output = cmd
        .args([
            "install",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("failed to run workspace self-dependency install");

    assert!(
        !output.status.success(),
        "self dependency must fail instead of self-linking\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("depends on itself") || stderr.contains("self-dependency"),
        "error should explain the malformed self-dependency, got:\n{stderr}",
    );
    let member_dir = project.path().join("packages/self-loop");
    assert!(
        !member_dir.join("node_modules/@smoke/self-loop").exists(),
        "self-dependency failure must not create a self-referential node_modules link",
    );
    assert!(
        !member_dir.join("lpm.lock").exists() && !member_dir.join("lpm.lockb").exists(),
        "self-dependency failure must happen before lockfiles are written",
    );
}

#[test]
fn install_workspace_dev_self_dependency_succeeds_without_creating_a_self_link() {
    let project = TempProject::empty(
        r#"{
  "name": "workspace-dev-self-root",
  "version": "1.0.0",
  "private": true,
  "workspaces": ["packages/*"]
}"#,
    );
    project.write_file(
        "packages/dev-self/package.json",
        r#"{
  "name": "@smoke/dev-self",
  "version": "1.0.0",
  "devDependencies": {
    "@smoke/dev-self": "workspace:*"
  }
}"#,
    );

    let mut cmd = lpm(&project);
    cmd.current_dir(project.path().join("packages/dev-self"));
    let output = cmd
        .args([
            "install",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("run workspace dev self-dependency install");

    assert!(
        output.status.success(),
        "a development-only self reference must not make the workspace uninstallable\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    assert!(
        !project
            .path()
            .join("packages/dev-self/node_modules/@smoke/dev-self")
            .exists(),
        "development-only self reference must not create a recursive node_modules link",
    );
}

/// Three-deep chain combining both discovery paths: root → foo via
/// `file:` (F9 path) → bar via `workspace:*` (BFS path) → baz via
/// `workspace:*` (BFS path again). All three must root-symlink. Pre-fix
/// the deepest link (baz) was lost when the BFS started from the
/// extracted top-level set rather than from F9-discovered members.
#[test]
fn store_v1_rollback_file_dedupe_transitives_link_member_sources_at_root() {
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

    let out = lpm_v1_with_registry(&project, "http://127.0.0.1:1")
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

fn workspace_repeat_project() -> TempProject {
    let project = TempProject::empty(
        r#"{
  "name": "ws-repeat-fast-lane",
  "private": true,
  "workspaces": ["packages/*"],
  "dependencies": { "foo": "workspace:*" }
}"#,
    );
    project.write_file(
        "packages/foo/package.json",
        r#"{ "name": "foo", "version": "1.0.0" }"#,
    );
    project
}

#[test]
fn recursive_frozen_replay_accepts_dependency_free_workspace_importer() {
    let project = TempProject::empty(
        r#"{
  "name": "recursive-empty-member",
  "private": true,
  "workspaces": ["packages/*"],
  "dependencies": { "linked-member": "workspace:*" }
}"#,
    );
    project.write_file(
        "packages/linked-member/package.json",
        r#"{ "name": "linked-member", "version": "1.0.0" }"#,
    );
    project.write_file(
        "packages/empty-member/package.json",
        "\u{feff}{\"name\":\"empty-member\",\"version\":\"1.0.0\"}",
    );
    project.write_file("pnpm-workspace.yaml", "packages:\n  - 'packages/*'\n");

    let first = lpm_with_registry(&project, "http://127.0.0.1:1")
        .args([
            "--json",
            "install",
            "--recursive",
            "--timing",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
            "--no-audit-after-install",
        ])
        .output()
        .expect("spawn initial recursive install");
    assert!(
        first.status.success(),
        "initial recursive install failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&first.stdout),
        String::from_utf8_lossy(&first.stderr),
    );

    let empty_lockfile = read_project_lockfile(&project, "packages/empty-member");
    assert!(
        empty_lockfile.importers.contains_key("."),
        "dependency-free workspace projections must record their importer snapshot",
    );

    let replay = lpm_with_registry(&project, "http://127.0.0.1:1")
        .args([
            "--json",
            "install",
            "--recursive",
            "--frozen-lockfile",
            "--timing",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
            "--no-audit-after-install",
        ])
        .output()
        .expect("spawn frozen recursive replay");
    assert!(
        replay.status.success(),
        "frozen recursive replay rejected a dependency-free member lockfile:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&replay.stdout),
        String::from_utf8_lossy(&replay.stderr),
    );
}

#[tokio::test]
async fn recursive_frozen_replay_accepts_parent_relative_workspace_peer_sources() {
    let mock = MockRegistry::start().await;
    mock.with_manifest_package(
        serde_json::json!({
            "name": "peer-consumer",
            "version": "1.0.0",
            "peerDependencies": { "workspace-lib": "^1.0.0" }
        }),
        &[],
    )
    .await;

    let project = TempProject::empty(
        r#"{
  "name": "recursive-frozen-local-sources",
  "private": true,
  "workspaces": ["docs", "packages/*"],
  "dependencies": { "workspace-lib": "workspace:*" }
}"#,
    );
    project.write_file(".npmrc", &format!("registry={}\n", mock.url()));
    project.write_file(
        "docs/package.json",
        r#"{
  "name": "docs",
  "version": "1.0.0",
  "dependencies": { "peer-consumer": "1.0.0" }
}"#,
    );
    project.write_file(
        "packages/workspace-lib/package.json",
        r#"{
  "name": "workspace-lib",
  "version": "1.0.0",
  "dependencies": { "peer-consumer": "1.0.0" }
}"#,
    );

    let first = lpm_with_registry(&project, &mock.url())
        .args([
            "install",
            "--recursive",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("spawn initial recursive install");
    assert!(
        first.status.success(),
        "initial recursive install failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&first.stdout),
        String::from_utf8_lossy(&first.stderr),
    );

    let docs_lockfile = read_project_lockfile(&project, "docs");
    assert!(
        docs_lockfile.packages.iter().any(|package| {
            package.name == "workspace-lib"
                && package.source.as_deref() == Some("directory+../packages/workspace-lib")
        }),
        "docs lockfile should capture the workspace package selected for the peer",
    );
    let member_lockfile = read_project_lockfile(&project, "packages/workspace-lib");
    assert!(
        member_lockfile.packages.iter().any(|package| {
            package.name == "workspace-lib" && package.source.as_deref() == Some("directory+.")
        }),
        "a workspace package selected for its own peer must use a non-empty local source",
    );

    let replay = lpm_with_registry(&project, &mock.url())
        .args([
            "install",
            "--recursive",
            "--frozen-lockfile",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("spawn frozen recursive replay");
    assert!(
        replay.status.success(),
        "frozen recursive replay rejected a workspace source:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&replay.stdout),
        String::from_utf8_lossy(&replay.stderr),
    );
    assert!(
        !String::from_utf8_lossy(&replay.stderr).contains("unsafe source URL"),
        "validated workspace sources must not emit an unsafe-source warning:\n{}",
        String::from_utf8_lossy(&replay.stderr),
    );
}

#[test]
fn recursive_frozen_replay_accepts_aliased_file_workspace_member_identity() {
    let project = TempProject::empty(
        r#"{
  "name": "recursive-aliased-file-member",
  "private": true,
  "workspaces": ["playground/**"]
}"#,
    );
    project.write_file(
        "playground/minify/package.json",
        r#"{
  "name": "@test/minify",
  "version": "0.0.0",
  "dependencies": { "minified-module": "file:./dir/module" }
}"#,
    );
    project.write_file(
        "playground/minify/dir/module/package.json",
        r#"{ "name": "@test/minify", "version": "0.0.0" }"#,
    );

    let initial = lpm_with_registry(&project, "http://127.0.0.1:1")
        .args([
            "install",
            "--recursive",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("spawn initial recursive install");
    assert!(
        initial.status.success(),
        "initial recursive install failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&initial.stdout),
        String::from_utf8_lossy(&initial.stderr),
    );

    let replay = lpm_with_registry(&project, "http://127.0.0.1:1")
        .args([
            "install",
            "--recursive",
            "--frozen-lockfile",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("spawn frozen recursive replay");
    assert!(
        replay.status.success(),
        "frozen recursive replay rejected its aliased local workspace source:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&replay.stdout),
        String::from_utf8_lossy(&replay.stderr),
    );
    assert!(
        !String::from_utf8_lossy(&replay.stderr).contains("unsafe source URL"),
        "validated aliased workspace sources must not emit an unsafe-source warning:\n{}",
        String::from_utf8_lossy(&replay.stderr),
    );

    let lockfile = read_project_lockfile(&project, "playground/minify");
    assert!(
        lockfile.packages.iter().any(|package| {
            package.name == "@test/minify"
                && package.source.as_deref() == Some("directory+dir/module")
        }),
        "the local alias must not replace the package's canonical identity",
    );
}

#[test]
fn recursive_lockfile_records_canonical_alias_for_transitive_file_workspace_member() {
    let project = TempProject::empty(
        r#"{
  "name": "recursive-transitive-file-alias",
  "private": true,
  "workspaces": ["packages/**"]
}"#,
    );
    project.write_file(
        "packages/app/package.json",
        r#"{
  "name": "app",
  "version": "1.0.0",
  "dependencies": { "host": "file:./host" }
}"#,
    );
    project.write_file(
        "packages/app/host/package.json",
        r#"{
  "name": "host",
  "version": "1.0.0",
  "dependencies": { "leaf-alias": "file:../leaf" }
}"#,
    );
    project.write_file(
        "packages/app/leaf/package.json",
        r#"{ "name": "@test/leaf", "version": "1.0.0" }"#,
    );

    let install = lpm_with_registry(&project, "http://127.0.0.1:1")
        .args([
            "install",
            "--recursive",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("spawn recursive install");
    assert!(
        install.status.success(),
        "recursive local-source install failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&install.stdout),
        String::from_utf8_lossy(&install.stderr),
    );

    let lockfile = read_project_lockfile(&project, "packages/app");
    let host = lockfile
        .packages
        .iter()
        .find(|package| package.name == "host")
        .expect("app lockfile should contain the local host package");
    assert!(
        host.alias_dependencies
            .iter()
            .any(|alias| { alias[0] == "leaf-alias" && alias[1] == "@test/leaf" }),
        "the transitive local edge must preserve its local and canonical names: {:?}",
        host.alias_dependencies,
    );
}

#[tokio::test]
async fn recursive_workspace_root_dependency_satisfies_member_transitive_peer() {
    let mock = MockRegistry::start().await;
    mock.with_manifest_package(
        serde_json::json!({
            "name": "peer-provider",
            "version": "1.0.0"
        }),
        &[],
    )
    .await;
    mock.with_manifest_package(
        serde_json::json!({
            "name": "peer-consumer",
            "version": "1.0.0",
            "main": "index.js",
            "peerDependencies": { "peer-provider": "^1.0.0" }
        }),
        &[(
            "index.js",
            b"module.exports = require('peer-provider/package.json').version;\n",
        )],
    )
    .await;

    let project = TempProject::empty(
        r#"{
  "name": "workspace-root-peer-provider",
  "private": true,
  "workspaces": ["app"],
  "dependencies": { "peer-provider": "1.0.0" },
  "lpm": { "autoInstallPeers": false }
}"#,
    );
    project.write_file(
        "app/package.json",
        r#"{
  "name": "workspace-member-peer-consumer",
  "private": true,
  "dependencies": { "peer-consumer": "1.0.0" },
  "lpm": { "autoInstallPeers": false }
}"#,
    );

    let install = lpm_with_registry(&project, &mock.url())
        .args([
            "install",
            "--recursive",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("spawn recursive install");
    assert!(
        install.status.success(),
        "recursive install should succeed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&install.stdout),
        String::from_utf8_lossy(&install.stderr),
    );

    let member_lockfile = read_project_lockfile(&project, "app");
    let consumer = member_lockfile
        .packages
        .iter()
        .find(|package| package.name == "peer-consumer")
        .expect("member lockfile should contain peer-consumer");
    assert_eq!(
        consumer.peers,
        vec!["peer-provider@1.0.0"],
        "the workspace root dependency must be recorded as the member consumer's peer context",
    );

    let runtime = std::process::Command::new("node")
        .current_dir(project.path().join("app"))
        .arg("-e")
        .arg("process.stdout.write(require('peer-consumer'))")
        .output()
        .expect("run member peer consumer");
    assert!(
        runtime.status.success(),
        "member consumer should resolve the workspace root peer\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&runtime.stdout),
        String::from_utf8_lossy(&runtime.stderr),
    );
    assert_eq!(String::from_utf8_lossy(&runtime.stdout), "1.0.0");
}

#[tokio::test]
async fn recursive_workspace_root_local_dependency_satisfies_member_transitive_peer() {
    let mock = MockRegistry::start().await;
    mock.with_manifest_package(
        serde_json::json!({
            "name": "provider-child",
            "version": "1.0.0"
        }),
        &[],
    )
    .await;
    mock.with_manifest_package(
        serde_json::json!({
            "name": "peer-consumer",
            "version": "1.0.0",
            "main": "index.js",
            "peerDependencies": { "workspace-provider": "^1.0.0" }
        }),
        &[(
            "index.js",
            b"module.exports = require('workspace-provider/package.json').version;\n",
        )],
    )
    .await;

    let project = TempProject::empty(
        r#"{
  "name": "workspace-root-local-peer-provider",
  "private": true,
  "workspaces": ["app", "packages/*"],
  "dependencies": { "workspace-provider": "workspace:*" },
  "lpm": { "autoInstallPeers": false }
}"#,
    );
    project.write_file(
        "app/package.json",
        r#"{
  "name": "workspace-member-local-peer-consumer",
  "private": true,
  "dependencies": { "peer-consumer": "1.0.0" },
  "lpm": { "autoInstallPeers": false }
}"#,
    );
    project.write_file(
        "packages/workspace-provider/package.json",
        r#"{
  "name": "workspace-provider",
  "version": "1.0.0",
  "dependencies": { "provider-child": "1.0.0" }
}"#,
    );

    let install = lpm_with_registry(&project, &mock.url())
        .args([
            "install",
            "--recursive",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("spawn recursive install");
    assert!(
        install.status.success(),
        "recursive install should rebase the root's workspace peer provider\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&install.stdout),
        String::from_utf8_lossy(&install.stderr),
    );

    let member_lockfile = read_project_lockfile(&project, "app");
    let provider = member_lockfile
        .packages
        .iter()
        .find(|package| package.name == "workspace-provider")
        .expect("member lockfile should contain the root workspace peer provider");
    assert_eq!(
        provider.source.as_deref(),
        Some("directory+../packages/workspace-provider"),
    );

    let runtime = std::process::Command::new("node")
        .current_dir(project.path().join("app"))
        .arg("-e")
        .arg("process.stdout.write(require('peer-consumer'))")
        .output()
        .expect("run member peer consumer");
    assert!(
        runtime.status.success(),
        "member consumer should resolve the root workspace peer\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&runtime.stdout),
        String::from_utf8_lossy(&runtime.stderr),
    );
    assert_eq!(String::from_utf8_lossy(&runtime.stdout), "1.0.0");

    let replay = lpm_with_registry(&project, &mock.url())
        .args([
            "install",
            "--recursive",
            "--frozen-lockfile",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("spawn frozen recursive replay");
    assert!(
        replay.status.success(),
        "frozen replay should reconstruct the root workspace provider fingerprint\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&replay.stdout),
        String::from_utf8_lossy(&replay.stderr),
    );
}

#[tokio::test]
async fn recursive_workspace_root_local_dependency_closure_satisfies_member_transitive_peer() {
    let mock = MockRegistry::start().await;
    mock.with_manifest_package(
        serde_json::json!({
            "name": "provider-child",
            "version": "1.0.0"
        }),
        &[],
    )
    .await;
    mock.with_manifest_package(
        serde_json::json!({
            "name": "peer-consumer",
            "version": "1.0.0",
            "main": "index.js",
            "peerDependencies": { "provider-child": "^1.0.0" }
        }),
        &[(
            "index.js",
            b"module.exports = require('provider-child/package.json').version;\n",
        )],
    )
    .await;

    let project = TempProject::empty(
        r#"{
  "name": "workspace-root-local-peer-provider-closure",
  "private": true,
  "workspaces": ["app", "packages/*"],
  "dependencies": { "workspace-provider": "workspace:*" },
  "lpm": { "autoInstallPeers": false }
}"#,
    );
    project.write_file(
        "app/package.json",
        r#"{
  "name": "workspace-member-local-peer-consumer-closure",
  "private": true,
  "dependencies": { "peer-consumer": "1.0.0" },
  "lpm": {
    "autoInstallPeers": false,
    "strictPeerDependencies": true
  }
}"#,
    );
    project.write_file(
        "packages/workspace-provider/package.json",
        r#"{
  "name": "workspace-provider",
  "version": "1.0.0",
  "dependencies": { "provider-child": "1.0.0" }
}"#,
    );

    let install = lpm_with_registry(&project, &mock.url())
        .args([
            "install",
            "--recursive",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("spawn recursive install");
    assert!(
        install.status.success(),
        "recursive install should expose the root local provider's closure as peer context\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&install.stdout),
        String::from_utf8_lossy(&install.stderr),
    );

    let member_lockfile = read_project_lockfile(&project, "app");
    let consumer = member_lockfile
        .packages
        .iter()
        .find(|package| package.name == "peer-consumer")
        .expect("member lockfile should contain peer-consumer");
    assert_eq!(consumer.peers, vec!["provider-child@1.0.0"]);

    let runtime = std::process::Command::new("node")
        .current_dir(project.path().join("app"))
        .arg("-e")
        .arg("process.stdout.write(require('peer-consumer'))")
        .output()
        .expect("run member peer consumer");
    assert!(
        runtime.status.success(),
        "member consumer should resolve the root provider closure\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&runtime.stdout),
        String::from_utf8_lossy(&runtime.stderr),
    );
    assert_eq!(String::from_utf8_lossy(&runtime.stdout), "1.0.0");
}

#[tokio::test]
async fn recursive_workspace_root_peer_context_replays_frozen_and_offline() {
    let mock = MockRegistry::start().await;
    mock.with_manifest_package(
        serde_json::json!({ "name": "peer-provider", "version": "1.0.0" }),
        &[],
    )
    .await;
    mock.with_manifest_package(
        serde_json::json!({
            "name": "peer-consumer",
            "version": "1.0.0",
            "main": "index.js",
            "peerDependencies": { "peer-provider": "^1.0.0" }
        }),
        &[(
            "index.js",
            b"module.exports = require('peer-provider/package.json').version;\n",
        )],
    )
    .await;

    let project = TempProject::empty(
        r#"{
  "name": "workspace-root-peer-replay",
  "private": true,
  "workspaces": ["app", "empty"],
  "dependencies": { "peer-provider": "1.0.0" },
  "lpm": { "autoInstallPeers": false }
}"#,
    );
    project.write_file(
        "app/package.json",
        r#"{
  "name": "workspace-member-peer-replay",
  "private": true,
  "dependencies": {
    "local-helper": "file:./local-helper",
    "peer-consumer": "1.0.0"
  },
  "lpm": { "autoInstallPeers": false }
}"#,
    );
    project.write_file(
        "app/local-helper/package.json",
        r#"{
  "name": "local-helper",
  "version": "1.0.0"
}"#,
    );
    project.write_file(
        "empty/package.json",
        r#"{
  "name": "workspace-member-without-root-peer-context",
  "private": true
}"#,
    );

    let first = lpm_with_registry(&project, &mock.url())
        .args([
            "install",
            "--recursive",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("spawn initial recursive install");
    assert!(
        first.status.success(),
        "initial recursive install should succeed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&first.stdout),
        String::from_utf8_lossy(&first.stderr),
    );
    std::fs::remove_dir_all(project.path().join("node_modules"))
        .expect("remove root materialization");
    std::fs::remove_dir_all(project.path().join("app/node_modules"))
        .expect("remove member materialization");

    let replay = lpm_with_registry(&project, &mock.url())
        .args([
            "install",
            "--recursive",
            "--offline",
            "--frozen-lockfile",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("spawn frozen offline recursive replay");
    assert!(
        replay.status.success(),
        "frozen offline recursive replay should succeed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&replay.stdout),
        String::from_utf8_lossy(&replay.stderr),
    );

    let runtime = std::process::Command::new("node")
        .current_dir(project.path().join("app"))
        .arg("-e")
        .arg("process.stdout.write(require('peer-consumer'))")
        .output()
        .expect("run replayed member peer consumer");
    assert!(
        runtime.status.success(),
        "replayed member consumer should resolve the root peer\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&runtime.stdout),
        String::from_utf8_lossy(&runtime.stderr),
    );
    assert_eq!(String::from_utf8_lossy(&runtime.stdout), "1.0.0");
}

#[tokio::test]
async fn recursive_workspace_root_provider_change_invalidates_member_peer_context() {
    let mock = MockRegistry::start().await;
    let provider_v1 = make_tarball_from_pkg_json(
        serde_json::json!({ "name": "peer-provider", "version": "1.0.0" }),
        &[],
    );
    let provider_v2 = make_tarball_from_pkg_json(
        serde_json::json!({ "name": "peer-provider", "version": "2.0.0" }),
        &[],
    );
    let provider_v1_integrity = compute_integrity(&provider_v1);
    let provider_v2_integrity = compute_integrity(&provider_v2);
    mock.with_package_metadata_and_tarballs(
        "peer-provider",
        serde_json::json!({
            "name": "peer-provider",
            "dist-tags": { "latest": "2.0.0" },
            "versions": {
                "1.0.0": {
                    "name": "peer-provider",
                    "version": "1.0.0",
                    "dist": {
                        "tarball": mock.tarball_url("peer-provider", "1.0.0"),
                        "integrity": provider_v1_integrity
                    }
                },
                "2.0.0": {
                    "name": "peer-provider",
                    "version": "2.0.0",
                    "dist": {
                        "tarball": mock.tarball_url("peer-provider", "2.0.0"),
                        "integrity": provider_v2_integrity
                    }
                }
            },
            "time": {
                "1.0.0": "2025-01-01T00:00:00.000Z",
                "2.0.0": "2025-01-02T00:00:00.000Z"
            }
        }),
        &[("1.0.0", provider_v1), ("2.0.0", provider_v2)],
    )
    .await;
    mock.with_manifest_package(
        serde_json::json!({
            "name": "peer-consumer",
            "version": "1.0.0",
            "main": "index.js",
            "peerDependencies": { "peer-provider": ">=1.0.0 <3.0.0" }
        }),
        &[(
            "index.js",
            b"module.exports = require('peer-provider/package.json').version;\n",
        )],
    )
    .await;

    let project = TempProject::empty(
        r#"{
  "name": "workspace-root-peer-change",
  "private": true,
  "workspaces": ["app"],
  "dependencies": { "peer-provider": "1.0.0" },
  "lpm": { "autoInstallPeers": false }
}"#,
    );
    project.write_file(
        "app/package.json",
        r#"{
  "name": "workspace-member-peer-change",
  "private": true,
  "dependencies": { "peer-consumer": "1.0.0" },
  "lpm": { "autoInstallPeers": false }
}"#,
    );
    let first = lpm_with_registry(&project, &mock.url())
        .args([
            "install",
            "--recursive",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("spawn initial recursive install");
    assert!(
        first.status.success(),
        "initial recursive install should succeed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&first.stdout),
        String::from_utf8_lossy(&first.stderr),
    );

    project.write_file(
        "package.json",
        r#"{
  "name": "workspace-root-peer-change",
  "description": "provider changed",
  "private": true,
  "workspaces": ["app"],
  "dependencies": { "peer-provider": "2.0.0" },
  "lpm": { "autoInstallPeers": false }
}"#,
    );
    let second = lpm_with_registry(&project, &mock.url())
        .args([
            "install",
            "--recursive",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("spawn recursive install after root provider change");
    assert!(
        second.status.success(),
        "recursive install should reconcile the changed root provider\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&second.stdout),
        String::from_utf8_lossy(&second.stderr),
    );

    let root_lockfile = read_project_lockfile(&project, "");
    assert!(
        root_lockfile
            .packages
            .iter()
            .any(|package| package.name == "peer-provider" && package.version == "2.0.0"),
        "root lockfile should select the changed provider: {:#?}",
        root_lockfile
            .packages
            .iter()
            .filter(|package| package.name == "peer-provider")
            .map(|package| package.version.as_str())
            .collect::<Vec<_>>(),
    );
    let member_lockfile = read_project_lockfile(&project, "app");
    let consumer = member_lockfile
        .packages
        .iter()
        .find(|package| package.name == "peer-consumer")
        .expect("member lockfile should contain peer-consumer");
    assert_eq!(consumer.peers, vec!["peer-provider@2.0.0"]);
}

#[tokio::test]
async fn recursive_workspace_root_provider_outside_peer_range_remains_strict_error() {
    let mock = MockRegistry::start().await;
    mock.with_manifest_package(
        serde_json::json!({ "name": "peer-provider", "version": "2.0.0" }),
        &[],
    )
    .await;
    mock.with_manifest_package(
        serde_json::json!({
            "name": "peer-consumer",
            "version": "1.0.0",
            "peerDependencies": { "peer-provider": "^1.0.0" }
        }),
        &[],
    )
    .await;
    let project = TempProject::empty(
        r#"{
  "name": "workspace-root-peer-out-of-range",
  "private": true,
  "workspaces": ["app"],
  "dependencies": { "peer-provider": "2.0.0" },
  "lpm": { "autoInstallPeers": false }
}"#,
    );
    project.write_file(
        "app/package.json",
        r#"{
  "name": "workspace-member-peer-out-of-range",
  "private": true,
  "dependencies": { "peer-consumer": "1.0.0" },
  "lpm": { "autoInstallPeers": false, "strictPeerDependencies": true }
}"#,
    );

    let install = lpm_with_registry(&project, &mock.url())
        .args([
            "install",
            "--recursive",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("spawn strict recursive install");
    assert!(
        !install.status.success(),
        "an out-of-range root provider must not satisfy the member peer"
    );
    assert!(
        String::from_utf8_lossy(&install.stderr).contains("strict-peer-dependencies failed"),
        "strict peer failure should remain visible:\n{}",
        String::from_utf8_lossy(&install.stderr),
    );
}

#[tokio::test]
async fn recursive_workspace_root_provider_closure_preserves_root_override_context() {
    let mock = MockRegistry::start().await;
    let child_v1 = make_tarball_from_pkg_json(
        serde_json::json!({ "name": "provider-child", "version": "1.0.0" }),
        &[],
    );
    let child_v2 = make_tarball_from_pkg_json(
        serde_json::json!({ "name": "provider-child", "version": "2.0.0" }),
        &[],
    );
    let child_v1_integrity = compute_integrity(&child_v1);
    let child_v2_integrity = compute_integrity(&child_v2);
    mock.with_package_metadata_and_tarballs(
        "provider-child",
        serde_json::json!({
            "name": "provider-child",
            "dist-tags": { "latest": "2.0.0" },
            "versions": {
                "1.0.0": {
                    "name": "provider-child",
                    "version": "1.0.0",
                    "dist": {
                        "tarball": mock.tarball_url("provider-child", "1.0.0"),
                        "integrity": child_v1_integrity
                    }
                },
                "2.0.0": {
                    "name": "provider-child",
                    "version": "2.0.0",
                    "dist": {
                        "tarball": mock.tarball_url("provider-child", "2.0.0"),
                        "integrity": child_v2_integrity
                    }
                }
            },
            "time": {
                "1.0.0": "2025-01-01T00:00:00.000Z",
                "2.0.0": "2025-01-02T00:00:00.000Z"
            }
        }),
        &[("1.0.0", child_v1), ("2.0.0", child_v2)],
    )
    .await;
    mock.with_manifest_package(
        serde_json::json!({
            "name": "peer-provider",
            "version": "1.0.0",
            "dependencies": { "provider-child": "*" }
        }),
        &[],
    )
    .await;
    mock.with_manifest_package(
        serde_json::json!({
            "name": "peer-consumer",
            "version": "1.0.0",
            "peerDependencies": { "peer-provider": "^1.0.0" }
        }),
        &[],
    )
    .await;

    let project = TempProject::empty(
        r#"{
  "name": "workspace-root-peer-override",
  "private": true,
  "workspaces": ["app"],
  "dependencies": { "peer-provider": "1.0.0" },
  "lpm": {
    "autoInstallPeers": false,
    "overrides": { "provider-child": "1.0.0" }
  }
}"#,
    );
    project.write_file(
        "app/package.json",
        r#"{
  "name": "workspace-member-peer-override",
  "private": true,
  "dependencies": { "peer-consumer": "1.0.0" },
  "lpm": {
    "autoInstallPeers": false,
    "overrides": { "provider-child": "2.0.0" }
  }
}"#,
    );

    let install = lpm_with_registry(&project, &mock.url())
        .args([
            "install",
            "--recursive",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("spawn recursive install with importer-specific overrides");
    assert!(
        install.status.success(),
        "recursive install should preserve the root provider closure\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&install.stdout),
        String::from_utf8_lossy(&install.stderr),
    );

    let member_lockfile = read_project_lockfile(&project, "app");
    let provider = member_lockfile
        .packages
        .iter()
        .find(|package| package.name == "peer-provider")
        .expect("member lockfile should contain the root peer provider");
    assert_eq!(provider.dependencies, vec!["provider-child@1.0.0"]);
    assert!(
        member_lockfile
            .packages
            .iter()
            .any(|package| { package.name == "provider-child" && package.version == "1.0.0" }),
        "member graph should import the child selected under the root override",
    );
}

#[tokio::test]
async fn recursive_workspace_root_provider_closure_preserves_registry_route_context() {
    let root_registry = MockRegistry::start().await;
    let member_registry = MockRegistry::start().await;
    root_registry
        .with_manifest_package(
            serde_json::json!({ "name": "peer-provider", "version": "1.0.0" }),
            &[],
        )
        .await;
    member_registry
        .with_manifest_package(
            serde_json::json!({
                "name": "peer-consumer",
                "version": "1.0.0",
                "peerDependencies": { "peer-provider": "^1.0.0" }
            }),
            &[],
        )
        .await;

    let project = TempProject::empty(
        r#"{
  "name": "workspace-root-peer-route",
  "private": true,
  "workspaces": ["app"],
  "dependencies": { "peer-provider": "1.0.0" },
  "lpm": { "autoInstallPeers": false }
}"#,
    );
    project.write_file(".npmrc", &format!("registry={}\n", root_registry.url()));
    project.write_file(
        "app/.npmrc",
        &format!("registry={}\n", member_registry.url()),
    );
    project.write_file(
        "app/package.json",
        r#"{
  "name": "workspace-member-peer-route",
  "private": true,
  "dependencies": { "peer-consumer": "1.0.0" },
  "lpm": { "autoInstallPeers": false }
}"#,
    );

    let install = lpm_with_registry(&project, &root_registry.url())
        .args([
            "install",
            "--recursive",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("spawn recursive install with importer-specific routes");
    assert!(
        install.status.success(),
        "recursive install should preserve importer registry routes\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&install.stdout),
        String::from_utf8_lossy(&install.stderr),
    );

    let member_lockfile = read_project_lockfile(&project, "app");
    let provider = member_lockfile
        .packages
        .iter()
        .find(|package| package.name == "peer-provider")
        .expect("member lockfile should contain the root peer provider");
    let consumer = member_lockfile
        .packages
        .iter()
        .find(|package| package.name == "peer-consumer")
        .expect("member lockfile should contain its direct consumer");
    assert_eq!(
        provider.source.as_deref(),
        Some(format!("registry+{}", root_registry.url()).as_str()),
    );
    assert_eq!(
        consumer.source.as_deref(),
        Some(format!("registry+{}", member_registry.url()).as_str()),
    );
}

#[tokio::test]
async fn recursive_frozen_replay_ignores_registry_roots_injected_by_workspace_source_expansion() {
    let mock = MockRegistry::start().await;
    mock.with_manifest_package(
        serde_json::json!({ "name": "external-dependency", "version": "1.0.0" }),
        &[],
    )
    .await;

    let project = TempProject::empty(
        r#"{
  "name": "workspace-source-expansion-root",
  "private": true,
  "workspaces": ["app", "packages/*"],
  "dependencies": { "workspace-host": "workspace:*" }
}"#,
    );
    project.write_file(
        "app/package.json",
        r#"{
  "name": "app",
  "version": "1.0.0",
  "dependencies": {
    "external-dependency": "1.0.0",
    "workspace-host": "workspace:*",
    "workspace-plugin": "workspace:*"
  }
}"#,
    );
    project.write_file(
        "packages/workspace-host/package.json",
        r#"{ "name": "workspace-host", "version": "1.0.0" }"#,
    );
    project.write_file(
        "packages/workspace-plugin/package.json",
        r#"{
  "name": "workspace-plugin",
  "version": "1.0.0",
  "peerDependencies": { "workspace-host": "^1.0.0" }
}"#,
    );

    let first = lpm_with_registry(&project, &mock.url())
        .args([
            "install",
            "--recursive",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("spawn initial recursive install");
    assert!(
        first.status.success(),
        "initial recursive install failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&first.stdout),
        String::from_utf8_lossy(&first.stderr),
    );

    for node_modules in [
        project.path().join("node_modules"),
        project.path().join("app/node_modules"),
        project.path().join("packages/workspace-host/node_modules"),
        project
            .path()
            .join("packages/workspace-plugin/node_modules"),
    ] {
        if node_modules.exists() {
            std::fs::remove_dir_all(node_modules).expect("remove installed workspace layout");
        }
    }

    let replay = lpm_with_registry(&project, &mock.url())
        .args([
            "install",
            "--recursive",
            "--frozen-lockfile",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("spawn frozen recursive replay");
    assert!(
        replay.status.success(),
        "frozen replay treated an expanded workspace peer as a registry root:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&replay.stdout),
        String::from_utf8_lossy(&replay.stderr),
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

#[test]
fn workspace_repeat_install_reports_the_recursive_target_count() {
    let project = workspace_repeat_project();

    let first = lpm(&project)
        .args(WORKSPACE_INSTALL_FLAGS)
        .output()
        .expect("spawn lpm install (first)");
    assert!(
        first.status.success(),
        "first install failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&first.stdout),
        String::from_utf8_lossy(&first.stderr),
    );

    let second = lpm(&project)
        .arg("install")
        .output()
        .expect("spawn lpm install (second)");
    assert!(
        second.status.success(),
        "second install failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&second.stdout),
        String::from_utf8_lossy(&second.stderr),
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&second.stdout),
        String::from_utf8_lossy(&second.stderr),
    );
    assert!(
        combined.contains("Installed 2 workspace packages"),
        "unchanged workspace repeat install should retain recursive orchestration; got:\n{combined}"
    );
}

#[test]
fn workspace_repeat_install_json_keeps_the_recursive_workspace_envelope() {
    let project = workspace_repeat_project();

    let first = lpm(&project)
        .args(WORKSPACE_INSTALL_FLAGS)
        .output()
        .expect("spawn lpm install (first)");
    assert!(
        first.status.success(),
        "first install failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&first.stdout),
        String::from_utf8_lossy(&first.stderr),
    );

    let second = lpm(&project)
        .args(["--json", "install"])
        .output()
        .expect("spawn lpm install --json (second)");
    assert!(
        second.status.success(),
        "second install --json failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&second.stdout),
        String::from_utf8_lossy(&second.stderr),
    );
    let envelope: serde_json::Value =
        serde_json::from_slice(&second.stdout).expect("install --json must emit JSON");
    assert_eq!(envelope["success"], true);
    assert_eq!(envelope["recursive"], true);
    assert_eq!(envelope["summary"]["total"], 2);
    assert_eq!(
        envelope["targets"].as_array().map(std::vec::Vec::len),
        Some(2),
        "workspace --json repeat install must report each recursive target; got:\n{envelope}"
    );
}

#[test]
fn recursive_install_timing_distinguishes_command_work_from_target_observations() {
    let project = workspace_repeat_project();

    let output = lpm(&project)
        .env("LPM_TIMING_DETAIL", "trace")
        .args([
            "install",
            "--json",
            "--timing",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("spawn recursive lpm install with timing");
    assert!(
        output.status.success(),
        "recursive timing install failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let envelope: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("recursive install timing must emit JSON");
    assert_eq!(envelope["timing"]["scope"], "recursive_command");
    assert_eq!(envelope["timing"]["work_is_cumulative"], true);
    assert_eq!(
        envelope["timing"]["phase_aggregation"],
        "sum_of_target_wall_clock"
    );
    assert_eq!(envelope["counts"]["scope"], "recursive_command");
    assert_eq!(
        envelope["counts"]["aggregation"],
        "sum_of_target_observations"
    );
    assert_eq!(
        envelope["counts"]["store_reuse_may_include_same_command_population"],
        true
    );
    assert!(
        envelope["timing"]["process"]["registry"].is_object(),
        "recursive process-wide registry metrics must be reported once at the command root: \
         {envelope:#}"
    );

    let targets = envelope["targets"]
        .as_array()
        .expect("recursive envelope must contain targets");
    assert!(
        !targets.is_empty(),
        "recursive envelope must report targets"
    );
    for target in targets {
        assert_eq!(target["counts"]["scope"], "target");
        assert_eq!(target["timing"]["scope"], "target");
        assert_eq!(target["timing"]["work_is_cumulative"], false);
        assert_eq!(target["timing"]["phase_aggregation"], "target_wall_clock");
        assert!(
            target["timing"]["waterfall"]["materialization_wait_ms"].is_number(),
            "target timing must separate serialized materialization waiting from command work: \
             {target:#}"
        );
        assert!(
            target["timing"]["waterfall"]["commit_wait_ms"].is_number(),
            "target timing must separate importer commit waiting from post-resolve work: \
             {target:#}"
        );
        assert_eq!(
            target["timing"]["process_global_metrics"]["reported_at"],
            "timing.process"
        );
        assert!(
            target["timing"]["detail"].get("metadata").is_none(),
            "process-global metadata must not be repeated as target-local data: {target:#}"
        );
    }

    assert_eq!(
        envelope["timing"]["work"]["resolver_substage_sums"]["aggregation"],
        "sum_of_resolver_pass_work"
    );

    let contract = serde_json::json!({
        "timing": {
            "scope": envelope["timing"]["scope"],
            "work_is_cumulative": envelope["timing"]["work_is_cumulative"],
            "phase_aggregation": envelope["timing"]["phase_aggregation"],
            "work": envelope["timing"]["work"],
            "wait": envelope["timing"]["wait"],
            "process_scope": envelope["timing"]["process"]["scope"],
        },
        "counts": envelope["counts"],
        "target": {
            "counts": targets[0]["counts"],
            "timing_scope": targets[0]["timing"]["scope"],
            "work_is_cumulative": targets[0]["timing"]["work_is_cumulative"],
            "phase_aggregation": targets[0]["timing"]["phase_aggregation"],
            "waterfall": {
                "materialization_wait_ms":
                    targets[0]["timing"]["waterfall"]["materialization_wait_ms"],
                "commit_wait_ms": targets[0]["timing"]["waterfall"]["commit_wait_ms"],
                "post_resolve_work_ms":
                    targets[0]["timing"]["waterfall"]["post_resolve_work_ms"],
                "pre_fetch_ms": targets[0]["timing"]["waterfall"]["pre_fetch_ms"],
            },
            "process_global_metrics": targets[0]["timing"]["process_global_metrics"],
        },
    });
    insta::assert_json_snapshot!("recursive_install_timing_semantics", contract, {
        ".timing.work.target_resolve_sum_ms" => "[DURATION]",
        ".timing.work.target_post_resolve_sum_ms" => "[DURATION]",
        ".timing.work.target_fetch_sum_ms" => "[DURATION]",
        ".timing.work.target_link_sum_ms" => "[DURATION]",
        ".timing.work.resolver_substage_sums.tree_policy_ms" => "[DURATION]",
        ".timing.work.resolver_substage_sums.policy_hydration_ms" => "[DURATION]",
        ".timing.work.resolver_substage_sums.manifest_wait_ms" => "[DURATION]",
        ".timing.work.resolver_substage_sums.edge_expansion_ms" => "[DURATION]",
        ".timing.work.resolver_substage_sums.graph_finalization_ms" => "[DURATION]",
        ".timing.wait.target_materialization_sum_ms" => "[DURATION]",
        ".timing.wait.target_commit_sum_ms" => "[DURATION]",
        ".target.waterfall.materialization_wait_ms" => "[DURATION]",
        ".target.waterfall.commit_wait_ms" => "[DURATION]",
        ".target.waterfall.post_resolve_work_ms" => "[DURATION]",
        ".target.waterfall.pre_fetch_ms" => "[DURATION]",
    });
}

#[tokio::test]
async fn recursive_install_does_not_commit_any_importer_when_preparation_fails() {
    let project = TempProject::empty(
        r#"{
  "name": "workspace-atomic-prepare-root",
  "version": "1.0.0",
  "private": true,
  "workspaces": ["packages/*"]
}"#,
    );
    project.write_file(
        "packages/a-valid/package.json",
        r#"{
  "name": "a-valid",
  "version": "1.0.0",
  "dependencies": { "valid-dependency": "1.0.0" }
}"#,
    );
    project.write_file(
        "packages/z-failing/package.json",
        r#"{
  "name": "z-failing",
  "version": "1.0.0",
  "dependencies": { "missing-tarball": "1.0.0" }
}"#,
    );
    project.write_file(
        "packages/z-failing/.lpm/wrappers/stale@1.0.0/ghost",
        "existing project state",
    );
    project.write_file(
        "packages/a-valid/node_modules/.lpm/legacy@1.0.0/node_modules/legacy/package.json",
        r#"{"name":"legacy","version":"1.0.0"}"#,
    );
    project.write_file("packages/a-valid/.gitignore", "existing-ignore\n");

    let mock = MockRegistry::start().await;
    let valid_tarball = make_tarball("valid-dependency", "1.0.0");
    mock.with_package("valid-dependency", "1.0.0", &valid_tarball)
        .await;
    mock.with_full_package_metadata(
        "missing-tarball",
        "1.0.0",
        &[("1.0.0", serde_json::json!({}), None)],
    )
    .await;

    let output = lpm_with_registry(&project, &mock.url())
        .env("LPM_STORE_VERSION", "v2")
        .args([
            "install",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("spawn recursive install with one failing importer");

    assert!(
        !output.status.success(),
        "recursive install must fail when one importer cannot prepare\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    for importer in ["packages/z-failing", ""] {
        let importer_dir = project.path().join(importer);
        assert!(
            !importer_dir.join("node_modules").exists(),
            "preparation failure must not commit node_modules for {}",
            importer_dir.display()
        );
        assert!(
            !importer_dir.join("lpm.lock").exists() && !importer_dir.join("lpm.lockb").exists(),
            "preparation failure must not commit lockfiles for {}",
            importer_dir.display()
        );
    }
    let valid_importer = project.path().join("packages/a-valid");
    assert!(
        !valid_importer
            .join("node_modules/valid-dependency")
            .exists(),
        "preparation failure must not link the prepared dependency"
    );
    assert!(
        !valid_importer.join("lpm.lock").exists() && !valid_importer.join("lpm.lockb").exists(),
        "preparation failure must not commit the valid importer's lockfiles"
    );
    assert_eq!(
        std::fs::read_to_string(
            project
                .path()
                .join("packages/z-failing/.lpm/wrappers/stale@1.0.0/ghost")
        )
        .expect("preparation failure must preserve existing project state"),
        "existing project state"
    );
    assert!(
        valid_importer
            .join("node_modules/.lpm/legacy@1.0.0/node_modules/legacy/package.json")
            .exists(),
        "preparation failure must preserve the existing linker layout"
    );
    assert_eq!(
        std::fs::read_to_string(valid_importer.join(".gitignore"))
            .expect("preparation failure must preserve the existing gitignore"),
        "existing-ignore\n"
    );
}

#[tokio::test]
async fn recursive_install_rolls_back_non_union_importer_when_later_importer_fails() {
    let project = TempProject::empty(
        r#"{
  "name": "workspace-non-union-rollback-root",
  "version": "1.0.0",
  "private": true,
  "workspaces": ["packages/*"],
  "dependencies": { "valid-dependency": "1.0.0" }
}"#,
    );
    project.write_file(
        "packages/union-participant/package.json",
        r#"{
  "name": "union-participant",
  "version": "1.0.0",
  "dependencies": { "valid-dependency": "1.0.0" }
}"#,
    );
    project.write_file(
        "packages/a-stateful/package.json",
        r#"{
  "name": "a-stateful",
  "version": "1.0.0"
}"#,
    );
    project.write_file(
        "packages/a-stateful/.lpm/install-hash",
        "original-install-hash",
    );
    project.write_file(
        "packages/z-failing/package.json",
        r#"{
  "name": "z-failing",
  "version": "1.0.0",
  "dependencies": {
    "a-stateful": "workspace:*",
    "missing-local": "file:./missing.tgz"
  }
}"#,
    );

    let mock = MockRegistry::start().await;
    let valid_tarball = make_tarball("valid-dependency", "1.0.0");
    mock.with_package("valid-dependency", "1.0.0", &valid_tarball)
        .await;

    let output = lpm_with_registry(&project, &mock.url())
        .env("LPM_STORE_VERSION", "v2")
        .args([
            "install",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("spawn recursive install with a later non-union failure");

    assert!(
        !output.status.success(),
        "recursive install must fail for the missing local tarball\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    assert_eq!(
        std::fs::read_to_string(project.path().join("packages/a-stateful/.lpm/install-hash"))
            .expect("read restored install hash"),
        "original-install-hash",
        "a successful non-union importer must roll back when a later importer fails"
    );
}

#[tokio::test]
async fn recursive_resolve_ahead_matches_sequential_lockfile_bytes() {
    fn workspace_fixture() -> TempProject {
        let project = TempProject::empty(
            r#"{
  "name": "recursive-determinism-root",
  "version": "1.0.0",
  "private": true,
  "workspaces": ["packages/*"],
  "dependencies": { "shared-dependency": "^1.0.0" }
}"#,
        );
        project.write_file(
            "packages/a/package.json",
            r#"{
  "name": "importer-a",
  "version": "1.0.0",
  "dependencies": {
    "peer-host": "1.0.0",
    "react": "18.3.1",
    "shared-dependency": "^1.0.0"
  }
}"#,
        );
        project.write_file(
            "packages/b/package.json",
            r#"{
  "name": "importer-b",
  "version": "1.0.0",
  "dependencies": { "shared-dependency": "^1.0.0" }
}"#,
        );
        project
    }

    fn lockfile_bytes(project: &TempProject) -> Vec<Vec<u8>> {
        vec![std::fs::read(project.path().join("lpm.lock")).expect("read workspace lockfile")]
    }

    let mock = MockRegistry::start().await;
    mock.with_manifest_package(
        serde_json::json!({
            "name": "peer-host",
            "version": "1.0.0",
            "peerDependencies": { "react": "^18.0.0" }
        }),
        &[],
    )
    .await;
    mock.with_manifest_package(
        serde_json::json!({ "name": "react", "version": "18.3.1" }),
        &[],
    )
    .await;
    mock.with_manifest_package(
        serde_json::json!({ "name": "shared-dependency", "version": "1.0.0" }),
        &[],
    )
    .await;

    let sequential = workspace_fixture();
    let sequential_output = lpm_with_registry(&sequential, &mock.url())
        .env("LPM_STORE_VERSION", "v2")
        .env("LPM_WORKSPACE_CONCURRENCY", "1")
        .args([
            "install",
            "--policy",
            "deny",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("run sequential recursive install");
    assert!(
        sequential_output.status.success(),
        "sequential recursive install failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&sequential_output.stdout),
        String::from_utf8_lossy(&sequential_output.stderr)
    );
    let resolve_ahead = workspace_fixture();
    let resolve_ahead_output = lpm_with_registry(&resolve_ahead, &mock.url())
        .env("LPM_STORE_VERSION", "v2")
        .args([
            "install",
            "--json",
            "--timing",
            "--policy",
            "deny",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("run resolve-ahead recursive install");
    assert!(
        resolve_ahead_output.status.success(),
        "resolve-ahead recursive install failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&resolve_ahead_output.stdout),
        String::from_utf8_lossy(&resolve_ahead_output.stderr)
    );
    let resolve_ahead_report: serde_json::Value =
        serde_json::from_slice(&resolve_ahead_output.stdout)
            .expect("resolve-ahead install must emit JSON");
    assert_eq!(resolve_ahead_report["success"], true);
    assert_eq!(
        lockfile_bytes(&resolve_ahead),
        lockfile_bytes(&sequential),
        "resolve-ahead importer lockfiles must be byte-identical to sequential resolution"
    );
}

#[tokio::test]
async fn recursive_fresh_resolution_matches_metadata_cache_warm_resolution() {
    fn workspace_fixture() -> TempProject {
        let project = TempProject::empty(
            r#"{
  "name": "recursive-overlapping-range-root",
  "version": "1.0.0",
  "private": true,
  "workspaces": ["packages/*"],
  "dependencies": {
    "importer-a": "workspace:*",
    "range-parent": "*",
    "shared-dependency": "1.0.0"
  }
}"#,
        );
        project.write_file(
            "packages/a/package.json",
            r#"{
  "name": "importer-a",
  "version": "1.0.0",
  "dependencies": { "shared-dependency": "*" }
}"#,
        );
        std::fs::create_dir_all(project.home().join(".lpm"))
            .expect("create isolated LPM config directory");
        std::fs::write(
            project.home().join(".lpm/config.toml"),
            "minimum-release-age-secs = 86400\nrelease-age-policy = \"strict\"\n",
        )
        .expect("write strict release-age fixture config");
        project
    }

    fn lockfile_bytes(project: &TempProject) -> Vec<Vec<u8>> {
        vec![std::fs::read(project.path().join("lpm.lock")).expect("read workspace lockfile")]
    }

    let mock = MockRegistry::start().await;
    let version_1_0_0 = make_tarball("shared-dependency", "1.0.0");
    let version_1_1_0 = make_tarball("shared-dependency", "1.1.0");
    mock.with_manifest_package(
        serde_json::json!({
            "name": "range-parent",
            "version": "1.0.0",
            "dependencies": { "shared-dependency": "*" }
        }),
        &[],
    )
    .await;
    let shared_metadata = serde_json::json!({
        "name": "shared-dependency",
        "modified": "2099-01-01T00:00:00.000Z",
        "dist-tags": { "latest": "1.1.0" },
        "versions": {
            "1.0.0": {
                "name": "shared-dependency",
                "version": "1.0.0",
                "dist": {
                    "tarball": mock.tarball_url("shared-dependency", "1.0.0"),
                    "integrity": compute_integrity(&version_1_0_0),
                },
                "dependencies": {}
            },
            "1.1.0": {
                "name": "shared-dependency",
                "version": "1.1.0",
                "dist": {
                    "tarball": mock.tarball_url("shared-dependency", "1.1.0"),
                    "integrity": compute_integrity(&version_1_1_0),
                },
                "dependencies": {}
            }
        }
    });
    let shared_release_times = serde_json::json!({
        "name": "shared-dependency",
        "time": {
            "1.0.0": "2025-01-01T00:00:00.000Z",
            "1.1.0": "2025-02-01T00:00:00.000Z"
        }
    });
    Mock::given(method("GET"))
        .and(path("/shared-dependency"))
        .and(header("Accept", "application/vnd.npm.install-v1+json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(shared_metadata))
        .expect(1)
        .mount(mock.server())
        .await;
    Mock::given(method("GET"))
        .and(path("/shared-dependency"))
        .and(header("Accept", "application/json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(shared_release_times))
        .expect(1..)
        .mount(mock.server())
        .await;
    for (version, tarball) in [("1.0.0", &version_1_0_0), ("1.1.0", &version_1_1_0)] {
        mock.register_tarball_bytes("shared-dependency", version, tarball);
        Mock::given(method("GET"))
            .and(path(MockRegistry::tarball_path(
                "shared-dependency",
                version,
            )))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_bytes(tarball.clone())
                    .insert_header("content-type", "application/octet-stream"),
            )
            .mount(mock.server())
            .await;
    }

    let project = workspace_fixture();
    project.write_file(".npmrc", &format!("registry={}/\n", mock.url()));
    let cold_output = lpm_with_registry(&project, &mock.url())
        .env("LPM_STORE_VERSION", "v2")
        .env("LPM_WORKSPACE_CONCURRENCY", "1")
        .env_remove("LPM_NPM_ROUTE")
        .args([
            "--json",
            "install",
            "--timing",
            "--policy",
            "deny",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("run cold recursive install");
    assert!(
        cold_output.status.success(),
        "cold recursive install failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&cold_output.stdout),
        String::from_utf8_lossy(&cold_output.stderr)
    );

    let cold_locks = lockfile_bytes(&project);
    let cold_root_lock =
        std::fs::read_to_string(project.path().join("lpm.lock")).expect("read cold root lockfile");
    assert!(
        cold_root_lock.contains("dependencies = [\"shared-dependency@1.0.0\"]"),
        "the explicit root constraint must govern the overlapping transitive edge"
    );
    let cold_member_lock = read_project_lockfile(&project, "packages/a")
        .to_toml()
        .expect("serialize cold member projection");
    assert!(
        cold_member_lock.contains("version = \"1.1.0\""),
        "the broad member fixture must select the newest shared dependency"
    );

    for relative in [
        "lpm.lock",
        "packages/a/lpm.lock",
        "node_modules",
        "packages/a/node_modules",
    ] {
        let target = project.path().join(relative);
        if target.is_dir() {
            std::fs::remove_dir_all(&target)
                .unwrap_or_else(|error| panic!("remove {}: {error}", target.display()));
        } else if target.exists() {
            std::fs::remove_file(&target)
                .unwrap_or_else(|error| panic!("remove {}: {error}", target.display()));
        }
    }

    let warm_output = lpm_with_registry(&project, &mock.url())
        .env("LPM_STORE_VERSION", "v2")
        .env("LPM_WORKSPACE_CONCURRENCY", "1")
        .env_remove("LPM_NPM_ROUTE")
        .args([
            "install",
            "--policy",
            "deny",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("run metadata-cache-warm recursive install");
    assert!(
        warm_output.status.success(),
        "metadata-cache-warm recursive install failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&warm_output.stdout),
        String::from_utf8_lossy(&warm_output.stderr)
    );

    assert_eq!(
        lockfile_bytes(&project),
        cold_locks,
        "metadata cache warmth must not change the resolved graph or lockfile bytes"
    );
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
fn store_v1_rollback_workspace_alias_and_transitive_target_get_root_links() {
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
    let out = lpm_v1_with_registry(&project, "http://127.0.0.1:1")
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
    let out_offline = lpm_v1_with_registry(&project, "http://127.0.0.1:1")
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
// The install-time cooldown gate blocks recently-published packages.
// Behaviors pinned here: CLI overrides, per-install bypasses, global
// config, package.json config, exact package excludes, range fallback,
// transitive fallback, and the invariant that exact version pins do not
// bypass the cooldown.

const RELEASE_AGE_PKG: &str = "@lpm.dev/acme.widget";
const RELEASE_AGE_VERSION: &str = "1.0.0";
const RELEASE_AGE_RANGE_PKG: &str = "release-age-range-pkg";
const RELEASE_AGE_ROLLED_BACK_LATEST_PKG: &str = "release-age-rolled-back-latest-pkg";
const RELEASE_AGE_PARENT_PKG: &str = "release-age-parent-pkg";
const RELEASE_AGE_CHILD_PKG: &str = "release-age-child-pkg";
const RELEASE_AGE_ALIAS_LOCAL_PKG: &str = "release-age-alias-local";
const RELEASE_AGE_ALIAS_TARGET_PKG: &str = "release-age-alias-target";
const TRUST_DOWNGRADE_PKG: &str = "trust-drop-pkg";

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

async fn mount_release_age_pkg_without_publish_time(mock: &MockRegistry) {
    let tarball = make_tarball(RELEASE_AGE_PKG, RELEASE_AGE_VERSION);
    let metadata = serde_json::json!({
        "name": RELEASE_AGE_PKG,
        "dist-tags": { "latest": RELEASE_AGE_VERSION },
        "modified": iso8601_n_secs_ago(3_600),
        "versions": {
            RELEASE_AGE_VERSION: {
                "name": RELEASE_AGE_PKG,
                "version": RELEASE_AGE_VERSION,
                "dist": {
                    "tarball": mock.tarball_url(RELEASE_AGE_PKG, RELEASE_AGE_VERSION),
                    "integrity": compute_integrity(&tarball),
                },
                "dependencies": {}
            }
        }
    });
    mock.with_package_metadata_and_tarballs(
        RELEASE_AGE_PKG,
        metadata,
        &[(RELEASE_AGE_VERSION, tarball)],
    )
    .await;
}

fn release_age_lpm_config_with_policy(
    manifest_min_release_age: Option<u64>,
    excludes: &[&str],
    policy: Option<&str>,
) -> Option<serde_json::Value> {
    let mut lpm = serde_json::Map::new();
    if let Some(secs) = manifest_min_release_age {
        lpm.insert(
            "minimumReleaseAge".to_string(),
            serde_json::Value::Number(secs.into()),
        );
    }
    if !excludes.is_empty() {
        lpm.insert(
            "minimumReleaseAgeExclude".to_string(),
            serde_json::json!(excludes),
        );
    }
    if let Some(policy) = policy {
        lpm.insert(
            "minimumReleaseAgePolicy".to_string(),
            serde_json::Value::String(policy.to_string()),
        );
    }
    (!lpm.is_empty()).then_some(serde_json::Value::Object(lpm))
}

/// Write the consumer's `package.json` for the release-age tests.
/// `manifest_min_release_age` injects `lpm.minimumReleaseAge = <secs>`.
fn write_release_age_manifest_with_deps(
    project: &TempProject,
    dependencies: serde_json::Value,
    manifest_min_release_age: Option<u64>,
    excludes: &[&str],
) {
    write_release_age_manifest_with_deps_and_policy(
        project,
        dependencies,
        manifest_min_release_age,
        excludes,
        None,
    );
}

fn write_release_age_manifest_with_deps_and_policy(
    project: &TempProject,
    dependencies: serde_json::Value,
    manifest_min_release_age: Option<u64>,
    excludes: &[&str],
    policy: Option<&str>,
) {
    let mut manifest = serde_json::json!({
        "name": "release-age-test",
        "version": "1.0.0",
        "dependencies": dependencies
    });
    if let Some(lpm) =
        release_age_lpm_config_with_policy(manifest_min_release_age, excludes, policy)
    {
        manifest["lpm"] = lpm;
    }
    project.write_file(
        "package.json",
        &serde_json::to_string_pretty(&manifest).unwrap(),
    );
}

fn write_release_age_manifest(project: &TempProject, manifest_min_release_age: Option<u64>) {
    write_release_age_manifest_with_deps(
        project,
        serde_json::json!({ RELEASE_AGE_PKG: RELEASE_AGE_VERSION }),
        manifest_min_release_age,
        &[],
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

fn write_npm_firewall_global_config(project: &TempProject, mode: &str) {
    let lpm_dir = project.home().join(".lpm");
    std::fs::create_dir_all(&lpm_dir).unwrap();
    std::fs::write(
        lpm_dir.join("config.toml"),
        format!("[firewall]\nmode = \"{mode}\"\n"),
    )
    .unwrap();
}

fn rewrite_lockfile_registry_sources_to_public_npm(project: &TempProject) {
    let lockfile_path = project.path().join(lpm_lockfile::LOCKFILE_NAME);
    let mut lockfile = lpm_lockfile::Lockfile::read_from_file(&lockfile_path).unwrap();
    for package in &mut lockfile.packages {
        if package
            .source
            .as_deref()
            .is_some_and(|source| source.starts_with("registry+"))
        {
            package.source = Some(format!("registry+{}", lpm_common::NPM_REGISTRY_URL));
        }
    }
    lockfile.write_to_file(&lockfile_path).unwrap();
    let _ = std::fs::remove_file(lockfile_path.with_extension("lockb"));
}

async fn warm_public_npm_lockfile_project_for_offline_firewall(mode: &str) -> TempProject {
    let mock = MockRegistry::start().await;
    mount_ms_2_1_3(&mock).await;

    let project = TempProject::empty(
        r#"{
        "name": "offline-firewall",
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

    assertions::assert_lockfile_exists(project.path());
    rewrite_lockfile_registry_sources_to_public_npm(&project);
    write_npm_firewall_global_config(&project, mode);

    let node_modules = project.path().join("node_modules");
    if node_modules.exists() {
        std::fs::remove_dir_all(node_modules).unwrap();
    }

    project
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

fn write_signatures_global_config(project: &TempProject, enabled: bool) {
    let lpm_dir = project.home().join(".lpm");
    std::fs::create_dir_all(&lpm_dir).unwrap();
    std::fs::write(
        lpm_dir.join("config.toml"),
        format!("signatures = {enabled}\n"),
    )
    .unwrap();
}

fn write_trust_policy_global_config(project: &TempProject, policy: &str) {
    let lpm_dir = project.home().join(".lpm");
    std::fs::create_dir_all(&lpm_dir).unwrap();
    std::fs::write(
        lpm_dir.join("config.toml"),
        format!("trust-policy = \"{policy}\"\n"),
    )
    .unwrap();
}

async fn mount_release_age_range_pkg(mock: &MockRegistry) {
    let v1_0_0 = make_tarball(RELEASE_AGE_RANGE_PKG, "1.0.0");
    let v1_1_0 = make_tarball(RELEASE_AGE_RANGE_PKG, "1.1.0");
    let metadata = serde_json::json!({
        "name": RELEASE_AGE_RANGE_PKG,
        "dist-tags": { "latest": "1.1.0" },
        "modified": iso8601_n_secs_ago(60),
        "versions": {
            "1.0.0": {
                "name": RELEASE_AGE_RANGE_PKG,
                "version": "1.0.0",
                "dist": {
                    "tarball": mock.tarball_url(RELEASE_AGE_RANGE_PKG, "1.0.0"),
                    "integrity": compute_integrity(&v1_0_0),
                },
                "dependencies": {}
            },
            "1.1.0": {
                "name": RELEASE_AGE_RANGE_PKG,
                "version": "1.1.0",
                "dist": {
                    "tarball": mock.tarball_url(RELEASE_AGE_RANGE_PKG, "1.1.0"),
                    "integrity": compute_integrity(&v1_1_0),
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
        RELEASE_AGE_RANGE_PKG,
        metadata,
        &[("1.0.0", v1_0_0), ("1.1.0", v1_1_0)],
    )
    .await;
}

async fn mount_release_age_rolled_back_latest_pkg(mock: &MockRegistry) {
    let v3_0_0 = make_tarball(RELEASE_AGE_ROLLED_BACK_LATEST_PKG, "3.0.0");
    let v3_1_0 = make_tarball(RELEASE_AGE_ROLLED_BACK_LATEST_PKG, "3.1.0");
    let v4_0_0 = make_tarball(RELEASE_AGE_ROLLED_BACK_LATEST_PKG, "4.0.0");
    let metadata = serde_json::json!({
        "name": RELEASE_AGE_ROLLED_BACK_LATEST_PKG,
        "dist-tags": { "latest": "3.1.0" },
        "modified": iso8601_n_secs_ago(60),
        "versions": {
            "3.0.0": {
                "name": RELEASE_AGE_ROLLED_BACK_LATEST_PKG,
                "version": "3.0.0",
                "dist": {
                    "tarball": mock.tarball_url(RELEASE_AGE_ROLLED_BACK_LATEST_PKG, "3.0.0"),
                    "integrity": compute_integrity(&v3_0_0),
                },
                "dependencies": {}
            },
            "3.1.0": {
                "name": RELEASE_AGE_ROLLED_BACK_LATEST_PKG,
                "version": "3.1.0",
                "dist": {
                    "tarball": mock.tarball_url(RELEASE_AGE_ROLLED_BACK_LATEST_PKG, "3.1.0"),
                    "integrity": compute_integrity(&v3_1_0),
                },
                "dependencies": {}
            },
            "4.0.0": {
                "name": RELEASE_AGE_ROLLED_BACK_LATEST_PKG,
                "version": "4.0.0",
                "dist": {
                    "tarball": mock.tarball_url(RELEASE_AGE_ROLLED_BACK_LATEST_PKG, "4.0.0"),
                    "integrity": compute_integrity(&v4_0_0),
                },
                "dependencies": {}
            }
        },
        "time": {
            "3.0.0": iso8601_n_secs_ago(3 * 86_400),
            "3.1.0": iso8601_n_secs_ago(3_600),
            "4.0.0": iso8601_n_secs_ago(270 * 86_400)
        }
    });
    mock.with_package_metadata_and_tarballs(
        RELEASE_AGE_ROLLED_BACK_LATEST_PKG,
        metadata,
        &[("3.0.0", v3_0_0), ("3.1.0", v3_1_0), ("4.0.0", v4_0_0)],
    )
    .await;
}

async fn mount_release_age_transitive_fallback_pkgs(mock: &MockRegistry) {
    let parent_1_0_0 = make_tarball(RELEASE_AGE_PARENT_PKG, "1.0.0");
    let parent_1_1_0 = make_tarball(RELEASE_AGE_PARENT_PKG, "1.1.0");
    let child_1_0_0 = make_tarball(RELEASE_AGE_CHILD_PKG, "1.0.0");
    let child_2_0_0 = make_tarball(RELEASE_AGE_CHILD_PKG, "2.0.0");

    let parent_metadata = serde_json::json!({
        "name": RELEASE_AGE_PARENT_PKG,
        "dist-tags": { "latest": "1.1.0" },
        "modified": iso8601_n_secs_ago(2 * 86_400),
        "versions": {
            "1.0.0": {
                "name": RELEASE_AGE_PARENT_PKG,
                "version": "1.0.0",
                "dist": {
                    "tarball": mock.tarball_url(RELEASE_AGE_PARENT_PKG, "1.0.0"),
                    "integrity": compute_integrity(&parent_1_0_0),
                },
                "dependencies": { RELEASE_AGE_CHILD_PKG: "^1.0.0" }
            },
            "1.1.0": {
                "name": RELEASE_AGE_PARENT_PKG,
                "version": "1.1.0",
                "dist": {
                    "tarball": mock.tarball_url(RELEASE_AGE_PARENT_PKG, "1.1.0"),
                    "integrity": compute_integrity(&parent_1_1_0),
                },
                "dependencies": { RELEASE_AGE_CHILD_PKG: "^2.0.0" }
            }
        },
        "time": {
            "1.0.0": iso8601_n_secs_ago(3 * 86_400),
            "1.1.0": iso8601_n_secs_ago(2 * 86_400)
        }
    });
    let child_metadata = serde_json::json!({
        "name": RELEASE_AGE_CHILD_PKG,
        "dist-tags": { "latest": "2.0.0" },
        "modified": iso8601_n_secs_ago(3_600),
        "versions": {
            "1.0.0": {
                "name": RELEASE_AGE_CHILD_PKG,
                "version": "1.0.0",
                "dist": {
                    "tarball": mock.tarball_url(RELEASE_AGE_CHILD_PKG, "1.0.0"),
                    "integrity": compute_integrity(&child_1_0_0),
                },
                "dependencies": {}
            },
            "2.0.0": {
                "name": RELEASE_AGE_CHILD_PKG,
                "version": "2.0.0",
                "dist": {
                    "tarball": mock.tarball_url(RELEASE_AGE_CHILD_PKG, "2.0.0"),
                    "integrity": compute_integrity(&child_2_0_0),
                },
                "dependencies": {}
            }
        },
        "time": {
            "1.0.0": iso8601_n_secs_ago(3 * 86_400),
            "2.0.0": iso8601_n_secs_ago(3_600)
        }
    });

    mock.with_package_metadata_and_tarballs(
        RELEASE_AGE_PARENT_PKG,
        parent_metadata.clone(),
        &[("1.0.0", parent_1_0_0), ("1.1.0", parent_1_1_0)],
    )
    .await;
    mock.with_package_metadata_and_tarballs(
        RELEASE_AGE_CHILD_PKG,
        child_metadata.clone(),
        &[("1.0.0", child_1_0_0), ("2.0.0", child_2_0_0)],
    )
    .await;
    mock.with_batch_metadata(vec![parent_metadata, child_metadata])
        .await;
}

async fn mount_release_age_alias_target_pkg(mock: &MockRegistry, published_at: &str) {
    let tarball = make_tarball(RELEASE_AGE_ALIAS_TARGET_PKG, RELEASE_AGE_VERSION);
    mock.with_package_published_at(
        RELEASE_AGE_ALIAS_TARGET_PKG,
        RELEASE_AGE_VERSION,
        &tarball,
        published_at,
    )
    .await;
    mock.with_batch_metadata(vec![serde_json::json!({
        "name": RELEASE_AGE_ALIAS_TARGET_PKG,
        "dist-tags": { "latest": RELEASE_AGE_VERSION },
        "versions": {
            RELEASE_AGE_VERSION: {
                "name": RELEASE_AGE_ALIAS_TARGET_PKG,
                "version": RELEASE_AGE_VERSION,
                "dist": {
                    "tarball": mock.tarball_url(RELEASE_AGE_ALIAS_TARGET_PKG, RELEASE_AGE_VERSION),
                    "integrity": compute_integrity(&tarball),
                },
                "dependencies": {}
            }
        },
        "time": { RELEASE_AGE_VERSION: published_at }
    })])
    .await;
}

async fn mount_trust_downgrade_pkg(mock: &MockRegistry) {
    let v1_0_0 = make_tarball(TRUST_DOWNGRADE_PKG, "1.0.0");
    let v1_1_0 = make_tarball(TRUST_DOWNGRADE_PKG, "1.1.0");
    let metadata = serde_json::json!({
        "name": TRUST_DOWNGRADE_PKG,
        "dist-tags": { "latest": "1.1.0" },
        "modified": "2025-01-03T00:00:00.000Z",
        "versions": {
            "1.0.0": {
                "name": TRUST_DOWNGRADE_PKG,
                "version": "1.0.0",
                "_npmUser": {
                    "trustedPublisher": {
                        "issuer": "https://token.actions.githubusercontent.com",
                        "subject": "repo:example/trusted-package:ref:refs/heads/main"
                    }
                },
                "dist": {
                    "tarball": mock.tarball_url(TRUST_DOWNGRADE_PKG, "1.0.0"),
                    "integrity": compute_integrity(&v1_0_0),
                    "attestations": {
                        "url": "https://registry.npmjs.org/-/npm/v1/attestations/trust-drop-pkg@1.0.0",
                        "provenance": { "predicateType": "https://slsa.dev/provenance/v1" }
                    }
                },
                "dependencies": {}
            },
            "1.1.0": {
                "name": TRUST_DOWNGRADE_PKG,
                "version": "1.1.0",
                "dist": {
                    "tarball": mock.tarball_url(TRUST_DOWNGRADE_PKG, "1.1.0"),
                    "integrity": compute_integrity(&v1_1_0)
                },
                "dependencies": {}
            }
        },
        "time": {
            "1.0.0": "2025-01-01T00:00:00.000Z",
            "1.1.0": "2025-01-02T00:00:00.000Z"
        }
    });
    mock.with_package_metadata_and_tarballs(
        TRUST_DOWNGRADE_PKG,
        metadata,
        &[("1.0.0", v1_0_0), ("1.1.0", v1_1_0)],
    )
    .await;
}

async fn mount_unsigned_signature_pkg(mock: &MockRegistry) {
    let tarball = make_tarball("unsigned-pkg", "1.0.0");
    let metadata = mock.package_metadata("unsigned-pkg", "1.0.0", &tarball);
    mock.with_package_metadata("unsigned-pkg", "1.0.0", &tarball, metadata.clone())
        .await;
    mock.with_batch_metadata(vec![metadata]).await;
}

async fn mount_signed_signature_pkg(mock: &MockRegistry) {
    let signer = RegistrySigningFixture::new();
    mock.with_registry_signing_keys(&signer).await;
    let tarball = make_tarball("signed-pkg", "1.0.0");
    let metadata = mock.signed_package_metadata("signed-pkg", "1.0.0", &tarball, &signer);
    mock.with_package_metadata("signed-pkg", "1.0.0", &tarball, metadata.clone())
        .await;
    mock.with_batch_metadata(vec![metadata]).await;
}

async fn mount_malformed_signature_pkg(mock: &MockRegistry) {
    let signer = RegistrySigningFixture::new();
    mock.with_registry_signing_keys(&signer).await;
    let name = "malformed-signature-pkg";
    let version = "1.0.0";
    let tarball = make_tarball(name, version);
    let mut metadata = mock.package_metadata(name, version, &tarball);
    metadata["versions"][version]["dist"]["signatures"] =
        serde_json::json!([{ "keyid": "SHA256:test" }]);
    mock.with_package_metadata(name, version, &tarball, metadata.clone())
        .await;
    mock.with_batch_metadata(vec![metadata]).await;
}

async fn mount_mismatched_signature_pkg(mock: &MockRegistry) {
    let signer = RegistrySigningFixture::new();
    mock.with_registry_signing_keys(&signer).await;
    let name = "mismatched-signature-pkg";
    let version = "1.0.0";
    let tarball = make_tarball(name, version);
    let integrity = compute_integrity(&tarball);
    let mut metadata = mock.package_metadata(name, version, &tarball);
    metadata["versions"][version]["dist"]["signatures"] =
        serde_json::json!([signer.signature_json("other-pkg", version, &integrity)]);
    mock.with_package_metadata(name, version, &tarball, metadata.clone())
        .await;
    mock.with_batch_metadata(vec![metadata]).await;
}

#[tokio::test]
async fn install_does_not_verify_registry_signatures_by_default() {
    let project = TempProject::empty(
        r#"{"name":"signatures-default","version":"1.0.0","dependencies":{"unsigned-pkg":"1.0.0"}}"#,
    );
    let mock = MockRegistry::start().await;
    project.write_file(".npmrc", &format!("registry={}\n", mock.url()));
    mount_unsigned_signature_pkg(&mock).await;

    let out = lpm_with_registry(&project, &mock.url())
        .args([
            "install",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("spawn lpm install");

    assert!(
        out.status.success(),
        "install must not require registry signatures unless enabled; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
}

#[tokio::test]
async fn install_config_signatures_true_blocks_unsigned_registry_package() {
    let project = TempProject::empty(
        r#"{"name":"signatures-enabled","version":"1.0.0","dependencies":{"unsigned-pkg":"1.0.0"}}"#,
    );
    let mock = MockRegistry::start().await;
    project.write_file(".npmrc", &format!("registry={}\n", mock.url()));
    write_signatures_global_config(&project, true);
    mount_unsigned_signature_pkg(&mock).await;

    let out = lpm_with_registry(&project, &mock.url())
        .args([
            "install",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("spawn lpm install");

    assert!(
        !out.status.success(),
        "signatures=true must block unsigned registry packages; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        combined.contains("unsigned-pkg@1.0.0") && combined.contains("missing dist.signatures"),
        "install failure must identify the unsigned package and reason; got:\n{combined}",
    );
}

#[tokio::test]
async fn install_config_signatures_true_blocks_malformed_registry_signature() {
    let project = TempProject::empty(
        r#"{"name":"signatures-malformed","version":"1.0.0","dependencies":{"malformed-signature-pkg":"1.0.0"}}"#,
    );
    let mock = MockRegistry::start().await;
    project.write_file(".npmrc", &format!("registry={}\n", mock.url()));
    write_signatures_global_config(&project, true);
    mount_malformed_signature_pkg(&mock).await;

    let out = lpm_with_registry(&project, &mock.url())
        .args([
            "install",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("spawn lpm install");

    assert!(
        !out.status.success(),
        "signatures=true must block malformed registry signatures; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        combined.contains("malformed-signature-pkg@1.0.0") && combined.contains("without sig"),
        "install failure must identify the malformed signature payload; got:\n{combined}",
    );
}

#[tokio::test]
async fn install_config_signatures_true_blocks_mismatched_registry_signature() {
    let project = TempProject::empty(
        r#"{"name":"signatures-mismatched","version":"1.0.0","dependencies":{"mismatched-signature-pkg":"1.0.0"}}"#,
    );
    let mock = MockRegistry::start().await;
    project.write_file(".npmrc", &format!("registry={}\n", mock.url()));
    write_signatures_global_config(&project, true);
    mount_mismatched_signature_pkg(&mock).await;

    let out = lpm_with_registry(&project, &mock.url())
        .args([
            "install",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("spawn lpm install");

    assert!(
        !out.status.success(),
        "signatures=true must block mismatched registry signatures; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        combined.contains("mismatched-signature-pkg@1.0.0")
            && combined.contains("invalid registry signature"),
        "install failure must identify the mismatched signature; got:\n{combined}",
    );
}

#[tokio::test]
async fn install_config_signatures_true_accepts_signed_registry_package() {
    let project = TempProject::empty(
        r#"{"name":"signatures-enabled","version":"1.0.0","dependencies":{"signed-pkg":"1.0.0"}}"#,
    );
    let mock = MockRegistry::start().await;
    project.write_file(".npmrc", &format!("registry={}\n", mock.url()));
    write_signatures_global_config(&project, true);
    mount_signed_signature_pkg(&mock).await;

    let out = lpm_with_registry(&project, &mock.url())
        .args([
            "install",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("spawn lpm install");

    assert!(
        out.status.success(),
        "signatures=true must allow packages with valid registry signatures; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("Registry signatures verified · 1 verified"),
        "install should emit one slim signature summary when verification is enabled; got:\n{stderr}",
    );
}

#[tokio::test]
async fn install_config_signatures_true_persists_registry_signature_metadata_in_lockfile() {
    let project = TempProject::empty(
        r#"{"name":"signatures-lockfile","version":"1.0.0","dependencies":{"signed-pkg":"1.0.0"}}"#,
    );
    let mock = MockRegistry::start().await;
    project.write_file(".npmrc", &format!("registry={}\n", mock.url()));
    write_signatures_global_config(&project, true);
    mount_signed_signature_pkg(&mock).await;

    let out = lpm_with_registry(&project, &mock.url())
        .args([
            "install",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("spawn lpm install");

    assert!(
        out.status.success(),
        "signed install must succeed before checking lpm.lock; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );

    let lockfile = project.read_file("lpm.lock");
    assert!(
        lockfile.contains("registry-published-at = \"2025-01-01T00:00:00.000Z\""),
        "lpm.lock must persist the publish timestamp used for registry signature verification:\n{lockfile}"
    );
    assert!(
        lockfile.contains("[[packages.registry-signatures]]"),
        "lpm.lock must persist registry signatures under the locked package:\n{lockfile}"
    );
    assert!(
        lockfile.contains("keyid = ") && lockfile.contains("sig = "),
        "lpm.lock must persist both registry signature fields:\n{lockfile}"
    );
}

#[tokio::test]
async fn install_range_selects_older_version_when_latest_is_inside_release_age_window() {
    let project = TempProject::empty(&format!(
        r#"{{
            "name":"release-age-range",
            "version":"1.0.0",
            "dependencies":{{"{RELEASE_AGE_RANGE_PKG}":"^1.0.0"}},
            "lpm":{{"minimumReleaseAge":86400}}
        }}"#
    ));
    let mock = MockRegistry::start().await;
    project.write_file(".npmrc", &format!("registry={}\n", mock.url()));
    mount_release_age_range_pkg(&mock).await;

    let out = lpm_with_registry(&project, &mock.url())
        .args([
            "install",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("spawn lpm install");

    assert!(
        out.status.success(),
        "range install must fall back to the latest mature version; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    let installed = project.read_file(&format!(
        "node_modules/{RELEASE_AGE_RANGE_PKG}/package.json"
    ));
    let manifest: serde_json::Value =
        serde_json::from_str(&installed).expect("installed package.json must parse");
    assert_eq!(manifest["version"], serde_json::json!("1.0.0"));
}

async fn assert_install_latest_fallback_never_exceeds_rolled_back_dist_tag(resolver: Option<&str>) {
    let project = TempProject::empty(&format!(
        r#"{{
            "name":"release-age-rolled-back-latest",
            "version":"1.0.0",
            "dependencies":{{"{RELEASE_AGE_ROLLED_BACK_LATEST_PKG}":"latest"}},
            "lpm":{{"minimumReleaseAge":86400}}
        }}"#
    ));
    let mock = MockRegistry::start().await;
    project.write_file(".npmrc", &format!("registry={}\n", mock.url()));
    mount_release_age_rolled_back_latest_pkg(&mock).await;

    let mut command = lpm_with_registry(&project, &mock.url());
    command.args([
        "install",
        "--no-security-summary",
        "--no-skills",
        "--no-editor-setup",
    ]);
    if let Some(resolver) = resolver {
        command.env("LPM_RESOLVER", resolver);
    }
    let out = command.output().expect("spawn lpm install");

    assert!(
        out.status.success(),
        "latest install must fall back to a mature version at or below the dist-tag target; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    let installed = project.read_file(&format!(
        "node_modules/{RELEASE_AGE_ROLLED_BACK_LATEST_PKG}/package.json"
    ));
    let manifest: serde_json::Value =
        serde_json::from_str(&installed).expect("installed package.json must parse");
    assert_eq!(manifest["version"], serde_json::json!("3.0.0"));
}

#[tokio::test]
async fn install_latest_fallback_never_exceeds_rolled_back_dist_tag() {
    assert_install_latest_fallback_never_exceeds_rolled_back_dist_tag(None).await;
}

#[tokio::test]
async fn install_pubgrub_latest_fallback_never_exceeds_rolled_back_dist_tag() {
    assert_install_latest_fallback_never_exceeds_rolled_back_dist_tag(Some("pubgrub")).await;
}

#[tokio::test]
async fn install_keeps_newer_parent_when_only_transitive_child_is_inside_release_age_window() {
    let project = TempProject::empty(&format!(
        r#"{{
            "name":"release-age-transitive-fallback",
            "version":"1.0.0",
            "dependencies":{{"{RELEASE_AGE_PARENT_PKG}":"^1.0.0"}},
            "lpm":{{"minimumReleaseAge":86400}}
        }}"#
    ));
    let mock = MockRegistry::start().await;
    project.write_file(".npmrc", &format!("registry={}\n", mock.url()));
    mount_release_age_transitive_fallback_pkgs(&mock).await;

    let out = lpm_with_registry(&project, &mock.url())
        .args([
            "install",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("spawn lpm install");

    assert!(
        out.status.success(),
        "install must not downgrade a mature direct parent only because its transitive child is inside minimumReleaseAge; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    let installed_parent = project.read_file(&format!(
        "node_modules/{RELEASE_AGE_PARENT_PKG}/package.json"
    ));
    let parent_manifest: serde_json::Value =
        serde_json::from_str(&installed_parent).expect("installed parent package.json must parse");
    assert_eq!(parent_manifest["version"], serde_json::json!("1.1.0"));
}

#[tokio::test]
async fn install_strict_release_age_selects_mature_transitive_path() {
    let project = TempProject::empty(&format!(
        r#"{{
            "name":"release-age-strict-transitive",
            "version":"1.0.0",
            "dependencies":{{"{RELEASE_AGE_PARENT_PKG}":"^1.0.0"}},
            "lpm":{{"minimumReleaseAge":86400,"minimumReleaseAgePolicy":"strict"}}
        }}"#
    ));
    let mock = MockRegistry::start().await;
    project.write_file(".npmrc", &format!("registry={}\n", mock.url()));
    mount_release_age_transitive_fallback_pkgs(&mock).await;

    let out = lpm_with_registry(&project, &mock.url())
        .args([
            "install",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("spawn lpm install");

    assert!(
        out.status.success(),
        "strict release-age install should choose the mature parent/child path; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    let installed_parent = project.read_file(&format!(
        "node_modules/{RELEASE_AGE_PARENT_PKG}/package.json"
    ));
    let parent_manifest: serde_json::Value =
        serde_json::from_str(&installed_parent).expect("installed parent package.json must parse");
    assert_eq!(parent_manifest["version"], serde_json::json!("1.0.0"));
}

#[tokio::test]
async fn install_strict_release_age_hydrates_platform_metadata_for_mature_optional_package() {
    const PARENT: &str = "strict-release-age-platform-parent";
    const PACKAGE: &str = "strict-release-age-native";
    const VERSION: &str = "1.0.0";

    let project = TempProject::empty(&format!(
        r#"{{
            "name":"strict-release-age-platform",
            "version":"1.0.0",
            "dependencies":{{"{PARENT}":"{VERSION}"}},
            "lpm":{{"minimumReleaseAge":86400,"minimumReleaseAgePolicy":"strict"}}
        }}"#
    ));
    let mock = MockRegistry::start().await;
    project.write_file(".npmrc", &format!("registry={}/\n", mock.url()));

    let parent_tarball = make_tarball(PARENT, VERSION);
    let package_tarball = make_tarball(PACKAGE, VERSION);
    let parent_abbreviated = serde_json::json!({
        "name": PARENT,
        "modified": "2025-01-01T00:00:00.000Z",
        "dist-tags": { "latest": VERSION },
        "versions": {
            VERSION: {
                "name": PARENT,
                "version": VERSION,
                "dist": {
                    "tarball": mock.tarball_url(PARENT, VERSION),
                    "integrity": compute_integrity(&parent_tarball),
                },
                "optionalDependencies": { PACKAGE: VERSION }
            }
        }
    });
    let abbreviated = serde_json::json!({
        "name": PACKAGE,
        "modified": "2025-01-01T00:00:00.000Z",
        "dist-tags": { "latest": VERSION },
        "versions": {
            VERSION: {
                "name": PACKAGE,
                "version": VERSION,
                "os": ["linux"],
                "cpu": ["arm64"],
                "dist": {
                    "tarball": mock.tarball_url(PACKAGE, VERSION),
                    "integrity": compute_integrity(&package_tarball),
                },
                "dependencies": {}
            }
        }
    });
    let parent_full = serde_json::json!({
        "name": PARENT,
        "time": { VERSION: "2025-01-01T00:00:00.000Z" },
        "versions": { VERSION: {} }
    });
    let package_full = serde_json::json!({
        "name": PACKAGE,
        "time": { VERSION: "2025-01-01T00:00:00.000Z" },
        "versions": {
            VERSION: {
                "os": ["linux"],
                "cpu": ["arm64"],
                "libc": ["glibc"]
            }
        }
    });
    for (name, install_metadata, full_metadata, full_request_count) in [
        (PARENT, parent_abbreviated, parent_full, 0),
        (PACKAGE, abbreviated, package_full, 1),
    ] {
        Mock::given(method("GET"))
            .and(path(format!("/{name}")))
            .and(header("Accept", "application/vnd.npm.install-v1+json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(install_metadata))
            .expect(1)
            .mount(mock.server())
            .await;
        Mock::given(method("GET"))
            .and(path(format!("/{name}")))
            .and(header("Accept", "application/json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(full_metadata))
            .expect(full_request_count)
            .mount(mock.server())
            .await;
    }
    for (name, tarball) in [(PARENT, parent_tarball), (PACKAGE, package_tarball)] {
        mock.register_tarball_bytes(name, VERSION, &tarball);
        Mock::given(method("GET"))
            .and(path(MockRegistry::tarball_path(name, VERSION)))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_bytes(tarball)
                    .insert_header("content-type", "application/octet-stream"),
            )
            .mount(mock.server())
            .await;
    }

    let output = lpm_with_registry(&project, &mock.url())
        .env_remove("LPM_NPM_ROUTE")
        .env("LPM_TIMING_DETAIL", "basic")
        .args([
            "--json",
            "install",
            "--timing",
            "--policy",
            "deny",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("run strict release-age install");
    assert!(
        output.status.success(),
        "strict release-age install failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let envelope: serde_json::Value = serde_json::from_slice(&output.stdout)
        .expect("timed platform hydration install should emit JSON");
    let platform_hydration = envelope["timing"]["detail"]["metadata"]
        .as_array()
        .and_then(|entries| {
            entries
                .iter()
                .find(|entry| entry["purpose"] == "platform_hydration")
        })
        .unwrap_or_else(|| {
            panic!("timing metadata should identify platform hydration work; got {envelope:#}")
        });
    assert_eq!(platform_hydration["request_count"], 1);
    assert_eq!(platform_hydration["unique_package_count"], 1);

    let lockfile = lpm_lockfile::Lockfile::read_from_file(&project.path().join("lpm.lock"))
        .expect("strict release-age lockfile should parse");
    let package = lockfile
        .packages
        .iter()
        .find(|package| package.name == PACKAGE && package.version == VERSION)
        .expect("strict release-age package should be locked");
    assert_eq!(
        package.libc,
        ["glibc"],
        "platform metadata present only in npm's full manifest must survive release-age merging"
    );
}

#[tokio::test]
async fn install_strict_release_age_revalidates_fresh_lockfile_entry() {
    let project = TempProject::empty("");
    write_release_age_manifest_with_deps(
        &project,
        serde_json::json!({ RELEASE_AGE_PKG: RELEASE_AGE_VERSION }),
        Some(0),
        &[],
    );
    let mock = MockRegistry::start().await;
    project.write_file(".npmrc", &format!("registry={}\n", mock.url()));
    mount_release_age_pkg(&mock, &iso8601_n_secs_ago(3_600)).await;
    write_signed_unlock(&project, &["cooldown-bypass"]);

    let initial = lpm_with_registry(&project, &mock.url())
        .args([
            "install",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("spawn initial lpm install");
    assert!(
        initial.status.success(),
        "cooldown-off install must create the lockfile fixture; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&initial.stdout),
        String::from_utf8_lossy(&initial.stderr),
    );
    let lockfile = project.read_file("lpm.lock");
    assert!(
        lockfile.contains("registry-published-at"),
        "fixture lockfile must persist publish time for strict replay:\n{lockfile}"
    );

    write_release_age_manifest_with_deps_and_policy(
        &project,
        serde_json::json!({ RELEASE_AGE_PKG: RELEASE_AGE_VERSION }),
        Some(86_400),
        &[],
        Some("strict"),
    );
    std::fs::remove_dir_all(project.path().join("node_modules"))
        .expect("remove node_modules before lockfile replay");

    let replay = lpm_with_registry(&project, &mock.url())
        .args([
            "install",
            "--frozen-lockfile",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("spawn strict lockfile replay");

    assert_cooldown_blocked(&replay);
}

#[tokio::test]
async fn install_strict_release_age_allows_custom_registry_without_publish_times() {
    let project = TempProject::empty("");
    write_release_age_manifest_with_deps_and_policy(
        &project,
        serde_json::json!({ RELEASE_AGE_PKG: RELEASE_AGE_VERSION }),
        Some(86_400),
        &[],
        Some("strict"),
    );
    let mock = MockRegistry::start().await;
    project.write_file(".npmrc", &format!("registry={}\n", mock.url()));
    mount_release_age_pkg_without_publish_time(&mock).await;

    let out = lpm_with_registry(&project, &mock.url())
        .args([
            "install",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("spawn strict release-age install");

    assert!(
        out.status.success(),
        "strict release-age should not fail closed when a custom registry omits publish times; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    assert_cooldown_not_blocked(&out);
}

#[tokio::test]
async fn install_package_json_min_release_age_exclude_allows_fresh_direct_dependency() {
    let project = TempProject::empty("");
    write_release_age_manifest_with_deps(
        &project,
        serde_json::json!({ RELEASE_AGE_PKG: RELEASE_AGE_VERSION }),
        None,
        &[RELEASE_AGE_PKG],
    );

    let mock = MockRegistry::start().await;
    mount_release_age_pkg(&mock, &iso8601_n_secs_ago(3_600)).await;

    let out = lpm_with_registry(&project, &mock.url())
        .args([
            "install",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("spawn lpm install");

    assert!(
        out.status.success(),
        "exact package exclude must allow the fresh direct dependency; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    assert_cooldown_not_blocked(&out);
}

#[tokio::test]
async fn install_package_json_version_release_age_exclude_allows_only_the_selected_release() {
    let project = TempProject::empty("");
    let version_selector = format!("{RELEASE_AGE_PKG}@{RELEASE_AGE_VERSION}");
    write_release_age_manifest_with_deps(
        &project,
        serde_json::json!({ RELEASE_AGE_PKG: RELEASE_AGE_VERSION }),
        None,
        &[&version_selector],
    );

    let mock = MockRegistry::start().await;
    mount_release_age_pkg(&mock, &iso8601_n_secs_ago(3_600)).await;

    let out = lpm_with_registry(&project, &mock.url())
        .args([
            "install",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("spawn version-excluded lpm install");

    assert!(
        out.status.success(),
        "an exact package-version exclusion must allow that fresh release; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    assert_cooldown_not_blocked(&out);
}

#[tokio::test]
async fn install_package_json_version_release_age_exclude_does_not_allow_another_release() {
    let project = TempProject::empty("");
    let other_version_selector = format!("{RELEASE_AGE_PKG}@2.0.0");
    write_release_age_manifest_with_deps(
        &project,
        serde_json::json!({ RELEASE_AGE_PKG: RELEASE_AGE_VERSION }),
        None,
        &[&other_version_selector],
    );

    let mock = MockRegistry::start().await;
    mount_release_age_pkg(&mock, &iso8601_n_secs_ago(3_600)).await;

    let out = lpm_with_registry(&project, &mock.url())
        .args([
            "install",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("spawn differently-versioned exclusion install");

    assert_cooldown_blocked(&out);
}

#[tokio::test]
async fn install_package_json_scoped_wildcard_release_age_exclude_allows_package_in_scope() {
    let project = TempProject::empty("");
    write_release_age_manifest_with_deps(
        &project,
        serde_json::json!({ RELEASE_AGE_PKG: RELEASE_AGE_VERSION }),
        None,
        &["@lpm.dev/*"],
    );

    let mock = MockRegistry::start().await;
    mount_release_age_pkg(&mock, &iso8601_n_secs_ago(3_600)).await;

    let out = lpm_with_registry(&project, &mock.url())
        .args([
            "install",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("spawn scope-excluded lpm install");

    assert!(
        out.status.success(),
        "a scoped wildcard exclusion must allow a fresh package inside that scope; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    assert_cooldown_not_blocked(&out);
}

#[tokio::test]
async fn install_min_release_age_exclude_cli_allows_fresh_direct_dependency() {
    let project = TempProject::empty("");
    write_release_age_manifest(&project, None);

    let mock = MockRegistry::start().await;
    mount_release_age_pkg(&mock, &iso8601_n_secs_ago(3_600)).await;

    let out = lpm_with_registry(&project, &mock.url())
        .args([
            "install",
            "--min-release-age-exclude",
            RELEASE_AGE_PKG,
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("spawn lpm install");

    assert!(
        out.status.success(),
        "CLI package exclude must allow the fresh direct dependency; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    assert_cooldown_not_blocked(&out);
}

#[tokio::test]
async fn install_min_release_age_exclude_matches_alias_target_canonical_name() {
    let project = TempProject::empty("");
    write_release_age_manifest_with_deps(
        &project,
        serde_json::json!({
            RELEASE_AGE_ALIAS_LOCAL_PKG: format!("npm:{RELEASE_AGE_ALIAS_TARGET_PKG}@{RELEASE_AGE_VERSION}")
        }),
        Some(86_400),
        &[RELEASE_AGE_ALIAS_TARGET_PKG],
    );

    let mock = MockRegistry::start().await;
    project.write_file(".npmrc", &format!("registry={}\n", mock.url()));
    mount_release_age_alias_target_pkg(&mock, &iso8601_n_secs_ago(3_600)).await;

    let out = lpm_with_registry(&project, &mock.url())
        .args([
            "install",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("spawn lpm install");

    assert!(
        out.status.success(),
        "alias target canonical exclude must allow the fresh target package; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    assert_cooldown_not_blocked(&out);
}

#[tokio::test]
async fn install_min_release_age_exclude_does_not_match_alias_local_name() {
    let project = TempProject::empty("");
    write_release_age_manifest_with_deps(
        &project,
        serde_json::json!({
            RELEASE_AGE_ALIAS_LOCAL_PKG: format!("npm:{RELEASE_AGE_ALIAS_TARGET_PKG}@{RELEASE_AGE_VERSION}")
        }),
        Some(86_400),
        &[RELEASE_AGE_ALIAS_LOCAL_PKG],
    );

    let mock = MockRegistry::start().await;
    project.write_file(".npmrc", &format!("registry={}\n", mock.url()));
    mount_release_age_alias_target_pkg(&mock, &iso8601_n_secs_ago(3_600)).await;

    let out = lpm_with_registry(&project, &mock.url())
        .args([
            "install",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("spawn lpm install");

    assert_cooldown_blocked(&out);
}

#[tokio::test]
async fn install_trust_policy_no_downgrade_blocks_exact_version_that_drops_trust_evidence() {
    let project = TempProject::empty(&format!(
        r#"{{
            "name":"trust-policy-install",
            "version":"1.0.0",
            "dependencies":{{"{TRUST_DOWNGRADE_PKG}":"1.1.0"}}
        }}"#
    ));
    let mock = MockRegistry::start().await;
    project.write_file(".npmrc", &format!("registry={}\n", mock.url()));
    write_trust_policy_global_config(&project, "no-downgrade");
    mount_trust_downgrade_pkg(&mock).await;

    let out = lpm_with_registry(&project, &mock.url())
        .args([
            "install",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("spawn lpm install");

    assert!(
        !out.status.success(),
        "trust-policy no-downgrade must block the exact downgraded version; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        combined.contains(TRUST_DOWNGRADE_PKG)
            && combined.contains("1.1.0")
            && combined.contains("trust-policy no-downgrade")
            && combined.contains("trusted publisher"),
        "install failure must identify the trust downgrade; got:\n{combined}",
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

/// `--allow-new` is a guarded cooldown bypass. Workflow tests do not
/// manufacture a native approval, so the command should stop at the
/// security boundary instead of exercising the approved success path.
#[tokio::test]
async fn install_allow_new_requires_security_approval() {
    let project = TempProject::empty("");
    write_release_age_manifest(&project, Some(0));

    let mock = MockRegistry::start().await;
    mount_release_age_pkg(&mock, &iso8601_n_secs_ago(3_600)).await;

    let out = lpm_with_registry(&project, &mock.url())
        .args(["--json", "install", "--allow-new", "--min-release-age=72h"])
        .output()
        .expect("spawn lpm install");

    let envelope = assertions::assert_security_approval_required(&out);
    assert!(
        envelope["error"]["requested_scopes"]
            .as_array()
            .is_some_and(|scopes| scopes.iter().any(|scope| scope == "cooldown-bypass")),
        "approval envelope must name the cooldown-bypass scope; got {envelope}",
    );
}

/// A raw global `minimum-release-age-secs` value below the approved
/// floor is guarded before it can weaken the release-age window.
#[tokio::test]
async fn install_global_config_min_release_age_below_floor_requires_security_approval() {
    let project = TempProject::empty("");
    write_release_age_manifest(&project, None);
    write_release_age_global_config(&project, 3_600);

    let mock = MockRegistry::start().await;
    mount_release_age_pkg(&mock, &iso8601_n_secs_ago(1_800)).await;

    let out = lpm_with_registry(&project, &mock.url())
        .args(["--json", "install"])
        .output()
        .expect("spawn lpm install");

    let envelope = assertions::assert_security_approval_required(&out);
    assert!(
        envelope["error"]["requested_scopes"]
            .as_array()
            .is_some_and(|scopes| scopes.iter().any(|scope| scope == "cooldown-bypass")),
        "approval envelope must name the cooldown-bypass scope; got {envelope}",
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

/// An explicit version pin (`pkg@1.0.0`) must NOT bypass the cooldown.
/// Otherwise renovate/dependabot auto-pin PRs could land compromised
/// versions during the detection window.
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

/// CLI flag `--linker symlink` is rejected at parse time. The install pipeline
/// never sees an unknown value through this surface, so the error format is the
/// slim command-line error rather than the install-time message.
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
        "`--linker symlink` should fail at parse time"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("invalid value")
            || stderr.contains("possible values")
            || stderr.contains("isolated"),
        "stderr must surface the parse rejection; got:\n{stderr}"
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
         change. Pre-fix, the install-hash didn't fold in the linker mode, \
         so a post-install env flip \
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

    // A TRULY bare `lpm install` with `LPM_LINKER=symlink` against
    // the warm cache. Critically NO
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
// (`install.rs::lockfile_needs_peer_state_repair`) drops the fast-path
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
