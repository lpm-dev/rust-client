//! Workflow tests for `lpm mcp setup / remove / status`.
//!
//! MCP setup writes server entries into existing well-known editor config
//! files (Claude Code: `~/.claude.json`, Cursor: `~/.cursor/mcp.json`,
//! etc.). Tests run under an isolated HOME so they don't touch the
//! developer's real editor config.

mod support;

use support::mock_registry::{MockRegistry, compute_integrity, make_tarball_from_pkg_json};
use support::{TempProject, lpm, lpm_with_registry};

const MCP_PACKAGE_SPEC: &str = "@lpm-registry/mcp-server@latest";

#[test]
fn mcp_invalid_syntax_reports_usage_errors() {
    let project = TempProject::empty(r#"{"name":"mcp-usage"}"#);
    for args in [
        vec!["mcp", "remove"],
        vec!["mcp", "status", "unexpected"],
        vec!["mcp", "invalid"],
        vec!["mcp", "serve", "unexpected"],
    ] {
        for json in [false, true] {
            let mut command = lpm(&project);
            command.args(&args);
            if json {
                command.arg("--json");
            }
            let output = command.output().unwrap();
            assert_eq!(output.status.code(), Some(2), "{args:?}: {output:?}");
            if json {
                let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
                assert_eq!(result["error_code"], "usage");
            }
        }
    }
}

#[cfg(unix)]
#[test]
fn mcp_setup_pins_the_launcher_before_project_path_lookup() {
    use std::os::unix::fs::PermissionsExt;
    let project = TempProject::empty(r#"{"name":"mcp-launcher"}"#);
    std::fs::write(project.home().join(".claude.json"), "{}").unwrap();
    project.write_file("lpm", "#!/bin/sh\nprintf hijacked > intercepted\nexit 91\n");
    std::fs::set_permissions(
        project.path().join("lpm"),
        std::fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    let setup = lpm(&project).args(["mcp", "setup"]).output().unwrap();
    assert!(setup.status.success(), "{setup:?}");
    let config: serde_json::Value =
        serde_json::from_slice(&std::fs::read(project.home().join(".claude.json")).unwrap())
            .unwrap();
    let server = &config["mcpServers"]["lpm-registry"];
    let mut paths = vec![project.path().to_path_buf()];
    paths.extend(std::env::split_paths(
        &std::env::var_os("PATH").unwrap_or_default(),
    ));
    let result = std::process::Command::new(server["command"].as_str().unwrap())
        .args(["mcp", "serve", "--help"])
        .current_dir(project.path())
        .env("PATH", std::env::join_paths(paths).unwrap())
        .output()
        .unwrap();
    assert!(
        !project.path().join("intercepted").exists(),
        "configured launcher resolved a project executable"
    );
    assert!(result.status.success(), "{result:?}");
    assert!(std::path::Path::new(server["command"].as_str().unwrap()).is_absolute());
    assert_eq!(server["env"]["LPM_CLI_PATH"], server["command"]);
}

#[cfg(unix)]
#[test]
fn mcp_mutations_preserve_linked_editor_configs() {
    for action in ["setup", "remove"] {
        let project = TempProject::empty(r#"{"name":"mcp-linked"}"#);
        let original = r#"{"mcpServers":{"lpm-registry":{"command":"old"}}}"#;
        let target = project.path().join("shared.json");
        std::fs::write(&target, original).unwrap();
        let config = project.home().join(".claude.json");
        std::os::unix::fs::symlink(&target, &config).unwrap();
        let output = lpm(&project)
            .args(["mcp", action, "lpm-registry", "--json"])
            .output()
            .unwrap();
        assert!(
            !output.status.success(),
            "linked config must be rejected: {output:?}"
        );
        assert!(
            std::fs::symlink_metadata(&config)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(std::fs::read_to_string(target).unwrap(), original);
    }
}

#[cfg(unix)]
#[test]
fn mcp_rejects_relative_home_without_editing_project_configs() {
    let project = TempProject::empty(r#"{"name":"mcp-home"}"#);
    project.write_file(".claude.json", "{}");
    let output = lpm(&project)
        .env("HOME", ".")
        .args(["mcp", "setup", "--json"])
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "relative HOME must be rejected: {output:?}"
    );
    assert_eq!(
        std::fs::read_to_string(project.path().join(".claude.json")).unwrap(),
        "{}"
    );
}
const HOSTILE_SERVER_NAME: &str =
    "safe\nFORGED\rrewritten\u{8}\u{1b}]52;c;AAAA\u{7}\u{0090}hidden\u{009c}end";

fn mcp_server_tarball(version: &str) -> Vec<u8> {
    let script = format!(
        "#!/usr/bin/env node\nconsole.log(`mcp-version:{version};cwd:${{process.cwd()}};auth:${{process.env.LPM_TOKEN ? \"present\" : \"missing\"}}`);\n"
    );
    make_tarball_from_pkg_json(
        serde_json::json!({
            "name": "@lpm-registry/mcp-server",
            "version": version,
            "bin": {
                "lpm-mcp-server": "bin/mcp-server.js"
            }
        }),
        &[("bin/mcp-server.js", script.as_bytes())],
    )
}

fn mcp_server_tarball_with_blocked_lifecycle(version: &str) -> Vec<u8> {
    let script = format!(
        "#!/usr/bin/env node\nconsole.log(`mcp-version:{version};cwd:${{process.cwd()}};auth:${{process.env.LPM_TOKEN ? \"present\" : \"missing\"}}`);\n"
    );
    make_tarball_from_pkg_json(
        serde_json::json!({
            "name": "@lpm-registry/mcp-server",
            "version": version,
            "bin": {
                "lpm-mcp-server": "bin/mcp-server.js"
            },
            "scripts": {
                "install": "node -e \"process.exit(0)\""
            }
        }),
        &[("bin/mcp-server.js", script.as_bytes())],
    )
}

fn published_at(seconds_ago: i64) -> String {
    use chrono::SecondsFormat;

    (chrono::Utc::now() - chrono::Duration::seconds(seconds_ago))
        .to_rfc3339_opts(SecondsFormat::Millis, true)
}

fn mcp_runtime_root(project: &TempProject) -> std::path::PathBuf {
    project.cache_dir().join("mcp/runtime")
}

fn expire_mcp_runtime(project: &TempProject) {
    let marker = mcp_runtime_root(project).join("package.json");
    let marker_file = std::fs::OpenOptions::new()
        .write(true)
        .open(&marker)
        .expect("open MCP runtime freshness marker");
    marker_file
        .set_modified(std::time::SystemTime::now() - std::time::Duration::from_secs(48 * 60 * 60))
        .expect("expire MCP runtime freshness marker");
    let metadata_cache = project.cache_dir().join("metadata");
    if metadata_cache.exists() {
        std::fs::remove_dir_all(metadata_cache)
            .expect("clear registry metadata cache before refreshing MCP runtime");
    }
}

async fn mount_mcp_server_versions(
    registry: &MockRegistry,
    versions: &[(&str, i64)],
    latest: &str,
) {
    let mut version_metadata = serde_json::Map::new();
    let mut publication_times = serde_json::Map::new();
    let mut tarballs = Vec::with_capacity(versions.len());

    for (version, seconds_ago) in versions {
        let tarball = mcp_server_tarball(version);
        version_metadata.insert(
            (*version).to_string(),
            serde_json::json!({
                "name": "@lpm-registry/mcp-server",
                "version": version,
                "bin": {
                    "lpm-mcp-server": "bin/mcp-server.js"
                },
                "dependencies": {},
                "dist": {
                    "tarball": registry.tarball_url("@lpm-registry/mcp-server", version),
                    "integrity": compute_integrity(&tarball),
                }
            }),
        );
        publication_times.insert(
            (*version).to_string(),
            serde_json::Value::String(published_at(*seconds_ago)),
        );
        tarballs.push((*version, tarball));
    }

    registry
        .with_package_metadata_and_tarballs(
            "@lpm-registry/mcp-server",
            serde_json::json!({
                "name": "@lpm-registry/mcp-server",
                "dist-tags": { "latest": latest },
                "versions": version_metadata,
                "time": publication_times,
            }),
            &tarballs,
        )
        .await;
}

async fn mount_mcp_server_without_integrity(
    registry: &MockRegistry,
    version: &str,
    seconds_ago: i64,
) {
    let tarball = mcp_server_tarball(version);
    let mut versions = serde_json::Map::new();
    versions.insert(
        version.to_string(),
        serde_json::json!({
            "name": "@lpm-registry/mcp-server",
            "version": version,
            "bin": {
                "lpm-mcp-server": "bin/mcp-server.js"
            },
            "dependencies": {},
            "dist": {
                "tarball": registry.tarball_url(
                    "@lpm-registry/mcp-server",
                    version
                ),
            }
        }),
    );
    let mut publication_times = serde_json::Map::new();
    publication_times.insert(
        version.to_string(),
        serde_json::Value::String(published_at(seconds_ago)),
    );
    registry
        .with_package_metadata_and_tarballs(
            "@lpm-registry/mcp-server",
            serde_json::json!({
                "name": "@lpm-registry/mcp-server",
                "dist-tags": { "latest": version },
                "versions": versions,
                "time": publication_times,
            }),
            &[(version, tarball)],
        )
        .await;
}

async fn mount_mcp_server_with_blocked_lifecycle(registry: &MockRegistry, version: &str) {
    let tarball = mcp_server_tarball_with_blocked_lifecycle(version);
    registry
        .with_package_metadata_and_tarballs(
            "@lpm-registry/mcp-server",
            serde_json::json!({
                "name": "@lpm-registry/mcp-server",
                "dist-tags": { "latest": version },
                "versions": {
                    version: {
                        "name": "@lpm-registry/mcp-server",
                        "version": version,
                        "bin": {
                            "lpm-mcp-server": "bin/mcp-server.js"
                        },
                        "scripts": {
                            "install": "node -e \"process.exit(0)\""
                        },
                        "dependencies": {},
                        "dist": {
                            "tarball": registry.tarball_url(
                                "@lpm-registry/mcp-server",
                                version
                            ),
                            "integrity": compute_integrity(&tarball),
                        }
                    }
                },
                "time": {
                    version: published_at(48 * 60 * 60)
                },
            }),
            &[(version, tarball)],
        )
        .await;
}

fn assert_hostile_server_name_is_inline_safe(context: &str, rendered: &str) {
    assert!(
        rendered.contains("safe?FORGED?rewritten?end"),
        "{context} must preserve readable server text without forged rows, got:\n{rendered}"
    );
    for attacker_fragment in [
        "\u{1b}", "\u{7}", "\u{8}", "\r", "\u{007f}", "\u{0090}", "\u{009c}", "hidden",
    ] {
        assert!(
            !rendered.contains(attacker_fragment),
            "{context} retained attacker fragment {attacker_fragment:?}:\n{rendered}"
        );
    }
}

// ─── status (read-only) ───────────────────────────────────────────────

#[test]
fn mcp_status_on_fresh_home_succeeds() {
    let project = TempProject::empty(r#"{"name":"mcp","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args(["mcp", "status"])
        .output()
        .expect("failed to run lpm mcp status");

    assert!(
        output.status.success(),
        "mcp status on fresh HOME must succeed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("✓ MCP status loaded"),
        "mcp status must finish with a slim completion line, got:\n{stderr}",
    );
    assert!(
        !stderr.contains('●') && !stderr.contains('│') && !stderr.contains('◇'),
        "mcp status must not use cliclack gutter output, got:\n{stderr}",
    );
}

#[test]
fn mcp_status_json_envelope_is_valid_json() {
    let project = TempProject::empty(r#"{"name":"mcp","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args(["--json", "mcp", "status"])
        .output()
        .expect("failed to run lpm mcp status --json");

    assert!(output.status.success(), "mcp status --json must succeed");

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let _envelope: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("mcp status --json must be valid JSON: {e}\n---\n{stdout}"));
}

// ─── remove without name ──────────────────────────────────────────────

#[test]
fn mcp_remove_without_name_fails_with_helpful_message() {
    let project = TempProject::empty(r#"{"name":"mcp","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args(["mcp", "remove"])
        .output()
        .expect("failed to run lpm mcp remove (no name)");

    assert!(
        !output.status.success(),
        "mcp remove without name must exit non-zero"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("<NAME>"),
        "stderr must guide the user, got:\n{stderr}",
    );
}

#[test]
fn mcp_remove_server_argument_cannot_inject_terminal_rows() {
    let project = TempProject::empty(r#"{"name":"mcp","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args(["mcp", "remove", HOSTILE_SERVER_NAME])
        .output()
        .expect("failed to run lpm mcp remove with terminal controls in the server name");

    assert!(
        output.status.success(),
        "mcp remove of an unknown server succeeds"
    );
    let rendered = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_hostile_server_name_is_inline_safe("mcp remove output", &rendered);
}

#[test]
fn mcp_status_configured_server_name_cannot_inject_terminal_rows() {
    let project = TempProject::empty(r#"{"name":"mcp","version":"1.0.0"}"#);
    let config = serde_json::json!({
        "mcpServers": {
            HOSTILE_SERVER_NAME: {
                "command": "node"
            }
        }
    });
    std::fs::write(
        project.home().join(".claude.json"),
        serde_json::to_vec(&config).expect("serialize hostile MCP config"),
    )
    .expect("write hostile MCP config");

    let output = lpm(&project)
        .args(["mcp", "status"])
        .output()
        .expect("failed to run lpm mcp status with a hostile configured server name");

    assert!(output.status.success(), "mcp status must succeed");
    let rendered = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_hostile_server_name_is_inline_safe("mcp status output", &rendered);
}

#[test]
fn mcp_setup_and_remove_use_slim_human_status() {
    let project = TempProject::empty(r#"{"name":"mcp","version":"1.0.0"}"#);
    std::fs::write(project.home().join(".claude.json"), "{}")
        .expect("failed to seed Claude Code MCP config");

    let setup = lpm(&project)
        .args(["mcp", "setup", "test-server"])
        .output()
        .expect("failed to run lpm mcp setup");

    assert!(
        setup.status.success(),
        "mcp setup must succeed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&setup.stdout),
        String::from_utf8_lossy(&setup.stderr),
    );

    let setup_stderr = String::from_utf8_lossy(&setup.stderr);
    assert!(
        setup_stderr.contains("› Configuring MCP servers for supported editors"),
        "mcp setup must start with a slim phase line, got:\n{setup_stderr}",
    );
    assert!(
        setup_stderr.contains("✓ Claude Code") && setup_stderr.contains("configured"),
        "mcp setup must report configured editors, got:\n{setup_stderr}",
    );
    assert!(
        setup_stderr.contains("○") && setup_stderr.contains("skipped (config not found)"),
        "mcp setup must report skipped editor configs, got:\n{setup_stderr}",
    );
    assert!(
        setup_stderr.contains("✓ Server name: test-server"),
        "mcp setup must report the configured server name, got:\n{setup_stderr}",
    );
    assert!(
        setup_stderr.contains("✓ Done · restart your editor to pick up the new MCP server"),
        "mcp setup must finish with a slim completion line, got:\n{setup_stderr}",
    );
    assert!(
        !setup_stderr.contains('●') && !setup_stderr.contains('│') && !setup_stderr.contains('◇'),
        "mcp setup must not use cliclack gutter output, got:\n{setup_stderr}",
    );
    assert!(
        setup_stderr.contains(MCP_PACKAGE_SPEC),
        "mcp setup must report the published package policy, got:\n{setup_stderr}"
    );

    let remove = lpm(&project)
        .args(["mcp", "remove", "test-server"])
        .output()
        .expect("failed to run lpm mcp remove");

    assert!(
        remove.status.success(),
        "mcp remove must succeed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&remove.stdout),
        String::from_utf8_lossy(&remove.stderr),
    );

    let remove_stderr = String::from_utf8_lossy(&remove.stderr);
    assert!(
        remove_stderr.contains("✓ Removed \"test-server\" from"),
        "mcp remove must report slim removal lines, got:\n{remove_stderr}",
    );
    assert!(
        !remove_stderr.contains('●')
            && !remove_stderr.contains('│')
            && !remove_stderr.contains('◇'),
        "mcp remove must not use cliclack gutter output, got:\n{remove_stderr}",
    );
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[test]
fn mcp_setup_writes_the_published_package_to_both_container_shapes_idempotently() {
    let project = TempProject::empty(r#"{"name":"mcp","version":"1.0.0"}"#);
    let claude_path = project.home().join(".claude.json");
    #[cfg(target_os = "macos")]
    let vscode_path = project
        .home()
        .join("Library/Application Support/Code/User/mcp.json");
    #[cfg(target_os = "linux")]
    let vscode_path = project.home().join(".config/Code/User/mcp.json");

    std::fs::create_dir_all(vscode_path.parent().unwrap()).unwrap();
    std::fs::write(
        &claude_path,
        r#"{"theme":"dark","mcpServers":{"keep":{"command":"node"}}}"#,
    )
    .unwrap();
    std::fs::write(
        &vscode_path,
        r#"{"inputs":[{"type":"promptString"}],"servers":{"keep":{"command":"node"}}}"#,
    )
    .unwrap();

    for _ in 0..2 {
        let output = lpm(&project)
            .args(["mcp", "setup"])
            .output()
            .expect("failed to run lpm mcp setup");
        assert!(
            output.status.success(),
            "repeated mcp setup must succeed\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let claude: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&claude_path).unwrap()).unwrap();
    let vscode: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&vscode_path).unwrap()).unwrap();
    let executable = assert_cmd::cargo::cargo_bin("lpm-rs")
        .canonicalize()
        .unwrap();
    let expected = serde_json::json!({
        "command": executable,
        "args": ["mcp", "serve"],
        "env": { "LPM_CLI_PATH": executable }
    });

    assert_eq!(claude["mcpServers"]["lpm-registry"], expected);
    assert_eq!(vscode["servers"]["lpm-registry"], expected);
    assert_eq!(claude["mcpServers"].as_object().unwrap().len(), 2);
    assert_eq!(vscode["servers"].as_object().unwrap().len(), 2);
    assert_eq!(claude["theme"], "dark");
    assert!(vscode["inputs"].is_array());
}

#[test]
fn mcp_setup_json_reports_the_same_published_package_policy_as_the_written_config() {
    let project = TempProject::empty(r#"{"name":"mcp","version":"1.0.0"}"#);
    let claude_path = project.home().join(".claude.json");
    std::fs::write(&claude_path, "{}").unwrap();

    let output = lpm(&project)
        .args(["--json", "mcp", "setup"])
        .output()
        .expect("failed to run lpm mcp setup --json");
    assert!(
        output.status.success(),
        "mcp setup --json must succeed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let envelope: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|error| panic!("stdout must be one JSON document: {error}\n{stdout}"));
    insta::assert_json_snapshot!(envelope, {
        ".command" => "[LPM_PATH]",
        ".env.LPM_CLI_PATH" => "[LPM_PATH]",
    }, @r###"
    {
      "success": true,
      "server": "lpm-registry",
      "configured": [
        "Claude Code"
      ],
      "package": "@lpm-registry/mcp-server",
      "package_spec": "@lpm-registry/mcp-server@latest",
      "version_policy": "latest-security-eligible",
      "command": "[LPM_PATH]",
      "args": [
        "mcp",
        "serve"
      ],
      "env": {
        "LPM_CLI_PATH": "[LPM_PATH]"
      }
    }
    "###);

    let config: serde_json::Value =
        serde_json::from_slice(&std::fs::read(claude_path).unwrap()).unwrap();
    assert_eq!(
        config["mcpServers"]["lpm-registry"]["args"],
        envelope["args"]
    );
}

#[tokio::test]
async fn mcp_serve_ignores_workspace_lockfile_and_security_overrides() {
    let project = TempProject::empty(
        r#"{
            "name":"mcp",
            "version":"1.0.0",
            "lpm":{"minimumReleaseAge":0}
        }"#,
    );
    let mut lockfile = lpm_lockfile::Lockfile::new();
    lockfile.add_package(lpm_lockfile::LockedPackage {
        instance_id: None,
        dependency_targets: std::collections::BTreeMap::new(),
        peer_targets: std::collections::BTreeMap::new(),
        name: "@lpm-registry/mcp-server".to_string(),
        version: "0.1.0".to_string(),
        integrity: Some(support::VALID_TEST_INTEGRITY.to_string()),
        ..Default::default()
    });
    support::finalize_exact_lockfile_fixture(
        &mut lockfile,
        &[(
            "@lpm-registry/mcp-server",
            "@lpm-registry/mcp-server",
            "0.1.0",
        )],
    );
    lockfile
        .write_to_file(&project.path().join(lpm_lockfile::LOCKFILE_NAME))
        .expect("seed workspace lockfile");

    let registry = MockRegistry::start().await;
    mount_mcp_server_versions(&registry, &[("1.0.0", 48 * 60 * 60)], "1.0.0").await;

    let output = lpm_with_registry(&project, &registry.url())
        .env("LPM_TOKEN", "workflow-mcp-token")
        .args(["mcp", "serve"])
        .output()
        .expect("run isolated MCP launcher");

    assert!(
        output.status.success(),
        "MCP launcher must ignore workspace install policy and lockfile:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("mcp-version:1.0.0"),
        "MCP launcher must resolve independently of the workspace pin: {stdout}"
    );
    assert!(
        stdout.contains(&format!(
            "cwd:{}",
            project
                .path()
                .canonicalize()
                .expect("canonicalize project path")
                .display()
        )),
        "the launched MCP server must still execute in the editor workspace: {stdout}"
    );
    assert!(
        stdout.contains("auth:present"),
        "the verified MCP server must receive the documented LPM_TOKEN environment: {stdout}"
    );
    assert!(
        mcp_runtime_root(&project).join("lpm.lock").is_file(),
        "the MCP launcher must use its dedicated verified runtime cache"
    );
    assert!(
        !project.cache_dir().join("dlx").exists(),
        "the managed MCP runtime must not be swept with ordinary dlx entries"
    );
}

#[tokio::test]
async fn mcp_serve_runs_the_newest_release_allowed_by_the_cooldown() {
    let project = TempProject::empty(r#"{"name":"mcp","version":"1.0.0"}"#);
    lpm(&project)
        .args(["config", "release-age", "--set", "1d"])
        .assert()
        .success();
    let registry = MockRegistry::start().await;
    mount_mcp_server_versions(
        &registry,
        &[("1.0.0", 48 * 60 * 60), ("2.0.0", 60)],
        "2.0.0",
    )
    .await;

    let output = lpm_with_registry(&project, &registry.url())
        .args(["mcp", "serve"])
        .output()
        .expect("run MCP launcher against a fresh latest release");

    assert!(
        output.status.success(),
        "MCP launcher must fall back to a mature release:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("mcp-version:1.0.0"),
        "MCP launcher must not bypass the release-age cooldown"
    );
}

#[tokio::test]
async fn mcp_serve_cold_install_reserves_stdout_when_lifecycle_scripts_are_blocked() {
    let project = TempProject::empty(r#"{"name":"mcp","version":"1.0.0"}"#);
    let registry = MockRegistry::start().await;
    mount_mcp_server_with_blocked_lifecycle(&registry, "1.0.0").await;

    let output = lpm_with_registry(&project, &registry.url())
        .args(["mcp", "serve"])
        .output()
        .expect("run MCP launcher with a blocked lifecycle script");

    assert!(
        output.status.success(),
        "MCP launcher must start after safely blocking lifecycle scripts:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let expected = format!(
        "mcp-version:1.0.0;cwd:{};auth:missing\n",
        project
            .path()
            .canonicalize()
            .expect("canonicalize project path")
            .display()
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        expected,
        "the cold install must not write lifecycle reporting into MCP JSON-RPC stdout"
    );
}

#[tokio::test]
async fn mcp_serve_refuses_registry_metadata_without_integrity() {
    let project = TempProject::empty(r#"{"name":"mcp","version":"1.0.0"}"#);
    let registry = MockRegistry::start().await;
    mount_mcp_server_without_integrity(&registry, "1.0.0", 48 * 60 * 60).await;

    let output = lpm_with_registry(&project, &registry.url())
        .args(["mcp", "serve"])
        .output()
        .expect("run MCP launcher against metadata without integrity");

    assert!(
        !output.status.success(),
        "the managed MCP runtime must not trust an unhashed registry tarball:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Refusing to install an unverified registry tarball"),
        "the failure must explain the integrity requirement, got:\n{stderr}"
    );
    assert!(
        !mcp_runtime_root(&project).exists(),
        "a rejected MCP runtime must never become active"
    );
}

#[tokio::test]
async fn mcp_serve_does_not_fallback_after_an_authentication_failure() {
    let project = TempProject::empty(r#"{"name":"mcp","version":"1.0.0"}"#);
    let initial_registry = MockRegistry::start().await;
    mount_mcp_server_versions(&initial_registry, &[("1.0.0", 48 * 60 * 60)], "1.0.0").await;
    let initial = lpm_with_registry(&project, &initial_registry.url())
        .args(["mcp", "serve"])
        .output()
        .expect("install the initial verified MCP runtime");
    assert!(
        initial.status.success(),
        "initial MCP launch must succeed: {}",
        String::from_utf8_lossy(&initial.stderr)
    );
    expire_mcp_runtime(&project);

    let auth_registry = MockRegistry::start().await;
    auth_registry
        .with_npm_package_error(
            "@lpm-registry/mcp-server",
            403,
            serde_json::json!({ "error": "forbidden" }),
        )
        .await;
    std::fs::write(
        project.home().join(".npmrc"),
        format!("@lpm-registry:registry={}/\n", auth_registry.url()),
    )
    .expect("write isolated user npmrc");
    let rejected = lpm_with_registry(&project, &auth_registry.url())
        .args(["mcp", "serve"])
        .output()
        .expect("refresh MCP runtime against an authentication failure");

    assert!(
        !rejected.status.success(),
        "an authentication failure must fail closed instead of running stale code:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&rejected.stdout),
        String::from_utf8_lossy(&rejected.stderr)
    );
    assert!(
        !String::from_utf8_lossy(&rejected.stdout).contains("mcp-version:"),
        "the cached MCP server must not execute after an authentication failure"
    );
    assert!(
        !String::from_utf8_lossy(&rejected.stderr).contains("last verified version"),
        "authentication failures must not be described as an outage fallback"
    );
}

#[tokio::test]
async fn mcp_serve_uses_the_last_verified_runtime_during_a_registry_outage() {
    let project = TempProject::empty(r#"{"name":"mcp","version":"1.0.0"}"#);
    let registry = MockRegistry::start().await;
    mount_mcp_server_versions(&registry, &[("1.0.0", 48 * 60 * 60)], "1.0.0").await;

    let initial = lpm_with_registry(&project, &registry.url())
        .args(["mcp", "serve"])
        .output()
        .expect("install the initial verified MCP runtime");
    assert!(
        initial.status.success(),
        "initial MCP launch must succeed: {}",
        String::from_utf8_lossy(&initial.stderr)
    );
    let initial_stderr = String::from_utf8_lossy(&initial.stderr);
    assert!(
        !initial_stderr.contains("Checking stored LPM"),
        "the unattended MCP launcher must not inspect stored credentials:\n{initial_stderr}"
    );

    expire_mcp_runtime(&project);

    let fallback = lpm_with_registry(&project, "http://127.0.0.1:9")
        .args(["mcp", "serve"])
        .output()
        .expect("run MCP launcher during registry outage");

    assert!(
        fallback.status.success(),
        "a transport outage must not prevent a verified cached launch:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&fallback.stdout),
        String::from_utf8_lossy(&fallback.stderr)
    );
    assert!(
        String::from_utf8_lossy(&fallback.stdout).contains("mcp-version:1.0.0"),
        "the last verified MCP server must execute during the outage"
    );
    let fallback_stderr = String::from_utf8_lossy(&fallback.stderr);
    assert!(
        fallback_stderr.contains("last verified version"),
        "the launcher must report its stale-cache fallback on stderr, got:\n{fallback_stderr}"
    );
    assert!(
        !fallback_stderr.contains("Checking stored LPM"),
        "the unattended MCP launcher must never inspect stored credentials:\n{fallback_stderr}"
    );
    let installed: serde_json::Value = serde_json::from_slice(
        &std::fs::read(
            mcp_runtime_root(&project).join("node_modules/@lpm-registry/mcp-server/package.json"),
        )
        .expect("read retained MCP package manifest"),
    )
    .expect("parse retained MCP package manifest");
    assert_eq!(installed["version"], "1.0.0");
}

// ─── unknown action ───────────────────────────────────────────────────

#[test]
fn mcp_unknown_action_reports_usage_and_points_to_help() {
    let project = TempProject::empty(r#"{"name":"mcp","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args(["mcp", "not-a-real-action"])
        .output()
        .expect("failed to run lpm mcp bogus");

    assert!(
        !output.status.success(),
        "unknown mcp action must exit non-zero"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("usage lpm mcp") && stderr.contains("--help"),
        "stderr must show usage and the help option, got:\n{stderr}",
    );
}

#[cfg(unix)]
#[tokio::test]
async fn mcp_cached_runtime_does_not_use_caller_controlled_node() {
    use std::os::unix::fs::PermissionsExt;
    let project = TempProject::empty(r#"{"name":"mcp-runtime-boundary","version":"1.0.0"}"#);
    let registry = MockRegistry::start().await;
    mount_mcp_server_versions(&registry, &[("1.0.0", 72 * 3600)], "1.0.0").await;
    let first = lpm_with_registry(&project, &registry.url())
        .args(["mcp", "serve"])
        .output()
        .unwrap();
    assert!(
        first.status.success(),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    project.write_file(
        "node_modules/.bin/node",
        "#!/bin/sh\nif [ -n \"$LPM_TOKEN\" ]; then printf intercepted > intercepted; fi\nexit 92\n",
    );
    let node = project.path().join("node_modules/.bin/node");
    std::fs::set_permissions(&node, std::fs::Permissions::from_mode(0o755)).unwrap();
    let output = lpm_with_registry(&project, &registry.url())
        .env("LPM_TOKEN", "dummy-mcp-token")
        .args(["mcp", "serve"])
        .output()
        .unwrap();
    assert!(
        !project.path().join("intercepted").exists(),
        "caller Node received the managed runtime token"
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("mcp-version:1.0.0"));
    assert!(stdout.contains("auth:present"));
}

#[cfg(unix)]
#[tokio::test]
async fn mcp_ignores_inherited_project_paths_and_symlinks() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let project = TempProject::empty(r#"{"name":"mcp-path-boundary","version":"1.0.0"}"#);
    let registry = MockRegistry::start().await;
    mount_mcp_server_versions(&registry, &[("1.0.0", 72 * 3600)], "1.0.0").await;
    let first = lpm_with_registry(&project, &registry.url())
        .args(["mcp", "serve"])
        .output()
        .unwrap();
    assert!(
        first.status.success(),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    project.write_file(
        "tools/node",
        "#!/bin/sh\nprintf intercepted > intercepted\nexit 92\n",
    );
    std::fs::set_permissions(
        project.path().join("tools/node"),
        std::fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    let external = tempfile::tempdir().unwrap();
    symlink(project.path().join("tools"), external.path().join("alias")).unwrap();
    for untrusted in [
        std::path::PathBuf::from("tools"),
        project.path().join("tools"),
        external.path().join("alias"),
    ] {
        let path = std::env::join_paths(
            std::iter::once(untrusted)
                .chain(std::env::split_paths(&std::env::var_os("PATH").unwrap())),
        )
        .unwrap();
        let output = lpm_with_registry(&project, &registry.url())
            .env("PATH", path)
            .env("LPM_TOKEN", "dummy-mcp-token")
            .args(["mcp", "serve"])
            .output()
            .unwrap();
        assert!(
            !project.path().join("intercepted").exists(),
            "caller path reached managed execution"
        );
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(String::from_utf8_lossy(&output.stdout).contains("auth:present"));
    }
}

#[cfg(windows)]
#[tokio::test]
async fn mcp_ignores_node_commands_in_the_caller_directory() {
    let project = TempProject::empty(r#"{"name":"mcp-cwd-boundary","version":"1.0.0"}"#);
    let registry = MockRegistry::start().await;
    mount_mcp_server_versions(&registry, &[("1.0.0", 72 * 3600)], "1.0.0").await;
    let first = lpm_with_registry(&project, &registry.url())
        .args(["mcp", "serve"])
        .output()
        .unwrap();
    assert!(
        first.status.success(),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    project.write_file(
        "node.cmd",
        "@echo off\r\necho intercepted>intercepted\r\nexit /b 92\r\n",
    );
    let output = lpm_with_registry(&project, &registry.url())
        .env("LPM_TOKEN", "dummy-mcp-token")
        .args(["mcp", "serve"])
        .output()
        .unwrap();
    assert!(!project.path().join("intercepted").exists());
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("auth:present"));
}

#[tokio::test]
async fn mcp_promoted_runtime_remains_reachable_during_store_pruning() {
    let project = TempProject::empty(r#"{"name":"mcp-prune","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    mount_mcp_server_versions(&mock, &[("1.0.0", 72 * 3600)], "1.0.0").await;
    let first = lpm_with_registry(&project, &mock.url())
        .args(["mcp", "serve"])
        .output()
        .unwrap();
    assert!(
        first.status.success(),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    lpm(&project)
        .args(["cache", "prune", "--apply"])
        .assert()
        .success();
    mock.server().reset().await;
    let warm = lpm_with_registry(&project, &mock.url())
        .args(["mcp", "serve"])
        .output()
        .unwrap();
    assert!(
        warm.status.success(),
        "prune removed the active runtime: {}",
        String::from_utf8_lossy(&warm.stderr)
    );
    assert!(String::from_utf8_lossy(&warm.stdout).contains("mcp-version:1.0.0"));
}

#[tokio::test]
async fn mcp_store_pruning_waits_until_the_active_server_finishes() {
    let project = TempProject::empty(r#"{"name":"mcp-active-prune","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    let script = b"#!/usr/bin/env node\nconst fs=require('fs');fs.writeFileSync('ready','ready');const start=Date.now();const timer=setInterval(()=>{if(fs.existsSync('release')||Date.now()-start>10000){clearInterval(timer);try{fs.readFileSync(__filename);console.log('MCP_ALIVE')}catch(e){console.error(e.message);process.exitCode=31;}}},20);";
    mock.with_manifest_package(serde_json::json!({"name":"@lpm-registry/mcp-server","version":"1.0.0","bin":{"lpm-mcp-server":"server.js"}}), &[("server.js", script)]).await;
    let mut server = support::lpm_spawnable_with_registry(&project, &mock.url())
        .args(["mcp", "serve"])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while !project.file_exists("ready") {
        if server.try_wait().unwrap().is_some() || std::time::Instant::now() >= deadline {
            let _ = server.kill();
            let output = server.wait_with_output().unwrap();
            panic!(
                "server did not reach readiness: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    let mut prune = support::lpm_spawnable(&project)
        .args(["cache", "prune", "--apply"])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    std::thread::sleep(std::time::Duration::from_millis(300));
    let waited = prune.try_wait().unwrap().is_none();
    project.write_file("release", "done");
    let output = server.wait_with_output().unwrap();
    let pruned = prune.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        pruned.status.success(),
        "{}",
        String::from_utf8_lossy(&pruned.stderr)
    );
    assert!(
        waited,
        "pruning ran while the server still used store files"
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("MCP_ALIVE"));
}

#[tokio::test]
async fn mcp_refresh_keeps_the_previous_runtime_when_its_default_executable_is_missing() {
    let project = TempProject::empty(r#"{"name":"mcp-unusable-refresh","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    mount_mcp_server_versions(&mock, &[("1.0.0", 72 * 3600)], "1.0.0").await;
    lpm_with_registry(&project, &mock.url())
        .args(["mcp", "serve"])
        .assert()
        .success();
    expire_mcp_runtime(&project);
    let marker = mcp_runtime_root(&project).join("package.json");
    let modified = std::fs::metadata(&marker).unwrap().modified().unwrap();
    mock.server().reset().await;
    mock.with_manifest_package(serde_json::json!({"name":"@lpm-registry/mcp-server","version":"2.0.0","bin":{"mcp-server":"missing.js","helper":"helper.js"}}), &[("helper.js", b"#!/usr/bin/env node\nconsole.log('HELPER');")]).await;
    let output = lpm_with_registry(&project, &mock.url())
        .args(["mcp", "serve"])
        .output()
        .unwrap();
    assert!(!output.status.success(), "unusable MCP refresh succeeded");
    let manifest: serde_json::Value = serde_json::from_slice(
        &std::fs::read(
            mcp_runtime_root(&project).join("node_modules/@lpm-registry/mcp-server/package.json"),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        manifest["version"], "1.0.0",
        "unusable refresh discarded the previous runtime"
    );
    assert_eq!(
        std::fs::metadata(marker).unwrap().modified().unwrap(),
        modified
    );
}
