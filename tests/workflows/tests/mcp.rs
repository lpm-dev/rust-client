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
        stderr.contains("specify server name") || stderr.contains("name"),
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
    let expected = serde_json::json!({
        "command": "lpm",
        "args": ["mcp", "serve"]
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
    insta::assert_json_snapshot!(envelope, @r###"
    {
      "success": true,
      "server": "lpm-registry",
      "configured": [
        "Claude Code"
      ],
      "package": "@lpm-registry/mcp-server",
      "package_spec": "@lpm-registry/mcp-server@latest",
      "version_policy": "latest-security-eligible",
      "command": "lpm",
      "args": [
        "mcp",
        "serve"
      ]
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
fn mcp_unknown_action_lists_valid_subcommands() {
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
        stderr.contains("setup")
            && stderr.contains("remove")
            && stderr.contains("status")
            && stderr.contains("serve"),
        "stderr must enumerate valid actions, got:\n{stderr}",
    );
}
