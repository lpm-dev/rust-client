mod support;

use flate2::Compression;
use flate2::write::GzEncoder;
use std::io::Write;
use support::{TempProject, lpm};
use wiremock::matchers::{method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

const ROLLDOWN_UPDATE_VERSION: &str = "1.2.5";

fn plugin_root(project: &TempProject) -> std::path::PathBuf {
    project.home().join(".lpm").join("plugins")
}

fn engine_root(project: &TempProject) -> std::path::PathBuf {
    project.home().join(".lpm").join("engines")
}

fn seed_installed_plugin(project: &TempProject, name: &str, version: &str) {
    use sha2::{Digest, Sha256};
    let platform = current_engine_platform();
    let directory = plugin_root(project).join(name).join(version).join(platform);
    std::fs::create_dir_all(&directory).unwrap();
    let binary = directory.join(name);
    let content = b"#!/bin/sh\nexit 0\n";
    std::fs::write(&binary, content).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let hash = format!("{:x}", Sha256::digest(content));
    let receipt = lpm_plugin::sidecar::Sidecar::new(
        name,
        version,
        platform,
        name,
        "https://example.invalid/tool",
        &hash,
        &hash,
        lpm_plugin::sidecar::VerificationSource::Bundled,
    )
    .with_current_binary_snapshot(&binary);
    lpm_plugin::sidecar::write_atomic(&directory.join(".lpm-plugin.json"), &receipt).unwrap();
}

fn plugin_entry<'a>(plugins: &'a [serde_json::Value], name: &str) -> &'a serde_json::Value {
    plugins
        .iter()
        .find(|plugin| plugin["name"] == serde_json::json!(name))
        .unwrap_or_else(|| panic!("missing plugin entry for {name}"))
}

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

fn current_engine_platform() -> &'static str {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("macos", "aarch64") => "darwin-arm64",
        ("macos", "x86_64") => "darwin-x64",
        ("linux", "x86_64") => "linux-x64",
        ("linux", "arm") => "linux-arm",
        ("linux", "aarch64") => "linux-arm64",
        ("windows", "x86_64") => "win-x64",
        ("windows", "aarch64") => "win-arm64",
        other => panic!("unsupported rolldown test platform: {other:?}"),
    }
}

fn rolldown_binding_package_for_current_platform() -> &'static str {
    match current_engine_platform() {
        "darwin-arm64" => "@rolldown/binding-darwin-arm64",
        "darwin-x64" => "@rolldown/binding-darwin-x64",
        "linux-arm" => "@rolldown/binding-linux-arm-gnueabihf",
        "linux-arm64" => "@rolldown/binding-linux-arm64-gnu",
        "linux-x64" => "@rolldown/binding-linux-x64-gnu",
        "win-arm64" => "@rolldown/binding-win32-arm64-msvc",
        "win-x64" => "@rolldown/binding-win32-x64-msvc",
        platform => panic!("unsupported rolldown test platform: {platform}"),
    }
}

fn encode_npm_path(package: &str) -> String {
    package.replace('@', "%40").replace('/', "%2f")
}

fn create_test_tarball(files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut tar_data = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut tar_data);
        for (name, content) in files {
            let mut header = tar::Header::new_gnu();
            header.set_size(content.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            let tar_path = format!("package/{name}");
            builder
                .append_data(&mut header, &tar_path, &content[..])
                .unwrap();
        }
        builder.finish().unwrap();
    }

    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(&tar_data).unwrap();
    encoder.finish().unwrap()
}

fn integrity(bytes: &[u8]) -> String {
    lpm_common::Integrity::from_bytes(lpm_common::integrity::HashAlgorithm::Sha512, bytes)
        .to_string()
}

fn npm_version_metadata(
    name: &str,
    version: &str,
    server: &MockServer,
    tarball_path: &str,
    tarball: &[u8],
) -> serde_json::Value {
    serde_json::json!({
        "name": name,
        "version": version,
        "dist": {
            "tarball": format!("{}{}", server.uri(), tarball_path),
            "integrity": integrity(tarball),
        },
    })
}

async fn mount_github_latest(server: &MockServer) {
    Mock::given(method("GET"))
        .and(path("/repos/oxc-project/oxc/releases"))
        .and(query_param("per_page", "20"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
            { "tag_name": "apps_v1.79.1" }
        ])))
        .mount(server)
        .await;

    Mock::given(method("GET"))
        .and(path("/repos/biomejs/biome/releases"))
        .and(query_param("per_page", "20"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
            { "tag_name": "@biomejs/biome@2.5.10" }
        ])))
        .mount(server)
        .await;
}

async fn mount_rolldown_update_graph(server: &MockServer) {
    let root_tarball = create_test_tarball(&[
        ("bin/cli.mjs", b"#!/usr/bin/env node\n"),
        (
            "package.json",
            br#"{"name":"rolldown","version":"1.2.5","bin":{"rolldown":"./bin/cli.mjs"}}"#,
        ),
    ]);
    let pluginutils_tarball = create_test_tarball(&[(
        "package.json",
        br#"{"name":"@rolldown/pluginutils","version":"1.1.0"}"#,
    )]);
    let oxc_types_tarball = create_test_tarball(&[(
        "package.json",
        br#"{"name":"@oxc-project/types","version":"0.146.0"}"#,
    )]);
    let binding_package = rolldown_binding_package_for_current_platform();
    let binding_package_json =
        format!(r#"{{"name":"{binding_package}","version":"{ROLLDOWN_UPDATE_VERSION}"}}"#);
    let binding_tarball = create_test_tarball(&[
        ("package.json", binding_package_json.as_bytes()),
        ("binding.node", b"binding-bytes"),
    ]);

    let root_path = "/rolldown/-/rolldown-1.2.5.tgz";
    let pluginutils_path = "/@rolldown/pluginutils/-/pluginutils-1.1.0.tgz";
    let oxc_types_path = "/@oxc-project/types/-/types-0.146.0.tgz";
    let binding_path = format!(
        "/{binding_package}/-/{}-{ROLLDOWN_UPDATE_VERSION}.tgz",
        binding_package.rsplit('/').next().unwrap()
    );

    let mut root = npm_version_metadata(
        "rolldown",
        ROLLDOWN_UPDATE_VERSION,
        server,
        root_path,
        &root_tarball,
    );
    root["dependencies"] = serde_json::json!({
        "@rolldown/pluginutils": "^1.0.0",
        "@oxc-project/types": "=0.146.0",
    });
    let mut optional_dependencies = serde_json::Map::new();
    optional_dependencies.insert(
        binding_package.to_string(),
        serde_json::json!(ROLLDOWN_UPDATE_VERSION),
    );
    root["optionalDependencies"] = serde_json::Value::Object(optional_dependencies);

    let pluginutils = npm_version_metadata(
        "@rolldown/pluginutils",
        "1.1.0",
        server,
        pluginutils_path,
        &pluginutils_tarball,
    );
    let oxc_types = npm_version_metadata(
        "@oxc-project/types",
        "0.146.0",
        server,
        oxc_types_path,
        &oxc_types_tarball,
    );
    let binding = npm_version_metadata(
        binding_package,
        ROLLDOWN_UPDATE_VERSION,
        server,
        &binding_path,
        &binding_tarball,
    );

    Mock::given(method("GET"))
        .and(path("/rolldown/latest"))
        .respond_with(ResponseTemplate::new(200).set_body_json(root))
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/{}", encode_npm_path("@rolldown/pluginutils"))))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "versions": {
                "1.0.0": npm_version_metadata("@rolldown/pluginutils", "1.0.0", server, pluginutils_path, &pluginutils_tarball),
                "1.1.0": pluginutils,
            }
        })))
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!(
            "/{}/0.146.0",
            encode_npm_path("@oxc-project/types")
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(oxc_types))
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!(
            "/{}/{}",
            encode_npm_path(binding_package),
            ROLLDOWN_UPDATE_VERSION
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(binding))
        .mount(server)
        .await;

    for (tarball_path, tarball) in [
        (root_path.to_string(), root_tarball),
        (pluginutils_path.to_string(), pluginutils_tarball),
        (oxc_types_path.to_string(), oxc_types_tarball),
        (binding_path, binding_tarball),
    ] {
        Mock::given(method("GET"))
            .and(path(tarball_path))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(tarball))
            .mount(server)
            .await;
    }
}

#[test]
fn plugin_list_json_reports_installed_versions_and_known_latest_versions() {
    let project = TempProject::empty(r#"{"name":"plugin-test","version":"1.0.0"}"#);
    seed_installed_plugin(&project, "oxlint", "1.57.0");

    let output = lpm(&project)
        .args(["plugin", "list", "--json"])
        .output()
        .expect("failed to run lpm plugin list --json");

    assert!(
        output.status.success(),
        "lpm plugin list --json failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let envelope: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("plugin list --json must be valid JSON: {e}\n---\n{stdout}"));

    assert_eq!(envelope["success"], serde_json::json!(true));
    let plugins = envelope["plugins"]
        .as_array()
        .expect("plugins must be an array");
    assert_eq!(envelope["count"], serde_json::json!(plugins.len()));

    let oxlint = plugin_entry(plugins, "oxlint");
    assert_eq!(oxlint["installed"], serde_json::json!(["1.57.0"]));
    assert_eq!(oxlint["current"], serde_json::json!("1.57.0"));
    assert_eq!(oxlint["latest"], serde_json::json!("1.79.0"));

    let biome = plugin_entry(plugins, "biome");
    assert_eq!(biome["installed"], serde_json::json!([]));
    assert_eq!(biome["current"], serde_json::json!("not installed"));
    assert_eq!(biome["latest"], serde_json::json!("2.5.9"));

    let rolldown = plugin_entry(plugins, "rolldown");
    assert_eq!(rolldown["installed"], serde_json::json!([]));
    assert_eq!(rolldown["current"], serde_json::json!("not installed"));
    assert_eq!(rolldown["latest"], serde_json::json!("1.2.4"));

    insta::assert_json_snapshot!("plugin_list_json_one_installed_plugin", envelope);
}

#[test]
fn plugin_list_human_renders_table_and_slim_completion() {
    let project = TempProject::empty(r#"{"name":"plugin-test","version":"1.0.0"}"#);
    seed_installed_plugin(&project, "oxlint", "1.57.0");
    seed_installed_plugin(&project, "biome", "2.5.9");

    let output = lpm(&project)
        .args(["--color=always", "plugin", "list"])
        .output()
        .expect("failed to run lpm plugin list");

    assert!(
        output.status.success(),
        "lpm plugin list failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let stdout_raw = String::from_utf8_lossy(&output.stdout);
    let stdout = strip_ansi(&stdout_raw);
    assert!(
        stdout.contains("Plugin") && stdout.contains("Current") && stdout.contains("Latest"),
        "plugin list must render a table header, got:\n{stdout}"
    );
    assert!(
        stdout.contains("oxlint") && stdout.contains("1.57.0"),
        "plugin list must render the installed plugin row, got:\n{stdout}"
    );
    assert!(
        stdout.contains("biome") && stdout.contains("current"),
        "plugin list must render the current status row, got:\n{stdout}"
    );
    assert!(
        stdout.contains("rolldown"),
        "plugin list must include managed plugins, got:\n{stdout}"
    );
    assert!(
        stdout.contains("update available"),
        "plugin list must render update status, got:\n{stdout}"
    );
    assert!(
        stdout_raw.contains("\u{1b}[2mPlugin")
            && stdout_raw.contains("\u{1b}[2m1.57.0")
            && stdout_raw.contains("\u{1b}[33m1.79.0")
            && stdout_raw.contains("\u{1b}[33mupdate available")
            && stdout_raw.contains("\u{1b}[32mcurrent"),
        "plugin list must apply slim color roles, got:\n{stdout_raw:?}"
    );

    let stderr_raw = String::from_utf8_lossy(&output.stderr);
    let stderr = strip_ansi(&stderr_raw);
    assert!(
        stderr.contains("✓ 3 managed plugins"),
        "plugin list must report a slim installed count, got:\n{stderr}"
    );
    assert!(
        !stderr.contains('●') && !stderr.contains('│'),
        "plugin list status output must not use cliclack gutter output, got:\n{stderr}"
    );
}

#[tokio::test]
async fn plugin_outdated_json_reports_managed_tools_and_project_owned_tsdown() {
    let project = TempProject::empty(r#"{"name":"plugin-test","version":"1.0.0"}"#);
    let server = MockServer::start().await;
    mount_github_latest(&server).await;
    mount_rolldown_update_graph(&server).await;

    let output = lpm(&project)
        .env("LPM_PLUGIN_GITHUB_API_BASE", server.uri())
        .env("LPM_MANAGED_TOOL_NPM_REGISTRY", server.uri())
        .args(["plugin", "outdated", "--json"])
        .output()
        .expect("failed to run lpm plugin outdated --json");

    assert!(
        output.status.success(),
        "lpm plugin outdated --json failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let envelope: serde_json::Value = serde_json::from_str(&stdout).unwrap_or_else(|e| {
        panic!("plugin outdated --json must be valid JSON: {e}\n---\n{stdout}")
    });
    let plugins = envelope["plugins"]
        .as_array()
        .expect("plugins must be an array");

    assert_eq!(envelope["success"], serde_json::json!(true));
    assert_eq!(envelope["outdated_count"], serde_json::json!(3));
    assert_eq!(plugin_entry(plugins, "oxlint")["latest"], "1.79.1");
    assert_eq!(plugin_entry(plugins, "biome")["latest"], "2.5.10");
    assert_eq!(
        plugin_entry(plugins, "rolldown")["latest"],
        ROLLDOWN_UPDATE_VERSION
    );
    assert_eq!(
        envelope["project_owned"][0]["name"],
        serde_json::json!("tsdown")
    );

    insta::assert_json_snapshot!("plugin_outdated_json_managed_tools", envelope);
}

#[tokio::test]
async fn plugin_update_rolldown_downloads_verified_graph_and_approves_version() {
    let project = TempProject::empty(r#"{"name":"plugin-test","version":"1.0.0"}"#);
    let server = MockServer::start().await;
    mount_rolldown_update_graph(&server).await;

    let output = lpm(&project)
        .env("LPM_MANAGED_TOOL_NPM_REGISTRY", server.uri())
        .args(["plugin", "update", "rolldown"])
        .output()
        .expect("failed to run lpm plugin update rolldown");

    assert!(
        output.status.success(),
        "lpm plugin update rolldown failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Checking rolldown releases")
            && stderr.contains("Downloading rolldown")
            && stderr.contains("Verified npm package integrity")
            && stderr.contains("Updated rolldown"),
        "plugin update rolldown must render slim update phases, got:\n{stderr}"
    );

    let platform = current_engine_platform();
    assert!(
        engine_root(&project)
            .join("rolldown")
            .join(ROLLDOWN_UPDATE_VERSION)
            .join(platform)
            .join(".lpm-engine.json")
            .exists(),
        "rolldown sidecar should be installed for {platform}"
    );

    let cache = std::fs::read_to_string(engine_root(&project).join(".version-cache.json"))
        .expect("engine version cache should be written");
    let cache_json: serde_json::Value =
        serde_json::from_str(&cache).expect("engine version cache should be JSON");
    assert_eq!(
        cache_json["engines"]["rolldown"]["selected"][platform],
        serde_json::json!(ROLLDOWN_UPDATE_VERSION)
    );
}

#[test]
fn plugin_update_json_reports_zero_updates_when_no_plugins_are_installed() {
    let project = TempProject::empty(r#"{"name":"plugin-test","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args(["plugin", "update", "--json"])
        .output()
        .expect("failed to run lpm plugin update --json");

    assert!(
        output.status.success(),
        "lpm plugin update --json failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let envelope: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("plugin update --json must be valid JSON: {e}\n---\n{stdout}"));

    assert_eq!(envelope["success"], serde_json::json!(true));
    assert_eq!(envelope["count"], serde_json::json!(0));
    assert_eq!(envelope["updated"], serde_json::json!([]));

    insta::assert_json_snapshot!("plugin_update_json_zero_installed_plugins", envelope);
}

#[test]
fn plugin_update_human_zero_installed_uses_slim_warning() {
    let project = TempProject::empty(r#"{"name":"plugin-test","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args(["plugin", "update"])
        .output()
        .expect("failed to run lpm plugin update");

    assert!(
        output.status.success(),
        "lpm plugin update failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("! No managed plugins installed to update"),
        "plugin update must use a slim warning when nothing is installed, got:\n{stderr}"
    );
    assert!(
        !stderr.contains('●') && !stderr.contains('│'),
        "plugin update status output must not use cliclack gutter output, got:\n{stderr}"
    );
}

#[test]
fn plugin_remove_rejects_paths_and_preserves_external_sentinels() {
    let project = TempProject::empty(r#"{"name":"plugin-paths"}"#);
    let victim = project.home().join(".lpm/victim");
    for name in [
        "../victim".to_string(),
        victim.to_string_lossy().into_owned(),
    ] {
        std::fs::create_dir_all(&victim).unwrap();
        std::fs::write(victim.join("keep.txt"), "untouched").unwrap();
        let output = lpm(&project)
            .args(["plugin", "remove", &name, "--json"])
            .output()
            .unwrap();
        assert!(!output.status.success(), "unsafe name accepted: {name}");
        assert_eq!(
            std::fs::read_to_string(victim.join("keep.txt")).unwrap(),
            "untouched"
        );
    }
}

#[test]
fn plugin_list_ignores_incomplete_and_staging_directories() {
    let project = TempProject::empty(r#"{"name":"plugin-incomplete"}"#);
    for root in [
        plugin_root(&project).join("oxlint"),
        engine_root(&project).join("rolldown"),
    ] {
        for version in ["1.0.0", "1.1.0", ".stage-incomplete"] {
            std::fs::create_dir_all(root.join(version)).unwrap();
        }
        std::fs::write(root.join("1.1.0/.install.lock"), "").unwrap();
    }
    let output = lpm(&project)
        .args(["plugin", "list", "--json"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let value = support::assertions::parse_json_output(&output.stdout);
    for name in ["oxlint", "rolldown"] {
        let row = plugin_entry(value["plugins"].as_array().unwrap(), name);
        assert_eq!(row["installed"], serde_json::json!([]), "{value}");
    }
}

#[test]
fn plugin_list_orders_installed_versions_semantically() {
    let project = TempProject::empty(r#"{"name":"plugin-order"}"#);
    for version in ["1.2.0", "1.10.0", "1.9.0"] {
        seed_installed_plugin(&project, "oxlint", version);
    }
    let output = lpm(&project)
        .args(["plugin", "list", "--json"])
        .output()
        .unwrap();
    let value = support::assertions::parse_json_output(&output.stdout);
    assert_eq!(
        plugin_entry(value["plugins"].as_array().unwrap(), "oxlint")["installed"],
        serde_json::json!(["1.2.0", "1.9.0", "1.10.0"])
    );
}

#[test]
fn plugin_list_and_outdated_reject_an_ignored_name() {
    let project = TempProject::empty(r#"{"name":"plugin-names"}"#);
    for action in ["list", "ls", "outdated"] {
        let output = lpm(&project)
            .env("HTTPS_PROXY", "http://127.0.0.1:1")
            .env("ALL_PROXY", "http://127.0.0.1:1")
            .env("NO_PROXY", "")
            .args(["plugin", action, "biome", "--json"])
            .output()
            .unwrap();
        assert!(
            !output.status.success(),
            "{action} silently ignored the name"
        );
    }
}

#[tokio::test]
async fn plugin_outdated_selects_the_highest_stable_nondraft_release() {
    let project = TempProject::empty(r#"{"name":"plugin-releases"}"#);
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/repos/oxc-project/oxc/releases"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
            {"tag_name":"apps_v9.0.0", "draft":true, "prerelease":false},
            {"tag_name":"apps_v8.0.0", "draft":false, "prerelease":true},
            {"tag_name":"apps_v7.0.0-beta.1", "draft":false, "prerelease":false},
            {"tag_name":"apps_v2.9.0", "draft":false, "prerelease":false},
            {"tag_name":"apps_v2.10.0", "draft":false, "prerelease":false}
        ])))
        .mount(&server)
        .await;
    let output = lpm(&project)
        .env("LPM_PLUGIN_GITHUB_API_BASE", server.uri())
        .env("LPM_MANAGED_TOOL_NPM_REGISTRY", server.uri())
        .args(["plugin", "outdated", "--json"])
        .output()
        .unwrap();
    let value = support::assertions::parse_json_output(&output.stdout);
    assert_eq!(
        plugin_entry(value["plugins"].as_array().unwrap(), "oxlint")["latest"],
        "2.10.0",
        "{value}"
    );
}

#[tokio::test]
async fn plugin_failed_engine_download_removes_its_stage() {
    let project = TempProject::empty(r#"{"name":"plugin-stage"}"#);
    let server = MockServer::start().await;
    mount_rolldown_update_graph(&server).await;
    Mock::given(method("GET"))
        .and(path("/rolldown/-/rolldown-1.2.5.tgz"))
        .respond_with(ResponseTemplate::new(500))
        .with_priority(1)
        .mount(&server)
        .await;
    let output = lpm(&project)
        .env("LPM_MANAGED_TOOL_NPM_REGISTRY", server.uri())
        .args(["plugin", "update", "rolldown", "--json"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let version = engine_root(&project)
        .join("rolldown")
        .join(ROLLDOWN_UPDATE_VERSION);
    if version.exists() {
        let stages: Vec<_> = std::fs::read_dir(version)
            .unwrap()
            .flatten()
            .filter(|entry| entry.file_type().is_ok_and(|kind| kind.is_dir()))
            .collect();
        assert!(
            stages.is_empty(),
            "failed install left staging directories: {stages:?}"
        );
    }
}

#[cfg(unix)]
#[test]
fn plugin_failed_forced_download_preserves_the_previous_binary_and_receipt() {
    let project = TempProject::empty(r#"{"name":"plugin-replace"}"#);
    let version = lpm_plugin::registry::get_plugin("oxlint")
        .unwrap()
        .latest_version;
    seed_installed_plugin(&project, "oxlint", version);
    let directory = plugin_root(&project)
        .join("oxlint")
        .join(version)
        .join(current_engine_platform());
    let binary = std::fs::read(directory.join("oxlint")).unwrap();
    let receipt = std::fs::read(directory.join(".lpm-plugin.json")).unwrap();
    let output = lpm(&project)
        .env("LPM_FORCE_TOOL_INSTALL", "1")
        .env("HTTPS_PROXY", "http://127.0.0.1:1")
        .env("ALL_PROXY", "http://127.0.0.1:1")
        .env("NO_PROXY", "")
        .args(["lint", "--json"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert_eq!(std::fs::read(directory.join("oxlint")).unwrap(), binary);
    assert_eq!(
        std::fs::read(directory.join(".lpm-plugin.json")).unwrap(),
        receipt
    );
}

fn command_waits_for_tool_installation(
    project: &TempProject,
    namespace: &str,
    name: &str,
    version: &str,
    command: &mut std::process::Command,
) -> bool {
    let root = project.home().join(".lpm");
    let legacy = root
        .join(namespace)
        .join(name)
        .join(version)
        .join(".install.lock");
    let stable = root
        .join(".locks")
        .join(namespace)
        .join("operations")
        .join(format!("{name}.lock"));
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let holder = std::thread::spawn(move || {
        lpm_common::with_exclusive_lock(legacy, || {
            lpm_common::with_exclusive_lock(stable, || {
                ready_tx.send(()).unwrap();
                release_rx.recv().unwrap();
                Ok::<_, lpm_common::LpmError>(())
            })
        })
        .unwrap();
    });
    ready_rx
        .recv_timeout(std::time::Duration::from_secs(5))
        .unwrap();
    let mut child = command
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
    let blocked = loop {
        if child.try_wait().unwrap().is_some() {
            break false;
        }
        if std::time::Instant::now() >= deadline {
            break true;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    };
    release_tx.send(()).unwrap();
    holder.join().unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    blocked
}

#[test]
fn plugin_removal_waits_for_an_active_installation() {
    let project = TempProject::empty(r#"{"name":"plugin-remove-lock"}"#);
    seed_installed_plugin(&project, "oxlint", "1.0.0");
    let mut command = support::lpm_spawnable(&project);
    command.args(["plugin", "remove", "oxlint", "--json"]);
    assert!(command_waits_for_tool_installation(
        &project,
        "plugins",
        "oxlint",
        "1.0.0",
        &mut command
    ));
}

#[tokio::test]
async fn plugin_rolldown_update_waits_for_an_active_installation() {
    let project = TempProject::empty(r#"{"name":"plugin-update-lock"}"#);
    let server = MockServer::start().await;
    mount_rolldown_update_graph(&server).await;
    let mut command = support::lpm_spawnable(&project);
    command
        .env("LPM_MANAGED_TOOL_NPM_REGISTRY", server.uri())
        .args(["plugin", "update", "rolldown", "--json"]);
    assert!(command_waits_for_tool_installation(
        &project,
        "engines",
        "rolldown",
        ROLLDOWN_UPDATE_VERSION,
        &mut command
    ));
}

#[cfg(unix)]
#[test]
fn plugin_cached_execution_waits_for_installation_before_refreshing_its_receipt() {
    let project = TempProject::empty(r#"{"name":"plugin-reuse-lock"}"#);
    let version = lpm_plugin::registry::get_plugin("oxlint")
        .unwrap()
        .latest_version;
    seed_installed_plugin(&project, "oxlint", version);
    let mut command = support::lpm_spawnable(&project);
    command.args(["lint", "--json"]);
    assert!(command_waits_for_tool_installation(
        &project,
        "plugins",
        "oxlint",
        version,
        &mut command
    ));
}

#[test]
fn plugin_remove_rejects_dot_versions_without_deleting_other_versions() {
    let project = TempProject::empty(r#"{"name":"plugin-dot-version"}"#);
    for (namespace, name) in [("plugins", "oxlint"), ("engines", "rolldown")] {
        let keep = project
            .home()
            .join(".lpm")
            .join(namespace)
            .join(name)
            .join("1.0.0")
            .join("keep.txt");
        std::fs::create_dir_all(keep.parent().unwrap()).unwrap();
        std::fs::write(&keep, "untouched").unwrap();
        let output = lpm(&project)
            .args(["plugin", "remove", &format!("{name}@."), "--json"])
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert_eq!(std::fs::read_to_string(&keep).unwrap(), "untouched");
    }
}

#[tokio::test]
async fn plugin_outdated_checks_later_release_pages_before_selecting_latest() {
    let project = TempProject::empty(r#"{"name":"plugin-pages"}"#);
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/repos/oxc-project/oxc/releases"))
        .and(wiremock::matchers::query_param("page", "2"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
            {"tag_name":"apps_v3.0.0", "draft":false, "prerelease":false}
        ])))
        .expect(1)
        .with_priority(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/repos/oxc-project/oxc/releases"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("link", "<https://untrusted.invalid/next>; rel=\"next\"")
                .set_body_json(serde_json::json!([{ "tag_name":"apps_v2.0.0" }])),
        )
        .expect(1)
        .with_priority(2)
        .mount(&server)
        .await;
    let output = lpm(&project)
        .env("LPM_PLUGIN_GITHUB_API_BASE", server.uri())
        .env("LPM_MANAGED_TOOL_NPM_REGISTRY", server.uri())
        .args(["plugin", "outdated", "--json"])
        .output()
        .unwrap();
    let value = support::assertions::parse_json_output(&output.stdout);
    assert_eq!(
        plugin_entry(value["plugins"].as_array().unwrap(), "oxlint")["latest"],
        "3.0.0"
    );
}
