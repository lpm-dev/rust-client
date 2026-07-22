mod support;

use flate2::Compression;
use flate2::write::GzEncoder;
use std::io::Write;
use support::{TempProject, lpm};
use wiremock::matchers::{method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

const ROLLDOWN_UPDATE_VERSION: &str = "1.2.1";

fn plugin_root(project: &TempProject) -> std::path::PathBuf {
    project.home().join(".lpm").join("plugins")
}

fn engine_root(project: &TempProject) -> std::path::PathBuf {
    project.home().join(".lpm").join("engines")
}

fn seed_installed_plugin(project: &TempProject, name: &str, version: &str) {
    std::fs::create_dir_all(
        plugin_root(project)
            .join(name)
            .join(version)
            .join("darwin-arm64"),
    )
    .expect("failed to seed installed plugin directory");
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
            { "tag_name": "apps_v1.75.1" }
        ])))
        .mount(server)
        .await;

    Mock::given(method("GET"))
        .and(path("/repos/biomejs/biome/releases"))
        .and(query_param("per_page", "20"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
            { "tag_name": "@biomejs/biome@2.5.6" }
        ])))
        .mount(server)
        .await;
}

async fn mount_rolldown_update_graph(server: &MockServer) {
    let root_tarball = create_test_tarball(&[
        ("bin/cli.mjs", b"#!/usr/bin/env node\n"),
        (
            "package.json",
            br#"{"name":"rolldown","version":"1.2.1","bin":{"rolldown":"./bin/cli.mjs"}}"#,
        ),
    ]);
    let pluginutils_tarball = create_test_tarball(&[(
        "package.json",
        br#"{"name":"@rolldown/pluginutils","version":"1.1.0"}"#,
    )]);
    let oxc_types_tarball = create_test_tarball(&[(
        "package.json",
        br#"{"name":"@oxc-project/types","version":"0.140.0"}"#,
    )]);
    let binding_package = rolldown_binding_package_for_current_platform();
    let binding_package_json =
        format!(r#"{{"name":"{binding_package}","version":"{ROLLDOWN_UPDATE_VERSION}"}}"#);
    let binding_tarball = create_test_tarball(&[
        ("package.json", binding_package_json.as_bytes()),
        ("binding.node", b"binding-bytes"),
    ]);

    let root_path = "/rolldown/-/rolldown-1.2.1.tgz";
    let pluginutils_path = "/@rolldown/pluginutils/-/pluginutils-1.1.0.tgz";
    let oxc_types_path = "/@oxc-project/types/-/types-0.140.0.tgz";
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
        "@oxc-project/types": "=0.140.0",
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
        "0.140.0",
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
            "/{}/0.140.0",
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
    assert_eq!(oxlint["latest"], serde_json::json!("1.75.0"));

    let biome = plugin_entry(plugins, "biome");
    assert_eq!(biome["installed"], serde_json::json!([]));
    assert_eq!(biome["current"], serde_json::json!("not installed"));
    assert_eq!(biome["latest"], serde_json::json!("2.5.5"));

    let rolldown = plugin_entry(plugins, "rolldown");
    assert_eq!(rolldown["installed"], serde_json::json!([]));
    assert_eq!(rolldown["current"], serde_json::json!("not installed"));
    assert_eq!(rolldown["latest"], serde_json::json!("1.2.0"));

    insta::assert_json_snapshot!("plugin_list_json_one_installed_plugin", envelope);
}

#[test]
fn plugin_list_human_renders_table_and_slim_completion() {
    let project = TempProject::empty(r#"{"name":"plugin-test","version":"1.0.0"}"#);
    seed_installed_plugin(&project, "oxlint", "1.57.0");
    seed_installed_plugin(&project, "biome", "2.5.5");

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
            && stdout_raw.contains("\u{1b}[33m1.75.0")
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
    assert_eq!(plugin_entry(plugins, "oxlint")["latest"], "1.75.1");
    assert_eq!(plugin_entry(plugins, "biome")["latest"], "2.5.6");
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
