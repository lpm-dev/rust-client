use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use sha2::{Digest, Sha512};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const PACKAGE_NAME: &str = "@lpm.dev/acme.widget";
const CURRENT_VERSION: &str = "1.2.0";
const MINOR_VERSION: &str = "1.3.0";
const MAJOR_VERSION: &str = "2.0.0";

struct CommandOutput {
    status: ExitStatus,
    stdout: String,
    stderr: String,
}

struct MockUpgradeRegistry {
    server: MockServer,
}

struct VersionFixture {
    version: &'static str,
    dependencies: serde_json::Value,
    peer_dependencies: serde_json::Value,
    lifecycle_scripts: Option<serde_json::Value>,
    tarball: Vec<u8>,
}

impl MockUpgradeRegistry {
    async fn start() -> Self {
        Self {
            server: MockServer::start().await,
        }
    }

    fn url(&self) -> String {
        self.server.uri()
    }

    async fn mount_upgrade_package(
        &self,
        package_name: &str,
        latest: &str,
        versions: &[VersionFixture],
        fail_tarball_version: Option<&str>,
    ) -> serde_json::Value {
        let metadata = package_metadata(&self.url(), package_name, latest, versions);

        Mock::given(method("GET"))
            .and(path(format!("/api/registry/{package_name}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(metadata.clone()))
            .mount(&self.server)
            .await;

        Mock::given(method("POST"))
            .and(path("/api/registry/batch-metadata"))
            .respond_with(ResponseTemplate::new(200).set_body_json({
                let mut packages = serde_json::Map::new();
                packages.insert(package_name.to_string(), metadata.clone());
                serde_json::json!({ "packages": packages })
            }))
            .mount(&self.server)
            .await;

        for version in versions {
            let tarball_path = tarball_path(package_name, version.version);
            let response = if Some(version.version) == fail_tarball_version {
                ResponseTemplate::new(404).set_body_string("missing tarball")
            } else {
                ResponseTemplate::new(200)
                    .set_body_bytes(version.tarball.clone())
                    .insert_header("content-type", "application/octet-stream")
            };

            Mock::given(method("GET"))
                .and(path(tarball_path))
                .respond_with(response)
                .mount(&self.server)
                .await;
        }

        metadata
    }
}

fn project_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir()
        .join("lpm-upgrade-phase7-regression")
        .join(format!("{name}.{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn run_lpm(cwd: &Path, args: &[&str], registry_url: Option<&str>) -> CommandOutput {
    let exe = env!("CARGO_BIN_EXE_lpm-rs");
    let home = cwd.join(".home");
    fs::create_dir_all(&home).unwrap();

    let mut command = Command::new(exe);
    command
        .args(args)
        .current_dir(cwd)
        .env("HOME", &home)
        .env("NO_COLOR", "1")
        .env("LPM_NO_UPDATE_CHECK", "1")
        .env("LPM_DISABLE_TELEMETRY", "1")
        .env("LPM_FORCE_FILE_VAULT", "1")
        .env_remove("LPM_TOKEN")
        .env_remove("RUST_LOG");

    if let Some(url) = registry_url {
        command.env("LPM_REGISTRY_URL", url);
    }

    let output = command.output().expect("failed to spawn lpm-rs");
    CommandOutput {
        status: output.status,
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
    }
}

fn write_manifest(path: &Path, value: &serde_json::Value) {
    fs::write(
        path.join("package.json"),
        serde_json::to_string_pretty(value).unwrap(),
    )
    .unwrap();
}

fn write_lockfile(dir: &Path, entries: &[(&str, &str)]) {
    let packages = entries
        .iter()
        .map(|(name, version)| {
            format!(
                r#"[[packages]]
name = "{name}"
version = "{version}"
"#
            )
        })
        .collect::<Vec<_>>()
        .join("\n");

    let lockfile = format!(
        r#"[metadata]
lockfile-version = 1
resolved-with = "pubgrub"

{packages}
"#
    );

    fs::write(dir.join("lpm.lock"), lockfile).unwrap();
}

fn manifest_with_dependency(range: &str, include_patch: bool) -> serde_json::Value {
    let mut dependencies = serde_json::Map::new();
    dependencies.insert(
        PACKAGE_NAME.to_string(),
        serde_json::Value::String(range.to_string()),
    );

    let mut value = serde_json::json!({
        "name": "upgrade-phase7-test",
        "version": "1.0.0",
        "dependencies": dependencies,
    });

    if include_patch {
        let mut patched_dependencies = serde_json::Map::new();
        patched_dependencies.insert(
            format!("{PACKAGE_NAME}@{CURRENT_VERSION}"),
            serde_json::json!({
                "path": "patches/acme-widget.patch",
                "originalIntegrity": "sha512-original-fixture"
            }),
        );
        value["lpm"] = serde_json::json!({
            "patchedDependencies": patched_dependencies,
        });
    }

    value
}

fn parse_stdout_json(stdout: &str, stderr: &str) -> serde_json::Value {
    serde_json::from_str(stdout).unwrap_or_else(|err| {
        panic!("stdout was not valid JSON: {err}\nstdout:\n{stdout}\nstderr:\n{stderr}")
    })
}

fn package_metadata(
    registry_url: &str,
    package_name: &str,
    latest: &str,
    versions: &[VersionFixture],
) -> serde_json::Value {
    let mut versions_map = serde_json::Map::new();
    let mut times_map = serde_json::Map::new();

    for version in versions {
        let tarball_url = format!(
            "{registry_url}{}",
            tarball_path(package_name, version.version)
        );
        let integrity = compute_integrity(&version.tarball);
        let mut value = serde_json::json!({
            "name": package_name,
            "version": version.version,
            "dist": {
                "tarball": tarball_url,
                "integrity": integrity,
            },
            "dependencies": version.dependencies.clone(),
        });

        if !version.peer_dependencies.is_null() {
            value["peerDependencies"] = version.peer_dependencies.clone();
        }
        if let Some(scripts) = &version.lifecycle_scripts {
            value["_lifecycleScripts"] = scripts.clone();
        }

        versions_map.insert(version.version.to_string(), value);
        times_map.insert(
            version.version.to_string(),
            serde_json::Value::String("2025-01-01T00:00:00.000Z".into()),
        );
    }

    serde_json::json!({
        "name": package_name,
        "dist-tags": {
            "latest": latest,
        },
        "versions": versions_map,
        "time": times_map,
    })
}

fn tarball_path(package_name: &str, version: &str) -> String {
    let slug = package_name
        .chars()
        .map(|ch| if ch.is_ascii_alphanumeric() { ch } else { '-' })
        .collect::<String>();
    format!("/tarballs/{slug}-{version}.tgz")
}

fn compute_integrity(data: &[u8]) -> String {
    let digest = Sha512::digest(data);
    format!("sha512-{}", BASE64.encode(digest))
}

fn make_tarball(name: &str, version: &str) -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());

    let package_json = serde_json::json!({
        "name": name,
        "version": version,
        "main": "index.js",
    });
    let package_json_bytes = serde_json::to_vec_pretty(&package_json).unwrap();
    let mut header = tar::Header::new_gnu();
    header.set_path("package/package.json").unwrap();
    header.set_size(package_json_bytes.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    builder.append(&header, &package_json_bytes[..]).unwrap();

    let index_js = b"module.exports = 'phase7';\n";
    let mut header = tar::Header::new_gnu();
    header.set_path("package/index.js").unwrap();
    header.set_size(index_js.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    builder.append(&header, &index_js[..]).unwrap();

    let tar_bytes = builder.into_inner().unwrap();
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(&tar_bytes).unwrap();
    encoder.finish().unwrap()
}

async fn setup_enriched_dry_run_fixture(test_name: &str) -> (PathBuf, MockUpgradeRegistry) {
    let dir = project_dir(test_name);
    write_manifest(&dir, &manifest_with_dependency("^1.2.0", true));
    write_lockfile(
        &dir,
        &[(PACKAGE_NAME, CURRENT_VERSION), ("react", "17.0.2")],
    );

    let mock = MockUpgradeRegistry::start().await;
    let versions = vec![
        VersionFixture {
            version: CURRENT_VERSION,
            dependencies: serde_json::json!({}),
            peer_dependencies: serde_json::Value::Null,
            lifecycle_scripts: None,
            tarball: make_tarball(PACKAGE_NAME, CURRENT_VERSION),
        },
        VersionFixture {
            version: MINOR_VERSION,
            dependencies: serde_json::json!({}),
            peer_dependencies: serde_json::json!({
                "react": "^18.0.0"
            }),
            lifecycle_scripts: Some(serde_json::json!({
                "postinstall": "node install.js"
            })),
            tarball: make_tarball(PACKAGE_NAME, MINOR_VERSION),
        },
    ];
    mock.mount_upgrade_package(PACKAGE_NAME, MINOR_VERSION, &versions, None)
        .await;

    (dir, mock)
}

async fn setup_successful_upgrade_fixture(
    test_name: &str,
    latest: &'static str,
    include_major: bool,
) -> (PathBuf, MockUpgradeRegistry) {
    let dir = project_dir(test_name);
    write_manifest(&dir, &manifest_with_dependency("^1.2.0", false));

    let mock = MockUpgradeRegistry::start().await;
    let mut versions = vec![
        VersionFixture {
            version: CURRENT_VERSION,
            dependencies: serde_json::json!({}),
            peer_dependencies: serde_json::Value::Null,
            lifecycle_scripts: None,
            tarball: make_tarball(PACKAGE_NAME, CURRENT_VERSION),
        },
        VersionFixture {
            version: MINOR_VERSION,
            dependencies: serde_json::json!({}),
            peer_dependencies: serde_json::Value::Null,
            lifecycle_scripts: None,
            tarball: make_tarball(PACKAGE_NAME, MINOR_VERSION),
        },
    ];

    if include_major {
        versions.push(VersionFixture {
            version: MAJOR_VERSION,
            dependencies: serde_json::json!({}),
            peer_dependencies: serde_json::Value::Null,
            lifecycle_scripts: None,
            tarball: make_tarball(PACKAGE_NAME, MAJOR_VERSION),
        });
    }

    mock.mount_upgrade_package(PACKAGE_NAME, latest, &versions, None)
        .await;

    (dir, mock)
}

async fn setup_failed_install_fixture(test_name: &str) -> (PathBuf, MockUpgradeRegistry) {
    let dir = project_dir(test_name);
    write_manifest(&dir, &manifest_with_dependency("^1.2.0", false));

    let mock = MockUpgradeRegistry::start().await;
    let versions = vec![
        VersionFixture {
            version: CURRENT_VERSION,
            dependencies: serde_json::json!({}),
            peer_dependencies: serde_json::Value::Null,
            lifecycle_scripts: None,
            tarball: make_tarball(PACKAGE_NAME, CURRENT_VERSION),
        },
        VersionFixture {
            version: MINOR_VERSION,
            dependencies: serde_json::json!({}),
            peer_dependencies: serde_json::Value::Null,
            lifecycle_scripts: None,
            tarball: make_tarball(PACKAGE_NAME, MINOR_VERSION),
        },
    ];
    mock.mount_upgrade_package(PACKAGE_NAME, MINOR_VERSION, &versions, Some(MINOR_VERSION))
        .await;

    (dir, mock)
}

#[test]
fn cli_upgrade_yes_with_no_candidates_emits_legacy_success() {
    let dir = project_dir("no-candidates-json");
    write_manifest(
        &dir,
        &serde_json::json!({
            "name": "no-candidates",
            "version": "1.0.0",
            "dependencies": {
                "left-pad": "1.3.0"
            }
        }),
    );

    let output = run_lpm(&dir, &["upgrade", "-y", "--json"], None);
    assert!(
        output.status.success(),
        "upgrade -y --json should succeed\nstdout:\n{}\nstderr:\n{}",
        output.stdout,
        output.stderr,
    );

    let json = parse_stdout_json(&output.stdout, &output.stderr);
    assert_eq!(json["success"], true);
    assert_eq!(json["upgraded"], 0);
    assert_eq!(json["packages"], serde_json::json!([]));
    assert_eq!(json["fetch_errors"], 0);
}

#[tokio::test]
async fn cli_upgrade_yes_with_legacy_jsonshape_unchanged() {
    let (dir, mock) = setup_enriched_dry_run_fixture("legacy-json-shape").await;
    let output = run_lpm(
        &dir,
        &["upgrade", "-y", "--json", "--dry-run"],
        Some(&mock.url()),
    );
    assert!(
        output.status.success(),
        "{}{}",
        output.stdout,
        output.stderr
    );

    let json = parse_stdout_json(&output.stdout, &output.stderr);
    let package = &json["packages"][0];
    assert_eq!(package["name"], PACKAGE_NAME);
    assert_eq!(package["from"], CURRENT_VERSION);
    assert_eq!(package["to"], MINOR_VERSION);
    assert_eq!(package["new_range"], "^1.3.0");
    assert_eq!(package["is_dev"], false);
    assert!(package.get("semver_class").is_some());
    assert!(package.get("has_install_scripts").is_some());
    assert!(package.get("peer_impact").is_some());
    assert!(package.get("patch_invalidation").is_some());
}

#[tokio::test]
async fn cli_upgrade_yes_dry_run_does_not_mutate_package_json() {
    let (dir, mock) = setup_enriched_dry_run_fixture("dry-run-no-mutate").await;
    let before = fs::read_to_string(dir.join("package.json")).unwrap();

    let output = run_lpm(&dir, &["upgrade", "-y", "--dry-run"], Some(&mock.url()));
    assert!(
        output.status.success(),
        "{}{}",
        output.stdout,
        output.stderr
    );

    let after = fs::read_to_string(dir.join("package.json")).unwrap();
    assert_eq!(before, after);
}

#[tokio::test]
async fn cli_upgrade_yes_writes_manifest_when_not_dry_run() {
    let (dir, mock) =
        setup_successful_upgrade_fixture("writes-manifest", MINOR_VERSION, false).await;
    let output = run_lpm(&dir, &["upgrade", "-y"], Some(&mock.url()));
    assert!(
        output.status.success(),
        "upgrade -y should succeed\nstdout:\n{}\nstderr:\n{}",
        output.stdout,
        output.stderr,
    );

    let manifest = fs::read_to_string(dir.join("package.json")).unwrap();
    assert!(manifest.contains(&format!("\"{PACKAGE_NAME}\": \"^1.3.0\"")));
    assert!(dir.join("node_modules").join(PACKAGE_NAME).exists());
}

#[tokio::test]
async fn cli_upgrade_default_in_no_tty_matches_yes_output() {
    let (dir, mock) = setup_enriched_dry_run_fixture("default-no-tty").await;

    let yes_output = run_lpm(
        &dir,
        &["upgrade", "-y", "--json", "--dry-run"],
        Some(&mock.url()),
    );
    assert!(
        yes_output.status.success(),
        "{}{}",
        yes_output.stdout,
        yes_output.stderr
    );
    let default_output = run_lpm(&dir, &["upgrade", "--json", "--dry-run"], Some(&mock.url()));
    assert!(
        default_output.status.success(),
        "{}{}",
        default_output.stdout,
        default_output.stderr,
    );

    let yes_json = parse_stdout_json(&yes_output.stdout, &yes_output.stderr);
    let default_json = parse_stdout_json(&default_output.stdout, &default_output.stderr);
    assert_eq!(yes_json, default_json);
}

#[test]
fn cli_upgrade_interactive_with_json_is_hard_error() {
    let dir = project_dir("interactive-json-error");
    write_manifest(&dir, &manifest_with_dependency("^1.2.0", false));

    let output = run_lpm(&dir, &["upgrade", "-i", "--json"], None);
    assert!(!output.status.success());
    let combined = format!("{}{}", output.stdout, output.stderr);
    assert!(combined.contains("interactive"));
    assert!(combined.contains("json"));
}

#[test]
fn cli_upgrade_interactive_and_yes_is_hard_error() {
    let dir = project_dir("interactive-yes-error");
    write_manifest(&dir, &manifest_with_dependency("^1.2.0", false));

    let output = run_lpm(&dir, &["upgrade", "-i", "-y"], None);
    assert!(!output.status.success());
    let combined = format!("{}{}", output.stdout, output.stderr);
    assert!(combined.contains("mutually exclusive"));
    assert!(combined.contains("-i"));
    assert!(combined.contains("-y"));
}

#[test]
fn cli_upgrade_major_in_interactive_is_hard_error_when_resolved_interactive() {
    let dir = project_dir("major-interactive-error");
    write_manifest(&dir, &manifest_with_dependency("^1.2.0", false));

    let output = run_lpm(&dir, &["upgrade", "--major", "-i"], None);
    assert!(!output.status.success());
    let combined = format!("{}{}", output.stdout, output.stderr);
    assert!(combined.contains("--major"));
    assert!(combined.contains("interactive mode"));
}

#[tokio::test]
async fn cli_upgrade_major_yes_still_works() {
    let (dir, mock) = setup_successful_upgrade_fixture("major-yes", MAJOR_VERSION, true).await;
    let output = run_lpm(
        &dir,
        &["upgrade", "--major", "-y", "--json", "--dry-run"],
        Some(&mock.url()),
    );
    assert!(
        output.status.success(),
        "{}{}",
        output.stdout,
        output.stderr
    );

    let json = parse_stdout_json(&output.stdout, &output.stderr);
    let package = &json["packages"][0];
    assert_eq!(package["to"], MAJOR_VERSION);
    assert_eq!(package["new_range"], "^2.0.0");
    assert_eq!(package["semver_class"], "major");
}

#[tokio::test]
async fn cli_upgrade_yes_marks_install_scripts_in_json() {
    let (dir, mock) = setup_enriched_dry_run_fixture("marks-install-scripts").await;
    let output = run_lpm(
        &dir,
        &["upgrade", "-y", "--json", "--dry-run"],
        Some(&mock.url()),
    );
    assert!(
        output.status.success(),
        "{}{}",
        output.stdout,
        output.stderr
    );

    let json = parse_stdout_json(&output.stdout, &output.stderr);
    assert_eq!(json["packages"][0]["has_install_scripts"], true);
}

#[tokio::test]
async fn cli_upgrade_yes_marks_peer_violation_in_json() {
    let (dir, mock) = setup_enriched_dry_run_fixture("marks-peer-violation").await;
    let output = run_lpm(
        &dir,
        &["upgrade", "-y", "--json", "--dry-run"],
        Some(&mock.url()),
    );
    assert!(
        output.status.success(),
        "{}{}",
        output.stdout,
        output.stderr
    );

    let json = parse_stdout_json(&output.stdout, &output.stderr);
    let peer_impact = &json["packages"][0]["peer_impact"];
    assert_eq!(peer_impact["ok"], false);
    assert_eq!(peer_impact["basis"], "current_lockfile");
    assert_eq!(peer_impact["violations"][0]["name"], "react");
    assert_eq!(peer_impact["violations"][0]["have"], "17.0.2");
    assert_eq!(peer_impact["violations"][0]["want"], "^18.0.0");
}

#[tokio::test]
async fn cli_upgrade_yes_marks_patch_invalidation_in_json() {
    let (dir, mock) = setup_enriched_dry_run_fixture("marks-patch-invalidation").await;
    let output = run_lpm(
        &dir,
        &["upgrade", "-y", "--json", "--dry-run"],
        Some(&mock.url()),
    );
    assert!(
        output.status.success(),
        "{}{}",
        output.stdout,
        output.stderr
    );

    let json = parse_stdout_json(&output.stdout, &output.stderr);
    let patch_invalidation = &json["packages"][0]["patch_invalidation"];
    assert_eq!(
        patch_invalidation["key"],
        format!("{PACKAGE_NAME}@{CURRENT_VERSION}")
    );
    assert_eq!(patch_invalidation["from_version"], CURRENT_VERSION);
    assert_eq!(patch_invalidation["to_version"], MINOR_VERSION);
}

#[tokio::test]
async fn cli_upgrade_yes_install_failure_restores_manifest() {
    let (dir, mock) = setup_failed_install_fixture("install-failure-restores").await;
    let before = fs::read_to_string(dir.join("package.json")).unwrap();

    let output = run_lpm(&dir, &["upgrade", "-y"], Some(&mock.url()));
    assert!(!output.status.success(), "upgrade unexpectedly succeeded");

    let after = fs::read_to_string(dir.join("package.json")).unwrap();
    assert_eq!(
        before, after,
        "package.json should be restored on install failure"
    );
}

#[tokio::test]
async fn cli_upgrade_yes_offline_after_upgrade_succeeds() {
    let (dir, mock) =
        setup_successful_upgrade_fixture("offline-after-upgrade", MINOR_VERSION, false).await;
    let upgrade = run_lpm(&dir, &["upgrade", "-y"], Some(&mock.url()));
    assert!(
        upgrade.status.success(),
        "{}{}",
        upgrade.stdout,
        upgrade.stderr
    );

    let offline = run_lpm(&dir, &["install", "--offline", "--json"], Some(&mock.url()));
    assert!(
        offline.status.success(),
        "{}{}",
        offline.stdout,
        offline.stderr
    );
    let json = parse_stdout_json(&offline.stdout, &offline.stderr);
    assert!(
        json.as_object().is_some_and(|value| !value.is_empty()),
        "offline install should return structured JSON after an upgrade"
    );
}

#[tokio::test]
async fn cli_upgrade_yes_dry_run_emits_valid_json_with_enrichment() {
    let (dir, mock) = setup_enriched_dry_run_fixture("comprehensive-json-smoke").await;
    let output = run_lpm(
        &dir,
        &["upgrade", "-y", "--json", "--dry-run"],
        Some(&mock.url()),
    );
    assert!(
        output.status.success(),
        "{}{}",
        output.stdout,
        output.stderr
    );

    let json = parse_stdout_json(&output.stdout, &output.stderr);
    assert_eq!(json["success"], true);
    assert_eq!(json["dry_run"], true);
    assert_eq!(json["upgraded"], 1);
    assert_eq!(json["fetch_errors"], 0);
    assert_eq!(json["packages"].as_array().map(Vec::len), Some(1));

    let package = &json["packages"][0];
    assert_eq!(package["name"], PACKAGE_NAME);
    assert_eq!(package["from"], CURRENT_VERSION);
    assert_eq!(package["to"], MINOR_VERSION);
    assert_eq!(package["new_range"], "^1.3.0");
    assert_eq!(package["is_dev"], false);
    assert_eq!(package["semver_class"], "minor");
    assert_eq!(package["has_install_scripts"], true);
    assert_eq!(package["peer_impact"]["ok"], false);
    assert_eq!(
        package["patch_invalidation"]["key"],
        format!("{PACKAGE_NAME}@{CURRENT_VERSION}")
    );
}
