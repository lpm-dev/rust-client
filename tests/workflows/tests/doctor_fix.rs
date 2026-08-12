//! Workflow tests for local and mocked network-backed `lpm doctor --fix` actions.

mod support;

#[cfg(unix)]
use std::sync::Arc;
use std::{io::Write, path::PathBuf};

#[cfg(unix)]
use lpm_store::v2::{
    GraphKey, GraphKeyInputs, LinkMeta, LinkMetaPlatform, LinkerModeTag, PlatformTuple, Store,
};
use sha2::{Digest, Sha256};
use support::{TempProject, lpm};
use wiremock::matchers::{method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};
use zip::write::SimpleFileOptions;

/// Run `lpm doctor` with a deliberately-broken registry URL so the
/// network-dependent checks fail fast without hanging on a real TCP
/// connection. Port 1 reliably refuses connections cross-platform.
fn lpm_doctor_offline(project: &TempProject) -> assert_cmd::Command {
    let mut cmd = lpm(project);
    cmd.args(["--registry", "http://127.0.0.1:1", "--insecure"]);
    cmd
}

/// Seed a "healthy hoisted" install marker so the
/// `node_modules_missing` check doesn't fire (which would trigger an
/// auto-fix attempt to run `lpm install`, requiring a real registry).
fn seed_healthy_hoisted_install(project: &TempProject) {
    std::fs::create_dir_all(project.path().join("node_modules"))
        .expect("failed to create node_modules");
    std::fs::create_dir_all(project.path().join(".lpm/hoisted"))
        .expect("failed to create .lpm/hoisted");
    std::fs::write(
        project.path().join(".lpm/hoisted/metadata.json"),
        r#"{"version":1,"members":{},"packages":{}}"#,
    )
    .expect("failed to seed hoisted metadata");
}

/// Seed a minimal `lpm.lock` so the `lockfile_missing` check doesn't
/// fire (the auto-fix branch for that one would invoke `lpm install`).
fn seed_minimal_lockfile(project: &TempProject) {
    project.write_file("lpm.lock", "[metadata]\nlockfile-version = 1\n");
}

fn current_bun_asset_name() -> String {
    format!(
        "bun-{}.zip",
        lpm_runtime::platform::Platform::current()
            .expect("resolve current Bun runtime platform")
            .bun_suffix()
    )
}

fn make_bun_runtime_zip() -> Vec<u8> {
    let asset_name = current_bun_asset_name();
    let root_dir = asset_name.trim_end_matches(".zip");
    let binary_name = if cfg!(windows) { "bun.exe" } else { "bun" };
    let binary = if cfg!(windows) {
        b"mock-bun.exe\n".as_slice()
    } else {
        b"#!/bin/sh\necho mock-bun\n".as_slice()
    };

    let cursor = std::io::Cursor::new(Vec::new());
    let mut writer = zip::ZipWriter::new(cursor);
    let options = SimpleFileOptions::default();
    writer
        .add_directory(format!("{root_dir}/"), options)
        .expect("add Bun zip root directory");
    writer
        .start_file(format!("{root_dir}/{binary_name}"), options)
        .expect("start Bun binary in zip");
    writer.write_all(binary).expect("write Bun binary in zip");
    writer.finish().expect("finish Bun zip").into_inner()
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

fn write_bun_index_cache(project: &TempProject, releases: &serde_json::Value) {
    let runtimes_dir = project.home().join(".lpm/runtimes");
    std::fs::create_dir_all(&runtimes_dir).expect("create runtime cache directory");
    std::fs::write(
        runtimes_dir.join("bun-index-cache.json"),
        serde_json::to_vec(releases).expect("serialize Bun release cache"),
    )
    .expect("write Bun release cache");
}

fn managed_bun_dir(project: &TempProject, version: &str) -> PathBuf {
    project.home().join(".lpm/runtimes/bun").join(version)
}

fn seed_verified_plugin_with_binary(
    project: &TempProject,
    name: &str,
    version: &str,
    binary: &[u8],
) {
    let definition = lpm_plugin::registry::get_plugin(name).expect("known plugin fixture");
    let platform = lpm_runtime::platform::Platform::current()
        .expect("resolve current plugin platform")
        .to_string();
    let platform_dir = project
        .home()
        .join(".lpm/plugins")
        .join(name)
        .join(version)
        .join(&platform);
    let binary_path = platform_dir.join(definition.binary_name);
    std::fs::create_dir_all(binary_path.parent().expect("plugin platform directory"))
        .expect("create plugin platform directory");
    std::fs::write(&binary_path, binary).expect("write plugin fixture binary");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&binary_path, std::fs::Permissions::from_mode(0o755))
            .expect("make plugin fixture executable");
    }
    let digest = sha256_hex(binary);
    let sidecar = lpm_plugin::sidecar::Sidecar::new(
        name,
        version,
        &platform,
        "fixture-asset",
        "https://fixture.invalid/plugin",
        digest.clone(),
        digest,
        lpm_plugin::sidecar::VerificationSource::Bundled,
    )
    .with_current_binary_snapshot(&binary_path);
    let sidecar_path = platform_dir.join(lpm_plugin::sidecar::SIDECAR_FILE_NAME);
    lpm_plugin::sidecar::write_atomic(&sidecar_path, &sidecar)
        .expect("write verified plugin sidecar");
}

fn seed_verified_plugin(project: &TempProject, name: &str, version: &str) {
    seed_verified_plugin_with_binary(project, name, version, b"doctor plugin update fixture");
}

fn plugin_version_cache(project: &TempProject) -> PathBuf {
    project.home().join(".lpm/plugins/.version-cache.json")
}

#[cfg(unix)]
fn seed_orphaned_store_link(project: &TempProject) -> std::path::PathBuf {
    let root = lpm_common::LpmRoot::from_dir(project.home().join(".lpm"));
    lpm_common::known_projects::register(&root.known_projects(), project.path())
        .expect("failed to register doctor fixture project");
    let store = Store::from_lpm_root(&root);
    let graph_key = GraphKey::derive(&GraphKeyInputs::new(
        "doctor-orphan",
        "1.0.0",
        PlatformTuple::current(),
        LinkerModeTag::Isolated,
    ));
    let link_dir = store.paths().link_dir(&graph_key);
    std::fs::create_dir_all(link_dir.join("node_modules/doctor-orphan"))
        .expect("failed to create orphaned link entry");
    LinkMeta::new(
        &graph_key,
        "sha512-doctor-orphan",
        "objects/doctor-orphan",
        Vec::new(),
        Arc::new(LinkMetaPlatform {
            os: std::env::consts::OS.into(),
            cpu: std::env::consts::ARCH.into(),
            libc: None,
        }),
    )
    .write_to(&link_dir)
    .expect("failed to write orphaned link metadata");
    link_dir
}

// ─── gitattributes_missing fix ────────────────────────────────────────

#[test]
fn doctor_fix_creates_gitattributes_when_lockfile_exists_without_it() {
    let project = TempProject::empty(r#"{"name":"doctor-gitattr","version":"1.0.0"}"#);
    seed_healthy_hoisted_install(&project);
    seed_minimal_lockfile(&project);
    // Crucially: NO .gitattributes file. lpm.lock exists, so the
    // GITATTRIBUTES_MISSING warn fires.
    assert!(
        !project.file_exists(".gitattributes"),
        "preconditions: .gitattributes must not exist before --fix"
    );

    // `.gitattributes` hygiene is Extended-tier, so the default fast
    // preset doesn't check it. Add `--all` so the warn fires and the
    // auto-fix branch runs.
    let output = lpm_doctor_offline(&project)
        .arg("doctor")
        .arg("--all")
        .arg("--fix")
        .arg("--yes")
        .output()
        .expect("failed to run lpm doctor --all --fix");

    // Doctor's exit code reflects whether any failing checks remain.
    // Registry/auth always fail in this offline harness, so non-zero
    // exit is expected; we only assert the fix-branch side effect.
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    assert!(
        project.file_exists(".gitattributes"),
        "doctor --all --fix must create .gitattributes when lpm.lock is present and the file is missing\noutput:\n{combined}"
    );

    let content = project.read_file(".gitattributes");
    assert!(
        content.contains("lpm.lockb binary"),
        ".gitattributes must mark lpm.lockb as binary, got:\n{content}"
    );
}

// ─── lockfile_binary_missing fix ──────────────────────────────────────

#[test]
fn doctor_fix_without_yes_in_noninteractive_session_refuses_before_mutation() {
    let project = TempProject::empty(r#"{"name":"doctor-confirm","version":"1.0.0"}"#);
    seed_healthy_hoisted_install(&project);
    seed_minimal_lockfile(&project);

    let output = lpm_doctor_offline(&project)
        .arg("doctor")
        .arg("--fix")
        .output()
        .expect("failed to run lpm doctor --fix");

    assert!(
        !output.status.success(),
        "non-interactive doctor --fix must require explicit confirmation"
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("--yes"),
        "the refusal must explain how to confirm automatic fixes"
    );
    assert!(
        !project.file_exists("lpm.lockb"),
        "doctor must not apply a fix before confirmation"
    );
}

#[test]
fn doctor_fix_json_without_yes_emits_one_error_and_does_not_mutate() {
    let project = TempProject::empty(r#"{"name":"doctor-confirm-json","version":"1.0.0"}"#);
    seed_healthy_hoisted_install(&project);
    seed_minimal_lockfile(&project);

    let output = lpm_doctor_offline(&project)
        .args(["--json", "doctor", "--fix"])
        .output()
        .expect("failed to run lpm doctor --fix --json");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let envelope: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|error| panic!("doctor must emit one JSON error: {error}\n{stdout}"));

    assert!(!output.status.success(), "the JSON refusal must fail");
    assert_eq!(envelope["success"], false, "{envelope:#}");
    assert!(
        envelope["error"]
            .as_str()
            .is_some_and(|error| error.contains("--yes")),
        "the JSON error must explain how to confirm automatic fixes: {envelope:#}"
    );
    insta::assert_json_snapshot!("doctor_fix_requires_yes", envelope);
    assert!(
        !project.file_exists("lpm.lockb"),
        "JSON mode must not apply a fix before confirmation"
    );
}

#[test]
fn doctor_fix_regenerates_binary_lockfile_when_toml_present() {
    let project = TempProject::empty(r#"{"name":"doctor-lockb","version":"1.0.0"}"#);
    seed_healthy_hoisted_install(&project);
    seed_minimal_lockfile(&project);
    // No lpm.lockb on disk yet.
    assert!(
        !project.file_exists("lpm.lockb"),
        "preconditions: lpm.lockb must not exist before --fix"
    );

    let output = lpm_doctor_offline(&project)
        .arg("doctor")
        .arg("--fix")
        .arg("--yes")
        .output()
        .expect("failed to run lpm doctor --fix");

    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    assert!(
        project.file_exists("lpm.lockb"),
        "doctor --fix must regenerate lpm.lockb when lpm.lock is present and the binary is missing\noutput:\n{combined}"
    );
}

#[test]
fn doctor_fix_lockfile_binary_write_failure_uses_slim_error() {
    let project = TempProject::empty(r#"{"name":"doctor-lockb-dir","version":"1.0.0"}"#);
    seed_healthy_hoisted_install(&project);
    seed_minimal_lockfile(&project);
    std::fs::create_dir(project.path().join("lpm.lockb"))
        .expect("failed to create lpm.lockb directory fixture");

    let output = lpm_doctor_offline(&project)
        .arg("doctor")
        .arg("--fix")
        .arg("--yes")
        .output()
        .expect("failed to run lpm doctor --fix");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("✗ reconcile lpm.lockb failed:"),
        "doctor auto-fix failure must use a slim failure line, got:\n{stderr}"
    );
    assert!(
        !stderr.contains("  error ") && !stderr.contains("warning:"),
        "doctor auto-fix failure must not use the legacy raw error label, got:\n{stderr}"
    );
}

// ─── doctor (no --fix) is read-only ──────────────────────────────────

#[test]
fn doctor_without_fix_does_not_create_gitattributes_or_lockb() {
    let project = TempProject::empty(r#"{"name":"doctor-readonly","version":"1.0.0"}"#);
    seed_healthy_hoisted_install(&project);
    seed_minimal_lockfile(&project);

    // No --fix: doctor must be read-only. Both files must remain
    // absent regardless of which checks doctor reports.
    let _ = lpm_doctor_offline(&project)
        .arg("doctor")
        .output()
        .expect("failed to run lpm doctor");

    assert!(
        !project.file_exists(".gitattributes"),
        "doctor without --fix must not create .gitattributes"
    );
    assert!(
        !project.file_exists("lpm.lockb"),
        "doctor without --fix must not create lpm.lockb"
    );
}

// ─── --fix JSON envelope surfaces fixes_applied ──────────────────────

#[test]
fn doctor_fix_json_envelope_carries_fixes_applied_array() {
    let project = TempProject::empty(r#"{"name":"doctor-json","version":"1.0.0"}"#);
    seed_healthy_hoisted_install(&project);
    seed_minimal_lockfile(&project);

    let output = lpm_doctor_offline(&project)
        .arg("--json")
        .arg("doctor")
        .arg("--fix")
        .arg("--yes")
        .output()
        .expect("failed to run lpm doctor --fix --json");

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let envelope: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("doctor --json must be valid JSON: {e}\n---\n{stdout}"));

    // Stable schema: fixes_applied must be present (possibly empty)
    let fixes = envelope["fixes_applied"]
        .as_array()
        .expect("fixes_applied must be an array even when no fixes ran");

    // Sanity: at least one fix should have run (gitattributes,
    // lpm.lockb, or both, depending on doctor's check order).
    assert!(
        !fixes.is_empty(),
        "doctor --fix --json on the seeded project must report at least one fix, got: {envelope}",
    );
}

#[test]
#[cfg(unix)]
fn doctor_all_fix_prunes_store_entries_reported_as_orphaned() {
    let project = TempProject::empty(r#"{"name":"doctor-prune","version":"1.0.0"}"#);
    seed_healthy_hoisted_install(&project);
    seed_minimal_lockfile(&project);
    let orphan_link = seed_orphaned_store_link(&project);

    let output = lpm_doctor_offline(&project)
        .arg("--json")
        .arg("doctor")
        .arg("--all")
        .arg("--fix")
        .arg("--yes")
        .output()
        .expect("failed to run lpm doctor --all --fix --json");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let envelope: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|error| panic!("doctor must emit JSON: {error}\nstdout={stdout}"));
    assert!(
        envelope["checks"].as_array().is_some_and(|checks| {
            checks
                .iter()
                .any(|check| check["code"] == "v2_store_orphans")
        }),
        "fixture must emit the store-orphan warning: {envelope:#}"
    );
    assert!(
        !orphan_link.exists(),
        "doctor --all --fix must apply the advertised store prune action"
    );
}

#[tokio::test]
async fn doctor_fix_installs_the_pinned_bun_runtime_from_verified_release_metadata() {
    let server = MockServer::start().await;
    let version = "1.3.14";
    let asset_name = current_bun_asset_name();
    let zip_bytes = make_bun_runtime_zip();
    Mock::given(method("GET"))
        .and(path(format!("/bun-dist/{asset_name}")))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(zip_bytes.clone()))
        .expect(1)
        .mount(&server)
        .await;

    let project = TempProject::empty(r#"{"name":"doctor-bun","version":"1.0.0"}"#);
    seed_healthy_hoisted_install(&project);
    seed_minimal_lockfile(&project);
    project.write_file(
        "lpm.json",
        &format!(r#"{{"runtime":{{"bun":"{version}"}}}}"#),
    );
    write_bun_index_cache(
        &project,
        &serde_json::json!([{
            "tag_name": format!("bun-v{version}"),
            "name": format!("Bun {version}"),
            "draft": false,
            "prerelease": false,
            "assets": [{
                "name": asset_name,
                "browser_download_url": format!("{}/bun-dist/{asset_name}", server.uri()),
                "digest": format!("sha256:{}", sha256_hex(&zip_bytes)),
            }],
        }]),
    );

    let output = lpm_doctor_offline(&project)
        .args(["--json", "doctor", "--fix", "--yes"])
        .output()
        .expect("run doctor Bun auto-fix");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let envelope: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|error| panic!("doctor must emit JSON: {error}\nstdout={stdout}"));

    assert!(
        envelope["checks"]
            .as_array()
            .is_some_and(|checks| checks.iter().any(|check| matches!(
                check["code"].as_str(),
                Some("bun_missing_pinned" | "bun_pinned_unmet")
            ))),
        "fixture must emit a pinned Bun runtime mismatch: {envelope:#}"
    );
    assert!(
        envelope["fixes_applied"]
            .as_array()
            .is_some_and(|fixes| fixes.iter().any(|fix| fix == "installed bun 1.3.14")),
        "doctor must report the Bun install action: {envelope:#}"
    );
    assert!(
        managed_bun_dir(&project, version).exists(),
        "doctor --fix must install the pinned Bun runtime"
    );
}

#[tokio::test]
async fn doctor_all_fix_routes_plugin_updates_through_the_managed_updater() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/repos/biomejs/biome/releases"))
        .and(query_param("per_page", "20"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
            { "tag_name": "@biomejs/biome@2.5.7" }
        ])))
        .expect(1)
        .mount(&server)
        .await;

    let project = TempProject::empty(r#"{"name":"doctor-plugin","version":"1.0.0"}"#);
    seed_healthy_hoisted_install(&project);
    seed_minimal_lockfile(&project);
    seed_verified_plugin(&project, "biome", "2.5.7");
    let cache_path = plugin_version_cache(&project);
    std::fs::create_dir_all(cache_path.parent().expect("plugin cache directory"))
        .expect("create plugin cache directory");
    std::fs::write(&cache_path, r#"{"versions":{"biome":"2.5.8"}}"#)
        .expect("seed newer approved plugin version");

    let output = lpm_doctor_offline(&project)
        .env("LPM_PLUGIN_GITHUB_API_BASE", server.uri())
        .args(["--json", "doctor", "--all", "--fix", "--yes"])
        .output()
        .expect("run doctor plugin auto-fix");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let envelope: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|error| panic!("doctor must emit JSON: {error}\nstdout={stdout}"));

    assert!(
        envelope["checks"].as_array().is_some_and(|checks| checks
            .iter()
            .any(|check| check["code"] == "plugin_update_available")),
        "fixture must emit the plugin update warning: {envelope:#}"
    );
    assert!(
        envelope["fixes_applied"].as_array().is_some_and(|fixes| {
            fixes
                .iter()
                .any(|fix| fix == "updated plugin biome to 2.5.7")
        }),
        "doctor must report the managed plugin update: {envelope:#}"
    );
    let cache: serde_json::Value = serde_json::from_slice(
        &std::fs::read(cache_path).expect("read updated plugin version cache"),
    )
    .expect("plugin version cache must remain valid JSON");
    assert_eq!(cache["versions"]["biome"], "2.5.7");
}

#[test]
#[cfg(unix)]
fn doctor_all_fix_keeps_formatter_output_out_of_the_json_document() {
    let project = TempProject::empty(r#"{"name":"doctor-format","version":"1.0.0"}"#);
    seed_healthy_hoisted_install(&project);
    seed_minimal_lockfile(&project);
    let marker = project.path().join("format-applied");
    let formatter = format!(
        "#!/bin/sh\nif [ \"$2\" = \"--check\" ]; then\n  echo 'Formatter would have printed fixture.js' >&2\n  exit 1\nfi\necho 'formatter stdout must stay captured'\nprintf 'applied' > \"{}\"\n",
        marker.display()
    );
    seed_verified_plugin_with_binary(&project, "biome", "2.5.7", formatter.as_bytes());

    let output = lpm_doctor_offline(&project)
        .args(["--json", "doctor", "--all", "--fix", "--yes"])
        .output()
        .expect("run doctor format auto-fix");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let envelope: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|error| panic!("doctor must emit one JSON document: {error}\n{stdout}"));

    assert!(
        envelope["checks"].as_array().is_some_and(|checks| checks
            .iter()
            .any(|check| check["code"] == "fmt_unformatted")),
        "fixture must emit the unformatted warning: {envelope:#}"
    );
    assert!(
        envelope["fixes_applied"]
            .as_array()
            .is_some_and(|fixes| fixes.iter().any(|fix| fix == "lpm fmt")),
        "doctor must report the format action: {envelope:#}"
    );
    assert!(marker.exists(), "doctor --fix must run the formatter");
}

#[test]
fn workspace_member_doctor_uses_its_projection_and_repairs_root_lockfile_hygiene() {
    let project = TempProject::empty(
        r#"{
  "name": "doctor-workspace",
  "version": "1.0.0",
  "private": true,
  "workspaces": ["packages/*"]
}"#,
    );
    project.write_file(
        "packages/app/package.json",
        r#"{"name":"doctor-app","version":"1.0.0","private":true,"dependencies":{"member-only":"^1.0.0"}}"#,
    );
    project.write_file(
        "packages/sibling/package.json",
        r#"{"name":"doctor-sibling","version":"1.0.0","private":true,"dependencies":{"sibling-only":"^1.0.0"}}"#,
    );
    let app_dir = project.path().join("packages/app");
    std::fs::create_dir_all(app_dir.join("node_modules")).unwrap();
    std::fs::create_dir_all(app_dir.join(".lpm/hoisted")).unwrap();
    std::fs::write(
        app_dir.join(".lpm/hoisted/metadata.json"),
        r#"{"version":1,"members":{},"packages":{}}"#,
    )
    .unwrap();

    let mut app_projection = lpm_lockfile::Lockfile::new();
    app_projection.add_package(lpm_lockfile::LockedPackage {
        instance_id: None,
        dependency_targets: std::collections::BTreeMap::new(),
        peer_targets: std::collections::BTreeMap::new(),
        name: "member-only".into(),
        version: "1.0.0".into(),
        source: Some("registry+https://registry.npmjs.org".into()),
        ..Default::default()
    });
    support::finalize_exact_lockfile_fixture(
        &mut app_projection,
        &[("member-only", "member-only", "1.0.0")],
    );
    app_projection.importers.insert(
        ".".to_string(),
        lpm_lockfile::ImporterSnapshot {
            dependencies: std::collections::BTreeMap::from([(
                "member-only".to_string(),
                "^1.0.0".to_string(),
            )]),
            ..Default::default()
        },
    );
    let mut sibling_projection = lpm_lockfile::Lockfile::new();
    sibling_projection.add_package(lpm_lockfile::LockedPackage {
        instance_id: None,
        dependency_targets: std::collections::BTreeMap::new(),
        peer_targets: std::collections::BTreeMap::new(),
        name: "sibling-only".into(),
        version: "1.0.0".into(),
        source: Some("registry+https://registry.npmjs.org".into()),
        ..Default::default()
    });
    support::finalize_exact_lockfile_fixture(
        &mut sibling_projection,
        &[("sibling-only", "sibling-only", "1.0.0")],
    );
    sibling_projection.importers.insert(
        ".".to_string(),
        lpm_lockfile::ImporterSnapshot {
            dependencies: std::collections::BTreeMap::from([(
                "sibling-only".to_string(),
                "^1.0.0".to_string(),
            )]),
            ..Default::default()
        },
    );
    let mut root_lockfile = lpm_lockfile::Lockfile::new();
    root_lockfile
        .absorb_importer("packages/app", app_projection)
        .unwrap();
    root_lockfile
        .absorb_importer("packages/sibling", sibling_projection)
        .unwrap();
    root_lockfile
        .write_to_file(&project.path().join("lpm.lock"))
        .unwrap();
    project.write_file("lpm.lockb", "obsolete union binary cache");

    let output = lpm_doctor_offline(&project)
        .current_dir(&app_dir)
        .arg("--json")
        .arg("doctor")
        .arg("--all")
        .arg("--fix")
        .arg("--yes")
        .output()
        .expect("run doctor from workspace member");
    let envelope: serde_json::Value =
        serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
            panic!(
                "workspace doctor must emit JSON: {error}\nstdout={}\nstderr={}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr),
            )
        });
    let codes = envelope["checks"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|check| check["code"].as_str())
        .collect::<std::collections::BTreeSet<_>>();
    assert!(codes.contains("lockfile_present"), "{envelope:#}");
    assert!(!codes.contains("lockfile_missing"), "{envelope:#}");
    assert!(codes.contains("deps_sync_clean"), "{envelope:#}");
    assert!(!codes.contains("deps_sync_drift"), "{envelope:#}");

    assert!(
        !project.file_exists("lpm.lockb"),
        "doctor must remove an obsolete binary cache that cannot represent workspace projections"
    );
    assert!(
        project
            .read_file(".gitattributes")
            .contains("lpm.lockb binary")
    );
    assert!(!app_dir.join("lpm.lock").exists());
    assert!(!app_dir.join("lpm.lockb").exists());
    assert!(!app_dir.join(".gitattributes").exists());
}
