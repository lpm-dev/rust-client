//! Workflow coverage for runtime validation during otherwise unchanged installs.

#![cfg(unix)]

mod support;

use std::os::unix::fs::{MetadataExt, PermissionsExt};

use support::mock_registry::{MockRegistry, compute_integrity, make_tarball_from_pkg_json};
use support::{TempProject, lpm, lpm_with_registry};

fn bare_install(project: &TempProject) -> assert_cmd::Command {
    let mut command = lpm(project);
    command.args(["--json", "install"]);
    with_node_shim(project, &mut command);
    command
}

fn with_node_shim(project: &TempProject, command: &mut assert_cmd::Command) {
    command.env(
        "PATH",
        std::env::join_paths(std::iter::once(project.home().join("node-shim-bin")).chain(
            std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default()),
        ))
        .unwrap(),
    );
}

fn install(project: &TempProject, registry: &str) -> assert_cmd::Command {
    let mut command = lpm_with_registry(project, registry);
    command.args([
        "--json",
        "install",
        "--no-skills",
        "--no-editor-setup",
        "--no-security-summary",
    ]);
    with_node_shim(project, &mut command);
    command
}

fn write_node_shim(project: &TempProject) {
    let quote =
        |path: std::path::PathBuf| format!("'{}'", path.to_str().unwrap().replace('\'', "'\\''"));
    project.write_file("node-version", "v20.0.0\n");
    let bin = project.home().join("node-shim-bin");
    std::fs::create_dir_all(&bin).unwrap();
    std::fs::write(
        bin.join("node"),
        format!(
            "#!/bin/sh\nprintf 'probe\\n' >> {}\n/bin/cat {}\n",
            quote(project.path().join("node-probes")),
            quote(project.path().join("node-version")),
        ),
    )
    .unwrap();
    std::fs::set_permissions(bin.join("node"), std::fs::Permissions::from_mode(0o755)).unwrap();
}

fn probe_count(project: &TempProject) -> usize {
    std::fs::read_to_string(project.path().join("node-probes"))
        .unwrap_or_default()
        .lines()
        .count()
}

#[tokio::test]
async fn bare_unchanged_install_rejects_changed_root_node_engine() {
    let mock = MockRegistry::start().await;
    mock.with_manifest_package(
        serde_json::json!({"name": "engine-free", "version": "1.0.0"}),
        &[],
    )
    .await;
    let project = TempProject::empty(
        r#"{"name":"consumer","version":"1.0.0","engines":{"node":">=20 <21"},"dependencies":{"engine-free":"1.0.0"}}"#,
    );
    write_node_shim(&project);
    install(&project, &mock.url()).assert().success();
    assert!(project.read_file(".lpm/install-hash").contains("e:none"));
    bare_install(&project).assert().success();
    project.write_file("node-version", "v22.0.0\n");
    let output = bare_install(&project)
        .assert()
        .failure()
        .get_output()
        .clone();
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(result.to_string().contains("engine_mismatch"), "{result}");
}

#[tokio::test]
async fn bare_unchanged_install_rejects_root_lpm_engine_mismatch() {
    let mock = MockRegistry::start().await;
    mock.with_manifest_package(
        serde_json::json!({"name": "engine-free", "version": "1.0.0"}),
        &[],
    )
    .await;
    let project = TempProject::empty(
        r#"{"name":"consumer","version":"1.0.0","engines":{"lpm":">=9999"},"dependencies":{"engine-free":"1.0.0"}}"#,
    );
    install(&project, &mock.url())
        .arg("--no-engine-strict")
        .assert()
        .success();
    let output = bare_install(&project)
        .assert()
        .failure()
        .get_output()
        .clone();
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(result.to_string().contains("engine_mismatch"), "{result}");
}

#[tokio::test]
async fn bare_unchanged_install_checks_strict_dependency_source_edits() {
    let mock = MockRegistry::start().await;
    mock.with_manifest_package(
        serde_json::json!({"name": "declared", "version": "1.0.0"}),
        &[],
    )
    .await;
    let project = TempProject::empty(
        r#"{"name":"consumer","dependencies":{"declared":"1.0.0"},"lpm":{"strictDeps":"strict"}}"#,
    );
    project.write_file("src/index.js", "import value from 'declared';\n");
    install(&project, &mock.url()).assert().success();
    bare_install(&project).assert().success();
    project.write_file(
        "src/index.js",
        "import value from 'undeclared-dependency';\n",
    );
    let output = bare_install(&project)
        .assert()
        .failure()
        .get_output()
        .clone();
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(
        result.to_string().contains("undeclared-dependency"),
        "{result}"
    );
}

#[tokio::test]
async fn bare_unchanged_install_obeys_new_managed_source_analysis_requirement() {
    let mock = MockRegistry::start().await;
    mock.with_manifest_package(
        serde_json::json!({"name": "engine-free", "version": "1.0.0"}),
        &[],
    )
    .await;
    let project =
        TempProject::empty(r#"{"name":"consumer","dependencies":{"engine-free":"1.0.0"}}"#);
    install(&project, &mock.url()).assert().success();
    bare_install(&project).assert().success();
    std::fs::write(
        project.home().join(".lpm/security-policy.toml"),
        "install-time-source-analysis = true\n",
    )
    .unwrap();
    let output = bare_install(&project)
        .assert()
        .failure()
        .get_output()
        .clone();
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(result.to_string().contains("managed"), "{result}");
}

#[tokio::test]
async fn bare_unchanged_install_rebuilds_missing_source_analysis_cache() {
    let mock = MockRegistry::start().await;
    let tarball = make_tarball_from_pkg_json(
        serde_json::json!({"name": "analysis-dep", "version": "1.0.0"}),
        &[("index.js", b"module.exports = 1;\n")],
    );
    mock.with_package("analysis-dep", "1.0.0", &tarball).await;
    let project =
        TempProject::empty(r#"{"name":"consumer","dependencies":{"analysis-dep":"1.0.0"}}"#);
    std::fs::create_dir_all(project.home().join(".lpm")).unwrap();
    std::fs::write(
        project.home().join(".lpm/config.toml"),
        "install-time-source-analysis = true\n",
    )
    .unwrap();
    install(&project, &mock.url()).assert().success();
    let store = lpm_store::v2::Store::at(project.home().join(".lpm/store/v2"));
    let cache = store
        .paths()
        .object_dir(&compute_integrity(&tarball))
        .unwrap()
        .join(".lpm-security.json");
    assert!(cache.exists());
    std::fs::remove_file(&cache).unwrap();
    bare_install(&project)
        .env("LPM_REGISTRY_URL", mock.url())
        .assert()
        .success();
    assert!(
        cache.exists(),
        "bare install must regenerate missing analysis"
    );
}

#[tokio::test]
async fn bare_unchanged_install_obeys_new_strict_peer_policy() {
    assert_replayed_strict_peer_policy(&[]).await;
}

#[tokio::test]
async fn frozen_install_obeys_new_strict_peer_policy() {
    assert_replayed_strict_peer_policy(&["--frozen-lockfile"]).await;
}

#[tokio::test]
async fn offline_install_obeys_new_strict_peer_policy() {
    assert_replayed_strict_peer_policy(&["--offline"]).await;
}

async fn assert_replayed_strict_peer_policy(args: &[&str]) {
    let mock = MockRegistry::start().await;
    mock.with_manifest_package(
        serde_json::json!({"name": "peer-host", "version": "1.0.0", "peerDependencies": {"missing-peer": "^1.0.0"}}),
        &[],
    )
    .await;
    let project = TempProject::empty(
        r#"{"name":"consumer","dependencies":{"peer-host":"1.0.0"},"lpm":{"autoInstallPeers":false}}"#,
    );
    let installed = install(&project, &mock.url())
        .assert()
        .success()
        .get_output()
        .clone();
    let result: serde_json::Value = serde_json::from_slice(&installed.stdout).unwrap();
    assert_eq!(result["peer_issues"]["missing_count"], 1, "{result}");
    bare_install(&project).assert().success();
    std::fs::write(
        project.home().join(".lpm/config.toml"),
        "strict-peer-dependencies = true\n",
    )
    .unwrap();
    let output = bare_install(&project)
        .env("LPM_REGISTRY_URL", mock.url())
        .args(args)
        .assert()
        .failure()
        .get_output()
        .clone();
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(
        result
            .to_string()
            .contains("strict-peer-dependencies failed"),
        "{result}"
    );
}

#[tokio::test]
async fn bare_unchanged_install_refuses_pending_release_transaction() {
    let mock = MockRegistry::start().await;
    mock.with_manifest_package(
        serde_json::json!({"name": "engine-free", "version": "1.0.0"}),
        &[],
    )
    .await;
    let project =
        TempProject::empty(r#"{"name":"consumer","dependencies":{"engine-free":"1.0.0"}}"#);
    install(&project, &mock.url()).assert().success();
    bare_install(&project).assert().success();
    project.write_file(
        ".lpm/release-apply/journal.json",
        &serde_json::json!({
            "schema_version": 1,
            "transaction_id": "0".repeat(32),
            "operation": {"kind": "release_apply", "fingerprint": "0".repeat(64)},
            "state": "applying",
            "path_encoding": "unix-bytes-v1",
            "entries": [{
                "path": "cGFja2FnZS5qc29u",
                "original_sha256": "0".repeat(64),
                "original_base64": "e30=",
                "updated_sha256": "0".repeat(64)
            }]
        })
        .to_string(),
    );
    std::fs::set_permissions(
        project.path().join(".lpm/release-apply"),
        std::fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    std::fs::set_permissions(
        project.path().join(".lpm/release-apply/journal.json"),
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    let output = bare_install(&project)
        .assert()
        .failure()
        .get_output()
        .clone();
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(
        result
            .to_string()
            .contains("interrupted release manifest transaction"),
        "{result}"
    );
}

#[tokio::test]
async fn bare_unchanged_install_runs_root_lifecycle_scripts() {
    let mock = MockRegistry::start().await;
    mock.with_manifest_package(
        serde_json::json!({"name": "engine-free", "version": "1.0.0"}),
        &[],
    )
    .await;
    let project = TempProject::empty(
        r#"{"name":"consumer","version":"1.0.0","dependencies":{"engine-free":"1.0.0"},"scripts":{"pnpm:devPreinstall":"echo before >> before.log","postinstall":"echo after >> after.log"}}"#,
    );
    install(&project, &mock.url()).assert().success();
    assert_eq!(project.read_file("before.log").lines().count(), 1);
    assert_eq!(project.read_file("after.log").lines().count(), 1);
    bare_install(&project)
        .env("LPM_REGISTRY_URL", mock.url())
        .assert()
        .success();
    assert_eq!(project.read_file("before.log").lines().count(), 2);
    assert_eq!(project.read_file("after.log").lines().count(), 2);
}

#[tokio::test]
async fn bare_unchanged_install_obeys_managed_typosquat_policy() {
    let mock = MockRegistry::start().await;
    mock.with_manifest_package(
        serde_json::json!({"name": "engine-free", "version": "1.0.0"}),
        &[],
    )
    .await;
    let project =
        TempProject::empty(r#"{"name":"consumer","dependencies":{"engine-free":"1.0.0"}}"#);
    install(&project, &mock.url()).assert().success();
    std::fs::write(
        project.home().join(".lpm/config.toml"),
        "typosquat-guard = \"off\"\n",
    )
    .unwrap();
    std::fs::write(
        project.home().join(".lpm/security-policy.toml"),
        "typosquat-guard = \"on\"\n",
    )
    .unwrap();
    let output = bare_install(&project)
        .assert()
        .failure()
        .get_output()
        .clone();
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(result.to_string().contains("managed"), "{result}");
}

#[tokio::test]
async fn bare_unchanged_install_validates_security_config() {
    let mock = MockRegistry::start().await;
    mock.with_manifest_package(
        serde_json::json!({"name": "engine-free", "version": "1.0.0"}),
        &[],
    )
    .await;
    for config in [
        "fetch-lpm-security-insights = \"sometimes\"\n",
        "[firewall.npm.policies]\nunknown-check = \"deny\"\n",
    ] {
        let project =
            TempProject::empty(r#"{"name":"consumer","dependencies":{"engine-free":"1.0.0"}}"#);
        install(&project, &mock.url()).assert().success();
        std::fs::write(project.home().join(".lpm/config.toml"), config).unwrap();
        let expected = install(&project, &mock.url())
            .assert()
            .failure()
            .get_output()
            .clone();
        let actual = bare_install(&project)
            .assert()
            .failure()
            .get_output()
            .clone();
        let expected: serde_json::Value = serde_json::from_slice(&expected.stdout).unwrap();
        let actual: serde_json::Value = serde_json::from_slice(&actual.stdout).unwrap();
        assert_eq!(actual["error"], expected["error"]);
        assert_eq!(actual["error_code"], expected["error_code"]);
    }
}

#[tokio::test]
async fn bare_unchanged_install_probes_dependency_node_once() {
    let mock = MockRegistry::start().await;
    mock.with_manifest_package(
        serde_json::json!({"name": "engine-dep", "version": "1.0.0", "engines": {"node": ">=20 <21"}}),
        &[],
    )
    .await;
    let project =
        TempProject::empty(r#"{"name":"consumer","dependencies":{"engine-dep":"1.0.0"}}"#);
    write_node_shim(&project);
    install(&project, &mock.url()).assert().success();
    assert_eq!(probe_count(&project), 1);
    for count in 2..=3 {
        let output = bare_install(&project)
            .assert()
            .success()
            .get_output()
            .clone();
        let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(result["up_to_date"], true);
        assert_eq!(probe_count(&project), count);
    }
    project.write_file("node-version", "v22.0.0\n");
    let output = bare_install(&project)
        .env("LPM_REGISTRY_URL", mock.url())
        .assert()
        .failure()
        .get_output()
        .clone();
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(result.to_string().contains("engine_mismatch"), "{result}");
}

#[tokio::test]
async fn unchanged_install_probes_once_and_rejects_changed_shim_output() {
    let mock = MockRegistry::start().await;
    mock.with_manifest_package(
        serde_json::json!({
            "name": "engine-dep", "version": "1.0.0", "engines": {"node": ">=20 <21"}
        }),
        &[],
    )
    .await;
    for root_engine in [false, true] {
        let mut manifest = serde_json::json!({
            "name": "consumer", "version": "1.0.0", "dependencies": {"engine-dep": "1.0.0"}
        });
        if root_engine {
            manifest["engines"] = serde_json::json!({"node": ">=20 <21"});
        }
        let project = TempProject::empty(&manifest.to_string());
        write_node_shim(&project);
        install(&project, &mock.url()).assert().success();
        assert_eq!(probe_count(&project), 1);
        let state = std::fs::read(project.path().join(".lpm/install-hash")).unwrap();
        for count in 2..=3 {
            let output = install(&project, &mock.url())
                .assert()
                .success()
                .get_output()
                .clone();
            let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
            assert_eq!(result["up_to_date"], true);
            assert_eq!(probe_count(&project), count);
        }
        let shim = project.home().join("node-shim-bin/node");
        let before = std::fs::metadata(&shim).unwrap();
        project.write_file("node-version", "v22.0.0\n");
        let after = std::fs::metadata(shim).unwrap();
        assert_eq!(
            (
                before.ino(),
                before.len(),
                before.modified().unwrap(),
                before.mode()
            ),
            (
                after.ino(),
                after.len(),
                after.modified().unwrap(),
                after.mode()
            )
        );
        let output = install(&project, &mock.url())
            .assert()
            .failure()
            .get_output()
            .clone();
        let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert!(result.to_string().contains("engine_mismatch"), "{result}");
        assert_eq!(probe_count(&project), 4);
        assert_eq!(
            std::fs::read(project.path().join(".lpm/install-hash")).unwrap(),
            state
        );
        project.write_file("package.json", r#"{"name":"consumer","version":"1.0.0"}"#);
        install(&project, &mock.url()).assert().success();
        assert_eq!(probe_count(&project), 4);
    }
}

#[tokio::test]
async fn engine_free_installs_do_not_execute_node() {
    let mock = MockRegistry::start().await;
    mock.with_manifest_package(
        serde_json::json!({"name": "engine-free", "version": "1.0.0"}),
        &[],
    )
    .await;
    let project = TempProject::empty(
        r#"{"name":"consumer","version":"1.0.0","dependencies":{"engine-free":"1.0.0"}}"#,
    );
    write_node_shim(&project);
    install(&project, &mock.url()).assert().success();
    install(&project, &mock.url()).assert().success();
    assert_eq!(probe_count(&project), 0);
    project.write_file("lpm.lock", "invalid = [");
    install(&project, &mock.url())
        .arg("--frozen-lockfile")
        .assert()
        .failure();
    assert_eq!(probe_count(&project), 0);
}

#[tokio::test]
async fn strict_replay_accepts_exact_local_peer_providers() {
    let mock = MockRegistry::start().await;
    for protocol in [
        "workspace:*",
        "file:../provider",
        "link:../provider",
        "catalog:",
    ] {
        let project = TempProject::empty(
            r#"{"name":"root","private":true,"workspaces":["packages/*"],"catalogs":{"default":{"provider":"workspace:*"}},"dependencies":{"host":"workspace:*","provider":"workspace:*"}}"#,
        );
        project.write_file(
            "packages/provider/package.json",
            r#"{"name":"provider","version":"1.0.0"}"#,
        );
        project.write_file(
            "packages/host/package.json",
            &serde_json::json!({
                "name":"host", "version":"1.0.0", "peerDependencies":{"provider":protocol}
            })
            .to_string(),
        );
        install(&project, &mock.url())
            .arg("--strict-peer-dependencies")
            .assert()
            .success();
        let lockfile = project.read_file("lpm.lock");
        for args in [&[][..], &["--frozen-lockfile"][..], &["--offline"][..]] {
            install(&project, &mock.url())
                .arg("--strict-peer-dependencies")
                .args(args)
                .assert()
                .success();
            assert_eq!(project.read_file("lpm.lock"), lockfile);
        }
    }
}

#[tokio::test]
async fn strict_replay_accepts_matching_tagged_peer_without_changing_lockfile() {
    let mock = MockRegistry::start().await;
    let tarball = make_tarball_from_pkg_json(
        serde_json::json!({"name":"provider", "version":"1.0.0"}),
        &[],
    );
    let mut metadata = mock.package_metadata("provider", "1.0.0", &tarball);
    metadata["dist-tags"]["stable"] = serde_json::json!("1.0.0");
    mock.with_package_metadata("provider", "1.0.0", &tarball, metadata)
        .await;
    for tag in ["latest", "stable"] {
        let host = format!("host-{tag}");
        mock.with_manifest_package(
            serde_json::json!({
                "name":host,"version":"1.0.0","peerDependencies":{"provider":tag}
            }),
            &[],
        )
        .await;
        let project = TempProject::empty(
            &serde_json::json!({
                "name":"consumer","dependencies":{host:"1.0.0","provider":"1.0.0"}
            })
            .to_string(),
        );
        install(&project, &mock.url())
            .arg("--strict-peer-dependencies")
            .assert()
            .success();
        let lockfile = project.read_file("lpm.lock");
        for args in [&[][..], &["--frozen-lockfile"][..], &["--offline"][..]] {
            install(&project, &mock.url())
                .arg("--strict-peer-dependencies")
                .args(args)
                .assert()
                .success();
            assert_eq!(project.read_file("lpm.lock"), lockfile);
        }
        std::fs::remove_dir_all(project.home().join(".lpm/cache")).unwrap();
        let output = install(&project, &mock.url())
            .args(["--strict-peer-dependencies", "--offline"])
            .assert()
            .failure()
            .get_output()
            .clone();
        assert!(
            String::from_utf8_lossy(&output.stdout)
                .contains("fresh registry metadata is unavailable")
        );
        install(&project, &mock.url())
            .args(["--strict-peer-dependencies", "--frozen-lockfile"])
            .assert()
            .success();
        assert_eq!(project.read_file("lpm.lock"), lockfile);
    }
}

#[tokio::test]
async fn strict_replay_rejects_malformed_peer_manifests() {
    let mock = MockRegistry::start().await;
    for (index, mut malformed) in [
        serde_json::json!({"name":"host","version":"1.0.0","peerDependencies":[]}),
        serde_json::json!({"name":"host","version":"1.0.0","peerDependencies":{"provider":{"range":"^1"}}}),
        serde_json::json!({"name":"host","version":"1.0.0","peerDependenciesMeta":{"provider":{"optional":"yes"}}}),
    ].into_iter().enumerate() {
        let name = format!("malformed-host-{index}");
        malformed["name"] = serde_json::json!(name);
        let tarball = make_tarball_from_pkg_json(malformed, &[]);
        let metadata = mock.package_metadata(&name, "1.0.0", &tarball);
        mock.with_package_metadata(&name, "1.0.0", &tarball, metadata).await;
        let project = TempProject::empty(&serde_json::json!({"name":"consumer","dependencies":{name:"1.0.0"}}).to_string());
        install(&project, &mock.url()).assert().success();
        for args in [&["--frozen-lockfile"][..], &["--offline"][..]] {
            let output = install(&project, &mock.url()).arg("--strict-peer-dependencies").args(args).assert().failure().get_output().clone();
            assert!(String::from_utf8_lossy(&output.stdout).contains("cannot validate peers from"));
        }
    }
}

#[tokio::test]
async fn strict_replay_failure_preserves_v1_project_links() {
    let mock = MockRegistry::start().await;
    mock.with_manifest_package(
        serde_json::json!({"name":"host","version":"1.0.0","peerDependencies":{"missing":"^1"}}),
        &[],
    )
    .await;
    let project = TempProject::empty(
        r#"{"name":"consumer","dependencies":{"host":"1.0.0"},"lpm":{"autoInstallPeers":false}}"#,
    );
    install(&project, &mock.url())
        .env("LPM_STORE_VERSION", "v1")
        .args(["--linker", "isolated"])
        .assert()
        .success();
    project.write_file(
        "previous/package.json",
        r#"{"name":"previous","version":"1.0.0"}"#,
    );
    let target = std::fs::read_link(project.path().join("node_modules/host")).unwrap();
    std::os::unix::fs::symlink(&target, project.path().join("node_modules/previous")).unwrap();
    let output = install(&project, &mock.url())
        .env("LPM_STORE_VERSION", "v1")
        .args(["--linker", "isolated"])
        .arg("--strict-peer-dependencies")
        .assert()
        .failure()
        .get_output()
        .clone();
    assert!(String::from_utf8_lossy(&output.stdout).contains("strict-peer-dependencies failed"));
    assert_eq!(
        std::fs::read_link(project.path().join("node_modules/previous")).unwrap(),
        target
    );
}

#[tokio::test]
async fn strict_replay_rejects_substituted_local_peer_source() {
    let mock = MockRegistry::start().await;
    for protocol in ["file:", "link:", "workspace:"] {
        let workspace = protocol == "workspace:";
        let peer_slot = if workspace { "expected" } else { "peer-alias" };
        let project = TempProject::empty(
            r#"{"name":"consumer","dependencies":{"host":"file:./packages/host","other":"file:./packages/other","expected":"file:./packages/expected"}}"#,
        );
        if workspace {
            let mut root: serde_json::Value =
                serde_json::from_str(&project.read_file("package.json")).unwrap();
            root["workspaces"] =
                serde_json::json!(["packages/app", "packages/host", "packages/expected"]);
            root.as_object_mut().unwrap().remove("dependencies");
            project.write_file("packages/app/package.json", r#"{"name":"app","version":"1.0.0","dependencies":{"host":"file:../host","expected":"workspace:*","other":"file:../other"}}"#);
            project.write_file("package.json", &root.to_string());
        }
        project.write_file(
            "packages/expected/package.json",
            r#"{"name":"expected","version":"1.0.0"}"#,
        );
        project.write_file(
            "packages/other/package.json",
            &serde_json::json!({"name":if workspace {"expected"} else {"other"},"version":"1.0.0"})
                .to_string(),
        );
        project.write_file("packages/host/package.json", &serde_json::json!({"name":"host","version":"1.0.0","peerDependencies":{peer_slot:if workspace {"workspace:*".to_string()} else {format!("{protocol}../expected")}}}).to_string());
        install(&project, &mock.url())
            .arg("--strict-peer-dependencies")
            .args(if workspace {
                &["--filter", "app"][..]
            } else {
                &[][..]
            })
            .assert()
            .success();
        install(&project, &mock.url())
            .arg("--strict-peer-dependencies")
            .args(if workspace {
                &["--filter", "app"][..]
            } else {
                &[][..]
            })
            .arg("--offline")
            .assert()
            .success();
        if workspace {
            let mut root: serde_json::Value =
                serde_json::from_str(&project.read_file("package.json")).unwrap();
            root["workspaces"] = serde_json::json!(["packages/app", "packages/expected"]);
            project.write_file("package.json", &root.to_string());
        }
        let mut union =
            lpm_lockfile::Lockfile::read_fast(&project.path().join("lpm.lock")).unwrap();
        let importer = if workspace { "packages/app" } else { "." };
        let mut lockfile = union.project_importer(importer).unwrap();
        let other = lockfile
            .packages
            .iter()
            .find(|package| {
                package
                    .source
                    .as_deref()
                    .is_some_and(|source| source.ends_with("/other"))
            })
            .unwrap_or_else(|| panic!("missing other source: {}", project.read_file("lpm.lock")))
            .clone();
        let host = lockfile
            .packages
            .iter_mut()
            .find(|package| package.name == "host")
            .unwrap();
        host.peer_targets
            .insert(peer_slot.into(), other.instance_id.unwrap());
        let peer = host
            .peer_edges
            .iter_mut()
            .find(|peer| peer.local_name == peer_slot)
            .unwrap();
        peer.target_name = other.name.clone();
        peer.target_version = other.version.clone();
        peer.target_wrapper_id = Some(other.source_kind().unwrap().unwrap().source_id());
        union.replace_importer(importer, lockfile).unwrap();
        union
            .write_to_file(&project.path().join("lpm.lock"))
            .unwrap();
        for args in [&["--frozen-lockfile"][..], &["--offline"][..]] {
            let output = install(&project, &mock.url())
                .arg("--strict-peer-dependencies")
                .args(if workspace {
                    &["--filter", "app"][..]
                } else {
                    &[][..]
                })
                .args(args)
                .assert()
                .failure()
                .get_output()
                .clone();
            assert!(
                String::from_utf8_lossy(&output.stdout).contains("different source"),
                "{protocol}: {}",
                String::from_utf8_lossy(&output.stdout)
            );
        }
    }
}

#[tokio::test]
async fn strict_replay_preserves_missing_latest_tag_resolution_semantics() {
    let mock = MockRegistry::start().await;
    let tarball = make_tarball_from_pkg_json(
        serde_json::json!({"name":"provider", "version":"1.0.0"}),
        &[],
    );
    let mut metadata = mock.package_metadata("provider", "1.0.0", &tarball);
    metadata["dist-tags"] = serde_json::json!({});
    mock.with_package_metadata("provider", "1.0.0", &tarball, metadata)
        .await;
    mock.with_manifest_package(serde_json::json!({"name":"host","version":"1.0.0","peerDependencies":{"provider":"latest"}}), &[]).await;
    let project = TempProject::empty(
        r#"{"name":"consumer","dependencies":{"host":"1.0.0","provider":"1.0.0"},"lpm":{"autoInstallPeers":false}}"#,
    );
    install(&project, &mock.url())
        .arg("--strict-peer-dependencies")
        .assert()
        .success();
    for args in [&["--frozen-lockfile"][..], &["--offline"][..]] {
        install(&project, &mock.url())
            .arg("--strict-peer-dependencies")
            .args(args)
            .assert()
            .success();
    }
}

#[tokio::test]
async fn strict_replay_rejects_incompatible_tagged_providers() {
    for (tag, tagged_version) in [("stable", "2.0.0"), ("latest", "0.5.0")] {
        let mock = MockRegistry::start().await;
        let tarball = make_tarball_from_pkg_json(
            serde_json::json!({"name":"provider", "version":"1.0.0"}),
            &[],
        );
        let tagged_tarball = make_tarball_from_pkg_json(
            serde_json::json!({"name":"provider", "version":tagged_version}),
            &[],
        );
        let mut metadata = mock.package_metadata("provider", "1.0.0", &tarball);
        let tagged_metadata = mock.package_metadata("provider", tagged_version, &tagged_tarball);
        metadata["versions"][tagged_version] = tagged_metadata["versions"][tagged_version].clone();
        metadata["dist-tags"][tag] = serde_json::json!(tagged_version);
        mock.with_package_metadata_and_tarballs(
            "provider",
            metadata,
            &[("1.0.0", tarball), (tagged_version, tagged_tarball)],
        )
        .await;
        mock.with_manifest_package(serde_json::json!({"name":"host","version":"1.0.0","peerDependencies":{"provider":tag}}), &[]).await;
        let project = TempProject::empty(
            r#"{"name":"consumer","dependencies":{"host":"1.0.0","provider":"1.0.0"},"lpm":{"autoInstallPeers":false}}"#,
        );
        install(&project, &mock.url()).assert().success();
        for args in [&["--frozen-lockfile"][..], &["--offline"][..]] {
            let output = install(&project, &mock.url())
                .arg("--strict-peer-dependencies")
                .args(args)
                .assert()
                .failure()
                .get_output()
                .clone();
            assert!(
                String::from_utf8_lossy(&output.stdout).contains("strict-peer-dependencies failed")
            );
        }
    }
}

#[tokio::test]
async fn bare_unchanged_install_validates_current_npmrc() {
    let mock = MockRegistry::start().await;
    mock.with_manifest_package(
        serde_json::json!({"name":"engine-dep","version":"1.0.0","engines":{"node":">=20"}}),
        &[],
    )
    .await;
    let project =
        TempProject::empty(r#"{"name":"consumer","dependencies":{"engine-dep":"1.0.0"}}"#);
    write_node_shim(&project);
    install(&project, &mock.url()).assert().success();
    bare_install(&project).assert().success();
    project.write_file(
        ".npmrc",
        "strict-npmrc=true\nregistri=https://typo.example/\n",
    );
    bare_install(&project)
        .env_remove("LPM_TEST_UNSET_REGISTRY")
        .assert()
        .failure();
}

#[tokio::test]
async fn bare_unchanged_install_rechecks_changed_registry_route() {
    let mock = MockRegistry::start().await;
    mock.with_manifest_package(
        serde_json::json!({"name":"engine-dep","version":"1.0.0","engines":{"node":">=20"}}),
        &[],
    )
    .await;
    let project =
        TempProject::empty(r#"{"name":"consumer","dependencies":{"engine-dep":"1.0.0"}}"#);
    write_node_shim(&project);
    install(&project, &mock.url()).assert().success();
    bare_install(&project).assert().success();
    project.write_file(
        ".npmrc",
        &format!("registry={}/changed-registry\n", mock.url()),
    );
    bare_install(&project).assert().failure();
}

#[tokio::test]
async fn bare_install_repairs_unexpected_sidecars_after_manifest_mtime_changes() {
    let mock = MockRegistry::start().await;
    mock.with_manifest_package(
        serde_json::json!({"name":"engine-free","version":"1.0.0"}),
        &[],
    )
    .await;
    let project =
        TempProject::empty(r#"{"name":"consumer","dependencies":{"engine-free":"1.0.0"}}"#);
    install(&project, &mock.url()).assert().success();
    bare_install(&project).assert().success();
    let original_hash = project.read_file(".lpm/install-hash");
    assert!(original_hash.contains("b:not-required"));
    let manifest = project.read_file("package.json");
    project.write_file("package.json", &format!("{manifest}\n"));
    bare_install(&project)
        .env("LPM_REGISTRY_URL", mock.url())
        .assert()
        .success();
    assert_ne!(project.read_file(".lpm/install-hash"), original_hash);
    project.write_file("lpm.lockb", "invalid sidecar");
    bare_install(&project)
        .env("LPM_REGISTRY_URL", mock.url())
        .assert()
        .success();
    assert!(!project.path().join("lpm.lockb").exists());
    assert!(
        project
            .path()
            .join("node_modules/engine-free/package.json")
            .exists()
    );
}

#[tokio::test]
async fn bare_install_keeps_compact_noop_after_semantically_unchanged_edits() {
    let mock = MockRegistry::start().await;
    mock.with_manifest_package(
        serde_json::json!({"name":"engine-free","version":"1.0.0"}),
        &[],
    )
    .await;
    let project =
        TempProject::empty(r#"{"name":"consumer","dependencies":{"engine-free":"1.0.0"}}"#);
    install(&project, &mock.url()).assert().success();
    let manifest = std::fs::File::open(project.path().join("package.json")).unwrap();
    let modified = manifest.metadata().unwrap().modified().unwrap();
    manifest
        .set_modified(modified + std::time::Duration::from_secs(1))
        .unwrap();
    let output = bare_install(&project)
        .assert()
        .success()
        .get_output()
        .clone();
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["up_to_date"], true);
    assert!(
        result.get("counts").is_none(),
        "expected compact no-op response: {result}"
    );
    let lockfile = project.read_file("lpm.lock");
    project.write_file(
        "lpm.lock",
        &format!("{lockfile}\n# unchanged dependency graph\n"),
    );
    let output = bare_install(&project)
        .assert()
        .success()
        .get_output()
        .clone();
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["up_to_date"], true);
    assert!(
        result.get("counts").is_none(),
        "expected normalized lockfile hash: {result}"
    );
}
