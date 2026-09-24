//! Workflow coverage for runtime validation during otherwise unchanged installs.

#![cfg(unix)]

mod support;

use std::os::unix::fs::{MetadataExt, PermissionsExt};

use support::mock_registry::MockRegistry;
use support::{TempProject, lpm_with_registry};

fn install(project: &TempProject, registry: &str) -> assert_cmd::Command {
    let mut command = lpm_with_registry(project, registry);
    command.args([
        "--json",
        "install",
        "--no-skills",
        "--no-editor-setup",
        "--no-security-summary",
    ]);
    command.env(
        "PATH",
        std::env::join_paths(std::iter::once(project.home().join("node-shim-bin")).chain(
            std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default()),
        ))
        .unwrap(),
    );
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
