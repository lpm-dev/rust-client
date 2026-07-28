//! Workflow tests for deterministic registry fault handling.

mod support;

use std::path::PathBuf;

use support::fault_registry::{
    FaultRegistry, MetadataReply, TarballReply, integrity_for, missing_tarball_reply,
};
use support::mock_registry::make_tarball;
use support::{TempProject, lpm_spawnable_with_registry, lpm_with_registry};

const INSTALL_ARGS: &[&str] = &[
    "install",
    "--no-security-summary",
    "--no-skills",
    "--no-editor-setup",
];

fn project_with_dep(project_name: &str, dep_name: &str, dep_spec: &str) -> TempProject {
    TempProject::empty(&format!(
        r#"{{
            "name": "{project_name}",
            "version": "1.0.0",
            "dependencies": {{
                "{dep_name}": "{dep_spec}"
            }}
        }}"#
    ))
}

fn install(project: &TempProject, registry: &FaultRegistry) -> std::process::Output {
    install_with(project, registry, &[], &[], false)
}

fn install_with(
    project: &TempProject,
    registry: &FaultRegistry,
    extra_args: &[&str],
    env: &[(&str, &str)],
    json: bool,
) -> std::process::Output {
    let mut command = lpm_with_registry(project, &registry.url());
    if !env.iter().any(|(name, _)| *name == "LPM_GREEDY_FUSION") {
        command.env("LPM_GREEDY_FUSION", "0");
    }
    command.env("LPM_STREAM_FETCH", "1");
    for (name, value) in env {
        command.env(name, value);
    }
    if json {
        command.arg("--json");
    }
    command
        .args(INSTALL_ARGS)
        .args(extra_args)
        .output()
        .expect("failed to run lpm install")
}

fn ci_with(
    project: &TempProject,
    registry: &FaultRegistry,
    env: &[(&str, &str)],
) -> std::process::Output {
    let mut command = lpm_with_registry(project, &registry.url());
    command
        .env("LPM_GREEDY_FUSION", "0")
        .env("LPM_STREAM_FETCH", "1");
    for (name, value) in env {
        command.env(name, value);
    }
    command
        .args([
            "ci",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("failed to run lpm ci")
}

fn capture_lockfiles(project: &TempProject) -> (Vec<u8>, Vec<u8>) {
    let lock = std::fs::read(project.path().join("lpm.lock")).expect("read established lpm.lock");
    let lockb_path = project.path().join("lpm.lockb");
    if !lockb_path.exists() {
        lpm_lockfile::binary::write_binary(&lpm_lockfile::Lockfile::new(), &lockb_path)
            .expect("seed a valid preexisting binary companion");
    }
    let lockb = std::fs::read(lockb_path).expect("read established lpm.lockb");
    (lock, lockb)
}

fn assert_lockfiles_unchanged(project: &TempProject, expected: &(Vec<u8>, Vec<u8>)) {
    assert_eq!(
        std::fs::read(project.path().join("lpm.lock")).expect("read preserved lpm.lock"),
        expected.0,
        "artifact failure must preserve lpm.lock byte-for-byte"
    );
    assert_eq!(
        std::fs::read(project.path().join("lpm.lockb")).expect("read preserved lpm.lockb"),
        expected.1,
        "artifact failure must preserve lpm.lockb byte-for-byte"
    );
}

fn clear_materialized_state(project: &TempProject) {
    for path in [project.path().join("node_modules"), project.store_dir()] {
        match std::fs::remove_dir_all(&path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => panic!("remove {} before artifact replay: {error}", path.display()),
        }
    }
}

fn assert_pinned_artifact_failure(output: &std::process::Output, package_name: &str) {
    assert!(
        !output.status.success(),
        "install must fail when the pinned artifact is unavailable\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Pinned artifact unavailable")
            && stderr.contains(&format!("{package_name}@1.0.0"))
            && stderr.contains("preserved")
            && stderr.contains(&format!("lpm upgrade {package_name}")),
        "error must identify the pin, preservation contract, and explicit upgrade command:\n{stderr}"
    );
}

async fn establish_lockfile_then_yank(
    project_name: &str,
    package_name: &str,
) -> (FaultRegistry, TempProject, (Vec<u8>, Vec<u8>)) {
    establish_project_lockfile_then_yank(
        project_with_dep(project_name, package_name, "1.0.0"),
        package_name,
    )
    .await
}

async fn establish_project_lockfile_then_yank(
    project: TempProject,
    package_name: &str,
) -> (FaultRegistry, TempProject, (Vec<u8>, Vec<u8>)) {
    let registry = FaultRegistry::start().await;
    let version = "1.0.0";
    let tarball = make_tarball(package_name, version);
    let metadata = registry.package_metadata(package_name, version, &tarball);
    let tarball_path = FaultRegistry::tarball_path(package_name, version);

    registry.with_batch_metadata(vec![metadata.clone()]).await;
    registry
        .with_package_metadata_reply(package_name, MetadataReply::Ok(metadata))
        .await;
    registry
        .with_tarball_sequence(
            &tarball_path,
            vec![TarballReply::Bytes(tarball), missing_tarball_reply()],
        )
        .await;

    let first = install(&project, &registry);
    assert!(
        first.status.success(),
        "initial install must establish both lockfiles\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&first.stdout),
        String::from_utf8_lossy(&first.stderr),
    );
    let lockfiles = capture_lockfiles(&project);
    clear_materialized_state(&project);

    (registry, project, lockfiles)
}

fn install_with_tree_integrity_store_version(
    project: &TempProject,
    registry_url: &str,
    store_version: &str,
    extra_args: &[&str],
) -> std::process::Output {
    let mut cmd = lpm_with_registry(project, registry_url);
    cmd.env("LPM_GREEDY_FUSION", "0")
        .env("LPM_STORE_VERSION", store_version)
        .env("LPM_V2_OBJECT_INTEGRITY", "tree")
        .args(INSTALL_ARGS)
        .args(extra_args)
        .output()
        .expect("failed to run lpm install")
}

fn package_install_path(project: &TempProject, package_name: &str) -> PathBuf {
    package_name
        .split('/')
        .fold(project.path().join("node_modules"), |path, segment| {
            path.join(segment)
        })
}

fn assert_failed_cleanly(output: &std::process::Output, project: &TempProject, package_name: &str) {
    assert!(
        !output.status.success(),
        "install must fail under the injected registry fault\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    assert!(
        !project.file_exists("lpm.lock"),
        "failed install must not leave a text lockfile"
    );
    assert!(
        !project.file_exists("lpm.lockb"),
        "failed install must not leave a binary lockfile"
    );
    assert!(
        !package_install_path(project, package_name).exists(),
        "failed install must not materialize node_modules/{package_name}"
    );
}

fn locked_package(project: &TempProject, package_name: &str) -> lpm_lockfile::LockedPackage {
    let lockfile = lpm_lockfile::Lockfile::read_from_file(&project.path().join("lpm.lock"))
        .expect("read lpm.lock");
    lockfile
        .packages
        .into_iter()
        .find(|package| package.name == package_name)
        .unwrap_or_else(|| panic!("lockfile must contain {package_name}"))
}

#[tokio::test]
async fn fresh_resolution_artifact_failure_exercises_fetch_overlap() {
    let registry = FaultRegistry::start().await;
    let package_name = "fault-yanked-mid-resolution";
    let version = "1.0.0";
    let tarball = make_tarball(package_name, version);
    let metadata = registry.package_metadata(package_name, version, &tarball);
    let tarball_path = FaultRegistry::tarball_path(package_name, version);

    registry.with_batch_metadata(vec![metadata.clone()]).await;
    registry
        .with_package_metadata_reply(package_name, MetadataReply::Ok(metadata))
        .await;
    let tarball_hits = registry
        .with_tarball_reply(&tarball_path, missing_tarball_reply())
        .await;

    let project = project_with_dep("fault-yanked-mid-resolution-app", package_name, version);
    let output = install_with(
        &project,
        &registry,
        &[],
        &[
            ("LPM_GREEDY_FUSION", "1"),
            ("LPM_FETCH_OVERLAP", "1"),
            ("LPM_FETCH_OVERLAP_MIN_SELECTED", "1"),
        ],
        false,
    );

    assert_failed_cleanly(&output, &project, package_name);
    assert!(
        tarball_hits.get() >= 2,
        "selected-event overlap and authoritative fetch must both attempt the unavailable tarball"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Selected artifact unavailable")
            && stderr.contains(&format!("{package_name}@{version}"))
            && stderr.contains("preserved"),
        "fresh resolution error should identify the selected artifact and preservation contract, got:\n{stderr}"
    );
}

#[tokio::test]
async fn selected_artifact_json_error_exposes_stable_preservation_contract() {
    let registry = FaultRegistry::start().await;
    let package_name = "fault-json-selected-artifact";
    let version = "1.0.0";
    let tarball = make_tarball(package_name, version);
    let metadata = registry.package_metadata(package_name, version, &tarball);
    let tarball_path = FaultRegistry::tarball_path(package_name, version);

    registry.with_batch_metadata(vec![metadata.clone()]).await;
    registry
        .with_package_metadata_reply(package_name, MetadataReply::Ok(metadata))
        .await;
    registry
        .with_tarball_reply(&tarball_path, missing_tarball_reply())
        .await;

    let project = project_with_dep("fault-json-selected-artifact-app", package_name, version);
    let output = install_with(&project, &registry, &[], &[], true);

    assert!(
        !output.status.success(),
        "JSON install must fail when the selected artifact is unavailable"
    );
    assert!(
        !project.file_exists("lpm.lock") && !project.file_exists("lpm.lockb"),
        "selected artifact failure must not create lockfiles"
    );
    let envelope: serde_json::Value =
        serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
            panic!(
                "selected artifact error must emit one JSON envelope: {error}\n{}",
                String::from_utf8_lossy(&output.stdout)
            )
        });
    assert_eq!(envelope["error_code"], "selected_artifact_unavailable");
    assert_eq!(envelope["error"]["package"], package_name);
    assert_eq!(envelope["error"]["version"], version);
    assert_eq!(envelope["error"]["kind"], "selected");
    assert_eq!(envelope["error"]["lockfiles_preserved"], true);
    assert!(envelope["error"]["suggested_command"].is_null());
    assert!(
        envelope.get("next_steps").is_none(),
        "fresh-resolution failures must not expose a pin-update action"
    );
    insta::assert_json_snapshot!("selected_artifact_unavailable_error", envelope, {
        ".error.message" => "[SELECTED ARTIFACT MESSAGE]",
        ".error.source" => "[REGISTRY]",
    });
}

#[tokio::test]
async fn install_fails_without_fetching_tarball_when_tarball_exists_without_metadata() {
    let registry = FaultRegistry::start().await;
    let package_name = "fault-tarball-only-publish";
    let version = "1.0.0";
    let tarball = make_tarball(package_name, version);
    let tarball_path = FaultRegistry::tarball_path(package_name, version);

    registry.with_batch_metadata(Vec::new()).await;
    registry
        .with_package_metadata_reply(
            package_name,
            MetadataReply::NotFound(r#"{"error":"package metadata not visible"}"#.to_string()),
        )
        .await;
    let tarball_hits = registry
        .with_tarball_reply(&tarball_path, TarballReply::Bytes(tarball))
        .await;

    let project = project_with_dep("fault-tarball-only-publish-app", package_name, version);
    let output = install(&project, &registry);

    assert_failed_cleanly(&output, &project, package_name);
    assert_eq!(
        tarball_hits.get(),
        0,
        "resolver must not fetch an unreferenced tarball when metadata is absent"
    );
}

#[tokio::test]
async fn mutable_lockfile_replay_preserves_pins_when_tarball_is_yanked() {
    let package_name = "fault-lockfile-yanked";
    let (registry, project, lockfiles) =
        establish_lockfile_then_yank("fault-lockfile-yanked-app", package_name).await;

    let second = install(&project, &registry);
    assert_pinned_artifact_failure(&second, package_name);
    assert_lockfiles_unchanged(&project, &lockfiles);
    assert!(
        !package_install_path(&project, package_name).exists(),
        "failed replay must not materialize node_modules/{package_name}"
    );
}

#[tokio::test]
async fn frozen_lockfile_replay_preserves_pins_when_tarball_is_yanked() {
    let package_name = "fault-frozen-lockfile-yanked";
    let (registry, project, lockfiles) =
        establish_lockfile_then_yank("fault-frozen-lockfile-yanked-app", package_name).await;

    let output = install_with(&project, &registry, &["--frozen-lockfile"], &[], false);

    assert_pinned_artifact_failure(&output, package_name);
    assert_lockfiles_unchanged(&project, &lockfiles);
}

#[tokio::test]
async fn ci_replay_preserves_pins_when_tarball_is_yanked() {
    let package_name = "fault-ci-lockfile-yanked";
    let (registry, project, lockfiles) =
        establish_lockfile_then_yank("fault-ci-lockfile-yanked-app", package_name).await;

    let output = ci_with(&project, &registry, &[]);

    assert_pinned_artifact_failure(&output, package_name);
    assert_lockfiles_unchanged(&project, &lockfiles);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("mutable development environment") && stderr.contains("commit"),
        "CI error must explain how to update and commit the lockfile explicitly:\n{stderr}"
    );
}

#[tokio::test]
async fn install_automatically_frozen_by_ci_preserves_pins_when_tarball_is_yanked() {
    let package_name = "fault-auto-frozen-lockfile-yanked";
    let (registry, project, lockfiles) =
        establish_lockfile_then_yank("fault-auto-frozen-lockfile-yanked-app", package_name).await;

    let output = install_with(&project, &registry, &[], &[("CI", "true")], false);

    assert_pinned_artifact_failure(&output, package_name);
    assert_lockfiles_unchanged(&project, &lockfiles);
}

#[tokio::test]
async fn frozen_replay_does_not_select_newer_version_when_pinned_tarball_is_yanked() {
    let registry = FaultRegistry::start().await;
    let package_name = "fault-frozen-newer-version";
    let pinned_version = "1.0.0";
    let newer_version = "2.0.0";
    let pinned_tarball = make_tarball(package_name, pinned_version);
    let newer_tarball = make_tarball(package_name, newer_version);
    let pinned_metadata = registry.package_metadata(package_name, pinned_version, &pinned_tarball);
    let mut combined_metadata =
        registry.package_metadata(package_name, newer_version, &newer_tarball);
    combined_metadata["versions"][pinned_version] =
        pinned_metadata["versions"][pinned_version].clone();
    combined_metadata["time"][pinned_version] = serde_json::json!("2025-01-01T00:00:00.000Z");

    registry
        .with_batch_metadata(vec![combined_metadata.clone()])
        .await;
    registry
        .with_package_metadata_reply(package_name, MetadataReply::Ok(combined_metadata))
        .await;
    registry
        .with_tarball_sequence(
            &FaultRegistry::tarball_path(package_name, pinned_version),
            vec![TarballReply::Bytes(pinned_tarball), missing_tarball_reply()],
        )
        .await;
    let newer_hits = registry
        .with_tarball_reply(
            &FaultRegistry::tarball_path(package_name, newer_version),
            TarballReply::Bytes(newer_tarball),
        )
        .await;

    let project = project_with_dep(
        "fault-frozen-newer-version-app",
        package_name,
        pinned_version,
    );
    let first = install(&project, &registry);
    assert!(
        first.status.success(),
        "initial install must pin {package_name}@{pinned_version}:\n{}",
        String::from_utf8_lossy(&first.stderr)
    );
    let lockfiles = capture_lockfiles(&project);
    clear_materialized_state(&project);

    let output = install_with(&project, &registry, &["--frozen-lockfile"], &[], false);

    assert_pinned_artifact_failure(&output, package_name);
    assert_lockfiles_unchanged(&project, &lockfiles);
    assert_eq!(
        newer_hits.get(),
        0,
        "frozen replay must not fetch the newer advertised version"
    );
    assert_eq!(
        locked_package(&project, package_name).version,
        pinned_version
    );
}

#[tokio::test]
async fn metadata_refresh_server_error_keeps_http_classification_and_lockfiles() {
    let registry = FaultRegistry::start().await;
    let package_name = "fault-refresh-server-error";
    let version = "1.0.0";
    let tarball = make_tarball(package_name, version);
    let metadata = registry.package_metadata(package_name, version, &tarball);
    let tarball_path = FaultRegistry::tarball_path(package_name, version);

    registry.with_batch_metadata(vec![metadata]).await;
    registry
        .with_package_metadata_reply(
            package_name,
            MetadataReply::Status {
                code: 500,
                body: r#"{"error":"registry unavailable"}"#.to_string(),
            },
        )
        .await;
    registry
        .with_tarball_sequence(
            &tarball_path,
            vec![TarballReply::Bytes(tarball), missing_tarball_reply()],
        )
        .await;

    let project = project_with_dep("fault-refresh-server-error-app", package_name, version);
    let first = install(&project, &registry);
    assert!(
        first.status.success(),
        "initial install must establish lockfiles:\n{}",
        String::from_utf8_lossy(&first.stderr)
    );
    let lockfiles = capture_lockfiles(&project);
    clear_materialized_state(&project);

    let output = install(&project, &registry);

    assert!(
        !output.status.success(),
        "metadata refresh HTTP 500 must fail the replay"
    );
    assert_lockfiles_unchanged(&project, &lockfiles);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("500")
            && (stderr.contains("HTTP") || stderr.contains("Registry error"))
            && !stderr.contains("Pinned artifact unavailable")
            && !stderr.contains("tarball not found"),
        "metadata refresh failure must retain its HTTP/registry classification:\n{stderr}"
    );
}

#[tokio::test]
async fn lockfile_artifact_failures_preserve_files_across_authoritative_and_experimental_routes() {
    let cases = [
        (
            "legacy-v1",
            vec![("LPM_STORE_VERSION", "v1"), ("LPM_STREAM_FETCH", "0")],
            false,
        ),
        (
            "streaming-v2",
            vec![("LPM_STORE_VERSION", "v2"), ("LPM_STREAM_FETCH", "1")],
            false,
        ),
        (
            "experimental",
            vec![
                ("LPM_STORE_VERSION", "v2"),
                ("LPM_STREAM_FETCH", "1"),
                ("LPM_EXPERIMENTAL_INSTALLER_SPIKE", "1"),
                ("LPM_INSTALLER_SPIKE_BENCHMARK_ONLY", "1"),
                ("LPM_INSTALLER_SPIKE_GRAPH", "lockfile"),
                ("LPM_INSTALLER_SPIKE_PARITY", "lockfile-deny"),
            ],
            true,
        ),
    ];

    for (route_name, env, json) in cases {
        let registry = FaultRegistry::start().await;
        let package_name = format!("fault-{route_name}-yanked");
        let version = "1.0.0";
        let tarball = make_tarball(&package_name, version);
        let metadata = registry.package_metadata(&package_name, version, &tarball);
        let tarball_path = FaultRegistry::tarball_path(&package_name, version);
        registry.with_batch_metadata(vec![metadata.clone()]).await;
        registry
            .with_package_metadata_reply(&package_name, MetadataReply::Ok(metadata))
            .await;
        registry
            .with_tarball_sequence(
                &tarball_path,
                vec![TarballReply::Bytes(tarball), missing_tarball_reply()],
            )
            .await;

        let project = project_with_dep(&format!("fault-{route_name}-app"), &package_name, version);
        let first = if json {
            install(&project, &registry)
        } else {
            install_with(&project, &registry, &[], &env, false)
        };
        assert!(
            first.status.success(),
            "{route_name} initial install must establish lockfiles:\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&first.stdout),
            String::from_utf8_lossy(&first.stderr)
        );
        let lockfiles = capture_lockfiles(&project);
        clear_materialized_state(&project);

        let extra_args: &[&str] = if json { &["--frozen-lockfile"] } else { &[] };
        let output = install_with(&project, &registry, extra_args, &env, json);

        if json {
            assert!(
                !output.status.success(),
                "{route_name} replay must fail when the pinned artifact is unavailable"
            );
            let envelope: serde_json::Value = serde_json::from_slice(&output.stdout)
                .unwrap_or_else(|error| {
                    panic!(
                        "{route_name} must emit a JSON error envelope: {error}\n{}",
                        String::from_utf8_lossy(&output.stdout)
                    )
                });
            assert_eq!(
                envelope["error_code"], "pinned_artifact_unavailable",
                "{route_name} must retain pinned-artifact classification"
            );
            assert_eq!(envelope["error"]["lockfiles_preserved"], true);
        } else {
            assert_pinned_artifact_failure(&output, &package_name);
        }
        assert_lockfiles_unchanged(&project, &lockfiles);
    }
}

#[tokio::test]
async fn direct_dependency_pinned_artifact_json_error_uses_manifest_key() {
    let package_name = "fault-json-pinned-artifact";
    let (registry, project, lockfiles) =
        establish_lockfile_then_yank("fault-json-pinned-artifact-app", package_name).await;

    let output = install_with(&project, &registry, &[], &[], true);

    assert!(
        !output.status.success(),
        "JSON install must fail when its pinned artifact is unavailable"
    );
    assert_lockfiles_unchanged(&project, &lockfiles);
    let envelope: serde_json::Value =
        serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
            panic!(
                "pinned artifact error must emit one JSON envelope: {error}\n{}",
                String::from_utf8_lossy(&output.stdout)
            )
        });
    assert_eq!(envelope["error_code"], "pinned_artifact_unavailable");
    assert_eq!(envelope["error"]["package"], package_name);
    assert_eq!(envelope["error"]["version"], "1.0.0");
    assert_eq!(envelope["error"]["kind"], "pinned");
    assert_eq!(envelope["error"]["lockfiles_preserved"], true);
    assert_eq!(
        envelope["error"]["suggested_command"],
        format!("lpm upgrade {package_name}")
    );
    assert_eq!(
        envelope["next_steps"][0]["command"],
        format!("lpm upgrade {package_name}")
    );
    insta::assert_json_snapshot!("pinned_artifact_unavailable_error", envelope, {
        ".error.message" => "[PINNED ARTIFACT MESSAGE]",
        ".error.source" => "[REGISTRY]",
    });
}

#[tokio::test]
async fn aliased_dependency_pinned_artifact_json_error_uses_alias_manifest_key() {
    let canonical_name = "fault-json-aliased-artifact";
    let alias_name = "local-artifact";
    let project = project_with_dep(
        "fault-json-aliased-artifact-app",
        alias_name,
        &format!("npm:{canonical_name}@1.0.0"),
    );
    let (registry, project, lockfiles) =
        establish_project_lockfile_then_yank(project, canonical_name).await;

    let output = install_with(&project, &registry, &[], &[], true);

    assert!(
        !output.status.success(),
        "JSON install must fail when an aliased dependency artifact is unavailable"
    );
    assert_lockfiles_unchanged(&project, &lockfiles);
    let envelope: serde_json::Value =
        serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
            panic!(
                "aliased artifact error must emit one JSON envelope: {error}\n{}",
                String::from_utf8_lossy(&output.stdout)
            )
        });
    assert_eq!(
        envelope["error"]["suggested_command"],
        format!("lpm upgrade {alias_name}")
    );
    assert_eq!(
        envelope["next_steps"][0]["command"],
        format!("lpm upgrade {alias_name}")
    );
    insta::assert_json_snapshot!("aliased_pinned_artifact_unavailable_error", envelope, {
        ".error.message" => "[ALIASED PINNED ARTIFACT MESSAGE]",
        ".error.source" => "[REGISTRY]",
    });
}

#[tokio::test]
async fn transitive_dependency_pinned_artifact_json_error_has_no_command_action() {
    let registry = FaultRegistry::start().await;
    let direct_name = "fault-json-direct-owner";
    let transitive_name = "fault-json-transitive-artifact";
    let version = "1.0.0";
    let direct_tarball = make_tarball(direct_name, version);
    let transitive_tarball = make_tarball(transitive_name, version);
    let mut direct_metadata = registry.package_metadata(direct_name, version, &direct_tarball);
    direct_metadata["versions"][version]["dependencies"] =
        serde_json::json!({ transitive_name: version });
    let transitive_metadata =
        registry.package_metadata(transitive_name, version, &transitive_tarball);

    registry
        .with_batch_metadata(vec![direct_metadata.clone(), transitive_metadata.clone()])
        .await;
    registry
        .with_package_metadata_reply(direct_name, MetadataReply::Ok(direct_metadata))
        .await;
    registry
        .with_package_metadata_reply(transitive_name, MetadataReply::Ok(transitive_metadata))
        .await;
    registry
        .with_tarball_reply(
            &FaultRegistry::tarball_path(direct_name, version),
            TarballReply::Bytes(direct_tarball),
        )
        .await;
    registry
        .with_tarball_sequence(
            &FaultRegistry::tarball_path(transitive_name, version),
            vec![
                TarballReply::Bytes(transitive_tarball),
                missing_tarball_reply(),
            ],
        )
        .await;

    let project = project_with_dep("fault-json-transitive-artifact-app", direct_name, version);
    let first = install(&project, &registry);
    assert!(
        first.status.success(),
        "initial install must establish a transitive lockfile graph:\n{}",
        String::from_utf8_lossy(&first.stderr)
    );
    let lockfiles = capture_lockfiles(&project);
    clear_materialized_state(&project);

    let output = install_with(&project, &registry, &[], &[], true);

    assert!(
        !output.status.success(),
        "JSON replay must fail when a transitive artifact is unavailable"
    );
    assert_lockfiles_unchanged(&project, &lockfiles);
    let envelope: serde_json::Value =
        serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
            panic!(
                "transitive artifact error must emit one JSON envelope: {error}\n{}",
                String::from_utf8_lossy(&output.stdout)
            )
        });
    assert_eq!(envelope["error"]["package"], transitive_name);
    assert!(
        envelope["error"]["suggested_command"].is_null(),
        "transitive packages must not expose an unusable upgrade command"
    );
    assert!(
        envelope.get("next_steps").is_none(),
        "transitive packages must not expose a machine-actionable command"
    );
    let message = envelope["error"]["message"]
        .as_str()
        .expect("artifact error message must be a string");
    assert!(
        message.contains("owning direct dependency")
            && message.contains("override")
            && message.contains("restore"),
        "transitive recovery guidance must explain the actionable choices: {message}"
    );
    insta::assert_json_snapshot!("transitive_pinned_artifact_unavailable_error", envelope, {
        ".error.message" => "[TRANSITIVE PINNED ARTIFACT MESSAGE]",
        ".error.source" => "[REGISTRY]",
    });
}

#[tokio::test]
async fn install_recovers_when_stale_metadata_points_to_moved_tarball_with_same_integrity() {
    let registry = FaultRegistry::start().await;
    let package_name = "fault-stale-moved-tarball";
    let version = "1.0.0";
    let tarball = make_tarball(package_name, version);
    let integrity = integrity_for(&tarball);
    let old_url = registry.tarball_url(package_name, version);
    let old_path = FaultRegistry::tarball_path(package_name, version);
    let fresh_path = format!("/tarballs/{package_name}/-/{package_name}-{version}-fresh.tgz");
    let fresh_url = format!("{}{}", registry.url(), fresh_path);
    let stale_metadata =
        registry.package_metadata_with_tarball_url(package_name, version, &old_url, &integrity);
    let fresh_metadata =
        registry.package_metadata_with_tarball_url(package_name, version, &fresh_url, &integrity);

    registry.with_batch_metadata(vec![stale_metadata]).await;
    registry
        .with_package_metadata_reply(package_name, MetadataReply::Ok(fresh_metadata))
        .await;
    registry
        .with_tarball_reply(&old_path, missing_tarball_reply())
        .await;
    registry
        .with_tarball_reply(&fresh_path, TarballReply::Bytes(tarball))
        .await;

    let project = project_with_dep("fault-stale-moved-tarball-app", package_name, "^1.0.0");
    let output = install(&project, &registry);
    assert!(
        output.status.success(),
        "install should recover from stale metadata when fresh metadata points to the same bytes\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let locked = locked_package(&project, package_name);
    assert_eq!(locked.version, version);
    assert_eq!(
        locked.tarball.as_deref(),
        Some(fresh_url.as_str()),
        "lockfile must persist the verified fresh tarball URL"
    );
}

#[tokio::test]
async fn install_rejects_tarball_bytes_that_change_after_resolution() {
    let registry = FaultRegistry::start().await;
    let package_name = "fault-toctou-tarball";
    let version = "1.0.0";
    let resolved_tarball = make_tarball(package_name, version);
    let changed_tarball = make_tarball("fault-toctou-other-bytes", version);
    let metadata = registry.package_metadata(package_name, version, &resolved_tarball);
    let tarball_path = FaultRegistry::tarball_path(package_name, version);

    registry.with_batch_metadata(vec![metadata.clone()]).await;
    registry
        .with_package_metadata_reply(package_name, MetadataReply::Ok(metadata))
        .await;
    registry
        .with_tarball_reply(&tarball_path, TarballReply::Bytes(changed_tarball))
        .await;

    let project = project_with_dep("fault-toctou-tarball-app", package_name, version);
    let output = install(&project, &registry);

    assert_failed_cleanly(&output, &project, package_name);
    let stderr = String::from_utf8_lossy(&output.stderr).to_ascii_lowercase();
    assert!(
        stderr.contains("integrity") || stderr.contains("checksum"),
        "error should explain the integrity failure, got:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[tokio::test]
async fn offline_v2_tree_integrity_install_fails_cleanly_when_cached_object_is_corrupted() {
    let registry = FaultRegistry::start().await;
    let package_name = "fault-corrupted-cache";
    let version = "1.0.0";
    let tarball = make_tarball(package_name, version);
    let integrity = integrity_for(&tarball);
    let metadata = registry.package_metadata(package_name, version, &tarball);
    let tarball_path = FaultRegistry::tarball_path(package_name, version);

    registry.with_batch_metadata(vec![metadata.clone()]).await;
    registry
        .with_package_metadata_reply(package_name, MetadataReply::Ok(metadata))
        .await;
    registry
        .with_tarball_reply(&tarball_path, TarballReply::Bytes(tarball))
        .await;

    let project = project_with_dep("fault-corrupted-cache-app", package_name, version);
    let online = install_with_tree_integrity_store_version(&project, &registry.url(), "v2", &[]);
    assert!(
        online.status.success(),
        "online v2 install must warm the cache\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&online.stdout),
        String::from_utf8_lossy(&online.stderr),
    );

    let v2_store = lpm_store::v2::Store::at(project.home().join(".lpm/store/v2"));
    let object_dir = v2_store
        .paths()
        .object_dir(&integrity)
        .expect("test integrity should map to a v2 object dir");
    std::fs::write(
        object_dir.join("index.js"),
        b"module.exports = 'corrupted';",
    )
    .expect("tamper cached object");
    std::fs::remove_dir_all(project.path().join("node_modules"))
        .expect("remove node_modules before offline reinstall");

    let offline = install_with_tree_integrity_store_version(
        &project,
        "http://127.0.0.1:1",
        "v2",
        &["--offline"],
    );
    assert!(
        !offline.status.success(),
        "offline reinstall must fail when the only cached object is corrupted\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&offline.stdout),
        String::from_utf8_lossy(&offline.stderr),
    );
    assert!(
        project.file_exists("lpm.lock"),
        "offline cache failure may preserve the existing lockfile graph"
    );
    assert!(
        !package_install_path(&project, package_name).exists(),
        "offline cache failure must not link corrupted bytes into node_modules/{package_name}"
    );
    let stderr = String::from_utf8_lossy(&offline.stderr).to_ascii_lowercase();
    assert!(
        stderr.contains("integrity") || stderr.contains("corrupt") || stderr.contains("offline"),
        "offline cache-corruption error should be explicit, got:\n{}",
        String::from_utf8_lossy(&offline.stderr)
    );
}

#[tokio::test]
async fn concurrent_publish_allows_one_winner_for_the_same_package_version() {
    let registry = FaultRegistry::start().await;
    registry.with_whoami("testuser", "test@example.com").await;
    let publish_counter = registry.with_single_winner_publish().await;

    let package_json = r#"{
        "name": "@lpm.dev/testuser.concurrent-fault-publish",
        "version": "1.0.0",
        "description": "publish race fixture",
        "main": "index.js",
        "license": "MIT"
    }"#;
    let project_a = TempProject::empty(package_json);
    let project_b = TempProject::empty(package_json);
    project_a.write_file("index.js", "module.exports = 'a';\n");
    project_b.write_file("index.js", "module.exports = 'b';\n");

    let child_a = lpm_spawnable_with_registry(&project_a, &registry.url())
        .args(["publish", "--yes", "--token", "test-token-123", "--lpm"])
        .spawn()
        .expect("spawn first publish");
    let child_b = lpm_spawnable_with_registry(&project_b, &registry.url())
        .args(["publish", "--yes", "--token", "test-token-123", "--lpm"])
        .spawn()
        .expect("spawn second publish");

    let output_a = child_a.wait_with_output().expect("wait for first publish");
    let output_b = child_b.wait_with_output().expect("wait for second publish");
    let success_count =
        usize::from(output_a.status.success()) + usize::from(output_b.status.success());

    assert_eq!(
        success_count,
        1,
        "exactly one concurrent publish should win\nA stdout:\n{}\nA stderr:\n{}\nB stdout:\n{}\nB stderr:\n{}",
        String::from_utf8_lossy(&output_a.stdout),
        String::from_utf8_lossy(&output_a.stderr),
        String::from_utf8_lossy(&output_b.stdout),
        String::from_utf8_lossy(&output_b.stderr),
    );
    assert_eq!(
        publish_counter.get(),
        2,
        "both publish clients must reach the registry publish endpoint"
    );

    let requests = registry
        .server()
        .received_requests()
        .await
        .expect("wiremock request log must be available");
    let put_count = requests
        .iter()
        .filter(|request| request.method.as_str() == "PUT")
        .count();
    assert_eq!(put_count, 2, "registry must observe both publish attempts");
}
