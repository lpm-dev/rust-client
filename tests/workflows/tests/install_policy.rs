//! Workflow tests for install-time `--policy` / `--yolo` semantics.
//!
//! Policy semantics are exhaustively covered at the `rebuild` and
//! `approve-scripts` surfaces (see `rebuild.rs`, `approve_scripts.rs`).
//! This file covers the install-time CLI contract specifically:
//!
//! - clap-level mutual exclusion (`--policy` + `--yolo` rejected)
//! - default policy (deny) on a scripted package blocks execution and
//!   surfaces the approval hint
//! - `--policy=allow` and `--yolo` are accepted at parse time and
//!   produce the auto-build code path
//! - allow-policy install-time builds have the same lifecycle tail on
//!   fresh and offline lockfile paths
//! - build-state and generated bins are refreshed after successful
//!   install-time builds

mod support;

use support::mock_registry::{MockRegistry, compute_integrity, make_tarball_from_pkg_json};
use support::{TempProject, lpm_with_registry, write_signed_unlock};

/// Mount a scripted package on the mock registry. The package
/// declares a `postinstall` script in its `package.json` — this is
/// what makes install-time policy actually fire.
async fn mount_scripted_pkg(mock: &MockRegistry, name: &str) {
    let pkg_json = serde_json::json!({
        "name": name,
        "version": "1.0.0",
        "license": "MIT",
        "main": "index.js",
        "scripts": {
            "postinstall": "node -e \"process.exit(0)\""
        },
    });
    let tarball = make_tarball_from_pkg_json(pkg_json, &[]);
    mock.with_package(name, "1.0.0", &tarball).await;
    mock.with_batch_metadata(vec![serde_json::json!({
        "name": name,
        "dist-tags": { "latest": "1.0.0" },
        "versions": {
            "1.0.0": {
                "name": name,
                "version": "1.0.0",
                "scripts": { "postinstall": "node -e \"process.exit(0)\"" },
                "dist": {
                    "tarball": format!("{}/tarballs/{name}/-/{name}-1.0.0.tgz", mock.url()),
                    "integrity": compute_integrity(&tarball),
                },
                "dependencies": {}
            }
        },
        "time": { "1.0.0": "2025-01-01T00:00:00.000Z" }
    })])
    .await;
}

async fn mount_failing_scripted_pkg(mock: &MockRegistry, name: &str) {
    let pkg_json = serde_json::json!({
        "name": name,
        "version": "1.0.0",
        "license": "MIT",
        "main": "index.js",
        "scripts": {
            "postinstall": "node fail.js"
        },
    });
    mock.with_manifest_package(
        pkg_json,
        &[(
            "fail.js",
            br#"require('fs').writeFileSync('fail-marker.txt', 'ran');
process.exit(1);
"#,
        )],
    )
    .await;
}

async fn mount_marker_scripted_pkg(mock: &MockRegistry, name: &str) {
    let pkg_json = serde_json::json!({
        "name": name,
        "version": "1.0.0",
        "license": "MIT",
        "main": "index.js",
        "scripts": {
            "postinstall": "node build.js"
        },
    });
    mock.with_manifest_package(
        pkg_json,
        &[(
            "build.js",
            br#"require('fs').writeFileSync('postinstall-marker.txt', 'ran');
"#,
        )],
    )
    .await;
}

async fn mount_generated_bin_pkg(mock: &MockRegistry, name: &str, bin_name: &str) {
    let pkg_json = serde_json::json!({
        "name": name,
        "version": "1.0.0",
        "license": "MIT",
        "main": "index.js",
        "bin": {
            bin_name: "bin/generated-cli.js"
        },
        "scripts": {
            "postinstall": "node build-bin.js"
        },
    });
    mock.with_manifest_package(
        pkg_json,
        &[(
            "build-bin.js",
            br#"const fs = require('fs');
fs.mkdirSync('bin', { recursive: true });
fs.writeFileSync('bin/generated-cli.js', '#!/usr/bin/env node\nconsole.log("generated-cli-ok");\n');
fs.chmodSync('bin/generated-cli.js', 0o755);
"#,
        )],
    )
    .await;
}

async fn mount_consumer_with_generated_bin_transitive(
    mock: &MockRegistry,
    consumer_name: &str,
    generated_name: &str,
) {
    mount_generated_bin_pkg(mock, generated_name, "generated-transitive-cli").await;
    let index_js = format!("module.exports = require.resolve('{generated_name}/package.json');\n");
    mock.with_manifest_package(
        serde_json::json!({
            "name": consumer_name,
            "version": "1.0.0",
            "license": "MIT",
            "main": "index.js",
            "dependencies": {
                generated_name: "1.0.0"
            }
        }),
        &[("index.js", index_js.as_bytes())],
    )
    .await;
}

fn empty_project_with_dep(dep: &str) -> TempProject {
    TempProject::empty(&format!(
        r#"{{"name":"install-policy","version":"1.0.0","dependencies":{{"{dep}":"^1.0.0"}}}}"#
    ))
}

fn empty_project_without_deps() -> TempProject {
    TempProject::empty(r#"{"name":"install-policy","version":"1.0.0"}"#)
}

fn parse_last_json_object(stdout: &[u8], stderr: &[u8]) -> serde_json::Value {
    let text = String::from_utf8_lossy(stdout);
    let mut starts: Vec<usize> = text.match_indices('{').map(|(idx, _)| idx).collect();
    starts.reverse();
    for start in starts {
        if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&text[start..]) {
            return parsed;
        }
    }
    panic!(
        "stdout must contain a parseable JSON object\nstdout:\n{}\nstderr:\n{}",
        text,
        String::from_utf8_lossy(stderr),
    );
}

fn assert_generated_bin_executes(project: &TempProject, bin_name: &str) {
    let bin_path = project.path().join("node_modules/.bin").join(bin_name);
    assert!(
        bin_path.exists(),
        "postinstall-generated bin must be linked into node_modules/.bin at {}",
        bin_path.display(),
    );

    let output = std::process::Command::new(&bin_path)
        .output()
        .unwrap_or_else(|e| panic!("generated bin must be executable: {e}"));
    assert!(
        output.status.success(),
        "generated bin must execute successfully\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        "generated-cli-ok"
    );
}

// ─── parse mutual-exclusion contract ─────────────────────────────────

#[tokio::test]
async fn install_policy_and_yolo_together_is_rejected_by_clap() {
    let project = empty_project_with_dep("scripted-pkg");
    let mock = MockRegistry::start().await;
    mount_scripted_pkg(&mock, "scripted-pkg").await;

    let output = lpm_with_registry(&project, &mock.url())
        .args(["install", "--policy=allow", "--yolo"])
        .output()
        .expect("failed to run lpm install --policy --yolo");

    assert!(
        !output.status.success(),
        "--policy and --yolo are mutually exclusive; parser must reject"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("--yolo") || stderr.contains("--policy") || stderr.contains("conflict"),
        "stderr must explain the conflict, got:\n{stderr}",
    );
}

#[tokio::test]
async fn install_policy_and_triage_together_is_rejected_by_clap() {
    let project = empty_project_with_dep("scripted-pkg");
    let mock = MockRegistry::start().await;
    mount_scripted_pkg(&mock, "scripted-pkg").await;

    let output = lpm_with_registry(&project, &mock.url())
        .args(["install", "--policy=allow", "--triage"])
        .output()
        .expect("failed to run lpm install --policy --triage");

    assert!(
        !output.status.success(),
        "--policy and --triage are mutually exclusive; parser must reject"
    );
}

#[tokio::test]
async fn install_yolo_and_triage_together_is_rejected_by_clap() {
    let project = empty_project_with_dep("scripted-pkg");
    let mock = MockRegistry::start().await;
    mount_scripted_pkg(&mock, "scripted-pkg").await;

    let output = lpm_with_registry(&project, &mock.url())
        .args(["install", "--yolo", "--triage"])
        .output()
        .expect("failed to run lpm install --yolo --triage");

    assert!(
        !output.status.success(),
        "--yolo and --triage are mutually exclusive; parser must reject"
    );
}

// ─── invalid policy value ────────────────────────────────────────────

#[tokio::test]
async fn install_policy_with_invalid_value_is_rejected() {
    let project = empty_project_with_dep("scripted-pkg");
    let mock = MockRegistry::start().await;
    mount_scripted_pkg(&mock, "scripted-pkg").await;

    let output = lpm_with_registry(&project, &mock.url())
        .args(["install", "--policy=nonsense-value"])
        .output()
        .expect("failed to run lpm install --policy=nonsense-value");

    assert!(
        !output.status.success(),
        "invalid policy value must be rejected"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("policy")
            || stderr.contains("deny")
            || stderr.contains("allow")
            || stderr.contains("triage"),
        "stderr must list valid policy values, got:\n{stderr}",
    );
}

/// `lpm --json install --policy=<invalid>` surfaces the same rejection
/// as a JSON envelope on stdout. The invalid-value error is raised by
/// `script_policy_config::collapse_policy_flags` inside the install
/// arm — prior to the per-arm async wrap it short-circuited past the
/// `--json` envelope handler (finding #76 in private/findings.md).
/// This test pins that the wrap restored the contract.
#[tokio::test]
async fn install_policy_with_invalid_value_under_json_emits_error_envelope_on_stdout() {
    let project = empty_project_with_dep("scripted-pkg");
    let mock = MockRegistry::start().await;
    mount_scripted_pkg(&mock, "scripted-pkg").await;

    let output = lpm_with_registry(&project, &mock.url())
        .args(["--json", "install", "--policy=nonsense-value"])
        .output()
        .expect("failed to run lpm --json install --policy=nonsense-value");

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let envelope: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap_or_else(|e| {
        panic!("--json install --policy=nonsense must emit JSON: {e}\n---\n{stdout}")
    });
    assert_eq!(envelope["success"], serde_json::json!(false));
    let err = envelope["error"].as_str().unwrap_or_default();
    assert!(
        err.contains("policy") || err.contains("nonsense") || err.contains("invalid"),
        "error must reference the invalid policy value, got: {err}",
    );
    // The error message lists the allowed values so users can self-correct.
    assert!(
        err.contains("deny") && err.contains("allow") && err.contains("triage"),
        "error must enumerate valid policies, got: {err}",
    );
}

// ─── default policy: deny is in effect ───────────────────────────────

#[tokio::test]
async fn install_default_policy_blocks_postinstall_scripts() {
    let project = empty_project_with_dep("scripted-pkg");
    let mock = MockRegistry::start().await;
    mount_scripted_pkg(&mock, "scripted-pkg").await;

    let output = lpm_with_registry(&project, &mock.url())
        .args(["install"])
        .output()
        .expect("failed to run lpm install");

    assert!(
        output.status.success(),
        "install with default policy on a scripted package must succeed (deny just skips scripts)\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    // Default-deny installs surface a build-hint guiding the user to
    // approve-scripts. Pin that contract — the exact wording may shift
    // but `approve-scripts` should always appear.
    assert!(
        combined.contains("approve-scripts")
            || combined.contains("lifecycle script")
            || combined.contains("scripts"),
        "default-deny install must mention the script-policy hint, got:\n{combined}",
    );
}

#[tokio::test]
async fn install_default_policy_json_suggests_approve_scripts_for_blocked_packages() {
    let project = empty_project_with_dep("scripted-pkg");
    let mock = MockRegistry::start().await;
    mount_scripted_pkg(&mock, "scripted-pkg").await;

    let output = lpm_with_registry(&project, &mock.url())
        .args(["--json", "install"])
        .output()
        .expect("failed to run lpm --json install");

    assert!(
        output.status.success(),
        "default-policy install with blocked scripts must still succeed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let envelope = parse_last_json_object(&output.stdout, &output.stderr);
    assert_eq!(envelope["schema_version"], serde_json::json!(2));
    assert!(
        envelope["blocked_count"]
            .as_u64()
            .is_some_and(|count| count > 0),
        "default-policy JSON must report blocked script packages; got {envelope}",
    );
    assert!(
        envelope["blocked_packages"]
            .as_array()
            .is_some_and(|packages| !packages.is_empty()),
        "default-policy JSON must list blocked script packages; got {envelope}",
    );
    assert_eq!(
        envelope["next_steps"][0]["description"],
        "Review blocked lifecycle scripts"
    );
    assert_eq!(envelope["next_steps"][0]["command"], "lpm approve-scripts");
}

#[tokio::test]
async fn install_default_policy_prints_approve_scripts_hint_after_done_summary() {
    let project = empty_project_with_dep("scripted-pkg");
    let mock = MockRegistry::start().await;
    mount_scripted_pkg(&mock, "scripted-pkg").await;

    let output = lpm_with_registry(&project, &mock.url())
        .args(["install"])
        .output()
        .expect("failed to run lpm install");

    assert!(
        output.status.success(),
        "install with default policy on a scripted package must succeed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    let done_idx = stderr.find("Done · installed").unwrap_or_else(|| {
        panic!("install output must include final Done summary; stderr:\n{stderr}")
    });
    let script_hint_idx = stderr
        .find("package(s) have install scripts")
        .unwrap_or_else(|| {
            panic!("install output must include lifecycle script summary; stderr:\n{stderr}")
        });
    let approve_idx = stderr.find("Run `lpm approve-scripts`").unwrap_or_else(|| {
        panic!("install output must include approve-scripts pointer; stderr:\n{stderr}")
    });

    assert!(
        done_idx < script_hint_idx && script_hint_idx < approve_idx,
        "lifecycle approval hint must print after final install summary; stderr:\n{stderr}",
    );
}

#[tokio::test]
async fn install_default_policy_blocks_postinstall_scripts_under_v2_store() {
    let project = empty_project_with_dep("scripted-pkg");
    let mock = MockRegistry::start().await;
    mount_scripted_pkg(&mock, "scripted-pkg").await;

    let output = lpm_with_registry(&project, &mock.url())
        .env("LPM_STORE_VERSION", "v2")
        .args(["install"])
        .output()
        .expect("failed to run lpm install under v2 store");

    assert!(
        output.status.success(),
        "install with default policy on a scripted package must succeed under v2 store (deny just skips scripts)\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    assert!(
        combined.contains("approve-scripts")
            || combined.contains("lifecycle script")
            || combined.contains("scripts"),
        "default-deny install under v2 store must mention the script-policy hint, got:\n{combined}",
    );
}

// ─── --policy=allow and --yolo accepted ──────────────────────────────

#[tokio::test]
async fn install_policy_allow_is_accepted_at_parse_time() {
    let project = empty_project_with_dep("scripted-pkg");
    let mock = MockRegistry::start().await;
    mount_scripted_pkg(&mock, "scripted-pkg").await;

    let output = lpm_with_registry(&project, &mock.url())
        .args(["install", "--policy=allow"])
        .output()
        .expect("failed to run lpm install --policy=allow");

    // Whether the postinstall actually fires depends on `node` being
    // available; we only assert the parse-time contract here. The
    // script-execution path is exercised in `rebuild.rs`.
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // A non-zero exit is acceptable ONLY if it's from script
        // execution failure (Node missing, etc.) — never from clap
        // rejection.
        assert!(
            !stderr.contains("invalid value") && !stderr.contains("unexpected argument"),
            "--policy=allow must be parsed without clap errors, got stderr:\n{stderr}",
        );
    }
}

#[tokio::test]
async fn install_policy_allow_reports_no_blocked_packages_after_running_dependency_scripts() {
    let project = empty_project_with_dep("scripted-marker");
    let mock = MockRegistry::start().await;
    mount_marker_scripted_pkg(&mock, "scripted-marker").await;
    write_signed_unlock(&project, &["scripts-allow", "sandbox-none"]);

    let output = lpm_with_registry(&project, &mock.url())
        .args(["--json", "install", "--policy=allow", "--no-sandbox"])
        .output()
        .expect("failed to run lpm install --policy=allow --json");

    assert!(
        output.status.success(),
        "allow-policy install must succeed after running dependency postinstall\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let envelope = parse_last_json_object(&output.stdout, &output.stderr);
    assert_eq!(
        envelope["blocked_count"],
        serde_json::json!(0),
        "successful allow-policy auto-build must not report packages as still blocked: {envelope}",
    );
    assert_eq!(
        envelope["blocked_packages"],
        serde_json::json!([]),
        "successful allow-policy auto-build must clear blocked package JSON: {envelope}",
    );
    assert!(
        envelope.get("next_steps").is_none(),
        "allow-policy JSON must not suggest approve-scripts when nothing is blocked: {envelope}",
    );

    let build_state: serde_json::Value =
        serde_json::from_str(&project.read_file(".lpm/build-state.json"))
            .expect("build-state.json must parse");
    assert_eq!(
        build_state["blocked_packages"],
        serde_json::json!([]),
        "successful allow-policy auto-build must persist an empty blocked set: {build_state}",
    );
}

#[tokio::test]
async fn install_policy_allow_links_bin_generated_by_dependency_postinstall() {
    let project = empty_project_with_dep("generated-bin-pkg");
    let mock = MockRegistry::start().await;
    mount_generated_bin_pkg(&mock, "generated-bin-pkg", "generated-cli").await;
    write_signed_unlock(&project, &["scripts-allow", "sandbox-none"]);

    let output = lpm_with_registry(&project, &mock.url())
        .args(["install", "--policy=allow", "--no-sandbox"])
        .output()
        .expect("failed to run lpm install --policy=allow");

    assert!(
        output.status.success(),
        "allow-policy install must succeed and generate the declared bin\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    assert_generated_bin_executes(&project, "generated-cli");
}

#[tokio::test]
async fn warm_v2_reinstall_rebuilds_postinstall_generated_bin_after_node_modules_wipe() {
    let project = empty_project_with_dep("warm-generated-bin-pkg");
    let mock = MockRegistry::start().await;
    mount_generated_bin_pkg(&mock, "warm-generated-bin-pkg", "warm-generated-cli").await;
    write_signed_unlock(&project, &["scripts-allow", "sandbox-none"]);

    let first = lpm_with_registry(&project, &mock.url())
        .env("LPM_STORE_VERSION", "v2")
        .args(["install", "--policy=allow", "--no-sandbox"])
        .output()
        .expect("failed to run first v2 lpm install --policy=allow");
    assert!(
        first.status.success(),
        "first v2 allow-policy install must succeed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&first.stdout),
        String::from_utf8_lossy(&first.stderr),
    );
    assert_generated_bin_executes(&project, "warm-generated-cli");

    std::fs::remove_dir_all(project.path().join("node_modules"))
        .expect("remove node_modules before warm v2 reinstall");

    let second = lpm_with_registry(&project, &mock.url())
        .env("LPM_STORE_VERSION", "v2")
        .args(["install", "--policy=allow", "--no-sandbox"])
        .output()
        .expect("failed to run second v2 lpm install --policy=allow");
    assert!(
        second.status.success(),
        "warm v2 reinstall must recreate lifecycle-generated bins\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&second.stdout),
        String::from_utf8_lossy(&second.stderr),
    );

    assert_generated_bin_executes(&project, "warm-generated-cli");
}

#[tokio::test]
async fn v2_allow_policy_builds_transitive_postinstall_generated_file() {
    let project = empty_project_with_dep("transitive-generated-consumer");
    let mock = MockRegistry::start().await;
    mount_consumer_with_generated_bin_transitive(
        &mock,
        "transitive-generated-consumer",
        "generated-transitive-bin",
    )
    .await;
    write_signed_unlock(&project, &["scripts-allow", "sandbox-none"]);

    let output = lpm_with_registry(&project, &mock.url())
        .env("LPM_STORE_VERSION", "v2")
        .args(["install", "--policy=allow", "--no-sandbox"])
        .output()
        .expect("failed to run v2 lpm install --policy=allow");

    assert!(
        output.status.success(),
        "v2 allow-policy install must run transitive dependency postinstall\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let resolved = std::process::Command::new("node")
        .current_dir(project.path())
        .arg("-e")
        .arg(
            r#"const fs = require('fs');
const path = require('path');
const pkgJson = require('transitive-generated-consumer');
const generated = path.join(path.dirname(pkgJson), 'bin/generated-cli.js');
fs.accessSync(generated, fs.constants.X_OK);
process.stdout.write(generated);
"#,
        )
        .output()
        .expect("node must resolve the transitive generated package");
    assert!(
        resolved.status.success(),
        "transitive dependency postinstall must create an executable generated file\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&resolved.stdout),
        String::from_utf8_lossy(&resolved.stderr),
    );
}

#[tokio::test]
async fn install_package_policy_allow_links_bin_generated_by_dependency_postinstall() {
    let project = empty_project_without_deps();
    let mock = MockRegistry::start().await;
    mount_generated_bin_pkg(&mock, "generated-bin-add-pkg", "generated-add-cli").await;
    write_signed_unlock(&project, &["scripts-allow", "sandbox-none"]);

    let output = lpm_with_registry(&project, &mock.url())
        .args([
            "install",
            "generated-bin-add-pkg",
            "--policy=allow",
            "--no-sandbox",
            "--yes",
        ])
        .output()
        .expect("failed to run lpm install <pkg> --policy=allow");

    assert!(
        output.status.success(),
        "package-add install must succeed and generate the declared bin\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let bin_path = project.path().join("node_modules/.bin/generated-add-cli");
    assert!(
        bin_path.exists(),
        "postinstall-generated bin from package-add install must be linked into node_modules/.bin at {}",
        bin_path.display(),
    );
}

#[tokio::test]
async fn offline_install_policy_allow_runs_dependency_postinstall_from_lockfile() {
    let project = empty_project_with_dep("offline-scripted-marker");
    let mock = MockRegistry::start().await;
    mount_marker_scripted_pkg(&mock, "offline-scripted-marker").await;

    lpm_with_registry(&project, &mock.url())
        .args(["install"])
        .assert()
        .success();
    std::fs::remove_dir_all(project.path().join("node_modules"))
        .expect("remove node_modules before offline install");
    write_signed_unlock(&project, &["scripts-allow", "sandbox-none"]);

    let output = lpm_with_registry(&project, &mock.url())
        .args(["install", "--offline", "--policy=allow", "--no-sandbox"])
        .output()
        .expect("failed to run offline lpm install --policy=allow");

    assert!(
        output.status.success(),
        "offline allow-policy install must run dependency postinstall from the lockfile\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let marker = project
        .path()
        .join("node_modules/offline-scripted-marker/postinstall-marker.txt");
    assert!(
        marker.exists(),
        "offline allow-policy install must run postinstall and create {}",
        marker.display(),
    );
}

#[tokio::test]
async fn offline_install_policy_allow_fails_when_dependency_postinstall_fails() {
    let project = empty_project_with_dep("offline-scripted-fail");
    let mock = MockRegistry::start().await;
    mount_failing_scripted_pkg(&mock, "offline-scripted-fail").await;

    lpm_with_registry(&project, &mock.url())
        .args(["install"])
        .assert()
        .success();
    std::fs::remove_dir_all(project.path().join("node_modules"))
        .expect("remove node_modules before offline install");
    write_signed_unlock(&project, &["scripts-allow", "sandbox-none"]);

    let output = lpm_with_registry(&project, &mock.url())
        .args(["install", "--offline", "--policy=allow", "--no-sandbox"])
        .output()
        .expect("failed to run offline lpm install --policy=allow");

    assert!(
        !output.status.success(),
        "offline allow-policy install must fail when a dependency postinstall fails\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    assert!(
        combined.contains("postinstall failed")
            || combined.contains("Auto-build failed")
            || combined.contains("failed to build"),
        "offline install must surface the failing lifecycle script, got:\n{combined}",
    );
}

#[tokio::test]
async fn install_auto_build_failing_script_exits_nonzero() {
    let project = empty_project_with_dep("scripted-fail");
    let mock = MockRegistry::start().await;
    mount_failing_scripted_pkg(&mock, "scripted-fail").await;

    write_signed_unlock(&project, &["scripts-allow", "sandbox-none"]);

    let output = lpm_with_registry(&project, &mock.url())
        .args(["install", "--policy=allow", "--auto-build", "--no-sandbox"])
        .output()
        .expect("failed to run lpm install --auto-build");

    assert!(
        !output.status.success(),
        "trusted auto-build failure must fail install\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    assert!(
        combined.contains("postinstall failed")
            || combined.contains("Auto-build failed")
            || combined.contains("failed to build"),
        "install must surface the failing lifecycle script, got:\n{combined}",
    );
}

#[tokio::test]
async fn install_yolo_is_accepted_at_parse_time() {
    let project = empty_project_with_dep("scripted-pkg");
    let mock = MockRegistry::start().await;
    mount_scripted_pkg(&mock, "scripted-pkg").await;

    let output = lpm_with_registry(&project, &mock.url())
        .args(["install", "--yolo"])
        .output()
        .expect("failed to run lpm install --yolo");

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            !stderr.contains("invalid value") && !stderr.contains("unexpected argument"),
            "--yolo must be parsed without clap errors, got stderr:\n{stderr}",
        );
    }
}
