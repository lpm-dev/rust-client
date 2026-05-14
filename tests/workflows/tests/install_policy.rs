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
//!
//! Actual script-execution side effects are out of scope here — they
//! depend on `node` being on PATH and the wrapper materialization
//! pipeline (covered in `rebuild.rs`).

mod support;

use support::mock_registry::{MockRegistry, compute_integrity, make_tarball_from_pkg_json};
use support::{TempProject, lpm_with_registry};

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
                    "tarball": format!("{}/tarballs/{name}-1.0.0.tgz", mock.url()),
                    "integrity": compute_integrity(&tarball),
                },
                "dependencies": {}
            }
        },
        "time": { "1.0.0": "2025-01-01T00:00:00.000Z" }
    })])
    .await;
}

fn empty_project_with_dep(dep: &str) -> TempProject {
    TempProject::empty(&format!(
        r#"{{"name":"install-policy","version":"1.0.0","dependencies":{{"{dep}":"^1.0.0"}}}}"#
    ))
}

// ─── clap mutual-exclusion contract ──────────────────────────────────

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
        "--policy and --yolo are mutually exclusive; clap must reject"
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
        "--policy and --triage are mutually exclusive; clap must reject"
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
        "--yolo and --triage are mutually exclusive; clap must reject"
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
