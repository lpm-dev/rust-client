//! Workflow coverage for dependency lifecycle-build artifact reuse.

#![cfg(target_os = "macos")]

mod support;

use support::mock_registry::MockRegistry;
use support::{TempProject, lpm_spawnable_with_registry, lpm_with_registry};

const PACKAGE_NAME: &str = "synthetic-native-cache";
const PACKAGE_VERSION: &str = "1.0.0";
const BUILD_SCRIPT: &str = r#"
const fs = require('fs');
fs.writeFileSync('native-output.txt', process.hrtime.bigint().toString());
"#;

fn node_available() -> bool {
    std::process::Command::new("node")
        .arg("--version")
        .output()
        .is_ok_and(|output| output.status.success())
}

fn project_manifest() -> String {
    format!(
        r#"{{
  "name": "native-build-cache-workflow",
  "version": "1.0.0",
  "dependencies": {{
    "{PACKAGE_NAME}": "{PACKAGE_VERSION}"
  }}
}}"#
    )
}

fn installed_package_dir(project: &TempProject) -> std::path::PathBuf {
    std::fs::canonicalize(project.path().join("node_modules").join(PACKAGE_NAME))
        .expect("installed dependency must resolve into the v2 link entry")
}

#[tokio::test]
async fn native_lifecycle_output_is_restored_after_pristine_rematerialization() {
    if !node_available() {
        eprintln!("skipping: node is required for the native build-cache workflow");
        return;
    }

    let registry = MockRegistry::start().await;
    registry
        .with_manifest_package(
            serde_json::json!({
                "name": PACKAGE_NAME,
                "version": PACKAGE_VERSION,
                "scripts": {
                    "postinstall": "node build.js # node-gyp rebuild"
                }
            }),
            &[("build.js", BUILD_SCRIPT.as_bytes())],
        )
        .await;
    let project = TempProject::empty(&project_manifest());

    let install = lpm_with_registry(&project, &registry.url())
        .arg("install")
        .env("LPM_STORE_VERSION", "v2")
        .output()
        .expect("initial install");
    assert!(
        install.status.success(),
        "initial install failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&install.stdout),
        String::from_utf8_lossy(&install.stderr)
    );

    let first_rebuild = lpm_with_registry(&project, &registry.url())
        .args(["rebuild", "--all", "--strict-sandbox"])
        .env("LPM_STORE_VERSION", "v2")
        .output()
        .expect("first native rebuild");
    assert!(
        first_rebuild.status.success(),
        "first rebuild failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&first_rebuild.stdout),
        String::from_utf8_lossy(&first_rebuild.stderr)
    );
    let first_output =
        std::fs::read_to_string(installed_package_dir(&project).join("native-output.txt"))
            .expect("first build must produce native-output.txt");
    let builds_root = project.store_dir().join("v2/builds");
    assert!(
        builds_root.is_dir(),
        "first rebuild did not create the build cache:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&first_rebuild.stdout),
        String::from_utf8_lossy(&first_rebuild.stderr)
    );
    assert_eq!(
        std::fs::read_dir(&builds_root)
            .expect("build artifact root")
            .count(),
        1,
        "first rebuild must publish exactly one artifact"
    );

    std::fs::remove_dir_all(project.path().join("node_modules"))
        .expect("remove project materialization");
    let reinstall = lpm_with_registry(&project, &registry.url())
        .args(["install", "--force"])
        .env("LPM_STORE_VERSION", "v2")
        .output()
        .expect("pristine reinstall");
    assert!(
        reinstall.status.success(),
        "reinstall failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&reinstall.stdout),
        String::from_utf8_lossy(&reinstall.stderr)
    );
    assert!(
        !installed_package_dir(&project)
            .join("native-output.txt")
            .exists(),
        "reinstall must rematerialize pristine source bytes before cache restore"
    );

    let second_rebuild = lpm_with_registry(&project, &registry.url())
        .args(["--json", "rebuild", "--all", "--strict-sandbox"])
        .env("LPM_STORE_VERSION", "v2")
        .output()
        .expect("cached native rebuild");
    assert!(
        second_rebuild.status.success(),
        "cached rebuild failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&second_rebuild.stdout),
        String::from_utf8_lossy(&second_rebuild.stderr)
    );
    let mut envelope: serde_json::Value = serde_json::from_slice(&second_rebuild.stdout)
        .expect("cached rebuild stdout must be a JSON envelope");
    assert_eq!(envelope["build_cache"]["hits"], 1);
    assert_eq!(envelope["build_cache"]["misses"], 0);
    assert_eq!(envelope["build_cache"]["scripts_avoided"], 1);
    envelope["build_cache"]["restored_bytes"] = serde_json::json!("<bytes>");
    envelope["build_cache"]["lifecycle_ms_avoided"] = serde_json::json!("<ms>");
    for field in [
        "preparation",
        "key",
        "lookup",
        "restore",
        "rematerialize",
        "publish",
    ] {
        envelope["build_cache"]["timings_ms"][field] = serde_json::json!("<ms>");
    }
    insta::assert_json_snapshot!("native_build_cache_hit_metrics", envelope);
    assert_eq!(
        std::fs::read_to_string(installed_package_dir(&project).join("native-output.txt"))
            .expect("cached output must be restored"),
        first_output,
        "cache hit must restore the first build output instead of executing the script again"
    );

    let invalidated_rebuild = lpm_with_registry(&project, &registry.url())
        .args(["--json", "rebuild", "--all", "--strict-sandbox"])
        .env("LPM_STORE_VERSION", "v2")
        .env("CFLAGS", "-DLPM_BUILD_CACHE_INVALIDATION=1")
        .output()
        .expect("rebuild with changed build environment");
    assert!(
        invalidated_rebuild.status.success(),
        "invalidated rebuild failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&invalidated_rebuild.stdout),
        String::from_utf8_lossy(&invalidated_rebuild.stderr)
    );
    let invalidated_envelope: serde_json::Value =
        serde_json::from_slice(&invalidated_rebuild.stdout)
            .expect("invalidated rebuild stdout must be JSON");
    assert_eq!(invalidated_envelope["build_cache"]["hits"], 0);
    assert_eq!(invalidated_envelope["build_cache"]["misses"], 1);
    assert_ne!(
        std::fs::read_to_string(installed_package_dir(&project).join("native-output.txt"))
            .expect("invalidated rebuild must produce native-output.txt"),
        first_output,
        "a changed build-environment key must invalidate keyed local build state and rerun the lifecycle command"
    );
}

#[tokio::test]
async fn concurrent_native_rebuilds_execute_one_lifecycle_build_per_key() {
    if !node_available() {
        eprintln!("skipping: node is required for the native build-cache workflow");
        return;
    }

    let registry = MockRegistry::start().await;
    let script = br#"
const fs = require('fs');
fs.appendFileSync('executions.txt', `${process.pid}\n`);
Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 500);
"#;
    registry
        .with_manifest_package(
            serde_json::json!({
                "name": PACKAGE_NAME,
                "version": PACKAGE_VERSION,
                "scripts": {
                    "postinstall": "node build.js # node-gyp rebuild"
                }
            }),
            &[("build.js", script)],
        )
        .await;
    let project = TempProject::empty(&project_manifest());
    let install = lpm_with_registry(&project, &registry.url())
        .arg("install")
        .env("LPM_STORE_VERSION", "v2")
        .output()
        .expect("initial install");
    assert!(install.status.success());

    let mut first_command = lpm_spawnable_with_registry(&project, &registry.url());
    first_command
        .args(["--json", "rebuild", "--all", "--strict-sandbox"])
        .env("LPM_STORE_VERSION", "v2");
    let mut second_command = lpm_spawnable_with_registry(&project, &registry.url());
    second_command
        .args(["--json", "rebuild", "--all", "--strict-sandbox"])
        .env("LPM_STORE_VERSION", "v2");

    let first = first_command.spawn().expect("spawn first rebuild");
    let second = second_command.spawn().expect("spawn second rebuild");
    let first_output = first.wait_with_output().expect("wait for first rebuild");
    let second_output = second.wait_with_output().expect("wait for second rebuild");
    assert!(
        first_output.status.success() && second_output.status.success(),
        "concurrent rebuild failed:\nfirst stderr:\n{}\nsecond stderr:\n{}",
        String::from_utf8_lossy(&first_output.stderr),
        String::from_utf8_lossy(&second_output.stderr)
    );

    let executions =
        std::fs::read_to_string(installed_package_dir(&project).join("executions.txt"))
            .expect("the winning lifecycle build must produce executions.txt");
    assert_eq!(
        executions.lines().count(),
        1,
        "the per-key lock must prevent duplicate lifecycle execution"
    );
    let envelopes = [&first_output.stdout, &second_output.stdout]
        .into_iter()
        .map(|stdout| serde_json::from_slice::<serde_json::Value>(stdout).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(
        envelopes
            .iter()
            .map(|value| {
                value["build_cache"]["hits"].as_u64().unwrap()
                    + value["build_cache"]["local_state_hits"].as_u64().unwrap()
            })
            .sum::<u64>(),
        1,
        "one contender must build and the other must reuse its keyed result"
    );
}
