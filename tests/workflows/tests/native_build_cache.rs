//! Workflow coverage for dependency lifecycle-build artifact reuse.

#![cfg(any(target_os = "macos", target_os = "linux"))]

mod support;

use support::mock_registry::MockRegistry;
use support::{TempProject, lpm_spawnable_with_registry, lpm_with_registry};

const PACKAGE_NAME: &str = "esbuild";
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
                    "postinstall": "node install.js"
                }
            }),
            &[("install.js", BUILD_SCRIPT.as_bytes())],
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
async fn custom_lifecycle_environment_change_invalidates_cached_output() {
    if !node_available() {
        eprintln!("skipping: node is required for the native build-cache workflow");
        return;
    }

    let registry = MockRegistry::start().await;
    let script = br#"
const fs = require('fs');
fs.writeFileSync('native-output.txt', process.env.LPM_NATIVE_TEST_INPUT);
"#;
    registry
        .with_manifest_package(
            serde_json::json!({
                "name": PACKAGE_NAME,
                "version": PACKAGE_VERSION,
                "scripts": {
                    "postinstall": "node install.js"
                }
            }),
            &[("install.js", script)],
        )
        .await;
    let project = TempProject::empty(&project_manifest());
    let install = lpm_with_registry(&project, &registry.url())
        .arg("install")
        .env("LPM_STORE_VERSION", "v2")
        .output()
        .expect("initial install");
    assert!(install.status.success());

    for value in ["first", "second"] {
        let rebuild = lpm_with_registry(&project, &registry.url())
            .args(["--json", "rebuild", "--all", "--strict-sandbox"])
            .env("LPM_STORE_VERSION", "v2")
            .env("LPM_NATIVE_TEST_INPUT", value)
            .output()
            .expect("native rebuild");
        assert!(
            rebuild.status.success(),
            "rebuild failed for {value}: {}",
            String::from_utf8_lossy(&rebuild.stderr)
        );
        let envelope: serde_json::Value =
            serde_json::from_slice(&rebuild.stdout).expect("native rebuild stdout must be JSON");
        assert_eq!(
            envelope["build_cache"]["misses"],
            1,
            "{value} must execute under its own cache key; envelope: {envelope}; stderr: {}",
            String::from_utf8_lossy(&rebuild.stderr)
        );
    }

    assert_eq!(
        std::fs::read_to_string(installed_package_dir(&project).join("native-output.txt"))
            .expect("second build output"),
        "second"
    );
    assert_eq!(
        std::fs::read_dir(project.store_dir().join("v2/builds"))
            .expect("build artifacts")
            .count(),
        2,
        "each visible custom environment must have a distinct cache key"
    );
}

#[tokio::test]
async fn native_toolchain_snapshot_persists_across_rebuild_processes() {
    if !node_available() {
        eprintln!("skipping: node is required for the native build-cache workflow");
        return;
    }

    let registry = MockRegistry::start().await;
    registry
        .with_manifest_package(
            serde_json::json!({
                "name": "sharp",
                "version": PACKAGE_VERSION,
                "scripts": {
                    "postinstall": "node install/check"
                }
            }),
            &[(
                "install/check",
                b"require('fs').writeFileSync('native-output.txt', 'built');",
            )],
        )
        .await;
    let project = TempProject::empty(&format!(
        r#"{{
  "name": "native-toolchain-snapshot-workflow",
  "version": "1.0.0",
  "dependencies": {{
    "sharp": "{PACKAGE_VERSION}"
  }}
}}"#
    ));
    let install = lpm_with_registry(&project, &registry.url())
        .arg("install")
        .env("LPM_STORE_VERSION", "v2")
        .output()
        .expect("initial install");
    assert!(
        install.status.success(),
        "initial install failed: {}",
        String::from_utf8_lossy(&install.stderr)
    );

    let first_rebuild = lpm_with_registry(&project, &registry.url())
        .args(["rebuild", "--all", "--strict-sandbox"])
        .env("LPM_STORE_VERSION", "v2")
        .output()
        .expect("first native rebuild");
    assert!(
        first_rebuild.status.success(),
        "first rebuild failed: {}",
        String::from_utf8_lossy(&first_rebuild.stderr)
    );

    let snapshot_dir = project.cache_dir().join("metadata/native-toolchains/v1");
    let snapshots = std::fs::read_dir(&snapshot_dir)
        .expect("native toolchain snapshot directory")
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "json")
        })
        .collect::<Vec<_>>();
    assert_eq!(snapshots.len(), 1);
    let first_snapshot: serde_json::Value = serde_json::from_slice(
        &std::fs::read(&snapshots[0]).expect("persisted native toolchain snapshot"),
    )
    .expect("native toolchain snapshot must be valid JSON");
    assert_eq!(first_snapshot["schema"], 1);

    let second_rebuild = lpm_with_registry(&project, &registry.url())
        .args(["rebuild", "--all", "--strict-sandbox"])
        .env("LPM_STORE_VERSION", "v2")
        .output()
        .expect("second native rebuild");
    assert!(
        second_rebuild.status.success(),
        "second rebuild failed: {}",
        String::from_utf8_lossy(&second_rebuild.stderr)
    );

    let second_snapshot: serde_json::Value = serde_json::from_slice(
        &std::fs::read(&snapshots[0]).expect("native toolchain snapshot after second rebuild"),
    )
    .expect("native toolchain snapshot must remain valid JSON");
    assert_eq!(second_snapshot["schema"], 1);
    assert_eq!(second_snapshot["base_key"], first_snapshot["base_key"]);
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
                    "postinstall": "node install.js"
                }
            }),
            &[("install.js", script)],
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

#[tokio::test]
async fn concurrent_native_rebuilds_with_different_keys_serialize_shared_package_mutation() {
    if !node_available() {
        eprintln!("skipping: node is required for the native build-cache workflow");
        return;
    }

    let registry = MockRegistry::start().await;
    let script = br#"
const fs = require('fs');
const label = process.env.CFLAGS;
fs.writeFileSync('active-build.txt', label);
Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 6000);
const active = fs.existsSync('active-build.txt')
  ? fs.readFileSync('active-build.txt', 'utf8')
  : '<missing>';
if (active !== label) {
  throw new Error(`shared package tree was mutated by ${active} while ${label} was building`);
}
fs.rmSync('active-build.txt');
fs.writeFileSync('native-output.txt', label);
"#;
    registry
        .with_manifest_package(
            serde_json::json!({
                "name": PACKAGE_NAME,
                "version": PACKAGE_VERSION,
                "scripts": {
                    "postinstall": "node install.js"
                }
            }),
            &[("install.js", script)],
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
        .env("LPM_STORE_VERSION", "v2")
        .env("CFLAGS", "build-a");
    let first = first_command.spawn().expect("spawn first rebuild");
    let active_path = installed_package_dir(&project).join("active-build.txt");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while !active_path.is_file() && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    assert!(
        active_path.is_file(),
        "first build did not enter its lifecycle script"
    );
    let mut second_command = lpm_spawnable_with_registry(&project, &registry.url());
    second_command
        .args(["--json", "rebuild", "--all", "--strict-sandbox"])
        .env("LPM_STORE_VERSION", "v2")
        .env("CFLAGS", "build-b");
    let second = second_command.spawn().expect("spawn second rebuild");
    let first_output = first.wait_with_output().expect("wait for first rebuild");
    let second_output = second.wait_with_output().expect("wait for second rebuild");

    assert!(
        first_output.status.success() && second_output.status.success(),
        "different-key rebuilds raced on one package tree:\nfirst stderr:\n{}\nsecond stderr:\n{}",
        String::from_utf8_lossy(&first_output.stderr),
        String::from_utf8_lossy(&second_output.stderr)
    );
    let mut artifact_outputs = std::fs::read_dir(project.store_dir().join("v2/builds"))
        .expect("build artifacts")
        .map(|entry| {
            std::fs::read_to_string(
                entry
                    .expect("build artifact entry")
                    .path()
                    .join("package/native-output.txt"),
            )
            .expect("each key must preserve its own native output")
        })
        .collect::<Vec<_>>();
    artifact_outputs.sort_unstable();
    assert_eq!(artifact_outputs, ["build-a", "build-b"]);
}
