mod support;

#[cfg(unix)]
use std::collections::BTreeSet;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

#[cfg(unix)]
use support::assertions::parse_json_output;
use support::{TempProject, lpm};

#[cfg(unix)]
const ROLLDOWN_VERSION: &str = "1.2.3";
#[cfg(unix)]
const ROLLDOWN_ROOT_TARBALL_URL: &str = "https://registry.npmjs.org/rolldown/-/rolldown-1.2.3.tgz";
#[cfg(unix)]
const ROLLDOWN_ROOT_TARBALL_INTEGRITY: &str = "sha512-rn9wpmxplLf7NLNyCk9FyWh3FM43DbY8jOzCdEPzH7uflhTftRbCEpqi6Ly2osgoU8OwObtmavMbWLaWy4LX7A==";
#[cfg(unix)]
const ROLLDOWN_PLUGINUTILS_TARBALL_URL: &str =
    "https://registry.npmjs.org/@rolldown/pluginutils/-/pluginutils-1.0.1.tgz";
#[cfg(unix)]
const ROLLDOWN_PLUGINUTILS_TARBALL_INTEGRITY: &str = "sha512-2j9bGt5Jh8hj+vPtgzPtl72j0yRxHAyumoo6TNfAjsLB04UtpSvPbPcDcBMxz7n+9CYB0c1GxQFxYRg2jimqGw==";
#[cfg(unix)]
const OXC_TYPES_TARBALL_URL: &str =
    "https://registry.npmjs.org/@oxc-project/types/-/types-0.143.0.tgz";
#[cfg(unix)]
const OXC_TYPES_TARBALL_INTEGRITY: &str = "sha512-u6JZdLBTLotrNC9Vd6vPssINdzcCzleKAH6EJKImQb7GtYvX5keN2dxkoK44stCc4tffE6QQRtZTXVSzsLUlWA==";

#[cfg(unix)]
fn current_bundle_platform() -> &'static str {
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

#[cfg(unix)]
fn normalize_rel_path(path: &std::path::Path) -> String {
    path.components()
        .map(|component| component.as_os_str().to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .join("/")
}

#[cfg(unix)]
fn normalize_test_path(path: &str) -> String {
    path.strip_prefix("/private").unwrap_or(path).to_string()
}

#[cfg(unix)]
fn seeded_rolldown_sidecar_packages_for_version(
    version: &str,
    platform: &str,
) -> Vec<serde_json::Value> {
    if version != ROLLDOWN_VERSION {
        return fake_rolldown_sidecar_packages_for_version(version, platform);
    }

    let (binding_subdir, binding_url, binding_integrity) = match platform {
        "darwin-arm64" => (
            "node_modules/@rolldown/binding-darwin-arm64",
            "https://registry.npmjs.org/@rolldown/binding-darwin-arm64/-/binding-darwin-arm64-1.2.3.tgz",
            "sha512-ieIiibVCp0tX7TLu2cafoNPv8wJyYi01ekXpbf8q2j7F4rGAhhXb/eQh7ge9DRBY78GwmRQtvjZDux7EDbA8kA==",
        ),
        "darwin-x64" => (
            "node_modules/@rolldown/binding-darwin-x64",
            "https://registry.npmjs.org/@rolldown/binding-darwin-x64/-/binding-darwin-x64-1.2.3.tgz",
            "sha512-Zh9tCon19eDXJoihx0rqKhMUlMYqzwj3aPsSuHmI4RWZh62dWUL+DJN4C5YQya5TcQBJU/Fe8+rY0jhXTQITqA==",
        ),
        "linux-x64" => (
            "node_modules/@rolldown/binding-linux-x64-gnu",
            "https://registry.npmjs.org/@rolldown/binding-linux-x64-gnu/-/binding-linux-x64-gnu-1.2.3.tgz",
            "sha512-TytMwF2KVGqP2tgd0I1OY0PAv78dZRAYcF5ssDzjM34SUXCED3uXvSd5+lHoC0bTD6eEdFz7LdQNCO1y0oVk9w==",
        ),
        "linux-arm64" => (
            "node_modules/@rolldown/binding-linux-arm64-gnu",
            "https://registry.npmjs.org/@rolldown/binding-linux-arm64-gnu/-/binding-linux-arm64-gnu-1.2.3.tgz",
            "sha512-TkqEAcmmvH3I/q4114NB4RVt6241Dao48pF45uLcFGrwAaIn0iITgTAKP/dLjbN0R4buJjGb91+UHSoFmpgIWw==",
        ),
        other => panic!("unsupported seeded rolldown platform: {other}"),
    };

    vec![
        serde_json::json!({
            "install_subdir": "",
            "tarball_url": ROLLDOWN_ROOT_TARBALL_URL,
            "tarball_integrity": ROLLDOWN_ROOT_TARBALL_INTEGRITY,
            "tarball_sha256": "test-sha256-root",
        }),
        serde_json::json!({
            "install_subdir": "node_modules/@rolldown/pluginutils",
            "tarball_url": ROLLDOWN_PLUGINUTILS_TARBALL_URL,
            "tarball_integrity": ROLLDOWN_PLUGINUTILS_TARBALL_INTEGRITY,
            "tarball_sha256": "test-sha256-pluginutils",
        }),
        serde_json::json!({
            "install_subdir": "node_modules/@oxc-project/types",
            "tarball_url": OXC_TYPES_TARBALL_URL,
            "tarball_integrity": OXC_TYPES_TARBALL_INTEGRITY,
            "tarball_sha256": "test-sha256-oxc-types",
        }),
        serde_json::json!({
            "install_subdir": binding_subdir,
            "tarball_url": binding_url,
            "tarball_integrity": binding_integrity,
            "tarball_sha256": "test-sha256-binding",
        }),
    ]
}

#[cfg(unix)]
fn fake_rolldown_sidecar_packages_for_version(
    version: &str,
    platform: &str,
) -> Vec<serde_json::Value> {
    let binding_subdir = match platform {
        "darwin-arm64" => "node_modules/@rolldown/binding-darwin-arm64",
        "darwin-x64" => "node_modules/@rolldown/binding-darwin-x64",
        "linux-x64" => "node_modules/@rolldown/binding-linux-x64-gnu",
        "linux-arm64" => "node_modules/@rolldown/binding-linux-arm64-gnu",
        other => panic!("unsupported seeded rolldown platform: {other}"),
    };

    vec![
        serde_json::json!({
            "install_subdir": "",
            "tarball_url": format!("https://example.test/rolldown-{version}.tgz"),
            "tarball_integrity": format!("sha512-root-{version}"),
            "tarball_sha256": "test-sha256-root",
        }),
        serde_json::json!({
            "install_subdir": "node_modules/@rolldown/pluginutils",
            "tarball_url": format!("https://example.test/pluginutils-{version}.tgz"),
            "tarball_integrity": format!("sha512-pluginutils-{version}"),
            "tarball_sha256": "test-sha256-pluginutils",
        }),
        serde_json::json!({
            "install_subdir": "node_modules/@oxc-project/types",
            "tarball_url": format!("https://example.test/types-{version}.tgz"),
            "tarball_integrity": format!("sha512-types-{version}"),
            "tarball_sha256": "test-sha256-oxc-types",
        }),
        serde_json::json!({
            "install_subdir": binding_subdir,
            "tarball_url": format!("https://example.test/binding-{platform}-{version}.tgz"),
            "tarball_integrity": format!("sha512-binding-{platform}-{version}"),
            "tarball_sha256": "test-sha256-binding",
        }),
    ]
}

#[cfg(unix)]
fn hash_directory_tree_for_test(root: &std::path::Path) -> String {
    use sha2::Digest;
    use std::io::Read;

    fn collect_files(
        root: &std::path::Path,
        current: &std::path::Path,
        rel_files: &mut Vec<std::path::PathBuf>,
    ) {
        for entry in std::fs::read_dir(current).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            let file_type = entry.file_type().unwrap();
            if file_type.is_dir() {
                collect_files(root, &path, rel_files);
            } else {
                let rel = path.strip_prefix(root).unwrap().to_path_buf();
                if rel.as_path() == std::path::Path::new(".lpm-engine.json") {
                    continue;
                }
                rel_files.push(rel);
            }
        }
    }

    let mut rel_files = Vec::new();
    collect_files(root, root, &mut rel_files);
    rel_files.sort();

    let mut hasher = sha2::Sha256::new();
    for rel in rel_files {
        hasher.update(normalize_rel_path(&rel).as_bytes());
        hasher.update([0]);
        let mut file = std::fs::File::open(root.join(&rel)).unwrap();
        let mut buf = [0_u8; 64 * 1024];
        loop {
            let read = file.read(&mut buf).unwrap();
            if read == 0 {
                break;
            }
            hasher.update(&buf[..read]);
        }
        hasher.update([0]);
    }

    format!("{:x}", hasher.finalize())
}

#[cfg(unix)]
fn write_unix_executable(path: &std::path::Path, content: &str) {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("failed to create executable parent dir");
    }
    std::fs::write(path, content).expect("failed to write executable file");
    let mut perms = std::fs::metadata(path)
        .expect("failed to stat executable file")
        .permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(path, perms).expect("failed to chmod executable file");
}

#[cfg(unix)]
fn seed_fake_rolldown_engine(project: &TempProject, marker_file: &std::path::Path) {
    seed_fake_rolldown_engine_version(project, marker_file, ROLLDOWN_VERSION, false);
}

#[cfg(unix)]
fn seed_fake_rolldown_engine_version(
    project: &TempProject,
    marker_file: &std::path::Path,
    version: &str,
    approve: bool,
) {
    let platform = current_bundle_platform();
    let engine_dir = project
        .home()
        .join(".lpm")
        .join("engines")
        .join("rolldown")
        .join(version)
        .join(platform);
    let entry_path = engine_dir.join("bin/cli.mjs");
    let marker_literal = serde_json::to_string(&marker_file.to_string_lossy().into_owned())
        .expect("failed to serialize marker path");
    let script = format!(
        "#!/usr/bin/env node\nimport {{ appendFileSync }} from 'node:fs'\nconst line = JSON.stringify({{ cwd: process.cwd(), args: process.argv.slice(2) }})\nappendFileSync({marker_literal}, `${{line}}\\n`)\n"
    );

    write_unix_executable(&entry_path, &script);
    std::fs::write(
        engine_dir.join("package.json"),
        format!(
            r#"{{
  "name": "rolldown",
  "version": "{version}",
  "bin": {{ "rolldown": "./bin/cli.mjs" }}
}}"#
        ),
    )
    .expect("failed to write rolldown package.json");

    let layout_sha256 = hash_directory_tree_for_test(&engine_dir);
    let sidecar = serde_json::json!({
        "schema_version": 2,
        "engine_name": "rolldown",
        "version": version,
        "platform": platform,
        "entry_rel_path": "bin/cli.mjs",
        "packages": seeded_rolldown_sidecar_packages_for_version(version, platform),
        "layout_sha256": layout_sha256,
        "verified_at_unix": 0,
    });
    std::fs::write(
        engine_dir.join(".lpm-engine.json"),
        serde_json::to_vec_pretty(&sidecar).expect("failed to serialize rolldown sidecar"),
    )
    .expect("failed to write rolldown sidecar");

    if approve {
        let packages: Vec<serde_json::Value> =
            seeded_rolldown_sidecar_packages_for_version(version, platform)
                .into_iter()
                .map(|mut package| {
                    package
                        .as_object_mut()
                        .expect("package metadata must be object")
                        .remove("tarball_sha256");
                    package
                })
                .collect();
        let mut cache = serde_json::json!({
            "engines": {
                "rolldown": {
                    "selected": {},
                    "assets": {},
                },
            },
        });
        cache["engines"]["rolldown"]["selected"]
            .as_object_mut()
            .expect("selected cache must be object")
            .insert(platform.to_string(), serde_json::json!(version));
        let mut platform_assets = serde_json::Map::new();
        platform_assets.insert(
            platform.to_string(),
            serde_json::json!({
                "entry_rel_path": "bin/cli.mjs",
                "packages": packages,
            }),
        );
        cache["engines"]["rolldown"]["assets"]
            .as_object_mut()
            .expect("assets cache must be object")
            .insert(
                version.to_string(),
                serde_json::Value::Object(platform_assets),
            );
        std::fs::write(
            project
                .home()
                .join(".lpm")
                .join("engines")
                .join(".version-cache.json"),
            serde_json::to_vec_pretty(&cache).expect("failed to serialize engine cache"),
        )
        .expect("failed to write engine version cache");
    }
}

#[cfg(unix)]
fn read_marker_lines(path: &std::path::Path) -> Vec<serde_json::Value> {
    let text = std::fs::read_to_string(path).expect("failed to read marker file");
    text.lines()
        .map(|line| serde_json::from_str(line).expect("invalid marker json"))
        .collect()
}

#[cfg(unix)]
#[test]
fn bundle_uses_seeded_managed_rolldown_engine_with_lpm_flags() {
    let project = TempProject::empty(
        r#"{
  "name": "bundle-test-project",
  "version": "1.0.0"
}"#,
    );
    project.write_file("src/index.js", "export const answer = 42\n");

    let marker_file = project.home().join("bundle-single.log");
    seed_fake_rolldown_engine(&project, &marker_file);

    let output = lpm(&project)
        .args([
            "bundle",
            "--entry",
            "src/index.js",
            "--out-dir",
            "dist",
            "--format",
            "esm",
            "--platform",
            "browser",
            "--minify",
            "--sourcemap",
        ])
        .output()
        .expect("failed to run lpm bundle");

    assert!(
        output.status.success(),
        "bundle must succeed, got: {}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr),
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("› Bundling with Rolldown 1.2.3"),
        "bundle must use a slim phase line, got:\n{stderr}"
    );
    assert!(
        stderr.contains("✓ Done · bundled in "),
        "bundle must report a slim timed completion line, got:\n{stderr}"
    );
    assert!(
        !stderr.contains('●') && !stderr.contains('│'),
        "bundle output must not use cliclack gutter output, got:\n{stderr}"
    );

    let invocations = read_marker_lines(&marker_file);
    assert_eq!(invocations.len(), 1, "expected one rolldown invocation");
    let invocation = &invocations[0];
    assert_eq!(
        invocation["cwd"].as_str().map(normalize_test_path),
        Some(normalize_test_path(
            project.path().to_str().expect("project path must be utf8"),
        ))
    );
    assert_eq!(
        invocation["args"],
        serde_json::json!([
            "--input",
            "src/index.js",
            "--dir",
            "dist",
            "--format",
            "esm",
            "--platform",
            "browser",
            "--minify",
            "--sourcemap"
        ])
    );
}

#[cfg(unix)]
#[test]
fn bundle_uses_approved_rolldown_pin_from_lpm_json() {
    let project = TempProject::empty(
        r#"{
  "name": "bundle-test-project",
  "version": "1.0.0"
}"#,
    );
    project.write_file(
        "lpm.json",
        r#"{
  "tools": {
    "rolldown": "1.1.2"
  }
}"#,
    );
    project.write_file("src/index.js", "export const answer = 42\n");

    let marker_file = project.home().join("bundle-pinned.log");
    seed_fake_rolldown_engine_version(&project, &marker_file, "1.1.2", true);

    let output = lpm(&project)
        .args(["bundle", "--entry", "src/index.js", "--out-dir", "dist"])
        .output()
        .expect("failed to run pinned lpm bundle");

    assert!(
        output.status.success(),
        "pinned bundle must succeed, got: {}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr),
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("› Bundling with Rolldown 1.1.2"),
        "bundle must announce the pinned approved rolldown version, got:\n{stderr}"
    );

    let invocations = read_marker_lines(&marker_file);
    assert_eq!(invocations.len(), 1, "expected one rolldown invocation");
}

#[cfg(unix)]
#[test]
fn bundle_rejects_unapproved_rolldown_pin_before_running_node() {
    let project = TempProject::empty(
        r#"{
  "name": "bundle-test-project",
  "version": "1.0.0"
}"#,
    );
    project.write_file(
        "lpm.json",
        r#"{
  "tools": {
    "rolldown": "9.9.9"
  }
}"#,
    );
    project.write_file("src/index.js", "export const answer = 42\n");

    let output = lpm(&project)
        .args(["bundle", "--entry", "src/index.js", "--out-dir", "dist"])
        .output()
        .expect("failed to run unapproved pinned lpm bundle");

    assert!(
        !output.status.success(),
        "unapproved rolldown pin must fail, got success\nstderr:\n{}",
        String::from_utf8_lossy(&output.stderr),
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("tools.rolldown")
            && stderr.contains("not approved")
            && stderr.contains("lpm plugin update rolldown"),
        "bundle must clearly explain how to approve a pinned rolldown version, got:\n{stderr}"
    );
}

#[cfg(unix)]
#[test]
fn bundle_workspace_human_reports_slim_summary() {
    let project = TempProject::from_fixture("workspace-monorepo");
    for member in ["packages/utils", "packages/core", "packages/app"] {
        project.write_file(&format!("{member}/src/index.js"), "export default 1\n");
    }

    let marker_file = project.home().join("bundle-workspace-human.log");
    seed_fake_rolldown_engine(&project, &marker_file);

    let output = lpm(&project)
        .args([
            "bundle",
            "--all",
            "--entry",
            "src/index.js",
            "--out-dir",
            "dist",
        ])
        .output()
        .expect("failed to run lpm bundle --all");

    assert!(
        output.status.success(),
        "workspace bundle must succeed, got: {}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr),
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("✓ bundle passed in 3 packages in "),
        "workspace bundle must report a slim timed summary, got:\n{stderr}"
    );
    assert!(
        !stderr.contains('●') && !stderr.contains('│'),
        "workspace bundle output must not use cliclack gutter output, got:\n{stderr}"
    );

    let invocations = read_marker_lines(&marker_file);
    assert_eq!(
        invocations.len(),
        3,
        "expected one rolldown invocation per member"
    );
}

#[test]
fn bundle_filter_typo_without_fail_flag_uses_slim_warning() {
    let project = TempProject::from_fixture("workspace-monorepo");

    let output = lpm(&project)
        .args([
            "bundle",
            "--filter",
            "this-package-does-not-exist",
            "--entry",
            "src/index.js",
        ])
        .output()
        .expect("failed to run lpm bundle");

    assert!(
        output.status.success(),
        "empty-match without --fail-if-no-match must exit 0, got: {}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr),
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("No packages matched"),
        "expected slim empty-match warning, got:\n{stderr}"
    );
    assert!(
        !stderr.contains('●') && !stderr.contains('│'),
        "empty-match bundle output must not use cliclack gutter output, got:\n{stderr}"
    );
}

#[cfg(unix)]
#[test]
fn bundle_workspace_json_emits_valid_envelope_per_member() {
    let project = TempProject::from_fixture("workspace-monorepo");
    for member in ["packages/utils", "packages/core", "packages/app"] {
        project.write_file(&format!("{member}/src/index.js"), "export default 1\n");
    }

    let marker_file = project.home().join("bundle-workspace.log");
    seed_fake_rolldown_engine(&project, &marker_file);

    let output = lpm(&project)
        .args([
            "bundle",
            "--all",
            "--json",
            "--entry",
            "src/index.js",
            "--out-dir",
            "dist",
        ])
        .output()
        .expect("failed to run lpm bundle --all --json");

    assert!(
        output.status.success(),
        "workspace bundle must succeed, got: {}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr),
    );

    let json = parse_json_output(&output.stdout);
    assert_eq!(json["success"], serde_json::json!(true));
    assert_eq!(json["packages"], serde_json::json!(3));
    assert_eq!(json["succeeded"], serde_json::json!(3));
    assert_eq!(json["failed"], serde_json::json!(0));

    let members = json["members"].as_array().expect("members must be array");
    let member_names: BTreeSet<String> = members
        .iter()
        .map(|member| {
            assert_eq!(member["success"], serde_json::json!(true));
            member["name"]
                .as_str()
                .expect("member name must be string")
                .to_string()
        })
        .collect();
    assert_eq!(
        member_names,
        BTreeSet::from([
            "@test/app".to_string(),
            "@test/core".to_string(),
            "@test/utils".to_string(),
        ])
    );

    let invocations = read_marker_lines(&marker_file);
    let invoked_dirs: BTreeSet<String> = invocations
        .iter()
        .map(|value| normalize_test_path(value["cwd"].as_str().expect("cwd must be string")))
        .collect();
    let expected_dirs: BTreeSet<String> = ["packages/utils", "packages/core", "packages/app"]
        .iter()
        .map(|rel| {
            normalize_test_path(
                project
                    .path()
                    .join(rel)
                    .to_str()
                    .expect("member dir path must be utf8"),
            )
        })
        .collect();
    assert_eq!(invoked_dirs, expected_dirs);
}

#[test]
fn bundle_filter_typo_with_fail_flag_exits_nonzero() {
    let project = TempProject::from_fixture("workspace-monorepo");

    let output = lpm(&project)
        .args([
            "bundle",
            "--filter",
            "this-package-does-not-exist",
            "--fail-if-no-match",
            "--entry",
            "src/index.js",
        ])
        .output()
        .expect("failed to run lpm bundle");

    assert!(
        !output.status.success(),
        "empty-match with --fail-if-no-match must exit non-zero, got: 0\nstderr:\n{}",
        String::from_utf8_lossy(&output.stderr),
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("no workspace packages matched the filter")
            || stderr.contains("--fail-if-no-match"),
        "expected error message mentioning the empty-match condition, got:\n{stderr}"
    );
}
