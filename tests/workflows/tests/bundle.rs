mod support;

#[cfg(unix)]
use std::collections::BTreeSet;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

#[cfg(unix)]
use support::assertions::parse_json_output;
use support::{TempProject, lpm};

#[cfg(unix)]
const ROLLDOWN_VERSION: &str = "1.2.4";
#[cfg(unix)]
const ROLLDOWN_ROOT_TARBALL_URL: &str = "https://registry.npmjs.org/rolldown/-/rolldown-1.2.4.tgz";
#[cfg(unix)]
const ROLLDOWN_ROOT_TARBALL_INTEGRITY: &str = "sha512-rSr7irW0K7QRWzjdJXqZowkcRdDtjRduh43rBltnVKd0VFq839l1lJoDvGJb6gl7+4rTTCrPWu+YfujUL8Ug7w==";
#[cfg(unix)]
const ROLLDOWN_PLUGINUTILS_TARBALL_URL: &str =
    "https://registry.npmjs.org/@rolldown/pluginutils/-/pluginutils-1.0.1.tgz";
#[cfg(unix)]
const ROLLDOWN_PLUGINUTILS_TARBALL_INTEGRITY: &str = "sha512-2j9bGt5Jh8hj+vPtgzPtl72j0yRxHAyumoo6TNfAjsLB04UtpSvPbPcDcBMxz7n+9CYB0c1GxQFxYRg2jimqGw==";
#[cfg(unix)]
const OXC_TYPES_TARBALL_URL: &str =
    "https://registry.npmjs.org/@oxc-project/types/-/types-0.144.0.tgz";
#[cfg(unix)]
const OXC_TYPES_TARBALL_INTEGRITY: &str = "sha512-nuhZIOLuI6TFQ32I/WnUx+SCPY7SdSKwgnFHydAuoS1+Z4BRcaP+RRJmGzl9lw+0OFF7UmaESf7KQRXaNLHypg==";

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
            "https://registry.npmjs.org/@rolldown/binding-darwin-arm64/-/binding-darwin-arm64-1.2.4.tgz",
            "sha512-Dc5mPD8F5F/FS8i01syd7FTF6yB2fVthH/TRkjwJkzUK6EpoxHtqvZQP5Zwq80/5z19TWYHIg1KOHboCgVx/aQ==",
        ),
        "darwin-x64" => (
            "node_modules/@rolldown/binding-darwin-x64",
            "https://registry.npmjs.org/@rolldown/binding-darwin-x64/-/binding-darwin-x64-1.2.4.tgz",
            "sha512-fpDm4oBo6SqLvWUYCmFhdde3U9KH2fRNNMeAnAPAIwxRL345xutL0EtEUcuoxsoazdJGv/MuDBQHlCDrtbvqOg==",
        ),
        "linux-x64" => (
            "node_modules/@rolldown/binding-linux-x64-gnu",
            "https://registry.npmjs.org/@rolldown/binding-linux-x64-gnu/-/binding-linux-x64-gnu-1.2.4.tgz",
            "sha512-4/GyVjmhR+Tc6HLJvwc1sOhPqAZtySiSMesOZyX6JQ5XBxoTDEMKQzvo07NIK6nTon/SivlZqvhzvuVBNQhObQ==",
        ),
        "linux-arm64" => (
            "node_modules/@rolldown/binding-linux-arm64-gnu",
            "https://registry.npmjs.org/@rolldown/binding-linux-arm64-gnu/-/binding-linux-arm64-gnu-1.2.4.tgz",
            "sha512-tIP06BeD9EqvECBrPZ+sqdPlYrT+aYaAiu1wYziVx5elRK/ftm33JxVDy2bXGbr6J0CrtirCkR87/X5a2euEng==",
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
        stderr.contains("› Bundling with Rolldown 1.2.4"),
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

#[cfg(unix)]
fn replace_seeded_rolldown_script(project: &TempProject, version: &str, script: &str) {
    let directory = project
        .home()
        .join(".lpm/engines/rolldown")
        .join(version)
        .join(current_bundle_platform());
    write_unix_executable(&directory.join("bin/cli.mjs"), script);
    let sidecar = directory.join(".lpm-engine.json");
    let mut value: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&sidecar).unwrap()).unwrap();
    value["layout_sha256"] = serde_json::json!(hash_directory_tree_for_test(&directory));
    std::fs::write(sidecar, serde_json::to_vec(&value).unwrap()).unwrap();
}

#[cfg(unix)]
#[test]
fn bundle_single_json_keeps_one_envelope_and_child_failure_code() {
    let project = TempProject::empty(r#"{"name":"bundle-json"}"#);
    seed_fake_rolldown_engine(&project, &project.home().join("unused"));
    replace_seeded_rolldown_script(
        &project,
        ROLLDOWN_VERSION,
        "console.log('bundle output');console.error('bundle error');process.exit(7);",
    );
    let output = lpm(&project).args(["bundle", "--json"]).output().unwrap();
    assert_eq!(output.status.code(), Some(7));
    let value: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("one JSON envelope");
    assert_eq!(value["members"][0]["stdout"], "bundle output\n");
    insta::assert_json_snapshot!("bundle_single_failure", value, {".duration_ms" => 0,".members[].duration_ms" => 0});
}

#[cfg(unix)]
#[test]
fn bundle_json_caps_multibyte_diagnostics_without_panicking() {
    let project = TempProject::empty(r#"{"name":"bundle-large","workspaces":["packages/*"]}"#);
    project.write_file("packages/a/package.json", r#"{"name":"a"}"#);
    seed_fake_rolldown_engine(&project, &project.home().join("unused"));
    replace_seeded_rolldown_script(
        &project,
        ROLLDOWN_VERSION,
        "import {writeSync} from 'node:fs';const chunk='€'.repeat(4096);for(let i=0;i<1024;i++)writeSync(1,chunk);process.exit(7);",
    );
    let output = lpm(&project)
        .args(["bundle", "--all", "--json"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    let value: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("one bounded JSON envelope");
    let stdout = value["members"][0]["stdout"].as_str().unwrap();
    assert!(stdout.len() <= 10 * 1024 * 1024 + 100);
    assert!(stdout.contains("truncated"));
}

#[cfg(unix)]
#[test]
fn bundle_workspace_preserves_root_and_member_pins_from_each_cwd() {
    let project = TempProject::from_fixture("workspace-monorepo");
    project.write_file(
        "lpm.json",
        &serde_json::json!({"tools":{"rolldown":ROLLDOWN_VERSION}}).to_string(),
    );
    project.write_file(
        "packages/utils/lpm.json",
        r#"{"tools":{"rolldown":"1.1.2"}}"#,
    );
    for (version, approve) in [(ROLLDOWN_VERSION, false), ("1.1.2", true)] {
        seed_fake_rolldown_engine_version(
            &project,
            &project.home().join("unused"),
            version,
            approve,
        );
        replace_seeded_rolldown_script(
            &project,
            version,
            &format!(
                "import {{writeFileSync}} from 'node:fs';writeFileSync('selected-version','{version}');"
            ),
        );
    }
    for cwd in [
        project.path().to_path_buf(),
        project.path().join("packages/utils"),
    ] {
        let output = lpm(&project)
            .current_dir(cwd)
            .args(["bundle", "--all", "--json"])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stdout)
        );
        for (member, expected) in [
            ("utils", "1.1.2"),
            ("core", ROLLDOWN_VERSION),
            ("app", ROLLDOWN_VERSION),
        ] {
            assert_eq!(
                project.read_file(&format!("packages/{member}/selected-version")),
                expected
            );
        }
    }
}

#[cfg(unix)]
#[test]
fn bundle_workspace_processes_can_reach_a_shared_barrier_concurrently() {
    let count = std::thread::available_parallelism()
        .map_or(1, |value| value.get())
        .min(4);
    if count < 2 {
        return;
    }
    let project = TempProject::empty(r#"{"name":"bundle-parallel","workspaces":["packages/*"]}"#);
    for i in 0..count {
        project.write_file(
            &format!("packages/p{i}/package.json"),
            &serde_json::json!({"name":format!("p{i}")}).to_string(),
        );
    }
    seed_fake_rolldown_engine(&project, &project.home().join("unused"));
    let gate = serde_json::to_string(&project.path().join("gate")).unwrap();
    replace_seeded_rolldown_script(
        &project,
        ROLLDOWN_VERSION,
        &format!(
            "import fs from 'node:fs';fs.mkdirSync({gate},{{recursive:true}});fs.writeFileSync({gate}+'/'+process.pid,'');const started=Date.now();const timer=setInterval(()=>{{if(fs.readdirSync({gate}).length==={count}){{clearInterval(timer)}}else if(Date.now()-started>3000)process.exit(7)}},10);"
        ),
    );
    let output = lpm(&project)
        .args(["bundle", "--all", "--json"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "processes could not run concurrently: {}",
        String::from_utf8_lossy(&output.stdout)
    );
}

#[cfg(unix)]
#[test]
fn bundle_uses_installed_node_ranges_without_selecting_an_older_prefix() {
    let project = TempProject::empty(r#"{"name":"bundle-runtime"}"#);
    seed_fake_rolldown_engine(&project, &project.home().join("unused"));
    for version in ["22.5.0", "22.5.1", "22.8.0", "24.0.0"] {
        write_unix_executable(
            &project
                .home()
                .join(".lpm/runtimes/node")
                .join(version)
                .join("bin/node"),
            &format!("#!/bin/sh\nprintf '{version}' > runtime-version\n"),
        );
    }
    let mut selections = Vec::new();
    let mut expected_selections = Vec::new();
    for (spec, expected) in [
        ("^22.5.0", "22.8.0"),
        ("~22.5.0", "22.5.1"),
        (">=22.5.0 <24", "22.8.0"),
        ("22.x", "22.8.0"),
        ("=22.5.0", "22.5.0"),
    ] {
        project.write_file(
            "lpm.json",
            &serde_json::json!({"runtime":{"node":spec}}).to_string(),
        );
        project.write_file("runtime-version", "not selected");
        let output = lpm(&project).arg("bundle").output().unwrap();
        assert!(
            output.status.success(),
            "{spec}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        selections.push((spec, project.read_file("runtime-version")));
        expected_selections.push((spec, expected.to_string()));
    }
    assert_eq!(selections, expected_selections);
}

#[cfg(unix)]
#[test]
fn bundle_does_not_run_node_from_an_unrelated_ancestor_project() {
    let outer = TempProject::empty(r#"{"name":"outer"}"#);
    outer.write_file("nested/package.json", r#"{"name":"nested"}"#);
    seed_fake_rolldown_engine(&outer, &outer.home().join("used-engine"));
    write_unix_executable(
        &outer.path().join("node_modules/.bin/node"),
        "#!/bin/sh\necho escaped > escaped\nexit 7\n",
    );
    let output = lpm(&outer)
        .current_dir(outer.path().join("nested"))
        .arg("bundle")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "unrelated parent node reached bundle: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!outer.file_exists("nested/escaped"));
    assert!(outer.home().join("used-engine").is_file());
}

#[cfg(unix)]
#[test]
fn bundle_workspace_inherits_node_but_keeps_member_overrides() {
    let project = TempProject::empty(r#"{"name":"root","workspaces":["packages/*"]}"#);
    project.write_file("lpm.json", r#"{"runtime":{"node":"22.0.0"}}"#);
    for name in ["a", "b"] {
        project.write_file(
            &format!("packages/{name}/package.json"),
            &serde_json::json!({"name":name}).to_string(),
        );
    }
    project.write_file("packages/b/lpm.json", r#"{"runtime":{"node":"24.0.0"}}"#);
    seed_fake_rolldown_engine(&project, &project.home().join("unused"));
    for version in ["22.0.0", "24.0.0"] {
        write_unix_executable(
            &project
                .home()
                .join(".lpm/runtimes/node")
                .join(version)
                .join("bin/node"),
            &format!("#!/bin/sh\nprintf '{version}' > runtime-version\n"),
        );
    }
    let output = lpm(&project).args(["bundle", "--all"]).output().unwrap();
    assert!(output.status.success());
    assert_eq!(project.read_file("packages/a/runtime-version"), "22.0.0");
    assert_eq!(project.read_file("packages/b/runtime-version"), "24.0.0");
}

#[cfg(unix)]
#[test]
fn bundle_starts_ready_members_without_waiting_for_a_full_chunk() {
    let limit = std::thread::available_parallelism().map_or(4, |n| n.get());
    if limit < 2 {
        return;
    }
    let project = TempProject::empty(r#"{"name":"bundle-ready","workspaces":["packages/*"]}"#);
    for i in 0..=limit {
        project.write_file(
            &format!("packages/p{i:04}/package.json"),
            &serde_json::json!({"name":format!("p{i:04}")}).to_string(),
        );
    }
    seed_fake_rolldown_engine(&project, &project.home().join("unused"));
    write_unix_executable(
        &project.path().join("node_modules/.bin/node"),
        "#!/bin/sh\nname=${PWD##*/}\nif [ \"$name\" = p0000 ]; then\n count=0\n while [ ! -f \"$BUNDLE_GATE\" ]; do\n  count=$((count + 1))\n  if [ \"$count\" -gt 300 ]; then exit 7; fi\n  sleep 0.01\n done\nfi\nif [ \"$name\" = \"$BUNDLE_LAST\" ]; then printf x > \"$BUNDLE_GATE\"; fi\n",
    );
    let output = lpm(&project)
        .env("BUNDLE_GATE", project.path().join("ready"))
        .env("BUNDLE_LAST", format!("p{limit:04}"))
        .args(["bundle", "--all", "--json"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "ready member remained behind a chunk barrier: {}",
        String::from_utf8_lossy(&output.stdout)
    );
}

#[cfg(unix)]
#[test]
fn bundle_watch_false_is_a_finite_workspace_run() {
    let project = TempProject::from_fixture("workspace-monorepo");
    seed_fake_rolldown_engine(&project, &project.home().join("calls"));
    for flag in ["--watch=false", "-w=false"] {
        let output = lpm(&project)
            .args(["bundle", "--all", "--json", "--", flag])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "disabled watch rejected: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[cfg(unix)]
#[test]
fn bundle_watch_rejects_json_before_starting_the_engine() {
    let project = TempProject::empty(r#"{"name":"watch-json"}"#);
    let marker = project.home().join("calls");
    seed_fake_rolldown_engine(&project, &marker);
    let output = lpm(&project)
        .args(["bundle", "--json", "--", "--watch"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(!marker.exists());
}

#[cfg(unix)]
fn assert_bundle_stop(args: &[&str], workspace: bool, json: bool) {
    use std::os::unix::process::CommandExt;
    use std::time::{Duration, Instant};
    let project = TempProject::empty(r#"{"name":"bundle-stop"}"#);
    if workspace {
        project.write_file(
            "package.json",
            r#"{"name":"root","workspaces":["packages/*"]}"#,
        );
        project.write_file("packages/a/package.json", r#"{"name":"a"}"#);
        project.write_file(
            "packages/b/package.json",
            r#"{"name":"b","dependencies":{"a":"workspace:*"}}"#,
        );
    }
    seed_fake_rolldown_engine(&project, &project.home().join("unused"));
    replace_seeded_rolldown_script(
        &project,
        ROLLDOWN_VERSION,
        "import {writeFileSync} from 'node:fs';writeFileSync('started','yes');import {spawn} from 'node:child_process';spawn(process.execPath,['-e',\"setInterval(()=>require('fs').appendFileSync(process.env.BUNDLE_HEARTBEAT,'x'),20)\"],{stdio:'inherit'});setInterval(()=>{},1000);",
    );
    let mut command = support::lpm_spawnable(&project);
    command
        .args(args)
        .env("BUNDLE_HEARTBEAT", project.path().join("heartbeat"))
        .process_group(0)
        .stdout(std::fs::File::create(project.path().join("stdout")).unwrap())
        .stderr(std::process::Stdio::null());
    let mut child = command.spawn().unwrap();
    let group = child.id() as i32;
    let deadline = Instant::now() + Duration::from_secs(10);
    while !project.file_exists("heartbeat") && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    let ready = project.file_exists("heartbeat");
    // SAFETY: this is the owned fixture CLI process.
    unsafe {
        libc::kill(group, libc::SIGTERM);
    }
    let deadline = Instant::now() + Duration::from_secs(4);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break Some(status);
        }
        if Instant::now() >= deadline {
            break None;
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let before = std::fs::read(project.path().join("heartbeat")).unwrap_or_default();
    std::thread::sleep(Duration::from_millis(150));
    let after = std::fs::read(project.path().join("heartbeat")).unwrap_or_default();
    // SAFETY: this process group contains only isolated fixture descendants.
    unsafe {
        libc::kill(-group, libc::SIGKILL);
    }
    let _ = child.wait();
    assert!(ready);
    assert!(status.is_some());
    assert_eq!(before, after, "engine descendant survived interruption");
    assert_eq!(status.unwrap().code(), Some(143));
    if json {
        let value: serde_json::Value = serde_json::from_str(&project.read_file("stdout"))
            .expect("interrupted JSON remains parseable");
        assert_eq!(value["success"], false);
    }
    if workspace {
        assert!(!project.file_exists("packages/b/started"));
    }
}

#[cfg(unix)]
#[test]
fn bundle_member_bun_selection_keeps_root_node_and_unavailable_node_masks_it() {
    let project = TempProject::empty(r#"{"name":"root","workspaces":["packages/*"]}"#);
    project.write_file("lpm.json", r#"{"runtime":{"node":"22.0.0"}}"#);
    for name in ["bun-only", "unavailable"] {
        project.write_file(
            &format!("packages/{name}/package.json"),
            &serde_json::json!({"name":name}).to_string(),
        );
    }
    project.write_file(
        "packages/bun-only/lpm.json",
        r#"{"runtime":{"bun":"1.2.0"}}"#,
    );
    project.write_file(
        "packages/unavailable/lpm.json",
        r#"{"runtime":{"node":"99.0.0"}}"#,
    );
    seed_fake_rolldown_engine(&project, &project.home().join("unused"));
    write_unix_executable(
        &project.home().join(".lpm/runtimes/node/22.0.0/bin/node"),
        "#!/bin/sh\nprintf managed > selected-node\n",
    );
    let fallback = project.home().join("fallback");
    write_unix_executable(
        &fallback.join("node"),
        "#!/bin/sh\nprintf fallback > selected-node\n",
    );
    let path = std::env::join_paths(
        std::iter::once(fallback).chain(std::env::split_paths(&std::env::var_os("PATH").unwrap())),
    )
    .unwrap();
    let output = lpm(&project)
        .env("PATH", path)
        .args(["bundle", "--all", "--json"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert_eq!(
        project.read_file("packages/bun-only/selected-node"),
        "managed"
    );
    assert_eq!(
        project.read_file("packages/unavailable/selected-node"),
        "fallback"
    );
    assert!(!project.home().join(".lpm/runtimes/node/99.0.0").exists());
}

#[cfg(unix)]
#[test]
fn bundle_nested_invocation_keeps_project_pin_and_current_directory() {
    let project = TempProject::empty(r#"{"name":"nested-bundle"}"#);
    project.write_file("lpm.json", r#"{"tools":{"rolldown":"1.1.2"}}"#);
    project.write_file("src/nested/entry.js", "");
    let marker = project.home().join("calls");
    seed_fake_rolldown_engine_version(&project, &marker, "1.1.2", true);
    let output = lpm(&project)
        .current_dir(project.path().join("src/nested"))
        .arg("bundle")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let calls = read_marker_lines(&marker);
    assert_eq!(calls.len(), 1);
    assert_eq!(
        normalize_test_path(calls[0]["cwd"].as_str().unwrap()),
        normalize_test_path(project.path().join("src/nested").to_str().unwrap())
    );
}

#[cfg(unix)]
#[test]
fn bundle_filtered_watch_validates_root_config_and_aggregates_child_failure() {
    let project = TempProject::empty(r#"{"name":"root","workspaces":["packages/*"]}"#);
    project.write_file("packages/a/package.json", r#"{"name":"a"}"#);
    project.write_file(
        "packages/a/lpm.json",
        &serde_json::json!({"tools":{"rolldown":ROLLDOWN_VERSION}}).to_string(),
    );
    let marker = project.home().join("calls");
    seed_fake_rolldown_engine(&project, &marker);
    project.write_file("lpm.json", "{");
    let invalid = lpm(&project)
        .args(["bundle", "--filter", "a", "--", "--watch"])
        .output()
        .unwrap();
    assert!(!invalid.status.success());
    assert!(!marker.exists());
    project.write_file("lpm.json", "{}");
    replace_seeded_rolldown_script(&project, ROLLDOWN_VERSION, "process.exit(7)");
    let failed = lpm(&project)
        .args(["bundle", "--filter", "a", "--", "--watch"])
        .output()
        .unwrap();
    assert_eq!(failed.status.code(), Some(1));
}

#[cfg(unix)]
#[test]
fn bundle_watch_admission_matches_rolldown_clusters_values_and_duplicates() {
    let project = TempProject::empty(r#"{"name":"watch-args"}"#);
    let marker = project.home().join("calls");
    seed_fake_rolldown_engine(&project, &marker);
    let mut actual = Vec::new();
    let cases: &[(&[&str], bool)] = &[
        (&["-ww"], false),
        (&["-mw"], false),
        (&["--watch", "--watch=false"], true),
        (&["--watch=false", "--watch"], false),
        (&["--watch", "false"], true),
        (&["-ww=false"], true),
        (&["--no-watch"], true),
        (&["-w", "--watch=false"], false),
        (&["--watch", "-w=false"], false),
        (&["--watch=false", "-w"], true),
        (&["--watch", "--no-watch"], true),
        (&["--no-watch", "--watch"], false),
        (&["--watch="], false),
        (&["--watch", ""], true),
        (&["--watch=false", "--", "-ww"], true),
        (&["--external", "watch", "--watch=false"], true),
    ];
    for (args, finite) in cases {
        let _ = std::fs::remove_file(&marker);
        let output = lpm(&project)
            .args(["bundle", "--json", "--"])
            .args(*args)
            .output()
            .unwrap();
        actual.push((args.to_vec(), output.status.success(), marker.exists()));
        let _: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        if !finite {
            assert!(output.stdout.len() < 4096);
        }
    }
    let expected: Vec<_> = cases
        .iter()
        .map(|(args, finite)| (args.to_vec(), *finite, *finite))
        .collect();
    assert_eq!(actual, expected);
}

#[cfg(unix)]
#[test]
fn bundle_stop_signal_terminates_engine_descendants() {
    assert_bundle_stop(&["bundle"], false, false);
}

#[cfg(unix)]
#[test]
fn bundle_json_interruption_stops_descendants_and_reports_failure() {
    assert_bundle_stop(&["bundle", "--json"], false, true);
}

#[cfg(unix)]
#[test]
fn bundle_workspace_interruption_does_not_launch_waiting_dependents() {
    assert_bundle_stop(&["bundle", "--all", "--json"], true, true);
}
