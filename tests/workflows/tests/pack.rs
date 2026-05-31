mod support;

#[cfg(unix)]
use std::collections::BTreeSet;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

#[cfg(unix)]
use support::assertions::parse_json_output;
#[cfg(unix)]
use support::{TempProject, lpm};

#[cfg(unix)]
fn normalize_test_path(path: &str) -> String {
    path.strip_prefix("/private").unwrap_or(path).to_string()
}

#[cfg(unix)]
fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' && chars.peek() == Some(&'[') {
            chars.next();
            for cc in chars.by_ref() {
                let cb = cc as u32;
                if (0x40..=0x7e).contains(&cb) {
                    break;
                }
            }
        } else {
            out.push(c);
        }
    }
    out
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
fn seed_fake_tsdown(project: &TempProject, marker_file: &std::path::Path) {
    let marker_literal = marker_file.to_string_lossy().replace('"', "\\\"");
    let script = format!(
        "#!/bin/sh\n{{\n  printf '%s' \"$PWD\"\n  for arg in \"$@\"; do\n    printf '\\t%s' \"$arg\"\n  done\n  printf '\\n'\n}} >> \"{marker_literal}\"\n"
    );

    write_unix_executable(&project.path().join("node_modules/.bin/tsdown"), &script);
}

#[cfg(unix)]
fn read_marker_lines(path: &std::path::Path) -> Vec<(String, Vec<String>)> {
    let text = std::fs::read_to_string(path).expect("failed to read marker file");
    text.lines()
        .map(|line| {
            let mut parts = line.split('\t');
            let cwd = parts.next().expect("marker line must have cwd").to_string();
            let args = parts.map(ToOwned::to_owned).collect();
            (cwd, args)
        })
        .collect()
}

#[cfg(unix)]
#[test]
fn pack_runs_project_tsdown_with_lpm_flags() {
    let project = TempProject::empty(
        r#"{
  "name": "pack-test-project",
  "version": "1.0.0"
}"#,
    );
    project.write_file("src/index.ts", "export const answer = 42\n");

    let marker_file = project.home().join("pack-single.log");
    seed_fake_tsdown(&project, &marker_file);

    let output = lpm(&project)
        .args([
            "--color=always",
            "pack",
            "--entry",
            "src/index.ts",
            "--out-dir",
            "dist",
            "--format",
            "esm",
            "--platform",
            "node",
            "--dts",
            "--minify",
            "--sourcemap",
        ])
        .output()
        .expect("failed to run lpm pack");

    assert!(
        output.status.success(),
        "pack must succeed, got: {}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr),
    );
    let stderr_raw = String::from_utf8_lossy(&output.stderr);
    let stderr = strip_ansi(&stderr_raw);
    assert!(
        stderr.contains("› Using local tsdown"),
        "pack must use a slim phase line, got:\n{stderr}"
    );
    assert!(
        stderr_raw.contains("\u{1b}[33mtsdown\u{1b}[39m"),
        "pack must color the local tool name, got:\n{stderr_raw:?}"
    );
    assert!(
        stderr.contains("✓ Done · package build complete in "),
        "pack must report a slim timed completion line, got:\n{stderr}"
    );
    assert!(
        !stderr.contains('●') && !stderr.contains('│'),
        "pack output must not use cliclack gutter output, got:\n{stderr}"
    );

    let invocations = read_marker_lines(&marker_file);
    assert_eq!(invocations.len(), 1, "expected one tsdown invocation");
    let (cwd, args) = &invocations[0];
    assert_eq!(
        normalize_test_path(cwd),
        normalize_test_path(project.path().to_str().expect("project path must be utf8"))
    );
    assert_eq!(
        args,
        &vec![
            "src/index.ts".to_string(),
            "--out-dir".to_string(),
            "dist".to_string(),
            "--format".to_string(),
            "esm".to_string(),
            "--platform".to_string(),
            "node".to_string(),
            "--dts".to_string(),
            "--minify".to_string(),
            "--sourcemap".to_string(),
        ]
    );
}

#[cfg(unix)]
#[test]
fn pack_workspace_human_reports_slim_summary() {
    let project = TempProject::from_fixture("workspace-monorepo");
    for member in ["packages/utils", "packages/core", "packages/app"] {
        project.write_file(&format!("{member}/src/index.ts"), "export default 1\n");
    }

    let marker_file = project.home().join("pack-workspace-human.log");
    seed_fake_tsdown(&project, &marker_file);

    let output = lpm(&project)
        .args([
            "pack",
            "--all",
            "--entry",
            "src/index.ts",
            "--out-dir",
            "dist",
            "--dts",
        ])
        .output()
        .expect("failed to run lpm pack --all");

    assert!(
        output.status.success(),
        "workspace pack must succeed, got: {}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr),
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("✓ pack passed in 3 packages in "),
        "workspace pack must report a slim timed summary, got:\n{stderr}"
    );
    assert!(
        !stderr.contains('●') && !stderr.contains('│'),
        "workspace pack output must not use cliclack gutter output, got:\n{stderr}"
    );

    let invocations = read_marker_lines(&marker_file);
    assert_eq!(
        invocations.len(),
        3,
        "expected one tsdown invocation per member"
    );
}

#[test]
fn pack_filter_typo_without_fail_flag_uses_slim_warning() {
    let project = TempProject::from_fixture("workspace-monorepo");

    let output = lpm(&project)
        .args([
            "pack",
            "--filter",
            "this-package-does-not-exist",
            "--entry",
            "src/index.ts",
        ])
        .output()
        .expect("failed to run lpm pack");

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
        "empty-match pack output must not use cliclack gutter output, got:\n{stderr}"
    );
}

#[cfg(unix)]
#[test]
fn pack_workspace_json_emits_valid_envelope_per_member() {
    let project = TempProject::from_fixture("workspace-monorepo");
    for member in ["packages/utils", "packages/core", "packages/app"] {
        project.write_file(&format!("{member}/src/index.ts"), "export default 1\n");
    }

    let marker_file = project.home().join("pack-workspace.log");
    seed_fake_tsdown(&project, &marker_file);

    let output = lpm(&project)
        .args([
            "pack",
            "--all",
            "--json",
            "--entry",
            "src/index.ts",
            "--out-dir",
            "dist",
            "--dts",
        ])
        .output()
        .expect("failed to run lpm pack --all --json");

    assert!(
        output.status.success(),
        "workspace pack must succeed, got: {}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr),
    );

    let envelope = parse_json_output(&output.stdout);
    assert_eq!(envelope["success"], serde_json::json!(true));
    assert_eq!(envelope["packages"], serde_json::json!(3));
    assert_eq!(envelope["succeeded"], serde_json::json!(3));
    assert_eq!(envelope["failed"], serde_json::json!(0));

    insta::with_settings!({ filters => vec![(r#""duration_ms":\s*\d+"#, r#""duration_ms":0"#)] }, {
        insta::assert_json_snapshot!("pack_workspace_json_envelope_per_member", envelope);
    });

    let members = envelope["members"]
        .as_array()
        .expect("members must be an array");
    let member_names: BTreeSet<String> = members
        .iter()
        .map(|member| {
            assert_eq!(member["success"], serde_json::json!(true));
            member["name"]
                .as_str()
                .expect("member name must be a string")
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
    assert_eq!(
        invocations.len(),
        3,
        "expected one pack per workspace member"
    );
    let cwd_set: BTreeSet<String> = invocations
        .iter()
        .map(|(cwd, _)| normalize_test_path(cwd))
        .collect();
    let expected_cwds = BTreeSet::from([
        normalize_test_path(
            project
                .path()
                .join("packages/app")
                .to_str()
                .expect("workspace app path must be utf8"),
        ),
        normalize_test_path(
            project
                .path()
                .join("packages/core")
                .to_str()
                .expect("workspace core path must be utf8"),
        ),
        normalize_test_path(
            project
                .path()
                .join("packages/utils")
                .to_str()
                .expect("workspace utils path must be utf8"),
        ),
    ]);
    assert_eq!(cwd_set, expected_cwds);
}

#[cfg(unix)]
#[test]
fn pack_filter_typo_with_fail_flag_exits_nonzero() {
    let project = TempProject::from_fixture("workspace-monorepo");
    let output = lpm(&project)
        .args(["pack", "--filter", "does-not-exist", "--fail-if-no-match"])
        .output()
        .expect("failed to run lpm pack --filter does-not-exist --fail-if-no-match");

    assert!(
        !output.status.success(),
        "pack must fail when --fail-if-no-match is set\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("no workspace packages matched the filter")
            || stderr.contains("--fail-if-no-match"),
        "expected error message mentioning the empty-match condition, got:\n{stderr}"
    );
}
