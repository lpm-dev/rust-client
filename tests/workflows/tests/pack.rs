mod support;

#[cfg(unix)]
use std::collections::BTreeSet;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

#[cfg(unix)]
use support::assertions::parse_json_output;
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
fn pack_single_package_json_emits_success_envelope() {
    let project = TempProject::empty(
        r#"{
  "name": "pack-json-project",
  "version": "1.0.0"
}"#,
    );
    project.write_file("src/index.ts", "export const answer = 42\n");

    let marker_file = project.home().join("pack-single-json.log");
    seed_fake_tsdown(&project, &marker_file);

    let output = lpm(&project)
        .args([
            "pack",
            "--json",
            "--entry",
            "src/index.ts",
            "--out-dir",
            "dist",
        ])
        .output()
        .expect("failed to run lpm pack --json");

    assert!(
        output.status.success(),
        "single-package pack --json must succeed, got: {}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr),
    );

    let envelope = parse_json_output(&output.stdout);
    assert_eq!(envelope["success"], serde_json::json!(true));
    assert_eq!(envelope["packages"], serde_json::json!(1));
    assert_eq!(envelope["succeeded"], serde_json::json!(1));
    assert_eq!(envelope["failed"], serde_json::json!(0));
    assert_eq!(
        envelope["members"][0]["name"],
        serde_json::json!("pack-json-project")
    );
    assert_eq!(envelope["members"][0]["success"], serde_json::json!(true));

    let invocations = read_marker_lines(&marker_file);
    assert_eq!(invocations.len(), 1, "expected one tsdown invocation");
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

#[cfg(unix)]
fn seed_pack_script(project: &TempProject, script: &str) {
    write_unix_executable(
        &project.path().join("node_modules/.bin/tsdown"),
        &format!("#!/usr/bin/env node\n{script}"),
    );
}

#[cfg(unix)]
#[test]
fn pack_single_json_preserves_the_child_exit_code() {
    let project = TempProject::empty(r#"{"name":"pack-json"}"#);
    seed_pack_script(
        &project,
        "console.log('pack output');console.error('pack error');process.exit(7)",
    );
    let output = lpm(&project).args(["pack", "--json"]).output().unwrap();
    assert_eq!(output.status.code(), Some(7));
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["members"][0]["stdout"], "pack output\n");
    assert_eq!(value["members"][0]["exit_code"], 7);
}

#[cfg(unix)]
#[test]
fn pack_json_caps_multibyte_diagnostics_without_panicking() {
    let project = TempProject::empty(r#"{"name":"pack-large"}"#);
    seed_pack_script(
        &project,
        "const chunk='€'.repeat(4096);for(let i=0;i<1024;i++)require('fs').writeSync(1,chunk);process.exit(7)",
    );
    let output = lpm(&project).args(["pack", "--json"]).output().unwrap();
    assert_eq!(output.status.code(), Some(7));
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let stdout = value["members"][0]["stdout"].as_str().unwrap();
    assert!(stdout.len() <= 10 * 1024 * 1024 + 100);
    assert!(stdout.contains("truncated"));
}

#[cfg(unix)]
#[test]
fn pack_does_not_execute_tsdown_from_an_unrelated_ancestor_project() {
    let project = TempProject::empty(r#"{"name":"outer"}"#);
    project.write_file("nested/package.json", r#"{"name":"nested"}"#);
    let marker = project.home().join("escaped");
    seed_fake_tsdown(&project, &marker);
    let output = lpm(&project)
        .current_dir(project.path().join("nested"))
        .arg("pack")
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(!marker.exists());
}

#[cfg(unix)]
#[test]
fn pack_does_not_execute_node_from_an_unrelated_ancestor_project() {
    let project = TempProject::empty(r#"{"name":"outer"}"#);
    project.write_file("nested/package.json", r#"{"name":"nested"}"#);
    write_unix_executable(
        &project.path().join("node_modules/.bin/node"),
        "#!/bin/sh\nprintf escaped > escaped\nexit 7\n",
    );
    write_unix_executable(
        &project.path().join("nested/node_modules/.bin/tsdown"),
        "#!/usr/bin/env node\nrequire('fs').writeFileSync('built','yes')",
    );
    let output = lpm(&project)
        .current_dir(project.path().join("nested"))
        .arg("pack")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!project.file_exists("nested/escaped"));
    assert!(project.file_exists("nested/built"));
}

#[cfg(unix)]
#[test]
fn pack_preserves_node_ranges_and_workspace_runtime_inheritance() {
    let project = TempProject::empty(r#"{"name":"root","workspaces":["packages/*"]}"#);
    project.write_file("lpm.json", r#"{"runtime":{"node":"^22.5.0"}}"#);
    for name in ["a", "b"] {
        project.write_file(
            &format!("packages/{name}/package.json"),
            &serde_json::json!({"name":name}).to_string(),
        );
    }
    project.write_file("packages/b/lpm.json", r#"{"runtime":{"node":"24.0.0"}}"#);
    seed_pack_script(&project, "");
    for version in ["22.5.0", "22.8.0", "24.0.0"] {
        write_unix_executable(
            &project
                .home()
                .join(format!(".lpm/runtimes/node/{version}/bin/node")),
            &format!("#!/bin/sh\nprintf '{version}' > runtime-version\n"),
        );
    }
    let single = lpm(&project).arg("pack").output().unwrap();
    assert!(single.status.success());
    assert_eq!(project.read_file("runtime-version"), "22.8.0");
    let workspace = lpm(&project).args(["pack", "--all"]).output().unwrap();
    assert!(workspace.status.success());
    assert_eq!(project.read_file("packages/a/runtime-version"), "22.8.0");
    assert_eq!(project.read_file("packages/b/runtime-version"), "24.0.0");
}

#[cfg(unix)]
#[test]
fn pack_starts_ready_members_without_waiting_for_a_full_chunk() {
    let limit = std::thread::available_parallelism().map_or(4, |n| n.get());
    if limit < 2 {
        return;
    }
    let project = TempProject::empty(r#"{"name":"pack-ready","workspaces":["packages/*"]}"#);
    for i in 0..=limit {
        project.write_file(
            &format!("packages/p{i:04}/package.json"),
            &serde_json::json!({"name":format!("p{i:04}")}).to_string(),
        );
    }
    write_unix_executable(
        &project.path().join("node_modules/.bin/tsdown"),
        "#!/bin/sh\nname=${PWD##*/}\nif [ \"$name\" = p0000 ]; then\n count=0\n while [ ! -f \"$PACK_GATE\" ]; do\n  count=$((count + 1))\n  if [ \"$count\" -gt 300 ]; then exit 7; fi\n  sleep 0.01\n done\nfi\nif [ \"$name\" = \"$PACK_LAST\" ]; then printf x > \"$PACK_GATE\"; fi\n",
    );
    let output = lpm(&project)
        .env("PACK_GATE", project.path().join("ready"))
        .env("PACK_LAST", format!("p{limit:04}"))
        .args(["pack", "--all", "--json"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
}

#[cfg(unix)]
#[test]
fn pack_watch_rejects_json_before_starting_tsdown() {
    let project = TempProject::empty(r#"{"name":"pack-watch"}"#);
    let marker = project.home().join("calls");
    seed_fake_tsdown(&project, &marker);
    for args in [vec!["--watch"], vec!["-ww"], vec!["--watch=false"]] {
        let output = lpm(&project)
            .args(["pack", "--json", "--"])
            .args(&args)
            .output()
            .unwrap();
        assert!(!output.status.success(), "{args:?}");
        assert!(!marker.exists());
    }
}

#[cfg(unix)]
#[test]
fn pack_filtered_watch_aggregates_child_failure() {
    let project = TempProject::empty(r#"{"name":"root","workspaces":["packages/*"]}"#);
    project.write_file("packages/a/package.json", r#"{"name":"a"}"#);
    seed_pack_script(&project, "process.exit(7)");
    let output = lpm(&project)
        .args(["pack", "--filter", "a", "--", "--watch"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
}

#[cfg(unix)]
fn assert_pack_stop(args: &[&str], workspace: bool, json: bool) {
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
    seed_pack_script(
        &project,
        "const {writeFileSync}=require('node:fs');writeFileSync('started','yes');const {spawn}=require('node:child_process');spawn(process.execPath,['-e',\"setInterval(()=>require('fs').appendFileSync(process.env.PACK_HEARTBEAT,'x'),20)\"],{stdio:'inherit'});setInterval(()=>{},1000);",
    );
    let mut command = support::lpm_spawnable(&project);
    command
        .args(args)
        .env("PACK_HEARTBEAT", project.path().join("heartbeat"))
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
fn pack_stop_signal_terminates_descendants_in_human_and_json_modes() {
    assert_pack_stop(&["pack"], false, false);
    assert_pack_stop(&["pack", "--json"], false, true);
    assert_pack_stop(&["pack", "--all", "--json"], true, true);
}

#[cfg(unix)]
#[test]
fn pack_json_and_workspace_builds_disable_configuration_only_watch() {
    use std::time::{Duration, Instant};
    for workspace in [false, true] {
        let project = TempProject::empty(r#"{"name":"root","workspaces":["packages/*"]}"#);
        project.write_file("packages/a/package.json", r#"{"name":"a"}"#);
        project.write_file("packages/b/package.json", r#"{"name":"b"}"#);
        project.write_file("tsdown.config.mjs", "export default {watch:true}");
        seed_pack_script(
            &project,
            "if (!process.argv.includes('--no-watch')) setInterval(()=>{},1000)",
        );
        let mut command = support::lpm_spawnable(&project);
        command.args(["pack", "--json"]);
        if workspace {
            command.arg("--all");
        }
        command
            .stdout(std::fs::File::create(project.path().join("result.json")).unwrap())
            .stderr(std::process::Stdio::null());
        let mut child = command.spawn().unwrap();
        let deadline = Instant::now() + Duration::from_secs(3);
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break Some(status);
            }
            if Instant::now() >= deadline {
                break None;
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        if status.is_none() {
            let _ = lpm_runner::ports::terminate_child_process_tree(&mut child);
        }
        assert!(
            status.is_some_and(|status| status.success()),
            "config-only watch did not finish (workspace={workspace})"
        );
        let value: serde_json::Value =
            serde_json::from_str(&project.read_file("result.json")).unwrap();
        assert_eq!(value["success"], true);
    }
}

#[cfg(windows)]
#[test]
fn pack_prefers_windows_cmd_shim_when_a_posix_sibling_exists() {
    let project = TempProject::empty(r#"{"name":"windows-pack"}"#);
    project.write_file("node_modules/.bin/tsdown", "#!/bin/sh\nexit 9\n");
    project.write_file(
        "node_modules/.bin/tsdown.cmd",
        "@echo off\r\necho cmd-shim>cmd-shim.txt\r\nexit /b 0\r\n",
    );
    let output = lpm(&project).args(["pack", "--json"]).output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert_eq!(project.read_file("cmd-shim.txt").trim(), "cmd-shim");
}

#[cfg(unix)]
#[test]
fn pack_watch_admission_keeps_tsdown_path_and_negation_semantics() {
    let project = TempProject::empty(r#"{"name":"watch-paths"}"#);
    let marker = project.home().join("calls");
    seed_fake_tsdown(&project, &marker);
    let cases: &[(&[&str], bool)] = &[
        (&["--watch=false"], false),
        (&["--watch", "false"], false),
        (&["--watch", "src"], false),
        (&["-ww"], false),
        (&["--watch", "--no-watch"], true),
        (&["--no-watch", "--watch"], false),
        (&["-w", "--no-watch"], false),
        (&["--no-watch", "-w"], true),
        (&["--watch=0"], true),
        (&["--watch", ""], true),
        (&["--watch=0", "--watch=0"], false),
        (&["--no-watch", "--", "-ww"], true),
    ];
    let mut actual = Vec::new();
    for (args, finite) in cases {
        let _ = std::fs::remove_file(&marker);
        let output = lpm(&project)
            .args(["pack", "--json", "--"])
            .args(*args)
            .output()
            .unwrap();
        actual.push((args.to_vec(), output.status.success(), marker.exists()));
        let _: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        if *finite {
            let invocations = read_marker_lines(&marker);
            let args = &invocations[0].1;
            let no_watch = args.iter().position(|arg| arg == "--no-watch").unwrap();
            let delimiter = args
                .iter()
                .position(|arg| arg == "--")
                .unwrap_or(args.len());
            assert!(no_watch < delimiter);
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
fn pack_wrapper_values_cannot_become_tsdown_options() {
    let project = TempProject::empty(r#"{"name":"wrapper-values"}"#);
    let marker = project.home().join("calls");
    seed_fake_tsdown(&project, &marker);
    let output = lpm(&project)
        .args([
            "pack",
            "--json",
            "--entry=-w",
            "--config=--watch",
            "--tsconfig=--watch",
            "--target=-w",
            "--out-dir=--",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    let calls = read_marker_lines(&marker);
    assert_eq!(
        calls[0].1,
        [
            "--config=--watch",
            "--tsconfig=--watch",
            "--target=-w",
            "./-w",
            "--out-dir=--",
            "--no-watch"
        ]
    );
}
