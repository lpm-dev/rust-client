mod support;

use std::path::Path;
use support::{TempProject, lpm};

#[cfg(unix)]
fn make_executable(path: &Path) {
    use std::os::unix::fs::PermissionsExt;

    let mut permissions = std::fs::metadata(path)
        .expect("fake binary must exist")
        .permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(path, permissions).expect("mark fake binary executable");
}

#[cfg(not(unix))]
fn make_executable(_path: &Path) {}

fn write_fake_node(project: &TempProject, version: &str) {
    let node_path = if cfg!(windows) {
        project.path().join("node_modules/.bin/node.cmd")
    } else {
        project.path().join("node_modules/.bin/node")
    };
    std::fs::create_dir_all(node_path.parent().expect("fake node has parent"))
        .expect("create fake node bin dir");
    let script = if cfg!(windows) {
        format!("@echo off\r\necho {version}\r\n")
    } else {
        format!("#!/bin/sh\necho {version}\n")
    };
    std::fs::write(&node_path, script).expect("write fake node");
    make_executable(&node_path);
}

fn write_fake_tsx(project: &TempProject) {
    let tsx_path = if cfg!(windows) {
        project.path().join("node_modules/.bin/tsx.cmd")
    } else {
        project.path().join("node_modules/.bin/tsx")
    };
    std::fs::create_dir_all(tsx_path.parent().expect("fake tsx has parent"))
        .expect("create fake tsx bin dir");
    let script = if cfg!(windows) {
        "@echo off\r\necho local-tsx %*\r\n".to_string()
    } else {
        "#!/bin/sh\necho local-tsx \"$@\"\n".to_string()
    };
    std::fs::write(&tsx_path, script).expect("write fake tsx");
    make_executable(&tsx_path);
}

#[test]
fn exec_js_file_loads_dotenv_and_forwards_args() {
    let project = TempProject::empty(r#"{"name":"exec-test","version":"1.0.0"}"#);
    project.write_file(".env", "EXEC_MESSAGE=hello-from-dotenv\n");
    project.write_file(
        "scripts/echo.js",
        concat!(
            "const payload = {\n",
            "  env: process.env.EXEC_MESSAGE,\n",
            "  args: process.argv.slice(2),\n",
            "};\n",
            "console.log(JSON.stringify(payload));\n",
        ),
    );

    let output = lpm(&project)
        .args(["exec", "scripts/echo.js", "--", "--flag", "value"])
        .output()
        .expect("failed to run lpm exec");

    assert!(
        output.status.success(),
        "lpm exec failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains(r#"{"env":"hello-from-dotenv","args":["--flag","value"]}"#),
        "exec must load .env vars and forward args to the script, got:\n{stdout}"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("› Executing scripts/echo.js with Node.js"),
        "exec must name the selected runtime in the slim phase line, got:\n{stderr}"
    );
    assert!(
        stderr.contains("✓ Done · exited 0 in"),
        "exec must show the slim elapsed-time terminus, got:\n{stderr}"
    );
}

#[test]
fn exec_missing_file_fails_before_runtime_execution() {
    let project = TempProject::empty(r#"{"name":"exec-test","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args(["exec", "scripts/missing.js"])
        .output()
        .expect("failed to run lpm exec on a missing file");

    assert!(!output.status.success(), "missing exec target must fail");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("file not found"),
        "missing-file error must mention the path lookup failure, got:\n{stderr}"
    );
}

#[test]
fn exec_env_flag_loads_selected_env_file() {
    let project = TempProject::empty(r#"{"name":"exec-test","version":"1.0.0"}"#);
    project.write_file(".env", "EXEC_MESSAGE=default\n");
    project.write_file(".env.staging", "EXEC_MESSAGE=from-staging\n");
    project.write_file("scripts/env.js", "console.log(process.env.EXEC_MESSAGE);\n");

    let output = lpm(&project)
        .args(["exec", "--env", "staging", "scripts/env.js"])
        .output()
        .expect("failed to run lpm exec --env");

    assert!(
        output.status.success(),
        "lpm exec --env failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("from-staging"),
        "exec must load the selected env mode, got:\n{stdout}"
    );
}

#[test]
fn exec_no_env_check_skips_schema_validation() {
    let project = TempProject::empty(r#"{"name":"exec-test","version":"1.0.0"}"#);
    project.write_file(
        "lpm.json",
        r#"{"envSchema":{"vars":{"REQUIRED_TOKEN":{"required":true}}}}"#,
    );
    project.write_file("scripts/noop.js", "console.log('ok');\n");

    let output = lpm(&project)
        .args(["exec", "--no-env-check", "scripts/noop.js"])
        .output()
        .expect("failed to run lpm exec --no-env-check");

    assert!(
        output.status.success(),
        "--no-env-check must skip env schema validation for exec:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

#[test]
fn exec_typescript_without_safe_runtime_refuses_npx_tsx() {
    let project = TempProject::empty(r#"{"name":"exec-test","version":"1.0.0"}"#);
    project.write_file("scripts/seed.ts", "console.log('seed');\n");
    write_fake_node(&project, "v20.5.0");

    let output = lpm(&project)
        .args(["exec", "scripts/seed.ts"])
        .output()
        .expect("failed to run lpm exec on TypeScript without safe runtime");

    assert!(
        !output.status.success(),
        "unsafe TypeScript fallback must fail closed"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("will not fall back to `npx tsx`"),
        "error must explain that npx tsx is refused, got:\n{stderr}"
    );
    assert!(
        stderr.contains("lpm use node@22.6+"),
        "error must suggest a managed Node runtime, got:\n{stderr}"
    );
}

#[test]
fn exec_tsx_file_uses_project_local_tsx() {
    let project = TempProject::empty(r#"{"name":"exec-test","version":"1.0.0"}"#);
    project.write_file("scripts/view.tsx", "export const view = <main />;\n");
    write_fake_node(&project, "v22.18.0");
    write_fake_tsx(&project);

    let output = lpm(&project)
        .args(["exec", "scripts/view.tsx"])
        .output()
        .expect("failed to run lpm exec on TSX with local tsx");

    assert!(
        output.status.success(),
        "TSX with local tsx must succeed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("local-tsx scripts/view.tsx"),
        "exec must invoke project-local tsx for TSX files, got:\n{stdout}"
    );
}

#[test]
fn exec_missing_file_under_json_emits_error_envelope_on_stdout() {
    let project = TempProject::empty(r#"{"name":"exec-test","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args(["--json", "exec", "scripts/missing.js"])
        .output()
        .expect("failed to run lpm --json exec on a missing file");

    // `support::assertions::parse_json_output` finds the first `{` in
    // stdout — tolerant of the human "● exec ..." banner that the
    // exec command emits before the envelope. The envelope itself
    // must be valid JSON with `success: false` and the missing-file
    // error_code.
    let envelope = support::assertions::parse_json_output(&output.stdout);
    assert_eq!(envelope["success"], serde_json::json!(false));
    assert!(
        envelope["error"]
            .as_str()
            .is_some_and(|s| s.contains("file not found") || s.contains("missing.js")),
        "error must reference the missing file path, got: {envelope}",
    );
}
