mod support;

use std::path::{Path, PathBuf};
#[cfg(unix)]
use std::time::{Duration, Instant};
#[cfg(unix)]
use support::lpm_spawnable;
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

fn write_fake_local_bin(project: &TempProject, name: &str, unix_body: &str, windows_body: &str) {
    let bin_path = if cfg!(windows) {
        project.path().join(format!("node_modules/.bin/{name}.cmd"))
    } else {
        project.path().join(format!("node_modules/.bin/{name}"))
    };
    std::fs::create_dir_all(bin_path.parent().expect("fake bin has parent"))
        .expect("create fake bin dir");
    let script = if cfg!(windows) {
        windows_body
    } else {
        unix_body
    };
    std::fs::write(&bin_path, script).expect("write fake local bin");
    make_executable(&bin_path);
}

fn transform_cache_dir(project: &TempProject) -> PathBuf {
    let runtime_root = project.home().join(".lpm/cache/exec-ts-runtime");
    let mut candidates = std::fs::read_dir(&runtime_root)
        .expect("LPM TS runtime root must exist")
        .filter_map(|entry| {
            let path = entry.expect("runtime root entry must be readable").path();
            let cache_dir = path.join("transform-cache");
            cache_dir.is_dir().then_some(cache_dir)
        })
        .collect::<Vec<_>>();
    candidates.sort();
    assert_eq!(
        candidates.len(),
        1,
        "test project must have exactly one LPM TS runtime transform cache dir under {}",
        runtime_root.display()
    );
    candidates.remove(0)
}

fn read_ts_runtime_trace(trace_path: &Path) -> Vec<serde_json::Value> {
    let trace = std::fs::read_to_string(trace_path)
        .unwrap_or_else(|e| panic!("failed to read trace {}: {e}", trace_path.display()));
    trace
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).expect("trace line must be JSON"))
        .collect()
}

fn has_persistent_transport_event(
    events: &[serde_json::Value],
    filename_suffix: &str,
    request_mode: &str,
) -> bool {
    events.iter().any(|event| {
        event["phase"].as_str() == Some("persistent_transport")
            && event["filename"]
                .as_str()
                .is_some_and(|filename| filename.ends_with(filename_suffix))
            && event["requestMode"].as_str() == Some(request_mode)
    })
}

fn write_fake_react_runtime(project: &TempProject) {
    project.write_file(
        "node_modules/react/package.json",
        concat!(
            "{",
            r#""name":"react","#,
            r#""version":"0.0.0","#,
            r#""type":"commonjs","#,
            r#""exports":{"." : {"import":"./index.mjs","require":"./index.js"},"./jsx-runtime":{"import":"./jsx-runtime.mjs","require":"./jsx-runtime.js"}}"#,
            "}",
        ),
    );
    project.write_file(
        "node_modules/react/jsx-runtime.js",
        concat!(
            "const Fragment = 'Fragment';\n",
            "function jsx(type, props, key) { return { type, props: props || {}, key: key ?? null }; }\n",
            "exports.Fragment = Fragment;\n",
            "exports.jsx = jsx;\n",
            "exports.jsxs = jsx;\n",
        ),
    );
    project.write_file(
        "node_modules/react/jsx-runtime.mjs",
        concat!(
            "export const Fragment = 'Fragment';\n",
            "export function jsx(type, props, key) { return { type, props: props || {}, key: key ?? null }; }\n",
            "export const jsxs = jsx;\n",
        ),
    );
    project.write_file(
        "node_modules/react/index.js",
        concat!(
            "function createElement(type, props, ...children) {\n",
            "  const next = Object.assign({}, props || {});\n",
            "  if (children.length === 1) next.children = children[0];\n",
            "  else if (children.length > 1) next.children = children;\n",
            "  return { type, props: next, key: next.key ?? null };\n",
            "}\n",
            "module.exports = { createElement, Fragment: 'Fragment' };\n",
            "module.exports.default = module.exports;\n",
        ),
    );
    project.write_file(
        "node_modules/react/index.mjs",
        concat!(
            "export const Fragment = 'Fragment';\n",
            "export function createElement(type, props, ...children) {\n",
            "  const next = Object.assign({}, props || {});\n",
            "  if (children.length === 1) next.children = children[0];\n",
            "  else if (children.length > 1) next.children = children;\n",
            "  return { type, props: next, key: next.key ?? null };\n",
            "}\n",
            "export default { createElement, Fragment };\n",
        ),
    );
}

#[test]
fn exec_runs_project_local_binary_with_env_and_args() {
    let project = TempProject::empty(r#"{"name":"exec-bin-test","version":"1.0.0"}"#);
    project.write_file(".env", "EXEC_BIN_MESSAGE=from-env\n");
    write_fake_local_bin(
        &project,
        "say-env",
        "#!/bin/sh\necho \"$EXEC_BIN_MESSAGE $1 $2\"\n",
        "@echo off\r\necho %EXEC_BIN_MESSAGE% %1 %2\r\n",
    );

    let output = lpm(&project)
        .args(["exec", "say-env", "--flag", "value"])
        .output()
        .expect("failed to run project-local binary via lpm exec");

    assert!(
        output.status.success(),
        "lpm exec must run the project-local binary:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("from-env --flag value"),
        "local binary must receive project env and forwarded args, got:\n{stdout}"
    );
}

#[test]
fn exec_errors_when_project_local_binary_is_missing() {
    let project = TempProject::empty(r#"{"name":"exec-bin-test","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args(["exec", "missing-bin"])
        .output()
        .expect("failed to run lpm exec on a missing local binary");

    assert!(!output.status.success(), "missing local binary must fail");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("project-local binary 'missing-bin'"),
        "missing local-bin error must explain the lookup scope, got:\n{stderr}"
    );
}

#[test]
fn exec_rejects_source_file_paths_without_compatibility_alias() {
    let project = TempProject::empty(r#"{"name":"exec-bin-test","version":"1.0.0"}"#);
    project.write_file("scripts/seed.ts", "console.log('seed');\n");

    let output = lpm(&project)
        .args(["exec", "scripts/seed.ts"])
        .output()
        .expect("failed to run lpm exec on a source-file path");

    assert!(
        !output.status.success(),
        "lpm exec must not keep the unshipped source-file alias"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Use `lpm scripts/seed.ts`"),
        "source-file alias rejection must point at naked file execution, got:\n{stderr}"
    );
}

#[test]
fn naked_bare_word_still_runs_script_shortcut() {
    let project = TempProject::empty(
        r#"{"name":"exec-bin-test","version":"1.0.0","scripts":{"storybook":"echo script-shortcut"}}"#,
    );

    let output = lpm(&project)
        .args(["storybook"])
        .output()
        .expect("failed to run script shortcut");

    assert!(
        output.status.success(),
        "bare script shortcut must still run package script:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("script-shortcut"),
        "bare word must stay a script shortcut unless it looks like a source file, got:\n{stdout}"
    );
}

#[test]
fn bare_local_bin_shorthand_runs_project_local_binary_when_script_is_absent() {
    let project = TempProject::empty(r#"{"name":"exec-bin-test","version":"1.0.0"}"#);
    write_fake_local_bin(
        &project,
        "jest",
        "#!/bin/sh\necho local-jest \"$@\"\n",
        "@echo off\r\necho local-jest %*\r\n",
    );

    let output = lpm(&project)
        .args(["jest", "--version"])
        .output()
        .expect("failed to run local-bin shorthand");

    assert!(
        output.status.success(),
        "bare local-bin shorthand must run the project-local binary:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("local-jest --version"),
        "local binary must receive forwarded args, got:\n{stdout}"
    );
}

#[test]
fn bare_script_shortcut_wins_over_same_named_local_binary() {
    let project = TempProject::empty(
        r#"{"name":"exec-bin-test","version":"1.0.0","scripts":{"jest":"echo script-jest"}}"#,
    );
    write_fake_local_bin(
        &project,
        "jest",
        "#!/bin/sh\necho local-jest \"$@\"\n",
        "@echo off\r\necho local-jest %*\r\n",
    );

    let output = lpm(&project)
        .args(["jest", "--version"])
        .output()
        .expect("failed to run script shortcut");

    assert!(
        output.status.success(),
        "script shortcut must win over same-named local binary:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("script-jest --version") && !stdout.contains("local-jest"),
        "script output must be used instead of local-bin output, got:\n{stdout}"
    );
}

#[test]
fn missing_bare_word_reports_scripts_tasks_and_local_bins_were_checked() {
    let project = TempProject::empty(r#"{"name":"exec-bin-test","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args(["missing-command"])
        .output()
        .expect("failed to run missing bare word");

    assert!(!output.status.success(), "missing bare word must fail");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("package.json script")
            && stderr.contains("lpm.json task")
            && stderr.contains("node_modules/.bin"),
        "missing bare-word error must name both checked surfaces, got:\n{stderr}"
    );
}

#[test]
fn path_like_source_file_invocation_runs_file_instead_of_local_bin_fallback() {
    let project = TempProject::empty(r#"{"name":"exec-bin-test","version":"1.0.0"}"#);
    project.write_file("scripts/seed.ts", "console.log('source-file-seed');\n");
    write_fake_local_bin(
        &project,
        "scripts/seed.ts",
        "#!/bin/sh\necho bin-fallback\n",
        "@echo off\r\necho bin-fallback\r\n",
    );

    let output = lpm(&project)
        .args(["scripts/seed.ts"])
        .output()
        .expect("failed to run source file");

    assert!(
        output.status.success(),
        "path-like source-file invocation must run the file:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("source-file-seed") && !stdout.contains("bin-fallback"),
        "source file must run instead of local-bin fallback, got:\n{stdout}"
    );
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
        .args(["scripts/echo.js", "--", "--flag", "value"])
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
fn exec_js_file_does_not_install_lpm_typescript_runtime() {
    let project = TempProject::empty(r#"{"name":"exec-test","version":"1.0.0"}"#);
    project.write_file(
        "scripts/plain.js",
        "console.log(process.env.NODE_OPTIONS || 'no-node-options');\n",
    );

    let output = lpm(&project)
        .args(["scripts/plain.js"])
        .output()
        .expect("failed to run lpm exec on JavaScript");

    assert!(
        output.status.success(),
        "JavaScript exec must succeed without TS runtime preload:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("no-node-options"),
        "JavaScript exec must not receive LPM NODE_OPTIONS, got:\n{stdout}"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("LPM TS runtime"),
        "JavaScript exec must not be labelled as the LPM TS runtime, got:\n{stderr}"
    );
}

#[test]
fn exec_js_file_ignores_node_options_from_env_secrets() {
    let project = TempProject::empty(r#"{"name":"exec-test","version":"1.0.0"}"#);
    project.write_file("bad-preload.cjs", "process.exit(99);\n");
    project.write_file("scripts/plain.js", "console.log('safe-js');\n");

    let bad_preload = project.path().join("bad-preload.cjs");
    let set_output = lpm(&project)
        .args(["env", "set"])
        .arg(format!("NODE_OPTIONS=--require={}", bad_preload.display()))
        .output()
        .expect("failed to write env secret");
    assert!(
        set_output.status.success(),
        "env set must create the test secret:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&set_output.stdout),
        String::from_utf8_lossy(&set_output.stderr),
    );

    let output = lpm(&project)
        .args(["scripts/plain.js"])
        .output()
        .expect("failed to run lpm exec with env-secret NODE_OPTIONS");

    assert!(
        output.status.success(),
        "env-secret NODE_OPTIONS must not hijack JavaScript exec:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("safe-js"),
        "JavaScript exec must ignore NODE_OPTIONS from env secrets, got:\n{stdout}"
    );
}

#[test]
fn exec_js_file_ignores_runtime_hook_env_secrets() {
    let project = TempProject::empty(r#"{"name":"exec-test","version":"1.0.0"}"#);
    project.write_file(
        "scripts/plain.js",
        "if (process.env.BASH_ENV) process.exit(42);\nconsole.log('safe-js');\n",
    );

    let set_output = lpm(&project)
        .args(["env", "set", "BASH_ENV=./bad-shell-env"])
        .output()
        .expect("failed to write runtime-hook env secret");
    assert!(
        set_output.status.success(),
        "env set must create the test runtime-hook secret:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&set_output.stdout),
        String::from_utf8_lossy(&set_output.stderr),
    );

    let output = lpm(&project)
        .args(["scripts/plain.js"])
        .output()
        .expect("failed to run lpm exec with runtime-hook env secret");

    assert!(
        output.status.success(),
        "runtime-hook env secrets must not reach JavaScript exec:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("safe-js"),
        "JavaScript exec must ignore runtime-hook env secrets, got:\n{stdout}"
    );
}

#[test]
fn exec_js_file_ignores_lowercase_runtime_hook_env_secrets() {
    let project = TempProject::empty(r#"{"name":"exec-test","version":"1.0.0"}"#);
    project.write_file(
        "scripts/plain.js",
        "if (process.env.node_options) process.exit(42);\nconsole.log('safe-js');\n",
    );

    let set_output = lpm(&project)
        .args(["env", "set", "node_options=--require=./bad-preload.cjs"])
        .output()
        .expect("failed to write lowercase runtime-hook env secret");
    assert!(
        set_output.status.success(),
        "env set must create the lowercase runtime-hook secret:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&set_output.stdout),
        String::from_utf8_lossy(&set_output.stderr),
    );

    let output = lpm(&project)
        .args(["scripts/plain.js"])
        .output()
        .expect("failed to run lpm exec with lowercase runtime-hook env secret");

    assert!(
        output.status.success(),
        "lowercase runtime-hook env secrets must not reach JavaScript exec:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("safe-js"),
        "JavaScript exec must ignore lowercase runtime-hook env secrets, got:\n{stdout}"
    );
}

#[test]
fn exec_js_file_ignores_node_options_from_env_schema_defaults() {
    let project = TempProject::empty(r#"{"name":"exec-test","version":"1.0.0"}"#);
    project.write_file("bad-preload.cjs", "process.exit(99);\n");
    project.write_file(
        "lpm.json",
        r#"{"envSchema":{"vars":{"NODE_OPTIONS":{"default":"--require=./bad-preload.cjs"}}}}"#,
    );
    project.write_file("scripts/plain.js", "console.log('safe-js');\n");

    let output = lpm(&project)
        .args(["scripts/plain.js"])
        .output()
        .expect("failed to run lpm exec with env-schema NODE_OPTIONS default");

    assert!(
        output.status.success(),
        "env-schema NODE_OPTIONS defaults must not hijack JavaScript exec:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("safe-js"),
        "JavaScript exec must ignore NODE_OPTIONS from env schema defaults, got:\n{stdout}"
    );
}

#[test]
fn exec_missing_file_fails_before_runtime_execution() {
    let project = TempProject::empty(r#"{"name":"exec-test","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args(["scripts/missing.js"])
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
        .args(["--env", "staging", "scripts/env.js"])
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
        .args(["--no-env-check", "scripts/noop.js"])
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
        .args(["scripts/seed.ts"])
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
        stderr.contains("lpm use node@22.18+"),
        "error must suggest a managed Node runtime, got:\n{stderr}"
    );
}

#[test]
fn exec_typescript_file_uses_lpm_runtime_without_project_local_tsx() {
    let project = TempProject::empty(r#"{"name":"exec-test","version":"1.0.0"}"#);
    project.write_file(
        "scripts/seed.ts",
        "const message: string = 'managed-ts';\nconsole.log(message);\n",
    );

    let output = lpm(&project)
        .args(["scripts/seed.ts"])
        .output()
        .expect("failed to run lpm exec on TypeScript");

    assert!(
        output.status.success(),
        "managed TypeScript exec must succeed without local tsx:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("managed-ts"),
        "exec must run the TypeScript file through the LPM runtime, got:\n{stdout}"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("LPM TS runtime"),
        "exec must name the managed TS runtime, got:\n{stderr}"
    );
}

#[test]
fn exec_typescript_transform_cache_contains_inline_source_map() {
    let project = TempProject::empty(r#"{"name":"exec-test","version":"1.0.0"}"#);
    project.write_file(
        "scripts/seed.ts",
        "const message: string = 'source-map-ts';\nconsole.log(message);\n",
    );

    let output = lpm(&project)
        .args(["scripts/seed.ts"])
        .output()
        .expect("failed to run lpm exec on TypeScript");

    assert!(
        output.status.success(),
        "managed TypeScript exec must succeed before checking source maps:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let cache_dir = transform_cache_dir(&project);
    let mut found_source_map = false;
    for entry in std::fs::read_dir(&cache_dir).expect("transform cache dir must exist") {
        let entry = entry.expect("cache entry must be readable");
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
            continue;
        }
        let text = std::fs::read_to_string(&path).expect("cache entry must be utf8 JSON");
        let json: serde_json::Value =
            serde_json::from_str(&text).expect("cache entry must be JSON");
        found_source_map |= json["code"]
            .as_str()
            .is_some_and(|code| code.contains("sourceMappingURL=data:application/json"));
    }

    assert!(
        found_source_map,
        "transform cache must store code with an inline source map"
    );
}

#[test]
fn exec_typescript_trace_reports_inline_persistent_transport_for_small_source() {
    let project = TempProject::empty(r#"{"name":"exec-test","version":"1.0.0"}"#);
    project.write_file(
        "scripts/seed.ts",
        "const message: string = 'trace-inline';\nconsole.log(message);\n",
    );
    let trace_path = project.path().join("trace-inline.jsonl");

    let output = lpm(&project)
        .env("LPM_TS_RUNTIME_TRACE", "1")
        .env("LPM_TS_RUNTIME_TRACE_FILE", trace_path.as_os_str())
        .args(["scripts/seed.ts"])
        .output()
        .expect("failed to run lpm on traced TypeScript");

    assert!(
        output.status.success(),
        "traced managed TypeScript exec must succeed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let events = read_ts_runtime_trace(&trace_path);
    assert!(
        has_persistent_transport_event(&events, "scripts/seed.ts", "inline"),
        "small TS source must use inline persistent transport, got: {events:?}"
    );
}

#[test]
fn exec_typescript_trace_reports_file_transport_for_large_source() {
    let project = TempProject::empty(r#"{"name":"exec-test","version":"1.0.0"}"#);
    let payload = "x".repeat(300 * 1024);
    let source = format!("const message: string = {payload:?};\nconsole.log(message.length);\n");
    project.write_file("scripts/large.ts", &source);
    let trace_path = project.path().join("trace-large.jsonl");

    let output = lpm(&project)
        .env("LPM_TS_RUNTIME_TRACE", "1")
        .env("LPM_TS_RUNTIME_TRACE_FILE", trace_path.as_os_str())
        .args(["scripts/large.ts"])
        .output()
        .expect("failed to run lpm on traced large TypeScript");

    assert!(
        output.status.success(),
        "traced large TypeScript exec must succeed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("307200"),
        "large source must execute after transform, got:\n{stdout}"
    );
    let events = read_ts_runtime_trace(&trace_path);
    assert!(
        has_persistent_transport_event(&events, "scripts/large.ts", "file"),
        "large TS source must use file fallback persistent transport, got: {events:?}"
    );
}

#[test]
fn exec_typescript_file_forwards_args_through_lpm_runtime() {
    let project = TempProject::empty(r#"{"name":"exec-test","version":"1.0.0"}"#);
    project.write_file(
        "scripts/args.ts",
        "const args: string[] = process.argv.slice(2);\nconsole.log(JSON.stringify(args));\n",
    );

    let output = lpm(&project)
        .args(["scripts/args.ts", "--", "--flag", "value"])
        .output()
        .expect("failed to run lpm exec on TypeScript args script");

    assert!(
        output.status.success(),
        "TypeScript exec must succeed through the LPM runtime:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains(r#"["--flag","value"]"#),
        "TypeScript exec must preserve script args, got:\n{stdout}"
    );
}

#[test]
fn exec_typescript_commonjs_file_ignores_type_only_exports_when_detecting_module_format() {
    let project = TempProject::empty(r#"{"name":"exec-test","version":"1.0.0"}"#);
    project.write_file(
        "scripts/seed.ts",
        concat!(
            "export type SeedMessage = string;\n",
            "const fs = require('node:fs');\n",
            "const message: SeedMessage = fs.existsSync('package.json') ? 'commonjs-ts' : 'missing';\n",
            "console.log(message);\n",
        ),
    );

    let output = lpm(&project)
        .args(["scripts/seed.ts"])
        .output()
        .expect("failed to run lpm exec on CommonJS TypeScript");

    assert!(
        output.status.success(),
        "type-only exports must not force CommonJS TypeScript into ESM:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("commonjs-ts"),
        "CommonJS TypeScript with type-only exports must keep require available, got:\n{stdout}"
    );
}

#[test]
fn exec_typescript_commonjs_file_ignores_type_only_imports_when_detecting_module_format() {
    let project = TempProject::empty(r#"{"name":"exec-test","version":"1.0.0"}"#);
    project.write_file("scripts/types.ts", "export type SeedMessage = string;\n");
    project.write_file(
        "scripts/seed.ts",
        concat!(
            "import type { SeedMessage } from './types';\n",
            "const fs = require('node:fs');\n",
            "const message: SeedMessage = fs.existsSync('package.json') ? 'import-type-commonjs-ts' : 'missing';\n",
            "module.exports = { message };\n",
            "console.log(module.exports.message);\n",
        ),
    );

    let output = lpm(&project)
        .args(["scripts/seed.ts"])
        .output()
        .expect("failed to run lpm exec on CommonJS TypeScript with import type");

    assert!(
        output.status.success(),
        "type-only imports must not force CommonJS TypeScript into ESM:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("import-type-commonjs-ts"),
        "CommonJS TypeScript with type-only imports must keep module available, got:\n{stdout}"
    );
}

#[test]
fn exec_typescript_commonjs_file_ignores_commented_esm_syntax_when_detecting_module_format() {
    let project = TempProject::empty(r#"{"name":"exec-test","version":"1.0.0"}"#);
    project.write_file(
        "scripts/seed.ts",
        concat!(
            "/*\n",
            "export const sample = 1;\n",
            "*/\n",
            "const fs = require('node:fs');\n",
            "console.log(fs.existsSync('package.json') ? 'commented-commonjs-ts' : 'missing');\n",
        ),
    );

    let output = lpm(&project)
        .args(["scripts/seed.ts"])
        .output()
        .expect("failed to run lpm exec on commented CommonJS TypeScript");

    assert!(
        output.status.success(),
        "commented ESM syntax must not force CommonJS TypeScript into ESM:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("commented-commonjs-ts"),
        "CommonJS TypeScript with commented ESM syntax must keep require available, got:\n{stdout}"
    );
}

#[test]
fn exec_typescript_file_treats_top_level_await_as_module() {
    let project = TempProject::empty(r#"{"name":"exec-test","version":"1.0.0"}"#);
    project.write_file(
        "scripts/seed.ts",
        "const value: string = await Promise.resolve('top-level-await-ts');\nconsole.log(value);\n",
    );

    let output = lpm(&project)
        .args(["scripts/seed.ts"])
        .output()
        .expect("failed to run lpm exec on top-level-await TypeScript");

    assert!(
        output.status.success(),
        "top-level await must select ESM format for TypeScript:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("top-level-await-ts"),
        "TypeScript with top-level await must execute as ESM, got:\n{stdout}"
    );
}

#[test]
fn exec_typescript_file_treats_parenthesized_top_level_await_as_module() {
    let project = TempProject::empty(r#"{"name":"exec-test","version":"1.0.0"}"#);
    project.write_file(
        "scripts/seed.ts",
        "const value: string = (await Promise.resolve('parenthesized-top-level-await-ts'));\nconsole.log(value);\n",
    );

    let output = lpm(&project)
        .args(["scripts/seed.ts"])
        .output()
        .expect("failed to run lpm exec on parenthesized top-level-await TypeScript");

    assert!(
        output.status.success(),
        "parenthesized top-level await must select ESM format for TypeScript:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("parenthesized-top-level-await-ts"),
        "TypeScript with parenthesized top-level await must execute as ESM, got:\n{stdout}"
    );
}

#[test]
fn exec_typescript_file_treats_import_meta_as_module() {
    let project = TempProject::empty(r#"{"name":"exec-test","version":"1.0.0"}"#);
    project.write_file(
        "scripts/seed.ts",
        "console.log(import.meta.url.startsWith('file:') ? 'import-meta-ts' : 'missing');\n",
    );

    let output = lpm(&project)
        .args(["scripts/seed.ts"])
        .output()
        .expect("failed to run lpm exec on import-meta TypeScript");

    assert!(
        output.status.success(),
        "import.meta must select ESM format for TypeScript:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("import-meta-ts"),
        "TypeScript with import.meta must execute as ESM, got:\n{stdout}"
    );
}

#[test]
fn exec_typescript_file_treats_multiline_named_export_as_module() {
    let project = TempProject::empty(r#"{"name":"exec-test","version":"1.0.0"}"#);
    project.write_file(
        "scripts/seed.ts",
        "const value: string = 'multiline-export-ts';\nexport\n{ value };\nconsole.log(value);\n",
    );

    let output = lpm(&project)
        .args(["scripts/seed.ts"])
        .output()
        .expect("failed to run lpm exec on multiline-export TypeScript");

    assert!(
        output.status.success(),
        "multiline named exports must select ESM format for TypeScript:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("multiline-export-ts"),
        "TypeScript with multiline named exports must execute as ESM, got:\n{stdout}"
    );
}

#[test]
fn exec_typescript_file_treats_compact_named_export_as_module() {
    let project = TempProject::empty(r#"{"name":"exec-test","version":"1.0.0"}"#);
    project.write_file(
        "scripts/seed.ts",
        "const value: string = 'compact-export-ts';\nexport{value};\nconsole.log(value);\n",
    );

    let output = lpm(&project)
        .args(["scripts/seed.ts"])
        .output()
        .expect("failed to run lpm exec on compact-export TypeScript");

    assert!(
        output.status.success(),
        "compact named exports must select ESM format for TypeScript:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("compact-export-ts"),
        "TypeScript with compact named exports must execute as ESM, got:\n{stdout}"
    );
}

#[test]
fn exec_mts_file_runs_as_esm_through_lpm_runtime() {
    let project = TempProject::empty(r#"{"name":"exec-test","version":"1.0.0"}"#);
    project.write_file(
        "scripts/module.mts",
        "export const value: string = 'managed-mts';\nconsole.log(value);\n",
    );

    let output = lpm(&project)
        .args(["scripts/module.mts"])
        .output()
        .expect("failed to run lpm exec on MTS");

    assert!(
        output.status.success(),
        "managed MTS exec must run as ESM:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("managed-mts"),
        "MTS execution must preserve ESM semantics, got:\n{stdout}"
    );
}

#[test]
fn exec_cts_file_runs_as_commonjs_through_lpm_runtime() {
    let project = TempProject::empty(r#"{"name":"exec-test","version":"1.0.0"}"#);
    project.write_file(
        "scripts/common.cts",
        concat!(
            "const fs = require('node:fs');\n",
            "const value: string = fs.existsSync('package.json') ? 'managed-cts' : 'missing';\n",
            "module.exports = { value };\n",
            "console.log(module.exports.value);\n",
        ),
    );

    let output = lpm(&project)
        .args(["scripts/common.cts"])
        .output()
        .expect("failed to run lpm exec on CTS");

    assert!(
        output.status.success(),
        "managed CTS exec must run as CommonJS:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("managed-cts"),
        "CTS execution must preserve CommonJS semantics, got:\n{stdout}"
    );
}

#[test]
fn exec_tsx_file_uses_lpm_runtime_without_project_local_tsx() {
    let project = TempProject::empty(r#"{"name":"exec-test","version":"1.0.0"}"#);
    write_fake_react_runtime(&project);
    project.write_file(
        "scripts/view.tsx",
        "const view = <main id=\"root\">hello</main>;\nconsole.log(JSON.stringify(view));\n",
    );

    let output = lpm(&project)
        .args(["scripts/view.tsx"])
        .output()
        .expect("failed to run lpm exec on TSX");

    assert!(
        output.status.success(),
        "managed TSX exec must succeed without local tsx:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains(r#""type":"main""#) && stdout.contains(r#""id":"root""#),
        "exec must transform TSX through the LPM runtime, got:\n{stdout}"
    );
}

#[test]
fn exec_tsx_file_transforms_jsx_fragments_with_project_react_runtime() {
    let project = TempProject::empty(r#"{"name":"exec-test","version":"1.0.0"}"#);
    write_fake_react_runtime(&project);
    project.write_file(
        "scripts/view.tsx",
        concat!(
            "const view = <><span id=\"x\" />fragment-text</>;\n",
            "console.log(JSON.stringify(view));\n",
        ),
    );

    let output = lpm(&project)
        .args(["scripts/view.tsx"])
        .output()
        .expect("failed to run lpm exec on TSX fragment");

    assert!(
        output.status.success(),
        "managed TSX exec must transform JSX fragments:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains(r#""type":"Fragment""#)
            && stdout.contains(r#""type":"span""#)
            && stdout.contains("fragment-text"),
        "exec must transform JSX fragments through the project React runtime, got:\n{stdout}"
    );
}

#[test]
fn exec_tsx_file_honors_classic_react_import_when_configured() {
    let project = TempProject::empty(r#"{"name":"exec-test","version":"1.0.0"}"#);
    write_fake_react_runtime(&project);
    project.write_file("tsconfig.json", r#"{"compilerOptions":{"jsx":"react"}}"#);
    project.write_file(
        "scripts/view.tsx",
        concat!(
            "import React from 'react';\n",
            "const view = <main id=\"classic\">classic-react</main>;\n",
            "console.log(JSON.stringify(view));\n",
        ),
    );

    let output = lpm(&project)
        .args(["scripts/view.tsx"])
        .output()
        .expect("failed to run lpm exec on classic React TSX");

    assert!(
        output.status.success(),
        "managed TSX exec must honor classic React imports when tsconfig requests them:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains(r#""id":"classic""#) && stdout.contains("classic-react"),
        "exec must use local React import semantics for classic TSX, got:\n{stdout}"
    );
}

#[test]
fn exec_tsx_file_preserves_typescript_generics_while_transforming_jsx() {
    let project = TempProject::empty(r#"{"name":"exec-test","version":"1.0.0"}"#);
    write_fake_react_runtime(&project);
    project.write_file(
        "scripts/view.tsx",
        concat!(
            "function id<T>(value: T): T { return value; }\n",
            "const view = <main id=\"root\">{id<string>('generic-tsx')}</main>;\n",
            "console.log(JSON.stringify(view));\n",
        ),
    );

    let output = lpm(&project)
        .args(["scripts/view.tsx"])
        .output()
        .expect("failed to run lpm exec on generic TSX");

    assert!(
        output.status.success(),
        "managed TSX exec must preserve TypeScript generics:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains(r#""type":"main""#) && stdout.contains("generic-tsx"),
        "exec must preserve TypeScript generics while transforming JSX, got:\n{stdout}"
    );
}

#[test]
fn exec_tsx_file_preserves_constrained_generic_arrows_while_transforming_jsx() {
    let project = TempProject::empty(r#"{"name":"exec-test","version":"1.0.0"}"#);
    write_fake_react_runtime(&project);
    project.write_file(
        "scripts/view.tsx",
        concat!(
            "const id = <T extends string>(value: T): T => value;\n",
            "const view = <main>{id('constrained-generic-tsx')}</main>;\n",
            "console.log(JSON.stringify(view));\n",
        ),
    );

    let output = lpm(&project)
        .args(["scripts/view.tsx"])
        .output()
        .expect("failed to run lpm exec on constrained generic TSX");

    assert!(
        output.status.success(),
        "managed TSX exec must preserve constrained generic arrows:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains(r#""type":"main""#) && stdout.contains("constrained-generic-tsx"),
        "exec must preserve constrained generic arrows while transforming JSX, got:\n{stdout}"
    );
}

#[test]
fn exec_tsx_file_preserves_generic_arrows_with_literal_delimiters_while_transforming_jsx() {
    let project = TempProject::empty(r#"{"name":"exec-test","version":"1.0.0"}"#);
    write_fake_react_runtime(&project);
    project.write_file(
        "scripts/view.tsx",
        concat!(
            "const defaulted = <T extends string>(value = ')'): T => value as T;\n",
            "const constrained = <T extends '>'>(value: T): T => value;\n",
            "const view = <main>{defaulted('default-param')}{constrained('>')}</main>;\n",
            "console.log(JSON.stringify(view));\n",
        ),
    );

    let output = lpm(&project)
        .args(["scripts/view.tsx"])
        .output()
        .expect("failed to run lpm exec on generic TSX with literal delimiters");

    assert!(
        output.status.success(),
        "managed TSX exec must preserve generic arrows with literal delimiters:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains(r#""type":"main""#)
            && stdout.contains("default-param")
            && stdout.contains(r#"">""#),
        "exec must preserve generic arrows with literal delimiters while transforming JSX, got:\n{stdout}"
    );
}

#[test]
fn exec_tsx_file_preserves_generic_arrows_with_regex_defaults_while_transforming_jsx() {
    let project = TempProject::empty(r#"{"name":"exec-test","version":"1.0.0"}"#);
    write_fake_react_runtime(&project);
    project.write_file(
        "scripts/view.tsx",
        concat!(
            r"const id = <T extends string>(value = /\)/): T => value.source as T;",
            "\n",
            r"const view = <main>{id(/regex-default/)}</main>;",
            "\n",
            "console.log(JSON.stringify(view));\n",
        ),
    );

    let output = lpm(&project)
        .args(["scripts/view.tsx"])
        .output()
        .expect("failed to run lpm exec on generic TSX with regex defaults");

    assert!(
        output.status.success(),
        "managed TSX exec must preserve generic arrows with regex defaults:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains(r#""type":"main""#) && stdout.contains("regex-default"),
        "exec must preserve generic arrows with regex defaults while transforming JSX, got:\n{stdout}"
    );
}

#[test]
fn exec_tsx_file_preserves_regex_literals_inside_jsx_braces() {
    let project = TempProject::empty(r#"{"name":"exec-test","version":"1.0.0"}"#);
    write_fake_react_runtime(&project);
    project.write_file(
        "scripts/view.tsx",
        concat!(
            r"const spread = /\}/.test('}') ? { role: 'presentation' } : {};",
            "\n",
            r"const view = <main data-ok={/\}/.test('}') ? 'attr-regex' : 'missing'} {...spread}>{/\}/.test('}') ? 'child-regex' : 'missing'}</main>;",
            "\n",
            "console.log(JSON.stringify(view));\n",
        ),
    );

    let output = lpm(&project)
        .args(["scripts/view.tsx"])
        .output()
        .expect("failed to run lpm exec on TSX with regex literals inside braces");

    assert!(
        output.status.success(),
        "managed TSX exec must preserve regex literals inside JSX braces:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains(r#""data-ok":"attr-regex""#)
            && stdout.contains(r#""role":"presentation""#)
            && stdout.contains("child-regex"),
        "exec must preserve regex literals inside JSX braces, got:\n{stdout}"
    );
}

#[test]
fn exec_tsx_file_preserves_hashbang_while_transforming_jsx() {
    let project = TempProject::empty(r#"{"name":"exec-test","version":"1.0.0"}"#);
    write_fake_react_runtime(&project);
    project.write_file(
        "scripts/view.tsx",
        concat!(
            "#!/usr/bin/env node\n",
            "const view = <main>hashbang-tsx</main>;\n",
            "console.log(JSON.stringify(view));\n",
        ),
    );

    let output = lpm(&project)
        .args(["scripts/view.tsx"])
        .output()
        .expect("failed to run lpm exec on hashbang TSX");

    assert!(
        output.status.success(),
        "managed TSX exec must keep hashbang first:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("hashbang-tsx"),
        "exec must preserve hashbang TSX execution, got:\n{stdout}"
    );
}

#[test]
fn exec_tsx_file_preserves_strict_directive_while_transforming_jsx() {
    let project = TempProject::empty(r#"{"name":"exec-test","version":"1.0.0"}"#);
    write_fake_react_runtime(&project);
    project.write_file(
        "scripts/view.tsx",
        concat!(
            "\"use strict\";\n",
            "function strictThis() { return this === undefined ? 'strict-mode' : 'sloppy-mode'; }\n",
            "const view = <main>{strictThis()}</main>;\n",
            "console.log(JSON.stringify(view));\n",
        ),
    );

    let output = lpm(&project)
        .args(["scripts/view.tsx"])
        .output()
        .expect("failed to run lpm exec on strict TSX");

    assert!(
        output.status.success(),
        "managed TSX exec must keep strict directive first:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("strict-mode") && !stdout.contains("sloppy-mode"),
        "exec must preserve strict directive semantics, got:\n{stdout}"
    );
}

#[test]
fn exec_tsx_file_preserves_strict_directive_with_line_comment_while_transforming_jsx() {
    let project = TempProject::empty(r#"{"name":"exec-test","version":"1.0.0"}"#);
    write_fake_react_runtime(&project);
    project.write_file(
        "scripts/view.tsx",
        concat!(
            "\"use strict\" // strict prologue comment\n",
            "function strictThis() { return this === undefined ? 'strict-line-comment' : 'sloppy-mode'; }\n",
            "const view = <main>{strictThis()}</main>;\n",
            "console.log(JSON.stringify(view));\n",
        ),
    );

    let output = lpm(&project)
        .args(["scripts/view.tsx"])
        .output()
        .expect("failed to run lpm exec on strict TSX with line comment");

    assert!(
        output.status.success(),
        "managed TSX exec must keep strict directive with line comment first:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("strict-line-comment") && !stdout.contains("sloppy-mode"),
        "exec must preserve strict directive line-comment semantics, got:\n{stdout}"
    );
}

#[test]
fn exec_tsx_file_preserves_strict_directive_with_block_comment_while_transforming_jsx() {
    let project = TempProject::empty(r#"{"name":"exec-test","version":"1.0.0"}"#);
    write_fake_react_runtime(&project);
    project.write_file(
        "scripts/view.tsx",
        concat!(
            "\"use strict\" /* strict prologue comment */;\n",
            "function strictThis() { return this === undefined ? 'strict-block-comment' : 'sloppy-mode'; }\n",
            "const view = <main>{strictThis()}</main>;\n",
            "console.log(JSON.stringify(view));\n",
        ),
    );

    let output = lpm(&project)
        .args(["scripts/view.tsx"])
        .output()
        .expect("failed to run lpm exec on strict TSX with block comment");

    assert!(
        output.status.success(),
        "managed TSX exec must keep strict directive with block comment first:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("strict-block-comment") && !stdout.contains("sloppy-mode"),
        "exec must preserve strict directive block-comment semantics, got:\n{stdout}"
    );
}

#[test]
fn exec_tsx_file_allows_user_jsx_helper_named_binding() {
    let project = TempProject::empty(r#"{"name":"exec-test","version":"1.0.0"}"#);
    write_fake_react_runtime(&project);
    project.write_file(
        "scripts/view.tsx",
        concat!(
            "const __lpmJsx = () => 'user-helper';\n",
            "const view = <main>{__lpmJsx()}</main>;\n",
            "console.log(JSON.stringify(view));\n",
        ),
    );

    let output = lpm(&project)
        .args(["scripts/view.tsx"])
        .output()
        .expect("failed to run lpm exec on TSX with user helper binding");

    assert!(
        output.status.success(),
        "managed TSX exec must not collide with user __lpmJsx binding:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("user-helper"),
        "exec must preserve user __lpmJsx binding, got:\n{stdout}"
    );
}

#[test]
fn exec_tsx_file_allows_user_symbol_named_binding() {
    let project = TempProject::empty(r#"{"name":"exec-test","version":"1.0.0"}"#);
    write_fake_react_runtime(&project);
    project.write_file(
        "scripts/view.tsx",
        concat!(
            "const Symbol = { for: () => 'user-symbol' };\n",
            "const view = <main>{Symbol.for()}</main>;\n",
            "console.log(JSON.stringify(view));\n",
        ),
    );

    let output = lpm(&project)
        .args(["scripts/view.tsx"])
        .output()
        .expect("failed to run lpm exec on TSX with user Symbol binding");

    assert!(
        output.status.success(),
        "managed TSX exec must not collide with user Symbol binding:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("user-symbol"),
        "exec must preserve user Symbol binding, got:\n{stdout}"
    );
}

#[test]
fn exec_tsx_file_allows_user_global_this_named_binding() {
    let project = TempProject::empty(r#"{"name":"exec-test","version":"1.0.0"}"#);
    write_fake_react_runtime(&project);
    project.write_file(
        "scripts/view.tsx",
        concat!(
            "const globalThis = { local: true };\n",
            "const view = <main>{globalThis.local ? 'local-globalThis' : 'missing'}</main>;\n",
            "console.log(JSON.stringify(view));\n",
        ),
    );

    let output = lpm(&project)
        .args(["scripts/view.tsx"])
        .output()
        .expect("failed to run lpm exec on TSX with user globalThis binding");

    assert!(
        output.status.success(),
        "managed TSX exec must not collide with user globalThis binding:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("local-globalThis"),
        "exec must preserve user globalThis binding, got:\n{stdout}"
    );
}

#[test]
fn exec_tsx_file_ignores_stale_transform_cache_after_runtime_output_changes() {
    let project = TempProject::empty(r#"{"name":"exec-test","version":"1.0.0"}"#);
    write_fake_react_runtime(&project);
    let source = concat!(
        "const globalThis = { local: true };\n",
        "const view = <main>{globalThis.local ? 'local-globalThis' : 'missing'}</main>;\n",
        "console.log(JSON.stringify(view));\n",
    );
    project.write_file("scripts/view.tsx", source);

    let first_output = lpm(&project)
        .args(["scripts/view.tsx"])
        .output()
        .expect("failed to populate LPM TS transform cache");
    assert!(
        first_output.status.success(),
        "initial managed TSX exec must populate transform cache:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&first_output.stdout),
        String::from_utf8_lossy(&first_output.stderr),
    );
    let cache_dir = transform_cache_dir(&project);
    let mut corrupted_entries = 0;
    for entry in std::fs::read_dir(&cache_dir).expect("transform cache dir must exist") {
        let entry = entry.expect("cache entry must be readable");
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) == Some("json") {
            let text = std::fs::read_to_string(&path).expect("cache entry must be utf8 JSON");
            let mut json: serde_json::Value =
                serde_json::from_str(&text).expect("cache entry must be JSON");
            json["runtimeVersion"] = serde_json::json!("stale-runtime");
            json["code"] = serde_json::json!("throw new Error('stale cache was trusted');\n");
            std::fs::write(
                &path,
                serde_json::to_vec(&json).expect("serialize stale cache"),
            )
            .expect("rewrite stale cache entry");
            corrupted_entries += 1;
        }
    }
    assert!(
        corrupted_entries > 0,
        "initial run must create at least one transform cache entry"
    );

    let output = lpm(&project)
        .args(["scripts/view.tsx"])
        .output()
        .expect("failed to run lpm exec with stale transform cache");

    assert!(
        output.status.success(),
        "managed TSX exec must ignore stale transform cache entries:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("local-globalThis"),
        "exec must ignore stale transform cache entries after runtime output changes, got:\n{stdout}"
    );
}

#[cfg(unix)]
#[test]
fn exec_tsx_file_reports_mismatched_closing_tags_without_hanging() {
    use std::os::unix::process::CommandExt;

    let project = TempProject::empty(r#"{"name":"exec-test","version":"1.0.0"}"#);
    write_fake_react_runtime(&project);
    project.write_file(
        "scripts/view.tsx",
        "const view = <main><span></main>;\nconsole.log(view);\n",
    );

    let mut command = lpm_spawnable(&project);
    command.args(["scripts/view.tsx"]);
    // SAFETY: this test-only pre-exec hook only moves the child process into
    // its own process group before it can spawn Node, so timeout cleanup can
    // kill the whole group without touching the test runner.
    unsafe {
        command.pre_exec(|| {
            // SAFETY: `setpgid(0, 0)` applies to the just-forked child before
            // exec and uses no borrowed memory from the parent process.
            if libc::setpgid(0, 0) == 0 {
                Ok(())
            } else {
                Err(std::io::Error::last_os_error())
            }
        });
    }

    let mut child = command
        .spawn()
        .expect("failed to spawn lpm exec on mismatched TSX");
    let started = Instant::now();
    while child
        .try_wait()
        .expect("failed to poll lpm exec child")
        .is_none()
    {
        if started.elapsed() > Duration::from_secs(10) {
            // SAFETY: the child was placed in its own process group above.
            // A negative pid targets that group and prevents an orphaned Node
            // process from keeping captured pipes open.
            unsafe {
                libc::kill(-(child.id() as libc::pid_t), libc::SIGKILL);
            }
            let output = child
                .wait_with_output()
                .expect("failed to collect killed lpm exec output");
            panic!(
                "mismatched TSX closing tags must fail without hanging:\nstdout: {}\nstderr: {}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr),
            );
        }
        std::thread::sleep(Duration::from_millis(20));
    }

    let output = child
        .wait_with_output()
        .expect("failed to collect lpm exec output");
    assert!(
        !output.status.success(),
        "mismatched TSX closing tags must fail:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("LPM OXC TypeScript parse failed")
            && stderr.contains("Expected corresponding JSX closing tag"),
        "mismatched TSX closing tags must report an OXC JSX syntax error, got:\n{stderr}"
    );
}

#[test]
fn exec_tsx_file_transforms_jsx_inside_child_expressions() {
    let project = TempProject::empty(r#"{"name":"exec-test","version":"1.0.0"}"#);
    write_fake_react_runtime(&project);
    project.write_file(
        "scripts/view.tsx",
        concat!(
            "const ok: boolean = true;\n",
            "const view = <main>{ok && <span id=\"x\" />}</main>;\n",
            "console.log(JSON.stringify(view));\n",
        ),
    );

    let output = lpm(&project)
        .args(["scripts/view.tsx"])
        .output()
        .expect("failed to run lpm exec on expression-nested TSX");

    assert!(
        output.status.success(),
        "managed TSX exec must transform JSX inside child expressions:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains(r#""type":"span""#) && stdout.contains(r#""id":"x""#),
        "exec must transform JSX nested inside child expressions, got:\n{stdout}"
    );
}

#[test]
fn exec_tsx_file_ignores_comment_only_child_expressions() {
    let project = TempProject::empty(r#"{"name":"exec-test","version":"1.0.0"}"#);
    write_fake_react_runtime(&project);
    project.write_file(
        "scripts/view.tsx",
        concat!(
            "const view = <main>{/* hidden */}<span id=\"x\" /></main>;\n",
            "console.log(JSON.stringify(view));\n",
        ),
    );

    let output = lpm(&project)
        .args(["scripts/view.tsx"])
        .output()
        .expect("failed to run lpm exec on comment-child TSX");

    assert!(
        output.status.success(),
        "comment-only JSX child expressions must not become empty call arguments:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains(r#""type":"span""#) && stdout.contains(r#""id":"x""#),
        "exec must ignore comment-only JSX child expressions and keep following children, got:\n{stdout}"
    );
}

#[test]
fn exec_tsx_file_transforms_nested_jsx_children_after_whitespace() {
    let project = TempProject::empty(r#"{"name":"exec-test","version":"1.0.0"}"#);
    write_fake_react_runtime(&project);
    project.write_file(
        "scripts/view.tsx",
        concat!(
            "const view = <main>\n",
            "  <span id=\"x\" />\n",
            "</main>;\n",
            "console.log(JSON.stringify(view));\n",
        ),
    );

    let output = lpm(&project)
        .args(["scripts/view.tsx"])
        .output()
        .expect("failed to run lpm exec on nested TSX children");

    assert!(
        output.status.success(),
        "managed TSX exec must transform nested JSX children after whitespace:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains(r#""type":"span""#) && stdout.contains(r#""id":"x""#),
        "exec must transform nested JSX children after whitespace, got:\n{stdout}"
    );
}

#[test]
fn exec_tsx_file_transforms_jsx_inside_spread_attributes() {
    let project = TempProject::empty(r#"{"name":"exec-test","version":"1.0.0"}"#);
    write_fake_react_runtime(&project);
    project.write_file(
        "scripts/view.tsx",
        concat!(
            "const view = <main {...{ child: <span id=\"x\" /> }} />;\n",
            "console.log(JSON.stringify(view.props.child));\n",
        ),
    );

    let output = lpm(&project)
        .args(["scripts/view.tsx"])
        .output()
        .expect("failed to run lpm exec on spread-attribute TSX");

    assert!(
        output.status.success(),
        "managed TSX exec must transform JSX inside spread attributes:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains(r#""type":"span""#) && stdout.contains(r#""id":"x""#),
        "exec must transform JSX nested inside spread attributes, got:\n{stdout}"
    );
}

#[test]
fn exec_tsx_file_preserves_spread_attribute_order() {
    let project = TempProject::empty(r#"{"name":"exec-test","version":"1.0.0"}"#);
    write_fake_react_runtime(&project);
    project.write_file(
        "scripts/view.tsx",
        concat!(
            "const spreadWins = <main id=\"static\" {...{ id: 'spread' }} />;\n",
            "const explicitWins = <main {...{ id: 'spread' }} id=\"static\" />;\n",
            "console.log(`${spreadWins.props.id}:${explicitWins.props.id}`);\n",
        ),
    );

    let output = lpm(&project)
        .args(["scripts/view.tsx"])
        .output()
        .expect("failed to run lpm exec on ordered spread attributes");

    assert!(
        output.status.success(),
        "managed TSX exec must preserve spread attribute order:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("spread:static"),
        "exec must preserve JSX spread attribute override order, got:\n{stdout}"
    );
}

#[test]
fn exec_tsx_file_uses_project_local_tsx_when_node_cannot_load_lpm_runtime() {
    let project = TempProject::empty(r#"{"name":"exec-test","version":"1.0.0"}"#);
    project.write_file("scripts/view.tsx", "export const view = <main />;\n");
    write_fake_node(&project, "v20.5.0");
    write_fake_tsx(&project);

    let output = lpm(&project)
        .args(["scripts/view.tsx"])
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
fn exec_typescript_parent_spawns_typescript_child_with_lpm_runtime() {
    let project = TempProject::empty(r#"{"name":"exec-test","version":"1.0.0"}"#);
    project.write_file(
        "tsconfig.json",
        r#"{"compilerOptions":{"baseUrl":".","paths":{"@fixtures/*":["fixtures/*"]}}}"#,
    );
    project.write_file(
        "fixtures/value.ts",
        "export const value: string = 'child-ts';\n",
    );
    project.write_file(
        "scripts/child.ts",
        "import { value } from '@fixtures/value';\nconsole.log(value);\n",
    );
    project.write_file(
        "scripts/parent.ts",
        concat!(
            "const { spawnSync } = require('node:child_process');\n",
            "const result = spawnSync(process.execPath, ['scripts/child.ts'], { encoding: 'utf8' });\n",
            "if (result.status !== 0) {\n",
            "  console.error(result.stderr);\n",
            "  process.exit(result.status || 1);\n",
            "}\n",
            "process.stdout.write(result.stdout);\n",
        ),
    );

    let output = lpm(&project)
        .args(["scripts/parent.ts"])
        .output()
        .expect("failed to run lpm exec parent TypeScript script");

    assert!(
        output.status.success(),
        "TS parent must propagate LPM runtime to TS child:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("child-ts"),
        "TS child must run with tsconfig path resolution, got:\n{stdout}"
    );
}

#[test]
fn exec_typescript_parent_spawns_javascript_child_with_lpm_runtime() {
    let project = TempProject::empty(r#"{"name":"exec-test","version":"1.0.0"}"#);
    project.write_file("scripts/child.js", "console.log('child-js');\n");
    project.write_file(
        "scripts/parent.ts",
        concat!(
            "const { spawnSync } = require('node:child_process');\n",
            "const result = spawnSync(process.execPath, ['scripts/child.js'], { encoding: 'utf8' });\n",
            "process.stdout.write(result.stdout);\n",
            "process.exit(result.status || 0);\n",
        ),
    );

    let output = lpm(&project)
        .args(["scripts/parent.ts"])
        .output()
        .expect("failed to run lpm exec parent TypeScript script");

    assert!(
        output.status.success(),
        "TS parent must still spawn JS children:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("child-js"),
        "JS child output must pass through, got:\n{stdout}"
    );
}

#[test]
fn exec_plain_node_disables_typescript_child_augmentation() {
    let project = TempProject::empty(r#"{"name":"exec-test","version":"1.0.0"}"#);
    project.write_file(
        "tsconfig.json",
        r#"{"compilerOptions":{"baseUrl":".","paths":{"@fixtures/*":["fixtures/*"]}}}"#,
    );
    project.write_file(
        "fixtures/value.ts",
        "export const value: string = 'child-ts';\n",
    );
    project.write_file(
        "scripts/child.ts",
        "import { value } from '@fixtures/value';\nconsole.log(value);\n",
    );
    project.write_file(
        "scripts/parent.ts",
        concat!(
            "const { spawnSync } = require('node:child_process');\n",
            "const result = spawnSync(process.execPath, ['scripts/child.ts'], { encoding: 'utf8' });\n",
            "process.exit(result.status === 0 ? 1 : 0);\n",
        ),
    );

    let output = lpm(&project)
        .args(["--plain-node", "scripts/parent.ts"])
        .output()
        .expect("failed to run lpm exec --plain-node");

    assert!(
        output.status.success(),
        "--plain-node must disable LPM TS child augmentation:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

#[test]
fn exec_plain_node_refuses_project_local_tsx_for_typescript() {
    let project = TempProject::empty(r#"{"name":"exec-test","version":"1.0.0"}"#);
    project.write_file("scripts/seed.ts", "console.log('seed');\n");
    write_fake_node(&project, "v20.5.0");
    write_fake_tsx(&project);

    let output = lpm(&project)
        .args(["--plain-node", "scripts/seed.ts"])
        .output()
        .expect("failed to run lpm exec --plain-node on TypeScript");

    assert!(
        !output.status.success(),
        "--plain-node must not fall back to project-local tsx for TypeScript"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.contains("local-tsx"),
        "--plain-node must not invoke project-local tsx, got:\n{stdout}"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("--plain-node"),
        "plain-node TypeScript refusal must explain the selected mode, got:\n{stderr}"
    );
}

#[test]
fn exec_strips_inherited_node_options_before_installing_lpm_runtime() {
    let project = TempProject::empty(r#"{"name":"exec-test","version":"1.0.0"}"#);
    project.write_file("bad-preload.cjs", "process.exit(99);\n");
    project.write_file(
        "scripts/seed.ts",
        "const message: string = 'scrubbed-node-options';\nconsole.log(message);\n",
    );

    let bad_preload = project.path().join("bad-preload.cjs");
    let output = lpm(&project)
        .env(
            "NODE_OPTIONS",
            format!("--require={}", bad_preload.display()),
        )
        .args(["scripts/seed.ts"])
        .output()
        .expect("failed to run lpm exec with inherited NODE_OPTIONS");

    assert!(
        output.status.success(),
        "inherited NODE_OPTIONS must not hijack planning or execution:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("scrubbed-node-options"),
        "managed TS runtime must still run after scrubbing NODE_OPTIONS, got:\n{stdout}"
    );
}

#[test]
fn exec_project_env_cannot_replace_lpm_transformer_helper() {
    let project = TempProject::empty(r#"{"name":"exec-test","version":"1.0.0"}"#);
    project.write_file(".env", "LPM_TS_RUNTIME_TRANSFORMER=/definitely/not/lpm\n");
    project.write_file(
        "scripts/seed.ts",
        "const message: string = 'controlled-transformer';\nconsole.log(message);\n",
    );

    let output = lpm(&project)
        .args(["scripts/seed.ts"])
        .output()
        .expect("failed to run lpm exec with project env transformer override");

    assert!(
        output.status.success(),
        "project env must not replace the controlled LPM transformer helper:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("controlled-transformer"),
        "managed TS runtime must use LPM's transformer helper, got:\n{stdout}"
    );
}

#[test]
fn exec_missing_file_under_json_emits_error_envelope_on_stdout() {
    let project = TempProject::empty(r#"{"name":"exec-test","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args(["--json", "scripts/missing.js"])
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
