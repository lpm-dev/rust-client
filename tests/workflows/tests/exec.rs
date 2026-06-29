mod support;

use std::path::Path;
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
fn exec_js_file_does_not_install_lpm_typescript_runtime() {
    let project = TempProject::empty(r#"{"name":"exec-test","version":"1.0.0"}"#);
    project.write_file(
        "scripts/plain.js",
        "console.log(process.env.NODE_OPTIONS || 'no-node-options');\n",
    );

    let output = lpm(&project)
        .args(["exec", "scripts/plain.js"])
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
        .args(["exec", "scripts/plain.js"])
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
        .args(["exec", "scripts/plain.js"])
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
        .args(["exec", "scripts/plain.js"])
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
        .args(["exec", "scripts/plain.js"])
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
        .args(["exec", "scripts/seed.ts"])
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
fn exec_typescript_file_forwards_args_through_lpm_runtime() {
    let project = TempProject::empty(r#"{"name":"exec-test","version":"1.0.0"}"#);
    project.write_file(
        "scripts/args.ts",
        "const args: string[] = process.argv.slice(2);\nconsole.log(JSON.stringify(args));\n",
    );

    let output = lpm(&project)
        .args(["exec", "scripts/args.ts", "--", "--flag", "value"])
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
        .args(["exec", "scripts/seed.ts"])
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
        .args(["exec", "scripts/seed.ts"])
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
        .args(["exec", "scripts/seed.ts"])
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
        .args(["exec", "scripts/seed.ts"])
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
        .args(["exec", "scripts/seed.ts"])
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
        .args(["exec", "scripts/seed.ts"])
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
        .args(["exec", "scripts/seed.ts"])
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
fn exec_tsx_file_uses_lpm_runtime_without_project_local_tsx() {
    let project = TempProject::empty(r#"{"name":"exec-test","version":"1.0.0"}"#);
    project.write_file(
        "scripts/view.tsx",
        "const view = <main id=\"root\">hello</main>;\nconsole.log(JSON.stringify(view));\n",
    );

    let output = lpm(&project)
        .args(["exec", "scripts/view.tsx"])
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
fn exec_tsx_file_preserves_typescript_generics_while_transforming_jsx() {
    let project = TempProject::empty(r#"{"name":"exec-test","version":"1.0.0"}"#);
    project.write_file(
        "scripts/view.tsx",
        concat!(
            "function id<T>(value: T): T { return value; }\n",
            "const view = <main id=\"root\">{id<string>('generic-tsx')}</main>;\n",
            "console.log(JSON.stringify(view));\n",
        ),
    );

    let output = lpm(&project)
        .args(["exec", "scripts/view.tsx"])
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

#[cfg(unix)]
#[test]
fn exec_tsx_file_reports_mismatched_closing_tags_without_hanging() {
    use std::os::unix::process::CommandExt;

    let project = TempProject::empty(r#"{"name":"exec-test","version":"1.0.0"}"#);
    project.write_file(
        "scripts/view.tsx",
        "const view = <main><span></main>;\nconsole.log(view);\n",
    );

    let mut command = lpm_spawnable(&project);
    command.args(["exec", "scripts/view.tsx"]);
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
        stderr.contains("Invalid TSX"),
        "mismatched TSX closing tags must report a TSX syntax error, got:\n{stderr}"
    );
}

#[test]
fn exec_tsx_file_transforms_jsx_inside_child_expressions() {
    let project = TempProject::empty(r#"{"name":"exec-test","version":"1.0.0"}"#);
    project.write_file(
        "scripts/view.tsx",
        concat!(
            "const ok: boolean = true;\n",
            "const view = <main>{ok && <span id=\"x\" />}</main>;\n",
            "console.log(JSON.stringify(view));\n",
        ),
    );

    let output = lpm(&project)
        .args(["exec", "scripts/view.tsx"])
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
    project.write_file(
        "scripts/view.tsx",
        concat!(
            "const view = <main>{/* hidden */}<span id=\"x\" /></main>;\n",
            "console.log(JSON.stringify(view));\n",
        ),
    );

    let output = lpm(&project)
        .args(["exec", "scripts/view.tsx"])
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
        .args(["exec", "scripts/view.tsx"])
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
    project.write_file(
        "scripts/view.tsx",
        concat!(
            "const view = <main {...{ child: <span id=\"x\" /> }} />;\n",
            "console.log(JSON.stringify(view.props.child));\n",
        ),
    );

    let output = lpm(&project)
        .args(["exec", "scripts/view.tsx"])
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
    project.write_file(
        "scripts/view.tsx",
        concat!(
            "const spreadWins = <main id=\"static\" {...{ id: 'spread' }} />;\n",
            "const explicitWins = <main {...{ id: 'spread' }} id=\"static\" />;\n",
            "console.log(`${spreadWins.props.id}:${explicitWins.props.id}`);\n",
        ),
    );

    let output = lpm(&project)
        .args(["exec", "scripts/view.tsx"])
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
        .args(["exec", "scripts/parent.ts"])
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
        .args(["exec", "scripts/parent.ts"])
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
        .args(["exec", "--plain-node", "scripts/parent.ts"])
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
        .args(["exec", "--plain-node", "scripts/seed.ts"])
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
        .args(["exec", "scripts/seed.ts"])
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
