//! Workflow tests for `lpm lint` / `lpm fmt` / `lpm check` workspace mode.
//!
//! These tests primarily exercise the orchestrator's selection, JSON
//! envelope, and failure-mode contracts without requiring real tool
//! downloads. Happy-path coverage uses seeded local stand-ins: a cached
//! fake Biome binary for `fmt`, a fake root `tsc` for `check`, and one
//! optional real-network `lint` path gated behind `LPM_E2E_NETWORK=1`.

mod support;

#[cfg(unix)]
fn runner_lifetime_fixture(tool: &str, local: bool, workspace: bool, orphan: bool) -> TempProject {
    let project = TempProject::empty(
        r#"{"name":"runner-lifetime","private":true,"workspaces":["packages/*"]}"#,
    );
    let directory = if workspace { "packages/member/" } else { "" };
    let mut manifest = serde_json::json!({"name":"runner-member","version":"1.0.0"});
    if local {
        manifest["devDependencies"] = serde_json::json!({"vitest":"4.1.9"});
        write_unix_executable(
            &project
                .path()
                .join(format!("{directory}node_modules/.bin/vitest")),
            "#!/bin/sh\nexec node runner.cjs\n",
        );
    } else {
        manifest["scripts"] = serde_json::json!({tool:"node runner.cjs"});
    }
    if tool == "lint" {
        project.write_file("lpm.json", r#"{"tools":{"oxlint":"1.0.0"}}"#);
        project.write_file(
            &format!("{directory}lpm.json"),
            r#"{"tools":{"oxlint":"1.0.0"}}"#,
        );
        seed_fake_plugin_script(
            &project,
            "oxlint",
            "1.0.0",
            "#!/bin/sh\nexec node runner.cjs\n",
        );
    }
    project.write_file(&format!("{directory}package.json"), &manifest.to_string());
    project.write_file(&format!("{directory}runner.cjs"), &format!(
        "const fs=require('fs'); const child=require('child_process').spawn(process.execPath,['-e',\"setInterval(()=>require('fs').appendFileSync('heartbeat','x'),20)\"],{{stdio:'inherit'}}); fs.writeFileSync('ready',String(child.pid)); {}",
        if orphan { "setTimeout(()=>process.exit(7),100);" } else { "setInterval(()=>{},1000);" }
    ));
    project
}

#[cfg(unix)]
fn run_lifetime_case(tool: &str, local: bool, workspace: bool, json: bool, orphan: bool) {
    use std::os::unix::process::CommandExt;
    use std::time::{Duration, Instant};
    let project = runner_lifetime_fixture(tool, local, workspace, orphan);
    let directory = if workspace {
        project.path().join("packages/member")
    } else {
        project.path().to_path_buf()
    };
    let output_path = project.path().join("output.json");
    let mut command = lpm_spawnable(&project);
    if json {
        command.arg("--json");
    }
    command.arg(tool);
    if workspace {
        command.arg("--all");
    }
    command
        .process_group(0)
        .stdout(std::fs::File::create(&output_path).unwrap())
        .stderr(std::process::Stdio::null());
    let mut child = command.spawn().unwrap();
    let group = child.id() as i32;
    let ready_deadline = Instant::now() + Duration::from_secs(10);
    while !directory.join("heartbeat").exists() && Instant::now() < ready_deadline {
        if child.try_wait().unwrap().is_some() {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let ready = directory.join("heartbeat").exists();
    if ready && !orphan {
        // SAFETY: this PID is the owned fixture child, not its process group.
        unsafe {
            libc::kill(group, libc::SIGTERM);
        }
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
    let before = std::fs::read(directory.join("heartbeat")).unwrap_or_default();
    std::thread::sleep(Duration::from_millis(200));
    let after = std::fs::read(directory.join("heartbeat")).unwrap_or_default();
    // SAFETY: this process group contains only the isolated fixture processes.
    unsafe {
        libc::kill(-group, libc::SIGKILL);
    }
    let _ = child.wait();
    assert!(ready, "runner did not reach its ready gate");
    assert!(status.is_some(), "runner capture hung after parent exit");
    assert_eq!(
        before, after,
        "runner descendant remained active after CLI completion"
    );
    let code = status.unwrap().code();
    assert_eq!(
        code,
        Some(if orphan {
            if workspace { 1 } else { 7 }
        } else {
            143
        })
    );
    if json {
        let envelope: serde_json::Value =
            serde_json::from_slice(&std::fs::read(output_path).unwrap())
                .expect("one failure envelope");
        assert_eq!(envelope["success"], false);
    }
}

#[cfg(unix)]
#[test]
fn test_and_bench_stop_signals_stop_runner_descendants() {
    for tool in ["test", "bench"] {
        for local in [false, true] {
            for workspace in [false, true] {
                for json in [false, true] {
                    run_lifetime_case(tool, local, workspace, json, false);
                }
            }
        }
    }
}

#[cfg(unix)]
#[test]
fn test_and_bench_json_completes_when_descendants_inherit_output_pipes() {
    for tool in ["test", "bench"] {
        for local in [false, true] {
            for workspace in [false, true] {
                run_lifetime_case(tool, local, workspace, true, true);
            }
        }
    }
}

#[test]
fn test_and_bench_json_keeps_pre_hook_services_until_the_script_finishes() {
    for tool in ["test", "bench"] {
        let pre = format!("pre{tool}");
        let project = TempProject::empty(
            &serde_json::json!({
                "name":"hook-service","version":"1.0.0",
                "scripts":{pre:"node start.cjs",tool:"node check.cjs"}
            })
            .to_string(),
        );
        project.write_file("start.cjs", "const c=require('child_process').spawn(process.execPath,['-e',\"setInterval(()=>require('fs').appendFileSync('service-heartbeat','x'),10)\"],{stdio:'ignore'}); c.unref();");
        project.write_file("check.cjs", "const fs=require('fs');setTimeout(()=>{const a=fs.existsSync('service-heartbeat')?fs.readFileSync('service-heartbeat','utf8'):'';setTimeout(()=>{const b=fs.existsSync('service-heartbeat')?fs.readFileSync('service-heartbeat','utf8'):'';process.exit(b.length>a.length?0:8)},150)},150);");
        let output = lpm(&project).args(["--json", tool]).output().unwrap();
        assert!(
            output.status.success(),
            "pre-hook service stopped before the main script: {}",
            String::from_utf8_lossy(&output.stdout)
        );
        let before = project.read_file("service-heartbeat");
        std::thread::sleep(std::time::Duration::from_millis(150));
        assert_eq!(
            before,
            project.read_file("service-heartbeat"),
            "service survived the script sequence"
        );
    }
}

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use support::assertions::parse_json_output;
use support::{TempProject, lpm, lpm_spawnable};

#[cfg(unix)]
const WORKSPACE_MEMBERS: [&str; 3] = ["packages/utils", "packages/core", "packages/app"];

#[cfg(unix)]
const TSGO_VERSION: &str = "7.0.0-dev.20260707.2";

#[cfg(unix)]
fn current_plugin_platform() -> &'static str {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("macos", "aarch64") => "darwin-arm64",
        ("macos", "x86_64") => "darwin-x64",
        ("linux", "x86_64") => "linux-x64",
        ("linux", "aarch64") => "linux-arm64",
        ("windows", "x86_64") => "win-x64",
        other => panic!("unsupported plugin test platform: {other:?}"),
    }
}

#[cfg(unix)]
fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::Digest;

    let mut hasher = sha2::Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

#[cfg(unix)]
fn write_unix_executable(path: &std::path::Path, script: &str) {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("failed to create executable parent dir");
    }
    std::fs::write(path, script).expect("failed to write executable script");
    let mut perms = std::fs::metadata(path)
        .expect("failed to stat executable script")
        .permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(path, perms).expect("failed to chmod executable script");
}

#[cfg(unix)]
fn seed_workspace_tool_pin(project: &TempProject, tool: &str, version: &str) {
    let body = format!(r#"{{"tools":{{"{tool}":"{version}"}}}}"#);
    project.write_file("lpm.json", &body);
    for member in WORKSPACE_MEMBERS {
        project.write_file(&format!("{member}/lpm.json"), &body);
    }
}

#[cfg(unix)]
fn seed_fake_plugin(project: &TempProject, plugin: &str, version: &str, marker_file: &str) {
    seed_fake_plugin_script(
        project,
        plugin,
        version,
        &format!("#!/bin/sh\n: > {marker_file}\n"),
    );
}

#[cfg(unix)]
fn seed_fake_plugin_script(project: &TempProject, plugin: &str, version: &str, script: &str) {
    let platform = current_plugin_platform();
    let plugin_dir = project
        .home()
        .join(".lpm")
        .join("plugins")
        .join(plugin)
        .join(version)
        .join(platform);
    let bin_path = plugin_dir.join(plugin);
    let sidecar_path = plugin_dir.join(".lpm-plugin.json");
    write_unix_executable(&bin_path, script);

    let hash = sha256_hex(&std::fs::read(&bin_path).expect("failed to read fake plugin binary"));
    let sidecar = serde_json::json!({
        "schema_version": 1,
        "plugin_name": plugin,
        "version": version,
        "platform": platform,
        "asset_name": plugin,
        "asset_url": format!("https://example.invalid/{plugin}"),
        "asset_sha256": hash,
        "binary_sha256": hash,
        "verification_source": "bundled",
        "verified_at_unix": 0,
    });
    std::fs::create_dir_all(&plugin_dir).expect("failed to create fake plugin dir");
    std::fs::write(
        &sidecar_path,
        serde_json::to_vec_pretty(&sidecar).expect("failed to serialize fake sidecar"),
    )
    .expect("failed to write fake plugin sidecar");
}

#[cfg(unix)]
fn seed_fake_root_tsc(project: &TempProject, marker_file: &str) {
    let script = format!("#!/bin/sh\n: > {marker_file}\n");
    let bin_path = project.path().join("node_modules").join(".bin").join("tsc");
    write_unix_executable(&bin_path, &script);
}

#[cfg(unix)]
fn current_engine_platform() -> (&'static str, &'static str) {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("macos", "aarch64") => ("darwin-arm64", "lib/tsgo"),
        ("macos", "x86_64") => ("darwin-x64", "lib/tsgo"),
        ("linux", "x86_64") => ("linux-x64", "lib/tsgo"),
        ("linux", "arm") => ("linux-arm", "lib/tsgo"),
        ("linux", "aarch64") => ("linux-arm64", "lib/tsgo"),
        ("windows", "x86_64") => ("win-x64", "lib/tsgo.exe"),
        ("windows", "aarch64") => ("win-arm64", "lib/tsgo.exe"),
        other => panic!("unsupported tsgo test platform: {other:?}"),
    }
}

#[cfg(unix)]
fn seeded_tsgo_sidecar_packages(platform: &str) -> Vec<serde_json::Value> {
    let (tarball_url, tarball_integrity) = match platform {
        "darwin-arm64" => (
            "https://registry.npmjs.org/@typescript/native-preview-darwin-arm64/-/native-preview-darwin-arm64-7.0.0-dev.20260707.2.tgz",
            "sha512-wny2pgKjGbiZtnOIHVa3tXC1UfDqxNEFzyPGmiqybedG8hipG2Nfp0l5UxbaKCjkLacUpH/W5bP2hBOMVhCOzg==",
        ),
        "darwin-x64" => (
            "https://registry.npmjs.org/@typescript/native-preview-darwin-x64/-/native-preview-darwin-x64-7.0.0-dev.20260707.2.tgz",
            "sha512-Afc7M5zOwo+GpfcYwz5Z8HMB2tPVsui7nNIqEuuFB73MPdVqNn/Wmpe4tP4MRri0AtJnJknoHBaTJ/VDAp/Jhw==",
        ),
        "linux-x64" => (
            "https://registry.npmjs.org/@typescript/native-preview-linux-x64/-/native-preview-linux-x64-7.0.0-dev.20260707.2.tgz",
            "sha512-du0dzi6y97Po5vDNdPJTyyijHCpaS22JLRnKZEJXBDaO9gCIymOv/5QQokFRuOlQm0bWl3i9PF4OVdGP6uAOQA==",
        ),
        "linux-arm" => (
            "https://registry.npmjs.org/@typescript/native-preview-linux-arm/-/native-preview-linux-arm-7.0.0-dev.20260707.2.tgz",
            "sha512-hJm/UOqZTr9FHmR7uNm8VGX4oKtfWk0Jem0zPeJFNC8ckGUfSBueyiEYMZB+XmRc1aG4x1E46y3CplP4CLHvGQ==",
        ),
        "linux-arm64" => (
            "https://registry.npmjs.org/@typescript/native-preview-linux-arm64/-/native-preview-linux-arm64-7.0.0-dev.20260707.2.tgz",
            "sha512-iITBa2WjjTI5N9t5l7Z4KoOSI+2zBlhbvFzsD/f8qX8QoKjz/Y4DPyBDgezYi8nkqjjksbgSOJ3/ykzhwrB9cg==",
        ),
        "win-x64" => (
            "https://registry.npmjs.org/@typescript/native-preview-win32-x64/-/native-preview-win32-x64-7.0.0-dev.20260707.2.tgz",
            "sha512-DL4u27stv0fo71sVhOzHSwE+YMZsbBijVI+kg5dLDLilSH79WFTJ8RSQ46vJrCMt+Gjlv/JOZP1PuLJDfioYeQ==",
        ),
        "win-arm64" => (
            "https://registry.npmjs.org/@typescript/native-preview-win32-arm64/-/native-preview-win32-arm64-7.0.0-dev.20260707.2.tgz",
            "sha512-SsAwfhyHJ1akgBc+99z4+hwdbHsdWaKB8EwCNIMA6JfSLMeUjffrYvxu+vfMyxVtOVOz7RrRXRoiDiu4a2sCtg==",
        ),
        other => panic!("unsupported seeded tsgo platform: {other}"),
    };

    vec![serde_json::json!({
        "install_subdir": "",
        "tarball_url": tarball_url,
        "tarball_integrity": tarball_integrity,
        "tarball_sha256": "test-sha256",
    })]
}

#[cfg(unix)]
fn normalize_rel_path(path: &std::path::Path) -> String {
    path.components()
        .map(|component| component.as_os_str().to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .join("/")
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
fn seed_fake_tsgo_engine(project: &TempProject, marker_file: &str) {
    let (platform, entry_rel_path) = current_engine_platform();
    let engine_dir = project
        .home()
        .join(".lpm")
        .join("engines")
        .join("tsgo")
        .join(TSGO_VERSION)
        .join(platform);
    let entry_path = engine_dir.join(entry_rel_path);
    std::fs::create_dir_all(entry_path.parent().unwrap()).expect("failed to create tsgo parent");

    let script = format!(
        "#!/bin/sh\nprintf '%s\n' \"$PWD\" >> '{}'\nexit 0\n",
        marker_file
    );
    write_unix_executable(&entry_path, &script);
    std::fs::write(
        engine_dir.join("lib/lib.d.ts"),
        b"declare const x: string;\n",
    )
    .expect("failed to write tsgo lib.d.ts");

    let layout_sha256 = hash_directory_tree_for_test(&engine_dir);
    let sidecar = serde_json::json!({
        "schema_version": 2,
        "engine_name": "tsgo",
        "version": TSGO_VERSION,
        "platform": platform,
        "entry_rel_path": entry_rel_path,
        "packages": seeded_tsgo_sidecar_packages(platform),
        "layout_sha256": layout_sha256,
        "verified_at_unix": 0,
    });
    std::fs::write(
        engine_dir.join(".lpm-engine.json"),
        serde_json::to_vec_pretty(&sidecar).expect("failed to serialize tsgo sidecar"),
    )
    .expect("failed to write tsgo sidecar");
}

// ─── empty-match contract ───────────────────────────────────────

#[test]
fn lint_filter_typo_without_fail_flag_exits_zero() {
    let project = TempProject::from_fixture("workspace-monorepo");

    let output = lpm(&project)
        .args(["lint", "--filter", "this-package-does-not-exist"])
        .output()
        .expect("failed to run lpm lint");

    assert!(
        output.status.success(),
        "empty-match without --fail-if-no-match must exit 0, got: {}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr),
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("No packages matched"),
        "expected 'No packages matched' in stderr, got:\n{stderr}"
    );
}

#[test]
fn lint_filter_typo_with_fail_flag_exits_nonzero() {
    let project = TempProject::from_fixture("workspace-monorepo");

    let output = lpm(&project)
        .args([
            "lint",
            "--filter",
            "this-package-does-not-exist",
            "--fail-if-no-match",
        ])
        .output()
        .expect("failed to run lpm lint");

    assert!(
        !output.status.success(),
        "empty-match with --fail-if-no-match must exit non-zero, got: 0\nstderr:\n{}",
        String::from_utf8_lossy(&output.stderr),
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("no workspace packages matched") || stderr.contains("--fail-if-no-match"),
        "expected error message mentioning the empty-match condition, got:\n{stderr}"
    );
}

// ─── JSON envelope: empty match ─────────────────────────────────

#[test]
fn lint_filter_typo_json_emits_valid_envelope() {
    let project = TempProject::from_fixture("workspace-monorepo");

    let output = lpm(&project)
        .args(["--json", "lint", "--filter", "this-package-does-not-exist"])
        .output()
        .expect("failed to run lpm lint --json");

    assert!(
        output.status.success(),
        "empty-match without --fail-if-no-match must exit 0, got: {}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr),
    );

    let json = parse_json_output(&output.stdout);
    assert_eq!(json["success"], serde_json::json!(true));
    assert_eq!(json["packages"], serde_json::json!(0));
    assert_eq!(json["succeeded"], serde_json::json!(0));
    assert_eq!(json["failed"], serde_json::json!(0));
    assert_eq!(json["members"], serde_json::json!([]));
    assert!(
        json["duration_ms"].is_number(),
        "duration_ms must be numeric"
    );
}

// ─── JSON envelope: spawn failure path ──────────────────────────

#[test]
fn check_workspace_json_emits_valid_envelope_per_member() {
    // `lpm check` shells out to tsc which won't be on PATH inside the isolated
    // test HOME. Each workspace member's spawn fails — exercises the non-exit
    // failure branch (exit_code: null + error field) AND proves the orchestrator
    // emits a single, valid JSON envelope (no interleaved child output).
    let project = TempProject::from_fixture("workspace-monorepo");

    let output = lpm(&project)
        // Strip PATH so tsc cannot be found anywhere — guarantees spawn failure
        // even on a developer machine that has tsc installed globally.
        .env("PATH", "")
        .args(["--json", "check", "--all"])
        .output()
        .expect("failed to run lpm check --all --json");

    assert!(
        !output.status.success(),
        "spawn failures must surface as non-zero exit, got: 0"
    );

    // Verify stdout is a single, valid JSON document — proves child output
    // didn't bleed into the envelope.
    let raw = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value =
        serde_json::from_str(raw.trim()).unwrap_or_else(|e| {
            panic!("workspace --json must emit a single valid JSON document. Parse error: {e}\nRaw stdout:\n{raw}")
        });

    assert_eq!(json["success"], serde_json::json!(false));
    assert_eq!(json["packages"], serde_json::json!(3));
    assert_eq!(json["succeeded"], serde_json::json!(0));
    assert_eq!(json["failed"], serde_json::json!(3));

    let members = json["members"]
        .as_array()
        .expect("members must be an array");
    assert_eq!(members.len(), 3);

    for member in members {
        assert_eq!(member["success"], serde_json::json!(false));
        // exit_code MUST be null (spawn failure, not a non-zero exit)
        assert_eq!(
            member["exit_code"],
            serde_json::Value::Null,
            "spawn failure must have exit_code: null, got: {}",
            member["exit_code"],
        );
        assert!(
            member["error"].is_string(),
            "spawn failure must populate the error field, member: {member}"
        );
        assert!(
            member["duration_ms"].is_number(),
            "duration_ms must be numeric, member: {member}"
        );
    }
}

#[test]
#[cfg(unix)]
fn check_workspace_json_uses_selected_tsgo_engine_per_member() {
    let project = TempProject::from_fixture("workspace-monorepo");
    let marker = project.path().join(".tsgo-workspace-members.txt");
    seed_fake_tsgo_engine(&project, &marker.display().to_string());

    let output = lpm(&project)
        .env("PATH", "")
        .args(["--json", "check", "--engine", "tsgo", "--all"])
        .output()
        .expect("failed to run lpm check --engine tsgo --all --json");

    assert!(
        output.status.success(),
        "workspace tsgo check should succeed; stderr:\n{}",
        String::from_utf8_lossy(&output.stderr),
    );

    let json = parse_json_output(&output.stdout);
    assert_eq!(json["success"], serde_json::json!(true));
    assert_eq!(json["packages"], serde_json::json!(3));
    assert_eq!(json["succeeded"], serde_json::json!(3));
    assert_eq!(json["failed"], serde_json::json!(0));

    let members = std::fs::read_to_string(&marker).expect("expected tsgo marker file");
    assert_eq!(
        members.lines().count(),
        3,
        "expected one tsgo invocation per workspace member; got:\n{members}"
    );
}

// ─── --affected with no changes keeps its specific success message ──
//
// Regression guard: the empty-target branch was previously folding every
// empty result into the generic "No packages matched" warning. The
// `--affected --base HEAD` case (no diff vs the base ref) is the common
// "nothing changed" signal and gets its own success message so it doesn't
// read like a filter typo.

#[test]
fn lint_affected_with_no_changes_prints_specific_success_message() {
    use std::process::Command;

    let project = TempProject::from_fixture("workspace-monorepo");

    // Initialize a git repo at HEAD so `--affected --base HEAD` is meaningful
    // and the diff-vs-HEAD set is empty (nothing has changed since HEAD).
    Command::new("git")
        .args(["init", "-q"])
        .current_dir(project.path())
        .status()
        .expect("git init failed");
    Command::new("git")
        .args(["add", "-A"])
        .current_dir(project.path())
        .status()
        .expect("git add failed");
    Command::new("git")
        .args([
            "-c",
            "user.email=t@t.t",
            "-c",
            "user.name=t",
            "commit",
            "-q",
            "-m",
            "init",
        ])
        .current_dir(project.path())
        .status()
        .expect("git commit failed");

    let output = lpm(&project)
        .args(["lint", "--affected", "--base", "HEAD"])
        .output()
        .expect("failed to run lpm lint --affected");

    assert!(
        output.status.success(),
        "empty --affected must exit 0, got: {}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr),
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("nothing to lint") || stderr.contains("no packages affected"),
        "expected affected-specific success message, got:\n{stderr}"
    );
    assert!(
        !stderr.contains("No packages matched"),
        "must not fall into the filter-miss path, got:\n{stderr}"
    );
}

// ─── workspace-mode requires a workspace ────────────────────────

#[test]
fn lint_all_outside_workspace_errors_clearly() {
    let project = TempProject::empty(r#"{"name": "single", "version": "1.0.0"}"#);

    let output = lpm(&project)
        .args(["lint", "--all"])
        .output()
        .expect("failed to run lpm lint --all");

    assert!(!output.status.success());

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("no workspace") || stderr.contains("monorepo"),
        "expected workspace-required error, got:\n{stderr}"
    );
}

// ─── Happy-path workspace lint E2E (network-gated) ─────────────
//
// The only test that proves "tool exited 0 across N members" end-to-end.
// Every other tools test exercises empty-set, failure, or detection-failure
// branches. This one downloads oxlint (real network), runs it across three
// workspace members with clean source files, and asserts the success
// envelope shape.
//
// Gated on `LPM_E2E_NETWORK=1` because:
//   - First run downloads ~3-5 MB
//   - Adds ~2-5s to the CI run cold, ~1s warm
//   - Pinning a specific oxlint version in the fixture would silently
//     break when that version retired upstream; following the registry
//     default matches what real users experience but means the test's
//     stability is tied to the shipped plugin version's lint behavior
//     against trivial JS files (clean files → safe).

#[test]
fn lint_all_happy_path_e2e_network_gated() {
    // Explicit truthy gate so `LPM_E2E_NETWORK=0` reads as "off" instead of
    // "set, therefore on." Accepts `1` and `true` (case-insensitive).
    let enabled = std::env::var("LPM_E2E_NETWORK")
        .ok()
        .is_some_and(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true"));
    if !enabled {
        eprintln!(
            "skipping lint_all_happy_path_e2e_network_gated (set LPM_E2E_NETWORK=1 to run; real-network test downloads oxlint)"
        );
        return;
    }

    let project = TempProject::from_fixture("workspace-monorepo-lintable");

    let output = lpm(&project)
        // Suppress the interactive "Plugin not installed. Downloading..." banner
        // so stdout stays a clean JSON envelope. The env var ONLY suppresses
        // the banner — the download itself is unconditional on cache miss.
        .env("LPM_PLUGIN_QUIET", "1")
        .args(["--json", "lint", "--all"])
        .output()
        .expect("failed to run lpm lint --all --json");

    assert!(
        output.status.success(),
        "happy-path lint must exit 0, got: {}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr),
    );

    let raw = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(raw.trim()).unwrap_or_else(|e| {
        panic!("happy-path workspace lint must emit a single valid JSON envelope. Parse error: {e}\nRaw stdout:\n{raw}\nstderr:\n{}", String::from_utf8_lossy(&output.stderr))
    });

    assert_eq!(json["success"], serde_json::json!(true));
    assert_eq!(
        json["packages"],
        serde_json::json!(3),
        "all 3 workspace members must be in the envelope"
    );
    assert_eq!(json["succeeded"], serde_json::json!(3));
    assert_eq!(json["failed"], serde_json::json!(0));

    // Prove all three members actually ran by asserting the member array
    // contains entries for each. The fixture is utils → core → app; topology
    // order is preserved by the orchestrator.
    let members = json["members"]
        .as_array()
        .expect("members must be an array");
    assert_eq!(members.len(), 3, "envelope must list all 3 members");

    let names: std::collections::HashSet<&str> =
        members.iter().filter_map(|m| m["name"].as_str()).collect();
    for expected in &["@test/utils", "@test/core", "@test/app"] {
        assert!(
            names.contains(expected),
            "envelope members must include {expected}, got: {names:?}"
        );
    }

    // Every member should report success and a real exit code.
    for member in members {
        assert_eq!(
            member["success"],
            serde_json::json!(true),
            "every member must succeed in the happy path, got: {member}"
        );
        assert_eq!(
            member["exit_code"],
            serde_json::json!(0),
            "every member must report exit_code: 0, got: {member}"
        );
        // Success-case members must NOT carry stdout/stderr/error fields.
        assert!(
            member.get("stdout").is_none(),
            "success member must not include stdout, got: {member}"
        );
        assert!(
            member.get("stderr").is_none(),
            "success member must not include stderr, got: {member}"
        );
        assert!(
            member.get("error").is_none(),
            "success member must not include error, got: {member}"
        );
    }
}

#[cfg(unix)]
#[test]
fn fmt_all_happy_path_with_seeded_plugin_cache() {
    let project = TempProject::from_fixture("workspace-monorepo");
    seed_workspace_tool_pin(&project, "biome", "1.0.0");
    seed_fake_plugin(&project, "biome", "1.0.0", ".fmt-ok");

    let output = lpm(&project)
        .args(["--json", "fmt", "--all", "--check"])
        .output()
        .expect("failed to run lpm fmt --all --check --json");

    assert!(
        output.status.success(),
        "happy-path fmt must exit 0, got: {}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr),
    );

    let raw = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(raw.trim()).unwrap_or_else(|e| {
        panic!("happy-path workspace fmt must emit a single valid JSON envelope. Parse error: {e}\nRaw stdout:\n{raw}\nstderr:\n{}", String::from_utf8_lossy(&output.stderr))
    });

    assert_eq!(json["success"], serde_json::json!(true));
    assert_eq!(json["packages"], serde_json::json!(3));
    assert_eq!(json["succeeded"], serde_json::json!(3));
    assert_eq!(json["failed"], serde_json::json!(0));

    let members = json["members"]
        .as_array()
        .expect("members must be an array");
    assert_eq!(members.len(), 3, "envelope must list all 3 members");

    for member in members {
        assert_eq!(member["success"], serde_json::json!(true));
        assert_eq!(member["exit_code"], serde_json::json!(0));
        assert!(
            member.get("stdout").is_none(),
            "success member must not include stdout, got: {member}"
        );
        assert!(
            member.get("stderr").is_none(),
            "success member must not include stderr, got: {member}"
        );
        assert!(
            member.get("error").is_none(),
            "success member must not include error, got: {member}"
        );
    }

    for member in WORKSPACE_MEMBERS {
        assert!(
            project.file_exists(&format!("{member}/.fmt-ok")),
            "fmt stand-in must execute inside {member}"
        );
    }
}

#[cfg(unix)]
#[test]
fn check_all_happy_path_with_seeded_root_tsc() {
    let project = TempProject::from_fixture("workspace-monorepo");
    seed_fake_root_tsc(&project, ".check-ok");

    let output = lpm(&project)
        .args(["--json", "check", "--all"])
        .output()
        .expect("failed to run lpm check --all --json");

    assert!(
        output.status.success(),
        "happy-path check must exit 0, got: {}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr),
    );

    let raw = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(raw.trim()).unwrap_or_else(|e| {
        panic!("happy-path workspace check must emit a single valid JSON envelope. Parse error: {e}\nRaw stdout:\n{raw}\nstderr:\n{}", String::from_utf8_lossy(&output.stderr))
    });

    assert_eq!(json["success"], serde_json::json!(true));
    assert_eq!(json["packages"], serde_json::json!(3));
    assert_eq!(json["succeeded"], serde_json::json!(3));
    assert_eq!(json["failed"], serde_json::json!(0));

    let members = json["members"]
        .as_array()
        .expect("members must be an array");
    assert_eq!(members.len(), 3, "envelope must list all 3 members");

    for member in members {
        assert_eq!(member["success"], serde_json::json!(true));
        assert_eq!(member["exit_code"], serde_json::json!(0));
        assert!(
            member.get("stdout").is_none(),
            "success member must not include stdout, got: {member}"
        );
        assert!(
            member.get("stderr").is_none(),
            "success member must not include stderr, got: {member}"
        );
        assert!(
            member.get("error").is_none(),
            "success member must not include error, got: {member}"
        );
    }

    for member in WORKSPACE_MEMBERS {
        assert!(
            project.file_exists(&format!("{member}/.check-ok")),
            "check stand-in must execute inside {member}"
        );
    }
}

#[cfg(unix)]
#[test]
fn lint_single_package_reports_slim_completion_with_elapsed_time() {
    let project = TempProject::empty(r#"{"name":"slim-lint","version":"1.0.0"}"#);
    project.write_file("lpm.json", r#"{"tools":{"oxlint":"1.0.0"}}"#);
    seed_fake_plugin(&project, "oxlint", "1.0.0", ".lint-ok");

    let output = lpm(&project)
        .args(["lint"])
        .output()
        .expect("failed to run lpm lint");

    assert!(
        output.status.success(),
        "lint stand-in must succeed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    assert!(
        project.file_exists(".lint-ok"),
        "lint stand-in must execute inside the project"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("› Using Oxlint 1.0.0"),
        "lint must announce the selected tool, got:\n{stderr}"
    );
    assert!(
        stderr.contains("✓ lint passed in "),
        "lint must report a meaningful elapsed completion line, got:\n{stderr}"
    );
    assert!(
        !stderr.contains('●') && !stderr.contains('│'),
        "lint output must not use cliclack gutter output, got:\n{stderr}"
    );
}

#[cfg(unix)]
#[test]
fn lint_malformed_lpm_json_stops_before_running_an_unpinned_tool() {
    let project = TempProject::empty(r#"{"name":"invalid-lint-config","version":"1.0.0"}"#);
    project.write_file("lpm.json", "{");
    seed_fake_plugin(&project, "oxlint", "1.79.0", ".lint-ok");
    let output = lpm(&project).args(["--json", "lint"]).output().unwrap();
    assert!(
        !output.status.success(),
        "malformed tool pin must not fall back to another version"
    );
    assert!(!project.file_exists(".lint-ok"));
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["success"], false);
}

#[cfg(unix)]
#[test]
fn fmt_write_single_package_reports_slim_completion_with_elapsed_time() {
    let project = TempProject::empty(r#"{"name":"slim-fmt","version":"1.0.0"}"#);
    project.write_file("lpm.json", r#"{"tools":{"biome":"1.0.0"}}"#);
    seed_fake_plugin(&project, "biome", "1.0.0", ".fmt-ok");

    let output = lpm(&project)
        .args(["fmt"])
        .output()
        .expect("failed to run lpm fmt");

    assert!(
        output.status.success(),
        "fmt stand-in must succeed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    assert!(
        project.file_exists(".fmt-ok"),
        "fmt stand-in must execute inside the project"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("› Using Biome 1.0.0"),
        "fmt must announce the selected tool, got:\n{stderr}"
    );
    assert!(
        stderr.contains("✓ Done · codebase is now formatted in "),
        "fmt must report a meaningful elapsed completion line, got:\n{stderr}"
    );
    assert!(
        !stderr.contains('●') && !stderr.contains('│'),
        "fmt output must not use cliclack gutter output, got:\n{stderr}"
    );
}

#[cfg(unix)]
#[test]
fn fmt_check_single_package_reports_slim_completion_with_elapsed_time() {
    let project = TempProject::empty(r#"{"name":"slim-fmt-check","version":"1.0.0"}"#);
    project.write_file("lpm.json", r#"{"tools":{"biome":"1.0.0"}}"#);
    seed_fake_plugin(&project, "biome", "1.0.0", ".fmt-check-ok");

    let output = lpm(&project)
        .args(["fmt", "--check"])
        .output()
        .expect("failed to run lpm fmt --check");

    assert!(
        output.status.success(),
        "fmt --check stand-in must succeed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    assert!(
        project.file_exists(".fmt-check-ok"),
        "fmt --check stand-in must execute inside the project"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("✓ fmt check passed in "),
        "fmt --check must report a meaningful elapsed completion line, got:\n{stderr}"
    );
}

#[cfg(unix)]
#[test]
fn check_single_package_reports_slim_completion_with_elapsed_time() {
    let project = TempProject::empty(
        r#"{
            "name": "slim-check",
            "version": "1.0.0",
            "devDependencies": { "typescript": "5.0.0" }
        }"#,
    );
    project.write_file("tsconfig.json", r#"{"compilerOptions": {}}"#);
    seed_fake_root_tsc(&project, ".check-ok");

    let output = lpm(&project)
        .args(["check"])
        .output()
        .expect("failed to run lpm check");

    assert!(
        output.status.success(),
        "check stand-in must succeed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    assert!(
        project.file_exists(".check-ok"),
        "check stand-in must execute inside the project"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("› Using tsc --noEmit"),
        "check must announce the selected typecheck engine, got:\n{stderr}"
    );
    assert!(
        stderr.contains("✓ typecheck passed in "),
        "check must report a meaningful elapsed completion line, got:\n{stderr}"
    );
    assert!(
        !stderr.contains('●') && !stderr.contains('│'),
        "check output must not use cliclack gutter output, got:\n{stderr}"
    );
}

#[test]
fn test_single_package_reports_slim_runner_and_timed_completion() {
    let project = TempProject::empty(
        r#"{
            "name": "slim-test-runner",
            "version": "1.0.0",
            "scripts": { "test": "echo test-ok" }
        }"#,
    );

    let output = lpm(&project)
        .args(["test"])
        .output()
        .expect("failed to run lpm test");

    assert!(
        output.status.success(),
        "test script must succeed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("test-ok"),
        "runner stdout must pass through, got:\n{stdout}"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("› Using package.json test script"),
        "test runner line must use slim UI, got:\n{stderr}"
    );
    assert!(
        stderr.contains("✓ Tests complete in "),
        "test must report a meaningful elapsed completion line, got:\n{stderr}"
    );
    assert!(
        !stderr.contains('●') && !stderr.contains('│'),
        "test runner line must not use cliclack gutter output, got:\n{stderr}"
    );
}

#[test]
fn test_single_package_json_owns_the_success_envelope() {
    let project = TempProject::empty(
        r#"{
            "name": "json-test-runner",
            "version": "1.0.0",
            "scripts": { "test": "echo child-forged-json" }
        }"#,
    );

    let output = lpm(&project)
        .args(["--json", "test"])
        .output()
        .expect("run a single-package test under JSON mode");

    assert!(output.status.success());
    let mut envelope: serde_json::Value = serde_json::from_slice(&output.stdout)
        .expect("single-package test output must be one LPM-owned JSON document");
    assert_eq!(envelope["success"], true);
    assert_eq!(envelope["packages"], 1);
    assert_eq!(envelope["members"][0]["name"], "json-test-runner");
    assert!(envelope["members"][0].get("stdout").is_none());
    envelope["duration_ms"] = serde_json::json!(0);
    envelope["members"][0]["duration_ms"] = serde_json::json!(0);
    insta::assert_json_snapshot!("test_single_package_json_success_envelope", envelope);
}

#[cfg(unix)]
#[test]
fn test_single_package_json_owns_the_failure_envelope() {
    let project = TempProject::empty(
        r#"{
            "name": "json-test-failure",
            "version": "1.0.0",
            "scripts": {
                "test": "printf 'child stdout\\n'; printf 'child stderr\\n' >&2; exit 3"
            }
        }"#,
    );

    let output = lpm(&project)
        .args(["--json", "test"])
        .output()
        .expect("run a failing single-package test under JSON mode");

    assert!(!output.status.success());
    let mut envelope: serde_json::Value = serde_json::from_slice(&output.stdout)
        .expect("single-package test failure must be one LPM-owned JSON document");
    assert_eq!(envelope["success"], false);
    assert_eq!(envelope["members"][0]["exit_code"], 3);
    assert_eq!(envelope["members"][0]["stdout"], "child stdout\n");
    assert_eq!(envelope["members"][0]["stderr"], "child stderr\n");
    envelope["duration_ms"] = serde_json::json!(0);
    envelope["members"][0]["duration_ms"] = serde_json::json!(0);
    insta::assert_json_snapshot!("test_single_package_json_failure_envelope", envelope);
}

#[test]
fn bench_single_package_json_owns_the_success_envelope() {
    let project = TempProject::empty(
        r#"{
            "name": "json-bench-runner",
            "version": "1.0.0",
            "scripts": { "bench": "echo child-forged-json" }
        }"#,
    );

    let output = lpm(&project)
        .args(["--json", "bench"])
        .output()
        .expect("run a single-package benchmark under JSON mode");

    assert!(output.status.success());
    let mut envelope: serde_json::Value = serde_json::from_slice(&output.stdout)
        .expect("single-package benchmark output must be one LPM-owned JSON document");
    assert_eq!(envelope["success"], true);
    assert_eq!(envelope["packages"], 1);
    assert_eq!(envelope["members"][0]["name"], "json-bench-runner");
    assert!(envelope["members"][0].get("stdout").is_none());
    envelope["duration_ms"] = serde_json::json!(0);
    envelope["members"][0]["duration_ms"] = serde_json::json!(0);
    insta::assert_json_snapshot!("bench_single_package_json_success_envelope", envelope);
}

#[cfg(unix)]
#[test]
fn bench_single_package_json_owns_the_failure_envelope() {
    let project = TempProject::empty(
        r#"{
            "name": "json-bench-failure",
            "version": "1.0.0",
            "scripts": {
                "bench": "printf 'child stdout\\n'; printf 'child stderr\\n' >&2; exit 3"
            }
        }"#,
    );

    let output = lpm(&project)
        .args(["--json", "bench"])
        .output()
        .expect("run a failing single-package benchmark under JSON mode");

    assert!(!output.status.success());
    let mut envelope: serde_json::Value = serde_json::from_slice(&output.stdout)
        .expect("single-package benchmark failure must be one LPM-owned JSON document");
    assert_eq!(envelope["success"], false);
    assert_eq!(envelope["members"][0]["exit_code"], 3);
    assert_eq!(envelope["members"][0]["stdout"], "child stdout\n");
    assert_eq!(envelope["members"][0]["stderr"], "child stderr\n");
    envelope["duration_ms"] = serde_json::json!(0);
    envelope["members"][0]["duration_ms"] = serde_json::json!(0);
    insta::assert_json_snapshot!("bench_single_package_json_failure_envelope", envelope);
}

#[cfg(unix)]
#[test]
fn test_uses_the_system_shell_even_when_project_bin_contains_sh() {
    let project = TempProject::empty(
        r#"{
            "name": "trusted-test-shell",
            "version": "1.0.0",
            "scripts": { "test": "echo test-ok" }
        }"#,
    );
    let hijack_marker = project.path().join("shell-hijacked");
    write_unix_executable(
        &project.path().join("node_modules/.bin/sh"),
        &format!(
            "#!/bin/sh\nprintf hijacked > '{}'\nexec /bin/sh \"$@\"\n",
            hijack_marker.display()
        ),
    );

    let output = lpm(&project)
        .args(["test"])
        .output()
        .expect("run test with a project-local sh binary");

    assert!(
        output.status.success(),
        "benign test script must still succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !hijack_marker.exists(),
        "project .bin/sh must not become the interpreter"
    );
}

#[cfg(unix)]
#[test]
fn bench_uses_the_system_shell_even_when_project_bin_contains_sh() {
    let project = TempProject::empty(
        r#"{
            "name": "trusted-bench-shell",
            "version": "1.0.0",
            "scripts": { "bench": "echo bench-ok" }
        }"#,
    );
    let hijack_marker = project.path().join("shell-hijacked");
    write_unix_executable(
        &project.path().join("node_modules/.bin/sh"),
        &format!(
            "#!/bin/sh\nprintf hijacked > '{}'\nexec /bin/sh \"$@\"\n",
            hijack_marker.display()
        ),
    );

    let output = lpm(&project)
        .args(["bench"])
        .output()
        .expect("run benchmark with a project-local sh binary");

    assert!(
        output.status.success(),
        "benign benchmark script must still succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !hijack_marker.exists(),
        "project .bin/sh must not become the interpreter"
    );
}

#[cfg(unix)]
#[test]
fn test_runner_resolution_does_not_escape_to_an_ancestor_project() {
    let project = TempProject::empty(r#"{"name":"attacker-parent","version":"1.0.0"}"#);
    let victim = project.path().join("victim");
    std::fs::create_dir_all(&victim).expect("create victim project");
    std::fs::write(
        victim.join("package.json"),
        r#"{
            "name": "victim",
            "version": "1.0.0",
            "devDependencies": { "vitest": "1.0.0" }
        }"#,
    )
    .expect("write victim manifest");
    let marker = project.path().join("ancestor-runner-executed");
    write_unix_executable(
        &project.path().join("node_modules/.bin/vitest"),
        &format!("#!/bin/sh\nprintf executed > '{}'\n", marker.display()),
    );

    let output = lpm(&project)
        .current_dir(&victim)
        .args(["test"])
        .output()
        .expect("run test from a standalone nested project");

    assert!(!output.status.success());
    assert!(
        !marker.exists(),
        "runner lookup must not execute an ancestor project's binary"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("vitest") && stderr.contains("install"));
}

#[cfg(unix)]
#[test]
fn bench_runner_resolution_does_not_escape_to_an_ancestor_project() {
    let project = TempProject::empty(r#"{"name":"attacker-parent","version":"1.0.0"}"#);
    let victim = project.path().join("victim");
    std::fs::create_dir_all(&victim).expect("create victim project");
    std::fs::write(
        victim.join("package.json"),
        r#"{
            "name": "victim",
            "version": "1.0.0",
            "devDependencies": { "vitest": "1.0.0" }
        }"#,
    )
    .expect("write victim manifest");
    let marker = project.path().join("ancestor-runner-executed");
    write_unix_executable(
        &project.path().join("node_modules/.bin/vitest"),
        &format!("#!/bin/sh\nprintf executed > '{}'\n", marker.display()),
    );

    let output = lpm(&project)
        .current_dir(&victim)
        .args(["bench"])
        .output()
        .expect("run benchmark from a standalone nested project");

    assert!(!output.status.success());
    assert!(
        !marker.exists(),
        "runner lookup must not execute an ancestor project's binary"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("vitest") && stderr.contains("install"));
}

#[test]
fn test_from_nested_directory_uses_the_nearest_project_root() {
    let project = TempProject::empty(
        r#"{
            "name": "nested-test-project",
            "version": "1.0.0",
            "scripts": { "test": "echo nested-test-ok" }
        }"#,
    );
    let nested = project.path().join("src/deep");
    std::fs::create_dir_all(&nested).expect("create nested project directory");

    let output = lpm(&project)
        .current_dir(&nested)
        .args(["test"])
        .output()
        .expect("run test from a nested directory");

    assert!(
        output.status.success(),
        "nested test invocation must find the project root: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("nested-test-ok"));
}

#[test]
fn bench_from_nested_directory_uses_the_nearest_project_root() {
    let project = TempProject::empty(
        r#"{
            "name": "nested-bench-project",
            "version": "1.0.0",
            "scripts": { "bench": "echo nested-bench-ok" }
        }"#,
    );
    let nested = project.path().join("src/deep");
    std::fs::create_dir_all(&nested).expect("create nested project directory");

    let output = lpm(&project)
        .current_dir(&nested)
        .args(["bench"])
        .output()
        .expect("run benchmark from a nested directory");

    assert!(
        output.status.success(),
        "nested benchmark invocation must find the project root: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("nested-bench-ok"));
}

#[test]
fn bench_single_package_reports_slim_completion_with_elapsed_time() {
    let project = TempProject::empty(
        r#"{
            "name": "slim-bench-runner",
            "version": "1.0.0",
            "scripts": { "bench": "echo bench-ok" }
        }"#,
    );

    let output = lpm(&project)
        .args(["bench"])
        .output()
        .expect("failed to run lpm bench");

    assert!(
        output.status.success(),
        "bench script must succeed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("bench-ok"),
        "runner stdout must pass through, got:\n{stdout}"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("› Using package.json bench script"),
        "bench runner line must use slim UI, got:\n{stderr}"
    );
    assert!(
        stderr.contains("✓ Benchmarks complete in "),
        "bench must report a meaningful elapsed completion line, got:\n{stderr}"
    );
    assert!(
        !stderr.contains('●') && !stderr.contains('│'),
        "bench output must not use cliclack gutter output, got:\n{stderr}"
    );
}

#[cfg(unix)]
#[test]
fn check_failure_reports_slim_failed_line_with_exit_code() {
    let project = TempProject::empty(
        r#"{
            "name": "slim-check-runner",
            "version": "1.0.0",
            "devDependencies": { "typescript": "5.0.0" }
        }"#,
    );
    project.write_file("tsconfig.json", r#"{"compilerOptions": {}}"#);
    write_unix_executable(
        &project.path().join("node_modules/.bin/tsc"),
        "#!/bin/sh\necho 'type error' >&2\nexit 2\n",
    );

    let output = lpm(&project)
        .args(["check"])
        .output()
        .expect("failed to run lpm check");

    assert!(
        !output.status.success(),
        "check stand-in must fail\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("› Using tsc --noEmit"),
        "check runner line must use slim UI, got:\n{stderr}"
    );
    assert!(
        stderr.contains("✗ typecheck failed · exit code 2"),
        "check failure must use a slim failed terminus, got:\n{stderr}"
    );
    assert!(
        !stderr.contains('▲') && !stderr.contains('●') && !stderr.contains('│'),
        "check failure must not use cliclack warning/gutter output, got:\n{stderr}"
    );
}

// Parser-level coverage for `--filter` / `--fail-if-no-match` lives in
// `crates/lpm-cli/src/commands/tools.rs::tests` (lint_filter_parses_with_grammar,
// fmt_filter_and_check_compose, check_filter_parses). The compat contract that
// positional args don't get claimed by `--filter` falls out of clap's grammar
// (`--filter` is `Vec<String>` requiring the explicit flag).

// ─── Test/Bench workspace surface ──────────────────────

#[test]
fn test_filter_typo_with_fail_flag_exits_nonzero() {
    let project = TempProject::from_fixture("workspace-monorepo");

    let output = lpm(&project)
        .args([
            "test",
            "--filter",
            "this-package-does-not-exist",
            "--fail-if-no-match",
        ])
        .output()
        .expect("failed to run lpm test");

    assert!(
        !output.status.success(),
        "empty-match with --fail-if-no-match must exit non-zero"
    );
}

#[test]
fn test_filter_typo_json_emits_valid_envelope() {
    let project = TempProject::from_fixture("workspace-monorepo");

    let output = lpm(&project)
        .args(["--json", "test", "--filter", "does-not-exist"])
        .output()
        .expect("failed to run lpm test --json");

    assert!(output.status.success());

    let raw = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(raw.trim()).unwrap_or_else(|e| {
        panic!("workspace --json must emit a single valid JSON document. Parse error: {e}\nRaw stdout:\n{raw}")
    });

    assert_eq!(json["success"], serde_json::json!(true));
    assert_eq!(json["packages"], serde_json::json!(0));
    assert_eq!(json["members"], serde_json::json!([]));
}

#[test]
fn test_multi_member_watch_is_rejected_with_count() {
    // Selection resolves to 3 members (--all against the 3-member fixture).
    // Watch must reject with a count-aware message, not the old blanket
    // "workspace mode" wording.
    let project = TempProject::from_fixture("workspace-monorepo");

    let output = lpm(&project)
        .args(["test", "--all", "--watch"])
        .output()
        .expect("failed to run lpm test --all --watch");

    assert!(!output.status.success(), "multi-member watch must reject");

    // The renderer line-wraps long error messages with `│ ` continuation
    // markers, so we assert the load-bearing tokens individually.
    // The renderer line-wraps long error messages with `│ ` continuation
    // markers, so we assert on individual tokens that survive wrapping
    // rather than on multi-word phrases that may get split.
    let stderr = String::from_utf8_lossy(&output.stderr);
    let normalized = stderr.replace(['\n', '│', ' '], "");
    assert!(
        normalized.contains("resolvesto3members") || normalized.contains("3members"),
        "reject message must surface the actual count, got:\n{stderr}"
    );
    assert!(
        normalized.contains("startonewatcherpermember"),
        "reject must explain the footgun, got:\n{stderr}"
    );
    assert!(
        stderr.contains("lpm test"),
        "reject must mention `lpm test`, got:\n{stderr}"
    );
    assert!(
        stderr.contains("--filter"),
        "reject must point at narrowing the filter, got:\n{stderr}"
    );
}

#[test]
fn test_watch_false_runs_all_selected_members_once() {
    let project = TempProject::empty(
        r#"{
            "name": "watch-false-workspace",
            "version": "1.0.0",
            "private": true,
            "workspaces": ["packages/*"]
        }"#,
    );
    for name in ["a", "b"] {
        project.write_file(
            &format!("packages/{name}/package.json"),
            &format!(
                r#"{{"name":"{name}","version":"1.0.0","scripts":{{"test":"echo {name}-ok"}}}}"#
            ),
        );
    }

    let output = lpm(&project)
        .args(["test", "--all", "--watch=false"])
        .output()
        .expect("run workspace tests with watch explicitly disabled");

    assert!(
        output.status.success(),
        "--watch=false must not enter watcher routing: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("a-ok") && stdout.contains("b-ok"));
}

#[test]
fn bench_watch_false_runs_all_selected_members_once() {
    let project = TempProject::empty(
        r#"{
            "name": "bench-watch-false-workspace",
            "version": "1.0.0",
            "private": true,
            "workspaces": ["packages/*"]
        }"#,
    );
    for name in ["a", "b"] {
        project.write_file(
            &format!("packages/{name}/package.json"),
            &format!(
                r#"{{"name":"{name}","version":"1.0.0","scripts":{{"bench":"echo {name}-ok"}}}}"#
            ),
        );
    }

    let output = lpm(&project)
        .args(["bench", "--all", "--watch=false"])
        .output()
        .expect("run workspace benchmarks with watch explicitly disabled");

    assert!(
        output.status.success(),
        "--watch=false must not enter watcher routing: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("a-ok") && stdout.contains("b-ok"));
}

#[test]
fn test_filtered_independent_member_ignores_unselected_workspace_cycle() {
    let project = TempProject::empty(
        r#"{
            "name": "cycle-workspace",
            "version": "1.0.0",
            "private": true,
            "workspaces": ["packages/*"]
        }"#,
    );
    project.write_file(
        "packages/a/package.json",
        r#"{"name":"a","version":"1.0.0","dependencies":{"b":"workspace:*"}}"#,
    );
    project.write_file(
        "packages/b/package.json",
        r#"{"name":"b","version":"1.0.0","dependencies":{"a":"workspace:*"}}"#,
    );
    project.write_file(
        "packages/c/package.json",
        r#"{"name":"c","version":"1.0.0","scripts":{"test":"echo selected-c"}}"#,
    );

    let output = lpm(&project)
        .args(["test", "--filter", "c"])
        .output()
        .expect("run an independent member beside an unselected cycle");

    assert!(
        output.status.success(),
        "unselected workspace cycles must not block a filtered member: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("selected-c"));
}

#[test]
fn bench_filtered_independent_member_ignores_unselected_workspace_cycle() {
    let project = TempProject::empty(
        r#"{
            "name": "bench-cycle-workspace",
            "version": "1.0.0",
            "private": true,
            "workspaces": ["packages/*"]
        }"#,
    );
    project.write_file(
        "packages/a/package.json",
        r#"{"name":"a","version":"1.0.0","dependencies":{"b":"workspace:*"}}"#,
    );
    project.write_file(
        "packages/b/package.json",
        r#"{"name":"b","version":"1.0.0","dependencies":{"a":"workspace:*"}}"#,
    );
    project.write_file(
        "packages/c/package.json",
        r#"{"name":"c","version":"1.0.0","scripts":{"bench":"echo selected-c"}}"#,
    );

    let output = lpm(&project)
        .args(["bench", "--filter", "c"])
        .output()
        .expect("run an independent benchmark member beside an unselected cycle");

    assert!(
        output.status.success(),
        "unselected workspace cycles must not block a filtered member: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("selected-c"));
}

#[cfg(unix)]
#[test]
fn test_workspace_json_workers_do_not_read_shared_stdin() {
    use std::io::Write;
    use std::process::Stdio;

    let project = TempProject::empty(
        r#"{
            "name": "stdin-workspace",
            "version": "1.0.0",
            "private": true,
            "workspaces": ["packages/*"]
        }"#,
    );
    for name in ["a", "b"] {
        project.write_file(
            &format!("packages/{name}/package.json"),
            &format!(
                r#"{{"name":"{name}","version":"1.0.0","scripts":{{"test":"if IFS= read -r value; then printf 'unexpected stdin: %s\\n' \"$value\" >&2; exit 9; fi"}}}}"#
            ),
        );
    }

    let mut child = lpm_spawnable(&project)
        .args(["--json", "test", "--all"])
        .stdin(Stdio::piped())
        .spawn()
        .expect("start workspace test with piped stdin");
    child
        .stdin
        .take()
        .expect("open child stdin")
        .write_all(b"sentinel-input\n")
        .expect("write piped stdin");
    let output = child.wait_with_output().expect("wait for workspace test");

    assert!(
        output.status.success(),
        "captured workers must receive null stdin: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    let envelope: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("parse workspace test JSON");
    assert_eq!(envelope["succeeded"], 2);
}

#[cfg(unix)]
#[test]
fn bench_workspace_json_workers_do_not_read_shared_stdin() {
    use std::io::Write;
    use std::process::Stdio;

    let project = TempProject::empty(
        r#"{
            "name": "bench-stdin-workspace",
            "version": "1.0.0",
            "private": true,
            "workspaces": ["packages/*"]
        }"#,
    );
    for name in ["a", "b"] {
        project.write_file(
            &format!("packages/{name}/package.json"),
            &format!(
                r#"{{"name":"{name}","version":"1.0.0","scripts":{{"bench":"if IFS= read -r value; then printf 'unexpected stdin: %s\\n' \"$value\" >&2; exit 9; fi"}}}}"#
            ),
        );
    }

    let mut child = lpm_spawnable(&project)
        .args(["--json", "bench", "--all"])
        .stdin(Stdio::piped())
        .spawn()
        .expect("start workspace benchmark with piped stdin");
    child
        .stdin
        .take()
        .expect("open child stdin")
        .write_all(b"sentinel-input\n")
        .expect("write piped stdin");
    let output = child
        .wait_with_output()
        .expect("wait for workspace benchmark");

    assert!(
        output.status.success(),
        "captured workers must receive null stdin: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    let envelope: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("parse workspace benchmark JSON");
    assert_eq!(envelope["succeeded"], 2);
}

#[cfg(unix)]
fn warm_lpm_binary(project: &TempProject) {
    let output = lpm(project)
        .arg("--version")
        .output()
        .expect("warm lpm binary before timing");
    assert!(
        output.status.success(),
        "lpm warm gate failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[cfg(unix)]
#[test]
fn test_workspace_releases_dependent_when_its_own_prerequisite_finishes() {
    let project = TempProject::empty(
        r#"{
            "name": "ready-queue-workspace",
            "version": "1.0.0",
            "private": true,
            "workspaces": ["packages/*"]
        }"#,
    );
    let marker = project.path().join("dependent-started");
    project.write_file(
        "packages/a-slow/package.json",
        &format!(
            r#"{{"name":"a-slow","version":"1.0.0","scripts":{{"test":"i=0; while [ ! -f '{}' ] && [ $i -lt 100 ]; do sleep 0.02; i=$((i + 1)); done; test -f '{}'"}}}}"#,
            marker.display(),
            marker.display()
        ),
    );
    project.write_file(
        "packages/b-fast/package.json",
        r#"{"name":"b-fast","version":"1.0.0","scripts":{"test":"sleep 0.05"}}"#,
    );
    project.write_file(
        "packages/c-dependent/package.json",
        &format!(
            r#"{{"name":"c-dependent","version":"1.0.0","dependencies":{{"b-fast":"workspace:*"}},"scripts":{{"test":": > '{}'"}}}}"#,
            marker.display()
        ),
    );

    warm_lpm_binary(&project);
    let started = std::time::Instant::now();
    let output = lpm(&project)
        .args(["test", "--all", "--workspace-concurrency", "2"])
        .output()
        .expect("run dependency-aware ready queue");

    assert!(
        output.status.success(),
        "dependent must start before an unrelated slow root finishes: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        started.elapsed() < std::time::Duration::from_millis(1200),
        "per-level barriers delayed a ready dependent for {:?}",
        started.elapsed()
    );
}

#[cfg(unix)]
#[test]
fn bench_workspace_releases_dependent_when_its_own_prerequisite_finishes() {
    let project = TempProject::empty(
        r#"{
            "name": "bench-ready-queue-workspace",
            "version": "1.0.0",
            "private": true,
            "workspaces": ["packages/*"]
        }"#,
    );
    let marker = project.path().join("dependent-started");
    project.write_file(
        "packages/a-slow/package.json",
        &format!(
            r#"{{"name":"a-slow","version":"1.0.0","scripts":{{"bench":"i=0; while [ ! -f '{}' ] && [ $i -lt 100 ]; do sleep 0.02; i=$((i + 1)); done; test -f '{}'"}}}}"#,
            marker.display(),
            marker.display()
        ),
    );
    project.write_file(
        "packages/b-fast/package.json",
        r#"{"name":"b-fast","version":"1.0.0","scripts":{"bench":"sleep 0.05"}}"#,
    );
    project.write_file(
        "packages/c-dependent/package.json",
        &format!(
            r#"{{"name":"c-dependent","version":"1.0.0","dependencies":{{"b-fast":"workspace:*"}},"scripts":{{"bench":": > '{}'"}}}}"#,
            marker.display()
        ),
    );

    warm_lpm_binary(&project);
    let started = std::time::Instant::now();
    let output = lpm(&project)
        .args(["bench", "--all", "--workspace-concurrency", "2"])
        .output()
        .expect("run dependency-aware benchmark ready queue");

    assert!(
        output.status.success(),
        "dependent must start before an unrelated slow root finishes: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        started.elapsed() < std::time::Duration::from_millis(1200),
        "per-level barriers delayed a ready dependent for {:?}",
        started.elapsed()
    );
}

#[cfg(unix)]
#[test]
fn test_workspace_process_waits_do_not_block_tokio_workers() {
    let project = TempProject::empty(
        r#"{
            "name": "blocking-worker-workspace",
            "version": "1.0.0",
            "private": true,
            "workspaces": ["packages/*"]
        }"#,
    );
    for name in ["a", "b", "c", "d"] {
        project.write_file(
            &format!("packages/{name}/package.json"),
            &format!(r#"{{"name":"{name}","version":"1.0.0","scripts":{{"test":"sleep 0.3"}}}}"#),
        );
    }

    warm_lpm_binary(&project);
    let started = std::time::Instant::now();
    let output = lpm(&project)
        .env("TOKIO_WORKER_THREADS", "1")
        .args(["test", "--all", "--workspace-concurrency", "4"])
        .output()
        .expect("run test processes with one Tokio worker");

    assert!(
        output.status.success(),
        "blocking runner tasks must succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        started.elapsed() < std::time::Duration::from_millis(900),
        "subprocess waits serialized on a Tokio worker for {:?}",
        started.elapsed()
    );
}

#[cfg(unix)]
#[test]
fn bench_workspace_process_waits_do_not_block_tokio_workers() {
    let project = TempProject::empty(
        r#"{
            "name": "bench-blocking-worker-workspace",
            "version": "1.0.0",
            "private": true,
            "workspaces": ["packages/*"]
        }"#,
    );
    for name in ["a", "b", "c", "d"] {
        project.write_file(
            &format!("packages/{name}/package.json"),
            &format!(r#"{{"name":"{name}","version":"1.0.0","scripts":{{"bench":"sleep 0.3"}}}}"#),
        );
    }

    warm_lpm_binary(&project);
    let started = std::time::Instant::now();
    let output = lpm(&project)
        .env("TOKIO_WORKER_THREADS", "1")
        .args(["bench", "--all", "--workspace-concurrency", "4"])
        .output()
        .expect("run benchmark processes with one Tokio worker");

    assert!(
        output.status.success(),
        "blocking runner tasks must succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        started.elapsed() < std::time::Duration::from_millis(900),
        "subprocess waits serialized on a Tokio worker for {:?}",
        started.elapsed()
    );
}

#[test]
fn bench_multi_member_watch_is_rejected_with_count() {
    // Symmetric reject for bench — `vitest bench --watch` is just as much
    // a footgun as `vitest run --watch`.
    let project = TempProject::from_fixture("workspace-monorepo");

    let output = lpm(&project)
        .args(["bench", "--all", "--watch"])
        .output()
        .expect("failed to run lpm bench --all --watch");

    assert!(
        !output.status.success(),
        "multi-member watch must reject for bench too"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    let normalized = stderr.replace(['\n', '│', ' '], "");
    assert!(
        normalized.contains("resolvesto3members") || normalized.contains("3members"),
        "reject must surface the count, got:\n{stderr}"
    );
    assert!(
        stderr.contains("lpm bench"),
        "reject must reference bench, not test, got:\n{stderr}"
    );
}

/// `lpm --json bench --watch` outside a workspace (so the dispatcher
/// falls through to the single-package path) and without vitest /
/// `scripts.bench` defined emits the "no benchmark runner found"
/// error envelope on stdout. The load-bearing claim is the envelope
/// shape — actual bench runner detection is covered by the existing
/// detect_bench_runner tests in tools.rs.
#[test]
fn bench_no_runner_under_json_emits_error_envelope_on_stdout() {
    let project = TempProject::empty(r#"{"name":"bench-noop","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args(["--json", "bench", "--watch"])
        .output()
        .expect("failed to run lpm --json bench --watch");

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let envelope: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap_or_else(|e| {
        panic!("--json bench --watch error path must emit JSON: {e}\n---\n{stdout}")
    });
    assert_eq!(envelope["success"], serde_json::json!(false));
    assert!(
        envelope["error"]
            .as_str()
            .is_some_and(|s| s.contains("benchmark runner") || s.contains("bench")),
        "error must reference the missing-runner condition, got: {envelope}",
    );
}

// ─── one-member watch IS allowed (hands off to single-package) ──
//
// The previous blanket reject contradicted the documented
// `lpm test --filter <name> --watch` workaround. The dispatcher
// now resolves selection upfront: when --watch is requested AND the filter
// resolves to exactly one member, hand off to the single-package path
// against that member's directory.
//
// We can't run vitest here without installing it, but we can prove the
// dispatcher took the single-package path: the failure mode shifts from
// the workspace-watch reject to the single-package "no test runner found"
// detection error.

#[test]
fn test_filter_one_member_with_watch_hands_off_to_single_package() {
    let project = TempProject::from_fixture("workspace-monorepo");

    let output = lpm(&project)
        .args(["test", "--filter", "@test/app", "--watch"])
        .output()
        .expect("failed to run lpm test --filter @test/app --watch");

    // No runner installed → single-package path errors with detection failure.
    assert!(
        !output.status.success(),
        "no runner installed → single-package failure"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("no test runner found"),
        "must reach single-package detection, got:\n{stderr}"
    );
    // Critically: must NOT have hit the workspace-watch reject.
    assert!(
        !stderr.contains("would start one watcher per member"),
        "must NOT trigger the multi-member watch reject — \
         this is the load-bearing test that the documented workaround works. Got:\n{stderr}"
    );
    assert!(
        !stderr.contains("nothing to watch"),
        "must NOT trigger the empty-selection watch reject. Got:\n{stderr}"
    );
}

#[test]
fn bench_filter_one_member_with_watch_hands_off_to_single_package() {
    let project = TempProject::from_fixture("workspace-monorepo");

    let output = lpm(&project)
        .args(["bench", "--filter", "@test/utils", "--watch"])
        .output()
        .expect("failed to run lpm bench --filter @test/utils --watch");

    assert!(!output.status.success());

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("no benchmark runner found"),
        "must reach single-package bench detection, got:\n{stderr}"
    );
    assert!(
        !stderr.contains("would start one watcher per member"),
        "one-member bench watch must hand off to single-package, got:\n{stderr}"
    );
}

#[test]
fn bench_filter_one_member_with_watch_executes_member_bench_script() {
    let project = TempProject::from_fixture("workspace-monorepo");
    project.write_file(
        "packages/utils/package.json",
        r#"{
  "name": "@test/utils",
  "version": "1.0.0",
  "scripts": {
    "bench": "echo bench-args:"
  },
  "dependencies": {
    "ms": "2.1.3"
  }
}"#,
    );

    let output = lpm(&project)
        .args(["bench", "--filter", "@test/utils", "--watch"])
        .output()
        .expect("failed to run lpm bench --filter @test/utils --watch");

    assert!(
        output.status.success(),
        "bench script should run successfully after one-member watch handoff\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    assert!(
        combined.contains("bench-args: '--watch'") || combined.contains("bench-args: --watch"),
        "bench runner must receive the forwarded --watch arg after handoff, got:\n{combined}"
    );
    assert!(
        !combined.contains("would start one watcher per member"),
        "successful one-member handoff must not trigger the workspace-watch reject, got:\n{combined}"
    );
}

#[test]
fn test_zero_member_watch_rejects_with_nothing_to_watch() {
    // A filter that resolves to zero members + --watch is degenerate. Distinct
    // from the multi-member reject (different message).
    let project = TempProject::from_fixture("workspace-monorepo");

    let output = lpm(&project)
        .args(["test", "--filter", "does-not-exist", "--watch"])
        .output()
        .expect("failed to run lpm test --filter does-not-exist --watch");

    assert!(!output.status.success());

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("nothing to watch"),
        "expected the empty-selection watch message, got:\n{stderr}"
    );
}

#[test]
fn test_workspace_json_emits_valid_envelope_per_member() {
    // Mirrors the `check_workspace_json_emits_valid_envelope_per_member` shape
    // for the test runner: every workspace member's detect_test_runner fails
    // (no vitest/jest/mocha installed in the fixture, no scripts.test) so
    // every member surfaces with `exit_code: null` + an `error` string. Proves
    // the test/bench arms route through the same envelope contract as
    // lint/fmt/check.
    let project = TempProject::from_fixture("workspace-monorepo");

    let output = lpm(&project)
        .args(["--json", "test", "--all"])
        .output()
        .expect("failed to run lpm test --all --json");

    assert!(!output.status.success());

    let raw = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(raw.trim()).unwrap_or_else(|e| {
        panic!("workspace --json must emit a single valid JSON document. Parse error: {e}\nRaw stdout:\n{raw}")
    });

    assert_eq!(json["success"], serde_json::json!(false));
    assert_eq!(json["packages"], serde_json::json!(3));
    assert_eq!(json["failed"], serde_json::json!(3));

    let members = json["members"]
        .as_array()
        .expect("members must be an array");
    assert_eq!(members.len(), 3);

    for member in members {
        assert_eq!(member["success"], serde_json::json!(false));
        assert_eq!(
            member["exit_code"],
            serde_json::Value::Null,
            "detect_test_runner failure must surface as exit_code: null"
        );
        let err = member["error"]
            .as_str()
            .expect("error must be populated for detection failure");
        assert!(
            err.contains("no test runner found"),
            "error must reference the missing-runner cause, got: {err}"
        );
    }
}

#[test]
fn bench_workspace_json_emits_valid_envelope_per_member() {
    let project = TempProject::from_fixture("workspace-monorepo");

    let output = lpm(&project)
        .args(["--json", "bench", "--all"])
        .output()
        .expect("failed to run lpm bench --all --json");

    assert!(!output.status.success());

    let raw = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(raw.trim()).unwrap_or_else(|e| {
        panic!("workspace --json must emit a single valid JSON document. Parse error: {e}\nRaw stdout:\n{raw}")
    });

    assert_eq!(json["success"], serde_json::json!(false));
    assert_eq!(json["packages"], serde_json::json!(3));
    assert_eq!(json["failed"], serde_json::json!(3));

    let members = json["members"]
        .as_array()
        .expect("members must be an array");
    assert_eq!(members.len(), 3);

    for member in members {
        assert_eq!(member["success"], serde_json::json!(false));
        assert_eq!(
            member["exit_code"],
            serde_json::Value::Null,
            "detect_bench_runner failure must surface as exit_code: null"
        );
        let err = member["error"]
            .as_str()
            .expect("error must be populated for detection failure");
        assert!(
            err.contains("no benchmark runner found"),
            "error must reference the missing-runner cause, got: {err}"
        );
    }
}

// ─── compat-seam end-to-end ────────────────────────────
//
// Prove that `lpm test -- --all` still forwards `--all` to the underlying
// runner after it claims `--all` as an LPM workspace flag. We use a
// `scripts.test` fallback that simply
// echoes a literal sentinel (no shell-positional `$@` — the runner path
// builds a single command string with args appended, not passed as `$@`).

#[test]
fn test_double_dash_still_forwards_recognized_flags_to_runner() {
    // scripts.test = "echo args:" — args are appended to the command string
    // by build_safe_command, so the actual exec is `sh -c "echo args: '--all'"`.
    // Stdout therefore contains `args: --all` only when --all is forwarded,
    // and `args:` alone when --all is claimed by clap as a workspace flag.
    let project = TempProject::empty(
        r#"{
            "name": "compat-test",
            "version": "1.0.0",
            "scripts": { "test": "echo args:" }
        }"#,
    );

    // CASE A: `lpm test -- --all` — `--` is the separator, `--all` must reach
    // the runner.
    let output = lpm(&project)
        .args(["test", "--", "--all"])
        .output()
        .expect("failed to run lpm test -- --all");

    assert!(
        output.status.success(),
        "exit code: {}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr),
    );

    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    assert!(
        combined.contains("args: '--all'") || combined.contains("args: --all"),
        "with `--`, --all MUST reach the runner. Got:\n{combined}"
    );
}

#[test]
fn bench_double_dash_still_forwards_recognized_flags_to_runner() {
    let project = TempProject::empty(
        r#"{
            "name": "compat-bench",
            "version": "1.0.0",
            "scripts": { "bench": "echo args:" }
        }"#,
    );

    let output = lpm(&project)
        .args(["bench", "--", "--all"])
        .output()
        .expect("failed to run lpm bench -- --all");

    assert!(
        output.status.success(),
        "exit code: {}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr),
    );

    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    assert!(
        combined.contains("args: '--all'") || combined.contains("args: --all"),
        "with `--`, --all MUST reach the bench runner. Got:\n{combined}"
    );
}

#[test]
fn test_no_double_dash_claims_all_as_workspace_flag() {
    // CASE B: `lpm test --all` (no `--` separator) — `--all` is claimed by
    // clap as a workspace flag and must NOT reach the runner. In a single-
    // package project (no workspace), this errors with "no workspace found".
    let project = TempProject::empty(
        r#"{
            "name": "compat-test",
            "version": "1.0.0",
            "scripts": { "test": "echo args:" }
        }"#,
    );

    let output = lpm(&project)
        .args(["test", "--all"])
        .output()
        .expect("failed to run lpm test --all");

    assert!(
        !output.status.success(),
        "without `--`, --all is claimed by clap and triggers workspace mode in a non-workspace"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("no workspace") || stderr.contains("monorepo"),
        "expected workspace-required error, got:\n{stderr}"
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.contains("args:"),
        "the runner must NOT execute when --all enters workspace mode, got stdout:\n{stdout}"
    );
}

// ─── fmt: workspace dispatch + JSON envelope ────────────────────────
//
// These tests cover the orchestrator's selection / failure-mode contract
// without requiring biome to be installed. The empty-match path never
// invokes the underlying formatter, and the `PATH=""` path forces a
// spawn failure to exercise the failure-envelope shape.

#[test]
fn fmt_filter_typo_without_fail_flag_exits_zero() {
    let project = TempProject::from_fixture("workspace-monorepo");

    let output = lpm(&project)
        .args(["fmt", "--filter", "this-package-does-not-exist"])
        .output()
        .expect("failed to run lpm fmt");

    assert!(
        output.status.success(),
        "empty-match without --fail-if-no-match must exit 0, got: {}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr),
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("No packages matched"),
        "expected 'No packages matched' in stderr, got:\n{stderr}"
    );
}

#[test]
fn fmt_filter_typo_with_fail_flag_exits_nonzero() {
    let project = TempProject::from_fixture("workspace-monorepo");

    let output = lpm(&project)
        .args([
            "fmt",
            "--filter",
            "this-package-does-not-exist",
            "--fail-if-no-match",
        ])
        .output()
        .expect("failed to run lpm fmt");

    assert!(
        !output.status.success(),
        "empty-match with --fail-if-no-match must exit non-zero"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("no workspace packages matched") || stderr.contains("--fail-if-no-match"),
        "expected error message mentioning the empty-match condition, got:\n{stderr}"
    );
}

#[test]
fn fmt_filter_typo_json_emits_valid_envelope() {
    let project = TempProject::from_fixture("workspace-monorepo");

    let output = lpm(&project)
        .args(["--json", "fmt", "--filter", "this-package-does-not-exist"])
        .output()
        .expect("failed to run lpm fmt --json");

    assert!(output.status.success(), "fmt --json failed");

    let json = parse_json_output(&output.stdout);
    assert_eq!(json["success"], serde_json::json!(true));
    assert_eq!(json["packages"], serde_json::json!(0));
    assert_eq!(json["succeeded"], serde_json::json!(0));
    assert_eq!(json["failed"], serde_json::json!(0));
    assert_eq!(json["members"], serde_json::json!([]));
    assert!(
        json["duration_ms"].is_number(),
        "duration_ms must be numeric"
    );
}

#[test]
fn fmt_check_flag_is_accepted_alongside_filter() {
    // The mutually-exclusive group rule (clap `conflicts_with_all`)
    // applies to the selection axes — `--all` / `--filter` / `--affected`.
    // `--check` is orthogonal: it must compose with `--filter` without
    // tripping the conflict rule.
    let project = TempProject::from_fixture("workspace-monorepo");

    let output = lpm(&project)
        .args(["fmt", "--check", "--filter", "this-package-does-not-exist"])
        .output()
        .expect("failed to run lpm fmt --check --filter");

    assert!(
        output.status.success(),
        "fmt --check --filter <typo> empty-match must exit 0, got: {}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr),
    );
}

#[test]
fn test_and_bench_json_launch_failures_emit_one_document() {
    for tool in ["test", "bench"] {
        let project = TempProject::empty(
            r#"{"name":"missing-runner","version":"1.0.0","devDependencies":{"vitest":"4.1.9"}}"#,
        );
        let output = lpm(&project).args(["--json", tool]).output().unwrap();
        assert!(!output.status.success());
        let envelope: serde_json::Value = serde_json::from_slice(&output.stdout)
            .expect("launch failure must emit one JSON document");
        assert_eq!(envelope["success"], false);
        assert!(envelope["members"][0]["exit_code"].is_null());
        assert!(
            envelope["members"][0]["error"]
                .as_str()
                .is_some_and(|e| e.contains("vitest"))
        );
    }
}

#[test]
fn test_and_bench_script_fallback_loads_named_environments_and_validates_schema() {
    for tool in ["test", "bench"] {
        for json in [false, true] {
            let project=TempProject::empty(&serde_json::json!({"name":"fallback-env","version":"1.0.0","scripts":{tool:"node capture.cjs"}}).to_string());
            project.write_file("capture.cjs","require('fs').writeFileSync('captured.txt',process.env.LPM_TB_FIXTURE_VALUE || 'missing');");
            project.write_file(".env.staging", "LPM_TB_FIXTURE_VALUE=selected\n");
            project.write_file(
                "lpm.json",
                &serde_json::json!({"env":{tool:".env.staging"}}).to_string(),
            );
            let mut command = lpm(&project);
            if json {
                command.arg("--json");
            }
            let output = command.arg(tool).output().unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert_eq!(project.read_file("captured.txt"), "selected");
            project.write_file(
                "lpm.json",
                r#"{"envSchema":{"vars":{"LPM_TB_MISSING_REQUIRED":{"required":true}}}}"#,
            );
            std::fs::remove_file(project.path().join("captured.txt")).unwrap();
            let mut command = lpm(&project);
            if json {
                command.arg("--json");
            }
            let output = command.arg(tool).output().unwrap();
            assert!(
                !output.status.success(),
                "missing schema input did not stop {tool}"
            );
            assert!(!project.file_exists("captured.txt"));
            if json {
                let _: serde_json::Value =
                    serde_json::from_slice(&output.stdout).expect("one setup error envelope");
            }
        }
    }
}

#[cfg(unix)]
#[test]
fn workspace_jest_workers_are_not_watch_mode_and_watch_all_is_gated() {
    let project = TempProject::empty(
        r#"{"name":"jest-workspace","private":true,"workspaces":["packages/*"]}"#,
    );
    for name in ["a", "b"] {
        project.write_file(
            &format!("packages/{name}/package.json"),
            &serde_json::json!({"name":name,"version":"1.0.0","devDependencies":{"jest":"30.0.0"}})
                .to_string(),
        );
    }
    write_unix_executable(
        &project.path().join("node_modules/.bin/jest"),
        "#!/bin/sh\nprintf '%s\\n' \"$@\" > invoked.args\n",
    );
    let workers = lpm(&project)
        .args(["test", "--all", "--", "-w", "2"])
        .output()
        .unwrap();
    assert!(
        workers.status.success(),
        "Jest worker count was rejected: {}",
        String::from_utf8_lossy(&workers.stderr)
    );
    for name in ["a", "b"] {
        assert_eq!(
            project.read_file(&format!("packages/{name}/invoked.args")),
            "-w\n2\n"
        );
        std::fs::remove_file(project.path().join(format!("packages/{name}/invoked.args"))).unwrap();
    }
    let watch = lpm(&project)
        .args(["test", "--all", "--", "--watchAll"])
        .output()
        .unwrap();
    assert!(
        !watch.status.success(),
        "multiple workspace watchers were launched"
    );
    for name in ["a", "b"] {
        assert!(!project.file_exists(&format!("packages/{name}/invoked.args")));
    }
}

#[test]
fn test_and_bench_script_fallback_runs_hooks_with_npm_lifecycle_context() {
    for tool in ["test", "bench"] {
        for json in [false, true] {
            let pre = format!("pre{tool}");
            let post = format!("post{tool}");
            let project = TempProject::empty(&serde_json::json!({"name":"fallback-lifecycle","version":"1.2.3","scripts":{&pre:"node capture.cjs",tool:"node capture.cjs",&post:"node capture.cjs"}}).to_string());
            project.write_file("capture.cjs", "require('fs').appendFileSync('phases.jsonl',JSON.stringify({event:process.env.npm_lifecycle_event,name:process.env.npm_package_name,version:process.env.npm_package_version,args:process.argv.slice(2)})+'\\n');");
            let mut command = lpm(&project);
            if json {
                command.arg("--json");
            }
            let output = command.args([tool, "--", "space value"]).output().unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            let rows = project
                .read_file("phases.jsonl")
                .lines()
                .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
                .collect::<Vec<_>>();
            assert_eq!(rows.len(), 3, "package script hooks did not run");
            for (index, event) in [pre.as_str(), tool, post.as_str()].iter().enumerate() {
                assert_eq!(rows[index]["event"], *event);
                assert_eq!(rows[index]["name"], "fallback-lifecycle");
                assert_eq!(rows[index]["version"], "1.2.3");
                assert_eq!(
                    rows[index]["args"],
                    if index == 1 {
                        serde_json::json!(["space value"])
                    } else {
                        serde_json::json!([])
                    }
                );
            }
            if json {
                let _: serde_json::Value =
                    serde_json::from_slice(&output.stdout).expect("one JSON document");
            }
        }
    }
}

#[cfg(unix)]
#[test]
fn test_and_bench_inherit_workspace_runtime_pins_without_overriding_member_pins() {
    for tool in ["test", "bench"] {
        let project = TempProject::empty(
            r#"{"name":"runtime-workspace","private":true,"workspaces":["packages/*"]}"#,
        );
        project.write_file("lpm.json", r#"{"runtime":{"node":"22.0.0"}}"#);
        for (name, version) in [("a", None), ("b", Some("24.0.0"))] {
            project.write_file(&format!("packages/{name}/package.json"), &serde_json::json!({"name":name,"version":"1.0.0","devDependencies":{"vitest":"4.1.9"}}).to_string());
            if let Some(version) = version {
                project.write_file(
                    &format!("packages/{name}/lpm.json"),
                    &serde_json::json!({"runtime":{"node":version}}).to_string(),
                );
            }
        }
        for version in ["22.0.0", "24.0.0"] {
            let directory = project
                .home()
                .join(".lpm/runtimes/node")
                .join(version)
                .join("bin");
            write_unix_executable(
                &directory.join("node"),
                &format!(
                    "#!/bin/sh\nif [ \"$1\" = '--version' ]; then echo v{version}; else echo '{version}' > runtime.txt; fi\n"
                ),
            );
        }
        write_unix_executable(
            &project.path().join("node_modules/.bin/vitest"),
            "#!/usr/bin/env node\n",
        );
        let output = lpm(&project).args([tool, "--all"]).output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(project.read_file("packages/a/runtime.txt").trim(), "22.0.0");
        assert_eq!(project.read_file("packages/b/runtime.txt").trim(), "24.0.0");
    }
}

#[test]
fn test_and_bench_preserve_each_script_phase_exit_code() {
    for tool in ["test", "bench"] {
        for (prefix, code) in [("", 7), ("pre", 8), ("post", 9)] {
            for json in [false, true] {
                let phase = format!("{prefix}{tool}");
                let mut scripts = serde_json::json!({tool:"node -e \"process.exit(0)\""});
                scripts[&phase] = serde_json::json!(format!("node -e \"process.exit({code})\""));
                let project = TempProject::empty(
                    &serde_json::json!({"name":"phase-status","version":"1.0.0","scripts":scripts})
                        .to_string(),
                );
                let mut command = lpm(&project);
                if json {
                    command.arg("--json");
                }
                let output = command.arg(tool).output().unwrap();
                assert_eq!(
                    output.status.code(),
                    Some(code),
                    "{phase} json={json}: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
            }
        }
    }
}

#[cfg(unix)]
#[test]
fn test_and_bench_json_cancellation_keeps_logs_and_runs_cleanup_handlers() {
    use std::os::unix::process::CommandExt;
    use std::time::{Duration, Instant};
    for tool in ["test", "bench"] {
        let project=TempProject::empty(&serde_json::json!({"name":"stop-logs","version":"1.0.0","scripts":{format!("pre{tool}"):"node -e \"console.log('PRE_LOG')\"",tool:"node runner.cjs"}}).to_string());
        project.write_file("runner.cjs","console.log('MAIN_LOG');console.error('ERROR_LOG');process.on('SIGTERM',()=>{require('fs').writeFileSync('cleanup','done');process.exit(0)});require('fs').writeFileSync('ready','ok');setInterval(()=>{},1000);");
        let output_file = project.path().join("output.json");
        let mut child = lpm_spawnable(&project)
            .args(["--json", tool])
            .process_group(0)
            .stdout(std::fs::File::create(&output_file).unwrap())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let group = child.id() as i32;
        let deadline = Instant::now() + Duration::from_secs(10);
        while !project.file_exists("ready") && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        // SAFETY: signal only our owned fixture CLI.
        unsafe {
            libc::kill(group, libc::SIGTERM);
        }
        let deadline = Instant::now() + Duration::from_secs(4);
        let status = loop {
            if let Some(s) = child.try_wait().unwrap() {
                break Some(s);
            }
            if Instant::now() >= deadline {
                break None;
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        // SAFETY: cleanup the isolated fixture group.
        unsafe {
            libc::kill(-group, libc::SIGKILL);
        }
        let _ = child.wait();
        assert_eq!(status.and_then(|s| s.code()), Some(143));
        let envelope: serde_json::Value =
            serde_json::from_slice(&std::fs::read(output_file).unwrap()).unwrap();
        let out = envelope["members"][0]["stdout"]
            .as_str()
            .unwrap_or_default();
        let err = envelope["members"][0]["stderr"]
            .as_str()
            .unwrap_or_default();
        assert!(
            out.contains("PRE_LOG") && out.contains("MAIN_LOG") && err.contains("ERROR_LOG"),
            "cancelled diagnostics lost: {envelope}"
        );
        assert!(
            project.file_exists("cleanup"),
            "JSON cancellation skipped the SIGTERM handler"
        );
    }
}

#[cfg(unix)]
#[test]
fn test_json_cancellation_stops_detached_descendants() {
    use std::os::unix::process::CommandExt;
    use std::time::{Duration, Instant};
    let project = runner_lifetime_fixture("test", false, false, false);
    project.write_file("runner.cjs","const fs=require('fs');const c=require('child_process').spawn(process.execPath,['-e',\"setInterval(()=>require('fs').appendFileSync('heartbeat','x'),20)\"],{stdio:'inherit',detached:true});fs.writeFileSync('detached',String(c.pid));setInterval(()=>{},1000);");
    let mut child = lpm_spawnable(&project)
        .args(["--json", "test"])
        .process_group(0)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let group = child.id() as i32;
    let deadline = Instant::now() + Duration::from_secs(10);
    while !project.file_exists("heartbeat") && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    let detached = project.read_file("detached").parse::<i32>().unwrap();
    // SAFETY: signals target only the recorded fixture CLI.
    unsafe {
        libc::kill(group, libc::SIGTERM);
    }
    let deadline = Instant::now() + Duration::from_secs(4);
    while child.try_wait().unwrap().is_none() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    let before = project.read_file("heartbeat");
    std::thread::sleep(Duration::from_millis(150));
    let after = project.read_file("heartbeat");
    // SAFETY: both groups belong only to this fixture, including its detached child.
    unsafe {
        libc::kill(-detached, libc::SIGKILL);
        libc::kill(-group, libc::SIGKILL);
    }
    let _ = child.wait();
    assert_eq!(before, after, "detached child survived cancellation");
}

#[cfg(unix)]
#[test]
fn workspace_check_does_not_swallow_stop_signals() {
    use std::os::unix::process::CommandExt;
    use std::time::{Duration, Instant};
    let project =
        TempProject::empty(r#"{"name":"check-stop","private":true,"workspaces":["packages/*"]}"#);
    project.write_file(
        "packages/a/package.json",
        r#"{"name":"a","version":"1.0.0","devDependencies":{"typescript":"5.0.0"}}"#,
    );
    project.write_file("packages/a/tsconfig.json", "{}");
    write_unix_executable(
        &project.path().join("node_modules/.bin/tsc"),
        "#!/bin/sh\necho ready > ready\nsleep 20\n",
    );
    let mut child = lpm_spawnable(&project)
        .args(["check", "--all"])
        .process_group(0)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let group = child.id() as i32;
    let deadline = Instant::now() + Duration::from_secs(10);
    while !project.file_exists("packages/a/ready") && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    // SAFETY: signal only the fixture CLI.
    unsafe {
        libc::kill(group, libc::SIGTERM);
    }
    let deadline = Instant::now() + Duration::from_secs(2);
    let exited = loop {
        if child.try_wait().unwrap().is_some() {
            break true;
        }
        if Instant::now() >= deadline {
            break false;
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    // SAFETY: cleanup only the isolated fixture group.
    unsafe {
        libc::kill(-group, libc::SIGKILL);
    }
    let _ = child.wait();
    assert!(
        exited,
        "test handlers swallowed the unrelated check stop signal"
    );
}

#[cfg(unix)]
#[test]
fn workspace_vitest_watch_forms_cannot_bypass_the_single_member_gate() {
    let project =
        TempProject::empty(r#"{"name":"vitest-watch","private":true,"workspaces":["packages/*"]}"#);
    for name in ["a", "b"] {
        project.write_file(
            &format!("packages/{name}/package.json"),
            &serde_json::json!({"name":name,"devDependencies":{"vitest":"4.1.9"}}).to_string(),
        );
    }
    write_unix_executable(
        &project.path().join("node_modules/.bin/vitest"),
        "#!/bin/sh\necho ran > ran\n",
    );
    for flag in ["--watch=off", "--watch=0", "--watch=FALSE", "-w=true"] {
        let output = lpm(&project)
            .args(["test", "--all", "--", flag])
            .output()
            .unwrap();
        assert!(!output.status.success(), "{flag} bypassed watch admission");
        assert!(!project.file_exists("packages/a/ran"));
    }
    for flags in [vec!["--watchAll=false"], vec!["-w", "2"]] {
        let output = lpm(&project)
            .args(["test", "--filter", "missing", "--"])
            .args(flags)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "empty nonwatch selection was rejected"
        );
    }
}

#[test]
fn test_and_bench_fallback_uses_task_environment_without_task_command() {
    for tool in ["test", "bench"] {
        let project=TempProject::empty(&serde_json::json!({"name":"task-env","version":"1.0.0","scripts":{tool:"node read.cjs"}}).to_string());
        project.write_file(
            "read.cjs",
            "require('fs').writeFileSync('value',process.env.LPM_FIXTURE_TEST_VALUE);",
        );
        project.write_file(".env.named", "LPM_FIXTURE_TEST_VALUE=script\n");
        project.write_file(".env.production", "LPM_FIXTURE_TEST_VALUE=task\n");
        project.write_file("lpm.json",&serde_json::json!({"env":{tool:".env.named"},"tasks":{tool:{"command":"node absent-command.cjs","env":"production"}}}).to_string());
        let output = lpm(&project).args(["--json", tool]).output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stdout)
        );
        assert_eq!(project.read_file("value"), "task");
    }
}

#[test]
fn test_and_bench_keep_pre_hook_output_pipes_through_later_phases() {
    for tool in ["test", "bench"] {
        let project=TempProject::empty(&serde_json::json!({"name":"late-service-output","version":"1.0.0","scripts":{format!("pre{tool}"):"node start.cjs",tool:"node check.cjs"}}).to_string());
        project.write_file("start.cjs","const c=require('child_process').spawn(process.execPath,['service.cjs'],{stdio:'inherit'});c.unref();");
        project.write_file("service.cjs","setInterval(()=>require('fs').appendFileSync('heartbeat','x'),10);setTimeout(()=>{console.log('LATE_SERVICE');console.error('LATE_ERROR')},500);");
        project.write_file("check.cjs","const fs=require('fs');setTimeout(()=>{const a=fs.readFileSync('heartbeat','utf8');setTimeout(()=>{const b=fs.readFileSync('heartbeat','utf8');process.exit(b.length>a.length?7:8)},200)},600);");
        let output = lpm(&project).args(["--json", tool]).output().unwrap();
        assert_eq!(
            output.status.code(),
            Some(7),
            "service died after its inherited pipe was closed: {}",
            String::from_utf8_lossy(&output.stdout)
        );
        let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert!(
            value["members"][0]["stdout"]
                .as_str()
                .unwrap_or_default()
                .contains("LATE_SERVICE")
        );
        assert!(
            value["members"][0]["stderr"]
                .as_str()
                .unwrap_or_default()
                .contains("LATE_ERROR")
        );
    }
}

#[cfg(unix)]
#[test]
fn lint_workspace_inherits_root_pin_and_keeps_member_overrides_from_any_cwd() {
    let project = TempProject::from_fixture("workspace-monorepo");
    project.write_file("lpm.json", r#"{"tools":{"oxlint":"1.0.0"}}"#);
    project.write_file("packages/utils/lpm.json", r#"{"tools":{"oxlint":"2.0.0"}}"#);
    for version in ["1.0.0", "2.0.0", "1.79.0"] {
        seed_fake_plugin_script(
            &project,
            "oxlint",
            version,
            &format!("#!/bin/sh\nprintf '{version}' > selected-version\n"),
        );
    }
    for cwd in [
        project.path().to_path_buf(),
        project.path().join("packages/utils"),
    ] {
        let output = lpm(&project)
            .current_dir(cwd)
            .args(["--json", "lint", "--all"])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stdout)
        );
        for member in WORKSPACE_MEMBERS {
            let expected = if member == "packages/utils" {
                "2.0.0"
            } else {
                "1.0.0"
            };
            assert_eq!(
                project.read_file(&format!("{member}/selected-version")),
                expected,
                "wrong pin for {member}"
            );
        }
    }
}

#[cfg(unix)]
#[test]
fn lint_workspace_does_not_install_an_unused_root_version() {
    let project = TempProject::from_fixture("workspace-monorepo");
    seed_workspace_tool_pin(&project, "oxlint", "1.0.0");
    project.write_file("lpm.json", r#"{"tools":{"oxlint":"not-a-valid-version"}}"#);
    seed_fake_plugin(&project, "oxlint", "1.0.0", ".lint-ok");
    let output = lpm(&project)
        .args(["--json", "lint", "--all"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "unused root version blocked explicit member pins: {}",
        String::from_utf8_lossy(&output.stdout)
    );
}

#[cfg(unix)]
#[test]
fn lint_workspace_processes_can_reach_a_shared_barrier_concurrently() {
    let project =
        TempProject::empty(r#"{"name":"tool-barrier","private":true,"workspaces":["packages/*"]}"#);
    project.write_file("lpm.json", r#"{"tools":{"oxlint":"1.0.0"}}"#);
    let count = std::thread::available_parallelism()
        .map_or(1, usize::from)
        .min(4);
    if count < 2 {
        return;
    }
    for name in ["a", "b", "c", "d"].into_iter().take(count) {
        project.write_file(
            &format!("packages/{name}/package.json"),
            &format!(r#"{{"name":"{name}","version":"1.0.0"}}"#),
        );
        project.write_file(
            &format!("packages/{name}/lpm.json"),
            r#"{"tools":{"oxlint":"1.0.0"}}"#,
        );
    }
    seed_fake_plugin_script(
        &project,
        "oxlint",
        "1.0.0",
        &format!(
            "#!/bin/sh\n: > ready\ni=0\nwhile [ $i -lt 100 ]; do\n  count=$(find .. -name ready | wc -l)\n  [ $count -eq {count} ] && exit 0\n  i=$((i+1))\n  sleep 0.02\ndone\nexit 8\n"
        ),
    );
    let output = lpm(&project)
        .env("TOKIO_WORKER_THREADS", "1")
        .args(["--json", "lint", "--all"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "tool waits serialized: {}",
        String::from_utf8_lossy(&output.stdout)
    );
}

#[cfg(unix)]
#[test]
fn lint_json_captures_one_envelope_and_preserves_the_child_exit_code() {
    let project = TempProject::empty(r#"{"name":"lint-json","version":"1.0.0"}"#);
    project.write_file("lpm.json", r#"{"tools":{"oxlint":"1.0.0"}}"#);
    seed_fake_plugin_script(
        &project,
        "oxlint",
        "1.0.0",
        "#!/bin/sh\necho lint-diagnostic\necho lint-error >&2\nexit 7\n",
    );
    let output = lpm(&project).args(["--json", "lint"]).output().unwrap();
    assert_eq!(output.status.code(), Some(7));
    let value: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("one JSON envelope");
    assert_eq!(value["members"][0]["stdout"], "lint-diagnostic\n");
    assert_eq!(value["members"][0]["stderr"], "lint-error\n");
    insta::assert_json_snapshot!("lint_single_failure", value, {
        ".duration_ms" => 0,
        ".members[].duration_ms" => 0,
    });
}

#[cfg(unix)]
#[test]
fn lint_workspace_json_bounds_multibyte_diagnostics_without_panicking() {
    let project = TempProject::from_fixture("workspace-monorepo");
    seed_workspace_tool_pin(&project, "oxlint", "1.0.0");
    seed_fake_plugin_script(
        &project,
        "oxlint",
        "1.0.0",
        "#!/bin/sh\nnode -e \"process.stdout.write('a'.repeat(10*1024*1024-1)+'€'.repeat(1024));process.exitCode=7\"\n",
    );
    let output = lpm(&project)
        .args(["--json", "lint", "--filter", "@test/utils"])
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(1),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("UTF-8-safe bounded envelope");
    let stdout = value["members"][0]["stdout"].as_str().unwrap();
    assert!(stdout.len() <= 10 * 1024 * 1024 + 128);
    assert!(stdout.contains("truncated"));
}

#[cfg(unix)]
#[test]
fn lint_stop_signals_stop_tool_descendants() {
    for workspace in [false, true] {
        for json in [false, true] {
            run_lifetime_case("lint", false, workspace, json, false);
        }
    }
}

#[cfg(unix)]
#[test]
fn lint_json_finishes_when_descendants_inherit_output_pipes() {
    for workspace in [false, true] {
        run_lifetime_case("lint", false, workspace, true, true);
    }
}

#[cfg(unix)]
#[test]
fn lint_json_marks_newline_terminated_output_only_when_truncated() {
    for extra in [0, 2] {
        let project = TempProject::empty(r#"{"name":"lint-cap","version":"1.0.0"}"#);
        project.write_file("lpm.json", r#"{"tools":{"oxlint":"1.0.0"}}"#);
        seed_fake_plugin_script(
            &project,
            "oxlint",
            "1.0.0",
            &format!(
                "#!/bin/sh\nnode -e \"const s='a\\n'.repeat((10*1024*1024+{extra})/2);process.stdout.write(s);process.stderr.write(s);process.exitCode=7\"\n"
            ),
        );
        let output = lpm(&project).args(["--json", "lint"]).output().unwrap();
        let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        for key in ["stdout", "stderr"] {
            let text = value["members"][0][key].as_str().unwrap();
            assert_eq!(
                text.contains("truncated"),
                extra > 0,
                "missing or false truncation marker for {key}"
            );
        }
    }
}

#[cfg(unix)]
#[test]
fn lint_workspace_can_be_interrupted_during_plugin_preparation() {
    use std::io::Read;
    use std::net::TcpListener;
    use std::sync::mpsc;
    use std::time::{Duration, Instant};
    let project = TempProject::from_fixture("workspace-monorepo");
    seed_workspace_tool_pin(&project, "oxlint", "1.0.0");
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let proxy = format!("http://{}", listener.local_addr().unwrap());
    let (ready_tx, ready_rx) = mpsc::channel();
    let (done_tx, done_rx) = mpsc::channel();
    let server = std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if let Ok((mut stream, _)) = listener.accept() {
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                let mut buffer = [0u8; 4096];
                let size = stream.read(&mut buffer).unwrap();
                ready_tx
                    .send(String::from_utf8_lossy(&buffer[..size]).starts_with("CONNECT "))
                    .unwrap();
                let _ = done_rx.recv_timeout(Duration::from_secs(10));
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    });
    let mut child = lpm_spawnable(&project)
        .args(["--json", "lint", "--all"])
        .env("HTTPS_PROXY", &proxy)
        .env("https_proxy", &proxy)
        .env("NO_PROXY", "")
        .env("no_proxy", "")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let ready = ready_rx
        .recv_timeout(Duration::from_secs(10))
        .unwrap_or(false);
    // SAFETY: child is the fixture's owned CLI process.
    unsafe {
        libc::kill(child.id() as i32, libc::SIGTERM);
    }
    let deadline = Instant::now() + Duration::from_secs(2);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break Some(status);
        }
        if Instant::now() > deadline {
            break None;
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    let _ = child.kill();
    let _ = child.wait();
    let _ = done_tx.send(());
    server.join().unwrap();
    assert!(ready, "plugin download did not reach the controlled proxy");
    assert!(status.is_some(), "plugin preparation swallowed SIGTERM");
}

#[cfg(unix)]
#[test]
fn lint_json_reporting_stops_when_the_reader_blocks_and_the_cli_is_interrupted() {
    use std::io::Read;
    use std::time::{Duration, Instant};
    for workspace in [false, true] {
        let project = TempProject::from_fixture("workspace-monorepo");
        seed_workspace_tool_pin(&project, "oxlint", "1.0.0");
        seed_fake_plugin_script(
            &project,
            "oxlint",
            "1.0.0",
            "#!/bin/sh\nnode -e \"process.stdout.write('x'.repeat(1024*1024));process.exitCode=7\"\n",
        );
        let mut command = lpm_spawnable(&project);
        command.args(["--json", "lint"]);
        if workspace {
            command.arg("--all");
        }
        let mut child = command
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let mut output = child.stdout.take().unwrap();
        let mut byte = [0u8; 1];
        output.read_exact(&mut byte).unwrap();
        // SAFETY: the process identifier belongs to this fixture.
        unsafe {
            libc::kill(child.id() as i32, libc::SIGTERM);
        }
        let deadline = Instant::now() + Duration::from_secs(2);
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break Some(status);
            }
            if Instant::now() > deadline {
                break None;
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        let _ = child.kill();
        let _ = child.wait();
        assert!(
            status.is_some(),
            "JSON reporting ignored interruption with workspace={workspace}"
        );
        assert_eq!(status.unwrap().code(), Some(143));
    }
}

#[cfg(unix)]
#[test]
fn lint_workspace_reports_bad_member_config_without_skipping_healthy_members() {
    let project = TempProject::from_fixture("workspace-monorepo");
    seed_workspace_tool_pin(&project, "oxlint", "1.0.0");
    seed_fake_plugin(&project, "oxlint", "1.0.0", ".lint-ok");
    project.write_file("packages/utils/lpm.json", "{");
    let output = lpm(&project)
        .args(["--json", "lint", "--all"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["failed"], 1);
    assert_eq!(value["succeeded"], 2);
    assert!(!project.file_exists("packages/utils/.lint-ok"));
    assert!(project.file_exists("packages/core/.lint-ok"));
}

#[cfg(unix)]
#[test]
fn native_tools_keep_project_pins_when_run_from_nested_directories() {
    for (command, plugin) in [("lint", "oxlint"), ("fmt", "biome")] {
        for workspace in [false, true] {
            let project = TempProject::empty(if workspace {
                r#"{"name":"root","private":true,"workspaces":["packages/*"]}"#
            } else {
                r#"{"name":"single"}"#
            });
            let member = if workspace { "packages/member/" } else { "" };
            project.write_file(
                "lpm.json",
                &serde_json::json!({"tools":{plugin:"1.0.0"}}).to_string(),
            );
            project.write_file(&format!("{member}package.json"), r#"{"name":"member"}"#);
            project.write_file(
                &format!("{member}lpm.json"),
                &serde_json::json!({"tools":{plugin:"2.0.0"}}).to_string(),
            );
            for version in ["1.0.0", "2.0.0", "1.79.0", "2.5.9"] {
                seed_fake_plugin_script(
                    &project,
                    plugin,
                    version,
                    &format!("#!/bin/sh\nprintf '{version}' > selected-version\n"),
                );
            }
            project.write_file(&format!("{member}src/input.js"), "");
            let output = lpm(&project)
                .current_dir(project.path().join(format!("{member}src")))
                .arg(command)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert_eq!(
                project.read_file(&format!("{member}src/selected-version")),
                "2.0.0",
                "nested {command} lost its project pin"
            );
        }
    }
}
