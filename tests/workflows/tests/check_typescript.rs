//! Workflow tests for the TypeScript readiness contract.
//!
//! Pins the source/docs parity bug fix:
//!
//! - `lpm doctor --json` now emits per-tsconfig checks with the codes
//!   `typescript_healthy`, `typescript_missing_for_tsconfig`, and
//!   `typescript_unavailable`. Doctor never runs a real type-check —
//!   only cheap reachability + dep-declaration checks.
//! - `lpm check`'s call-site preflight surfaces the missing-tsconfig
//!   and missing-typescript cases with LPM-formatted errors instead
//!   of letting tsc emit a less actionable message. The preflight is
//!   argument-aware: explicit `-p` / positional file targets bypass it.
//! - Unsupported `lpm.json > tools` keys (anything other than `oxlint`
//!   and `biome`) emit a single warning per process invocation.

mod support;

use support::assertions::parse_json_output;
use support::{TempProject, lpm, lpm_with_registry};

const TSGO_VERSION: &str = "7.0.0-dev.20260707.2";

fn make_local_tool(project: &TempProject, rel_dir: &str, tool_name: &str, script: &str) {
    let bin_rel = if rel_dir.is_empty() {
        format!("node_modules/.bin/{tool_name}")
    } else {
        format!("{rel_dir}/node_modules/.bin/{tool_name}")
    };
    project.write_file(&bin_rel, script);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let path = project.path().join(&bin_rel);
        let mut perms = std::fs::metadata(&path).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&path, perms).unwrap();
    }
}

fn make_local_tsc(project: &TempProject, rel_dir: &str) {
    // Create a fake tsc shim inside `<rel_dir>/node_modules/.bin/`.
    // We never spawn it — the predicate only checks file existence.
    make_local_tool(project, rel_dir, "tsc", "#!/bin/sh\nexit 0\n");
}

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

fn normalize_rel_path(path: &std::path::Path) -> String {
    path.components()
        .map(|component| component.as_os_str().to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .join("/")
}

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

fn seed_fake_tsgo_engine(project: &TempProject, entry_script: &str) {
    let (platform, entry_rel_path) = current_engine_platform();
    let engine_dir = project
        .home()
        .join(".lpm")
        .join("engines")
        .join("tsgo")
        .join(TSGO_VERSION)
        .join(platform);
    let entry_path = engine_dir.join(entry_rel_path);
    let lib_dts_path = engine_dir.join("lib/lib.d.ts");

    std::fs::create_dir_all(entry_path.parent().unwrap()).unwrap();
    std::fs::write(&entry_path, entry_script).unwrap();
    std::fs::write(&lib_dts_path, b"declare const x: string\n").unwrap();

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&entry_path).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&entry_path, perms).unwrap();
    }

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
        serde_json::to_vec_pretty(&sidecar).unwrap(),
    )
    .unwrap();
}

fn find_check_by_code<'a>(
    json: &'a serde_json::Value,
    code: &str,
) -> Option<&'a serde_json::Value> {
    json["checks"]
        .as_array()?
        .iter()
        .find(|c| c["code"].as_str() == Some(code))
}

// ─── lpm doctor: typescript_healthy ────────────────────────────────

#[test]
fn doctor_emits_typescript_healthy_when_local_tsc_resolves() {
    let project = TempProject::empty(
        r#"{"name": "test", "version": "1.0.0", "devDependencies": {"typescript": "^5"}}"#,
    );
    project.write_file("tsconfig.json", r#"{"compilerOptions": {}}"#);
    make_local_tsc(&project, "");

    let output = lpm_with_registry(&project, "http://127.0.0.1:1")
        .args(["doctor", "--all", "--json"])
        .output()
        .expect("failed to run lpm doctor --json");

    let json = parse_json_output(&output.stdout);
    let entry = find_check_by_code(&json, "typescript_healthy")
        .unwrap_or_else(|| panic!("expected typescript_healthy; got: {json}"));
    assert_eq!(entry["severity"].as_str(), Some("pass"));
    assert_eq!(entry["passed"].as_bool(), Some(true));
}

// ─── lpm doctor: typescript_unavailable, dep declared but not installed ──

#[test]
fn doctor_emits_typescript_unavailable_when_declared_but_not_installed() {
    let project = TempProject::empty(
        r#"{"name": "test", "version": "1.0.0", "devDependencies": {"typescript": "^5"}}"#,
    );
    project.write_file("tsconfig.json", r#"{"compilerOptions": {}}"#);

    let output = lpm_with_registry(&project, "http://127.0.0.1:1")
        // Strip PATH so no system tsc is reachable — guarantees the
        // unavailable branch even on a developer machine.
        .env("PATH", "")
        .args(["doctor", "--all", "--json"])
        .output()
        .expect("failed to run lpm doctor --json");

    let json = parse_json_output(&output.stdout);
    let entry = find_check_by_code(&json, "typescript_unavailable")
        .unwrap_or_else(|| panic!("expected typescript_unavailable; got: {json}"));
    assert_eq!(entry["severity"].as_str(), Some("fail"));
    assert!(
        entry["detail"]
            .as_str()
            .unwrap_or("")
            .contains("declared but not installed"),
        "detail should mention the declared-but-not-installed case; got: {}",
        entry["detail"]
    );
}

// ─── lpm doctor: typescript_unavailable, dep not declared ──────────

#[test]
fn doctor_emits_typescript_unavailable_when_dep_not_declared() {
    let project = TempProject::empty(r#"{"name": "test", "version": "1.0.0"}"#);
    project.write_file("tsconfig.json", r#"{"compilerOptions": {}}"#);

    let output = lpm_with_registry(&project, "http://127.0.0.1:1")
        .env("PATH", "")
        .args(["doctor", "--all", "--json"])
        .output()
        .expect("failed to run lpm doctor --json");

    let json = parse_json_output(&output.stdout);
    let entry = find_check_by_code(&json, "typescript_unavailable")
        .unwrap_or_else(|| panic!("expected typescript_unavailable; got: {json}"));
    assert_eq!(entry["severity"].as_str(), Some("fail"));
    assert!(
        entry["detail"]
            .as_str()
            .unwrap_or("")
            .contains("lpm install -D typescript"),
        "detail should suggest `lpm install -D typescript`; got: {}",
        entry["detail"]
    );
}

// ─── lpm doctor: silent when no tsconfig ───────────────────────────

#[test]
fn doctor_emits_no_typescript_check_when_no_tsconfig_anywhere() {
    let project = TempProject::empty(r#"{"name": "test", "version": "1.0.0"}"#);

    let output = lpm_with_registry(&project, "http://127.0.0.1:1")
        .env("PATH", "")
        .args(["doctor", "--all", "--json"])
        .output()
        .expect("failed to run lpm doctor --json");

    let json = parse_json_output(&output.stdout);
    assert!(
        find_check_by_code(&json, "typescript_healthy").is_none()
            && find_check_by_code(&json, "typescript_missing_for_tsconfig").is_none()
            && find_check_by_code(&json, "typescript_unavailable").is_none(),
        "no tsconfig in tree must produce no TS check; got: {json}"
    );
}

// ─── lpm doctor: workspace-aware — per-member checks ───────────────

#[test]
fn doctor_emits_per_member_typescript_checks_in_workspace() {
    let project = TempProject::empty(
        r#"{
            "name": "root",
            "version": "1.0.0",
            "private": true,
            "workspaces": ["packages/*"],
            "devDependencies": {"typescript": "^5"}
        }"#,
    );

    // Two members: one with tsconfig (should fire), one without (silent).
    project.write_file("packages/app/package.json", r#"{"name":"@scope/app"}"#);
    project.write_file("packages/app/tsconfig.json", r#"{"compilerOptions": {}}"#);
    project.write_file("packages/lib/package.json", r#"{"name":"@scope/lib"}"#);

    // Local tsc at the root only — typescript is hoisted in the
    // common monorepo shape. Members walk up to find it.
    make_local_tsc(&project, "");

    let output = lpm_with_registry(&project, "http://127.0.0.1:1")
        .args(["doctor", "--all", "--json"])
        .output()
        .expect("failed to run lpm doctor --json");

    let json = parse_json_output(&output.stdout);
    let entries: Vec<_> = json["checks"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|c| c["code"].as_str() == Some("typescript_healthy"))
        .collect();
    // No root tsconfig, one member tsconfig — exactly one healthy entry.
    assert_eq!(
        entries.len(),
        1,
        "expected exactly one healthy entry for the member with tsconfig; got: {entries:?}"
    );
    assert!(
        entries[0]["detail"]
            .as_str()
            .unwrap_or("")
            .starts_with("packages/app:")
            || entries[0]["detail"]
                .as_str()
                .unwrap_or("")
                .contains("packages/app"),
        "detail should label the member path; got: {}",
        entries[0]["detail"]
    );
}

// ─── lpm check preflight: missing tsconfig ─────────────────────────

#[test]
fn check_preflight_errors_when_no_tsconfig_and_no_explicit_target() {
    let project = TempProject::empty(r#"{"name": "test", "version": "1.0.0"}"#);

    let output = lpm(&project)
        .args(["check"])
        .output()
        .expect("failed to run lpm check");

    assert!(
        !output.status.success(),
        "missing tsconfig must fail preflight; got success"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("no tsconfig.json found"),
        "preflight error must mention missing tsconfig; got:\n{stderr}"
    );
}

// ─── lpm check preflight: explicit -p bypasses the tsconfig check ──

#[test]
fn check_preflight_skips_when_user_passes_explicit_project() {
    let project = TempProject::empty(
        r#"{"name": "test", "version": "1.0.0", "devDependencies": {"typescript": "^5"}}"#,
    );
    project.write_file("tsconfig.test.json", r#"{"compilerOptions": {}}"#);

    let output = lpm(&project)
        // No tsc reachable — the spawn at run_tsc fails, but the
        // failure is the spawn-level "Is typescript installed?" hint,
        // NOT our preflight's "no tsconfig.json found in ..." error.
        .env("PATH", "")
        .args(["check", "--", "-p", "tsconfig.test.json"])
        .output()
        .expect("failed to run lpm check");

    assert!(!output.status.success(), "spawn fails without tsc on PATH");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("no tsconfig.json found"),
        "preflight must defer to tsc when -p is passed; got stderr:\n{stderr}"
    );
}

// ─── lpm check preflight: typescript missing entirely ──────────────

#[test]
fn check_preflight_errors_when_typescript_not_installed_or_declared() {
    let project = TempProject::empty(r#"{"name": "test", "version": "1.0.0"}"#);
    project.write_file("tsconfig.json", r#"{"compilerOptions": {}}"#);

    let output = lpm(&project)
        .env("PATH", "")
        .args(["check"])
        .output()
        .expect("failed to run lpm check");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("typescript not installed") && stderr.contains("lpm install -D typescript"),
        "preflight should suggest `lpm install -D typescript`; got:\n{stderr}"
    );
}

// ─── lpm check preflight: declared but not installed ───────────────

#[test]
fn check_preflight_errors_when_typescript_declared_but_not_installed() {
    let project = TempProject::empty(
        r#"{"name": "test", "version": "1.0.0", "devDependencies": {"typescript": "^5"}}"#,
    );
    project.write_file("tsconfig.json", r#"{"compilerOptions": {}}"#);

    let output = lpm(&project)
        .env("PATH", "")
        .args(["check"])
        .output()
        .expect("failed to run lpm check");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("declared in package.json but not installed")
            && stderr.contains("lpm install"),
        "preflight should distinguish declared-vs-not-declared; got:\n{stderr}"
    );
}

// ─── lpm check --engine tsgo: local shim + noEmit contract ───────

#[test]
fn check_tsgo_engine_uses_seeded_managed_engine_with_no_emit() {
    let project = TempProject::empty(r#"{"name": "test", "version": "1.0.0"}"#);
    project.write_file("tsconfig.json", r#"{"compilerOptions": {}}"#);
    seed_fake_tsgo_engine(
        &project,
        "#!/bin/sh\nprintf '%s\n' \"$@\" > .tsgo-args.txt\nexit 0\n",
    );

    let output = lpm(&project)
        .env("PATH", "")
        .args(["check", "--engine", "tsgo"])
        .output()
        .expect("failed to run lpm check --engine tsgo");

    assert!(
        output.status.success(),
        "seeded managed tsgo should satisfy lpm check; stderr:\n{}",
        String::from_utf8_lossy(&output.stderr),
    );

    let args = std::fs::read_to_string(project.path().join(".tsgo-args.txt"))
        .expect("expected tsgo shim to capture args");
    assert!(
        args.lines().any(|line| line == "--noEmit"),
        "lpm check must preserve no-emit semantics for tsgo; got args:\n{args}"
    );
}

// ─── lpm.json > tools.<unsupported>: warns once on tool command ────

#[test]
fn unsupported_tool_pin_emits_warning_on_tool_command() {
    let project = TempProject::empty(
        r#"{"name": "test", "version": "1.0.0", "devDependencies": {"typescript": "^5"}}"#,
    );
    project.write_file("tsconfig.json", r#"{"compilerOptions": {}}"#);
    project.write_file(
        "lpm.json",
        r#"{"tools": {"typescript": "5.4.0", "biome": "2.4.10"}}"#,
    );
    make_local_tsc(&project, "");

    let output = lpm(&project)
        .args(["check"])
        .output()
        .expect("failed to run lpm check");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("tools.typescript ignored")
            || stderr.contains("tools.typescript")
                && stderr.contains("ignored")
                && stderr.contains("oxlint")
                && stderr.contains("biome"),
        "expected unsupported-tools warning naming the offending key + supported set; got:\n{stderr}"
    );
}

#[test]
fn unsupported_tool_pin_silent_when_only_supported_keys() {
    let project = TempProject::empty(
        r#"{"name": "test", "version": "1.0.0", "devDependencies": {"typescript": "^5"}}"#,
    );
    project.write_file("tsconfig.json", r#"{"compilerOptions": {}}"#);
    project.write_file(
        "lpm.json",
        r#"{"tools": {"oxlint": "1.58.0", "biome": "2.4.10"}}"#,
    );
    make_local_tsc(&project, "");

    let output = lpm(&project)
        .args(["check"])
        .output()
        .expect("failed to run lpm check");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("ignored — only oxlint and biome"),
        "no warning expected when tools.* keys are all plugin-backed; got:\n{stderr}"
    );
}

#[cfg(unix)]
fn seed_recording_tsc(project: &TempProject) {
    make_local_tool(
        project,
        "",
        "tsc",
        "#!/bin/sh\nprintf '%s\\n' \"$@\" > .check-args.txt\nprintf 'compiler output\\n'\nexit 0\n",
    );
}

#[cfg(unix)]
#[test]
fn check_preserves_build_as_the_first_compiler_argument() {
    for engine in ["tsc", "tsgo"] {
        let project = TempProject::empty(r#"{"name":"build-check"}"#);
        project.write_file("tsconfig.json", "{}");
        let script =
            "#!/bin/sh\n[ \"$1\" = --build ] || exit 7\nprintf '%s\\n' \"$@\" > .check-args.txt\n";
        make_local_tool(&project, "", "tsc", script);
        seed_fake_tsgo_engine(&project, script);
        let output = lpm(&project)
            .args(["check", "--engine", engine, "--", "--build"])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{engine}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            project
                .read_file(".check-args.txt")
                .lines()
                .any(|arg| arg == "--noEmit")
        );
    }
}

#[cfg(unix)]
#[test]
fn check_help_version_and_invalid_options_reach_the_compiler_without_a_config() {
    let project = TempProject::empty(r#"{"name":"compiler-options"}"#);
    seed_recording_tsc(&project);
    for args in [
        vec!["--help"],
        vec!["--version"],
        vec!["--all"],
        vec!["-p"],
        vec!["--pretty", "false"],
    ] {
        let output = lpm(&project)
            .args(["check", "--"])
            .args(&args)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(String::from_utf8_lossy(&output.stdout).contains("compiler output"));
    }
}

#[cfg(unix)]
#[test]
fn check_bare_nested_invocation_finds_an_ancestor_project_config() {
    let project = TempProject::empty(r#"{"name":"ancestor-config"}"#);
    project.write_file("tsconfig.json", "{}");
    project.write_file("src/nested/entry.ts", "export const x=1");
    seed_recording_tsc(&project);
    let output = lpm(&project)
        .current_dir(project.path().join("src/nested"))
        .arg("check")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[cfg(unix)]
#[test]
fn check_single_json_captures_diagnostics_and_preserves_compiler_exit_code() {
    let project = TempProject::empty(r#"{"name":"failed-check"}"#);
    project.write_file("tsconfig.json", "{}");
    make_local_tool(
        &project,
        "",
        "tsc",
        "#!/bin/sh\nprintf 'type error\\n'\nprintf 'details\\n' >&2\nexit 7\n",
    );
    let output = lpm(&project).args(["check", "--json"]).output().unwrap();
    assert_eq!(output.status.code(), Some(7));
    let value: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("one JSON envelope");
    assert_eq!(value["members"][0]["exit_code"], 7);
    assert!(
        value["members"][0]["stdout"]
            .as_str()
            .unwrap()
            .contains("type error")
    );
    insta::assert_json_snapshot!("check_single_failure", value, {".duration_ms" => "[duration]", ".members[].duration_ms" => "[duration]"});
}

#[cfg(unix)]
#[test]
fn check_no_emit_wins_over_forwarded_flags_responses_and_dangling_values() {
    let project = TempProject::empty(r#"{"name":"no-emit"}"#);
    project.write_file("tsconfig.json", "{}");
    project.write_file("inner.args", "--noEmit false\n");
    project.write_file("outer.args", "@inner.args\n");
    project.write_file("compiler.cjs", r#"
const fs=require('fs');let noEmit=false;
function parse(args){for(let i=0;i<args.length;i++){
 const a=args[i]; if(a.startsWith('@')) {parse(fs.readFileSync(a.slice(1),'utf8').trim().split(/\s+/));continue;}
 const key=a.replace(/^--?/,'').toLowerCase();
 if(key==='outdir'){i++;continue;}
 if(key==='noemit') {const v=args[i+1];noEmit=v!=='false'&&v!=='null';if(['true','false','null'].includes(v))i++;}
}}
parse(process.argv.slice(2)); if(!noEmit) fs.writeFileSync('unexpected.js','emitted');
"#);
    make_local_tool(
        &project,
        "",
        "tsc",
        "#!/bin/sh\nexec node compiler.cjs \"$@\"\n",
    );
    let cases: &[&[&str]] = &[
        &["--noEmit", "false"],
        &["--NoEmit", "null"],
        &["-noemit", "false"],
        &["@outer.args"],
        &["--noEmit", "false", "--outDir"],
    ];
    for args in cases {
        let output = lpm(&project)
            .args(["check", "--"])
            .args(*args)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            !project.file_exists("unexpected.js"),
            "{args:?} enabled output"
        );
    }
}

#[cfg(unix)]
#[test]
fn check_rejects_writing_and_server_modes_before_starting_a_compiler() {
    let project = TempProject::empty(r#"{"name":"finite-check"}"#);
    project.write_file("tsconfig.json", "{}");
    seed_recording_tsc(&project);
    for args in [
        vec!["check", "--", "--init"],
        vec!["check", "--", "--build", "--clean"],
        vec!["check", "--engine", "tsgo", "--", "--api"],
        vec!["check", "--engine", "tsgo", "--", "--lsp"],
    ] {
        let output = lpm(&project).args(&args).output().unwrap();
        assert!(!output.status.success(), "{args:?} was allowed");
        assert!(
            !project.file_exists(".check-args.txt"),
            "{args:?} started the compiler"
        );
    }
}

#[cfg(unix)]
#[test]
fn check_json_watch_admission_respects_case_values_and_response_frames() {
    let project = TempProject::empty(r#"{"name":"watch-check"}"#);
    project.write_file("tsconfig.json", "{}");
    project.write_file("watch.args", "--WaTcH true\n");
    project.write_file("value.args", "--outDir\n");
    seed_recording_tsc(&project);
    let cases: &[(&[&str], bool)] = &[
        (&["--watch"], false),
        (&["-W"], false),
        (&["@watch.args"], false),
        (&["--watch", "false"], true),
        (&["--watch", "true", "--watch", "null"], true),
        (&["--outDir", "--watch"], true),
        (&["@value.args", "--watch"], false),
        (&["--watch", "--help"], true),
        (&["--watch", "--version"], true),
    ];
    for (args, allowed) in cases {
        let _ = std::fs::remove_file(project.path().join(".check-args.txt"));
        let output = lpm(&project)
            .args(["check", "--json", "--"])
            .args(*args)
            .output()
            .unwrap();
        assert_eq!(
            output.status.success(),
            *allowed,
            "{args:?}: {}",
            String::from_utf8_lossy(&output.stdout)
        );
        assert_eq!(project.file_exists(".check-args.txt"), *allowed, "{args:?}");
    }
}

#[cfg(unix)]
#[test]
fn check_does_not_execute_a_compiler_from_an_unrelated_ancestor() {
    let project = TempProject::empty(r#"{"name":"unrelated"}"#);
    seed_recording_tsc(&project);
    project.write_file("nested/package.json", r#"{"name":"actual-project"}"#);
    project.write_file("nested/tsconfig.json", "{}");
    let output = lpm(&project)
        .current_dir(project.path().join("nested"))
        .env("PATH", "")
        .arg("check")
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(!project.file_exists("nested/.check-args.txt"));
}

#[cfg(unix)]
#[test]
fn check_response_snapshots_do_not_strip_a_second_content_bom() {
    let project = TempProject::empty(r#"{"name":"response-bom"}"#);
    project.write_file("args.txt", "\u{feff}\u{feff}--watch\n");
    project.write_file("compiler.cjs", r#"
const fs=require('fs');const arg=process.argv.find(a=>a.startsWith('@'));const text=fs.readFileSync(arg.slice(1),'utf8').replace(/^\uFEFF/,'');if(text.replace(/^[\x00-\x20]*/, '').startsWith('--watch'))process.exit(9);
"#);
    make_local_tool(
        &project,
        "",
        "tsc",
        "#!/bin/sh\nexec node compiler.cjs \"$@\"\n",
    );
    let text = "\u{feff}--watch\n";
    let utf16_le = [
        vec![0xff, 0xfe],
        text.encode_utf16().flat_map(u16::to_le_bytes).collect(),
    ]
    .concat();
    let utf16_be = [
        vec![0xfe, 0xff],
        text.encode_utf16().flat_map(u16::to_be_bytes).collect(),
    ]
    .concat();
    for bytes in [
        "\u{feff}\u{feff}--watch\n".as_bytes().to_vec(),
        utf16_le,
        utf16_be,
    ] {
        std::fs::write(project.path().join("args.txt"), bytes).unwrap();
        let output = lpm(&project)
            .args(["check", "--json", "--", "@args.txt"])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "a content BOM must not become a watch flag: {}",
            String::from_utf8_lossy(&output.stdout)
        );
    }
}

#[cfg(unix)]
#[test]
fn check_snapshots_response_files_before_starting_the_compiler() {
    let project = TempProject::empty(r#"{"name":"response-capture"}"#);
    project.write_file("outer.args", "@nested.args");
    project.write_file("nested.args", "--watch false");
    project.write_file("compiler.cjs", r#"
const fs=require('fs');fs.writeFileSync('outer.args','--watch true');const seen=[];
function read(args) {for (const a of args) {if(!a.startsWith('@'))continue;const path=a.slice(1);const text=fs.readFileSync(path,'utf8');seen.push({path,text});read([...text.matchAll(/"([^"]*)"|([^\s]+)/g)].map(m=>m[1]??m[2]));}}
read(process.argv.slice(2));fs.writeFileSync('.response-seen.json',JSON.stringify(seen));
"#);
    make_local_tool(
        &project,
        "",
        "tsc",
        "#!/bin/sh\nexec node compiler.cjs \"$@\"\n",
    );
    let output = lpm(&project)
        .args(["check", "--json", "--", "@outer.args"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    let seen: serde_json::Value =
        serde_json::from_str(&project.read_file(".response-seen.json")).unwrap();
    let seen = seen.as_array().unwrap();
    assert_eq!(
        seen.len(),
        2,
        "the compiler must read the captured nested frame"
    );
    assert_eq!(seen[1]["text"].as_str().unwrap().trim(), "--watch false");
    for file in seen {
        assert!(
            !std::path::Path::new(file["path"].as_str().unwrap()).exists(),
            "temporary responses must be cleaned after execution"
        );
    }
}

#[cfg(unix)]
#[test]
fn check_rejects_recursive_and_oversized_responses_without_starting_the_compiler() {
    let project = TempProject::empty(r#"{"name":"response-limits"}"#);
    seed_recording_tsc(&project);
    project.write_file("cycle.args", "@cycle.args\n");
    project.write_file("large.args", &" ".repeat(4 * 1024 * 1024 + 1));
    for name in ["cycle.args", "large.args"] {
        let output = lpm(&project)
            .args(["check", "--json", "--", &format!("@{name}")])
            .output()
            .unwrap();
        assert!(!output.status.success(), "{name} was accepted");
        assert!(!project.file_exists(".check-args.txt"));
    }
}

#[cfg(unix)]
#[test]
fn doctor_does_not_mark_a_nonexecutable_local_compiler_healthy() {
    use std::os::unix::fs::PermissionsExt;
    let project = TempProject::empty(
        r#"{"name":"nonexecutable-compiler","devDependencies":{"typescript":"6"}}"#,
    );
    project.write_file("tsconfig.json", "{}");
    make_local_tsc(&project, "");
    std::fs::set_permissions(
        project.path().join("node_modules/.bin/tsc"),
        std::fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    let output = lpm_with_registry(&project, "http://127.0.0.1:1")
        .env("PATH", "")
        .args(["doctor", "--all", "--json"])
        .output()
        .unwrap();
    let value = parse_json_output(&output.stdout);
    assert!(
        find_check_by_code(&value, "typescript_unavailable").is_some(),
        "{value}"
    );
    assert!(find_check_by_code(&value, "typescript_healthy").is_none());
}

#[cfg(unix)]
#[test]
fn check_rejects_unrepresentable_nested_response_snapshot_paths() {
    #[cfg(target_os = "linux")]
    use std::os::unix::ffi::OsStringExt;
    let project = TempProject::empty(r#"{"name":"snapshot-paths"}"#);
    seed_recording_tsc(&project);
    project.write_file("outer.args", "@inner.args\n");
    project.write_file("inner.args", "--help\n");
    #[cfg(target_os = "linux")]
    let names = [
        std::ffi::OsString::from("quote\" and space"),
        std::ffi::OsString::from_vec(b"invalid-\xff".to_vec()),
    ];
    #[cfg(not(target_os = "linux"))]
    let names = [std::ffi::OsString::from("quote\" and space")];
    for name in names {
        let temp = project.path().join(name);
        std::fs::create_dir(&temp).unwrap();
        let _ = std::fs::remove_file(project.path().join(".check-args.txt"));
        let output = lpm(&project)
            .env("TMPDIR", &temp)
            .args(["check", "--json", "--", "@outer.args"])
            .output()
            .unwrap();
        assert!(
            !output.status.success(),
            "unrepresentable path was accepted: {}",
            temp.display()
        );
        assert!(!project.file_exists(".check-args.txt"));
    }
}

#[cfg(windows)]
#[test]
fn check_prefers_windows_cmd_shims_and_captures_their_exit_code() {
    let project = TempProject::empty(r#"{"name":"windows-check"}"#);
    project.write_file("tsconfig.json", "{}");
    project.write_file("node_modules/.bin/tsc", "#!/bin/sh\nexit 9\n");
    project.write_file(
        "node_modules/.bin/tsc.cmd",
        "@echo off\r\necho cmd-shim>cmd-shim.txt\r\nexit /b 7\r\n",
    );
    let output = lpm(&project).args(["check", "--json"]).output().unwrap();
    assert_eq!(output.status.code(), Some(7));
    let value = parse_json_output(&output.stdout);
    assert_eq!(value["members"][0]["exit_code"], 7);
    assert_eq!(project.read_file("cmd-shim.txt").trim(), "cmd-shim");
}

#[cfg(unix)]
#[test]
fn check_workspace_watch_requires_exactly_one_selected_member() {
    let project = TempProject::empty(r#"{"name":"root","workspaces":["packages/*"]}"#);
    project.write_file("packages/a/package.json", r#"{"name":"a"}"#);
    project.write_file("packages/b/package.json", r#"{"name":"b"}"#);
    seed_recording_tsc(&project);
    let cases: &[(&[&str], bool)] = &[
        (&["--all"], false),
        (&["--filter", "a"], true),
        (&["--filter", "missing"], false),
    ];
    for (selection, allowed) in cases {
        let output = lpm(&project)
            .arg("check")
            .args(*selection)
            .args(["--", "--watch"])
            .output()
            .unwrap();
        assert_eq!(
            output.status.success(),
            *allowed,
            "{selection:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    assert!(project.file_exists("packages/a/.check-args.txt"));
    assert!(!project.file_exists("packages/b/.check-args.txt"));
}

#[cfg(unix)]
#[test]
fn check_and_doctor_resolve_relative_path_from_each_workspace_member() {
    use std::os::unix::fs::PermissionsExt;
    let project = TempProject::empty(r#"{"name":"root","workspaces":["packages/*"]}"#);
    for name in ["a", "b"] {
        project.write_file(
            &format!("packages/{name}/package.json"),
            &format!(r#"{{"name":"{name}"}}"#),
        );
        project.write_file(&format!("packages/{name}/tsconfig.json"), "{}");
    }
    {
        let path = "packages/a/bin/tsc";
        project.write_file(
            path,
            "#!/bin/sh\nprintf 'member compiler' > compiler-seen.txt\nexit 0\n",
        );
        std::fs::set_permissions(
            project.path().join(path),
            std::fs::Permissions::from_mode(0o755),
        )
        .unwrap();
    }
    let output = lpm(&project)
        .env("PATH", "bin:/usr/bin:/bin")
        .args(["check", "--all", "--json"])
        .output()
        .unwrap();
    let value = parse_json_output(&output.stdout);
    let members = value["members"].as_array().unwrap();
    assert_eq!(
        members.iter().find(|m| m["name"] == "a").unwrap()["exit_code"],
        0,
        "{value}"
    );
    assert!(
        members.iter().find(|m| m["name"] == "b").unwrap()["exit_code"].is_null(),
        "{value}"
    );
    assert!(project.file_exists("packages/a/compiler-seen.txt"));
    assert!(!project.file_exists("packages/b/compiler-seen.txt"));
    project.write_file("bin/tsc", "#!/bin/sh\nexit 0\n");
    std::fs::set_permissions(
        project.path().join("bin/tsc"),
        std::fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    let output = lpm_with_registry(&project, "http://127.0.0.1:1")
        .env("PATH", "bin:/usr/bin:/bin")
        .args(["doctor", "--all", "--json"])
        .output()
        .unwrap();
    let value = parse_json_output(&output.stdout);
    assert!(
        find_check_by_code(&value, "typescript_unavailable").is_some(),
        "{value}"
    );
    assert!(
        find_check_by_code(&value, "typescript_missing_for_tsconfig").is_some(),
        "{value}"
    );
}

#[test]
fn check_does_not_prepare_tsgo_when_every_response_file_is_invalid() {
    let project = TempProject::empty(r#"{"name":"root","workspaces":["packages/*"]}"#);
    project.write_file("packages/a/package.json", r#"{"name":"a"}"#);
    let output = lpm(&project)
        .env("HTTPS_PROXY", "http://127.0.0.1:1")
        .env("ALL_PROXY", "http://127.0.0.1:1")
        .env("NO_PROXY", "")
        .args([
            "check",
            "--all",
            "--engine",
            "tsgo",
            "--json",
            "--",
            "@missing.args",
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let value = parse_json_output(&output.stdout);
    assert!(
        value["members"][0]["error"]
            .as_str()
            .unwrap()
            .contains("missing.args"),
        "{value}"
    );
    assert!(
        !project.home().join(".lpm/engines/tsgo").exists(),
        "invalid arguments must not prepare or download tsgo"
    );
}
