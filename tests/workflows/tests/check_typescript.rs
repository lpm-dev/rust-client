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

const TSGO_VERSION: &str = "7.0.0-dev.20260626.1";

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
            "https://registry.npmjs.org/@typescript/native-preview-darwin-arm64/-/native-preview-darwin-arm64-7.0.0-dev.20260626.1.tgz",
            "sha512-VDPHf8RZRzsBH6cgArK1u9sH8MODMNkvkNczEt1EXpOLfZeplIhcpKld5Zc9Da8/S9YB4768rjfBkdFokxBu+Q==",
        ),
        "darwin-x64" => (
            "https://registry.npmjs.org/@typescript/native-preview-darwin-x64/-/native-preview-darwin-x64-7.0.0-dev.20260626.1.tgz",
            "sha512-bi7iQZe2A90cFJ3EQnigezEI7F0e5vX6E/QUGluQ1mKZmcbbQCdAwDMDQFV8Z6w3xNrk9AYyNQbvq0DtzJX46w==",
        ),
        "linux-x64" => (
            "https://registry.npmjs.org/@typescript/native-preview-linux-x64/-/native-preview-linux-x64-7.0.0-dev.20260626.1.tgz",
            "sha512-4o80l1+RoJLkR1G4KOZjTYN1yOAGbq0K2CAP0zF35MPnD8O559Tw8OMuYA+XPpEFE0fkb7mmcxL8J9cxM/kAbw==",
        ),
        "linux-arm" => (
            "https://registry.npmjs.org/@typescript/native-preview-linux-arm/-/native-preview-linux-arm-7.0.0-dev.20260626.1.tgz",
            "sha512-ilB0Ew5GWLrqMklNVrMdCEyNePypoEMnd4l5aUopnDRebgtXmtu0RE2GDl9LOTZ1BwlbXsuYAkEHt18Ta25hxg==",
        ),
        "linux-arm64" => (
            "https://registry.npmjs.org/@typescript/native-preview-linux-arm64/-/native-preview-linux-arm64-7.0.0-dev.20260626.1.tgz",
            "sha512-/iptuCYiucdY0HK0nE5ydRjIx0KOf3AY7fieRaQHA4X9/s4ey37rc/58aBX3dtx0x2EhlzpXT5f0ikYY65Zynw==",
        ),
        "win-x64" => (
            "https://registry.npmjs.org/@typescript/native-preview-win32-x64/-/native-preview-win32-x64-7.0.0-dev.20260626.1.tgz",
            "sha512-Iuf5nqTY4m5kxEvraDpieEf0XS6gDdjBBkw3g74pseznhpMeDFzgRvVCbSaf2pdjBNGugZbiBDVTEOclmD9cjA==",
        ),
        "win-arm64" => (
            "https://registry.npmjs.org/@typescript/native-preview-win32-arm64/-/native-preview-win32-arm64-7.0.0-dev.20260626.1.tgz",
            "sha512-xHxewRWY74zJnwt4bj+Kdf6Owfs6L0Fbggb37psSa6CvofqcvSI3AyuwiBNjC0T8Eb/d/BMMXttbPJ4XXqMpXQ==",
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
