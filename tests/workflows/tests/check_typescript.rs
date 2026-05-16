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

fn make_local_tsc(project: &TempProject, rel_dir: &str) {
    // Create a fake tsc shim inside `<rel_dir>/node_modules/.bin/`.
    // We never spawn it — the predicate only checks file existence.
    let bin_rel = if rel_dir.is_empty() {
        "node_modules/.bin/tsc".to_string()
    } else {
        format!("{rel_dir}/node_modules/.bin/tsc")
    };
    project.write_file(&bin_rel, "#!/bin/sh\nexit 0\n");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let path = project.path().join(&bin_rel);
        let mut perms = std::fs::metadata(&path).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&path, perms).unwrap();
    }
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
