//! Workflow tests for `lpm lint` / `lpm fmt` / `lpm check` workspace mode.
//!
//! These tests primarily exercise the orchestrator's selection, JSON
//! envelope, and failure-mode contracts without requiring real tool
//! downloads. Happy-path coverage uses seeded local stand-ins: a cached
//! fake Biome binary for `fmt`, a fake root `tsc` for `check`, and one
//! optional real-network `lint` path gated behind `LPM_E2E_NETWORK=1`.

mod support;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use support::assertions::parse_json_output;
use support::{TempProject, lpm};

#[cfg(unix)]
const WORKSPACE_MEMBERS: [&str; 3] = ["packages/utils", "packages/core", "packages/app"];

#[cfg(unix)]
const TSGO_VERSION: &str = "7.0.0-dev.20260525.1";

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
    let script = format!("#!/bin/sh\n: > {marker_file}\n");

    write_unix_executable(&bin_path, &script);

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
            "https://registry.npmjs.org/@typescript/native-preview-darwin-arm64/-/native-preview-darwin-arm64-7.0.0-dev.20260525.1.tgz",
            "sha512-x0ClBYc6xQDLXvpRn/zg6SViX/r1F8LXHyfSHmKx4ieiaZiVvGsEww/qzdHind+Y62MIUN3e/XfDFrpRxWDv0g==",
        ),
        "darwin-x64" => (
            "https://registry.npmjs.org/@typescript/native-preview-darwin-x64/-/native-preview-darwin-x64-7.0.0-dev.20260525.1.tgz",
            "sha512-CSHbx6HfM+xXqceGFtG4kcqqoQ5xjT1BHO0bqLfLeQtKlMlze59dIV2DbOb5Aj6wm2ACTKU4K9aurJDdHARx1g==",
        ),
        "linux-x64" => (
            "https://registry.npmjs.org/@typescript/native-preview-linux-x64/-/native-preview-linux-x64-7.0.0-dev.20260525.1.tgz",
            "sha512-GhC0kXeYxn55Rk3klmWET/Y033AHeMzLBMO58yP7R8m5ZdGiBisejDZnvttzczYJtgT42LNOtVmbtsG/+R8XWw==",
        ),
        "linux-arm" => (
            "https://registry.npmjs.org/@typescript/native-preview-linux-arm/-/native-preview-linux-arm-7.0.0-dev.20260525.1.tgz",
            "sha512-hY2EVAaGc1bsaxthJiNUbzn6ESkMSLBiWRCNhQl8XdhDWew8KhKCjw4DHe0lAYSdxLJBe6fCPpcFjDnoSowBxA==",
        ),
        "linux-arm64" => (
            "https://registry.npmjs.org/@typescript/native-preview-linux-arm64/-/native-preview-linux-arm64-7.0.0-dev.20260525.1.tgz",
            "sha512-0DFKd3EuZ/Z0/mB114mATrlRxQUo7rcpXYgd5CJN7y1dbIgkavbjVamzzJKt3s42tkJGfdys83w6aIHDu6fykw==",
        ),
        "win-x64" => (
            "https://registry.npmjs.org/@typescript/native-preview-win32-x64/-/native-preview-win32-x64-7.0.0-dev.20260525.1.tgz",
            "sha512-xJCdFz9smVQVpXYW0vZZJsM0GIANPqSt8eMDRYfDY6M/BcXNXYOAt7tsxnSRyYWnFf9Ci7wKNRZaihZrDJ2m6A==",
        ),
        "win-arm64" => (
            "https://registry.npmjs.org/@typescript/native-preview-win32-arm64/-/native-preview-win32-arm64-7.0.0-dev.20260525.1.tgz",
            "sha512-L2+bsx73FyuEzLNgybtIxhnT9lYYAh9rTRFWZ4wZlJg44DGstjgz4FBKVHBO/cm3Hz7YNWeJESrB9ROUNbffPg==",
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

    // Reviewer add: prove all three members actually ran by asserting the
    // member array contains entries for each. The fixture is utils → core
    // → app; topology order is preserved by the orchestrator.
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
// The reviewer caught that the previous blanket reject contradicted the
// documented `lpm test --filter <name> --watch` workaround. The dispatcher
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
// The reviewer's load-bearing test: prove that `lpm test -- --all` still
// forwards `--all` to the underlying runner after it claims `--all`
// as an LPM workspace flag. We use a `scripts.test` fallback that simply
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
