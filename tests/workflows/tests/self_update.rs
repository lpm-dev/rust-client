//! Workflow tests for `lpm self-update`.
//!
//! The full happy path probes npm + GitHub Releases for the latest
//! version and then shells out to the installer, neither of which is
//! reproducible in CI. Workflow coverage focuses on the cache-driven
//! branches that don't require network: cache-hit "already on latest"
//! and the recent-failure backoff path.

mod support;

use std::time::{SystemTime, UNIX_EPOCH};
use support::{TempProject, lpm, lpm_from_path, lpm_spawnable_from_path};

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn cache_path(project: &TempProject) -> std::path::PathBuf {
    project.home().join(".lpm").join("update-check.json")
}

fn seed_available_update_notice(project: &TempProject) {
    std::fs::create_dir_all(cache_path(project).parent().unwrap()).expect("mkdir ~/.lpm");
    let payload = serde_json::json!({
        "latest": "99999.0.0",
        "lastCheck": now_secs(),
    });
    std::fs::write(cache_path(project), payload.to_string()).expect("seed update notice");
}

fn read_current_version(project: &TempProject) -> String {
    let output = lpm(project)
        .arg("--version")
        .output()
        .expect("failed to run lpm --version");
    let stdout = String::from_utf8_lossy(&output.stdout);
    // Format: `lpm-rs 0.40.0` (or similar)
    stdout
        .split_whitespace()
        .last()
        .unwrap_or("0.0.0")
        .trim()
        .to_string()
}

fn npm_managed_lpm_path(project: &TempProject) -> std::path::PathBuf {
    managed_lpm_path(
        project,
        std::path::Path::new("lib")
            .join("node_modules")
            .join("@lpm-registry")
            .join("cli"),
    )
}

fn managed_lpm_path(
    project: &TempProject,
    relative_parent: std::path::PathBuf,
) -> std::path::PathBuf {
    let source = assert_cmd::cargo::cargo_bin("lpm-rs");
    let file_name = if cfg!(windows) {
        "lpm-rs.exe"
    } else {
        "lpm-rs"
    };
    let destination = project.home().join(relative_parent).join(file_name);
    std::fs::create_dir_all(destination.parent().unwrap()).expect("create npm-shaped path");
    std::fs::copy(source, &destination).expect("copy lpm binary into npm-shaped path");
    destination
}

fn configure_plan_manager(
    project: &TempProject,
    binary: &std::path::Path,
    manager: &str,
) -> std::path::PathBuf {
    let bin = project.home().join("bin");
    std::fs::create_dir_all(&bin).expect("create manager plan bin");
    #[cfg(unix)]
    {
        use std::os::unix::fs::{PermissionsExt, symlink};

        symlink(binary, bin.join("lpm")).expect("link manager plan launcher");
        let query_result = match manager {
            "npm" => project.home().to_path_buf(),
            "pnpm" | "bun" | "yarn" => bin.clone(),
            "volta" => binary.to_path_buf(),
            _ => panic!("unsupported plan manager {manager}"),
        };
        let query = match manager {
            "npm" => "prefix --global",
            "pnpm" => "bin --global",
            "bun" => "pm bin --global",
            "yarn" => "global bin",
            "volta" => "which lpm",
            _ => unreachable!(),
        };
        let manager_path = bin.join(manager);
        std::fs::write(
            &manager_path,
            format!(
                "#!/bin/sh\nif [ \"$*\" = '{query}' ]; then printf '%s\\n' '{}'; exit 0; fi\nexit 9\n",
                query_result.display()
            ),
        )
        .expect("write plan manager");
        std::fs::set_permissions(&manager_path, std::fs::Permissions::from_mode(0o755))
            .expect("make plan manager executable");
    }
    #[cfg(windows)]
    {
        std::fs::write(
            bin.join("lpm.cmd"),
            format!("@echo off\r\n\"{}\" %*\r\n", binary.display()),
        )
        .expect("write manager plan launcher");
        let query_result = match manager {
            "npm" => project.home().to_path_buf(),
            "pnpm" | "bun" | "yarn" => bin.clone(),
            "volta" => binary.to_path_buf(),
            _ => panic!("unsupported plan manager {manager}"),
        };
        let query = match manager {
            "npm" => "prefix --global",
            "pnpm" => "bin --global",
            "bun" => "pm bin --global",
            "yarn" => "global bin",
            "volta" => "which lpm",
            _ => unreachable!(),
        };
        std::fs::write(
            bin.join(format!("{manager}.cmd")),
            format!(
                "@echo off\r\nif /I \"%*\"==\"{query}\" (echo {}& exit /b 0)\r\nexit /b 9\r\n",
                query_result.display()
            ),
        )
        .expect("write plan manager");
    }
    bin
}

fn platform_plan_command(posix: &str) -> String {
    if cfg!(windows) {
        let mut fields = posix.split_ascii_whitespace();
        let program = fields.next().expect("plan command program");
        let mut rendered = format!("& '{program}'");
        for field in fields {
            rendered.push_str(" '");
            rendered.push_str(field);
            rendered.push('\'');
        }
        rendered
    } else {
        posix.to_string()
    }
}

fn seed_newer_stable_release(project: &TempProject) {
    std::fs::create_dir_all(cache_path(project).parent().unwrap()).expect("mkdir ~/.lpm");
    let payload = serde_json::json!({
        "latest": "99999.0.0",
        "lastCheck": now_secs(),
    });
    std::fs::write(cache_path(project), payload.to_string()).expect("seed stable update cache");
}

// ─── cache-hit "already on latest" ───────────────────────────────────

#[test]
fn no_update_check_suppresses_cached_notice_on_version_fast_path() {
    let project = TempProject::empty(r#"{"name":"su","version":"1.0.0"}"#);
    seed_available_update_notice(&project);

    let output = lpm(&project)
        .arg("--version")
        .output()
        .expect("run lpm --version");

    assert!(output.status.success(), "--version must succeed");
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !combined.contains("Update available"),
        "LPM_NO_UPDATE_CHECK must suppress cached notices on --version, got:\n{combined}"
    );
}

#[test]
fn no_update_check_suppresses_cached_notice_after_regular_command() {
    let project = TempProject::empty(r#"{"name":"su","version":"1.0.0"}"#);
    seed_available_update_notice(&project);

    let output = lpm(&project)
        .args(["store", "path"])
        .output()
        .expect("run lpm store path");

    assert!(output.status.success(), "store path must succeed");
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !combined.contains("Update available"),
        "LPM_NO_UPDATE_CHECK must suppress cached notices after commands, got:\n{combined}"
    );
}

#[test]
fn self_update_cache_hit_with_matching_latest_reports_up_to_date() {
    let project = TempProject::empty(r#"{"name":"su","version":"1.0.0"}"#);
    let current = read_current_version(&project);

    // Seed the cache so the network probe is skipped entirely.
    std::fs::create_dir_all(cache_path(&project).parent().unwrap()).expect("mkdir ~/.lpm");
    let payload = serde_json::json!({
        "latest": current,
        "lastCheck": now_secs(),
    });
    std::fs::write(cache_path(&project), payload.to_string()).expect("seed cache");

    let output = lpm(&project)
        .args(["--json", "self-update"])
        .output()
        .expect("failed to run lpm self-update --json");

    assert!(
        output.status.success(),
        "cache-hit on matching latest must exit 0\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let envelope: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("self-update --json must be valid JSON: {e}\n---\n{stdout}"));

    assert_eq!(envelope["success"], serde_json::json!(true));
    assert_eq!(envelope["up_to_date"], serde_json::json!(true));
    assert_eq!(envelope["cache_hit"], serde_json::json!(true));
    assert_eq!(envelope["current"], serde_json::json!(current));
    assert_eq!(envelope["latest"], serde_json::json!(current));
    assert_eq!(envelope["channel"], serde_json::json!("stable"));
    assert_eq!(envelope["target_channel"], serde_json::json!("stable"));
    assert_eq!(envelope["channel_changed"], serde_json::json!(false));
    assert!(envelope["duration_ms"].is_u64());
    assert!(output.stderr.is_empty(), "JSON mode must keep stderr empty");

    let mut snapshot = envelope;
    snapshot["current"] = serde_json::json!("<current-version>");
    snapshot["latest"] = serde_json::json!("<current-version>");
    snapshot["duration_ms"] = serde_json::json!("<duration-ms>");
    insta::assert_json_snapshot!(snapshot, @r#"
    {
      "success": true,
      "current": "<current-version>",
      "latest": "<current-version>",
      "up_to_date": true,
      "cache_hit": true,
      "channel": "stable",
      "target_channel": "stable",
      "channel_changed": false,
      "duration_ms": "<duration-ms>"
    }
    "#);
}

#[test]
fn self_update_explicit_nightly_switch_returns_exact_npm_install_plan() {
    let project = TempProject::empty(r#"{"name":"su","version":"1.0.0"}"#);
    let nightly = "999.0.0-nightly.20260728.42.d82ceea";

    std::fs::create_dir_all(cache_path(&project).parent().unwrap()).expect("mkdir ~/.lpm");
    let payload = serde_json::json!({
        "nightly": {
            "latest": nightly,
            "lastCheck": now_secs(),
        }
    });
    std::fs::write(cache_path(&project), payload.to_string()).expect("seed nightly cache");

    let binary = npm_managed_lpm_path(&project);
    let bin = configure_plan_manager(&project, &binary, "npm");
    let mut command = lpm_from_path(&project, &binary);
    command.env("PATH", &bin).env("PATHEXT", ".EXE;.CMD").args([
        "--json",
        "self-update",
        "--channel",
        "nightly",
    ]);
    let output = command.output().expect("run npm-managed lpm self-update");

    assert!(
        output.status.success(),
        "stable to nightly plan must succeed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let envelope: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|error| panic!("self-update JSON must parse: {error}\n{stdout}"));
    assert_eq!(envelope["channel"], "stable");
    assert_eq!(envelope["target_channel"], "nightly");
    assert_eq!(envelope["channel_changed"], true);
    assert_eq!(envelope["latest"], nightly);
    assert_eq!(envelope["install_method"], "npm");
    assert_eq!(envelope["applied"], false);
    assert_eq!(envelope["launcher_verified"], true);
    assert_eq!(envelope["manager_target_verified"], true);
    assert!(envelope["duration_ms"].is_u64());
    assert!(output.stderr.is_empty(), "JSON mode must keep stderr empty");
    assert_eq!(envelope.get("verified"), None);
    let manager_program =
        std::fs::canonicalize(bin.join(if cfg!(windows) { "npm.cmd" } else { "npm" }))
            .expect("canonicalize verified npm manager");
    assert_eq!(
        envelope["update_program"],
        manager_program.to_string_lossy().as_ref()
    );
    assert_eq!(
        envelope["update_args"],
        serde_json::json!(["install", "-g", format!("@lpm-registry/cli@{nightly}")])
    );
    assert_eq!(
        envelope["update_command"],
        platform_plan_command(&format!(
            "{} install -g @lpm-registry/cli@{nightly}",
            manager_program.display()
        ))
    );
    assert_eq!(
        envelope["update_shell"],
        if cfg!(windows) { "powershell" } else { "posix" }
    );

    let mut snapshot = envelope;
    snapshot["current"] = serde_json::json!("<current-version>");
    snapshot["update_command"] = serde_json::json!("<platform-update-command>");
    snapshot["update_program"] = serde_json::json!("<verified-manager>");
    snapshot["update_shell"] = serde_json::json!("<platform-shell>");
    snapshot["duration_ms"] = serde_json::json!("<duration-ms>");
    insta::assert_json_snapshot!(snapshot, @r#"
    {
      "success": true,
      "current": "<current-version>",
      "latest": "999.0.0-nightly.20260728.42.d82ceea",
      "up_to_date": false,
      "install_method": "npm",
      "update_command": "<platform-update-command>",
      "update_shell": "<platform-shell>",
      "update_program": "<verified-manager>",
      "update_args": [
        "install",
        "-g",
        "@lpm-registry/cli@999.0.0-nightly.20260728.42.d82ceea"
      ],
      "applied": false,
      "launcher_verified": true,
      "manager_target_verified": true,
      "cache_hit": true,
      "channel": "stable",
      "target_channel": "nightly",
      "channel_changed": true,
      "duration_ms": "<duration-ms>"
    }
    "#);
}

#[test]
fn self_update_json_plan_refuses_an_unverified_manager_target() {
    let project = TempProject::empty(r#"{"name":"su","version":"1.0.0"}"#);
    let nightly = "999.0.0-nightly.20260728.42.d82ceea";
    std::fs::create_dir_all(cache_path(&project).parent().unwrap()).expect("mkdir ~/.lpm");
    std::fs::write(
        cache_path(&project),
        serde_json::json!({
            "nightly": { "latest": nightly, "lastCheck": now_secs() }
        })
        .to_string(),
    )
    .expect("seed nightly cache");
    let binary = npm_managed_lpm_path(&project);
    let bin = configure_plan_manager(&project, &binary, "npm");
    let unrelated = tempfile::tempdir().expect("create unrelated manager target");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let manager = bin.join("npm");
        std::fs::write(
            &manager,
            format!(
                "#!/bin/sh\nif [ \"$*\" = 'prefix --global' ]; then printf '%s\\n' '{}'; exit 0; fi\nexit 9\n",
                unrelated.path().display()
            ),
        )
        .expect("write unrelated npm target");
        std::fs::set_permissions(&manager, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    #[cfg(windows)]
    std::fs::write(
        bin.join("npm.cmd"),
        format!(
            "@echo off\r\nif /I \"%*\"==\"prefix --global\" (echo {}& exit /b 0)\r\nexit /b 9\r\n",
            unrelated.path().display()
        ),
    )
    .expect("write unrelated npm target");
    let mut command = lpm_from_path(&project, &binary);
    command.env("PATH", &bin).env("PATHEXT", ".EXE;.CMD").args([
        "--json",
        "self-update",
        "--channel",
        "nightly",
    ]);

    let output = command.output().expect("run unverified manager plan");

    assert!(!output.status.success());
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(combined.contains("does not own the active LPM launcher"));
}

#[test]
fn self_update_rejects_a_manager_from_an_unrecognized_working_directory() {
    let project = TempProject::empty(r#"{"name":"su","version":"1.0.0"}"#);
    let nightly = "999.0.0-nightly.20260728.42.d82ceea";
    std::fs::create_dir_all(cache_path(&project).parent().unwrap()).expect("mkdir ~/.lpm");
    std::fs::write(
        cache_path(&project),
        serde_json::json!({
            "nightly": { "latest": nightly, "lastCheck": now_secs() }
        })
        .to_string(),
    )
    .expect("seed nightly cache");

    let binary = npm_managed_lpm_path(&project);
    let working_dir = project.home().join("unrecognized-checkout");
    let local_bin = working_dir.join("bin");
    std::fs::create_dir_all(&local_bin).expect("create unrecognized local bin");
    #[cfg(unix)]
    {
        use std::os::unix::fs::{PermissionsExt, symlink};

        symlink(&binary, local_bin.join("lpm")).expect("link local launcher");
        let manager = local_bin.join("npm");
        std::fs::write(
            &manager,
            format!(
                "#!/bin/sh\nif [ \"$*\" = 'prefix --global' ]; then printf '%s\\n' '{}'; exit 0; fi\nexit 9\n",
                project.home().display()
            ),
        )
        .expect("write local npm manager");
        std::fs::set_permissions(&manager, std::fs::Permissions::from_mode(0o755))
            .expect("make local npm manager executable");
    }
    #[cfg(windows)]
    {
        std::fs::write(
            local_bin.join("lpm.cmd"),
            format!("@echo off\r\n\"{}\" %*\r\n", binary.display()),
        )
        .expect("write local launcher");
        std::fs::write(
            local_bin.join("npm.cmd"),
            format!(
                "@echo off\r\nif /I \"%*\"==\"prefix --global\" (echo {}& exit /b 0)\r\nexit /b 9\r\n",
                project.home().display()
            ),
        )
        .expect("write local npm manager");
    }

    let mut command = lpm_from_path(&project, &binary);
    command
        .current_dir(&working_dir)
        .env("PATH", &local_bin)
        .env("PATHEXT", ".EXE;.CMD")
        .args(["--json", "self-update", "--channel", "nightly"]);
    let output = command
        .output()
        .expect("run self-update from unrecognized checkout");
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    assert!(
        !output.status.success(),
        "self-update must not trust a manager from the working directory\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("`npm` does not resolve to an absolute non-project executable on PATH"),
        "self-update failed for an unrelated reason: {combined}"
    );
}

fn assert_manager_plan(relative_parent: std::path::PathBuf, manager: &str, command: &str) {
    let project = TempProject::empty(r#"{"name":"su","version":"1.0.0"}"#);
    let nightly = "999.0.0-nightly.20260728.42.d82ceea";

    std::fs::create_dir_all(cache_path(&project).parent().unwrap()).expect("mkdir ~/.lpm");
    let payload = serde_json::json!({
        "nightly": {
            "latest": nightly,
            "lastCheck": now_secs(),
        }
    });
    std::fs::write(cache_path(&project), payload.to_string()).expect("seed nightly cache");

    let binary = managed_lpm_path(&project, relative_parent);
    let bin = configure_plan_manager(&project, &binary, manager);
    let mut invocation = lpm_from_path(&project, &binary);
    invocation
        .env("PATH", &bin)
        .env("PATHEXT", ".EXE;.CMD")
        .args(["--json", "self-update", "--channel", "nightly"]);
    let output = invocation
        .output()
        .expect("run package-manager-owned lpm self-update");

    assert!(
        output.status.success(),
        "{manager} self-update plan must succeed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let envelope: serde_json::Value = serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|error| panic!("self-update JSON must parse: {error}"));
    let manager_program = std::fs::canonicalize(bin.join(if cfg!(windows) {
        format!("{manager}.cmd")
    } else {
        manager.to_string()
    }))
    .expect("canonicalize verified package manager");
    let (_, args) = command
        .split_once(' ')
        .expect("manager plan contains arguments");
    assert_eq!(envelope["install_method"], manager);
    assert_eq!(
        envelope["update_program"],
        manager_program.to_string_lossy().as_ref()
    );
    assert_eq!(
        envelope["update_command"],
        platform_plan_command(&format!("{} {args}", manager_program.display()))
    );
    assert_eq!(envelope["applied"], false);
    assert_eq!(envelope["launcher_verified"], true);
    assert_eq!(envelope["manager_target_verified"], true);
    assert_eq!(envelope.get("verified"), None);
}

#[test]
fn self_update_pnpm_install_plan_uses_pnpm_global_owner() {
    assert_manager_plan(
        std::path::Path::new(".local")
            .join("share")
            .join("pnpm")
            .join("global")
            .join("5")
            .join(".pnpm")
            .join("@lpm-registry+cli@1.0.0")
            .join("node_modules")
            .join("@lpm-registry")
            .join("cli"),
        "pnpm",
        "pnpm add --global @lpm-registry/cli@999.0.0-nightly.20260728.42.d82ceea",
    );
}

#[test]
fn self_update_bun_install_plan_uses_bun_global_owner() {
    assert_manager_plan(
        std::path::Path::new(".bun")
            .join("install")
            .join("global")
            .join("node_modules")
            .join("@lpm-registry")
            .join("cli"),
        "bun",
        "bun add --global @lpm-registry/cli@999.0.0-nightly.20260728.42.d82ceea",
    );
}

#[test]
fn self_update_yarn_install_plan_uses_yarn_global_owner() {
    assert_manager_plan(
        std::path::Path::new(".config")
            .join("yarn")
            .join("global")
            .join("node_modules")
            .join("@lpm-registry")
            .join("cli"),
        "yarn",
        "yarn global add @lpm-registry/cli@999.0.0-nightly.20260728.42.d82ceea",
    );
}

#[test]
fn self_update_volta_install_plan_uses_volta_owner() {
    assert_manager_plan(
        std::path::Path::new(".volta")
            .join("tools")
            .join("image")
            .join("packages")
            .join("@lpm-registry")
            .join("cli")
            .join("bin"),
        "volta",
        "volta install @lpm-registry/cli@999.0.0-nightly.20260728.42.d82ceea",
    );
}

#[cfg(unix)]
fn assert_manager_execution(
    relative_install: std::path::PathBuf,
    relative_bin: std::path::PathBuf,
    manager: &str,
    query_condition: &str,
    query_target_is_executable: bool,
    expected_install_args: &str,
) {
    use std::os::unix::fs::{PermissionsExt, symlink};

    let project = TempProject::empty(r#"{"name":"su","version":"1.0.0"}"#);
    seed_newer_stable_release(&project);
    let installation = managed_lpm_path(&project, relative_install);
    let bin = project.home().join(relative_bin);
    std::fs::create_dir_all(&bin).expect("create manager bin");
    symlink(&installation, bin.join("lpm")).expect("link manager-owned public launcher");
    let invocation = bin.join("manager-invocation");
    let query_target = if query_target_is_executable {
        installation.as_path()
    } else {
        bin.as_path()
    };
    let manager_path = bin.join(manager);
    std::fs::write(
        &manager_path,
        format!(
            "#!/bin/sh\nif [ \"$*\" = '{}' ]; then printf '%s\\n' '{}'; exit 0; fi\nprintf '%s' \"$*\" > '{}'\n",
            query_condition,
            query_target.display(),
            invocation.display()
        ),
    )
    .expect("write fake manager");
    std::fs::set_permissions(&manager_path, std::fs::Permissions::from_mode(0o755))
        .expect("make fake manager executable");

    let output = lpm_from_path(&project, &installation)
        .arg("self-update")
        .env("PATH", &bin)
        .output()
        .expect("run manager-owned self-update");

    assert!(
        !output.status.success(),
        "unchanged fake launcher must fail post-update verification"
    );
    let invocation = std::fs::read_to_string(&invocation).unwrap_or_else(|error| {
        panic!(
            "manager install command must run: {error}\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        )
    });
    assert_eq!(invocation, expected_install_args);
}

#[cfg(unix)]
#[test]
fn self_update_pnpm_execution_uses_the_verified_global_owner() {
    assert_manager_execution(
        std::path::Path::new(".local")
            .join("share")
            .join("pnpm")
            .join("global")
            .join("5")
            .join(".pnpm")
            .join("@lpm-registry+cli@1.0.0")
            .join("node_modules")
            .join("@lpm-registry")
            .join("cli"),
        std::path::Path::new(".local").join("share").join("pnpm"),
        "pnpm",
        "bin --global",
        false,
        "add --global @lpm-registry/cli@99999.0.0",
    );
}

#[cfg(unix)]
#[test]
fn self_update_bun_execution_uses_the_verified_global_owner() {
    assert_manager_execution(
        std::path::Path::new(".bun")
            .join("install")
            .join("global")
            .join("node_modules")
            .join("@lpm-registry")
            .join("cli"),
        std::path::Path::new(".bun").join("bin"),
        "bun",
        "pm bin --global",
        false,
        "add --global @lpm-registry/cli@99999.0.0",
    );
}

#[cfg(unix)]
#[test]
fn self_update_yarn_execution_uses_the_verified_global_owner() {
    assert_manager_execution(
        std::path::Path::new(".config")
            .join("yarn")
            .join("global")
            .join("node_modules")
            .join("@lpm-registry")
            .join("cli"),
        std::path::Path::new(".yarn").join("bin"),
        "yarn",
        "global bin",
        false,
        "global add @lpm-registry/cli@99999.0.0",
    );
}

#[cfg(unix)]
#[test]
fn self_update_volta_execution_uses_the_verified_global_owner() {
    assert_manager_execution(
        std::path::Path::new(".volta")
            .join("tools")
            .join("image")
            .join("packages")
            .join("@lpm-registry")
            .join("cli")
            .join("bin"),
        std::path::Path::new(".volta").join("bin"),
        "volta",
        "which lpm",
        true,
        "install @lpm-registry/cli@99999.0.0",
    );
}

#[cfg(unix)]
fn write_successful_fake_installer(
    bin_dir: &std::path::Path,
    name: &str,
    launcher_target: &std::path::Path,
    ownership_path: &std::path::Path,
) -> std::path::PathBuf {
    use std::os::unix::fs::{PermissionsExt, symlink};

    std::fs::create_dir_all(bin_dir).expect("create fake manager bin");
    let installer = bin_dir.join(name);
    std::fs::write(
        &installer,
        format!(
            "#!/bin/sh\ncase \"$1 $2\" in\n  'prefix --global'|'--prefix lpm') printf '%s\\n' '{}' ; exit 0 ;;\nesac\nexit 0\n",
            ownership_path.display()
        ),
    )
    .expect("write fake installer");
    std::fs::set_permissions(&installer, std::fs::Permissions::from_mode(0o755))
        .expect("make fake installer executable");
    let launcher = bin_dir.join("lpm");
    symlink(launcher_target, &launcher).expect("link public launcher to current installation");
    bin_dir.to_path_buf()
}

#[cfg(unix)]
#[test]
fn self_update_refuses_success_when_installer_does_not_change_active_version() {
    let project = TempProject::empty(r#"{"name":"su","version":"1.0.0"}"#);
    seed_newer_stable_release(&project);
    let binary = npm_managed_lpm_path(&project);
    let fake_bin = write_successful_fake_installer(
        &project.home().join("bin"),
        "npm",
        &binary,
        project.home(),
    );

    let output = lpm_from_path(&project, &binary)
        .arg("self-update")
        .env("PATH", fake_bin)
        .output()
        .expect("run npm-owned lpm self-update");

    assert!(
        !output.status.success(),
        "zero installer exit with a stale binary must not report success\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    assert!(
        !String::from_utf8_lossy(&output.stderr).contains("Done · LPM updated to"),
        "stale executable must not print a success line"
    );
}

#[cfg(unix)]
#[test]
fn self_update_stamps_success_only_after_the_bound_launcher_reports_the_target() {
    use std::os::unix::fs::{PermissionsExt, symlink};

    let project = TempProject::empty(r#"{"name":"su","version":"1.0.0"}"#);
    seed_newer_stable_release(&project);
    let installation = npm_managed_lpm_path(&project);
    let bin_dir = project.home().join("bin");
    std::fs::create_dir_all(&bin_dir).expect("create global bin");
    let launcher = bin_dir.join("lpm");
    symlink(&installation, &launcher).expect("link public launcher to current installation");
    let installer = bin_dir.join("npm");
    std::fs::write(
        &installer,
        format!(
            r#"#!/bin/sh
if [ "$1" = prefix ]; then printf '%s\n' '{}'; exit 0; fi
/bin/rm -f '{}'
printf '%s\n' '#!/bin/sh' 'printf "lpm 99999.0.0\n"' > '{}'
/bin/chmod 755 '{}'
"#,
            project.home().display(),
            launcher.display(),
            launcher.display(),
            launcher.display()
        ),
    )
    .expect("write launcher-updating manager");
    std::fs::set_permissions(&installer, std::fs::Permissions::from_mode(0o755))
        .expect("make launcher-updating manager executable");

    let output = lpm_from_path(&project, &installation)
        .arg("self-update")
        .env("PATH", &bin_dir)
        .output()
        .expect("run exact-version self-update");

    assert!(
        output.status.success(),
        "exact post-update launcher version must succeed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let cache: serde_json::Value = serde_json::from_slice(
        &std::fs::read(cache_path(&project)).expect("read stamped update cache"),
    )
    .expect("parse stamped update cache");
    assert_eq!(cache["latest"], "99999.0.0");
}

#[cfg(unix)]
#[test]
fn concurrent_self_updates_serialize_the_manager_mutation_window() {
    use std::os::unix::fs::{PermissionsExt, symlink};

    let project = TempProject::empty(r#"{"name":"su","version":"1.0.0"}"#);
    seed_newer_stable_release(&project);
    let installation = npm_managed_lpm_path(&project);
    let bin = project.home().join("bin");
    std::fs::create_dir_all(&bin).expect("create manager bin");
    symlink(&installation, bin.join("lpm")).expect("link manager-owned launcher");
    let critical = project.home().join("manager-critical");
    let overlap = project.home().join("manager-overlap");
    let manager = bin.join("npm");
    std::fs::write(
        &manager,
        format!(
            "#!/bin/sh\nif [ \"$*\" = 'prefix --global' ]; then printf '%s\\n' '{}'; exit 0; fi\nif ! /bin/mkdir '{}'; then : > '{}'; exit 0; fi\n/bin/sleep 2\n/bin/rmdir '{}'\n",
            project.home().display(),
            critical.display(),
            overlap.display(),
            critical.display(),
        ),
    )
    .expect("write contended manager");
    std::fs::set_permissions(&manager, std::fs::Permissions::from_mode(0o755))
        .expect("make contended manager executable");

    let mut first = lpm_spawnable_from_path(&project, &installation);
    first.arg("self-update").env("PATH", &bin);
    let mut second = lpm_spawnable_from_path(&project, &installation);
    second.arg("self-update").env("PATH", &bin);

    let first = first.spawn().expect("start first self-update");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    while !critical.exists() {
        assert!(
            std::time::Instant::now() < deadline,
            "first self-update did not enter the manager mutation window"
        );
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    let second_started = std::time::Instant::now();
    let second = second
        .spawn()
        .expect("start second self-update")
        .wait_with_output()
        .expect("wait for second self-update");
    let second_elapsed = second_started.elapsed();
    let first = first
        .wait_with_output()
        .expect("wait for first self-update");

    assert!(!first.status.success());
    assert!(!second.status.success());
    assert!(
        second_elapsed < std::time::Duration::from_secs(1),
        "a contending self-update must refuse promptly instead of waiting for the full manager operation; elapsed {second_elapsed:?}\nsecond stderr: {}",
        String::from_utf8_lossy(&second.stderr),
    );
    assert!(
        String::from_utf8_lossy(&second.stderr).contains("another self-update operation"),
        "contending self-update must explain why it refused\nsecond stderr: {}",
        String::from_utf8_lossy(&second.stderr),
    );
    assert!(
        !overlap.exists(),
        "two package-manager mutations overlapped despite the self-update lock\nfirst stdout: {}\nfirst stderr: {}\nsecond stdout: {}\nsecond stderr: {}",
        String::from_utf8_lossy(&first.stdout),
        String::from_utf8_lossy(&first.stderr),
        String::from_utf8_lossy(&second.stdout),
        String::from_utf8_lossy(&second.stderr),
    );
}

#[cfg(windows)]
#[test]
fn windows_cmd_manager_update_binds_ownership_arguments_and_replacement_launcher() {
    let project = TempProject::empty(r#"{"name":"su","version":"1.0.0"}"#);
    seed_newer_stable_release(&project);
    let installation = npm_managed_lpm_path(&project);
    let bin = project.home().join("bin");
    std::fs::create_dir_all(&bin).expect("create Windows manager bin");
    let launcher = bin.join("lpm.cmd");
    std::fs::write(
        &launcher,
        format!("@echo off\r\n\"{}\" %*\r\n", installation.display()),
    )
    .expect("write Windows public launcher");
    let replacement = bin.join("replacement-lpm.cmd");
    std::fs::write(
        &replacement,
        "@echo off\r\nif /I \"%1\"==\"-V\" (echo lpm 99999.0.0& exit /b 0)\r\nexit /b 9\r\n",
    )
    .expect("write replacement Windows launcher");
    let invocation = bin.join("manager-invocation.txt");
    std::fs::write(
        bin.join("npm.cmd"),
        format!(
            "@echo off\r\nif /I \"%*\"==\"prefix --global\" (echo {}& exit /b 0)\r\nif /I not \"%*\"==\"install -g @lpm-registry/cli@99999.0.0\" exit /b 17\r\n>\"{}\" echo %*\r\ncopy /Y \"{}\" \"{}\" >NUL\r\n",
            project.home().display(),
            invocation.display(),
            replacement.display(),
            launcher.display()
        ),
    )
    .expect("write Windows npm manager");
    let mut command = lpm_from_path(&project, &installation);
    command
        .env("PATH", &bin)
        .env("PATHEXT", ".EXE;.CMD")
        .arg("self-update");

    let output = command.output().expect("run Windows cmd manager update");

    assert!(
        output.status.success(),
        "Windows manager update must succeed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        std::fs::read_to_string(invocation).unwrap().trim(),
        "install -g @lpm-registry/cli@99999.0.0"
    );
}

#[cfg(unix)]
#[test]
fn self_update_homebrew_refuses_success_when_formula_lags_requested_version() {
    let project = TempProject::empty(r#"{"name":"su","version":"1.0.0"}"#);
    seed_newer_stable_release(&project);
    let binary = managed_lpm_path(
        &project,
        std::path::Path::new("homebrew")
            .join("Cellar")
            .join("lpm")
            .join("0.1.0")
            .join("bin"),
    );
    let fake_bin = write_successful_fake_installer(
        &project.home().join("homebrew").join("bin"),
        "brew",
        &binary,
        binary.parent().and_then(std::path::Path::parent).unwrap(),
    );

    let output = lpm_from_path(&project, &binary)
        .arg("self-update")
        .env("PATH", fake_bin)
        .output()
        .expect("run Homebrew-owned lpm self-update");

    assert!(
        !output.status.success(),
        "Homebrew must not claim a requested version that the active executable does not report\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    assert!(
        !String::from_utf8_lossy(&output.stderr).contains("Done · LPM updated to 99999.0.0"),
        "lagging formula must not print an exact-version success line"
    );
}

#[cfg(unix)]
#[test]
fn self_update_rejects_the_wrong_public_launcher_before_running_the_installer() {
    use std::os::unix::fs::PermissionsExt;

    let project = TempProject::empty(r#"{"name":"su","version":"1.0.0"}"#);
    seed_newer_stable_release(&project);
    let binary = npm_managed_lpm_path(&project);
    let tools = tempfile::tempdir().expect("create external fake tools");
    let installer = tools.path().join("npm");
    std::fs::write(&installer, "#!/bin/sh\n: > \"$LPM_TEST_INSTALL_MARKER\"\n")
        .expect("write observable fake installer");
    std::fs::set_permissions(&installer, std::fs::Permissions::from_mode(0o755))
        .expect("make fake installer executable");
    let launcher = tools.path().join("lpm");
    std::fs::write(&launcher, "#!/bin/sh\nprintf 'lpm 0.0.0\\n'\n")
        .expect("write wrong public launcher");
    std::fs::set_permissions(&launcher, std::fs::Permissions::from_mode(0o755))
        .expect("make wrong public launcher executable");
    let marker = tools.path().join("installer-ran");

    let output = lpm_from_path(&project, &binary)
        .arg("self-update")
        .env("PATH", tools.path())
        .env("LPM_TEST_INSTALL_MARKER", &marker)
        .output()
        .expect("run npm-owned lpm self-update");

    assert!(
        !output.status.success(),
        "a launcher that does not match the running version must fail preflight\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    assert!(
        !marker.exists(),
        "the installer must not run before launcher preflight succeeds"
    );
}

#[cfg(unix)]
#[test]
fn self_update_rejects_a_same_version_launcher_from_another_installation() {
    use std::os::unix::fs::PermissionsExt;

    let project = TempProject::empty(r#"{"name":"su","version":"1.0.0"}"#);
    seed_newer_stable_release(&project);
    let current = read_current_version(&project);
    let installation_a = npm_managed_lpm_path(&project);
    let installation_b = tempfile::tempdir().expect("create second global installation");
    let updated = installation_b.path().join("updated");
    let installer = installation_b.path().join("npm");
    std::fs::write(&installer, "#!/bin/sh\n: > \"$LPM_TEST_UPDATED\"\n")
        .expect("write second-installation updater");
    std::fs::set_permissions(&installer, std::fs::Permissions::from_mode(0o755))
        .expect("make second-installation updater executable");
    let launcher = installation_b.path().join("lpm");
    std::fs::write(
        &launcher,
        format!(
            "#!/bin/sh\nif [ -e \"$LPM_TEST_UPDATED\" ]; then printf 'lpm 99999.0.0\\n'; else printf 'lpm {current}\\n'; fi\n"
        ),
    )
    .expect("write second-installation launcher");
    std::fs::set_permissions(&launcher, std::fs::Permissions::from_mode(0o755))
        .expect("make second-installation launcher executable");

    let output = lpm_from_path(&project, &installation_a)
        .arg("self-update")
        .env("PATH", installation_b.path())
        .env("LPM_TEST_UPDATED", &updated)
        .output()
        .expect("run first installation against second installation PATH");

    assert!(
        !output.status.success(),
        "self-update must not report that installation A changed after updating only installation B\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    assert!(
        !updated.exists(),
        "ownership preflight must refuse before mutating installation B"
    );
}

#[cfg(unix)]
#[test]
fn self_update_rejects_a_project_local_executable_before_manager_mutation() {
    use std::os::unix::fs::PermissionsExt;

    let project = TempProject::empty(r#"{"name":"su","version":"1.0.0"}"#);
    seed_newer_stable_release(&project);
    let local = project
        .path()
        .join("node_modules")
        .join("@lpm-registry")
        .join("cli")
        .join("lpm-rs");
    std::fs::create_dir_all(local.parent().unwrap()).expect("create local package path");
    std::fs::copy(assert_cmd::cargo::cargo_bin("lpm-rs"), &local).expect("copy project-local LPM");
    let tools = tempfile::tempdir().expect("create external manager tools");
    let marker = tools.path().join("installer-ran");
    let installer = tools.path().join("npm");
    std::fs::write(&installer, "#!/bin/sh\n: > \"$LPM_TEST_INSTALL_MARKER\"\n")
        .expect("write observable installer");
    std::fs::set_permissions(&installer, std::fs::Permissions::from_mode(0o755))
        .expect("make observable installer executable");
    let launcher = tools.path().join("lpm");
    std::os::unix::fs::symlink(&local, launcher).expect("link global-looking launcher");

    let output = lpm_from_path(&project, &local)
        .arg("self-update")
        .env("PATH", tools.path())
        .env("LPM_TEST_INSTALL_MARKER", &marker)
        .output()
        .expect("run project-local self-update");

    assert!(!output.status.success());
    assert!(!marker.exists());
}

#[cfg(unix)]
#[test]
fn self_update_manager_does_not_inherit_code_injection_environment() {
    use std::os::unix::fs::{PermissionsExt, symlink};

    let project = TempProject::empty(r#"{"name":"su","version":"1.0.0"}"#);
    seed_newer_stable_release(&project);
    let installation = npm_managed_lpm_path(&project);
    let tools = project.home().join("bin");
    std::fs::create_dir_all(&tools).expect("create global manager tools");
    symlink(&installation, tools.join("lpm")).expect("link public launcher to installation");
    let environment_record = tools.join("manager-environment");
    let bash_env = tools.join("bash-env");
    std::fs::write(&bash_env, "").expect("write inert BASH_ENV fixture");
    let installer = tools.join("npm");
    std::fs::write(
        &installer,
        format!(
            "#!/bin/sh\nif [ \"$1\" = prefix ]; then printf '%s\\n' '{}'; exit 0; fi\nprintf '%s|%s|%s' \"${{NODE_OPTIONS-unset}}\" \"${{BASH_ENV-unset}}\" \"${{RUBYOPT-unset}}\" > '{}'\n",
            project.home().display(),
            environment_record.display()
        ),
    )
    .expect("write environment-recording manager");
    std::fs::set_permissions(&installer, std::fs::Permissions::from_mode(0o755))
        .expect("make environment-recording manager executable");

    let output = lpm_from_path(&project, &installation)
        .arg("self-update")
        .env("PATH", &tools)
        .env("NODE_OPTIONS", "--require=/project/owned.js")
        .env("BASH_ENV", &bash_env)
        .env("RUBYOPT", "-r/project/owned.rb")
        .output()
        .expect("run self-update with hostile inherited environment");

    let environment = std::fs::read_to_string(&environment_record).unwrap_or_else(|error| {
        panic!(
            "manager must record its environment: {error}\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        )
    });
    assert_eq!(environment, "unset|unset|unset");
}

#[test]
fn self_update_human_cache_hit_uses_slim_status() {
    let project = TempProject::empty(r#"{"name":"su","version":"1.0.0"}"#);
    let current = read_current_version(&project);

    std::fs::create_dir_all(cache_path(&project).parent().unwrap()).expect("mkdir ~/.lpm");
    let payload = serde_json::json!({
        "latest": current,
        "lastCheck": now_secs(),
    });
    std::fs::write(cache_path(&project), payload.to_string()).expect("seed cache");

    let output = lpm(&project)
        .args(["self-update"])
        .output()
        .expect("failed to run lpm self-update");

    assert!(
        output.status.success(),
        "cache-hit on matching latest must exit 0\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("› Checking for updates")
            && stderr.contains("current")
            && stderr.contains("latest")
            && stderr.contains("✓ Done · already on latest version"),
        "self-update cache hit must use slim status output, got:\n{stderr}",
    );
    assert!(
        !stderr.contains('●') && !stderr.contains('│') && !stderr.contains('◇'),
        "self-update must not use cliclack spinner/gutter output, got:\n{stderr}",
    );
}

#[test]
fn self_update_human_cache_hit_applies_slim_color_roles_when_forced() {
    let project = TempProject::empty(r#"{"name":"su","version":"1.0.0"}"#);
    let current = read_current_version(&project);

    std::fs::create_dir_all(cache_path(&project).parent().unwrap()).expect("mkdir ~/.lpm");
    let payload = serde_json::json!({
        "latest": current,
        "lastCheck": now_secs(),
    });
    std::fs::write(cache_path(&project), payload.to_string()).expect("seed cache");

    let output = lpm(&project)
        .args(["--color=always", "self-update"])
        .output()
        .expect("failed to run colored lpm self-update");

    assert!(
        output.status.success(),
        "colored cache-hit self-update must exit 0\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("\x1b[2mcurrent\x1b[22m")
            && stderr.contains("\x1b[2mlatest\x1b[22m")
            && stderr.contains("\x1b[32m")
            && stderr.contains("\x1b[33m"),
        "self-update should dim labels, green latest status, and yellow version targets, got:\n{stderr:?}",
    );
}

// ─── failure-backoff path ─────────────────────────────────────────────

#[test]
fn self_update_recent_failure_short_circuits_with_backoff_error() {
    let project = TempProject::empty(r#"{"name":"su","version":"1.0.0"}"#);

    // Seed a recent failure so the backoff gate trips before probing.
    std::fs::create_dir_all(cache_path(&project).parent().unwrap()).expect("mkdir ~/.lpm");
    let payload = serde_json::json!({
        "lastFailureCheck": now_secs(),
    });
    std::fs::write(cache_path(&project), payload.to_string()).expect("seed cache");

    let output = lpm(&project)
        .args(["self-update"])
        .output()
        .expect("failed to run lpm self-update");

    assert!(
        !output.status.success(),
        "recent-failure backoff must exit non-zero"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("last attempt failed") || stderr.contains("--refresh"),
        "stderr must mention the backoff condition + --refresh, got:\n{stderr}",
    );
    assert!(
        !stderr.contains('●') && !stderr.contains('◇'),
        "self-update backoff must not use cliclack spinner glyphs, got:\n{stderr}",
    );
}
