use super::*;

#[test]
#[cfg(unix)]
fn self_update_never_runs_interpreters_from_shared_writable_path_directories() {
    use std::os::unix::fs::PermissionsExt;
    let project = TempProject::empty(r#"{"name":"update-path"}"#);
    seed_newer_stable_release(&project);
    let binary = npm_managed_lpm_path(&project);
    let bin = configure_plan_manager(&project, &binary, "npm");
    std::fs::write(bin.join("npm"), "#!/usr/bin/env node\n").unwrap();
    let shared = project.home().join("shared-tools");
    std::fs::create_dir(&shared).unwrap();
    std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o777)).unwrap();
    let marker = project.home().join("untrusted-interpreter-ran");
    let node = shared.join("node");
    std::fs::write(
        &node,
        format!("#!/bin/sh\nprintf x > '{}'\nexit 9\n", marker.display()),
    )
    .unwrap();
    std::fs::set_permissions(&node, std::fs::Permissions::from_mode(0o755)).unwrap();
    let search = std::env::join_paths([shared, bin]).unwrap();
    let output = lpm_from_path(&project, &binary)
        .args(["self-update", "--json"])
        .env("PATH", search)
        .output()
        .unwrap();
    assert!(
        !marker.exists(),
        "untrusted interpreter executed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!output.status.success());
}

#[test]
fn self_update_never_runs_writable_or_redirected_helpers_in_private_path_directories() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    for shape in ["writable", "symlink"] {
        let project = TempProject::empty(r#"{"name":"update-helper"}"#);
        seed_newer_stable_release(&project);
        let binary = npm_managed_lpm_path(&project);
        let bin = configure_plan_manager(&project, &binary, "npm");
        std::fs::write(bin.join("npm"), "#!/usr/bin/env node\n").unwrap();
        let shared = project.home().join("shared-tools");
        std::fs::create_dir(&shared).unwrap();
        std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o777)).unwrap();
        let marker = project.home().join("untrusted-helper-ran");
        let node = if shape == "writable" {
            bin.join("node")
        } else {
            shared.join("node")
        };
        std::fs::write(
            &node,
            format!("#!/bin/sh\nprintf x > '{}'\nexit 9\n", marker.display()),
        )
        .unwrap();
        std::fs::set_permissions(
            &node,
            std::fs::Permissions::from_mode(if shape == "writable" { 0o777 } else { 0o755 }),
        )
        .unwrap();
        if shape == "symlink" {
            symlink(&node, bin.join("node")).unwrap();
        }
        let output = lpm_from_path(&project, &binary)
            .args(["self-update", "--json"])
            .env("PATH", bin)
            .output()
            .unwrap();
        assert!(
            !marker.exists(),
            "{shape}: untrusted helper executed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!output.status.success());
    }
}

#[test]
fn self_update_accepts_trusted_intermediate_directory_aliases() {
    use std::os::unix::fs::symlink;
    let project = TempProject::empty(r#"{"name":"update-alias"}"#);
    seed_newer_stable_release(&project);
    let binary = npm_managed_lpm_path(&project);
    let bin = configure_plan_manager(&project, &binary, "npm");
    let tools = project.home().join("tools");
    std::fs::create_dir_all(&tools).unwrap();
    let current = tools.join("current");
    symlink(project.home(), &current).unwrap();
    let output = lpm_from_path(&project, &binary)
        .args(["self-update", "--json"])
        .env("PATH", current.join("bin"))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        report["update_program"],
        std::fs::canonicalize(bin.join("npm"))
            .unwrap()
            .to_string_lossy()
            .as_ref()
    );
}

#[test]
fn self_update_never_runs_project_helpers_through_global_symlinks() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let project = TempProject::empty(r#"{"name":"update-project-helper"}"#);
    seed_newer_stable_release(&project);
    let checkout = project.home().join("checkout");
    std::fs::create_dir(&checkout).unwrap();
    std::fs::write(checkout.join("package.json"), r#"{"name":"checkout"}"#).unwrap();
    let binary = npm_managed_lpm_path(&project);
    let bin = configure_plan_manager(&project, &binary, "npm");
    std::fs::write(bin.join("npm"), "#!/usr/bin/env node\n").unwrap();
    let marker = project.home().join("project-helper-ran");
    let node = checkout.join("node");
    std::fs::write(
        &node,
        format!("#!/bin/sh\nprintf x > '{}'\nexit 9\n", marker.display()),
    )
    .unwrap();
    std::fs::set_permissions(&node, std::fs::Permissions::from_mode(0o755)).unwrap();
    symlink(&node, bin.join("node")).unwrap();
    let output = lpm_from_path(&project, &binary)
        .current_dir(&checkout)
        .args(["self-update", "--json"])
        .env("PATH", bin)
        .output()
        .unwrap();
    assert!(
        !marker.exists(),
        "project helper executed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!output.status.success());
}
