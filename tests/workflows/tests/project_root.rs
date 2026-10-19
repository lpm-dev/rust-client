//! Project-scoped commands run below the project act on the project, while
//! the paths a user types stay relative to where the command ran.

mod support;

use support::{TempProject, lpm};

fn project_with_src() -> (TempProject, std::path::PathBuf) {
    let project = TempProject::empty(r#"{"name":"project-root","version":"1.0.0"}"#);
    let src = project.path().join("src/deep");
    std::fs::create_dir_all(&src).unwrap();
    (project, src)
}

#[test]
fn env_from_a_subdirectory_uses_the_project_s_env() {
    let (project, src) = project_with_src();

    lpm(&project)
        .current_dir(&src)
        .args(["env", "set", "TOKEN=fixture"])
        .assert()
        .success();
    let printed = lpm(&project)
        .args(["env", "get", "TOKEN", "--reveal"])
        .output()
        .unwrap();

    assert!(project.file_exists("lpm.json"));
    assert!(!src.join("lpm.json").exists());
    assert!(!src.join(".lpm").exists());
    assert!(String::from_utf8_lossy(&printed.stdout).contains("fixture"));
}

#[test]
fn a_project_with_only_lpm_json_is_found_from_below() {
    let project = TempProject::empty("{}");
    std::fs::remove_file(project.path().join("package.json")).unwrap();
    project.write_file("lpm.json", "{}\n");
    let src = project.path().join("config");
    std::fs::create_dir(&src).unwrap();

    lpm(&project)
        .current_dir(&src)
        .args(["env", "set", "TOKEN=fixture"])
        .assert()
        .success();

    assert!(project.read_file("lpm.json").contains("\"vault\""));
    assert!(!src.join("lpm.json").exists());
}

#[test]
fn env_file_arguments_stay_relative_to_where_the_command_ran() {
    let (project, src) = project_with_src();
    lpm(&project)
        .args(["env", "set", "TOKEN=fixture"])
        .assert()
        .success();

    lpm(&project)
        .current_dir(&src)
        .args(["env", "export", "local.env"])
        .assert()
        .success();

    assert!(src.join("local.env").is_file());
    assert!(!project.file_exists("local.env"));
}

#[test]
fn skill_sources_stay_relative_to_where_the_command_ran() {
    let (project, src) = project_with_src();
    project.write_file(
        "src/deep/team-skills/release-notes/SKILL.md",
        "---\nname: release-notes\ndescription: A useful release-notes skill for workflow testing\n---\n\nSummarize the changes.\n",
    );

    lpm(&project)
        .current_dir(&src)
        .args([
            "skills",
            "add",
            "./team-skills",
            "--skill",
            "release-notes",
            "--agent",
            "codex",
            "--project",
            "--yes",
        ])
        .assert()
        .success();

    let record = project.read_file("lpm-agent-skills.json");
    assert!(record.contains("\"./src/deep/team-skills\""), "{record}");
    assert!(project.file_exists(".agents/skills/release-notes/SKILL.md"));
}

#[test]
fn tunnel_logs_from_a_subdirectory_read_the_project_s_capture() {
    let (project, src) = project_with_src();

    let _ = lpm(&project)
        .current_dir(&src)
        .args(["tunnel", "log", "--json"])
        .output()
        .unwrap();

    assert!(
        !src.join(".lpm").exists(),
        "no capture database below the project"
    );
}

#[test]
fn package_commands_from_a_subdirectory_act_on_the_package() {
    let (project, src) = project_with_src();

    let output = lpm(&project)
        .current_dir(&src)
        .args(["publish", "--dry-run", "--json"])
        .output()
        .unwrap();

    assert!(
        !src.join(".lpm").exists(),
        "no lock directory below the package"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.contains("no package.json found in current directory"),
        "{stdout}"
    );
}

#[cfg(unix)]
#[test]
fn a_package_command_in_a_linked_home_leaves_the_project_around_it_alone() {
    let project = TempProject::empty(r#"{"name":"parent","version":"1.0.0"}"#);
    // The home directory sits in the project, and `HOME` names it through a
    // link.
    let home = project.path().join("home");
    let work = home.join("work");
    std::fs::create_dir_all(&work).unwrap();
    let linked_home = project.home().join("linked-home");
    std::os::unix::fs::symlink(&home, &linked_home).unwrap();

    let output = lpm(&project)
        .current_dir(&work)
        .env("HOME", &linked_home)
        .args(["version", "patch", "--no-git-tag-version", "--json"])
        .output()
        .unwrap();

    assert!(
        !output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    let manifest = std::fs::read_to_string(project.path().join("package.json")).unwrap();
    assert!(manifest.contains(r#""1.0.0""#), "{manifest}");
}

#[test]
fn state_writing_commands_refuse_the_home_directory_without_a_project() {
    let project = TempProject::empty(r#"{"name":"home-guard","version":"1.0.0"}"#);
    std::fs::create_dir_all(project.home().join(".lpm")).unwrap();

    let output = lpm(&project)
        .current_dir(project.home())
        .args(["env", "set", "TOKEN=fixture"])
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("not inside a project"), "{stderr}");
    assert!(!stderr.contains("lpm.json tasks"), "{stderr}");
    assert!(!project.home().join("lpm.json").exists());
}

#[test]
fn state_writing_commands_in_a_project_that_is_the_home_directory_name_lpm_home() {
    // `HOME=/app` with the app in `/app`, as some hosts run one.
    let project = TempProject::empty(r#"{"name":"home-app","version":"1.0.0"}"#);
    std::fs::create_dir_all(project.path().join(".lpm")).unwrap();

    let output = lpm(&project)
        .env("HOME", project.path())
        .env("LPM_HOME", project.path().join(".lpm"))
        .args(["env", "set", "TOKEN=fixture"])
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("set LPM_HOME to a directory outside the project")
            && !stderr.contains("not inside a project"),
        "{stderr}"
    );
    assert!(!project.path().join("lpm.json").exists());
}

#[test]
fn account_env_actions_run_in_the_home_directory() {
    let project = TempProject::empty(r#"{"name":"home-guard","version":"1.0.0"}"#);
    std::fs::create_dir_all(project.home().join(".lpm")).unwrap();

    for action in [
        &["env", "pair", "ABCD-1234"][..],
        &["env", "unpair"],
        &["env", "ls-remote"],
        &["env", "list-remote"],
        &["env", "rotate-sharing-key"],
    ] {
        let output = lpm(&project)
            .current_dir(project.home())
            .args(action)
            .output()
            .unwrap();

        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            !stderr.contains("not inside a project"),
            "{action:?}: {stderr}"
        );
    }
    assert!(!project.home().join("lpm.json").exists());
}

#[test]
fn doctor_from_a_subdirectory_checks_the_project() {
    let (project, src) = project_with_src();

    let output = lpm(&project)
        .current_dir(&src)
        .args(["doctor", "--json"])
        .output()
        .unwrap();

    let report = String::from_utf8_lossy(&output.stdout);
    assert!(!report.contains("package_json_missing"), "{report}");
}

#[test]
fn security_status_from_a_subdirectory_says_which_package_it_reports() {
    let (project, src) = project_with_src();

    let output = lpm(&project)
        .current_dir(&src)
        .args(["security", "status"])
        .output()
        .unwrap();

    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.status.success(), "{text}");
    assert!(text.contains("nearest ancestor manifest"), "{text}");
}
