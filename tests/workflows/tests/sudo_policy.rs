mod support;

#[cfg(unix)]
use predicates::prelude::*;
#[cfg(unix)]
use support::{TempProject, lpm, lpm_from_path};

#[cfg(unix)]
fn project() -> TempProject {
    TempProject::empty(r#"{"name":"sudo-policy-test","version":"1.0.0"}"#)
}

#[cfg(unix)]
fn configure_sudo_transition(command: &mut assert_cmd::Command) {
    command
        .env("LPM_TEST_ASSUME_EUID_ROOT", "1")
        .env("SUDO_USER", "alice");
}

#[cfg(unix)]
#[test]
fn user_command_through_sudo_fails_before_command_dispatch() {
    let project = project();
    let mut command = lpm(&project);
    configure_sudo_transition(&mut command);
    command.env("LPM_PROVENANCE_ENFORCE", "not-a-valid-mode");

    command
        .args(["schema", "lpm.json"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("Sudo is not supported"))
        .stderr(predicate::str::contains("Run LPM without sudo"));
}

#[cfg(unix)]
#[test]
fn fast_lane_install_through_sudo_fails_before_project_reads() {
    let project = project();
    let mut command = lpm(&project);
    configure_sudo_transition(&mut command);

    command
        .arg("install")
        .assert()
        .failure()
        .stderr(predicate::str::contains("Sudo is not supported"));
}

#[cfg(unix)]
#[test]
fn lpx_through_sudo_is_rejected() {
    let project = project();
    let source = assert_cmd::cargo::cargo_bin("lpm-rs");
    let lpx = project.home().join("lpx");
    std::fs::copy(source, &lpx).expect("copy lpm binary as lpx");
    let mut command = lpm_from_path(&project, &lpx);
    configure_sudo_transition(&mut command);

    command
        .arg("cowsay")
        .assert()
        .failure()
        .stderr(predicate::str::contains("Sudo is not supported"));
}

#[cfg(unix)]
#[test]
fn help_and_version_remain_available_through_sudo() {
    let project = project();
    for flag in ["--help", "--version"] {
        let mut command = lpm(&project);
        configure_sudo_transition(&mut command);
        command.arg(flag).assert().success();
    }
}

#[cfg(unix)]
#[test]
fn plain_root_session_without_sudo_user_is_allowed() {
    let project = project();
    let mut command = lpm(&project);
    command.env("LPM_TEST_ASSUME_EUID_ROOT", "1");

    command.args(["schema", "lpm.json"]).assert().success();
}

#[cfg(unix)]
#[test]
fn validated_internal_security_policy_helper_is_allowed_through_sudo() {
    let project = project();
    let mut command = lpm(&project);
    configure_sudo_transition(&mut command);
    command.env("LPM_PROVENANCE_ENFORCE", "not-a-valid-mode");

    command
        .args(["internal-security-policy", "enable-enforce"])
        .assert()
        .success();

    let policy = std::fs::read_to_string(project.home().join(".lpm/security-policy.toml"))
        .expect("read managed policy written by helper");
    assert!(policy.contains("mode = \"enforce\""), "policy: {policy}");
}

#[cfg(unix)]
#[test]
fn internal_security_policy_helper_rejects_an_arbitrary_path() {
    let project = project();
    let mut command = lpm(&project);
    configure_sudo_transition(&mut command);

    command
        .args([
            "internal-security-policy",
            "enable-enforce",
            "/tmp/unmanaged-policy.toml",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("unexpected argument"));

    assert!(!project.home().join(".lpm/security-policy.toml").exists());
}
