//! Typed environment generation workflows, filesystem ownership, and JSON contracts.
mod support;
use support::{TempProject, lpm};

fn project() -> TempProject {
    let project = TempProject::empty(r#"{"name":"typed-env"}"#);
    project.write_file("lpm.json",r#"{"env":{"release":".env.production","default":".env.production"},"envSchema":{"vars":{"TOKEN":{"required":true,"secret":true},"PORT":{"format":"port","default":"3000","requiredIn":[{"environment":["production"],"stage":["build"]}]}}}}"#);
    project
}

#[test]
fn env_generate_json_describes_the_canonical_context_and_owned_files() {
    let project = project();
    let output = lpm(&project)
        .args([
            "env", "generate", "--env", "release", "--stage", "build", "--json",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let response: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(response["context"]["environment"], "production");
    insta::assert_json_snapshot!("env_generate_success",response,{".identity"=>"[identity]"});
    let implicit = lpm(&project)
        .args(["env", "generate", "--stage", "build", "--check", "--json"])
        .output()
        .unwrap();
    assert!(implicit.status.success());
}

#[test]
fn env_generate_checks_every_file_and_does_not_rewrite_current_output() {
    let project = project();
    assert!(
        lpm(&project)
            .args(["env", "generate"])
            .output()
            .unwrap()
            .status
            .success()
    );
    let path = project.path().join("env.generated/server.js");
    let before = std::fs::metadata(&path).unwrap().modified().unwrap();
    assert!(
        lpm(&project)
            .args(["env", "generate", "--check"])
            .output()
            .unwrap()
            .status
            .success()
    );
    assert_eq!(
        std::fs::metadata(&path).unwrap().modified().unwrap(),
        before
    );
    project.write_file("env.generated/server.js", "changed");
    assert!(
        !lpm(&project)
            .args(["env", "generate", "--check"])
            .output()
            .unwrap()
            .status
            .success()
    );
    assert!(
        !lpm(&project)
            .args(["env", "generate"])
            .output()
            .unwrap()
            .status
            .success()
    );
    assert_eq!(std::fs::read_to_string(path).unwrap(), "changed");
}

#[test]
fn env_generate_semantic_identity_ignores_root_formatting_and_sync_metadata() {
    let project = project();
    assert!(
        lpm(&project)
            .args(["env", "generate"])
            .output()
            .unwrap()
            .status
            .success()
    );
    let mut config: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(project.path().join("lpm.json")).unwrap())
            .unwrap();
    config["vaultSync"] = serde_json::json!({});
    project.write_file("lpm.json", &serde_json::to_string_pretty(&config).unwrap());
    assert!(
        lpm(&project)
            .args(["env", "generate", "--check"])
            .output()
            .unwrap()
            .status
            .success()
    );
}

#[test]
fn env_generate_rejects_invalid_flags_and_output_paths_before_publication() {
    let project = project();
    for args in [
        vec!["--out-dir", ".."],
        vec!["--out-dir", "."],
        vec!["--out-dir", "../outside"],
        vec!["--adapter", "unknown"],
        vec!["--stage", "unknown"],
        vec!["--out-dir", "/tmp/output"],
        vec!["--unknown"],
    ] {
        assert!(
            !lpm(&project)
                .args(["env", "generate"])
                .args(args)
                .output()
                .unwrap()
                .status
                .success()
        );
    }
    assert!(!project.path().join("env.generated").exists());
}

#[test]
fn env_generate_json_rejects_a_missing_schema_without_creating_output() {
    let project = TempProject::empty(r#"{"name":"missing-schema"}"#);
    project.write_file("lpm.json", "{}");
    let output = lpm(&project)
        .args(["env", "generate", "--check", "--json"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let response: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(response["success"], false);
    assert_eq!(response["diagnostics"][0]["code"], "env.schema_missing");
    insta::assert_json_snapshot!("env_generate_missing_schema", response);
    assert!(!project.path().join("env.generated").exists());
    assert!(!project.path().join(".lpm").exists());
}

#[test]
fn env_generate_check_detects_effective_fragment_changes_without_rewriting_files() {
    let project = TempProject::empty(r#"{"name":"schema-fragments"}"#);
    project.write_file("lpm.json", r#"{"envSchema":{"extends":["schema.json"]}}"#);
    project.write_file(
        "schema.json",
        r#"{"vars":{"PORT":{"format":"port","default":"3000"}}}"#,
    );
    assert!(
        lpm(&project)
            .args(["env", "generate"])
            .output()
            .unwrap()
            .status
            .success()
    );
    let original = std::fs::read(project.path().join("env.generated/server.js")).unwrap();
    project.write_file(
        "schema.json",
        r#"{"vars":{"PORT":{"format":"port","default":"4000"}}}"#,
    );
    let output = lpm(&project)
        .args(["env", "generate", "--check", "--json"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let response: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(response["diagnostics"][0]["code"], "env.generate_stale");
    assert_eq!(
        std::fs::read(project.path().join("env.generated/server.js")).unwrap(),
        original
    );
}

#[cfg(unix)]
#[test]
fn env_generate_rejects_a_fifo_root_without_waiting_for_a_writer() {
    let project = project();
    std::fs::remove_file(project.path().join("lpm.json")).unwrap();
    assert!(
        std::process::Command::new("mkfifo")
            .arg(project.path().join("lpm.json"))
            .status()
            .unwrap()
            .success()
    );
    let mut command = support::lpm_spawnable(&project);
    let mut child = command
        .args(["env", "generate", "--check"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            assert!(!status.success());
            break;
        }
        if std::time::Instant::now() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("generation blocked on FIFO root");
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    assert!(!project.path().join("env.generated").exists());
}
