//! Typed environment generation workflows, filesystem ownership, and JSON contracts.
mod support;
use support::{TempProject, lpm};

fn project() -> TempProject {
    let project = TempProject::empty(r#"{"name":"typed-env"}"#);
    project.write_file("lpm.json",r#"{"env":{"release":".env.production","default":".env.production"},"envSchema":{"vars":{"TOKEN":{"required":true,"secret":true},"PORT":{"format":"port","default":"3000","requiredIn":[{"environment":["production"],"stage":["build"]}]}}}}"#);
    project
}

#[test]
fn env_local_argument_errors_use_the_json_usage_envelope() {
    let project = project();
    for args in [
        vec!["env", "check", "--json", "--bogus"],
        vec!["env", "check", "--stage=nope", "--json"],
        vec!["env", "generate", "--json", "--adapter=bad"],
    ] {
        let output = lpm(&project).args(args).output().unwrap();
        assert_eq!(output.status.code(), Some(2));
        let response: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(response["error_code"], "usage");
        assert_eq!(response["success"], false);
        assert!(output.stderr.is_empty());
        if response["argument"] == "--bogus" {
            insta::assert_json_snapshot!("env_local_unknown_argument", response);
        }
    }
    lpm(&project)
        .args(["env", "generate", "--help", "--json"])
        .assert()
        .success();
}

#[test]
fn env_generate_requires_valid_ownership_before_recommending_extra_file_removal() {
    for kind in ["source", "empty", "invalid"] {
        let project = project();
        std::fs::create_dir(project.path().join("existing")).unwrap();
        if kind != "empty" {
            project.write_file("existing/source.rs", "user source");
        }
        if kind == "invalid" {
            project.write_file("existing/.lpm-env-generated.json", "{}");
        }
        for check in [false, true] {
            let mut command = lpm(&project);
            command.args(["env", "generate", "--out-dir", "existing"]);
            if check {
                command.arg("--check");
            }
            let output = command.output().unwrap();
            assert!(!output.status.success());
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert!(
                stderr.contains("not a generated directory"),
                "{kind}: {stderr}"
            );
            assert!(stderr.contains("nonexistent output path"), "{stderr}");
            assert!(!stderr.contains("Remove extra files"), "{stderr}");
            assert!(!stderr.contains("Restore modified files"), "{stderr}");
        }
        if kind != "empty" {
            assert_eq!(project.read_file("existing/source.rs"), "user source");
        }
    }
}

#[test]
fn env_generate_ownership_json_preserves_unicode_filenames() {
    let project = project();
    lpm(&project).args(["env", "generate"]).assert().success();
    project.write_file("env.generated/café.txt", "keep");
    let output = lpm(&project)
        .args(["env", "generate", "--json"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let response: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(response["diagnostics"][0]["entry"], "café.txt");
    let output = lpm(&project).args(["env", "generate"]).output().unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("café.txt"), "{stderr}");
    assert_eq!(project.read_file("env.generated/café.txt"), "keep");
}

#[test]
#[cfg(unix)]
fn env_generate_ownership_filenames_escape_terminal_controls_once() {
    let project = project();
    lpm(&project).args(["env", "generate"]).assert().success();
    let name = "line\n\u{1b}[31m.txt";
    project.write_file(&format!("env.generated/{name}"), "keep");
    let output = lpm(&project)
        .args(["env", "generate", "--json"])
        .output()
        .unwrap();
    let response: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(response["diagnostics"][0]["entry"], name);
    let output = lpm(&project).args(["env", "generate"]).output().unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains(r"line\n\u{1b}[31m.txt"), "{stderr}");
    assert!(!stderr.contains('\u{1b}'), "{stderr}");
}

#[test]
fn env_generate_existing_file_hint_uses_a_nonexistent_output_path() {
    let project = project();
    project.write_file("output", "keep");
    for check in [false, true] {
        let mut command = lpm(&project);
        command.args(["env", "generate", "--out-dir", "output"]);
        if check {
            command.arg("--check");
        }
        let output = command.output().unwrap();
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(!output.status.success());
        assert!(stderr.contains("nonexistent output path"), "{stderr}");
        assert_eq!(project.read_file("output"), "keep");
    }
}

#[test]
fn env_generate_rejects_portable_reserved_names_and_accepts_lookalikes() {
    let project = project();
    for name in [
        "COM¹",
        "COM².txt",
        "com³",
        "LPT¹",
        "lpt².txt",
        "LPT³",
        "CONIN$",
        "conout$.txt",
    ] {
        let output = lpm(&project)
            .args(["env", "generate", "--out-dir", name, "--json"])
            .output()
            .unwrap();
        assert!(!output.status.success(), "accepted {name}");
        let response: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(response["diagnostics"][0]["code"], "env.generate_path");
        assert!(!project.path().join(name).exists());
    }
    for name in ["COM10", "COM⁴", "CONINX"] {
        lpm(&project)
            .args(["env", "generate", "--out-dir", name])
            .assert()
            .success();
    }
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

#[test]
fn env_generate_accepts_a_leading_current_directory_component() {
    let project = project();
    for flags in [
        vec!["env", "generate", "--out-dir", "./env.generated"],
        vec!["env", "generate", "--out-dir", "./env.generated", "--check"],
    ] {
        let output = lpm(&project).args(flags).output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    for path in ["./", "./../outside", "./nested/../outside"] {
        assert!(
            !lpm(&project)
                .args(["env", "generate", "--out-dir", path])
                .output()
                .unwrap()
                .status
                .success()
        );
    }
}

#[test]
fn env_generate_errors_explain_generation_recovery_without_unsupported_skip_flags() {
    let project = TempProject::empty(r#"{"name":"missing-schema"}"#);
    project.write_file("lpm.json", "{}");
    let output = lpm(&project).args(["env", "generate"]).output().unwrap();
    let error = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success());
    assert!(error.contains("Environment generation failed"), "{error}");
    assert!(!error.contains("--no-env-check"), "{error}");
    assert!(error.contains("envSchema"), "{error}");
}

#[test]
fn env_generate_remains_owned_after_a_git_autocrlf_checkout() {
    let project = project();
    assert!(
        lpm(&project)
            .args(["env", "generate"])
            .output()
            .unwrap()
            .status
            .success()
    );
    let before = std::fs::read(project.path().join("env.generated/server.js")).unwrap();
    let git = |args: &[&str]| {
        let output = std::process::Command::new("git")
            .current_dir(project.path())
            .args(args)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    };
    git(&["init", "-q"]);
    git(&["config", "core.autocrlf", "true"]);
    git(&["add", "env.generated"]);
    git(&[
        "-c",
        "user.name=Test",
        "-c",
        "user.email=test@example.invalid",
        "commit",
        "-qm",
        "generated fixture",
    ]);
    std::fs::remove_dir_all(project.path().join("env.generated")).unwrap();
    git(&["checkout", "--", "env.generated"]);
    assert_eq!(
        std::fs::read(project.path().join("env.generated/server.js")).unwrap(),
        before
    );
    let output = lpm(&project)
        .args(["env", "generate", "--check"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn env_generate_reports_schema_source_and_pointer_in_json_and_human_output() {
    let project = project();
    project.write_file("lpm.json", r#"{"envSchema":{"extends":["base.json"]}}"#);
    project.write_file("base.json", r#"{"vars":{"VALUE":{"pattern":"["}}}"#);
    for json in [false, true] {
        let mut command = lpm(&project);
        command.args(["env", "generate"]);
        if json {
            command.arg("--json");
        }
        let output = command.output().unwrap();
        assert!(!output.status.success());
        if json {
            let response: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
            assert_eq!(response["diagnostics"][0]["code"], "env.invalid_pattern");
            assert_eq!(response["diagnostics"][0]["source"], "base.json");
            assert_eq!(response["diagnostics"][0]["pointer"], "/vars/VALUE");
            insta::assert_json_snapshot!("env_generate_invalid_schema", response);
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert!(
                stderr.contains("env.invalid_pattern") && stderr.contains("base.json/vars/VALUE"),
                "{stderr}"
            );
        }
    }
}

#[test]
fn env_generate_names_unowned_extra_and_modified_files_without_overwriting_them() {
    for (entry, extra) in [(".DS_Store", true), ("server.js", false)] {
        let project = project();
        lpm(&project).args(["env", "generate"]).assert().success();
        project.write_file(&format!("env.generated/{entry}"), "user-owned");
        for check in [false, true] {
            let mut command = lpm(&project);
            command.args(["env", "generate"]);
            if check {
                command.arg("--check");
            }
            let output = command.output().unwrap();
            assert!(!output.status.success());
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert!(stderr.contains(entry), "{stderr}");
            assert!(
                stderr.contains(if extra {
                    "Remove extra files"
                } else {
                    "Restore modified files"
                }),
                "{stderr}"
            );
            assert_eq!(
                project.read_file(&format!("env.generated/{entry}")),
                "user-owned"
            );
        }
    }
}

#[test]
fn env_generate_stale_hint_retains_the_original_invocation() {
    let project = project();
    lpm(&project)
        .args([
            "env",
            "generate",
            "--adapter",
            "vite",
            "--env",
            "release",
            "--out-dir",
            "typed.env",
        ])
        .assert()
        .success();
    let config = project.read_file("lpm.json").replace("3000", "3001");
    project.write_file("lpm.json", &config);
    let output = lpm(&project)
        .args([
            "env",
            "generate",
            "--adapter",
            "vite",
            "--env",
            "release",
            "--out-dir",
            "typed.env",
            "--check",
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("same command without --check"), "{stderr}");
}

#[test]
fn env_generate_path_errors_explain_portable_names() {
    let project = project();
    for path in ["con.json", "bad:name", "name.", "name "] {
        let output = lpm(&project)
            .args(["env", "generate", "--out-dir", path])
            .output()
            .unwrap();
        assert!(!output.status.success());
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("portable") && stderr.contains("reserved"),
            "{stderr}"
        );
    }
}

#[test]
fn env_generate_rejects_unconfigured_services_and_allows_abstract_contexts() {
    for configured in [false, true] {
        let project = project();
        let mut config: serde_json::Value =
            serde_json::from_str(&project.read_file("lpm.json")).unwrap();
        if configured {
            config["services"] = serde_json::json!({"api":{"command":"node api.js"}});
        }
        project.write_file("lpm.json", &config.to_string());
        let output = lpm(&project)
            .args(["env", "generate", "--service", "apii", "--json"])
            .output()
            .unwrap();
        assert_eq!(
            output.status.success(),
            !configured,
            "{}",
            String::from_utf8_lossy(&output.stdout)
        );
        assert_eq!(project.path().join("env.generated").exists(), !configured);
    }
}

#[test]
fn env_help_lists_generation_and_action_help_exits_successfully() {
    let project = project();
    let output = lpm(&project).args(["env", "--help"]).output().unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("generate") && stdout.contains("schema"),
        "{stdout}"
    );
    for action in ["generate", "schema", "check", "print"] {
        let output = lpm(&project)
            .args(["env", action, "--help"])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(String::from_utf8_lossy(&output.stdout).contains("Usage:"));
    }
}

#[test]
fn env_generate_flag_errors_do_not_suggest_package_scripts() {
    let project = project();
    for args in [["--adapter", "typo"], ["--stage", "typo"]] {
        let output = lpm(&project)
            .args(["env", "generate"])
            .args(args)
            .output()
            .unwrap();
        assert!(!output.status.success());
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            !stderr.contains("Script error") && !stderr.contains("package.json scripts"),
            "{stderr}"
        );
    }
}
