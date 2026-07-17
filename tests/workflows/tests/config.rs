mod support;

use support::{TempProject, assertions, lpm};

fn config_path(project: &TempProject) -> std::path::PathBuf {
    project.home().join(".lpm").join("config.toml")
}

fn seed_config(project: &TempProject, content: &str) {
    let path = config_path(project);
    std::fs::create_dir_all(path.parent().expect("config path must have a parent"))
        .expect("failed to create config dir");
    std::fs::write(path, content).expect("failed to seed config.toml");
}

#[test]
fn config_without_action_requires_interactive_terminal() {
    let project = TempProject::empty(r#"{"name":"config-menu","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args(["config"])
        .output()
        .expect("failed to run bare lpm config");

    assert!(
        !output.status.success(),
        "bare lpm config without a TTY must fail:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("lpm config requires an interactive terminal"),
        "bare lpm config must emit the guided-editor TTY error, got:\n{stderr}",
    );
    assert!(
        !stderr.contains("required arguments") && !stderr.contains("Usage:"),
        "bare lpm config must be handled by the command, not rejected by clap, got:\n{stderr}",
    );
}

#[test]
fn config_lpm_skills_without_set_requires_interactive_terminal() {
    let project = TempProject::empty(r#"{"name":"config-lpm-skills","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args(["config", "lpm-skills"])
        .output()
        .expect("failed to run lpm config lpm-skills");

    assert!(
        !output.status.success(),
        "lpm config lpm-skills without --set and without a TTY must fail"
    );
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("lpm config lpm-skills requires a TTY; use `--set true|false` instead"),
        "non-interactive error must explain the --set form, got:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn config_lpm_skills_set_false_persists_boolean_and_migrates_legacy_key() {
    let project = TempProject::empty(r#"{"name":"config-lpm-skills","version":"1.0.0"}"#);
    seed_config(
        &project,
        "registry = \"https://registry.example.test\"\nnoSkills = false\n",
    );

    let output = lpm(&project)
        .args(["--json", "config", "lpm-skills", "--set", "false"])
        .output()
        .expect("failed to run lpm config lpm-skills --set false");

    assert!(
        output.status.success(),
        "lpm config lpm-skills --set false failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let envelope: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap_or_else(|e| {
        panic!(
            "config lpm-skills --json stdout must be valid JSON: {e}\n---\n{}",
            String::from_utf8_lossy(&output.stdout)
        )
    });
    assert_eq!(
        envelope["auto-install-lpm-skills"],
        serde_json::json!(false)
    );
    insta::assert_json_snapshot!(envelope, @r###"
    {
      "success": true,
      "auto-install-lpm-skills": false
    }
    "###);

    let content = std::fs::read_to_string(config_path(&project)).expect("config file must exist");
    assert!(
        content.contains("auto-install-lpm-skills = false"),
        "wizard must persist a native TOML boolean, got:\n{content}"
    );
    assert!(
        content.contains("registry = \"https://registry.example.test\""),
        "wizard must preserve unrelated config, got:\n{content}"
    );
    assert!(
        !content.contains("noSkills"),
        "wizard must remove the migrated legacy key, got:\n{content}"
    );
}

#[test]
fn generic_config_set_lpm_skills_rejects_non_boolean_values() {
    let project = TempProject::empty(r#"{"name":"config-lpm-skills","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args(["config", "set", "auto-install-lpm-skills", "sometimes"])
        .output()
        .expect("failed to run generic lpm-skills config setter");

    assert!(!output.status.success(), "invalid boolean value must fail");
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("`auto-install-lpm-skills` must be true or false"),
        "invalid boolean error must name the canonical key, got:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !config_path(&project).exists(),
        "invalid lpm-skills config must not create config.toml"
    );
}

#[test]
fn config_set_writes_value_into_isolated_home() {
    let project = TempProject::empty(r#"{"name":"config-test","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args([
            "--json",
            "config",
            "set",
            "registry",
            "https://registry.example.test",
        ])
        .output()
        .expect("failed to run lpm config set");

    assert!(
        output.status.success(),
        "lpm config set failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let envelope: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap_or_else(|e| {
        panic!(
            "config set --json stdout must be valid JSON: {e}\n---\n{}",
            String::from_utf8_lossy(&output.stdout)
        )
    });
    assert_eq!(envelope["success"], serde_json::json!(true));

    let content = std::fs::read_to_string(config_path(&project))
        .expect("config set must create ~/.lpm/config.toml in the isolated HOME");
    assert!(
        content.contains("registry = \"https://registry.example.test\""),
        "config set must persist the key, got:\n{content}"
    );
}

#[test]
fn config_set_signatures_true_persists_boolean() {
    let project = TempProject::empty(r#"{"name":"config-signatures","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args(["--json", "config", "set", "signatures", "true"])
        .output()
        .expect("failed to run lpm config set signatures true");

    assert!(
        output.status.success(),
        "lpm config set signatures true failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let envelope: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap_or_else(|e| {
        panic!(
            "config set signatures --json stdout must be valid JSON: {e}\n---\n{}",
            String::from_utf8_lossy(&output.stdout)
        )
    });
    assert_eq!(envelope["success"], serde_json::json!(true));
    assert_eq!(envelope["value"], serde_json::json!(true));

    let content = std::fs::read_to_string(config_path(&project))
        .expect("config set must create ~/.lpm/config.toml in the isolated HOME");
    assert!(
        content.contains("signatures = true"),
        "signatures config must persist as a TOML boolean, got:\n{content}"
    );
}

#[test]
fn config_get_signatures_json_returns_boolean() {
    let project = TempProject::empty(r#"{"name":"config-signatures","version":"1.0.0"}"#);
    seed_config(&project, "signatures = true\n");

    let output = lpm(&project)
        .args(["--json", "config", "get", "signatures"])
        .output()
        .expect("failed to run lpm config get signatures");

    assert!(
        output.status.success(),
        "lpm config get signatures failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let envelope: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap_or_else(|e| {
        panic!(
            "config get signatures --json stdout must be valid JSON: {e}\n---\n{}",
            String::from_utf8_lossy(&output.stdout)
        )
    });
    assert_eq!(envelope["success"], serde_json::json!(true));
    assert_eq!(envelope["signatures"], serde_json::json!(true));
}

#[test]
fn config_signatures_set_false_preserves_unrelated_keys() {
    let project = TempProject::empty(r#"{"name":"config-signatures","version":"1.0.0"}"#);
    seed_config(
        &project,
        "registry = \"https://registry.example.test\"\nsignatures = true\n",
    );

    let output = lpm(&project)
        .args(["--json", "config", "signatures", "--set", "false"])
        .output()
        .expect("failed to run lpm config signatures --set false");

    assert!(
        output.status.success(),
        "lpm config signatures --set false failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let envelope: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap_or_else(|e| {
        panic!(
            "config signatures --json stdout must be valid JSON: {e}\n---\n{}",
            String::from_utf8_lossy(&output.stdout)
        )
    });
    assert_eq!(envelope["success"], serde_json::json!(true));
    assert_eq!(envelope["signatures"], serde_json::json!(false));

    let content = std::fs::read_to_string(config_path(&project)).expect("config file must exist");
    assert!(
        content.contains("registry = \"https://registry.example.test\""),
        "signatures wizard must preserve unrelated keys, got:\n{content}"
    );
    assert!(
        content.contains("signatures = false"),
        "signatures wizard must persist false as a TOML boolean, got:\n{content}"
    );
}

#[test]
fn config_set_trust_policy_no_downgrade_persists_string() {
    let project = TempProject::empty(r#"{"name":"config-trust-policy","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args(["--json", "config", "set", "trust-policy", "no-downgrade"])
        .output()
        .expect("failed to run lpm config set trust-policy no-downgrade");

    assert!(
        output.status.success(),
        "lpm config set trust-policy no-downgrade failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let envelope: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap_or_else(|e| {
        panic!(
            "config set trust-policy --json stdout must be valid JSON: {e}\n---\n{}",
            String::from_utf8_lossy(&output.stdout)
        )
    });
    assert_eq!(envelope["success"], serde_json::json!(true));
    assert_eq!(envelope["value"], serde_json::json!("no-downgrade"));

    let content = std::fs::read_to_string(config_path(&project))
        .expect("config set must create ~/.lpm/config.toml in the isolated HOME");
    assert!(
        content.contains("trust-policy = \"no-downgrade\""),
        "trust-policy config must persist as a TOML string, got:\n{content}"
    );
}

#[test]
fn config_set_release_age_policy_strict_persists_canonical_string() {
    let project = TempProject::empty(r#"{"name":"config-release-age-policy","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args(["--json", "config", "set", "release-age-policy", "strict"])
        .output()
        .expect("failed to run lpm config set release-age-policy strict");

    assert!(
        output.status.success(),
        "lpm config set release-age-policy strict failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let envelope: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap_or_else(|e| {
        panic!(
            "config set release-age-policy --json stdout must be valid JSON: {e}\n---\n{}",
            String::from_utf8_lossy(&output.stdout)
        )
    });
    assert_eq!(envelope["success"], serde_json::json!(true));
    assert_eq!(envelope["value"], serde_json::json!("strict"));

    let content = std::fs::read_to_string(config_path(&project))
        .expect("config set must create ~/.lpm/config.toml in the isolated HOME");
    assert!(
        content.contains("release-age-policy = \"strict\""),
        "release-age-policy config must persist as a TOML string, got:\n{content}"
    );
}

#[test]
fn config_get_release_age_policy_returns_stored_value() {
    let project = TempProject::empty(r#"{"name":"config-release-age-policy","version":"1.0.0"}"#);
    seed_config(&project, "release-age-policy = \"strict\"\n");

    let output = lpm(&project)
        .args(["--json", "config", "get", "release-age-policy"])
        .output()
        .expect("failed to run lpm config get release-age-policy");

    assert!(
        output.status.success(),
        "lpm config get release-age-policy failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let envelope: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap_or_else(|e| {
        panic!(
            "config get release-age-policy --json stdout must be valid JSON: {e}\n---\n{}",
            String::from_utf8_lossy(&output.stdout)
        )
    });
    assert_eq!(envelope["success"], serde_json::json!(true));
    assert_eq!(envelope["release-age-policy"], serde_json::json!("strict"));
}

#[test]
fn config_set_release_age_policy_direct_requires_approval_after_strict() {
    let project = TempProject::empty(r#"{"name":"config-release-age-policy","version":"1.0.0"}"#);

    let strict = lpm(&project)
        .args(["--json", "config", "set", "release-age-policy", "strict"])
        .output()
        .expect("failed to run lpm config set release-age-policy strict");
    assert!(
        strict.status.success(),
        "strict setup must succeed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&strict.stdout),
        String::from_utf8_lossy(&strict.stderr),
    );

    let direct = lpm(&project)
        .args(["--json", "config", "set", "release-age-policy", "direct"])
        .output()
        .expect("failed to run lpm config set release-age-policy direct");

    assert!(
        !direct.status.success(),
        "weakening strict release-age-policy must require approval:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&direct.stdout),
        String::from_utf8_lossy(&direct.stderr),
    );
    let envelope = assertions::assert_security_approval_required(&direct);
    assert!(
        envelope["error"]["requested_scopes"]
            .as_array()
            .is_some_and(|scopes| scopes
                .iter()
                .any(|scope| scope.as_str() == Some("cooldown-window"))),
        "approval envelope must name the cooldown-window scope; got {envelope}",
    );
}

#[test]
fn config_trust_policy_set_off_preserves_unrelated_keys() {
    let project = TempProject::empty(r#"{"name":"config-trust-policy","version":"1.0.0"}"#);
    seed_config(
        &project,
        "registry = \"https://registry.example.test\"\ntrust-policy = \"no-downgrade\"\n",
    );

    let output = lpm(&project)
        .args(["--json", "config", "trust-policy", "--set", "off"])
        .output()
        .expect("failed to run lpm config trust-policy --set off");

    assert!(
        output.status.success(),
        "lpm config trust-policy --set off failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let envelope: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap_or_else(|e| {
        panic!(
            "config trust-policy --json stdout must be valid JSON: {e}\n---\n{}",
            String::from_utf8_lossy(&output.stdout)
        )
    });
    assert_eq!(envelope["success"], serde_json::json!(true));
    assert_eq!(envelope["trust-policy"], serde_json::json!("off"));

    let content = std::fs::read_to_string(config_path(&project)).expect("config file must exist");
    assert!(
        content.contains("registry = \"https://registry.example.test\""),
        "trust-policy wizard must preserve unrelated keys, got:\n{content}"
    );
    assert!(
        content.contains("trust-policy = \"off\""),
        "trust-policy wizard must persist off as a TOML string, got:\n{content}"
    );
}

#[test]
fn config_set_trust_policy_rejects_unknown_value() {
    let project = TempProject::empty(r#"{"name":"config-trust-policy","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args(["--json", "config", "set", "trust-policy", "warn"])
        .output()
        .expect("failed to run lpm config set trust-policy warn");

    assert!(
        !output.status.success(),
        "invalid trust-policy must fail:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("invalid trust-policy") && combined.contains("no-downgrade"),
        "invalid trust-policy error must name accepted values; got:\n{combined}"
    );
    assert!(
        !config_path(&project).exists(),
        "invalid trust-policy must not create config.toml"
    );
}

#[test]
fn config_set_human_uses_slim_success() {
    let project = TempProject::empty(r#"{"name":"config-test","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args(["config", "set", "registry", "https://registry.example.test"])
        .output()
        .expect("failed to run lpm config set");

    assert!(
        output.status.success(),
        "lpm config set failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("✓ Done · registry = \"https://registry.example.test\""),
        "config set must use a slim success line, got:\n{stderr}",
    );
    assert!(
        !stderr.contains('●') && !stderr.contains('│') && !stderr.contains('◇'),
        "config set must not use cliclack gutter output, got:\n{stderr}",
    );
}

#[test]
fn config_get_json_returns_existing_value() {
    let project = TempProject::empty(r#"{"name":"config-test","version":"1.0.0"}"#);
    seed_config(&project, "registry = \"https://registry.example.test\"\n");

    let output = lpm(&project)
        .args(["config", "get", "registry", "--json"])
        .output()
        .expect("failed to run lpm config get --json");

    assert!(
        output.status.success(),
        "lpm config get --json failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let envelope: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("config get --json must be valid JSON: {e}\n---\n{stdout}"));

    assert_eq!(envelope["success"], serde_json::json!(true));
    assert_eq!(
        envelope["registry"],
        serde_json::json!("https://registry.example.test")
    );

    insta::assert_json_snapshot!("config_get_json_envelope_single_key", envelope);
}

#[test]
fn config_delete_removes_existing_key_and_preserves_other_entries() {
    let project = TempProject::empty(r#"{"name":"config-test","version":"1.0.0"}"#);
    seed_config(
        &project,
        "registry = \"https://registry.example.test\"\ncolor = \"always\"\n",
    );

    let output = lpm(&project)
        .args(["--json", "config", "delete", "registry"])
        .output()
        .expect("failed to run lpm config delete");

    assert!(
        output.status.success(),
        "lpm config delete failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let envelope: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap_or_else(|e| {
        panic!(
            "config delete --json stdout must be valid JSON: {e}\n---\n{}",
            String::from_utf8_lossy(&output.stdout)
        )
    });
    assert_eq!(envelope["success"], serde_json::json!(true));

    let content =
        std::fs::read_to_string(config_path(&project)).expect("config file must still exist");
    assert!(
        !content.contains("registry"),
        "config delete must remove the target key, got:\n{content}"
    );
    assert!(
        content.contains("color = \"always\""),
        "config delete must preserve unrelated entries, got:\n{content}"
    );
}

#[test]
fn config_list_json_reports_all_keys() {
    let project = TempProject::empty(r#"{"name":"config-test","version":"1.0.0"}"#);
    seed_config(
        &project,
        "registry = \"https://registry.example.test\"\ncolor = \"always\"\n",
    );

    let output = lpm(&project)
        .args(["config", "list", "--json"])
        .output()
        .expect("failed to run lpm config list --json");

    assert!(
        output.status.success(),
        "lpm config list --json failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let envelope: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("config list --json must be valid JSON: {e}\n---\n{stdout}"));

    assert_eq!(envelope["success"], serde_json::json!(true));
    assert_eq!(
        envelope["registry"],
        serde_json::json!("https://registry.example.test")
    );
    assert_eq!(envelope["color"], serde_json::json!("always"));

    insta::assert_json_snapshot!("config_list_json_envelope_two_keys", envelope);
}

#[test]
fn config_list_human_keeps_values_on_stdout() {
    let project = TempProject::empty(r#"{"name":"config-test","version":"1.0.0"}"#);
    seed_config(
        &project,
        "registry = \"https://registry.example.test\"\ncolor = \"always\"\n",
    );

    let output = lpm(&project)
        .args(["config", "list"])
        .output()
        .expect("failed to run lpm config list");

    assert!(
        output.status.success(),
        "lpm config list failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("registry") && stdout.contains("https://registry.example.test"),
        "config list must render config rows to stdout, got:\n{stdout}",
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains('●') && !stderr.contains('│') && !stderr.contains('◇'),
        "config list must not use cliclack gutter output, got:\n{stderr}",
    );
}

#[test]
fn config_get_missing_key_uses_slim_warning() {
    let project = TempProject::empty(r#"{"name":"config-test","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args(["config", "get", "registry"])
        .output()
        .expect("failed to run lpm config get");

    assert!(
        output.status.success(),
        "lpm config get missing key failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("! registry is not set"),
        "missing config key must use a slim warning, got:\n{stderr}",
    );
    assert!(
        !stderr.contains('●') && !stderr.contains('│') && !stderr.contains('◇'),
        "config get must not use cliclack gutter output, got:\n{stderr}",
    );
}
