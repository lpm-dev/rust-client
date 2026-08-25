mod support;

use support::{
    LOCK_CONTENTION_MARKER_ENV, TempProject, assertions, lpm, lpm_spawnable,
    wait_for_lock_contention, write_signed_release_age_exclusion_posture,
    write_signed_typosquat_guard_posture,
};

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
fn config_lpm_insights_set_false_persists_boolean_json_contract() {
    let project = TempProject::empty(r#"{"name":"config-lpm-insights","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args(["--json", "config", "lpm-insights", "--set", "false"])
        .output()
        .expect("failed to run lpm config lpm-insights --set false");

    assert!(
        output.status.success(),
        "lpm config lpm-insights --set false failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let envelope: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    insta::assert_json_snapshot!(envelope, @r###"
    {
      "success": true,
      "fetch-lpm-security-insights": false
    }
    "###);
    let content = std::fs::read_to_string(config_path(&project)).unwrap();
    assert!(content.contains("fetch-lpm-security-insights = false"));
}

#[test]
fn config_source_analysis_set_true_persists_default_security_posture() {
    let project = TempProject::empty(r#"{"name":"config-source-analysis","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args(["--json", "config", "source-analysis", "--set", "true"])
        .output()
        .expect("failed to run lpm config source-analysis --set true");

    assert!(
        output.status.success(),
        "lpm config source-analysis --set true failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let envelope: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    insta::assert_json_snapshot!(envelope, @r###"
    {
      "success": true,
      "install-time-source-analysis": true
    }
    "###);
    let content = std::fs::read_to_string(config_path(&project)).unwrap();
    assert!(content.contains("install-time-source-analysis = true"));
}

#[test]
fn config_source_analysis_disable_requires_security_approval_in_json_mode() {
    let project = TempProject::empty(r#"{"name":"config-source-analysis","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args(["--json", "config", "source-analysis", "--set", "false"])
        .output()
        .expect("failed to run guarded source-analysis setter");

    let envelope = assertions::assert_security_approval_required(&output);
    assert!(
        envelope["error"]["requested_scopes"]
            .as_array()
            .is_some_and(|scopes| scopes
                .iter()
                .any(|scope| scope.as_str() == Some("source-analysis-disable"))),
        "guarded disable must request source-analysis-disable, got:\n{envelope}"
    );
    assert!(!config_path(&project).exists());
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
fn generic_config_set_sandbox_preserves_nested_sibling_fields() {
    let project = TempProject::empty(r#"{"name":"config-sandbox","version":"1.0.0"}"#);
    seed_config(
        &project,
        "[sandbox]\nmode = \"default\"\nallow-degraded = true\n",
    );

    let output = lpm(&project)
        .args(["--json", "config", "set", "sandbox", "strict"])
        .output()
        .expect("failed to run generic sandbox config setter");

    assert!(
        output.status.success(),
        "generic sandbox setter must succeed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let envelope = assertions::parse_json_output(&output.stdout);
    assert_eq!(envelope["success"], true);
    assert_eq!(envelope["action"], "set");
    assert_eq!(envelope["key"], "sandbox");
    assert_eq!(envelope["value"], serde_json::json!({ "mode": "strict" }));

    let config: toml::Value = toml::from_str(
        &std::fs::read_to_string(config_path(&project)).expect("read config after sandbox set"),
    )
    .expect("config must remain valid TOML");
    let sandbox = config["sandbox"]
        .as_table()
        .expect("sandbox must remain a table");
    assert_eq!(sandbox["mode"].as_str(), Some("strict"));
    assert_eq!(sandbox["allow-degraded"].as_bool(), Some(true));

    insta::assert_json_snapshot!("config_set_nested_sandbox_json_envelope", envelope);
}

#[test]
fn generic_config_set_sigstore_preserves_nested_sibling_fields() {
    let project = TempProject::empty(r#"{"name":"config-sigstore","version":"1.0.0"}"#);
    seed_config(
        &project,
        "[sigstore]\nverify = \"deny\"\nscope = \"approved\"\navailability = \"best-effort\"\n",
    );

    let output = lpm(&project)
        .args(["--json", "config", "set", "sigstore", "scope=all"])
        .output()
        .expect("failed to run generic sigstore config setter");

    assert!(
        output.status.success(),
        "generic sigstore setter must succeed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let envelope = assertions::parse_json_output(&output.stdout);
    assert_eq!(envelope["value"], serde_json::json!({ "scope": "all" }));

    let config: toml::Value = toml::from_str(
        &std::fs::read_to_string(config_path(&project)).expect("read config after sigstore set"),
    )
    .expect("config must remain valid TOML");
    let sigstore = config["sigstore"]
        .as_table()
        .expect("sigstore must remain a table");
    assert_eq!(sigstore["verify"].as_str(), Some("deny"));
    assert_eq!(sigstore["scope"].as_str(), Some("all"));
    assert_eq!(sigstore["availability"].as_str(), Some("best-effort"));
}

#[test]
fn generic_config_set_firewall_preserves_nested_sibling_fields() {
    let project = TempProject::empty(r#"{"name":"config-firewall","version":"1.0.0"}"#);
    seed_config(&project, "[firewall]\nmode = \"off\"\nnote = \"keep-me\"\n");

    let output = lpm(&project)
        .args(["--json", "config", "set", "firewall", "monitor"])
        .output()
        .expect("failed to run generic firewall config setter");

    assert!(
        output.status.success(),
        "generic firewall setter must succeed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let envelope = assertions::parse_json_output(&output.stdout);
    assert_eq!(envelope["value"], serde_json::json!({ "mode": "monitor" }));

    let config: toml::Value = toml::from_str(
        &std::fs::read_to_string(config_path(&project)).expect("read config after firewall set"),
    )
    .expect("config must remain valid TOML");
    let firewall = config["firewall"]
        .as_table()
        .expect("firewall must remain a table");
    assert_eq!(firewall["mode"].as_str(), Some("monitor"));
    assert_eq!(firewall["note"].as_str(), Some("keep-me"));
}

#[test]
fn generic_config_set_policy_rejects_scalar_without_mutation() {
    let project = TempProject::empty(r#"{"name":"config-policy","version":"1.0.0"}"#);
    let original = "[policy.extensions.fixture]\ncommand = [\"policy-fixture\"]\n";
    seed_config(&project, original);

    let output = lpm(&project)
        .args(["--json", "config", "set", "policy", "enforce"])
        .output()
        .expect("failed to run generic policy config setter");

    assert!(!output.status.success(), "nested policy set must fail");
    let envelope = assertions::parse_json_output(&output.stdout);
    assert_eq!(envelope["error_code"], "registry");
    assert!(
        envelope["error"]
            .as_str()
            .is_some_and(|error| error.contains("cannot write nested section `policy`")),
        "error must identify the unsupported section: {envelope}"
    );
    assert_eq!(
        std::fs::read_to_string(config_path(&project)).expect("read preserved policy config"),
        original
    );
    insta::assert_json_snapshot!("config_set_nested_policy_rejected", envelope);
}

#[test]
fn generic_config_set_tunnel_rejects_scalar_without_mutation() {
    let project = TempProject::empty(r#"{"name":"config-tunnel","version":"1.0.0"}"#);
    let original = "[tunnel]\nrelay-url = \"wss://relay.example.test/connect\"\n";
    seed_config(&project, original);

    let output = lpm(&project)
        .args(["--json", "config", "set", "tunnel", "replacement"])
        .output()
        .expect("failed to run generic tunnel config setter");

    assert!(!output.status.success(), "nested tunnel set must fail");
    let envelope = assertions::parse_json_output(&output.stdout);
    assert_eq!(envelope["error_code"], "registry");
    assert_eq!(
        std::fs::read_to_string(config_path(&project)).expect("read preserved tunnel config"),
        original
    );
}

#[test]
fn generic_config_set_sandbox_rejects_invalid_mode_without_mutation() {
    let project = TempProject::empty(r#"{"name":"config-sandbox-invalid","version":"1.0.0"}"#);
    let original = "[sandbox]\nmode = \"strict\"\nallow-degraded = false\n";
    seed_config(&project, original);

    let output = lpm(&project)
        .args(["--json", "config", "set", "sandbox", "unrestricted"])
        .output()
        .expect("failed to run generic sandbox config setter");

    assert!(!output.status.success(), "invalid sandbox mode must fail");
    let envelope = assertions::parse_json_output(&output.stdout);
    assert_eq!(envelope["error_code"], "registry");
    assert!(
        envelope["error"]
            .as_str()
            .is_some_and(|error| error.contains("default | strict | none")),
        "error must list valid sandbox modes: {envelope}"
    );
    assert_eq!(
        std::fs::read_to_string(config_path(&project)).expect("read preserved sandbox config"),
        original
    );
}

#[test]
fn generic_config_set_sandbox_uses_security_approval_without_mutation() {
    let project = TempProject::empty(r#"{"name":"config-sandbox-approval","version":"1.0.0"}"#);
    let original = "[sandbox]\nmode = \"strict\"\nallow-degraded = false\n";
    seed_config(&project, original);

    let output = lpm(&project)
        .args(["--json", "config", "set", "sandbox", "none"])
        .output()
        .expect("failed to run generic sandbox config setter");

    let envelope = assertions::assert_security_approval_required(&output);
    assert!(
        envelope["error"]["requested_scopes"]
            .as_array()
            .is_some_and(|scopes| scopes
                .iter()
                .any(|scope| scope.as_str() == Some("sandbox-none"))),
        "generic setter must request the sandbox-none scope: {envelope}"
    );
    assert_eq!(
        std::fs::read_to_string(config_path(&project)).expect("read preserved sandbox config"),
        original
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
    assert_eq!(
        envelope,
        serde_json::json!({
            "success": true,
            "action": "get",
            "key": "signatures",
            "value": true,
            "found": true,
        })
    );
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
    assert_eq!(
        envelope,
        serde_json::json!({
            "success": true,
            "action": "get",
            "key": "release-age-policy",
            "value": "strict",
            "found": true,
        })
    );
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

    assert_eq!(
        envelope,
        serde_json::json!({
            "success": true,
            "action": "get",
            "key": "registry",
            "value": "https://registry.example.test",
            "found": true,
        })
    );

    insta::assert_json_snapshot!("config_get_json_envelope_single_key", envelope);
}

#[test]
fn config_get_missing_key_json_returns_stable_envelope() {
    let project = TempProject::empty(r#"{"name":"config-test","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args(["config", "get", "registry", "--json"])
        .output()
        .expect("failed to run lpm config get --json for a missing key");

    assert!(
        output.status.success(),
        "lpm config get --json failed for a missing key:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let envelope: serde_json::Value = serde_json::from_str(&stdout).unwrap_or_else(|error| {
        panic!("config get --json must return JSON for a missing key: {error}\n---\n{stdout}")
    });

    assert_eq!(
        envelope,
        serde_json::json!({
            "success": true,
            "action": "get",
            "key": "registry",
            "value": null,
            "found": false,
        })
    );
    assert!(
        output.stderr.is_empty(),
        "config get --json must not write human output to stderr: {}",
        String::from_utf8_lossy(&output.stderr),
    );

    insta::assert_json_snapshot!("config_get_json_envelope_missing_key", envelope);
}

#[test]
fn config_get_json_preserves_special_characters_in_missing_key() {
    let project = TempProject::empty(r#"{"name":"config-test","version":"1.0.0"}"#);
    let key = "registry\"\\path\n⚠";

    let output = lpm(&project)
        .args(["config", "get", key, "--json"])
        .output()
        .expect("failed to run lpm config get --json with a special-character key");

    assert!(
        output.status.success(),
        "lpm config get --json failed with a special-character key:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let envelope: serde_json::Value =
        serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
            panic!(
                "config get --json must escape a special-character key: {error}\n---\n{}",
                String::from_utf8_lossy(&output.stdout)
            )
        });

    assert_eq!(
        envelope,
        serde_json::json!({
            "success": true,
            "action": "get",
            "key": key,
            "value": null,
            "found": false,
        })
    );
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
fn config_mutations_wait_for_one_shared_transaction_lock_and_preserve_prior_updates() {
    let project = TempProject::empty(r#"{"name":"config-lock","version":"1.0.0"}"#);
    seed_config(&project, "color = \"always\"\n");
    write_signed_release_age_exclusion_posture(&project, &["react"]);
    let lock_path = project.home().join(".lpm/.config.lock");

    for (index, args) in [
        vec!["config", "release-age-exclude", "add", "react"],
        vec!["config", "set", "registry", "https://registry.example.test"],
        vec!["config", "lpm-skills", "--set", "false"],
        vec!["config", "delete", "registry"],
    ]
    .into_iter()
    .enumerate()
    {
        let transaction_lock = lpm_common::acquire_exclusive_lock(&lock_path)
            .expect("hold the config transaction lock");
        let marker_path = project
            .home()
            .join(format!("config-lock-contention-{index}"));
        let mut command = lpm_spawnable(&project);
        command
            .env(LOCK_CONTENTION_MARKER_ENV, &marker_path)
            .args(args);
        let mut child = command.spawn().expect("spawn config mutation");

        wait_for_lock_contention(&mut child, &marker_path, &lock_path);
        let mut config = std::fs::OpenOptions::new()
            .append(true)
            .open(config_path(&project))
            .expect("open config as the active transaction owner");
        std::io::Write::write_all(
            &mut config,
            format!("lock-holder-update-{index} = true\n").as_bytes(),
        )
        .expect("append a concurrent config transaction update");
        drop(transaction_lock);

        let output = child.wait_with_output().expect("finish config mutation");
        assert!(
            output.status.success(),
            "config mutation failed after lock release:\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
    }

    let config: toml::Value =
        toml::from_str(&std::fs::read_to_string(config_path(&project)).unwrap()).unwrap();
    assert_eq!(config["color"].as_str(), Some("always"));
    assert_eq!(
        config["minimum-release-age-exclude"],
        toml::Value::Array(vec![toml::Value::String("react".to_string())])
    );
    assert_eq!(config["auto-install-lpm-skills"].as_bool(), Some(false));
    assert!(config.get("registry").is_none());
    for index in 0..4 {
        assert_eq!(
            config[format!("lock-holder-update-{index}")].as_bool(),
            Some(true),
            "the waiting writer must reload the lock holder's update"
        );
    }
}

#[test]
fn config_list_json_reports_every_known_effective_key() {
    let project = TempProject::empty(r#"{"name":"config-test","version":"1.0.0"}"#);

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
    assert_eq!(envelope["action"], serde_json::json!("list"));
    let entries = envelope["entries"]
        .as_array()
        .expect("config list --json must return an entries array");
    let keys: Vec<&str> = entries
        .iter()
        .map(|entry| {
            entry["key"]
                .as_str()
                .expect("each effective config entry must have a string key")
        })
        .collect();
    assert_eq!(
        keys,
        [
            "save-prefix",
            "save-exact",
            "script-policy",
            "triage-advisor",
            "sandbox.mode",
            "sandbox.allow-degraded",
            "script-read-allow",
            "max-sandbox-write-roots",
            "minimum-release-age-secs",
            "release-age-policy",
            "minimum-release-age-exclude",
            "sigstore.verify",
            "sigstore.scope",
            "sigstore.availability",
            "signatures",
            "trust-policy",
            "typosquat-guard",
            "firewall.mode",
            "firewall.npm.policies.trusted_public_malicious_advisories",
            "firewall.npm.policies.lpm_ai_confirmed_malware",
            "firewall.npm.policies.lpm_ai_agent_control_surface",
            "firewall.npm.policies.critical_vulnerability",
            "firewall.npm.policies.lpm_ai_suspicious",
            "integrity",
            "install-time-source-analysis",
            "fetch-lpm-security-insights",
            "engine-strict",
            "strict-peer-dependencies",
            "auto-install-peers",
            "auto-install-lpm-skills",
            "audit-after-install",
            "linker",
            "workspace-concurrency",
            "tunnel.relay-url",
        ]
    );
    assert_eq!(envelope["count"], serde_json::json!(entries.len()));
    assert!(entries.iter().all(|entry| {
        entry["group"].is_string() && entry["source"].is_string() && !entry["value"].is_null()
    }));

    let mut snapshot = envelope;
    let workspace_concurrency = snapshot["entries"]
        .as_array_mut()
        .and_then(|entries| {
            entries
                .iter_mut()
                .find(|entry| entry["key"] == "workspace-concurrency")
        })
        .expect("workspace-concurrency must exist in the snapshot envelope");
    workspace_concurrency["value"] = serde_json::json!("[available parallelism]");
    insta::assert_json_snapshot!("config_list_json_effective_defaults", snapshot);
}

#[test]
fn config_list_resolves_project_user_and_environment_sources() {
    let project = TempProject::empty(
        r#"{
            "name": "config-test",
            "version": "1.0.0",
            "lpm": {
                "minimumReleaseAge": 172800,
                "autoInstallPeers": false,
                "strictPeerDependencies": true
            }
        }"#,
    );
    project.write_file(
        "lpm.toml",
        "save-prefix = \"~\"\n[workspace]\nconcurrency = 2\n[sandbox]\nmode = \"strict\"\n",
    );
    seed_config(
        &project,
        "save-exact = true\nlinker = \"isolated\"\ncustom-future-key = \"kept\"\n",
    );

    let output = lpm(&project)
        .env("LPM_AUDIT_AFTER_INSTALL", "true")
        .args(["config", "list", "--json"])
        .output()
        .expect("failed to run lpm config list --json");

    assert!(
        output.status.success(),
        "lpm config list --json failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let envelope: serde_json::Value = serde_json::from_slice(&output.stdout)
        .expect("config list --json stdout must be valid JSON");
    let entries = envelope["entries"]
        .as_array()
        .expect("config list --json must return an entries array");
    let entry = |key: &str| {
        entries
            .iter()
            .find(|entry| entry["key"] == key)
            .unwrap_or_else(|| panic!("missing effective config entry for {key}"))
    };

    assert_eq!(entry("save-prefix")["value"], serde_json::json!("~"));
    assert_eq!(
        entry("save-prefix")["source"],
        serde_json::json!("lpm.toml")
    );
    assert_eq!(
        entry("save-exact")["source"],
        serde_json::json!("~/.lpm/config.toml")
    );
    assert_eq!(
        entry("minimum-release-age-secs")["source"],
        serde_json::json!("package.json > lpm")
    );
    assert_eq!(
        entry("sandbox.mode")["source"],
        serde_json::json!("lpm.toml")
    );
    assert_eq!(
        entry("auto-install-peers")["source"],
        serde_json::json!("package.json > lpm")
    );
    assert_eq!(
        entry("strict-peer-dependencies")["source"],
        serde_json::json!("package.json > lpm")
    );
    assert_eq!(
        entry("workspace-concurrency")["source"],
        serde_json::json!("lpm.toml")
    );
    assert_eq!(
        entry("audit-after-install")["source"],
        serde_json::json!("LPM_AUDIT_AFTER_INSTALL")
    );
    assert_eq!(
        entry("custom-future-key")["source"],
        serde_json::json!("~/.lpm/config.toml")
    );
}

#[test]
fn config_list_human_groups_effective_values_and_sources() {
    let project = TempProject::empty(r#"{"name":"config-test","version":"1.0.0"}"#);
    seed_config(&project, "[sigstore]\nverify = \"deny\"\nscope = \"all\"\n");

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
    assert!(stdout.contains("Dependency saving"));
    assert!(stdout.contains("Lifecycle scripts"));
    assert!(stdout.contains("Supply-chain security"));
    assert!(stdout.contains("Installation"));
    assert!(stdout.contains("Workspaces"));
    assert!(stdout.contains("Network"));
    assert!(stdout.contains("sigstore.verify"));
    assert!(stdout.contains("~/.lpm/config.toml"));
    assert!(stdout.contains("built-in default"));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains('●') && !stderr.contains('│') && !stderr.contains('◇'),
        "config list must not use cliclack gutter output, got:\n{stderr}",
    );
}

#[test]
fn config_list_reports_managed_security_floor_sources() {
    let project = TempProject::empty(r#"{"name":"config-test","version":"1.0.0"}"#);
    let policy_path = project.home().join(".lpm").join("security-policy.toml");
    std::fs::create_dir_all(
        policy_path
            .parent()
            .expect("policy path must have a parent"),
    )
    .expect("failed to create managed policy directory");
    std::fs::write(
        policy_path,
        "script-policy = \"deny\"\n[sandbox]\nmode = \"strict\"\n",
    )
    .expect("failed to seed managed security policy");

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
    let envelope: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("config list stdout must be JSON");
    let entries = envelope["entries"]
        .as_array()
        .expect("config list --json must return entries");
    let entry = |key: &str| {
        entries
            .iter()
            .find(|entry| entry["key"] == key)
            .unwrap_or_else(|| panic!("missing effective config entry for {key}"))
    };

    assert_eq!(
        entry("script-policy")["source"],
        serde_json::json!("managed security policy")
    );
    assert_eq!(entry("sandbox.mode")["value"], serde_json::json!("strict"));
    assert_eq!(
        entry("sandbox.mode")["source"],
        serde_json::json!("managed security policy")
    );
}

#[test]
fn config_list_reports_approved_security_posture_sources() {
    let project = TempProject::empty(r#"{"name":"config-test","version":"1.0.0"}"#);
    write_signed_typosquat_guard_posture(&project, "off");

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
    let envelope: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("config list stdout must be JSON");
    let typosquat = envelope["entries"]
        .as_array()
        .and_then(|entries| {
            entries
                .iter()
                .find(|entry| entry["key"] == "typosquat-guard")
        })
        .expect("config list must include typosquat-guard");

    assert_eq!(typosquat["value"], serde_json::json!("off"));
    assert_eq!(
        typosquat["source"],
        serde_json::json!("approved security posture")
    );
}

#[test]
fn config_list_expands_named_policy_extension_fields() {
    let project = TempProject::empty(r#"{"name":"config-test","version":"1.0.0"}"#);
    seed_config(
        &project,
        r#"
[policy.extensions.local-feed]
command = ["node", "--version"]
mode = "enforce"
on-error = "block"
timeout-ms = 2500
events = ["package.candidate"]

[policy.extensions.defaults-feed]
command = ["node", "--version"]

[policy.extensions.paused-feed]
enabled = false
"#,
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
    let envelope: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("config list stdout must be JSON");
    let entries = envelope["entries"]
        .as_array()
        .expect("config list --json must return entries");
    let extension_keys: Vec<_> = entries
        .iter()
        .filter_map(|entry| {
            entry["key"]
                .as_str()
                .filter(|key| key.starts_with("policy.extensions."))
        })
        .collect();

    assert_eq!(
        extension_keys,
        [
            "policy.extensions.defaults-feed.enabled",
            "policy.extensions.defaults-feed.command",
            "policy.extensions.defaults-feed.mode",
            "policy.extensions.defaults-feed.on-error",
            "policy.extensions.defaults-feed.timeout-ms",
            "policy.extensions.defaults-feed.events",
            "policy.extensions.local-feed.enabled",
            "policy.extensions.local-feed.command",
            "policy.extensions.local-feed.mode",
            "policy.extensions.local-feed.on-error",
            "policy.extensions.local-feed.timeout-ms",
            "policy.extensions.local-feed.events",
            "policy.extensions.paused-feed.enabled",
        ]
    );

    let entry = |key: &str| {
        entries
            .iter()
            .find(|entry| entry["key"] == key)
            .unwrap_or_else(|| panic!("missing effective config entry for {key}"))
    };
    assert_eq!(
        entry("policy.extensions.defaults-feed.enabled")["source"],
        serde_json::json!("built-in default")
    );
    assert_eq!(
        entry("policy.extensions.defaults-feed.command")["source"],
        serde_json::json!("~/.lpm/config.toml")
    );
    for key in ["mode", "on-error", "timeout-ms", "events"] {
        assert_eq!(
            entry(&format!("policy.extensions.defaults-feed.{key}"))["source"],
            serde_json::json!("built-in default"),
            "omitted extension field {key} must report its default source"
        );
    }
}

#[test]
fn config_list_rejects_a_malformed_known_value() {
    let project = TempProject::empty(r#"{"name":"config-test","version":"1.0.0"}"#);
    seed_config(&project, "minimum-release-age-secs = \"soon\"\n");

    let output = lpm(&project)
        .args(["config", "list", "--json"])
        .output()
        .expect("failed to run lpm config list --json");

    assert!(
        !output.status.success(),
        "config list must reject a malformed known value"
    );
    let envelope = assertions::parse_json_output(&output.stdout);
    assert_eq!(envelope["error_code"], "registry");
    assert!(
        envelope["error"].as_str().is_some_and(|error| {
            error.contains("minimum-release-age-secs")
                && error.contains("must be a non-negative integer")
        }),
        "config list must identify the malformed key and expected type: {envelope}"
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

#[test]
fn generic_config_set_rejects_release_age_exclude_scalar_without_mutation() {
    let project = TempProject::empty(r#"{"name":"config-excludes","version":"1.0.0"}"#);
    seed_config(
        &project,
        "registry = \"https://registry.example.test\"\nminimum-release-age-exclude = [\"react\"]\n",
    );
    let path = config_path(&project);
    let before = std::fs::read(&path).unwrap();

    let output = lpm(&project)
        .args(["config", "set", "minimum-release-age-exclude", "lodash"])
        .output()
        .expect("failed to run generic release-age exclusion setter");

    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("lpm config release-age-exclude add lodash"),
        "error must point to the typed list command: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(std::fs::read(path).unwrap(), before);
}

#[test]
fn config_release_age_exclude_add_accepts_supported_selectors_and_writes_a_toml_array() {
    let project = TempProject::empty(r#"{"name":"config-excludes","version":"1.0.0"}"#);
    seed_config(&project, "registry = \"https://registry.example.test\"\n");
    let selectors = ["react", "@company/*", "react@1.0.0"];
    write_signed_release_age_exclusion_posture(&project, &selectors);

    for selector in selectors {
        let output = lpm(&project)
            .args(["--json", "config", "release-age-exclude", "add", selector])
            .output()
            .expect("failed to add user release-age exclusion");
        assert!(
            output.status.success(),
            "user exclusion add failed for {selector}:\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
    }

    let content = std::fs::read_to_string(config_path(&project)).unwrap();
    let config: toml::Value = toml::from_str(&content).unwrap();
    assert_eq!(
        config["minimum-release-age-exclude"],
        toml::Value::Array(
            ["react", "@company/*", "react@1.0.0"]
                .into_iter()
                .map(|entry| toml::Value::String(entry.to_string()))
                .collect()
        )
    );
    assert_eq!(
        config["registry"].as_str(),
        Some("https://registry.example.test")
    );

    let list = lpm(&project)
        .args(["--json", "config", "release-age-exclude", "list"])
        .output()
        .expect("failed to list user release-age exclusions");
    assert!(list.status.success());
    let envelope: serde_json::Value = serde_json::from_slice(&list.stdout).unwrap();
    insta::assert_json_snapshot!(envelope, @r###"
    {
      "success": true,
      "schema_version": 1,
      "command": "config release-age-exclude",
      "scope": "user",
      "action": "list",
      "changed": false,
      "normalized": false,
      "count": 3,
      "exclusions": [
        "react",
        "@company/*",
        "react@1.0.0"
      ]
    }
    "###);
}

#[test]
fn config_release_age_exclude_add_reports_a_duplicate_without_rewriting_config() {
    let project = TempProject::empty(r#"{"name":"config-excludes","version":"1.0.0"}"#);
    seed_config(
        &project,
        "registry = \"https://registry.example.test\"\nminimum-release-age-exclude = [\"react\"]\n",
    );
    let path = config_path(&project);
    let before = std::fs::read(&path).unwrap();

    let output = lpm(&project)
        .args(["--json", "config", "release-age-exclude", "add", "react"])
        .output()
        .expect("failed to repeat user release-age exclusion");

    assert!(output.status.success());
    let envelope: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    insta::assert_json_snapshot!(envelope, @r###"
    {
      "success": true,
      "schema_version": 1,
      "command": "config release-age-exclude",
      "scope": "user",
      "action": "add",
      "selector": "react",
      "changed": false,
      "normalized": false,
      "count": 1,
      "exclusions": [
        "react"
      ]
    }
    "###);
    assert_eq!(std::fs::read(path).unwrap(), before);
}

#[test]
fn config_release_age_exclude_duplicate_add_normalizes_storage_without_claiming_a_selector_change()
{
    let project = TempProject::empty(r#"{"name":"config-excludes","version":"1.0.0"}"#);
    seed_config(
        &project,
        "minimum-release-age-exclude = [\"react\", \"react\"]\n",
    );

    let output = lpm(&project)
        .args(["--json", "config", "release-age-exclude", "add", "react"])
        .output()
        .expect("failed to normalize duplicate user release-age exclusions");

    assert!(output.status.success());
    let envelope: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(envelope["changed"], serde_json::json!(false));
    assert_eq!(envelope["normalized"], serde_json::json!(true));
    assert_eq!(envelope["count"], serde_json::json!(1));
    assert_eq!(envelope["exclusions"], serde_json::json!(["react"]));

    let config: toml::Value =
        toml::from_str(&std::fs::read_to_string(config_path(&project)).unwrap()).unwrap();
    assert_eq!(
        config["minimum-release-age-exclude"],
        toml::Value::Array(vec![toml::Value::String("react".to_string())])
    );
}

#[test]
fn config_release_age_exclude_remove_only_removes_the_complete_selector() {
    let project = TempProject::empty(r#"{"name":"config-excludes","version":"1.0.0"}"#);
    seed_config(
        &project,
        "minimum-release-age-exclude = [\"react\", \"react@1.0.0\", \"@company/*\"]\n",
    );

    let output = lpm(&project)
        .args([
            "--json",
            "config",
            "release-age-exclude",
            "remove",
            "react@1.0.0",
        ])
        .output()
        .expect("failed to remove user release-age exclusion");

    assert!(output.status.success());
    let envelope: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    insta::assert_json_snapshot!(envelope, @r###"
    {
      "success": true,
      "schema_version": 1,
      "command": "config release-age-exclude",
      "scope": "user",
      "action": "remove",
      "selector": "react@1.0.0",
      "changed": true,
      "normalized": false,
      "count": 2,
      "exclusions": [
        "react",
        "@company/*"
      ]
    }
    "###);
}

#[test]
fn config_release_age_exclude_remove_last_selector_deletes_only_the_config_key() {
    let project = TempProject::empty(r#"{"name":"config-excludes","version":"1.0.0"}"#);
    seed_config(
        &project,
        "registry = \"https://registry.example.test\"\nminimum-release-age-exclude = [\"react\"]\n",
    );

    let output = lpm(&project)
        .args(["config", "release-age-exclude", "remove", "react"])
        .output()
        .expect("failed to remove final user release-age exclusion");

    assert!(output.status.success());
    let content = std::fs::read_to_string(config_path(&project)).unwrap();
    let config: toml::Value = toml::from_str(&content).unwrap();
    assert!(config.get("minimum-release-age-exclude").is_none());
    assert_eq!(
        config["registry"].as_str(),
        Some("https://registry.example.test")
    );
}

#[test]
fn config_release_age_exclude_rejects_ranges_without_creating_config() {
    let project = TempProject::empty(r#"{"name":"config-excludes","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args(["config", "release-age-exclude", "add", "react@^1.0.0"])
        .output()
        .expect("failed to run invalid user release-age exclusion");

    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("exact semantic version"),
        "error must explain exact-version selectors: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!config_path(&project).exists());
}

#[test]
fn config_release_age_exclude_rejects_the_legacy_scalar_without_mutation() {
    let project = TempProject::empty(r#"{"name":"config-excludes","version":"1.0.0"}"#);
    seed_config(&project, "minimum-release-age-exclude = \"react\"\n");
    let path = config_path(&project);
    let before = std::fs::read(&path).unwrap();

    let output = lpm(&project)
        .args(["config", "release-age-exclude", "add", "lodash"])
        .output()
        .expect("failed to inspect scalar user release-age exclusion");

    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("must be an array of strings"),
        "error must identify the required list shape: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(std::fs::read(path).unwrap(), before);
}

#[test]
fn config_release_age_exclude_list_without_config_reports_an_empty_user_list() {
    let project = TempProject::empty(r#"{"name":"config-excludes","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args(["--json", "config", "release-age-exclude", "list"])
        .output()
        .expect("failed to list user release-age exclusions without config");

    assert!(output.status.success());
    let envelope: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(envelope["exclusions"], serde_json::json!([]));
    assert_eq!(envelope["count"], serde_json::json!(0));
    assert_eq!(envelope["normalized"], serde_json::json!(false));
    assert!(!config_path(&project).exists());
}

#[test]
fn config_rejects_arguments_that_do_not_belong_to_the_selected_action() {
    let cases: &[&[&str]] = &[
        &["config", "list", "ignored"],
        &["config", "get", "registry", "ignored"],
        &["config", "delete", "registry", "ignored"],
        &["config", "scripts", "ignored", "--set", "deny"],
        &["config", "list", "--set", "anything"],
        &["config", "set", "registry", "value", "--set", "ignored"],
    ];

    for args in cases {
        let project = TempProject::empty(r#"{"name":"config-shape","version":"1.0.0"}"#);
        let output = lpm(&project)
            .args(*args)
            .output()
            .unwrap_or_else(|error| panic!("failed to run {args:?}: {error}"));
        assert!(
            !output.status.success(),
            "invalid config shape {args:?} must fail:\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
        assert!(
            !config_path(&project).exists(),
            "invalid config shape {args:?} must not create config.toml"
        );
    }
}

#[test]
fn config_mutation_preserves_unrelated_toml_comments_and_formatting() {
    let project = TempProject::empty(r#"{"name":"config-comments","version":"1.0.0"}"#);
    seed_config(
        &project,
        "# registry routing\nregistry = \"https://registry.example.test\" # keep inline\n\n[sandbox] # containment\nmode = \"default\"\n",
    );

    let output = lpm(&project)
        .args(["config", "set", "color", "always"])
        .output()
        .expect("failed to mutate commented config");
    assert!(output.status.success());

    let content = std::fs::read_to_string(config_path(&project)).unwrap();
    assert!(content.contains("# registry routing"), "{content}");
    assert!(
        content.contains("registry = \"https://registry.example.test\" # keep inline"),
        "{content}"
    );
    assert!(content.contains("[sandbox] # containment"), "{content}");
}

#[test]
fn config_get_and_delete_round_trip_nested_list_keys() {
    let project = TempProject::empty(r#"{"name":"config-nested","version":"1.0.0"}"#);
    seed_config(
        &project,
        "[sandbox]\nmode = \"strict\"\nallow-degraded = false\n",
    );

    let get = lpm(&project)
        .args(["--json", "config", "get", "sandbox.mode"])
        .output()
        .expect("failed to get nested config key");
    assert!(get.status.success());
    let envelope: serde_json::Value = serde_json::from_slice(&get.stdout).unwrap();
    assert_eq!(envelope["found"], serde_json::json!(true));
    assert_eq!(envelope["value"], serde_json::json!("strict"));

    let delete = lpm(&project)
        .args(["--json", "config", "delete", "sandbox.mode"])
        .output()
        .expect("failed to delete nested config key");
    assert!(delete.status.success());
    let envelope: serde_json::Value = serde_json::from_slice(&delete.stdout).unwrap();
    assert_eq!(envelope["existed"], serde_json::json!(true));

    let config: toml::Value =
        toml::from_str(&std::fs::read_to_string(config_path(&project)).unwrap()).unwrap();
    assert!(config["sandbox"].get("mode").is_none());
    assert_eq!(config["sandbox"]["allow-degraded"].as_bool(), Some(false));
}

#[test]
fn deleting_an_absent_config_key_is_a_true_no_op() {
    let project = TempProject::empty(r#"{"name":"config-delete-noop","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args(["--json", "config", "delete", "missing"])
        .output()
        .expect("failed to delete absent config key");
    assert!(output.status.success());
    let envelope: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(envelope["existed"], serde_json::json!(false));
    assert!(!config_path(&project).exists());
}

#[test]
fn config_list_rejects_every_malformed_known_scalar() {
    let cases = [
        ("signatures = \"sometimes\"\n", "signatures"),
        ("trust-policy = \"warn\"\n", "trust-policy"),
        ("typosquat-guard = \"maybe\"\n", "typosquat-guard"),
        ("engine-strict = \"maybe\"\n", "engine-strict"),
        (
            "strict-peer-dependencies = \"maybe\"\n",
            "strict-peer-dependencies",
        ),
        ("auto-install-peers = \"maybe\"\n", "auto-install-peers"),
        ("audit-after-install = \"maybe\"\n", "audit-after-install"),
        ("triage-advisor = 42\n", "triage-advisor"),
    ];

    for (content, key) in cases {
        let project = TempProject::empty(r#"{"name":"config-invalid","version":"1.0.0"}"#);
        seed_config(&project, content);
        let output = lpm(&project)
            .args(["--json", "config", "list"])
            .output()
            .unwrap_or_else(|error| panic!("failed to list malformed {key}: {error}"));
        assert!(
            !output.status.success(),
            "malformed known key {key} must fail:\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
        let diagnostic = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            diagnostic.contains(key),
            "diagnostic must name {key}: {diagnostic}",
        );
    }
}

#[test]
fn sandbox_config_and_list_use_lpm_home_when_home_differs() {
    let project = TempProject::empty(r#"{"name":"config-lpm-home","version":"1.0.0"}"#);
    let other_home = project.path().join("other-home");
    std::fs::create_dir_all(&other_home).unwrap();

    let set = lpm(&project)
        .env("HOME", &other_home)
        .args(["config", "sandbox", "--set", "strict"])
        .output()
        .expect("failed to set sandbox under custom LPM_HOME");
    assert!(set.status.success());

    let list = lpm(&project)
        .env("HOME", &other_home)
        .args(["--json", "config", "list"])
        .output()
        .expect("failed to list sandbox under custom LPM_HOME");
    assert!(list.status.success());
    let envelope: serde_json::Value = serde_json::from_slice(&list.stdout).unwrap();
    let sandbox = envelope["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["key"] == "sandbox.mode")
        .expect("sandbox.mode entry");
    assert_eq!(sandbox["value"], serde_json::json!("strict"));
    assert_eq!(
        sandbox["source"],
        serde_json::json!("$LPM_HOME/config.toml")
    );
}

#[test]
fn managed_release_age_policy_rejects_a_new_user_wide_exclusion() {
    let project = TempProject::empty(r#"{"name":"config-managed-exclude","version":"1.0.0"}"#);
    let policy_path = project.home().join(".lpm/security-policy.toml");
    std::fs::create_dir_all(policy_path.parent().unwrap()).unwrap();
    std::fs::write(&policy_path, "minimum-release-age-secs = 259200\n").unwrap();

    let output = lpm(&project)
        .args(["--json", "config", "release-age-exclude", "add", "react"])
        .output()
        .expect("failed to attempt managed release-age exclusion");
    assert!(!output.status.success());
    let diagnostic = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        diagnostic.contains("managed security policy"),
        "managed-policy diagnostic missing: {diagnostic}",
    );
    assert!(!config_path(&project).exists());
}

#[test]
fn unapproved_user_wide_release_age_exclusion_requires_explicit_approval() {
    let project = TempProject::empty(r#"{"name":"config-unapproved-exclude","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args(["--json", "config", "release-age-exclude", "add", "react"])
        .output()
        .expect("failed to attempt unapproved release-age exclusion");

    assert!(!output.status.success());
    let envelope: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(envelope["error_code"], "security_approval_required");
    assert_eq!(
        envelope["error"]["requested_scopes"],
        serde_json::json!(["cooldown-bypass"])
    );
    assert!(!config_path(&project).exists());
}

#[test]
fn config_output_redacts_secret_values_except_for_explicit_get() {
    let project = TempProject::empty(r#"{"name":"config-redaction","version":"1.0.0"}"#);

    let set = lpm(&project)
        .args(["--json", "config", "set", "api-token", "super-secret"])
        .output()
        .expect("failed to set secret-like config key");
    assert!(set.status.success());
    let envelope: serde_json::Value = serde_json::from_slice(&set.stdout).unwrap();
    assert_eq!(envelope["value"], serde_json::json!("[REDACTED]"));
    assert!(!String::from_utf8_lossy(&set.stdout).contains("super-secret"));

    let list = lpm(&project)
        .args(["--json", "config", "list"])
        .output()
        .expect("failed to list secret-like config key");
    assert!(list.status.success());
    assert!(!String::from_utf8_lossy(&list.stdout).contains("super-secret"));

    let get = lpm(&project)
        .args(["--json", "config", "get", "api-token"])
        .output()
        .expect("failed to explicitly get secret-like config key");
    assert!(get.status.success());
    let envelope: serde_json::Value = serde_json::from_slice(&get.stdout).unwrap();
    assert_eq!(envelope["value"], serde_json::json!("super-secret"));
}

#[cfg(unix)]
#[test]
fn config_mutation_creates_an_owner_only_config_file() {
    use std::os::unix::fs::PermissionsExt as _;

    let project = TempProject::empty(r#"{"name":"config-mode","version":"1.0.0"}"#);
    let output = lpm(&project)
        .args(["config", "set", "color", "always"])
        .output()
        .expect("failed to create config file");
    assert!(output.status.success());

    let mode = std::fs::metadata(config_path(&project))
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o600);
}
