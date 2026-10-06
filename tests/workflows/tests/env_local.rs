#![cfg(debug_assertions)]

//! Workflow tests for the local-only `lpm env *` surfaces.
//!
//! `env_vault.rs` covers the cloud-sync surfaces (pair / push / pull /
//! OIDC) that require a vault server mock. This file covers the
//! purely-local surfaces — set / get / list / delete / import / export /
//! print / copy / diff / validate / check / init / ls — which act on
//! files in the project directory and `lpm_vault`'s local store.

mod support;

use support::{TempProject, lpm};

#[test]
fn env_init_imports_colon_aliases_with_portable_file_suffixes() {
    let project = TempProject::empty(r#"{"name":"colon-env-init"}"#);
    project.write_file("lpm.json", r#"{"env":{"test:unit":".env.test"}}"#);
    project.write_file(".env.test", "COLON_VALUE=imported\n");
    let output = lpm(&project)
        .args(["env", "init", "--json"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let value = parse_json_stdout(&output, "colon alias initialization");
    assert_eq!(value["skipped"], serde_json::json!([]));
    let imported = lpm(&project)
        .args(["env", "get", "COLON_VALUE", "--env=test:unit", "--reveal"])
        .output()
        .unwrap();
    assert!(imported.status.success());
    assert!(String::from_utf8_lossy(&imported.stdout).contains("imported"));
}

#[test]
fn env_init_skipped_inheritance_diagnostics_identify_the_invalid_parent() {
    let project = TempProject::empty(r#"{"name":"invalid-parent-init"}"#);
    project.write_file("lpm.json", r#"{"environments":{"b":{"extends":"c:d"}}}"#);
    let output = lpm(&project)
        .args(["env", "init", "--json"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let value = parse_json_stdout(&output, "invalid parent initialization");
    assert!(
        value["skipped"][0]["error"]
            .as_str()
            .unwrap()
            .contains("parent \"c:d\"")
    );
}

#[test]
fn env_init_imports_custom_path_environment_mappings() {
    let project = TempProject::empty(r#"{"name":"custom-env-init"}"#);
    project.write_file("lpm.json", r#"{"env":{"unit":"config/unit.env"}}"#);
    project.write_file("config/unit.env", "CUSTOM_PATH_VALUE=fixture\n");
    lpm(&project)
        .args(["env", "init", "--json"])
        .assert()
        .success();
    let output = lpm(&project)
        .args(["env", "get", "CUSTOM_PATH_VALUE", "--env=unit", "--reveal"])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("fixture"));
}

#[test]
fn env_init_skips_invalid_aliases_and_imports_valid_environments() {
    let project = TempProject::empty(r#"{"name":"mixed-env-init"}"#);
    project.write_file(
        "lpm.json",
        r#"{"env":{"test:unit":"config/bad.env","unit":"config/unit.env"}}"#,
    );
    project.write_file("config/bad.env", "VALUE=invalid-alias\n");
    project.write_file("config/unit.env", "VALUE=valid-alias\n");
    let output = lpm(&project)
        .args(["env", "init", "--json"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    let value = parse_json_stdout(&output, "mixed env initialization");
    insta::assert_json_snapshot!("env_init_skips_invalid_aliases", value);
    assert_eq!(value["skipped"][0]["alias"], "test:unit");
    assert!(
        value["skipped"][0]["error"]
            .as_str()
            .unwrap()
            .contains("portable alias")
    );
    let value = lpm(&project)
        .args(["env", "get", "VALUE", "--env=unit", "--reveal"])
        .output()
        .unwrap();
    assert!(value.status.success());
    assert!(String::from_utf8_lossy(&value.stdout).contains("valid-alias"));
    let invalid = lpm(&project)
        .args(["env", "get", "VALUE", "--env=test:unit", "--reveal"])
        .output()
        .unwrap();
    assert!(!invalid.status.success());
}

#[test]
fn env_ls_invalid_alias_errors_include_context_and_readable_human_separators() {
    let project = TempProject::empty(r#"{"name":"alias-status"}"#);
    project.write_file(
        "lpm.json",
        r#"{"env":{"test:unit":"config/unit.env"},"envSchema":{"vars":{"VALUE":{}}}}"#,
    );
    let output = lpm(&project)
        .args(["env", "ls", "--json"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let value = parse_json_stdout(&output, "alias status");
    let row = value["environments"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["environment"] == "test:unit")
        .unwrap();
    let error = row["schemaError"].as_str().unwrap();
    assert!(error.contains("environment alias"), "{error}");
    assert!(error.contains("tasks.<name>.env"), "{error}");
    let output = lpm(&project).args(["env", "ls"]).output().unwrap();
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(!text.contains("failed:?"), "{text}");
    assert!(text.contains("portable alias"), "{text}");
}

#[test]
fn invalid_custom_path_alias_errors_name_the_alias_and_remedy() {
    let project = TempProject::empty(r#"{"name":"invalid-env-alias"}"#);
    project.write_file(
        "lpm.json",
        r#"{"env":{"test:unit":"config/unit.env"},"envSchema":{"vars":{"VALUE":{}}}}"#,
    );
    for args in [
        vec!["env", "check", "--json"],
        vec!["env", "print", "--env=test:unit"],
    ] {
        let output = lpm(&project).args(args).output().unwrap();
        assert!(!output.status.success());
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(text.contains("test:unit"), "{text}");
        assert!(text.contains("portable alias"), "{text}");
        assert!(!text.contains("invalid envSchema rule"), "{text}");
    }
}

#[test]
fn configured_services_reject_unknown_schema_selectors() {
    for field in ["requiredIn", "defaultsIn"] {
        let project = TempProject::empty(r#"{"name":"service-selectors"}"#);
        let selector = serde_json::json!({"service":["apii"]});
        let rule = if field == "requiredIn" {
            serde_json::json!({field:[selector]})
        } else {
            serde_json::json!({field:[{"when":selector,"value":"fixture"}]})
        };
        project.write_file("lpm.json", &serde_json::json!({"services":{"api":{"command":"echo api"}},"envSchema":{"vars":{"VALUE":rule}}}).to_string());
        let output = lpm(&project)
            .args(["env", "check", "--service=api", "--json"])
            .output()
            .unwrap();
        assert!(!output.status.success(), "unconfigured {field} accepted");
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(text.contains("apii") && text.contains(field), "{text}");
    }
}

#[test]
fn env_assignment_errors_do_not_print_secret_values() {
    let project = TempProject::empty(r#"{"name":"env-private-errors"}"#);
    for assignment in ["BAD-NAME=private-fixture-value", "private-fixture-value"] {
        let output = lpm(&project)
            .args(["env", "set", assignment, "--json"])
            .output()
            .unwrap();
        assert!(!output.status.success());
        for bytes in [&output.stdout, &output.stderr] {
            assert!(
                !String::from_utf8_lossy(bytes).contains("private-fixture-value"),
                "assignment error exposed its value"
            );
        }
        assert!(!project.path().join("lpm.json").exists());
    }
}

#[test]
fn env_set_rejects_partial_assignments_before_writing_the_vault() {
    let project = TempProject::empty(r#"{"name":"env-assignment-validation"}"#);
    let output = lpm(&project)
        .args(["env", "set", "GOOD=fixture-only", "NOT_AN_ASSIGNMENT"])
        .output()
        .unwrap();
    assert!(!output.status.success(), "malformed assignments must fail");
    assert!(!project.path().join("lpm.json").exists());
}

#[test]
fn env_local_arguments_reject_unknown_flags_and_extra_operands() {
    let cases: &[&[&str]] = &[
        &["list", "--unknown"],
        &["get", "GOOD", "EXTRA", "--reveal"],
        &["print", "--en=staging"],
        &["print", "--env"],
        &["print", "--format"],
        &["print", "--env="],
        &["list", "--env=staging", "--env=default"],
        &["import", ".env", "extra.env"],
        &["export", "out.env", "extra.env"],
        &["init", "--unknown"],
        &["ls", "--env=staging"],
        &["check", "--stage=unknown"],
        &["validate", "--unknown"],
        &["example", "--unknown"],
        &["copy", "default", "staging", "production"],
    ];
    let mut accepted = Vec::new();
    for args in cases {
        let project = TempProject::empty(r#"{"name":"env-argument-validation"}"#);
        project.write_file(".env", "GOOD=fixture-only\n");
        project.write_file(".env.example", "GOOD=\n");
        project.write_file("lpm.json", r#"{"envSchema":{"vars":{"GOOD":{}}}}"#);
        lpm(&project)
            .args(["env", "set", "GOOD=fixture-only"])
            .assert()
            .success();
        let output = lpm(&project).arg("env").args(*args).output().unwrap();
        if output.status.success() {
            accepted.push(args.join(" "));
        }
    }
    assert!(
        accepted.is_empty(),
        "accepted invalid arguments: {accepted:?}"
    );
}

#[test]
fn env_trailing_json_applies_to_success_and_error_output() {
    let project = TempProject::empty(r#"{"name":"env-trailing-json"}"#);
    lpm(&project)
        .args(["env", "set", "GOOD=fixture-only"])
        .assert()
        .success();
    let output = lpm(&project)
        .args(["env", "list", "--json"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let value = parse_json_stdout(&output, "env list --json");
    insta::assert_json_snapshot!(value, @r###"
    {
      "GOOD": "••••••••"
    }
    "###);
    let error = lpm(&project)
        .args(["env", "get", "MISSING", "--json"])
        .output()
        .unwrap();
    assert!(!error.status.success());
    assert_eq!(
        parse_json_stdout(&error, "env get --json")["success"],
        false
    );
}

#[test]
fn env_json_print_and_ci_export_report_the_resolved_environment() {
    let project = TempProject::empty(r#"{"name":"env-json-outputs"}"#);
    project.write_file(".env", "VALUE=fixture-only\n");
    let printed = lpm(&project)
        .args(["env", "print", "--json"])
        .output()
        .unwrap();
    assert!(printed.status.success());
    insta::assert_json_snapshot!(parse_json_stdout(&printed, "env print --json"), @r###"
    {
      "VALUE": "fixture-only"
    }
    "###);
    let exported = lpm(&project)
        .args(["env", "export", "--ci", "ci.env", "--json"])
        .output()
        .unwrap();
    assert!(exported.status.success());
    insta::assert_json_snapshot!(parse_json_stdout(&exported, "env export --ci --json"), @r###"
    {
      "success": true,
      "exported": 1,
      "to": "ci.env",
      "env": "default"
    }
    "###);
    assert_eq!(project.read_file("ci.env"), "VALUE=fixture-only");
}

#[test]
fn env_dispatch_does_not_treat_a_global_flag_value_as_the_command() {
    let project = TempProject::empty(r#"{"name":"env-token-value"}"#);
    let output = lpm(&project)
        .args(["--token", "env", "--json", "env", "list"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert_eq!(
        parse_json_stdout(&output, "env list"),
        serde_json::json!({})
    );
}

#[test]
fn bare_env_validates_project_configuration_before_listing_secrets() {
    let project = TempProject::empty(r#"{"name":"env-bare-config"}"#);
    project.write_file("lpm.json", "{not json");
    let output = lpm(&project).args(["--json", "env"]).output().unwrap();
    assert!(!output.status.success());
    assert_eq!(parse_json_stdout(&output, "bare env")["success"], false);
}

#[cfg(unix)]
#[test]
fn env_ci_export_never_changes_a_linked_destination() {
    let project = TempProject::empty(r#"{"name":"env-ci-export-link"}"#);
    project.write_file(".env", "VALUE=fixture-only\n");
    project.write_file("sentinel.txt", "original");
    std::os::unix::fs::symlink("sentinel.txt", project.path().join("ci.env")).unwrap();
    let output = lpm(&project)
        .args(["env", "export", "--ci", "ci.env"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "export must atomically replace the link"
    );
    assert_eq!(project.read_file("sentinel.txt"), "original");
}

#[cfg(unix)]
#[test]
fn env_example_never_changes_a_linked_destination() {
    let project = TempProject::empty(r#"{"name":"env-example-link"}"#);
    project.write_file(
        "lpm.json",
        r#"{"envSchema":{"vars":{"VALUE":{"default":"fixture-only"}}}}"#,
    );
    project.write_file("sentinel.txt", "original");
    std::os::unix::fs::symlink("sentinel.txt", project.path().join(".env.example")).unwrap();
    let output = lpm(&project).args(["env", "example"]).output().unwrap();
    assert!(
        output.status.success(),
        "export must atomically replace the link"
    );
    assert_eq!(project.read_file("sentinel.txt"), "original");
}

#[test]
fn env_export_round_trips_multiline_values_through_project_loading() {
    let project = TempProject::empty(r#"{"name":"env-export-round-trip"}"#);
    let consumer = TempProject::empty(r#"{"name":"env-export-consumer"}"#);
    let value = "first \\\"quote\\\" \\path\nsecond $literal #hash\tend";
    lpm(&project)
        .args(["env", "set", &format!("VALUE={value}")])
        .assert()
        .success();
    lpm(&project)
        .args(["env", "export", "export.env"])
        .assert()
        .success();
    consumer.write_file(".env", &project.read_file("export.env"));
    let output = lpm(&consumer)
        .args(["env", "print", "--format=json"])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_eq!(parse_json_stdout(&output, "round trip")["VALUE"], value);
}

#[test]
fn env_example_keeps_multiline_metadata_and_defaults_in_one_variable() {
    let project = TempProject::empty(r#"{"name":"env-example-escaping"}"#);
    let consumer = TempProject::empty(r#"{"name":"env-example-consumer"}"#);
    let value = "first\nINJECTED=from-default\nlast \\\"quote\\\"";
    project.write_file(
        "lpm.json",
        &serde_json::json!({"envSchema":{"vars":{"VALUE":{
            "description":"description\nINJECTED_COMMENT=from-comment", "default":value
        }}}})
        .to_string(),
    );
    lpm(&project).args(["env", "example"]).assert().success();
    consumer.write_file(".env", &project.read_file(".env.example"));
    let output = lpm(&consumer)
        .args(["env", "print", "--format=json"])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_eq!(
        parse_json_stdout(&output, "example round trip"),
        serde_json::json!({"VALUE":value})
    );
}

#[test]
fn env_print_rejects_missing_schema_and_conflicting_formats() {
    let project = TempProject::empty(r#"{"name":"env-print-controls"}"#);
    project.write_file(".env", "UNDECLARED=fixture-only\n");
    for args in [
        vec!["--schema-only"],
        vec!["--ci", "--format=json"],
        vec!["--ci", "--schema-only"],
    ] {
        let output = lpm(&project)
            .args(["env", "print"])
            .args(&args)
            .output()
            .unwrap();
        assert!(
            !output.status.success(),
            "accepted unsupported print controls: {args:?}"
        );
        assert!(!String::from_utf8_lossy(&output.stdout).contains("fixture-only"));
    }
}

#[cfg(unix)]
#[test]
fn env_github_output_runs_as_shell_and_masks_multiline_secrets() {
    let project = TempProject::empty(r#"{"name":"env-github-format"}"#);
    let value = "first%0A;$(touch injected-marker)\nsecond'\\tail";
    project.write_file(
        "lpm.json",
        &serde_json::json!({"envSchema":{"vars":{"VALUE":{
            "secret":true
        }}}})
        .to_string(),
    );
    lpm(&project)
        .args(["env", "set", &format!("VALUE={value}")])
        .assert()
        .success();
    let output = lpm(&project)
        .args(["env", "print", "--format=github-actions"])
        .output()
        .unwrap();
    assert!(output.status.success());
    project.write_file("apply.sh", &String::from_utf8(output.stdout).unwrap());
    let applied = std::process::Command::new("sh")
        .args(["-eu", "apply.sh"])
        .current_dir(project.path())
        .env("GITHUB_ENV", project.path().join("github.env"))
        .output()
        .unwrap();
    assert!(
        applied.status.success(),
        "{}",
        String::from_utf8_lossy(&applied.stderr)
    );
    let log = String::from_utf8(applied.stdout).unwrap();
    assert!(
        log.contains("::add-mask::first%250A;$(touch injected-marker)%0Asecond'\\tail"),
        "{log}"
    );
    assert!(project.read_file("github.env").contains(value));
    assert!(!project.path().join("injected-marker").exists());
}

#[test]
fn env_list_and_validate_fail_closed_on_malformed_lpm_json() {
    let project = TempProject::empty(r#"{"name":"env-config-matrix","version":"1.0.0"}"#);
    project.write_file("lpm.json", "{ not valid json");

    let list = lpm(&project)
        .args(["--json", "env", "list"])
        .output()
        .expect("run env list with malformed config");
    assert!(
        !list.status.success(),
        "env list must fail closed because aliases and inheritance can change its result:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&list.stdout),
        String::from_utf8_lossy(&list.stderr)
    );
    assert_eq!(
        serde_json::Deserializer::from_slice(&list.stdout)
            .into_iter::<serde_json::Value>()
            .count(),
        1,
        "JSON mode must emit exactly one document"
    );

    let validate = lpm(&project)
        .args(["--json", "env", "validate"])
        .output()
        .expect("run config-dependent env validate");
    assert!(!validate.status.success());
    assert_eq!(
        serde_json::Deserializer::from_slice(&validate.stdout)
            .into_iter::<serde_json::Value>()
            .count(),
        1,
        "JSON mode must emit exactly one document"
    );
}

fn write_dotenv(project: &TempProject, file: &str, content: &str) {
    project.write_file(file, content);
}

fn strip_ansi(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '\u{1b}' && chars.peek() == Some(&'[') {
            chars.next();
            for code in chars.by_ref() {
                if code.is_ascii_alphabetic() {
                    break;
                }
            }
        } else {
            out.push(ch);
        }
    }
    out
}

fn parse_json_stdout(output: &std::process::Output, command: &str) -> serde_json::Value {
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "{command} must emit exactly one JSON document: {error}\nstdout:\n{}",
            String::from_utf8_lossy(&output.stdout),
        )
    })
}

// ─── set / get / list / delete ────────────────────────────────────────

#[test]
fn env_set_persists_key_value_and_get_reveals_it() {
    let project = TempProject::empty(r#"{"name":"env-set","version":"1.0.0"}"#);

    let set = lpm(&project)
        .args(["env", "set", "FOO=bar"])
        .output()
        .expect("failed to run lpm env set");
    assert!(
        set.status.success(),
        "env set failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&set.stdout),
        String::from_utf8_lossy(&set.stderr),
    );

    let get = lpm(&project)
        .args(["env", "get", "FOO", "--reveal"])
        .output()
        .expect("failed to run lpm env get");
    assert!(get.status.success(), "env get failed");
    let stdout = String::from_utf8_lossy(&get.stdout);
    assert!(
        stdout.contains("bar"),
        "env get --reveal must surface the stored value, got:\n{stdout}",
    );
}

#[test]
fn env_get_without_reveal_masks_the_value() {
    let project = TempProject::empty(r#"{"name":"env","version":"1.0.0"}"#);

    lpm(&project)
        .args(["env", "set", "SECRET=swordfish"])
        .assert()
        .success();

    let out = lpm(&project)
        .args(["env", "get", "SECRET"])
        .output()
        .expect("failed to run lpm env get");
    assert!(out.status.success());

    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        !stdout.contains("swordfish"),
        "default env get must MASK the value (no --reveal), got:\n{stdout}",
    );
    assert!(
        stdout.contains("•"),
        "masked output must use dots, got:\n{stdout}",
    );
}

#[test]
fn env_delete_removes_key() {
    let project = TempProject::empty(r#"{"name":"env","version":"1.0.0"}"#);

    lpm(&project)
        .args(["env", "set", "GONE=value"])
        .assert()
        .success();
    lpm(&project)
        .args(["env", "delete", "GONE"])
        .assert()
        .success();

    let out = lpm(&project)
        .args(["env", "get", "GONE", "--reveal"])
        .output()
        .expect("failed to run lpm env get");
    assert!(
        !out.status.success(),
        "get after delete must exit non-zero (key gone)"
    );

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("not found"),
        "stderr must say not found, got:\n{stderr}",
    );
}

#[test]
fn env_list_json_envelope_carries_keys() {
    let project = TempProject::empty(r#"{"name":"env","version":"1.0.0"}"#);

    lpm(&project)
        .args(["env", "set", "A=1", "B=2", "C=3"])
        .assert()
        .success();

    let out = lpm(&project)
        .args(["--json", "env", "list"])
        .output()
        .expect("failed to run lpm env list --json");
    assert!(out.status.success(), "env list --json failed");

    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let envelope: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("env list --json must be valid JSON: {e}\n---\n{stdout}"));

    // Schema: a flat JSON object with key → masked-value or array.
    // Strict shape varies per implementation; at minimum, the three keys
    // we set must appear somewhere in the envelope.
    let s = envelope.to_string();
    for key in ["A", "B", "C"] {
        assert!(
            s.contains(key),
            "env list --json must mention key {key}, got:\n{envelope}",
        );
    }

    insta::with_settings!({
        sort_maps => true,
        filters => vec![
            (r#"/var/folders/[^"\s]+"#, "[TEMP]"),
            (r#"/private/var/folders/[^"\s]+"#, "[TEMP]"),
            (r#"/tmp/[^"\s]+"#, "[TEMP]"),
        ],
    }, {
        insta::assert_json_snapshot!("env_list_json_envelope_three_keys", envelope);
    });
}

#[test]
fn env_ls_human_renders_sync_columns_and_active_environment_footer() {
    let project = TempProject::empty(r#"{"name":"env-ls","version":"1.0.0"}"#);
    project.write_file(
        "lpm.json",
        r#"{
  "vault": "vault-123",
  "vaultSync": {
    "personalVersion": 7,
    "personalSyncedAt": "2026-05-31T08:00:00Z"
  },
  "environments": {
    "production": ".env.production"
  }
}"#,
    );

    lpm(&project)
        .args(["env", "set", "API_URL=https://dev.example"])
        .assert()
        .success();
    lpm(&project)
        .args([
            "env",
            "set",
            "--env=production",
            "API_URL=https://prod.example",
        ])
        .assert()
        .success();

    let manifest_read_log = project.path().join("env-ls-manifest-reads.log");
    let out = lpm(&project)
        .env("LPM_TEST_MANIFEST_READ_LOG", &manifest_read_log)
        .args(["env", "ls"])
        .output()
        .expect("failed to run lpm env ls");
    assert!(
        out.status.success(),
        "env ls failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    let stdout = strip_ansi(&String::from_utf8_lossy(&out.stdout));

    assert!(
        stdout.contains("Environment"),
        "env ls should render the Environment column, got:\n{stdout}",
    );
    assert!(
        stdout.contains("Variables"),
        "env ls should render the Variables column, got:\n{stdout}",
    );
    assert!(
        stdout.contains("Synced"),
        "env ls should render the Synced column, got:\n{stdout}",
    );
    assert!(
        stdout.contains("Updated"),
        "env ls should render the Updated column, got:\n{stdout}",
    );
    assert!(
        !stdout.contains("Required") && !stdout.contains("Alias"),
        "env ls should use the slim sync columns, got:\n{stdout}",
    );
    assert!(
        !stdout.contains("---"),
        "env ls should not render the old dashed separator, got:\n{stdout}",
    );
    assert!(stdout.contains("default"));
    assert!(stdout.contains("production"));
    assert!(stdout.contains("yes"));
    assert!(stdout.contains("2026-05-31T08:00:00Z"));
    assert!(stdout.contains("Active environment: default"));
    assert!(stdout.contains("Use lpm env list --env <name> to inspect secrets."));
    assert_eq!(
        std::fs::read_to_string(manifest_read_log)
            .expect("read env-ls manifest access log")
            .lines()
            .count(),
        1,
        "env ls needs one validated manifest snapshot",
    );

    let json_out = lpm(&project)
        .args(["--json", "env", "ls"])
        .output()
        .expect("failed to run lpm env ls --json");
    assert!(json_out.status.success(), "env ls --json failed");
    let json_stdout = String::from_utf8_lossy(&json_out.stdout);
    let envelope: serde_json::Value = serde_json::from_str(&json_stdout)
        .unwrap_or_else(|e| panic!("env ls --json must be valid JSON: {e}\n---\n{json_stdout}"));
    let row = envelope["environments"]
        .as_array()
        .and_then(|rows| rows.first())
        .expect("env ls --json must include at least one environment");
    assert!(
        row.get("synced").is_none() && row.get("updated").is_none(),
        "env ls --json contract should not grow sync-only human fields: {envelope}",
    );
}

// ─── set with usage error ─────────────────────────────────────────────

#[test]
fn env_set_without_pairs_fails_with_usage_message() {
    let project = TempProject::empty(r#"{"name":"env","version":"1.0.0"}"#);

    let out = lpm(&project)
        .args(["env", "set"])
        .output()
        .expect("failed to run lpm env set (no args)");

    assert!(!out.status.success(), "env set with no pairs must fail");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("usage:") || stderr.contains("KEY=VALUE"),
        "stderr must show usage, got:\n{stderr}",
    );
}

// ─── multi-env (--env=staging) ─────────────────────────────────────────

#[test]
fn env_set_with_env_flag_scopes_to_named_environment() {
    let project = TempProject::empty(
        r#"{"name":"env-multi","version":"1.0.0","lpm":{"environments":{"staging":{}}}}"#,
    );

    // Set differently scoped values; default scope vs staging scope must
    // be independent.
    lpm(&project)
        .args(["env", "set", "API_URL=default-url"])
        .assert()
        .success();
    lpm(&project)
        .args(["env", "set", "--env=staging", "API_URL=staging-url"])
        .assert()
        .success();

    let default_val = lpm(&project)
        .args(["env", "get", "API_URL", "--reveal"])
        .output()
        .expect("get default");
    let staging_val = lpm(&project)
        .args(["env", "get", "--env=staging", "API_URL", "--reveal"])
        .output()
        .expect("get staging");

    let d = String::from_utf8_lossy(&default_val.stdout);
    let s = String::from_utf8_lossy(&staging_val.stdout);
    assert!(
        d.contains("default-url"),
        "default scope must hold default-url, got:\n{d}"
    );
    assert!(
        s.contains("staging-url"),
        "staging scope must hold staging-url, got:\n{s}"
    );
}

#[test]
fn env_ls_treats_a_valid_unconfigured_environment_as_current_vault_state() {
    let project = TempProject::empty(r#"{"name":"env-custom","version":"1.0.0"}"#);

    lpm(&project)
        .args(["env", "set", "--env=preview", "API_URL=preview-url"])
        .assert()
        .success();

    let human = lpm(&project)
        .args(["env", "ls"])
        .output()
        .expect("list custom environment");
    assert!(human.status.success());
    let human_stdout = String::from_utf8_lossy(&human.stdout);
    assert!(human_stdout.contains("preview"));
    assert!(!human_stdout.to_ascii_lowercase().contains("legacy"));

    let json = lpm(&project)
        .args(["--json", "env", "ls"])
        .output()
        .expect("list custom environment as JSON");
    assert!(json.status.success());
    let envelope: serde_json::Value =
        serde_json::from_slice(&json.stdout).expect("env ls JSON must be one document");
    let preview = envelope["environments"]
        .as_array()
        .and_then(|rows| rows.iter().find(|row| row["environment"] == "preview"))
        .expect("custom environment must be present");
    assert_eq!(preview["source"], "Vault");
}

// ─── init (explicit `lpm env init` action) ─────────────────────────────

#[test]
fn env_init_under_json_emits_envelope_with_environments_and_results_arrays() {
    let project = TempProject::empty(r#"{"name":"env-init-test","version":"1.0.0"}"#);

    let out = lpm(&project)
        .args(["--json", "env", "init"])
        .output()
        .expect("failed to run lpm env init --json");
    assert!(
        out.status.success(),
        "env init --json failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    let envelope: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
        panic!(
            "env init --json stdout must be valid JSON: {e}\n---\n{}",
            String::from_utf8_lossy(&out.stdout)
        )
    });
    assert_eq!(envelope["success"], serde_json::json!(true));
    assert!(
        envelope["environments"].is_array(),
        "env init envelope must carry an environments[] array, got: {envelope}",
    );
    assert!(
        envelope["actions"].is_array(),
        "env init envelope must carry an actions[] array, got: {envelope}",
    );
}

#[test]
fn env_init_configured_alias_and_path_cannot_inject_terminal_rows() {
    let project = TempProject::empty(r#"{"name":"env-init-test","version":"1.0.0"}"#);
    let hostile = "safe\nFORGED\rrewritten\u{8}\u{1b}]52;c;AAAA\u{7}\u{0090}hidden\u{009c}end";
    let env = serde_json::Map::from_iter([(
        hostile.to_owned(),
        serde_json::Value::String(".env.safe".to_owned()),
    )]);
    project.write_file("lpm.json", &serde_json::json!({ "env": env }).to_string());

    let output = lpm(&project)
        .args(["env", "init"])
        .output()
        .expect("failed to run lpm env init");

    assert!(output.status.success(), "env init failed: {output:?}");
    let rendered = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    assert!(
        rendered.contains("safe?FORGED?rewritten?end"),
        "hostile env fields must remain visible as one sanitized field: {rendered:?}",
    );
    for attacker_fragment in [
        "\u{1b}", "\u{7}", "\u{8}", "\r", "\u{007f}", "\u{0090}", "\u{009c}", "hidden",
    ] {
        assert!(
            !rendered.contains(attacker_fragment),
            "env init output retained {attacker_fragment:?}: {rendered:?}",
        );
    }
}

#[test]
fn env_init_skips_an_invalid_configured_environment_without_mutating_the_manifest() {
    let project = TempProject::empty(r#"{"name":"env-init-invalid","version":"1.0.0"}"#);
    let manifest = serde_json::json!({
        "env": {
            "dev": ".env.invalid\nname"
        }
    })
    .to_string();
    project.write_file("lpm.json", &manifest);

    let output = lpm(&project)
        .args(["--json", "env", "init"])
        .output()
        .expect("failed to run lpm env init");

    assert!(output.status.success(), "invalid env entry must be skipped");
    let value = parse_json_stdout(&output, "invalid init identity");
    assert_eq!(value["skipped"].as_array().unwrap().len(), 1);
    assert_eq!(project.read_file("lpm.json"), manifest);
}

// ─── pair / unpair (auth-error envelope path only) ─────────────────────

/// `lpm env pair` requires a session-backed login. On an isolated HOME
/// with no credentials, the command fails before reaching the registry —
/// under `--json` that failure must emit a parseable error envelope on
/// stdout, not a free-form stderr message. Happy-path pairing requires
/// a vault server mock (see `env_vault.rs`); this test pins only the
/// auth-required error envelope shape, the cheapest contract that proves
/// `lpm --json env pair` is machine-readable.
#[test]
fn env_pair_without_auth_under_json_emits_error_envelope_on_stdout() {
    let project = TempProject::empty(r#"{"name":"env-pair-auth","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args(["--json", "env", "pair", "ABC123"])
        .output()
        .expect("failed to run lpm --json env pair");

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let envelope: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap_or_else(|e| {
        panic!("--json env pair error path must emit JSON: {e}\n---\n{stdout}")
    });
    assert_eq!(envelope["success"], serde_json::json!(false));
    let err = envelope["error"].as_str().unwrap_or_default();
    assert!(
        err.contains("login") || err.contains("session"),
        "error must reference auth/login state, got: {err}"
    );
}

/// `lpm env unpair` shares the auth-required contract with `pair`. Same
/// envelope shape expected on the unauthenticated error path.
#[test]
fn env_unpair_without_auth_under_json_emits_error_envelope_on_stdout() {
    let project = TempProject::empty(r#"{"name":"env-unpair-auth","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args(["--json", "env", "unpair"])
        .output()
        .expect("failed to run lpm --json env unpair");

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let envelope: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap_or_else(|e| {
        panic!("--json env unpair error path must emit JSON: {e}\n---\n{stdout}")
    });
    assert_eq!(envelope["success"], serde_json::json!(false));
    let err = envelope["error"].as_str().unwrap_or_default();
    assert!(
        err.contains("login") || err.contains("session"),
        "error must reference auth/login state, got: {err}"
    );
}

// ─── import / export ──────────────────────────────────────────────────

#[test]
fn env_import_from_dotenv_file_populates_vault() {
    let project = TempProject::empty(r#"{"name":"env","version":"1.0.0"}"#);

    write_dotenv(
        &project,
        ".env",
        "DATABASE_URL=postgres://localhost/dev\nDEBUG=true\n",
    );

    let out = lpm(&project)
        .args(["--json", "env", "import", ".env"])
        .output()
        .expect("failed to run lpm env import");
    assert!(
        out.status.success(),
        "env import failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );

    let envelope: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
        panic!(
            "env import --json stdout must be valid JSON: {e}\n---\n{}",
            String::from_utf8_lossy(&out.stdout)
        )
    });
    assert_eq!(envelope["success"], serde_json::json!(true));
    assert_eq!(envelope["imported"], serde_json::json!(2));

    let get = lpm(&project)
        .args(["env", "get", "DATABASE_URL", "--reveal"])
        .output()
        .expect("get after import");
    assert!(get.status.success());
    let value = String::from_utf8_lossy(&get.stdout);
    assert!(
        value.contains("postgres://localhost/dev"),
        "imported value must be retrievable, got:\n{value}",
    );
}

#[test]
fn env_export_writes_dotenv_with_all_keys() {
    let project = TempProject::empty(r#"{"name":"env","version":"1.0.0"}"#);

    lpm(&project)
        .args(["env", "set", "FOO=foo-value"])
        .assert()
        .success();
    lpm(&project)
        .args(["env", "set", "BAR=bar-value"])
        .assert()
        .success();

    let export_path = project.path().join("exported.env");
    let out = lpm(&project)
        .args(["--json", "env", "export", export_path.to_str().unwrap()])
        .output()
        .expect("failed to run lpm env export");
    assert!(
        out.status.success(),
        "env export failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );

    let envelope: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
        panic!(
            "env export --json stdout must be valid JSON: {e}\n---\n{}",
            String::from_utf8_lossy(&out.stdout)
        )
    });
    assert_eq!(envelope["success"], serde_json::json!(true));
    assert_eq!(envelope["exported"], serde_json::json!(2));

    let content = std::fs::read_to_string(&export_path).expect("read exported.env");
    assert!(
        content.contains("FOO") && content.contains("foo-value"),
        "exported file must contain FOO, got:\n{content}",
    );
    assert!(
        content.contains("BAR") && content.contains("bar-value"),
        "exported file must contain BAR, got:\n{content}",
    );
}

// ─── print ─────────────────────────────────────────────────────────────

#[test]
fn env_print_streams_keys_to_stdout() {
    let project = TempProject::empty(r#"{"name":"env","version":"1.0.0"}"#);

    lpm(&project)
        .args(["env", "set", "X=x-value"])
        .assert()
        .success();

    let out = lpm(&project)
        .args(["env", "print"])
        .output()
        .expect("failed to run lpm env print");
    assert!(
        out.status.success(),
        "env print failed:\nstderr: {}",
        String::from_utf8_lossy(&out.stderr),
    );

    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("X"),
        "env print must include set keys, got:\n{stdout}",
    );
}

// ─── copy (environment → environment) ──────────────────────────────────

#[test]
fn env_copy_duplicates_environment_into_target() {
    let project = TempProject::empty(
        r#"{"name":"env-copy","version":"1.0.0","lpm":{"environments":{"src":{}, "dst":{}}}}"#,
    );

    lpm(&project)
        .args(["env", "set", "--env=src", "K1=v1", "K2=v2"])
        .assert()
        .success();

    let out = lpm(&project)
        .args(["--json", "env", "copy", "src", "dst"])
        .output()
        .expect("failed to run lpm env copy");
    assert!(
        out.status.success(),
        "env copy failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );

    let envelope: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
        panic!(
            "env copy --json stdout must be valid JSON: {e}\n---\n{}",
            String::from_utf8_lossy(&out.stdout)
        )
    });
    assert_eq!(envelope["success"], serde_json::json!(true));

    let get = lpm(&project)
        .args(["env", "get", "--env=dst", "K1", "--reveal"])
        .output()
        .expect("get after copy");
    assert!(get.status.success(), "key must exist in dst env after copy");
    let value = String::from_utf8_lossy(&get.stdout);
    assert!(
        value.contains("v1"),
        "copied value must be retrievable from dst, got:\n{value}",
    );
}

// ─── usage errors ──────────────────────────────────────────────────────

// ─── diff (local vs local) ─────────────────────────────────────────────

#[test]
fn env_diff_local_vs_local_reports_added_removed_and_changed_keys() {
    let project = TempProject::empty(
        r#"{"name":"env-diff","version":"1.0.0","lpm":{"environments":{"a":{},"b":{}}}}"#,
    );

    // env A has FOO=1, COMMON=same
    // env B has BAR=2, COMMON=same
    // diff a b → A-only: FOO; B-only: BAR; unchanged: COMMON
    lpm(&project)
        .args(["env", "set", "--env=a", "FOO=1", "COMMON=same"])
        .assert()
        .success();
    lpm(&project)
        .args(["env", "set", "--env=b", "BAR=2", "COMMON=same"])
        .assert()
        .success();

    let manifest_read_log = project.path().join("env-diff-manifest-reads.log");
    let output = lpm(&project)
        .env("LPM_TEST_MANIFEST_READ_LOG", &manifest_read_log)
        .args(["env", "diff", "a", "b"])
        .output()
        .expect("failed to run lpm env diff a b");

    assert!(
        output.status.success(),
        "env diff local-vs-local must succeed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    // Output must reference each side and the per-side keys.
    assert!(
        combined.contains("FOO") && combined.contains("BAR"),
        "diff must mention both A-only and B-only keys, got:\n{combined}",
    );
    assert_eq!(
        std::fs::read_to_string(manifest_read_log)
            .expect("read env-diff manifest access log")
            .lines()
            .count(),
        1,
        "local env diff needs one validated manifest snapshot",
    );
}

// ─── validate (vs .env.example) ────────────────────────────────────────

#[test]
fn env_validate_json_exits_nonzero_and_reports_missing_keys() {
    let project = TempProject::empty(r#"{"name":"env-validate","version":"1.0.0"}"#);

    write_dotenv(&project, ".env.example", "REQUIRED_ONE=\nREQUIRED_TWO=\n");
    lpm(&project)
        .args(["env", "set", "REQUIRED_ONE=value"])
        .assert()
        .success();

    let output = lpm(&project)
        .args(["--json", "env", "validate"])
        .output()
        .expect("failed to run lpm env validate --json");

    assert!(
        !output.status.success(),
        "env validate --json must fail when a required key is missing"
    );

    let envelope = parse_json_stdout(&output, "env validate --json");
    assert_eq!(envelope["success"], serde_json::json!(false));
    assert_eq!(envelope["valid"], serde_json::json!(false));
    assert_eq!(envelope["required"], serde_json::json!(2));
    let present = envelope["present"]
        .as_array()
        .expect("present must be array");
    let missing = envelope["missing"]
        .as_array()
        .expect("missing must be array");
    assert_eq!(present.len(), 1, "REQUIRED_ONE must be present: {envelope}");
    assert_eq!(missing.len(), 1, "REQUIRED_TWO must be missing: {envelope}");
    assert!(
        missing.iter().any(|k| k.as_str() == Some("REQUIRED_TWO")),
        "missing array must list REQUIRED_TWO: {envelope}"
    );
    insta::assert_json_snapshot!("env_validate_json_missing_required", envelope);
}

#[test]
fn env_validate_human_remediation_assigns_each_missing_key() {
    let project = TempProject::empty(r#"{"name":"env-validate","version":"1.0.0"}"#);
    write_dotenv(
        &project,
        ".env.example",
        "REQUIRED_ONE=\nREQUIRED_TWO=\nREQUIRED_THREE=\n",
    );
    lpm(&project)
        .args(["env", "set", "REQUIRED_ONE=value"])
        .assert()
        .success();

    let output = lpm(&project)
        .args(["env", "validate"])
        .output()
        .expect("failed to run lpm env validate");

    assert!(
        !output.status.success(),
        "env validate must fail when a required key is missing"
    );
    let stdout = strip_ansi(&String::from_utf8_lossy(&output.stdout));
    assert!(
        stdout.contains("lpm env set REQUIRED_TWO=... REQUIRED_THREE=..."),
        "human remediation must provide one KEY=VALUE operand per missing key:\n{stdout}"
    );
}

#[test]
fn env_validate_json_exits_zero_when_all_required_keys_are_present() {
    let project = TempProject::empty(r#"{"name":"env-validate","version":"1.0.0"}"#);
    write_dotenv(
        &project,
        ".env.example",
        "REQUIRED_ONE=ignored\nREQUIRED_TWO=\n",
    );
    lpm(&project)
        .args([
            "env",
            "set",
            "REQUIRED_ONE=actual-one",
            "REQUIRED_TWO=actual-two",
        ])
        .assert()
        .success();

    let output = lpm(&project)
        .args(["--json", "env", "validate"])
        .output()
        .expect("failed to run lpm env validate --json");

    assert!(
        output.status.success(),
        "env validate --json must succeed when all required keys are present"
    );
    let envelope = parse_json_stdout(&output, "env validate --json");
    assert_eq!(envelope["success"], serde_json::json!(true));
    assert_eq!(envelope["valid"], serde_json::json!(true));
    assert_eq!(
        envelope["present"],
        serde_json::json!(["REQUIRED_ONE", "REQUIRED_TWO"])
    );
    assert_eq!(envelope["missing"], serde_json::json!([]));
}

#[test]
fn env_validate_json_allows_extra_keys_without_strict() {
    let project = TempProject::empty(r#"{"name":"env-validate","version":"1.0.0"}"#);
    write_dotenv(&project, ".env.example", "REQUIRED=\n");
    lpm(&project)
        .args(["env", "set", "REQUIRED=value", "EXTRA=extra-value"])
        .assert()
        .success();

    let output = lpm(&project)
        .args(["--json", "env", "validate"])
        .output()
        .expect("failed to run lpm env validate --json");

    assert!(
        output.status.success(),
        "non-strict env validate must allow extra keys"
    );
    let envelope = parse_json_stdout(&output, "env validate --json");
    assert_eq!(envelope["success"], serde_json::json!(true));
    assert_eq!(envelope["valid"], serde_json::json!(true));
}

#[test]
fn env_validate_json_strict_exits_nonzero_and_reports_extra_keys() {
    let project = TempProject::empty(r#"{"name":"env-validate","version":"1.0.0"}"#);
    write_dotenv(&project, ".env.example", "REQUIRED=\n");
    lpm(&project)
        .args([
            "env",
            "set",
            "REQUIRED=value",
            "ZETA=z",
            "ALPHA=a",
            "MIDDLE=m",
        ])
        .assert()
        .success();

    let output = lpm(&project)
        .args(["--json", "env", "validate", "--strict"])
        .output()
        .expect("failed to run lpm env validate --strict --json");

    assert!(
        !output.status.success(),
        "strict env validate must fail when the default env has extra keys"
    );
    let envelope = parse_json_stdout(&output, "env validate --strict --json");
    assert_eq!(envelope["success"], serde_json::json!(false));
    assert_eq!(envelope["valid"], serde_json::json!(false));
    assert_eq!(
        envelope["extra"],
        serde_json::json!(["ALPHA", "MIDDLE", "ZETA"])
    );
    insta::assert_json_snapshot!("env_validate_json_strict_extra", envelope);
}

#[test]
fn env_validate_human_strict_sorts_extra_key_remediation() {
    let project = TempProject::empty(r#"{"name":"env-validate","version":"1.0.0"}"#);
    write_dotenv(&project, ".env.example", "REQUIRED=\n");
    lpm(&project)
        .args([
            "env",
            "set",
            "REQUIRED=value",
            "ZETA=z",
            "ALPHA=a",
            "MIDDLE=m",
        ])
        .assert()
        .success();

    let output = lpm(&project)
        .args(["env", "validate", "--strict"])
        .output()
        .expect("failed to run lpm env validate --strict");

    assert!(
        !output.status.success(),
        "strict env validate must fail when the default env has extra keys"
    );
    let stdout = strip_ansi(&String::from_utf8_lossy(&output.stdout));
    assert!(
        stdout.contains("lpm env delete ALPHA MIDDLE ZETA"),
        "human remediation must list extra keys in deterministic order:\n{stdout}"
    );
}

#[test]
fn env_validate_without_dotenv_example_fails_with_helpful_message() {
    let project = TempProject::empty(r#"{"name":"env","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args(["env", "validate"])
        .output()
        .expect("failed to run lpm env validate");

    assert!(
        !output.status.success(),
        "validate without .env.example must exit non-zero"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(".env.example"),
        "stderr must guide the user, got:\n{stderr}",
    );
}

// ─── check (vs lpm.json envSchema) ─────────────────────────────────────

#[test]
fn env_check_json_exits_nonzero_and_reports_invalid_environment() {
    let project = TempProject::empty(r#"{"name":"env-check","version":"1.0.0"}"#);
    project.write_file(
        "lpm.json",
        r#"{
  "envSchema": {
    "vars": {
      "REQUIRED": { "required": true }
    }
  }
}"#,
    );

    let output = lpm(&project)
        .args(["--json", "env", "check"])
        .output()
        .expect("failed to run lpm env check --json");

    assert!(
        !output.status.success(),
        "env check --json must fail when an environment is invalid"
    );
    let envelope = parse_json_stdout(&output, "env check --json");
    assert_eq!(envelope["success"], serde_json::json!(false));
    assert_eq!(envelope["environments"][0]["environment"], "default");
    assert_eq!(envelope["environments"][0]["errors"][0]["key"], "REQUIRED");
    insta::assert_json_snapshot!("env_check_json_invalid", envelope);
}

#[test]
fn env_check_json_exits_zero_when_environment_is_valid() {
    let project = TempProject::empty(r#"{"name":"env-check","version":"1.0.0"}"#);
    project.write_file(
        "lpm.json",
        r#"{
  "envSchema": {
    "vars": {
      "REQUIRED": { "required": true }
    }
  }
}"#,
    );
    write_dotenv(&project, ".env", "REQUIRED=present\n");

    let output = lpm(&project)
        .args(["--json", "env", "check"])
        .output()
        .expect("failed to run lpm env check --json");

    assert!(
        output.status.success(),
        "env check --json must succeed when every environment is valid"
    );
    let envelope = parse_json_stdout(&output, "env check --json");
    assert_eq!(envelope["success"], serde_json::json!(true));
    assert_eq!(envelope["environments"][0]["errors"], serde_json::json!([]));
}

#[test]
fn env_check_accepts_documented_regex_and_validated_defaults() {
    let project = TempProject::empty(r#"{"name":"env-check","version":"1.0.0"}"#);
    project.write_file(
        "lpm.json",
        r#"{
  "envSchema": {
    "vars": {
      "LOG_LEVEL": { "pattern": "^(trace|debug|info|warn|error)$" },
      "PORT": { "default": "3000", "format": "port" }
    }
  }
}"#,
    );
    write_dotenv(&project, ".env", "LOG_LEVEL=info\n");

    let output = lpm(&project)
        .args(["env", "check"])
        .output()
        .expect("failed to run lpm env check");

    assert!(
        output.status.success(),
        "documented regex and valid default must pass:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

#[test]
fn env_check_rejects_invalid_secret_default_without_exposing_it() {
    let project = TempProject::empty(r#"{"name":"env-check","version":"1.0.0"}"#);
    let secret = "prefix_private_material_suffix";
    project.write_file(
        "lpm.json",
        &format!(
            r#"{{
  "envSchema": {{
    "vars": {{
      "TOKEN": {{ "default": "{secret}", "format": "url", "secret": true }}
    }}
  }}
}}"#
        ),
    );

    let output = lpm(&project)
        .args(["env", "check"])
        .output()
        .expect("failed to run lpm env check");

    assert!(!output.status.success(), "invalid default must fail");
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    for fragment in [secret, "prefix", "suffix", "private_material"] {
        assert!(!combined.contains(fragment), "output leaked {fragment}");
    }
    assert!(combined.contains("TOKEN"), "{combined}");
}

#[test]
fn env_check_human_output_reports_an_invalid_default_as_invalid() {
    let project = TempProject::empty(r#"{"name":"env-check","version":"1.0.0"}"#);
    project.write_file(
        "lpm.json",
        r#"{"envSchema":{"vars":{"PORT":{"default":"70000","format":"port"}}}}"#,
    );

    let output = lpm(&project)
        .args(["env", "check"])
        .output()
        .expect("run lpm env check with an invalid default");
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    assert!(!output.status.success(), "invalid default must fail");
    assert!(
        combined.contains("env.invalid_format at lpm.json/envSchema/vars/PORT"),
        "{combined}"
    );
    assert!(!combined.contains("missing: PORT"), "{combined}");
}

#[test]
fn env_check_without_lpm_json_env_schema_fails_with_helpful_message() {
    let project = TempProject::empty(r#"{"name":"env","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args(["env", "check"])
        .output()
        .expect("failed to run lpm env check");

    assert!(
        !output.status.success(),
        "env check without envSchema must exit non-zero"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("envSchema") || stderr.contains("lpm.json"),
        "stderr must mention envSchema/lpm.json, got:\n{stderr}",
    );
}

#[test]
fn env_set_invalid_key_reports_public_env_wording() {
    let project = TempProject::empty(r#"{"name":"env-invalid-key","version":"1.0.0"}"#);

    let out = lpm(&project)
        .args(["env", "set", "BAD-NAME=value"])
        .output()
        .expect("failed to run lpm env set with invalid key");

    assert!(!out.status.success(), "invalid env key must fail");

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("env keys must match"),
        "stderr must describe the public env key contract, got:\n{stderr}",
    );
    assert!(
        !stderr.contains("vault keys"),
        "env command errors must not leak internal vault wording, got:\n{stderr}",
    );
}

#[test]
fn env_unknown_action_lists_available_subcommands() {
    let project = TempProject::empty(r#"{"name":"env","version":"1.0.0"}"#);

    let out = lpm(&project)
        .args(["env", "no-such-action"])
        .output()
        .expect("failed to run lpm env bogus");

    assert!(
        !out.status.success(),
        "unknown env action must exit non-zero"
    );

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("unknown env action"),
        "stderr must name the public env command surface, got:\n{stderr}",
    );
    assert!(
        !stderr.contains("unknown vars action"),
        "stderr must not leak legacy vars wording, got:\n{stderr}",
    );
    assert!(
        stderr.contains("set")
            && stderr.contains("get")
            && stderr.contains("list")
            && stderr.contains("delete"),
        "stderr must enumerate available actions, got:\n{stderr}",
    );
}

#[cfg(unix)]
#[test]
fn env_import_and_export_warn_when_gitignore_cannot_be_updated() {
    use std::os::unix::fs::PermissionsExt as _;
    for operation in ["import", "export"] {
        for json in [false, true] {
            let project = TempProject::empty(r#"{"name":"env-ignore-warning"}"#);
            lpm(&project)
                .args(["env", "set", "VALUE=private-fixture-value"])
                .assert()
                .success();
            project.write_file(".gitignore", "existing\n");
            project.write_file("secrets.env", "VALUE=private-fixture-value\n");
            let ignore = project.path().join(".gitignore");
            std::fs::set_permissions(&ignore, std::fs::Permissions::from_mode(0o444)).unwrap();
            let mut command = lpm(&project);
            command.args(["env", operation, "secrets.env"]);
            if json {
                command.arg("--json");
            }
            let output = command.output().unwrap();
            std::fs::set_permissions(&ignore, std::fs::Permissions::from_mode(0o644)).unwrap();
            assert!(output.status.success());
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert!(
                stderr.contains(".gitignore") && stderr.contains("before committing"),
                "{operation}: {stderr}"
            );
            assert!(!stderr.contains("private-fixture-value"));
            assert_eq!(project.read_file(".gitignore"), "existing\n");
            if json {
                assert_eq!(parse_json_stdout(&output, operation)["success"], true);
            }
            if operation == "export" {
                assert_eq!(
                    std::fs::metadata(project.path().join("secrets.env"))
                        .unwrap()
                        .permissions()
                        .mode()
                        & 0o777,
                    0o600
                );
            }
        }
    }
}

#[test]
fn env_export_does_not_append_to_linked_gitignore_targets() {
    for &hard_link in if cfg!(unix) {
        &[false, true][..]
    } else {
        &[true][..]
    } {
        let project = TempProject::empty(r#"{"name":"env-ignore-link"}"#);
        lpm(&project)
            .args(["env", "set", "VALUE=private-fixture-value"])
            .assert()
            .success();
        let outside = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(outside.path(), "outside bytes\n").unwrap();
        let ignore = project.path().join(".gitignore");
        if hard_link {
            std::fs::hard_link(outside.path(), &ignore).unwrap();
        } else {
            #[cfg(unix)]
            std::os::unix::fs::symlink(outside.path(), &ignore).unwrap();
        }
        let output = lpm(&project)
            .args(["env", "export", "secrets.env", "--json"])
            .output()
            .unwrap();
        assert!(output.status.success());
        assert_eq!(
            std::fs::read_to_string(outside.path()).unwrap(),
            "outside bytes\n"
        );
        assert!(String::from_utf8_lossy(&output.stderr).contains(".gitignore"));
        assert_eq!(parse_json_stdout(&output, "export")["success"], true);
    }
}

#[test]
fn env_init_without_imported_files_does_not_create_gitignore() {
    let project = TempProject::empty(r#"{"name":"env-init-empty"}"#);
    project.write_file(
        "lpm.json",
        r#"{"environments":{"staging":{"file":".env.staging"}}}"#,
    );
    lpm(&project)
        .args(["env", "init", "--json"])
        .assert()
        .success();
    assert!(!project.path().join(".gitignore").exists());
}

#[test]
fn env_schema_typos_never_expose_supplied_secrets() {
    let project = TempProject::empty(r#"{"name":"env-schema-typo"}"#);
    project.write_file(
        "lpm.json",
        r#"{"envSchema":{"vars":{"TOKEN":{"secert":true,"format":"integer"}}}}"#,
    );
    project.write_file(".env", "TOKEN=private-fixture-value\n");
    let output = lpm(&project).args(["env", "check"]).output().unwrap();
    assert!(!output.status.success());
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(text.contains("envSchema"));
    assert!(!text.contains("private-fixture-value"));
}

#[test]
fn env_schema_invalid_unused_defaults_stop_checks() {
    let project = TempProject::empty(r#"{"name":"env-schema-default"}"#);
    project.write_file(
        "lpm.json",
        r#"{"envSchema":{"vars":{"PORT":{"format":"port","default":"70000"}}}}"#,
    );
    project.write_file(".env", "PORT=3000\n");
    lpm(&project).args(["env", "check"]).assert().failure();
}

#[test]
fn env_schema_secret_literals_are_rejected_before_example_generation() {
    let project = TempProject::empty(r#"{"name":"env-schema-secret"}"#);
    for literal in [
        r#""default":"private-fixture-value""#,
        r#""enum":["private-fixture-value"]"#,
    ] {
        project.write_file(
            "lpm.json",
            &format!(r#"{{"envSchema":{{"vars":{{"TOKEN":{{"secret":true,{literal}}}}}}}}}"#),
        );
        let output = lpm(&project)
            .args(["env", "example", "--json"])
            .output()
            .unwrap();
        assert!(!output.status.success());
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!text.contains("private-fixture-value"));
        assert!(!project.path().join(".env.example").exists());
    }
}

#[test]
fn undeclared_nul_values_stop_checks_and_execution_before_hooks() {
    let project = TempProject::empty(
        r#"{"name":"env-nul","scripts":{"start":"echo executed > child-marker","prestart":"echo hook > hook-marker"}}"#,
    );
    project.write_file("lpm.json", r#"{"envSchema":{"vars":{"OPTIONAL":{}}}}"#);
    project.write_file(".env", "UNDECLARED=private\0fixture\n");
    for args in [
        vec!["env", "check"],
        vec!["run", "start"],
        vec!["run", "start", "--no-env-check"],
    ] {
        let output = lpm(&project).args(args).output().unwrap();
        assert!(!output.status.success());
        let text = String::from_utf8_lossy(&output.stderr);
        assert!(text.contains("NUL"), "{text}");
        assert!(!text.contains("private"));
        assert!(!project.path().join("hook-marker").exists());
        assert!(!project.path().join("child-marker").exists());
    }
}

#[test]
fn malformed_secret_declarations_report_paths_without_literals() {
    let project = TempProject::empty(r#"{"name":"env-private-parse"}"#);
    for rule in [
        r#"{"secret":true,"default":918273645}"#,
        r#"{"enum":[918273645],"secret":true}"#,
        r#"{"secret":true,"format":"private-fixture-value"}"#,
    ] {
        project.write_file(
            "lpm.json",
            &format!(r#"{{"envSchema":{{"vars":{{"TOKEN":{rule}}}}}}}"#),
        );
        let output = lpm(&project).args(["env", "check"]).output().unwrap();
        assert!(!output.status.success());
        for bytes in [&output.stdout, &output.stderr] {
            let text = String::from_utf8_lossy(bytes);
            assert!(!text.contains("918273645"));
            assert!(!text.contains("private-fixture-value"));
        }
    }
}

#[test]
fn undeclared_nul_keys_stop_checks_and_execution_before_hooks() {
    let project = TempProject::empty(
        r#"{"name":"env-nul","scripts":{"start":"echo executed > child-marker","prestart":"echo hook > hook-marker"}}"#,
    );
    project.write_file("lpm.json", r#"{"envSchema":{"vars":{"OPTIONAL":{}}}}"#);
    project.write_file(".env", "BAD\0NAME=private-fixture-value\n");
    for args in [
        vec!["env", "check"],
        vec!["run", "start"],
        vec!["run", "start", "--no-env-check"],
    ] {
        let output = lpm(&project).args(args).output().unwrap();
        assert!(!output.status.success());
        let text = String::from_utf8_lossy(&output.stderr);
        assert!(text.contains("NUL"), "{text}");
        assert!(!text.contains("private"));
        assert!(!project.path().join("hook-marker").exists());
        assert!(!project.path().join("child-marker").exists());
    }
}

#[test]
fn client_only_print_excludes_server_and_undeclared_values() {
    let project = TempProject::empty(r#"{"name":"env-client"}"#);
    project.write_file("lpm.json", r#"{"envSchema":{"vars":{"PUBLIC_API":{"client":true},"TOKEN":{"secret":true},"BUILD_MODE":{"ci":"variable"}}}}"#);
    project.write_file(".env", "PUBLIC_API=https://example.test\nTOKEN=private-fixture-value\nBUILD_MODE=production\nUNDECLARED=private-other\n");
    let output = lpm(&project)
        .args(["env", "print", "--client-only", "--json"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    insta::assert_json_snapshot!("env_print_client_only", value);
    assert!(!String::from_utf8_lossy(&output.stdout).contains("private"));
}

#[test]
fn client_only_print_requires_an_exposure_schema() {
    let project = TempProject::empty(r#"{"name":"env-client"}"#);
    project.write_file(".env", "PUBLIC_API=value\n");
    lpm(&project)
        .args(["env", "print", "--client-only"])
        .assert()
        .failure();
}

#[test]
fn env_check_counts_distinct_failed_variables_when_groups_overlap() {
    let project = TempProject::empty(r#"{"name":"env-relational-counts"}"#);
    project.write_file("lpm.json", r#"{"envSchema":{"vars":{"A":{"format":"integer","min":1},"B":{}},"groups":{"A":{"mode":"exactlyOne","vars":["A","B"]},"other":{"mode":"exactlyOne","vars":["A","B"]}}}}"#);
    write_dotenv(&project, ".env", "A=0\nB=present\n");
    let output = lpm(&project)
        .args(["--json", "env", "check"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let result = parse_json_stdout(&output, "env check group counts");
    assert_eq!(result["environments"][0]["total"], 2);
    assert_eq!(result["environments"][0]["valid"], 0);
    assert_eq!(
        result["environments"][0]["errors"]
            .as_array()
            .unwrap()
            .len(),
        5
    );
    let text = lpm(&project).args(["env", "check"]).output().unwrap();
    assert!(!text.status.success());
    assert!(String::from_utf8_lossy(&text.stdout).contains("0/2"));
}

#[test]
fn env_ls_checks_effective_values_defaults_conditions_and_groups() {
    let project = TempProject::empty(r#"{"name":"env-status"}"#);
    project.write_file("lpm.json", r#"{"envSchema":{"vars":{"PORT":{"format":"port","required":true},"MODE":{"default":"on"},"TOKEN":{"requiredWhen":{"variable":"MODE","equals":"on"}},"LEFT":{},"RIGHT":{}},"groups":{"auth":{"mode":"exactlyOne","vars":["LEFT","RIGHT"]}}}}"#);
    project.write_file(".env", "PORT=invalid\n");
    let output = lpm(&project)
        .args(["env", "ls", "--json"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stdout: {} stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let result = parse_json_stdout(&output, "env ls --json");
    let row = &result["environments"][0];
    let check = lpm(&project)
        .args(["env", "check", "--json"])
        .output()
        .unwrap();
    let checked = parse_json_stdout(&check, "env check --json");
    assert_eq!(row["schemaTotal"], checked["environments"][0]["total"]);
    assert_eq!(row["schemaValid"], checked["environments"][0]["valid"]);
    assert_eq!(row["variables"], 0);
    project.write_file(".env", "PORT=3000\nTOKEN=present\nLEFT=yes\n");
    let output = lpm(&project)
        .args(["env", "ls", "--json"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stdout: {} stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let result = parse_json_stdout(&output, "env ls --json");
    assert_eq!(result["environments"][0]["schemaValid"], 5);
}

#[test]
fn env_ls_keeps_healthy_rows_when_one_environment_file_fails() {
    let project = TempProject::empty(r#"{"name":"env-row-errors"}"#);
    project.write_file("lpm.json", r#"{"environments":{"base":{},"broken":{"extends":"missing"},"healthy":{}},"envSchema":{"vars":{"MODE":{"default":"ok"}}}}"#);
    let output = lpm(&project)
        .args(["env", "ls", "--json"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value = parse_json_stdout(&output, "env ls --json");
    let rows = value["environments"].as_array().unwrap();
    let healthy = rows.iter().find(|r| r["environment"] == "healthy").unwrap();
    assert_eq!(healthy["schemaValid"], 1);
    let broken = rows.iter().find(|r| r["environment"] == "broken").unwrap();
    assert_eq!(broken["schemaValid"], 0);
    assert!(broken["schemaError"].as_str().unwrap().contains("missing"));
}

#[test]
fn env_print_and_ci_export_preserve_nested_alias_paths() {
    let project = TempProject::empty(r#"{"name":"mapped-env","scripts":{"show":"node show.cjs"}}"#);
    project.write_file("show.cjs", "console.log(process.env.SELECTED);");
    project.write_file(
        "lpm.json",
        r#"{"env":{"show":"config/show.env"},"envSchema":{"vars":{"SELECTED":{"required":true}}}}"#,
    );
    project.write_file(".env", "SELECTED=base\n");
    project.write_file("config/show.env", "SELECTED=mapped\n");
    let printed = lpm(&project)
        .args(["env", "print", "--env=show", "--json"])
        .output()
        .unwrap();
    assert!(printed.status.success());
    assert_eq!(
        parse_json_stdout(&printed, "mapped print")["SELECTED"],
        "mapped"
    );
    lpm(&project)
        .args(["env", "export", "--ci", "--env=show", "export.env"])
        .assert()
        .success();
    assert_eq!(project.read_file("export.env"), "SELECTED=mapped");
}

#[test]
fn env_check_uses_inherited_declared_values_for_types_and_relationships() {
    let project = TempProject::empty(r#"{"name":"inherited-check"}"#);
    project.write_file("lpm.json", r#"{"envSchema":{"vars":{"INHERITED_ENV_COUNT":{"required":true,"format":"integer"},"TOKEN":{"requiredWhen":{"variable":"INHERITED_ENV_COUNT","equals":"7"}}}}}"#);
    project.write_file(".env", "INHERITED_ENV_COUNT=invalid\nTOKEN=available\n");
    let checked = lpm(&project)
        .env("INHERITED_ENV_COUNT", "7")
        .args(["env", "check", "--json"])
        .output()
        .unwrap();
    assert!(
        checked.status.success(),
        "{}",
        String::from_utf8_lossy(&checked.stdout)
    );
    assert_eq!(
        parse_json_stdout(&checked, "inherited check")["environments"][0]["valid"],
        2
    );
}

#[test]
fn env_check_includes_configured_default_and_nested_alias_environments() {
    let project = TempProject::empty(r#"{"name":"env-inventory"}"#);
    project.write_file("lpm.json", r#"{"env":{"show":"config/show.env"},"environments":{"default":{"file":"config/default.env"}},"envSchema":{"vars":{"SELECTED":{"required":true,"enum":["configured"]}}}}"#);
    project.write_file(".env", "SELECTED=wrong\n");
    project.write_file("config/default.env", "SELECTED=configured\n");
    project.write_file("config/show.env", "SELECTED=configured\n");
    let checked = lpm(&project)
        .args(["env", "check", "--json"])
        .output()
        .unwrap();
    assert!(
        checked.status.success(),
        "{}",
        String::from_utf8_lossy(&checked.stdout)
    );
    let value = parse_json_stdout(&checked, "configured inventory");
    let names: Vec<_> = value["environments"]
        .as_array()
        .unwrap()
        .iter()
        .map(|env| env["environment"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["default", "show"]);
}

#[test]
fn invalid_execution_environment_stops_before_hooks_even_without_schema_checks() {
    for mode in ["../production", "", "__index__"] {
        for skip in [false, true] {
            let project = TempProject::empty(
                r#"{"name":"invalid-selection","scripts":{"preshow":"node marker.cjs","show":"node marker.cjs"}}"#,
            );
            project.write_file(
                "marker.cjs",
                "require('node:fs').writeFileSync('started','yes');",
            );
            project.write_file(".env", "SELECTED=default\n");
            let mut command = lpm(&project);
            command.args(["run", "show", "--env", mode]);
            if skip {
                command.arg("--no-env-check");
            }
            let output = command.output().unwrap();
            assert!(
                !output.status.success(),
                "invalid selection {mode:?} executed"
            );
            assert!(!project.path().join("started").exists());
        }
    }
}

#[test]
fn runner_owned_metadata_is_validated_before_pre_hooks() {
    for key in ["LPM_SCRIPT_CHILD", "npm_lifecycle_event"] {
        let project = TempProject::empty(
            r#"{"name":"final-child-map","scripts":{"preshow":"node marker.cjs","show":"node marker.cjs"}}"#,
        );
        project.write_file(
            "marker.cjs",
            "require('node:fs').writeFileSync('started','yes');",
        );
        project.write_file("lpm.json",&format!(r#"{{"envSchema":{{"vars":{{"{key}":{{"default":"expected","enum":["expected"]}}}}}}}}"#));
        let output = lpm(&project).args(["run", "show"]).output().unwrap();
        assert!(
            !output.status.success(),
            "runner override for {key} escaped validation"
        );
        assert!(!project.path().join("started").exists());
    }
}

#[test]
fn script_extra_overrides_are_validated_before_pre_hooks() {
    let project = TempProject::empty(
        r#"{"scripts":{"prestart":"echo ran > pre.marker","start":"echo ran > main.marker"}}"#,
    );
    project.write_file(
        "lpm.json",
        r#"{"envSchema":{"vars":{"OVERRIDDEN":{"enum":["allowed"],"default":"allowed"}}}}"#,
    );
    let result = lpm_runner::script::run_script_with_envs(
        project.path(),
        "start",
        &[],
        None,
        &[("OVERRIDDEN".into(), "wrong".into())],
        &lpm_runner::bin_path::ManagedRuntimeHint::Unknown,
    );
    assert!(result.is_err(), "extra override escaped validation");
    assert!(!project.path().join("pre.marker").exists());
}

#[test]
fn command_extra_overrides_are_validated_before_spawning() {
    let project = TempProject::empty(r#"{"name":"override-validation"}"#);
    project.write_file(
        "lpm.json",
        r#"{"envSchema":{"vars":{"OVERRIDDEN":{"enum":["allowed"],"default":"allowed"}}}}"#,
    );
    let result = lpm_runner::script::run_command_buffered_with_envs(
        project.path(),
        "echo ran > child.marker",
        &[],
        None,
        &[("OVERRIDDEN".into(), "wrong".into())],
        &lpm_runner::bin_path::ManagedRuntimeHint::Unknown,
    );
    assert!(result.is_err(), "extra override escaped validation");
    assert!(!project.path().join("child.marker").exists());
}

#[test]
fn env_selection_resolves_alias_and_canonical_collisions_once() {
    let project = TempProject::empty(
        r#"{"name":"alias-collision","scripts":{"release":"test \"$SELECTED\" = \"production\""}}"#,
    );
    project.write_file(".env.production", "SELECTED=production\n");
    project.write_file(".env.staging", "SELECTED=staging\n");
    project.write_file("lpm.json",r#"{"env":{"release":".env.production","production":".env.staging"},"envSchema":{"vars":{"SELECTED":{"enum":["production","staging"]}}}}"#);
    let output = lpm(&project)
        .args(["env", "print", "--env=release", "--format=json"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        parse_json_stdout(&output, "one resolution")["SELECTED"],
        "production"
    );
}

#[test]
fn implicit_default_preserves_its_resolved_scope_for_scripts() {
    let project = TempProject::empty(r#"{"scripts":{"start":"echo ran > child.marker"}}"#);
    project.write_file("lpm.json",r#"{"env":{"default":".env.production"},"envSchema":{"vars":{"REQUIRED_FOR_PRODUCTION":{"requiredIn":[{"environment":["production"]}]}}}}"#);
    let output = lpm(&project)
        .args(["run", "start", "--no-cache"])
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "implicit production scope was bypassed"
    );
    assert!(!project.path().join("child.marker").exists());
}

#[test]
fn explicit_selection_accepts_configured_script_aliases_with_colons() {
    let project = TempProject::empty(r#"{"name":"colon-alias"}"#);
    project.write_file(".env.test", "SELECTED=test\n");
    project.write_file("lpm.json", r#"{"env":{"test:unit":".env.test"}}"#);
    let output = lpm(&project)
        .args(["env", "print", "--env=test:unit", "--format=json"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        parse_json_stdout(&output, "configured alias")["SELECTED"],
        "test"
    );
}

#[cfg(unix)]
#[test]
fn declared_inherited_non_utf8_values_are_rejected_without_using_defaults() {
    use std::os::unix::ffi::OsStrExt;
    let project = TempProject::empty(r#"{"scripts":{"start":"echo ran > child.marker"}}"#);
    for rule in [
        r#"{"required":true}"#,
        r#"{"default":"fallback"}"#,
        r#"{"format":"integer"}"#,
    ] {
        project.write_file(
            "lpm.json",
            &format!(r#"{{"envSchema":{{"vars":{{"INVALID_UTF8":{rule}}}}}}}"#),
        );
        let output = lpm(&project)
            .args(["run", "start", "--no-cache"])
            .env("INVALID_UTF8", std::ffi::OsStr::from_bytes(&[0xff]))
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("UTF-8"),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!project.path().join("child.marker").exists());
    }
}

#[test]
fn denied_process_hooks_cannot_satisfy_requirements_through_defaults() {
    let project = TempProject::empty(r#"{"scripts":{"start":"echo ran > child.marker"}}"#);
    project.write_file(
        "lpm.json",
        r#"{"envSchema":{"vars":{"NODE_OPTIONS":{"required":true,"default":"fixture"}}}}"#,
    );
    let output = lpm(&project)
        .args(["run", "start", "--no-cache"])
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "discarded hook default satisfied a requirement"
    );
    assert!(!project.path().join("child.marker").exists());
}

#[test]
fn scoped_env_commands_merge_configured_service_overlays() {
    let project = TempProject::empty(r#"{"name":"service-overlays"}"#);
    project.write_file("lpm.json",r#"{"services":{"api":{"command":"node server.js","env":{"SERVICE_VALUE":"configured"}}},"envSchema":{"vars":{"SERVICE_VALUE":{"requiredIn":[{"service":["api"]}],"enum":["configured"]}}}}"#);
    let output = lpm(&project)
        .args(["env", "check", "--service=api", "--json"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    let output = lpm(&project)
        .args(["env", "print", "--service=api", "--format=json"])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_eq!(
        parse_json_stdout(&output, "service overlay")["SERVICE_VALUE"],
        "configured"
    );
}

#[test]
fn cached_and_uncached_scripts_validate_the_same_runner_metadata() {
    let project = TempProject::empty(r#"{"scripts":{"build":"node build.js"}}"#);
    project.write_file("build.js","require('node:fs').mkdirSync('dist',{recursive:true}); require('node:fs').writeFileSync('dist/out','ok');\n");
    project.write_file("lpm.json",r#"{"tasks":{"build":{"cache":true,"inputs":["build.js"],"outputs":["dist/**"]}},"envSchema":{"vars":{"npm_lifecycle_event":{"required":true,"enum":["build"]},"LPM_SCRIPT_CHILD":{"required":true,"enum":["1"]}}}}"#);
    lpm(&project)
        .args(["run", "build", "--no-cache"])
        .assert()
        .success();
    lpm(&project).args(["run", "build"]).assert().success();
    lpm(&project).args(["run", "build"]).assert().success();
}

#[test]
fn project_loaders_preserve_the_implicit_default_file_cascade() {
    let project = TempProject::empty(r#"{"name":"default-cascade"}"#);
    project.write_file(".env", "CASCADE_VALUE=base\n");
    project.write_file(".env.local", "CASCADE_VALUE=local\n");
    project.write_file(".env.default", "CASCADE_VALUE=unexpected\n");
    project.write_file(
        "lpm.json",
        r#"{"envSchema":{"vars":{"CASCADE_VALUE":{"enum":["local"]}}}}"#,
    );
    let config = lpm_runner::lpm_json::read_lpm_json(project.path()).unwrap();
    for values in [
        lpm_runner::dotenv::load_project_env_with_schema_validation(project.path(), None, true),
        lpm_runner::dotenv::load_project_env_with_config(project.path(), None, config.as_ref()),
        lpm_runner::dotenv::load_project_env_with_config_and_context(
            project.path(),
            None,
            config.as_ref(),
            Default::default(),
            None,
        ),
    ] {
        assert_eq!(values.unwrap()["CASCADE_VALUE"], "local");
    }
}

#[test]
fn project_loaders_honor_the_configured_default_file_and_scope() {
    let project = TempProject::empty(r#"{"name":"configured-default"}"#);
    project.write_file(".env", "CASCADE_VALUE=base\n");
    project.write_file("config/default.env", "CASCADE_VALUE=configured\n");
    project.write_file("lpm.json", r#"{"env":{"default":"config/default.env"},"envSchema":{"vars":{"CASCADE_VALUE":{"requiredIn":[{"environment":["default"]}],"enum":["configured"]}}}}"#);
    let config = lpm_runner::lpm_json::read_lpm_json(project.path()).unwrap();
    for values in [
        lpm_runner::dotenv::load_project_env_with_schema_validation(project.path(), None, true),
        lpm_runner::dotenv::load_project_env_with_config(project.path(), None, config.as_ref()),
        lpm_runner::dotenv::load_project_env_with_config_and_context(
            project.path(),
            None,
            config.as_ref(),
            Default::default(),
            None,
        ),
    ] {
        assert_eq!(values.unwrap()["CASCADE_VALUE"], "configured");
    }
}

#[test]
fn explicit_default_selects_the_same_files_for_print_and_script_execution() {
    let project = TempProject::empty(r#"{"scripts":{"show":"node show.cjs"}}"#);
    project.write_file("show.cjs", "console.log(process.env.CASCADE_VALUE)");
    project.write_file(".env", "CASCADE_VALUE=base\n");
    project.write_file(".env.default", "CASCADE_VALUE=explicit\n");
    let printed = lpm(&project)
        .args(["env", "print", "--env=default", "--format=json"])
        .output()
        .unwrap();
    assert!(printed.status.success());
    assert_eq!(
        parse_json_stdout(&printed, "explicit default")["CASCADE_VALUE"],
        "explicit"
    );
    let executed = lpm(&project)
        .args(["run", "show", "--env=default", "--no-cache"])
        .output()
        .unwrap();
    assert!(executed.status.success());
    assert!(
        String::from_utf8_lossy(&executed.stdout)
            .lines()
            .any(|line| line == "explicit")
    );
}

#[test]
fn scoped_check_json_applies_environment_stage_and_service_together() {
    let project = TempProject::empty(r#"{"name":"scoped-check"}"#);
    project.write_file("lpm.json", r#"{"envSchema":{"vars":{"VALUE":{"requiredIn":[{"environment":["production"],"stage":["build"],"service":["api"]}],"defaultsIn":[{"when":{"stage":["test"]},"value":"fixture"}]}}}}"#);
    let output = lpm(&project)
        .args([
            "env",
            "check",
            "--env=production",
            "--stage=build",
            "--service=api",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    insta::assert_json_snapshot!(
        "env_scoped_check",
        parse_json_stdout(&output, "scoped check")
    );
    for flags in [
        ["--env=staging", "--stage=build", "--service=api"],
        ["--env=production", "--stage=runtime", "--service=api"],
        ["--env=production", "--stage=build", "--service=worker"],
    ] {
        lpm(&project)
            .args(["env", "check"])
            .args(flags)
            .assert()
            .success();
    }
    let printed = lpm(&project)
        .args(["env", "print", "--stage=test", "--format=json"])
        .output()
        .unwrap();
    assert!(printed.status.success());
    assert_eq!(
        parse_json_stdout(&printed, "scoped defaults")["VALUE"],
        "fixture"
    );
}

#[test]
fn build_hooks_use_the_original_stage_for_scoped_defaults() {
    let project = TempProject::empty(
        r#"{"scripts":{"prebuild:api":"node show.cjs","build:api":"node show.cjs","postbuild:api":"node show.cjs"}}"#,
    );
    project.write_file(
        "show.cjs",
        "require('node:fs').appendFileSync('stages', process.env.SCOPED_VALUE + '\\n')",
    );
    project.write_file("lpm.json", r#"{"envSchema":{"vars":{"SCOPED_VALUE":{"requiredIn":[{"stage":["build"]}],"default":"runtime","defaultsIn":[{"when":{"stage":["build"]},"value":"build"}]}}}}"#);
    lpm(&project)
        .args(["run", "build:api", "--no-cache"])
        .assert()
        .success();
    assert_eq!(project.read_file("stages"), "build\nbuild\nbuild\n");
}

#[test]
fn generated_examples_describe_scopes_without_selecting_a_scoped_value() {
    let project = TempProject::empty(r#"{"name":"scoped-example"}"#);
    project.write_file("lpm.json", r#"{"envSchema":{"vars":{"VALUE":{"requiredIn":[{"environment":["production"],"stage":["build"]}],"defaultsIn":[{"when":{"stage":["test"]},"value":"fixture"}]},"TOKEN":{"secret":true,"requiredIn":[{"service":["api"]}]}}}}"#);
    lpm(&project).args(["env", "example"]).assert().success();
    let example = project.read_file(".env.example");
    assert!(example.contains("required for environment=production & stage=build"));
    assert!(example.contains("default for stage=test: fixture"));
    assert!(example.contains("required for service=api"));
    assert!(example.lines().any(|line| line == "VALUE="));
}

#[test]
fn redirected_default_alias_retains_the_base_inventory_cascade() {
    let project = TempProject::empty(r#"{"name":"redirected-default"}"#);
    project.write_file(".env", "VALUE=base\n");
    project.write_file(".env.default", "VALUE=bad\n");
    project.write_file(".env.production", "VALUE=production\n");
    project.write_file("lpm.json", r#"{"env":{"default":".env.production"},"envSchema":{"vars":{"VALUE":{"enum":["base","production"]}}}}"#);
    let checked = lpm(&project)
        .args(["env", "check", "--json"])
        .output()
        .unwrap();
    assert!(
        checked.status.success(),
        "{}",
        String::from_utf8_lossy(&checked.stdout)
    );
    let value = parse_json_stdout(&checked, "redirected default inventory");
    let names: Vec<_> = value["environments"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| entry["environment"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["default", "production"]);
}

#[test]
fn large_inherited_schemas_preserve_explicit_precedence_and_empty_defaults() {
    let project = TempProject::empty(r#"{"scripts":{"start":"node check.cjs"}}"#);
    let mut vars = serde_json::Map::new();
    for index in 0..32 {
        vars.insert(
            format!("LPM_SCOPE_{index}"),
            serde_json::json!({"required":true,"enum":["inherited"]}),
        );
    }
    vars.insert(
        "EMPTY_SCOPED".into(),
        serde_json::json!({"empty":"missing","default":"fallback"}),
    );
    vars.insert(
        "EXPLICIT_SCOPED".into(),
        serde_json::json!({"enum":["inherited"]}),
    );
    project.write_file(
        "lpm.json",
        &serde_json::json!({"envSchema":{"vars":vars}}).to_string(),
    );
    project.write_file(".env", "EXPLICIT_SCOPED=file\n");
    project.write_file("check.cjs", "const e=process.env; if(e.EMPTY_SCOPED!=='fallback'||e.EXPLICIT_SCOPED!=='inherited'||Array.from({length:32},(_,i)=>e['LPM_SCOPE_'+i]).some(v=>v!=='inherited')) process.exit(1)");
    let mut command = lpm(&project);
    command
        .args(["run", "start", "--no-cache"])
        .env("EMPTY_SCOPED", "")
        .env("EXPLICIT_SCOPED", "inherited");
    for index in 0..32 {
        command.env(format!("LPM_SCOPE_{index}"), "inherited");
    }
    command.assert().success();
}

#[cfg(unix)]
#[test]
fn large_inherited_schemas_reject_declared_non_utf8_and_ignore_undeclared_non_utf8() {
    use std::os::unix::ffi::OsStrExt;
    let project = TempProject::empty(r#"{"scripts":{"start":"echo ran > child.marker"}}"#);
    let mut vars = serde_json::Map::new();
    for index in 0..32 {
        vars.insert(
            format!("LPM_SCOPE_{index}"),
            serde_json::json!({"default":"fallback"}),
        );
    }
    project.write_file(
        "lpm.json",
        &serde_json::json!({"envSchema":{"vars":vars}}).to_string(),
    );
    for (name, success) in [("LPM_UNDECLARED_NON_UTF8", true), ("LPM_SCOPE_0", false)] {
        let output = lpm(&project)
            .args(["run", "start", "--no-cache"])
            .env(name, std::ffi::OsStr::from_bytes(&[0xff]))
            .output()
            .unwrap();
        assert_eq!(
            output.status.success(),
            success,
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        if !success {
            assert!(String::from_utf8_lossy(&output.stderr).contains("UTF-8"));
        }
    }
}

#[test]
fn scoped_direct_files_and_local_bins_use_the_canonical_environment_and_final_values() {
    let project = TempProject::empty(r#"{"name":"scope-runtime-matrix"}"#);
    project.write_file("lpm.json",r#"{"env":{"release":".env.production"},"environments":{"production":{"file":"config/exact.env"}},"envSchema":{"vars":{"SCOPED_RUNTIME_VALUE":{"format":"integer","enum":["3"],"requiredIn":[{"environment":["production"],"stage":["runtime"]}],"defaultsIn":[{"when":{"stage":["runtime"]},"value":"3"}]}}}}"#);
    project.write_file("config/exact.env", "SCOPED_RUNTIME_VALUE=3\n");
    project.write_file(
        ".env.production",
        "SCOPED_RUNTIME_VALUE=wrong-derived-file\n",
    );
    project.write_file("entry.cjs","if(process.env.SCOPED_RUNTIME_VALUE!=='3') process.exit(1); require('node:fs').writeFileSync('child.marker','ok');");
    if cfg!(windows) {
        project.write_file("node_modules/.bin/scoped-tool.cmd", "@node entry.cjs\r\n");
    } else {
        project.write_file(
            "node_modules/.bin/scoped-tool",
            "#!/bin/sh\nexec node entry.cjs\n",
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(
                project.path().join("node_modules/.bin/scoped-tool"),
                std::fs::Permissions::from_mode(0o755),
            )
            .unwrap();
        }
    }
    for args in [
        vec!["entry.cjs", "--env=release"],
        vec!["exec", "scoped-tool", "--env=release"],
    ] {
        lpm(&project).args(&args).assert().success();
        assert!(project.file_exists("child.marker"));
        std::fs::remove_file(project.path().join("child.marker")).unwrap();
        project.write_file("config/exact.env", "SCOPED_RUNTIME_VALUE=invalid\n");
        let output = lpm(&project).args(&args).output().unwrap();
        assert!(
            !output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!project.file_exists("child.marker"));
        project.write_file("config/exact.env", "SCOPED_RUNTIME_VALUE=3\n");
    }
}

#[cfg(windows)]
#[test]
fn sparse_and_bulk_inherited_lookup_match_windows_canonical_names() {
    for count in [31, 32] {
        let project = TempProject::empty(r#"{"name":"inherited-casing"}"#);
        let rules = (0..count)
            .map(|index| {
                (
                    format!("LPM_BULK_{index}"),
                    serde_json::json!({"format":"integer","required":true}),
                )
            })
            .collect::<serde_json::Map<String, serde_json::Value>>();
        project.write_file(
            "lpm.json",
            &serde_json::json!({"envSchema":{"vars":rules}}).to_string(),
        );
        for valid in [true, false] {
            let mut command = lpm(&project);
            command.args(["env", "check", "--json"]);
            for index in 0..count {
                command.env(
                    format!("lpm_bulk_{index}"),
                    if !valid && index == 0 { "invalid" } else { "2" },
                );
            }
            let output = command.output().unwrap();
            assert_eq!(
                output.status.success(),
                valid,
                "{}",
                String::from_utf8_lossy(&output.stdout)
            );
        }
    }
}

#[test]
fn env_check_reports_invalid_custom_path_alias_without_aborting_other_environments() {
    let project = TempProject::empty(r#"{"name":"alias-inventory"}"#);
    project.write_file("lpm.json", r#"{"env":{"test:unit":"config/unit.env"},"envSchema":{"vars":{"VALUE":{"default":"ok"}}}}"#);
    let output = lpm(&project)
        .args(["env", "check", "--json"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let result = parse_json_stdout(&output, "invalid alias inventory");
    let rows = result["environments"]
        .as_array()
        .expect("inventory must retain other environments");
    assert!(
        rows.iter()
            .any(|row| row["environment"] == "default"
                && row["errors"].as_array().unwrap().is_empty())
    );
    assert!(rows.iter().any(|row| {
        row["environment"] == "test:unit"
            && ["test:unit", "portable alias", "tasks.<name>.env"]
                .iter()
                .all(|text| row["errors"][0]["error"].as_str().unwrap().contains(text))
    }));
}

#[test]
fn selected_services_reject_configured_typos_and_allow_abstract_contexts() {
    let project = TempProject::empty(r#"{"name":"service-context"}"#);
    for configured in [true, false] {
        project.write_file("lpm.json", &serde_json::json!({"envSchema":{"vars":{"VALUE":{}}}, "services":if configured {serde_json::json!({"api":{"command":"echo api"}})} else {serde_json::json!({})}}).to_string());
        for name in ["api", "apii"] {
            let output = lpm(&project)
                .args(["env", "check", "--service", name, "--json"])
                .output()
                .unwrap();
            assert_eq!(
                output.status.success(),
                !configured || name == "api",
                "{}",
                String::from_utf8_lossy(&output.stdout)
            );
        }
    }
}

#[test]
fn env_ls_uses_the_inventory_environment_for_scoped_rules() {
    let project = TempProject::empty(r#"{"name":"scoped-status"}"#);
    project.write_file("lpm.json", r#"{"env":{"release":".env.production"},"envSchema":{"vars":{"VALUE":{"requiredIn":[{"environment":["production"]}]}}}}"#);
    let output = lpm(&project)
        .args(["env", "ls", "--json"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let result = parse_json_stdout(&output, "scoped inventory");
    assert_eq!(result["environments"][1]["schemaValid"], 0);
}

#[test]
fn env_ls_and_check_agree_on_default_inheritance_and_invalid_aliases() {
    let project = TempProject::empty(r#"{"name":"inventory-parity"}"#);
    project.write_file("config/base.env", "VALUE=base\n");
    for child in [false, true] {
        project.write_file("config/child.env", "OTHER=child\n");
        project.write_file("lpm.json", &serde_json::json!({"environments":{"base":"config/base.env","default":if child {serde_json::json!({"extends":"base","file":"config/child.env"})} else {serde_json::json!({"extends":"base"})}},"env":{"test:unit":"config/unit.env"},"envSchema":{"vars":{"VALUE":{"required":true}}}}).to_string());
        let checked = lpm(&project)
            .args(["env", "check", "--env=default", "--json"])
            .output()
            .unwrap();
        assert!(
            checked.status.success(),
            "{}",
            String::from_utf8_lossy(&checked.stdout)
        );
        let listed = lpm(&project)
            .args(["env", "ls", "--json"])
            .output()
            .unwrap();
        assert!(listed.status.success());
        let result = parse_json_stdout(&listed, "inventory parity");
        let rows = result["environments"].as_array().unwrap();
        assert_eq!(
            rows.iter().find(|r| r["environment"] == "default").unwrap()["schemaValid"],
            1
        );
        assert_eq!(
            rows.iter()
                .find(|r| r["environment"] == "test:unit")
                .unwrap()["schemaValid"],
            0
        );
    }
}

#[test]
fn env_schema_json_reports_import_provenance_without_reading_values() {
    let project = TempProject::empty(r#"{"name":"schema-definition"}"#);
    project.write_file("lpm.json", r#"{"envSchema":{"extends":["preset:node","base.json"],"vars":{"LOCAL":{"required":true}}}}"#);
    project.write_file(
        "base.json",
        r#"{"vars":{"TOKEN":{"secret":true,"required":true}}}"#,
    );
    let output = lpm(&project)
        .args(["--json", "env", "schema"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value = parse_json_stdout(&output, "env schema");
    assert_eq!(value["origins"]["TOKEN"]["source"], "base.json");
    assert_eq!(
        value["origins"]["LOCAL"]["pointer"],
        "/envSchema/vars/LOCAL"
    );
    assert_eq!(value["dependencies"], serde_json::json!(["base.json"]));
    insta::assert_json_snapshot!("env_schema_definition_json", value, {".fingerprint" => "[fingerprint]"});
}

#[test]
fn env_schema_fragment_type_errors_report_safe_field_locations() {
    let project = TempProject::empty(r#"{"name":"fragment-types"}"#);
    project.write_file("lpm.json", r#"{"envSchema":{"extends":["base.json"]}}"#);
    project.write_file(
        "base.json",
        r#"{"vars":{"VALUE":{"required":"private-fixture-value"}}}"#,
    );
    let output = lpm(&project)
        .args(["env", "schema", "--json"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let value = parse_json_stdout(&output, "fragment type diagnostic");
    assert_eq!(value["diagnostics"][0]["code"], "env.invalid_definition");
    assert_eq!(value["diagnostics"][0]["source"], "base.json");
    assert_eq!(value["diagnostics"][0]["pointer"], "/vars/VALUE/required");
    assert!(
        value["diagnostics"][0]["message"]
            .as_str()
            .unwrap()
            .contains("value type")
    );
    assert!(!String::from_utf8_lossy(&output.stdout).contains("private-fixture-value"));
}

#[test]
fn env_schema_json_reports_static_codes_and_source_pointers_without_literals() {
    let project = TempProject::empty(r#"{"name":"schema-invalid"}"#);
    project.write_file("lpm.json", r#"{"envSchema":{"extends":["base.json"]}}"#);
    project.write_file(
        "base.json",
        r#"{"vars":{"VALUE":{"pattern":"[PRIVATE_PATTERN"}}}"#,
    );
    let output = lpm(&project)
        .args(["--json", "env", "schema"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(!String::from_utf8_lossy(&output.stdout).contains("PRIVATE_PATTERN"));
    let value = parse_json_stdout(&output, "env schema invalid");
    assert_eq!(value["diagnostics"][0]["code"], "env.invalid_pattern");
    assert_eq!(value["diagnostics"][0]["source"], "base.json");
    assert_eq!(value["diagnostics"][0]["pointer"], "/vars/VALUE");
    insta::assert_json_snapshot!("env_schema_definition_invalid_json", value);
}

#[test]
fn imported_rules_drive_examples_runtime_checks_and_definition_errors() {
    let project = TempProject::empty(r#"{"name":"schema-import-flow"}"#);
    project.write_file("lpm.json", r#"{"envSchema":{"extends":["base.json"]}}"#);
    project.write_file(
        "base.json",
        r#"{"vars":{"VALUE":{"format":"integer","default":"4"}}}"#,
    );
    let example = lpm(&project)
        .args(["env", "example", "--json"])
        .output()
        .unwrap();
    assert!(example.status.success());
    assert!(
        parse_json_stdout(&example, "env example")["content"]
            .as_str()
            .unwrap()
            .contains("VALUE=4")
    );
    let check = lpm(&project)
        .args(["env", "check", "--json"])
        .output()
        .unwrap();
    assert!(
        check.status.success(),
        "{}",
        String::from_utf8_lossy(&check.stderr)
    );
    project.write_file(
        "base.json",
        r#"{"vars":{"VALUE":{"format":"integer","default":"invalid"}}}"#,
    );
    let example = lpm(&project)
        .args(["env", "example", "--json"])
        .output()
        .unwrap();
    assert!(!example.status.success());
}
