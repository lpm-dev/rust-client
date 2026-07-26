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

    let out = lpm(&project)
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
    project.write_file(
        "lpm.json",
        &serde_json::json!({ "env": { "dev": format!(".env.{hostile}") } }).to_string(),
    );

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

    let output = lpm(&project)
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
