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
        .args(["env", "import", ".env"])
        .output()
        .expect("failed to run lpm env import");
    assert!(
        out.status.success(),
        "env import failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );

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
        .args(["env", "export", export_path.to_str().unwrap()])
        .output()
        .expect("failed to run lpm env export");
    assert!(
        out.status.success(),
        "env export failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );

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
        .args(["env", "copy", "src", "dst"])
        .output()
        .expect("failed to run lpm env copy");
    assert!(
        out.status.success(),
        "env copy failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );

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
        stderr.contains("set")
            && stderr.contains("get")
            && stderr.contains("list")
            && stderr.contains("delete"),
        "stderr must enumerate available actions, got:\n{stderr}",
    );
}
