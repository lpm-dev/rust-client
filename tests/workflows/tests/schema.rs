//! Workflow tests for `lpm schema lpm.json` and `lpm schema lpm.config.json`.
//!
//! Both schemas ship as JSON Schema documents — the `lpm.json` schema
//! is derived from a typed struct via schemars; the `lpm.config.json`
//! schema is hand-authored. `crates/lpm-cli/tests/schema_drift.rs`
//! pins the byte-identity against the committed copies in this repo's
//! `public/schemas/` directory. This file covers the CLI surface
//! contract: stdout emission + `--out <path>` file writing + unknown
//! kind error handling.

mod support;

use support::{TempProject, lpm};

// ─── stdout emission ──────────────────────────────────────────────────

#[test]
fn schema_lpm_json_emits_valid_json_schema_to_stdout() {
    let project = TempProject::empty(r#"{"name":"schema","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args(["schema", "lpm.json"])
        .output()
        .expect("failed to run lpm schema lpm.json");

    assert!(
        output.status.success(),
        "lpm schema lpm.json failed\nstderr: {}",
        String::from_utf8_lossy(&output.stderr),
    );

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let parsed: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("schema output must be valid JSON: {e}\n---\n{stdout}"));

    // JSON Schema documents declare `$schema` and have a `type` or
    // `oneOf` at the root.
    assert!(
        parsed["$schema"].is_string() || parsed["type"].is_string(),
        "lpm.json schema must declare $schema or root type, got:\n{parsed}",
    );
}

#[test]
fn schema_color_always_keeps_non_tty_stdout_byte_identical() {
    let project = TempProject::empty(r#"{"name":"schema","version":"1.0.0"}"#);

    let plain = lpm(&project)
        .args(["schema", "lpm.config.json"])
        .output()
        .expect("failed to run plain lpm schema");
    let forced_color = lpm(&project)
        .args(["--color=always", "schema", "lpm.config.json"])
        .output()
        .expect("failed to run color-forced lpm schema");

    assert!(plain.status.success(), "plain schema must succeed");
    assert!(
        forced_color.status.success(),
        "color-forced schema must succeed"
    );
    assert_eq!(
        forced_color.stdout, plain.stdout,
        "non-TTY schema stdout must remain pipe-safe even with --color=always"
    );
}

#[test]
fn schema_lpm_config_json_emits_hand_authored_schema_with_id() {
    let project = TempProject::empty(r#"{"name":"schema","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args(["schema", "lpm.config.json"])
        .output()
        .expect("failed to run lpm schema lpm.config.json");

    assert!(
        output.status.success(),
        "lpm schema lpm.config.json failed\nstderr: {}",
        String::from_utf8_lossy(&output.stderr),
    );

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let parsed: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("schema output must be valid JSON: {e}\n---\n{stdout}"));

    // The hand-authored schema carries a stable `$id` pointing at the
    // public URL. Source of truth: `crates/lpm-cli/schemas/lpm.config.schema.json`.
    assert_eq!(
        parsed["$id"].as_str(),
        Some("https://lpm.dev/schemas/lpm.config.json"),
        "lpm.config.json schema must declare its public $id, got:\n{parsed}",
    );
}

// ─── --out file writing ───────────────────────────────────────────────

#[test]
fn schema_lpm_json_with_out_writes_to_file_and_silences_stdout() {
    let project = TempProject::empty(r#"{"name":"schema","version":"1.0.0"}"#);
    let out_path = project.path().join("emitted.schema.json");

    let output = lpm(&project)
        .args(["schema", "lpm.json", "--out", out_path.to_str().unwrap()])
        .output()
        .expect("failed to run lpm schema --out");

    assert!(output.status.success(), "lpm schema --out failed");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.contains("\"$schema\"") && !stdout.contains("\"type\""),
        "--out must NOT also print to stdout, got:\n{stdout}"
    );

    let content = std::fs::read_to_string(&out_path).expect("read emitted file");
    let _parsed: serde_json::Value = serde_json::from_str(&content)
        .unwrap_or_else(|e| panic!("emitted file must be valid JSON: {e}\n---\n{content}"));
}

// ─── unknown kind error ──────────────────────────────────────────────

#[test]
fn schema_unknown_kind_fails_with_helpful_message() {
    let project = TempProject::empty(r#"{"name":"schema","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args(["schema", "not-a-real-schema"])
        .output()
        .expect("failed to run lpm schema bogus");

    assert!(
        !output.status.success(),
        "unknown schema kind must exit non-zero"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("lpm.json") && stderr.contains("lpm.config.json"),
        "stderr must list valid schema kinds, got:\n{stderr}",
    );
}
