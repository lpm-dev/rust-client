//! Workflow tests for the `lpm doctor` sigstore-verify posture row.
//!
//! Inline unit tests in `commands/doctor.rs` cover
//! `check_sigstore_verify_posture` directly. This file drives the
//! real binary so a regression in the wiring between
//! `EnforceMode::resolve_from_chain`, `GlobalConfig::get_sigstore_verify`,
//! and the doctor catalog surfaces here.

mod support;

use serde_json::Value;
use support::{TempProject, lpm_with_registry};

fn run_doctor_json(project: &TempProject) -> Value {
    let output = lpm_with_registry(project, "http://127.0.0.1:1")
        .env_remove("LPM_PROVENANCE_ENFORCE")
        .args(["doctor", "--all", "--json"])
        .output()
        .expect("failed to run lpm doctor --all --json");
    let stdout = String::from_utf8_lossy(&output.stdout);
    serde_json::from_str(stdout.trim()).unwrap_or_else(|e| {
        panic!(
            "doctor --json stdout must parse as JSON: {e}\nraw stdout: {stdout}\nstderr: {}",
            String::from_utf8_lossy(&output.stderr),
        )
    })
}

/// Find the check entry whose `code` field equals the supplied name.
/// Returns `None` if no row carries that code — the calling test
/// distinguishes "row absent" from "row present, wrong severity."
fn find_check<'a>(envelope: &'a Value, code: &str) -> Option<&'a Value> {
    envelope["checks"]
        .as_array()
        .expect("doctor envelope must carry checks array")
        .iter()
        .find(|c| c["code"].as_str() == Some(code))
}

fn write_sigstore_verify_to_config(project: &TempProject, value: &str) {
    let cfg_dir = project.home().join(".lpm");
    std::fs::create_dir_all(&cfg_dir).expect("mkdir ~/.lpm");
    std::fs::write(
        cfg_dir.join("config.toml"),
        format!("[sigstore]\nverify = \"{value}\"\n"),
    )
    .expect("write config.toml");
}

/// Default posture (no env var, no config file). Doctor must emit
/// the dedicated `sigstore_verify_enforced` PASS row — NOT the warn
/// or disabled variant. If this regresses, a clean install ships
/// what looks like a degraded posture to anyone reading
/// `lpm doctor`.
#[test]
fn doctor_is_clean_when_sigstore_verify_is_absent_default_deny() {
    let project = TempProject::empty(r#"{"name":"doctor-sigstore","version":"1.0.0"}"#);
    let envelope = run_doctor_json(&project);

    let row = find_check(&envelope, "sigstore_verify_enforced").unwrap_or_else(|| {
        panic!(
            "default posture must emit `sigstore_verify_enforced` (pass). Envelope: {envelope:#?}",
        )
    });
    assert_eq!(
        row["severity"].as_str(),
        Some("pass"),
        "default posture row must be `pass`. Row: {row}",
    );
    assert!(
        find_check(&envelope, "sigstore_verify_warn_mode").is_none(),
        "default posture must NOT also emit the warn-mode row. Envelope: {envelope:#?}",
    );
    assert!(
        find_check(&envelope, "sigstore_verify_disabled").is_none(),
        "default posture must NOT also emit the disabled row. Envelope: {envelope:#?}",
    );
}

/// `[sigstore] verify = "warn"` in config must surface the dedicated
/// `sigstore_verify_warn_mode` row at warn severity, naming the
/// config source so the operator knows where to flip it. The
/// re-enable command hint must be in the row detail so audit
/// pipelines can extract a remediation step.
#[test]
fn doctor_warns_when_sigstore_verify_is_warn_in_config() {
    let project = TempProject::empty(r#"{"name":"doctor-sigstore","version":"1.0.0"}"#);
    write_sigstore_verify_to_config(&project, "warn");
    let envelope = run_doctor_json(&project);

    let row = find_check(&envelope, "sigstore_verify_warn_mode").unwrap_or_else(|| {
        panic!("warn posture must emit `sigstore_verify_warn_mode`. Envelope: {envelope:#?}",)
    });
    assert_eq!(
        row["severity"].as_str(),
        Some("warn"),
        "warn-posture row must be `warn` severity. Row: {row}",
    );
    let detail = row["detail"].as_str().unwrap_or("");
    assert!(
        detail.contains("[sigstore].verify in ~/.lpm/config.toml"),
        "row detail must name the config source so the operator knows \
         where to flip the knob; got: {detail}",
    );
    assert!(
        detail.contains("lpm config sigstore --set deny"),
        "row detail must surface the re-enable command hint; got: {detail}",
    );
    assert!(
        find_check(&envelope, "sigstore_verify_enforced").is_none(),
        "warn posture must NOT also emit the enforced (pass) row. Envelope: {envelope:#?}",
    );
}

/// `[sigstore] verify = "off"` in config must surface the
/// `sigstore_verify_disabled` row at warn severity. This is the
/// load-bearing footgun mitigation — the audit pipeline reading
/// `lpm doctor --json` sees the off posture in machine-readable
/// form and can refuse to ship until it's flipped back.
#[test]
fn doctor_warns_when_sigstore_verify_is_off_in_config() {
    let project = TempProject::empty(r#"{"name":"doctor-sigstore","version":"1.0.0"}"#);
    write_sigstore_verify_to_config(&project, "off");
    let envelope = run_doctor_json(&project);

    let row = find_check(&envelope, "sigstore_verify_disabled").unwrap_or_else(|| {
        panic!("off posture must emit `sigstore_verify_disabled`. Envelope: {envelope:#?}",)
    });
    assert_eq!(
        row["severity"].as_str(),
        Some("warn"),
        "off-posture row must be `warn` severity. Row: {row}",
    );
    let detail = row["detail"].as_str().unwrap_or("");
    assert!(
        detail.contains("[sigstore].verify in ~/.lpm/config.toml"),
        "row detail must name the config source; got: {detail}",
    );
    assert!(
        detail.contains("IGNORED"),
        "off-posture row detail must be stern about the consequence \
         (Sigstore attestations IGNORED); got: {detail}",
    );
    assert!(
        find_check(&envelope, "sigstore_verify_enforced").is_none(),
        "off posture must NOT also emit the enforced (pass) row. Envelope: {envelope:#?}",
    );
}

/// `[sigstore] verify = "deny"` in config (explicit affirmation,
/// not the implicit default) must still resolve to the enforced
/// pass row. Differentiates "no posture set" from "operator
/// explicitly chose deny" — both are pass, but the source label in
/// detail changes. This pins the GlobalConfig::get_sigstore_verify
/// → `EnforceModeSource::Config` resolution arm.
#[test]
fn doctor_is_clean_when_sigstore_verify_is_explicit_deny_in_config() {
    let project = TempProject::empty(r#"{"name":"doctor-sigstore","version":"1.0.0"}"#);
    write_sigstore_verify_to_config(&project, "deny");
    let envelope = run_doctor_json(&project);

    let row = find_check(&envelope, "sigstore_verify_enforced").unwrap_or_else(|| {
        panic!(
            "explicit deny in config must emit `sigstore_verify_enforced`. \
             Envelope: {envelope:#?}",
        )
    });
    assert_eq!(
        row["severity"].as_str(),
        Some("pass"),
        "explicit-deny row must be `pass`. Row: {row}",
    );
    let detail = row["detail"].as_str().unwrap_or("");
    assert!(
        detail.contains("deny"),
        "row detail must name the resolved mode; got: {detail}",
    );
}

/// `LPM_PROVENANCE_ENFORCE=off` in env overrides whatever sits in
/// `[sigstore] verify` in the config — env wins over config per
/// the resolution chain. The doctor row's detail must name the env
/// source (not the config source) so the operator knows where to
/// flip the actually-effective knob.
#[test]
fn doctor_env_var_overrides_config_when_resolving_sigstore_posture() {
    let project = TempProject::empty(r#"{"name":"doctor-sigstore","version":"1.0.0"}"#);
    // Config says deny — env says off. Env must win.
    write_sigstore_verify_to_config(&project, "deny");

    let output = lpm_with_registry(&project, "http://127.0.0.1:1")
        .env("LPM_PROVENANCE_ENFORCE", "off")
        .args(["doctor", "--all", "--json"])
        .output()
        .expect("failed to run lpm doctor --all --json with env override");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let envelope: Value = serde_json::from_str(stdout.trim())
        .unwrap_or_else(|e| panic!("doctor --json must parse: {e}\nraw: {stdout}"));

    let row = find_check(&envelope, "sigstore_verify_disabled").unwrap_or_else(|| {
        panic!(
            "env=off + config=deny must resolve to disabled (env wins). \
             Envelope: {envelope:#?}",
        )
    });
    let detail = row["detail"].as_str().unwrap_or("");
    assert!(
        detail.contains("LPM_PROVENANCE_ENFORCE env"),
        "row detail must name the env source (not config); got: {detail}",
    );
}
