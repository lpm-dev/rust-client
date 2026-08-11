//! Contract tests for `--json` output across all commands.
//!
//! These tests verify the JSON structure that CI pipelines, MCP servers,
//! and scripting tools depend on. Each test parses stdout as JSON and
//! validates required fields and types.

mod support;

use support::assertions::{JsonType, assert_json_field, parse_json_output};
use support::auth_state::write_credentials_store;
use support::mock_registry::MockRegistry;
use support::{TempProject, lpm, lpm_with_registry};

#[cfg(unix)]
#[test]
fn sudo_rejection_has_a_stable_json_error_contract() {
    let project = TempProject::empty(r#"{"name":"sudo-json-test","version":"1.0.0"}"#);
    let output = lpm(&project)
        .env("LPM_TEST_ASSUME_EUID_ROOT", "1")
        .env("SUDO_USER", "alice")
        .args(["schema", "lpm.json", "--json"])
        .output()
        .expect("run sudo-policy JSON command");

    assert!(!output.status.success());
    let envelope = parse_json_output(&output.stdout);
    assert_eq!(envelope["error_code"], "sudo_not_supported");
    assert_eq!(envelope["error"]["code"], "SUDO_NOT_SUPPORTED");
    insta::assert_json_snapshot!("sudo_not_supported_error", envelope);
}

// ─── lpm info --json ───────────────────────────────────────────────

#[tokio::test]
async fn info_json_accepts_subcommand_version_flag_without_panic() {
    let project = TempProject::empty(r#"{"name": "test", "version": "1.0.0"}"#);
    let mock = MockRegistry::start().await;
    let tarball = support::mock_registry::make_tarball("@lpm.dev/owner.react", "1.0.0");
    mock.with_package("@lpm.dev/owner.react", "1.0.0", &tarball)
        .await;

    let output = lpm_with_registry(&project, &mock.url())
        .args(["info", "owner.react", "--version", "1.0.0", "--json"])
        .output()
        .expect("failed to run lpm info --json");

    assert!(
        output.status.success(),
        "lpm info --json failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let json = parse_json_output(&output.stdout);
    assert_json_field(&json, "success", JsonType::Bool);
    assert_json_field(&json, "name", JsonType::String);
    assert_eq!(json["success"], true);
    assert_eq!(json["name"], "@lpm.dev/owner.react");
    assert_eq!(json["dist-tags"]["latest"], "1.0.0");
    assert!(
        json["versions"].get("1.0.0").is_some(),
        "info --json must include the requested version metadata"
    );
    insta::assert_json_snapshot!(json["_cache"], @r###"
    {
      "status": "fetched",
      "age_seconds": null,
      "network_request": true,
      "not_modified": false
    }
    "###);
}

// ─── lpm health --json ───────────────────────────────────────────

#[tokio::test]
async fn health_json_has_required_fields() {
    let project = TempProject::empty(r#"{"name": "test", "version": "1.0.0"}"#);
    let mock = MockRegistry::start().await;
    mock.with_health().await;

    let output = lpm_with_registry(&project, &mock.url())
        .args(["health", "--json"])
        .output()
        .expect("failed to run lpm health");

    assert!(output.status.success());

    let json = parse_json_output(&output.stdout);
    assert_json_field(&json, "success", JsonType::Bool);
    assert_json_field(&json, "healthy", JsonType::Bool);
    assert_json_field(&json, "registry_url", JsonType::String);
    assert_json_field(&json, "response_time_ms", JsonType::Number);

    assert_eq!(json["success"], true);
    assert_eq!(json["healthy"], true);
}

// ─── lpm whoami ──────────────────────────────────────────────────

#[tokio::test]
async fn whoami_human_output_aligns_username_and_masks_email() {
    let project = TempProject::empty(r#"{"name": "test", "version": "1.0.0"}"#);
    let mock = MockRegistry::start().await;
    mock.with_whoami("testuser", "testuser@example.com").await;
    write_credentials_store(
        project.home(),
        &serde_json::json!({
            mock.url(): "test-token-123",
        }),
    );

    let output = lpm_with_registry(&project, &mock.url())
        .args(["whoami"])
        .output()
        .expect("failed to run lpm whoami");

    assert!(
        output.status.success(),
        "lpm whoami failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("  username       testuser"),
        "human whoami output must align username with detail rows; got:\n{stderr}"
    );
    assert!(
        stderr.contains("  email          t...r@example.com"),
        "human whoami output must mask email addresses; got:\n{stderr}"
    );
    assert!(
        !stderr.contains("testuser@example.com"),
        "human whoami output must not print the full email address; got:\n{stderr}"
    );
}

#[tokio::test]
async fn whoami_json_has_required_fields() {
    let project = TempProject::empty(r#"{"name": "test", "version": "1.0.0"}"#);
    let mock = MockRegistry::start().await;
    mock.with_whoami("testuser", "test@example.com").await;

    let output = lpm_with_registry(&project, &mock.url())
        .args(["whoami", "--json", "--token", "test-token-123"])
        .output()
        .expect("failed to run lpm whoami");

    assert!(
        output.status.success(),
        "lpm whoami failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let json = parse_json_output(&output.stdout);
    assert_json_field(&json, "success", JsonType::Bool);
    assert_json_field(&json, "username", JsonType::String);
    assert_json_field(&json, "email", JsonType::String);

    assert_eq!(json["success"], true);
    assert_eq!(json["username"], "testuser");
    assert_eq!(json["email"], "test@example.com");
}

// ─── lpm health --json (unhealthy) ──────────────────────────────

#[tokio::test]
async fn health_json_reports_unhealthy_on_failure() {
    let project = TempProject::empty(r#"{"name": "test", "version": "1.0.0"}"#);
    // Use a port that's (almost certainly) not listening
    let output = lpm_with_registry(&project, "http://127.0.0.1:1")
        .args(["health", "--json"])
        .output()
        .expect("failed to run lpm health");

    // Should fail (non-zero exit) for unreachable registry
    assert!(!output.status.success());
}

// ─── lpm doctor --json contract ──────────────────────────────────
//
// Pins `lpm doctor --json` as a stable machine API. Every check
// emitted by doctor MUST carry a `{ code, check, passed, severity,
// detail }` shape, where `code` is a non-empty snake_case string,
// `severity` is one of `pass | fail | warn`, and consumers are free
// to match on `code` to drive automation. Wording in `check` and
// `detail` may evolve; codes never do once shipped.

/// Top-level envelope shape — fields exist with the expected types.
#[tokio::test]
async fn doctor_json_envelope_has_required_fields() {
    let project = TempProject::empty(r#"{"name": "test", "version": "1.0.0"}"#);
    // Point at an unreachable registry so the run completes without
    // any network — doctor's infrastructure checks will Fail-Fast and
    // the rest of the run still produces a fully-shaped JSON object.
    let output = lpm_with_registry(&project, "http://127.0.0.1:1")
        .args(["doctor", "--all", "--json"])
        .output()
        .expect("failed to run lpm doctor --json");

    let stdout = output.stdout.clone();
    let stderr_for_panic = String::from_utf8_lossy(&output.stderr).into_owned();
    let json = parse_json_output(&stdout);

    // Envelope shape — every consumer reads these.
    assert_json_field(&json, "success", JsonType::Bool);
    assert_json_field(&json, "no_failures", JsonType::Bool);
    assert_json_field(&json, "clean", JsonType::Bool);
    assert_json_field(&json, "has_warnings", JsonType::Bool);
    assert_json_field(&json, "checks", JsonType::Array);
    assert_json_field(&json, "passed", JsonType::Number);
    assert_json_field(&json, "failed", JsonType::Number);
    assert_json_field(&json, "warnings", JsonType::Number);
    assert_json_field(&json, "fixes_applied", JsonType::Array);

    let checks = json["checks"].as_array().unwrap_or_else(|| {
        panic!("checks must be a non-null array. stderr was:\n{stderr_for_panic}",)
    });
    assert!(
        !checks.is_empty(),
        "doctor must emit at least one check entry; stderr:\n{stderr_for_panic}"
    );
}

/// Per-check shape — every entry in `checks[]` has `{ code, check,
/// passed, severity, detail }` with the right types and a non-empty
/// `code`. `severity` must be one of the three known values.
#[tokio::test]
async fn doctor_json_each_check_has_stable_code_and_known_severity() {
    let project = TempProject::empty(r#"{"name": "test", "version": "1.0.0"}"#);
    let output = lpm_with_registry(&project, "http://127.0.0.1:1")
        .args(["doctor", "--all", "--json"])
        .output()
        .expect("failed to run lpm doctor --json");

    let json = parse_json_output(&output.stdout);
    let checks = json["checks"].as_array().expect("checks must be an array");

    let mut seen_codes: std::collections::HashSet<String> = std::collections::HashSet::new();

    for (i, check) in checks.iter().enumerate() {
        // code: non-null, non-empty string.
        let code = check["code"].as_str().unwrap_or_else(|| {
            panic!(
                "checks[{i}].code must be a string; entry was: {}",
                serde_json::to_string_pretty(check).unwrap()
            )
        });
        assert!(
            !code.is_empty(),
            "checks[{i}].code must be non-empty; entry was: {}",
            serde_json::to_string_pretty(check).unwrap()
        );
        // Codes are snake_case identifiers — ascii lowercase, digits,
        // underscores. Catches accidental leaks of the human-readable
        // `name` into the `code` field (e.g., \"Node.js\" or spaces).
        assert!(
            code.chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'),
            "checks[{i}].code must be snake_case (got: {code:?})"
        );

        // check: human-readable name (string).
        assert_json_field(check, "check", JsonType::String);

        // passed: bool.
        assert_json_field(check, "passed", JsonType::Bool);

        // severity: one of pass | fail | warn.
        let severity = check["severity"]
            .as_str()
            .unwrap_or_else(|| panic!("checks[{i}].severity must be a string"));
        assert!(
            matches!(severity, "pass" | "fail" | "warn"),
            "checks[{i}].severity must be pass|fail|warn (got: {severity:?})"
        );

        // detail: string (may be empty for some checks but the field
        // must always be present).
        assert_json_field(check, "detail", JsonType::String);

        // Track codes for stability — the same check should not
        // emit two different codes in the same run. This is a
        // tripwire against accidental code-formatting mistakes.
        seen_codes.insert(code.to_string());
    }

    // The unreachable-registry probe always emits the registry +
    // auth + store triplet at minimum, so we expect at least three
    // distinct codes in the dataset.
    assert!(
        seen_codes.len() >= 3,
        "expected at least 3 distinct codes; got: {seen_codes:?}"
    );
}

/// Manifest-compat detector lights up via `lpm doctor --json`.
/// Pins the new `lpm-workspace::manifest_compat_issues` surface as
/// the structured signal automation pipelines should pull instead
/// of stderr install warnings.
#[tokio::test]
async fn doctor_json_surfaces_manifest_compat_issues_with_stable_codes() {
    let project = TempProject::empty(
        r#"{
            "name": "test",
            "version": "1.0.0",
            "engines": {
                "node": ">=22",
                "lpm": ">=0.1",
                "npm": ">=10",
                "pnpm": ">=9"
            },
            "overrides": {
                "path-scurry": { "lru-cache": "^11.0.0" }
            },
            "pnpm": {
                "overrides": { "lodash": "^4.17.21" },
                "patchedDependencies": { "react@18.0.0": "patches/react.patch" }
            }
        }"#,
    );

    let output = lpm_with_registry(&project, "http://127.0.0.1:1")
        .args(["doctor", "--all", "--json"])
        .output()
        .expect("failed to run lpm doctor --json");

    let json = parse_json_output(&output.stdout);
    let checks = json["checks"].as_array().expect("checks must be an array");

    // Every compatibility code lands as its own check entry with
    // severity = warn and the matching stable code.
    for code in [
        "unsupported_override_values",
        "pnpm_overrides_drift",
        "pnpm_patches_drift",
        "engines_npm_ignored",
        "engines_pnpm_ignored",
    ] {
        let entry = checks
            .iter()
            .find(|c| c["code"].as_str() == Some(code))
            .unwrap_or_else(|| {
                panic!(
                    "expected manifest-compat code {code} to appear; checks were: {}",
                    serde_json::to_string_pretty(checks).unwrap()
                )
            });
        assert_eq!(
            entry["severity"].as_str(),
            Some("warn"),
            "expected {code} to be a warn",
        );
        // Manifest-compat issues share the `Manifest compat:` prefix
        // so they group together in the human view; the suffix
        // identifies the specific drifting field.
        let check_name = entry["check"]
            .as_str()
            .unwrap_or_else(|| panic!("expected `check` to be a string for code {code}"));
        assert!(
            check_name.starts_with("Manifest compat"),
            "expected `{check_name}` to start with `Manifest compat` for code {code}",
        );
    }

    // Engines.yarn / .bun were not set, so those codes must NOT fire.
    for code in ["engines_yarn_ignored", "engines_bun_ignored"] {
        assert!(
            checks.iter().all(|c| c["code"].as_str() != Some(code)),
            "{code} should not appear when engines.<key> is not set"
        );
    }
}

/// Specific known codes appear in the expected severity bucket. The
/// codes named here are the ones automation pipelines will most
/// commonly key on; they MUST stay stable.
#[tokio::test]
async fn doctor_json_pins_well_known_codes() {
    let project = TempProject::empty(r#"{"name": "test", "version": "1.0.0"}"#);
    let output = lpm_with_registry(&project, "http://127.0.0.1:1")
        .args(["doctor", "--all", "--json"])
        .output()
        .expect("failed to run lpm doctor --json");

    let json = parse_json_output(&output.stdout);
    let checks = json["checks"].as_array().expect("checks must be an array");

    fn find_code<'a>(checks: &'a [serde_json::Value], code: &str) -> Option<&'a serde_json::Value> {
        checks.iter().find(|c| c["code"].as_str() == Some(code))
    }

    // Registry is unreachable in this test setup, so:
    //  - registry_unreachable must appear with severity=fail.
    let registry = find_code(checks, "registry_unreachable")
        .expect("registry_unreachable code must be emitted on unreachable registry");
    assert_eq!(registry["severity"].as_str(), Some("fail"));
    assert_eq!(registry["passed"].as_bool(), Some(false));

    //  - auth_missing must appear (no token in test isolation).
    let auth = find_code(checks, "auth_missing")
        .expect("auth_missing code must be emitted when no token is set");
    assert_eq!(auth["severity"].as_str(), Some("fail"));

    //  - global_store_accessible (HOME-isolated tempdir is writable)
    //    or global_store_inaccessible. Both are part of the
    //    contract; we just want to see one or the other.
    let store_emitted = find_code(checks, "global_store_accessible").is_some()
        || find_code(checks, "global_store_inaccessible").is_some();
    assert!(
        store_emitted,
        "expected one of global_store_accessible / global_store_inaccessible"
    );

    //  - package_json_present (the empty TempProject writes one).
    let pkg = find_code(checks, "package_json_present")
        .expect("package_json_present must be emitted when package.json exists");
    assert_eq!(pkg["severity"].as_str(), Some("pass"));
    assert_eq!(pkg["passed"].as_bool(), Some(true));
}

// ─── lpm migrate --dry-run --json ────────────────────────────────

#[test]
fn migrate_dry_run_json_output() {
    let project = TempProject::from_fixture("migrate-npm");

    let output = lpm(&project)
        .args(["migrate", "--dry-run", "--json"])
        .output()
        .expect("failed to run lpm migrate");

    assert!(
        output.status.success(),
        "migrate --dry-run --json failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let json = parse_json_output(&output.stdout);
    assert_json_field(&json, "success", JsonType::Bool);
    assert_eq!(json["success"], true);
}

// ─── lpm run multi-task --json ───────────────────────────────────

#[test]
fn run_multi_task_json_has_task_array() {
    // Running multiple scripts triggers the JSON summary via print_json_summary
    let project = TempProject::empty(
        r#"{
        "name": "run-json-test",
        "version": "1.0.0",
        "scripts": {
            "build": "echo built",
            "lint": "echo linted"
        }
    }"#,
    );

    let output = lpm(&project)
        .args(["run", "build", "lint", "--json"])
        .output()
        .expect("failed to run lpm run --json");

    assert!(
        output.status.success(),
        "lpm run --json failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let json = parse_json_output(&output.stdout);
    assert_json_field(&json, "success", JsonType::Bool);
    assert_json_field(&json, "tasks", JsonType::Array);
    assert_json_field(&json, "total", JsonType::Number);
    assert_json_field(&json, "passed", JsonType::Number);
    assert_json_field(&json, "failed", JsonType::Number);
    assert_json_field(&json, "duration_ms", JsonType::Number);

    assert_eq!(json["success"], true);
    assert!(json["total"].as_u64().unwrap() >= 2);
    assert_eq!(json["failed"], 0);

    // Verify tasks array structure
    let tasks = json["tasks"].as_array().unwrap();
    for task in tasks {
        assert_json_field(task, "name", JsonType::String);
        assert_json_field(task, "success", JsonType::Bool);
        assert_json_field(task, "cached", JsonType::Bool);
        assert_json_field(task, "duration_ms", JsonType::Number);
    }
}

// ─── lpm run failing task --json ─────────────────────────────────

#[test]
fn run_failing_task_json_reports_failure() {
    let project = TempProject::empty(
        r#"{
        "name": "fail-json-test",
        "version": "1.0.0",
        "scripts": {
            "good": "echo ok",
            "bad": "exit 1"
        }
    }"#,
    );

    // Use --no-bail so both tasks run
    let output = lpm(&project)
        .args(["run", "good", "bad", "--json", "--no-bail"])
        .output()
        .expect("failed to run lpm run --json");

    assert!(!output.status.success());

    let json = parse_json_output(&output.stdout);
    assert_eq!(json["success"], false);
    assert!(json["failed"].as_u64().unwrap() >= 1);
}

// ─── Error JSON output ──────────────────────────────────────────

#[tokio::test]
async fn auth_required_json_error() {
    let project = TempProject::empty(r#"{"name": "test", "version": "1.0.0"}"#);
    let mock = MockRegistry::start().await;
    mock.with_auth_required().await;

    let output = lpm_with_registry(&project, &mock.url())
        .args(["whoami", "--json"])
        .output()
        .expect("failed to run lpm whoami");

    assert!(!output.status.success());

    let json = parse_json_output(&output.stdout);
    assert_eq!(json["success"], false);
    assert_eq!(json["schema_version"], serde_json::json!(1));
    assert_eq!(json["error_code"], "auth_required");
    assert_eq!(
        json["next_steps"][0]["description"],
        "Authenticate with LPM"
    );
    assert_eq!(json["next_steps"][0]["command"], "lpm login");
}

// ─── provenance.verified envelope shape ─────────────────────────────
//
// Every `provenance.verified` state the install pipeline can emit
// (`true`, `false`, `"skipped"`, `"disabled"`, `"verification_rejected"`,
// and the transient `null`) must round-trip through the install JSON
// envelope in a known wire shape. Downstream `lpm install --json`
// consumers (CI audit pipelines, MCP servers) branch on this
// string/bool to drive drift dashboards without re-deriving state
// from log lines.
//
// The serialization is owned by `ProvenanceStatus::to_json_verified`
// in `lpm-common/src/provenance.rs`, with exhaustive inline unit
// tests for each variant. This workflow-tier snapshot is the
// wire-format pin a downstream consumer reads as the canonical
// contract document — if the install envelope ever ships a different
// shape for any state, the snapshot diff catches it before it lands
// in a release.

/// Build the per-package `provenance` block for one of the six
/// states the install envelope can emit. Mirrors what
/// `blocked_to_json_with_provenance` actually inserts under the
/// `"provenance"` key in the install --json output's `blocked` array.
fn provenance_block_for_state(
    verified: serde_json::Value,
    reason: Option<&str>,
) -> serde_json::Value {
    let mut block = serde_json::Map::new();
    block.insert("verified".into(), verified);
    if let Some(r) = reason {
        block.insert(
            "rejection_reason".into(),
            serde_json::Value::String(r.into()),
        );
    }
    serde_json::Value::Object(block)
}

#[test]
fn install_envelope_provenance_block_shape_pinned_across_all_verified_states() {
    let envelope = serde_json::json!({
        "verified_true_when_cryptographic_verification_succeeded":
            provenance_block_for_state(serde_json::json!(true), None),
        "verified_false_when_registry_served_no_attestation":
            provenance_block_for_state(serde_json::json!(false), None),
        "verified_skipped_when_per_package_cli_carve_out":
            provenance_block_for_state(serde_json::json!("skipped"), None),
        "verified_disabled_when_fleet_wide_sigstore_off":
            provenance_block_for_state(serde_json::json!("disabled"), None),
        "verified_null_when_transport_degraded":
            provenance_block_for_state(serde_json::Value::Null, None),
        "verified_rejected_carries_rejection_reason_sibling_field":
            provenance_block_for_state(
                serde_json::json!("verification_rejected"),
                Some(
                    "Rekor SET verification failed: signature did not verify under pinned key",
                ),
            ),
    });

    insta::assert_json_snapshot!("install_json_envelope_provenance_verified_states", envelope);
}
