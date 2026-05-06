//! Workflow tests for `lpm doctor list` (catalog inventory surface)
//! and the drift-guard that pins every emitted code to the catalog.
//!
//! `lpm doctor list` is the canonical inventory of every check
//! `lpm doctor` can emit. The catalog is the source of truth: it
//! drives `lpm doctor`'s own constructors (each `Check` carries a
//! `&'static CheckEntry`) AND the docs generation table. The
//! drift-guard test here is the binary-level guarantee that
//! `lpm doctor` cannot emit a code that isn't in the catalog —
//! the constructor would refuse to compile, and any future
//! refactor that loosens that signature is caught here.

mod support;

use std::collections::HashSet;
use support::assertions::parse_json_output;
use support::{TempProject, lpm, lpm_with_registry};

fn read_catalog_codes() -> HashSet<String> {
    let project = TempProject::empty(r#"{"name":"x","version":"1.0.0"}"#);
    let output = lpm(&project)
        .args(["--json", "doctor", "list"])
        .output()
        .expect("failed to run lpm doctor list --json");
    assert!(
        output.status.success(),
        "doctor list failed; stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json = parse_json_output(&output.stdout);
    json["entries"]
        .as_array()
        .expect("entries must be an array")
        .iter()
        .map(|e| {
            e["code"]
                .as_str()
                .expect("each entry must have a code")
                .to_string()
        })
        .collect()
}

#[test]
fn doctor_list_envelope_shape() {
    let project = TempProject::empty(r#"{"name":"x","version":"1.0.0"}"#);
    let output = lpm(&project)
        .args(["--json", "doctor", "list"])
        .output()
        .expect("failed to run lpm doctor list --json");
    assert!(output.status.success());

    let json = parse_json_output(&output.stdout);
    assert_eq!(json["success"], serde_json::json!(true));
    let count = json["count"].as_u64().expect("count must be a number");
    let entries = json["entries"]
        .as_array()
        .expect("entries must be an array");
    assert_eq!(
        count as usize,
        entries.len(),
        "envelope count must match entries length"
    );
    assert!(!entries.is_empty(), "catalog must be non-empty");
}

#[test]
fn doctor_list_each_entry_has_required_fields() {
    let project = TempProject::empty(r#"{"name":"x","version":"1.0.0"}"#);
    let output = lpm(&project)
        .args(["--json", "doctor", "list"])
        .output()
        .expect("failed to run lpm doctor list --json");
    let json = parse_json_output(&output.stdout);
    let entries = json["entries"]
        .as_array()
        .expect("entries must be an array");

    for entry in entries {
        // `check` is the human-readable label, matching the field name
        // used by `lpm doctor --json` so consumers using both surfaces
        // can match on one schema.
        for field in [
            "code",
            "check",
            "category",
            "description",
            "when_fires",
            "remediation",
        ] {
            assert!(
                entry[field].is_string() && !entry[field].as_str().unwrap().is_empty(),
                "field `{field}` must be a non-empty string. entry: {entry}"
            );
        }
        let severities = entry["possible_severities"]
            .as_array()
            .unwrap_or_else(|| panic!("possible_severities must be an array. entry: {entry}"));
        assert!(
            !severities.is_empty(),
            "possible_severities must be non-empty. entry: {entry}"
        );
        for s in severities {
            let s = s.as_str().expect("each severity must be a string");
            assert!(
                matches!(s, "pass" | "warn" | "fail"),
                "unknown severity `{s}` in entry: {entry}"
            );
        }
        // auto_fix may be null OR a non-empty string.
        let auto = &entry["auto_fix"];
        assert!(
            auto.is_null() || auto.is_string(),
            "auto_fix must be null or string; got: {auto}"
        );
    }
}

#[test]
fn doctor_list_filter_by_code_returns_single_entry() {
    let project = TempProject::empty(r#"{"name":"x","version":"1.0.0"}"#);
    let output = lpm(&project)
        .args([
            "--json",
            "doctor",
            "list",
            "--code",
            "typescript_unavailable",
        ])
        .output()
        .expect("failed to run lpm doctor list --json --code");
    let json = parse_json_output(&output.stdout);
    assert_eq!(json["count"], serde_json::json!(1));
    assert_eq!(
        json["entries"][0]["code"],
        serde_json::json!("typescript_unavailable")
    );
    assert_eq!(
        json["entries"][0]["category"],
        serde_json::json!("TypeScript")
    );
}

#[test]
fn doctor_list_filter_by_code_typo_exits_nonzero_and_emits_single_json_envelope() {
    // `--code` is exact-match: a typo should fail loudly so automation
    // gating on a specific code doesn't silently pass when the code
    // doesn't exist. JSON mode must still emit a single valid JSON
    // document (the standard `LpmError` envelope) — no double-emit.
    let project = TempProject::empty(r#"{"name":"x","version":"1.0.0"}"#);
    let output = lpm(&project)
        .args(["--json", "doctor", "list", "--code", "does_not_exist"])
        .output()
        .expect("failed to run lpm doctor list --json --code typo");

    assert!(
        !output.status.success(),
        "lpm doctor list --code <typo> must exit non-zero. exit: {}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let raw = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(raw.trim()).unwrap_or_else(|e| {
        panic!("stdout must be a single valid JSON document. Parse error: {e}\nRaw stdout:\n{raw}")
    });
    assert_eq!(json["success"], serde_json::json!(false));
    assert_eq!(
        json["error_code"].as_str(),
        Some("script"),
        "expected canonical error_code = `script`; got: {}",
        json["error_code"]
    );
    assert!(
        json["error"]
            .as_str()
            .unwrap_or("")
            .contains("does_not_exist"),
        "error message should name the offending code; got: {}",
        json["error"]
    );
}

#[test]
fn doctor_list_filter_by_category_returns_subset() {
    let project = TempProject::empty(r#"{"name":"x","version":"1.0.0"}"#);
    let output = lpm(&project)
        .args(["--json", "doctor", "list", "--category", "tunnel"])
        .output()
        .expect("failed to run lpm doctor list --json --category");
    let json = parse_json_output(&output.stdout);
    let entries = json["entries"]
        .as_array()
        .expect("entries must be an array");
    assert!(
        !entries.is_empty(),
        "tunnel category must have at least one entry"
    );
    for entry in entries {
        assert_eq!(entry["category"], serde_json::json!("Tunnel"));
    }
}

#[test]
fn doctor_list_includes_typescript_codes_from_tranche_1() {
    let codes = read_catalog_codes();
    for code in [
        "typescript_healthy",
        "typescript_missing_for_tsconfig",
        "typescript_unavailable",
    ] {
        assert!(
            codes.contains(code),
            "catalog missing TypeScript code `{code}`"
        );
    }
}

#[test]
fn doctor_list_includes_manifest_compat_codes() {
    let codes = read_catalog_codes();
    for code in [
        "pnpm_overrides_drift",
        "pnpm_patches_drift",
        "pnpm_peer_rules_drift",
        "engines_npm_ignored",
        "engines_pnpm_ignored",
        "engines_yarn_ignored",
        "engines_bun_ignored",
    ] {
        assert!(
            codes.contains(code),
            "catalog missing manifest-compat code `{code}`"
        );
    }
}

// ─── Drift-guard: every emitted runtime code is registered ────────

/// The structural promise of the catalog: `lpm doctor` cannot emit a
/// code that isn't in `lpm doctor list`. We verify this by taking
/// the union of codes the runtime actually emits across two
/// fixtures (an unreachable-registry probe + a manifest-compat
/// fixture) and asserting every code is in the catalog.
///
/// A failure here means a constructor was added that bypasses the
/// catalog, OR a runtime detector is emitting a code the catalog
/// doesn't carry. Either way the inventory surface is no longer
/// canonical and needs to be re-aligned before merge.
#[test]
fn every_runtime_emitted_code_is_in_the_catalog() {
    let catalog: HashSet<String> = read_catalog_codes();

    // Fixture 1: empty project pointed at an unreachable registry.
    // Surfaces infrastructure / auth / project-state codes.
    let proj_a = TempProject::empty(r#"{"name":"x","version":"1.0.0"}"#);
    let out_a = lpm_with_registry(&proj_a, "http://127.0.0.1:1")
        .args(["doctor", "--json"])
        .output()
        .expect("failed to run lpm doctor --json (fixture A)");
    let json_a = parse_json_output(&out_a.stdout);

    // Fixture 2: manifest with engines + pnpm fields → exercises the
    // manifest-compat detectors so workspace-owned codes land in the
    // emitted set.
    let proj_b = TempProject::empty(
        r#"{
            "name":"y","version":"1.0.0",
            "engines":{"node":">=22","npm":">=10","pnpm":">=9","yarn":">=4","bun":">=1"},
            "pnpm":{
                "overrides":{"lodash":"^4.17.21"},
                "patchedDependencies":{"react@18.0.0":"patches/react.patch"},
                "peerDependencyRules":{"ignoreMissing":["react"]}
            }
        }"#,
    );
    let out_b = lpm_with_registry(&proj_b, "http://127.0.0.1:1")
        .args(["doctor", "--json"])
        .output()
        .expect("failed to run lpm doctor --json (fixture B)");
    let json_b = parse_json_output(&out_b.stdout);

    let mut emitted: HashSet<String> = HashSet::new();
    for json in [&json_a, &json_b] {
        for check in json["checks"].as_array().expect("checks must be an array") {
            let code = check["code"]
                .as_str()
                .expect("each check must have a string code");
            emitted.insert(code.to_string());
        }
    }

    assert!(!emitted.is_empty(), "fixtures must emit at least one check");

    let unregistered: Vec<&String> = emitted.difference(&catalog).collect();
    assert!(
        unregistered.is_empty(),
        "runtime emitted code(s) not in the catalog: {unregistered:?}"
    );
}
