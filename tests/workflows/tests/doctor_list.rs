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

use std::collections::{BTreeMap, HashSet};
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
fn doctor_list_auto_fix_metadata_matches_every_supported_runtime_action() {
    let project = TempProject::empty(r#"{"name":"x","version":"1.0.0"}"#);
    let output = lpm(&project)
        .args(["--json", "doctor", "list"])
        .output()
        .expect("failed to run lpm doctor list --json");
    let json = parse_json_output(&output.stdout);
    let actual: BTreeMap<&str, &str> = json["entries"]
        .as_array()
        .expect("entries must be an array")
        .iter()
        .filter_map(|entry| Some((entry["code"].as_str()?, entry["auto_fix"].as_str()?)))
        .collect();
    let expected = BTreeMap::from([
        ("bun_missing_pinned", "lpm use bun@<spec>"),
        ("bun_pinned_unmet", "lpm use bun@<spec>"),
        ("deps_sync_drift", "lpm install"),
        ("fmt_other_issue", "lpm fmt"),
        ("fmt_unformatted", "lpm fmt"),
        ("gitattributes_lockb_unmarked", "update .gitattributes"),
        ("gitattributes_missing", "update .gitattributes"),
        ("lockfile_binary_corrupt", "reconcile lpm.lockb"),
        ("lockfile_binary_missing", "reconcile lpm.lockb"),
        ("lockfile_binary_stale", "reconcile lpm.lockb"),
        ("lockfile_missing", "lpm install"),
        ("node_missing_pinned", "lpm use node@<spec>"),
        ("node_missing_unpinned", "lpm use node@22"),
        ("node_modules_legacy_layout", "lpm install"),
        ("node_modules_missing", "lpm install"),
        ("node_modules_mixed_layout", "lpm install"),
        ("node_modules_no_store", "lpm install"),
        ("node_modules_symlinked", "lpm doctor --fix"),
        ("node_pinned_unmet", "lpm use node@<spec>"),
        ("plugin_update_available", "lpm plugin update <name>"),
        ("tunnel_not_claimed", "lpm tunnel claim <domain>"),
        ("v2_store_orphans", "lpm cache prune --apply"),
    ]);

    assert_eq!(actual, expected);
    insta::assert_json_snapshot!("doctor_list_auto_fix_actions", actual);
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
fn doctor_list_tunnel_reachability_metadata_matches_runtime_contract() {
    let project = TempProject::empty(r#"{"name":"x","version":"1.0.0"}"#);
    let output = lpm(&project)
        .args(["--json", "doctor", "list", "--category", "tunnel"])
        .output()
        .expect("failed to run lpm doctor list --json --category tunnel");
    assert!(
        output.status.success(),
        "doctor list failed; stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let json = parse_json_output(&output.stdout);
    let relevant_codes = [
        "tunnel_active",
        "tunnel_idle",
        "tunnel_unreachable",
        "tunnel_unverified",
    ];
    let actual: BTreeMap<&str, serde_json::Value> = json["entries"]
        .as_array()
        .expect("entries must be an array")
        .iter()
        .filter_map(|entry| {
            let code = entry["code"].as_str()?;
            relevant_codes.contains(&code).then(|| {
                (
                    code,
                    serde_json::json!({
                        "description": entry["description"],
                        "when_fires": entry["when_fires"],
                        "remediation": entry["remediation"],
                    }),
                )
            })
        })
        .collect();

    let expected = BTreeMap::from([
        (
            "tunnel_active",
            serde_json::json!({
                "description": "The configured tunnel domain is claimed by your account and responds to a request.",
                "when_fires": "Ownership lookup succeeds, and the reachability request returns a status other than 404.",
                "remediation": "No action — informational pass.",
            }),
        ),
        (
            "tunnel_idle",
            serde_json::json!({
                "description": "The configured tunnel domain is claimed by your account, but no tunnel is active.",
                "when_fires": "Ownership lookup succeeds, and the reachability request returns 404.",
                "remediation": "No action — informational pass.",
            }),
        ),
        (
            "tunnel_unreachable",
            serde_json::json!({
                "description": "Your account owns the configured tunnel domain, but the domain did not respond.",
                "when_fires": "Ownership lookup succeeds, but the HTTPS reachability request fails.",
                "remediation": "Examine DNS and tunnel state. Then run `lpm doctor` again.",
            }),
        ),
        (
            "tunnel_unverified",
            serde_json::json!({
                "description": "The registry request for tunnel domain ownership failed.",
                "when_fires": "The registry ownership request fails.",
                "remediation": "Run `lpm health`. Then run `lpm doctor` again.",
            }),
        ),
    ]);

    assert_eq!(actual, expected);
    insta::assert_json_snapshot!("doctor_list_tunnel_reachability_metadata", actual);
}

#[test]
fn doctor_list_global_manifest_metadata_matches_toml_contract() {
    let project = TempProject::empty(r#"{"name":"x","version":"1.0.0"}"#);
    let output = lpm(&project)
        .args(["--json", "doctor", "list", "--category", "global"])
        .output()
        .expect("failed to run lpm doctor list --json --category global");
    assert!(
        output.status.success(),
        "doctor list failed; stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let json = parse_json_output(&output.stdout);
    let relevant_codes = [
        "global_manifest_absent",
        "global_manifest_corrupt",
        "global_manifest_structurally_invalid",
        "global_manifest_valid",
    ];
    let actual: BTreeMap<&str, serde_json::Value> = json["entries"]
        .as_array()
        .expect("entries must be an array")
        .iter()
        .filter_map(|entry| {
            let code = entry["code"].as_str()?;
            relevant_codes.contains(&code).then(|| {
                (
                    code,
                    serde_json::json!({
                        "description": entry["description"],
                        "when_fires": entry["when_fires"],
                        "remediation": entry["remediation"],
                    }),
                )
            })
        })
        .collect();

    let expected = BTreeMap::from([
        (
            "global_manifest_absent",
            serde_json::json!({
                "description": "The global install manifest does not exist.",
                "when_fires": "`~/.lpm/global/manifest.toml` does not exist.",
                "remediation": "No action is necessary.",
            }),
        ),
        (
            "global_manifest_corrupt",
            serde_json::json!({
                "description": "LPM cannot read `~/.lpm/global/manifest.toml` as a supported TOML manifest.",
                "when_fires": "The file is unreadable, is not valid UTF-8 or TOML, or uses a newer schema version.",
                "remediation": "Repair `~/.lpm/global/manifest.toml`, or reinstall the affected global packages.",
            }),
        ),
        (
            "global_manifest_structurally_invalid",
            serde_json::json!({
                "description": "`~/.lpm/global/manifest.toml` contains an invalid package, pending recovery, alias, or tombstone record.",
                "when_fires": "The manifest parses, but a record fails global install validation.",
                "remediation": "Repair the affected records, or reinstall the affected global packages.",
            }),
        ),
        (
            "global_manifest_valid",
            serde_json::json!({
                "description": "`~/.lpm/global/manifest.toml` contains valid TOML and valid global install records.",
                "when_fires": "The manifest exists, parses as TOML, uses a supported schema, and passes structural validation.",
                "remediation": "No action is necessary.",
            }),
        ),
    ]);

    assert_eq!(actual, expected);
    insta::assert_json_snapshot!("doctor_list_global_manifest_metadata", actual);
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
        "unsupported_override_values",
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

    // Both fixtures run `--all` so the union covers infrastructure +
    // auth + manifest-compat codes. The default fast preset deliberately
    // omits those tiers (zero network, zero subprocess); fixture
    // coverage must opt into `--all` to assert their drift-guard.
    let proj_a = TempProject::empty(r#"{"name":"x","version":"1.0.0"}"#);
    let out_a = lpm_with_registry(&proj_a, "http://127.0.0.1:1")
        .args(["doctor", "--all", "--json"])
        .output()
        .expect("failed to run lpm doctor --all --json (fixture A)");
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
        .args(["doctor", "--all", "--json"])
        .output()
        .expect("failed to run lpm doctor --all --json (fixture B)");
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
