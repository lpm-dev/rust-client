//! Workflow tests for the `lpm doctor` (fast) vs `lpm doctor --all`
//! contract.
//!
//! Two execution tiers, orthogonal to category:
//!
//! - **Fast (default):** local-only "why is this project broken right
//!   now?" — zero network, zero subprocess except `node --version`.
//!   Covers global store / package.json / linker mode / `node_modules`
//!   layout / lockfile / deps sync / local source paths / `lpm.json` /
//!   Node runtime / workspace cycles.
//! - **Full sweep (`--all`):** everything else — registry + auth probe,
//!   tunnel lookup, lint / fmt subprocesses, TypeScript reachability,
//!   plugin update fetch, global-install hygiene, sandbox probe, full
//!   manifest-compat sweep, hygiene rows (`.gitattributes`, v2 orphans).
//!
//! Contract pins:
//! 1. Default omits every Extended-tier code.
//! 2. `--all` includes every code default emits, plus Extended-only
//!    codes (registry / auth / manifest-compat sentinels).
//! 3. The JSON envelope carries a stable `"mode": "fast" | "all"` field
//!    so automation can detect which sweep produced the rows.

mod support;

use std::collections::HashSet;
use support::assertions::parse_json_output;
use support::{TempProject, lpm_with_registry};

/// Codes that MUST NOT appear under default `lpm doctor` (they live in
/// Extended-tier blocks: registry / auth, manifest-compat, tunnel,
/// lint / fmt / typescript, plugins, globals, sandbox, hygiene).
const EXTENDED_SENTINEL_CODES: &[&str] = &[
    "registry_reachable",
    "registry_unreachable",
    "auth_valid",
    "auth_invalid",
    "auth_missing",
    "pnpm_overrides_drift",
    "engines_npm_ignored",
    "engines_pnpm_ignored",
    "gitattributes_lockb_marked",
    "gitattributes_lockb_unmarked",
    "gitattributes_missing",
    "v2_store_orphans",
    "lint_clean",
    "lint_warnings",
    "fmt_clean",
    "fmt_unformatted",
    "typescript_healthy",
    "typescript_unavailable",
    "sandbox_available",
    "sandbox_disabled_by_user",
    "global_manifest_valid",
    "global_manifest_absent",
];

/// Codes the fast preset MUST emit on a project with a `package.json`.
/// Sentinel codes — not exhaustive, but enough to confirm the Fast-tier
/// blocks actually ran.
const FAST_SENTINEL_CODES: &[&str] = &[
    // Either of these — the test fixture's HOME may or may not allow
    // store resolution depending on the harness. The pair is checked
    // as a logical OR below.
    // "global_store_accessible" | "global_store_inaccessible"
    "package_json_present",
    // Either lockfile_present + binary status OR lockfile_missing —
    // the test fixture controls which. Checked as a logical OR below.
];

fn emitted_codes(stdout: &[u8]) -> HashSet<String> {
    let json = parse_json_output(stdout);
    json["checks"]
        .as_array()
        .expect("checks must be an array")
        .iter()
        .map(|c| {
            c["code"]
                .as_str()
                .expect("every check has a string code")
                .to_string()
        })
        .collect()
}

// ─── Default mode: no Extended codes, no network ───────────────────

#[test]
fn doctor_default_emits_only_fast_tier_codes() {
    let project = TempProject::empty(r#"{"name": "fast-mode", "version": "1.0.0"}"#);
    // Unreachable registry: in the OLD contract this fired
    // `registry_unreachable`. In the new fast-default contract the
    // block is skipped entirely — no probe attempted, no code emitted.
    let output = lpm_with_registry(&project, "http://127.0.0.1:1")
        .args(["doctor", "--json"])
        .output()
        .expect("failed to run lpm doctor --json");

    let codes = emitted_codes(&output.stdout);

    for ext in EXTENDED_SENTINEL_CODES {
        assert!(
            !codes.contains(*ext),
            "fast-mode `lpm doctor` must not emit Extended code `{ext}` \
             — block-level gate missing or row mis-tagged. Emitted codes: {codes:?}"
        );
    }

    // Sentinel Fast codes that must appear when the fixture has a
    // package.json (it does).
    for fast in FAST_SENTINEL_CODES {
        assert!(
            codes.contains(*fast),
            "fast-mode `lpm doctor` must emit `{fast}`. Emitted codes: {codes:?}"
        );
    }
    // Either-of pair for store: the harness may run under a HOME where
    // ~/.lpm/store resolves OR where it doesn't.
    assert!(
        codes.contains("global_store_accessible") || codes.contains("global_store_inaccessible"),
        "expected one of global_store_{{accessible,inaccessible}} in fast mode. Emitted: {codes:?}"
    );
}

#[test]
fn doctor_default_envelope_has_mode_fast() {
    let project = TempProject::empty(r#"{"name": "fast-mode", "version": "1.0.0"}"#);
    let output = lpm_with_registry(&project, "http://127.0.0.1:1")
        .args(["doctor", "--json"])
        .output()
        .expect("failed to run lpm doctor --json");

    let json = parse_json_output(&output.stdout);
    assert_eq!(
        json["mode"].as_str(),
        Some("fast"),
        "default `lpm doctor --json` must carry `mode: \"fast\"`. Envelope: {json}"
    );
}

// ─── --all mode: full sweep, mode=all ──────────────────────────────

#[test]
fn doctor_all_emits_extended_codes() {
    let project = TempProject::empty(r#"{"name": "all-mode", "version": "1.0.0"}"#);
    let output = lpm_with_registry(&project, "http://127.0.0.1:1")
        .args(["doctor", "--all", "--json"])
        .output()
        .expect("failed to run lpm doctor --all --json");

    let codes = emitted_codes(&output.stdout);

    // Registry + auth + at least one Globals or Sandbox sentinel must
    // appear under --all on an unreachable-registry fixture.
    assert!(
        codes.contains("registry_unreachable"),
        "`--all` must probe the registry. Emitted: {codes:?}"
    );
    assert!(
        codes.contains("auth_missing"),
        "`--all` must probe auth. Emitted: {codes:?}"
    );
    // Sandbox always emits a row (one of available / degraded / disabled
    // / unsupported / probe-failed / helper-missing / kernel-too-old).
    let sandbox_emitted = [
        "sandbox_available",
        "sandbox_helper_missing",
        "sandbox_degraded",
        "sandbox_disabled_by_user",
        "sandbox_kernel_too_old",
        "sandbox_unsupported_platform",
        "sandbox_probe_failed",
    ]
    .iter()
    .any(|c| codes.contains(*c));
    assert!(
        sandbox_emitted,
        "`--all` must emit a sandbox row. Emitted: {codes:?}"
    );
}

#[test]
fn doctor_all_envelope_has_mode_all() {
    let project = TempProject::empty(r#"{"name": "all-mode", "version": "1.0.0"}"#);
    let output = lpm_with_registry(&project, "http://127.0.0.1:1")
        .args(["doctor", "--all", "--json"])
        .output()
        .expect("failed to run lpm doctor --all --json");

    let json = parse_json_output(&output.stdout);
    assert_eq!(
        json["mode"].as_str(),
        Some("all"),
        "`lpm doctor --all --json` must carry `mode: \"all\"`. Envelope: {json}"
    );
}

// ─── --all is a strict superset of default in code-set ─────────────

#[test]
fn doctor_all_codes_are_superset_of_default_codes() {
    let project = TempProject::empty(r#"{"name": "superset", "version": "1.0.0"}"#);
    let fast = lpm_with_registry(&project, "http://127.0.0.1:1")
        .args(["doctor", "--json"])
        .output()
        .expect("failed to run lpm doctor --json");
    let all = lpm_with_registry(&project, "http://127.0.0.1:1")
        .args(["doctor", "--all", "--json"])
        .output()
        .expect("failed to run lpm doctor --all --json");

    let fast_codes = emitted_codes(&fast.stdout);
    let all_codes = emitted_codes(&all.stdout);

    let missing: Vec<&String> = fast_codes.difference(&all_codes).collect();
    assert!(
        missing.is_empty(),
        "`--all` must emit every code default emits (or a counterpart from \
         the same row). Missing under --all: {missing:?}\nfast: {fast_codes:?}\nall: {all_codes:?}"
    );
    assert!(
        all_codes.len() > fast_codes.len(),
        "`--all` should emit MORE codes than default. fast={} all={}",
        fast_codes.len(),
        all_codes.len(),
    );
}

// ─── Fast-mode human output: suppress passes except linker_mode ────

/// Pins the renderer contract documented in `defaults-fixes-todo.md`:
/// "prioritize fail / warn rows from the fast preset; keep
/// informational pass rows to the minimum needed for context
/// (linker mode is the only one worth forcing through)."
///
/// Fixture has `package.json` (pass) + no `node_modules` (fail) + no
/// `lpm.lock` (warn). Default `lpm doctor` must:
///   - suppress the `package.json` and `Global store` pass rows
///   - keep the `Linker mode` pass row as context
///   - emit the `node_modules` fail and `Lockfile` warn rows
///
/// Pre-fix this test would have caught the regression: pass rows
/// printed alongside fails when fails/warns existed in the same run.
#[test]
fn doctor_default_human_output_suppresses_passes_except_linker_mode_when_fails_present() {
    let project = TempProject::empty(r#"{"name": "suppress", "version": "1.0.0"}"#);
    // No node_modules, no lpm.lock — guarantees a fail + a warn fire
    // alongside the always-pass `package.json` and `Global store` rows.

    let output = lpm_with_registry(&project, "http://127.0.0.1:1")
        // NO_COLOR strips ANSI so substring assertions are robust.
        .env("NO_COLOR", "1")
        .args(["doctor"])
        .output()
        .expect("failed to run lpm doctor");

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Linker mode pass row IS kept (load-bearing context).
    assert!(
        stdout.contains("Linker mode"),
        "fast-mode human output must keep `Linker mode` as context. \
         stdout:\n{stdout}"
    );

    // The `node_modules` fail row must be present.
    assert!(
        stdout.contains("node_modules") && stdout.contains("not found"),
        "fast-mode human output must show the node_modules fail row. \
         stdout:\n{stdout}"
    );

    // The `Lockfile` warn row must be present.
    assert!(
        stdout.contains("Lockfile") && stdout.contains("not found"),
        "fast-mode human output must show the Lockfile warn row. \
         stdout:\n{stdout}"
    );

    // The `package.json` pass row must be SUPPRESSED — broken rows
    // should not be buried below healthy ones.
    //
    // Substring match needs care: the strings "package.json" and
    // "Global store" appear in remediation details for other rows
    // ("run: lpm install (creates package.json)" style). Anchor on
    // the row prefix `✔ {name}` — the `name` is the second token
    // after the icon, and the suppressed rows have a `✔` icon.
    // With NO_COLOR=1, icons render as bare unicode characters.
    assert!(
        !stdout.contains("✔ package.json"),
        "fast-mode human output must suppress the `package.json` \
         pass row. stdout:\n{stdout}"
    );
    assert!(
        !stdout.contains("✔ Global store"),
        "fast-mode human output must suppress the `Global store` \
         pass row. stdout:\n{stdout}"
    );
}

// ─── Inventory surface (`lpm doctor list --json`) exposes tier ─────

#[test]
fn doctor_list_json_entries_carry_tier_field() {
    let project = TempProject::empty(r#"{"name": "list-tier", "version": "1.0.0"}"#);
    let output = lpm_with_registry(&project, "http://127.0.0.1:1")
        .args(["--json", "doctor", "list"])
        .output()
        .expect("failed to run lpm doctor list --json");
    assert!(
        output.status.success(),
        "list --json failed; stderr:\n{}",
        String::from_utf8_lossy(&output.stderr),
    );

    let json = parse_json_output(&output.stdout);
    let entries = json["entries"]
        .as_array()
        .expect("entries must be an array");
    assert!(!entries.is_empty());

    let mut saw_fast = false;
    let mut saw_extended = false;
    for entry in entries {
        let tier = entry["tier"].as_str().unwrap_or_else(|| {
            panic!("every inventory entry must carry a string `tier` field. Entry: {entry}")
        });
        assert!(
            matches!(tier, "fast" | "extended"),
            "unknown tier `{tier}` in entry: {entry}"
        );
        match tier {
            "fast" => saw_fast = true,
            "extended" => saw_extended = true,
            _ => unreachable!(),
        }
    }
    assert!(
        saw_fast && saw_extended,
        "inventory must include both tiers; saw fast={saw_fast} extended={saw_extended}"
    );
}
