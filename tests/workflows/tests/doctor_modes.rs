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
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::time::{Duration, Instant};
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
    "unsupported_override_values",
    "pnpm_overrides_drift",
    "engines_npm_ignored",
    "engines_pnpm_ignored",
    "gitattributes_lockb_marked",
    "gitattributes_lockb_unmarked",
    "gitattributes_missing",
    "v2_store_orphans",
    "store_orphan_analysis_unavailable",
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

fn assert_doctor_preserves_torn_global_wal(arguments: &[&str]) {
    let project = TempProject::empty(r#"{"name":"doctor-wal","version":"1.0.0"}"#);
    let root = lpm_common::LpmRoot::from_dir(project.home().join(".lpm"));
    std::fs::create_dir_all(root.global_root()).unwrap();
    let original = b"torn-global-transaction";
    std::fs::write(root.global_wal(), original).unwrap();

    let _ = lpm_with_registry(&project, "http://127.0.0.1:1")
        .args(arguments)
        .output()
        .expect("failed to run lpm doctor");

    assert_eq!(
        std::fs::read(root.global_wal()).unwrap(),
        original,
        "diagnostic commands must not truncate or recover the global WAL"
    );
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
fn doctor_list_does_not_recover_or_mutate_the_global_wal() {
    assert_doctor_preserves_torn_global_wal(&["--json", "doctor", "list"]);
}

#[test]
fn doctor_default_does_not_recover_or_mutate_the_global_wal() {
    assert_doctor_preserves_torn_global_wal(&["--json", "doctor"]);
}

#[test]
fn doctor_all_does_not_recover_or_mutate_the_global_wal() {
    assert_doctor_preserves_torn_global_wal(&["--json", "doctor", "--all"]);
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

#[test]
fn doctor_reports_an_invalid_package_manifest_without_aborting_json_output() {
    let project = TempProject::empty("{not-json");
    let output = lpm_with_registry(&project, "http://127.0.0.1:1")
        .args(["doctor", "--json"])
        .output()
        .expect("failed to run lpm doctor --json");

    let json = parse_json_output(&output.stdout);
    assert!(
        json["checks"].as_array().is_some_and(|checks| checks
            .iter()
            .any(|check| check["code"] == "package_json_invalid")),
        "doctor must preserve its JSON report and identify the invalid manifest: {json:#}"
    );
}

#[test]
fn doctor_reports_an_invalid_pnpm_workspace_manifest_without_aborting() {
    let project = TempProject::empty(r#"{"name":"workspace-yaml","version":"1.0.0"}"#);
    project.write_file("pnpm-workspace.yaml", "packages: [\n");

    let output = lpm_with_registry(&project, "http://127.0.0.1:1")
        .args(["doctor", "--json"])
        .output()
        .expect("failed to run lpm doctor --json");
    let json = parse_json_output(&output.stdout);

    assert!(
        json["checks"].as_array().is_some_and(|checks| checks
            .iter()
            .any(|check| check["code"] == "workspace_discovery_failed")),
        "doctor must preserve its report and identify the invalid workspace manifest: {json:#}"
    );
}

#[test]
fn doctor_reports_an_invalid_workspace_member_manifest_without_aborting() {
    let project = TempProject::empty(
        r#"{"name":"workspace-member","version":"1.0.0","workspaces":["packages/*"]}"#,
    );
    project.write_file("packages/app/package.json", "{not-json");

    let output = lpm_with_registry(&project, "http://127.0.0.1:1")
        .args(["doctor", "--json"])
        .output()
        .expect("failed to run lpm doctor --json");
    let json = parse_json_output(&output.stdout);

    assert!(
        json["checks"].as_array().is_some_and(|checks| checks
            .iter()
            .any(|check| check["code"] == "workspace_discovery_failed")),
        "doctor must preserve its report and identify the invalid member manifest: {json:#}"
    );
}

#[test]
fn doctor_reports_a_store_path_that_is_a_regular_file_as_inaccessible() {
    let project = TempProject::empty(r#"{"name":"store-file","version":"1.0.0"}"#);
    std::fs::create_dir_all(project.home().join(".lpm")).unwrap();
    std::fs::write(project.home().join(".lpm/store"), b"not a directory").unwrap();

    let output = lpm_with_registry(&project, "http://127.0.0.1:1")
        .args(["doctor", "--json"])
        .output()
        .expect("failed to run lpm doctor --json");
    let codes = emitted_codes(&output.stdout);

    assert!(codes.contains("global_store_inaccessible"), "{codes:?}");
    assert!(!codes.contains("global_store_accessible"), "{codes:?}");
}

#[test]
fn doctor_list_combined_filters_do_not_call_a_valid_code_unknown() {
    let project = TempProject::empty(r#"{"name":"catalog","version":"1.0.0"}"#);
    let output = lpm_with_registry(&project, "http://127.0.0.1:1")
        .args([
            "doctor",
            "list",
            "--code",
            "registry_reachable",
            "--category",
            "runtime",
            "--json",
        ])
        .output()
        .expect("failed to run filtered lpm doctor list");

    let json = parse_json_output(&output.stdout);
    assert!(output.status.success(), "{json:#}");
    assert_eq!(json["count"], 0, "{json:#}");
    assert_eq!(json["entries"], serde_json::json!([]), "{json:#}");
}

#[test]
#[cfg(unix)]
fn doctor_default_does_not_execute_project_local_node_shim() {
    let project = TempProject::empty(r#"{"name":"untrusted-node","version":"1.0.0"}"#);
    let shim = project.path().join("node_modules/.bin/node");
    let marker = project.path().join("node-shim-executed");
    project.write_file(
        "node_modules/.bin/node",
        "#!/bin/sh\ntouch \"$DOCTOR_RUNTIME_MARKER\"\nprintf 'v99.0.0\\n'\n",
    );
    let mut permissions = std::fs::metadata(&shim)
        .expect("read project-local node shim metadata")
        .permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(&shim, permissions).expect("make project-local node shim executable");

    let _ = lpm_with_registry(&project, "http://127.0.0.1:1")
        .env("DOCTOR_RUNTIME_MARKER", &marker)
        .args(["doctor", "--json"])
        .output()
        .expect("failed to run lpm doctor --json");

    assert!(
        !marker.exists(),
        "doctor must not execute a project-controlled node_modules/.bin/node shim"
    );
}

#[test]
#[cfg(unix)]
fn doctor_default_does_not_execute_project_local_bun_shim() {
    let project = TempProject::empty(r#"{"name":"untrusted-bun","version":"1.0.0"}"#);
    project.write_file("lpm.json", r#"{"runtime":{"bun":"1.3.0"}}"#);
    let shim = project.path().join("node_modules/.bin/bun");
    let marker = project.path().join("bun-shim-executed");
    project.write_file(
        "node_modules/.bin/bun",
        "#!/bin/sh\ntouch \"$DOCTOR_RUNTIME_MARKER\"\nprintf '1.3.0\\n'\n",
    );
    let mut permissions = std::fs::metadata(&shim)
        .expect("read project-local bun shim metadata")
        .permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(&shim, permissions).expect("make project-local bun shim executable");

    let _ = lpm_with_registry(&project, "http://127.0.0.1:1")
        .env("DOCTOR_RUNTIME_MARKER", &marker)
        .args(["doctor", "--json"])
        .output()
        .expect("failed to run lpm doctor --json");

    assert!(
        !marker.exists(),
        "doctor must not execute a project-controlled node_modules/.bin/bun shim"
    );
}

#[test]
#[cfg(unix)]
fn doctor_runtime_probe_times_out_and_reaps_a_hanging_node() {
    let project = TempProject::empty(r#"{"name":"hanging-node","version":"1.0.0"}"#);
    let runtime_dir = project.home().join("trusted-runtime-bin");
    std::fs::create_dir_all(&runtime_dir).unwrap();
    let node = runtime_dir.join("node");
    std::fs::write(&node, "#!/bin/sh\nexec /bin/sleep 30\n").unwrap();
    let mut permissions = std::fs::metadata(&node).unwrap().permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(&node, permissions).unwrap();

    let started = Instant::now();
    let output = lpm_with_registry(&project, "http://127.0.0.1:1")
        .env("PATH", &runtime_dir)
        .args(["doctor", "--json"])
        .output()
        .expect("failed to run lpm doctor --json");

    assert!(
        started.elapsed() < Duration::from_secs(12),
        "runtime probe exceeded its deadline: {:?}\n{}",
        started.elapsed(),
        String::from_utf8_lossy(&output.stderr)
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

#[tokio::test]
async fn doctor_all_output_redacts_registry_credentials() {
    let project = TempProject::empty(r#"{"name":"redacted-registry","version":"1.0.0"}"#);
    let mock = support::mock_registry::MockRegistry::start().await;
    mock.with_health().await;
    let registry_url = mock.url().replacen("://", "://audit-user:audit-secret@", 1);

    for arguments in [vec!["doctor", "--all"], vec!["doctor", "--all", "--json"]] {
        let output = lpm_with_registry(&project, &registry_url)
            .args(arguments)
            .output()
            .expect("failed to run lpm doctor --all");
        let combined = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            !combined.contains("audit-user") && !combined.contains("audit-secret"),
            "doctor must not expose registry URL credentials: {combined}"
        );
    }
}

#[tokio::test]
async fn doctor_all_validates_an_lpm_token_environment_credential() {
    let project = TempProject::empty(r#"{"name":"env-auth","version":"1.0.0"}"#);
    let mock = support::mock_registry::MockRegistry::start().await;
    mock.with_health().await;
    mock.with_authenticated_whoami("doctor-token", "doctor", "doctor@example.test")
        .await;

    let output = lpm_with_registry(&project, &mock.url())
        .env("LPM_TOKEN", "doctor-token")
        .args(["doctor", "--all", "--json"])
        .output()
        .expect("failed to run authenticated lpm doctor --all");
    let codes = emitted_codes(&output.stdout);

    assert!(codes.contains("auth_valid"), "{codes:?}");
    assert!(!codes.contains("auth_missing"), "{codes:?}");
}

#[tokio::test]
async fn doctor_all_does_not_call_a_token_invalid_when_whoami_returns_500() {
    let project = TempProject::empty(r#"{"name":"auth-outage","version":"1.0.0"}"#);
    let mock = support::mock_registry::MockRegistry::start().await;
    mock.with_health().await;
    mock.with_authenticated_whoami_error("doctor-token", 500, 4)
        .await;

    let output = lpm_with_registry(&project, &mock.url())
        .env("LPM_TOKEN", "doctor-token")
        .env("LPM_RETRY_BACKOFF_MS_OVERRIDE", "1")
        .args(["doctor", "--all", "--json"])
        .output()
        .expect("failed to run lpm doctor --all");
    let codes = emitted_codes(&output.stdout);

    assert!(codes.contains("auth_unverified"), "{codes:?}");
    assert!(!codes.contains("auth_invalid"), "{codes:?}");
}

#[tokio::test]
async fn doctor_all_skips_authenticated_tunnel_lookup_after_token_rejection() {
    let project = TempProject::empty(r#"{"name":"auth-tunnel","version":"1.0.0"}"#);
    project.write_file("lpm.json", r#"{"tunnel":{"domain":"doctor-auth.lpm.fyi"}}"#);
    let mock = support::mock_registry::MockRegistry::start().await;
    mock.with_health().await;
    mock.with_authenticated_whoami_error("rejected-token", 401, 1)
        .await;

    let output = lpm_with_registry(&project, &mock.url())
        .env("LPM_TOKEN", "rejected-token")
        .args(["doctor", "--all", "--json"])
        .output()
        .expect("failed to run doctor with a rejected token");
    let codes = emitted_codes(&output.stdout);

    assert!(codes.contains("auth_invalid"), "{codes:?}");
    assert!(
        codes.contains("tunnel_unauthenticated"),
        "a rejected token must not enable authenticated tunnel checks: {codes:?}"
    );
    assert!(!codes.contains("tunnel_unverified"), "{codes:?}");
}

#[test]
fn doctor_all_does_not_claim_no_orphans_without_a_known_projects_registry() {
    let project = TempProject::empty(r#"{"name":"unknown-orphans","version":"1.0.0"}"#);
    let output = lpm_with_registry(&project, "http://127.0.0.1:1")
        .args(["doctor", "--all", "--json"])
        .output()
        .expect("failed to run doctor without known-projects state");
    let json = parse_json_output(&output.stdout);
    let orphan = json["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|check| check["code"] == "v2_store_orphans");

    assert!(
        orphan.is_none_or(|check| check["detail"] != "no orphans"),
        "doctor must not report a healthy orphan analysis without registry roots: {json:#}"
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

#[test]
fn doctor_all_human_output_shows_slim_progress_on_stderr() {
    let project = TempProject::empty(r#"{"name": "doctor-progress", "version": "1.0.0"}"#);
    let output = lpm_with_registry(&project, "http://127.0.0.1:1")
        .env("NO_COLOR", "1")
        .args(["doctor", "--all"])
        .output()
        .expect("failed to run lpm doctor --all");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        stderr.contains("› Running doctor --all checks"),
        "human `doctor --all` must show a slim progress line on stderr while \
         expensive checks run.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        stdout.contains("doctor found") || stdout.contains("All "),
        "human `doctor --all` report must remain on stdout. stdout:\n{stdout}\nstderr:\n{stderr}"
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
    let lockfile_row = stdout
        .lines()
        .find(|line| line.contains("Lockfile"))
        .expect("Lockfile row must be present");
    assert!(
        lockfile_row.contains("Lockfile     "),
        "doctor detail rows must align to the widest visible check name. \
         row: {lockfile_row:?}\nstdout:\n{stdout}"
    );

    // The `package.json` pass row must be SUPPRESSED — broken rows
    // should not be buried below healthy ones.
    //
    // Substring match needs care: the strings "package.json" and
    // "Global store" appear in remediation details for other rows
    // ("run: lpm install (creates package.json)" style). Anchor on
    // the row prefix `✓ {name}` — the `name` is the second token
    // after the icon, and the suppressed rows have a `✔` icon.
    // With NO_COLOR=1, icons render as bare unicode characters.
    assert!(
        !stdout.contains("✓ package.json"),
        "fast-mode human output must suppress the `package.json` \
         pass row. stdout:\n{stdout}"
    );
    assert!(
        !stdout.contains("✓ Global store"),
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
