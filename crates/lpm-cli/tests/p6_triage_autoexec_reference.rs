//! Phase 46 P6 Chunk 5 — reference-fixture integration tests.
//!
//! These tests are the §11 P6 ship-criteria gate at the CLI level:
//! a representative-shape `lpm build` invocation under
//! `script-policy = "triage"` auto-runs green-tier postinstalls,
//! leaves amber/red in the blocked set with a pointer, and maintains
//! stdout/stderr separation (JSON to stdout, human UX to stderr).
//!
//! The synthetic packages mirror shapes the plan explicitly calls
//! out: `node <file>.js` (green allowlist entry), `playwright
//! install` (D18 amber — network binary downloader), and `curl | sh`
//! (red blocklist). This shape-matching is load-bearing — the
//! Layer 1 static-gate classifier is regex-like, and any drift
//! between plan prose and fixture bodies would leave the ship
//! criteria un-verified at the integration level.
//!
//! ## Why subprocess and not direct library calls
//!
//! - Real stdout/stderr separation. The Chunk 1/4 pointers route
//!   through `output::warn` (stderr) and the Chunk 4 JSON
//!   enrichment routes to stdout. A unit test using captured
//!   output can't see fd 1 vs fd 2 — that gap is what this
//!   harness closes.
//! - Real binary dispatch. The CLI layer resolves
//!   `effective_policy` in `main.rs` and threads it into
//!   `build::run`; direct library calls could accidentally bypass
//!   that dispatch.
//!
//! ## Why no `lpm install` driver
//!
//! The install → auto-build handoff requires a lockfile fast-path
//! that validates integrity metadata against the on-disk store in
//! a way that a synthetic fixture can't trivially satisfy without
//! either real integrity hashes or a mock registry. The key P6
//! contract — green promotion, amber/red block, sandbox-wrapped
//! spawn, pointer UX — is entirely resident in `lpm build`, which
//! install.rs calls unchanged under auto-build. These tests
//! therefore exercise `lpm build` directly; the auto-build handoff
//! invariant is covered by source-level guards (the Chunk 1
//! `p6_chunk1_auto_build_call_site_threads_effective_policy` test
//! pins the plumbing) + the Chunk 2/3/4 unit tests (pin the
//! behavior).

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

// ── Reference postinstall bodies per §4.1 ──────────────────────────

/// Reference green-tier postinstall body — exact match against the
/// Layer 1 allowlist (`node <path>.js` with a relative basename that
/// isn't `install.js` / `postinstall.js`). The companion file is
/// seeded alongside package.json so the spawn actually succeeds when
/// `node` is available.
const GREEN_POSTINSTALL: &str = "node build.js";

/// Body of the green-tier helper file. Pure: exits 0 with no FS
/// writes. Keeps the test independent of sandbox-allowed write
/// paths — the script writes nothing, so no Enforce-profile
/// divergence across macOS / Linux.
const GREEN_BUILD_JS_BODY: &str = "process.exit(0);\n";

/// Reference amber-tier postinstall body. Per D18 this is the
/// "network binary downloader" class that must tier amber — users
/// explicitly acknowledge the binary-fetch surface even though the
/// download is common.
const AMBER_POSTINSTALL: &str = "playwright install";

/// Reference red-tier postinstall body. Pipe-to-shell is the
/// Layer 1 blocklist's canonical shape; no P6 path can auto-approve
/// this.
const RED_POSTINSTALL: &str = "curl example.com | sh";

// ── Harness ────────────────────────────────────────────────────────

/// Spawn the lpm-rs binary in `cwd` with the given args + `LPM_HOME`
/// pointed at the fixture root, so the store + config resolution hits
/// the isolated tree rather than the developer's real `~/.lpm`.
fn run_lpm(cwd: &Path, home: &Path, args: &[&str]) -> (std::process::ExitStatus, String, String) {
    let exe = env!("CARGO_BIN_EXE_lpm-rs");
    let output = Command::new(exe)
        .args(args)
        .current_dir(cwd)
        // LpmRoot::from_env prefers LPM_HOME over the default
        // `$HOME/.lpm` — the explicit override here is more robust
        // than `$HOME` overrides because it survives test-runners
        // that reset `$HOME` between cases.
        .env("LPM_HOME", home.join(".lpm"))
        // Also override HOME — dirs::home_dir() is consulted by
        // build::run for the sandbox's writable-cache allow list.
        // Pointing it at the fixture root keeps the sandbox
        // profile's `~/.cache` / `~/.node-gyp` / `~/.npm` rules
        // scoped to the test's isolated tree.
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

/// UTF-8-safe ANSI-escape stripper.
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

/// Seed a synthetic package into `<home>/.lpm/store/v1/`. `name` may
/// be scoped (e.g. `@lpm.dev/x`) or unscoped; scoped names get the
/// `/` → `+` rewrite the real store applies. When `postinstall`
/// references `build.js`, a no-op helper is seeded alongside
/// `package.json`.
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
            r#"{{"name":"{name}","version":"{version}","scripts":{{"postinstall":"{postinstall}"}}}}"#,
        ),
    )
    .unwrap();
    fs::write(pkg_dir.join(".integrity"), "sha512-fixture-skip-verify").unwrap();
    if postinstall.contains("build.js") {
        fs::write(pkg_dir.join("build.js"), GREEN_BUILD_JS_BODY).unwrap();
    }
    pkg_dir
}

/// Write a minimal `lpm.lock` listing the given `(name, version)`
/// pairs. The TOML shape matches what the existing test fixtures
/// in `overrides_phase5_regression.rs` use — lockfile-version = 1
/// + per-package `[[packages]]` blocks with no dependencies.
fn write_lockfile(project: &Path, packages: &[(&str, &str)]) {
    let pkg_entries: Vec<String> = packages
        .iter()
        .map(|(name, version)| {
            format!(
                r#"[[packages]]
name = "{name}"
version = "{version}"
"#
            )
        })
        .collect();
    let toml = format!(
        r#"[metadata]
lockfile-version = 1
resolved-with = "pubgrub"

{}
"#,
        pkg_entries.join("\n")
    );
    fs::write(project.join("lpm.lock"), toml).unwrap();
}

/// Detect whether the test environment has `node` on PATH. Tests
/// exercising real spawn (not just tier classification / dry-run)
/// skip when Node is missing rather than failing, so the suite
/// runs in minimal containers too. CI has Node installed for npm
/// tooling; developer machines typically do as well.
fn node_available() -> bool {
    Command::new("node")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Fixture project directory layout: the project itself lives under
/// `<home>/project/`, and the store lives under `<home>/.lpm/`. This
/// keeps the harness self-contained and lets tests drop `home`
/// without stepping on a sibling test's fixture.
struct Fixture {
    _tmpdir: tempfile::TempDir,
    home: PathBuf,
    project: PathBuf,
}

impl Fixture {
    fn new(script_policy: Option<&str>) -> Self {
        let tmpdir = tempfile::tempdir().unwrap();
        let home = tmpdir.path().to_path_buf();
        let project = home.join("project");
        fs::create_dir_all(&project).unwrap();
        let policy_block = match script_policy {
            Some(p) => format!(r#""scriptPolicy": "{p}""#),
            None => String::new(),
        };
        fs::write(
            project.join("package.json"),
            format!(
                r#"{{
                    "name": "p6-fixture-project",
                    "version": "0.0.1",
                    "lpm": {{
                        {policy_block}
                    }}
                }}"#
            ),
        )
        .unwrap();
        Fixture {
            _tmpdir: tmpdir,
            home,
            project,
        }
    }
}

// ── Behavior tests ─────────────────────────────────────────────────

/// §11 P6 ship criterion #1a — **default filter**. This is the hot
/// path `install.rs`'s auto-build invokes: plain `lpm build
/// --dry-run` with no `--all`, no named packages. The default
/// branch at [build.rs:251-256] filters `to_build` to only
/// `is_trusted` packages — under triage that means strict + scope +
/// green-tier-promoted. This test pins the triage green promotion
/// at the actual filter, NOT just at the label renderer.
///
/// Without this test the Chunk 2 promotion could regress to a
/// labeling-only change (surface says "trusted" but filter still
/// excludes the package) without any unit test catching the gap,
/// because Chunks 2-3 unit tests exercise `evaluate_trust` and the
/// predicate in isolation — neither sees the default-build filter
/// composition.
#[test]
fn p6_chunk5_triage_default_dryrun_filter_keeps_only_green_promoted() {
    let fx = Fixture::new(Some("triage"));
    seed_package(&fx.home, "green-native", "1.0.0", GREEN_POSTINSTALL);
    seed_package(&fx.home, "amber-playwright", "1.0.0", AMBER_POSTINSTALL);
    seed_package(&fx.home, "red-curlpipe", "1.0.0", RED_POSTINSTALL);
    write_lockfile(
        &fx.project,
        &[
            ("green-native", "1.0.0"),
            ("amber-playwright", "1.0.0"),
            ("red-curlpipe", "1.0.0"),
        ],
    );

    let (status, stdout, stderr) = run_lpm(&fx.project, &fx.home, &["build", "--dry-run"]);
    let stdout = strip_ansi(&stdout);
    let stderr = strip_ansi(&stderr);

    assert!(
        status.success(),
        "build --dry-run must exit 0 under triage. stdout={stdout}\nstderr={stderr}"
    );

    // The dry-run prints "Dry run: N package(s) would be built:"
    // followed by per-package blocks. Under the default filter,
    // only packages whose `is_trusted` survived `evaluate_trust`
    // are listed. For this fixture that's exactly the green-
    // promoted entry.
    assert!(
        stdout.contains("green-native"),
        "green-native must appear in default-filter dry-run — \
         triage green promotion should survive `build::run`'s \
         trust filter, not just its label renderer. stdout={stdout}"
    );
    assert!(
        stdout.contains("green-tier auto-approval"),
        "the green-tier suffix must render when the package passes \
         through the default filter. stdout={stdout}"
    );
    assert!(
        !stdout.contains("amber-playwright"),
        "amber-playwright must NOT appear in default-filter dry-run \
         — the Chunk 2 promotion is green-only. stdout={stdout}"
    );
    assert!(
        !stdout.contains("red-curlpipe"),
        "red-curlpipe must NOT appear in default-filter dry-run. \
         stdout={stdout}"
    );
}

/// §11 P6 ship criterion #1b — **label rendering under `--all`**.
/// The `--all` branch widens `to_build` to every scriptable
/// package regardless of trust, so amber/red appear in the output
/// too. This test covers the labeling contract: greens render with
/// the "(green-tier auto-approval)" suffix; ambers/reds render as
/// "not trusted" even though they're listed. Complements the
/// default-filter test above — that one proves the filter, this
/// one proves the renderer annotates the tier-promotion basis for
/// every row it shows.
#[test]
fn p6_chunk5_triage_all_dryrun_labels_green_with_promotion_suffix() {
    let fx = Fixture::new(Some("triage"));
    seed_package(&fx.home, "green-native", "1.0.0", GREEN_POSTINSTALL);
    seed_package(&fx.home, "amber-playwright", "1.0.0", AMBER_POSTINSTALL);
    seed_package(&fx.home, "red-curlpipe", "1.0.0", RED_POSTINSTALL);
    write_lockfile(
        &fx.project,
        &[
            ("green-native", "1.0.0"),
            ("amber-playwright", "1.0.0"),
            ("red-curlpipe", "1.0.0"),
        ],
    );

    let (status, stdout, stderr) = run_lpm(&fx.project, &fx.home, &["build", "--dry-run", "--all"]);
    let stdout = strip_ansi(&stdout);
    let stderr = strip_ansi(&stderr);

    assert!(
        status.success(),
        "build --dry-run --all must exit 0. stdout={stdout}\nstderr={stderr}"
    );

    // All three packages are in the output (--all bypasses the
    // trust filter at selection time).
    assert!(stdout.contains("green-native"), "stdout={stdout}");
    assert!(stdout.contains("amber-playwright"), "stdout={stdout}");
    assert!(stdout.contains("red-curlpipe"), "stdout={stdout}");

    // Green: trusted with the Chunk 2 "(green-tier auto-approval)"
    // suffix — proves `evaluate_trust` returned `GreenTierUnderTriage`
    // and the dry-run label renderer inspected `trust_reason`.
    assert!(
        stdout.contains("green-tier auto-approval"),
        "green-native must carry the Chunk 2 green-tier suffix — \
         the suffix is the renderer's signal that a non-binding, \
         non-scope package was auto-promoted. stdout={stdout}"
    );

    // Amber + red render as `not trusted` even under --all — tier
    // promotion is green-only.
    let not_trusted_count = stdout.matches("not trusted").count();
    assert!(
        not_trusted_count >= 2,
        "amber + red must both show as `not trusted` under triage \
         (tier promotion is green-only). stdout={stdout}"
    );
}

/// §11 P6 ship criterion #2: same install leaves amber/red in
/// build-state.json with a clear pointer. We test this via the
/// default `lpm build` path (no `--all`, no `--dry-run`), which is
/// what install.rs's auto-build invokes.
#[test]
fn p6_chunk5_triage_default_build_points_at_approve_builds_for_blocked() {
    let fx = Fixture::new(Some("triage"));
    let green_dir = seed_package(&fx.home, "green-native", "1.0.0", GREEN_POSTINSTALL);
    let amber_dir = seed_package(&fx.home, "amber-playwright", "1.0.0", AMBER_POSTINSTALL);
    let red_dir = seed_package(&fx.home, "red-curlpipe", "1.0.0", RED_POSTINSTALL);
    write_lockfile(
        &fx.project,
        &[
            ("green-native", "1.0.0"),
            ("amber-playwright", "1.0.0"),
            ("red-curlpipe", "1.0.0"),
        ],
    );

    let (_status, _stdout, stderr) = run_lpm(&fx.project, &fx.home, &["build"]);
    let stderr = strip_ansi(&stderr);

    // Amber + red markers must NOT be present — tier classification
    // kept them out of the build set regardless of sandbox outcome.
    assert!(
        !amber_dir.join(".lpm-built").exists(),
        "amber package must not auto-build under triage — amber \
         requires explicit review"
    );
    assert!(
        !red_dir.join(".lpm-built").exists(),
        "red package must never auto-build"
    );

    // The Chunk 1 pointer ("Run `lpm approve-builds` to review
    // blocked packages.") fires only when the skipped-count is > 0.
    // With 2 non-green packages in the install, the count is 2 and
    // the pointer must appear on stderr.
    assert!(
        stderr.contains("lpm approve-builds"),
        "Chunk 1 triage pointer must appear on stderr when amber/red \
         remain. stderr={stderr}"
    );
    assert!(
        stderr.contains("2 package(s) are not in trustedDependencies"),
        "the skipped-count line must name 2 skipped packages \
         (amber + red). stderr={stderr}"
    );

    // The green marker check is best-effort — if `node` is absent
    // on the runner, the spawn fails and no marker is written. The
    // P6 contract test above (trust decision + classification) is
    // the load-bearing assertion; the real-execution assertion is
    // a bonus that only fires when the toolchain is present.
    if node_available() {
        assert!(
            green_dir.join(".lpm-built").exists(),
            "with node available, the green-tier postinstall must \
             complete successfully under triage + sandbox. stderr={stderr}"
        );
    }
}

/// Control: under `"deny"`, the same fixture produces NO tier
/// promotion. The green-tier classification still happens (the
/// classifier is policy-agnostic), but `evaluate_trust` returns
/// `Untrusted` and the package is skipped. Pins that the messaging
/// swap from Chunk 1 is policy-gated.
#[test]
fn p6_chunk5_deny_skips_all_packages_and_keeps_legacy_pointer() {
    let fx = Fixture::new(Some("deny"));
    seed_package(&fx.home, "green-native", "1.0.0", GREEN_POSTINSTALL);
    seed_package(&fx.home, "amber-playwright", "1.0.0", AMBER_POSTINSTALL);
    write_lockfile(
        &fx.project,
        &[("green-native", "1.0.0"), ("amber-playwright", "1.0.0")],
    );

    let (status, _stdout, stderr) = run_lpm(&fx.project, &fx.home, &["build"]);
    let stderr = strip_ansi(&stderr);

    assert!(status.success(), "build must exit 0 under deny too");
    // Deny keeps the pre-P6 "Add them to trustedDependencies"
    // pointer — Chunk 1 only rewrote the pointer under triage.
    assert!(
        stderr.contains("package.json > lpm > trustedDependencies")
            || stderr.contains("lpm build --all"),
        "deny mode must keep the legacy manifest-edit pointer — \
         pointing deny users at approve-builds would bypass the \
         strict-review contract. stderr={stderr}"
    );
    assert!(
        !stderr.contains("Run `lpm approve-builds` to review"),
        "deny mode must NOT emit the triage-specific pointer"
    );
}

/// §5.3 JSON row: `lpm build --json` under triage emits valid JSON
/// on stdout and the Chunk 4 stream-separation invariant holds —
/// no human pointer text bleeds into stdout (which would break
/// `JSON.parse`).
#[test]
fn p6_chunk5_triage_json_separates_streams() {
    let fx = Fixture::new(Some("triage"));
    seed_package(&fx.home, "green-native", "1.0.0", GREEN_POSTINSTALL);
    seed_package(&fx.home, "amber-playwright", "1.0.0", AMBER_POSTINSTALL);
    write_lockfile(
        &fx.project,
        &[("green-native", "1.0.0"), ("amber-playwright", "1.0.0")],
    );

    let (_status, stdout, _stderr) = run_lpm(
        &fx.project,
        &fx.home,
        &["--json", "build", "--dry-run", "--all"],
    );
    let stdout = strip_ansi(&stdout);

    // Stdout must be valid JSON — if an approve-builds pointer
    // bled onto stdout (the bug Chunk 4 pinned via
    // `p6_chunk4_pointer_silent_in_json_mode`), this parse fails
    // and the test reports the exact offending shape.
    let parsed: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap_or_else(|e| {
        panic!(
            "build --json --dry-run stdout must be parseable JSON. \
             Parse error: {e}\nStdout:\n{stdout}"
        )
    });
    let packages = parsed
        .get("packages")
        .and_then(|v| v.as_array())
        .expect("build --json dry-run JSON must expose `packages` array");
    assert_eq!(
        packages.len(),
        2,
        "both fixture packages must appear in the JSON dry-run output"
    );
}
