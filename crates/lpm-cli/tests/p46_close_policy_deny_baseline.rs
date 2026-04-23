//! Phase 46 close-out Chunk 5 — deterministic `--policy=deny`
//! baseline snapshot.
//!
//! §18 ("Before the full phase ships"):
//!
//! > `lpm install --policy=deny` output snapshot matches Phase 32
//! > Phase 4 baseline (zero-regression guarantee for the default).
//!
//! §12.7 (v2.10 reframe):
//!
//! > A deterministic `--policy=deny` baseline output snapshot on a
//! > small synthetic 2-pkg fixture guards the zero-regression-for-
//! > the-default guarantee from §18 at the subprocess level.
//!
//! ## Why `lpm build --dry-run --policy=deny --json`, not `lpm install`
//!
//! A real `lpm install` against a synthetic fixture would need
//! either (a) network access to lpm.dev, or (b) a mocked registry
//! via `wiremock`. Both are out of 46.0 close-out scope — the v2.9
//! residual gap explicitly flags "a real end-to-end install
//! fixture is a separate workstream." For the close-out guarantee,
//! a post-install command surface suffices: the JSON-mode output
//! of `lpm build --dry-run` is a direct function of the persisted
//! state that install would have produced, and under
//! `--policy=deny` its shape is the pre-Phase-46 contract
//! verbatim.
//!
//! The golden file at `tests/fixtures/p46_close_policy_deny_baseline.stdout`
//! captures that byte-exact output. A future phase that
//! accidentally widens the deny-mode schema (e.g. adding a
//! `static_tier` field to dry-run entries under default policy)
//! fails this test. Fix forward: either the new field is
//! intentional (update the golden via `UPDATE_GOLDEN=1 cargo test
//! --test p46_close_policy_deny_baseline`), or the change was
//! unintended (back it out).
//!
//! ## Why a 2-pkg fixture
//!
//! The Chunk 5 signoff explicitly split wall-clock benchmarking
//! (51-pkg fixture) from subprocess golden snapshots (2-pkg
//! deterministic fixture). At 51 packages the JSON output picks up
//! resolver noise — HashMap insertion order in `scripts`, toposort
//! tie-breaks — that makes byte-equal assertions flaky. Two
//! packages, one trusted and one untrusted, is the minimum that
//! exercises the deny-mode default-branch filter (trusted in, untrusted
//! filtered out) while staying byte-stable across runs.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

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

/// Seed a synthetic package version into `<home>/.lpm/store/v1/`.
/// Shape mirrors the P6/P7 reference fixtures so the store entry
/// is valid enough for `lpm build` to resolve.
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
    pkg_dir
}

/// Minimal lockfile listing the two fixture packages.
fn write_lockfile(project: &Path) {
    let toml = r#"[metadata]
lockfile-version = 1
resolved-with = "pubgrub"

[[packages]]
name = "trusted-pkg"
version = "1.0.0"

[[packages]]
name = "untrusted-pkg"
version = "1.0.0"
"#;
    fs::write(project.join("lpm.lock"), toml).unwrap();
}

/// Project `package.json` with a legacy bare-name entry in
/// `lpm.trustedDependencies`. Legacy form is load-bearing here: the
/// strict-form binding would require a real `scriptHash` to match
/// the seeded package, which couples the fixture to the hash
/// algorithm's current output. Legacy bare-name bypasses the hash
/// check (accepts any script body for the named package) — exactly
/// the pre-P4 behavior that earned it its soft-deprecation
/// warning. Under `--policy=deny` the LegacyName trust reason
/// still promotes the package to `is_trusted = true`, which is all
/// the golden needs: one trusted (included) and one untrusted
/// (filtered out).
fn write_project_package_json(project: &Path) {
    fs::write(
        project.join("package.json"),
        r#"{
    "name": "p46-close-deny-baseline",
    "version": "0.0.1",
    "lpm": {
        "trustedDependencies": ["trusted-pkg"]
    }
}
"#,
    )
    .unwrap();
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
        seed_package(&home, "trusted-pkg", "1.0.0", "echo hi");
        seed_package(&home, "untrusted-pkg", "1.0.0", "echo hi");
        write_lockfile(&project);
        write_project_package_json(&project);
        Fixture {
            _tmpdir: tmpdir,
            home,
            project,
        }
    }
}

// ── Baseline guard ─────────────────────────────────────────────────

/// Ship criterion for Chunk 5: `lpm build --dry-run --policy=deny
/// --json` on the 2-pkg fixture produces byte-equal output with
/// the committed golden. Any drift — intentional or not —
/// requires touching this file, which forces the developer to
/// decide whether the delta is a legit schema evolution (update
/// via `UPDATE_GOLDEN=1`) or an accidental regression (revert).
#[test]
fn p46_close_chunk5_policy_deny_dry_run_json_matches_golden() {
    let fx = Fixture::new();

    let (status, stdout, stderr) = run_lpm(
        &fx.project,
        &fx.home,
        &["--json", "build", "--dry-run", "--policy=deny"],
    );

    assert!(
        status.success(),
        "build --dry-run --policy=deny --json must exit 0. \
         stdout={stdout}\nstderr={stderr}"
    );

    let golden_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("p46_close_policy_deny_baseline.stdout");

    if std::env::var_os("UPDATE_GOLDEN").is_some() {
        fs::write(&golden_path, &stdout).unwrap();
        // Re-read so the assertion still fires; if the write
        // succeeded the comparison is trivially byte-equal, but
        // the assertion's error path is where the developer sees
        // the new content in a diff if another mismatch sneaks in.
    }

    let expected = fs::read_to_string(&golden_path).expect(
        "golden file missing at tests/fixtures/p46_close_policy_deny_baseline.stdout \
         — run once with UPDATE_GOLDEN=1 to capture the initial baseline",
    );

    assert_eq!(
        stdout, expected,
        "deny-mode `--dry-run --json` output drifted from the committed baseline. \
         If the change is intentional (new field, reshaped key, etc.), re-run:\n\
         \n    UPDATE_GOLDEN=1 cargo test -p lpm-cli --test p46_close_policy_deny_baseline\n\
         \n\
         …and commit the updated golden. If the change is unintended, revert \
         the code change that produced the drift.\n\
         \n\
         --- expected (golden) ---\n{expected}\n\
         --- actual ---\n{stdout}\n"
    );
}

/// Stream-separation sanity: under `--json`, stdout must be
/// parseable JSON and contain only the envelope — no human
/// warnings, no pointer text, no stderr bleed. Pairs with the
/// byte-equal golden above: if the golden ever passes but
/// stdout has extra content before/after the JSON, this parse
/// fails first and reports the exact offending shape.
#[test]
fn p46_close_chunk5_policy_deny_dry_run_json_stdout_is_clean_json() {
    let fx = Fixture::new();

    let (status, stdout, _stderr) = run_lpm(
        &fx.project,
        &fx.home,
        &["--json", "build", "--dry-run", "--policy=deny"],
    );

    assert!(status.success());
    let parsed: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap_or_else(|e| {
        panic!(
            "deny-mode --dry-run --json stdout must be parseable JSON. \
             Parse error: {e}\nstdout:\n{stdout}"
        )
    });
    assert_eq!(parsed["dry_run"].as_bool(), Some(true));
    let packages = parsed["packages"]
        .as_array()
        .expect("packages array must be present");
    assert_eq!(
        packages.len(),
        1,
        "deny-mode filter must include only the trusted package"
    );
    assert_eq!(packages[0]["name"].as_str(), Some("trusted-pkg"));
    assert_eq!(packages[0]["trusted"].as_bool(), Some(true));
}
