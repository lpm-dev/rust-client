//! Workflow tests for `lpm patch` + `lpm patch-commit`.
//!
//! Phase 32 Phase 6 acceptance criteria for the patch authoring loop:
//! - `lpm patch <key>` extracts a clean staging copy (filtering internal
//!   sentinels), prints a breadcrumb, and surfaces the staging path.
//! - `lpm patch-commit <dir>` writes `patches/<key>.patch`, updates
//!   `package.json > lpm > patchedDependencies`, and cleans up staging.
//! - Range version keys are rejected (only exact pins are supported today).
//! - Binary-file changes are rejected (text-only patch contract).
//! - "No changes" attempts hard-error with a clear diagnostic.
//!
//! The companion install + apply + offline + JSON tests live in
//! `install_patches.rs`. Graph `--why` + patch traces live in `graph.rs`.
//!
//! Subprocess-only — patch authoring exercises the file-system staging
//! dir + breadcrumb format + JSON envelope; unit tests can't observe
//! stdout/stderr separation or the on-disk artifact layout.

mod support;

use std::path::{Path, PathBuf};
use support::{TempProject, lpm_with_registry};

// ─── Helpers ────────────────────────────────────────────────────────────

/// Strip ANSI escapes; UTF-8-safe (iterates `chars()`).
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

/// Seed `<store>/v1/<safe_name>@<version>/` with package.json, the
/// supplied source files, and the `.integrity` sentinel. Returns the
/// integrity string the engine reads back from disk.
fn seed_store_package(
    project: &TempProject,
    name: &str,
    version: &str,
    files: &[(&str, &str)],
) -> String {
    let safe_name = name.replace(['/', '\\'], "+");
    let dir = project
        .store_dir()
        .join("v1")
        .join(format!("{safe_name}@{version}"));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("package.json"),
        format!(r#"{{"name":"{name}","version":"{version}"}}"#),
    )
    .unwrap();
    for (rel, content) in files {
        let p = dir.join(rel);
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(&p, content).unwrap();
    }
    let integrity = format!("sha512-fixture-{name}-{version}");
    std::fs::write(dir.join(".integrity"), &integrity).unwrap();
    integrity
}

// ─── `lpm patch <key>` extracts staging dir ────────────────────────────

/// `lpm patch <name@version>` copies the store package into a temp
/// staging dir, drops a `.lpm-patch.json` breadcrumb, and prints the
/// staging path. Internal sentinels (`.integrity`) must NOT survive
/// into the staging copy.
#[test]
fn patch_extracts_to_temp_dir_with_breadcrumb() {
    let project = TempProject::empty(r#"{"name":"patch-extract-test","version":"0.0.0"}"#);
    seed_store_package(
        &project,
        "lodash",
        "4.17.21",
        &[("index.js", "module.exports = 'orig'")],
    );

    let out = lpm_with_registry(&project, "http://127.0.0.1:1")
        .args(["--json", "patch", "lodash@4.17.21"])
        .output()
        .expect("spawn lpm patch");
    assert!(
        out.status.success(),
        "patch must succeed; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    // F-V12 contract: stdout in --json mode is valid JSON.
    let stdout = String::from_utf8_lossy(&out.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&strip_ansi(&stdout))
        .unwrap_or_else(|e| panic!("stdout not valid JSON: {e}\nstdout:\n{stdout}"));
    assert_eq!(parsed["success"], serde_json::json!(true));
    assert_eq!(parsed["name"].as_str(), Some("lodash"));
    assert_eq!(parsed["version"].as_str(), Some("4.17.21"));

    let staging = PathBuf::from(
        parsed["staging_dir"]
            .as_str()
            .expect("staging_dir must be present"),
    );

    let pkg_dir = staging.join("node_modules").join("lodash");
    assert!(
        pkg_dir.join("package.json").exists(),
        "package.json must exist in staging"
    );
    assert!(
        pkg_dir.join("index.js").exists(),
        "index.js must exist in staging"
    );

    // Breadcrumb at the staging root.
    let breadcrumb = staging.join(".lpm-patch.json");
    assert!(breadcrumb.exists(), "breadcrumb file must exist");
    let bc: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&breadcrumb).unwrap()).unwrap();
    assert_eq!(bc["name"].as_str(), Some("lodash"));
    assert_eq!(bc["version"].as_str(), Some("4.17.21"));
    assert_eq!(bc["key"].as_str(), Some("lodash@4.17.21"));

    // Internal sentinels filtered.
    assert!(
        !pkg_dir.join(".integrity").exists(),
        ".integrity must not survive into the staging copy"
    );

    let _ = std::fs::remove_dir_all(&staging);
}

/// `lpm patch <key>` against a package not in the store hard-errors
/// with a recovery hint pointing at `lpm install`.
#[test]
fn patch_fails_when_package_not_in_store() {
    let project = TempProject::empty(r#"{"name":"patch-no-store","version":"0.0.0"}"#);
    // Intentionally no seeded store entry.

    let out = lpm_with_registry(&project, "http://127.0.0.1:1")
        .args(["patch", "lodash@4.17.21"])
        .output()
        .expect("spawn lpm patch");
    assert!(
        !out.status.success(),
        "patch must fail when store has no copy; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let combined = strip_ansi(&format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    ));
    assert!(
        combined.contains("not in the global store") || combined.contains("Run `lpm install"),
        "error must explain how to recover; got:\n{combined}"
    );
}

/// Range selectors require a project lockfile to resolve against.
/// Without one, the command errors before taking the global store
/// lock with an actionable "run `lpm install`" hint. The exact-pin
/// path is unaffected — it works on projects with no lockfile (see
/// `patch_extracts_to_temp_dir_with_breadcrumb`).
#[test]
fn patch_range_without_lockfile_errors_with_actionable_hint() {
    let project = TempProject::empty(r#"{"name":"patch-range-no-lock","version":"0.0.0"}"#);
    seed_store_package(&project, "lodash", "4.17.21", &[("a.js", "x")]);

    let out = lpm_with_registry(&project, "http://127.0.0.1:1")
        .args(["patch", "lodash@^4.17.0"])
        .output()
        .expect("spawn lpm patch");
    assert!(
        !out.status.success(),
        "range selector without lockfile must fail; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let combined = strip_ansi(&format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    ));
    assert!(
        combined.contains("require") && combined.contains("lockfile"),
        "error must explain lockfile requirement; got:\n{combined}"
    );
    assert!(
        combined.contains("lpm install") || combined.contains("exact pin"),
        "error must hint at the recovery paths; got:\n{combined}"
    );
}

/// Dist-tags (`latest`, `next`, `beta`) are explicitly out of scope.
/// The selector path never consults the registry.
#[test]
fn patch_rejects_dist_tag_selectors() {
    let project = TempProject::empty(r#"{"name":"patch-dist-tag","version":"0.0.0"}"#);
    seed_store_package(&project, "lodash", "4.17.21", &[("a.js", "x")]);

    let out = lpm_with_registry(&project, "http://127.0.0.1:1")
        .args(["patch", "lodash@latest"])
        .output()
        .expect("spawn lpm patch");
    assert!(!out.status.success(), "dist-tag selector must fail");
    let combined = strip_ansi(&format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    ));
    assert!(
        combined.contains("dist-tag"),
        "error must mention dist-tag; got:\n{combined}"
    );
}

// ─── `lpm patch-commit <dir>` writes patch + updates manifest ──────────

/// End-to-end happy path: extract → edit → commit. Pin all four
/// post-conditions: (1) JSON envelope shape, (2) on-disk patch file
/// content, (3) `package.json > lpm > patchedDependencies` mutation,
/// (4) staging dir cleanup.
#[test]
fn patch_commit_writes_patch_file_and_updates_manifest() {
    let project = TempProject::empty(r#"{"name":"patch-commit-flow","version":"0.0.0"}"#);
    let integrity = seed_store_package(
        &project,
        "lodash",
        "4.17.21",
        &[("index.js", "module.exports = 'orig'\n")],
    );

    // Step 1: extract.
    let out1 = lpm_with_registry(&project, "http://127.0.0.1:1")
        .args(["--json", "patch", "lodash@4.17.21"])
        .output()
        .expect("spawn lpm patch");
    assert!(
        out1.status.success(),
        "extract failed: stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out1.stdout),
        String::from_utf8_lossy(&out1.stderr)
    );
    let parsed1: serde_json::Value =
        serde_json::from_str(&strip_ansi(&String::from_utf8_lossy(&out1.stdout))).unwrap();
    let staging = PathBuf::from(parsed1["staging_dir"].as_str().unwrap());

    // Step 2: edit a file in the staging dir.
    let edit_target = staging.join("node_modules/lodash/index.js");
    std::fs::write(&edit_target, "module.exports = 'PATCHED'\n").unwrap();

    // Step 3: commit.
    let out2 = lpm_with_registry(&project, "http://127.0.0.1:1")
        .args(["--json", "patch-commit", staging.to_str().unwrap()])
        .output()
        .expect("spawn lpm patch-commit");
    assert!(
        out2.status.success(),
        "patch-commit failed; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out2.stdout),
        String::from_utf8_lossy(&out2.stderr)
    );

    // F-V12: stdout valid JSON.
    let parsed2: serde_json::Value =
        serde_json::from_str(&strip_ansi(&String::from_utf8_lossy(&out2.stdout))).unwrap();
    assert_eq!(parsed2["success"], serde_json::json!(true));
    assert_eq!(parsed2["name"].as_str(), Some("lodash"));
    assert_eq!(parsed2["version"].as_str(), Some("4.17.21"));
    assert_eq!(parsed2["files_changed"].as_u64(), Some(1));
    assert!(parsed2["insertions"].as_u64().unwrap() >= 1);
    assert!(parsed2["deletions"].as_u64().unwrap() >= 1);
    assert_eq!(
        parsed2["original_integrity"].as_str(),
        Some(integrity.as_str())
    );

    // Patch file on disk + content.
    let patch_file = project.path().join("patches/lodash@4.17.21.patch");
    assert!(patch_file.exists(), "patch file must exist");
    let patch_text = std::fs::read_to_string(&patch_file).unwrap();
    assert!(patch_text.contains("--- a/index.js"));
    assert!(patch_text.contains("+++ b/index.js"));
    assert!(patch_text.contains("-module.exports = 'orig'"));
    assert!(patch_text.contains("+module.exports = 'PATCHED'"));

    // Manifest has the new entry.
    let pkg: serde_json::Value = serde_json::from_str(&project.read_file("package.json")).unwrap();
    assert_eq!(
        pkg["lpm"]["patchedDependencies"]["lodash@4.17.21"]["path"].as_str(),
        Some("patches/lodash@4.17.21.patch")
    );
    assert_eq!(
        pkg["lpm"]["patchedDependencies"]["lodash@4.17.21"]["originalIntegrity"].as_str(),
        Some(integrity.as_str())
    );

    // Staging dir cleaned up.
    assert!(
        !staging.exists(),
        "patch-commit must clean up the staging dir"
    );
}

/// `lpm patch-commit` against a staging dir with no edits hard-errors
/// with a clear "no changes detected" diagnostic. Avoids generating an
/// empty patch file that would break later drift checks.
#[test]
fn patch_commit_fails_on_no_changes() {
    let project = TempProject::empty(r#"{"name":"patch-no-changes","version":"0.0.0"}"#);
    seed_store_package(&project, "lodash", "4.17.21", &[("index.js", "x\n")]);

    let out1 = lpm_with_registry(&project, "http://127.0.0.1:1")
        .args(["--json", "patch", "lodash@4.17.21"])
        .output()
        .expect("spawn lpm patch");
    let parsed1: serde_json::Value =
        serde_json::from_str(&strip_ansi(&String::from_utf8_lossy(&out1.stdout))).unwrap();
    let staging = PathBuf::from(parsed1["staging_dir"].as_str().unwrap());

    // Don't edit anything; commit must fail.
    let out = lpm_with_registry(&project, "http://127.0.0.1:1")
        .args(["patch-commit", staging.to_str().unwrap()])
        .output()
        .expect("spawn lpm patch-commit");
    assert!(
        !out.status.success(),
        "patch-commit with no changes must fail; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let combined = strip_ansi(&format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    ));
    assert!(
        combined.contains("no changes detected"),
        "error must mention 'no changes detected'; got:\n{combined}"
    );
    let _: &Path = staging.as_path();
    let _ = std::fs::remove_dir_all(&staging);
}

/// Binary-file changes must be rejected at commit. The text-only patch
/// contract avoids unrepresentable diffs that the apply pass couldn't
/// reverse cleanly.
#[test]
fn patch_commit_fails_on_binary_change() {
    let project = TempProject::empty(r#"{"name":"patch-binary","version":"0.0.0"}"#);
    seed_store_package(&project, "lodash", "4.17.21", &[("logo.txt", "hello\n")]);

    let out1 = lpm_with_registry(&project, "http://127.0.0.1:1")
        .args(["--json", "patch", "lodash@4.17.21"])
        .output()
        .expect("spawn lpm patch");
    let parsed1: serde_json::Value =
        serde_json::from_str(&strip_ansi(&String::from_utf8_lossy(&out1.stdout))).unwrap();
    let staging = PathBuf::from(parsed1["staging_dir"].as_str().unwrap());

    // Replace text content with binary bytes.
    std::fs::write(
        staging.join("node_modules/lodash/logo.txt"),
        b"hello\x00binary",
    )
    .unwrap();

    let out = lpm_with_registry(&project, "http://127.0.0.1:1")
        .args(["patch-commit", staging.to_str().unwrap()])
        .output()
        .expect("spawn lpm patch-commit");
    assert!(
        !out.status.success(),
        "patch-commit must reject binary edits; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let combined = strip_ansi(&format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    ));
    assert!(
        combined.contains("binary"),
        "error must mention 'binary'; got:\n{combined}"
    );
    let _ = std::fs::remove_dir_all(&staging);
}

// ─── Selector resolution (Slice A) ─────────────────────────────────────

/// Write a synthetic `lpm.lock` listing `(name, version)` pairs. Used
/// to set up selector-resolution fixtures. `source` defaults to npm.
fn write_lockfile(project: &TempProject, entries: &[(&str, &str)]) {
    let mut toml = String::from("[metadata]\nlockfile-version = 2\nresolved-with = \"test\"\n\n");
    for (name, version) in entries {
        toml.push_str(&format!(
            "[[packages]]\nname = \"{name}\"\nversion = \"{version}\"\n\
             source = \"registry+https://registry.npmjs.org\"\n\n",
        ));
    }
    project.write_file("lpm.lock", &toml);
}

/// `lpm patch lodash@^4.0.0` against a project with `lodash@4.17.21`
/// in the lockfile resolves the range to the exact pin BEFORE writing
/// the staging breadcrumb. The breadcrumb's `key` field is the
/// resolved exact pin, never the raw user input.
#[test]
fn patch_range_selector_resolves_to_exact_pin() {
    let project = TempProject::empty(r#"{"name":"patch-range-resolve","version":"0.0.0"}"#);
    seed_store_package(&project, "lodash", "4.17.21", &[("a.js", "x")]);
    write_lockfile(&project, &[("lodash", "4.17.21")]);

    let out = lpm_with_registry(&project, "http://127.0.0.1:1")
        .args(["--json", "patch", "lodash@^4.0.0"])
        .output()
        .expect("spawn lpm patch");
    assert!(
        out.status.success(),
        "range selector must resolve; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let parsed: serde_json::Value =
        serde_json::from_str(&strip_ansi(&String::from_utf8_lossy(&out.stdout))).unwrap();
    assert_eq!(parsed["name"].as_str(), Some("lodash"));
    assert_eq!(parsed["version"].as_str(), Some("4.17.21"));
    assert_eq!(
        parsed["key"].as_str(),
        Some("lodash@4.17.21"),
        "JSON envelope key must be the resolved exact pin, not the raw range"
    );

    let staging = PathBuf::from(parsed["staging_dir"].as_str().unwrap());
    let breadcrumb: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(staging.join(".lpm-patch.json")).unwrap())
            .unwrap();
    assert_eq!(
        breadcrumb["key"].as_str(),
        Some("lodash@4.17.21"),
        "breadcrumb key must be the resolved exact pin"
    );
    let _ = std::fs::remove_dir_all(&staging);
}

/// `lpm patch lodash` (bare name) against a project with a unique
/// `lodash` entry resolves to that version. End-to-end including
/// `lpm patch-commit` → the persisted-key invariant holds (the
/// `patches/<key>.patch` filename and `lpm.patchedDependencies` entry
/// both carry the resolved exact pin).
#[test]
fn patch_bare_name_selector_resolves_and_commits_exact_pin() {
    let project = TempProject::empty(r#"{"name":"patch-bare-name","version":"0.0.0"}"#);
    let integrity = seed_store_package(
        &project,
        "lodash",
        "4.17.21",
        &[("index.js", "module.exports = 'orig'\n")],
    );
    write_lockfile(&project, &[("lodash", "4.17.21")]);

    // Step 1: extract via bare name.
    let out1 = lpm_with_registry(&project, "http://127.0.0.1:1")
        .args(["--json", "patch", "lodash"])
        .output()
        .expect("spawn lpm patch");
    assert!(
        out1.status.success(),
        "bare-name selector must resolve; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out1.stdout),
        String::from_utf8_lossy(&out1.stderr),
    );
    let parsed1: serde_json::Value =
        serde_json::from_str(&strip_ansi(&String::from_utf8_lossy(&out1.stdout))).unwrap();
    assert_eq!(parsed1["key"].as_str(), Some("lodash@4.17.21"));
    let staging = PathBuf::from(parsed1["staging_dir"].as_str().unwrap());

    // Step 2: edit a file.
    std::fs::write(
        staging.join("node_modules/lodash/index.js"),
        "module.exports = 'PATCHED'\n",
    )
    .unwrap();

    // Step 3: commit. Should produce `patches/lodash@4.17.21.patch` and
    // a `lpm.patchedDependencies."lodash@4.17.21"` entry — NOT a raw-
    // range filename or key.
    let out2 = lpm_with_registry(&project, "http://127.0.0.1:1")
        .args(["--json", "patch-commit", staging.to_str().unwrap()])
        .output()
        .expect("spawn lpm patch-commit");
    assert!(
        out2.status.success(),
        "patch-commit must succeed; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out2.stdout),
        String::from_utf8_lossy(&out2.stderr),
    );

    let patch_file = project.path().join("patches/lodash@4.17.21.patch");
    assert!(
        patch_file.exists(),
        "patch file must use the resolved exact pin in its name"
    );
    let pkg: serde_json::Value = serde_json::from_str(&project.read_file("package.json")).unwrap();
    assert_eq!(
        pkg["lpm"]["patchedDependencies"]["lodash@4.17.21"]["path"].as_str(),
        Some("patches/lodash@4.17.21.patch"),
        "lpm.patchedDependencies key must be the resolved exact pin"
    );
    assert_eq!(
        pkg["lpm"]["patchedDependencies"]["lodash@4.17.21"]["originalIntegrity"].as_str(),
        Some(integrity.as_str())
    );
}

/// Bare name on a project with multiple distinct versions of the
/// package errors with a list-and-exit, no breadcrumb written.
#[test]
fn patch_bare_name_errors_with_list_on_multiple_versions() {
    let project = TempProject::empty(r#"{"name":"patch-multi","version":"0.0.0"}"#);
    seed_store_package(&project, "lodash", "3.10.0", &[("a.js", "x")]);
    seed_store_package(&project, "lodash", "4.17.21", &[("a.js", "x")]);
    write_lockfile(&project, &[("lodash", "3.10.0"), ("lodash", "4.17.21")]);

    let out = lpm_with_registry(&project, "http://127.0.0.1:1")
        .args(["patch", "lodash"])
        .output()
        .expect("spawn lpm patch");
    assert!(
        !out.status.success(),
        "ambiguous bare-name must fail; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let combined = strip_ansi(&format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    ));
    assert!(combined.contains("lodash@3.10.0"), "got:\n{combined}");
    assert!(combined.contains("lodash@4.17.21"), "got:\n{combined}");
    assert!(
        combined.contains("specify a precise version"),
        "got:\n{combined}"
    );
}
