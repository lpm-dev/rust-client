//! Workflow tests for `lpm patch` + `lpm patch-commit`.
//!
//! Acceptance criteria for the patch authoring loop:
//! - `lpm patch <selector>` extracts a clean staging copy (filtering
//!   internal sentinels), prints a breadcrumb, and surfaces the staging
//!   path. `<selector>` is a bare name, exact pin, or semver range —
//!   bare-name / range resolve against the project lockfile to an
//!   exact pin before staging.
//! - `lpm patch-commit <dir>` writes `patches/<safe_key>.patch`,
//!   updates `package.json > lpm > patchedDependencies`, and cleans up
//!   staging. The persisted key is always the resolved exact pin; for
//!   scoped names the `/` is replaced with `__` in the filename only
//!   (the manifest key keeps the real package selector).
//! - Range / bare-name selectors without a lockfile error with an
//!   actionable hint pointing at `lpm install` or an exact pin.
//! - Dist-tags (`latest`, `next`, `beta`) are rejected — the selector
//!   path never consults the registry.
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
    assert_eq!(
        parsed["next_steps"][0]["description"].as_str(),
        Some("Commit the patch after editing package_dir")
    );
    assert!(
        parsed["next_steps"][0]["command"]
            .as_str()
            .is_some_and(|command| command.starts_with("lpm patch-commit ")),
        "patch JSON must expose a runnable patch-commit next step: {parsed}",
    );

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

#[test]
fn patch_human_output_uses_slim_status_lines() {
    let project = TempProject::empty(r#"{"name":"patch-human","version":"0.0.0"}"#);
    seed_store_package(
        &project,
        "lodash",
        "4.17.21",
        &[("index.js", "module.exports = 'orig'")],
    );

    let out = lpm_with_registry(&project, "http://127.0.0.1:1")
        .args(["--color=always", "patch", "lodash@4.17.21"])
        .output()
        .expect("spawn lpm patch");
    assert!(
        out.status.success(),
        "patch must succeed; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    let raw = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let combined = strip_ansi(&raw);
    assert!(
        combined.contains("› Extracting pristine store entry for lodash@4.17.21"),
        "human output must start with a slim phase line; got:\n{combined}"
    );
    assert!(
        combined.contains("source:"),
        "must show source path:\n{combined}"
    );
    assert!(
        combined.contains("staging:"),
        "must show staging path:\n{combined}"
    );
    assert!(
        combined.contains("✓ Ready · edit files in the staging directory, then run:"),
        "must show slim ready line; got:\n{combined}"
    );
    assert!(
        combined.contains("lpm patch-commit"),
        "must show next command; got:\n{combined}"
    );
    assert!(
        raw.contains("\u{1b}[33mlodash@4.17.21\u{1b}[39m")
            && raw.contains("\u{1b}[2msource: \u{1b}[22m")
            && raw.contains("\u{1b}[2mstaging:\u{1b}[22m")
            && raw.contains("\u{1b}[33mlpm patch-commit"),
        "patch output must apply slim color roles, got:\n{raw:?}"
    );
    assert!(
        !combined.contains('│') && !combined.contains('◇'),
        "patch output should not use bordered/cliclack glyphs; got:\n{combined}"
    );

    if let Some(staging) = combined
        .lines()
        .find_map(|line| line.trim().strip_prefix("lpm patch-commit "))
    {
        let _ = std::fs::remove_dir_all(staging);
    }
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

#[test]
fn patch_commit_updates_lockfile_patch_checksum_record() {
    let project = TempProject::empty(r#"{"name":"patch-commit-lockfile","version":"0.0.0"}"#);
    let integrity = seed_store_package(
        &project,
        "lodash",
        "4.17.21",
        &[("index.js", "module.exports = 'orig'\n")],
    );
    write_lockfile(&project, &[("lodash", "4.17.21")]);

    let extract = lpm_with_registry(&project, "http://127.0.0.1:1")
        .args(["--json", "patch", "lodash@4.17.21"])
        .output()
        .expect("spawn lpm patch");
    assert!(
        extract.status.success(),
        "extract failed: stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&extract.stdout),
        String::from_utf8_lossy(&extract.stderr)
    );
    let parsed: serde_json::Value =
        serde_json::from_str(&strip_ansi(&String::from_utf8_lossy(&extract.stdout))).unwrap();
    let staging = PathBuf::from(parsed["staging_dir"].as_str().unwrap());
    std::fs::write(
        staging.join("node_modules/lodash/index.js"),
        "module.exports = 'PATCHED'\n",
    )
    .unwrap();

    let commit = lpm_with_registry(&project, "http://127.0.0.1:1")
        .args(["--json", "patch-commit", staging.to_str().unwrap()])
        .output()
        .expect("spawn lpm patch-commit");
    assert!(
        commit.status.success(),
        "patch-commit failed: stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&commit.stdout),
        String::from_utf8_lossy(&commit.stderr)
    );
    let commit_json: serde_json::Value =
        serde_json::from_str(&strip_ansi(&String::from_utf8_lossy(&commit.stdout))).unwrap();
    assert_eq!(commit_json["lockfile_updated"], serde_json::json!(true));

    let lockfile = lpm_lockfile::Lockfile::read_fast(&project.path().join("lpm.lock")).unwrap();
    let record = lockfile.patches.get("lodash@4.17.21").unwrap();
    assert_eq!(record.path, "patches/lodash@4.17.21.patch");
    assert_eq!(record.original_integrity, integrity);
    assert_eq!(
        record.sha256,
        patch_sha256(&project, "patches/lodash@4.17.21.patch")
    );
}

#[test]
fn patch_commit_human_output_uses_slim_status_lines() {
    let project = TempProject::empty(r#"{"name":"patch-commit-human","version":"0.0.0"}"#);
    seed_store_package(
        &project,
        "lodash",
        "4.17.21",
        &[("index.js", "module.exports = 'orig'\n")],
    );

    let extract = lpm_with_registry(&project, "http://127.0.0.1:1")
        .args(["--json", "patch", "lodash@4.17.21"])
        .output()
        .expect("spawn lpm patch");
    assert!(extract.status.success(), "extract must succeed");
    let parsed: serde_json::Value =
        serde_json::from_str(&strip_ansi(&String::from_utf8_lossy(&extract.stdout))).unwrap();
    let staging = PathBuf::from(parsed["staging_dir"].as_str().unwrap());
    std::fs::write(
        staging.join("node_modules/lodash/index.js"),
        "module.exports = 'PATCHED'\n",
    )
    .unwrap();

    let out = lpm_with_registry(&project, "http://127.0.0.1:1")
        .args(["--color=always", "patch-commit", staging.to_str().unwrap()])
        .output()
        .expect("spawn lpm patch-commit");
    assert!(
        out.status.success(),
        "patch-commit failed; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    let raw = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let combined = strip_ansi(&raw);
    assert!(
        combined.contains("› Generating patch for lodash@4.17.21"),
        "must show slim phase line; got:\n{combined}"
    );
    assert!(
        combined.contains("✓ Wrote patches/lodash@4.17.21.patch"),
        "must show patch file write; got:\n{combined}"
    );
    assert!(
        combined.contains("✓ Updated package.json › lpm.patchedDependencies"),
        "must show manifest update; got:\n{combined}"
    );
    assert!(
        raw.contains("\u{1b}[33mlodash@4.17.21\u{1b}[39m")
            && raw.contains("\u{1b}[2mpatches/lodash@4.17.21.patch\u{1b}[22m")
            && raw.contains("\u{1b}[36mpackage.json › lpm.patchedDependencies\u{1b}[39m"),
        "patch-commit output must apply slim color roles, got:\n{raw:?}"
    );
    assert!(
        combined.contains("✓ Done · patch registered for future installs"),
        "must show final slim completion; got:\n{combined}"
    );
    assert!(
        !combined.contains('│') && !combined.contains('◇'),
        "patch-commit output should not use bordered/cliclack glyphs; got:\n{combined}"
    );
}

/// `lpm patch-remove <exact-pin> --json` removes the manifest entry
/// and deletes the now-unreferenced patch file.
#[test]
fn patch_remove_exact_pin_removes_manifest_entry_and_patch_file() {
    let project = TempProject::empty(
        r#"{
  "name": "patch-remove-flow",
  "version": "0.0.0",
  "lpm": {
    "patchedDependencies": {
      "lodash@4.17.21": {
        "path": "patches/lodash@4.17.21.patch",
        "originalIntegrity": "sha512-fixture"
      }
    }
  }
}"#,
    );
    project.write_file("patches/lodash@4.17.21.patch", "diff --git a/a b/a\n");

    let out = lpm_with_registry(&project, "http://127.0.0.1:1")
        .args(["--json", "patch-remove", "lodash@4.17.21"])
        .output()
        .expect("spawn lpm patch-remove");
    assert!(
        out.status.success(),
        "patch-remove failed; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    let parsed: serde_json::Value =
        serde_json::from_str(&strip_ansi(&String::from_utf8_lossy(&out.stdout))).unwrap();
    assert_eq!(parsed["success"], serde_json::json!(true));
    assert_eq!(parsed["dry_run"], serde_json::json!(false));
    assert_eq!(parsed["removed"][0]["key"].as_str(), Some("lodash@4.17.21"));
    assert_eq!(
        parsed["removed"][0]["patch_file"].as_str(),
        Some("patches/lodash@4.17.21.patch")
    );
    assert_eq!(
        parsed["removed"][0]["deleted_patch_file"],
        serde_json::json!(true)
    );

    assert!(
        !project.file_exists("patches/lodash@4.17.21.patch"),
        "patch file should be deleted"
    );
    let pkg: serde_json::Value = serde_json::from_str(&project.read_file("package.json")).unwrap();
    assert!(
        pkg.get("lpm").is_none(),
        "empty lpm section should be removed after the last patch entry"
    );
}

#[test]
fn patch_remove_removes_lockfile_patch_checksum_record() {
    let project = TempProject::empty(
        r#"{
  "name": "patch-remove-lockfile",
  "version": "0.0.0",
  "lpm": {
    "patchedDependencies": {
      "lodash@4.17.21": {
        "path": "patches/lodash@4.17.21.patch",
        "originalIntegrity": "sha512-fixture"
      }
    }
  }
}"#,
    );
    project.write_file("patches/lodash@4.17.21.patch", "diff --git a/a b/a\n");
    write_lockfile(&project, &[("lodash", "4.17.21")]);
    append_lockfile_patch_record(
        &project,
        "lodash@4.17.21",
        "patches/lodash@4.17.21.patch",
        "sha512-fixture",
    );

    let out = lpm_with_registry(&project, "http://127.0.0.1:1")
        .args(["--json", "patch-remove", "lodash@4.17.21"])
        .output()
        .expect("spawn lpm patch-remove");
    assert!(
        out.status.success(),
        "patch-remove failed; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let parsed: serde_json::Value =
        serde_json::from_str(&strip_ansi(&String::from_utf8_lossy(&out.stdout))).unwrap();
    assert_eq!(parsed["lockfile_updated"], serde_json::json!(true));

    let lockfile = lpm_lockfile::Lockfile::read_fast(&project.path().join("lpm.lock")).unwrap();
    assert!(
        !lockfile.patches.contains_key("lodash@4.17.21"),
        "patch-remove must delete the matching lpm.lock patch record"
    );
}

#[test]
fn workspace_member_patch_commit_and_remove_change_only_its_root_projection() {
    let project = TempProject::empty(
        r#"{
  "name": "patch-workspace",
  "version": "1.0.0",
  "private": true,
  "workspaces": ["packages/*"]
}"#,
    );
    project.write_file(
        "packages/app/package.json",
        r#"{"name":"patch-app","version":"1.0.0","private":true}"#,
    );
    project.write_file(
        "packages/sibling/package.json",
        r#"{"name":"patch-sibling","version":"1.0.0","private":true}"#,
    );

    let mut root_lockfile = lpm_lockfile::Lockfile::new();
    root_lockfile
        .absorb_importer(".", lpm_lockfile::Lockfile::new())
        .unwrap();
    root_lockfile
        .absorb_importer("packages/app", lpm_lockfile::Lockfile::new())
        .unwrap();
    let mut sibling_projection = lpm_lockfile::Lockfile::new();
    sibling_projection.patches.insert(
        "sibling@1.0.0".into(),
        lpm_lockfile::LockfilePatch {
            path: "patches/sibling.patch".into(),
            sha256: "sha256-sibling".into(),
            original_integrity: "sha512-sibling".into(),
        },
    );
    root_lockfile
        .absorb_importer("packages/sibling", sibling_projection)
        .unwrap();
    root_lockfile
        .write_all(&project.path().join("lpm.lock"))
        .unwrap();
    let sibling_before = root_lockfile.project_importer("packages/sibling").unwrap();

    seed_store_package(
        &project,
        "lodash",
        "4.17.21",
        &[("index.js", "module.exports = 'orig'\n")],
    );
    let app_dir = project.path().join("packages/app");
    let extract = lpm_with_registry(&project, "http://127.0.0.1:1")
        .current_dir(&app_dir)
        .args(["--json", "patch", "lodash@4.17.21"])
        .output()
        .expect("extract workspace member patch staging tree");
    assert!(
        extract.status.success(),
        "workspace patch extraction failed: stdout={} stderr={}",
        String::from_utf8_lossy(&extract.stdout),
        String::from_utf8_lossy(&extract.stderr),
    );
    let extract_json: serde_json::Value =
        serde_json::from_slice(&extract.stdout).expect("parse patch extraction JSON");
    let staging = PathBuf::from(extract_json["staging_dir"].as_str().unwrap());
    std::fs::write(
        staging.join("node_modules/lodash/index.js"),
        "module.exports = 'patched'\n",
    )
    .unwrap();

    let commit = lpm_with_registry(&project, "http://127.0.0.1:1")
        .current_dir(&app_dir)
        .args(["--json", "patch-commit", staging.to_str().unwrap()])
        .output()
        .expect("commit workspace member patch");
    assert!(
        commit.status.success(),
        "workspace patch commit failed: stdout={} stderr={}",
        String::from_utf8_lossy(&commit.stdout),
        String::from_utf8_lossy(&commit.stderr),
    );

    let after_commit = lpm_lockfile::Lockfile::read_fast(&project.path().join("lpm.lock")).unwrap();
    assert!(
        after_commit
            .project_importer("packages/app")
            .unwrap()
            .patches
            .contains_key("lodash@4.17.21")
    );
    assert_eq!(
        after_commit.project_importer("packages/sibling").unwrap(),
        sibling_before
    );
    assert!(!app_dir.join("lpm.lock").exists());

    let remove = lpm_with_registry(&project, "http://127.0.0.1:1")
        .current_dir(&app_dir)
        .args(["--json", "patch-remove", "lodash@4.17.21"])
        .output()
        .expect("remove workspace member patch");
    assert!(
        remove.status.success(),
        "workspace patch removal failed: stdout={} stderr={}",
        String::from_utf8_lossy(&remove.stdout),
        String::from_utf8_lossy(&remove.stderr),
    );

    let after_remove = lpm_lockfile::Lockfile::read_fast(&project.path().join("lpm.lock")).unwrap();
    assert!(
        !after_remove
            .project_importer("packages/app")
            .unwrap()
            .patches
            .contains_key("lodash@4.17.21")
    );
    assert_eq!(
        after_remove.project_importer("packages/sibling").unwrap(),
        sibling_before
    );
    assert!(!app_dir.join("lpm.lockb").exists());
}

#[test]
fn patch_remove_human_output_uses_slim_status_lines() {
    let project = TempProject::empty(
        r#"{
  "name": "patch-remove-human",
  "version": "0.0.0",
  "lpm": {
    "patchedDependencies": {
      "lodash@4.17.21": {
        "path": "patches/lodash@4.17.21.patch",
        "originalIntegrity": "sha512-fixture"
      }
    }
  }
}"#,
    );
    project.write_file("patches/lodash@4.17.21.patch", "diff --git a/a b/a\n");

    let out = lpm_with_registry(&project, "http://127.0.0.1:1")
        .args(["--color=always", "patch-remove", "lodash@4.17.21"])
        .output()
        .expect("spawn lpm patch-remove");
    assert!(
        out.status.success(),
        "patch-remove failed; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    let raw = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let combined = strip_ansi(&raw);
    assert!(
        combined.contains("› Removing patch registration for lodash@4.17.21"),
        "must show slim phase line; got:\n{combined}"
    );
    assert!(combined.contains("manifest: package.json"));
    assert!(combined.contains("file:"));
    assert!(combined.contains("patches/lodash@4.17.21.patch"));
    assert!(
        raw.contains("\u{1b}[33mlodash@4.17.21\u{1b}[39m")
            && raw.contains("\u{1b}[2mmanifest:\u{1b}[22m")
            && raw.contains("\u{1b}[2mfile:    \u{1b}[22m")
            && raw.contains("\u{1b}[2mpatches/lodash@4.17.21.patch\u{1b}[22m"),
        "patch-remove output must align labels and apply slim color roles, got:\n{raw:?}"
    );
    assert!(combined.contains("✓ Deleted patch file"));
    assert!(combined.contains("✓ Done · re-run lpm install to refresh node_modules"));
    assert!(
        !combined.contains('│') && !combined.contains('◇'),
        "patch-remove output should not use bordered/cliclack glyphs; got:\n{combined}"
    );
}

/// Dry-run reports the same target but leaves both package.json and the
/// patch file untouched.
#[test]
fn patch_remove_dry_run_keeps_manifest_entry_and_patch_file() {
    let project = TempProject::empty(
        r#"{
  "name": "patch-remove-dry-run",
  "version": "0.0.0",
  "lpm": {
    "patchedDependencies": {
      "lodash@4.17.21": {
        "path": "patches/lodash@4.17.21.patch",
        "originalIntegrity": "sha512-fixture"
      }
    }
  }
}"#,
    );
    project.write_file("patches/lodash@4.17.21.patch", "diff --git a/a b/a\n");
    let before = project.read_file("package.json");

    let out = lpm_with_registry(&project, "http://127.0.0.1:1")
        .args(["--json", "patch-remove", "--dry-run", "lodash@4.17.21"])
        .output()
        .expect("spawn lpm patch-remove --dry-run");
    assert!(
        out.status.success(),
        "patch-remove dry-run failed; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    let parsed: serde_json::Value =
        serde_json::from_str(&strip_ansi(&String::from_utf8_lossy(&out.stdout))).unwrap();
    assert_eq!(parsed["dry_run"], serde_json::json!(true));
    assert_eq!(
        parsed["removed"][0]["retained_reason"].as_str(),
        Some("dry-run")
    );
    assert_eq!(project.read_file("package.json"), before);
    assert!(project.file_exists("patches/lodash@4.17.21.patch"));
}

/// Scoped packages (both npm-style `@scope/name` and lpm.dev-style
/// `@lpm.dev/owner.name`) flow through `patch-commit` correctly:
///
/// 1. The on-disk filename sanitizes `/` to `__`:
///    `patches/@posthog__nextjs-config@4.17.21.patch`.
/// 2. The `lpm.patchedDependencies` MANIFEST KEY keeps the real
///    package selector shape with `/`:
///    `"@posthog/nextjs-config@4.17.21"`.
/// 3. The `path` field inside that entry points at the sanitized
///    filename so the install pipeline can find it on disk.
///
/// `parse_patch_key` resolves the version by splitting on the LAST
/// `@`, so the leading `@` of the scope is preserved as part of the
/// name.
#[test]
fn patch_commit_handles_npm_scoped_package() {
    let project = TempProject::empty(r#"{"name":"patch-scoped-npm","version":"0.0.0"}"#);
    let integrity = seed_store_package(
        &project,
        "@posthog/nextjs-config",
        "4.17.21",
        &[("index.js", "module.exports = { posthog: true }\n")],
    );

    // Extract.
    let out1 = lpm_with_registry(&project, "http://127.0.0.1:1")
        .args(["--json", "patch", "@posthog/nextjs-config@4.17.21"])
        .output()
        .expect("spawn lpm patch");
    assert!(
        out1.status.success(),
        "scoped-name extract failed: stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out1.stdout),
        String::from_utf8_lossy(&out1.stderr)
    );
    let parsed1: serde_json::Value =
        serde_json::from_str(&strip_ansi(&String::from_utf8_lossy(&out1.stdout))).unwrap();
    assert_eq!(parsed1["name"].as_str(), Some("@posthog/nextjs-config"));
    assert_eq!(parsed1["version"].as_str(), Some("4.17.21"));
    let staging = PathBuf::from(parsed1["staging_dir"].as_str().unwrap());

    // Edit.
    let edit_target = staging.join("node_modules/@posthog/nextjs-config/index.js");
    std::fs::write(&edit_target, "module.exports = { posthog: 'PATCHED' }\n").unwrap();

    // Commit.
    let out2 = lpm_with_registry(&project, "http://127.0.0.1:1")
        .args(["--json", "patch-commit", staging.to_str().unwrap()])
        .output()
        .expect("spawn lpm patch-commit");
    assert!(
        out2.status.success(),
        "scoped patch-commit failed; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out2.stdout),
        String::from_utf8_lossy(&out2.stderr)
    );

    // On-disk filename: `/` → `__`.
    let patch_file = project
        .path()
        .join("patches/@posthog__nextjs-config@4.17.21.patch");
    assert!(
        patch_file.exists(),
        "patch file must be at sanitized path; expected: {patch_file:?}"
    );
    // The legacy raw-slash path must NOT exist (would break the
    // portability contract).
    assert!(
        !project
            .path()
            .join("patches/@posthog/nextjs-config@4.17.21.patch")
            .exists(),
        "raw-slash filename must not be created"
    );

    // Manifest key keeps the real package selector shape.
    let pkg: serde_json::Value = serde_json::from_str(&project.read_file("package.json")).unwrap();
    let entry = &pkg["lpm"]["patchedDependencies"]["@posthog/nextjs-config@4.17.21"];
    assert_eq!(
        entry["path"].as_str(),
        Some("patches/@posthog__nextjs-config@4.17.21.patch"),
        "manifest path field must point at the sanitized filename"
    );
    assert_eq!(
        entry["originalIntegrity"].as_str(),
        Some(integrity.as_str())
    );
}

/// `@lpm.dev/owner.name` packages — the LPM canonical scoping convention
/// (one dot in the name segment is normal here, unlike npm scopes which
/// rarely have dots). Same contract as the npm-scoped test.
#[test]
fn patch_commit_handles_lpm_dev_scoped_package() {
    let project = TempProject::empty(r#"{"name":"patch-scoped-lpm","version":"0.0.0"}"#);
    let integrity = seed_store_package(
        &project,
        "@lpm.dev/user.package",
        "1.2.3",
        &[("lib.js", "module.exports = 'lpm-orig'\n")],
    );

    let out1 = lpm_with_registry(&project, "http://127.0.0.1:1")
        .args(["--json", "patch", "@lpm.dev/user.package@1.2.3"])
        .output()
        .expect("spawn lpm patch");
    assert!(
        out1.status.success(),
        "lpm.dev scoped extract failed: stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out1.stdout),
        String::from_utf8_lossy(&out1.stderr)
    );
    let parsed1: serde_json::Value =
        serde_json::from_str(&strip_ansi(&String::from_utf8_lossy(&out1.stdout))).unwrap();
    assert_eq!(parsed1["name"].as_str(), Some("@lpm.dev/user.package"));
    assert_eq!(parsed1["version"].as_str(), Some("1.2.3"));
    let staging = PathBuf::from(parsed1["staging_dir"].as_str().unwrap());

    let edit_target = staging.join("node_modules/@lpm.dev/user.package/lib.js");
    std::fs::write(&edit_target, "module.exports = 'lpm-PATCHED'\n").unwrap();

    let out2 = lpm_with_registry(&project, "http://127.0.0.1:1")
        .args(["--json", "patch-commit", staging.to_str().unwrap()])
        .output()
        .expect("spawn lpm patch-commit");
    assert!(
        out2.status.success(),
        "lpm.dev patch-commit failed; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out2.stdout),
        String::from_utf8_lossy(&out2.stderr)
    );

    let patch_file = project
        .path()
        .join("patches/@lpm.dev__user.package@1.2.3.patch");
    assert!(patch_file.exists(), "expected: {patch_file:?}");

    let pkg: serde_json::Value = serde_json::from_str(&project.read_file("package.json")).unwrap();
    let entry = &pkg["lpm"]["patchedDependencies"]["@lpm.dev/user.package@1.2.3"];
    assert_eq!(
        entry["path"].as_str(),
        Some("patches/@lpm.dev__user.package@1.2.3.patch")
    );
    assert_eq!(
        entry["originalIntegrity"].as_str(),
        Some(integrity.as_str())
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
    let mut lockfile = lpm_lockfile::Lockfile::new_with_resolver("test");
    for (name, version) in entries {
        lockfile.add_package(lpm_lockfile::LockedPackage {
            name: (*name).to_string(),
            version: (*version).to_string(),
            source: Some("registry+https://registry.npmjs.org".to_string()),
            ..Default::default()
        });
    }
    if entries.iter().all(|(name, _)| {
        entries
            .iter()
            .filter(|(candidate, _)| candidate == name)
            .count()
            == 1
    }) {
        let roots = entries
            .iter()
            .map(|(name, version)| (*name, *name, *version))
            .collect::<Vec<_>>();
        support::finalize_exact_lockfile_fixture(&mut lockfile, &roots);
    } else {
        for (index, package) in lockfile.packages.iter_mut().enumerate() {
            package.instance_id = Some(lpm_common::PackageInstanceId::derive(
                &package.name,
                &package.version,
                package.source.as_deref().expect("registry source"),
                &format!("fixture/patch-selector/{index}"),
            ));
        }
        lockfile.metadata.lockfile_version = 12;
        for package in &mut lockfile.packages {
            package.instance_id = None;
        }
    }
    lockfile
        .write_all(&project.path().join("lpm.lock"))
        .expect("write patch selector lockfile");
}

fn patch_sha256(project: &TempProject, rel_path: &str) -> String {
    use sha2::{Digest, Sha256};
    let bytes = std::fs::read(project.path().join(rel_path)).unwrap();
    format!("sha256-{}", hex::encode(Sha256::digest(bytes)))
}

fn append_lockfile_patch_record(
    project: &TempProject,
    selector: &str,
    path: &str,
    integrity: &str,
) {
    let mut toml = project.read_file("lpm.lock");
    toml.push_str(&format!(
        "\n[patches.\"{selector}\"]\npath = \"{path}\"\nsha256 = \"{}\"\noriginal-integrity = \"{integrity}\"\n",
        patch_sha256(project, path),
    ));
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
