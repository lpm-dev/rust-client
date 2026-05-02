//! Workflow tests for `lpm migrate`.
//!
//! Tests the full migration path from npm/yarn/pnpm/bun lockfiles to LPM,
//! including backup creation, rollback, and dry-run.

mod support;

use support::assertions;
use support::{TempProject, lpm};

// ─── npm Migration ───────────────────────────────────────────────

#[test]
fn migrate_npm_creates_lockfile() {
    let project = TempProject::from_fixture("migrate-npm");

    let output = lpm(&project)
        .args(["migrate", "--no-install", "--force"])
        .output()
        .expect("failed to run lpm migrate");

    assert!(
        output.status.success(),
        "lpm migrate failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    assertions::assert_both_lockfiles_exist(project.path());
}

#[test]
fn migrate_npm_creates_backup() {
    let project = TempProject::from_fixture("migrate-npm");

    lpm(&project)
        .args(["migrate", "--no-install", "--force"])
        .assert()
        .success();

    assertions::assert_backup_exists(project.path(), "package-lock.json");
}

// ─── yarn Migration ──────────────────────────────────────────────

#[test]
fn migrate_yarn_creates_lockfile() {
    let project = TempProject::from_fixture("migrate-yarn");

    let output = lpm(&project)
        .args(["migrate", "--no-install", "--force"])
        .output()
        .expect("failed to run lpm migrate");

    assert!(
        output.status.success(),
        "lpm migrate (yarn) failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    assertions::assert_both_lockfiles_exist(project.path());
}

// ─── pnpm Migration ─────────────────────────────────────────────

#[test]
fn migrate_pnpm_creates_lockfile() {
    let project = TempProject::from_fixture("migrate-pnpm");

    let output = lpm(&project)
        .args(["migrate", "--no-install", "--force"])
        .output()
        .expect("failed to run lpm migrate");

    assert!(
        output.status.success(),
        "lpm migrate (pnpm) failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    assertions::assert_both_lockfiles_exist(project.path());
}

// ─── Phase 64 #34: pnpm.overrides translation ──────────────────

/// Clean translation: `pnpm.overrides` populated, no existing
/// `lpm.overrides`. Migration should write the converted block to
/// `lpm.overrides`, back up `package.json`, and report on stderr.
#[test]
fn migrate_pnpm_translates_overrides_to_lpm_section() {
    let project = TempProject::from_fixture("migrate-pnpm-overrides");

    let output = lpm(&project)
        .args(["migrate", "--no-install", "--force"])
        .output()
        .expect("failed to run lpm migrate");

    assert!(
        output.status.success(),
        "lpm migrate failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    // Verify lpm.overrides was populated with the pnpm entries.
    let pkg_json = std::fs::read_to_string(project.path().join("package.json")).unwrap();
    let pkg: serde_json::Value = serde_json::from_str(&pkg_json).unwrap();
    let lpm_overrides = pkg["lpm"]["overrides"]
        .as_object()
        .expect("lpm.overrides must be an object after migrate");
    assert_eq!(
        lpm_overrides.get("lodash").and_then(|v| v.as_str()),
        Some("^4.17.21"),
        "lodash entry should be carried over verbatim"
    );
    assert_eq!(
        lpm_overrides.get("react").and_then(|v| v.as_str()),
        Some("18.2.0")
    );

    // pnpm.overrides should still be in place — migrate doesn't strip
    // it (transition safety, FLAG F). The diff-aware install warning
    // silences naturally because lpm.overrides now mirrors it.
    let pnpm_overrides = pkg["pnpm"]["overrides"]
        .as_object()
        .expect("pnpm.overrides should remain in place after migrate");
    assert_eq!(pnpm_overrides.len(), 2);

    // package.json was backed up because the plan had entries to apply.
    assertions::assert_backup_exists(project.path(), "package.json");

    // stderr should report the translation count.
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Translated 2 `pnpm.overrides`"),
        "stderr should report translation count, got:\n{stderr}"
    );
}

/// Conflict path: `pnpm.overrides` and existing `lpm.overrides` both
/// have the same key with DIFFERENT targets. Migration must abort
/// before any disk mutation and report the offending key.
#[test]
fn migrate_pnpm_overrides_conflict_aborts_before_any_write() {
    let project = TempProject::from_fixture("migrate-pnpm-overrides-conflict");

    // Capture the pre-migration package.json bytes — they must be
    // unchanged after the failed migration.
    let pkg_before = std::fs::read_to_string(project.path().join("package.json")).unwrap();

    let output = lpm(&project)
        .args(["migrate", "--no-install", "--force"])
        .output()
        .expect("failed to run lpm migrate");

    assert!(
        !output.status.success(),
        "migration must fail on conflict, got success.\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("conflicts with existing `lpm.overrides`"),
        "stderr should describe the conflict, got:\n{stderr}"
    );
    assert!(
        stderr.contains("`lodash`"),
        "stderr should name the conflicting key, got:\n{stderr}"
    );
    assert!(
        stderr.contains("No files were modified"),
        "stderr should reassure the user no disk mutation happened, got:\n{stderr}"
    );

    // Concrete proof of the "no files modified" claim: package.json
    // bytes must be identical to the pre-migration content, lpm.lock
    // must not exist, and no .backup files should be lying around.
    let pkg_after = std::fs::read_to_string(project.path().join("package.json")).unwrap();
    assert_eq!(
        pkg_before, pkg_after,
        "package.json must be byte-identical after a conflict-aborted migration"
    );
    assert!(
        !project.path().join("lpm.lock").exists(),
        "lpm.lock must not exist — abort happened before the lockfile write"
    );
    assert!(
        !project.path().join("package.json.backup").exists(),
        "no package.json.backup — the backup chain hadn't started yet"
    );
}

/// Dry-run with translatable entries: report the count, no writes.
#[test]
fn migrate_pnpm_overrides_dry_run_reports_translation_count() {
    let project = TempProject::from_fixture("migrate-pnpm-overrides");

    let output = lpm(&project)
        .args(["migrate", "--dry-run"])
        .output()
        .expect("failed to run lpm migrate --dry-run");

    assert!(output.status.success());

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("2 `pnpm.overrides`"),
        "dry-run should report translation count, got:\n{stderr}"
    );
    assert!(stderr.contains("No files written"));

    // Concrete: lpm.overrides should NOT be present after a dry run.
    let pkg: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(project.path().join("package.json")).unwrap(),
    )
    .unwrap();
    assert!(
        pkg["lpm"]["overrides"].is_null(),
        "dry-run must not modify package.json"
    );
}

// ─── Phase 64 #35: pnpm.patchedDependencies translation ──────────

/// Clean translation: `pnpm.patchedDependencies` populated, source
/// patch file present at the user's path, no existing
/// `lpm.patchedDependencies`. Migrate must:
///   1. Bind integrity from the migrated lockfile
///   2. Copy the source patch file to LPM's canonical path (or no-op
///      for self-copy)
///   3. Write `lpm.patchedDependencies[k] = { path, originalIntegrity }`
///   4. Back up package.json (since the plan has entries to apply)
#[test]
fn migrate_pnpm_translates_patches_to_lpm_section() {
    let project = TempProject::from_fixture("migrate-pnpm-patches");

    let output = lpm(&project)
        .args(["migrate", "--no-install", "--force"])
        .output()
        .expect("failed to run lpm migrate");

    assert!(
        output.status.success(),
        "lpm migrate failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    // Verify lpm.patchedDependencies got the entry with both `path`
    // and `originalIntegrity` populated.
    let pkg_json = std::fs::read_to_string(project.path().join("package.json")).unwrap();
    let pkg: serde_json::Value = serde_json::from_str(&pkg_json).unwrap();
    let entry = &pkg["lpm"]["patchedDependencies"]["ms@2.1.3"];
    assert!(
        entry.is_object(),
        "lpm.patchedDependencies[ms@2.1.3] must be an object"
    );
    assert_eq!(
        entry["path"].as_str(),
        Some("patches/ms@2.1.3.patch"),
        "path should point at LPM's canonical destination"
    );
    let integrity = entry["originalIntegrity"]
        .as_str()
        .expect("originalIntegrity must be present");
    assert!(
        integrity.starts_with("sha512-"),
        "originalIntegrity should be the SRI from the migrated lockfile, got: {integrity}"
    );

    // pnpm.patchedDependencies stays in place (transition safety).
    let pnpm_block = &pkg["pnpm"]["patchedDependencies"];
    assert!(pnpm_block.is_object());
    assert!(pnpm_block.get("ms@2.1.3").is_some());

    // Source path == canonical LPM dest in this fixture, so it's a
    // self-copy: dest patch file must exist with the original content.
    let dest_content = std::fs::read_to_string(project.path().join("patches/ms@2.1.3.patch"))
        .expect("patch file must still exist after self-copy translation");
    assert!(
        dest_content.contains("/* patched */"),
        "patch file content should be intact"
    );

    // package.json was backed up because the plan had entries.
    assertions::assert_backup_exists(project.path(), "package.json");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Translated 1 `pnpm.patchedDependencies`"),
        "stderr should report translation count, got:\n{stderr}"
    );
}

/// Conflict path: `pnpm.patchedDependencies` and existing
/// `lpm.patchedDependencies` agree on key but disagree on `path`.
/// Migration must abort BEFORE any disk mutation.
#[test]
fn migrate_pnpm_patches_conflict_aborts_before_any_write() {
    let project = TempProject::from_fixture("migrate-pnpm-patches-conflict");

    let pkg_before = std::fs::read_to_string(project.path().join("package.json")).unwrap();

    let output = lpm(&project)
        .args(["migrate", "--no-install", "--force"])
        .output()
        .expect("failed to run lpm migrate");

    assert!(
        !output.status.success(),
        "migration must fail on conflict.\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("conflicts with existing `lpm.patchedDependencies`"),
        "stderr should describe the conflict, got:\n{stderr}"
    );
    assert!(
        stderr.contains("`ms@2.1.3`"),
        "stderr should name the conflicting key, got:\n{stderr}"
    );
    assert!(
        stderr.contains("No files were modified"),
        "stderr should reassure no disk mutation, got:\n{stderr}"
    );

    let pkg_after = std::fs::read_to_string(project.path().join("package.json")).unwrap();
    assert_eq!(
        pkg_before, pkg_after,
        "package.json must be byte-identical after a conflict-aborted migration"
    );
    assert!(
        !project.path().join("lpm.lock").exists(),
        "lpm.lock must not exist — abort happened before the lockfile write"
    );
    assert!(
        !project.path().join("package.json.backup").exists(),
        "no package.json.backup — the backup chain hadn't started yet"
    );
}

/// Non-canonical source path: pnpm value points at `vendor-patches/`,
/// migrate copies to LPM's canonical `patches/<safe_key>.patch` AND
/// rewrites the `pnpm.patchedDependencies[k]` value to the canonical
/// path. The rewrite is what makes the diff-aware install warning
/// silence post-migrate when source paths weren't already canonical.
///
/// Asserts both halves: (1) the rewrite landed in package.json,
/// (2) `lpm install` against the migrated project is silent.
#[test]
fn migrate_pnpm_patches_rewrites_pnpm_path_for_non_canonical_source() {
    let project = TempProject::from_fixture("migrate-pnpm-patches-non-canonical");

    let output = lpm(&project)
        .args(["migrate", "--no-install", "--force"])
        .output()
        .expect("failed to run lpm migrate");

    assert!(
        output.status.success(),
        "lpm migrate failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let pkg_json = std::fs::read_to_string(project.path().join("package.json")).unwrap();
    let pkg: serde_json::Value = serde_json::from_str(&pkg_json).unwrap();

    // LPM side gets the canonical destination
    assert_eq!(
        pkg["lpm"]["patchedDependencies"]["ms@2.1.3"]["path"].as_str(),
        Some("patches/ms@2.1.3.patch"),
    );

    // PNPM side ALSO gets rewritten to the canonical destination, so
    // the diff-aware install warning silences naturally. Without this
    // rewrite, pnpm.patchedDependencies["ms@2.1.3"] would still be
    // "vendor-patches/ms-custom.patch" and the install warning would
    // fire on every `lpm install`.
    assert_eq!(
        pkg["pnpm"]["patchedDependencies"]["ms@2.1.3"].as_str(),
        Some("patches/ms@2.1.3.patch"),
        "pnpm.patchedDependencies value must be rewritten to canonical path \
         so the diff-aware install warning is silent post-migrate"
    );

    // Patch file landed at the canonical path with original content.
    let dest_content =
        std::fs::read_to_string(project.path().join("patches/ms@2.1.3.patch")).unwrap();
    assert!(dest_content.contains("non-canonical"));

    // Original source file is left in place — transition safety. The
    // user can clean it up at their leisure.
    assert!(
        project
            .path()
            .join("vendor-patches/ms-custom.patch")
            .exists(),
        "original non-canonical source patch must remain in place"
    );

    // Concrete proof of the silent-post-migrate contract: a fresh
    // install against the migrated project should NOT fire the
    // patches warning, because pnpm and lpm now agree on the path.
    let install_output = lpm(&project)
        .args(["install"])
        .output()
        .expect("failed to run lpm install after migrate");
    let install_stderr = String::from_utf8_lossy(&install_output.stderr);
    assert!(
        !install_stderr.contains("`pnpm.patchedDependencies` entries that LPM doesn't honor"),
        "post-migrate install must be silent for non-canonical source path \
         that was successfully rewritten, but warning fired:\n{install_stderr}"
    );
}

/// Path-violation case: pnpm.patchedDependencies points at a directory.
/// Migrate must abort before any write.
#[test]
fn migrate_pnpm_patches_directory_path_aborts() {
    let project = TempProject::from_fixture("migrate-pnpm-patches");

    // Replace the package.json with one whose patch path resolves to
    // a directory (the patches dir itself).
    std::fs::write(
        project.path().join("package.json"),
        r#"{
            "name": "directory-path-test",
            "dependencies": { "ms": "^2.1.3", "depd": "^2.0.0" },
            "pnpm": {
                "patchedDependencies": {
                    "ms@2.1.3": "patches"
                }
            }
        }"#,
    )
    .unwrap();

    let output = lpm(&project)
        .args(["migrate", "--no-install", "--force"])
        .output()
        .expect("failed to run lpm migrate");

    assert!(!output.status.success());

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("path validation failures") || stderr.contains("directory"),
        "stderr should describe the path violation, got:\n{stderr}"
    );
    assert!(stderr.contains("No files were modified"));
    assert!(!project.path().join("lpm.lock").exists());
}

// ─── bun Migration ───────────────────────────────────────────────

#[test]
fn migrate_bun_creates_lockfile() {
    let project = TempProject::from_fixture("migrate-bun");

    let output = lpm(&project)
        .args(["migrate", "--no-install", "--force"])
        .output()
        .expect("failed to run lpm migrate");

    assert!(
        output.status.success(),
        "lpm migrate (bun) failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    assertions::assert_both_lockfiles_exist(project.path());
}

// ─── Dry Run ─────────────────────────────────────────────────────

#[test]
fn migrate_dry_run_does_not_write_lockfile() {
    let project = TempProject::from_fixture("migrate-npm");

    lpm(&project)
        .args(["migrate", "--dry-run"])
        .assert()
        .success();

    // Dry run should NOT create any lockfile
    assert!(
        !project.file_exists("lpm.lock"),
        "lpm.lock should not exist after --dry-run"
    );
    assert!(
        !project.file_exists("lpm.lockb"),
        "lpm.lockb should not exist after --dry-run"
    );
}

// ─── Rollback ────────────────────────────────────────────────────

#[test]
fn migrate_rollback_restores_original() {
    let project = TempProject::from_fixture("migrate-npm");

    // First, migrate (creates lockfile + backup)
    lpm(&project)
        .args(["migrate", "--no-install", "--force"])
        .assert()
        .success();

    assertions::assert_both_lockfiles_exist(project.path());
    assertions::assert_backup_exists(project.path(), "package-lock.json");

    // Now rollback
    lpm(&project)
        .args(["migrate", "--rollback"])
        .assert()
        .success();

    // After rollback, the lpm lockfiles should be gone and original restored
    assert!(
        !project.file_exists("lpm.lock"),
        "lpm.lock should be removed after rollback"
    );
}

// ─── Error: No package.json ──────────────────────────────────────

#[test]
fn migrate_without_package_json_fails() {
    let dir = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();

    let mut cmd = assert_cmd::Command::cargo_bin("lpm-rs").unwrap();
    cmd.current_dir(dir.path());
    cmd.env("HOME", home.path());
    cmd.env("NO_COLOR", "1");
    cmd.env("LPM_NO_UPDATE_CHECK", "1");
    cmd.env_remove("LPM_TOKEN");

    let output = cmd
        .args(["migrate"])
        .output()
        .expect("failed to run lpm migrate");

    assert!(!output.status.success());

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("package.json"),
        "expected error about missing package.json, got:\n{stderr}"
    );
}

// ─── Error: Existing lockfile without --force ────────────────────

#[test]
fn migrate_refuses_overwrite_without_force() {
    let project = TempProject::from_fixture("migrate-npm");

    // Create an existing lpm.lock
    project.write_file("lpm.lock", "# existing lockfile");

    let output = lpm(&project)
        .args(["migrate", "--no-install"])
        .output()
        .expect("failed to run lpm migrate");

    assert!(
        !output.status.success(),
        "should fail when lpm.lock exists without --force"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("--force") || stderr.contains("already exists"),
        "expected error about existing lockfile, got:\n{stderr}"
    );
}

// ─── Lockfile Content Validation ─────────────────────────────────

#[test]
fn migrate_npm_lockfile_contains_packages() {
    let project = TempProject::from_fixture("migrate-npm");

    lpm(&project)
        .args(["migrate", "--no-install", "--force"])
        .assert()
        .success();

    let lockfile_content = project.read_file("lpm.lock");

    // The migrate-npm fixture has real packages — verify they're in the lockfile
    assert!(
        !lockfile_content.is_empty(),
        "lpm.lock should not be empty after migration"
    );

    // TOML lockfile should have [[packages]] entries
    assert!(
        lockfile_content.contains("[[packages]]"),
        "lpm.lock should contain package entries, got:\n{}",
        &lockfile_content[..lockfile_content.len().min(500)]
    );
}
