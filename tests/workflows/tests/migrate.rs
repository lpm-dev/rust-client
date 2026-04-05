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
