//! Workflow tests for `lpm migrate`.
//!
//! Tests the full migration path from npm/yarn/pnpm/bun lockfiles to LPM,
//! including backup creation, rollback, and dry-run.

mod support;

use support::assertions;
use support::{TempProject, lpm};

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

#[test]
fn migrate_human_output_uses_slim_contract() {
    let project = TempProject::from_fixture("migrate-pnpm");

    let output = lpm(&project)
        .args([
            "--color=always",
            "migrate",
            "--no-install",
            "--force",
            "--skip-verify",
            "--no-npmrc",
        ])
        .output()
        .expect("failed to run lpm migrate");

    assert!(
        output.status.success(),
        "lpm migrate failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let stderr_raw = String::from_utf8_lossy(&output.stderr);
    let stderr = strip_ansi(&stderr_raw);

    for expected in [
        "› Detecting current package manager",
        "source:",
        "pnpm-lock.yaml",
        "backups:",
        "✓ Converted lockfile",
        "wrote:",
        "lpm.lock",
        "lpm.lockb",
        "✓ Done · migration completed successfully",
    ] {
        assert!(
            stderr.contains(expected),
            "migrate slim output missing {expected:?}, got:\n{stderr}"
        );
    }

    assert!(
        stderr_raw.contains("\u{1b}[2msource:")
            && stderr_raw.contains("\u{1b}[2mbackups:")
            && stderr_raw.contains("\u{1b}[33mpnpm-lock.yaml"),
        "migrate slim output must dim labels and color the source lockfile, got:\n{stderr_raw:?}"
    );
    assert!(
        !stderr.contains("Migrating to LPM")
            && !stderr.contains("[1/")
            && !stderr.contains("Next steps:"),
        "migrate output must drop the old banner, step counters, and next-steps footer, got:\n{stderr}"
    );
}

// ─── pnpm.overrides translation ──────────────────

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
    let stderr_clean = strip_ansi(&stderr);
    assert!(
        stderr_clean.contains("✗ Cannot translate `pnpm.overrides` to `lpm.overrides`"),
        "stderr should render the conflict headline as a slim failure line, got:\n{stderr_clean}"
    );
    assert!(
        !stderr_clean.contains("  error ") && !stderr_clean.contains("error:"),
        "stderr must not use the legacy raw error label, got:\n{stderr_clean}"
    );
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

// ─── pnpm.patchedDependencies translation ──────────

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

    let lockfile = lpm_lockfile::Lockfile::read_from_file(&project.path().join("lpm.lock"))
        .expect("migrated lockfile must remain readable");
    assert_eq!(
        lockfile.metadata.lockfile_version,
        lpm_lockfile::LOCKFILE_VERSION_WITH_STRUCTURED_PEERS,
        "--no-install migration cannot claim exact package-instance identity"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Translated 1 `pnpm.patchedDependencies`"),
        "stderr should report translation count, got:\n{stderr}"
    );
    assert!(
        !project.file_exists("lpm.lockb"),
        "patch metadata makes the staging lockfile TOML-only"
    );
    assert!(
        !stderr.contains("wrote:   lpm.lockb"),
        "migrate must not report a binary artifact removed by the final TOML-only write: {stderr}"
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
    let stderr_clean = strip_ansi(&stderr);
    assert!(
        stderr_clean
            .contains("✗ Cannot translate `pnpm.patchedDependencies` to `lpm.patchedDependencies`"),
        "stderr should render the conflict headline as a slim failure line, got:\n{stderr_clean}"
    );
    assert!(
        !stderr_clean.contains("  error ") && !stderr_clean.contains("error:"),
        "stderr must not use the legacy raw error label, got:\n{stderr_clean}"
    );
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

    // The migrate-npm fixture intentionally has no .gitattributes —
    // verifying upfront that a freshly-created file gets cleaned up
    // on rollback (otherwise this test reduces to "we restored from a
    // backup", which is the easy case).
    assert!(
        !project.file_exists(".gitattributes"),
        "fixture must NOT pre-ship a .gitattributes for this test \
         to exercise the freshly-created path",
    );

    // First, migrate (creates lockfile + backup)
    lpm(&project)
        .args(["migrate", "--no-install", "--force"])
        .assert()
        .success();

    assertions::assert_both_lockfiles_exist(project.path());
    assertions::assert_backup_exists(project.path(), "package-lock.json");
    assert!(
        project.file_exists(".gitattributes"),
        "migrate must create .gitattributes (records lpm.lockb as binary)"
    );

    // Now rollback — read the --json envelope so the contract is pinned
    // alongside the file-system effect assertions below.
    let rollback_out = lpm(&project)
        .args(["--json", "migrate", "--rollback"])
        .output()
        .expect("failed to run lpm migrate --rollback --json");
    assert!(
        rollback_out.status.success(),
        "migrate --rollback failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&rollback_out.stdout),
        String::from_utf8_lossy(&rollback_out.stderr),
    );
    let rollback_envelope: serde_json::Value = serde_json::from_slice(&rollback_out.stdout)
        .unwrap_or_else(|e| {
            panic!(
                "migrate --rollback --json stdout must be valid JSON: {e}\n---\n{}",
                String::from_utf8_lossy(&rollback_out.stdout)
            )
        });
    assert_eq!(rollback_envelope["success"], serde_json::json!(true));
    assert_eq!(rollback_envelope["rollback"], serde_json::json!(true));
    assert!(
        rollback_envelope["restored_files"].is_array(),
        "envelope must carry a restored_files array"
    );

    // After rollback, every file the migration created must be gone —
    // `lpm.lock` and `lpm.lockb` (the lockfile pair), plus
    // `.gitattributes` which `ensure_gitattributes` may create when
    // absent. The backup layer's v2 `created` array tracks all three;
    // any of them surviving means the rollback contract is broken.
    assert!(
        !project.file_exists("lpm.lock"),
        "lpm.lock should be removed after rollback"
    );
    assert!(
        !project.file_exists("lpm.lockb"),
        "lpm.lockb should be removed after rollback (it's derived from lpm.lock)"
    );
    assert!(
        !project.file_exists(".gitattributes"),
        ".gitattributes should be removed after rollback when migrate \
         created it (didn't exist pre-migration)"
    );
}

/// `-y` is reserved (non-interactive flag) and intentionally does NOT
/// imply `--force`. Without an explicit `--force`, migrate must refuse
/// to overwrite an existing lpm.lock even when `-y` is set.
#[test]
fn migrate_yes_alone_does_not_overwrite_existing_lockfile() {
    let project = TempProject::from_fixture("migrate-npm");

    // Plant an lpm.lock first (simulates a project mid-migration or
    // a re-run scenario).
    std::fs::write(
        project.path().join("lpm.lock"),
        "# user's hand-tuned lockfile that we MUST NOT clobber\n",
    )
    .unwrap();
    let pre_bytes = std::fs::read(project.path().join("lpm.lock")).unwrap();

    // -y should NOT clobber the existing lpm.lock — that's the job of
    // --force, and the public contract is now that the two are decoupled.
    let output = lpm(&project)
        .args(["migrate", "--no-install", "-y"])
        .output()
        .expect("failed to run lpm migrate -y");

    assert!(
        !output.status.success(),
        "lpm migrate -y must refuse to overwrite without --force; \
         stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let post_bytes = std::fs::read(project.path().join("lpm.lock")).unwrap();
    assert_eq!(
        pre_bytes, post_bytes,
        "lpm.lock must be byte-identical to its pre-`-y` state"
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
    cmd.env("LPM_HOME", home.path().join(".lpm"));
    cmd.env("NO_COLOR", "1");
    cmd.env("LPM_NO_UPDATE_CHECK", "1");
    cmd.env("LPM_DISABLE_TELEMETRY", "1");
    cmd.env("LPM_FORCE_FILE_AUTH", "1");
    cmd.env("LPM_TEST_FAST_SCRYPT", "1");
    cmd.env("LPM_FORCE_FILE_VAULT", "1");
    cmd.env("LPM_DISABLE_HOST_CLI_AUTH", "1");
    cmd.env(
        "LPM_SECURITY_POLICY_PATH",
        home.path().join(".lpm/security-policy.toml"),
    );
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

// ─── --ci flag (CI workflow template generation) ──────────────────────

#[test]
fn migrate_with_ci_flag_generates_workflow_template_file() {
    let project = TempProject::from_fixture("migrate-npm");

    // Seed a `.github/workflows/` parent so the GitHub Actions template
    // is the deterministic detected target.
    std::fs::create_dir_all(project.path().join(".github/workflows"))
        .expect("seed .github/workflows");

    let output = lpm(&project)
        .args(["--json", "migrate", "--no-install", "--force", "--ci"])
        .output()
        .expect("failed to run lpm migrate --ci");

    assert!(
        output.status.success(),
        "migrate --ci failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    // The --json envelope carries the migration summary even when the
    // --ci side effect (workflow file emission) is the user-visible
    // claim. Pin the envelope's `success` so the JSON contract is
    // testable alongside the file-system effect.
    let envelope: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap_or_else(|e| {
        panic!(
            "migrate --ci --json stdout must be valid JSON: {e}\n---\n{}",
            String::from_utf8_lossy(&output.stdout)
        )
    });
    assert_eq!(envelope["success"], serde_json::json!(true));

    // A new workflow file must exist under .github/workflows/ after --ci.
    let entries: Vec<_> = std::fs::read_dir(project.path().join(".github/workflows"))
        .expect("read .github/workflows")
        .filter_map(Result::ok)
        .collect();
    assert!(
        !entries.is_empty(),
        "migrate --ci must write at least one workflow file under .github/workflows/, got: {entries:?}",
    );
}

#[test]
fn migrate_without_ci_flag_does_not_generate_workflow_file() {
    let project = TempProject::from_fixture("migrate-npm");
    std::fs::create_dir_all(project.path().join(".github/workflows"))
        .expect("seed .github/workflows");

    lpm(&project)
        .args(["migrate", "--no-install", "--force"])
        .assert()
        .success();

    let entries: Vec<_> = std::fs::read_dir(project.path().join(".github/workflows"))
        .expect("read .github/workflows")
        .filter_map(Result::ok)
        .collect();
    assert!(
        entries.is_empty(),
        "migrate without --ci must NOT write any workflow file, got: {entries:?}",
    );
}

// ─── --no-npmrc flag ──────────────────────────────────────────────────

#[test]
fn migrate_no_npmrc_skips_npmrc_creation() {
    let project = TempProject::from_fixture("migrate-npm");

    assert!(
        !project.file_exists(".npmrc"),
        "preconditions: fixture must not start with .npmrc"
    );

    lpm(&project)
        .args(["migrate", "--no-install", "--force", "--no-npmrc"])
        .assert()
        .success();

    assert!(
        !project.file_exists(".npmrc"),
        "migrate --no-npmrc must not create .npmrc"
    );
}

#[test]
fn migrate_default_creates_npmrc_unless_no_npmrc_passed() {
    // Inverse of the --no-npmrc test: without the flag, migrate writes
    // .npmrc. Locks the default behavior so a future flip would fail
    // this test (and the --no-npmrc test) symmetrically.
    let project = TempProject::from_fixture("migrate-npm");

    lpm(&project)
        .args(["migrate", "--no-install", "--force"])
        .assert()
        .success();

    assert!(
        project.file_exists(".npmrc"),
        "migrate without --no-npmrc must write .npmrc by default"
    );
}
