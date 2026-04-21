//! `lpm migrate` — Migrate from npm/yarn/pnpm/bun to LPM.
//!
//! Full migration flow:
//! 1. Pre-flight checks (package.json exists, no existing lpm.lock unless --force)
//! 2. Detect source package manager, parse foreign lockfile, convert
//! 3. Write lpm.lock + lpm.lockb (with backup of source lockfile + .npmrc)
//! 4. Optionally configure .npmrc
//! 5. Run `lpm install` (lockfile fast path — no re-resolution)
//! 6. Optionally verify build+test scripts pass
//! 7. Optionally generate CI template
//! 8. Print summary

use lpm_common::LpmError;
use lpm_lockfile::LOCKFILE_NAME;
use lpm_migrate::backup::{self, MigrationBackup};
use lpm_registry::RegistryClient;
use owo_colors::OwoColorize;
use std::path::Path;

#[allow(clippy::too_many_arguments)]
pub async fn run(
    client: &RegistryClient,
    cwd: &Path,
    skip_verify: bool,
    no_npmrc: bool,
    no_ci: bool,
    ci: bool,
    no_install: bool,
    dry_run: bool,
    force: bool,
    rollback: bool,
    json: bool,
) -> Result<(), LpmError> {
    // --rollback mode: restore from .backup files
    if rollback {
        return run_rollback(cwd, json);
    }

    // Step 1: Pre-flight checks
    if !json {
        eprintln!(
            "\n{}  {}",
            "lpm migrate".bold(),
            "Migrating to LPM...".dimmed()
        );
        eprintln!();
    }

    // Check package.json exists
    let pkg_json_path = cwd.join("package.json");
    if !pkg_json_path.exists() {
        return Err(LpmError::Script(
            "no package.json found in the current directory".to_string(),
        ));
    }

    // Check for existing lpm.lock
    let lockfile_path = cwd.join(LOCKFILE_NAME);
    if lockfile_path.exists() && !force && !dry_run {
        return Err(LpmError::Script(
            "lpm.lock already exists. Use --force to overwrite, or --dry-run to preview."
                .to_string(),
        ));
    }

    // Calculate total steps dynamically
    let total_steps = count_steps(no_npmrc, no_install, skip_verify);

    // Step 1: Detect, parse, convert
    if !json {
        eprint!(
            "  {} Detecting package manager...",
            step_num(1, total_steps)
        );
    }

    let result = lpm_migrate::migrate(cwd)?;

    if !json {
        let workspace_info = if result.workspace_members > 0 {
            format!(", {} workspace members", result.workspace_members)
        } else {
            String::new()
        };
        eprintln!(
            " {} ({} v{}, {} packages{})",
            "done".green(),
            result.source.kind,
            result.source.version,
            result.package_count,
            workspace_info,
        );
    }

    // Print skipped packages
    if !json && !result.skipped.is_empty() {
        eprintln!();
        eprintln!(
            "  {} {} skipped:",
            "!".yellow().bold(),
            result.skipped.len()
        );
        for skip in &result.skipped {
            eprintln!(
                "    {} {} ({})",
                "-".dimmed(),
                skip.name,
                skip.reason.dimmed()
            );
        }
    }

    // Print warnings
    if !json && !result.warnings.is_empty() {
        eprintln!();
        for w in &result.warnings {
            eprintln!("  {} {}", "warn".yellow().bold(), w);
        }
    }

    // Dry-run: stop here
    if dry_run {
        if json {
            let output = serde_json::json!({
                "success": true,
                "dry_run": true,
                "source": format!("{}", result.source.kind),
                "source_version": result.source.version,
                "package_count": result.package_count,
                "integrity_count": result.integrity_count,
                "skipped_count": result.skipped.len(),
                "warning_count": result.warnings.len(),
                "workspace_members": result.workspace_members,
            });
            println!("{}", serde_json::to_string_pretty(&output)?);
        } else {
            eprintln!();
            eprintln!(
                "  {} {} packages would be migrated ({} with integrity)",
                "dry-run".cyan().bold(),
                result.package_count,
                result.integrity_count,
            );
            eprintln!("  {} No files written.", "dry-run".cyan().bold());
        }
        return Ok(());
    }

    // Step 2: Write lockfile (with backup)
    if !json {
        eprint!("  {} Writing lpm.lock...", step_num(2, total_steps));
    }

    let mut migration_backup = MigrationBackup::new();

    // Back up the source lockfile (package-lock.json, yarn.lock, etc.)
    migration_backup.backup_file(&result.source.path)?;

    // Back up existing lpm.lock if overwriting
    migration_backup.backup_file(&lockfile_path)?;

    // Back up .gitattributes if it exists (will be modified by ensure_gitattributes)
    let gitattributes_path = cwd.join(".gitattributes");
    if gitattributes_path.exists() {
        migration_backup.backup_file(&gitattributes_path)?;
    }

    migration_backup.write_manifest(cwd)?;

    // Write the lockfile — on failure, rollback
    if let Err(e) = result.lockfile.write_all(&lockfile_path) {
        eprintln!("  {} Migration failed: {e}", "error".red().bold());
        if let Err(rollback_err) = migration_backup.rollback() {
            eprintln!(
                "  {} Rollback also failed: {rollback_err}",
                "error".red().bold()
            );
            eprintln!(
                "  {} Manual cleanup may be needed. Check .backup files.",
                "warn".yellow().bold()
            );
        } else {
            eprintln!("  {} Rolled back to original state.", "info".blue().bold());
        }
        return Err(LpmError::Script(format!("failed to write lockfile: {e}")));
    }

    // Ensure .gitattributes marks lpm.lockb as binary
    if let Err(e) = lpm_lockfile::ensure_gitattributes(cwd) {
        // Non-fatal: warn but continue
        if !json {
            eprintln!(
                "  {} failed to update .gitattributes: {e}",
                "warn".yellow().bold()
            );
        }
    }

    if !json {
        eprintln!(" {}", "done".green());
    }

    // Step 3: Configure .npmrc (optional)
    let mut current_step: u32 = 3;
    if !no_npmrc {
        configure_npmrc(cwd, current_step, total_steps, json, &mut migration_backup)?;
        current_step += 1;
    }

    // Step N: Install (optional, default on)
    if !no_install {
        if !json {
            eprint!(
                "  {} Installing packages...",
                step_num(current_step, total_steps)
            );
        }

        match super::install::run_with_options(
            client, cwd, json, false, // not offline — need to download tarballs
            false, // force
            false, // allow_new
            None,  // linker_override
            true,  // no_skills — skip skill setup during migration
            true,  // no_editor_setup — skip editor setup during migration
            true,  // no_security_summary — migration already showed warnings
            false, // auto_build
            None,  // target_set: migrate is single-project
            None,  // direct_versions_out: migrate does not finalize Phase 33 placeholders
            None,  // script_policy_override: `lpm migrate` does not expose policy flags
            None,  // min_release_age_override: `lpm migrate` uses the chain
        )
        .await
        {
            Ok(()) => {
                // install prints its own output
            }
            Err(e) => {
                if !json {
                    eprintln!();
                    eprintln!("  {} Install failed: {e}", "warn".yellow().bold());
                    eprintln!(
                        "  {} The lockfile was written successfully. Run {} manually to retry.",
                        "info".blue().bold(),
                        "lpm install".bold()
                    );
                }
                // Install failure is non-fatal for migration — the lockfile is still valid.
                // The user can retry install separately.
            }
        }
        current_step += 1;
    }

    // Step N: Verify build+test (optional)
    if !skip_verify {
        run_verification(cwd, current_step, total_steps, json).await?;
        current_step += 1;
    }

    // CI template (optional)
    if !no_ci {
        if ci {
            // --ci flag: actually generate the template file
            generate_ci_template(cwd, current_step, total_steps, json, &mut migration_backup)?;
        } else if let Some(platform) = lpm_migrate::ci::detect_ci_platform(cwd)
            && !json
        {
            eprintln!(
                "\n  {} Detected {} CI — run {} to generate a workflow template",
                "info".blue().bold(),
                platform,
                "lpm migrate --ci".bold(),
            );
        }
    }

    // Write final manifest (includes all backed-up and newly created files).
    // Backups are intentionally NOT cleaned up — they remain on disk so
    // `lpm migrate --rollback` can undo the migration after success.
    migration_backup.write_manifest(cwd)?;

    // Summary
    let _ = current_step; // suppress unused warning
    if json {
        let output = serde_json::json!({
            "success": true,
            "source": format!("{}", result.source.kind),
            "source_version": result.source.version,
            "package_count": result.package_count,
            "integrity_count": result.integrity_count,
            "skipped_count": result.skipped.len(),
            "warning_count": result.warnings.len(),
            "workspace_members": result.workspace_members,
        });
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        eprintln!();
        eprintln!(
            "  {} Migrated {} packages from {} ({} with integrity hashes)",
            "done".green().bold(),
            result.package_count.to_string().bold(),
            result.source.kind.to_string().bold(),
            result.integrity_count,
        );
        if !result.skipped.is_empty() {
            eprintln!(
                "  {} {} packages skipped (file:/git:/link: deps)",
                "note".dimmed(),
                result.skipped.len(),
            );
        }
        eprintln!();
        eprintln!("  Next steps:");
        eprintln!("    {} Commit lpm.lock to version control", "1.".dimmed());
        eprintln!(
            "    {} Remove old lockfile when ready: {}",
            "2.".dimmed(),
            format!(
                "git rm {}",
                result
                    .source
                    .path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("lockfile")
            )
            .dimmed(),
        );
        eprintln!();
    }

    Ok(())
}

/// Count the total number of steps for progress display.
fn count_steps(no_npmrc: bool, no_install: bool, skip_verify: bool) -> u32 {
    let mut steps: u32 = 2; // detect + write lockfile
    if !no_npmrc {
        steps += 1;
    }
    if !no_install {
        steps += 1;
    }
    if !skip_verify {
        steps += 1;
    }
    steps
}

/// Configure .npmrc with the LPM registry scope.
fn configure_npmrc(
    cwd: &Path,
    step: u32,
    total: u32,
    json: bool,
    backup: &mut MigrationBackup,
) -> Result<(), LpmError> {
    let npmrc_path = cwd.join(".npmrc");

    if npmrc_path.exists() {
        let content = std::fs::read_to_string(&npmrc_path)
            .map_err(|e| LpmError::Script(format!("failed to read .npmrc: {e}")))?;

        if content.contains("@lpm.dev:registry") {
            if !json {
                eprintln!(
                    "  {} .npmrc already has @lpm.dev:registry scope",
                    "info".blue().bold()
                );
            }
            return Ok(());
        }

        if !json {
            eprint!("  {} Updating .npmrc...", step_num(step, total));
        }

        backup.backup_file(&npmrc_path)?;
        backup.write_manifest(cwd)?;

        let mut new_content = content;
        if !new_content.ends_with('\n') {
            new_content.push('\n');
        }
        new_content.push_str("@lpm.dev:registry=https://lpm.dev/api/registry/\n");

        if let Err(e) = std::fs::write(&npmrc_path, &new_content) {
            eprintln!("  {} Failed to update .npmrc: {e}", "error".red().bold());
            if let Err(re) = backup.rollback() {
                eprintln!("  {} Rollback also failed: {re}", "error".red().bold());
            }
            return Err(LpmError::Script(format!("failed to write .npmrc: {e}")));
        }

        if !json {
            eprintln!(
                " {} (added @lpm.dev:registry scope, original backed up)",
                "done".green()
            );
        }
    } else {
        if !json {
            eprint!("  {} Configuring .npmrc...", step_num(step, total));
        }

        backup.backup_file(&npmrc_path)?;

        let npmrc_content = "@lpm.dev:registry=https://lpm.dev/api/registry/\n";
        if let Err(e) = std::fs::write(&npmrc_path, npmrc_content) {
            eprintln!("  {} Failed to write .npmrc: {e}", "error".red().bold());
            if let Err(re) = backup.rollback() {
                eprintln!("  {} Rollback also failed: {re}", "error".red().bold());
            }
            return Err(LpmError::Script(format!("failed to write .npmrc: {e}")));
        }

        if !json {
            eprintln!(" {}", "done".green());
        }
    }

    Ok(())
}

/// Run build and test verification scripts from package.json.
///
/// Returns `Err` if any script fails — the migration lockfile is valid but the
/// project does not build/test cleanly, so the user should investigate before
/// committing. Use `--skip-verify` to bypass.
async fn run_verification(cwd: &Path, step: u32, total: u32, json: bool) -> Result<(), LpmError> {
    if !json {
        eprint!("  {} Verifying migration...", step_num(step, total));
    }

    // Read package.json to find available scripts
    let pkg_json_path = cwd.join("package.json");
    let scripts = match std::fs::read_to_string(&pkg_json_path)
        .ok()
        .and_then(|c| serde_json::from_str::<serde_json::Value>(&c).ok())
    {
        Some(json_val) => json_val
            .get("scripts")
            .and_then(|s| s.as_object())
            .map(|s| s.keys().cloned().collect::<Vec<_>>())
            .unwrap_or_default(),
        None => Vec::new(),
    };

    let has_build = scripts.iter().any(|s| s == "build");
    let has_test = scripts.iter().any(|s| s == "test");

    if !has_build && !has_test {
        if !json {
            eprintln!(
                " {} (no build/test scripts in package.json)",
                "skipped".dimmed()
            );
        }
        return Ok(());
    }

    let mut failures: Vec<String> = Vec::new();

    // Run build if it exists
    if has_build {
        match super::run::run(cwd, "build", &[], None, false).await {
            Ok(()) => {
                if !json {
                    eprint!(" build {}", "ok".green());
                }
            }
            Err(e) => {
                failures.push(format!("build: {e}"));
                if !json {
                    eprint!(" build {}", "failed".red());
                }
            }
        }
    }

    // Run test if it exists
    if has_test {
        match super::run::run(cwd, "test", &[], None, false).await {
            Ok(()) => {
                if !json {
                    eprint!(" test {}", "ok".green());
                }
            }
            Err(e) => {
                failures.push(format!("test: {e}"));
                if !json {
                    eprint!(" test {}", "failed".red());
                }
            }
        }
    }

    if failures.is_empty() {
        if !json {
            eprintln!(" {}", "done".green());
        }
        Ok(())
    } else {
        if !json {
            eprintln!();
            eprintln!();
            eprintln!(
                "  {} Verification failed. The lockfile is valid but your project has issues:",
                "error".red().bold()
            );
            for f in &failures {
                eprintln!("    {} {}", "-".dimmed(), f);
            }
            eprintln!();
            eprintln!("  Options:");
            eprintln!(
                "    {} Fix the issues and run {} again",
                "1.".dimmed(),
                "lpm migrate --force".bold()
            );
            eprintln!(
                "    {} Skip verification: {}",
                "2.".dimmed(),
                "lpm migrate --skip-verify".bold()
            );
            eprintln!(
                "    {} Undo the migration: {}",
                "3.".dimmed(),
                "lpm migrate --rollback".bold()
            );
            eprintln!();
        }
        Err(LpmError::Script(format!(
            "verification failed: {}",
            failures.join("; ")
        )))
    }
}

/// Generate a CI workflow template for the detected platform.
fn generate_ci_template(
    cwd: &Path,
    _step: u32,
    _total: u32,
    json: bool,
    backup: &mut MigrationBackup,
) -> Result<(), LpmError> {
    let platform = match lpm_migrate::ci::detect_ci_platform(cwd) {
        Some(p) => p,
        None => {
            if !json {
                eprintln!(
                    "  {} No CI platform detected (no .github/workflows, .gitlab-ci.yml, etc.)",
                    "info".blue().bold()
                );
            }
            return Ok(());
        }
    };

    let template = lpm_migrate::ci::generate_template(platform);
    let output_path = lpm_migrate::ci::template_output_path(cwd, platform);

    // Back up existing file if present
    if output_path.exists() {
        backup.backup_file(&output_path)?;
    }

    std::fs::write(&output_path, &template).map_err(|e| {
        LpmError::Script(format!(
            "failed to write CI template {}: {e}",
            output_path.display()
        ))
    })?;

    if !json {
        eprintln!(
            "  {} Generated {} CI template: {}",
            "done".green().bold(),
            platform,
            output_path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("ci template"),
        );
    }

    Ok(())
}

fn run_rollback(cwd: &Path, json: bool) -> Result<(), LpmError> {
    if !json {
        eprintln!(
            "\n{}  {}",
            "lpm migrate --rollback".bold(),
            "Restoring from backup files...".dimmed()
        );
    }

    let restored = backup::rollback_from_backups(cwd)?;

    // Also remove lpm.lockb if lpm.lock was restored (the binary lockfile is derived)
    let lockb_path = cwd.join("lpm.lockb");
    if lockb_path.exists() && restored.iter().any(|f| f == "lpm.lock") {
        let _ = std::fs::remove_file(&lockb_path);
    }

    if json {
        let output = serde_json::json!({
            "success": true,
            "rollback": true,
            "restored_files": restored,
        });
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else if restored.is_empty() {
        eprintln!("  No backup files found. Nothing to restore.");
    } else {
        eprintln!();
        for file in &restored {
            eprintln!("  {} Restored {}", "ok".green(), file);
        }
        eprintln!();
        eprintln!(
            "  {} {} files restored.",
            "done".green().bold(),
            restored.len()
        );
        eprintln!();
    }

    Ok(())
}

fn step_num(n: u32, total: u32) -> String {
    format!("[{}/{}]", n, total)
}
