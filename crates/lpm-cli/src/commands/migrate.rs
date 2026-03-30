//! `lpm migrate` — Migrate from npm/yarn/pnpm/bun to LPM.
//!
//! Full migration flow:
//! 1. Pre-flight checks (package.json exists, no existing lpm.lock unless --force)
//! 2. Detect source package manager
//! 3. Parse foreign lockfile
//! 4. Convert to LPM lockfile format
//! 5. Write lpm.lock (with backup)
//! 6. Optionally configure .npmrc
//! 7. Optionally generate CI template
//! 8. Print summary

use lpm_common::LpmError;
use lpm_lockfile::LOCKFILE_NAME;
use lpm_migrate::backup::{self, MigrationBackup};
use owo_colors::OwoColorize;
use std::path::Path;

pub async fn run(
    cwd: &Path,
    skip_verify: bool,
    no_npmrc: bool,
    no_ci: bool,
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
            "lpm.lock already exists. Use --force to overwrite, or --dry-run to preview.".to_string(),
        ));
    }

    // Calculate total steps dynamically:
    // 1 = detect, 2 = write lockfile, +1 if npmrc, +1 if verify
    let total_steps = 2 + u32::from(!no_npmrc) + u32::from(!skip_verify);

    // Step 1: Detect, parse, convert
    if !json {
        eprint!("  {} Detecting package manager...", step_num(1, total_steps));
    }

    let result = lpm_migrate::migrate(cwd)?;

    if !json {
        eprintln!(
            " {} ({} v{})",
            "done".green(),
            result.source.kind,
            result.source.version
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
            eprintln!("    {} {} ({})", "-".dimmed(), skip.name, skip.reason.dimmed());
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

    // Step 5: Write lockfile (with backup)
    if !json {
        eprint!("  {} Writing lpm.lock...", step_num(2, total_steps));
    }

    let mut migration_backup = MigrationBackup::new();
    migration_backup.backup_file(&lockfile_path)?;
    migration_backup.write_manifest(cwd)?;

    // Write the lockfile — on failure, rollback
    if let Err(e) = result.lockfile.write_all(&lockfile_path) {
        eprintln!("  {} Migration failed: {e}", "error".red().bold());
        if let Err(rollback_err) = migration_backup.rollback() {
            eprintln!(
                "  {} Rollback also failed: {rollback_err}",
                "error".red().bold()
            );
            eprintln!("  {} Manual cleanup may be needed. Check .backup files.", "warn".yellow().bold());
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

    // Step 6: Configure .npmrc (optional)
    if !no_npmrc {
        let npmrc_path = cwd.join(".npmrc");
        let step = step_num(3, total_steps);

        if npmrc_path.exists() {
            let content = std::fs::read_to_string(&npmrc_path).map_err(|e| {
                LpmError::Script(format!("failed to read .npmrc: {e}"))
            })?;

            if content.contains("@lpm.dev:registry") {
                if !json {
                    eprintln!(
                        "  {} .npmrc already has @lpm.dev:registry scope",
                        "info".blue().bold()
                    );
                }
            } else {
                if !json {
                    eprint!("  {} Updating .npmrc...", step);
                }

                migration_backup.backup_file(&npmrc_path)?;
                migration_backup.write_manifest(cwd)?;

                let mut new_content = content;
                if !new_content.ends_with('\n') {
                    new_content.push('\n');
                }
                new_content.push_str("@lpm.dev:registry=https://lpm.dev/api/packages/\n");

                if let Err(e) = std::fs::write(&npmrc_path, &new_content) {
                    eprintln!("  {} Failed to update .npmrc: {e}", "error".red().bold());
                    if let Err(re) = migration_backup.rollback() {
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
            }
        } else {
            if !json {
                eprint!("  {} Configuring .npmrc...", step);
            }

            migration_backup.backup_file(&npmrc_path)?;

            let npmrc_content = "@lpm.dev:registry=https://lpm.dev/api/packages/\n";
            if let Err(e) = std::fs::write(&npmrc_path, npmrc_content) {
                eprintln!("  {} Failed to write .npmrc: {e}", "error".red().bold());
                if let Err(re) = migration_backup.rollback() {
                    eprintln!("  {} Rollback also failed: {re}", "error".red().bold());
                }
                return Err(LpmError::Script(format!("failed to write .npmrc: {e}")));
            }

            if !json {
                eprintln!(" {}", "done".green());
            }
        }
    }

    // Verify step (optional)
    if !skip_verify {
        let verify_step = if no_npmrc { 3 } else { 4 };
        if !json {
            eprint!(
                "  {} Verifying migration...",
                step_num(verify_step, total_steps)
            );
        }

        // Basic verification: ensure lpm.lock was written and is non-empty
        let lock_meta = std::fs::metadata(&lockfile_path).map_err(|e| {
            LpmError::Script(format!("verification failed — lpm.lock missing: {e}"))
        })?;
        if lock_meta.len() == 0 {
            return Err(LpmError::Script(
                "verification failed — lpm.lock is empty".to_string(),
            ));
        }

        if !json {
            eprintln!(" {}", "done".green());
        }
    }

    // Generate CI template hint (optional, informational only)
    if !no_ci {
        if let Some(platform) = lpm_migrate::ci::detect_ci_platform(cwd) {
            if !json {
                eprintln!(
                    "  {} Detected {} CI — template available via `lpm migrate --ci`",
                    "info".blue().bold(),
                    platform,
                );
            }
        }
    }

    // Clean up backups on success (also removes manifest)
    migration_backup.cleanup_backups()?;

    // Summary
    if json {
        let output = serde_json::json!({
            "success": true,
            "source": format!("{}", result.source.kind),
            "source_version": result.source.version,
            "package_count": result.package_count,
            "integrity_count": result.integrity_count,
            "skipped_count": result.skipped.len(),
            "warning_count": result.warnings.len(),
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
        eprintln!("    {} Run {} to install packages", "1.".dimmed(), "lpm install".bold());
        eprintln!("    {} Verify your project builds and tests pass", "2.".dimmed());
        eprintln!("    {} Commit lpm.lock to version control", "3.".dimmed());
        eprintln!();
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
        eprintln!("  {} {} files restored.", "done".green().bold(), restored.len());
        eprintln!();
    }

    Ok(())
}

fn step_num(n: u32, total: u32) -> String {
    format!("[{}/{}]", n, total)
}
