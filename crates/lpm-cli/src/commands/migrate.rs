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
use lpm_common::color::Painted;
use lpm_lockfile::LOCKFILE_NAME;
use lpm_migrate::backup::{self, MigrationBackup};
use lpm_registry::RegistryClient;
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

    // #34 / #35 — plan the `pnpm.overrides` and
    // `pnpm.patchedDependencies` translations BEFORE any file mutation
    // so parse errors / shape errors / containment violations / merge
    // conflicts / missing-integrity bindings surface up-front. Read
    // package.json once here; both plans + the install-time warning
    // logic want it.
    let pkg_json_path = cwd.join("package.json");
    let pkg = lpm_workspace::read_package_json(&pkg_json_path)
        .map_err(|e| LpmError::Script(format!("failed to read package.json: {e}")))?;
    let overrides_plan = super::migrate_overrides::build_plan(&pkg)?;
    let patches_plan = super::migrate_patches::build_plan(&pkg, cwd, &result.lockfile)?;
    let peer_rules_plan = super::migrate_peer_rules::build_plan(&pkg)?;

    if overrides_plan.has_blocking_errors() {
        render_overrides_plan_errors(&overrides_plan, json);
        return Err(LpmError::Script(
            "cannot translate `pnpm.overrides` to `lpm.overrides` — see errors above. \
             No files were modified."
                .to_string(),
        ));
    }

    if patches_plan.has_blocking_errors() {
        render_patches_plan_errors(&patches_plan, json);
        return Err(LpmError::Script(
            "cannot translate `pnpm.patchedDependencies` to `lpm.patchedDependencies` — \
             see errors above. No files were modified."
                .to_string(),
        ));
    }

    if peer_rules_plan.has_blocking_errors() {
        render_peer_rules_plan_errors(&peer_rules_plan, json);
        return Err(LpmError::Script(
            "cannot translate `pnpm.peerDependencyRules` to `lpm.peerDependencyRules` — \
             see errors above. No files were modified."
                .to_string(),
        ));
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
                "pnpm_overrides_to_translate": overrides_plan.to_apply.len(),
                "pnpm_patches_to_translate": patches_plan.to_apply.len(),
                "pnpm_peer_rules_to_translate": peer_rules_plan.ignore_missing_to_apply.len()
                    + peer_rules_plan.allow_any_to_apply.len()
                    + peer_rules_plan.allowed_versions_to_apply.len(),
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
            if overrides_plan.has_entries() {
                eprintln!(
                    "  {} {} `pnpm.overrides` entr{} would be translated to `lpm.overrides`",
                    "dry-run".cyan().bold(),
                    overrides_plan.to_apply.len(),
                    if overrides_plan.to_apply.len() == 1 {
                        "y"
                    } else {
                        "ies"
                    },
                );
            }
            if patches_plan.has_entries() {
                eprintln!(
                    "  {} {} `pnpm.patchedDependencies` entr{} would be translated to \
                     `lpm.patchedDependencies`",
                    "dry-run".cyan().bold(),
                    patches_plan.to_apply.len(),
                    if patches_plan.to_apply.len() == 1 {
                        "y"
                    } else {
                        "ies"
                    },
                );
            }
            if peer_rules_plan.has_entries() {
                let n = peer_rules_plan.ignore_missing_to_apply.len()
                    + peer_rules_plan.allow_any_to_apply.len()
                    + peer_rules_plan.allowed_versions_to_apply.len();
                eprintln!(
                    "  {} {} `pnpm.peerDependencyRules` entr{} would be translated to \
                     `lpm.peerDependencyRules`",
                    "dry-run".cyan().bold(),
                    n,
                    if n == 1 { "y" } else { "ies" },
                );
            }
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

    // Back up lpm.lockb too — `Lockfile::write_all` writes both files
    // atomically (the binary file is derived from the TOML content), so
    // both need to round-trip through the backup chain. Without this
    // line, a fresh migration's freshly-created lpm.lockb would survive
    // `lpm migrate --rollback` even after lpm.lock was removed from the
    // `created` list, leaving the project with a stale binary lockfile.
    let lockb_path = cwd.join("lpm.lockb");
    migration_backup.backup_file(&lockb_path)?;

    // Back up .gitattributes unconditionally — `ensure_gitattributes`
    // creates the file when missing AND modifies it when present, so
    // the backup chain needs to track it on both paths. With the
    // existence guard the v2 manifest's `created` array would miss the
    // newly-created file, leaving a stray `.gitattributes` on disk
    // after `lpm migrate --rollback`.
    let gitattributes_path = cwd.join(".gitattributes");
    migration_backup.backup_file(&gitattributes_path)?;

    // #34 / #35 — back up package.json IFF EITHER plan is
    // about to write to it. Skipping when there's nothing to apply
    // keeps the backup surface narrow and avoids littering the
    // project with stray `.backup` files for migrations that didn't
    // touch the manifest.
    if overrides_plan.has_entries() || patches_plan.has_entries() {
        migration_backup.backup_file(&pkg_json_path)?;
    }

    // #35 — for each non-self-copy patch entry whose
    // destination ALREADY exists pre-migration (rare: user mid-manual-
    // port), back up the destination so a rollback restores its prior
    // content. Self-copy entries don't write to the destination, so
    // they don't widen the backup surface.
    for translation in &patches_plan.to_apply {
        if !translation.is_self_copy && translation.dest_pre_exists {
            migration_backup.backup_file(&translation.dest_absolute)?;
        }
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

    // #34 — apply the validated `pnpm.overrides` translation
    // to `package.json > lpm.overrides`. The plan was already checked
    // for blocking errors before any disk mutation; reaching here means
    // every entry in `to_apply` is parsable and non-conflicting.
    //
    // On failure: the backup chain (extended above when the plan had
    // entries) carries package.json, so `migration_backup.rollback()`
    // restores it cleanly along with the lockfile.
    if overrides_plan.has_entries() {
        if let Err(e) = apply_overrides_to_package_json(&pkg_json_path, &overrides_plan.to_apply) {
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
            return Err(e);
        }
        if !json {
            let n = overrides_plan.to_apply.len();
            eprintln!(
                "  {} Translated {n} `pnpm.overrides` entr{} → `lpm.overrides`",
                "ok".green().bold(),
                if n == 1 { "y" } else { "ies" },
            );
        }
    }

    // #35 — apply the validated `pnpm.patchedDependencies`
    // translation. Per-entry: copy the source patch file into LPM's
    // canonical `patches/<safe_key>.patch` location (skipped for
    // self-copy entries), then write the matching
    // `lpm.patchedDependencies[key] = { path, originalIntegrity }`
    // block to package.json.
    //
    // Same rollback contract as the overrides apply: any failure
    // triggers `migration_backup.rollback()` which restores
    // package.json, removes any newly-written patch files (tracked
    // via the v2 manifest's `created` list), and brings the
    // pre-existing destination paths back from their backups.
    if patches_plan.has_entries() {
        if let Err(e) = apply_patches(
            &pkg_json_path,
            &patches_plan.to_apply,
            &mut migration_backup,
        ) {
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
            return Err(e);
        }
        if !json {
            let n = patches_plan.to_apply.len();
            let copied = patches_plan
                .to_apply
                .iter()
                .filter(|t| !t.is_self_copy)
                .count();
            eprintln!(
                "  {} Translated {n} `pnpm.patchedDependencies` entr{} → `lpm.patchedDependencies` \
                 ({copied} patch file{} copied)",
                "ok".green().bold(),
                if n == 1 { "y" } else { "ies" },
                if copied == 1 { "" } else { "s" },
            );
        }
    }

    // #33 — apply the validated `pnpm.peerDependencyRules`
    // translation to `lpm.peerDependencyRules`. Three sub-fields are
    // appended/merged independently. Same rollback contract: any
    // failure triggers `migration_backup.rollback()` which restores
    // package.json from the backup taken alongside the lockfile.
    if peer_rules_plan.has_entries() {
        if let Err(e) = apply_peer_rules_to_package_json(&pkg_json_path, &peer_rules_plan) {
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
            return Err(e);
        }
        if !json {
            let n = peer_rules_plan.ignore_missing_to_apply.len()
                + peer_rules_plan.allow_any_to_apply.len()
                + peer_rules_plan.allowed_versions_to_apply.len();
            eprintln!(
                "  {} Translated {n} `pnpm.peerDependencyRules` entr{} → \
                 `lpm.peerDependencyRules`",
                "ok".green().bold(),
                if n == 1 { "y" } else { "ies" },
            );
        }
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
            client,
            cwd,
            json,
            false, // not offline — need to download tarballs
            false, // force
            false, // allow_new
            false, // strict_integrity
            None,  // linker_override
            true,  // no_skills — skip skill setup during migration
            true,  // no_editor_setup — skip editor setup during migration
            true,  // no_security_summary — migration already showed warnings
            false, // auto_build
            None,  // target_set: migrate is single-project
            None,  // direct_versions_out: migrate does not finalize placeholders
            None,  // script_policy_override: `lpm migrate` does not expose policy flags
            None,  // advisor_override: `lpm migrate` does not expose `--advisor`
            None,  // min_release_age_override: `lpm migrate` uses the chain
            crate::provenance_fetch::DriftIgnorePolicy::default(), // drift-ignore: `lpm migrate` enforces drift
            crate::provenance_fetch::VerifyPolicy::resolve_no_cli(), // verify-policy: `lpm migrate` honors env + config posture chain
            // `lpm migrate` does not surface its
            // own sandbox-mode flags. The env / config / default
            // chain inside `rebuild::run` still applies.
            false, // strict_sandbox
            false, // no_sandbox
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
        eprintln!(
            "    {} Need to undo? Run {}",
            "3.".dimmed(),
            "lpm migrate --rollback".bold(),
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

    // Resolve the managed runtime once for the whole verification pass — the
    // build and test scripts run back-to-back against the same project.
    let bin_hint = super::run::ensure_runtime(cwd).await;

    // Run build if it exists
    if has_build {
        match super::run::run(cwd, "build", &[], None, false, &bin_hint).await {
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
        match super::run::run(cwd, "test", &[], None, false, &bin_hint).await {
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

    // The backup layer's v2 manifest tracks lpm.lock + lpm.lockb both as
    // "newly created" (when the migration was fresh) or as restored from
    // backup (when overwriting). No special-case handling needed here —
    // every file the migration touched round-trips through the manifest.
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

/// Render a structured `pnpm.overrides` translation-plan failure to
/// stderr. JSON mode prints a structured object; human mode groups by
/// category. Either way, the message ends with "No files were modified"
/// because we render this BEFORE any disk mutation.
fn render_overrides_plan_errors(plan: &super::migrate_overrides::PnpmOverridesPlan, json: bool) {
    if json {
        let payload = serde_json::json!({
            "success": false,
            "error": "pnpm-overrides-translation",
            "conflicts": plan.conflicts.iter().map(|c| serde_json::json!({
                "key": c.key,
                "pnpm_target": c.pnpm_target,
                "lpm_target": c.lpm_target,
            })).collect::<Vec<_>>(),
            "parse_errors": plan.parse_errors.iter().map(|e| serde_json::json!({
                "key": e.key,
                "target": e.target,
                "error": e.error,
            })).collect::<Vec<_>>(),
            "unsupported_shapes": plan.unsupported_shapes.iter().map(|s| serde_json::json!({
                "key": s.key,
                "got": s.got,
            })).collect::<Vec<_>>(),
        });
        eprintln!(
            "{}",
            serde_json::to_string_pretty(&payload).unwrap_or_default()
        );
        return;
    }

    eprintln!();
    eprintln!(
        "  {} cannot translate `pnpm.overrides` to `lpm.overrides`:",
        "error".red().bold()
    );

    if !plan.parse_errors.is_empty() {
        eprintln!();
        eprintln!("  parse errors (entries rejected by LPM's selector grammar):");
        for e in &plan.parse_errors {
            eprintln!(
                "    {} {}: {}",
                "-".dimmed(),
                format!("`{}`", e.key).bold(),
                e.error,
            );
        }
    }

    if !plan.unsupported_shapes.is_empty() {
        eprintln!();
        eprintln!("  unsupported value shapes (LPM only accepts string targets):");
        for s in &plan.unsupported_shapes {
            eprintln!(
                "    {} {}: {}",
                "-".dimmed(),
                format!("`{}`", s.key).bold(),
                s.got,
            );
        }
    }

    if !plan.conflicts.is_empty() {
        eprintln!();
        eprintln!("  conflicts with existing `lpm.overrides` (same key, different target):");
        for c in &plan.conflicts {
            eprintln!(
                "    {} {} — pnpm has {}, lpm.overrides has {}",
                "-".dimmed(),
                format!("`{}`", c.key).bold(),
                format!("\"{}\"", c.pnpm_target).cyan(),
                format!("\"{}\"", c.lpm_target).cyan(),
            );
        }
    }

    eprintln!();
    eprintln!(
        "  {} No files were modified. Resolve the issues above in `package.json` and re-run {}.",
        "info".blue().bold(),
        "lpm migrate".bold()
    );
}

/// Merge the validated `pnpm.overrides` plan into
/// `package.json > lpm.overrides` with an atomic write.
///
/// Mirrors the JSON-Value-mutation pattern used by
/// `commands::patch::update_package_json_patches` so existing key
/// ordering is preserved (the workspace enables `serde_json`'s
/// `preserve_order` feature). Atomic via `.tmp` + rename so a partial
/// write can't leave the manifest corrupted.
fn apply_overrides_to_package_json(
    pkg_path: &Path,
    to_apply: &std::collections::HashMap<String, String>,
) -> Result<(), LpmError> {
    let raw = std::fs::read_to_string(pkg_path)
        .map_err(|e| LpmError::Script(format!("package.json at {pkg_path:?} unreadable: {e}")))?;
    let mut value: serde_json::Value = serde_json::from_str(&raw)
        .map_err(|e| LpmError::Script(format!("package.json malformed: {e}")))?;

    let lpm_section = value
        .as_object_mut()
        .ok_or_else(|| LpmError::Script("package.json root is not an object".into()))?
        .entry("lpm".to_string())
        .or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()));

    let lpm_obj = lpm_section
        .as_object_mut()
        .ok_or_else(|| LpmError::Script("package.json `lpm` is not an object".into()))?;

    let overrides = lpm_obj
        .entry("overrides".to_string())
        .or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()));
    let overrides_obj = overrides
        .as_object_mut()
        .ok_or_else(|| LpmError::Script("package.json `lpm.overrides` is not an object".into()))?;

    // Merge: each entry in `to_apply` is either a brand-new key or an
    // idempotent re-write of an existing same-target entry (the planner
    // already filtered out conflicts).
    for (key, target) in to_apply {
        overrides_obj.insert(key.clone(), serde_json::Value::String(target.clone()));
    }

    let mut output = serde_json::to_string_pretty(&value)
        .map_err(|e| LpmError::Script(format!("failed to re-serialize package.json: {e}")))?;
    if !output.ends_with('\n') {
        output.push('\n');
    }

    let tmp = pkg_path.with_extension("json.tmp");
    std::fs::write(&tmp, output.as_bytes()).map_err(LpmError::Io)?;
    if let Err(e) = std::fs::rename(&tmp, pkg_path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(LpmError::Io(e));
    }
    Ok(())
}

/// Render a structured `pnpm.patchedDependencies` translation-plan
/// failure to stderr (or as a JSON object under `--json`). Mirrors the
/// shape of `render_overrides_plan_errors` so the error reporting feels
/// uniform between the two pnpm surfaces. Always ends with "No files
/// were modified" because we render this BEFORE any disk mutation.
fn render_patches_plan_errors(plan: &super::migrate_patches::PnpmPatchesPlan, json: bool) {
    if json {
        let payload = serde_json::json!({
            "success": false,
            "error": "pnpm-patches-translation",
            "conflicts": plan.conflicts.iter().map(|c| serde_json::json!({
                "key": c.key,
                "pnpm_dest": c.pnpm_dest,
                "lpm_path": c.lpm_path,
            })).collect::<Vec<_>>(),
            "parse_errors": plan.parse_errors.iter().map(|e| serde_json::json!({
                "key": e.key,
                "reason": e.reason,
            })).collect::<Vec<_>>(),
            "unsupported_shapes": plan.unsupported_shapes.iter().map(|s| serde_json::json!({
                "key": s.key,
                "got": s.got,
            })).collect::<Vec<_>>(),
            "path_violations": plan.path_violations.iter().map(|v| serde_json::json!({
                "key": v.key,
                "raw_value": v.raw_value,
                "kind": format!("{:?}", v.kind),
                "detail": v.detail,
            })).collect::<Vec<_>>(),
            "integrity_misses": plan.integrity_misses.iter().map(|m| serde_json::json!({
                "key": m.key,
                "name": m.name,
                "version": m.version,
                "reason": format!("{:?}", m.reason),
            })).collect::<Vec<_>>(),
        });
        eprintln!(
            "{}",
            serde_json::to_string_pretty(&payload).unwrap_or_default()
        );
        return;
    }

    eprintln!();
    eprintln!(
        "  {} cannot translate `pnpm.patchedDependencies` to `lpm.patchedDependencies`:",
        "error".red().bold()
    );

    if !plan.parse_errors.is_empty() {
        eprintln!();
        eprintln!("  parse errors (key isn't `name@version`-shaped):");
        for e in &plan.parse_errors {
            eprintln!(
                "    {} {}: {}",
                "-".dimmed(),
                format!("`{}`", e.key).bold(),
                e.reason,
            );
        }
    }

    if !plan.unsupported_shapes.is_empty() {
        eprintln!();
        eprintln!("  unsupported value shapes (LPM only accepts string paths):");
        for s in &plan.unsupported_shapes {
            eprintln!(
                "    {} {}: {}",
                "-".dimmed(),
                format!("`{}`", s.key).bold(),
                s.got,
            );
        }
    }

    if !plan.path_violations.is_empty() {
        eprintln!();
        eprintln!("  path validation failures:");
        for v in &plan.path_violations {
            eprintln!(
                "    {} {} → {}",
                "-".dimmed(),
                format!("`{}`", v.key).bold(),
                v.detail,
            );
        }
    }

    if !plan.integrity_misses.is_empty() {
        eprintln!();
        eprintln!(
            "  cannot bind to a tarball integrity hash (LPM patches require \
             `originalIntegrity`):"
        );
        for m in &plan.integrity_misses {
            let why = match m.reason {
                super::migrate_patches::IntegrityMissReason::NotInLockfile => {
                    "not present in the migrated lockfile"
                }
                super::migrate_patches::IntegrityMissReason::LockfileMissingIntegrity => {
                    "lockfile entry has no `integrity` field (workspace link or git dep?)"
                }
            };
            eprintln!(
                "    {} {} ({}@{}) — {why}",
                "-".dimmed(),
                format!("`{}`", m.key).bold(),
                m.name,
                m.version,
            );
        }
    }

    if !plan.conflicts.is_empty() {
        eprintln!();
        eprintln!(
            "  conflicts with existing `lpm.patchedDependencies` (same key, different path):"
        );
        for c in &plan.conflicts {
            eprintln!(
                "    {} {} — pnpm would write {}, lpm.patchedDependencies has {}",
                "-".dimmed(),
                format!("`{}`", c.key).bold(),
                format!("\"{}\"", c.pnpm_dest).cyan(),
                format!("\"{}\"", c.lpm_path).cyan(),
            );
        }
    }

    eprintln!();
    eprintln!(
        "  {} No files were modified. Resolve the issues above in `package.json` and re-run {}.",
        "info".blue().bold(),
        "lpm migrate".bold()
    );
}

/// Render a structured `pnpm.peerDependencyRules` translation-plan
/// failure to stderr (or as a JSON object under `--json`). Mirrors the
/// shape of `render_overrides_plan_errors` / `render_patches_plan_errors`
/// so the error reporting feels uniform across the three pnpm
/// surfaces. Always ends with "No files were modified" because we
/// render this BEFORE any disk mutation.
fn render_peer_rules_plan_errors(plan: &super::migrate_peer_rules::PnpmPeerRulesPlan, json: bool) {
    if json {
        let payload = serde_json::json!({
            "success": false,
            "error": "pnpm-peer-rules-translation",
            "allowed_versions_conflicts": plan
                .allowed_versions_conflicts
                .iter()
                .map(|c| serde_json::json!({
                    "name": c.name,
                    "pnpm_range": c.pnpm_range,
                    "lpm_range": c.lpm_range,
                }))
                .collect::<Vec<_>>(),
            "allowed_versions_parse_errors": plan
                .allowed_versions_parse_errors
                .iter()
                .map(|e| serde_json::json!({
                    "name": e.name,
                    "range": e.range,
                    "error": e.error,
                }))
                .collect::<Vec<_>>(),
            "unsupported_shapes": plan
                .unsupported_shapes
                .iter()
                .map(|s| serde_json::json!({
                    "field": s.field,
                    "got": s.got,
                }))
                .collect::<Vec<_>>(),
        });
        eprintln!(
            "{}",
            serde_json::to_string_pretty(&payload).unwrap_or_default()
        );
        return;
    }

    eprintln!();
    eprintln!(
        "  {} cannot translate `pnpm.peerDependencyRules` to `lpm.peerDependencyRules`:",
        "error".red().bold()
    );

    if !plan.allowed_versions_parse_errors.is_empty() {
        eprintln!();
        eprintln!("  parse errors in `allowedVersions`:");
        for e in &plan.allowed_versions_parse_errors {
            eprintln!(
                "    {} {}: {} ({})",
                "-".dimmed(),
                format!("`{}`", e.name).bold(),
                format!("\"{}\"", e.range).cyan(),
                e.error,
            );
        }
    }

    if !plan.unsupported_shapes.is_empty() {
        eprintln!();
        eprintln!("  unsupported value shapes:");
        for s in &plan.unsupported_shapes {
            eprintln!(
                "    {} {}: got {}",
                "-".dimmed(),
                format!("`{}`", s.field).bold(),
                s.got,
            );
        }
    }

    if !plan.allowed_versions_conflicts.is_empty() {
        eprintln!();
        eprintln!(
            "  conflicts with existing `lpm.peerDependencyRules.allowedVersions` \
             (same name, different range):"
        );
        for c in &plan.allowed_versions_conflicts {
            eprintln!(
                "    {} {} — pnpm wants {}, lpm.peerDependencyRules has {}",
                "-".dimmed(),
                format!("`{}`", c.name).bold(),
                format!("\"{}\"", c.pnpm_range).cyan(),
                format!("\"{}\"", c.lpm_range).cyan(),
            );
        }
    }

    eprintln!();
    eprintln!(
        "  {} No files were modified. Resolve the issues above in `package.json` and re-run {}.",
        "info".blue().bold(),
        "lpm migrate".bold()
    );
}

/// Apply a validated peer-rules plan to
/// `package.json > lpm.peerDependencyRules`. Three sub-fields are
/// merged independently:
///
/// - `ignoreMissing` — append new names to the existing array,
///   preserving order.
/// - `allowAny` — append new patterns to the existing array,
///   preserving order.
/// - `allowedVersions` — insert each new (name, range) pair into the
///   existing object. The planner already filtered out same-name
///   same-range no-ops and same-name different-range conflicts.
///
/// Atomic via `.tmp` + rename so a partial write can't corrupt the
/// manifest. The caller is responsible for rolling back via
/// `migration_backup.rollback()` on failure — `package.json` is
/// already in the backup chain by the time this runs.
fn apply_peer_rules_to_package_json(
    pkg_path: &Path,
    plan: &super::migrate_peer_rules::PnpmPeerRulesPlan,
) -> Result<(), LpmError> {
    let raw = std::fs::read_to_string(pkg_path)
        .map_err(|e| LpmError::Script(format!("package.json at {pkg_path:?} unreadable: {e}")))?;
    let mut value: serde_json::Value = serde_json::from_str(&raw)
        .map_err(|e| LpmError::Script(format!("package.json malformed: {e}")))?;

    let lpm_section = value
        .as_object_mut()
        .ok_or_else(|| LpmError::Script("package.json root is not an object".into()))?
        .entry("lpm".to_string())
        .or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()));

    let lpm_obj = lpm_section
        .as_object_mut()
        .ok_or_else(|| LpmError::Script("package.json `lpm` is not an object".into()))?;

    let rules = lpm_obj
        .entry("peerDependencyRules".to_string())
        .or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()));
    let rules_obj = rules.as_object_mut().ok_or_else(|| {
        LpmError::Script("package.json `lpm.peerDependencyRules` is not an object".into())
    })?;

    if !plan.ignore_missing_to_apply.is_empty() {
        let arr = rules_obj
            .entry("ignoreMissing".to_string())
            .or_insert_with(|| serde_json::Value::Array(Vec::new()))
            .as_array_mut()
            .ok_or_else(|| {
                LpmError::Script(
                    "package.json `lpm.peerDependencyRules.ignoreMissing` is not an array".into(),
                )
            })?;
        for name in &plan.ignore_missing_to_apply {
            arr.push(serde_json::Value::String(name.clone()));
        }
    }

    if !plan.allow_any_to_apply.is_empty() {
        let arr = rules_obj
            .entry("allowAny".to_string())
            .or_insert_with(|| serde_json::Value::Array(Vec::new()))
            .as_array_mut()
            .ok_or_else(|| {
                LpmError::Script(
                    "package.json `lpm.peerDependencyRules.allowAny` is not an array".into(),
                )
            })?;
        for pattern in &plan.allow_any_to_apply {
            arr.push(serde_json::Value::String(pattern.clone()));
        }
    }

    if !plan.allowed_versions_to_apply.is_empty() {
        let map = rules_obj
            .entry("allowedVersions".to_string())
            .or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()))
            .as_object_mut()
            .ok_or_else(|| {
                LpmError::Script(
                    "package.json `lpm.peerDependencyRules.allowedVersions` is not an object"
                        .into(),
                )
            })?;
        for (name, range) in &plan.allowed_versions_to_apply {
            map.insert(name.clone(), serde_json::Value::String(range.clone()));
        }
    }

    let mut output = serde_json::to_string_pretty(&value)
        .map_err(|e| LpmError::Script(format!("failed to re-serialize package.json: {e}")))?;
    if !output.ends_with('\n') {
        output.push('\n');
    }

    let tmp = pkg_path.with_extension("json.tmp");
    std::fs::write(&tmp, output.as_bytes()).map_err(LpmError::Io)?;
    if let Err(e) = std::fs::rename(&tmp, pkg_path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(LpmError::Io(e));
    }
    Ok(())
}

/// Apply a validated patches plan: copy each patch file into LPM's
/// canonical `patches/<safe_key>.patch` location (skipping self-copy
/// entries) and merge the matching `lpm.patchedDependencies[key]`
/// block into `package.json`. The caller is responsible for rolling
/// back via `migration_backup.rollback()` on failure — every file we
/// write here is tracked in the backup chain.
fn apply_patches(
    pkg_path: &Path,
    to_apply: &[super::migrate_patches::PatchTranslation],
    migration_backup: &mut MigrationBackup,
) -> Result<(), LpmError> {
    use std::collections::HashMap;

    // 1. Copy patch files. Track each new write through the backup
    //    chain so rollback knows to remove them.
    for t in to_apply {
        if t.is_self_copy {
            continue;
        }

        if let Some(parent) = t.dest_absolute.parent()
            && !parent.exists()
        {
            std::fs::create_dir_all(parent).map_err(LpmError::Io)?;
        }

        // Record BEFORE write: backup_file's "did the file exist?"
        // probe must happen first so rollback's "newly created"
        // tracking is correct. backup_file copies pre-existing
        // content to .backup if present (that's already handled in
        // the caller's pre-write loop above), or just records the
        // path as newly-created.
        if !t.dest_pre_exists {
            migration_backup.backup_file(&t.dest_absolute)?;
        }

        std::fs::copy(&t.src_absolute, &t.dest_absolute).map_err(|e| {
            LpmError::Script(format!(
                "failed to copy {} → {}: {e}",
                t.src_absolute.display(),
                t.dest_absolute.display(),
            ))
        })?;
    }

    // 2. Merge the manifest entries into `lpm.patchedDependencies`.
    //    Atomic JSON Value mutation pattern (mirrors the overrides
    //    apply step + commands::patch::update_package_json_patches).
    let mut entries: HashMap<String, (String, String)> = HashMap::new();
    for t in to_apply {
        entries.insert(
            t.lpm_key.clone(),
            (t.dest_relative.clone(), t.integrity.clone()),
        );
    }

    let raw = std::fs::read_to_string(pkg_path)
        .map_err(|e| LpmError::Script(format!("package.json at {pkg_path:?} unreadable: {e}")))?;
    let mut value: serde_json::Value = serde_json::from_str(&raw)
        .map_err(|e| LpmError::Script(format!("package.json malformed: {e}")))?;

    {
        let lpm_section = value
            .as_object_mut()
            .ok_or_else(|| LpmError::Script("package.json root is not an object".into()))?
            .entry("lpm".to_string())
            .or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()));

        let lpm_obj = lpm_section
            .as_object_mut()
            .ok_or_else(|| LpmError::Script("package.json `lpm` is not an object".into()))?;

        let patches = lpm_obj
            .entry("patchedDependencies".to_string())
            .or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()));
        let patches_obj = patches.as_object_mut().ok_or_else(|| {
            LpmError::Script("package.json `lpm.patchedDependencies` is not an object".into())
        })?;

        for (key, (path, integrity)) in &entries {
            patches_obj.insert(
                key.clone(),
                serde_json::json!({
                    "path": path,
                    "originalIntegrity": integrity,
                }),
            );
        }
    } // drop the lpm-side mut borrows so we can re-borrow `value` for pnpm

    // 3. Rewrite `pnpm.patchedDependencies` values for non-self-copy
    //    entries to point at LPM's canonical destination. This keeps
    //    the diff-aware install-time warning correctly silent
    //    post-migrate when the user had a non-canonical source path —
    //    without it, `pnpm[k] = "vendor/x.patch"` and
    //    `lpm[k].path = "patches/x.patch"` would diverge at the path
    //    level even though both refer to the same patch and the
    //    migration has done its job.
    //
    //    Self-copy entries already point at the canonical path (that
    //    was the precondition for `is_self_copy = true`), so they
    //    don't need rewriting.
    //
    //    Pnpm itself remains usable: the file we just copied to the
    //    canonical destination is what pnpm now finds at the rewritten
    //    path. The original source file is left in place — the user
    //    can clean it up at their leisure.
    if to_apply.iter().any(|t| !t.is_self_copy) {
        let pnpm_section = value
            .as_object_mut()
            .and_then(|root| root.get_mut("pnpm"))
            .and_then(|v| v.as_object_mut());
        if let Some(pnpm_obj) = pnpm_section
            && let Some(pnpm_patches) = pnpm_obj
                .get_mut("patchedDependencies")
                .and_then(|v| v.as_object_mut())
        {
            for t in to_apply {
                if t.is_self_copy {
                    continue;
                }
                if let Some(entry) = pnpm_patches.get_mut(&t.pnpm_key)
                    && entry.is_string()
                {
                    *entry = serde_json::Value::String(t.dest_relative.clone());
                }
            }
        }
    }

    let mut output = serde_json::to_string_pretty(&value)
        .map_err(|e| LpmError::Script(format!("failed to re-serialize package.json: {e}")))?;
    if !output.ends_with('\n') {
        output.push('\n');
    }

    let tmp = pkg_path.with_extension("json.tmp");
    std::fs::write(&tmp, output.as_bytes()).map_err(LpmError::Io)?;
    if let Err(e) = std::fs::rename(&tmp, pkg_path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(LpmError::Io(e));
    }
    Ok(())
}
