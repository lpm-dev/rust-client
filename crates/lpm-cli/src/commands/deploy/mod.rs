//! `lpm deploy` — materialize a workspace member's selected dependency closure into
//! a self-contained directory ready for Docker / `COPY --from=pruned`.
//!
//! ## High-level pipeline
//!
//! 1. Resolve `--filter <expr>` via [`crate::commands::install_targets`]; assert
//!    the result is exactly one member (deploy is single-target).
//! 2. Validate the output directory (must be outside the workspace, must be
//!    empty unless `--force`).
//! 3. Copy package-publishable source files into the output dir, applying
//!    the deny list (no `.env`, no `node_modules`, no `.git`, etc.).
//! 4. Copy any selected local workspace dependencies into a deploy-local
//!    source area and rewrite `workspace:*` references to relative `file:`
//!    specs.
//! 5. Run the install pipeline with an LPM root inside the output dir to materialize the
//!    dependency tree (downloads tarballs, links into `output/node_modules`).
//! 6. Emit a structured success summary.
//!
//! ## Key invariants
//!
//! - **The source workspace is read-only.** Deploy never modifies any file
//!   under the workspace root.
//! - **`--dry-run` writes nothing.** Hard rule: zero filesystem writes when
//!   `dry_run == true`.
//! - **Deploy targets exactly one member.** Multi-member deploy is a future release.
//! - **Deploy output is portable on Unix.** Internal absolute symlinks under
//!   `node_modules` are rewritten to relative symlinks after install.

mod copy;
mod file_select;
mod lockfile_prune;
mod manifest_rewrite;
mod paths;

#[cfg(test)]
mod tests;

use crate::install_ui;
use copy::{copy_member_source, retarget_internal_node_modules_symlinks};
use lockfile_prune::write_pruned_deploy_lockfile_if_possible;
use lpm_common::LpmError;
use lpm_registry::RegistryClient;
use manifest_rewrite::{
    apply_dependency_selection_to_deploy_manifest, copy_workspace_dependency_closure,
};
use paths::{read_member_name, resolve_deploy_target};
use std::path::Path;
use std::time::Instant;

pub(in crate::commands::deploy) const DEPLOY_WORKSPACE_DIR: &str = ".lpm/deploy-workspace";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::commands::deploy) enum DependencyMode {
    Production,
    Development,
}

impl DependencyMode {
    pub(in crate::commands::deploy) fn from_flags(_prod: bool, dev: bool) -> Self {
        if dev {
            Self::Development
        } else {
            Self::Production
        }
    }

    pub(in crate::commands::deploy) fn label(self) -> &'static str {
        match self {
            Self::Production => "production",
            Self::Development => "development",
        }
    }
}

#[derive(Debug, Clone, Default)]
pub(in crate::commands::deploy) struct ManifestSelectionStats {
    pub(in crate::commands::deploy) dev_dependencies_stripped: usize,
    pub(in crate::commands::deploy) production_dependencies_stripped: usize,
    pub(in crate::commands::deploy) optional_dependencies_stripped: usize,
}

impl ManifestSelectionStats {
    pub(in crate::commands::deploy) fn add(&mut self, other: &Self) {
        self.dev_dependencies_stripped += other.dev_dependencies_stripped;
        self.production_dependencies_stripped += other.production_dependencies_stripped;
        self.optional_dependencies_stripped += other.optional_dependencies_stripped;
    }
}

/// Run the `lpm deploy` command.
///
/// All four steps are wired — target resolution, source file
/// copy, manifest rewrite, and install pipeline at the deploy output dir.
///
/// In `--json` mode the deploy command produces a deploy-specific summary
/// JSON object on stdout AFTER the install pipeline's own JSON output.
/// Together they form a JSON-Lines stream (two objects, one per line).
/// This is the same multi-object pattern uses for multi-target
/// installs and is documented as the deploy JSON contract.
#[allow(clippy::too_many_arguments)] // matches the install/uninstall surface for consistency
pub async fn run(
    client: &RegistryClient,
    cwd: &Path,
    output_dir: &Path,
    filters: &[String],
    filter_prod: &[String],
    changed_files_ignore_pattern: &[String],
    test_pattern: &[String],
    force: bool,
    prod: bool,
    dev: bool,
    no_optional: bool,
    dry_run: bool,
    json_output: bool,
) -> Result<(), LpmError> {
    let start = Instant::now();
    if prod && dev {
        return Err(LpmError::Script(
            "lpm deploy: --prod and --dev are mutually exclusive".into(),
        ));
    }
    let dependency_mode = DependencyMode::from_flags(prod, dev);
    let plan = resolve_deploy_target(
        cwd,
        output_dir,
        filters,
        filter_prod,
        changed_files_ignore_pattern,
        test_pattern,
        force,
    )?;
    let member_name = read_member_name(&plan.member_manifest);
    let materialize_message = crate::install_ui::terminal_line!(
        "Materializing {} closure for {}",
        dependency_mode.label(),
        install_ui::yellow(&member_name)
    );

    if dry_run {
        // Dry-run: validation succeeded, but write nothing. Surface the
        // resolved plan so the user knows what would happen.
        if json_output {
            let payload = serde_json::json!({
                "success": true,
                "dry_run": true,
                "member": member_name,
                "member_dir": plan.member_dir.display().to_string(),
                "output_dir": plan.output_dir.display().to_string(),
                "dependency_mode": dependency_mode.label(),
                "optional_dependencies": !no_optional,
            });
            println!(
                "{}",
                serde_json::to_string_pretty(&payload).unwrap_or_default()
            );
        } else {
            install_ui::phase_line(materialize_message);
            deploy_detail_colored(
                "output:",
                install_ui::yellow(&plan.output_dir.display().to_string()),
            );
            deploy_detail_colored(
                "member:",
                install_ui::cyan(&plan.member_dir.display().to_string()),
            );
            deploy_detail_colored("dry run:", install_ui::status_ok("yes"));
            deploy_detail_colored(
                "dependency mode:",
                install_ui::status_ok(dependency_mode.label()),
            );
            deploy_detail_colored(
                "optional deps:",
                install_ui::status_ok(if no_optional { "omitted" } else { "included" }),
            );
            install_ui::done("Done · dry run complete");
        }
        return Ok(());
    }

    let deploy_progress = (!json_output).then(|| install_ui::spin_line(materialize_message));

    // validate_output_dir has already proven this path is outside the source
    // workspace, so force-clearing here preserves a clean snapshot without
    // risking source files.
    if force && plan.output_dir.exists() {
        std::fs::remove_dir_all(&plan.output_dir).map_err(|e| {
            LpmError::Script(format!(
                "lpm deploy --force: failed to clear output directory {:?}: {e}",
                plan.output_dir
            ))
        })?;
        std::fs::create_dir_all(&plan.output_dir).map_err(|e| {
            LpmError::Script(format!(
                "lpm deploy --force: failed to recreate empty output directory {:?}: {e}",
                plan.output_dir
            ))
        })?;
    }

    let copy_stats = copy_member_source(&plan.member_dir, &plan.output_dir)?;

    let mut selection_stats = apply_dependency_selection_to_deploy_manifest(
        &plan.output_dir,
        dependency_mode,
        no_optional,
    )?;

    let (
        workspace_members_copied,
        workspace_spec_rewrites,
        workspace_copy_stats,
        workspace_selection_stats,
    ) = copy_workspace_dependency_closure(
        &plan.output_dir,
        cwd,
        &member_name,
        dependency_mode,
        no_optional,
    )?;
    selection_stats.add(&workspace_selection_stats);

    let pruned_lockfile_packages =
        write_pruned_deploy_lockfile_if_possible(cwd, &plan.output_dir)?.unwrap_or(0);

    let target_set: Vec<String> = vec![plan.output_dir.display().to_string()];

    crate::commands::install::run_with_options_with_lpm_root(
        client,
        &plan.output_dir,
        json_output,
        false, // offline
        crate::commands::install::FrozenLockfileMode::Never,
        false, // force — don't force re-link, the output dir is fresh
        false, // allow_new — deploy should not bypass minimumReleaseAge
        false, // strict_integrity — deploy uses lockfile, integrity is recorded
        false, // no_engine_strict
        None,  // strict_peer_dependencies_override
        None,  // linker_override
        crate::lpm_skills_config::LpmSkillsPreference::Disabled,
        true,  // no_editor_setup — same reason
        false, // no_security_summary — keep findings visible in CI
        false, // auto_build — build is a separate concern
        Some(&target_set),
        None, // direct_versions_out: deploy does not finalize placeholders
        None, // requested_add_count: deploy is not an add-path install
        None, // script_policy_override: `lpm deploy` does not expose policy flags
        None, // advisor_override: `lpm deploy` does not expose `--advisor`
        None, // min_release_age_override: use install defaults
        &[],
        // drift-ignore: deploy captures an already-resolved tree;
        // drift is an orthogonal gate. Deploy inherits the same
        // default "enforce"; the output dir carries whatever
        // trustedDependencies the project defined, so legitimately
        // identical identities pass normally.
        crate::provenance_fetch::DriftIgnorePolicy::default(),
        // verify-policy: `lpm deploy` does not surface its own
        // `--unverified-provenance{,-all}` flags. Honors the
        // operator-persistent posture chain (env + `[sigstore]
        // verify` config) for uniformity with `lpm install`.
        crate::provenance_fetch::VerifyPolicy::resolve_no_cli(),
        crate::commands::install::InstallOmitPolicy {
            dev: false,
            optional: no_optional,
        },
        // `lpm deploy` does not surface its own
        // sandbox-mode flags. CI deployers can still flip strict
        // via `LPM_STRICT_SANDBOX=1`; the env tier of the chain
        // inside `rebuild::run` honors that.
        false, // strict_sandbox
        false, // no_sandbox
        false, // verbose: internal pipeline, no user-facing Done footer
        false, // audit_after_install: internal pipeline never runs audit
        false, // timing: deploy does not expose install's --timing flag
        &[],
        true,  // emit the install report before the deploy-specific summary
        false, // reserve_stdout: deploy owns no stdio protocol channel
        None,
        lpm_common::LpmRoot::from_dir(plan.output_dir.join(".lpm")),
    )
    .await?;

    let internal_symlinks_retargeted = retarget_internal_node_modules_symlinks(&plan.output_dir)?;
    drop(deploy_progress);

    let elapsed = start.elapsed();

    // Emit the deploy-specific summary AFTER the install pipeline's output.
    // In JSON mode this produces a JSON-Lines stream (install JSON, then
    // deploy JSON). In human mode it's a final success line.
    if json_output {
        let payload = serde_json::json!({
            "success": true,
            "dry_run": false,
            "deployed": {
                "member": member_name,
                "member_dir": plan.member_dir.display().to_string(),
                "output_dir": plan.output_dir.display().to_string(),
            },
            "copy_stats": {
                "files_copied": copy_stats.files_copied,
                "files_skipped": copy_stats.files_skipped,
                "bytes_copied": copy_stats.bytes_copied,
            },
            "workspace_copy_stats": {
                "members_copied": workspace_members_copied,
                "files_copied": workspace_copy_stats.files_copied,
                "files_skipped": workspace_copy_stats.files_skipped,
                "bytes_copied": workspace_copy_stats.bytes_copied,
            },
            "workspace_protocol_rewrites": workspace_spec_rewrites,
            "dependency_mode": dependency_mode.label(),
            "optional_dependencies": !no_optional,
            "dependencies_stripped": {
                "dev": selection_stats.dev_dependencies_stripped,
                "production": selection_stats.production_dependencies_stripped,
                "optional": selection_stats.optional_dependencies_stripped,
            },
            "pruned_lockfile_packages": pruned_lockfile_packages,
            "internal_symlinks_retargeted": internal_symlinks_retargeted,
            "duration_ms": elapsed.as_millis() as u64,
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&payload).unwrap_or_default()
        );
    } else {
        deploy_detail_colored(
            "output:",
            install_ui::yellow(&plan.output_dir.display().to_string()),
        );
        deploy_detail_colored(
            "dependency mode:",
            install_ui::status_ok(dependency_mode.label()),
        );
        deploy_detail_colored(
            "workspace deps copied:",
            install_ui::status_ok(&workspace_members_copied.to_string()),
        );
        deploy_detail_colored(
            "workspace refs localized:",
            install_ui::status_ok(&workspace_spec_rewrites.to_string()),
        );
        deploy_detail_colored(
            "pruned lockfile packages:",
            install_ui::status_ok(&pruned_lockfile_packages.to_string()),
        );
        deploy_detail_colored(
            "relative symlinks:",
            install_ui::status_ok(&internal_symlinks_retargeted.to_string()),
        );
        deploy_detail_colored("node_modules installed:", install_ui::status_ok("yes"));
        install_ui::done_line(crate::install_ui::terminal_line!(
            "Copied source, lockfile, and {} dependencies",
            install_ui::status_ok(dependency_mode.label())
        ));
        install_ui::done_line(crate::install_ui::terminal_line!(
            "Done · deploy tree ready at {}",
            install_ui::yellow(&plan.output_dir.display().to_string())
        ));
    }

    Ok(())
}

fn deploy_detail_colored(label: &'static str, value: install_ui::TerminalFragment) {
    install_ui::detail_line(crate::install_ui::terminal_line!(
        "    {} {}",
        install_ui::dim(&format!("{label:<25}")),
        value
    ));
}
