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
mod lockfile_prune;
mod manifest_rewrite;
mod paths;
mod secret_scan;

#[cfg(test)]
mod tests;

use crate::install_ui;
use copy::{retarget_internal_node_modules_symlinks, select_member_source, write_member_source};
use lockfile_prune::write_pruned_deploy_lockfile_if_possible;
use lpm_common::LpmError;
use lpm_registry::RegistryClient;
use manifest_rewrite::{
    apply_dependency_selection_to_deploy_manifest, plan_workspace_dependency_closure,
    write_workspace_dependency_closure,
};
use paths::{read_member_name, resolve_deploy_target};
use secret_scan::DeploySecretScan;
use std::path::{Path, PathBuf};
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
/// JSON output is one deploy summary after the installation succeeds.
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
    allow_secrets: bool,
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

    // Everything copied is chosen and scanned before anything is written, so
    // a refusal leaves the output as it was, and a dry run reports what a
    // deploy would.
    let mut secrets = (!allow_secrets).then(DeploySecretScan::new);
    let member = select_member_source(&plan.member_dir, None, secrets.as_mut())?;
    let closure = plan_workspace_dependency_closure(
        &plan.output_dir,
        cwd,
        &member_name,
        dependency_mode,
        no_optional,
        secrets.as_mut(),
    )?;
    if let Some(secrets) = &secrets {
        secrets.refuse_findings(cwd, json_output)?;
    }

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
        paths::remove_output(&plan.output_dir).map_err(|e| {
            LpmError::Script(format!(
                "lpm deploy --force: failed to clear output directory {:?}: {e}",
                plan.output_dir
            ))
        })?;
    }
    let output = paths::Output::prepare(&plan.output_dir)?;

    let copy_stats = write_member_source(&member, &plan.output_dir)?;
    output.verify()?;

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
    ) = write_workspace_dependency_closure(&closure, &plan.output_dir, no_optional)?;
    selection_stats.add(&workspace_selection_stats);

    let pruned_lockfile_packages =
        write_pruned_deploy_lockfile_if_possible(cwd, &plan.output_dir)?.unwrap_or(0);
    output.verify()?;

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
        !json_output, // JSON belongs to the single deploy summary
        false,        // reserve_stdout: deploy owns no stdio protocol channel
        None,
        lpm_common::LpmRoot::from_dir(plan.output_dir.join(".lpm")),
    )
    .await?;

    output.verify()?;
    let internal_symlinks_retargeted = retarget_internal_node_modules_symlinks(&plan.output_dir)?;
    output.verify()?;
    // The output's `.lpm` holds its package store and workspace sources,
    // which travel with it, as git commits it too.
    let state_ignore = lpm_common::project_state_dir(&plan.output_dir)
        .join(lpm_common::project_state::PROJECT_STATE_IGNORE_FILE);
    lpm_common::write_file_atomic_with_options(
        &state_ignore,
        lpm_common::project_state::DEPLOY_OUTPUT_STATE_IGNORE.as_bytes(),
        lpm_common::AtomicWriteOptions::new().unix_mode(0o644),
    )
    .map_err(|error| {
        LpmError::Script(format!(
            "deploy: failed to write {}, which lets git commit the output's dependencies: {error}",
            state_ignore.display()
        ))
    })?;
    let tree = OutputTree::read(&plan.output_dir)?;
    let output_ignore = plan
        .output_dir
        .join(lpm_common::project_state::PROJECT_STATE_IGNORE_FILE);
    lpm_common::write_file_atomic_with_options(
        &output_ignore,
        tree.take_backs().as_bytes(),
        lpm_common::AtomicWriteOptions::new().unix_mode(0o644),
    )
    .map_err(|error| {
        LpmError::Script(format!(
            "deploy: failed to write {}, which keeps git's rules outside the output from leaving out what the deploy wrote: {error}",
            output_ignore.display()
        ))
    })?;
    output.verify()?;
    let dependency_ignore_files = tree.dependency_ignore_files;
    drop(deploy_progress);

    let elapsed = start.elapsed();

    // The install pipeline reserves JSON stdout for this final result.
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
            "dependency_ignore_files": dependency_ignore_files,
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
        if !dependency_ignore_files.is_empty() {
            let directories: Vec<String> = dependency_ignore_files
                .iter()
                .map(|path| {
                    shell_quoted(
                        path.rsplit_once('/')
                            .map_or(".", |(directory, _)| directory),
                    )
                })
                .collect();
            install_ui::warn_line(crate::install_ui::terminal_line!(
                "{} .gitignore files came with dependencies, and git leaves out what they name; to commit the output, run in it: git add -f -- {}",
                install_ui::status_ok(&dependency_ignore_files.len().to_string()),
                &lpm_common::sanitize_terminal_inline(&directories.join(" "))
            ));
        }
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

/// What a deploy wrote into its output, as git reads it.
struct OutputTree {
    /// The `.gitignore` files below the output's top but its state
    /// directory's own, each `/`-separated and relative to it: what
    /// dependencies brought, as the deploy leaves the member's and its
    /// sources' out. Git leaves out the files one names whatever the files
    /// above it say.
    dependency_ignore_files: Vec<String>,
    /// The output's top-level entries, with a `/` after a directory.
    written: Vec<String>,
}

impl OutputTree {
    /// Reads `output` without following links.
    fn read(output: &Path) -> Result<Self, LpmError> {
        let mut tree = Self {
            dependency_ignore_files: Vec::new(),
            written: Vec::new(),
        };
        let mut pending = vec![(output.to_path_buf(), PathBuf::new())];
        while let Some((directory, relative)) = pending.pop() {
            let top = relative.as_os_str().is_empty();
            let entries = std::fs::read_dir(&directory).map_err(|error| {
                LpmError::Script(format!(
                    "deploy: failed to read {}: {error}",
                    directory.display()
                ))
            })?;
            for entry in entries {
                let entry = entry.map_err(LpmError::Io)?;
                let name = entry.file_name();
                let path = relative.join(&name);
                let file_type = entry.file_type().map_err(LpmError::Io)?;
                // The deploy writes only names its selection read as UTF-8
                // at the top.
                if top && let Some(name) = name.to_str() {
                    tree.written.push(if file_type.is_dir() {
                        format!("{name}/")
                    } else {
                        name.to_owned()
                    });
                }
                if file_type.is_dir() {
                    pending.push((entry.path(), path));
                } else if file_type.is_file()
                    && !top
                    // A file system that folds names reads `.GITIGNORE`,
                    // and HFS+ the name with a mark it ignores, as
                    // `.gitignore`.
                    && name.to_str().is_some_and(|name| {
                        crate::commands::publish_common::listed_in(
                            name,
                            &[lpm_common::project_state::PROJECT_STATE_IGNORE_FILE],
                        )
                    })
                    && relative.as_os_str() != lpm_common::PROJECT_STATE_DIR
                {
                    tree.dependency_ignore_files.push(portable_relative(&path));
                }
            }
        }
        tree.dependency_ignore_files.sort_unstable();
        tree.written.sort_unstable();
        Ok(tree)
    }

    /// The output's own `.gitignore`, which takes back from the rules of
    /// a repository the output is in, and from global ones, each entry in
    /// [`Self::written`], every directory in those directories, and all of
    /// `node_modules`; a rule there for files, such as `*.log`, still
    /// applies in those directories, and so does every rule for a file or a
    /// top-level entry added later. A line for each directory below the
    /// top would take back only what the deploy wrote, but git matches
    /// every path against every line, which grows with the output's square.
    /// It only takes back, so a tool that reads it for what to leave out
    /// leaves out nothing. Git reads `.lpm/.gitignore` in the state
    /// directory, and a dependency's `.gitignore` in the dependency, over
    /// it.
    fn take_backs(&self) -> String {
        let mut ignore = String::from(
            "# Written by lpm deploy: git commits what the deploy wrote here,\n\
             # whatever a rule outside the output says.\n!/.gitignore\n",
        );
        // No line can hold a line break, and a wildcard in its place would
        // take back other names too.
        for written in self
            .written
            .iter()
            .filter(|written| !written.contains(['\n', '\r']))
        {
            // Git on macOS reads a name the disk lists decomposed composed,
            // and as listed where `core.precomposeunicode` is off.
            let composed = lpm_common::names::composed(written);
            let spellings = std::iter::once(written.as_str())
                .chain((composed != written.as_str()).then_some(composed.as_ref()));
            for spelling in spellings {
                let pattern = ignore_pattern_literal(spelling);
                ignore.push_str(&format!("!/{pattern}\n"));
                match spelling.strip_suffix('/') {
                    Some("node_modules") => ignore.push_str("!/node_modules/**\n"),
                    Some(directory) if directory == lpm_common::PROJECT_STATE_DIR => {}
                    Some(_) => ignore.push_str(&format!("!/{pattern}**/\n")),
                    None => {}
                }
            }
        }
        ignore
    }
}

/// `name`, which holds no line break, as a `.gitignore` pattern that
/// matches it alone: git's glob characters escaped, and spaces at the end,
/// which git drops, escaped.
fn ignore_pattern_literal(name: &str) -> String {
    let kept = name.trim_end_matches(' ');
    let mut pattern = String::with_capacity(name.len() + 4);
    for character in kept.chars() {
        match character {
            '\\' | '*' | '?' | '[' => {
                pattern.push('\\');
                pattern.push(character);
            }
            _ => pattern.push(character),
        }
    }
    for _ in kept.len()..name.len() {
        pattern.push_str("\\ ");
    }
    pattern
}

/// `path`'s components joined with `/`, each as UTF-8 or as near as it
/// reads.
fn portable_relative(path: &Path) -> String {
    let mut portable = String::new();
    for component in path.components() {
        if !portable.is_empty() {
            portable.push('/');
        }
        portable.push_str(&component.as_os_str().to_string_lossy());
    }
    portable
}

/// `word` as one POSIX shell word.
fn shell_quoted(word: &str) -> String {
    if !word.is_empty()
        && word
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"/._-+@,=".contains(&byte))
    {
        word.to_owned()
    } else {
        format!("'{}'", word.replace('\'', "'\\''"))
    }
}

fn deploy_detail_colored(label: &'static str, value: install_ui::TerminalFragment) {
    install_ui::detail_line(crate::install_ui::terminal_line!(
        "    {} {}",
        install_ui::dim(&format!("{label:<25}")),
        value
    ));
}
