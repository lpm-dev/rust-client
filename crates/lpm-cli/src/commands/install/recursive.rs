use super::*;
use lpm_task::graph::WorkspaceGraph;
use std::collections::HashSet;
use std::sync::Arc;

pub(crate) struct RecursiveInstallOptions {
    pub(crate) json_output: bool,
    pub(crate) offline: bool,
    pub(crate) frozen_lockfile: FrozenLockfileMode,
    pub(crate) force: bool,
    pub(crate) allow_new: bool,
    pub(crate) strict_integrity: bool,
    pub(crate) no_engine_strict: bool,
    pub(crate) strict_peer_dependencies_override: Option<bool>,
    pub(crate) linker_override: Option<lpm_linker::LinkerMode>,
    pub(crate) lpm_skills_preference: crate::lpm_skills_config::LpmSkillsPreference,
    pub(crate) no_editor_setup: bool,
    pub(crate) no_security_summary: bool,
    pub(crate) auto_build: bool,
    pub(crate) script_policy_override: Option<crate::script_policy_config::ScriptPolicy>,
    pub(crate) advisor_override: Option<String>,
    pub(crate) min_release_age_override: Option<u64>,
    pub(crate) min_release_age_exclude: Vec<String>,
    pub(crate) drift_ignore_policy: crate::provenance_fetch::DriftIgnorePolicy,
    pub(crate) verify_policy: crate::provenance_fetch::VerifyPolicy,
    pub(crate) omit_policy: InstallOmitPolicy,
    pub(crate) strict_sandbox: bool,
    pub(crate) no_sandbox: bool,
    pub(crate) verbose: bool,
    pub(crate) audit_after_install: bool,
    pub(crate) timing: bool,
}

struct WorkspaceInstallTarget {
    name: String,
    path: PathBuf,
    kind: &'static str,
}

struct WorkspaceInstallOutcome {
    name: String,
    path: PathBuf,
    kind: &'static str,
    duration_ms: u64,
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn run_recursive_workspace_install(
    client: &RegistryClient,
    cwd: &Path,
    filters: &[String],
    filter_prod: &[String],
    changed_files_ignore_pattern: &[String],
    test_pattern: &[String],
    fail_if_no_match: bool,
    options: RecursiveInstallOptions,
) -> Result<(), LpmError> {
    let workspace = lpm_workspace::discover_workspace(cwd)
        .map_err(|error| LpmError::Script(format!("workspace discovery failed: {error}")))?
        .ok_or_else(|| {
            LpmError::Script(
                "`--recursive` requires a workspace. Run `lpm install` without `--recursive` \
                 for a standalone project."
                    .into(),
            )
        })?;
    let targets = select_workspace_install_targets(
        &workspace,
        filters,
        filter_prod,
        changed_files_ignore_pattern,
        test_pattern,
    )?;

    if targets.is_empty() {
        if fail_if_no_match {
            return Err(LpmError::Script(
                "no workspace packages matched the filter (--fail-if-no-match)".into(),
            ));
        }
        emit_workspace_install_report(&workspace.root, &[], options.json_output, 0);
        return Ok(());
    }

    let workspace_root = workspace.root.clone();
    let mut active_workspace = Arc::new(workspace);
    let workspace_lock = lpm_common::project_install_lock(&workspace_root);
    let started = Instant::now();
    let lpm_root = lpm_common::LpmRoot::from_env()?;
    let outcomes = lpm_common::with_exclusive_lock_async(workspace_lock, async {
        let mut outcomes = Vec::with_capacity(targets.len());

        for target in targets {
            let dev_lifecycle =
                crate::commands::root_lifecycle::RootProjectLifecycle::load(&target.path)?;
            dev_lifecycle.run_dev_preinstall(&target.path, options.json_output)?;

            crate::workspace_discovery_cache::refresh_target(
                Arc::make_mut(&mut active_workspace),
                &target.path,
            )
            .map_err(|error| {
                LpmError::Script(format!(
                    "failed to refresh workspace package {}: {error}",
                    target.path.display()
                ))
            })?;
            let target_started = Instant::now();
            let install = run_with_options_with_lpm_root(
                client,
                &target.path,
                options.json_output,
                options.offline,
                options.frozen_lockfile,
                options.force,
                options.allow_new,
                options.strict_integrity,
                options.no_engine_strict,
                options.strict_peer_dependencies_override,
                options.linker_override,
                options.lpm_skills_preference,
                options.no_editor_setup,
                options.no_security_summary,
                options.auto_build,
                None,
                None,
                None,
                options.script_policy_override,
                options.advisor_override.clone(),
                options.min_release_age_override,
                &options.min_release_age_exclude,
                options.drift_ignore_policy.clone(),
                options.verify_policy.clone(),
                options.omit_policy,
                options.strict_sandbox,
                options.no_sandbox,
                options.verbose,
                options.audit_after_install,
                options.timing,
                &[],
                false,
                false,
                lpm_root.clone(),
            );
            crate::workspace_discovery_cache::scope(Arc::clone(&active_workspace), install).await?;

            crate::commands::root_lifecycle::RootProjectLifecycle::load(&target.path)?
                .run_after_successful_install(&target.path, options.json_output)?;
            outcomes.push(WorkspaceInstallOutcome {
                name: target.name,
                path: target.path,
                kind: target.kind,
                duration_ms: duration_ms(target_started.elapsed()),
            });
        }

        Ok(outcomes)
    })
    .await?;

    emit_workspace_install_report(
        &workspace_root,
        &outcomes,
        options.json_output,
        duration_ms(started.elapsed()),
    );
    Ok(())
}

fn select_workspace_install_targets(
    workspace: &lpm_workspace::Workspace,
    filters: &[String],
    filter_prod: &[String],
    changed_files_ignore_pattern: &[String],
    test_pattern: &[String],
) -> Result<Vec<WorkspaceInstallTarget>, LpmError> {
    let graph = WorkspaceGraph::from_workspace(workspace);
    let filtered = !filters.is_empty() || !filter_prod.is_empty();
    let mut selected = HashSet::new();

    if filters.is_empty() && filter_prod.is_empty() {
        selected.extend(0..graph.len());
    } else {
        let selected_with_all_edges = if filters.is_empty() {
            HashSet::new()
        } else {
            crate::workspace_select::select_workspace_target_set(
                &graph,
                &workspace.root,
                filters,
                &[],
                changed_files_ignore_pattern,
                test_pattern,
                false,
                "main",
            )?
        };
        let dependencies: HashSet<usize> = selected_with_all_edges
            .iter()
            .flat_map(|&id| graph.transitive_dependencies(id))
            .collect();
        selected.extend(selected_with_all_edges);
        selected.extend(dependencies);

        let selected_with_prod_edges = if filter_prod.is_empty() {
            HashSet::new()
        } else {
            crate::workspace_select::select_workspace_target_set(
                &graph,
                &workspace.root,
                &[],
                filter_prod,
                changed_files_ignore_pattern,
                test_pattern,
                false,
                "main",
            )?
        };
        let production_dependencies: HashSet<usize> = selected_with_prod_edges
            .iter()
            .flat_map(|&id| graph.transitive_prod_dependencies(id))
            .collect();
        selected.extend(selected_with_prod_edges);
        selected.extend(production_dependencies);
    }

    let ordered_ids = match graph.topological_sort() {
        Ok(ids) => ids,
        Err(error) => {
            tracing::warn!(
                "workspace dependency graph is cyclic; using deterministic path order: {error}"
            );
            let mut ids: Vec<_> = (0..graph.len()).collect();
            ids.sort_unstable_by(|left, right| {
                workspace.members[*left]
                    .path
                    .cmp(&workspace.members[*right].path)
            });
            ids
        }
    };

    let root_capacity = usize::from(!filtered);
    let mut targets = Vec::with_capacity(selected.len() + root_capacity);
    for id in ordered_ids {
        if !selected.contains(&id) {
            continue;
        }
        let member = &workspace.members[id];
        targets.push(WorkspaceInstallTarget {
            name: member
                .package
                .name
                .clone()
                .unwrap_or_else(|| graph.members[id].name.clone()),
            path: member.path.clone(),
            kind: "member",
        });
    }

    if !filtered {
        targets.push(WorkspaceInstallTarget {
            name: workspace
                .root_package
                .name
                .clone()
                .unwrap_or_else(|| "(workspace root)".into()),
            path: workspace.root.clone(),
            kind: "root",
        });
    }

    Ok(targets)
}

fn emit_workspace_install_report(
    workspace_root: &Path,
    outcomes: &[WorkspaceInstallOutcome],
    json_output: bool,
    duration_ms: u64,
) {
    if json_output {
        let targets: Vec<serde_json::Value> = outcomes
            .iter()
            .map(|outcome| {
                serde_json::json!({
                    "name": outcome.name,
                    "path": outcome.path.display().to_string(),
                    "kind": outcome.kind,
                    "status": "success",
                    "duration_ms": outcome.duration_ms,
                })
            })
            .collect();
        let report = serde_json::json!({
            "schema_version": crate::json_contract::INSTALL_JSON_SCHEMA_VERSION,
            "success": true,
            "recursive": true,
            "workspace_root": workspace_root.display().to_string(),
            "duration_ms": duration_ms,
            "targets": targets,
            "summary": {
                "total": outcomes.len(),
                "succeeded": outcomes.len(),
                "failed": 0,
            },
        });
        println!("{}", serde_json::to_string_pretty(&report).unwrap());
    } else {
        output::success(&format!(
            "Installed {} workspace package{} in {duration_ms}ms",
            outcomes.len(),
            if outcomes.len() == 1 { "" } else { "s" },
        ));
    }
}

fn duration_ms(duration: std::time::Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}
