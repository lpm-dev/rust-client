use crate::commands::publish;
use crate::install_ui;
use crate::output;
use crate::release_plan::{self, ReleasePlan};
use crate::workspace_select;
use lpm_common::{LpmError, PackageName};
use lpm_registry::RegistryClient;
use lpm_semver::VersionBump;
use std::collections::HashSet;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub(crate) struct ReleaseSelection {
    pub(crate) all: bool,
    pub(crate) affected: bool,
    pub(crate) base: String,
    pub(crate) filter: Vec<String>,
    pub(crate) filter_prod: Vec<String>,
    pub(crate) changed_files_ignore_pattern: Vec<String>,
    pub(crate) test_pattern: Vec<String>,
    pub(crate) fail_if_no_match: bool,
}

#[derive(Debug, Clone)]
pub(crate) struct ReleasePublishOptions {
    pub(crate) dry_run: bool,
    pub(crate) yes: bool,
    pub(crate) otp: Option<String>,
    pub(crate) min_score: Option<u32>,
    pub(crate) allow_secrets: bool,
    pub(crate) npm: bool,
    pub(crate) lpm: bool,
    pub(crate) github: bool,
    pub(crate) gitlab: bool,
    pub(crate) publish_registry: Option<String>,
    pub(crate) provenance: bool,
    pub(crate) no_provenance: bool,
    pub(crate) provenance_file: Option<PathBuf>,
}

struct PublishMember {
    idx: usize,
    name: String,
    version: String,
    already_published: bool,
}

pub(crate) fn plan(
    project_dir: &Path,
    selection: &ReleaseSelection,
    bump: Option<&VersionBump>,
    json_output: bool,
) -> Result<(), LpmError> {
    let plan = build_plan(project_dir, selection, bump)?;
    emit_plan(&plan, true, json_output)
}

pub(crate) fn apply(
    project_dir: &Path,
    selection: &ReleaseSelection,
    bump: Option<&VersionBump>,
    dry_run: bool,
    json_output: bool,
) -> Result<(), LpmError> {
    let plan = build_plan(project_dir, selection, bump)?;
    if !dry_run {
        let planned = plan.planned_manifests()?;
        release_plan::write_planned_manifests(&planned)?;
    }
    emit_plan(&plan, dry_run, json_output)
}

pub(crate) async fn publish(
    client: &RegistryClient,
    project_dir: &Path,
    selection: &ReleaseSelection,
    options: &ReleasePublishOptions,
    json_output: bool,
) -> Result<(), LpmError> {
    let (workspace, graph, selected) = resolve_workspace_selection(project_dir, selection)?;
    release_plan::validate_workspace_internal_ranges(&workspace)?;
    let selected = release_plan::ensure_unique_selection(&selected);
    let selected_set: HashSet<usize> = selected.iter().copied().collect();
    let publish_order = release_plan::sorted_selected_indices(&graph, &selected_set)?;
    let mut members = Vec::with_capacity(publish_order.len());
    for idx in publish_order {
        members
            .push(publish_member_preflight(client, &workspace.members[idx], idx, options).await?);
    }
    let mut results = Vec::with_capacity(members.len());

    for publish_member in &members {
        let member = &workspace.members[publish_member.idx];
        let name = publish_member.name.as_str();
        let version = publish_member.version.as_str();
        if publish_member.already_published {
            results.push(serde_json::json!({
                "name": name,
                "version": version,
                "path": member.path,
                "status": "skipped",
                "reason": "already_published",
            }));
            if !json_output {
                install_ui::detail_untrusted(&format!("skip {name}@{version}: already published"));
            }
            continue;
        }

        if options.dry_run {
            results.push(serde_json::json!({
                "name": name,
                "version": version,
                "path": member.path,
                "status": "planned",
            }));
            continue;
        }

        let _stdout = output::suppress_stdout(json_output).map_err(LpmError::Script)?;
        publish::run(
            client,
            &member.path,
            false,
            false,
            false,
            None,
            options.otp.as_deref(),
            options.yes || json_output,
            json_output,
            options.min_score,
            options.allow_secrets,
            options.npm,
            options.lpm,
            options.github,
            options.gitlab,
            options.publish_registry.as_deref(),
            options.provenance,
            options.no_provenance,
            options.provenance_file.as_deref(),
        )
        .await?;
        results.push(serde_json::json!({
            "name": name,
            "version": version,
            "path": member.path,
            "status": "published",
        }));
    }

    let json = serde_json::json!({
        "success": true,
        "dry_run": options.dry_run,
        "packages": results.len(),
        "results": results,
    });
    if json_output {
        println!("{}", output::format_json_answer(&json)?);
    } else {
        install_ui::done_untrusted(&format!(
            "release publish processed {} packages",
            results.len()
        ));
    }
    Ok(())
}

async fn publish_member_preflight(
    client: &RegistryClient,
    member: &lpm_workspace::WorkspaceMember,
    idx: usize,
    options: &ReleasePublishOptions,
) -> Result<PublishMember, LpmError> {
    let manifest = publish::read_publish_manifest(&member.path)?;
    let name = manifest.name.clone();
    let version = manifest.version.clone();
    let target_names = resolved_publish_target_names(&manifest, options)?;
    let mut checked_targets = 0usize;
    let mut existing_targets = Vec::new();

    for (target, target_name) in &target_names {
        match target {
            publish::PublishTarget::Lpm => {
                checked_targets += 1;
                if lpm_version_exists(client, target_name, &version).await? {
                    existing_targets.push(target.display_name().to_string());
                }
            }
            publish::PublishTarget::Npm => {
                checked_targets += 1;
                if npm_version_exists(client, target_name, &version).await? {
                    existing_targets.push(target.display_name().to_string());
                }
            }
            publish::PublishTarget::GitHub
            | publish::PublishTarget::GitLab
            | publish::PublishTarget::Custom(_) => {}
        }
    }

    let already_published = checked_targets > 0 && existing_targets.len() == target_names.len();
    if !already_published && !existing_targets.is_empty() {
        return Err(LpmError::Registry(format!(
            "{}@{} already exists on {}; release publish cannot partially skip targets. Re-run with a narrower publish target.",
            name,
            version,
            existing_targets.join(", ")
        )));
    }

    Ok(PublishMember {
        idx,
        name,
        version,
        already_published,
    })
}

fn resolved_publish_target_names(
    manifest: &publish::PublishManifest,
    options: &ReleasePublishOptions,
) -> Result<Vec<(publish::PublishTarget, String)>, LpmError> {
    let targets = publish::resolve_targets(
        options.npm,
        options.lpm,
        options.github,
        options.gitlab,
        options.publish_registry.as_deref(),
        manifest.publish_config.as_ref(),
    )?;
    let mut names = publish::resolve_target_names(manifest, &targets)?;
    let mut out = Vec::with_capacity(targets.len());
    for target in targets {
        let resolved = names.remove(&target.key()).ok_or_else(|| {
            LpmError::Registry(format!("no name resolved for {}", target.display_name()))
        })?;
        out.push((target, resolved));
    }
    Ok(out)
}

fn build_plan(
    project_dir: &Path,
    selection: &ReleaseSelection,
    bump: Option<&VersionBump>,
) -> Result<ReleasePlan, LpmError> {
    let (workspace, graph, selected) = resolve_workspace_selection(project_dir, selection)?;
    let selected = release_plan::ensure_unique_selection(&selected);
    let change_bumps = release_plan::load_change_bumps(&workspace.root)?;
    let selected_set: HashSet<usize> = selected.iter().copied().collect();
    let sorted = release_plan::sorted_selected_indices(&graph, &selected_set)?;
    release_plan::plan_workspace(&workspace, &sorted, &change_bumps, bump)
}

fn resolve_workspace_selection(
    project_dir: &Path,
    selection: &ReleaseSelection,
) -> Result<
    (
        lpm_workspace::Workspace,
        lpm_task::graph::WorkspaceGraph,
        Vec<usize>,
    ),
    LpmError,
> {
    let workspace = lpm_workspace::discover_workspace(project_dir)
        .map_err(|error| LpmError::Workspace(error.to_string()))?
        .ok_or_else(|| {
            LpmError::Script("no workspace found. `lpm release` requires a monorepo.".into())
        })?;
    let graph = lpm_task::graph::WorkspaceGraph::from_workspace(&workspace);
    let selected_set: HashSet<usize> = if selection.all {
        (0..graph.len()).collect()
    } else if selection.affected
        || !selection.filter.is_empty()
        || !selection.filter_prod.is_empty()
    {
        workspace_select::select_workspace_target_set(
            &graph,
            &workspace.root,
            &selection.filter,
            &selection.filter_prod,
            &selection.changed_files_ignore_pattern,
            &selection.test_pattern,
            selection.affected,
            &selection.base,
        )?
    } else {
        return Err(LpmError::Script(
            "`lpm release` needs an explicit selection: pass --all, --affected, or --filter."
                .into(),
        ));
    };

    if selected_set.is_empty() && selection.fail_if_no_match {
        return Err(LpmError::Script(
            "no workspace packages matched the release selection (--fail-if-no-match)".into(),
        ));
    }
    Ok((workspace, graph, selected_set.into_iter().collect()))
}

fn emit_plan(plan: &ReleasePlan, dry_run: bool, json_output: bool) -> Result<(), LpmError> {
    if json_output {
        println!("{}", output::format_json_answer(&plan.to_json(dry_run))?);
        return Ok(());
    }
    if plan.packages.is_empty() {
        install_ui::done("release plan is empty");
        return Ok(());
    }
    for package in &plan.packages {
        install_ui::detail_untrusted(&format!(
            "{} {} -> {}",
            package.name, package.old_version, package.new_version
        ));
    }
    install_ui::done_untrusted(&format!("planned {} packages", plan.packages.len()));
    Ok(())
}

async fn lpm_version_exists(
    client: &RegistryClient,
    name: &str,
    version: &str,
) -> Result<bool, LpmError> {
    if !name.starts_with("@lpm.dev/") {
        return Ok(false);
    }
    let package_name = PackageName::parse(name)?;
    match client.get_package_metadata(&package_name).await {
        Ok(metadata) => Ok(metadata.versions.contains_key(version)),
        Err(err) if err.to_string().contains("not found") => Ok(false),
        Err(err) => Err(err),
    }
}

async fn npm_version_exists(
    client: &RegistryClient,
    name: &str,
    version: &str,
) -> Result<bool, LpmError> {
    match client.get_npm_package_metadata(name).await {
        Ok(metadata) => Ok(metadata.versions.contains_key(version)),
        Err(err) if is_not_found_error(&err) => Ok(false),
        Err(err) => Err(err),
    }
}

fn is_not_found_error(error: &LpmError) -> bool {
    let message = error.to_string();
    message.contains("not found") || message.contains("404")
}
