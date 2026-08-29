use crate::commands::{publish, publish_common};
use crate::install_ui;
use crate::output;
use crate::release_plan::{self, ReleasePlan};
use crate::workspace_select;
use futures::StreamExt;
use futures::stream::FuturesUnordered;
use lpm_common::LpmError;
use lpm_registry::RegistryClient;
use lpm_semver::VersionBump;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[cfg(any(debug_assertions, feature = "acceptance-test-hooks"))]
const RELEASE_WORKSPACE_DISCOVERY_MARKER_ENV: &str =
    "LPM_INTERNAL_TEST_RELEASE_WORKSPACE_DISCOVERY_MARKER";

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
    pub(crate) ignore_scripts: bool,
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

struct ReleasePublishMember {
    path: PathBuf,
    intent: publish::PublishIntent,
    publish_lifecycle: Option<Arc<publish::PublishLifecycle>>,
}

struct ReleasePublishWorkspace {
    member_paths_by_name: HashMap<String, PathBuf>,
    member_paths: Vec<PathBuf>,
    generation: lpm_workspace::PublishWorkspaceGeneration,
}

impl ReleasePublishWorkspace {
    fn from_snapshot(
        snapshot: lpm_workspace::Workspace,
        initial_root: &SelectedReleaseWorkspaceRoot,
    ) -> Result<Self, LpmError> {
        let mut member_paths_by_name = HashMap::with_capacity(snapshot.members.len());
        let mut member_paths = Vec::with_capacity(snapshot.members.len());
        for member in &snapshot.members {
            member_paths.push(member.path.clone());
            if let Some(name) = member.package.name.as_ref() {
                member_paths_by_name.insert(name.clone(), member.path.clone());
            }
        }
        let generation = lpm_workspace::capture_publish_workspace_generation_from_open_root(
            &initial_root.path,
            &initial_root.directory,
            &member_paths_by_name,
            &member_paths,
        )
        .map_err(|error| LpmError::Workspace(error.to_string()))?;
        Ok(Self {
            member_paths_by_name,
            member_paths,
            generation,
        })
    }
}

struct SelectedReleaseWorkspaceRoot {
    path: PathBuf,
    directory: cap_std::fs::Dir,
    identity: same_file::Handle,
}

impl SelectedReleaseWorkspaceRoot {
    fn from_open_project(
        project_path: &Path,
        project_directory: &cap_std::fs::Dir,
    ) -> Result<Self, LpmError> {
        let workspace =
            lpm_workspace::find_workspace_root_from_open_project(project_path, project_directory)
                .map_err(|error| LpmError::Workspace(error.to_string()))?
                .ok_or_else(|| {
                    LpmError::Script(
                        "no workspace found. `lpm release` requires a monorepo.".into(),
                    )
                })?;
        let (path, directory) = workspace.into_parts();
        Self::from_open_directory(path, directory)
    }

    fn from_open_directory(path: PathBuf, directory: cap_std::fs::Dir) -> Result<Self, LpmError> {
        let identity = same_file::Handle::from_file(
            directory.try_clone().map_err(LpmError::Io)?.into_std_file(),
        )
        .map_err(LpmError::Io)?;
        Ok(Self {
            path,
            directory,
            identity,
        })
    }

    fn try_clone(&self) -> Result<Self, LpmError> {
        let directory = self.directory.try_clone().map_err(LpmError::Io)?;
        let identity = same_file::Handle::from_file(
            directory.try_clone().map_err(LpmError::Io)?.into_std_file(),
        )
        .map_err(LpmError::Io)?;
        Ok(Self {
            path: self.path.clone(),
            directory,
            identity,
        })
    }

    fn validate_named_path(&self) -> Result<(), LpmError> {
        let current = publish_common::open_tarball_source_root(&self.path)?;
        let current_identity =
            same_file::Handle::from_file(current.into_std_file()).map_err(LpmError::Io)?;
        if current_identity != self.identity {
            return Err(LpmError::Script(format!(
                "release workspace root changed while waiting for the transaction lock: {}; retry the command",
                self.path.display()
            )));
        }
        Ok(())
    }

    fn discover(&self, start_dir: &Path) -> Result<lpm_workspace::Workspace, LpmError> {
        #[cfg(any(debug_assertions, feature = "acceptance-test-hooks"))]
        if let Some(marker_path) = std::env::var_os(RELEASE_WORKSPACE_DISCOVERY_MARKER_ENV) {
            use std::io::Write as _;

            let mut marker = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(marker_path)
                .map_err(LpmError::Io)?;
            marker.write_all(b"discover\n").map_err(LpmError::Io)?;
        }
        lpm_workspace::discover_workspace_from_open_root(&self.path, &self.directory, start_dir)
            .map_err(|error| LpmError::Workspace(error.to_string()))?
            .ok_or_else(|| {
                LpmError::Script("no workspace found. `lpm release` requires a monorepo.".into())
            })
    }
}

pub(crate) fn plan(
    project_dir: &Path,
    selection: &ReleaseSelection,
    bump: Option<&VersionBump>,
    json_output: bool,
) -> Result<(), LpmError> {
    let plan = build_plan_read_only(project_dir, selection, bump)?;
    emit_plan(&plan, true, json_output)
}

pub(crate) fn apply(
    project_dir: &Path,
    selection: &ReleaseSelection,
    bump: Option<&VersionBump>,
    dry_run: bool,
    json_output: bool,
) -> Result<(), LpmError> {
    if dry_run {
        return emit_plan(
            &build_plan_read_only(project_dir, selection, bump)?,
            true,
            json_output,
        );
    }

    let initial_workspace = discover_release_workspace(project_dir)?;
    let initial_root = initial_workspace
        .root
        .canonicalize()
        .map_err(LpmError::Io)?;
    let allowed_manifests = release_workspace_manifest_paths(&initial_workspace, true);
    let transaction_operation = release_apply_transaction_operation(selection, bump)?;
    let lock_path = lpm_common::project_install_lock(&initial_root);
    let plan = lpm_common::with_exclusive_lock(lock_path, || {
        if matches!(
            release_plan::recover_pending_operation_transaction(
                &initial_root,
                &allowed_manifests,
                &transaction_operation,
            )?,
            release_plan::ReleaseOperationRecoveryOutcome::Completed { .. }
        ) {
            return Ok(None);
        }
        let workspace = discover_release_workspace(project_dir)?;
        ensure_workspace_root_unchanged(&initial_root, &workspace.root)?;
        let plan = build_plan_for_workspace(&workspace, selection, bump)?;
        let planned = plan.planned_manifests()?;
        release_plan::write_planned_manifests(&workspace.root, &planned, transaction_operation)?;
        Ok(Some(plan))
    })?;
    match plan {
        Some(plan) => emit_plan(&plan, false, json_output),
        None if json_output => {
            println!(
                "{}",
                output::format_json_answer(&serde_json::json!({
                    "success": true,
                    "dry_run": false,
                    "recovered": true,
                }))?
            );
            Ok(())
        }
        None => {
            install_ui::done("Recovered completed release apply");
            Ok(())
        }
    }
}

fn release_apply_transaction_operation(
    selection: &ReleaseSelection,
    bump: Option<&VersionBump>,
) -> Result<release_plan::ReleaseTransactionOperation, LpmError> {
    let identity = serde_json::to_vec(&serde_json::json!({
        "all": selection.all,
        "affected": selection.affected,
        "base": selection.base,
        "filter": selection.filter,
        "filter_prod": selection.filter_prod,
        "changed_files_ignore_pattern": selection.changed_files_ignore_pattern,
        "test_pattern": selection.test_pattern,
        "fail_if_no_match": selection.fail_if_no_match,
        "bump": bump.map(VersionBump::as_str),
    }))?;
    Ok(release_plan::ReleaseTransactionOperation::new(
        release_plan::ReleaseTransactionOperationKind::ReleaseApply,
        &identity,
    ))
}

pub(crate) async fn publish(
    client: &RegistryClient,
    project_dir: &Path,
    selection: &ReleaseSelection,
    options: &ReleasePublishOptions,
    json_output: bool,
) -> Result<(), LpmError> {
    let project_source = publish::PublishSource::open(project_dir)?;
    let project_dir = project_source.project_dir().to_path_buf();
    let initial_root = SelectedReleaseWorkspaceRoot::from_open_project(
        &project_dir,
        &project_source.try_clone_directory()?,
    )?;
    let workspace = initial_root.discover(&project_dir)?;
    let allowed_manifests = release_workspace_manifest_paths(&workspace, true);
    let lock_directory = lpm_common::ProjectLockDirectory::open_or_create(
        &initial_root.directory,
        &initial_root.path,
    )?;
    let publication_lock_directory = lock_directory.try_clone()?;
    let transaction = async move {
        let members = plan_release_publish_under_workspace_lock(
            &project_dir,
            selection,
            options,
            json_output,
            initial_root.try_clone()?,
            allowed_manifests,
        )
        .await?;
        lpm_common::with_project_exclusive_lock_async(
            publication_lock_directory,
            lpm_common::ProjectLockKind::Publish,
            publish_intent_members(client, initial_root, members, options, json_output),
        )
        .await
    };
    if options.dry_run {
        lpm_common::with_project_shared_lock_async(
            lock_directory,
            lpm_common::ProjectLockKind::Install,
            transaction,
        )
        .await
    } else {
        lpm_common::with_project_exclusive_lock_async(
            lock_directory,
            lpm_common::ProjectLockKind::Install,
            transaction,
        )
        .await
    }
}

async fn plan_release_publish_under_workspace_lock(
    project_dir: &Path,
    selection: &ReleaseSelection,
    options: &ReleasePublishOptions,
    json_output: bool,
    initial_root: SelectedReleaseWorkspaceRoot,
    allowed_manifests: Vec<PathBuf>,
) -> Result<Vec<ReleasePublishMember>, LpmError> {
    initial_root.validate_named_path()?;
    if options.dry_run {
        release_plan::ensure_no_pending_release_transaction_from_open_root(
            &initial_root.path,
            &initial_root.directory,
        )?;
    } else {
        release_plan::recover_pending_release_transaction_from_open_root(
            &initial_root.path,
            &initial_root.directory,
            &allowed_manifests,
        )?;
    }
    let mut workspace = initial_root.discover(project_dir)?;
    let (graph, selected) = resolve_workspace_selection_for(&workspace, selection)?;
    release_plan::validate_workspace_internal_ranges(&workspace)?;
    let selected = release_plan::ensure_unique_selection(&selected);
    let selected_set: HashSet<usize> = selected.iter().copied().collect();
    let mut publish_order = release_plan::sorted_selected_indices(&graph, &selected_set)?;
    let planned_paths: HashSet<PathBuf> = publish_order
        .iter()
        .map(|index| workspace.members[*index].path.clone())
        .collect();
    let mut lifecycles = HashMap::with_capacity(publish_order.len());
    let mut has_lifecycle = false;
    for index in &publish_order {
        let member_path = &workspace.members[*index].path;
        let lifecycle = publish::PublishLifecycle::load_for_publish(
            member_path,
            options.yes,
            options.ignore_scripts,
            json_output,
        )?
        .map(Arc::new);
        if let Some(lifecycle) = &lifecycle {
            lifecycle.run_before_pack(member_path, json_output)?;
            has_lifecycle = true;
        }
        lifecycles.insert(member_path.clone(), lifecycle);
    }
    if has_lifecycle {
        workspace = initial_root.discover(project_dir)?;
        release_plan::validate_workspace_internal_ranges(&workspace)?;
        let (graph, selected) = resolve_workspace_selection_for(&workspace, selection)?;
        let selected = release_plan::ensure_unique_selection(&selected);
        let selected_set: HashSet<usize> = selected.iter().copied().collect();
        publish_order = release_plan::sorted_selected_indices(&graph, &selected_set)?;
        let current_paths: HashSet<PathBuf> = publish_order
            .iter()
            .map(|index| workspace.members[*index].path.clone())
            .collect();
        if current_paths != planned_paths {
            return Err(LpmError::Registry(
                "release workspace selection changed while running publish lifecycle scripts; retry the command"
                    .into(),
            ));
        }
    }
    let mut members = Vec::with_capacity(publish_order.len());
    for idx in publish_order {
        let member = &workspace.members[idx];
        let relative = member.path.strip_prefix(&initial_root.path).map_err(|_| {
            LpmError::Registry(format!(
                "release workspace member is outside the selected root: {}",
                member.path.display()
            ))
        })?;
        let directory = publish_common::open_cap_directory_path(&initial_root.directory, relative)?
            .ok_or_else(|| {
                LpmError::Registry(format!(
                    "release workspace member changed during publish preflight: {}",
                    member.path.display()
                ))
            })?;
        let source = publish::PublishSource::from_open_directory(member.path.clone(), directory)?;
        let intent = publish::plan_publish_intent_from_source(
            source,
            &workspace,
            options.npm,
            options.lpm,
            options.github,
            options.gitlab,
            options.publish_registry.as_deref(),
        )?;
        members.push(ReleasePublishMember {
            path: member.path.clone(),
            intent,
            publish_lifecycle: lifecycles.remove(&member.path).unwrap_or(None),
        });
    }
    Ok(members)
}

async fn publish_intent_members(
    client: &RegistryClient,
    initial_root: SelectedReleaseWorkspaceRoot,
    members: Vec<ReleasePublishMember>,
    options: &ReleasePublishOptions,
    json_output: bool,
) -> Result<(), LpmError> {
    validate_unique_publication_destinations(client, &members)?;
    let mut results = Vec::with_capacity(members.len());
    let has_npm_compatible_targets = members
        .iter()
        .any(|member| member.intent.has_npm_compatible_targets());
    let has_lpm_target = members.iter().any(|member| member.intent.has_lpm_target());
    let has_npm_target = members.iter().any(|member| member.intent.has_npm_target());
    let publish_clients = publish::ReleasePublishClients::new(
        has_npm_compatible_targets,
        has_lpm_target,
        has_npm_target,
        !options.dry_run,
    )?;
    let already_published = preflight_publish_members(client, &members, &publish_clients).await?;
    let workspace = refresh_release_publish_workspace(&initial_root, &members)?;

    for (index, (member, is_published)) in members.iter().zip(&already_published).enumerate() {
        let name = member.intent.package_name().to_string();
        let version = member.intent.package_version().to_string();
        if *is_published {
            if let Err(error) =
                validate_release_publish_member(&initial_root, &workspace, member, options)
            {
                let error_summary = release_publish_error_summary(&error);
                append_failed_and_unattempted_results(
                    &mut results,
                    member,
                    &members[index + 1..],
                    &error_summary,
                    &[],
                );
                emit_release_publish_results(&results, members.len(), options, json_output, false)?;
                return Err(LpmError::ExitCode(1));
            }
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

        let prepared = match prepare_release_publish_member(
            &initial_root,
            &workspace,
            member,
            options,
            json_output,
        )
        .await
        {
            Ok(prepared) => prepared,
            Err(error) => {
                let error_summary = release_publish_error_summary(&error);
                append_failed_and_unattempted_results(
                    &mut results,
                    member,
                    &members[index + 1..],
                    &error_summary,
                    &[],
                );
                emit_release_publish_results(&results, members.len(), options, json_output, false)?;
                return Err(LpmError::ExitCode(1));
            }
        };

        if options.dry_run {
            let lifecycle_result = member
                .publish_lifecycle
                .as_ref()
                .map_or(Ok(()), |lifecycle| {
                    lifecycle.run_after_publish(&member.path, json_output)
                });
            drop(prepared);
            if let Err(error) = lifecycle_result {
                let error_summary = release_publish_error_summary(&error);
                append_failed_and_unattempted_results(
                    &mut results,
                    member,
                    &members[index + 1..],
                    &error_summary,
                    &[],
                );
                emit_release_publish_results(&results, members.len(), options, json_output, false)?;
                return Err(LpmError::ExitCode(1));
            }
            results.push(serde_json::json!({
                "name": name,
                "version": version,
                "path": member.path,
                "status": "planned",
            }));
            continue;
        }

        let publish_result: Result<publish::PublishExecutionReport, LpmError> =
            publish::execute_prepared_for_release(client, prepared, &publish_clients).await;
        match publish_result {
            Ok(report) if report.success => {}
            Ok(report) => {
                let failure_summary = report.failure_summary();
                append_failed_and_unattempted_results(
                    &mut results,
                    member,
                    &members[index + 1..],
                    &failure_summary,
                    &report.results,
                );
                emit_release_publish_results(&results, members.len(), options, json_output, false)?;
                return Err(LpmError::ExitCode(1));
            }
            Err(error) => {
                let error_summary = release_publish_error_summary(&error);
                append_failed_and_unattempted_results(
                    &mut results,
                    member,
                    &members[index + 1..],
                    &error_summary,
                    &[],
                );
                emit_release_publish_results(&results, members.len(), options, json_output, false)?;
                return Err(LpmError::ExitCode(1));
            }
        }
        results.push(serde_json::json!({
            "name": name,
            "version": version,
            "path": member.path,
            "status": "published",
        }));
    }

    emit_release_publish_results(&results, members.len(), options, json_output, true)
}

fn append_failed_and_unattempted_results(
    results: &mut Vec<serde_json::Value>,
    failed: &ReleasePublishMember,
    remaining: &[ReleasePublishMember],
    error: &str,
    target_results: &[serde_json::Value],
) {
    let mut failed_result = serde_json::json!({
        "name": failed.intent.package_name(),
        "version": failed.intent.package_version(),
        "path": failed.path,
        "status": "failed",
        "error": error,
    });
    if !target_results.is_empty() {
        failed_result["targets"] = serde_json::Value::Array(target_results.to_vec());
    }
    results.push(failed_result);
    results.reserve(remaining.len());
    for member in remaining {
        results.push(serde_json::json!({
            "name": member.intent.package_name(),
            "version": member.intent.package_version(),
            "path": member.path,
            "status": "not_attempted",
            "reason": "a previous package failed",
        }));
    }
}

fn release_publish_error_summary(error: &LpmError) -> String {
    match error {
        LpmError::ExitCode(_) => "one or more publish targets failed".to_string(),
        error => lpm_common::sanitize_terminal_inline(&error.to_string())
            .chars()
            .take(500)
            .collect(),
    }
}

fn emit_release_publish_results(
    results: &[serde_json::Value],
    package_count: usize,
    options: &ReleasePublishOptions,
    json_output: bool,
    success: bool,
) -> Result<(), LpmError> {
    let uploaded = results.iter().any(|result| {
        result["status"] == "published"
            || result["targets"]
                .as_array()
                .is_some_and(|targets| targets.iter().any(|target| target["success"] == true))
    });
    let warning = (!success).then_some({
        if uploaded {
            "Publishing is not transactional. Successful uploads were not rolled back; retry only failed and not-attempted packages."
        } else {
            "Publishing stopped before all selected packages were processed; retry failed and not-attempted packages."
        }
    });
    let mut json = serde_json::json!({
        "success": success,
        "dry_run": options.dry_run,
        "packages": package_count,
        "results": results,
    });
    if let Some(warning) = warning {
        json["warning"] = serde_json::Value::String(warning.to_string());
    }
    if json_output {
        println!("{}", output::format_json_answer(&json)?);
    } else {
        if !success {
            for result in results.iter().filter(|result| result["status"] == "failed") {
                let name = result["name"].as_str().unwrap_or("package");
                let version = result["version"].as_str().unwrap_or("unknown");
                let error = result["error"].as_str().unwrap_or("publish failed");
                install_ui::failed_untrusted(&format!("{name}@{version}: {error}"));
            }
        }
        if let Some(warning) = warning {
            install_ui::warn_untrusted(warning);
        } else {
            install_ui::done_untrusted(&format!(
                "release publish processed {package_count} packages"
            ));
        }
    }
    Ok(())
}

fn refresh_release_publish_workspace(
    initial_root: &SelectedReleaseWorkspaceRoot,
    members: &[ReleasePublishMember],
) -> Result<ReleasePublishWorkspace, LpmError> {
    initial_root.validate_named_path()?;
    let workspace = initial_root.discover(&initial_root.path)?;
    release_plan::validate_workspace_internal_ranges(&workspace)?;
    let current_member_paths: HashSet<&Path> = workspace
        .members
        .iter()
        .map(|member| member.path.as_path())
        .collect();
    for member in members {
        if !current_member_paths.contains(member.path.as_path()) {
            return Err(LpmError::Registry(format!(
                "{} changed after release publish preflight; retry the command",
                member.path.display()
            )));
        }
    }
    ReleasePublishWorkspace::from_snapshot(workspace, initial_root)
}

fn current_release_publish_projection(
    initial_root: &SelectedReleaseWorkspaceRoot,
    workspace: &ReleasePublishWorkspace,
    member: &ReleasePublishMember,
    validate_workspace_generation: bool,
) -> Result<(lpm_workspace::Workspace, publish::PublishManifest), LpmError> {
    initial_root.validate_named_path()?;
    let relative = member.path.strip_prefix(&initial_root.path).map_err(|_| {
        LpmError::Registry(format!(
            "release workspace member is outside the selected root: {}",
            member.path.display()
        ))
    })?;
    let directory = publish_common::open_cap_directory_path(&initial_root.directory, relative)?
        .ok_or_else(|| {
            LpmError::Registry(format!(
                "release workspace member changed during publish: {}",
                member.path.display()
            ))
        })?;
    let source = publish::PublishSource::from_open_directory(member.path.clone(), directory)?;
    let publish_manifest =
        publish::select_publish_projection(publish::read_publish_manifest_from_source(source)?)?;
    let projection_context = lpm_workspace::PublishProjectionContext::new(
        &workspace.member_paths_by_name,
        &workspace.member_paths,
        &workspace.generation,
        validate_workspace_generation,
    );
    let projection = lpm_workspace::read_publish_projection_from_open_root(
        &initial_root.path,
        &initial_root.directory,
        &member.path,
        &publish_manifest.package_json_content,
        &projection_context,
    )
    .map_err(|error| LpmError::Workspace(error.to_string()))?;
    release_plan::validate_workspace_internal_ranges(&projection)?;
    Ok((projection, publish_manifest))
}

fn validate_release_publish_member(
    initial_root: &SelectedReleaseWorkspaceRoot,
    workspace: &ReleasePublishWorkspace,
    member: &ReleasePublishMember,
    options: &ReleasePublishOptions,
) -> Result<(), LpmError> {
    let (projection, publish_manifest) =
        current_release_publish_projection(initial_root, workspace, member, !options.dry_run)?;
    publish::validate_intent_with_workspace_lock_held(
        &member.path,
        &publish_manifest,
        &projection,
        &member.intent,
        options.npm,
        options.lpm,
        options.github,
        options.gitlab,
        options.publish_registry.as_deref(),
    )
}

async fn prepare_release_publish_member(
    initial_root: &SelectedReleaseWorkspaceRoot,
    workspace: &ReleasePublishWorkspace,
    member: &ReleasePublishMember,
    options: &ReleasePublishOptions,
    json_output: bool,
) -> Result<publish::PreparedPublish, LpmError> {
    let (projection, publish_manifest) =
        current_release_publish_projection(initial_root, workspace, member, !options.dry_run)?;
    let prepared = publish::prepare_intent_with_workspace_lock_held(
        &member.path,
        publish_manifest,
        &projection,
        &member.intent,
        options.dry_run,
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
    publish::finish_release_publish_preparation(
        prepared,
        member.publish_lifecycle.as_ref().map(Arc::clone),
        &member.path,
        json_output,
    )
}

const RELEASE_PREFLIGHT_CONCURRENCY: usize = 4;

async fn preflight_publish_members(
    client: &RegistryClient,
    members: &[ReleasePublishMember],
    clients: &publish::ReleasePublishClients,
) -> Result<Vec<bool>, LpmError> {
    let permit_limit = u32::try_from(RELEASE_PREFLIGHT_CONCURRENCY)
        .map_err(|_| LpmError::Registry("release preflight concurrency is invalid".into()))?;
    let permits = tokio::sync::Semaphore::new(RELEASE_PREFLIGHT_CONCURRENCY);
    let mut jobs = members
        .iter()
        .enumerate()
        .flat_map(|(member_index, member)| {
            (0..member.intent.preflight_target_count())
                .map(move |target_index| (member_index, target_index, member))
        })
        .enumerate();
    let mut in_flight = FuturesUnordered::new();
    for _ in 0..RELEASE_PREFLIGHT_CONCURRENCY {
        let Some((job_index, (member_index, target_index, member))) = jobs.next() else {
            break;
        };
        in_flight.push(run_release_preflight_job(
            job_index,
            member_index,
            target_index,
            member,
            client,
            clients,
            &permits,
            permit_limit,
        ));
    }

    let mut checked_targets = vec![0usize; members.len()];
    let mut existing_targets = vec![Vec::new(); members.len()];
    let mut already_published = vec![false; members.len()];
    let mut ordered_outcomes = BTreeMap::new();
    let mut next_ordered_job = 0usize;
    let mut earliest_observed_error = None;

    while let Some((job_index, member_index, outcome)) = in_flight.next().await {
        if outcome.is_err() {
            earliest_observed_error = Some(
                earliest_observed_error
                    .map_or(job_index, |earliest: usize| earliest.min(job_index)),
            );
        }
        ordered_outcomes.insert(job_index, (member_index, outcome));

        while let Some((member_index, outcome)) = ordered_outcomes.remove(&next_ordered_job) {
            let outcome = outcome?;
            checked_targets[member_index] += 1;
            if outcome.version_exists {
                existing_targets[member_index].push(outcome.target_display);
            }
            if checked_targets[member_index]
                == members[member_index].intent.preflight_target_count()
            {
                let existing = &existing_targets[member_index];
                let all_exist = existing.len() == checked_targets[member_index];
                if !all_exist && !existing.is_empty() {
                    let member = &members[member_index];
                    return Err(LpmError::Registry(format!(
                        "{}@{} already exists on {}; release publish cannot partially skip targets. Re-run with a narrower publish target.",
                        member.intent.package_name(),
                        member.intent.package_version(),
                        existing.join(", ")
                    )));
                }
                already_published[member_index] = all_exist;
            }
            next_ordered_job += 1;
        }

        while in_flight.len() < RELEASE_PREFLIGHT_CONCURRENCY {
            let Some((job_index, (member_index, target_index, member))) = jobs.next() else {
                break;
            };
            if earliest_observed_error.is_some_and(|error_index| job_index > error_index) {
                break;
            }
            in_flight.push(run_release_preflight_job(
                job_index,
                member_index,
                target_index,
                member,
                client,
                clients,
                &permits,
                permit_limit,
            ));
        }
    }
    Ok(already_published)
}

#[allow(clippy::too_many_arguments)]
async fn run_release_preflight_job(
    job_index: usize,
    member_index: usize,
    target_index: usize,
    member: &ReleasePublishMember,
    client: &RegistryClient,
    clients: &publish::ReleasePublishClients,
    permits: &tokio::sync::Semaphore,
    permit_limit: u32,
) -> (
    usize,
    usize,
    Result<publish::PublishTargetPreflight, LpmError>,
) {
    let outcome = member
        .intent
        .preflight_target(target_index, client, clients, permits, permit_limit)
        .await;
    (job_index, member_index, outcome)
}

fn validate_unique_publication_destinations(
    client: &RegistryClient,
    members: &[ReleasePublishMember],
) -> Result<(), LpmError> {
    let mut destinations = HashMap::new();
    for member in members {
        for (protocol, endpoint, name, version) in
            member.intent.publication_coordinates(client.base_url())
        {
            let endpoint = normalize_publication_endpoint(endpoint)?;
            let coordinate = (protocol.to_string(), endpoint, name.to_string());
            if let Some((previous_path, previous_version)) =
                destinations.insert(coordinate, (&member.path, version))
            {
                let detail = if previous_version == version {
                    format!("the same publication destination for {name}@{version}")
                } else {
                    format!(
                        "the same remote package {name} at different versions ({previous_version} and {version})"
                    )
                };
                return Err(LpmError::Registry(format!(
                    "{} and {} resolve to {detail}",
                    previous_path.display(),
                    member.path.display()
                )));
            }
        }
    }
    Ok(())
}

fn normalize_publication_endpoint(endpoint: &str) -> Result<String, LpmError> {
    let mut parsed = reqwest::Url::parse(endpoint).map_err(|error| {
        LpmError::Registry(format!("invalid publish registry endpoint: {error}"))
    })?;
    let normalized_path = canonicalize_url_path(parsed.path());
    let normalized_path = normalized_path.trim_end_matches('/');
    parsed.set_path(if normalized_path.is_empty() {
        "/"
    } else {
        normalized_path
    });
    Ok(parsed.as_str().trim_end_matches('/').to_string())
}

fn canonicalize_url_path(path: &str) -> String {
    let bytes = path.as_bytes();
    let mut normalized = String::with_capacity(path.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%'
            && index + 2 < bytes.len()
            && let (Some(high), Some(low)) =
                (hex_value(bytes[index + 1]), hex_value(bytes[index + 2]))
        {
            let decoded = (high << 4) | low;
            if decoded.is_ascii_alphanumeric() || matches!(decoded, b'-' | b'.' | b'_' | b'~') {
                normalized.push(char::from(decoded));
            } else {
                const HEX: &[u8; 16] = b"0123456789ABCDEF";
                normalized.push('%');
                normalized.push(char::from(HEX[usize::from(high)]));
                normalized.push(char::from(HEX[usize::from(low)]));
            }
            index += 3;
            continue;
        }
        normalized.push(char::from(bytes[index]));
        index += 1;
    }
    normalized
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn build_plan_read_only(
    project_dir: &Path,
    selection: &ReleaseSelection,
    bump: Option<&VersionBump>,
) -> Result<ReleasePlan, LpmError> {
    let initial_workspace = discover_release_workspace(project_dir)?;
    let initial_root = initial_workspace
        .root
        .canonicalize()
        .map_err(LpmError::Io)?;
    let lock_path = lpm_common::project_install_lock(&initial_root);
    lpm_common::with_shared_lock(lock_path, || {
        release_plan::ensure_no_pending_release_transaction(&initial_root)?;
        let workspace = discover_release_workspace(project_dir)?;
        ensure_workspace_root_unchanged(&initial_root, &workspace.root)?;
        build_plan_for_workspace(&workspace, selection, bump)
    })
}

pub(crate) fn release_workspace_manifest_paths(
    workspace: &lpm_workspace::Workspace,
    include_root: bool,
) -> Vec<PathBuf> {
    let mut manifests = Vec::with_capacity(workspace.members.len() + usize::from(include_root));
    if include_root {
        manifests.push(workspace.root.join("package.json"));
    }
    manifests.extend(
        workspace
            .members
            .iter()
            .map(|member| member.path.join("package.json")),
    );
    manifests
}

fn ensure_workspace_root_unchanged(expected: &Path, actual: &Path) -> Result<(), LpmError> {
    let actual = actual.canonicalize().map_err(LpmError::Io)?;
    if actual != expected {
        return Err(LpmError::Script(format!(
            "release workspace root changed while waiting for the transaction lock ({} -> {}); retry the command",
            expected.display(),
            actual.display()
        )));
    }
    Ok(())
}

fn build_plan_for_workspace(
    workspace: &lpm_workspace::Workspace,
    selection: &ReleaseSelection,
    bump: Option<&VersionBump>,
) -> Result<ReleasePlan, LpmError> {
    let (graph, selected) = resolve_workspace_selection_for(workspace, selection)?;
    let selected = release_plan::ensure_unique_selection(&selected);
    let change_bumps = release_plan::load_change_bumps(&workspace.root)?;
    let selected_set: HashSet<usize> = selected.iter().copied().collect();
    let sorted = release_plan::sorted_selected_indices(&graph, &selected_set)?;
    release_plan::plan_workspace(workspace, &sorted, &change_bumps, bump)
}

fn discover_release_workspace(project_dir: &Path) -> Result<lpm_workspace::Workspace, LpmError> {
    let workspace = lpm_workspace::discover_workspace(project_dir)
        .map_err(|error| LpmError::Workspace(error.to_string()))?
        .ok_or_else(|| {
            LpmError::Script("no workspace found. `lpm release` requires a monorepo.".into())
        })?;
    Ok(workspace)
}

fn resolve_workspace_selection_for(
    workspace: &lpm_workspace::Workspace,
    selection: &ReleaseSelection,
) -> Result<(lpm_task::graph::WorkspaceGraph, Vec<usize>), LpmError> {
    let graph = lpm_task::graph::WorkspaceGraph::from_workspace(workspace);
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
    Ok((graph, selected_set.into_iter().collect()))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn publication_endpoint_normalization_decodes_unreserved_path_bytes() {
        let plain = normalize_publication_endpoint("https://registry.example.test/npm").unwrap();
        let encoded_lower =
            normalize_publication_endpoint("https://registry.example.test/%6epm").unwrap();
        let encoded_upper =
            normalize_publication_endpoint("https://registry.example.test/%6Epm").unwrap();

        assert_eq!(encoded_lower, plain);
        assert_eq!(encoded_upper, plain);
    }

    #[test]
    fn release_workspace_selection_keeps_the_opened_generation_after_same_path_replacement() {
        let temp = tempfile::tempdir().unwrap();
        let selected = temp.path().join("workspace");
        let displaced = temp.path().join("displaced");
        let project = selected.join("packages/app");
        std::fs::create_dir_all(&project).unwrap();
        std::fs::write(
            selected.join("package.json"),
            r#"{"name":"original","workspaces":["packages/*"]}"#,
        )
        .unwrap();
        std::fs::write(
            project.join("package.json"),
            r#"{"name":"original-app","version":"1.0.0"}"#,
        )
        .unwrap();
        let selected = selected.canonicalize().unwrap();
        let project = project.canonicalize().unwrap();
        let project_source = publish::PublishSource::open(&project).unwrap();
        let root = SelectedReleaseWorkspaceRoot::from_open_project(
            &project,
            &project_source.try_clone_directory().unwrap(),
        )
        .unwrap();

        std::fs::rename(&selected, &displaced).unwrap();
        std::fs::create_dir_all(&project).unwrap();
        std::fs::write(
            selected.join("package.json"),
            r#"{"name":"replacement","workspaces":["packages/*"]}"#,
        )
        .unwrap();
        std::fs::write(
            project.join("package.json"),
            r#"{"name":"replacement-app","version":"9.9.9"}"#,
        )
        .unwrap();

        let rediscovered = root.discover(&project).unwrap();

        assert_eq!(rediscovered.root_package.name.as_deref(), Some("original"));
    }

    #[test]
    fn release_workspace_identity_rejects_same_path_replacement() {
        let temp = tempfile::tempdir().unwrap();
        let selected = temp.path().join("workspace");
        let displaced = temp.path().join("displaced");
        std::fs::create_dir(&selected).unwrap();
        let selected = selected.canonicalize().unwrap();
        let directory = publish_common::open_tarball_source_root(&selected).unwrap();
        let initial_root =
            SelectedReleaseWorkspaceRoot::from_open_directory(selected.clone(), directory).unwrap();
        std::fs::rename(&selected, &displaced).unwrap();
        std::fs::create_dir(&selected).unwrap();

        let error = initial_root
            .validate_named_path()
            .expect_err("same-path replacement must change the workspace identity")
            .to_string();

        assert!(error.contains("changed"), "{error}");
    }
}
