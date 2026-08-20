use super::npm_artifact::prepare_npm_target_artifact;
use super::output::{
    DryRunSummary, format_lpm_publication_notice, format_multi_publish_partial_summary,
    format_multi_publish_success_summary, format_publish_retry_detail,
    format_single_publish_success_summary, format_upload_message, lpm_visibility,
    print_dry_run_summary, print_upload_details, publish_check_json, publish_detail,
    publish_result_json, visibility_from_access,
};
use super::prepare::{
    PublishSource, prepare_publish_project_from_manifest, read_publish_manifest,
    read_publish_manifest_from_source, validate_publish_tarball_size,
};
use super::provenance::{
    ProvenanceRequest, load_provenance_request_file, materialize_provenance_request,
    resolve_provenance_request_from_project_source,
};
use super::quality_gate::run_publish_quality_gate;
use super::secret_scan::run_publish_secret_scan;
use super::skills::{ManifestWriteMode, compute_published_skills_digest, ensure_lpm_in_files};
use super::target::resolve_targets;
use super::types::{
    LpmPublicationStatus, NpmTargetArtifact, NpmTargetArtifactInput, PublicationWaitResult,
    PublishProject, PublishQualityGateInput, PublishResult, PublishTarget, ResolvedProvenance,
};
use super::upload_lpm::publish_to_lpm;
use super::version_data::{build_publish_version_data, integrity_to_sha512_hex};
use super::wait::{DEFAULT_PUBLICATION_WAIT_TIMEOUT, wait_for_lpm_publication_with_oidc};
use crate::commands::skills::author;
use crate::commands::{npm_auth, publish_common, publish_npm};
use crate::{auth, install_ui, oidc, provenance, sigstore};
use lpm_common::LpmError;
use lpm_registry::RegistryClient;
use sha2::{Digest as _, Sha256};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

struct NpmFilePreflightInput<'a> {
    provenance_request: &'a ProvenanceRequest,
    targets: &'a [PublishTarget],
    target_names: &'a HashMap<String, String>,
    package_json_name: &'a str,
    version: &'a str,
    version_data: &'a serde_json::Value,
    tarball_data: &'a std::sync::Arc<Vec<u8>>,
    tarball_hashes: &'a std::sync::Arc<publish_common::TarballHashes>,
    rewritten_tarballs: &'a HashMap<String, publish_common::RewrittenTarball>,
    json_output: bool,
}

struct PublishTransactionRoot {
    path: PathBuf,
    directory: cap_std::fs::Dir,
    identity: same_file::Handle,
}

impl PublishTransactionRoot {
    #[inline]
    fn path(&self) -> &Path {
        &self.path
    }
}

pub(crate) struct PreparedPublish {
    publish_started: std::time::Instant,
    dry_run: bool,
    check_only: bool,
    wait_for_publication: bool,
    otp: Option<String>,
    yes: bool,
    json_output: bool,
    targets: Vec<PublishTarget>,
    targets_lpm: bool,
    publication_wait_timeout: Option<std::time::Duration>,
    target_names: HashMap<String, String>,
    has_skills: bool,
    local_skills_digest: Option<String>,
    pkg_json: serde_json::Value,
    name: String,
    version: String,
    publish_config: Option<lpm_runner::lpm_json::PublishConfig>,
    readme: Option<String>,
    tarball_data: std::sync::Arc<Vec<u8>>,
    tarball_hashes: std::sync::Arc<publish_common::TarballHashes>,
    tarball_files: Vec<publish_common::TarballFile>,
    tarball_size: usize,
    lpm_config: Option<serde_json::Value>,
    detected_ecosystem: String,
    swift_manifest: Option<serde_json::Value>,
    provenance_request: ProvenanceRequest,
    rewritten_tarballs: HashMap<String, publish_common::RewrittenTarball>,
    version_data: serde_json::Value,
    precomputed_npm_artifacts: HashMap<String, NpmTargetArtifact>,
    quality_result: Option<crate::quality::QualityResult>,
}

pub(crate) struct PublishExecutionReport {
    pub(crate) success: bool,
    pub(crate) results: Vec<serde_json::Value>,
    json_output: bool,
    any_upload_failed: bool,
    any_publication_failed: bool,
}

impl PublishExecutionReport {
    fn successful(json_output: bool) -> Self {
        Self {
            success: true,
            results: Vec::new(),
            json_output,
            any_upload_failed: false,
            any_publication_failed: false,
        }
    }

    fn into_command_result(self) -> Result<(), LpmError> {
        if self.success {
            return Ok(());
        }
        if self.json_output {
            Err(LpmError::ExitCode(1))
        } else if self.any_upload_failed {
            Err(LpmError::Registry(
                "one or more publish targets failed".into(),
            ))
        } else if self.any_publication_failed {
            Err(LpmError::Registry(
                "the upload succeeded, but LPM.dev Registry publication was not confirmed; do not publish the same version again"
                    .into(),
            ))
        } else {
            Ok(())
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ResolvedPublishTarget {
    target: PublishTarget,
    name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PublishIntent {
    project_directory_identity: std::sync::Arc<same_file::Handle>,
    package_name: String,
    package_version: String,
    package_manifest_fingerprint: [u8; 32],
    projected_manifest_fingerprint: [u8; 32],
    publish_config_fingerprint: [u8; 32],
    targets: Vec<ResolvedPublishTarget>,
}

impl PublishIntent {
    pub(crate) fn package_name(&self) -> &str {
        &self.package_name
    }

    pub(crate) fn package_version(&self) -> &str {
        &self.package_version
    }

    pub(crate) fn resolved_targets(&self) -> impl Iterator<Item = (&PublishTarget, &str)> {
        self.targets
            .iter()
            .map(|target| (&target.target, target.name.as_str()))
    }
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
pub(crate) fn plan_publish_intent(
    project_dir: &Path,
    workspace: &lpm_workspace::Workspace,
    cli_npm: bool,
    cli_lpm: bool,
    cli_github: bool,
    cli_gitlab: bool,
    cli_registry: Option<&str>,
) -> Result<PublishIntent, LpmError> {
    let manifest = read_publish_manifest(project_dir)?;
    publish_intent_from_manifest(
        &manifest,
        workspace,
        cli_npm,
        cli_lpm,
        cli_github,
        cli_gitlab,
        cli_registry,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn plan_publish_intent_from_source(
    source: PublishSource,
    workspace: &lpm_workspace::Workspace,
    cli_npm: bool,
    cli_lpm: bool,
    cli_github: bool,
    cli_gitlab: bool,
    cli_registry: Option<&str>,
) -> Result<PublishIntent, LpmError> {
    let manifest = read_publish_manifest_from_source(source)?;
    publish_intent_from_manifest(
        &manifest,
        workspace,
        cli_npm,
        cli_lpm,
        cli_github,
        cli_gitlab,
        cli_registry,
    )
}

#[allow(clippy::too_many_arguments)]
fn publish_intent_from_manifest(
    manifest: &super::prepare::PublishManifest,
    workspace: &lpm_workspace::Workspace,
    cli_npm: bool,
    cli_lpm: bool,
    cli_github: bool,
    cli_gitlab: bool,
    cli_registry: Option<&str>,
) -> Result<PublishIntent, LpmError> {
    let (targets, target_names) = resolve_publish_targets(
        manifest,
        cli_npm,
        cli_lpm,
        cli_github,
        cli_gitlab,
        cli_registry,
    )?;
    let mut resolved_targets = Vec::with_capacity(targets.len());
    for target in targets {
        let key = target.key();
        let name = target_names.get(&key).cloned().ok_or_else(|| {
            LpmError::Registry(format!("no name resolved for {}", target.display_name()))
        })?;
        resolved_targets.push(ResolvedPublishTarget { target, name });
    }
    let publish_config = serde_json::to_vec(&manifest.publish_config).map_err(|error| {
        LpmError::Registry(format!("failed to fingerprint publish config: {error}"))
    })?;
    let projected_manifest_fingerprint = projected_manifest_fingerprint(manifest, workspace)?;
    Ok(PublishIntent {
        project_directory_identity: std::sync::Arc::clone(&manifest.package_json_parent_identity),
        package_name: manifest.name.clone(),
        package_version: manifest.version.clone(),
        package_manifest_fingerprint: Sha256::digest(manifest.package_json_content.as_bytes())
            .into(),
        projected_manifest_fingerprint,
        publish_config_fingerprint: Sha256::digest(&publish_config).into(),
        targets: resolved_targets,
    })
}

#[allow(clippy::too_many_arguments)]
pub(super) fn validate_publish_intent(
    project_dir: &Path,
    manifest: &super::prepare::PublishManifest,
    workspace: &lpm_workspace::Workspace,
    expected: &PublishIntent,
    cli_npm: bool,
    cli_lpm: bool,
    cli_github: bool,
    cli_gitlab: bool,
    cli_registry: Option<&str>,
) -> Result<(), LpmError> {
    let actual = publish_intent_from_manifest(
        manifest,
        workspace,
        cli_npm,
        cli_lpm,
        cli_github,
        cli_gitlab,
        cli_registry,
    )?;
    if actual != *expected {
        let subject = if actual.package_manifest_fingerprint
            == expected.package_manifest_fingerprint
            && actual.projected_manifest_fingerprint != expected.projected_manifest_fingerprint
        {
            "workspace or catalog dependency projection"
        } else {
            "publish inputs"
        };
        return Err(LpmError::Registry(format!(
            "{subject} for {} changed after release publish preflight; retry the command",
            project_dir.display(),
        )));
    }
    Ok(())
}

fn projected_manifest_fingerprint(
    manifest: &super::prepare::PublishManifest,
    workspace: &lpm_workspace::Workspace,
) -> Result<[u8; 32], LpmError> {
    let source = manifest.package_json_content.as_bytes();
    let projected = publish_common::rewrite_workspace_deps_in_package_json(source, workspace)?;
    Ok(match projected {
        Some(bytes) => Sha256::digest(bytes).into(),
        None => Sha256::digest(source).into(),
    })
}

#[allow(clippy::too_many_arguments)]
fn resolve_publish_targets(
    manifest: &super::prepare::PublishManifest,
    cli_npm: bool,
    cli_lpm: bool,
    cli_github: bool,
    cli_gitlab: bool,
    cli_registry: Option<&str>,
) -> Result<(Vec<PublishTarget>, HashMap<String, String>), LpmError> {
    let targets = resolve_targets(
        cli_npm,
        cli_lpm,
        cli_github,
        cli_gitlab,
        cli_registry,
        manifest.publish_config.as_ref(),
    )?;
    const MAX_REGISTRIES: usize = 5;
    if targets.len() > MAX_REGISTRIES {
        return Err(LpmError::Registry(format!(
            "too many target registries ({}, max {MAX_REGISTRIES})",
            targets.len()
        )));
    }
    let target_names = resolve_target_names(manifest, &targets)?;
    Ok((targets, target_names))
}

#[allow(clippy::too_many_arguments)]
pub async fn run(
    client: &RegistryClient,
    project_dir: &Path,
    dry_run: bool,
    check_only: bool,
    wait_for_publication: bool,
    wait_timeout_seconds: Option<u64>,
    otp: Option<&str>,
    yes: bool,
    json_output: bool,
    min_score: Option<u32>,
    allow_secrets: bool,
    cli_npm: bool,
    cli_lpm: bool,
    cli_github: bool,
    cli_gitlab: bool,
    cli_registry: Option<&str>,
    provenance_flag: bool,
    no_provenance: bool,
    provenance_file: Option<&Path>,
) -> Result<(), LpmError> {
    let publish_source = PublishSource::open(project_dir)?;
    let project_dir = publish_source.project_dir().to_path_buf();
    let transaction_root = select_publish_transaction_root(&project_dir, &publish_source)?;
    let prepare = async {
        ensure_publish_transaction_root_unchanged(
            &project_dir,
            &publish_source,
            &transaction_root,
        )?;
        publish_source.validate_named_project_root()?;
        if dry_run || check_only {
            crate::release_plan::ensure_no_pending_release_transaction_from_open_root(
                transaction_root.path(),
                &transaction_root.directory,
            )?;
        } else if crate::release_plan::has_release_transaction_from_open_root(
            transaction_root.path(),
            &transaction_root.directory,
        )? {
            let workspace = lpm_workspace::discover_workspace_from_open_root(
                transaction_root.path(),
                &transaction_root.directory,
                transaction_root.path(),
            )
            .map_err(|error| LpmError::Workspace(error.to_string()))?;
            let allowed_manifests = workspace.map_or_else(
                || vec![transaction_root.path().join("package.json")],
                |workspace| {
                    crate::commands::release::release_workspace_manifest_paths(&workspace, true)
                },
            );
            crate::release_plan::recover_pending_release_transaction_from_open_root(
                transaction_root.path(),
                &transaction_root.directory,
                &allowed_manifests,
            )?;
        }
        prepare_with_workspace_lock_held(
            &project_dir,
            publish_source,
            dry_run,
            check_only,
            wait_for_publication,
            wait_timeout_seconds,
            otp,
            yes,
            json_output,
            min_score,
            allow_secrets,
            cli_npm,
            cli_lpm,
            cli_github,
            cli_gitlab,
            cli_registry,
            provenance_flag,
            no_provenance,
            provenance_file,
        )
        .await
    };
    let lock_directory = open_publish_lock_directory(&transaction_root)?;
    let publication_lock_directory = lock_directory.try_clone()?;
    let prepared =
        with_publish_install_lock(lock_directory, dry_run || check_only, prepare).await?;
    if check_only {
        return execute_prepared(client, prepared).await;
    }
    with_publish_publication_lock(
        publication_lock_directory,
        execute_prepared(client, prepared),
    )
    .await
}

fn open_publish_lock_directory(
    transaction_root: &PublishTransactionRoot,
) -> Result<lpm_common::ProjectLockDirectory, LpmError> {
    lpm_common::ProjectLockDirectory::open_or_create(
        &transaction_root.directory,
        transaction_root.path(),
    )
}

async fn with_publish_install_lock<R>(
    lock_directory: lpm_common::ProjectLockDirectory,
    shared: bool,
    body: impl std::future::Future<Output = Result<R, LpmError>>,
) -> Result<R, LpmError> {
    if shared {
        lpm_common::with_project_shared_lock_async(
            lock_directory,
            lpm_common::ProjectLockKind::Install,
            body,
        )
        .await
    } else {
        lpm_common::with_project_exclusive_lock_async(
            lock_directory,
            lpm_common::ProjectLockKind::Install,
            body,
        )
        .await
    }
}

async fn with_publish_publication_lock<R>(
    lock_directory: lpm_common::ProjectLockDirectory,
    body: impl std::future::Future<Output = Result<R, LpmError>>,
) -> Result<R, LpmError> {
    lpm_common::with_project_exclusive_lock_async(
        lock_directory,
        lpm_common::ProjectLockKind::Publish,
        body,
    )
    .await
}

fn select_publish_transaction_root(
    project_dir: &Path,
    publish_source: &PublishSource,
) -> Result<PublishTransactionRoot, LpmError> {
    publish_source.validate_named_project_root()?;
    let project_directory = publish_source.try_clone_directory()?;
    let workspace =
        lpm_workspace::find_workspace_root_from_open_project(project_dir, &project_directory)
            .map_err(|error| LpmError::Workspace(error.to_string()))?;
    let (path, directory) = workspace.map_or_else(
        || (project_dir.to_path_buf(), project_directory),
        lpm_workspace::OpenWorkspaceRoot::into_parts,
    );
    let identity =
        same_file::Handle::from_file(directory.try_clone().map_err(LpmError::Io)?.into_std_file())
            .map_err(LpmError::Io)?;
    Ok(PublishTransactionRoot {
        path,
        directory,
        identity,
    })
}

fn ensure_publish_transaction_root_unchanged(
    project_dir: &Path,
    publish_source: &PublishSource,
    expected: &PublishTransactionRoot,
) -> Result<(), LpmError> {
    let current = select_publish_transaction_root(project_dir, publish_source)?;
    if current.path != expected.path || current.identity != expected.identity {
        return Err(LpmError::Registry(format!(
            "publish project scope changed while waiting for the transaction lock ({} -> {}); retry the command",
            expected.path.display(),
            current.path.display()
        )));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn prepare_with_workspace_lock_held(
    project_dir: &Path,
    publish_source: PublishSource,
    dry_run: bool,
    check_only: bool,
    wait_for_publication: bool,
    wait_timeout_seconds: Option<u64>,
    otp: Option<&str>,
    yes: bool,
    json_output: bool,
    min_score: Option<u32>,
    allow_secrets: bool,
    cli_npm: bool,
    cli_lpm: bool,
    cli_github: bool,
    cli_gitlab: bool,
    cli_registry: Option<&str>,
    provenance_flag: bool,
    no_provenance: bool,
    provenance_file: Option<&Path>,
) -> Result<PreparedPublish, LpmError> {
    let publish_manifest = read_publish_manifest_from_source(publish_source)?;
    let workspace = super::prepare::discover_workspace_for_publish(project_dir, &publish_manifest)?;
    prepare_publish_manifest_with_workspace_lock_held(
        project_dir,
        publish_manifest,
        workspace.as_ref(),
        dry_run,
        check_only,
        wait_for_publication,
        wait_timeout_seconds,
        otp,
        yes,
        json_output,
        min_score,
        allow_secrets,
        cli_npm,
        cli_lpm,
        cli_github,
        cli_gitlab,
        cli_registry,
        provenance_flag,
        no_provenance,
        provenance_file,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn prepare_intent_with_workspace_lock_held(
    project_dir: &Path,
    workspace: &lpm_workspace::Workspace,
    intent: &PublishIntent,
    dry_run: bool,
    check_only: bool,
    wait_for_publication: bool,
    wait_timeout_seconds: Option<u64>,
    otp: Option<&str>,
    yes: bool,
    json_output: bool,
    min_score: Option<u32>,
    allow_secrets: bool,
    cli_npm: bool,
    cli_lpm: bool,
    cli_github: bool,
    cli_gitlab: bool,
    cli_registry: Option<&str>,
    provenance_flag: bool,
    no_provenance: bool,
    provenance_file: Option<&Path>,
) -> Result<PreparedPublish, LpmError> {
    let publish_manifest = read_publish_manifest(project_dir)?;
    validate_publish_intent(
        project_dir,
        &publish_manifest,
        workspace,
        intent,
        cli_npm,
        cli_lpm,
        cli_github,
        cli_gitlab,
        cli_registry,
    )?;
    prepare_publish_manifest_with_workspace_lock_held(
        project_dir,
        publish_manifest,
        Some(workspace),
        dry_run,
        check_only,
        wait_for_publication,
        wait_timeout_seconds,
        otp,
        yes,
        json_output,
        min_score,
        allow_secrets,
        cli_npm,
        cli_lpm,
        cli_github,
        cli_gitlab,
        cli_registry,
        provenance_flag,
        no_provenance,
        provenance_file,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn prepare_publish_manifest_with_workspace_lock_held(
    project_dir: &Path,
    publish_manifest: super::prepare::PublishManifest,
    workspace: Option<&lpm_workspace::Workspace>,
    dry_run: bool,
    check_only: bool,
    wait_for_publication: bool,
    wait_timeout_seconds: Option<u64>,
    otp: Option<&str>,
    yes: bool,
    json_output: bool,
    min_score: Option<u32>,
    allow_secrets: bool,
    cli_npm: bool,
    cli_lpm: bool,
    cli_github: bool,
    cli_gitlab: bool,
    cli_registry: Option<&str>,
    provenance_flag: bool,
    no_provenance: bool,
    provenance_file: Option<&Path>,
) -> Result<PreparedPublish, LpmError> {
    let publish_started = std::time::Instant::now();
    let mut publish_manifest = publish_manifest;
    let (targets, target_names) = resolve_publish_targets(
        &publish_manifest,
        cli_npm,
        cli_lpm,
        cli_github,
        cli_gitlab,
        cli_registry,
    )?;

    let targets_lpm = targets.contains(&PublishTarget::Lpm);
    if wait_for_publication && !targets_lpm {
        return Err(LpmError::Registry(
            "--wait requires publishing to the LPM registry".into(),
        ));
    }
    let publication_wait_timeout = wait_for_publication.then(|| {
        wait_timeout_seconds.map_or(
            DEFAULT_PUBLICATION_WAIT_TIMEOUT,
            std::time::Duration::from_secs,
        )
    });
    let validated_skills = {
        let validation =
            author::validate_publish_directory(&publish_manifest.package_json_parent, project_dir)?;

        if !validation.security_issues.is_empty() {
            for located in &validation.security_issues {
                let issue = &located.issue;
                install_ui::warn_untrusted(&format!(
                    "Skill security: {} — {} at line {} ({})",
                    lpm_common::sanitize_terminal_inline(&located.path),
                    lpm_common::sanitize_terminal_inline(&issue.category),
                    issue.line_number,
                    lpm_common::sanitize_terminal_inline(&issue.rule_id)
                ));
            }
            return Err(LpmError::Registry(
                "skills contain blocked security patterns".into(),
            ));
        }

        if !validation.errors.is_empty() {
            for error in &validation.errors {
                install_ui::warn_untrusted(&lpm_common::sanitize_terminal_inline(error));
            }
            return Err(LpmError::Registry(
                "skills validation failed — fix errors above".into(),
            ));
        }

        let has_authored_skills = !validation.validated_files.is_empty();
        if has_authored_skills && targets_lpm {
            if !json_output {
                install_ui::done_untrusted(&format!(
                    "{} skill(s) validated",
                    validation.valid_files.len()
                ));
            }
            let write_mode = if dry_run || check_only {
                ManifestWriteMode::ReadOnly
            } else {
                ManifestWriteMode::Persist
            };
            ensure_lpm_in_files(&mut publish_manifest, write_mode)?;
        }
        validation.validated_files
    };
    let has_skills = !validated_skills.is_empty();

    let PublishProject {
        source_dir,
        pkg_json,
        name,
        version,
        publish_config,
        readme,
        tarball_data,
        tarball_hashes,
        tarball_files,
        secret_scan,
        tarball_size,
        lpm_config,
        detected_ecosystem,
        swift_manifest,
    } = prepare_publish_project_from_manifest(
        publish_manifest,
        workspace,
        Some(&validated_skills),
        !allow_secrets,
    )?;
    let publish_config_ref = publish_config.as_ref();

    let npm_config = publish_config_ref.and_then(|p| p.npm.as_ref());
    let github_config = publish_config_ref.and_then(|p| p.github.as_ref());
    let gitlab_config = publish_config_ref.and_then(|p| p.gitlab.as_ref());

    let provenance_request = resolve_provenance_request_from_project_source(
        project_dir,
        &source_dir,
        &pkg_json,
        provenance_flag,
        no_provenance,
        provenance_file,
    )?;
    if matches!(provenance_request, ProvenanceRequest::File(_)) && targets_lpm {
        return Err(LpmError::Registry(
            "--provenance-file is only supported for npm-compatible publish targets".into(),
        ));
    }
    if !matches!(provenance_request, ProvenanceRequest::Disabled) {
        for target in &targets {
            if !is_npm_compatible_target(target) {
                continue;
            }
            let npm_name_str = target_names.get(&target.key()).ok_or_else(|| {
                LpmError::Registry(format!("no name resolved for {}", target.display_name()))
            })?;
            let (npm_access, _) =
                resolve_npm_target_access(target, npm_config, github_config, gitlab_config);
            if npm_access != "public" {
                return Err(LpmError::Registry(format!(
                    "npm provenance requires public access for {npm_name_str}. \
                     Set publish.npm.access to \"public\" or omit restricted access."
                )));
            }
        }
    }

    let rewritten_tarballs = prepare_rewritten_target_tarballs(
        &targets,
        &target_names,
        &name,
        &tarball_data,
        !allow_secrets,
    )?;
    let version_data = build_publish_version_data(
        &pkg_json,
        &name,
        &version,
        readme.as_deref(),
        &tarball_hashes,
    );
    let precomputed_npm_artifacts = precompute_file_provenance_artifacts(NpmFilePreflightInput {
        provenance_request: &provenance_request,
        targets: &targets,
        target_names: &target_names,
        package_json_name: &name,
        version: &version,
        version_data: &version_data,
        tarball_data: &tarball_data,
        tarball_hashes: &tarball_hashes,
        rewritten_tarballs: &rewritten_tarballs,
        json_output,
    })
    .await?;

    let mut final_secret_scans = Vec::with_capacity(targets.len());
    if !allow_secrets {
        for target in &targets {
            let target_name = target_names.get(&target.key()).ok_or_else(|| {
                LpmError::Registry(format!("no name resolved for {}", target.display_name()))
            })?;
            final_secret_scans.push(target_secret_scan(
                target_name,
                &name,
                secret_scan.as_ref(),
                &rewritten_tarballs,
            )?);
        }
    }
    run_publish_secret_scan(final_secret_scans, json_output, allow_secrets)?;

    // Quality checks are required only for the LPM target.
    let quality_result = if targets_lpm {
        Some(run_publish_quality_gate(PublishQualityGateInput {
            pkg_json: &pkg_json,
            readme: readme.as_deref(),
            tarball_files: &tarball_files,
            detected_ecosystem: &detected_ecosystem,
            swift_manifest: swift_manifest.as_ref(),
            min_score,
            json_output,
        })?)
    } else {
        None
    };

    let local_skills_digest =
        has_skills.then(|| author::compute_validated_digest(&validated_skills));

    Ok(PreparedPublish {
        publish_started,
        dry_run,
        check_only,
        wait_for_publication,
        otp: otp.map(str::to_owned),
        yes,
        json_output,
        targets,
        targets_lpm,
        publication_wait_timeout,
        target_names,
        has_skills,
        local_skills_digest,
        pkg_json,
        name,
        version,
        publish_config,
        readme,
        tarball_data,
        tarball_hashes,
        tarball_files,
        tarball_size,
        lpm_config,
        detected_ecosystem,
        swift_manifest,
        provenance_request,
        rewritten_tarballs,
        version_data,
        precomputed_npm_artifacts,
        quality_result,
    })
}

pub(crate) async fn execute_prepared(
    client: &RegistryClient,
    prepared: PreparedPublish,
) -> Result<(), LpmError> {
    execute_prepared_inner(client, prepared, true)
        .await?
        .into_command_result()
}

pub(crate) async fn execute_prepared_for_release(
    client: &RegistryClient,
    prepared: PreparedPublish,
) -> Result<PublishExecutionReport, LpmError> {
    execute_prepared_inner(client, prepared, false).await
}

async fn execute_prepared_inner(
    client: &RegistryClient,
    prepared: PreparedPublish,
    emit_summary: bool,
) -> Result<PublishExecutionReport, LpmError> {
    let PreparedPublish {
        publish_started,
        dry_run,
        check_only,
        wait_for_publication,
        otp,
        yes,
        json_output,
        targets,
        targets_lpm,
        publication_wait_timeout,
        target_names,
        has_skills,
        local_skills_digest,
        pkg_json,
        name,
        version,
        publish_config,
        readme,
        tarball_data,
        tarball_hashes,
        tarball_files,
        tarball_size,
        lpm_config,
        detected_ecosystem,
        swift_manifest,
        provenance_request,
        rewritten_tarballs,
        version_data,
        mut precomputed_npm_artifacts,
        quality_result,
    } = prepared;
    let publish_config = publish_config.as_ref();
    let npm_config = publish_config.and_then(|config| config.npm.as_ref());
    let github_config = publish_config.and_then(|config| config.github.as_ref());
    let gitlab_config = publish_config.and_then(|config| config.gitlab.as_ref());

    // OIDC auto-exchange is limited to LPM publishes, real publish, and dry-run.
    //
    // Gated on `targets_lpm && !check_only`:
    //
    // - **`targets_lpm`** — `--npm` / `--github` / `--gitlab`-only publishes
    //   never touch the LPM target client, so leaking the package name to the
    //   LPM exchange endpoint would be a privacy violation with no upside.
    // - **`!check_only`** — `--check` is a local-validation surface; running
    //   a real CI OIDC exchange there mints a session token the user never
    //   asked for and contradicts the documented contract. `--dry-run` IS
    //   honored — it forms part of the LPM-side preflight (alongside the
    //   skills-staleness lookup below) so OIDC trust misconfiguration
    //   surfaces before a real publish. The dry-run authorization and version
    //   check runs below; upload-only checks still run only on a real publish.
    //
    // This runs before the skill-staleness check so the first LPM network
    // call uses the exchanged client too.
    //
    // The origin requires `package` for `scope=publish`, and the package name
    // only becomes known after `package.json` is parsed — that's why this
    // can't live in main.rs.
    //
    let mut oidc_token_for_wait = None;
    let oidc_swapped_client;
    let client: &RegistryClient =
        if targets_lpm && !check_only && oidc::registry_exchange_jwt_available() {
            let resolved_lpm_name = target_names.get("lpm").ok_or_else(|| {
                LpmError::Registry("no resolved LPM.dev package name for OIDC exchange".into())
            })?;
            let oidc_token = oidc::exchange_publish_oidc_token(
                client.base_url(),
                resolved_lpm_name,
                publication_wait_timeout,
            )
            .await
            .map_err(|error| {
                LpmError::Registry(format!(
                    "Trusted Publisher exchange failed for {resolved_lpm_name}: {error}"
                ))
            })?;
            if let Some(timeout) = publication_wait_timeout {
                oidc_token.publication_status_token_for_wait(timeout)?;
                oidc_token_for_wait = Some(oidc_token.clone());
            }
            oidc_swapped_client = client
                .clone_with_config()
                .with_token_override(oidc_token.token);
            if !json_output {
                install_ui::phase("Using OIDC-exchanged session token for LPM publish");
            }
            &oidc_swapped_client
        } else {
            client
        };

    // Skills staleness check is an LPM network read, so skip it in --check.
    //
    // Gated to skip in `--check` mode: this is a network read against the
    // LPM registry, and `--check` is the local-validation surface. Kept on
    // for `--dry-run` because the staleness diagnostic ("your skills are
    // identical to the previously published version") is part of the
    // LPM-side preflight a dry-run is meant to surface.
    if has_skills && targets_lpm && !check_only {
        let resolved_lpm_name = target_names.get("lpm").ok_or_else(|| {
            LpmError::Registry("no resolved LPM.dev package name for skills preflight".into())
        })?;
        let name_short = resolved_lpm_name
            .strip_prefix("@lpm.dev/")
            .unwrap_or(resolved_lpm_name);
        let prev = match client.get_skills(name_short, None).await {
            Ok(prev) => Some(prev),
            Err(LpmError::NotFound(_)) => None,
            Err(error) => {
                return Err(LpmError::Registry(format!(
                    "could not check previously published skills for {resolved_lpm_name}: {error}"
                )));
            }
        };
        if let Some(prev) = prev
            && !prev.skills.is_empty()
        {
            let published_digest = compute_published_skills_digest(&prev.skills);
            if local_skills_digest.as_deref() == Some(published_digest.as_str()) && !json_output {
                install_ui::warn(
                    "Skills are identical to the previously published version — consider updating them",
                );
            }
        }
    }

    // Check-only and dry-run modes stop before publishing.
    if check_only {
        if emit_summary && json_output {
            let json = publish_check_json(quality_result.as_ref(), &targets, &target_names);
            println!("{}", serde_json::to_string_pretty(&json).unwrap());
        }
        return Ok(PublishExecutionReport::successful(json_output));
    }

    if dry_run {
        if targets_lpm {
            let resolved_lpm_name = target_names.get("lpm").ok_or_else(|| {
                LpmError::Registry("no resolved LPM.dev package name for publish preflight".into())
            })?;
            client
                .publish_preflight(resolved_lpm_name, &version)
                .await
                .map_err(|error| {
                    LpmError::Registry(format!(
                        "LPM.dev publish preflight failed for {resolved_lpm_name}@{version}: {error}"
                    ))
                })?;
        }
        if emit_summary && json_output {
            let json = serde_json::json!({
                "success": true,
                "dry_run": true,
                "name": name,
                "version": version,
                "files": tarball_files.len(),
                "tarball_size": tarball_size,
                "quality": quality_result,
                "targets": targets.iter().map(|t| {
                    let key = t.key();
                    let name = target_names.get(&key);
                    serde_json::json!({"registry": t.output_key(), "name": name})
                }).collect::<Vec<_>>(),
            });
            println!("{}", serde_json::to_string_pretty(&json).unwrap());
        } else if emit_summary {
            let eco = detected_ecosystem.clone();

            let summary = DryRunSummary {
                name: &name,
                version: &version,
                target_names: &target_names,
                file_count: tarball_files.len(),
                tarball_size,
                quality_result: quality_result.as_ref(),
                has_skills,
                ecosystem: &eco,
                targets: &targets,
            };
            print_dry_run_summary(&summary);
        }
        return Ok(PublishExecutionReport::successful(json_output));
    }

    // Prompt before a real human-facing publish unless explicitly confirmed.
    if !json_output && !yes {
        println!();
        let is_tty = std::io::IsTerminal::is_terminal(&std::io::stdin());
        if is_tty {
            let safe_name = lpm_common::sanitize_terminal_inline(&name);
            let safe_version = lpm_common::sanitize_terminal_inline(&version);
            let prompt_msg = if targets.len() > 1 {
                format!(
                    "Publish {safe_name}@{safe_version} to {}?",
                    targets
                        .iter()
                        .map(|t| t.display_name())
                        .collect::<Vec<_>>()
                        .join(" + ")
                )
            } else {
                format!("Publish {safe_name}@{safe_version}?")
            };
            let confirm = cliclack::confirm(prompt_msg)
                .initial_value(true)
                .interact()
                .map_err(|e| LpmError::Registry(e.to_string()))?;

            if !confirm {
                install_ui::skipped("Publish cancelled");
                return Ok(PublishExecutionReport::successful(json_output));
            }
        }
    }

    let provenance_context = match provenance_request {
        ProvenanceRequest::File(_) => None,
        request => materialize_provenance_request(request).await?,
    };

    // Publish sequentially so per-target auth prompts and summaries stay deterministic.
    // All per-target errors are caught and collected — the loop NEVER aborts early.
    let mut results: Vec<PublishResult> = Vec::with_capacity(targets.len());

    for target in &targets {
        let start = std::time::Instant::now();

        match target {
            PublishTarget::Lpm => {
                // Wrap the entire LPM publish path so any error becomes a PublishResult
                let lpm_result: Result<serde_json::Value, LpmError> = async {
                    let lpm_name = target_names.get("lpm").map_or(name.as_str(), |s| s.as_str());

                    let lpm_tarball = target_tarball(
                        lpm_name,
                        &name,
                        &tarball_data,
                        &tarball_hashes,
                        &rewritten_tarballs,
                    )?;

                    // Recompute dist hashes from the final rewritten tarball so metadata
                    // matches the actual uploaded artifact (not the pre-rewrite original).
                    let mut lpm_version_data = version_data.clone();
                    lpm_version_data["name"] = serde_json::json!(lpm_name);
                    lpm_version_data["_id"] =
                        serde_json::json!(format!("{lpm_name}@{version}"));
                    lpm_version_data["dist"] = serde_json::json!({
                        "shasum": lpm_tarball.hashes.shasum,
                        "integrity": lpm_tarball.hashes.integrity,
                    });

                    // Generate per-target provenance from the final rewritten tarball
                    if let Some(ref provenance) = provenance_context {
                        let ResolvedProvenance::Generate(context) = provenance else {
                            return Err(LpmError::Registry(
                                "--provenance-file is only supported for npm-compatible publish targets"
                                    .into(),
                            ));
                        };
                        let sha512_hex = integrity_to_sha512_hex(&lpm_tarball.hashes.integrity);
                        let slsa = provenance::build_slsa_statement(
                            &context.ci,
                            lpm_name,
                            &version,
                            &sha512_hex,
                        );
                        let slsa_json = serde_json::to_vec(&slsa)
                            .map_err(|e| LpmError::Registry(format!("failed to serialize SLSA statement: {e}")))?;

                        // --provenance is strict: fail if Sigstore fails
                        let bundle = sigstore::sign_and_record(&context.jwt, &slsa_json).await
                            .map_err(|e| LpmError::Registry(format!(
                                "Sigstore provenance failed: {e}. \
                                 Publish aborted because --provenance requires successful provenance generation."
                            )))?;

                        if !json_output {
                            install_ui::done("Sigstore provenance generated and recorded in Rekor");
                        }
                        let bundle_json = serde_json::to_value(&bundle).unwrap_or_default();
                        lpm_version_data["_provenance"] = bundle_json.clone();
                        lpm_version_data["_npmProvenanceAttestations"] = bundle_json;
                    }

                    let upload_spinner = if json_output {
                        None
                    } else {
                        Some(install_ui::spin_line(format_upload_message("lpm.dev")))
                    };
                    let response = publish_to_lpm(
                        client,
                        lpm_name,
                        &version,
                        &readme,
                        lpm_tarball.data,
                        &tarball_files,
                        lpm_tarball.package_json_size,
                        &lpm_version_data,
                        &quality_result,
                        &lpm_config,
                        otp.as_deref(),
                        json_output,
                        &detected_ecosystem,
                        &swift_manifest,
                    )
                    .await?;
                    drop(upload_spinner);
                    if !json_output {
                        print_upload_details(lpm_name, &version, lpm_visibility(&pkg_json), "latest");
                    }
                    Ok(response)
                }
                .await;

                let duration = start.elapsed();
                let lpm_name = target_names
                    .get("lpm")
                    .map_or(name.as_str(), |s| s.as_str());
                match lpm_result {
                    Ok(resp) => {
                        let publication_status =
                            LpmPublicationStatus::from_registry_response(&resp);
                        let current_latest_version = resp
                            .get("currentLatestVersion")
                            .and_then(serde_json::Value::as_str)
                            .map(str::to_string);
                        if !json_output {
                            if let Some(url) = lpm_package_url(lpm_name) {
                                publish_detail("url", install_ui::url(&url));
                            }
                            if let Some(notice) = publication_status
                                .as_ref()
                                .and_then(format_lpm_publication_notice)
                            {
                                install_ui::warn_line(notice);
                            }
                            if !matches!(
                                publication_status.as_ref(),
                                Some(LpmPublicationStatus::Active)
                            ) {
                                publish_detail(
                                    "current latest",
                                    install_ui::yellow(
                                        current_latest_version.as_deref().unwrap_or("none"),
                                    ),
                                );
                            }
                            if let Some(warnings) = resp.get("warnings").and_then(|w| w.as_array())
                            {
                                for w in warnings {
                                    if let Some(msg) = w.as_str() {
                                        install_ui::warn_untrusted(
                                            &lpm_common::sanitize_terminal_inline(msg),
                                        );
                                    }
                                }
                            }
                        }
                        results.push(PublishResult {
                            target: "lpm".into(),
                            success: true,
                            error: None,
                            auth: None,
                            publication_status,
                            current_latest_version,
                            publication_wait: None,
                            duration,
                        });
                    }
                    Err(e) => {
                        if !json_output {
                            let error = e.to_string();
                            install_ui::warn_untrusted(&format!(
                                "LPM publish failed: {}",
                                lpm_common::sanitize_terminal_inline(&error)
                            ));
                        }
                        results.push(PublishResult {
                            target: "lpm".into(),
                            success: false,
                            error: Some(e.to_string()),
                            auth: None,
                            publication_status: None,
                            current_latest_version: None,
                            publication_wait: None,
                            duration,
                        });
                    }
                }
            }
            PublishTarget::Npm
            | PublishTarget::GitHub
            | PublishTarget::GitLab
            | PublishTarget::Custom(_) => {
                // Wrap the entire npm-like target path so any error becomes a PublishResult.
                // This ensures the loop always continues to the next target.
                let npm_target_result: Result<PublishResult, LpmError> = async {
                    let npm_name_str = target_names.get(&target.key()).ok_or_else(|| {
                        LpmError::Registry(format!(
                            "no name resolved for {}",
                            target.display_name()
                        ))
                    })?;

                    // Resolve registry URL, token, display name per target
                    let (registry_url, token, display, auth_source) = match target {
                        PublishTarget::Npm => {
                            let registry_url = publish_npm::resolve_npm_registry(npm_config);
                            let npm_auth =
                                npm_auth::resolve_publish_auth(npm_name_str, &registry_url)
                                    .await?;
                            (
                                registry_url,
                                npm_auth.token().to_string(),
                                "npm",
                                Some(npm_auth.source().as_str()),
                            )
                        }
                        PublishTarget::GitHub => (
                            "https://npm.pkg.github.com".to_string(),
                            auth::get_github_token().ok_or_else(|| {
                                LpmError::Registry(
                                    "no GitHub Packages token found. Run `gh auth login --hostname github.com`, run `lpm login --github --token <pat>`, or set GITHUB_TOKEN.".into(),
                                )
                            })?,
                            "GitHub Packages",
                            None,
                        ),
                        PublishTarget::GitLab => {
                            let gl_cfg = publish_config.and_then(|p| p.gitlab.as_ref());
                            let project_id = gl_cfg
                                .and_then(|c| c.project_id.as_deref())
                                .ok_or_else(|| {
                                    LpmError::Registry(
                                        "GitLab publish requires publish.gitlab.projectId in lpm.json"
                                            .into(),
                                    )
                                })?;
                            let gitlab_host = gl_cfg
                                .and_then(|c| c.registry.as_deref())
                                .unwrap_or("https://gitlab.com");
                            if gitlab_host.trim_end_matches('/') != "https://gitlab.com" {
                                tracing::warn!(
                                    target_url = %crate::install_ui::safe_url_origin(gitlab_host),
                                    "publish.gitlab.registry overridden — an exact registry-scoped token is required",
                                );
                            }
                            let url = format!(
                                "{}/api/v4/projects/{}/packages/npm",
                                gitlab_host.trim_end_matches('/'),
                                urlencoding::encode(project_id)
                            );
                            let token = auth::get_gitlab_token_for_host(&url).ok_or_else(|| {
                                LpmError::Registry(format!(
                                    "no GitLab Packages token found. For gitlab.com, run `glab auth login`; otherwise run `lpm login --login-registry {} --token <token>`.",
                                    crate::install_ui::safe_url_origin(&url)
                                ))
                            })?;
                            (
                                url,
                                token,
                                "GitLab Packages",
                                None,
                            )
                        }
                        PublishTarget::Custom(url) => (
                            url.clone(),
                            auth::get_custom_registry_token(url).ok_or_else(|| {
                                let safe_origin = crate::install_ui::safe_url_origin(url);
                                LpmError::Registry(format!(
                                    "no token found for {safe_origin}. Run `lpm login --login-registry <configured-registry-url> --token <token>`."
                                ))
                            })?,
                            "custom",
                            None,
                        ),
                        _ => unreachable!(),
                    };

                    if auth_source == Some("oidc") && !json_output {
                        install_ui::phase("Using npm Trusted Publishing (OIDC)");
                    }

                    // Per-target access
                    let (npm_access, _) = resolve_npm_target_access(
                        target,
                        npm_config,
                        github_config,
                        gitlab_config,
                    );
                    if provenance_context.is_some() && npm_access != "public" {
                        return Err(LpmError::Registry(format!(
                            "npm provenance requires public access for {npm_name_str}. \
                             Set publish.npm.access to \"public\" or omit restricted access."
                        )));
                    }
                    let npm_tag = publish_npm::resolve_npm_tag(npm_config);
                    let npm_tag_explicit = npm_config
                        .and_then(|config| config.tag.as_deref())
                        .is_some();
                    publish_npm::preflight_npm_publish_version(
                        &token,
                        npm_name_str,
                        &version,
                        npm_tag_explicit,
                        &registry_url,
                    )
                    .await?;

                    // OTP preemption
                    let registry_key_for_otp = match target {
                        PublishTarget::Npm => "npmjs.org",
                        PublishTarget::GitHub => "github.com",
                        PublishTarget::GitLab => "gitlab.com",
                        _ => "",
                    };
                    let otp_preempt = npm_config
                        .and_then(|c| c.otp_required)
                        .unwrap_or(false)
                        || auth::is_otp_required(registry_key_for_otp);

                    let target_key = target.key();
                    let target_artifact =
                        if let Some(artifact) = precomputed_npm_artifacts.remove(&target_key) {
                            artifact
                        } else {
                            let final_tarball = target_tarball(
                                npm_name_str,
                                &name,
                                &tarball_data,
                                &tarball_hashes,
                                &rewritten_tarballs,
                            )?;
                            prepare_npm_target_artifact(NpmTargetArtifactInput {
                                npm_name: npm_name_str,
                                version: &version,
                                base_version_data: &version_data,
                                final_tarball_data: std::sync::Arc::clone(final_tarball.data),
                                final_tarball_hashes: std::sync::Arc::clone(final_tarball.hashes),
                                provenance_context: provenance_context.as_ref(),
                                target_label: display,
                                json_output,
                            })
                            .await?
                        };

                    let upload_spinner = if json_output {
                        None
                    } else {
                        Some(install_ui::spin_line(format_upload_message(display)))
                    };
                    let npm_result = publish_npm::publish_to_npm(
                        &token,
                        npm_name_str,
                        &version,
                        &target_artifact.version_data,
                        &target_artifact.tarball_data,
                        &target_artifact.tarball_hashes,
                        target_artifact.provenance_attachment.as_ref(),
                        npm_access,
                        &npm_tag,
                        &registry_url,
                        otp_preempt,
                        json_output,
                        yes,
                    )
                    .await?;
                    drop(upload_spinner);
                    if !json_output {
                        print_upload_details(
                            npm_name_str,
                            &version,
                            visibility_from_access(npm_access),
                            &npm_tag,
                        );
                    }

                    if npm_result.success {
                        if !json_output {
                            let package_url = match target {
                                PublishTarget::Npm => {
                                    Some(format!(
                                        "https://www.npmjs.com/package/{}",
                                        npm_name_str
                                    ))
                                }
                                PublishTarget::GitHub => npm_name_str
                                    .strip_prefix('@')
                                    .and_then(|s| s.split_once('/'))
                                    .map(|(scope, pkg)| {
                                        format!("https://github.com/users/{scope}/packages/npm/package/{pkg}")
                                    }),
                                PublishTarget::GitLab => {
                                    let gl_cfg = publish_config.and_then(|p| p.gitlab.as_ref());
                                    let host = gl_cfg
                                        .and_then(|c| c.registry.as_deref())
                                        .unwrap_or("https://gitlab.com");
                                    gl_cfg
                                        .and_then(|c| c.project_id.as_deref())
                                        .map(|pid| format!("{host}/projects/{pid}/packages"))
                                }
                                _ => None,
                            };
                            if let Some(url) = package_url {
                                publish_detail("url", install_ui::url(&url));
                            }
                        }
                    } else if !json_output {
                        let err_msg = npm_result.error.as_deref().unwrap_or("unknown error");
                        install_ui::warn_untrusted(&format!(
                            "{} publish failed: {}",
                            lpm_common::sanitize_terminal_inline(display),
                            lpm_common::sanitize_terminal_inline(err_msg)
                        ));
                    }

                    Ok(PublishResult {
                        target: target.output_key(),
                        success: npm_result.success,
                        error: npm_result.error,
                        auth: auth_source,
                        publication_status: None,
                        current_latest_version: None,
                        publication_wait: None,
                        duration: npm_result.duration,
                    })
                }
                .await;

                // Catch any error from the npm-like target and convert to a failed PublishResult.
                // This ensures the loop always continues to the next target.
                match npm_target_result {
                    Ok(result) => results.push(result),
                    Err(e) => {
                        let duration = start.elapsed();
                        if !json_output {
                            let error = e.to_string();
                            install_ui::warn_untrusted(&format!(
                                "{} publish failed: {}",
                                lpm_common::sanitize_terminal_inline(target.display_name()),
                                lpm_common::sanitize_terminal_inline(&error)
                            ));
                        }
                        results.push(PublishResult {
                            target: target.output_key(),
                            success: false,
                            error: Some(e.to_string()),
                            auth: None,
                            publication_status: None,
                            current_latest_version: None,
                            publication_wait: None,
                            duration,
                        });
                    }
                }
            }
        }
    }

    if wait_for_publication {
        let lpm_name = target_names
            .get("lpm")
            .map_or(name.as_str(), String::as_str);
        if let Some(result) = results
            .iter_mut()
            .find(|result| result.target == "lpm" && result.success)
        {
            if !json_output {
                install_ui::phase("Waiting for LPM.dev Registry publication");
            }
            let timeout = publication_wait_timeout.unwrap_or(DEFAULT_PUBLICATION_WAIT_TIMEOUT);
            let wait_result = match result.publication_status.clone() {
                Some(LpmPublicationStatus::Active) => PublicationWaitResult::active()
                    .with_current_latest_version(result.current_latest_version.clone()),
                Some(status) if status.is_terminal_rejection() => {
                    PublicationWaitResult::terminal(status)
                        .with_current_latest_version(result.current_latest_version.clone())
                }
                _ => {
                    wait_for_lpm_publication_with_oidc(
                        client,
                        lpm_name,
                        &version,
                        timeout,
                        oidc_token_for_wait.as_ref(),
                    )
                    .await
                }
            };
            if let Some(status) = wait_result.status.clone() {
                result.publication_status = Some(status);
            }
            if let Some(current_latest_version) = wait_result.current_latest_version.clone() {
                result.current_latest_version = Some(current_latest_version);
            }
            if !json_output {
                if wait_result.success {
                    install_ui::done("LPM.dev Registry publication is active");
                } else if let Some(error) = wait_result.error.as_deref() {
                    install_ui::warn_untrusted(&lpm_common::sanitize_terminal_inline(error));
                }
            }
            result.publication_wait = Some(wait_result);
        }
    }

    // Final summary after every target has had a chance to publish.
    let any_failed = results.iter().any(|r| !r.success);
    let any_publication_failed = results.iter().any(|result| {
        result
            .publication_status
            .as_ref()
            .is_some_and(LpmPublicationStatus::is_terminal_rejection)
            || result
                .publication_wait
                .as_ref()
                .is_some_and(|wait| !wait.success)
    });
    let command_failed = any_failed || any_publication_failed;
    let succeeded = results.iter().filter(|r| r.success).count();
    let lpm_publication_status = results
        .iter()
        .find(|result| result.target == "lpm" && result.success)
        .and_then(|result| result.publication_status.as_ref());

    if emit_summary && json_output {
        let json = serde_json::json!({
            "success": !command_failed,
            "results": results.iter().map(publish_result_json).collect::<Vec<_>>(),
        });
        println!("{}", serde_json::to_string_pretty(&json).unwrap());
    } else if emit_summary && targets.len() > 1 && any_failed {
        install_ui::warn_line(format_multi_publish_partial_summary(
            succeeded,
            targets.len(),
            lpm_publication_status,
        ));
        for (target, result) in targets.iter().zip(results.iter()) {
            if !result.success {
                install_ui::detail_line(format_publish_retry_detail(target));
            }
        }
    } else if emit_summary && !any_publication_failed && targets.len() > 1 {
        let elapsed = install_ui::format_duration(publish_started.elapsed());
        install_ui::done_line(format_multi_publish_success_summary(
            targets.len(),
            &elapsed,
            lpm_publication_status,
        ));
    } else if emit_summary && !any_publication_failed && !any_failed {
        let target = &targets[0];
        let key = target.key();
        let published_name = target_names.get(&key).map_or(name.as_str(), |s| s.as_str());
        let elapsed = install_ui::format_duration(publish_started.elapsed());
        install_ui::done_line(format_single_publish_success_summary(
            published_name,
            &version,
            &elapsed,
            lpm_publication_status,
        ));
    }

    Ok(PublishExecutionReport {
        success: !command_failed,
        results: results.iter().map(publish_result_json).collect(),
        json_output,
        any_upload_failed: any_failed,
        any_publication_failed,
    })
}

fn prepare_rewritten_target_tarballs(
    targets: &[PublishTarget],
    target_names: &HashMap<String, String>,
    package_json_name: &str,
    base_tarball_data: &[u8],
    scan_secrets: bool,
) -> Result<HashMap<String, publish_common::RewrittenTarball>, LpmError> {
    let mut rewritten_tarballs = HashMap::with_capacity(targets.len());
    for target in targets {
        let target_name = target_names.get(&target.key()).ok_or_else(|| {
            LpmError::Registry(format!("no name resolved for {}", target.display_name()))
        })?;
        if target_name == package_json_name || rewritten_tarballs.contains_key(target_name) {
            continue;
        }

        let rewritten = publish_common::rewrite_tarball_name_for_publish(
            base_tarball_data,
            package_json_name,
            target_name,
            scan_secrets,
        )?
        .ok_or_else(|| {
            LpmError::Registry(format!(
                "target tarball rewrite was skipped for renamed package {target_name}"
            ))
        })?;
        validate_publish_tarball_size(rewritten.data.len())?;
        rewritten_tarballs.insert(target_name.clone(), rewritten);
    }
    Ok(rewritten_tarballs)
}

struct TargetTarball<'a> {
    data: &'a std::sync::Arc<Vec<u8>>,
    hashes: &'a std::sync::Arc<publish_common::TarballHashes>,
    package_json_size: Option<u64>,
}

fn target_tarball<'a>(
    target_name: &str,
    package_json_name: &str,
    base_tarball_data: &'a std::sync::Arc<Vec<u8>>,
    base_tarball_hashes: &'a std::sync::Arc<publish_common::TarballHashes>,
    rewritten_tarballs: &'a HashMap<String, publish_common::RewrittenTarball>,
) -> Result<TargetTarball<'a>, LpmError> {
    if target_name == package_json_name {
        return Ok(TargetTarball {
            data: base_tarball_data,
            hashes: base_tarball_hashes,
            package_json_size: None,
        });
    }
    rewritten_tarballs
        .get(target_name)
        .map(|tarball| TargetTarball {
            data: &tarball.data,
            hashes: &tarball.hashes,
            package_json_size: Some(tarball.package_json_size),
        })
        .ok_or_else(|| {
            LpmError::Registry(format!(
                "missing prepared tarball for renamed package {target_name}"
            ))
        })
}

fn target_secret_scan<'a>(
    target_name: &str,
    package_json_name: &str,
    base_secret_scan: Option<&'a lpm_security::behavioral::secrets::SecretScanResult>,
    rewritten_tarballs: &'a HashMap<String, publish_common::RewrittenTarball>,
) -> Result<&'a lpm_security::behavioral::secrets::SecretScanResult, LpmError> {
    let scan = if target_name == package_json_name {
        base_secret_scan
    } else {
        rewritten_tarballs
            .get(target_name)
            .and_then(|tarball| tarball.secret_scan.as_ref())
    };
    scan.ok_or_else(|| {
        LpmError::Registry(format!(
            "publish artifact for {target_name} was prepared without a secret scan"
        ))
    })
}

async fn precompute_file_provenance_artifacts(
    input: NpmFilePreflightInput<'_>,
) -> Result<HashMap<String, NpmTargetArtifact>, LpmError> {
    let ProvenanceRequest::File(request) = input.provenance_request else {
        return Ok(HashMap::new());
    };
    let file = load_provenance_request_file(request)?;
    let provenance = ResolvedProvenance::File(file);
    let npm_target_count = input
        .targets
        .iter()
        .filter(|target| is_npm_compatible_target(target))
        .count();
    let mut artifacts = HashMap::with_capacity(npm_target_count);

    for target in input.targets {
        if !is_npm_compatible_target(target) {
            continue;
        }
        let key = target.key();
        let npm_name = input.target_names.get(&key).ok_or_else(|| {
            LpmError::Registry(format!("no name resolved for {}", target.display_name()))
        })?;
        let tarball = target_tarball(
            npm_name,
            input.package_json_name,
            input.tarball_data,
            input.tarball_hashes,
            input.rewritten_tarballs,
        )?;
        let artifact = prepare_npm_target_artifact(NpmTargetArtifactInput {
            npm_name,
            version: input.version,
            base_version_data: input.version_data,
            final_tarball_data: std::sync::Arc::clone(tarball.data),
            final_tarball_hashes: std::sync::Arc::clone(tarball.hashes),
            provenance_context: Some(&provenance),
            target_label: target.display_name(),
            json_output: input.json_output,
        })
        .await?;
        artifacts.insert(key, artifact);
    }

    Ok(artifacts)
}

fn is_npm_compatible_target(target: &PublishTarget) -> bool {
    matches!(
        target,
        PublishTarget::Npm
            | PublishTarget::GitHub
            | PublishTarget::GitLab
            | PublishTarget::Custom(_)
    )
}

pub(crate) fn resolve_target_names(
    manifest: &super::prepare::PublishManifest,
    targets: &[PublishTarget],
) -> Result<HashMap<String, String>, LpmError> {
    let publish_config = manifest.publish_config.as_ref();
    let lpm_config = publish_config.and_then(|config| config.lpm.as_ref());
    let npm_config = publish_config.and_then(|config| config.npm.as_ref());
    let github_config = publish_config.and_then(|config| config.github.as_ref());
    let gitlab_config = publish_config.and_then(|config| config.gitlab.as_ref());

    if targets.contains(&PublishTarget::GitLab) {
        let project_id = gitlab_config
            .and_then(|config| config.project_id.as_deref())
            .ok_or_else(|| {
                LpmError::Registry(
                    "GitLab Packages requires publish.gitlab.projectId in lpm.json".into(),
                )
            })?;
        if project_id.trim().is_empty() || project_id.trim() != project_id {
            return Err(LpmError::Registry(
                "publish.gitlab.projectId must be a non-empty value without surrounding whitespace"
                    .into(),
            ));
        }
        if let Some(registry) = gitlab_config.and_then(|config| config.registry.as_deref()) {
            publish_npm::validate_npm_registry_setting(registry, "publish.gitlab.registry")?;
        }
    }

    if targets.iter().any(is_npm_compatible_target) {
        publish_npm::validate_npm_publish_config(
            npm_config,
            targets.contains(&PublishTarget::Npm),
        )?;
        if npm_config
            .and_then(|config| config.tag.as_deref())
            .is_none()
            && lpm_semver::Version::parse(&manifest.version)?.is_prerelease()
        {
            return Err(LpmError::Registry(
                "prerelease publishing requires an explicit publish.npm.tag".into(),
            ));
        }
    }

    let mut target_names = HashMap::with_capacity(targets.len());
    for target in targets {
        let resolved = match target {
            PublishTarget::Lpm => lpm_config
                .and_then(|config| config.name.clone())
                .unwrap_or_else(|| manifest.name.clone()),
            PublishTarget::Npm => publish_npm::resolve_npm_name(&manifest.name, npm_config)?,
            PublishTarget::GitHub => {
                let name = github_config
                    .and_then(|config| config.name.clone())
                    .or_else(|| npm_config.and_then(|config| config.name.clone()))
                    .map_or_else(|| publish_npm::resolve_npm_name(&manifest.name, None), Ok)?;
                if !name.starts_with('@') {
                    return Err(LpmError::Registry(
                        "GitHub Packages requires scoped package names (@owner/package). \
						 Set publish.github.name in lpm.json."
                            .into(),
                    ));
                }
                name
            }
            PublishTarget::GitLab => gitlab_config
                .and_then(|config| config.name.clone())
                .or_else(|| npm_config.and_then(|config| config.name.clone()))
                .map_or_else(|| publish_npm::resolve_npm_name(&manifest.name, None), Ok)?,
            PublishTarget::Custom(_) => npm_config
                .and_then(|config| config.name.clone())
                .map_or_else(|| publish_npm::resolve_npm_name(&manifest.name, None), Ok)?,
        };
        if matches!(target, PublishTarget::Lpm) {
            validate_lpm_publish_name(&resolved)?;
        } else {
            publish_npm::validate_npm_name(&resolved)?;
            let (access, source) =
                resolve_npm_target_access(target, npm_config, github_config, gitlab_config);
            publish_npm::validate_npm_access(access, source)?;
            if matches!(target, PublishTarget::Npm)
                && access == "restricted"
                && !resolved.starts_with('@')
            {
                return Err(LpmError::Registry(
                    "npm cannot restrict access to an unscoped package".into(),
                ));
            }
        }
        target_names.insert(target.key(), resolved);
    }
    Ok(target_names)
}

fn resolve_npm_target_access<'a>(
    target: &PublishTarget,
    npm_config: Option<&'a lpm_runner::lpm_json::NpmPublishConfig>,
    github_config: Option<&'a lpm_runner::lpm_json::GithubPublishConfig>,
    gitlab_config: Option<&'a lpm_runner::lpm_json::GitlabPublishConfig>,
) -> (&'a str, &'static str) {
    match target {
        PublishTarget::GitHub => github_config
            .and_then(|config| config.access.as_deref())
            .map_or_else(
                || npm_publish_access(npm_config),
                |access| (access, "publish.github.access"),
            ),
        PublishTarget::GitLab => gitlab_config
            .and_then(|config| config.access.as_deref())
            .map_or_else(
                || npm_publish_access(npm_config),
                |access| (access, "publish.gitlab.access"),
            ),
        PublishTarget::Npm | PublishTarget::Custom(_) => npm_publish_access(npm_config),
        PublishTarget::Lpm => ("public", "publish.npm.access"),
    }
}

fn npm_publish_access(
    npm_config: Option<&lpm_runner::lpm_json::NpmPublishConfig>,
) -> (&str, &'static str) {
    npm_config
        .and_then(|config| config.access.as_deref())
        .map_or(("public", "publish.npm.access"), |access| {
            (access, "publish.npm.access")
        })
}

fn validate_lpm_publish_name(name: &str) -> Result<(), LpmError> {
    let Some(identity) = name.strip_prefix("@lpm.dev/") else {
        return Err(LpmError::InvalidPackageName(format!(
            "LPM publish name must use the exact lowercase @lpm.dev/owner.package format: {name}"
        )));
    };
    let Some((owner, package)) = identity.split_once('.') else {
        return Err(LpmError::InvalidPackageName(format!(
            "LPM publish name must use the exact lowercase @lpm.dev/owner.package format: {name}"
        )));
    };
    let owner_is_canonical = !owner.is_empty()
        && owner
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-');
    let package_is_canonical = !package.is_empty()
        && package
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-');
    if !owner_is_canonical || !package_is_canonical {
        return Err(LpmError::InvalidPackageName(format!(
            "LPM publish name must use the exact lowercase @lpm.dev/owner.package format: {name}"
        )));
    }
    Ok(())
}

pub(super) fn lpm_package_url(name: &str) -> Option<String> {
    let package = name.strip_prefix("@lpm.dev/")?;
    let (owner, package_name) = package.split_once('.')?;
    if owner.is_empty()
        || package_name.is_empty()
        || !package
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
    {
        return None;
    }
    Some(format!("https://lpm.dev/{package}"))
}

#[cfg(test)]
mod transaction_root_tests {
    use super::{
        ensure_publish_transaction_root_unchanged, open_publish_lock_directory,
        select_publish_transaction_root,
    };
    use crate::commands::publish::prepare::PublishSource;

    #[cfg(unix)]
    #[test]
    fn publish_transaction_root_rejects_a_linked_workspace_manifest() {
        let root = tempfile::tempdir().unwrap();
        let workspace = root.path().join("workspace");
        let project = workspace.join("packages/app");
        std::fs::create_dir_all(&project).unwrap();
        let external = root.path().join("external-package.json");
        std::fs::write(&external, r#"{"name":"root","workspaces":["packages/*"]}"#).unwrap();
        std::os::unix::fs::symlink(&external, workspace.join("package.json")).unwrap();
        std::fs::write(
            project.join("package.json"),
            r#"{"name":"app","version":"1.0.0"}"#,
        )
        .unwrap();

        let source = PublishSource::open(&project).unwrap();
        let Err(error) = select_publish_transaction_root(&project.canonicalize().unwrap(), &source)
        else {
            panic!("linked workspace metadata must not select the publish lock scope");
        };
        let error = error.to_string();

        assert!(
            error.contains("workspace") || error.contains("unsafe"),
            "{error}"
        );
    }

    #[test]
    fn publish_transaction_root_rejects_same_path_directory_replacement() {
        let root = tempfile::tempdir().unwrap();
        let project = root.path().join("project");
        let displaced = root.path().join("displaced");
        std::fs::create_dir(&project).unwrap();
        std::fs::write(
            project.join("package.json"),
            r#"{"name":"selected","version":"1.0.0"}"#,
        )
        .unwrap();
        let source = PublishSource::open(&project).unwrap();
        let project_path = project.canonicalize().unwrap();
        let expected = select_publish_transaction_root(&project_path, &source).unwrap();
        std::fs::rename(&project, &displaced).unwrap();
        std::fs::create_dir(&project).unwrap();
        std::fs::write(
            project.join("package.json"),
            r#"{"name":"replacement","version":"9.9.9"}"#,
        )
        .unwrap();

        let error = ensure_publish_transaction_root_unchanged(&project_path, &source, &expected)
            .expect_err("the publish transaction root identity must remain stable")
            .to_string();

        assert!(
            error.contains("changed") && error.contains("retry"),
            "{error}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn publish_install_lock_rejects_a_linked_state_directory() {
        let root = tempfile::tempdir().unwrap();
        let project = root.path().join("project");
        let outside = root.path().join("outside");
        std::fs::create_dir(&project).unwrap();
        std::fs::create_dir(&outside).unwrap();
        std::fs::write(
            project.join("package.json"),
            r#"{"name":"selected","version":"1.0.0"}"#,
        )
        .unwrap();
        let source = PublishSource::open(&project).unwrap();
        let transaction_root =
            select_publish_transaction_root(&project.canonicalize().unwrap(), &source).unwrap();
        std::os::unix::fs::symlink(&outside, project.join(".lpm")).unwrap();

        let result = open_publish_lock_directory(&transaction_root);

        assert!(
            result.is_err() && std::fs::read_dir(&outside).unwrap().next().is_none(),
            "a linked state directory must not receive publish lock files: {result:?}"
        );
    }
}
