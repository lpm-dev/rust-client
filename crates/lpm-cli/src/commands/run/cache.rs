use lpm_common::LpmError;
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::Arc;

#[derive(Clone)]
pub(super) struct WorkspaceCacheContract {
    fingerprint: lpm_task::hasher::WorkspaceContractFingerprint,
    validation: lpm_task::hasher::FilesystemValidation,
}

impl WorkspaceCacheContract {
    pub(super) fn capture(root: &Path) -> Result<Self, LpmError> {
        let snapshot = lpm_task::hasher::compute_workspace_contract_snapshot(root)?;
        Ok(Self {
            fingerprint: snapshot.fingerprint,
            validation: snapshot.validation,
        })
    }
}

#[derive(Clone)]
pub(super) struct CompletedTaskCacheIdentity {
    value: String,
    output_validation: Option<lpm_task::hasher::FilesystemValidation>,
    dependencies: Vec<Arc<Self>>,
}

impl CompletedTaskCacheIdentity {
    fn capture(project_dir: &Path, context: &CacheContext) -> Result<Arc<Self>, LpmError> {
        Ok(Arc::new(Self {
            value: context.cache_key.clone(),
            output_validation: Some(lpm_task::hasher::capture_task_output_validation(
                project_dir,
                &context.task_config.outputs,
            )?),
            dependencies: Vec::new(),
        }))
    }

    pub(super) fn meta(dependencies: &[TaskDependencyIdentity]) -> Arc<Self> {
        Arc::new(Self {
            value: lpm_task::hasher::compute_dependency_fingerprint(&dependency_identity_pairs(
                dependencies,
            )),
            output_validation: None,
            dependencies: dependencies
                .iter()
                .map(|dependency| Arc::clone(&dependency.node))
                .collect(),
        })
    }
}

#[derive(Clone)]
pub(super) struct TaskDependencyIdentity {
    pub(super) label: String,
    pub(super) node: Arc<CompletedTaskCacheIdentity>,
}

fn dependency_identity_pairs(dependencies: &[TaskDependencyIdentity]) -> Vec<(String, String)> {
    dependencies
        .iter()
        .map(|dependency| (dependency.label.clone(), dependency.node.value.clone()))
        .collect()
}

/// Check if a task has caching enabled, using pre-read config.
pub(super) fn is_task_cached_with_config(
    script_name: &str,
    lpm_config: Option<&lpm_runner::lpm_json::LpmJsonConfig>,
) -> bool {
    lpm_config
        .and_then(|c| c.tasks.get(script_name))
        .is_some_and(|tc| tc.cache && !tc.outputs.is_empty())
}

/// Pre-computed cache context to avoid re-reading lpm.json and package.json
/// multiple times per task.
pub(super) struct CacheContext {
    pub(super) task_config: lpm_runner::lpm_json::TaskConfig,
    pub(super) cache_key: String,
    pub(super) command: String,
    pub(super) env_vars: HashMap<String, String>,
    pub(super) inherited_env: HashMap<String, String>,
    pub(super) remote_cache: Option<crate::commands::remote_cache::RemoteCacheClient>,
    workspace_validation: Option<lpm_task::hasher::FilesystemValidation>,
    input_validation: lpm_task::hasher::FilesystemValidation,
    dependencies: Vec<TaskDependencyIdentity>,
}

pub(super) struct CacheStoreRequest<'a> {
    pub(super) project_dir: &'a Path,
    pub(super) workspace_contract: Option<&'a WorkspaceCacheContract>,
    pub(super) script_name: &'a str,
    pub(super) env_mode: Option<&'a str>,
    pub(super) extra_args: &'a [String],
    pub(super) bin_hint: &'a lpm_runner::bin_path::ManagedRuntimeHint,
    pub(super) duration_ms: u64,
    pub(super) stdout: &'a str,
    pub(super) stderr: &'a str,
}

enum RemoteCacheResolution {
    Resolve(Option<Arc<lpm_auth::SessionManager>>),
    Omit,
}

pub(super) type WorkspaceDependencyIdentities =
    HashMap<String, Option<Vec<TaskDependencyIdentity>>>;

pub(super) fn resolve_task_dependency_identities(
    script_name: &str,
    tasks: &HashMap<String, lpm_runner::lpm_json::TaskConfig>,
    workspace_dependencies: &WorkspaceDependencyIdentities,
    completed_cache_identities: &HashMap<String, Arc<CompletedTaskCacheIdentity>>,
) -> Option<Vec<TaskDependencyIdentity>> {
    let local_dependencies = tasks
        .get(script_name)
        .map(|task| {
            task.depends_on
                .iter()
                .filter(|dependency| !dependency.starts_with('^'))
        })
        .into_iter()
        .flatten();
    let mut identities = match workspace_dependencies.get(script_name) {
        Some(Some(identities)) => identities.clone(),
        Some(None) => return None,
        None => Vec::new(),
    };
    for dependency in local_dependencies {
        let node = completed_cache_identities.get(dependency)?;
        identities.push(TaskDependencyIdentity {
            label: format!("local:{dependency}"),
            node: Arc::clone(node),
        });
    }
    identities.sort_unstable_by(|left, right| {
        left.label
            .cmp(&right.label)
            .then_with(|| left.node.value.cmp(&right.node.value))
    });
    identities
        .dedup_by(|left, right| left.label == right.label && left.node.value == right.node.value);
    Some(identities)
}

fn effective_cache_inputs(
    task_config: &lpm_runner::lpm_json::TaskConfig,
    lpm_config: Option<&lpm_runner::lpm_json::LpmJsonConfig>,
) -> Vec<String> {
    let mut inputs = task_config.effective_inputs();
    if let Some(config) = lpm_config {
        for dependency in task_config
            .depends_on
            .iter()
            .filter(|dependency| !dependency.starts_with('^'))
        {
            if let Some(dependency_config) = config.tasks.get(dependency) {
                inputs.extend(dependency_config.outputs.iter().cloned());
            }
        }
    }
    inputs.sort_unstable();
    inputs.dedup();
    inputs
}

/// Build the cache context for a task: reads lpm.json (or uses provided config),
/// resolves the command, and computes the cache key. Returns `None` if caching
/// is not enabled or outputs are empty (shared helper eliminates
/// duplication between try_cache_store and try_cache_store_with_output).
#[cfg(test)]
pub(super) fn build_cache_context(
    project_dir: &Path,
    script_name: &str,
    env_mode: Option<&str>,
    extra_args: &[String],
    bin_hint: &lpm_runner::bin_path::ManagedRuntimeHint,
    lpm_config: Option<&lpm_runner::lpm_json::LpmJsonConfig>,
) -> Result<Option<CacheContext>, LpmError> {
    build_task_context(
        project_dir,
        None,
        &[],
        script_name,
        env_mode,
        extra_args,
        bin_hint,
        lpm_config,
        RemoteCacheResolution::Resolve(None),
    )
}

#[expect(
    clippy::too_many_arguments,
    reason = "cache context preserves distinct execution inputs"
)]
fn build_task_context(
    project_dir: &Path,
    workspace_contract: Option<&WorkspaceCacheContract>,
    dependency_identities: &[TaskDependencyIdentity],
    script_name: &str,
    env_mode: Option<&str>,
    extra_args: &[String],
    bin_hint: &lpm_runner::bin_path::ManagedRuntimeHint,
    lpm_config: Option<&lpm_runner::lpm_json::LpmJsonConfig>,
    remote_cache: RemoteCacheResolution,
) -> Result<Option<CacheContext>, LpmError> {
    if let Some(provided_config) = lpm_config {
        let current_config =
            lpm_runner::lpm_json::read_lpm_json(project_dir).map_err(LpmError::Script)?;
        if current_config
            .as_ref()
            .and_then(|config| config.tasks.get(script_name))
            != provided_config.tasks.get(script_name)
        {
            tracing::warn!(
                "task configuration changed before '{}' started; disabling its cache",
                lpm_common::sanitize_terminal_inline(script_name)
            );
            return Ok(None);
        }
    }

    // Use provided config or read from disk
    let owned_config;
    let config_ref = if let Some(cfg) = lpm_config {
        Some(cfg)
    } else {
        owned_config =
            lpm_runner::lpm_json::read_lpm_json(project_dir).map_err(LpmError::Script)?;
        owned_config.as_ref()
    };

    let task_config = match config_ref.and_then(|config| config.tasks.get(script_name)) {
        Some(task_config) if task_config.cache && !task_config.outputs.is_empty() => {
            task_config.clone()
        }
        _ => return Ok(None),
    };

    let env_vars = lpm_runner::script::load_script_env_with_config(
        project_dir,
        script_name,
        env_mode,
        config_ref,
    )?;
    let inherited_env = lpm_runner::shell::inherited_child_env();
    let mut child_env = HashMap::with_capacity(inherited_env.len() + env_vars.len());
    child_env.extend(
        inherited_env
            .iter()
            .map(|(key, value)| (key.clone(), value.clone())),
    );
    child_env.extend(
        env_vars
            .iter()
            .map(|(key, value)| (key.clone(), value.clone())),
    );
    let mut runtime_identities = bin_hint.cache_identities();
    let child_path =
        lpm_runner::bin_path::build_path_with_bins_pre_resolved(project_dir, bin_hint)?;
    bin_hint.append_executable_cache_identities(
        project_dir,
        std::ffi::OsStr::new(&child_path),
        &mut runtime_identities,
    );

    let pkg_json_path = project_dir.join("package.json");
    let (package, package_json) = if pkg_json_path.exists() {
        let package_json = lpm_common::read_text_file_capped(
            &pkg_json_path,
            lpm_common::CONFIG_FILE_SIZE_CAP_BYTES,
        )
        .map_err(|error| LpmError::Script(format!("failed to read package.json: {error}")))?;
        let package: lpm_workspace::PackageJson = serde_json::from_str(
            lpm_common::strip_utf8_bom_str(&package_json),
        )
        .map_err(|error| LpmError::Script(format!("failed to parse package.json: {error}")))?;
        (Some(package), package_json)
    } else {
        (None, "{}".into())
    };

    let command = if let Some(cmd) = &task_config.command {
        cmd.clone()
    } else {
        package
            .as_ref()
            .and_then(|pkg| pkg.scripts.get(script_name))
            .cloned()
            .unwrap_or_default()
    };

    let cache_inputs = effective_cache_inputs(&task_config, config_ref);
    let dependency_pairs = dependency_identity_pairs(dependency_identities);
    let cache_snapshot = lpm_task::hasher::compute_cache_key_snapshot_with_workspace_contract(
        project_dir,
        workspace_contract.map(|contract| &contract.fingerprint),
        &dependency_pairs,
        &command,
        extra_args,
        &runtime_identities,
        &cache_inputs,
        &child_env,
        &package_json,
    )?;

    Ok(Some(CacheContext {
        task_config,
        cache_key: cache_snapshot.key,
        command,
        env_vars,
        inherited_env,
        remote_cache: match remote_cache {
            RemoteCacheResolution::Resolve(session) => {
                crate::commands::remote_cache::client_from_config(config_ref, session)
            }
            RemoteCacheResolution::Omit => None,
        },
        workspace_validation: workspace_contract.map(|contract| contract.validation.clone()),
        input_validation: cache_snapshot.validation,
        dependencies: dependency_identities.to_vec(),
    }))
}

#[expect(
    clippy::too_many_arguments,
    reason = "cache context preserves distinct execution inputs"
)]
pub(super) fn prepare_cache_context_with_config(
    project_dir: &Path,
    workspace_contract: Option<&WorkspaceCacheContract>,
    dependency_identities: &[TaskDependencyIdentity],
    script_name: &str,
    env_mode: Option<&str>,
    extra_args: &[String],
    bin_hint: &lpm_runner::bin_path::ManagedRuntimeHint,
    lpm_config: Option<&lpm_runner::lpm_json::LpmJsonConfig>,
    session: Option<Arc<lpm_auth::SessionManager>>,
) -> Result<Option<CacheContext>, LpmError> {
    build_task_context(
        project_dir,
        workspace_contract,
        dependency_identities,
        script_name,
        env_mode,
        extra_args,
        bin_hint,
        lpm_config,
        RemoteCacheResolution::Resolve(session),
    )
}

pub(super) fn try_cache_hit_with_context(
    project_dir: &Path,
    ctx: &CacheContext,
) -> Result<Option<lpm_task::cache::CacheHit>, LpmError> {
    if !cache_context_is_unchanged(ctx)? {
        return Ok(None);
    }
    if lpm_task::cache::has_cache_hit(&ctx.cache_key) {
        match lpm_task::cache::restore_cache_if(
            &ctx.cache_key,
            project_dir,
            &ctx.task_config.outputs,
            || cache_context_is_unchanged(ctx),
        ) {
            Ok(Some(hit)) => return Ok(Some(hit)),
            Ok(None) => return Ok(None),
            Err(error) => {
                tracing::warn!(
                    "local task cache entry {} is invalid; treating it as a miss: {error}",
                    ctx.cache_key
                );
            }
        }
    }

    if let Some(remote_cache) = &ctx.remote_cache
        && let Some(hit) = crate::commands::remote_cache::try_restore(
            remote_cache,
            &ctx.cache_key,
            project_dir,
            &ctx.task_config.outputs,
            || cache_context_is_unchanged(ctx),
        )
    {
        if let Err(error) = lpm_task::cache::store_cache(
            &ctx.cache_key,
            project_dir,
            &hit.meta.command,
            &ctx.task_config.outputs,
            &hit.stdout,
            &hit.stderr,
            hit.meta.duration_ms,
        ) {
            tracing::warn!("failed to populate local task cache from remote hit: {error}");
        }
        return Ok(Some(hit));
    }

    Ok(None)
}

fn cache_context_is_unchanged(context: &CacheContext) -> Result<bool, LpmError> {
    if let Some(validation) = &context.workspace_validation
        && !validation.is_unchanged()?
    {
        return Ok(false);
    }
    if !context.input_validation.is_unchanged()? {
        return Ok(false);
    }
    dependency_outputs_are_unchanged(&context.dependencies)
}

fn dependency_outputs_are_unchanged(
    dependencies: &[TaskDependencyIdentity],
) -> Result<bool, LpmError> {
    let mut pending = Vec::with_capacity(dependencies.len());
    pending.extend(
        dependencies
            .iter()
            .map(|dependency| dependency.node.as_ref()),
    );
    let mut visited = HashSet::with_capacity(pending.len());

    while let Some(identity) = pending.pop() {
        if !visited.insert(identity as *const CompletedTaskCacheIdentity) {
            continue;
        }
        if let Some(validation) = &identity.output_validation {
            if !validation.is_unchanged()? {
                return Ok(false);
            }
            continue;
        }
        pending.extend(
            identity
                .dependencies
                .iter()
                .map(|dependency| dependency.as_ref()),
        );
    }
    Ok(true)
}

pub(super) fn complete_task_cache_identity(
    project_dir: &Path,
    script_name: &str,
    context: &CacheContext,
) -> Option<Arc<CompletedTaskCacheIdentity>> {
    match CompletedTaskCacheIdentity::capture(project_dir, context) {
        Ok(identity) => Some(identity),
        Err(error) => {
            tracing::warn!(
                "failed to validate outputs for successful task '{}': {error}",
                lpm_common::sanitize_terminal_inline(script_name)
            );
            None
        }
    }
}

pub(super) fn try_cache_store_with_context(
    request: CacheStoreRequest<'_>,
    expected: &CacheContext,
) -> bool {
    let script_name = request.script_name;
    match store_cache_with_context(request, expected) {
        Ok(stored) => stored,
        Err(error) => {
            tracing::warn!(
                "failed to publish cache for successful task '{}': {error}",
                lpm_common::sanitize_terminal_inline(script_name)
            );
            false
        }
    }
}

fn store_cache_with_context(
    request: CacheStoreRequest<'_>,
    expected: &CacheContext,
) -> Result<bool, LpmError> {
    if !cache_context_is_unchanged(expected)? {
        tracing::warn!(
            "task cache contract, inputs, or dependencies changed while task '{}' ran; skipping cache publication",
            request.script_name
        );
        return Ok(false);
    }
    let current = match build_task_context(
        request.project_dir,
        request.workspace_contract,
        &expected.dependencies,
        request.script_name,
        request.env_mode,
        request.extra_args,
        request.bin_hint,
        None,
        RemoteCacheResolution::Omit,
    )? {
        Some(current) => current,
        None => return Ok(false),
    };
    if !cache_context_is_unchanged(&current)? {
        tracing::warn!(
            "task cache contract, inputs, or dependencies changed while task '{}' was revalidated; skipping cache publication",
            request.script_name
        );
        return Ok(false);
    }
    if current.cache_key != expected.cache_key {
        tracing::warn!(
            "task cache inputs changed while task '{}' ran; skipping cache publication",
            request.script_name
        );
        return Ok(false);
    }
    if current.task_config != expected.task_config {
        tracing::warn!(
            "task output contract changed while task '{}' ran; skipping cache publication",
            request.script_name
        );
        return Ok(false);
    }

    lpm_task::cache::store_cache(
        &expected.cache_key,
        request.project_dir,
        &expected.command,
        &expected.task_config.outputs,
        request.stdout,
        request.stderr,
        request.duration_ms,
    )?;

    if let Some(remote_cache) = &expected.remote_cache {
        crate::commands::remote_cache::try_store(
            remote_cache,
            &expected.cache_key,
            request.project_dir,
            &expected.command,
            &expected.task_config.outputs,
            request.stdout,
            request.stderr,
            request.duration_ms,
            &expected.env_vars,
            &expected.inherited_env,
        );
    }

    tracing::debug!(
        "stored cache for task '{}' (key: {}, stdout: {} bytes)",
        request.script_name,
        expected.cache_key,
        request.stdout.len()
    );
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn completed_identity(value: &str) -> Arc<CompletedTaskCacheIdentity> {
        Arc::new(CompletedTaskCacheIdentity {
            value: value.into(),
            output_validation: None,
            dependencies: Vec::new(),
        })
    }

    fn output_identity(
        value: &str,
        project_dir: &Path,
        output: &str,
        dependencies: Vec<Arc<CompletedTaskCacheIdentity>>,
    ) -> Arc<CompletedTaskCacheIdentity> {
        Arc::new(CompletedTaskCacheIdentity {
            value: value.into(),
            output_validation: Some(
                lpm_task::hasher::capture_task_output_validation(
                    project_dir,
                    &[output.to_string()],
                )
                .unwrap(),
            ),
            dependencies,
        })
    }

    fn task_with_dependencies(dependencies: &[&str]) -> lpm_runner::lpm_json::TaskConfig {
        lpm_runner::lpm_json::TaskConfig {
            depends_on: dependencies
                .iter()
                .map(|dependency| (*dependency).to_string())
                .collect(),
            ..Default::default()
        }
    }

    #[test]
    fn local_dependency_cache_identity_is_chained_into_the_dependent_task() {
        let tasks = HashMap::from([("deploy".into(), task_with_dependencies(&["build"]))]);
        let completed = HashMap::from([("build".into(), completed_identity("build-key"))]);

        let identities =
            resolve_task_dependency_identities("deploy", &tasks, &HashMap::new(), &completed);

        assert_eq!(
            identities.as_deref().map(dependency_identity_pairs),
            Some(vec![("local:build".into(), "build-key".into())])
        );
    }

    #[test]
    fn missing_local_dependency_cache_identity_disables_dependent_caching() {
        let tasks = HashMap::from([("deploy".into(), task_with_dependencies(&["build"]))]);

        let identities =
            resolve_task_dependency_identities("deploy", &tasks, &HashMap::new(), &HashMap::new());

        assert!(identities.is_none());
    }

    #[test]
    fn unavailable_workspace_dependency_identity_disables_only_its_dependent_task() {
        let workspace_dependencies = HashMap::from([("build".into(), None)]);

        let blocked = resolve_task_dependency_identities(
            "build",
            &HashMap::new(),
            &workspace_dependencies,
            &HashMap::new(),
        );
        let independent = resolve_task_dependency_identities(
            "lint",
            &HashMap::new(),
            &workspace_dependencies,
            &HashMap::new(),
        );

        assert!(blocked.is_none());
        assert!(independent.is_some_and(|identities| identities.is_empty()));
    }

    #[test]
    fn output_producing_dependency_is_a_validation_boundary() {
        let project = tempfile::tempdir().unwrap();
        std::fs::write(project.path().join("transitive.txt"), "before").unwrap();
        std::fs::write(project.path().join("direct.txt"), "stable").unwrap();
        let transitive = output_identity("transitive", project.path(), "transitive.txt", vec![]);
        let direct = output_identity("direct", project.path(), "direct.txt", vec![transitive]);
        std::fs::write(project.path().join("transitive.txt"), "after").unwrap();

        let dependencies = vec![TaskDependencyIdentity {
            label: "local:direct".into(),
            node: direct,
        }];
        assert!(dependency_outputs_are_unchanged(&dependencies).unwrap());
    }

    #[test]
    fn meta_dependency_forwards_transitive_output_validation() {
        let project = tempfile::tempdir().unwrap();
        std::fs::write(project.path().join("generated.txt"), "before").unwrap();
        let generated = output_identity("generated", project.path(), "generated.txt", vec![]);
        let meta = Arc::new(CompletedTaskCacheIdentity {
            value: "meta".into(),
            output_validation: None,
            dependencies: vec![generated],
        });
        std::fs::write(project.path().join("generated.txt"), "after").unwrap();

        let dependencies = vec![TaskDependencyIdentity {
            label: "local:meta".into(),
            node: meta,
        }];
        assert!(!dependency_outputs_are_unchanged(&dependencies).unwrap());
    }

    #[test]
    fn direct_dependency_outputs_are_rechecked_for_cache_publication() {
        let build = lpm_runner::lpm_json::TaskConfig {
            depends_on: vec!["generate".into()],
            inputs: vec!["build.js".into()],
            ..Default::default()
        };
        let config = lpm_runner::lpm_json::LpmJsonConfig {
            tasks: HashMap::from([(
                "generate".into(),
                lpm_runner::lpm_json::TaskConfig {
                    outputs: vec!["generated/**".into()],
                    ..Default::default()
                },
            )]),
            ..Default::default()
        };

        let inputs = effective_cache_inputs(&build, Some(&config));

        assert_eq!(inputs, vec!["build.js", "generated/**"]);
    }

    #[test]
    fn transitive_dependency_outputs_are_not_materialized_in_each_task() {
        let build = lpm_runner::lpm_json::TaskConfig {
            depends_on: vec!["meta".into()],
            inputs: vec!["build.js".into()],
            ..Default::default()
        };
        let config = lpm_runner::lpm_json::LpmJsonConfig {
            tasks: HashMap::from([
                (
                    "meta".into(),
                    lpm_runner::lpm_json::TaskConfig {
                        depends_on: vec!["generate".into()],
                        ..Default::default()
                    },
                ),
                (
                    "generate".into(),
                    lpm_runner::lpm_json::TaskConfig {
                        outputs: vec!["generated/**".into()],
                        ..Default::default()
                    },
                ),
            ]),
            ..Default::default()
        };

        let inputs = effective_cache_inputs(&build, Some(&config));

        assert_eq!(inputs, vec!["build.js"]);
    }
}
