use lpm_common::LpmError;
use lpm_runtime::task_identity::{TaskRuntimeIdentity, TaskRuntimeScope, TaskRuntimeVersions};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock};

/// Runtime versions probed for task-cache keys, shared by every task of this
/// process.
static TASK_RUNTIME_VERSIONS: LazyLock<TaskRuntimeVersions> =
    LazyLock::new(|| TaskRuntimeVersions::new(crate::engine_check::recorded_node_versions()));

#[derive(Clone)]
pub(super) struct WorkspaceCacheContract {
    root: PathBuf,
    fingerprint: lpm_task::hasher::WorkspaceContractFingerprint,
    validation: lpm_task::hasher::FilesystemValidation,
}

impl WorkspaceCacheContract {
    pub(super) fn capture(root: &Path) -> Result<Self, LpmError> {
        let snapshot = lpm_task::hasher::compute_workspace_contract_snapshot(root)?;
        Ok(Self {
            root: root.to_path_buf(),
            fingerprint: snapshot.fingerprint,
            validation: snapshot.validation,
        })
    }

    /// The contract of the workspace at `root`, for a run that caches tasks.
    /// A workspace that can't be read sets `no_cache` instead: a key without
    /// the root lockfile would reuse results across dependency changes.
    pub(super) fn for_cached_run(root: &Path, no_cache: &mut bool) -> Option<Self> {
        match Self::capture(root) {
            Ok(contract) => Some(contract),
            Err(error) => {
                warn_unreadable_workspace(root, &error);
                *no_cache = true;
                None
            }
        }
    }

    /// [`Self::for_cached_run`] for the workspace that `project_dir` belongs
    /// to, so that a run from a member's directory keys its tasks as a
    /// `--filter` run from the root does. `None` outside a workspace.
    pub(super) fn for_cached_project_run(project_dir: &Path, no_cache: &mut bool) -> Option<Self> {
        match lpm_workspace::find_workspace_root(project_dir) {
            Ok(Some(root)) => Self::for_cached_run(&root, no_cache),
            Ok(None) => None,
            Err(error) => {
                warn_unreadable_workspace(project_dir, &error);
                *no_cache = true;
                None
            }
        }
    }
}

fn warn_unreadable_workspace(location: &Path, error: &dyn std::fmt::Display) {
    tracing::warn!(
        "could not read the workspace at {} ({error}); running without the task cache",
        location.display()
    );
}

/// The runtimes a task's key was computed with, rechecked against the task's
/// current `PATH` before a restore or an upload.
struct RuntimeCheck {
    bin_hint: lpm_runner::bin_path::ManagedRuntimeHint,
    identity: TaskRuntimeIdentity,
}

impl RuntimeCheck {
    fn is_unchanged(&self) -> Result<bool, LpmError> {
        // A `node_modules/.bin` created since the key was computed can select
        // another runtime, so the PATH is built again.
        let path = lpm_runner::bin_path::build_path_with_bins_pre_resolved(
            self.identity.cwd(),
            &self.bin_hint,
        )?;
        Ok(self
            .identity
            .is_unchanged_on_path(std::ffi::OsStr::new(&path)))
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
    pub(super) inherited_env: HashMap<std::ffi::OsString, std::ffi::OsString>,
    pub(super) remote_cache: Option<crate::commands::remote_cache::RemoteCacheClient>,
    workspace_validation: Option<lpm_task::hasher::FilesystemValidation>,
    input_validation: lpm_task::hasher::FilesystemValidation,
    runtime: RuntimeCheck,
    schema_snapshot: Option<Arc<lpm_env_source::SchemaSnapshot>>,
    dependencies: Vec<TaskDependencyIdentity>,
    command_preference: CommandPreference,
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

#[derive(Clone, Copy)]
enum CommandPreference {
    Task,
    PackageScript,
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
        CommandPreference::Task,
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
    command_preference: CommandPreference,
) -> Result<Option<CacheContext>, LpmError> {
    if let Some(provided_config) = lpm_config {
        if !is_task_cached_with_config(script_name, Some(provided_config)) {
            return Ok(None);
        }
        let captured_sources_unchanged = provided_config
            .env_schema_resolution
            .as_ref()
            .is_some_and(|snapshot| {
                lpm_common::read_text_file_capped(
                    &project_dir.join("lpm.json"),
                    lpm_common::CONFIG_FILE_SIZE_CAP_BYTES,
                )
                .is_ok_and(|content| {
                    snapshot.matches_root_content(content.as_bytes())
                        && snapshot.verify_dependencies().is_ok()
                })
            });
        if !captured_sources_unchanged {
            let current_config =
                lpm_runner::lpm_json::read_lpm_json(project_dir).map_err(LpmError::Script)?;
            if current_config
                .as_ref()
                .and_then(|config| config.env_schema_resolution.as_ref())
                .map(|snapshot| snapshot.fingerprint)
                != provided_config
                    .env_schema_resolution
                    .as_ref()
                    .map(|snapshot| snapshot.fingerprint)
            {
                return Ok(None);
            }
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

    let child_path =
        lpm_runner::bin_path::build_path_with_bins_pre_resolved(project_dir, bin_hint)?;

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

    let package_command = package
        .as_ref()
        .and_then(|pkg| pkg.scripts.get(script_name));
    let command = match command_preference {
        CommandPreference::Task => task_config.command.as_ref().or(package_command),
        CommandPreference::PackageScript => package_command.or(task_config.command.as_ref()),
    }
    .cloned()
    .unwrap_or_default();

    let script_context = lpm_runner::npm_context::NpmScriptContext::new(
        package.as_ref().and_then(|pkg| pkg.name.as_deref()),
        package.as_ref().and_then(|pkg| pkg.version.as_deref()),
        project_dir,
        &std::env::current_dir()?,
    );
    let env_vars = lpm_runner::script::load_script_child_env_with_config(
        project_dir,
        script_name,
        env_mode,
        config_ref,
        &child_path,
        &command,
        &script_context,
        lpm_runner::dotenv::OverridePolicy::Apply,
    )?;

    let inherited_env = lpm_runner::shell::inherited_child_env();
    let cache_env = task_config.cache_env.as_ref().map(|names| {
        names
            .iter()
            .map(|name| std::ffi::OsStr::new(name.as_str()))
            .collect::<HashSet<_>>()
    });
    // The fingerprint keeps each value's exact bytes, so inherited values that
    // are not valid UTF-8 still distinguish cache entries.
    let mut child_env: HashMap<std::ffi::OsString, std::ffi::OsString> =
        HashMap::with_capacity(inherited_env.len() + env_vars.len());
    child_env.extend(
        inherited_env
            .iter()
            .filter(|(key, _)| {
                cache_env
                    .as_ref()
                    .is_none_or(|names| names.contains(key.as_os_str()))
            })
            .map(|(key, value)| (key.clone(), value.clone())),
    );
    child_env.extend(
        env_vars
            .iter()
            .filter(|(key, _)| {
                key.as_str() != "PATH"
                    || cache_env
                        .as_ref()
                        .is_none_or(|names| names.contains(std::ffi::OsStr::new("PATH")))
            })
            .map(|(key, value)| (key.into(), value.into())),
    );
    let root = cache_key_root(project_dir, workspace_contract);
    if task_config.is_cache_portable() {
        match script_context.portable_manifest_path(&root) {
            Ok(manifest) => {
                child_env.insert("npm_package_json".into(), manifest.into());
            }
            Err(error) => {
                tracing::warn!(
                    "could not place task '{}' in its workspace ({error}); not using the cache for it",
                    lpm_common::sanitize_terminal_inline(script_name)
                );
                return Ok(None);
            }
        }
        // These name the caller's directories, not the task's, and a key that
        // held them would differ between a member directory and the workspace
        // root, or after any `cd`. A task whose output depends on one lists
        // it in cacheEnv or sets cachePortable: false.
        child_env.retain(|key, _| {
            !is_invocation_directory(key)
                || cache_env
                    .as_ref()
                    .is_some_and(|names| names.contains(key.as_os_str()))
        });
    }

    let project_variables: Vec<(std::ffi::OsString, std::ffi::OsString)> = env_vars
        .iter()
        .filter(|(name, _)| lpm_runtime::task_identity::is_version_manager_variable(name))
        .map(|(name, value)| (name.into(), value.into()))
        .collect();
    let Some(runtime) = TaskRuntimeIdentity::capture(
        project_dir,
        std::ffi::OsStr::new(&child_path),
        TaskRuntimeScope {
            workspace_root: &root,
            project_variables: &project_variables,
        },
        &TASK_RUNTIME_VERSIONS,
    ) else {
        tracing::warn!(
            "the runtime of task '{}' changed or could not be identified; not using the cache for it",
            lpm_common::sanitize_terminal_inline(script_name)
        );
        return Ok(None);
    };

    let cache_inputs = effective_cache_inputs(&task_config, config_ref);
    let schema_snapshot = config_ref.and_then(|config| config.env_schema_resolution.clone());
    if let Some(snapshot) = &schema_snapshot {
        snapshot
            .verify_dependencies()
            .map_err(|error| LpmError::EnvValidation(error.to_string()))?;
    }
    let mut dependency_pairs = dependency_identity_pairs(dependency_identities);
    if let Some(snapshot) = &schema_snapshot {
        dependency_pairs.push((
            "lpm-env-schema-closure:v1".into(),
            hex::encode(snapshot.fingerprint),
        ));
    }
    let cache_snapshot = lpm_task::hasher::compute_cache_key_snapshot_with_workspace_contract(
        project_dir,
        workspace_contract.map(|contract| &contract.fingerprint),
        &dependency_pairs,
        &command,
        extra_args,
        runtime.identities(),
        &cache_inputs,
        &child_env,
        &package_json,
    )?;

    if let Some(snapshot) = &schema_snapshot {
        snapshot
            .verify_dependencies()
            .map_err(|error| LpmError::EnvValidation(error.to_string()))?;
    }
    let remote_cache = match remote_cache {
        RemoteCacheResolution::Resolve(session) => {
            crate::commands::remote_cache::client_from_config(config_ref, session)
        }
        RemoteCacheResolution::Omit => None,
    };
    if remote_cache.is_some() && task_config.cache_env.is_none() {
        crate::commands::remote_cache::warn_task_without_cache_env(script_name);
    }
    Ok(Some(CacheContext {
        command_preference,
        task_config,
        cache_key: cache_snapshot.key,
        command,
        env_vars,
        inherited_env,
        remote_cache,
        workspace_validation: workspace_contract.map(|contract| contract.validation.clone()),
        input_validation: cache_snapshot.validation,
        runtime: RuntimeCheck {
            bin_hint: bin_hint.clone(),
            identity: runtime,
        },
        schema_snapshot,
        dependencies: dependency_identities.to_vec(),
    }))
}

/// The variables that name the directory a command was run from.
fn is_invocation_directory(key: &std::ffi::OsStr) -> bool {
    ["INIT_CWD", "PWD", "OLDPWD"].iter().any(|name| {
        if cfg!(windows) {
            key.eq_ignore_ascii_case(name)
        } else {
            key == *name
        }
    })
}

/// The directory that portable cache keys name paths from: the workspace
/// root, or the project itself outside a workspace.
fn cache_key_root(
    project_dir: &Path,
    workspace_contract: Option<&WorkspaceCacheContract>,
) -> PathBuf {
    if let Some(contract) = workspace_contract {
        return contract.root.clone();
    }
    lpm_workspace::find_workspace_root(project_dir)
        .ok()
        .flatten()
        .unwrap_or_else(|| project_dir.to_path_buf())
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
        CommandPreference::Task,
    )
}

#[expect(
    clippy::too_many_arguments,
    reason = "cache context preserves distinct execution inputs"
)]
pub(super) fn prepare_package_script_cache_context(
    project_dir: &Path,
    workspace_contract: Option<&WorkspaceCacheContract>,
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
        &[],
        script_name,
        env_mode,
        extra_args,
        bin_hint,
        lpm_config,
        RemoteCacheResolution::Resolve(session),
        CommandPreference::PackageScript,
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
            || execution_context_is_unchanged(ctx),
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

    // A remote hit also fills the local cache, from the downloaded artifact.
    Ok(ctx.remote_cache.as_ref().and_then(|remote_cache| {
        crate::commands::remote_cache::try_restore(
            remote_cache,
            &ctx.cache_key,
            project_dir,
            &ctx.task_config.outputs,
            || execution_context_is_unchanged(ctx),
        )
    }))
}

/// Whether the task's inputs and the runtimes its key names are unchanged.
/// Checked before a restore replaces outputs and before a result is published,
/// since a download or the task's own run can take long enough for either to
/// change.
fn execution_context_is_unchanged(context: &CacheContext) -> Result<bool, LpmError> {
    Ok(cache_context_is_unchanged(context)? && context.runtime.is_unchanged()?)
}

fn cache_context_is_unchanged(context: &CacheContext) -> Result<bool, LpmError> {
    if context
        .schema_snapshot
        .as_ref()
        .is_some_and(|snapshot| snapshot.verify_dependencies().is_err())
    {
        return Ok(false);
    }
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

fn warn_execution_context_changed(script_name: &str, expected: &CacheContext) {
    let script_name = lpm_common::sanitize_terminal_inline(script_name);
    match expected
        .input_validation
        .first_file_also_matched_by_outputs(&expected.task_config.outputs)
    {
        Ok(Some(path)) => tracing::warn!(
            "task '{script_name}' writes {}, which its cache inputs also match, so it is never reused from the cache; set `inputs` in lpm.json to leave out generated files",
            lpm_common::sanitize_terminal_inline(&path.display().to_string())
        ),
        _ => tracing::warn!(
            "task cache contract, inputs, dependencies, or runtime changed while task '{script_name}' ran; skipping cache publication"
        ),
    }
}

fn store_cache_with_context(
    request: CacheStoreRequest<'_>,
    expected: &CacheContext,
) -> Result<bool, LpmError> {
    // The rebuild rereads what the input snapshot doesn't cover, such as env
    // files and vault values, from disk and the vault rather than from the
    // run's earlier reads. The execution context is checked after it, so that
    // one check also covers the time the rebuild took.
    let fresh_vault_reads = lpm_runner::env_access::fresh_vault_reads();
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
        expected.command_preference,
    )? {
        Some(current) => current,
        None => return Ok(false),
    };
    drop(fresh_vault_reads);
    if !execution_context_is_unchanged(expected)? {
        warn_execution_context_changed(request.script_name, expected);
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

    let stored = lpm_task::cache::store_cache(
        &expected.cache_key,
        request.project_dir,
        &expected.command,
        &expected.task_config.outputs,
        request.stdout,
        request.stderr,
        request.duration_ms,
    )?;

    // A kept entry is another run's result, which this run's upload checks
    // don't cover.
    if let (Some(remote_cache), lpm_task::cache::StoredCacheEntry::Published(published)) =
        (&expected.remote_cache, stored)
    {
        crate::commands::remote_cache::try_store(
            remote_cache,
            published,
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
