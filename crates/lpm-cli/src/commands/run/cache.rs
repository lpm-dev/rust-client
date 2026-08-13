use lpm_common::LpmError;
use std::collections::HashMap;
use std::path::Path;

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
}

pub(super) struct CacheStoreRequest<'a> {
    pub(super) project_dir: &'a Path,
    pub(super) script_name: &'a str,
    pub(super) env_mode: Option<&'a str>,
    pub(super) extra_args: &'a [String],
    pub(super) bin_hint: &'a lpm_runner::bin_path::ManagedRuntimeHint,
    pub(super) duration_ms: u64,
    pub(super) stdout: &'a str,
    pub(super) stderr: &'a str,
    pub(super) lpm_config: Option<&'a lpm_runner::lpm_json::LpmJsonConfig>,
}

/// Build the cache context for a task: reads lpm.json (or uses provided config),
/// resolves the command, and computes the cache key. Returns `None` if caching
/// is not enabled or outputs are empty (shared helper eliminates
/// duplication between try_cache_store and try_cache_store_with_output).
pub(super) fn build_cache_context(
    project_dir: &Path,
    script_name: &str,
    env_mode: Option<&str>,
    extra_args: &[String],
    bin_hint: &lpm_runner::bin_path::ManagedRuntimeHint,
    lpm_config: Option<&lpm_runner::lpm_json::LpmJsonConfig>,
) -> Result<Option<CacheContext>, LpmError> {
    // Use provided config or read from disk
    let owned_config;
    let config_ref = if let Some(cfg) = lpm_config {
        Some(cfg)
    } else {
        owned_config =
            lpm_runner::lpm_json::read_lpm_json(project_dir).map_err(LpmError::Script)?;
        owned_config.as_ref()
    };

    let task_config = config_ref.and_then(|c| c.tasks.get(script_name));

    let task_config = match task_config {
        Some(tc) if tc.cache && !tc.outputs.is_empty() => tc,
        _ => return Ok(None),
    };

    let env_vars = lpm_runner::script::load_script_env(project_dir, script_name, env_mode)?;
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
    let deps_json = if pkg_json_path.exists() {
        let pkg = lpm_workspace::read_package_json(&pkg_json_path)
            .map_err(|e| LpmError::Script(format!("failed to read package.json: {e}")))?;
        serde_json::to_string(&pkg.dependencies).unwrap_or_default()
    } else {
        "{}".into()
    };

    let command = if let Some(cmd) = &task_config.command {
        cmd.clone()
    } else if pkg_json_path.exists() {
        let pkg = lpm_workspace::read_package_json(&pkg_json_path)
            .map_err(|e| LpmError::Script(format!("{e}")))?;
        pkg.scripts.get(script_name).cloned().unwrap_or_default()
    } else {
        String::new()
    };

    let cache_key = lpm_task::hasher::compute_cache_key(
        project_dir,
        &command,
        extra_args,
        &runtime_identities,
        &task_config.effective_inputs(),
        &child_env,
        &deps_json,
    );

    Ok(Some(CacheContext {
        task_config: task_config.clone(),
        cache_key,
        command,
        env_vars,
        inherited_env,
        remote_cache: crate::commands::remote_cache::client_from_config(config_ref),
    }))
}

/// Check for a cache hit. Returns `None` if caching is disabled, outputs are
/// empty (matches the `is_task_cached_with_config` predicate), or no hit
/// exists. Callers thread a pre-read `lpm.json` through to avoid re-reading
/// per task in parallel execution.
pub(super) fn try_cache_hit_with_config(
    project_dir: &Path,
    script_name: &str,
    env_mode: Option<&str>,
    extra_args: &[String],
    bin_hint: &lpm_runner::bin_path::ManagedRuntimeHint,
    lpm_config: Option<&lpm_runner::lpm_json::LpmJsonConfig>,
) -> Result<Option<lpm_task::cache::CacheHit>, LpmError> {
    let ctx = match build_cache_context(
        project_dir,
        script_name,
        env_mode,
        extra_args,
        bin_hint,
        lpm_config,
    )? {
        Some(ctx) => ctx,
        None => return Ok(None),
    };

    if lpm_task::cache::has_cache_hit(&ctx.cache_key) {
        let hit = lpm_task::cache::restore_cache(&ctx.cache_key, project_dir)?;
        return Ok(Some(hit));
    }

    if let Some(remote_cache) = &ctx.remote_cache
        && let Some(hit) =
            crate::commands::remote_cache::try_restore(remote_cache, &ctx.cache_key, project_dir)
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

/// Store cache with captured stdout/stderr. Callers thread a pre-read
/// `lpm.json` through to avoid re-reading per task in parallel execution.
pub(super) fn try_cache_store_with_output_and_config(
    request: CacheStoreRequest<'_>,
) -> Result<(), LpmError> {
    let ctx = match build_cache_context(
        request.project_dir,
        request.script_name,
        request.env_mode,
        request.extra_args,
        request.bin_hint,
        request.lpm_config,
    )? {
        Some(ctx) => ctx,
        None => return Ok(()),
    };

    lpm_task::cache::store_cache(
        &ctx.cache_key,
        request.project_dir,
        &ctx.command,
        &ctx.task_config.outputs,
        request.stdout,
        request.stderr,
        request.duration_ms,
    )?;

    if let Some(remote_cache) = &ctx.remote_cache {
        crate::commands::remote_cache::try_store(
            remote_cache,
            &ctx.cache_key,
            request.project_dir,
            &ctx.command,
            &ctx.task_config.outputs,
            request.stdout,
            request.stderr,
            request.duration_ms,
            &ctx.env_vars,
            &ctx.inherited_env,
        );
    }

    tracing::debug!(
        "stored cache for task '{}' (key: {}, stdout: {} bytes)",
        request.script_name,
        ctx.cache_key,
        request.stdout.len()
    );
    Ok(())
}
