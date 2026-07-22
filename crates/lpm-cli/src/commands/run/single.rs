use super::cache::{
    is_task_cached_with_config, try_cache_hit_with_config, try_cache_store_with_output_and_config,
};
use super::format::{print_captured_stderr, print_captured_stdout};
use super::runtime::ensure_runtime;
use super::task::reject_direct_hidden_scripts;
use crate::install_ui;
use lpm_common::LpmError;
use lpm_runner::bin_path::ManagedRuntimeHint;
use std::io::{IsTerminal, Write as _};
use std::path::Path;

fn script_command_for_display(
    project_dir: &Path,
    script_name: &str,
    lpm_config: Option<&lpm_runner::lpm_json::LpmJsonConfig>,
) -> Result<Option<String>, LpmError> {
    let pkg_json_path = project_dir.join("package.json");
    if pkg_json_path.exists() {
        let pkg = lpm_workspace::read_package_json(&pkg_json_path)
            .map_err(|e| LpmError::Script(format!("failed to read package.json: {e}")))?;
        if let Some(command) = pkg.scripts.get(script_name) {
            return Ok(Some(command.clone()));
        }
    }

    Ok(lpm_config
        .and_then(|config| config.tasks.get(script_name))
        .and_then(|task| task.command.clone()))
}

fn print_run_metadata(cache_status: &str, command: Option<&str>) {
    install_ui::detail_line(crate::install_ui::terminal_line!(
        "    {} {}",
        install_ui::dim(&format!("{:<8}", "cache")),
        cache_status,
    ));
    if let Some(command) = command {
        let command = lpm_common::sanitize_terminal_inline(command);
        install_ui::detail_line(crate::install_ui::terminal_line!(
            "    {} {}",
            install_ui::dim(&format!("{:<8}", "command")),
            command,
        ));
    }
    install_ui::detail("");
}

/// Run a script from package.json (single package).
///
/// Delegates to `lpm_runner::script::run_script()` which provides:
/// - PATH injection (`node_modules/.bin` prepended)
/// - `.env` file loading (auto + `--env` flag + `lpm.json` mapping)
/// - Pre/post script hooks (npm convention)
/// - Task caching (when enabled in `lpm.json`)
///
/// **Caller contract:** invoke [`ensure_runtime`] first and pass its return
/// value as `bin_hint`; doing so surfaces the runtime notice, performs
/// auto-install when needed, and avoids re-probing the runtime for the script.
pub async fn run(
    project_dir: &Path,
    script_name: &str,
    extra_args: &[String],
    env_mode: Option<&str>,
    no_cache: bool,
    bin_hint: &ManagedRuntimeHint,
) -> Result<(), LpmError> {
    // Read lpm.json once so the cache lookup and task predicate share the same config.
    let lpm_config = lpm_runner::lpm_json::read_lpm_json(project_dir)
        .ok()
        .flatten();
    let command = script_command_for_display(project_dir, script_name, lpm_config.as_ref())?;
    let caching_enabled = !no_cache && is_task_cached_with_config(script_name, lpm_config.as_ref());

    // Check if caching is enabled for this task
    if !no_cache
        && let Some(hit) =
            try_cache_hit_with_config(project_dir, script_name, env_mode, lpm_config.as_ref())?
    {
        // Cache hit — replay output
        if !hit.stdout.is_empty() {
            print_captured_stdout(&hit.stdout);
        }
        if !hit.stderr.is_empty() {
            print_captured_stderr(&hit.stderr);
        }
        install_ui::done_line(crate::install_ui::terminal_line!(
            "{} · restored from {} (originally {})",
            install_ui::yellow(script_name),
            install_ui::dim("cache"),
            install_ui::green(&install_ui::format_duration(
                std::time::Duration::from_millis(hit.meta.duration_ms)
            )),
        ));
        return Ok(());
    }

    install_ui::phase_line(crate::install_ui::terminal_line!(
        "Running {}",
        install_ui::yellow(script_name)
    ));
    let cache_status = if no_cache {
        "disabled"
    } else if caching_enabled {
        "miss"
    } else {
        "disabled"
    };
    print_run_metadata(cache_status, command.as_deref());

    let start = std::time::Instant::now();

    if caching_enabled {
        // Run with tee capture (output streams to terminal + captured for cache)
        let output = lpm_runner::script::run_script_captured(
            project_dir,
            script_name,
            extra_args,
            env_mode,
            bin_hint,
        )?;
        let duration_ms = start.elapsed().as_millis() as u64;
        let _ = try_cache_store_with_output_and_config(
            project_dir,
            script_name,
            env_mode,
            duration_ms,
            &output.stdout,
            &output.stderr,
            lpm_config.as_ref(),
        );
    } else {
        // Run normally (inherited stdio, no capture)
        lpm_runner::script::run_script(project_dir, script_name, extra_args, env_mode, bin_hint)?;
    }

    install_ui::done_line(crate::install_ui::terminal_line!(
        "{} · success in {}",
        install_ui::yellow(script_name),
        install_ui::green(&install_ui::format_duration(start.elapsed())),
    ));

    Ok(())
}

/// Run a script in watch mode — re-run on file changes.
///
/// Watch mode always runs fresh (no caching) — this is the correct behavior
/// for a development workflow where you want immediate feedback on every save.
/// The `--no-cache` flag has no effect in watch mode.
///
/// If the task has configured `inputs` globs in `lpm.json`, only file changes
/// matching those globs trigger a rebuild. Otherwise, any relevant file change
/// (excluding `.git/`, `node_modules/`, etc.) triggers a rebuild.
pub fn run_watch(
    project_dir: &Path,
    script_name: &str,
    extra_args: &[String],
    env_mode: Option<&str>,
    bin_hint: ManagedRuntimeHint,
) -> Result<(), LpmError> {
    reject_direct_hidden_scripts(&[script_name.to_string()])?;

    // Read task config for input globs — only trigger on relevant file changes
    let lpm_config = lpm_runner::lpm_json::read_lpm_json(project_dir)
        .ok()
        .flatten();
    let input_globs = lpm_config
        .as_ref()
        .and_then(|c| c.tasks.get(script_name))
        .map(|tc| tc.effective_inputs())
        .unwrap_or_default();

    if input_globs.is_empty() {
        install_ui::phase_untrusted(&format!(
            "Watching {} (Ctrl+C to stop)",
            lpm_common::sanitize_terminal_inline(script_name)
        ));
    } else {
        install_ui::phase_line(crate::install_ui::terminal_line!(
            "Watching {} [{}] (Ctrl+C to stop)",
            lpm_common::sanitize_terminal_inline(script_name),
            install_ui::dim(&input_globs.join(", ")),
        ));
    }

    let script = script_name.to_string();
    let args: Vec<String> = extra_args.to_vec();
    let mode = env_mode.map(|s| s.to_string());
    let dir = project_dir.to_path_buf();
    // Move the hint into the closure so each watch iteration reuses the
    // initial-startup-resolved managed runtime bin.
    let hint = bin_hint;

    lpm_task::watch::watch_and_run(
        project_dir,
        Box::new(move || {
            let mut stderr = std::io::stderr();
            if stderr.is_terminal() {
                let _ = write!(stderr, "\x1B[2J\x1B[1;1H");
                let _ = stderr.flush();
            }
            install_ui::phase_line(crate::install_ui::terminal_line!(
                "watch running {}",
                install_ui::yellow(&script)
            ));

            let result =
                lpm_runner::script::run_script(&dir, &script, &args, mode.as_deref(), &hint);

            match result {
                Ok(()) => {
                    install_ui::done_line(crate::install_ui::terminal_line!(
                        "{} completed. Waiting for changes...",
                        install_ui::yellow(&script)
                    ));
                }
                Err(e) => {
                    install_ui::failed_line(crate::install_ui::terminal_line!(
                        "{}: {}",
                        install_ui::yellow(&script),
                        lpm_common::sanitize_for_terminal(&e.to_string())
                    ));
                    install_ui::detail("  Waiting for changes...");
                }
            }
        }),
        &input_globs,
        None, // No shutdown channel — runs until Ctrl+C
    )
    .map_err(|e| LpmError::Script(format!("watch error: {e}")))?;

    Ok(())
}

/// Run a project-local binary from node_modules/.bin.
pub async fn exec(
    project_dir: &Path,
    command_name: &str,
    extra_args: &[String],
    env_mode: Option<&str>,
    no_env_check: bool,
) -> Result<(), LpmError> {
    let bin_hint = ensure_runtime(project_dir).await?;
    install_ui::phase_line(crate::install_ui::terminal_line!(
        "Executing {}",
        install_ui::yellow(command_name)
    ));
    let start = std::time::Instant::now();
    lpm_runner::script::run_local_bin(
        project_dir,
        command_name,
        extra_args,
        env_mode,
        no_env_check,
        &bin_hint,
    )?;
    install_ui::done_line(crate::install_ui::terminal_line!(
        "Done · exited 0 in {}",
        install_ui::green(&install_ui::format_duration(start.elapsed())),
    ));
    Ok(())
}

/// Execute a source file directly, auto-detecting the runtime.
pub async fn run_file(
    project_dir: &Path,
    file_path: &str,
    extra_args: &[String],
    env_mode: Option<&str>,
    no_env_check: bool,
    plain_node: bool,
) -> Result<(), LpmError> {
    let bin_hint = ensure_runtime(project_dir).await?;
    let options = exec_options(env_mode, no_env_check, plain_node, bin_hint);
    exec_once(project_dir, file_path, extra_args, &options)
}

fn exec_once(
    project_dir: &Path,
    file_path: &str,
    extra_args: &[String],
    options: &lpm_runner::exec::ExecOptions,
) -> Result<(), LpmError> {
    let plan = lpm_runner::exec::build_exec_plan(project_dir, file_path, extra_args, options)?;
    install_ui::phase_line(crate::install_ui::terminal_line!(
        "Executing {} with {}",
        lpm_common::sanitize_terminal_inline(file_path),
        install_ui::yellow(&plan.runtime_label())
    ));
    let start = std::time::Instant::now();
    lpm_runner::exec::execute_exec_plan(project_dir, &plan)?;
    install_ui::done_line(crate::install_ui::terminal_line!(
        "Done · exited 0 in {}",
        install_ui::green(&install_ui::format_duration(start.elapsed())),
    ));
    Ok(())
}

pub async fn run_file_watch(
    project_dir: &Path,
    file_path: &str,
    extra_args: &[String],
    env_mode: Option<&str>,
    no_env_check: bool,
    plain_node: bool,
) -> Result<(), LpmError> {
    let bin_hint = ensure_runtime(project_dir).await?;
    let options = exec_options(env_mode, no_env_check, plain_node, bin_hint);
    let plan = lpm_runner::exec::build_exec_plan(project_dir, file_path, extra_args, &options)?;
    let (watch_dir, input_globs) = exec_watch_scope(project_dir, &plan);

    install_ui::phase_untrusted(&format!(
        "Watching {} (Ctrl+C to stop)",
        lpm_common::sanitize_terminal_inline(file_path)
    ));

    let dir = project_dir.to_path_buf();
    let file = file_path.to_string();
    let plan_for_watch = plan;

    lpm_task::watch::watch_and_run(
        &watch_dir,
        Box::new(move || {
            let mut stderr = std::io::stderr();
            if stderr.is_terminal() {
                let _ = write!(stderr, "\x1B[2J\x1B[1;1H");
                let _ = stderr.flush();
            }

            install_ui::phase_line(crate::install_ui::terminal_line!(
                "watch executing {} with {}",
                install_ui::yellow(&file),
                install_ui::yellow(&plan_for_watch.runtime_label())
            ));
            let start = std::time::Instant::now();

            match lpm_runner::exec::execute_exec_plan(&dir, &plan_for_watch) {
                Ok(()) => {
                    install_ui::done_line(crate::install_ui::terminal_line!(
                        "{} completed in {}. Waiting for changes...",
                        install_ui::yellow(&file),
                        install_ui::green(&install_ui::format_duration(start.elapsed())),
                    ));
                }
                Err(e) => {
                    install_ui::failed_line(crate::install_ui::terminal_line!(
                        "{}: {}",
                        install_ui::yellow(&file),
                        lpm_common::sanitize_for_terminal(&e.to_string())
                    ));
                    install_ui::detail("  Waiting for changes...");
                }
            }
        }),
        &input_globs,
        None,
    )
    .map_err(|e| LpmError::Script(format!("watch error: {e}")))?;

    Ok(())
}

fn exec_options(
    env_mode: Option<&str>,
    no_env_check: bool,
    plain_node: bool,
    managed_runtime_hint: lpm_runner::bin_path::ManagedRuntimeHint,
) -> lpm_runner::exec::ExecOptions {
    lpm_runner::exec::ExecOptions {
        env_mode: env_mode.map(str::to_string),
        no_env_check,
        managed_runtime_hint,
        plain_node,
        runtime_cache_root: None,
    }
}

fn exec_watch_scope(
    project_dir: &Path,
    plan: &lpm_runner::exec::ExecPlan,
) -> (std::path::PathBuf, Vec<String>) {
    if let Ok(relative) = plan.resolved_path.strip_prefix(project_dir) {
        return (project_dir.to_path_buf(), vec![path_glob_string(relative)]);
    }

    let watch_dir = plan
        .resolved_path
        .parent()
        .map_or_else(|| project_dir.to_path_buf(), Path::to_path_buf);
    let input_globs = plan
        .resolved_path
        .file_name()
        .map(|name| vec![name.to_string_lossy().replace('\\', "/")])
        .unwrap_or_default();

    (watch_dir, input_globs)
}

fn path_glob_string(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

#[derive(Clone, Debug)]
struct DlxResolvedIdentity {
    package_name: String,
    version: String,
    integrity: Option<String>,
    source: DlxIdentitySource,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DlxIdentitySource {
    Project,
    Cache,
    Install,
}

impl DlxIdentitySource {
    fn label(self) -> &'static str {
        match self {
            Self::Project => "project lockfile",
            Self::Cache => "dlx cache lockfile",
            Self::Install => "dlx install lockfile",
        }
    }
}

#[derive(Clone, Debug)]
struct DlxTarget {
    package_name: String,
    requested_spec: String,
    install_spec: String,
    cache_key: String,
    expected_identity: Option<DlxResolvedIdentity>,
}

fn package_version_spec(name: &str, version: &str) -> String {
    format!("{name}@{version}")
}

fn identity_from_locked_package(
    package: &lpm_lockfile::LockedPackage,
    source: DlxIdentitySource,
) -> DlxResolvedIdentity {
    DlxResolvedIdentity {
        package_name: package.name.clone(),
        version: package.version.clone(),
        integrity: package.integrity.clone(),
        source,
    }
}

fn cache_key_for_identity(identity: &DlxResolvedIdentity) -> String {
    let mut key = package_version_spec(&identity.package_name, &identity.version);
    if let Some(integrity) = identity.integrity.as_deref() {
        key.push('#');
        key.push_str(integrity);
    }
    key
}

fn lockfile_package_for_dlx<'a>(
    lockfile: &'a lpm_lockfile::Lockfile,
    package_name: &str,
    requested_spec: &str,
) -> Option<&'a lpm_lockfile::LockedPackage> {
    let candidate = crate::commands::install::select_locked_package_for_requested_spec(
        lockfile,
        package_name,
        requested_spec,
    )?;

    let Some(range_text) =
        crate::commands::install::requested_range_for_locked_lookup(requested_spec)
    else {
        return Some(candidate);
    };
    let range = lpm_resolver::NpmRange::parse(&range_text).ok()?;
    let version = lpm_resolver::NpmVersion::parse(&candidate.version).ok()?;
    range.satisfies(&version).then_some(candidate)
}

fn resolve_dlx_target(project_dir: &Path, package_spec: &str) -> Result<DlxTarget, LpmError> {
    let (package_name, requested_spec) = lpm_runner::dlx::parse_package_spec(package_spec);
    let mut target = DlxTarget {
        package_name,
        requested_spec,
        install_spec: package_spec.to_string(),
        cache_key: package_spec.to_string(),
        expected_identity: None,
    };

    let lockfile_path = project_dir.join(lpm_lockfile::LOCKFILE_NAME);
    if !lockfile_path.exists() {
        return Ok(target);
    }

    let lockfile = lpm_lockfile::Lockfile::read_fast(&lockfile_path).map_err(|e| {
        LpmError::Script(format!(
            "failed to read {} for dlx resolution: {e}",
            lockfile_path.display()
        ))
    })?;
    let Some(locked) =
        lockfile_package_for_dlx(&lockfile, &target.package_name, &target.requested_spec)
    else {
        return Ok(target);
    };

    let identity = identity_from_locked_package(locked, DlxIdentitySource::Project);
    target.install_spec = package_version_spec(&identity.package_name, &identity.version);
    target.cache_key = cache_key_for_identity(&identity);
    target.expected_identity = Some(identity);
    Ok(target)
}

fn read_project_lpm_config(project_dir: &Path) -> Result<Option<serde_json::Value>, LpmError> {
    let path = project_dir.join("package.json");
    let content =
        match lpm_common::read_text_file_capped(&path, lpm_common::CONFIG_FILE_SIZE_CAP_BYTES) {
            Ok(content) => content,
            Err(lpm_common::BoundedReadError::NotFound { .. }) => return Ok(None),
            Err(e) => {
                return Err(LpmError::Script(format!(
                    "failed to read caller package.json for dlx policy: {e}"
                )));
            }
        };
    let value: serde_json::Value = serde_json::from_str(&content).map_err(|e| {
        LpmError::Script(format!(
            "failed to parse caller package.json for dlx policy: {e}"
        ))
    })?;
    Ok(value.get("lpm").cloned())
}

fn dlx_manifest_text(project_dir: &Path, install_spec: &str) -> Result<String, LpmError> {
    let (pkg_name, version_spec) = lpm_runner::dlx::parse_package_spec(install_spec);
    let mut deps = serde_json::Map::new();
    deps.insert(pkg_name, serde_json::Value::String(version_spec));

    let mut manifest = serde_json::Map::new();
    manifest.insert("private".to_string(), serde_json::Value::Bool(true));
    manifest.insert("dependencies".to_string(), serde_json::Value::Object(deps));
    if let Some(lpm_config) = read_project_lpm_config(project_dir)? {
        manifest.insert("lpm".to_string(), lpm_config);
    }

    serde_json::to_string(&serde_json::Value::Object(manifest))
        .map_err(|e| LpmError::Script(format!("failed to render dlx package.json: {e}")))
}

fn read_dlx_identity(
    root: &Path,
    package_name: &str,
    requested_spec: &str,
    source: DlxIdentitySource,
) -> Option<DlxResolvedIdentity> {
    let lockfile =
        lpm_lockfile::Lockfile::read_fast(&root.join(lpm_lockfile::LOCKFILE_NAME)).ok()?;
    let package = lockfile_package_for_dlx(&lockfile, package_name, requested_spec)?;
    Some(identity_from_locked_package(package, source))
}

fn identity_matches_expected(actual: &DlxResolvedIdentity, expected: &DlxResolvedIdentity) -> bool {
    actual.package_name == expected.package_name
        && actual.version == expected.version
        && expected
            .integrity
            .as_ref()
            .is_none_or(|integrity| actual.integrity.as_ref() == Some(integrity))
}

fn cache_identity_matches_target(identity: &DlxResolvedIdentity, target: &DlxTarget) -> bool {
    target
        .expected_identity
        .as_ref()
        .is_none_or(|expected| identity_matches_expected(identity, expected))
}

fn identity_for_display(
    target: &DlxTarget,
    root: &Path,
    source: DlxIdentitySource,
) -> DlxResolvedIdentity {
    let recorded = read_dlx_identity(root, &target.package_name, &target.requested_spec, source);
    match (target.expected_identity.as_ref(), recorded) {
        (Some(expected), Some(mut recorded)) if identity_matches_expected(&recorded, expected) => {
            recorded.source = DlxIdentitySource::Project;
            recorded
        }
        (Some(expected), _) => expected.clone(),
        (None, Some(recorded)) => recorded,
        (None, None) => DlxResolvedIdentity {
            package_name: target.package_name.clone(),
            version: target.requested_spec.clone(),
            integrity: None,
            source,
        },
    }
}

fn print_dlx_identity(identity: &DlxResolvedIdentity) {
    let package = package_version_spec(&identity.package_name, &identity.version);
    let integrity = identity.integrity.as_deref().unwrap_or("unavailable");
    install_ui::done_line(crate::install_ui::terminal_line!(
        "Resolved {} · {} {} · {} {}",
        install_ui::yellow(&package),
        install_ui::dim("integrity"),
        install_ui::cyan(integrity),
        install_ui::dim("source"),
        install_ui::cyan(identity.source.label()),
    ));
}

/// Run a package binary without installing it into the project.
///
/// Uses LPM's own install pipeline (self-hosted, no npm dependency).
/// Caches installations for 24 hours from install time. Use `--refresh` to force reinstall.
pub struct DlxOptions<'a> {
    pub extra_args: &'a [String],
    pub refresh: bool,
    pub allow_new: bool,
    pub min_release_age_override: Option<u64>,
    pub min_release_age_exclude: &'a [String],
}

pub async fn dlx(
    client: &lpm_registry::RegistryClient,
    project_dir: &Path,
    package_spec: &str,
    options: DlxOptions<'_>,
) -> Result<(), LpmError> {
    let target = resolve_dlx_target(project_dir, package_spec)?;
    let cache_dir = lpm_runner::dlx::dlx_cache_dir(&target.cache_key)?;
    let install = lpm_runner::isolate::IsolatedInstall::ephemeral(
        &target.install_spec,
        cache_dir,
        std::time::Duration::from_secs(lpm_runner::dlx::CACHE_TTL_SECS),
    );

    let markers_ready = install.is_ready();
    let cached_identity = if markers_ready {
        read_dlx_identity(
            install.root(),
            &target.package_name,
            &target.requested_spec,
            DlxIdentitySource::Cache,
        )
    } else {
        None
    };
    let was_ready = markers_ready
        && cached_identity
            .as_ref()
            .is_some_and(|identity| cache_identity_matches_target(identity, &target));
    let needs_install = options.refresh || !was_ready;
    install_ui::phase_line(crate::install_ui::terminal_line!(
        "Resolving {}",
        install_ui::yellow(package_spec)
    ));
    if !options.refresh && was_ready {
        install_ui::phase_line(crate::install_ui::terminal_line!(
            "Reusing dlx cache entry ({})",
            install_ui::status_ok("fresh"),
        ));
    } else if !options.refresh && !install.root().join("node_modules/.bin").is_dir() {
        // First install or evicted entry — silent install (matches prior dlx behavior).
    } else if !options.refresh && cached_identity.is_none() {
        install_ui::phase_line(crate::install_ui::terminal_line!(
            "Refreshing unaudited dlx cache entry for {}",
            install_ui::yellow(package_spec),
        ));
    } else if !options.refresh {
        // Markers present but TTL expired — be loud about the reinstall.
        install_ui::phase_line(crate::install_ui::terminal_line!(
            "Refreshing expired dlx cache entry for {}",
            install_ui::yellow(package_spec),
        ));
    }

    if needs_install {
        install.prepare()?;

        std::fs::write(
            install.root().join("package.json"),
            dlx_manifest_text(project_dir, &target.install_spec)?,
        )
        .map_err(|e| LpmError::Script(format!("failed to write dlx package.json: {e}")))?;

        install_ui::phase_line(crate::install_ui::terminal_line!(
            "Installing {}",
            install_ui::yellow(&target.install_spec)
        ));

        // Use the injected client so authenticated registry scopes keep their
        // configured credentials during the internal install.
        crate::commands::install::run_with_options(
            client,
            install.root(),
            false, // json_output
            false, // offline
            crate::commands::install::FrozenLockfileMode::Never,
            false, // force
            options.allow_new,
            false, // strict_integrity
            false, // no_engine_strict
            None,  // strict_peer_dependencies_override
            None,  // linker_override
            crate::lpm_skills_config::LpmSkillsPreference::Config,
            false, // no_editor_setup
            true,  // no_security_summary (dlx doesn't need it)
            false, // auto_build
            None,  // target_set: dlx is single-project
            None,  // direct_versions_out: dlx does not finalize placeholders
            None,  // requested_add_count: dlx is not an add-path install
            None,  // script_policy_override: `lpm dlx` does not expose policy flags
            None,  // advisor_override: `lpm dlx` does not expose `--advisor`
            options.min_release_age_override,
            options.min_release_age_exclude,
            crate::provenance_fetch::DriftIgnorePolicy::default(), // drift-ignore: `lpm dlx` enforces drift
            crate::provenance_fetch::VerifyPolicy::resolve_no_cli(), // verify-policy: dlx honors env + config posture chain
            crate::commands::install::InstallOmitPolicy::default(),
            // dlx does not surface its own
            // sandbox-mode flags. The env / config / default chain
            // inside `rebuild::run` still applies.
            false, // strict_sandbox
            false, // no_sandbox
            false, // verbose: internal pipeline, no user-facing Done footer
            false, // audit_after_install: internal pipeline never runs audit
            false, // timing: dlx does not expose install's --timing flag
            &[],
        )
        .await?;
    }

    let display_identity = if let Some(identity) = cached_identity
        && was_ready
    {
        match target.expected_identity.as_ref() {
            Some(expected) if identity_matches_expected(&identity, expected) => expected.clone(),
            _ => identity,
        }
    } else {
        identity_for_display(&target, install.root(), DlxIdentitySource::Install)
    };
    print_dlx_identity(&display_identity);

    tracing::warn!(
        target: "lpm_cli::dlx",
        package = display_identity.package_name,
        version = display_identity.version,
        integrity = display_identity.integrity.as_deref().unwrap_or("unavailable"),
        "lpm dlx executed `{}` after install-policy gates; the package command inherits the caller cwd and process privileges.",
        package_spec,
    );
    install_ui::warn_untrusted(&format!(
        "running `{package_spec}` inherits cwd privileges; credential env vars are stripped"
    ));

    lpm_runner::dlx::exec_dlx_binary(
        project_dir,
        install.root(),
        &target.install_spec,
        options.extra_args,
    )
}
