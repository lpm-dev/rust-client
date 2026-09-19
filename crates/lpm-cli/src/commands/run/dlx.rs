use crate::install_ui;
use lpm_common::{LpmError, LpmRoot, ResolutionFailureKind};
use std::path::Path;

#[derive(Clone, Debug)]
struct DlxResolvedIdentity {
    package_name: String,
    version: String,
    integrity: Option<String>,
    registry_source: Option<String>,
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
        registry_source: package.source.clone(),
        source,
    }
}

fn cache_key_for_identity(identity: &DlxResolvedIdentity) -> String {
    let mut key = package_version_spec(&identity.package_name, &identity.version);
    if let Some(source) = &identity.registry_source {
        key.push_str("#source=");
        key.push_str(source);
    }
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
    let range = lpm_resolver::NpmRange::parse_registry_spec(requested_spec).ok()?;
    let lookup = if range.dist_tag().is_some() {
        "*"
    } else {
        requested_spec
    };
    let candidate = crate::commands::install::select_locked_root_package(
        lockfile,
        package_name,
        package_name,
        lookup,
    )?;
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

    if lpm_resolver::NpmRange::parse_registry_spec(&target.requested_spec)
        .is_ok_and(|range| range.dist_tag().is_some())
    {
        return Ok(target);
    }

    let lockfile = match lpm_lockfile::Lockfile::read_for_project(project_dir) {
        Ok(project) => project.lockfile,
        Err(lpm_lockfile::LockfileError::NotFound(_)) => return Ok(target),
        Err(error) => {
            return Err(LpmError::Script(format!(
                "failed to read lpm.lock for dlx resolution: {error}"
            )));
        }
    };
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

fn registry_dlx_target(package_spec: &str) -> DlxTarget {
    let (package_name, requested_spec) = lpm_runner::dlx::parse_package_spec(package_spec);
    DlxTarget {
        package_name,
        requested_spec,
        install_spec: package_spec.to_string(),
        cache_key: package_spec.to_string(),
        expected_identity: None,
    }
}

fn dlx_manifest_text(install_spec: &str) -> Result<String, LpmError> {
    let (name, version) = lpm_runner::dlx::parse_package_spec(install_spec);
    serde_json::to_string(&serde_json::json!({"private": true, "dependencies": {name: version}}))
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
        && actual.registry_source == expected.registry_source
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

fn installed_dlx_identity(
    target: &DlxTarget,
    root: &Path,
) -> Result<DlxResolvedIdentity, LpmError> {
    let mut actual = read_dlx_identity(
        root,
        &target.package_name,
        &target.requested_spec,
        DlxIdentitySource::Install,
    )
    .ok_or_else(|| {
        LpmError::Script("dlx installation has no matching exact root identity".into())
    })?;
    if let Some(expected) = &target.expected_identity {
        if !identity_matches_expected(&actual, expected) {
            return Err(LpmError::Script(format!(
                "dlx installation of '{}' differs from the project lockfile version, source, or integrity",
                target.package_name
            )));
        }
        actual.source = DlxIdentitySource::Project;
    }
    Ok(actual)
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
    pub strict_integrity: bool,
    pub min_release_age_override: Option<u64>,
    pub min_release_age_exclude: &'a [String],
    pub inherit_caller_context: bool,
    pub reserve_stdout: bool,
}

async fn install_dlx_target(
    client: &lpm_registry::RegistryClient,
    project_dir: &Path,
    target: &DlxTarget,
    install: &lpm_runner::isolate::IsolatedInstall,
    options: &DlxOptions<'_>,
    caller_routes: Option<&lpm_registry::RouteTable>,
) -> Result<(), LpmError> {
    install.prepare()?;

    std::fs::write(
        install.root().join("package.json"),
        dlx_manifest_text(&target.install_spec)?,
    )
    .map_err(|e| LpmError::Script(format!("failed to write dlx package.json: {e}")))?;

    install_ui::phase_line(crate::install_ui::terminal_line!(
        "Installing {}",
        install_ui::yellow(&target.install_spec)
    ));

    let route_table = caller_routes.cloned();
    client.invalidate_metadata_cache(&target.package_name);
    if let Some(expected) = &target.expected_identity {
        client.invalidate_npm_version_metadata_cache(&target.package_name, &expected.version);
    }
    if let Some(routes) = &route_table
        && let lpm_registry::UpstreamRoute::Custom {
            target: registry,
            auth,
        } = routes.route_for_package(&target.package_name)
    {
        client.invalidate_custom_metadata_cache(
            registry.base_url.as_ref(),
            &target.package_name,
            auth.as_deref(),
        );
    }

    crate::commands::install::run_with_options_with_lpm_root(
        client,
        install.root(),
        options.reserve_stdout, // json_output
        false,                  // offline
        crate::commands::install::FrozenLockfileMode::Never,
        false,                    // force
        options.allow_new,        // allow_new
        options.strict_integrity, // strict_integrity
        false,                    // cli_no_engine_strict
        None,                     // strict_peer_dependencies_override
        None,                     // linker_override
        crate::lpm_skills_config::LpmSkillsPreference::Config,
        false,                                                   // no_editor_setup
        true,                                                    // no_security_summary
        false,                                                   // auto_build
        None,                                                    // target_set
        None,                                                    // direct_versions_out
        None,                                                    // requested_add_count
        None,                                                    // script_policy_override
        None,                                                    // advisor_override
        options.min_release_age_override,                        // min_release_age_override
        options.min_release_age_exclude,                         // min_release_age_exclude
        crate::provenance_fetch::DriftIgnorePolicy::default(),   // drift_ignore_policy
        crate::provenance_fetch::VerifyPolicy::resolve_no_cli(), // verify_policy
        crate::commands::install::InstallOmitPolicy::default(),  // omit_policy
        false,                                                   // strict_sandbox
        false,                                                   // no_sandbox
        false,                                                   // verbose
        false,                                                   // audit_after_install
        false,                                                   // timing
        &[],                                                     // compatibility_bin_names
        !options.reserve_stdout,                                 // emit_install_report
        options.reserve_stdout,
        route_table.map(
            |route_table| crate::commands::install::InstallCallerContext {
                route_table,
                policy_project_dir: Some(project_dir),
                expected_root: target.expected_identity.as_ref().map(|identity| {
                    crate::commands::install::ExpectedInstallRoot {
                        name: identity.package_name.clone(),
                        version: identity.version.clone(),
                        source: identity.registry_source.clone(),
                        integrity: identity.integrity.clone(),
                    }
                }),
            },
        ),
        lpm_common::LpmRoot::from_env()?,
    )
    .await
}

fn cached_dlx_identity(
    install: &lpm_runner::isolate::IsolatedInstall,
    target: &DlxTarget,
    receipt: Option<&str>,
    prepared_generation: Option<&str>,
) -> Option<DlxResolvedIdentity> {
    if !install.is_ready() {
        return None;
    }
    let prepared_here = prepared_generation.is_some_and(|expected| {
        std::fs::read_to_string(install.root().join(".generation"))
            .is_ok_and(|stored| stored == expected)
    });
    let receipt_matches = receipt.is_some_and(|expected| {
        std::fs::read_to_string(install.root().join(".caller-policy"))
            .is_ok_and(|stored| stored == expected)
    });
    if !prepared_here && !receipt_matches {
        return None;
    }
    let mut identity = read_dlx_identity(
        install.root(),
        &target.package_name,
        &target.requested_spec,
        if prepared_here {
            DlxIdentitySource::Install
        } else {
            DlxIdentitySource::Cache
        },
    )?;
    if !cache_identity_matches_target(&identity, target) {
        return None;
    }
    if target.expected_identity.is_some() {
        identity.source = DlxIdentitySource::Project;
    }
    Some(identity)
}

fn check_dlx_execution_engines(
    command: &std::process::Command,
    cwd: &Path,
    policy_dir: &Path,
    install_dir: &Path,
    json_output: bool,
) -> Result<(), LpmError> {
    let lockfile =
        lpm_lockfile::Lockfile::read_fast(&install_dir.join(lpm_lockfile::LOCKFILE_NAME))
            .map_err(|error| LpmError::Script(format!("invalid dlx lockfile: {error}")))?;
    if !lockfile
        .packages
        .iter()
        .any(|package| package.node_engine.is_some())
    {
        return Ok(());
    }
    let installed =
        crate::commands::manifest_metadata::installed_lockfile_paths(install_dir, &lockfile)?;
    let policy =
        crate::engine_check::dependency_policy_for_command(cwd, policy_dir, command, json_output)?;
    for package in &lockfile.packages {
        let key = crate::commands::manifest_metadata::package_metadata_key(package);
        let Some(path) = installed.get(&key) else {
            if package.optional {
                continue;
            }
            return Err(LpmError::Script(format!(
                "dlx dependency '{}@{}' is missing; retry with --refresh",
                package.name, package.version
            )));
        };
        let manifest =
            lpm_workspace::read_package_json(&path.join("package.json")).map_err(|error| {
                LpmError::Script(format!("invalid installed dlx dependency: {error}"))
            })?;
        if manifest.name.as_deref() != Some(package.name.as_str())
            || manifest.version.as_deref() != Some(package.version.as_str())
        {
            return Err(LpmError::Script(format!(
                "dlx dependency '{}' differs from its lockfile; retry with --refresh",
                package.name
            )));
        }
        if let Some(required) = &package.node_engine {
            policy.enforce_dependency(&package.name, &package.version, required, false)?;
        }
    }
    Ok(())
}

pub async fn dlx(
    client: &lpm_registry::RegistryClient,
    project_dir: &Path,
    package_spec: &str,
    options: DlxOptions<'_>,
) -> Result<(), LpmError> {
    let root = LpmRoot::from_env()?;
    lpm_common::with_shared_lock_async(
        root.store_lock(),
        dlx_under_store_lock(client, project_dir, package_spec, options, &root),
    )
    .await
}

async fn dlx_under_store_lock(
    client: &lpm_registry::RegistryClient,
    project_dir: &Path,
    package_spec: &str,
    options: DlxOptions<'_>,
    root: &LpmRoot,
) -> Result<(), LpmError> {
    let caller_root =
        lpm_workspace::find_project_root(project_dir).unwrap_or_else(|| project_dir.to_path_buf());
    let target = if options.inherit_caller_context {
        resolve_dlx_target(&caller_root, package_spec)?
    } else {
        registry_dlx_target(package_spec)
    };
    let cache_dir = lpm_runner::dlx::dlx_cache_dir(&target.cache_key)?;
    lpm_common::with_shared_lock_async(root.cache_root().join(".dlx.lock"), async {
        let install = lpm_runner::isolate::IsolatedInstall::ephemeral(
            &target.install_spec, cache_dir, std::time::Duration::from_secs(lpm_runner::dlx::CACHE_TTL_SECS),
        );
        let caller_policy = if options.inherit_caller_context {
            Some(super::dlx_policy::authorize(client, &caller_root, &options)?)
        } else { None };
        let receipt = caller_policy.as_ref().and_then(|policy| policy.receipt.as_deref());
        let cache_parent = install.root().parent().ok_or_else(|| LpmError::Script("dlx cache has no parent".into()))?;
        lpm_runner::dlx::create_cache_dir(cache_parent)?;
        let lock_path = cache_parent.join(".entry-locks").join(format!("{}.lock", lpm_runner::dlx::deterministic_hash(&target.cache_key)));
        let mut force_refresh = options.refresh;
        let mut prepared_generation = None;
        install_ui::phase_line(crate::install_ui::terminal_line!("Resolving {}", install_ui::yellow(package_spec)));
        loop {
            if !force_refresh {
                let executed = lpm_common::with_shared_lock_async(lock_path.clone(), async {
                    if let Some(policy) = &caller_policy { policy.recheck(client, &caller_root)?; }
                    let Some(identity) = cached_dlx_identity(&install, &target, receipt, prepared_generation.as_deref()) else { return Ok(false) };
                    let command = lpm_runner::dlx::build_dlx_command(project_dir, install.root(), &target.install_spec, options.extra_args)?;
                    check_dlx_execution_engines(&command, project_dir, &caller_root, install.root(), options.reserve_stdout)?;
                    if prepared_generation.is_none() {
                        install_ui::phase_line(crate::install_ui::terminal_line!("Reusing dlx cache entry ({})", install_ui::status_ok("fresh")));
                    }
                    print_dlx_identity(&identity);
                    install_ui::warn_untrusted(&format!("running `{package_spec}` inherits cwd privileges; credential env vars are stripped"));
                    lpm_runner::dlx::exec_built_dlx_command(command, &target.install_spec)?;
                    Ok(true)
                }).await?;
                if executed { return Ok(()); }
            }
            prepared_generation = lpm_common::with_exclusive_lock_async(lock_path.clone(), async {
                if let Some(policy) = &caller_policy { policy.recheck(client, &caller_root)?; }
                if !force_refresh && cached_dlx_identity(&install, &target, receipt, None).is_some() { return Ok(None); }
                if install.root().exists() {
                    install_ui::phase_line(crate::install_ui::terminal_line!("Refreshing dlx cache entry for {}", install_ui::yellow(package_spec)));
                }
                let stage = tempfile::Builder::new().prefix(".staging-").tempdir_in(cache_parent)?;
                let staged_install = lpm_runner::isolate::IsolatedInstall::ephemeral(
                    &target.install_spec, stage.path(), std::time::Duration::from_secs(lpm_runner::dlx::CACHE_TTL_SECS),
                );
                install_dlx_target(client, &caller_root, &target, &staged_install, &options, caller_policy.as_ref().map(|policy| &policy.routes)).await?;
                installed_dlx_identity(&target, stage.path())?;
                let command = lpm_runner::dlx::build_dlx_command(project_dir, stage.path(), &target.install_spec, options.extra_args)?;
                check_dlx_execution_engines(&command, project_dir, &caller_root, stage.path(), options.reserve_stdout)?;
                if let Some(receipt) = receipt { std::fs::write(stage.path().join(".caller-policy"), receipt)?; }
                let generation = hex::encode(rand::random::<[u8; 16]>());
                std::fs::write(stage.path().join(".generation"), &generation)?;
                lpm_runner::dlx::touch_cache(stage.path());
                let previous = install.root().with_extension("previous");
                replace_runtime_entry(install.root(), &previous, stage.path())?;
                lpm_common::known_projects::register(&root.known_projects(), install.root())?;
                Ok(Some(generation))
            }).await?;
            force_refresh = false;
        }
    }).await
}

#[derive(Debug)]
enum ManagedRuntimeState {
    Fresh(DlxResolvedIdentity),
    Stale(DlxResolvedIdentity),
    Missing,
}

fn managed_runtime_markers_present(root: &Path) -> bool {
    [
        root.join("package.json"),
        root.join(lpm_lockfile::LOCKFILE_NAME),
    ]
    .iter()
    .all(|path| {
        std::fs::symlink_metadata(path).is_ok_and(|metadata| metadata.file_type().is_file())
    }) && std::fs::symlink_metadata(root.join("node_modules/.bin"))
        .is_ok_and(|metadata| metadata.file_type().is_dir())
}

fn managed_runtime_state(root: &Path, target: &DlxTarget, ttl_secs: u64) -> ManagedRuntimeState {
    if !managed_runtime_markers_present(root) {
        return ManagedRuntimeState::Missing;
    }
    let Some(identity) = read_dlx_identity(
        root,
        &target.package_name,
        &target.requested_spec,
        DlxIdentitySource::Cache,
    ) else {
        return ManagedRuntimeState::Missing;
    };
    if identity
        .integrity
        .as_deref()
        .is_none_or(|integrity| lpm_common::Integrity::parse(integrity).is_err())
    {
        return ManagedRuntimeState::Missing;
    }
    if !cache_identity_matches_target(&identity, target) {
        return ManagedRuntimeState::Missing;
    }
    if lpm_runner::dlx::is_cache_fresh(root, ttl_secs) {
        ManagedRuntimeState::Fresh(identity)
    } else {
        ManagedRuntimeState::Stale(identity)
    }
}

fn remove_cache_entry(path: &Path) -> Result<(), LpmError> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {
            std::fs::remove_dir_all(path).map_err(LpmError::Io)
        }
        Ok(_) => std::fs::remove_file(path).map_err(LpmError::Io),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(LpmError::Io(error)),
    }
}

fn cache_entry_exists(path: &Path) -> Result<bool, LpmError> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(LpmError::Io(error)),
    }
}

fn recover_managed_runtime(
    active: &Path,
    previous: &Path,
    target: &DlxTarget,
    ttl_secs: u64,
) -> Result<(), LpmError> {
    if !cache_entry_exists(previous)? {
        return Ok(());
    }
    if !matches!(
        managed_runtime_state(active, target, ttl_secs),
        ManagedRuntimeState::Missing
    ) {
        remove_cache_entry(previous)?;
        return Ok(());
    }
    if matches!(
        managed_runtime_state(previous, target, ttl_secs),
        ManagedRuntimeState::Missing
    ) {
        remove_cache_entry(previous)?;
        return Ok(());
    }
    remove_cache_entry(active)?;
    std::fs::rename(previous, active).map_err(LpmError::Io)
}

fn replace_runtime_entry(active: &Path, previous: &Path, staged: &Path) -> Result<(), LpmError> {
    remove_cache_entry(previous)?;
    let had_active = cache_entry_exists(active)?;
    if had_active {
        std::fs::rename(active, previous).map_err(LpmError::Io)?;
    }
    if let Err(error) = std::fs::rename(staged, active) {
        if had_active {
            let _ = std::fs::rename(previous, active);
        }
        return Err(LpmError::Io(error));
    }
    if let Err(error) = remove_cache_entry(previous) {
        tracing::warn!(
            target: "lpm_cli::mcp",
            "Runtime refresh succeeded but the previous installation could not be removed: {error}"
        );
    }
    Ok(())
}

fn cleanup_managed_staging_dirs(cache_root: &Path) {
    let Ok(entries) = std::fs::read_dir(cache_root) else {
        return;
    };
    for entry in entries.flatten() {
        if entry
            .file_name()
            .to_str()
            .is_some_and(|name| name.starts_with(".staging-"))
        {
            let _ = remove_cache_entry(&entry.path());
        }
    }
}

fn retryable_http_status(status: u16) -> bool {
    matches!(status, 408 | 425 | 429) || (500..=599).contains(&status)
}

fn resolution_fetch_failure_is_transient(context: &lpm_common::ResolutionErrorContext) -> bool {
    if context.kind != ResolutionFailureKind::FetchFailed {
        return false;
    }
    if context.reason.starts_with("network error:") || context.reason.starts_with("rate limited") {
        return true;
    }
    context
        .reason
        .strip_prefix("HTTP ")
        .and_then(|reason| reason.split_once(':').map(|(status, _)| status))
        .and_then(|status| status.parse::<u16>().ok())
        .is_some_and(retryable_http_status)
}

fn refresh_can_use_verified_fallback(error: &LpmError) -> bool {
    match error {
        LpmError::Network(_) | LpmError::RateLimited { .. } => true,
        LpmError::Http { status, .. } => retryable_http_status(*status),
        LpmError::Resolution(context) => resolution_fetch_failure_is_transient(context),
        _ => false,
    }
}

async fn refresh_managed_runtime(
    client: &lpm_registry::RegistryClient,
    project_dir: &Path,
    target: &DlxTarget,
    cache_root: &Path,
    active: &Path,
    previous: &Path,
    ttl_secs: u64,
) -> Result<(), LpmError> {
    lpm_runner::dlx::create_cache_dir(cache_root)?;
    recover_managed_runtime(active, previous, target, ttl_secs)?;
    if matches!(
        managed_runtime_state(active, target, ttl_secs),
        ManagedRuntimeState::Fresh(_)
    ) {
        return Ok(());
    }

    cleanup_managed_staging_dirs(cache_root);
    let staging = tempfile::Builder::new()
        .prefix(".staging-")
        .tempdir_in(cache_root)
        .map_err(LpmError::Io)?;
    let install = lpm_runner::isolate::IsolatedInstall::ephemeral(
        &target.install_spec,
        staging.path(),
        std::time::Duration::from_secs(ttl_secs),
    );
    let options = DlxOptions {
        extra_args: &[],
        refresh: true,
        allow_new: false,
        strict_integrity: true,
        min_release_age_override: None,
        min_release_age_exclude: &[],
        inherit_caller_context: false,
        reserve_stdout: true,
    };
    install_dlx_target(client, project_dir, target, &install, &options, None).await?;
    lpm_runner::dlx::validate_managed_runtime_entrypoint(staging.path(), &target.install_spec)?;
    if matches!(
        managed_runtime_state(staging.path(), target, ttl_secs),
        ManagedRuntimeState::Missing
    ) {
        return Err(LpmError::Script(
            "MCP runtime installation completed without a verified executable".into(),
        ));
    }

    let staged = staging.keep();
    if let Err(error) = replace_runtime_entry(active, previous, &staged) {
        let _ = remove_cache_entry(&staged);
        return Err(error);
    }
    Ok(())
}

fn execute_managed_runtime(
    lock_path: &Path,
    project_dir: &Path,
    active: &Path,
    target: &DlxTarget,
    ttl_secs: u64,
    allow_stale: bool,
    stale_reason: Option<&'static str>,
) -> Result<Option<()>, LpmError> {
    lpm_common::with_shared_lock(lock_path, || {
        let state = managed_runtime_state(active, target, ttl_secs);
        let identity = match state {
            ManagedRuntimeState::Fresh(identity) => identity,
            ManagedRuntimeState::Stale(identity) if allow_stale => {
                if let Some(reason) = stale_reason {
                    install_ui::warn(reason);
                }
                identity
            }
            ManagedRuntimeState::Stale(_) | ManagedRuntimeState::Missing => return Ok(None),
        };
        let root = LpmRoot::from_env()?;
        lpm_common::known_projects::register(&root.known_projects(), active)?;
        print_dlx_identity(&identity);
        tracing::warn!(
            target: "lpm_cli::mcp",
            package = identity.package_name,
            version = identity.version,
            integrity = identity.integrity.as_deref().unwrap_or("unavailable"),
            "lpm mcp serve launched a verified cached runtime"
        );
        lpm_runner::dlx::exec_verified_lpm_runtime(project_dir, active, &target.install_spec, &[])?;
        Ok(Some(()))
    })
}

pub async fn managed_dlx(
    client: &lpm_registry::RegistryClient,
    project_dir: &Path,
    package_spec: &str,
) -> Result<(), LpmError> {
    let root = LpmRoot::from_env()?;
    lpm_common::with_shared_lock_async(
        root.store_lock(),
        managed_dlx_under_store_lock(client, project_dir, package_spec, &root),
    )
    .await
}

async fn managed_dlx_under_store_lock(
    client: &lpm_registry::RegistryClient,
    project_dir: &Path,
    package_spec: &str,
    root: &LpmRoot,
) -> Result<(), LpmError> {
    let target = registry_dlx_target(package_spec);
    let cache_root = root.cache_mcp();
    let active = cache_root.join("runtime");
    let previous = cache_root.join("previous");
    let lock_path = root.cache_mcp_lock();
    let ttl_secs = lpm_runner::dlx::CACHE_TTL_SECS;

    loop {
        if execute_managed_runtime(
            &lock_path,
            project_dir,
            &active,
            &target,
            ttl_secs,
            false,
            None,
        )?
        .is_some()
        {
            return Ok(());
        }

        if let Some(refresh_lock) = lpm_common::try_acquire_exclusive_lock(&lock_path)? {
            let refresh = refresh_managed_runtime(
                client,
                project_dir,
                &target,
                &cache_root,
                &active,
                &previous,
                ttl_secs,
            )
            .await;
            drop(refresh_lock);
            match refresh {
                Ok(()) => continue,
                Err(error) if refresh_can_use_verified_fallback(&error) => {
                    if execute_managed_runtime(
                        &lock_path,
                        project_dir,
                        &active,
                        &target,
                        ttl_secs,
                        true,
                        Some(
                            "MCP runtime refresh could not reach the registry; using the last verified version",
                        ),
                    )?
                    .is_some()
                    {
                        return Ok(());
                    }
                    return Err(error);
                }
                Err(error) => return Err(error),
            }
        }

        if execute_managed_runtime(
            &lock_path,
            project_dir,
            &active,
            &target,
            ttl_secs,
            true,
            Some("MCP runtime refresh deferred while the verified cache is in use"),
        )?
        .is_some()
        {
            return Ok(());
        }

        lpm_common::with_exclusive_lock_async(lock_path.clone(), async { Ok(()) }).await?;
    }
}

#[cfg(test)]
mod managed_runtime_tests {
    use super::*;

    fn resolution_fetch_failure(reason: &str) -> LpmError {
        LpmError::Resolution(Box::new(lpm_common::ResolutionErrorContext {
            package: "@lpm-registry/mcp-server".to_string(),
            requested: "latest".to_string(),
            dependency: "@lpm-registry/mcp-server".to_string(),
            required_by: None,
            kind: ResolutionFailureKind::FetchFailed,
            reason: reason.to_string(),
            available_versions: None,
            newest_version: None,
            derivation: None,
        }))
    }

    fn seed_managed_runtime(root: &Path) {
        std::fs::create_dir_all(root.join("node_modules/.bin")).unwrap();
        std::fs::write(
            root.join("package.json"),
            r#"{"private":true,"dependencies":{"@lpm-registry/mcp-server":"latest"}}"#,
        )
        .unwrap();
        let source = "registry+https://registry.npmjs.org";
        let instance_id = lpm_common::PackageInstanceId::derive(
            "@lpm-registry/mcp-server",
            "1.0.0",
            source,
            "root/@lpm-registry/mcp-server",
        );
        let mut lockfile = lpm_lockfile::Lockfile::new();
        lockfile.add_package(lpm_lockfile::LockedPackage {
            instance_id: Some(instance_id),
            name: "@lpm-registry/mcp-server".to_string(),
            version: "1.0.0".to_string(),
            source: Some(source.to_string()),
            integrity: Some(
                "sha512-z4PhNX7vuL3xVChQ1m2AB9Yg5AULVxXcg/SpIdNs6c5H0NE8XYXysP+DGNKHfuwvY7kxvUdBeoGlODJ6+SfaPg=="
                    .to_string(),
            ),
            ..Default::default()
        });
        lockfile.root_resolutions.insert(
            "@lpm-registry/mcp-server".to_string(),
            lpm_lockfile::LockedRootResolution {
                instance_id: Some(instance_id),
                package: "@lpm-registry/mcp-server".to_string(),
                version: "1.0.0".to_string(),
                source: Some(source.to_string()),
            },
        );
        lockfile
            .write_to_file(&root.join(lpm_lockfile::LOCKFILE_NAME))
            .unwrap();
    }

    #[test]
    fn managed_runtime_requires_all_completeness_markers() {
        let temp = tempfile::tempdir().unwrap();
        seed_managed_runtime(temp.path());
        let target = registry_dlx_target("@lpm-registry/mcp-server@latest");

        assert!(matches!(
            managed_runtime_state(temp.path(), &target, lpm_runner::dlx::CACHE_TTL_SECS),
            ManagedRuntimeState::Fresh(_)
        ));

        std::fs::remove_file(temp.path().join("package.json")).unwrap();

        assert!(matches!(
            managed_runtime_state(temp.path(), &target, lpm_runner::dlx::CACHE_TTL_SECS),
            ManagedRuntimeState::Missing
        ));
    }

    #[test]
    fn managed_runtime_rejects_a_lockfile_without_valid_integrity() {
        for integrity in [None, Some("sha512-invalid".to_string())] {
            let temp = tempfile::tempdir().unwrap();
            seed_managed_runtime(temp.path());
            let source = "registry+https://registry.npmjs.org";
            let instance_id = lpm_common::PackageInstanceId::derive(
                "@lpm-registry/mcp-server",
                "1.0.0",
                source,
                "root/@lpm-registry/mcp-server",
            );
            let mut lockfile = lpm_lockfile::Lockfile::new();
            lockfile.add_package(lpm_lockfile::LockedPackage {
                instance_id: Some(instance_id),
                name: "@lpm-registry/mcp-server".to_string(),
                version: "1.0.0".to_string(),
                source: Some(source.to_string()),
                integrity: integrity.clone(),
                ..Default::default()
            });
            lockfile.root_resolutions.insert(
                "@lpm-registry/mcp-server".to_string(),
                lpm_lockfile::LockedRootResolution {
                    instance_id: Some(instance_id),
                    package: "@lpm-registry/mcp-server".to_string(),
                    version: "1.0.0".to_string(),
                    source: Some(source.to_string()),
                },
            );
            let lockfile_path = temp.path().join(lpm_lockfile::LOCKFILE_NAME);
            if integrity.is_some() {
                std::fs::write(
                    &lockfile_path,
                    format!(
                        "[metadata]\nlockfile-version = {}\nresolved-with = \"greedy-fusion\"\n\n[[packages]]\nname = \"@lpm-registry/mcp-server\"\nversion = \"1.0.0\"\nintegrity = \"sha512-invalid\"\n",
                        lpm_lockfile::LOCKFILE_VERSION,
                    ),
                )
                .unwrap();
            } else {
                lockfile.write_to_file(&lockfile_path).unwrap();
            }
            let target = registry_dlx_target("@lpm-registry/mcp-server@latest");

            assert!(matches!(
                managed_runtime_state(temp.path(), &target, lpm_runner::dlx::CACHE_TTL_SECS),
                ManagedRuntimeState::Missing
            ));
        }
    }

    #[test]
    fn managed_runtime_recovery_restores_the_last_complete_runtime() {
        let temp = tempfile::tempdir().unwrap();
        let active = temp.path().join("runtime");
        let previous = temp.path().join("previous");
        seed_managed_runtime(&previous);
        let target = registry_dlx_target("@lpm-registry/mcp-server@latest");

        recover_managed_runtime(&active, &previous, &target, lpm_runner::dlx::CACHE_TTL_SECS)
            .unwrap();

        assert!(matches!(
            managed_runtime_state(&active, &target, lpm_runner::dlx::CACHE_TTL_SECS),
            ManagedRuntimeState::Fresh(_)
        ));
        assert!(!previous.exists());
    }

    #[test]
    fn managed_runtime_replacement_rolls_back_when_staged_promotion_fails() {
        let temp = tempfile::tempdir().unwrap();
        let active = temp.path().join("runtime");
        let previous = temp.path().join("previous");
        let missing_staged = temp.path().join("missing-staged");
        seed_managed_runtime(&active);
        let target = registry_dlx_target("@lpm-registry/mcp-server@latest");

        replace_runtime_entry(&active, &previous, &missing_staged).unwrap_err();

        assert!(matches!(
            managed_runtime_state(&active, &target, lpm_runner::dlx::CACHE_TTL_SECS),
            ManagedRuntimeState::Fresh(_)
        ));
        assert!(!previous.exists());
    }

    #[test]
    fn managed_runtime_fallback_accepts_only_transient_refresh_failures() {
        assert!(refresh_can_use_verified_fallback(&LpmError::Network(
            "connection reset".into()
        )));
        assert!(refresh_can_use_verified_fallback(&LpmError::Http {
            status: 503,
            message: "unavailable".into(),
        }));
        assert!(!refresh_can_use_verified_fallback(
            &LpmError::IntegrityMismatch {
                expected: "sha512-good".into(),
                actual: "sha512-bad".into(),
            }
        ));
        assert!(!refresh_can_use_verified_fallback(&LpmError::Http {
            status: 403,
            message: "forbidden".into(),
        }));
        assert!(!refresh_can_use_verified_fallback(&LpmError::Registry(
            "security policy blocked the candidate".into(),
        )));
        assert!(refresh_can_use_verified_fallback(
            &resolution_fetch_failure("network error: connection refused",)
        ));
        assert!(refresh_can_use_verified_fallback(
            &resolution_fetch_failure("HTTP 503: unavailable",)
        ));
        assert!(!refresh_can_use_verified_fallback(
            &resolution_fetch_failure("HTTP 403: forbidden"),
        ));
        assert!(!refresh_can_use_verified_fallback(
            &resolution_fetch_failure("authentication required"),
        ));
    }
}
