use crate::install_ui;
use lpm_common::{LpmError, LpmRoot};
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
    pub reserve_stdout: bool,
}

async fn install_dlx_target(
    client: &lpm_registry::RegistryClient,
    project_dir: &Path,
    target: &DlxTarget,
    install: &lpm_runner::isolate::IsolatedInstall,
    options: &DlxOptions<'_>,
    caller_routes: &lpm_registry::RouteTable,
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

    let expected_version = target
        .expected_identity
        .as_ref()
        .map(|expected| expected.version.as_str());
    client.invalidate_routed_metadata_cache(
        &lpm_registry::UpstreamRoute::NpmDirect,
        &target.package_name,
        expected_version,
    );
    if let route @ lpm_registry::UpstreamRoute::Custom { .. } =
        caller_routes.route_for_package(&target.package_name)
    {
        client.invalidate_routed_metadata_cache(&route, &target.package_name, expected_version);
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
        Some(crate::commands::install::InstallCallerContext {
            route_table: caller_routes.clone(),
            policy_project_dir: Some(project_dir),
            expected_root: target.expected_identity.as_ref().map(|identity| {
                crate::commands::install::ExpectedInstallRoot {
                    name: identity.package_name.clone(),
                    version: identity.version.clone(),
                    source: identity.registry_source.clone(),
                    integrity: identity.integrity.clone(),
                }
            }),
        }),
        lpm_common::LpmRoot::from_env()?,
    )
    .await
}

/// The cache entry's key: the target, and the receipt of the caller policy
/// its install ran under, when that policy allows reuse.
fn dlx_entry_key<'a>(cache_key: &'a str, receipt: Option<&str>) -> std::borrow::Cow<'a, str> {
    match receipt {
        Some(receipt) => std::borrow::Cow::Owned(format!("{cache_key}\0{receipt}")),
        None => std::borrow::Cow::Borrowed(cache_key),
    }
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

/// The package `lpm create <initializer>` runs, following npm's
/// initializer naming: `foo` → `create-foo`, `@scope` → `@scope/create`,
/// `@scope/foo` → `@scope/create-foo`, keeping any `@version` suffix.
pub fn initializer_package(initializer: &str) -> Result<String, LpmError> {
    let invalid = || {
        LpmError::Script(format!(
            "`{}` is not an initializer name; try `lpm create vite`",
            lpm_common::sanitize_terminal_inline(initializer)
        ))
    };
    if initializer.is_empty() || initializer.starts_with('-') || initializer.contains(['\\', ' ']) {
        return Err(invalid());
    }
    let (scope, rest) = match initializer.strip_prefix('@') {
        Some(scoped) => {
            let end = scoped.find(['/', '@']).unwrap_or(scoped.len());
            (Some(&scoped[..end]), &scoped[end..])
        }
        None => (None, initializer),
    };
    if scope.is_some_and(str::is_empty) {
        return Err(invalid());
    }
    let (name, version) = match rest.strip_prefix('/') {
        Some(named) => {
            let end = named.find('@').unwrap_or(named.len());
            (Some(&named[..end]), &named[end..])
        }
        None if scope.is_some() => (None, rest),
        None => {
            let end = rest.find('@').unwrap_or(rest.len());
            (Some(&rest[..end]), &rest[end..])
        }
    };
    if name.is_some_and(str::is_empty) || (!version.is_empty() && version.len() == 1) {
        return Err(invalid());
    }
    Ok(match (scope, name) {
        (Some(scope), Some(name)) => format!("@{scope}/create-{name}{version}"),
        (Some(scope), None) => format!("@{scope}/create{version}"),
        (None, Some(name)) => format!("create-{name}{version}"),
        (None, None) => return Err(invalid()),
    })
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
    let target = resolve_dlx_target(&caller_root, package_spec)?;
    let caller_policy = super::dlx_policy::authorize(client, &caller_root, &options)?;
    let receipt = caller_policy.receipt.as_deref();
    // Each caller policy has its own entry, so running a tool in another
    // project doesn't replace the entry this one reuses.
    let entry_key = dlx_entry_key(&target.cache_key, receipt);
    // The cache's migration and sweep run only while no dlx run holds it, so
    // before this one takes its hold.
    let cache_dir = lpm_runner::dlx::dlx_cache_dir(&entry_key)?;
    lpm_common::with_shared_lock_async(root.cache_root().join(".dlx.lock"), async {
        let install = lpm_runner::isolate::IsolatedInstall::ephemeral(
            &target.install_spec, cache_dir, std::time::Duration::from_secs(lpm_runner::dlx::CACHE_TTL_SECS),
        );
        let cache_parent = install.root().parent().ok_or_else(|| LpmError::Script("dlx cache has no parent".into()))?;
        lpm_runner::dlx::create_cache_dir(cache_parent)?;
        let lock_path = cache_parent.join(".entry-locks").join(format!("{}.lock", lpm_runner::dlx::deterministic_hash(&entry_key)));
        let mut force_refresh = options.refresh;
        let mut prepared_generation = None;
        install_ui::phase_line(crate::install_ui::terminal_line!("Resolving {}", install_ui::yellow(package_spec)));
        loop {
            if !force_refresh {
                let executed = lpm_common::with_shared_lock_async(lock_path.clone(), async {
                    caller_policy.recheck(client, &caller_root)?;
                    let Some(identity) = cached_dlx_identity(&install, &target, receipt, prepared_generation.as_deref()) else { return Ok(false) };
                    let mut command = lpm_runner::dlx::build_dlx_command(project_dir, install.root(), &target.install_spec, options.extra_args)?;
                    check_dlx_execution_engines(&command, project_dir, &caller_root, install.root(), options.reserve_stdout)?;
                    if prepared_generation.is_none() {
                        install_ui::phase_line(crate::install_ui::terminal_line!("Reusing dlx cache entry ({})", install_ui::status_ok("fresh")));
                    }
                    print_dlx_identity(&identity);
                    install_ui::warn_untrusted(&format!("running `{package_spec}` inherits cwd privileges; credential env vars are stripped"));
                    let tool = super::nested_pm::ToolRun::attach(&mut command);
                    let result = lpm_runner::dlx::exec_built_dlx_command(command, &target.install_spec);
                    tool.report(package_spec, project_dir);
                    result?;
                    Ok(true)
                }).await?;
                if executed { return Ok(()); }
            }
            prepared_generation = lpm_common::with_exclusive_lock_async(lock_path.clone(), async {
                caller_policy.recheck(client, &caller_root)?;
                if !force_refresh && cached_dlx_identity(&install, &target, receipt, None).is_some() { return Ok(None); }
                if install.root().exists() {
                    install_ui::phase_line(crate::install_ui::terminal_line!("Refreshing dlx cache entry for {}", install_ui::yellow(package_spec)));
                }
                let stage = tempfile::Builder::new().prefix(".staging-").tempdir_in(cache_parent)?;
                let staged_install = lpm_runner::isolate::IsolatedInstall::ephemeral(
                    &target.install_spec, stage.path(), std::time::Duration::from_secs(lpm_runner::dlx::CACHE_TTL_SECS),
                );
                install_dlx_target(client, &caller_root, &target, &staged_install, &options, &caller_policy.routes).await?;
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
            target: "lpm_cli::dlx",
            "The dlx entry was replaced but its previous installation could not be removed: {error}"
        );
    }
    Ok(())
}

#[cfg(test)]
mod entry_tests {
    use super::*;

    #[test]
    fn replace_runtime_entry_keeps_the_active_entry_when_promotion_fails() {
        let temp = tempfile::tempdir().unwrap();
        let active = temp.path().join("entry");
        let previous = temp.path().join("entry.previous");
        std::fs::create_dir_all(&active).unwrap();
        std::fs::write(active.join("package.json"), "{}").unwrap();

        replace_runtime_entry(&active, &previous, &temp.path().join("missing-staged")).unwrap_err();

        assert_eq!(
            std::fs::read_to_string(active.join("package.json")).unwrap(),
            "{}"
        );
        assert!(!previous.exists());
    }
}

#[cfg(test)]
mod initializer_tests {
    use super::initializer_package;

    #[test]
    fn initializer_names_follow_npm_create_naming() {
        for (initializer, package) in [
            ("vite", "create-vite"),
            ("vite@6", "create-vite@6"),
            ("vite@latest", "create-vite@latest"),
            ("@scope", "@scope/create"),
            ("@scope@2.0.0", "@scope/create@2.0.0"),
            ("@scope/app", "@scope/create-app"),
            ("@scope/app@next", "@scope/create-app@next"),
        ] {
            assert_eq!(
                initializer_package(initializer).unwrap(),
                package,
                "{initializer}"
            );
        }
        for invalid in ["", "-y", "@", "@/app", "vite@", "a b"] {
            assert!(initializer_package(invalid).is_err(), "{invalid:?}");
        }
    }
}
