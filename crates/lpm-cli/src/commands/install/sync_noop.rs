use std::path::Path;

use lpm_common::LpmError;

pub(crate) fn is_up_to_date(
    project_dir: &Path,
    package_json: &str,
    json_output: bool,
) -> Result<bool, LpmError> {
    let Ok(cached_state) = lpm_common::read_text_file_capped(
        &project_dir.join(".lpm/install-hash"),
        lpm_common::STATE_FILE_SIZE_CAP_BYTES,
    ) else {
        return Ok(false);
    };
    let Some(cached_engine) = super::state::parse_cached_dependency_engine_state(&cached_state)
    else {
        return Ok(false);
    };
    if cached_engine.key != "none"
        && cached_engine
            .key
            .strip_prefix("1:")
            .is_none_or(|version| lpm_semver::Version::parse(version).is_err())
    {
        return Ok(false);
    }
    let Ok(package) = serde_json::from_str::<lpm_workspace::PackageJson>(package_json) else {
        return Ok(false);
    };
    if crate::install_recovery::pending(project_dir)
        || project_dir.join("Package.swift").exists()
        || crate::commands::root_lifecycle::RootProjectLifecycle::from_package(&package)
            .has_scripts()
        || lpm_workspace::find_workspace_root(project_dir)
            .map_err(|error| LpmError::Workspace(error.to_string()))?
            .is_some()
    {
        return Ok(false);
    }
    let global = crate::commands::config::GlobalConfig::load_checked()?;
    crate::npm_firewall_config::config_policy_profile(&global)?;
    crate::lpm_insights_config::read_fetch_lpm_security_insights(&global)?;
    if super::peer::resolve_strict_peer_dependencies(None, &package, &global) {
        return Ok(false);
    }
    let analysis_enabled = crate::source_analysis_config::resolve_install_time_source_analysis(
        &global,
        project_dir,
        json_output,
    )?;
    if analysis_enabled {
        return Ok(false);
    }
    let linker = crate::linker_config::resolve_effective_linker_from_bytes(
        None,
        package_json,
        &global,
        project_dir,
    )
    .map_err(LpmError::Registry)?;
    let integrity = crate::commands::config::resolve_object_integrity_policy(&global)?;
    let Ok(project_lockfile) = lpm_lockfile::Lockfile::read_for_project(project_dir) else {
        return Ok(false);
    };
    if project_lockfile.workspace_root.is_some()
        || project_lockfile.lockfile.metadata.lockfile_version
            < lpm_lockfile::LOCKFILE_VERSION_WITH_DEPENDENCY_ENGINES
        || requires_install_access(&project_lockfile.lockfile)
    {
        return Ok(false);
    }
    if !crate::install_state::check_install_state_with_lockfile(
        project_dir,
        package_json,
        &project_lockfile,
        linker,
        integrity,
        lpm_store::StoreVersion::from_env(),
        crate::install_state::InstallHashContext {
            dependency_engine_key: cached_engine.key,
            security_analysis_policy: lpm_store::SecurityAnalysisPolicy::Disabled,
        },
    )
    .up_to_date
    {
        return Ok(false);
    }
    if std::env::var_os("LPM_INTERNAL_TEST_NPM_REGISTRY_URL").is_some() {
        return Ok(false);
    }
    let routes = lpm_registry::RouteTable::from_env_and_filesystem(project_dir)
        .map_err(|error| LpmError::Registry(format!("npmrc: {error}")))?;
    for package in &project_lockfile.lockfile.packages {
        if !matches!(
            package.source_kind(),
            Some(Ok(lpm_lockfile::Source::Registry { .. })) | None
        ) {
            return Ok(false);
        }
        let route = routes.route_for_package(&package.name);
        let expected = match &route {
            lpm_registry::UpstreamRoute::Custom { target, .. } => target.base_url.as_ref(),
            _ => lpm_common::NPM_REGISTRY_URL,
        };
        if !super::lockfile::locked_registry_source_matches_url(package, expected) {
            return Ok(false);
        }
    }
    crate::release_plan::ensure_no_pending_release_transaction(project_dir)?;
    super::validation::validate_project_layout(project_dir)?;
    super::setup::check_project_policy(
        &global,
        project_dir,
        project_dir,
        &project_dir.join("package.json"),
        &package,
        json_output,
    )?;
    crate::release_age_config::ReleaseAgeResolver::resolve_config(
        project_dir,
        None,
        &[],
        json_output,
    )?;
    let extensions = super::policy_extensions::load_policy_extension_configs(&global)?;
    let skills_ready = !crate::lpm_skills_config::LpmSkillsPreference::Config.resolve(&global)?
        || crate::commands::skills::package::materialization_complete(project_dir, package_json);
    if !extensions.is_empty() || !skills_ready {
        return Ok(false);
    }
    let engine_policy =
        crate::engine_check::prepare_dependency_policy(project_dir, false, json_output)?;
    // The saved key only admits a candidate. Context-sensitive Node launchers
    // still run before success; a changed version re-enters optional filtering.
    Ok(engine_policy.freshness_key(&project_lockfile.content) == cached_engine.key)
}

fn requires_install_access(lockfile: &lpm_lockfile::Lockfile) -> bool {
    lockfile
        .packages
        .iter()
        .any(|package| package.name.starts_with("@lpm.dev/"))
}

#[cfg(test)]
fn lockfile_contains_lpm_package(project_dir: &Path) -> bool {
    lpm_lockfile::Lockfile::read_for_project(project_dir)
        .map_or(true, |project| requires_install_access(&project.lockfile))
}

#[cfg(test)]
mod tests {
    use super::lockfile_contains_lpm_package;

    fn lockfile_with_packages(names: &[&str]) -> lpm_lockfile::Lockfile {
        let mut lockfile = lpm_lockfile::Lockfile::new();
        lockfile.metadata.lockfile_version = lpm_lockfile::LOCKFILE_VERSION_WITH_STRUCTURED_PEERS;
        for name in names {
            lockfile.add_package(lpm_lockfile::LockedPackage {
                instance_id: None,
                dependency_targets: std::collections::BTreeMap::new(),
                peer_targets: std::collections::BTreeMap::new(),
                name: (*name).to_string(),
                version: "1.0.0".to_string(),
                ..lpm_lockfile::LockedPackage::default()
            });
        }
        lockfile
    }

    #[test]
    fn npm_only_toml_lockfile_allows_synchronous_fast_lane() {
        let directory = tempfile::tempdir().unwrap();
        lockfile_with_packages(&["react", "@types/node"])
            .write_to_file(&directory.path().join(lpm_lockfile::LOCKFILE_NAME))
            .unwrap();

        assert!(!lockfile_contains_lpm_package(directory.path()));
    }

    #[test]
    fn lpm_package_in_toml_lockfile_requires_install_pipeline() {
        let directory = tempfile::tempdir().unwrap();
        lockfile_with_packages(&["react", "@lpm.dev/alice.alpha"])
            .write_to_file(&directory.path().join(lpm_lockfile::LOCKFILE_NAME))
            .unwrap();

        assert!(lockfile_contains_lpm_package(directory.path()));
    }

    #[test]
    fn lpm_package_in_binary_lockfile_requires_install_pipeline() {
        let directory = tempfile::tempdir().unwrap();
        let lockfile = lockfile_with_packages(&["react", "@lpm.dev/bob.beta"]);
        lockfile
            .write_to_file(&directory.path().join(lpm_lockfile::LOCKFILE_NAME))
            .unwrap();
        lpm_lockfile::binary::write_binary(
            &lockfile,
            &directory.path().join(lpm_lockfile::BINARY_LOCKFILE_NAME),
        )
        .unwrap();

        assert!(lockfile_contains_lpm_package(directory.path()));
    }

    #[test]
    fn binary_lockfile_cannot_hide_lpm_package_from_authoritative_toml() {
        let directory = tempfile::tempdir().unwrap();
        let authoritative = lockfile_with_packages(&["react", "@lpm.dev/alice.alpha"]);
        authoritative
            .write_to_file(&directory.path().join(lpm_lockfile::LOCKFILE_NAME))
            .unwrap();
        let crafted_binary = lockfile_with_packages(&["react"]);
        lpm_lockfile::binary::write_binary(
            &crafted_binary,
            &directory.path().join(lpm_lockfile::BINARY_LOCKFILE_NAME),
        )
        .unwrap();

        assert!(lockfile_contains_lpm_package(directory.path()));
    }

    #[test]
    fn unreadable_lockfile_requires_install_pipeline() {
        let directory = tempfile::tempdir().unwrap();

        assert!(lockfile_contains_lpm_package(directory.path()));
    }
}
