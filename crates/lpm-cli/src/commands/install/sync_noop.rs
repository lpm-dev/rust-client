use std::path::Path;

use lpm_common::LpmError;

pub(crate) fn is_up_to_date(
    project_dir: &Path,
    package_json: &str,
    mode: crate::install_state::FastLaneMode,
) -> Result<bool, LpmError> {
    let json_output = mode.json;
    let package_json = lpm_common::strip_utf8_bom_str(package_json);
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
        || crate::commands::root_lifecycle::RootProjectLifecycle::from_package(
            project_dir,
            &package,
        )
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
    let (linker, _) = crate::linker_config::resolve_effective_linker_with_source_and_workspace(
        None, &package, &global, false,
    )
    .map_err(LpmError::Registry)?;
    let integrity = crate::commands::config::resolve_object_integrity_policy(&global)?;
    let store_version = lpm_store::StoreVersion::from_env();
    let hash_context = crate::install_state::InstallHashContext {
        dependency_engine_key: cached_engine.key,
        security_analysis_policy: lpm_store::SecurityAnalysisPolicy::Disabled,
    };
    let frozen = match mode.frozen_lockfile {
        super::FrozenLockfileMode::Always => true,
        super::FrozenLockfileMode::Never => false,
        super::FrozenLockfileMode::Auto => super::install_running_in_ci(),
    };
    let auto_install_peers = super::setup::resolve_auto_install_peers(&package, &global);
    let routes = lpm_registry::RouteTable::from_env_and_filesystem(project_dir)
        .map_err(|error| LpmError::Registry(format!("npmrc: {error}")))?;
    let lock_path = project_dir.join(lpm_lockfile::LOCKFILE_NAME);

    let fast_has_node_engines = if let Some(proof) =
        crate::install_state::SyncNoopLockfileProof::parse_from_state(&cached_state)
        && proof.lockfile_eligible
        && (!frozen || (proof.frozen_ok && proof.auto_install_peers == auto_install_peers))
        && proof.routes_fingerprint == routes.routing_fingerprint()
        && let Some(mtime_match) = crate::install_state::check_cached_state_mtime_match(
            project_dir,
            &lock_path,
            package_json,
            &cached_state,
            linker,
            integrity,
            store_version,
            hash_context,
        )
        && mtime_match.pkg_size == proof.pkg_size
        && mtime_match.lock_size == proof.lock_size
        && mtime_match.lock_size > 0
    {
        Some(proof.has_node_engines)
    } else {
        None
    };

    let full_lockfile = if fast_has_node_engines.is_some() {
        None
    } else {
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
            store_version,
            hash_context,
        )
        .up_to_date
        {
            return Ok(false);
        }
        if !lockfile_roots_and_routes_match(
            project_dir,
            &package,
            &project_lockfile.lockfile,
            &routes,
        ) {
            return Ok(false);
        }
        if frozen
            && super::validation::frozen_install_accepts_lockfile(
                project_dir,
                &lock_path,
                &package,
                None,
                &project_lockfile.lockfile,
                auto_install_peers,
            )
            .is_err()
        {
            // The full install reports why a frozen install refuses it.
            return Ok(false);
        }
        Some(project_lockfile)
    };

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
    crate::release_age_config::ReleaseAgeResolver::resolve_config_with_context(
        &global,
        Some(&package),
        project_dir,
        None,
        &[],
        json_output,
    )?;
    let extensions = super::policy_extensions::load_policy_extension_configs(&global)?;
    let skills_ready = mode.no_skills
        || ((!crate::lpm_skills_config::LpmSkillsPreference::Config.resolve(&global)?
            || crate::commands::skills::package::materialization_complete(
                project_dir,
                package_json,
            ))
            && crate::commands::skills::project_skills_ready(project_dir));
    if !extensions.is_empty() || !skills_ready {
        return Ok(false);
    }
    let engine_policy = crate::engine_check::prepare_dependency_policy_for_standalone_root(
        project_dir,
        &package,
        &global,
        false,
        json_output,
        crate::engine_check::NodeVersionReuse::recorded(cached_engine.observed_node()),
    )?;
    // The saved key only admits a candidate. Node launchers still run before
    // success; a changed version re-enters optional filtering.
    let current_engine_key = match fast_has_node_engines {
        Some(has_node_engines) => engine_policy.freshness_key_from_flags(true, has_node_engines),
        None => engine_policy.freshness_key(
            &full_lockfile
                .as_ref()
                .expect("slow path verified project_lockfile")
                .content,
        ),
    };
    if current_engine_key != cached_engine.key {
        return Ok(false);
    }
    if cached_engine.key != "none" {
        let runtime_fingerprint = engine_policy.resolved_node_runtime_fingerprint();
        if runtime_fingerprint != cached_engine.runtime_fingerprint {
            match crate::install_state::refresh_install_hash_node_runtime_fingerprint(
                project_dir,
                cached_engine.key,
                runtime_fingerprint,
            ) {
                Ok(true) => {
                    crate::cli::keep_state_ignored_at_exit_from(project_dir);
                    crate::cli::keep_state_ignored_at_exit();
                }
                Ok(false) => {}
                Err(error) => {
                    tracing::debug!("failed to refresh the cached Node runtime fingerprint: {error}");
                }
            }
        }
    }
    Ok(true)
}

pub(super) fn compute_sync_noop_proof(
    project_dir: &Path,
    lock_path: &Path,
    package: &lpm_workspace::PackageJson,
    lockfile: &lpm_lockfile::Lockfile,
    lock_content: &str,
    routes: &lpm_registry::RouteTable,
    auto_install_peers: bool,
) -> crate::install_state::SyncNoopLockfileProofInput {
    let version_ok = lockfile.metadata.lockfile_version
        >= lpm_lockfile::LOCKFILE_VERSION_WITH_DEPENDENCY_ENGINES;
    let standalone_ok =
        lockfile.workspace_packages.is_empty() && lockfile.importers.keys().all(|k| k == ".");
    let lockfile_eligible = version_ok
        && standalone_ok
        && !requires_install_access(lockfile)
        && lockfile_roots_and_routes_match(project_dir, package, lockfile, routes);
    let frozen_ok = lockfile_eligible
        && super::validation::frozen_install_accepts_lockfile(
            project_dir,
            lock_path,
            package,
            None,
            lockfile,
            auto_install_peers,
        )
        .is_ok();
    crate::install_state::SyncNoopLockfileProofInput {
        lockfile_eligible,
        has_node_engines: crate::engine_check::lockfile_has_dependency_node_engines(lock_content),
        auto_install_peers,
        frozen_ok,
        routes_fingerprint: routes.routing_fingerprint(),
    }
}

fn lockfile_roots_and_routes_match(
    project_dir: &Path,
    package: &lpm_workspace::PackageJson,
    lockfile: &lpm_lockfile::Lockfile,
    routes: &lpm_registry::RouteTable,
) -> bool {
    let mut manifest_deps = super::manifest::manifest_install_deps(package);
    if super::manifest::normalize_jsr_manifest_deps(&mut manifest_deps).is_err() {
        return false;
    }
    let mut manifest_deps = std::borrow::Cow::Owned(manifest_deps);
    let Some(catalog_resolutions) =
        super::lockfile::current_catalog_resolutions(package, None, &mut manifest_deps)
    else {
        return false;
    };
    let optional_root_names: std::collections::HashSet<String> =
        package.optional_dependencies.keys().cloned().collect();
    let locked_packages: Vec<&lpm_lockfile::LockedPackage> = lockfile.packages.iter().collect();
    if !super::lockfile::locked_catalogs_and_roots_match_manifest(
        lockfile,
        &super::lockfile::LockedRows::indexed(&locked_packages),
        super::lockfile::LockedManifest {
            deps: &manifest_deps,
            catalog_resolutions: catalog_resolutions.as_resolutions(),
            optional_root_names: &optional_root_names,
        },
        project_dir,
        false,
    ) {
        return false;
    }
    for locked_package in &lockfile.packages {
        if !matches!(
            locked_package.source_kind(),
            Some(Ok(lpm_lockfile::Source::Registry { .. })) | None
        ) {
            return false;
        }
        let route = routes.route_for_package(&locked_package.name);
        let expected = match &route {
            lpm_registry::UpstreamRoute::Custom { target, .. } => target.base_url.as_ref(),
            _ => lpm_common::NPM_REGISTRY_URL,
        };
        if !super::lockfile::locked_registry_source_matches_url(locked_package, expected) {
            return false;
        }
    }
    true
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
    fn leftover_binary_lockfile_cannot_hide_lpm_package_from_the_lockfile() {
        let directory = tempfile::tempdir().unwrap();
        lockfile_with_packages(&["react", "@lpm.dev/alice.alpha"])
            .write_to_file(&directory.path().join(lpm_lockfile::LOCKFILE_NAME))
            .unwrap();
        std::fs::write(
            directory
                .path()
                .join(lpm_lockfile::OBSOLETE_BINARY_LOCKFILE_NAME),
            b"LPMB lists only react",
        )
        .unwrap();

        assert!(lockfile_contains_lpm_package(directory.path()));
    }

    #[test]
    fn unreadable_lockfile_requires_install_pipeline() {
        let directory = tempfile::tempdir().unwrap();

        assert!(lockfile_contains_lpm_package(directory.path()));
    }

    #[test]
    fn sync_noop_proof_fast_path_skips_lockfile_parse_and_invalidates_on_route_or_lock_change() {
        let home = tempfile::tempdir().unwrap();
        let _env = crate::test_env::ScopedEnv::set([
            ("LPM_HOME", home.path().as_os_str().to_owned()),
            ("CI", std::ffi::OsString::from("")),
        ]);
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path();
        let pkg_json = r#"{"name":"app","version":"1.0.0","dependencies":{"react":"^1.0.0"}}"#;
        std::fs::write(project.join("package.json"), pkg_json).unwrap();
        std::fs::create_dir_all(project.join("node_modules")).unwrap();

        let mut lockfile = lockfile_with_packages(&["react"]);
        lockfile.root_resolutions.insert(
            "react".to_string(),
            lpm_lockfile::LockedRootResolution {
                instance_id: None,
                package: "react".to_string(),
                version: "1.0.0".to_string(),
                source: None,
            },
        );
        let lock_path = project.join(lpm_lockfile::LOCKFILE_NAME);
        lockfile.write_to_file(&lock_path).unwrap();
        let lock_content = std::fs::read_to_string(&lock_path).unwrap();
        let package: lpm_workspace::PackageJson = serde_json::from_str(pkg_json).unwrap();
        let routes = lpm_registry::RouteTable::from_env_and_filesystem(project).unwrap();
        let proof = super::compute_sync_noop_proof(
            project,
            &lock_path,
            &package,
            &lockfile,
            &lock_content,
            &routes,
            true,
        );
        assert!(proof.lockfile_eligible);
        assert!(!proof.has_node_engines);

        let platform = lpm_store::v2::PlatformTuple::current();
        let hash = crate::install_state::compute_install_hash_v10(
            pkg_json,
            &lock_content,
            &[],
            lpm_linker::LinkerMode::Hoisted,
            lpm_store::v2::ObjectIntegrityPolicy::Source,
            &platform,
            crate::install_state::InstallHashContext {
                dependency_engine_key: "none",
                security_analysis_policy: lpm_store::SecurityAnalysisPolicy::Disabled,
            },
        );
        crate::install_state::write_install_hash_with_known_runtime_state(
            project,
            &hash,
            lpm_linker::LinkerMode::Hoisted,
            lpm_store::v2::ObjectIntegrityPolicy::Source,
            &platform,
            "none",
            crate::install_state::KnownInstallHashRuntimeState {
                lockfile_path: &lock_path,
                node_runtime_fingerprint: None,
                security_analysis_policy: lpm_store::SecurityAnalysisPolicy::Disabled,
                sync_noop_proof: Some(&proof),
            },
        )
        .unwrap();

        let mode = crate::install_state::FastLaneMode {
            json: true,
            timing: false,
            frozen_lockfile: crate::commands::install::FrozenLockfileMode::Never,
            no_skills: true,
        };
        assert!(super::is_up_to_date(project, pkg_json, mode).unwrap());

        // Changing `.npmrc` changes the route fingerprint, so the proof must miss
        // and the fallback check must reject the lockfile.
        std::fs::write(
            project.join(".npmrc"),
            "registry=https://custom.registry.example/\n",
        )
        .unwrap();
        assert!(!super::is_up_to_date(project, pkg_json, mode).unwrap());

        std::fs::remove_file(project.join(".npmrc")).unwrap();
        assert!(super::is_up_to_date(project, pkg_json, mode).unwrap());

        // Changing a package version in lpm.lock changes both content and size/mtime,
        // invalidating both the fast-lane proof and the fallback lockfile check.
        let mut modified_lockfile = lockfile_with_packages(&["react", "left-pad"]);
        modified_lockfile.root_resolutions.insert(
            "react".to_string(),
            lpm_lockfile::LockedRootResolution {
                instance_id: None,
                package: "react".to_string(),
                version: "1.0.0".to_string(),
                source: None,
            },
        );
        modified_lockfile.write_to_file(&lock_path).unwrap();
        assert!(!super::is_up_to_date(project, pkg_json, mode).unwrap());
    }
}
