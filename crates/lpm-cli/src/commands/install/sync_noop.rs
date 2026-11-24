use std::path::Path;

use lpm_common::LpmError;

pub(crate) fn is_up_to_date(
    project_dir: &Path,
    package_json: &str,
    mode: &crate::install_state::FastLaneMode,
) -> Result<bool, LpmError> {
    let json_output = mode.json;
    let suppression_warnings = crate::security_floor::defer_suppression_warnings();
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
        mode.linker,
        &package,
        &global,
        false,
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
    let parsed_proof = crate::install_state::SyncNoopLockfileProof::parse_from_state(&cached_state);

    let fast_has_node_engines = if let Some(proof) = parsed_proof.as_ref()
        && proof.lockfile_eligible
        && (!frozen
            || (package
                .lpm
                .as_ref()
                .is_none_or(|lpm| lpm.patched_dependencies.is_empty())
                && proof.frozen_ok
                && proof.auto_install_peers == auto_install_peers))
        && proof.routes_fingerprint == routes.routing_fingerprint()
        && !has_ancestor_lockfile(project_dir)
        && crate::install_state::check_cached_state_mtime_match(
            project_dir,
            &lock_path,
            package_json,
            &cached_state,
            linker,
            integrity,
            store_version,
            hash_context,
        )
        .is_some_and(|m| m.lock_size > 0)
        && let Ok(lock_raw) = lpm_common::read_file_capped(
            &lock_path,
            lpm_common::STATE_FILE_SIZE_CAP_BYTES.max(64 * 1024 * 1024),
        )
        && !raw_lockfile_mentions_lpm_scope(&lock_raw)
        && crate::install_state::sync_noop_content_digest_hex(package_json.as_bytes())
            == proof.pkg_digest
        && crate::install_state::sync_noop_content_digest_hex(&lock_raw) == proof.lock_digest
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
    let cli_min_age = match mode.min_release_age.as_deref() {
        Some(raw) => match crate::release_age_config::parse_duration(raw) {
            Ok(secs) => Some(secs),
            // Let clap and the full CLI dispatch render invalid duration errors.
            Err(_) => return Ok(false),
        },
        None => None,
    };
    let cli_excludes = if mode.min_release_age_exclude.is_empty() {
        Vec::new()
    } else {
        match crate::release_age_config::validate_release_age_excludes(
            "--min-release-age-exclude",
            &mode.min_release_age_exclude,
        ) {
            Ok(excludes) => excludes,
            Err(_) => return Ok(false),
        }
    };
    let resolved_age = crate::release_age_config::ReleaseAgeResolver::resolve_config_with_context(
        &global,
        Some(&package),
        project_dir,
        cli_min_age,
        &cli_excludes,
        json_output,
    )?;
    let current_release_age_key = crate::install_state::release_age_freshness_key(
        resolved_age.minimum_release_age_secs,
        resolved_age.minimum_release_age_policy,
        &resolved_age.minimum_release_age_exclude,
        false,
    );
    if current_release_age_key.is_some()
        && crate::install_state::parse_release_age_policy_line(&cached_state)
            != current_release_age_key.as_deref()
    {
        return Ok(false);
    }
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
        mode.no_engine_strict,
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
                    tracing::debug!(
                        "failed to refresh the cached Node runtime fingerprint: {error}"
                    );
                }
            }
        }
    }
    if fast_has_node_engines.is_none()
        && let Some(project_lockfile) = full_lockfile.as_ref()
        && project_lockfile.path == lock_path
        && !has_ancestor_lockfile(project_dir)
        && !crate::install_state::package_json_needs_slow_freshness(package_json)
        && let Ok(lock_raw) = lpm_common::read_file_capped(
            &lock_path,
            lpm_common::STATE_FILE_SIZE_CAP_BYTES.max(64 * 1024 * 1024),
        )
    {
        let proof = compute_sync_noop_proof(
            project_dir,
            &lock_path,
            &package,
            package_json,
            &project_lockfile.lockfile,
            &lock_raw,
            &routes,
            auto_install_peers,
        );
        if let Ok(true) =
            crate::install_state::backfill_install_hash_sync_noop_proof(project_dir, &proof)
        {
            crate::cli::keep_state_ignored_at_exit_from(project_dir);
            crate::cli::keep_state_ignored_at_exit();
        }
    }
    suppression_warnings.flush(json_output);
    Ok(true)
}

fn has_ancestor_lockfile(project_dir: &Path) -> bool {
    let mut parent = project_dir.parent();
    while let Some(dir) = parent {
        if dir.join(lpm_lockfile::LOCKFILE_NAME).is_file() {
            return true;
        }
        parent = dir.parent();
    }
    false
}

fn raw_lockfile_mentions_lpm_scope(bytes: &[u8]) -> bool {
    const NEEDLE: &[u8] = b"@lpm.dev/";
    bytes.windows(NEEDLE.len()).any(|window| window == NEEDLE)
}

#[allow(clippy::too_many_arguments)]
pub(super) fn compute_sync_noop_proof(
    project_dir: &Path,
    lock_path: &Path,
    package: &lpm_workspace::PackageJson,
    package_json_stripped: &str,
    lockfile: &lpm_lockfile::Lockfile,
    lock_raw_bytes: &[u8],
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
        && !raw_lockfile_mentions_lpm_scope(lock_raw_bytes)
        && lockfile_roots_and_routes_match(project_dir, package, lockfile, routes);
    let frozen_ok = lockfile_eligible
        && package
            .lpm
            .as_ref()
            .is_none_or(|lpm| lpm.patched_dependencies.is_empty())
        && super::validation::frozen_install_accepts_lockfile(
            project_dir,
            lock_path,
            package,
            None,
            lockfile,
            auto_install_peers,
        )
        .is_ok();
    let has_node_engines = lockfile
        .packages
        .iter()
        .any(|pkg| pkg.node_engine.is_some());
    crate::install_state::SyncNoopLockfileProofInput {
        pkg_digest: crate::install_state::sync_noop_content_digest_hex(
            package_json_stripped.as_bytes(),
        ),
        lock_digest: crate::install_state::sync_noop_content_digest_hex(lock_raw_bytes),
        lockfile_eligible,
        has_node_engines,
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

const WORKSPACE_SYNC_NOOP_FILENAME: &str = "workspace-sync-noop.json";
const WORKSPACE_SYNC_NOOP_SCHEMA: u32 = 1;

#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
struct FileStamp {
    size: u64,
    mtime_sec: i64,
    mtime_nsec: u32,
    ctime_sec: i64,
    ctime_nsec: u32,
}

impl FileStamp {
    fn from_path(path: &Path) -> Option<Self> {
        let meta = std::fs::symlink_metadata(path).ok()?;
        if !meta.is_file() {
            return None;
        }
        let (mtime_sec, mtime_nsec, ctime_sec, ctime_nsec) = metadata_timestamps(&meta)?;
        Some(Self {
            size: meta.len(),
            mtime_sec,
            mtime_nsec,
            ctime_sec,
            ctime_nsec,
        })
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
struct DirStamp {
    rel_path: String,
    mtime_sec: i64,
    mtime_nsec: u32,
    ctime_sec: i64,
    ctime_nsec: u32,
}

impl DirStamp {
    fn from_path(root: &Path, rel: &Path) -> Option<Self> {
        let full = if rel.as_os_str().is_empty() {
            root.to_path_buf()
        } else {
            root.join(rel)
        };
        let meta = std::fs::symlink_metadata(&full).ok()?;
        if !meta.is_dir() {
            return None;
        }
        let (mtime_sec, mtime_nsec, ctime_sec, ctime_nsec) = metadata_timestamps(&meta)?;
        Some(Self {
            rel_path: rel.to_string_lossy().into_owned(),
            mtime_sec,
            mtime_nsec,
            ctime_sec,
            ctime_nsec,
        })
    }
}

fn metadata_timestamps(meta: &std::fs::Metadata) -> Option<(i64, u32, i64, u32)> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        Some((
            meta.mtime(),
            u32::try_from(meta.mtime_nsec()).ok()?,
            meta.ctime(),
            u32::try_from(meta.ctime_nsec()).ok()?,
        ))
    }
    #[cfg(not(unix))]
    {
        let modified = meta.modified().ok()?;
        let dur = modified.duration_since(std::time::UNIX_EPOCH).ok()?;
        Some((i64::try_from(dur.as_secs()).ok()?, dur.subsec_nanos(), 0, 0))
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub(crate) struct WorkspaceSyncNoopTarget {
    pub(crate) name: String,
    pub(crate) rel_path: String,
    pub(crate) kind: String,
    pkg_stamp: FileStamp,
    has_node_modules: bool,
    pub(crate) no_dependencies: bool,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
struct WorkspaceSyncNoopState {
    schema: u32,
    lockfile_version: u32,
    bin_shim_format: String,
    graph_key_schema: String,
    install_script_rules: String,
    linker: String,
    integrity: String,
    store_version: String,
    platform: String,
    auto_install_peers: bool,
    frozen_ok: bool,
    routes_fingerprint: String,
    release_age_policy_key: Option<String>,
    no_engine_strict: bool,
    has_node_engines: bool,
    dependency_engine_key: String,
    lockfile_stamp: FileStamp,
    pnpm_workspace_yaml: Option<FileStamp>,
    glob_parent_dirs: Vec<DirStamp>,
    targets: Vec<WorkspaceSyncNoopTarget>,
}

fn current_platform_key() -> String {
    let p = lpm_store::v2::PlatformTuple::current();
    format!("{}/{}/{}", p.os, p.cpu, p.libc.as_deref().unwrap_or("none"))
}

pub(crate) struct WorkspaceSyncNoopHit {
    pub(crate) targets: Vec<WorkspaceSyncNoopTarget>,
}

#[derive(Clone, Copy)]
pub(super) struct WorkspaceSyncNoopTargetInput<'a> {
    pub(super) name: &'a str,
    pub(super) path: &'a Path,
    pub(super) kind: &'static str,
    pub(super) has_scripts: bool,
    pub(super) has_dev_preinstall: bool,
    pub(super) no_dependencies: bool,
}

fn workspace_sync_noop_state_path(workspace_root: &Path) -> std::path::PathBuf {
    workspace_root
        .join(".lpm")
        .join(WORKSPACE_SYNC_NOOP_FILENAME)
}

fn remove_workspace_sync_noop_state(workspace_root: &Path) {
    let path = workspace_sync_noop_state_path(workspace_root);
    if path.exists() {
        let _ = std::fs::remove_file(&path);
    }
}

fn manifest_has_local_file_or_link(pkg_content: &str) -> bool {
    pkg_content.contains("\"file:") || pkg_content.contains("\"link:")
}

fn member_has_custom_lpm_install_policy(package: &lpm_workspace::PackageJson) -> bool {
    if !package.engines.is_empty() {
        return true;
    }
    let Some(lpm) = package.lpm.as_ref() else {
        return false;
    };
    lpm.linker.is_some()
        || lpm.auto_install_peers.is_some()
        || lpm.strict_peer_dependencies.is_some()
        || !lpm.patched_dependencies.is_empty()
        || lpm.minimum_release_age.is_some()
        || !lpm.minimum_release_age_exclude.is_empty()
}

pub(super) fn write_workspace_sync_noop_state(
    workspace: &lpm_workspace::Workspace,
    target_inputs: &[WorkspaceSyncNoopTargetInput<'_>],
    options: &super::recursive::RecursiveInstallOptions,
    filters_empty: bool,
) {
    let root = &workspace.root;
    let eligible = filters_empty
        && options.omit_policy.is_default()
        && !options.offline
        && !options.auto_build
        && options.strict_peer_dependencies_override != Some(true)
        && !target_inputs.is_empty()
        && target_inputs.iter().all(|target| {
            let scripts_eligible = if target.kind == "root" {
                !target.has_dev_preinstall
            } else {
                !target.has_scripts
            };
            scripts_eligible
                && !crate::install_recovery::pending(target.path)
                && !target.path.join("Package.swift").exists()
        })
        && !crate::install_recovery::pending(root)
        && !root.join("Package.swift").exists()
        && !root
            .join(lpm_lockfile::OBSOLETE_BINARY_LOCKFILE_NAME)
            .exists()
        && workspace
            .root_package
            .lpm
            .as_ref()
            .is_none_or(|lpm| lpm.patched_dependencies.is_empty())
        && workspace
            .members
            .iter()
            .all(|member| !member_has_custom_lpm_install_policy(&member.package));

    if !eligible {
        tracing::debug!("workspace sync-noop ineligible; clearing cached state");
        remove_workspace_sync_noop_state(root);
        return;
    }

    let state = (|| -> Result<WorkspaceSyncNoopState, String> {
        let global = crate::commands::config::GlobalConfig::load_checked()
            .map_err(|e| format!("global config: {e}"))?;
        crate::npm_firewall_config::config_policy_profile(&global)
            .map_err(|e| format!("firewall config: {e}"))?;
        crate::lpm_insights_config::read_fetch_lpm_security_insights(&global)
            .map_err(|e| format!("insights config: {e}"))?;
        if super::peer::resolve_strict_peer_dependencies(
            options.strict_peer_dependencies_override,
            &workspace.root_package,
            &global,
        ) {
            return Err("strict-peer-dependencies enabled".into());
        }
        if crate::source_analysis_config::resolve_install_time_source_analysis(
            &global,
            root,
            options.json_output,
        )
        .map_err(|e| format!("source analysis config: {e}"))?
        {
            return Err("source analysis enabled".into());
        }
        if !super::policy_extensions::load_policy_extension_configs(&global)
            .map_err(|e| format!("policy extensions: {e}"))?
            .is_empty()
        {
            return Err("policy extensions active".into());
        }

        let lock_path = root.join(lpm_lockfile::LOCKFILE_NAME);
        let lockfile_stamp =
            FileStamp::from_path(&lock_path).ok_or_else(|| "missing lockfile stamp".to_string())?;
        let lock_raw = lpm_common::read_file_capped(
            &lock_path,
            lpm_common::STATE_FILE_SIZE_CAP_BYTES.max(64 * 1024 * 1024),
        )
        .map_err(|e| format!("read lockfile: {e}"))?;
        if raw_lockfile_mentions_lpm_scope(&lock_raw) {
            return Err("lockfile references @lpm.dev/".into());
        }
        let lock_text =
            std::str::from_utf8(&lock_raw).map_err(|e| format!("lockfile utf8: {e}"))?;
        let has_node_engines = crate::engine_check::lockfile_has_dependency_node_engines(lock_text);

        let (linker, _) = crate::linker_config::resolve_effective_linker_with_source_and_workspace(
            options.linker_override,
            &workspace.root_package,
            &global,
            true,
        )
        .map_err(|e| format!("linker: {e}"))?;
        let integrity = crate::commands::config::resolve_object_integrity_policy(&global)
            .map_err(|e| format!("integrity: {e}"))?;
        let store_version = lpm_store::StoreVersion::from_env();
        let platform = current_platform_key();
        let auto_install_peers =
            super::setup::resolve_auto_install_peers(&workspace.root_package, &global);
        let routes = lpm_registry::RouteTable::from_env_and_filesystem(root)
            .map_err(|e| format!("routes: {e}"))?;
        let resolved_age =
            crate::release_age_config::ReleaseAgeResolver::resolve_config_with_context(
                &global,
                Some(&workspace.root_package),
                root,
                options.min_release_age_override,
                &options.min_release_age_exclude,
                options.json_output,
            )
            .map_err(|e| format!("release age: {e}"))?;
        let release_age_policy_key = crate::install_state::release_age_freshness_key(
            resolved_age.minimum_release_age_secs,
            resolved_age.minimum_release_age_policy,
            &resolved_age.minimum_release_age_exclude,
            false,
        );
        let engine_policy = crate::engine_check::prepare_dependency_policy_for_standalone_root(
            root,
            &workspace.root_package,
            &global,
            options.no_engine_strict,
            options.json_output,
            crate::engine_check::NodeVersionReuse::recorded(None),
        )
        .map_err(|e| format!("engine policy: {e}"))?;
        let dependency_engine_key = engine_policy.freshness_key_from_flags(true, has_node_engines);

        let state_path = workspace_sync_noop_state_path(root);
        if let Some(parent) = state_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }

        let watch_dirs = lpm_workspace::workspace_discovery_watch_dirs(root)
            .map_err(|e| format!("watch_dirs: {e}"))?;
        let mut glob_parent_dirs = Vec::with_capacity(watch_dirs.len());
        for rel in watch_dirs {
            glob_parent_dirs.push(
                DirStamp::from_path(root, &rel)
                    .ok_or_else(|| format!("dir stamp missing for {}", rel.display()))?,
            );
        }

        let mut targets = Vec::with_capacity(target_inputs.len());
        for input in target_inputs {
            let pkg_path = input.path.join("package.json");
            let pkg_content = lpm_common::read_text_file_capped(
                &pkg_path,
                lpm_common::CONFIG_FILE_SIZE_CAP_BYTES,
            )
            .map_err(|e| format!("read pkg {}: {e}", pkg_path.display()))?;
            if manifest_has_local_file_or_link(&pkg_content) {
                return Err(format!("local file/link dep in {}", pkg_path.display()));
            }
            let rel_path = if input.path == root {
                ".".to_string()
            } else {
                input
                    .path
                    .strip_prefix(root)
                    .map_err(|e| format!("strip_prefix: {e}"))?
                    .to_string_lossy()
                    .into_owned()
            };
            targets.push(WorkspaceSyncNoopTarget {
                name: input.name.to_string(),
                rel_path,
                kind: input.kind.to_string(),
                pkg_stamp: FileStamp::from_path(&pkg_path)
                    .ok_or_else(|| format!("pkg stamp missing for {}", pkg_path.display()))?,
                has_node_modules: input.path.join("node_modules").is_dir(),
                no_dependencies: input.no_dependencies,
            });
        }

        let pnpm_yaml_path = root.join("pnpm-workspace.yaml");
        let pnpm_workspace_yaml = if pnpm_yaml_path.exists() {
            Some(
                FileStamp::from_path(&pnpm_yaml_path)
                    .ok_or_else(|| "pnpm-workspace.yaml stamp missing".to_string())?,
            )
        } else {
            None
        };

        Ok(WorkspaceSyncNoopState {
            schema: WORKSPACE_SYNC_NOOP_SCHEMA,
            lockfile_version: lpm_lockfile::LOCKFILE_VERSION,
            bin_shim_format: lpm_linker::BIN_SHIM_FORMAT.to_string(),
            graph_key_schema: lpm_store::v2::GraphKey::SCHEMA_VERSION.to_string(),
            install_script_rules: lpm_security::INSTALL_SCRIPT_RULES.to_string(),
            linker: linker.as_str().to_string(),
            integrity: integrity.as_str().to_string(),
            store_version: store_version.to_string(),
            platform,
            auto_install_peers,
            frozen_ok: true,
            routes_fingerprint: routes.routing_fingerprint(),
            release_age_policy_key,
            no_engine_strict: options.no_engine_strict,
            has_node_engines,
            dependency_engine_key,
            lockfile_stamp,
            pnpm_workspace_yaml,
            glob_parent_dirs,
            targets,
        })
    })();

    let state = match state {
        Ok(state) => state,
        Err(reason) => {
            tracing::debug!("skipping workspace sync-noop state: {reason}");
            remove_workspace_sync_noop_state(root);
            return;
        }
    };

    if let Ok(bytes) = serde_json::to_vec(&state) {
        let state_path = workspace_sync_noop_state_path(root);
        if let Some(parent) = state_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if let Err(error) = lpm_common::write_file_atomic_with_options(
            &state_path,
            &bytes,
            lpm_common::AtomicWriteOptions::new().unix_mode(0o600),
        ) {
            tracing::debug!("failed to write workspace sync-noop state: {error}");
        }
    }
}

pub(crate) fn try_workspace_up_to_date(
    workspace_root: &Path,
    pkg_content_opt: Option<&str>,
    mode: &crate::install_state::FastLaneMode,
) -> Result<Option<WorkspaceSyncNoopHit>, LpmError> {
    if std::env::var_os("LPM_TIMING_DETAIL").is_some_and(|value| !value.is_empty()) {
        return Ok(None);
    }
    let Some(pkg_content) = pkg_content_opt else {
        return Ok(None);
    };
    let Ok(raw_state) = lpm_common::read_file_capped(
        &workspace_sync_noop_state_path(workspace_root),
        lpm_common::STATE_FILE_SIZE_CAP_BYTES,
    ) else {
        return Ok(None);
    };
    let Ok(state) = serde_json::from_slice::<WorkspaceSyncNoopState>(&raw_state) else {
        return Ok(None);
    };
    if state.schema != WORKSPACE_SYNC_NOOP_SCHEMA
        || state.lockfile_version != lpm_lockfile::LOCKFILE_VERSION
        || state.bin_shim_format != lpm_linker::BIN_SHIM_FORMAT
        || state.graph_key_schema != lpm_store::v2::GraphKey::SCHEMA_VERSION
        || state.install_script_rules != lpm_security::INSTALL_SCRIPT_RULES
        || state.targets.is_empty()
    {
        return Ok(None);
    }
    if state.no_engine_strict && !mode.no_engine_strict {
        return Ok(None);
    }

    let lock_path = workspace_root.join(lpm_lockfile::LOCKFILE_NAME);
    if FileStamp::from_path(&lock_path) != Some(state.lockfile_stamp) {
        return Ok(None);
    }
    let pnpm_yaml_path = workspace_root.join("pnpm-workspace.yaml");
    let current_pnpm_yaml = if pnpm_yaml_path.exists() {
        let Some(stamp) = FileStamp::from_path(&pnpm_yaml_path) else {
            return Ok(None);
        };
        Some(stamp)
    } else {
        None
    };
    if current_pnpm_yaml != state.pnpm_workspace_yaml {
        return Ok(None);
    }
    for dir_stamp in &state.glob_parent_dirs {
        if DirStamp::from_path(workspace_root, Path::new(&dir_stamp.rel_path)).as_ref()
            != Some(dir_stamp)
        {
            return Ok(None);
        }
    }

    let package_json = lpm_common::strip_utf8_bom_str(pkg_content);
    let Ok(package) = serde_json::from_str::<lpm_workspace::PackageJson>(package_json) else {
        return Ok(None);
    };
    let root_lifecycle = crate::commands::root_lifecycle::RootProjectLifecycle::from_package(
        workspace_root,
        &package,
    );
    if crate::install_recovery::pending(workspace_root)
        || workspace_root.join("Package.swift").exists()
        || workspace_root
            .join(lpm_lockfile::OBSOLETE_BINARY_LOCKFILE_NAME)
            .exists()
        || root_lifecycle.has_dev_preinstall()
    {
        return Ok(None);
    }
    for target in &state.targets {
        let target_dir = if target.rel_path == "." {
            workspace_root.to_path_buf()
        } else {
            workspace_root.join(&target.rel_path)
        };
        if FileStamp::from_path(&target_dir.join("package.json")) != Some(target.pkg_stamp)
            || crate::install_recovery::pending(&target_dir)
            || target_dir.join("Package.swift").exists()
            || (target.has_node_modules && !target_dir.join("node_modules").is_dir())
        {
            return Ok(None);
        }
    }

    let json_output = mode.json;
    let suppression_warnings = crate::security_floor::defer_suppression_warnings();
    let global = crate::commands::config::GlobalConfig::load_checked()?;
    crate::npm_firewall_config::config_policy_profile(&global)?;
    crate::lpm_insights_config::read_fetch_lpm_security_insights(&global)?;
    if super::peer::resolve_strict_peer_dependencies(None, &package, &global) {
        return Ok(None);
    }
    if crate::source_analysis_config::resolve_install_time_source_analysis(
        &global,
        workspace_root,
        json_output,
    )? {
        return Ok(None);
    }
    let (linker, _) = crate::linker_config::resolve_effective_linker_with_source_and_workspace(
        mode.linker,
        &package,
        &global,
        true,
    )
    .map_err(LpmError::Registry)?;
    let integrity = crate::commands::config::resolve_object_integrity_policy(&global)?;
    let store_version = lpm_store::StoreVersion::from_env();
    let platform = current_platform_key();
    let auto_install_peers = super::setup::resolve_auto_install_peers(&package, &global);
    if linker.as_str() != state.linker
        || integrity.as_str() != state.integrity
        || store_version.to_string() != state.store_version
        || platform != state.platform
        || auto_install_peers != state.auto_install_peers
    {
        return Ok(None);
    }

    let frozen = match mode.frozen_lockfile {
        super::FrozenLockfileMode::Always => true,
        super::FrozenLockfileMode::Never => false,
        super::FrozenLockfileMode::Auto => super::install_running_in_ci(),
    };
    if frozen && !state.frozen_ok {
        return Ok(None);
    }

    let routes = lpm_registry::RouteTable::from_env_and_filesystem(workspace_root)
        .map_err(|error| LpmError::Registry(format!("npmrc: {error}")))?;
    if routes.routing_fingerprint() != state.routes_fingerprint {
        return Ok(None);
    }

    crate::release_plan::ensure_no_pending_release_transaction(workspace_root)?;
    super::validation::validate_project_layout(workspace_root)?;
    super::setup::check_project_policy(
        &global,
        workspace_root,
        workspace_root,
        &workspace_root.join("package.json"),
        &package,
        json_output,
    )?;

    let cli_min_age = match mode.min_release_age.as_deref() {
        Some(raw) => match crate::release_age_config::parse_duration(raw) {
            Ok(secs) => Some(secs),
            Err(_) => return Ok(None),
        },
        None => None,
    };
    let cli_excludes = if mode.min_release_age_exclude.is_empty() {
        Vec::new()
    } else {
        match crate::release_age_config::validate_release_age_excludes(
            "--min-release-age-exclude",
            &mode.min_release_age_exclude,
        ) {
            Ok(excludes) => excludes,
            Err(_) => return Ok(None),
        }
    };
    let resolved_age = crate::release_age_config::ReleaseAgeResolver::resolve_config_with_context(
        &global,
        Some(&package),
        workspace_root,
        cli_min_age,
        &cli_excludes,
        json_output,
    )?;
    let current_release_age_key = crate::install_state::release_age_freshness_key(
        resolved_age.minimum_release_age_secs,
        resolved_age.minimum_release_age_policy,
        &resolved_age.minimum_release_age_exclude,
        false,
    );
    if current_release_age_key.is_some() && current_release_age_key != state.release_age_policy_key
    {
        return Ok(None);
    }

    let extensions = super::policy_extensions::load_policy_extension_configs(&global)?;
    let skills_ready = mode.no_skills
        || ((!crate::lpm_skills_config::LpmSkillsPreference::Config.resolve(&global)?
            || crate::commands::skills::package::materialization_complete(
                workspace_root,
                package_json,
            ))
            && crate::commands::skills::project_skills_ready(workspace_root));
    if !extensions.is_empty() || !skills_ready {
        return Ok(None);
    }

    let engine_policy = crate::engine_check::prepare_dependency_policy_for_standalone_root(
        workspace_root,
        &package,
        &global,
        mode.no_engine_strict,
        json_output,
        crate::engine_check::NodeVersionReuse::recorded(None),
    )?;
    let current_engine_key = engine_policy.freshness_key_from_flags(true, state.has_node_engines);
    if current_engine_key != state.dependency_engine_key {
        return Ok(None);
    }

    suppression_warnings.flush(json_output);
    if root_lifecycle.has_scripts() {
        root_lifecycle.run_after_successful_install(workspace_root, json_output)?;
    }
    Ok(Some(WorkspaceSyncNoopHit {
        targets: state.targets,
    }))
}

pub(crate) fn emit_workspace_sync_noop_report(
    workspace_root: &Path,
    hit: &WorkspaceSyncNoopHit,
    mode: &crate::install_state::FastLaneMode,
    elapsed_ms: u64,
) {
    if mode.json {
        let timing_requested = crate::json_contract::install_timing_requested(mode.timing);
        let targets: Vec<serde_json::Value> = hit
            .targets
            .iter()
            .map(|target| {
                let target_path = if target.rel_path == "." {
                    workspace_root.to_path_buf()
                } else {
                    workspace_root.join(&target.rel_path)
                };
                let mut entry = serde_json::json!({
                    "name": target.name,
                    "path": target_path.display().to_string(),
                    "kind": target.kind,
                    "status": "success",
                    "duration_ms": 0,
                    "up_to_date": true,
                });
                if target.no_dependencies {
                    entry["no_dependencies"] = serde_json::json!(true);
                }
                entry
            })
            .collect();
        let mut report = serde_json::json!({
            "schema_version": crate::json_contract::INSTALL_JSON_SCHEMA_VERSION,
            "success": true,
            "recursive": true,
            "workspace_root": workspace_root.display().to_string(),
            "duration_ms": elapsed_ms,
            "up_to_date": true,
            "targets": targets,
            "summary": {
                "total": hit.targets.len(),
                "succeeded": hit.targets.len(),
                "failed": 0,
            },
            "counts": {
                "scope": "recursive_command",
                "aggregation": "sum_of_target_observations",
                "work_is_cumulative": true,
                "resolved_package_row_count": 0,
                "authoritative_fetch_candidate_count": 0,
                "store_reuse_observation_count": 0,
                "store_reuse_may_include_same_command_population": true,
                "linker_entry_created_count": 0,
                "linker_entry_reused_count": 0,
                "project_root_symlink_created_count": 0,
                "bin_link_created_count": 0,
            },
        });
        if timing_requested {
            report["timing"] = serde_json::json!({
                "scope": "recursive_command",
                "work_is_cumulative": true,
                "phase_aggregation": "sum_of_target_wall_clock",
                "resolve_ms": 0,
                "fetch_ms": 0,
                "link_ms": 0,
                "total_ms": elapsed_ms,
                "workspace_union": {
                    "scope": "recursive_command",
                    "aggregation": "sum_of_union_groups",
                    "importer_count": 0,
                    "eligible_importer_count": 0,
                    "projected_importer_count": 0,
                    "isolated_importer_count": 0,
                    "expansion_pass_count": 0,
                    "expansion_capped": false,
                    "isolated_importer_reasons": {
                        "root_specifier_count": 0,
                        "release_age_policy_count": 0,
                        "projection_count": 0,
                        "ambient_peer_cap_count": 0,
                        "ambient_peer_stalled_count": 0,
                    },
                },
                "waterfall": {
                    "total_ms": elapsed_ms,
                },
                "wait": {
                    "aggregation": "sum_of_target_wall_clock",
                    "target_materialization_sum_ms": 0,
                    "target_commit_sum_ms": 0,
                },
                "work": {
                    "target_resolve_sum_ms": 0,
                    "target_post_resolve_sum_ms": 0,
                    "target_fetch_sum_ms": 0,
                    "target_link_sum_ms": 0,
                },
            });
        }
        println!("{}", serde_json::to_string_pretty(&report).unwrap());
    } else {
        crate::output::success(&format!(
            "Installed {} workspace package{} in {elapsed_ms}ms",
            hit.targets.len(),
            if hit.targets.len() == 1 { "" } else { "s" },
        ));
    }
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
    fn sync_noop_proof_fast_path_validates_content_routes_and_security_invariants() {
        let home = tempfile::tempdir().unwrap();
        let _env = crate::test_env::ScopedEnv::set([
            ("LPM_HOME", home.path().as_os_str().to_owned()),
            ("HOME", home.path().as_os_str().to_owned()),
            (
                "NPM_CONFIG_USERCONFIG",
                home.path().join(".npmrc").into_os_string(),
            ),
            ("LPM_LINKER", std::ffi::OsString::from("hoisted")),
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
        let lock_raw = std::fs::read(&lock_path).unwrap();
        let lock_content = std::str::from_utf8(&lock_raw).unwrap();
        let package: lpm_workspace::PackageJson = serde_json::from_str(pkg_json).unwrap();
        let routes = lpm_registry::RouteTable::from_env_and_filesystem(project).unwrap();
        let proof = super::compute_sync_noop_proof(
            project, &lock_path, &package, pkg_json, &lockfile, &lock_raw, &routes, true,
        );
        assert!(proof.lockfile_eligible);
        assert!(!proof.has_node_engines);

        let platform = lpm_store::v2::PlatformTuple::current();
        let hash = crate::install_state::compute_install_hash_v10(
            pkg_json,
            lock_content,
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
                release_age_policy_key: None,
            },
        )
        .unwrap();

        let mode = crate::install_state::FastLaneMode {
            json: true,
            timing: false,
            frozen_lockfile: crate::commands::install::FrozenLockfileMode::Never,
            no_skills: true,
            min_release_age: None,
            min_release_age_exclude: Vec::new(),
            linker: None,
            no_engine_strict: false,
        };
        assert!(super::is_up_to_date(project, pkg_json, &mode).unwrap());

        // Same-size edit with restored mtime must invalidate the content-bound proof.
        let pkg_mtime = std::fs::metadata(project.join("package.json"))
            .unwrap()
            .modified()
            .unwrap();
        let edited_pkg = r#"{"name":"app","version":"1.0.0","dependencies":{"react":"^2.0.0"}}"#;
        assert_eq!(edited_pkg.len(), pkg_json.len());
        std::fs::write(project.join("package.json"), edited_pkg).unwrap();
        std::fs::File::options()
            .write(true)
            .open(project.join("package.json"))
            .unwrap()
            .set_modified(pkg_mtime)
            .unwrap();
        assert!(!super::is_up_to_date(project, edited_pkg, &mode).unwrap());
        // Restore original package.json and mtime.
        std::fs::write(project.join("package.json"), pkg_json).unwrap();
        std::fs::File::options()
            .write(true)
            .open(project.join("package.json"))
            .unwrap()
            .set_modified(pkg_mtime)
            .unwrap();
        assert!(super::is_up_to_date(project, pkg_json, &mode).unwrap());

        // Changing `.npmrc` changes the route fingerprint, invalidating the proof.
        std::fs::write(
            project.join(".npmrc"),
            "registry=https://custom.registry.example/\n",
        )
        .unwrap();
        assert!(!super::is_up_to_date(project, pkg_json, &mode).unwrap());

        std::fs::remove_file(project.join(".npmrc")).unwrap();
        assert!(super::is_up_to_date(project, pkg_json, &mode).unwrap());

        // A patched project must never mark frozen_ok in the sync proof.
        let patched_pkg_json = r#"{"name":"app","version":"1.0.0","dependencies":{"react":"^1.0.0"},"lpm":{"patchedDependencies":{"react@1.0.0":{"path":"patches/react@1.0.0.patch","originalIntegrity":"sha512-test"}}}}"#;
        let patched_pkg: lpm_workspace::PackageJson =
            serde_json::from_str(patched_pkg_json).unwrap();
        let patched_proof = super::compute_sync_noop_proof(
            project,
            &lock_path,
            &patched_pkg,
            patched_pkg_json,
            &lockfile,
            &lock_raw,
            &routes,
            true,
        );
        assert!(!patched_proof.frozen_ok);

        // Changing lpm.lock invalidates both the proof and fallback check.
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
        assert!(!super::is_up_to_date(project, pkg_json, &mode).unwrap());
    }

    #[test]
    fn standalone_sync_noop_respects_explicit_linker_override() {
        let home = tempfile::tempdir().unwrap();
        let _env = crate::test_env::ScopedEnv::set([
            ("LPM_HOME", home.path().as_os_str().to_owned()),
            ("HOME", home.path().as_os_str().to_owned()),
            (
                "NPM_CONFIG_USERCONFIG",
                home.path().join(".npmrc").into_os_string(),
            ),
            ("LPM_LINKER", std::ffi::OsString::from("hoisted")),
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
        let lock_raw = std::fs::read(&lock_path).unwrap();
        let lock_content = std::str::from_utf8(&lock_raw).unwrap();
        let package: lpm_workspace::PackageJson = serde_json::from_str(pkg_json).unwrap();
        let routes = lpm_registry::RouteTable::from_env_and_filesystem(project).unwrap();
        let proof = super::compute_sync_noop_proof(
            project, &lock_path, &package, pkg_json, &lockfile, &lock_raw, &routes, true,
        );
        let platform = lpm_store::v2::PlatformTuple::current();
        let hash = crate::install_state::compute_install_hash_v10(
            pkg_json,
            lock_content,
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
                release_age_policy_key: None,
            },
        )
        .unwrap();

        let matching = crate::install_state::FastLaneMode {
            json: true,
            timing: false,
            frozen_lockfile: crate::commands::install::FrozenLockfileMode::Never,
            no_skills: true,
            min_release_age: None,
            min_release_age_exclude: Vec::new(),
            linker: Some(lpm_linker::LinkerMode::Hoisted),
            no_engine_strict: false,
        };
        assert!(super::is_up_to_date(project, pkg_json, &matching).unwrap());

        let mismatched = crate::install_state::FastLaneMode {
            linker: Some(lpm_linker::LinkerMode::Isolated),
            ..matching
        };
        assert!(!super::is_up_to_date(project, pkg_json, &mismatched).unwrap());
    }

    #[test]
    fn workspace_sync_noop_hits_clean_state_and_invalidates_on_mutations() {
        let home = tempfile::tempdir().unwrap();
        let _env = crate::test_env::ScopedEnv::set([
            ("LPM_HOME", home.path().as_os_str().to_owned()),
            ("HOME", home.path().as_os_str().to_owned()),
            (
                "NPM_CONFIG_USERCONFIG",
                home.path().join(".npmrc").into_os_string(),
            ),
            ("LPM_LINKER", std::ffi::OsString::from("isolated")),
            ("CI", std::ffi::OsString::from("")),
            ("GITHUB_ACTIONS", std::ffi::OsString::from("")),
        ]);
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let root_pkg = r#"{"name":"mono","private":true,"workspaces":["packages/*"]}"#;
        let member_dir = root.join("packages/ui");
        let empty_dir = root.join("packages/placeholder");
        std::fs::create_dir_all(&member_dir).unwrap();
        std::fs::create_dir_all(&empty_dir).unwrap();
        std::fs::create_dir_all(root.join("node_modules")).unwrap();
        std::fs::create_dir_all(member_dir.join("node_modules")).unwrap();
        std::fs::write(root.join("package.json"), root_pkg).unwrap();
        std::fs::write(
            root.join("pnpm-workspace.yaml"),
            "packages:\n  - packages/*\n",
        )
        .unwrap();
        std::fs::write(
            member_dir.join("package.json"),
            r#"{"name":"@mono/ui","version":"1.0.0"}"#,
        )
        .unwrap();
        let lockfile = lockfile_with_packages(&["react"]);
        let lock_path = root.join(lpm_lockfile::LOCKFILE_NAME);
        lockfile.write_to_file(&lock_path).unwrap();

        let workspace = lpm_workspace::discover_workspace(root).unwrap().unwrap();
        let options = crate::commands::install::recursive::RecursiveInstallOptions {
            json_output: true,
            emit_summary: true,
            offline: false,
            frozen_lockfile: crate::commands::install::FrozenLockfileMode::Never,
            force: false,
            allow_new: false,
            strict_integrity: false,
            no_engine_strict: true,
            strict_peer_dependencies_override: None,
            linker_override: None,
            lpm_skills_preference: crate::lpm_skills_config::LpmSkillsPreference::Disabled,
            no_security_summary: true,
            auto_build: false,
            script_policy_override: None,
            advisor_override: None,
            min_release_age_override: None,
            min_release_age_exclude: Vec::new(),
            drift_ignore_policy: crate::provenance_fetch::DriftIgnorePolicy::EnforceAll,
            verify_policy: crate::provenance_fetch::VerifyPolicy::default(),
            omit_policy: crate::commands::install::InstallOmitPolicy::default(),
            strict_sandbox: false,
            no_sandbox: false,
            verbose: false,
            audit_after_install: false,
            timing: false,
            workspace_concurrency: None,
        };
        let target_inputs = [
            super::WorkspaceSyncNoopTargetInput {
                name: "@mono/ui",
                path: &member_dir,
                kind: "member",
                has_scripts: false,
                has_dev_preinstall: false,
                no_dependencies: false,
            },
            super::WorkspaceSyncNoopTargetInput {
                name: "mono",
                path: root,
                kind: "root",
                has_scripts: false,
                has_dev_preinstall: false,
                no_dependencies: false,
            },
        ];
        super::write_workspace_sync_noop_state(&workspace, &target_inputs, &options, true);

        let mode = crate::install_state::FastLaneMode {
            json: true,
            timing: false,
            frozen_lockfile: crate::commands::install::FrozenLockfileMode::Never,
            no_skills: true,
            min_release_age: None,
            min_release_age_exclude: Vec::new(),
            linker: None,
            no_engine_strict: true,
        };
        let hit = super::try_workspace_up_to_date(root, Some(root_pkg), &mode)
            .unwrap()
            .expect("clean workspace should hit sync_noop");
        assert_eq!(hit.targets.len(), 2);

        // Tightening engine-strict from no_engine_strict=true -> false must invalidate.
        let strict_mode = crate::install_state::FastLaneMode {
            no_engine_strict: false,
            ..mode.clone()
        };
        assert!(
            super::try_workspace_up_to_date(root, Some(root_pkg), &strict_mode)
                .unwrap()
                .is_none()
        );

        // Switching --linker must invalidate.
        let hoisted_mode = crate::install_state::FastLaneMode {
            linker: Some(lpm_linker::LinkerMode::Hoisted),
            ..mode.clone()
        };
        assert!(
            super::try_workspace_up_to_date(root, Some(root_pkg), &hoisted_mode)
                .unwrap()
                .is_none()
        );

        // Adding a custom .npmrc route invalidates.
        std::fs::write(
            root.join(".npmrc"),
            "registry=https://custom.registry.example/\n",
        )
        .unwrap();
        assert!(
            super::try_workspace_up_to_date(root, Some(root_pkg), &mode)
                .unwrap()
                .is_none()
        );
        std::fs::remove_file(root.join(".npmrc")).unwrap();
        assert!(
            super::try_workspace_up_to_date(root, Some(root_pkg), &mode)
                .unwrap()
                .is_some()
        );

        // Deleting a member's node_modules invalidates.
        std::fs::remove_dir(member_dir.join("node_modules")).unwrap();
        assert!(
            super::try_workspace_up_to_date(root, Some(root_pkg), &mode)
                .unwrap()
                .is_none()
        );
        std::fs::create_dir_all(member_dir.join("node_modules")).unwrap();

        // Editing a member package.json invalidates.
        super::write_workspace_sync_noop_state(&workspace, &target_inputs, &options, true);
        assert!(
            super::try_workspace_up_to_date(root, Some(root_pkg), &mode)
                .unwrap()
                .is_some()
        );
        std::fs::write(
            member_dir.join("package.json"),
            r#"{"name":"@mono/ui","version":"1.0.1"}"#,
        )
        .unwrap();
        assert!(
            super::try_workspace_up_to_date(root, Some(root_pkg), &mode)
                .unwrap()
                .is_none()
        );

        // Adding a package.json inside an existing non-member directory invalidates.
        super::write_workspace_sync_noop_state(&workspace, &target_inputs, &options, true);
        assert!(
            super::try_workspace_up_to_date(root, Some(root_pkg), &mode)
                .unwrap()
                .is_some()
        );
        std::fs::write(
            empty_dir.join("package.json"),
            r#"{"name":"@mono/placeholder","version":"1.0.0"}"#,
        )
        .unwrap();
        assert!(
            super::try_workspace_up_to_date(root, Some(root_pkg), &mode)
                .unwrap()
                .is_none()
        );

        // Adding a brand-new directory under packages/ invalidates.
        super::write_workspace_sync_noop_state(&workspace, &target_inputs, &options, true);
        assert!(
            super::try_workspace_up_to_date(root, Some(root_pkg), &mode)
                .unwrap()
                .is_some()
        );
        std::fs::create_dir_all(root.join("packages/brand-new")).unwrap();
        assert!(
            super::try_workspace_up_to_date(root, Some(root_pkg), &mode)
                .unwrap()
                .is_none()
        );

        // Modifying pnpm-workspace.yaml invalidates.
        super::write_workspace_sync_noop_state(&workspace, &target_inputs, &options, true);
        assert!(
            super::try_workspace_up_to_date(root, Some(root_pkg), &mode)
                .unwrap()
                .is_some()
        );
        std::fs::write(
            root.join("pnpm-workspace.yaml"),
            "packages:\n  - packages/*\n  - apps/*\n",
        )
        .unwrap();
        assert!(
            super::try_workspace_up_to_date(root, Some(root_pkg), &mode)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn workspace_sync_noop_hits_and_runs_root_after_install_scripts() {
        let home = tempfile::tempdir().unwrap();
        let _env = crate::test_env::ScopedEnv::set([
            ("LPM_HOME", home.path().as_os_str().to_owned()),
            ("HOME", home.path().as_os_str().to_owned()),
            (
                "NPM_CONFIG_USERCONFIG",
                home.path().join(".npmrc").into_os_string(),
            ),
            ("LPM_LINKER", std::ffi::OsString::from("isolated")),
            ("CI", std::ffi::OsString::from("")),
            ("GITHUB_ACTIONS", std::ffi::OsString::from("")),
        ]);
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let marker = root.join("postinstall-ran.txt");
        let root_pkg = format!(
            r#"{{"name":"mono","private":true,"workspaces":["packages/*"],"scripts":{{"postinstall":"node -e \"require('fs').writeFileSync('{}', 'ok')\""}}}}"#,
            marker.to_string_lossy().replace('\\', "\\\\")
        );
        let member_dir = root.join("packages/ui");
        std::fs::create_dir_all(member_dir.join("node_modules")).unwrap();
        std::fs::create_dir_all(root.join("node_modules")).unwrap();
        std::fs::write(root.join("package.json"), &root_pkg).unwrap();
        std::fs::write(
            member_dir.join("package.json"),
            r#"{"name":"@mono/ui","version":"1.0.0"}"#,
        )
        .unwrap();
        let lockfile = lockfile_with_packages(&["react"]);
        lockfile
            .write_to_file(&root.join(lpm_lockfile::LOCKFILE_NAME))
            .unwrap();

        let workspace = lpm_workspace::discover_workspace(root).unwrap().unwrap();
        let options = crate::commands::install::recursive::RecursiveInstallOptions {
            json_output: true,
            emit_summary: true,
            offline: false,
            frozen_lockfile: crate::commands::install::FrozenLockfileMode::Never,
            force: false,
            allow_new: false,
            strict_integrity: false,
            no_engine_strict: true,
            strict_peer_dependencies_override: None,
            linker_override: None,
            lpm_skills_preference: crate::lpm_skills_config::LpmSkillsPreference::Disabled,
            no_security_summary: true,
            auto_build: false,
            script_policy_override: None,
            advisor_override: None,
            min_release_age_override: None,
            min_release_age_exclude: Vec::new(),
            drift_ignore_policy: crate::provenance_fetch::DriftIgnorePolicy::EnforceAll,
            verify_policy: crate::provenance_fetch::VerifyPolicy::default(),
            omit_policy: crate::commands::install::InstallOmitPolicy::default(),
            strict_sandbox: false,
            no_sandbox: false,
            verbose: false,
            audit_after_install: false,
            timing: false,
            workspace_concurrency: None,
        };
        let target_inputs = [
            super::WorkspaceSyncNoopTargetInput {
                name: "@mono/ui",
                path: &member_dir,
                kind: "member",
                has_scripts: false,
                has_dev_preinstall: false,
                no_dependencies: false,
            },
            super::WorkspaceSyncNoopTargetInput {
                name: "mono",
                path: root,
                kind: "root",
                has_scripts: true,
                has_dev_preinstall: false,
                no_dependencies: false,
            },
        ];
        super::write_workspace_sync_noop_state(&workspace, &target_inputs, &options, true);

        let mode = crate::install_state::FastLaneMode {
            json: true,
            timing: false,
            frozen_lockfile: crate::commands::install::FrozenLockfileMode::Never,
            no_skills: true,
            min_release_age: None,
            min_release_age_exclude: Vec::new(),
            linker: None,
            no_engine_strict: true,
        };
        let hit = super::try_workspace_up_to_date(root, Some(&root_pkg), &mode)
            .unwrap()
            .expect("workspace with root postinstall should hit sync_noop");
        assert_eq!(hit.targets.len(), 2);
        assert_eq!(std::fs::read_to_string(&marker).unwrap(), "ok");

        // devPreinstall on the root still bypasses workspace sync_noop.
        let dev_preinstall_pkg = r#"{"name":"mono","private":true,"workspaces":["packages/*"],"scripts":{"pnpm:devPreinstall":"node -e 0"}}"#;
        std::fs::write(root.join("package.json"), dev_preinstall_pkg).unwrap();
        let workspace_dev = lpm_workspace::discover_workspace(root).unwrap().unwrap();
        let dev_inputs = [
            target_inputs[0],
            super::WorkspaceSyncNoopTargetInput {
                has_dev_preinstall: true,
                ..target_inputs[1]
            },
        ];
        super::write_workspace_sync_noop_state(&workspace_dev, &dev_inputs, &options, true);
        assert!(
            super::try_workspace_up_to_date(root, Some(dev_preinstall_pkg), &mode)
                .unwrap()
                .is_none()
        );
    }
}
