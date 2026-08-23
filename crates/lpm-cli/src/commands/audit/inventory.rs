//! Shared package inventory for `audit` and `query` commands.
//!
//! Provides a single entry point that discovers packages, loads behavioral
//! analysis from the appropriate cache, and builds the data structures
//! needed for both auditing and querying.

use super::cache::ProjectAuditCache;
use super::discovery::{self, DiscoveredPackage, DiscoveryResult, ScanMode};
use dashmap::mapref::entry::Entry;
use lpm_security::behavioral::PackageAnalysis;
use rayon::prelude::*;
use std::collections::{HashMap, HashSet, VecDeque};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

pub(crate) struct ProjectV2BaselineIndex {
    uses_virtual_store: bool,
    scoped: lpm_store::V2BaselineIndex,
    by_instance: HashMap<lpm_common::PackageInstanceId, Arc<lpm_store::InstalledPackageBaseline>>,
    global: std::sync::OnceLock<lpm_store::V2BaselineIndex>,
}

pub(crate) fn build_project_v2_baseline_index(
    project_dir: &Path,
    lpm_root: &lpm_common::LpmRoot,
    store_version: lpm_store::StoreVersion,
    lockfile: Option<&lpm_lockfile::Lockfile>,
    workspace_root: Option<&super::discovery::WorkspaceRootDiscovery>,
) -> ProjectV2BaselineIndex {
    if !store_version.uses_virtual_store() {
        return ProjectV2BaselineIndex {
            uses_virtual_store: false,
            scoped: lpm_store::V2BaselineIndex::default(),
            by_instance: HashMap::new(),
            global: std::sync::OnceLock::new(),
        };
    }
    let scoped = lpm_store::V2BaselineIndex::for_project(project_dir, lpm_root);
    let mut by_instance = lockfile.map_or_else(HashMap::new, |lockfile| {
        build_instance_baselines(project_dir, &scoped, lockfile)
    });
    if let Some(workspace) = workspace_root {
        let workspace_index =
            lpm_store::V2BaselineIndex::for_project(&workspace.project_root, lpm_root);
        by_instance.extend(build_instance_baselines(
            &workspace.project_root,
            &workspace_index,
            &workspace.lockfile,
        ));
    }
    ProjectV2BaselineIndex {
        uses_virtual_store: true,
        scoped,
        by_instance,
        global: std::sync::OnceLock::new(),
    }
}

pub(crate) fn build_instance_baselines(
    project_dir: &Path,
    index: &lpm_store::V2BaselineIndex,
    lockfile: &lpm_lockfile::Lockfile,
) -> HashMap<lpm_common::PackageInstanceId, Arc<lpm_store::InstalledPackageBaseline>> {
    let locked_by_instance: HashMap<_, _> = lockfile
        .packages
        .iter()
        .filter_map(|package| package.instance_id.map(|id| (id, package)))
        .collect();
    let mut to_visit = VecDeque::new();
    for (local_name, resolution) in &lockfile.root_resolutions {
        let Some(instance_id) = resolution.instance_id else {
            continue;
        };
        let package_path = project_dir.join("node_modules").join(local_name);
        let Some(graph_digest) = index.graph_digest_for_package_dir(&package_path) else {
            continue;
        };
        to_visit.push_back((instance_id, graph_digest.to_string()));
    }

    let mut by_instance = HashMap::with_capacity(locked_by_instance.len());
    let mut visited = HashSet::new();
    while let Some((instance_id, graph_digest)) = to_visit.pop_front() {
        if !visited.insert((instance_id, graph_digest.clone())) {
            continue;
        }
        let Some(package) = locked_by_instance.get(&instance_id) else {
            continue;
        };
        let Some(baseline) = index.lookup_shared_by_graph_digest(&graph_digest) else {
            continue;
        };
        if package
            .integrity
            .as_deref()
            .is_some_and(|integrity| integrity != baseline.integrity)
        {
            continue;
        }
        by_instance
            .entry(instance_id)
            .or_insert_with(|| Arc::clone(baseline));

        let Some(dependencies) = index.graph_dependencies(&graph_digest) else {
            continue;
        };
        for dependency in dependencies {
            let target_id = package
                .dependency_targets
                .get(&dependency.local)
                .or_else(|| package.peer_targets.get(&dependency.local));
            let Some(target_id) = target_id.copied() else {
                continue;
            };
            let Some(target) = locked_by_instance.get(&target_id) else {
                continue;
            };
            if target.name == dependency.target_name && target.version == dependency.target_version
            {
                to_visit.push_back((target_id, dependency.target_graph_key.clone()));
            }
        }
    }
    by_instance
}

pub(crate) fn find_project_baseline_by_identity(
    index: &ProjectV2BaselineIndex,
    lpm_root: &lpm_common::LpmRoot,
    package: &DiscoveredPackage,
) -> Option<Arc<lpm_store::InstalledPackageBaseline>> {
    if let Some(instance_id) = package.instance_id {
        if let Some(baseline) = index.by_instance.get(&instance_id) {
            return Some(Arc::clone(baseline));
        }
        if index.uses_virtual_store {
            return package
                .integrity
                .as_deref()
                .and_then(|integrity| index.scoped.lookup_shared_by_integrity(integrity))
                .map(Arc::clone)
                .or_else(|| {
                    let global = index.global.get_or_init(|| {
                        lpm_store::V2BaselineIndex::build(lpm_root).unwrap_or_default()
                    });
                    package
                        .integrity
                        .as_deref()
                        .and_then(|integrity| global.lookup_shared_by_integrity(integrity))
                        .map(Arc::clone)
                });
        }
    }
    if let Some(integrity) = package.integrity.as_deref()
        && let Some(baseline) = index.scoped.lookup_shared_by_integrity(integrity)
    {
        return Some(Arc::clone(baseline));
    }
    let global = index
        .global
        .get_or_init(|| lpm_store::V2BaselineIndex::build(lpm_root).unwrap_or_default());
    lpm_store::find_installed_package_baseline_by_identity_indexed(
        global,
        lpm_root,
        &package.name,
        &package.version,
        package.integrity.as_deref(),
    )
    .map(Arc::new)
}

pub(crate) fn find_project_baseline(
    index: Option<&ProjectV2BaselineIndex>,
    lpm_root: &lpm_common::LpmRoot,
    name: &str,
    version: &str,
) -> Option<lpm_store::InstalledPackageBaseline> {
    if let Some(index) = index {
        return lpm_store::find_installed_package_baseline_indexed(
            &index.scoped,
            lpm_root,
            name,
            version,
        );
    }
    lpm_store::find_installed_package_baseline(lpm_root, name, version)
        .ok()
        .flatten()
}

/// A fully loaded package inventory ready for audit or query consumption.
///
/// Contains discovered packages with their behavioral analysis loaded
/// from the appropriate cache (LPM store or project audit cache).
pub struct PackageInventory {
    /// Discovery result (manager, lockfile, packages, etc.)
    pub discovery: DiscoveryResult,
    /// Behavioral analysis aligned with [`DiscoveryResult::packages`].
    pub analyses: Vec<Option<Arc<PackageAnalysis>>>,
    /// Source directories aligned with [`DiscoveryResult::packages`].
    pub source_paths: Vec<Option<PathBuf>>,
    pub(crate) baseline_index: Option<ProjectV2BaselineIndex>,
}

struct LoadedAnalysis {
    scan_index: usize,
    package_index: usize,
    analysis: Arc<PackageAnalysis>,
    cache_fingerprint: Option<String>,
    source_path: PathBuf,
}

impl PackageInventory {
    /// Build a package inventory from a project directory.
    ///
    /// Cheap pre-discovery: read the project's lockfile and return the
    /// resulting [`DiscoveryResult`] without loading any behavioral
    /// analyses. Does NOT touch the LPM store.
    ///
    /// Callers that need to take the store lock around the
    /// store-touching part of inventory load should call this first to
    /// learn `discovery.manager`, then conditionally lock and call
    /// [`PackageInventory::from_discovery_with_lpm_root`].
    pub fn discover(
        project_dir: &Path,
    ) -> Result<discovery::DiscoveryResult, lpm_common::LpmError> {
        discovery::discover_packages_retaining_parsed_lpm_lockfile(project_dir)
    }

    pub(crate) fn from_discovery_with_lpm_root(
        discovery: discovery::DiscoveryResult,
        store_version: lpm_store::StoreVersion,
        lpm_root: Option<&lpm_common::LpmRoot>,
    ) -> Self {
        let baseline_index = lpm_root.map(|root| {
            build_project_v2_baseline_index(
                &discovery.project_root,
                root,
                store_version,
                discovery.lpm_lockfile.as_deref(),
                discovery.workspace_root.as_ref(),
            )
        });
        let (analyses, source_paths) =
            load_behavioral_analyses_with_index(&discovery, lpm_root, baseline_index.as_ref());
        Self {
            discovery,
            analyses,
            source_paths,
            baseline_index,
        }
    }
}

pub(crate) fn load_behavioral_analyses(
    discovery: &DiscoveryResult,
    store_version: lpm_store::StoreVersion,
) -> (Vec<Option<Arc<PackageAnalysis>>>, Vec<Option<PathBuf>>) {
    let needs_store = discovery
        .packages
        .iter()
        .any(|package| package.scan_mode == ScanMode::RegistryAndStore);
    let lpm_root = needs_store
        .then(lpm_common::LpmRoot::from_env)
        .transpose()
        .ok()
        .flatten();
    let baseline_index = lpm_root.as_ref().map(|root| {
        build_project_v2_baseline_index(
            &discovery.project_root,
            root,
            store_version,
            discovery.lpm_lockfile.as_deref(),
            discovery.workspace_root.as_ref(),
        )
    });
    load_behavioral_analyses_with_index(discovery, lpm_root.as_ref(), baseline_index.as_ref())
}

fn load_behavioral_analyses_with_index(
    discovery: &DiscoveryResult,
    lpm_root: Option<&lpm_common::LpmRoot>,
    baseline_index: Option<&ProjectV2BaselineIndex>,
) -> (Vec<Option<Arc<PackageAnalysis>>>, Vec<Option<PathBuf>>) {
    let scannable: Vec<(usize, &DiscoveredPackage)> = discovery
        .packages
        .iter()
        .enumerate()
        .filter(|(_, package)| {
            matches!(
                package.scan_mode,
                ScanMode::FullLocal | ScanMode::RegistryAndStore
            )
        })
        .collect();
    let manager = discovery.manager.to_string();
    let mut analysis_keys: Vec<String> = scannable
        .iter()
        .map(|(_, package)| package.analysis_key())
        .collect();
    let mut project_cache = ProjectAuditCache::read(&discovery.project_root, &manager);
    if let Some(cache) = project_cache.as_mut() {
        let active_keys: HashSet<&str> = analysis_keys.iter().map(String::as_str).collect();
        cache.retain_active(&active_keys);
    }

    let project_root = open_project_root(&discovery.project_root).ok();
    let project_cache_ref = project_cache.as_ref();
    let shared_by_fingerprint = dashmap::DashMap::new();
    let loaded: Vec<LoadedAnalysis> = scannable
        .par_iter()
        .enumerate()
        .filter_map(|(scan_index, (package_index, package))| {
            let package_source =
                open_package_source(project_root.as_ref(), package, lpm_root, baseline_index)
                    .ok()?;
            let package_directory = &package_source.directory;
            let key = &analysis_keys[scan_index];
            if let Some(cache) = project_cache_ref
                && cache.has_candidate(key, package)
            {
                let fingerprint =
                    lpm_security::behavioral::package_input_fingerprint_from_open_dir(
                        package_directory,
                    )
                    .ok();
                if let Some(cached) = fingerprint
                    .as_deref()
                    .and_then(|fingerprint| cache.get(key, package, fingerprint))
                {
                    return Some(LoadedAnalysis {
                        scan_index,
                        package_index: *package_index,
                        analysis: cached,
                        cache_fingerprint: None,
                        source_path: package_source.path,
                    });
                }
            }

            let (analysis, cache_fingerprint) =
                lpm_security::behavioral::analyze_package_from_open_dir_with_fingerprint(
                    package_directory,
                );
            let mut analysis = Arc::new(analysis);
            if let Some(fingerprint) = cache_fingerprint.as_ref() {
                analysis = match shared_by_fingerprint.entry(fingerprint.clone()) {
                    Entry::Occupied(entry) => Arc::clone(entry.get()),
                    Entry::Vacant(entry) => Arc::clone(&entry.insert(analysis)),
                };
            }
            Some(LoadedAnalysis {
                scan_index,
                package_index: *package_index,
                analysis,
                cache_fingerprint,
                source_path: package_source.path,
            })
        })
        .collect();

    let mut analyses = vec![None; discovery.packages.len()];
    let mut source_paths = vec![None; discovery.packages.len()];
    for loaded in loaded {
        let package = &discovery.packages[loaded.package_index];
        let key = std::mem::take(&mut analysis_keys[loaded.scan_index]);
        if let Some(fingerprint) = loaded.cache_fingerprint.as_ref() {
            if project_cache.is_none() {
                project_cache = ProjectAuditCache::new(&discovery.project_root, &manager);
            }
            if let Some(cache) = project_cache.as_mut() {
                cache.insert(
                    key,
                    package,
                    fingerprint.clone(),
                    Arc::clone(&loaded.analysis),
                );
            }
        }
        analyses[loaded.package_index] = Some(loaded.analysis);
        if loaded.source_path != Path::new(&package.path) {
            source_paths[loaded.package_index] = Some(loaded.source_path);
        }
    }

    if let Some(cache) = project_cache.as_mut()
        && let Err(error) = cache.write(&discovery.project_root)
    {
        tracing::debug!("failed to write behavioral analysis cache: {error}");
    }
    (analyses, source_paths)
}

pub(crate) fn open_project_root(path: &Path) -> io::Result<cap_std::fs::Dir> {
    let canonical = path.canonicalize()?;
    cap_std::fs::Dir::open_ambient_dir(canonical, cap_std::ambient_authority())
}

pub(crate) fn open_package_source_directory(
    project_root: Option<&cap_std::fs::Dir>,
    package: &DiscoveredPackage,
    lpm_root: Option<&lpm_common::LpmRoot>,
    baseline_index: Option<&ProjectV2BaselineIndex>,
) -> io::Result<cap_std::fs::Dir> {
    open_package_source(project_root, package, lpm_root, baseline_index)
        .map(|source| source.directory)
}

struct OpenedPackageSource {
    directory: cap_std::fs::Dir,
    path: PathBuf,
}

fn open_package_source(
    project_root: Option<&cap_std::fs::Dir>,
    package: &DiscoveredPackage,
    lpm_root: Option<&lpm_common::LpmRoot>,
    baseline_index: Option<&ProjectV2BaselineIndex>,
) -> io::Result<OpenedPackageSource> {
    if let Some(source_dir) = package.local_source_dir.as_ref() {
        return open_absolute_directory_nofollow(source_dir).map(|directory| OpenedPackageSource {
            directory,
            path: source_dir.clone(),
        });
    }
    let baseline = lpm_root
        .zip(baseline_index)
        .and_then(|(root, index)| find_project_baseline_by_identity(index, root, package));

    if package.patch_sha256.is_some() {
        if let Some(baseline) = baseline.as_ref()
            && baseline.layout == lpm_store::PackageBaselineLayout::V2
        {
            return open_absolute_directory_nofollow(&baseline.package_dir).map(|directory| {
                OpenedPackageSource {
                    directory,
                    path: baseline.package_dir.clone(),
                }
            });
        }
        return open_project_package_directory(project_root, &package.path).map(|directory| {
            OpenedPackageSource {
                directory,
                path: PathBuf::from(&package.path),
            }
        });
    }

    if let Some(baseline) = baseline
        && let Ok(directory) = open_absolute_directory_nofollow(&baseline.package_dir)
    {
        return Ok(OpenedPackageSource {
            directory,
            path: baseline.package_dir.clone(),
        });
    }
    open_project_package_directory(project_root, &package.path).map(|directory| {
        OpenedPackageSource {
            directory,
            path: PathBuf::from(&package.path),
        }
    })
}

fn open_project_package_directory(
    project_root: Option<&cap_std::fs::Dir>,
    relative_path: &str,
) -> io::Result<cap_std::fs::Dir> {
    let root = project_root
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "project root is unavailable"))?;
    let mut directory = root.try_clone()?;
    for component in Path::new(relative_path).components() {
        let std::path::Component::Normal(name) = component else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "package path contains an unsafe component",
            ));
        };
        directory = cap_fs_ext::DirExt::open_dir_nofollow(&directory, name)?;
    }
    Ok(directory)
}

fn open_absolute_directory_nofollow(path: &Path) -> io::Result<cap_std::fs::Dir> {
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "package path has no parent"))?;
    let name = path.file_name().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "package path has no final component",
        )
    })?;
    let parent = cap_std::fs::Dir::open_ambient_dir(parent, cap_std::ambient_authority())?;
    cap_fs_ext::DirExt::open_dir_nofollow(&parent, PathBuf::from(name))
}

#[cfg(test)]
mod tests {
    use super::super::discovery::ScanMode;
    use super::*;

    fn discovered_package(
        integrity: Option<&str>,
        patch_sha256: Option<&str>,
    ) -> DiscoveredPackage {
        DiscoveredPackage {
            name: "left-pad".to_string(),
            version: "1.3.0".to_string(),
            instance_id: None,
            path: "node_modules/left-pad".to_string(),
            integrity: integrity.map(str::to_string),
            patch_sha256: patch_sha256.map(str::to_string),
            resolved_url: None,
            local_source_dir: None,
            scan_mode: ScanMode::RegistryAndStore,
            is_dev: false,
            is_optional: false,
            dependencies: Vec::new(),
        }
    }

    #[test]
    fn analysis_key_changes_when_patch_checksum_changes() {
        let first = discovered_package(Some("sha512-package"), Some("sha256-first"));
        let second = discovered_package(Some("sha512-package"), Some("sha256-second"));

        assert_ne!(first.analysis_key(), second.analysis_key());
    }

    #[test]
    fn audit_cache_identity_changes_when_a_patched_packages_base_integrity_changes() {
        let first = discovered_package(Some("sha512-first-base"), Some("sha256-patch"));
        let second = discovered_package(Some("sha512-second-base"), Some("sha256-patch"));

        assert_ne!(first.analysis_key(), second.analysis_key());
    }

    #[test]
    fn exact_instance_id_controls_analysis_identity() {
        let mut first = discovered_package(Some("sha512-package"), None);
        let mut second = first.clone();
        first.instance_id = Some(lpm_common::PackageInstanceId::derive(
            "left-pad",
            "1.3.0",
            "registry+npm",
            "root/first",
        ));
        second.instance_id = Some(lpm_common::PackageInstanceId::derive(
            "left-pad",
            "1.3.0",
            "registry+npm",
            "root/second",
        ));

        assert_ne!(first.analysis_key(), second.analysis_key());
    }

    #[test]
    fn fresh_duplicate_directory_sources_share_one_analysis_value() {
        let root = tempfile::tempdir().unwrap();
        let project_root = root.path().join("project");
        let source_root = root.path().join("local-source");
        std::fs::create_dir_all(&project_root).unwrap();
        std::fs::create_dir_all(&source_root).unwrap();
        std::fs::write(
            source_root.join("package.json"),
            r#"{"name":"local","version":"1.0.0","license":"MIT"}"#,
        )
        .unwrap();
        std::fs::write(
            source_root.join("index.js"),
            "module.exports = () => eval('local')\n",
        )
        .unwrap();
        let _env = crate::test_env::ScopedEnv::set([(
            "LPM_HOME",
            root.path().join("home/.lpm").into_os_string(),
        )]);
        let mut first = discovered_package(None, None);
        first.name = "local".to_string();
        first.version = "1.0.0".to_string();
        first.instance_id = Some(lpm_common::PackageInstanceId::derive(
            "local",
            "1.0.0",
            "directory+../local-source",
            "root/first",
        ));
        first.local_source_dir = Some(source_root);
        let mut second = first.clone();
        second.instance_id = Some(lpm_common::PackageInstanceId::derive(
            "local",
            "1.0.0",
            "directory+../local-source",
            "root/second",
        ));
        let discovery = DiscoveryResult {
            manager: super::super::discovery::ManagerKind::Lpm,
            lockfile_path: None,
            project_root,
            is_degraded: false,
            is_yarn_pnp: false,
            packages: vec![first, second],
            lpm_lockfile: None,
            lpm_lockfile_content: None,
            workspace_root: None,
        };

        let (analyses, _) = load_behavioral_analyses(&discovery, lpm_store::StoreVersion::V1);
        let first = analyses[0].as_ref().unwrap();
        let second = analyses[1].as_ref().unwrap();

        assert!(first.source.eval);
        assert!(Arc::ptr_eq(first, second));
    }
}
