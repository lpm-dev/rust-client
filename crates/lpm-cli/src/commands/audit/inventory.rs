//! Shared package inventory for `audit` and `query` commands.
//!
//! Provides a single entry point that discovers packages, loads behavioral
//! analysis from the appropriate cache, and builds the data structures
//! needed for both auditing and querying.

use super::cache::ProjectAuditCache;
use super::discovery::{self, DiscoveredPackage, DiscoveryResult, ScanMode};
use dashmap::mapref::entry::Entry;
use lpm_security::behavioral::{PackageAnalysis, PackageDirectory};
use rayon::prelude::*;
use std::collections::{HashMap, HashSet, VecDeque};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

pub(crate) struct ProjectV2BaselineIndex {
    uses_virtual_store: bool,
    scoped: lpm_store::V2BaselineIndex,
    by_instance: HashMap<lpm_common::PackageInstanceId, Arc<lpm_store::InstalledPackageBaseline>>,
    by_coordinates: HashMap<(String, String), Vec<Arc<lpm_store::InstalledPackageBaseline>>>,
    global: std::sync::OnceLock<lpm_store::V2BaselineIndex>,
    global_artifact_directories: std::sync::OnceLock<HashMap<String, Vec<PathBuf>>>,
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
            by_coordinates: HashMap::new(),
            global: std::sync::OnceLock::new(),
            global_artifact_directories: std::sync::OnceLock::new(),
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
        by_coordinates: HashMap::new(),
        global: std::sync::OnceLock::new(),
        global_artifact_directories: std::sync::OnceLock::new(),
    }
}

pub(crate) fn build_project_script_review_index(
    project_dir: &Path,
    lpm_root: &lpm_common::LpmRoot,
    store_version: lpm_store::StoreVersion,
    lockfile: Option<&lpm_lockfile::Lockfile>,
) -> ProjectV2BaselineIndex {
    let mut index =
        build_project_v2_baseline_index(project_dir, lpm_root, store_version, lockfile, None);
    if !store_version.uses_virtual_store() {
        index.by_coordinates = v1_artifact_baselines(project_dir, lpm_root, lockfile);
    } else {
        for package in lockfile.into_iter().flat_map(|lockfile| &lockfile.packages) {
            if let Some(baseline) = package
                .instance_id
                .and_then(|id| index.by_instance.get(&id))
            {
                index
                    .by_coordinates
                    .entry((package.name.clone(), package.version.clone()))
                    .or_default()
                    .push(Arc::clone(baseline));
            }
        }
    }
    index
}

fn v1_artifact_baselines(
    project_dir: &Path,
    lpm_root: &lpm_common::LpmRoot,
    lockfile: Option<&lpm_lockfile::Lockfile>,
) -> HashMap<(String, String), Vec<Arc<lpm_store::InstalledPackageBaseline>>> {
    use lpm_lockfile::Source;
    let store = lpm_store::PackageStore::from_root(lpm_root);
    let mut candidates: HashMap<_, Vec<_>> = HashMap::new();
    for package in lockfile.into_iter().flat_map(|lockfile| &lockfile.packages) {
        let path = match package.source_kind() {
            Some(Ok(Source::Directory { path } | Source::Link { path })) => {
                project_dir.join(path).canonicalize().ok()
            }
            Some(Ok(Source::Tarball { url })) if url.starts_with("file:") => package
                .integrity
                .as_deref()
                .and_then(|sri| lpm_common::integrity::Integrity::parse(sri).ok())
                .filter(|sri| sri.algorithm == lpm_common::integrity::HashAlgorithm::Sha256)
                .and_then(|sri| store.tarball_local_store_path(&hex::encode(sri.hash)).ok()),
            Some(Ok(Source::Tarball { .. } | Source::Git { .. })) => package
                .integrity
                .as_deref()
                .and_then(|sri| store.tarball_store_path(sri).ok()),
            Some(Ok(Source::Registry { .. })) | None => {
                Some(store.package_dir(&package.name, &package.version))
            }
            Some(Err(_)) => None,
        };
        if let Some(package_dir) = path {
            candidates
                .entry((package.name.clone(), package.version.clone()))
                .or_default()
                .push(Arc::new(lpm_store::InstalledPackageBaseline {
                    pristine_dir: package_dir.clone(),
                    package_dir,
                    integrity: package.integrity.clone().unwrap_or_default(),
                    layout: lpm_store::PackageBaselineLayout::V1,
                }));
        }
    }
    candidates
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

pub(crate) fn find_project_artifact_directories(
    index: &ProjectV2BaselineIndex,
    lpm_root: &lpm_common::LpmRoot,
    name: &str,
    version: &str,
    integrity: Option<&str>,
) -> Vec<PathBuf> {
    let mut directories = Vec::new();
    if let Some(candidates) = index
        .by_coordinates
        .get(&(name.to_string(), version.to_string()))
    {
        for candidate in candidates {
            if integrity.is_none_or(|value| value == candidate.integrity) {
                directories.push(candidate.package_dir.clone());
            }
        }
    }
    if let Some(candidate) = lpm_store::find_installed_package_baseline_by_identity_indexed(
        &index.scoped,
        lpm_root,
        name,
        version,
        integrity,
    ) {
        directories.push(candidate.package_dir);
    }
    directories.sort_unstable();
    directories.dedup();
    directories
}

pub(crate) fn find_cached_artifact_directories(
    index: &ProjectV2BaselineIndex,
    lpm_root: &lpm_common::LpmRoot,
    name: &str,
    version: &str,
    integrity: Option<&str>,
) -> Vec<PathBuf> {
    let global = index
        .global
        .get_or_init(|| lpm_store::V2BaselineIndex::build(lpm_root).unwrap_or_default());
    let by_integrity = index.global_artifact_directories.get_or_init(|| {
        let mut directories: HashMap<String, Vec<PathBuf>> = HashMap::new();
        for baseline in global.materializations() {
            directories
                .entry(baseline.integrity.clone())
                .or_default()
                .push(baseline.package_dir.clone());
        }
        for paths in directories.values_mut() {
            paths.sort_unstable();
            paths.dedup();
        }
        directories
    });
    if let Some(paths) = integrity.and_then(|value| by_integrity.get(value)) {
        return paths.clone();
    }
    lpm_store::find_installed_package_baseline_by_identity_indexed(
        global, lpm_root, name, version, integrity,
    )
    .map(|baseline| vec![baseline.package_dir])
    .unwrap_or_default()
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
    /// Packages the install left out, aligned with [`DiscoveryResult::packages`].
    pub(crate) not_installed: Vec<bool>,
    pub(crate) baseline_index: Option<ProjectV2BaselineIndex>,
}

/// Behavioral analyses for a [`DiscoveryResult`], each vector aligned with
/// its packages.
pub(crate) struct BehavioralAnalyses {
    pub(crate) analyses: Vec<Option<Arc<PackageAnalysis>>>,
    pub(crate) source_paths: Vec<Option<PathBuf>>,
    /// Packages with no source because the install left them out: optional
    /// or dev packages missing from the paths `package-lock.json` records,
    /// and `lpm.lock` packages skipped on this platform whose source is
    /// absent.
    pub(crate) not_installed: Vec<bool>,
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
    /// [`PackageInventory::from_discovery_with_options`].
    pub fn discover(
        project_dir: &Path,
    ) -> Result<discovery::DiscoveryResult, lpm_common::LpmError> {
        discovery::discover_packages_retaining_parsed_lpm_lockfile(project_dir)
    }

    /// [`Self::discover`] with the lockfile search stopped at `boundary`.
    pub(crate) fn discover_within(
        project_dir: &Path,
        boundary: &Path,
    ) -> Result<discovery::DiscoveryResult, lpm_common::LpmError> {
        discovery::discover_packages_within(project_dir, boundary)
    }

    pub(crate) fn from_discovery_with_options(
        discovery: discovery::DiscoveryResult,
        store_version: lpm_store::StoreVersion,
        lpm_root: Option<&lpm_common::LpmRoot>,
        load_behavioral_analysis: bool,
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
        let BehavioralAnalyses {
            analyses,
            source_paths,
            not_installed,
        } = if load_behavioral_analysis {
            load_behavioral_analyses_with_index(&discovery, lpm_root, baseline_index.as_ref())
        } else {
            resolve_package_sources_with_index(&discovery, lpm_root, baseline_index.as_ref())
        };
        Self {
            discovery,
            analyses,
            source_paths,
            not_installed,
            baseline_index,
        }
    }

    /// Drop the packages the install left out, so the inventory holds only
    /// the installed tree.
    pub(crate) fn retain_installed(&mut self) {
        if !self.not_installed.contains(&true) {
            return;
        }
        let not_installed = std::mem::take(&mut self.not_installed);
        self.not_installed = vec![false; not_installed.len()];
        self.remove_marked(&not_installed);
    }

    /// Drop the packages `keep` rejects.
    pub(crate) fn retain_packages(&mut self, keep: impl Fn(&DiscoveredPackage) -> bool) {
        let remove: Vec<bool> = self
            .discovery
            .packages
            .iter()
            .map(|package| !keep(package))
            .collect();
        self.remove_marked(&remove);
    }

    /// Drop the packages `remove` marks, aligned with the discovered
    /// packages, with their per-package data.
    fn remove_marked(&mut self, remove: &[bool]) {
        if !remove.contains(&true) {
            return;
        }
        self.discovery.remove_packages(remove);
        retain_unmarked(&mut self.analyses, remove);
        retain_unmarked(&mut self.source_paths, remove);
        retain_unmarked(&mut self.not_installed, remove);
    }
}

fn retain_unmarked<T>(values: &mut Vec<T>, remove: &[bool]) {
    let mut marks = remove.iter();
    values.retain(|_| !marks.next().is_some_and(|&flag| flag));
}

pub(crate) fn load_behavioral_analyses(
    discovery: &DiscoveryResult,
    store_version: lpm_store::StoreVersion,
) -> BehavioralAnalyses {
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

fn scannable_packages(discovery: &DiscoveryResult) -> Vec<(usize, &DiscoveredPackage)> {
    discovery
        .packages
        .iter()
        .enumerate()
        .filter(|(_, package)| {
            matches!(
                package.scan_mode,
                ScanMode::FullLocal | ScanMode::RegistryAndStore
            )
        })
        .collect()
}

fn resolve_package_sources_with_index(
    discovery: &DiscoveryResult,
    lpm_root: Option<&lpm_common::LpmRoot>,
    baseline_index: Option<&ProjectV2BaselineIndex>,
) -> BehavioralAnalyses {
    enum SourceProbe {
        Present {
            package_index: usize,
            source_path: PathBuf,
        },
        NotInstalled(usize),
    }

    let scannable = scannable_packages(discovery);
    let project_root = open_project_root(&discovery.project_root).ok();
    let probed: Vec<SourceProbe> = scannable
        .par_iter()
        .filter_map(|(package_index, package)| {
            match open_package_source(project_root.as_ref(), package, lpm_root, baseline_index) {
                Ok(source) => Some(SourceProbe::Present {
                    package_index: *package_index,
                    source_path: source.path,
                }),
                Err(error)
                    if package.platform_skipped
                        && project_root.is_some()
                        && error.kind() == io::ErrorKind::NotFound =>
                {
                    Some(SourceProbe::NotInstalled(*package_index))
                }
                Err(_) => None,
            }
        })
        .collect();

    let analyses = vec![None; discovery.packages.len()];
    let mut source_paths = vec![None; discovery.packages.len()];
    let mut not_installed: Vec<bool> = discovery
        .packages
        .iter()
        .map(|package| package.scan_mode == ScanMode::NotInstalled)
        .collect();
    for probe in probed {
        match probe {
            SourceProbe::Present {
                package_index,
                source_path,
            } => {
                if source_path != Path::new(&discovery.packages[package_index].path) {
                    source_paths[package_index] = Some(source_path);
                }
            }
            SourceProbe::NotInstalled(package_index) => {
                not_installed[package_index] = true;
            }
        }
    }

    BehavioralAnalyses {
        analyses,
        source_paths,
        not_installed,
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
enum StoreGroupKey {
    Identified(PathBuf, crate::directory_transaction::DirectoryIdentity),
    Unique(usize),
}

fn load_behavioral_analyses_with_index(
    discovery: &DiscoveryResult,
    lpm_root: Option<&lpm_common::LpmRoot>,
    baseline_index: Option<&ProjectV2BaselineIndex>,
) -> BehavioralAnalyses {
    struct OpenedRow {
        scan_index: usize,
        package_index: usize,
        source: OpenedPackageSource,
        dir_identity: Option<crate::directory_transaction::DirectoryIdentity>,
    }

    enum OpenStep {
        Opened(OpenedRow),
        NotInstalled(usize),
    }

    let scannable = scannable_packages(discovery);
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
    let nested = lpm_security::behavioral::nested_packages(
        discovery
            .packages
            .iter()
            .map(|package| Path::new(&package.path)),
    );

    let opened_steps: Vec<OpenStep> = scannable
        .par_iter()
        .enumerate()
        .filter_map(|(scan_index, (package_index, package))| {
            match open_package_source(project_root.as_ref(), package, lpm_root, baseline_index) {
                Ok(source) => {
                    let dir_identity = if source.origin == SourceOrigin::Store {
                        crate::directory_transaction::directory_identity(&source.directory).ok()
                    } else {
                        None
                    };
                    Some(OpenStep::Opened(OpenedRow {
                        scan_index,
                        package_index: *package_index,
                        source,
                        dir_identity,
                    }))
                }
                Err(error)
                    if package.platform_skipped
                        && project_root.is_some()
                        && error.kind() == io::ErrorKind::NotFound =>
                {
                    Some(OpenStep::NotInstalled(*package_index))
                }
                Err(_) => None,
            }
        })
        .collect();

    let mut not_installed: Vec<bool> = discovery
        .packages
        .iter()
        .map(|package| package.scan_mode == ScanMode::NotInstalled)
        .collect();

    // Group store rows by (path, filesystem identity) before entering Rayon so
    // each physical directory is fingerprinted and analyzed once without ever
    // blocking a Rayon worker on a OnceLock across nested Rayon work.
    struct WorkGroup {
        representative_dir: cap_std::fs::Dir,
        origin: SourceOrigin,
        members: Vec<(usize, usize, PathBuf)>,
    }

    let mut store_group_indices: HashMap<StoreGroupKey, usize> = HashMap::new();
    let mut groups: Vec<WorkGroup> = Vec::with_capacity(opened_steps.len());

    for step in opened_steps {
        match step {
            OpenStep::NotInstalled(package_index) => {
                not_installed[package_index] = true;
            }
            OpenStep::Opened(row) => {
                if row.source.origin == SourceOrigin::Store {
                    let group_key = match row.dir_identity {
                        Some(identity) => {
                            StoreGroupKey::Identified(row.source.path.clone(), identity)
                        }
                        None => StoreGroupKey::Unique(row.scan_index),
                    };
                    if let Some(&group_idx) = store_group_indices.get(&group_key) {
                        groups[group_idx].members.push((
                            row.scan_index,
                            row.package_index,
                            row.source.path,
                        ));
                    } else {
                        let group_idx = groups.len();
                        store_group_indices.insert(group_key, group_idx);
                        groups.push(WorkGroup {
                            representative_dir: row.source.directory,
                            origin: SourceOrigin::Store,
                            members: vec![(row.scan_index, row.package_index, row.source.path)],
                        });
                    }
                } else {
                    groups.push(WorkGroup {
                        representative_dir: row.source.directory,
                        origin: row.source.origin,
                        members: vec![(row.scan_index, row.package_index, row.source.path)],
                    });
                }
            }
        }
    }

    let project_cache_ref = project_cache.as_ref();
    let shared_by_fingerprint = dashmap::DashMap::new();

    let loaded: Vec<LoadedAnalysis> = groups
        .into_par_iter()
        .flat_map_iter(|group| {
            let mut results = Vec::with_capacity(group.members.len());
            let mut cache_misses = Vec::new();
            let contents = match group.origin {
                SourceOrigin::Store => PackageDirectory::Published,
                SourceOrigin::Project => {
                    let first_pkg = &discovery.packages[group.members[0].1];
                    PackageDirectory::Installed(
                        nested
                            .get(Path::new(&first_pkg.path))
                            .map_or(&[], Vec::as_slice),
                    )
                }
                SourceOrigin::LocalDirectory => PackageDirectory::LocalSource,
            };

            if let Some(cache) = project_cache_ref {
                let any_candidate = group.members.iter().any(|(scan_index, package_index, _)| {
                    cache.has_candidate(
                        &analysis_keys[*scan_index],
                        &discovery.packages[*package_index],
                    )
                });
                let fingerprint = if any_candidate {
                    lpm_security::behavioral::package_input_fingerprint_from_open_dir(
                        &group.representative_dir,
                        contents,
                    )
                    .ok()
                } else {
                    None
                };
                for member in group.members {
                    let (scan_index, package_index, source_path) = member;
                    let key = &analysis_keys[scan_index];
                    let package = &discovery.packages[package_index];
                    if let Some(cached) = fingerprint
                        .as_deref()
                        .and_then(|fp| cache.get(key, package, fp))
                    {
                        results.push(LoadedAnalysis {
                            scan_index,
                            package_index,
                            analysis: cached,
                            cache_fingerprint: None,
                            source_path,
                        });
                    } else {
                        cache_misses.push((scan_index, package_index, source_path));
                    }
                }
            } else {
                cache_misses = group.members;
            }

            if !cache_misses.is_empty() {
                let (analysis, cache_fingerprint) =
                    lpm_security::behavioral::analyze_package_from_open_dir_with_fingerprint(
                        &group.representative_dir,
                        contents,
                    );
                let mut analysis = Arc::new(analysis);
                if let Some(fingerprint) = cache_fingerprint.as_ref() {
                    analysis = match shared_by_fingerprint.entry(fingerprint.clone()) {
                        Entry::Occupied(entry) => Arc::clone(entry.get()),
                        Entry::Vacant(entry) => Arc::clone(&entry.insert(analysis)),
                    };
                }
                for (scan_index, package_index, source_path) in cache_misses {
                    results.push(LoadedAnalysis {
                        scan_index,
                        package_index,
                        analysis: Arc::clone(&analysis),
                        cache_fingerprint: cache_fingerprint.clone(),
                        source_path,
                    });
                }
            }

            results
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
    BehavioralAnalyses {
        analyses,
        source_paths,
        not_installed,
    }
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

/// Opens the bytes a package was published with, for consumers that must
/// never read what an install script or patch changed: a `file:` or `link:`
/// dependency's own directory, else the store's pristine copy of the
/// release. Only a project without an LPM store falls back to its
/// `node_modules` copy.
pub(crate) fn open_package_pristine_directory(
    project_root: Option<&cap_std::fs::Dir>,
    package: &DiscoveredPackage,
    lpm_root: Option<&lpm_common::LpmRoot>,
    baseline_index: Option<&ProjectV2BaselineIndex>,
) -> io::Result<cap_std::fs::Dir> {
    if let Some(source_dir) = package.local_source_dir.as_ref() {
        return open_absolute_directory_nofollow(source_dir);
    }
    match lpm_root.zip(baseline_index) {
        Some((root, index)) => {
            let baseline =
                find_project_baseline_by_identity(index, root, package).ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::NotFound,
                        "the package's published bytes are not in the store",
                    )
                })?;
            open_absolute_directory_nofollow(&baseline.pristine_dir)
        }
        None => open_project_package_directory(project_root, &package.path),
    }
}

struct OpenedPackageSource {
    directory: cap_std::fs::Dir,
    path: PathBuf,
    origin: SourceOrigin,
}

/// Where an opened package directory is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SourceOrigin {
    /// The store, which holds the package's published files.
    Store,
    /// The project, where a linker may have nested other packages in it.
    Project,
    /// The local directory a `file:` or `link:` dependency names.
    LocalDirectory,
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
            origin: SourceOrigin::LocalDirectory,
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
                    origin: SourceOrigin::Store,
                }
            });
        }
        return open_project_package_directory(project_root, &package.path).map(|directory| {
            OpenedPackageSource {
                directory,
                path: PathBuf::from(&package.path),
                origin: SourceOrigin::Project,
            }
        });
    }

    if let Some(baseline) = baseline
        && let Ok(directory) = open_absolute_directory_nofollow(&baseline.package_dir)
    {
        return Ok(OpenedPackageSource {
            directory,
            path: baseline.package_dir.clone(),
            origin: SourceOrigin::Store,
        });
    }
    open_project_package_directory(project_root, &package.path).map(|directory| {
        OpenedPackageSource {
            directory,
            path: PathBuf::from(&package.path),
            origin: SourceOrigin::Project,
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
            platform_skipped: false,
            installed: None,
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

        let analyses = load_behavioral_analyses(&discovery, lpm_store::StoreVersion::V1).analyses;
        let first = analyses[0].as_ref().unwrap();
        let second = analyses[1].as_ref().unwrap();

        assert!(first.source.eval);
        assert!(Arc::ptr_eq(first, second));
    }

    #[test]
    fn a_platform_skipped_package_is_not_installed_only_when_its_source_is_absent() {
        let root = tempfile::tempdir().unwrap();
        let _env = crate::test_env::ScopedEnv::set([(
            "LPM_HOME",
            root.path().join("home/.lpm").into_os_string(),
        )]);
        let project_root = root.path().join("project");
        let installed = project_root.join("node_modules/installed-skipped");
        std::fs::create_dir_all(&installed).unwrap();
        std::fs::write(
            installed.join("package.json"),
            r#"{"name":"installed-skipped","version":"1.0.0","license":"MIT"}"#,
        )
        .unwrap();
        std::fs::write(installed.join("index.js"), "module.exports = 1\n").unwrap();
        let package = |name: &str, platform_skipped: bool| DiscoveredPackage {
            name: name.to_string(),
            version: "1.0.0".to_string(),
            path: format!("node_modules/{name}"),
            platform_skipped,
            ..discovered_package(None, None)
        };
        let discovery = DiscoveryResult {
            manager: super::super::discovery::ManagerKind::Lpm,
            lockfile_path: None,
            project_root,
            is_degraded: false,
            is_yarn_pnp: false,
            packages: vec![
                package("installed-skipped", true),
                package("absent-skipped", true),
                package("absent-required", false),
                DiscoveredPackage {
                    scan_mode: ScanMode::NotInstalled,
                    ..package("absent-foreign-optional", false)
                },
            ],
            lpm_lockfile: None,
            lpm_lockfile_content: None,
            workspace_root: None,
        };

        let loaded = load_behavioral_analyses_with_index(&discovery, None, None);

        assert!(loaded.analyses[0].is_some());
        assert!(loaded.analyses[1..].iter().all(Option::is_none));
        assert_eq!(loaded.not_installed, [false, true, false, true]);
    }

    #[test]
    fn a_platform_skipped_package_is_not_called_not_installed_when_the_project_root_cannot_open() {
        let root = tempfile::tempdir().unwrap();
        let _env = crate::test_env::ScopedEnv::set([(
            "LPM_HOME",
            root.path().join("home/.lpm").into_os_string(),
        )]);
        let discovery = DiscoveryResult {
            manager: super::super::discovery::ManagerKind::Lpm,
            lockfile_path: None,
            project_root: root.path().join("missing-project"),
            is_degraded: false,
            is_yarn_pnp: false,
            packages: vec![DiscoveredPackage {
                platform_skipped: true,
                ..discovered_package(None, None)
            }],
            lpm_lockfile: None,
            lpm_lockfile_content: None,
            workspace_root: None,
        };

        let loaded = load_behavioral_analyses_with_index(&discovery, None, None);

        assert_eq!(loaded.not_installed, [false]);
    }

    #[test]
    fn reads_bundled_dependencies_but_not_the_packages_nested_in_a_package_or_local_installs() {
        let root = tempfile::tempdir().unwrap();
        let _env = crate::test_env::ScopedEnv::set([(
            "LPM_HOME",
            root.path().join("home/.lpm").into_os_string(),
        )]);
        let project_root = root.path().join("project");
        let source_root = root.path().join("local-source");
        let files = [
            (
                "project/node_modules/kit/package.json",
                r#"{"name":"kit","version":"1.0.0","license":"MIT"}"#,
            ),
            (
                "project/node_modules/kit/index.js",
                "module.exports = require('helper')\n",
            ),
            (
                "project/node_modules/kit/node_modules/helper/index.js",
                "module.exports = input => eval(input)\n",
            ),
            (
                "project/node_modules/kit/node_modules/@scope/runner/package.json",
                r#"{"name":"@scope/runner","version":"2.0.0","license":"MIT"}"#,
            ),
            (
                "project/node_modules/kit/node_modules/@scope/runner/index.js",
                "require('child_process').exec('echo runner')\n",
            ),
            (
                "local-source/package.json",
                r#"{"name":"local","version":"1.0.0","license":"MIT"}"#,
            ),
            ("local-source/index.js", "module.exports = 1\n"),
            (
                "local-source/node_modules/tool/index.js",
                "module.exports = input => eval(input)\n",
            ),
        ];
        for (path, content) in files {
            let path = root.path().join(path);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, content).unwrap();
        }
        let package = |name: &str, version: &str, path: &str| DiscoveredPackage {
            name: name.to_string(),
            version: version.to_string(),
            path: path.to_string(),
            scan_mode: ScanMode::FullLocal,
            ..discovered_package(None, None)
        };
        let local = DiscoveredPackage {
            local_source_dir: Some(source_root),
            ..package("local", "1.0.0", "node_modules/local")
        };
        let discovery = DiscoveryResult {
            manager: super::super::discovery::ManagerKind::Npm,
            lockfile_path: None,
            project_root,
            is_degraded: false,
            is_yarn_pnp: false,
            packages: vec![
                package("kit", "1.0.0", "node_modules/kit"),
                package(
                    "@scope/runner",
                    "2.0.0",
                    "node_modules/kit/node_modules/@scope/runner",
                ),
                local,
            ],
            lpm_lockfile: None,
            lpm_lockfile_content: None,
            workspace_root: None,
        };

        let analyses = load_behavioral_analyses_with_index(&discovery, None, None).analyses;
        let [kit, runner, local] = [0, 1, 2].map(|index| analyses[index].as_ref().unwrap());

        assert!(kit.source.eval);
        assert!(!kit.source.child_process);
        assert!(runner.source.child_process);
        assert!(!local.source.eval);
        assert_eq!(local.meta.files_scanned, 1);
    }

    #[test]
    fn from_discovery_without_behavioral_analysis_skips_ast_scan_and_preserves_not_installed() {
        let root = tempfile::tempdir().unwrap();
        let project_root = root.path().join("project");
        let pkg_dir = project_root.join("node_modules/present-pkg");
        std::fs::create_dir_all(&pkg_dir).unwrap();
        std::fs::write(
            pkg_dir.join("package.json"),
            r#"{"name":"present-pkg","version":"1.0.0"}"#,
        )
        .unwrap();
        std::fs::write(pkg_dir.join("index.js"), "eval('x')\n").unwrap();

        let present = DiscoveredPackage {
            name: "present-pkg".to_string(),
            version: "1.0.0".to_string(),
            path: "node_modules/present-pkg".to_string(),
            scan_mode: ScanMode::FullLocal,
            ..discovered_package(None, None)
        };
        let skipped = DiscoveredPackage {
            name: "darwin-only".to_string(),
            version: "1.0.0".to_string(),
            path: "node_modules/darwin-only".to_string(),
            scan_mode: ScanMode::FullLocal,
            platform_skipped: true,
            ..discovered_package(None, None)
        };
        let discovery = DiscoveryResult {
            manager: super::super::discovery::ManagerKind::Npm,
            lockfile_path: None,
            project_root,
            is_degraded: false,
            is_yarn_pnp: false,
            packages: vec![present, skipped],
            lpm_lockfile: None,
            lpm_lockfile_content: None,
            workspace_root: None,
        };

        let mut inv = PackageInventory::from_discovery_with_options(
            discovery,
            lpm_store::StoreVersion::V2,
            None,
            false,
        );
        assert_eq!(inv.analyses.len(), 2);
        assert!(inv.analyses.iter().all(Option::is_none));
        assert_eq!(inv.not_installed, vec![false, true]);
        inv.retain_installed();
        assert_eq!(inv.discovery.packages.len(), 1);
        assert_eq!(inv.discovery.packages[0].name, "present-pkg");
    }

    #[test]
    fn shared_store_directory_with_nested_rayon_files_completes_without_deadlock() {
        let root = tempfile::tempdir().unwrap();
        let lpm_home = root.path().join("lpm-home");
        let _env =
            crate::test_env::ScopedEnv::set([("LPM_HOME", lpm_home.clone().into_os_string())]);
        let lpm_root = lpm_common::LpmRoot::from_dir(lpm_home);
        let project_root = root.path().join("project");
        std::fs::create_dir_all(&project_root).unwrap();

        let store_pkg = lpm_root.store_v1().join("shared-lib@1.0.0");
        std::fs::create_dir_all(&store_pkg).unwrap();
        let integrity = "sha512-shared-lib-test";
        std::fs::write(store_pkg.join(".integrity"), integrity).unwrap();
        std::fs::write(
            store_pkg.join("package.json"),
            r#"{"name":"shared-lib","version":"1.0.0"}"#,
        )
        .unwrap();
        // >= 20 source files triggers nested Rayon inside lpm-security.
        for idx in 0..24 {
            let body = if idx == 0 {
                "eval('1 + 1');\n"
            } else {
                "export const ok = 1;\n"
            };
            std::fs::write(store_pkg.join(format!("mod_{idx:02}.js")), body).unwrap();
        }

        let packages: Vec<DiscoveredPackage> = (0..4)
            .map(|idx| DiscoveredPackage {
                name: "shared-lib".to_string(),
                version: "1.0.0".to_string(),
                path: format!("node_modules/p{idx}/node_modules/shared-lib"),
                scan_mode: ScanMode::RegistryAndStore,
                ..discovered_package(Some(integrity), None)
            })
            .collect();
        let discovery = DiscoveryResult {
            manager: super::super::discovery::ManagerKind::Lpm,
            lockfile_path: None,
            project_root: project_root.clone(),
            is_degraded: false,
            is_yarn_pnp: false,
            packages,
            lpm_lockfile: None,
            lpm_lockfile_content: None,
            workspace_root: None,
        };
        let baseline_index = build_project_v2_baseline_index(
            &project_root,
            &lpm_root,
            lpm_store::StoreVersion::V1,
            None,
            None,
        );

        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let pool = rayon::ThreadPoolBuilder::new()
                .num_threads(2)
                .build()
                .unwrap();
            let result = pool.install(|| {
                load_behavioral_analyses_with_index(
                    &discovery,
                    Some(&lpm_root),
                    Some(&baseline_index),
                )
            });
            let _ = tx.send(result);
        });

        let loaded = rx
            .recv_timeout(std::time::Duration::from_secs(15))
            .expect("behavioral scan on shared store path must not deadlock");
        assert_eq!(loaded.analyses.len(), 4);
        let first = loaded.analyses[0].as_ref().unwrap();
        assert!(first.source.eval);
        for other in &loaded.analyses[1..] {
            assert!(Arc::ptr_eq(first, other.as_ref().unwrap()));
        }
    }
}
