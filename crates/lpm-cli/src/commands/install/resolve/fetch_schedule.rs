use super::super::*;
use super::ExperimentalResolverStats;
use super::PackageIdentity;
use super::graph::{PackageDraft, package_should_materialize};

pub(super) type FetchHandle = tokio::task::JoinHandle<Result<FetchOutcome, LpmError>>;

#[derive(Debug)]
pub(super) struct FetchOutcome {
    pub(super) key: String,
    pub(super) package_display: String,
    pub(super) computed_sri: Option<String>,
    pub(super) timings: Option<TaskTimings>,
    pub(super) cached: bool,
}

pub(super) fn lockfile_fetch_schedule(packages: &[InstallPackage]) -> Vec<InstallPackage> {
    let mut scheduled = packages.to_vec();
    scheduled.sort_by(|a, b| {
        b.is_direct
            .cmp(&a.is_direct)
            .then_with(|| b.dependencies.len().cmp(&a.dependencies.len()))
            .then_with(|| b.peers.len().cmp(&a.peers.len()))
            .then_with(|| a.name.cmp(&b.name))
            .then_with(|| a.version.cmp(&b.version))
    });
    scheduled
}

#[allow(clippy::too_many_arguments)]
pub(super) fn spawn_missing_fetches_for_drafts(
    packages: &HashMap<PackageIdentity, PackageDraft>,
    store: &PackageStore,
    store_v2_handle: Option<Arc<lpm_store::v2::Store>>,
    project_dir: &Path,
    client: &Arc<RegistryClient>,
    route_table: &RouteTable,
    fetch_queue: &Arc<Semaphore>,
    gate_stats: Arc<GateStats>,
    force: bool,
    fetch_extract_limiter: FetchExtractLimiter,
    fetch_handles: &mut HashMap<String, FetchHandle>,
    stats: &mut ExperimentalResolverStats,
) -> Result<(), LpmError> {
    for draft in packages.values() {
        let package = &draft.package;
        if fetch_handles.contains_key(&install_pkg_key(package)) {
            continue;
        }
        if package_should_materialize(package)? {
            maybe_spawn_fetch(
                package.clone(),
                store,
                store_v2_handle.clone(),
                project_dir,
                Arc::clone(client),
                route_table.clone(),
                Arc::clone(fetch_queue),
                Arc::clone(&gate_stats),
                force,
                fetch_extract_limiter.clone(),
                ArtifactSelection::FreshResolution,
                fetch_handles,
                stats,
            );
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(super) fn spawn_fetches_for_packages(
    packages: &[InstallPackage],
    store: &PackageStore,
    store_v2_handle: Option<Arc<lpm_store::v2::Store>>,
    project_dir: &Path,
    client: &Arc<RegistryClient>,
    route_table: &RouteTable,
    fetch_queue: &Arc<Semaphore>,
    gate_stats: Arc<GateStats>,
    force: bool,
    fetch_extract_limiter: FetchExtractLimiter,
    artifact_selection: ArtifactSelection,
    fetch_handles: &mut HashMap<String, FetchHandle>,
    stats: &mut ExperimentalResolverStats,
) -> Result<(), LpmError> {
    for package in packages {
        if package_should_materialize(package)? {
            maybe_spawn_fetch(
                package.clone(),
                store,
                store_v2_handle.clone(),
                project_dir,
                Arc::clone(client),
                route_table.clone(),
                Arc::clone(fetch_queue),
                Arc::clone(&gate_stats),
                force,
                fetch_extract_limiter.clone(),
                artifact_selection,
                fetch_handles,
                stats,
            );
        } else {
            stats.platform_pre_skipped += 1;
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(super) fn maybe_spawn_fetch(
    package: InstallPackage,
    store: &PackageStore,
    store_v2_handle: Option<Arc<lpm_store::v2::Store>>,
    project_dir: &Path,
    client: Arc<RegistryClient>,
    route_table: RouteTable,
    fetch_queue: Arc<Semaphore>,
    gate_stats: Arc<GateStats>,
    force: bool,
    fetch_extract_limiter: FetchExtractLimiter,
    artifact_selection: ArtifactSelection,
    fetch_handles: &mut HashMap<String, FetchHandle>,
    stats: &mut ExperimentalResolverStats,
) {
    let key = install_pkg_key(&package);
    if fetch_handles.contains_key(&key) {
        return;
    }
    let insert_key = key.clone();
    let package_display = format!("{}@{}", package.name, package.version);
    stats.fetch_dispatched += 1;
    let store = store.clone();
    let project_dir = project_dir.to_path_buf();
    let handle = tokio::spawn(async move {
        if is_local_source_package(&package) {
            if package.store_has_source_aware(&store, &project_dir) {
                return Ok(FetchOutcome {
                    key,
                    package_display,
                    computed_sri: package.integrity.clone(),
                    timings: None,
                    cached: true,
                });
            }
            package.store_path_or_err(&store, &project_dir, None)?;
            return Err(LpmError::Registry(format!(
                "local source package {}@{} is missing package.json",
                package.name, package.version
            )));
        }

        if !force
            && package.store_has_for_install_layout(
                &store,
                store_v2_handle.as_deref(),
                &project_dir,
            )
        {
            return Ok(FetchOutcome {
                key,
                package_display,
                computed_sri: package.integrity.clone(),
                timings: None,
                cached: true,
            });
        }

        let queue_start = Instant::now();
        let permit = fetch_queue
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| LpmError::Registry("experimental resolver queue closed".into()))?;
        let queue_wait_ms = queue_start.elapsed().as_millis();
        let (computed_sri, timings, _, _) = fetch_and_store_streaming(
            &client,
            &route_table,
            &store,
            store_v2_handle.as_deref(),
            &package,
            queue_wait_ms,
            artifact_selection,
            &gate_stats,
            permit,
            &fetch_extract_limiter,
        )
        .await?;
        Ok(FetchOutcome {
            key,
            package_display,
            computed_sri: Some(computed_sri),
            timings: Some(timings),
            cached: false,
        })
    });
    fetch_handles.insert(insert_key, handle);
}

fn is_local_source_package(package: &InstallPackage) -> bool {
    matches!(
        package.source_kind(),
        Ok(lpm_lockfile::Source::Directory { .. }) | Ok(lpm_lockfile::Source::Link { .. })
    )
}
