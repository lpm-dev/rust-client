use super::*;

const ENV_FETCH_OVERLAP: &str = "LPM_FETCH_OVERLAP";
const ENV_FETCH_OVERLAP_MIN_SELECTED: &str = "LPM_FETCH_OVERLAP_MIN_SELECTED";
const DEFAULT_FETCH_OVERLAP_MIN_SELECTED: usize = 64;

#[derive(Debug)]
pub(super) struct FetchOverlapOutcome {
    pub(super) key: String,
    pub(super) package_display: String,
    pub(super) computed_sri: Option<String>,
    pub(super) timings: Option<TaskTimings>,
    pub(super) final_url: Option<String>,
}

#[derive(Debug)]
enum FetchOverlapTaskStatus {
    Completed(Box<FetchOverlapOutcome>),
    CacheHit,
    SkippedPlatform,
    Failed,
}

pub(super) struct FetchOverlapDrain {
    pub(super) outcomes: Vec<FetchOverlapOutcome>,
    pub(super) stats: FetchOverlapStats,
}

pub(super) struct FetchOverlapJoin {
    handle: Option<tokio::task::JoinHandle<FetchOverlapDrain>>,
}

struct BufferedSelectedPackage {
    event: lpm_resolver::SelectedPackageEvent,
    selected_at: Instant,
}

impl FetchOverlapJoin {
    pub(super) async fn drain(mut self) -> Result<FetchOverlapDrain, LpmError> {
        let start = Instant::now();
        let handle = self.handle.take().ok_or_else(|| {
            LpmError::Registry("fetch overlap dispatcher was already drained".into())
        })?;
        let mut drain = handle
            .await
            .map_err(|e| LpmError::Registry(format!("fetch overlap dispatcher panicked: {e}")))?;
        drain.stats.drain_ms = start.elapsed().as_millis();
        Ok(drain)
    }
}

impl Drop for FetchOverlapJoin {
    fn drop(&mut self) {
        if let Some(handle) = &self.handle {
            handle.abort();
        }
    }
}

pub(super) fn fetch_overlap_enabled(fusion_enabled: bool, force: bool, omit_dev: bool) -> bool {
    fetch_overlap_enabled_from_value(
        fusion_enabled,
        force,
        omit_dev,
        std::env::var(ENV_FETCH_OVERLAP).ok().as_deref(),
    )
}

fn fetch_overlap_enabled_from_value(
    fusion_enabled: bool,
    force: bool,
    omit_dev: bool,
    raw: Option<&str>,
) -> bool {
    fusion_enabled
        && !force
        && !omit_dev
        && raw.is_none_or(|value| parse_bool_env_value(value, true))
}

pub(super) fn fetch_overlap_min_selected() -> usize {
    std::env::var(ENV_FETCH_OVERLAP_MIN_SELECTED)
        .ok()
        .and_then(|raw| raw.parse::<usize>().ok())
        .filter(|&value| value > 0)
        .unwrap_or(DEFAULT_FETCH_OVERLAP_MIN_SELECTED)
}

#[allow(clippy::too_many_arguments)]
pub(super) fn spawn_fetch_overlap_dispatcher(
    mut rx: tokio::sync::mpsc::UnboundedReceiver<lpm_resolver::SelectedPackageEvent>,
    client: Arc<RegistryClient>,
    route_table: RouteTable,
    store: PackageStore,
    store_v2_handle: Option<Arc<lpm_store::v2::Store>>,
    fetch_semaphore: Arc<Semaphore>,
    fetch_coord: Arc<FetchCoordinator>,
    project_dir: PathBuf,
    gate_stats: Arc<GateStats>,
    fetch_extract_limiter: FetchExtractLimiter,
    dependency_engine_policy: Arc<crate::engine_check::DependencyEnginePolicy>,
    streaming_fetch: bool,
    min_selected: usize,
) -> FetchOverlapJoin {
    let handle = tokio::spawn(async move {
        let mut seen = HashSet::new();
        let mut buffered = Vec::new();
        let mut tasks = tokio::task::JoinSet::new();
        let mut outcomes = Vec::new();
        let mut stats = FetchOverlapStats::default();
        let mut dispatching = min_selected <= 1;

        loop {
            tokio::select! {
                event = rx.recv() => {
                    let Some(event) = event else {
                        break;
                    };
                    stats.selected_count = stats.selected_count.saturating_add(1);
                    if !dispatching {
                        buffered.push(BufferedSelectedPackage {
                            event,
                            selected_at: Instant::now(),
                        });
                        stats.record_buffered_event();
                        if stats.selected_count as usize >= min_selected {
                            dispatching = true;
                            for buffered_event in buffered.drain(..) {
                                stats.record_buffered_dispatch(
                                    buffered_event.selected_at.elapsed().as_millis(),
                                );
                                dispatch_selected_event(
                                    buffered_event.event,
                                    &route_table,
                                    &client,
                                    &store,
                                    &store_v2_handle,
                                    &fetch_semaphore,
                                    &fetch_coord,
                                    &project_dir,
                                    &gate_stats,
                                    &fetch_extract_limiter,
                                    dependency_engine_policy.as_ref(),
                                    streaming_fetch,
                                    &mut seen,
                                    &mut tasks,
                                    &mut stats,
                                );
                            }
                        }
                        continue;
                    }
                    dispatch_selected_event(
                        event,
                        &route_table,
                        &client,
                        &store,
                        &store_v2_handle,
                        &fetch_semaphore,
                        &fetch_coord,
                        &project_dir,
                        &gate_stats,
                        &fetch_extract_limiter,
                        dependency_engine_policy.as_ref(),
                        streaming_fetch,
                        &mut seen,
                        &mut tasks,
                        &mut stats,
                    );
                }
                joined = tasks.join_next(), if !tasks.is_empty() => {
                    record_overlap_task(joined, &mut stats, &mut outcomes);
                }
            }
        }

        while let Some(joined) = tasks.join_next().await {
            record_overlap_task(Some(joined), &mut stats, &mut outcomes);
        }

        FetchOverlapDrain { outcomes, stats }
    });

    FetchOverlapJoin {
        handle: Some(handle),
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn spawn_fetch_overlap_for_packages(
    packages: Vec<InstallPackage>,
    client: Arc<RegistryClient>,
    route_table: RouteTable,
    store: PackageStore,
    store_v2_handle: Option<Arc<lpm_store::v2::Store>>,
    fetch_semaphore: Arc<Semaphore>,
    fetch_coord: Arc<FetchCoordinator>,
    project_dir: PathBuf,
    gate_stats: Arc<GateStats>,
    fetch_extract_limiter: FetchExtractLimiter,
    streaming_fetch: bool,
) -> FetchOverlapJoin {
    let handle = tokio::spawn(async move {
        let mut seen = HashSet::with_capacity(packages.len());
        let mut tasks = tokio::task::JoinSet::new();
        let mut outcomes = Vec::new();
        let mut stats = FetchOverlapStats::default();

        for package in packages {
            stats.selected_count = stats.selected_count.saturating_add(1);
            dispatch_install_package(
                package,
                &route_table,
                &client,
                &store,
                &store_v2_handle,
                &fetch_semaphore,
                &fetch_coord,
                &project_dir,
                &gate_stats,
                &fetch_extract_limiter,
                streaming_fetch,
                &mut seen,
                &mut tasks,
                &mut stats,
            );
        }

        while let Some(joined) = tasks.join_next().await {
            record_overlap_task(Some(joined), &mut stats, &mut outcomes);
        }

        FetchOverlapDrain { outcomes, stats }
    });

    FetchOverlapJoin {
        handle: Some(handle),
    }
}

#[allow(clippy::too_many_arguments)]
fn dispatch_selected_event(
    event: lpm_resolver::SelectedPackageEvent,
    route_table: &RouteTable,
    client: &Arc<RegistryClient>,
    store: &PackageStore,
    store_v2_handle: &Option<Arc<lpm_store::v2::Store>>,
    fetch_semaphore: &Arc<Semaphore>,
    fetch_coord: &Arc<FetchCoordinator>,
    project_dir: &Path,
    gate_stats: &Arc<GateStats>,
    fetch_extract_limiter: &FetchExtractLimiter,
    dependency_engine_policy: &crate::engine_check::DependencyEnginePolicy,
    streaming_fetch: bool,
    seen: &mut HashSet<String>,
    tasks: &mut tokio::task::JoinSet<FetchOverlapTaskStatus>,
    stats: &mut FetchOverlapStats,
) {
    let package = install_package_from_selected_event(event, route_table, client.as_ref());
    if package.optional {
        stats.skipped_optional_count = stats.skipped_optional_count.saturating_add(1);
        return;
    }
    if !dependency_engine_policy.allows_dependency_materialization(package.node_engine.as_deref()) {
        stats.skipped_engine_count = stats.skipped_engine_count.saturating_add(1);
        return;
    }
    dispatch_install_package(
        package,
        route_table,
        client,
        store,
        store_v2_handle,
        fetch_semaphore,
        fetch_coord,
        project_dir,
        gate_stats,
        fetch_extract_limiter,
        streaming_fetch,
        seen,
        tasks,
        stats,
    );
}

#[allow(clippy::too_many_arguments)]
fn dispatch_install_package(
    package: InstallPackage,
    route_table: &RouteTable,
    client: &Arc<RegistryClient>,
    store: &PackageStore,
    store_v2_handle: &Option<Arc<lpm_store::v2::Store>>,
    fetch_semaphore: &Arc<Semaphore>,
    fetch_coord: &Arc<FetchCoordinator>,
    project_dir: &Path,
    gate_stats: &Arc<GateStats>,
    fetch_extract_limiter: &FetchExtractLimiter,
    streaming_fetch: bool,
    seen: &mut HashSet<String>,
    tasks: &mut tokio::task::JoinSet<FetchOverlapTaskStatus>,
    stats: &mut FetchOverlapStats,
) {
    let key = install_pkg_key(&package);
    if !seen.insert(key) {
        return;
    }
    if fetch_overlap_should_skip_auth(&package.name, route_table) {
        stats.skipped_auth_count = stats.skipped_auth_count.saturating_add(1);
        return;
    }
    stats.dispatched_count = stats.dispatched_count.saturating_add(1);
    tasks.spawn(fetch_selected_package(
        package,
        client.clone(),
        route_table.clone(),
        store.clone(),
        store_v2_handle.clone(),
        fetch_semaphore.clone(),
        fetch_coord.clone(),
        project_dir.to_path_buf(),
        gate_stats.clone(),
        fetch_extract_limiter.clone(),
        streaming_fetch,
    ));
}

fn record_overlap_task(
    joined: Option<Result<FetchOverlapTaskStatus, tokio::task::JoinError>>,
    stats: &mut FetchOverlapStats,
    outcomes: &mut Vec<FetchOverlapOutcome>,
) {
    match joined {
        Some(Ok(FetchOverlapTaskStatus::Completed(outcome))) => {
            stats.completed_count = stats.completed_count.saturating_add(1);
            if let Some(timings) = outcome.timings {
                stats.record_task(timings);
            }
            outcomes.push(*outcome);
        }
        Some(Ok(FetchOverlapTaskStatus::CacheHit)) => {
            stats.cache_hit_count = stats.cache_hit_count.saturating_add(1);
        }
        Some(Ok(FetchOverlapTaskStatus::SkippedPlatform)) => {
            stats.skipped_platform_count = stats.skipped_platform_count.saturating_add(1);
        }
        Some(Ok(FetchOverlapTaskStatus::Failed)) | Some(Err(_)) => {
            stats.failed_count = stats.failed_count.saturating_add(1);
        }
        None => {}
    }
}

fn fetch_overlap_should_skip_auth(name: &str, route_table: &RouteTable) -> bool {
    matches!(
        route_table.route_for_package(name),
        UpstreamRoute::Custom { auth: Some(_), .. }
    )
}

fn install_package_from_selected_event(
    event: lpm_resolver::SelectedPackageEvent,
    route_table: &RouteTable,
    registry_client: &RegistryClient,
) -> InstallPackage {
    let registry_url = registry_source_url_for(&event.name, route_table, registry_client);
    InstallPackage {
        name: event.name,
        version: event.version,
        source: format!("registry+{registry_url}"),
        dependencies: Vec::new(),
        aliases: HashMap::new(),
        root_link_names: None,
        is_direct: false,
        is_lpm: event.is_lpm,
        peers: Vec::new(),
        integrity: event.integrity,
        registry_signatures: Vec::new(),
        registry_published_at: None,
        platform: event.platform,
        node_engine: event.node_engine,
        optional: event.optional,
        tarball_url: event.tarball_url,
        metadata_checked_for_tarball: true,
    }
}

#[allow(clippy::too_many_arguments)]
async fn fetch_selected_package(
    package: InstallPackage,
    client: Arc<RegistryClient>,
    route_table: RouteTable,
    store: PackageStore,
    store_v2_handle: Option<Arc<lpm_store::v2::Store>>,
    fetch_semaphore: Arc<Semaphore>,
    fetch_coord: Arc<FetchCoordinator>,
    project_dir: PathBuf,
    gate_stats: Arc<GateStats>,
    fetch_extract_limiter: FetchExtractLimiter,
    streaming_fetch: bool,
) -> FetchOverlapTaskStatus {
    if !package_platform_compatible(&package) {
        return FetchOverlapTaskStatus::SkippedPlatform;
    }

    let key = install_pkg_key(&package);
    let package_display = format!("{}@{}", package.name, package.version);
    let result: Result<FetchOverlapTaskStatus, LpmError> = async {
        let queue_start = Instant::now();
        let key_lock = fetch_coord.lock_for(key.clone()).await;
        let _key_guard = key_lock.lock().await;

        if package.store_has_for_install_layout(&store, store_v2_handle.as_deref(), &project_dir) {
            return Ok(FetchOverlapTaskStatus::CacheHit);
        }

        let permit = fetch_semaphore
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| LpmError::Registry("fetch overlap semaphore closed".into()))?;
        let queue_wait_ms = queue_start.elapsed().as_millis();
        let (computed_sri, timings, final_url, _) = if streaming_fetch {
            fetch_and_store_streaming(
                &client,
                &route_table,
                &store,
                store_v2_handle.as_deref(),
                &package,
                queue_wait_ms,
                &project_dir,
                TarballNotFoundRecovery::PreserveProjectLockfiles,
                &gate_stats,
                permit,
                &fetch_extract_limiter,
            )
            .await?
        } else {
            fetch_and_store_legacy(
                &client,
                &route_table,
                &store,
                store_v2_handle.as_deref(),
                &package,
                queue_wait_ms,
                &project_dir,
                TarballNotFoundRecovery::PreserveProjectLockfiles,
                &gate_stats,
                permit,
                &fetch_extract_limiter,
            )
            .await?
        };

        Ok(FetchOverlapTaskStatus::Completed(Box::new(
            FetchOverlapOutcome {
                key,
                package_display: package_display.clone(),
                computed_sri: Some(computed_sri),
                timings: Some(timings),
                final_url: Some(final_url),
            },
        )))
    }
    .await;

    match result {
        Ok(status) => status,
        Err(err) => {
            tracing::debug!(
                "fetch overlap for {} failed before final fetch classification: {err}",
                package_display
            );
            FetchOverlapTaskStatus::Failed
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fetch_overlap_defaults_on_for_fresh_fusion_installs() {
        assert!(fetch_overlap_enabled_from_value(true, false, false, None));
    }

    #[test]
    fn fetch_overlap_can_be_disabled_by_environment_value() {
        assert!(!fetch_overlap_enabled_from_value(
            true,
            false,
            false,
            Some("0")
        ));
    }

    #[test]
    fn fetch_overlap_stays_off_outside_fusion_or_force_installs() {
        assert!(!fetch_overlap_enabled_from_value(false, false, false, None));
        assert!(!fetch_overlap_enabled_from_value(true, true, false, None));
    }

    #[test]
    fn fetch_overlap_stays_off_when_dev_dependencies_are_omitted() {
        assert!(!fetch_overlap_enabled_from_value(true, false, true, None));
    }

    #[test]
    fn fetch_overlap_min_selected_default_skips_tiny_graphs() {
        assert_eq!(DEFAULT_FETCH_OVERLAP_MIN_SELECTED, 64);
    }
}
