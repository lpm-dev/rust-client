use super::*;

const ENV_FETCH_OVERLAP: &str = "LPM_FETCH_OVERLAP";
const ENV_FETCH_OVERLAP_MIN_SELECTED: &str = "LPM_FETCH_OVERLAP_MIN_SELECTED";
const DEFAULT_FETCH_OVERLAP_MIN_SELECTED: usize = 64;
const FETCH_OVERLAP_QUEUE_MULTIPLIER: usize = 4;

fn fetch_overlap_queue_capacity(download_concurrency: usize) -> usize {
    download_concurrency
        .max(1)
        .saturating_mul(FETCH_OVERLAP_QUEUE_MULTIPLIER)
}

pub(super) fn selected_package_channel(
    fetch_semaphore: &Semaphore,
) -> (
    tokio::sync::mpsc::Sender<lpm_resolver::SelectedPackageEvent>,
    tokio::sync::mpsc::Receiver<lpm_resolver::SelectedPackageEvent>,
) {
    tokio::sync::mpsc::channel(fetch_overlap_queue_capacity(
        fetch_semaphore.available_permits(),
    ))
}

#[derive(Debug, Clone)]
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

struct WorkspaceFetchRequestContext {
    client: Arc<RegistryClient>,
    route_table: RouteTable,
    store: PackageStore,
    store_v2_handle: Option<Arc<lpm_store::v2::Store>>,
    fetch_semaphore: Arc<Semaphore>,
    fetch_coord: Arc<FetchCoordinator>,
    project_dir: PathBuf,
    gate_stats: Arc<GateStats>,
    fetch_extract_limiter: FetchExtractLimiter,
    install_accounting: ManagedInstallAccounting,
    streaming_fetch: bool,
}

struct WorkspaceFetchPool {
    store: PackageStore,
    store_v2_handle: Option<Arc<lpm_store::v2::Store>>,
    fetch_semaphore: Arc<Semaphore>,
    fetch_coord: Arc<FetchCoordinator>,
    fetch_extract_limiter: FetchExtractLimiter,
}

impl WorkspaceFetchPool {
    fn from_context(context: &WorkspaceFetchRequestContext) -> Self {
        Self {
            store: context.store.clone(),
            store_v2_handle: context.store_v2_handle.clone(),
            fetch_semaphore: context.fetch_semaphore.clone(),
            fetch_coord: context.fetch_coord.clone(),
            fetch_extract_limiter: context.fetch_extract_limiter.clone(),
        }
    }
}

struct WorkspaceFetchCompletion {
    status: Arc<FetchOverlapTaskStatus>,
    dispatched: bool,
}

struct WorkspaceFetchSubscriber {
    tx: tokio::sync::oneshot::Sender<WorkspaceFetchCompletion>,
    dispatched: bool,
}

enum WorkspaceFetchState {
    Running(Vec<WorkspaceFetchSubscriber>),
    Complete(Arc<FetchOverlapTaskStatus>),
}

struct WorkspaceFetchRequest {
    package: InstallPackage,
    context: Arc<WorkspaceFetchRequestContext>,
    completion: tokio::sync::oneshot::Sender<WorkspaceFetchCompletion>,
}

pub(super) struct WorkspaceFetchOverlapHub {
    tx: tokio::sync::mpsc::Sender<WorkspaceFetchRequest>,
}

impl WorkspaceFetchOverlapHub {
    pub(super) fn new(download_concurrency: usize) -> Self {
        let capacity = fetch_overlap_queue_capacity(download_concurrency);
        let (tx, rx) = tokio::sync::mpsc::channel(capacity);
        tokio::spawn(run_workspace_fetch_overlap_hub(rx, capacity));
        Self { tx }
    }

    async fn dispatch(
        &self,
        package: InstallPackage,
        context: Arc<WorkspaceFetchRequestContext>,
    ) -> tokio::sync::oneshot::Receiver<WorkspaceFetchCompletion> {
        let (completion, rx) = tokio::sync::oneshot::channel();
        let request = WorkspaceFetchRequest {
            package,
            context,
            completion,
        };
        if let Err(error) = self.tx.send(request).await {
            let request = error.0;
            let _ = request.completion.send(WorkspaceFetchCompletion {
                status: Arc::new(FetchOverlapTaskStatus::Failed),
                dispatched: false,
            });
        }
        rx
    }
}

async fn run_workspace_fetch_overlap_hub(
    mut rx: tokio::sync::mpsc::Receiver<WorkspaceFetchRequest>,
    task_limit: usize,
) {
    let mut pool = None;
    let mut states: HashMap<String, WorkspaceFetchState> = HashMap::new();
    let mut tasks = tokio::task::JoinSet::new();
    let mut identities_by_task = HashMap::new();

    loop {
        tokio::select! {
            request = rx.recv(), if tasks.len() < task_limit => {
                let Some(request) = request else {
                    break;
                };
                let identity = workspace_fetch_identity(&request.package);
                match states.get_mut(&identity) {
                    Some(WorkspaceFetchState::Running(subscribers)) => {
                        subscribers.push(WorkspaceFetchSubscriber {
                            tx: request.completion,
                            dispatched: false,
                        });
                    }
                    Some(WorkspaceFetchState::Complete(status)) => {
                        let _ = request.completion.send(WorkspaceFetchCompletion {
                            status: Arc::clone(status),
                            dispatched: false,
                        });
                    }
                    None => {
                        let shared_pool =
                            pool.get_or_insert_with(|| WorkspaceFetchPool::from_context(&request.context));
                        let context = request.context;
                        let package = request.package;
                        let identity_for_task = identity.clone();
                        let abort_handle = tasks.spawn(fetch_selected_package(
                            package,
                            context.client.clone(),
                            context.route_table.clone(),
                            shared_pool.store.clone(),
                            shared_pool.store_v2_handle.clone(),
                            shared_pool.fetch_semaphore.clone(),
                            shared_pool.fetch_coord.clone(),
                            context.project_dir.clone(),
                            context.gate_stats.clone(),
                            shared_pool.fetch_extract_limiter.clone(),
                            context.install_accounting,
                            context.streaming_fetch,
                            ArtifactSelection::FreshResolution,
                        ));
                        identities_by_task.insert(abort_handle.id(), identity_for_task);
                        states.insert(
                            identity,
                            WorkspaceFetchState::Running(vec![WorkspaceFetchSubscriber {
                                tx: request.completion,
                                dispatched: true,
                            }]),
                        );
                    }
                }
            }
            joined = tasks.join_next_with_id(), if !tasks.is_empty() => {
                match joined {
                    Some(Ok((id, status))) => {
                        if let Some(identity) = identities_by_task.remove(&id) {
                            finish_workspace_fetch(&mut states, identity, Arc::new(status));
                        }
                    }
                    Some(Err(error)) => {
                        if let Some(identity) = identities_by_task.remove(&error.id()) {
                            finish_workspace_fetch(
                                &mut states,
                                identity,
                                Arc::new(FetchOverlapTaskStatus::Failed),
                            );
                        }
                    }
                    None => {}
                }
            }
        }
    }

    tasks.abort_all();
    let failed = Arc::new(FetchOverlapTaskStatus::Failed);
    for state in states.into_values() {
        if let WorkspaceFetchState::Running(subscribers) = state {
            for subscriber in subscribers {
                let _ = subscriber.tx.send(WorkspaceFetchCompletion {
                    status: Arc::clone(&failed),
                    dispatched: subscriber.dispatched,
                });
            }
        }
    }
}

fn finish_workspace_fetch(
    states: &mut HashMap<String, WorkspaceFetchState>,
    identity: String,
    status: Arc<FetchOverlapTaskStatus>,
) {
    let Some(WorkspaceFetchState::Running(subscribers)) =
        states.insert(identity, WorkspaceFetchState::Complete(Arc::clone(&status)))
    else {
        return;
    };
    for subscriber in subscribers {
        let _ = subscriber.tx.send(WorkspaceFetchCompletion {
            status: Arc::clone(&status),
            dispatched: subscriber.dispatched,
        });
    }
}

fn workspace_fetch_identity(package: &InstallPackage) -> String {
    let mut identity = install_pkg_key(package);
    identity.push('\0');
    match package.integrity.as_deref() {
        Some(integrity) => {
            identity.push('1');
            identity.push_str(integrity);
        }
        None => identity.push('0'),
    }
    identity.push('\0');
    match package.tarball_url.as_deref() {
        Some(url) => {
            identity.push('1');
            identity.push_str(url);
        }
        None => identity.push('0'),
    }
    identity
}

pub(super) struct FetchOverlapDrain {
    pub(super) outcomes: Vec<FetchOverlapOutcome>,
    pub(super) stats: FetchOverlapStats,
}

pub(super) struct FetchOverlapJoin {
    handle: Option<tokio::task::JoinHandle<FetchOverlapDrain>>,
    workspace_shared: bool,
}

struct BufferedSelectedPackage {
    event: lpm_resolver::SelectedPackageEvent,
    selected_at: Instant,
}

impl FetchOverlapJoin {
    pub(super) fn workspace_shared(&self) -> bool {
        self.workspace_shared
    }

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
    mut rx: tokio::sync::mpsc::Receiver<lpm_resolver::SelectedPackageEvent>,
    client: Arc<RegistryClient>,
    route_table: RouteTable,
    store: PackageStore,
    store_v2_handle: Option<Arc<lpm_store::v2::Store>>,
    fetch_semaphore: Arc<Semaphore>,
    fetch_coord: Arc<FetchCoordinator>,
    project_dir: PathBuf,
    gate_stats: Arc<GateStats>,
    fetch_extract_limiter: FetchExtractLimiter,
    install_accounting: ManagedInstallAccounting,
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
        let task_limit = fetch_overlap_queue_capacity(fetch_semaphore.available_permits())
            .max(min_selected.max(1));

        loop {
            tokio::select! {
                event = rx.recv(), if tasks.len() < task_limit => {
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
                                    install_accounting,
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
                        install_accounting,
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
        workspace_shared: false,
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn spawn_workspace_fetch_overlap_dispatcher(
    hub: Arc<WorkspaceFetchOverlapHub>,
    mut rx: tokio::sync::mpsc::Receiver<lpm_resolver::SelectedPackageEvent>,
    client: Arc<RegistryClient>,
    route_table: RouteTable,
    store: PackageStore,
    store_v2_handle: Option<Arc<lpm_store::v2::Store>>,
    fetch_semaphore: Arc<Semaphore>,
    fetch_coord: Arc<FetchCoordinator>,
    project_dir: PathBuf,
    gate_stats: Arc<GateStats>,
    fetch_extract_limiter: FetchExtractLimiter,
    install_accounting: ManagedInstallAccounting,
    dependency_engine_policy: Arc<crate::engine_check::DependencyEnginePolicy>,
    streaming_fetch: bool,
) -> FetchOverlapJoin {
    let completion_limit = fetch_overlap_queue_capacity(fetch_semaphore.available_permits());
    let context = Arc::new(WorkspaceFetchRequestContext {
        client,
        route_table,
        store,
        store_v2_handle,
        fetch_semaphore,
        fetch_coord,
        project_dir,
        gate_stats,
        fetch_extract_limiter,
        install_accounting,
        streaming_fetch,
    });
    let handle = tokio::spawn(async move {
        let mut seen = HashSet::new();
        let mut completions = VecDeque::new();
        let mut outcomes = Vec::new();
        let mut stats = FetchOverlapStats::default();

        while let Some(event) = rx.recv().await {
            stats.selected_count = stats.selected_count.saturating_add(1);
            let package =
                install_package_from_selected_event(event, &context.route_table, &context.client);
            if package.optional {
                stats.skipped_optional_count = stats.skipped_optional_count.saturating_add(1);
                continue;
            }
            if !dependency_engine_policy
                .allows_dependency_materialization(package.node_engine.as_deref())
            {
                stats.skipped_engine_count = stats.skipped_engine_count.saturating_add(1);
                continue;
            }
            if !package_platform_compatible(&package) {
                stats.skipped_platform_count = stats.skipped_platform_count.saturating_add(1);
                continue;
            }
            let identity = workspace_fetch_identity(&package);
            if seen.insert(identity) {
                completions.push_back(hub.dispatch(package, Arc::clone(&context)).await);
                if completions.len() >= completion_limit {
                    let completion = completions
                        .pop_front()
                        .expect("completion queue reached its non-zero limit");
                    match completion.await {
                        Ok(completion) => {
                            record_workspace_fetch_completion(
                                completion,
                                &mut stats,
                                &mut outcomes,
                            );
                        }
                        Err(_) => {
                            stats.failed_count = stats.failed_count.saturating_add(1);
                        }
                    }
                }
            }
        }

        for completion in completions {
            match completion.await {
                Ok(completion) => {
                    record_workspace_fetch_completion(completion, &mut stats, &mut outcomes);
                }
                Err(_) => {
                    stats.failed_count = stats.failed_count.saturating_add(1);
                }
            }
        }

        FetchOverlapDrain { outcomes, stats }
    });

    FetchOverlapJoin {
        handle: Some(handle),
        workspace_shared: true,
    }
}

fn record_workspace_fetch_completion(
    completion: WorkspaceFetchCompletion,
    stats: &mut FetchOverlapStats,
    outcomes: &mut Vec<FetchOverlapOutcome>,
) {
    if completion.dispatched {
        stats.dispatched_count = stats.dispatched_count.saturating_add(1);
    }
    match completion.status.as_ref() {
        FetchOverlapTaskStatus::Completed(outcome) => {
            if completion.dispatched {
                stats.completed_count = stats.completed_count.saturating_add(1);
                if let Some(timings) = outcome.timings {
                    stats.record_task(timings);
                }
            }
            outcomes.push((**outcome).clone());
        }
        FetchOverlapTaskStatus::CacheHit => {
            if completion.dispatched {
                stats.cache_hit_count = stats.cache_hit_count.saturating_add(1);
            }
        }
        FetchOverlapTaskStatus::SkippedPlatform => {
            if completion.dispatched {
                stats.skipped_platform_count = stats.skipped_platform_count.saturating_add(1);
            }
        }
        FetchOverlapTaskStatus::Failed => {
            if completion.dispatched {
                stats.failed_count = stats.failed_count.saturating_add(1);
            }
        }
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
    install_accounting: ManagedInstallAccounting,
    streaming_fetch: bool,
    artifact_selection: ArtifactSelection,
) -> FetchOverlapJoin {
    let handle = tokio::spawn(async move {
        let mut seen = HashSet::with_capacity(packages.len());
        let mut tasks = tokio::task::JoinSet::new();
        let mut outcomes = Vec::new();
        let mut stats = FetchOverlapStats::default();
        let task_limit = fetch_overlap_queue_capacity(fetch_semaphore.available_permits());

        for package in packages {
            if tasks.len() >= task_limit {
                let joined = tasks.join_next().await;
                record_overlap_task(joined, &mut stats, &mut outcomes);
            }
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
                install_accounting,
                streaming_fetch,
                artifact_selection,
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
        workspace_shared: false,
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
    install_accounting: ManagedInstallAccounting,
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
        install_accounting,
        streaming_fetch,
        ArtifactSelection::FreshResolution,
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
    install_accounting: ManagedInstallAccounting,
    streaming_fetch: bool,
    artifact_selection: ArtifactSelection,
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
        install_accounting,
        streaming_fetch,
        artifact_selection,
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
        instance_id: None,
        dependency_targets: HashMap::new(),
        peer_targets: HashMap::new(),
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
        unpacked_size: event.unpacked_size,
        registry_signatures: Vec::new(),
        registry_published_at: None,
        platform: event.platform,
        node_engine: event.node_engine,
        optional: event.optional,
        tarball_url: event.tarball_url,
        metadata_checked_for_tarball: true,
        manifest_fingerprint: None,
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
    install_accounting: ManagedInstallAccounting,
    streaming_fetch: bool,
    artifact_selection: ArtifactSelection,
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
                artifact_selection,
                &gate_stats,
                permit,
                &fetch_extract_limiter,
                install_accounting,
                V2StreamingEligibility::Disabled,
                None,
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
                artifact_selection,
                &gate_stats,
                permit,
                &fetch_extract_limiter,
                install_accounting,
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

    fn workspace_fetch_package(integrity: &str, tarball_url: &str) -> InstallPackage {
        InstallPackage {
            instance_id: None,
            dependency_targets: HashMap::new(),
            peer_targets: HashMap::new(),
            name: "shared-package".to_string(),
            version: "1.0.0".to_string(),
            source: "registry+https://registry.npmjs.org".to_string(),
            dependencies: Vec::new(),
            aliases: HashMap::new(),
            root_link_names: None,
            is_direct: false,
            is_lpm: false,
            peers: Vec::new(),
            integrity: Some(integrity.to_string()),
            unpacked_size: None,
            registry_signatures: Vec::new(),
            registry_published_at: None,
            platform: None,
            node_engine: None,
            optional: false,
            tarball_url: Some(tarball_url.to_string()),
            metadata_checked_for_tarball: true,
            manifest_fingerprint: None,
        }
    }

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

    #[test]
    fn workspace_fetch_identity_ignores_importer_graph_projection() {
        let first = workspace_fetch_package("sha512-shared", "https://registry.test/shared.tgz");
        let mut second = first.clone();
        second.dependencies = vec![("child".to_string(), "2.0.0".to_string())];
        second.peers = vec![lpm_common::PeerEdge::registry("peer", "peer", "3.0.0")];
        second.is_direct = true;
        second.root_link_names = Some(vec!["alias".to_string()]);

        assert_eq!(
            workspace_fetch_identity(&first),
            workspace_fetch_identity(&second)
        );
    }

    #[test]
    fn workspace_fetch_identity_separates_integrity_expectations() {
        let first = workspace_fetch_package("sha512-first", "https://registry.test/shared.tgz");
        let second = workspace_fetch_package("sha512-second", "https://registry.test/shared.tgz");

        assert_ne!(
            workspace_fetch_identity(&first),
            workspace_fetch_identity(&second)
        );
    }

    #[test]
    fn workspace_fetch_identity_separates_tarball_urls() {
        let first = workspace_fetch_package("sha512-shared", "https://registry.test/first.tgz");
        let second = workspace_fetch_package("sha512-shared", "https://registry.test/second.tgz");

        assert_ne!(
            workspace_fetch_identity(&first),
            workspace_fetch_identity(&second)
        );
    }

    #[test]
    fn workspace_fetch_completion_fans_out_without_double_counting_dispatch() {
        let (owner_tx, mut owner_rx) = tokio::sync::oneshot::channel();
        let (reuse_tx, mut reuse_rx) = tokio::sync::oneshot::channel();
        let mut states = HashMap::from([(
            "shared".to_string(),
            WorkspaceFetchState::Running(vec![
                WorkspaceFetchSubscriber {
                    tx: owner_tx,
                    dispatched: true,
                },
                WorkspaceFetchSubscriber {
                    tx: reuse_tx,
                    dispatched: false,
                },
            ]),
        )]);

        finish_workspace_fetch(
            &mut states,
            "shared".to_string(),
            Arc::new(FetchOverlapTaskStatus::CacheHit),
        );

        assert!(owner_rx.try_recv().expect("owner completion").dispatched);
        assert!(!reuse_rx.try_recv().expect("reuse completion").dispatched);
    }
}
