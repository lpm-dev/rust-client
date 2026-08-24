use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};

use sha2::{Digest, Sha256};
use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore};

use super::{InstallOmitPolicy, InstallPackage, LpmError, PeerWarning, install_pkg_key};

pub(super) struct WorkspaceResolutionCoordinator {
    resolution_permits: Arc<Semaphore>,
    release_age_reference_unix: i64,
    target_count: usize,
    materialized: Box<[TargetCompletion]>,
    fetch_overlap_hub: OnceLock<Arc<super::fetch_overlap::WorkspaceFetchOverlapHub>>,
    resolver_fact_cache: lpm_resolver::SharedCache,
    resolver_metadata_concurrency: OnceLock<lpm_resolver::SharedMetadataConcurrency>,
    root_index: Option<usize>,
    root_provider_state: RootProviderState,
    union: Option<WorkspaceUnionState>,
}

impl WorkspaceResolutionCoordinator {
    #[cfg(test)]
    pub(super) fn new(target_count: usize, resolution_concurrency: usize) -> Self {
        Self::new_at_unix(
            target_count,
            resolution_concurrency,
            current_unix_timestamp(),
        )
    }

    pub(super) fn new_at_unix(
        target_count: usize,
        resolution_concurrency: usize,
        release_age_reference_unix: i64,
    ) -> Self {
        Self {
            resolution_permits: Arc::new(Semaphore::new(resolution_concurrency.max(1))),
            release_age_reference_unix,
            target_count,
            materialized: (0..target_count)
                .map(|_| TargetCompletion::default())
                .collect(),
            fetch_overlap_hub: OnceLock::new(),
            resolver_fact_cache: Arc::new(dashmap::DashMap::new()),
            resolver_metadata_concurrency: OnceLock::new(),
            root_index: None,
            root_provider_state: RootProviderState::new(),
            union: None,
        }
    }

    pub(super) fn new_with_root_at_unix(
        target_count: usize,
        resolution_concurrency: usize,
        root_index: usize,
        release_age_reference_unix: i64,
    ) -> Self {
        let mut coordinator = Self::new_at_unix(
            target_count,
            resolution_concurrency,
            release_age_reference_unix,
        );
        coordinator.root_index = Some(root_index);
        coordinator
    }

    pub(super) fn new_union_at_unix(
        target_count: usize,
        root_index: Option<usize>,
        release_age_reference_unix: i64,
    ) -> Self {
        let mut coordinator =
            Self::new_at_unix(target_count, target_count, release_age_reference_unix);
        coordinator.root_index = root_index;
        coordinator.union = Some(WorkspaceUnionState::new(target_count));
        coordinator
    }

    async fn enter(self: &Arc<Self>, index: usize) -> Arc<WorkspaceResolutionTask> {
        let resolution_permit = Arc::clone(&self.resolution_permits)
            .acquire_owned()
            .await
            .expect("workspace resolution semaphore must outlive target tasks");
        Arc::new(WorkspaceResolutionTask {
            coordinator: Arc::clone(self),
            index,
            resolution_permit: std::sync::Mutex::new(Some(resolution_permit)),
            resolution_finished: std::sync::atomic::AtomicBool::new(false),
            commit_entered: std::sync::atomic::AtomicBool::new(false),
        })
    }

    fn fetch_overlap_hub(&self) -> Arc<super::fetch_overlap::WorkspaceFetchOverlapHub> {
        Arc::clone(self.fetch_overlap_hub.get_or_init(|| {
            Arc::new(super::fetch_overlap::WorkspaceFetchOverlapHub::new(
                super::max_concurrent_downloads(),
            ))
        }))
    }

    fn publish_root_providers(&self, snapshot: RootProviderSnapshot) {
        self.root_provider_state.publish(snapshot);
    }

    fn fail_union(&self) {
        let Some(union) = self.union.as_ref() else {
            return;
        };
        let mut results = union
            .results
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for result in results.iter_mut() {
            if result.is_none() {
                *result = Some(WorkspaceUnionResult::Failed(
                    lpm_resolver::ResolveError::Cancelled(
                        "another workspace importer failed before union resolution completed"
                            .to_string(),
                    ),
                ));
            }
        }
        union.ready.notify_waiters();
    }

    async fn wait_for_root_providers(&self) -> Result<Option<Arc<RootProviderSnapshot>>, LpmError> {
        if self.root_index.is_none() {
            return Ok(None);
        }
        self.root_provider_state.wait().await.map(Some)
    }

    #[cfg(test)]
    fn fetch_overlap_hub_initialized(&self) -> bool {
        self.fetch_overlap_hub.get().is_some()
    }
}

struct WorkspaceUnionState {
    requests: std::sync::Mutex<Vec<Option<WorkspaceUnionRequest>>>,
    results: std::sync::Mutex<Vec<Option<WorkspaceUnionResult>>>,
    submitted: std::sync::atomic::AtomicUsize,
    ready: Notify,
}

#[derive(Eq, Hash, PartialEq)]
struct WorkspaceUnionGroupKey {
    overrides: String,
    policy: String,
    auto_install_peers: bool,
    include_optional_dependencies: bool,
    npm_fanout: usize,
    route: lpm_registry::WorkspaceResolutionKey,
}

impl WorkspaceUnionState {
    fn new(target_count: usize) -> Self {
        Self {
            requests: std::sync::Mutex::new((0..target_count).map(|_| None).collect()),
            results: std::sync::Mutex::new((0..target_count).map(|_| None).collect()),
            submitted: std::sync::atomic::AtomicUsize::new(0),
            ready: Notify::new(),
        }
    }
}

pub(super) struct WorkspaceUnionRequest {
    pub(super) client: Arc<lpm_registry::RegistryClient>,
    pub(super) root_dependencies: lpm_resolver::RootDependencies,
    pub(super) overrides: lpm_resolver::OverrideSet,
    pub(super) route_table: lpm_registry::RouteTable,
    pub(super) npm_fanout: usize,
    pub(super) shared_cache: lpm_resolver::SharedCache,
    pub(super) auto_install_peers: bool,
    pub(super) include_optional_dependencies: bool,
    pub(super) policy: lpm_resolver::ResolverPolicy,
}

enum WorkspaceUnionResult {
    Projected(Box<lpm_resolver::ResolveResult>),
    Isolated(Option<lpm_resolver::WorkspaceUnionStageTiming>),
    Failed(lpm_resolver::ResolveError),
}

pub(super) enum WorkspaceUnionResolution {
    Projected(Box<lpm_resolver::ResolveResult>),
    Isolated(Option<lpm_resolver::WorkspaceUnionStageTiming>),
}

struct RootProviderState {
    root_providers: OnceLock<Arc<RootProviderSnapshot>>,
    root_providers_ready: Notify,
    root_provider_failed: std::sync::atomic::AtomicBool,
}

impl RootProviderState {
    fn new() -> Self {
        Self {
            root_providers: OnceLock::new(),
            root_providers_ready: Notify::new(),
            root_provider_failed: std::sync::atomic::AtomicBool::new(false),
        }
    }

    fn publish(&self, snapshot: RootProviderSnapshot) {
        if self.root_providers.set(Arc::new(snapshot)).is_ok() {
            self.root_providers_ready.notify_waiters();
        }
    }

    async fn wait(&self) -> Result<Arc<RootProviderSnapshot>, LpmError> {
        loop {
            if let Some(snapshot) = self.root_providers.get() {
                return Ok(Arc::clone(snapshot));
            }
            if self
                .root_provider_failed
                .load(std::sync::atomic::Ordering::Acquire)
            {
                return Err(LpmError::Registry(
                    "workspace root resolution failed before peer providers were available"
                        .to_string(),
                ));
            }
            let notified = self.root_providers_ready.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.root_providers.get().is_some()
                || self
                    .root_provider_failed
                    .load(std::sync::atomic::Ordering::Acquire)
            {
                continue;
            }
            notified.await;
        }
    }

    fn fail(&self) {
        self.root_provider_failed
            .store(true, std::sync::atomic::Ordering::Release);
        self.root_providers_ready.notify_waiters();
    }

    fn has_snapshot(&self) -> bool {
        self.root_providers.get().is_some()
    }
}

pub(super) struct WorkspaceRootProviderCoordinator {
    state: RootProviderState,
    resolver_fact_cache: lpm_resolver::SharedCache,
    resolver_metadata_concurrency: OnceLock<lpm_resolver::SharedMetadataConcurrency>,
    release_age_reference_unix: i64,
}

impl WorkspaceRootProviderCoordinator {
    #[cfg(test)]
    pub(super) fn new() -> Self {
        Self::new_at_unix(current_unix_timestamp())
    }

    pub(super) fn new_at_unix(release_age_reference_unix: i64) -> Self {
        Self {
            state: RootProviderState::new(),
            resolver_fact_cache: Arc::new(dashmap::DashMap::new()),
            resolver_metadata_concurrency: OnceLock::new(),
            release_age_reference_unix,
        }
    }

    fn publish(&self, snapshot: RootProviderSnapshot) {
        self.state.publish(snapshot);
    }

    async fn wait(&self) -> Result<Arc<RootProviderSnapshot>, LpmError> {
        self.state.wait().await
    }

    fn fail(&self) {
        self.state.fail();
    }

    fn has_snapshot(&self) -> bool {
        self.state.has_snapshot()
    }
}

#[derive(Default)]
struct TargetCompletion {
    done: std::sync::atomic::AtomicBool,
    notify: Notify,
}

impl TargetCompletion {
    async fn wait(&self) {
        loop {
            if self.done.load(std::sync::atomic::Ordering::Acquire) {
                return;
            }
            let notified = self.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.done.load(std::sync::atomic::Ordering::Acquire) {
                return;
            }
            notified.await;
        }
    }

    fn finish(&self) {
        self.done.store(true, std::sync::atomic::Ordering::Release);
        self.notify.notify_waiters();
    }
}

struct WorkspaceResolutionTask {
    coordinator: Arc<WorkspaceResolutionCoordinator>,
    index: usize,
    resolution_permit: std::sync::Mutex<Option<OwnedSemaphorePermit>>,
    resolution_finished: std::sync::atomic::AtomicBool,
    commit_entered: std::sync::atomic::AtomicBool,
}

impl WorkspaceResolutionTask {
    fn is_root(&self) -> bool {
        self.coordinator.root_index == Some(self.index)
    }

    fn finish_resolution(&self) {
        if self
            .resolution_finished
            .swap(true, std::sync::atomic::Ordering::AcqRel)
        {
            return;
        }
        self.resolution_permit
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
    }

    fn enter_commit(&self) -> u128 {
        if self
            .commit_entered
            .swap(true, std::sync::atomic::Ordering::AcqRel)
        {
            return 0;
        }

        self.finish_resolution();
        self.coordinator.materialized[self.index].finish();
        0
    }

    async fn wait_for_materialization(&self) -> u128 {
        let wait_started = std::time::Instant::now();
        if let Some(previous) = self.index.checked_sub(1) {
            self.coordinator.materialized[previous].wait().await;
        }
        wait_started.elapsed().as_millis()
    }
}

tokio::task_local! {
    static ACTIVE_TASK: Arc<WorkspaceResolutionTask>;
    static ACTIVE_ROOT_PROVIDER_TASK: Arc<WorkspaceRootProviderTask>;
}

struct WorkspaceRootProviderTask {
    coordinator: Arc<WorkspaceRootProviderCoordinator>,
    is_root: bool,
}

pub(super) async fn scope<F, T, E>(
    coordinator: Arc<WorkspaceResolutionCoordinator>,
    index: usize,
    future: F,
) -> Result<T, E>
where
    F: Future<Output = Result<T, E>>,
{
    let task = coordinator.enter(index).await;
    let result = ACTIVE_TASK.scope(Arc::clone(&task), future).await;
    task.finish_resolution();
    if result.is_err() {
        task.coordinator.fail_union();
    }
    if task.is_root() && !task.coordinator.root_provider_state.has_snapshot() {
        task.coordinator.root_provider_state.fail();
    }
    result
}

pub(super) async fn root_provider_scope<F, T, E>(
    coordinator: Arc<WorkspaceRootProviderCoordinator>,
    is_root: bool,
    future: F,
) -> Result<T, E>
where
    F: Future<Output = Result<T, E>>,
{
    let task = Arc::new(WorkspaceRootProviderTask {
        coordinator,
        is_root,
    });
    let result = ACTIVE_ROOT_PROVIDER_TASK
        .scope(Arc::clone(&task), future)
        .await;
    if task.is_root && !task.coordinator.has_snapshot() {
        task.coordinator.fail();
    }
    result
}

pub(super) fn active() -> bool {
    ACTIVE_TASK.try_with(|_| ()).is_ok() || ACTIVE_ROOT_PROVIDER_TASK.try_with(|_| ()).is_ok()
}

pub(super) fn current_unix_timestamp() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| {
            i64::try_from(elapsed.as_secs()).unwrap_or(i64::MAX)
        })
}

pub(super) fn release_age_reference_unix() -> Option<i64> {
    ACTIVE_TASK
        .try_with(|task| task.coordinator.release_age_reference_unix)
        .or_else(|_| {
            ACTIVE_ROOT_PROVIDER_TASK.try_with(|task| task.coordinator.release_age_reference_unix)
        })
        .ok()
}

pub(super) fn fetch_overlap_hub() -> Option<Arc<super::fetch_overlap::WorkspaceFetchOverlapHub>> {
    ACTIVE_TASK
        .try_with(|task| task.coordinator.fetch_overlap_hub())
        .ok()
}

pub(super) fn resolver_fact_cache_for_importer(
    route_table: &lpm_registry::RouteTable,
) -> Option<lpm_resolver::SharedCache> {
    if !matches!(route_table.mode(), lpm_registry::RouteMode::Direct)
        || !route_table.supports_workspace_fetch_sharing()
    {
        return None;
    }

    ACTIVE_TASK
        .try_with(|task| Arc::clone(&task.coordinator.resolver_fact_cache))
        .or_else(|_| {
            ACTIVE_ROOT_PROVIDER_TASK
                .try_with(|task| Arc::clone(&task.coordinator.resolver_fact_cache))
        })
        .ok()
}

fn metadata_concurrency_with_limit(
    shared: &OnceLock<lpm_resolver::SharedMetadataConcurrency>,
    requested_fanout: usize,
) -> Option<lpm_resolver::SharedMetadataConcurrency> {
    let requested_fanout = requested_fanout.max(1);
    let concurrency =
        shared.get_or_init(|| lpm_resolver::SharedMetadataConcurrency::new(requested_fanout));
    (concurrency.limit() == requested_fanout).then(|| concurrency.clone())
}

pub(super) fn resolver_metadata_concurrency_for_importer(
    route_table: &lpm_registry::RouteTable,
    requested_fanout: usize,
) -> Option<lpm_resolver::SharedMetadataConcurrency> {
    if !matches!(route_table.mode(), lpm_registry::RouteMode::Direct)
        || !route_table.supports_workspace_fetch_sharing()
    {
        return None;
    }

    ACTIVE_TASK
        .try_with(|task| {
            metadata_concurrency_with_limit(
                &task.coordinator.resolver_metadata_concurrency,
                requested_fanout,
            )
        })
        .or_else(|_| {
            ACTIVE_ROOT_PROVIDER_TASK.try_with(|task| {
                metadata_concurrency_with_limit(
                    &task.coordinator.resolver_metadata_concurrency,
                    requested_fanout,
                )
            })
        })
        .ok()
        .flatten()
}

pub(super) async fn resolve_workspace_union(
    request: WorkspaceUnionRequest,
) -> Result<WorkspaceUnionResolution, LpmError> {
    let Ok(task) = ACTIVE_TASK.try_with(Arc::clone) else {
        return Ok(WorkspaceUnionResolution::Isolated(None));
    };
    let Some(union) = task.coordinator.union.as_ref() else {
        return Ok(WorkspaceUnionResolution::Isolated(None));
    };

    {
        let mut requests = union
            .requests
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if requests[task.index].replace(request).is_some() {
            return Err(LpmError::Registry(
                "workspace importer submitted resolver input more than once".to_string(),
            ));
        }
    }
    let submitted = union
        .submitted
        .fetch_add(1, std::sync::atomic::Ordering::AcqRel)
        .saturating_add(1);
    if submitted == task.coordinator.target_count {
        resolve_submitted_workspace_unions(&task.coordinator).await;
    } else {
        loop {
            let notified = union.ready.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if union
                .results
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)[task.index]
                .is_some()
            {
                break;
            }
            notified.await;
        }
    }

    let result = union
        .results
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)[task.index]
        .take()
        .ok_or_else(|| {
            LpmError::Registry("workspace union resolver completed without a result".to_string())
        })?;
    match result {
        WorkspaceUnionResult::Projected(result) => Ok(WorkspaceUnionResolution::Projected(result)),
        WorkspaceUnionResult::Isolated(timing) => Ok(WorkspaceUnionResolution::Isolated(timing)),
        WorkspaceUnionResult::Failed(error) => {
            Err(crate::resolver_error::resolver_error_to_lpm(error))
        }
    }
}

async fn resolve_submitted_workspace_unions(coordinator: &WorkspaceResolutionCoordinator) {
    let Some(union) = coordinator.union.as_ref() else {
        return;
    };
    let requests = {
        let mut requests = union
            .requests
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        std::mem::take(&mut *requests)
    };
    let Some(mut requests) = requests.into_iter().collect::<Option<Vec<_>>>() else {
        let error = lpm_resolver::ResolveError::Internal(
            "workspace union resolver started before every importer submitted input".to_string(),
        );
        *union
            .results
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = (0..coordinator.target_count)
            .map(|_| Some(WorkspaceUnionResult::Failed(error.clone())))
            .collect();
        union.ready.notify_waiters();
        return;
    };
    let mut groups = Vec::<Vec<usize>>::new();
    let mut group_positions =
        HashMap::<WorkspaceUnionGroupKey, usize>::with_capacity(requests.len());
    for (index, request) in requests.iter().enumerate() {
        let Some(route_key) = request.route_table.workspace_resolution_key() else {
            tracing::debug!(
                importer_index = index,
                reason = "route-key-unavailable",
                "workspace union resolution retained isolated importer"
            );
            groups.push(vec![index]);
            continue;
        };
        let key = WorkspaceUnionGroupKey {
            overrides: request.overrides.fingerprint().to_string(),
            policy: request.policy.workspace_resolution_key(),
            auto_install_peers: request.auto_install_peers,
            include_optional_dependencies: request.include_optional_dependencies,
            npm_fanout: request.npm_fanout,
            route: route_key,
        };
        if let Some(position) = group_positions.get(&key).copied() {
            groups[position].push(index);
        } else {
            group_positions.insert(key, groups.len());
            groups.push(vec![index]);
        }
    }

    let mut results = (0..requests.len())
        .map(|_| Some(WorkspaceUnionResult::Isolated(None)))
        .collect::<Vec<_>>();
    for indices in groups {
        if indices.len() < 2 {
            if let Some(importer_index) = indices.first().copied() {
                tracing::debug!(
                    importer_index,
                    reason = "singleton-equivalence-group",
                    "workspace union resolution retained isolated importer"
                );
            }
            continue;
        }
        let roots = indices
            .iter()
            .map(|index| requests[*index].root_dependencies.clone())
            .collect::<Vec<_>>();
        let policies = indices
            .iter()
            .map(|index| requests[*index].policy.clone())
            .collect::<Vec<_>>();
        let first = &mut requests[indices[0]];
        let metadata_concurrency = metadata_concurrency_with_limit(
            &coordinator.resolver_metadata_concurrency,
            first.npm_fanout,
        );
        let resolved = lpm_resolver::resolve_greedy_fused_workspace_with_cache_options_and_policy(
            Arc::clone(&first.client),
            roots,
            first.overrides.clone(),
            first.route_table.clone(),
            first.npm_fanout,
            Arc::clone(&first.shared_cache),
            first.auto_install_peers,
            first.include_optional_dependencies,
            policies,
            Some(Arc::clone(&coordinator.resolver_fact_cache)),
            metadata_concurrency,
        )
        .await;
        match resolved {
            Ok(lpm_resolver::WorkspaceResolveOutcome::Projected {
                results: projected,
                timing,
            }) => {
                let projected_count = projected.iter().filter(|result| result.is_some()).count();
                if let Some(materialization) = super::workspace_materialization::current() {
                    materialization.publish_union_object_candidates(
                        projected
                            .iter()
                            .flatten()
                            .flat_map(|result| result.packages.iter())
                            .filter_map(|package| package.integrity.clone()),
                    );
                }
                tracing::debug!(
                    importers = projected.len(),
                    projected = projected_count,
                    "workspace union resolution completed"
                );
                if projected_count == 0 {
                    results[indices[0]] = Some(WorkspaceUnionResult::Isolated(Some(timing)));
                }
                for (index, projection) in indices.into_iter().zip(projected) {
                    if let Some(projection) = projection {
                        results[index] =
                            Some(WorkspaceUnionResult::Projected(Box::new(projection)));
                    }
                }
            }
            Ok(lpm_resolver::WorkspaceResolveOutcome::RequiresIsolatedResolution) => {
                tracing::debug!(
                    importers = indices.len(),
                    reason = "resolver-group-ineligible",
                    "workspace union resolution retained isolated importer fallbacks"
                );
            }
            Err(error) => {
                for index in indices {
                    results[index] = Some(WorkspaceUnionResult::Failed(error.clone()));
                }
            }
        }
    }

    *union
        .results
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = results;
    union.ready.notify_waiters();
}

pub(super) fn finish_resolution() {
    if let Ok(task) = ACTIVE_TASK.try_with(Arc::clone) {
        task.finish_resolution();
    }
}

pub(super) async fn reconcile_root_peer_providers(
    project_dir: &Path,
    packages: &mut Vec<InstallPackage>,
    peer_warnings: &mut Vec<PeerWarning>,
    ephemeral_workspace_packages: &[InstallPackage],
    omit_policy: InstallOmitPolicy,
    root_optional_dependency_names: &HashSet<String>,
    production_dependency_names: &HashSet<String>,
) -> Result<Option<String>, LpmError> {
    if let Ok(task) = ACTIVE_TASK.try_with(Arc::clone) {
        if task.is_root() {
            task.coordinator
                .publish_root_providers(RootProviderSnapshot::new(
                    project_dir,
                    packages.clone(),
                    ephemeral_workspace_packages,
                    omit_policy,
                    root_optional_dependency_names,
                    production_dependency_names,
                ));
            return Ok(None);
        }
        let Some(snapshot) = task.coordinator.wait_for_root_providers().await? else {
            return Ok(None);
        };
        let used_root_provider = snapshot.reconcile(project_dir, packages, peer_warnings);
        return Ok(used_root_provider.then(|| snapshot.fingerprint.to_string()));
    }

    let Ok(task) = ACTIVE_ROOT_PROVIDER_TASK.try_with(Arc::clone) else {
        return Ok(None);
    };
    if task.is_root {
        task.coordinator.publish(RootProviderSnapshot::new(
            project_dir,
            packages.clone(),
            ephemeral_workspace_packages,
            omit_policy,
            root_optional_dependency_names,
            production_dependency_names,
        ));
        return Ok(None);
    }
    let snapshot = task.coordinator.wait().await?;
    let used_root_provider = snapshot.reconcile(project_dir, packages, peer_warnings);
    Ok(used_root_provider.then(|| snapshot.fingerprint.to_string()))
}

pub(super) fn reconcile_ambient_peer_roots(
    packages: &mut [InstallPackage],
    ambient_peer_installs: &mut Vec<String>,
    manifest_dependencies: &HashMap<String, String>,
) -> Result<(), LpmError> {
    let manifest_root_instances = packages
        .iter()
        .filter(|package| {
            package.root_link_names.as_ref().is_some_and(|names| {
                names
                    .iter()
                    .any(|name| manifest_dependencies.contains_key(name))
            })
        })
        .filter_map(|package| package.instance_id)
        .collect::<HashSet<_>>();
    for package in packages.iter() {
        for peer in &package.peers {
            let Some(target) = package.peer_targets.get(&peer.local_name) else {
                continue;
            };
            if manifest_root_instances.contains(target)
                && !manifest_dependencies.contains_key(&peer.target_name)
            {
                ambient_peer_installs.push(peer.target_name.clone());
            }
        }
    }

    let declared_root_links = packages
        .iter()
        .filter_map(|package| package.root_link_names.as_ref())
        .flatten()
        .filter(|name| manifest_dependencies.contains_key(*name))
        .map(String::as_str)
        .collect::<HashSet<_>>();
    ambient_peer_installs.retain(|name| !declared_root_links.contains(name.as_str()));
    ambient_peer_installs.sort_unstable();
    ambient_peer_installs.dedup();

    for ambient in ambient_peer_installs.iter() {
        if packages.iter().any(|package| {
            package
                .root_link_names
                .as_ref()
                .is_some_and(|names| names.iter().any(|name| name == ambient))
        }) {
            continue;
        }

        let mut targets = packages
            .iter()
            .flat_map(|package| {
                package.peers.iter().filter_map(|peer| {
                    (peer.target_name == *ambient)
                        .then(|| package.peer_targets.get(&peer.local_name).copied())
                        .flatten()
                })
            })
            .collect::<Vec<_>>();
        targets.sort_unstable();
        targets.dedup();
        let [target] = targets.as_slice() else {
            return Err(LpmError::Registry(format!(
                "ambient peer {ambient:?} does not have one exact root provider"
            )));
        };
        let provider = packages
            .iter_mut()
            .find(|package| package.instance_id == Some(*target))
            .ok_or_else(|| {
                LpmError::Registry(format!(
                    "ambient peer {ambient:?} references a missing exact root provider"
                ))
            })?;
        let link_names = provider.root_link_names.get_or_insert_with(Vec::new);
        link_names.push(ambient.clone());
        link_names.sort_unstable();
        link_names.dedup();
    }
    Ok(())
}

pub(super) fn publish_root_peer_providers_for_empty_install(
    project_dir: &Path,
    omit_policy: InstallOmitPolicy,
) {
    if let Ok(task) = ACTIVE_TASK.try_with(Arc::clone) {
        if task.is_root() {
            task.coordinator
                .publish_root_providers(RootProviderSnapshot::new(
                    project_dir,
                    Vec::new(),
                    &[],
                    omit_policy,
                    &HashSet::new(),
                    &HashSet::new(),
                ));
        }
        return;
    }

    if let Ok(task) = ACTIVE_ROOT_PROVIDER_TASK.try_with(Arc::clone)
        && task.is_root
    {
        task.coordinator.publish(RootProviderSnapshot::new(
            project_dir,
            Vec::new(),
            &[],
            omit_policy,
            &HashSet::new(),
            &HashSet::new(),
        ));
    }
}

pub(super) fn root_provider_fingerprint_from_projection(
    root_dir: &Path,
    lockfile: &lpm_lockfile::Lockfile,
    omit_policy: InstallOmitPolicy,
) -> Option<String> {
    let manifest = root_manifest_bytes(root_dir);
    let package = lpm_workspace::read_workspace_root_package(root_dir).unwrap_or_default();
    let local_packages = root_workspace_install_packages(root_dir, &package)?;
    let direct = direct_provider_identities(&package, lockfile, &local_packages);
    let rows = lockfile
        .packages
        .iter()
        .map(FingerprintPackage::from_locked)
        .collect::<Vec<_>>();
    let local = local_provider_fingerprints(root_dir, &local_packages);
    Some(root_provider_fingerprint(
        &manifest,
        &direct,
        &rows,
        &local,
        omit_policy,
    ))
}

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
struct ProviderIdentity {
    name: String,
    version: String,
    source: String,
}

#[derive(Eq, Ord, PartialEq, PartialOrd)]
struct LocalProviderFingerprint {
    name: String,
    version: String,
    source: String,
    manifest: Vec<u8>,
}

struct RootProviderSnapshot {
    root_dir: PathBuf,
    packages: Arc<[InstallPackage]>,
    direct_by_name: BTreeMap<String, Vec<usize>>,
    fingerprint: Arc<str>,
}

impl RootProviderSnapshot {
    fn new(
        root_dir: &Path,
        mut packages: Vec<InstallPackage>,
        workspace_packages: &[InstallPackage],
        omit_policy: InstallOmitPolicy,
        root_optional_dependency_names: &HashSet<String>,
        production_dependency_names: &HashSet<String>,
    ) -> Self {
        super::ensure_install_package_instance_ids(&mut packages);
        let mut lockfile = lpm_lockfile::Lockfile::new();
        for package in &packages {
            lockfile.add_package(super::lockfile::locked_package_from_install_package(
                package,
            ));
        }
        let package = lpm_workspace::read_workspace_root_package(root_dir).unwrap_or_default();
        let deps = super::manifest_install_deps(&package);
        lockfile.root_aliases = super::root_aliases_for_lockfile(&packages, &deps);
        lockfile.root_resolutions = super::root_resolutions_for_lockfile(&packages);
        let direct = direct_provider_identities(&package, &lockfile, workspace_packages);
        let rows = lockfile
            .packages
            .iter()
            .map(FingerprintPackage::from_locked)
            .collect::<Vec<_>>();
        let local = local_provider_fingerprints(root_dir, workspace_packages);
        let manifest = root_manifest_bytes(root_dir);
        let fingerprint = root_provider_fingerprint(&manifest, &direct, &rows, &local, omit_policy);
        if omit_policy.dev {
            super::filter_dev_packages(&mut packages, production_dependency_names);
        }
        if omit_policy.optional {
            super::filter_optional_packages(&mut packages, root_optional_dependency_names);
        }
        let mut direct_by_name = BTreeMap::<String, Vec<usize>>::new();
        for (index, package) in packages.iter().enumerate() {
            if package.is_direct {
                direct_by_name
                    .entry(package.name.clone())
                    .or_default()
                    .push(index);
            }
        }
        for candidates in direct_by_name.values_mut() {
            candidates.sort_unstable_by(|left, right| {
                packages[*right]
                    .version
                    .cmp(&packages[*left].version)
                    .then_with(|| packages[*left].source.cmp(&packages[*right].source))
            });
        }
        Self {
            root_dir: root_dir.to_path_buf(),
            packages: Arc::from(packages),
            direct_by_name,
            fingerprint: Arc::from(fingerprint),
        }
    }

    fn reconcile(
        &self,
        project_dir: &Path,
        packages: &mut Vec<InstallPackage>,
        warnings: &mut Vec<PeerWarning>,
    ) -> bool {
        let mut remaining = Vec::with_capacity(warnings.len());
        let mut used_root_provider = false;
        for warning in warnings.drain(..) {
            if self.reconcile_warning(project_dir, packages, &warning) {
                used_root_provider = true;
            } else {
                remaining.push(warning);
            }
        }
        *warnings = remaining;
        used_root_provider
    }

    fn reconcile_warning(
        &self,
        project_dir: &Path,
        packages: &mut Vec<InstallPackage>,
        warning: &PeerWarning,
    ) -> bool {
        super::ensure_install_package_instance_ids(packages);
        let Ok(range) = lpm_resolver::NpmRange::parse(&warning.required_range) else {
            return false;
        };
        let Some(provider_index) = self
            .direct_by_name
            .get(&warning.target)
            .into_iter()
            .flatten()
            .copied()
            .find(|index| {
                lpm_resolver::NpmVersion::parse(&self.packages[*index].version)
                    .ok()
                    .is_some_and(|version| range.satisfies(&version))
            })
        else {
            return false;
        };
        let mut consumer_indices = packages
            .iter()
            .enumerate()
            .filter(|(_, package)| {
                package.name == warning.package && package.version == warning.version
            })
            .map(|(index, _)| index);
        let Some(consumer_index) = consumer_indices.next() else {
            return false;
        };
        if consumer_indices.next().is_some() {
            return false;
        }

        let Some(closure) = self.provider_closure(provider_index) else {
            return false;
        };
        let mut imports = Vec::with_capacity(closure.len());
        let mut rebased_wrapper_ids = HashMap::with_capacity(closure.len());
        let mut rebased_instance_ids = HashMap::with_capacity(closure.len());
        for index in closure {
            let mut imported = self.packages[index].clone();
            let old_source = imported.source.clone();
            let old_wrapper_id = imported.wrapper_id_for_source();
            imported.source = rebase_local_source(&imported.source, &self.root_dir, project_dir);
            if imported.source != old_source {
                let Some(old_instance_id) = imported.instance_id else {
                    return false;
                };
                let new_instance_id = old_instance_id.rebase_source(
                    &imported.name,
                    &imported.version,
                    &imported.source,
                );
                imported.instance_id = Some(new_instance_id);
                rebased_instance_ids.insert(old_instance_id, new_instance_id);
            }
            if let (Some(old_wrapper_id), Some(new_wrapper_id)) =
                (old_wrapper_id, imported.wrapper_id_for_source())
            {
                rebased_wrapper_ids.insert(old_wrapper_id, new_wrapper_id);
            }
            if !package_can_be_imported(packages, &imported) {
                return false;
            }
            imports.push(imported);
        }

        for imported in &mut imports {
            for target in imported.dependency_targets.values_mut() {
                if let Some(rebased) = rebased_instance_ids.get(target) {
                    *target = *rebased;
                }
            }
            for target in imported.peer_targets.values_mut() {
                if let Some(rebased) = rebased_instance_ids.get(target) {
                    *target = *rebased;
                }
            }
            for (_, target) in &mut imported.dependencies {
                if let Some(rebased) = rebased_wrapper_ids.get(target) {
                    target.clone_from(rebased);
                }
            }
            for peer in &mut imported.peers {
                if let Some(wrapper_id) = peer.target_wrapper_id.as_mut()
                    && let Some(rebased) = rebased_wrapper_ids.get(wrapper_id)
                {
                    wrapper_id.clone_from(rebased);
                }
            }
        }
        if complete_imported_exact_targets(&mut imports).is_none() {
            return false;
        }

        let Some(imported_by_instance) = verified_imported_exact_target_index(&imports) else {
            return false;
        };

        let Some(mut provider_instance_id) = self.packages[provider_index].instance_id else {
            return false;
        };
        if let Some(rebased) = rebased_instance_ids.get(&provider_instance_id) {
            provider_instance_id = *rebased;
        }
        let Some(&provider_position) = imported_by_instance.get(&provider_instance_id) else {
            return false;
        };

        let provider = &imports[provider_position];
        let peer_binding = lpm_common::PeerEdge {
            local_name: warning.peer.clone(),
            target_name: warning.target.clone(),
            target_version: provider.version.clone(),
            target_wrapper_id: provider.wrapper_id_for_source(),
        };

        for mut imported in imports {
            if packages.iter().any(|package| {
                imported.instance_id.map_or_else(
                    || install_pkg_key(package) == install_pkg_key(&imported),
                    |instance_id| package.instance_id == Some(instance_id),
                )
            }) {
                continue;
            }
            imported.is_direct = false;
            imported.root_link_names = None;
            packages.push(imported);
        }
        let consumer = &mut packages[consumer_index];
        if let Some(edge) = consumer
            .peers
            .iter_mut()
            .find(|edge| edge.local_name == warning.peer)
        {
            edge.clone_from(&peer_binding);
        } else {
            consumer.peers.push(peer_binding);
            consumer
                .peers
                .sort_unstable_by(|left, right| left.local_name.cmp(&right.local_name));
        }
        consumer
            .peer_targets
            .insert(warning.peer.clone(), provider_instance_id);
        true
    }

    fn provider_closure(&self, provider_index: usize) -> Option<Vec<usize>> {
        let mut by_instance = HashMap::with_capacity(self.packages.len());
        let mut registry_by_name_version = HashMap::<(&str, &str), Vec<usize>>::new();
        let mut source_by_wrapper = HashMap::<String, Vec<usize>>::new();
        for (index, package) in self.packages.iter().enumerate() {
            if let Some(instance_id) = package.instance_id {
                by_instance.insert(instance_id, index);
            }
            if matches!(
                package.source_kind(),
                Ok(lpm_lockfile::Source::Registry { .. })
            ) {
                registry_by_name_version
                    .entry((&package.name, &package.version))
                    .or_default()
                    .push(index);
            }
            if let Some(wrapper_id) = package.wrapper_id_for_source() {
                source_by_wrapper.entry(wrapper_id).or_default().push(index);
            }
        }
        let mut seen = HashSet::new();
        let mut queue = VecDeque::from([provider_index]);
        while let Some(index) = queue.pop_front() {
            if !seen.insert(index) {
                continue;
            }
            let package = &self.packages[index];
            for (local_name, version) in &package.dependencies {
                if let Some(target_id) = package.dependency_targets.get(local_name) {
                    queue.push_back(*by_instance.get(target_id)?);
                    continue;
                }
                let target = package
                    .aliases
                    .get(local_name)
                    .map_or(local_name, |name| name);
                let candidates = source_by_wrapper.get(version).or_else(|| {
                    registry_by_name_version.get(&(target.as_str(), version.as_str()))
                })?;
                let [child] = candidates.as_slice() else {
                    return None;
                };
                queue.push_back(*child);
            }
            for peer in &package.peers {
                if let Some(target_id) = package.peer_targets.get(&peer.local_name) {
                    queue.push_back(*by_instance.get(target_id)?);
                    continue;
                }
                let candidates = match peer.target_wrapper_id.as_ref() {
                    Some(wrapper_id) => source_by_wrapper.get(wrapper_id),
                    None => registry_by_name_version
                        .get(&(peer.target_name.as_str(), peer.target_version.as_str())),
                }?;
                let [child] = candidates.as_slice() else {
                    return None;
                };
                queue.push_back(*child);
            }
        }
        let mut closure = seen.into_iter().collect::<Vec<_>>();
        closure.sort_unstable();
        Some(closure)
    }
}

#[cfg(test)]
thread_local! {
    static IMPORTED_EXACT_TARGET_OPERATIONS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
fn record_imported_exact_target_operation() {
    IMPORTED_EXACT_TARGET_OPERATIONS.with(|operations| operations.set(operations.get() + 1));
}

fn verified_imported_exact_target_index(
    packages: &[InstallPackage],
) -> Option<HashMap<lpm_common::PackageInstanceId, usize>> {
    let mut by_instance = HashMap::with_capacity(packages.len());
    for (index, package) in packages.iter().enumerate() {
        #[cfg(test)]
        record_imported_exact_target_operation();
        if by_instance.insert(package.instance_id?, index).is_some() {
            return None;
        }
    }

    for imported in packages {
        if imported.dependency_targets.len() != imported.dependencies.len()
            || imported.peer_targets.len() != imported.peers.len()
        {
            return None;
        }
        for (local_name, target_value) in &imported.dependencies {
            let target_id = imported.dependency_targets.get(local_name)?;
            #[cfg(test)]
            record_imported_exact_target_operation();
            let target = &packages[*by_instance.get(target_id)?];
            let target_name = imported.aliases.get(local_name).unwrap_or(local_name);
            if target.name != *target_name
                || target_value != &target.version
                    && target.wrapper_id_for_source().as_deref() != Some(target_value.as_str())
            {
                return None;
            }
        }
        for peer in &imported.peers {
            let target_id = imported.peer_targets.get(&peer.local_name)?;
            #[cfg(test)]
            record_imported_exact_target_operation();
            let target = &packages[*by_instance.get(target_id)?];
            if target.name != peer.target_name
                || target.version != peer.target_version
                || target.wrapper_id_for_source() != peer.target_wrapper_id
            {
                return None;
            }
        }
    }
    Some(by_instance)
}

fn complete_imported_exact_targets(packages: &mut [InstallPackage]) -> Option<()> {
    let mut registry_by_coordinate = HashMap::<String, Vec<lpm_common::PackageInstanceId>>::new();
    let mut source_by_wrapper = HashMap::<String, Vec<lpm_common::PackageInstanceId>>::new();
    for package in packages.iter() {
        let instance_id = package.instance_id?;
        if matches!(
            package.source_kind(),
            Ok(lpm_lockfile::Source::Registry { .. })
        ) {
            registry_by_coordinate
                .entry(super::link_target_lookup_key(
                    &package.name,
                    &package.version,
                ))
                .or_default()
                .push(instance_id);
        }
        if let Some(wrapper_id) = package.wrapper_id_for_source() {
            source_by_wrapper
                .entry(wrapper_id)
                .or_default()
                .push(instance_id);
        }
    }
    for instances in registry_by_coordinate.values_mut() {
        instances.sort_unstable();
        instances.dedup();
    }
    for instances in source_by_wrapper.values_mut() {
        instances.sort_unstable();
        instances.dedup();
    }

    for package in packages {
        for (local_name, target_value) in &package.dependencies {
            if package.dependency_targets.contains_key(local_name) {
                continue;
            }
            let target_name = package.aliases.get(local_name).unwrap_or(local_name);
            let candidates = source_by_wrapper.get(target_value).or_else(|| {
                registry_by_coordinate
                    .get(&super::link_target_lookup_key(target_name, target_value))
            })?;
            let [instance_id] = candidates.as_slice() else {
                return None;
            };
            package
                .dependency_targets
                .insert(local_name.clone(), *instance_id);
        }
        for peer in &package.peers {
            if package.peer_targets.contains_key(&peer.local_name) {
                continue;
            }
            let candidates = peer
                .target_wrapper_id
                .as_ref()
                .and_then(|wrapper_id| source_by_wrapper.get(wrapper_id))
                .or_else(|| {
                    registry_by_coordinate.get(&super::link_target_lookup_key(
                        &peer.target_name,
                        &peer.target_version,
                    ))
                })?;
            let [instance_id] = candidates.as_slice() else {
                return None;
            };
            package
                .peer_targets
                .insert(peer.local_name.clone(), *instance_id);
        }
    }
    Some(())
}

fn root_workspace_install_packages(
    root_dir: &Path,
    package: &lpm_workspace::PackageJson,
) -> Option<Vec<InstallPackage>> {
    let mut deps = super::manifest_install_deps(package);
    let optional_names = package.optional_dependencies.keys().cloned().collect();
    let context =
        super::prepare_workspace_install_context(root_dir, package, &mut deps, true, true).ok()?;
    super::pre_resolve_v2_direct_workspace_member_deps(
        root_dir,
        &mut deps,
        &context.direct_workspace_member_deps,
        &context.all_workspace_members,
        &optional_names,
        true,
        package
            .lpm
            .as_ref()
            .and_then(|lpm| lpm.auto_install_peers)
            .unwrap_or(true),
    )
    .ok()
    .map(|result| result.install_pkgs)
}

fn direct_provider_identities(
    package: &lpm_workspace::PackageJson,
    lockfile: &lpm_lockfile::Lockfile,
    local_packages: &[InstallPackage],
) -> Vec<ProviderIdentity> {
    let deps = super::manifest_install_deps(package);
    let mut direct = Vec::with_capacity(deps.len());
    for (local_name, requested_spec) in &deps {
        let target = lockfile
            .root_aliases
            .get(local_name)
            .map_or(local_name.as_str(), String::as_str);
        if let Some(package) =
            super::select_locked_root_package(lockfile, local_name, target, requested_spec)
        {
            direct.push(ProviderIdentity {
                name: package.name.clone(),
                version: package.version.clone(),
                source: package
                    .source
                    .clone()
                    .unwrap_or_else(default_registry_source),
            });
            continue;
        }
        if let Some(package) = local_packages.iter().find(|package| {
            package
                .root_link_names
                .as_ref()
                .is_some_and(|names| names.iter().any(|name| name == local_name))
        }) {
            direct.push(ProviderIdentity {
                name: package.name.clone(),
                version: package.version.clone(),
                source: package.source.clone(),
            });
        }
    }
    direct
}

fn local_provider_fingerprints(
    root_dir: &Path,
    packages: &[InstallPackage],
) -> Vec<LocalProviderFingerprint> {
    packages
        .iter()
        .filter_map(|package| {
            let path = match package.source_kind().ok()? {
                lpm_lockfile::Source::Directory { path } | lpm_lockfile::Source::Link { path } => {
                    path
                }
                _ => return None,
            };
            let manifest = lpm_common::read_file_capped(
                &root_dir.join(path).join("package.json"),
                lpm_common::CONFIG_FILE_SIZE_CAP_BYTES,
            )
            .unwrap_or_default();
            Some(LocalProviderFingerprint {
                name: package.name.clone(),
                version: package.version.clone(),
                source: package.source.clone(),
                manifest,
            })
        })
        .collect()
}

fn rebase_local_source(source: &str, source_base: &Path, target_base: &Path) -> String {
    let Ok(source_kind) = lpm_lockfile::Source::parse(source) else {
        return source.to_string();
    };
    let (kind, path) = match source_kind {
        lpm_lockfile::Source::Directory { path } => ("directory", path),
        lpm_lockfile::Source::Link { path } => ("link", path),
        _ => return source.to_string(),
    };
    let absolute = source_base.join(path);
    let relative = pathdiff::diff_paths(&absolute, target_base).unwrap_or(absolute);
    let mut path = relative.to_string_lossy().replace('\\', "/");
    if path.is_empty() {
        path.push('.');
    }
    format!("{kind}+{path}")
}

fn package_can_be_imported(packages: &[InstallPackage], root_package: &InstallPackage) -> bool {
    for package in packages.iter().filter(|package| {
        package.name == root_package.name && package.version == root_package.version
    }) {
        if package.source != root_package.source {
            return false;
        }
        if install_pkg_key(package) == install_pkg_key(root_package)
            && !package_graph_matches(package, root_package)
        {
            return false;
        }
    }
    true
}

fn package_graph_matches(left: &InstallPackage, right: &InstallPackage) -> bool {
    let mut left_dependencies = left.dependencies.clone();
    let mut right_dependencies = right.dependencies.clone();
    left_dependencies.sort_unstable();
    right_dependencies.sort_unstable();
    let mut left_peers = left.peers.clone();
    let mut right_peers = right.peers.clone();
    left_peers.sort_unstable();
    right_peers.sort_unstable();
    left_dependencies == right_dependencies
        && left.aliases == right.aliases
        && left_peers == right_peers
        && left.integrity == right.integrity
}

#[derive(Eq, Ord, PartialEq, PartialOrd)]
struct FingerprintPackage {
    name: String,
    version: String,
    source: String,
    integrity: String,
    dependencies: Vec<String>,
    aliases: Vec<[String; 2]>,
    peers: Vec<lpm_common::PeerEdge>,
    platform: Vec<String>,
    node_engine: String,
    optional: bool,
}

impl FingerprintPackage {
    fn from_locked(package: &lpm_lockfile::LockedPackage) -> Self {
        let mut dependencies = package.dependencies.clone();
        dependencies.sort_unstable();
        let mut aliases = package.alias_dependencies.clone();
        aliases.sort_unstable();
        let mut peers = if package.peer_edges.is_empty() {
            package
                .peers
                .iter()
                .filter_map(|value| {
                    value.rfind('@').map(|at| {
                        lpm_common::PeerEdge::registry(&value[..at], &value[..at], &value[at + 1..])
                    })
                })
                .collect()
        } else {
            package.peer_edges.clone()
        };
        peers.sort_unstable();
        let mut platform: Vec<String> = package
            .os
            .iter()
            .map(|value| format!("os:{value}"))
            .chain(package.cpu.iter().map(|value| format!("cpu:{value}")))
            .chain(package.libc.iter().map(|value| format!("libc:{value}")))
            .collect();
        platform.sort_unstable();
        Self {
            name: package.name.clone(),
            version: package.version.clone(),
            source: package
                .source
                .clone()
                .unwrap_or_else(default_registry_source),
            integrity: package.integrity.clone().unwrap_or_default(),
            dependencies,
            aliases,
            peers,
            platform,
            node_engine: package.node_engine.clone().unwrap_or_default(),
            optional: package.optional,
        }
    }
}

fn root_provider_fingerprint(
    manifest: &[u8],
    direct: &[ProviderIdentity],
    packages: &[FingerprintPackage],
    local: &[LocalProviderFingerprint],
    omit_policy: InstallOmitPolicy,
) -> String {
    let mut hasher = Sha256::new();
    hash_bytes(&mut hasher, b"lpm-workspace-root-peer-providers-v2");
    hash_bytes(
        &mut hasher,
        &[u8::from(omit_policy.dev), u8::from(omit_policy.optional)],
    );
    hash_bytes(&mut hasher, manifest);
    let mut direct = direct.to_vec();
    direct.sort_unstable();
    direct.dedup();
    for provider in direct {
        hash_bytes(&mut hasher, provider.name.as_bytes());
        hash_bytes(&mut hasher, provider.version.as_bytes());
        hash_bytes(&mut hasher, provider.source.as_bytes());
    }
    let mut packages = packages.iter().collect::<Vec<_>>();
    packages.sort_unstable();
    for package in packages {
        hash_bytes(&mut hasher, package.name.as_bytes());
        hash_bytes(&mut hasher, package.version.as_bytes());
        hash_bytes(&mut hasher, package.source.as_bytes());
        hash_bytes(&mut hasher, package.integrity.as_bytes());
        for dependency in &package.dependencies {
            hash_bytes(&mut hasher, dependency.as_bytes());
        }
        for alias in &package.aliases {
            hash_bytes(&mut hasher, alias[0].as_bytes());
            hash_bytes(&mut hasher, alias[1].as_bytes());
        }
        for peer in &package.peers {
            hash_bytes(&mut hasher, peer.local_name.as_bytes());
            hash_bytes(&mut hasher, peer.target_name.as_bytes());
            hash_bytes(&mut hasher, peer.target_version.as_bytes());
            hash_bytes(
                &mut hasher,
                peer.target_wrapper_id.as_deref().unwrap_or("").as_bytes(),
            );
        }
        for platform in &package.platform {
            hash_bytes(&mut hasher, platform.as_bytes());
        }
        hash_bytes(&mut hasher, package.node_engine.as_bytes());
        hash_bytes(&mut hasher, &[u8::from(package.optional)]);
    }
    let mut local = local.iter().collect::<Vec<_>>();
    local.sort_unstable();
    for package in local {
        hash_bytes(&mut hasher, package.name.as_bytes());
        hash_bytes(&mut hasher, package.version.as_bytes());
        hash_bytes(&mut hasher, package.source.as_bytes());
        hash_bytes(&mut hasher, &package.manifest);
    }
    format!("sha256-{}", hex::encode(hasher.finalize()))
}

fn hash_bytes(hasher: &mut Sha256, value: &[u8]) {
    hasher.update((value.len() as u64).to_le_bytes());
    hasher.update(value);
}

fn root_manifest_bytes(root_dir: &Path) -> Vec<u8> {
    lpm_common::read_file_capped(
        &root_dir.join("package.json"),
        lpm_common::CONFIG_FILE_SIZE_CAP_BYTES,
    )
    .unwrap_or_default()
}

fn default_registry_source() -> String {
    "registry+https://registry.npmjs.org".to_string()
}

pub(super) async fn wait_for_materialization() -> u128 {
    if let Ok(task) = ACTIVE_TASK.try_with(Arc::clone) {
        task.wait_for_materialization().await
    } else {
        0
    }
}

pub(super) fn enter_commit() -> u128 {
    if let Ok(task) = ACTIVE_TASK.try_with(Arc::clone) {
        task.enter_commit()
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{self, Write};
    use std::sync::Mutex;
    use tracing::instrument::WithSubscriber as _;
    use tracing_subscriber::fmt::MakeWriter;

    #[derive(Clone, Default)]
    struct TraceBuffer(Arc<Mutex<Vec<u8>>>);

    impl Write for TraceBuffer {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl<'writer> MakeWriter<'writer> for TraceBuffer {
        type Writer = TraceBuffer;

        fn make_writer(&'writer self) -> Self::Writer {
            self.clone()
        }
    }

    fn workspace_union_request_with_route_table(
        route_table: lpm_registry::RouteTable,
    ) -> WorkspaceUnionRequest {
        WorkspaceUnionRequest {
            client: Arc::new(lpm_registry::RegistryClient::new().with_cache_dir(None)),
            root_dependencies: lpm_resolver::RootDependencies::required(HashMap::new()),
            overrides: lpm_resolver::OverrideSet::empty(),
            route_table,
            npm_fanout: 8,
            shared_cache: Arc::new(dashmap::DashMap::new()),
            auto_install_peers: true,
            include_optional_dependencies: true,
            policy: lpm_resolver::ResolverPolicy::default(),
        }
    }

    fn workspace_union_request() -> WorkspaceUnionRequest {
        workspace_union_request_with_route_table(lpm_registry::RouteTable::from_mode_only(
            lpm_registry::RouteMode::Direct,
        ))
    }

    fn install_package(name: &str, source: &str, is_direct: bool) -> InstallPackage {
        InstallPackage {
            instance_id: None,
            dependency_targets: HashMap::new(),
            peer_targets: HashMap::new(),
            name: name.to_string(),
            version: "1.0.0".to_string(),
            source: source.to_string(),
            dependencies: Vec::new(),
            aliases: HashMap::new(),
            root_link_names: is_direct.then(|| vec![name.to_string()]),
            is_direct,
            is_lpm: false,
            peers: Vec::new(),
            integrity: None,
            unpacked_size: None,
            registry_signatures: Vec::new(),
            registry_published_at: None,
            platform: None,
            node_engine: None,
            optional: false,
            tarball_url: None,
            metadata_checked_for_tarball: false,
            manifest_fingerprint: None,
        }
    }

    fn credentialed_route_table(token: &str) -> lpm_registry::RouteTable {
        let npmrc = lpm_registry::NpmrcConfig::parse(
            &format!(
                "registry=https://registry.internal/\n//registry.internal/:_authToken={token}\n"
            ),
            "test",
            &|_| None,
        );
        lpm_registry::RouteTable::new(lpm_registry::RouteMode::Direct, npmrc)
            .expect("valid route table")
    }

    fn default_route_table_with_npm_auth() -> lpm_registry::RouteTable {
        let npmrc = lpm_registry::NpmrcConfig::parse(
            "//registry.npmjs.org/:_authToken=npm-token\n",
            "test",
            &|_| None,
        );
        lpm_registry::RouteTable::new(lpm_registry::RouteMode::Direct, npmrc)
            .expect("valid route table")
    }

    fn tls_customized_route_table() -> lpm_registry::RouteTable {
        let npmrc = lpm_registry::NpmrcConfig::parse("strict-ssl=true\n", "test", &|_| None);
        lpm_registry::RouteTable::new(lpm_registry::RouteMode::Direct, npmrc)
            .expect("valid route table")
    }

    async fn workspace_union_results_for_routes(
        first_route: lpm_registry::RouteTable,
        second_route: lpm_registry::RouteTable,
    ) -> (
        Option<lpm_resolver::ResolveResult>,
        Option<lpm_resolver::ResolveResult>,
    ) {
        let coordinator = Arc::new(WorkspaceResolutionCoordinator::new_union_at_unix(
            2,
            None,
            current_unix_timestamp(),
        ));
        let local = tokio::task::LocalSet::new();
        let (first, second) = local
            .run_until(async {
                tokio::join!(
                    {
                        let coordinator = Arc::clone(&coordinator);
                        tokio::task::spawn_local(async move {
                            scope(coordinator, 0, async {
                                resolve_workspace_union(workspace_union_request_with_route_table(
                                    first_route,
                                ))
                                .await
                            })
                            .await
                        })
                    },
                    {
                        let coordinator = Arc::clone(&coordinator);
                        tokio::task::spawn_local(async move {
                            scope(coordinator, 1, async {
                                resolve_workspace_union(workspace_union_request_with_route_table(
                                    second_route,
                                ))
                                .await
                            })
                            .await
                        })
                    },
                )
            })
            .await;
        let projected = |resolution| match resolution {
            WorkspaceUnionResolution::Projected(result) => Some(*result),
            WorkspaceUnionResolution::Isolated(_) => None,
        };
        (
            projected(first.unwrap().unwrap()),
            projected(second.unwrap().unwrap()),
        )
    }

    async fn fact_caches_for_resolution_importers(
        route_table: lpm_registry::RouteTable,
    ) -> (
        Option<lpm_resolver::SharedCache>,
        Option<lpm_resolver::SharedCache>,
    ) {
        let coordinator = Arc::new(WorkspaceResolutionCoordinator::new(2, 2));
        let local = tokio::task::LocalSet::new();
        let (first, second) = local
            .run_until(async {
                tokio::join!(
                    {
                        let coordinator = Arc::clone(&coordinator);
                        let route_table = route_table.clone();
                        tokio::task::spawn_local(async move {
                            scope(coordinator, 0, async {
                                Ok::<_, ()>(resolver_fact_cache_for_importer(&route_table))
                            })
                            .await
                        })
                    },
                    {
                        let coordinator = Arc::clone(&coordinator);
                        tokio::task::spawn_local(async move {
                            scope(coordinator, 1, async {
                                Ok::<_, ()>(resolver_fact_cache_for_importer(&route_table))
                            })
                            .await
                        })
                    },
                )
            })
            .await;
        (first.unwrap().unwrap(), second.unwrap().unwrap())
    }

    async fn metadata_concurrency_for_resolution_importers(
        route_table: lpm_registry::RouteTable,
        requested_fanout: usize,
    ) -> (
        Option<lpm_resolver::SharedMetadataConcurrency>,
        Option<lpm_resolver::SharedMetadataConcurrency>,
    ) {
        let coordinator = Arc::new(WorkspaceResolutionCoordinator::new(2, 2));
        let local = tokio::task::LocalSet::new();
        let (first, second) = local
            .run_until(async {
                tokio::join!(
                    {
                        let coordinator = Arc::clone(&coordinator);
                        let route_table = route_table.clone();
                        tokio::task::spawn_local(async move {
                            scope(coordinator, 0, async {
                                Ok::<_, ()>(resolver_metadata_concurrency_for_importer(
                                    &route_table,
                                    requested_fanout,
                                ))
                            })
                            .await
                        })
                    },
                    {
                        let coordinator = Arc::clone(&coordinator);
                        tokio::task::spawn_local(async move {
                            scope(coordinator, 1, async {
                                Ok::<_, ()>(resolver_metadata_concurrency_for_importer(
                                    &route_table,
                                    requested_fanout,
                                ))
                            })
                            .await
                        })
                    },
                )
            })
            .await;
        (first.unwrap().unwrap(), second.unwrap().unwrap())
    }

    #[test]
    fn missing_root_projection_has_no_peer_provider_fingerprint() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::write(
            directory.path().join("package.json"),
            r#"{"name":"root","private":true,"dependencies":{"peer":"1.0.0"}}"#,
        )
        .unwrap();

        let coordinator = super::super::workspace_lockfile::WorkspaceLockfileCoordinator::new(
            directory.path(),
            &[],
        )
        .unwrap();
        let fingerprint = coordinator.projection(".").ok().and_then(|lockfile| {
            root_provider_fingerprint_from_projection(
                directory.path(),
                &lockfile,
                InstallOmitPolicy::default(),
            )
        });

        assert_eq!(fingerprint, None);
    }

    #[test]
    fn root_provider_reconciliation_binds_aliased_peer_to_exact_local_source() {
        let workspace = tempfile::tempdir().unwrap();
        std::fs::write(workspace.path().join("package.json"), b"{}").unwrap();
        std::fs::create_dir_all(workspace.path().join("provider")).unwrap();
        std::fs::write(
            workspace.path().join("provider/package.json"),
            br#"{"name":"react","version":"1.0.0"}"#,
        )
        .unwrap();
        let project_dir = workspace.path().join("packages/app");
        std::fs::create_dir_all(&project_dir).unwrap();

        let mut provider = install_package("react", "directory+provider", true);
        let provider_id = lpm_common::PackageInstanceId::derive(
            "react",
            "1.0.0",
            "directory+provider",
            "root/react",
        );
        provider.instance_id = Some(provider_id);
        let snapshot = RootProviderSnapshot::new(
            workspace.path(),
            vec![provider],
            &[],
            InstallOmitPolicy::default(),
            &HashSet::new(),
            &HashSet::new(),
        );
        let mut consumer = install_package(
            "compat-consumer",
            "registry+https://registry.npmjs.org",
            false,
        );
        consumer.instance_id = Some(lpm_common::PackageInstanceId::derive(
            "compat-consumer",
            "1.0.0",
            "registry+https://registry.npmjs.org",
            "root/compat-consumer",
        ));
        let mut packages = vec![consumer];
        let mut warnings = vec![PeerWarning {
            package: "compat-consumer".to_string(),
            version: "1.0.0".to_string(),
            peer: "react-compat".to_string(),
            target: "react".to_string(),
            required_range: "*".to_string(),
            resolved_version: None,
        }];

        assert!(snapshot.reconcile(&project_dir, &mut packages, &mut warnings));
        assert!(warnings.is_empty());
        let imported_provider = packages
            .iter()
            .find(|package| package.name == "react")
            .expect("root provider imported");
        assert_eq!(
            imported_provider.instance_id,
            Some(provider_id.rebase_source("react", "1.0.0", &imported_provider.source,)),
            "rebased local sources must receive identities derived from their projected source",
        );
        let consumer = packages
            .iter()
            .find(|package| package.name == "compat-consumer")
            .unwrap();
        assert_eq!(
            consumer.peers,
            [lpm_common::PeerEdge {
                local_name: "react-compat".to_string(),
                target_name: "react".to_string(),
                target_version: "1.0.0".to_string(),
                target_wrapper_id: imported_provider.wrapper_id_for_source(),
            }]
        );
        assert_eq!(
            consumer.peer_targets.get("react-compat"),
            imported_provider.instance_id.as_ref()
        );
    }

    #[test]
    fn root_provider_closure_imports_exact_local_dependency_without_same_coordinate_registry_row() {
        let workspace = tempfile::tempdir().unwrap();
        std::fs::write(workspace.path().join("package.json"), b"{}").unwrap();
        let project_dir = workspace.path().join("packages/app");
        std::fs::create_dir_all(&project_dir).unwrap();

        let mut provider = install_package("provider", "directory+provider", true);
        let provider_id = lpm_common::PackageInstanceId::derive(
            "provider",
            "1.0.0",
            "directory+provider",
            "root/provider",
        );
        provider.instance_id = Some(provider_id);
        let mut local_child = install_package("child", "directory+local-child", false);
        let local_child_id = lpm_common::PackageInstanceId::derive(
            "child",
            "1.0.0",
            "directory+local-child",
            "root/provider/child",
        );
        local_child.instance_id = Some(local_child_id);
        let local_wrapper = local_child.wrapper_id_for_source().unwrap();
        provider
            .dependencies
            .push(("child".to_string(), local_wrapper.clone()));
        provider
            .dependency_targets
            .insert("child".to_string(), local_child_id);
        let registry_child = install_package("child", "registry+https://registry.npmjs.org", false);
        let snapshot = RootProviderSnapshot::new(
            workspace.path(),
            vec![provider, registry_child, local_child],
            &[],
            InstallOmitPolicy::default(),
            &HashSet::new(),
            &HashSet::new(),
        );
        let mut packages = vec![install_package(
            "consumer",
            "registry+https://registry.npmjs.org",
            false,
        )];
        let mut warnings = vec![PeerWarning {
            package: "consumer".to_string(),
            version: "1.0.0".to_string(),
            peer: "provider".to_string(),
            target: "provider".to_string(),
            required_range: "*".to_string(),
            resolved_version: None,
        }];

        assert!(snapshot.reconcile(&project_dir, &mut packages, &mut warnings));

        let children = packages
            .iter()
            .filter(|package| package.name == "child")
            .collect::<Vec<_>>();
        assert_eq!(children.len(), 1);
        let imported_wrapper = children[0].wrapper_id_for_source().unwrap();
        let imported_provider = packages
            .iter()
            .find(|package| package.name == "provider")
            .expect("provider imported");
        assert_ne!(imported_wrapper, local_wrapper);
        assert_eq!(imported_provider.dependencies[0].1, imported_wrapper);
        let imported_child_id = children[0].instance_id.unwrap();
        assert_eq!(
            imported_provider.instance_id,
            Some(provider_id.rebase_source("provider", "1.0.0", &imported_provider.source,))
        );
        assert_eq!(
            imported_child_id,
            local_child_id.rebase_source("child", "1.0.0", &children[0].source)
        );
        assert_eq!(
            imported_provider.dependency_targets.get("child"),
            Some(&imported_child_id),
            "exact dependency targets must follow the rebased local instance",
        );
    }

    #[test]
    fn reconciled_manifest_workspace_peer_is_not_persisted_as_ambient() {
        let provider_id = lpm_common::PackageInstanceId::derive(
            "workspace-lib",
            "1.0.0",
            "directory+../workspace-lib",
            "root/workspace-lib",
        );
        let consumer_id = lpm_common::PackageInstanceId::derive(
            "consumer",
            "1.0.0",
            "registry+https://registry.npmjs.org",
            "root/consumer",
        );
        let mut provider = install_package("workspace-lib", "directory+../workspace-lib", true);
        provider.instance_id = Some(provider_id);
        provider.root_link_names = Some(vec!["workspace-lib".to_string()]);
        let mut consumer = install_package("consumer", "registry+https://registry.npmjs.org", true);
        consumer.instance_id = Some(consumer_id);
        consumer.peers = vec![lpm_common::PeerEdge {
            local_name: "workspace-lib".to_string(),
            target_name: "workspace-lib".to_string(),
            target_version: "1.0.0".to_string(),
            target_wrapper_id: provider.wrapper_id_for_source(),
        }];
        consumer
            .peer_targets
            .insert("workspace-lib".to_string(), provider_id);
        let mut packages = vec![consumer, provider];
        let mut ambient = vec!["workspace-lib".to_string()];

        reconcile_ambient_peer_roots(
            &mut packages,
            &mut ambient,
            &HashMap::from([("workspace-lib".to_string(), "workspace:*".to_string())]),
        )
        .expect("reconcile declared workspace provider");

        assert!(ambient.is_empty());
    }

    #[test]
    fn manifest_alias_does_not_suppress_canonical_ambient_peer_root() {
        let provider_id = lpm_common::PackageInstanceId::derive(
            "react",
            "17.0.0",
            "registry+https://registry.npmjs.org",
            "root/react-17",
        );
        let consumer_id = lpm_common::PackageInstanceId::derive(
            "consumer",
            "1.0.0",
            "registry+https://registry.npmjs.org",
            "root/consumer",
        );
        let mut provider = install_package("react", "registry+https://registry.npmjs.org", true);
        provider.version = "17.0.0".to_string();
        provider.instance_id = Some(provider_id);
        provider.root_link_names = Some(vec!["react-17".to_string()]);
        let mut consumer = install_package("consumer", "registry+https://registry.npmjs.org", true);
        consumer.instance_id = Some(consumer_id);
        consumer.peers = vec![lpm_common::PeerEdge {
            local_name: "react".to_string(),
            target_name: "react".to_string(),
            target_version: "17.0.0".to_string(),
            target_wrapper_id: provider.wrapper_id_for_source(),
        }];
        consumer
            .peer_targets
            .insert("react".to_string(), provider_id);
        let mut packages = vec![consumer, provider];
        let mut ambient = Vec::new();

        reconcile_ambient_peer_roots(
            &mut packages,
            &mut ambient,
            &HashMap::from([("react-17".to_string(), "npm:react@17".to_string())]),
        )
        .expect("reconcile canonical peer beside manifest alias");

        let provider = packages
            .iter()
            .find(|package| package.name == "react")
            .expect("provider remains present");
        assert_eq!(
            (ambient.as_slice(), provider.root_link_names.as_deref()),
            (
                &["react".to_string()][..],
                Some(&["react".to_string(), "react-17".to_string()][..]),
            ),
        );
    }

    #[test]
    fn imported_exact_target_validation_scales_linearly_with_package_count() {
        const PACKAGE_COUNT: usize = 64;
        let source = "registry+https://registry.npmjs.org";
        let mut packages = (0..PACKAGE_COUNT)
            .map(|index| {
                let name = format!("node-{index}");
                let mut package = install_package(&name, source, false);
                package.instance_id = Some(lpm_common::PackageInstanceId::derive(
                    &name,
                    "1.0.0",
                    source,
                    &format!("root/{name}"),
                ));
                package
            })
            .collect::<Vec<_>>();
        for index in 0..PACKAGE_COUNT - 1 {
            let target_name = packages[index + 1].name.clone();
            let target_id = packages[index + 1].instance_id.unwrap();
            packages[index]
                .dependencies
                .push(("next".to_string(), "1.0.0".to_string()));
            packages[index]
                .aliases
                .insert("next".to_string(), target_name);
            packages[index]
                .dependency_targets
                .insert("next".to_string(), target_id);
        }

        IMPORTED_EXACT_TARGET_OPERATIONS.with(|operations| operations.set(0));
        let index = verified_imported_exact_target_index(&packages)
            .expect("the exact imported graph must validate");
        let operations = IMPORTED_EXACT_TARGET_OPERATIONS.with(std::cell::Cell::get);

        assert_eq!(index.len(), PACKAGE_COUNT);
        assert!(
            operations <= PACKAGE_COUNT * 2,
            "exact-target validation performed {operations} indexed operations for {PACKAGE_COUNT} packages"
        );
    }

    #[test]
    fn imported_exact_target_validation_rejects_duplicate_instance_ids() {
        let source = "registry+https://registry.npmjs.org";
        let mut first = install_package("first", source, false);
        let mut second = install_package("second", source, false);
        let duplicate =
            lpm_common::PackageInstanceId::derive("first", "1.0.0", source, "root/first");
        first.instance_id = Some(duplicate);
        second.instance_id = Some(duplicate);

        assert!(verified_imported_exact_target_index(&[first, second]).is_none());
    }

    #[test]
    fn imported_exact_target_validation_rejects_missing_instance_ids() {
        let package = install_package(
            "missing-instance",
            "registry+https://registry.npmjs.org",
            false,
        );

        assert!(verified_imported_exact_target_index(&[package]).is_none());
    }

    #[test]
    fn imported_exact_target_validation_rejects_incomplete_dependency_targets() {
        let source = "registry+https://registry.npmjs.org";
        let mut parent = install_package("parent", source, false);
        let mut child = install_package("child", source, false);
        parent.instance_id = Some(lpm_common::PackageInstanceId::derive(
            "parent",
            "1.0.0",
            source,
            "root/parent",
        ));
        child.instance_id = Some(lpm_common::PackageInstanceId::derive(
            "child",
            "1.0.0",
            source,
            "root/parent/child",
        ));
        parent
            .dependencies
            .push(("child".to_string(), "1.0.0".to_string()));

        assert!(verified_imported_exact_target_index(&[parent, child]).is_none());
    }

    #[test]
    fn root_provider_closure_follows_exact_contextual_dependency_target() {
        let workspace = tempfile::tempdir().unwrap();
        std::fs::write(workspace.path().join("package.json"), b"{}").unwrap();
        let project_dir = workspace.path().join("packages/app");
        std::fs::create_dir_all(&project_dir).unwrap();
        let source = "registry+https://registry.npmjs.org";

        let mut provider = install_package("provider", source, true);
        let provider_id =
            lpm_common::PackageInstanceId::derive("provider", "1.0.0", source, "root/provider");
        let unused_child_id =
            lpm_common::PackageInstanceId::derive("child", "1.0.0", source, "root/unused/child");
        let selected_child_id =
            lpm_common::PackageInstanceId::derive("child", "1.0.0", source, "root/provider/child");
        provider.instance_id = Some(provider_id);
        provider
            .dependencies
            .push(("child".to_string(), "1.0.0".to_string()));
        provider
            .dependency_targets
            .insert("child".to_string(), selected_child_id);
        let mut unused_child = install_package("child", source, false);
        unused_child.instance_id = Some(unused_child_id);
        let mut selected_child = unused_child.clone();
        selected_child.instance_id = Some(selected_child_id);
        let snapshot = RootProviderSnapshot::new(
            workspace.path(),
            vec![provider, unused_child, selected_child],
            &[],
            InstallOmitPolicy::default(),
            &HashSet::new(),
            &HashSet::new(),
        );
        let mut consumer = install_package("consumer", source, false);
        consumer.instance_id = Some(lpm_common::PackageInstanceId::derive(
            "consumer",
            "1.0.0",
            source,
            "root/consumer",
        ));
        let mut packages = vec![consumer];
        let mut warnings = vec![PeerWarning {
            package: "consumer".to_string(),
            version: "1.0.0".to_string(),
            peer: "provider".to_string(),
            target: "provider".to_string(),
            required_range: "*".to_string(),
            resolved_version: None,
        }];

        assert!(snapshot.reconcile(&project_dir, &mut packages, &mut warnings));

        let imported_children = packages
            .iter()
            .filter(|package| package.name == "child")
            .map(|package| package.instance_id.unwrap())
            .collect::<Vec<_>>();
        assert_eq!(imported_children, vec![selected_child_id]);
    }

    #[test]
    fn root_provider_closure_imports_only_exact_peer_wrapper() {
        let workspace = tempfile::tempdir().unwrap();
        std::fs::write(workspace.path().join("package.json"), b"{}").unwrap();
        let project_dir = workspace.path().join("packages/app");
        std::fs::create_dir_all(&project_dir).unwrap();

        let mut provider = install_package("provider", "directory+provider", true);
        let local_peer = install_package("runtime", "directory+runtime", false);
        let local_wrapper = local_peer.wrapper_id_for_source().unwrap();
        provider.peers = vec![lpm_common::PeerEdge {
            local_name: "runtime".to_string(),
            target_name: "runtime".to_string(),
            target_version: "1.0.0".to_string(),
            target_wrapper_id: Some(local_wrapper.clone()),
        }];
        let registry_peer =
            install_package("runtime", "registry+https://registry.npmjs.org", false);
        let snapshot = RootProviderSnapshot::new(
            workspace.path(),
            vec![provider, registry_peer, local_peer],
            &[],
            InstallOmitPolicy::default(),
            &HashSet::new(),
            &HashSet::new(),
        );
        let mut packages = vec![install_package(
            "consumer",
            "registry+https://registry.npmjs.org",
            false,
        )];
        let mut warnings = vec![PeerWarning {
            package: "consumer".to_string(),
            version: "1.0.0".to_string(),
            peer: "provider".to_string(),
            target: "provider".to_string(),
            required_range: "*".to_string(),
            resolved_version: None,
        }];

        assert!(snapshot.reconcile(&project_dir, &mut packages, &mut warnings));

        let peers = packages
            .iter()
            .filter(|package| package.name == "runtime")
            .collect::<Vec<_>>();
        assert_eq!(peers.len(), 1);
        let imported_wrapper = peers[0].wrapper_id_for_source().unwrap();
        let imported_provider = packages
            .iter()
            .find(|package| package.name == "provider")
            .expect("provider imported");
        assert_ne!(imported_wrapper, local_wrapper);
        assert_eq!(
            imported_provider.peers[0].target_wrapper_id.as_deref(),
            Some(imported_wrapper.as_str())
        );
    }

    #[test]
    fn root_provider_reconciliation_rejects_ambiguous_consumer_identity() {
        let workspace = tempfile::tempdir().unwrap();
        std::fs::write(workspace.path().join("package.json"), b"{}").unwrap();
        std::fs::create_dir_all(workspace.path().join("provider")).unwrap();
        std::fs::write(
            workspace.path().join("provider/package.json"),
            br#"{"name":"runtime","version":"1.0.0"}"#,
        )
        .unwrap();
        let project_dir = workspace.path().join("packages/app");
        std::fs::create_dir_all(&project_dir).unwrap();

        let provider = install_package("runtime", "directory+provider", true);
        let snapshot = RootProviderSnapshot::new(
            workspace.path(),
            vec![provider],
            &[],
            InstallOmitPolicy::default(),
            &HashSet::new(),
            &HashSet::new(),
        );
        let registry_consumer =
            install_package("consumer", "registry+https://registry.npmjs.org", false);
        let local_consumer = install_package("consumer", "directory+consumer", false);
        let mut packages = vec![registry_consumer, local_consumer];
        let mut warnings = vec![PeerWarning {
            package: "consumer".to_string(),
            version: "1.0.0".to_string(),
            peer: "runtime".to_string(),
            target: "runtime".to_string(),
            required_range: "*".to_string(),
            resolved_version: None,
        }];

        assert!(!snapshot.reconcile(&project_dir, &mut packages, &mut warnings));
        assert_eq!(warnings.len(), 1);
        assert_eq!(packages.len(), 2);
        assert!(packages.iter().all(|package| package.peers.is_empty()));
    }

    #[test]
    fn workspace_fetch_hub_is_not_initialized_until_fresh_resolution_needs_it() {
        let coordinator = WorkspaceResolutionCoordinator::new(4, 4);

        assert!(!coordinator.fetch_overlap_hub_initialized());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn workspace_fetch_hub_initializes_when_fresh_resolution_requests_it() {
        let coordinator = WorkspaceResolutionCoordinator::new(4, 4);

        let _hub = coordinator.fetch_overlap_hub();

        assert!(coordinator.fetch_overlap_hub_initialized());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn workspace_union_waiters_fail_when_a_participant_exits_before_submission() {
        let coordinator = Arc::new(WorkspaceResolutionCoordinator::new_union_at_unix(
            2,
            None,
            current_unix_timestamp(),
        ));
        let local = tokio::task::LocalSet::new();
        let (failed, waiter) = local
            .run_until(async {
                tokio::join!(
                    {
                        let coordinator = Arc::clone(&coordinator);
                        tokio::task::spawn_local(async move {
                            scope(coordinator, 0, async { Err::<(), _>("pre-submit failure") })
                                .await
                        })
                    },
                    {
                        let coordinator = Arc::clone(&coordinator);
                        tokio::task::spawn_local(async move {
                            scope(coordinator, 1, async {
                                resolve_workspace_union(workspace_union_request())
                                    .await
                                    .map(|_| ())
                            })
                            .await
                        })
                    },
                )
            })
            .await;

        assert_eq!(failed.unwrap(), Err("pre-submit failure"));
        let error = waiter.unwrap().unwrap_err().to_string();
        assert!(error.contains("another workspace importer failed"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn workspace_union_projects_importers_with_matching_credentials() {
        let route_table = credentialed_route_table("shared-token");

        let (first, second) =
            workspace_union_results_for_routes(route_table.clone(), route_table).await;

        assert!(first.is_some());
        assert!(second.is_some());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn workspace_union_logs_when_different_credentials_isolate_importers() {
        let output = TraceBuffer::default();
        let subscriber = tracing_subscriber::fmt()
            .without_time()
            .with_target(false)
            .with_level(false)
            .with_ansi(false)
            .with_max_level(tracing::Level::DEBUG)
            .with_writer(output.clone())
            .finish();
        let (first, second) = workspace_union_results_for_routes(
            credentialed_route_table("first-token"),
            credentialed_route_table("second-token"),
        )
        .with_subscriber(subscriber)
        .await;

        assert!(first.is_none());
        assert!(second.is_none());
        let rendered = String::from_utf8(output.0.lock().unwrap().clone()).unwrap();
        assert_eq!(
            rendered
                .matches("reason=\"singleton-equivalence-group\"")
                .count(),
            2,
            "{rendered}"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn workspace_union_logs_when_route_key_is_unavailable() {
        let output = TraceBuffer::default();
        let subscriber = tracing_subscriber::fmt()
            .without_time()
            .with_target(false)
            .with_level(false)
            .with_ansi(false)
            .with_max_level(tracing::Level::DEBUG)
            .with_writer(output.clone())
            .finish();
        let route_table = tls_customized_route_table();
        let (first, second) = workspace_union_results_for_routes(route_table.clone(), route_table)
            .with_subscriber(subscriber)
            .await;

        assert!(first.is_none());
        assert!(second.is_none());
        let rendered = String::from_utf8(output.0.lock().unwrap().clone()).unwrap();
        assert_eq!(
            rendered.matches("reason=\"route-key-unavailable\"").count(),
            2,
            "{rendered}"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn direct_workspace_importers_share_only_the_base_fact_cache() {
        let route_table = lpm_registry::RouteTable::from_mode_only(lpm_registry::RouteMode::Direct);
        let (first, second) = fact_caches_for_resolution_importers(route_table).await;
        let first = first.unwrap();
        let second = second.unwrap();

        assert!(Arc::ptr_eq(&first, &second));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn npm_auth_token_does_not_isolate_workspace_fact_caches() {
        let (first, second) =
            fact_caches_for_resolution_importers(default_route_table_with_npm_auth()).await;
        let first = first.unwrap();
        let second = second.unwrap();

        assert!(Arc::ptr_eq(&first, &second));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn root_provider_workspace_importers_share_only_the_base_fact_cache() {
        let coordinator = Arc::new(WorkspaceRootProviderCoordinator::new());
        let route_table = lpm_registry::RouteTable::from_mode_only(lpm_registry::RouteMode::Direct);
        let local = tokio::task::LocalSet::new();
        let (root, member) = local
            .run_until(async {
                tokio::join!(
                    {
                        let coordinator = Arc::clone(&coordinator);
                        let route_table = route_table.clone();
                        tokio::task::spawn_local(async move {
                            root_provider_scope(coordinator, true, async {
                                Ok::<_, ()>(resolver_fact_cache_for_importer(&route_table))
                            })
                            .await
                        })
                    },
                    {
                        let coordinator = Arc::clone(&coordinator);
                        tokio::task::spawn_local(async move {
                            root_provider_scope(coordinator, false, async {
                                Ok::<_, ()>(resolver_fact_cache_for_importer(&route_table))
                            })
                            .await
                        })
                    },
                )
            })
            .await;
        let root = root.unwrap().unwrap().unwrap();
        let member = member.unwrap().unwrap().unwrap();

        assert!(Arc::ptr_eq(&root, &member));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn direct_workspace_importers_share_one_metadata_permit_pool() {
        let route_table = lpm_registry::RouteTable::from_mode_only(lpm_registry::RouteMode::Direct);
        let (first, second) = metadata_concurrency_for_resolution_importers(route_table, 16).await;
        let first = first.unwrap();
        let second = second.unwrap();

        assert!(first.shares_pool_with(&second));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn npm_auth_token_does_not_isolate_workspace_metadata_permit_pool() {
        let (first, second) =
            metadata_concurrency_for_resolution_importers(default_route_table_with_npm_auth(), 16)
                .await;
        let first = first.unwrap();
        let second = second.unwrap();

        assert!(first.shares_pool_with(&second));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn root_provider_workspace_importers_share_one_metadata_permit_pool() {
        let coordinator = Arc::new(WorkspaceRootProviderCoordinator::new());
        let route_table = lpm_registry::RouteTable::from_mode_only(lpm_registry::RouteMode::Direct);
        let local = tokio::task::LocalSet::new();
        let (root, member) = local
            .run_until(async {
                tokio::join!(
                    {
                        let coordinator = Arc::clone(&coordinator);
                        let route_table = route_table.clone();
                        tokio::task::spawn_local(async move {
                            root_provider_scope(coordinator, true, async {
                                Ok::<_, ()>(resolver_metadata_concurrency_for_importer(
                                    &route_table,
                                    16,
                                ))
                            })
                            .await
                        })
                    },
                    {
                        let coordinator = Arc::clone(&coordinator);
                        tokio::task::spawn_local(async move {
                            root_provider_scope(coordinator, false, async {
                                Ok::<_, ()>(resolver_metadata_concurrency_for_importer(
                                    &route_table,
                                    16,
                                ))
                            })
                            .await
                        })
                    },
                )
            })
            .await;
        let root = root.unwrap().unwrap().unwrap();
        let member = member.unwrap().unwrap().unwrap();

        assert!(root.shares_pool_with(&member));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn importer_with_a_different_fanout_keeps_its_own_permit_pool() {
        let coordinator = Arc::new(WorkspaceResolutionCoordinator::new(1, 1));
        let route_table = lpm_registry::RouteTable::from_mode_only(lpm_registry::RouteMode::Direct);
        let (first, second) = scope(coordinator, 0, async {
            let first = resolver_metadata_concurrency_for_importer(&route_table, 16);
            let second = resolver_metadata_concurrency_for_importer(&route_table, 32);
            Ok::<_, ()>((first, second))
        })
        .await
        .unwrap();

        assert!(first.is_some());
        assert!(second.is_none());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn resolution_importers_share_the_command_release_age_reference() {
        const REFERENCE_UNIX: i64 = 1_800_000_000;
        let coordinator = Arc::new(WorkspaceResolutionCoordinator::new_at_unix(
            2,
            2,
            REFERENCE_UNIX,
        ));
        let local = tokio::task::LocalSet::new();
        let (first, second) = local
            .run_until(async {
                tokio::join!(
                    {
                        let coordinator = Arc::clone(&coordinator);
                        tokio::task::spawn_local(async move {
                            scope(coordinator, 0, async {
                                Ok::<_, ()>(release_age_reference_unix())
                            })
                            .await
                        })
                    },
                    {
                        let coordinator = Arc::clone(&coordinator);
                        tokio::task::spawn_local(async move {
                            scope(coordinator, 1, async {
                                Ok::<_, ()>(release_age_reference_unix())
                            })
                            .await
                        })
                    },
                )
            })
            .await;

        assert_eq!(
            (first.unwrap().unwrap(), second.unwrap().unwrap()),
            (Some(REFERENCE_UNIX), Some(REFERENCE_UNIX))
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn root_provider_importers_share_the_command_release_age_reference() {
        const REFERENCE_UNIX: i64 = 1_800_000_000;
        let coordinator = Arc::new(WorkspaceRootProviderCoordinator::new_at_unix(
            REFERENCE_UNIX,
        ));
        let local = tokio::task::LocalSet::new();
        let (root, member) = local
            .run_until(async {
                tokio::join!(
                    {
                        let coordinator = Arc::clone(&coordinator);
                        tokio::task::spawn_local(async move {
                            root_provider_scope(coordinator, true, async {
                                Ok::<_, ()>(release_age_reference_unix())
                            })
                            .await
                        })
                    },
                    {
                        let coordinator = Arc::clone(&coordinator);
                        tokio::task::spawn_local(async move {
                            root_provider_scope(coordinator, false, async {
                                Ok::<_, ()>(release_age_reference_unix())
                            })
                            .await
                        })
                    },
                )
            })
            .await;

        assert_eq!(
            (root.unwrap().unwrap(), member.unwrap().unwrap()),
            (Some(REFERENCE_UNIX), Some(REFERENCE_UNIX))
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn custom_route_workspace_importers_have_no_shared_base_fact_cache() {
        fn no_env(_name: &str) -> Option<String> {
            None
        }

        let npmrc = lpm_registry::NpmrcConfig::parse(
            "registry=https://registry.example.test\n",
            "test",
            &no_env,
        );
        let route_table =
            lpm_registry::RouteTable::new(lpm_registry::RouteMode::Direct, npmrc).unwrap();
        let (first, second) = fact_caches_for_resolution_importers(route_table).await;

        assert!(first.is_none());
        assert!(second.is_none());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn proxy_workspace_importers_have_no_shared_base_fact_cache() {
        let route_table = lpm_registry::RouteTable::from_mode_only(lpm_registry::RouteMode::Proxy);
        let (first, second) = fact_caches_for_resolution_importers(route_table).await;

        assert!(first.is_none());
        assert!(second.is_none());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn custom_route_workspace_importers_have_no_shared_metadata_permit_pool() {
        fn no_env(_name: &str) -> Option<String> {
            None
        }

        let npmrc = lpm_registry::NpmrcConfig::parse(
            "registry=https://registry.example.test\n",
            "test",
            &no_env,
        );
        let route_table =
            lpm_registry::RouteTable::new(lpm_registry::RouteMode::Direct, npmrc).unwrap();
        let (first, second) = metadata_concurrency_for_resolution_importers(route_table, 16).await;

        assert!(first.is_none());
        assert!(second.is_none());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn proxy_workspace_importers_have_no_shared_metadata_permit_pool() {
        let route_table = lpm_registry::RouteTable::from_mode_only(lpm_registry::RouteMode::Proxy);
        let (first, second) = metadata_concurrency_for_resolution_importers(route_table, 16).await;

        assert!(first.is_none());
        assert!(second.is_none());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn importer_enters_commit_without_waiting_for_other_importers() {
        let projects = tempfile::tempdir().unwrap();
        let first_project = projects.path().join("first");
        let second_project = projects.path().join("second");
        for project in [&first_project, &second_project] {
            std::fs::create_dir_all(project).unwrap();
            std::fs::write(project.join("package.json"), b"{}").unwrap();
        }
        let coordinator = Arc::new(WorkspaceResolutionCoordinator::new(2, 2));
        let project_state = Arc::new(
            super::super::workspace_project_state::WorkspaceProjectStateCoordinator::new(2),
        );
        let first_committed = Arc::new(Notify::new());
        let second_may_prepare = Arc::new(Notify::new());
        let second_resolved = Arc::new(Notify::new());
        let events = Arc::new(Mutex::new(Vec::new()));
        let local = tokio::task::LocalSet::new();

        local
            .run_until(async {
                let first = {
                    let coordinator = Arc::clone(&coordinator);
                    let first_committed = Arc::clone(&first_committed);
                    let events = Arc::clone(&events);
                    let first_project = first_project.clone();
                    let project_state = Arc::clone(&project_state);
                    tokio::task::spawn_local(async move {
                        super::super::workspace_project_state::scope(
                            project_state,
                            0,
                            scope(coordinator, 0, async {
                                events.lock().unwrap().push("first-resolved");
                                finish_resolution();
                                events.lock().unwrap().push("first-prepared");
                                super::super::workspace_project_state::enter(&first_project)
                                    .unwrap();
                                enter_commit();
                                events.lock().unwrap().push("first-commit");
                                first_committed.notify_one();
                                Ok::<_, ()>(())
                            }),
                        )
                        .await
                    })
                };
                let second = {
                    let coordinator = Arc::clone(&coordinator);
                    let second_may_prepare = Arc::clone(&second_may_prepare);
                    let second_resolved = Arc::clone(&second_resolved);
                    let events = Arc::clone(&events);
                    let second_project = second_project.clone();
                    let project_state = Arc::clone(&project_state);
                    tokio::task::spawn_local(async move {
                        super::super::workspace_project_state::scope(
                            project_state,
                            1,
                            scope(coordinator, 1, async {
                                events.lock().unwrap().push("second-resolved");
                                second_resolved.notify_one();
                                second_may_prepare.notified().await;
                                finish_resolution();
                                events.lock().unwrap().push("second-prepared");
                                super::super::workspace_project_state::enter(&second_project)
                                    .unwrap();
                                enter_commit();
                                events.lock().unwrap().push("second-commit");
                                Ok::<_, ()>(())
                            }),
                        )
                        .await
                    })
                };

                second_resolved.notified().await;
                tokio::time::timeout(
                    std::time::Duration::from_millis(100),
                    first_committed.notified(),
                )
                .await
                .expect("the first importer must enter commit independently");
                second_may_prepare.notify_one();
                first.await.unwrap().unwrap();
                second.await.unwrap().unwrap();
            })
            .await;

        let events = events.lock().unwrap();
        let first_commit = events
            .iter()
            .position(|event| *event == "first-commit")
            .unwrap();
        let second_prepare = events
            .iter()
            .position(|event| *event == "second-prepared")
            .unwrap();
        assert!(
            first_commit < second_prepare,
            "the first importer must commit before the second is allowed to prepare: {events:?}"
        );
        project_state.commit();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn later_importer_materialization_waits_for_its_predecessor() {
        let projects = tempfile::tempdir().unwrap();
        let first_project = projects.path().join("first");
        let second_project = projects.path().join("second");
        for project in [&first_project, &second_project] {
            std::fs::create_dir_all(project).unwrap();
            std::fs::write(project.join("package.json"), b"{}").unwrap();
        }
        let coordinator = Arc::new(WorkspaceResolutionCoordinator::new(2, 2));
        let project_state = Arc::new(
            super::super::workspace_project_state::WorkspaceProjectStateCoordinator::new(2),
        );
        let first_may_finish_materialization = Arc::new(Notify::new());
        let second_started_waiting = Arc::new(Notify::new());
        let events = Arc::new(Mutex::new(Vec::new()));
        let local = tokio::task::LocalSet::new();

        local
            .run_until(async {
                let first = {
                    let coordinator = Arc::clone(&coordinator);
                    let first_may_finish_materialization =
                        Arc::clone(&first_may_finish_materialization);
                    let events = Arc::clone(&events);
                    let first_project = first_project.clone();
                    let project_state = Arc::clone(&project_state);
                    tokio::task::spawn_local(async move {
                        super::super::workspace_project_state::scope(
                            project_state,
                            0,
                            scope(coordinator, 0, async {
                                finish_resolution();
                                wait_for_materialization().await;
                                events.lock().unwrap().push("first-materializing");
                                first_may_finish_materialization.notified().await;
                                super::super::workspace_project_state::enter(&first_project)
                                    .unwrap();
                                enter_commit();
                                events.lock().unwrap().push("first-commit");
                                Ok::<_, ()>(())
                            }),
                        )
                        .await
                    })
                };
                let second = {
                    let coordinator = Arc::clone(&coordinator);
                    let second_started_waiting = Arc::clone(&second_started_waiting);
                    let events = Arc::clone(&events);
                    let second_project = second_project.clone();
                    let project_state = Arc::clone(&project_state);
                    tokio::task::spawn_local(async move {
                        super::super::workspace_project_state::scope(
                            project_state,
                            1,
                            scope(coordinator, 1, async {
                                finish_resolution();
                                second_started_waiting.notify_one();
                                wait_for_materialization().await;
                                events.lock().unwrap().push("second-materializing");
                                super::super::workspace_project_state::enter(&second_project)
                                    .unwrap();
                                enter_commit();
                                events.lock().unwrap().push("second-commit");
                                Ok::<_, ()>(())
                            }),
                        )
                        .await
                    })
                };

                second_started_waiting.notified().await;
                tokio::task::yield_now().await;
                assert_eq!(*events.lock().unwrap(), vec!["first-materializing"]);
                first_may_finish_materialization.notify_one();
                first.await.unwrap().unwrap();
                second.await.unwrap().unwrap();
            })
            .await;

        assert_eq!(
            *events.lock().unwrap(),
            vec![
                "first-materializing",
                "first-commit",
                "second-materializing",
                "second-commit"
            ]
        );
        project_state.commit();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn preparation_failure_rolls_back_an_importer_that_entered_commit() {
        let projects = tempfile::tempdir().unwrap();
        let first_project = projects.path().join("first");
        std::fs::create_dir_all(first_project.join("node_modules/old-package")).unwrap();
        std::fs::write(first_project.join("package.json"), b"{}").unwrap();
        let coordinator = Arc::new(WorkspaceResolutionCoordinator::new(2, 2));
        let project_state = Arc::new(
            super::super::workspace_project_state::WorkspaceProjectStateCoordinator::new(2),
        );
        let second_failed = Arc::new(Notify::new());
        let local = tokio::task::LocalSet::new();

        local
            .run_until(async {
                let first = {
                    let coordinator = Arc::clone(&coordinator);
                    let first_project = first_project.clone();
                    let project_state = Arc::clone(&project_state);
                    tokio::task::spawn_local(async move {
                        super::super::workspace_project_state::scope(
                            project_state,
                            0,
                            scope(coordinator, 0, async {
                                finish_resolution();
                                super::super::workspace_project_state::enter(&first_project)
                                    .unwrap();
                                enter_commit();
                                std::fs::create_dir_all(
                                    first_project.join("node_modules/new-package"),
                                )
                                .unwrap();
                                Ok::<_, &'static str>(())
                            }),
                        )
                        .await
                    })
                };
                let second = {
                    let coordinator = Arc::clone(&coordinator);
                    let second_failed = Arc::clone(&second_failed);
                    let project_state = Arc::clone(&project_state);
                    tokio::task::spawn_local(async move {
                        let result = super::super::workspace_project_state::scope(
                            project_state,
                            1,
                            scope(coordinator, 1, async { Err::<(), _>("resolve failed") }),
                        )
                        .await;
                        second_failed.notify_one();
                        result
                    })
                };

                second_failed.notified().await;
                assert_eq!(second.await.unwrap(), Err("resolve failed"));
                first.await.unwrap().unwrap();
            })
            .await;

        assert!(project_state.rollback().is_empty());
        assert!(first_project.join("node_modules/old-package").is_dir());
        assert!(!first_project.join("node_modules/new-package").exists());
    }
}
