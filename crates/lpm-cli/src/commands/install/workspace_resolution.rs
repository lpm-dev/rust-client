use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};

use sha2::{Digest, Sha256};
use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore};

use super::{InstallPackage, LpmError, PeerWarning, install_pkg_key};

pub(super) struct WorkspaceResolutionCoordinator {
    resolution_permits: Arc<Semaphore>,
    release_age_reference_unix: i64,
    materialized: Box<[TargetCompletion]>,
    completed: Box<[TargetCompletion]>,
    prepared_count: std::sync::atomic::AtomicUsize,
    all_prepared: Notify,
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
            materialized: (0..target_count)
                .map(|_| TargetCompletion::default())
                .collect(),
            completed: (0..target_count)
                .map(|_| TargetCompletion::default())
                .collect(),
            prepared_count: std::sync::atomic::AtomicUsize::new(0),
            all_prepared: Notify::new(),
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
        Arc::clone(
            self.fetch_overlap_hub
                .get_or_init(|| Arc::new(super::fetch_overlap::WorkspaceFetchOverlapHub::new())),
        )
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
    Isolated,
    Failed(lpm_resolver::ResolveError),
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

    async fn wait_until_all_prepared(&self) {
        let notified = self.coordinator.all_prepared.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        let prepared = self
            .coordinator
            .prepared_count
            .fetch_add(1, std::sync::atomic::Ordering::AcqRel)
            .saturating_add(1);
        if prepared == self.coordinator.completed.len() {
            self.coordinator.all_prepared.notify_waiters();
            return;
        }
        while self
            .coordinator
            .prepared_count
            .load(std::sync::atomic::Ordering::Acquire)
            < self.coordinator.completed.len()
        {
            notified.as_mut().await;
            notified.set(self.coordinator.all_prepared.notified());
            notified.as_mut().enable();
        }
    }

    async fn enter_commit(&self) -> u128 {
        if self
            .commit_entered
            .swap(true, std::sync::atomic::Ordering::AcqRel)
        {
            return 0;
        }

        self.finish_resolution();
        self.coordinator.materialized[self.index].finish();
        let wait_started = std::time::Instant::now();
        self.wait_until_all_prepared().await;
        if let Some(previous) = self.index.checked_sub(1) {
            self.coordinator.completed[previous].wait().await;
        }
        wait_started.elapsed().as_millis()
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
    if result.is_ok() {
        task.enter_commit().await;
        coordinator.completed[index].finish();
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
) -> Result<Option<lpm_resolver::ResolveResult>, LpmError> {
    let Ok(task) = ACTIVE_TASK.try_with(Arc::clone) else {
        return Ok(None);
    };
    let Some(union) = task.coordinator.union.as_ref() else {
        return Ok(None);
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
    if submitted == task.coordinator.completed.len() {
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
        WorkspaceUnionResult::Projected(result) => Ok(Some(*result)),
        WorkspaceUnionResult::Isolated => Ok(None),
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
            .unwrap_or_else(std::sync::PoisonError::into_inner) = (0..coordinator.completed.len())
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
        .map(|_| Some(WorkspaceUnionResult::Isolated))
        .collect::<Vec<_>>();
    for indices in groups {
        if indices.len() < 2 {
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
            Ok(lpm_resolver::WorkspaceResolveOutcome::Projected(projected)) => {
                let projected_count = projected.iter().filter(|result| result.is_some()).count();
                tracing::debug!(
                    importers = projected.len(),
                    projected = projected_count,
                    "workspace union resolution completed"
                );
                for (index, projection) in indices.into_iter().zip(projected) {
                    if let Some(projection) = projection {
                        results[index] =
                            Some(WorkspaceUnionResult::Projected(Box::new(projection)));
                    }
                }
            }
            Ok(lpm_resolver::WorkspaceResolveOutcome::RequiresIsolatedResolution) => {}
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
) -> Result<Option<String>, LpmError> {
    if let Ok(task) = ACTIVE_TASK.try_with(Arc::clone) {
        if task.is_root() {
            task.coordinator
                .publish_root_providers(RootProviderSnapshot::new(
                    project_dir,
                    packages.clone(),
                    ephemeral_workspace_packages,
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
        ));
        return Ok(None);
    }
    let snapshot = task.coordinator.wait().await?;
    let used_root_provider = snapshot.reconcile(project_dir, packages, peer_warnings);
    Ok(used_root_provider.then(|| snapshot.fingerprint.to_string()))
}

pub(super) fn publish_root_peer_providers_for_empty_install(project_dir: &Path) {
    if let Ok(task) = ACTIVE_TASK.try_with(Arc::clone) {
        if task.is_root() {
            task.coordinator
                .publish_root_providers(RootProviderSnapshot::new(project_dir, Vec::new(), &[]));
        }
        return;
    }

    if let Ok(task) = ACTIVE_ROOT_PROVIDER_TASK.try_with(Arc::clone)
        && task.is_root
    {
        task.coordinator
            .publish(RootProviderSnapshot::new(project_dir, Vec::new(), &[]));
    }
}

pub(super) fn root_provider_fingerprint_from_projection(
    root_dir: &Path,
    lockfile: &lpm_lockfile::Lockfile,
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
    Some(root_provider_fingerprint(&manifest, &direct, &rows, &local))
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
        packages: Vec<InstallPackage>,
        workspace_packages: &[InstallPackage],
    ) -> Self {
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
        let rows = lockfile
            .packages
            .iter()
            .map(FingerprintPackage::from_locked)
            .collect::<Vec<_>>();
        let local = local_provider_fingerprints(root_dir, workspace_packages);
        let manifest = root_manifest_bytes(root_dir);
        let fingerprint = root_provider_fingerprint(&manifest, &direct, &rows, &local);
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
        let Ok(range) = lpm_resolver::NpmRange::parse(&warning.required_range) else {
            return false;
        };
        let Some(provider_index) = self
            .direct_by_name
            .get(&warning.peer)
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
        if !packages
            .iter()
            .any(|package| package.name == warning.package && package.version == warning.version)
        {
            return false;
        }

        let closure = self.provider_closure(provider_index);
        let mut imports = Vec::with_capacity(closure.len());
        for index in closure {
            let mut imported = self.packages[index].clone();
            imported.source = rebase_local_source(&imported.source, &self.root_dir, project_dir);
            if !package_can_be_imported(packages, &imported) {
                return false;
            }
            imports.push(imported);
        }

        for mut imported in imports {
            if packages
                .iter()
                .any(|package| install_pkg_key(package) == install_pkg_key(&imported))
            {
                continue;
            }
            imported.is_direct = false;
            imported.root_link_names = None;
            packages.push(imported);
        }

        let provider_version = self.packages[provider_index].version.clone();
        for consumer in packages
            .iter_mut()
            .filter(|package| package.name == warning.package && package.version == warning.version)
        {
            if let Some((_, version)) = consumer
                .peers
                .iter_mut()
                .find(|(name, _)| name == &warning.peer)
            {
                *version = provider_version.clone();
            } else {
                consumer
                    .peers
                    .push((warning.peer.clone(), provider_version.clone()));
                consumer
                    .peers
                    .sort_unstable_by(|left, right| left.0.cmp(&right.0));
            }
        }
        true
    }

    fn provider_closure(&self, provider_index: usize) -> Vec<usize> {
        let mut by_name_version = HashMap::<(&str, &str), Vec<usize>>::new();
        for (index, package) in self.packages.iter().enumerate() {
            by_name_version
                .entry((&package.name, &package.version))
                .or_default()
                .push(index);
        }
        let mut seen = HashSet::new();
        let mut queue = VecDeque::from([provider_index]);
        while let Some(index) = queue.pop_front() {
            if !seen.insert(index) {
                continue;
            }
            let package = &self.packages[index];
            for (local_name, version) in package.dependencies.iter().chain(&package.peers) {
                let target = package
                    .aliases
                    .get(local_name)
                    .map_or(local_name, |name| name);
                if let Some(children) = by_name_version.get(&(target.as_str(), version.as_str())) {
                    queue.extend(children.iter().copied());
                }
            }
        }
        let mut closure = seen.into_iter().collect::<Vec<_>>();
        closure.sort_unstable();
        closure
    }
}

fn root_workspace_install_packages(
    root_dir: &Path,
    package: &lpm_workspace::PackageJson,
) -> Option<Vec<InstallPackage>> {
    let mut deps = super::manifest_install_deps(package);
    let context =
        super::prepare_workspace_install_context(root_dir, package, &mut deps, true, true).ok()?;
    super::pre_resolve_v2_direct_workspace_member_deps(
        root_dir,
        &mut deps,
        &context.direct_workspace_member_deps,
        &context.all_workspace_members,
        true,
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
    peers: Vec<String>,
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
        let mut peers = package.peers.clone();
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
) -> String {
    let mut hasher = Sha256::new();
    hash_bytes(&mut hasher, b"lpm-workspace-root-peer-providers-v2");
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
            hash_bytes(&mut hasher, peer.as_bytes());
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

pub(super) async fn wait_for_commit() -> u128 {
    if let Ok(task) = ACTIVE_TASK.try_with(Arc::clone) {
        task.enter_commit().await
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    fn workspace_union_request() -> WorkspaceUnionRequest {
        WorkspaceUnionRequest {
            client: Arc::new(lpm_registry::RegistryClient::new().with_cache_dir(None)),
            root_dependencies: lpm_resolver::RootDependencies::required(HashMap::new()),
            overrides: lpm_resolver::OverrideSet::empty(),
            route_table: lpm_registry::RouteTable::from_mode_only(lpm_registry::RouteMode::Direct),
            npm_fanout: 8,
            shared_cache: Arc::new(dashmap::DashMap::new()),
            auto_install_peers: true,
            include_optional_dependencies: true,
            policy: lpm_resolver::ResolverPolicy::default(),
        }
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
            root_provider_fingerprint_from_projection(directory.path(), &lockfile)
        });

        assert_eq!(fingerprint, None);
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
    async fn direct_workspace_importers_share_only_the_base_fact_cache() {
        let route_table = lpm_registry::RouteTable::from_mode_only(lpm_registry::RouteMode::Direct);
        let (first, second) = fact_caches_for_resolution_importers(route_table).await;
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
    async fn every_importer_prepares_before_the_first_commit() {
        let coordinator = Arc::new(WorkspaceResolutionCoordinator::new(2, 1));
        let first_may_finish = Arc::new(Notify::new());
        let second_may_prepare = Arc::new(Notify::new());
        let second_resolved = Arc::new(Notify::new());
        let events = Arc::new(Mutex::new(Vec::new()));
        let local = tokio::task::LocalSet::new();

        local
            .run_until(async {
                let first = {
                    let coordinator = Arc::clone(&coordinator);
                    let first_may_finish = Arc::clone(&first_may_finish);
                    let events = Arc::clone(&events);
                    tokio::task::spawn_local(async move {
                        scope(coordinator, 0, async {
                            events.lock().unwrap().push("first-resolved");
                            finish_resolution();
                            events.lock().unwrap().push("first-prepared");
                            wait_for_commit().await;
                            events.lock().unwrap().push("first-commit");
                            first_may_finish.notified().await;
                            Ok::<_, ()>(())
                        })
                        .await
                    })
                };
                let second = {
                    let coordinator = Arc::clone(&coordinator);
                    let second_may_prepare = Arc::clone(&second_may_prepare);
                    let second_resolved = Arc::clone(&second_resolved);
                    let events = Arc::clone(&events);
                    tokio::task::spawn_local(async move {
                        scope(coordinator, 1, async {
                            events.lock().unwrap().push("second-resolved");
                            second_resolved.notify_one();
                            second_may_prepare.notified().await;
                            finish_resolution();
                            events.lock().unwrap().push("second-prepared");
                            wait_for_commit().await;
                            events.lock().unwrap().push("second-commit");
                            Ok::<_, ()>(())
                        })
                        .await
                    })
                };

                second_resolved.notified().await;
                assert_eq!(
                    *events.lock().unwrap(),
                    vec!["first-resolved", "first-prepared", "second-resolved"]
                );
                second_may_prepare.notify_one();
                tokio::task::yield_now().await;
                assert_eq!(
                    *events.lock().unwrap(),
                    vec![
                        "first-resolved",
                        "first-prepared",
                        "second-resolved",
                        "second-prepared",
                        "first-commit"
                    ]
                );
                first_may_finish.notify_one();
                first.await.unwrap().unwrap();
                second.await.unwrap().unwrap();
            })
            .await;

        assert_eq!(
            *events.lock().unwrap(),
            vec![
                "first-resolved",
                "first-prepared",
                "second-resolved",
                "second-prepared",
                "first-commit",
                "second-commit"
            ]
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn later_importer_materialization_waits_for_its_predecessor() {
        let coordinator = Arc::new(WorkspaceResolutionCoordinator::new(2, 2));
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
                    tokio::task::spawn_local(async move {
                        scope(coordinator, 0, async {
                            finish_resolution();
                            wait_for_materialization().await;
                            events.lock().unwrap().push("first-materializing");
                            first_may_finish_materialization.notified().await;
                            wait_for_commit().await;
                            events.lock().unwrap().push("first-commit");
                            Ok::<_, ()>(())
                        })
                        .await
                    })
                };
                let second = {
                    let coordinator = Arc::clone(&coordinator);
                    let second_started_waiting = Arc::clone(&second_started_waiting);
                    let events = Arc::clone(&events);
                    tokio::task::spawn_local(async move {
                        scope(coordinator, 1, async {
                            finish_resolution();
                            second_started_waiting.notify_one();
                            wait_for_materialization().await;
                            events.lock().unwrap().push("second-materializing");
                            wait_for_commit().await;
                            events.lock().unwrap().push("second-commit");
                            Ok::<_, ()>(())
                        })
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
                "second-materializing",
                "first-commit",
                "second-commit"
            ]
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn preparation_failure_returns_without_releasing_a_commit() {
        let coordinator = Arc::new(WorkspaceResolutionCoordinator::new(2, 2));
        let second_failed = Arc::new(Notify::new());
        let second_returned = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let first_committed = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let local = tokio::task::LocalSet::new();

        local
            .run_until(async {
                let first = {
                    let coordinator = Arc::clone(&coordinator);
                    let first_committed = Arc::clone(&first_committed);
                    tokio::task::spawn_local(async move {
                        scope(coordinator, 0, async {
                            finish_resolution();
                            wait_for_commit().await;
                            first_committed.store(true, std::sync::atomic::Ordering::Release);
                            Ok::<_, &'static str>(())
                        })
                        .await
                    })
                };
                let second = {
                    let coordinator = Arc::clone(&coordinator);
                    let second_failed = Arc::clone(&second_failed);
                    let second_returned = Arc::clone(&second_returned);
                    tokio::task::spawn_local(async move {
                        let result =
                            scope(coordinator, 1, async { Err::<(), _>("resolve failed") }).await;
                        second_returned.store(true, std::sync::atomic::Ordering::Release);
                        second_failed.notify_one();
                        result
                    })
                };

                second_failed.notified().await;
                assert!(second_returned.load(std::sync::atomic::Ordering::Acquire));
                assert!(!first_committed.load(std::sync::atomic::Ordering::Acquire));
                assert_eq!(second.await.unwrap(), Err("resolve failed"));
                first.abort();
                assert!(first.await.unwrap_err().is_cancelled());
            })
            .await;
    }
}
