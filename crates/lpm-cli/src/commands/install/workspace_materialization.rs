use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::hash::Hash;
use std::sync::Mutex as StdMutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};

use futures::StreamExt;
use lpm_common::LpmError;
use tokio::sync::{Mutex, Notify, OnceCell, Semaphore};

#[derive(Debug)]
pub(super) struct Coordinated<T> {
    pub(super) value: T,
    pub(super) performed: bool,
}

type SharedOperation<T, E> = Arc<OnceCell<Result<T, E>>>;

pub(super) struct SingleFlight<K, T, E> {
    entries: Mutex<HashMap<K, SharedOperation<T, E>>>,
}

impl<K, T, E> Default for SingleFlight<K, T, E> {
    fn default() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
        }
    }
}

impl<K, T, E> SingleFlight<K, T, E>
where
    K: Eq + Hash,
    T: Clone,
    E: Clone,
{
    pub(super) async fn run<F, Fut>(&self, key: K, operation: F) -> Result<Coordinated<T>, E>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<T, E>>,
    {
        let cell = {
            let mut entries = self.entries.lock().await;
            Arc::clone(
                entries
                    .entry(key)
                    .or_insert_with(|| Arc::new(OnceCell::new())),
            )
        };
        let performed = AtomicBool::new(false);
        let performed_by_this_request = &performed;
        let result = cell
            .get_or_init(|| async move {
                performed_by_this_request.store(true, Ordering::Relaxed);
                operation().await
            })
            .await
            .clone();
        result.map(|value| Coordinated {
            value,
            performed: performed.load(Ordering::Relaxed),
        })
    }
}

#[derive(Clone, Debug)]
enum SharedMaterializationError {
    Store(Arc<str>),
    Registry(Arc<str>),
    InvalidIntegrity(Arc<str>),
    IntegrityMismatch {
        expected: Arc<str>,
        actual: Arc<str>,
    },
}

impl From<LpmError> for SharedMaterializationError {
    fn from(error: LpmError) -> Self {
        match error {
            LpmError::Store(message) => Self::Store(Arc::from(message)),
            LpmError::Registry(message) => Self::Registry(Arc::from(message)),
            LpmError::InvalidIntegrity(message) => Self::InvalidIntegrity(Arc::from(message)),
            LpmError::IntegrityMismatch { expected, actual } => Self::IntegrityMismatch {
                expected: Arc::from(expected),
                actual: Arc::from(actual),
            },
            error => Self::Store(Arc::from(error.to_string())),
        }
    }
}

impl From<SharedMaterializationError> for LpmError {
    fn from(error: SharedMaterializationError) -> Self {
        match error {
            SharedMaterializationError::Store(message) => LpmError::Store(message.to_string()),
            SharedMaterializationError::Registry(message) => {
                LpmError::Registry(message.to_string())
            }
            SharedMaterializationError::InvalidIntegrity(message) => {
                LpmError::InvalidIntegrity(message.to_string())
            }
            SharedMaterializationError::IntegrityMismatch { expected, actual } => {
                LpmError::IntegrityMismatch {
                    expected: expected.to_string(),
                    actual: actual.to_string(),
                }
            }
        }
    }
}

#[derive(Clone)]
pub(super) struct ObjectValidation {
    pub(super) reusable: Option<lpm_store::v2::ReusableObject>,
    pub(super) timings: lpm_store::v2::ReusableObjectCheckTimings,
}

#[derive(Clone)]
pub(super) struct ObjectValidationSnapshot {
    results: Arc<dashmap::DashMap<String, ObjectValidation>>,
    pub(super) performed_count: usize,
    pub(super) performed_hit_count: usize,
    pub(super) concurrency: usize,
    pub(super) timings: super::V2ReusableValidationTimings,
}

impl ObjectValidationSnapshot {
    pub(super) fn reusable(&self, source_sri: &str) -> Option<lpm_store::v2::ReusableObject> {
        self.results
            .get(source_sri)
            .and_then(|validation| validation.reusable.clone())
    }

    fn without_performed_work(mut self) -> Self {
        self.performed_count = 0;
        self.performed_hit_count = 0;
        self.concurrency = 0;
        self.timings = super::V2ReusableValidationTimings::default();
        self
    }
}

#[derive(Clone)]
pub(super) struct LinkMaterialization {
    pub(super) materialized: lpm_linker::MaterializedPackage,
    pub(super) freshly_populated: bool,
    pub(super) ms: u128,
    pub(super) timings: lpm_store::v2::LinkEntryTimings,
}

#[derive(Clone, Eq, Hash, PartialEq)]
struct LinkMaterializationKey {
    graph_key: Arc<lpm_store::v2::GraphKey>,
}

#[derive(Clone, Eq, Hash, PartialEq)]
struct LocalSourcePopulationKey {
    source_dir: std::path::PathBuf,
    source_sri: String,
}

struct RetainedOperation<T> {
    result: StdMutex<Option<Result<T, SharedMaterializationError>>>,
    ready: Notify,
}

impl<T> Default for RetainedOperation<T> {
    fn default() -> Self {
        Self {
            result: StdMutex::new(None),
            ready: Notify::new(),
        }
    }
}

impl<T: Clone> RetainedOperation<T> {
    fn complete(&self, result: Result<T, SharedMaterializationError>) {
        *self
            .result
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(result);
        self.ready.notify_waiters();
    }

    async fn wait(&self) -> Result<T, SharedMaterializationError> {
        loop {
            if let Some(result) = self
                .result
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone()
            {
                return result;
            }
            let notified = self.ready.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self
                .result
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .is_some()
            {
                continue;
            }
            notified.await;
        }
    }
}

struct UnionObjectValidationOperation {
    result: RetainedOperation<ObjectValidationSnapshot>,
    telemetry_claimed: AtomicBool,
}

impl Default for UnionObjectValidationOperation {
    fn default() -> Self {
        Self {
            result: RetainedOperation::default(),
            telemetry_claimed: AtomicBool::new(false),
        }
    }
}

pub(super) struct WorkspaceLinkHandle {
    operation: Arc<RetainedOperation<LinkMaterialization>>,
    performed: bool,
}

impl WorkspaceLinkHandle {
    pub(super) fn performed(&self) -> bool {
        self.performed
    }

    pub(super) async fn wait(self) -> Result<Coordinated<LinkMaterialization>, LpmError> {
        self.operation
            .wait()
            .await
            .map(|value| Coordinated {
                value,
                performed: self.performed,
            })
            .map_err(LpmError::from)
    }
}

pub(super) struct WorkspaceMaterializationCoordinator {
    unshared_local_source_roots: Box<[std::path::PathBuf]>,
    fetch_semaphore: Arc<Semaphore>,
    fetch_extract_limiter: super::FetchExtractLimiter,
    limit_v1_extraction: bool,
    v2_link_task_semaphore: Arc<Semaphore>,
    graph_key_cache: lpm_linker::v2::GraphKeyCache,
    object_validation_permits: Arc<Semaphore>,
    object_validation_results: Arc<dashmap::DashMap<String, ObjectValidation>>,
    object_validations_in_flight: Mutex<HashSet<String>>,
    object_validations_ready: Notify,
    object_validation_batch: OnceLock<lpm_store::v2::ReusableObjectValidationBatch>,
    union_object_candidates: OnceLock<Arc<HashSet<String>>>,
    union_object_validation: OnceLock<Arc<UnionObjectValidationOperation>>,
    local_source_populations:
        SingleFlight<LocalSourcePopulationKey, std::path::PathBuf, SharedMaterializationError>,
    link_materializations:
        StdMutex<HashMap<LinkMaterializationKey, Arc<RetainedOperation<LinkMaterialization>>>>,
}

impl Default for WorkspaceMaterializationCoordinator {
    fn default() -> Self {
        Self::new(Vec::new())
    }
}

impl WorkspaceMaterializationCoordinator {
    pub(super) fn new(unshared_local_source_roots: Vec<std::path::PathBuf>) -> Self {
        let limit_v1_extraction = super::configured_fetch_extract_permits_from_env(false).is_some();
        let fetch_extract_limiter = super::configured_fetch_extract_permits_from_env(true)
            .map(Semaphore::new)
            .map(Arc::new);
        Self {
            unshared_local_source_roots: unshared_local_source_roots.into_boxed_slice(),
            fetch_semaphore: Arc::new(Semaphore::new(super::max_concurrent_downloads())),
            fetch_extract_limiter,
            limit_v1_extraction,
            v2_link_task_semaphore: Arc::new(Semaphore::new(super::v2_link_task_concurrency(
                Semaphore::MAX_PERMITS,
            ))),
            graph_key_cache: lpm_linker::v2::GraphKeyCache::default(),
            object_validation_permits: Arc::new(Semaphore::new(
                super::concurrency::V2_CACHE_CHECK_MAX_CONCURRENCY,
            )),
            object_validation_results: Arc::new(dashmap::DashMap::new()),
            object_validations_in_flight: Mutex::new(HashSet::new()),
            object_validations_ready: Notify::new(),
            object_validation_batch: OnceLock::new(),
            union_object_candidates: OnceLock::new(),
            union_object_validation: OnceLock::new(),
            local_source_populations: SingleFlight::default(),
            link_materializations: StdMutex::new(HashMap::new()),
        }
    }

    pub(super) fn fetch_semaphore(&self) -> Arc<Semaphore> {
        Arc::clone(&self.fetch_semaphore)
    }

    pub(super) fn fetch_extract_limiter(
        &self,
        v2_store_active: bool,
    ) -> super::FetchExtractLimiter {
        if v2_store_active || self.limit_v1_extraction {
            self.fetch_extract_limiter.clone()
        } else {
            None
        }
    }

    pub(super) fn v2_link_task_semaphore(&self) -> Arc<Semaphore> {
        Arc::clone(&self.v2_link_task_semaphore)
    }

    pub(super) fn graph_key_cache(&self) -> &lpm_linker::v2::GraphKeyCache {
        &self.graph_key_cache
    }

    pub(super) fn publish_union_object_candidates(
        &self,
        source_sris: impl IntoIterator<Item = String>,
    ) {
        let source_sris: HashSet<String> = source_sris.into_iter().collect();
        if !source_sris.is_empty() {
            let _ = self.union_object_candidates.set(Arc::new(source_sris));
        }
    }

    pub(super) fn start_union_object_validation(
        self: &Arc<Self>,
        store: Arc<lpm_store::v2::Store>,
    ) {
        let Some(source_sris) = self.union_object_candidates.get().map(Arc::clone) else {
            return;
        };
        let operation = Arc::new(UnionObjectValidationOperation::default());
        if self
            .union_object_validation
            .set(Arc::clone(&operation))
            .is_err()
        {
            return;
        }
        let coordinator = Arc::clone(self);
        tokio::spawn(async move {
            let result = coordinator
                .validate_object_set(&source_sris, store)
                .await
                .map_err(SharedMaterializationError::from);
            operation.result.complete(result);
        });
    }

    pub(super) async fn populate_local_source(
        &self,
        source_dir: std::path::PathBuf,
        source_sri: String,
        store: Arc<lpm_store::v2::Store>,
    ) -> Result<Coordinated<std::path::PathBuf>, LpmError> {
        if self
            .unshared_local_source_roots
            .iter()
            .any(|root| source_dir.starts_with(root))
        {
            let validation_sri = source_sri.clone();
            let object_dir = tokio::task::spawn_blocking(move || {
                store.populate_object_from_local_source(&source_dir, &source_sri)
            })
            .await
            .map_err(|error| {
                LpmError::Registry(format!("virtual-store local-source task panicked: {error}"))
            })??;
            self.object_validation_results.remove(&validation_sri);
            return Ok(Coordinated {
                value: object_dir,
                performed: true,
            });
        }

        let key = LocalSourcePopulationKey {
            source_dir,
            source_sri,
        };
        let validation_sri = key.source_sri.clone();
        let operation_key = key.clone();
        let result = self
            .local_source_populations
            .run(key, || async move {
                tokio::task::spawn_blocking(move || {
                    store.populate_object_from_local_source(
                        &operation_key.source_dir,
                        &operation_key.source_sri,
                    )
                })
                .await
                .map_err(|error| {
                    SharedMaterializationError::Registry(Arc::from(format!(
                        "virtual-store local-source task panicked: {error}"
                    )))
                })?
                .map_err(SharedMaterializationError::from)
            })
            .await
            .map_err(LpmError::from);
        if result.is_ok() {
            self.object_validation_results.remove(&validation_sri);
        }
        result
    }

    pub(super) async fn validate_objects(
        &self,
        source_sris: &[&str],
        store: Arc<lpm_store::v2::Store>,
    ) -> Result<ObjectValidationSnapshot, LpmError> {
        if let (Some(candidates), Some(operation)) = (
            self.union_object_candidates.get(),
            self.union_object_validation.get(),
        ) && source_sris
            .iter()
            .all(|source_sri| candidates.contains(*source_sri))
        {
            let snapshot = operation.result.wait().await.map_err(LpmError::from)?;
            if operation.telemetry_claimed.swap(true, Ordering::AcqRel) {
                return Ok(snapshot.without_performed_work());
            }
            return Ok(snapshot);
        }

        let requested: HashSet<String> = source_sris
            .iter()
            .map(|source_sri| (*source_sri).to_string())
            .collect();
        self.validate_object_set(&requested, store).await
    }

    async fn validate_object_set(
        &self,
        requested: &HashSet<String>,
        store: Arc<lpm_store::v2::Store>,
    ) -> Result<ObjectValidationSnapshot, LpmError> {
        let mut performed_count = 0usize;
        let mut performed_hit_count = 0usize;
        let mut max_concurrency = 0usize;
        let mut timings = super::V2ReusableValidationTimings::default();
        let validation_batch = self
            .object_validation_batch
            .get_or_init(|| store.reusable_object_validation_batch())
            .clone();

        loop {
            let notified = self.object_validations_ready.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            let mut in_flight = self.object_validations_in_flight.lock().await;
            let mut claimed = Vec::new();
            let mut waiting = false;
            for source_sri in requested {
                if self.object_validation_results.contains_key(source_sri) {
                    continue;
                }
                if in_flight.contains(source_sri) {
                    waiting = true;
                } else {
                    let source_sri = source_sri.clone();
                    in_flight.insert(source_sri.clone());
                    claimed.push(source_sri);
                }
            }
            drop(in_flight);

            if !claimed.is_empty() {
                let concurrency = self.object_validation_concurrency(claimed.len());
                max_concurrency = max_concurrency.max(concurrency);
                let permits = Arc::clone(&self.object_validation_permits);
                let check_source_sris = claimed.clone();
                let mut checks =
                    futures::stream::iter(check_source_sris.into_iter().map(|source_sri| {
                        let permits = Arc::clone(&permits);
                        let store = Arc::clone(&store);
                        let validation_batch = validation_batch.clone();
                        async move {
                            let _permit = permits.acquire_owned().await.map_err(|_| {
                                LpmError::Registry(
                                    "virtual-store object validation semaphore closed".into(),
                                )
                            })?;
                            tokio::task::spawn_blocking(move || {
                                store
                                    .reusable_object_with_timings_in_batch(
                                        &source_sri,
                                        &validation_batch,
                                    )
                                    .map(|(reusable, timings)| {
                                        (source_sri, ObjectValidation { reusable, timings })
                                    })
                            })
                            .await
                            .map_err(|error| {
                                LpmError::Registry(format!(
                                    "virtual-store cache check task panicked: {error}"
                                ))
                            })?
                        }
                    }))
                    .buffer_unordered(concurrency);

                let mut completed = Vec::with_capacity(claimed.len());
                while let Some(result) = checks.next().await {
                    match result {
                        Ok(result) => completed.push(result),
                        Err(error) => {
                            let mut in_flight = self.object_validations_in_flight.lock().await;
                            for source_sri in &claimed {
                                in_flight.remove(source_sri);
                            }
                            drop(in_flight);
                            self.object_validations_ready.notify_waiters();
                            return Err(error);
                        }
                    }
                }

                performed_count = performed_count.saturating_add(completed.len());
                let mut in_flight = self.object_validations_in_flight.lock().await;
                for (source_sri, validation) in completed {
                    let hit = validation.reusable.is_some();
                    timings.record(validation.timings, hit);
                    performed_hit_count = performed_hit_count.saturating_add(usize::from(hit));
                    self.object_validation_results
                        .insert(source_sri.clone(), validation);
                    in_flight.remove(&source_sri);
                }
                drop(in_flight);
                self.object_validations_ready.notify_waiters();
                continue;
            }

            if waiting {
                notified.await;
                continue;
            }
            break;
        }

        Ok(ObjectValidationSnapshot {
            results: Arc::clone(&self.object_validation_results),
            performed_count,
            performed_hit_count,
            concurrency: max_concurrency,
            timings,
        })
    }

    #[cfg(test)]
    async fn validate_object(
        &self,
        source_sri: String,
        store: Arc<lpm_store::v2::Store>,
    ) -> Result<Coordinated<ObjectValidation>, LpmError> {
        let snapshot = self.validate_objects(&[source_sri.as_str()], store).await?;
        let value = self
            .object_validation_results
            .get(&source_sri)
            .map(|validation| validation.clone())
            .ok_or_else(|| {
                LpmError::Store(format!(
                    "virtual-store object validation completed without a result for {source_sri}"
                ))
            })?;
        Ok(Coordinated {
            value,
            performed: snapshot.performed_count != 0,
        })
    }

    pub(super) fn object_validation_concurrency(&self, candidate_count: usize) -> usize {
        super::concurrency::V2_CACHE_CHECK_MAX_CONCURRENCY.min(candidate_count.max(1))
    }

    #[cfg(test)]
    async fn materialize_link(
        &self,
        plan: Arc<lpm_linker::v2::LinkPlanV2>,
        target: Arc<lpm_linker::v2::V2Target>,
        store: Arc<lpm_store::v2::Store>,
    ) -> Result<Coordinated<LinkMaterialization>, LpmError> {
        self.dispatch_link(plan, target, store)?.wait().await
    }

    pub(super) fn dispatch_link(
        &self,
        plan: Arc<lpm_linker::v2::LinkPlanV2>,
        target: Arc<lpm_linker::v2::V2Target>,
        store: Arc<lpm_store::v2::Store>,
    ) -> Result<WorkspaceLinkHandle, LpmError> {
        let graph_key = plan.graph_key_for(&target)?;
        let key = LinkMaterializationKey { graph_key };
        let (operation, performed) = {
            let mut materializations = self
                .link_materializations
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            match materializations.entry(key) {
                std::collections::hash_map::Entry::Occupied(entry) => {
                    (Arc::clone(entry.get()), false)
                }
                std::collections::hash_map::Entry::Vacant(entry) => {
                    let operation = Arc::new(RetainedOperation::default());
                    entry.insert(Arc::clone(&operation));
                    (operation, true)
                }
            }
        };
        if performed {
            let task_operation = Arc::clone(&operation);
            let semaphore = Arc::clone(&self.v2_link_task_semaphore);
            tokio::spawn(async move {
                let started = std::time::Instant::now();
                let result = async {
                    let _permit = semaphore.acquire_owned().await.map_err(|_| {
                        SharedMaterializationError::Registry(Arc::from(
                            "virtual-store link semaphore closed",
                        ))
                    })?;
                    tokio::task::spawn_blocking(move || {
                        lpm_linker::v2::link_v2_one_with_timings(&plan, &target, &store).map(
                            |(materialized, freshly_populated, timings)| LinkMaterialization {
                                materialized,
                                freshly_populated,
                                ms: started.elapsed().as_millis(),
                                timings,
                            },
                        )
                    })
                    .await
                    .map_err(|error| {
                        SharedMaterializationError::Registry(Arc::from(format!(
                            "virtual-store link task panicked: {error}"
                        )))
                    })?
                    .map_err(SharedMaterializationError::from)
                }
                .await;
                task_operation.complete(result);
            });
        }
        Ok(WorkspaceLinkHandle {
            operation,
            performed,
        })
    }
}

tokio::task_local! {
    static ACTIVE_COORDINATOR: Arc<WorkspaceMaterializationCoordinator>;
}

pub(super) async fn scope<F>(
    coordinator: Arc<WorkspaceMaterializationCoordinator>,
    future: F,
) -> F::Output
where
    F: Future,
{
    ACTIVE_COORDINATOR.scope(coordinator, future).await
}

pub(super) fn current() -> Option<Arc<WorkspaceMaterializationCoordinator>> {
    ACTIVE_COORDINATOR.try_with(Arc::clone).ok()
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    #[test]
    fn workspace_materialization_coordinator_reuses_resource_pools() {
        let _env = crate::test_env::ScopedEnv::update([
            ("LPM_CONCURRENT_DOWNLOADS", Some("7".into())),
            ("LPM_FETCH_EXTRACT_PERMITS", Some("3".into())),
            ("LPM_V2_LINK_TASKS", Some("5".into())),
        ]);
        let coordinator = WorkspaceMaterializationCoordinator::new(Vec::new());

        assert_eq!(coordinator.fetch_semaphore.available_permits(), 7);
        assert_eq!(
            coordinator
                .fetch_extract_limiter(true)
                .expect("virtual-store extraction limiter")
                .available_permits(),
            3,
        );
        assert_eq!(coordinator.v2_link_task_semaphore.available_permits(), 5);
    }

    #[test]
    fn workspace_materialization_coordinator_caps_link_pool_at_tokio_limit() {
        let _env = crate::test_env::ScopedEnv::update([(
            "LPM_V2_LINK_TASKS",
            Some(usize::MAX.to_string().into()),
        )]);
        let coordinator = WorkspaceMaterializationCoordinator::new(Vec::new());

        assert_eq!(
            coordinator.v2_link_task_semaphore.available_permits(),
            Semaphore::MAX_PERMITS,
        );
    }

    #[tokio::test]
    async fn single_flight_runs_one_operation_for_concurrent_same_key_requests() {
        let flight = SingleFlight::<&str, i32, Arc<str>>::default();
        let calls = Arc::new(AtomicUsize::new(0));
        let first_calls = Arc::clone(&calls);
        let second_calls = Arc::clone(&calls);

        let (first, second) = tokio::join!(
            flight.run("shared", || async move {
                first_calls.fetch_add(1, Ordering::SeqCst);
                tokio::task::yield_now().await;
                Ok(7)
            }),
            flight.run("shared", || async move {
                second_calls.fetch_add(1, Ordering::SeqCst);
                tokio::task::yield_now().await;
                Ok(7)
            }),
        );

        let first = first.expect("first request should succeed");
        let second = second.expect("second request should succeed");
        assert_eq!(
            (
                first.value,
                second.value,
                usize::from(first.performed) + usize::from(second.performed),
                calls.load(Ordering::SeqCst),
            ),
            (7, 7, 1, 1),
        );
    }

    #[tokio::test]
    async fn single_flight_reuses_error_for_later_same_key_requests() {
        let flight = SingleFlight::<&str, (), Arc<str>>::default();
        let calls = Arc::new(AtomicUsize::new(0));
        let first_calls = Arc::clone(&calls);
        let first = flight
            .run("shared", || async move {
                first_calls.fetch_add(1, Ordering::SeqCst);
                Err::<(), Arc<str>>(Arc::from("materialization failed"))
            })
            .await;
        let second_calls = Arc::clone(&calls);
        let second = flight
            .run("shared", || async move {
                second_calls.fetch_add(1, Ordering::SeqCst);
                Err::<(), Arc<str>>(Arc::from("materialization failed"))
            })
            .await;

        assert_eq!(
            (
                first.expect_err("first request should fail").as_ref(),
                second.expect_err("second request should fail").as_ref(),
                calls.load(Ordering::SeqCst),
            ),
            ("materialization failed", "materialization failed", 1),
        );
    }

    #[tokio::test]
    async fn single_flight_keeps_distinct_keys_isolated() {
        let flight = SingleFlight::<&str, (), Arc<str>>::default();
        let calls = Arc::new(AtomicUsize::new(0));

        for key in ["first", "second"] {
            let calls = Arc::clone(&calls);
            flight
                .run(key, || async move {
                    calls.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                })
                .await
                .expect("distinct-key request should succeed");
        }

        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn fresh_workspace_validation_rechecks_object_after_population() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("workspace-package");
        std::fs::create_dir_all(&source).unwrap();
        std::fs::write(
            source.join("package.json"),
            br#"{"name":"workspace-package","version":"1.0.0"}"#,
        )
        .unwrap();
        let store = Arc::new(lpm_store::v2::Store::at(temp.path().join("store")));
        let source_sri = lpm_store::compute_sri_hash(b"missing-object");
        let coordinator = WorkspaceMaterializationCoordinator::new(Vec::new());

        let first = coordinator
            .validate_object(source_sri.clone(), Arc::clone(&store))
            .await
            .unwrap();
        coordinator
            .populate_local_source(source, source_sri.clone(), Arc::clone(&store))
            .await
            .unwrap();
        let after_population = coordinator
            .validate_object(source_sri, store)
            .await
            .unwrap();

        assert!(first.performed);
        assert!(first.value.reusable.is_none());
        assert!(after_population.performed);
        assert!(after_population.value.reusable.is_some());
    }

    #[tokio::test]
    async fn recursive_workspace_populates_a_shared_local_source_once() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("workspace-package");
        std::fs::create_dir_all(&source).unwrap();
        std::fs::write(
            source.join("package.json"),
            br#"{"name":"workspace-package","version":"1.0.0"}"#,
        )
        .unwrap();
        std::fs::write(source.join("index.js"), b"module.exports = 1;\n").unwrap();
        let source_sri = lpm_store::compute_sri_hash(b"shared-local-source");
        let store = Arc::new(lpm_store::v2::Store::at(temp.path().join("store")));
        let coordinator = WorkspaceMaterializationCoordinator::new(Vec::new());

        let (first, second) = tokio::join!(
            coordinator.populate_local_source(
                source.clone(),
                source_sri.clone(),
                Arc::clone(&store),
            ),
            coordinator.populate_local_source(source, source_sri, store),
        );
        let first = first.unwrap();
        let second = second.unwrap();

        assert_eq!(
            usize::from(first.performed) + usize::from(second.performed),
            1
        );
        assert_eq!(first.value, second.value);
        assert!(first.value.join("package.json").is_file());
    }

    #[tokio::test]
    async fn scripted_provider_source_bypasses_shared_population() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("workspace-package");
        std::fs::create_dir_all(&source).unwrap();
        std::fs::write(
            source.join("package.json"),
            br#"{"name":"workspace-package","version":"1.0.0"}"#,
        )
        .unwrap();
        let source_sri = lpm_store::compute_sri_hash(b"unshared-local-source");
        let store = Arc::new(lpm_store::v2::Store::at(temp.path().join("store")));
        let coordinator = WorkspaceMaterializationCoordinator::new(vec![source.clone()]);

        let (first, second) = tokio::join!(
            coordinator.populate_local_source(
                source.clone(),
                source_sri.clone(),
                Arc::clone(&store),
            ),
            coordinator.populate_local_source(source, source_sri, store),
        );

        assert_eq!(
            usize::from(first.unwrap().performed) + usize::from(second.unwrap().performed),
            2,
        );
    }

    #[tokio::test]
    async fn fresh_workspace_validation_reuses_positive_result_concurrently() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("workspace-package");
        std::fs::create_dir_all(&source).unwrap();
        std::fs::write(
            source.join("package.json"),
            br#"{"name":"workspace-package","version":"1.0.0"}"#,
        )
        .unwrap();
        let source_sri = lpm_store::compute_sri_hash(b"shared-positive-object");
        let store = Arc::new(lpm_store::v2::Store::at(temp.path().join("store")));
        store
            .populate_object_from_local_source(&source, &source_sri)
            .unwrap();
        let coordinator = WorkspaceMaterializationCoordinator::new(Vec::new());

        let (first, second) = tokio::join!(
            coordinator.validate_object(source_sri.clone(), Arc::clone(&store)),
            coordinator.validate_object(source_sri, store),
        );
        let first = first.unwrap();
        let second = second.unwrap();

        assert_eq!(
            (
                first.value.reusable.is_some(),
                second.value.reusable.is_some(),
                usize::from(first.performed) + usize::from(second.performed),
            ),
            (true, true, 1),
        );
    }

    #[tokio::test]
    async fn union_validation_checks_the_published_object_set_once() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("workspace-package");
        std::fs::create_dir_all(&source).unwrap();
        std::fs::write(
            source.join("package.json"),
            br#"{"name":"workspace-package","version":"1.0.0"}"#,
        )
        .unwrap();
        let first_sri = lpm_store::compute_sri_hash(b"first-union-object");
        let second_sri = lpm_store::compute_sri_hash(b"second-union-object");
        let store = Arc::new(lpm_store::v2::Store::at(temp.path().join("store")));
        store
            .populate_object_from_local_source(&source, &first_sri)
            .unwrap();
        store
            .populate_object_from_local_source(&source, &second_sri)
            .unwrap();
        let coordinator = Arc::new(WorkspaceMaterializationCoordinator::new(Vec::new()));
        coordinator.publish_union_object_candidates([first_sri.clone(), second_sri.clone()]);
        coordinator.start_union_object_validation(Arc::clone(&store));
        let first_request = [first_sri.as_str()];
        let second_request = [second_sri.as_str()];

        let (first, second) = tokio::join!(
            coordinator.validate_objects(&first_request, Arc::clone(&store)),
            coordinator.validate_objects(&second_request, store),
        );
        let first = first.unwrap();
        let second = second.unwrap();

        assert_eq!(first.performed_count + second.performed_count, 2);
        assert_eq!(first.performed_hit_count + second.performed_hit_count, 2);
        assert!(first.reusable(&first_sri).is_some());
        assert!(second.reusable(&second_sri).is_some());
    }

    #[tokio::test]
    async fn link_materialization_coalesces_different_source_integrities_for_one_destination() {
        let temp = tempfile::tempdir().unwrap();
        let project = temp.path().join("project");
        let source = temp.path().join("source");
        std::fs::create_dir_all(&project).unwrap();
        std::fs::create_dir_all(&source).unwrap();
        std::fs::write(
            source.join("package.json"),
            br#"{"name":"shared","version":"1.0.0"}"#,
        )
        .unwrap();
        let store = Arc::new(lpm_store::v2::Store::at(temp.path().join("store")));
        let first_sri = lpm_store::compute_sri_hash(b"first-source-identity");
        let second_sri = lpm_store::compute_sri_hash(b"second-source-identity");
        store
            .populate_object_from_local_source(&source, &first_sri)
            .unwrap();
        store
            .populate_object_from_local_source(&source, &second_sri)
            .unwrap();
        let first_target = lpm_linker::v2::V2Target {
            instance_id: lpm_common::PackageInstanceId::derive(
                "shared",
                "1.0.0",
                "registry+npm",
                "first-source-identity",
            ),
            target: Arc::new(lpm_linker::LinkTarget {
                name: "shared".to_string(),
                version: "1.0.0".to_string(),
                store_path: std::path::PathBuf::new(),
                dependencies: Vec::new(),
                aliases: HashMap::new(),
                is_direct: true,
                root_link_names: None,
                wrapper_id: None,
                materialization: lpm_linker::Materialization::CasBacked,
                peers: Vec::new(),
                patch_fingerprint: None,
            }),
            dependency_targets: HashMap::new(),
            peer_targets: HashMap::new(),
            source_sri: first_sri,
            verified_object_integrity: None,
            fresh_object: None,
        };
        let mut second_target = first_target.clone();
        second_target.source_sri = second_sri;
        let plan = Arc::new(
            lpm_linker::v2::link_v2_prepare_with_authoritative_peer_context(
                &project,
                vec![first_target.clone()],
                &store,
                lpm_linker::LinkerMode::Isolated,
            )
            .unwrap(),
        );
        let coordinator = WorkspaceMaterializationCoordinator::new(Vec::new());

        let (first, second) = tokio::join!(
            coordinator.materialize_link(
                Arc::clone(&plan),
                Arc::new(first_target),
                Arc::clone(&store),
            ),
            coordinator.materialize_link(plan, Arc::new(second_target), store),
        );
        let first = first.unwrap();
        let second = second.unwrap();

        assert_eq!(
            usize::from(first.performed) + usize::from(second.performed),
            1
        );
        assert_eq!(
            first.value.materialized.destination,
            second.value.materialized.destination
        );
    }

    #[tokio::test]
    async fn link_materialization_keeps_direct_and_transitive_graph_contexts_distinct() {
        let temp = tempfile::tempdir().unwrap();
        let direct_project = temp.path().join("direct-project");
        let transitive_project = temp.path().join("transitive-project");
        let source = temp.path().join("source");
        std::fs::create_dir_all(&direct_project).unwrap();
        std::fs::create_dir_all(&transitive_project).unwrap();
        std::fs::create_dir_all(&source).unwrap();
        std::fs::write(
            source.join("package.json"),
            br#"{"name":"shared","version":"1.0.0"}"#,
        )
        .unwrap();
        let store = Arc::new(lpm_store::v2::Store::at(temp.path().join("store")));
        let source_sri = lpm_store::compute_sri_hash(b"shared-source-identity");
        store
            .populate_object_from_local_source(&source, &source_sri)
            .unwrap();
        let direct_target = lpm_linker::v2::V2Target {
            instance_id: lpm_common::PackageInstanceId::derive(
                "shared",
                "1.0.0",
                "registry+npm",
                "direct-context",
            ),
            target: Arc::new(lpm_linker::LinkTarget {
                name: "shared".to_string(),
                version: "1.0.0".to_string(),
                store_path: std::path::PathBuf::new(),
                dependencies: Vec::new(),
                aliases: HashMap::new(),
                is_direct: true,
                root_link_names: Some(vec!["shared".to_string()]),
                wrapper_id: None,
                materialization: lpm_linker::Materialization::CasBacked,
                peers: Vec::new(),
                patch_fingerprint: None,
            }),
            dependency_targets: HashMap::new(),
            peer_targets: HashMap::new(),
            source_sri,
            verified_object_integrity: None,
            fresh_object: None,
        };
        let mut transitive_target = direct_target.clone();
        let transitive_link_target = Arc::make_mut(&mut transitive_target.target);
        transitive_link_target.is_direct = false;
        transitive_link_target.root_link_names = Some(Vec::new());
        let direct_plan = Arc::new(
            lpm_linker::v2::link_v2_prepare_with_authoritative_peer_context(
                &direct_project,
                vec![direct_target.clone()],
                &store,
                lpm_linker::LinkerMode::Isolated,
            )
            .unwrap(),
        );
        let transitive_plan = Arc::new(
            lpm_linker::v2::link_v2_prepare_with_authoritative_peer_context(
                &transitive_project,
                vec![transitive_target.clone()],
                &store,
                lpm_linker::LinkerMode::Isolated,
            )
            .unwrap(),
        );
        let coordinator = WorkspaceMaterializationCoordinator::new(Vec::new());

        let (direct, transitive) = tokio::join!(
            coordinator.materialize_link(direct_plan, Arc::new(direct_target), Arc::clone(&store)),
            coordinator.materialize_link(transitive_plan, Arc::new(transitive_target), store),
        );
        let direct = direct.unwrap();
        let transitive = transitive.unwrap();

        assert!(direct.performed);
        assert!(transitive.performed);
        assert_ne!(
            direct.value.materialized.destination,
            transitive.value.materialized.destination
        );
    }

    #[tokio::test]
    async fn spawned_workspace_dispatches_keep_the_coordinator() {
        let temp = tempfile::tempdir().unwrap();
        let project = temp.path().join("project");
        let source = temp.path().join("source");
        std::fs::create_dir_all(&project).unwrap();
        std::fs::create_dir_all(&source).unwrap();
        std::fs::write(
            source.join("package.json"),
            br#"{"name":"shared","version":"1.0.0"}"#,
        )
        .unwrap();
        let store = Arc::new(lpm_store::v2::Store::at(temp.path().join("store")));
        let first_sri = lpm_store::compute_sri_hash(b"first-spawned-source");
        let second_sri = lpm_store::compute_sri_hash(b"second-spawned-source");
        store
            .populate_object_from_local_source(&source, &first_sri)
            .unwrap();
        store
            .populate_object_from_local_source(&source, &second_sri)
            .unwrap();
        let first_target = lpm_linker::v2::V2Target {
            instance_id: lpm_common::PackageInstanceId::derive(
                "shared",
                "1.0.0",
                "registry+npm",
                "first-spawned-source",
            ),
            target: Arc::new(lpm_linker::LinkTarget {
                name: "shared".to_string(),
                version: "1.0.0".to_string(),
                store_path: std::path::PathBuf::new(),
                dependencies: Vec::new(),
                aliases: HashMap::new(),
                is_direct: true,
                root_link_names: None,
                wrapper_id: None,
                materialization: lpm_linker::Materialization::CasBacked,
                peers: Vec::new(),
                patch_fingerprint: None,
            }),
            dependency_targets: HashMap::new(),
            peer_targets: HashMap::new(),
            source_sri: first_sri,
            verified_object_integrity: None,
            fresh_object: None,
        };
        let mut second_target = first_target.clone();
        second_target.source_sri = second_sri;
        let plan = Arc::new(
            lpm_linker::v2::link_v2_prepare_with_authoritative_peer_context(
                &project,
                vec![first_target.clone()],
                &store,
                lpm_linker::LinkerMode::Isolated,
            )
            .unwrap(),
        );
        let coordinator = Arc::new(WorkspaceMaterializationCoordinator::new(Vec::new()));
        let semaphore = coordinator.v2_link_task_semaphore();

        let (first, second) = scope(Arc::clone(&coordinator), async move {
            let dispatch_coordinator = current();
            tokio::join!(
                tokio::spawn({
                    let plan = Arc::clone(&plan);
                    let store = Arc::clone(&store);
                    let semaphore = Arc::clone(&semaphore);
                    let dispatch_coordinator = dispatch_coordinator.clone();
                    async move {
                        super::super::spawn_v2_link_task(
                            plan,
                            Arc::new(first_target),
                            store,
                            semaphore,
                            dispatch_coordinator,
                        )
                    }
                }),
                tokio::spawn(async move {
                    super::super::spawn_v2_link_task(
                        plan,
                        Arc::new(second_target),
                        store,
                        semaphore,
                        dispatch_coordinator,
                    )
                }),
            )
        })
        .await;
        let first = first.unwrap().unwrap();
        let second = second.unwrap().unwrap();

        assert_eq!(
            usize::from(first.dispatched()) + usize::from(second.dispatched()),
            1
        );
        first.wait().await.unwrap();
        second.wait().await.unwrap();
    }
}
