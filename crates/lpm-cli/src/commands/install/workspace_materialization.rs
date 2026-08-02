use std::collections::HashMap;
use std::future::Future;
use std::hash::Hash;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use lpm_common::LpmError;
use tokio::sync::{Mutex, OnceCell, Semaphore};

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
    K: Clone + Eq + Hash,
    T: Clone,
    E: Clone,
{
    pub(super) async fn run<F, Fut>(&self, key: K, operation: F) -> Result<Coordinated<T>, E>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<T, E>>,
    {
        self.run_retaining(key, operation, |_| true).await
    }

    pub(super) async fn run_retaining<F, Fut, Retain>(
        &self,
        key: K,
        operation: F,
        retain: Retain,
    ) -> Result<Coordinated<T>, E>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<T, E>>,
        Retain: FnOnce(&Result<T, E>) -> bool,
    {
        let lookup_key = key.clone();
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
        if !retain(&result) {
            self.remove_if_same(&lookup_key, &cell).await;
        }
        result.map(|value| Coordinated {
            value,
            performed: performed.load(Ordering::Relaxed),
        })
    }

    pub(super) async fn invalidate(&self, key: &K) {
        self.entries.lock().await.remove(key);
    }

    async fn remove_if_same(&self, key: &K, cell: &SharedOperation<T, E>) {
        let mut entries = self.entries.lock().await;
        if entries
            .get(key)
            .is_some_and(|entry| Arc::ptr_eq(entry, cell))
        {
            entries.remove(key);
        }
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
pub(super) struct LinkMaterialization {
    pub(super) materialized: lpm_linker::MaterializedPackage,
    pub(super) freshly_populated: bool,
    pub(super) timings: lpm_store::v2::LinkEntryTimings,
}

#[derive(Clone, Eq, Hash, PartialEq)]
struct LinkMaterializationKey {
    graph_key: Arc<lpm_store::v2::GraphKey>,
    source_sri: String,
}

#[derive(Clone, Eq, Hash, PartialEq)]
struct LocalSourcePopulationKey {
    source_dir: std::path::PathBuf,
    source_sri: String,
}

pub(super) struct WorkspaceMaterializationCoordinator {
    share_local_source_populations: bool,
    fetch_semaphore: Arc<Semaphore>,
    fetch_extract_limiter: super::FetchExtractLimiter,
    limit_v1_extraction: bool,
    v2_link_task_semaphore: Arc<Semaphore>,
    object_validation_permits: Arc<Semaphore>,
    object_validations: SingleFlight<String, ObjectValidation, SharedMaterializationError>,
    local_source_populations:
        SingleFlight<LocalSourcePopulationKey, std::path::PathBuf, SharedMaterializationError>,
    link_materializations:
        SingleFlight<LinkMaterializationKey, LinkMaterialization, SharedMaterializationError>,
}

impl Default for WorkspaceMaterializationCoordinator {
    fn default() -> Self {
        Self::new(true)
    }
}

impl WorkspaceMaterializationCoordinator {
    pub(super) fn new(share_local_source_populations: bool) -> Self {
        let limit_v1_extraction = super::configured_fetch_extract_permits_from_env(false).is_some();
        let fetch_extract_limiter = super::configured_fetch_extract_permits_from_env(true)
            .map(Semaphore::new)
            .map(Arc::new);
        Self {
            share_local_source_populations,
            fetch_semaphore: Arc::new(Semaphore::new(super::max_concurrent_downloads())),
            fetch_extract_limiter,
            limit_v1_extraction,
            v2_link_task_semaphore: Arc::new(Semaphore::new(super::v2_link_task_concurrency(
                Semaphore::MAX_PERMITS,
            ))),
            object_validation_permits: Arc::new(Semaphore::new(
                super::concurrency::V2_CACHE_CHECK_MAX_CONCURRENCY,
            )),
            object_validations: SingleFlight::default(),
            local_source_populations: SingleFlight::default(),
            link_materializations: SingleFlight::default(),
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

    pub(super) async fn populate_local_source(
        &self,
        source_dir: std::path::PathBuf,
        source_sri: String,
        store: Arc<lpm_store::v2::Store>,
    ) -> Result<Coordinated<std::path::PathBuf>, LpmError> {
        if !self.share_local_source_populations {
            let validation_sri = source_sri.clone();
            let object_dir = tokio::task::spawn_blocking(move || {
                store.populate_object_from_local_source(&source_dir, &source_sri)
            })
            .await
            .map_err(|error| {
                LpmError::Registry(format!("v2 local-source task panicked: {error}"))
            })??;
            self.object_validations.invalidate(&validation_sri).await;
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
                        "v2 local-source task panicked: {error}"
                    )))
                })?
                .map_err(SharedMaterializationError::from)
            })
            .await
            .map_err(LpmError::from);
        if result.is_ok() {
            self.object_validations.invalidate(&validation_sri).await;
        }
        result
    }

    pub(super) async fn validate_object(
        &self,
        source_sri: String,
        store: Arc<lpm_store::v2::Store>,
    ) -> Result<Coordinated<ObjectValidation>, LpmError> {
        let validation_permits = Arc::clone(&self.object_validation_permits);
        let operation_sri = source_sri.clone();
        self.object_validations
            .run_retaining(
                source_sri,
                || async move {
                    let _permit = validation_permits.acquire_owned().await.map_err(|_| {
                        SharedMaterializationError::Registry(Arc::from(
                            "v2 object validation semaphore closed",
                        ))
                    })?;
                    tokio::task::spawn_blocking(move || {
                        store
                            .reusable_object_with_timings(&operation_sri)
                            .map(|(reusable, timings)| ObjectValidation { reusable, timings })
                    })
                    .await
                    .map_err(|error| {
                        SharedMaterializationError::Registry(Arc::from(format!(
                            "v2 cache check task panicked: {error}"
                        )))
                    })?
                    .map_err(SharedMaterializationError::from)
                },
                |result| {
                    matches!(
                        result,
                        Ok(ObjectValidation {
                            reusable: Some(_),
                            ..
                        })
                    )
                },
            )
            .await
            .map_err(LpmError::from)
    }

    pub(super) fn object_validation_concurrency(&self, candidate_count: usize) -> usize {
        super::concurrency::V2_CACHE_CHECK_MAX_CONCURRENCY.min(candidate_count.max(1))
    }

    pub(super) async fn materialize_link(
        &self,
        plan: Arc<lpm_linker::v2::LinkPlanV2>,
        target: lpm_linker::v2::V2Target,
        store: Arc<lpm_store::v2::Store>,
    ) -> Result<Coordinated<LinkMaterialization>, LpmError> {
        let graph_key = plan.graph_key_for(&target)?;
        let key = LinkMaterializationKey {
            graph_key,
            source_sri: target.source_sri.clone(),
        };
        self.link_materializations
            .run(key, || async move {
                tokio::task::spawn_blocking(move || {
                    lpm_linker::v2::link_v2_one_with_timings(&plan, &target, &store).map(
                        |(materialized, freshly_populated, timings)| LinkMaterialization {
                            materialized,
                            freshly_populated,
                            timings,
                        },
                    )
                })
                .await
                .map_err(|error| {
                    SharedMaterializationError::Registry(Arc::from(format!(
                        "v2 link task panicked: {error}"
                    )))
                })?
                .map_err(SharedMaterializationError::from)
            })
            .await
            .map_err(LpmError::from)
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
        let coordinator = WorkspaceMaterializationCoordinator::new(true);

        assert_eq!(coordinator.fetch_semaphore.available_permits(), 7);
        assert_eq!(
            coordinator
                .fetch_extract_limiter(true)
                .expect("v2 extraction limiter")
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
        let coordinator = WorkspaceMaterializationCoordinator::new(true);

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
        let coordinator = WorkspaceMaterializationCoordinator::new(true);

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
        let coordinator = WorkspaceMaterializationCoordinator::new(true);

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
        let coordinator = WorkspaceMaterializationCoordinator::new(true);

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

    #[test]
    fn link_materialization_key_separates_source_integrities_for_the_same_graph() {
        let graph_key = Arc::new(lpm_store::v2::GraphKey::derive(
            &lpm_store::v2::GraphKeyInputs::new(
                "shared",
                "1.0.0",
                lpm_store::v2::PlatformTuple::current(),
                lpm_store::v2::LinkerModeTag::Isolated,
            ),
        ));
        let first = LinkMaterializationKey {
            graph_key: Arc::clone(&graph_key),
            source_sri: "sha512-first".to_string(),
        };
        let second = LinkMaterializationKey {
            graph_key,
            source_sri: "sha512-second".to_string(),
        };

        assert!(first != second);
    }
}
