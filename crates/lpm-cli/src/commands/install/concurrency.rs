use futures::StreamExt;
use lpm_linker::MaterializedPackage;

use super::*;

pub(super) const V2_CACHE_CHECK_MAX_CONCURRENCY: usize = 16;
pub(super) const V2_LINK_TASK_MAX_CONCURRENCY: usize = 16;
const ENV_V2_LINK_TASKS: &str = "LPM_V2_LINK_TASKS";

fn v2_cache_check_concurrency(candidate_count: usize) -> usize {
    let parallelism = std::thread::available_parallelism()
        .map(|threads| threads.get())
        .unwrap_or(4);
    parallelism
        .clamp(1, V2_CACHE_CHECK_MAX_CONCURRENCY)
        .min(candidate_count.max(1))
}

pub(super) fn v2_link_task_concurrency(target_count: usize) -> usize {
    v2_link_task_concurrency_with_limit(target_count, V2_LINK_TASK_MAX_CONCURRENCY)
}

pub(super) fn v2_cached_link_task_concurrency(target_count: usize) -> usize {
    let limit = if cfg!(target_os = "macos") {
        4
    } else {
        V2_LINK_TASK_MAX_CONCURRENCY
    };
    v2_link_task_concurrency_with_limit(target_count, limit)
}

fn v2_link_task_concurrency_with_limit(target_count: usize, limit: usize) -> usize {
    if let Some(configured) = std::env::var(ENV_V2_LINK_TASKS)
        .ok()
        .and_then(|value| value.trim().parse::<usize>().ok())
        .filter(|value| *value > 0)
    {
        return configured.min(target_count.max(1));
    }
    let parallelism = std::thread::available_parallelism()
        .map(|threads| threads.get())
        .unwrap_or(4);
    parallelism.clamp(1, limit).min(target_count.max(1))
}

pub(super) struct V2ReusablePrevalidation {
    hits: V2ReusableObjects,
    pub(super) candidate_count: usize,
    pub(super) hit_count: usize,
    pub(super) concurrency: usize,
    pub(super) validation_timings: V2ReusableValidationTimings,
}

enum V2ReusableObjects {
    Local(HashMap<String, lpm_store::v2::ReusableObject>),
    Workspace(Box<workspace_materialization::ObjectValidationSnapshot>),
}

impl V2ReusablePrevalidation {
    pub(super) fn reusable(&self, source_sri: &str) -> Option<lpm_store::v2::ReusableObject> {
        match &self.hits {
            V2ReusableObjects::Local(hits) => hits.get(source_sri).cloned(),
            V2ReusableObjects::Workspace(snapshot) => snapshot.reusable(source_sri),
        }
    }

    pub(super) fn empty() -> Self {
        Self {
            hits: V2ReusableObjects::Local(HashMap::new()),
            candidate_count: 0,
            hit_count: 0,
            concurrency: 0,
            validation_timings: V2ReusableValidationTimings::default(),
        }
    }
}

pub(super) struct V2LinkTaskResult {
    pub(super) materialized: MaterializedPackage,
    pub(super) freshly_populated: bool,
    pub(super) ms: u128,
    pub(super) timings: lpm_store::v2::LinkEntryTimings,
}

pub(super) type LinkHandle =
    tokio::task::JoinHandle<Result<(MaterializedPackage, lpm_linker::OnePackageResult), LpmError>>;

pub(super) enum V2LinkHandle {
    Task(tokio::task::JoinHandle<Result<V2LinkTaskResult, LpmError>>),
    Workspace(workspace_materialization::WorkspaceLinkHandle),
}

impl V2LinkHandle {
    pub(super) fn dispatched(&self) -> bool {
        match self {
            Self::Task(_) => true,
            Self::Workspace(handle) => handle.performed(),
        }
    }

    pub(super) async fn wait(self) -> Result<V2LinkTaskResult, LpmError> {
        match self {
            Self::Task(handle) => handle.await.map_err(|error| {
                LpmError::Registry(format!("virtual-store link task panicked: {error}"))
            })?,
            Self::Workspace(handle) => {
                let coordinated = handle.wait().await?;
                let materialization = coordinated.value;
                Ok(V2LinkTaskResult {
                    materialized: materialization.materialized,
                    freshly_populated: coordinated.performed && materialization.freshly_populated,
                    ms: if coordinated.performed {
                        materialization.ms
                    } else {
                        0
                    },
                    timings: if coordinated.performed {
                        materialization.timings
                    } else {
                        lpm_store::v2::LinkEntryTimings::default()
                    },
                })
            }
        }
    }
}

pub(super) fn spawn_v2_link_task(
    plan: std::sync::Arc<lpm_linker::v2::LinkPlanV2>,
    target: std::sync::Arc<lpm_linker::v2::V2Target>,
    store: std::sync::Arc<lpm_store::v2::Store>,
    semaphore: Arc<Semaphore>,
    workspace_coordinator: Option<
        Arc<workspace_materialization::WorkspaceMaterializationCoordinator>,
    >,
) -> Result<V2LinkHandle, LpmError> {
    if let Some(coordinator) = workspace_coordinator {
        return coordinator
            .dispatch_link(plan, target, store)
            .map(V2LinkHandle::Workspace);
    }
    Ok(V2LinkHandle::Task(tokio::spawn(async move {
        let _permit = semaphore
            .acquire_owned()
            .await
            .map_err(|_| LpmError::Registry("virtual-store link semaphore closed".into()))?;
        let start = Instant::now();
        tokio::task::spawn_blocking(move || {
            let (materialized, freshly_populated, timings) =
                lpm_linker::v2::link_v2_one_with_timings(&plan, &target, &store)?;
            Ok(V2LinkTaskResult {
                materialized,
                freshly_populated,
                ms: start.elapsed().as_millis(),
                timings,
            })
        })
        .await
        .map_err(|e| LpmError::Registry(format!("virtual-store link task panicked: {e}")))?
    })))
}

pub(super) struct CachedLinkJobs<T> {
    jobs: Vec<(usize, Option<std::num::NonZeroU64>, T)>,
}

impl<T> CachedLinkJobs<T> {
    pub(super) fn new(capacity: usize) -> Self {
        Self {
            jobs: Vec::with_capacity(capacity),
        }
    }

    pub(super) fn push(&mut self, size: Option<std::num::NonZeroU64>, target: T) {
        self.jobs.push((self.jobs.len(), size, target));
    }

    pub(super) fn len(&self) -> usize {
        self.jobs.len()
    }

    fn dispatch<H, E>(&mut self, mut spawn: impl FnMut(T) -> Result<H, E>) -> Result<Vec<H>, E> {
        self.jobs
            .sort_unstable_by_key(|(ordinal, size, _)| (std::cmp::Reverse(*size), *ordinal));
        let mut handles = Vec::with_capacity(self.jobs.len());
        for (ordinal, _, target) in self.jobs.drain(..) {
            handles.push((ordinal, spawn(target)?));
        }
        // Scheduling must not change materialized-result or error-reporting order.
        handles.sort_unstable_by_key(|(ordinal, _)| *ordinal);
        Ok(handles.into_iter().map(|(_, handle)| handle).collect())
    }
}

pub(super) fn spawn_cached_v2_link_tasks(
    jobs: &mut CachedLinkJobs<Arc<lpm_linker::v2::V2Target>>,
    handles: &mut Vec<V2LinkHandle>,
    plan: Option<&Arc<lpm_linker::v2::LinkPlanV2>>,
    store: Option<&Arc<lpm_store::v2::Store>>,
    semaphore: &Arc<Semaphore>,
    workspace_coordinator: &Option<
        Arc<workspace_materialization::WorkspaceMaterializationCoordinator>,
    >,
) -> Result<u64, LpmError> {
    if jobs.jobs.is_empty() {
        return Ok(0);
    }
    let (Some(plan), Some(store)) = (plan, store) else {
        return Err(LpmError::Registry(
            "cached link tasks require a virtual store plan".into(),
        ));
    };
    let batch = jobs.dispatch(|target| {
        spawn_v2_link_task(
            Arc::clone(plan),
            target,
            Arc::clone(store),
            Arc::clone(semaphore),
            workspace_coordinator.clone(),
        )
    })?;
    let dispatched = batch.iter().filter(|handle| handle.dispatched()).count();
    handles.extend(batch);
    Ok(dispatched as u64)
}

pub(super) async fn prevalidate_v2_reusable_objects(
    packages: &[InstallPackage],
    store_v2: Arc<lpm_store::v2::Store>,
) -> Result<V2ReusablePrevalidation, LpmError> {
    let candidates: Vec<&str> = packages
        .iter()
        .filter(|package| {
            !matches!(
                package.source_kind(),
                Ok(lpm_lockfile::Source::Directory { .. }) | Ok(lpm_lockfile::Source::Link { .. })
            )
        })
        .filter_map(|package| package.integrity.as_deref())
        .collect();

    if candidates.is_empty() {
        return Ok(V2ReusablePrevalidation::empty());
    }

    let workspace_coordinator = workspace_materialization::current();
    if let Some(coordinator) = workspace_coordinator {
        let snapshot = coordinator.validate_objects(&candidates, store_v2).await?;
        return Ok(V2ReusablePrevalidation {
            candidate_count: snapshot.performed_count,
            hit_count: snapshot.performed_hit_count,
            concurrency: snapshot.concurrency,
            validation_timings: snapshot.timings,
            hits: V2ReusableObjects::Workspace(Box::new(snapshot)),
        });
    }

    let unique_candidates: HashSet<String> = candidates.into_iter().map(str::to_owned).collect();
    let candidate_count = unique_candidates.len();
    let concurrency = v2_cache_check_concurrency(candidate_count);
    let validation_batch = store_v2.reusable_object_validation_batch();
    let mut checks = futures::stream::iter(unique_candidates.into_iter().map(|sri| {
        let store_v2 = Arc::clone(&store_v2);
        let validation_batch = validation_batch.clone();
        async move {
            tokio::task::spawn_blocking(move || {
                store_v2
                    .reusable_object_with_timings_in_batch(&sri, &validation_batch)
                    .map(|(hit, timings)| (sri, hit, timings))
            })
            .await
            .map_err(|error| {
                LpmError::Registry(format!("virtual-store cache check task panicked: {error}"))
            })?
        }
    }))
    .buffer_unordered(concurrency);

    let mut hits = HashMap::with_capacity(candidate_count);
    let mut validation_timings = V2ReusableValidationTimings::default();
    while let Some(result) = checks.next().await {
        let (sri, hit, timings) = result?;
        validation_timings.record(timings, hit.is_some());
        if let Some(hit) = hit {
            hits.insert(sri, hit);
        }
    }
    let hit_count = hits.len();
    Ok(V2ReusablePrevalidation {
        hits: V2ReusableObjects::Local(hits),
        candidate_count,
        hit_count,
        concurrency,
        validation_timings,
    })
}

#[cfg(test)]
mod cached_link_tests {
    use super::{CachedLinkJobs, v2_cached_link_task_concurrency, v2_link_task_concurrency};
    use std::num::NonZeroU64;

    #[test]
    fn fully_cached_link_width_keeps_explicit_overrides() {
        let _env = crate::test_env::ScopedEnv::set([("LPM_V2_LINK_TASKS", "9".into())]);
        assert_eq!(v2_cached_link_task_concurrency(100), 9);
        assert_eq!(v2_cached_link_task_concurrency(2), 2);
        assert_eq!(v2_link_task_concurrency(100), 9);
    }

    #[test]
    fn fully_cached_link_width_bounds_macos_metadata_contention() {
        let _env = crate::test_env::ScopedEnv::update([("LPM_V2_LINK_TASKS", None)]);
        let expected = if cfg!(target_os = "macos") {
            v2_link_task_concurrency(100).min(4)
        } else {
            v2_link_task_concurrency(100)
        };
        assert_eq!(v2_cached_link_task_concurrency(100), expected);
        assert_eq!(v2_cached_link_task_concurrency(0), 1);
    }

    #[test]
    fn large_cached_entries_are_submitted_first_without_reordering_results() {
        let mut jobs = CachedLinkJobs::new(5);
        for (size, target) in [
            (None, "unknown-a"),
            (Some(2), "small"),
            (Some(9), "large-a"),
            (Some(9), "large-b"),
            (None, "unknown-b"),
        ] {
            jobs.push(size.and_then(NonZeroU64::new), target);
        }
        let mut started = Vec::new();
        let results = jobs
            .dispatch::<_, ()>(|target| {
                started.push(target);
                Ok(format!("result:{target}"))
            })
            .unwrap();
        assert_eq!(
            started,
            ["large-a", "large-b", "small", "unknown-a", "unknown-b"]
        );
        assert_eq!(
            results,
            [
                "result:unknown-a",
                "result:small",
                "result:large-a",
                "result:large-b",
                "result:unknown-b"
            ]
        );
        assert!(jobs.jobs.is_empty());
    }

    #[test]
    fn cached_dispatch_failure_keeps_the_failing_target_identity() {
        let mut jobs = CachedLinkJobs::new(2);
        jobs.push(NonZeroU64::new(1), "small");
        jobs.push(NonZeroU64::new(9), "large");
        let result = jobs.dispatch::<(), _>(Err);
        assert_eq!(result, Err("large"));
        assert!(jobs.jobs.is_empty());
    }

    #[test]
    fn separate_cached_batches_preserve_their_result_order() {
        let mut jobs = CachedLinkJobs::new(2);
        let mut results = Vec::new();
        for batch in [[(1, "a"), (9, "b")], [(2, "c"), (8, "d")]] {
            for (size, target) in batch {
                jobs.push(NonZeroU64::new(size), target);
            }
            results.extend(jobs.dispatch::<_, ()>(Ok).unwrap());
        }
        assert_eq!(results, ["a", "b", "c", "d"]);
    }
}
