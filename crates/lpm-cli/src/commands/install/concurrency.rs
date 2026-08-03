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
    parallelism
        .clamp(1, V2_LINK_TASK_MAX_CONCURRENCY)
        .min(target_count.max(1))
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
            Self::Task(handle) => handle
                .await
                .map_err(|error| LpmError::Registry(format!("v2 link task panicked: {error}")))?,
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
            .map_err(|_| LpmError::Registry("v2 link semaphore closed".into()))?;
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
        .map_err(|e| LpmError::Registry(format!("v2 link task panicked: {e}")))?
    })))
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

    let unique_candidates: HashSet<&str> = candidates.into_iter().collect();
    let candidate_count = unique_candidates.len();
    let concurrency = v2_cache_check_concurrency(candidate_count);
    let mut checks = futures::stream::iter(unique_candidates.into_iter().map(|sri| {
        let store_v2 = Arc::clone(&store_v2);
        let sri = sri.to_string();
        async move {
            tokio::task::spawn_blocking(move || {
                store_v2
                    .reusable_object_with_timings(&sri)
                    .map(|(hit, timings)| (sri, hit, timings))
            })
            .await
            .map_err(|error| LpmError::Registry(format!("v2 cache check task panicked: {error}")))?
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
