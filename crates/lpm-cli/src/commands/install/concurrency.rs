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
    pub(super) hits: HashMap<String, lpm_store::v2::ReusableObject>,
    pub(super) candidate_count: usize,
    pub(super) concurrency: usize,
    pub(super) validation_timings: V2ReusableValidationTimings,
}

pub(super) struct V2LinkTaskResult {
    pub(super) materialized: MaterializedPackage,
    pub(super) freshly_populated: bool,
    pub(super) ms: u128,
    pub(super) timings: lpm_store::v2::LinkEntryTimings,
}

pub(super) type LinkHandle =
    tokio::task::JoinHandle<Result<(MaterializedPackage, lpm_linker::OnePackageResult), LpmError>>;

pub(super) type V2LinkHandle = tokio::task::JoinHandle<Result<V2LinkTaskResult, LpmError>>;

pub(super) fn spawn_v2_link_task(
    plan: std::sync::Arc<lpm_linker::v2::LinkPlanV2>,
    target: lpm_linker::v2::V2Target,
    store: std::sync::Arc<lpm_store::v2::Store>,
    semaphore: Arc<Semaphore>,
) -> V2LinkHandle {
    let workspace_coordinator = workspace_materialization::current();
    tokio::spawn(async move {
        let _permit = semaphore
            .acquire_owned()
            .await
            .map_err(|_| LpmError::Registry("v2 link semaphore closed".into()))?;
        let start = Instant::now();
        if let Some(coordinator) = workspace_coordinator {
            let coordinated = coordinator.materialize_link(plan, target, store).await?;
            let materialization = coordinated.value;
            Ok(V2LinkTaskResult {
                materialized: materialization.materialized,
                freshly_populated: coordinated.performed && materialization.freshly_populated,
                ms: start.elapsed().as_millis(),
                timings: if coordinated.performed {
                    materialization.timings
                } else {
                    lpm_store::v2::LinkEntryTimings::default()
                },
            })
        } else {
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
        }
    })
}

pub(super) async fn prevalidate_v2_reusable_objects(
    packages: &[InstallPackage],
    store_v2: Arc<lpm_store::v2::Store>,
) -> Result<V2ReusablePrevalidation, LpmError> {
    let candidates: Vec<(String, String)> = packages
        .iter()
        .filter(|package| {
            !matches!(
                package.source_kind(),
                Ok(lpm_lockfile::Source::Directory { .. }) | Ok(lpm_lockfile::Source::Link { .. })
            )
        })
        .filter_map(|package| {
            Some((
                install_pkg_key(package),
                package.integrity.as_ref()?.clone(),
            ))
        })
        .collect();

    if candidates.is_empty() {
        return Ok(V2ReusablePrevalidation {
            hits: HashMap::new(),
            candidate_count: 0,
            concurrency: 0,
            validation_timings: V2ReusableValidationTimings::default(),
        });
    }

    let candidate_count = candidates.len();
    let concurrency = v2_cache_check_concurrency(candidate_count);
    let workspace_coordinator = workspace_materialization::current();
    let mut checks = futures::stream::iter(candidates.into_iter().map(|(key, sri)| {
        let store_v2 = Arc::clone(&store_v2);
        let workspace_coordinator = workspace_coordinator.as_ref().map(Arc::clone);
        async move {
            if let Some(coordinator) = workspace_coordinator {
                let coordinated = coordinator.validate_object(sri, store_v2).await?;
                let validation = coordinated.value;
                Ok::<_, LpmError>((
                    key,
                    validation.reusable,
                    if coordinated.performed {
                        validation.timings
                    } else {
                        lpm_store::v2::ReusableObjectCheckTimings::default()
                    },
                ))
            } else {
                tokio::task::spawn_blocking(move || {
                    store_v2
                        .reusable_object_with_timings(&sri)
                        .map(|(hit, timings)| (key, hit, timings))
                })
                .await
                .map_err(|error| {
                    LpmError::Registry(format!("v2 cache check task panicked: {error}"))
                })?
            }
        }
    }))
    .buffer_unordered(concurrency);

    let mut hits = HashMap::with_capacity(candidate_count);
    let mut validation_timings = V2ReusableValidationTimings::default();
    while let Some(result) = checks.next().await {
        let (key, hit, timings) = result?;
        validation_timings.record(timings, hit.is_some());
        if let Some(hit) = hit {
            hits.insert(key, hit);
        }
    }
    Ok(V2ReusablePrevalidation {
        hits,
        candidate_count,
        concurrency,
        validation_timings,
    })
}
