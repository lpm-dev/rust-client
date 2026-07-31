use std::future::Future;
use std::sync::Arc;

use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore};

pub(super) struct WorkspaceResolutionCoordinator {
    resolution_permits: Arc<Semaphore>,
    materialized: Box<[TargetCompletion]>,
    completed: Box<[TargetCompletion]>,
    prepared_count: std::sync::atomic::AtomicUsize,
    all_prepared: Notify,
    fetch_overlap_hub: Arc<super::fetch_overlap::WorkspaceFetchOverlapHub>,
}

impl WorkspaceResolutionCoordinator {
    pub(super) fn new(target_count: usize, resolution_concurrency: usize) -> Self {
        Self {
            resolution_permits: Arc::new(Semaphore::new(resolution_concurrency.max(1))),
            materialized: (0..target_count)
                .map(|_| TargetCompletion::default())
                .collect(),
            completed: (0..target_count)
                .map(|_| TargetCompletion::default())
                .collect(),
            prepared_count: std::sync::atomic::AtomicUsize::new(0),
            all_prepared: Notify::new(),
            fetch_overlap_hub: Arc::new(super::fetch_overlap::WorkspaceFetchOverlapHub::new()),
        }
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
    if result.is_ok() {
        task.enter_commit().await;
        coordinator.completed[index].finish();
    }
    result
}

pub(super) fn active() -> bool {
    ACTIVE_TASK.try_with(|_| ()).is_ok()
}

pub(super) fn fetch_overlap_hub() -> Option<Arc<super::fetch_overlap::WorkspaceFetchOverlapHub>> {
    ACTIVE_TASK
        .try_with(|task| Arc::clone(&task.coordinator.fetch_overlap_hub))
        .ok()
}

pub(super) fn finish_resolution() {
    if let Ok(task) = ACTIVE_TASK.try_with(Arc::clone) {
        task.finish_resolution();
    }
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
