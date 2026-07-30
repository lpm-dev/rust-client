use std::future::Future;
use std::sync::Arc;

use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore};

pub(super) struct WorkspaceResolutionCoordinator {
    resolution_permits: Arc<Semaphore>,
    completed: Box<[TargetCompletion]>,
}

impl WorkspaceResolutionCoordinator {
    pub(super) fn new(target_count: usize, resolution_concurrency: usize) -> Self {
        Self {
            resolution_permits: Arc::new(Semaphore::new(resolution_concurrency.max(1))),
            completed: (0..target_count)
                .map(|_| TargetCompletion::default())
                .collect(),
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
    commit_entered: std::sync::atomic::AtomicBool,
}

impl WorkspaceResolutionTask {
    async fn enter_commit(&self) {
        if self
            .commit_entered
            .load(std::sync::atomic::Ordering::Acquire)
        {
            return;
        }

        self.resolution_permit
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();

        if let Some(previous) = self.index.checked_sub(1) {
            self.coordinator.completed[previous].wait().await;
        }
        self.commit_entered
            .store(true, std::sync::atomic::Ordering::Release);
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
    task.enter_commit().await;
    if result.is_ok() {
        coordinator.completed[index].finish();
    }
    result
}

pub(super) fn active() -> bool {
    ACTIVE_TASK.try_with(|_| ()).is_ok()
}

pub(super) async fn wait_for_commit() {
    if let Ok(task) = ACTIVE_TASK.try_with(Arc::clone) {
        task.enter_commit().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[tokio::test(flavor = "current_thread")]
    async fn later_importer_resolves_early_but_cannot_commit_before_predecessor() {
        let coordinator = Arc::new(WorkspaceResolutionCoordinator::new(2, 2));
        let first_may_finish = Arc::new(Notify::new());
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
                    let second_resolved = Arc::clone(&second_resolved);
                    let events = Arc::clone(&events);
                    tokio::task::spawn_local(async move {
                        scope(coordinator, 1, async {
                            events.lock().unwrap().push("second-resolved");
                            second_resolved.notify_one();
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
                    vec!["first-resolved", "first-commit", "second-resolved"]
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
                "first-commit",
                "second-resolved",
                "second-commit"
            ]
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn early_failure_waits_for_its_commit_turn() {
        let coordinator = Arc::new(WorkspaceResolutionCoordinator::new(2, 2));
        let first_may_finish = Arc::new(Notify::new());
        let second_failed = Arc::new(Notify::new());
        let second_returned = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let local = tokio::task::LocalSet::new();

        local
            .run_until(async {
                let first = {
                    let coordinator = Arc::clone(&coordinator);
                    let first_may_finish = Arc::clone(&first_may_finish);
                    tokio::task::spawn_local(async move {
                        scope(coordinator, 0, async {
                            wait_for_commit().await;
                            first_may_finish.notified().await;
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

                tokio::task::yield_now().await;
                assert!(!second_returned.load(std::sync::atomic::Ordering::Acquire));
                first_may_finish.notify_one();
                first.await.unwrap().unwrap();
                second_failed.notified().await;
                assert_eq!(second.await.unwrap(), Err("resolve failed"));
            })
            .await;
    }
}
