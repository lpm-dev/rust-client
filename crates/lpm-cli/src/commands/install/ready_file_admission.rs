use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard};

use lpm_common::LpmError;
use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore, oneshot};

type Reply = oneshot::Sender<OwnedSemaphorePermit>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ReadyClass {
    Large = 0,
    Ordinary = 1,
}

impl ReadyClass {
    pub(super) fn for_unpacked_size(size: Option<std::num::NonZeroU64>) -> Self {
        if size.is_some_and(|size| size.get() >= super::fetch::LARGE_V2_STREAMING_OBJECT_BYTES) {
            Self::Large
        } else {
            Self::Ordinary
        }
    }
}

struct State {
    queues: [BTreeMap<u64, Reply>; 2],
    next_ticket: u64,
    next_class: usize,
    running: bool,
}

impl State {
    fn is_empty(&self) -> bool {
        self.queues.iter().all(BTreeMap::is_empty)
    }

    fn pop(&mut self) -> Option<(usize, Reply)> {
        for class in [self.next_class, 1 - self.next_class] {
            if let Some((_, reply)) = self.queues[class].pop_first() {
                return Some((class, reply));
            }
        }
        None
    }
}

pub(super) struct ReadyFileAdmission {
    semaphore: Arc<Semaphore>,
    state: Mutex<State>,
    changed: Notify,
}

impl ReadyFileAdmission {
    pub(super) fn new(semaphore: Arc<Semaphore>) -> Self {
        Self {
            semaphore,
            state: Mutex::new(State {
                queues: std::array::from_fn(|_| BTreeMap::new()),
                next_ticket: 0,
                next_class: ReadyClass::Large as usize,
                running: false,
            }),
            changed: Notify::new(),
        }
    }

    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|error| error.into_inner())
    }

    #[tracing::instrument(
        target = "lpm_install_timeline",
        level = "trace",
        name = "ready_file_admission",
        skip_all
    )]
    pub(super) async fn acquire(
        self: &Arc<Self>,
        class: ReadyClass,
    ) -> Result<OwnedSemaphorePermit, LpmError> {
        let (receiver, mut ticket, dispatcher) = {
            let mut state = self.state();
            if !state.running && state.is_empty() {
                match self.semaphore.clone().try_acquire_owned() {
                    Ok(permit) => return Ok(permit),
                    Err(tokio::sync::TryAcquireError::NoPermits) => {}
                    Err(tokio::sync::TryAcquireError::Closed) => return Err(admission_closed()),
                }
            }
            let id = state.next_ticket;
            state.next_ticket = id.checked_add(1).ok_or_else(admission_closed)?;
            let (sender, receiver) = oneshot::channel();
            state.queues[class as usize].insert(id, sender);
            let dispatcher = if state.running {
                None
            } else {
                state.running = true;
                Some(Dispatcher {
                    admission: Arc::clone(self),
                    armed: true,
                })
            };
            (
                receiver,
                Ticket {
                    admission: Arc::clone(self),
                    class: class as usize,
                    id: Some(id),
                },
                dispatcher,
            )
        };
        if let Some(dispatcher) = dispatcher {
            tokio::spawn(dispatcher.run());
        }
        self.changed.notify_one();
        let permit = receiver.await.map_err(|_| admission_closed())?;
        ticket.id = None;
        Ok(permit)
    }
}

fn admission_closed() -> LpmError {
    LpmError::Registry("ready-file extraction admission closed unexpectedly".into())
}

struct Ticket {
    admission: Arc<ReadyFileAdmission>,
    class: usize,
    id: Option<u64>,
}

impl Drop for Ticket {
    fn drop(&mut self) {
        if let Some(id) = self.id {
            let sender = self.admission.state().queues[self.class].remove(&id);
            drop(sender);
            self.admission.changed.notify_one();
        }
    }
}

struct Dispatcher {
    admission: Arc<ReadyFileAdmission>,
    armed: bool,
}

impl Dispatcher {
    async fn run(mut self) {
        loop {
            // Queue arrivals must not reset our position among streaming semaphore waiters.
            let acquire = self.admission.semaphore.clone().acquire_owned();
            tokio::pin!(acquire);
            let permit = loop {
                let changed = self.admission.changed.notified();
                tokio::pin!(changed);
                changed.as_mut().enable();
                {
                    let mut state = self.admission.state();
                    if state.is_empty() {
                        state.running = false;
                        self.armed = false;
                        self.admission.changed.notify_waiters();
                        return;
                    }
                }
                tokio::select! {
                    biased;
                    result = &mut acquire => break result,
                    () = &mut changed => {}
                }
            };
            let Ok(mut permit) = permit else {
                return;
            };
            loop {
                let next = self.admission.state().pop();
                let Some((class, reply)) = next else {
                    break;
                };
                match reply.send(permit) {
                    Ok(()) => {
                        self.admission.state().next_class = 1 - class;
                        break;
                    }
                    Err(returned) => permit = returned,
                }
            }
        }
    }
}

impl Drop for Dispatcher {
    fn drop(&mut self) {
        if self.armed {
            let queues = {
                let mut state = self.admission.state();
                state.running = false;
                std::mem::take(&mut state.queues)
            };
            drop(queues);
            self.admission.changed.notify_waiters();
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use futures::poll;

    use super::*;

    #[test]
    fn unknown_and_small_files_share_the_ordinary_class() {
        let threshold = super::super::fetch::LARGE_V2_STREAMING_OBJECT_BYTES;
        assert_eq!(ReadyClass::for_unpacked_size(None), ReadyClass::Ordinary);
        assert_eq!(
            ReadyClass::for_unpacked_size(std::num::NonZeroU64::new(threshold - 1)),
            ReadyClass::Ordinary
        );
        assert_eq!(
            ReadyClass::for_unpacked_size(std::num::NonZeroU64::new(threshold)),
            ReadyClass::Large
        );
    }

    async fn receive<F: std::future::Future>(future: F) -> F::Output {
        tokio::time::timeout(Duration::from_secs(2), future)
            .await
            .expect("admission must make progress")
    }

    async fn wait_idle(admission: &ReadyFileAdmission) {
        receive(async {
            loop {
                let changed = admission.changed.notified();
                tokio::pin!(changed);
                changed.as_mut().enable();
                if !admission.state().running {
                    return;
                }
                changed.await;
            }
        })
        .await;
    }

    fn manual_dispatcher(admission: &Arc<ReadyFileAdmission>) -> Dispatcher {
        admission.state().running = true;
        Dispatcher {
            admission: Arc::clone(admission),
            armed: true,
        }
    }

    #[tokio::test]
    async fn ready_large_file_overtakes_ordinary_work_queued_while_capacity_is_busy() {
        let semaphore = Arc::new(Semaphore::new(1));
        let held = semaphore.clone().acquire_owned().await.unwrap();
        let admission = Arc::new(ReadyFileAdmission::new(semaphore.clone()));
        let mut dispatcher = Box::pin(manual_dispatcher(&admission).run());
        let ordinary = admission.acquire(ReadyClass::Ordinary);
        tokio::pin!(ordinary);
        assert!(poll!(&mut ordinary).is_pending());
        assert!(poll!(&mut dispatcher).is_pending());
        let large = admission.acquire(ReadyClass::Large);
        tokio::pin!(large);
        assert!(poll!(&mut large).is_pending());
        drop(held);
        assert!(poll!(&mut dispatcher).is_pending());
        drop(receive(large).await.unwrap());
        assert!(poll!(&mut dispatcher).is_ready());
        drop(receive(ordinary).await.unwrap());
        wait_idle(&admission).await;
        assert_eq!(semaphore.available_permits(), 1);
    }

    #[tokio::test]
    async fn both_classes_alternate_and_preserve_fifo_within_each_class() {
        let semaphore = Arc::new(Semaphore::new(1));
        let held = semaphore.clone().acquire_owned().await.unwrap();
        let admission = Arc::new(ReadyFileAdmission::new(semaphore));
        let mut futures = [
            ReadyClass::Ordinary,
            ReadyClass::Large,
            ReadyClass::Large,
            ReadyClass::Ordinary,
        ]
        .map(|class| Box::pin(admission.acquire(class)));
        for future in &mut futures {
            assert!(poll!(future).is_pending());
        }
        drop(held);
        for index in [1, 0, 2, 3] {
            drop(receive(&mut futures[index]).await.unwrap());
        }
        wait_idle(&admission).await;
    }

    #[tokio::test]
    async fn cancelling_every_ticket_retires_dispatcher_while_capacity_stays_held() {
        let semaphore = Arc::new(Semaphore::new(1));
        let _held = semaphore.clone().acquire_owned().await.unwrap();
        let admission = Arc::new(ReadyFileAdmission::new(semaphore));
        let mut dispatcher = Box::pin(manual_dispatcher(&admission).run());
        let mut waiting = Box::pin(admission.acquire(ReadyClass::Large));
        assert!(poll!(&mut waiting).is_pending());
        assert!(poll!(&mut dispatcher).is_pending());
        drop(waiting);
        assert!(poll!(&mut dispatcher).is_ready());
        drop(dispatcher);
        wait_idle(&admission).await;
        assert!(admission.state().is_empty());
        let weak = Arc::downgrade(&admission);
        drop(admission);
        assert!(weak.upgrade().is_none());
    }

    #[tokio::test]
    async fn closed_semaphore_wakes_all_queued_and_future_requests() {
        let semaphore = Arc::new(Semaphore::new(0));
        let admission = Arc::new(ReadyFileAdmission::new(semaphore.clone()));
        let mut one = Box::pin(admission.acquire(ReadyClass::Large));
        let mut two = Box::pin(admission.acquire(ReadyClass::Ordinary));
        assert!(poll!(&mut one).is_pending());
        assert!(poll!(&mut two).is_pending());
        semaphore.close();
        assert!(receive(one).await.is_err());
        assert!(receive(two).await.is_err());
        assert!(receive(admission.acquire(ReadyClass::Large)).await.is_err());
        wait_idle(&admission).await;
    }

    #[tokio::test]
    async fn queue_changes_preserve_semaphore_position_ahead_of_later_streaming_work() {
        let semaphore = Arc::new(Semaphore::new(1));
        let held = semaphore.clone().acquire_owned().await.unwrap();
        let admission = Arc::new(ReadyFileAdmission::new(semaphore.clone()));
        let mut dispatcher = Box::pin(manual_dispatcher(&admission).run());
        let mut first = Box::pin(admission.acquire(ReadyClass::Ordinary));
        assert!(poll!(&mut first).is_pending());
        assert!(poll!(&mut dispatcher).is_pending());
        let mut stream = Box::pin(semaphore.clone().acquire_owned());
        assert!(poll!(&mut stream).is_pending());
        let mut large = Box::pin(admission.acquire(ReadyClass::Large));
        assert!(poll!(&mut large).is_pending());
        assert!(poll!(&mut dispatcher).is_pending());
        drop(held);
        assert!(poll!(&mut dispatcher).is_pending());
        drop(receive(large).await.unwrap());
        drop(receive(stream).await.unwrap());
        assert!(poll!(&mut dispatcher).is_ready());
        drop(receive(first).await.unwrap());
    }

    #[tokio::test]
    async fn cancelled_receiver_releases_an_already_delivered_permit() {
        let semaphore = Arc::new(Semaphore::new(1));
        let held = semaphore.clone().acquire_owned().await.unwrap();
        let admission = Arc::new(ReadyFileAdmission::new(semaphore.clone()));
        let mut waiting = Box::pin(admission.acquire(ReadyClass::Large));
        assert!(poll!(&mut waiting).is_pending());
        drop(held);
        wait_idle(&admission).await;
        assert_eq!(semaphore.available_permits(), 0);
        drop(waiting);
        assert_eq!(semaphore.available_permits(), 1);
    }

    #[tokio::test]
    async fn failed_delivery_reuses_capacity_without_consuming_a_class_turn() {
        let semaphore = Arc::new(Semaphore::new(1));
        let held = semaphore.clone().acquire_owned().await.unwrap();
        let admission = Arc::new(ReadyFileAdmission::new(semaphore.clone()));
        let (sender, receiver) = oneshot::channel();
        drop(receiver);
        {
            let mut state = admission.state();
            state.queues[0].insert(0, sender);
            state.next_ticket = 1;
        }
        let mut ordinary = Box::pin(admission.acquire(ReadyClass::Ordinary));
        let mut large = Box::pin(admission.acquire(ReadyClass::Large));
        assert!(poll!(&mut ordinary).is_pending());
        assert!(poll!(&mut large).is_pending());
        drop(held);
        drop(receive(large).await.unwrap());
        drop(receive(ordinary).await.unwrap());
        wait_idle(&admission).await;
        assert_eq!(semaphore.available_permits(), 1);
    }

    #[tokio::test]
    async fn dropping_an_unstarted_dispatcher_drains_waiters_and_allows_replacement() {
        let semaphore = Arc::new(Semaphore::new(0));
        let admission = Arc::new(ReadyFileAdmission::new(semaphore.clone()));
        let (sender, receiver) = oneshot::channel();
        {
            let mut state = admission.state();
            state.queues[0].insert(0, sender);
            state.next_ticket = 1;
            state.running = true;
        }
        drop(
            Dispatcher {
                admission: Arc::clone(&admission),
                armed: true,
            }
            .run(),
        );
        assert!(receiver.await.is_err());
        assert!(!admission.state().running);
        let mut replacement = Box::pin(admission.acquire(ReadyClass::Ordinary));
        assert!(poll!(&mut replacement).is_pending());
        semaphore.add_permits(1);
        drop(receive(replacement).await.unwrap());
        wait_idle(&admission).await;
    }

    #[tokio::test]
    async fn delivered_ticket_guard_cannot_remove_a_successor_after_dispatcher_retires() {
        let semaphore = Arc::new(Semaphore::new(1));
        let held = semaphore.clone().acquire_owned().await.unwrap();
        let admission = Arc::new(ReadyFileAdmission::new(semaphore.clone()));
        let mut old = Box::pin(admission.acquire(ReadyClass::Large));
        assert!(poll!(&mut old).is_pending());
        drop(held);
        wait_idle(&admission).await;
        let mut new = Box::pin(admission.acquire(ReadyClass::Large));
        assert!(poll!(&mut new).is_pending());
        drop(old);
        drop(receive(new).await.unwrap());
        wait_idle(&admission).await;
    }

    #[tokio::test]
    async fn dropping_a_pending_dispatcher_releases_its_position_and_wakes_both_classes() {
        let semaphore = Arc::new(Semaphore::new(1));
        let held = semaphore.clone().acquire_owned().await.unwrap();
        let admission = Arc::new(ReadyFileAdmission::new(semaphore.clone()));
        let mut dispatcher = Box::pin(manual_dispatcher(&admission).run());
        let mut ordinary = Box::pin(admission.acquire(ReadyClass::Ordinary));
        let mut large = Box::pin(admission.acquire(ReadyClass::Large));
        assert!(poll!(&mut ordinary).is_pending());
        assert!(poll!(&mut large).is_pending());
        assert!(poll!(&mut dispatcher).is_pending());
        drop(dispatcher);
        assert!(receive(ordinary).await.is_err());
        assert!(receive(large).await.is_err());
        assert!(admission.state().is_empty());
        drop(held);
        drop(receive(admission.acquire(ReadyClass::Large)).await.unwrap());
        assert_eq!(semaphore.available_permits(), 1);
    }

    #[tokio::test]
    async fn a_weighted_stream_at_the_head_keeps_its_reserved_capacity() {
        let semaphore = Arc::new(Semaphore::new(2));
        let mut held = semaphore.clone().acquire_many_owned(2).await.unwrap();
        let one = held.split(1).unwrap();
        let mut stream = Box::pin(semaphore.clone().acquire_many_owned(2));
        assert!(poll!(&mut stream).is_pending());
        let admission = Arc::new(ReadyFileAdmission::new(semaphore.clone()));
        let mut dispatcher = Box::pin(manual_dispatcher(&admission).run());
        let mut file = Box::pin(admission.acquire(ReadyClass::Large));
        assert!(poll!(&mut file).is_pending());
        assert!(poll!(&mut dispatcher).is_pending());
        drop(one);
        assert!(poll!(&mut stream).is_pending());
        assert!(poll!(&mut dispatcher).is_pending());
        assert_eq!(semaphore.available_permits(), 0);
        drop(held);
        let stream_permit = receive(stream).await.unwrap();
        assert_eq!(stream_permit.num_permits(), 2);
        assert!(poll!(&mut dispatcher).is_pending());
        drop(stream_permit);
        assert!(poll!(&mut dispatcher).is_ready());
        drop(receive(file).await.unwrap());
        assert_eq!(semaphore.available_permits(), 2);
    }
}
