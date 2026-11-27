use crate::output::{CompletedFile, Identity, NewFile, PendingFile};
use lpm_common::LpmError;
use std::collections::VecDeque;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Weak, mpsc};
use std::thread::JoinHandle;

pub(super) const MAX_ENTRY_BYTES: usize = 512 * 1024;
pub(super) const MAX_PENDING_BYTES: usize = 4 * 1024 * 1024;
pub(super) const MAX_PENDING_ENTRIES: usize = 64;
const JOB_BATCH_MAX_FILES: usize = 16;
const JOB_BATCH_MAX_BYTES: usize = 128 * 1024;
const MAX_WRITER_POOLS: usize = 4;
static ACTIVE_WRITER_POOLS: AtomicUsize = AtomicUsize::new(0);

struct PendingBatch {
    jobs: Vec<Job>,
    bytes: usize,
    sender: Option<mpsc::Sender<Vec<Job>>>,
}

impl PendingBatch {
    fn flush(&mut self) -> Result<(), LpmError> {
        if self.jobs.is_empty() {
            return Ok(());
        }
        let batch = std::mem::replace(&mut self.jobs, Vec::with_capacity(JOB_BATCH_MAX_FILES));
        self.bytes = 0;
        self.sender
            .as_ref()
            .ok_or_else(|| io::Error::other("tarball file writers already stopped"))?
            .send(batch)
            .map_err(|_| io::Error::other("tarball file writers disconnected").into())
    }
}

struct BusyWorkerGuard(Arc<AtomicUsize>);

impl Drop for BusyWorkerGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

#[derive(Default)]
pub(super) struct FailureSignal {
    active: AtomicBool,
    failed: AtomicBool,
    pending_batch: Mutex<Option<Weak<Mutex<PendingBatch>>>>,
}

impl FailureSignal {
    pub(super) fn is_active(&self) -> bool {
        self.active.load(Ordering::Acquire)
    }

    pub(super) fn has_failed(&self) -> bool {
        self.failed.load(Ordering::Acquire)
    }

    fn attach_pending_batch(&self, batch: Weak<Mutex<PendingBatch>>) {
        *self
            .pending_batch
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(batch);
    }

    pub(super) fn flush_pending_batch(&self) {
        let batch = self
            .pending_batch
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
            .and_then(Weak::upgrade);
        if let Some(batch) = batch {
            let mut guard = batch
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let _ = guard.flush();
        }
    }
}

struct WriterAdmission(&'static AtomicUsize);

impl WriterAdmission {
    fn acquire(active: &'static AtomicUsize, capacity: usize) -> Option<Arc<Self>> {
        active
            .try_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                (count < capacity).then_some(count + 1)
            })
            .ok()
            .map(|_| Arc::new(Self(active)))
    }
}

impl Drop for WriterAdmission {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

#[cfg(unix)]
fn pool_capacity_for_descriptor_limit(limit: u64) -> usize {
    // Each queued file can retain a distinct parent; leave half for other I/O.
    let descriptors_per_pool = (2 * MAX_PENDING_ENTRIES + 8) as u64;
    (limit / 2 / descriptors_per_pool).min(MAX_WRITER_POOLS as u64) as usize
}

pub(super) fn writer_pool_capacity() -> usize {
    #[cfg(unix)]
    {
        let mut limit = std::mem::MaybeUninit::<libc::rlimit>::uninit();
        // SAFETY: getrlimit initializes this valid out pointer on success.
        if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, limit.as_mut_ptr()) } != 0 {
            return 0;
        }
        // SAFETY: getrlimit succeeded.
        let limit = unsafe { limit.assume_init() };
        pool_capacity_for_descriptor_limit(limit.rlim_cur)
    }
    #[cfg(not(unix))]
    {
        MAX_WRITER_POOLS
    }
}

pub(super) enum WriterSetup {
    Disabled,
    AfterFiles {
        count: usize,
        minimum: usize,
        failure: Option<Arc<FailureSignal>>,
        #[cfg(test)]
        hooks: TestHooks,
    },
    #[cfg(test)]
    Ready(WriterPool),
}

impl WriterSetup {
    pub(super) fn configured() -> Self {
        let default_count = lpm_common::resources::effective_cpu_count().clamp(1, 2);
        let count = std::env::var("LPM_INTERNAL_EXTRACT_WRITERS")
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(default_count)
            .min(8);
        if count == 0 {
            Self::Disabled
        } else {
            Self::AfterFiles {
                count,
                minimum: 256,
                failure: None,
                #[cfg(test)]
                hooks: TestHooks::default(),
            }
        }
    }

    pub(super) fn with_minimum_files(mut self, min_files: usize) -> Self {
        if let Self::AfterFiles { minimum, .. } = &mut self {
            *minimum = min_files;
        }
        self
    }

    pub(super) fn with_failure_signal(mut self, signal: Arc<FailureSignal>) -> Self {
        if let Self::AfterFiles { failure, .. } = &mut self {
            *failure = Some(signal);
        }
        self
    }

    pub(super) fn start_if_ready(&mut self, extracted: usize) -> Option<WriterPool> {
        match self {
            Self::Disabled => None,
            Self::AfterFiles {
                count,
                minimum,
                failure,
                #[cfg(test)]
                hooks,
            } if extracted >= *minimum => {
                let Some(admission) =
                    WriterAdmission::acquire(&ACTIVE_WRITER_POOLS, writer_pool_capacity())
                else {
                    *self = Self::Disabled;
                    return None;
                };
                let pool = WriterPool::new_with_hooks(
                    *count,
                    #[cfg(test)]
                    hooks.clone(),
                    failure.clone(),
                );
                *self = Self::Disabled;
                let Ok(mut pool) = pool else {
                    return None;
                };
                pool.admission = Some(admission);
                Some(pool)
            }
            Self::AfterFiles { .. } => None,
            #[cfg(test)]
            Self::Ready(_) => match std::mem::replace(self, Self::Disabled) {
                Self::Ready(pool) => Some(pool),
                _ => unreachable!(),
            },
        }
    }
}

pub(super) struct Job {
    pub sequence: usize,
    pub target: NewFile,
    pub bytes: Vec<u8>,
    pub exec_bits: u32,
    pub compute_blake3: bool,
}

/// A job whose output file the worker has created.
pub(super) struct OpenedJob {
    #[cfg(test)]
    pub sequence: usize,
    pub output: PendingFile,
    pub bytes: Vec<u8>,
    pub exec_bits: u32,
    pub compute_blake3: bool,
}

impl Job {
    fn open(self) -> Result<OpenedJob, LpmError> {
        Ok(OpenedJob {
            #[cfg(test)]
            sequence: self.sequence,
            output: self.target.create()?,
            bytes: self.bytes,
            exec_bits: self.exec_bits,
            compute_blake3: self.compute_blake3,
        })
    }
}

pub(super) struct Written {
    pub output: CompletedFile,
    pub digest: Option<[u8; 32]>,
}

pub(super) struct Completion {
    pub sequence: usize,
    pub result: Result<Written, LpmError>,
}

struct Slot {
    path: PathBuf,
    bytes: usize,
    result: Option<Result<Written, LpmError>>,
}

/// Files submitted to the writers, accepted in archive order as they complete.
pub(super) struct PendingEntries {
    slots: VecDeque<Slot>,
    /// Sequence number of the front slot.
    front_sequence: usize,
    bytes: usize,
    #[cfg(test)]
    observer: Option<TestObserver>,
    _admission: Option<Arc<WriterAdmission>>,
}

impl PendingEntries {
    pub(super) fn new(_pool: &WriterPool) -> Self {
        Self {
            slots: VecDeque::with_capacity(MAX_PENDING_ENTRIES),
            front_sequence: 0,
            bytes: 0,
            #[cfg(test)]
            observer: _pool.hooks.observer.clone(),
            _admission: _pool.admission.clone(),
        }
    }

    pub(super) fn len(&self) -> usize {
        self.slots.len()
    }

    pub(super) fn path(&self, index: usize) -> Option<&Path> {
        self.slots.get(index).map(|slot| slot.path.as_path())
    }

    pub(super) fn next_sequence(&self) -> usize {
        self.front_sequence + self.slots.len()
    }

    pub(super) fn has_capacity(&self, bytes: usize) -> bool {
        self.slots.len() < MAX_PENDING_ENTRIES
            && bytes <= MAX_PENDING_BYTES.saturating_sub(self.bytes)
    }

    pub(super) fn push(&mut self, path: PathBuf, capacity: usize) {
        self.push_slot(Slot {
            path,
            bytes: capacity,
            result: None,
        });
    }

    /// Queue a file this thread already wrote, so it is accepted in archive
    /// order behind the files the writers are still writing.
    pub(super) fn push_written(&mut self, path: PathBuf, written: Written) {
        self.push_slot(Slot {
            path,
            bytes: 0,
            result: Some(Ok(written)),
        });
    }

    fn push_slot(&mut self, slot: Slot) {
        self.bytes += slot.bytes;
        self.slots.push_back(slot);
        #[cfg(test)]
        self.observe(TestEvent::Admitted {
            entries: self.slots.len(),
            bytes: self.bytes,
        });
    }

    /// Accept the completed entries at the front without waiting.
    pub(super) fn accept_ready<E: crate::ExtractionRecord>(
        &mut self,
        pool: &mut WriterPool,
        records: &mut Vec<E>,
        identities: &mut Vec<Identity>,
    ) -> Result<(), LpmError> {
        while let Some(completion) = pool.try_receive()? {
            self.store(completion)?;
        }
        self.accept_front(records, identities)
    }

    /// Wait until `bytes` more fit, accepting the oldest entries as they complete.
    pub(super) fn make_room<E: crate::ExtractionRecord>(
        &mut self,
        pool: &mut WriterPool,
        bytes: usize,
        records: &mut Vec<E>,
        identities: &mut Vec<Identity>,
    ) -> Result<(), LpmError> {
        self.accept_ready(pool, records, identities)?;
        if self.has_capacity(bytes) {
            return Ok(());
        }
        pool.flush()?;
        #[cfg(test)]
        self.observe(TestEvent::DrainStarted);
        while !self.has_capacity(bytes) && !self.slots.is_empty() {
            self.store(pool.receive()?)?;
            self.accept_front(records, identities)?;
        }
        Ok(())
    }

    /// Wait for every entry and accept them in archive order.
    pub(super) fn drain<E: crate::ExtractionRecord>(
        &mut self,
        pool: &mut WriterPool,
        records: &mut Vec<E>,
        identities: &mut Vec<Identity>,
    ) -> Result<(), LpmError> {
        pool.flush()?;
        #[cfg(test)]
        self.observe(TestEvent::DrainStarted);
        while self.slots.iter().any(|slot| slot.result.is_none()) {
            self.store(pool.receive()?)?;
        }
        self.accept_front(records, identities)
    }

    fn store(&mut self, completion: Completion) -> Result<(), LpmError> {
        let slot = completion
            .sequence
            .checked_sub(self.front_sequence)
            .and_then(|index| self.slots.get_mut(index))
            .ok_or_else(|| io::Error::other("invalid file writer sequence"))?;
        if slot.result.is_some() {
            return Err(io::Error::other("duplicate file writer result").into());
        }
        slot.result = Some(completion.result);
        Ok(())
    }

    /// Accept front entries while their results are ready. The first failure
    /// stops acceptance; later completed files roll back when their slots drop.
    fn accept_front<E: crate::ExtractionRecord>(
        &mut self,
        records: &mut Vec<E>,
        identities: &mut Vec<Identity>,
    ) -> Result<(), LpmError> {
        while let Some(Slot {
            path,
            bytes,
            result: Some(result),
        }) = self.slots.pop_front_if(|slot| slot.result.is_some())
        {
            self.front_sequence += 1;
            self.bytes -= bytes;
            let written = result?;
            let record = E::from_extracted_file(path, written.digest)?;
            let identity = written.output.commit()?;
            records.push(record);
            identities.push(identity);
        }
        Ok(())
    }

    #[cfg(test)]
    fn observe(&self, event: TestEvent) {
        if let Some(observer) = &self.observer {
            observer(event);
        }
    }
}

pub(super) struct WriterPool {
    pending_batch: Arc<Mutex<PendingBatch>>,
    busy_workers: Arc<AtomicUsize>,
    worker_count: usize,
    ready: mpsc::Receiver<Vec<Completion>>,
    buffered_completions: VecDeque<Completion>,
    workers: Vec<JoinHandle<()>>,
    #[cfg(test)]
    hooks: TestHooks,
    admission: Option<Arc<WriterAdmission>>,
}

impl WriterPool {
    #[cfg(test)]
    pub(super) fn new(count: usize) -> Result<Self, LpmError> {
        Self::new_with_hooks(
            count,
            #[cfg(test)]
            TestHooks::default(),
            None,
        )
    }

    #[tracing::instrument(
        target = "lpm_install_timeline",
        level = "trace",
        name = "tar_entry_writer_pool",
        skip_all,
        fields(writer_count = count)
    )]
    pub(super) fn new_with_hooks(
        count: usize,
        #[cfg(test)] hooks: TestHooks,
        failure: Option<Arc<FailureSignal>>,
    ) -> Result<Self, LpmError> {
        let (sender, receiver) = mpsc::channel::<Vec<Job>>();
        let receiver = Arc::new(Mutex::new(receiver));
        let (completed, ready) = mpsc::channel::<Vec<Completion>>();
        let pending_batch = Arc::new(Mutex::new(PendingBatch {
            jobs: Vec::with_capacity(JOB_BATCH_MAX_FILES),
            bytes: 0,
            sender: Some(sender),
        }));
        let busy_workers = Arc::new(AtomicUsize::new(0));
        let mut pool = Self {
            pending_batch: Arc::clone(&pending_batch),
            busy_workers: Arc::clone(&busy_workers),
            worker_count: count,
            ready,
            buffered_completions: VecDeque::with_capacity(JOB_BATCH_MAX_FILES),
            workers: Vec::with_capacity(count),
            #[cfg(test)]
            hooks,
            admission: None,
        };
        for index in 0..count {
            #[cfg(test)]
            if let Some(before_spawn) = &pool.hooks.before_spawn {
                before_spawn(index)?;
            }
            let jobs = Arc::clone(&receiver);
            let results = completed.clone();
            let failure = failure.clone();
            let busy = Arc::clone(&busy_workers);
            #[cfg(test)]
            let hooks = pool.hooks.clone();
            pool.workers.push(
                std::thread::Builder::new()
                    .name(format!("lpm-file-{index}"))
                    .spawn(move || {
                        #[cfg(test)]
                        let _exit = TestExit(hooks.on_exit.clone());
                        loop {
                            let batch = match jobs.lock() {
                                Ok(receiver) => receiver.recv(),
                                Err(_) => return,
                            };
                            let Ok(batch) = batch else { return };
                            busy.fetch_add(1, Ordering::AcqRel);
                            let _busy_guard = BusyWorkerGuard(Arc::clone(&busy));
                            let mut completions = Vec::with_capacity(batch.len());
                            for job in batch {
                                let sequence = job.sequence;
                                let result =
                                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                                        #[cfg(test)]
                                        if let Some(before_open) = &hooks.before_open {
                                            before_open(&job)?;
                                        }
                                        let job = job.open()?;
                                        #[cfg(test)]
                                        let job = {
                                            let mut job = job;
                                            if let Some(before_write) = &hooks.before_write {
                                                before_write(&mut job)?;
                                            }
                                            job
                                        };
                                        let written = write(job)?;
                                        #[cfg(test)]
                                        if let Some(after_write) = &hooks.after_write {
                                            after_write(&written)?;
                                        }
                                        Ok(written)
                                    }))
                                    .unwrap_or_else(|_| {
                                        Err(io::Error::other("tarball file writer panicked").into())
                                    });
                                if result.is_err()
                                    && let Some(failure) = &failure
                                {
                                    failure.failed.store(true, Ordering::Release);
                                }
                                completions.push(Completion { sequence, result });
                                #[cfg(test)]
                                if let Some(observer) = &hooks.observer {
                                    observer(TestEvent::Completed { sequence });
                                }
                            }
                            if results.send(completions).is_err() {
                                return;
                            }
                        }
                    })?,
            );
        }
        if let Some(failure) = failure {
            failure.attach_pending_batch(Arc::downgrade(&pending_batch));
            failure.active.store(true, Ordering::Release);
        }
        Ok(pool)
    }

    pub(super) fn submit(&mut self, job: Job) -> Result<(), LpmError> {
        let job_bytes = job.bytes.len();
        let mut batch = self
            .pending_batch
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !batch.jobs.is_empty() && batch.bytes.saturating_add(job_bytes) > JOB_BATCH_MAX_BYTES {
            batch.flush()?;
        }
        batch.jobs.push(job);
        batch.bytes = batch.bytes.saturating_add(job_bytes);
        // Dispatch immediately whenever any writer thread is idle so small
        // packages (4-64 files) use full writer parallelism; accumulate up to
        // JOB_BATCH_MAX_FILES while all writers are busy.
        let writer_idle = self.busy_workers.load(Ordering::Acquire) < self.worker_count;
        if writer_idle
            || batch.jobs.len() >= JOB_BATCH_MAX_FILES
            || batch.bytes >= JOB_BATCH_MAX_BYTES
        {
            batch.flush()?;
        }
        Ok(())
    }

    pub(super) fn flush(&mut self) -> Result<(), LpmError> {
        let mut batch = self
            .pending_batch
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        batch.flush()
    }

    pub(super) fn receive(&mut self) -> Result<Completion, LpmError> {
        if let Some(completion) = self.buffered_completions.pop_front() {
            return Ok(completion);
        }
        self.flush()?;
        loop {
            let batch = self
                .ready
                .recv()
                .map_err(|_| io::Error::other("tarball file writers stopped before completion"))?;
            self.buffered_completions.extend(batch);
            if let Some(completion) = self.buffered_completions.pop_front() {
                return Ok(completion);
            }
        }
    }

    fn try_receive(&mut self) -> Result<Option<Completion>, LpmError> {
        if let Some(completion) = self.buffered_completions.pop_front() {
            return Ok(Some(completion));
        }
        loop {
            match self.ready.try_recv() {
                Ok(batch) => {
                    self.buffered_completions.extend(batch);
                    if let Some(completion) = self.buffered_completions.pop_front() {
                        return Ok(Some(completion));
                    }
                }
                Err(mpsc::TryRecvError::Empty) => return Ok(None),
                Err(mpsc::TryRecvError::Disconnected) => {
                    return Err(
                        io::Error::other("tarball file writers stopped before completion").into(),
                    );
                }
            }
        }
    }

    pub(super) fn finish(mut self) -> Result<(), LpmError> {
        self.join()
    }

    fn join(&mut self) -> Result<(), LpmError> {
        {
            let mut batch = self
                .pending_batch
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let _ = batch.flush();
            batch.sender.take();
        }
        let mut failed = false;
        for worker in self.workers.drain(..) {
            failed |= worker.join().is_err();
        }
        if failed {
            Err(io::Error::other("tarball file writer panicked").into())
        } else {
            Ok(())
        }
    }
}

impl Drop for WriterPool {
    fn drop(&mut self) {
        let _ = self.join();
    }
}

fn write(mut job: OpenedJob) -> Result<Written, LpmError> {
    job.output.file.write_all(&job.bytes)?;
    let digest = job
        .compute_blake3
        .then(|| *blake3::hash(&job.bytes).as_bytes());
    #[cfg(unix)]
    if job.exec_bits != 0 {
        use std::os::unix::fs::PermissionsExt;
        job.output
            .file
            .set_permissions(std::fs::Permissions::from_mode(0o644 | job.exec_bits))?;
    }
    #[cfg(not(unix))]
    let _ = job.exec_bits;
    Ok(Written {
        output: job.output.complete()?,
        digest,
    })
}

#[cfg(test)]
pub(super) type TestObserver = Arc<dyn Fn(TestEvent) + Send + Sync>;
#[cfg(test)]
type BeforeOpen = Arc<dyn Fn(&Job) -> Result<(), LpmError> + Send + Sync>;
#[cfg(test)]
type BeforeWrite = Arc<dyn Fn(&mut OpenedJob) -> Result<(), LpmError> + Send + Sync>;
#[cfg(test)]
type AfterWrite = Arc<dyn Fn(&Written) -> Result<(), LpmError> + Send + Sync>;

#[cfg(test)]
#[derive(Clone, Copy, Debug)]
pub(super) enum TestEvent {
    Admitted { entries: usize, bytes: usize },
    DrainStarted,
    Completed { sequence: usize },
}

#[cfg(test)]
#[derive(Clone, Default)]
pub(super) struct TestHooks {
    pub before_spawn: Option<Arc<dyn Fn(usize) -> io::Result<()> + Send + Sync>>,
    pub before_open: Option<BeforeOpen>,
    pub before_write: Option<BeforeWrite>,
    pub after_write: Option<AfterWrite>,
    pub on_exit: Option<Arc<dyn Fn() + Send + Sync>>,
    pub observer: Option<TestObserver>,
}

#[cfg(test)]
struct TestExit(Option<Arc<dyn Fn() + Send + Sync>>);

#[cfg(test)]
impl Drop for TestExit {
    fn drop(&mut self) {
        if let Some(exit) = &self.0 {
            exit();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writer_admission_is_bounded_and_retained_by_pending_results() {
        static ACTIVE: AtomicUsize = AtomicUsize::new(0);
        assert!(WriterAdmission::acquire(&ACTIVE, 0).is_none());
        let mut pool = WriterPool::new(1).unwrap();
        pool.admission = Some(WriterAdmission::acquire(&ACTIVE, 1).unwrap());
        let pending = PendingEntries::new(&pool);
        assert!(WriterAdmission::acquire(&ACTIVE, 1).is_none());
        drop(pool);
        assert!(WriterAdmission::acquire(&ACTIVE, 1).is_none());
        drop(pending);
        assert!(WriterAdmission::acquire(&ACTIVE, 1).is_some());
        assert_eq!(ACTIVE.load(Ordering::Acquire), 0);
    }

    #[cfg(unix)]
    #[test]
    fn writer_capacity_preserves_descriptor_headroom() {
        for (limit, expected) in [
            (96, 0),
            (256, 0),
            (512, 1),
            (1024, 3),
            (1088, 4),
            (u64::MAX, 4),
        ] {
            assert_eq!(pool_capacity_for_descriptor_limit(limit), expected);
        }
    }

    #[test]
    fn writer_pool_batches_when_busy_and_flushes_via_failure_signal() {
        let root = tempfile::tempdir().unwrap();
        let canonical = root.path().canonicalize().unwrap();
        let mut tree =
            crate::output::OutputTree::new(canonical, root.path().to_path_buf()).unwrap();
        let mut budget = crate::PathLedgerBudget::new(usize::MAX);

        let (entered_tx, entered_rx) = std::sync::mpsc::sync_channel::<()>(1);
        let (release_tx, release_rx) = std::sync::mpsc::sync_channel::<()>(1);
        let release_rx = Arc::new(Mutex::new(release_rx));
        let hooks = TestHooks {
            before_open: Some(Arc::new(move |job| {
                if job.sequence == 0 {
                    let _ = entered_tx.send(());
                    let _ = release_rx.lock().unwrap().recv();
                }
                Ok(())
            })),
            ..TestHooks::default()
        };
        let failure = Arc::new(FailureSignal::default());
        let mut pool = WriterPool::new_with_hooks(1, hooks, Some(Arc::clone(&failure))).unwrap();

        let make_job = |tree: &mut crate::output::OutputTree,
                        budget: &mut crate::PathLedgerBudget,
                        seq: usize,
                        name: &str| {
            let rel = Path::new(name);
            tree.prepare_parent(rel, budget).unwrap();
            Job {
                sequence: seq,
                target: tree.new_file(rel).unwrap(),
                bytes: b"ok".to_vec(),
                exec_bits: 0,
                compute_blake3: false,
            }
        };

        // Job 0 dispatches immediately because the single worker is idle.
        pool.submit(make_job(&mut tree, &mut budget, 0, "a.js"))
            .unwrap();
        entered_rx
            .recv_timeout(std::time::Duration::from_secs(2))
            .expect("idle worker must receive job 0 immediately");

        // While the worker is busy on job 0, jobs 1 and 2 accumulate in pending_batch.
        pool.submit(make_job(&mut tree, &mut budget, 1, "b.js"))
            .unwrap();
        pool.submit(make_job(&mut tree, &mut budget, 2, "c.js"))
            .unwrap();
        assert_eq!(
            pool.pending_batch.lock().unwrap().jobs.len(),
            2,
            "jobs submitted while all writers are busy must accumulate into a batch"
        );

        // FailureSignal::flush_pending_batch drains the partial batch without waiting for threshold.
        failure.flush_pending_batch();
        assert_eq!(
            pool.pending_batch.lock().unwrap().jobs.len(),
            0,
            "FailureSignal::flush_pending_batch must dispatch queued sub-threshold jobs"
        );

        release_tx.send(()).unwrap();
        for expected_seq in 0..3 {
            let completion = pool.receive().unwrap();
            assert_eq!(completion.sequence, expected_seq);
            completion.result.unwrap().output.commit().unwrap();
        }
        pool.finish().unwrap();
    }
}
