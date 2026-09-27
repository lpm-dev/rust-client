use crate::output::{CompletedFile, Identity, PendingFile};
use lpm_common::LpmError;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::thread::JoinHandle;

pub(super) const MAX_ENTRY_BYTES: usize = 256 * 1024;
pub(super) const MAX_PENDING_BYTES: usize = 4 * 1024 * 1024;
pub(super) const MAX_PENDING_ENTRIES: usize = 64;
const MAX_WRITER_POOLS: usize = 4;
static ACTIVE_WRITER_POOLS: AtomicUsize = AtomicUsize::new(0);

#[derive(Default)]
pub(super) struct FailureSignal {
    active: AtomicBool,
    failed: AtomicBool,
}

impl FailureSignal {
    pub(super) fn is_active(&self) -> bool {
        self.active.load(Ordering::Acquire)
    }

    pub(super) fn has_failed(&self) -> bool {
        self.failed.load(Ordering::Acquire)
    }
}

struct WriterAdmission(&'static AtomicUsize);

impl WriterAdmission {
    fn acquire(active: &'static AtomicUsize, capacity: usize) -> Option<Arc<Self>> {
        active
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
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
        let count = std::env::var("LPM_INTERNAL_EXTRACT_WRITERS")
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(2)
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
    pub output: PendingFile,
    pub bytes: Vec<u8>,
    pub exec_bits: u32,
    pub compute_blake3: bool,
}

pub(super) struct Written {
    pub output: CompletedFile,
    pub digest: Option<[u8; 32]>,
}

pub(super) struct Completion {
    pub sequence: usize,
    pub result: Result<Written, LpmError>,
}

pub(super) struct PendingEntries {
    paths: Vec<PathBuf>,
    results: Vec<Option<Result<Written, LpmError>>>,
    bytes: usize,
    #[cfg(test)]
    observer: Option<TestObserver>,
    _admission: Option<Arc<WriterAdmission>>,
}

impl PendingEntries {
    pub(super) fn new(_pool: &WriterPool) -> Self {
        Self {
            paths: Vec::with_capacity(MAX_PENDING_ENTRIES),
            results: Vec::with_capacity(MAX_PENDING_ENTRIES),
            bytes: 0,
            #[cfg(test)]
            observer: _pool.hooks.observer.clone(),
            _admission: _pool.admission.clone(),
        }
    }

    pub(super) fn len(&self) -> usize {
        self.paths.len()
    }

    pub(super) fn path(&self, index: usize) -> Option<&Path> {
        self.paths.get(index).map(PathBuf::as_path)
    }

    pub(super) fn has_capacity(&self, bytes: usize) -> bool {
        self.paths.len() < MAX_PENDING_ENTRIES
            && bytes <= MAX_PENDING_BYTES.saturating_sub(self.bytes)
    }

    pub(super) fn push(&mut self, path: PathBuf, capacity: usize) {
        self.paths.push(path);
        self.bytes += capacity;
        #[cfg(test)]
        self.observe(TestEvent::Admitted {
            entries: self.paths.len(),
            bytes: self.bytes,
        });
    }

    pub(super) fn drain<E: crate::ExtractionRecord>(
        &mut self,
        pool: &WriterPool,
        records: &mut Vec<E>,
        identities: &mut Vec<Identity>,
    ) -> Result<(), LpmError> {
        #[cfg(test)]
        self.observe(TestEvent::DrainStarted);
        self.results.resize_with(self.paths.len(), || None);
        let mut error = None;
        for _ in 0..self.paths.len() {
            match pool.receive() {
                Ok(completion) => {
                    let Some(slot) = self.results.get_mut(completion.sequence) else {
                        error.get_or_insert_with(|| {
                            LpmError::Io(io::Error::other("invalid file writer sequence"))
                        });
                        continue;
                    };
                    if slot.is_some() {
                        error.get_or_insert_with(|| {
                            LpmError::Io(io::Error::other("duplicate file writer result"))
                        });
                    }
                    *slot = Some(completion.result);
                }
                Err(failure) => {
                    error.get_or_insert(failure);
                    break;
                }
            }
        }
        self.bytes = 0;
        for (path, result) in self.paths.drain(..).zip(self.results.drain(..)) {
            let result = result
                .unwrap_or_else(|| Err(io::Error::other("missing file writer result").into()))
                .and_then(|written| {
                    let record = E::from_extracted_file(path, written.digest)?;
                    let identity = written.output.commit()?;
                    records.push(record);
                    identities.push(identity);
                    Ok(())
                });
            if let Err(failure) = result {
                error.get_or_insert(failure);
            }
        }
        error.map_or(Ok(()), Err)
    }

    #[cfg(test)]
    fn observe(&self, event: TestEvent) {
        if let Some(observer) = &self.observer {
            observer(event);
        }
    }
}

pub(super) struct WriterPool {
    sender: Option<mpsc::Sender<Job>>,
    ready: mpsc::Receiver<Completion>,
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
        let (sender, receiver) = mpsc::channel::<Job>();
        let receiver = Arc::new(Mutex::new(receiver));
        let (completed, ready) = mpsc::channel();
        let mut pool = Self {
            sender: Some(sender),
            ready,
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
            #[cfg(test)]
            let hooks = pool.hooks.clone();
            pool.workers.push(
                std::thread::Builder::new()
                    .name(format!("lpm-file-{index}"))
                    .spawn(move || {
                        #[cfg(test)]
                        let _exit = TestExit(hooks.on_exit.clone());
                        loop {
                            let job = match jobs.lock() {
                                Ok(receiver) => receiver.recv(),
                                Err(_) => return,
                            };
                            let Ok(job) = job else { return };
                            let sequence = job.sequence;
                            let result =
                                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
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
                            if results.send(Completion { sequence, result }).is_err() {
                                return;
                            }
                            #[cfg(test)]
                            if let Some(observer) = &hooks.observer {
                                observer(TestEvent::Completed { sequence });
                            }
                        }
                    })?,
            );
        }
        if let Some(failure) = failure {
            failure.active.store(true, Ordering::Release);
        }
        Ok(pool)
    }

    pub(super) fn submit(&self, job: Job) -> Result<(), LpmError> {
        self.sender
            .as_ref()
            .ok_or_else(|| io::Error::other("tarball file writers already stopped"))?
            .send(job)
            .map_err(|_| io::Error::other("tarball file writers disconnected").into())
    }

    pub(super) fn receive(&self) -> Result<Completion, LpmError> {
        self.ready
            .recv()
            .map_err(|_| io::Error::other("tarball file writers stopped before completion").into())
    }

    pub(super) fn finish(mut self) -> Result<(), LpmError> {
        self.join()
    }

    fn join(&mut self) -> Result<(), LpmError> {
        self.sender.take();
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

fn write(mut job: Job) -> Result<Written, LpmError> {
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
type BeforeWrite = Arc<dyn Fn(&mut Job) -> Result<(), LpmError> + Send + Sync>;
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
}
