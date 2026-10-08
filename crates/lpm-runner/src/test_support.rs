use std::process::Child;

pub(crate) struct KillOnDropChild(Child);

impl KillOnDropChild {
    pub(crate) fn new(child: Child) -> Self {
        Self(child)
    }

    pub(crate) fn id(&self) -> u32 {
        self.0.id()
    }

    pub(crate) fn child_mut(&mut self) -> &mut Child {
        &mut self.0
    }
}

impl Drop for KillOnDropChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn child_is_reaped_when_the_fixture_body_panics() {
    let mut pid = None;
    let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let child = KillOnDropChild::new(
            std::process::Command::new("node")
                .args(["-e", "setInterval(()=>{},1000)"])
                .spawn()
                .unwrap(),
        );
        pid = Some(child.id());
        panic!("injected fixture panic");
    }));
    assert!(panic.is_err());
    assert!(!crate::ports::process_is_running(pid.unwrap()));
}

#[cfg(unix)]
pub(crate) struct ProcessSpawners {
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    threads: Vec<std::thread::JoinHandle<()>>,
}

#[cfg(unix)]
impl ProcessSpawners {
    pub(crate) fn new() -> Self {
        let mut spawners = Self {
            stop: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            threads: Vec::with_capacity(4),
        };
        for _ in 0..4 {
            let stop = std::sync::Arc::clone(&spawners.stop);
            spawners.threads.push(std::thread::spawn(move || {
                while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                    let _ = std::process::Command::new("true").status();
                }
            }));
        }
        spawners
    }
}

#[cfg(unix)]
impl Drop for ProcessSpawners {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::Relaxed);
        let mut worker_panicked = false;
        for thread in self.threads.drain(..) {
            worker_panicked |= thread.join().is_err();
        }
        if !std::thread::panicking() {
            assert!(!worker_panicked, "process-spawning worker panicked");
        }
    }
}

#[cfg(unix)]
#[test]
fn process_spawners_stop_and_join_when_the_body_panics() {
    let mut shutdown = None;
    let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let spawners = ProcessSpawners::new();
        shutdown = Some(std::sync::Arc::downgrade(&spawners.stop));
        panic!("injected body panic");
    }));
    assert!(panic.is_err());
    let shutdown = shutdown.unwrap();
    let stopped = shutdown.upgrade().is_none();
    if let Some(stop) = shutdown.upgrade() {
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
    }
    assert!(stopped, "process-spawning workers survived the body panic");
}
