use std::ffi::OsString;
use std::sync::{Mutex, MutexGuard};

static ENV_LOCK: Mutex<()> = Mutex::new(());

#[cfg(test)]
thread_local! {
    static ENV_LOCK_CONTENTION_SIGNAL: std::cell::RefCell<Option<std::sync::mpsc::Sender<()>>> =
        const { std::cell::RefCell::new(None) };
}

pub(crate) fn lock_env() -> MutexGuard<'static, ()> {
    #[cfg(test)]
    match ENV_LOCK.try_lock() {
        Ok(guard) => return guard,
        Err(std::sync::TryLockError::Poisoned(poisoned)) => {
            return poisoned.into_inner();
        }
        Err(std::sync::TryLockError::WouldBlock) => {
            ENV_LOCK_CONTENTION_SIGNAL.with(|signal| {
                if let Some(signal) = signal.borrow_mut().take() {
                    signal.send(()).unwrap();
                }
            });
        }
    }

    ENV_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[cfg(test)]
pub(crate) fn signal_next_env_lock_contention(signal: std::sync::mpsc::Sender<()>) {
    ENV_LOCK_CONTENTION_SIGNAL.with(|slot| {
        assert!(
            slot.borrow_mut().replace(signal).is_none(),
            "environment lock contention signal already registered for this thread"
        );
    });
}

pub(crate) struct ScopedEnv {
    previous: Vec<(&'static str, Option<OsString>)>,
    _guard: MutexGuard<'static, ()>,
}

impl ScopedEnv {
    pub(crate) fn set<I>(vars: I) -> Self
    where
        I: IntoIterator<Item = (&'static str, OsString)>,
    {
        Self::update(vars.into_iter().map(|(key, value)| (key, Some(value))))
    }

    pub(crate) fn update<I>(vars: I) -> Self
    where
        I: IntoIterator<Item = (&'static str, Option<OsString>)>,
    {
        let vars = vars.into_iter().collect::<Vec<_>>();
        let guard = lock_env();
        let previous = vars
            .iter()
            .map(|(key, _)| (*key, std::env::var_os(key)))
            .collect();

        for (key, value) in &vars {
            // SAFETY: ENV_LOCK serializes test-owned process-environment mutations.
            unsafe {
                match value {
                    Some(value) => std::env::set_var(key, value),
                    None => std::env::remove_var(key),
                }
            }
        }

        Self {
            previous,
            _guard: guard,
        }
    }
}

impl Drop for ScopedEnv {
    fn drop(&mut self) {
        for (key, value) in self.previous.iter().rev() {
            // SAFETY: this guard retains ENV_LOCK until restoration completes.
            unsafe {
                match value {
                    Some(value) => std::env::set_var(key, value),
                    None => std::env::remove_var(key),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;
    use std::time::Duration;

    #[test]
    fn scoped_overrides_serialize_threads_and_restore_previous_values() {
        const KEY: &str = "LPM_TEST_SHARED_ENV_BOUNDARY";
        let original = std::env::var_os(KEY);
        // SAFETY: KEY is private to this test and has no concurrent readers or writers.
        unsafe { std::env::set_var(KEY, "baseline") };
        let (first_ready_tx, first_ready_rx) = mpsc::channel();
        let (release_first_tx, release_first_rx) = mpsc::channel();
        let (second_started_tx, second_started_rx) = mpsc::channel();
        let (second_acquired_tx, second_acquired_rx) = mpsc::channel();

        let first = std::thread::spawn(move || {
            let _env = ScopedEnv::set([(KEY, OsString::from("first"))]);
            first_ready_tx.send(()).unwrap();
            release_first_rx.recv().unwrap();
            assert_eq!(std::env::var_os(KEY), Some(OsString::from("first")));
        });
        first_ready_rx.recv().unwrap();

        let second = std::thread::spawn(move || {
            second_started_tx.send(()).unwrap();
            let _env = ScopedEnv::set([(KEY, OsString::from("second"))]);
            second_acquired_tx.send(std::env::var_os(KEY)).unwrap();
        });

        second_started_rx.recv().unwrap();
        assert!(
            second_acquired_rx
                .recv_timeout(Duration::from_millis(50))
                .is_err(),
            "second override acquired the process environment before the first guard dropped"
        );
        release_first_tx.send(()).unwrap();
        assert_eq!(
            second_acquired_rx
                .recv_timeout(Duration::from_secs(2))
                .unwrap(),
            Some(OsString::from("second"))
        );
        first.join().unwrap();
        second.join().unwrap();
        assert_eq!(std::env::var_os(KEY), Some(OsString::from("baseline")));
        // SAFETY: both worker threads have joined and KEY is private to this test.
        unsafe {
            match original {
                Some(value) => std::env::set_var(KEY, value),
                None => std::env::remove_var(KEY),
            }
        }
    }

    #[test]
    fn scoped_overrides_restore_previous_values_after_unwind() {
        const KEY: &str = "LPM_TEST_PANIC_ENV_RESTORE";
        let original = std::env::var_os(KEY);
        // SAFETY: KEY is private to this test and has no concurrent readers or writers.
        unsafe { std::env::set_var(KEY, "baseline") };

        let result = std::panic::catch_unwind(|| {
            let _env = ScopedEnv::set([(KEY, OsString::from("temporary"))]);
            panic!("exercise ScopedEnv drop during unwind");
        });

        assert!(result.is_err());
        assert_eq!(std::env::var_os(KEY), Some(OsString::from("baseline")));
        // SAFETY: the unwind completed and KEY is private to this test.
        unsafe {
            match original {
                Some(value) => std::env::set_var(KEY, value),
                None => std::env::remove_var(KEY),
            }
        }
    }

    #[test]
    fn scoped_env_restores_previous_value_on_drop() {
        const KEY: &str = "LPM_TEST_SCOPED_ENV_RESTORE";
        let previous = std::env::var_os(KEY);
        {
            let _env = ScopedEnv::set([(KEY, OsString::from("temporary"))]);
            assert_eq!(std::env::var_os(KEY), Some(OsString::from("temporary")));
        }
        assert_eq!(std::env::var_os(KEY), previous);
    }
}
