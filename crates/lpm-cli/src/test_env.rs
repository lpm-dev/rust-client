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
