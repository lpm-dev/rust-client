use std::ffi::OsString;
use std::sync::{Mutex, MutexGuard};

static ENV_LOCK: Mutex<()> = Mutex::new(());

pub(crate) fn lock_env() -> MutexGuard<'static, ()> {
    ENV_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
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