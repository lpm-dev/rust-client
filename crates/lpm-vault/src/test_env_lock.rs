//! Crate-wide env-mutation lock for tests across `crypto.rs`,
//! `lib.rs`, `keychain.rs`, and the `sync/` modules.
//!
//! Several test helpers mutate process-wide env vars (`HOME`,
//! `LPM_FORCE_FILE_VAULT`, `LPM_TEST_FAST_SCRYPT`) inside
//! `unsafe { std::env::set_var(...) }` blocks. Because the env table
//! is process-global, every such mutation must be serialised across
//! the whole crate's test suite — not just within a single module —
//! or one module's test can read inconsistent env state set by
//! another module's concurrent test (e.g. wrapping-key fetched
//! against HOME=A before mutation, then again against HOME=B after,
//! producing different keys and a panic on the round-trip
//! assertion).
//!
//! Contract: every test that calls `std::env::set_var` for any of
//! the vars above must hold the guard returned by
//! [`acquire_env_lock`] for the entire window from "set var" through
//! "do the work that reads var" through "restore var". The guard's
//! `Drop` releases the lock.
//!
//! Poison-handling: [`acquire_env_lock`] recovers from a poisoned
//! mutex (set when a prior test panicked while holding the lock).
//! The lock's invariant is "I am the only thread mutating env right
//! now", not "the prior holder's data is still valid" — env-restore
//! runs in `Drop`, so re-acquiring the poisoned lock is safe as long
//! as serialisation continues.

use std::sync::Mutex;

/// One mutex shared across every test helper in this crate that
/// mutates process-wide env. Tests acquire it via
/// [`acquire_env_lock`]; never lock this directly so the
/// poison-handling stays uniform.
pub(crate) static ENV_LOCK: Mutex<()> = Mutex::new(());

/// Acquire the shared env-mutation lock, recovering from a
/// previously poisoned-mutex state.
pub(crate) fn acquire_env_lock() -> std::sync::MutexGuard<'static, ()> {
    ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner())
}

/// Snapshot and redirect the process home env vars for tests.
///
/// `dirs::home_dir()` can use the Windows known-folder API, so tests
/// that only set `HOME` are not isolated from the real user profile
/// there. `LPM_TEST_HOME` gives crate path helpers a deterministic
/// test-only override.
pub(crate) struct HomeEnvSnapshot {
    prior_home: Option<std::ffi::OsString>,
    prior_lpm_test_home: Option<std::ffi::OsString>,
    #[cfg(windows)]
    prior_userprofile: Option<std::ffi::OsString>,
}

impl HomeEnvSnapshot {
    pub(crate) fn set(path: &std::path::Path) -> Self {
        let snapshot = Self {
            prior_home: std::env::var_os("HOME"),
            prior_lpm_test_home: std::env::var_os("LPM_TEST_HOME"),
            #[cfg(windows)]
            prior_userprofile: std::env::var_os("USERPROFILE"),
        };

        // SAFETY: callers hold `ENV_LOCK`, serialising process-wide env mutation.
        unsafe {
            std::env::set_var("HOME", path);
            std::env::set_var("LPM_TEST_HOME", path);
            #[cfg(windows)]
            std::env::set_var("USERPROFILE", path);
        }

        snapshot
    }

    pub(crate) fn restore(self) {
        // SAFETY: callers hold `ENV_LOCK`, serialising process-wide env mutation.
        unsafe {
            match self.prior_home {
                Some(value) => std::env::set_var("HOME", value),
                None => std::env::remove_var("HOME"),
            }
            match self.prior_lpm_test_home {
                Some(value) => std::env::set_var("LPM_TEST_HOME", value),
                None => std::env::remove_var("LPM_TEST_HOME"),
            }
            #[cfg(windows)]
            match self.prior_userprofile {
                Some(value) => std::env::set_var("USERPROFILE", value),
                None => std::env::remove_var("USERPROFILE"),
            }
        }
    }
}
