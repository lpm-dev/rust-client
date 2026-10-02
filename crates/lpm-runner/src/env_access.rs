//! Approval lifetime shared by the pending tasks of one run.

use std::cell::RefCell;
use std::process::{Child, Command};
use std::sync::{Arc, Mutex};

use lpm_common::LpmError;

/// Shares native approval denial across pending reads and process starts in one run.
#[derive(Clone, Default)]
pub struct EnvAccessScope {
    failure: Arc<Mutex<Option<String>>>,
}

thread_local! {
    static CURRENT: RefCell<Option<EnvAccessScope>> = const { RefCell::new(None) };
}

/// Restores the previous approval scope when synchronous work ends on this thread.
#[must_use]
pub struct EnvAccessBinding {
    previous: Option<EnvAccessScope>,
    thread: std::marker::PhantomData<std::rc::Rc<()>>,
}

impl Drop for EnvAccessBinding {
    fn drop(&mut self) {
        CURRENT.with_borrow_mut(|current| *current = self.previous.take());
    }
}

impl EnvAccessScope {
    /// Inherit the enclosing synchronous run, or start a fresh invocation.
    pub fn current_or_new() -> Self {
        CURRENT.with_borrow(|current| current.clone().unwrap_or_default())
    }

    /// Bind this scope while synchronous work runs and reject any latched denial.
    pub fn run<T>(&self, action: impl FnOnce() -> Result<T, LpmError>) -> Result<T, LpmError> {
        let _binding = self.bind();
        let result = action();
        self.check()?;
        result
    }

    /// Bind to the current thread until the guard is dropped. Do not hold across an await.
    pub fn bind(&self) -> EnvAccessBinding {
        EnvAccessBinding {
            previous: CURRENT.with_borrow_mut(|current| current.replace(self.clone())),
            thread: std::marker::PhantomData,
        }
    }

    /// Fail if any env retrieval in this invocation failed.
    pub fn check(&self) -> Result<(), LpmError> {
        let failure = self.failure.lock().map_err(|_| {
            LpmError::EnvValidation("env approval state is unavailable".to_string())
        })?;
        failure
            .as_ref()
            .map_or(Ok(()), |error| Err(LpmError::EnvValidation(error.clone())))
    }

    fn read<T>(&self, action: impl FnOnce() -> Result<T, String>) -> Result<T, String> {
        let mut failure = self
            .failure
            .lock()
            .map_err(|_| "env approval state is unavailable".to_string())?;
        if let Some(error) = failure.as_ref() {
            return Err(error.clone());
        }
        let result = action();
        if let Err(error) = &result {
            *failure = Some(error.clone());
        }
        result
    }

    fn spawn(&self, command: &mut Command) -> std::io::Result<Child> {
        let failure = self.failure.lock().map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "env approval state is unavailable",
            )
        })?;
        if let Some(error) = failure.as_ref() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                error.clone(),
            ));
        }
        command.spawn()
    }
}

pub(crate) fn read<T>(action: impl FnOnce() -> Result<T, String>) -> Result<T, String> {
    let scope = CURRENT.with_borrow(Clone::clone);
    match scope {
        Some(scope) => scope.read(action),
        None => action(),
    }
}

pub(crate) fn spawn(command: &mut Command) -> std::io::Result<Child> {
    let scope = CURRENT.with_borrow(Clone::clone);
    match scope {
        Some(scope) => scope.spawn(command),
        None => command.spawn(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::mpsc;

    #[test]
    fn denied_read_prevents_waiting_sibling_from_retrieving_values() {
        let scope = EnvAccessScope::default();
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let first_scope = scope.clone();
        let first = std::thread::spawn(move || {
            first_scope.read::<()>(|| {
                entered_tx.send(()).unwrap();
                release_rx.recv().unwrap();
                Err("approval cancelled".to_string())
            })
        });
        entered_rx.recv().unwrap();
        let reads = Arc::new(AtomicUsize::new(0));
        let second_reads = Arc::clone(&reads);
        let second_scope = scope;
        let second = std::thread::spawn(move || {
            second_scope.read(|| {
                second_reads.fetch_add(1, Ordering::SeqCst);
                Ok("synthetic")
            })
        });
        release_tx.send(()).unwrap();
        assert!(first.join().unwrap().is_err());
        assert!(second.join().unwrap().is_err());
        assert_eq!(reads.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn successful_reads_reload_values_and_new_scopes_can_retry_after_denial() {
        let scope = EnvAccessScope::default();
        assert_eq!(scope.read(|| Ok(1)), Ok(1));
        assert_eq!(scope.read(|| Ok(2)), Ok(2));
        assert!(scope.read::<()>(|| Err("cancelled".to_string())).is_err());
        assert_eq!(EnvAccessScope::default().read(|| Ok(3)), Ok(3));
    }

    #[test]
    fn swallowed_retrieval_errors_still_fail_the_invocation() {
        let scope = EnvAccessScope::default();
        let result = scope.run(|| {
            let _ = read::<()>(|| Err("cancelled".to_string()));
            Ok(())
        });
        assert!(matches!(result, Err(LpmError::EnvValidation(error)) if error == "cancelled"));
    }

    #[test]
    fn ordinary_script_errors_do_not_latch_or_leak_a_scope() {
        let scope = EnvAccessScope::default();
        assert!(scope.run::<()>(|| Err(LpmError::ExitCode(7))).is_err());
        assert!(scope.check().is_ok());
        let denied = EnvAccessScope::default();
        assert!(
            denied
                .run(|| {
                    let _ = read::<()>(|| Err("cancelled".to_string()));
                    Ok(())
                })
                .is_err()
        );
        assert_eq!(read(|| Ok(1)), Ok(1));
    }

    #[test]
    fn poisoned_approval_state_fails_closed() {
        let scope = EnvAccessScope::default();
        let _ = std::panic::catch_unwind(|| {
            let _guard = scope.failure.lock().unwrap();
            panic!("poison fixture");
        });
        assert!(scope.read(|| Ok(1)).is_err());
        assert!(scope.check().is_err());
    }

    #[test]
    fn denied_scope_prevents_a_later_process_spawn() {
        let scope = EnvAccessScope::default();
        scope
            .run(|| {
                assert!(read::<()>(|| Err("approval cancelled".to_string())).is_err());
                let mut command = Command::new("rustc");
                command.arg("--version");
                match spawn(&mut command) {
                    Ok(mut child) => {
                        child.wait().unwrap();
                        panic!("a process started after approval was denied");
                    }
                    Err(error) => assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied),
                }
                Ok(())
            })
            .unwrap_err();
    }
}
