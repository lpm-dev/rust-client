//! Approval lifetime shared by the pending tasks of one run.

use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::path::PathBuf;
use std::process::{Child, Command};
use std::sync::{Arc, Mutex, PoisonError};

use lpm_common::LpmError;

/// A project's vault values for one environment, and its personal overrides:
/// one snapshot the run's reads and each task's pin share, copied only by
/// the reader that takes it.
pub(crate) type VaultValues = Arc<(HashMap<String, String>, lpm_vault::PersonalOverrides)>;

/// Which vault values a read asks for: the project, the environment, and
/// whether personal overrides apply.
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub(crate) struct VaultReadKey {
    pub(crate) project_dir: PathBuf,
    pub(crate) env_name: Option<String>,
    pub(crate) with_overrides: bool,
}

/// Shares native approval denial across pending reads and process starts in
/// one run, and the vault values the run has read, so its tasks read each
/// project's vault once instead of once or twice each.
#[derive(Clone, Default)]
pub struct EnvAccessScope {
    failure: Arc<Mutex<Option<String>>>,
    vault_reads: Arc<Mutex<HashMap<VaultReadKey, VaultValues>>>,
}

thread_local! {
    static CURRENT: RefCell<Option<EnvAccessScope>> = const { RefCell::new(None) };
    static PINNED_VAULT_READS: RefCell<Option<HashMap<VaultReadKey, VaultValues>>> =
        const { RefCell::new(None) };
    static FRESH_VAULT_READS: Cell<usize> = const { Cell::new(0) };
}

/// While held, vault reads on this thread skip the run's earlier values and
/// replace them.
#[must_use]
pub struct FreshVaultReads {
    thread: std::marker::PhantomData<std::rc::Rc<()>>,
}

impl Drop for FreshVaultReads {
    fn drop(&mut self) {
        FRESH_VAULT_READS.with(|fresh| fresh.set(fresh.get() - 1));
    }
}

/// Makes this thread's vault reads go to the vault until the guard drops, as
/// a task's cache publication does to see values that changed while it ran.
pub fn fresh_vault_reads() -> FreshVaultReads {
    FRESH_VAULT_READS.with(|fresh| fresh.set(fresh.get() + 1));
    FreshVaultReads {
        thread: std::marker::PhantomData,
    }
}

/// While held, this thread's vault reads return the values they first
/// returned under it, so a task runs with the values its cache key was
/// computed from, even when another task's cache publication rereads them
/// meanwhile. A fresh read still goes to the vault and pins nothing.
#[must_use]
pub struct PinnedVaultReads {
    previous: Option<HashMap<VaultReadKey, VaultValues>>,
    thread: std::marker::PhantomData<std::rc::Rc<()>>,
}

impl Drop for PinnedVaultReads {
    fn drop(&mut self) {
        PINNED_VAULT_READS.with_borrow_mut(|pinned| *pinned = self.previous.take());
    }
}

/// Pins this thread's vault reads for one task, from before its cache key is
/// computed until its process has run.
pub fn pin_vault_reads() -> PinnedVaultReads {
    PinnedVaultReads {
        previous: PINNED_VAULT_READS.with_borrow_mut(|pinned| pinned.replace(HashMap::new())),
        thread: std::marker::PhantomData,
    }
}

/// `values` as this thread's pinned values for `key`, when it pins reads.
fn pin(key: &VaultReadKey, values: &VaultValues) {
    PINNED_VAULT_READS.with_borrow_mut(|pinned| {
        if let Some(pinned) = pinned {
            pinned.insert(key.clone(), values.clone());
        }
    });
}

fn vault_reads_are_fresh() -> bool {
    FRESH_VAULT_READS.with(Cell::get) > 0
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
        failure.as_ref().map_or(Ok(()), |error| {
            Err(if lpm_vault::is_env_project_refusal(error) {
                LpmError::EnvProjectRefused(error.clone())
            } else {
                LpmError::EnvValidation(error.clone())
            })
        })
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

    fn read_vault(
        &self,
        key: VaultReadKey,
        action: impl FnOnce() -> Result<VaultValues, String>,
    ) -> Result<VaultValues, String> {
        // Inside `read`, so a denial still fails the reads after it, and a
        // task that waited for another's read takes its values.
        self.read(|| {
            let fresh = vault_reads_are_fresh();
            if !fresh {
                let pinned = PINNED_VAULT_READS.with_borrow(|pinned| {
                    pinned.as_ref().and_then(|pinned| pinned.get(&key).cloned())
                });
                if let Some(values) = pinned {
                    return Ok(values);
                }
                let shared = self
                    .vault_reads
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .get(&key)
                    .cloned();
                if let Some(values) = shared {
                    pin(&key, &values);
                    return Ok(values);
                }
            }
            let values = action()?;
            if !fresh {
                pin(&key, &values);
            }
            self.vault_reads
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .insert(key, values.clone());
            Ok(values)
        })
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

#[cfg(test)]
fn read<T>(action: impl FnOnce() -> Result<T, String>) -> Result<T, String> {
    let scope = CURRENT.with_borrow(Clone::clone);
    match scope {
        Some(scope) => scope.read(action),
        None => action(),
    }
}

pub(crate) fn read_vault(
    key: VaultReadKey,
    action: impl FnOnce() -> Result<VaultValues, String>,
) -> Result<VaultValues, String> {
    let scope = CURRENT.with_borrow(Clone::clone);
    match scope {
        Some(scope) => scope.read_vault(key, action),
        None => action(),
    }
}

/// Reads with `action`, as a read of the run would, and keeps the values it
/// returns for each key, so the run's later reads of them use these.
/// Without a run there is nothing to keep, so nothing is read.
pub(crate) fn read_vaults<T>(
    action: impl FnOnce() -> Result<(T, Vec<(VaultReadKey, VaultValues)>), String>,
) -> Result<Option<T>, String> {
    let Some(scope) = CURRENT.with_borrow(Clone::clone) else {
        return Ok(None);
    };
    scope.read(|| {
        let (result, values) = action()?;
        scope
            .vault_reads
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .extend(values);
        Ok(Some(result))
    })
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
    fn a_swallowed_env_project_refusal_fails_the_invocation_as_a_refusal() {
        let scope = EnvAccessScope::default();
        let refusal = "This folder isn't linked to env project vault, which its lpm.json names: \
                       /work/copy. Run `lpm env link` in that folder to let it use the project's \
                       values on this machine.";
        assert!(lpm_vault::is_env_project_refusal(refusal));

        let result = scope.run(|| {
            let _ = read::<()>(|| Err(refusal.to_string()));
            Ok(())
        });

        assert!(matches!(result, Err(LpmError::EnvProjectRefused(error)) if error == refusal));
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

    fn key(env_name: &str) -> VaultReadKey {
        VaultReadKey {
            project_dir: PathBuf::from("/project"),
            env_name: Some(env_name.to_owned()),
            with_overrides: true,
        }
    }

    fn counted(reads: &AtomicUsize) -> VaultValues {
        let read = reads.fetch_add(1, Ordering::SeqCst);
        Arc::new((
            HashMap::from([("READ".to_owned(), read.to_string())]),
            lpm_vault::PersonalOverrides::default(),
        ))
    }

    #[test]
    fn a_run_reads_each_vault_environment_once() {
        let reads = AtomicUsize::new(0);
        let scope = EnvAccessScope::default();
        let _binding = scope.bind();

        let first = read_vault(key("dev"), || Ok(counted(&reads))).unwrap();
        let again = read_vault(key("dev"), || Ok(counted(&reads))).unwrap();
        read_vault(key("prod"), || Ok(counted(&reads))).unwrap();

        assert_eq!(first, again);
        assert_eq!(reads.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn a_fresh_read_goes_to_the_vault_and_later_reads_see_it() {
        let reads = AtomicUsize::new(0);
        let scope = EnvAccessScope::default();
        let _binding = scope.bind();
        read_vault(key("dev"), || Ok(counted(&reads))).unwrap();

        let fresh = {
            let _fresh = fresh_vault_reads();
            read_vault(key("dev"), || Ok(counted(&reads))).unwrap()
        };
        let later = read_vault(key("dev"), || Ok(counted(&reads))).unwrap();

        assert_eq!(reads.load(Ordering::SeqCst), 2);
        assert_eq!(later, fresh);
    }

    #[test]
    fn a_task_runs_with_the_values_it_first_read_while_another_rereads_them() {
        let reads = AtomicUsize::new(0);
        let scope = EnvAccessScope::default();
        let _binding = scope.bind();
        let pinned = pin_vault_reads();
        let first = read_vault(key("dev"), || Ok(counted(&reads))).unwrap();

        std::thread::scope(|threads| {
            threads.spawn(|| {
                let _binding = scope.bind();
                let _fresh = fresh_vault_reads();
                read_vault(key("dev"), || Ok(counted(&reads))).unwrap();
            });
        });
        let again = read_vault(key("dev"), || Ok(counted(&reads))).unwrap();
        drop(pinned);
        let next_task = read_vault(key("dev"), || Ok(counted(&reads))).unwrap();

        assert_eq!(again, first, "the task keeps the values its cache key used");
        assert_ne!(next_task, first, "the next task reads what was reread");
        assert_eq!(reads.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn a_pin_shares_the_run_s_values_rather_than_copying_them() {
        let reads = AtomicUsize::new(0);
        let scope = EnvAccessScope::default();
        let _binding = scope.bind();
        let _pinned = pin_vault_reads();

        let first = read_vault(key("dev"), || Ok(counted(&reads))).unwrap();
        let again = read_vault(key("dev"), || Ok(counted(&reads))).unwrap();

        let shared = scope.vault_reads.lock().unwrap()[&key("dev")].clone();
        assert!(Arc::ptr_eq(&first, &again), "the pin holds the read");
        assert!(Arc::ptr_eq(&first, &shared), "which the run holds too");
        assert_eq!(reads.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn a_new_run_and_a_denied_run_never_reuse_vault_values() {
        let reads = AtomicUsize::new(0);
        let scope = EnvAccessScope::default();
        {
            let _binding = scope.bind();
            read_vault(key("dev"), || Ok(counted(&reads))).unwrap();
            assert!(read::<()>(|| Err("approval cancelled".to_string())).is_err());
            assert!(read_vault(key("dev"), || Ok(counted(&reads))).is_err());
        }
        let _binding = EnvAccessScope::default().bind();
        read_vault(key("dev"), || Ok(counted(&reads))).unwrap();

        assert_eq!(reads.load(Ordering::SeqCst), 2);
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
