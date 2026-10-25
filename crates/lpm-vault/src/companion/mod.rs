//! Companion storage: records kept next to an env project's values item,
//! never inside it, with a feature marker that tells every client what they
//! are and what a client that doesn't support them may do.
//!
//! The values payload stays exactly `{"environments": …}`. Every operation
//! reads the project's marker inside its lock, finishes any interrupted
//! lifecycle step, and applies the operation matrix before touching values.

#[cfg(target_os = "macos")]
pub(crate) use lpm_env_companion::graph;
pub(crate) use lpm_env_companion::{account, gate, invariants, lifecycle, marker, overrides};

use std::cell::RefCell;
use std::collections::HashMap;

use account::CompanionAccount;
use gate::{Damage, Operation, ProjectGate};
use lifecycle::LifecycleStore;
use marker::{FeatureState, Marker, ProjectState, RestorePhase};

/// A store of one platform's companion records.
pub(crate) trait CompanionBackend: LifecycleStore {
    /// The companion records and staged records of `vault_id`, by name only.
    fn inventory(&mut self, vault_id: &str) -> Result<Vec<CompanionAccount>, String>;
}

thread_local! {
    /// Each project's marker state, for the outermost vault lock this thread
    /// holds. `None` outside a lock.
    static LOCK_SCOPE: RefCell<Option<HashMap<String, ProjectGate>>> = const { RefCell::new(None) };
}

/// Remembers marker states until the outermost vault lock is released.
pub(crate) struct LockScope {
    outermost: bool,
}

impl LockScope {
    pub(crate) fn enter() -> Self {
        let outermost = LOCK_SCOPE.with_borrow_mut(|scope| {
            if scope.is_some() {
                false
            } else {
                *scope = Some(HashMap::new());
                true
            }
        });
        Self { outermost }
    }
}

impl LockScope {
    pub(crate) fn is_outermost(&self) -> bool {
        self.outermost
    }
}

impl Drop for LockScope {
    fn drop(&mut self) {
        if self.outermost {
            LOCK_SCOPE.with_borrow_mut(|scope| *scope = None);
        }
    }
}

fn remembered(vault_id: &str) -> Option<ProjectGate> {
    LOCK_SCOPE.with_borrow(|scope| {
        scope
            .as_ref()
            .and_then(|gates| gates.get(vault_id).cloned())
    })
}

/// Replace what this lock scope knows about `vault_id`, after a change to its
/// marker or records.
pub(crate) fn remember(vault_id: &str, gate: &ProjectGate) {
    LOCK_SCOPE.with_borrow_mut(|scope| {
        if let Some(gates) = scope.as_mut() {
            gates.insert(vault_id.to_owned(), gate.clone());
        }
    });
}

/// Read `vault_id`'s marker, finishing any lifecycle step it describes.
pub(crate) fn open_project(
    backend: &mut impl CompanionBackend,
    vault_id: &str,
) -> Result<ProjectGate, String> {
    if let Some(gate) = remembered(vault_id) {
        return Ok(gate);
    }
    let marker_account = CompanionAccount::Marker {
        vault_id: vault_id.to_owned(),
    };
    let gate = match backend.read(&marker_account)? {
        None => ProjectGate::Plain,
        Some(bytes) => match Marker::parse(vault_id, &bytes) {
            Err(error) => ProjectGate::Damaged(error.into()),
            Ok(marker) if lifecycle::needs_resume(&marker) => {
                let notice = resume_notice(&marker);
                let inventory = backend.inventory(vault_id)?;
                let gate = match lifecycle::resume(backend, marker, inventory)? {
                    Some(marker) => ProjectGate::Marked(marker),
                    None => ProjectGate::Plain,
                };
                tracing::warn!("{notice}");
                gate
            }
            Ok(marker) => ProjectGate::Marked(marker),
        },
    };
    remember(vault_id, &gate);
    Ok(gate)
}

/// What the notice after a resume says it finished or undid.
fn resume_notice(marker: &Marker) -> String {
    let project = format!("env project {}'s newer data", marker.vault_id);
    match (
        marker.state,
        marker.restore.as_ref().map(|restore| restore.phase),
    ) {
        (ProjectState::Deleting, _) => format!("finished an interrupted deletion of {project}"),
        (ProjectState::Discarding, _) => format!("finished an interrupted discard of {project}"),
        (ProjectState::Restoring, Some(RestorePhase::Staging)) => {
            format!("undid an interrupted restore of {project}; run the restore again")
        }
        (ProjectState::Restoring, _) => format!("finished an interrupted restore of {project}"),
        (ProjectState::Active, _) => {
            let removing: Vec<&str> = marker
                .features
                .iter()
                .filter(|(_, entry)| entry.state == FeatureState::Removing)
                .map(|(name, _)| name.as_str())
                .collect();
            format!("finished removing {} from {project}", removing.join(", "))
        }
    }
}

/// [`open_project`], then the operation matrix.
pub(crate) fn authorize(
    backend: &mut impl CompanionBackend,
    vault_id: &str,
    operation: Operation,
) -> Result<ProjectGate, String> {
    let gate = open_project(backend, vault_id)?;
    gate.authorize(operation)
        .map_err(|error| error.to_string())?;
    Ok(gate)
}

/// Fail an Apply read on damage it found, in the gate's own words.
pub(crate) fn damaged(damage: Damage) -> String {
    gate::GateError::Damaged(damage).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resume_notices_name_the_project_in_one_sentence() {
        let mut marker = Marker::empty("proj", ProjectState::Deleting);
        assert_eq!(
            resume_notice(&marker),
            "finished an interrupted deletion of env project proj's newer data"
        );
        marker.state = ProjectState::Restoring;
        marker.restore = Some(marker::Restore {
            phase: RestorePhase::Staging,
            replaces: Vec::new(),
            features: std::collections::BTreeMap::new(),
        });
        assert_eq!(
            resume_notice(&marker),
            "undid an interrupted restore of env project proj's newer data; run the restore again"
        );
        let mut removing = Marker::empty("proj", ProjectState::Active);
        removing.features.insert(
            "overrides".to_owned(),
            marker::FeatureEntry {
                version: 1,
                if_unsupported: marker::Level::Refuse,
                kinds: vec!["overrides".to_owned()],
                state: FeatureState::Removing,
            },
        );
        assert_eq!(
            resume_notice(&removing),
            "finished removing overrides from env project proj's newer data"
        );
    }

    #[test]
    fn the_lock_scope_forgets_marker_states_when_the_outermost_lock_ends() {
        {
            let _outer = LockScope::enter();
            remember("proj", &ProjectGate::Plain);
            {
                let _inner = LockScope::enter();
                assert_eq!(remembered("proj"), Some(ProjectGate::Plain));
            }
            assert_eq!(remembered("proj"), Some(ProjectGate::Plain));
        }
        assert_eq!(remembered("proj"), None);
        remember("proj", &ProjectGate::Plain);
        assert_eq!(remembered("proj"), None);
    }
}
