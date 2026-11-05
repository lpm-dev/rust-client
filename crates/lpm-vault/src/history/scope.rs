//! What one held vault lock remembers for history: for each project whose
//! values it writes, the source, the values when it first read them, and
//! what its last write stored. The change is recorded when the outermost
//! lock ends, still inside it, after the operation's last durable step.

use std::cell::RefCell;
use std::collections::BTreeMap;

use super::Source;
use crate::EnvironmentMap;

/// One project's change within a lock scope.
#[derive(Debug, Clone)]
pub(crate) struct Tracked {
    pub(crate) source: Source,
    /// The stored values when the scope first read them, or when its first
    /// write began.
    pub(crate) before: Option<EnvironmentMap>,
    /// What the scope's last write stored.
    pub(crate) after: Option<EnvironmentMap>,
}

thread_local! {
    /// `None` outside a lock.
    static SCOPE: RefCell<Option<BTreeMap<String, Tracked>>> = const { RefCell::new(None) };
}

/// Proof that a values write declared its source, which every commit
/// primitive takes, so a write without a source doesn't compile.
#[derive(Debug)]
pub(crate) struct Recording {
    vault_id: String,
}

/// Start remembering for the outermost lock. Returns whether this call
/// started it.
pub(crate) fn enter() -> bool {
    SCOPE.with_borrow_mut(|scope| {
        if scope.is_some() {
            false
        } else {
            *scope = Some(BTreeMap::new());
            true
        }
    })
}

/// Stop remembering, returning what the scope tracked.
pub(crate) fn leave() -> BTreeMap<String, Tracked> {
    SCOPE.with_borrow_mut(Option::take).unwrap_or_default()
}

/// Declare that this lock scope writes `vault_id`'s values for `source`.
/// The first declaration in a scope is the one recorded.
pub(crate) fn begin(vault_id: &str, source: &Source) -> Recording {
    SCOPE.with_borrow_mut(|scope| {
        if let Some(scope) = scope.as_mut() {
            scope.entry(vault_id.to_owned()).or_insert_with(|| Tracked {
                source: source.clone(),
                before: None,
                after: None,
            });
        }
    });
    Recording {
        vault_id: vault_id.to_owned(),
    }
}

/// A values read inside the lock: the first one for a project being written
/// is its "before".
pub(crate) fn observe_read(vault_id: &str, environments: Option<&EnvironmentMap>) {
    SCOPE.with_borrow_mut(|scope| {
        if let Some(tracked) = scope.as_mut().and_then(|scope| scope.get_mut(vault_id))
            && tracked.before.is_none()
        {
            tracked.before = Some(environments.cloned().unwrap_or_default());
        }
    });
}

/// Whether the write `recording` declared still needs its "before", which
/// the commit primitive then reads itself.
pub(crate) fn needs_before(recording: &Recording) -> bool {
    SCOPE.with_borrow(|scope| {
        scope
            .as_ref()
            .and_then(|scope| scope.get(&recording.vault_id))
            .is_some_and(|tracked| tracked.before.is_none())
    })
}

/// Stop tracking `vault_id`, so its write goes unrecorded, as a client that
/// doesn't record history writes.
#[cfg(test)]
pub(crate) fn forget(vault_id: &str) {
    SCOPE.with_borrow_mut(|scope| {
        if let Some(scope) = scope.as_mut() {
            scope.remove(vault_id);
        }
    });
}

/// A values write that succeeded.
pub(crate) fn committed(recording: &Recording, after: &EnvironmentMap) {
    SCOPE.with_borrow_mut(|scope| {
        if let Some(tracked) = scope
            .as_mut()
            .and_then(|scope| scope.get_mut(&recording.vault_id))
        {
            tracked.after = Some(after.clone());
        }
    });
}
