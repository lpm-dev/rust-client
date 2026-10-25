//! Companion storage: records kept next to an env project's values item,
//! never inside it, with a feature marker that tells every client what they
//! are and what a client that doesn't support them may do.
//!
//! The values payload stays exactly `{"environments": …}`. Every operation
//! reads the project's marker inside its lock, finishes any interrupted
//! lifecycle step, and applies the operation matrix before touching values.

pub(crate) mod account;
#[cfg(test)]
mod contract_tests;
pub(crate) mod gate;
pub(crate) mod graph;
pub(crate) mod lifecycle;
pub(crate) mod marker;
pub(crate) mod overrides;

use std::cell::RefCell;
use std::collections::HashMap;

use account::CompanionAccount;
use gate::{Damage, Operation, ProjectGate};
use lifecycle::LifecycleStore;
use marker::{FeatureState, Marker};
use overrides::{OVERRIDES_KIND, PersonalOverrides};

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
                let inventory = backend.inventory(vault_id)?;
                match lifecycle::resume(backend, marker, inventory)? {
                    Some(marker) => ProjectGate::Marked(marker),
                    None => ProjectGate::Plain,
                }
            }
            Ok(marker) => ProjectGate::Marked(marker),
        },
    };
    remember(vault_id, &gate);
    Ok(gate)
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

/// The selected environment's personal overrides, from the overrides record
/// an Apply read always reads, found or not, so a missing marker can't hide
/// a record and a missing record can't pass for no overrides.
pub(crate) fn evaluate_overrides(
    gate: &ProjectGate,
    vault_id: &str,
    environment: &str,
    record: Option<&[u8]>,
) -> Result<PersonalOverrides, Damage> {
    let entry = gate
        .marker()
        .and_then(|marker| marker.feature(OVERRIDES_KIND))
        .filter(|entry| entry.state == FeatureState::Active);
    match (entry, record) {
        (None, None) => Ok(PersonalOverrides::default()),
        (None, Some(_)) => Err(Damage::UnlistedRecord {
            kind: OVERRIDES_KIND.to_owned(),
        }),
        (Some(_), None) => Err(Damage::MissingRecord {
            kind: OVERRIDES_KIND.to_owned(),
        }),
        (Some(entry), Some(bytes)) => {
            overrides::parse_selected(bytes, vault_id, entry.version, environment).map_err(
                |error| Damage::InvalidRecord {
                    kind: OVERRIDES_KIND.to_owned(),
                    reason: error.to_string(),
                },
            )
        }
    }
}

/// Fail an Apply read on damage it found, in the gate's own words.
pub(crate) fn damaged(damage: Damage) -> String {
    gate::GateError::Damaged(damage).to_string()
}

/// Where a deletion's first transaction leaves the marker: `deleting`, and
/// listing every kind the inventory found, so every record left for later
/// batches still belongs to a feature.
pub(crate) fn deleting_marker(
    vault_id: &str,
    current: Option<&Marker>,
    inventory: &[CompanionAccount],
) -> Marker {
    let mut marker = current
        .cloned()
        .unwrap_or_else(|| Marker::empty(vault_id, marker::ProjectState::Active));
    marker.state = marker::ProjectState::Deleting;
    marker.restore = None;
    for account in inventory {
        let Some(kind) = account.kind() else {
            continue;
        };
        if marker.lists_kind(kind) {
            continue;
        }
        let owner = graph::reserved_owner(kind).unwrap_or(kind).to_owned();
        let entry = marker
            .features
            .entry(owner)
            .or_insert_with(|| marker::FeatureEntry {
                version: u16::MAX,
                if_unsupported: marker::Level::Refuse,
                kinds: Vec::new(),
                state: FeatureState::Active,
            });
        entry.kinds.push(kind.to_owned());
    }
    marker
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn overrides_are_damaged_when_the_marker_and_the_record_disagree() {
        let mut marker = Marker::empty("proj", marker::ProjectState::Active);
        let plain = ProjectGate::Plain;
        assert_eq!(
            evaluate_overrides(&plain, "proj", "default", None),
            Ok(PersonalOverrides::default())
        );
        assert_eq!(
            evaluate_overrides(&plain, "proj", "default", Some(b"{}")),
            Err(Damage::UnlistedRecord {
                kind: "overrides".to_owned()
            })
        );
        marker.features.insert(
            "overrides".to_owned(),
            marker::FeatureEntry {
                version: 1,
                if_unsupported: marker::Level::Refuse,
                kinds: vec!["overrides".to_owned()],
                state: FeatureState::Active,
            },
        );
        let marked = ProjectGate::Marked(marker);
        assert_eq!(
            evaluate_overrides(&marked, "proj", "default", None),
            Err(Damage::MissingRecord {
                kind: "overrides".to_owned()
            })
        );
        let record = br#"{"schemaVersion":1,"vaultId":"proj","environments":{"default":{"set":{"A":"1"},"unset":[]}}}"#;
        let overrides =
            evaluate_overrides(&marked, "proj", "default", Some(record)).expect("valid");
        assert_eq!(overrides.set["A"], "1");
    }

    #[test]
    fn a_deleting_marker_lists_every_kind_found_including_unlisted_ones() {
        let inventory = [
            CompanionAccount::Record {
                kind: "overrides".to_owned(),
                vault_id: "proj".to_owned(),
                part: None,
            },
            CompanionAccount::Record {
                kind: "future-log".to_owned(),
                vault_id: "proj".to_owned(),
                part: Some(3),
            },
            CompanionAccount::Record {
                kind: "key".to_owned(),
                vault_id: "proj".to_owned(),
                part: None,
            },
        ];
        let marker = deleting_marker("proj", None, &inventory);
        marker.validate().expect("the deleting marker validates");
        assert_eq!(marker.state, marker::ProjectState::Deleting);
        for account in &inventory {
            assert!(marker.lists_kind(account.kind().unwrap()));
        }
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
