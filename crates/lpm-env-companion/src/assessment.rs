//! What a client concludes about a project from what it saw inside one lock
//! scope: the marker's bytes, and when it has them a names-only listing of
//! the project's records, the overrides record and the access it verified.
//! The CLI sees only the marker and, on Apply reads, the overrides record;
//! the app's listing also sees records no feature lists and required
//! records that are missing.

use std::collections::HashSet;

use crate::account::CompanionAccount;
use crate::gate::{Damage, GateError, Operation, ProjectGate};
use crate::graph::{OVERRIDES, known_feature};
use crate::invariants::is_listed;
use crate::lifecycle::needs_resume;
use crate::marker::{FeatureState, Marker};
use crate::overrides;

/// What a client saw of one project.
#[derive(Debug, Clone, Copy, Default)]
pub struct Observed<'a> {
    /// The bytes at the marker account, or `None` when it's absent.
    pub marker: Option<&'a [u8]>,
    /// The project's companion and staged records from a names-only listing
    /// taken in the same lock scope, or `None` without one.
    pub inventory: Option<&'a [CompanionAccount]>,
    /// The overrides record when the client read it, found or not.
    pub overrides: Option<Option<&'a [u8]>>,
    /// Why the client found the project's access damaged, if it did.
    pub access: Option<&'a str>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Assessment {
    /// The marker's state, which the operation matrix applies to.
    pub gate: ProjectGate,
    /// Every way the project is damaged beyond an invalid marker, each once,
    /// in the order found.
    pub damage: Vec<Damage>,
}

/// How a person repairs one damage, after fresh authentication.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Repair {
    /// Discard every companion record of the project, keeping its values.
    DiscardProject,
    /// Remove one feature and the records only it lists.
    RemoveFeature(String),
    /// Delete the records no feature lists.
    RemoveUnlisted,
}

pub fn assess(vault_id: &str, observed: Observed<'_>) -> Assessment {
    let gate = match observed.marker {
        None => ProjectGate::Plain,
        Some(bytes) => match Marker::parse(vault_id, bytes) {
            Ok(marker) => ProjectGate::Marked(marker),
            Err(error) => ProjectGate::Damaged(error.into()),
        },
    };
    let mut damage = Vec::new();
    let mut seen = HashSet::new();
    let mut found = |found: Damage| {
        if seen.insert(found.clone()) {
            damage.push(found);
        }
    };
    let records_are_read = match &gate {
        ProjectGate::Plain => true,
        ProjectGate::Marked(marker) => !needs_resume(marker),
        ProjectGate::Damaged(_) => false,
    };
    if records_are_read {
        if let Some(inventory) = observed.inventory {
            let project = || {
                inventory.iter().filter(|account| {
                    account.vault_id() == vault_id
                        && !matches!(account, CompanionAccount::Marker { .. })
                })
            };
            for account in project() {
                if !is_listed(gate.marker(), account)
                    && let Some(kind) = account.kind()
                {
                    found(Damage::UnlistedRecord {
                        kind: kind.to_owned(),
                    });
                }
            }
            for (name, entry) in gate
                .marker()
                .map(|marker| &marker.features)
                .into_iter()
                .flatten()
            {
                let Some(known) = known_feature(name).filter(|known| {
                    entry.state == FeatureState::Active
                        && known.supported_versions.contains(&entry.version)
                }) else {
                    continue;
                };
                for required in known.required {
                    let present = project().any(|account| {
                        matches!(account, CompanionAccount::Record { kind, part: None, .. } if kind == required)
                    });
                    if !present {
                        found(Damage::MissingRecord {
                            kind: (*required).to_owned(),
                        });
                    }
                }
            }
        }
        let overrides_are_supported = gate
            .marker()
            .and_then(|marker| marker.feature(overrides::OVERRIDES_KIND))
            .is_none_or(|entry| OVERRIDES.supported_versions.contains(&entry.version));
        if overrides_are_supported
            && let Some(record) = observed.overrides
            && let Err(damaged) = overrides::evaluate_all(&gate, vault_id, record)
        {
            found(damaged);
        }
    }
    if let Some(reason) = observed.access {
        found(Damage::Access(reason.to_owned()));
    }
    Assessment { gate, damage }
}

impl Assessment {
    /// Whether an interrupted lifecycle step must be finished before
    /// anything but maintenance runs.
    pub fn needs_resume(&self) -> bool {
        self.gate.marker().is_some_and(needs_resume)
    }

    /// The operation matrix over the marker and every damage found.
    pub fn authorize(&self, operation: Operation) -> Result<(), GateError> {
        self.gate.authorize(operation)?;
        self.damage
            .iter()
            .try_for_each(|damage| ProjectGate::Damaged(damage.clone()).authorize(operation))
    }

    /// Every damage, an invalid marker first.
    pub fn every_damage(&self) -> impl Iterator<Item = &Damage> {
        match &self.gate {
            ProjectGate::Damaged(damage) => Some(damage),
            ProjectGate::Plain | ProjectGate::Marked(_) => None,
        }
        .into_iter()
        .chain(&self.damage)
    }

    /// The repairs that set every damage right, each once, in the order
    /// their damage was found: a project-wide discard alone when any damage
    /// needs one, since it removes everything the others would. Damaged
    /// access has none.
    pub fn repairs(&self) -> Vec<Repair> {
        let mut repairs = Vec::new();
        for repair in self.every_damage().filter_map(|damage| self.repair(damage)) {
            if repair == Repair::DiscardProject {
                return vec![Repair::DiscardProject];
            }
            if !repairs.contains(&repair) {
                repairs.push(repair);
            }
        }
        repairs
    }

    /// The repair for `damage`, or `None` for damaged access, which the
    /// app's reconcile fixes.
    pub fn repair(&self, damage: &Damage) -> Option<Repair> {
        let marker = self.gate.marker();
        match damage {
            Damage::Access(_) => None,
            Damage::InvalidMarker(_) | Damage::Unfinished(_) => Some(Repair::DiscardProject),
            Damage::UnlistedRecord { .. } if marker.is_none() => Some(Repair::DiscardProject),
            Damage::UnlistedRecord { .. } => Some(Repair::RemoveUnlisted),
            Damage::MissingRecord { kind } | Damage::InvalidRecord { kind, .. } => Some(
                marker
                    .and_then(|marker| {
                        marker
                            .features
                            .iter()
                            .find(|(_, entry)| entry.kinds.iter().any(|listed| listed == kind))
                    })
                    .map_or(Repair::DiscardProject, |(name, _)| {
                        Repair::RemoveFeature(name.clone())
                    }),
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const OVERRIDES_MARKER: &[u8] = br#"{"schemaVersion":1,"vaultId":"proj","state":"active","features":{"overrides":{"version":1,"ifUnsupported":"refuse","kinds":["overrides"],"state":"active"}}}"#;
    const RECORD: &[u8] = br#"{"schemaVersion":1,"vaultId":"proj","environments":{"default":{"set":{"A":"1"},"unset":[]}}}"#;

    fn record(kind: &str, part: Option<u16>) -> CompanionAccount {
        CompanionAccount::Record {
            kind: kind.to_owned(),
            vault_id: "proj".to_owned(),
            part,
        }
    }

    #[test]
    fn overrides_of_a_version_this_client_doesnt_support_are_never_judged() {
        let marker = br#"{"schemaVersion":1,"vaultId":"proj","state":"active","features":{"overrides":{"version":2,"ifUnsupported":"refuse","kinds":["overrides"],"state":"active"}}}"#;
        let inventory = [record("overrides", None)];
        for overrides in [
            Some(&br#"{"schemaVersion":2,"vaultId":"proj","layers":[]}"#[..]),
            None,
        ] {
            let assessment = assess(
                "proj",
                Observed {
                    marker: Some(marker),
                    inventory: Some(&inventory),
                    overrides: Some(overrides),
                    access: None,
                },
            );
            assert!(assessment.damage.is_empty(), "{:?}", assessment.damage);
            assert!(
                assessment
                    .authorize(Operation::ReadApplyingOverrides)
                    .is_err()
            );
        }
    }

    #[test]
    fn a_healthy_project_allows_everything() {
        let inventory = [record("overrides", None)];
        let assessment = assess(
            "proj",
            Observed {
                marker: Some(OVERRIDES_MARKER),
                inventory: Some(&inventory),
                overrides: Some(Some(RECORD)),
                access: None,
            },
        );
        assert!(assessment.damage.is_empty());
        assert!(!assessment.needs_resume());
        for operation in [
            Operation::ReadExcludingOverrides,
            Operation::ReadApplyingOverrides,
            Operation::Write,
        ] {
            assert_eq!(assessment.authorize(operation), Ok(()));
        }
        assert_eq!(assess("proj", Observed::default()).gate, ProjectGate::Plain);
    }

    #[test]
    fn records_without_a_marker_are_damage_only_a_project_wide_discard_repairs() {
        let inventory = [record("future-kind", None), record("overrides", None)];
        let assessment = assess(
            "proj",
            Observed {
                inventory: Some(&inventory),
                overrides: Some(Some(RECORD)),
                ..Observed::default()
            },
        );
        assert_eq!(
            assessment.damage,
            [
                Damage::UnlistedRecord {
                    kind: "future-kind".to_owned()
                },
                Damage::UnlistedRecord {
                    kind: "overrides".to_owned()
                },
            ]
        );
        assert!(
            assessment
                .authorize(Operation::ReadExcludingOverrides)
                .is_err()
        );
        assert_eq!(
            assessment.repair(&assessment.damage[0]),
            Some(Repair::DiscardProject)
        );
    }

    #[test]
    fn only_damaged_overrides_still_allow_reads_that_exclude_them() {
        let assessment = assess(
            "proj",
            Observed {
                marker: Some(OVERRIDES_MARKER),
                inventory: Some(&[]),
                ..Observed::default()
            },
        );
        assert_eq!(
            assessment.damage,
            [Damage::MissingRecord {
                kind: "overrides".to_owned()
            }]
        );
        assert_eq!(
            assessment.authorize(Operation::ReadExcludingOverrides),
            Ok(())
        );
        assert!(
            assessment
                .authorize(Operation::ReadApplyingOverrides)
                .is_err()
        );
        assert!(assessment.authorize(Operation::Write).is_err());
        assert_eq!(
            assessment.repair(&assessment.damage[0]),
            Some(Repair::RemoveFeature("overrides".to_owned()))
        );
        let invalid = assess(
            "proj",
            Observed {
                marker: Some(OVERRIDES_MARKER),
                overrides: Some(Some(b"[]")),
                ..Observed::default()
            },
        );
        assert!(matches!(
            invalid.damage.as_slice(),
            [Damage::InvalidRecord { kind, .. }] if kind == "overrides"
        ));
    }

    #[test]
    fn a_stray_record_next_to_a_valid_marker_is_removed_alone() {
        let inventory = [record("overrides", None), record("notes", None)];
        let assessment = assess(
            "proj",
            Observed {
                marker: Some(OVERRIDES_MARKER),
                inventory: Some(&inventory),
                ..Observed::default()
            },
        );
        assert_eq!(
            assessment.damage,
            [Damage::UnlistedRecord {
                kind: "notes".to_owned()
            }]
        );
        assert_eq!(
            assessment.repair(&assessment.damage[0]),
            Some(Repair::RemoveUnlisted)
        );
        assert!(
            assessment
                .authorize(Operation::ReadExcludingOverrides)
                .is_err()
        );
    }

    #[test]
    fn an_invalid_marker_is_the_only_damage_and_blocks_everything_but_maintenance() {
        let inventory = [record("notes", None)];
        let assessment = assess(
            "proj",
            Observed {
                marker: Some(b"{}"),
                inventory: Some(&inventory),
                ..Observed::default()
            },
        );
        assert!(assessment.damage.is_empty());
        let every: Vec<&Damage> = assessment.every_damage().collect();
        assert!(matches!(every.as_slice(), [Damage::InvalidMarker(_)]));
        assert_eq!(assessment.repair(every[0]), Some(Repair::DiscardProject));
        assert!(
            assessment
                .authorize(Operation::ReadExcludingOverrides)
                .is_err()
        );
        assert_eq!(assessment.authorize(Operation::Maintenance), Ok(()));
    }

    #[test]
    fn an_interrupted_step_is_resumed_before_records_are_judged() {
        let deleting = br#"{"schemaVersion":1,"vaultId":"proj","state":"deleting","features":{}}"#;
        let inventory = [record("notes", None)];
        let assessment = assess(
            "proj",
            Observed {
                marker: Some(deleting),
                inventory: Some(&inventory),
                ..Observed::default()
            },
        );
        assert!(assessment.needs_resume());
        assert!(assessment.damage.is_empty());
    }

    #[test]
    fn damaged_access_blocks_reads_and_has_no_repair() {
        let assessment = assess(
            "proj",
            Observed {
                access: Some("the values' approval attributes contradict each other"),
                ..Observed::default()
            },
        );
        assert!(
            assessment
                .authorize(Operation::ReadExcludingOverrides)
                .is_err()
        );
        assert_eq!(assessment.repair(&assessment.damage[0]), None);
    }

    #[test]
    fn an_unsupported_version_has_no_required_records_this_client_knows() {
        let newer = br#"{"schemaVersion":1,"vaultId":"proj","state":"active","features":{"overrides":{"version":2,"ifUnsupported":"refuse","kinds":["overrides"],"state":"active"}}}"#;
        let assessment = assess(
            "proj",
            Observed {
                marker: Some(newer),
                inventory: Some(&[]),
                ..Observed::default()
            },
        );
        assert!(assessment.damage.is_empty());
        assert!(matches!(
            assessment.authorize(Operation::ReadExcludingOverrides),
            Err(GateError::Unsupported { .. })
        ));
    }
    #[test]
    fn repairs_run_once_each_and_a_discard_supersedes_the_others() {
        let marker = br#"{"schemaVersion":1,"vaultId":"proj","state":"active","features":{"overrides":{"version":1,"ifUnsupported":"refuse","kinds":["overrides"],"state":"active"},"history":{"version":1,"ifUnsupported":"ignore","kinds":["history-head","history","key"],"state":"active"}}}"#;
        let inventory = [
            record("notes", None),
            record("history", Some(0)),
            record("future-log", Some(0)),
        ];
        let assessment = assess(
            "proj",
            Observed {
                marker: Some(marker),
                inventory: Some(&inventory),
                ..Observed::default()
            },
        );
        assert_eq!(
            assessment.repairs(),
            [
                Repair::RemoveUnlisted,
                Repair::RemoveFeature("overrides".to_owned()),
            ],
            "two unlisted kinds need one removal"
        );

        let invalid = assess(
            "proj",
            Observed {
                marker: Some(b"{}"),
                inventory: Some(&inventory),
                ..Observed::default()
            },
        );
        assert_eq!(invalid.repairs(), [Repair::DiscardProject]);
        let access = assess(
            "proj",
            Observed {
                marker: Some(OVERRIDES_MARKER),
                inventory: Some(&[record("overrides", None)]),
                access: Some("contradicts"),
                ..Observed::default()
            },
        );
        assert_eq!(access.repairs(), [], "damaged access has no repair here");
    }
}
