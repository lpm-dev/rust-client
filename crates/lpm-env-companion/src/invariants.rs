//! Which companion records a marker lists, and the check every transaction
//! that touches companion records passes before it commits and again when
//! recovery replays it: each record it writes belongs to a feature of the
//! marker it leaves (I1, I5), and it never leaves a record that the marker
//! listed before it without a feature (I2).
//!
//! A record that no feature listed before the transaction is damage the
//! gate reports and a repair removes, never a reason to refuse: refusing to
//! replay over it would leave the project unrecoverable.

use std::collections::{BTreeMap, HashSet};
use std::fmt;

use crate::account::{CompanionAccount, is_in_companion_namespace};
use crate::marker::{Marker, ProjectState};

/// Whether `account` may exist next to `marker`: the marker itself always,
/// a record whose kind a feature or the restore in progress lists, a staged
/// record whose kind the restore lists, and under a `deleting` or
/// `discarding` marker every record, since none is read for its content
/// again. Without a marker no record may exist.
pub fn is_listed(marker: Option<&Marker>, account: &CompanionAccount) -> bool {
    match (account, marker) {
        (CompanionAccount::Marker { .. }, _) => true,
        (_, Some(marker))
            if matches!(
                marker.state,
                ProjectState::Deleting | ProjectState::Discarding
            ) =>
        {
            true
        }
        (CompanionAccount::Record { kind, .. }, Some(marker)) => {
            marker.lists_kind(kind) || marker.restore_lists_kind(kind)
        }
        (CompanionAccount::Staged { kind, .. }, Some(marker)) => marker.restore_lists_kind(kind),
        (_, None) => false,
    }
}

/// A record a transaction writes without a feature that lists it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unlisted(pub CompanionAccount);

impl fmt::Display for Unlisted {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "writes {} without a feature that lists it",
            self.0.name()
        )
    }
}

/// Why a transaction's companion changes are refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    InvalidAccount,
    /// The marker the transaction writes.
    InvalidMarker(String),
    /// The marker a touched project already has.
    InvalidLiveMarker {
        vault_id: String,
        reason: String,
    },
    Unlisted(Unlisted),
    /// A record the project's marker listed before the transaction, which
    /// the transaction keeps and the marker it leaves doesn't list.
    Orphans(CompanionAccount),
    /// Reading a live marker failed.
    Storage(String),
}

impl Refusal {
    /// The refusal as an error of `subject`, such as "vault transaction".
    pub fn describe(&self, subject: &str) -> String {
        match self {
            Self::Storage(error) => error.clone(),
            refusal => format!("{subject} {refusal}"),
        }
    }
}

/// The refusal as what the transaction does, for [`Refusal::describe`].
impl fmt::Display for Refusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidAccount => formatter.write_str("names an invalid companion account"),
            Self::InvalidMarker(reason) => {
                write!(formatter, "writes an invalid feature marker: {reason}")
            }
            Self::InvalidLiveMarker { vault_id, reason } => write!(
                formatter,
                "touches env project {vault_id}, whose feature marker is invalid: {reason}"
            ),
            Self::Unlisted(unlisted) => write!(formatter, "{unlisted}"),
            Self::Orphans(account) => write!(
                formatter,
                "would leave {} without a feature that lists it",
                account.name()
            ),
            Self::Storage(error) => formatter.write_str(error),
        }
    }
}

/// Check every record of one project a transaction writes against
/// `post_marker`, the marker the transaction leaves.
pub fn check_written<'account>(
    post_marker: Option<&Marker>,
    written: impl IntoIterator<Item = &'account CompanionAccount>,
) -> Result<(), Unlisted> {
    match written
        .into_iter()
        .find(|account| !is_listed(post_marker, account))
    {
        Some(account) => Err(Unlisted(account.clone())),
        None => Ok(()),
    }
}

/// Check one transaction for every project it touches: `changes` are
/// account names with the bytes each writes, or `None` for a deletion, and
/// only a marker's bytes are read, so other writes may pass empty bytes.
/// Accounts outside the companion namespace are skipped. `live_marker`
/// reads a touched project's marker as the store holds it now.
///
/// With `names`, a names-only listing of the store, a transaction that
/// changes a marker is also checked for records it would leave without a
/// feature. That needs the marker from before the transaction, so it's
/// checked only while the store still holds it: when recovery finds the
/// marker's change already replayed, refusing would undo nothing.
pub fn check_transaction(
    changes: &[(&str, Option<&[u8]>)],
    mut live_marker: impl FnMut(&str) -> Result<Option<Vec<u8>>, String>,
    names: Option<&[String]>,
) -> Result<(), Refusal> {
    type Changes<'value> = Vec<(CompanionAccount, Option<&'value [u8]>)>;
    let mut by_vault: BTreeMap<String, Changes<'_>> = BTreeMap::new();
    for (account, value) in changes {
        if !is_in_companion_namespace(account) {
            continue;
        }
        let parsed = CompanionAccount::parse(account).ok_or(Refusal::InvalidAccount)?;
        by_vault
            .entry(parsed.vault_id().to_owned())
            .or_default()
            .push((parsed, *value));
    }
    for (vault_id, vault_changes) in &by_vault {
        let marker_change = vault_changes
            .iter()
            .find(|(account, _)| matches!(account, CompanionAccount::Marker { .. }))
            .map(|(_, value)| *value);
        let live = match (marker_change, names) {
            (Some(_), None) => None,
            _ => Some(live_marker(vault_id).map_err(Refusal::Storage)?),
        };
        let post_marker = match (marker_change, &live) {
            (Some(Some(bytes)), _) => Some(
                Marker::parse(vault_id, bytes)
                    .map_err(|error| Refusal::InvalidMarker(error.to_string()))?,
            ),
            (Some(None), _) => None,
            (None, live) => live
                .as_ref()
                .and_then(Option::as_deref)
                .map(|bytes| {
                    Marker::parse(vault_id, bytes).map_err(|error| Refusal::InvalidLiveMarker {
                        vault_id: vault_id.clone(),
                        reason: error.to_string(),
                    })
                })
                .transpose()?,
        };
        let written = vault_changes
            .iter()
            .filter(|(_, value)| value.is_some())
            .map(|(account, _)| account);
        check_written(post_marker.as_ref(), written).map_err(Refusal::Unlisted)?;

        let before = match (marker_change, live.as_ref().and_then(Option::as_deref)) {
            (Some(Some(after)), Some(live)) if live != after => Some(live),
            (Some(None), Some(live)) => Some(live),
            _ => None,
        };
        if let (Some(names), Some(before)) = (names, before) {
            let before = Marker::parse(vault_id, before).ok();
            let deleted: HashSet<&CompanionAccount> = vault_changes
                .iter()
                .filter(|(_, value)| value.is_none())
                .map(|(account, _)| account)
                .collect();
            let orphan = names
                .iter()
                .filter_map(|name| CompanionAccount::parse(name))
                .filter(|account| account.vault_id() == vault_id && !deleted.contains(account))
                .find(|account| {
                    is_listed(before.as_ref(), account) && !is_listed(post_marker.as_ref(), account)
                });
            if let Some(account) = orphan {
                return Err(Refusal::Orphans(account));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::marker::{FeatureEntry, FeatureState, Level, Restore, RestorePhase};

    fn record(kind: &str) -> CompanionAccount {
        CompanionAccount::Record {
            kind: kind.to_owned(),
            vault_id: "proj".to_owned(),
            part: None,
        }
    }

    fn staged(kind: &str) -> CompanionAccount {
        CompanionAccount::Staged {
            kind: kind.to_owned(),
            vault_id: "proj".to_owned(),
            part: None,
        }
    }

    fn overrides_marker() -> Marker {
        let mut marker = Marker::empty("proj", ProjectState::Active);
        marker.features.insert(
            "overrides".to_owned(),
            FeatureEntry {
                version: 1,
                if_unsupported: Level::Refuse,
                kinds: vec!["overrides".to_owned()],
                state: FeatureState::Active,
            },
        );
        marker
    }

    #[test]
    fn without_a_marker_only_the_marker_is_listed() {
        assert!(is_listed(
            None,
            &CompanionAccount::Marker {
                vault_id: "proj".to_owned()
            }
        ));
        assert!(!is_listed(None, &record("overrides")));
        assert!(!is_listed(None, &staged("overrides")));
    }

    #[test]
    fn staged_records_are_listed_only_by_the_restore_in_progress() {
        let mut marker = overrides_marker();
        assert!(is_listed(Some(&marker), &record("overrides")));
        assert!(!is_listed(Some(&marker), &staged("overrides")));
        marker.state = ProjectState::Restoring;
        marker.restore = Some(Restore {
            phase: RestorePhase::Staging,
            replaces: vec!["overrides".to_owned()],
            features: [(
                "overrides".to_owned(),
                FeatureEntry {
                    version: 1,
                    if_unsupported: Level::Refuse,
                    kinds: vec!["overrides".to_owned()],
                    state: FeatureState::Active,
                },
            )]
            .into(),
        });
        assert!(is_listed(Some(&marker), &staged("overrides")));
    }

    const OVERRIDES_MARKER: &str = r#"{"schemaVersion":1,"vaultId":"proj","state":"active","features":{"overrides":{"version":1,"ifUnsupported":"refuse","kinds":["overrides"],"state":"active"}}}"#;

    #[test]
    fn a_transaction_writing_a_record_with_its_marker_passes() {
        let marker = crate::account::marker_account("proj");
        let overrides = crate::account::record_account("overrides", "proj", None);
        let changes = [
            ("proj", Some(&b"{}"[..])),
            (marker.as_str(), Some(OVERRIDES_MARKER.as_bytes())),
            (overrides.as_str(), Some(&b"{}"[..])),
        ];
        assert_eq!(
            check_transaction(&changes, |_| panic!("the marker changes"), None),
            Ok(())
        );
    }

    #[test]
    fn a_transaction_is_checked_against_the_live_marker_it_keeps() {
        let overrides = crate::account::record_account("overrides", "proj", None);
        let notes = crate::account::record_account("notes", "proj", None);
        let live = |vault_id: &str| {
            assert_eq!(vault_id, "proj");
            Ok(Some(OVERRIDES_MARKER.as_bytes().to_vec()))
        };
        assert_eq!(
            check_transaction(&[(overrides.as_str(), Some(&b"{}"[..]))], live, None),
            Ok(())
        );
        assert_eq!(
            check_transaction(&[(notes.as_str(), Some(&b"x"[..]))], live, None),
            Err(Refusal::Unlisted(Unlisted(record("notes"))))
        );
        assert_eq!(
            check_transaction(&[(notes.as_str(), None)], live, None),
            Ok(()),
            "deleting an unlisted record repairs it"
        );
        assert!(matches!(
            check_transaction(
                &[(overrides.as_str(), Some(&b"{}"[..]))],
                |_| Ok(Some(b"not a marker".to_vec())),
                None
            ),
            Err(Refusal::InvalidLiveMarker { .. })
        ));
        assert_eq!(
            check_transaction(&[("__vault_companion_v1__:Bad:cHJvag", None)], live, None),
            Err(Refusal::InvalidAccount)
        );
    }

    #[test]
    fn recovery_refuses_orphaning_listed_records_only_while_the_old_marker_is_there() {
        let marker = crate::account::marker_account("proj");
        let overrides = crate::account::record_account("overrides", "proj", None);
        let stray = crate::account::record_account("future-kind", "proj", None);
        let names = [marker.clone(), overrides.clone(), stray];
        let live = |_: &str| Ok(Some(OVERRIDES_MARKER.as_bytes().to_vec()));
        let deletes_marker = [(marker.as_str(), None)];
        assert_eq!(
            check_transaction(&deletes_marker, live, Some(&names)),
            Err(Refusal::Orphans(record("overrides")))
        );
        assert_eq!(
            check_transaction(&deletes_marker, |_| Ok(None), Some(&names)),
            Ok(()),
            "the deletion was replayed already"
        );
        let deletes_with_records = [(marker.as_str(), None), (overrides.as_str(), None)];
        assert_eq!(
            check_transaction(&deletes_with_records, live, Some(&names)),
            Ok(()),
            "the stray was unlisted before"
        );
        let empty = r#"{"schemaVersion":1,"vaultId":"proj","state":"active","features":{}}"#;
        let drops_feature = [(marker.as_str(), Some(empty.as_bytes()))];
        assert_eq!(
            check_transaction(&drops_feature, live, Some(&names)),
            Err(Refusal::Orphans(record("overrides")))
        );
        assert_eq!(
            check_transaction(
                &drops_feature,
                |_| Ok(Some(empty.as_bytes().to_vec())),
                Some(&names)
            ),
            Ok(()),
            "the marker was replayed already"
        );
        assert_eq!(
            check_transaction(&deletes_marker, live, None),
            Ok(()),
            "commits are planned from the inventory"
        );
    }

    #[test]
    fn a_write_the_post_marker_doesnt_list_is_refused_whatever_else_exists() {
        let marker = overrides_marker();
        assert_eq!(
            check_written(Some(&marker), [&record("notes")]),
            Err(Unlisted(record("notes")))
        );
        assert_eq!(
            check_written(None, [&record("overrides")]),
            Err(Unlisted(record("overrides")))
        );
        assert_eq!(check_written(Some(&marker), [&record("overrides")]), Ok(()));
        assert_eq!(
            check_written(Some(&marker), [&staged("overrides")]),
            Err(Unlisted(staged("overrides")))
        );
    }

    #[test]
    fn a_deleting_or_discarding_marker_covers_every_record_of_its_project() {
        for state in [ProjectState::Deleting, ProjectState::Discarding] {
            let marker = Marker::empty("proj", state);
            assert!(is_listed(Some(&marker), &record("future-kind")));
            assert!(is_listed(Some(&marker), &staged("overrides")));
        }
        assert!(!is_listed(
            Some(&Marker::empty("proj", ProjectState::Active)),
            &record("future-kind")
        ));
    }
}
