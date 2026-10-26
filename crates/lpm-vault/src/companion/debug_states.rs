//! Companion storage states planted by hand, for trying LPM and LPM Vault
//! against the same data on one machine. They go straight into the store
//! that holds the project, past the gate and the transaction check, as a
//! later client or damage would leave them. Debug builds only.

use serde_json::{Value, json};

use super::account::CompanionAccount;
use super::lifecycle::Mutation;
use super::overrides::OVERRIDES_KIND;

/// A companion storage state to plant for one project.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DebugCompanionState {
    /// Valid personal overrides of `environment`'s values.
    Overrides {
        environment: String,
        set: Vec<(String, String)>,
        unset: Vec<String>,
    },
    /// A marker listing personal overrides with no overrides record.
    MissingRecord,
    /// A marker that doesn't parse, next to an overrides record.
    InvalidMarker,
    /// Valid overrides, and records of a kind no feature lists.
    UnlistedRecords,
    /// Personal overrides of a version this LPM doesn't support.
    NewerVersion,
    /// A feature this LPM doesn't support, which lets it read but not write.
    ReadOnly,
    /// A deletion of the project's newer data that a crash left unfinished.
    InterruptedDeletion,
    /// A restore whose staged record is too large to move, so it can't be
    /// finished. Keychain only: the file store refuses such a record.
    StuckRestore,
    /// Valid overrides whose record names an approval policy LPM doesn't
    /// know, so its approval attributes contradict each other. Keychain only.
    ContradictoryRecord,
    /// Values that claim CLI approval the Keychain doesn't enforce, next to
    /// valid overrides. Keychain only, with the project's approval off.
    WeakValues,
    /// Newer data of a project with no values item, as an LPM Vault older
    /// than companion storage leaves when it deletes one. Keychain only.
    Orphans,
    /// None of the project's newer data.
    Clear,
}

impl DebugCompanionState {
    /// The state a command-line name chooses, and for `overrides` the
    /// environment and overrides it plants.
    pub fn named(
        name: &str,
        environment: Option<&str>,
        set: &[String],
        unset: &[String],
    ) -> Result<Self, String> {
        if name != "overrides" && (!set.is_empty() || !unset.is_empty()) {
            return Err("--set and --unset only go with the overrides state".to_owned());
        }
        if name == "overrides" && set.is_empty() && unset.is_empty() {
            return Err("the overrides state needs --set NAME=VALUE or --unset NAME".to_owned());
        }
        Ok(match name {
            "overrides" => Self::Overrides {
                environment: environment.unwrap_or("default").to_owned(),
                set: set
                    .iter()
                    .map(|pair| {
                        pair.split_once('=')
                            .map(|(name, value)| (name.to_owned(), value.to_owned()))
                            .ok_or_else(|| format!("--set {pair:?} isn't NAME=VALUE"))
                    })
                    .collect::<Result<_, _>>()?,
                unset: unset.to_vec(),
            },
            "missing-record" => Self::MissingRecord,
            "invalid-marker" => Self::InvalidMarker,
            "unlisted-records" => Self::UnlistedRecords,
            "newer-version" => Self::NewerVersion,
            "read-only" => Self::ReadOnly,
            "interrupted-deletion" => Self::InterruptedDeletion,
            "stuck-restore" => Self::StuckRestore,
            "contradictory-record" => Self::ContradictoryRecord,
            "weak-values" => Self::WeakValues,
            "orphans" => Self::Orphans,
            "clear" => Self::Clear,
            other => {
                return Err(format!(
                    "{other:?} isn't a state; one of: {}",
                    Self::NAMES.join(", ")
                ));
            }
        })
    }

    pub const NAMES: &'static [&'static str] = &[
        "overrides",
        "missing-record",
        "invalid-marker",
        "unlisted-records",
        "newer-version",
        "read-only",
        "interrupted-deletion",
        "stuck-restore",
        "contradictory-record",
        "weak-values",
        "orphans",
        "clear",
    ];

    /// Whether only the Keychain can hold this state.
    pub(crate) fn needs_keychain(&self) -> bool {
        matches!(
            self,
            Self::StuckRestore | Self::ContradictoryRecord | Self::WeakValues | Self::Orphans
        )
    }
}

/// An approval claim an item's attributes make, past what its access control
/// enforces.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PlantedClaim {
    /// A policy marker LPM doesn't know, which no client can trust.
    UnknownPolicy,
    /// The approval marker, on an item whose access control asks for nothing.
    ApprovalNotEnforced,
    /// No approval, as an item whose access control asks for nothing claims.
    #[cfg(target_os = "macos")]
    ApprovalOff,
}

/// What planting a state changes, for the store that holds the project.
#[derive(Debug, Default)]
pub(crate) struct Planting {
    /// The project's companion accounts to delete before the state's are
    /// written, its marker included.
    pub(crate) clear: Vec<CompanionAccount>,
    /// The state's accounts and their bytes.
    pub(crate) writes: Vec<(CompanionAccount, Vec<u8>)>,
    /// Approval claims to leave on items once they're written, by account.
    pub(crate) claims: Vec<(String, PlantedClaim)>,
    /// Another project's newer data, with the vault ID it's under.
    pub(crate) orphans: Option<(String, Vec<Mutation>)>,
    /// What was planted, and what each client should show for it.
    pub(crate) description: String,
}

/// Records a state writes, with their bytes.
type Records = Vec<(CompanionAccount, Vec<u8>)>;

/// What planting `state` for `vault_id` changes, `existing` being the
/// project's companion and staged records now.
pub(crate) fn planting(
    vault_id: &str,
    state: &DebugCompanionState,
    existing: Vec<CompanionAccount>,
) -> Planting {
    use DebugCompanionState as State;
    let mut planting = Planting::default();
    let overrides_v1 = feature(1, "refuse", &[OVERRIDES_KIND]);
    let (marker_bytes, records, description): (Option<Vec<u8>>, Records, String) = match state {
        State::Clear => (
            None,
            Vec::new(),
            "Removed this env project's newer data, and any approval claim a planted state left on its values that the Keychain doesn't enforce; its values stay.".to_owned(),
        ),
        State::Overrides {
            environment,
            set,
            unset,
        } => (
            Some(marker(vault_id, "active", json!({ "overrides": overrides_v1 }), None)),
            vec![(
                record(vault_id, OVERRIDES_KIND, None),
                overrides_record(vault_id, environment, set, unset),
            )],
            format!(
                "Planted personal overrides of {environment}: {}. lpm run, dev, exec, print, check and env ls apply them and say how many; CI emission and platform pushes leave them out. LPM Vault shows no banner, and a backup says it leaves them out.",
                overrides_summary(set, unset)
            ),
        ),
        State::MissingRecord => (
            Some(marker(vault_id, "active", json!({ "overrides": overrides_v1 }), None)),
            Vec::new(),
            "Planted a feature marker listing personal overrides, with no overrides record. lpm run refuses until it's repaired; lpm env repair removes the feature. LPM Vault shows the damage and refuses edits; Repair… removes personal overrides.".to_owned(),
        ),
        State::InvalidMarker => (
            Some(br#"{"schemaVersion":1}"#.to_vec()),
            vec![(
                record(vault_id, OVERRIDES_KIND, None),
                placeholder_overrides(vault_id),
            )],
            "Planted a feature marker that doesn't parse. Every read refuses until it's repaired; lpm env repair and LPM Vault's Repair… discard the newer data and keep the values.".to_owned(),
        ),
        State::UnlistedRecords => (
            Some(marker(vault_id, "active", json!({ "overrides": overrides_v1 }), None)),
            vec![
                (
                    record(vault_id, OVERRIDES_KIND, None),
                    placeholder_overrides(vault_id),
                ),
                (record(vault_id, "notes", None), b"stray".to_vec()),
            ],
            "Planted valid overrides and a \"notes\" record no feature lists. The CLI doesn't list the store, so it sees nothing wrong. LPM Vault shows the damage, refuses edits, and Repair… deletes only the stray record.".to_owned(),
        ),
        State::NewerVersion => (
            Some(marker(
                vault_id,
                "active",
                json!({ "overrides": feature(2, "refuse", &[OVERRIDES_KIND]) }),
                None,
            )),
            vec![(
                record(vault_id, OVERRIDES_KIND, None),
                br#"{"schemaVersion":2}"#.to_vec(),
            )],
            "Planted personal overrides v2. lpm refuses to read, run or write the project and asks for lpm self-update. LPM Vault hides its values and offers Check for Updates…; rename, hide, approval and delete still work.".to_owned(),
        ),
        State::ReadOnly => (
            Some(marker(
                vault_id,
                "active",
                json!({ "future": feature(1, "readOnly", &["future-log"]) }),
                None,
            )),
            vec![(record(vault_id, "future-log", Some(0)), b"entry".to_vec())],
            "Planted a feature this LPM can only read. Reads and runs work; writes are refused. LPM Vault shows the values, says changes need an update, and turns its edit controls off.".to_owned(),
        ),
        State::InterruptedDeletion => (
            Some(marker(vault_id, "deleting", json!({}), None)),
            (0..3)
                .map(|part| (record(vault_id, "future-log", Some(part)), b"left".to_vec()))
                .collect(),
            "Planted a deletion of the newer data that a crash left unfinished. The next lpm command or LPM Vault refresh finishes it and says so once; the values stay.".to_owned(),
        ),
        State::StuckRestore => (
            Some(marker(
                vault_id,
                "restoring",
                json!({}),
                Some(json!({
                    "phase": "activating",
                    "replaces": [],
                    "features": { "overrides": overrides_v1 },
                })),
            )),
            vec![(
                staged(vault_id, OVERRIDES_KIND),
                vec![b'x'; 101 * 1024],
            )],
            "Planted a restore whose staged record is over the 100 KiB a record may hold, so it can't be finished. Reads refuse with the reason. LPM Vault shows the unfinished change and why; deleting the project still works.".to_owned(),
        ),
        State::ContradictoryRecord => {
            let overrides = record(vault_id, OVERRIDES_KIND, None);
            planting
                .claims
                .push((overrides.name(), PlantedClaim::UnknownPolicy));
            (
                Some(marker(vault_id, "active", json!({ "overrides": overrides_v1 }), None)),
                vec![(overrides, placeholder_overrides(vault_id))],
                "Planted overrides whose record names an approval policy LPM doesn't know. lpm run refuses the record. LPM Vault shows damaged approval settings and sets them at its next unlock.".to_owned(),
            )
        }
        State::WeakValues => {
            planting
                .claims
                .push((vault_id.to_owned(), PlantedClaim::ApprovalNotEnforced));
            (
                Some(marker(vault_id, "active", json!({ "overrides": overrides_v1 }), None)),
                vec![(record(vault_id, OVERRIDES_KIND, None), placeholder_overrides(vault_id))],
                "Planted CLI approval on this project's values without the protection behind it: they still read without asking, while newer data written from now on takes the approval they claim, so lpm asks before reading it. LPM Vault gives the values that approval at its next unlock. clear undoes the claim.".to_owned(),
            )
        }
        State::Orphans => {
            let orphan = orphan_vault_id(vault_id);
            planting.orphans = Some((
                orphan.clone(),
                vec![
                    Mutation::Write {
                        account: marker_account(&orphan),
                        value: marker(&orphan, "active", json!({ "overrides": overrides_v1 }), None),
                    },
                    Mutation::Write {
                        account: record(&orphan, OVERRIDES_KIND, None),
                        value: placeholder_overrides(&orphan),
                    },
                ],
            ));
            (
                None,
                Vec::new(),
                format!(
                    "Planted newer data of {orphan}, a project with no values item, and left this project as it was. LPM Vault deletes it the next time it unlocks."
                ),
            )
        }
    };
    planting.description = description;
    if matches!(state, State::Orphans) {
        return planting;
    }
    planting.writes = marker_bytes
        .map(|value| (marker_account(vault_id), value))
        .into_iter()
        .chain(records)
        .collect();
    planting.clear = existing
        .into_iter()
        .chain([marker_account(vault_id)])
        .collect();
    planting
}

impl Planting {
    /// The project's changes as one transaction, which names each account
    /// once: what it writes isn't deleted first. A store whose writes keep an
    /// item's attributes clears every account before writing instead.
    pub(crate) fn one_transaction(&self) -> Vec<Mutation> {
        self.clear
            .iter()
            .filter(|account| !self.writes.iter().any(|(written, _)| written == *account))
            .map(|account| Mutation::Delete {
                account: account.clone(),
            })
            .chain(self.writes.iter().map(|(account, value)| Mutation::Write {
                account: account.clone(),
                value: value.clone(),
            }))
            .collect()
    }
}

/// The vault ID planted orphans belong to, the same for one project every time.
pub(crate) fn orphan_vault_id(vault_id: &str) -> String {
    let short: String = vault_id
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .take(8)
        .collect();
    format!("debug-orphan-{short}")
}

fn marker_account(vault_id: &str) -> CompanionAccount {
    CompanionAccount::Marker {
        vault_id: vault_id.to_owned(),
    }
}

fn record(vault_id: &str, kind: &str, part: Option<u16>) -> CompanionAccount {
    CompanionAccount::Record {
        kind: kind.to_owned(),
        vault_id: vault_id.to_owned(),
        part,
    }
}

fn staged(vault_id: &str, kind: &str) -> CompanionAccount {
    CompanionAccount::Staged {
        kind: kind.to_owned(),
        vault_id: vault_id.to_owned(),
        part: None,
    }
}

fn feature(version: u16, if_unsupported: &str, kinds: &[&str]) -> Value {
    json!({
        "version": version,
        "ifUnsupported": if_unsupported,
        "kinds": kinds,
        "state": "active",
    })
}

fn marker(vault_id: &str, state: &str, features: Value, restore: Option<Value>) -> Vec<u8> {
    let mut marker = json!({
        "schemaVersion": 1,
        "vaultId": vault_id,
        "state": state,
        "features": features,
    });
    if let Some(restore) = restore {
        marker["restore"] = restore;
    }
    marker.to_string().into_bytes()
}

fn overrides_record(
    vault_id: &str,
    environment: &str,
    set: &[(String, String)],
    unset: &[String],
) -> Vec<u8> {
    let set: serde_json::Map<String, Value> = set
        .iter()
        .map(|(name, value)| (name.clone(), Value::String(value.clone())))
        .collect();
    json!({
        "schemaVersion": 1,
        "vaultId": vault_id,
        "environments": { environment: { "set": set, "unset": unset } },
    })
    .to_string()
    .into_bytes()
}

/// A valid overrides record that changes nothing: it unsets a name no
/// project sets.
fn placeholder_overrides(vault_id: &str) -> Vec<u8> {
    overrides_record(
        vault_id,
        "default",
        &[],
        &["LPM_DEBUG_COMPANION_UNSET".to_owned()],
    )
}

fn overrides_summary(set: &[(String, String)], unset: &[String]) -> String {
    let mut parts: Vec<String> = set.iter().map(|(name, _)| format!("set {name}")).collect();
    parts.extend(unset.iter().map(|name| format!("unset {name}")));
    if parts.is_empty() {
        "none".to_owned()
    } else {
        parts.join(", ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::companion::assessment::{Observed, assess};

    const VAULT: &str = "550e8400-e29b-41d4-a716-446655440000";

    /// The project's state after `planting`, as a client with a listing judges it.
    fn assessed(planting: &Planting) -> crate::companion::assessment::Assessment {
        let mut marker = None;
        let mut inventory = Vec::new();
        let mut overrides = None;
        for mutation in &planting.one_transaction() {
            if let Mutation::Write { account, value } = mutation {
                match account {
                    CompanionAccount::Marker { .. } => marker = Some(value.clone()),
                    CompanionAccount::Record {
                        kind, part: None, ..
                    } if kind == OVERRIDES_KIND => {
                        overrides = Some(value.clone());
                        inventory.push(account.clone());
                    }
                    other => inventory.push(other.clone()),
                }
            }
        }
        assess(
            VAULT,
            Observed {
                marker: marker.as_deref(),
                inventory: Some(&inventory),
                overrides: Some(overrides.as_deref()),
                access: planting
                    .claims
                    .iter()
                    .any(|(_, claim)| *claim == PlantedClaim::UnknownPolicy)
                    .then_some("contradicts"),
                unfinished: None,
            },
        )
    }

    /// The state `name` chooses, overrides planting one set.
    fn named(name: &str) -> DebugCompanionState {
        let set = ["A=1".to_owned()];
        let set = if name == "overrides" { &set[..] } else { &[] };
        DebugCompanionState::named(name, None, set, &[]).expect(name)
    }

    fn planted(state: DebugCompanionState) -> Planting {
        planting(VAULT, &state, vec![record(VAULT, "old", None)])
    }

    #[test]
    fn every_state_is_named_on_the_command_line() {
        for name in DebugCompanionState::NAMES {
            named(name);
        }
        assert!(
            DebugCompanionState::named("overrides", None, &[], &[]).is_err(),
            "a record with no overrides is invalid"
        );
        assert!(DebugCompanionState::named("nonsense", None, &[], &[]).is_err());
        assert!(
            DebugCompanionState::named("clear", None, &["A=1".to_owned()], &[]).is_err(),
            "only overrides take overrides"
        );
        assert_eq!(
            DebugCompanionState::named(
                "overrides",
                Some("dev"),
                &["API_URL=mine".to_owned()],
                &["X".to_owned()]
            ),
            Ok(DebugCompanionState::Overrides {
                environment: "dev".to_owned(),
                set: vec![("API_URL".to_owned(), "mine".to_owned())],
                unset: vec!["X".to_owned()],
            })
        );
    }

    #[test]
    fn no_state_names_an_account_twice() {
        for name in DebugCompanionState::NAMES {
            let planting = planting(
                VAULT,
                &named(name),
                vec![
                    record(VAULT, OVERRIDES_KIND, None),
                    record(VAULT, "old", None),
                ],
            );
            let mutations = planting.one_transaction();
            let mut targets: Vec<&CompanionAccount> = mutations
                .iter()
                .map(|mutation| match mutation {
                    Mutation::Write { account, .. } | Mutation::Delete { account } => account,
                })
                .collect();
            let all = targets.len();
            targets.sort_by_key(|account| account.name());
            targets.dedup();
            assert_eq!(targets.len(), all, "{name}");
        }
    }

    #[test]
    fn every_state_first_clears_what_the_project_had() {
        for name in DebugCompanionState::NAMES
            .iter()
            .filter(|name| **name != "orphans")
        {
            let planting = planted(named(name));
            assert!(
                planting.one_transaction().iter().any(|mutation| matches!(
                    mutation,
                    Mutation::Delete { account } if *account == record(VAULT, "old", None)
                )),
                "{name}"
            );
        }
    }

    #[test]
    fn each_state_is_judged_as_its_description_says() {
        let overrides = planted(DebugCompanionState::Overrides {
            environment: "default".to_owned(),
            set: vec![("API_URL".to_owned(), "mine".to_owned())],
            unset: Vec::new(),
        });
        let healthy = assessed(&overrides);
        assert!(healthy.damage.is_empty(), "{:?}", healthy.damage);
        assert!(
            healthy
                .authorize(crate::companion::gate::Operation::ReadApplyingOverrides)
                .is_ok()
        );

        let codes = |state| {
            assessed(&planted(state))
                .every_damage()
                .map(|damage| {
                    let debug = format!("{damage:?}");
                    debug[..debug.find(['(', ' ']).unwrap_or(debug.len())].to_owned()
                })
                .collect::<Vec<_>>()
        };
        assert_eq!(codes(DebugCompanionState::MissingRecord), ["MissingRecord"]);
        assert_eq!(codes(DebugCompanionState::InvalidMarker), ["InvalidMarker"]);
        assert_eq!(
            codes(DebugCompanionState::UnlistedRecords),
            ["UnlistedRecord"]
        );
        assert_eq!(codes(DebugCompanionState::ContradictoryRecord), ["Access"]);
        assert!(codes(DebugCompanionState::NewerVersion).is_empty());
        let newer = assessed(&planted(DebugCompanionState::NewerVersion));
        assert!(
            newer
                .authorize(crate::companion::gate::Operation::ReadExcludingOverrides)
                .is_err()
        );
        let read_only = assessed(&planted(DebugCompanionState::ReadOnly));
        assert!(
            read_only
                .authorize(crate::companion::gate::Operation::ReadExcludingOverrides)
                .is_ok()
        );
        assert!(
            read_only
                .authorize(crate::companion::gate::Operation::Write)
                .is_err()
        );
        assert!(assessed(&planted(DebugCompanionState::InterruptedDeletion)).needs_resume());
        assert!(assessed(&planted(DebugCompanionState::StuckRestore)).needs_resume());
    }

    #[test]
    fn orphans_belong_to_another_project_and_leave_this_one_as_it_was() {
        let planting = planted(DebugCompanionState::Orphans);
        assert!(planting.clear.is_empty() && planting.writes.is_empty());
        let (orphan, mutations) = planting.orphans.expect("orphans");
        assert_eq!(orphan, "debug-orphan-550e8400");
        assert!(crate::vault_id::is_safe_vault_id(&orphan));
        assert_eq!(mutations.len(), 2);
        assert!(DebugCompanionState::Orphans.needs_keychain());
        assert!(DebugCompanionState::StuckRestore.needs_keychain());
        assert!(!DebugCompanionState::MissingRecord.needs_keychain());
    }
}
