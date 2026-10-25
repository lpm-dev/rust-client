//! Companion storage for an app that shares the CLI's credential store: the
//! CLI's account names, marker rules, operation matrix, damage and lifecycle
//! plans, through `lpm-env-companion`, so both clients decide alike. Each
//! function takes one JSON document. Stored bytes travel as standard base64,
//! and nothing here reads or writes a store.

use std::collections::BTreeMap;
use std::panic::{AssertUnwindSafe, catch_unwind};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use lpm_common::stored_env::is_safe_vault_id;
use lpm_env_companion::account::CompanionAccount;
use lpm_env_companion::assessment::{Assessment, Observed, Repair, assess};
use lpm_env_companion::gate::{Damage, Operation, ProjectGate};
use lpm_env_companion::graph::{AccessClass, record_access_class};
use lpm_env_companion::invariants::{Refusal, check_transaction};
use lpm_env_companion::lifecycle::{
    FoundMarker, MarkerChange, Plan, PlannedChange, needs_resume, plan_deletion, plan_discard,
    plan_feature_removal, plan_resume, plan_unlisted_removal,
};
use lpm_env_companion::marker::{
    FeatureEntry, FeatureState, Level, Marker, ProjectState, RestorePhase, is_supported,
};
use serde::de::{DeserializeOwned, Error as _};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::{ABI_VERSION, LPMEnvResult, OUTPUT_LIMIT, failure, result};

/// The largest request, matching `LPM_ENV_INPUT_LIMIT`.
const INPUT_LIMIT: usize = 2 * 1024 * 1024;
const REFUSED: u32 = 5;

/// Bytes a store holds, as standard base64 in JSON.
#[derive(Clone)]
struct Bytes(Vec<u8>);

impl<'de> Deserialize<'de> for Bytes {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let encoded = String::deserialize(deserializer)?;
        STANDARD
            .decode(encoded)
            .map(Self)
            .map_err(|_| D::Error::custom("invalid base64"))
    }
}

impl Serialize for Bytes {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&STANDARD.encode(&self.0))
    }
}

/// Run `handle` on the JSON request at `input`, inside a panic guard.
///
/// # Safety
/// A non-null pointer must reference readable bytes for its length during the call.
unsafe fn respond<T: DeserializeOwned>(
    input: *const u8,
    length: usize,
    handle: impl FnOnce(T) -> LPMEnvResult,
) -> LPMEnvResult {
    if input.is_null() || length == 0 || length > INPUT_LIMIT {
        return failure(2, "companion.invalid_input");
    }
    // SAFETY: The caller supplies a live readable range; its length was bounded above.
    let bytes = unsafe { std::slice::from_raw_parts(input, length) };
    catch_unwind(AssertUnwindSafe(|| match serde_json::from_slice(bytes) {
        Ok(request) => handle(request),
        Err(_) => failure(2, "companion.invalid_input"),
    }))
    .unwrap_or_else(|_| failure(3, "env.engine_panic"))
}

fn json(output: &impl Serialize) -> LPMEnvResult {
    match serde_json::to_vec(output) {
        Ok(bytes) if bytes.len() <= OUTPUT_LIMIT => result(0, bytes, None),
        Ok(_) => failure(4, "env.output_budget"),
        Err(_) => failure(3, "env.engine_internal"),
    }
}

fn refusal(code: &'static str, message: String) -> LPMEnvResult {
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct Refused {
        abi_version: u32,
        code: &'static str,
        message: String,
    }
    match serde_json::to_vec(&Refused {
        abi_version: ABI_VERSION,
        code,
        message,
    }) {
        Ok(bytes) => result(REFUSED, bytes, None),
        Err(_) => failure(3, "env.engine_internal"),
    }
}

/// The records of `vault_id` among `names`, the marker left out.
fn project_inventory(vault_id: &str, names: &[String]) -> Vec<CompanionAccount> {
    names
        .iter()
        .filter_map(|name| CompanionAccount::parse(name))
        .filter(|account| {
            account.vault_id() == vault_id && !matches!(account, CompanionAccount::Marker { .. })
        })
        .collect()
}

/// Describe each account name: `null` outside the companion namespace,
/// `{valid: false}` for a name in it spelled any other way than the one
/// spelling, else its role, vault ID, kind, part and access class.
/// # Safety
/// The pointer must reference readable bytes for its length during the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn lpm_env_companion_accounts(
    input: *const u8,
    length: usize,
) -> LPMEnvResult {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Request {
        names: Vec<String>,
    }
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct Described {
        valid: bool,
        #[serde(flatten, skip_serializing_if = "Option::is_none")]
        account: Option<Fields>,
    }
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct Fields {
        role: &'static str,
        vault_id: String,
        kind: Option<String>,
        part: Option<u16>,
        access: &'static str,
    }
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct Output {
        abi_version: u32,
        accounts: Vec<Option<Described>>,
    }
    // SAFETY: Forwarded from this function's contract.
    unsafe {
        respond(input, length, |request: Request| {
            let accounts = request
                .names
                .iter()
                .map(|name| {
                    if !lpm_env_companion::account::is_in_companion_namespace(name) {
                        return None;
                    }
                    let account = CompanionAccount::parse(name).map(|account| {
                        let (role, access) = match &account {
                            CompanionAccount::Marker { .. } => ("marker", AccessClass::Open),
                            CompanionAccount::Record { kind, part, .. } => {
                                ("record", record_access_class(kind, *part))
                            }
                            CompanionAccount::Staged { kind, part, .. } => {
                                ("staged", record_access_class(kind, *part))
                            }
                        };
                        Fields {
                            role,
                            vault_id: account.vault_id().to_owned(),
                            kind: account.kind().map(str::to_owned),
                            part: account.part(),
                            access: match access {
                                AccessClass::Open => "open",
                                AccessClass::FollowsValues => "followsValues",
                            },
                        }
                    });
                    Some(Described {
                        valid: account.is_some(),
                        account,
                    })
                })
                .collect();
            json(&Output {
                abi_version: ABI_VERSION,
                accounts,
            })
        })
    }
}

/// Spell accounts: each `{role, vaultId, kind?, part?}` becomes its one name.
/// # Safety
/// The pointer must reference readable bytes for its length during the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn lpm_env_companion_account_names(
    input: *const u8,
    length: usize,
) -> LPMEnvResult {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Request {
        accounts: Vec<Spec>,
    }
    #[derive(Deserialize)]
    #[serde(rename_all = "lowercase")]
    enum Role {
        Marker,
        Record,
        Staged,
    }
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct Spec {
        role: Role,
        vault_id: String,
        #[serde(default)]
        kind: Option<String>,
        #[serde(default)]
        part: Option<u16>,
    }
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct Output {
        abi_version: u32,
        names: Vec<String>,
    }
    // SAFETY: Forwarded from this function's contract.
    unsafe {
        respond(input, length, |request: Request| {
            let mut names = Vec::with_capacity(request.accounts.len());
            for spec in request.accounts {
                let account = match (spec.role, spec.kind) {
                    (Role::Marker, None) if spec.part.is_none() => CompanionAccount::Marker {
                        vault_id: spec.vault_id,
                    },
                    (Role::Record, Some(kind)) => CompanionAccount::Record {
                        kind,
                        vault_id: spec.vault_id,
                        part: spec.part,
                    },
                    (Role::Staged, Some(kind)) => CompanionAccount::Staged {
                        kind,
                        vault_id: spec.vault_id,
                        part: spec.part,
                    },
                    _ => return failure(2, "companion.invalid_account"),
                };
                let name = account.name();
                if CompanionAccount::parse(&name).as_ref() != Some(&account) {
                    return failure(2, "companion.invalid_account");
                }
                names.push(name);
            }
            json(&Output {
                abi_version: ABI_VERSION,
                names,
            })
        })
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct FeatureOutput<'marker> {
    name: &'marker str,
    #[serde(flatten)]
    entry: &'marker FeatureEntry,
    supported: bool,
}

fn features(marker: &Marker) -> Vec<FeatureOutput<'_>> {
    marker
        .features
        .iter()
        .map(|(name, entry)| FeatureOutput {
            name,
            entry,
            supported: is_supported(name, entry.version),
        })
        .collect()
}

/// What a client concludes about one project from what it saw in one lock
/// scope: the marker, the operation matrix's answers, and every damage
/// with its repair.
/// # Safety
/// The pointer must reference readable bytes for its length during the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn lpm_env_companion_assess(input: *const u8, length: usize) -> LPMEnvResult {
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct Request {
        vault_id: String,
        #[serde(default)]
        marker: Option<Bytes>,
        #[serde(default)]
        inventory: Option<Vec<String>>,
        #[serde(default)]
        overrides: Option<Read>,
        #[serde(default)]
        access_damage: Option<String>,
    }
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Read {
        bytes: Option<Bytes>,
    }
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct Unsupported<'marker> {
        feature: &'marker str,
        version: u16,
        level: Level,
    }
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct RepairOutput {
        action: &'static str,
        #[serde(skip_serializing_if = "Option::is_none")]
        feature: Option<String>,
    }
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct DamageOutput<'damage> {
        code: &'static str,
        #[serde(skip_serializing_if = "Option::is_none")]
        kind: Option<&'damage str>,
        #[serde(skip_serializing_if = "Option::is_none")]
        reason: Option<&'damage str>,
        repair: Option<RepairOutput>,
    }
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct Allows {
        read_excluding_overrides: bool,
        read_applying_overrides: bool,
        write: bool,
    }
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct Output<'assessment> {
        abi_version: u32,
        marker: &'static str,
        state: Option<ProjectState>,
        restore_phase: Option<RestorePhase>,
        needs_resume: bool,
        level: Option<Level>,
        unsupported: Option<Unsupported<'assessment>>,
        features: Vec<FeatureOutput<'assessment>>,
        damage: Vec<DamageOutput<'assessment>>,
        allows: Allows,
    }
    fn damage_output<'damage>(
        assessment: &Assessment,
        damage: &'damage Damage,
    ) -> DamageOutput<'damage> {
        let (code, kind, reason) = match damage {
            Damage::InvalidMarker(reason) => ("invalidMarker", None, Some(reason.as_str())),
            Damage::MissingRecord { kind } => ("missingRecord", Some(kind.as_str()), None),
            Damage::InvalidRecord { kind, reason } => {
                ("invalidRecord", Some(kind.as_str()), Some(reason.as_str()))
            }
            Damage::UnlistedRecord { kind } => ("unlistedRecord", Some(kind.as_str()), None),
            Damage::Access(reason) => ("access", None, Some(reason.as_str())),
        };
        DamageOutput {
            code,
            kind,
            reason,
            repair: assessment.repair(damage).map(|repair| match repair {
                Repair::DiscardProject => RepairOutput {
                    action: "discardProject",
                    feature: None,
                },
                Repair::RemoveFeature(feature) => RepairOutput {
                    action: "removeFeature",
                    feature: Some(feature),
                },
                Repair::RemoveUnlisted => RepairOutput {
                    action: "removeUnlisted",
                    feature: None,
                },
            }),
        }
    }
    // SAFETY: Forwarded from this function's contract.
    unsafe {
        respond(input, length, |request: Request| {
            if !is_safe_vault_id(&request.vault_id) {
                return failure(2, "companion.invalid_input");
            }
            let inventory = request
                .inventory
                .as_deref()
                .map(|names| project_inventory(&request.vault_id, names));
            let assessment = assess(
                &request.vault_id,
                Observed {
                    marker: request.marker.as_ref().map(|bytes| bytes.0.as_slice()),
                    inventory: inventory.as_deref(),
                    overrides: request
                        .overrides
                        .as_ref()
                        .map(|read| read.bytes.as_ref().map(|bytes| bytes.0.as_slice())),
                    access: request.access_damage.as_deref(),
                },
            );
            let marker = assessment.gate.marker();
            let needs_resume = assessment.needs_resume();
            let allows = |operation| !needs_resume && assessment.authorize(operation).is_ok();
            json(&Output {
                abi_version: ABI_VERSION,
                marker: match &assessment.gate {
                    ProjectGate::Plain => "absent",
                    ProjectGate::Marked(_) => "valid",
                    ProjectGate::Damaged(_) => "invalid",
                },
                state: marker.map(|marker| marker.state),
                restore_phase: marker
                    .and_then(|marker| marker.restore.as_ref())
                    .map(|restore| restore.phase),
                needs_resume,
                level: marker.map(Marker::level),
                unsupported: marker
                    .filter(|marker| marker.level() > Level::Ignore)
                    .and_then(Marker::strictest_unsupported)
                    .map(|(feature, entry)| Unsupported {
                        feature,
                        version: entry.version,
                        level: marker.map_or(Level::Ignore, Marker::level),
                    }),
                features: marker.map(features).unwrap_or_default(),
                damage: assessment
                    .every_damage()
                    .map(|damage| damage_output(&assessment, damage))
                    .collect(),
                allows: Allows {
                    read_excluding_overrides: allows(Operation::ReadExcludingOverrides),
                    read_applying_overrides: allows(Operation::ReadApplyingOverrides),
                    write: allows(Operation::Write),
                },
            })
        })
    }
}

/// Plan a lifecycle operation on one project as transactions the caller
/// commits in order, each atomically.
/// # Safety
/// The pointer must reference readable bytes for its length during the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn lpm_env_companion_plan(input: *const u8, length: usize) -> LPMEnvResult {
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    enum Action {
        Resume,
        Delete,
        Discard,
        RemoveFeature,
        RemoveUnlisted,
    }
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct Request {
        action: Action,
        vault_id: String,
        #[serde(default)]
        marker: Option<Bytes>,
        inventory: Vec<String>,
        #[serde(default)]
        own_operations: usize,
        #[serde(default)]
        feature: Option<String>,
    }
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct Move {
        staged: String,
        live: String,
    }
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct TransactionOutput {
        deletes: Vec<String>,
        moves: Vec<Move>,
        writes_marker: Option<Bytes>,
        deletes_marker: bool,
    }
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct Notice {
        kind: &'static str,
        features: Vec<String>,
    }
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct Output {
        abi_version: u32,
        transactions: Vec<TransactionOutput>,
        result: Option<Bytes>,
        notice: Option<Notice>,
    }
    fn encode(marker: &Marker) -> Result<Bytes, String> {
        marker
            .encode()
            .map(Bytes)
            .map_err(|error| error.to_string())
    }
    fn output(plan: Plan, notice: Option<Notice>) -> Result<Output, String> {
        let mut transactions = Vec::with_capacity(plan.transactions.len());
        for transaction in plan.transactions {
            let mut deletes = Vec::new();
            let mut moves = Vec::new();
            for change in transaction.changes {
                match change {
                    PlannedChange::Delete(account) => deletes.push(account.name()),
                    PlannedChange::Move { staged, live } => moves.push(Move {
                        staged: staged.name(),
                        live: live.name(),
                    }),
                }
            }
            transactions.push(TransactionOutput {
                deletes,
                moves,
                writes_marker: match &transaction.marker {
                    Some(MarkerChange::Write(marker)) => Some(encode(marker)?),
                    Some(MarkerChange::Delete) | None => None,
                },
                deletes_marker: matches!(transaction.marker, Some(MarkerChange::Delete)),
            });
        }
        Ok(Output {
            abi_version: ABI_VERSION,
            transactions,
            result: plan.result.as_ref().map(encode).transpose()?,
            notice,
        })
    }
    fn resume_notice(marker: &Marker) -> Option<Notice> {
        let kind = match (
            marker.state,
            marker.restore.as_ref().map(|restore| restore.phase),
        ) {
            (ProjectState::Deleting, _) => "deletion",
            (ProjectState::Discarding, _) => "discard",
            (ProjectState::Restoring, Some(RestorePhase::Staging)) => "restoreUndone",
            (ProjectState::Restoring, _) => "restore",
            (ProjectState::Active, _) if needs_resume(marker) => "featureRemoval",
            (ProjectState::Active, _) => return None,
        };
        Some(Notice {
            kind,
            features: marker
                .features
                .iter()
                .filter(|(_, entry)| entry.state == FeatureState::Removing)
                .map(|(name, _)| name.clone())
                .collect(),
        })
    }
    // SAFETY: Forwarded from this function's contract.
    unsafe {
        respond(input, length, |request: Request| {
            let vault_id = request.vault_id.as_str();
            if !is_safe_vault_id(vault_id) {
                return failure(2, "companion.invalid_input");
            }
            let parsed = request
                .marker
                .as_ref()
                .map(|bytes| Marker::parse(vault_id, &bytes.0));
            let found = match &parsed {
                None => FoundMarker::Absent,
                Some(Err(_)) => FoundMarker::Invalid,
                Some(Ok(marker)) => FoundMarker::Valid(marker),
            };
            let inventory = project_inventory(vault_id, &request.inventory);
            let valid = || match &parsed {
                Some(Ok(marker)) => Ok(marker),
                Some(Err(error)) => Err(format!("the feature marker is invalid: {error}")),
                None => Err("the env project has no feature marker".to_owned()),
            };
            let planned = match request.action {
                Action::Resume => valid().and_then(|marker| {
                    let notice = resume_notice(marker);
                    plan_resume(marker.clone(), inventory).map(|plan| (plan, notice))
                }),
                Action::Delete => plan_deletion(vault_id, found, inventory, request.own_operations)
                    .map(|plan| (plan, None)),
                Action::Discard => {
                    plan_discard(vault_id, found, inventory).map(|plan| (plan, None))
                }
                Action::RemoveFeature => match request.feature.as_deref() {
                    Some(feature) => valid().and_then(|marker| {
                        plan_feature_removal(marker, feature, inventory).map(|plan| (plan, None))
                    }),
                    None => return failure(2, "companion.invalid_input"),
                },
                Action::RemoveUnlisted => valid().and_then(|marker| {
                    plan_unlisted_removal(marker, inventory).map(|plan| (plan, None))
                }),
            };
            match planned.and_then(|(plan, notice)| output(plan, notice)) {
                Ok(output) => json(&output),
                Err(message) => refusal("companion.refused", message),
            }
        })
    }
}

/// Check one transaction the caller is about to commit, or found committed
/// in its journal, the way the CLI checks its own.
/// # Safety
/// The pointer must reference readable bytes for its length during the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn lpm_env_companion_check_transaction(
    input: *const u8,
    length: usize,
) -> LPMEnvResult {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Change {
        account: String,
        bytes: Option<Bytes>,
    }
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Request {
        changes: Vec<Change>,
        markers: BTreeMap<String, Option<Bytes>>,
        #[serde(default)]
        names: Option<Vec<String>>,
    }
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct Output {
        abi_version: u32,
    }
    const MISSING_MARKER: &str = "companion.missing_marker";
    // SAFETY: Forwarded from this function's contract.
    unsafe {
        respond(input, length, |request: Request| {
            let changes: Vec<(&str, Option<&[u8]>)> = request
                .changes
                .iter()
                .map(|change| {
                    (
                        change.account.as_str(),
                        change.bytes.as_ref().map(|bytes| bytes.0.as_slice()),
                    )
                })
                .collect();
            let live = |vault_id: &str| match request.markers.get(vault_id) {
                Some(marker) => Ok(marker.as_ref().map(|bytes| bytes.0.clone())),
                None => Err(MISSING_MARKER.to_owned()),
            };
            match check_transaction(&changes, live, request.names.as_deref()) {
                Ok(()) => json(&Output {
                    abi_version: ABI_VERSION,
                }),
                Err(Refusal::Storage(_)) => failure(2, MISSING_MARKER),
                Err(refused) => refusal("companion.refused", refused.describe("vault transaction")),
            }
        })
    }
}

#[cfg(test)]
mod tests;
