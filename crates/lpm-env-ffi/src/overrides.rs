//! Personal overrides for LPM Vault, read and planned exactly as the CLI
//! reads and plans them. Nothing here reads or writes a store: each function
//! takes what the app read inside its lock and returns what to commit. Every
//! function takes one frame and returns one frame (see `frame`); values
//! travel only as blobs, never in JSON.

use std::collections::BTreeMap;

use lpm_common::stored_env::{is_safe_vault_id, is_valid_variable_name};
use lpm_env_companion::budgets::ADMISSION_CAP;
use lpm_env_companion::gate::{GateError, Operation, ProjectGate};
use lpm_env_companion::lifecycle::{Mutation, needs_resume};
use lpm_env_companion::marker::{MAX_RECORD_BYTES, Marker};
use lpm_env_companion::overrides::change::{
    ChangePlan, Edit, EditError, Effect, EnvironmentMove, Inventory, InventoryNeed, PlanError,
    plan_change, plan_without_values,
};
use lpm_env_companion::overrides::evaluate_all;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use zeroize::Zeroizing;

use crate::frame::{self, Domain, Output, blob, refused, refused_with};
use crate::{LPMEnvResult, failure};

/// The most the values one batch sets may total.
pub(crate) const MAX_BATCH_VALUE_BYTES: usize = 4 * 1024 * 1024;

/// What one input carries at most: a marker and a record of 100 KiB each, a
/// batch's values ([`MAX_BATCH_VALUE_BYTES`]), and every account name in the
/// service, whose companion records the admission cap bounds at 4 MiB of
/// names at the longest, with room for its other items.
pub(crate) const OVERRIDES_INPUT_LIMIT: usize = 16 * 1024 * 1024;

const DOMAIN: Domain = Domain {
    invalid_input: "overrides.invalid_input",
    serialization: "overrides.serialization",
    panic: "overrides.panic",
    input_limit: OVERRIDES_INPUT_LIMIT,
    input_blobs: MAX_EDITS + 2,
};

/// The gate the marker read in the caller's lock gives.
pub(crate) fn gate_of(vault_id: &str, marker: Option<&[u8]>) -> ProjectGate {
    match marker {
        None => ProjectGate::Plain,
        Some(bytes) => match Marker::parse(vault_id, bytes) {
            Ok(marker) => ProjectGate::Marked(marker),
            Err(error) => ProjectGate::Damaged(error.into()),
        },
    }
}

fn gate_code(error: &GateError) -> &'static str {
    match error {
        GateError::Damaged(_) => "overrides.damaged",
        GateError::Unsupported { .. } => "overrides.unsupported",
    }
}

fn optional_blob<'a>(blobs: &[&'a [u8]], index: Option<usize>) -> Result<Option<&'a [u8]>, ()> {
    index.map_or(Ok(None), |index| blob(blobs, index).map(Some).ok_or(()))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ReadRequest {
    vault_id: String,
    #[serde(default)]
    marker: Option<usize>,
    #[serde(default)]
    record: Option<usize>,
    #[serde(default)]
    values: bool,
}

/// Every environment's personal overrides, after the gate allows reads that
/// apply them. See lpm_env.h.
///
/// # Safety
/// `input` must reference `length` readable bytes during the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn lpm_env_overrides_read(input: *const u8, length: usize) -> LPMEnvResult {
    // SAFETY: Forwarded from this function's contract.
    unsafe {
        frame::respond(&DOMAIN, input, length, |request: ReadRequest, blobs| {
            let vault_id = request.vault_id.as_str();
            if !is_safe_vault_id(vault_id) {
                return failure(2, DOMAIN.invalid_input);
            }
            let (Ok(marker), Ok(record)) = (
                optional_blob(blobs, request.marker),
                optional_blob(blobs, request.record),
            ) else {
                return failure(2, DOMAIN.invalid_input);
            };
            let gate = gate_of(vault_id, marker);
            if gate.marker().is_some_and(needs_resume) {
                return refused(
                    "overrides.needs_resume",
                    Some(PlanError::NeedsResume.to_string()),
                );
            }
            if let Err(error) = gate.authorize(Operation::ReadApplyingOverrides) {
                return refused(gate_code(&error), Some(error.to_string()));
            }
            let environments = match evaluate_all(&gate, vault_id, record) {
                Ok(environments) => environments,
                Err(damage) => {
                    return refused(
                        "overrides.damaged",
                        Some(GateError::Damaged(damage).to_string()),
                    );
                }
            };
            let mut output = Output::new(DOMAIN.serialization);
            let mut listed = Vec::with_capacity(environments.len());
            for (environment, overrides) in environments {
                let mut set: Vec<(String, String)> = overrides.set.into_iter().collect();
                set.sort_unstable_by(|left, right| left.0.cmp(&right.0));
                let mut unset = overrides.unset;
                unset.sort_unstable();
                let set: Vec<Value> = set
                    .into_iter()
                    .map(|(key, value)| {
                        let passed = !lpm_env::is_denied_env_var(&key);
                        let value = Zeroizing::new(value);
                        let mut entry = json!({ "key": key, "passed": passed });
                        if request.values {
                            entry["value"] = json!(output.secret(value));
                        }
                        entry
                    })
                    .collect();
                let unset: Vec<Value> = unset
                    .into_iter()
                    .map(|key| json!({ "passed": !lpm_env::is_denied_env_var(&key), "key": key }))
                    .collect();
                listed.push(json!({ "environment": environment, "set": set, "unset": unset }));
            }
            output.finish(&json!({ "environments": listed }))
        })
    }
}

#[derive(Deserialize)]
#[serde(tag = "action", rename_all = "camelCase", deny_unknown_fields)]
enum EditRequest {
    Set {
        environment: String,
        key: String,
        value: usize,
    },
    Unset {
        environment: String,
        key: String,
    },
    Remove {
        environment: String,
        key: String,
    },
    ClearEnvironment {
        environment: String,
    },
    ClearAll,
    EnvironmentRenamed {
        from: String,
        to: String,
    },
    EnvironmentRemoved {
        environment: String,
    },
    EnvironmentDuplicated {
        from: String,
        to: String,
    },
    EnvironmentCreated {
        environment: String,
    },
    EnvironmentsChanged {
        renamed: Vec<RenameRequest>,
        removed: Vec<String>,
    },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RenameRequest {
    from: String,
    to: String,
}

fn has_values() -> bool {
    true
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PlanRequest {
    vault_id: String,
    #[serde(default)]
    marker: Option<usize>,
    #[serde(default)]
    record: Option<usize>,
    /// Every account name in the service, from one names-only listing,
    /// once a plan asked for them.
    #[serde(default)]
    names: Option<Vec<String>>,
    /// Whether the project's values item exists, which overrides need.
    #[serde(default = "has_values")]
    values: bool,
    edits: Vec<EditRequest>,
}

/// The most edits one batch makes.
const MAX_EDITS: usize = 1024;

/// Why the edits of a request can't be read.
enum EditsFailure {
    InvalidInput,
    /// A set's name that isn't a valid variable name, refused before its
    /// value's size so a refusal never names it.
    InvalidKey {
        index: usize,
    },
    /// A value larger than one record holds, refused before it's copied.
    ValueTooLarge {
        index: usize,
        key: String,
    },
    /// The values set so far past what one input carries, refused before
    /// more is copied.
    ValuesTooLarge {
        index: usize,
    },
}

/// The edits a request names, each value copied once out of its blob.
fn edits(requests: Vec<EditRequest>, blobs: &[&[u8]]) -> Result<Vec<Edit>, EditsFailure> {
    let mut copied = 0_usize;
    let mut edits = Vec::with_capacity(requests.len());
    for (index, request) in requests.into_iter().enumerate() {
        edits.push(match request {
            EditRequest::Set {
                environment,
                key,
                value,
            } => {
                let bytes = blob(blobs, value).ok_or(EditsFailure::InvalidInput)?;
                if !is_valid_variable_name(&key) {
                    return Err(EditsFailure::InvalidKey { index });
                }
                if bytes.len() > MAX_RECORD_BYTES {
                    return Err(EditsFailure::ValueTooLarge { index, key });
                }
                copied = copied.saturating_add(bytes.len());
                if copied > MAX_BATCH_VALUE_BYTES {
                    return Err(EditsFailure::ValuesTooLarge { index });
                }
                let text = std::str::from_utf8(bytes).map_err(|_| EditsFailure::InvalidInput)?;
                Edit::Set {
                    environment,
                    key,
                    value: Zeroizing::new(text.to_owned()),
                }
            }
            EditRequest::Unset { environment, key } => Edit::Unset { environment, key },
            EditRequest::Remove { environment, key } => Edit::Remove { environment, key },
            EditRequest::ClearEnvironment { environment } => Edit::ClearEnvironment { environment },
            EditRequest::ClearAll => Edit::ClearAll,
            EditRequest::EnvironmentRenamed { from, to } => Edit::EnvironmentRenamed { from, to },
            EditRequest::EnvironmentRemoved { environment } => {
                Edit::EnvironmentRemoved { environment }
            }
            EditRequest::EnvironmentDuplicated { from, to } => {
                Edit::EnvironmentDuplicated { from, to }
            }
            EditRequest::EnvironmentCreated { environment } => {
                Edit::EnvironmentCreated { environment }
            }
            EditRequest::EnvironmentsChanged { renamed, removed } => Edit::EnvironmentsChanged {
                renamed: renamed
                    .into_iter()
                    .map(|rename| (rename.from, rename.to))
                    .collect(),
                removed,
            },
        });
    }
    Ok(edits)
}

/// What a refusal names besides its code: the edit and the name it's
/// about, or the sizes, never a value or an invalid key.
fn refusal_details(error: &PlanError) -> serde_json::Map<String, Value> {
    let mut details = serde_json::Map::new();
    match error {
        PlanError::Edit { index, reason } => {
            details.insert("edit".to_owned(), json!(index));
            match reason {
                EditError::InvalidEnvironment(environment)
                | EditError::SameEnvironment { environment, .. }
                | EditError::EnvironmentNamedTwice(environment) => {
                    details.insert("environment".to_owned(), json!(environment));
                }
                EditError::DeniedName(key) | EditError::NulValue(key) => {
                    details.insert("key".to_owned(), json!(key));
                }
                EditError::InvalidKey => {}
            }
        }
        PlanError::TooLarge(bytes) => {
            details.insert("bytes".to_owned(), json!(bytes));
            details.insert("limit".to_owned(), json!(MAX_RECORD_BYTES));
        }
        PlanError::AdmissionRefused(records) => {
            details.insert("records".to_owned(), json!(records));
            details.insert("limit".to_owned(), json!(ADMISSION_CAP));
        }
        _ => {}
    }
    details
}

#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
enum EffectOutput<'a> {
    #[serde(rename_all = "camelCase")]
    Key {
        environment: &'a str,
        key: &'a str,
        previous: lpm_env_companion::overrides::change::Previous,
        changed: bool,
    },
    #[serde(rename_all = "camelCase")]
    Cleared {
        environment: Option<&'a str>,
        removed: usize,
    },
    #[serde(rename_all = "camelCase")]
    EnvironmentRemoved {
        environment: &'a str,
        removed: usize,
    },
    #[serde(rename_all = "camelCase")]
    Moved {
        from: &'a str,
        to: &'a str,
        moved: usize,
        replaced: usize,
        kept: usize,
    },
    #[serde(rename_all = "camelCase")]
    NotCopied {
        from: &'a str,
        to: &'a str,
        count: usize,
        existing: usize,
    },
    #[serde(rename_all = "camelCase")]
    Existing { environment: &'a str, count: usize },
    #[serde(rename_all = "camelCase")]
    EnvironmentsChanged {
        moved: Vec<MoveOutput<'a>>,
        removed: Vec<RemovedOutput<'a>>,
    },
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct MoveOutput<'a> {
    from: &'a str,
    to: &'a str,
    moved: usize,
    replaced: usize,
    kept: usize,
}

impl<'a> From<&'a EnvironmentMove> for MoveOutput<'a> {
    fn from(change: &'a EnvironmentMove) -> Self {
        Self {
            from: &change.from,
            to: &change.to,
            moved: change.moved,
            replaced: change.replaced,
            kept: change.kept,
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RemovedOutput<'a> {
    environment: &'a str,
    removed: usize,
}

impl<'a> From<&'a Effect> for EffectOutput<'a> {
    fn from(effect: &'a Effect) -> Self {
        match effect {
            Effect::Key {
                environment,
                key,
                previous,
                changed,
            } => Self::Key {
                environment,
                key,
                previous: *previous,
                changed: *changed,
            },
            Effect::Cleared {
                environment,
                removed,
            } => Self::Cleared {
                environment: environment.as_deref(),
                removed: *removed,
            },
            Effect::EnvironmentRemoved {
                environment,
                removed,
            } => Self::EnvironmentRemoved {
                environment,
                removed: *removed,
            },
            Effect::Moved {
                from,
                to,
                moved,
                replaced,
                kept,
            } => Self::Moved {
                from,
                to,
                moved: *moved,
                replaced: *replaced,
                kept: *kept,
            },
            Effect::NotCopied {
                from,
                to,
                count,
                existing,
            } => Self::NotCopied {
                from,
                to,
                count: *count,
                existing: *existing,
            },
            Effect::Existing { environment, count } => Self::Existing {
                environment,
                count: *count,
            },
            Effect::EnvironmentsChanged { moved, removed } => Self::EnvironmentsChanged {
                moved: moved.iter().map(MoveOutput::from).collect(),
                removed: removed
                    .iter()
                    .map(|(environment, removed)| RemovedOutput {
                        environment,
                        removed: *removed,
                    })
                    .collect(),
            },
        }
    }
}

/// Plan a batch of changes to one project's personal overrides as one
/// transaction to commit. See lpm_env.h.
///
/// # Safety
/// `input` must reference `length` readable bytes during the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn lpm_env_overrides_plan(input: *const u8, length: usize) -> LPMEnvResult {
    // SAFETY: Forwarded from this function's contract.
    unsafe {
        frame::respond(&DOMAIN, input, length, |request: PlanRequest, blobs| {
            let vault_id = request.vault_id.as_str();
            if !is_safe_vault_id(vault_id) || request.edits.len() > MAX_EDITS {
                return failure(2, DOMAIN.invalid_input);
            }
            let (Ok(marker), Ok(record)) = (
                optional_blob(blobs, request.marker),
                optional_blob(blobs, request.record),
            ) else {
                return failure(2, DOMAIN.invalid_input);
            };
            let edits = match edits(request.edits, blobs) {
                Ok(edits) => edits,
                Err(EditsFailure::InvalidInput) => return failure(2, DOMAIN.invalid_input),
                Err(EditsFailure::InvalidKey { index }) => {
                    return refusal(&PlanError::Edit {
                        index,
                        reason: EditError::InvalidKey,
                    });
                }
                Err(EditsFailure::ValueTooLarge { index, key }) => {
                    let mut details = serde_json::Map::new();
                    details.insert("edit".to_owned(), json!(index));
                    details.insert("key".to_owned(), json!(key));
                    details.insert("limit".to_owned(), json!(MAX_RECORD_BYTES));
                    return refused_with(
                        "overrides.too_large",
                        Some(format!(
                            "the personal override of {key} would be larger than the {} KiB one record may hold",
                            MAX_RECORD_BYTES / 1024
                        )),
                        details,
                    );
                }
                Err(EditsFailure::ValuesTooLarge { index }) => {
                    let mut details = serde_json::Map::new();
                    details.insert("edit".to_owned(), json!(index));
                    details.insert("limit".to_owned(), json!(MAX_BATCH_VALUE_BYTES));
                    return refused_with(
                        "overrides.too_large",
                        Some(format!(
                            "the values one batch sets total more than {} MiB",
                            MAX_BATCH_VALUE_BYTES / (1024 * 1024)
                        )),
                        details,
                    );
                }
            };
            let gate = gate_of(vault_id, marker);
            if !request.values {
                return match plan_without_values(&gate, &edits) {
                    Ok(plan) => unchanged(&plan),
                    Err(error) => refusal(&error),
                };
            }
            let inventory = request
                .names
                .as_ref()
                .map(|names| Inventory::from_names(vault_id, names.iter().map(String::as_str)));
            let plan = match plan_change(vault_id, &gate, record, &edits, inventory.as_ref()) {
                Ok(plan) => plan,
                Err(PlanError::NeedsInventory { need, effects }) => {
                    let effects: Vec<EffectOutput<'_>> =
                        effects.iter().map(EffectOutput::from).collect();
                    let needs = match need {
                        InventoryNeed::Project => "project",
                        InventoryNeed::ProjectAndService => "projectAndService",
                    };
                    return Output::new(DOMAIN.serialization).finish(
                        &json!({ "result": "needsNames", "needs": needs, "effects": effects }),
                    );
                }
                Err(error) => return refusal(&error),
            };
            if plan.mutations.is_empty() {
                return unchanged(&plan);
            }
            let effects: Vec<EffectOutput<'_>> =
                plan.effects.iter().map(EffectOutput::from).collect();
            let mut output = Output::new(DOMAIN.serialization);
            let mut writes = Vec::with_capacity(plan.mutations.len());
            let mut deletes = Vec::new();
            for mutation in plan.mutations {
                match mutation {
                    Mutation::Write { account, mut value } => {
                        let index = output.blob(std::mem::take(&mut *value));
                        writes.push(json!({ "account": account.name(), "blob": index }));
                    }
                    Mutation::Delete { account } => deletes.push(account.name()),
                }
            }
            output.finish(&json!({
                "result": "planned",
                "journal": true,
                "writes": writes,
                "deletes": deletes,
                "markerAfter": match plan.gate {
                    ProjectGate::Plain => "absent",
                    _ => "present",
                },
                "activated": plan.activated,
                "overAdmissionTarget": plan.over_admission_target,
                "effects": effects,
            }))
        })
    }
}

fn refusal(error: &PlanError) -> LPMEnvResult {
    refused_with(
        &format!("overrides.{}", error.code()),
        Some(error.to_string()),
        refusal_details(error),
    )
}

/// A plan with nothing to commit: its effects alone.
fn unchanged(plan: &ChangePlan) -> LPMEnvResult {
    let effects: Vec<EffectOutput<'_>> = plan.effects.iter().map(EffectOutput::from).collect();
    Output::new(DOMAIN.serialization).finish(&json!({ "result": "unchanged", "effects": effects }))
}

/// Every environment's overrides, for `lpm_env_check`'s effective mode, or
/// the status and code it fails with: 2 for invalid input, 1 for overrides
/// it can't apply.
pub(crate) fn for_check(
    vault_id: &str,
    marker: Option<&[u8]>,
    record: Option<&[u8]>,
) -> Result<BTreeMap<String, lpm_env_companion::overrides::PersonalOverrides>, (u32, &'static str)>
{
    if !is_safe_vault_id(vault_id) {
        return Err((2, "env.invalid_input"));
    }
    let gate = gate_of(vault_id, marker);
    if gate.marker().is_some_and(needs_resume) {
        return Err((1, "overrides.needs_resume"));
    }
    gate.authorize(Operation::ReadApplyingOverrides)
        .map_err(|error| (1, gate_code(&error)))?;
    evaluate_all(&gate, vault_id, record).map_err(|_| (1, "overrides.damaged"))
}

#[cfg(test)]
mod tests;
