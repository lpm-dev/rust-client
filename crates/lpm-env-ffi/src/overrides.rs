//! Personal overrides for LPM Vault, read and planned exactly as the CLI
//! reads and plans them. Nothing here reads or writes a store: each function
//! takes what the app read inside its lock and returns what to commit. Every
//! function takes one frame and returns one frame (see `frame`); values
//! travel only as blobs, never in JSON.

use std::cell::Cell;
use std::collections::BTreeMap;
use std::fmt;
use std::marker::PhantomData;

use lpm_common::stored_env::is_safe_vault_id;
use lpm_env_companion::budgets::ADMISSION_CAP;
use lpm_env_companion::gate::{GateError, Operation, ProjectGate};
use lpm_env_companion::lifecycle::{Mutation, needs_resume};
use lpm_env_companion::marker::MAX_RECORD_BYTES;
use lpm_env_companion::overrides::change::{
    ChangePlan, Edit, EditError, Effect, EnvironmentMove, Inventory, InventoryNeed, PlanError,
    check_edit, check_set, check_writable, plan_change, plan_without_values,
};
use lpm_env_companion::overrides::evaluate_all;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use zeroize::Zeroizing;

use crate::frame::{self, Domain, Object, Output, blob, present, refused, refused_with};
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

pub(crate) use lpm_env_companion::assessment::gate_of;

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
    #[serde(default, deserialize_with = "present")]
    marker: Option<usize>,
    #[serde(default, deserialize_with = "present")]
    record: Option<usize>,
    has_values: bool,
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
        frame::respond(
            &DOMAIN,
            input,
            length,
            |Object(request): Object<ReadRequest>, blobs| {
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
                if !request.has_values {
                    return Output::new(DOMAIN.serialization)
                        .finish(&json!({ "environments": [] }));
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
                for (environment, mut overrides) in environments {
                    let mut set: Vec<(String, String)> =
                        std::mem::take(&mut overrides.set).into_iter().collect();
                    set.sort_unstable_by(|left, right| left.0.cmp(&right.0));
                    let mut unset = std::mem::take(&mut overrides.unset);
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
            },
        )
    }
}

#[cfg(test)]
thread_local! {
    /// How many times a plan has read a set's value: for its text, and for
    /// what the engine refuses in it.
    pub(super) static VALUE_SCANS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
fn scanned_value() {
    VALUE_SCANS.with(|scans| scans.set(scans.get() + 1));
}

#[cfg(not(test))]
fn scanned_value() {}

/// One edit, its fields checked against what its action takes, a set's
/// value the text of the blob it names.
enum EditRequest<'b> {
    Set {
        environment: String,
        key: String,
        blob: usize,
        value: &'b str,
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
        renamed: Bounded<Object<RenameRequest>, MAX_EDITS, true>,
        removed: Bounded<String, MAX_EDITS, true>,
    },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RenameRequest {
    from: String,
    to: String,
}

/// One edit as it's decoded: every field an edit takes, so its lists are
/// decoded item by item as they come rather than held whole first, as an
/// enum tagged inside the object holds them. [`edit`](Self::edit) refuses a
/// field missing or one its action doesn't take.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DecodedEdit {
    action: Action,
    #[serde(default, deserialize_with = "present")]
    environment: Option<String>,
    #[serde(default, deserialize_with = "present")]
    key: Option<String>,
    #[serde(default, deserialize_with = "present")]
    value: Option<usize>,
    #[serde(default, deserialize_with = "present")]
    from: Option<String>,
    #[serde(default, deserialize_with = "present")]
    to: Option<String>,
    #[serde(default, deserialize_with = "present")]
    renamed: Option<Bounded<Object<RenameRequest>, MAX_EDITS, true>>,
    #[serde(default, deserialize_with = "present")]
    removed: Option<Bounded<String, MAX_EDITS, true>>,
}

#[derive(Deserialize, Clone, Copy)]
#[serde(rename_all = "camelCase")]
enum Action {
    Set,
    Unset,
    Remove,
    ClearEnvironment,
    ClearAll,
    EnvironmentRenamed,
    EnvironmentRemoved,
    EnvironmentDuplicated,
    EnvironmentCreated,
    EnvironmentsChanged,
}

/// The text of each blob a set names, read once however many sets name it.
struct BlobTexts<'a, 'b> {
    blobs: &'a [&'b [u8]],
    texts: Vec<Option<Option<&'b str>>>,
}

impl<'a, 'b> BlobTexts<'a, 'b> {
    fn new(blobs: &'a [&'b [u8]]) -> Self {
        Self {
            blobs,
            texts: vec![None; blobs.len()],
        }
    }

    /// The text of the blob numbered `index`; `None` when there's no such
    /// blob or it isn't UTF-8.
    fn text(&mut self, index: usize) -> Option<&'b str> {
        let bytes = blob(self.blobs, index)?;
        *self.texts[index - 1].get_or_insert_with(|| {
            scanned_value();
            std::str::from_utf8(bytes).ok()
        })
    }
}

impl DecodedEdit {
    /// The edit its action makes, with exactly the fields that action takes;
    /// a set's value names a blob that holds text.
    fn edit<'b>(self, texts: &mut BlobTexts<'_, 'b>) -> Option<EditRequest<'b>> {
        let Self {
            action,
            environment,
            key,
            value,
            from,
            to,
            renamed,
            removed,
        } = self;
        Some(
            match (action, environment, key, value, from, to, renamed, removed) {
                (
                    Action::Set,
                    Some(environment),
                    Some(key),
                    Some(value),
                    None,
                    None,
                    None,
                    None,
                ) => EditRequest::Set {
                    environment,
                    key,
                    blob: value,
                    value: texts.text(value)?,
                },
                (Action::Unset, Some(environment), Some(key), None, None, None, None, None) => {
                    EditRequest::Unset { environment, key }
                }
                (Action::Remove, Some(environment), Some(key), None, None, None, None, None) => {
                    EditRequest::Remove { environment, key }
                }
                (
                    Action::ClearEnvironment,
                    Some(environment),
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                ) => EditRequest::ClearEnvironment { environment },
                (Action::ClearAll, None, None, None, None, None, None, None) => {
                    EditRequest::ClearAll
                }
                (
                    Action::EnvironmentRenamed,
                    None,
                    None,
                    None,
                    Some(from),
                    Some(to),
                    None,
                    None,
                ) => EditRequest::EnvironmentRenamed { from, to },
                (
                    Action::EnvironmentRemoved,
                    Some(environment),
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                ) => EditRequest::EnvironmentRemoved { environment },
                (
                    Action::EnvironmentDuplicated,
                    None,
                    None,
                    None,
                    Some(from),
                    Some(to),
                    None,
                    None,
                ) => EditRequest::EnvironmentDuplicated { from, to },
                (
                    Action::EnvironmentCreated,
                    Some(environment),
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                ) => EditRequest::EnvironmentCreated { environment },
                (
                    Action::EnvironmentsChanged,
                    None,
                    None,
                    None,
                    None,
                    None,
                    Some(renamed),
                    Some(removed),
                ) => EditRequest::EnvironmentsChanged { renamed, removed },
                _ => return None,
            },
        )
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PlanRequest {
    vault_id: String,
    #[serde(default, deserialize_with = "present")]
    marker: Option<usize>,
    #[serde(default, deserialize_with = "present")]
    record: Option<usize>,
    /// Every account name in the service, from one names-only listing,
    /// once a plan asked for them.
    #[serde(default, deserialize_with = "present")]
    names: Option<Bounded<String, MAX_NAMES, false>>,
    /// Whether the project's values item exists, which overrides need. A
    /// client says so every time, so it never leaves it out by mistake.
    has_values: bool,
    edits: Bounded<Object<DecodedEdit>, MAX_EDITS, false>,
}

/// The most edits one batch makes.
const MAX_EDITS: usize = 1024;

/// The most account names one request carries, past any service's.
const MAX_NAMES: usize = 128 * 1024;

thread_local! {
    /// What's left of the request's budget for the renames and removals of
    /// environments changed together, shared by every such edit.
    static ENVIRONMENT_CHANGES_LEFT: Cell<usize> = const { Cell::new(usize::MAX) };
}

/// A plan request's budget for environments changed together, from before
/// its decoding until it's answered: as many as the edits a batch makes.
struct EnvironmentChangeBudget;

impl EnvironmentChangeBudget {
    fn start() -> Self {
        ENVIRONMENT_CHANGES_LEFT.set(MAX_EDITS);
        Self
    }
}

impl Drop for EnvironmentChangeBudget {
    fn drop(&mut self) {
        ENVIRONMENT_CHANGES_LEFT.set(usize::MAX);
    }
}

/// A JSON list decoded item by item, refused as soon as it holds more than
/// `LIMIT` items or, when `BUDGETED`, takes more than the request's budget
/// for environments changed together, before more are kept.
struct Bounded<T, const LIMIT: usize, const BUDGETED: bool>(Vec<T>);

impl<'de, T, const LIMIT: usize, const BUDGETED: bool> Deserialize<'de>
    for Bounded<T, LIMIT, BUDGETED>
where
    T: Deserialize<'de>,
{
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Items<T, const LIMIT: usize, const BUDGETED: bool>(PhantomData<T>);

        impl<'de, T, const LIMIT: usize, const BUDGETED: bool> serde::de::Visitor<'de>
            for Items<T, LIMIT, BUDGETED>
        where
            T: Deserialize<'de>,
        {
            type Value = Vec<T>;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(formatter, "a list of at most {LIMIT} items")
            }

            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut sequence: A,
            ) -> Result<Vec<T>, A::Error> {
                let mut items = Vec::with_capacity(sequence.size_hint().unwrap_or(0).min(LIMIT));
                while let Some(item) = sequence.next_element()? {
                    let within_budget = !BUDGETED
                        || ENVIRONMENT_CHANGES_LEFT.with(|left| {
                            let remaining = left.get();
                            left.set(remaining.saturating_sub(1));
                            remaining > 0
                        });
                    if items.len() == LIMIT || !within_budget {
                        return Err(serde::de::Error::invalid_length(items.len() + 1, &self));
                    }
                    items.push(item);
                }
                Ok(items)
            }
        }

        deserializer
            .deserialize_seq(Items::<T, LIMIT, BUDGETED>(PhantomData))
            .map(Self)
    }
}

/// Why the edits of a request are refused.
enum EditsFailure {
    /// An edit the engine refuses whatever the overrides: checked before its
    /// value is copied, so a refusal never names a value or an invalid key.
    Refused(PlanError),
    /// A value larger than one record holds, refused before it's copied.
    ValueTooLarge { index: usize, key: String },
    /// The values set so far past what one input carries, refused before
    /// more is copied.
    ValuesTooLarge { index: usize },
}

/// The edits a request names, in order, each checked as the engine checks
/// it before its value is copied once out of its blob, one of `blob_count`.
/// A project without values takes no value at all: any set is refused,
/// whatever it holds.
fn edits(
    requests: Vec<EditRequest<'_>>,
    blob_count: usize,
    has_values: bool,
) -> Result<Vec<Edit>, EditsFailure> {
    let refused = |index| move |reason| EditsFailure::Refused(PlanError::Edit { index, reason });
    let mut checked_blobs = vec![false; blob_count];
    let mut copied = 0_usize;
    let mut edits = Vec::with_capacity(requests.len());
    for (index, request) in requests.into_iter().enumerate() {
        let edit = match request {
            EditRequest::Set {
                environment,
                key,
                blob,
                value,
            } => {
                // A value the engine already found nothing to refuse in
                // isn't read again: only this set's names are checked.
                let checked = &mut checked_blobs[blob - 1];
                let to_check = if *checked {
                    ""
                } else {
                    scanned_value();
                    value
                };
                check_set(&environment, &key, to_check).map_err(refused(index))?;
                *checked = true;
                if has_values {
                    if value.len() > MAX_RECORD_BYTES {
                        return Err(EditsFailure::ValueTooLarge { index, key });
                    }
                    copied = copied.saturating_add(value.len());
                    if copied > MAX_BATCH_VALUE_BYTES {
                        return Err(EditsFailure::ValuesTooLarge { index });
                    }
                }
                let value = if has_values {
                    value.to_owned()
                } else {
                    String::new()
                };
                Edit::Set {
                    environment,
                    key,
                    value: Zeroizing::new(value),
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
                    .0
                    .into_iter()
                    .map(|Object(rename)| (rename.from, rename.to))
                    .collect(),
                removed: removed.0,
            },
        };
        if !matches!(edit, Edit::Set { .. }) {
            check_edit(&edit).map_err(refused(index))?;
        }
        edits.push(edit);
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
    let _budget = EnvironmentChangeBudget::start();
    // SAFETY: Forwarded from this function's contract.
    unsafe {
        frame::respond(
            &DOMAIN,
            input,
            length,
            |Object(request): Object<PlanRequest>, blobs| {
                let vault_id = request.vault_id.as_str();
                if !is_safe_vault_id(vault_id) {
                    return failure(2, DOMAIN.invalid_input);
                }
                let mut texts = BlobTexts::new(blobs);
                let Some(requested) = request
                    .edits
                    .0
                    .into_iter()
                    .map(|Object(edit)| edit.edit(&mut texts))
                    .collect::<Option<Vec<_>>>()
                else {
                    return failure(2, DOMAIN.invalid_input);
                };
                let (Ok(marker), Ok(record)) = (
                    optional_blob(blobs, request.marker),
                    optional_blob(blobs, request.record),
                ) else {
                    return failure(2, DOMAIN.invalid_input);
                };
                let gate = gate_of(vault_id, marker);
                if let Err(error) = check_writable(&gate) {
                    return refusal(&error);
                }
                let edits = match edits(requested, blobs.len(), request.has_values) {
                    Ok(edits) => edits,
                    Err(EditsFailure::Refused(error)) => return refusal(&error),
                    Err(EditsFailure::ValueTooLarge { index, key }) => {
                        let mut details = serde_json::Map::new();
                        details.insert("edit".to_owned(), json!(index));
                        details.insert("key".to_owned(), json!(key));
                        details.insert("limit".to_owned(), json!(MAX_RECORD_BYTES));
                        return refused_with(
                            "overrides.too_large",
                            Some(format!(
                                "the personal override of {key} would be larger than the {} KiB a project's overrides can use",
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
                if !request.has_values {
                    return match plan_without_values(&gate, &edits) {
                        Ok(plan) => unchanged(&plan),
                        Err(error) => refusal(&error),
                    };
                }
                let inventory = request.names.as_ref().map(|names| {
                    Inventory::from_names(vault_id, names.0.iter().map(String::as_str))
                });
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
            },
        )
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
/// it can't apply. Without values, after the marker's refusals, there are
/// none: overrides live beside values.
pub(crate) fn for_check(
    vault_id: &str,
    marker: Option<&[u8]>,
    record: Option<&[u8]>,
    has_values: bool,
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
    if !has_values {
        return Ok(BTreeMap::new());
    }
    evaluate_all(&gate, vault_id, record).map_err(|_| (1, "overrides.damaged"))
}

#[cfg(test)]
mod tests;
