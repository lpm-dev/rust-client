//! Local history for LPM Vault, decided exactly as the CLI decides it.
//! Nothing here reads or writes a store: each function takes what the app
//! read inside its lock and returns what to write.
//!
//! Every function takes one frame and returns one frame:
//!
//! ```text
//! frame = "LPMF" ‖ u8 version=1 ‖ u32be count ‖ count × (u32be length ‖ bytes)
//! ```
//!
//! Field 0 is a UTF-8 JSON object of everything that isn't secret. The
//! other fields are blobs the JSON names by index: stored records, values
//! payloads, revealed values, records to write. Values and key records never
//! appear in JSON, and every output buffer is wiped when it's released.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::panic::{AssertUnwindSafe, catch_unwind};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use lpm_env_companion::append_log::{HISTORY, Head};
use lpm_env_companion::budgets::admission_count;
use lpm_env_companion::history::RecordWrite;
use lpm_env_companion::history::admission::{self, CreationAdmission};
use lpm_env_companion::history::append::{
    AppendPlan, AppendShape, Change, CreationPlan, Growth, NotRecorded, Stored, plan_append,
    plan_creation,
};
use lpm_env_companion::history::codec::{
    Action, Actor, Detail, EntryId, Platform, Related, RelatedSide, Remote,
};
use lpm_env_companion::history::read::{
    EntryInfo, EnvironmentKindInfo, Filter, KeyKindInfo, KeyMatch, KeysInfo, Opened, ReadError,
    RemoteInfo, SideInfo, SourceGroup, TimelineRow, check_records, read_timeline, reveal_entries,
};
use lpm_env_companion::history::rebuild::{
    Binding, Choices, PlanError, Point, Refusal, RollbackKind, RollbackPlan, TargetValue,
    UnknownReason, apply_rollback, plan_environment_rollback, plan_key_rollback, plan_undo,
};
use lpm_env_companion::history::removal::{
    Chosen, KeyMaintenance, Occurrence, Place, PlaceGroup, RemovalError, RemovalReview,
    finish_rotation, key_maintenance, needs_finishing, review_removal, rotate_part, start_removal,
    start_rotation,
};
use lpm_env_companion::history::switch::MarkerHistory;
use lpm_env_companion::history::values::{Rename, Values};
use lpm_env_companion::keyring::{Approval, Digest, SystemRandom};
use lpm_env_companion::marker::Marker;
use serde::Deserialize;
use serde_json::{Value, json};
use zeroize::Zeroizing;

use crate::{ABI_VERSION, LPMEnvResult, bytes, failure, result};

const FRAME_MAGIC: [u8; 4] = *b"LPMF";
const FRAME_VERSION: u8 = 1;
/// Sixteen parts of 100 KiB, values before and after, the head, the key and
/// the request, with room to spare.
pub(crate) const HISTORY_INPUT_LIMIT: usize = 4 * 1024 * 1024;
const REFUSED: u32 = 5;

/// A decoded input frame: the request and its blobs.
struct Frame<'a> {
    request: &'a [u8],
    blobs: Vec<&'a [u8]>,
}

fn decode_frame(bytes: &[u8]) -> Option<Frame<'_>> {
    let rest = bytes.strip_prefix(&FRAME_MAGIC)?;
    let (&version, rest) = rest.split_first()?;
    if version != FRAME_VERSION {
        return None;
    }
    let (count, mut rest) = rest.split_first_chunk::<4>()?;
    let count = u32::from_be_bytes(*count) as usize;
    if count == 0 || count > rest.len() / 4 + 1 {
        return None;
    }
    let mut fields = Vec::with_capacity(count);
    for _ in 0..count {
        let (length, after) = rest.split_first_chunk::<4>()?;
        let length = u32::from_be_bytes(*length) as usize;
        if length > after.len() {
            return None;
        }
        let (field, after) = after.split_at(length);
        fields.push(field);
        rest = after;
    }
    if !rest.is_empty() {
        return None;
    }
    let request = fields.remove(0);
    Some(Frame {
        request,
        blobs: fields,
    })
}

/// An output frame being built: the response and its blobs, which are
/// wiped when dropped.
#[derive(Default)]
struct Output {
    blobs: Vec<Zeroizing<Vec<u8>>>,
}

impl Output {
    fn blob(&mut self, bytes: impl Into<Vec<u8>>) -> usize {
        self.blobs.push(Zeroizing::new(bytes.into()));
        self.blobs.len()
    }

    fn write(&mut self, mut write: RecordWrite) -> Value {
        let account = write.account.name();
        let index = self.blob(std::mem::take(&mut *write.bytes));
        json!({ "account": account, "blob": index })
    }

    /// A secret value as a blob, moved out of the wiped buffer that held it.
    fn secret(&mut self, mut value: Zeroizing<String>) -> usize {
        self.blob(std::mem::take(&mut *value).into_bytes())
    }

    fn finish(self, mut response: Value) -> LPMEnvResult {
        if let Value::Object(object) = &mut response {
            object.insert("abiVersion".to_owned(), json!(ABI_VERSION));
        }
        let request = serde_json::to_vec(&response).unwrap_or_default();
        let total = 4
            + 1
            + 4
            + 4
            + request.len()
            + self.blobs.iter().map(|blob| 4 + blob.len()).sum::<usize>();
        let mut frame = Vec::with_capacity(total);
        frame.extend_from_slice(&FRAME_MAGIC);
        frame.push(FRAME_VERSION);
        frame.extend_from_slice(&((self.blobs.len() + 1) as u32).to_be_bytes());
        frame.extend_from_slice(&(request.len() as u32).to_be_bytes());
        frame.extend_from_slice(&request);
        for blob in &self.blobs {
            frame.extend_from_slice(&(blob.len() as u32).to_be_bytes());
            frame.extend_from_slice(blob);
        }
        debug_assert_eq!(frame.len(), total);
        result(0, frame, None)
    }
}

fn refused(code: &str, message: Option<String>) -> LPMEnvResult {
    let mut output = json!({ "abiVersion": ABI_VERSION, "code": code });
    if let Some(message) = message {
        output["message"] = json!(message);
    }
    result(
        REFUSED,
        serde_json::to_vec(&output).unwrap_or_default(),
        None,
    )
}

/// Run `handle` on a decoded frame and its parsed request, catching panics.
///
/// # Safety
/// `input` must reference `length` readable bytes during the call.
unsafe fn respond<R: for<'de> Deserialize<'de>>(
    input: *const u8,
    length: usize,
    handle: impl FnOnce(R, &[&[u8]]) -> LPMEnvResult,
) -> LPMEnvResult {
    if length > HISTORY_INPUT_LIMIT {
        return failure(2, "history.invalid_input");
    }
    // SAFETY: Forwarded from this function's contract; the length is bounded above.
    let Some(raw) = (unsafe { bytes(input, length) }) else {
        return failure(2, "history.invalid_input");
    };
    catch_unwind(AssertUnwindSafe(|| {
        let Some(frame) = decode_frame(raw) else {
            return failure(2, "history.invalid_input");
        };
        let Ok(request) = serde_json::from_slice::<R>(frame.request) else {
            return failure(2, "history.invalid_input");
        };
        handle(request, &frame.blobs)
    }))
    .unwrap_or_else(|_| failure(3, "history.panic"))
}

fn blob<'a>(blobs: &[&'a [u8]], index: usize) -> Option<&'a [u8]> {
    index
        .checked_sub(1)
        .and_then(|index| blobs.get(index))
        .copied()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Payload {
    environments: BTreeMap<String, BTreeMap<String, String>>,
}

/// A values payload, `{"environments": {name: {KEY: VALUE}}}`, as stored.
fn payload(bytes: &[u8]) -> Option<Payload> {
    serde_json::from_slice(bytes).ok()
}

fn values_of(payload: &Payload) -> Values<'_> {
    Values::from_environments(payload.environments.iter().map(|(name, keys)| {
        (
            name.as_str(),
            keys.iter()
                .map(|(key, value)| (key.as_str(), value.as_str())),
        )
    }))
}

fn entry_id(hex: &str) -> Option<EntryId> {
    let bytes = hex::decode(hex).ok()?;
    bytes.try_into().ok()
}

fn approval(name: &str) -> Option<Approval> {
    match name {
        "automatic" => Some(Approval::Automatic),
        "protected" => Some(Approval::Protected),
        "fileStore" => Some(Approval::FileStore),
        _ => None,
    }
}

fn side(name: &str) -> Option<RelatedSide> {
    match name {
        "before" => Some(RelatedSide::Before),
        "after" => Some(RelatedSide::After),
        _ => None,
    }
}

fn side_name(side: RelatedSide) -> &'static str {
    match side {
        RelatedSide::Before => "before",
        RelatedSide::After => "after",
    }
}

fn digest_text(digest: &Digest) -> String {
    URL_SAFE_NO_PAD.encode(digest)
}

fn digest_from(text: &str) -> Option<Digest> {
    let bytes = URL_SAFE_NO_PAD.decode(text).ok()?;
    let digest: Digest = bytes.try_into().ok()?;
    (URL_SAFE_NO_PAD.encode(digest) == text).then_some(digest)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RelatedRequest {
    id: String,
    side: String,
    time: i64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
enum RemoteRequest {
    Personal,
    Org(String),
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DetailRequest {
    #[serde(default)]
    file_name: Option<String>,
    #[serde(default)]
    pasted: bool,
    #[serde(default)]
    remote: Option<RemoteRequest>,
    #[serde(default)]
    remote_version: Option<u64>,
    #[serde(default)]
    platform: Option<String>,
    #[serde(default)]
    related: Option<RelatedRequest>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct EnvironmentRename {
    from: String,
    to: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct KeyRename {
    environment: String,
    from: String,
    to: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
enum RenameRequest {
    Environment(EnvironmentRename),
    Key(KeyRename),
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ChangeRequest {
    id: String,
    time: i64,
    action: String,
    #[serde(default)]
    detail: DetailRequest,
    #[serde(default)]
    renames: Vec<RenameRequest>,
}

fn action(name: &str) -> Option<Action> {
    Action::ALL.into_iter().find(|action| action.name() == name)
}

fn detail(request: &DetailRequest) -> Option<Detail<'_>> {
    Some(Detail {
        file_name: request.file_name.as_deref(),
        pasted: request.pasted,
        remote: request.remote.as_ref().map(|remote| match remote {
            RemoteRequest::Personal => Remote::Personal,
            RemoteRequest::Org(slug) => Remote::Org(slug),
        }),
        remote_version: request.remote_version,
        platform: match &request.platform {
            Some(name) => Some(Platform::from_name(name)?),
            None => None,
        },
        related: match &request.related {
            Some(related) => Some(Related {
                id: entry_id(&related.id)?,
                side: side(&related.side)?,
                time: related.time,
            }),
            None => None,
        },
    })
}

fn renames(requests: &[RenameRequest]) -> Vec<Rename<'_>> {
    requests
        .iter()
        .map(|rename| match rename {
            RenameRequest::Environment(rename) => Rename::Environment {
                from: &rename.from,
                to: &rename.to,
            },
            RenameRequest::Key(rename) => Rename::Key {
                environment: &rename.environment,
                from: &rename.from,
                to: &rename.to,
            },
        })
        .collect()
}

fn not_recorded(reason: &NotRecorded) -> Value {
    let code = match reason {
        NotRecorded::Damaged(_) => "damaged",
        NotRecorded::NeedsMaintenance => "needsMaintenance",
        NotRecorded::TooManyValues => "tooManyValues",
        NotRecorded::Random => "random",
    };
    json!({ "result": "notRecorded", "reason": code, "message": reason.to_string() })
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CreateRequest {
    #[serde(default)]
    marker: Option<usize>,
    approval: String,
    ring_limit: u16,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AppendRequest {
    head: usize,
    key: usize,
    #[serde(default)]
    tail: Option<usize>,
    #[serde(default)]
    previous: Option<usize>,
    growth: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RecordRequest {
    vault_id: String,
    change: ChangeRequest,
    before: usize,
    after: usize,
    #[serde(default)]
    create: Option<CreateRequest>,
    #[serde(default)]
    append: Option<AppendRequest>,
}

/// Plan recording one change: creating history, when `create` is given, or
/// appending to it, when `append` is. See lpm_env.h.
///
/// # Safety
/// `input` must reference `length` readable bytes during the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn lpm_env_history_record(input: *const u8, length: usize) -> LPMEnvResult {
    // SAFETY: Forwarded from this function's contract.
    unsafe {
        respond(input, length, |request: RecordRequest, blobs| {
            let vault_id = request.vault_id.as_str();
            let (Some(before), Some(after)) = (
                blob(blobs, request.before).and_then(payload),
                blob(blobs, request.after).and_then(payload),
            ) else {
                return failure(2, "history.invalid_input");
            };
            let (Some(id), Some(action), Some(detail)) = (
                entry_id(&request.change.id),
                action(&request.change.action),
                detail(&request.change.detail),
            ) else {
                return failure(2, "history.invalid_input");
            };
            let renames = renames(&request.change.renames);
            let before = values_of(&before);
            let after = values_of(&after);
            let change = Change {
                id,
                time: request.change.time,
                actor: Actor::App,
                action,
                detail,
                before: &before,
                after: &after,
                renames: &renames,
            };
            let mut output = Output::default();
            let mut random = SystemRandom;
            match (request.create, request.append) {
                (Some(create), None) => {
                    let marker = match create.marker {
                        Some(index) => match blob(blobs, index)
                            .and_then(|bytes| Marker::parse(vault_id, bytes).ok())
                        {
                            Some(marker) => Some(marker),
                            None => return failure(2, "history.invalid_input"),
                        },
                        None => None,
                    };
                    let Some(approval) = approval(&create.approval) else {
                        return failure(2, "history.invalid_input");
                    };
                    let response = match plan_creation(
                        vault_id,
                        marker.as_ref(),
                        &change,
                        approval,
                        create.ring_limit,
                        &mut random,
                    ) {
                        Ok(CreationPlan::NoKeyChanges) => json!({ "result": "noKeyChanges" }),
                        Ok(CreationPlan::Create(creation)) => {
                            let writes: Vec<Value> = creation
                                .writes
                                .into_iter()
                                .map(|write| output.write(write))
                                .collect();
                            json!({
                                "result": "write",
                                "journal": true,
                                "writes": writes,
                                "entry": hex::encode(creation.entry),
                                "gap": false,
                                "valuesKept": creation.values_kept,
                            })
                        }
                        Err(reason) => not_recorded(&reason),
                    };
                    output.finish(response)
                }
                (None, Some(append)) => {
                    let (Some(head), Some(key)) =
                        (blob(blobs, append.head), blob(blobs, append.key))
                    else {
                        return failure(2, "history.invalid_input");
                    };
                    let growth = match append.growth.as_str() {
                        "unasked" => Growth::Unasked,
                        "allowed" => Growth::Allowed,
                        "refused" => Growth::Refused,
                        _ => return failure(2, "history.invalid_input"),
                    };
                    let stored = Stored {
                        head,
                        key,
                        tail: append.tail.and_then(|index| blob(blobs, index)),
                        previous: append.previous.and_then(|index| blob(blobs, index)),
                    };
                    let response =
                        match plan_append(vault_id, &stored, &change, growth, &mut random) {
                            Ok(AppendPlan::Unchanged) => json!({ "result": "unchanged" }),
                            Ok(AppendPlan::AlreadyRecorded) => {
                                json!({ "result": "alreadyRecorded" })
                            }
                            Ok(AppendPlan::NeedsPrevious { part }) => {
                                json!({ "result": "needsPrevious", "part": part })
                            }
                            Ok(AppendPlan::NeedsGrowthAdmission) => {
                                json!({ "result": "needsGrowthAdmission" })
                            }
                            Ok(AppendPlan::Write(write)) => {
                                let (shape, dropped, grew) = match write.shape {
                                    AppendShape::Steady => ("steady", None, None),
                                    AppendShape::Slid { dropped } => ("slid", Some(dropped), None),
                                    AppendShape::Rollover { grew } => {
                                        ("rollover", None, Some(grew))
                                    }
                                    AppendShape::Recovered => ("recovered", None, None),
                                };
                                let mut writes = Vec::with_capacity(2);
                                if let Some(head) = write.head {
                                    writes.push(output.write(head));
                                }
                                writes.push(output.write(write.part));
                                json!({
                                    "result": "write",
                                    "journal": false,
                                    "writes": writes,
                                    "entry": hex::encode(write.entry),
                                    "gap": write.gap,
                                    "valuesKept": write.values_kept,
                                    "shape": shape,
                                    "dropped": dropped,
                                    "grew": grew,
                                })
                            }
                            Err(reason) => not_recorded(&reason),
                        };
                    output.finish(response)
                }
                _ => failure(2, "history.invalid_input"),
            }
        })
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PartBlob {
    part: u16,
    #[serde(default)]
    blob: Option<usize>,
}

/// What every reading function takes: the head, the key and the parts the
/// head lists, each with its blob, or none when its account is absent.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct HistoryRequest<T> {
    vault_id: String,
    head: usize,
    key: usize,
    #[serde(default)]
    values: Option<usize>,
    #[serde(default)]
    parts: Vec<PartBlob>,
    #[serde(flatten)]
    rest: T,
}

struct Opening<'a> {
    opened: Opened,
    parts: HashMap<u16, &'a [u8]>,
    values: Option<Payload>,
}

fn open<'a, T>(
    request: &HistoryRequest<T>,
    blobs: &[&'a [u8]],
) -> Result<Opening<'a>, LPMEnvResult> {
    let (Some(head), Some(key)) = (blob(blobs, request.head), blob(blobs, request.key)) else {
        return Err(failure(2, "history.invalid_input"));
    };
    let opened = Opened::open(&request.vault_id, head, key)
        .map_err(|error| refused("history.damaged", Some(error.to_string())))?;
    let mut parts = HashMap::with_capacity(request.parts.len());
    for part in &request.parts {
        if let Some(index) = part.blob {
            let Some(bytes) = blob(blobs, index) else {
                return Err(failure(2, "history.invalid_input"));
            };
            parts.insert(part.part, bytes);
        }
    }
    let values = match request.values {
        Some(index) => Some(
            blob(blobs, index)
                .and_then(payload)
                .ok_or_else(|| failure(2, "history.invalid_input"))?,
        ),
        None => None,
    };
    Ok(Opening {
        opened,
        parts,
        values,
    })
}

impl Opening<'_> {
    fn source(&self) -> impl FnMut(u16) -> Result<Option<Vec<u8>>, String> + '_ {
        |part| Ok(self.parts.get(&part).map(|bytes| bytes.to_vec()))
    }

    fn values(&self) -> Values<'_> {
        self.values.as_ref().map(values_of).unwrap_or_default()
    }
}

fn read_refusal(error: ReadError) -> LPMEnvResult {
    match error {
        ReadError::Damaged(reason) => refused("history.damaged", Some(reason)),
        ReadError::Storage(reason) => refused("history.storage", Some(reason)),
    }
}

fn side_info(side: SideInfo) -> &'static str {
    match side {
        SideInfo::Absent => "absent",
        SideInfo::Kept => "kept",
        SideInfo::NotRecorded => "notRecorded",
        SideInfo::TooLarge => "tooLarge",
        SideInfo::Removed => "removed",
    }
}

fn entry_json(info: &EntryInfo) -> Value {
    let environments: Vec<Value> = info
        .environments
        .iter()
        .map(|environment| {
            let mut object = json!({
                "name": environment.name,
                "change": match &environment.kind {
                    EnvironmentKindInfo::Unchanged => "unchanged",
                    EnvironmentKindInfo::Created => "created",
                    EnvironmentKindInfo::Removed => "removed",
                    EnvironmentKindInfo::RenamedFrom(_) => "renamed",
                },
            });
            if let EnvironmentKindInfo::RenamedFrom(from) = &environment.kind {
                object["renamedFrom"] = json!(from);
            }
            match &environment.keys {
                KeysInfo::Count(count) => object["keyCount"] = json!(count),
                KeysInfo::Changes(changes) => {
                    object["keys"] = changes
                        .iter()
                        .map(|change| {
                            let mut key = json!({
                                "key": change.key,
                                "change": match &change.kind {
                                    KeyKindInfo::Added => "added",
                                    KeyKindInfo::Changed => "changed",
                                    KeyKindInfo::Removed => "removed",
                                    KeyKindInfo::RenamedFrom(_) => "renamed",
                                },
                                "before": side_info(change.before),
                                "after": side_info(change.after),
                            });
                            if let KeyKindInfo::RenamedFrom(from) = &change.kind {
                                key["renamedFrom"] = json!(from);
                            }
                            key
                        })
                        .collect();
                }
            }
            object
        })
        .collect();
    let detail = &info.detail;
    json!({
        "id": hex::encode(info.id),
        "seq": info.seq,
        "time": info.time,
        "actor": match info.actor {
            Actor::App => "app",
            Actor::Cli => "cli",
            Actor::Outside => "outside",
        },
        "action": info.action.name(),
        "source": info.source().name(),
        "since": info.since,
        "valuesKept": !info.flags.values_not_kept,
        "oversized": info.flags.oversized,
        "fileName": detail.file_name,
        "pasted": detail.pasted,
        "remote": detail.remote.as_ref().map(|remote| match remote {
            RemoteInfo::Personal => json!("personal"),
            RemoteInfo::Org(slug) => json!({ "org": slug }),
        }),
        "remoteVersion": detail.remote_version,
        "platform": detail.platform.map(Platform::name),
        "related": detail.related.map(|related| json!({
            "id": hex::encode(related.id),
            "side": side_name(related.side),
            "time": related.time,
        })),
        "environments": environments,
    })
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct FilterRequest {
    #[serde(default)]
    environment: Option<String>,
    #[serde(default)]
    exact_key: Option<String>,
    #[serde(default)]
    key_contains: Option<String>,
    #[serde(default)]
    source: Option<String>,
    #[serde(default)]
    limit: Option<usize>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TimelineRest {
    #[serde(default)]
    filter: Option<FilterRequest>,
}

/// The timeline, newest first, with names and kinds only. See lpm_env.h.
///
/// # Safety
/// `input` must reference `length` readable bytes during the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn lpm_env_history_timeline(input: *const u8, length: usize) -> LPMEnvResult {
    // SAFETY: Forwarded from this function's contract.
    unsafe {
        respond(
            input,
            length,
            |request: HistoryRequest<TimelineRest>, blobs| {
                let opening = match open(&request, blobs) {
                    Ok(opening) => opening,
                    Err(refusal) => return refusal,
                };
                let filter_request = request.rest.filter.as_ref();
                let source = match filter_request.and_then(|filter| filter.source.as_deref()) {
                    Some(name) => match SourceGroup::from_name(name) {
                        Some(group) => Some(group),
                        None => return failure(2, "history.invalid_input"),
                    },
                    None => None,
                };
                let filter = Filter {
                    environment: filter_request.and_then(|filter| filter.environment.as_deref()),
                    key: filter_request.and_then(|filter| {
                        filter
                            .exact_key
                            .as_deref()
                            .map(KeyMatch::Exact)
                            .or_else(|| filter.key_contains.as_deref().map(KeyMatch::Contains))
                    }),
                    source,
                    limit: filter_request.and_then(|filter| filter.limit),
                };
                let values = opening.values();
                let timeline =
                    match read_timeline(&opening.opened, &mut opening.source(), &values, &filter) {
                        Ok(timeline) => timeline,
                        Err(error) => return read_refusal(error),
                    };
                let rows: Vec<Value> = timeline
                    .rows
                    .iter()
                    .map(|row| match row {
                        TimelineRow::Entry(info) => entry_json(info),
                        TimelineRow::Unreadable {
                            part,
                            after,
                            before,
                        } => json!({
                            "unreadable": true,
                            "part": part,
                            "after": after,
                            "before": before,
                        }),
                    })
                    .collect();
                let counts: serde_json::Map<String, Value> = timeline
                    .counts
                    .iter()
                    .map(|(group, count)| (group.name().to_owned(), json!(count)))
                    .collect();
                Output::default().finish(json!({
                "rows": rows,
                "liveGap": timeline.live_gap.map(|gap| json!({
                    "since": gap.since,
                    "environments": gap.environments.iter().map(|environment| json!({
                        "name": environment.name,
                        "keys": match &environment.keys {
                            KeysInfo::Changes(changes) => changes.iter().map(|change| change.key.clone()).collect::<Vec<_>>(),
                            KeysInfo::Count(_) => Vec::new(),
                        },
                    })).collect::<Vec<_>>(),
                })),
                "readable": timeline.readable,
                "counts": counts,
                "oldest": timeline.oldest,
                "damagedTail": timeline.damaged_tail,
                "unreadableParts": timeline.unreadable_parts,
                "environments": timeline.environments.iter().map(|environment| json!({
                    "name": environment.name,
                    "deletedAt": environment.deleted_at,
                })).collect::<Vec<_>>(),
                "keyGeneration": opening.opened.record.current().generation(),
            }))
            },
        )
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RevealRest {
    ids: Vec<String>,
}

/// The entries `ids` names, with each kept value as a blob. See lpm_env.h.
///
/// # Safety
/// `input` must reference `length` readable bytes during the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn lpm_env_history_reveal(input: *const u8, length: usize) -> LPMEnvResult {
    // SAFETY: Forwarded from this function's contract.
    unsafe {
        respond(
            input,
            length,
            |request: HistoryRequest<RevealRest>, blobs| {
                let opening = match open(&request, blobs) {
                    Ok(opening) => opening,
                    Err(refusal) => return refusal,
                };
                let Some(ids) = request
                    .rest
                    .ids
                    .iter()
                    .map(|id| entry_id(id))
                    .collect::<Option<BTreeSet<EntryId>>>()
                else {
                    return failure(2, "history.invalid_input");
                };
                let revealed = match reveal_entries(&opening.opened, &mut opening.source(), &ids) {
                    Ok(revealed) => revealed,
                    Err(error) => return read_refusal(error),
                };
                let mut output = Output::default();
                let entries: Vec<Value> = revealed
                    .into_iter()
                    .map(|entry| {
                        let mut object = entry_json(&entry.info);
                        object["values"] = entry
                            .values
                            .into_iter()
                            .map(|environment| {
                                environment
                                .into_iter()
                                .map(|values| {
                                    json!({
                                        "before": values.before.map(|value| output.secret(value)),
                                        "after": values.after.map(|value| output.secret(value)),
                                    })
                                })
                                .collect::<Vec<_>>()
                            })
                            .collect();
                        object
                    })
                    .collect();
                output.finish(json!({ "entries": entries }))
            },
        )
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RollbackRequestJson {
    kind: String,
    entry: String,
    #[serde(default)]
    environment: Option<String>,
    #[serde(default)]
    key: Option<String>,
    #[serde(default)]
    side: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RollbackRest {
    rollback: RollbackRequestJson,
    #[serde(default)]
    apply: Option<ApplyRequest>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ApplyRequest {
    fingerprint: String,
    #[serde(default)]
    skipped: Vec<(usize, usize)>,
    #[serde(default)]
    keep_empty: Vec<usize>,
}

fn plan_rollback(
    opening: &Opening<'_>,
    request: &RollbackRequestJson,
) -> Result<RollbackPlan, LPMEnvResult> {
    let entry = entry_id(&request.entry).ok_or_else(|| failure(2, "history.invalid_input"))?;
    let values = opening.values();
    let planned = match request.kind.as_str() {
        "environment" => {
            let (Some(environment), Some(side)) = (
                request.environment.as_deref(),
                request.side.as_deref().and_then(side),
            ) else {
                return Err(failure(2, "history.invalid_input"));
            };
            plan_environment_rollback(
                &opening.opened,
                &mut opening.source(),
                &values,
                environment,
                Point { entry, side },
            )
        }
        "key" => {
            let (Some(environment), Some(key)) =
                (request.environment.as_deref(), request.key.as_deref())
            else {
                return Err(failure(2, "history.invalid_input"));
            };
            plan_key_rollback(
                &opening.opened,
                &mut opening.source(),
                &values,
                environment,
                key,
                entry,
            )
        }
        "undo" => plan_undo(&opening.opened, &mut opening.source(), &values, entry),
        _ => return Err(failure(2, "history.invalid_input")),
    };
    planned.map_err(|error| match error {
        PlanError::Read(error) => read_refusal(error),
        PlanError::EntryNotFound => refused("history.entry_not_found", None),
        PlanError::UnknownEnvironment => refused("history.unknown_environment", None),
    })
}

/// What a review saw, so an apply can tell whether a fresh plan matches it:
/// every row's key, its target's kind and digest, and each binding.
fn fingerprint(opened: &Opened, plan: &RollbackPlan) -> String {
    let mut encoded = Zeroizing::new(Vec::new());
    encoded.extend_from_slice(&plan.generation.to_be_bytes());
    for environment in &plan.environments {
        for name in [&environment.current, &environment.target] {
            match name {
                Some(name) => {
                    encoded.push(1);
                    encoded.extend_from_slice(&(name.len() as u32).to_be_bytes());
                    encoded.extend_from_slice(name.as_bytes());
                }
                None => encoded.push(0),
            }
        }
        let binding = match environment.binding {
            Binding::Environment(digest) | Binding::Key(digest) => digest,
        };
        encoded.extend_from_slice(&binding.unwrap_or([0; 16]));
        for row in &environment.rows {
            encoded.extend_from_slice(&(row.key.len() as u32).to_be_bytes());
            encoded.extend_from_slice(row.key.as_bytes());
            match &row.target {
                TargetValue::Known(value) => {
                    encoded.push(1);
                    encoded.extend_from_slice(&opened.keys.value(value.as_bytes()));
                }
                TargetValue::Absent => encoded.push(2),
                TargetValue::Unknown(_) => encoded.push(3),
            }
        }
    }
    digest_text(&opened.keys.value(&encoded))
}

fn unknown_reason(reason: UnknownReason) -> &'static str {
    match reason {
        UnknownReason::NotRecorded => "notRecorded",
        UnknownReason::TooLarge => "tooLarge",
        UnknownReason::Removed => "removed",
        UnknownReason::Unreadable => "unreadable",
    }
}

fn plan_json(opened: &Opened, plan: RollbackPlan, output: &mut Output) -> Value {
    let fingerprint = fingerprint(opened, &plan);
    let environments: Vec<Value> = plan
        .environments
        .into_iter()
        .map(|environment| {
            let recreates = environment.recreates();
            let offers_deletion = environment.offers_deletion();
            let rows: Vec<Value> = environment
                .rows
                .into_iter()
                .map(|row| {
                    let changes = row.changes();
                    let (change, reason) = match (&row.target, &row.current) {
                        (TargetValue::Unknown(reason), _) => ("unknown", Some(unknown_reason(*reason))),
                        (TargetValue::Known(_), Some(_)) => ("changed", None),
                        (TargetValue::Known(_), None) => ("added", None),
                        (TargetValue::Absent, _) => ("removed", None),
                    };
                    let current = row.current.map(|value| output.secret(value));
                    let target = match row.target {
                        TargetValue::Known(value) => Some(output.secret(value)),
                        TargetValue::Absent | TargetValue::Unknown(_) => None,
                    };
                    json!({
                        "key": row.key,
                        "change": change,
                        "changes": changes,
                        "reason": reason,
                        "current": current,
                        "target": target,
                        "gaps": row.gaps.iter().map(|gap| json!({ "since": gap.since, "until": gap.until })).collect::<Vec<_>>(),
                        "pulled": row.pulled.map(|pulled| json!({
                            "remote": match pulled.remote {
                                Some(lpm_env_companion::history::rebuild::RemoteName::Org(slug)) => json!({ "org": slug }),
                                _ => json!("personal"),
                            },
                            "version": pulled.version,
                            "time": pulled.time,
                        })),
                        "changedAgain": row.changed_again.map(|changed| json!({
                            "time": changed.time,
                            "actor": match changed.actor {
                                Actor::App => "app",
                                Actor::Cli => "cli",
                                Actor::Outside => "outside",
                            },
                            "action": changed.action.name(),
                        })),
                    })
                })
                .collect();
            json!({
                "current": environment.current,
                "target": environment.target,
                "recreates": recreates,
                "offersDeletion": offers_deletion,
                "rows": rows,
            })
        })
        .collect();
    json!({
        "kind": match plan.kind {
            RollbackKind::Environment => "environment",
            RollbackKind::Key => "key",
            RollbackKind::Undo => "undo",
        },
        "point": {
            "entry": hex::encode(plan.point.entry),
            "side": side_name(plan.point.side),
            "time": plan.point_time,
        },
        "generation": plan.generation,
        "fingerprint": fingerprint,
        "environments": environments,
    })
}

/// Plan a rollback for review, or, with `apply`, plan it again and return
/// the environments to write if it still matches the review. See lpm_env.h.
///
/// # Safety
/// `input` must reference `length` readable bytes during the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn lpm_env_history_rollback(input: *const u8, length: usize) -> LPMEnvResult {
    // SAFETY: Forwarded from this function's contract.
    unsafe {
        respond(
            input,
            length,
            |request: HistoryRequest<RollbackRest>, blobs| {
                let opening = match open(&request, blobs) {
                    Ok(opening) => opening,
                    Err(refusal) => return refusal,
                };
                if opening.values.is_none() {
                    return failure(2, "history.invalid_input");
                }
                let plan = match plan_rollback(&opening, &request.rest.rollback) {
                    Ok(plan) => plan,
                    Err(refusal) => return refusal,
                };
                let mut output = Output::default();
                let Some(apply) = request.rest.apply else {
                    let plan = plan_json(&opening.opened, plan, &mut output);
                    return output.finish(json!({ "plan": plan }));
                };
                if fingerprint(&opening.opened, &plan) != apply.fingerprint {
                    return refused("history.changed_since_review", None);
                }
                let choices = Choices {
                    skipped: apply.skipped.into_iter().collect::<HashSet<_>>(),
                    keep_empty: apply.keep_empty.into_iter().collect::<HashSet<_>>(),
                };
                let values = opening.values();
                let writes = match apply_rollback(
                    &plan,
                    &choices,
                    &values,
                    &opening.opened.keys,
                    opening.opened.record.current().generation(),
                ) {
                    Ok(writes) => writes,
                    Err(Refusal::ChangedSinceReview) => {
                        return refused("history.changed_since_review", None);
                    }
                    Err(Refusal::NothingToApply) => return refused("history.target_unknown", None),
                };
                let writes: Vec<Value> = writes
                    .into_iter()
                    .map(|write| {
                        let values = write.values.map(|values| {
                            let object: BTreeMap<&str, &str> = values
                                .iter()
                                .map(|(key, value)| (key.as_str(), value.as_str()))
                                .collect();
                            output.blob(serde_json::to_vec(&object).unwrap_or_default())
                        });
                        json!({
                            "name": write.name,
                            "renamedFrom": write.renamed_from,
                            "values": values,
                        })
                    })
                    .collect();
                output.finish(json!({ "writes": writes }))
            },
        )
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ChosenRequest {
    entry: String,
    environment: String,
    key: String,
    side: String,
}

/// A place as a review returned it; fields a start doesn't need, such as
/// occurrences, are passed back with it and ignored.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PlaceRequest {
    environment: String,
    key: String,
    #[serde(default)]
    renamed_from: Vec<String>,
    group: String,
    current: bool,
    digests: Vec<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ReviewRequest {
    value: String,
    generation: u32,
    places: Vec<PlaceRequest>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RemovalRest {
    #[serde(default)]
    chosen: Option<ChosenRequest>,
    #[serde(default)]
    start: Option<StartRequest>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StartRequest {
    review: ReviewRequest,
    selection: Vec<usize>,
    approval: String,
}

fn removal_refusal(error: RemovalError) -> LPMEnvResult {
    let code = match &error {
        RemovalError::Read(_) | RemovalError::Damaged(_) => "history.damaged",
        RemovalError::NotFound => "history.entry_not_found",
        RemovalError::NothingToRemove => "history.nothing_to_remove",
        RemovalError::ValueIsCurrent => "history.value_is_current",
        RemovalError::Limit => "history.limit",
        RemovalError::ChangedSinceReview => "history.changed_since_review",
        RemovalError::GenerationExhausted => "history.generation_exhausted",
        RemovalError::Running => "history.running",
        RemovalError::Random => "history.random_failed",
    };
    refused(code, Some(error.to_string()))
}

fn review_json(review: &RemovalReview) -> Value {
    json!({
        "value": digest_text(&review.value),
        "generation": review.generation,
        "places": review.places.iter().map(|place| json!({
            "environment": place.environment,
            "key": place.key,
            "renamedFrom": place.renamed_from,
            "group": match place.group {
                PlaceGroup::ThisKey => "thisKey",
                PlaceGroup::OtherKey => "otherKey",
            },
            "current": place.current,
            "occurrences": place.occurrences.iter().map(|occurrence| json!({
                "set": occurrence.set,
                "replaced": occurrence.replaced,
            })).collect::<Vec<_>>(),
            "digests": place.digests.iter().map(digest_text).collect::<Vec<_>>(),
        })).collect::<Vec<_>>(),
        "defaultSelection": review.default_selection(),
    })
}

fn review_from(request: &ReviewRequest) -> Option<RemovalReview> {
    Some(RemovalReview {
        value: digest_from(&request.value)?,
        generation: request.generation,
        places: request
            .places
            .iter()
            .map(|place| {
                Some(Place {
                    environment: place.environment.clone(),
                    key: place.key.clone(),
                    renamed_from: place.renamed_from.clone(),
                    group: match place.group.as_str() {
                        "thisKey" => PlaceGroup::ThisKey,
                        "otherKey" => PlaceGroup::OtherKey,
                        _ => return None,
                    },
                    occurrences: Vec::<Occurrence>::new(),
                    current: place.current,
                    digests: place
                        .digests
                        .iter()
                        .map(|digest| digest_from(digest))
                        .collect::<Option<Vec<_>>>()?,
                })
            })
            .collect::<Option<Vec<_>>>()?,
    })
}

/// Review removing one value, with `chosen`, or start the removal the
/// person confirmed, with `start`. See lpm_env.h.
///
/// # Safety
/// `input` must reference `length` readable bytes during the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn lpm_env_history_removal(input: *const u8, length: usize) -> LPMEnvResult {
    // SAFETY: Forwarded from this function's contract.
    unsafe {
        respond(
            input,
            length,
            |request: HistoryRequest<RemovalRest>, blobs| {
                let opening = match open(&request, blobs) {
                    Ok(opening) => opening,
                    Err(refusal) => return refusal,
                };
                let values = opening.values();
                match (&request.rest.chosen, &request.rest.start) {
                    (Some(chosen), None) => {
                        let (Some(entry), Some(side)) =
                            (entry_id(&chosen.entry), side(&chosen.side))
                        else {
                            return failure(2, "history.invalid_input");
                        };
                        match review_removal(
                            &opening.opened,
                            &mut opening.source(),
                            &values,
                            Chosen {
                                entry,
                                environment: &chosen.environment,
                                key: &chosen.key,
                                side,
                            },
                        ) {
                            Ok(review) => {
                                Output::default().finish(json!({ "review": review_json(&review) }))
                            }
                            Err(error) => removal_refusal(error),
                        }
                    }
                    (None, Some(start)) => {
                        let (Some(review), Some(approval)) =
                            (review_from(&start.review), approval(&start.approval))
                        else {
                            return failure(2, "history.invalid_input");
                        };
                        let selection: BTreeSet<usize> = start.selection.iter().copied().collect();
                        match start_removal(
                            &opening.opened,
                            &review,
                            &selection,
                            &values,
                            approval,
                            &mut SystemRandom,
                        ) {
                            Ok(writes) => {
                                let mut output = Output::default();
                                let writes: Vec<Value> = writes
                                    .into_iter()
                                    .map(|write| output.write(write))
                                    .collect();
                                output.finish(json!({ "journal": true, "writes": writes }))
                            }
                            Err(error) => removal_refusal(error),
                        }
                    }
                    _ => failure(2, "history.invalid_input"),
                }
            },
        )
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct MaintenanceRest {
    step: String,
    #[serde(default)]
    approval: Option<String>,
    #[serde(default)]
    part: Option<u16>,
}

/// Key upkeep: what the key needs for the values item's access, starting a
/// rotation, rotating one part, and finishing. See lpm_env.h.
///
/// # Safety
/// `input` must reference `length` readable bytes during the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn lpm_env_history_maintenance(
    input: *const u8,
    length: usize,
) -> LPMEnvResult {
    // SAFETY: Forwarded from this function's contract.
    unsafe {
        respond(
            input,
            length,
            |request: HistoryRequest<MaintenanceRest>, blobs| {
                let opening = match open(&request, blobs) {
                    Ok(opening) => opening,
                    Err(refusal) => return refusal,
                };
                let opened = &opening.opened;
                let mut output = Output::default();
                let approval = request.rest.approval.as_deref().and_then(approval);
                let response = match request.rest.step.as_str() {
                    "check" => {
                        let Some(approval) = approval else {
                            return failure(2, "history.invalid_input");
                        };
                        let (key, write) = match key_maintenance(opened, approval) {
                            KeyMaintenance::Nothing => ("nothing", None),
                            KeyMaintenance::Rotate => ("rotate", None),
                            KeyMaintenance::Lower(write) => ("lower", Some(output.write(write))),
                        };
                        json!({
                            "needsFinishing": needs_finishing(opened),
                            "parts": opened.head.parts,
                            "key": key,
                            "writes": write.into_iter().collect::<Vec<_>>(),
                            "journal": false,
                        })
                    }
                    "start" => {
                        let Some(approval) = approval else {
                            return failure(2, "history.invalid_input");
                        };
                        match start_rotation(opened, approval, &mut SystemRandom) {
                            Ok(writes) => json!({
                                "journal": true,
                                "writes": writes.into_iter().map(|write| output.write(write)).collect::<Vec<_>>(),
                            }),
                            Err(error) => return removal_refusal(error),
                        }
                    }
                    "rotatePart" => {
                        let Some(part) = request.rest.part else {
                            return failure(2, "history.invalid_input");
                        };
                        let sealed = opening.parts.get(&part).copied();
                        match rotate_part(opened, part, sealed, &mut SystemRandom) {
                            Ok(write) => json!({
                                "journal": false,
                                "writes": write.map(|write| output.write(write)).into_iter().collect::<Vec<_>>(),
                            }),
                            Err(error) => return removal_refusal(error),
                        }
                    }
                    "finish" => match finish_rotation(opened) {
                        Ok(writes) => json!({
                            "journal": true,
                            "writes": writes.into_iter().map(|write| output.write(write)).collect::<Vec<_>>(),
                        }),
                        Err(error) => return removal_refusal(error),
                    },
                    _ => return failure(2, "history.invalid_input"),
                };
                output.finish(response)
            },
        )
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CheckRequest {
    vault_id: String,
    #[serde(default)]
    marker: Option<usize>,
    #[serde(default)]
    head: Option<usize>,
    #[serde(default)]
    key: Option<usize>,
    #[serde(default)]
    parts: Vec<PartBlob>,
}

/// What the marker says about history, and any damage in its records that
/// a listing can't see. See lpm_env.h.
///
/// # Safety
/// `input` must reference `length` readable bytes during the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn lpm_env_history_check(input: *const u8, length: usize) -> LPMEnvResult {
    // SAFETY: Forwarded from this function's contract.
    unsafe {
        respond(input, length, |request: CheckRequest, blobs| {
            let vault_id = request.vault_id.as_str();
            let marker = match request.marker {
                Some(index) => match blob(blobs, index).map(|bytes| Marker::parse(vault_id, bytes))
                {
                    Some(Ok(marker)) => Some(marker),
                    Some(Err(_)) => return refused("history.invalid_marker", None),
                    None => return failure(2, "history.invalid_input"),
                },
                None => None,
            };
            let state = MarkerHistory::of(marker.as_ref());
            let (name, version) = match state {
                MarkerHistory::Default => ("default", None),
                MarkerHistory::On => ("on", Some(lpm_env_companion::history::VERSION)),
                MarkerHistory::Removing => ("removing", None),
                MarkerHistory::Unsupported { version } => ("unsupported", Some(version)),
                MarkerHistory::Off => ("off", None),
                MarkerHistory::Both => ("both", None),
            };
            let parts: HashMap<u16, &[u8]> = request
                .parts
                .iter()
                .filter_map(|part| Some((part.part, blob(blobs, part.blob?)?)))
                .collect();
            let damage = if state == MarkerHistory::On {
                check_records(
                    vault_id,
                    request.head.and_then(|index| blob(blobs, index)),
                    request.key.and_then(|index| blob(blobs, index)),
                    |part| parts.get(&part).map(|bytes| bytes.to_vec()),
                )
            } else {
                Vec::new()
            };
            let tail = request
                .head
                .and_then(|index| blob(blobs, index))
                .and_then(|bytes| Head::parse(HISTORY, vault_id, bytes).ok())
                .map(|head| head.tail());
            Output::default().finish(json!({
                "history": name,
                "version": version,
                "tailPart": tail,
                "damage": damage.iter().map(|damage| json!({ "description": damage.to_string() })).collect::<Vec<_>>(),
            }))
        })
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AdmissionRequest {
    names: Vec<String>,
    operation: String,
    #[serde(default)]
    trimmable: Option<Vec<String>>,
    #[serde(default)]
    max_trims: Option<usize>,
}

/// Admission and trims, from a names-only listing of the service: no
/// secrets, so a JSON-only frame. See lpm_env.h.
///
/// # Safety
/// `input` must reference `length` readable bytes during the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn lpm_env_history_admission(
    input: *const u8,
    length: usize,
) -> LPMEnvResult {
    // SAFETY: Forwarded from this function's contract.
    unsafe {
        respond(input, length, |request: AdmissionRequest, _| {
            let existing = admission_count(request.names.iter().map(String::as_str));
            let accounts: Vec<_> = request
                .names
                .iter()
                .filter_map(|name| lpm_env_companion::account::CompanionAccount::parse(name))
                .collect();
            let adding = match request.operation.as_str() {
                "creation" => admission::CREATION_ACCOUNTS,
                "growth" => 1,
                "trim" => 0,
                _ => return failure(2, "history.invalid_input"),
            };
            let rings = admission::rings(&accounts);
            let trimmable: Option<HashSet<&str>> = request
                .trimmable
                .as_ref()
                .map(|names| names.iter().map(String::as_str).collect());
            let trims = admission::plan_trims(
                existing + adding,
                &rings,
                request.max_trims.unwrap_or(64),
                |vault_id| {
                    trimmable
                        .as_ref()
                        .is_none_or(|names| names.contains(vault_id))
                },
            );
            let trimmed: usize = trims.iter().map(|(_, count)| count).sum();
            let after_trims = existing.saturating_sub(trimmed);
            let creation = match admission::admit_creation(after_trims) {
                CreationAdmission::Full => "full",
                CreationAdmission::Reduced => "reduced",
                CreationAdmission::Refused => "refused",
            };
            Output::default().finish(json!({
                "existing": existing,
                "trims": trims.iter().map(|(vault_id, count)| json!({ "vaultId": vault_id, "count": count })).collect::<Vec<_>>(),
                "afterTrims": after_trims,
                "creation": creation,
                "ringLimit": admission::admit_creation(after_trims).ring_limit(),
                "growth": admission::admit_growth(after_trims),
                "regrow": after_trims < admission::REGROW_BELOW,
            }))
        })
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RingRequest {
    vault_id: String,
    head: usize,
    action: String,
    #[serde(default)]
    existing: usize,
    #[serde(default)]
    inventory: Vec<String>,
}

/// One ring's upkeep: trimming its oldest part, raising a shrunk limit, and
/// the parts its head doesn't list. See lpm_env.h.
///
/// # Safety
/// `input` must reference `length` readable bytes during the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn lpm_env_history_ring(input: *const u8, length: usize) -> LPMEnvResult {
    // SAFETY: Forwarded from this function's contract.
    unsafe {
        respond(input, length, |request: RingRequest, blobs| {
            let vault_id = request.vault_id.as_str();
            let Some(head) = blob(blobs, request.head)
                .and_then(|bytes| Head::parse(HISTORY, vault_id, bytes).ok())
            else {
                return refused("history.damaged", None);
            };
            let mut output = Output::default();
            let response = match request.action.as_str() {
                "trim" => match admission::trim_oldest(&head) {
                    Some(trim) => json!({
                        "writes": [output.write(trim.head)],
                        "delete": trim.delete.name(),
                    }),
                    None => json!({ "writes": [], "delete": null }),
                },
                "raiseLimit" => json!({
                    "writes": admission::raise_limit(&head, request.existing)
                        .map(|write| output.write(write))
                        .into_iter()
                        .collect::<Vec<_>>(),
                }),
                "orphans" => {
                    let accounts: Vec<_> = request
                        .inventory
                        .iter()
                        .filter_map(|name| {
                            lpm_env_companion::account::CompanionAccount::parse(name)
                        })
                        .collect();
                    json!({
                        "delete": admission::orphan_parts(&head, &accounts)
                            .iter()
                            .map(lpm_env_companion::account::CompanionAccount::name)
                            .collect::<Vec<_>>(),
                    })
                }
                _ => return failure(2, "history.invalid_input"),
            };
            output.finish(response)
        })
    }
}

#[cfg(test)]
mod tests;
