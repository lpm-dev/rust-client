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

use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::panic::{AssertUnwindSafe, catch_unwind};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use lpm_env_companion::append_log::{HISTORY, Head};
use lpm_env_companion::budgets::admission_count;
use lpm_env_companion::history::RecordWrite;
use lpm_env_companion::history::admission::{self, CreationAdmission, TrimStep, TrimTail};
use lpm_env_companion::history::append::{
    AppendCache, AppendPlan, AppendShape, Change, CreationPlan, Growth, NotRecorded, Stored,
    plan_append, plan_creation,
};
use lpm_env_companion::history::codec::{
    Action, Actor, Detail, EntryId, Platform, Related, RelatedSide, Remote,
};
use lpm_env_companion::history::read::{
    EntryInfo, EnvironmentInfo, EnvironmentKindInfo, Filter, IdPrefix, KeyKindInfo, KeyMatch,
    KeysInfo, Opened, PartSource, ReadError, RemoteInfo, RevealedValues, SideInfo, SourceGroup,
    Timeline, TimelineRow, check_records, read_timeline, reveal_entries,
};
use lpm_env_companion::history::rebuild::{
    Binding, Choices, EnvironmentName, EnvironmentRef, PlanError, Point, Refusal, RollbackKind,
    RollbackPlan, Target, TargetValue, UnknownReason, apply_rollback, plan_environment_rollback,
    plan_key_rollback, plan_rollback as plan_by_entry,
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
use serde::ser::SerializeMap as _;
use serde::{Deserialize, Serialize};
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

/// The most blobs a frame carries: every input names far fewer (a reading
/// names the head, the key, the values and at most 16 parts).
const MAX_FRAME_BLOBS: usize = 64;

fn decode_frame(bytes: &[u8]) -> Option<Frame<'_>> {
    let rest = bytes.strip_prefix(&FRAME_MAGIC)?;
    let (&version, rest) = rest.split_first()?;
    if version != FRAME_VERSION {
        return None;
    }
    let (count, mut rest) = rest.split_first_chunk::<4>()?;
    let count = u32::from_be_bytes(*count) as usize;
    if count == 0 || count > MAX_FRAME_BLOBS + 1 || count > rest.len() / 4 + 1 {
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

    /// The output frame: `response` with the ABI version, serialized once,
    /// then every blob, in a buffer sized exactly.
    fn finish(self, response: &impl Serialize) -> LPMEnvResult {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Framed<'r, R> {
            #[serde(flatten)]
            response: &'r R,
            abi_version: u32,
        }
        /// Counts what a serialization writes, so the frame is sized once.
        struct Counted(usize);
        impl std::io::Write for Counted {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.0 += bytes.len();
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let framed = Framed {
            response,
            abi_version: ABI_VERSION,
        };
        // Serializing twice costs less than holding the JSON twice: the
        // frame is written once, at its exact size.
        let mut counted = Counted(0);
        if serde_json::to_writer(&mut counted, &framed).is_err() {
            return failure(3, "history.serialization");
        }
        let request_len = counted.0;
        let total = 4
            + 1
            + 4
            + 4
            + request_len
            + self.blobs.iter().map(|blob| 4 + blob.len()).sum::<usize>();
        let mut frame = Vec::with_capacity(total);
        frame.extend_from_slice(&FRAME_MAGIC);
        frame.push(FRAME_VERSION);
        frame.extend_from_slice(&((self.blobs.len() + 1) as u32).to_be_bytes());
        frame.extend_from_slice(&(request_len as u32).to_be_bytes());
        if serde_json::to_writer(&mut frame, &framed).is_err() {
            return failure(3, "history.serialization");
        }
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
        NotRecorded::Marker(MarkerHistory::Default) => "noHistory",
        NotRecorded::Marker(MarkerHistory::On) => "exists",
        NotRecorded::Marker(MarkerHistory::Off) => "off",
        NotRecorded::Marker(MarkerHistory::Removing) => "removing",
        NotRecorded::Marker(MarkerHistory::Unsupported { .. }) => "newerVersion",
        NotRecorded::Marker(MarkerHistory::Both) | NotRecorded::Damaged(_) => "damaged",
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
    marker: usize,
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
                    output.finish(&response)
                }
                (None, Some(append)) => {
                    let (Some(marker), Some(head), Some(key)) = (
                        blob(blobs, append.marker)
                            .and_then(|bytes| Marker::parse(vault_id, bytes).ok()),
                        blob(blobs, append.head),
                        blob(blobs, append.key),
                    ) else {
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
                    let mut cache = AppendCache::default();
                    let response = match plan_append(
                        vault_id,
                        Some(&marker),
                        &stored,
                        &change,
                        growth,
                        &mut cache,
                        &mut random,
                    ) {
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
                                AppendShape::Rollover { grew } => ("rollover", None, Some(grew)),
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
                    output.finish(&response)
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
/// head lists, each with its blob, or none when its account is absent. With
/// `partial`, `parts` holds only the parts read so far, and a part the walk
/// reaches that isn't among them is asked for instead.
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
    #[serde(default)]
    partial: bool,
    #[serde(flatten)]
    rest: T,
}

struct Opening<'a> {
    opened: Opened,
    parts: HashMap<u16, &'a [u8]>,
    values: Option<Payload>,
    /// With a partial read, the parts the request listed, read or absent.
    listed: Option<HashSet<u16>>,
    /// The part a partial read's walk reached without having it.
    needed: Cell<Option<u16>>,
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
    let listed = request
        .partial
        .then(|| request.parts.iter().map(|part| part.part).collect());
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
        listed,
        needed: Cell::new(None),
    })
}

/// The parts the app passed, lent to a reader without copying. In a partial
/// read, reaching a part the app didn't list stops the walk, noting the part.
struct LentParts<'a, 'b> {
    parts: &'b HashMap<u16, &'a [u8]>,
    listed: Option<&'b HashSet<u16>>,
    needed: &'b Cell<Option<u16>>,
}

impl PartSource for LentParts<'_, '_> {
    fn part(&mut self, part: u16) -> Result<Option<std::borrow::Cow<'_, [u8]>>, String> {
        if let Some(bytes) = self.parts.get(&part) {
            return Ok(Some(std::borrow::Cow::Borrowed(*bytes)));
        }
        match self.listed {
            Some(listed) if !listed.contains(&part) => {
                self.needed.set(Some(part));
                Err(format!("history part {part} hasn't been read yet"))
            }
            _ => Ok(None),
        }
    }
}

impl<'a> Opening<'a> {
    fn source(&self) -> LentParts<'a, '_> {
        LentParts {
            parts: &self.parts,
            listed: self.listed.as_ref(),
            needed: &self.needed,
        }
    }

    /// The answer that asks for the part a partial read's walk stopped at,
    /// when it stopped for one.
    fn asked(&self) -> Option<LPMEnvResult> {
        self.needed
            .get()
            .map(|part| Output::default().finish(&json!({ "needsParts": [part] })))
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

fn actor_name(actor: Actor) -> &'static str {
    match actor {
        Actor::App => "app",
        Actor::Cli => "cli",
        Actor::Outside => "outside",
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct KeyOut<'a> {
    key: &'a str,
    change: &'static str,
    before: &'static str,
    after: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    renamed_from: Option<&'a str>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct EnvironmentOut<'a> {
    name: &'a str,
    change: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    renamed_from: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    key_count: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    keys: Option<Vec<KeyOut<'a>>>,
}

#[derive(Serialize)]
#[serde(untagged)]
enum RemoteOut<'a> {
    Personal(&'static str),
    Org { org: &'a str },
}

#[derive(Serialize)]
struct RelatedOut {
    id: String,
    side: &'static str,
    time: i64,
}

/// A kept value's blobs, before and after.
#[derive(Serialize)]
struct ValuesOut {
    before: Option<usize>,
    after: Option<usize>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct EntryOut<'a> {
    id: String,
    seq: u64,
    time: i64,
    actor: &'static str,
    action: &'static str,
    source: &'static str,
    since: Option<i64>,
    values_kept: bool,
    oversized: bool,
    file_name: Option<&'a str>,
    pasted: bool,
    remote: Option<RemoteOut<'a>>,
    remote_version: Option<u64>,
    platform: Option<&'static str>,
    related: Option<RelatedOut>,
    environments: Vec<EnvironmentOut<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    values: Option<Vec<Vec<ValuesOut>>>,
}

fn environments_out(environments: &[EnvironmentInfo]) -> Vec<EnvironmentOut<'_>> {
    environments
        .iter()
        .map(|environment| {
            let (key_count, keys) = match &environment.keys {
                KeysInfo::Count(count) => (Some(*count), None),
                KeysInfo::Changes(changes) => (
                    None,
                    Some(
                        changes
                            .iter()
                            .map(|change| KeyOut {
                                key: &change.key,
                                change: match &change.kind {
                                    KeyKindInfo::Added => "added",
                                    KeyKindInfo::Changed => "changed",
                                    KeyKindInfo::Removed => "removed",
                                    KeyKindInfo::RenamedFrom(_) => "renamed",
                                },
                                before: side_info(change.before),
                                after: side_info(change.after),
                                renamed_from: match &change.kind {
                                    KeyKindInfo::RenamedFrom(from) => Some(from),
                                    _ => None,
                                },
                            })
                            .collect(),
                    ),
                ),
            };
            EnvironmentOut {
                name: &environment.name,
                change: match &environment.kind {
                    EnvironmentKindInfo::Unchanged => "unchanged",
                    EnvironmentKindInfo::Created => "created",
                    EnvironmentKindInfo::Removed => "removed",
                    EnvironmentKindInfo::RenamedFrom(_) => "renamed",
                },
                renamed_from: match &environment.kind {
                    EnvironmentKindInfo::RenamedFrom(from) => Some(from),
                    _ => None,
                },
                key_count,
                keys,
            }
        })
        .collect()
}

fn entry_out(info: &EntryInfo) -> EntryOut<'_> {
    let detail = &info.detail;
    EntryOut {
        id: hex::encode(info.id),
        seq: info.seq,
        time: info.time,
        actor: actor_name(info.actor),
        action: info.action.name(),
        source: info.source().name(),
        since: info.since,
        values_kept: !info.flags.values_not_kept,
        oversized: info.flags.oversized,
        file_name: detail.file_name.as_deref(),
        pasted: detail.pasted,
        remote: detail.remote.as_ref().map(|remote| match remote {
            RemoteInfo::Personal => RemoteOut::Personal("personal"),
            RemoteInfo::Org(slug) => RemoteOut::Org { org: slug },
        }),
        remote_version: detail.remote_version,
        platform: detail.platform.map(Platform::name),
        related: detail.related.map(|related| RelatedOut {
            id: hex::encode(related.id),
            side: side_name(related.side),
            time: related.time,
        }),
        environments: environments_out(&info.environments),
        values: None,
    }
}

/// The source counts as a map, in the groups' order.
struct CountsOut<'a>(&'a BTreeMap<SourceGroup, usize>);

impl Serialize for CountsOut<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(self.0.len()))?;
        for (group, count) in self.0 {
            map.serialize_entry(group.name(), count)?;
        }
        map.end()
    }
}

// Unreadable rows are rare, and boxing every entry would cost an allocation
// per row of every timeline.
#[allow(clippy::large_enum_variant)]
#[derive(Serialize)]
#[serde(untagged)]
enum RowOut<'a> {
    Entry(EntryOut<'a>),
    Unreadable {
        unreadable: bool,
        part: u16,
        after: Option<i64>,
        before: Option<i64>,
    },
}

#[derive(Serialize)]
struct LiveGapEnvironmentOut<'a> {
    name: &'a str,
    keys: Vec<&'a str>,
}

#[derive(Serialize)]
struct LiveGapOut<'a> {
    since: Option<i64>,
    environments: Vec<LiveGapEnvironmentOut<'a>>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct EnvironmentNameOut<'a> {
    name: &'a str,
    deleted_at: Option<i64>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TimelineOut<'a> {
    rows: Vec<RowOut<'a>>,
    live_gap: Option<LiveGapOut<'a>>,
    readable: usize,
    counts: CountsOut<'a>,
    oldest: Option<i64>,
    damaged_tail: bool,
    unreadable_parts: usize,
    environments: Vec<EnvironmentNameOut<'a>>,
    key_generation: u32,
}

fn timeline_out(timeline: &Timeline, key_generation: u32) -> TimelineOut<'_> {
    TimelineOut {
        rows: timeline
            .rows
            .iter()
            .map(|row| match row {
                TimelineRow::Entry(info) => RowOut::Entry(entry_out(info)),
                TimelineRow::Unreadable {
                    part,
                    after,
                    before,
                } => RowOut::Unreadable {
                    unreadable: true,
                    part: *part,
                    after: *after,
                    before: *before,
                },
            })
            .collect(),
        live_gap: timeline.live_gap.as_ref().map(|gap| LiveGapOut {
            since: gap.since,
            environments: gap
                .environments
                .iter()
                .map(|environment| LiveGapEnvironmentOut {
                    name: &environment.name,
                    keys: match &environment.keys {
                        KeysInfo::Changes(changes) => {
                            changes.iter().map(|change| change.key.as_str()).collect()
                        }
                        KeysInfo::Count(_) => Vec::new(),
                    },
                })
                .collect(),
        }),
        readable: timeline.readable,
        counts: CountsOut(&timeline.counts),
        oldest: timeline.oldest,
        damaged_tail: timeline.damaged_tail,
        unreadable_parts: timeline.unreadable_parts,
        environments: timeline
            .environments
            .iter()
            .map(|environment| EnvironmentNameOut {
                name: &environment.name,
                deleted_at: environment.deleted_at,
            })
            .collect(),
        key_generation,
    }
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
                let timeline = match read_timeline(
                    &opening.opened,
                    &mut opening.source(),
                    &values,
                    &filter,
                    false,
                ) {
                    Ok(timeline) => timeline,
                    Err(error) => return opening.asked().unwrap_or_else(|| read_refusal(error)),
                };
                Output::default().finish(&timeline_out(
                    &timeline,
                    opening.opened.record.current().generation(),
                ))
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
                    Err(error) => return opening.asked().unwrap_or_else(|| read_refusal(error)),
                };
                let mut output = Output::default();
                let mut infos = Vec::with_capacity(revealed.len());
                let mut blobs: Vec<Vec<Vec<ValuesOut>>> = Vec::with_capacity(revealed.len());
                for entry in revealed {
                    blobs.push(
                        entry
                            .values
                            .into_iter()
                            .map(|environment| {
                                environment
                                    .into_iter()
                                    .map(|RevealedValues { before, after }| ValuesOut {
                                        before: before.map(|value| output.secret(value)),
                                        after: after.map(|value| output.secret(value)),
                                    })
                                    .collect()
                            })
                            .collect(),
                    );
                    infos.push(entry.info);
                }
                let entries: Vec<EntryOut<'_>> = infos
                    .iter()
                    .zip(blobs)
                    .map(|(info, values)| EntryOut {
                        values: Some(values),
                        ..entry_out(info)
                    })
                    .collect();
                #[derive(Serialize)]
                struct Revealed<'a> {
                    entries: Vec<EntryOut<'a>>,
                }
                output.finish(&Revealed { entries })
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
    /// How `environment` is named: `"now"`, or `"atPoint"`, as the entry
    /// there names it. An environment rollback defaults to `"atPoint"`, a
    /// key rollback to `"now"`.
    #[serde(default)]
    environment_named: Option<String>,
    #[serde(default)]
    key: Option<String>,
    #[serde(default)]
    side: Option<String>,
}

fn environment_ref<'a>(
    name: &'a str,
    named: Option<&str>,
    default: fn(&'a str) -> EnvironmentRef<'a>,
) -> Option<EnvironmentRef<'a>> {
    match named {
        None => Some(default(name)),
        Some("now") => Some(EnvironmentRef::Now(name)),
        Some("atPoint") => Some(EnvironmentRef::AtPoint(name)),
        Some(_) => None,
    }
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
                request.environment.as_deref().and_then(|name| {
                    environment_ref(
                        name,
                        request.environment_named.as_deref(),
                        EnvironmentRef::AtPoint,
                    )
                }),
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
            let (Some(environment), Some(key)) = (
                request.environment.as_deref().and_then(|name| {
                    environment_ref(
                        name,
                        request.environment_named.as_deref(),
                        EnvironmentRef::Now,
                    )
                }),
                request.key.as_deref(),
            ) else {
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
        "undo" => {
            let only = match request.environment.as_deref() {
                Some(name) => match environment_ref(
                    name,
                    request.environment_named.as_deref(),
                    EnvironmentRef::Now,
                ) {
                    Some(only) => Some(EnvironmentName::from(only)),
                    None => return Err(failure(2, "history.invalid_input")),
                },
                None => None,
            };
            plan_by_entry(
                &opening.opened,
                &mut opening.source(),
                &values,
                &IdPrefix::whole(entry),
                |_| Ok::<_, PlanError>(Target::Undo { only }),
            )
            .map(|(_, plan)| plan)
        }
        _ => return Err(failure(2, "history.invalid_input")),
    };
    planned.map_err(|error| match error {
        PlanError::Read(_) if opening.needed.get().is_some() => {
            opening.asked().expect("a part was asked for")
        }
        PlanError::Read(error) => read_refusal(error),
        PlanError::EntryNotFound => refused("history.entry_not_found", None),
        PlanError::AmbiguousEntry => refused("history.ambiguous_entry", None),
        PlanError::UnknownEnvironment => refused("history.unknown_environment", None),
        PlanError::NameTaken(name) => refused(
            "history.name_taken",
            Some(PlanError::NameTaken(name).to_string()),
        ),
    })
}

/// What a review saw, so an apply can tell whether a fresh plan matches it:
/// every row's key, its target's kind and digest, and each binding.
fn fingerprint(opened: &Opened, plan: &RollbackPlan) -> String {
    let length = 4 + plan
        .environments
        .iter()
        .map(|environment| {
            2 + 8
                + environment.current.as_ref().map_or(0, String::len)
                + environment.target.as_ref().map_or(0, String::len)
                + 16
                + 1
                + environment
                    .rows
                    .iter()
                    .map(|row| {
                        4 + row.key.len()
                            + 17
                            + row.linked.iter().map(|key| 4 + key.len()).sum::<usize>()
                            + 4
                    })
                    .sum::<usize>()
        })
        .sum::<usize>();
    let mut encoded = Zeroizing::new(Vec::with_capacity(length));
    encoded.extend_from_slice(&plan.generation.to_be_bytes());
    encoded.extend_from_slice(&plan.key_id);
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
        encoded.push(u8::from(environment.unnamed_keys.is_some()));
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
            encoded.extend_from_slice(&(row.linked.len() as u32).to_be_bytes());
            for key in &row.linked {
                encoded.extend_from_slice(&(key.len() as u32).to_be_bytes());
                encoded.extend_from_slice(key.as_bytes());
            }
        }
    }
    digest_text(&opened.keys.binding("rollback", &encoded))
}

fn unknown_reason(reason: UnknownReason) -> &'static str {
    match reason {
        UnknownReason::NotRecorded => "notRecorded",
        UnknownReason::TooLarge => "tooLarge",
        UnknownReason::Removed => "removed",
        UnknownReason::Unreadable => "unreadable",
    }
}

#[derive(Serialize)]
struct GapOut {
    since: Option<i64>,
    until: Option<i64>,
}

#[derive(Serialize)]
struct PulledOut {
    remote: Value,
    version: Option<u64>,
    time: i64,
}

#[derive(Serialize)]
struct ChangedAgainOut {
    time: i64,
    actor: &'static str,
    action: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PlanRowOut {
    key: String,
    change: &'static str,
    changes: bool,
    reason: Option<&'static str>,
    current: Option<usize>,
    target: Option<usize>,
    gaps: Vec<GapOut>,
    pulled: Option<PulledOut>,
    changed_again: Option<ChangedAgainOut>,
    linked: Vec<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PlanEnvironmentOut {
    current: Option<String>,
    target: Option<String>,
    recreates: bool,
    offers_deletion: bool,
    renames: bool,
    unnamed_keys: Option<&'static str>,
    rows: Vec<PlanRowOut>,
}

#[derive(Serialize)]
struct PointOut {
    entry: String,
    side: &'static str,
    time: i64,
}

#[derive(Serialize)]
struct PlanOut {
    kind: &'static str,
    point: PointOut,
    generation: u32,
    fingerprint: String,
    environments: Vec<PlanEnvironmentOut>,
}

fn plan_out(opened: &Opened, plan: RollbackPlan, output: &mut Output) -> PlanOut {
    let fingerprint = fingerprint(opened, &plan);
    let environments = plan
        .environments
        .into_iter()
        .map(|environment| {
            let recreates = environment.recreates();
            let offers_deletion = environment.offers_deletion();
            let renames = environment.renames();
            let rows = environment
                .rows
                .into_iter()
                .map(|row| {
                    let changes = row.changes();
                    let (change, reason) = match (&row.target, &row.current) {
                        (TargetValue::Unknown(reason), _) => {
                            ("unknown", Some(unknown_reason(*reason)))
                        }
                        (TargetValue::Known(_), Some(_)) => ("changed", None),
                        (TargetValue::Known(_), None) => ("added", None),
                        (TargetValue::Absent, _) => ("removed", None),
                    };
                    PlanRowOut {
                        key: row.key,
                        change,
                        changes,
                        reason,
                        current: row.current.map(|value| output.secret(value)),
                        target: match row.target {
                            TargetValue::Known(value) => Some(output.secret(value)),
                            TargetValue::Absent | TargetValue::Unknown(_) => None,
                        },
                        gaps: row
                            .gaps
                            .iter()
                            .map(|gap| GapOut {
                                since: gap.since,
                                until: gap.until,
                            })
                            .collect(),
                        pulled: row.pulled.map(|pulled| PulledOut {
                            remote: match pulled.remote {
                                Some(lpm_env_companion::history::rebuild::RemoteName::Org(
                                    slug,
                                )) => {
                                    json!({ "org": slug })
                                }
                                _ => json!("personal"),
                            },
                            version: pulled.version,
                            time: pulled.time,
                        }),
                        changed_again: row.changed_again.map(|changed| ChangedAgainOut {
                            time: changed.time,
                            actor: actor_name(changed.actor),
                            action: changed.action.name(),
                        }),
                        linked: row.linked,
                    }
                })
                .collect();
            PlanEnvironmentOut {
                current: environment.current,
                target: environment.target,
                recreates,
                offers_deletion,
                renames,
                unnamed_keys: environment.unnamed_keys.map(unknown_reason),
                rows,
            }
        })
        .collect();
    PlanOut {
        kind: match plan.kind {
            RollbackKind::Environment => "environment",
            RollbackKind::Key => "key",
            RollbackKind::Undo => "undo",
        },
        point: PointOut {
            entry: hex::encode(plan.point.entry),
            side: side_name(plan.point.side),
            time: plan.point_time,
        },
        generation: plan.generation,
        fingerprint,
        environments,
    }
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
                    #[derive(Serialize)]
                    struct Planned {
                        plan: PlanOut,
                    }
                    let plan = plan_out(&opening.opened, plan, &mut output);
                    return output.finish(&Planned { plan });
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
                    opening.opened.record.current().history_key(),
                ) {
                    Ok(writes) => writes,
                    Err(Refusal::ChangedSinceReview) => {
                        return refused("history.changed_since_review", None);
                    }
                    Err(Refusal::NothingToApply) => return refused("history.target_unknown", None),
                };
                #[derive(Serialize)]
                struct ValueOut {
                    key: String,
                    value: usize,
                }
                #[derive(Serialize)]
                #[serde(rename_all = "camelCase")]
                struct WriteOut {
                    name: String,
                    renamed_from: Option<String>,
                    values: Option<Vec<ValueOut>>,
                }
                #[derive(Serialize)]
                struct Writes {
                    writes: Vec<WriteOut>,
                }
                let writes = writes
                    .into_iter()
                    .map(|write| WriteOut {
                        name: write.name,
                        renamed_from: write.renamed_from,
                        values: write.values.map(|values| {
                            values
                                .into_iter()
                                .map(|(key, value)| ValueOut {
                                    key,
                                    value: output.secret(value),
                                })
                                .collect()
                        }),
                    })
                    .collect();
                output.finish(&Writes { writes })
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
    #[serde(default)]
    renamed_environments: Vec<String>,
    group: String,
    current: bool,
    digests: Vec<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ReviewRequest {
    value: String,
    generation: u32,
    key_id: String,
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
    /// The review's fingerprint, which binds a start to the review shown.
    fingerprint: String,
}

/// What a removal review showed, keyed with the history's digest key, so a
/// start can tell the review it was given is the one the engine returned:
/// the value, the generation, and every place's names, group, current flag
/// and digests.
fn review_fingerprint(opened: &Opened, review: &RemovalReview) -> String {
    let text = |encoded: &mut Vec<u8>, text: &str| {
        encoded.extend_from_slice(&(text.len() as u32).to_be_bytes());
        encoded.extend_from_slice(text.as_bytes());
    };
    let length = 16
        + 4
        + review
            .places
            .iter()
            .map(|place| {
                8 + place.environment.len()
                    + place.key.len()
                    + place
                        .renamed_from
                        .iter()
                        .chain(&place.renamed_environments)
                        .map(|name| 4 + name.len())
                        .sum::<usize>()
                    + 8
                    + 2
                    + 4
                    + 16 * place.digests.len()
            })
            .sum::<usize>();
    let mut encoded = Vec::with_capacity(length);
    encoded.extend_from_slice(&review.value);
    encoded.extend_from_slice(&review.generation.to_be_bytes());
    encoded.extend_from_slice(&review.key_id);
    for place in &review.places {
        text(&mut encoded, &place.environment);
        text(&mut encoded, &place.key);
        for names in [&place.renamed_from, &place.renamed_environments] {
            encoded.extend_from_slice(&(names.len() as u32).to_be_bytes());
            for name in names {
                text(&mut encoded, name);
            }
        }
        encoded.push(match place.group {
            PlaceGroup::ThisKey => 1,
            PlaceGroup::OtherKey => 2,
        });
        encoded.push(u8::from(place.current));
        encoded.extend_from_slice(&(place.digests.len() as u32).to_be_bytes());
        for digest in &place.digests {
            encoded.extend_from_slice(digest);
        }
    }
    digest_text(&opened.keys.binding("removal", &encoded))
}

fn removal_refusal(error: RemovalError) -> LPMEnvResult {
    let code = match &error {
        RemovalError::Read(_) | RemovalError::Damaged(_) => "history.damaged",
        RemovalError::NotFound => "history.entry_not_found",
        RemovalError::AmbiguousEntry => "history.ambiguous_entry",
        RemovalError::NothingToRemove => "history.nothing_to_remove",
        RemovalError::ValueIsCurrent => "history.value_is_current",
        RemovalError::Limit => "history.limit",
        RemovalError::ChangedSinceReview => "history.changed_since_review",
        RemovalError::GenerationExhausted => "history.generation_exhausted",
        RemovalError::Running => "history.running",
        RemovalError::PartNotRotated(_) => "history.part_not_rotated",
        RemovalError::Random => "history.random_failed",
    };
    refused(code, Some(error.to_string()))
}

#[derive(Serialize)]
struct OccurrenceOut {
    set: Option<i64>,
    replaced: Option<i64>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PlaceOut<'a> {
    environment: &'a str,
    key: &'a str,
    renamed_from: &'a [String],
    renamed_environments: &'a [String],
    group: &'static str,
    current: bool,
    occurrences: Vec<OccurrenceOut>,
    digests: Vec<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ReviewOut<'a> {
    value: String,
    generation: u32,
    key_id: String,
    places: Vec<PlaceOut<'a>>,
    default_selection: BTreeSet<usize>,
    fingerprint: String,
}

fn review_out<'a>(opened: &Opened, review: &'a RemovalReview) -> ReviewOut<'a> {
    ReviewOut {
        fingerprint: review_fingerprint(opened, review),
        value: digest_text(&review.value),
        generation: review.generation,
        key_id: hex::encode(review.key_id),
        places: review
            .places
            .iter()
            .map(|place| PlaceOut {
                environment: &place.environment,
                key: &place.key,
                renamed_from: &place.renamed_from,
                renamed_environments: &place.renamed_environments,
                group: match place.group {
                    PlaceGroup::ThisKey => "thisKey",
                    PlaceGroup::OtherKey => "otherKey",
                },
                current: place.current,
                occurrences: place
                    .occurrences
                    .iter()
                    .map(|occurrence| OccurrenceOut {
                        set: occurrence.set,
                        replaced: occurrence.replaced,
                    })
                    .collect(),
                digests: place.digests.iter().map(digest_text).collect(),
            })
            .collect(),
        default_selection: review.default_selection(),
    }
}

fn review_from(request: &ReviewRequest) -> Option<RemovalReview> {
    Some(RemovalReview {
        value: digest_from(&request.value)?,
        generation: request.generation,
        key_id: hex::decode(&request.key_id).ok()?.try_into().ok()?,
        places: request
            .places
            .iter()
            .map(|place| {
                Some(Place {
                    environment: place.environment.clone(),
                    key: place.key.clone(),
                    renamed_from: place.renamed_from.clone(),
                    renamed_environments: place.renamed_environments.clone(),
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
                                #[derive(Serialize)]
                                struct Reviewed<'a> {
                                    review: ReviewOut<'a>,
                                }
                                Output::default().finish(&Reviewed {
                                    review: review_out(&opening.opened, &review),
                                })
                            }
                            Err(error) => opening.asked().unwrap_or_else(|| removal_refusal(error)),
                        }
                    }
                    (None, Some(start)) => {
                        let (Some(review), Some(approval)) =
                            (review_from(&start.review), approval(&start.approval))
                        else {
                            return failure(2, "history.invalid_input");
                        };
                        if review_fingerprint(&opening.opened, &review) != start.fingerprint {
                            return refused("history.changed_since_review", None);
                        }
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
                                output.finish(&json!({ "journal": true, "writes": writes }))
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
                    "finish" => {
                        match finish_rotation(opened, |part| opening.parts.get(&part).copied()) {
                            Ok(writes) => json!({
                                "journal": true,
                                "writes": writes.into_iter().map(|write| output.write(write)).collect::<Vec<_>>(),
                            }),
                            Err(error) => return removal_refusal(error),
                        }
                    }
                    _ => return failure(2, "history.invalid_input"),
                };
                output.finish(&response)
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
            let head = request
                .head
                .and_then(|index| blob(blobs, index))
                .and_then(|bytes| Head::parse(HISTORY, vault_id, bytes).ok());
            let needed: Vec<u16> = head
                .iter()
                .flat_map(|head| std::iter::once(head.tail()).chain(head.before_tail()))
                .collect();
            let listed: HashMap<u16, Option<&[u8]>> = request
                .parts
                .iter()
                .map(|part| (part.part, part.blob.and_then(|index| blob(blobs, index))))
                .collect();
            #[derive(Serialize)]
            struct DamageOut {
                kind: String,
                reason: String,
                description: String,
            }
            #[derive(Serialize)]
            #[serde(rename_all = "camelCase")]
            struct Checked {
                history: &'static str,
                version: Option<u16>,
                tail_part: Option<u16>,
                /// The parts the check needs before it can say: the tail and
                /// the part before it, each listed with its blob, or without
                /// one when its account is absent.
                needs_parts: Option<Vec<u16>>,
                damage: Option<Vec<DamageOut>>,
            }
            let missing =
                state == MarkerHistory::On && needed.iter().any(|part| !listed.contains_key(part));
            let damage = if missing {
                None
            } else if state == MarkerHistory::On {
                Some(
                    check_records(
                        vault_id,
                        request.head.and_then(|index| blob(blobs, index)),
                        request.key.and_then(|index| blob(blobs, index)),
                        |part| {
                            listed
                                .get(&part)
                                .copied()
                                .flatten()
                                .map(std::borrow::Cow::Borrowed)
                        },
                    )
                    .into_iter()
                    .map(|damage| {
                        let description = damage.to_string();
                        match damage {
                            lpm_env_companion::gate::Damage::InvalidRecord { kind, reason } => {
                                DamageOut {
                                    kind,
                                    reason,
                                    description,
                                }
                            }
                            _ => DamageOut {
                                kind: String::new(),
                                reason: description.clone(),
                                description,
                            },
                        }
                    })
                    .collect(),
                )
            } else {
                Some(Vec::new())
            };
            Output::default().finish(&Checked {
                history: name,
                version,
                tail_part: head.as_ref().map(Head::tail),
                needs_parts: missing.then_some(needed),
                damage,
            })
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
    /// For growth: the growing ring's vault ID and head blob, which say
    /// whether it grows below its limit or grows back after shrinking.
    #[serde(default)]
    vault_id: Option<String>,
    #[serde(default)]
    head: Option<usize>,
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
        respond(input, length, |request: AdmissionRequest, blobs| {
            let growing = match (&request.vault_id, request.head) {
                (Some(vault_id), Some(index)) => match blob(blobs, index)
                    .and_then(|bytes| Head::parse(HISTORY, vault_id, bytes).ok())
                {
                    Some(head) => Some(head),
                    None => return failure(2, "history.invalid_input"),
                },
                (None, None) => None,
                _ => return failure(2, "history.invalid_input"),
            };
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
            let trimmed: usize = trims.iter().map(|planned| planned.count).sum();
            let after_trims = existing.saturating_sub(trimmed);
            let creation = match admission::admit_creation(after_trims) {
                CreationAdmission::Full => "full",
                CreationAdmission::Reduced => "reduced",
                CreationAdmission::Refused => "refused",
            };
            Output::default().finish(&json!({
                "existing": existing,
                "trims": trims.iter().map(|planned| json!({ "vaultId": planned.vault_id, "count": planned.count, "floor": planned.floor })).collect::<Vec<_>>(),
                "afterTrims": after_trims,
                "creation": creation,
                "ringLimit": admission::admit_creation(after_trims).ring_limit(),
                "growth": growing.map_or_else(
                    || admission::admit_growth(after_trims),
                    |mut head| {
                        // Trims of the growing ring itself leave it at its new
                        // size, which may only grow back below the regrowth
                        // threshold.
                        if let Some(own) =
                            trims.iter().find(|planned| planned.vault_id == head.vault_id)
                        {
                            for _ in 0..own.count {
                                match head.trim_oldest() {
                                    Some((trimmed, _)) if head.parts.len() > own.floor => {
                                        head = trimmed;
                                    }
                                    _ => break,
                                }
                            }
                        }
                        admission::admit_growth_of(&head, after_trims)
                    },
                ),
                "regrow": after_trims < admission::REGROW_BELOW,
            }))
        })
    }
}

/// The key and tail a trim to one part reads: `part` is omitted when the
/// tail's account is absent.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RingTail {
    key: usize,
    #[serde(default)]
    part: Option<usize>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RingRequest {
    vault_id: String,
    head: usize,
    action: String,
    #[serde(default)]
    floor: Option<usize>,
    #[serde(default)]
    tail: Option<RingTail>,
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
                "trim" => {
                    let Some(floor) = request.floor else {
                        return failure(2, "history.invalid_input");
                    };
                    let tail = match &request.tail {
                        None => TrimTail::Unread,
                        Some(read) => match blob(blobs, read.key) {
                            Some(key) => TrimTail::Read {
                                key,
                                tail: read.part.and_then(|index| blob(blobs, index)),
                            },
                            None => return failure(2, "history.invalid_input"),
                        },
                    };
                    match admission::trim_oldest(&head, floor, tail) {
                        TrimStep::Trim(trim) => json!({
                            "writes": [output.write(trim.head)],
                            "delete": trim.delete.name(),
                        }),
                        TrimStep::NeedsTail => {
                            json!({ "needsTail": true, "writes": [], "delete": null })
                        }
                        TrimStep::Keep => json!({ "writes": [], "delete": null }),
                    }
                }
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
            output.finish(&response)
        })
    }
}

#[cfg(test)]
mod tests;
