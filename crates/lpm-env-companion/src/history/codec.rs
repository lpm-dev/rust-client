//! The plaintext inside a history part: its epoch, the digest summary of
//! the project's state after its last entry, and its entries.
//!
//! ```text
//! part    = "LPMH" ‖ u8 version=1 ‖ u64be epoch ‖ summary ‖ u32be entries, each: u32be length ‖ entry
//! summary = u16be environments, each: str16 name
//!           ‖ u32be keys, each: str16 key ‖ u8 tag (1 digest, 2 removed) ‖ digest [16] when 1
//! entry   = u64be seq ‖ id [16] ‖ i64be time ‖ u8 actor ‖ u8 action ‖ u8 flags
//!           ‖ i64be since, only for `outside`
//!           ‖ u16be detail bytes ‖ detail: u8 type ‖ u16be length ‖ bytes, types ascending
//!           ‖ u16be environments, each: str16 name ‖ u8 change (0 none, 1 created,
//!             2 removed, 3 renamed ‖ str16 from)
//!             ‖ oversized: u32be key count
//!             ‖ otherwise u32be key changes, each: str16 key ‖ u8 change (1 added,
//!               2 changed, 3 removed, 4 renamed ‖ str16 from) ‖ side before ‖ side after
//! side    = u8 0 absent | 1 value: u32be length ‖ UTF-8 ‖ digest [16]
//!           | 2 digest only: digest [16] ‖ u8 reason (1 too large, 2 not recorded) | 3 removed
//! ```
//!
//! `str16` is a big-endian `u16` length and non-empty UTF-8. Names are sorted
//! by their bytes and distinct, every length is bounded by the bytes left,
//! and trailing bytes are refused. Decoded parts borrow from the plaintext,
//! so values are never copied out of the wiped buffer that holds them.

use std::collections::BTreeMap;
use std::fmt;

use zeroize::Zeroizing;

use crate::keyring::{Digest, PART_CAPACITY};

pub const PART_MAGIC: [u8; 4] = *b"LPMH";
pub const PART_VERSION: u8 = 1;
const PART_HEADER_BYTES: usize = 4 + 1 + 8;
const MAX_FILE_NAME_BYTES: usize = 255;

pub type EntryId = [u8; 16];

/// Why a part's plaintext can't be read. A part that opens but won't decode
/// is as unreadable as one that won't open.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidPart(pub &'static str);

impl fmt::Display for InvalidPart {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "a history part is invalid: {}", self.0)
    }
}

type Result<T> = std::result::Result<T, InvalidPart>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Actor {
    App,
    Cli,
    Outside,
}

impl Actor {
    pub fn byte(self) -> u8 {
        match self {
            Self::App => 1,
            Self::Cli => 2,
            Self::Outside => 3,
        }
    }

    pub fn from_byte(byte: u8) -> Option<Self> {
        Some(match byte {
            1 => Self::App,
            2 => Self::Cli,
            3 => Self::Outside,
            _ => return None,
        })
    }
}

/// What a person did, a closed set both clients write.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Action {
    Set,
    Delete,
    EditKey,
    RenameKey,
    RawEdit,
    CreateEnvironment,
    RenameEnvironment,
    DuplicateEnvironment,
    ClearEnvironment,
    DeleteEnvironment,
    CopyEnvironment,
    InitFromFiles,
    ProjectImport,
    Import,
    Restore,
    Pull,
    PlatformPull,
    Rollback,
    Undo,
    Outside,
}

impl Action {
    pub const ALL: [Self; 20] = [
        Self::Set,
        Self::Delete,
        Self::EditKey,
        Self::RenameKey,
        Self::RawEdit,
        Self::CreateEnvironment,
        Self::RenameEnvironment,
        Self::DuplicateEnvironment,
        Self::ClearEnvironment,
        Self::DeleteEnvironment,
        Self::CopyEnvironment,
        Self::InitFromFiles,
        Self::ProjectImport,
        Self::Import,
        Self::Restore,
        Self::Pull,
        Self::PlatformPull,
        Self::Rollback,
        Self::Undo,
        Self::Outside,
    ];

    pub fn byte(self) -> u8 {
        Self::ALL
            .iter()
            .position(|action| *action == self)
            .map_or(0, |index| index as u8 + 1)
    }

    pub fn from_byte(byte: u8) -> Option<Self> {
        byte.checked_sub(1)
            .and_then(|index| Self::ALL.get(usize::from(index)))
            .copied()
    }

    /// The name both clients' JSON uses.
    pub fn name(self) -> &'static str {
        match self {
            Self::Set => "set",
            Self::Delete => "delete",
            Self::EditKey => "editKey",
            Self::RenameKey => "renameKey",
            Self::RawEdit => "rawEdit",
            Self::CreateEnvironment => "createEnvironment",
            Self::RenameEnvironment => "renameEnvironment",
            Self::DuplicateEnvironment => "duplicateEnvironment",
            Self::ClearEnvironment => "clearEnvironment",
            Self::DeleteEnvironment => "deleteEnvironment",
            Self::CopyEnvironment => "copyEnvironment",
            Self::InitFromFiles => "initFromFiles",
            Self::ProjectImport => "projectImport",
            Self::Import => "import",
            Self::Restore => "restore",
            Self::Pull => "pull",
            Self::PlatformPull => "platformPull",
            Self::Rollback => "rollback",
            Self::Undo => "undo",
            Self::Outside => "outside",
        }
    }
}

/// The env platforms `lpm env pull --from` reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Platform {
    Vercel,
    Coolify,
    Fly,
    Railway,
    GithubActions,
}

impl Platform {
    pub fn byte(self) -> u8 {
        match self {
            Self::Vercel => 1,
            Self::Coolify => 2,
            Self::Fly => 3,
            Self::Railway => 4,
            Self::GithubActions => 5,
        }
    }

    pub fn from_byte(byte: u8) -> Option<Self> {
        Some(match byte {
            1 => Self::Vercel,
            2 => Self::Coolify,
            3 => Self::Fly,
            4 => Self::Railway,
            5 => Self::GithubActions,
            _ => return None,
        })
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Vercel => "vercel",
            Self::Coolify => "coolify",
            Self::Fly => "fly",
            Self::Railway => "railway",
            Self::GithubActions => "github-actions",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        [
            Self::Vercel,
            Self::Coolify,
            Self::Fly,
            Self::Railway,
            Self::GithubActions,
        ]
        .into_iter()
        .find(|platform| platform.name() == name)
    }
}

/// Where a pull came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Remote<'a> {
    Personal,
    Org(&'a str),
}

/// Which side of a related entry a rollback or an undo went back to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RelatedSide {
    Before,
    After,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Related {
    pub id: EntryId,
    pub side: RelatedSide,
    /// The related entry's time, so the timeline can say "Rolled back to
    /// Nov 3, 14:02" after that entry leaves retention.
    pub time: i64,
}

/// What an action names besides its changes.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct Detail<'a> {
    /// An imported file's base name.
    pub file_name: Option<&'a str>,
    /// An import of pasted text.
    pub pasted: bool,
    pub remote: Option<Remote<'a>>,
    pub remote_version: Option<u64>,
    pub platform: Option<Platform>,
    pub related: Option<Related>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct Flags {
    /// The change was too large for a part with its values, so its sides
    /// keep digests only.
    pub values_not_kept: bool,
    /// The first entry of a tail rewritten after a crash between a
    /// rollover's head and part.
    pub interrupted_rollover: bool,
    /// Even without values the change didn't fit, so only environment names
    /// and key counts are kept.
    pub oversized: bool,
}

impl Flags {
    const VALUES_NOT_KEPT: u8 = 1;
    const INTERRUPTED_ROLLOVER: u8 = 2;
    const OVERSIZED: u8 = 4;

    fn byte(self) -> u8 {
        (if self.values_not_kept {
            Self::VALUES_NOT_KEPT
        } else {
            0
        }) | (if self.interrupted_rollover {
            Self::INTERRUPTED_ROLLOVER
        } else {
            0
        }) | (if self.oversized { Self::OVERSIZED } else { 0 })
    }

    fn from_byte(byte: u8) -> Option<Self> {
        (byte & !(Self::VALUES_NOT_KEPT | Self::INTERRUPTED_ROLLOVER | Self::OVERSIZED) == 0)
            .then_some(Self {
                values_not_kept: byte & Self::VALUES_NOT_KEPT != 0,
                interrupted_rollover: byte & Self::INTERRUPTED_ROLLOVER != 0,
                oversized: byte & Self::OVERSIZED != 0,
            })
    }
}

/// Why a side keeps a digest but not its value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Unkept {
    TooLarge,
    NotRecorded,
}

/// One side of a key change.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub enum Side<'a> {
    Absent,
    Value { value: &'a str, digest: Digest },
    DigestOnly { digest: Digest, reason: Unkept },
    Removed,
}

impl fmt::Debug for Side<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Absent => formatter.write_str("Absent"),
            Self::Value { digest, .. } => formatter
                .debug_struct("Value")
                .field("digest", digest)
                .finish_non_exhaustive(),
            Self::DigestOnly { digest, reason } => formatter
                .debug_struct("DigestOnly")
                .field("digest", digest)
                .field("reason", reason)
                .finish(),
            Self::Removed => formatter.write_str("Removed"),
        }
    }
}

impl<'a> Side<'a> {
    pub fn digest(&self) -> Option<Digest> {
        match self {
            Self::Value { digest, .. } | Self::DigestOnly { digest, .. } => Some(*digest),
            Self::Absent | Self::Removed => None,
        }
    }

    pub fn is_absent(&self) -> bool {
        matches!(self, Self::Absent)
    }

    /// This side without its value: a digest when it had one.
    pub fn without_value(self) -> Self {
        match self {
            Self::Value { digest, .. } => Self::DigestOnly {
                digest,
                reason: Unkept::TooLarge,
            },
            other => other,
        }
    }

    fn encoded_len(&self) -> usize {
        match self {
            Self::Absent | Self::Removed => 1,
            Self::Value { value, .. } => 1 + 4 + value.len() + 16,
            Self::DigestOnly { .. } => 1 + 16 + 1,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyKind<'a> {
    Added,
    Changed,
    Removed,
    RenamedFrom(&'a str),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct KeyChange<'a> {
    pub key: &'a str,
    pub kind: KeyKind<'a>,
    pub before: Side<'a>,
    pub after: Side<'a>,
}

impl KeyChange<'_> {
    fn encoded_len(&self) -> usize {
        let from = match self.kind {
            KeyKind::RenamedFrom(from) => 2 + from.len(),
            _ => 0,
        };
        2 + self.key.len() + 1 + from + self.before.encoded_len() + self.after.encoded_len()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EnvironmentKind<'a> {
    Unchanged,
    Created,
    Removed,
    RenamedFrom(&'a str),
}

/// An environment's key changes, or in an oversized entry, their count.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Keys<'a> {
    Changes(Vec<KeyChange<'a>>),
    Count(u32),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EnvironmentChange<'a> {
    pub name: &'a str,
    pub kind: EnvironmentKind<'a>,
    pub keys: Keys<'a>,
}

impl EnvironmentChange<'_> {
    pub fn key_count(&self) -> usize {
        match &self.keys {
            Keys::Changes(changes) => changes.len(),
            Keys::Count(count) => *count as usize,
        }
    }

    fn encoded_len(&self) -> usize {
        let from = match self.kind {
            EnvironmentKind::RenamedFrom(from) => 2 + from.len(),
            _ => 0,
        };
        let keys = match &self.keys {
            Keys::Count(_) => 4,
            Keys::Changes(changes) => 4 + changes.iter().map(KeyChange::encoded_len).sum::<usize>(),
        };
        2 + self.name.len() + 1 + from + keys
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Entry<'a> {
    pub seq: u64,
    pub id: EntryId,
    pub time: i64,
    pub actor: Actor,
    pub action: Action,
    pub flags: Flags,
    /// For `outside` entries, the time of the entry before them.
    pub since: Option<i64>,
    pub detail: Detail<'a>,
    pub environments: Vec<EnvironmentChange<'a>>,
}

impl<'a> Entry<'a> {
    /// How many keys the entry changes, across its environments.
    pub fn key_count(&self) -> usize {
        self.environments
            .iter()
            .map(EnvironmentChange::key_count)
            .sum()
    }

    /// Whether the entry changes at least one key, which creating history
    /// requires.
    pub fn changes_keys(&self) -> bool {
        self.key_count() > 0
    }

    /// The bytes [`Entry::encode_into`] writes.
    pub fn encoded_len(&self) -> usize {
        8 + 16
            + 8
            + 3
            + if self.action == Action::Outside { 8 } else { 0 }
            + 2
            + detail_len(&self.detail)
            + 2
            + self
                .environments
                .iter()
                .map(EnvironmentChange::encoded_len)
                .sum::<usize>()
    }

    /// The entry without values: every value side keeps only its digest.
    pub fn without_values(&self) -> Self {
        let mut entry = self.clone();
        entry.flags.values_not_kept = true;
        for environment in &mut entry.environments {
            if let Keys::Changes(changes) = &mut environment.keys {
                for change in changes {
                    change.before = change.before.without_value();
                    change.after = change.after.without_value();
                }
            }
        }
        entry
    }

    /// The entry with environment names and key counts only.
    pub fn oversized(&self) -> Self {
        let mut entry = self.clone();
        entry.flags.values_not_kept = true;
        entry.flags.oversized = true;
        for environment in &mut entry.environments {
            environment.keys = Keys::Count(environment.key_count().try_into().unwrap_or(u32::MAX));
        }
        entry
    }

    /// Append the encoding to `out`, after checking every rule a reader
    /// checks.
    pub fn encode_into(&self, out: &mut Vec<u8>) -> Result<()> {
        self.validate()?;
        out.reserve(self.encoded_len());
        out.extend_from_slice(&self.seq.to_be_bytes());
        out.extend_from_slice(&self.id);
        out.extend_from_slice(&self.time.to_be_bytes());
        out.push(self.actor.byte());
        out.push(self.action.byte());
        out.push(self.flags.byte());
        if self.action == Action::Outside {
            out.extend_from_slice(&self.since.unwrap_or(self.time).to_be_bytes());
        }
        let detail_bytes = u16::try_from(detail_len(&self.detail))
            .map_err(|_| InvalidPart("an entry's detail is too large"))?;
        out.extend_from_slice(&detail_bytes.to_be_bytes());
        encode_detail(&self.detail, out);
        let environments = u16::try_from(self.environments.len())
            .map_err(|_| InvalidPart("an entry lists too many environments"))?;
        out.extend_from_slice(&environments.to_be_bytes());
        for environment in &self.environments {
            put_str16(out, environment.name)?;
            match environment.kind {
                EnvironmentKind::Unchanged => out.push(0),
                EnvironmentKind::Created => out.push(1),
                EnvironmentKind::Removed => out.push(2),
                EnvironmentKind::RenamedFrom(from) => {
                    out.push(3);
                    put_str16(out, from)?;
                }
            }
            match &environment.keys {
                Keys::Count(count) => out.extend_from_slice(&count.to_be_bytes()),
                Keys::Changes(changes) => {
                    let count = u32::try_from(changes.len())
                        .map_err(|_| InvalidPart("an environment lists too many keys"))?;
                    out.extend_from_slice(&count.to_be_bytes());
                    for change in changes {
                        put_str16(out, change.key)?;
                        match change.kind {
                            KeyKind::Added => out.push(1),
                            KeyKind::Changed => out.push(2),
                            KeyKind::Removed => out.push(3),
                            KeyKind::RenamedFrom(from) => {
                                out.push(4);
                                put_str16(out, from)?;
                            }
                        }
                        put_side(out, &change.before)?;
                        put_side(out, &change.after)?;
                    }
                }
            }
        }
        Ok(())
    }

    fn validate(&self) -> Result<()> {
        if (self.action == Action::Outside) != (self.actor == Actor::Outside) {
            return Err(InvalidPart("only outside entries have the outside actor"));
        }
        if self.since.is_some() != (self.action == Action::Outside) {
            return Err(InvalidPart("only outside entries have a start time"));
        }
        if let Some(name) = self.detail.file_name
            && (name.is_empty() || name.len() > MAX_FILE_NAME_BYTES)
        {
            return Err(InvalidPart("an imported file's name is invalid"));
        }
        if let Some(Remote::Org(slug)) = self.detail.remote
            && (slug.is_empty() || slug.len() > usize::from(u16::MAX))
        {
            return Err(InvalidPart("an org slug is invalid"));
        }
        if !strictly_sorted(self.environments.iter().map(|environment| environment.name)) {
            return Err(InvalidPart("an entry's environments aren't sorted"));
        }
        for environment in &self.environments {
            match &environment.keys {
                Keys::Count(_) if !self.flags.oversized => {
                    return Err(InvalidPart("only oversized entries count keys"));
                }
                Keys::Changes(_) if self.flags.oversized => {
                    return Err(InvalidPart("oversized entries list no keys"));
                }
                Keys::Count(_) => {}
                Keys::Changes(changes) => {
                    if !strictly_sorted(changes.iter().map(|change| change.key)) {
                        return Err(InvalidPart("an environment's keys aren't sorted"));
                    }
                    for change in changes {
                        let consistent = match change.kind {
                            KeyKind::Added => {
                                change.before.is_absent() && !change.after.is_absent()
                            }
                            KeyKind::Removed => {
                                !change.before.is_absent() && change.after.is_absent()
                            }
                            KeyKind::Changed | KeyKind::RenamedFrom(_) => {
                                !change.before.is_absent() && !change.after.is_absent()
                            }
                        };
                        if !consistent {
                            return Err(InvalidPart("a key change's sides don't match its kind"));
                        }
                        if self.flags.values_not_kept
                            && (matches!(change.before, Side::Value { .. })
                                || matches!(change.after, Side::Value { .. }))
                        {
                            return Err(InvalidPart("an entry without values keeps a value"));
                        }
                    }
                }
            }
        }
        Ok(())
    }

    /// Decode one entry from exactly `bytes`.
    pub fn decode(bytes: &'a [u8]) -> Result<Self> {
        let mut reader = Reader::new(bytes);
        let seq = reader.u64()?;
        let id = reader.array::<16>()?;
        let time = reader.i64()?;
        let actor = Actor::from_byte(reader.u8()?).ok_or(InvalidPart("an unknown actor"))?;
        let action = Action::from_byte(reader.u8()?).ok_or(InvalidPart("an unknown action"))?;
        let flags = Flags::from_byte(reader.u8()?).ok_or(InvalidPart("unknown entry flags"))?;
        let since = (action == Action::Outside)
            .then(|| reader.i64())
            .transpose()?;
        let detail_bytes = usize::from(reader.u16()?);
        let detail = decode_detail(reader.bytes(detail_bytes)?)?;
        let environment_count = usize::from(reader.u16()?);
        let mut environments = Vec::with_capacity(environment_count.min(reader.remaining()));
        for _ in 0..environment_count {
            let name = reader.str16()?;
            let kind = match reader.u8()? {
                0 => EnvironmentKind::Unchanged,
                1 => EnvironmentKind::Created,
                2 => EnvironmentKind::Removed,
                3 => EnvironmentKind::RenamedFrom(reader.str16()?),
                _ => return Err(InvalidPart("an unknown environment change")),
            };
            let count = reader.u32()?;
            let keys = if flags.oversized {
                Keys::Count(count)
            } else {
                let count = count as usize;
                let mut changes = Vec::with_capacity(count.min(reader.remaining() / 5));
                for _ in 0..count {
                    let key = reader.str16()?;
                    let kind = match reader.u8()? {
                        1 => KeyKind::Added,
                        2 => KeyKind::Changed,
                        3 => KeyKind::Removed,
                        4 => KeyKind::RenamedFrom(reader.str16()?),
                        _ => return Err(InvalidPart("an unknown key change")),
                    };
                    let before = reader.side()?;
                    let after = reader.side()?;
                    changes.push(KeyChange {
                        key,
                        kind,
                        before,
                        after,
                    });
                }
                Keys::Changes(changes)
            };
            environments.push(EnvironmentChange { name, kind, keys });
        }
        reader.finish()?;
        let entry = Self {
            seq,
            id,
            time,
            actor,
            action,
            flags,
            since,
            detail,
            environments,
        };
        entry.validate()?;
        Ok(entry)
    }
}

/// The fields every entry starts with, read without decoding the rest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EntryHeader {
    pub seq: u64,
    pub id: EntryId,
    pub time: i64,
}

impl Entry<'_> {
    pub fn header(&self) -> EntryHeader {
        EntryHeader {
            seq: self.seq,
            id: self.id,
            time: self.time,
        }
    }
}

impl EntryHeader {
    pub fn of(bytes: &[u8]) -> Result<Self> {
        let mut reader = Reader::new(bytes);
        Ok(Self {
            seq: reader.u64()?,
            id: reader.array::<16>()?,
            time: reader.i64()?,
        })
    }
}

const DETAIL_FILE_NAME: u8 = 1;
const DETAIL_PASTED: u8 = 2;
const DETAIL_PERSONAL: u8 = 3;
const DETAIL_ORG: u8 = 4;
const DETAIL_REMOTE_VERSION: u8 = 5;
const DETAIL_PLATFORM: u8 = 6;
const DETAIL_RELATED_ID: u8 = 7;
const DETAIL_RELATED_SIDE: u8 = 8;
const DETAIL_RELATED_TIME: u8 = 9;

fn detail_len(detail: &Detail<'_>) -> usize {
    let field = |length: usize| 3 + length;
    detail.file_name.map_or(0, |name| field(name.len()))
        + if detail.pasted { field(0) } else { 0 }
        + match detail.remote {
            None => 0,
            Some(Remote::Personal) => field(0),
            Some(Remote::Org(slug)) => field(slug.len()),
        }
        + detail.remote_version.map_or(0, |_| field(8))
        + detail.platform.map_or(0, |_| field(1))
        + detail
            .related
            .map_or(0, |_| field(16) + field(1) + field(8))
}

fn encode_detail(detail: &Detail<'_>, out: &mut Vec<u8>) {
    let mut field = |kind: u8, bytes: &[u8]| {
        out.push(kind);
        out.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
        out.extend_from_slice(bytes);
    };
    if let Some(name) = detail.file_name {
        field(DETAIL_FILE_NAME, name.as_bytes());
    }
    if detail.pasted {
        field(DETAIL_PASTED, &[]);
    }
    match detail.remote {
        None => {}
        Some(Remote::Personal) => field(DETAIL_PERSONAL, &[]),
        Some(Remote::Org(slug)) => field(DETAIL_ORG, slug.as_bytes()),
    }
    if let Some(version) = detail.remote_version {
        field(DETAIL_REMOTE_VERSION, &version.to_be_bytes());
    }
    if let Some(platform) = detail.platform {
        field(DETAIL_PLATFORM, &[platform.byte()]);
    }
    if let Some(related) = detail.related {
        field(DETAIL_RELATED_ID, &related.id);
        field(
            DETAIL_RELATED_SIDE,
            &[match related.side {
                RelatedSide::Before => 1,
                RelatedSide::After => 2,
            }],
        );
        field(DETAIL_RELATED_TIME, &related.time.to_be_bytes());
    }
}

fn decode_detail(bytes: &[u8]) -> Result<Detail<'_>> {
    let mut reader = Reader::new(bytes);
    let mut detail = Detail::default();
    let mut last = 0_u8;
    let (mut related_id, mut related_side, mut related_time) = (None, None, None);
    while reader.remaining() > 0 {
        let kind = reader.u8()?;
        if kind <= last {
            return Err(InvalidPart("an entry's detail isn't in order"));
        }
        last = kind;
        let length = usize::from(reader.u16()?);
        let value = reader.bytes(length)?;
        let fixed = |expected: usize| {
            (value.len() == expected)
                .then_some(())
                .ok_or(InvalidPart("an entry's detail has the wrong length"))
        };
        match kind {
            DETAIL_FILE_NAME => {
                let name = std::str::from_utf8(value)
                    .map_err(|_| InvalidPart("a file name isn't UTF-8"))?;
                if name.is_empty() || name.len() > MAX_FILE_NAME_BYTES {
                    return Err(InvalidPart("an imported file's name is invalid"));
                }
                detail.file_name = Some(name);
            }
            DETAIL_PASTED => {
                fixed(0)?;
                detail.pasted = true;
            }
            DETAIL_PERSONAL => {
                fixed(0)?;
                detail.remote = Some(Remote::Personal);
            }
            DETAIL_ORG => {
                if detail.remote.is_some() || value.is_empty() {
                    return Err(InvalidPart("a pull names two remotes"));
                }
                detail.remote = Some(Remote::Org(
                    std::str::from_utf8(value)
                        .map_err(|_| InvalidPart("an org slug isn't UTF-8"))?,
                ));
            }
            DETAIL_REMOTE_VERSION => {
                fixed(8)?;
                detail.remote_version = Some(u64::from_be_bytes(value.try_into().expect("eight")));
            }
            DETAIL_PLATFORM => {
                fixed(1)?;
                detail.platform =
                    Some(Platform::from_byte(value[0]).ok_or(InvalidPart("an unknown platform"))?);
            }
            DETAIL_RELATED_ID => {
                fixed(16)?;
                related_id = Some(value.try_into().expect("sixteen"));
            }
            DETAIL_RELATED_SIDE => {
                fixed(1)?;
                related_side = Some(match value[0] {
                    1 => RelatedSide::Before,
                    2 => RelatedSide::After,
                    _ => return Err(InvalidPart("an unknown related side")),
                });
            }
            DETAIL_RELATED_TIME => {
                fixed(8)?;
                related_time = Some(i64::from_be_bytes(value.try_into().expect("eight")));
            }
            _ => return Err(InvalidPart("an unknown detail")),
        }
    }
    detail.related = match (related_id, related_side, related_time) {
        (Some(id), Some(side), Some(time)) => Some(Related { id, side, time }),
        (None, None, None) => None,
        _ => return Err(InvalidPart("a related entry is incomplete")),
    };
    Ok(detail)
}

/// A summary slot: a value's digest, or a value removed from history.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Slot {
    Digest(Digest),
    Removed,
}

/// The project's state after a part's last entry: every environment and
/// key, with each value's digest.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Summary<'a> {
    pub environments: BTreeMap<&'a str, BTreeMap<&'a str, Slot>>,
}

impl Summary<'_> {
    pub fn encoded_len(&self) -> usize {
        2 + self
            .environments
            .iter()
            .map(|(name, keys)| {
                2 + name.len()
                    + 4
                    + keys
                        .iter()
                        .map(|(key, slot)| {
                            2 + key.len()
                                + 1
                                + match slot {
                                    Slot::Digest(_) => 16,
                                    Slot::Removed => 0,
                                }
                        })
                        .sum::<usize>()
            })
            .sum::<usize>()
    }

    fn encode_into(&self, out: &mut Vec<u8>) -> Result<()> {
        let environments = u16::try_from(self.environments.len())
            .map_err(|_| InvalidPart("the summary lists too many environments"))?;
        out.extend_from_slice(&environments.to_be_bytes());
        for (name, keys) in &self.environments {
            put_str16(out, name)?;
            let count = u32::try_from(keys.len())
                .map_err(|_| InvalidPart("the summary lists too many keys"))?;
            out.extend_from_slice(&count.to_be_bytes());
            for (key, slot) in keys {
                put_str16(out, key)?;
                match slot {
                    Slot::Digest(digest) => {
                        out.push(1);
                        out.extend_from_slice(digest);
                    }
                    Slot::Removed => out.push(2),
                }
            }
        }
        Ok(())
    }

    /// Whether every name fits a `str16`, which the summary needs to be
    /// written at all.
    pub fn is_encodable(&self) -> bool {
        self.environments.len() <= usize::from(u16::MAX)
            && self
                .environments
                .iter()
                .all(|(name, keys)| fits_str16(name) && keys.keys().all(|key| fits_str16(key)))
    }
}

/// A decoded part, borrowing from the plaintext. Each entry is decoded
/// once, when the part is checked, and kept with its encoded bytes, which
/// an append copies into the next part unchanged. Its `Debug` shows counts
/// only: entries hold values.
#[derive(Clone, PartialEq, Eq)]
pub struct Part<'a> {
    pub epoch: u64,
    pub summary: Summary<'a>,
    pub entries: Vec<&'a [u8]>,
    decoded: Vec<Entry<'a>>,
}

/// The bytes of a part with `summary` and entries of the given lengths.
pub fn part_len(summary_len: usize, entry_lens: impl IntoIterator<Item = usize>) -> usize {
    PART_HEADER_BYTES
        + summary_len
        + 4
        + entry_lens
            .into_iter()
            .map(|length| 4 + length)
            .sum::<usize>()
}

impl fmt::Debug for Part<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Part")
            .field("epoch", &self.epoch)
            .field("environments", &self.summary.environments.len())
            .field("entries", &self.entries.len())
            .finish()
    }
}

impl<'a> Part<'a> {
    /// Decode a part's plaintext, checking every entry.
    pub fn decode(bytes: &'a [u8]) -> Result<Self> {
        crate::work::note(crate::work::Work::PartDecode);
        if bytes.len() > PART_CAPACITY {
            return Err(InvalidPart("the part is larger than its capacity"));
        }
        let mut reader = Reader::new(bytes);
        if reader.array::<4>()? != PART_MAGIC {
            return Err(InvalidPart("the part isn't a history part"));
        }
        if reader.u8()? != PART_VERSION {
            return Err(InvalidPart("the part's version is unknown"));
        }
        let epoch = reader.u64()?;
        let mut summary = Summary::default();
        let environment_count = reader.u16()?;
        let mut last_environment: Option<&str> = None;
        for _ in 0..environment_count {
            let name = reader.str16()?;
            if last_environment.is_some_and(|last| last >= name) {
                return Err(InvalidPart("the summary's environments aren't sorted"));
            }
            last_environment = Some(name);
            let key_count = reader.u32()?;
            let mut keys = BTreeMap::new();
            let mut last_key: Option<&str> = None;
            for _ in 0..key_count {
                let key = reader.str16()?;
                if last_key.is_some_and(|last| last >= key) {
                    return Err(InvalidPart("the summary's keys aren't sorted"));
                }
                last_key = Some(key);
                let slot = match reader.u8()? {
                    1 => Slot::Digest(reader.array::<16>()?),
                    2 => Slot::Removed,
                    _ => return Err(InvalidPart("an unknown summary slot")),
                };
                keys.insert(key, slot);
            }
            summary.environments.insert(name, keys);
        }
        let entry_count = reader.u32()? as usize;
        let capacity = entry_count.min(reader.remaining() / 4);
        let mut entries = Vec::with_capacity(capacity);
        let mut decoded: Vec<Entry<'a>> = Vec::with_capacity(capacity);
        for _ in 0..entry_count {
            let length = reader.u32()? as usize;
            let bytes = reader.bytes(length)?;
            let entry = Entry::decode(bytes)?;
            if decoded.last().is_some_and(|last| last.seq >= entry.seq) {
                return Err(InvalidPart("the part's entries aren't in sequence"));
            }
            entries.push(bytes);
            decoded.push(entry);
        }
        reader.finish()?;
        Ok(Self {
            epoch,
            summary,
            entries,
            decoded,
        })
    }

    /// The decoded entries, oldest first.
    pub fn decoded_entries(&self) -> std::slice::Iter<'_, Entry<'a>> {
        self.decoded.iter()
    }

    pub fn last_header(&self) -> Option<EntryHeader> {
        self.decoded.last().map(Entry::header)
    }

    pub fn contains_id(&self, id: &EntryId) -> bool {
        self.decoded.iter().any(|entry| entry.id == *id)
    }
}

/// Encode a part whose entries are already-encoded `existing` followed by
/// `new` ones. The buffer is sized exactly and wiped when dropped.
pub fn encode_part(
    epoch: u64,
    summary: &Summary<'_>,
    existing: &[&[u8]],
    new: &[Entry<'_>],
) -> Result<Zeroizing<Vec<u8>>> {
    let length = part_len(
        summary.encoded_len(),
        existing
            .iter()
            .map(|bytes| bytes.len())
            .chain(new.iter().map(Entry::encoded_len)),
    );
    if length > PART_CAPACITY {
        return Err(InvalidPart("the part is larger than its capacity"));
    }
    let mut out = Zeroizing::new(Vec::with_capacity(length));
    out.extend_from_slice(&PART_MAGIC);
    out.push(PART_VERSION);
    out.extend_from_slice(&epoch.to_be_bytes());
    summary.encode_into(&mut out)?;
    let count = u32::try_from(existing.len() + new.len())
        .map_err(|_| InvalidPart("the part holds too many entries"))?;
    out.extend_from_slice(&count.to_be_bytes());
    for bytes in existing {
        out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
        out.extend_from_slice(bytes);
    }
    for entry in new {
        out.extend_from_slice(&(entry.encoded_len() as u32).to_be_bytes());
        entry.encode_into(&mut out)?;
    }
    debug_assert_eq!(out.len(), length);
    Ok(out)
}

fn strictly_sorted<'a>(names: impl Iterator<Item = &'a str>) -> bool {
    let mut last: Option<&str> = None;
    for name in names {
        if last.is_some_and(|last| last >= name) {
            return false;
        }
        last = Some(name);
    }
    true
}

pub fn fits_str16(text: &str) -> bool {
    !text.is_empty() && text.len() <= usize::from(u16::MAX)
}

fn put_str16(out: &mut Vec<u8>, text: &str) -> Result<()> {
    if !fits_str16(text) {
        return Err(InvalidPart("a name is empty or too long"));
    }
    out.extend_from_slice(&(text.len() as u16).to_be_bytes());
    out.extend_from_slice(text.as_bytes());
    Ok(())
}

fn put_side(out: &mut Vec<u8>, side: &Side<'_>) -> Result<()> {
    match side {
        Side::Absent => out.push(0),
        Side::Value { value, digest } => {
            out.push(1);
            let length =
                u32::try_from(value.len()).map_err(|_| InvalidPart("a value is too large"))?;
            out.extend_from_slice(&length.to_be_bytes());
            out.extend_from_slice(value.as_bytes());
            out.extend_from_slice(digest);
        }
        Side::DigestOnly { digest, reason } => {
            out.push(2);
            out.extend_from_slice(digest);
            out.push(match reason {
                Unkept::TooLarge => 1,
                Unkept::NotRecorded => 2,
            });
        }
        Side::Removed => out.push(3),
    }
    Ok(())
}

struct Reader<'a> {
    bytes: &'a [u8],
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }

    fn remaining(&self) -> usize {
        self.bytes.len()
    }

    fn bytes(&mut self, length: usize) -> Result<&'a [u8]> {
        if length > self.bytes.len() {
            return Err(InvalidPart("a length runs past the end"));
        }
        let (taken, rest) = self.bytes.split_at(length);
        self.bytes = rest;
        Ok(taken)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        Ok(self.bytes(N)?.try_into().expect("N bytes"))
    }

    fn u8(&mut self) -> Result<u8> {
        Ok(self.array::<1>()?[0])
    }

    fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    fn i64(&mut self) -> Result<i64> {
        Ok(i64::from_be_bytes(self.array()?))
    }

    fn str16(&mut self) -> Result<&'a str> {
        let length = usize::from(self.u16()?);
        if length == 0 {
            return Err(InvalidPart("a name is empty"));
        }
        std::str::from_utf8(self.bytes(length)?).map_err(|_| InvalidPart("a name isn't UTF-8"))
    }

    fn side(&mut self) -> Result<Side<'a>> {
        Ok(match self.u8()? {
            0 => Side::Absent,
            1 => {
                let length = self.u32()? as usize;
                let value = std::str::from_utf8(self.bytes(length)?)
                    .map_err(|_| InvalidPart("a value isn't UTF-8"))?;
                Side::Value {
                    value,
                    digest: self.array()?,
                }
            }
            2 => Side::DigestOnly {
                digest: self.array()?,
                reason: match self.u8()? {
                    1 => Unkept::TooLarge,
                    2 => Unkept::NotRecorded,
                    _ => return Err(InvalidPart("an unknown reason")),
                },
            },
            3 => Side::Removed,
            _ => return Err(InvalidPart("an unknown side")),
        })
    }

    fn finish(&self) -> Result<()> {
        if self.bytes.is_empty() {
            Ok(())
        } else {
            Err(InvalidPart("trailing bytes"))
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn digest(byte: u8) -> Digest {
        [byte; 16]
    }

    pub(crate) fn sample_entry(seq: u64) -> Entry<'static> {
        Entry {
            seq,
            id: [seq as u8; 16],
            time: 1_762_000_000_000 + seq as i64,
            actor: Actor::App,
            action: Action::Pull,
            flags: Flags::default(),
            since: None,
            detail: Detail {
                remote: Some(Remote::Org("acme")),
                remote_version: Some(14),
                ..Detail::default()
            },
            environments: vec![
                EnvironmentChange {
                    name: "production",
                    kind: EnvironmentKind::Unchanged,
                    keys: Keys::Changes(vec![
                        KeyChange {
                            key: "API_KEY",
                            kind: KeyKind::Changed,
                            before: Side::Value {
                                value: "old",
                                digest: digest(1),
                            },
                            after: Side::Value {
                                value: "new",
                                digest: digest(2),
                            },
                        },
                        KeyChange {
                            key: "DB_URL",
                            kind: KeyKind::Changed,
                            before: Side::DigestOnly {
                                digest: digest(3),
                                reason: Unkept::NotRecorded,
                            },
                            after: Side::Value {
                                value: "postgres://",
                                digest: digest(4),
                            },
                        },
                    ]),
                },
                EnvironmentChange {
                    name: "staging",
                    kind: EnvironmentKind::RenamedFrom("stage"),
                    keys: Keys::Changes(vec![KeyChange {
                        key: "FLAGS",
                        kind: KeyKind::Added,
                        before: Side::Absent,
                        after: Side::Value {
                            value: "{}",
                            digest: digest(5),
                        },
                    }]),
                },
            ],
        }
    }

    fn encode(entry: &Entry<'_>) -> Vec<u8> {
        let mut out = Vec::new();
        entry.encode_into(&mut out).expect("encode");
        assert_eq!(out.len(), entry.encoded_len());
        out
    }

    #[test]
    fn entries_round_trip_with_every_detail_and_side() {
        let mut entry = sample_entry(9);
        entry.detail = Detail {
            file_name: Some(".env.local"),
            pasted: true,
            remote: Some(Remote::Org("acme")),
            remote_version: Some(u64::MAX),
            platform: Some(Platform::GithubActions),
            related: Some(Related {
                id: [7; 16],
                side: RelatedSide::After,
                time: -5,
            }),
        };
        if let Keys::Changes(changes) = &mut entry.environments[0].keys {
            changes[1].after = Side::Removed;
            changes.push(KeyChange {
                key: "OLD",
                kind: KeyKind::RenamedFrom("OLDER"),
                before: Side::DigestOnly {
                    digest: digest(8),
                    reason: Unkept::TooLarge,
                },
                after: Side::Removed,
            });
        }
        let bytes = encode(&entry);
        assert_eq!(Entry::decode(&bytes), Ok(entry.clone()));
        assert_eq!(
            EntryHeader::of(&bytes),
            Ok(EntryHeader {
                seq: 9,
                id: [9; 16],
                time: entry.time
            })
        );

        let outside = Entry {
            actor: Actor::Outside,
            action: Action::Outside,
            since: Some(1_000),
            detail: Detail::default(),
            ..sample_entry(10)
        };
        assert_eq!(Entry::decode(&encode(&outside)), Ok(outside));
    }

    #[test]
    fn entries_without_values_and_oversized_entries_round_trip() {
        let entry = sample_entry(3);
        let without = entry.without_values();
        assert!(without.flags.values_not_kept);
        assert!(without.encoded_len() < entry.encoded_len());
        assert_eq!(Entry::decode(&encode(&without)), Ok(without.clone()));
        let Keys::Changes(changes) = &without.environments[0].keys else {
            panic!("changes");
        };
        assert_eq!(
            changes[0].before,
            Side::DigestOnly {
                digest: digest(1),
                reason: Unkept::TooLarge
            }
        );

        let oversized = entry.oversized();
        assert_eq!(oversized.key_count(), 3);
        assert_eq!(oversized.environments[0].keys, Keys::Count(2));
        assert_eq!(Entry::decode(&encode(&oversized)), Ok(oversized));
    }

    #[test]
    fn entry_decoding_refuses_trailing_truncated_unsorted_and_inconsistent_bytes() {
        let bytes = encode(&sample_entry(1));
        assert!(Entry::decode(&[bytes.as_slice(), &[0]].concat()).is_err());
        for length in 0..bytes.len() {
            assert!(
                Entry::decode(&bytes[..length]).is_err(),
                "truncated at {length}"
            );
        }

        let mut unsorted = sample_entry(1);
        unsorted.environments.swap(0, 1);
        assert!(unsorted.encode_into(&mut Vec::new()).is_err());

        let mut repeated = sample_entry(1);
        let first = repeated.environments[0].clone();
        repeated.environments.insert(0, first);
        assert!(repeated.encode_into(&mut Vec::new()).is_err());

        let mut inconsistent = sample_entry(1);
        if let Keys::Changes(changes) = &mut inconsistent.environments[1].keys {
            changes[0].before = Side::Removed;
        }
        assert!(
            inconsistent.encode_into(&mut Vec::new()).is_err(),
            "added with a before"
        );

        let mut kept = sample_entry(1);
        kept.flags.values_not_kept = true;
        assert!(
            kept.encode_into(&mut Vec::new()).is_err(),
            "values not kept but kept"
        );

        let mut sinceless = sample_entry(1);
        sinceless.actor = Actor::Outside;
        sinceless.action = Action::Outside;
        assert!(sinceless.encode_into(&mut Vec::new()).is_err());

        let mut long_name = sample_entry(1);
        let name = "f".repeat(256);
        long_name.detail.file_name = Some(&name);
        assert!(long_name.encode_into(&mut Vec::new()).is_err());

        // An unknown action, actor, flag or side byte.
        for (at, value) in [(32, 0), (32, 4), (33, 0), (33, 21), (34, 8)] {
            let mut changed = bytes.clone();
            changed[at] = value;
            assert!(Entry::decode(&changed).is_err(), "byte {at} = {value}");
        }
    }

    #[test]
    fn detail_fields_must_be_ordered_complete_and_known() {
        let decode = |fields: &[(u8, &[u8])]| {
            let mut bytes = Vec::new();
            for (kind, value) in fields {
                bytes.push(*kind);
                bytes.extend_from_slice(&(value.len() as u16).to_be_bytes());
                bytes.extend_from_slice(value);
            }
            decode_detail(&bytes).map(|detail| format!("{detail:?}"))
        };
        assert!(decode(&[(DETAIL_PASTED, &[]), (DETAIL_FILE_NAME, b"a")]).is_err());
        assert!(decode(&[(DETAIL_PASTED, &[]), (DETAIL_PASTED, &[])]).is_err());
        assert!(decode(&[(DETAIL_PERSONAL, &[]), (DETAIL_ORG, b"acme")]).is_err());
        assert!(decode(&[(DETAIL_RELATED_ID, &[0; 16])]).is_err());
        assert!(decode(&[(DETAIL_PLATFORM, &[6])]).is_err());
        assert!(decode(&[(10, &[])]).is_err());
        assert!(decode(&[(DETAIL_REMOTE_VERSION, &[0; 7])]).is_err());
        assert!(decode(&[(DETAIL_PERSONAL, &[]), (DETAIL_REMOTE_VERSION, &[0; 8])]).is_ok());
    }

    fn summary() -> Summary<'static> {
        let mut summary = Summary::default();
        summary.environments.insert(
            "production",
            BTreeMap::from([("API_KEY", Slot::Digest(digest(1))), ("OLD", Slot::Removed)]),
        );
        summary.environments.insert("staging", BTreeMap::new());
        summary
    }

    #[test]
    fn parts_round_trip_and_keep_entries_encoded() {
        let entries = [sample_entry(4), sample_entry(5)];
        let first = encode(&entries[0]);
        let bytes = encode_part(3, &summary(), &[&first], &entries[1..]).expect("part");
        assert_eq!(bytes.len(), bytes.capacity());
        let part = Part::decode(&bytes).expect("decode");
        assert_eq!(part.epoch, 3);
        assert_eq!(part.summary, summary());
        assert_eq!(part.entries.len(), 2);
        assert_eq!(
            part.decoded_entries().cloned().collect::<Vec<_>>(),
            entries.to_vec()
        );
        assert!(part.contains_id(&[5; 16]));
        assert!(!part.contains_id(&[6; 16]));
        assert_eq!(part.last_header().map(|header| header.seq), Some(5));
        assert_eq!(
            bytes.len(),
            part_len(
                summary().encoded_len(),
                entries.iter().map(Entry::encoded_len)
            )
        );
    }

    #[test]
    fn part_decoding_refuses_bad_order_versions_and_trailing_bytes() {
        let ordered =
            encode_part(1, &summary(), &[], &[sample_entry(2), sample_entry(3)]).expect("part");
        assert!(Part::decode(&[ordered.as_slice(), &[0]].concat()).is_err());
        let mut version = ordered.to_vec();
        version[4] = 2;
        assert!(Part::decode(&version).is_err());
        let out_of_order =
            encode_part(1, &summary(), &[], &[sample_entry(3), sample_entry(2)]).expect("encodes");
        assert!(Part::decode(&out_of_order).is_err(), "sequence must rise");
        let repeated =
            encode_part(1, &summary(), &[], &[sample_entry(3), sample_entry(3)]).expect("encodes");
        assert!(Part::decode(&repeated).is_err());
        for length in 0..ordered.len() {
            assert!(
                Part::decode(&ordered[..length]).is_err(),
                "truncated at {length}"
            );
        }
    }

    #[test]
    fn a_part_over_capacity_is_refused_and_one_at_capacity_is_not() {
        let empty = Summary::default();
        let fixed = part_len(empty.encoded_len(), [0]) - 4;
        let mut entry = sample_entry(1);
        entry.environments.truncate(1);
        let value_room = PART_CAPACITY - fixed - (entry.encoded_len() + 4) + "old".len();
        let value = "v".repeat(value_room);
        if let Keys::Changes(changes) = &mut entry.environments[0].keys {
            changes[0].before = Side::Value {
                value: &value,
                digest: digest(1),
            };
        }
        let full = encode_part(1, &empty, &[], std::slice::from_ref(&entry)).expect("at capacity");
        assert_eq!(full.len(), PART_CAPACITY);
        assert!(Part::decode(&full).is_ok());
        let longer = format!("{value}v");
        if let Keys::Changes(changes) = &mut entry.environments[0].keys {
            changes[0].before = Side::Value {
                value: &longer,
                digest: digest(1),
            };
        }
        assert!(encode_part(1, &empty, &[], &[entry]).is_err());
    }

    #[test]
    fn every_action_has_a_byte_and_a_name() {
        for action in Action::ALL {
            assert_eq!(Action::from_byte(action.byte()), Some(action));
            assert!(!action.name().is_empty());
        }
        assert_eq!(Action::from_byte(0), None);
        assert_eq!(Action::from_byte(21), None);
        assert_eq!(Action::Set.byte(), 1);
        assert_eq!(Action::Outside.byte(), 20);
        for name in ["vercel", "coolify", "fly", "railway", "github-actions"] {
            let platform = Platform::from_name(name).expect(name);
            assert_eq!(Platform::from_byte(platform.byte()), Some(platform));
        }
    }

    #[test]
    fn debug_output_never_shows_values() {
        let entry = sample_entry(1);
        let debug = format!("{entry:?}");
        assert!(!debug.contains("postgres://"), "{debug}");
        assert!(!debug.contains("\"old\""), "{debug}");
    }

    #[test]
    fn a_part_s_debug_shows_no_entry_bytes() {
        let entry = Entry {
            seq: 1,
            id: [7; 16],
            time: 0,
            actor: Actor::Cli,
            action: Action::Set,
            flags: Flags::default(),
            since: None,
            detail: Detail::default(),
            environments: vec![EnvironmentChange {
                name: "e",
                kind: EnvironmentKind::Unchanged,
                keys: Keys::Changes(vec![KeyChange {
                    key: "K",
                    kind: KeyKind::Added,
                    before: Side::Absent,
                    after: Side::Value {
                        value: "plaintext-sentinel",
                        digest: [1; 16],
                    },
                }]),
            }],
        };
        let bytes = encode_part(1, &Summary::default(), &[], &[entry]).expect("part");
        let part = Part::decode(&bytes).expect("decodes");
        let shown = format!("{part:?}");
        assert!(!shown.contains("plaintext"), "{shown}");
        let sentinel: Vec<String> = b"plaintext-sentinel".iter().map(u8::to_string).collect();
        assert!(!shown.contains(&sentinel[..4].join(", ")), "{shown}");
    }
}
