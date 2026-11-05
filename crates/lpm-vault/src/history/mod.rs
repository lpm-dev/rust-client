//! Local history in the CLI: every values write records the net change its
//! lock scope made, and history can be read, rolled back, removed from and
//! switched off.
//!
//! The rules live in `lpm-env-companion`; this module captures what each
//! operation read and wrote, and runs the engine's plans against the
//! Keychain or the file store.

pub(crate) mod record;
pub(crate) mod scope;
pub(crate) mod store;

use std::cell::RefCell;
use std::fmt;

pub use lpm_env_companion::history::codec::{Action, Actor, Platform, RelatedSide};
use lpm_env_companion::history::codec::{Detail, Related, Remote};
use lpm_env_companion::history::values::Values;
use lpm_env_companion::keyring::{Random as _, SystemRandom};

use crate::EnvironmentMap;
use crate::storage_transaction::VaultStorageDirectory;

/// Run `$body` with the history store of the store that holds companion
/// records: the Keychain on macOS, the file store elsewhere.
macro_rules! with_history_store {
    ($directory:expr, |$store:ident| $body:expr) => {{
        #[cfg(target_os = "macos")]
        let result = if crate::force_file_vault_backend() {
            crate::fallback::companion::history_store($directory, |$store| $body)
        } else {
            let _ = $directory;
            crate::keychain::history_store(|$store| $body)
        };
        #[cfg(not(target_os = "macos"))]
        let result = crate::fallback::companion::history_store($directory, |$store| $body);
        result
    }};
}

mod api;

pub use api::{
    ChosenValue, EnvironmentName, HistoryError, HistoryState, HistoryStatus, Listing, Paused,
    RollbackRequest, Shown, commit_rollback, forget, review_forget, review_rollback, show, status,
    timeline, turn_off, turn_on,
};
pub use lpm_env_companion::history::codec::Flags;
pub use lpm_env_companion::history::read::{
    DetailInfo, EntryInfo, EntryLookup, EnvironmentInfo, EnvironmentKindInfo, Filter, KeyInfo,
    KeyKindInfo, KeyMatch, KeysInfo, LiveGap, RemoteInfo, RevealedEntry, RevealedValues, SideInfo,
    SourceGroup, Timeline, TimelineRow,
};
pub use lpm_env_companion::history::rebuild::{
    Binding, Choices, EnvironmentPlan, Gap, Point, Pulled, RemoteName, RollbackKind, RollbackPlan,
    Row, TargetValue, UnknownReason,
};
pub use lpm_env_companion::history::removal::{Occurrence, Place, PlaceGroup, RemovalReview};
/// The wiped buffer past values come back in.
pub use zeroize::Zeroizing;

/// Where a pull came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RemoteSource {
    Personal,
    Org(String),
}

/// What an action names besides its changes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SourceDetail {
    /// An imported file's base name.
    pub file_name: Option<String>,
    pub remote: Option<RemoteSource>,
    pub remote_version: Option<u64>,
    pub platform: Option<Platform>,
    /// The entry a rollback went back to, which side of it, and its time.
    pub related: Option<([u8; 16], RelatedSide, i64)>,
}

impl SourceDetail {
    pub(crate) fn borrowed(&self) -> Detail<'_> {
        Detail {
            file_name: self.file_name.as_deref(),
            pasted: false,
            remote: self.remote.as_ref().map(|remote| match remote {
                RemoteSource::Personal => Remote::Personal,
                RemoteSource::Org(slug) => Remote::Org(slug),
            }),
            remote_version: self.remote_version,
            platform: self.platform,
            related: self
                .related
                .map(|(id, side, time)| Related { id, side, time }),
        }
    }
}

/// Who changed values and how. Every API that writes values takes one, and
/// one user action makes one, so a retry of the same action is recorded
/// once.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Source {
    pub(crate) id: [u8; 16],
    pub(crate) action: Action,
    pub(crate) detail: SourceDetail,
}

impl Source {
    pub fn new(action: Action) -> Self {
        Self::with_detail(action, SourceDetail::default())
    }

    pub fn with_detail(action: Action, detail: SourceDetail) -> Self {
        let mut id = [0_u8; 16];
        if SystemRandom.fill(&mut id).is_err() {
            // Without randomness the entry still records; only a retry's
            // deduplication relies on the ID.
            id[..8].copy_from_slice(&record::now_ms().to_be_bytes());
        }
        Self { id, action, detail }
    }

    pub fn action(&self) -> Action {
        self.action
    }
}

/// Why a change wasn't added to history. The values write it followed
/// succeeded regardless.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NotRecorded {
    Damaged,
    /// The Mac holds too much LPM data to start history for this project.
    Limit,
    TooManyValues,
    /// A newer LPM keeps this project's history, or is removing it.
    NewerVersion,
    /// The Keychain couldn't confirm the values item's approval.
    Unavailable,
    Failed(String),
}

impl NotRecorded {
    /// The stable code JSON output uses.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Damaged => "damaged",
            Self::Limit => "limit",
            Self::TooManyValues => "too_many_values",
            Self::NewerVersion => "newer_version",
            Self::Unavailable => "unavailable",
            Self::Failed(_) => "storage",
        }
    }
}

impl fmt::Display for NotRecorded {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Damaged => {
                formatter.write_str("local history is damaged; repair it with lpm env repair")
            }
            Self::Limit => formatter
                .write_str("this Mac holds too much LPM data to keep history for this env project"),
            Self::TooManyValues => {
                formatter.write_str("this env project has too many values to keep history")
            }
            Self::NewerVersion => {
                formatter.write_str("a newer LPM keeps this env project's history")
            }
            Self::Unavailable => formatter.write_str("the Keychain is unavailable"),
            Self::Failed(error) => formatter.write_str(error),
        }
    }
}

/// What happened to history after one values write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    Recorded {
        /// The service's record count when it's past the target, so history
        /// keeps less for each project.
        crowded: Option<usize>,
        /// Whether a change made outside history was recorded first.
        gap: bool,
    },
    /// Nothing to record: the values didn't change, or no key changed
    /// before history existed.
    Nothing,
    Off,
    NotRecorded(NotRecorded),
}

/// One project's outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Recorded {
    pub vault_id: String,
    pub outcome: Outcome,
}

thread_local! {
    static OUTCOMES: RefCell<Vec<Recorded>> = const { RefCell::new(Vec::new()) };
}

/// What history did after the values writes this thread made since the last
/// call, oldest first.
pub fn take_outcomes() -> Vec<Recorded> {
    OUTCOMES.with_borrow_mut(std::mem::take)
}

/// Record every change the outermost lock scope made, still inside it.
pub(crate) fn finish_scope(directory: &VaultStorageDirectory) {
    for (vault_id, tracked) in scope::leave() {
        if tracked.after.is_none() {
            continue;
        }
        let outcome = with_history_store!(directory, |store| record::record(
            store, &vault_id, &tracked
        ))
        .unwrap_or_else(|error| Outcome::NotRecorded(NotRecorded::Failed(error)));
        OUTCOMES.with_borrow_mut(|outcomes| outcomes.push(Recorded { vault_id, outcome }));
    }
}

/// Zero every value of `environments` in place, for copies history made.
pub(crate) fn wipe_values(environments: &mut EnvironmentMap) {
    use zeroize::Zeroize as _;
    for values in environments.values_mut() {
        for value in values.values_mut() {
            value.zeroize();
        }
    }
}

/// A project's values as history sees them.
pub(crate) fn values_of(environments: &EnvironmentMap) -> Values<'_> {
    Values::from_environments(environments.iter().map(|(name, keys)| {
        (
            name.as_str(),
            keys.iter()
                .map(|(key, value)| (key.as_str(), value.as_str())),
        )
    }))
}

#[cfg(test)]
mod tests;
