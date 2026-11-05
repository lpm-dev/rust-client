//! Local history: an encrypted record, kept on this Mac, of how a project's
//! values changed, so a person can see and roll back those changes.
//!
//! Everything here is pure. Plans take the bytes a client read inside its
//! lock and return what to write; each client's executor writes it.

pub mod admission;
pub mod append;
pub mod codec;
pub mod read;
pub mod rebuild;
pub mod removal;
pub mod switch;
pub mod values;

#[cfg(test)]
mod fixtures;
#[cfg(test)]
pub(crate) mod test_support;

use std::fmt;

use zeroize::Zeroizing;

use crate::account::CompanionAccount;
use crate::append_log::HISTORY;
use crate::graph::SHARED_KEY_KIND;
use crate::keyring::PartIdentity;
use crate::marker::{FeatureEntry, FeatureState, Level};

/// The feature whose records hold history.
pub const FEATURE: &str = "history";
/// The feature whose entry, with no records, says history is off.
pub const OFF_FEATURE: &str = "history-off";
pub const VERSION: u16 = 1;

/// The marker entry for history v1.
pub fn feature_entry() -> FeatureEntry {
    FeatureEntry {
        version: VERSION,
        if_unsupported: Level::Ignore,
        kinds: vec![
            HISTORY.head_kind.to_owned(),
            HISTORY.kind.to_owned(),
            SHARED_KEY_KIND.to_owned(),
        ],
        state: FeatureState::Active,
    }
}

/// The marker entry that keeps history off.
pub fn off_entry() -> FeatureEntry {
    FeatureEntry {
        version: 1,
        if_unsupported: Level::Ignore,
        kinds: vec![OFF_FEATURE.to_owned()],
        state: FeatureState::Active,
    }
}

pub fn key_account(vault_id: &str) -> CompanionAccount {
    CompanionAccount::Record {
        kind: SHARED_KEY_KIND.to_owned(),
        vault_id: vault_id.to_owned(),
        part: None,
    }
}

pub fn head_account(vault_id: &str) -> CompanionAccount {
    CompanionAccount::Record {
        kind: HISTORY.head_kind.to_owned(),
        vault_id: vault_id.to_owned(),
        part: None,
    }
}

pub fn part_account(vault_id: &str, part: u16) -> CompanionAccount {
    CompanionAccount::Record {
        kind: HISTORY.kind.to_owned(),
        vault_id: vault_id.to_owned(),
        part: Some(part),
    }
}

/// What a history part's associated data binds it to.
pub fn part_identity(vault_id: &str, part: u16) -> PartIdentity<'_> {
    PartIdentity {
        vault_id,
        kind: HISTORY.kind,
        part,
        schema_version: HISTORY.schema_version,
    }
}

/// One record a plan writes. The key record's bytes are secret, so every
/// write is held in a buffer that's wiped when dropped.
pub struct RecordWrite {
    pub account: CompanionAccount,
    pub bytes: Zeroizing<Vec<u8>>,
}

impl RecordWrite {
    pub fn new(account: CompanionAccount, bytes: Vec<u8>) -> Self {
        Self {
            account,
            bytes: Zeroizing::new(bytes),
        }
    }
}

impl fmt::Debug for RecordWrite {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecordWrite")
            .field("account", &self.account.name())
            .field("bytes", &self.bytes.len())
            .finish()
    }
}
