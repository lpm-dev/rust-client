//! What history needs from a store of companion records, beyond the
//! journal transactions and names-only inventory every companion store has.

use std::collections::HashSet;

use zeroize::Zeroizing;

use crate::companion::account::CompanionAccount;
use crate::companion::{Checked, CompanionBackend};
use lpm_env_companion::history::admission::Ring;
use lpm_env_companion::keyring::Approval;

/// What admission counts, from one names-only inventory.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct AdmissionInventory {
    /// Companion and staged records in the service, markers excluded.
    pub(crate) count: usize,
    /// The history rings this client can name, for trims.
    pub(crate) rings: Vec<Ring>,
    /// The rings' projects whose records this client can write without
    /// asking for approval, which trimming another project's history
    /// needs. Known from the same listing, with no read per project.
    pub(crate) trimmable: HashSet<String>,
}

/// Why a record that follows values couldn't be used.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RecordError {
    /// The store holds it, but its content or access is damaged: Repair
    /// removes history.
    Damaged(String),
    /// The store failed; trying again may work.
    Store(String),
}

impl std::fmt::Display for RecordError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Damaged(reason) | Self::Store(reason) => formatter.write_str(reason),
        }
    }
}

impl From<String> for RecordError {
    fn from(error: String) -> Self {
        Self::Store(error)
    }
}

/// One history part's sealed bytes. A part whose content the store can't
/// read comes back empty, so it reads as an unreadable part, as one that
/// won't open does.
pub(crate) fn read_part(
    store: &mut impl HistoryStore,
    vault_id: &str,
    part: u16,
) -> Result<Option<Vec<u8>>, String> {
    Ok(
        match store.read_checked(&lpm_env_companion::history::part_account(vault_id, part))? {
            Checked::Present(mut sealed) => Some(std::mem::take(&mut *sealed)),
            Checked::Absent => None,
            Checked::Unreadable(_) => Some(Vec::new()),
        },
    )
}

pub(crate) trait HistoryStore: CompanionBackend {
    /// A record that follows values (the head or the key), read with its
    /// access: one that claims less than the values item requires is
    /// strengthened, and verified, before its bytes are used.
    fn read_following_values(
        &mut self,
        account: &CompanionAccount,
    ) -> Result<Option<Zeroizing<Vec<u8>>>, RecordError>;

    /// Replace one record outside the journal, verified, with the access its
    /// kind takes: the values item's for records that follow values.
    fn replace(&mut self, account: &CompanionAccount, bytes: &[u8]) -> Result<(), String>;

    /// Delete one record outside the journal.
    fn delete(&mut self, account: &CompanionAccount) -> Result<(), String>;

    /// The names-only inventory admission and trims count. The file store
    /// names project folders by digest, so it counts every record but can
    /// name only `vault_id`'s ring.
    fn admission_inventory(&mut self, vault_id: &str) -> Result<AdmissionInventory, String>;

    /// The values item's access as its attributes claim it.
    fn claimed_approval(&mut self, vault_id: &str) -> Result<Approval, String>;

    /// The values item's access, verified by a probe when its claim needs
    /// one; `None` when the Keychain is unavailable, so nothing is known.
    fn verified_approval(&mut self, vault_id: &str) -> Result<Option<Approval>, String>;
}
