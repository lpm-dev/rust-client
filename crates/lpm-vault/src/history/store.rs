//! What history needs from a store of companion records, beyond the
//! journal transactions and names-only inventory every companion store has.

use zeroize::Zeroizing;

use crate::companion::CompanionBackend;
use crate::companion::account::CompanionAccount;
use lpm_env_companion::history::admission::Ring;
use lpm_env_companion::keyring::Approval;

/// What admission counts, from one names-only inventory.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct AdmissionInventory {
    /// Companion and staged records in the service, markers excluded.
    pub(crate) count: usize,
    /// The history rings this client can name, for trims.
    pub(crate) rings: Vec<Ring>,
}

pub(crate) trait HistoryStore: CompanionBackend {
    /// A record that follows values (the head or the key), read with its
    /// access: one that claims less than the values item requires is
    /// strengthened, and verified, before its bytes are used.
    fn read_following_values(
        &mut self,
        account: &CompanionAccount,
    ) -> Result<Option<Zeroizing<Vec<u8>>>, String>;

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

    /// Whether this client can write `vault_id`'s records without asking
    /// for approval, which trimming another project's history needs.
    fn writes_without_prompt(&mut self, vault_id: &str) -> Result<bool, String>;
}
