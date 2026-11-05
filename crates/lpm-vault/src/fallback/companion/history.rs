//! History's store on the Linux and Windows file store: one entry is
//! replaced by staging it and renaming it into place, so a crash leaves
//! only a stage, which recovery sweeps, and never a temporary file in the
//! companion folder.

use zeroize::Zeroizing;

use super::{
    FileCompanion, MARKER_ENTRY, companion_folder_name, entry_name, seal, stage_folder_name,
};
use crate::companion::account::CompanionAccount;
use crate::companion::{Checked, CompanionBackend as _};
use crate::history::store::{AdmissionInventory, HistoryStore, RecordError};
use crate::storage_transaction::VaultStorageDirectory;
use lpm_env_companion::history::admission;
use lpm_env_companion::keyring::Approval;

/// Run `run` against the file store inside the caller's lock.
pub(crate) fn history_store<T>(
    directory: &VaultStorageDirectory,
    run: impl FnOnce(&mut FileCompanion<'_>) -> T,
) -> Result<T, String> {
    let mut companion = FileCompanion::open(directory)?;
    Ok(run(&mut companion))
}

impl FileCompanion<'_> {
    fn replace_entry(&mut self, account: &CompanionAccount, value: &[u8]) -> Result<(), String> {
        let key = Zeroizing::new(self.data_key()?);
        let sealed = seal(&key, account, value)?;
        let vault_id = account.vault_id();
        let entry = entry_name(account);
        let staged = format!("replace.{entry}");
        {
            let stage = self
                .vaults
                .open_or_create_directory(&stage_folder_name(vault_id))?;
            stage.write_owner_only_file_unsynced(&staged, &sealed, "a history record")?;
            let folder_name = companion_folder_name(vault_id);
            let created = !self.vaults.entry_exists(&folder_name)?;
            let folder = self.vaults.open_or_create_directory(&folder_name)?;
            stage.rename_to(&staged, &folder, &entry, "a history record")?;
            folder.sync("companion records")?;
            if created {
                self.vaults.sync("env files")?;
            }
            if self.read_sealed(&folder, &entry)?.as_deref() != Some(sealed.as_slice()) {
                return Err(format!("local history couldn't verify {entry}"));
            }
        }
        // The stage was renamed away, so its folder is empty. Removing it
        // without listing keeps an append free of directory listings; one
        // left behind is swept by the next recovery.
        let _ = self
            .vaults
            .remove_empty_directory(&stage_folder_name(vault_id), "a history record's stage");
        Ok(())
    }

    fn delete_entry(&mut self, account: &CompanionAccount) -> Result<(), String> {
        let Some(folder) = self.folder(account.vault_id())? else {
            return Ok(());
        };
        if folder.remove_file_unsynced(&entry_name(account), "a history record")? {
            folder.sync("companion records")?;
        }
        Ok(())
    }

    fn record_count(&self) -> Result<usize, String> {
        let mut count = 0;
        for name in self.vaults.entry_names()? {
            if !name.ends_with(".companion") {
                continue;
            }
            let Some(folder) = self.vaults.open_existing_directory(&name)? else {
                continue;
            };
            count += folder
                .entry_names()?
                .iter()
                .filter(|entry| entry.as_str() != MARKER_ENTRY)
                .count();
        }
        Ok(count)
    }
}

impl HistoryStore for FileCompanion<'_> {
    fn read_following_values(
        &mut self,
        account: &CompanionAccount,
    ) -> Result<Option<Zeroizing<Vec<u8>>>, RecordError> {
        match self.read_checked(account)? {
            Checked::Present(bytes) => Ok(Some(bytes)),
            Checked::Absent => Ok(None),
            Checked::Unreadable(reason) => Err(RecordError::Damaged(reason)),
        }
    }

    fn replace(&mut self, account: &CompanionAccount, bytes: &[u8]) -> Result<(), String> {
        self.replace_entry(account, bytes)
    }

    fn delete(&mut self, account: &CompanionAccount) -> Result<(), String> {
        self.delete_entry(account)
    }

    fn admission_inventory(&mut self, vault_id: &str) -> Result<AdmissionInventory, String> {
        let rings = admission::rings(&self.inventory_of(vault_id)?);
        Ok(AdmissionInventory {
            count: self.record_count()?,
            trimmable: rings.iter().map(|ring| ring.vault_id.clone()).collect(),
            rings,
        })
    }

    fn claimed_approval(&mut self, _vault_id: &str) -> Result<Approval, String> {
        Ok(Approval::FileStore)
    }

    fn verified_approval(&mut self, _vault_id: &str) -> Result<Option<Approval>, String> {
        Ok(Some(Approval::FileStore))
    }
}
