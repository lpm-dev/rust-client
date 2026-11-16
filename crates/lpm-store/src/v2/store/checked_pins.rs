//! Which stored object holds the bytes a weaker integrity names.
//!
//! An object is stored under the sha512 of its archive. A lockfile may pin
//! the same archive by a SHA-1 or SHA-256 it can't replace, which names no
//! object. A fetch that checked the archive against such a pin records the
//! pair here, so a later install finds the object without the archive.
//!
//! A record answers for the package it was made for and no other. Two
//! archives can be built to share a SHA-1, and a record that answered by
//! the hash alone would hand one package's bytes to another package pinned
//! by the same hash, which a download from its registry would not.

use std::path::PathBuf;

use lpm_common::LpmError;
use lpm_common::integrity::{HashAlgorithm, Integrity};

use super::{Store, ensure_store_tier_dir_locked, harden_tier_of, sri_to_segment};

const CHECKED_PINS_DIR: &str = "checked-pins";

/// A record holds one sha512 integrity and a package's name and version,
/// each on a line.
const RECORD_SIZE_CAP_BYTES: u64 = 1024;

const SHA512_PREFIX: &str = "sha512-";

fn algorithm_of(sri: &str) -> Option<HashAlgorithm> {
    Integrity::parse(sri)
        .ok()
        .map(|integrity| integrity.algorithm)
}

impl Store {
    fn checked_pin_path(&self, pin: &str) -> Result<PathBuf, LpmError> {
        Ok(self
            .paths
            .root()
            .join(CHECKED_PINS_DIR)
            .join(sri_to_segment(pin)?))
    }

    /// Records that the object stored under `stored` holds the archive
    /// `pin` names for `name@version`. The caller checked one archive
    /// against both.
    pub fn record_checked_pin(
        &self,
        name: &str,
        version: &str,
        pin: &str,
        stored: &str,
    ) -> Result<(), LpmError> {
        if algorithm_of(pin).is_none_or(|algorithm| algorithm == HashAlgorithm::Sha512)
            || algorithm_of(stored) != Some(HashAlgorithm::Sha512)
        {
            return Err(LpmError::InvalidIntegrity(format!(
                "a checked pin pairs a weaker integrity with a sha512 one, not {pin} with {stored}"
            )));
        }
        let path = self.checked_pin_path(pin)?;
        if let Some(directory) = path.parent() {
            ensure_store_tier_dir_locked(directory).map_err(|error| {
                LpmError::Store(format!(
                    "failed to keep the virtual-store checked-pins dir private: {error}"
                ))
            })?;
        }
        lpm_common::write_file_atomic_with_options(
            &path,
            format!("{stored}\n{name}@{version}\n"),
            lpm_common::AtomicWriteOptions::new().owner_only(),
        )?;
        Ok(())
    }

    /// The integrity of the stored object that holds the archive `pin`
    /// names for `name@version`, as a fetch that checked it recorded. A
    /// record whose object is gone is removed: the next fetch writes it
    /// again. A records directory that isn't this user's alone, and can't
    /// be made so, answers for no pin.
    pub fn checked_pin(&self, name: &str, version: &str, pin: &str) -> Option<String> {
        if pin.starts_with(SHA512_PREFIX)
            || algorithm_of(pin).is_none_or(|algorithm| algorithm == HashAlgorithm::Sha512)
        {
            return None;
        }
        let path = self.checked_pin_path(pin).ok()?;
        harden_tier_of(&path, "checked-pins").ok()?;
        let record =
            lpm_common::read_text_file_capped_nofollow(&path, RECORD_SIZE_CAP_BYTES).ok()?;
        let (stored, package) = record.strip_suffix('\n')?.split_once('\n')?;
        if algorithm_of(stored) != Some(HashAlgorithm::Sha512)
            || package
                .strip_suffix(version)
                .and_then(|name_at| name_at.strip_suffix('@'))
                != Some(name)
        {
            return None;
        }
        if !self.paths.object_dir(stored).ok()?.is_dir() {
            let _ = std::fs::remove_file(&path);
            return None;
        }
        Some(stored.to_owned())
    }

    /// [`Self::reusable_object_dir`] for the object `pin` names for
    /// `name@version`, itself or through a record of a fetch that checked
    /// it.
    pub fn reusable_object_dir_for_pin(
        &self,
        name: &str,
        version: &str,
        pin: &str,
    ) -> Result<Option<PathBuf>, LpmError> {
        match self.checked_pin(name, version, pin) {
            Some(stored) => self.reusable_object_dir(&stored),
            None => self.reusable_object_dir(pin),
        }
    }

    /// Removes the records whose objects are gone, as a prune of the
    /// objects leaves them, and says how many it removed.
    pub fn sweep_checked_pins(&self) -> Result<usize, LpmError> {
        let directory = self.paths.root().join(CHECKED_PINS_DIR);
        let entries = match std::fs::read_dir(&directory) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(0),
            Err(error) => return Err(error.into()),
        };
        harden_tier_of(&directory.join("record"), "checked-pins")?;
        let mut removed = 0;
        for entry in entries {
            let path = entry?.path();
            let names_an_object =
                lpm_common::read_text_file_capped_nofollow(&path, RECORD_SIZE_CAP_BYTES)
                    .ok()
                    .and_then(|record| {
                        let (stored, _) = record.split_once('\n')?;
                        self.paths.object_dir(stored).ok()
                    })
                    .is_some_and(|object_dir| object_dir.is_dir());
            if !names_an_object && std::fs::remove_file(&path).is_ok() {
                removed += 1;
            }
        }
        Ok(removed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{compute_sri_hash, compute_sri_hash_sha1, compute_sri_hash_sha256};

    const NAME: &str = "@scope/pinned";
    const VERSION: &str = "1.0.0";

    fn store_with_object(archive: &[u8]) -> (tempfile::TempDir, Store, String) {
        let home = tempfile::tempdir().unwrap();
        let store = Store::from_lpm_root_for_version(
            &lpm_common::LpmRoot::from_dir(home.path()),
            crate::StoreVersion::V2,
        );
        let stored = compute_sri_hash(archive);
        std::fs::create_dir_all(store.paths().object_dir(&stored).unwrap()).unwrap();
        (home, store, stored)
    }

    fn checked(store: &Store, pin: &str) -> Option<String> {
        store.checked_pin(NAME, VERSION, pin)
    }

    fn record(store: &Store, pin: &str, stored: &str) -> Result<(), LpmError> {
        store.record_checked_pin(NAME, VERSION, pin, stored)
    }

    #[test]
    fn a_checked_pin_names_the_object_it_was_checked_against_and_no_other_pin_does() {
        let (_home, store, stored) = store_with_object(b"archive");
        let sha1 = compute_sri_hash_sha1(b"archive");
        let sha256 = compute_sri_hash_sha256(b"archive");
        assert_eq!(checked(&store, &sha1), None);

        record(&store, &sha1, &stored).unwrap();

        assert_eq!(checked(&store, &sha1), Some(stored.clone()));
        assert_eq!(checked(&store, &sha256), None);
        assert_eq!(checked(&store, &compute_sri_hash_sha1(b"another")), None);
        assert_eq!(checked(&store, &stored), None);
    }

    #[test]
    fn a_record_answers_only_for_the_package_it_was_made_for() {
        let (_home, store, stored) = store_with_object(b"archive");
        let sha1 = compute_sri_hash_sha1(b"archive");
        record(&store, &sha1, &stored).unwrap();

        for (name, version) in [
            ("another", VERSION),
            (NAME, "1.0.1"),
            ("@scope/pinned@1.0", "0"),
            ("@scope/pinne", "d@1.0.0"),
        ] {
            assert_eq!(
                store.checked_pin(name, version, &sha1),
                None,
                "{name} {version}"
            );
        }
        assert_eq!(checked(&store, &sha1), Some(stored));
    }

    #[test]
    fn a_record_whose_object_is_gone_names_nothing_and_is_removed() {
        let (_home, store, stored) = store_with_object(b"archive");
        let sha1 = compute_sri_hash_sha1(b"archive");
        record(&store, &sha1, &stored).unwrap();
        std::fs::remove_dir(store.paths().object_dir(&stored).unwrap()).unwrap();

        assert_eq!(checked(&store, &sha1), None);
        assert!(!store.checked_pin_path(&sha1).unwrap().exists());
    }

    #[test]
    fn a_sweep_removes_the_records_whose_objects_are_gone_and_no_others() {
        let (_home, store, stored) = store_with_object(b"archive");
        let (kept, gone) = (
            compute_sri_hash_sha1(b"archive"),
            compute_sri_hash_sha256(b"archive"),
        );
        let pruned = compute_sri_hash(b"pruned");
        std::fs::create_dir_all(store.paths().object_dir(&pruned).unwrap()).unwrap();
        assert_eq!(store.sweep_checked_pins().unwrap(), 0);
        record(&store, &kept, &stored).unwrap();
        record(&store, &gone, &pruned).unwrap();
        std::fs::remove_dir(store.paths().object_dir(&pruned).unwrap()).unwrap();

        assert_eq!(store.sweep_checked_pins().unwrap(), 1);

        assert_eq!(checked(&store, &kept), Some(stored));
        assert!(!store.checked_pin_path(&gone).unwrap().exists());
    }

    #[test]
    fn a_record_that_is_not_an_integrity_and_a_package_names_nothing() {
        let (_home, store, stored) = store_with_object(b"archive");
        let sha1 = compute_sri_hash_sha1(b"archive");
        record(&store, &sha1, &stored).unwrap();
        let path = store.checked_pin_path(&sha1).unwrap();
        for content in [
            String::new(),
            format!("{stored}\n"),
            format!("{stored}\n{NAME}@{VERSION}"),
            format!("{sha1}\n{NAME}@{VERSION}\n"),
            format!("{stored}\n{NAME}@{VERSION}\n{NAME}@{VERSION}\n"),
            format!("../../objects\n{NAME}@{VERSION}\n"),
        ] {
            std::fs::write(&path, &content).unwrap();
            assert_eq!(checked(&store, &sha1), None, "{content:?}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn records_are_this_users_alone_and_a_linked_directory_holds_none() {
        use std::os::unix::fs::PermissionsExt;
        let (home, store, stored) = store_with_object(b"archive");
        let sha1 = compute_sri_hash_sha1(b"archive");
        record(&store, &sha1, &stored).unwrap();
        let path = store.checked_pin_path(&sha1).unwrap();
        let directory = path.parent().unwrap();
        let mode = |path: &std::path::Path| path.metadata().unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(directory), 0o700);
        assert_eq!(mode(&path), 0o600);

        let elsewhere = home.path().join("elsewhere");
        std::fs::rename(directory, &elsewhere).unwrap();
        std::os::unix::fs::symlink(&elsewhere, directory).unwrap();

        assert_eq!(checked(&store, &sha1), None);
        assert!(record(&store, &sha1, &stored).is_err());
    }

    #[test]
    fn only_a_weaker_pin_and_a_sha512_object_are_recorded() {
        let (_home, store, stored) = store_with_object(b"archive");
        let sha1 = compute_sri_hash_sha1(b"archive");

        assert!(record(&store, &stored, &stored).is_err());
        assert!(record(&store, &sha1, &sha1).is_err());
        assert!(record(&store, "sha1-not base64", &stored).is_err());
    }
}
