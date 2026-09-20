use crate::storage_transaction::VaultStorageDirectory;

#[cfg(any(not(target_os = "macos"), test))]
pub(super) trait NativeWrappingKeyStore {
    fn read(&self) -> Result<Option<[u8; 32]>, String>;
    fn write(&self, candidate: &[u8; 32]) -> Result<(), String>;
}

#[cfg(any(not(target_os = "macos"), test))]
pub(super) fn load_with_native(
    directory: &VaultStorageDirectory,
    filename: &str,
    store: &dyn NativeWrappingKeyStore,
) -> Result<[u8; 32], String> {
    load_or_create_with_native(directory, filename, store, true)
}

#[cfg(any(not(target_os = "macos"), test))]
pub(super) fn load_or_create_with_native(
    directory: &VaultStorageDirectory,
    filename: &str,
    store: &dyn NativeWrappingKeyStore,
    create: bool,
) -> Result<[u8; 32], String> {
    let fallback = read_file(directory, filename)?;
    match store.read() {
        Ok(Some(key)) => {
            if let Some(existing) = fallback {
                if existing != key {
                    return Err("native and file-fallback env wrapping keys conflict; both were preserved".into());
                }
                directory.remove_file(filename, "env wrapping-key file")?;
            }
            return Ok(key);
        }
        Err(error) => return fallback.ok_or_else(|| format!("system keyring is unavailable and no established env wrapping-key file exists: {error}")),
        Ok(None) => {}
    }
    if fallback.is_none() && !create {
        return Err("no personal env root key exists for this registry and account; use the trusted device or pair this browser again".into());
    }
    let candidate = fallback.unwrap_or_else(super::generate_aes_key);
    if let Err(error) = store.write(&candidate) {
        tracing::debug!(%error, "system keyring write unavailable; retaining the same env wrapping key in the protected file");
        return get_or_create_file(directory, filename, &candidate);
    }
    let stored = store.read()?.ok_or_else(|| {
        "system keyring write succeeded but no env wrapping key was readable".to_owned()
    })?;
    if stored != candidate {
        return Err("system keyring did not preserve the selected env wrapping key; stored keys were preserved".into());
    }
    if fallback.is_some() {
        directory.remove_file(filename, "env wrapping-key file")?;
    }
    Ok(stored)
}

pub(super) fn read_file(
    directory: &VaultStorageDirectory,
    filename: &str,
) -> Result<Option<[u8; 32]>, String> {
    let Some(data) = directory.read_owner_only_file(filename, "env wrapping-key file")? else {
        return Ok(None);
    };
    let encoded = std::str::from_utf8(&data)
        .map_err(|_| "env wrapping-key file is not valid UTF-8".to_owned())?;
    super::decode_wrapping_key(encoded).map(Some)
}

pub(super) fn get_or_create_file(
    directory: &VaultStorageDirectory,
    filename: &str,
    candidate: &[u8; 32],
) -> Result<[u8; 32], String> {
    if let Some(existing) = read_file(directory, filename)? {
        return Ok(existing);
    }
    if directory.create_owner_only_file(
        filename,
        hex::encode(candidate).as_bytes(),
        "env wrapping-key file",
    )? {
        return Ok(*candidate);
    }
    read_file(directory, filename)?.ok_or_else(|| {
        "env wrapping-key file was created concurrently but could not be read".to_owned()
    })
}

#[cfg(all(test, debug_assertions))]
mod tests {
    use super::*;
    use std::cell::RefCell;

    struct Native {
        read: RefCell<Result<Option<[u8; 32]>, String>>,
        write_error: bool,
        readback: Option<Result<Option<[u8; 32]>, String>>,
    }
    impl NativeWrappingKeyStore for Native {
        fn read(&self) -> Result<Option<[u8; 32]>, String> {
            self.read.borrow().clone()
        }
        fn write(&self, key: &[u8; 32]) -> Result<(), String> {
            if self.write_error {
                return Err("write unavailable".into());
            }
            *self.read.borrow_mut() = self.readback.clone().unwrap_or(Ok(Some(*key)));
            Ok(())
        }
    }

    #[test]
    fn native_recovery_preserves_the_established_file_key() {
        let _env = super::super::tests::IsolatedVaultEnv::new();
        crate::storage_transaction::with_vault_transaction(|directory| {
            let key = [0x42; 32];
            get_or_create_file(directory, ".vault-key", &key)?;
            let native = Native {
                read: RefCell::new(Err("temporarily unavailable".into())),
                write_error: false,
                readback: None,
            };
            assert_eq!(load_with_native(directory, ".vault-key", &native)?, key);
            *native.read.borrow_mut() = Ok(None);
            assert_eq!(
                load_with_native(directory, ".vault-key", &native)?,
                key,
                "keyring recovery replaced the cloud wrapping key"
            );
            Ok(())
        })
        .unwrap();
    }
    #[test]
    fn native_file_conflict_preserves_both_keys() {
        let _env = super::super::tests::IsolatedVaultEnv::new();
        crate::storage_transaction::with_vault_transaction(|directory| {
            get_or_create_file(directory, ".vault-key", &[0x42; 32])?;
            let native = Native {
                read: RefCell::new(Ok(Some([0x21; 32]))),
                write_error: false,
                readback: None,
            };
            assert!(load_with_native(directory, ".vault-key", &native).is_err());
            assert_eq!(read_file(directory, ".vault-key")?, Some([0x42; 32]));
            assert_eq!(native.read()?, Some([0x21; 32]));
            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn equal_native_key_removes_the_redundant_file() {
        let _env = super::super::tests::IsolatedVaultEnv::new();
        crate::storage_transaction::with_vault_transaction(|directory| {
            get_or_create_file(directory, ".vault-key", &[0x42; 32])?;
            let native = Native {
                read: RefCell::new(Ok(Some([0x42; 32]))),
                write_error: false,
                readback: None,
            };
            assert_eq!(
                load_with_native(directory, ".vault-key", &native)?,
                [0x42; 32]
            );
            assert_eq!(read_file(directory, ".vault-key")?, None);
            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn failed_promotion_preserves_the_file_until_native_readback_matches() {
        let _env = super::super::tests::IsolatedVaultEnv::new();
        crate::storage_transaction::with_vault_transaction(|directory| {
            get_or_create_file(directory, ".vault-key", &[0x42; 32])?;
            let mut native = Native {
                read: RefCell::new(Ok(None)),
                write_error: true,
                readback: None,
            };
            assert_eq!(
                load_with_native(directory, ".vault-key", &native)?,
                [0x42; 32]
            );
            native.write_error = false;
            for readback in [
                Err("read unavailable".into()),
                Ok(None),
                Ok(Some([0x21; 32])),
            ] {
                *native.read.borrow_mut() = Ok(None);
                native.readback = Some(readback);
                assert!(load_with_native(directory, ".vault-key", &native).is_err());
                assert_eq!(read_file(directory, ".vault-key")?, Some([0x42; 32]));
            }
            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn unknown_native_state_without_fallback_does_not_create_a_key() {
        let _env = super::super::tests::IsolatedVaultEnv::new();
        crate::storage_transaction::with_vault_transaction(|directory| {
            let native = Native {
                read: RefCell::new(Err("read unavailable".into())),
                write_error: false,
                readback: None,
            };
            assert!(load_with_native(directory, ".vault-key", &native).is_err());
            assert_eq!(read_file(directory, ".vault-key")?, None);
            Ok(())
        })
        .unwrap();
    }
}
