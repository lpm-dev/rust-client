use core_foundation::base::{CFType, CFTypeRef, TCFType};
use core_foundation::boolean::CFBoolean;
use core_foundation::data::CFData;
use core_foundation::dictionary::CFDictionary;
use core_foundation::string::{CFString, CFStringRef};
use security_framework::os::macos::keychain::SecKeychain;
use security_framework::passwords::{
    PasswordOptions, delete_generic_password_options, generic_password,
};
use security_framework_sys::access_control::kSecAttrAccessibleWhenUnlockedThisDeviceOnly;
use security_framework_sys::item::{
    kSecAttrAccessGroup, kSecAttrAccount, kSecAttrService, kSecAttrSynchronizable, kSecClass,
    kSecClassGenericPassword, kSecReturnData, kSecUseDataProtectionKeychain, kSecUseKeychain,
    kSecValueData,
};
use security_framework_sys::keychain_item::{
    SecItemAdd, SecItemCopyMatching, SecItemDelete, SecItemUpdate,
};

#[link(name = "Security", kind = "framework")]
unsafe extern "C" {
    static kSecAttrAccessible: CFStringRef;
}

pub(crate) const SHARED_ACCESS_GROUP: &str = "823S8YKMRW.dev.lpm.vault.shared";

const ERR_SEC_ITEM_NOT_FOUND: i32 = -25300;
const ERR_SEC_DUPLICATE_ITEM: i32 = -25299;
const ERR_SEC_INTERACTION_NOT_ALLOWED: i32 = -25308;
const ERR_SEC_MISSING_ENTITLEMENT: i32 = -34018;

#[derive(Debug, thiserror::Error)]
enum KeychainStorageError {
    #[error(
        "this LPM binary is not signed for the shared macOS Keychain access group; install an official signed build or use scripts/build-signed-macos.sh"
    )]
    MissingEntitlement,
    #[error(
        "the macOS Data Protection Keychain is locked or unavailable in this login context; unlock the login Keychain with `security unlock-keychain ~/Library/Keychains/login.keychain-db` and retry"
    )]
    InteractionNotAllowed,
    #[error("macOS Keychain {operation} failed (OSStatus {code})")]
    Security { operation: &'static str, code: i32 },
    #[error("macOS Keychain value is not valid UTF-8")]
    InvalidUtf8,
    #[error("macOS Keychain item already exists")]
    DuplicateItem,
    #[error(
        "macOS Keychain values changed during a secure update; finish other LPM operations and retry"
    )]
    MigrationConflict,
    #[error(
        "macOS Keychain verification failed; no protected value was found and any legacy value was preserved"
    )]
    MigrationVerificationFailed,
}

#[derive(Clone, Copy)]
enum KeychainLocation {
    Shared,
    Legacy,
}

trait KeychainBackend {
    fn read(
        &self,
        service: &str,
        account: &str,
        location: KeychainLocation,
    ) -> Result<Option<Vec<u8>>, KeychainStorageError>;

    fn write_shared(
        &self,
        service: &str,
        account: &str,
        value: &[u8],
    ) -> Result<(), KeychainStorageError>;

    fn write_legacy(
        &self,
        service: &str,
        account: &str,
        value: &[u8],
    ) -> Result<(), KeychainStorageError>;

    fn add_shared(
        &self,
        service: &str,
        account: &str,
        value: &[u8],
    ) -> Result<(), KeychainStorageError>;

    fn add_legacy(
        &self,
        service: &str,
        account: &str,
        value: &[u8],
    ) -> Result<(), KeychainStorageError>;

    fn normalize_shared(&self, service: &str, account: &str) -> Result<(), KeychainStorageError>;

    fn delete(
        &self,
        service: &str,
        account: &str,
        location: KeychainLocation,
    ) -> Result<bool, KeychainStorageError>;
}

struct SecurityFrameworkBackend;

/// Serialize compound Vault/CLI Keychain operations across processes.
///
/// The lock file contains no secret data. `O_NOFOLLOW`, owner validation, and
/// mode normalization prevent a pre-existing link or permissive file from
/// redirecting the shared advisory-lock domain.
pub(crate) fn with_keychain_transaction<T>(
    operation: impl FnOnce() -> Result<T, String>,
) -> Result<T, String> {
    crate::storage_transaction::with_vault_transaction(|_| operation())
}

impl SecurityFrameworkBackend {
    fn shared_options(service: &str, account: &str) -> PasswordOptions {
        let mut options = PasswordOptions::new_generic_password(service, account);
        options.set_access_group(SHARED_ACCESS_GROUP);
        options.set_access_synchronized(Some(false));
        options.use_protected_keychain();
        options
    }

    fn map_status(operation: &'static str, code: i32) -> KeychainStorageError {
        match code {
            ERR_SEC_MISSING_ENTITLEMENT => KeychainStorageError::MissingEntitlement,
            ERR_SEC_INTERACTION_NOT_ALLOWED => KeychainStorageError::InteractionNotAllowed,
            code => KeychainStorageError::Security { operation, code },
        }
    }

    fn map_error(
        operation: &'static str,
        error: security_framework::base::Error,
    ) -> KeychainStorageError {
        Self::map_status(operation, error.code())
    }

    fn legacy_identity_pairs(
        service: &str,
        account: &str,
    ) -> Result<Vec<(CFString, CFType)>, KeychainStorageError> {
        let keychain = SecKeychain::default()
            .map_err(|error| Self::map_error("locate legacy keychain", error))?;
        Ok(Self::legacy_identity_pairs_with_keychain(
            service,
            account,
            keychain.into_CFType(),
        ))
    }

    fn legacy_identity_pairs_with_keychain(
        service: &str,
        account: &str,
        keychain: CFType,
    ) -> Vec<(CFString, CFType)> {
        vec![
            (
                unsafe { CFString::wrap_under_get_rule(kSecClass) },
                unsafe { CFString::wrap_under_get_rule(kSecClassGenericPassword) }.into_CFType(),
            ),
            (
                unsafe { CFString::wrap_under_get_rule(kSecAttrService) },
                CFString::from(service).into_CFType(),
            ),
            (
                unsafe { CFString::wrap_under_get_rule(kSecAttrAccount) },
                CFString::from(account).into_CFType(),
            ),
            (
                unsafe { CFString::wrap_under_get_rule(kSecUseKeychain) },
                keychain,
            ),
        ]
    }

    fn legacy_query(
        service: &str,
        account: &str,
    ) -> Result<CFDictionary<CFString, CFType>, KeychainStorageError> {
        Ok(CFDictionary::from_CFType_pairs(
            &Self::legacy_identity_pairs(service, account)?,
        ))
    }

    fn read_legacy(service: &str, account: &str) -> Result<Option<Vec<u8>>, KeychainStorageError> {
        let mut pairs = Self::legacy_identity_pairs(service, account)?;
        pairs.push((
            unsafe { CFString::wrap_under_get_rule(kSecReturnData) },
            CFBoolean::from(true).into_CFType(),
        ));
        let query = CFDictionary::from_CFType_pairs(&pairs);
        let mut result: CFTypeRef = std::ptr::null();
        let status = unsafe { SecItemCopyMatching(query.as_concrete_TypeRef(), &mut result) };
        if status == ERR_SEC_ITEM_NOT_FOUND {
            return Ok(None);
        }
        if status != 0 {
            return Err(Self::map_status("read legacy", status));
        }
        if result.is_null() {
            return Err(KeychainStorageError::Security {
                operation: "read legacy result",
                code: -2070,
            });
        }

        // SAFETY: A successful SecItemCopyMatching call returns an owned CF
        // object. CFType takes that +1 retain and releases it on every exit.
        let value = unsafe { CFType::wrap_under_create_rule(result) };
        let data = value
            .downcast_into::<CFData>()
            .ok_or(KeychainStorageError::Security {
                operation: "read legacy result",
                code: -2070,
            })?;
        Ok(Some(data.bytes().to_vec()))
    }

    fn delete_legacy(service: &str, account: &str) -> Result<bool, KeychainStorageError> {
        let query = Self::legacy_query(service, account)?;
        let status = unsafe { SecItemDelete(query.as_concrete_TypeRef()) };
        match status {
            0 => Ok(true),
            ERR_SEC_ITEM_NOT_FOUND => Ok(false),
            status => Err(Self::map_status("delete legacy", status)),
        }
    }

    fn shared_identity_pairs(service: &str, account: &str) -> Vec<(CFString, CFType)> {
        vec![
            (
                unsafe { CFString::wrap_under_get_rule(kSecClass) },
                unsafe { CFString::wrap_under_get_rule(kSecClassGenericPassword) }.into_CFType(),
            ),
            (
                unsafe { CFString::wrap_under_get_rule(kSecAttrService) },
                CFString::from(service).into_CFType(),
            ),
            (
                unsafe { CFString::wrap_under_get_rule(kSecAttrAccount) },
                CFString::from(account).into_CFType(),
            ),
            (
                unsafe { CFString::wrap_under_get_rule(kSecAttrAccessGroup) },
                CFString::from(SHARED_ACCESS_GROUP).into_CFType(),
            ),
            (
                unsafe { CFString::wrap_under_get_rule(kSecAttrSynchronizable) },
                CFBoolean::from(false).into_CFType(),
            ),
            (
                unsafe { CFString::wrap_under_get_rule(kSecUseDataProtectionKeychain) },
                CFBoolean::from(true).into_CFType(),
            ),
        ]
    }

    fn shared_query(service: &str, account: &str) -> CFDictionary<CFString, CFType> {
        CFDictionary::from_CFType_pairs(&Self::shared_identity_pairs(service, account))
    }

    fn shared_attribute_pairs(value: Option<&[u8]>) -> Vec<(CFString, CFType)> {
        let mut pairs = vec![(
            unsafe { CFString::wrap_under_get_rule(kSecAttrAccessible) },
            unsafe { CFString::wrap_under_get_rule(kSecAttrAccessibleWhenUnlockedThisDeviceOnly) }
                .into_CFType(),
        )];
        if let Some(value) = value {
            pairs.push((
                unsafe { CFString::wrap_under_get_rule(kSecValueData) },
                CFData::from_buffer(value).into_CFType(),
            ));
        }
        pairs
    }

    fn shared_attributes(value: Option<&[u8]>) -> CFDictionary<CFString, CFType> {
        CFDictionary::from_CFType_pairs(&Self::shared_attribute_pairs(value))
    }

    fn update_shared(
        service: &str,
        account: &str,
        value: Option<&[u8]>,
        operation: &'static str,
    ) -> Result<(), KeychainStorageError> {
        let query = Self::shared_query(service, account);
        let attributes = Self::shared_attributes(value);
        let status = unsafe {
            SecItemUpdate(
                query.as_concrete_TypeRef(),
                attributes.as_concrete_TypeRef(),
            )
        };
        if status == 0 {
            Ok(())
        } else {
            Err(Self::map_error(
                operation,
                security_framework::base::Error::from_code(status),
            ))
        }
    }

    fn update_legacy(
        service: &str,
        account: &str,
        value: &[u8],
    ) -> Result<(), KeychainStorageError> {
        let query = Self::legacy_query(service, account)?;
        let attributes = CFDictionary::from_CFType_pairs(&[(
            unsafe { CFString::wrap_under_get_rule(kSecValueData) },
            CFData::from_buffer(value).into_CFType(),
        )]);
        let status = unsafe {
            SecItemUpdate(
                query.as_concrete_TypeRef(),
                attributes.as_concrete_TypeRef(),
            )
        };
        if status == 0 {
            Ok(())
        } else {
            Err(Self::map_status("write legacy", status))
        }
    }

    fn add_legacy(service: &str, account: &str, value: &[u8]) -> Result<(), KeychainStorageError> {
        let mut pairs = Self::legacy_identity_pairs(service, account)?;
        pairs.push((
            unsafe { CFString::wrap_under_get_rule(kSecValueData) },
            CFData::from_buffer(value).into_CFType(),
        ));
        let add = CFDictionary::from_CFType_pairs(&pairs);
        let status = unsafe { SecItemAdd(add.as_concrete_TypeRef(), std::ptr::null_mut()) };
        match status {
            0 => Ok(()),
            ERR_SEC_DUPLICATE_ITEM => Err(KeychainStorageError::DuplicateItem),
            status => Err(Self::map_status("add legacy", status)),
        }
    }
}

impl KeychainBackend for SecurityFrameworkBackend {
    fn read(
        &self,
        service: &str,
        account: &str,
        location: KeychainLocation,
    ) -> Result<Option<Vec<u8>>, KeychainStorageError> {
        match location {
            KeychainLocation::Shared => {
                match generic_password(Self::shared_options(service, account)) {
                    Ok(value) => Ok(Some(value)),
                    Err(error) if error.code() == ERR_SEC_ITEM_NOT_FOUND => Ok(None),
                    Err(error) => Err(Self::map_error("read", error)),
                }
            }
            KeychainLocation::Legacy => Self::read_legacy(service, account),
        }
    }

    fn write_shared(
        &self,
        service: &str,
        account: &str,
        value: &[u8],
    ) -> Result<(), KeychainStorageError> {
        match self.add_shared(service, account, value) {
            Ok(()) => Ok(()),
            Err(KeychainStorageError::DuplicateItem) => {
                Self::update_shared(service, account, Some(value), "write")
            }
            Err(error) => Err(error),
        }
    }

    fn write_legacy(
        &self,
        service: &str,
        account: &str,
        value: &[u8],
    ) -> Result<(), KeychainStorageError> {
        match Self::add_legacy(service, account, value) {
            Ok(()) => Ok(()),
            Err(KeychainStorageError::DuplicateItem) => {
                Self::update_legacy(service, account, value)
            }
            Err(error) => Err(error),
        }
    }

    fn add_shared(
        &self,
        service: &str,
        account: &str,
        value: &[u8],
    ) -> Result<(), KeychainStorageError> {
        let mut pairs = Self::shared_identity_pairs(service, account);
        pairs.extend(Self::shared_attribute_pairs(Some(value)));
        let add = CFDictionary::from_CFType_pairs(&pairs);
        let status = unsafe { SecItemAdd(add.as_concrete_TypeRef(), std::ptr::null_mut()) };
        match status {
            0 => Ok(()),
            ERR_SEC_DUPLICATE_ITEM => Err(KeychainStorageError::DuplicateItem),
            status => Err(Self::map_error(
                "add",
                security_framework::base::Error::from_code(status),
            )),
        }
    }

    fn add_legacy(
        &self,
        service: &str,
        account: &str,
        value: &[u8],
    ) -> Result<(), KeychainStorageError> {
        Self::add_legacy(service, account, value)
    }

    fn normalize_shared(&self, service: &str, account: &str) -> Result<(), KeychainStorageError> {
        Self::update_shared(service, account, None, "normalize accessibility")
    }

    fn delete(
        &self,
        service: &str,
        account: &str,
        location: KeychainLocation,
    ) -> Result<bool, KeychainStorageError> {
        match location {
            KeychainLocation::Shared => {
                match delete_generic_password_options(Self::shared_options(service, account)) {
                    Ok(()) => Ok(true),
                    Err(error) if error.code() == ERR_SEC_ITEM_NOT_FOUND => Ok(false),
                    Err(error) => Err(Self::map_error("delete", error)),
                }
            }
            KeychainLocation::Legacy => Self::delete_legacy(service, account),
        }
    }
}

fn read_reconciled<B: KeychainBackend>(
    backend: &B,
    service: &str,
    account: &str,
) -> Result<Option<Vec<u8>>, KeychainStorageError> {
    if !legacy_compatibility_active(backend, service)? {
        let shared = backend.read(service, account, KeychainLocation::Shared)?;
        if shared.is_some() {
            backend.normalize_shared(service, account)?;
        }
        return Ok(shared);
    }

    // Until the coordinated cutover, an installed pre-shared-Keychain CLI can
    // only update the legacy item. Treat that copy as authoritative and repair
    // the protected copy so old and new signed clients can coexist.
    const RECONCILIATION_ATTEMPTS: usize = 3;
    for _ in 0..RECONCILIATION_ATTEMPTS {
        let legacy = backend.read(service, account, KeychainLocation::Legacy)?;
        let shared = backend.read(service, account, KeychainLocation::Shared)?;
        let Some(legacy) = legacy else {
            let Some(shared) = shared else {
                return Ok(None);
            };
            match backend.add_legacy(service, account, &shared) {
                Ok(()) => {}
                Err(KeychainStorageError::DuplicateItem) => continue,
                Err(error) => return Err(error),
            }
            let verified_legacy = backend.read(service, account, KeychainLocation::Legacy)?;
            let verified_shared = backend.read(service, account, KeychainLocation::Shared)?;
            if verified_legacy.as_deref() != Some(shared.as_slice())
                || verified_shared.as_deref() != Some(shared.as_slice())
            {
                return Err(KeychainStorageError::MigrationVerificationFailed);
            }
            backend.normalize_shared(service, account)?;
            return Ok(Some(shared));
        };

        if shared.as_deref() != Some(legacy.as_slice()) {
            backend.write_shared(service, account, &legacy)?;
        }

        let verified_shared = backend.read(service, account, KeychainLocation::Shared)?;
        let verified_legacy = backend.read(service, account, KeychainLocation::Legacy)?;
        if verified_legacy.as_deref() != Some(legacy.as_slice()) {
            continue;
        }
        if verified_shared.as_deref() != Some(legacy.as_slice()) {
            return Err(KeychainStorageError::MigrationVerificationFailed);
        }
        backend.normalize_shared(service, account)?;
        return Ok(Some(legacy));
    }

    Err(KeychainStorageError::MigrationConflict)
}

const LEGACY_CUTOVER_ACCOUNT: &str = "__legacy_keychain_cutover_v1__";
const LEGACY_CUTOVER_VALUE: &[u8] = b"protected-only-v1";

fn legacy_compatibility_active<B: KeychainBackend>(
    backend: &B,
    service: &str,
) -> Result<bool, KeychainStorageError> {
    match backend.read(service, LEGACY_CUTOVER_ACCOUNT, KeychainLocation::Shared)? {
        None => Ok(true),
        Some(marker) if marker == LEGACY_CUTOVER_VALUE => Ok(false),
        Some(_) => Err(KeychainStorageError::MigrationConflict),
    }
}

fn write_reconciled<B: KeychainBackend>(
    backend: &B,
    service: &str,
    account: &str,
    value: &[u8],
) -> Result<(), KeychainStorageError> {
    let previous = read_reconciled(backend, service, account)?;
    let compatibility_active = legacy_compatibility_active(backend, service)?;
    if compatibility_active {
        backend.write_legacy(service, account, value)?;
        if backend
            .read(service, account, KeychainLocation::Legacy)?
            .as_deref()
            != Some(value)
        {
            return Err(KeychainStorageError::MigrationConflict);
        }
    }

    let result = (|| {
        write_shared_with_retry(backend, service, account, value)?;
        let verified = backend.read(service, account, KeychainLocation::Shared)?;
        match verified {
            Some(verified)
                if verified == value
                    && (!compatibility_active
                        || backend
                            .read(service, account, KeychainLocation::Legacy)?
                            .as_deref()
                            == Some(value)) =>
            {
                Ok(())
            }
            Some(_) => Err(KeychainStorageError::MigrationConflict),
            None => Err(KeychainStorageError::MigrationVerificationFailed),
        }
    })();
    if let Err(error) = result {
        if compatibility_active {
            restore_legacy(backend, service, account, value, previous.as_deref())?;
        }
        return Err(error);
    }
    Ok(())
}

fn write_shared_with_retry<B: KeychainBackend>(
    backend: &B,
    service: &str,
    account: &str,
    value: &[u8],
) -> Result<(), KeychainStorageError> {
    match backend.write_shared(service, account, value) {
        Ok(()) => Ok(()),
        Err(_)
            if backend
                .read(service, account, KeychainLocation::Shared)?
                .as_deref()
                == Some(value) =>
        {
            Ok(())
        }
        Err(_) => backend.write_shared(service, account, value),
    }
}

fn add_shared_with_retry<B: KeychainBackend>(
    backend: &B,
    service: &str,
    account: &str,
    value: &[u8],
) -> Result<(), KeychainStorageError> {
    match backend.add_shared(service, account, value) {
        Ok(()) => Ok(()),
        Err(_)
            if backend
                .read(service, account, KeychainLocation::Shared)?
                .as_deref()
                == Some(value) =>
        {
            Ok(())
        }
        Err(_) => backend.add_shared(service, account, value),
    }
}

fn restore_legacy<B: KeychainBackend>(
    backend: &B,
    service: &str,
    account: &str,
    attempted: &[u8],
    previous: Option<&[u8]>,
) -> Result<(), KeychainStorageError> {
    if backend
        .read(service, account, KeychainLocation::Legacy)?
        .as_deref()
        != Some(attempted)
    {
        return Err(KeychainStorageError::MigrationConflict);
    }
    match previous {
        Some(previous) => backend.write_legacy(service, account, previous)?,
        None => {
            let _ = backend.delete(service, account, KeychainLocation::Legacy)?;
        }
    }
    if backend
        .read(service, account, KeychainLocation::Legacy)?
        .as_deref()
        != previous
    {
        return Err(KeychainStorageError::MigrationVerificationFailed);
    }
    Ok(())
}

pub(crate) fn read_string(service: &str, account: &str) -> Result<Option<String>, String> {
    read_reconciled(&SecurityFrameworkBackend, service, account)
        .and_then(|value| {
            value
                .map(String::from_utf8)
                .transpose()
                .map_err(|_| KeychainStorageError::InvalidUtf8)
        })
        .map_err(|error| error.to_string())
}

pub(crate) fn write_string(service: &str, account: &str, value: &str) -> Result<(), String> {
    write_reconciled(
        &SecurityFrameworkBackend,
        service,
        account,
        value.as_bytes(),
    )
    .map_err(|error| error.to_string())
}

/// Return an existing protected value or atomically create it from `candidate`.
///
/// This is the only safe primitive for create-once private keys shared by the
/// Vault app and CLI. A duplicate means another process won the `SecItemAdd`
/// race, so the winner is read and returned instead of being overwritten.
pub(crate) fn get_or_insert_string(
    service: &str,
    account: &str,
    candidate: &str,
) -> Result<String, String> {
    get_or_insert_reconciled(
        &SecurityFrameworkBackend,
        service,
        account,
        candidate.as_bytes(),
    )
    .and_then(|value| String::from_utf8(value).map_err(|_| KeychainStorageError::InvalidUtf8))
    .map_err(|error| error.to_string())
}

fn get_or_insert_reconciled<B: KeychainBackend>(
    backend: &B,
    service: &str,
    account: &str,
    candidate: &[u8],
) -> Result<Vec<u8>, KeychainStorageError> {
    if let Some(existing) = read_reconciled(backend, service, account)? {
        return Ok(existing);
    }

    let compatibility_active = legacy_compatibility_active(backend, service)?;
    if compatibility_active {
        match backend.add_legacy(service, account, candidate) {
            Ok(()) => {}
            Err(KeychainStorageError::DuplicateItem) => {
                return read_reconciled(backend, service, account)?
                    .ok_or(KeychainStorageError::MigrationConflict);
            }
            Err(error) => return Err(error),
        }
        if backend
            .read(service, account, KeychainLocation::Legacy)?
            .as_deref()
            != Some(candidate)
        {
            return Err(KeychainStorageError::MigrationConflict);
        }
    }

    let result = (|| {
        add_shared_with_retry(backend, service, account, candidate)?;
        let shared = backend.read(service, account, KeychainLocation::Shared)?;
        if shared.as_deref() != Some(candidate) {
            return match shared {
                Some(_) => Err(KeychainStorageError::MigrationConflict),
                None => Err(KeychainStorageError::MigrationVerificationFailed),
            };
        }
        if compatibility_active
            && backend
                .read(service, account, KeychainLocation::Legacy)?
                .as_deref()
                != Some(candidate)
        {
            return Err(KeychainStorageError::MigrationConflict);
        }
        Ok(())
    })();
    if let Err(error) = result {
        if compatibility_active {
            restore_legacy(backend, service, account, candidate, None)?;
        }
        return Err(error);
    }
    Ok(candidate.to_vec())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KeychainDeleteOutcome {
    Deleted,
    NotFound,
}

fn delete_reconciled<B: KeychainBackend>(
    backend: &B,
    service: &str,
    account: &str,
) -> Result<KeychainDeleteOutcome, KeychainStorageError> {
    // Deletion is an explicit user action, so remove both stores. Legacy is
    // deleted first: if authorization fails, the authoritative shared value
    // remains intact and the operation can be retried safely.
    let deleted_legacy = backend.delete(service, account, KeychainLocation::Legacy)?;
    let deleted_shared = backend.delete(service, account, KeychainLocation::Shared)?;
    if deleted_legacy || deleted_shared {
        Ok(KeychainDeleteOutcome::Deleted)
    } else {
        Ok(KeychainDeleteOutcome::NotFound)
    }
}

pub(crate) fn delete(service: &str, account: &str) -> Result<KeychainDeleteOutcome, String> {
    delete_reconciled(&SecurityFrameworkBackend, service, account)
        .map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use std::cell::{Cell, RefCell};
    use std::collections::HashMap;

    use super::*;

    #[test]
    fn interaction_not_allowed_explains_how_to_unlock_the_data_protection_keychain() {
        let error = SecurityFrameworkBackend::map_error(
            "add",
            security_framework::base::Error::from_code(ERR_SEC_INTERACTION_NOT_ALLOWED),
        );

        assert!(matches!(error, KeychainStorageError::InteractionNotAllowed));
        assert!(error.to_string().contains("security unlock-keychain"));
    }

    #[test]
    fn legacy_query_is_scoped_to_the_default_file_keychain() {
        let pairs = SecurityFrameworkBackend::legacy_identity_pairs_with_keychain(
            "service",
            "account",
            CFString::from("test-keychain").into_CFType(),
        );
        let keychain_key = unsafe { CFString::wrap_under_get_rule(kSecUseKeychain) };
        let protected_keychain_key =
            unsafe { CFString::wrap_under_get_rule(kSecUseDataProtectionKeychain) };

        assert!(pairs.iter().any(|(key, _)| key == &keychain_key));
        assert!(pairs.iter().all(|(key, _)| key != &protected_keychain_key));
    }

    type Slot = (String, String);

    #[derive(Default)]
    struct FakeBackend {
        shared: RefCell<HashMap<Slot, Vec<u8>>>,
        legacy: RefCell<HashMap<Slot, Vec<u8>>>,
        drop_shared_writes: Cell<bool>,
        shared_write_failures_remaining: Cell<usize>,
        reject_legacy_delete: Cell<bool>,
        reject_shared_delete: Cell<bool>,
        normalized_shared: Cell<usize>,
        legacy_value_inserted_before_add: RefCell<Option<Vec<u8>>>,
        shared_value_inserted_before_add: RefCell<Option<Vec<u8>>>,
        shared_value_updated_after_add: RefCell<Option<Vec<u8>>>,
        shared_value_updated_after_write: RefCell<Option<Vec<u8>>>,
        legacy_value_updated_on_shared_failure: RefCell<Option<Vec<u8>>>,
    }

    impl FakeBackend {
        fn slot(service: &str, account: &str) -> Slot {
            (service.to_owned(), account.to_owned())
        }

        fn insert_legacy(&self, service: &str, account: &str, value: &[u8]) {
            self.legacy
                .borrow_mut()
                .insert(Self::slot(service, account), value.to_vec());
        }

        fn insert_shared(&self, service: &str, account: &str, value: &[u8]) {
            self.shared
                .borrow_mut()
                .insert(Self::slot(service, account), value.to_vec());
        }
    }

    impl KeychainBackend for FakeBackend {
        fn read(
            &self,
            service: &str,
            account: &str,
            location: KeychainLocation,
        ) -> Result<Option<Vec<u8>>, KeychainStorageError> {
            let slot = Self::slot(service, account);
            Ok(match location {
                KeychainLocation::Shared => self.shared.borrow().get(&slot).cloned(),
                KeychainLocation::Legacy => self.legacy.borrow().get(&slot).cloned(),
            })
        }

        fn write_shared(
            &self,
            service: &str,
            account: &str,
            value: &[u8],
        ) -> Result<(), KeychainStorageError> {
            let failures_remaining = self.shared_write_failures_remaining.get();
            if failures_remaining > 0 {
                self.shared_write_failures_remaining
                    .set(failures_remaining - 1);
                if let Some(concurrent) = self
                    .legacy_value_updated_on_shared_failure
                    .borrow_mut()
                    .take()
                {
                    self.legacy
                        .borrow_mut()
                        .insert(Self::slot(service, account), concurrent);
                }
                return Err(KeychainStorageError::Security {
                    operation: "write",
                    code: -25291,
                });
            }
            if self.drop_shared_writes.get() {
                return Ok(());
            }
            self.shared
                .borrow_mut()
                .insert(Self::slot(service, account), value.to_vec());
            if let Some(concurrent) = self.shared_value_updated_after_write.borrow_mut().take() {
                self.shared
                    .borrow_mut()
                    .insert(Self::slot(service, account), concurrent);
            }
            Ok(())
        }

        fn write_legacy(
            &self,
            service: &str,
            account: &str,
            value: &[u8],
        ) -> Result<(), KeychainStorageError> {
            self.legacy
                .borrow_mut()
                .insert(Self::slot(service, account), value.to_vec());
            Ok(())
        }

        fn add_shared(
            &self,
            service: &str,
            account: &str,
            value: &[u8],
        ) -> Result<(), KeychainStorageError> {
            let slot = Self::slot(service, account);
            if let Some(concurrent) = self.shared_value_inserted_before_add.borrow_mut().take() {
                self.shared.borrow_mut().insert(slot, concurrent);
                return Err(KeychainStorageError::DuplicateItem);
            }
            if self.shared.borrow().contains_key(&slot) {
                return Err(KeychainStorageError::DuplicateItem);
            }
            self.write_shared(service, account, value)?;
            if let Some(concurrent) = self.shared_value_updated_after_add.borrow_mut().take() {
                self.shared.borrow_mut().insert(slot, concurrent);
            }
            Ok(())
        }

        fn add_legacy(
            &self,
            service: &str,
            account: &str,
            value: &[u8],
        ) -> Result<(), KeychainStorageError> {
            let slot = Self::slot(service, account);
            if let Some(concurrent) = self.legacy_value_inserted_before_add.borrow_mut().take() {
                self.legacy.borrow_mut().insert(slot, concurrent);
                return Err(KeychainStorageError::DuplicateItem);
            }
            if self.legacy.borrow().contains_key(&slot) {
                return Err(KeychainStorageError::DuplicateItem);
            }
            self.legacy.borrow_mut().insert(slot, value.to_vec());
            Ok(())
        }

        fn normalize_shared(
            &self,
            service: &str,
            account: &str,
        ) -> Result<(), KeychainStorageError> {
            if !self
                .shared
                .borrow()
                .contains_key(&Self::slot(service, account))
            {
                return Err(KeychainStorageError::Security {
                    operation: "normalize accessibility",
                    code: ERR_SEC_ITEM_NOT_FOUND,
                });
            }
            self.normalized_shared.set(self.normalized_shared.get() + 1);
            Ok(())
        }

        fn delete(
            &self,
            service: &str,
            account: &str,
            location: KeychainLocation,
        ) -> Result<bool, KeychainStorageError> {
            if matches!(location, KeychainLocation::Legacy) && self.reject_legacy_delete.get() {
                return Err(KeychainStorageError::Security {
                    operation: "delete",
                    code: -25293,
                });
            }
            if matches!(location, KeychainLocation::Shared) && self.reject_shared_delete.get() {
                return Err(KeychainStorageError::Security {
                    operation: "delete",
                    code: -25291,
                });
            }
            let slot = Self::slot(service, account);
            Ok(match location {
                KeychainLocation::Shared => self.shared.borrow_mut().remove(&slot).is_some(),
                KeychainLocation::Legacy => self.legacy.borrow_mut().remove(&slot).is_some(),
            })
        }
    }

    #[test]
    fn read_reconciled_copies_verifies_and_preserves_the_legacy_value() {
        let backend = FakeBackend::default();
        backend.insert_legacy("service", "account", b"secret");

        let result = read_reconciled(&backend, "service", "account");

        assert_eq!(result.unwrap().as_deref(), Some(b"secret".as_slice()));
        assert_eq!(
            backend
                .legacy
                .borrow()
                .get(&FakeBackend::slot("service", "account"))
                .map(Vec::as_slice),
            Some(b"secret".as_slice())
        );
    }

    #[test]
    fn read_reconciled_preserves_legacy_value_when_verification_fails() {
        let backend = FakeBackend::default();
        backend.insert_legacy("service", "account", b"secret");
        backend.drop_shared_writes.set(true);

        let error = read_reconciled(&backend, "service", "account").unwrap_err();

        assert!(matches!(
            error,
            KeychainStorageError::MigrationVerificationFailed
        ));
        assert_eq!(
            backend
                .legacy
                .borrow()
                .get(&FakeBackend::slot("service", "account"))
                .map(Vec::as_slice),
            Some(b"secret".as_slice())
        );
        assert!(backend.shared.borrow().is_empty());
    }

    #[test]
    fn read_reconciled_repairs_shared_when_current_cli_updates_legacy() {
        let backend = FakeBackend::default();
        backend.insert_shared("service", "account", b"protected");
        backend.insert_legacy("service", "account", b"legacy");

        let value = read_reconciled(&backend, "service", "account").unwrap();

        assert_eq!(value.as_deref(), Some(b"legacy".as_slice()));
        assert_eq!(
            backend
                .shared
                .borrow()
                .get(&FakeBackend::slot("service", "account"))
                .map(Vec::as_slice),
            Some(b"legacy".as_slice())
        );
    }

    #[test]
    fn read_reconciled_backfills_legacy_when_only_shared_exists() {
        let backend = FakeBackend::default();
        backend.insert_shared("service", "account", b"protected");

        let value = read_reconciled(&backend, "service", "account").unwrap();

        assert_eq!(value.as_deref(), Some(b"protected".as_slice()));
        assert_eq!(
            backend
                .legacy
                .borrow()
                .get(&FakeBackend::slot("service", "account"))
                .map(Vec::as_slice),
            Some(b"protected".as_slice())
        );
    }

    #[test]
    fn read_reconciled_uses_legacy_winner_when_backfill_loses_create_race() {
        let backend = FakeBackend::default();
        backend.insert_shared("service", "account", b"protected");
        *backend.legacy_value_inserted_before_add.borrow_mut() = Some(b"legacy".to_vec());

        let value = read_reconciled(&backend, "service", "account").unwrap();

        assert_eq!(value.as_deref(), Some(b"legacy".as_slice()));
        assert_eq!(
            backend
                .shared
                .borrow()
                .get(&FakeBackend::slot("service", "account"))
                .map(Vec::as_slice),
            Some(b"legacy".as_slice())
        );
    }

    #[test]
    fn read_reconciled_accepts_existing_identical_compatibility_copies() {
        let backend = FakeBackend::default();
        backend.insert_legacy("service", "account", b"secret");
        backend.insert_shared("service", "account", b"secret");

        let result = read_reconciled(&backend, "service", "account").unwrap();

        assert_eq!(result.as_deref(), Some(b"secret".as_slice()));
        assert!(!backend.legacy.borrow().is_empty());
        assert_eq!(backend.normalized_shared.get(), 1);
    }

    #[test]
    fn read_reconciled_fails_if_shared_changes_during_verification() {
        let backend = FakeBackend::default();
        backend.insert_legacy("service", "account", b"legacy");
        *backend.shared_value_updated_after_write.borrow_mut() = Some(b"protected".to_vec());

        let error = read_reconciled(&backend, "service", "account").unwrap_err();

        assert!(matches!(
            error,
            KeychainStorageError::MigrationVerificationFailed
        ));
        assert_eq!(
            backend
                .shared
                .borrow()
                .get(&FakeBackend::slot("service", "account"))
                .map(Vec::as_slice),
            Some(b"protected".as_slice())
        );
        assert!(!backend.legacy.borrow().is_empty());
    }

    #[test]
    fn read_reconciled_never_deletes_a_shared_value_updated_after_repair() {
        let backend = FakeBackend::default();
        backend.insert_legacy("service", "account", b"legacy");
        *backend.shared_value_updated_after_write.borrow_mut() = Some(b"concurrent".to_vec());

        let error = read_reconciled(&backend, "service", "account").unwrap_err();

        assert!(matches!(
            error,
            KeychainStorageError::MigrationVerificationFailed
        ));
        assert_eq!(
            backend
                .shared
                .borrow()
                .get(&FakeBackend::slot("service", "account"))
                .map(Vec::as_slice),
            Some(b"concurrent".as_slice())
        );
        assert!(!backend.legacy.borrow().is_empty());
    }

    #[test]
    fn read_reconciled_never_attempts_automatic_legacy_cleanup() {
        let backend = FakeBackend::default();
        backend.insert_legacy("service", "account", b"secret");
        backend.reject_legacy_delete.set(true);

        let value = read_reconciled(&backend, "service", "account").unwrap();

        assert_eq!(value.as_deref(), Some(b"secret".as_slice()));
        assert!(!backend.shared.borrow().is_empty());
        assert!(!backend.legacy.borrow().is_empty());
    }

    #[test]
    fn read_reconciled_ignores_legacy_after_persistent_cutover() {
        let backend = FakeBackend::default();
        backend.insert_shared("service", "account", b"protected");
        backend.insert_legacy("service", "account", b"legacy");
        backend.insert_shared("service", LEGACY_CUTOVER_ACCOUNT, LEGACY_CUTOVER_VALUE);

        let value = read_reconciled(&backend, "service", "account").unwrap();

        assert_eq!(value.as_deref(), Some(b"protected".as_slice()));
        assert_eq!(
            backend
                .legacy
                .borrow()
                .get(&FakeBackend::slot("service", "account"))
                .map(Vec::as_slice),
            Some(b"legacy".as_slice())
        );
    }

    #[test]
    fn write_reconciled_creates_both_compatibility_copies() {
        let backend = FakeBackend::default();

        write_reconciled(&backend, "service", "account", b"secret").unwrap();

        assert_eq!(
            backend
                .shared
                .borrow()
                .get(&FakeBackend::slot("service", "account"))
                .map(Vec::as_slice),
            Some(b"secret".as_slice())
        );
        assert_eq!(
            backend
                .legacy
                .borrow()
                .get(&FakeBackend::slot("service", "account"))
                .map(Vec::as_slice),
            Some(b"secret".as_slice())
        );
    }

    #[test]
    fn write_reconciled_updates_both_compatibility_copies() {
        let backend = FakeBackend::default();
        backend.insert_legacy("service", "account", b"old");

        write_reconciled(&backend, "service", "account", b"new").unwrap();

        assert_eq!(
            backend
                .shared
                .borrow()
                .get(&FakeBackend::slot("service", "account"))
                .map(Vec::as_slice),
            Some(b"new".as_slice())
        );
        assert_eq!(
            backend
                .legacy
                .borrow()
                .get(&FakeBackend::slot("service", "account"))
                .map(Vec::as_slice),
            Some(b"new".as_slice())
        );
    }

    #[test]
    fn write_reconciled_restores_legacy_after_persistent_shared_failure() {
        let backend = FakeBackend::default();
        backend.insert_shared("service", "account", b"old");
        backend.insert_legacy("service", "account", b"old");
        backend.shared_write_failures_remaining.set(2);

        write_reconciled(&backend, "service", "account", b"new").unwrap_err();

        assert_eq!(
            backend
                .shared
                .borrow()
                .get(&FakeBackend::slot("service", "account"))
                .map(Vec::as_slice),
            Some(b"old".as_slice())
        );
        assert_eq!(
            backend
                .legacy
                .borrow()
                .get(&FakeBackend::slot("service", "account"))
                .map(Vec::as_slice),
            Some(b"old".as_slice())
        );
    }

    #[test]
    fn write_reconciled_rollback_preserves_a_concurrent_legacy_update() {
        let backend = FakeBackend::default();
        backend.insert_shared("service", "account", b"old");
        backend.insert_legacy("service", "account", b"old");
        backend.shared_write_failures_remaining.set(2);
        *backend.legacy_value_updated_on_shared_failure.borrow_mut() = Some(b"concurrent".to_vec());

        let error = write_reconciled(&backend, "service", "account", b"new").unwrap_err();

        assert!(matches!(error, KeychainStorageError::MigrationConflict));
        assert_eq!(
            backend
                .shared
                .borrow()
                .get(&FakeBackend::slot("service", "account"))
                .map(Vec::as_slice),
            Some(b"old".as_slice())
        );
        assert_eq!(
            backend
                .legacy
                .borrow()
                .get(&FakeBackend::slot("service", "account"))
                .map(Vec::as_slice),
            Some(b"concurrent".as_slice())
        );
    }

    #[test]
    fn write_reconciled_recovers_a_transient_shared_failure() {
        let backend = FakeBackend::default();
        backend.shared_write_failures_remaining.set(1);

        write_reconciled(&backend, "service", "account", b"new").unwrap();

        assert_eq!(
            backend
                .shared
                .borrow()
                .get(&FakeBackend::slot("service", "account"))
                .map(Vec::as_slice),
            Some(b"new".as_slice())
        );
        assert_eq!(
            backend
                .legacy
                .borrow()
                .get(&FakeBackend::slot("service", "account"))
                .map(Vec::as_slice),
            Some(b"new".as_slice())
        );
    }

    #[test]
    fn write_reconciled_stops_dual_writing_after_persistent_cutover() {
        let backend = FakeBackend::default();
        backend.insert_shared("service", "account", b"protected");
        backend.insert_legacy("service", "account", b"legacy");
        backend.insert_shared("service", LEGACY_CUTOVER_ACCOUNT, LEGACY_CUTOVER_VALUE);

        write_reconciled(&backend, "service", "account", b"new").unwrap();

        assert_eq!(
            backend
                .shared
                .borrow()
                .get(&FakeBackend::slot("service", "account"))
                .map(Vec::as_slice),
            Some(b"new".as_slice())
        );
        assert_eq!(
            backend
                .legacy
                .borrow()
                .get(&FakeBackend::slot("service", "account"))
                .map(Vec::as_slice),
            Some(b"legacy".as_slice())
        );
    }

    #[test]
    fn get_or_insert_creates_both_compatibility_copies() {
        let backend = FakeBackend::default();

        let value = get_or_insert_reconciled(&backend, "service", "account", b"candidate").unwrap();

        assert_eq!(value, b"candidate");
        assert_eq!(
            backend
                .shared
                .borrow()
                .get(&FakeBackend::slot("service", "account"))
                .map(Vec::as_slice),
            Some(b"candidate".as_slice())
        );
        assert_eq!(
            backend
                .legacy
                .borrow()
                .get(&FakeBackend::slot("service", "account"))
                .map(Vec::as_slice),
            Some(b"candidate".as_slice())
        );
    }

    #[test]
    fn get_or_insert_removes_legacy_candidate_after_persistent_shared_failure() {
        let backend = FakeBackend::default();
        backend.shared_write_failures_remaining.set(2);

        get_or_insert_reconciled(&backend, "service", "account", b"candidate").unwrap_err();

        assert!(backend.shared.borrow().is_empty());
        assert!(backend.legacy.borrow().is_empty());
        assert_eq!(
            get_or_insert_reconciled(&backend, "service", "account", b"candidate").unwrap(),
            b"candidate"
        );
    }

    #[test]
    fn get_or_insert_recovers_a_transient_shared_failure() {
        let backend = FakeBackend::default();
        backend.shared_write_failures_remaining.set(1);

        let value = get_or_insert_reconciled(&backend, "service", "account", b"candidate").unwrap();

        assert_eq!(value, b"candidate");
        assert_eq!(
            backend
                .shared
                .borrow()
                .get(&FakeBackend::slot("service", "account"))
                .map(Vec::as_slice),
            Some(b"candidate".as_slice())
        );
        assert_eq!(
            backend
                .legacy
                .borrow()
                .get(&FakeBackend::slot("service", "account"))
                .map(Vec::as_slice),
            Some(b"candidate".as_slice())
        );
    }

    #[test]
    fn get_or_insert_uses_concurrent_legacy_winner() {
        let backend = FakeBackend::default();
        *backend.legacy_value_inserted_before_add.borrow_mut() = Some(b"winner".to_vec());

        let value = get_or_insert_reconciled(&backend, "service", "account", b"candidate").unwrap();

        assert_eq!(value, b"winner");
        assert_eq!(
            backend
                .shared
                .borrow()
                .get(&FakeBackend::slot("service", "account"))
                .map(Vec::as_slice),
            Some(b"winner".as_slice())
        );
    }

    #[test]
    fn get_or_insert_stops_creating_legacy_after_persistent_cutover() {
        let backend = FakeBackend::default();
        backend.insert_shared("service", LEGACY_CUTOVER_ACCOUNT, LEGACY_CUTOVER_VALUE);

        let value = get_or_insert_reconciled(&backend, "service", "account", b"candidate").unwrap();

        assert_eq!(value, b"candidate");
        assert!(backend.legacy.borrow().is_empty());
    }

    #[test]
    fn write_reconciled_never_rolls_back_a_concurrent_shared_update() {
        let backend = FakeBackend::default();
        backend.insert_shared("service", "account", b"previous");
        *backend.shared_value_updated_after_write.borrow_mut() = Some(b"concurrent".to_vec());

        let error = write_reconciled(&backend, "service", "account", b"requested").unwrap_err();

        assert!(matches!(error, KeychainStorageError::MigrationConflict));
        assert_eq!(
            backend
                .shared
                .borrow()
                .get(&FakeBackend::slot("service", "account"))
                .map(Vec::as_slice),
            Some(b"concurrent".as_slice())
        );
        assert_eq!(
            backend
                .legacy
                .borrow()
                .get(&FakeBackend::slot("service", "account"))
                .map(Vec::as_slice),
            Some(b"previous".as_slice())
        );
    }

    #[test]
    fn delete_reconciled_removes_legacy_without_migrating_it() {
        let backend = FakeBackend::default();
        backend.insert_legacy("service", "account", b"secret");

        let result = delete_reconciled(&backend, "service", "account");

        assert_eq!(result.unwrap(), KeychainDeleteOutcome::Deleted);
        assert!(backend.shared.borrow().is_empty());
        assert!(backend.legacy.borrow().is_empty());
    }

    #[test]
    fn delete_reconciled_preserves_shared_when_legacy_deletion_is_denied() {
        let backend = FakeBackend::default();
        backend.insert_legacy("service", "account", b"secret");
        backend.insert_shared("service", "account", b"secret");
        backend.reject_legacy_delete.set(true);

        let error = delete_reconciled(&backend, "service", "account").unwrap_err();

        assert!(matches!(
            error,
            KeychainStorageError::Security {
                operation: "delete",
                ..
            }
        ));
        assert_eq!(
            backend
                .legacy
                .borrow()
                .get(&FakeBackend::slot("service", "account"))
                .map(Vec::as_slice),
            Some(b"secret".as_slice())
        );
        assert_eq!(
            backend
                .shared
                .borrow()
                .get(&FakeBackend::slot("service", "account"))
                .map(Vec::as_slice),
            Some(b"secret".as_slice())
        );
    }

    #[test]
    fn delete_reconciled_shared_failure_is_repaired_on_the_next_read() {
        let backend = FakeBackend::default();
        backend.insert_legacy("service", "account", b"secret");
        backend.insert_shared("service", "account", b"secret");
        backend.reject_shared_delete.set(true);

        let error = delete_reconciled(&backend, "service", "account").unwrap_err();

        assert!(matches!(
            error,
            KeychainStorageError::Security {
                operation: "delete",
                ..
            }
        ));
        assert!(backend.legacy.borrow().is_empty());
        assert!(!backend.shared.borrow().is_empty());

        backend.reject_shared_delete.set(false);
        let value = read_reconciled(&backend, "service", "account").unwrap();

        assert_eq!(value.as_deref(), Some(b"secret".as_slice()));
        assert_eq!(
            backend
                .legacy
                .borrow()
                .get(&FakeBackend::slot("service", "account"))
                .map(Vec::as_slice),
            Some(b"secret".as_slice())
        );
    }
}
