use core_foundation::base::{CFType, CFTypeRef, TCFType};
use core_foundation::data::CFData;
use core_foundation::dictionary::CFDictionary;
use core_foundation::string::CFString;
use security_framework::os::macos::keychain::SecKeychain;
use security_framework_sys::item::{
    kSecAttrAccount, kSecAttrService, kSecClass, kSecClassGenericPassword, kSecReturnData,
    kSecUseKeychain, kSecValueData,
};
use security_framework_sys::keychain_item::{
    SecItemAdd, SecItemCopyMatching, SecItemDelete, SecItemUpdate,
};

const ERR_SEC_ITEM_NOT_FOUND: i32 = -25300;
const ERR_SEC_DUPLICATE_ITEM: i32 = -25299;
const ERR_SEC_INTERACTION_NOT_ALLOWED: i32 = -25308;

#[cfg(test)]
pub(crate) const SHARED_ACCESS_GROUP: &str = "823S8YKMRW.dev.lpm.vault.shared";

#[derive(Debug, thiserror::Error)]
enum LegacyKeychainError {
    #[error(
        "the macOS login Keychain is locked or unavailable; unlock the login Keychain with `security unlock-keychain ~/Library/Keychains/login.keychain-db` and retry"
    )]
    InteractionNotAllowed,
    #[error("macOS legacy Keychain {operation} failed (OSStatus {code})")]
    Security { operation: &'static str, code: i32 },
    #[error("macOS legacy Keychain value is not valid UTF-8")]
    InvalidUtf8,
    #[error("macOS legacy Keychain item already exists")]
    DuplicateItem,
    #[error("macOS legacy Keychain verification failed")]
    VerificationFailed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KeychainDeleteOutcome {
    Deleted,
    NotFound,
}

fn map_status(operation: &'static str, code: i32) -> LegacyKeychainError {
    match code {
        ERR_SEC_INTERACTION_NOT_ALLOWED => LegacyKeychainError::InteractionNotAllowed,
        code => LegacyKeychainError::Security { operation, code },
    }
}

fn identity_pairs(
    service: &str,
    account: &str,
) -> Result<Vec<(CFString, CFType)>, LegacyKeychainError> {
    let keychain =
        SecKeychain::default().map_err(|error| map_status("locate Keychain", error.code()))?;
    Ok(identity_pairs_with_keychain(
        service,
        account,
        keychain.into_CFType(),
    ))
}

fn identity_pairs_with_keychain(
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

fn query(
    service: &str,
    account: &str,
) -> Result<CFDictionary<CFString, CFType>, LegacyKeychainError> {
    Ok(CFDictionary::from_CFType_pairs(&identity_pairs(
        service, account,
    )?))
}

fn read_bytes(service: &str, account: &str) -> Result<Option<Vec<u8>>, LegacyKeychainError> {
    let mut pairs = identity_pairs(service, account)?;
    pairs.push((
        unsafe { CFString::wrap_under_get_rule(kSecReturnData) },
        core_foundation::boolean::CFBoolean::from(true).into_CFType(),
    ));
    let query = CFDictionary::from_CFType_pairs(&pairs);
    let mut result: CFTypeRef = std::ptr::null();
    let status = unsafe { SecItemCopyMatching(query.as_concrete_TypeRef(), &mut result) };
    if status == ERR_SEC_ITEM_NOT_FOUND {
        return Ok(None);
    }
    if status != 0 {
        return Err(map_status("read", status));
    }
    if result.is_null() {
        return Err(LegacyKeychainError::Security {
            operation: "read result",
            code: -2070,
        });
    }

    // SAFETY: A successful SecItemCopyMatching call returns an owned CF object.
    let value = unsafe { CFType::wrap_under_create_rule(result) };
    let data = value
        .downcast_into::<CFData>()
        .ok_or(LegacyKeychainError::Security {
            operation: "read result",
            code: -2070,
        })?;
    Ok(Some(data.bytes().to_vec()))
}

fn add_bytes(service: &str, account: &str, value: &[u8]) -> Result<(), LegacyKeychainError> {
    let mut pairs = identity_pairs(service, account)?;
    pairs.push((
        unsafe { CFString::wrap_under_get_rule(kSecValueData) },
        CFData::from_buffer(value).into_CFType(),
    ));
    let attributes = CFDictionary::from_CFType_pairs(&pairs);
    match unsafe { SecItemAdd(attributes.as_concrete_TypeRef(), std::ptr::null_mut()) } {
        0 => Ok(()),
        ERR_SEC_DUPLICATE_ITEM => Err(LegacyKeychainError::DuplicateItem),
        status => Err(map_status("add", status)),
    }
}

fn write_bytes(service: &str, account: &str, value: &[u8]) -> Result<(), LegacyKeychainError> {
    match add_bytes(service, account, value) {
        Ok(()) => {}
        Err(LegacyKeychainError::DuplicateItem) => {
            let query = query(service, account)?;
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
            if status != 0 {
                return Err(map_status("write", status));
            }
        }
        Err(error) => return Err(error),
    }
    if read_bytes(service, account)?.as_deref() == Some(value) {
        Ok(())
    } else {
        Err(LegacyKeychainError::VerificationFailed)
    }
}

pub(crate) fn with_keychain_transaction<T>(
    operation: impl FnOnce() -> Result<T, String>,
) -> Result<T, String> {
    crate::storage_transaction::with_vault_transaction(|_| operation())
}

pub(crate) fn read_string(service: &str, account: &str) -> Result<Option<String>, String> {
    read_bytes(service, account)
        .and_then(|value| {
            value
                .map(String::from_utf8)
                .transpose()
                .map_err(|_| LegacyKeychainError::InvalidUtf8)
        })
        .map_err(|error| error.to_string())
}

pub(crate) fn write_string(service: &str, account: &str, value: &str) -> Result<(), String> {
    write_bytes(service, account, value.as_bytes()).map_err(|error| error.to_string())
}

pub(crate) fn get_or_insert_string(
    service: &str,
    account: &str,
    candidate: &str,
) -> Result<String, String> {
    let result = match read_bytes(service, account) {
        Ok(Some(existing)) => Ok(existing),
        Ok(None) => match add_bytes(service, account, candidate.as_bytes()) {
            Ok(()) => Ok(candidate.as_bytes().to_vec()),
            Err(LegacyKeychainError::DuplicateItem) => read_bytes(service, account)
                .and_then(|value| value.ok_or(LegacyKeychainError::VerificationFailed)),
            Err(error) => Err(error),
        },
        Err(error) => Err(error),
    };
    result
        .and_then(|value| String::from_utf8(value).map_err(|_| LegacyKeychainError::InvalidUtf8))
        .map_err(|error| error.to_string())
}

pub(crate) fn delete(service: &str, account: &str) -> Result<KeychainDeleteOutcome, String> {
    let query = query(service, account).map_err(|error| error.to_string())?;
    match unsafe { SecItemDelete(query.as_concrete_TypeRef()) } {
        0 => Ok(KeychainDeleteOutcome::Deleted),
        ERR_SEC_ITEM_NOT_FOUND => Ok(KeychainDeleteOutcome::NotFound),
        status => Err(map_status("delete", status).to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_compatibility_queries_pin_the_default_file_keychain() {
        let pairs = identity_pairs_with_keychain(
            "service",
            "account",
            CFString::from("test-keychain").into_CFType(),
        );
        let keychain_key = unsafe { CFString::wrap_under_get_rule(kSecUseKeychain) };

        assert!(pairs.iter().any(|(key, _)| key == &keychain_key));
    }
}
