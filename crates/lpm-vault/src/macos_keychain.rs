use core_foundation::base::{CFType, CFTypeRef, TCFType};
use core_foundation::boolean::CFBoolean;
use core_foundation::data::CFData;
use core_foundation::dictionary::CFDictionary;
use core_foundation::string::{CFString, CFStringRef};
use security_framework::passwords::{PasswordOptions, delete_generic_password_options};
use security_framework_sys::access_control::kSecAttrAccessibleWhenUnlockedThisDeviceOnly;
use security_framework_sys::item::{
    kSecAttrAccessGroup, kSecAttrAccount, kSecAttrService, kSecAttrSynchronizable, kSecClass,
    kSecClassGenericPassword, kSecReturnData, kSecUseDataProtectionKeychain, kSecValueData,
};
use security_framework_sys::keychain_item::{SecItemAdd, SecItemCopyMatching, SecItemUpdate};

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
    #[error("macOS Keychain verification failed")]
    VerificationFailed,
}

struct SecurityFrameworkBackend;

pub(crate) fn with_keychain_transaction<T>(
    operation: impl FnOnce() -> Result<T, String>,
) -> Result<T, String> {
    crate::storage_transaction::with_vault_transaction(|_| operation())
}

impl SecurityFrameworkBackend {
    fn options(service: &str, account: &str) -> PasswordOptions {
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

    fn identity_pairs(service: &str, account: &str) -> Vec<(CFString, CFType)> {
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

    fn identity_query(service: &str, account: &str) -> CFDictionary<CFString, CFType> {
        CFDictionary::from_CFType_pairs(&Self::identity_pairs(service, account))
    }

    fn attribute_pairs(value: Option<&[u8]>) -> Vec<(CFString, CFType)> {
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

    fn read(service: &str, account: &str) -> Result<Option<Vec<u8>>, KeychainStorageError> {
        let mut pairs = Self::identity_pairs(service, account);
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
            return Err(Self::map_status("read", status));
        }
        if result.is_null() {
            return Err(KeychainStorageError::VerificationFailed);
        }
        let value = unsafe { CFType::wrap_under_create_rule(result) };
        let data = value
            .downcast_into::<CFData>()
            .ok_or(KeychainStorageError::VerificationFailed)?;
        Ok(Some(data.bytes().to_vec()))
    }

    fn add(service: &str, account: &str, value: &[u8]) -> Result<(), KeychainStorageError> {
        let mut pairs = Self::identity_pairs(service, account);
        pairs.extend(Self::attribute_pairs(Some(value)));
        let attributes = CFDictionary::from_CFType_pairs(&pairs);
        let status = unsafe { SecItemAdd(attributes.as_concrete_TypeRef(), std::ptr::null_mut()) };
        match status {
            0 => Ok(()),
            ERR_SEC_DUPLICATE_ITEM => Err(KeychainStorageError::DuplicateItem),
            status => Err(Self::map_status("add", status)),
        }
    }

    fn update(service: &str, account: &str, value: &[u8]) -> Result<(), KeychainStorageError> {
        let query = Self::identity_query(service, account);
        let attributes = CFDictionary::from_CFType_pairs(&Self::attribute_pairs(Some(value)));
        let status = unsafe {
            SecItemUpdate(
                query.as_concrete_TypeRef(),
                attributes.as_concrete_TypeRef(),
            )
        };
        if status == 0 {
            Ok(())
        } else {
            Err(Self::map_status("write", status))
        }
    }

    fn write(service: &str, account: &str, value: &[u8]) -> Result<(), KeychainStorageError> {
        match Self::add(service, account, value) {
            Ok(()) => Ok(()),
            Err(KeychainStorageError::DuplicateItem) => Self::update(service, account, value),
            Err(error) => Err(error),
        }
    }
}

pub(crate) fn read_string(service: &str, account: &str) -> Result<Option<String>, String> {
    SecurityFrameworkBackend::read(service, account)
        .and_then(|value| {
            value
                .map(String::from_utf8)
                .transpose()
                .map_err(|_| KeychainStorageError::InvalidUtf8)
        })
        .map_err(|error| error.to_string())
}

pub(crate) fn write_string(service: &str, account: &str, value: &str) -> Result<(), String> {
    SecurityFrameworkBackend::write(service, account, value.as_bytes())
        .and_then(
            |()| match SecurityFrameworkBackend::read(service, account)? {
                Some(stored) if stored == value.as_bytes() => Ok(()),
                _ => Err(KeychainStorageError::VerificationFailed),
            },
        )
        .map_err(|error| error.to_string())
}

pub(crate) fn get_or_insert_string(
    service: &str,
    account: &str,
    candidate: &str,
) -> Result<String, String> {
    get_or_insert_with_backend(
        candidate.as_bytes(),
        || SecurityFrameworkBackend::read(service, account),
        |value| SecurityFrameworkBackend::add(service, account, value),
    )
    .and_then(|value| String::from_utf8(value).map_err(|_| KeychainStorageError::InvalidUtf8))
    .map_err(|error| error.to_string())
}

fn get_or_insert_with_backend(
    candidate: &[u8],
    mut read: impl FnMut() -> Result<Option<Vec<u8>>, KeychainStorageError>,
    mut add: impl FnMut(&[u8]) -> Result<(), KeychainStorageError>,
) -> Result<Vec<u8>, KeychainStorageError> {
    if let Some(value) = read()? {
        return Ok(value);
    }
    match add(candidate) {
        Ok(()) => match read()? {
            Some(value) if value == candidate => Ok(value),
            _ => Err(KeychainStorageError::VerificationFailed),
        },
        Err(KeychainStorageError::DuplicateItem) => {
            read()?.ok_or(KeychainStorageError::VerificationFailed)
        }
        Err(error) => Err(error),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KeychainDeleteOutcome {
    Deleted,
    NotFound,
}

pub(crate) fn delete(service: &str, account: &str) -> Result<KeychainDeleteOutcome, String> {
    match delete_generic_password_options(SecurityFrameworkBackend::options(service, account)) {
        Ok(()) => Ok(KeychainDeleteOutcome::Deleted),
        Err(error) if error.code() == ERR_SEC_ITEM_NOT_FOUND => Ok(KeychainDeleteOutcome::NotFound),
        Err(error) => Err(SecurityFrameworkBackend::map_error("delete", error).to_string()),
    }
}

#[cfg(test)]
mod tests {
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
    fn shared_query_uses_the_data_protection_access_group() {
        let pairs = SecurityFrameworkBackend::identity_pairs("service", "account");
        let keys = pairs
            .iter()
            .map(|(key, _)| key.to_string())
            .collect::<Vec<_>>();
        let access_group =
            unsafe { CFString::wrap_under_get_rule(kSecAttrAccessGroup) }.to_string();
        let protected =
            unsafe { CFString::wrap_under_get_rule(kSecUseDataProtectionKeychain) }.to_string();

        assert!(keys.contains(&access_group));
        assert!(keys.contains(&protected));
    }

    #[test]
    fn successful_get_or_insert_add_is_read_back_once() {
        let reads = std::cell::Cell::new(0);
        let stored = std::cell::RefCell::new(None);

        let value = get_or_insert_with_backend(
            b"candidate",
            || {
                reads.set(reads.get() + 1);
                Ok(stored.borrow().clone())
            },
            |candidate| {
                *stored.borrow_mut() = Some(candidate.to_vec());
                Ok(())
            },
        )
        .expect("a verified add should succeed");

        assert_eq!(value, b"candidate");
        assert_eq!(reads.get(), 2);
    }

    #[test]
    fn duplicate_get_or_insert_returns_the_concurrent_winner() {
        let mut reads = 0;

        let value = get_or_insert_with_backend(
            b"candidate",
            || {
                reads += 1;
                Ok((reads == 2).then(|| b"winner".to_vec()))
            },
            |_| Err(KeychainStorageError::DuplicateItem),
        )
        .expect("a concurrent winner should be preserved");

        assert_eq!(value, b"winner");
        assert_eq!(reads, 2);
    }
}
