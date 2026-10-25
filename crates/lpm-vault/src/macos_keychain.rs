use core_foundation::base::{CFType, CFTypeRef, TCFType};
use core_foundation::boolean::CFBoolean;
use core_foundation::data::CFData;
use core_foundation::dictionary::CFDictionary;
use core_foundation::string::{CFString, CFStringRef};
use security_framework::access_control::SecAccessControl;
use security_framework::passwords::{PasswordOptions, delete_generic_password_options};
use security_framework_sys::access_control::kSecAttrAccessibleWhenUnlockedThisDeviceOnly;
use security_framework_sys::item::{
    kSecAttrAccessGroup, kSecAttrAccount, kSecAttrService, kSecAttrSynchronizable, kSecClass,
    kSecClassGenericPassword, kSecMatchLimit, kSecMatchLimitAll, kSecReturnAttributes,
    kSecReturnData, kSecUseAuthenticationContext, kSecUseDataProtectionKeychain, kSecValueData,
};
use security_framework_sys::keychain_item::{SecItemAdd, SecItemCopyMatching, SecItemUpdate};

#[link(name = "Security", kind = "framework")]
unsafe extern "C" {
    static kSecAttrAccessible: CFStringRef;
    static kSecAttrAccessControl: CFStringRef;
    static kSecAttrGeneric: CFStringRef;
    static kSecUseOperationPrompt: CFStringRef;
}

/// The reason the approval prompt gives for reading `account`: a values
/// item is named by its vault ID, a companion record by what it holds.
fn operation_prompt(account: &str) -> String {
    use crate::companion::account::CompanionAccount;
    match CompanionAccount::parse(account) {
        Some(record) => {
            let holds = match record.kind() {
                Some(crate::companion::overrides::OVERRIDES_KIND) => "personal overrides",
                _ => "newer data",
            };
            format!(
                "Allow LPM CLI to access env project {}'s {holds}",
                record.vault_id()
            )
        }
        None => format!("Allow LPM CLI to access env project {account}"),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CliAccess {
    Automatic,
    RequireApproval,
}

/// The CLI approval an item's attributes claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ClaimedAccess {
    Automatic,
    RequireApproval,
    /// A marker other than the approval marker, or the approval marker
    /// without an access control.
    Contradictory,
}

const APPROVAL_MARKER: &[u8] = b"lpm-cli-access:require-approval:v1";

thread_local! {
    // Keep native approval within this CLI invocation; never persist or export it.
    static AUTHENTICATION_CONTEXT: std::cell::RefCell<Option<CFType>> = const { std::cell::RefCell::new(None) };
}

fn authentication_context() -> CFType {
    AUTHENTICATION_CONTEXT.with_borrow_mut(|stored| {
        stored
            .get_or_insert_with(|| {
                // SAFETY: The query retains the LAContext before its owning reference is released.
                let context = unsafe { objc2_local_authentication::LAContext::new() };
                let pointer = std::ptr::from_ref(&*context).cast::<std::ffi::c_void>();
                unsafe { CFType::wrap_under_get_rule(pointer) }
            })
            .clone()
    })
}

/// A context that never shows authentication UI and never reuses an earlier
/// authentication, so a read through it shows whether an item demands user
/// presence. It's never installed as the thread's context.
fn non_interactive_context() -> CFType {
    // SAFETY: `wrap_under_get_rule` retains the LAContext before its owning reference is released.
    let context = unsafe { objc2_local_authentication::LAContext::new() };
    unsafe {
        context.setInteractionNotAllowed(true);
        context.setTouchIDAuthenticationAllowableReuseDuration(0.0);
    }
    let pointer = std::ptr::from_ref(&*context).cast::<std::ffi::c_void>();
    unsafe { CFType::wrap_under_get_rule(pointer) }
}

/// What reading an item without authentication UI showed about its access.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProbeOutcome {
    /// The item read without user presence.
    Automatic,
    /// The item demanded user presence while an open item in the same
    /// Keychain read.
    Protected,
    Absent,
    /// The Keychain may be unavailable, such as while the Mac is locked, so
    /// nothing about the item's access can be concluded.
    Inconclusive,
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
        "the macOS Data Protection Keychain is locked or native env approval is unavailable in this session; retry from an interactive macOS login, or unlock a locked login Keychain with `security unlock-keychain ~/Library/Keychains/login.keychain-db`"
    )]
    InteractionNotAllowed,
    #[error("env access approval was cancelled; no secrets were released")]
    ApprovalCancelled,
    #[error("env access approval failed; no secrets were released")]
    ApprovalFailed,
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
            -128 => KeychainStorageError::ApprovalCancelled,
            -25293 => KeychainStorageError::ApprovalFailed,
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

    fn attribute_pairs(value: Option<&[u8]>) -> Vec<(CFString, CFType)> {
        let mut pairs = Vec::with_capacity(1);
        if let Some(value) = value {
            pairs.push((
                unsafe { CFString::wrap_under_get_rule(kSecValueData) },
                CFData::from_buffer(value).into_CFType(),
            ));
        }
        pairs
    }

    fn access_pairs(access: CliAccess) -> Result<Vec<(CFString, CFType)>, KeychainStorageError> {
        if access == CliAccess::Automatic {
            return Ok(vec![(
                unsafe { CFString::wrap_under_get_rule(kSecAttrAccessible) },
                unsafe {
                    CFString::wrap_under_get_rule(kSecAttrAccessibleWhenUnlockedThisDeviceOnly)
                }
                .into_CFType(),
            )]);
        }
        let control = SecAccessControl::create_with_protection(
            Some(security_framework::access_control::ProtectionMode::AccessibleWhenUnlockedThisDeviceOnly),
            security_framework_sys::access_control::kSecAccessControlUserPresence,
        ).map_err(|error| Self::map_error("create env approval", error))?;
        Ok(vec![
            (
                unsafe { CFString::wrap_under_get_rule(kSecAttrAccessControl) },
                control.into_CFType(),
            ),
            (
                unsafe { CFString::wrap_under_get_rule(kSecAttrGeneric) },
                CFData::from_buffer(APPROVAL_MARKER).into_CFType(),
            ),
        ])
    }

    fn cli_access(service: &str, account: &str) -> Result<CliAccess, KeychainStorageError> {
        let mut pairs = Self::identity_pairs(service, account);
        pairs.push((
            unsafe { CFString::wrap_under_get_rule(kSecUseAuthenticationContext) },
            authentication_context(),
        ));
        pairs.push((
            unsafe { CFString::wrap_under_get_rule(kSecReturnAttributes) },
            CFBoolean::from(true).into_CFType(),
        ));
        let query = CFDictionary::from_CFType_pairs(&pairs);
        let mut result: CFTypeRef = std::ptr::null();
        let status = unsafe { SecItemCopyMatching(query.as_concrete_TypeRef(), &mut result) };
        if status == ERR_SEC_ITEM_NOT_FOUND {
            return Ok(CliAccess::Automatic);
        }
        if status != 0 {
            return Err(Self::map_status("read env access policy", status));
        }
        if result.is_null() {
            return Err(KeychainStorageError::VerificationFailed);
        }
        let attributes = unsafe { CFType::wrap_under_create_rule(result) }
            .downcast_into::<CFDictionary>()
            .ok_or(KeychainStorageError::VerificationFailed)?;
        // SAFETY: The successful downcast established the dictionary's type; keys and values come from Security.framework.
        let attributes: CFDictionary<CFString, CFType> =
            unsafe { CFDictionary::wrap_under_get_rule(attributes.as_concrete_TypeRef()) };
        Self::classify(&attributes)
    }

    /// An item's CLI approval as its attributes claim it: the approval marker
    /// with an access control, or no marker (or an empty one, which the app
    /// writes when approval is off), in the one accessibility class LPM
    /// writes. Any other combination is contradictory.
    fn classify(
        attributes: &CFDictionary<CFString, CFType>,
    ) -> Result<CliAccess, KeychainStorageError> {
        let accessible = unsafe { CFString::wrap_under_get_rule(kSecAttrAccessible) };
        if let Some(class) = attributes.find(&accessible) {
            let class = class
                .downcast::<CFString>()
                .ok_or(KeychainStorageError::VerificationFailed)?;
            if class
                != unsafe {
                    CFString::wrap_under_get_rule(kSecAttrAccessibleWhenUnlockedThisDeviceOnly)
                }
            {
                return Err(KeychainStorageError::VerificationFailed);
            }
        }
        let generic = unsafe { CFString::wrap_under_get_rule(kSecAttrGeneric) };
        let Some(marker) = attributes.find(&generic) else {
            return Ok(CliAccess::Automatic);
        };
        let marker = marker
            .downcast::<CFData>()
            .ok_or(KeychainStorageError::VerificationFailed)?;
        if marker.bytes().is_empty() {
            return Ok(CliAccess::Automatic);
        }
        let control = unsafe { CFString::wrap_under_get_rule(kSecAttrAccessControl) };
        if marker.bytes() == APPROVAL_MARKER
            && attributes
                .find(&control)
                .is_some_and(|value| value.downcast::<SecAccessControl>().is_some())
        {
            Ok(CliAccess::RequireApproval)
        } else {
            Err(KeychainStorageError::VerificationFailed)
        }
    }

    fn read(service: &str, account: &str) -> Result<Option<Vec<u8>>, KeychainStorageError> {
        Self::read_with_context(service, account, authentication_context())
    }

    /// Read an item's data and the approval its attributes claim, in one
    /// Security.framework call, so they describe the same item.
    fn read_with_access(
        service: &str,
        account: &str,
    ) -> Result<Option<(Vec<u8>, ClaimedAccess)>, KeychainStorageError> {
        let mut pairs = Self::identity_pairs(service, account);
        pairs.push((
            unsafe { CFString::wrap_under_get_rule(kSecUseAuthenticationContext) },
            authentication_context(),
        ));
        pairs.push((
            unsafe { CFString::wrap_under_get_rule(kSecUseOperationPrompt) },
            CFString::from(operation_prompt(account).as_str()).into_CFType(),
        ));
        for key in [unsafe { kSecReturnData }, unsafe { kSecReturnAttributes }] {
            pairs.push((
                unsafe { CFString::wrap_under_get_rule(key) },
                CFBoolean::from(true).into_CFType(),
            ));
        }
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
        let attributes = unsafe { CFType::wrap_under_create_rule(result) }
            .downcast_into::<CFDictionary>()
            .ok_or(KeychainStorageError::VerificationFailed)?;
        // SAFETY: The successful downcast established the dictionary's type; keys and values come from Security.framework.
        let attributes: CFDictionary<CFString, CFType> =
            unsafe { CFDictionary::wrap_under_get_rule(attributes.as_concrete_TypeRef()) };
        let data_key = unsafe { CFString::wrap_under_get_rule(kSecValueData) };
        let data = attributes
            .find(&data_key)
            .and_then(|value| value.downcast::<CFData>())
            .ok_or(KeychainStorageError::VerificationFailed)?;
        Ok(Some((data.bytes().to_vec(), Self::claim(&attributes))))
    }

    fn claim(attributes: &CFDictionary<CFString, CFType>) -> ClaimedAccess {
        match Self::classify(attributes) {
            Ok(CliAccess::Automatic) => ClaimedAccess::Automatic,
            Ok(CliAccess::RequireApproval) => ClaimedAccess::RequireApproval,
            Err(_) => ClaimedAccess::Contradictory,
        }
    }

    /// The approval `account`'s attributes claim, or `None` when it's absent.
    fn claimed_access(
        service: &str,
        account: &str,
    ) -> Result<Option<ClaimedAccess>, KeychainStorageError> {
        let mut pairs = Self::identity_pairs(service, account);
        pairs.push((
            unsafe { CFString::wrap_under_get_rule(kSecUseAuthenticationContext) },
            non_interactive_context(),
        ));
        pairs.push((
            unsafe { CFString::wrap_under_get_rule(kSecReturnAttributes) },
            CFBoolean::from(true).into_CFType(),
        ));
        let query = CFDictionary::from_CFType_pairs(&pairs);
        let mut result: CFTypeRef = std::ptr::null();
        let status = unsafe { SecItemCopyMatching(query.as_concrete_TypeRef(), &mut result) };
        if status == ERR_SEC_ITEM_NOT_FOUND {
            return Ok(None);
        }
        if status != 0 {
            return Err(Self::map_status("read env access policy", status));
        }
        if result.is_null() {
            return Err(KeychainStorageError::VerificationFailed);
        }
        let attributes = unsafe { CFType::wrap_under_create_rule(result) }
            .downcast_into::<CFDictionary>()
            .ok_or(KeychainStorageError::VerificationFailed)?;
        // SAFETY: The successful downcast established the dictionary's type; keys and values come from Security.framework.
        let attributes: CFDictionary<CFString, CFType> =
            unsafe { CFDictionary::wrap_under_get_rule(attributes.as_concrete_TypeRef()) };
        Ok(Some(Self::claim(&attributes)))
    }

    /// The account names of every item in `service`, from attributes alone,
    /// without authentication UI.
    fn account_names(service: &str) -> Result<Vec<String>, KeychainStorageError> {
        let mut pairs = Self::identity_pairs(service, "");
        let account_key = unsafe { CFString::wrap_under_get_rule(kSecAttrAccount) };
        pairs.retain(|(key, _)| key != &account_key);
        pairs.push((
            unsafe { CFString::wrap_under_get_rule(kSecUseAuthenticationContext) },
            non_interactive_context(),
        ));
        pairs.push((
            unsafe { CFString::wrap_under_get_rule(kSecReturnAttributes) },
            CFBoolean::from(true).into_CFType(),
        ));
        pairs.push((
            unsafe { CFString::wrap_under_get_rule(kSecMatchLimit) },
            unsafe { CFString::wrap_under_get_rule(kSecMatchLimitAll) }.into_CFType(),
        ));
        let query = CFDictionary::from_CFType_pairs(&pairs);
        let mut result: CFTypeRef = std::ptr::null();
        let status = unsafe { SecItemCopyMatching(query.as_concrete_TypeRef(), &mut result) };
        if status == ERR_SEC_ITEM_NOT_FOUND {
            return Ok(Vec::new());
        }
        if status != 0 {
            return Err(Self::map_status("list", status));
        }
        if result.is_null() {
            return Err(KeychainStorageError::VerificationFailed);
        }
        let items = unsafe { CFType::wrap_under_create_rule(result) }
            .downcast_into::<core_foundation::array::CFArray>()
            .ok_or(KeychainStorageError::VerificationFailed)?;
        let mut names = Vec::with_capacity(usize::try_from(items.len()).unwrap_or_default());
        for item in items.iter() {
            // SAFETY: Security.framework returns an array of attribute dictionaries.
            let attributes: CFDictionary<CFString, CFType> =
                unsafe { CFDictionary::wrap_under_get_rule((*item).cast()) };
            let account = attributes
                .find(&account_key)
                .and_then(|value| value.downcast::<CFString>())
                .ok_or(KeychainStorageError::VerificationFailed)?;
            names.push(account.to_string());
        }
        Ok(names)
    }

    fn probe(service: &str, account: &str, open_accounts: &[&str]) -> ProbeOutcome {
        let context = non_interactive_context();
        match Self::read_with_context(service, account, context.clone()) {
            Ok(Some(_)) => ProbeOutcome::Automatic,
            Ok(None) => ProbeOutcome::Absent,
            Err(KeychainStorageError::InteractionNotAllowed) => {
                let keychain_is_available = open_accounts.iter().any(|open| {
                    matches!(
                        Self::read_with_context(service, open, context.clone()),
                        Ok(Some(_))
                    )
                });
                if keychain_is_available {
                    ProbeOutcome::Protected
                } else {
                    ProbeOutcome::Inconclusive
                }
            }
            Err(_) => ProbeOutcome::Inconclusive,
        }
    }

    /// Give an existing item CLI approval, keeping its data.
    fn require_approval(service: &str, account: &str) -> Result<(), KeychainStorageError> {
        let mut pairs = Self::identity_pairs(service, account);
        pairs.push((
            unsafe { CFString::wrap_under_get_rule(kSecUseAuthenticationContext) },
            authentication_context(),
        ));
        let query = CFDictionary::from_CFType_pairs(&pairs);
        let update =
            CFDictionary::from_CFType_pairs(&Self::access_pairs(CliAccess::RequireApproval)?);
        let status =
            unsafe { SecItemUpdate(query.as_concrete_TypeRef(), update.as_concrete_TypeRef()) };
        if status == 0 {
            Ok(())
        } else {
            Err(Self::map_status("require env approval", status))
        }
    }

    fn read_with_context(
        service: &str,
        account: &str,
        context: CFType,
    ) -> Result<Option<Vec<u8>>, KeychainStorageError> {
        let mut pairs = Self::identity_pairs(service, account);
        pairs.push((
            unsafe { CFString::wrap_under_get_rule(kSecUseAuthenticationContext) },
            context,
        ));
        pairs.push((
            unsafe { CFString::wrap_under_get_rule(kSecUseOperationPrompt) },
            CFString::from(operation_prompt(account).as_str()).into_CFType(),
        ));
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
        pairs.extend(Self::access_pairs(CliAccess::Automatic)?);
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
        let mut pairs = Self::identity_pairs(service, account);
        pairs.push((
            unsafe { CFString::wrap_under_get_rule(kSecUseAuthenticationContext) },
            authentication_context(),
        ));
        let query = CFDictionary::from_CFType_pairs(&pairs);
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

    fn write_with_access(
        service: &str,
        account: &str,
        value: &[u8],
        access: CliAccess,
    ) -> Result<(), KeychainStorageError> {
        if access == CliAccess::Automatic {
            return Self::write(service, account, value);
        }
        let mut attributes = Self::access_pairs(access)?;
        attributes.extend(Self::attribute_pairs(Some(value)));
        let mut pairs = Self::identity_pairs(service, account);
        pairs.extend(attributes.iter().cloned());
        let add = CFDictionary::from_CFType_pairs(&pairs);
        let status = unsafe { SecItemAdd(add.as_concrete_TypeRef(), std::ptr::null_mut()) };
        if status == 0 {
            return Ok(());
        }
        if status != ERR_SEC_DUPLICATE_ITEM {
            return Err(Self::map_status("write approved env", status));
        }
        pairs = Self::identity_pairs(service, account);
        pairs.push((
            unsafe { CFString::wrap_under_get_rule(kSecUseAuthenticationContext) },
            authentication_context(),
        ));
        let query = CFDictionary::from_CFType_pairs(&pairs);
        let update = CFDictionary::from_CFType_pairs(&attributes);
        let status =
            unsafe { SecItemUpdate(query.as_concrete_TypeRef(), update.as_concrete_TypeRef()) };
        if status == 0 {
            Ok(())
        } else {
            Err(Self::map_status("write approved env", status))
        }
    }
}

/// Write `value` to `account` with the CLI approval `source` claims, then
/// verify it reads back.
pub(crate) fn write_bytes_with_access_from(
    service: &str,
    account: &str,
    value: &[u8],
    source: &str,
) -> Result<(), String> {
    let result = (|| {
        let access = SecurityFrameworkBackend::cli_access(service, source)?;
        SecurityFrameworkBackend::write_with_access(service, account, value, access)?;
        verify_stored(service, account, value)
    })();
    result.map_err(|error| error.to_string())
}

/// Write `value` to `account` with `access` when the item is created; an
/// existing item keeps its own access unless `access` requires approval.
pub(crate) fn write_bytes_with_access(
    service: &str,
    account: &str,
    value: &[u8],
    access: CliAccess,
) -> Result<(), String> {
    SecurityFrameworkBackend::write_with_access(service, account, value, access)
        .and_then(|()| verify_stored(service, account, value))
        .map_err(|error| error.to_string())
}

fn verify_stored(service: &str, account: &str, value: &[u8]) -> Result<(), KeychainStorageError> {
    match SecurityFrameworkBackend::read(service, account)? {
        Some(stored) if stored == value => Ok(()),
        _ => Err(KeychainStorageError::VerificationFailed),
    }
}

pub(crate) fn read_bytes(service: &str, account: &str) -> Result<Option<Vec<u8>>, String> {
    SecurityFrameworkBackend::read(service, account).map_err(|error| error.to_string())
}

pub(crate) fn read_bytes_with_access(
    service: &str,
    account: &str,
) -> Result<Option<(Vec<u8>, ClaimedAccess)>, String> {
    SecurityFrameworkBackend::read_with_access(service, account).map_err(|error| error.to_string())
}

pub(crate) fn claimed_access(
    service: &str,
    account: &str,
) -> Result<Option<ClaimedAccess>, String> {
    SecurityFrameworkBackend::claimed_access(service, account).map_err(|error| error.to_string())
}

pub(crate) fn write_bytes(service: &str, account: &str, value: &[u8]) -> Result<(), String> {
    SecurityFrameworkBackend::write(service, account, value)
        .and_then(|()| verify_stored(service, account, value))
        .map_err(|error| error.to_string())
}

pub(crate) fn account_names(service: &str) -> Result<Vec<String>, String> {
    SecurityFrameworkBackend::account_names(service).map_err(|error| error.to_string())
}

/// Read `account` without authentication UI to learn whether it demands user
/// presence. `open_accounts` are items without approval in the same service;
/// one of them must read for a refusal to count as protection.
pub(crate) fn probe(service: &str, account: &str, open_accounts: &[&str]) -> ProbeOutcome {
    SecurityFrameworkBackend::probe(service, account, open_accounts)
}

/// Give `account` CLI approval, then confirm by probing that it demands user
/// presence.
pub(crate) fn require_approval(
    service: &str,
    account: &str,
    open_accounts: &[&str],
) -> Result<(), String> {
    SecurityFrameworkBackend::require_approval(service, account)
        .map_err(|error| error.to_string())?;
    match probe(service, account, open_accounts) {
        ProbeOutcome::Protected => Ok(()),
        ProbeOutcome::Inconclusive => Err(
            "the macOS Keychain is unavailable, so env approval couldn't be confirmed; retry once the Mac is unlocked"
                .to_owned(),
        ),
        ProbeOutcome::Automatic | ProbeOutcome::Absent => {
            Err(format!("env approval couldn't be confirmed for {account}"))
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
    write_bytes(service, account, value.as_bytes())
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
    fn approval_prompts_say_what_they_read() {
        assert_eq!(
            operation_prompt("8c1f0d2e-6a35-4c1b-9f3e-2d7b5a1c9e40"),
            "Allow LPM CLI to access env project 8c1f0d2e-6a35-4c1b-9f3e-2d7b5a1c9e40"
        );
        assert_eq!(
            operation_prompt(&crate::companion::account::record_account(
                "overrides",
                "8c1f0d2e-6a35-4c1b-9f3e-2d7b5a1c9e40",
                None
            )),
            "Allow LPM CLI to access env project 8c1f0d2e-6a35-4c1b-9f3e-2d7b5a1c9e40's personal overrides"
        );
        assert_eq!(
            operation_prompt(&crate::companion::account::record_account(
                "future-log",
                "proj",
                Some(3)
            )),
            "Allow LPM CLI to access env project proj's newer data"
        );
    }

    #[test]
    fn access_claims_classify_as_the_shared_fixture_records() {
        #[derive(serde::Deserialize)]
        struct Fixture {
            cases: Vec<Case>,
        }
        #[derive(serde::Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Case {
            name: String,
            marker: Option<String>,
            access_control: bool,
            accessible: Option<String>,
            claim: String,
        }
        let fixture: Fixture = serde_json::from_str(include_str!(
            "../../lpm-env-companion/tests/fixtures/access-claims.json"
        ))
        .expect("the access fixture decodes");
        for case in fixture.cases {
            let mut pairs: Vec<(CFString, CFType)> = Vec::new();
            if let Some(marker) = &case.marker {
                pairs.push((
                    unsafe { CFString::wrap_under_get_rule(kSecAttrGeneric) },
                    CFData::from_buffer(marker.as_bytes()).into_CFType(),
                ));
            }
            if case.access_control {
                let control = SecAccessControl::create_with_protection(
                    Some(security_framework::access_control::ProtectionMode::AccessibleWhenUnlockedThisDeviceOnly),
                    0,
                )
                .expect("an access control");
                pairs.push((
                    unsafe { CFString::wrap_under_get_rule(kSecAttrAccessControl) },
                    control.into_CFType(),
                ));
            }
            if let Some(class) = &case.accessible {
                let class = match class.as_str() {
                    "whenUnlockedThisDeviceOnly" => unsafe {
                        kSecAttrAccessibleWhenUnlockedThisDeviceOnly
                    },
                    "whenUnlocked" => unsafe {
                        security_framework_sys::access_control::kSecAttrAccessibleWhenUnlocked
                    },
                    "afterFirstUnlock" => unsafe {
                        security_framework_sys::access_control::kSecAttrAccessibleAfterFirstUnlock
                    },
                    other => panic!("{}: unknown class {other}", case.name),
                };
                pairs.push((
                    unsafe { CFString::wrap_under_get_rule(kSecAttrAccessible) },
                    unsafe { CFString::wrap_under_get_rule(class) }.into_CFType(),
                ));
            }
            let attributes = CFDictionary::from_CFType_pairs(&pairs);
            let claim = match SecurityFrameworkBackend::claim(&attributes) {
                ClaimedAccess::Automatic => "automatic",
                ClaimedAccess::RequireApproval => "requireApproval",
                ClaimedAccess::Contradictory => "contradictory",
            };
            assert_eq!(claim, case.claim, "{}", case.name);
        }
    }

    #[test]
    #[ignore = "requires a signed macOS test bundle with the shared Keychain entitlement"]
    fn native_keychain_denies_protected_project_and_stage_reads_without_user_presence() {
        assert_eq!(std::env::var("LPM_RUN_KEYCHAIN_TESTS").as_deref(), Ok("1"));
        let service = format!("dev.lpm.cli-approval.fixture.{}", rand::random::<u128>());
        struct FixtureCleanup<'a>(&'a str);
        impl Drop for FixtureCleanup<'_> {
            fn drop(&mut self) {
                for account in ["project", "stage"] {
                    let _ = delete(self.0, account);
                }
            }
        }
        let _cleanup = FixtureCleanup(&service);
        let blocked_context = || {
            let context = unsafe { objc2_local_authentication::LAContext::new() };
            unsafe { context.setInteractionNotAllowed(true) };
            let pointer = std::ptr::from_ref(&*context).cast::<std::ffi::c_void>();
            unsafe { CFType::wrap_under_get_rule(pointer) }
        };
        SecurityFrameworkBackend::add(&service, "project", b"synthetic-fixture")
            .expect("create isolated fixture");
        assert_eq!(
            SecurityFrameworkBackend::read_with_context(&service, "project", blocked_context())
                .expect("automatic access needs no approval"),
            Some(b"synthetic-fixture".to_vec())
        );
        let query = CFDictionary::from_CFType_pairs(&SecurityFrameworkBackend::identity_pairs(
            &service, "project",
        ));
        let attributes = CFDictionary::from_CFType_pairs(
            &SecurityFrameworkBackend::access_pairs(CliAccess::RequireApproval)
                .expect("create native approval"),
        );
        assert_eq!(
            unsafe {
                SecItemUpdate(
                    query.as_concrete_TypeRef(),
                    attributes.as_concrete_TypeRef(),
                )
            },
            0
        );
        assert!(matches!(
            SecurityFrameworkBackend::read_with_context(&service, "project", blocked_context()),
            Err(KeychainStorageError::InteractionNotAllowed)
        ));
        SecurityFrameworkBackend::write_with_access(
            &service,
            "stage",
            b"synthetic-fixture",
            CliAccess::RequireApproval,
        )
        .expect("stage must be protected at creation");
        assert!(matches!(
            SecurityFrameworkBackend::read_with_context(&service, "stage", blocked_context()),
            Err(KeychainStorageError::InteractionNotAllowed)
        ));
    }

    #[test]
    #[ignore = "requires a signed macOS test bundle with the shared Keychain entitlement"]
    fn native_probe_tells_protected_items_from_automatic_and_unavailable_ones() {
        assert_eq!(std::env::var("LPM_RUN_KEYCHAIN_TESTS").as_deref(), Ok("1"));
        let service = format!("dev.lpm.companion-probe.fixture.{}", rand::random::<u128>());
        struct FixtureCleanup<'a>(&'a str);
        impl Drop for FixtureCleanup<'_> {
            fn drop(&mut self) {
                for account in ["open", "automatic", "protected", "contradictory"] {
                    let _ = delete(self.0, account);
                }
            }
        }
        let _cleanup = FixtureCleanup(&service);
        SecurityFrameworkBackend::add(&service, "open", b"open").expect("open item");
        SecurityFrameworkBackend::add(&service, "automatic", b"synthetic-fixture")
            .expect("automatic item");
        SecurityFrameworkBackend::write_with_access(
            &service,
            "protected",
            b"synthetic-fixture",
            CliAccess::RequireApproval,
        )
        .expect("protected item");

        assert_eq!(
            probe(&service, "automatic", &["open"]),
            ProbeOutcome::Automatic
        );
        assert_eq!(
            probe(&service, "protected", &["open"]),
            ProbeOutcome::Protected
        );
        assert_eq!(
            probe(&service, "protected", &["missing"]),
            ProbeOutcome::Inconclusive,
            "a refusal counts as protection only when an open item reads"
        );
        assert_eq!(probe(&service, "missing", &["open"]), ProbeOutcome::Absent);
        assert_eq!(
            claimed_access(&service, "protected").expect("attributes"),
            Some(ClaimedAccess::RequireApproval)
        );
        assert_eq!(
            claimed_access(&service, "automatic").expect("attributes"),
            Some(ClaimedAccess::Automatic)
        );

        let query = CFDictionary::from_CFType_pairs(&SecurityFrameworkBackend::identity_pairs(
            &service,
            "automatic",
        ));
        let marker_only = CFDictionary::from_CFType_pairs(&[(
            unsafe { CFString::wrap_under_get_rule(kSecAttrGeneric) },
            CFData::from_buffer(APPROVAL_MARKER).into_CFType(),
        )]);
        assert_eq!(
            unsafe {
                SecItemUpdate(
                    query.as_concrete_TypeRef(),
                    marker_only.as_concrete_TypeRef(),
                )
            },
            0
        );
        assert_eq!(
            claimed_access(&service, "automatic").expect("attributes"),
            Some(ClaimedAccess::Contradictory),
            "an approval marker without an access control contradicts itself"
        );
        assert_eq!(
            probe(&service, "automatic", &["open"]),
            ProbeOutcome::Automatic,
            "the probe reports what the item does, not what it claims"
        );
        require_approval(&service, "automatic", &["open"]).expect("strengthen");
        assert_eq!(
            probe(&service, "automatic", &["open"]),
            ProbeOutcome::Protected
        );
        let names = account_names(&service).expect("listing");
        for account in ["open", "automatic", "protected"] {
            assert!(names.iter().any(|name| name == account), "{names:?}");
        }
    }

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
    fn updating_values_preserves_existing_keychain_access_control() {
        let pairs = SecurityFrameworkBackend::attribute_pairs(Some(b"replacement"));
        let accessible = unsafe { CFString::wrap_under_get_rule(kSecAttrAccessible) };
        assert!(pairs.iter().all(|(key, _)| key != &accessible));
    }

    #[test]
    fn native_approval_cancellation_is_reported_without_a_fallback() {
        let error = SecurityFrameworkBackend::map_status("read", -128);
        assert!(matches!(error, KeychainStorageError::ApprovalCancelled));
        assert_eq!(
            error.to_string(),
            "env access approval was cancelled; no secrets were released"
        );
    }

    #[test]
    fn native_authentication_failure_is_reported_without_a_fallback() {
        let error = SecurityFrameworkBackend::map_status("read", -25293);
        assert!(matches!(error, KeychainStorageError::ApprovalFailed));
    }

    #[test]
    fn approval_attributes_use_native_access_control_and_the_shared_policy_marker() {
        let pairs = SecurityFrameworkBackend::access_pairs(CliAccess::RequireApproval)
            .expect("create access control");
        let control = unsafe { CFString::wrap_under_get_rule(kSecAttrAccessControl) };
        let generic = unsafe { CFString::wrap_under_get_rule(kSecAttrGeneric) };
        let accessible = unsafe { CFString::wrap_under_get_rule(kSecAttrAccessible) };
        assert!(
            pairs
                .iter()
                .any(|(key, value)| key == &control
                    && value.downcast::<SecAccessControl>().is_some())
        );
        assert!(pairs.iter().any(|(key, value)| {
            key == &generic
                && value
                    .downcast::<CFData>()
                    .is_some_and(|data| data.bytes() == APPROVAL_MARKER)
        }));
        assert!(pairs.iter().all(|(key, _)| key != &accessible));
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
