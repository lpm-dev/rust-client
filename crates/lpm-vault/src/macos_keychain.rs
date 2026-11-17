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

thread_local! {
    /// What the running command reads for, when it's more than one item:
    /// local history reads the values first, and only one prompt shows.
    static PURPOSE: std::cell::Cell<Option<&'static str>> = const { std::cell::Cell::new(None) };
}

/// The folder a command reads a vault for, and the project name the vault's
/// own records give, so an approval prompt names both rather than an ID.
struct Requester {
    vault_id: String,
    folder: std::path::PathBuf,
    project_name: Option<String>,
}

thread_local! {
    static REQUESTER: std::cell::RefCell<Option<Requester>> = const { std::cell::RefCell::new(None) };
}

/// Name `folder`, which may use the vault `vault_id`, in the approval
/// prompts for the vault's items. `project_name` runs only when the vault or
/// the folder differs from the last one noted.
pub(crate) fn note_requester(
    vault_id: &str,
    folder: &std::path::Path,
    project_name: impl FnOnce() -> Option<String>,
) {
    let noted = REQUESTER.with_borrow(|requester| {
        requester
            .as_ref()
            .is_some_and(|requester| requester.vault_id == vault_id && requester.folder == folder)
    });
    if noted {
        return;
    }
    // Read outside the borrow: reading the project record builds prompts too.
    let project_name = project_name().filter(|name| !name.is_empty());
    REQUESTER.set(Some(Requester {
        vault_id: vault_id.to_owned(),
        folder: folder.to_path_buf(),
        project_name,
    }));
}

const PROMPT_NAME_CHARS: usize = 64;

/// How the prompt names the project: its recorded name, quoted and cut
/// short, or its vault ID.
fn prompt_project(vault_id: &str, project_name: Option<&str>) -> String {
    let Some(name) = project_name else {
        return vault_id.to_owned();
    };
    let quoted = match name.char_indices().nth(PROMPT_NAME_CHARS) {
        Some((end, _)) => format!("{:?}", format!("{}…", &name[..end])),
        None => format!("{name:?}"),
    };
    lpm_common::sanitize_terminal_inline(&quoted).into_owned()
}

/// The folder as the prompt names it, with the home folder as `~`.
fn prompt_folder(folder: &std::path::Path) -> String {
    let shown = dirs::home_dir()
        .and_then(|home| folder.strip_prefix(home).ok())
        .map_or_else(
            || folder.display().to_string(),
            |relative| {
                std::path::Path::new("~")
                    .join(relative)
                    .display()
                    .to_string()
            },
        );
    lpm_common::sanitize_terminal_inline(&shown).into_owned()
}

/// Run `run` with every approval prompt saying it's for the project's
/// local history, as a history command's one prompt must.
pub(crate) fn prompting_for_local_history<T>(run: impl FnOnce() -> T) -> T {
    struct Restore(Option<&'static str>);
    impl Drop for Restore {
        fn drop(&mut self) {
            PURPOSE.set(self.0);
        }
    }
    let _restore = Restore(PURPOSE.replace(Some("local history")));
    run()
}

/// The reason the approval prompt gives for reading `account`: the folder
/// asking and the project's recorded name when a link check noted them, else
/// its vault ID; a companion record also by what it holds, and either by
/// what the running command reads for when it says.
fn operation_prompt(account: &str) -> String {
    use crate::companion::account::CompanionAccount;
    let history = lpm_env_companion::append_log::HISTORY;
    let record = CompanionAccount::parse(account);
    let vault_id = record.as_ref().map_or(account, CompanionAccount::vault_id);
    let holds = PURPOSE.get().or_else(|| match record.as_ref()?.kind() {
        Some(crate::companion::overrides::OVERRIDES_KIND) => Some("personal overrides"),
        Some(kind) if kind == history.kind || kind == history.head_kind => Some("local history"),
        _ => Some("newer data"),
    });
    let (project, requester) = REQUESTER.with_borrow(|requester| match requester {
        Some(requester) if requester.vault_id == vault_id => (
            prompt_project(vault_id, requester.project_name.as_deref()),
            format!(" in {}", prompt_folder(&requester.folder)),
        ),
        _ => (vault_id.to_owned(), String::new()),
    });
    match holds {
        Some(holds) => {
            format!("Allow LPM CLI{requester} to access env project {project}'s {holds}")
        }
        None => format!("Allow LPM CLI{requester} to access env project {project}"),
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
    static AUTHENTICATION_CONTEXT: std::cell::RefCell<
        Option<objc2::rc::Retained<objc2_local_authentication::LAContext>>,
    > = const { std::cell::RefCell::new(None) };
}

/// What the invocation's one context gives as its reason when the Keychain
/// call that raises a prompt gives none of its own. Without one, macOS asks
/// only to "continue with LPM CLI".
const AUTHENTICATION_REASON: &str = "access LPM env values";

/// The invocation's one context. macOS shows its reason only when the
/// Keychain call gives no prompt of its own.
fn shared_authentication_context() -> objc2::rc::Retained<objc2_local_authentication::LAContext> {
    AUTHENTICATION_CONTEXT.with_borrow_mut(|stored| {
        stored
            .get_or_insert_with(|| {
                // SAFETY: creating an LAContext has no preconditions.
                let context = unsafe { objc2_local_authentication::LAContext::new() };
                let reason = objc2_foundation::NSString::from_str(AUTHENTICATION_REASON);
                // SAFETY: the context copies the string, which outlives the call.
                unsafe { context.setLocalizedReason(&reason) };
                context
            })
            .clone()
    })
}

fn authentication_context() -> CFType {
    let context = shared_authentication_context();
    let pointer = objc2::rc::Retained::as_ptr(&context).cast::<std::ffi::c_void>();
    // SAFETY: get-rule retains the context, so the CFType outlives `context`.
    unsafe { CFType::wrap_under_get_rule(pointer) }
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
    #[error(
        "LPM's lifecycle-script sandbox closes the macOS Keychain, so env values can't be read or changed from a package's install script"
    )]
    LifecycleSandboxDenied,
    #[error(
        "a sandbox around this process closes the macOS Keychain (OSStatus {code}), so env values can't be read or changed here; run lpm outside it"
    )]
    OtherSandboxDenied { code: i32 },
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
        Self::map_status_in(
            operation,
            code,
            lpm_common::platform::macos_keychain_denial(),
        )
    }

    /// Every Keychain call fails once a sandbox denies its services, so the
    /// sandbox outranks whatever status the failure carries.
    fn map_status_in(
        operation: &'static str,
        code: i32,
        denial: Option<lpm_common::platform::MacosKeychainDenial>,
    ) -> KeychainStorageError {
        use lpm_common::platform::MacosKeychainDenial;
        match denial {
            Some(MacosKeychainDenial::LifecycleSandbox) => {
                return KeychainStorageError::LifecycleSandboxDenied;
            }
            Some(MacosKeychainDenial::OtherSandbox) => {
                return KeychainStorageError::OtherSandboxDenied { code };
            }
            None => {}
        }
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
        // Attributes need no authentication, but a context that forbids
        // interaction makes the Keychain refuse an item that demands user
        // presence even for them, so attribute queries pass none.
        let mut pairs = Self::identity_pairs(service, account);
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

    /// The account name of every item in `service`, with the approval its
    /// attributes claim, from attributes alone, which never ask for
    /// authentication. Like [`Self::claimed_access`], it passes no
    /// authentication context.
    fn accounts(service: &str) -> Result<Vec<(String, ClaimedAccess)>, KeychainStorageError> {
        let mut pairs = Self::identity_pairs(service, "");
        let account_key = unsafe { CFString::wrap_under_get_rule(kSecAttrAccount) };
        pairs.retain(|(key, _)| key != &account_key);
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
            names.push((account.to_string(), Self::claim(&attributes)));
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
    stored_matches(SecurityFrameworkBackend::read(service, account)?, value)
}

/// Whether `stored`, read back after a write, is `value`. The bytes may be
/// a key, so they're wiped either way.
fn stored_matches(stored: Option<Vec<u8>>, value: &[u8]) -> Result<(), KeychainStorageError> {
    match stored.map(zeroize::Zeroizing::new) {
        Some(stored) if stored.as_slice() == value => Ok(()),
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

/// Every account in `service` with the approval its attributes claim, in
/// one attributes-only listing.
pub(crate) fn accounts_with_access(service: &str) -> Result<Vec<(String, ClaimedAccess)>, String> {
    SecurityFrameworkBackend::accounts(service).map_err(|error| error.to_string())
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

/// Leave `claim` on `account`'s attributes, past what its access control
/// enforces. Debug builds only, for planting those states by hand.
#[cfg(debug_assertions)]
pub(crate) fn plant_approval_claim(
    service: &str,
    account: &str,
    claim: crate::companion::debug_states::PlantedClaim,
) -> Result<(), String> {
    use crate::companion::debug_states::PlantedClaim;
    let policy: &[u8] = match claim {
        PlantedClaim::UnknownPolicy => b"lpm-cli-access:require-approval:v2",
        PlantedClaim::ApprovalNotEnforced => APPROVAL_MARKER,
        PlantedClaim::ApprovalOff => b"",
    };
    let mut pairs = SecurityFrameworkBackend::identity_pairs(service, account);
    pairs.push((
        unsafe { CFString::wrap_under_get_rule(kSecUseAuthenticationContext) },
        authentication_context(),
    ));
    let query = CFDictionary::from_CFType_pairs(&pairs);
    let attributes = CFDictionary::from_CFType_pairs(&[(
        unsafe { CFString::wrap_under_get_rule(kSecAttrGeneric) },
        CFData::from_buffer(policy).into_CFType(),
    )]);
    // SAFETY: Both dictionaries are live CoreFoundation objects for the call.
    let status = unsafe {
        SecItemUpdate(
            query.as_concrete_TypeRef(),
            attributes.as_concrete_TypeRef(),
        )
    };
    if status == 0 {
        Ok(())
    } else {
        Err(SecurityFrameworkBackend::map_status("claim approval", status).to_string())
    }
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
    fn a_keychain_failure_inside_lpms_sandbox_says_its_install_script_sandbox_closed_the_keychain()
    {
        use lpm_common::platform::MacosKeychainDenial;
        let error = SecurityFrameworkBackend::map_status_in(
            "read",
            -25291,
            Some(MacosKeychainDenial::LifecycleSandbox),
        );
        assert!(
            matches!(error, KeychainStorageError::LifecycleSandboxDenied),
            "{error:?}"
        );
        assert!(error.to_string().contains("install script"), "{error}");
    }

    #[test]
    fn a_keychain_failure_inside_another_sandbox_names_no_install_script_and_keeps_its_status() {
        use lpm_common::platform::MacosKeychainDenial;
        let error = SecurityFrameworkBackend::map_status_in(
            "read",
            -25291,
            Some(MacosKeychainDenial::OtherSandbox),
        );
        let message = error.to_string();
        assert!(!message.contains("install script"), "{message}");
        assert!(message.contains("-25291"), "{message}");
    }

    #[test]
    fn a_keychain_failure_outside_a_sandbox_keeps_its_status() {
        assert!(matches!(
            SecurityFrameworkBackend::map_status_in("read", -25291, None),
            KeychainStorageError::Security {
                operation: "read",
                code: -25291
            }
        ));
        assert!(matches!(
            SecurityFrameworkBackend::map_status_in("read", -128, None),
            KeychainStorageError::ApprovalCancelled
        ));
    }

    #[cfg(not(miri))]
    #[test]
    fn verifying_a_write_wipes_what_it_read_back() {
        use crate::freed_memory_probe::{MARKER, watch};
        let (verified, found) =
            watch(|| stored_matches(Some(MARKER.as_bytes().to_vec()), MARKER.as_bytes()).is_ok());
        assert!(verified);
        assert!(!found, "the read-back bytes, perhaps a key, are wiped");
        let (verified, found) =
            watch(|| stored_matches(Some(MARKER.as_bytes().to_vec()), b"other").is_ok());
        assert!(!verified);
        assert!(!found, "and wiped when they differ");
    }

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
    fn approval_prompts_name_the_folder_asking_and_the_recorded_project() {
        let vault_id = "8c1f0d2e-6a35-4c1b-9f3e-2d7b5a1c9e40";
        let folder = std::path::Path::new("/srv/checkouts/proj-a");
        note_requester(vault_id, folder, || Some("proj-a".into()));

        assert_eq!(
            operation_prompt(vault_id),
            "Allow LPM CLI in /srv/checkouts/proj-a to access env project \"proj-a\""
        );
        assert_eq!(
            operation_prompt(&crate::companion::account::record_account(
                "overrides",
                vault_id,
                None
            )),
            "Allow LPM CLI in /srv/checkouts/proj-a to access env project \"proj-a\"'s personal overrides"
        );
        assert_eq!(
            operation_prompt("another-vault"),
            "Allow LPM CLI to access env project another-vault",
            "another vault's prompt names nothing it wasn't checked for"
        );
    }

    #[test]
    fn a_requester_s_project_record_is_read_once_per_folder() {
        let reads = std::cell::Cell::new(0);
        let read = || {
            reads.set(reads.get() + 1);
            Some("proj-a".to_owned())
        };
        let own = std::path::Path::new("/srv/own");

        note_requester("vault", own, read);
        note_requester("vault", own, read);
        note_requester("vault", std::path::Path::new("/srv/other"), read);

        assert_eq!(reads.get(), 2);
    }

    #[test]
    fn a_requester_without_a_recorded_name_is_prompted_for_by_vault_id() {
        note_requester("vault", std::path::Path::new("/srv/own"), || {
            Some(String::new())
        });

        assert_eq!(
            operation_prompt("vault"),
            "Allow LPM CLI in /srv/own to access env project vault"
        );
    }

    #[test]
    fn a_recorded_name_is_escaped_and_cut_short_in_the_prompt() {
        let long = "n".repeat(100);
        assert_eq!(
            prompt_project("vault", Some("proj\nAllow everything\u{202e}")),
            "\"proj\\nAllow everything\\u{202e}\""
        );
        assert_eq!(
            prompt_project("vault", Some(&long)),
            format!("\"{}…\"", "n".repeat(PROMPT_NAME_CHARS))
        );
    }

    #[test]
    fn a_folder_under_home_is_prompted_for_from_home() {
        let Some(home) = dirs::home_dir() else {
            return;
        };

        assert_eq!(
            prompt_folder(&home.join("code").join("proj-a")),
            "~/code/proj-a"
        );
    }

    #[test]
    fn a_keychain_read_without_its_own_prompt_still_says_what_it_reads() {
        // SAFETY: reading a property of a live context has no preconditions.
        let reason = unsafe { shared_authentication_context().localizedReason() };
        assert_eq!(reason.to_string(), AUTHENTICATION_REASON);
    }

    #[test]
    fn approval_prompts_name_local_history_for_its_records_and_its_commands() {
        let head = lpm_env_companion::history::head_account("proj").name();
        let part = lpm_env_companion::history::part_account("proj", 3).name();
        for account in [&head, &part] {
            assert_eq!(
                operation_prompt(account),
                "Allow LPM CLI to access env project proj's local history"
            );
        }
        let values = "8c1f0d2e-6a35-4c1b-9f3e-2d7b5a1c9e40";
        assert_eq!(
            prompting_for_local_history(|| operation_prompt(values)),
            "Allow LPM CLI to access env project 8c1f0d2e-6a35-4c1b-9f3e-2d7b5a1c9e40's local history",
            "a history command's first prompt, for the values, says what it's for"
        );
        assert_eq!(
            operation_prompt(values),
            "Allow LPM CLI to access env project 8c1f0d2e-6a35-4c1b-9f3e-2d7b5a1c9e40",
            "and only while it runs"
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
            Some(ClaimedAccess::RequireApproval),
            "every Data Protection item reports an access control, so an approval marker over one that asks for nothing claims approval"
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
        SecurityFrameworkBackend::add(&service, "contradictory", b"synthetic-fixture")
            .expect("contradictory item");
        let unknown_policy = CFDictionary::from_CFType_pairs(&[(
            unsafe { CFString::wrap_under_get_rule(kSecAttrGeneric) },
            CFData::from_buffer(b"lpm-cli-access:require-approval:v2").into_CFType(),
        )]);
        let query = CFDictionary::from_CFType_pairs(&SecurityFrameworkBackend::identity_pairs(
            &service,
            "contradictory",
        ));
        assert_eq!(
            unsafe {
                SecItemUpdate(
                    query.as_concrete_TypeRef(),
                    unknown_policy.as_concrete_TypeRef(),
                )
            },
            0
        );
        assert_eq!(
            claimed_access(&service, "contradictory").expect("attributes"),
            Some(ClaimedAccess::Contradictory),
            "a policy LPM doesn't know contradicts itself"
        );
        let accounts = accounts_with_access(&service)
            .expect("items that demand user presence never stop the listing");
        for account in ["open", "automatic", "protected", "contradictory"] {
            assert_eq!(
                accounts
                    .iter()
                    .find(|(name, _)| name == account)
                    .map(|(_, claim)| *claim),
                claimed_access(&service, account).expect("attributes"),
                "the listing reports {account}'s claim as reading its attributes does"
            );
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
