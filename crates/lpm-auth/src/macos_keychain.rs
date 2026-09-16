use core_foundation::{
    base::{CFType, CFTypeRef, TCFType},
    boolean::CFBoolean,
    data::CFData,
    dictionary::CFDictionary,
    string::{CFString, CFStringRef},
};
use security_framework::base::Error;
use security_framework_sys::{
    access_control::kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
    item::{
        kSecAttrAccessGroup, kSecAttrAccount, kSecAttrService, kSecAttrSynchronizable, kSecClass,
        kSecClassGenericPassword, kSecReturnData, kSecUseAuthenticationContext,
        kSecUseDataProtectionKeychain, kSecValueData,
    },
    keychain_item::{SecItemAdd, SecItemCopyMatching, SecItemDelete, SecItemUpdate},
};

#[link(name = "Security", kind = "framework")]
unsafe extern "C" {
    static kSecAttrAccessible: CFStringRef;
}

pub(super) const ACCESS_GROUP: &str = "823S8YKMRW.dev.lpm.vault.shared";
const NOT_FOUND: i32 = -25300;
const DUPLICATE: i32 = -25299;

#[derive(Clone, Copy)]
pub(super) enum Scope {
    Shared,
    Legacy,
}

fn identity(service: &str, account: &str, scope: Scope) -> Vec<(CFString, CFType)> {
    // SAFETY: Security.framework exports these keys and values as immortal CFStrings.
    unsafe {
        let mut pairs = vec![
            (
                CFString::wrap_under_get_rule(kSecClass),
                CFString::wrap_under_get_rule(kSecClassGenericPassword).into_CFType(),
            ),
            (
                CFString::wrap_under_get_rule(kSecAttrService),
                CFString::from(service).into_CFType(),
            ),
            (
                CFString::wrap_under_get_rule(kSecAttrAccount),
                CFString::from(account).into_CFType(),
            ),
            (
                CFString::wrap_under_get_rule(kSecUseDataProtectionKeychain),
                CFBoolean::from(matches!(scope, Scope::Shared)).into_CFType(),
            ),
        ];
        if matches!(scope, Scope::Shared) {
            pairs.push((
                CFString::wrap_under_get_rule(kSecAttrAccessGroup),
                CFString::from(ACCESS_GROUP).into_CFType(),
            ));
            pairs.push((
                CFString::wrap_under_get_rule(kSecAttrSynchronizable),
                CFBoolean::from(false).into_CFType(),
            ));
        }
        pairs
    }
}

pub(super) fn read(
    service: &str,
    account: &str,
    scope: Scope,
    interactive: bool,
) -> Result<Option<String>, Error> {
    let mut pairs = identity(service, account, scope);
    // SAFETY: The key is a framework-owned CFString and the value is retained by the query.
    pairs.push(unsafe {
        (
            CFString::wrap_under_get_rule(kSecReturnData),
            CFBoolean::from(true).into_CFType(),
        )
    });
    if !interactive {
        // SAFETY: LAContext is retained until the query releases its CFType reference.
        let context = unsafe { objc2_local_authentication::LAContext::new() };
        unsafe { context.setInteractionNotAllowed(true) };
        let pointer = std::ptr::from_ref(&*context).cast::<std::ffi::c_void>();
        // SAFETY: kSecUseAuthenticationContext accepts an LAContext, and get-rule retains it.
        pairs.push(unsafe {
            (
                CFString::wrap_under_get_rule(kSecUseAuthenticationContext),
                CFType::wrap_under_get_rule(pointer),
            )
        });
    }
    let query = CFDictionary::from_CFType_pairs(&pairs);
    let mut result: CFTypeRef = std::ptr::null();
    let _lock = lpm_common::platform::macos_keychain_operation_lock();
    // SAFETY: The dictionary and output pointer remain valid for the synchronous call.
    let status = unsafe { SecItemCopyMatching(query.as_concrete_TypeRef(), &mut result) };
    if status == NOT_FOUND {
        return Ok(None);
    }
    if status != 0 {
        return Err(Error::from_code(status));
    }
    if result.is_null() {
        return Err(Error::from_code(-26275));
    }
    // SAFETY: A successful Copy call transfers one reference to the caller.
    let value = unsafe { CFType::wrap_under_create_rule(result) };
    let data = value
        .downcast_into::<CFData>()
        .ok_or_else(|| Error::from_code(-26275))?;
    let token = std::str::from_utf8(data.bytes())
        .map_err(|_| Error::from_code(-26275))?
        .trim();
    if token.is_empty() {
        return Err(Error::from_code(-26275));
    }
    Ok(Some(token.to_owned()))
}

pub(super) fn write(service: &str, account: &str, token: &str) -> Result<(), Error> {
    let mut identity = identity(service, account, Scope::Shared);
    let query = CFDictionary::from_CFType_pairs(&identity);
    // SAFETY: Framework constants are immortal; both owned attribute values survive the calls.
    let attributes = unsafe {
        vec![
            (
                CFString::wrap_under_get_rule(kSecValueData),
                CFData::from_buffer(token.as_bytes()).into_CFType(),
            ),
            (
                CFString::wrap_under_get_rule(kSecAttrAccessible),
                CFString::wrap_under_get_rule(kSecAttrAccessibleWhenUnlockedThisDeviceOnly)
                    .into_CFType(),
            ),
        ]
    };
    let changes = CFDictionary::from_CFType_pairs(&attributes);
    let _lock = lpm_common::platform::macos_keychain_operation_lock();
    // SAFETY: Both dictionaries remain alive during the synchronous call.
    let status =
        unsafe { SecItemUpdate(query.as_concrete_TypeRef(), changes.as_concrete_TypeRef()) };
    if status == 0 {
        return Ok(());
    }
    if status != NOT_FOUND {
        return Err(Error::from_code(status));
    }
    identity.extend(attributes);
    let add = CFDictionary::from_CFType_pairs(&identity);
    // SAFETY: The dictionary remains alive and no result object is requested.
    let status = unsafe { SecItemAdd(add.as_concrete_TypeRef(), std::ptr::null_mut()) };
    let status = if status == DUPLICATE {
        // SAFETY: A concurrent writer won the add; update only the same scoped identity.
        unsafe { SecItemUpdate(query.as_concrete_TypeRef(), changes.as_concrete_TypeRef()) }
    } else {
        status
    };
    if status == 0 {
        Ok(())
    } else {
        Err(Error::from_code(status))
    }
}

pub(super) fn delete(service: &str, account: &str, scope: Scope) -> Result<(), Error> {
    let query = CFDictionary::from_CFType_pairs(&identity(service, account, scope));
    let _lock = lpm_common::platform::macos_keychain_operation_lock();
    // SAFETY: The dictionary remains valid throughout the synchronous call.
    match unsafe { SecItemDelete(query.as_concrete_TypeRef()) } {
        0 | NOT_FOUND => Ok(()),
        status => Err(Error::from_code(status)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_query_selects_the_shared_data_protection_group() {
        let pairs = identity("lpm-cli", "test-account", Scope::Shared);
        let description = format!("{pairs:?}");
        assert!(description.contains(ACCESS_GROUP));
        // SAFETY: Security.framework owns the immortal query key.
        let key = unsafe { CFString::wrap_under_get_rule(kSecUseDataProtectionKeychain) };
        let pairs = identity("lpm-cli", "test-account", Scope::Shared);
        let protected = pairs
            .iter()
            .find(|(name, _)| *name == key)
            .unwrap()
            .1
            .downcast::<CFBoolean>()
            .unwrap();
        assert!(bool::from(protected));
    }

    #[test]
    fn legacy_query_explicitly_excludes_the_shared_store() {
        let description = format!("{:?}", identity("lpm-cli", "test-account", Scope::Legacy));
        assert!(!description.contains(ACCESS_GROUP));
        // SAFETY: Security.framework owns the immortal query key.
        let key = unsafe { CFString::wrap_under_get_rule(kSecUseDataProtectionKeychain) };
        let pairs = identity("lpm-cli", "test-account", Scope::Legacy);
        let protected = pairs
            .iter()
            .find(|(name, _)| *name == key)
            .unwrap()
            .1
            .downcast::<CFBoolean>()
            .unwrap();
        assert!(!bool::from(protected));
    }
}
