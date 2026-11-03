//! The operating system's credential store, which LPM shares with LPM Vault
//! and with earlier LPM releases.
//!
//! Items are found and created exactly where keyring 3 put them, so
//! credentials that earlier releases and LPM Vault wrote stay readable, and
//! earlier releases read what this one writes:
//!
//! - macOS: generic passwords in the login keychain, named by service and
//!   account.
//! - Windows: generic credentials in Credential Manager, named
//!   `{user}.{service}`.
//! - Linux: Secret Service items whose `service`, `username` and `target`
//!   attributes are the service, the user and `default`.

use std::sync::{Arc, Mutex, PoisonError};

use keyring_core::CredentialStore;
pub use keyring_core::{Entry, Error, Result};

/// The credential for `user` under `service` in the operating system's store.
pub fn entry(service: &str, user: &str) -> Result<Entry> {
    static STORE: Mutex<Option<Arc<CredentialStore>>> = Mutex::new(None);
    build(&opened(&STORE, platform_store)?, service, user)
}

/// The store `open` returns, opened again by each call until it succeeds:
/// connecting to Secret Service fails until a session provides it.
fn opened(
    slot: &Mutex<Option<Arc<CredentialStore>>>,
    open: impl FnOnce() -> Result<Arc<CredentialStore>>,
) -> Result<Arc<CredentialStore>> {
    let mut store = slot.lock().unwrap_or_else(PoisonError::into_inner);
    match store.as_ref() {
        Some(store) => Ok(Arc::clone(store)),
        None => Ok(Arc::clone(store.insert(open()?))),
    }
}

#[cfg(target_os = "macos")]
fn platform_store() -> Result<Arc<CredentialStore>> {
    let store: Arc<CredentialStore> = apple_native_keyring_store::keychain::Store::new()?;
    Ok(store)
}

#[cfg(windows)]
fn platform_store() -> Result<Arc<CredentialStore>> {
    let store: Arc<CredentialStore> = windows_native_keyring_store::Store::new()?;
    Ok(store)
}

// keyring 3's `linux-native-sync-persistent` store, which earlier releases
// selected, built Secret Service credentials only, so they never cached a
// credential in keyutils. A keyutils cache now would keep serving a
// credential that an earlier release replaced or deleted.
#[cfg(target_os = "linux")]
fn platform_store() -> Result<Arc<CredentialStore>> {
    let store: Arc<CredentialStore> = dbus_secret_service_keyring_store::Store::new()?;
    Ok(store)
}

#[cfg(not(any(target_os = "macos", windows, target_os = "linux")))]
fn platform_store() -> Result<Arc<CredentialStore>> {
    Err(Error::NoDefaultStore)
}

#[cfg(target_os = "linux")]
fn build(store: &Arc<CredentialStore>, service: &str, user: &str) -> Result<Entry> {
    // keyring 3 gave every item `target=default` and found items by it.
    let target = std::collections::HashMap::from([("target", "default")]);
    store.build(service, user, Some(&target))
}

#[cfg(not(target_os = "linux"))]
fn build(store: &Arc<CredentialStore>, service: &str, user: &str) -> Result<Entry> {
    store.build(service, user, None)
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use keyring_core::mock;

    use super::*;

    #[test]
    fn a_store_that_failed_to_open_is_opened_again_and_then_kept() {
        let slot = Mutex::new(None);
        let opens = Cell::new(0);
        let open = |succeeds: bool| {
            opens.set(opens.get() + 1);
            if succeeds {
                let store: Arc<CredentialStore> = mock::Store::new()?;
                Ok(store)
            } else {
                Err(Error::NoStorageAccess("no Secret Service session".into()))
            }
        };

        let error = opened(&slot, || open(false)).expect_err("the first open fails");
        assert!(matches!(error, Error::NoStorageAccess(_)), "{error:?}");
        let first = opened(&slot, || open(true)).expect("the second open succeeds");
        let kept = opened(&slot, || open(true)).expect("the store is kept");

        assert_eq!(opens.get(), 2);
        assert!(Arc::ptr_eq(&first, &kept));
    }
}
