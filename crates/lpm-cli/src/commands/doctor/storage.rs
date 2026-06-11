use crate::{auth, doctor_catalog};

use super::check::Check;

pub(super) fn vault_storage_check(backend: lpm_vault::VaultStorageBackend) -> Check {
    match backend {
        lpm_vault::VaultStorageBackend::MacosKeychain => {
            Check::pass(&doctor_catalog::VAULT_STORAGE_KEYCHAIN, "macOS Keychain")
        }
        lpm_vault::VaultStorageBackend::NativeProtected => Check::pass(
            &doctor_catalog::VAULT_STORAGE_NATIVE,
            "native-protected data key",
        ),
        lpm_vault::VaultStorageBackend::NativePreferred => Check::pass(
            &doctor_catalog::VAULT_STORAGE_NATIVE,
            "native secure store preferred for new vault data",
        ),
        lpm_vault::VaultStorageBackend::FileFallback => Check::warn(
            &doctor_catalog::VAULT_STORAGE_FALLBACK,
            "encrypted-file fallback (~/.lpm/.vault-fallback-key, 0600)",
        ),
        lpm_vault::VaultStorageBackend::Unavailable { message } => {
            Check::fail(&doctor_catalog::VAULT_STORAGE_UNAVAILABLE, &message)
        }
    }
}

pub(super) fn auth_storage_check(status: auth::AuthStorageStatus) -> Option<Check> {
    match status.backend {
        Some(auth::AuthStorageBackend::Keychain) => Some(Check::pass(
            &doctor_catalog::AUTH_STORAGE_KEYCHAIN,
            "secure storage backend: keychain",
        )),
        Some(auth::AuthStorageBackend::EncryptedFileFallback) => Some(Check::warn(
            &doctor_catalog::AUTH_STORAGE_FALLBACK,
            "secure storage backend: encrypted file fallback",
        )),
        None => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::doctor_catalog::Severity;

    #[test]
    fn vault_storage_check_reports_native_backend_as_pass() {
        let check = vault_storage_check(lpm_vault::VaultStorageBackend::NativeProtected);

        assert_eq!(check.code(), "vault_storage_native");
        assert!(matches!(check.severity, Severity::Pass));
        assert!(check.detail.contains("native-protected"));
    }

    #[test]
    fn vault_storage_check_reports_file_backend_as_warning() {
        let check = vault_storage_check(lpm_vault::VaultStorageBackend::FileFallback);

        assert_eq!(check.code(), "vault_storage_fallback");
        assert!(matches!(check.severity, Severity::Warn));
        assert!(check.detail.contains(".vault-fallback-key"));
    }

    #[test]
    fn vault_storage_check_reports_unavailable_backend_as_failure() {
        let check = vault_storage_check(lpm_vault::VaultStorageBackend::Unavailable {
            message: "native store locked".to_string(),
        });

        assert_eq!(check.code(), "vault_storage_unavailable");
        assert!(matches!(check.severity, Severity::Fail));
        assert_eq!(check.detail, "native store locked");
    }
}
