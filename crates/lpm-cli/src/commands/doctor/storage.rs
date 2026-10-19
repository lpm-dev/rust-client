use std::path::Path;

use crate::{auth, doctor_catalog};

use super::check::Check;

/// Files LPM CLI keeps in an LPM home for login and local env secrets.
const CREDENTIAL_STATE_FILES: [&str; 5] = [
    ".credentials",
    ".credential-authority.json",
    ".vault-key",
    ".vault-fallback-key",
    "vaults",
];
const CREDENTIAL_STATE_PREFIXES: [&str; 2] = [".env-project-key-floor-", ".org-recipient-set-"];

fn fallback_key_display() -> String {
    match lpm_common::LpmRoot::from_env() {
        Ok(root) if !root.is_default() => root
            .root()
            .join(".vault-fallback-key")
            .display()
            .to_string(),
        _ => "~/.lpm/.vault-fallback-key".to_owned(),
    }
}

/// Warns when `LPM_HOME` moves login and env secrets away from `~/.lpm`
/// while `~/.lpm` still holds them, so a missing login or env isn't a
/// mystery.
pub(super) fn lpm_home_default_state_check() -> Option<Check> {
    let root = lpm_common::LpmRoot::from_env().ok()?;
    if root.is_default() {
        return None;
    }
    let default_root = dirs::home_dir()?.join(".lpm");
    let found = credential_state_in(&default_root);
    (!found.is_empty()).then(|| {
        Check::warn(
            &doctor_catalog::LPM_HOME_DEFAULT_STATE_UNUSED,
            &format!(
                "LPM_HOME is {}; {} in {} are not used",
                root.root().display(),
                found.join(", "),
                default_root.display()
            ),
        )
    })
}

fn credential_state_in(root: &Path) -> Vec<String> {
    let Ok(entries) = std::fs::read_dir(root) else {
        return Vec::new();
    };
    let mut found: Vec<String> = entries
        .filter_map(Result::ok)
        .filter_map(|entry| entry.file_name().into_string().ok())
        .filter(|name| {
            CREDENTIAL_STATE_FILES.contains(&name.as_str())
                || CREDENTIAL_STATE_PREFIXES
                    .iter()
                    .any(|prefix| name.starts_with(prefix))
        })
        .collect();
    found.sort_unstable();
    found
}

pub(super) fn vault_storage_check(backend: lpm_vault::VaultStorageBackend) -> Check {
    match backend {
        lpm_vault::VaultStorageBackend::MacosKeychain => Check::pass(
            &doctor_catalog::VAULT_STORAGE_KEYCHAIN,
            "macOS Keychain selected; access not probed",
        ),
        lpm_vault::VaultStorageBackend::NativeProtected => Check::pass(
            &doctor_catalog::VAULT_STORAGE_NATIVE,
            "native-protected data key",
        ),
        lpm_vault::VaultStorageBackend::NativeProtectedWithFallback => Check::warn(
            &doctor_catalog::VAULT_STORAGE_NATIVE_WITH_FALLBACK,
            &format!(
                "native data key is present, but {} still permits offline decryption",
                fallback_key_display()
            ),
        ),
        lpm_vault::VaultStorageBackend::NativePreferred => Check::pass(
            &doctor_catalog::VAULT_STORAGE_NATIVE,
            "native secure store preferred for new local secrets; access not established",
        ),
        lpm_vault::VaultStorageBackend::FileFallback => Check::warn(
            &doctor_catalog::VAULT_STORAGE_FALLBACK,
            &format!("encrypted-file fallback ({}, 0600)", fallback_key_display()),
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

    #[cfg(unix)]
    #[test]
    fn warns_when_lpm_home_leaves_login_and_env_data_in_the_default_home() {
        let home = tempfile::tempdir().unwrap();
        let default_root = home.path().join(".lpm");
        std::fs::create_dir_all(default_root.join("vaults")).unwrap();
        std::fs::write(default_root.join(".credentials"), "x").unwrap();
        std::fs::write(default_root.join("config.toml"), "").unwrap();
        let other = home.path().join("other-lpm");

        let check = {
            let _env = crate::test_env::ScopedEnv::update([
                ("HOME", Some(home.path().as_os_str().to_owned())),
                ("LPM_HOME", Some(other.into_os_string())),
            ]);
            lpm_home_default_state_check().expect("a warning for the unused default home")
        };
        assert_eq!(check.code(), "lpm_home_default_state_unused");
        assert!(matches!(check.severity, Severity::Warn));
        assert!(
            check.detail.contains(".credentials, vaults"),
            "{}",
            check.detail
        );
        assert!(!check.detail.contains("config.toml"), "{}", check.detail);

        for lpm_home in [None, Some(default_root.into_os_string())] {
            let _env = crate::test_env::ScopedEnv::update([
                ("HOME", Some(home.path().as_os_str().to_owned())),
                ("LPM_HOME", lpm_home),
            ]);
            assert!(lpm_home_default_state_check().is_none());
        }
    }

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
    fn vault_storage_check_warns_when_native_backend_retains_fallback_key() {
        let check =
            vault_storage_check(lpm_vault::VaultStorageBackend::NativeProtectedWithFallback);

        assert_eq!(check.code(), "vault_storage_native_with_fallback");
        assert!(matches!(check.severity, Severity::Warn));
        assert!(check.detail.contains("offline decryption"));
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
