use crate::credential_authority::{CredentialAuthority, CredentialBackend};

trait MigrationBackend {
    fn read_legacy(&mut self) -> Result<Option<String>, String>;
    fn write_shared(&mut self, token: &str) -> Result<(), String>;
    fn read_shared(&mut self) -> Result<Option<String>, String>;
    fn save_authority(&mut self, authority: &CredentialAuthority) -> Result<(), String>;
    fn delete_legacy(&mut self) -> Result<(), String>;
}

fn migrate(
    authority: &mut CredentialAuthority,
    backend: &mut impl MigrationBackend,
) -> Result<(), String> {
    let mut verified = false;
    if authority.backend() == Some(CredentialBackend::Keychain) {
        let token = backend
            .read_legacy()?
            .ok_or("legacy Keychain credential is unavailable")?;
        if !authority.matches_token(&token) {
            return Err(
                "legacy Keychain credential does not match its authority record".to_owned(),
            );
        }
        backend.write_shared(&token)?;
        if backend.read_shared()?.as_deref() != Some(token.as_str()) {
            return Err("shared Keychain migration verification failed".to_owned());
        }
        let next = authority.with_shared_keychain_cleanup(true);
        backend.save_authority(&next)?;
        *authority = next;
        verified = true;
    }
    if authority.has_pending_legacy_keychain_cleanup() {
        if !verified {
            let token = backend
                .read_shared()?
                .ok_or("shared Keychain credential is unavailable")?;
            if !authority.matches_token(&token) {
                return Err(
                    "shared Keychain credential does not match its authority record".to_owned(),
                );
            }
        }
        backend.delete_legacy()?;
        let next = authority.with_shared_keychain_cleanup(false);
        backend.save_authority(&next)?;
        *authority = next;
    }
    Ok(())
}

#[cfg(target_os = "macos")]
pub(super) fn prepare(
    registry: &str,
    kind: crate::credential_authority::CredentialKind,
    account: &str,
    authority: &mut CredentialAuthority,
    notice: impl FnMut(),
) -> Result<(), String> {
    struct Native<'a, F> {
        registry: &'a str,
        kind: crate::credential_authority::CredentialKind,
        account: &'a str,
        service: std::borrow::Cow<'static, str>,
        notice: F,
    }
    impl<F: FnMut()> MigrationBackend for Native<'_, F> {
        fn read_legacy(&mut self) -> Result<Option<String>, String> {
            use crate::macos_keychain::{self, Scope};
            match macos_keychain::read(&self.service, self.account, Scope::Legacy, false) {
                Err(error) if error.code() == crate::ERR_SEC_INTERACTION_NOT_ALLOWED => {
                    (self.notice)();
                    macos_keychain::read(&self.service, self.account, Scope::Legacy, true)
                        .map_err(|error| format!("legacy Keychain read failed: {error}"))
                }
                result => result.map_err(|error| format!("legacy Keychain read failed: {error}")),
            }
        }
        fn write_shared(&mut self, token: &str) -> Result<(), String> {
            crate::macos_keychain::write(&self.service, self.account, token)
                .map_err(|error| format!("shared Keychain migration failed: {error}"))
        }
        fn read_shared(&mut self) -> Result<Option<String>, String> {
            crate::macos_keychain::read(
                &self.service,
                self.account,
                crate::macos_keychain::Scope::Shared,
                false,
            )
            .map_err(|error| format!("shared Keychain read failed: {error}"))
        }
        fn save_authority(&mut self, authority: &CredentialAuthority) -> Result<(), String> {
            crate::credential_authority::set(self.registry, self.kind, authority.clone())
        }
        fn delete_legacy(&mut self) -> Result<(), String> {
            crate::macos_keychain::delete(
                &self.service,
                self.account,
                crate::macos_keychain::Scope::Legacy,
            )
            .map_err(|error| format!("legacy Keychain cleanup failed: {error}"))
        }
    }
    migrate(
        authority,
        &mut Native {
            registry,
            kind,
            account,
            service: crate::keychain_service(),
            notice,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct Memory {
        legacy: Option<String>,
        shared: Option<String>,
        saved: Option<CredentialAuthority>,
        fail_write: bool,
        fail_delete: bool,
        fail_save: bool,
        corrupt_copy: bool,
        legacy_reads: usize,
        writes: usize,
    }
    impl MigrationBackend for Memory {
        fn read_legacy(&mut self) -> Result<Option<String>, String> {
            self.legacy_reads += 1;
            Ok(self.legacy.clone())
        }
        fn write_shared(&mut self, token: &str) -> Result<(), String> {
            self.writes += 1;
            if self.fail_write {
                return Err("write failed".into());
            }
            self.shared = Some(if self.corrupt_copy { "corrupt" } else { token }.to_owned());
            Ok(())
        }
        fn read_shared(&mut self) -> Result<Option<String>, String> {
            Ok(self.shared.clone())
        }
        fn save_authority(&mut self, authority: &CredentialAuthority) -> Result<(), String> {
            if self.fail_save {
                return Err("save failed".into());
            }
            self.saved = Some(authority.clone());
            Ok(())
        }
        fn delete_legacy(&mut self) -> Result<(), String> {
            if self.fail_delete {
                return Err("delete failed".into());
            }
            self.legacy = None;
            Ok(())
        }
    }
    fn legacy() -> (CredentialAuthority, Memory) {
        (
            CredentialAuthority::active(CredentialBackend::Keychain, "valid"),
            Memory {
                legacy: Some("valid".into()),
                ..Memory::default()
            },
        )
    }

    #[test]
    fn matching_legacy_credential_moves_to_shared_storage() {
        let (mut authority, mut memory) = legacy();
        migrate(&mut authority, &mut memory).unwrap();
        assert_eq!(authority.backend(), Some(CredentialBackend::SharedKeychain));
        assert!(!authority.has_pending_legacy_keychain_cleanup());
        assert_eq!(memory.shared.as_deref(), Some("valid"));
        assert!(memory.legacy.is_none());
        assert_eq!(memory.saved.as_ref(), Some(&authority));
    }
    #[test]
    fn substituted_legacy_credential_is_never_copied() {
        let (mut authority, mut memory) = legacy();
        memory.legacy = Some("substitution".into());
        assert!(migrate(&mut authority, &mut memory).is_err());
        assert_eq!(memory.writes, 0);
        assert!(memory.shared.is_none());
    }
    #[test]
    fn failed_write_keeps_legacy_credential_and_authority() {
        let (mut authority, mut memory) = legacy();
        memory.fail_write = true;
        assert!(migrate(&mut authority, &mut memory).is_err());
        assert_eq!(authority.backend(), Some(CredentialBackend::Keychain));
        assert_eq!(memory.legacy.as_deref(), Some("valid"));
        memory.fail_write = false;
        migrate(&mut authority, &mut memory).unwrap();
    }
    #[test]
    fn failed_verification_or_authority_commit_never_deletes_legacy() {
        for corrupt in [false, true] {
            let (mut authority, mut memory) = legacy();
            memory.corrupt_copy = corrupt;
            memory.fail_save = !corrupt;
            assert!(migrate(&mut authority, &mut memory).is_err());
            assert_eq!(authority.backend(), Some(CredentialBackend::Keychain));
            assert_eq!(memory.legacy.as_deref(), Some("valid"));
        }
    }
    #[test]
    fn interrupted_cleanup_uses_shared_authority_without_reimporting_legacy() {
        let (mut authority, mut memory) = legacy();
        memory.fail_delete = true;
        assert!(migrate(&mut authority, &mut memory).is_err());
        assert!(authority.has_pending_legacy_keychain_cleanup());
        assert_eq!(authority.backend(), Some(CredentialBackend::SharedKeychain));
        memory.legacy = Some("stale".into());
        memory.fail_delete = false;
        migrate(&mut authority, &mut memory).unwrap();
        assert_eq!(memory.legacy_reads, 1);
        assert_eq!(memory.shared.as_deref(), Some("valid"));
        assert!(!authority.has_pending_legacy_keychain_cleanup());
    }
    #[test]
    fn revoked_and_file_credentials_never_touch_either_keychain() {
        for mut authority in [
            CredentialAuthority::Revoked,
            CredentialAuthority::active(CredentialBackend::EncryptedFileFallback, "valid"),
        ] {
            let mut memory = Memory::default();
            migrate(&mut authority, &mut memory).unwrap();
            assert_eq!(memory.legacy_reads, 0);
            assert_eq!(memory.writes, 0);
            assert!(memory.saved.is_none());
        }
    }
}
