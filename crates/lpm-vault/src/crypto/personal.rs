use super::{
    CURRENT_CRYPTO_VERSION, VaultScope, decrypt_with_associated_data, encrypt_with_associated_data,
    generate_aes_key,
};
use elliptic_curve::zeroize::{Zeroize, Zeroizing};
use sha2::{Digest, Sha256};

pub const PERSONAL_KEY_SCHEME: i32 = 2;
const ROOT_SERVICE: &str = "dev.lpm.env-personal-root-v2";

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PersonalKeyEnvelope {
    pub personal_key_scheme: i32,
    pub personal_registry_origin: String,
    pub project_key_version: i32,
    pub wrapped_project_key: String,
}

pub struct PersonalProjectKey {
    pub envelope: PersonalKeyEnvelope,
    pub key: [u8; 32],
}

pub struct PersonalKeyContext<'a> {
    pub registry_origin: &'a str,
    pub principal_id: &'a str,
    pub vault_id: &'a str,
    pub project_key_version: i32,
}

pub fn registry_origin(registry_url: &str) -> Result<String, String> {
    let url = reqwest::Url::parse(registry_url).map_err(|_| "invalid personal env registry URL")?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.origin().ascii_serialization().len() > 2048
    {
        return Err("invalid personal env registry URL".into());
    }
    Ok(url.origin().ascii_serialization())
}

fn root_account(origin: &str, principal: &str) -> Result<String, String> {
    if registry_origin(origin)? != origin || principal.is_empty() || principal.len() > 128 {
        return Err("invalid personal env root identity".into());
    }
    let mut hash = Sha256::new();
    hash.update(b"lpm-env-personal-root-v2\0");
    hash.update((origin.len() as u32).to_be_bytes());
    hash.update(origin.as_bytes());
    hash.update((principal.len() as u32).to_be_bytes());
    hash.update(principal.as_bytes());
    Ok(hex::encode(hash.finalize()))
}

pub fn personal_root_key(
    registry_url: &str,
    principal: &str,
    create: bool,
) -> Result<[u8; 32], String> {
    let origin = registry_origin(registry_url)?;
    let account = root_account(&origin, principal)?;
    crate::storage_transaction::with_vault_transaction(|directory| {
        let filename = format!(".env-personal-root-v2-{account}");
        if super::force_file_wrapping_key() {
            return if create {
                super::wrapping_store::get_or_create_file(directory, &filename, &generate_aes_key())
            } else {
                super::wrapping_store::read_file(directory, &filename)?.ok_or_else(|| {
                    "no personal env root key exists for this registry and account".into()
                })
            };
        }
        #[cfg(target_os = "macos")]
        {
            if let Some(encoded) = crate::macos_keychain::read_string(ROOT_SERVICE, &account)? {
                return super::decode_wrapping_key(&encoded);
            }
            if !create {
                return Err("no personal env root key exists for this registry and account".into());
            }
            let encoded = crate::macos_keychain::get_or_insert_string(
                ROOT_SERVICE,
                &account,
                &hex::encode(generate_aes_key()),
            )?;
            super::decode_wrapping_key(&encoded)
        }
        #[cfg(not(target_os = "macos"))]
        super::wrapping_store::load_or_create_with_native(
            directory,
            &filename,
            &PersonalRootStore { account: &account },
            create,
        )
    })
}

#[cfg(not(target_os = "macos"))]
struct PersonalRootStore<'a> {
    account: &'a str,
}
#[cfg(not(target_os = "macos"))]
impl super::wrapping_store::NativeWrappingKeyStore for PersonalRootStore<'_> {
    fn read(&self) -> Result<Option<[u8; 32]>, String> {
        let entry = keyring::Entry::new(ROOT_SERVICE, self.account)
            .map_err(|error| format!("env root keyring entry: {error}"))?;
        match entry.get_password() {
            Ok(value) => super::decode_wrapping_key(&value).map(Some),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(error) => Err(format!("env root keyring read: {error}")),
        }
    }
    fn write(&self, candidate: &[u8; 32]) -> Result<(), String> {
        keyring::Entry::new(ROOT_SERVICE, self.account)
            .map_err(|error| format!("env root keyring entry: {error}"))?
            .set_password(&hex::encode(candidate))
            .map_err(|error| format!("env root keyring write: {error}"))
    }
}

pub fn key_associated_data(
    context: &PersonalKeyContext<'_>,
    revision: Option<i32>,
) -> Result<Vec<u8>, String> {
    if registry_origin(context.registry_origin)? != context.registry_origin
        || context.principal_id.is_empty()
        || context.principal_id.len() > 128
        || context.vault_id.is_empty()
        || context.vault_id.len() > 256
        || context.project_key_version <= 0
    {
        return Err("invalid personal env key context".into());
    }
    let mut aad = Vec::with_capacity(
        64 + context.registry_origin.len() + context.principal_id.len() + context.vault_id.len(),
    );
    aad.extend_from_slice(b"lpm-env-personal-key\0");
    aad.extend_from_slice(&PERSONAL_KEY_SCHEME.to_be_bytes());
    aad.push(if revision.is_some() { 2 } else { 1 });
    for value in [
        context.registry_origin,
        context.principal_id,
        context.vault_id,
    ] {
        aad.extend_from_slice(&(value.len() as u32).to_be_bytes());
        aad.extend_from_slice(value.as_bytes());
    }
    aad.extend_from_slice(&context.project_key_version.to_be_bytes());
    if let Some(revision) = revision {
        if revision <= 0 {
            return Err("invalid personal env content revision".into());
        }
        aad.extend_from_slice(&CURRENT_CRYPTO_VERSION.to_be_bytes());
        aad.extend_from_slice(&i64::from(revision).to_be_bytes());
    }
    Ok(aad)
}

fn unwrap(key: &[u8; 32], wrapped: &str, aad: &[u8]) -> Result<[u8; 32], String> {
    let plaintext = Zeroizing::new(decrypt_with_associated_data(key, wrapped, aad)?);
    plaintext
        .as_slice()
        .try_into()
        .map_err(|_| "invalid personal env key length".into())
}

pub fn create_project_key(context: &PersonalKeyContext<'_>) -> Result<PersonalProjectKey, String> {
    let root = Zeroizing::new(personal_root_key(
        context.registry_origin,
        context.principal_id,
        true,
    )?);
    let key = Zeroizing::new(generate_aes_key());
    let wrapped =
        encrypt_with_associated_data(&root, key.as_ref(), &key_associated_data(context, None)?);
    Ok(PersonalProjectKey {
        key: *key,
        envelope: PersonalKeyEnvelope {
            personal_key_scheme: PERSONAL_KEY_SCHEME,
            personal_registry_origin: context.registry_origin.into(),
            project_key_version: context.project_key_version,
            wrapped_project_key: wrapped?,
        },
    })
}

pub fn open_project_key(
    envelope: &PersonalKeyEnvelope,
    registry_url: &str,
    principal: &str,
    vault_id: &str,
) -> Result<PersonalProjectKey, String> {
    if envelope.personal_key_scheme != PERSONAL_KEY_SCHEME
        || registry_origin(registry_url)? != envelope.personal_registry_origin
    {
        return Err("personal env key scheme or registry binding does not match".into());
    }
    let context = PersonalKeyContext {
        registry_origin: &envelope.personal_registry_origin,
        principal_id: principal,
        vault_id,
        project_key_version: envelope.project_key_version,
    };
    let root = Zeroizing::new(personal_root_key(registry_url, principal, false)?);
    let key = unwrap(
        &root,
        &envelope.wrapped_project_key,
        &key_associated_data(&context, None)?,
    );
    Ok(PersonalProjectKey {
        envelope: envelope.clone(),
        key: key?,
    })
}

pub fn encrypt_personal_payload(
    project: &PersonalProjectKey,
    principal: &str,
    vault_id: &str,
    revision: i32,
    plaintext: &str,
) -> Result<(String, String), String> {
    let context = PersonalKeyContext {
        registry_origin: &project.envelope.personal_registry_origin,
        principal_id: principal,
        vault_id,
        project_key_version: project.envelope.project_key_version,
    };
    let content_key = Zeroizing::new(generate_aes_key());
    let encrypted_blob = super::encrypt_vault_payload(
        &content_key,
        plaintext.as_bytes(),
        VaultScope::Personal,
        principal,
        vault_id,
        revision,
    )?;
    let wrapped_key = encrypt_with_associated_data(
        &project.key,
        content_key.as_ref(),
        &key_associated_data(&context, Some(revision))?,
    )?;
    Ok((encrypted_blob, wrapped_key))
}

pub fn decrypt_personal_payload(
    project: &PersonalProjectKey,
    principal: &str,
    vault_id: &str,
    revision: i32,
    crypto_version: i32,
    encrypted_blob: &str,
    wrapped_key: &str,
) -> Result<String, String> {
    let context = PersonalKeyContext {
        registry_origin: &project.envelope.personal_registry_origin,
        principal_id: principal,
        vault_id,
        project_key_version: project.envelope.project_key_version,
    };
    let content_key = Zeroizing::new(unwrap(
        &project.key,
        wrapped_key,
        &key_associated_data(&context, Some(revision))?,
    )?);
    let plaintext = super::decrypt_vault_payload(
        &content_key,
        encrypted_blob,
        VaultScope::Personal,
        principal,
        vault_id,
        revision,
        crypto_version,
    );
    String::from_utf8(plaintext?).map_err(|_| "decrypted personal env data is not UTF-8".into())
}

impl Drop for PersonalProjectKey {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

fn project_floor_name(origin: &str, principal: &str, vault_id: &str) -> Result<String, String> {
    let mut hash = Sha256::new();
    hash.update(root_account(origin, principal)?.as_bytes());
    hash.update(vault_id.as_bytes());
    Ok(format!(
        ".env-project-key-floor-{}",
        hex::encode(hash.finalize())
    ))
}

fn read_floor(
    directory: &crate::storage_transaction::VaultStorageDirectory,
    filename: &str,
) -> Result<i32, String> {
    let Some(bytes) = directory.read_owner_only_file(filename, "personal env key checkpoint")?
    else {
        return Ok(0);
    };
    std::str::from_utf8(&bytes)
        .ok()
        .and_then(|text| text.parse::<i32>().ok())
        .filter(|value| *value > 0)
        .ok_or_else(|| "invalid personal env key checkpoint".into())
}

pub fn project_key_floor(
    registry_url: &str,
    principal: &str,
    vault_id: &str,
) -> Result<i32, String> {
    let filename = project_floor_name(&registry_origin(registry_url)?, principal, vault_id)?;
    crate::storage_transaction::with_vault_transaction(|directory| read_floor(directory, &filename))
}

pub fn validate_key_floor(
    envelope: Option<&PersonalKeyEnvelope>,
    registry_url: &str,
    principal: &str,
    vault_id: &str,
) -> Result<(), String> {
    let floor = project_key_floor(registry_url, principal, vault_id)?;
    let version = envelope.map_or(0, |key| key.project_key_version);
    if version < floor {
        return Err(
            "cloud personal env keys are older than the trusted local key checkpoint".into(),
        );
    }
    Ok(())
}

pub fn remember_key_version(
    envelope: &PersonalKeyEnvelope,
    principal: &str,
    vault_id: &str,
) -> Result<(), String> {
    let filename = project_floor_name(&envelope.personal_registry_origin, principal, vault_id)?;
    crate::storage_transaction::with_vault_transaction(|directory| {
        let floor = read_floor(directory, &filename)?;
        if envelope.project_key_version < floor {
            return Err(
                "cloud personal env keys are older than the trusted local key checkpoint".into(),
            );
        }
        if envelope.project_key_version > floor {
            directory.write_owner_only_file_durable(
                &filename,
                envelope.project_key_version.to_string().as_bytes(),
                "personal env key checkpoint",
            )?;
        }
        Ok(())
    })
}

#[cfg(all(test, debug_assertions))]
mod tests {
    use super::*;

    fn context() -> PersonalKeyContext<'static> {
        PersonalKeyContext {
            registry_origin: "https://lpm.dev",
            principal_id: "user-a",
            vault_id: "project-a",
            project_key_version: 1,
        }
    }

    #[test]
    fn trusted_project_checkpoint_rejects_legacy_and_older_project_keys() {
        let _env = super::super::tests::IsolatedVaultEnv::new();
        let project = create_project_key(&context()).unwrap();
        assert!(validate_key_floor(None, "https://lpm.dev", "user-a", "project-a").is_ok());
        remember_key_version(&project.envelope, "user-a", "project-a").unwrap();
        assert!(validate_key_floor(None, "https://lpm.dev", "user-a", "project-a").is_err());
        let mut rotated = project.envelope.clone();
        rotated.project_key_version = 2;
        remember_key_version(&rotated, "user-a", "project-a").unwrap();
        assert!(
            validate_key_floor(
                Some(&project.envelope),
                "https://lpm.dev",
                "user-a",
                "project-a"
            )
            .is_err()
        );
        assert!(remember_key_version(&project.envelope, "user-a", "project-a").is_err());
        assert_eq!(
            project_key_floor("https://lpm.dev/", "user-a", "project-a").unwrap(),
            2
        );
        assert!(
            validate_key_floor(Some(&rotated), "https://lpm.dev", "user-a", "project-a").is_ok()
        );
    }

    #[test]
    fn project_checkpoints_are_scoped_to_registry_account_and_project() {
        let _env = super::super::tests::IsolatedVaultEnv::new();
        let project = create_project_key(&context()).unwrap();
        remember_key_version(&project.envelope, "user-a", "project-a").unwrap();
        for (origin, principal, project_id) in [
            ("https://other.example", "user-a", "project-a"),
            ("https://lpm.dev", "user-b", "project-a"),
            ("https://lpm.dev", "user-a", "project-b"),
        ] {
            assert_eq!(project_key_floor(origin, principal, project_id).unwrap(), 0);
        }
    }

    #[test]
    fn every_personal_save_uses_a_fresh_content_key() {
        let _env = super::super::tests::IsolatedVaultEnv::new();
        let project = create_project_key(&context()).unwrap();
        let (first_blob, first_wrapped) =
            encrypt_personal_payload(&project, "user-a", "project-a", 1, "first").unwrap();
        let (second_blob, second_wrapped) =
            encrypt_personal_payload(&project, "user-a", "project-a", 2, "second").unwrap();
        let first_key = unwrap(
            &project.key,
            &first_wrapped,
            &key_associated_data(&context(), Some(1)).unwrap(),
        )
        .unwrap();
        let second_key = unwrap(
            &project.key,
            &second_wrapped,
            &key_associated_data(&context(), Some(2)).unwrap(),
        )
        .unwrap();
        assert_ne!(first_key, second_key);
        assert_eq!(
            decrypt_personal_payload(
                &project,
                "user-a",
                "project-a",
                1,
                3,
                &first_blob,
                &first_wrapped
            )
            .unwrap(),
            "first"
        );
        assert_eq!(
            decrypt_personal_payload(
                &project,
                "user-a",
                "project-a",
                2,
                3,
                &second_blob,
                &second_wrapped
            )
            .unwrap(),
            "second"
        );
    }

    #[test]
    fn personal_content_key_context_matches_browser_wire_bytes() {
        assert_eq!(
            hex::encode(key_associated_data(&context(), Some(7)).unwrap()),
            "6c706d2d656e762d706572736f6e616c2d6b65790000000002020000000f68747470733a2f2f6c706d2e64657600000006757365722d610000000970726f6a6563742d6100000001000000030000000000000007"
        );
    }

    #[test]
    fn escrowed_project_key_cannot_open_other_projects_or_their_envelopes() {
        let _env = super::super::tests::IsolatedVaultEnv::new();
        let a = create_project_key(&context()).unwrap();
        let b_context = PersonalKeyContext {
            vault_id: "project-b",
            ..context()
        };
        let b = create_project_key(&b_context).unwrap();
        let (blob, wrapped) =
            encrypt_personal_payload(&b, "user-a", "project-b", 7, "fixture").unwrap();
        assert!(
            unwrap(
                &a.key,
                &b.envelope.wrapped_project_key,
                &key_associated_data(&b_context, None).unwrap()
            )
            .is_err()
        );
        let forged = PersonalProjectKey {
            envelope: b.envelope.clone(),
            key: a.key,
        };
        assert!(
            decrypt_personal_payload(&forged, "user-a", "project-b", 7, 3, &blob, &wrapped)
                .is_err()
        );
        assert_eq!(
            decrypt_personal_payload(&b, "user-a", "project-b", 7, 3, &blob, &wrapped).unwrap(),
            "fixture"
        );
    }

    #[test]
    fn personal_roots_are_independent_of_legacy_keys_registries_and_accounts() {
        let _env = super::super::tests::IsolatedVaultEnv::new();
        let legacy = super::super::get_or_create_wrapping_key().unwrap();
        let root = personal_root_key("https://lpm.dev", "user-a", true).unwrap();
        assert_ne!(root, legacy);
        assert_eq!(
            root,
            personal_root_key("https://lpm.dev/", "user-a", false).unwrap()
        );
        assert_ne!(
            root,
            personal_root_key("https://other.example", "user-a", true).unwrap()
        );
        assert_ne!(
            root,
            personal_root_key("https://lpm.dev", "user-b", true).unwrap()
        );
        assert_eq!(super::super::get_or_create_wrapping_key().unwrap(), legacy);
    }

    #[test]
    fn project_envelope_and_content_authenticate_context_and_revision() {
        let _env = super::super::tests::IsolatedVaultEnv::new();
        let project = create_project_key(&context()).unwrap();
        let opened =
            open_project_key(&project.envelope, "https://lpm.dev", "user-a", "project-a").unwrap();
        assert_eq!(opened.key, project.key);
        assert!(
            open_project_key(&project.envelope, "https://lpm.dev", "user-a", "project-b").is_err()
        );
        assert!(
            open_project_key(
                &project.envelope,
                "https://other.example",
                "user-a",
                "project-a"
            )
            .is_err()
        );
        let mut envelope = project.envelope.clone();
        envelope.project_key_version += 1;
        assert!(open_project_key(&envelope, "https://lpm.dev", "user-a", "project-a").is_err());
        let (blob, wrapped) =
            encrypt_personal_payload(&project, "user-a", "project-a", 7, "fixture").unwrap();
        assert!(
            decrypt_personal_payload(&project, "user-a", "project-a", 8, 3, &blob, &wrapped)
                .is_err()
        );
        assert_eq!(
            decrypt_personal_payload(&opened, "user-a", "project-a", 7, 3, &blob, &wrapped)
                .unwrap(),
            "fixture"
        );
    }
}
