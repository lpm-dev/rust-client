use base64::Engine as _;
use sha2::{Digest as _, Sha256};

use super::public_key::{MemberPublicKey, public_key_fingerprint};
use crate::crypto;

const RECIPIENT_SET_SCHEMA_VERSION: u32 = 2;

#[cfg(test)]
thread_local! {
    static SERIALIZATION_COUNT: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct RecipientTrustScope {
    registry_url: String,
    organization_id: String,
    organization_slug: String,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct TrustedRecipientSet {
    schema_version: u32,
    scope: RecipientTrustScope,
    recipients: Vec<RecipientBinding>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(super) struct RecipientBinding {
    pub(super) user_id: String,
    pub(super) public_key_version: i32,
    pub(super) public_key_fingerprint: String,
}

#[derive(Debug)]
pub(super) struct PreparedRecipient {
    pub(super) binding: RecipientBinding,
    pub(super) public_key: [u8; 32],
}

pub(super) fn prepare_recipients(
    members: &[&MemberPublicKey],
) -> Result<Vec<PreparedRecipient>, String> {
    let mut recipients = Vec::with_capacity(members.len());
    for member in members {
        if member.user_id.is_empty() {
            return Err("organization recipient user ID cannot be empty".to_owned());
        }
        let encoded = member
            .public_key
            .as_deref()
            .ok_or_else(|| format!("missing public key for user {}", member.user_id))?;
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .map_err(|error| format!("invalid public key for user {}: {error}", member.user_id))?;
        let public_key: [u8; 32] = decoded.try_into().map_err(|decoded: Vec<u8>| {
            format!(
                "invalid public key for user {}: expected 32 bytes, got {}",
                member.user_id,
                decoded.len()
            )
        })?;
        crypto::validate_contributory_x25519_public_key(&public_key)
            .map_err(|error| format!("invalid public key for user {}: {error}", member.user_id))?;
        let fingerprint = public_key_fingerprint(&public_key);
        let expected_fingerprint = member
            .public_key_fingerprint
            .as_deref()
            .ok_or_else(|| format!("missing public-key fingerprint for user {}", member.user_id))?;
        if fingerprint != expected_fingerprint {
            return Err(format!(
                "public-key fingerprint mismatch for organization member {}",
                member.user_id
            ));
        }
        let public_key_version = member
            .public_key_version
            .filter(|version| *version > 0)
            .ok_or_else(|| format!("invalid public-key version for user {}", member.user_id))?;
        recipients.push(PreparedRecipient {
            binding: RecipientBinding {
                user_id: member.user_id.clone(),
                public_key_version,
                public_key_fingerprint: fingerprint,
            },
            public_key,
        });
    }

    recipients.sort_unstable_by(|left, right| left.binding.user_id.cmp(&right.binding.user_id));
    if let Some(duplicate) = recipients
        .windows(2)
        .find(|pair| pair[0].binding.user_id == pair[1].binding.user_id)
    {
        return Err(format!(
            "duplicate organization recipient user ID: {}",
            duplicate[0].binding.user_id
        ));
    }
    Ok(recipients)
}

pub(super) fn enforce_recipient_trust(
    registry_url: &str,
    organization_id: &str,
    organization_slug: &str,
    recipients: &[PreparedRecipient],
    accepted_digest: Option<&str>,
) -> Result<(), String> {
    let scope = RecipientTrustScope::new(registry_url, organization_id, organization_slug)?;
    let file_name = recipient_set_file_name(&scope);

    crate::storage_transaction::with_vault_transaction(|directory| {
        let mut storage = DirectoryRecipientSetStorage { directory };
        enforce_recipient_trust_with_storage(
            &mut storage,
            &file_name,
            &scope,
            recipients,
            accepted_digest,
        )
    })
}

#[cfg(all(test, debug_assertions))]
pub(super) fn acceptance_digest(
    registry_url: &str,
    organization_id: &str,
    organization_slug: &str,
    recipients: &[PreparedRecipient],
) -> Result<String, String> {
    let scope = RecipientTrustScope::new(registry_url, organization_id, organization_slug)?;
    let proposed = proposed_recipient_set(&scope, recipients);
    Ok(recipient_set_digest(&serialize_recipient_set(&proposed)?))
}

trait RecipientSetStorage {
    fn read(&mut self, file_name: &str) -> Result<Option<Vec<u8>>, String>;
    fn write(&mut self, file_name: &str, contents: &[u8]) -> Result<(), String>;
}

struct DirectoryRecipientSetStorage<'a> {
    directory: &'a crate::storage_transaction::VaultStorageDirectory,
}

impl RecipientSetStorage for DirectoryRecipientSetStorage<'_> {
    fn read(&mut self, file_name: &str) -> Result<Option<Vec<u8>>, String> {
        self.directory
            .read_owner_only_file(file_name, "trusted recipient set")
    }

    fn write(&mut self, file_name: &str, contents: &[u8]) -> Result<(), String> {
        self.directory
            .write_owner_only_file_durable(file_name, contents, "trusted recipient set")
    }
}

fn enforce_recipient_trust_with_storage(
    storage: &mut impl RecipientSetStorage,
    file_name: &str,
    scope: &RecipientTrustScope,
    recipients: &[PreparedRecipient],
    accepted_digest: Option<&str>,
) -> Result<(), String> {
    if let Some(stored) = storage.read(file_name)? {
        let trusted = parse_stored_recipient_set(&stored, scope)?;
        if trusted.recipients.len() == recipients.len()
            && trusted
                .recipients
                .iter()
                .zip(recipients)
                .all(|(trusted, proposed)| trusted == &proposed.binding)
        {
            return Ok(());
        }
    }

    let proposed = proposed_recipient_set(scope, recipients);
    let proposed_bytes = serialize_recipient_set(&proposed)?;
    let proposed_digest = recipient_set_digest(&proposed_bytes);

    if accepted_digest == Some(proposed_digest.as_str()) {
        storage.write(file_name, &proposed_bytes)?;
        let persisted = storage
            .read(file_name)?
            .ok_or_else(|| "trusted recipient set disappeared after persistence".to_owned())?;
        if parse_stored_recipient_set(&persisted, &proposed.scope)? != proposed {
            return Err("persisted recipient set does not match the accepted set".to_owned());
        }
        return Ok(());
    }

    let proposed_display = serde_json::to_string_pretty(&proposed.recipients)
        .map_err(|error| format!("failed to display proposed recipient set: {error}"))?;
    Err(format!(
        "organization recipient set is not trusted. Review the exact proposed bindings:\n{proposed_display}\nRerun with `--accept-recipient-keys {proposed_digest}` to trust this exact set."
    ))
}

fn proposed_recipient_set(
    scope: &RecipientTrustScope,
    recipients: &[PreparedRecipient],
) -> TrustedRecipientSet {
    TrustedRecipientSet {
        schema_version: RECIPIENT_SET_SCHEMA_VERSION,
        scope: scope.clone(),
        recipients: recipients
            .iter()
            .map(|recipient| recipient.binding.clone())
            .collect(),
    }
}

fn serialize_recipient_set(recipient_set: &TrustedRecipientSet) -> Result<Vec<u8>, String> {
    #[cfg(test)]
    SERIALIZATION_COUNT.with(|count| count.set(count.get() + 1));
    serde_json::to_vec(recipient_set)
        .map_err(|error| format!("failed to serialize trusted recipient set: {error}"))
}

#[cfg(test)]
fn reset_serialization_count() {
    SERIALIZATION_COUNT.with(|count| count.set(0));
}

#[cfg(test)]
fn serialization_count() -> usize {
    SERIALIZATION_COUNT.with(std::cell::Cell::get)
}

fn recipient_set_digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn parse_stored_recipient_set(
    bytes: &[u8],
    expected_scope: &RecipientTrustScope,
) -> Result<TrustedRecipientSet, String> {
    let trusted: TrustedRecipientSet = serde_json::from_slice(bytes)
        .map_err(|error| format!("trusted recipient set is malformed: {error}"))?;
    if trusted.schema_version != RECIPIENT_SET_SCHEMA_VERSION {
        return Err(format!(
            "unsupported trusted recipient-set schema version: {}",
            trusted.schema_version
        ));
    }
    if trusted.scope != *expected_scope {
        return Err("trusted recipient set belongs to another organization".to_owned());
    }
    for recipient in &trusted.recipients {
        if recipient.user_id.is_empty()
            || recipient.public_key_version <= 0
            || recipient.public_key_fingerprint.len() != 64
            || !recipient
                .public_key_fingerprint
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err("trusted recipient set contains an invalid binding".to_owned());
        }
    }
    if trusted
        .recipients
        .windows(2)
        .any(|pair| pair[0].user_id >= pair[1].user_id)
    {
        return Err("trusted recipient set is not in canonical user-ID order".to_owned());
    }
    Ok(trusted)
}

fn recipient_set_file_name(scope: &RecipientTrustScope) -> String {
    let mut digest = Sha256::new();
    for component in [
        scope.registry_url.as_bytes(),
        scope.organization_id.as_bytes(),
        scope.organization_slug.as_bytes(),
    ] {
        digest.update((component.len() as u64).to_be_bytes());
        digest.update(component);
    }
    format!(
        ".org-recipient-set-v2-{}.json",
        hex::encode(digest.finalize())
    )
}

impl RecipientTrustScope {
    fn new(
        registry_url: &str,
        organization_id: &str,
        organization_slug: &str,
    ) -> Result<Self, String> {
        if !super::public_key::is_canonical_organization_id(organization_id) {
            return Err("invalid organization identity header".to_owned());
        }
        Ok(Self {
            registry_url: super::public_key::canonical_registry_url(registry_url)?,
            organization_id: organization_id.to_owned(),
            organization_slug: organization_slug.to_owned(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_ORGANIZATION_ID: &str = "00000000-0000-4000-8000-000000000001";

    struct MemoryStorage {
        contents: Option<Vec<u8>>,
        write_error: Option<String>,
    }

    impl RecipientSetStorage for MemoryStorage {
        fn read(&mut self, _file_name: &str) -> Result<Option<Vec<u8>>, String> {
            Ok(self.contents.clone())
        }

        fn write(&mut self, _file_name: &str, contents: &[u8]) -> Result<(), String> {
            if let Some(error) = &self.write_error {
                return Err(error.clone());
            }
            self.contents = Some(contents.to_vec());
            Ok(())
        }
    }

    fn member(user_id: &str, public_key: [u8; 32], version: i32) -> MemberPublicKey {
        MemberPublicKey {
            user_id: user_id.to_owned(),
            role: "member".to_owned(),
            public_key: Some(base64::engine::general_purpose::STANDARD.encode(public_key)),
            public_key_version: Some(version),
            public_key_fingerprint: Some(public_key_fingerprint(&public_key)),
            has_public_key: true,
        }
    }

    fn proposal(
        members: &[&MemberPublicKey],
    ) -> (TrustedRecipientSet, Vec<u8>, String, Vec<PreparedRecipient>) {
        proposal_for_scope(
            &RecipientTrustScope::new("https://registry.example", TEST_ORGANIZATION_ID, "acme")
                .expect("valid test trust scope"),
            members,
        )
    }

    fn proposal_for_scope(
        scope: &RecipientTrustScope,
        members: &[&MemberPublicKey],
    ) -> (TrustedRecipientSet, Vec<u8>, String, Vec<PreparedRecipient>) {
        let recipients = prepare_recipients(members).expect("prepare recipient bindings");
        let proposed = proposed_recipient_set(scope, &recipients);
        let bytes = serialize_recipient_set(&proposed).expect("serialize proposal");
        let digest = recipient_set_digest(&bytes);
        (proposed, bytes, digest, recipients)
    }

    #[test]
    fn first_recipient_set_requires_its_exact_digest_before_persistence() {
        let member = member("user-a", [7u8; 32], 1);
        let (proposed, _bytes, digest, recipients) = proposal(&[&member]);
        let mut storage = MemoryStorage {
            contents: None,
            write_error: None,
        };

        let error = enforce_recipient_trust_with_storage(
            &mut storage,
            "recipient-set.json",
            &proposed.scope,
            &recipients,
            None,
        )
        .expect_err("first use must require explicit acceptance");

        assert!(error.contains(&format!("--accept-recipient-keys {digest}")));
        assert!(storage.contents.is_none());
    }

    #[test]
    fn exact_acceptance_is_durable_and_allows_subsequent_matching_sets() {
        let member = member("user-a", [7u8; 32], 1);
        let (proposed, bytes, digest, recipients) = proposal(&[&member]);
        let mut storage = MemoryStorage {
            contents: None,
            write_error: None,
        };

        enforce_recipient_trust_with_storage(
            &mut storage,
            "recipient-set.json",
            &proposed.scope,
            &recipients,
            Some(&digest),
        )
        .expect("exact digest should persist");
        enforce_recipient_trust_with_storage(
            &mut storage,
            "recipient-set.json",
            &proposed.scope,
            &recipients,
            None,
        )
        .expect("persisted exact set should remain trusted");

        assert_eq!(storage.contents, Some(bytes));
    }

    #[test]
    fn matching_durable_recipient_set_skips_proposal_serialization() {
        let _guard = crate::sync::test_support::env_lock_guard();
        let temp = tempfile::tempdir().expect("create recipient trust home");
        let original_home = crate::test_env_lock::HomeEnvSnapshot::set(temp.path());
        let member = member("user-a", [7u8; 32], 1);
        let recipients = prepare_recipients(&[&member]).expect("prepare recipients");
        let digest = acceptance_digest(
            "https://registry.example",
            TEST_ORGANIZATION_ID,
            "acme",
            &recipients,
        )
        .expect("derive acceptance digest");

        enforce_recipient_trust(
            "https://registry.example",
            TEST_ORGANIZATION_ID,
            "acme",
            &recipients,
            Some(&digest),
        )
        .expect("persist accepted recipient set");
        reset_serialization_count();

        enforce_recipient_trust(
            "https://registry.example",
            TEST_ORGANIZATION_ID,
            "acme",
            &recipients,
            None,
        )
        .expect("reuse matching durable recipient set");

        original_home.restore();
        assert_eq!(serialization_count(), 0);
    }

    #[test]
    fn recipient_trust_is_isolated_by_registry_and_immutable_organization_id() {
        let member = member("user-a", [7u8; 32], 1);
        let first_scope = RecipientTrustScope::new(
            "https://registry-a.example/",
            "00000000-0000-4000-8000-000000000001",
            "acme",
        )
        .expect("valid first scope");
        let second_scope = RecipientTrustScope::new(
            "https://registry-b.example",
            "00000000-0000-4000-8000-000000000002",
            "acme",
        )
        .expect("valid second scope");
        let (_, _, first_digest, _) = proposal_for_scope(&first_scope, &[&member]);
        let (_, _, second_digest, _) = proposal_for_scope(&second_scope, &[&member]);

        assert_ne!(
            recipient_set_file_name(&first_scope),
            recipient_set_file_name(&second_scope)
        );
        assert_ne!(first_digest, second_digest);
    }

    #[test]
    fn changed_recipient_set_rejects_the_previous_acceptance_digest() {
        let member_a = member("user-a", [7u8; 32], 1);
        let member_b = member("user-b", [8u8; 32], 1);
        let (original, original_bytes, original_digest, _original_recipients) =
            proposal(&[&member_a]);
        let (changed, _changed_bytes, changed_digest, changed_recipients) =
            proposal(&[&member_a, &member_b]);
        let mut storage = MemoryStorage {
            contents: Some(original_bytes.clone()),
            write_error: None,
        };

        let error = enforce_recipient_trust_with_storage(
            &mut storage,
            "recipient-set.json",
            &changed.scope,
            &changed_recipients,
            Some(&original_digest),
        )
        .expect_err("a stale acceptance digest must not authorize a changed set");

        assert!(error.contains(&changed_digest));
        assert_eq!(storage.contents, Some(original_bytes));
        assert_ne!(original, changed);
    }

    #[test]
    fn malformed_persisted_json_fails_closed_even_with_a_current_digest() {
        let member = member("user-a", [7u8; 32], 1);
        let (proposed, _bytes, digest, recipients) = proposal(&[&member]);
        let mut storage = MemoryStorage {
            contents: Some(b"{malformed".to_vec()),
            write_error: None,
        };

        let error = enforce_recipient_trust_with_storage(
            &mut storage,
            "recipient-set.json",
            &proposed.scope,
            &recipients,
            Some(&digest),
        )
        .expect_err("malformed trusted state must not be overwritten silently");

        assert!(error.contains("trusted recipient set is malformed"));
    }

    #[test]
    fn durable_write_failure_prevents_recipient_acceptance() {
        let member = member("user-a", [7u8; 32], 1);
        let (proposed, _bytes, digest, recipients) = proposal(&[&member]);
        let mut storage = MemoryStorage {
            contents: None,
            write_error: Some("simulated durable write failure".to_owned()),
        };

        let error = enforce_recipient_trust_with_storage(
            &mut storage,
            "recipient-set.json",
            &proposed.scope,
            &recipients,
            Some(&digest),
        )
        .expect_err("persistence failure must fail closed");

        assert_eq!(error, "simulated durable write failure");
        assert!(storage.contents.is_none());
    }

    #[test]
    fn duplicate_recipient_user_ids_are_rejected() {
        let member_a = member("duplicate", [7u8; 32], 1);
        let member_b = member("duplicate", [8u8; 32], 2);

        let error = prepare_recipients(&[&member_a, &member_b])
            .expect_err("duplicate recipients must fail closed");

        assert_eq!(error, "duplicate organization recipient user ID: duplicate");
    }

    #[test]
    fn non_contributory_public_keys_are_rejected_before_recipient_trust() {
        for public_key in [[0u8; 32], {
            let mut key = [0u8; 32];
            key[0] = 1;
            key
        }] {
            let member = member("low-order", public_key, 1);

            let error = prepare_recipients(&[&member])
                .expect_err("low-order recipient keys must fail before trust persistence");

            assert!(error.contains("non-contributory"), "{error}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn recipient_set_symlink_is_rejected() {
        use std::os::unix::fs::symlink;

        let _guard = crate::sync::test_support::env_lock_guard();
        let temp = tempfile::tempdir().expect("create recipient trust home");
        let original_home = crate::test_env_lock::HomeEnvSnapshot::set(temp.path());
        let lpm_home = temp.path().join(".lpm");
        std::fs::create_dir_all(&lpm_home).expect("create .lpm directory");
        let attacker_file = temp.path().join("attacker-recipient-set.json");
        std::fs::write(&attacker_file, b"{}").expect("create symlink target");
        let scope =
            RecipientTrustScope::new("https://registry.example", TEST_ORGANIZATION_ID, "acme")
                .expect("valid test trust scope");
        symlink(
            &attacker_file,
            lpm_home.join(recipient_set_file_name(&scope)),
        )
        .expect("create recipient-set symlink");
        let member = member("user-a", [7u8; 32], 1);
        let recipients = prepare_recipients(&[&member]).expect("prepare recipients");

        let error = enforce_recipient_trust(
            "https://registry.example",
            TEST_ORGANIZATION_ID,
            "acme",
            &recipients,
            None,
        )
        .expect_err("recipient-set symlink must fail closed");

        original_home.restore();
        assert!(error.contains("failed to open trusted recipient set"));
    }
}
