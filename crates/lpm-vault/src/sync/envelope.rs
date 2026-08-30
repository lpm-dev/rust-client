use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::RngCore;
use sha2::{Digest, Sha256};

use crate::crypto;

pub(super) const REQUEST_NONCE_HEADER: &str = "X-LPM-Vault-Request-Nonce";

const ENVELOPE_VERSION: i32 = 2;
const REQUEST_NONCE_BYTES: usize = 32;
const PAYLOAD_DIGEST_DOMAIN: &[u8] = b"lpm-vault-payload\0";

#[derive(Clone, Copy)]
pub(super) enum SyncScope<'a> {
    Personal,
    Organization(&'a str),
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct AuthenticatedSyncResponse {
    pub(super) vault_id: Option<String>,
    pub(super) encrypted_blob: Option<String>,
    pub(super) wrapped_key: Option<String>,
    pub(super) version: Option<i32>,
    pub(super) crypto_version: Option<i32>,
    pub(super) envelope_version: Option<i32>,
    pub(super) scope: Option<String>,
    pub(super) organization_slug: Option<String>,
    pub(super) request_nonce: Option<String>,
    pub(super) payload_digest: Option<String>,
    pub(super) content_key_version: Option<i32>,
    pub(super) recipient_public_key_version: Option<i32>,
    pub(super) recipient_public_key_fingerprint: Option<String>,
    pub(super) status: Option<String>,
    pub(super) error: Option<String>,
    pub(super) code: Option<String>,
    pub(super) server_version: Option<i32>,
    pub(super) hint: Option<String>,
}

impl AuthenticatedSyncResponse {
    pub(super) fn validate(
        &self,
        expected_vault_id: &str,
        expected_scope: SyncScope<'_>,
        expected_request_nonce: &str,
    ) -> Result<(), String> {
        if self.envelope_version != Some(ENVELOPE_VERSION) {
            return Err("authenticated sync envelope version is missing or unsupported".into());
        }
        if self.vault_id.as_deref() != Some(expected_vault_id) {
            return Err("authenticated sync envelope is bound to a different vault".into());
        }
        if self.crypto_version != Some(crypto::CURRENT_CRYPTO_VERSION) {
            return Err("authenticated sync envelope has an unsupported crypto version".into());
        }
        if self.request_nonce.as_deref() != Some(expected_request_nonce) {
            return Err("authenticated sync envelope does not match the request nonce".into());
        }

        let version = self
            .version
            .ok_or("authenticated sync envelope omitted the vault version")?;
        if version <= 0 {
            return Err("authenticated sync envelope has a non-positive vault version".into());
        }
        if self.server_version != Some(version) {
            return Err("authenticated sync envelope has a mismatched server version".into());
        }

        match expected_scope {
            SyncScope::Personal => {
                if self.scope.as_deref() != Some("personal") || self.organization_slug.is_some() {
                    return Err(
                        "authenticated sync envelope has a mismatched personal scope".into(),
                    );
                }
            }
            SyncScope::Organization(expected_slug) => {
                if self.scope.as_deref() != Some("organization")
                    || self.organization_slug.as_deref() != Some(expected_slug)
                {
                    return Err(
                        "authenticated sync envelope has a mismatched organization scope".into(),
                    );
                }
            }
        }

        match (
            self.encrypted_blob.as_deref(),
            self.wrapped_key.as_deref(),
            self.payload_digest.as_deref(),
        ) {
            (None, None, None) => Ok(()),
            (Some(encrypted_blob), Some(wrapped_key), Some(payload_digest)) => {
                let expected_digest = vault_payload_digest(encrypted_blob, wrapped_key)?;
                if payload_digest == expected_digest {
                    Ok(())
                } else {
                    Err("authenticated sync envelope payload digest does not match".into())
                }
            }
            _ => Err("authenticated sync envelope has an incomplete payload binding".into()),
        }
    }
}

pub(super) fn generate_request_nonce() -> Result<String, String> {
    let mut bytes = [0u8; REQUEST_NONCE_BYTES];
    rand::thread_rng()
        .try_fill_bytes(&mut bytes)
        .map_err(|error| format!("failed to generate authenticated sync request nonce: {error}"))?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

pub(super) fn vault_payload_digest(
    encrypted_blob: &str,
    wrapped_key: &str,
) -> Result<String, String> {
    let mut hash = Sha256::new();
    hash.update(PAYLOAD_DIGEST_DOMAIN);
    append_length_prefixed(&mut hash, encrypted_blob)?;
    append_length_prefixed(&mut hash, wrapped_key)?;
    Ok(hex::encode(hash.finalize()))
}

fn append_length_prefixed(hash: &mut Sha256, value: &str) -> Result<(), String> {
    let bytes = value.as_bytes();
    let length = u32::try_from(bytes.len())
        .map_err(|_| "authenticated sync payload field exceeds the protocol limit".to_owned())?;
    hash.update(length.to_be_bytes());
    hash.update(bytes);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vault_payload_digest_matches_the_cross_language_fixture() {
        let digest = vault_payload_digest("ciphertext", "wrapped")
            .expect("cross-language digest fixture should fit the protocol");

        assert_eq!(
            digest,
            "129f6d5175b7c0875d84918c4cbf6a12a4843cea2167345b932568c94fb0dc8f"
        );
    }

    #[test]
    fn generate_request_nonce_returns_unpadded_base64url() {
        let nonce = generate_request_nonce().expect("OS randomness should be available");

        assert!(
            nonce.len() == 43
                && nonce
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        );
    }
}
