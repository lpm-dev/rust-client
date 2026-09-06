//! Origin-authenticated Ed25519 verification for Vault API responses.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

pub const KEY_ID_HEADER: &str = "X-LPM-Response-Key-ID";
pub const SIGNATURE_HEADER: &str = "X-LPM-Response-Signature";

const SIGNATURE_VERSION: u8 = 4;
const SIGNATURE_DOMAIN: &[u8] = b"lpm-authenticated-response\0";
const CURRENT_KEY_ID: &str = "vault-2026-09-06";
const CURRENT_PUBLIC_KEY: [u8; 32] = [
    0x85, 0x86, 0x22, 0x5f, 0xd3, 0xa6, 0x3b, 0xf6, 0xd1, 0x95, 0x83, 0xee, 0x8f, 0xb1, 0xac, 0x8a,
    0x8b, 0xd8, 0x5a, 0x4c, 0xf5, 0x6f, 0xe4, 0x12, 0x00, 0x30, 0x5f, 0xcf, 0x46, 0x1b, 0x96, 0x2a,
];
const PREVIOUS_KEY_ID: &str = "vault-2026-09";
const PREVIOUS_PUBLIC_KEY: [u8; 32] = [
    0xbc, 0x44, 0xf7, 0x37, 0xb6, 0x25, 0x34, 0x24, 0x47, 0x46, 0x16, 0xd6, 0xab, 0x6e, 0x03, 0x12,
    0x77, 0x02, 0xd8, 0x06, 0x96, 0x4e, 0x96, 0x79, 0x11, 0x54, 0xf3, 0x21, 0x4f, 0x90, 0xc9, 0x1f,
];

#[cfg(any(test, debug_assertions, feature = "acceptance-test-hooks"))]
const TEST_KEY_ID: &str = "vault-test-rfc8032";
#[cfg(any(test, debug_assertions, feature = "acceptance-test-hooks"))]
const TEST_PUBLIC_KEY: [u8; 32] = [
    0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
    0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
];

#[derive(Debug, thiserror::Error)]
pub enum SignatureError {
    #[error("vault response is missing the {KEY_ID_HEADER} header")]
    MissingKeyId,
    #[error("vault response is missing the {SIGNATURE_HEADER} header")]
    MissingSignature,
    #[error("vault response signing key ID is unknown")]
    UnknownKeyId,
    #[error("vault response signature is not canonical base64url")]
    InvalidEncoding,
    #[error("vault response signature does not match its status and body")]
    Mismatch,
    #[error("vault response status cannot be signed")]
    InvalidStatus,
}

fn signature_frame(status: u16, key_id: &str, body: &[u8]) -> Result<Vec<u8>, SignatureError> {
    if !(100..=599).contains(&status) || key_id.len() > u8::MAX as usize {
        return Err(SignatureError::InvalidStatus);
    }
    let body_length = u64::try_from(body.len()).map_err(|_| SignatureError::InvalidStatus)?;
    let body_digest = Sha256::digest(body);
    let mut frame =
        Vec::with_capacity(SIGNATURE_DOMAIN.len() + 12 + key_id.len() + body_digest.len());
    frame.extend_from_slice(SIGNATURE_DOMAIN);
    frame.push(SIGNATURE_VERSION);
    frame.extend_from_slice(&status.to_be_bytes());
    frame.push(key_id.len() as u8);
    frame.extend_from_slice(key_id.as_bytes());
    frame.extend_from_slice(&body_length.to_be_bytes());
    frame.extend_from_slice(&body_digest);
    Ok(frame)
}

fn verify_response_with_trusted_key(
    status: u16,
    body: &[u8],
    key_id_header: Option<&str>,
    signature_header: Option<&str>,
    trusted_public_key: impl FnOnce(&str) -> Option<[u8; 32]>,
) -> Result<(), SignatureError> {
    let encoded_signature = signature_header.ok_or(SignatureError::MissingSignature)?;
    let key_id = key_id_header.ok_or(SignatureError::MissingKeyId)?;
    let public_key = trusted_public_key(key_id).ok_or(SignatureError::UnknownKeyId)?;
    if encoded_signature.len() != 86
        || !encoded_signature
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(SignatureError::InvalidEncoding);
    }
    let signature_bytes = URL_SAFE_NO_PAD
        .decode(encoded_signature)
        .map_err(|_| SignatureError::InvalidEncoding)?;
    if signature_bytes.len() != 64 || URL_SAFE_NO_PAD.encode(&signature_bytes) != encoded_signature
    {
        return Err(SignatureError::InvalidEncoding);
    }
    let signature =
        Signature::from_slice(&signature_bytes).map_err(|_| SignatureError::InvalidEncoding)?;
    let verifying_key =
        VerifyingKey::from_bytes(&public_key).map_err(|_| SignatureError::Mismatch)?;
    verifying_key
        .verify(&signature_frame(status, key_id, body)?, &signature)
        .map_err(|_| SignatureError::Mismatch)
}

pub fn verify_response(
    status: u16,
    body: &[u8],
    key_id_header: Option<&str>,
    signature_header: Option<&str>,
) -> Result<(), SignatureError> {
    verify_response_with_trusted_key(status, body, key_id_header, signature_header, |key_id| {
        match key_id {
            CURRENT_KEY_ID => Some(CURRENT_PUBLIC_KEY),
            PREVIOUS_KEY_ID => Some(PREVIOUS_PUBLIC_KEY),
            _ => None,
        }
    })
}

/// Whether a debug response can use the built-in localhost signing key.
#[cfg(debug_assertions)]
#[inline]
pub fn is_local_development_key(url: &reqwest::Url, key_id: Option<&str>) -> bool {
    key_id == Some(TEST_KEY_ID)
        && url.scheme() == "http"
        && matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"))
}

#[cfg(any(test, debug_assertions, feature = "acceptance-test-hooks"))]
pub fn verify_response_with_test_key(
    status: u16,
    body: &[u8],
    key_id_header: Option<&str>,
    signature_header: Option<&str>,
) -> Result<(), SignatureError> {
    verify_response_with_trusted_key(status, body, key_id_header, signature_header, |key_id| {
        (key_id == TEST_KEY_ID).then_some(TEST_PUBLIC_KEY)
    })
}

#[cfg(any(test, feature = "acceptance-test-hooks"))]
pub fn sign_response_for_test(status: u16, body: &[u8]) -> (String, String) {
    use ed25519_dalek::{Signer, SigningKey};

    const TEST_PRIVATE_KEY_SEED: [u8; 32] = [
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c,
        0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae,
        0x7f, 0x60,
    ];
    let signing_key = SigningKey::from_bytes(&TEST_PRIVATE_KEY_SEED);
    let frame = signature_frame(status, TEST_KEY_ID, body).expect("test status should be valid");
    let signature = signing_key.sign(&frame);
    (
        TEST_KEY_ID.to_owned(),
        URL_SAFE_NO_PAD.encode(signature.to_bytes()),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(debug_assertions)]
    #[test]
    fn development_signing_key_is_scoped_to_local_http_responses() {
        for address in [
            "http://localhost:3000",
            "http://127.0.0.1:3000",
            "http://[::1]:3000",
        ] {
            let url = reqwest::Url::parse(address).unwrap();
            assert!(is_local_development_key(&url, Some(TEST_KEY_ID)));
            assert!(!is_local_development_key(&url, Some(CURRENT_KEY_ID)));
        }
        for address in [
            "https://lpm.dev",
            "http://example.test",
            "https://localhost:3000",
        ] {
            let url = reqwest::Url::parse(address).unwrap();
            assert!(!is_local_development_key(&url, Some(TEST_KEY_ID)));
        }
    }

    const BODY: &[u8] = br#"{"vaultId":"v1","version":3}"#;
    const FIXTURE_SIGNATURE: &str =
        "ABiBKJ3ihBNVXfSmsCZEK_YdQa1Y2VQm8w3uU9apguJ3j4G1FhiHrLVjPQDLiqQUHJV_H6OIqrGWCpaRNAJ0CQ";

    #[test]
    fn production_response_signature_accepts_the_deployed_key_and_binds_status_body_and_key_id() {
        const KEY_ID: &str = "vault-2026-09-06";
        const SIGNATURE: &str = "qHV0sHXlvnDewhvNfLUGNR09T96GC2YqkYxhy8K6JGPEOh0KOZB94jmdLodFv3WZb62yDBcExziVXge_dpuGDA";
        let verified = verify_response(200, BODY, Some(KEY_ID), Some(SIGNATURE));
        assert!(verified.is_ok(), "{verified:?}");

        for (status, body, key_id) in [
            (404, BODY, KEY_ID),
            (200, b"changed".as_slice(), KEY_ID),
            (200, BODY, "vault-2026-09"),
        ] {
            let error = verify_response(status, body, Some(key_id), Some(SIGNATURE))
                .expect_err("a changed signed response must be rejected");
            assert!(matches!(error, SignatureError::Mismatch), "{error:?}");
        }
    }

    #[test]
    fn current_response_signature_matches_the_cross_language_fixture() {
        let verified =
            verify_response_with_test_key(200, BODY, Some(TEST_KEY_ID), Some(FIXTURE_SIGNATURE));

        assert!(verified.is_ok(), "{verified:?}");
    }

    #[test]
    fn production_trust_anchor_rejects_the_published_rfc_test_key() {
        const RFC_SIGNATURE_FOR_PRODUCTION_KEY_ID: &str = "-4Wt-YkQkGV8-nlni_U_m58rtZ-Bs_FhH-ZR7qPxPkuUAI4YKToV0rvn-qgwZscJ_ml3-1yp3YfhDvFYX1rwAQ";
        let error = verify_response(
            200,
            BODY,
            Some(PREVIOUS_KEY_ID),
            Some(RFC_SIGNATURE_FOR_PRODUCTION_KEY_ID),
        )
        .expect_err("the production trust anchor must not use a published test private key");

        assert!(matches!(error, SignatureError::Mismatch));
    }

    #[test]
    fn response_signature_binds_the_http_status() {
        let error =
            verify_response_with_test_key(404, BODY, Some(TEST_KEY_ID), Some(FIXTURE_SIGNATURE))
                .expect_err("changing only the HTTP status must invalidate the signature");

        assert!(matches!(error, SignatureError::Mismatch));
    }

    #[test]
    fn response_signature_rejects_unknown_key_ids() {
        let error = verify_response(200, BODY, Some("unknown"), Some(FIXTURE_SIGNATURE))
            .expect_err("unknown signing keys must fail closed");

        assert!(matches!(error, SignatureError::UnknownKeyId));
    }

    #[test]
    fn response_signature_rejects_noncanonical_encoding() {
        let padded = format!("{FIXTURE_SIGNATURE}=");
        let error = verify_response_with_test_key(200, BODY, Some(TEST_KEY_ID), Some(&padded))
            .expect_err("padded base64 must not be accepted by the current protocol");

        assert!(matches!(error, SignatureError::InvalidEncoding));
    }

    #[test]
    fn response_signature_is_byte_exact_on_the_body() {
        let mut changed_body = BODY.to_vec();
        changed_body.push(b' ');
        let error = verify_response_with_test_key(
            200,
            &changed_body,
            Some(TEST_KEY_ID),
            Some(FIXTURE_SIGNATURE),
        )
        .expect_err("changing the body bytes must invalidate the signature");

        assert!(matches!(error, SignatureError::Mismatch));
    }

    #[test]
    fn response_signature_frame_size_is_independent_of_body_size() {
        let small = signature_frame(200, TEST_KEY_ID, b"small").expect("valid signature frame");
        let large_body = vec![b'x'; 16 * 1024 * 1024];
        let large = signature_frame(200, TEST_KEY_ID, &large_body).expect("valid signature frame");

        assert_eq!(large.len(), small.len());
    }

    #[test]
    fn test_signer_matches_the_cross_language_fixture() {
        let (key_id, signature) = sign_response_for_test(200, BODY);

        assert_eq!(
            (key_id.as_str(), signature.as_str()),
            (TEST_KEY_ID, FIXTURE_SIGNATURE)
        );
    }
}
