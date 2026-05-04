//! HMAC-SHA256 verification for vault sync responses.
//!
//! The server signs successful vault sync responses with HMAC-SHA256, using
//! `SHA-256(auth_token)` as the key, and ships the base64-encoded signature
//! in the `X-LPM-Signature` header. The CLI verifies the signature before
//! parsing the body — so a tampered or replayed response never reaches the
//! decryption path.
//!
//! ## Why HMAC, not a public/private key
//!
//! The auth token is a per-user shared secret already known to both sides,
//! so deriving a per-token HMAC key avoids any global server signing key
//! and the rotation story that goes with it. Rotation is automatic — when
//! a user rotates their auth token, both sides immediately switch to the
//! new key. There is no "public key in CLI binary" to keep in sync.
//!
//! ## What the AEAD already covers
//!
//! The encrypted blob is authenticated by AES-GCM, so confidentiality and
//! blob-integrity are not affected by a missing/invalid signature. The
//! HMAC adds tamper detection over the *response envelope*: `version`,
//! `wrappedKey`, `vaultId`, `status`, and metadata. A TLS-terminating
//! intermediary or a compromised CDN cache cannot forge a successful
//! response without the auth token.
//!
//! ## Server side
//!
//! See `a-package-manager/lib/vault/response-signature.js`.

use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

/// HTTP header carrying the response signature.
pub const SIGNATURE_HEADER: &str = "X-LPM-Signature";

/// Reasons signature verification can fail.
#[derive(Debug, thiserror::Error)]
pub enum SignatureError {
    /// Successful response from a signed endpoint did not include the
    /// signature header. Either the server is older than the CLI, or
    /// the response was stripped/replaced in transit.
    #[error(
        "vault response is missing the {SIGNATURE_HEADER} header — \
         cannot verify integrity. Update the LPM server (or your CLI) \
         so both sides agree on response signing."
    )]
    Missing,
    /// Signature header is present but not valid base64.
    #[error("vault response signature is not valid base64: {0}")]
    InvalidEncoding(String),
    /// Signature does not match the response body.
    ///
    /// Caller should treat this as tampering — never fall back to the
    /// unsigned body, never retry against the same response.
    #[error(
        "vault response signature does not match the body — \
         possible tampering or token mismatch"
    )]
    Mismatch,
}

/// Compute the canonical signature for `body` using `auth_token`.
///
/// Mirrors `signVaultResponse` in `lib/vault/response-signature.js`:
/// `HMAC-SHA256(body, SHA-256(auth_token))`.
fn compute_mac(body: &[u8], auth_token: &str) -> Hmac<Sha256> {
    let key = Sha256::digest(auth_token.as_bytes());
    let mut mac =
        <Hmac<Sha256>>::new_from_slice(&key).expect("HMAC-SHA256 accepts a key of any length");
    mac.update(body);
    mac
}

/// Verify the `X-LPM-Signature` header against `body`.
///
/// Uses `Mac::verify_slice`, which performs a constant-time comparison —
/// no timing oracle on the byte differential.
pub fn verify_response_body(
    body: &[u8],
    auth_token: &str,
    signature_header: Option<&str>,
) -> Result<(), SignatureError> {
    let header = signature_header.ok_or(SignatureError::Missing)?;
    let received = BASE64
        .decode(header.trim())
        .map_err(|e| SignatureError::InvalidEncoding(e.to_string()))?;
    compute_mac(body, auth_token)
        .verify_slice(&received)
        .map_err(|_| SignatureError::Mismatch)
}

/// Compute the canonical signature as a base64 string. Used by tests
/// and any future call site that needs to mint a signature locally.
pub fn sign_body(body: &[u8], auth_token: &str) -> String {
    let bytes = compute_mac(body, auth_token).finalize().into_bytes();
    BASE64.encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TOKEN: &str = "lpm_test_token_abc123";
    const BODY: &str = r#"{"vaultId":"v1","version":3}"#;

    #[test]
    fn sign_body_matches_node_reference_value() {
        // Reference value computed via the JS implementation:
        //   const k = createHash("sha256").update(TOKEN).digest()
        //   createHmac("sha256", k).update(BODY).digest("base64")
        // Hard-coded so a refactor that breaks parity with the server
        // fails this test even without the server running.
        let sig = sign_body(BODY.as_bytes(), TOKEN);
        assert_eq!(sig.len(), 44, "base64 of HMAC-SHA-256 is 44 chars");
        let expected = "ldVu3vojQWNaIcbhLIy3iRC13cArq7tBYVMlUvvq/ko=";
        assert_eq!(
            sig, expected,
            "HMAC must match the JS server's signVaultResponse output"
        );
    }

    #[test]
    fn sign_body_is_deterministic() {
        let a = sign_body(BODY.as_bytes(), TOKEN);
        let b = sign_body(BODY.as_bytes(), TOKEN);
        assert_eq!(a, b);
    }

    #[test]
    fn sign_body_changes_with_body() {
        let a = sign_body(b"{\"a\":1}", TOKEN);
        let b = sign_body(b"{\"a\":2}", TOKEN);
        assert_ne!(a, b);
    }

    #[test]
    fn sign_body_changes_with_token() {
        let a = sign_body(BODY.as_bytes(), "token-a");
        let b = sign_body(BODY.as_bytes(), "token-b");
        assert_ne!(a, b);
    }

    #[test]
    fn verify_accepts_valid_signature() {
        let sig = sign_body(BODY.as_bytes(), TOKEN);
        assert!(verify_response_body(BODY.as_bytes(), TOKEN, Some(&sig)).is_ok());
    }

    #[test]
    fn verify_rejects_missing_header() {
        let err = verify_response_body(BODY.as_bytes(), TOKEN, None).unwrap_err();
        assert!(matches!(err, SignatureError::Missing));
    }

    #[test]
    fn verify_rejects_tampered_body() {
        let sig = sign_body(BODY.as_bytes(), TOKEN);
        let tampered = br#"{"vaultId":"v1","version":4}"#;
        let err = verify_response_body(tampered, TOKEN, Some(&sig)).unwrap_err();
        assert!(matches!(err, SignatureError::Mismatch));
    }

    #[test]
    fn verify_rejects_signature_minted_by_different_token() {
        let sig_other = sign_body(BODY.as_bytes(), "different-token");
        let err = verify_response_body(BODY.as_bytes(), TOKEN, Some(&sig_other)).unwrap_err();
        assert!(matches!(err, SignatureError::Mismatch));
    }

    #[test]
    fn verify_rejects_invalid_base64() {
        let err = verify_response_body(BODY.as_bytes(), TOKEN, Some("not base 64!@#")).unwrap_err();
        assert!(matches!(err, SignatureError::InvalidEncoding(_)));
    }

    #[test]
    fn verify_tolerates_surrounding_whitespace_in_header() {
        let sig = sign_body(BODY.as_bytes(), TOKEN);
        let padded = format!("  {sig}  ");
        assert!(verify_response_body(BODY.as_bytes(), TOKEN, Some(&padded)).is_ok());
    }

    #[test]
    fn verify_rejects_truncated_signature() {
        let sig = sign_body(BODY.as_bytes(), TOKEN);
        let truncated = &sig[..sig.len() - 4];
        let err = verify_response_body(BODY.as_bytes(), TOKEN, Some(truncated)).unwrap_err();
        // Decodable base64 of the wrong length, but Mac::verify_slice
        // rejects the wrong-length tag. Accept either Mismatch or
        // InvalidEncoding here so we don't pin internal behavior.
        assert!(matches!(
            err,
            SignatureError::Mismatch | SignatureError::InvalidEncoding(_)
        ));
    }

    #[test]
    fn verify_is_byte_exact_on_body() {
        // A trailing whitespace byte must invalidate the signature —
        // proves we're verifying over the exact bytes the server
        // signed, not a "normalized" form.
        let sig = sign_body(BODY.as_bytes(), TOKEN);
        let mut padded = BODY.as_bytes().to_vec();
        padded.push(b' ');
        let err = verify_response_body(&padded, TOKEN, Some(&sig)).unwrap_err();
        assert!(matches!(err, SignatureError::Mismatch));
    }
}
