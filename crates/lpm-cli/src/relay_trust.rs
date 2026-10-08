//! Relay key authorization anchored to LPM's GitHub Actions signing identity.

use crate::sigstore_verify::{
    IdentityExpectations, VerifiedProvenance, VerifyOptions, extract_subject_digest_from_statement,
    verify_sigstore_bundle,
};
use lpm_common::LpmError;
use sha2::{Digest, Sha256};

const TRUST_URL: &str = "https://github.com/lpm-dev/rust-client/releases/download/relay-trust";
const WORKFLOW: &str = ".github/workflows/relay-trust.yml";
const MANIFEST_CAP: usize = 16 * 1024;
const BUNDLE_CAP: usize = 1024 * 1024;
const MAX_VALIDITY_SECS: i64 = 7 * 24 * 60 * 60;

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RelayTrustManifest {
    schema_version: u32,
    host: String,
    issued_at: i64,
    expires_at: i64,
    spki_sha256: Vec<String>,
}

pub(crate) fn pin_provider() -> lpm_tunnel::client::TunnelPinProvider {
    lpm_tunnel::client::TunnelPinProvider::new(|| Box::pin(fetch_approved_pins()))
}

fn trust_error(detail: impl std::fmt::Display) -> LpmError {
    LpmError::Tunnel(format!("relay key authorization failed: {detail}"))
}

async fn fetch_approved_pins() -> Result<Vec<String>, LpmError> {
    // This source is independent of the relay. No registry or tunnel bearer is sent.
    let client = lpm_http::client_builder()
        .https_only(true)
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(trust_error)?;
    let manifest = fetch_asset(&client, "relay-trust.json", MANIFEST_CAP).await?;
    let bundle = fetch_asset(&client, "relay-trust.json.sigstore", BUNDLE_CAP).await?;
    verify_approved_pins(&manifest, &bundle, chrono::Utc::now().timestamp())
}

async fn fetch_asset(
    client: &reqwest::Client,
    name: &str,
    cap: usize,
) -> Result<Vec<u8>, LpmError> {
    let response = client
        .get(format!("{TRUST_URL}/{name}"))
        .send()
        .await
        .map_err(trust_error)?
        .error_for_status()
        .map_err(trust_error)?;
    lpm_http::read_body_capped(response, cap)
        .await
        .map_err(trust_error)
}

fn verify_approved_pins(manifest: &[u8], bundle: &[u8], now: i64) -> Result<Vec<String>, LpmError> {
    if manifest.len() > MANIFEST_CAP || bundle.len() > BUNDLE_CAP {
        return Err(trust_error("the signed key list exceeds the size limit"));
    }
    let identity = IdentityExpectations {
        expected_issuer: Some("https://token.actions.githubusercontent.com".into()),
        expected_san_uri_prefix: Some("https://github.com/lpm-dev/rust-client/".into()),
        expected_workflow_path: Some(WORKFLOW.into()),
    };
    let verified =
        verify_sigstore_bundle(bundle, &identity, VerifyOptions::strict()).map_err(trust_error)?;
    validate_approved_pins(manifest, &verified, now)
}

fn validate_approved_pins(
    bytes: &[u8],
    verified: &VerifiedProvenance,
    now: i64,
) -> Result<Vec<String>, LpmError> {
    if verified.snapshot.workflow_ref.as_deref() != Some("refs/heads/main") {
        return Err(trust_error("the signing workflow did not run on main"));
    }
    let (subject, digest) =
        extract_subject_digest_from_statement(&verified.statement, "sha256", true)
            .map_err(trust_error)?;
    if subject != "relay-trust.json" || digest != hex::encode(Sha256::digest(bytes)) {
        return Err(trust_error(
            "the signature does not match the relay key list",
        ));
    }
    let manifest: RelayTrustManifest = serde_json::from_slice(bytes).map_err(trust_error)?;
    let signed_at = chrono::DateTime::<chrono::Utc>::from(verified.integrated_time).timestamp();
    // Short-lived authorization limits replay without trusting HTTP timestamps or unsigned metadata.
    if manifest.schema_version != 1 || manifest.host != lpm_tunnel::relay::DEFAULT_RELAY_HOST {
        return Err(trust_error(
            "the key list names an unsupported schema or relay",
        ));
    }
    if manifest.issued_at < 0
        || manifest.issued_at > now.saturating_add(300)
        || manifest.expires_at <= now
        || manifest.expires_at <= manifest.issued_at
        || manifest.expires_at.saturating_sub(manifest.issued_at) > MAX_VALIDITY_SECS
        || signed_at < manifest.issued_at.saturating_sub(300)
        || signed_at > manifest.issued_at.saturating_add(900)
        || signed_at > now.saturating_add(300)
    {
        return Err(trust_error(
            "the signed key list is expired or has an invalid validity window",
        ));
    }
    if manifest.spki_sha256.is_empty()
        || manifest.spki_sha256.len() > 16
        || manifest.spki_sha256.iter().any(|pin| {
            pin.len() != 64
                || !pin
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
    {
        return Err(trust_error(
            "the key list contains an invalid public-key fingerprint",
        ));
    }
    Ok(manifest.spki_sha256)
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_791_504_000;

    fn manifest() -> serde_json::Value {
        serde_json::json!({
            "schema_version": 1,
            "host": "relay.lpm.fyi",
            "issued_at": NOW,
            "expires_at": NOW + MAX_VALIDITY_SECS,
            "spki_sha256": ["a".repeat(64), "b".repeat(64)]
        })
    }

    // These cases exercise policy after cryptographic verification. The verifier has its own signature corpus.
    fn authenticated(bytes: &[u8]) -> VerifiedProvenance {
        VerifiedProvenance {
            snapshot: lpm_workspace::ProvenanceSnapshot {
                workflow_ref: Some("refs/heads/main".into()),
                ..Default::default()
            },
            statement: serde_json::json!({"subject": [{"name": "relay-trust.json",
                "digest": {"sha256": hex::encode(Sha256::digest(bytes))}}]}),
            integrated_time: std::time::UNIX_EPOCH + std::time::Duration::from_secs(NOW as u64),
            leaf_cert_sha256: String::new(),
            log_id: String::new(),
            log_index: 0,
        }
    }

    #[test]
    fn signed_key_list_accepts_overlapping_approved_keys() {
        let bytes = serde_json::to_vec(&manifest()).unwrap();
        assert_eq!(
            validate_approved_pins(&bytes, &authenticated(&bytes), NOW).unwrap(),
            vec!["a".repeat(64), "b".repeat(64)]
        );
    }

    #[test]
    fn signed_key_list_rejects_invalid_host_time_schema_and_fingerprints() {
        for (field, value) in [
            ("host", serde_json::json!("attacker.example")),
            ("schema_version", serde_json::json!(2)),
            ("issued_at", serde_json::json!(NOW + 301)),
            ("expires_at", serde_json::json!(NOW)),
            ("expires_at", serde_json::json!(NOW + MAX_VALIDITY_SECS + 1)),
            ("spki_sha256", serde_json::json!([])),
            ("spki_sha256", serde_json::json!(["invalid"])),
            ("spki_sha256", serde_json::json!(["A".repeat(64)])),
        ] {
            let mut value_manifest = manifest();
            value_manifest[field] = value;
            let bytes = serde_json::to_vec(&value_manifest).unwrap();
            assert!(
                validate_approved_pins(&bytes, &authenticated(&bytes), NOW).is_err(),
                "field={field}"
            );
        }
    }

    #[test]
    fn signed_key_list_rejects_tampered_bytes_and_branch_signatures() {
        let bytes = serde_json::to_vec(&manifest()).unwrap();
        let mut verified = authenticated(&bytes);
        assert!(validate_approved_pins(b"{}", &verified, NOW).is_err());
        verified.snapshot.workflow_ref = Some("refs/heads/feature".into());
        assert!(validate_approved_pins(&bytes, &verified, NOW).is_err());
    }

    #[test]
    fn signed_key_list_rejects_forged_and_unrelated_bundles() {
        let bytes = serde_json::to_vec(&manifest()).unwrap();
        assert!(verify_approved_pins(&bytes, b"{}", NOW).is_err());
        let fixture =
            include_bytes!("../tests/fixtures/sigstore_bundles/20-real-npm-axios-1.14.0.json");
        assert!(verify_approved_pins(&bytes, fixture, NOW).is_err());
    }

    #[test]
    fn signed_key_list_rejects_wrong_subject_and_unbound_signing_times() {
        let bytes = serde_json::to_vec(&manifest()).unwrap();
        let mut verified = authenticated(&bytes);
        verified.statement["subject"][0]["name"] = serde_json::json!("another.json");
        assert!(validate_approved_pins(&bytes, &verified, NOW).is_err());
        for signed_at in [NOW - 301, NOW + 301, NOW + 901] {
            let mut verified = authenticated(&bytes);
            verified.integrated_time =
                std::time::UNIX_EPOCH + std::time::Duration::from_secs(signed_at as u64);
            assert!(validate_approved_pins(&bytes, &verified, NOW).is_err());
        }
    }

    #[test]
    fn signed_key_list_rejects_oversized_inputs_and_excess_keys() {
        let bytes = serde_json::to_vec(&manifest()).unwrap();
        assert!(verify_approved_pins(&vec![0; MANIFEST_CAP + 1], b"{}", NOW).is_err());
        assert!(verify_approved_pins(&bytes, &vec![0; BUNDLE_CAP + 1], NOW).is_err());
        let mut manifest = manifest();
        manifest["spki_sha256"] =
            serde_json::json!((0..17).map(|pin| format!("{pin:064x}")).collect::<Vec<_>>());
        let bytes = serde_json::to_vec(&manifest).unwrap();
        assert!(validate_approved_pins(&bytes, &authenticated(&bytes), NOW).is_err());
    }
}
