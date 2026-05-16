//! Sigstore client: Fulcio certificate exchange + Rekor transparency log.
//!
//! Implements the Sigstore signing protocol directly using standard crypto
//! libraries (p256/ecdsa) and HTTP (reqwest). This avoids pulling in the
//! heavy `sigstore` monolith crate while giving full control over the flow.
//!
//! Protocol:
//! 1. Generate ephemeral ECDSA P-256 keypair
//! 2. Exchange OIDC token + public key with Fulcio → signing certificate
//! 3. Sign SLSA statement → DSSE envelope
//! 4. Upload to Rekor transparency log → inclusion proof
//! 5. Bundle = DSSE envelope + cert chain + Rekor entry

use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use ecdsa::signature::Signer;
use lpm_common::LpmError;
use p256::ecdsa::{SigningKey, VerifyingKey};
use p256::pkcs8::EncodePublicKey;

/// Fulcio public instance (v2 API).
const FULCIO_URL: &str = "https://fulcio.sigstore.dev";

/// Rekor public instance.
const REKOR_URL: &str = "https://rekor.sigstore.dev";

/// Sigstore service endpoints. Injected into the signing flow so tests
/// can substitute wiremock servers without overriding global constants.
pub struct SigstoreEndpoints {
    pub fulcio: String,
    pub rekor: String,
}

impl SigstoreEndpoints {
    pub fn production() -> Self {
        Self {
            fulcio: FULCIO_URL.to_string(),
            rekor: REKOR_URL.to_string(),
        }
    }
}

/// A complete Sigstore bundle ready to attach to a publish payload.
#[derive(Debug, Clone, serde::Serialize)]
pub struct SigstoreBundle {
    /// The DSSE envelope (signed statement).
    #[serde(rename = "dsseEnvelope")]
    pub dsse_envelope: DsseEnvelope,

    /// Verification material (certificate chain + Rekor log entry).
    #[serde(rename = "verificationMaterial")]
    pub verification_material: VerificationMaterial,
}

/// Dead Simple Signing Envelope (DSSE).
#[derive(Debug, Clone, serde::Serialize)]
pub struct DsseEnvelope {
    /// Payload type URI.
    #[serde(rename = "payloadType")]
    pub payload_type: String,

    /// Base64-encoded payload (the SLSA statement).
    pub payload: String,

    /// Signatures over the PAE-encoded payload.
    pub signatures: Vec<DsseSignature>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct DsseSignature {
    /// Key ID (empty for Sigstore — identity is in the certificate).
    pub keyid: String,

    /// Base64-encoded signature.
    pub sig: String,
}

/// Verification material for a Sigstore bundle.
#[derive(Debug, Clone, serde::Serialize)]
pub struct VerificationMaterial {
    /// X.509 certificate chain from Fulcio.
    #[serde(rename = "x509CertificateChain")]
    pub x509_certificate_chain: CertificateChain,

    /// Rekor transparency log entry.
    #[serde(rename = "tlogEntries")]
    pub tlog_entries: Vec<TlogEntry>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct CertificateChain {
    pub certificates: Vec<Certificate>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct Certificate {
    /// Base64-encoded DER certificate.
    #[serde(rename = "rawBytes")]
    pub raw_bytes: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct TlogEntry {
    /// Log index in the transparency log.
    #[serde(rename = "logIndex")]
    pub log_index: String,

    /// Log ID (Rekor instance identifier).
    #[serde(rename = "logId")]
    pub log_id: LogId,

    /// RFC 3339 timestamp of inclusion.
    #[serde(rename = "integratedTime")]
    pub integrated_time: String,

    /// Inclusion proof (if available).
    #[serde(rename = "inclusionProof", skip_serializing_if = "Option::is_none")]
    pub inclusion_proof: Option<serde_json::Value>,

    /// The canonicalized entry body.
    #[serde(rename = "canonicalizedBody")]
    pub canonicalized_body: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct LogId {
    /// Hex-encoded key ID of the Rekor log.
    #[serde(rename = "keyId")]
    pub key_id: String,
}

/// Generate a DSSE Pre-Authentication Encoding.
///
/// PAE(type, payload) = "DSSEv1" + SP + len(type) + SP + type + SP + len(payload) + SP + payload
fn pae(payload_type: &str, payload: &[u8]) -> Vec<u8> {
    let mut pae = Vec::new();
    pae.extend_from_slice(b"DSSEv1 ");
    pae.extend_from_slice(payload_type.len().to_string().as_bytes());
    pae.push(b' ');
    pae.extend_from_slice(payload_type.as_bytes());
    pae.push(b' ');
    pae.extend_from_slice(payload.len().to_string().as_bytes());
    pae.push(b' ');
    pae.extend_from_slice(payload);
    pae
}

/// Run the complete Sigstore signing flow against the public Fulcio /
/// Rekor instances. Thin shim around [`sign_and_record_with_endpoints`].
pub async fn sign_and_record(
    oidc_token: &str,
    slsa_statement_json: &[u8],
) -> Result<SigstoreBundle, LpmError> {
    sign_and_record_with_endpoints(
        oidc_token,
        slsa_statement_json,
        &SigstoreEndpoints::production(),
    )
    .await
}

/// Run the complete Sigstore signing flow against caller-supplied endpoints.
///
/// 1. Generate ephemeral keypair
/// 2. Exchange OIDC token with Fulcio for a signing certificate
/// 3. Sign the SLSA statement as a DSSE envelope
/// 4. Upload to Rekor transparency log
/// 5. Return the complete Sigstore bundle
pub async fn sign_and_record_with_endpoints(
    oidc_token: &str,
    slsa_statement_json: &[u8],
    endpoints: &SigstoreEndpoints,
) -> Result<SigstoreBundle, LpmError> {
    // Step 1: Generate ephemeral ECDSA P-256 keypair
    let signing_key = SigningKey::random(&mut rand::thread_rng());
    let verifying_key = VerifyingKey::from(&signing_key);

    // Encode public key as PEM (SPKI format) for Fulcio v2
    let public_key_pem = verifying_key
        .to_public_key_pem(p256::pkcs8::LineEnding::LF)
        .map_err(|e| LpmError::Registry(format!("failed to encode public key: {e}")))?;

    // Step 2: Extract subject from OIDC JWT and sign it as proof-of-possession
    // Fulcio verifies that we control the private key by checking this signature
    // against the subject ("sub") claim from the OIDC token
    let subject = extract_jwt_subject(oidc_token)?;
    let proof_signature: p256::ecdsa::Signature = signing_key.sign(subject.as_bytes());
    let proof_b64 = BASE64.encode(proof_signature.to_der().as_bytes());

    // Step 3: Exchange OIDC token for Fulcio signing certificate (v2 API)
    let (cert_pem, cert_chain_der) =
        fulcio_get_certificate(&endpoints.fulcio, oidc_token, &public_key_pem, &proof_b64).await?;

    // Step 4: Create DSSE envelope
    let payload_type = "application/vnd.in-toto+json";
    let payload_b64 = BASE64.encode(slsa_statement_json);

    // Sign the PAE-encoded payload with ECDSA P-256.
    // The signature is encoded as raw R||S bytes (64 bytes for P-256), NOT DER.
    // Rekor accepts both raw and DER; raw is simpler and matches npm's format.
    let pae_bytes = pae(payload_type, slsa_statement_json);
    let signature: p256::ecdsa::Signature = signing_key.sign(&pae_bytes);
    let signature_b64 = BASE64.encode(signature.to_bytes().as_slice());

    let dsse_envelope = DsseEnvelope {
        payload_type: payload_type.into(),
        payload: payload_b64,
        signatures: vec![DsseSignature {
            keyid: String::new(),
            sig: signature_b64,
        }],
    };

    // Step 4: Upload to Rekor
    let tlog_entry = rekor_upload(&endpoints.rekor, &dsse_envelope, &cert_pem).await?;

    // Step 5: Build the bundle
    let verification_material = VerificationMaterial {
        x509_certificate_chain: CertificateChain {
            certificates: cert_chain_der
                .iter()
                .map(|der| Certificate {
                    raw_bytes: BASE64.encode(der),
                })
                .collect(),
        },
        tlog_entries: vec![tlog_entry],
    };

    Ok(SigstoreBundle {
        dsse_envelope,
        verification_material,
    })
}

/// Exchange an OIDC token and public key with Fulcio for a signing certificate.
///
/// Uses Fulcio v2 API: POST /api/v2/signingCert
/// - OIDC token in request body (credentials.oidcIdentityToken)
/// - PEM public key + proof-of-possession signature
/// - Returns JSON with certificate chain
async fn fulcio_get_certificate(
    fulcio_url: &str,
    oidc_token: &str,
    public_key_pem: &str,
    proof_b64: &str,
) -> Result<(String, Vec<Vec<u8>>), LpmError> {
    let client = reqwest::Client::new();

    let body = serde_json::json!({
        "credentials": {
            "oidcIdentityToken": oidc_token,
        },
        "publicKeyRequest": {
            "publicKey": {
                "algorithm": "EC",
                "content": public_key_pem,
            },
            "proofOfPossession": proof_b64,
        },
    });

    let response = client
        .post(format!("{fulcio_url}/api/v2/signingCert"))
        .header("Content-Type", "application/json")
        .json(&body)
        .send()
        .await
        .map_err(|e| LpmError::Registry(format!("Fulcio request failed: {e}")))?;

    if !response.status().is_success() {
        let status = response.status();
        let text = response.text().await.unwrap_or_default();
        return Err(LpmError::Registry(format!(
            "Fulcio certificate exchange failed ({status}): {text}"
        )));
    }

    // Fulcio v1 with Accept: application/pem-certificate-chain returns
    // a raw PEM chain (multiple certs concatenated). If it returns JSON
    // instead, fall back to parsing the JSON response.
    let content_type = response
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    let response_text = response
        .text()
        .await
        .map_err(|e| LpmError::Registry(format!("Fulcio response read error: {e}")))?;

    tracing::debug!("Fulcio response content-type: {content_type}");
    tracing::debug!(
        "Fulcio response body (first 500 chars): {}",
        &response_text[..response_text.len().min(500)]
    );

    // Parse response — v2 returns JSON with PEM certs inside, v1 returns raw PEM.
    // Check content-type ONLY (not body text) to choose the parser, because v2 JSON
    // contains PEM strings that would falsely match "BEGIN CERTIFICATE".
    let (cert_pem, cert_chain_der) =
        if content_type.contains("pem") && !content_type.contains("json") {
            // PEM chain format — split into individual certificates
            let mut certs_pem = Vec::new();
            let mut current = String::new();
            let mut in_cert = false;

            for line in response_text.lines() {
                if line.contains("BEGIN CERTIFICATE") {
                    in_cert = true;
                    current.clear();
                    current.push_str(line);
                    current.push('\n');
                } else if line.contains("END CERTIFICATE") {
                    current.push_str(line);
                    current.push('\n');
                    certs_pem.push(current.clone());
                    in_cert = false;
                } else if in_cert {
                    current.push_str(line);
                    current.push('\n');
                }
            }

            if certs_pem.is_empty() {
                return Err(LpmError::Registry(
                    "Fulcio returned empty certificate chain".into(),
                ));
            }

            let first_pem = certs_pem[0].clone();
            let ders: Result<Vec<Vec<u8>>, _> = certs_pem.iter().map(|p| pem_to_der(p)).collect();
            (first_pem, ders?)
        } else {
            // JSON response — parse certificate chain
            let result: serde_json::Value = serde_json::from_str(&response_text)
                .map_err(|e| LpmError::Registry(format!("Fulcio response parse error: {e}")))?;

            let chain = result
                .get("signedCertificateEmbeddedSct")
                .or_else(|| result.get("signedCertificateDetachedSct"))
                .and_then(|v| v.get("chain"))
                .and_then(|v| v.get("certificates"))
                .and_then(|v| v.as_array())
                .ok_or_else(|| {
                    LpmError::Registry(format!(
                        "Fulcio response missing certificate chain: {response_text}"
                    ))
                })?;

            let mut cert_pem = String::new();
            let mut cert_chain_der = Vec::new();

            for cert_val in chain {
                if let Some(cert_str) = cert_val.as_str() {
                    if cert_pem.is_empty() {
                        cert_pem = cert_str.to_string();
                    }
                    let der = pem_to_der(cert_str)?;
                    cert_chain_der.push(der);
                }
            }

            if cert_pem.is_empty() {
                return Err(LpmError::Registry(
                    "Fulcio returned empty certificate chain".into(),
                ));
            }

            (cert_pem, cert_chain_der)
        };

    Ok((cert_pem, cert_chain_der))
}

/// Upload a signed DSSE envelope to Rekor transparency log.
///
/// POST https://rekor.sigstore.dev/api/v1/log/entries
async fn rekor_upload(
    rekor_url: &str,
    envelope: &DsseEnvelope,
    cert_pem: &str,
) -> Result<TlogEntry, LpmError> {
    let client = reqwest::Client::new();

    use sha2::{Digest, Sha256};

    // Rekor intoto v0.0.2: envelope as JSON object with double-encoded payload/sig.
    let cert_b64 = BASE64.encode(cert_pem.as_bytes());
    let payload_double_b64 = BASE64.encode(envelope.payload.as_bytes());

    // Build signature entry — omit keyid if empty (Rekor strips it)
    let sig = &envelope.signatures[0];
    let sig_double_b64 = BASE64.encode(sig.sig.as_bytes());
    let mut sig_entry = serde_json::json!({
        "sig": &sig_double_b64,
        "publicKey": &cert_b64,
    });
    if !sig.keyid.is_empty() {
        sig_entry["keyid"] = serde_json::json!(&sig.keyid);
    }

    let rekor_envelope = serde_json::json!({
        "payloadType": &envelope.payload_type,
        "payload": &payload_double_b64,
        "signatures": [sig_entry],
    });

    // Compute required hashes
    // payloadHash: SHA-256 of the raw payload (before base64 encoding)
    let raw_payload = BASE64
        .decode(envelope.payload.as_bytes())
        .unwrap_or_default();
    let payload_hash = format!("{:x}", Sha256::digest(&raw_payload));

    // hash: SHA-256 of the canonicalized envelope (with publicKey included)
    let envelope_hash = {
        let canonical = serde_json::to_string(&rekor_envelope).unwrap_or_default();
        format!("{:x}", Sha256::digest(canonical.as_bytes()))
    };

    let body = serde_json::json!({
        "apiVersion": "0.0.2",
        "kind": "intoto",
        "spec": {
            "content": {
                "envelope": rekor_envelope,
                "hash": {
                    "algorithm": "sha256",
                    "value": envelope_hash,
                },
                "payloadHash": {
                    "algorithm": "sha256",
                    "value": payload_hash,
                },
            },
        },
    });

    let response = client
        .post(format!("{rekor_url}/api/v1/log/entries"))
        .header("Content-Type", "application/json")
        .json(&body)
        .send()
        .await
        .map_err(|e| LpmError::Registry(format!("Rekor upload failed: {e}")))?;

    if !response.status().is_success() {
        let status = response.status();
        let text = response.text().await.unwrap_or_default();
        return Err(LpmError::Registry(format!(
            "Rekor transparency log upload failed ({status}): {text}"
        )));
    }

    let result: serde_json::Value = response
        .json()
        .await
        .map_err(|e| LpmError::Registry(format!("Rekor response parse error: {e}")))?;

    // Rekor returns { "uuid": { ...entry } } — one entry
    let (_uuid, entry) = result
        .as_object()
        .and_then(|obj| obj.iter().next())
        .ok_or_else(|| LpmError::Registry("Rekor response empty".into()))?;

    let log_index = entry
        .get("logIndex")
        .and_then(|v| v.as_i64())
        .unwrap_or(0)
        .to_string();

    let integrated_time = entry
        .get("integratedTime")
        .and_then(|v| v.as_i64())
        .unwrap_or(0)
        .to_string();

    let log_id = entry
        .get("logID")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let body_b64 = entry
        .get("body")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let inclusion_proof = entry.get("verification").cloned();

    Ok(TlogEntry {
        log_index,
        log_id: LogId { key_id: log_id },
        integrated_time,
        inclusion_proof,
        canonicalized_body: body_b64,
    })
}

/// Extract the "sub" (subject) claim from a JWT without verifying the signature.
///
/// The subject is used as the proof-of-possession challenge for Fulcio —
/// we sign it with the ephemeral key to prove we control the private key.
fn extract_jwt_subject(jwt: &str) -> Result<String, LpmError> {
    let parts: Vec<&str> = jwt.split('.').collect();
    if parts.len() != 3 {
        return Err(LpmError::Registry("invalid JWT format".into()));
    }

    // Decode the payload (second part) — JWT uses base64url encoding
    let payload_b64 = parts[1];
    // Pad to multiple of 4 for standard base64
    let padded = match payload_b64.len() % 4 {
        2 => format!("{payload_b64}=="),
        3 => format!("{payload_b64}="),
        _ => payload_b64.to_string(),
    };
    // JWT uses base64url (- instead of +, _ instead of /)
    let standard_b64 = padded.replace('-', "+").replace('_', "/");

    let payload_bytes = BASE64
        .decode(standard_b64.as_bytes())
        .map_err(|e| LpmError::Registry(format!("failed to decode JWT payload: {e}")))?;

    let payload: serde_json::Value = serde_json::from_slice(&payload_bytes)
        .map_err(|e| LpmError::Registry(format!("failed to parse JWT payload: {e}")))?;

    payload
        .get("sub")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| LpmError::Registry("JWT missing 'sub' claim".into()))
}

/// Decode a PEM-encoded certificate to DER bytes.
fn pem_to_der(pem: &str) -> Result<Vec<u8>, LpmError> {
    let content: String = pem
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect();

    BASE64
        .decode(content.as_bytes())
        .map_err(|e| LpmError::Registry(format!("invalid PEM certificate: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pae_encoding() {
        let result = pae("application/vnd.in-toto+json", b"{}");
        let expected = b"DSSEv1 28 application/vnd.in-toto+json 2 {}";
        assert_eq!(result, expected);
    }

    #[test]
    fn pem_to_der_basic() {
        let pem = "-----BEGIN CERTIFICATE-----\nYWJj\n-----END CERTIFICATE-----";
        let der = pem_to_der(pem).unwrap();
        assert_eq!(der, b"abc");
    }

    #[test]
    fn dsse_envelope_serializes() {
        let envelope = DsseEnvelope {
            payload_type: "application/vnd.in-toto+json".into(),
            payload: "eyJ0ZXN0IjogdHJ1ZX0=".into(),
            signatures: vec![DsseSignature {
                keyid: String::new(),
                sig: "c2lnbmF0dXJl".into(),
            }],
        };

        let json = serde_json::to_value(&envelope).unwrap();
        assert_eq!(json["payloadType"], "application/vnd.in-toto+json");
        assert_eq!(json["signatures"][0]["sig"], "c2lnbmF0dXJl");
    }

    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use wiremock::matchers::{method, path as match_path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    // ─── Fixture helpers ──────────────────────────────────────────

    const PEM_CERT_LEAF: &str = "-----BEGIN CERTIFICATE-----\nYWJj\n-----END CERTIFICATE-----\n";
    const PEM_CERT_INTERMEDIATE: &str =
        "-----BEGIN CERTIFICATE-----\nZGVm\n-----END CERTIFICATE-----\n";
    const PEM_CERT_ROOT: &str = "-----BEGIN CERTIFICATE-----\nZ2hp\n-----END CERTIFICATE-----\n";

    fn make_jwt(payload_json: &str) -> String {
        let header_b64 = URL_SAFE_NO_PAD.encode(br#"{"alg":"RS256","typ":"JWT"}"#);
        let payload_b64 = URL_SAFE_NO_PAD.encode(payload_json.as_bytes());
        let sig_b64 = URL_SAFE_NO_PAD.encode(b"fake-sig-not-verified");
        format!("{header_b64}.{payload_b64}.{sig_b64}")
    }

    fn dsse_fixture() -> DsseEnvelope {
        DsseEnvelope {
            payload_type: "application/vnd.in-toto+json".into(),
            payload: BASE64.encode(b"{}"),
            signatures: vec![DsseSignature {
                keyid: String::new(),
                sig: BASE64.encode(b"sig-bytes"),
            }],
        }
    }

    // ─── Fulcio response parsing ──────────────────────────────────

    #[tokio::test]
    async fn fulcio_parses_pem_chain_single_cert() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(match_path("/api/v2/signingCert"))
            .respond_with(ResponseTemplate::new(200).set_body_raw(
                PEM_CERT_LEAF.as_bytes().to_vec(),
                "application/pem-certificate-chain",
            ))
            .expect(1)
            .mount(&server)
            .await;

        let (pem, ders) = fulcio_get_certificate(&server.uri(), "tok", "key-pem", "proof")
            .await
            .expect("expected success");
        assert_eq!(pem, PEM_CERT_LEAF);
        assert_eq!(ders.len(), 1);
        assert_eq!(ders[0], b"abc");
    }

    #[tokio::test]
    async fn fulcio_parses_pem_chain_multi_cert() {
        let server = MockServer::start().await;
        let chain = format!("{PEM_CERT_LEAF}{PEM_CERT_INTERMEDIATE}{PEM_CERT_ROOT}");
        Mock::given(method("POST"))
            .and(match_path("/api/v2/signingCert"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_raw(chain.into_bytes(), "application/pem-certificate-chain"),
            )
            .mount(&server)
            .await;

        let (leaf_pem, ders) = fulcio_get_certificate(&server.uri(), "tok", "key", "proof")
            .await
            .expect("expected success");
        assert_eq!(leaf_pem, PEM_CERT_LEAF);
        assert_eq!(ders.len(), 3);
        assert_eq!(ders[0], b"abc");
        assert_eq!(ders[1], b"def");
        assert_eq!(ders[2], b"ghi");
    }

    #[tokio::test]
    async fn fulcio_parses_json_embedded_sct() {
        let server = MockServer::start().await;
        let body = serde_json::json!({
            "signedCertificateEmbeddedSct": {
                "chain": {
                    "certificates": [PEM_CERT_LEAF, PEM_CERT_INTERMEDIATE]
                }
            }
        });
        Mock::given(method("POST"))
            .and(match_path("/api/v2/signingCert"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/json")
                    .set_body_json(body),
            )
            .mount(&server)
            .await;

        let (leaf_pem, ders) = fulcio_get_certificate(&server.uri(), "tok", "key", "proof")
            .await
            .expect("expected success");
        assert_eq!(leaf_pem, PEM_CERT_LEAF);
        assert_eq!(ders.len(), 2);
    }

    #[tokio::test]
    async fn fulcio_parses_json_detached_sct() {
        let server = MockServer::start().await;
        let body = serde_json::json!({
            "signedCertificateDetachedSct": {
                "chain": {
                    "certificates": [PEM_CERT_LEAF]
                }
            }
        });
        Mock::given(method("POST"))
            .and(match_path("/api/v2/signingCert"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/json")
                    .set_body_json(body),
            )
            .mount(&server)
            .await;

        let (leaf_pem, ders) = fulcio_get_certificate(&server.uri(), "tok", "key", "proof")
            .await
            .expect("expected success");
        assert_eq!(leaf_pem, PEM_CERT_LEAF);
        assert_eq!(ders.len(), 1);
    }

    #[tokio::test]
    async fn fulcio_json_with_neither_chain_key_errors() {
        let server = MockServer::start().await;
        let body = serde_json::json!({"someOtherShape": {}});
        Mock::given(method("POST"))
            .and(match_path("/api/v2/signingCert"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/json")
                    .set_body_json(body),
            )
            .mount(&server)
            .await;

        let err = fulcio_get_certificate(&server.uri(), "tok", "key", "proof")
            .await
            .expect_err("expected error");
        let msg = format!("{err}");
        assert!(msg.contains("missing certificate chain"), "got: {msg}");
    }

    #[tokio::test]
    async fn fulcio_pem_empty_chain_errors() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(match_path("/api/v2/signingCert"))
            .respond_with(ResponseTemplate::new(200).set_body_raw(
                b"(no certs here)".to_vec(),
                "application/pem-certificate-chain",
            ))
            .mount(&server)
            .await;

        let err = fulcio_get_certificate(&server.uri(), "tok", "key", "proof")
            .await
            .expect_err("expected error");
        let msg = format!("{err}");
        assert!(msg.contains("empty certificate chain"), "got: {msg}");
    }

    #[tokio::test]
    async fn fulcio_http_500_errors_with_status() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(match_path("/api/v2/signingCert"))
            .respond_with(ResponseTemplate::new(500).set_body_string("upstream broken"))
            .mount(&server)
            .await;

        let err = fulcio_get_certificate(&server.uri(), "tok", "key", "proof")
            .await
            .expect_err("expected error");
        let msg = format!("{err}");
        assert!(msg.contains("500"), "expected status echoed, got: {msg}");
        assert!(
            msg.contains("upstream broken"),
            "expected body echoed, got: {msg}"
        );
    }

    #[tokio::test]
    async fn fulcio_json_content_type_with_begin_certificate_body_picks_json_branch() {
        // Regression guard for the comment at the content-type-check site:
        // "Check content-type ONLY (not body text) to choose the parser,
        //  because v2 JSON contains PEM strings that would falsely match
        //  'BEGIN CERTIFICATE'." A JSON-typed response whose embedded
        //  PEM string contains the marker must still parse as JSON.
        let server = MockServer::start().await;
        let body = serde_json::json!({
            "signedCertificateEmbeddedSct": {
                "chain": {
                    "certificates": [PEM_CERT_LEAF]
                }
            }
        });
        Mock::given(method("POST"))
            .and(match_path("/api/v2/signingCert"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/json")
                    .set_body_json(body),
            )
            .mount(&server)
            .await;

        let (pem, ders) = fulcio_get_certificate(&server.uri(), "tok", "key", "proof")
            .await
            .expect("expected JSON-branch parse");
        assert_eq!(pem, PEM_CERT_LEAF);
        assert_eq!(ders.len(), 1);
    }

    // ─── Rekor response parsing ───────────────────────────────────

    #[tokio::test]
    async fn rekor_parses_full_entry() {
        let server = MockServer::start().await;
        let body = serde_json::json!({
            "uuid-deadbeef": {
                "logIndex": 42,
                "integratedTime": 1700000000_i64,
                "logID": "log-abc",
                "body": "base64-body",
                "verification": {"inclusionProof": {"checkpoint": "..."}}
            }
        });
        Mock::given(method("POST"))
            .and(match_path("/api/v1/log/entries"))
            .respond_with(ResponseTemplate::new(201).set_body_json(body))
            .mount(&server)
            .await;

        let envelope = dsse_fixture();
        let entry = rekor_upload(&server.uri(), &envelope, "cert-pem")
            .await
            .expect("expected success");
        assert_eq!(entry.log_index, "42");
        assert_eq!(entry.integrated_time, "1700000000");
        assert_eq!(entry.log_id.key_id, "log-abc");
        assert_eq!(entry.canonicalized_body, "base64-body");
        assert!(entry.inclusion_proof.is_some());
    }

    #[tokio::test]
    async fn rekor_omits_inclusion_proof_when_verification_missing() {
        let server = MockServer::start().await;
        let body = serde_json::json!({
            "uuid": {
                "logIndex": 7,
                "integratedTime": 1700000000_i64,
                "logID": "log",
                "body": "b"
            }
        });
        Mock::given(method("POST"))
            .and(match_path("/api/v1/log/entries"))
            .respond_with(ResponseTemplate::new(201).set_body_json(body))
            .mount(&server)
            .await;

        let envelope = dsse_fixture();
        let entry = rekor_upload(&server.uri(), &envelope, "cert")
            .await
            .unwrap();
        assert!(entry.inclusion_proof.is_none());
    }

    #[tokio::test]
    async fn rekor_defaults_missing_log_index_to_zero() {
        // Current behavior: when `logIndex` is absent the function falls
        // back to "0" rather than erroring. This test pins that
        // contract; if the function later starts rejecting absent
        // fields, update the test to assert the new error shape.
        let server = MockServer::start().await;
        let body = serde_json::json!({
            "uuid": {
                "integratedTime": 1700000000_i64,
                "logID": "log",
                "body": "b"
            }
        });
        Mock::given(method("POST"))
            .and(match_path("/api/v1/log/entries"))
            .respond_with(ResponseTemplate::new(201).set_body_json(body))
            .mount(&server)
            .await;

        let entry = rekor_upload(&server.uri(), &dsse_fixture(), "cert")
            .await
            .unwrap();
        assert_eq!(entry.log_index, "0");
    }

    #[tokio::test]
    async fn rekor_empty_object_response_errors() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(match_path("/api/v1/log/entries"))
            .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({})))
            .mount(&server)
            .await;

        let err = rekor_upload(&server.uri(), &dsse_fixture(), "cert")
            .await
            .expect_err("expected error");
        assert!(format!("{err}").contains("Rekor response empty"));
    }

    #[tokio::test]
    async fn rekor_http_500_errors_with_status() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(match_path("/api/v1/log/entries"))
            .respond_with(ResponseTemplate::new(500).set_body_string("rekor down"))
            .mount(&server)
            .await;

        let err = rekor_upload(&server.uri(), &dsse_fixture(), "cert")
            .await
            .expect_err("expected error");
        let msg = format!("{err}");
        assert!(msg.contains("500"), "expected status, got: {msg}");
        assert!(msg.contains("rekor down"), "expected body, got: {msg}");
    }

    // ─── JWT subject extraction ───────────────────────────────────

    #[test]
    fn jwt_subject_extracts_from_valid_token() {
        let jwt = make_jwt(r#"{"sub":"user@example.com","iss":"https://oidc"}"#);
        assert_eq!(extract_jwt_subject(&jwt).unwrap(), "user@example.com");
    }

    #[test]
    fn jwt_subject_handles_base64url_chars() {
        // Build a payload whose base64url encoding contains `-` and `_`.
        // The byte sequence below was chosen so that standard base64
        // would use `+` / `/`, forcing the URL-safe alphabet.
        let payload = "{\"sub\":\"\u{00fb}\u{00fe}~\"}";
        let jwt = make_jwt(payload);
        // Confirm the test JWT actually contains url-safe chars
        let middle = jwt.split('.').nth(1).unwrap();
        assert!(
            middle.contains('-') || middle.contains('_'),
            "test fixture is meant to exercise base64url decoding; got: {middle}"
        );
        assert_eq!(extract_jwt_subject(&jwt).unwrap(), "\u{00fb}\u{00fe}~");
    }

    #[test]
    fn jwt_subject_handles_all_padding_lengths() {
        // The standard-base64 padding fixup in extract_jwt_subject covers
        // four cases (mod 4 = 0, 1, 2, 3). The "% 4 == 1" branch is
        // invalid base64 — only 0, 2, and 3 round-trip. Cover them.
        for pad_target in [0usize, 2, 3] {
            // Generate JSON payloads whose URL-safe encoding has the
            // target padding-mod. Vary the `sub` value length until it
            // matches.
            let mut sub = String::new();
            let jwt = loop {
                sub.push('x');
                let json = format!("{{\"sub\":\"{sub}\"}}");
                let enc = URL_SAFE_NO_PAD.encode(json.as_bytes());
                if enc.len() % 4 == pad_target {
                    break make_jwt(&json);
                }
                if sub.len() > 64 {
                    panic!("could not find input whose b64url length mod 4 = {pad_target}");
                }
            };
            assert_eq!(
                extract_jwt_subject(&jwt).unwrap(),
                sub,
                "padding case {pad_target}"
            );
        }
    }

    #[test]
    fn jwt_subject_rejects_wrong_segment_count() {
        assert!(extract_jwt_subject("only-one-segment").is_err());
        assert!(extract_jwt_subject("two.segments").is_err());
        assert!(extract_jwt_subject("a.b.c.d").is_err());
    }

    #[test]
    fn jwt_subject_rejects_non_base64_payload() {
        let jwt = "header.this-payload-has-====-invalid-padding-chars.sig";
        let err = extract_jwt_subject(jwt).expect_err("expected error");
        assert!(format!("{err}").contains("decode JWT payload"));
    }

    #[test]
    fn jwt_subject_rejects_non_json_payload() {
        let payload_b64 = URL_SAFE_NO_PAD.encode(b"this is not json");
        let jwt = format!("header.{payload_b64}.sig");
        let err = extract_jwt_subject(&jwt).expect_err("expected error");
        assert!(format!("{err}").contains("parse JWT payload"));
    }

    #[test]
    fn jwt_subject_rejects_missing_sub_claim() {
        let jwt = make_jwt(r#"{"iss":"https://oidc","aud":"sigstore"}"#);
        let err = extract_jwt_subject(&jwt).expect_err("expected error");
        assert!(format!("{err}").contains("missing 'sub' claim"));
    }

    #[test]
    fn jwt_subject_rejects_non_string_sub_claim() {
        let jwt = make_jwt(r#"{"sub":42}"#);
        let err = extract_jwt_subject(&jwt).expect_err("expected error");
        // The current code path bails out via the same "missing 'sub'"
        // arm because `.as_str()` returns None for non-string values.
        // That's a documented contract: assert it explicitly.
        assert!(format!("{err}").contains("missing 'sub' claim"));
    }

    // ─── sign_and_record_with_endpoints orchestration ─────────────

    #[tokio::test]
    async fn sign_and_record_with_endpoints_orchestrates_full_flow() {
        let fulcio = MockServer::start().await;
        let rekor = MockServer::start().await;

        Mock::given(method("POST"))
            .and(match_path("/api/v2/signingCert"))
            .respond_with(ResponseTemplate::new(200).set_body_raw(
                format!("{PEM_CERT_LEAF}{PEM_CERT_ROOT}").into_bytes(),
                "application/pem-certificate-chain",
            ))
            .mount(&fulcio)
            .await;

        Mock::given(method("POST"))
            .and(match_path("/api/v1/log/entries"))
            .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
                "uuid": {
                    "logIndex": 99,
                    "integratedTime": 1700000000_i64,
                    "logID": "log",
                    "body": "b"
                }
            })))
            .mount(&rekor)
            .await;

        let endpoints = SigstoreEndpoints {
            fulcio: fulcio.uri(),
            rekor: rekor.uri(),
        };
        let jwt = make_jwt(r#"{"sub":"ci@example.com"}"#);

        let bundle = sign_and_record_with_endpoints(&jwt, b"{\"_type\":\"in-toto\"}", &endpoints)
            .await
            .expect("expected success");

        assert_eq!(
            bundle.dsse_envelope.payload_type,
            "application/vnd.in-toto+json"
        );
        assert_eq!(bundle.dsse_envelope.signatures.len(), 1);
        assert_eq!(
            bundle
                .verification_material
                .x509_certificate_chain
                .certificates
                .len(),
            2
        );
        assert_eq!(bundle.verification_material.tlog_entries.len(), 1);
        assert_eq!(bundle.verification_material.tlog_entries[0].log_index, "99");
    }

    #[tokio::test]
    async fn sign_and_record_with_endpoints_propagates_fulcio_error() {
        let fulcio = MockServer::start().await;
        let rekor = MockServer::start().await;

        Mock::given(method("POST"))
            .and(match_path("/api/v2/signingCert"))
            .respond_with(ResponseTemplate::new(503).set_body_string("fulcio down"))
            .mount(&fulcio)
            .await;
        // Rekor mock not strictly required — the call must short-circuit
        // before reaching it.

        let endpoints = SigstoreEndpoints {
            fulcio: fulcio.uri(),
            rekor: rekor.uri(),
        };
        let jwt = make_jwt(r#"{"sub":"ci"}"#);

        let err = sign_and_record_with_endpoints(&jwt, b"{}", &endpoints)
            .await
            .expect_err("expected fulcio error to surface");
        assert!(format!("{err}").contains("503"));
    }

    // ─── Legacy serde-shape tests (kept; format ownership) ────────

    #[test]
    fn sigstore_bundle_serializes() {
        let bundle = SigstoreBundle {
            dsse_envelope: DsseEnvelope {
                payload_type: "application/vnd.in-toto+json".into(),
                payload: "dGVzdA==".into(),
                signatures: vec![],
            },
            verification_material: VerificationMaterial {
                x509_certificate_chain: CertificateChain {
                    certificates: vec![Certificate {
                        raw_bytes: "Y2VydA==".into(),
                    }],
                },
                tlog_entries: vec![],
            },
        };

        let json = serde_json::to_string(&bundle).unwrap();
        assert!(json.contains("dsseEnvelope"));
        assert!(json.contains("verificationMaterial"));
        assert!(json.contains("x509CertificateChain"));
    }
}
