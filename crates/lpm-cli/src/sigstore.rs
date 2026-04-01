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

/// Run the complete Sigstore signing flow.
///
/// 1. Generate ephemeral keypair
/// 2. Exchange OIDC token with Fulcio for a signing certificate
/// 3. Sign the SLSA statement as a DSSE envelope
/// 4. Upload to Rekor transparency log
/// 5. Return the complete Sigstore bundle
pub async fn sign_and_record(
    oidc_token: &str,
    slsa_statement_json: &[u8],
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
        fulcio_get_certificate(oidc_token, &public_key_pem, &proof_b64).await?;

    // Step 4: Create DSSE envelope
    let payload_type = "application/vnd.in-toto+json";
    let payload_b64 = BASE64.encode(slsa_statement_json);

    // Sign the PAE-encoded payload
    // DSSE/Rekor expects the signature in DER format for ECDSA
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
    let tlog_entry = rekor_upload(&dsse_envelope, &cert_pem).await?;

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
        .post(format!("{FULCIO_URL}/api/v2/signingCert"))
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
async fn rekor_upload(envelope: &DsseEnvelope, cert_pem: &str) -> Result<TlogEntry, LpmError> {
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
        .post(format!("{REKOR_URL}/api/v1/log/entries"))
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
