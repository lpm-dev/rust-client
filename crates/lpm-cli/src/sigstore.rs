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

/// Fulcio public instance.
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

	// Encode public key as PEM for Fulcio
	let public_key_der = verifying_key.to_encoded_point(false);
	let public_key_b64 = BASE64.encode(public_key_der.as_bytes());

	// Step 2: Exchange OIDC token for Fulcio signing certificate
	let (cert_pem, cert_chain_der) =
		fulcio_get_certificate(oidc_token, &public_key_b64).await?;

	// Step 3: Create DSSE envelope
	let payload_type = "application/vnd.in-toto+json";
	let payload_b64 = BASE64.encode(slsa_statement_json);

	// Sign the PAE-encoded payload
	let pae_bytes = pae(payload_type, slsa_statement_json);
	let signature: p256::ecdsa::Signature = signing_key.sign(&pae_bytes);
	let signature_b64 = BASE64.encode(signature.to_der().as_bytes());

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
/// POST https://fulcio.sigstore.dev/api/v2/signingCertificate
async fn fulcio_get_certificate(
	oidc_token: &str,
	public_key_b64: &str,
) -> Result<(String, Vec<Vec<u8>>), LpmError> {
	let client = reqwest::Client::new();

	let body = serde_json::json!({
		"credentials": {
			"oidcIdentityToken": oidc_token,
		},
		"publicKeyRequest": {
			"publicKey": {
				"algorithm": "ECDSA",
				"content": public_key_b64,
			},
			"proofOfPossession": oidc_token,
		},
	});

	let response = client
		.post(format!("{FULCIO_URL}/api/v2/signingCertificate"))
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

	let result: serde_json::Value = response
		.json()
		.await
		.map_err(|e| LpmError::Registry(format!("Fulcio response parse error: {e}")))?;

	// Extract certificate chain from response
	let chain = result
		.get("signedCertificateEmbeddedSct")
		.or_else(|| result.get("signedCertificateDetachedSct"))
		.and_then(|v| v.get("chain"))
		.and_then(|v| v.get("certificates"))
		.and_then(|v| v.as_array())
		.ok_or_else(|| {
			LpmError::Registry("Fulcio response missing certificate chain".into())
		})?;

	let mut cert_pem = String::new();
	let mut cert_chain_der = Vec::new();

	for cert_val in chain {
		if let Some(cert_str) = cert_val.as_str() {
			if cert_pem.is_empty() {
				cert_pem = cert_str.to_string();
			}
			// Decode PEM to DER for the bundle
			let der = pem_to_der(cert_str)?;
			cert_chain_der.push(der);
		}
	}

	if cert_pem.is_empty() {
		return Err(LpmError::Registry(
			"Fulcio returned empty certificate chain".into(),
		));
	}

	Ok((cert_pem, cert_chain_der))
}

/// Upload a signed DSSE envelope to Rekor transparency log.
///
/// POST https://rekor.sigstore.dev/api/v1/log/entries
async fn rekor_upload(
	envelope: &DsseEnvelope,
	cert_pem: &str,
) -> Result<TlogEntry, LpmError> {
	let client = reqwest::Client::new();

	let envelope_json = serde_json::to_string(envelope)
		.map_err(|e| LpmError::Registry(format!("failed to serialize DSSE envelope: {e}")))?;
	let envelope_b64 = BASE64.encode(envelope_json.as_bytes());

	let body = serde_json::json!({
		"apiVersion": "0.0.2",
		"kind": "intoto",
		"spec": {
			"content": {
				"envelope": envelope_b64,
			},
			"publicKey": {
				"content": BASE64.encode(cert_pem.as_bytes()),
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
