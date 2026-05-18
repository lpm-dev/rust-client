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

/// Wall-clock budget for any single Fulcio or Rekor request, including
/// connection, TLS handshake, and the entire response body. A hostile
/// or unreachable endpoint must surface as an error rather than wedge
/// `lpm publish` indefinitely.
const SIGSTORE_HTTP_TIMEOUT_SECS: u64 = 30;

/// Maximum response body bytes we will buffer from Fulcio or Rekor.
/// Real responses are kilobyte-sized; the cap exists to prevent a
/// compromised endpoint from streaming GiB of data into our heap. Matches
/// the cap in [`crate::provenance_fetch`] for consistency.
const SIGSTORE_RESPONSE_CAP_BYTES: usize = 1024 * 1024;

/// Sigstore service endpoints.
///
/// Fields are intentionally private. Only [`Self::production`] (the
/// pinned public instance) is wired into the publish path. A future
/// override mechanism — e.g. an `SIGSTORE_FULCIO_URL` env var — must
/// add a new public constructor that is visible in code review,
/// which is the gate that prevents attestation traffic from being
/// silently redirected to an attacker-controlled host.
pub struct SigstoreEndpoints {
    fulcio: String,
    rekor: String,
}

impl SigstoreEndpoints {
    /// Pinned public Sigstore instance.
    pub fn production() -> Self {
        Self {
            fulcio: FULCIO_URL.to_string(),
            rekor: REKOR_URL.to_string(),
        }
    }

    /// Test-only constructor for wiremock-driven scenarios.
    #[cfg(test)]
    fn for_test(fulcio: String, rekor: String) -> Self {
        Self { fulcio, rekor }
    }
}

/// Build the HTTP client used for every Fulcio / Rekor exchange.
/// Centralised so the wall-clock timeout cannot be omitted at any
/// call site.
///
/// M2: redirect policy is explicitly set to `Policy::none()`. The
/// Fulcio / Rekor endpoints should never redirect a legitimate
/// signing request; a `Location:` header on either flow would only
/// happen if the canonical endpoint had been compromised AND tried
/// to bounce traffic via a third-party host (where the request body
/// — OIDC bearer + signing-request payload — would be exposed). The
/// pre-fix client used reqwest's default of 10 follows, which strips
/// cross-host `Authorization` only on the host hop reqwest knows
/// about; the OIDC bearer travels in the JSON body, not the
/// `Authorization` header, so reqwest's strip wouldn't have caught
/// it. Explicitly refusing redirects closes the bounce-and-capture
/// arm. A legitimate Fulcio rotation would be announced as a new
/// constant + code release, not a transparent redirect.
fn sigstore_http_client() -> Result<reqwest::Client, LpmError> {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(SIGSTORE_HTTP_TIMEOUT_SECS))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| LpmError::Registry(format!("failed to build Sigstore HTTP client: {e}")))
}

/// M2: embedded SPKI pin for the canonical Fulcio TLS leaf. When
/// `Some(hex)`, the TLS connector must reject any handshake whose
/// presented leaf cert SPKI does not match the pinned hash —
/// closes the "system-trust-store CA was compromised, attacker
/// substitutes the Fulcio leaf" arm even when WebPKI says the chain
/// is otherwise valid. Default `None` keeps today's behaviour so a
/// stale pin in a shipped binary can't brick legitimate Sigstore
/// rotation; release process flips the constant to the rotated SPKI
/// hash and ships a new lpm-cli build.
///
/// A custom `rustls::client::ServerCertVerifier` wired through the
/// reqwest builder is the remaining work; the slot here is the
/// audit hook so a future PR that adds the verifier without
/// referencing M2 stands out in code review.
#[allow(dead_code)]
pub(crate) const EMBEDDED_FULCIO_SPKI_PIN_HEX: Option<&str> = None;

/// M2: embedded SPKI pin for the canonical Rekor TLS leaf. Same
/// shape and rationale as [`EMBEDDED_FULCIO_SPKI_PIN_HEX`].
#[allow(dead_code)]
pub(crate) const EMBEDDED_REKOR_SPKI_PIN_HEX: Option<&str> = None;

/// Read a response body with a two-stage size cap: reject pre-stream
/// when `Content-Length` declares an oversized body, then reject mid-
/// stream when accumulating chunks would cross the cap. The label
/// (e.g. `"Fulcio"`) appears in error messages so a failure points at
/// the right hop.
async fn read_response_body_capped(
    response: reqwest::Response,
    label: &str,
) -> Result<String, LpmError> {
    use futures::StreamExt;

    if let Some(declared) = response.content_length()
        && declared as usize > SIGSTORE_RESPONSE_CAP_BYTES
    {
        return Err(LpmError::Registry(format!(
            "{label} response declared body length {declared} exceeds cap {SIGSTORE_RESPONSE_CAP_BYTES}"
        )));
    }

    let mut buf: Vec<u8> = Vec::with_capacity(8 * 1024);
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk
            .map_err(|e| LpmError::Registry(format!("{label} response body read error: {e}")))?;
        if buf.len().saturating_add(chunk.len()) > SIGSTORE_RESPONSE_CAP_BYTES {
            return Err(LpmError::Registry(format!(
                "{label} response streamed body exceeded cap {SIGSTORE_RESPONSE_CAP_BYTES}"
            )));
        }
        buf.extend_from_slice(&chunk);
    }

    String::from_utf8(buf)
        .map_err(|e| LpmError::Registry(format!("{label} response was not valid UTF-8: {e}")))
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
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DsseEnvelope {
    /// Payload type URI.
    #[serde(rename = "payloadType")]
    pub payload_type: String,

    /// Base64-encoded payload (the SLSA statement).
    pub payload: String,

    /// Signatures over the PAE-encoded payload.
    pub signatures: Vec<DsseSignature>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DsseSignature {
    /// Key ID (empty for Sigstore — identity is in the certificate).
    #[serde(default)]
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

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
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

    /// Sigstore Bundle v0.3 spec: top-level inclusion promise carrying
    /// the Signed Entry Timestamp (SET). Populated when deserializing a
    /// spec-compliant bundle from npm, GitHub `attest-build-provenance`,
    /// or LPM's own publish path (which lifts Rekor's nested
    /// `verification.inclusionPromise` into this field).
    #[serde(
        rename = "inclusionPromise",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub inclusion_promise: Option<RekorInclusionPromise>,

    /// Sigstore Bundle v0.3 spec: top-level inclusion proof + checkpoint.
    /// Populated under the same rules as [`Self::inclusion_promise`].
    #[serde(
        rename = "inclusionProof",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub inclusion_proof: Option<RekorInclusionProof>,

    /// Rekor API response shape (`POST /api/v1/log/entries`), kept as a
    /// deserialization fallback. Real Rekor responses nest inclusion
    /// material under a `verification` envelope two levels deep:
    /// `verification.inclusionPromise.signedEntryTimestamp` and
    /// `verification.inclusionProof`. The Sigstore Bundle v0.3 spec
    /// flattens those onto the TlogEntry directly, but in-the-wild
    /// LPM bundles published before this schema change captured Rekor's
    /// response verbatim. Verifier reads via the
    /// [`Self::resolved_inclusion_promise`] /
    /// [`Self::resolved_inclusion_proof`] accessors which prefer the
    /// spec-compliant top-level fields and fall back through this
    /// envelope. New LPM bundles never write to this field — the
    /// publish path lifts the nested values into the top-level fields.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verification: Option<RekorVerification>,

    /// The canonicalized entry body.
    #[serde(rename = "canonicalizedBody")]
    pub canonicalized_body: String,
}

// Consumers of these accessors land alongside the install-time
// verifier (Phase 1.6+); the schema bump is a precondition that ships
// ahead of the verifier so the data model is in place when verifier
// code wires in. `#[allow(dead_code)]` matches the pattern used for
// the M2 SPKI pin slots — declared up front, consumed in a follow-up.
#[allow(dead_code)]
impl TlogEntry {
    /// Inclusion promise (carrying the SET) preferring the
    /// Sigstore Bundle v0.3 spec-compliant top-level field, falling
    /// back through the legacy Rekor `verification` envelope. See the
    /// doc-comment on [`Self::verification`] for why both paths exist.
    pub fn resolved_inclusion_promise(&self) -> Option<&RekorInclusionPromise> {
        self.inclusion_promise.as_ref().or_else(|| {
            self.verification
                .as_ref()
                .and_then(|v| v.inclusion_promise.as_ref())
        })
    }

    /// Inclusion proof + checkpoint preferring the spec-compliant
    /// top-level field, falling back through the legacy Rekor
    /// `verification` envelope.
    pub fn resolved_inclusion_proof(&self) -> Option<&RekorInclusionProof> {
        self.inclusion_proof.as_ref().or_else(|| {
            self.verification
                .as_ref()
                .and_then(|v| v.inclusion_proof.as_ref())
        })
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LogId {
    /// Hex-encoded key ID of the Rekor log.
    #[serde(rename = "keyId")]
    pub key_id: String,
}

/// Rekor's `verification` envelope as returned by
/// `POST /api/v1/log/entries`. This shape is NOT part of the Sigstore
/// Bundle v0.3 spec (the spec flattens these onto TlogEntry directly),
/// but it appears in legacy LPM-published bundles. New publish flow
/// lifts the fields into [`TlogEntry::inclusion_promise`] /
/// [`TlogEntry::inclusion_proof`]; this type exists only so the
/// verifier can still read older bundles.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RekorVerification {
    #[serde(
        rename = "inclusionPromise",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub inclusion_promise: Option<RekorInclusionPromise>,

    #[serde(
        rename = "inclusionProof",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub inclusion_proof: Option<RekorInclusionProof>,
}

/// Carries the Signed Entry Timestamp — Rekor's offline-verifiable
/// proof that an entry was integrated into the log at
/// `integratedTime`. The SET is a base64-encoded ECDSA signature over
/// a canonical `{ body, integratedTime, logIndex, logID }` JSON
/// produced by the Rekor log's signing key.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RekorInclusionPromise {
    #[serde(rename = "signedEntryTimestamp")]
    pub signed_entry_timestamp: String,
}

/// Merkle inclusion proof for the Rekor entry's leaf hash, plus the
/// checkpoint the proof terminates at. The checkpoint signature
/// is verified against the same Rekor log key that signs the SET.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RekorInclusionProof {
    /// The signed checkpoint the proof terminates at. Shape varies by
    /// Rekor version; the verifier parses it via the checkpoint format
    /// rather than relying on a fixed struct.
    pub checkpoint: serde_json::Value,

    /// Sibling hashes along the Merkle path from leaf to root.
    pub hashes: Vec<String>,

    #[serde(rename = "logIndex")]
    pub log_index: i64,

    #[serde(rename = "rootHash")]
    pub root_hash: String,

    #[serde(rename = "treeSize")]
    pub tree_size: i64,
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
    let pae_bytes = crate::sigstore_verify::pae(payload_type, slsa_statement_json);
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
    let client = sigstore_http_client()?;

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
        let text = read_response_body_capped(response, "Fulcio")
            .await
            .unwrap_or_default();
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

    let response_text = read_response_body_capped(response, "Fulcio").await?;

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
            let certs_pem = split_pem_chain(&response_text)?;
            if certs_pem.is_empty() {
                return Err(LpmError::Registry(
                    "Fulcio returned empty certificate chain".into(),
                ));
            }
            let first_pem = certs_pem[0].clone();
            let ders: Result<Vec<Vec<u8>>, _> = certs_pem.iter().map(|p| pem_to_der(p)).collect();
            (first_pem, ders?)
        } else {
            // JSON response — parse certificate chain.
            //
            // Sigstore-bundle hygiene: ONLY accept the
            // `signedCertificateEmbeddedSct` response variant. The legacy
            // `signedCertificateDetachedSct` variant (Fulcio v1) returns
            // the cert chain plus a separate `signedCertificateTimestamp`
            // field — but the Sigstore Bundle v0.3 spec has no
            // first-class detached-SCT field, so any bundle built from
            // such a response would be signed-but-unverifiable at
            // install time (the install-side verifier requires embedded
            // SCTs per Phase 1.4). Reject loudly instead of building an
            // unverifiable bundle.
            let result: serde_json::Value = serde_json::from_str(&response_text)
                .map_err(|e| LpmError::Registry(format!("Fulcio response parse error: {e}")))?;

            if result.get("signedCertificateDetachedSct").is_some() {
                tracing::error!(
                    target: "lpm_cli::sigstore",
                    "Fulcio returned `signedCertificateDetachedSct` — Sigstore Bundle v0.3 \
                     has no first-class detached-SCT field, so a bundle built from this \
                     response would be unverifiable at install time"
                );
                return Err(LpmError::Registry(
                    "Fulcio returned the legacy `signedCertificateDetachedSct` response variant; \
                     a Sigstore Bundle built from it would be unverifiable at install time \
                     (no embedded SCT). Update Fulcio to the v2 API that returns \
                     `signedCertificateEmbeddedSct`."
                        .into(),
                ));
            }

            let chain = result
                .get("signedCertificateEmbeddedSct")
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
    let client = sigstore_http_client()?;

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
        let text = read_response_body_capped(response, "Rekor")
            .await
            .unwrap_or_default();
        return Err(LpmError::Registry(format!(
            "Rekor transparency log upload failed ({status}): {text}"
        )));
    }

    let response_text = read_response_body_capped(response, "Rekor").await?;
    let result: serde_json::Value = serde_json::from_str(&response_text)
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

    // Lift Rekor's `verification.inclusionPromise` / `inclusionProof`
    // into top-level `TlogEntry` fields so the persisted bundle matches
    // the Sigstore Bundle v0.3 spec shape (top-level
    // inclusionPromise/inclusionProof on TransparencyLogEntry). The
    // `verification` envelope is Rekor's API response wrapping — it is
    // not part of the bundle wire format. Bundles produced before this
    // change captured the envelope verbatim; the verifier's
    // `TlogEntry::resolved_inclusion_*` accessors fall back through
    // that legacy shape so old bundles still verify.
    let verification_obj = entry.get("verification");
    let inclusion_promise = verification_obj
        .and_then(|v| v.get("inclusionPromise"))
        .and_then(|v| serde_json::from_value::<RekorInclusionPromise>(v.clone()).ok());
    let inclusion_proof = verification_obj
        .and_then(|v| v.get("inclusionProof"))
        .and_then(|v| serde_json::from_value::<RekorInclusionProof>(v.clone()).ok());

    Ok(TlogEntry {
        log_index,
        log_id: LogId { key_id: log_id },
        integrated_time,
        inclusion_promise,
        inclusion_proof,
        verification: None,
        canonicalized_body: body_b64,
    })
}

/// Issuers whose JWTs we will accept the `sub` claim from. Fulcio is
/// the canonical signature verifier; this allowlist is a defense-in-
/// depth gate so that even a future bug that bypassed Fulcio would
/// still refuse to trust a JWT from a non-recognised issuer.
///
/// Listed exactly as the OIDC providers we support produce them:
/// - GitHub Actions: <https://token.actions.githubusercontent.com>
/// - GitLab CI:      <https://gitlab.com>
///
/// Tests use `extract_jwt_subject_with_issuers` with a wider set so
/// the wiremock-driven scenarios in this module's test suite continue
/// to work without leaking test-only issuers into the production
/// allowlist.
const ALLOWED_OIDC_ISSUERS: &[&str] = &[
    "https://token.actions.githubusercontent.com",
    "https://gitlab.com",
];

/// Extract the "sub" (subject) claim from a JWT without verifying the
/// signature — but only after the `iss` claim matches an allowlisted
/// issuer.
///
/// The subject is used as the proof-of-possession challenge for Fulcio
/// — we sign it with the ephemeral key to prove we control the
/// private key. M1: pre-fix this function decoded `sub` regardless of
/// who issued the token; a future change that started honouring the
/// `sub` outside the Fulcio flow (or any downstream consumer that
/// trusted the local decode) would have inherited that gap. The
/// allowlist gate closes the structural arm.
fn extract_jwt_subject(jwt: &str) -> Result<String, LpmError> {
    extract_jwt_subject_with_issuers(jwt, ALLOWED_OIDC_ISSUERS)
}

/// Same as [`extract_jwt_subject`] but with a caller-supplied issuer
/// allowlist. Reserved for `#[cfg(test)]` scenarios that need to
/// admit a wiremock issuer.
fn extract_jwt_subject_with_issuers(
    jwt: &str,
    allowed_issuers: &[&str],
) -> Result<String, LpmError> {
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

    // M1: the issuer allowlist gate. Reject a JWT whose `iss` claim is
    // absent OR not in the allowlist BEFORE returning the unverified
    // `sub`. Fulcio remains the canonical signature verifier; this is
    // defense-in-depth.
    let iss = payload
        .get("iss")
        .and_then(|v| v.as_str())
        .ok_or_else(|| LpmError::Registry("JWT missing 'iss' claim".into()))?;
    if !allowed_issuers.contains(&iss) {
        return Err(LpmError::Registry(format!(
            "JWT issuer '{iss}' is not in the allowlist (M1)",
        )));
    }

    payload
        .get("sub")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| LpmError::Registry("JWT missing 'sub' claim".into()))
}

/// Decode a single PEM-encoded `CERTIFICATE` block to DER bytes.
///
/// Strict parser: rejects PEMs whose label is anything other than
/// `CERTIFICATE` (so a `PRIVATE KEY` or `SIGNATURE` block can't sneak
/// past as a cert), refuses any non-blank content between the END
/// marker and EOF, and refuses any other `-----LABEL-----` line inside
/// the body. The previous implementation simply stripped every line
/// starting with `-----` and base64-decoded the rest, which let a
/// hostile Fulcio response smuggle bytes into the DER by interleaving
/// extra labels or trailing content.
pub(crate) fn pem_to_der(pem: &str) -> Result<Vec<u8>, LpmError> {
    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    const END: &str = "-----END CERTIFICATE-----";

    let mut lines = pem.lines();

    let begin = lines
        .by_ref()
        .map(str::trim_end)
        .find(|l| !l.is_empty())
        .ok_or_else(|| LpmError::Registry("PEM input is empty".into()))?;
    if begin != BEGIN {
        return Err(LpmError::Registry(format!(
            "expected `{BEGIN}`, got `{begin}`"
        )));
    }

    let mut body = String::new();
    let mut saw_end = false;
    for line in lines.by_ref() {
        let trimmed = line.trim_end();
        if trimmed == END {
            saw_end = true;
            break;
        }
        if trimmed.is_empty() {
            continue;
        }
        if trimmed.starts_with("-----") {
            return Err(LpmError::Registry(format!(
                "unexpected PEM marker inside CERTIFICATE body: `{trimmed}`"
            )));
        }
        body.push_str(trimmed);
    }
    if !saw_end {
        return Err(LpmError::Registry(format!("missing `{END}` marker")));
    }

    for line in lines {
        if !line.trim().is_empty() {
            return Err(LpmError::Registry(format!(
                "unexpected content after `{END}`: `{}`",
                line.trim_end()
            )));
        }
    }

    BASE64
        .decode(body.as_bytes())
        .map_err(|e| LpmError::Registry(format!("invalid PEM certificate base64: {e}")))
}

/// Split a PEM chain (multiple `CERTIFICATE` blocks concatenated) into
/// individual PEM strings, each still terminated by its `-----END
/// CERTIFICATE-----` marker so it parses cleanly through [`pem_to_der`].
///
/// Strict parser: requires the BEGIN / END markers to appear on their
/// own line (no substring match), refuses any non-blank content between
/// blocks, and refuses a nested BEGIN or stray END marker. The previous
/// implementation accepted lines that merely *contained* the marker
/// substring, allowing a hostile Fulcio response to interleave content
/// into the chain.
fn split_pem_chain(text: &str) -> Result<Vec<String>, LpmError> {
    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    const END: &str = "-----END CERTIFICATE-----";

    let mut certs = Vec::new();
    let mut current = String::new();
    let mut in_cert = false;

    for line in text.lines() {
        let trimmed = line.trim_end();
        if trimmed == BEGIN {
            if in_cert {
                return Err(LpmError::Registry(
                    "nested `-----BEGIN CERTIFICATE-----` in PEM chain".into(),
                ));
            }
            in_cert = true;
            current.clear();
            current.push_str(line);
            current.push('\n');
        } else if trimmed == END {
            if !in_cert {
                return Err(LpmError::Registry(
                    "stray `-----END CERTIFICATE-----` in PEM chain".into(),
                ));
            }
            current.push_str(line);
            current.push('\n');
            certs.push(std::mem::take(&mut current));
            in_cert = false;
        } else if in_cert {
            current.push_str(line);
            current.push('\n');
        } else if !trimmed.is_empty() {
            return Err(LpmError::Registry(format!(
                "unexpected content outside PEM block in chain: `{trimmed}`"
            )));
        }
    }

    if in_cert {
        return Err(LpmError::Registry(
            "unterminated `-----BEGIN CERTIFICATE-----` in PEM chain".into(),
        ));
    }

    Ok(certs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pem_to_der_basic() {
        let pem = "-----BEGIN CERTIFICATE-----\nYWJj\n-----END CERTIFICATE-----";
        let der = pem_to_der(pem).unwrap();
        assert_eq!(der, b"abc");
    }

    #[test]
    fn pem_to_der_rejects_private_key_label() {
        let pem = "-----BEGIN PRIVATE KEY-----\nYWJj\n-----END PRIVATE KEY-----";
        let err = pem_to_der(pem).expect_err("non-CERTIFICATE label must be rejected");
        assert!(
            format!("{err}").contains("expected `-----BEGIN CERTIFICATE-----`"),
            "got: {err}"
        );
    }

    #[test]
    fn pem_to_der_rejects_unexpected_marker_inside_body() {
        let pem = "-----BEGIN CERTIFICATE-----\nYWJj\n-----BEGIN SIGNATURE-----\nZGVm\n-----END CERTIFICATE-----";
        let err = pem_to_der(pem).expect_err("nested marker must be rejected");
        assert!(
            format!("{err}").contains("unexpected PEM marker inside CERTIFICATE body"),
            "got: {err}"
        );
    }

    #[test]
    fn pem_to_der_rejects_trailing_content_after_end_marker() {
        let pem = "-----BEGIN CERTIFICATE-----\nYWJj\n-----END CERTIFICATE-----\nZGVm";
        let err = pem_to_der(pem).expect_err("trailing content must be rejected");
        assert!(
            format!("{err}").contains("unexpected content after"),
            "got: {err}"
        );
    }

    #[test]
    fn pem_to_der_rejects_missing_end_marker() {
        let pem = "-----BEGIN CERTIFICATE-----\nYWJj\n";
        let err = pem_to_der(pem).expect_err("missing END must be rejected");
        assert!(format!("{err}").contains("missing"), "got: {err}");
    }

    #[test]
    fn pem_to_der_rejects_empty_input() {
        let err = pem_to_der("").expect_err("empty input must be rejected");
        assert!(
            format!("{err}").contains("PEM input is empty"),
            "got: {err}"
        );
    }

    #[test]
    fn pem_to_der_ignores_leading_blank_lines() {
        let pem = "\n\n-----BEGIN CERTIFICATE-----\nYWJj\n-----END CERTIFICATE-----\n";
        assert_eq!(pem_to_der(pem).unwrap(), b"abc");
    }

    #[test]
    fn split_pem_chain_handles_concatenated_blocks() {
        let chain = format!("{PEM_CERT_LEAF}{PEM_CERT_INTERMEDIATE}{PEM_CERT_ROOT}");
        let certs = split_pem_chain(&chain).unwrap();
        assert_eq!(certs.len(), 3);
        assert_eq!(pem_to_der(&certs[0]).unwrap(), b"abc");
        assert_eq!(pem_to_der(&certs[1]).unwrap(), b"def");
        assert_eq!(pem_to_der(&certs[2]).unwrap(), b"ghi");
    }

    #[test]
    fn split_pem_chain_rejects_content_between_blocks() {
        // Hostile-server smuggling case: extra base64 between an END
        // and the next BEGIN that the lax parser would have silently
        // ignored. Strict parser refuses.
        let chain = format!("{PEM_CERT_LEAF}smuggled-line\n{PEM_CERT_INTERMEDIATE}");
        let err = split_pem_chain(&chain).expect_err("inter-block content must be rejected");
        assert!(
            format!("{err}").contains("unexpected content outside PEM block"),
            "got: {err}"
        );
    }

    #[test]
    fn split_pem_chain_rejects_stray_end_marker() {
        let chain = "-----END CERTIFICATE-----\n";
        let err = split_pem_chain(chain).expect_err("stray END must be rejected");
        assert!(format!("{err}").contains("stray"), "got: {err}");
    }

    #[test]
    fn split_pem_chain_rejects_nested_begin_marker() {
        let chain = "-----BEGIN CERTIFICATE-----\nYWJj\n-----BEGIN CERTIFICATE-----\nZGVm\n-----END CERTIFICATE-----\n";
        let err = split_pem_chain(chain).expect_err("nested BEGIN must be rejected");
        assert!(format!("{err}").contains("nested"), "got: {err}");
    }

    #[test]
    fn split_pem_chain_rejects_unterminated_block() {
        let chain = "-----BEGIN CERTIFICATE-----\nYWJj\n";
        let err = split_pem_chain(chain).expect_err("missing END must be rejected");
        assert!(format!("{err}").contains("unterminated"), "got: {err}");
    }

    #[test]
    fn split_pem_chain_rejects_substring_marker_match() {
        // Old parser used `line.contains("BEGIN CERTIFICATE")`, which
        // would treat `# BEGIN CERTIFICATE comment` as a block opener.
        // Strict parser only matches the exact marker line.
        let chain = "# BEGIN CERTIFICATE — this is a comment\n";
        let err =
            split_pem_chain(chain).expect_err("substring match must be rejected as out-of-block");
        assert!(
            format!("{err}").contains("unexpected content outside PEM block"),
            "got: {err}"
        );
    }

    #[test]
    fn split_pem_chain_empty_input_yields_no_certs() {
        let certs = split_pem_chain("").unwrap();
        assert!(certs.is_empty());
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
    async fn fulcio_rejects_detached_sct_response_because_bundle_cannot_persist_scts() {
        // Phase 1.4 hygiene: a Fulcio response carrying the legacy
        // `signedCertificateDetachedSct` variant returns the cert
        // chain plus a separate `signedCertificateTimestamp`, but the
        // Sigstore Bundle v0.3 spec has no first-class detached-SCT
        // field. Accepting this would let publish build an
        // unverifiable bundle (install-side verifier requires
        // embedded SCTs). Reject loudly.
        let server = MockServer::start().await;
        let body = serde_json::json!({
            "signedCertificateDetachedSct": {
                "chain": {
                    "certificates": [PEM_CERT_LEAF]
                },
                "signedCertificateTimestamp": "<some-base64>"
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

        let err = fulcio_get_certificate(&server.uri(), "tok", "key", "proof")
            .await
            .expect_err("legacy detached-SCT response must reject");
        assert!(
            format!("{err}").contains("signedCertificateDetachedSct"),
            "expected detached-SCT diagnostic, got: {err}"
        );
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
        // Strict parser rejects the stray `(no certs here)` line as
        // out-of-block content rather than reaching the "empty chain"
        // arm below it. Either rejection is the right outcome; the
        // assertion pins the stricter one.
        assert!(
            msg.contains("unexpected content outside PEM block"),
            "got: {msg}"
        );
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
    async fn rekor_parses_full_entry_and_lifts_set_to_top_level_inclusion_promise() {
        let server = MockServer::start().await;
        let body = serde_json::json!({
            "uuid-deadbeef": {
                "logIndex": 42,
                "integratedTime": 1700000000_i64,
                "logID": "log-abc",
                "body": "base64-body",
                "verification": {
                    "inclusionPromise": {
                        "signedEntryTimestamp": "MEUCIQDexample=="
                    },
                    "inclusionProof": {
                        "checkpoint": "rekor.sigstore.dev - 1\n100\nabc=\n\n",
                        "hashes": ["aa", "bb"],
                        "logIndex": 42,
                        "rootHash": "rootabc",
                        "treeSize": 101
                    }
                }
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

        let promise = entry
            .inclusion_promise
            .as_ref()
            .expect("SET must be lifted from Rekor verification envelope into top-level field");
        assert_eq!(promise.signed_entry_timestamp, "MEUCIQDexample==");

        let proof = entry.inclusion_proof.as_ref().expect(
            "inclusion proof must be lifted from Rekor verification envelope into top-level field",
        );
        assert_eq!(proof.log_index, 42);
        assert_eq!(proof.tree_size, 101);
        assert_eq!(proof.root_hash, "rootabc");
        assert_eq!(proof.hashes, vec!["aa".to_string(), "bb".to_string()]);

        // Spec-compliant publish path never writes the Rekor-API
        // envelope; it lives on the struct only as a deserialization
        // fallback for legacy bundles.
        assert!(
            entry.verification.is_none(),
            "publish path must not persist the Rekor-API `verification` envelope; \
             top-level fields are the wire format"
        );
    }

    #[tokio::test]
    async fn rekor_omits_inclusion_material_when_verification_missing() {
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
        assert!(entry.inclusion_promise.is_none());
        assert!(entry.inclusion_proof.is_none());
        assert!(entry.verification.is_none());
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

    // ─── TlogEntry schema: spec-compliant vs legacy-nested ────────

    #[test]
    fn tlog_entry_deserializes_set_from_top_level_inclusion_promise_field() {
        // Sigstore Bundle v0.3 spec: TransparencyLogEntry carries
        // `inclusionPromise` and `inclusionProof` as TOP-LEVEL fields.
        // npm and GitHub `attest-build-provenance` emit this shape.
        // The verifier must read SET from here without any
        // `verification` envelope present.
        let json = serde_json::json!({
            "logIndex": "10",
            "logId": {"keyId": "kid"},
            "integratedTime": "1700000000",
            "inclusionPromise": {
                "signedEntryTimestamp": "MEUCIQDspec=="
            },
            "canonicalizedBody": "body"
        });
        let entry: TlogEntry = serde_json::from_value(json).expect("spec-shape must deserialize");
        assert!(entry.verification.is_none());
        let promise = entry
            .resolved_inclusion_promise()
            .expect("resolved accessor must return the top-level SET");
        assert_eq!(promise.signed_entry_timestamp, "MEUCIQDspec==");
    }

    #[test]
    fn tlog_entry_deserializes_set_from_nested_verification_envelope_for_legacy_bundles() {
        // Legacy LPM bundles (published before the publish-side fix
        // that lifts Rekor's response into top-level fields) carry the
        // SET nested under `verification.inclusionPromise`. The
        // resolved accessor must transparently fall back through that
        // envelope so old bundles still verify.
        let json = serde_json::json!({
            "logIndex": "10",
            "logId": {"keyId": "kid"},
            "integratedTime": "1700000000",
            "verification": {
                "inclusionPromise": {
                    "signedEntryTimestamp": "MEUCIQDlegacy=="
                }
            },
            "canonicalizedBody": "body"
        });
        let entry: TlogEntry = serde_json::from_value(json).expect("legacy shape must deserialize");
        assert!(
            entry.inclusion_promise.is_none(),
            "top-level field should be absent on legacy bundles"
        );
        let promise = entry
            .resolved_inclusion_promise()
            .expect("resolved accessor must fall back through legacy `verification` envelope");
        assert_eq!(promise.signed_entry_timestamp, "MEUCIQDlegacy==");
    }

    #[test]
    fn tlog_entry_top_level_field_wins_when_both_shapes_present() {
        // Defensive: if a future signer emits both the spec-compliant
        // top-level field AND the legacy nested envelope (e.g. during
        // a migration window), the resolved accessor prefers the
        // spec-compliant top-level. Pins which authority the verifier
        // honours when the bundle is internally redundant.
        let json = serde_json::json!({
            "logIndex": "10",
            "logId": {"keyId": "kid"},
            "integratedTime": "1700000000",
            "inclusionPromise": {
                "signedEntryTimestamp": "MEUCIQDtop=="
            },
            "verification": {
                "inclusionPromise": {
                    "signedEntryTimestamp": "MEUCIQDnested=="
                }
            },
            "canonicalizedBody": "body"
        });
        let entry: TlogEntry = serde_json::from_value(json).unwrap();
        let promise = entry.resolved_inclusion_promise().unwrap();
        assert_eq!(
            promise.signed_entry_timestamp, "MEUCIQDtop==",
            "top-level (spec-compliant) field must win when both shapes are present"
        );
    }

    #[test]
    fn tlog_entry_resolves_inclusion_proof_via_both_shapes() {
        let spec_shape = serde_json::json!({
            "logIndex": "1",
            "logId": {"keyId": "k"},
            "integratedTime": "0",
            "inclusionProof": {
                "checkpoint": "ckpt",
                "hashes": ["a"],
                "logIndex": 1,
                "rootHash": "r",
                "treeSize": 2
            },
            "canonicalizedBody": "b"
        });
        let entry: TlogEntry = serde_json::from_value(spec_shape).unwrap();
        assert_eq!(entry.resolved_inclusion_proof().unwrap().tree_size, 2);

        let legacy_shape = serde_json::json!({
            "logIndex": "1",
            "logId": {"keyId": "k"},
            "integratedTime": "0",
            "verification": {
                "inclusionProof": {
                    "checkpoint": "ckpt",
                    "hashes": ["a"],
                    "logIndex": 1,
                    "rootHash": "r",
                    "treeSize": 99
                }
            },
            "canonicalizedBody": "b"
        });
        let entry: TlogEntry = serde_json::from_value(legacy_shape).unwrap();
        assert_eq!(entry.resolved_inclusion_proof().unwrap().tree_size, 99);
    }

    #[tokio::test]
    async fn bundle_persists_spec_compliant_top_level_inclusion_promise_and_proof() {
        // End-to-end: build a bundle through the publish flow and
        // assert the persisted TlogEntry shape is Sigstore Bundle v0.3
        // spec-compliant — top-level `inclusionPromise` /
        // `inclusionProof`, no `verification` envelope written.
        let server = MockServer::start().await;
        let body = serde_json::json!({
            "uuid": {
                "logIndex": 5,
                "integratedTime": 1700000000_i64,
                "logID": "log",
                "body": "b",
                "verification": {
                    "inclusionPromise": {
                        "signedEntryTimestamp": "MEUCIQDend=="
                    },
                    "inclusionProof": {
                        "checkpoint": "ckpt",
                        "hashes": ["a"],
                        "logIndex": 5,
                        "rootHash": "r",
                        "treeSize": 6
                    }
                }
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

        let json = serde_json::to_value(&entry).unwrap();
        let obj = json.as_object().unwrap();
        assert!(
            obj.contains_key("inclusionPromise"),
            "spec shape requires top-level inclusionPromise; got keys: {:?}",
            obj.keys().collect::<Vec<_>>()
        );
        assert!(
            obj.contains_key("inclusionProof"),
            "spec shape requires top-level inclusionProof"
        );
        assert!(
            !obj.contains_key("verification"),
            "publish path must not write Rekor's `verification` envelope to the bundle wire \
             format; lift its contents into the top-level fields instead"
        );
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
        let jwt = make_jwt(
            r#"{"sub":"user@example.com","iss":"https://token.actions.githubusercontent.com"}"#,
        );
        assert_eq!(extract_jwt_subject(&jwt).unwrap(), "user@example.com");
    }

    #[test]
    fn jwt_subject_handles_base64url_chars() {
        // Build a payload whose base64url encoding contains `-` and `_`.
        // The byte sequence below was chosen so that standard base64
        // would use `+` / `/`, forcing the URL-safe alphabet.
        let payload = "{\"sub\":\"\u{00fb}\u{00fe}~\",\"iss\":\"https://token.actions.githubusercontent.com\"}";
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
                let json = format!(
                    "{{\"sub\":\"{sub}\",\"iss\":\"https://token.actions.githubusercontent.com\"}}",
                );
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
        let jwt =
            make_jwt(r#"{"iss":"https://token.actions.githubusercontent.com","aud":"sigstore"}"#);
        let err = extract_jwt_subject(&jwt).expect_err("expected error");
        assert!(format!("{err}").contains("missing 'sub' claim"));
    }

    #[test]
    fn jwt_subject_rejects_non_string_sub_claim() {
        let jwt = make_jwt(r#"{"sub":42,"iss":"https://token.actions.githubusercontent.com"}"#);
        let err = extract_jwt_subject(&jwt).expect_err("expected error");
        // The current code path bails out via the same "missing 'sub'"
        // arm because `.as_str()` returns None for non-string values.
        // That's a documented contract: assert it explicitly.
        assert!(format!("{err}").contains("missing 'sub' claim"));
    }

    /// M1: a JWT with no `iss` claim must be refused even if the
    /// signature would have verified — defense-in-depth so that a
    /// future bug that bypassed Fulcio cannot trust the decoded sub.
    #[test]
    fn jwt_subject_rejects_missing_iss_claim() {
        let jwt = make_jwt(r#"{"sub":"ci@example.com"}"#);
        let err = extract_jwt_subject(&jwt).expect_err("expected error");
        assert!(
            format!("{err}").contains("missing 'iss' claim"),
            "expected missing-iss error, got: {err}",
        );
    }

    /// M1: an `iss` claim that is not in [`ALLOWED_OIDC_ISSUERS`] is
    /// refused. Pre-fix the function returned the unverified `sub`
    /// regardless of who issued the token.
    #[test]
    fn jwt_subject_rejects_unknown_issuer() {
        let jwt = make_jwt(r#"{"sub":"ci@example.com","iss":"https://attacker.example.com"}"#);
        let err = extract_jwt_subject(&jwt).expect_err("expected error");
        assert!(
            format!("{err}").contains("not in the allowlist"),
            "expected allowlist-rejection error, got: {err}",
        );
    }

    /// M1: the canonical GitHub Actions issuer passes the allowlist
    /// gate, end-to-end. Pinning this here keeps the prod-allowlist
    /// regression visible if the constant is ever silently widened.
    #[test]
    fn jwt_subject_accepts_canonical_github_actions_issuer() {
        let jwt = make_jwt(
            r#"{"sub":"repo:owner/repo:ref:refs/heads/main","iss":"https://token.actions.githubusercontent.com"}"#,
        );
        assert_eq!(
            extract_jwt_subject(&jwt).unwrap(),
            "repo:owner/repo:ref:refs/heads/main",
        );
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

        let endpoints = SigstoreEndpoints::for_test(fulcio.uri(), rekor.uri());
        let jwt = make_jwt(
            r#"{"sub":"ci@example.com","iss":"https://token.actions.githubusercontent.com"}"#,
        );

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

        let endpoints = SigstoreEndpoints::for_test(fulcio.uri(), rekor.uri());
        let jwt = make_jwt(r#"{"sub":"ci","iss":"https://token.actions.githubusercontent.com"}"#);

        let err = sign_and_record_with_endpoints(&jwt, b"{}", &endpoints)
            .await
            .expect_err("expected fulcio error to surface");
        assert!(format!("{err}").contains("503"));
    }

    // ─── Body-size cap on Fulcio / Rekor responses ────────────────

    #[tokio::test]
    async fn read_response_body_capped_accepts_payload_under_cap() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(match_path("/x"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(vec![b'a'; 1024]))
            .mount(&server)
            .await;

        let resp = reqwest::get(format!("{}/x", server.uri())).await.unwrap();
        let body = read_response_body_capped(resp, "Test").await.unwrap();
        assert_eq!(body.len(), 1024);
    }

    #[tokio::test]
    async fn read_response_body_capped_rejects_oversized_stream() {
        let server = MockServer::start().await;
        let oversized = vec![b'a'; SIGSTORE_RESPONSE_CAP_BYTES + 1024];
        Mock::given(method("GET"))
            .and(match_path("/x"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(oversized))
            .mount(&server)
            .await;

        let resp = reqwest::get(format!("{}/x", server.uri())).await.unwrap();
        let err = read_response_body_capped(resp, "Test")
            .await
            .expect_err("oversized body must be rejected");
        let msg = format!("{err}");
        // Either the pre-stream `Content-Length` check or the
        // mid-stream accumulator check must reject. Both error
        // messages contain "exceed".
        assert!(msg.contains("exceed"), "got: {msg}");
    }

    #[tokio::test]
    async fn read_response_body_capped_rejects_declared_oversized_content_length() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        // Bypass hyper to dodge its declared-vs-actual framing panic
        // when the response body doesn't match the declared length.
        // Send headers with a huge Content-Length and close — the
        // pre-stream cap rejects before reading any body.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let declared = SIGSTORE_RESPONSE_CAP_BYTES + 1;

        tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener.accept().await {
                let mut buf = [0u8; 1024];
                let _ = socket.read(&mut buf).await;
                let resp = format!(
                    "HTTP/1.1 200 OK\r\n\
                     Content-Length: {declared}\r\n\
                     Content-Type: application/octet-stream\r\n\
                     Connection: close\r\n\
                     \r\n",
                );
                let _ = socket.write_all(resp.as_bytes()).await;
                let _ = socket.shutdown().await;
            }
        });

        let resp = reqwest::get(format!("http://{addr}/")).await.unwrap();
        let err = read_response_body_capped(resp, "Test")
            .await
            .expect_err("declared oversized length must be rejected pre-stream");
        assert!(
            format!("{err}").contains("declared body length"),
            "got: {err}"
        );
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
