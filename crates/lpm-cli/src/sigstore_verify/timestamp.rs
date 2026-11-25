//! RFC 3161 signed timestamps from a bundle's `timestampVerificationData`.
//!
//! A timestamp authority signs the hash of the bundle's signature together
//! with the time it saw it. Rekor v2 entries carry no integrated time, so
//! such a timestamp is the only signed evidence of when the signature
//! existed, and the time the signing certificate must have been valid at.

use sha2::{Digest, Sha256, Sha384, Sha512};
use std::time::{Duration, SystemTime};
use x509_parser::extensions::ParsedExtension;
use x509_parser::prelude::{FromDer, X509Certificate};

use super::chain::{
    check_cert_validity_at, enforce_issuer_constraints, verify_chain_link, verify_ecdsa_prehash,
};
use super::der::{self, Element, Reader};
use super::{TimestampAuthority, VerifyError};

/// The most signed timestamps a bundle may carry.
pub(super) const MAX_SIGNED_TIMESTAMPS: usize = 32;

const CHECK: &str = "RFC 3161 timestamp";

const OID_SIGNED_DATA: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02];
const OID_TST_INFO: &[u8] = &[
    0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x10, 0x01, 0x04,
];
const OID_CONTENT_TYPE: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x03];
const OID_MESSAGE_DIGEST: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x04];
const OID_SHA1: &[u8] = &[0x2B, 0x0E, 0x03, 0x02, 0x1A];
const OID_SHA256: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];
const OID_SHA384: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02];
const OID_SHA512: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03];
const OID_EC_PUBLIC_KEY: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01];
const OID_ECDSA_WITH_SHA256: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02];
const OID_ECDSA_WITH_SHA384: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x03];
const OID_ECDSA_WITH_SHA512: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x04];

/// A timestamp that verified: the time a trusted authority signed for
/// the bundle's signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct VerifiedTimestamp {
    pub(super) time: SystemTime,
    /// The `uri` of the timestamp authority that signed it.
    pub(super) authority: String,
}

/// Verify each of a bundle's signed timestamps over `signature`, the
/// bundle's signature bytes, against `authorities`.
/// Returns those that verified; the others prove nothing and are skipped.
pub(super) fn verify_signed_timestamps(
    signed_timestamps: &[Vec<u8>],
    signature: &[u8],
    authorities: &[TimestampAuthority],
) -> Vec<VerifiedTimestamp> {
    let mut verified = Vec::with_capacity(signed_timestamps.len());
    for signed_timestamp in signed_timestamps {
        match verify_signed_timestamp(signed_timestamp, signature, authorities) {
            Ok(timestamp) => verified.push(timestamp),
            Err(error) => tracing::debug!(
                target: "lpm_cli::sigstore_verify",
                %error,
                "an RFC 3161 timestamp in the bundle did not verify",
            ),
        }
    }
    verified
}

/// Verify one `signedTimestamp`, a DER `TimeStampResp`, over `signature`.
///
/// It verifies when a trusted authority's certificate signed it, that
/// certificate is a timestamping-only end-entity certificate chaining to
/// the authority's trust anchor, every certificate on that path and the
/// authority's own validity window contain the signed time, and the
/// timestamp's message imprint is the hash of `signature`.
pub(super) fn verify_signed_timestamp(
    signed_timestamp: &[u8],
    signature: &[u8],
    authorities: &[TimestampAuthority],
) -> Result<VerifiedTimestamp, VerifyError> {
    let token = parse_response(signed_timestamp).map_err(VerifyError::Timestamp)?;
    let info = parse_tst_info(token.tst_info).map_err(VerifyError::Timestamp)?;
    if info.imprint_hash.digest(signature) != info.hashed_message {
        return Err(VerifyError::Timestamp(
            "its message imprint is not the hash of the bundle's signature".into(),
        ));
    }

    let mut failures = Vec::new();
    for authority in authorities {
        match verify_with_authority(&token, &info, authority) {
            Ok(()) => {
                return Ok(VerifiedTimestamp {
                    time: info.gen_time,
                    authority: authority.uri.clone(),
                });
            }
            Err(AuthorityRejection::NotTheSigner) => {}
            Err(AuthorityRejection::Failed(why)) => {
                failures.push(format!("{}: {why}", authority_label(authority)));
            }
        }
    }
    if failures.is_empty() {
        Err(VerifyError::MissingTrustMaterial {
            check: CHECK,
            detail: "no timestamp authority in the trust root holds the certificate that \
                     signed it"
                .into(),
        })
    } else {
        Err(VerifyError::Timestamp(failures.join("; ")))
    }
}

fn authority_label(authority: &TimestampAuthority) -> &str {
    if authority.uri.is_empty() {
        "timestamp authority"
    } else {
        &authority.uri
    }
}

enum AuthorityRejection {
    /// The authority holds no certificate matching the timestamp's signer.
    NotTheSigner,
    Failed(String),
}

fn verify_with_authority(
    token: &TimestampToken<'_>,
    info: &TstInfo,
    authority: &TimestampAuthority,
) -> Result<(), AuthorityRejection> {
    let mut chain = Vec::with_capacity(authority.cert_chain_der.len());
    for (index, der) in authority.cert_chain_der.iter().enumerate() {
        let (_, cert) = X509Certificate::from_der(der).map_err(|e| {
            AuthorityRejection::Failed(format!(
                "trust root certificate {index} is not valid DER X.509: {e}"
            ))
        })?;
        chain.push(cert);
    }
    let Some(first) = chain.first() else {
        return Err(AuthorityRejection::NotTheSigner);
    };

    // A chain that starts with an end-entity certificate pins the signing
    // certificate; otherwise the timestamp must carry it.
    let embedded: Vec<X509Certificate<'_>>;
    let (signer, issuers) = if is_ca(first) {
        embedded = token
            .certificates
            .iter()
            .filter_map(|der| X509Certificate::from_der(der).ok().map(|(_, cert)| cert))
            .collect();
        let signer = embedded
            .iter()
            .find(|cert| token.signer.id.matches(cert))
            .ok_or(AuthorityRejection::NotTheSigner)?;
        (signer, chain.as_slice())
    } else if token.signer.id.matches(first) {
        (first, &chain[1..])
    } else {
        return Err(AuthorityRejection::NotTheSigner);
    };

    verify_signer_signature(token, signer).map_err(AuthorityRejection::Failed)?;
    enforce_timestamping_leaf(signer).map_err(AuthorityRejection::Failed)?;

    if !authority.valid_for.contains(info.gen_time) {
        return Err(AuthorityRejection::Failed(format!(
            "its time {} is outside the authority's validity window in the trust root",
            lpm_common::Timestamp::from(info.gen_time).to_rfc3339()
        )));
    }

    let at_time = lpm_common::Timestamp::from(info.gen_time);
    let failed = |error: VerifyError| AuthorityRejection::Failed(error.to_string());
    check_cert_validity_at(signer, at_time, "timestamp signing certificate").map_err(failed)?;
    let mut child = signer;
    for (index, issuer) in issuers.iter().enumerate() {
        let label = format!("timestamp authority certificate {index}");
        check_cert_validity_at(issuer, at_time, &label).map_err(failed)?;
        enforce_issuer_constraints(issuer, index, &label).map_err(failed)?;
        if index + 1 < issuers.len() {
            enforce_timestamping_intermediate(issuer).map_err(AuthorityRejection::Failed)?;
        }
        verify_chain_link(child, issuer, &label).map_err(failed)?;
        child = issuer;
    }
    Ok(())
}

fn is_ca(cert: &X509Certificate<'_>) -> bool {
    matches!(cert.basic_constraints(), Ok(Some(constraints)) if constraints.value.ca)
}

fn verify_signer_signature(
    token: &TimestampToken<'_>,
    signer: &X509Certificate<'_>,
) -> Result<(), String> {
    match token.signer.signature_algorithm {
        SignatureAlgorithm::Ecdsa(hash) if hash == token.signer.digest => {}
        SignatureAlgorithm::Ecdsa(_) => {
            return Err(
                "its signature algorithm hashes with a different algorithm than its \
                        digest algorithm"
                    .into(),
            );
        }
        SignatureAlgorithm::Other => {
            return Err("it is not signed with ECDSA, the only algorithm supported".into());
        }
    }
    let signed = der::encode_set(token.signer.signed_attributes);
    let digest = token.signer.digest.digest(&signed);
    verify_ecdsa_prehash(signer.public_key().raw, &digest, token.signer.signature)
        .map_err(|why| format!("its CMS signature: {why}"))
}

/// RFC 3161 §2.3: the signing certificate is an end-entity certificate
/// whose only extended key usage, marked critical, is timestamping.
fn enforce_timestamping_leaf(cert: &X509Certificate<'_>) -> Result<(), String> {
    if is_ca(cert) {
        return Err("its signing certificate is a CA certificate".into());
    }
    let key_usage = cert
        .key_usage()
        .map_err(|e| format!("its signing certificate's key usage is malformed: {e}"))?;
    if let Some(key_usage) = key_usage
        && !key_usage.value.digital_signature()
        && !key_usage.value.non_repudiation()
    {
        return Err("its signing certificate's key usage does not allow signing".into());
    }
    let extended = cert
        .extended_key_usage()
        .map_err(|e| format!("its signing certificate's extended key usage is malformed: {e}"))?
        .ok_or("its signing certificate has no extended key usage")?;
    if !extended.critical {
        return Err("its signing certificate's extended key usage is not critical".into());
    }
    let usage = extended.value;
    let purposes = [
        usage.any,
        usage.server_auth,
        usage.client_auth,
        usage.code_signing,
        usage.email_protection,
        usage.time_stamping,
        usage.ocsp_signing,
    ]
    .into_iter()
    .filter(|&set| set)
    .count()
        + usage.other.len();
    if !usage.time_stamping || purposes != 1 {
        return Err(
            "its signing certificate's extended key usage is not timestamping alone".into(),
        );
    }
    Ok(())
}

/// An intermediate between the signing certificate and the trust anchor
/// either doesn't restrict its extended key usage or allows timestamping.
fn enforce_timestamping_intermediate(cert: &X509Certificate<'_>) -> Result<(), String> {
    let extended = cert
        .extended_key_usage()
        .map_err(|e| format!("an intermediate's extended key usage is malformed: {e}"))?;
    match extended {
        Some(extended) if !extended.value.time_stamping && !extended.value.any => {
            Err("an intermediate certificate does not allow timestamping".into())
        }
        _ => Ok(()),
    }
}

// ─── Parsing ─────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HashAlgorithm {
    Sha256,
    Sha384,
    Sha512,
}

impl HashAlgorithm {
    fn digest(self, data: &[u8]) -> Vec<u8> {
        match self {
            Self::Sha256 => Sha256::digest(data).to_vec(),
            Self::Sha384 => Sha384::digest(data).to_vec(),
            Self::Sha512 => Sha512::digest(data).to_vec(),
        }
    }

    fn from_oid(oid: &[u8], what: &str) -> Result<Self, String> {
        match oid {
            OID_SHA256 => Ok(Self::Sha256),
            OID_SHA384 => Ok(Self::Sha384),
            OID_SHA512 => Ok(Self::Sha512),
            OID_SHA1 => Err(format!("{what} uses SHA-1, which is not accepted")),
            _ => Err(format!("{what} uses an unsupported hash algorithm")),
        }
    }

    /// An `AlgorithmIdentifier` naming a hash, with its parameters absent
    /// or NULL.
    fn from_algorithm_identifier(element: &Element<'_>, what: &str) -> Result<Self, String> {
        let mut identifier = algorithm_identifier(element, what)?;
        let algorithm = Self::from_oid(identifier.oid, what)?;
        if let Some(null) = identifier.parameters.optional(der::TAG_NULL)?
            && !null.contents.is_empty()
        {
            return Err(format!("{what} has malformed parameters"));
        }
        identifier.parameters.finish(what)?;
        Ok(algorithm)
    }
}

struct AlgorithmIdentifier<'a> {
    oid: &'a [u8],
    parameters: Reader<'a>,
}

fn algorithm_identifier<'a>(
    element: &Element<'a>,
    what: &str,
) -> Result<AlgorithmIdentifier<'a>, String> {
    if element.tag != der::TAG_SEQUENCE {
        return Err(format!("{what} is not an AlgorithmIdentifier"));
    }
    let mut reader = Reader::new(element.contents);
    let oid = reader.expect(der::TAG_OID, what)?.contents;
    Ok(AlgorithmIdentifier {
        oid,
        parameters: reader,
    })
}

struct TimestampToken<'a> {
    /// The DER `TSTInfo` the signer signed.
    tst_info: &'a [u8],
    /// Certificates the timestamp carries, DER-encoded.
    certificates: Vec<&'a [u8]>,
    signer: SignerInfo<'a>,
}

struct SignerInfo<'a> {
    id: SignerId<'a>,
    digest: HashAlgorithm,
    signature_algorithm: SignatureAlgorithm,
    /// The contents of the signed attributes, which the signature covers
    /// encoded as a SET OF.
    signed_attributes: &'a [u8],
    /// The value of the message digest signed attribute.
    message_digest: &'a [u8],
    signature: &'a [u8],
}

/// Judged once a trusted certificate matches the signer, so a timestamp
/// from an authority outside the trust root reads as such whatever it
/// signs with.
enum SignatureAlgorithm {
    Ecdsa(HashAlgorithm),
    Other,
}

enum SignerId<'a> {
    IssuerAndSerialNumber {
        /// The encoded issuer `Name`.
        issuer: &'a [u8],
        /// The contents of the serial number INTEGER.
        serial: &'a [u8],
    },
    SubjectKeyIdentifier(&'a [u8]),
}

impl SignerId<'_> {
    fn matches(&self, cert: &X509Certificate<'_>) -> bool {
        match self {
            Self::IssuerAndSerialNumber { issuer, serial } => {
                cert.tbs_certificate.issuer.as_raw() == *issuer
                    && cert.tbs_certificate.raw_serial() == *serial
            }
            Self::SubjectKeyIdentifier(key_id) => cert.extensions().iter().any(|extension| {
                matches!(
                    extension.parsed_extension(),
                    ParsedExtension::SubjectKeyIdentifier(id) if id.0 == *key_id
                )
            }),
        }
    }
}

/// `TimeStampResp` (RFC 3161 §2.4.2) down to the one `SignerInfo` of its
/// `SignedData` (RFC 5652 §5).
fn parse_response(bytes: &[u8]) -> Result<TimestampToken<'_>, String> {
    let mut outer = Reader::new(bytes);
    let mut response = outer.nested(der::TAG_SEQUENCE, "the TimeStampResp")?;
    outer.finish("the TimeStampResp")?;

    let mut status_info = response.nested(der::TAG_SEQUENCE, "the PKIStatusInfo")?;
    let status = der::small_unsigned(
        &status_info.expect(der::TAG_INTEGER, "the PKIStatus")?,
        "the PKIStatus",
    )?;
    while !status_info.is_empty() {
        status_info.element()?;
    }
    // 0 is granted and 1 granted with modifications.
    if status > 1 {
        return Err(format!(
            "the timestamp authority did not grant it (status {status})"
        ));
    }
    if response.is_empty() {
        return Err("the TimeStampResp carries no timestamp token".into());
    }
    let mut content_info = response.nested(der::TAG_SEQUENCE, "the TimeStampToken")?;
    response.finish("the TimeStampResp")?;

    if content_info
        .expect(der::TAG_OID, "the token's content type")?
        .contents
        != OID_SIGNED_DATA
    {
        return Err("the timestamp token is not CMS SignedData".into());
    }
    let mut explicit = content_info.nested(der::context_constructed(0), "the token's content")?;
    content_info.finish("the TimeStampToken")?;
    let mut signed_data = explicit.nested(der::TAG_SEQUENCE, "the SignedData")?;
    explicit.finish("the token's content")?;

    let version = der::small_unsigned(
        &signed_data.expect(der::TAG_INTEGER, "the SignedData version")?,
        "the SignedData version",
    )?;
    if version != 3 {
        return Err(format!(
            "the SignedData version is {version} where a timestamp token's is 3"
        ));
    }
    signed_data.expect(der::TAG_SET, "the SignedData digest algorithms")?;

    let mut encapsulated = signed_data.nested(der::TAG_SEQUENCE, "the encapsulated content")?;
    if encapsulated
        .expect(der::TAG_OID, "the encapsulated content type")?
        .contents
        != OID_TST_INFO
    {
        return Err("the token's content is not a TSTInfo".into());
    }
    let mut content =
        encapsulated.nested(der::context_constructed(0), "the encapsulated content")?;
    let tst_info = content
        .expect(der::TAG_OCTET_STRING, "the encapsulated TSTInfo")?
        .contents;
    content.finish("the encapsulated content")?;
    encapsulated.finish("the encapsulated content")?;

    let mut certificates = Vec::new();
    if let Some(set) = signed_data.optional(der::context_constructed(0))? {
        let mut choices = Reader::new(set.contents);
        while !choices.is_empty() {
            let choice = choices.element()?;
            // Other CertificateChoices (attribute or other certificates)
            // can't sign a timestamp.
            if choice.tag == der::TAG_SEQUENCE {
                certificates.push(choice.encoded);
            }
        }
    }
    signed_data.optional(der::context_constructed(1))?;

    let mut signer_infos = signed_data.nested(der::TAG_SET, "the SignerInfos")?;
    signed_data.finish("the SignedData")?;
    if signer_infos.is_empty() {
        return Err("the timestamp token has no signer".into());
    }
    let signer = parse_signer_info(
        signer_infos
            .expect(der::TAG_SEQUENCE, "the SignerInfo")?
            .contents,
    )?;
    if !signer_infos.is_empty() {
        return Err("the timestamp token has more than one signer".into());
    }
    if signer.digest.digest(tst_info) != signer.message_digest {
        return Err("the signed message digest is not the digest of its TSTInfo".into());
    }

    Ok(TimestampToken {
        tst_info,
        certificates,
        signer,
    })
}

fn parse_signer_info(contents: &[u8]) -> Result<SignerInfo<'_>, String> {
    let mut signer = Reader::new(contents);
    let version = der::small_unsigned(
        &signer.expect(der::TAG_INTEGER, "the SignerInfo version")?,
        "the SignerInfo version",
    )?;
    let id = if signer.peek_tag() == Some(der::TAG_SEQUENCE) {
        let mut issuer_and_serial = signer.nested(der::TAG_SEQUENCE, "the signer's identifier")?;
        let issuer = issuer_and_serial
            .expect(der::TAG_SEQUENCE, "the signer's issuer")?
            .encoded;
        let serial =
            der::integer_contents(&issuer_and_serial.element()?, "the signer's serial number")?;
        issuer_and_serial.finish("the signer's identifier")?;
        if version != 1 {
            return Err(format!(
                "the SignerInfo version is {version} where an issuer and serial number \
                 identifier's is 1"
            ));
        }
        SignerId::IssuerAndSerialNumber { issuer, serial }
    } else {
        let key_id = signer
            .expect(der::context_primitive(0), "the signer's identifier")?
            .contents;
        if version != 3 {
            return Err(format!(
                "the SignerInfo version is {version} where a subject key identifier's is 3"
            ));
        }
        SignerId::SubjectKeyIdentifier(key_id)
    };

    let digest = HashAlgorithm::from_algorithm_identifier(
        &signer.element()?,
        "the signer's digest algorithm",
    )?;
    if signer.peek_tag() != Some(der::context_constructed(0)) {
        return Err("the SignerInfo has no signed attributes".into());
    }
    let signed_attributes = signer.element()?.contents;
    let signature_algorithm = signature_algorithm(&signer.element()?, digest)?;
    let signature = signer
        .expect(der::TAG_OCTET_STRING, "the signer's signature")?
        .contents;
    signer.optional(der::context_constructed(1))?;
    signer.finish("the SignerInfo")?;

    let message_digest = signed_message_digest(signed_attributes)?;
    Ok(SignerInfo {
        id,
        digest,
        signature_algorithm,
        signed_attributes,
        message_digest,
        signature,
    })
}

fn signature_algorithm(
    element: &Element<'_>,
    digest: HashAlgorithm,
) -> Result<SignatureAlgorithm, String> {
    let identifier = algorithm_identifier(element, "the signer's signature algorithm")?;
    Ok(match identifier.oid {
        OID_ECDSA_WITH_SHA256 => SignatureAlgorithm::Ecdsa(HashAlgorithm::Sha256),
        OID_ECDSA_WITH_SHA384 => SignatureAlgorithm::Ecdsa(HashAlgorithm::Sha384),
        OID_ECDSA_WITH_SHA512 => SignatureAlgorithm::Ecdsa(HashAlgorithm::Sha512),
        OID_EC_PUBLIC_KEY => SignatureAlgorithm::Ecdsa(digest),
        _ => SignatureAlgorithm::Other,
    })
}

/// The content type and message digest attributes RFC 5652 §5.3 requires,
/// each present once with one value, with the content type naming a
/// TSTInfo. Returns the message digest.
fn signed_message_digest(contents: &[u8]) -> Result<&[u8], String> {
    let mut attributes = Reader::new(contents);
    let mut content_type: Option<&[u8]> = None;
    let mut message_digest: Option<&[u8]> = None;
    while !attributes.is_empty() {
        let mut attribute = attributes.nested(der::TAG_SEQUENCE, "a signed attribute")?;
        let oid = attribute
            .expect(der::TAG_OID, "a signed attribute's type")?
            .contents;
        let mut values = attribute.nested(der::TAG_SET, "a signed attribute's values")?;
        attribute.finish("a signed attribute")?;
        let (slot, tag, name) = match oid {
            OID_CONTENT_TYPE => (&mut content_type, der::TAG_OID, "content type"),
            OID_MESSAGE_DIGEST => (&mut message_digest, der::TAG_OCTET_STRING, "message digest"),
            _ => continue,
        };
        let value = values.expect(tag, name)?.contents;
        values.finish(name)?;
        if slot.replace(value).is_some() {
            return Err(format!(
                "the {name} signed attribute appears more than once"
            ));
        }
    }
    if content_type.ok_or("the signed attributes carry no content type")? != OID_TST_INFO {
        return Err("the signed content type is not a TSTInfo".into());
    }
    message_digest.ok_or_else(|| "the signed attributes carry no message digest".into())
}

struct TstInfo {
    imprint_hash: HashAlgorithm,
    hashed_message: Vec<u8>,
    gen_time: SystemTime,
}

/// `TSTInfo` (RFC 3161 §2.4.2).
fn parse_tst_info(bytes: &[u8]) -> Result<TstInfo, String> {
    let mut outer = Reader::new(bytes);
    let mut info = outer.nested(der::TAG_SEQUENCE, "the TSTInfo")?;
    outer.finish("the TSTInfo")?;

    let version = der::small_unsigned(
        &info.expect(der::TAG_INTEGER, "the TSTInfo version")?,
        "the TSTInfo version",
    )?;
    if version != 1 {
        return Err(format!(
            "the TSTInfo version is {version} where 1 is expected"
        ));
    }
    info.expect(der::TAG_OID, "the TSTInfo policy")?;
    let mut imprint = info.nested(der::TAG_SEQUENCE, "the message imprint")?;
    let imprint_hash =
        HashAlgorithm::from_algorithm_identifier(&imprint.element()?, "the message imprint")?;
    let hashed_message = imprint
        .expect(der::TAG_OCTET_STRING, "the message imprint's hash")?
        .contents
        .to_vec();
    imprint.finish("the message imprint")?;
    der::integer_contents(&info.element()?, "the TSTInfo serial number")?;
    let gen_time = parse_generalized_time(
        info.expect(der::TAG_GENERALIZED_TIME, "the TSTInfo time")?
            .contents,
    )?;
    info.optional(der::TAG_SEQUENCE)?;
    info.optional(der::TAG_BOOLEAN)?;
    info.optional(der::TAG_INTEGER)?;
    info.optional(der::context_constructed(0))?;
    info.optional(der::context_constructed(1))?;
    info.finish("the TSTInfo")?;

    Ok(TstInfo {
        imprint_hash,
        hashed_message,
        gen_time,
    })
}

/// A DER `GeneralizedTime`: `YYYYMMDDHHMMSS`, an optional fraction of a
/// second without trailing zeros, then `Z`.
fn parse_generalized_time(bytes: &[u8]) -> Result<SystemTime, String> {
    const WHAT: &str = "the TSTInfo time";
    let text = std::str::from_utf8(bytes).map_err(|_| format!("{WHAT} is not ASCII"))?;
    let body = text
        .strip_suffix('Z')
        .ok_or_else(|| format!("{WHAT} `{text}` is not in UTC"))?;
    let (whole, fraction) = match body.split_once('.') {
        Some((whole, fraction)) => (whole, Some(fraction)),
        None => (body, None),
    };
    if whole.len() != 14 || !whole.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(format!("{WHAT} `{text}` is malformed"));
    }
    let field = |range: std::ops::Range<usize>| -> u32 {
        whole[range]
            .bytes()
            .fold(0, |value, digit| value * 10 + u32::from(digit - b'0'))
    };
    let (year, month, day) = (field(0..4), field(4..6), field(6..8));
    let (hour, minute, second) = (field(8..10), field(10..12), field(12..14));
    if !(1..=12).contains(&month)
        || day == 0
        || day > days_in_month(year, month)
        || hour > 23
        || minute > 59
        || second > 59
    {
        return Err(format!("{WHAT} `{text}` is not a valid time"));
    }
    let nanos = match fraction {
        None => 0,
        Some(fraction) => {
            if fraction.is_empty()
                || fraction.ends_with('0')
                || !fraction.bytes().all(|byte| byte.is_ascii_digit())
            {
                return Err(format!("{WHAT} `{text}` has a malformed fraction"));
            }
            let mut nanos = 0u32;
            for (place, digit) in fraction.bytes().take(9).enumerate() {
                nanos += u32::from(digit - b'0') * 10u32.pow(8 - place as u32);
            }
            nanos
        }
    };
    let days = days_from_civil(year, month, day);
    let seconds = days * 86_400 + i64::from(hour * 3600 + minute * 60 + second);
    let seconds = u64::try_from(seconds).map_err(|_| format!("{WHAT} `{text}` is before 1970"))?;
    Ok(SystemTime::UNIX_EPOCH + Duration::new(seconds, nanos))
}

fn days_in_month(year: u32, month: u32) -> u32 {
    match month {
        2 if (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400) => {
            29
        }
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

/// Days from 1970-01-01 to a proleptic Gregorian date.
fn days_from_civil(year: u32, month: u32, day: u32) -> i64 {
    let year = i64::from(year) - i64::from(month <= 2);
    let era = year.div_euclid(400);
    let year_of_era = year - era * 400;
    let month = i64::from(month);
    let day_of_year = (153 * (month + if month > 2 { -3 } else { 9 }) + 2) / 5 + i64::from(day) - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}
