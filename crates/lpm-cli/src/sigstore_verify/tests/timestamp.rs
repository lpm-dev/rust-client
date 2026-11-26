//! RFC 3161 signed timestamps: Sigstore's conformance cases for the
//! shapes real timestamp authorities produce, and synthesized tokens for
//! the refusals those cases don't reach.

use super::super::der;
use super::super::timestamp::{
    VerifiedTimestamp, verify_signed_timestamp, verify_signed_timestamps,
};
use super::super::trust_root::ValidityWindow;
use super::super::{
    IdentityExpectations, TimestampAuthority, TrustRoot, VerifyError, VerifyOptions,
    bundle::verify_sigstore_bundle_with,
};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use ecdsa::signature::hazmat::PrehashSigner;
use lpm_common::Timestamp;
use p384::pkcs8::DecodePrivateKey;
use rcgen::{CertificateParams, CustomExtension, IsCa, KeyPair, KeyUsagePurpose};
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::time::SystemTime;
use x509_parser::prelude::{FromDer, X509Certificate};

fn conformance_file(case: &str, file: &str) -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/sigstore_conformance")
        .join(case)
        .join(file);
    std::fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

struct ConformanceTimestamp {
    signature: Vec<u8>,
    signed_timestamp: Vec<u8>,
    trust: TrustRoot,
}

/// A message-signature conformance bundle's signature and first
/// timestamp, with the case's trust root.
fn conformance_timestamp(case: &str) -> ConformanceTimestamp {
    let bundle: serde_json::Value =
        serde_json::from_slice(&conformance_file(case, "bundle.sigstore.json")).unwrap();
    let signature = BASE64
        .decode(bundle["messageSignature"]["signature"].as_str().unwrap())
        .unwrap();
    let signed_timestamp =
        BASE64
            .decode(
                bundle["verificationMaterial"]["timestampVerificationData"]["rfc3161Timestamps"][0]
                    ["signedTimestamp"]
                    .as_str()
                    .unwrap(),
            )
            .unwrap();
    let trust = TrustRoot::parse(&conformance_file(case, "trusted_root.json")).unwrap();
    ConformanceTimestamp {
        signature,
        signed_timestamp,
        trust,
    }
}

fn verify_conformance_case(case: &str) -> Result<VerifiedTimestamp, VerifyError> {
    let case = conformance_timestamp(case);
    verify_signed_timestamp(
        &case.signed_timestamp,
        &case.signature,
        &case.trust.timestamp_authorities,
    )
}

fn rfc3339(time: SystemTime) -> String {
    Timestamp::from(time).to_rfc3339_seconds()
}

#[test]
fn sigstores_timestamp_authority_shapes_verify() {
    let cases = [
        ("rekor2-happy-path", "2025-06-12T12:02:20Z"),
        (
            "rekor2-timestamp-with-embedded-cert",
            "2025-08-06T18:51:36Z",
        ),
        (
            "rekor2-timestamp-without-embedded-cert",
            "2025-08-06T19:03:51Z",
        ),
    ];
    for (case, expected) in cases {
        let verified = verify_conformance_case(case).unwrap_or_else(|e| panic!("{case}: {e}"));
        assert_eq!(rfc3339(verified.time), expected, "{case}");
        assert_eq!(
            verified.authority, "https://timestamp.sigstage.dev/api/v1/timestamp",
            "{case}"
        );
    }
}

#[test]
fn a_timestamp_verifies_after_its_authoritys_certificates_expire() {
    // The chain expired minutes after it signed; the signed time is what
    // the certificates must contain, not the current time.
    let verified = verify_conformance_case("rekor2-timestamp-with-expired-cert-chain").unwrap();
    assert!(verified.time < SystemTime::now());
}

#[test]
fn a_timestamp_at_the_end_of_its_authoritys_validity_window_verifies() {
    let verified = verify_conformance_case("trust-root-tsa-validity-end-inclusive").unwrap();
    assert_eq!(rfc3339(verified.time), "2025-06-12T12:02:20Z");
}

#[test]
fn a_timestamp_after_its_authoritys_validity_window_needs_newer_trust_material() {
    // As for the other roles' keys, a newer trust root may move the window.
    let refused = verify_conformance_case("rekor2-timestamp-outside-trust-root-tsa-validity_fail")
        .unwrap_err();
    assert!(
        matches!(
            &refused,
            VerifyError::MissingTrustMaterial { check: "RFC 3161 timestamp", detail }
                if detail.contains("validity window in the trust root")
        ),
        "{refused:?}"
    );
}

#[test]
fn a_timestamp_outside_its_signing_certificates_lifetime_is_refused() {
    let refused =
        verify_conformance_case("rekor2-timestamp-outside-tsa-cert-validity_fail").unwrap_err();
    assert!(
        matches!(&refused, VerifyError::Timestamp(why) if why.contains("does not contain the signing time")),
        "{refused:?}"
    );
}

#[test]
fn a_timestamp_over_a_different_signature_is_refused() {
    let refused = verify_conformance_case("rekor2-timestamp-payload-mismatch_fail").unwrap_err();
    assert!(
        matches!(&refused, VerifyError::Timestamp(why) if why.contains("message imprint")),
        "{refused:?}"
    );
}

#[test]
fn a_timestamp_from_an_authority_outside_the_trust_root_needs_newer_trust_material() {
    for case in [
        "rekor2-timestamp-untrusted-tsa-with-embedded-cert_fail",
        "rekor2-timestamp-untrusted-tsa-without-embedded-cert_fail",
    ] {
        let refused = verify_conformance_case(case).unwrap_err();
        assert!(
            matches!(
                &refused,
                VerifyError::MissingTrustMaterial {
                    check: "RFC 3161 timestamp",
                    ..
                }
            ),
            "{case}: {refused:?}"
        );
        assert!(refused.is_missing_trust_material(), "{case}");
    }
}

#[test]
fn a_bundle_timestamped_outside_its_certificates_lifetime_is_refused() {
    // A Rekor v1 bundle whose log entry is otherwise valid: the timestamp
    // it also carries is a signed time the certificate wasn't valid at.
    let case = "intoto-tsa-timestamp-outside-cert-validity_fail";
    let trust = TrustRoot::parse(&conformance_file(case, "trusted_root.json")).unwrap();
    let refused = verify_sigstore_bundle_with(
        &conformance_file(case, "bundle.sigstore.json"),
        &IdentityExpectations::none(),
        VerifyOptions::npm_attestation(),
        &trust,
    )
    .unwrap_err();
    assert!(
        matches!(&refused, VerifyError::Chain(why) if why.contains("does not contain the signing time")),
        "{refused:?}"
    );
}

#[test]
fn a_proof_only_rekor_v1_entry_naming_no_log_is_malformed() {
    let case = "intoto-with-custom-trust-root";
    let trust = TrustRoot::parse(&conformance_file(case, "trusted_root.json")).unwrap();
    let mut bundle: serde_json::Value =
        serde_json::from_slice(&conformance_file(case, "bundle.sigstore.json")).unwrap();
    let entry = bundle["verificationMaterial"]["tlogEntries"][0]
        .as_object_mut()
        .unwrap();
    entry.remove("inclusionPromise");
    entry.insert("logId".into(), serde_json::json!({}));
    let refused = verify_sigstore_bundle_with(
        &serde_json::to_vec(&bundle).unwrap(),
        &IdentityExpectations::none(),
        VerifyOptions::npm_attestation(),
        &trust,
    )
    .unwrap_err();
    assert!(
        matches!(&refused, VerifyError::InclusionProof(why)
            if why.contains("names no log") && !why.contains("SET")),
        "{refused:?}"
    );
}

// ─── Synthesized timestamp tokens ────────────────────────────────

const OID_SIGNED_DATA: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02];
const OID_TST_INFO: &[u8] = &[
    0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x10, 0x01, 0x04,
];
const OID_CONTENT_TYPE: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x03];
const OID_MESSAGE_DIGEST: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x04];
const OID_SHA1: &[u8] = &[0x2B, 0x0E, 0x03, 0x02, 0x1A];
const OID_SHA256: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];
const OID_SHA384: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02];
const OID_EC_PUBLIC_KEY: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01];
const OID_ECDSA_WITH_SHA384: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x03];
const OID_RSA_WITH_SHA256: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B];
const OID_ECDSA_WITH_SHA256: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02];
const OID_SIGSTORE_TSA_POLICY: &[u8] = &[0x2B, 0x06, 0x01, 0x04, 0x01, 0x83, 0xBF, 0x30, 0x02];
const OID_TIME_STAMPING: &[u64] = &[1, 3, 6, 1, 5, 5, 7, 3, 8];
const OID_CODE_SIGNING: &[u64] = &[1, 3, 6, 1, 5, 5, 7, 3, 3];

const SIGNATURE: &[u8] = b"the bundle's signature";

fn tlv(tag: u8, parts: &[&[u8]]) -> Vec<u8> {
    let contents = parts.concat();
    let mut encoded = vec![tag];
    encoded.extend(der::encode_length(contents.len()));
    encoded.extend(contents);
    encoded
}

fn oid(contents: &[u8]) -> Vec<u8> {
    tlv(der::TAG_OID, &[contents])
}

fn algorithm(oid_contents: &[u8]) -> Vec<u8> {
    tlv(der::TAG_SEQUENCE, &[&oid(oid_contents)])
}

fn integer(value: u8) -> Vec<u8> {
    tlv(der::TAG_INTEGER, &[&[value]])
}

/// An extended key usage extension naming `purposes`.
fn extended_key_usage(purposes: &[&[u64]], critical: bool) -> CustomExtension {
    let encoded: Vec<Vec<u8>> = purposes
        .iter()
        .map(|purpose| {
            let parsed = x509_parser::der_parser::oid::Oid::from(purpose).unwrap();
            oid(parsed.as_bytes())
        })
        .collect();
    let refs: Vec<&[u8]> = encoded.iter().map(Vec::as_slice).collect();
    let mut extension =
        CustomExtension::from_oid_content(&[2, 5, 29, 37], tlv(der::TAG_SEQUENCE, &refs));
    extension.set_criticality(critical);
    extension
}

struct TestAuthority {
    root_der: Vec<u8>,
    intermediate_der: Option<Vec<u8>>,
    leaf_der: Vec<u8>,
    leaf_key: p384::ecdsa::SigningKey,
    leaf_keypair: KeyPair,
    /// The certificate and key that issued the leaf.
    issuer_cert: rcgen::Certificate,
    issuer_key: KeyPair,
    root_cert: rcgen::Certificate,
    root_key: KeyPair,
}

fn validity(not_before: (i32, u8, u8), not_after: (i32, u8, u8)) -> CertificateParams {
    let mut params = CertificateParams::default();
    params.not_before = rcgen::date_time_ymd(not_before.0, not_before.1, not_before.2);
    params.not_after = rcgen::date_time_ymd(not_after.0, not_after.1, not_after.2);
    params
}

fn ca_params(name: &str, path_len: u8) -> CertificateParams {
    let mut params = validity((2020, 1, 1), (2040, 1, 1));
    params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Constrained(path_len));
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, name);
    params
}

/// A timestamping leaf; without `serial`, rcgen derives one from the key.
fn timestamping_leaf_params(serial: Option<u64>) -> CertificateParams {
    let mut params = validity((2021, 1, 1), (2039, 1, 1));
    params.is_ca = IsCa::ExplicitNoCa;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.custom_extensions = vec![extended_key_usage(&[OID_TIME_STAMPING], true)];
    params.serial_number = serial.map(rcgen::SerialNumber::from);
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "test-tsa");
    params
}

/// A timestamp authority with a P-384 root and a leaf whose profile
/// `customize_leaf` may change from a valid timestamping certificate.
fn test_authority(customize_leaf: impl FnOnce(&mut CertificateParams)) -> TestAuthority {
    authority_with(false, customize_leaf)
}

/// [`test_authority`], with an intermediate between the root and the leaf
/// when `intermediate` is set.
fn authority_with(
    intermediate: bool,
    customize_leaf: impl FnOnce(&mut CertificateParams),
) -> TestAuthority {
    authority_with_intermediate(
        intermediate.then_some(|_: &mut CertificateParams| {}),
        customize_leaf,
    )
}

fn authority_with_intermediate(
    customize_intermediate: Option<impl FnOnce(&mut CertificateParams)>,
    customize_leaf: impl FnOnce(&mut CertificateParams),
) -> TestAuthority {
    let root_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap();
    let root = ca_params("test-tsa-root", 1)
        .self_signed(&root_key)
        .unwrap();
    let root_der = root.der().to_vec();
    let root_key_copy = KeyPair::try_from(root_key.serialize_der().as_slice()).unwrap();
    let root_cert = root.clone();
    let (intermediate_der, issuer_cert, issuer_key) =
        if let Some(customize) = customize_intermediate {
            let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap();
            let root_issuer = rcgen::Issuer::from_ca_cert_der(root.der(), &root_key).unwrap();
            let mut params = ca_params("test-tsa-intermediate", 0);
            customize(&mut params);
            let cert = params.signed_by(&key, &root_issuer).unwrap();
            (Some(cert.der().to_vec()), cert, key)
        } else {
            (None, root, root_key)
        };

    let leaf_keypair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap();
    let mut leaf_params = timestamping_leaf_params(None);
    customize_leaf(&mut leaf_params);
    let issuer = rcgen::Issuer::from_ca_cert_der(issuer_cert.der(), &issuer_key).unwrap();
    let leaf = leaf_params.signed_by(&leaf_keypair, &issuer).unwrap();

    TestAuthority {
        root_der,
        intermediate_der,
        leaf_der: leaf.der().to_vec(),
        leaf_key: p384::ecdsa::SigningKey::from_pkcs8_der(&leaf_keypair.serialize_der()).unwrap(),
        leaf_keypair,
        issuer_cert,
        issuer_key,
        root_cert,
        root_key: root_key_copy,
    }
}

impl TestAuthority {
    fn trusted(&self) -> TimestampAuthority {
        let mut cert_chain_der = vec![self.leaf_der.clone()];
        cert_chain_der.extend(self.intermediate_der.clone());
        cert_chain_der.push(self.root_der.clone());
        TimestampAuthority {
            uri: "https://tsa.test.example".into(),
            cert_chain_der,
            valid_for: ValidityWindow {
                start: Timestamp::parse_rfc3339("2022-01-01T00:00:00Z").unwrap(),
                end: None,
            },
        }
    }

    /// The authority as a trust root that lists only its root.
    fn trusted_root_only(&self) -> TimestampAuthority {
        TimestampAuthority {
            cert_chain_der: vec![self.root_der.clone()],
            ..self.trusted()
        }
    }

    /// Another certificate for the intermediate's name and key, from the
    /// root, that expired before the tokens' time.
    fn expired_intermediate_copy(&self) -> Vec<u8> {
        let root = rcgen::Issuer::from_ca_cert_der(self.root_cert.der(), &self.root_key).unwrap();
        let mut params = ca_params("test-tsa-intermediate", 0);
        params.not_after = rcgen::date_time_ymd(2025, 1, 1);
        params
            .signed_by(&self.issuer_key, &root)
            .unwrap()
            .der()
            .to_vec()
    }

    /// The authority as a trust root listing `chain`.
    fn trusted_as(&self, chain: Vec<Vec<u8>>) -> TimestampAuthority {
        TimestampAuthority {
            cert_chain_der: chain,
            ..self.trusted()
        }
    }

    /// Another self-signed certificate for the root's name and key, as
    /// `customize` changes it.
    fn root_copy(&self, customize: impl FnOnce(&mut CertificateParams)) -> Vec<u8> {
        let mut params = ca_params("test-tsa-root", 1);
        customize(&mut params);
        params.self_signed(&self.root_key).unwrap().der().to_vec()
    }

    /// Another certificate for the leaf's key, from the same issuer, as
    /// `customize` changes it.
    fn reissued_leaf_with(
        &self,
        serial: u64,
        customize: impl FnOnce(&mut CertificateParams),
    ) -> Vec<u8> {
        let issuer =
            rcgen::Issuer::from_ca_cert_der(self.issuer_cert.der(), &self.issuer_key).unwrap();
        let mut params = timestamping_leaf_params(Some(serial));
        customize(&mut params);
        params
            .signed_by(&self.leaf_keypair, &issuer)
            .unwrap()
            .der()
            .to_vec()
    }

    /// Copies of the root under its name and key, each with its own serial
    /// number, so each signs every other.
    fn root_copies(&self, count: u64) -> Vec<Vec<u8>> {
        (1..=count)
            .map(|serial| {
                self.root_copy(|params| {
                    params.serial_number = Some(rcgen::SerialNumber::from(serial));
                })
            })
            .collect()
    }

    /// Another certificate for the leaf's key, from the same issuer.
    fn reissued_leaf(&self, serial: u64) -> Vec<u8> {
        let issuer =
            rcgen::Issuer::from_ca_cert_der(self.issuer_cert.der(), &self.issuer_key).unwrap();
        timestamping_leaf_params(Some(serial))
            .signed_by(&self.leaf_keypair, &issuer)
            .unwrap()
            .der()
            .to_vec()
    }
}

/// The signing-certificate attribute a token carries.
#[derive(Clone)]
enum Ess {
    None,
    /// `SigningCertificateV2` naming the signer by its SHA-256 hash.
    V2,
    /// `SigningCertificate` naming the signer by its SHA-1 hash.
    V1,
    /// `SigningCertificateV2` naming this certificate instead.
    V2Naming(Vec<u8>),
    /// `SigningCertificateV2` with the signer's hash and this certificate's
    /// issuer and serial number.
    V2IssuerSerialOf(Vec<u8>),
    /// `SigningCertificateV2` naming its hash algorithm, and the signer's
    /// hash under the second algorithm.
    V2Hashed(&'static [u8], &'static [u8]),
}

/// What a synthesized token says; [`Token::default`] is a valid token
/// over [`SIGNATURE`].
struct Token {
    status: u8,
    gen_time: &'static str,
    imprint_algorithm: &'static [u8],
    imprint: Vec<u8>,
    content_type: Option<&'static [u8]>,
    /// The message digest attribute in place of the TSTInfo's digest.
    message_digest: Option<Vec<u8>>,
    signers: usize,
    embed_leaf: bool,
    embed_intermediate: bool,
    ess: Ess,
    /// The certificate the signer identifier names, in place of the leaf.
    signer_cert: Option<Vec<u8>>,
    /// A TSTInfo extension, marked critical when set.
    critical_tst_extension: bool,
    /// Certificates carried after the leaf and before the intermediate.
    extra_embedded: Vec<Vec<u8>>,
    /// Identify the signer by its subject key identifier.
    signer_key_id: bool,
    signature_algorithm: &'static [u8],
    /// NULL parameters on the signature algorithm.
    signature_algorithm_parameters: bool,
}

impl Default for Token {
    fn default() -> Self {
        Self {
            status: 0,
            gen_time: "20260513192333Z",
            imprint_algorithm: OID_SHA256,
            imprint: Sha256::digest(SIGNATURE).to_vec(),
            content_type: Some(OID_TST_INFO),
            message_digest: None,
            signers: 1,
            embed_leaf: false,
            embed_intermediate: false,
            ess: Ess::V2,
            signer_cert: None,
            critical_tst_extension: false,
            extra_embedded: Vec::new(),
            signer_key_id: false,
            signature_algorithm: OID_ECDSA_WITH_SHA256,
            signature_algorithm_parameters: false,
        }
    }
}

const OID_SIGNING_CERTIFICATE: &[u8] = &[
    0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x10, 0x02, 0x0C,
];
const OID_SIGNING_CERTIFICATE_V2: &[u8] = &[
    0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x10, 0x02, 0x2F,
];

/// `IssuerSerial` for `cert`: its issuer as a directory name, and serial.
fn issuer_serial(cert: &[u8]) -> Vec<u8> {
    let (_, parsed) = X509Certificate::from_der(cert).unwrap();
    tlv(
        der::TAG_SEQUENCE,
        &[
            &tlv(
                der::TAG_SEQUENCE,
                &[&tlv(
                    der::context_constructed(4),
                    &[parsed.tbs_certificate.issuer.as_raw()],
                )],
            ),
            &tlv(der::TAG_INTEGER, &[parsed.tbs_certificate.raw_serial()]),
        ],
    )
}

fn ess_attribute(ess: &Ess, signer: &[u8]) -> Option<Vec<u8>> {
    let (oid_contents, cert_id) = match ess {
        Ess::None => return None,
        Ess::V2 | Ess::V2Naming(_) | Ess::V2IssuerSerialOf(_) => {
            let (hashed, identified) = match ess {
                Ess::V2Naming(other) => (other.as_slice(), other.as_slice()),
                Ess::V2IssuerSerialOf(other) => (signer, other.as_slice()),
                _ => (signer, signer),
            };
            (
                OID_SIGNING_CERTIFICATE_V2,
                tlv(
                    der::TAG_SEQUENCE,
                    &[
                        &tlv(der::TAG_OCTET_STRING, &[&Sha256::digest(hashed)]),
                        &issuer_serial(identified),
                    ],
                ),
            )
        }
        Ess::V2Hashed(named_algorithm, hashed_with) => (
            OID_SIGNING_CERTIFICATE_V2,
            tlv(
                der::TAG_SEQUENCE,
                &[
                    &algorithm(named_algorithm),
                    &tlv(
                        der::TAG_OCTET_STRING,
                        &[&if *hashed_with == OID_SHA384 {
                            sha2::Sha384::digest(signer).to_vec()
                        } else {
                            Sha256::digest(signer).to_vec()
                        }],
                    ),
                    &issuer_serial(signer),
                ],
            ),
        ),
        Ess::V1 => (
            OID_SIGNING_CERTIFICATE,
            tlv(
                der::TAG_SEQUENCE,
                &[
                    &tlv(der::TAG_OCTET_STRING, &[&sha1::Sha1::digest(signer)]),
                    &issuer_serial(signer),
                ],
            ),
        ),
    };
    Some(tlv(
        der::TAG_SEQUENCE,
        &[
            &oid(oid_contents),
            &tlv(
                der::TAG_SET,
                &[&tlv(
                    der::TAG_SEQUENCE,
                    &[&tlv(der::TAG_SEQUENCE, &[&cert_id])],
                )],
            ),
        ],
    ))
}

impl Token {
    fn signed_by(&self, authority: &TestAuthority) -> Vec<u8> {
        let extensions = if self.critical_tst_extension {
            tlv(
                der::context_constructed(1),
                &[&tlv(
                    der::TAG_SEQUENCE,
                    &[
                        &oid(&[0x2A, 0x03, 0x04]),
                        &tlv(der::TAG_BOOLEAN, &[&[0xFF]]),
                        &tlv(der::TAG_OCTET_STRING, &[&[0x05, 0x00]]),
                    ],
                )],
            )
        } else {
            Vec::new()
        };
        let tst_info = tlv(
            der::TAG_SEQUENCE,
            &[
                &integer(1),
                &oid(OID_SIGSTORE_TSA_POLICY),
                &tlv(
                    der::TAG_SEQUENCE,
                    &[
                        &algorithm(self.imprint_algorithm),
                        &tlv(der::TAG_OCTET_STRING, &[&self.imprint]),
                    ],
                ),
                &integer(7),
                &tlv(der::TAG_GENERALIZED_TIME, &[self.gen_time.as_bytes()]),
                &extensions,
            ],
        );

        let signer_cert = self.signer_cert.as_ref().unwrap_or(&authority.leaf_der);
        let digest = self
            .message_digest
            .clone()
            .unwrap_or_else(|| Sha256::digest(&tst_info).to_vec());
        let mut attributes = Vec::new();
        if let Some(content_type) = self.content_type {
            attributes.extend(tlv(
                der::TAG_SEQUENCE,
                &[
                    &oid(OID_CONTENT_TYPE),
                    &tlv(der::TAG_SET, &[&oid(content_type)]),
                ],
            ));
        }
        attributes.extend(tlv(
            der::TAG_SEQUENCE,
            &[
                &oid(OID_MESSAGE_DIGEST),
                &tlv(der::TAG_SET, &[&tlv(der::TAG_OCTET_STRING, &[&digest])]),
            ],
        ));
        attributes.extend(ess_attribute(&self.ess, &authority.leaf_der).unwrap_or_default());
        let signature: p384::ecdsa::Signature = authority
            .leaf_key
            .sign_prehash(&Sha256::digest(der::encode_set(&attributes)))
            .unwrap();

        let (_, named) = X509Certificate::from_der(signer_cert).unwrap();
        let (version, signer_id) = if self.signer_key_id {
            let key_id = named
                .extensions()
                .iter()
                .find_map(|extension| match extension.parsed_extension() {
                    x509_parser::extensions::ParsedExtension::SubjectKeyIdentifier(id) => {
                        Some(id.0.to_vec())
                    }
                    _ => None,
                })
                .expect("the leaf has a subject key identifier");
            (3, tlv(der::context_primitive(0), &[&key_id]))
        } else {
            (
                1,
                tlv(
                    der::TAG_SEQUENCE,
                    &[
                        named.tbs_certificate.issuer.as_raw(),
                        &tlv(der::TAG_INTEGER, &[named.tbs_certificate.raw_serial()]),
                    ],
                ),
            )
        };
        let signature_algorithm = if self.signature_algorithm_parameters {
            tlv(
                der::TAG_SEQUENCE,
                &[&oid(self.signature_algorithm), &tlv(der::TAG_NULL, &[])],
            )
        } else {
            algorithm(self.signature_algorithm)
        };
        let signer_info = tlv(
            der::TAG_SEQUENCE,
            &[
                &integer(version),
                &signer_id,
                &algorithm(OID_SHA256),
                &tlv(der::context_constructed(0), &[&attributes]),
                &signature_algorithm,
                &tlv(der::TAG_OCTET_STRING, &[signature.to_der().as_bytes()]),
            ],
        );
        let signer_infos: Vec<&[u8]> =
            std::iter::repeat_n(signer_info.as_slice(), self.signers).collect();

        let mut embedded: Vec<&[u8]> = Vec::new();
        if self.embed_leaf {
            embedded.push(signer_cert);
            if signer_cert != &authority.leaf_der {
                embedded.push(&authority.leaf_der);
            }
        }
        embedded.extend(self.extra_embedded.iter().map(Vec::as_slice));
        if self.embed_intermediate {
            embedded.extend(authority.intermediate_der.as_deref());
        }
        let certificates = if embedded.is_empty() {
            Vec::new()
        } else {
            tlv(der::context_constructed(0), &embedded)
        };
        let signed_data = tlv(
            der::TAG_SEQUENCE,
            &[
                &integer(3),
                &tlv(der::TAG_SET, &[&algorithm(OID_SHA256)]),
                &tlv(
                    der::TAG_SEQUENCE,
                    &[
                        &oid(OID_TST_INFO),
                        &tlv(
                            der::context_constructed(0),
                            &[&tlv(der::TAG_OCTET_STRING, &[&tst_info])],
                        ),
                    ],
                ),
                &certificates,
                &tlv(der::TAG_SET, &signer_infos),
            ],
        );
        let content_info = tlv(
            der::TAG_SEQUENCE,
            &[
                &oid(OID_SIGNED_DATA),
                &tlv(der::context_constructed(0), &[&signed_data]),
            ],
        );
        tlv(
            der::TAG_SEQUENCE,
            &[
                &tlv(der::TAG_SEQUENCE, &[&integer(self.status)]),
                &content_info,
            ],
        )
    }
}

fn verify_token(
    token: &Token,
    authority: &TestAuthority,
) -> Result<VerifiedTimestamp, VerifyError> {
    verify_signed_timestamp(
        &token.signed_by(authority),
        SIGNATURE,
        &[authority.trusted()],
    )
}

fn refusal(token: &Token, authority: &TestAuthority) -> String {
    match verify_token(token, authority) {
        Err(VerifyError::Timestamp(why)) => why,
        other => panic!("expected a timestamp refusal, got {other:?}"),
    }
}

#[test]
fn a_synthesized_token_verifies() {
    let authority = test_authority(|_| {});
    let verified = verify_token(&Token::default(), &authority).unwrap();
    assert_eq!(rfc3339(verified.time), "2026-05-13T19:23:33Z");
    assert_eq!(verified.authority, "https://tsa.test.example");
}

#[test]
fn a_token_carrying_its_signing_certificate_still_uses_the_trusted_one() {
    let authority = test_authority(|_| {});
    let token = Token {
        embed_leaf: true,
        ..Token::default()
    };
    verify_token(&token, &authority).unwrap();

    let other = test_authority(|_| {});
    let refused =
        verify_signed_timestamp(&token.signed_by(&other), SIGNATURE, &[authority.trusted()])
            .unwrap_err();
    assert!(refused.is_missing_trust_material(), "{refused:?}");
}

#[test]
fn a_signing_certificate_only_the_token_carries_must_chain_to_the_trust_anchor() {
    let authority = test_authority(|_| {});
    let anchor_only = TimestampAuthority {
        cert_chain_der: vec![authority.root_der.clone()],
        ..authority.trusted()
    };
    let embedded = Token {
        embed_leaf: true,
        ..Token::default()
    };
    verify_signed_timestamp(
        &embedded.signed_by(&authority),
        SIGNATURE,
        std::slice::from_ref(&anchor_only),
    )
    .unwrap();

    let refused = verify_signed_timestamp(
        &Token::default().signed_by(&authority),
        SIGNATURE,
        &[anchor_only],
    )
    .unwrap_err();
    assert!(refused.is_missing_trust_material(), "{refused:?}");
}

#[test]
fn a_token_the_authority_did_not_grant_is_refused() {
    let authority = test_authority(|_| {});
    let token = Token {
        status: 2,
        ..Token::default()
    };
    assert!(refusal(&token, &authority).contains("did not grant it"));
}

#[test]
fn a_sha1_message_imprint_is_refused() {
    let authority = test_authority(|_| {});
    let token = Token {
        imprint_algorithm: OID_SHA1,
        imprint: vec![0; 20],
        ..Token::default()
    };
    assert!(refusal(&token, &authority).contains("SHA-1"));
}

#[test]
fn a_token_whose_signed_digest_is_not_its_content_is_refused() {
    let authority = test_authority(|_| {});
    let token = Token {
        message_digest: Some(vec![0; 32]),
        ..Token::default()
    };
    assert!(refusal(&token, &authority).contains("message digest"));
}

#[test]
fn signed_attributes_without_a_content_type_are_refused() {
    let authority = test_authority(|_| {});
    let token = Token {
        content_type: None,
        ..Token::default()
    };
    assert!(refusal(&token, &authority).contains("no content type"));
}

#[test]
fn a_token_with_two_signers_is_refused() {
    let authority = test_authority(|_| {});
    let token = Token {
        signers: 2,
        ..Token::default()
    };
    assert!(refusal(&token, &authority).contains("more than one signer"));
}

#[test]
fn a_signature_by_another_key_is_refused() {
    let authority = test_authority(|_| {});
    let mut impostor = test_authority(|_| {});
    impostor.root_der = authority.root_der.clone();
    impostor.leaf_der = authority.leaf_der.clone();
    let refused = verify_signed_timestamp(
        &Token::default().signed_by(&impostor),
        SIGNATURE,
        &[authority.trusted()],
    )
    .unwrap_err();
    assert!(
        matches!(&refused, VerifyError::Timestamp(why) if why.contains("CMS signature")),
        "{refused:?}"
    );
}

#[test]
fn a_signing_certificate_without_a_timestamping_only_profile_is_refused() {
    type CustomizeLeaf = Box<dyn FnOnce(&mut CertificateParams)>;
    let cases: [(&str, CustomizeLeaf); 4] = [
        (
            "not critical",
            Box::new(|params| {
                params.custom_extensions = vec![extended_key_usage(&[OID_TIME_STAMPING], false)];
            }),
        ),
        (
            "not timestamping alone",
            Box::new(|params| {
                params.custom_extensions = vec![extended_key_usage(
                    &[OID_TIME_STAMPING, OID_CODE_SIGNING],
                    true,
                )];
            }),
        ),
        (
            "no extended key usage",
            Box::new(|params| params.custom_extensions.clear()),
        ),
        (
            "does not allow signing",
            Box::new(|params| params.key_usages = vec![KeyUsagePurpose::KeyEncipherment]),
        ),
    ];
    for (expected, customize) in cases {
        let authority = test_authority(customize);
        let why = refusal(&Token::default(), &authority);
        assert!(why.contains(expected), "{expected}: {why}");
    }
}

#[test]
fn a_ca_certificate_cannot_sign_timestamps() {
    let authority = test_authority(|params| {
        params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Constrained(0));
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyCertSign,
        ];
    });
    let anchor_and_signer = TimestampAuthority {
        cert_chain_der: vec![authority.leaf_der.clone(), authority.root_der.clone()],
        ..authority.trusted()
    };
    let embedded = Token {
        embed_leaf: true,
        ..Token::default()
    };
    let refused = verify_signed_timestamp(
        &embedded.signed_by(&authority),
        SIGNATURE,
        &[anchor_and_signer],
    )
    .unwrap_err();
    assert!(
        matches!(&refused, VerifyError::Timestamp(why) if why.contains("is a CA certificate")),
        "{refused:?}"
    );
}

#[test]
fn a_time_outside_the_signing_certificates_lifetime_is_refused() {
    let authority = test_authority(|_| {});
    let token = Token {
        gen_time: "20390601000000Z",
        ..Token::default()
    };
    assert!(refusal(&token, &authority).contains("does not contain the signing time"));
}

#[test]
fn generalized_times_follow_the_der_profile() {
    let authority = test_authority(|_| {});
    let with_fraction = Token {
        gen_time: "20260513192333.25Z",
        ..Token::default()
    };
    let verified = verify_token(&with_fraction, &authority).unwrap();
    assert_eq!(
        Timestamp::from(verified.time).to_rfc3339_milliseconds(),
        "2026-05-13T19:23:33.250Z"
    );

    for malformed in [
        "20260513192333.250Z",
        "20260513192333.Z",
        "20260513192333",
        "20260513192333+0000",
        "20260230000000Z",
        "20261301000000Z",
        "20260513246000Z",
        "2026051319233Z",
    ] {
        let token = Token {
            gen_time: malformed,
            ..Token::default()
        };
        let why = refusal(&token, &authority);
        assert!(why.contains("TSTInfo time"), "{malformed}: {why}");
    }

    let leap_day = Token {
        gen_time: "20280229120000Z",
        ..Token::default()
    };
    assert_eq!(
        rfc3339(verify_token(&leap_day, &authority).unwrap().time),
        "2028-02-29T12:00:00Z"
    );
}

#[test]
fn a_token_may_carry_the_intermediate_between_its_signer_and_a_trusted_root() {
    let authority = authority_with(true, |_| {});
    let token = Token {
        embed_leaf: true,
        embed_intermediate: true,
        ..Token::default()
    };
    verify_signed_timestamp(
        &token.signed_by(&authority),
        SIGNATURE,
        &[authority.trusted_root_only()],
    )
    .unwrap();

    let without_intermediate = Token {
        embed_leaf: true,
        ..Token::default()
    };
    let refused = verify_signed_timestamp(
        &without_intermediate.signed_by(&authority),
        SIGNATURE,
        &[authority.trusted_root_only()],
    )
    .unwrap_err();
    assert!(refused.is_missing_trust_material(), "{refused:?}");
}

#[test]
fn a_signer_from_another_authority_needs_newer_trust_material() {
    // A stale trust root that lists only an older authority's root: the
    // token's own signing certificate chains to a root it doesn't hold.
    let held = test_authority(|_| {});
    let other = test_authority(|_| {});
    let token = Token {
        embed_leaf: true,
        ..Token::default()
    };
    let refused = verify_signed_timestamp(
        &token.signed_by(&other),
        SIGNATURE,
        &[held.trusted_root_only()],
    )
    .unwrap_err();
    assert!(refused.is_missing_trust_material(), "{refused:?}");
}

#[test]
fn a_signing_certificate_with_an_unhandled_critical_extension_is_refused() {
    let authority = test_authority(|params| {
        let mut extension = CustomExtension::from_oid_content(&[1, 2, 3, 4], vec![0x05, 0x00]);
        extension.set_criticality(true);
        params.custom_extensions.push(extension);
    });
    assert!(refusal(&Token::default(), &authority).contains("critical extension"));
}

#[test]
fn the_signing_certificate_attribute_must_name_the_signer() {
    let authority = test_authority(|_| {});
    for ess in [Ess::V2, Ess::V1, Ess::None] {
        let token = Token {
            ess,
            ..Token::default()
        };
        verify_token(&token, &authority).unwrap();
    }

    // Two certificates for one key: the signer identifier, which the
    // signature doesn't cover, names a reissued certificate while the
    // signed attribute names the original.
    let reissued = authority.reissued_leaf(42);
    let swapped = Token {
        embed_leaf: true,
        signer_cert: Some(reissued.clone()),
        ..Token::default()
    };
    let why = match verify_signed_timestamp(
        &swapped.signed_by(&authority),
        SIGNATURE,
        &[authority.trusted_root_only()],
    ) {
        Err(VerifyError::Timestamp(why)) => why,
        other => panic!("expected a timestamp refusal, got {other:?}"),
    };
    assert!(why.contains("signing certificate attribute"), "{why}");

    let wrong = Token {
        ess: Ess::V2Naming(reissued),
        ..Token::default()
    };
    assert!(refusal(&wrong, &authority).contains("signing certificate attribute"));
}

#[test]
fn the_signing_certificate_attribute_may_name_its_hash_algorithm() {
    let authority = test_authority(|_| {});
    for (named, hashed_with) in [(OID_SHA256, OID_SHA256), (OID_SHA384, OID_SHA384)] {
        let token = Token {
            ess: Ess::V2Hashed(named, hashed_with),
            ..Token::default()
        };
        verify_token(&token, &authority).unwrap();
    }
    let mismatched = Token {
        ess: Ess::V2Hashed(OID_SHA384, OID_SHA256),
        ..Token::default()
    };
    assert!(refusal(&mismatched, &authority).contains("names another certificate"));
}

#[test]
fn a_critical_tstinfo_extension_is_refused() {
    let authority = test_authority(|_| {});
    let token = Token {
        critical_tst_extension: true,
        ..Token::default()
    };
    assert!(refusal(&token, &authority).contains("critical extension"));
}

#[test]
fn a_signer_identified_by_its_subject_key_identifier_verifies() {
    let authority = test_authority(|_| {});
    let token = Token {
        signer_key_id: true,
        ..Token::default()
    };
    verify_token(&token, &authority).unwrap();
}

#[test]
fn an_intermediate_that_does_not_allow_timestamping_is_refused() {
    let authority = authority_with_intermediate(
        Some(|params: &mut CertificateParams| {
            params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::CodeSigning];
        }),
        |_| {},
    );
    assert!(refusal(&Token::default(), &authority).contains("does not allow timestamping"));
}

#[test]
fn the_signature_algorithm_must_be_ecdsa_over_the_signers_digest() {
    let authority = test_authority(|_| {});
    let ec_public_key = Token {
        signature_algorithm: OID_EC_PUBLIC_KEY,
        ..Token::default()
    };
    verify_token(&ec_public_key, &authority).unwrap();

    let cases = [
        (
            Token {
                signature_algorithm: OID_ECDSA_WITH_SHA384,
                ..Token::default()
            },
            "different algorithm than its digest",
        ),
        (
            Token {
                signature_algorithm: OID_RSA_WITH_SHA256,
                ..Token::default()
            },
            "not signed with ECDSA",
        ),
        (
            Token {
                signature_algorithm_parameters: true,
                ..Token::default()
            },
            "trailing",
        ),
    ];
    for (token, expected) in cases {
        let why = refusal(&token, &authority);
        assert!(why.contains(expected), "{expected}: {why}");
    }
}

#[test]
fn a_sha384_message_imprint_verifies() {
    let authority = test_authority(|_| {});
    let token = Token {
        imprint_algorithm: OID_SHA384,
        imprint: sha2::Sha384::digest(SIGNATURE).to_vec(),
        ..Token::default()
    };
    verify_token(&token, &authority).unwrap();
}

#[test]
fn a_timestamp_signs_the_time_of_a_rekor_v1_bundle_without_a_set() {
    let case = "intoto-with-custom-trust-root";
    let trust = TrustRoot::parse(&conformance_file(case, "trusted_root.json")).unwrap();
    let mut bundle: serde_json::Value =
        serde_json::from_slice(&conformance_file(case, "bundle.sigstore.json")).unwrap();
    let verify = |bundle: &serde_json::Value| {
        verify_sigstore_bundle_with(
            &serde_json::to_vec(bundle).unwrap(),
            &IdentityExpectations::none(),
            VerifyOptions::npm_attestation(),
            &trust,
        )
    };
    let with_set = verify(&bundle).unwrap();
    assert_eq!(rfc3339(with_set.signed_at), "2023-02-01T00:00:00Z");

    // The unsigned integrated time no longer counts; the timestamp does.
    let entry = &mut bundle["verificationMaterial"]["tlogEntries"][0];
    entry.as_object_mut().unwrap().remove("inclusionPromise");
    entry["integratedTime"] = serde_json::json!("1700000000");
    let without_set = verify(&bundle).unwrap();
    assert_eq!(rfc3339(without_set.signed_at), "2023-02-01T00:00:00Z");

    bundle["verificationMaterial"]
        .as_object_mut()
        .unwrap()
        .remove("timestampVerificationData");
    let refused = verify(&bundle).unwrap_err();
    assert!(
        matches!(&refused, VerifyError::Timestamp(why) if why.contains("no signed time")),
        "{refused:?}"
    );
}

#[test]
fn every_candidate_intermediate_is_tried_whatever_their_order() {
    // Two certificates for the intermediate's name and key: the first one
    // carried expired before the token's time, the second is current.
    let authority = authority_with(true, |_| {});
    let token = Token {
        embed_leaf: true,
        embed_intermediate: true,
        extra_embedded: vec![authority.expired_intermediate_copy()],
        ..Token::default()
    };
    verify_signed_timestamp(
        &token.signed_by(&authority),
        SIGNATURE,
        &[authority.trusted_root_only()],
    )
    .unwrap();

    let only_expired = Token {
        embed_leaf: true,
        extra_embedded: vec![authority.expired_intermediate_copy()],
        ..Token::default()
    };
    let why = match verify_signed_timestamp(
        &only_expired.signed_by(&authority),
        SIGNATURE,
        &[authority.trusted_root_only()],
    ) {
        Err(VerifyError::Timestamp(why)) => why,
        other => panic!("expected a timestamp refusal, got {other:?}"),
    };
    assert!(why.contains("does not contain the signing time"), "{why}");

    let current_first = Token {
        embed_leaf: true,
        extra_embedded: vec![
            authority.intermediate_der.clone().unwrap(),
            authority.expired_intermediate_copy(),
        ],
        ..Token::default()
    };
    verify_signed_timestamp(
        &current_first.signed_by(&authority),
        SIGNATURE,
        &[authority.trusted_root_only()],
    )
    .unwrap();
}

/// A critical extension the verifier doesn't process.
fn unhandled_critical_extension() -> CustomExtension {
    let mut extension = CustomExtension::from_oid_content(&[1, 2, 3, 4], vec![0x05, 0x00]);
    extension.set_criticality(true);
    extension
}

/// An authority whose leaf sits `depth` intermediates below its root, and
/// those intermediates from the leaf's issuer up.
fn authority_with_intermediates(depth: u8) -> (TestAuthority, Vec<Vec<u8>>) {
    let root_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap();
    let root = ca_params("test-tsa-root", depth)
        .self_signed(&root_key)
        .unwrap();
    let mut issuer_cert = root.clone();
    let mut issuer_key = KeyPair::try_from(root_key.serialize_der().as_slice()).unwrap();
    let mut intermediates = Vec::new();
    for level in 0..depth {
        let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap();
        let issuer = rcgen::Issuer::from_ca_cert_der(issuer_cert.der(), &issuer_key).unwrap();
        let cert = ca_params(&format!("test-tsa-intermediate-{level}"), depth - level - 1)
            .signed_by(&key, &issuer)
            .unwrap();
        intermediates.insert(0, cert.der().to_vec());
        issuer_cert = cert;
        issuer_key = key;
    }
    let leaf_keypair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap();
    let issuer = rcgen::Issuer::from_ca_cert_der(issuer_cert.der(), &issuer_key).unwrap();
    let leaf = timestamping_leaf_params(None)
        .signed_by(&leaf_keypair, &issuer)
        .unwrap();
    let authority = TestAuthority {
        root_der: root.der().to_vec(),
        intermediate_der: None,
        leaf_der: leaf.der().to_vec(),
        leaf_key: p384::ecdsa::SigningKey::from_pkcs8_der(&leaf_keypair.serialize_der()).unwrap(),
        leaf_keypair,
        issuer_cert,
        issuer_key,
        root_cert: root,
        root_key,
    };
    (authority, intermediates)
}

#[test]
fn an_issuer_the_trust_root_holds_that_has_since_expired_needs_newer_trust_material() {
    // The authority reissued its root, or an intermediate, under the same
    // name and key; a stale trust root still holds the expired copy.
    let authority = authority_with(true, |_| {});
    let expired_root = authority.root_copy(|params| {
        params.not_after = rcgen::date_time_ymd(2025, 1, 1);
    });
    let carrying_leaf_and_intermediate = Token {
        embed_leaf: true,
        embed_intermediate: true,
        ..Token::default()
    };
    let refused = verify_signed_timestamp(
        &carrying_leaf_and_intermediate.signed_by(&authority),
        SIGNATURE,
        &[authority.trusted_as(vec![expired_root])],
    )
    .unwrap_err();
    assert!(refused.is_missing_trust_material(), "{refused:?}");

    let carrying_leaf = Token {
        embed_leaf: true,
        ..Token::default()
    };
    let stale_intermediate = authority.trusted_as(vec![
        authority.expired_intermediate_copy(),
        authority.root_der.clone(),
    ]);
    let refused = verify_signed_timestamp(
        &carrying_leaf.signed_by(&authority),
        SIGNATURE,
        std::slice::from_ref(&stale_intermediate),
    )
    .unwrap_err();
    assert!(refused.is_missing_trust_material(), "{refused:?}");

    // A current copy the token carries completes the path instead.
    verify_signed_timestamp(
        &carrying_leaf_and_intermediate.signed_by(&authority),
        SIGNATURE,
        &[stale_intermediate],
    )
    .unwrap();
}

#[test]
fn another_authoritys_certificates_decide_nothing() {
    // A token from an authority the trust root doesn't hold carries its own
    // leaf, which this verifier would refuse, and its self-signed root.
    let held = authority_with(true, |_| {});
    let other = test_authority(|params| {
        params
            .custom_extensions
            .push(unhandled_critical_extension())
    });
    let token = Token {
        embed_leaf: true,
        extra_embedded: vec![other.root_der.clone()],
        ..Token::default()
    };
    let refused = verify_signed_timestamp(
        &token.signed_by(&other),
        SIGNATURE,
        &[held.trusted_root_only()],
    )
    .unwrap_err();
    assert!(refused.is_missing_trust_material(), "{refused:?}");
}

#[test]
fn a_timestamp_carrying_more_than_16_certificates_is_refused() {
    let authority = test_authority(|_| {});
    let token = Token {
        embed_leaf: true,
        extra_embedded: authority.root_copies(16),
        ..Token::default()
    };
    let why = match verify_signed_timestamp(
        &token.signed_by(&authority),
        SIGNATURE,
        &[authority.trusted_root_only()],
    ) {
        Err(VerifyError::Timestamp(why)) => why,
        other => panic!("expected a timestamp refusal, got {other:?}"),
    };
    assert!(why.contains("more than 16 certificates"), "{why}");
}

#[test]
fn a_bundle_whose_timestamps_need_too_many_signature_checks_is_refused_in_any_order() {
    // Copies of the root under its name and key each sign every other, so
    // against an anchor that signed none of them, every ordering of them is
    // a path to try.
    let authority = test_authority(|_| {});
    let impostor_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap();
    let impostor_anchor = ca_params("test-tsa-root", 3)
        .self_signed(&impostor_key)
        .unwrap()
        .der()
        .to_vec();
    let hostile = Token {
        embed_leaf: true,
        extra_embedded: authority.root_copies(15),
        ..Token::default()
    }
    .signed_by(&authority);
    let valid = Token::default().signed_by(&authority);
    let impostor = || authority.trusted_as(vec![impostor_anchor.clone()]);

    // The authority that verifies the hostile timestamp's signature may be
    // listed first or last: every authority is consulted either way.
    for authorities in [
        [impostor(), authority.trusted()],
        [authority.trusted(), impostor()],
    ] {
        for timestamps in [
            vec![hostile.clone(), valid.clone()],
            vec![valid.clone(), hostile.clone()],
        ] {
            match verify_signed_timestamps(&timestamps, SIGNATURE, &authorities) {
                Err(VerifyError::Timestamp(why)) => {
                    assert!(why.contains("signature checks"), "{why}")
                }
                other => panic!("expected the bundle refused, got {other:?}"),
            }
        }
        assert_eq!(
            verify_signed_timestamps(std::slice::from_ref(&valid), SIGNATURE, &authorities)
                .unwrap()
                .verified
                .len(),
            1
        );
    }
}

#[test]
fn an_expired_trust_root_issuer_does_not_hide_a_refusal_further_up_its_path() {
    // The trust root's intermediate expired, which a newer trust root could
    // mend, but its anchor may not issue that deep, which it couldn't.
    let authority = authority_with(true, |_| {});
    let shallow_anchor = authority.root_copy(|params| {
        params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Constrained(0));
    });
    let token = Token {
        embed_leaf: true,
        ..Token::default()
    };
    let why = match verify_signed_timestamp(
        &token.signed_by(&authority),
        SIGNATURE,
        &[authority.trusted_as(vec![authority.expired_intermediate_copy(), shallow_anchor])],
    ) {
        Err(VerifyError::Timestamp(why)) => why,
        other => panic!("expected a timestamp refusal, got {other:?}"),
    };
    assert!(why.contains("pathLenConstraint"), "{why}");
}

#[test]
fn a_trust_root_issuer_not_yet_valid_at_the_signed_time_is_refused() {
    // Only an issuer that expired may have been reissued since.
    let authority = test_authority(|_| {});
    let future_anchor = authority.root_copy(|params| {
        params.not_before = rcgen::date_time_ymd(2027, 1, 1);
    });
    let token = Token {
        embed_leaf: true,
        ..Token::default()
    };
    let refused = verify_signed_timestamp(
        &token.signed_by(&authority),
        SIGNATURE,
        &[authority.trusted_as(vec![future_anchor])],
    )
    .unwrap_err();
    assert!(
        matches!(&refused, VerifyError::Timestamp(why) if why.contains("does not contain the signing time")),
        "{refused:?}"
    );
}

#[test]
fn every_carried_certificate_matching_the_signer_is_tried() {
    // Two certificates for the leaf's key, so its key identifier names
    // both: the first expired before the token's time.
    let authority = test_authority(|_| {});
    let expired = authority.reissued_leaf_with(42, |params| {
        params.not_after = rcgen::date_time_ymd(2025, 1, 1);
    });
    let token = Token {
        signer_key_id: true,
        extra_embedded: vec![expired, authority.leaf_der.clone()],
        ..Token::default()
    };
    verify_signed_timestamp(
        &token.signed_by(&authority),
        SIGNATURE,
        &[authority.trusted_root_only()],
    )
    .unwrap();
}

#[test]
fn a_signing_certificate_more_than_three_intermediates_below_its_root_is_not_placed() {
    let (three_deep, intermediates) = authority_with_intermediates(3);
    let token = Token {
        embed_leaf: true,
        extra_embedded: intermediates,
        ..Token::default()
    };
    verify_signed_timestamp(
        &token.signed_by(&three_deep),
        SIGNATURE,
        &[three_deep.trusted_root_only()],
    )
    .unwrap();

    let (four_deep, intermediates) = authority_with_intermediates(4);
    let token = Token {
        embed_leaf: true,
        extra_embedded: intermediates,
        ..Token::default()
    };
    let refused = verify_signed_timestamp(
        &token.signed_by(&four_deep),
        SIGNATURE,
        &[four_deep.trusted_root_only()],
    )
    .unwrap_err();
    assert!(refused.is_missing_trust_material(), "{refused:?}");
}

#[test]
fn an_authority_that_only_dates_the_timestamp_out_outranks_one_that_refuses_it() {
    let authority = test_authority(|_| {});
    // The same root, reissued as an end-entity certificate: it can't issue.
    let not_a_ca = authority.root_copy(|params| {
        params.is_ca = IsCa::ExplicitNoCa;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    });
    let refusing = || authority.trusted_as(vec![authority.leaf_der.clone(), not_a_ca.clone()]);
    let unrelated = test_authority(|_| {}).trusted_root_only();
    let token = Token::default().signed_by(&authority);

    match verify_signed_timestamp(&token, SIGNATURE, &[unrelated, refusing()]) {
        Err(VerifyError::Timestamp(why)) => assert!(why.contains("cA is FALSE"), "{why}"),
        other => panic!("expected a timestamp refusal, got {other:?}"),
    }

    let dated_out = TimestampAuthority {
        valid_for: ValidityWindow {
            start: Timestamp::parse_rfc3339("2027-01-01T00:00:00Z").unwrap(),
            end: None,
        },
        ..authority.trusted()
    };
    let refused = verify_signed_timestamp(&token, SIGNATURE, &[refusing(), dated_out]).unwrap_err();
    assert!(refused.is_missing_trust_material(), "{refused:?}");
}

#[test]
fn the_signing_certificate_attribute_must_name_the_signers_issuer_and_serial() {
    let authority = test_authority(|_| {});
    let token = Token {
        ess: Ess::V2IssuerSerialOf(authority.reissued_leaf(42)),
        ..Token::default()
    };
    assert!(refusal(&token, &authority).contains("issuer and serial number"));
}

#[test]
fn an_intermediate_with_an_unhandled_critical_extension_is_refused() {
    let authority = authority_with_intermediate(
        Some(|params: &mut CertificateParams| {
            params
                .custom_extensions
                .push(unhandled_critical_extension());
        }),
        |_| {},
    );
    assert!(refusal(&Token::default(), &authority).contains("critical extension"));
}

#[test]
fn a_trust_anchors_critical_extensions_are_its_trust_roots_business() {
    let authority = test_authority(|_| {});
    let anchor = authority.root_copy(|params| {
        params
            .custom_extensions
            .push(unhandled_critical_extension());
    });
    let token = Token {
        embed_leaf: true,
        ..Token::default()
    };
    verify_signed_timestamp(
        &token.signed_by(&authority),
        SIGNATURE,
        &[authority.trusted_as(vec![anchor])],
    )
    .unwrap();
}

#[test]
fn a_pinned_signing_certificate_with_an_unhandled_critical_extension_is_refused() {
    // A trust root that lists only the leaf pins it as the anchor too.
    let authority = test_authority(|params| {
        params
            .custom_extensions
            .push(unhandled_critical_extension())
    });
    let why = match verify_signed_timestamp(
        &Token::default().signed_by(&authority),
        SIGNATURE,
        &[authority.trusted_as(vec![authority.leaf_der.clone()])],
    ) {
        Err(VerifyError::Timestamp(why)) => why,
        other => panic!("expected a timestamp refusal, got {other:?}"),
    };
    assert!(why.contains("critical extension"), "{why}");
}
