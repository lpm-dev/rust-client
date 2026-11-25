//! RFC 3161 signed timestamps: Sigstore's conformance cases for the
//! shapes real timestamp authorities produce, and synthesized tokens for
//! the refusals those cases don't reach.

use super::super::der;
use super::super::timestamp::{VerifiedTimestamp, verify_signed_timestamp};
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
fn a_timestamp_after_its_authoritys_validity_window_is_refused() {
    let refused = verify_conformance_case("rekor2-timestamp-outside-trust-root-tsa-validity_fail")
        .unwrap_err();
    assert!(
        matches!(&refused, VerifyError::Timestamp(why) if why.contains("validity window in the trust root")),
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

// ─── Synthesized timestamp tokens ────────────────────────────────

const OID_SIGNED_DATA: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02];
const OID_TST_INFO: &[u8] = &[
    0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x10, 0x01, 0x04,
];
const OID_CONTENT_TYPE: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x03];
const OID_MESSAGE_DIGEST: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x04];
const OID_SHA1: &[u8] = &[0x2B, 0x0E, 0x03, 0x02, 0x1A];
const OID_SHA256: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];
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
    leaf_der: Vec<u8>,
    leaf_key: p384::ecdsa::SigningKey,
}

fn validity(not_before: (i32, u8, u8), not_after: (i32, u8, u8)) -> CertificateParams {
    let mut params = CertificateParams::default();
    params.not_before = rcgen::date_time_ymd(not_before.0, not_before.1, not_before.2);
    params.not_after = rcgen::date_time_ymd(not_after.0, not_after.1, not_after.2);
    params
}

/// A timestamp authority with a P-384 root and a leaf whose profile
/// `customize_leaf` may change from a valid timestamping certificate.
fn test_authority(customize_leaf: impl FnOnce(&mut CertificateParams)) -> TestAuthority {
    let root_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap();
    let mut root_params = validity((2020, 1, 1), (2040, 1, 1));
    root_params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Constrained(0));
    root_params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    root_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "test-tsa-root");
    let root = root_params.self_signed(&root_key).unwrap();

    let leaf_keypair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap();
    let mut leaf_params = validity((2021, 1, 1), (2039, 1, 1));
    leaf_params.is_ca = IsCa::ExplicitNoCa;
    leaf_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    leaf_params.custom_extensions = vec![extended_key_usage(&[OID_TIME_STAMPING], true)];
    leaf_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "test-tsa");
    customize_leaf(&mut leaf_params);
    let issuer = rcgen::Issuer::from_ca_cert_der(root.der(), &root_key).unwrap();
    let leaf = leaf_params.signed_by(&leaf_keypair, &issuer).unwrap();

    TestAuthority {
        root_der: root.der().to_vec(),
        leaf_der: leaf.der().to_vec(),
        leaf_key: p384::ecdsa::SigningKey::from_pkcs8_der(&leaf_keypair.serialize_der()).unwrap(),
    }
}

impl TestAuthority {
    fn trusted(&self) -> TimestampAuthority {
        TimestampAuthority {
            uri: "https://tsa.test.example".into(),
            cert_chain_der: vec![self.leaf_der.clone(), self.root_der.clone()],
            valid_for: ValidityWindow {
                start: Timestamp::parse_rfc3339("2022-01-01T00:00:00Z").unwrap(),
                end: None,
            },
        }
    }
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
        }
    }
}

impl Token {
    fn signed_by(&self, authority: &TestAuthority) -> Vec<u8> {
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
            ],
        );

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
        let signature: p384::ecdsa::Signature = authority
            .leaf_key
            .sign_prehash(&Sha256::digest(der::encode_set(&attributes)))
            .unwrap();

        let (_, leaf) = X509Certificate::from_der(&authority.leaf_der).unwrap();
        let signer_info = tlv(
            der::TAG_SEQUENCE,
            &[
                &integer(1),
                &tlv(
                    der::TAG_SEQUENCE,
                    &[
                        leaf.tbs_certificate.issuer.as_raw(),
                        &tlv(der::TAG_INTEGER, &[leaf.tbs_certificate.raw_serial()]),
                    ],
                ),
                &algorithm(OID_SHA256),
                &tlv(der::context_constructed(0), &[&attributes]),
                &algorithm(OID_ECDSA_WITH_SHA256),
                &tlv(der::TAG_OCTET_STRING, &[signature.to_der().as_bytes()]),
            ],
        );
        let signer_infos: Vec<&[u8]> =
            std::iter::repeat_n(signer_info.as_slice(), self.signers).collect();

        let certificates = if self.embed_leaf {
            tlv(der::context_constructed(0), &[&authority.leaf_der])
        } else {
            Vec::new()
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
    let impostor = TestAuthority {
        leaf_key: test_authority(|_| {}).leaf_key,
        root_der: authority.root_der.clone(),
        leaf_der: authority.leaf_der.clone(),
    };
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
