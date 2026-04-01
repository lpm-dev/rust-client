//! Root Certificate Authority generation.
//!
//! Generates a self-signed root CA using ECDSA P-256 with a 10-year validity period.
//! This CA is used to sign per-project certificates for local HTTPS development.

use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair, KeyUsagePurpose,
};
use time::{Duration, OffsetDateTime};

/// Generate a new root CA certificate and private key.
///
/// Returns `(cert_pem, key_pem)` as PEM-encoded strings.
pub fn generate_ca() -> Result<(String, String), Box<dyn std::error::Error>> {
    let mut params = CertificateParams::default();

    // Distinguished Name
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "LPM Local Development CA");
    dn.push(DnType::OrganizationName, "LPM");
    params.distinguished_name = dn;

    // CA-specific settings
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];

    // 10-year validity
    let now = OffsetDateTime::now_utc();
    params.not_before = now;
    params.not_after = now + Duration::days(3650);

    // Generate ECDSA P-256 key pair
    let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;

    // Self-sign the CA certificate
    let cert = params.self_signed(&key_pair)?;

    Ok((cert.pem(), key_pair.serialize_pem()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_ca_produces_valid_pem() {
        let (cert_pem, key_pem) = generate_ca().unwrap();

        assert!(cert_pem.starts_with("-----BEGIN CERTIFICATE-----"));
        assert!(cert_pem.ends_with("-----END CERTIFICATE-----\n"));
        assert!(key_pem.starts_with("-----BEGIN PRIVATE KEY-----"));
        assert!(key_pem.ends_with("-----END PRIVATE KEY-----\n"));
    }

    #[test]
    fn ca_cert_is_parseable() {
        let (cert_pem, _) = generate_ca().unwrap();

        // Parse with x509-parser to verify it's a valid CA
        let pem = pem::parse(&cert_pem).unwrap();
        let (_, cert) = x509_parser::parse_x509_certificate(pem.contents()).unwrap();

        // Verify it's a CA
        let bc = cert.basic_constraints().unwrap().unwrap();
        assert!(bc.value.ca);

        // Verify the subject CN
        let cn = cert
            .subject()
            .iter_common_name()
            .next()
            .unwrap()
            .as_str()
            .unwrap();
        assert_eq!(cn, "LPM Local Development CA");
    }

    #[test]
    fn ca_cert_has_path_length_constraint_zero() {
        let (cert_pem, _) = generate_ca().unwrap();

        let pem = pem::parse(&cert_pem).unwrap();
        let (_, cert) = x509_parser::parse_x509_certificate(pem.contents()).unwrap();

        let bc = cert.basic_constraints().unwrap().unwrap();
        assert!(bc.value.ca, "certificate should be a CA");
        assert_eq!(
            bc.value.path_len_constraint,
            Some(0),
            "CA pathLenConstraint should be 0 (only sign leaf certs, no intermediates)"
        );
    }

    #[test]
    fn ca_cert_has_10_year_validity() {
        let (cert_pem, _) = generate_ca().unwrap();

        let pem = pem::parse(&cert_pem).unwrap();
        let (_, cert) = x509_parser::parse_x509_certificate(pem.contents()).unwrap();

        let not_before = cert.validity().not_before.to_datetime();
        let not_after = cert.validity().not_after.to_datetime();

        // Should be approximately 10 years (3650 days)
        let duration = not_after - not_before;
        let days = duration.whole_days();
        assert!(
            days >= 3649 && days <= 3651,
            "expected ~3650 days, got {days}"
        );
    }
}
