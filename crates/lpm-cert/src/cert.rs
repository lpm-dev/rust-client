//! Project certificate generation and management.
//!
//! Generates certificates signed by the LPM root CA for use with local dev servers.
//! Default SANs: localhost, 127.0.0.1, ::1, *.local — plus any user-specified hostnames.

use lpm_common::LpmError;
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, SanType};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;
use time::{Duration, OffsetDateTime};

/// Certificate info extracted from an existing cert file.
#[derive(Debug, Clone)]
pub struct CertInfo {
    pub subject: String,
    pub issuer: String,
    pub not_before: String,
    pub not_after: String,
    pub san_entries: Vec<String>,
    pub is_ca: bool,
}

/// Generate a project certificate signed by the given CA.
///
/// Default SANs: `localhost`, `127.0.0.1`, `::1`, `*.local`
/// Additional hostnames are appended from `extra_hostnames`.
///
/// Returns `(cert_pem, key_pem)` as PEM-encoded strings.
pub fn generate_project_cert(
    ca_cert_pem: &str,
    ca_key_pem: &str,
    extra_hostnames: &[String],
) -> Result<(String, String), Box<dyn std::error::Error>> {
    // Parse the CA certificate and key
    let ca_key_pair = KeyPair::from_pem(ca_key_pem)?;
    let ca_cert_params = CertificateParams::from_ca_cert_pem(ca_cert_pem)?;
    let ca_cert = ca_cert_params.self_signed(&ca_key_pair)?;

    // Build the project cert params
    let mut params = CertificateParams::default();

    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "LPM Local Dev Server");
    dn.push(DnType::OrganizationName, "LPM");
    params.distinguished_name = dn;

    // Not a CA
    params.is_ca = rcgen::IsCa::NoCa;
    params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];

    // 1-year validity
    let now = OffsetDateTime::now_utc();
    params.not_before = now;
    params.not_after = now + Duration::days(365);

    // Subject Alternative Names
    let mut sans = vec![
        SanType::DnsName("localhost".try_into()?),
        SanType::IpAddress(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))),
        SanType::IpAddress(IpAddr::V6(Ipv6Addr::LOCALHOST)),
    ];

    // Add extra hostnames
    for hostname in extra_hostnames {
        // Try parsing as IP first
        if let Ok(ip) = hostname.parse::<IpAddr>() {
            sans.push(SanType::IpAddress(ip));
        } else {
            sans.push(SanType::DnsName(hostname.clone().try_into()?));
        }
    }

    params.subject_alt_names = sans;

    // Generate new key pair for the project cert
    let project_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;

    // Sign with the CA
    let project_cert = params.signed_by(&project_key, &ca_cert, &ca_key_pair)?;

    Ok((project_cert.pem(), project_key.serialize_pem()))
}

/// Check if a certificate file needs renewal (within 30 days of expiry or invalid).
pub fn needs_renewal(cert_path: &Path) -> Result<bool, LpmError> {
    let pem_str = std::fs::read_to_string(cert_path)
        .map_err(|e| LpmError::Cert(format!("failed to read cert: {e}")))?;

    let pem = pem::parse(&pem_str).map_err(|e| LpmError::Cert(format!("invalid PEM: {e}")))?;

    let (_, cert) = x509_parser::parse_x509_certificate(pem.contents())
        .map_err(|e| LpmError::Cert(format!("invalid X.509: {e}")))?;

    let not_after = cert.validity().not_after.to_datetime();
    let now = time::OffsetDateTime::now_utc();
    let renewal_threshold = now + Duration::days(30);

    Ok(not_after <= renewal_threshold)
}

/// Read certificate information from a PEM file.
pub fn read_cert_info(cert_path: &Path) -> Result<CertInfo, LpmError> {
    let pem_str = std::fs::read_to_string(cert_path)
        .map_err(|e| LpmError::Cert(format!("failed to read cert: {e}")))?;

    let pem = pem::parse(&pem_str).map_err(|e| LpmError::Cert(format!("invalid PEM: {e}")))?;

    let (_, cert) = x509_parser::parse_x509_certificate(pem.contents())
        .map_err(|e| LpmError::Cert(format!("invalid X.509: {e}")))?;

    let subject = cert
        .subject()
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
        .unwrap_or("unknown")
        .to_string();

    let issuer = cert
        .issuer()
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
        .unwrap_or("unknown")
        .to_string();

    let not_before = format_asn1_time(&cert.validity().not_before);
    let not_after = format_asn1_time(&cert.validity().not_after);

    // Extract SANs
    let san_entries = cert
        .subject_alternative_name()
        .ok()
        .flatten()
        .map(|san| {
            san.value
                .general_names
                .iter()
                .map(|name| format!("{name}"))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    let is_ca = cert
        .basic_constraints()
        .ok()
        .flatten()
        .map(|bc| bc.value.ca)
        .unwrap_or(false);

    Ok(CertInfo {
        subject,
        issuer,
        not_before,
        not_after,
        san_entries,
        is_ca,
    })
}

fn format_asn1_time(time: &x509_parser::time::ASN1Time) -> String {
    let dt = time.to_datetime();
    format!("{}-{:02}-{:02}", dt.year(), dt.month() as u8, dt.day())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ca;

    #[test]
    fn generate_project_cert_signed_by_ca() {
        let (ca_cert_pem, ca_key_pem) = ca::generate_ca().unwrap();
        let (cert_pem, key_pem) = generate_project_cert(&ca_cert_pem, &ca_key_pem, &[]).unwrap();

        assert!(cert_pem.starts_with("-----BEGIN CERTIFICATE-----"));
        assert!(key_pem.starts_with("-----BEGIN PRIVATE KEY-----"));

        // Parse and verify issuer matches CA
        let pem = pem::parse(&cert_pem).unwrap();
        let (_, cert) = x509_parser::parse_x509_certificate(pem.contents()).unwrap();

        let issuer_cn = cert
            .issuer()
            .iter_common_name()
            .next()
            .unwrap()
            .as_str()
            .unwrap();
        assert_eq!(issuer_cn, "LPM Local Development CA");

        // Verify it's NOT a CA
        let bc = cert.basic_constraints().ok().flatten();
        assert!(bc.is_none() || !bc.unwrap().value.ca);
    }

    #[test]
    fn project_cert_has_default_sans() {
        let (ca_cert_pem, ca_key_pem) = ca::generate_ca().unwrap();
        let (cert_pem, _) = generate_project_cert(&ca_cert_pem, &ca_key_pem, &[]).unwrap();

        let pem = pem::parse(&cert_pem).unwrap();
        let (_, cert) = x509_parser::parse_x509_certificate(pem.contents()).unwrap();

        let san = cert.subject_alternative_name().unwrap().unwrap();
        let san_strs: Vec<String> = san
            .value
            .general_names
            .iter()
            .map(|n| format!("{n}"))
            .collect();

        assert!(
            san_strs.iter().any(|s| s.contains("localhost")),
            "missing localhost in SANs: {san_strs:?}"
        );
        // IP addresses are shown in hex by x509-parser: 127.0.0.1 = 7f:00:00:01
        assert!(
            san_strs.iter().any(|s| s.contains("7f:00:00:01")),
            "missing 127.0.0.1 in SANs: {san_strs:?}"
        );
    }

    #[test]
    fn project_cert_with_extra_hostnames() {
        let (ca_cert_pem, ca_key_pem) = ca::generate_ca().unwrap();
        let extras = vec!["myapp.test".to_string(), "192.168.1.42".to_string()];
        let (cert_pem, _) = generate_project_cert(&ca_cert_pem, &ca_key_pem, &extras).unwrap();

        let pem = pem::parse(&cert_pem).unwrap();
        let (_, cert) = x509_parser::parse_x509_certificate(pem.contents()).unwrap();

        let san = cert.subject_alternative_name().unwrap().unwrap();
        let san_strs: Vec<String> = san
            .value
            .general_names
            .iter()
            .map(|n| format!("{n}"))
            .collect();

        assert!(
            san_strs.iter().any(|s| s.contains("myapp.test")),
            "missing custom host: {san_strs:?}"
        );
        // 192.168.1.42 in hex = c0:a8:01:2a
        assert!(
            san_strs.iter().any(|s| s.contains("c0:a8:01:2a")),
            "missing custom IP: {san_strs:?}"
        );
    }

    #[test]
    fn project_cert_has_1_year_validity() {
        let (ca_cert_pem, ca_key_pem) = ca::generate_ca().unwrap();
        let (cert_pem, _) = generate_project_cert(&ca_cert_pem, &ca_key_pem, &[]).unwrap();

        let pem = pem::parse(&cert_pem).unwrap();
        let (_, cert) = x509_parser::parse_x509_certificate(pem.contents()).unwrap();

        let not_before = cert.validity().not_before.to_datetime();
        let not_after = cert.validity().not_after.to_datetime();
        let days = (not_after - not_before).whole_days();
        assert!(days >= 364 && days <= 366, "expected ~365 days, got {days}");
    }

    #[test]
    fn needs_renewal_for_fresh_cert() {
        let (ca_cert_pem, ca_key_pem) = ca::generate_ca().unwrap();
        let (cert_pem, _) = generate_project_cert(&ca_cert_pem, &ca_key_pem, &[]).unwrap();

        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), &cert_pem).unwrap();

        // Fresh cert should NOT need renewal
        assert!(!needs_renewal(tmp.path()).unwrap());
    }

    #[test]
    fn read_cert_info_works() {
        let (ca_cert_pem, ca_key_pem) = ca::generate_ca().unwrap();
        let (cert_pem, _) = generate_project_cert(&ca_cert_pem, &ca_key_pem, &[]).unwrap();

        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), &cert_pem).unwrap();

        let info = read_cert_info(tmp.path()).unwrap();
        assert_eq!(info.subject, "LPM Local Dev Server");
        assert_eq!(info.issuer, "LPM Local Development CA");
        assert!(!info.is_ca);
        assert!(!info.san_entries.is_empty());
    }
}
