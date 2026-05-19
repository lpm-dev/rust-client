//! Root Certificate Authority generation.
//!
//! Generates a self-signed root CA using ECDSA P-256 with an 825-day validity period.
//! This CA is used to sign per-project certificates for local HTTPS development.

use rcgen::{
    BasicConstraints, CertificateParams, CidrSubnet, DistinguishedName, DnType, GeneralSubtree,
    IsCa, KeyPair, KeyUsagePurpose, NameConstraints,
};
use std::str::FromStr;
use time::{Duration, OffsetDateTime};

/// Local-CA validity in days. Chosen as a product-security policy: bounded value of a
/// stolen offline key, comfortably > 2× the 365d leaf cadence in `cert.rs`. The 825d
/// number is familiar from CAB/F leaf rules — referenced as a recognizable anchor only;
/// CAB/F does not regulate private/local CAs.
pub const CA_VALIDITY_DAYS: i64 = 825;

const NAME_CONSTRAINTS_ENV: &str = "LPM_CERT_NAME_CONSTRAINTS";

/// Build the permitted-subtrees list for the local development CA.
///
/// RFC 5280 §4.2.1.10: DNS-name subtrees use leading-dot semantics for "any subdomain
/// of"; a bare entry only matches the exact name. The two-entry pattern below covers
/// both forms so e.g. `localhost` and `api.localhost` both validate.
fn permitted_subtrees() -> Vec<GeneralSubtree> {
    vec![
        GeneralSubtree::DnsName("localhost".into()),
        GeneralSubtree::DnsName(".localhost".into()),
        GeneralSubtree::DnsName(".local".into()),
        GeneralSubtree::DnsName(".lpm.test".into()),
        GeneralSubtree::DnsName(".test".into()),
        GeneralSubtree::IpAddress(
            CidrSubnet::from_str("127.0.0.0/8").expect("static loopback CIDR"),
        ),
        GeneralSubtree::IpAddress(
            CidrSubnet::from_str("::1/128").expect("static IPv6 loopback CIDR"),
        ),
        GeneralSubtree::IpAddress(CidrSubnet::from_str("10.0.0.0/8").expect("static RFC1918 /8")),
        GeneralSubtree::IpAddress(
            CidrSubnet::from_str("172.16.0.0/12").expect("static RFC1918 /12"),
        ),
        GeneralSubtree::IpAddress(
            CidrSubnet::from_str("192.168.0.0/16").expect("static RFC1918 /16"),
        ),
        GeneralSubtree::IpAddress(
            CidrSubnet::from_str("169.254.0.0/16").expect("static IPv4 link-local"),
        ),
        GeneralSubtree::IpAddress(CidrSubnet::from_str("fc00::/7").expect("static IPv6 ULA")),
        GeneralSubtree::IpAddress(
            CidrSubnet::from_str("fe80::/10").expect("static IPv6 link-local"),
        ),
    ]
}

/// Whether the env-flag gating NameConstraints is enabled for this process.
fn name_constraints_enabled() -> bool {
    matches!(
        std::env::var(NAME_CONSTRAINTS_ENV).as_deref(),
        Ok("1") | Ok("true") | Ok("yes") | Ok("on")
    )
}

/// Options for `generate_ca_with_options`.
#[derive(Debug, Clone, Copy, Default)]
pub struct CaOptions {
    /// If `true`, attach the RFC 5280 NameConstraints extension to the CA. Ignores
    /// the `LPM_CERT_NAME_CONSTRAINTS` env var.
    pub name_constraints: bool,
}

/// Generate a new root CA certificate and private key.
///
/// Returns `(cert_pem, key_pem)` as PEM-encoded strings.
///
/// NameConstraints are attached only when the `LPM_CERT_NAME_CONSTRAINTS` env var is
/// truthy (`1`/`true`/`yes`/`on`); the default omits the extension. Default-on requires
/// verified client-side enforcement across the supported browsers and TLS stacks.
pub fn generate_ca() -> Result<(String, String), Box<dyn std::error::Error>> {
    generate_ca_with_options(CaOptions {
        name_constraints: name_constraints_enabled(),
    })
}

/// Generate a new root CA with caller-supplied options. Tests use this to drive both
/// branches deterministically without mutating process env.
pub fn generate_ca_with_options(
    opts: CaOptions,
) -> Result<(String, String), Box<dyn std::error::Error>> {
    let mut params = CertificateParams::default();

    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "LPM Local Development CA");
    dn.push(DnType::OrganizationName, "LPM");
    params.distinguished_name = dn;

    // `Constrained(0)` forbids this CA from signing intermediates that themselves issue.
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];

    if opts.name_constraints {
        params.name_constraints = Some(NameConstraints {
            permitted_subtrees: permitted_subtrees(),
            excluded_subtrees: vec![],
        });
    }

    let now = OffsetDateTime::now_utc();
    params.not_before = now;
    params.not_after = now + Duration::days(CA_VALIDITY_DAYS);

    let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
    let cert = params.self_signed(&key_pair)?;

    Ok((cert.pem(), key_pair.serialize_pem()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_ca_produces_valid_pem() {
        let (cert_pem, key_pem) = generate_ca_with_options(CaOptions::default()).unwrap();

        assert!(cert_pem.starts_with("-----BEGIN CERTIFICATE-----"));
        assert!(cert_pem.ends_with("-----END CERTIFICATE-----\n"));
        assert!(key_pem.starts_with("-----BEGIN PRIVATE KEY-----"));
        assert!(key_pem.ends_with("-----END PRIVATE KEY-----\n"));
    }

    #[test]
    fn ca_cert_is_parseable() {
        let (cert_pem, _) = generate_ca_with_options(CaOptions::default()).unwrap();

        let pem = pem::parse(&cert_pem).unwrap();
        let (_, cert) = x509_parser::parse_x509_certificate(pem.contents()).unwrap();

        let bc = cert.basic_constraints().unwrap().unwrap();
        assert!(bc.value.ca);

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
        let (cert_pem, _) = generate_ca_with_options(CaOptions::default()).unwrap();

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
    fn ca_cert_has_825_day_validity() {
        let (cert_pem, _) = generate_ca_with_options(CaOptions::default()).unwrap();

        let pem = pem::parse(&cert_pem).unwrap();
        let (_, cert) = x509_parser::parse_x509_certificate(pem.contents()).unwrap();

        let not_before = cert.validity().not_before.to_datetime();
        let not_after = cert.validity().not_after.to_datetime();

        let days = (not_after - not_before).whole_days();
        assert!(
            (824..=826).contains(&days),
            "expected ~825 days, got {days}"
        );
    }

    #[test]
    fn ca_cert_has_no_name_constraints_by_default() {
        let (cert_pem, _) = generate_ca_with_options(CaOptions {
            name_constraints: false,
        })
        .unwrap();

        let pem = pem::parse(&cert_pem).unwrap();
        let (_, cert) = x509_parser::parse_x509_certificate(pem.contents()).unwrap();

        assert!(
            cert.name_constraints().unwrap().is_none(),
            "default build (flag off) must not emit NameConstraints"
        );
    }

    #[test]
    fn ca_cert_has_name_constraints_when_opted_in() {
        let (cert_pem, _) = generate_ca_with_options(CaOptions {
            name_constraints: true,
        })
        .unwrap();

        let pem = pem::parse(&cert_pem).unwrap();
        let (_, cert) = x509_parser::parse_x509_certificate(pem.contents()).unwrap();

        let nc_ext = cert
            .name_constraints()
            .unwrap()
            .expect("name_constraints extension must be present when flag is on");

        let permitted = nc_ext
            .value
            .permitted_subtrees
            .as_ref()
            .expect("permitted_subtrees must be present");
        assert!(
            !permitted.is_empty(),
            "permitted_subtrees must not be empty"
        );

        let dns_names: Vec<String> = permitted
            .iter()
            .filter_map(|s| match &s.base {
                x509_parser::extensions::GeneralName::DNSName(name) => Some(name.to_string()),
                _ => None,
            })
            .collect();
        assert!(
            dns_names.iter().any(|d| d == "localhost"),
            "expected bare `localhost` subtree, got {dns_names:?}"
        );
        assert!(
            dns_names.iter().any(|d| d == ".localhost"),
            "expected leading-dot `.localhost` subtree, got {dns_names:?}"
        );
        assert!(
            dns_names.iter().any(|d| d == ".local"),
            "expected `.local` subtree, got {dns_names:?}"
        );
        assert!(
            dns_names.iter().any(|d| d == ".test"),
            "expected `.test` subtree, got {dns_names:?}"
        );

        let has_ip_subtree = permitted
            .iter()
            .any(|s| matches!(s.base, x509_parser::extensions::GeneralName::IPAddress(_)));
        assert!(
            has_ip_subtree,
            "expected at least one IP-address permitted subtree"
        );
    }

    #[test]
    fn ca_cert_name_constraints_is_critical_when_opted_in() {
        let (cert_pem, _) = generate_ca_with_options(CaOptions {
            name_constraints: true,
        })
        .unwrap();

        let pem = pem::parse(&cert_pem).unwrap();
        let (_, cert) = x509_parser::parse_x509_certificate(pem.contents()).unwrap();

        let nc_ext = cert
            .name_constraints()
            .unwrap()
            .expect("name_constraints extension required");
        assert!(
            nc_ext.critical,
            "RFC 5280 §4.2.1.10: NameConstraints SHOULD be marked critical so non-honoring clients reject the chain"
        );
    }
}
