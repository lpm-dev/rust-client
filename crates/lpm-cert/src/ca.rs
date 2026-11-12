//! Root Certificate Authority generation.
//!
//! Generates a self-signed root CA using ECDSA P-256 with an 825-day validity period.
//! This CA is used to sign per-project certificates for local HTTPS development.

use lpm_common::LpmError;
use rcgen::{
    BasicConstraints, CertificateParams, CidrSubnet, DistinguishedName, DnType, GeneralSubtree,
    IsCa, KeyPair, KeyUsagePurpose, NameConstraints,
};
use std::path::Path;
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
        // The private-use names `cert.extraPermittedDns` accepts without
        // `allowPublicDns`, as `name_constraints` lists them.
        GeneralSubtree::DnsName(".internal".into()),
        GeneralSubtree::DnsName(".home.arpa".into()),
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

/// The organizational unit of a CA LPM made without name constraints because
/// it was asked to, which tells it apart from one an earlier release made
/// without them. The common name stays as it was: trust stores are searched
/// by it.
const UNCONSTRAINED_UNIT: &str = "Not limited to local names, as asked";

/// The names [`permitted_subtrees`] lets a constrained CA sign, as a person
/// reads them.
pub const PERMITTED_NAMES_SUMMARY: &str = "localhost, *.localhost, *.local, *.test, *.lpm.test, \
     *.internal, *.home.arpa, loopback, private and link-local addresses";

/// What `LPM_CERT_NAME_CONSTRAINTS` asks for: `Some(false)` for `0`, `false`,
/// `no` or `off`; `Some(true)` for any other value; `None` when it is unset.
pub fn name_constraints_override() -> Option<bool> {
    let value = std::env::var(NAME_CONSTRAINTS_ENV).ok()?;
    Some(!matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "0" | "false" | "no" | "off"
    ))
}

/// Whether a new CA is limited to local names: unless
/// `LPM_CERT_NAME_CONSTRAINTS` turns that off. Verified to be enforced by
/// Windows CryptoAPI, macOS's Security framework and OpenSSL.
pub fn wants_name_constraints() -> bool {
    name_constraints_override().unwrap_or(true)
}

/// Whether the PEM-encoded CA was made without name constraints because it
/// was asked to, by `lpm cert rotate --no-name-constraints` or
/// `LPM_CERT_NAME_CONSTRAINTS=0`.
pub fn cert_declines_name_constraints_bytes(cert_pem: &[u8]) -> Result<bool, LpmError> {
    let pem = pem::parse(cert_pem)
        .map_err(|e| LpmError::Cert(format!("invalid CA certificate PEM: {e}")))?;
    let (_, cert) = x509_parser::parse_x509_certificate(pem.contents())
        .map_err(|e| LpmError::Cert(format!("invalid CA X.509: {e}")))?;
    Ok(cert
        .subject()
        .iter_organizational_unit()
        .any(|unit| unit.as_str() == Ok(UNCONSTRAINED_UNIT)))
}

/// Of `hostnames`, names or addresses a certificate would name, and
/// `subtrees`, DNS subtrees a project intermediate would permit, the ones the
/// PEM-encoded CA's name constraints don't wholly permit; none when it has no
/// constraints.
pub fn names_outside_constraints(
    cert_pem: &[u8],
    hostnames: &[String],
    subtrees: &[String],
) -> Result<Vec<String>, LpmError> {
    crate::cert::names_outside_root(cert_pem, hostnames, subtrees)
}

/// [`names_outside_constraints`] for a CA this release would make limited to
/// local names: what only an unconstrained CA could sign.
pub fn names_outside_local_names(
    hostnames: &[String],
    subtrees: &[String],
) -> Result<Vec<String>, LpmError> {
    let (local, _) = generate_ca_with_options(CaOptions {
        name_constraints: true,
    })
    .map_err(|error| LpmError::Cert(format!("failed to model the local-names CA: {error}")))?;
    names_outside_constraints(local.as_bytes(), hostnames, subtrees)
}

/// The PEM-encoded CA's name constraints as a person reads them; `None`
/// when it has none.
pub fn constraints_summary(cert_pem: &[u8]) -> Result<Option<Vec<String>>, LpmError> {
    crate::cert::constraints_summary(cert_pem)
}

/// True iff the PEM-encoded CA at `path` carries a NameConstraints extension.
///
/// Returns `Err` if the file is unreadable or not a valid X.509 cert; returns
/// `Ok(false)` if the file is a valid cert but the extension is absent.
pub fn cert_has_name_constraints(path: &Path) -> Result<bool, LpmError> {
    let pem_str =
        lpm_common::read_text_file_capped(path, lpm_common::TLS_MATERIAL_FILE_SIZE_CAP_BYTES)
            .map_err(|e| {
                LpmError::Cert(format!("failed to read CA cert at {}: {e}", path.display()))
            })?;
    cert_has_name_constraints_bytes(pem_str.as_bytes())
}

pub(crate) fn cert_has_name_constraints_bytes(cert_pem: &[u8]) -> Result<bool, LpmError> {
    let pem = pem::parse(cert_pem)
        .map_err(|e| LpmError::Cert(format!("invalid CA certificate PEM: {e}")))?;
    let (_, cert) = x509_parser::parse_x509_certificate(pem.contents())
        .map_err(|e| LpmError::Cert(format!("invalid CA X.509: {e}")))?;

    Ok(cert
        .name_constraints()
        .map_err(|e| LpmError::Cert(format!("failed to parse name constraints: {e}")))?
        .is_some())
}

/// True iff the PEM-encoded root CA at `path` is allowed to sign a project
/// intermediate CA.
pub fn cert_allows_project_intermediates(path: &Path) -> Result<bool, LpmError> {
    let pem_str =
        lpm_common::read_text_file_capped(path, lpm_common::TLS_MATERIAL_FILE_SIZE_CAP_BYTES)
            .map_err(|e| {
                LpmError::Cert(format!("failed to read CA cert at {}: {e}", path.display()))
            })?;
    cert_allows_project_intermediates_bytes(pem_str.as_bytes())
}

pub(crate) fn cert_allows_project_intermediates_bytes(cert_pem: &[u8]) -> Result<bool, LpmError> {
    let pem = pem::parse(cert_pem)
        .map_err(|e| LpmError::Cert(format!("invalid CA certificate PEM: {e}")))?;
    let (_, cert) = x509_parser::parse_x509_certificate(pem.contents())
        .map_err(|e| LpmError::Cert(format!("invalid CA X.509: {e}")))?;

    let Some(basic_constraints) = cert
        .basic_constraints()
        .map_err(|e| LpmError::Cert(format!("failed to parse basic constraints: {e}")))?
    else {
        return Ok(false);
    };

    if !basic_constraints.value.ca {
        return Ok(false);
    }

    Ok(basic_constraints
        .value
        .path_len_constraint
        .is_none_or(|path_len| path_len >= 1))
}

/// Options for `generate_ca_with_options`.
#[derive(Debug, Clone, Copy, Default)]
pub struct CaOptions {
    /// If `true`, attach the RFC 5280 NameConstraints extension to the CA;
    /// if `false`, mark it as made without them on request. Ignores the
    /// `LPM_CERT_NAME_CONSTRAINTS` env var.
    pub name_constraints: bool,
}

/// Generate a new root CA certificate and private key.
///
/// Returns `(cert_pem, key_pem)` as PEM-encoded strings.
///
/// NameConstraints limit it to local names unless `LPM_CERT_NAME_CONSTRAINTS` is `0`,
/// `false`, `no` or `off`, which marks it as unconstrained on request.
pub fn generate_ca() -> Result<(String, String), Box<dyn std::error::Error>> {
    generate_ca_with_options(CaOptions {
        name_constraints: wants_name_constraints(),
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
    if !opts.name_constraints {
        dn.push(DnType::OrganizationalUnitName, UNCONSTRAINED_UNIT);
    }
    params.distinguished_name = dn;

    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(1));
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

    /// A new CA is limited to local names unless `LPM_CERT_NAME_CONSTRAINTS`
    /// turns that off, and one made unlimited so is marked as asked for.
    #[test]
    fn new_cas_are_limited_to_local_names_unless_asked_not_to() {
        let _serial = crate::test_env_lock();
        let previous = std::env::var_os(NAME_CONSTRAINTS_ENV);
        let generated = |value: Option<&str>| {
            // SAFETY: the test env lock serializes this process's env.
            unsafe {
                match value {
                    Some(value) => std::env::set_var(NAME_CONSTRAINTS_ENV, value),
                    None => std::env::remove_var(NAME_CONSTRAINTS_ENV),
                }
            }
            let (cert, _) = generate_ca().unwrap();
            (
                cert_has_name_constraints_bytes(cert.as_bytes()).unwrap(),
                cert_declines_name_constraints_bytes(cert.as_bytes()).unwrap(),
            )
        };
        let results = [None, Some("1"), Some("0"), Some("off"), Some("FALSE")].map(generated);
        // SAFETY: as above.
        unsafe {
            match previous {
                Some(value) => std::env::set_var(NAME_CONSTRAINTS_ENV, value),
                None => std::env::remove_var(NAME_CONSTRAINTS_ENV),
            }
        }
        assert_eq!(
            results,
            [
                (true, false),
                (true, false),
                (false, true),
                (false, true),
                (false, true)
            ]
        );
    }

    /// The names a project asks for that a constrained CA may not sign are
    /// the ones named; an unconstrained CA may sign any.
    #[test]
    fn names_a_constrained_ca_may_not_sign_are_named() {
        let (constrained, _) = generate_ca_with_options(CaOptions {
            name_constraints: true,
        })
        .unwrap();
        let hostnames = [
            "localhost",
            "app.localhost",
            "myapp.local",
            "x.lpm.test",
            "app.internal",
            "router.home.arpa",
            "127.0.0.1",
            "192.168.1.20",
            "::1",
            "fe80::1",
            "staging.example.com",
            "local",
            "8.8.8.8",
        ]
        .map(str::to_owned);
        let subtrees =
            ["myapp.local", ".api.test", "example.dev", ".example.dev"].map(str::to_owned);

        assert_eq!(
            names_outside_constraints(constrained.as_bytes(), &hostnames, &subtrees).unwrap(),
            [
                "staging.example.com",
                "local",
                "8.8.8.8",
                "example.dev",
                ".example.dev"
            ]
        );
        let (unconstrained, _) = generate_ca_with_options(CaOptions::default()).unwrap();
        assert!(
            names_outside_constraints(unconstrained.as_bytes(), &hostnames, &subtrees)
                .unwrap()
                .is_empty()
        );
    }

    /// A subtree is permitted only when all of it is: within a permitted
    /// subtree, with no excluded one reaching into it.
    #[test]
    fn a_subtree_with_an_excluded_part_is_not_permitted() {
        let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let mut params = CertificateParams::default();
        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(1));
        params.name_constraints = Some(NameConstraints {
            permitted_subtrees: vec![GeneralSubtree::DnsName(".test".into())],
            excluded_subtrees: vec![GeneralSubtree::DnsName("blocked.team.test".into())],
        });
        let root = params.self_signed(&key).unwrap().pem();
        let subtrees = [
            "team.test",
            ".team.test",
            "blocked.team.test",
            "other.test",
            ".other.test",
            "test",
        ]
        .map(str::to_owned);

        assert_eq!(
            names_outside_constraints(root.as_bytes(), &[], &subtrees).unwrap(),
            ["team.test", ".team.test", "blocked.team.test", "test"]
        );
        assert_eq!(
            constraints_summary(root.as_bytes()).unwrap(),
            Some(vec![
                "*.test".to_string(),
                "not blocked.team.test".to_string()
            ])
        );
    }

    /// The consent lists the names the CA itself permits.
    #[test]
    fn a_constrained_cas_summary_lists_its_own_names() {
        let (constrained, _) = generate_ca_with_options(CaOptions {
            name_constraints: true,
        })
        .unwrap();
        let summary = constraints_summary(constrained.as_bytes())
            .unwrap()
            .unwrap();
        for name in [
            "localhost",
            "*.local",
            "*.internal",
            "127.0.0.0/8",
            "::1/128",
            "fe80::/10",
        ] {
            assert!(
                summary.iter().any(|entry| entry == name),
                "{name}: {summary:?}"
            );
        }
        let (unconstrained, _) = generate_ca_with_options(CaOptions::default()).unwrap();
        assert_eq!(constraints_summary(unconstrained.as_bytes()).unwrap(), None);
    }

    #[test]
    fn generate_ca_produces_valid_pem() {
        let (cert_pem, key_pem) = generate_ca_with_options(CaOptions::default()).unwrap();

        assert!(cert_pem.starts_with("-----BEGIN CERTIFICATE-----"));
        assert_eq!(cert_pem.lines().last(), Some("-----END CERTIFICATE-----"));
        assert!(key_pem.starts_with("-----BEGIN PRIVATE KEY-----"));
        assert_eq!(key_pem.lines().last(), Some("-----END PRIVATE KEY-----"));
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
    fn ca_cert_allows_exactly_one_intermediate_ca() {
        let (cert_pem, _) = generate_ca_with_options(CaOptions::default()).unwrap();

        let pem = pem::parse(&cert_pem).unwrap();
        let (_, cert) = x509_parser::parse_x509_certificate(pem.contents()).unwrap();

        let bc = cert.basic_constraints().unwrap().unwrap();
        assert!(bc.value.ca, "certificate should be a CA");
        assert_eq!(
            bc.value.path_len_constraint,
            Some(1),
            "CA pathLenConstraint should allow one project-scoped intermediate"
        );
    }

    #[test]
    fn cert_allows_project_intermediates_rejects_path_length_zero_roots() {
        let mut params = CertificateParams::default();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "Legacy LPM Local Development CA");
        dn.push(DnType::OrganizationName, "LPM");
        params.distinguished_name = dn;
        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];

        let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let cert = params.self_signed(&key_pair).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rootCA.pem");
        std::fs::write(&path, cert.pem()).unwrap();

        assert!(!cert_allows_project_intermediates(&path).unwrap());
    }

    #[test]
    fn cert_allows_project_intermediates_accepts_new_roots() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rootCA.pem");
        let (cert_pem, _) = generate_ca_with_options(CaOptions::default()).unwrap();
        std::fs::write(&path, cert_pem).unwrap();

        assert!(cert_allows_project_intermediates(&path).unwrap());
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
    fn a_ca_made_without_name_constraints_has_none() {
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

    #[test]
    fn cert_has_name_constraints_returns_false_for_unconstrained_ca() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rootCA.pem");
        let (cert_pem, _) = generate_ca_with_options(CaOptions {
            name_constraints: false,
        })
        .unwrap();
        std::fs::write(&path, &cert_pem).unwrap();

        assert!(!cert_has_name_constraints(&path).unwrap());
    }

    #[test]
    fn cert_has_name_constraints_returns_true_for_constrained_ca() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rootCA.pem");
        let (cert_pem, _) = generate_ca_with_options(CaOptions {
            name_constraints: true,
        })
        .unwrap();
        std::fs::write(&path, &cert_pem).unwrap();

        assert!(cert_has_name_constraints(&path).unwrap());
    }
}
