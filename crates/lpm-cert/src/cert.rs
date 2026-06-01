//! Project certificate generation and management.
//!
//! Generates certificates signed by the LPM root CA for use with local dev servers.
//! Default SANs: localhost, 127.0.0.1, ::1 — plus any user-specified hostnames.

use lpm_common::LpmError;
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, CidrSubnet, DistinguishedName, DnType,
    GeneralSubtree, IsCa, KeyPair, KeyUsagePurpose, NameConstraints, SanType,
};
use sha1::Digest as _;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;
use std::str::FromStr;
use time::{Duration, OffsetDateTime};
use x509_parser::extensions::GeneralName;

/// SHA-256 fingerprint of the DER body of a PEM-encoded certificate at `path`.
///
/// "Fingerprint" in X.509 always means the digest of the DER body, never of the PEM
/// envelope. macOS `security` and openssl both emit it as colon-separated uppercase
/// hex (`AB:CD:…`); callers convert via `fingerprint_hex`.
pub fn fingerprint_sha256(path: &Path) -> Result<[u8; 32], LpmError> {
    let der = read_cert_der(path)?;
    Ok(sha2::Sha256::digest(&der).into())
}

/// SHA-1 fingerprint (thumbprint) of the DER body of a PEM-encoded cert. SHA-1 is the
/// identifier Windows `certutil` accepts as a `-store` search key — kept for that
/// platform's lookup only, not for cryptographic binding.
pub fn fingerprint_sha1(path: &Path) -> Result<[u8; 20], LpmError> {
    let der = read_cert_der(path)?;
    Ok(sha1::Sha1::digest(&der).into())
}

/// Format a fingerprint as uppercase colon-separated hex (`AB:CD:EF:…`).
pub fn fingerprint_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 3);
    for (i, b) in bytes.iter().enumerate() {
        if i > 0 {
            out.push(':');
        }
        out.push_str(&format!("{b:02X}"));
    }
    out
}

fn read_cert_der(path: &Path) -> Result<Vec<u8>, LpmError> {
    let pem_str = std::fs::read_to_string(path)
        .map_err(|e| LpmError::Cert(format!("failed to read cert at {}: {e}", path.display())))?;
    let pem = pem::parse(&pem_str)
        .map_err(|e| LpmError::Cert(format!("invalid PEM at {}: {e}", path.display())))?;
    Ok(pem.into_contents())
}

fn read_cert_chain_der(path: &Path) -> Result<Vec<Vec<u8>>, LpmError> {
    let pem_str = std::fs::read_to_string(path)
        .map_err(|e| LpmError::Cert(format!("failed to read cert at {}: {e}", path.display())))?;
    let pems = pem::parse_many(&pem_str)
        .map_err(|e| LpmError::Cert(format!("invalid PEM at {}: {e}", path.display())))?;
    if pems.is_empty() {
        return Err(LpmError::Cert(format!(
            "no certificate PEM blocks found at {}",
            path.display()
        )));
    }
    Ok(pems.into_iter().map(pem::Pem::into_contents).collect())
}

/// A `cert.pem` SAN entry, decoded from the X.509 extension into a form callers can
/// hand straight back to `rcgen` for reissue. Display-formatted strings from
/// `x509_parser::GeneralName` (`DNSName("foo")`, `IPAddress(...)`) are not safe to
/// round-trip — this enum is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SanEntry {
    Dns(String),
    Ip(IpAddr),
}

impl SanEntry {
    /// String form suitable for `generate_project_cert`'s `extra_hostnames` slice:
    /// the bare DNS name, or the canonical IP literal. Both round-trip correctly
    /// through the SAN parser in `cert::generate_project_cert`.
    pub fn as_extra_hostname(&self) -> String {
        match self {
            SanEntry::Dns(s) => s.clone(),
            SanEntry::Ip(ip) => ip.to_string(),
        }
    }
}

/// Decode every SAN in the leaf at `path` to a typed `SanEntry`. Skips entries
/// the rotation reissue flow cannot reproduce (URI, RFC822, X400, etc.) — these
/// are not used by `lpm-cert::generate_project_cert`.
pub fn read_san_entries(path: &Path) -> Result<Vec<SanEntry>, LpmError> {
    let pem_str = std::fs::read_to_string(path)
        .map_err(|e| LpmError::Cert(format!("failed to read cert at {}: {e}", path.display())))?;
    let pem = pem::parse(&pem_str)
        .map_err(|e| LpmError::Cert(format!("invalid PEM at {}: {e}", path.display())))?;
    let (_, cert) = x509_parser::parse_x509_certificate(pem.contents())
        .map_err(|e| LpmError::Cert(format!("invalid X.509 at {}: {e}", path.display())))?;

    let Some(san_ext) = cert.subject_alternative_name().ok().flatten() else {
        return Ok(Vec::new());
    };

    let mut out: Vec<SanEntry> = Vec::with_capacity(san_ext.value.general_names.len());
    for gn in &san_ext.value.general_names {
        match gn {
            GeneralName::DNSName(name) => out.push(SanEntry::Dns(name.to_string())),
            GeneralName::IPAddress(bytes) => match bytes.len() {
                4 => {
                    let arr: [u8; 4] = (*bytes).try_into().unwrap();
                    out.push(SanEntry::Ip(IpAddr::V4(Ipv4Addr::from(arr))));
                }
                16 => {
                    let arr: [u8; 16] = (*bytes).try_into().unwrap();
                    out.push(SanEntry::Ip(IpAddr::V6(Ipv6Addr::from(arr))));
                }
                _ => {
                    tracing::debug!(
                        "skipping IP-address SAN with non-{{4,16}} length: {}",
                        bytes.len()
                    );
                }
            },
            _ => {}
        }
    }
    Ok(out)
}

/// Verify that the leaf at `leaf_path` was signed by the CA at `ca_path`. Returns
/// `Ok(true)` on a verifying chain; `Ok(false)` on any verification failure
/// (mismatched issuer/subject, bad signature). Errors only on unreadable input.
///
/// Used by `ensure_https` to detect "leaf chained to old CA after rotation" and
/// trigger re-issuance against the active root.
pub fn leaf_signed_by(leaf_path: &Path, ca_path: &Path) -> Result<bool, LpmError> {
    let leaf_der = read_cert_der(leaf_path)?;
    let ca_der = read_cert_der(ca_path)?;
    let (_, leaf) = x509_parser::parse_x509_certificate(&leaf_der)
        .map_err(|e| LpmError::Cert(format!("invalid leaf X.509: {e}")))?;
    let (_, ca) = x509_parser::parse_x509_certificate(&ca_der)
        .map_err(|e| LpmError::Cert(format!("invalid CA X.509: {e}")))?;
    if leaf.issuer() != ca.subject() {
        return Ok(false);
    }
    Ok(leaf.verify_signature(Some(ca.public_key())).is_ok())
}

/// Verify that the project certificate at `cert_path` chains to the root CA at
/// `root_path`. Accepts the legacy direct root-signed leaf format and the newer
/// leaf-plus-project-intermediate PEM chain format.
pub fn project_cert_chains_to_root(cert_path: &Path, root_path: &Path) -> Result<bool, LpmError> {
    let cert_chain = read_cert_chain_der(cert_path)?;
    let root_der = read_cert_der(root_path)?;
    let (_, leaf) = x509_parser::parse_x509_certificate(&cert_chain[0])
        .map_err(|e| LpmError::Cert(format!("invalid leaf X.509: {e}")))?;
    let (_, root) = x509_parser::parse_x509_certificate(&root_der)
        .map_err(|e| LpmError::Cert(format!("invalid root X.509: {e}")))?;

    if leaf.issuer() == root.subject() {
        return Ok(leaf.verify_signature(Some(root.public_key())).is_ok());
    }

    let Some(intermediate_der) = cert_chain.get(1) else {
        return Ok(false);
    };
    let (_, intermediate) = x509_parser::parse_x509_certificate(intermediate_der)
        .map_err(|e| LpmError::Cert(format!("invalid intermediate X.509: {e}")))?;

    let Some(basic_constraints) = intermediate
        .basic_constraints()
        .map_err(|e| LpmError::Cert(format!("failed to parse intermediate constraints: {e}")))?
    else {
        return Ok(false);
    };

    if !basic_constraints.value.ca
        || leaf.issuer() != intermediate.subject()
        || intermediate.issuer() != root.subject()
    {
        return Ok(false);
    }
    if leaf
        .verify_signature(Some(intermediate.public_key()))
        .is_err()
    {
        return Ok(false);
    }

    Ok(intermediate
        .verify_signature(Some(root.public_key()))
        .is_ok())
}

/// True when `cert_path` contains a leaf plus at least one intermediate cert.
pub fn project_cert_has_intermediate(cert_path: &Path) -> Result<bool, LpmError> {
    Ok(read_cert_chain_der(cert_path)?.len() > 1)
}

/// Return DNS permitted-subtree entries from the project intermediate in
/// `cert_path`. Direct root-signed leaf files return an empty list.
pub fn read_project_dns_constraints(cert_path: &Path) -> Result<Vec<String>, LpmError> {
    let cert_chain = read_cert_chain_der(cert_path)?;
    let Some(intermediate_der) = cert_chain.get(1) else {
        return Ok(Vec::new());
    };
    let (_, intermediate) = x509_parser::parse_x509_certificate(intermediate_der)
        .map_err(|e| LpmError::Cert(format!("invalid intermediate X.509: {e}")))?;
    let Some(constraints) = intermediate
        .name_constraints()
        .map_err(|e| LpmError::Cert(format!("failed to parse intermediate constraints: {e}")))?
    else {
        return Ok(Vec::new());
    };
    let Some(permitted) = constraints.value.permitted_subtrees.as_ref() else {
        return Ok(Vec::new());
    };

    let mut dns_constraints = Vec::with_capacity(permitted.len());
    for subtree in permitted {
        if let GeneralName::DNSName(name) = &subtree.base {
            dns_constraints.push(name.to_ascii_lowercase());
        }
    }
    Ok(dns_constraints)
}

/// Check whether an existing project certificate's intermediate permits the
/// requested DNS names and configured extra DNS subtrees.
pub fn project_cert_constraints_cover_dns(
    cert_path: &Path,
    requested_hostnames: &[String],
    extra_permitted_dns_subtrees: &[String],
) -> Result<bool, LpmError> {
    let mut required =
        Vec::with_capacity(requested_hostnames.len() + extra_permitted_dns_subtrees.len());
    for hostname in requested_hostnames {
        if hostname.parse::<IpAddr>().is_err() {
            push_unique_string(&mut required, hostname.to_ascii_lowercase());
        }
    }
    for subtree in extra_permitted_dns_subtrees {
        push_unique_string(&mut required, subtree.to_ascii_lowercase());
    }
    if required.is_empty() {
        return Ok(true);
    }

    let constraints = read_project_dns_constraints(cert_path)?;
    if constraints.is_empty() {
        return Ok(false);
    }

    Ok(required
        .iter()
        .all(|required| constraints.iter().any(|actual| actual == required)))
}

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
/// Default SANs: `localhost`, `127.0.0.1`, `::1`
/// Additional hostnames are appended from `extra_hostnames`.
///
/// Returns `(cert_pem, key_pem)` as PEM-encoded strings.
pub fn generate_project_cert(
    ca_cert_pem: &str,
    ca_key_pem: &str,
    extra_hostnames: &[String],
) -> Result<(String, String), Box<dyn std::error::Error>> {
    let (ca_cert, ca_key_pair) = issuer_from_ca_pem(ca_cert_pem, ca_key_pem)?;
    let params = project_leaf_params(extra_hostnames)?;
    let project_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
    let project_cert = params.signed_by(&project_key, &ca_cert, &ca_key_pair)?;

    Ok((project_cert.pem(), project_key.serialize_pem()))
}

/// Generate a leaf certificate chain signed by a project-scoped constrained
/// intermediate CA.
///
/// The returned cert PEM is ordered for TLS servers: leaf first, then the
/// intermediate certificate. The root CA remains the trust anchor and is not
/// appended to the chain.
pub fn generate_project_cert_with_constrained_intermediate(
    ca_cert_pem: &str,
    ca_key_pem: &str,
    extra_hostnames: &[String],
    extra_permitted_dns_subtrees: &[String],
) -> Result<(String, String), Box<dyn std::error::Error>> {
    let (ca_cert, ca_key_pair) = issuer_from_ca_pem(ca_cert_pem, ca_key_pem)?;
    let intermediate_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
    let intermediate_params =
        project_intermediate_params(extra_hostnames, extra_permitted_dns_subtrees)?;
    let intermediate_cert =
        intermediate_params.signed_by(&intermediate_key, &ca_cert, &ca_key_pair)?;

    let project_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
    let leaf_params = project_leaf_params(extra_hostnames)?;
    let leaf_cert = leaf_params.signed_by(&project_key, &intermediate_cert, &intermediate_key)?;
    let chain_pem = format!("{}{}", leaf_cert.pem(), intermediate_cert.pem());

    Ok((chain_pem, project_key.serialize_pem()))
}

fn issuer_from_ca_pem(
    ca_cert_pem: &str,
    ca_key_pem: &str,
) -> Result<(Certificate, KeyPair), Box<dyn std::error::Error>> {
    let ca_key_pair = KeyPair::from_pem(ca_key_pem)?;
    let ca_cert_params = CertificateParams::from_ca_cert_pem(ca_cert_pem)?;
    let ca_cert = ca_cert_params.self_signed(&ca_key_pair)?;
    Ok((ca_cert, ca_key_pair))
}

fn project_leaf_params(
    extra_hostnames: &[String],
) -> Result<CertificateParams, Box<dyn std::error::Error>> {
    let mut params = CertificateParams::default();

    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "LPM Local Dev Server");
    dn.push(DnType::OrganizationName, "LPM");
    params.distinguished_name = dn;

    params.is_ca = IsCa::NoCa;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
    params.use_authority_key_identifier_extension = true;

    let now = OffsetDateTime::now_utc();
    params.not_before = now;
    params.not_after = now + Duration::days(365);
    params.subject_alt_names = project_subject_alt_names(extra_hostnames)?;

    Ok(params)
}

fn project_intermediate_params(
    extra_hostnames: &[String],
    extra_permitted_dns_subtrees: &[String],
) -> Result<CertificateParams, Box<dyn std::error::Error>> {
    let mut params = CertificateParams::default();

    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "LPM Project Development CA");
    dn.push(DnType::OrganizationName, "LPM");
    params.distinguished_name = dn;

    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params.name_constraints = Some(NameConstraints {
        permitted_subtrees: project_permitted_subtrees(
            extra_hostnames,
            extra_permitted_dns_subtrees,
        )?,
        excluded_subtrees: Vec::new(),
    });
    params.use_authority_key_identifier_extension = true;

    let now = OffsetDateTime::now_utc();
    params.not_before = now;
    params.not_after = now + Duration::days(365);

    Ok(params)
}

fn project_subject_alt_names(
    extra_hostnames: &[String],
) -> Result<Vec<SanType>, Box<dyn std::error::Error>> {
    let mut sans = Vec::with_capacity(3 + extra_hostnames.len());
    sans.push(SanType::DnsName("localhost".try_into()?));
    sans.push(SanType::IpAddress(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))));
    sans.push(SanType::IpAddress(IpAddr::V6(Ipv6Addr::LOCALHOST)));

    for hostname in extra_hostnames {
        if let Ok(ip) = hostname.parse::<IpAddr>() {
            sans.push(SanType::IpAddress(ip));
        } else {
            sans.push(SanType::DnsName(hostname.clone().try_into()?));
        }
    }

    Ok(sans)
}

fn project_permitted_subtrees(
    extra_hostnames: &[String],
    extra_permitted_dns_subtrees: &[String],
) -> Result<Vec<GeneralSubtree>, Box<dyn std::error::Error>> {
    let mut subtrees =
        Vec::with_capacity(3 + extra_hostnames.len() + extra_permitted_dns_subtrees.len());
    push_dns_subtree_unique(&mut subtrees, "localhost")?;
    subtrees.push(cidr_subtree("127.0.0.1/32")?);
    subtrees.push(cidr_subtree("::1/128")?);

    for hostname in extra_hostnames {
        if let Ok(ip) = hostname.parse::<IpAddr>() {
            subtrees.push(ip_subtree(ip)?);
        } else {
            push_dns_subtree_unique(&mut subtrees, hostname)?;
        }
    }
    for subtree in extra_permitted_dns_subtrees {
        push_dns_subtree_unique(&mut subtrees, subtree)?;
    }

    Ok(subtrees)
}

fn push_dns_subtree_unique(
    subtrees: &mut Vec<GeneralSubtree>,
    subtree: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let normalized = normalize_dns_constraint_subtree(subtree)?;
    if !subtrees
        .iter()
        .any(|existing| matches!(existing, GeneralSubtree::DnsName(name) if name == &normalized))
    {
        subtrees.push(GeneralSubtree::DnsName(normalized));
    }
    Ok(())
}

fn normalize_dns_constraint_subtree(subtree: &str) -> Result<String, Box<dyn std::error::Error>> {
    let normalized = subtree.trim().to_ascii_lowercase();
    let bare = normalized.strip_prefix('.').unwrap_or(&normalized);
    let invalid = normalized.is_empty()
        || bare.is_empty()
        || (bare != "localhost" && !bare.contains('.'))
        || bare.contains("..")
        || bare.ends_with('.')
        || bare.starts_with('-')
        || bare.ends_with('-')
        || bare.contains(char::is_whitespace)
        || bare
            .bytes()
            .any(|byte| !(byte.is_ascii_alphanumeric() || byte == b'.' || byte == b'-'));
    if invalid {
        return Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("invalid DNS name-constraint subtree {subtree:?}"),
        )));
    }
    Ok(normalized)
}

fn push_unique_string(values: &mut Vec<String>, value: String) {
    if !values.iter().any(|existing| existing == &value) {
        values.push(value);
    }
}

fn ip_subtree(ip: IpAddr) -> Result<GeneralSubtree, Box<dyn std::error::Error>> {
    let cidr = match ip {
        IpAddr::V4(ip) => format!("{ip}/32"),
        IpAddr::V6(ip) => format!("{ip}/128"),
    };
    cidr_subtree(&cidr)
}

fn cidr_subtree(cidr: &str) -> Result<GeneralSubtree, Box<dyn std::error::Error>> {
    let subnet = CidrSubnet::from_str(cidr).map_err(|()| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("invalid IP name-constraint CIDR {cidr}"),
        )
    })?;
    Ok(GeneralSubtree::IpAddress(subnet))
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

/// Check whether a certificate already covers the requested extra hostnames.
pub fn covers_requested_hostnames(
    cert_path: &Path,
    requested_hostnames: &[String],
) -> Result<bool, LpmError> {
    if requested_hostnames.is_empty() {
        return Ok(true);
    }

    let pem_str = std::fs::read_to_string(cert_path)
        .map_err(|e| LpmError::Cert(format!("failed to read cert: {e}")))?;

    let pem = pem::parse(&pem_str).map_err(|e| LpmError::Cert(format!("invalid PEM: {e}")))?;

    let (_, cert) = x509_parser::parse_x509_certificate(pem.contents())
        .map_err(|e| LpmError::Cert(format!("invalid X.509: {e}")))?;

    let Some(san) = cert.subject_alternative_name().ok().flatten() else {
        return Ok(false);
    };

    Ok(requested_hostnames.iter().all(|requested_hostname| {
        san.value
            .general_names
            .iter()
            .any(|name| general_name_matches_requested_host(name, requested_hostname))
    }))
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
        .is_some_and(|bc| bc.value.ca);

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

fn general_name_matches_requested_host(name: &GeneralName<'_>, requested_host: &str) -> bool {
    if let Ok(ip) = requested_host.parse::<IpAddr>() {
        return match (ip, name) {
            (IpAddr::V4(ip), GeneralName::IPAddress(bytes)) => *bytes == ip.octets().as_slice(),
            (IpAddr::V6(ip), GeneralName::IPAddress(bytes)) => *bytes == ip.octets().as_slice(),
            _ => false,
        };
    }

    matches!(name, GeneralName::DNSName(hostname) if *hostname == requested_host)
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
    fn constrained_project_cert_contains_leaf_and_intermediate_chain() {
        let (ca_cert_pem, ca_key_pem) = ca::generate_ca().unwrap();
        let extras = vec!["myapp.test".to_string(), "192.168.1.42".to_string()];
        let (cert_pem, key_pem) = generate_project_cert_with_constrained_intermediate(
            &ca_cert_pem,
            &ca_key_pem,
            &extras,
            &[],
        )
        .unwrap();

        assert!(key_pem.starts_with("-----BEGIN PRIVATE KEY-----"));
        let chain = pem::parse_many(&cert_pem).unwrap();
        assert_eq!(chain.len(), 2, "TLS chain should be leaf + intermediate");

        let (_, leaf) = x509_parser::parse_x509_certificate(chain[0].contents()).unwrap();
        let (_, intermediate) = x509_parser::parse_x509_certificate(chain[1].contents()).unwrap();
        let leaf_issuer = leaf
            .issuer()
            .iter_common_name()
            .next()
            .unwrap()
            .as_str()
            .unwrap();
        assert_eq!(leaf_issuer, "LPM Project Development CA");

        let intermediate_bc = intermediate.basic_constraints().unwrap().unwrap();
        assert!(intermediate_bc.value.ca);
        assert_eq!(intermediate_bc.value.path_len_constraint, Some(0));
    }

    #[test]
    fn constrained_project_intermediate_permits_only_leaf_sans() {
        let (ca_cert_pem, ca_key_pem) = ca::generate_ca().unwrap();
        let extras = vec!["myapp.test".to_string(), "192.168.1.42".to_string()];
        let (cert_pem, _) = generate_project_cert_with_constrained_intermediate(
            &ca_cert_pem,
            &ca_key_pem,
            &extras,
            &[],
        )
        .unwrap();

        let chain = pem::parse_many(&cert_pem).unwrap();
        let (_, intermediate) = x509_parser::parse_x509_certificate(chain[1].contents()).unwrap();
        let constraints = intermediate.name_constraints().unwrap().unwrap();
        let permitted = constraints
            .value
            .permitted_subtrees
            .as_ref()
            .expect("project intermediate must have permitted subtrees");
        let dns_names: Vec<&str> = permitted
            .iter()
            .filter_map(|subtree| match &subtree.base {
                GeneralName::DNSName(name) => Some(*name),
                _ => None,
            })
            .collect();

        assert!(dns_names.contains(&"localhost"));
        assert!(dns_names.contains(&"myapp.test"));
        assert!(
            !dns_names.contains(&".test"),
            "project intermediate must not broaden to the whole .test suffix"
        );
    }

    #[test]
    fn constrained_project_intermediate_includes_extra_permitted_dns_subtrees() {
        let (ca_cert_pem, ca_key_pem) = ca::generate_ca().unwrap();
        let extras = vec!["web.myapp.local".to_string()];
        let extra_constraints = vec!["myapp.local".to_string(), ".myapp.local".to_string()];
        let (cert_pem, _) = generate_project_cert_with_constrained_intermediate(
            &ca_cert_pem,
            &ca_key_pem,
            &extras,
            &extra_constraints,
        )
        .unwrap();

        let dir = tempfile::tempdir().unwrap();
        let cert_path = dir.path().join("cert.pem");
        std::fs::write(&cert_path, cert_pem).unwrap();

        let constraints = read_project_dns_constraints(&cert_path).unwrap();
        assert!(constraints.contains(&"web.myapp.local".to_string()));
        assert!(constraints.contains(&"myapp.local".to_string()));
        assert!(constraints.contains(&".myapp.local".to_string()));
        assert!(
            project_cert_constraints_cover_dns(&cert_path, &extras, &extra_constraints).unwrap()
        );
    }

    #[test]
    fn project_cert_chains_to_root_accepts_direct_and_intermediate_formats() {
        let (ca_cert_pem, ca_key_pem) = ca::generate_ca().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let ca_path = dir.path().join("rootCA.pem");
        let direct_path = dir.path().join("direct.pem");
        let chain_path = dir.path().join("chain.pem");
        std::fs::write(&ca_path, &ca_cert_pem).unwrap();

        let (direct_pem, _) = generate_project_cert(&ca_cert_pem, &ca_key_pem, &[]).unwrap();
        std::fs::write(&direct_path, direct_pem).unwrap();
        assert!(project_cert_chains_to_root(&direct_path, &ca_path).unwrap());
        assert!(!project_cert_has_intermediate(&direct_path).unwrap());

        let (chain_pem, _) = generate_project_cert_with_constrained_intermediate(
            &ca_cert_pem,
            &ca_key_pem,
            &["myapp.test".to_string()],
            &[],
        )
        .unwrap();
        std::fs::write(&chain_path, chain_pem).unwrap();
        assert!(project_cert_chains_to_root(&chain_path, &ca_path).unwrap());
        assert!(project_cert_has_intermediate(&chain_path).unwrap());
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
        assert!(
            (364..=366).contains(&days),
            "expected ~365 days, got {days}"
        );
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

    #[test]
    fn covers_requested_hostnames_detects_missing_requested_sans() {
        let (ca_cert_pem, ca_key_pem) = ca::generate_ca().unwrap();
        let extras = vec!["myapp.test".to_string(), "192.168.1.42".to_string()];
        let (cert_pem, _) = generate_project_cert(&ca_cert_pem, &ca_key_pem, &extras).unwrap();

        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), &cert_pem).unwrap();

        assert!(covers_requested_hostnames(tmp.path(), &extras).unwrap());
        assert!(!covers_requested_hostnames(tmp.path(), &["missing.test".to_string()]).unwrap());
    }

    #[test]
    fn fingerprint_sha256_is_stable_across_reads() {
        let (ca_pem, _) = ca::generate_ca().unwrap();
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), &ca_pem).unwrap();

        let a = fingerprint_sha256(tmp.path()).unwrap();
        let b = fingerprint_sha256(tmp.path()).unwrap();
        assert_eq!(a, b);
        assert_eq!(a.len(), 32);
    }

    #[test]
    fn fingerprint_sha256_differs_per_cert() {
        let (ca_pem_a, _) = ca::generate_ca().unwrap();
        let (ca_pem_b, _) = ca::generate_ca().unwrap();
        let ta = tempfile::NamedTempFile::new().unwrap();
        let tb = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(ta.path(), &ca_pem_a).unwrap();
        std::fs::write(tb.path(), &ca_pem_b).unwrap();

        let fa = fingerprint_sha256(ta.path()).unwrap();
        let fb = fingerprint_sha256(tb.path()).unwrap();
        assert_ne!(
            fa, fb,
            "two freshly-generated CAs must produce distinct SHA-256 fingerprints"
        );
    }

    #[test]
    fn fingerprint_sha1_length_is_20() {
        let (ca_pem, _) = ca::generate_ca().unwrap();
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), &ca_pem).unwrap();

        let fp = fingerprint_sha1(tmp.path()).unwrap();
        assert_eq!(fp.len(), 20);
    }

    #[test]
    fn fingerprint_hex_uppercase_colon_separated() {
        let bytes: [u8; 4] = [0xab, 0xcd, 0x12, 0x34];
        assert_eq!(fingerprint_hex(&bytes), "AB:CD:12:34");
    }

    #[test]
    fn fingerprint_hex_empty_input() {
        assert_eq!(fingerprint_hex(&[]), "");
    }
}
