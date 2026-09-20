use super::{name_constraint_matches, project_subject_alt_names};
use lpm_common::LpmError;
use rcgen::SanType;
use std::net::IpAddr;
use x509_parser::certificate::X509Certificate;
use x509_parser::extensions::{GeneralName, NameConstraints};

fn outside_root() -> LpmError {
    LpmError::Cert(
        "active root CA name constraints do not permit every requested hostname; use a permitted local hostname or explicitly rotate the CA with the intended constraint policy".into(),
    )
}

pub(super) fn validate_requested_names(
    ca_cert_pem: &str,
    hostnames: &[String],
) -> Result<(), Box<dyn std::error::Error>> {
    let pem = pem::parse(ca_cert_pem)?;
    let (_, root) = x509_parser::parse_x509_certificate(pem.contents())?;
    let Some(constraints) = root.name_constraints()? else {
        return Ok(());
    };
    validate_supported_constraints(constraints.value)?;
    for name in project_subject_alt_names(hostnames)? {
        let permitted = match name {
            SanType::DnsName(name) => {
                permits(constraints.value, &GeneralName::DNSName(name.as_str()))
            }
            SanType::IpAddress(IpAddr::V4(address)) => permits(
                constraints.value,
                &GeneralName::IPAddress(&address.octets()),
            ),
            SanType::IpAddress(IpAddr::V6(address)) => permits(
                constraints.value,
                &GeneralName::IPAddress(&address.octets()),
            ),
            _ => false,
        };
        if !permitted {
            return Err(outside_root().into());
        }
    }
    Ok(())
}

pub(super) fn validate_leaf(
    root: &X509Certificate<'_>,
    leaf: &X509Certificate<'_>,
) -> Result<(), LpmError> {
    let Some(constraints) = root
        .name_constraints()
        .map_err(|error| LpmError::Cert(format!("invalid root name constraints: {error}")))?
    else {
        return Ok(());
    };
    validate_supported_constraints(constraints.value)?;
    let names = leaf
        .subject_alternative_name()
        .map_err(|error| LpmError::Cert(format!("invalid project leaf SAN extension: {error}")))?
        .ok_or_else(|| LpmError::Cert("project leaf is missing SAN entries".into()))?;
    if names
        .value
        .general_names
        .iter()
        .all(|name| permits(constraints.value, name))
    {
        Ok(())
    } else {
        Err(outside_root())
    }
}

fn permits(constraints: &NameConstraints<'_>, name: &GeneralName<'_>) -> bool {
    let permitted = constraints
        .permitted_subtrees
        .as_deref()
        .unwrap_or_default();
    let excluded = constraints.excluded_subtrees.as_deref().unwrap_or_default();
    // A permitted subtree restricts only its own name type.
    let constrained = permitted
        .iter()
        .any(|subtree| std::mem::discriminant(&subtree.base) == std::mem::discriminant(name));
    (!constrained
        || permitted
            .iter()
            .any(|subtree| name_constraint_matches(&subtree.base, name)))
        && !excluded
            .iter()
            .any(|subtree| name_constraint_matches(&subtree.base, name))
}

fn validate_supported_constraints(constraints: &NameConstraints<'_>) -> Result<(), LpmError> {
    if constraints
        .permitted_subtrees
        .iter()
        .chain(&constraints.excluded_subtrees)
        .flatten()
        .any(|subtree| {
            !matches!(
                subtree.base,
                GeneralName::DNSName(_) | GeneralName::IPAddress(_)
            )
        })
    {
        return Err(LpmError::Cert("active root CA uses unsupported name constraints; use a root with DNS and IP constraints".into()));
    }
    Ok(())
}
