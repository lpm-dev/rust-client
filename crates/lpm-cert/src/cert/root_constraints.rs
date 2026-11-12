use super::{name_constraint_matches, project_subject_alt_names};
use lpm_common::LpmError;
use rcgen::SanType;
use std::net::IpAddr;
use x509_parser::certificate::X509Certificate;
use x509_parser::extensions::{GeneralName, NameConstraints};

fn outside_root() -> LpmError {
    LpmError::Cert(
        "the local CA's name constraints don't permit every requested hostname; use a local name, or run `lpm cert rotate --no-name-constraints` to replace the CA with one that may sign any name".into(),
    )
}

fn root_der(ca_cert_pem: &[u8]) -> Result<Vec<u8>, LpmError> {
    pem::parse(ca_cert_pem)
        .map(pem::Pem::into_contents)
        .map_err(|error| LpmError::Cert(format!("invalid CA certificate PEM: {error}")))
}

/// Of `hostnames`, names or IP addresses a certificate would name, and
/// `subtrees`, DNS subtrees a project intermediate would permit (`x` for `x`
/// and the names below it, `.x` or `*.x` for those below it alone), the ones
/// the PEM-encoded root's name constraints don't wholly permit, in order;
/// none when it has none.
pub(crate) fn names_outside_root(
    ca_cert_pem: &[u8],
    hostnames: &[String],
    subtrees: &[String],
) -> Result<Vec<String>, LpmError> {
    let der = root_der(ca_cert_pem)?;
    let (_, root) = x509_parser::parse_x509_certificate(&der)
        .map_err(|error| LpmError::Cert(format!("invalid CA X.509: {error}")))?;
    let Some(constraints) = root
        .name_constraints()
        .map_err(|error| LpmError::Cert(format!("invalid root name constraints: {error}")))?
    else {
        return Ok(Vec::new());
    };
    validate_supported_constraints(constraints.value)?;
    let mut outside = Vec::new();
    for hostname in hostnames {
        let host = hostname.trim().trim_end_matches('.').to_ascii_lowercase();
        let permitted = match host.parse::<IpAddr>() {
            Ok(IpAddr::V4(address)) => permits(
                constraints.value,
                &GeneralName::IPAddress(&address.octets()),
            ),
            Ok(IpAddr::V6(address)) => permits(
                constraints.value,
                &GeneralName::IPAddress(&address.octets()),
            ),
            Err(_) => permits(constraints.value, &GeneralName::DNSName(&host)),
        };
        if !permitted {
            outside.push(hostname.clone());
        }
    }
    outside.extend(
        subtrees
            .iter()
            .filter(|subtree| !subtree_permitted(constraints.value, subtree))
            .cloned(),
    );
    Ok(outside)
}

/// Whether every name in the DNS subtree `subtree`, as
/// [`names_outside_root`] spells subtrees, is one `constraints` permits: it
/// lies within a permitted DNS subtree, and no excluded one reaches into it.
fn subtree_permitted(constraints: &NameConstraints<'_>, subtree: &str) -> bool {
    let subtree = subtree.trim().trim_end_matches('.').to_ascii_lowercase();
    let (base, below_only) = match subtree
        .strip_prefix("*.")
        .or_else(|| subtree.strip_prefix('.'))
    {
        Some(base) => (base.to_owned(), true),
        None => (subtree.clone(), false),
    };
    let within = |inner: &str, outer: &str| inner == outer || inner.ends_with(&format!(".{outer}"));
    let dns_base = |name: &GeneralName<'_>| match name {
        GeneralName::DNSName(name) => Some(name.trim_end_matches('.').to_ascii_lowercase()),
        _ => None,
    };
    let permitted = constraints
        .permitted_subtrees
        .as_deref()
        .unwrap_or_default();
    let excluded = constraints.excluded_subtrees.as_deref().unwrap_or_default();
    // A permitted subtree restricts only its own name type.
    let dns_permitted = permitted
        .iter()
        .filter_map(|permitted| dns_base(&permitted.base))
        .collect::<Vec<_>>();
    let contained = dns_permitted.is_empty()
        || dns_permitted
            .iter()
            .any(|permitted| match permitted.strip_prefix('.') {
                // `.p` holds the names below `p` alone.
                Some(parent) if below_only => within(&base, parent),
                Some(parent) => base.ends_with(&format!(".{parent}")),
                None => within(&base, permitted),
            });
    // Any excluded subtree whose base is at, above or below this one's
    // takes some of its names.
    let reached = excluded
        .iter()
        .filter_map(|excluded| dns_base(&excluded.base))
        .any(|excluded| {
            let excluded = excluded.trim_start_matches('.');
            within(&base, excluded) || within(excluded, &base)
        });
    contained && !reached
}

/// The PEM-encoded root's name constraints as a person reads them, `*.x`
/// for the names below `x`, addresses as CIDR ranges, and excluded ones
/// after `not`; `None` when it has none.
pub(crate) fn constraints_summary(ca_cert_pem: &[u8]) -> Result<Option<Vec<String>>, LpmError> {
    let der = root_der(ca_cert_pem)?;
    let (_, root) = x509_parser::parse_x509_certificate(&der)
        .map_err(|error| LpmError::Cert(format!("invalid CA X.509: {error}")))?;
    let Some(constraints) = root
        .name_constraints()
        .map_err(|error| LpmError::Cert(format!("invalid root name constraints: {error}")))?
    else {
        return Ok(None);
    };
    let spell = |name: &GeneralName<'_>| match name {
        GeneralName::DNSName(name) => Some(match name.strip_prefix('.') {
            Some(parent) => format!("*.{parent}"),
            None => (*name).to_owned(),
        }),
        GeneralName::IPAddress(range) => {
            let (network, mask) = range.split_at(range.len() / 2);
            let prefix: u32 = mask.iter().map(|byte| byte.count_ones()).sum();
            let address = match network.len() {
                4 => <[u8; 4]>::try_from(network).ok().map(IpAddr::from),
                16 => <[u8; 16]>::try_from(network).ok().map(IpAddr::from),
                _ => None,
            }?;
            Some(format!("{address}/{prefix}"))
        }
        _ => None,
    };
    let value = constraints.value;
    Ok(Some(
        value
            .permitted_subtrees
            .as_deref()
            .unwrap_or_default()
            .iter()
            .filter_map(|subtree| spell(&subtree.base))
            .chain(
                value
                    .excluded_subtrees
                    .as_deref()
                    .unwrap_or_default()
                    .iter()
                    .filter_map(|subtree| spell(&subtree.base).map(|name| format!("not {name}"))),
            )
            .collect(),
    ))
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
