//! Users have installed root CAs that earlier releases created, so leaves this
//! release issues must chain to them and keep the structure earlier releases
//! gave leaves. The fixtures are a root CA, a leaf and a constrained chain that
//! lpm-cert made with rcgen 0.13. The CA's key is a test fixture trusted
//! nowhere.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use lpm_cert::cert;
use x509_parser::extensions::ParsedExtension;
use x509_parser::prelude::{FromDer, X509Certificate};

const SUBJECT_KEY_IDENTIFIER: &str = "2.5.29.14";
const AUTHORITY_KEY_IDENTIFIER: &str = "2.5.29.35";
const NAME_CONSTRAINTS: &str = "2.5.29.30";

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/rcgen-0.13")
        .join(name)
}

fn read(name: &str) -> String {
    std::fs::read_to_string(fixture(name)).unwrap()
}

fn ders(pem: &str) -> Vec<Vec<u8>> {
    pem::parse_many(pem)
        .unwrap()
        .into_iter()
        .map(pem::Pem::into_contents)
        .collect()
}

fn parse(der: &[u8]) -> X509Certificate<'_> {
    X509Certificate::from_der(der).unwrap().1
}

fn subject_key_identifier(certificate: &X509Certificate<'_>) -> Vec<u8> {
    certificate
        .extensions()
        .iter()
        .find_map(|extension| match extension.parsed_extension() {
            ParsedExtension::SubjectKeyIdentifier(identifier) => Some(identifier.0.to_vec()),
            _ => None,
        })
        .expect("subject key identifier")
}

fn authority_key_identifier(certificate: &X509Certificate<'_>) -> Vec<u8> {
    certificate
        .extensions()
        .iter()
        .find_map(|extension| match extension.parsed_extension() {
            ParsedExtension::AuthorityKeyIdentifier(identifier) => {
                identifier.key_identifier.as_ref().map(|key| key.0.to_vec())
            }
            _ => None,
        })
        .expect("authority key identifier")
}

/// What a certificate carries besides its key, serial number, dates and
/// signature: names, algorithms, validity length and every extension's
/// criticality and encoding, without the extensions `skip` names.
fn structure(der: &[u8], skip: &[&str]) -> BTreeMap<String, String> {
    let certificate = parse(der);
    let mut structure = BTreeMap::from([
        (
            "version".to_string(),
            format!("{:?}", certificate.version()),
        ),
        ("issuer".to_string(), hex(certificate.issuer().as_raw())),
        ("subject".to_string(), hex(certificate.subject().as_raw())),
        (
            "signature algorithm".to_string(),
            certificate.signature_algorithm.algorithm.to_id_string(),
        ),
        (
            "key algorithm".to_string(),
            certificate.public_key().algorithm.algorithm.to_id_string(),
        ),
        (
            "validity seconds".to_string(),
            (certificate.validity().not_after.timestamp()
                - certificate.validity().not_before.timestamp())
            .to_string(),
        ),
    ]);
    for extension in certificate.extensions() {
        let oid = extension.oid.to_id_string();
        if skip.contains(&oid.as_str()) {
            continue;
        }
        // rcgen 0.13 padded the key usage bit string with a zero byte, which
        // DER doesn't allow; 0.14 encodes the same usages minimally.
        let value = match extension.parsed_extension() {
            ParsedExtension::KeyUsage(usage) => format!("usages={:#06x}", usage.flags),
            _ => hex(extension.value),
        };
        structure.insert(
            format!("extension {oid}"),
            format!("critical={} {value}", extension.critical),
        );
    }
    structure
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn hostnames() -> Vec<String> {
    vec!["app.localhost".to_string()]
}

#[test]
fn a_leaf_chains_to_a_root_an_earlier_release_created() {
    let (ca, ca_key) = (read("ca.pem"), read("ca.key"));
    let (leaf, _) = cert::generate_project_cert(&ca, &ca_key, &hostnames()).unwrap();
    let directory = tempfile::tempdir().unwrap();
    let leaf_path = directory.path().join("leaf.pem");
    std::fs::write(&leaf_path, &leaf).unwrap();

    assert!(cert::leaf_signed_by(&leaf_path, &fixture("ca.pem")).unwrap());
    assert!(cert::project_cert_chains_to_root(&leaf_path, &fixture("ca.pem")).unwrap());
    let ca_der = &ders(&ca)[0];
    let leaf_der = &ders(&leaf)[0];
    assert_eq!(
        authority_key_identifier(&parse(leaf_der)),
        subject_key_identifier(&parse(ca_der))
    );
}

#[test]
fn a_constrained_chain_chains_to_a_root_an_earlier_release_created() {
    let (ca, ca_key) = (read("ca.pem"), read("ca.key"));
    let (chain, _) =
        cert::generate_project_cert_with_constrained_intermediate(&ca, &ca_key, &hostnames(), &[])
            .unwrap();
    let directory = tempfile::tempdir().unwrap();
    let chain_path = directory.path().join("chain.pem");
    std::fs::write(&chain_path, &chain).unwrap();

    assert!(cert::project_cert_chains_to_root(&chain_path, &fixture("ca.pem")).unwrap());
    let chain = ders(&chain);
    let (leaf, intermediate) = (parse(&chain[0]), parse(&chain[1]));
    assert_eq!(
        authority_key_identifier(&intermediate),
        subject_key_identifier(&parse(&ders(&ca)[0]))
    );
    assert_eq!(
        authority_key_identifier(&leaf),
        subject_key_identifier(&intermediate)
    );
}

#[test]
fn certificates_keep_the_structure_an_earlier_release_gave_them() {
    let (ca, ca_key) = (read("ca.pem"), read("ca.key"));
    let (leaf, _) = cert::generate_project_cert(&ca, &ca_key, &hostnames()).unwrap();
    let (chain, _) =
        cert::generate_project_cert_with_constrained_intermediate(&ca, &ca_key, &hostnames(), &[])
            .unwrap();
    let (earlier_leaf, earlier_chain) = (ders(&read("leaf.pem")), ders(&read("chain.pem")));
    let chain = ders(&chain);

    // Each new key has its own identifier, and so has the intermediate that
    // signs the constrained leaf.
    assert_eq!(
        structure(&ders(&leaf)[0], &[SUBJECT_KEY_IDENTIFIER]),
        structure(&earlier_leaf[0], &[SUBJECT_KEY_IDENTIFIER])
    );
    assert_eq!(
        structure(&chain[1], &[SUBJECT_KEY_IDENTIFIER]),
        structure(&earlier_chain[1], &[SUBJECT_KEY_IDENTIFIER])
    );
    assert_eq!(
        structure(
            &chain[0],
            &[SUBJECT_KEY_IDENTIFIER, AUTHORITY_KEY_IDENTIFIER]
        ),
        structure(
            &earlier_chain[0],
            &[SUBJECT_KEY_IDENTIFIER, AUTHORITY_KEY_IDENTIFIER]
        )
    );
}

#[test]
fn a_new_root_ca_keeps_the_structure_an_earlier_release_gave_it() {
    let (ca, _) = lpm_cert::ca::generate_ca_with_options(lpm_cert::ca::CaOptions {
        name_constraints: true,
    })
    .unwrap();

    let (new, earlier) = (ders(&ca), ders(&read("ca.pem")));
    assert_eq!(
        structure(&new[0], &[SUBJECT_KEY_IDENTIFIER, NAME_CONSTRAINTS]),
        structure(&earlier[0], &[SUBJECT_KEY_IDENTIFIER, NAME_CONSTRAINTS])
    );
    // The constraints changed on purpose, by adding the private-use names
    // `cert.extraPermittedDns` accepts without `allowPublicDns`.
    let permitted = |der: &[u8]| -> Vec<String> {
        parse(der)
            .name_constraints()
            .unwrap()
            .unwrap()
            .value
            .permitted_subtrees
            .clone()
            .unwrap_or_default()
            .iter()
            .map(|subtree| format!("{:?}", subtree.base))
            .collect()
    };
    let (new_permitted, earlier_permitted) = (permitted(&new[0]), permitted(&earlier[0]));
    assert!(
        earlier_permitted
            .iter()
            .all(|subtree| new_permitted.contains(subtree)),
        "{new_permitted:?}"
    );
    assert_eq!(
        new_permitted
            .iter()
            .filter(|subtree| !earlier_permitted.contains(subtree))
            .collect::<Vec<_>>(),
        [r#"DNSName(".internal")"#, r#"DNSName(".home.arpa")"#]
    );
}
