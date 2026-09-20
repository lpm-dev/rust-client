use super::*;

#[test]
fn constrained_root_refuses_outside_hostnames_before_issuance() {
    let (root, key) = crate::ca::generate_ca_with_options(crate::ca::CaOptions {
        name_constraints: true,
    })
    .unwrap();
    for host in [
        "app.internal",
        "app.home.arpa",
        "staging.example.com",
        "8.8.8.8",
    ] {
        let names = vec![host.to_owned()];
        assert!(
            generate_project_cert(&root, &key, &names).is_err(),
            "direct issuance accepted {host}"
        );
        assert!(
            generate_project_cert_with_constrained_intermediate(&root, &key, &names, &[]).is_err(),
            "intermediate issuance accepted {host}"
        );
    }
}

#[test]
fn constrained_root_refuses_existing_outside_chain_at_publication() {
    let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let mut params = CertificateParams::default();
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(1));
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let unconstrained = params.clone().self_signed(&key).unwrap();
    params.name_constraints = Some(NameConstraints {
        permitted_subtrees: vec![
            GeneralSubtree::DnsName(".test".into()),
            GeneralSubtree::DnsName("localhost".into()),
            cidr_subtree("127.0.0.1/32").unwrap(),
            cidr_subtree("::1/128").unwrap(),
        ],
        excluded_subtrees: vec![],
    });
    let constrained = params.self_signed(&key).unwrap();
    let names = vec!["app.internal".to_owned()];
    let (chain, _) = generate_project_cert_with_constrained_intermediate(
        &unconstrained.pem(),
        &key.serialize_pem(),
        &names,
        &[],
    )
    .unwrap();
    assert!(
        validate_project_server_chain_bytes(chain.as_bytes(), constrained.pem().as_bytes(), &names)
            .is_err()
    );
}

#[test]
fn constrained_root_accepts_local_dns_and_private_addresses() {
    let (root, key) = crate::ca::generate_ca_with_options(crate::ca::CaOptions {
        name_constraints: true,
    })
    .unwrap();
    let names = [
        "app.test",
        "app.local",
        "api.localhost",
        "10.1.2.3",
        "192.168.1.8",
        "fc00::1",
    ]
    .map(str::to_owned);
    let (chain, _) =
        generate_project_cert_with_constrained_intermediate(&root, &key, &names, &[]).unwrap();
    validate_project_server_chain_bytes(chain.as_bytes(), root.as_bytes(), &names).unwrap();
}

#[test]
fn unconstrained_root_keeps_opted_in_custom_hostnames_supported() {
    let (root, key) = crate::ca::generate_ca_with_options(crate::ca::CaOptions::default()).unwrap();
    let names = ["app.internal", "app.home.arpa", "staging.example.com"].map(str::to_owned);
    let (chain, _) =
        generate_project_cert_with_constrained_intermediate(&root, &key, &names, &[]).unwrap();
    validate_project_server_chain_bytes(chain.as_bytes(), root.as_bytes(), &names).unwrap();
}

#[test]
fn root_exclusions_override_permitted_dns_without_restricting_unlisted_ip_types() {
    let mut params = CertificateParams::default();
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(1));
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params.name_constraints = Some(NameConstraints {
        permitted_subtrees: vec![
            GeneralSubtree::DnsName("localhost".into()),
            GeneralSubtree::DnsName(".test".into()),
        ],
        excluded_subtrees: vec![GeneralSubtree::DnsName("blocked.test".into())],
    });
    let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let root = params.self_signed(&key).unwrap().pem();
    for name in [
        "blocked.test",
        "api.blocked.test",
        "app.test.attacker.example",
    ] {
        assert!(generate_project_cert(&root, &key.serialize_pem(), &[name.into()]).is_err());
    }
    generate_project_cert(
        &root,
        &key.serialize_pem(),
        &["api.test".into(), "192.168.1.2".into()],
    )
    .unwrap();
}

#[test]
fn root_with_unsupported_excluded_name_type_is_rejected() {
    let mut params = CertificateParams::default();
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(1));
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params.name_constraints = Some(NameConstraints {
        permitted_subtrees: vec![],
        excluded_subtrees: vec![GeneralSubtree::Rfc822Name("blocked.example.com".into())],
    });
    let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let root = params.self_signed(&key).unwrap().pem();
    assert!(generate_project_cert(&root, &key.serialize_pem(), &[]).is_err());
}
