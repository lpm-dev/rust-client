#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NpmMetadataSource {
    PublicNpm,
    ConfiguredRegistry,
}

pub(crate) fn lockfile_npm_metadata_source(
    lockfile: Option<&lpm_lockfile::Lockfile>,
    name: &str,
    client: &lpm_registry::RegistryClient,
) -> Option<NpmMetadataSource> {
    let pkg = lockfile?.find_package(name)?;
    let url = lockfile_package_registry_source_url(pkg)?;
    if is_public_npm_origin(&url) {
        return Some(NpmMetadataSource::PublicNpm);
    }
    if is_lpm_registry_origin(&url, client) && pkg.tarball.is_some() {
        return Some(NpmMetadataSource::ConfiguredRegistry);
    }
    None
}

fn lockfile_package_registry_source_url(pkg: &lpm_lockfile::LockedPackage) -> Option<String> {
    match pkg.source_kind()? {
        Ok(lpm_lockfile::Source::Registry { url }) => Some(url),
        _ => None,
    }
}

fn is_public_npm_origin(url: &str) -> bool {
    let lower = url.trim_end_matches('/').to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "https://registry.npmjs.org" | "https://registry.npmjs.com"
    )
}

fn is_lpm_worker_origin(url: &str) -> bool {
    let lower = url.trim_end_matches('/').to_ascii_lowercase();
    matches!(lower.as_str(), "https://lpm.dev")
}

fn is_lpm_registry_origin(url: &str, client: &lpm_registry::RegistryClient) -> bool {
    is_lpm_worker_origin(url) || same_origin(url, client.base_url())
}

fn same_origin(left: &str, right: &str) -> bool {
    let Ok(left) = reqwest::Url::parse(left) else {
        return false;
    };
    let Ok(right) = reqwest::Url::parse(right) else {
        return false;
    };
    left.origin().ascii_serialization() == right.origin().ascii_serialization()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lockfile_with_source(source: &str, tarball: Option<&str>) -> lpm_lockfile::Lockfile {
        lpm_lockfile::Lockfile {
            metadata: lpm_lockfile::LockfileMetadata {
                lockfile_version: 2,
                resolved_with: Some("greedy-fusion".into()),
                auto_isolated_peer_conflicts: false,
            },
            catalogs: Default::default(),
            packages: vec![lpm_lockfile::LockedPackage {
                name: "ms".into(),
                version: "2.1.3".into(),
                source: Some(source.into()),
                tarball: tarball.map(str::to_string),
                ..Default::default()
            }],
            root_aliases: Default::default(),
            ambient_peer_installs: Vec::new(),
        }
    }

    #[test]
    fn public_npm_origin_recognises_canonical_shapes() {
        assert!(is_public_npm_origin("https://registry.npmjs.org"));
        assert!(is_public_npm_origin("https://registry.npmjs.org/"));
        assert!(is_public_npm_origin("https://registry.npmjs.com"));
        assert!(is_public_npm_origin("https://REGISTRY.NPMJS.ORG"));
    }

    #[test]
    fn public_npm_origin_rejects_private_mirrors() {
        assert!(!is_public_npm_origin("https://npm.internal.example.com"));
        assert!(!is_public_npm_origin("https://npm.pkg.github.com"));
        assert!(!is_public_npm_origin("https://verdaccio.local"));
        assert!(!is_public_npm_origin("http://localhost:4873"));
        assert!(!is_public_npm_origin(""));
    }

    #[test]
    fn lpm_worker_origin_recognises_canonical_registry() {
        assert!(is_lpm_worker_origin("https://lpm.dev"));
        assert!(is_lpm_worker_origin("https://lpm.dev/"));
        assert!(is_lpm_worker_origin("https://LPM.DEV"));
        assert!(!is_lpm_worker_origin("https://npm.internal.example.com"));
    }

    #[test]
    fn lpm_registry_source_recognises_current_base_url_origin() {
        let client =
            lpm_registry::RegistryClient::new().with_base_url("http://127.0.0.1:4873/api/registry");
        assert!(is_lpm_registry_origin("http://127.0.0.1:4873", &client));
        assert!(is_lpm_registry_origin(
            "http://127.0.0.1:4873/api/registry",
            &client,
        ));
        assert!(!is_lpm_registry_origin("http://127.0.0.1:4874", &client,));
    }

    #[test]
    fn configured_private_npm_registry_is_not_treated_as_lpm_proxy_source() {
        let client = lpm_registry::RegistryClient::new()
            .with_base_url("https://lpm.dev")
            .with_npm_registry_url("https://npm.internal.example.com");
        let lockfile = lockfile_with_source(
            "registry+https://npm.internal.example.com",
            Some("https://npm.internal.example.com/ms/-/ms-2.1.3.tgz"),
        );
        assert_eq!(
            lockfile_npm_metadata_source(Some(&lockfile), "ms", &client),
            None,
        );
    }

    #[test]
    fn configured_lpm_registry_source_with_tarball_uses_proxy_metadata() {
        let client = lpm_registry::RegistryClient::new().with_base_url("http://127.0.0.1:4873");
        let lockfile = lockfile_with_source(
            "registry+http://127.0.0.1:4873",
            Some("http://127.0.0.1:4873/tarballs/ms/-/ms-2.1.3.tgz"),
        );
        assert_eq!(
            lockfile_npm_metadata_source(Some(&lockfile), "ms", &client),
            Some(NpmMetadataSource::ConfiguredRegistry),
        );
    }
}
