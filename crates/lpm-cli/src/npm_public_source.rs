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
    locked_package_npm_metadata_source(pkg, client)
}

pub(crate) fn locked_package_npm_metadata_source(
    pkg: &lpm_lockfile::LockedPackage,
    client: &lpm_registry::RegistryClient,
) -> Option<NpmMetadataSource> {
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

pub(crate) fn is_public_npm_origin(url: &str) -> bool {
    let Ok(parsed) = reqwest::Url::parse(url.trim()) else {
        return false;
    };
    if parsed.scheme() != "https" || parsed.port_or_known_default() != Some(443) {
        return false;
    }
    parsed.host_str().is_some_and(|host| {
        matches!(
            host.to_ascii_lowercase().as_str(),
            "registry.npmjs.org" | "registry.npmjs.com"
        )
    })
}

pub(crate) fn is_lpm_worker_origin(url: &str) -> bool {
    let lower = url.trim_end_matches('/').to_ascii_lowercase();
    matches!(lower.as_str(), "https://lpm.dev")
}

pub(crate) fn is_lpm_registry_origin(url: &str, client: &lpm_registry::RegistryClient) -> bool {
    let Ok(candidate) = reqwest::Url::parse(url.trim()) else {
        return false;
    };
    if candidate.query().is_some() || candidate.fragment().is_some() {
        return false;
    }
    if is_lpm_worker_origin(candidate.as_str()) {
        return true;
    }

    let Ok(base) = reqwest::Url::parse(client.base_url().trim()) else {
        return false;
    };
    if candidate.origin().ascii_serialization() != base.origin().ascii_serialization() {
        return false;
    }

    is_root_path(candidate.path()) || is_lpm_npm_proxy_registry_path(candidate.path())
}

fn is_root_path(path: &str) -> bool {
    path.trim_end_matches('/').is_empty()
}

fn is_lpm_npm_proxy_registry_path(path: &str) -> bool {
    path.trim_end_matches('/') == "/api/registry"
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
            importers: Default::default(),
            patches: Default::default(),
            catalogs: Default::default(),
            provenance: Default::default(),
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
        assert!(is_public_npm_origin("https://registry.npmjs.org:443/"));
        assert!(is_public_npm_origin("https://registry.npmjs.com"));
        assert!(is_public_npm_origin("https://registry.npmjs.com:443/"));
        assert!(is_public_npm_origin("https://REGISTRY.NPMJS.ORG"));
    }

    #[test]
    fn public_npm_origin_rejects_private_mirrors() {
        assert!(!is_public_npm_origin("https://npm.internal.example.com"));
        assert!(!is_public_npm_origin("https://npm.pkg.github.com"));
        assert!(!is_public_npm_origin("https://verdaccio.local"));
        assert!(!is_public_npm_origin("http://localhost:4873"));
        assert!(!is_public_npm_origin("https://registry.npmjs.org:444"));
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
        let client = lpm_registry::RegistryClient::new().with_base_url("http://127.0.0.1:4873");
        assert!(is_lpm_registry_origin("http://127.0.0.1:4873", &client));
        assert!(is_lpm_registry_origin(
            "http://127.0.0.1:4873/api/registry",
            &client,
        ));
        assert!(is_lpm_registry_origin(
            "http://127.0.0.1:4873/api/registry/",
            &client,
        ));
        assert!(!is_lpm_registry_origin("http://127.0.0.1:4874", &client,));
    }

    #[test]
    fn lpm_registry_source_rejects_same_origin_custom_registry_paths() {
        let client = lpm_registry::RegistryClient::new().with_base_url("https://lpm.dev");
        for registry in [
            "https://lpm.dev/private-registry",
            "https://lpm.dev/api/registry-private",
            "https://lpm.dev/api/registry?tenant=private",
            "https://lpm.dev/api/registry#private",
        ] {
            assert!(
                !is_lpm_registry_origin(registry, &client),
                "{registry} must not be treated as the lpm.dev npm proxy"
            );
        }
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
            "registry+http://127.0.0.1:4873/api/registry",
            Some("http://127.0.0.1:4873/api/registry/tarballs/ms/-/ms-2.1.3.tgz"),
        );
        assert_eq!(
            lockfile_npm_metadata_source(Some(&lockfile), "ms", &client),
            Some(NpmMetadataSource::ConfiguredRegistry),
        );
    }
}
