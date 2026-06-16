use crate::npm_version::NpmVersion;
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct SpeculativePackageMetadata {
    pub dist_tags: HashMap<String, String>,
    pub versions: HashMap<String, SpeculativeVersionMetadata>,
}

#[derive(Debug, Clone)]
pub struct SpeculativeVersionMetadata {
    pub parsed_version: Option<NpmVersion>,
    pub tarball_url: Option<String>,
    pub integrity: Option<String>,
    pub dependencies: HashMap<String, String>,
}

impl From<lpm_registry::PackageMetadata> for SpeculativePackageMetadata {
    fn from(meta: lpm_registry::PackageMetadata) -> Self {
        let mut versions = HashMap::with_capacity(meta.versions.len());
        for (version, version_meta) in meta.versions {
            let parsed_version = NpmVersion::parse(&version).ok();
            let tarball_url = version_meta.tarball_url().map(ToOwned::to_owned);
            let integrity = version_meta.integrity_or_shasum().map(|s| s.into_owned());
            versions.insert(
                version,
                SpeculativeVersionMetadata {
                    parsed_version,
                    tarball_url,
                    integrity,
                    dependencies: version_meta.dependencies,
                },
            );
        }
        Self {
            dist_tags: meta.dist_tags,
            versions,
        }
    }
}

impl From<&lpm_registry::PackageMetadata> for SpeculativePackageMetadata {
    fn from(meta: &lpm_registry::PackageMetadata) -> Self {
        let mut versions = HashMap::with_capacity(meta.versions.len());
        for (version, version_meta) in &meta.versions {
            let parsed_version = NpmVersion::parse(version).ok();
            let tarball_url = version_meta.tarball_url().map(ToOwned::to_owned);
            let integrity = version_meta.integrity_or_shasum().map(|s| s.into_owned());
            versions.insert(
                version.clone(),
                SpeculativeVersionMetadata {
                    parsed_version,
                    tarball_url,
                    integrity,
                    dependencies: version_meta.dependencies.clone(),
                },
            );
        }
        Self {
            dist_tags: meta.dist_tags.clone(),
            versions,
        }
    }
}
