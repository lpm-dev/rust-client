//! The integrity a migrated lockfile recorded for each package version.
//!
//! A migration resolves its packages again, so a package can come back at
//! the version the source package manager locked but with other bytes: a
//! registry that serves something else under a published version, or a
//! public package taking a private one's place. An install that carries
//! these integrities refuses such a package before anything is linked.

use super::package::InstallPackage;
use lpm_common::{LpmError, SriComparison, compare_sri};
use std::collections::HashMap;

#[derive(Debug, Default)]
pub(crate) struct LockedIntegrities {
    by_version: HashMap<(String, String), String>,
}

impl LockedIntegrities {
    /// The integrity of every package `lockfile` records one for.
    pub(crate) fn from_lockfile(lockfile: &lpm_lockfile::Lockfile) -> Self {
        let by_version = lockfile
            .packages
            .iter()
            .filter_map(|package| {
                let integrity = package.integrity.clone()?;
                Some(((package.name.clone(), package.version.clone()), integrity))
            })
            .collect();
        Self { by_version }
    }

    /// Refuses the first package resolved at a locked version whose
    /// registry integrity disagrees with the recorded one. A package whose
    /// integrity names no algorithm the record does can't be compared; the
    /// fetch still verifies its bytes against the registry's integrity.
    pub(super) fn check(&self, packages: &[InstallPackage]) -> Result<(), LpmError> {
        for package in packages {
            let Some(locked) = self
                .by_version
                .get(&(package.name.clone(), package.version.clone()))
            else {
                continue;
            };
            let Some(resolved) = package.integrity.as_deref() else {
                continue;
            };
            if compare_sri(locked, resolved) == SriComparison::Disagree {
                return Err(LpmError::Registry(format!(
                    "{}@{} from {} has integrity {resolved}, but the migrated lockfile \
                     recorded {locked} for that version. LPM refused to install it.",
                    package.name,
                    package.version,
                    package
                        .source
                        .strip_prefix("registry+")
                        .unwrap_or(&package.source),
                )));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn resolved(name: &str, version: &str, integrity: Option<&str>) -> InstallPackage {
        InstallPackage {
            instance_id: None,
            dependency_targets: HashMap::new(),
            peer_targets: HashMap::new(),
            name: name.to_owned(),
            version: version.to_owned(),
            source: "registry+https://registry.npmjs.org".to_owned(),
            dependencies: Vec::new(),
            aliases: HashMap::new(),
            root_link_names: None,
            is_direct: true,
            is_lpm: false,
            peers: Vec::new(),
            integrity: integrity.map(str::to_owned),
            unpacked_size: None,
            registry_signatures: Vec::new(),
            registry_published_at: None,
            platform: None,
            node_engine: None,
            optional: false,
            tarball_url: None,
            metadata_checked_for_tarball: false,
            manifest_fingerprint: None,
        }
    }

    fn locked(name: &str, version: &str, integrity: &str) -> LockedIntegrities {
        LockedIntegrities {
            by_version: HashMap::from([(
                (name.to_owned(), version.to_owned()),
                integrity.to_owned(),
            )]),
        }
    }

    fn sri(algorithm: lpm_common::integrity::HashAlgorithm, data: &[u8]) -> String {
        lpm_common::Integrity::from_bytes(algorithm, data).to_string()
    }

    use lpm_common::integrity::HashAlgorithm::{Sha1, Sha512};

    #[test]
    fn a_package_at_a_locked_version_with_other_bytes_is_refused() {
        let pins = locked("corp-utils", "1.0.0", &sri(Sha512, b"private"));
        let error = pins
            .check(&[resolved(
                "corp-utils",
                "1.0.0",
                Some(&sri(Sha512, b"public")),
            )])
            .unwrap_err()
            .to_string();
        assert!(error.contains("corp-utils@1.0.0"), "{error}");
        assert!(error.contains("registry.npmjs.org"), "{error}");
    }

    #[test]
    fn a_package_at_a_locked_version_with_the_recorded_bytes_installs() {
        let pins = locked("corp-utils", "1.0.0", &sri(Sha512, b"same"));
        pins.check(&[resolved("corp-utils", "1.0.0", Some(&sri(Sha512, b"same")))])
            .unwrap();
    }

    #[test]
    fn a_package_at_another_version_is_not_compared() {
        let pins = locked("corp-utils", "1.0.0", &sri(Sha512, b"private"));
        pins.check(&[resolved(
            "corp-utils",
            "1.0.1",
            Some(&sri(Sha512, b"public")),
        )])
        .unwrap();
    }

    #[test]
    fn an_integrity_with_no_algorithm_in_common_is_left_to_the_fetch() {
        let pins = locked("old-pkg", "1.0.0", &sri(Sha1, b"old"));
        pins.check(&[resolved("old-pkg", "1.0.0", Some(&sri(Sha512, b"old")))])
            .unwrap();
    }
}
