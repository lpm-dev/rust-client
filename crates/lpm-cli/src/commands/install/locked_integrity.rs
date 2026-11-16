//! The integrity a migrated lockfile recorded for each package version.
//!
//! No install replays the lockfile `lpm migrate` writes: the next install
//! resolves every package again. A package can then come back at the
//! version the source package manager locked but with other bytes, from a
//! registry that serves something else under a published version or a
//! public package taking a private one's place. Until an install replaces
//! that lockfile, each install holds what it resolves to the integrities
//! it recorded, before any tarball is fetched.

use super::package::InstallPackage;
use lpm_common::integrity::Integrity;
use lpm_common::{LpmError, SriComparison, compare_sri};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

/// How much of a lockfile [`LockedIntegrities::detect`] reads to find the
/// resolver its `[metadata]` table records.
const LOCKFILE_HEAD_BYTES: usize = 4096;

#[derive(Debug, Default)]
pub(crate) struct LockedIntegrities {
    /// The recorded integrity by package name, then version.
    by_name: HashMap<String, HashMap<String, String>>,
}

impl LockedIntegrities {
    /// The integrities in the lockfile `lpm migrate` wrote at `root`, or
    /// `None` when `root` holds no lockfile, another one, or one with no
    /// integrities.
    pub(crate) fn detect(root: &Path) -> Result<Option<Arc<Self>>, LpmError> {
        let path = root.join(lpm_lockfile::LOCKFILE_NAME);
        let marker = format!("\"{}\"", lpm_migrate::MIGRATED_LOCKFILE_RESOLVER);
        let unreadable = |error: &dyn std::fmt::Display| {
            LpmError::Io(std::io::Error::other(format!(
                "can't read {}: {error}",
                path.display()
            )))
        };
        // The `[metadata]` table that records the resolver comes first, so
        // the head of the file settles nearly every install without reading
        // the rest.
        let mut head = Vec::with_capacity(LOCKFILE_HEAD_BYTES);
        match std::fs::File::open(&path) {
            Ok(file) => {
                use std::io::Read as _;
                file.take(LOCKFILE_HEAD_BYTES as u64)
                    .read_to_end(&mut head)
                    .map_err(|error| unreadable(&error))?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(unreadable(&error)),
        }
        if !head
            .windows(marker.len())
            .any(|window| window == marker.as_bytes())
        {
            return Ok(None);
        }
        let content =
            lpm_common::read_text_file_capped(&path, lpm_lockfile::TOML_LOCKFILE_SIZE_CAP_BYTES)
                .map_err(|error| unreadable(&error))?;
        let Ok(lockfile) = lpm_lockfile::Lockfile::from_toml_shared(&content) else {
            return Ok(None);
        };
        if lockfile.metadata.resolved_with.as_deref()
            != Some(lpm_migrate::MIGRATED_LOCKFILE_RESOLVER)
        {
            return Ok(None);
        }
        let integrities = Self::from_lockfile(&lockfile);
        Ok((!integrities.by_name.is_empty()).then(|| Arc::new(integrities)))
    }

    fn from_lockfile(lockfile: &lpm_lockfile::Lockfile) -> Self {
        let mut by_name: HashMap<String, HashMap<String, String>> = HashMap::new();
        for package in &lockfile.packages {
            if let Some(integrity) = &package.integrity {
                by_name
                    .entry(package.name.clone())
                    .or_default()
                    .insert(package.version.clone(), integrity.clone());
            }
        }
        Self { by_name }
    }

    /// Holds each package resolved at a recorded version to the recorded
    /// integrity. Refuses one whose registry integrity disagrees with it.
    /// One whose registry gives no integrity, or only hashes weaker than
    /// the record's, takes the record's strongest, so its fetch verifies
    /// the bytes against what the lockfile recorded. A record weaker than
    /// the registry's integrity can't be compared, and the fetch verifies
    /// the registry's.
    pub(super) fn apply(
        &self,
        packages: &mut [InstallPackage],
        packages_for_lockfile: &mut [InstallPackage],
    ) -> Result<(), LpmError> {
        for package in packages.iter_mut().chain(packages_for_lockfile.iter_mut()) {
            self.apply_to(package)?;
        }
        Ok(())
    }

    fn apply_to(&self, package: &mut InstallPackage) -> Result<(), LpmError> {
        let Some(locked) = self
            .by_name
            .get(&package.name)
            .and_then(|versions| versions.get(&package.version))
        else {
            return Ok(());
        };
        let adopt = match package.integrity.as_deref() {
            None => true,
            Some(resolved) => match compare_sri(locked, resolved) {
                SriComparison::Agree => false,
                SriComparison::Disagree => return Err(refusal(package, resolved, locked)),
                SriComparison::NoCommonAlgorithm => {
                    Integrity::strongest_in(locked).map(|hash| hash.algorithm)
                        > Integrity::strongest_in(resolved).map(|hash| hash.algorithm)
                }
            },
        };
        if adopt && let Some(strongest) = Integrity::strongest_in(locked) {
            package.integrity = Some(strongest.to_string());
        }
        Ok(())
    }
}

fn refusal(package: &InstallPackage, resolved: &str, locked: &str) -> LpmError {
    let source = package
        .source
        .strip_prefix("registry+")
        .unwrap_or(&package.source);
    LpmError::Registry(format!(
        "{}@{} from {source} has integrity {resolved}, but the lockfile `lpm migrate` wrote \
         recorded {locked} for that version, so these aren't the bytes the project had. \
         Nothing was installed. Find out which package is the right one before going on: \
         `lpm migrate --rollback` restores the original lockfile.",
        package.name, package.version,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use lpm_common::integrity::HashAlgorithm::{Sha1, Sha256, Sha512};

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
            by_name: HashMap::from([(
                name.to_owned(),
                HashMap::from([(version.to_owned(), integrity.to_owned())]),
            )]),
        }
    }

    fn sri(algorithm: lpm_common::integrity::HashAlgorithm, data: &[u8]) -> String {
        Integrity::from_bytes(algorithm, data).to_string()
    }

    fn apply_one(
        pins: &LockedIntegrities,
        package: InstallPackage,
    ) -> Result<InstallPackage, LpmError> {
        let mut packages = vec![package];
        pins.apply(&mut packages, &mut [])?;
        Ok(packages.remove(0))
    }

    #[test]
    fn a_package_at_a_locked_version_with_other_bytes_is_refused() {
        let pins = locked("corp-utils", "1.0.0", &sri(Sha512, b"private"));
        let error = apply_one(
            &pins,
            resolved("corp-utils", "1.0.0", Some(&sri(Sha512, b"public"))),
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("corp-utils@1.0.0"), "{error}");
        assert!(error.contains("registry.npmjs.org"), "{error}");
        assert!(error.contains("lpm migrate --rollback"), "{error}");
    }

    #[test]
    fn a_package_in_the_lockfile_list_with_other_bytes_is_refused_too() {
        let pins = locked("corp-utils", "1.0.0", &sri(Sha512, b"private"));
        let mut for_lockfile = vec![resolved(
            "corp-utils",
            "1.0.0",
            Some(&sri(Sha512, b"public")),
        )];
        assert!(pins.apply(&mut [], &mut for_lockfile).is_err());
    }

    #[test]
    fn a_package_at_a_locked_version_with_the_recorded_bytes_installs_unchanged() {
        let integrity = sri(Sha512, b"same");
        let pins = locked("corp-utils", "1.0.0", &integrity);
        let package = apply_one(&pins, resolved("corp-utils", "1.0.0", Some(&integrity))).unwrap();
        assert_eq!(package.integrity.as_deref(), Some(integrity.as_str()));
    }

    #[test]
    fn a_package_at_another_version_is_not_compared() {
        let pins = locked("corp-utils", "1.0.0", &sri(Sha512, b"private"));
        let public = sri(Sha512, b"public");
        let package = apply_one(&pins, resolved("corp-utils", "1.0.1", Some(&public))).unwrap();
        assert_eq!(package.integrity.as_deref(), Some(public.as_str()));
    }

    #[test]
    fn a_registry_that_gives_no_integrity_has_its_bytes_verified_against_the_record() {
        let recorded = sri(Sha512, b"private");
        let pins = locked(
            "corp-utils",
            "1.0.0",
            &format!("{} {recorded}", sri(Sha1, b"private")),
        );
        let package = apply_one(&pins, resolved("corp-utils", "1.0.0", None)).unwrap();
        assert_eq!(package.integrity.as_deref(), Some(recorded.as_str()));
    }

    #[test]
    fn a_registry_that_gives_only_a_weaker_hash_has_its_bytes_verified_against_the_record() {
        let recorded = sri(Sha512, b"private");
        let pins = locked("corp-utils", "1.0.0", &recorded);
        let package = apply_one(
            &pins,
            resolved("corp-utils", "1.0.0", Some(&sri(Sha1, b"public"))),
        )
        .unwrap();
        assert_eq!(package.integrity.as_deref(), Some(recorded.as_str()));
    }

    #[test]
    fn a_record_weaker_than_the_registry_hash_leaves_the_fetch_to_verify_the_registrys() {
        let pins = locked("old-pkg", "1.0.0", &sri(Sha1, b"old"));
        let registry = sri(Sha256, b"old");
        let package = apply_one(&pins, resolved("old-pkg", "1.0.0", Some(&registry))).unwrap();
        assert_eq!(package.integrity.as_deref(), Some(registry.as_str()));
    }

    #[test]
    fn only_a_lockfile_lpm_migrate_wrote_is_detected() {
        let directory = tempfile::tempdir().unwrap();
        assert!(
            LockedIntegrities::detect(directory.path())
                .unwrap()
                .is_none()
        );

        let (mut lockfile, _) =
            lpm_migrate::normalize::to_lockfile(vec![lpm_migrate::MigratedPackage {
                lockfile_key: None,
                name: "migrate".to_owned(),
                version: "1.0.0".to_owned(),
                resolved: Some("https://registry.npmjs.org/migrate/-/migrate-1.0.0.tgz".to_owned()),
                integrity: Some(sri(Sha512, b"migrate")),
                dependencies: Vec::new(),
                is_optional: false,
                is_dev: false,
                fetched_from: lpm_migrate::FetchedFrom::Registry,
            }])
            .unwrap();
        let path = directory.path().join(lpm_lockfile::LOCKFILE_NAME);
        lockfile.metadata.resolved_with = Some("greedy-fusion".to_owned());
        lockfile.write_all(&path).unwrap();
        assert!(
            LockedIntegrities::detect(directory.path())
                .unwrap()
                .is_none(),
            "a lockfile an install wrote is the install's to replay"
        );

        lockfile.metadata.resolved_with = Some(lpm_migrate::MIGRATED_LOCKFILE_RESOLVER.to_owned());
        lockfile.write_all(&path).unwrap();
        let detected = LockedIntegrities::detect(directory.path())
            .unwrap()
            .unwrap();
        assert!(
            apply_one(
                &detected,
                resolved("migrate", "1.0.0", Some(&sri(Sha512, b"other")))
            )
            .is_err()
        );
    }
}
