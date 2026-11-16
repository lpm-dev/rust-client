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
use lpm_common::integrity::{HashAlgorithm, Integrity, sri_hashes};
use lpm_common::{LpmError, SriComparison, compare_sri};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

/// How much of a lockfile [`LockedIntegrities::detect`] reads to find the
/// resolver its `[metadata]` table records.
const LOCKFILE_HEAD_BYTES: usize = 4096;

#[derive(Debug, Default)]
pub(crate) struct LockedIntegrities {
    /// The recorded integrity of each registry package, by name, then
    /// version.
    by_name: HashMap<String, HashMap<String, String>>,
    /// The recorded integrity of each package fetched from a tarball URL, by
    /// that URL without credentials, query or fragment.
    by_tarball: HashMap<String, String>,
}

impl LockedIntegrities {
    /// The integrities in the lockfile `lpm migrate` wrote at `root`, or
    /// `None` when `root` holds no lockfile, another one, or one with no
    /// integrities.
    pub(crate) fn detect(root: &Path) -> Result<Option<Arc<Self>>, LpmError> {
        let path = root.join(lpm_lockfile::LOCKFILE_NAME);
        let marker = format!(
            "resolved-with = \"{}\"",
            lpm_migrate::MIGRATED_LOCKFILE_RESOLVER
        );
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
        // Install would otherwise resolve again with nothing held to the
        // recorded integrities, as after a merge left conflict markers.
        let lockfile = lpm_lockfile::Lockfile::from_toml_shared(&content).map_err(|error| {
            LpmError::Registry(format!(
                "{} was written by `lpm migrate`, but it can't be read: {error}. Fix the file, \
                 or restore the original lockfile with `lpm migrate --rollback` and migrate \
                 again.",
                path.display()
            ))
        })?;
        if lockfile.metadata.resolved_with.as_deref()
            != Some(lpm_migrate::MIGRATED_LOCKFILE_RESOLVER)
        {
            return Ok(None);
        }
        let integrities = Self::from_lockfile(&lockfile);
        let holds_any = !integrities.by_name.is_empty() || !integrities.by_tarball.is_empty();
        Ok(holds_any.then(|| Arc::new(integrities)))
    }

    fn from_lockfile(lockfile: &lpm_lockfile::Lockfile) -> Self {
        let mut integrities = Self::default();
        for package in &lockfile.packages {
            let Some(integrity) = &package.integrity else {
                continue;
            };
            match package
                .source
                .as_deref()
                .and_then(|source| source.strip_prefix("tarball+"))
            {
                Some(url) => {
                    if let Some(url) = tarball_key(url) {
                        integrities.by_tarball.insert(url, integrity.clone());
                    }
                }
                None => {
                    integrities
                        .by_name
                        .entry(package.name.clone())
                        .or_default()
                        .insert(package.version.clone(), integrity.clone());
                }
            }
        }
        integrities
    }

    /// Refuses a tarball downloaded from `url` whose bytes don't match the
    /// integrity recorded for that URL, before anything extracts it. For
    /// each algorithm the record names, one of its digests must match.
    pub(super) fn check_tarball_file(&self, url: &str, file: &Path) -> Result<(), LpmError> {
        let Some(locked) = tarball_key(url).and_then(|key| self.by_tarball.get(&key)) else {
            return Ok(());
        };
        let mut algorithms: Vec<HashAlgorithm> =
            sri_hashes(locked).map(|hash| hash.algorithm).collect();
        algorithms.sort_unstable();
        algorithms.dedup();
        for algorithm in algorithms {
            let mut matched = false;
            for expected in sri_hashes(locked).filter(|hash| hash.algorithm == algorithm) {
                match expected.verify_file(file) {
                    Ok(()) => {
                        matched = true;
                        break;
                    }
                    Err(LpmError::IntegrityMismatch { .. }) => {}
                    Err(error) => return Err(error),
                }
            }
            if !matched {
                return Err(LpmError::Registry(format!(
                    "the tarball at {} doesn't have the integrity {locked} that the lockfile \
                     `lpm migrate` wrote recorded for it, so these aren't the bytes the project \
                     had. Nothing was installed. Find out which tarball is the right one before \
                     going on: `lpm migrate --rollback` restores the original lockfile.",
                    lpm_common::safe_url_origin(url),
                )));
            }
        }
        Ok(())
    }

    /// Holds each package resolved at a recorded version to the recorded
    /// integrity. Refuses one whose registry integrity disagrees with it.
    /// One whose registry gives no integrity, or none as strong as the
    /// record's, takes the record's strongest hash, so its fetch verifies
    /// the bytes against what the lockfile recorded; a record that offers
    /// several alternatives of that algorithm can't be narrowed to one, and
    /// is left as compared. A record weaker than the registry's integrity
    /// leaves the fetch to verify the registry's.
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
        let locked = match package.source.strip_prefix("tarball+") {
            Some(url) => tarball_key(url).and_then(|url| self.by_tarball.get(&url)),
            None => self
                .by_name
                .get(&package.name)
                .and_then(|versions| versions.get(&package.version)),
        };
        let Some(locked) = locked else {
            return Ok(());
        };
        let resolved_strength = match package.integrity.as_deref() {
            None => None,
            Some(resolved) => {
                if compare_sri(locked, resolved) == SriComparison::Disagree {
                    return Err(refusal(package, resolved, locked));
                }
                strongest_algorithm(resolved)
            }
        };
        if strongest_algorithm(locked) > resolved_strength
            && let Some(strongest) = unique_strongest(locked)
        {
            package.integrity = Some(strongest.to_string());
        }
        Ok(())
    }
}

fn strongest_algorithm(sri: &str) -> Option<HashAlgorithm> {
    sri_hashes(sri).map(|hash| hash.algorithm).max()
}

/// The record's hash of its strongest algorithm, or `None` when it offers
/// several different ones of that algorithm, which one expected hash can't
/// express.
fn unique_strongest(sri: &str) -> Option<Integrity> {
    let algorithm = strongest_algorithm(sri)?;
    let mut hashes = sri_hashes(sri).filter(|hash| hash.algorithm == algorithm);
    let first = hashes.next()?;
    hashes.all(|hash| hash == first).then_some(first)
}

/// A tarball URL without credentials, query or fragment, as a migrated
/// lockfile records it.
fn tarball_key(url: &str) -> Option<String> {
    let mut url = reqwest::Url::parse(url).ok()?;
    let _ = url.set_username("");
    let _ = url.set_password(None);
    url.set_query(None);
    url.set_fragment(None);
    Some(url.into())
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
            by_tarball: HashMap::new(),
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
    fn a_registry_hash_weaker_than_the_record_is_replaced_even_when_it_agrees() {
        let recorded = sri(Sha512, b"private");
        let pins = locked(
            "corp-utils",
            "1.0.0",
            &format!("{} {recorded}", sri(Sha1, b"private")),
        );
        let package = apply_one(
            &pins,
            resolved("corp-utils", "1.0.0", Some(&sri(Sha1, b"private"))),
        )
        .unwrap();
        assert_eq!(package.integrity.as_deref(), Some(recorded.as_str()));
    }

    #[test]
    fn a_record_with_several_digests_of_its_strongest_algorithm_is_not_narrowed_to_one() {
        let pins = locked(
            "corp-utils",
            "1.0.0",
            &format!("{} {}", sri(Sha512, b"one"), sri(Sha512, b"two")),
        );
        let package = apply_one(&pins, resolved("corp-utils", "1.0.0", None)).unwrap();
        assert_eq!(package.integrity, None);
    }

    #[test]
    fn a_tarball_is_held_to_the_integrity_recorded_for_its_url_before_extraction() {
        let mut pins = LockedIntegrities::default();
        pins.by_tarball.insert(
            "https://cdn.example/actual-1.0.0.tgz".to_owned(),
            format!("{} {}", sri(Sha1, b"original"), sri(Sha512, b"original")),
        );
        let directory = tempfile::tempdir().unwrap();
        let file = directory.path().join("downloaded.tgz");

        std::fs::write(&file, b"original").unwrap();
        pins.check_tarball_file(
            "https://user:token@cdn.example/actual-1.0.0.tgz?sig=1#x",
            &file,
        )
        .unwrap();

        std::fs::write(&file, b"swapped").unwrap();
        let error = pins
            .check_tarball_file("https://cdn.example/actual-1.0.0.tgz", &file)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("cdn.example") && error.contains("lpm migrate --rollback"),
            "{error}"
        );
        assert!(!error.contains("token"), "{error}");

        pins.check_tarball_file("https://cdn.example/other-1.0.0.tgz", &file)
            .unwrap();
    }

    #[test]
    fn a_record_weaker_than_the_registry_hash_leaves_the_fetch_to_verify_the_registrys() {
        let pins = locked("old-pkg", "1.0.0", &sri(Sha1, b"old"));
        let registry = sri(Sha256, b"old");
        let package = apply_one(&pins, resolved("old-pkg", "1.0.0", Some(&registry))).unwrap();
        assert_eq!(package.integrity.as_deref(), Some(registry.as_str()));
    }

    #[test]
    fn a_tarball_package_is_held_to_the_record_for_its_url_not_a_registry_copys() {
        let mut pins = locked("foo", "1.0.0", &sri(Sha512, b"registry"));
        pins.by_tarball.insert(
            "https://example.test/foo-1.0.0.tgz".to_owned(),
            sri(Sha512, b"fork"),
        );
        let mut fork = resolved("foo", "1.0.0", Some(&sri(Sha512, b"fork")));
        fork.source = "tarball+https://example.test/foo-1.0.0.tgz".to_owned();
        apply_one(&pins, fork.clone()).unwrap();
        apply_one(
            &pins,
            resolved("foo", "1.0.0", Some(&sri(Sha512, b"registry"))),
        )
        .unwrap();

        fork.integrity = Some(sri(Sha512, b"swapped"));
        assert!(apply_one(&pins, fork).is_err());
    }

    #[test]
    fn tarballs_wait_for_the_check_while_a_migrated_lockfile_holds_integrities() {
        let without = super::super::InstallExpectations::default();
        assert!(!without.hold_tarball_prefetch(&[]));
        let with = super::super::InstallExpectations {
            locked_integrities: Some(Arc::new(LockedIntegrities::default())),
            ..Default::default()
        };
        assert!(with.hold_tarball_prefetch(&[]));
    }

    #[test]
    fn a_migrated_lockfile_holding_only_a_tarball_package_is_detected() {
        let directory = tempfile::tempdir().unwrap();
        let (mut lockfile, _) =
            lpm_migrate::normalize::to_lockfile(vec![lpm_migrate::MigratedPackage {
                lockfile_key: None,
                name: "shim".to_owned(),
                version: "1.0.0".to_owned(),
                resolved: Some("https://example.test/actual-1.0.0.tgz".to_owned()),
                integrity: Some(sri(Sha512, b"original")),
                dependencies: Vec::new(),
                is_optional: false,
                is_dev: false,
                published_as: Some("actual".to_owned()),
                fetched_from: lpm_migrate::FetchedFrom::DependencySpec,
            }])
            .unwrap();
        lockfile.metadata.resolved_with = Some(lpm_migrate::MIGRATED_LOCKFILE_RESOLVER.to_owned());
        lockfile
            .write_all(&directory.path().join(lpm_lockfile::LOCKFILE_NAME))
            .unwrap();

        let detected = LockedIntegrities::detect(directory.path())
            .unwrap()
            .unwrap();
        let file = directory.path().join("downloaded.tgz");
        std::fs::write(&file, b"swapped").unwrap();
        assert!(
            detected
                .check_tarball_file("https://example.test/actual-1.0.0.tgz", &file)
                .is_err()
        );
    }

    #[test]
    fn a_migrated_lockfile_that_no_longer_parses_stops_the_install() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::write(
            directory.path().join(lpm_lockfile::LOCKFILE_NAME),
            "[metadata]\nlockfile-version = 12\nresolved-with = \"migrate\"\n<<<<<<< HEAD\n",
        )
        .unwrap();
        let error = LockedIntegrities::detect(directory.path())
            .unwrap_err()
            .to_string();
        assert!(error.contains("lpm migrate --rollback"), "{error}");
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
                published_as: None,
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
