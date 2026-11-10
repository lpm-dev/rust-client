//! OSV knows npm packages, not `@lpm.dev` ones. An installed LPM package is
//! vulnerable through the npm packages it depends on directly, at the
//! versions its lockfile edges installed.

use std::collections::{BTreeSet, HashMap, HashSet};

use lpm_common::PackageInstanceId;
use lpm_common::package_name::is_lpm_package;

use super::discovery::DiscoveredPackage;
use super::osv::OsvVulnerability;

/// An OSV advisory on a direct npm dependency of an installed LPM package.
#[derive(Debug, Clone, Copy)]
pub(super) struct DependencyAdvisory<'a> {
    pub(super) dependency: &'a str,
    pub(super) version: &'a str,
    pub(super) vulnerability: &'a OsvVulnerability,
}

/// The advisories on each installed LPM package's direct npm dependencies,
/// by the package's lockfile instance. Two instances of one version can
/// install different versions of a dependency, so each answers for its own
/// edges. A lockfile without instances leaves only the name and version, and
/// the instances of one version count together.
pub(super) struct LpmDependencyAdvisories<'a> {
    by_instance: HashMap<PackageInstanceId, Vec<DependencyAdvisory<'a>>>,
    by_version: HashMap<&'a str, HashMap<&'a str, Vec<DependencyAdvisory<'a>>>>,
}

impl<'a> LpmDependencyAdvisories<'a> {
    pub(super) fn new(
        packages: &'a [DiscoveredPackage],
        vulnerabilities: &'a [OsvVulnerability],
    ) -> Self {
        let mut index = Self {
            by_instance: HashMap::new(),
            by_version: HashMap::new(),
        };
        let mut flagged_versions: HashMap<(&str, &str), Vec<&OsvVulnerability>> =
            HashMap::with_capacity(vulnerabilities.len());
        for vulnerability in vulnerabilities {
            flagged_versions
                .entry((&vulnerability.package, &vulnerability.version))
                .or_default()
                .push(vulnerability);
        }
        if flagged_versions.is_empty() {
            return index;
        }
        for advisories in flagged_versions.values_mut() {
            advisories.sort_unstable_by(|left, right| left.id.cmp(&right.id));
            advisories.dedup_by(|left, right| left.id == right.id);
        }

        // Each installed package's flagged edges, once each however many
        // lockfile rows share them, before any advisory is attached.
        let mut by_instance: HashMap<PackageInstanceId, BTreeSet<(&str, &str)>> = HashMap::new();
        let mut by_version: HashMap<(&str, &str), BTreeSet<(&str, &str)>> = HashMap::new();
        for package in packages
            .iter()
            .filter(|package| is_lpm_package(&package.name))
        {
            let mut edges = package
                .dependencies
                .iter()
                .filter(|(dependency, version)| {
                    !is_lpm_package(dependency)
                        && flagged_versions.contains_key(&(dependency.as_str(), version.as_str()))
                })
                .map(|(dependency, version)| (dependency.as_str(), version.as_str()))
                .peekable();
            if edges.peek().is_none() {
                continue;
            }
            match package.instance_id {
                Some(instance) => by_instance.entry(instance).or_default().extend(edges),
                None => by_version
                    .entry((&package.name, &package.version))
                    .or_default()
                    .extend(edges),
            }
        }
        let advisories = |edges: BTreeSet<(&'a str, &'a str)>| -> Vec<DependencyAdvisory<'a>> {
            edges
                .into_iter()
                .flat_map(|edge| {
                    flagged_versions[&edge]
                        .iter()
                        .map(move |vulnerability| DependencyAdvisory {
                            dependency: edge.0,
                            version: edge.1,
                            vulnerability,
                        })
                })
                .collect()
        };
        for (instance, edges) in by_instance {
            index.by_instance.insert(instance, advisories(edges));
        }
        for ((name, version), edges) in by_version {
            index
                .by_version
                .entry(name)
                .or_default()
                .insert(version, advisories(edges));
        }
        index
    }

    /// The advisories on the direct npm dependencies of the installed
    /// package `locked`, sorted by dependency, version and advisory id.
    pub(super) fn of(&self, locked: &lpm_lockfile::LockedPackage) -> &[DependencyAdvisory<'a>] {
        match locked.instance_id {
            Some(instance) => self.by_instance.get(&instance),
            None => self
                .by_version
                .get(locked.name.as_str())
                .and_then(|versions| versions.get(locked.version.as_str())),
        }
        .map_or(&[], Vec::as_slice)
    }
}

/// For each package in `packages`, whether it is an LPM package with a
/// direct npm dependency at a version in `vulnerable`, which maps package
/// names to vulnerable versions. Each answers for its own edges, so two
/// instances of one version can differ.
pub(crate) fn lpm_packages_with_vulnerable_dependencies(
    packages: &[DiscoveredPackage],
    vulnerable: &HashMap<String, HashSet<String>>,
) -> Vec<bool> {
    packages
        .iter()
        .map(|package| {
            is_lpm_package(&package.name)
                && package.dependencies.iter().any(|(dependency, version)| {
                    !is_lpm_package(dependency)
                        && vulnerable
                            .get(dependency)
                            .is_some_and(|versions| versions.contains(version))
                })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::audit::discovery::ScanMode;

    fn package(name: &str, version: &str, dependencies: &[(&str, &str)]) -> DiscoveredPackage {
        DiscoveredPackage {
            name: name.to_string(),
            version: version.to_string(),
            instance_id: None,
            path: format!("node_modules/{name}"),
            integrity: None,
            patch_sha256: None,
            resolved_url: None,
            local_source_dir: None,
            scan_mode: ScanMode::RegistryAndStore,
            is_dev: false,
            is_optional: false,
            dependencies: dependencies
                .iter()
                .map(|(name, version)| (name.to_string(), version.to_string()))
                .collect(),
        }
    }

    fn instance(n: u8) -> PackageInstanceId {
        PackageInstanceId::parse(&format!("{n:064x}")).unwrap()
    }

    fn installed_at(
        id: u8,
        name: &str,
        version: &str,
        dependencies: &[(&str, &str)],
    ) -> DiscoveredPackage {
        DiscoveredPackage {
            instance_id: Some(instance(id)),
            ..package(name, version, dependencies)
        }
    }

    fn locked(name: &str, version: &str, id: Option<u8>) -> lpm_lockfile::LockedPackage {
        lpm_lockfile::LockedPackage {
            name: name.to_string(),
            version: version.to_string(),
            instance_id: id.map(instance),
            ..Default::default()
        }
    }

    fn vulnerable(entries: &[(&str, &str)]) -> HashMap<String, HashSet<String>> {
        let mut map: HashMap<String, HashSet<String>> = HashMap::new();
        for (name, version) in entries {
            map.entry(name.to_string())
                .or_default()
                .insert(version.to_string());
        }
        map
    }

    #[test]
    fn the_index_lists_each_advisory_once_however_many_instances_share_it() {
        let mut packages: Vec<DiscoveredPackage> = (0..50)
            .map(|_| {
                package(
                    "@lpm.dev/acme.ui",
                    "1.0.0",
                    &[("lodash", "4.17.20"), ("react", "18.0.0")],
                )
            })
            .collect();
        packages.push(package("lodash", "4.17.20", &[]));
        let vulnerabilities = [
            OsvVulnerability::for_test("lodash", "4.17.20", "GHSA-b"),
            OsvVulnerability::for_test("lodash", "4.17.20", "GHSA-a"),
            OsvVulnerability::for_test("lodash", "4.17.20", "GHSA-a"),
            OsvVulnerability::for_test("lodash", "4.17.21", "GHSA-c"),
        ];

        let index = LpmDependencyAdvisories::new(&packages, &vulnerabilities);
        let advisories = index.of(&locked("@lpm.dev/acme.ui", "1.0.0", None));

        assert_eq!(
            advisories
                .iter()
                .map(|advisory| (
                    advisory.dependency,
                    advisory.version,
                    advisory.vulnerability.id.as_str()
                ))
                .collect::<Vec<_>>(),
            [
                ("lodash", "4.17.20", "GHSA-a"),
                ("lodash", "4.17.20", "GHSA-b")
            ]
        );
        assert!(
            index
                .of(&locked("@lpm.dev/acme.ui", "2.0.0", None))
                .is_empty()
        );
        assert!(index.of(&locked("lodash", "4.17.20", None)).is_empty());
    }

    #[test]
    fn each_instance_of_a_version_answers_for_its_own_edges() {
        let packages = [
            installed_at(1, "@lpm.dev/acme.ui", "1.0.0", &[("lodash", "4.17.20")]),
            installed_at(2, "@lpm.dev/acme.ui", "1.0.0", &[("lodash", "4.17.21")]),
            installed_at(3, "lodash", "4.17.20", &[]),
            installed_at(4, "lodash", "4.17.21", &[]),
        ];
        let vulnerabilities = [OsvVulnerability::for_test("lodash", "4.17.20", "GHSA-a")];

        let index = LpmDependencyAdvisories::new(&packages, &vulnerabilities);

        assert_eq!(
            index
                .of(&locked("@lpm.dev/acme.ui", "1.0.0", Some(1)))
                .len(),
            1
        );
        assert!(
            index
                .of(&locked("@lpm.dev/acme.ui", "1.0.0", Some(2)))
                .is_empty()
        );
        assert!(
            index
                .of(&locked("@lpm.dev/acme.ui", "1.0.0", None))
                .is_empty()
        );
        assert_eq!(
            lpm_packages_with_vulnerable_dependencies(
                &packages,
                &vulnerable(&[("lodash", "4.17.20")])
            ),
            [true, false, false, false]
        );
    }

    #[test]
    fn an_lpm_package_is_vulnerable_only_through_the_npm_versions_it_installs() {
        let packages = [
            package("@lpm.dev/acme.ui", "1.0.0", &[("lodash", "4.17.20")]),
            package("@lpm.dev/acme.form", "2.0.0", &[("lodash", "4.17.21")]),
            package("lodash", "4.17.20", &[]),
            package("lodash", "4.17.21", &[]),
        ];

        let matched = lpm_packages_with_vulnerable_dependencies(
            &packages,
            &vulnerable(&[("lodash", "4.17.20")]),
        );

        assert_eq!(matched, [true, false, false, false]);
    }

    #[test]
    fn an_lpm_package_is_not_vulnerable_through_another_lpm_package() {
        let packages = [
            package(
                "@lpm.dev/acme.app",
                "1.0.0",
                &[("@lpm.dev/acme.ui", "1.0.0")],
            ),
            package("@lpm.dev/acme.ui", "1.0.0", &[("lodash", "4.17.20")]),
        ];

        let matched = lpm_packages_with_vulnerable_dependencies(
            &packages,
            &vulnerable(&[("@lpm.dev/acme.ui", "1.0.0"), ("lodash", "4.17.20")]),
        );

        assert_eq!(matched, [false, true]);
    }

    #[test]
    fn npm_packages_are_left_to_their_own_osv_results() {
        let packages = [package("react", "18.0.0", &[("loose-envify", "1.0.0")])];

        assert_eq!(
            lpm_packages_with_vulnerable_dependencies(
                &packages,
                &vulnerable(&[("loose-envify", "1.0.0")])
            ),
            [false]
        );
    }
}
