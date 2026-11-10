//! OSV knows npm packages, not `@lpm.dev` ones. An installed LPM package is
//! vulnerable through the npm packages it depends on directly, at the
//! versions its lockfile edges installed.

use std::collections::{BTreeSet, HashMap, HashSet};

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
/// by the package's name and version. The instances of one version installed
/// under different peers count together.
pub(super) struct LpmDependencyAdvisories<'a> {
    by_package: HashMap<&'a str, HashMap<&'a str, Vec<DependencyAdvisory<'a>>>>,
}

impl<'a> LpmDependencyAdvisories<'a> {
    pub(super) fn new(
        packages: &'a [DiscoveredPackage],
        vulnerabilities: &'a [OsvVulnerability],
    ) -> Self {
        let mut by_instance: HashMap<(&str, &str), Vec<&OsvVulnerability>> =
            HashMap::with_capacity(vulnerabilities.len());
        for vulnerability in vulnerabilities {
            by_instance
                .entry((&vulnerability.package, &vulnerability.version))
                .or_default()
                .push(vulnerability);
        }
        for advisories in by_instance.values_mut() {
            advisories.sort_unstable_by(|left, right| left.id.cmp(&right.id));
            advisories.dedup_by(|left, right| left.id == right.id);
        }

        let mut by_package: HashMap<&str, HashMap<&str, Vec<DependencyAdvisory<'a>>>> =
            HashMap::new();
        if by_instance.is_empty() {
            return Self { by_package };
        }
        // The flagged edges of each LPM version, once each however many
        // instances share them, before any advisory is attached.
        let mut flagged: HashMap<(&str, &str), BTreeSet<(&str, &str)>> = HashMap::new();
        for package in packages
            .iter()
            .filter(|package| is_lpm_package(&package.name))
        {
            for (dependency, version) in &package.dependencies {
                if !is_lpm_package(dependency)
                    && by_instance.contains_key(&(dependency.as_str(), version.as_str()))
                {
                    flagged
                        .entry((&package.name, &package.version))
                        .or_default()
                        .insert((dependency, version));
                }
            }
        }
        for ((name, version), edges) in flagged {
            let advisories = edges
                .into_iter()
                .flat_map(|edge| {
                    by_instance[&edge]
                        .iter()
                        .map(move |vulnerability| DependencyAdvisory {
                            dependency: edge.0,
                            version: edge.1,
                            vulnerability,
                        })
                })
                .collect();
            by_package
                .entry(name)
                .or_default()
                .insert(version, advisories);
        }
        Self { by_package }
    }

    /// The advisories on `name`@`version`'s direct npm dependencies, sorted
    /// by dependency, version and advisory id.
    pub(super) fn of(&self, name: &str, version: &str) -> &[DependencyAdvisory<'a>] {
        self.by_package
            .get(name)
            .and_then(|versions| versions.get(version))
            .map_or(&[], Vec::as_slice)
    }
}

/// The installed LPM package versions with a direct npm dependency at a
/// version in `vulnerable`, which maps package names to vulnerable versions.
pub(crate) fn lpm_versions_with_vulnerable_dependencies(
    packages: &[DiscoveredPackage],
    vulnerable: &HashMap<String, HashSet<String>>,
) -> Vec<(String, String)> {
    if vulnerable.is_empty() {
        return Vec::new();
    }
    packages
        .iter()
        .filter(|package| is_lpm_package(&package.name))
        .filter(|package| {
            package.dependencies.iter().any(|(dependency, version)| {
                !is_lpm_package(dependency)
                    && vulnerable
                        .get(dependency)
                        .is_some_and(|versions| versions.contains(version))
            })
        })
        .map(|package| (package.name.clone(), package.version.clone()))
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
        let advisories = index.of("@lpm.dev/acme.ui", "1.0.0");

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
        assert!(index.of("@lpm.dev/acme.ui", "2.0.0").is_empty());
        assert!(index.of("lodash", "4.17.20").is_empty());
    }

    #[test]
    fn an_lpm_package_is_vulnerable_only_through_the_npm_versions_it_installs() {
        let packages = [
            package("@lpm.dev/acme.ui", "1.0.0", &[("lodash", "4.17.20")]),
            package("@lpm.dev/acme.form", "2.0.0", &[("lodash", "4.17.21")]),
            package("lodash", "4.17.20", &[]),
            package("lodash", "4.17.21", &[]),
        ];

        let matched = lpm_versions_with_vulnerable_dependencies(
            &packages,
            &vulnerable(&[("lodash", "4.17.20")]),
        );

        assert_eq!(
            matched,
            [("@lpm.dev/acme.ui".to_string(), "1.0.0".to_string())]
        );
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

        let matched = lpm_versions_with_vulnerable_dependencies(
            &packages,
            &vulnerable(&[("@lpm.dev/acme.ui", "1.0.0"), ("lodash", "4.17.20")]),
        );

        assert_eq!(
            matched,
            [("@lpm.dev/acme.ui".to_string(), "1.0.0".to_string())]
        );
    }

    #[test]
    fn npm_packages_are_left_to_their_own_osv_results() {
        let packages = [package("react", "18.0.0", &[("loose-envify", "1.0.0")])];

        assert!(
            lpm_versions_with_vulnerable_dependencies(
                &packages,
                &vulnerable(&[("loose-envify", "1.0.0")])
            )
            .is_empty()
        );
    }
}
