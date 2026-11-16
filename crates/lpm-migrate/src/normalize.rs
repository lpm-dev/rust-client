//! Conversion from `Vec<MigratedPackage>` to `lpm_lockfile::Lockfile`.
//!
//! Handles:
//! - Skipping unsupported dependency types (file:, link:, workspace:, patch:, git:, etc.)
//! - Inferring the source registry from the resolved URL, by its exact host
//! - Deduplicating same name+version pairs
//! - Formatting dependencies as `"name@version"` strings
//! - Sorting output for deterministic lockfiles

use crate::{CustomRegistryPackage, FetchedFrom, MigratedPackage, SkippedPackage};
use lpm_common::integrity::{HashAlgorithm, sri_hashes};
use lpm_common::{LpmError, SriComparison, compare_sri};
use lpm_lockfile::{
    LOCKFILE_VERSION_WITH_STRUCTURED_PEERS, LockedPackage, Lockfile, LockfileMetadata,
};
use std::collections::{HashMap, HashSet};

/// Prefixes that indicate non-registry dependencies (to be skipped).
const SKIP_PREFIXES: &[&str] = &[
    "exec:",
    "file:",
    "link:",
    "portal:",
    "workspace:",
    "patch:",
    "git:",
    "git+",
    "github:",
    "git+ssh:",
    "git+https:",
    "git+http:",
];

/// Convert parsed migration packages into an LPM lockfile.
///
/// Returns the lockfile and a list of skipped packages (with reasons).
pub fn to_lockfile(
    packages: Vec<MigratedPackage>,
) -> Result<(Lockfile, Vec<SkippedPackage>), LpmError> {
    let (lockfile, skipped, _) = to_lockfile_with_registries(packages)?;
    Ok((lockfile, skipped))
}

/// [`to_lockfile`], with every package the source package manager fetched
/// from a registry other than npm's and LPM's.
///
/// A package installed under an npm alias is recorded under the name its
/// registry publishes it as, and each dependency edge to it names that
/// target, as LPM's own lockfiles do. Refuses a lockfile that records two
/// different integrities for one version of a package, since LPM installs
/// one copy of each.
pub fn to_lockfile_with_registries(
    packages: Vec<MigratedPackage>,
) -> Result<(Lockfile, Vec<SkippedPackage>, Vec<CustomRegistryPackage>), LpmError> {
    let mut skipped = Vec::new();
    let mut custom_registry_packages: Vec<CustomRegistryPackage> = Vec::new();
    let mut reported_custom: HashSet<(String, String, String)> = HashSet::new();
    let mut locked_packages: Vec<LockedPackage> = Vec::with_capacity(packages.len());
    let mut locked_at: HashMap<(String, String, Option<String>), usize> =
        HashMap::with_capacity(packages.len());
    let alias_targets: HashMap<(String, String), String> = packages
        .iter()
        .filter_map(|package| {
            let target = package.published_as.as_ref()?;
            Some((
                (package.name.clone(), package.version.clone()),
                target.clone(),
            ))
        })
        .collect();

    for pkg in packages {
        // Skip packages with empty names
        if pkg.name.is_empty() {
            skipped.push(SkippedPackage {
                name: "(empty)".to_string(),
                reason: "empty package name".to_string(),
            });
            continue;
        }

        // Reject path traversal in package names
        if contains_path_traversal(&pkg.name) || contains_path_traversal(pkg.published_name()) {
            skipped.push(SkippedPackage {
                name: pkg.name.clone(),
                reason: "rejected: package name contains path traversal".to_string(),
            });
            continue;
        }

        // Skip file:/link:/git: dependencies
        if let Some(ref resolved) = pkg.resolved
            && let Some(prefix) = SKIP_PREFIXES.iter().find(|p| resolved.starts_with(**p))
        {
            skipped.push(SkippedPackage {
                name: pkg.name.clone(),
                reason: format!("unsupported dependency type: {prefix}"),
            });
            continue;
        }

        // Also check if version string itself is a non-registry reference
        if SKIP_PREFIXES.iter().any(|p| pkg.version.starts_with(p)) {
            skipped.push(SkippedPackage {
                name: pkg.name.clone(),
                reason: format!("unsupported version specifier: {}", pkg.version),
            });
            continue;
        }

        let (source, custom) = source_of(&pkg);
        if let Some(custom) = custom
            && reported_custom.insert((
                custom.name.clone(),
                custom.version.clone(),
                custom.tarball_url.clone(),
            ))
        {
            custom_registry_packages.push(custom);
        }

        // A copy fetched from a tarball URL is a different package from a
        // registry copy of the same version, and LPM keeps both apart.
        let spec_source = (pkg.fetched_from == FetchedFrom::DependencySpec).then(|| source.clone());
        let key = (
            pkg.published_as.unwrap_or(pkg.name),
            pkg.version,
            spec_source,
        );
        if let Some(&index) = locked_at.get(&key) {
            let locked = &mut locked_packages[index];
            match (locked.integrity.as_deref(), pkg.integrity) {
                (Some(recorded), Some(other)) => match compare_sri(recorded, &other) {
                    SriComparison::Disagree => {
                        return Err(LpmError::Script(format!(
                            "the lockfile records two different integrities for {}@{} from \
                             the same source, and LPM installs one copy of it. Install the \
                             project with its current package manager to settle on one, then \
                             migrate again.",
                            key.0, key.1
                        )));
                    }
                    SriComparison::Agree | SriComparison::NoCommonAlgorithm
                        if strongest_algorithm(&other) > strongest_algorithm(recorded) =>
                    {
                        locked.integrity = Some(other);
                    }
                    SriComparison::Agree | SriComparison::NoCommonAlgorithm => {}
                },
                (None, Some(other)) => locked.integrity = Some(other),
                (_, None) => {}
            }
            continue;
        }

        let mut dependencies = Vec::with_capacity(pkg.dependencies.len());
        let mut alias_dependencies = Vec::new();
        for (dependency, version) in pkg.dependencies {
            dependencies.push(format!("{dependency}@{version}"));
            if alias_targets.is_empty() {
                continue;
            }
            let edge = (dependency, version);
            if let Some(target) = alias_targets.get(&edge) {
                alias_dependencies.push([edge.0, target.clone()]);
            }
        }
        alias_dependencies.sort_unstable();
        alias_dependencies.dedup_by(|later, earlier| later[0] == earlier[0]);

        locked_at.insert(key.clone(), locked_packages.len());
        let (name, version, _) = key;
        locked_packages.push(LockedPackage {
            instance_id: None,
            dependency_targets: std::collections::BTreeMap::new(),
            peer_targets: std::collections::BTreeMap::new(),
            name,
            version,
            source: Some(source),
            integrity: pkg.integrity,
            unpacked_size: None,
            manifest_fingerprint: None,
            registry_signatures: Vec::new(),
            registry_published_at: None,
            os: Vec::new(),
            cpu: Vec::new(),
            libc: Vec::new(),
            node_engine: None,
            optional: false,
            dependencies,
            alias_dependencies,
            // Migrated lockfiles don't carry per-package peer state
            // from the source format. The next `lpm install`
            // re-derives peers through the resolver and writes them
            // into the lockfile.
            peers: Vec::new(),
            peer_edges: Vec::new(),
            tarball: None,
        });
    }

    // Sort by name, then version for deterministic output
    // The lockfile orders packages by name, version, then source identity,
    // which only a version taken from both a registry and a tarball URL needs.
    locked_packages.sort_by(|a, b| {
        a.name
            .cmp(&b.name)
            .then_with(|| a.version.cmp(&b.version))
            .then_with(|| a.package_key().source_id.cmp(&b.package_key().source_id))
    });

    let lockfile = Lockfile {
        metadata: LockfileMetadata {
            lockfile_version: LOCKFILE_VERSION_WITH_STRUCTURED_PEERS,
            resolved_with: Some(crate::MIGRATED_LOCKFILE_RESOLVER.to_owned()),
            auto_isolated_peer_conflicts: false,
        },
        importers: lpm_lockfile::ImporterSnapshots::new(),
        patches: lpm_lockfile::LockfilePatches::new(),
        catalogs: lpm_lockfile::CatalogSnapshots::new(),
        provenance: std::collections::BTreeMap::new(),
        packages: locked_packages,
        workspace_packages: std::collections::BTreeMap::new(),
        root_aliases: std::collections::BTreeMap::new(),
        root_resolutions: lpm_lockfile::RootResolutions::new(),
        // `lpm migrate` translates yarn/pnpm/npm lockfiles into the
        // lpm shape; the source formats don't track synthesized ambient
        // peers (those are an lpm-resolver semantic, not a generic
        // lockfile concept). Migrated lockfiles start with no ambient
        // peers; the next
        // `lpm install` re-derives them through the resolver if
        // `auto_install_peers` is on, and writes them into the next
        // lockfile.
        ambient_peer_installs: Vec::new(),
    };

    Ok((lockfile, skipped, custom_registry_packages))
}

fn strongest_algorithm(sri: &str) -> Option<HashAlgorithm> {
    sri_hashes(sri).map(|hash| hash.algorithm).max()
}

/// Mark packages as dev or optional based on package.json dependency sets.
///
/// Yarn v1 lockfiles don't encode dev/optional at the entry level, so this
/// function cross-references with the names from `devDependencies` and
/// `optionalDependencies` in package.json.
pub fn mark_dev_optional(
    packages: &mut [MigratedPackage],
    dev_deps: &HashSet<String>,
    optional_deps: &HashSet<String>,
) {
    for pkg in packages.iter_mut() {
        if dev_deps.contains(&pkg.name) {
            pkg.is_dev = true;
        }
        if optional_deps.contains(&pkg.name) {
            pkg.is_optional = true;
        }
    }
}

/// Check if a package name contains path traversal sequences.
///
/// Rejects names with `..`, backslashes, or control characters that could
/// be used to escape the intended directory structure during install/link.
fn contains_path_traversal(name: &str) -> bool {
    // Scoped packages start with @ — that's fine. But the rest must be clean.
    // Allow: @scope/name, name, @scope/name-with-dashes
    // Reject: ../evil, name\..\..\etc, name with NUL bytes
    name.contains("..")
        || name.contains('\\')
        || name.contains('\0')
        || name.bytes().any(|b| b < 0x20 && b != b'\t')
}

const NPM_SOURCE: &str = "registry+https://registry.npmjs.org";
const LPM_SOURCE: &str = "registry+https://lpm.dev";

/// Which registry a tarball URL belongs to, by its exact host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistryOrigin {
    Npm,
    Lpm,
    Custom,
}

/// The registry of an `http(s)` tarball URL. A host that merely contains a
/// known registry's name, such as `registry.npmjs.org.example`, is custom,
/// and so is any host under `lpm.dev` other than the registry's own.
pub fn registry_origin(url: &str) -> RegistryOrigin {
    let Some(host) = url::Url::parse(url)
        .ok()
        .and_then(|url| url.host_str().map(str::to_ascii_lowercase))
    else {
        return RegistryOrigin::Custom;
    };
    match host.as_str() {
        "registry.npmjs.org" | "registry.yarnpkg.com" => RegistryOrigin::Npm,
        "lpm.dev" => RegistryOrigin::Lpm,
        _ => RegistryOrigin::Custom,
    }
}

/// The lockfile source for `package`, and the package as a
/// [`CustomRegistryPackage`] when the registry it came from is neither
/// npm's nor LPM's.
fn source_of(package: &MigratedPackage) -> (String, Option<CustomRegistryPackage>) {
    let url = package.resolved.as_deref().and_then(public_tarball_url);
    let Some(registry_name) = package.registry_name() else {
        return match url {
            Some(url) => (format!("tarball+{url}"), None),
            None => (NPM_SOURCE.to_owned(), None),
        };
    };
    let Some(url) = url else {
        let unreadable = package
            .resolved
            .as_deref()
            .is_some_and(|resolved| !resolved.trim().is_empty())
            .then(|| {
                let shown = "a resolved location that isn't an http(s) URL".to_owned();
                CustomRegistryPackage {
                    name: registry_name.to_owned(),
                    version: package.version.clone(),
                    tarball_url: shown.clone(),
                    shown_as: shown,
                }
            });
        return (NPM_SOURCE.to_owned(), unreadable);
    };
    match registry_origin(url.as_str()) {
        RegistryOrigin::Npm => (NPM_SOURCE.to_owned(), None),
        RegistryOrigin::Lpm => (LPM_SOURCE.to_owned(), None),
        RegistryOrigin::Custom => (
            format!("registry+{}", registry_base(&url, registry_name)),
            Some(CustomRegistryPackage {
                name: registry_name.to_owned(),
                version: package.version.clone(),
                shown_as: url.to_string(),
                tarball_url: url.into(),
            }),
        ),
    }
}

/// `resolved` as an `http(s)` URL without credentials, query or fragment, so
/// nothing it reports or records can carry a registry token.
pub(crate) fn public_tarball_url(resolved: &str) -> Option<url::Url> {
    let mut url = url::Url::parse(resolved).ok()?;
    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
        return None;
    }
    let _ = url.set_username("");
    let _ = url.set_password(None);
    url.set_query(None);
    url.set_fragment(None);
    Some(url)
}

/// The registry a URL sits under: everything before the npm layout's
/// `/<name>/-/`. A tarball outside that layout gives its origin; a URL
/// that names no tarball, as Bun records a registry, is the registry.
fn registry_base(url: &url::Url, name: &str) -> String {
    let path = url.path();
    let lowercase_path = path.to_ascii_lowercase();
    let lowercase_name = name.to_ascii_lowercase();
    let encoded = lowercase_name.replacen('/', "%2f", 1);
    let prefix_end = [format!("/{lowercase_name}/-/"), format!("/{encoded}/-/")]
        .iter()
        .find_map(|marker| lowercase_path.find(marker.as_str()))
        .map(|at| at + 1);
    let mut base = url.origin().ascii_serialization();
    match prefix_end {
        Some(end) => base.push_str(&path[..end]),
        None if lowercase_path.ends_with(".tgz") => base.push('/'),
        None => {
            base.push_str(path.trim_end_matches('/'));
            base.push('/');
        }
    }
    base
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_pkg(name: &str, version: &str, resolved: Option<&str>) -> MigratedPackage {
        MigratedPackage {
            lockfile_key: None,
            name: name.to_string(),
            version: version.to_string(),
            resolved: resolved.map(String::from),
            integrity: Some(format!("sha512-{name}{version}")),
            dependencies: Vec::new(),
            is_optional: false,
            is_dev: false,
            published_as: None,
            fetched_from: FetchedFrom::Registry,
        }
    }

    #[test]
    fn basic_conversion() {
        let packages = vec![
            make_pkg(
                "express",
                "4.22.1",
                Some("https://registry.npmjs.org/express/-/express-4.22.1.tgz"),
            ),
            make_pkg(
                "lodash",
                "4.17.21",
                Some("https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"),
            ),
        ];

        let (lockfile, skipped) = to_lockfile(packages).unwrap();
        assert!(skipped.is_empty());
        assert_eq!(lockfile.packages.len(), 2);
        assert_eq!(lockfile.metadata.resolved_with.as_deref(), Some("migrate"));
        assert_eq!(
            lockfile.metadata.lockfile_version,
            LOCKFILE_VERSION_WITH_STRUCTURED_PEERS
        );

        // Sorted by name
        assert_eq!(lockfile.packages[0].name, "express");
        assert_eq!(lockfile.packages[1].name, "lodash");
    }

    #[test]
    fn skips_file_and_git_links() {
        let packages = vec![
            make_pkg(
                "real-pkg",
                "1.0.0",
                Some("https://registry.npmjs.org/real-pkg/-/real-pkg-1.0.0.tgz"),
            ),
            MigratedPackage {
                lockfile_key: None,
                name: "local-pkg".to_string(),
                version: "1.0.0".to_string(),
                resolved: Some("file:../local-pkg".to_string()),
                integrity: None,
                dependencies: Vec::new(),
                is_optional: false,
                is_dev: false,
                published_as: None,
                fetched_from: FetchedFrom::Registry,
            },
            MigratedPackage {
                lockfile_key: None,
                name: "git-pkg".to_string(),
                version: "1.0.0".to_string(),
                resolved: Some("git+https://github.com/user/repo.git#abc123".to_string()),
                integrity: None,
                dependencies: Vec::new(),
                is_optional: false,
                is_dev: false,
                published_as: None,
                fetched_from: FetchedFrom::Registry,
            },
            MigratedPackage {
                lockfile_key: None,
                name: "link-pkg".to_string(),
                version: "1.0.0".to_string(),
                resolved: Some("link:./packages/link-pkg".to_string()),
                integrity: None,
                dependencies: Vec::new(),
                is_optional: false,
                is_dev: false,
                published_as: None,
                fetched_from: FetchedFrom::Registry,
            },
        ];

        let (lockfile, skipped) = to_lockfile(packages).unwrap();
        assert_eq!(lockfile.packages.len(), 1);
        assert_eq!(lockfile.packages[0].name, "real-pkg");
        assert_eq!(skipped.len(), 3);

        let skip_names: Vec<&str> = skipped.iter().map(|s| s.name.as_str()).collect();
        assert!(skip_names.contains(&"local-pkg"));
        assert!(skip_names.contains(&"git-pkg"));
        assert!(skip_names.contains(&"link-pkg"));
    }

    #[test]
    fn skips_empty_name() {
        let packages = vec![MigratedPackage {
            lockfile_key: None,
            name: String::new(),
            version: "1.0.0".to_string(),
            resolved: Some("https://registry.npmjs.org/x.tgz".to_string()),
            integrity: None,
            dependencies: Vec::new(),
            is_optional: false,
            is_dev: false,
            published_as: None,
            fetched_from: FetchedFrom::Registry,
        }];

        let (lockfile, skipped) = to_lockfile(packages).unwrap();
        assert_eq!(lockfile.packages.len(), 0);
        assert_eq!(skipped.len(), 1);
        assert!(skipped[0].reason.contains("empty"));
    }

    #[test]
    fn source_inference() {
        let packages = vec![
            make_pkg(
                "lpm-pkg",
                "1.0.0",
                Some("https://lpm.dev/api/packages/lpm-pkg/-/lpm-pkg-1.0.0.tgz"),
            ),
            make_pkg(
                "npm-pkg",
                "1.0.0",
                Some("https://registry.npmjs.org/npm-pkg/-/npm-pkg-1.0.0.tgz"),
            ),
            make_pkg(
                "yarn-pkg",
                "1.0.0",
                Some("https://registry.yarnpkg.com/yarn-pkg/-/yarn-pkg-1.0.0.tgz"),
            ),
            make_pkg("unknown-pkg", "1.0.0", None),
        ];

        let (lockfile, _) = to_lockfile(packages).unwrap();
        assert_eq!(lockfile.packages.len(), 4);

        let lpm = lockfile
            .packages
            .iter()
            .find(|p| p.name == "lpm-pkg")
            .unwrap();
        assert_eq!(lpm.source.as_deref(), Some("registry+https://lpm.dev"));

        let npm = lockfile
            .packages
            .iter()
            .find(|p| p.name == "npm-pkg")
            .unwrap();
        assert_eq!(
            npm.source.as_deref(),
            Some("registry+https://registry.npmjs.org")
        );

        let yarn = lockfile
            .packages
            .iter()
            .find(|p| p.name == "yarn-pkg")
            .unwrap();
        assert_eq!(
            yarn.source.as_deref(),
            Some("registry+https://registry.npmjs.org")
        );

        let unknown = lockfile
            .packages
            .iter()
            .find(|p| p.name == "unknown-pkg")
            .unwrap();
        assert_eq!(
            unknown.source.as_deref(),
            Some("registry+https://registry.npmjs.org")
        );
    }

    #[test]
    fn dedup_same_name_version() {
        let packages = vec![
            make_pkg(
                "express",
                "4.22.1",
                Some("https://registry.npmjs.org/express/-/express-4.22.1.tgz"),
            ),
            make_pkg(
                "express",
                "4.22.1",
                Some("https://registry.npmjs.org/express/-/express-4.22.1.tgz"),
            ),
        ];

        let (lockfile, _) = to_lockfile(packages).unwrap();
        assert_eq!(lockfile.packages.len(), 1);
    }

    #[test]
    fn multi_version_preserved() {
        let packages = vec![
            make_pkg(
                "debug",
                "2.6.9",
                Some("https://registry.npmjs.org/debug/-/debug-2.6.9.tgz"),
            ),
            make_pkg(
                "debug",
                "4.3.4",
                Some("https://registry.npmjs.org/debug/-/debug-4.3.4.tgz"),
            ),
        ];

        let (lockfile, _) = to_lockfile(packages).unwrap();
        assert_eq!(lockfile.packages.len(), 2);
        assert_eq!(lockfile.packages[0].version, "2.6.9");
        assert_eq!(lockfile.packages[1].version, "4.3.4");
    }

    #[test]
    fn preserves_deps_as_name_at_version() {
        let packages = vec![MigratedPackage {
            lockfile_key: None,
            name: "express".to_string(),
            version: "4.22.1".to_string(),
            resolved: Some("https://registry.npmjs.org/express/-/express-4.22.1.tgz".to_string()),
            integrity: Some("sha512-abc".to_string()),
            dependencies: vec![
                ("accepts".to_string(), "1.3.8".to_string()),
                ("body-parser".to_string(), "1.20.3".to_string()),
            ],
            is_optional: false,
            is_dev: false,
            published_as: None,
            fetched_from: FetchedFrom::Registry,
        }];

        let (lockfile, _) = to_lockfile(packages).unwrap();
        let express = &lockfile.packages[0];
        assert_eq!(express.dependencies.len(), 2);
        assert_eq!(express.dependencies[0], "accepts@1.3.8");
        assert_eq!(express.dependencies[1], "body-parser@1.20.3");
    }

    #[test]
    fn sorted_output() {
        let packages = vec![
            make_pkg(
                "zlib",
                "1.0.0",
                Some("https://registry.npmjs.org/zlib/-/zlib-1.0.0.tgz"),
            ),
            make_pkg(
                "alpha",
                "2.0.0",
                Some("https://registry.npmjs.org/alpha/-/alpha-2.0.0.tgz"),
            ),
            make_pkg(
                "middle",
                "3.0.0",
                Some("https://registry.npmjs.org/middle/-/middle-3.0.0.tgz"),
            ),
        ];

        let (lockfile, _) = to_lockfile(packages).unwrap();
        assert_eq!(lockfile.packages[0].name, "alpha");
        assert_eq!(lockfile.packages[1].name, "middle");
        assert_eq!(lockfile.packages[2].name, "zlib");
    }

    #[test]
    fn a_registry_is_recognized_by_its_exact_host() {
        assert_eq!(
            registry_origin("https://registry.npmjs.org/ms/-/ms-2.1.3.tgz"),
            RegistryOrigin::Npm
        );
        assert_eq!(
            registry_origin("https://registry.yarnpkg.com/ms/-/ms-2.1.3.tgz"),
            RegistryOrigin::Npm
        );
        assert_eq!(
            registry_origin("https://lpm.dev/api/registry/@lpm.dev/a/-/a-1.0.0.tgz"),
            RegistryOrigin::Lpm
        );
        for custom in [
            "https://registry.npmjs.org.evil.example/ms/-/ms-2.1.3.tgz",
            "https://evil-lpm.dev/ms/-/ms-2.1.3.tgz",
            "https://mirror.lpm.dev/ms/-/ms-2.1.3.tgz",
            "https://npm.corp.example/ms/-/ms-2.1.3.tgz",
        ] {
            assert_eq!(registry_origin(custom), RegistryOrigin::Custom, "{custom}");
        }
    }

    #[test]
    fn a_package_from_a_custom_registry_is_reported_with_its_tarball_url() {
        let (lockfile, _, custom) = to_lockfile_with_registries(vec![
            make_pkg(
                "ms",
                "2.1.3",
                Some("https://registry.npmjs.org/ms/-/ms-2.1.3.tgz"),
            ),
            make_pkg(
                "corp-utils",
                "1.0.0",
                Some(
                    "https://user:secret@npm.corp.example/api/npm/corp-utils/-/corp-utils-1.0.0.tgz?sig=x",
                ),
            ),
        ]).unwrap();
        assert_eq!(
            custom,
            vec![CustomRegistryPackage {
                name: "corp-utils".to_owned(),
                version: "1.0.0".to_owned(),
                tarball_url: "https://npm.corp.example/api/npm/corp-utils/-/corp-utils-1.0.0.tgz"
                    .to_owned(),
                shown_as: "https://npm.corp.example/api/npm/corp-utils/-/corp-utils-1.0.0.tgz"
                    .to_owned(),
            }],
            "only the custom registry is reported, and never with its credentials"
        );
        let corp = lockfile.find_package("corp-utils").unwrap();
        assert_eq!(
            corp.source.as_deref(),
            Some("registry+https://npm.corp.example/api/npm/")
        );
    }

    #[test]
    fn a_scoped_package_records_the_registry_above_its_scope() {
        let (lockfile, _, _) = to_lockfile_with_registries(vec![make_pkg(
            "@corp/utils",
            "1.0.0",
            Some("https://npm.corp.example/@corp/utils/-/utils-1.0.0.tgz"),
        )])
        .unwrap();
        assert_eq!(
            lockfile
                .find_package("@corp/utils")
                .unwrap()
                .source
                .as_deref(),
            Some("registry+https://npm.corp.example/")
        );
    }

    fn aliased(installed: &str, target: &str, version: &str, resolved: &str) -> MigratedPackage {
        MigratedPackage {
            published_as: Some(target.to_owned()),
            ..make_pkg(installed, version, Some(resolved))
        }
    }

    #[test]
    fn an_aliased_package_is_recorded_and_reported_under_the_name_its_registry_publishes() {
        let mut dependent = make_pkg(
            "app-lib",
            "2.0.0",
            Some("https://registry.npmjs.org/app-lib/-/app-lib-2.0.0.tgz"),
        );
        dependent.dependencies = vec![("utils".to_owned(), "1.0.0".to_owned())];
        dependent.integrity = None;
        let mut target = aliased(
            "utils",
            "@corp/utils",
            "1.0.0",
            "https://npm.corp.example/@corp/utils/-/utils-1.0.0.tgz",
        );
        target.integrity = None;
        let (lockfile, _, custom) = to_lockfile_with_registries(vec![dependent, target]).unwrap();

        assert!(lockfile.find_package("utils").is_none());
        let target = lockfile.find_package("@corp/utils").unwrap();
        assert_eq!(
            target.source.as_deref(),
            Some("registry+https://npm.corp.example/")
        );
        let dependent = lockfile.find_package("app-lib").unwrap();
        assert_eq!(dependent.dependencies, vec!["utils@1.0.0".to_owned()]);
        assert_eq!(
            dependent.alias_dependencies,
            vec![["utils".to_owned(), "@corp/utils".to_owned()]]
        );
        assert_eq!(
            custom,
            vec![CustomRegistryPackage {
                name: "@corp/utils".to_owned(),
                version: "1.0.0".to_owned(),
                tarball_url: "https://npm.corp.example/@corp/utils/-/utils-1.0.0.tgz".to_owned(),
                shown_as: "https://npm.corp.example/@corp/utils/-/utils-1.0.0.tgz".to_owned(),
            }]
        );
        lockfile
            .to_toml()
            .expect("the alias edge must satisfy the lockfile's own schema");
    }

    #[test]
    fn a_package_fetched_from_its_dependency_spec_is_recorded_as_a_tarball_and_not_reported() {
        let (lockfile, _, custom) = to_lockfile_with_registries(vec![MigratedPackage {
            fetched_from: FetchedFrom::DependencySpec,
            ..make_pkg(
                "xlsx",
                "0.20.3",
                Some("https://cdn.sheetjs.com/xlsx-0.20.3/xlsx-0.20.3.tgz"),
            )
        }])
        .unwrap();
        assert!(custom.is_empty(), "{custom:?}");
        assert_eq!(
            lockfile.find_package("xlsx").unwrap().source.as_deref(),
            Some("tarball+https://cdn.sheetjs.com/xlsx-0.20.3/xlsx-0.20.3.tgz")
        );
    }

    #[test]
    fn a_tarball_dependency_is_recorded_under_the_name_its_own_package_gives() {
        let (lockfile, _, custom) = to_lockfile_with_registries(vec![MigratedPackage {
            published_as: Some("actual".to_owned()),
            fetched_from: FetchedFrom::DependencySpec,
            ..make_pkg(
                "shim",
                "1.0.0",
                Some("https://example.test/actual-1.0.0.tgz"),
            )
        }])
        .unwrap();
        assert!(custom.is_empty(), "{custom:?}");
        assert!(lockfile.find_package("shim").is_none());
        assert_eq!(
            lockfile.find_package("actual").unwrap().source.as_deref(),
            Some("tarball+https://example.test/actual-1.0.0.tgz")
        );
    }

    fn real_sri(algorithm: lpm_common::integrity::HashAlgorithm, data: &[u8]) -> String {
        lpm_common::Integrity::from_bytes(algorithm, data).to_string()
    }

    #[test]
    fn a_version_from_a_tarball_url_and_from_a_registry_is_kept_as_two_packages() {
        use lpm_common::integrity::HashAlgorithm::Sha512;
        let fork = MigratedPackage {
            integrity: Some(real_sri(Sha512, b"fork")),
            fetched_from: FetchedFrom::DependencySpec,
            ..make_pkg("foo", "1.0.0", Some("https://example.test/foo-1.0.0.tgz"))
        };
        let registry = MigratedPackage {
            integrity: Some(real_sri(Sha512, b"registry")),
            ..make_pkg(
                "foo",
                "1.0.0",
                Some("https://registry.npmjs.org/foo/-/foo-1.0.0.tgz"),
            )
        };
        let (lockfile, _, _) = to_lockfile_with_registries(vec![fork, registry]).unwrap();
        let mut sources: Vec<_> = lockfile
            .packages
            .iter()
            .map(|package| {
                (
                    package.source.clone().unwrap(),
                    package.integrity.clone().unwrap(),
                )
            })
            .collect();
        sources.sort();
        assert_eq!(
            sources,
            vec![
                (
                    "registry+https://registry.npmjs.org".to_owned(),
                    real_sri(Sha512, b"registry")
                ),
                (
                    "tarball+https://example.test/foo-1.0.0.tgz".to_owned(),
                    real_sri(Sha512, b"fork")
                ),
            ]
        );
        lockfile
            .to_toml()
            .expect("two sources of one version must satisfy the lockfile's order");
    }

    #[test]
    fn the_stronger_integrity_of_two_copies_is_kept_whichever_came_first() {
        use lpm_common::integrity::HashAlgorithm::{Sha1, Sha512};
        let copy = |integrity: String| MigratedPackage {
            integrity: Some(integrity),
            ..make_pkg(
                "ms",
                "2.1.3",
                Some("https://registry.npmjs.org/ms/-/ms-2.1.3.tgz"),
            )
        };
        let (lockfile, _, _) = to_lockfile_with_registries(vec![
            copy(real_sri(Sha1, b"ms")),
            copy(real_sri(Sha512, b"ms")),
        ])
        .unwrap();
        assert_eq!(
            lockfile.find_package("ms").unwrap().integrity,
            Some(real_sri(Sha512, b"ms"))
        );
    }

    #[test]
    fn the_stronger_integrity_of_two_agreeing_copies_is_kept_in_either_order() {
        use lpm_common::integrity::HashAlgorithm::{Sha1, Sha512};
        let copy = |integrity: String| MigratedPackage {
            integrity: Some(integrity),
            ..make_pkg(
                "ms",
                "2.1.3",
                Some("https://registry.npmjs.org/ms/-/ms-2.1.3.tgz"),
            )
        };
        let weak = real_sri(Sha1, b"ms");
        let strong = format!("{weak} {}", real_sri(Sha512, b"ms"));
        for order in [
            [weak.clone(), strong.clone()],
            [strong.clone(), weak.clone()],
        ] {
            let (lockfile, _, _) =
                to_lockfile_with_registries(order.iter().cloned().map(copy).collect()).unwrap();
            assert_eq!(
                lockfile.find_package("ms").unwrap().integrity.as_deref(),
                Some(strong.as_str()),
                "{order:?}"
            );
        }
    }

    #[test]
    fn every_copy_of_a_version_from_a_custom_registry_is_reported() {
        let (lockfile, _, custom) = to_lockfile_with_registries(vec![
            make_pkg(
                "corp-utils",
                "1.0.0",
                Some("https://registry.npmjs.org/corp-utils/-/corp-utils-1.0.0.tgz"),
            ),
            make_pkg(
                "corp-utils",
                "1.0.0",
                Some("https://npm.corp.example/corp-utils/-/corp-utils-1.0.0.tgz"),
            ),
        ])
        .unwrap();
        assert_eq!(lockfile.packages.len(), 1);
        assert_eq!(
            custom,
            vec![CustomRegistryPackage {
                name: "corp-utils".to_owned(),
                version: "1.0.0".to_owned(),
                tarball_url: "https://npm.corp.example/corp-utils/-/corp-utils-1.0.0.tgz"
                    .to_owned(),
                shown_as: "https://npm.corp.example/corp-utils/-/corp-utils-1.0.0.tgz".to_owned(),
            }]
        );
    }

    #[test]
    fn two_integrities_for_one_package_version_refuse_the_migration() {
        let sri = |data: &[u8]| {
            lpm_common::Integrity::from_bytes(lpm_common::integrity::HashAlgorithm::Sha512, data)
                .to_string()
        };
        let copy = |resolved: &str, integrity: String| MigratedPackage {
            integrity: Some(integrity),
            ..make_pkg("corp-utils", "1.0.0", Some(resolved))
        };
        let error = to_lockfile_with_registries(vec![
            copy(
                "https://npm.corp.example/corp-utils/-/corp-utils-1.0.0.tgz",
                sri(b"private"),
            ),
            copy(
                "https://registry.npmjs.org/corp-utils/-/corp-utils-1.0.0.tgz",
                sri(b"public"),
            ),
        ])
        .unwrap_err()
        .to_string();
        assert!(error.contains("corp-utils@1.0.0"), "{error}");
    }

    #[test]
    fn a_copy_that_records_an_integrity_fills_in_one_that_records_none() {
        let mut first = make_pkg(
            "ms",
            "2.1.3",
            Some("https://registry.npmjs.org/ms/-/ms-2.1.3.tgz"),
        );
        first.integrity = None;
        let second = make_pkg(
            "ms",
            "2.1.3",
            Some("https://registry.npmjs.org/ms/-/ms-2.1.3.tgz"),
        );
        let recorded = second.integrity.clone();
        let (lockfile, _, _) = to_lockfile_with_registries(vec![first, second]).unwrap();
        assert_eq!(lockfile.find_package("ms").unwrap().integrity, recorded);
    }

    #[test]
    fn a_registry_url_bun_records_is_the_registry_itself() {
        let (lockfile, _, _) = to_lockfile_with_registries(vec![make_pkg(
            "@corp/utils",
            "1.0.0",
            Some("https://corp.example/artifactory/api/npm/npm-private/"),
        )])
        .unwrap();
        assert_eq!(
            lockfile
                .find_package("@corp/utils")
                .unwrap()
                .source
                .as_deref(),
            Some("registry+https://corp.example/artifactory/api/npm/npm-private/")
        );
    }

    #[test]
    fn a_resolved_location_that_is_not_a_url_is_reported_rather_than_taken_for_npm() {
        let (_, _, custom) = to_lockfile_with_registries(vec![make_pkg(
            "corp-utils",
            "1.0.0",
            Some("//npm.corp.example/corp-utils/-/corp-utils-1.0.0.tgz"),
        )])
        .unwrap();
        assert_eq!(custom.len(), 1, "{custom:?}");
        assert_eq!(custom[0].name, "corp-utils");
        assert!(
            !custom[0].tarball_url.contains("npm.corp.example"),
            "{custom:?}"
        );
    }

    #[test]
    fn skips_version_with_file_prefix() {
        let packages = vec![MigratedPackage {
            lockfile_key: None,
            name: "local".to_string(),
            version: "file:../local".to_string(),
            resolved: None,
            integrity: None,
            dependencies: Vec::new(),
            is_optional: false,
            is_dev: false,
            published_as: None,
            fetched_from: FetchedFrom::Registry,
        }];

        let (lockfile, skipped) = to_lockfile(packages).unwrap();
        assert_eq!(lockfile.packages.len(), 0);
        assert_eq!(skipped.len(), 1);
    }

    #[test]
    fn skips_workspace_and_patch_protocols() {
        let packages = vec![
            MigratedPackage {
                lockfile_key: None,
                name: "workspace-a".to_string(),
                version: "0.0.0-use.local".to_string(),
                resolved: Some("workspace:packages/workspace-a".to_string()),
                integrity: None,
                dependencies: Vec::new(),
                is_optional: false,
                is_dev: false,
                published_as: None,
                fetched_from: FetchedFrom::Registry,
            },
            MigratedPackage {
                lockfile_key: None,
                name: "patched".to_string(),
                version: "1.0.0".to_string(),
                resolved: Some("patch:patched@npm%3A1.0.0#./patched.patch".to_string()),
                integrity: None,
                dependencies: Vec::new(),
                is_optional: false,
                is_dev: false,
                published_as: None,
                fetched_from: FetchedFrom::Registry,
            },
        ];

        let (lockfile, skipped) = to_lockfile(packages).unwrap();

        assert!(lockfile.packages.is_empty());
        assert_eq!(skipped.len(), 2);
    }

    #[test]
    fn rejects_path_traversal_dotdot() {
        let packages = vec![make_pkg(
            "../../../etc/passwd",
            "1.0.0",
            Some("https://registry.npmjs.org/evil/-/evil-1.0.0.tgz"),
        )];

        let (lockfile, skipped) = to_lockfile(packages).unwrap();
        assert_eq!(lockfile.packages.len(), 0);
        assert_eq!(skipped.len(), 1);
        assert!(skipped[0].reason.contains("path traversal"));
    }

    #[test]
    fn rejects_path_traversal_backslash() {
        let packages = vec![make_pkg(
            "evil\\..\\..\\etc\\passwd",
            "1.0.0",
            Some("https://registry.npmjs.org/evil/-/evil-1.0.0.tgz"),
        )];

        let (lockfile, skipped) = to_lockfile(packages).unwrap();
        assert_eq!(lockfile.packages.len(), 0);
        assert!(skipped[0].reason.contains("path traversal"));
    }

    #[test]
    fn rejects_path_traversal_null_byte() {
        let packages = vec![make_pkg(
            "evil\0pkg",
            "1.0.0",
            Some("https://registry.npmjs.org/evil/-/evil-1.0.0.tgz"),
        )];

        let (lockfile, skipped) = to_lockfile(packages).unwrap();
        assert_eq!(lockfile.packages.len(), 0);
        assert!(skipped[0].reason.contains("path traversal"));
    }

    #[test]
    fn allows_scoped_packages_with_dots() {
        // Ensure we don't accidentally reject valid names that contain single dots
        let packages = vec![make_pkg(
            "@lpm.dev/owner.package",
            "1.0.0",
            Some("https://lpm.dev/api/packages/@lpm.dev/owner.package/-/owner.package-1.0.0.tgz"),
        )];

        let (lockfile, skipped) = to_lockfile(packages).unwrap();
        assert_eq!(lockfile.packages.len(), 1);
        assert!(skipped.is_empty());
    }

    #[test]
    fn mark_dev_optional_marks_correctly() {
        let mut packages = vec![
            make_pkg(
                "express",
                "4.0.0",
                Some("https://registry.npmjs.org/express/-/express-4.0.0.tgz"),
            ),
            make_pkg(
                "jest",
                "29.0.0",
                Some("https://registry.npmjs.org/jest/-/jest-29.0.0.tgz"),
            ),
            make_pkg(
                "fsevents",
                "2.3.0",
                Some("https://registry.npmjs.org/fsevents/-/fsevents-2.3.0.tgz"),
            ),
        ];

        let dev_deps: HashSet<String> = ["jest".to_string()].into();
        let optional_deps: HashSet<String> = ["fsevents".to_string()].into();

        mark_dev_optional(&mut packages, &dev_deps, &optional_deps);

        assert!(!packages[0].is_dev);
        assert!(!packages[0].is_optional);
        assert!(packages[1].is_dev);
        assert!(!packages[1].is_optional);
        assert!(!packages[2].is_dev);
        assert!(packages[2].is_optional);
    }
}
