//! Conversion from `Vec<MigratedPackage>` to `lpm_lockfile::Lockfile`.
//!
//! Handles:
//! - Skipping unsupported dependency types (file:, link:, git:, git+, github:)
//! - Inferring the source registry from the resolved URL
//! - Deduplicating same name+version pairs
//! - Formatting dependencies as `"name@version"` strings
//! - Sorting output for deterministic lockfiles

use crate::{MigratedPackage, SkippedPackage};
use lpm_lockfile::{LOCKFILE_VERSION, LockedPackage, Lockfile, LockfileMetadata};
use std::collections::HashSet;

/// Prefixes that indicate non-registry dependencies (to be skipped).
const SKIP_PREFIXES: &[&str] = &[
    "file:",
    "link:",
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
pub fn to_lockfile(packages: Vec<MigratedPackage>) -> (Lockfile, Vec<SkippedPackage>) {
    let mut skipped = Vec::new();
    let mut locked_packages = Vec::with_capacity(packages.len());
    let mut seen: HashSet<(String, String)> = HashSet::with_capacity(packages.len());

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
        if contains_path_traversal(&pkg.name) {
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

        // Deduplicate same name+version
        let key = (pkg.name.clone(), pkg.version.clone());
        if !seen.insert(key) {
            continue;
        }

        let source = infer_source(&pkg.resolved);

        // Format dependencies as "name@version" strings
        let dependencies: Vec<String> = pkg
            .dependencies
            .iter()
            .map(|(name, version)| format!("{name}@{version}"))
            .collect();

        locked_packages.push(LockedPackage {
            name: pkg.name,
            version: pkg.version,
            source: Some(source),
            integrity: pkg.integrity,
            dependencies,
        });
    }

    // Sort by name, then version for deterministic output
    locked_packages.sort_by(|a, b| a.name.cmp(&b.name).then_with(|| a.version.cmp(&b.version)));

    let lockfile = Lockfile {
        metadata: LockfileMetadata {
            lockfile_version: LOCKFILE_VERSION,
            resolved_with: Some("migrate".to_string()),
        },
        packages: locked_packages,
    };

    (lockfile, skipped)
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

/// Infer the source registry URL from the resolved tarball URL.
fn infer_source(resolved: &Option<String>) -> String {
    match resolved {
        Some(url) if url.contains("lpm.dev") => "registry+https://lpm.dev".to_string(),
        Some(url) if url.contains("registry.npmjs.org") => {
            "registry+https://registry.npmjs.org".to_string()
        }
        Some(url) if url.contains("registry.yarnpkg.com") => {
            "registry+https://registry.npmjs.org".to_string()
        }
        Some(url) => {
            tracing::warn!(
                url,
                "unknown registry URL, defaulting to registry.npmjs.org"
            );
            "registry+https://registry.npmjs.org".to_string()
        }
        None => "registry+https://registry.npmjs.org".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_pkg(name: &str, version: &str, resolved: Option<&str>) -> MigratedPackage {
        MigratedPackage {
            name: name.to_string(),
            version: version.to_string(),
            resolved: resolved.map(String::from),
            integrity: Some(format!("sha512-{name}{version}")),
            dependencies: Vec::new(),
            is_optional: false,
            is_dev: false,
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

        let (lockfile, skipped) = to_lockfile(packages);
        assert!(skipped.is_empty());
        assert_eq!(lockfile.packages.len(), 2);
        assert_eq!(lockfile.metadata.resolved_with.as_deref(), Some("migrate"));
        assert_eq!(lockfile.metadata.lockfile_version, LOCKFILE_VERSION);

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
                name: "local-pkg".to_string(),
                version: "1.0.0".to_string(),
                resolved: Some("file:../local-pkg".to_string()),
                integrity: None,
                dependencies: Vec::new(),
                is_optional: false,
                is_dev: false,
            },
            MigratedPackage {
                name: "git-pkg".to_string(),
                version: "1.0.0".to_string(),
                resolved: Some("git+https://github.com/user/repo.git#abc123".to_string()),
                integrity: None,
                dependencies: Vec::new(),
                is_optional: false,
                is_dev: false,
            },
            MigratedPackage {
                name: "link-pkg".to_string(),
                version: "1.0.0".to_string(),
                resolved: Some("link:./packages/link-pkg".to_string()),
                integrity: None,
                dependencies: Vec::new(),
                is_optional: false,
                is_dev: false,
            },
        ];

        let (lockfile, skipped) = to_lockfile(packages);
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
            name: String::new(),
            version: "1.0.0".to_string(),
            resolved: Some("https://registry.npmjs.org/x.tgz".to_string()),
            integrity: None,
            dependencies: Vec::new(),
            is_optional: false,
            is_dev: false,
        }];

        let (lockfile, skipped) = to_lockfile(packages);
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

        let (lockfile, _) = to_lockfile(packages);
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

        let (lockfile, _) = to_lockfile(packages);
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

        let (lockfile, _) = to_lockfile(packages);
        assert_eq!(lockfile.packages.len(), 2);
        assert_eq!(lockfile.packages[0].version, "2.6.9");
        assert_eq!(lockfile.packages[1].version, "4.3.4");
    }

    #[test]
    fn preserves_deps_as_name_at_version() {
        let packages = vec![MigratedPackage {
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
        }];

        let (lockfile, _) = to_lockfile(packages);
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

        let (lockfile, _) = to_lockfile(packages);
        assert_eq!(lockfile.packages[0].name, "alpha");
        assert_eq!(lockfile.packages[1].name, "middle");
        assert_eq!(lockfile.packages[2].name, "zlib");
    }

    #[test]
    fn infer_source_unknown_registry_returns_default() {
        // Finding #11: unknown registry URLs should still return npmjs default
        let source = infer_source(&Some("https://private.corp/pkg.tgz".to_string()));
        assert_eq!(source, "registry+https://registry.npmjs.org");
    }

    #[test]
    fn skips_version_with_file_prefix() {
        let packages = vec![MigratedPackage {
            name: "local".to_string(),
            version: "file:../local".to_string(),
            resolved: None,
            integrity: None,
            dependencies: Vec::new(),
            is_optional: false,
            is_dev: false,
        }];

        let (lockfile, skipped) = to_lockfile(packages);
        assert_eq!(lockfile.packages.len(), 0);
        assert_eq!(skipped.len(), 1);
    }

    #[test]
    fn rejects_path_traversal_dotdot() {
        let packages = vec![make_pkg(
            "../../../etc/passwd",
            "1.0.0",
            Some("https://registry.npmjs.org/evil/-/evil-1.0.0.tgz"),
        )];

        let (lockfile, skipped) = to_lockfile(packages);
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

        let (lockfile, skipped) = to_lockfile(packages);
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

        let (lockfile, skipped) = to_lockfile(packages);
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

        let (lockfile, skipped) = to_lockfile(packages);
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
