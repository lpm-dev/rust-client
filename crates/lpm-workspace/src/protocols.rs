use std::collections::HashMap;
use std::fmt;

use crate::discovery::Workspace;

pub fn resolve_workspace_protocol(
    deps: &mut HashMap<String, String>,
    workspace: &Workspace,
) -> Result<Vec<(String, String, String)>, String> {
    let mut resolved = Vec::new();

    // Build member name → version mapping
    let member_versions: HashMap<&str, &str> = workspace
        .members
        .iter()
        .filter_map(|m| {
            let name = m.package.name.as_deref()?;
            let version = m.package.version.as_deref().unwrap_or("0.0.0");
            Some((name, version))
        })
        .collect();

    for (name, range) in deps.iter_mut() {
        if !range.starts_with("workspace:") {
            continue;
        }

        let protocol = &range["workspace:".len()..];

        if let Some(&member_version) = member_versions.get(name.as_str()) {
            let original = range.clone();
            *range = match protocol {
                "*" | "" => member_version.to_string(),
                "^" => format!("^{member_version}"),
                "~" => format!("~{member_version}"),
                // workspace:>=1.0.0 → passthrough as-is
                exact => exact.to_string(),
            };
            resolved.push((name.clone(), original, range.clone()));
        } else {
            let mut available: Vec<&str> = member_versions.keys().copied().collect();
            available.sort();
            let available_str = if available.is_empty() {
                "(none)".to_string()
            } else {
                available.join(", ")
            };
            return Err(format!(
                "workspace:{protocol} references package '{name}' which is not a workspace member. \
				 Available members: {available_str}"
            ));
        }
    }

    Ok(resolved)
}

/// One dependency rewritten from a catalog protocol reference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatalogProtocolResolution {
    /// Catalog name used for lookup. Bare `catalog:` resolves through `default`.
    pub catalog_name: String,
    /// Dependency package name from the consumer manifest.
    pub package_name: String,
    /// Consumer-side protocol reference, e.g. `catalog:` or `catalog:testing`.
    pub reference: String,
    /// Range/specifier stored in the catalog entry.
    pub specifier: String,
}

/// Error raised while resolving a dependency's catalog protocol reference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CatalogProtocolError {
    CatalogNotFound {
        dependency: String,
        catalog: String,
        available: String,
    },
    EntryNotFound {
        dependency: String,
        catalog: String,
        available: String,
    },
    RecursiveDefinition {
        dependency: String,
        catalog: String,
        specifier: String,
    },
}

impl fmt::Display for CatalogProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CatalogProtocolError::CatalogNotFound {
                dependency,
                catalog,
                available,
            } => write!(
                f,
                "catalog '{catalog}' not found for dependency '{dependency}'. Available catalogs: {available}"
            ),
            CatalogProtocolError::EntryNotFound {
                dependency,
                catalog,
                available,
            } => write!(
                f,
                "dependency '{dependency}' not found in catalog '{catalog}'. Available: {available}"
            ),
            CatalogProtocolError::RecursiveDefinition {
                dependency,
                catalog,
                specifier,
            } => write!(
                f,
                "invalid recursive catalog entry for dependency '{dependency}' in catalog '{catalog}': catalog entry value '{specifier}' cannot use the catalog protocol recursively"
            ),
        }
    }
}

impl std::error::Error for CatalogProtocolError {}

/// Resolve `catalog:` and `catalog:{name}` protocol references in dependencies.
///
/// - `"catalog:"` resolves from `catalogs["default"]`
/// - `"catalog:testing"` resolves from `catalogs["testing"]`
///
/// Must be called before passing dependencies to the resolver.
///
/// Returns a list of catalog resolution records for logging and lockfile provenance.
pub fn resolve_catalog_protocol(
    deps: &mut HashMap<String, String>,
    catalogs: &HashMap<String, HashMap<String, String>>,
) -> Result<Vec<CatalogProtocolResolution>, CatalogProtocolError> {
    let mut resolved = Vec::new();

    for (name, range) in deps.iter_mut() {
        if !range.starts_with("catalog:") {
            continue;
        }

        let catalog_ref = &range["catalog:".len()..];
        let catalog_name = if catalog_ref.is_empty() {
            "default".to_string()
        } else {
            catalog_ref.to_string()
        };

        let catalog = catalogs.get(catalog_name.as_str()).ok_or_else(|| {
            CatalogProtocolError::CatalogNotFound {
                dependency: name.clone(),
                catalog: catalog_name.clone(),
                available: format_catalog_keys(catalogs.keys()),
            }
        })?;

        let version =
            catalog
                .get(name.as_str())
                .ok_or_else(|| CatalogProtocolError::EntryNotFound {
                    dependency: name.clone(),
                    catalog: catalog_name.clone(),
                    available: format_catalog_keys(catalog.keys()),
                })?;

        if version.starts_with("catalog:") {
            return Err(CatalogProtocolError::RecursiveDefinition {
                dependency: name.clone(),
                catalog: catalog_name,
                specifier: version.clone(),
            });
        }

        let original = range.clone();
        *range = version.clone();
        resolved.push(CatalogProtocolResolution {
            catalog_name: catalog_name.to_string(),
            package_name: name.clone(),
            reference: original,
            specifier: version.clone(),
        });
    }

    Ok(resolved)
}

fn format_catalog_keys<'a>(keys: impl Iterator<Item = &'a String>) -> String {
    let mut keys: Vec<&str> = keys.map(String::as_str).collect();
    if keys.is_empty() {
        "(none)".to_string()
    } else {
        keys.sort_unstable();
        keys.join(", ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::discovery::WorkspaceMember;
    use crate::package_json::PackageJson;
    use std::collections::HashMap;

    fn make_workspace(members: Vec<(&str, &str)>) -> Workspace {
        let root = std::path::PathBuf::from("/test");
        let root_package = PackageJson {
            name: Some("root".to_string()),
            version: Some("1.0.0".to_string()),
            ..Default::default()
        };
        let members = members
            .into_iter()
            .map(|(name, version)| WorkspaceMember {
                path: root.join(format!("packages/{name}")),
                package: PackageJson {
                    name: Some(name.to_string()),
                    version: Some(version.to_string()),
                    ..Default::default()
                },
            })
            .collect();
        Workspace {
            root,
            root_package,
            members,
        }
    }

    #[test]
    fn workspace_star_resolves_to_exact() {
        let ws = make_workspace(vec![("@scope/ui", "2.3.1")]);
        let mut deps = HashMap::from([("@scope/ui".to_string(), "workspace:*".to_string())]);
        let resolved = resolve_workspace_protocol(&mut deps, &ws).unwrap();
        assert_eq!(deps["@scope/ui"], "2.3.1");
        assert_eq!(resolved.len(), 1);
    }

    #[test]
    fn workspace_caret() {
        let ws = make_workspace(vec![("utils", "1.0.0")]);
        let mut deps = HashMap::from([("utils".to_string(), "workspace:^".to_string())]);
        resolve_workspace_protocol(&mut deps, &ws).unwrap();
        assert_eq!(deps["utils"], "^1.0.0");
    }

    #[test]
    fn workspace_tilde() {
        let ws = make_workspace(vec![("utils", "1.0.0")]);
        let mut deps = HashMap::from([("utils".to_string(), "workspace:~".to_string())]);
        resolve_workspace_protocol(&mut deps, &ws).unwrap();
        assert_eq!(deps["utils"], "~1.0.0");
    }

    #[test]
    fn workspace_missing_member_errors() {
        let ws = make_workspace(vec![("utils", "1.0.0")]);
        let mut deps = HashMap::from([("missing".to_string(), "workspace:*".to_string())]);
        let err = resolve_workspace_protocol(&mut deps, &ws).unwrap_err();
        assert!(
            err.contains("not a workspace member"),
            "expected 'not a workspace member' in error, got: {err}"
        );
        assert!(
            err.contains("utils"),
            "expected available member 'utils' in error, got: {err}"
        );
    }

    #[test]
    fn non_workspace_deps_unchanged() {
        let ws = make_workspace(vec![("utils", "1.0.0")]);
        let mut deps = HashMap::from([
            ("react".to_string(), "^18.2.0".to_string()),
            ("utils".to_string(), "workspace:*".to_string()),
        ]);
        resolve_workspace_protocol(&mut deps, &ws).unwrap();
        assert_eq!(deps["react"], "^18.2.0"); // unchanged
        assert_eq!(deps["utils"], "1.0.0"); // resolved
    }

    #[test]
    fn multiple_members() {
        let ws = make_workspace(vec![("@scope/ui", "2.0.0"), ("@scope/utils", "1.5.0")]);
        let mut deps = HashMap::from([
            ("@scope/ui".to_string(), "workspace:^".to_string()),
            ("@scope/utils".to_string(), "workspace:~".to_string()),
        ]);
        resolve_workspace_protocol(&mut deps, &ws).unwrap();
        assert_eq!(deps["@scope/ui"], "^2.0.0");
        assert_eq!(deps["@scope/utils"], "~1.5.0");
    }

    #[test]
    fn workspace_empty_protocol_resolves_to_exact() {
        let ws = make_workspace(vec![("utils", "3.0.0")]);
        let mut deps = HashMap::from([("utils".to_string(), "workspace:".to_string())]);
        resolve_workspace_protocol(&mut deps, &ws).unwrap();
        assert_eq!(deps["utils"], "3.0.0");
    }

    #[test]
    fn workspace_explicit_version() {
        let ws = make_workspace(vec![("utils", "1.0.0")]);
        let mut deps = HashMap::from([("utils".to_string(), "workspace:1.2.3".to_string())]);
        resolve_workspace_protocol(&mut deps, &ws).unwrap();
        assert_eq!(deps["utils"], "1.2.3"); // exact passthrough
    }

    /// `workspace:` with arbitrary semver range is a passthrough.
    /// e.g., "workspace:>=1.0.0" for a member with version "2.0.0" → resolves to ">=1.0.0".
    #[test]
    fn workspace_semver_range_passthrough() {
        let ws = make_workspace(vec![("utils", "2.0.0")]);
        let mut deps = HashMap::from([("utils".to_string(), "workspace:>=1.0.0".to_string())]);
        resolve_workspace_protocol(&mut deps, &ws).unwrap();
        // The range after "workspace:" is kept as-is — the member's actual version is irrelevant
        assert_eq!(deps["utils"], ">=1.0.0");
    }

    #[test]
    fn member_without_version_defaults_to_0_0_0() {
        let root = std::path::PathBuf::from("/test");
        let ws = Workspace {
            root: root.clone(),
            root_package: PackageJson {
                name: Some("root".to_string()),
                ..Default::default()
            },
            members: vec![WorkspaceMember {
                path: root.join("packages/no-ver"),
                package: PackageJson {
                    name: Some("no-ver".to_string()),
                    version: None,
                    ..Default::default()
                },
            }],
        };
        let mut deps = HashMap::from([("no-ver".to_string(), "workspace:*".to_string())]);
        resolve_workspace_protocol(&mut deps, &ws).unwrap();
        assert_eq!(deps["no-ver"], "0.0.0");
    }

    /// Lockfile assertion: after resolve_workspace_protocol, no values contain
    /// "workspace:" prefix. This guarantees the lockfile (and published tarball)
    /// will contain concrete semver, not protocol references.
    #[test]
    fn no_workspace_protocol_survives_resolution() {
        let ws = make_workspace(vec![
            ("@scope/ui", "2.3.1"),
            ("@scope/core", "1.0.0"),
            ("utils", "3.5.0"),
        ]);
        let mut deps = HashMap::from([
            ("@scope/ui".to_string(), "workspace:*".to_string()),
            ("@scope/core".to_string(), "workspace:^".to_string()),
            ("utils".to_string(), "workspace:~".to_string()),
            ("lodash".to_string(), "^4.17.0".to_string()),
            ("react".to_string(), "^18.0.0".to_string()),
        ]);

        resolve_workspace_protocol(&mut deps, &ws).unwrap();

        for (name, range) in &deps {
            assert!(
                !range.starts_with("workspace:"),
                "{name} still has workspace: protocol after resolution: {range}"
            );
        }

        // Verify concrete values
        assert_eq!(deps["@scope/ui"], "2.3.1");
        assert_eq!(deps["@scope/core"], "^1.0.0");
        assert_eq!(deps["utils"], "~3.5.0");
        // Non-workspace deps unchanged
        assert_eq!(deps["lodash"], "^4.17.0");
        assert_eq!(deps["react"], "^18.0.0");
    }

    #[test]
    fn catalog_default_resolves() {
        let mut deps = HashMap::from([("react".to_string(), "catalog:".to_string())]);
        let catalogs = HashMap::from([(
            "default".to_string(),
            HashMap::from([("react".to_string(), "^18.2.0".to_string())]),
        )]);
        resolve_catalog_protocol(&mut deps, &catalogs).unwrap();
        assert_eq!(deps["react"], "^18.2.0");
    }

    #[test]
    fn catalog_named_resolves() {
        let mut deps = HashMap::from([("jest".to_string(), "catalog:testing".to_string())]);
        let catalogs = HashMap::from([(
            "testing".to_string(),
            HashMap::from([("jest".to_string(), "^29.0.0".to_string())]),
        )]);
        resolve_catalog_protocol(&mut deps, &catalogs).unwrap();
        assert_eq!(deps["jest"], "^29.0.0");
    }

    #[test]
    fn catalog_missing_catalog_errors() {
        let mut deps = HashMap::from([("react".to_string(), "catalog:nonexistent".to_string())]);
        let catalogs = HashMap::new();
        let result = resolve_catalog_protocol(&mut deps, &catalogs);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("catalog 'nonexistent' not found"));
    }

    #[test]
    fn catalog_missing_entry_errors() {
        let mut deps = HashMap::from([("vue".to_string(), "catalog:".to_string())]);
        let catalogs = HashMap::from([(
            "default".to_string(),
            HashMap::from([("react".to_string(), "^18.2.0".to_string())]),
        )]);
        let result = resolve_catalog_protocol(&mut deps, &catalogs);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("dependency 'vue' not found in catalog"));
    }

    #[test]
    fn catalog_recursive_entry_errors_before_resolution() {
        let mut deps = HashMap::from([("react".to_string(), "catalog:".to_string())]);
        let catalogs = HashMap::from([(
            "default".to_string(),
            HashMap::from([("react".to_string(), "catalog:shared".to_string())]),
        )]);

        let result = resolve_catalog_protocol(&mut deps, &catalogs);
        let err = result.expect_err("recursive catalog value must error");
        let message = err.to_string();

        assert!(
            matches!(
                err,
                CatalogProtocolError::RecursiveDefinition {
                    dependency,
                    catalog,
                    specifier,
                } if dependency == "react" && catalog == "default" && specifier == "catalog:shared"
            ),
            "error should preserve typed recursive catalog context, got: {message}"
        );
        assert!(
            message.contains("recursive")
                && message.contains("react")
                && message.contains("catalog 'default'")
                && message.contains("catalog:shared"),
            "error should identify recursive catalog entry, got: {message}"
        );
        assert_eq!(
            deps["react"], "catalog:",
            "failed catalog resolution must leave dependency spec unchanged"
        );
    }

    #[test]
    fn non_catalog_deps_unchanged() {
        let mut deps = HashMap::from([
            ("react".to_string(), "^18.2.0".to_string()),
            ("jest".to_string(), "catalog:testing".to_string()),
        ]);
        let catalogs = HashMap::from([(
            "testing".to_string(),
            HashMap::from([("jest".to_string(), "^29.0.0".to_string())]),
        )]);
        resolve_catalog_protocol(&mut deps, &catalogs).unwrap();
        assert_eq!(deps["react"], "^18.2.0"); // unchanged
        assert_eq!(deps["jest"], "^29.0.0"); // resolved
    }

    #[test]
    fn catalog_returns_resolved_log() {
        let mut deps = HashMap::from([
            ("react".to_string(), "catalog:".to_string()),
            ("jest".to_string(), "catalog:testing".to_string()),
        ]);
        let catalogs = HashMap::from([
            (
                "default".to_string(),
                HashMap::from([("react".to_string(), "^18.2.0".to_string())]),
            ),
            (
                "testing".to_string(),
                HashMap::from([("jest".to_string(), "^29.0.0".to_string())]),
            ),
        ]);
        let resolved = resolve_catalog_protocol(&mut deps, &catalogs).unwrap();
        assert_eq!(resolved.len(), 2);
    }

    #[test]
    fn catalog_multiple_entries_in_default() {
        let mut deps = HashMap::from([
            ("react".to_string(), "catalog:".to_string()),
            ("react-dom".to_string(), "catalog:".to_string()),
        ]);
        let catalogs = HashMap::from([(
            "default".to_string(),
            HashMap::from([
                ("react".to_string(), "^18.2.0".to_string()),
                ("react-dom".to_string(), "^18.2.0".to_string()),
            ]),
        )]);
        resolve_catalog_protocol(&mut deps, &catalogs).unwrap();
        assert_eq!(deps["react"], "^18.2.0");
        assert_eq!(deps["react-dom"], "^18.2.0");
    }
}
