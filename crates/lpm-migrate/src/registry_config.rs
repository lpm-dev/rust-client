//! Where Yarn Berry and Bun place packages their lockfiles record no URL for.
//!
//! A Yarn Berry lockfile names no registry for any package, and a Bun
//! lockfile leaves the source empty for a package from its default
//! registry. Both take the registry from their own configuration
//! (`.yarnrc.yml`, `bunfig.toml`), which LPM doesn't route by, so the
//! migration reads it to learn where each such package came from.

use crate::normalize::{RegistryOrigin, public_tarball_url, registry_origin};
use crate::{CustomRegistryPackage, MigratedPackage};
use lpm_common::LpmError;
use std::collections::{HashMap, HashSet};
use std::path::Path;

/// The registries a package manager's configuration names: one for each
/// scope it routes, and a default for every other package.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct ConfiguredRegistries {
    default: Option<String>,
    scopes: HashMap<String, String>,
}

impl ConfiguredRegistries {
    /// The registries `.yarnrc.yml` names, if the project has one.
    pub(crate) fn yarn(project_dir: &Path) -> Result<Option<Self>, LpmError> {
        let Some(content) = read_config(&project_dir.join(".yarnrc.yml"))? else {
            return Ok(None);
        };
        Self::from_yarnrc(&content).map(Some)
    }

    /// The registries `bunfig.toml` names, if the project has one.
    pub(crate) fn bun(project_dir: &Path) -> Result<Option<Self>, LpmError> {
        let Some(content) = read_config(&project_dir.join("bunfig.toml"))? else {
            return Ok(None);
        };
        Self::from_bunfig(&content).map(Some)
    }

    fn from_yarnrc(content: &str) -> Result<Self, LpmError> {
        let root: serde_yaml::Value = serde_yaml::from_str(content)
            .map_err(|error| LpmError::Script(format!("can't read .yarnrc.yml: {error}")))?;
        let server = |value: &serde_yaml::Value| {
            value
                .get("npmRegistryServer")
                .and_then(serde_yaml::Value::as_str)
                .map(str::to_owned)
        };
        let scopes = root
            .get("npmScopes")
            .and_then(serde_yaml::Value::as_mapping)
            .into_iter()
            .flatten()
            .filter_map(|(scope, settings)| Some((scope_name(scope.as_str()?), server(settings)?)))
            .collect();
        Ok(Self {
            default: server(&root),
            scopes,
        })
    }

    fn from_bunfig(content: &str) -> Result<Self, LpmError> {
        let root: toml::Table = content
            .parse()
            .map_err(|error| LpmError::Script(format!("can't read bunfig.toml: {error}")))?;
        let install = root.get("install").and_then(toml::Value::as_table);
        let url = |value: &toml::Value| match value {
            toml::Value::String(url) => Some(url.clone()),
            toml::Value::Table(table) => table
                .get("url")
                .and_then(toml::Value::as_str)
                .map(str::to_owned),
            _ => None,
        };
        let scopes = install
            .and_then(|install| install.get("scopes"))
            .and_then(toml::Value::as_table)
            .into_iter()
            .flatten()
            .filter_map(|(scope, settings)| Some((scope_name(scope), url(settings)?)))
            .collect();
        Ok(Self {
            default: install
                .and_then(|install| install.get("registry"))
                .and_then(url),
            scopes,
        })
    }

    fn registry_for(&self, name: &str) -> Option<&str> {
        name.strip_prefix('@')
            .and_then(|scoped| scoped.split_once('/'))
            .and_then(|(scope, _)| self.scopes.get(scope))
            .or(self.default.as_ref())
            .map(String::as_str)
    }
}

fn scope_name(scope: &str) -> String {
    scope.trim_start_matches('@').to_owned()
}

fn read_config(path: &Path) -> Result<Option<String>, LpmError> {
    match lpm_common::read_text_file_capped(path, lpm_common::CONFIG_FILE_SIZE_CAP_BYTES) {
        Ok(content) => Ok(Some(lpm_common::strip_utf8_bom_str(&content).to_owned())),
        Err(lpm_common::BoundedReadError::NotFound { .. }) => Ok(None),
        Err(error) => Err(LpmError::Script(format!(
            "can't read {}: {error}",
            path.display()
        ))),
    }
}

/// Gives each package that records no URL the tarball URL its configured
/// registry would serve, when that registry is a custom one. A configured
/// registry that isn't a URL can't become one, so its packages are
/// returned as written instead, to be refused rather than taken for npm's.
pub(crate) fn place_unrecorded(
    packages: &mut [MigratedPackage],
    registries: &ConfiguredRegistries,
) -> Vec<CustomRegistryPackage> {
    let mut unreadable = Vec::new();
    let mut reported = HashSet::new();
    for package in packages
        .iter_mut()
        .filter(|package| package.resolved.is_none())
    {
        let Some(registry) = registries.registry_for(&package.name) else {
            continue;
        };
        let basename = package.name.rsplit('/').next().unwrap_or(&package.name);
        let tarball = format!(
            "{}/{}/-/{basename}-{}.tgz",
            registry.trim_end_matches('/'),
            package.name,
            package.version
        );
        match public_tarball_url(&tarball) {
            Some(url) if registry_origin(url.as_str()) == RegistryOrigin::Custom => {
                package.resolved = Some(url.into());
            }
            Some(_) => {}
            None => {
                if reported.insert((package.name.clone(), package.version.clone())) {
                    unreadable.push(CustomRegistryPackage {
                        name: package.name.clone(),
                        version: package.version.clone(),
                        tarball_url: tarball,
                    });
                }
            }
        }
    }
    unreadable
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unrecorded(name: &str) -> MigratedPackage {
        MigratedPackage {
            lockfile_key: None,
            name: name.to_owned(),
            version: "1.0.0".to_owned(),
            resolved: None,
            integrity: None,
            dependencies: Vec::new(),
            is_optional: false,
            is_dev: false,
        }
    }

    #[test]
    fn yarn_places_a_scoped_package_on_its_scope_registry_and_others_on_the_default() {
        let registries = ConfiguredRegistries::from_yarnrc(
            "npmRegistryServer: \"https://mirror.corp.example\"\nnpmScopes:\n  corp:\n    npmRegistryServer: \"https://npm.corp.example/private/\"\n",
        )
        .unwrap();
        let mut packages = vec![unrecorded("@corp/utils"), unrecorded("ms")];
        assert!(place_unrecorded(&mut packages, &registries).is_empty());
        assert_eq!(
            packages[0].resolved.as_deref(),
            Some("https://npm.corp.example/private/@corp/utils/-/utils-1.0.0.tgz")
        );
        assert_eq!(
            packages[1].resolved.as_deref(),
            Some("https://mirror.corp.example/ms/-/ms-1.0.0.tgz")
        );
    }

    #[test]
    fn a_package_on_npms_registry_keeps_no_url() {
        let registries = ConfiguredRegistries::from_yarnrc(
            "npmRegistryServer: \"https://registry.yarnpkg.com\"\n",
        )
        .unwrap();
        let mut packages = vec![unrecorded("ms")];
        assert!(place_unrecorded(&mut packages, &registries).is_empty());
        assert_eq!(packages[0].resolved, None);
    }

    #[test]
    fn a_registry_the_configuration_names_by_variable_is_reported_as_written() {
        let registries = ConfiguredRegistries::from_yarnrc(
            "npmScopes:\n  corp:\n    npmRegistryServer: \"${CORP_REGISTRY}\"\n",
        )
        .unwrap();
        let mut packages = vec![unrecorded("@corp/utils")];
        assert_eq!(
            place_unrecorded(&mut packages, &registries),
            vec![CustomRegistryPackage {
                name: "@corp/utils".to_owned(),
                version: "1.0.0".to_owned(),
                tarball_url: "${CORP_REGISTRY}/@corp/utils/-/utils-1.0.0.tgz".to_owned(),
            }]
        );
        assert_eq!(packages[0].resolved, None);
    }

    #[test]
    fn bun_reads_registries_written_as_text_or_tables_without_their_credentials() {
        let registries = ConfiguredRegistries::from_bunfig(
            "[install]\nregistry = { url = \"https://mirror.corp.example/\", token = \"secret\" }\n\n[install.scopes]\n\"@corp\" = \"https://user:secret@npm.corp.example/\"\n",
        )
        .unwrap();
        let mut packages = vec![unrecorded("@corp/utils"), unrecorded("ms")];
        assert!(place_unrecorded(&mut packages, &registries).is_empty());
        assert_eq!(
            packages[0].resolved.as_deref(),
            Some("https://npm.corp.example/@corp/utils/-/utils-1.0.0.tgz")
        );
        assert_eq!(
            packages[1].resolved.as_deref(),
            Some("https://mirror.corp.example/ms/-/ms-1.0.0.tgz")
        );
    }

    #[test]
    fn a_package_whose_lockfile_records_a_url_keeps_it() {
        let registries = ConfiguredRegistries::from_bunfig(
            "[install]\nregistry = \"https://mirror.corp.example/\"\n",
        )
        .unwrap();
        let mut recorded = unrecorded("ms");
        recorded.resolved = Some("https://registry.npmjs.org/ms/-/ms-1.0.0.tgz".to_owned());
        let mut packages = vec![recorded];
        place_unrecorded(&mut packages, &registries);
        assert_eq!(
            packages[0].resolved.as_deref(),
            Some("https://registry.npmjs.org/ms/-/ms-1.0.0.tgz")
        );
    }
}
