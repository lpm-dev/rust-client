//! Where Yarn Berry and Bun place packages their lockfiles record no URL for.
//!
//! A Yarn Berry lockfile names no registry for any package, and a Bun
//! lockfile leaves the source empty for a package from its default
//! registry. Both take the registry from their own configuration, which
//! LPM doesn't route by, so the migration reads that configuration the way
//! each tool does to learn where each such package came from.

use crate::normalize::{RegistryOrigin, public_tarball_url, registry_origin};
use crate::{CustomRegistryPackage, MigratedPackage};
use lpm_common::LpmError;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

type Environment<'a> = &'a dyn Fn(&str) -> Option<String>;

/// The registries a package manager's configuration names: one for each
/// scope it routes, and a default for every other package.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct ConfiguredRegistries {
    default: Option<ConfiguredRegistry>,
    scopes: HashMap<String, ConfiguredRegistry>,
}

/// One configured registry.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ConfiguredRegistry {
    /// The value with its environment variables expanded, or `None` when it
    /// names one that isn't set.
    value: Option<String>,
    /// The setting and file that configure it, so a value LPM can't read as
    /// a URL is reported by where it's set rather than by what it holds.
    setting: String,
    /// Whether expansion put an environment variable's value into it. Such a
    /// value may carry a token, so it's compared but never shown or recorded.
    expanded: bool,
}

impl ConfiguredRegistry {
    fn new(
        raw: &str,
        setting: String,
        expand: fn(&str, Environment<'_>) -> Option<String>,
        env: Environment<'_>,
    ) -> Self {
        let value = expand(raw, env);
        Self {
            expanded: value.as_deref() != Some(raw),
            value,
            setting,
        }
    }

    fn describe(&self) -> String {
        let reason = if self.value.is_some() {
            "isn't a URL"
        } else {
            "names an environment variable that isn't set"
        };
        format!("the registry {} names, which {reason}", self.setting)
    }

    /// A value an environment variable holds whole may carry a token too.
    fn from_environment(mut self) -> Self {
        self.expanded = true;
        self
    }

    fn describe_expanded(&self) -> String {
        format!(
            "the registry {} names, with its environment variables expanded",
            self.setting
        )
    }
}

impl ConfiguredRegistries {
    /// The registries Yarn Berry would use in `project_dir`, if any of its
    /// configuration names one.
    pub(crate) fn yarn_berry(project_dir: &Path) -> Result<Option<Self>, LpmError> {
        Self::yarn_berry_with(
            project_dir,
            lpm_common::npmrc::npm_home_dir().as_deref(),
            &|name| std::env::var(name).ok(),
        )
    }

    /// Yarn merges the `.yarnrc.yml` in the project directory and in each
    /// of its ancestors over the one in the home directory, the nearest
    /// winning, and lets `YARN_NPM_REGISTRY_SERVER` override them all.
    fn yarn_berry_with(
        project_dir: &Path,
        home: Option<&Path>,
        env: Environment<'_>,
    ) -> Result<Option<Self>, LpmError> {
        let filename = env("YARN_RC_FILENAME")
            .filter(|filename| !filename.is_empty())
            .unwrap_or_else(|| ".yarnrc.yml".to_owned());
        let mut files: Vec<PathBuf> = project_dir
            .ancestors()
            .map(|directory| directory.join(&filename))
            .collect();
        if let Some(home) = home {
            let home_file = home.join(&filename);
            if !files.contains(&home_file) {
                files.push(home_file);
            }
        }

        let mut registries = Self::default();
        let mut configured = false;
        for file in files.iter().rev() {
            let Some(content) = read_config(file)? else {
                continue;
            };
            configured = true;
            registries.merge_yarnrc(&content, file, env)?;
        }
        if let Some(server) = env("YARN_NPM_REGISTRY_SERVER").filter(|server| !server.is_empty()) {
            configured = true;
            registries.default = Some(
                ConfiguredRegistry::new(
                    &server,
                    "`YARN_NPM_REGISTRY_SERVER`".to_owned(),
                    expand_yarn,
                    env,
                )
                .from_environment(),
            );
        }
        Ok(configured.then_some(registries))
    }

    fn merge_yarnrc(
        &mut self,
        content: &str,
        file: &Path,
        env: Environment<'_>,
    ) -> Result<(), LpmError> {
        let root: serde_yaml::Value = serde_yaml::from_str(content).map_err(|error| {
            let at = error
                .location()
                .map(|location| {
                    format!(" (line {}, column {})", location.line(), location.column())
                })
                .unwrap_or_default();
            LpmError::Script(format!("{} isn't valid YAML{at}", file.display()))
        })?;
        fn server(settings: &serde_yaml::Value) -> Option<&str> {
            settings
                .get("npmRegistryServer")
                .and_then(serde_yaml::Value::as_str)
        }
        if let Some(raw) = server(&root) {
            self.default = Some(ConfiguredRegistry::new(
                raw,
                format!("`npmRegistryServer` in {}", file.display()),
                expand_yarn,
                env,
            ));
        }
        for (scope, settings) in root
            .get("npmScopes")
            .and_then(serde_yaml::Value::as_mapping)
            .into_iter()
            .flatten()
        {
            let (Some(scope), Some(raw)) = (scope.as_str(), server(settings)) else {
                continue;
            };
            let scope = scope_name(scope);
            let setting = format!(
                "`npmScopes.{scope}.npmRegistryServer` in {}",
                file.display()
            );
            self.scopes.insert(
                scope,
                ConfiguredRegistry::new(raw, setting, expand_yarn, env),
            );
        }
        Ok(())
    }

    /// The registries Bun would use in `project_dir`, if any of its
    /// configuration names one.
    pub(crate) fn bun(project_dir: &Path) -> Result<Option<Self>, LpmError> {
        Self::bun_with(
            project_dir,
            lpm_common::npmrc::npm_home_dir().as_deref(),
            &|name| std::env::var(name).ok(),
        )
    }

    /// Bun reads its global `.bunfig.toml` from `$XDG_CONFIG_HOME` when that
    /// is set, and from the home directory otherwise, under the project's
    /// `bunfig.toml`, and lets `BUN_CONFIG_REGISTRY`, then
    /// `NPM_CONFIG_REGISTRY`, override the default registry.
    fn bun_with(
        project_dir: &Path,
        home: Option<&Path>,
        env: Environment<'_>,
    ) -> Result<Option<Self>, LpmError> {
        let global = env("XDG_CONFIG_HOME")
            .filter(|directory| !directory.is_empty())
            .map(PathBuf::from)
            .or_else(|| home.map(Path::to_path_buf))
            .map(|directory| directory.join(".bunfig.toml"));
        let project = project_dir.join("bunfig.toml");

        let mut registries = Self::default();
        let mut configured = false;
        for file in global.iter().chain(std::iter::once(&project)) {
            let Some(content) = read_config(file)? else {
                continue;
            };
            configured = true;
            registries.merge_bunfig(&content, file, env)?;
        }
        if let Some((variable, registry)) = [
            "BUN_CONFIG_REGISTRY",
            "NPM_CONFIG_REGISTRY",
            "npm_config_registry",
        ]
        .into_iter()
        .find_map(|variable| {
            env(variable)
                .filter(|registry| !registry.is_empty())
                .map(|registry| (variable, registry))
        }) {
            configured = true;
            registries.default = Some(
                ConfiguredRegistry::new(&registry, format!("`{variable}`"), expand_bun, env)
                    .from_environment(),
            );
        }
        Ok(configured.then_some(registries))
    }

    fn merge_bunfig(
        &mut self,
        content: &str,
        file: &Path,
        env: Environment<'_>,
    ) -> Result<(), LpmError> {
        let root: toml::Table = content.parse().map_err(|error: toml::de::Error| {
            let at = error
                .span()
                .map(|span| {
                    let (line, column) = line_and_column(content, span.start);
                    format!(" (line {line}, column {column})")
                })
                .unwrap_or_default();
            LpmError::Script(format!("{} isn't valid TOML{at}", file.display()))
        })?;
        let install = root.get("install").and_then(toml::Value::as_table);
        let url = |value: &toml::Value| match value {
            toml::Value::String(url) => Some(url.clone()),
            toml::Value::Table(table) => table
                .get("url")
                .and_then(toml::Value::as_str)
                .map(str::to_owned),
            _ => None,
        };
        if let Some(raw) = install
            .and_then(|install| install.get("registry"))
            .and_then(url)
        {
            self.default = Some(ConfiguredRegistry::new(
                &raw,
                format!("`install.registry` in {}", file.display()),
                expand_bun,
                env,
            ));
        }
        for (scope, settings) in install
            .and_then(|install| install.get("scopes"))
            .and_then(toml::Value::as_table)
            .into_iter()
            .flatten()
        {
            let Some(raw) = url(settings) else {
                continue;
            };
            let scope = scope_name(scope);
            let setting = format!("`install.scopes.{scope}` in {}", file.display());
            self.scopes.insert(
                scope,
                ConfiguredRegistry::new(&raw, setting, expand_bun, env),
            );
        }
        Ok(())
    }

    fn registry_for(&self, name: &str) -> Option<&ConfiguredRegistry> {
        name.strip_prefix('@')
            .and_then(|scoped| scoped.split_once('/'))
            .and_then(|(scope, _)| self.scopes.get(scope))
            .or(self.default.as_ref())
    }
}

fn scope_name(scope: &str) -> String {
    scope.trim_start_matches('@').to_owned()
}

fn line_and_column(content: &str, offset: usize) -> (usize, usize) {
    let before = &content[..content.floor_char_boundary(offset)];
    let line = before.matches('\n').count() + 1;
    let column = before
        .rsplit('\n')
        .next()
        .map_or(0, |line| line.chars().count())
        + 1;
    (line, column)
}

/// Yarn's `${NAME}`, `${NAME-fallback}` and `${NAME:-fallback}`, where the
/// colon also takes the fallback for a variable set to nothing. `None` when
/// a variable without a fallback isn't set, which Yarn refuses too.
fn expand_yarn(value: &str, env: Environment<'_>) -> Option<String> {
    let mut expanded = String::with_capacity(value.len());
    let mut rest = value;
    while let Some(start) = rest.find("${") {
        expanded.push_str(&rest[..start]);
        let reference = &rest[start + 2..];
        let Some(end) = reference.find('}') else {
            rest = &rest[start..];
            break;
        };
        let inner = &reference[..end];
        let name_end = inner
            .find(|character: char| !(character.is_ascii_alphanumeric() || character == '_'))
            .unwrap_or(inner.len());
        let (name, modifier) = inner.split_at(name_end);
        let variable = (!name.is_empty()).then(|| env(name)).flatten();
        let replacement = match modifier {
            _ if name.is_empty() => None,
            "" | ":" => Some(variable?),
            modifier if modifier.starts_with(":-") => Some(
                variable
                    .filter(|value| !value.is_empty())
                    .unwrap_or_else(|| modifier[2..].to_owned()),
            ),
            modifier if modifier.starts_with('-') => {
                Some(variable.unwrap_or_else(|| modifier[1..].to_owned()))
            }
            _ => None,
        };
        match replacement {
            Some(replacement) => expanded.push_str(&replacement),
            None => {
                expanded.push_str("${");
                expanded.push_str(inner);
                expanded.push('}');
            }
        }
        rest = &reference[end + 1..];
    }
    expanded.push_str(rest);
    Some(expanded)
}

/// Bun's `$NAME` and `${NAME}`. `None` when a variable isn't set.
fn expand_bun(value: &str, env: Environment<'_>) -> Option<String> {
    let mut expanded = String::with_capacity(value.len());
    let mut rest = value;
    while let Some(start) = rest.find('$') {
        expanded.push_str(&rest[..start]);
        let reference = &rest[start + 1..];
        let (name, after) = match reference.strip_prefix('{') {
            Some(braced) => match braced.find('}') {
                Some(end) => (&braced[..end], &braced[end + 1..]),
                None => ("", reference),
            },
            None => {
                let end = reference
                    .find(|character: char| {
                        !(character.is_ascii_alphanumeric() || character == '_')
                    })
                    .unwrap_or(reference.len());
                (&reference[..end], &reference[end..])
            }
        };
        if name.is_empty() || name.starts_with(|character: char| character.is_ascii_digit()) {
            expanded.push('$');
            rest = reference;
            continue;
        }
        expanded.push_str(&env(name)?);
        rest = after;
    }
    expanded.push_str(rest);
    Some(expanded)
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

/// What [`place_unrecorded`] learned beyond the URLs it placed.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Placement {
    /// Packages a configured registry LPM can't read as a URL couldn't
    /// place, to be refused rather than taken for npm's.
    pub(crate) unreadable: Vec<CustomRegistryPackage>,
    /// For each package, by published name and version, placed on a
    /// registry whose value came from environment variables: how to name
    /// that registry, since its URL may carry a token.
    pub(crate) expanded: HashMap<(String, String), String>,
}

/// Gives each registry package that records no URL the tarball URL its
/// configured registry would serve, when that registry is a custom one.
pub(crate) fn place_unrecorded(
    packages: &mut [MigratedPackage],
    registries: &ConfiguredRegistries,
) -> Placement {
    let mut placement = Placement::default();
    let mut reported = HashSet::new();
    for package in packages
        .iter_mut()
        .filter(|package| package.resolved.is_none())
    {
        let Some(registry_name) = package.registry_name() else {
            continue;
        };
        let Some(registry) = registries.registry_for(registry_name) else {
            continue;
        };
        let basename = registry_name.rsplit('/').next().unwrap_or(registry_name);
        let placed = registry.value.as_deref().and_then(|value| {
            public_tarball_url(&format!(
                "{}/{registry_name}/-/{basename}-{}.tgz",
                value.trim_end_matches('/'),
                package.version
            ))
        });
        match placed {
            Some(url) if registry_origin(url.as_str()) == RegistryOrigin::Custom => {
                if registry.expanded {
                    placement.expanded.insert(
                        (registry_name.to_owned(), package.version.clone()),
                        registry.describe_expanded(),
                    );
                }
                package.resolved = Some(url.into());
            }
            Some(_) => {}
            None => {
                let key = (registry_name.to_owned(), package.version.clone());
                if !reported.contains(&key) {
                    let description = registry.describe();
                    placement.unreadable.push(CustomRegistryPackage {
                        name: key.0.clone(),
                        version: key.1.clone(),
                        tarball_url: description.clone(),
                        shown_as: description,
                    });
                    reported.insert(key);
                }
            }
        }
    }
    placement
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::FetchedFrom;

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
            published_as: None,
            fetched_from: FetchedFrom::Registry,
        }
    }

    fn no_env(_: &str) -> Option<String> {
        None
    }

    fn yarnrc(content: &str) -> ConfiguredRegistries {
        let mut registries = ConfiguredRegistries::default();
        registries
            .merge_yarnrc(content, Path::new(".yarnrc.yml"), &no_env)
            .unwrap();
        registries
    }

    fn bunfig(content: &str) -> ConfiguredRegistries {
        let mut registries = ConfiguredRegistries::default();
        registries
            .merge_bunfig(content, Path::new("bunfig.toml"), &no_env)
            .unwrap();
        registries
    }

    fn placed(registries: &ConfiguredRegistries, name: &str) -> Option<String> {
        let mut packages = vec![unrecorded(name)];
        assert_eq!(
            place_unrecorded(&mut packages, registries).unreadable,
            Vec::new()
        );
        packages.remove(0).resolved
    }

    #[test]
    fn yarn_places_a_scoped_package_on_its_scope_registry_and_others_on_the_default() {
        let registries = yarnrc(
            "npmRegistryServer: \"https://mirror.corp.example\"\nnpmScopes:\n  corp:\n    npmRegistryServer: \"https://npm.corp.example/private/\"\n",
        );
        assert_eq!(
            placed(&registries, "@corp/utils").as_deref(),
            Some("https://npm.corp.example/private/@corp/utils/-/utils-1.0.0.tgz")
        );
        assert_eq!(
            placed(&registries, "ms").as_deref(),
            Some("https://mirror.corp.example/ms/-/ms-1.0.0.tgz")
        );
    }

    #[test]
    fn a_package_on_npms_registry_keeps_no_url() {
        let registries = yarnrc("npmRegistryServer: \"https://registry.yarnpkg.com\"\n");
        assert_eq!(placed(&registries, "ms"), None);
    }

    #[test]
    fn an_aliased_package_is_placed_by_the_name_its_registry_publishes() {
        let registries =
            yarnrc("npmScopes:\n  corp:\n    npmRegistryServer: \"https://npm.corp.example/\"\n");
        let mut packages = vec![MigratedPackage {
            published_as: Some("@corp/utils".to_owned()),
            ..unrecorded("utils")
        }];
        assert_eq!(
            place_unrecorded(&mut packages, &registries),
            Placement::default()
        );
        assert_eq!(
            packages[0].resolved.as_deref(),
            Some("https://npm.corp.example/@corp/utils/-/utils-1.0.0.tgz")
        );
    }

    #[test]
    fn a_package_fetched_from_its_dependency_spec_is_not_placed_on_a_registry() {
        let registries = yarnrc("npmRegistryServer: \"https://mirror.corp.example\"\n");
        let mut packages = vec![MigratedPackage {
            fetched_from: FetchedFrom::DependencySpec,
            ..unrecorded("xlsx")
        }];
        assert_eq!(
            place_unrecorded(&mut packages, &registries),
            Placement::default()
        );
        assert_eq!(packages[0].resolved, None);
    }

    #[test]
    fn yarn_expands_environment_variables_with_its_own_fallback_rules() {
        let env = |name: &str| match name {
            "CORP" => Some("https://npm.corp.example".to_owned()),
            "EMPTY" => Some(String::new()),
            _ => None,
        };
        let expand = |value: &str| expand_yarn(value, &env);
        assert_eq!(
            expand("${CORP}/npm/").as_deref(),
            Some("https://npm.corp.example/npm/")
        );
        assert_eq!(
            expand("${MISSING-https://a.example}").as_deref(),
            Some("https://a.example")
        );
        assert_eq!(expand("${EMPTY-https://a.example}").as_deref(), Some(""));
        assert_eq!(
            expand("${EMPTY:-https://a.example}").as_deref(),
            Some("https://a.example")
        );
        assert_eq!(expand("${MISSING}"), None);
        assert_eq!(
            expand("$CORP").as_deref(),
            Some("$CORP"),
            "Yarn needs braces"
        );
        assert_eq!(expand("https://h/${X").as_deref(), Some("https://h/${X"));
    }

    #[test]
    fn bun_expands_bare_and_braced_environment_variables() {
        let env = |name: &str| (name == "CORP").then(|| "https://npm.corp.example".to_owned());
        let expand = |value: &str| expand_bun(value, &env);
        assert_eq!(
            expand("$CORP/").as_deref(),
            Some("https://npm.corp.example/")
        );
        assert_eq!(
            expand("${CORP}/npm").as_deref(),
            Some("https://npm.corp.example/npm")
        );
        assert_eq!(expand("$MISSING"), None);
        assert_eq!(expand("cost: $5").as_deref(), Some("cost: $5"));
    }

    #[test]
    fn a_registry_named_by_an_unset_variable_is_reported_by_where_it_is_set() {
        let registries = yarnrc(
            "npmScopes:\n  corp:\n    npmRegistryServer: \"${CORP_REGISTRY:-https://user:secret@npm.corp.example}${PATH_PART}\"\n",
        );
        let mut packages = vec![unrecorded("@corp/utils")];
        let reported = place_unrecorded(&mut packages, &registries).unreadable;
        assert_eq!(reported.len(), 1);
        let from = &reported[0].tarball_url;
        assert!(from.contains("npmScopes.corp.npmRegistryServer"), "{from}");
        assert!(from.contains("isn't set"), "{from}");
        assert!(
            !from.contains("secret") && !from.contains("CORP_REGISTRY"),
            "{from}"
        );
        assert_eq!(packages[0].resolved, None);
    }

    #[test]
    fn a_registry_whose_value_comes_from_the_environment_is_placed_but_named_by_its_setting() {
        let mut registries = ConfiguredRegistries::default();
        let env = |name: &str| (name == "REG_TOKEN").then(|| "secret123".to_owned());
        registries
            .merge_yarnrc(
                "npmScopes:\n  corp:\n    npmRegistryServer: \"https://dl.example/${REG_TOKEN}/npm/\"\nnpmRegistryServer: \"https://mirror.example/\"\n",
                Path::new(".yarnrc.yml"),
                &env,
            )
            .unwrap();
        let mut packages = vec![unrecorded("@corp/utils"), unrecorded("ms")];
        let placement = place_unrecorded(&mut packages, &registries);
        assert_eq!(
            packages[0].resolved.as_deref(),
            Some("https://dl.example/secret123/npm/@corp/utils/-/utils-1.0.0.tgz"),
            "the route check compares the expanded URL"
        );
        let shown = &placement.expanded[&("@corp/utils".to_owned(), "1.0.0".to_owned())];
        assert!(
            shown.contains("npmScopes.corp.npmRegistryServer"),
            "{shown}"
        );
        assert!(!shown.contains("secret123"), "{shown}");
        assert!(
            !placement
                .expanded
                .contains_key(&("ms".to_owned(), "1.0.0".to_owned())),
            "a value written out in full is shown as it is"
        );
    }

    #[test]
    fn a_configured_registry_that_is_not_a_url_is_reported_without_its_value() {
        let registries = bunfig("[install]\nregistry = \"npm_secretToken123\"\n");
        let mut packages = vec![unrecorded("ms")];
        let reported = place_unrecorded(&mut packages, &registries).unreadable;
        assert_eq!(reported.len(), 1);
        let from = &reported[0].tarball_url;
        assert!(
            from.contains("install.registry") && from.contains("isn't a URL"),
            "{from}"
        );
        assert!(!from.contains("secretToken"), "{from}");
    }

    #[test]
    fn bun_reads_registries_written_as_text_or_tables_without_their_credentials() {
        let registries = bunfig(
            "[install]\nregistry = { url = \"https://mirror.corp.example/\", token = \"secret\" }\n\n[install.scopes]\n\"@corp\" = \"https://user:secret@npm.corp.example/\"\n",
        );
        assert_eq!(
            placed(&registries, "@corp/utils").as_deref(),
            Some("https://npm.corp.example/@corp/utils/-/utils-1.0.0.tgz")
        );
        assert_eq!(
            placed(&registries, "ms").as_deref(),
            Some("https://mirror.corp.example/ms/-/ms-1.0.0.tgz")
        );
    }

    #[test]
    fn a_package_whose_lockfile_records_a_url_keeps_it() {
        let registries = bunfig("[install]\nregistry = \"https://mirror.corp.example/\"\n");
        let mut recorded = unrecorded("ms");
        recorded.resolved = Some("https://registry.npmjs.org/ms/-/ms-1.0.0.tgz".to_owned());
        let mut packages = vec![recorded];
        place_unrecorded(&mut packages, &registries);
        assert_eq!(
            packages[0].resolved.as_deref(),
            Some("https://registry.npmjs.org/ms/-/ms-1.0.0.tgz")
        );
    }

    #[test]
    fn yarn_reads_ancestor_and_home_files_with_the_nearest_winning_and_its_variable_last() {
        let root = tempfile::tempdir().unwrap();
        let home = root.path().join("home");
        let repo = root.path().join("repo");
        let project = repo.join("packages/app");
        std::fs::create_dir_all(&home).unwrap();
        std::fs::create_dir_all(&project).unwrap();
        std::fs::write(
            home.join(".yarnrc.yml"),
            "npmRegistryServer: \"https://home.example\"\nnpmScopes:\n  home:\n    npmRegistryServer: \"https://home-scope.example\"\n",
        )
        .unwrap();
        std::fs::write(
            repo.join(".yarnrc.yml"),
            "npmScopes:\n  corp:\n    npmRegistryServer: \"https://repo-scope.example\"\n",
        )
        .unwrap();

        let registries = ConfiguredRegistries::yarn_berry_with(&project, Some(&home), &no_env)
            .unwrap()
            .unwrap();
        assert_eq!(
            placed(&registries, "@corp/utils").as_deref(),
            Some("https://repo-scope.example/@corp/utils/-/utils-1.0.0.tgz")
        );
        assert_eq!(
            placed(&registries, "@home/lib").as_deref(),
            Some("https://home-scope.example/@home/lib/-/lib-1.0.0.tgz")
        );
        assert_eq!(
            placed(&registries, "ms").as_deref(),
            Some("https://home.example/ms/-/ms-1.0.0.tgz")
        );

        let env = |name: &str| {
            (name == "YARN_NPM_REGISTRY_SERVER").then(|| "https://env.example".to_owned())
        };
        let registries = ConfiguredRegistries::yarn_berry_with(&project, Some(&home), &env)
            .unwrap()
            .unwrap();
        assert_eq!(
            placed(&registries, "ms").as_deref(),
            Some("https://env.example/ms/-/ms-1.0.0.tgz")
        );
    }

    #[test]
    fn yarn_without_any_configuration_places_nothing() {
        let root = tempfile::tempdir().unwrap();
        let registries =
            ConfiguredRegistries::yarn_berry_with(root.path(), Some(root.path()), &no_env).unwrap();
        assert_eq!(registries, None);
    }

    #[test]
    fn bun_reads_its_global_file_under_the_project_and_lets_the_registry_variable_override() {
        let root = tempfile::tempdir().unwrap();
        let config_home = root.path().join("config");
        let project = root.path().join("project");
        std::fs::create_dir_all(&config_home).unwrap();
        std::fs::create_dir_all(&project).unwrap();
        std::fs::write(
            config_home.join(".bunfig.toml"),
            "[install]\nregistry = \"https://global.example/\"\n[install.scopes]\ncorp = \"https://global-scope.example/\"\n",
        )
        .unwrap();
        std::fs::write(
            project.join("bunfig.toml"),
            "[install.scopes]\ncorp = \"https://project-scope.example/\"\n",
        )
        .unwrap();
        let config_home_text = config_home.to_string_lossy().into_owned();
        let env = |name: &str| (name == "XDG_CONFIG_HOME").then(|| config_home_text.clone());

        let registries = ConfiguredRegistries::bun_with(&project, None, &env)
            .unwrap()
            .unwrap();
        assert_eq!(
            placed(&registries, "@corp/utils").as_deref(),
            Some("https://project-scope.example/@corp/utils/-/utils-1.0.0.tgz")
        );
        assert_eq!(
            placed(&registries, "ms").as_deref(),
            Some("https://global.example/ms/-/ms-1.0.0.tgz")
        );

        let env = |name: &str| match name {
            "XDG_CONFIG_HOME" => Some(config_home_text.clone()),
            "NPM_CONFIG_REGISTRY" => Some("https://npm-env.example/".to_owned()),
            _ => None,
        };
        let registries = ConfiguredRegistries::bun_with(&project, None, &env)
            .unwrap()
            .unwrap();
        assert_eq!(
            placed(&registries, "ms").as_deref(),
            Some("https://npm-env.example/ms/-/ms-1.0.0.tgz")
        );
    }

    #[test]
    fn bun_reads_no_home_file_while_xdg_config_home_is_set() {
        let root = tempfile::tempdir().unwrap();
        let home = root.path().join("home");
        let config_home = root.path().join("config");
        let project = root.path().join("project");
        for directory in [&home, &config_home, &project] {
            std::fs::create_dir_all(directory).unwrap();
        }
        std::fs::write(
            home.join(".bunfig.toml"),
            "[install]\nregistry = \"https://home.example/\"\n",
        )
        .unwrap();
        let config_home_text = config_home.to_string_lossy().into_owned();
        let env = |name: &str| (name == "XDG_CONFIG_HOME").then(|| config_home_text.clone());
        assert_eq!(
            ConfiguredRegistries::bun_with(&project, Some(&home), &env).unwrap(),
            None
        );
    }

    #[test]
    fn a_configuration_that_does_not_parse_is_reported_by_position_without_its_text() {
        let mut registries = ConfiguredRegistries::default();
        let error = registries
            .merge_bunfig(
                "[install]\nregistry = { url = \"https://a.example\", token = \"npm_secret\n",
                Path::new("bunfig.toml"),
                &no_env,
            )
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("bunfig.toml") && error.contains("line 2"),
            "{error}"
        );
        assert!(!error.contains("npm_secret"), "{error}");

        let error = registries
            .merge_yarnrc(
                "npmAuthToken: \"npm_secret\"\nnpmScopes: [\n",
                Path::new(".yarnrc.yml"),
                &no_env,
            )
            .unwrap_err()
            .to_string();
        assert!(
            error.contains(".yarnrc.yml") && error.contains("line"),
            "{error}"
        );
        assert!(!error.contains("npm_secret"), "{error}");
    }
}
