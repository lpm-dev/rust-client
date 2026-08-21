//! npm `package-lock.json` parser.
//!
//! Supports lockfile versions 1, 2, and 3:
//! - v3 (npm 7+): uses `packages` map with `node_modules/` prefixed keys
//! - v2 (npm 6→7 bridge): has both `packages` and `dependencies` — prefers `packages`
//! - v1 (npm 5–6): uses nested `dependencies` tree
//!
//! Package rows retain their exact installed paths. Dependency edges resolve through
//! the package-specific `node_modules` scopes visible from those paths.

use crate::{
    BoundedMap, MAX_PACKAGES, MigratedPackage, enforce_package_limit, read_lockfile_snapshot,
};
use lpm_common::LpmError;
use serde::Deserialize;
use serde::de::{self, DeserializeSeed, IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde_json::Value;
use std::collections::HashMap;
use std::fmt;
use std::path::Path;
use tracing::warn;

/// One decoded npm lockfile snapshot and the exact installed paths that
/// correspond to its normalized registry package rows.
#[derive(Debug)]
pub struct ParsedNpmLockfile {
    pub version: u32,
    pub packages: Vec<MigratedPackage>,
}

const MAX_NPM_DEPENDENCIES_PER_PACKAGE: usize = 10_000;
const MAX_NPM_DEPENDENCY_EDGES: usize = 1_000_000;
const MAX_NPM_PACKAGE_PATH_BYTES: usize = 32 * 1024;
const MAX_NPM_PACKAGE_DEPTH: usize = 256;

type NpmPackageMap = BoundedMap<serde_json::Map<String, Value>, MAX_PACKAGES>;

struct NpmLockfile {
    lockfile_version: Option<Value>,
    packages: Option<NpmPackageMap>,
    dependencies: Option<V1Dependencies>,
}

enum V1Dependencies {
    Map(Vec<RawEntry>),
    NonMap,
}

impl<'de> Deserialize<'de> for NpmLockfile {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_map(NpmLockfileVisitor)
    }
}

struct NpmLockfileVisitor;

impl<'de> Visitor<'de> for NpmLockfileVisitor {
    type Value = NpmLockfile;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("an npm package-lock object")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut lockfile_version = None;
        let mut packages = None;
        let mut dependencies = None;
        let mut saw_dependencies = false;

        while let Some(field) = map.next_key::<String>()? {
            match field.as_str() {
                "lockfileVersion" => {
                    if lockfile_version.is_some() {
                        return Err(de::Error::duplicate_field("lockfileVersion"));
                    }
                    lockfile_version = Some(map.next_value::<Value>()?);
                }
                "packages" => {
                    if packages.is_some() {
                        return Err(de::Error::duplicate_field("packages"));
                    }
                    packages = Some(map.next_value::<NpmPackageMap>()?);
                }
                "dependencies" => {
                    if saw_dependencies {
                        return Err(de::Error::duplicate_field("dependencies"));
                    }
                    saw_dependencies = true;
                    let version_uses_packages = lockfile_version
                        .as_ref()
                        .and_then(Value::as_u64)
                        .is_some_and(|version| version >= 2);
                    if packages.is_some() || version_uses_packages {
                        map.next_value::<IgnoredAny>()?;
                        dependencies = Some(V1Dependencies::NonMap);
                        continue;
                    }
                    let mut state = V1DecodeState::default();
                    map.next_value_seed(V1DependenciesSeed {
                        state: &mut state,
                        parent_path: String::new(),
                        depth: 0,
                    })?;
                    dependencies = Some(if state.root_was_map {
                        V1Dependencies::Map(state.entries)
                    } else {
                        V1Dependencies::NonMap
                    });
                }
                _ => {
                    map.next_value::<IgnoredAny>()?;
                }
            }
        }

        Ok(NpmLockfile {
            lockfile_version,
            packages,
            dependencies,
        })
    }
}

/// Parse an npm `package-lock.json` file from disk.
pub fn parse(path: &Path, lockfile_version: u32) -> Result<Vec<MigratedPackage>, LpmError> {
    let content = read_lockfile_snapshot(path)?;
    parse_str(&content, lockfile_version)
}

/// Decode an npm lockfile snapshot once for audit discovery.
pub fn parse_snapshot(content: &str) -> Result<ParsedNpmLockfile, LpmError> {
    let lockfile = decode_lockfile(content)?;
    let version = lockfile_version_from_field(lockfile.lockfile_version.as_ref())?;
    let packages = parse_lockfile_maps(lockfile, version)?;

    Ok(ParsedNpmLockfile { version, packages })
}

/// Parse npm `package-lock.json` content from a string.
pub fn parse_str(content: &str, lockfile_version: u32) -> Result<Vec<MigratedPackage>, LpmError> {
    let lockfile = decode_lockfile(content)?;
    let detected_version = lockfile_version_from_field(lockfile.lockfile_version.as_ref())?;
    if detected_version != lockfile_version {
        return Err(LpmError::Script(format!(
            "npm lockfile version changed while parsing: detected {detected_version}, expected {lockfile_version}"
        )));
    }
    parse_lockfile_maps(lockfile, detected_version)
}

fn decode_lockfile(content: &str) -> Result<NpmLockfile, LpmError> {
    serde_json::from_str(content)
        .map_err(|error| LpmError::Script(format!("invalid package-lock.json: {error}")))
}

/// Read and validate `lockfileVersion` from a parsed package-lock snapshot.
pub fn lockfile_version_from_value(json: &Value) -> Result<u32, LpmError> {
    lockfile_version_from_field(json.get("lockfileVersion"))
}

fn lockfile_version_from_field(value: Option<&Value>) -> Result<u32, LpmError> {
    let value = value.ok_or_else(|| {
        LpmError::Script("package-lock.json is missing lockfileVersion".to_string())
    })?;
    let raw = value.as_u64().ok_or_else(|| {
        LpmError::Script("package-lock.json has a non-integer lockfileVersion".to_string())
    })?;
    let version = u32::try_from(raw).map_err(|_| {
        LpmError::Script(format!(
            "package-lock.json lockfileVersion {raw} exceeds the supported integer range"
        ))
    })?;
    if !(1..=3).contains(&version) {
        return Err(LpmError::Script(format!(
            "unsupported npm lockfile version {version}; supported versions are 1, 2, and 3"
        )));
    }
    Ok(version)
}

fn parse_lockfile_maps(
    lockfile: NpmLockfile,
    lockfile_version: u32,
) -> Result<Vec<MigratedPackage>, LpmError> {
    if !(1..=3).contains(&lockfile_version) {
        return Err(LpmError::Script(format!(
            "unsupported npm lockfile version {lockfile_version}; supported versions are 1, 2, and 3"
        )));
    }
    if let Some(packages) = lockfile.packages {
        return parse_packages_block(&packages);
    }
    if lockfile_version == 1 {
        return match lockfile.dependencies {
            Some(V1Dependencies::Map(entries)) => finalize_entries(entries),
            Some(V1Dependencies::NonMap) => Err(LpmError::Script(
                "npm dependencies must be a package map".to_string(),
            )),
            None => Err(LpmError::Script(
                "package-lock.json has no 'packages' or 'dependencies' block".to_string(),
            )),
        };
    }
    Err(LpmError::Script(
        "package-lock.json has no 'packages' or 'dependencies' block".to_string(),
    ))
}

/// Parse a previously decoded package-lock snapshot.
pub fn parse_value(json: &Value, lockfile_version: u32) -> Result<Vec<MigratedPackage>, LpmError> {
    if !(1..=3).contains(&lockfile_version) {
        return Err(LpmError::Script(format!(
            "unsupported npm lockfile version {lockfile_version}; supported versions are 1, 2, and 3"
        )));
    }

    // v2 and v3 both have "packages" — prefer it over "dependencies"
    if let Some(packages) = json.get("packages").and_then(|p| p.as_object()) {
        return parse_packages_block(packages);
    }

    // v1 fallback: use "dependencies" block
    if lockfile_version <= 1
        && let Some(deps) = json.get("dependencies").and_then(|d| d.as_object())
    {
        return parse_dependencies_block(deps);
    }

    Err(LpmError::Script(
        "package-lock.json has no 'packages' or 'dependencies' block".to_string(),
    ))
}

/// Return the normalized identity of one registry-backed v2/v3 package row.
pub fn registry_package_identity<'a>(
    key: &str,
    value: &'a Value,
) -> Result<Option<(String, &'a str)>, LpmError> {
    if key.is_empty()
        || value.get("link").and_then(Value::as_bool).unwrap_or(false)
        || !key.contains("node_modules/")
        || value.get("resolved").and_then(Value::as_str).is_none()
    {
        return Ok(None);
    }
    validate_package_path(key)?;
    let name = extract_name_from_key(key).ok_or_else(|| {
        LpmError::Script(format!(
            "package-lock.json contains an invalid package path: {key}"
        ))
    })?;
    let Some(version) = value.get("version").and_then(Value::as_str) else {
        return Ok(None);
    };
    Ok(Some((name, version)))
}

fn validate_package_path(raw: &str) -> Result<(), LpmError> {
    if raw.len() > MAX_NPM_PACKAGE_PATH_BYTES {
        return Err(LpmError::Script(format!(
            "package-lock.json package path length exceeds {MAX_NPM_PACKAGE_PATH_BYTES} bytes"
        )));
    }
    let path = Path::new(raw);
    if raw.contains('\\')
        || raw
            .split('/')
            .any(|component| component.is_empty() || matches!(component, "." | ".."))
        || path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, std::path::Component::Normal(_)))
    {
        return Err(LpmError::Script(format!(
            "package-lock.json contains an unsafe package path: {raw}"
        )));
    }
    let mut components = raw.split('/');
    let marker_found = components
        .by_ref()
        .any(|component| component == "node_modules");
    if !marker_found {
        return Err(invalid_package_path(raw));
    }

    let mut depth = 0usize;
    loop {
        depth += 1;
        if depth > MAX_NPM_PACKAGE_DEPTH {
            return Err(LpmError::Script(format!(
                "package-lock.json package path exceeds the maximum nesting depth of {MAX_NPM_PACKAGE_DEPTH}"
            )));
        }

        let Some(first) = components.next() else {
            return Err(invalid_package_path(raw));
        };
        if first.is_empty() {
            return Err(invalid_package_path(raw));
        }
        if let Some(scope) = first.strip_prefix('@')
            && (scope.is_empty()
                || components
                    .next()
                    .is_none_or(|package_name| package_name.is_empty()))
        {
            return Err(invalid_package_path(raw));
        }

        match components.next() {
            None => break,
            Some("node_modules") => {}
            Some(_) => return Err(invalid_package_path(raw)),
        }
    }
    Ok(())
}

fn invalid_package_path(raw: &str) -> LpmError {
    LpmError::Script(format!(
        "package-lock.json contains an invalid package path: {raw}"
    ))
}

/// Intermediate entry collected during first pass.
struct RawEntry {
    name: String,
    version: String,
    resolved: Option<String>,
    integrity: Option<String>,
    is_optional: bool,
    is_dev: bool,
    /// Dependency names declared by this package (semver ranges, not exact versions).
    dep_names: Vec<String>,
    /// The full key in the packages map (for nested resolution).
    key: String,
}

/// Extract the package name from a `node_modules/...` key.
///
/// Handles:
/// - `"node_modules/express"` → `"express"`
/// - `"node_modules/@scope/pkg"` → `"@scope/pkg"`
/// - `"node_modules/a/node_modules/b"` → `"b"`
/// - `"node_modules/a/node_modules/@scope/pkg"` → `"@scope/pkg"`
fn extract_name_from_key(key: &str) -> Option<String> {
    let mut components = key.rsplit('/');
    let package_name = components.next()?;
    if let Some(scope) = components
        .next()
        .filter(|component| component.starts_with('@'))
    {
        let mut name = String::with_capacity(scope.len() + 1 + package_name.len());
        name.push_str(scope);
        name.push('/');
        name.push_str(package_name);
        Some(name)
    } else {
        Some(package_name.to_string())
    }
}

/// Parse the v2/v3 `packages` block.
fn parse_packages_block(
    packages: &serde_json::Map<String, Value>,
) -> Result<Vec<MigratedPackage>, LpmError> {
    enforce_package_limit(packages.len())?;
    let mut entries = Vec::with_capacity(packages.len().min(1024));
    let mut dependency_edge_count = 0usize;

    for (key, value) in packages {
        let Some((name, version)) = registry_package_identity(key, value)? else {
            continue;
        };
        let version = version.to_string();

        let resolved = value
            .get("resolved")
            .and_then(|v| v.as_str())
            .map(String::from);

        let integrity = value
            .get("integrity")
            .and_then(|v| v.as_str())
            .map(String::from);
        let is_optional = value
            .get("optional")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let is_dev = value.get("dev").and_then(|v| v.as_bool()).unwrap_or(false);

        let dep_names = dependency_names(value, &name, &mut dependency_edge_count)?;

        entries.push(RawEntry {
            name,
            version,
            resolved,
            integrity,
            is_optional,
            is_dev,
            dep_names,
            key: key.clone(),
        });
    }

    finalize_entries(entries)
}

fn dependency_names(
    value: &Value,
    package_name: &str,
    aggregate_count: &mut usize,
) -> Result<Vec<String>, LpmError> {
    let dependencies = value.get("dependencies").and_then(Value::as_object);
    let optional_dependencies = value.get("optionalDependencies").and_then(Value::as_object);
    let declared_count = dependencies.map_or(0, serde_json::Map::len)
        + optional_dependencies.map_or(0, serde_json::Map::len);
    if declared_count > MAX_NPM_DEPENDENCIES_PER_PACKAGE {
        return Err(LpmError::Script(format!(
            "npm package {package_name} declares more than 10,000 dependencies"
        )));
    }

    let mut names = Vec::with_capacity(declared_count);
    if let Some(dependencies) = dependencies {
        names.extend(dependencies.keys().cloned());
    }
    if let Some(optional_dependencies) = optional_dependencies {
        names.extend(optional_dependencies.keys().cloned());
    }
    names.sort_unstable();
    names.dedup();

    *aggregate_count = aggregate_count
        .checked_add(names.len())
        .ok_or_else(|| LpmError::Script("npm dependency edge count overflowed".to_string()))?;
    if *aggregate_count > MAX_NPM_DEPENDENCY_EDGES {
        return Err(LpmError::Script(format!(
            "npm lockfile contains more than {MAX_NPM_DEPENDENCY_EDGES} dependency edges"
        )));
    }
    Ok(names)
}

struct NpmScopeIndex<'a> {
    parents: Vec<Option<usize>>,
    package_scopes: Vec<usize>,
    visible_versions: HashMap<(usize, &'a str), &'a str>,
}

impl<'a> NpmScopeIndex<'a> {
    fn new(entries: &'a [RawEntry]) -> Result<Self, LpmError> {
        let mut scope_paths = Vec::with_capacity(entries.len() + 1);
        let mut scope_by_path = HashMap::with_capacity(entries.len() + 1);
        scope_paths.push("");
        scope_by_path.insert("", 0usize);

        for entry in entries {
            let mut scope_path = entry.key.as_str();
            loop {
                if !scope_by_path.contains_key(scope_path) {
                    let scope_id = scope_paths.len();
                    scope_paths.push(scope_path);
                    scope_by_path.insert(scope_path, scope_id);
                }
                let Some((parent, _)) = split_package_location(scope_path) else {
                    break;
                };
                if parent.is_empty() {
                    break;
                }
                scope_path = parent;
            }
        }

        let mut parents = Vec::with_capacity(scope_paths.len());
        for scope_path in &scope_paths {
            if scope_path.is_empty() {
                parents.push(None);
                continue;
            }
            let parent_path = split_package_location(scope_path).map_or("", |(parent, _)| parent);
            parents.push(scope_by_path.get(parent_path).copied().or(Some(0)));
        }

        let mut package_scopes = Vec::with_capacity(entries.len());
        let mut visible_versions = HashMap::with_capacity(entries.len());
        for entry in entries {
            let package_scope =
                scope_by_path
                    .get(entry.key.as_str())
                    .copied()
                    .ok_or_else(|| {
                        LpmError::Script(format!(
                            "package-lock.json lost the package scope for {}",
                            entry.key
                        ))
                    })?;
            package_scopes.push(package_scope);
            let (parent_path, _) = split_package_location(&entry.key).ok_or_else(|| {
                LpmError::Script(format!(
                    "package-lock.json contains an invalid package path: {}",
                    entry.key
                ))
            })?;
            let parent_scope = scope_by_path.get(parent_path).copied().ok_or_else(|| {
                LpmError::Script(format!(
                    "package-lock.json lost the parent package scope for {}",
                    entry.key
                ))
            })?;
            visible_versions.insert((parent_scope, entry.name.as_str()), entry.version.as_str());
        }

        Ok(Self {
            parents,
            package_scopes,
            visible_versions,
        })
    }

    fn resolve(&self, package_index: usize, dependency: &str) -> Option<&'a str> {
        let mut scope = Some(self.package_scopes[package_index]);
        while let Some(scope_id) = scope {
            if let Some(version) = self.visible_versions.get(&(scope_id, dependency)) {
                return Some(*version);
            }
            scope = self.parents[scope_id];
        }
        None
    }
}

fn split_package_location(path: &str) -> Option<(&str, &str)> {
    const MARKER: &str = "node_modules/";
    let marker_start = path.rfind(MARKER)?;
    let parent = path[..marker_start]
        .strip_suffix('/')
        .unwrap_or(&path[..marker_start]);
    Some((parent, &path[marker_start + MARKER.len()..]))
}

fn finalize_entries(entries: Vec<RawEntry>) -> Result<Vec<MigratedPackage>, LpmError> {
    if entries.iter().all(|entry| entry.dep_names.is_empty()) {
        let result = entries
            .into_iter()
            .map(|entry| migrated_package(entry, Vec::new()))
            .collect();
        return sort_and_validate_packages(result);
    }

    let scope_index = NpmScopeIndex::new(&entries)?;
    let mut resolved_dependencies = Vec::with_capacity(entries.len());
    let mut unresolved_count = 0usize;
    for (package_index, entry) in entries.iter().enumerate() {
        let mut dependencies = Vec::with_capacity(entry.dep_names.len());
        for dependency in &entry.dep_names {
            if let Some(version) = scope_index.resolve(package_index, dependency) {
                dependencies.push((dependency.clone(), version.to_string()));
            } else {
                unresolved_count += 1;
            }
        }
        resolved_dependencies.push(dependencies);
    }
    drop(scope_index);

    if unresolved_count > 0 {
        warn!(
            unresolved_count,
            "could not resolve dependency versions from visible npm package scopes"
        );
    }

    let mut result = Vec::with_capacity(entries.len());
    for (entry, dependencies) in entries.into_iter().zip(resolved_dependencies) {
        result.push(migrated_package(entry, dependencies));
    }
    sort_and_validate_packages(result)
}

fn migrated_package(entry: RawEntry, dependencies: Vec<(String, String)>) -> MigratedPackage {
    MigratedPackage {
        lockfile_key: Some(entry.key),
        name: entry.name,
        version: entry.version,
        resolved: entry.resolved,
        integrity: entry.integrity,
        dependencies,
        is_optional: entry.is_optional,
        is_dev: entry.is_dev,
    }
}

fn sort_and_validate_packages(
    mut result: Vec<MigratedPackage>,
) -> Result<Vec<MigratedPackage>, LpmError> {
    result.sort_by(|a, b| {
        a.name
            .cmp(&b.name)
            .then_with(|| a.version.cmp(&b.version))
            .then_with(|| a.lockfile_key.cmp(&b.lockfile_key))
    });
    enforce_package_limit(result.len())?;
    Ok(result)
}

#[derive(Default)]
struct V1DecodeState {
    entries: Vec<RawEntry>,
    package_count: usize,
    dependency_edge_count: usize,
    root_was_map: bool,
}

struct V1DependenciesSeed<'a> {
    state: &'a mut V1DecodeState,
    parent_path: String,
    depth: usize,
}

impl<'de> DeserializeSeed<'de> for V1DependenciesSeed<'_> {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(V1DependenciesVisitor {
            state: self.state,
            parent_path: self.parent_path,
            depth: self.depth,
        })
    }
}

struct V1DependenciesVisitor<'a> {
    state: &'a mut V1DecodeState,
    parent_path: String,
    depth: usize,
}

impl<'de> Visitor<'de> for V1DependenciesVisitor<'_> {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("an npm v1 dependencies map or null")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        if self.depth == 0 {
            self.state.root_was_map = true;
        }
        if self.depth > MAX_V1_DEPTH {
            return Err(de::Error::custom(format!(
                "npm v1 lockfile exceeds the maximum nesting depth of {MAX_V1_DEPTH}"
            )));
        }

        while let Some(name) = map.next_key::<String>()? {
            self.state.package_count = self
                .state
                .package_count
                .checked_add(1)
                .ok_or_else(|| de::Error::custom("npm package count overflowed"))?;
            if self.state.package_count > MAX_PACKAGES {
                return Err(de::Error::custom(format!(
                    "npm package map exceeds the maximum of {MAX_PACKAGES} entries"
                )));
            }
            validate_v1_package_name(&name).map_err(de::Error::custom)?;
            let package_path =
                v1_package_path(&self.parent_path, &name).map_err(de::Error::custom)?;
            map.next_value_seed(V1PackageSeed {
                state: self.state,
                name,
                package_path,
                depth: self.depth,
            })?;
        }
        Ok(())
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_bool<E>(self, _value: bool) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_i64<E>(self, _value: i64) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_u64<E>(self, _value: u64) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_f64<E>(self, _value: f64) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_str<E>(self, _value: &str) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_string<E>(self, _value: String) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        while sequence.next_element::<IgnoredAny>()?.is_some() {}
        Ok(())
    }
}

struct V1PackageSeed<'a> {
    state: &'a mut V1DecodeState,
    name: String,
    package_path: String,
    depth: usize,
}

impl<'de> DeserializeSeed<'de> for V1PackageSeed<'_> {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(V1PackageVisitor {
            state: self.state,
            name: self.name,
            package_path: self.package_path,
            depth: self.depth,
        })
    }
}

struct V1PackageVisitor<'a> {
    state: &'a mut V1DecodeState,
    name: String,
    package_path: String,
    depth: usize,
}

impl<'de> Visitor<'de> for V1PackageVisitor<'_> {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("an npm v1 package object or null")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut version = None;
        let mut resolved = None;
        let mut integrity = None;
        let mut is_optional = false;
        let mut is_dev = false;
        let mut dep_names = Vec::new();
        let mut saw_dependencies = false;
        let mut saw_requires = false;

        while let Some(field) = map.next_key::<String>()? {
            match field.as_str() {
                "version" => {
                    let value = map.next_value::<Value>()?;
                    version = value.as_str().map(String::from);
                }
                "resolved" => {
                    let value = map.next_value::<Value>()?;
                    resolved = value.as_str().map(String::from);
                }
                "integrity" => {
                    let value = map.next_value::<Value>()?;
                    integrity = value.as_str().map(String::from);
                }
                "optional" => {
                    let value = map.next_value::<Value>()?;
                    is_optional = value.as_bool().unwrap_or(false);
                }
                "dev" => {
                    let value = map.next_value::<Value>()?;
                    is_dev = value.as_bool().unwrap_or(false);
                }
                "dependencies" => {
                    if saw_dependencies {
                        return Err(de::Error::duplicate_field("dependencies"));
                    }
                    saw_dependencies = true;
                    map.next_value_seed(V1DependenciesSeed {
                        state: self.state,
                        parent_path: self.package_path.clone(),
                        depth: self.depth + 1,
                    })?;
                }
                "requires" => {
                    if saw_requires {
                        return Err(de::Error::duplicate_field("requires"));
                    }
                    saw_requires = true;
                    dep_names = map.next_value_seed(DependencyNamesSeed)?;
                }
                _ => {
                    map.next_value::<IgnoredAny>()?;
                }
            }
        }

        self.state.dependency_edge_count = self
            .state
            .dependency_edge_count
            .checked_add(dep_names.len())
            .ok_or_else(|| de::Error::custom("npm dependency edge count overflowed"))?;
        if self.state.dependency_edge_count > MAX_NPM_DEPENDENCY_EDGES {
            return Err(de::Error::custom(format!(
                "npm lockfile contains more than {MAX_NPM_DEPENDENCY_EDGES} dependency edges"
            )));
        }

        if let (Some(version), Some(resolved)) = (version, resolved) {
            self.state.entries.push(RawEntry {
                name: self.name,
                version,
                resolved: Some(resolved),
                integrity,
                is_optional,
                is_dev,
                dep_names,
                key: self.package_path,
            });
        }
        Ok(())
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_bool<E>(self, _value: bool) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_i64<E>(self, _value: i64) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_u64<E>(self, _value: u64) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_f64<E>(self, _value: f64) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_str<E>(self, _value: &str) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_string<E>(self, _value: String) -> Result<Self::Value, E> {
        Ok(())
    }
}

struct DependencyNamesSeed;

impl<'de> DeserializeSeed<'de> for DependencyNamesSeed {
    type Value = Vec<String>;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(DependencyNamesVisitor)
    }
}

struct DependencyNamesVisitor;

impl<'de> Visitor<'de> for DependencyNamesVisitor {
    type Value = Vec<String>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("an npm dependency map or null")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut names = Vec::with_capacity(map.size_hint().unwrap_or(0).min(1024));
        while let Some(name) = map.next_key::<String>()? {
            if names.len() == MAX_NPM_DEPENDENCIES_PER_PACKAGE {
                return Err(de::Error::custom(
                    "npm package declares more than 10,000 dependencies",
                ));
            }
            names.push(name);
            map.next_value::<IgnoredAny>()?;
        }
        names.sort_unstable();
        Ok(names)
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(Vec::new())
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(Vec::new())
    }
}

fn v1_package_path(parent_path: &str, package_name: &str) -> Result<String, LpmError> {
    let additional =
        usize::from(!parent_path.is_empty()) + "node_modules/".len() + package_name.len();
    let mut path = String::with_capacity(parent_path.len() + additional);
    path.push_str(parent_path);
    if !parent_path.is_empty() {
        path.push('/');
    }
    path.push_str("node_modules/");
    path.push_str(package_name);
    validate_package_path(&path)?;
    Ok(path)
}

fn parse_dependencies_block(
    deps: &serde_json::Map<String, Value>,
) -> Result<Vec<MigratedPackage>, LpmError> {
    let mut entries = Vec::with_capacity(deps.len().min(1024));
    let mut raw_package_count = 0usize;
    let mut dependency_edge_count = 0usize;
    let mut package_path = String::new();
    collect_v1_entries(
        deps,
        &mut package_path,
        &mut entries,
        &mut raw_package_count,
        &mut dependency_edge_count,
        0,
    )?;
    finalize_entries(entries)
}

const MAX_V1_DEPTH: usize = 256;

fn collect_v1_entries(
    deps: &serde_json::Map<String, Value>,
    package_path: &mut String,
    entries: &mut Vec<RawEntry>,
    package_count: &mut usize,
    dependency_edge_count: &mut usize,
    depth: usize,
) -> Result<(), LpmError> {
    if depth > MAX_V1_DEPTH {
        return Err(LpmError::Script(format!(
            "npm v1 lockfile exceeds the maximum nesting depth of {MAX_V1_DEPTH}"
        )));
    }
    for (name, value) in deps {
        *package_count = package_count
            .checked_add(1)
            .ok_or_else(|| LpmError::Script("npm package count overflowed".to_string()))?;
        enforce_package_limit(*package_count)?;
        validate_v1_package_name(name)?;
        let original_path_len = package_path.len();
        if !package_path.is_empty() {
            package_path.push('/');
        }
        package_path.push_str("node_modules/");
        package_path.push_str(name);
        validate_package_path(package_path)?;

        if let (Some(version), Some(resolved)) = (
            value.get("version").and_then(Value::as_str),
            value.get("resolved").and_then(Value::as_str),
        ) {
            let mut dep_names: Vec<String> = value
                .get("requires")
                .and_then(Value::as_object)
                .map(|requires| requires.keys().cloned().collect())
                .unwrap_or_default();
            if dep_names.len() > MAX_NPM_DEPENDENCIES_PER_PACKAGE {
                return Err(LpmError::Script(format!(
                    "npm package {name} declares more than 10,000 dependencies"
                )));
            }
            dep_names.sort_unstable();
            *dependency_edge_count = dependency_edge_count
                .checked_add(dep_names.len())
                .ok_or_else(|| {
                    LpmError::Script("npm dependency edge count overflowed".to_string())
                })?;
            if *dependency_edge_count > MAX_NPM_DEPENDENCY_EDGES {
                return Err(LpmError::Script(format!(
                    "npm lockfile contains more than {MAX_NPM_DEPENDENCY_EDGES} dependency edges"
                )));
            }

            entries.push(RawEntry {
                name: name.clone(),
                version: version.to_string(),
                resolved: Some(resolved.to_string()),
                integrity: value
                    .get("integrity")
                    .and_then(Value::as_str)
                    .map(String::from),
                is_optional: value
                    .get("optional")
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
                is_dev: value.get("dev").and_then(Value::as_bool).unwrap_or(false),
                dep_names,
                key: package_path.clone(),
            });
        }

        if let Some(nested) = value.get("dependencies").and_then(Value::as_object) {
            collect_v1_entries(
                nested,
                package_path,
                entries,
                package_count,
                dependency_edge_count,
                depth + 1,
            )?;
        }
        package_path.truncate(original_path_len);
    }
    Ok(())
}

fn validate_v1_package_name(name: &str) -> Result<(), LpmError> {
    let mut components = name.split('/');
    let Some(first) = components.next() else {
        return Err(LpmError::Script("npm v1 package name is empty".to_string()));
    };
    let valid = if first.starts_with('@') {
        first.len() > 1
            && components.next().is_some_and(|package| !package.is_empty())
            && components.next().is_none()
    } else {
        !first.is_empty() && components.next().is_none()
    };
    if !valid || name.contains('\\') {
        return Err(LpmError::Script(format!(
            "npm v1 lockfile contains an invalid package name: {name}"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_minimal_v3() {
        let json = r#"{
            "name": "test-project",
            "version": "1.0.0",
            "lockfileVersion": 3,
            "packages": {
                "": {
                    "name": "test-project",
                    "version": "1.0.0"
                },
                "node_modules/express": {
                    "version": "4.22.1",
                    "resolved": "https://registry.npmjs.org/express/-/express-4.22.1.tgz",
                    "integrity": "sha512-abc123"
                }
            }
        }"#;

        let result = parse_str(json, 3).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].name, "express");
        assert_eq!(result[0].version, "4.22.1");
        assert_eq!(
            result[0].resolved.as_deref(),
            Some("https://registry.npmjs.org/express/-/express-4.22.1.tgz")
        );
        assert_eq!(result[0].integrity.as_deref(), Some("sha512-abc123"));
    }

    #[test]
    fn parse_with_dependencies() {
        let json = r#"{
            "lockfileVersion": 3,
            "packages": {
                "": { "name": "proj", "version": "1.0.0" },
                "node_modules/express": {
                    "version": "4.22.1",
                    "resolved": "https://registry.npmjs.org/express/-/express-4.22.1.tgz",
                    "integrity": "sha512-aaa",
                    "dependencies": {
                        "accepts": "~1.3.8",
                        "body-parser": "1.20.3"
                    }
                },
                "node_modules/accepts": {
                    "version": "1.3.8",
                    "resolved": "https://registry.npmjs.org/accepts/-/accepts-1.3.8.tgz",
                    "integrity": "sha512-bbb"
                },
                "node_modules/body-parser": {
                    "version": "1.20.3",
                    "resolved": "https://registry.npmjs.org/body-parser/-/body-parser-1.20.3.tgz",
                    "integrity": "sha512-ccc"
                }
            }
        }"#;

        let result = parse_str(json, 3).unwrap();
        assert_eq!(result.len(), 3);

        let express = result.iter().find(|p| p.name == "express").unwrap();
        assert_eq!(express.dependencies.len(), 2);
        // Dependencies are sorted by name
        assert_eq!(
            express.dependencies[0],
            ("accepts".to_string(), "1.3.8".to_string())
        );
        assert_eq!(
            express.dependencies[1],
            ("body-parser".to_string(), "1.20.3".to_string())
        );
    }

    #[test]
    fn parse_scoped_packages() {
        let json = r#"{
            "lockfileVersion": 3,
            "packages": {
                "": { "name": "proj", "version": "1.0.0" },
                "node_modules/@babel/core": {
                    "version": "7.24.0",
                    "resolved": "https://registry.npmjs.org/@babel/core/-/core-7.24.0.tgz",
                    "integrity": "sha512-babel"
                },
                "node_modules/@types/node": {
                    "version": "20.11.0",
                    "resolved": "https://registry.npmjs.org/@types/node/-/node-20.11.0.tgz",
                    "integrity": "sha512-types"
                }
            }
        }"#;

        let result = parse_str(json, 3).unwrap();
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].name, "@babel/core");
        assert_eq!(result[0].version, "7.24.0");
        assert_eq!(result[1].name, "@types/node");
        assert_eq!(result[1].version, "20.11.0");
    }

    #[test]
    fn parse_nested_multi_version() {
        let json = r#"{
            "lockfileVersion": 3,
            "packages": {
                "": { "name": "proj", "version": "1.0.0" },
                "node_modules/debug": {
                    "version": "4.3.4",
                    "resolved": "https://registry.npmjs.org/debug/-/debug-4.3.4.tgz",
                    "integrity": "sha512-root"
                },
                "node_modules/express": {
                    "version": "4.22.1",
                    "resolved": "https://registry.npmjs.org/express/-/express-4.22.1.tgz",
                    "integrity": "sha512-expr",
                    "dependencies": {
                        "debug": "2.6.9"
                    }
                },
                "node_modules/express/node_modules/debug": {
                    "version": "2.6.9",
                    "resolved": "https://registry.npmjs.org/debug/-/debug-2.6.9.tgz",
                    "integrity": "sha512-nested"
                }
            }
        }"#;

        let result = parse_str(json, 3).unwrap();
        // Should have 3 entries: debug@4.3.4, debug@2.6.9, express
        assert_eq!(result.len(), 3);

        let debugs: Vec<_> = result.iter().filter(|p| p.name == "debug").collect();
        assert_eq!(debugs.len(), 2);
        let versions: Vec<&str> = debugs.iter().map(|d| d.version.as_str()).collect();
        assert!(versions.contains(&"4.3.4"));
        assert!(versions.contains(&"2.6.9"));

        // Express should resolve debug to 2.6.9 (nested version, not root)
        let express = result.iter().find(|p| p.name == "express").unwrap();
        assert_eq!(express.dependencies.len(), 1);
        assert_eq!(
            express.dependencies[0],
            ("debug".to_string(), "2.6.9".to_string())
        );
    }

    #[test]
    fn parse_skips_root_entry() {
        let json = r#"{
            "lockfileVersion": 3,
            "packages": {
                "": {
                    "name": "my-app",
                    "version": "1.0.0",
                    "dependencies": { "lodash": "^4.17.21" }
                },
                "node_modules/lodash": {
                    "version": "4.17.21",
                    "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
                    "integrity": "sha512-lodash"
                }
            }
        }"#;

        let result = parse_str(json, 3).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].name, "lodash");
        // Root project "my-app" should NOT appear
        assert!(result.iter().all(|p| p.name != "my-app"));
    }

    #[test]
    fn parse_skips_link_entries() {
        let json = r#"{
            "lockfileVersion": 3,
            "packages": {
                "": { "name": "monorepo", "version": "1.0.0" },
                "node_modules/my-lib": {
                    "resolved": "packages/my-lib",
                    "link": true
                },
                "node_modules/lodash": {
                    "version": "4.17.21",
                    "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
                    "integrity": "sha512-lodash"
                },
                "packages/my-lib": {
                    "name": "my-lib",
                    "version": "1.0.0"
                }
            }
        }"#;

        let result = parse_str(json, 3).unwrap();
        // Only lodash should be included; my-lib is a workspace link
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].name, "lodash");
    }

    #[test]
    fn parse_preserves_integrity() {
        let integrity = "sha512-aGVz0Rb+QLGxaNJUqL/xCRJJhoyPbLOfMQjRQmo5A2VjMbCT7BPH02LcQRbOBLXCEPE9LaXIjIvemG0TwjWbQ==";
        let json = format!(
            r#"{{
                "lockfileVersion": 3,
                "packages": {{
                    "": {{ "name": "proj", "version": "1.0.0" }},
                    "node_modules/accepts": {{
                        "version": "1.3.8",
                        "resolved": "https://registry.npmjs.org/accepts/-/accepts-1.3.8.tgz",
                        "integrity": "{integrity}"
                    }}
                }}
            }}"#
        );

        let result = parse_str(&json, 3).unwrap();
        assert_eq!(result[0].integrity.as_deref(), Some(integrity));
    }

    #[test]
    fn parse_handles_optional() {
        let json = r#"{
            "lockfileVersion": 3,
            "packages": {
                "": { "name": "proj", "version": "1.0.0" },
                "node_modules/fsevents": {
                    "version": "2.3.3",
                    "resolved": "https://registry.npmjs.org/fsevents/-/fsevents-2.3.3.tgz",
                    "integrity": "sha512-fse",
                    "optional": true
                },
                "node_modules/lodash": {
                    "version": "4.17.21",
                    "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
                    "integrity": "sha512-lod"
                }
            }
        }"#;

        let result = parse_str(json, 3).unwrap();
        let fsevents = result.iter().find(|p| p.name == "fsevents").unwrap();
        assert!(fsevents.is_optional);

        let lodash = result.iter().find(|p| p.name == "lodash").unwrap();
        assert!(!lodash.is_optional);
    }

    #[test]
    fn parse_handles_dev() {
        let json = r#"{
            "lockfileVersion": 3,
            "packages": {
                "": { "name": "proj", "version": "1.0.0" },
                "node_modules/vitest": {
                    "version": "1.0.0",
                    "resolved": "https://registry.npmjs.org/vitest/-/vitest-1.0.0.tgz",
                    "integrity": "sha512-vit",
                    "dev": true
                },
                "node_modules/express": {
                    "version": "4.22.1",
                    "resolved": "https://registry.npmjs.org/express/-/express-4.22.1.tgz",
                    "integrity": "sha512-exp"
                }
            }
        }"#;

        let result = parse_str(json, 3).unwrap();
        let vitest = result.iter().find(|p| p.name == "vitest").unwrap();
        assert!(vitest.is_dev);

        let express = result.iter().find(|p| p.name == "express").unwrap();
        assert!(!express.is_dev);
    }

    #[test]
    fn parse_handles_missing_resolved() {
        let json = r#"{
            "lockfileVersion": 3,
            "packages": {
                "": { "name": "proj", "version": "1.0.0" },
                "node_modules/local-pkg": {
                    "version": "1.0.0"
                },
                "node_modules/lodash": {
                    "version": "4.17.21",
                    "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
                    "integrity": "sha512-lod"
                }
            }
        }"#;

        let result = parse_str(json, 3).unwrap();
        // local-pkg without resolved URL should be skipped
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].name, "lodash");
    }

    #[test]
    fn parse_v2_uses_packages_block() {
        let json = r#"{
            "name": "proj",
            "version": "1.0.0",
            "lockfileVersion": 2,
            "requires": true,
            "packages": {
                "": { "name": "proj", "version": "1.0.0" },
                "node_modules/lodash": {
                    "version": "4.17.21",
                    "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
                    "integrity": "sha512-lodv2"
                }
            },
            "dependencies": {
                "lodash": {
                    "version": "4.17.21",
                    "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
                    "integrity": "sha512-lodv1-compat",
                    "dependencies": {"transitive": "1.0.0"}
                }
            }
        }"#;

        let result = parse_str(json, 2).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].name, "lodash");
        // Should use packages block, not the v1 dependencies block
        assert_eq!(result[0].integrity.as_deref(), Some("sha512-lodv2"));
    }

    #[test]
    fn parse_v2_ignores_null_legacy_dependencies_when_packages_are_present() {
        let json = r#"{
            "lockfileVersion": 2,
            "dependencies": null,
            "packages": {
                "node_modules/lodash": {
                    "version": "4.17.21",
                    "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"
                }
            }
        }"#;

        let result = parse_str(json, 2).unwrap();

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].name, "lodash");
    }

    #[test]
    fn parse_v1_rejects_null_dependencies() {
        let error = parse_str(
            r#"{
                "lockfileVersion": 1,
                "dependencies": null
            }"#,
            1,
        )
        .unwrap_err();

        assert!(error.to_string().contains("must be a package map"));
    }

    #[test]
    fn parse_empty_packages() {
        let json = r#"{
            "lockfileVersion": 3,
            "packages": {
                "": { "name": "empty-proj", "version": "1.0.0" }
            }
        }"#;

        let result = parse_str(json, 3).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn parse_real_world_small() {
        let json = r#"{
            "name": "my-api",
            "version": "2.0.0",
            "lockfileVersion": 3,
            "packages": {
                "": {
                    "name": "my-api",
                    "version": "2.0.0",
                    "dependencies": {
                        "express": "^4.22.0",
                        "cors": "^2.8.5"
                    },
                    "devDependencies": {
                        "vitest": "^1.0.0"
                    }
                },
                "node_modules/express": {
                    "version": "4.22.1",
                    "resolved": "https://registry.npmjs.org/express/-/express-4.22.1.tgz",
                    "integrity": "sha512-ePqK5MnFG2so8cWsFDfg3wEgrBqMFuPsHCMqb3vjBVQ+kDH7rMKBUB6PE/aGHkivOpFMw2naYNyGFhmi8eiDg==",
                    "dependencies": {
                        "accepts": "~1.3.8",
                        "debug": "2.6.9"
                    }
                },
                "node_modules/cors": {
                    "version": "2.8.5",
                    "resolved": "https://registry.npmjs.org/cors/-/cors-2.8.5.tgz",
                    "integrity": "sha512-KIHbLJqu73RGr/hnbrO9uBeixNGuvSQjul/jdFvS05CbVHts80oPh0BmFUf09+os9NQ7jJKbN+JQwrAJR3drNA==",
                    "dependencies": {
                        "object-assign": "^4",
                        "vary": "^1"
                    }
                },
                "node_modules/accepts": {
                    "version": "1.3.8",
                    "resolved": "https://registry.npmjs.org/accepts/-/accepts-1.3.8.tgz",
                    "integrity": "sha512-PYAthTa2m2VKxuvSD3DPC/Gy+U+sOA1LAuT8mkmRuvw+NACSaeXEQ+NHcVF7rONl6qcaxV3Uuemwawk+7+SJLw=="
                },
                "node_modules/debug": {
                    "version": "4.3.4",
                    "resolved": "https://registry.npmjs.org/debug/-/debug-4.3.4.tgz",
                    "integrity": "sha512-debug434"
                },
                "node_modules/express/node_modules/debug": {
                    "version": "2.6.9",
                    "resolved": "https://registry.npmjs.org/debug/-/debug-2.6.9.tgz",
                    "integrity": "sha512-debug269"
                },
                "node_modules/object-assign": {
                    "version": "4.1.1",
                    "resolved": "https://registry.npmjs.org/object-assign/-/object-assign-4.1.1.tgz",
                    "integrity": "sha512-objassign"
                },
                "node_modules/vary": {
                    "version": "1.1.2",
                    "resolved": "https://registry.npmjs.org/vary/-/vary-1.1.2.tgz",
                    "integrity": "sha512-vary112"
                },
                "node_modules/vitest": {
                    "version": "1.2.0",
                    "resolved": "https://registry.npmjs.org/vitest/-/vitest-1.2.0.tgz",
                    "integrity": "sha512-vitest120",
                    "dev": true
                }
            }
        }"#;

        let result = parse_str(json, 3).unwrap();

        // 8 packages (everything except root)
        assert_eq!(result.len(), 8);

        // Check express resolves debug to 2.6.9 (nested), not 4.3.4 (root)
        let express = result.iter().find(|p| p.name == "express").unwrap();
        let debug_dep = express
            .dependencies
            .iter()
            .find(|d| d.0 == "debug")
            .unwrap();
        assert_eq!(debug_dep.1, "2.6.9");

        // Check cors resolves its deps to root-level versions
        let cors = result.iter().find(|p| p.name == "cors").unwrap();
        assert_eq!(cors.dependencies.len(), 2);
        let oa_dep = cors
            .dependencies
            .iter()
            .find(|d| d.0 == "object-assign")
            .unwrap();
        assert_eq!(oa_dep.1, "4.1.1");
        let vary_dep = cors.dependencies.iter().find(|d| d.0 == "vary").unwrap();
        assert_eq!(vary_dep.1, "1.1.2");

        // Check vitest is dev
        let vitest = result.iter().find(|p| p.name == "vitest").unwrap();
        assert!(vitest.is_dev);

        // Two debug packages exist
        assert_eq!(result.iter().filter(|p| p.name == "debug").count(), 2);

        // All packages have integrity
        assert!(result.iter().all(|p| p.integrity.is_some()));
    }

    #[test]
    fn extract_name_basic() {
        assert_eq!(
            extract_name_from_key("node_modules/express"),
            Some("express".to_string())
        );
    }

    #[test]
    fn extract_name_scoped() {
        assert_eq!(
            extract_name_from_key("node_modules/@babel/core"),
            Some("@babel/core".to_string())
        );
    }

    #[test]
    fn extract_name_nested() {
        assert_eq!(
            extract_name_from_key("node_modules/express/node_modules/debug"),
            Some("debug".to_string())
        );
    }

    #[test]
    fn extract_name_nested_scoped() {
        assert_eq!(
            extract_name_from_key("node_modules/a/node_modules/@scope/pkg"),
            Some("@scope/pkg".to_string())
        );
    }

    #[test]
    fn parse_v1_fallback() {
        let json = r#"{
            "name": "old-project",
            "version": "1.0.0",
            "lockfileVersion": 1,
            "dependencies": {
                "lodash": {
                    "version": "4.17.21",
                    "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
                    "integrity": "sha512-lodv1"
                },
                "express": {
                    "version": "4.17.1",
                    "resolved": "https://registry.npmjs.org/express/-/express-4.17.1.tgz",
                    "integrity": "sha512-exv1",
                    "requires": {
                        "debug": "2.6.9"
                    },
                    "dependencies": {
                        "debug": {
                            "version": "2.6.9",
                            "resolved": "https://registry.npmjs.org/debug/-/debug-2.6.9.tgz",
                            "integrity": "sha512-dbgv1"
                        }
                    }
                }
            }
        }"#;

        let result = parse_str(json, 1).unwrap();
        assert_eq!(result.len(), 3);

        let express = result.iter().find(|p| p.name == "express").unwrap();
        assert_eq!(express.dependencies.len(), 1);
        assert_eq!(
            express.dependencies[0],
            ("debug".to_string(), "2.6.9".to_string())
        );

        // Nested debug should also be present
        let debugs: Vec<_> = result.iter().filter(|p| p.name == "debug").collect();
        assert_eq!(debugs.len(), 1); // Only the nested one (it's the only one with `resolved`)
        assert_eq!(debugs[0].version, "2.6.9");
    }

    #[test]
    fn version_lookup_prefers_root_level_deterministic() {
        // Root-level entry should always win over nested
        let json = r#"{
            "lockfileVersion": 3,
            "packages": {
                "": { "name": "proj", "version": "1.0.0" },
                "node_modules/some-pkg/node_modules/express": {
                    "version": "4.18.0",
                    "resolved": "https://registry.npmjs.org/express/-/express-4.18.0.tgz",
                    "integrity": "sha512-nested"
                },
                "node_modules/express": {
                    "version": "4.22.1",
                    "resolved": "https://registry.npmjs.org/express/-/express-4.22.1.tgz",
                    "integrity": "sha512-root"
                },
                "node_modules/consumer": {
                    "version": "1.0.0",
                    "resolved": "https://registry.npmjs.org/consumer/-/consumer-1.0.0.tgz",
                    "integrity": "sha512-cons",
                    "dependencies": {
                        "express": "^4.0.0"
                    }
                }
            }
        }"#;

        let result = parse_str(json, 3).unwrap();
        let consumer = result.iter().find(|p| p.name == "consumer").unwrap();
        // consumer is at root level, so its dep on express should resolve to root express (4.22.1)
        assert_eq!(
            consumer.dependencies[0],
            ("express".to_string(), "4.22.1".to_string())
        );
    }

    #[test]
    fn parse_snapshot_keeps_delimiter_ambiguous_coordinates_bound_to_their_paths() {
        let parsed = parse_snapshot(
            r#"{
                "lockfileVersion": 3,
                "packages": {
                    "node_modules/a": {
                        "version": "b@c",
                        "resolved": "https://registry.npmjs.org/a/-/a-b-c.tgz"
                    },
                    "node_modules/a@b": {
                        "version": "c",
                        "resolved": "https://registry.npmjs.org/a-at-b/-/a-at-b-c.tgz"
                    }
                }
            }"#,
        )
        .unwrap();

        let identities_and_paths: Vec<_> = parsed
            .packages
            .iter()
            .map(|package| {
                (
                    package.name.as_str(),
                    package.version.as_str(),
                    package.lockfile_key.as_deref(),
                )
            })
            .collect();

        assert_eq!(
            identities_and_paths,
            vec![
                ("a", "b@c", Some("node_modules/a")),
                ("a@b", "c", Some("node_modules/a@b")),
            ]
        );
    }

    #[test]
    fn v1_requires_resolve_through_the_nearest_visible_ancestor() {
        let packages = parse_str(
            r#"{
                "lockfileVersion": 1,
                "dependencies": {
                    "visible": {
                        "version": "9.0.0",
                        "resolved": "https://registry.npmjs.org/visible/-/visible-9.0.0.tgz"
                    },
                    "z-ancestor": {
                        "version": "1.0.0",
                        "resolved": "https://registry.npmjs.org/z-ancestor/-/z-ancestor-1.0.0.tgz",
                        "dependencies": {
                            "branch": {
                                "version": "1.0.0",
                                "resolved": "https://registry.npmjs.org/branch/-/branch-1.0.0.tgz",
                                "dependencies": {
                                    "consumer": {
                                        "version": "1.0.0",
                                        "resolved": "https://registry.npmjs.org/consumer/-/consumer-1.0.0.tgz",
                                        "requires": {"visible": "*"}
                                    }
                                }
                            },
                            "visible": {
                                "version": "2.0.0",
                                "resolved": "https://registry.npmjs.org/visible/-/visible-2.0.0.tgz"
                            }
                        }
                    }
                }
            }"#,
            1,
        )
        .unwrap();

        let consumer = packages
            .iter()
            .find(|package| package.name == "consumer")
            .unwrap();

        assert_eq!(
            consumer.dependencies,
            vec![("visible".to_string(), "2.0.0".to_string())]
        );
    }

    #[test]
    fn v1_packages_retain_their_nested_install_paths() {
        let parsed = parse_snapshot(
            r#"{
                "lockfileVersion": 1,
                "dependencies": {
                    "a": {
                        "version": "1.0.0",
                        "resolved": "https://registry.npmjs.org/a/-/a-1.0.0.tgz",
                        "dependencies": {
                            "dep": {
                                "version": "1.0.0",
                                "resolved": "https://registry.npmjs.org/dep/-/dep-1.0.0.tgz"
                            }
                        }
                    },
                    "dep": {
                        "version": "2.0.0",
                        "resolved": "https://registry.npmjs.org/dep/-/dep-2.0.0.tgz"
                    }
                }
            }"#,
        )
        .unwrap();

        let dep_paths: Vec<_> = parsed
            .packages
            .iter()
            .filter(|package| package.name == "dep")
            .map(|package| (package.version.as_str(), package.lockfile_key.as_deref()))
            .collect();

        assert_eq!(
            dep_paths,
            vec![
                ("1.0.0", Some("node_modules/a/node_modules/dep")),
                ("2.0.0", Some("node_modules/dep")),
            ]
        );
    }

    #[test]
    fn v3_dependency_resolution_ignores_unreachable_sibling_instances() {
        let packages = parse_str(
            r#"{
                "lockfileVersion": 3,
                "packages": {
                    "node_modules/a": {
                        "version": "1.0.0",
                        "resolved": "https://registry.npmjs.org/a/-/a-1.0.0.tgz",
                        "dependencies": {"c": "1.0.0"}
                    },
                    "node_modules/b/node_modules/c": {
                        "version": "1.0.0",
                        "resolved": "https://registry.npmjs.org/c/-/c-1.0.0.tgz"
                    }
                }
            }"#,
            3,
        )
        .unwrap();

        let package_a = packages.iter().find(|package| package.name == "a").unwrap();

        assert!(package_a.dependencies.is_empty());
    }

    #[test]
    fn v1_skipped_wrapper_keeps_registry_backed_descendants() {
        let packages = parse_str(
            r#"{
                "lockfileVersion": 1,
                "dependencies": {
                    "local-wrapper": {
                        "version": "1.0.0",
                        "dependencies": {
                            "registry-child": {
                                "version": "2.0.0",
                                "resolved": "https://registry.npmjs.org/registry-child/-/registry-child-2.0.0.tgz"
                            }
                        }
                    }
                }
            }"#,
            1,
        )
        .unwrap();

        assert_eq!(
            packages
                .iter()
                .map(|package| package.name.as_str())
                .collect::<Vec<_>>(),
            vec!["registry-child"]
        );
    }

    #[test]
    fn overlapping_dependency_sections_emit_one_dependency_edge() {
        let packages = parse_str(
            r#"{
                "lockfileVersion": 3,
                "packages": {
                    "node_modules/p": {
                        "version": "1.0.0",
                        "resolved": "https://registry.npmjs.org/p/-/p-1.0.0.tgz",
                        "dependencies": {"q": "1.0.0"},
                        "optionalDependencies": {"q": "1.0.0"}
                    },
                    "node_modules/q": {
                        "version": "1.0.0",
                        "resolved": "https://registry.npmjs.org/q/-/q-1.0.0.tgz"
                    }
                }
            }"#,
            3,
        )
        .unwrap();

        let package_p = packages.iter().find(|package| package.name == "p").unwrap();

        assert_eq!(
            package_p.dependencies,
            vec![("q".to_string(), "1.0.0".to_string())]
        );
    }

    #[test]
    fn structurally_invalid_package_paths_are_rejected() {
        for invalid_path in [
            "node_modules/foo/bar",
            "node_modules/@scope",
            "node_modules/@scope/pkg/extra",
            "node_modules/foo/bar/node_modules/pkg",
        ] {
            let lockfile = serde_json::json!({
                "lockfileVersion": 3,
                "packages": {
                    invalid_path: {
                        "version": "1.0.0",
                        "resolved": "https://registry.npmjs.org/invalid/-/invalid-1.0.0.tgz"
                    }
                }
            });

            let error = parse_str(&lockfile.to_string(), 3).unwrap_err();

            assert!(
                error.to_string().contains("invalid package path"),
                "unexpected error for {invalid_path}: {error}"
            );
        }
    }

    #[test]
    fn package_depth_counts_install_scopes_instead_of_name_substrings() {
        let mut package_path = String::new();
        for depth in 0..129 {
            if depth > 0 {
                package_path.push('/');
            }
            package_path.push_str("node_modules/@node_modules/pkg");
        }

        validate_package_path(&package_path).unwrap();
    }

    #[test]
    fn scoped_name_matching_the_install_directory_marker_is_preserved() {
        let packages = parse_str(
            r#"{
                "lockfileVersion": 3,
                "packages": {
                    "node_modules/@node_modules/pkg": {
                        "version": "1.0.0",
                        "resolved": "https://registry.npmjs.org/@node_modules/pkg/-/pkg-1.0.0.tgz"
                    }
                }
            }"#,
            3,
        )
        .unwrap();

        assert_eq!(packages[0].name, "@node_modules/pkg");
    }

    #[test]
    fn package_dependency_count_is_bounded() {
        let mut dependencies = serde_json::Map::new();
        for index in 0..=10_000 {
            dependencies.insert(format!("dep-{index}"), Value::String("*".to_string()));
        }
        let lockfile = serde_json::json!({
            "lockfileVersion": 3,
            "packages": {
                "node_modules/wide": {
                    "version": "1.0.0",
                    "resolved": "https://registry.npmjs.org/wide/-/wide-1.0.0.tgz",
                    "dependencies": dependencies
                }
            }
        });

        let error = parse_str(&lockfile.to_string(), 3).unwrap_err();

        assert!(error.to_string().contains("10,000 dependencies"));
    }

    #[test]
    fn aggregate_dependency_edge_limit_rejects_the_next_edge() {
        let package = serde_json::json!({"dependencies": {"dep": "*"}});
        let mut aggregate_count = MAX_NPM_DEPENDENCY_EDGES;

        let error = dependency_names(&package, "wide", &mut aggregate_count).unwrap_err();

        assert!(error.to_string().contains("dependency edges"));
    }

    #[test]
    fn aggregate_dependency_edge_limit_accepts_the_exact_boundary() {
        let package = serde_json::json!({"dependencies": {"dep": "*"}});
        let mut aggregate_count = MAX_NPM_DEPENDENCY_EDGES - 1;

        let names = dependency_names(&package, "wide", &mut aggregate_count).unwrap();

        assert_eq!(names, vec!["dep"]);
        assert_eq!(aggregate_count, MAX_NPM_DEPENDENCY_EDGES);
    }

    #[test]
    fn deeply_nested_v3_package_paths_are_rejected() {
        let mut package_path = String::new();
        for depth in 0..=MAX_V1_DEPTH {
            if depth > 0 {
                package_path.push('/');
            }
            package_path.push_str("node_modules/p");
        }
        let lockfile = serde_json::json!({
            "lockfileVersion": 3,
            "packages": {
                package_path: {
                    "version": "1.0.0",
                    "resolved": "https://registry.npmjs.org/p/-/p-1.0.0.tgz"
                }
            }
        });

        let error = parse_str(&lockfile.to_string(), 3).unwrap_err();

        assert!(error.to_string().contains("nesting depth"));
    }

    #[test]
    fn excessively_long_package_paths_are_rejected() {
        let package_name = "a".repeat(32 * 1024);
        let package_path = format!("node_modules/{package_name}");
        let lockfile = serde_json::json!({
            "lockfileVersion": 3,
            "packages": {
                package_path: {
                    "version": "1.0.0",
                    "resolved": "https://registry.npmjs.org/long/-/long-1.0.0.tgz"
                }
            }
        });

        let error = parse_str(&lockfile.to_string(), 3).unwrap_err();

        assert!(error.to_string().contains("path length"));
    }

    #[test]
    fn parse_no_blocks_returns_error() {
        let json = r#"{ "lockfileVersion": 3 }"#;
        let result = parse_str(json, 3);
        assert!(result.is_err());
    }

    #[test]
    fn parse_rejects_unsupported_lockfile_version_even_with_packages_block() {
        let error = parse_str(
            r#"{
                "lockfileVersion": 4,
                "packages": {
                    "node_modules/future": {
                        "version": "1.0.0",
                        "resolved": "https://registry.npmjs.org/future/-/future-1.0.0.tgz"
                    }
                }
            }"#,
            4,
        )
        .unwrap_err();

        assert!(
            error
                .to_string()
                .contains("unsupported npm lockfile version")
        );
    }

    #[test]
    fn parse_rejects_missing_lockfile_version() {
        let error = parse_snapshot(r#"{"packages": {}}"#).unwrap_err();

        assert!(error.to_string().contains("missing lockfileVersion"));
    }

    #[test]
    fn parse_rejects_nonnumeric_lockfile_version() {
        let error = parse_snapshot(r#"{"lockfileVersion": "3", "packages": {}}"#).unwrap_err();

        assert!(error.to_string().contains("non-integer lockfileVersion"));
    }

    #[test]
    fn parse_rejects_lockfile_version_larger_than_u32() {
        let error =
            parse_snapshot(r#"{"lockfileVersion": 4294967296, "packages": {}}"#).unwrap_err();

        assert!(error.to_string().contains("supported integer range"));
    }

    #[test]
    fn raw_package_map_limit_is_enforced_before_filtering() {
        let mut packages = serde_json::Map::new();
        for index in 0..=crate::MAX_PACKAGES {
            packages.insert(format!("skipped-{index}"), Value::Null);
        }
        let json = Value::Object(serde_json::Map::from_iter([
            ("lockfileVersion".to_string(), Value::from(3)),
            ("packages".to_string(), Value::Object(packages)),
        ]));

        let error = parse_value(&json, 3).unwrap_err();

        assert!(error.to_string().contains("200001 packages"));
    }

    #[test]
    fn raw_v1_dependency_limit_is_enforced_before_filtering() {
        let mut dependencies = serde_json::Map::new();
        for index in 0..=crate::MAX_PACKAGES {
            dependencies.insert(
                format!("filtered-{index}"),
                serde_json::json!({"version": "1.0.0"}),
            );
        }
        let json = Value::Object(serde_json::Map::from_iter([
            ("lockfileVersion".to_string(), Value::from(1)),
            ("dependencies".to_string(), Value::Object(dependencies)),
        ]));

        let error = parse_value(&json, 1).unwrap_err();

        assert!(error.to_string().contains("200001 packages"));
    }

    #[test]
    fn v1_dependency_depth_limit_fails_instead_of_truncating_inventory() {
        let mut nested = serde_json::json!({
            "version": "1.0.0",
            "resolved": "https://registry.npmjs.org/sentinel/-/sentinel-1.0.0.tgz"
        });
        for depth in (0..=MAX_V1_DEPTH).rev() {
            nested = serde_json::json!({
                "version": "1.0.0",
                "resolved": format!("https://registry.npmjs.org/level-{depth}/-/level-{depth}-1.0.0.tgz"),
                "dependencies": {format!("level-{depth}"): nested}
            });
        }
        let json = serde_json::json!({
            "lockfileVersion": 1,
            "dependencies": {"root": nested}
        });

        let error = parse_value(&json, 1).unwrap_err();

        assert!(error.to_string().contains("nesting depth"));
    }

    #[test]
    fn package_map_limit_is_enforced_before_the_overflow_value_is_decoded() {
        use std::fmt::Write as _;

        let mut lockfile = String::with_capacity(crate::MAX_PACKAGES * 16);
        lockfile.push_str(r#"{"lockfileVersion":3,"packages":{"#);
        for index in 0..crate::MAX_PACKAGES {
            write!(lockfile, r#""p{index}":null,"#).unwrap();
        }
        lockfile.push_str(r#""overflow":["#);

        let error = parse_snapshot(&lockfile).unwrap_err();

        assert!(error.to_string().contains("package map exceeds"));
    }

    #[test]
    fn nested_v1_package_limit_is_enforced_before_the_overflow_value_is_decoded() {
        use std::fmt::Write as _;

        let mut lockfile = String::with_capacity(crate::MAX_PACKAGES * 18);
        lockfile.push_str(r#"{"lockfileVersion":1,"dependencies":{"root":{"dependencies":{"#);
        for index in 0..(crate::MAX_PACKAGES - 1) {
            write!(lockfile, r#""p{index}":null,"#).unwrap();
        }
        lockfile.push_str(r#""overflow":["#);

        let error = parse_snapshot(&lockfile).unwrap_err();

        assert!(error.to_string().contains("package map exceeds"));
    }

    #[test]
    fn v1_requires_limit_is_enforced_before_the_overflow_value_is_decoded() {
        use std::fmt::Write as _;

        let mut lockfile = String::with_capacity(MAX_NPM_DEPENDENCIES_PER_PACKAGE * 14);
        lockfile.push_str(
            r#"{"lockfileVersion":1,"dependencies":{"root":{"version":"1.0.0","resolved":"https://registry.npmjs.org/root/-/root-1.0.0.tgz","requires":{"#,
        );
        for index in 0..MAX_NPM_DEPENDENCIES_PER_PACKAGE {
            write!(lockfile, r#""d{index}":null,"#).unwrap();
        }
        lockfile.push_str(r#""overflow":["#);

        let error = parse_snapshot(&lockfile).unwrap_err();

        assert!(error.to_string().contains("10,000 dependencies"));
    }
}
