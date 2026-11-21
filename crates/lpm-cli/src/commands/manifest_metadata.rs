pub(crate) mod graph;

use lpm_common::{BoundedReadError, LpmError, LpmRoot, with_shared_lock};
use lpm_lockfile::{LockedPackage, Lockfile};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Default)]
pub(crate) struct ManifestMetadata {
    pub(crate) description: Option<String>,
    pub(crate) licenses: Vec<String>,
    pub(crate) homepage: Option<String>,
    pub(crate) repository: Option<String>,
    pub(crate) author: Option<String>,
}

impl ManifestMetadata {
    pub(crate) fn merge_missing(&mut self, other: ManifestMetadata) {
        if self.description.is_none() {
            self.description = other.description;
        }
        if self.homepage.is_none() {
            self.homepage = other.homepage;
        }
        if self.repository.is_none() {
            self.repository = other.repository;
        }
        if self.author.is_none() {
            self.author = other.author;
        }
        if self.licenses.is_empty() {
            self.licenses = other.licenses;
        }
    }
}

#[derive(Debug)]
pub(crate) struct InstalledManifestInventory {
    metadata_by_package: BTreeMap<String, ManifestMetadata>,
    platform_skipped_packages: BTreeSet<String>,
}

impl InstalledManifestInventory {
    pub(crate) fn get(&self, package: &LockedPackage) -> Option<&ManifestMetadata> {
        self.metadata_by_package.get(&package_metadata_key(package))
    }

    pub(crate) fn is_platform_skipped(&self, package: &LockedPackage) -> bool {
        self.platform_skipped_packages
            .contains(&package_metadata_key(package))
    }
}

pub(crate) fn read_json_file(path: &Path) -> Result<Value, LpmError> {
    let (content, _) = lpm_common::read_text_regular_file_capped_with_metadata(
        path,
        lpm_common::CONFIG_FILE_SIZE_CAP_BYTES,
    )?;
    let object: serde_json::Map<String, Value> =
        serde_json::from_str(lpm_common::strip_utf8_bom_str(&content)).map_err(|e| {
            LpmError::Registry(format!("failed to parse JSON from {}: {e}", path.display()))
        })?;
    Ok(Value::Object(object))
}

pub(crate) fn extract_manifest_metadata(value: &Value) -> ManifestMetadata {
    extract_manifest_metadata_fields(
        value.get("description"),
        value.get("homepage"),
        value.get("repository"),
        value.get("author"),
        value.get("license"),
        value.get("licenses"),
    )
}

fn extract_manifest_metadata_fields(
    description: Option<&Value>,
    homepage: Option<&Value>,
    repository: Option<&Value>,
    author: Option<&Value>,
    license: Option<&Value>,
    licenses_field: Option<&Value>,
) -> ManifestMetadata {
    let description = description
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    let homepage = homepage
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    let repository = repository.and_then(extract_urlish);
    let author = author.and_then(extract_author);
    let mut licenses = Vec::new();
    if let Some(license) = license {
        collect_licenses(license, &mut licenses);
    }
    if let Some(license) = licenses_field {
        collect_licenses(license, &mut licenses);
    }
    licenses.sort();
    licenses.dedup();
    ManifestMetadata {
        description,
        licenses,
        homepage,
        repository,
        author,
    }
}

pub(crate) fn read_installed_manifest_metadata(
    project_dir: &Path,
    lockfile: &Lockfile,
    root_json: &Value,
) -> Result<InstalledManifestInventory, LpmError> {
    let root = LpmRoot::from_env()?;
    let lock_path = root.store_lock();
    let root_for_lock = root;
    with_shared_lock(lock_path, || {
        let baseline_index = lpm_store::V2BaselineIndex::for_project(project_dir, &root_for_lock);
        let store_version = lpm_store::StoreVersion::from_env();
        let packages = &lockfile.packages;
        let indexes = graph::PackageIndexes::new(packages);
        let roots = graph::selected_roots(root_json, lockfile, &indexes);
        let platform_skip_flags = platform_skipped_packages(lockfile, &indexes, &roots);
        let instance_baselines = super::audit::inventory::build_instance_baselines(
            project_dir,
            &baseline_index,
            lockfile,
        );
        let installed_paths = installed_package_paths(project_dir, lockfile, &indexes, &roots)?;
        let manifest_cache = ManifestReadCache::new();

        let resolve_one = |package: &LockedPackage,
                           platform_skipped: bool|
         -> Result<PackageManifestOutcome, LpmError> {
            let package_key = package_metadata_key(package);
            if let Some(path) = installed_paths.get(&package_key) {
                if let Some(baseline) = baseline_index.lookup_by_package_dir(path)
                    && package
                        .integrity
                        .as_deref()
                        .is_some_and(|expected| expected != baseline.integrity)
                {
                    return Err(LpmError::Store(format!(
                        "installed package {}@{} has a different integrity than lpm.lock. Run `lpm install` to repair this project's dependencies",
                        package.name, package.version
                    )));
                }
                let manifest = path.join("package.json");
                match read_matching_manifest_metadata_cached(&manifest, package, &manifest_cache)? {
                    ManifestProbe::Match(metadata) => {
                        return Ok(PackageManifestOutcome::Metadata(package_key, metadata));
                    }
                    ManifestProbe::Missing | ManifestProbe::DifferentPackage { .. } => {
                        if store_version.uses_virtual_store() {
                            return Err(missing_installed_manifest(package, Some(&manifest)));
                        }
                    }
                }
            }
            let virtual_baseline = package
                .instance_id
                .and_then(|id| instance_baselines.get(&id).map(std::sync::Arc::as_ref))
                .or_else(|| {
                    if package.instance_id.is_some() {
                        return None;
                    }
                    match package.integrity.as_deref() {
                        Some(integrity) => baseline_index.lookup_by_integrity(integrity),
                        None => baseline_index.lookup(&package.name, &package.version),
                    }
                });
            if let Some(baseline) = virtual_baseline {
                let manifest_path = baseline.package_dir.join("package.json");
                let metadata = read_required_manifest_metadata_cached(
                    &manifest_path,
                    package,
                    &manifest_cache,
                )?;
                return Ok(PackageManifestOutcome::Metadata(package_key, metadata));
            }

            if package.instance_id.is_some() && store_version.uses_virtual_store() {
                if platform_skipped {
                    return Ok(PackageManifestOutcome::PlatformSkipped(package_key));
                }
                return Err(missing_installed_manifest(package, None));
            }
            let project_manifest = node_modules_package_json(project_dir, &package.name);
            match read_matching_manifest_metadata_cached(
                &project_manifest,
                package,
                &manifest_cache,
            )? {
                ManifestProbe::Match(metadata) => {
                    return Ok(PackageManifestOutcome::Metadata(package_key, metadata));
                }
                ManifestProbe::Missing | ManifestProbe::DifferentPackage { .. } => {}
            }

            if store_version == lpm_store::StoreVersion::V1
                && let Some(baseline) =
                    lpm_store::find_installed_package_baseline_by_identity_indexed(
                        &baseline_index,
                        &root_for_lock,
                        &package.name,
                        &package.version,
                        package.integrity.as_deref(),
                    )
            {
                let manifest_path = baseline.package_dir.join("package.json");
                let metadata = read_required_manifest_metadata_cached(
                    &manifest_path,
                    package,
                    &manifest_cache,
                )?;
                return Ok(PackageManifestOutcome::Metadata(package_key, metadata));
            }

            if platform_skipped {
                return Ok(PackageManifestOutcome::PlatformSkipped(package_key));
            }

            Err(missing_installed_manifest(package, None))
        };

        let outcomes: Vec<Option<Result<PackageManifestOutcome, LpmError>>> = if packages.len() >= 4
        {
            use rayon::prelude::*;
            let failed = std::sync::atomic::AtomicBool::new(false);
            packages
                .par_iter()
                .zip(platform_skip_flags.par_iter())
                .map(|(package, &platform_skipped)| {
                    if failed.load(std::sync::atomic::Ordering::Acquire) {
                        return None;
                    }
                    let outcome = resolve_one(package, platform_skipped);
                    if outcome.is_err() {
                        failed.store(true, std::sync::atomic::Ordering::Release);
                    }
                    Some(outcome)
                })
                .collect()
        } else {
            packages
                .iter()
                .zip(&platform_skip_flags)
                .map(|(package, &platform_skipped)| Some(resolve_one(package, platform_skipped)))
                .collect()
        };

        let mut metadata_by_package = BTreeMap::new();
        let mut platform_skipped_packages = BTreeSet::new();
        for (index, outcome) in outcomes.into_iter().enumerate() {
            let outcome = match outcome {
                Some(outcome) => outcome?,
                None => resolve_one(&packages[index], platform_skip_flags[index])?,
            };
            match outcome {
                PackageManifestOutcome::Metadata(key, metadata) => {
                    metadata_by_package.insert(key, metadata);
                }
                PackageManifestOutcome::PlatformSkipped(key) => {
                    platform_skipped_packages.insert(key);
                }
            }
        }
        Ok(InstalledManifestInventory {
            metadata_by_package,
            platform_skipped_packages,
        })
    })
}

enum PackageManifestOutcome {
    Metadata(String, ManifestMetadata),
    PlatformSkipped(String),
}

#[derive(Clone)]
struct ParsedManifestEntry {
    name: Option<String>,
    version: Option<String>,
    metadata: ManifestMetadata,
}

#[derive(Default)]
struct RawManifestFields {
    name: Option<Value>,
    version: Option<Value>,
    description: Option<Value>,
    homepage: Option<Value>,
    repository: Option<Value>,
    author: Option<Value>,
    license: Option<Value>,
    licenses: Option<Value>,
}

impl RawManifestFields {
    fn into_parsed_entry(self) -> ParsedManifestEntry {
        let name = self
            .name
            .as_ref()
            .and_then(Value::as_str)
            .map(str::to_owned);
        let version = self
            .version
            .as_ref()
            .and_then(Value::as_str)
            .map(str::to_owned);
        let metadata = extract_manifest_metadata_fields(
            self.description.as_ref(),
            self.homepage.as_ref(),
            self.repository.as_ref(),
            self.author.as_ref(),
            self.license.as_ref(),
            self.licenses.as_ref(),
        );
        ParsedManifestEntry {
            name,
            version,
            metadata,
        }
    }
}

impl<'de> serde::Deserialize<'de> for RawManifestFields {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = RawManifestFields;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a JSON value")
            }

            fn visit_bool<E>(self, _: bool) -> Result<Self::Value, E> {
                Ok(RawManifestFields::default())
            }
            fn visit_i64<E>(self, _: i64) -> Result<Self::Value, E> {
                Ok(RawManifestFields::default())
            }
            fn visit_u64<E>(self, _: u64) -> Result<Self::Value, E> {
                Ok(RawManifestFields::default())
            }
            fn visit_f64<E>(self, _: f64) -> Result<Self::Value, E> {
                Ok(RawManifestFields::default())
            }
            fn visit_str<E>(self, _: &str) -> Result<Self::Value, E> {
                Ok(RawManifestFields::default())
            }
            fn visit_unit<E>(self) -> Result<Self::Value, E> {
                Ok(RawManifestFields::default())
            }
            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                while seq.next_element::<serde::de::IgnoredAny>()?.is_some() {}
                Ok(RawManifestFields::default())
            }
            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::MapAccess<'de>,
            {
                let mut fields = RawManifestFields::default();
                while let Some(key) = map.next_key::<std::borrow::Cow<'de, str>>()? {
                    match key.as_ref() {
                        "name" => fields.name = Some(map.next_value()?),
                        "version" => fields.version = Some(map.next_value()?),
                        "description" => fields.description = Some(map.next_value()?),
                        "homepage" => fields.homepage = Some(map.next_value()?),
                        "repository" => fields.repository = Some(map.next_value()?),
                        "author" => fields.author = Some(map.next_value()?),
                        "license" => fields.license = Some(map.next_value()?),
                        "licenses" => fields.licenses = Some(map.next_value()?),
                        _ => {
                            let _: serde::de::IgnoredAny = map.next_value()?;
                        }
                    }
                }
                Ok(fields)
            }
        }
        deserializer.deserialize_any(Visitor)
    }
}

enum ManifestProbe {
    Missing,
    Match(ManifestMetadata),
    DifferentPackage {
        name: Option<String>,
        version: Option<String>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
struct ManifestFileCacheKey {
    path: PathBuf,
    #[cfg(unix)]
    dev: u64,
    #[cfg(unix)]
    ino: u64,
    len: u64,
    mtime_nanos: Option<i128>,
    #[cfg(unix)]
    ctime_nanos: i128,
}

fn manifest_file_cache_key(path: &Path) -> Option<ManifestFileCacheKey> {
    let meta = std::fs::metadata(path).ok()?;
    if !meta.is_file() {
        return None;
    }
    let mtime_nanos = meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_nanos() as i128);
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        let ctime_nanos = i128::from(meta.ctime()) * 1_000_000_000 + i128::from(meta.ctime_nsec());
        Some(ManifestFileCacheKey {
            path: path.to_path_buf(),
            dev: meta.dev(),
            ino: meta.ino(),
            len: meta.len(),
            mtime_nanos,
            ctime_nanos,
        })
    }
    #[cfg(not(unix))]
    {
        Some(ManifestFileCacheKey {
            path: path.to_path_buf(),
            len: meta.len(),
            mtime_nanos,
        })
    }
}

type ManifestReadCell = std::sync::OnceLock<Result<Option<ParsedManifestEntry>, String>>;
type ManifestReadCache = dashmap::DashMap<ManifestFileCacheKey, std::sync::Arc<ManifestReadCell>>;

fn read_required_manifest_metadata_cached(
    path: &Path,
    package: &LockedPackage,
    cache: &ManifestReadCache,
) -> Result<ManifestMetadata, LpmError> {
    match read_matching_manifest_metadata_cached(path, package, cache)? {
        ManifestProbe::Match(metadata) => Ok(metadata),
        ManifestProbe::Missing => Err(missing_installed_manifest(package, Some(path))),
        ManifestProbe::DifferentPackage { name, version } => Err(mismatched_installed_manifest(
            package,
            path,
            name.as_deref(),
            version.as_deref(),
        )),
    }
}

fn read_matching_manifest_metadata_cached(
    path: &Path,
    package: &LockedPackage,
    cache: &ManifestReadCache,
) -> Result<ManifestProbe, LpmError> {
    let parsed_storage;
    let parsed = if let Some(key) = manifest_file_cache_key(path) {
        let slot = cache
            .entry(key)
            .or_insert_with(|| std::sync::Arc::new(std::sync::OnceLock::new()))
            .clone();
        parsed_storage = slot
            .get_or_init(|| read_parsed_manifest_entry(path))
            .clone();
        &parsed_storage
    } else {
        parsed_storage = read_parsed_manifest_entry(path);
        &parsed_storage
    };
    match parsed {
        Ok(None) => Ok(ManifestProbe::Missing),
        Ok(Some(entry)) => {
            if entry.name.as_deref() == Some(package.name.as_str())
                && entry.version.as_deref() == Some(package.version.as_str())
            {
                Ok(ManifestProbe::Match(entry.metadata.clone()))
            } else {
                Ok(ManifestProbe::DifferentPackage {
                    name: entry.name.clone(),
                    version: entry.version.clone(),
                })
            }
        }
        Err(message) => Err(LpmError::Store(message.clone())),
    }
}

fn read_parsed_manifest_entry(path: &Path) -> Result<Option<ParsedManifestEntry>, String> {
    let content = match lpm_common::read_text_regular_file_capped_with_metadata(
        path,
        lpm_common::CONFIG_FILE_SIZE_CAP_BYTES,
    ) {
        Ok((content, _)) => content,
        Err(BoundedReadError::NotFound { .. }) => return Ok(None),
        Err(error) => {
            return Err(format!(
                "failed to read installed package manifest: {error}"
            ));
        }
    };
    let fields: RawManifestFields = serde_json::from_str(lpm_common::strip_utf8_bom_str(&content))
        .map_err(|error| {
            format!(
                "failed to parse installed package manifest {}: {error}",
                path.display()
            )
        })?;
    Ok(Some(fields.into_parsed_entry()))
}

pub(crate) fn package_metadata_key(package: &LockedPackage) -> String {
    if let Some(instance_id) = package.instance_id {
        return instance_id.to_string();
    }
    package_artifact_key(package)
}

pub(crate) fn package_artifact_key(package: &LockedPackage) -> String {
    let source = package.source.as_deref().unwrap_or("");
    let integrity = package.integrity.as_deref().unwrap_or("");
    let mut key = String::with_capacity(
        package.name.len() + package.version.len() + source.len() + integrity.len() + 3,
    );
    key.push_str(&package.name);
    key.push('\0');
    key.push_str(&package.version);
    key.push('\0');
    key.push_str(source);
    key.push('\0');
    key.push_str(integrity);
    key
}

fn collect_licenses(value: &Value, out: &mut Vec<String>) {
    match value {
        Value::String(s) if !s.trim().is_empty() => out.push(s.trim().to_string()),
        Value::Object(obj) => {
            if let Some(s) = obj
                .get("type")
                .or_else(|| obj.get("name"))
                .or_else(|| obj.get("url"))
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|s| !s.is_empty())
            {
                out.push(s.to_string());
            }
        }
        Value::Array(items) => {
            for item in items {
                collect_licenses(item, out);
            }
        }
        _ => {}
    }
}

fn extract_urlish(value: &Value) -> Option<String> {
    match value {
        Value::String(s) if !s.is_empty() => Some(s.clone()),
        Value::Object(obj) => obj
            .get("url")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .map(str::to_string),
        _ => None,
    }
}

fn extract_author(value: &Value) -> Option<String> {
    match value {
        Value::String(s) if !s.is_empty() => Some(s.clone()),
        Value::Object(obj) => obj
            .get("name")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .map(str::to_string),
        _ => None,
    }
}

fn node_modules_package_json(project_dir: &Path, name: &str) -> PathBuf {
    project_dir
        .join("node_modules")
        .join(name)
        .join("package.json")
}

fn missing_installed_manifest(package: &LockedPackage, path: Option<&Path>) -> LpmError {
    let location = path.map_or_else(
        || "in this project's linker graph".to_string(),
        |path| format!("at {}", path.display()),
    );
    LpmError::NotFound(format!(
        "installed package manifest for {}@{} was not found {location}. Run `lpm install` to repair this project's dependencies",
        package.name, package.version
    ))
}

fn mismatched_installed_manifest(
    package: &LockedPackage,
    path: &Path,
    actual_name: Option<&str>,
    actual_version: Option<&str>,
) -> LpmError {
    let actual_name = actual_name.unwrap_or("<missing name>");
    let actual_version = actual_version.unwrap_or("<missing version>");
    LpmError::Store(format!(
        "installed package manifest at {} identifies {actual_name}@{actual_version}, expected {}@{}. Run `lpm install` to repair this project's dependencies",
        path.display(),
        package.name,
        package.version
    ))
}

/// Which of `lockfile`'s packages install leaves off the current platform,
/// aligned with `lockfile.packages`: each optional package whose `os`,
/// `cpu` or `libc` excludes this platform, and each optional package
/// reachable only through one. A root dependency keeps a package reachable:
/// the lockfile's exact root resolutions name them, and a lockfile without
/// them falls back to `root_json`, the importer's `package.json`, read only
/// when some package is excluded. Without either, only packages whose own
/// `os`, `cpu` or `libc` excludes this platform count.
pub(crate) fn platform_skipped_package_flags(
    lockfile: &Lockfile,
    root_json: impl FnOnce() -> Option<Value>,
) -> Vec<bool> {
    let blocked = platform_blocked_packages(lockfile);
    if !blocked.contains(&true) {
        return blocked;
    }
    let indexes = graph::PackageIndexes::new(&lockfile.packages);
    let roots = match exact_root_indexes(lockfile, &indexes) {
        Some(roots) => roots,
        None => match root_json() {
            Some(root_json) => graph::selected_roots(&root_json, lockfile, &indexes)
                .into_iter()
                .map(|(_, index, _)| index)
                .collect(),
            None => return blocked,
        },
    };
    platform_skipped_from_blocked(lockfile, &indexes, roots, blocked)
}

/// The rows the lockfile's root resolutions select, when every resolution
/// names an exact instance the lockfile holds.
fn exact_root_indexes(
    lockfile: &Lockfile,
    indexes: &graph::PackageIndexes<'_>,
) -> Option<Vec<usize>> {
    if lockfile.root_resolutions.is_empty() {
        return None;
    }
    lockfile
        .root_resolutions
        .values()
        .map(|resolution| {
            resolution
                .instance_id
                .and_then(|id| indexes.by_instance.get(&id).copied())
        })
        .collect()
}

fn platform_skipped_packages(
    lockfile: &Lockfile,
    indexes: &graph::PackageIndexes<'_>,
    roots: &[(String, usize, graph::PackageScope)],
) -> Vec<bool> {
    let blocked = platform_blocked_packages(lockfile);
    if !blocked.contains(&true) {
        return blocked;
    }
    platform_skipped_from_blocked(
        lockfile,
        indexes,
        roots.iter().map(|(_, index, _)| *index),
        blocked,
    )
}

fn platform_blocked_packages(lockfile: &Lockfile) -> Vec<bool> {
    lockfile
        .packages
        .iter()
        .map(|package| package.optional && !locked_package_matches_current_platform(package))
        .collect()
}

fn platform_skipped_from_blocked(
    lockfile: &Lockfile,
    indexes: &graph::PackageIndexes<'_>,
    roots: impl IntoIterator<Item = usize>,
    blocked: Vec<bool>,
) -> Vec<bool> {
    let packages = &lockfile.packages;
    let adjacency = graph::package_adjacency(packages, indexes);
    let mut candidates = vec![false; packages.len()];
    let mut queue: VecDeque<_> = blocked
        .iter()
        .enumerate()
        .filter_map(|(index, blocked)| blocked.then_some(index))
        .collect();
    while let Some(index) = queue.pop_front() {
        if candidates[index] {
            continue;
        }
        candidates[index] = true;
        queue.extend(
            adjacency[index]
                .iter()
                .copied()
                .filter(|&child| packages[child].optional),
        );
    }
    let mut reachable = vec![false; packages.len()];
    queue.extend(roots);
    queue.extend(
        packages
            .iter()
            .enumerate()
            .filter_map(|(index, package)| (!package.optional).then_some(index)),
    );
    while let Some(index) = queue.pop_front() {
        if blocked[index] || reachable[index] {
            continue;
        }
        reachable[index] = true;
        queue.extend(adjacency[index].iter().copied());
    }
    for (candidate, reachable) in candidates.iter_mut().zip(reachable) {
        *candidate &= !reachable;
    }
    candidates
}

pub(crate) fn installed_lockfile_paths(
    project_dir: &Path,
    lockfile: &Lockfile,
) -> Result<BTreeMap<String, PathBuf>, LpmError> {
    let root_json = read_json_file(&project_dir.join("package.json"))?;
    let indexes = graph::PackageIndexes::new(&lockfile.packages);
    let roots = graph::selected_roots(&root_json, lockfile, &indexes);
    installed_package_paths(project_dir, lockfile, &indexes, &roots)
}

fn installed_package_paths(
    project_dir: &Path,
    lockfile: &Lockfile,
    indexes: &graph::PackageIndexes<'_>,
    roots: &[(String, usize, graph::PackageScope)],
) -> Result<BTreeMap<String, PathBuf>, LpmError> {
    let project_dir = project_dir.canonicalize()?;
    let mut paths = BTreeMap::new();
    let mut pending = VecDeque::new();
    for (local, index, _) in roots {
        if let Some(path) = installed_slot(&project_dir, local)? {
            pending.push_back((*index, path));
        }
    }
    while let Some((index, path)) = pending.pop_front() {
        let package = &lockfile.packages[index];
        let key = package_metadata_key(package);
        if paths.contains_key(&key) {
            continue;
        }
        paths.insert(key, path.clone());
        for (local, target_index) in graph::package_targets(package, indexes) {
            if paths.contains_key(&package_metadata_key(&lockfile.packages[target_index])) {
                continue;
            }
            let mut resolved = None;
            for directory in path.ancestors() {
                if let Some(candidate) = installed_slot(directory, local)? {
                    resolved = Some(candidate);
                    break;
                }
                if directory == project_dir {
                    break;
                }
            }
            if resolved.is_none() && !path.starts_with(&project_dir) {
                resolved = installed_slot(&project_dir, local)?;
            }
            if let Some(path) = resolved {
                pending.push_back((target_index, path));
            }
        }
    }
    Ok(paths)
}

fn installed_slot(directory: &Path, local: &str) -> Result<Option<PathBuf>, LpmError> {
    Lockfile::validate_package_name_and_version(local, "0.0.0")
        .map_err(|error| LpmError::Store(error.to_string()))?;
    let path = directory.join("node_modules").join(local);
    match std::fs::symlink_metadata(&path) {
        Ok(_) => Ok(Some(path.canonicalize()?)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn locked_package_matches_current_platform(package: &LockedPackage) -> bool {
    if package.os.is_empty() && package.cpu.is_empty() && package.libc.is_empty() {
        return true;
    }
    lpm_resolver::is_platform_compatible(&lpm_resolver::PlatformMeta {
        os: package.os.clone(),
        cpu: package.cpu.clone(),
        libc: package.libc.clone(),
    })
}

pub(crate) fn license_expression_from_list(licenses: &[String]) -> String {
    if licenses.is_empty() {
        return "NOASSERTION".to_string();
    }
    if licenses.len() == 1 {
        return licenses[0].clone();
    }
    licenses
        .iter()
        .map(|license| {
            if license.contains(char::is_whitespace) {
                format!("({license})")
            } else {
                license.clone()
            }
        })
        .collect::<Vec<_>>()
        .join(" AND ")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn platform_skipped_test_flags(packages: Vec<LockedPackage>) -> Vec<bool> {
        let lockfile = Lockfile {
            packages,
            ..Lockfile::new()
        };
        platform_skipped_package_flags(&lockfile, || Some(serde_json::json!({})))
    }

    fn instance(n: u8) -> lpm_common::PackageInstanceId {
        lpm_common::PackageInstanceId::parse(&format!("{n:064x}")).unwrap()
    }

    fn wasm_only_parent_of_runtime() -> (LockedPackage, LockedPackage) {
        let mut wasm = locked_package("wasm-only", true);
        wasm.instance_id = Some(instance(1));
        wasm.cpu = vec!["wasm32".to_string()];
        wasm.dependencies = vec!["runtime@1.0.0".to_string()];
        wasm.dependency_targets =
            std::collections::BTreeMap::from([("runtime".to_string(), instance(2))]);
        let mut runtime = locked_package("runtime", true);
        runtime.instance_id = Some(instance(2));
        (wasm, runtime)
    }

    #[test]
    fn platform_skip_keeps_an_exact_root_reachable_without_reading_the_manifest() {
        let (wasm, runtime) = wasm_only_parent_of_runtime();
        let lockfile = Lockfile {
            packages: vec![wasm, runtime],
            root_resolutions: std::collections::BTreeMap::from([(
                "runtime".to_string(),
                lpm_lockfile::LockedRootResolution {
                    instance_id: Some(instance(2)),
                    ..Default::default()
                },
            )]),
            ..Lockfile::new()
        };

        let skipped = platform_skipped_package_flags(&lockfile, || {
            panic!("exact root resolutions need no package.json")
        });

        assert_eq!(skipped, [true, false]);
    }

    #[test]
    fn platform_skip_without_known_roots_exempts_only_packages_that_exclude_this_platform() {
        let (wasm, runtime) = wasm_only_parent_of_runtime();
        let lockfile = Lockfile {
            packages: vec![wasm, runtime],
            ..Lockfile::new()
        };

        let skipped = platform_skipped_package_flags(&lockfile, || None);

        assert_eq!(skipped, [true, false]);
    }

    fn locked_package(name: &str, optional: bool) -> LockedPackage {
        LockedPackage {
            instance_id: None,
            dependency_targets: std::collections::BTreeMap::new(),
            peer_targets: std::collections::BTreeMap::new(),
            name: name.to_string(),
            version: "1.0.0".to_string(),
            optional,
            ..Default::default()
        }
    }

    #[test]
    fn extract_manifest_metadata_collects_legacy_license_shapes() {
        let value = serde_json::json!({
            "license": { "type": "MIT" },
            "licenses": ["Apache-2.0", { "name": "BSD-3-Clause" }],
        });

        let metadata = extract_manifest_metadata(&value);

        assert_eq!(metadata.licenses, vec!["Apache-2.0", "BSD-3-Clause", "MIT"]);
    }

    #[test]
    fn platform_skip_includes_optional_descendants_of_incompatible_package() {
        let mut platform_package = locked_package("platform-package", true);
        platform_package.cpu = vec!["wasm32".to_string()];
        platform_package.dependencies = vec!["optional-runtime@1.0.0".to_string()];
        let runtime = locked_package("optional-runtime", true);

        let skipped = platform_skipped_test_flags(vec![platform_package, runtime]);

        assert_eq!(skipped, [true, true]);
    }

    #[test]
    fn platform_skip_preserves_descendant_with_required_reachability() {
        let mut platform_package = locked_package("platform-package", true);
        platform_package.cpu = vec!["wasm32".to_string()];
        platform_package.dependencies = vec!["shared-runtime@1.0.0".to_string()];
        let runtime = locked_package("shared-runtime", false);

        let skipped = platform_skipped_test_flags(vec![platform_package, runtime]);

        assert_eq!(skipped, [true, false]);
    }

    #[test]
    fn read_parsed_manifest_entry_accepts_duplicate_keys_last_wins_and_rejects_nbsp() {
        let dir = tempfile::tempdir().unwrap();
        let manifest = dir.path().join("package.json");
        std::fs::write(
            &manifest,
            r#"{"name":"dup","version":"1.0.0","license":"MIT","license":"ISC"}"#,
        )
        .unwrap();
        let entry = read_parsed_manifest_entry(&manifest)
            .unwrap()
            .expect("manifest entry present");
        assert_eq!(entry.name.as_deref(), Some("dup"));
        assert_eq!(entry.metadata.licenses, vec!["ISC"]);

        std::fs::write(
            &manifest,
            "\u{00A0}{\"name\":\"dup\",\"version\":\"1.0.0\"}",
        )
        .unwrap();
        assert!(read_parsed_manifest_entry(&manifest).is_err());

        std::fs::write(&manifest, "[]").unwrap();
        let non_object = read_parsed_manifest_entry(&manifest)
            .unwrap()
            .expect("valid non-object JSON");
        assert!(non_object.name.is_none());
    }
}
