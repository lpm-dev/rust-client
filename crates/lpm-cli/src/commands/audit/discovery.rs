//! Universal package discovery for audit.
//!
//! Discovers packages from any supported lockfile format or by walking
//! `node_modules/` as a fallback. Reuses parsers from `lpm-migrate`.
//!
//! Priority: `lpm.lock` → `package-lock.json` → `pnpm-lock.yaml`
//!           → `yarn.lock` → `node_modules/` walk (degraded mode).

#[cfg(test)]
use std::cell::Cell;
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use lpm_common::LpmError;
use sha2::{Digest as _, Sha256};

/// How a discovered package can be scanned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanMode {
    /// Source is present on disk, can be behaviorally analyzed.
    FullLocal,
    /// Package can be queried in OSV but source is unavailable (e.g., Yarn PnP).
    OsvOnly,
    /// @lpm.dev package with registry metadata, source in LPM store.
    RegistryAndStore,
    /// Lockfile says it exists, but source is not present on disk.
    LocalMissing,
    /// An optional or dev package missing from the path `package-lock.json`
    /// records for it after an install: npm leaves such packages out for
    /// another platform or under `--omit`, so there is no source to scan.
    NotInstalled,
}

/// A package discovered during the inventory phase.
#[derive(Debug, Clone)]
#[allow(dead_code)] // is_dev and is_optional used by --fail-on policy
pub struct DiscoveredPackage {
    /// Package name (e.g., "react", "@scope/name", "@lpm.dev/owner.pkg").
    pub name: String,
    /// Exact resolved version.
    pub version: String,
    /// Exact LPM graph instance, when the lockfile provides one.
    pub instance_id: Option<lpm_common::PackageInstanceId>,
    /// Path relative to project root (e.g., "node_modules/react").
    /// For LPM store packages this is the lockfile key.
    pub path: String,
    /// SRI integrity hash from the lockfile (e.g., "sha512-...").
    pub integrity: Option<String>,
    /// Patch-file digest from `lpm.lock`, when this package's installed bytes are patched.
    pub patch_sha256: Option<String>,
    /// Tarball resolved URL. Used for private registry detection.
    pub resolved_url: Option<String>,
    /// Canonical source directory for `file:` and `link:` dependencies.
    pub local_source_dir: Option<PathBuf>,
    /// How this package can be scanned.
    pub scan_mode: ScanMode,
    /// Whether this is a dev dependency.
    pub is_dev: bool,
    /// Whether this is an optional dependency.
    pub is_optional: bool,
    /// Whether `lpm install` leaves this `lpm.lock` package off the current
    /// platform: an optional package whose `os`, `cpu` or `libc` excludes
    /// it, or one reachable only through such a package. Only a row with an
    /// instance id qualifies, since only then can discovery resolve its
    /// install path from its parent; when its source is absent, it isn't
    /// installed rather than missing.
    pub platform_skipped: bool,
    /// Whether the importer's install tree holds this `lpm.lock` instance,
    /// when discovery works it out. `None` where it isn't asked or has
    /// nothing to go on: rows without an instance id, a lockfile without
    /// root instances, and other lockfiles, whose scan mode says what is on
    /// disk.
    pub installed: Option<Installation>,
    /// Direct dependencies: (name, exact_version).
    /// Extracted from lockfile dependency edges. Used by the query engine
    /// for `>` combinator traversal (e.g., `lpm query :eval > :network`).
    pub dependencies: Vec<(String, String)>,
}

impl DiscoveredPackage {
    pub(crate) fn analysis_key(&self) -> String {
        if let Some(instance_id) = self.instance_id {
            return format!("instance:{instance_id}");
        }
        let mut hasher = Sha256::new();
        hasher.update(b"lpm-audit-package-fallback-v1\0");
        for value in [
            Some(self.path.as_str()),
            Some(self.name.as_str()),
            Some(self.version.as_str()),
            self.integrity.as_deref(),
            self.patch_sha256.as_deref(),
            self.local_source_dir.as_deref().and_then(Path::to_str),
        ] {
            match value {
                Some(value) => {
                    hasher.update((value.len() as u64).to_le_bytes());
                    hasher.update(value.as_bytes());
                }
                None => hasher.update(u64::MAX.to_le_bytes()),
            }
        }
        format!("fallback:{}", hex::encode(hasher.finalize()))
    }
}

/// Which package manager produced the inventory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManagerKind {
    Lpm,
    Npm,
    Pnpm,
    Yarn,
    Bun,
    /// No lockfile — walked `node_modules/` directly.
    FallbackNodeModules,
}

impl std::fmt::Display for ManagerKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ManagerKind::Lpm => write!(f, "lpm"),
            ManagerKind::Npm => write!(f, "npm"),
            ManagerKind::Pnpm => write!(f, "pnpm"),
            ManagerKind::Yarn => write!(f, "yarn"),
            ManagerKind::Bun => write!(f, "bun"),
            ManagerKind::FallbackNodeModules => write!(f, "node_modules"),
        }
    }
}

/// Result of package discovery.
pub struct DiscoveryResult {
    /// Which package manager was detected.
    pub manager: ManagerKind,
    /// Path to the lockfile (if any).
    pub lockfile_path: Option<PathBuf>,
    /// The project root where the lockfile / node_modules was found.
    pub project_root: PathBuf,
    /// Whether this is degraded mode (no lockfile, weaker identity).
    pub is_degraded: bool,
    /// Whether Yarn PnP was detected (packages are OsvOnly).
    pub is_yarn_pnp: bool,
    /// All discovered packages.
    pub packages: Vec<DiscoveredPackage>,
    pub(super) lpm_lockfile: Option<Arc<lpm_lockfile::Lockfile>>,
    pub(super) lpm_lockfile_content: Option<Arc<[u8]>>,
    pub(crate) workspace_root: Option<WorkspaceRootDiscovery>,
}

pub(crate) struct WorkspaceRootDiscovery {
    pub(crate) project_root: PathBuf,
    pub(crate) lockfile: Arc<lpm_lockfile::Lockfile>,
}

/// Whether an importer's install tree holds an `lpm.lock` instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Installation {
    /// A root dependency whose entry holds the release, or what Node loads
    /// from such a package.
    Installed,
    /// Left out of the install, as `--prod` leaves dev dependencies and
    /// `--no-optional` or the platform optional ones.
    Absent,
    /// Behind an entry that couldn't be inspected: it may or may not be
    /// there.
    Unknown,
}

impl DiscoveryResult {
    /// A project with nothing installed yet: no lockfile and no
    /// `node_modules`.
    pub(crate) fn nothing_installed(project_root: PathBuf) -> Self {
        Self {
            manager: ManagerKind::FallbackNodeModules,
            lockfile_path: None,
            project_root,
            is_degraded: true,
            is_yarn_pnp: false,
            packages: Vec::new(),
            lpm_lockfile: None,
            lpm_lockfile_content: None,
            workspace_root: None,
        }
    }

    pub(crate) fn retained_lpm_lockfile(&self) -> Option<&lpm_lockfile::Lockfile> {
        self.lpm_lockfile.as_deref()
    }

    /// Remove the packages `remove` marks, aligned with [`Self::packages`].
    /// The retained `lpm.lock` rows line up with the packages discovered
    /// from them, so the same rows leave it too.
    pub(crate) fn remove_packages(&mut self, remove: &[bool]) {
        debug_assert_eq!(remove.len(), self.packages.len());
        if let Some(lockfile) = self.lpm_lockfile.as_mut() {
            debug_assert_eq!(lockfile.packages.len(), remove.len());
            let mut removed = remove.iter();
            Arc::make_mut(lockfile)
                .packages
                .retain(|_| !removed.next().is_some_and(|&flag| flag));
        }
        let mut removed = remove.iter();
        self.packages
            .retain(|_| !removed.next().is_some_and(|&flag| flag));
    }

    /// Add the workspace root's graph, which a selector anchored at the root
    /// needs. A root row joins only when neither its package nor its
    /// `lpm.lock` row is already present, so the packages and the retained
    /// rows stay aligned for [`Self::remove_packages`] and the query graph.
    pub(crate) fn include_workspace_root_graph(&mut self) {
        let Some(workspace) = self.workspace_root.as_ref() else {
            return;
        };
        let row_key = |package: &lpm_lockfile::LockedPackage| {
            (
                package.instance_id,
                package.name.clone(),
                package.version.clone(),
                package.source.clone(),
            )
        };
        let mut package_keys: HashSet<_> = self
            .packages
            .iter()
            .map(DiscoveredPackage::analysis_key)
            .collect();
        let mut row_keys: HashSet<_> = self
            .lpm_lockfile
            .as_deref()
            .into_iter()
            .flat_map(|lockfile| lockfile.packages.iter().map(row_key))
            .collect();
        let mut added_rows = Vec::new();
        let discovered = lpm_discovered_packages(
            &workspace.project_root,
            &workspace.lockfile,
            Reachability::Skip,
        );
        for (package, row) in discovered.into_iter().zip(&workspace.lockfile.packages) {
            let package_key = package.analysis_key();
            let key = row_key(row);
            if package_keys.contains(&package_key) || row_keys.contains(&key) {
                continue;
            }
            package_keys.insert(package_key);
            row_keys.insert(key);
            self.packages.push(package);
            added_rows.push(row.clone());
        }
        if let Some(lockfile) = self.lpm_lockfile.as_mut() {
            Arc::make_mut(lockfile).packages.extend(added_rows);
        }
    }
}

#[cfg(test)]
thread_local! {
    static FOREIGN_LOCKFILE_SNAPSHOT_READS: Cell<usize> = const { Cell::new(0) };
}

/// Discover all packages in a project.
///
/// Walks up from `start_dir` to find the closest lockfile, then parses it.
/// Falls back to walking `node_modules/` if no lockfile is found.
///
/// Priority:
/// 1. `lpm.lock` always wins (LPM-managed project)
/// 2. For foreign lockfiles, uses `lpm-migrate`'s mtime-based detection
///    (most recently modified lockfile wins when multiple exist)
/// 3. Falls back to walking `node_modules/` (degraded mode)
pub fn discover_packages(start_dir: &Path) -> Result<DiscoveryResult, LpmError> {
    discover_packages_with_options(start_dir, DiscoveryOptions::default())
}

pub(super) fn discover_packages_retaining_lpm_lockfile(
    start_dir: &Path,
) -> Result<DiscoveryResult, LpmError> {
    discover_packages_with_options(
        start_dir,
        DiscoveryOptions {
            retain_lockfile: true,
            retain_lockfile_content: true,
            ..DiscoveryOptions::default()
        },
    )
}

pub(super) fn discover_packages_retaining_parsed_lpm_lockfile(
    start_dir: &Path,
) -> Result<DiscoveryResult, LpmError> {
    discover_packages_with_options(
        start_dir,
        DiscoveryOptions {
            retain_lockfile: true,
            ..DiscoveryOptions::default()
        },
    )
}

/// [`discover_packages_retaining_parsed_lpm_lockfile`] that looks for a
/// lockfile from `start_dir` up to `boundary` and never above it, so a
/// lockfile some unrelated project higher up holds is never read as this
/// one's, and works out which `lpm.lock` instances the install tree holds.
/// A `boundary` that doesn't contain `start_dir` stops the search at
/// `start_dir`.
pub(super) fn discover_packages_within(
    start_dir: &Path,
    boundary: &Path,
) -> Result<DiscoveryResult, LpmError> {
    let boundary = if start_dir.starts_with(boundary) {
        boundary
    } else {
        start_dir
    };
    discover_packages_with_options(
        start_dir,
        DiscoveryOptions {
            boundary: Some(boundary),
            retain_lockfile: true,
            reachability: Reachability::Track,
            ..DiscoveryOptions::default()
        },
    )
}

#[derive(Clone, Copy, Default)]
struct DiscoveryOptions<'a> {
    /// The directory the lockfile search stops at.
    boundary: Option<&'a Path>,
    retain_lockfile: bool,
    retain_lockfile_content: bool,
    reachability: Reachability,
}

/// Whether discovery works out which `lpm.lock` instances the install tree
/// holds, as [`DiscoveredPackage::installed`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum Reachability {
    #[default]
    Skip,
    Track,
}

fn discover_packages_with_options(
    start_dir: &Path,
    options: DiscoveryOptions<'_>,
) -> Result<DiscoveryResult, LpmError> {
    // Walk up to find a lockfile
    let mut current = start_dir.to_path_buf();
    loop {
        // 1. lpm.lock — always highest priority (LPM-managed project)
        if current.join("lpm.lock").exists() {
            return discover_from_lpm_lock(start_dir, &current, options);
        }

        // 2. Foreign lockfiles — use lpm-migrate's mtime-based detection.
        // This correctly handles projects with multiple lockfiles by
        // picking the most recently modified one.
        if let Some(source) = lpm_migrate::detect::detect_lockfile(&current)? {
            return match source.kind {
                lpm_migrate::SourceKind::Npm => discover_from_npm_lockfile(&current, &source.path),
                lpm_migrate::SourceKind::Pnpm => {
                    discover_from_pnpm_lockfile(&current, &source.path)
                }
                lpm_migrate::SourceKind::Yarn => {
                    discover_from_yarn_lockfile(&current, &source.path)
                }
                lpm_migrate::SourceKind::Bun => discover_from_bun_lockfile(&current, &source.path),
            };
        }

        if options.boundary.is_some_and(|boundary| current == boundary) || !current.pop() {
            break;
        }
    }

    // No lockfile found — try node_modules/ fallback from start_dir
    let nm_dir = start_dir.join("node_modules");
    if nm_dir.is_dir() {
        return discover_from_node_modules(start_dir);
    }

    Err(LpmError::NotFound(
        "No lockfile or node_modules found. Nothing to audit.".into(),
    ))
}

// ─── LPM lockfile ───────────────────────────────────────────────────────────

fn discover_from_lpm_lock(
    start_dir: &Path,
    project_root: &Path,
    options: DiscoveryOptions<'_>,
) -> Result<DiscoveryResult, LpmError> {
    let DiscoveryOptions {
        retain_lockfile,
        retain_lockfile_content,
        reachability,
        ..
    } = options;
    let target_root =
        lpm_workspace::find_project_root(start_dir).unwrap_or_else(|| start_dir.to_path_buf());
    let (lockfile_path, lockfile, lpm_lockfile_content, workspace_root) = if retain_lockfile {
        let project = lpm_lockfile::Lockfile::read_for_project(&target_root).map_err(|e| {
            LpmError::Registry(format!(
                "failed to read retained lpm.lock view for {}: {e}",
                target_root.display()
            ))
        })?;
        let workspace_root = project
            .workspace_root
            .map(|workspace| WorkspaceRootDiscovery {
                project_root: workspace.root,
                lockfile: Arc::new(workspace.lockfile),
            });
        (
            project.path,
            project.lockfile,
            retain_lockfile_content.then(|| Arc::<[u8]>::from(project.content.into_bytes())),
            workspace_root,
        )
    } else {
        (
            project_root.join("lpm.lock"),
            crate::commands::install::workspace_lockfile::read_project(&target_root).map_err(
                |e| {
                    LpmError::Registry(format!(
                        "failed to read active lpm.lock view for {}: {e}",
                        target_root.display()
                    ))
                },
            )?,
            None,
            None,
        )
    };

    let packages = lpm_discovered_packages(&target_root, &lockfile, reachability);

    let lpm_lockfile = retain_lockfile.then(|| Arc::new(lockfile));
    Ok(DiscoveryResult {
        manager: ManagerKind::Lpm,
        lockfile_path: Some(lockfile_path),
        project_root: target_root,
        is_degraded: false,
        is_yarn_pnp: false,
        packages,
        lpm_lockfile,
        lpm_lockfile_content,
        workspace_root,
    })
}

fn lpm_discovered_packages(
    project_root: &Path,
    lockfile: &lpm_lockfile::Lockfile,
    reachability: Reachability,
) -> Vec<DiscoveredPackage> {
    let ProjectPackagePaths {
        paths: project_paths,
        unverified,
    } = resolve_lpm_project_paths(project_root, lockfile);
    let by_instance: HashMap<_, _> = lockfile
        .packages
        .iter()
        .filter_map(|package| package.instance_id.map(|id| (id, package)))
        .collect();
    let platform_skipped = lpm_platform_skipped_packages(project_root, lockfile);
    let reach = match reachability {
        Reachability::Track => installed_lpm_instances(project_root, lockfile, &by_instance),
        Reachability::Skip => None,
    };
    lockfile
        .packages
        .iter()
        .zip(platform_skipped)
        .map(|(p, platform_skipped)| {
            // All packages in lpm.lock (both @lpm.dev and npm) are in the
            // LPM store at ~/.lpm/store/v1/<name>@<version>/. The store-backed
            // scan uses store.package_dir(name, version), not the path field.
            let dependencies = installed_dependencies(p, &by_instance);

            let selector = format!("{}@{}", p.name, p.version);
            let patch_sha256 = lockfile
                .patches
                .get(&selector)
                .map(|patch| patch.sha256.clone());
            let local_source_dir = p
                .source
                .as_deref()
                .and_then(|source| lpm_lockfile::Source::parse(source).ok())
                .and_then(|source| match source {
                    lpm_lockfile::Source::Directory { path }
                    | lpm_lockfile::Source::Link { path } => {
                        project_root.join(path).canonicalize().ok()
                    }
                    _ => None,
                });

            DiscoveredPackage {
                name: p.name.clone(),
                version: p.version.clone(),
                instance_id: p.instance_id,
                path: p
                    .instance_id
                    .and_then(|instance_id| project_paths.get(&instance_id).cloned())
                    .unwrap_or_else(|| format!("node_modules/{}", p.name)),
                integrity: p.integrity.clone(),
                patch_sha256,
                resolved_url: None,
                local_source_dir,
                scan_mode: ScanMode::RegistryAndStore,
                is_dev: false,
                is_optional: p.optional,
                platform_skipped: platform_skipped
                    && p.instance_id.is_some_and(|id| !unverified.contains(&id)),
                installed: p.instance_id.and_then(|id| Some(reach.as_ref()?.of(id))),
                dependencies,
            }
        })
        .collect()
}

/// What an importer's install tree holds of its `lpm.lock` instances.
struct Reach {
    installed: HashSet<lpm_common::PackageInstanceId>,
    /// Behind an entry that couldn't be inspected, and never found
    /// installed another way.
    unknown: HashSet<lpm_common::PackageInstanceId>,
}

impl Reach {
    fn of(&self, instance: lpm_common::PackageInstanceId) -> Installation {
        if self.installed.contains(&instance) {
            Installation::Installed
        } else if self.unknown.contains(&instance) {
            Installation::Unknown
        } else {
            Installation::Absent
        }
    }
}

/// The `lpm.lock` instances the importer at `project_root` installed: each
/// root dependency whose entry in its `node_modules` holds that very
/// release, and each dependency Node would load from an installed package,
/// following the lockfile's edges. Entries are followed wherever they lead,
/// since the store's linked layout puts packages outside the project, and
/// a dependency an install left out, as `--prod` does for dev dependencies
/// and `--no-optional` or the platform for optional ones, has no entry
/// there. An entry that can't be inspected leaves its release, and what
/// only it reaches, unknown. `None` when the lockfile records no root
/// instances.
fn installed_lpm_instances(
    project_root: &Path,
    lockfile: &lpm_lockfile::Lockfile,
    by_instance: &HashMap<lpm_common::PackageInstanceId, &lpm_lockfile::LockedPackage>,
) -> Option<Reach> {
    let mut installed = HashSet::with_capacity(by_instance.len());
    let mut unknown = Vec::new();
    let mut to_visit = Vec::with_capacity(lockfile.root_resolutions.len());
    let mut entry = PathBuf::with_capacity(project_root.as_os_str().len() + 64);
    let mut records_roots = false;
    for (local_name, resolution) in &lockfile.root_resolutions {
        let Some(instance_id) = resolution.instance_id else {
            continue;
        };
        let Some(package) = by_instance.get(&instance_id) else {
            continue;
        };
        records_roots = true;
        let Some(segments) = PackageSegments::of(local_name) else {
            continue;
        };
        segments.entry_in(project_root, &mut entry);
        match installed_copy(&entry, package) {
            InstalledCopy::Found(path) => {
                if installed.insert(instance_id) {
                    to_visit.push((instance_id, path));
                }
            }
            InstalledCopy::Other | InstalledCopy::Unloadable => {}
            InstalledCopy::Unknown => unknown.push(instance_id),
        }
    }
    if !records_roots {
        return None;
    }
    let mut lookup = NodeLookup::default();
    while let Some((instance_id, path)) = to_visit.pop() {
        let Some(package) = by_instance.get(&instance_id) else {
            continue;
        };
        lookup.start(&path);
        for (local_name, target_id) in package
            .dependency_targets
            .iter()
            .chain(&package.peer_targets)
        {
            if installed.contains(target_id) {
                continue;
            }
            let Some(target) = by_instance.get(target_id) else {
                continue;
            };
            let Some(segments) = PackageSegments::of(local_name) else {
                continue;
            };
            match lookup.resolve(segments, target) {
                InstalledCopy::Found(found) => {
                    installed.insert(*target_id);
                    to_visit.push((*target_id, found));
                }
                InstalledCopy::Other | InstalledCopy::Unloadable => {}
                InstalledCopy::Unknown => unknown.push(*target_id),
            }
        }
    }
    let mut behind_unknown = HashSet::new();
    while let Some(instance_id) = unknown.pop() {
        if installed.contains(&instance_id) || !behind_unknown.insert(instance_id) {
            continue;
        }
        if let Some(package) = by_instance.get(&instance_id) {
            unknown.extend(
                package
                    .dependency_targets
                    .values()
                    .chain(package.peer_targets.values())
                    .copied(),
            );
        }
    }
    Some(Reach {
        installed,
        unknown: behind_unknown,
    })
}

/// What an install tree holds where a package is looked up.
enum InstalledCopy {
    /// The release itself, at this real path.
    Found(PathBuf),
    /// Something Node loads there in place of the release.
    Other,
    /// Nothing Node loads: no entry, a dangling link, or a folder without a
    /// `package.json` or an `index` file.
    Unloadable,
    /// Something that couldn't be inspected.
    Unknown,
}

/// A package name's path segments: one, or a scope and a name.
#[derive(Clone, Copy)]
struct PackageSegments<'a> {
    first: &'a str,
    second: Option<&'a str>,
}

impl<'a> PackageSegments<'a> {
    /// `None` unless lpm-lockfile accepts `local_name` as a package name,
    /// which keeps each segment a plain path component on every platform.
    fn of(local_name: &'a str) -> Option<Self> {
        if !lpm_lockfile::is_valid_package_name(local_name) {
            return None;
        }
        let (first, second) = match local_name.split_once('/') {
            Some((scope, name)) => (scope, Some(name)),
            None => (local_name, None),
        };
        Some(Self { first, second })
    }

    /// Sets `path` to the package's entry in `directory`'s `node_modules`,
    /// pushing segment by segment so a verbatim Windows path never holds a
    /// `/`.
    fn entry_in(self, directory: &Path, path: &mut PathBuf) {
        path.clear();
        path.push(directory);
        path.push("node_modules");
        path.push(self.first);
        if let Some(second) = self.second {
            path.push(second);
        }
    }
}

/// The fields of a `package.json` that name its release, and those that give
/// CommonJS an entry point, borrowed from the text unless they hold escapes.
/// A repeated field takes its last value and a `null` counts as absent, as
/// the installer reads them.
#[derive(Default)]
struct ManifestIdentity<'a> {
    name: Field<'a>,
    version: Field<'a>,
    main: Field<'a>,
    exports: Field<'a>,
}

#[derive(Default)]
enum Field<'a> {
    #[default]
    Absent,
    Text(std::borrow::Cow<'a, str>),
    /// Present, but not a string.
    Other,
}

impl ManifestIdentity<'_> {
    /// Whether it names `package`'s release. A manifest without a version
    /// names `0.0.0`, as a local package's does when the installer locks it.
    fn names(&self, package: &lpm_lockfile::LockedPackage) -> bool {
        matches!(&self.name, Field::Text(name) if *name == package.name)
            && match &self.version {
                Field::Absent => package.version == "0.0.0",
                Field::Text(version) => *version == package.version,
                Field::Other => false,
            }
    }

    /// Whether CommonJS has an entry point here: `exports`, or a `main` that
    /// isn't empty.
    fn has_entry_point(&self) -> bool {
        !matches!(self.exports, Field::Absent)
            || match &self.main {
                Field::Absent => false,
                Field::Text(main) => !main.is_empty(),
                Field::Other => true,
            }
    }
}

impl<'de> serde::Deserialize<'de> for ManifestIdentity<'de> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Fields;

        impl<'de> serde::de::Visitor<'de> for Fields {
            type Value = ManifestIdentity<'de>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a package.json object")
            }

            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut map: A,
            ) -> Result<Self::Value, A::Error> {
                let mut identity = ManifestIdentity::default();
                while let Some(key) = map.next_key::<IdentityKey>()? {
                    match key {
                        IdentityKey::Name => identity.name = map.next_value()?,
                        IdentityKey::Version => identity.version = map.next_value()?,
                        IdentityKey::Main => identity.main = map.next_value()?,
                        IdentityKey::Exports => identity.exports = map.next_value()?,
                        IdentityKey::Other => {
                            map.next_value::<serde::de::IgnoredAny>()?;
                        }
                    }
                }
                Ok(identity)
            }
        }

        deserializer.deserialize_map(Fields)
    }
}

enum IdentityKey {
    Name,
    Version,
    Main,
    Exports,
    Other,
}

impl<'de> serde::Deserialize<'de> for IdentityKey {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Key;

        impl serde::de::Visitor<'_> for Key {
            type Value = IdentityKey;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a field name")
            }

            fn visit_str<E: serde::de::Error>(self, key: &str) -> Result<IdentityKey, E> {
                Ok(match key {
                    "name" => IdentityKey::Name,
                    "version" => IdentityKey::Version,
                    "main" => IdentityKey::Main,
                    "exports" => IdentityKey::Exports,
                    _ => IdentityKey::Other,
                })
            }
        }

        deserializer.deserialize_identifier(Key)
    }
}

impl<'de> serde::Deserialize<'de> for Field<'de> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Value;

        impl<'de> serde::de::Visitor<'de> for Value {
            type Value = Field<'de>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a JSON value")
            }

            fn visit_borrowed_str<E: serde::de::Error>(
                self,
                text: &'de str,
            ) -> Result<Field<'de>, E> {
                Ok(Field::Text(std::borrow::Cow::Borrowed(text)))
            }

            fn visit_str<E: serde::de::Error>(self, text: &str) -> Result<Field<'de>, E> {
                Ok(Field::Text(std::borrow::Cow::Owned(text.to_owned())))
            }

            fn visit_string<E: serde::de::Error>(self, text: String) -> Result<Field<'de>, E> {
                Ok(Field::Text(std::borrow::Cow::Owned(text)))
            }

            fn visit_unit<E: serde::de::Error>(self) -> Result<Field<'de>, E> {
                Ok(Field::Absent)
            }

            fn visit_bool<E: serde::de::Error>(self, _: bool) -> Result<Field<'de>, E> {
                Ok(Field::Other)
            }

            fn visit_i64<E: serde::de::Error>(self, _: i64) -> Result<Field<'de>, E> {
                Ok(Field::Other)
            }

            fn visit_u64<E: serde::de::Error>(self, _: u64) -> Result<Field<'de>, E> {
                Ok(Field::Other)
            }

            fn visit_f64<E: serde::de::Error>(self, _: f64) -> Result<Field<'de>, E> {
                Ok(Field::Other)
            }

            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> Result<Field<'de>, A::Error> {
                while seq.next_element::<serde::de::IgnoredAny>()?.is_some() {}
                Ok(Field::Other)
            }

            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut map: A,
            ) -> Result<Field<'de>, A::Error> {
                while map
                    .next_entry::<serde::de::IgnoredAny, serde::de::IgnoredAny>()?
                    .is_some()
                {}
                Ok(Field::Other)
            }
        }

        deserializer.deserialize_any(Value)
    }
}

/// What `entry` holds of `package` for a root dependency: found only when
/// it leads to a folder whose `package.json` names `package`'s release.
fn installed_copy(entry: &Path, package: &lpm_lockfile::LockedPackage) -> InstalledCopy {
    match inspect_entry(entry, package) {
        Entry::Release(real) => InstalledCopy::Found(real),
        Entry::File | Entry::OtherPackage => InstalledCopy::Other,
        Entry::Missing | Entry::Bare => InstalledCopy::Unloadable,
        Entry::Unknown => InstalledCopy::Unknown,
    }
}

/// What a package's entry in one `node_modules` folder holds.
enum Entry {
    /// No entry, or a link that leads nowhere.
    Missing,
    /// Something other than a folder, which CommonJS loads as a file and ES
    /// modules look past.
    File,
    /// A folder whose `package.json` names the release, at this real path.
    Release(PathBuf),
    /// A folder Node loads something else from: another release with an
    /// entry point, or an `index` file.
    OtherPackage,
    /// A folder that isn't the release and that CommonJS can't load, having
    /// no entry point and no `index` file, so it looks past it; ES modules
    /// stop at it.
    Bare,
    /// Something that couldn't be inspected.
    Unknown,
}

/// Classifies `entry` against `package`. A `package.json` that isn't valid
/// UTF-8 is read as Node reads it, with replacement characters; one that is
/// a FIFO, a device or a socket can't be read without risking a hang, so
/// what it holds is unknown.
fn inspect_entry(entry: &Path, package: &lpm_lockfile::LockedPackage) -> Entry {
    let real = match entry.canonicalize() {
        Ok(real) => real,
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
            ) =>
        {
            return Entry::Missing;
        }
        Err(_) => return Entry::Unknown,
    };
    match std::fs::metadata(&real) {
        Ok(metadata) if metadata.is_dir() => {}
        Ok(_) => return Entry::File,
        Err(_) => return Entry::Unknown,
    }
    let manifest_path = real.join("package.json");
    match std::fs::metadata(&manifest_path) {
        Ok(metadata) if metadata.is_file() => {}
        Ok(metadata) if metadata.is_dir() => return without_manifest(&real),
        Ok(_) => return Entry::Unknown,
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
            ) =>
        {
            return without_manifest(&real);
        }
        Err(_) => return Entry::Unknown,
    }
    let Ok((manifest, _)) = lpm_common::read_regular_file_capped_with_metadata(
        &manifest_path,
        lpm_common::STATE_FILE_SIZE_CAP_BYTES,
    ) else {
        return Entry::Unknown;
    };
    let text = String::from_utf8_lossy(&manifest);
    match serde_json::from_str::<ManifestIdentity<'_>>(lpm_common::strip_utf8_bom_str(&text)) {
        Ok(identity) if identity.names(package) => Entry::Release(real),
        Ok(identity) if !identity.has_entry_point() => without_manifest(&real),
        _ => Entry::OtherPackage,
    }
}

/// Whether `manifest`, a `package.json`'s bytes, names `package`'s release,
/// read as Node reads it: invalid UTF-8 as replacement characters, a
/// byte-order mark skipped.
fn manifest_names(manifest: &[u8], package: &lpm_lockfile::LockedPackage) -> bool {
    let text = String::from_utf8_lossy(manifest);
    serde_json::from_str::<ManifestIdentity<'_>>(lpm_common::strip_utf8_bom_str(&text))
        .is_ok_and(|identity| identity.names(package))
}

/// What a package folder without an entry point holds for Node: the `index`
/// file CommonJS loads in its place, which isn't the release, or nothing.
fn without_manifest(folder: &Path) -> Entry {
    if ["index.js", "index.json", "index.node"]
        .iter()
        .any(|name| folder.join(name).is_file())
    {
        Entry::OtherPackage
    } else {
        Entry::Bare
    }
}

/// Looks up what Node loads for each dependency of one installed package,
/// reusing its buffers and remembering which `node_modules` folders exist
/// on the way up from the package.
#[derive(Default)]
struct NodeLookup {
    package_path: PathBuf,
    entry: PathBuf,
    scratch: PathBuf,
    /// Whether each folder on the way up has a `node_modules` folder, by
    /// position; `None` until it is needed.
    modules: Vec<Option<bool>>,
}

impl NodeLookup {
    /// Starts the lookups from the package installed at `package_path`.
    fn start(&mut self, package_path: &Path) {
        self.package_path.clear();
        self.package_path.push(package_path);
        self.modules.clear();
    }

    /// What Node loads as the package named `segments` from the package
    /// being looked up from, against `target`'s release. CommonJS takes a
    /// file named for the package, or with a `.js`, `.json` or `.node`
    /// extension, before a folder, and looks past a folder it can't load;
    /// ES modules take the first folder of that name and look past files.
    /// The release counts as found when either loads it, so a copy one of
    /// them runs is never taken for absent, and where it sits even without an
    /// entry point, as a package that only ships skills has none.
    fn resolve(
        &mut self,
        segments: PackageSegments<'_>,
        target: &lpm_lockfile::LockedPackage,
    ) -> InstalledCopy {
        let mut commonjs_open = true;
        let mut es_modules_open = true;
        let mut stopped = false;
        let Self {
            package_path,
            entry,
            scratch,
            modules,
        } = self;
        let mut position = 0;
        for directory in package_path.ancestors() {
            if directory
                .file_name()
                .is_some_and(|name| name == "node_modules")
            {
                continue;
            }
            let level = position;
            position += 1;
            if modules.len() <= level {
                modules.resize(level + 1, None);
            }
            if modules[level].is_none() {
                scratch.clear();
                scratch.push(directory);
                scratch.push("node_modules");
                modules[level] = match std::fs::metadata(&*scratch) {
                    Ok(metadata) => Some(metadata.is_dir()),
                    Err(error)
                        if matches!(
                            error.kind(),
                            std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
                        ) =>
                    {
                        Some(false)
                    }
                    Err(_) => None,
                };
            }
            if modules[level] == Some(false) {
                continue;
            }
            segments.entry_in(directory, entry);
            let found = inspect_entry(entry, target);
            let mut file_beside = || loads_as_file(entry, scratch);
            match found {
                Entry::Unknown => return InstalledCopy::Unknown,
                Entry::Release(real) => {
                    if es_modules_open || !file_beside() {
                        return InstalledCopy::Found(real);
                    }
                    // CommonJS loads the file beside it unless the folder's
                    // `exports` take over, which this walk doesn't read.
                    return InstalledCopy::Unknown;
                }
                Entry::OtherPackage => return InstalledCopy::Other,
                Entry::File => {
                    commonjs_open = false;
                    stopped = true;
                }
                Entry::Bare => {
                    es_modules_open = false;
                    stopped = true;
                    if commonjs_open && file_beside() {
                        commonjs_open = false;
                    }
                }
                Entry::Missing => {
                    if commonjs_open && file_beside() {
                        commonjs_open = false;
                        stopped = true;
                    }
                }
            }
            if !commonjs_open && !es_modules_open {
                return InstalledCopy::Other;
            }
        }
        if stopped {
            InstalledCopy::Other
        } else {
            InstalledCopy::Unloadable
        }
    }
}

/// Whether CommonJS loads a file in place of `entry`: `entry` with a `.js`,
/// `.json` or `.node` extension. `scratch` is reused.
fn loads_as_file(entry: &Path, scratch: &mut PathBuf) -> bool {
    [".js", ".json", ".node"].iter().any(|extension| {
        scratch.clear();
        scratch.push(entry);
        scratch.as_mut_os_string().push(extension);
        scratch.is_file()
    })
}

/// [`crate::commands::manifest_metadata::platform_skipped_package_flags`]
/// for the importer at `project_root`, reading its `package.json` only for
/// a lockfile without exact root resolutions.
fn lpm_platform_skipped_packages(
    project_root: &Path,
    lockfile: &lpm_lockfile::Lockfile,
) -> Vec<bool> {
    crate::commands::manifest_metadata::platform_skipped_package_flags(lockfile, || {
        crate::commands::manifest_metadata::read_json_file(&project_root.join("package.json")).ok()
    })
}

/// The packages `package` installs directly, peers included, each as the
/// lockfile row it resolved to: its canonical name, so an npm alias names
/// its target, and that row's version. A lockfile without exact targets
/// falls back to the edge's own `<local name>@<version>`, with the alias
/// target in place of the local name.
fn installed_dependencies(
    package: &lpm_lockfile::LockedPackage,
    by_instance: &HashMap<lpm_common::PackageInstanceId, &lpm_lockfile::LockedPackage>,
) -> Vec<(String, String)> {
    let target_of = |local: &str, targets: &BTreeMap<String, lpm_common::PackageInstanceId>| {
        targets
            .get(local)
            .and_then(|id| by_instance.get(id))
            .map(|target| (target.name.clone(), target.version.clone()))
    };
    let mut installed: Vec<(String, String)> = package
        .dependencies
        .iter()
        .filter_map(|dep_ref| {
            let at = dep_ref.rfind('@').filter(|&at| at > 0)?;
            let (local, version) = (&dep_ref[..at], &dep_ref[at + 1..]);
            target_of(local, &package.dependency_targets).or_else(|| {
                let name = package
                    .alias_dependencies
                    .iter()
                    .find(|[alias, _]| alias == local)
                    .map_or(local, |[_, target]| target.as_str());
                Some((name.to_string(), version.to_string()))
            })
        })
        .collect();
    installed.extend(package.peer_edges.iter().map(|edge| {
        target_of(&edge.local_name, &package.peer_targets)
            .unwrap_or_else(|| (edge.target_name.clone(), edge.target_version.clone()))
    }));
    installed.sort_unstable();
    installed.dedup();
    installed
}

/// Where the project installs each `lpm.lock` instance, as Node resolves it
/// from the instance's parent.
struct ProjectPackagePaths {
    paths: HashMap<lpm_common::PackageInstanceId, String>,
    /// Instances with something at a path Node would load them from that
    /// discovery couldn't verify as them, so their absence isn't confirmed.
    unverified: HashSet<lpm_common::PackageInstanceId>,
}

fn resolve_lpm_project_paths(
    project_root: &Path,
    lockfile: &lpm_lockfile::Lockfile,
) -> ProjectPackagePaths {
    let mut unverified = HashSet::new();
    let Ok(canonical_root) = project_root.canonicalize() else {
        return ProjectPackagePaths {
            paths: HashMap::new(),
            unverified,
        };
    };
    let packages_by_instance: HashMap<_, _> = lockfile
        .packages
        .iter()
        .filter_map(|package| {
            package
                .instance_id
                .map(|instance_id| (instance_id, package))
        })
        .collect();
    let mut absolute_paths = HashMap::with_capacity(packages_by_instance.len());
    let mut to_visit = VecDeque::new();
    let mut candidate = PathBuf::with_capacity(canonical_root.as_os_str().len() + 64);

    for (local_name, resolution) in &lockfile.root_resolutions {
        let Some(instance_id) = resolution.instance_id else {
            continue;
        };
        let Some(package) = packages_by_instance.get(&instance_id) else {
            continue;
        };
        let Some(segments) = PackageSegments::of(local_name) else {
            continue;
        };
        segments.entry_in(&canonical_root, &mut candidate);
        let path = match project_package_candidate(&candidate, &canonical_root, package) {
            CandidatePath::Matched(path) => path,
            CandidatePath::Absent => continue,
            CandidatePath::Unverified => {
                unverified.insert(instance_id);
                continue;
            }
        };
        if absolute_paths.insert(instance_id, path.clone()).is_none() {
            to_visit.push_back((instance_id, path));
        }
    }

    while let Some((instance_id, package_path)) = to_visit.pop_front() {
        let Some(package) = packages_by_instance.get(&instance_id) else {
            continue;
        };
        for (local_name, target_id) in package
            .dependency_targets
            .iter()
            .chain(&package.peer_targets)
        {
            if absolute_paths.contains_key(target_id) {
                continue;
            }
            let Some(target) = packages_by_instance.get(target_id) else {
                continue;
            };
            let Some(segments) = PackageSegments::of(local_name) else {
                continue;
            };
            let path =
                match resolve_node_modules_target(&package_path, &canonical_root, segments, target)
                {
                    CandidatePath::Matched(path) => path,
                    CandidatePath::Absent => continue,
                    CandidatePath::Unverified => {
                        unverified.insert(*target_id);
                        continue;
                    }
                };
            absolute_paths.insert(*target_id, path.clone());
            to_visit.push_back((*target_id, path));
        }
    }

    let paths = absolute_paths
        .into_iter()
        .filter_map(|(instance_id, path)| {
            let relative = path.strip_prefix(&canonical_root).ok()?;
            Some((instance_id, lockfile_style_path(relative)))
        })
        .collect();
    ProjectPackagePaths { paths, unverified }
}

/// `relative` as lockfiles spell a package path, with `/` between its
/// components on every platform, so a package reads the same whichever way
/// discovery found it.
fn lockfile_style_path(relative: &Path) -> String {
    let mut path = String::with_capacity(relative.as_os_str().len());
    for component in relative.components() {
        if !path.is_empty() {
            path.push('/');
        }
        path.push_str(&component.as_os_str().to_string_lossy());
    }
    path
}

/// What is at a path Node would load a package from.
enum CandidatePath {
    Matched(PathBuf),
    Absent,
    /// Something is there that discovery couldn't verify as the package.
    Unverified,
}

/// The first of the paths Node would load `target` from walking up from
/// `package_path`: a match, or else whether any of them held something.
fn resolve_node_modules_target(
    package_path: &Path,
    project_root: &Path,
    segments: PackageSegments<'_>,
    target: &lpm_lockfile::LockedPackage,
) -> CandidatePath {
    let mut saw_unverified = false;
    let mut candidate = PathBuf::with_capacity(package_path.as_os_str().len() + 64);
    let mut current = Some(package_path);
    while let Some(directory) = current {
        if !directory.starts_with(project_root) {
            break;
        }
        segments.entry_in(directory, &mut candidate);
        match project_package_candidate(&candidate, project_root, target) {
            CandidatePath::Matched(path) => return CandidatePath::Matched(path),
            CandidatePath::Unverified => saw_unverified = true,
            CandidatePath::Absent => {}
        }
        if directory == project_root {
            break;
        }
        current = directory.parent();
    }
    if saw_unverified {
        CandidatePath::Unverified
    } else {
        CandidatePath::Absent
    }
}

fn project_package_candidate(
    candidate: &Path,
    project_root: &Path,
    target: &lpm_lockfile::LockedPackage,
) -> CandidatePath {
    let canonical = match candidate.canonicalize() {
        Ok(canonical) => canonical,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return CandidatePath::Absent;
        }
        Err(_) => return CandidatePath::Unverified,
    };
    let matches = canonical.starts_with(project_root)
        && canonical.is_dir()
        && lpm_common::read_regular_file_capped_with_metadata(
            &canonical.join("package.json"),
            lpm_common::STATE_FILE_SIZE_CAP_BYTES,
        )
        .is_ok_and(|(manifest, _)| manifest_names(&manifest, target));
    if matches {
        CandidatePath::Matched(canonical)
    } else {
        CandidatePath::Unverified
    }
}

// ─── npm (package-lock.json) ────────────────────────────────────────────────

fn discover_from_npm_lockfile(
    project_root: &Path,
    lockfile_path: &Path,
) -> Result<DiscoveryResult, LpmError> {
    let parsed = {
        let snapshot = read_foreign_lockfile_snapshot(lockfile_path)?;
        lpm_migrate::npm::parse_snapshot(&snapshot)?
    };
    let packages = migrated_npm_to_discovered(project_root, parsed.packages)?;

    Ok(DiscoveryResult {
        manager: ManagerKind::Npm,
        lockfile_path: Some(lockfile_path.to_path_buf()),
        project_root: project_root.to_path_buf(),
        is_degraded: false,
        is_yarn_pnp: false,
        packages,
        lpm_lockfile: None,
        lpm_lockfile_content: None,
        workspace_root: None,
    })
}

// ─── pnpm (pnpm-lock.yaml) ─────────────────────────────────────────────────

fn discover_from_pnpm_lockfile(
    project_root: &Path,
    lockfile_path: &Path,
) -> Result<DiscoveryResult, LpmError> {
    let migrated = {
        let snapshot = read_foreign_lockfile_snapshot(lockfile_path)?;
        lpm_migrate::pnpm::parse_str(&snapshot)?
    };
    let installed_paths = installed_pnpm_package_paths(project_root, &migrated)?;
    let packages = migrated_to_discovered_pnpm(project_root, migrated, installed_paths)?;

    Ok(DiscoveryResult {
        manager: ManagerKind::Pnpm,
        lockfile_path: Some(lockfile_path.to_path_buf()),
        project_root: project_root.to_path_buf(),
        is_degraded: false,
        is_yarn_pnp: false,
        packages,
        lpm_lockfile: None,
        lpm_lockfile_content: None,
        workspace_root: None,
    })
}

// ─── yarn (yarn.lock) ───────────────────────────────────────────────────────

fn discover_from_yarn_lockfile(
    project_root: &Path,
    lockfile_path: &Path,
) -> Result<DiscoveryResult, LpmError> {
    // Check for Yarn PnP
    let is_yarn_pnp =
        project_root.join(".pnp.cjs").exists() || project_root.join(".pnp.js").exists();

    let migrated = {
        let snapshot = read_foreign_lockfile_snapshot(lockfile_path)?;
        lpm_migrate::yarn::parse_str(&snapshot)?
    };

    let packages: Vec<DiscoveredPackage> = if is_yarn_pnp {
        // PnP mode — packages are in zip archives, can't scan source
        migrated
            .into_iter()
            .map(|package| {
                let path = format!("node_modules/{}", package.name);
                DiscoveredPackage {
                    name: package.name,
                    version: package.version,
                    instance_id: None,
                    path,
                    integrity: package.integrity,
                    patch_sha256: None,
                    resolved_url: package.resolved,
                    local_source_dir: None,
                    scan_mode: ScanMode::OsvOnly,
                    is_dev: package.is_dev,
                    is_optional: package.is_optional,
                    platform_skipped: false,
                    installed: None,
                    dependencies: package.dependencies,
                }
            })
            .collect()
    } else {
        migrated_to_discovered(project_root, migrated)?
    };

    Ok(DiscoveryResult {
        manager: ManagerKind::Yarn,
        lockfile_path: Some(lockfile_path.to_path_buf()),
        project_root: project_root.to_path_buf(),
        is_degraded: false,
        is_yarn_pnp,
        packages,
        lpm_lockfile: None,
        lpm_lockfile_content: None,
        workspace_root: None,
    })
}

// ─── bun (bun.lockb / bun.lock) ────────────────────────────────────────────

fn discover_from_bun_lockfile(
    project_root: &Path,
    lockfile_path: &Path,
) -> Result<DiscoveryResult, LpmError> {
    let migrated = if lockfile_path
        .extension()
        .is_some_and(|extension| extension == "lock")
    {
        let snapshot = read_foreign_lockfile_snapshot(lockfile_path)?;
        lpm_migrate::bun::parse_json_str(&snapshot)?
    } else {
        lpm_migrate::bun::parse_selected(lockfile_path)?
    };
    let packages = migrated_to_discovered(project_root, migrated)?;

    Ok(DiscoveryResult {
        manager: ManagerKind::Bun,
        lockfile_path: Some(lockfile_path.to_path_buf()),
        project_root: project_root.to_path_buf(),
        is_degraded: false,
        is_yarn_pnp: false,
        packages,
        lpm_lockfile: None,
        lpm_lockfile_content: None,
        workspace_root: None,
    })
}

// ─── node_modules fallback (degraded mode) ──────────────────────────────────

fn discover_from_node_modules(project_root: &Path) -> Result<DiscoveryResult, LpmError> {
    let nm_dir = project_root.join("node_modules");

    let mut entries: Vec<(DiscoveredPackage, Vec<String>, std::path::PathBuf, String)> = Vec::new();
    let mut visited = std::collections::HashSet::new();
    collect_node_modules_entries(project_root, &nm_dir, &mut entries, &mut visited)?;

    let scope_index = NodeModulesScopeIndex::new(project_root, &entries);
    let mut resolved_dependencies = Vec::with_capacity(entries.len());
    for (package_index, (_, dependency_names, _, _)) in entries.iter().enumerate() {
        let mut dependencies = Vec::with_capacity(dependency_names.len());
        for dependency_name in dependency_names {
            if let Some((canonical_name, version)) =
                scope_index.resolve(package_index, dependency_name)
            {
                dependencies.push((canonical_name.to_string(), version.to_string()));
            }
        }
        resolved_dependencies.push(dependencies);
    }
    drop(scope_index);

    let packages = entries
        .into_iter()
        .zip(resolved_dependencies)
        .map(|((mut package, _, _, _), dependencies)| {
            package.dependencies = dependencies;
            package
        })
        .collect();

    Ok(DiscoveryResult {
        manager: ManagerKind::FallbackNodeModules,
        lockfile_path: None,
        project_root: project_root.to_path_buf(),
        is_degraded: true,
        is_yarn_pnp: false,
        packages,
        lpm_lockfile: None,
        lpm_lockfile_content: None,
        workspace_root: None,
    })
}

fn inspect_fallback_directory(path: &Path) -> Result<bool, LpmError> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(fallback_inventory_error(path, error)),
    };
    if lpm_common::is_symlink_or_junction(&metadata) {
        return Err(fallback_inventory_error(
            path,
            "package links require a supported lockfile",
        ));
    }
    Ok(metadata.is_dir())
}

fn fallback_inventory_error(path: &Path, error: impl std::fmt::Display) -> LpmError {
    LpmError::Script(format!(
        "incomplete node_modules inventory at {}: {error}",
        path.display()
    ))
}

fn collect_node_modules_entries(
    project_root: &Path,
    node_modules: &Path,
    entries: &mut Vec<(DiscoveredPackage, Vec<String>, std::path::PathBuf, String)>,
    visited: &mut std::collections::HashSet<std::path::PathBuf>,
) -> Result<(), LpmError> {
    if !inspect_fallback_directory(node_modules)? {
        return Ok(());
    }
    let identity = node_modules
        .canonicalize()
        .map_err(|error| fallback_inventory_error(node_modules, error))?;
    if !visited.insert(identity) {
        return Ok(());
    }
    let dir_entries = std::fs::read_dir(node_modules)
        .map_err(|error| fallback_inventory_error(node_modules, error))?;
    for entry in dir_entries {
        let entry = entry.map_err(|error| fallback_inventory_error(node_modules, error))?;
        let name = entry.file_name().to_string_lossy().to_string();
        if name.starts_with('.') {
            continue;
        }
        if !inspect_fallback_directory(&entry.path())? {
            continue;
        }
        if name.starts_with('@') {
            let scoped_entries = std::fs::read_dir(entry.path())
                .map_err(|error| fallback_inventory_error(&entry.path(), error))?;
            for scoped_entry in scoped_entries {
                let scoped_entry =
                    scoped_entry.map_err(|error| fallback_inventory_error(&entry.path(), error))?;
                if !inspect_fallback_directory(&scoped_entry.path())? {
                    continue;
                }
                let scoped_name = scoped_entry.file_name().to_string_lossy().to_string();
                let full_name = format!("{name}/{scoped_name}");
                collect_node_modules_package(
                    project_root,
                    &scoped_entry.path(),
                    &full_name,
                    entries,
                    visited,
                )?;
            }
        } else {
            collect_node_modules_package(project_root, &entry.path(), &name, entries, visited)?;
        }
    }
    Ok(())
}

fn collect_node_modules_package(
    project_root: &Path,
    package_dir: &Path,
    name: &str,
    entries: &mut Vec<(DiscoveredPackage, Vec<String>, std::path::PathBuf, String)>,
    visited: &mut std::collections::HashSet<std::path::PathBuf>,
) -> Result<(), LpmError> {
    let (package, dependencies) = read_package_from_node_modules(project_root, package_dir, name)?;
    entries.push((
        package,
        dependencies,
        package_dir.to_path_buf(),
        name.to_string(),
    ));
    collect_node_modules_entries(
        project_root,
        &package_dir.join("node_modules"),
        entries,
        visited,
    )
}

struct NodeModulesScopeIndex<'a> {
    parents: Vec<Option<usize>>,
    package_scopes: Vec<usize>,
    visible_versions: HashMap<(usize, &'a str), (&'a str, &'a str)>,
}

impl<'a> NodeModulesScopeIndex<'a> {
    fn new(
        project_root: &'a Path,
        entries: &'a [(DiscoveredPackage, Vec<String>, PathBuf, String)],
    ) -> Self {
        let mut scope_paths = Vec::with_capacity(entries.len() + 1);
        let mut scope_by_path = HashMap::with_capacity(entries.len() + 1);
        scope_paths.push(project_root);
        scope_by_path.insert(project_root, 0usize);

        for (_, _, package_dir, _) in entries {
            let mut scope_path = package_dir.as_path();
            while scope_path.starts_with(project_root) && scope_path != project_root {
                if !scope_by_path.contains_key(scope_path) {
                    let scope_id = scope_paths.len();
                    scope_paths.push(scope_path);
                    scope_by_path.insert(scope_path, scope_id);
                }
                scope_path = node_modules_parent_scope(scope_path).unwrap_or(project_root);
            }
        }

        let mut parents = Vec::with_capacity(scope_paths.len());
        for scope_path in &scope_paths {
            if *scope_path == project_root {
                parents.push(None);
                continue;
            }
            let parent_path = node_modules_parent_scope(scope_path).unwrap_or(project_root);
            parents.push(scope_by_path.get(parent_path).copied().or(Some(0)));
        }

        let mut package_scopes = Vec::with_capacity(entries.len());
        let mut visible_versions = HashMap::with_capacity(entries.len());
        for (package, _, package_dir, installed_name) in entries {
            package_scopes.push(
                scope_by_path
                    .get(package_dir.as_path())
                    .copied()
                    .unwrap_or(0),
            );
            let parent_path = node_modules_parent_scope(package_dir).unwrap_or(project_root);
            let parent_scope = scope_by_path.get(parent_path).copied().unwrap_or(0);
            visible_versions.insert(
                (parent_scope, installed_name.as_str()),
                (package.name.as_str(), package.version.as_str()),
            );
        }

        Self {
            parents,
            package_scopes,
            visible_versions,
        }
    }

    fn resolve(&self, package_index: usize, dependency: &str) -> Option<(&'a str, &'a str)> {
        let mut scope = self.package_scopes.get(package_index).copied();
        while let Some(scope_id) = scope {
            if let Some(identity) = self.visible_versions.get(&(scope_id, dependency)) {
                return Some(*identity);
            }
            scope = self.parents.get(scope_id).copied().flatten();
        }
        None
    }
}

fn node_modules_parent_scope(package_dir: &Path) -> Option<&Path> {
    let parent = package_dir.parent()?;
    if parent
        .file_name()
        .is_some_and(|name| name == "node_modules")
    {
        return parent.parent();
    }
    let node_modules = parent.parent()?;
    if node_modules
        .file_name()
        .is_some_and(|name| name == "node_modules")
    {
        return node_modules.parent();
    }
    None
}

fn read_package_from_node_modules(
    project_root: &Path,
    pkg_dir: &Path,
    name: &str,
) -> Result<(DiscoveredPackage, Vec<String>), LpmError> {
    let pkg_json_path = pkg_dir.join("package.json");
    let content = lpm_common::read_text_file_capped_nofollow(
        &pkg_json_path,
        lpm_common::CONFIG_FILE_SIZE_CAP_BYTES,
    )
    .map_err(|error| fallback_inventory_error(&pkg_json_path, error))?;
    let json: serde_json::Value = serde_json::from_str(lpm_common::strip_utf8_bom_str(&content))
        .map_err(|error| fallback_inventory_error(&pkg_json_path, error))?;
    let version = json
        .get("version")
        .and_then(serde_json::Value::as_str)
        .filter(|version| !version.is_empty())
        .ok_or_else(|| fallback_inventory_error(&pkg_json_path, "missing string package version"))?
        .to_string();
    let canonical_name = json
        .get("name")
        .and_then(|value| value.as_str())
        .unwrap_or(name)
        .to_string();

    let rel_path = pkg_dir
        .strip_prefix(project_root)
        .map_err(|error| fallback_inventory_error(pkg_dir, error))?;
    let path = lockfile_style_path(rel_path);

    let mut dep_names = Vec::new();
    if let Some(deps) = json.get("dependencies").and_then(|d| d.as_object()) {
        for dep_name in deps.keys() {
            dep_names.push(dep_name.clone());
        }
    }
    if let Some(opt_deps) = json.get("optionalDependencies").and_then(|d| d.as_object()) {
        for dep_name in opt_deps.keys() {
            dep_names.push(dep_name.clone());
        }
    }
    dep_names.sort_unstable();
    dep_names.dedup();

    Ok((
        DiscoveredPackage {
            name: canonical_name,
            version,
            instance_id: None,
            path,
            integrity: None,
            patch_sha256: None,
            resolved_url: None,
            local_source_dir: None,
            scan_mode: ScanMode::FullLocal,
            is_dev: false,      // Can't determine without lockfile
            is_optional: false, // Can't determine without lockfile
            platform_skipped: false,
            installed: None,
            dependencies: Vec::new(), // Resolved in second pass
        },
        dep_names,
    ))
}

// ─── Shared conversion ─────────────────────────────────────────────────────

fn read_foreign_lockfile_snapshot(path: &Path) -> Result<String, LpmError> {
    #[cfg(test)]
    FOREIGN_LOCKFILE_SNAPSHOT_READS.set(FOREIGN_LOCKFILE_SNAPSHOT_READS.get() + 1);
    lpm_migrate::read_lockfile_snapshot(path)
}

fn migrated_to_discovered(
    project_root: &Path,
    migrated: Vec<lpm_migrate::MigratedPackage>,
) -> Result<Vec<DiscoveredPackage>, LpmError> {
    migrated_to_discovered_with(project_root, migrated, |package| {
        Ok(SelectedPackagePath::Probe(format!(
            "node_modules/{}",
            package.name
        )))
    })
}

fn migrated_npm_to_discovered(
    project_root: &Path,
    migrated: Vec<lpm_migrate::MigratedPackage>,
) -> Result<Vec<DiscoveredPackage>, LpmError> {
    let installed = npm_installed_paths(project_root);
    migrated_to_discovered_with(project_root, migrated, |package| {
        let path = package.lockfile_key.clone().ok_or_else(|| {
            LpmError::Script(format!(
                "package-lock.json did not retain the exact package path for {}@{}",
                package.name, package.version
            ))
        })?;
        let left_out = installed
            .as_ref()
            .is_some_and(|installed| !installed.contains(&path));
        Ok(if left_out {
            SelectedPackagePath::Recorded(path)
        } else {
            SelectedPackagePath::Probe(path)
        })
    })
}

/// The package paths npm recorded installing in `node_modules/.package-lock.json`,
/// or `None` without that record (no install, or npm before version 7), when an
/// absent package can't be shown to have been left out.
fn npm_installed_paths(project_root: &Path) -> Option<HashSet<String>> {
    let record =
        lpm_migrate::read_lockfile_snapshot(&project_root.join("node_modules/.package-lock.json"))
            .ok()?;
    let record: serde_json::Value = serde_json::from_str(&record).ok()?;
    Some(
        record
            .get("packages")?
            .as_object()?
            .keys()
            .cloned()
            .collect(),
    )
}

enum SelectedPackagePath {
    /// The path the lockfile records the package installed at.
    Recorded(String),
    /// A path to check whose absence doesn't show the package wasn't
    /// installed: a root path for a manager that records none, or an
    /// instance found by searching.
    Probe(String),
    /// No installed instance matches the lockfile, which can't tell an
    /// absent package from one installed under another name or version.
    Missing(String),
}

fn migrated_to_discovered_with<F>(
    project_root: &Path,
    migrated: Vec<lpm_migrate::MigratedPackage>,
    mut select_path: F,
) -> Result<Vec<DiscoveredPackage>, LpmError>
where
    F: FnMut(&lpm_migrate::MigratedPackage) -> Result<SelectedPackagePath, LpmError>,
{
    let canonical_project_root = project_root.canonicalize().map_err(LpmError::Io)?;
    let mut packages = Vec::with_capacity(migrated.len());

    for package in migrated {
        let selected_path = select_path(&package)?;
        let lpm_migrate::MigratedPackage {
            lockfile_key: _,
            name,
            version,
            resolved,
            integrity,
            dependencies,
            is_optional,
            is_dev,
            published_as: _,
            fetched_from: _,
        } = package;
        let (path, scan_mode) = match selected_path {
            SelectedPackagePath::Recorded(path) => {
                let presence = package_presence(project_root, &canonical_project_root, &path)?;
                (path, presence.scan_mode(is_optional || is_dev))
            }
            SelectedPackagePath::Probe(path) => {
                let presence = package_presence(project_root, &canonical_project_root, &path)?;
                (path, presence.scan_mode(false))
            }
            SelectedPackagePath::Missing(path) => (path, ScanMode::LocalMissing),
        };

        packages.push(DiscoveredPackage {
            name,
            version,
            instance_id: None,
            path,
            integrity,
            patch_sha256: None,
            resolved_url: resolved,
            local_source_dir: None,
            scan_mode,
            is_dev,
            is_optional,
            platform_skipped: false,
            installed: None,
            dependencies,
        });
    }

    Ok(packages)
}

struct InstalledPnpmPackagePaths {
    virtual_store_present: bool,
    paths_by_lockfile_key: HashMap<String, String>,
}

fn migrated_to_discovered_pnpm(
    project_root: &Path,
    migrated: Vec<lpm_migrate::MigratedPackage>,
    installed: InstalledPnpmPackagePaths,
) -> Result<Vec<DiscoveredPackage>, LpmError> {
    migrated_to_discovered_with(project_root, migrated, |package| {
        if !installed.virtual_store_present {
            return Ok(SelectedPackagePath::Probe(format!(
                "node_modules/{}",
                package.name
            )));
        }
        let key = package.lockfile_key.as_deref().ok_or_else(|| {
            LpmError::Script(format!(
                "pnpm lockfile did not retain the package instance key for {}@{}",
                package.name, package.version
            ))
        })?;
        if let Some(path) = installed.paths_by_lockfile_key.get(key) {
            return Ok(SelectedPackagePath::Probe(path.clone()));
        }
        let directory = lpm_migrate::pnpm::virtual_store_directory_name(key)?;
        Ok(SelectedPackagePath::Missing(format!(
            "node_modules/.pnpm/{directory}/node_modules/{}",
            package.name
        )))
    })
}

#[derive(Clone, Copy)]
enum PackagePresence {
    Directory,
    Absent,
    /// Something other than a directory is at the package's path. Node can
    /// still load a file there, so it isn't an uninstalled package.
    NotDirectory,
}

impl PackagePresence {
    /// `may_be_left_out` holds for a package the manager may leave out, at
    /// a path the lockfile records, so its absence means it isn't installed.
    fn scan_mode(self, may_be_left_out: bool) -> ScanMode {
        match self {
            Self::Directory => ScanMode::FullLocal,
            Self::Absent if may_be_left_out => ScanMode::NotInstalled,
            Self::Absent | Self::NotDirectory => ScanMode::LocalMissing,
        }
    }
}

fn package_presence(
    project_root: &Path,
    canonical_project_root: &Path,
    relative_path: &str,
) -> Result<PackagePresence, LpmError> {
    let relative = Path::new(relative_path);
    if relative_path.contains('\\')
        || relative.is_absolute()
        || relative
            .components()
            .any(|component| !matches!(component, std::path::Component::Normal(_)))
    {
        return Err(LpmError::Script(format!(
            "lockfile contains an unsafe package path: {relative_path}"
        )));
    }

    let absolute = project_root.join(relative);
    match std::fs::metadata(&absolute) {
        Ok(metadata) if metadata.is_dir() => {
            let canonical = absolute.canonicalize().map_err(LpmError::Io)?;
            if !canonical.starts_with(canonical_project_root) {
                return Err(LpmError::Script(format!(
                    "lockfile package path resolves outside the project: {relative_path}"
                )));
            }
            Ok(PackagePresence::Directory)
        }
        Ok(_) => Ok(PackagePresence::NotDirectory),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            validate_nearest_existing_ancestor(&absolute, canonical_project_root, relative_path)?;
            Ok(PackagePresence::Absent)
        }
        Err(error) => Err(LpmError::Io(error)),
    }
}

fn validate_nearest_existing_ancestor(
    absolute: &Path,
    canonical_project_root: &Path,
    relative_path: &str,
) -> Result<(), LpmError> {
    let mut probe = absolute;
    loop {
        match probe.canonicalize() {
            Ok(canonical) => {
                if canonical.starts_with(canonical_project_root) {
                    return Ok(());
                }
                return Err(LpmError::Script(format!(
                    "lockfile package path resolves outside the project: {relative_path}"
                )));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                probe = probe.parent().ok_or_else(|| {
                    LpmError::Script(format!(
                        "lockfile package path has no project ancestor: {relative_path}"
                    ))
                })?;
            }
            Err(error) => return Err(LpmError::Io(error)),
        }
    }
}

fn installed_pnpm_package_paths(
    project_root: &Path,
    packages: &[lpm_migrate::MigratedPackage],
) -> Result<InstalledPnpmPackagePaths, LpmError> {
    use cap_fs_ext::DirExt as _;

    let canonical_root = project_root.canonicalize().map_err(LpmError::Io)?;
    let root = cap_std::fs::Dir::open_ambient_dir(&canonical_root, cap_std::ambient_authority())
        .map_err(LpmError::Io)?;
    let node_modules = match root.open_dir_nofollow("node_modules") {
        Ok(directory) => directory,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(InstalledPnpmPackagePaths {
                virtual_store_present: false,
                paths_by_lockfile_key: HashMap::new(),
            });
        }
        Err(error) => return Err(LpmError::Io(error)),
    };
    let virtual_store = match node_modules.open_dir_nofollow(".pnpm") {
        Ok(directory) => directory,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(InstalledPnpmPackagePaths {
                virtual_store_present: false,
                paths_by_lockfile_key: HashMap::new(),
            });
        }
        Err(error) => {
            return Err(LpmError::Script(format!(
                "pnpm virtual store is linked, invalid, or unreadable: {error}"
            )));
        }
    };

    let mut paths = HashMap::with_capacity(packages.len());
    for package in packages {
        let Some(key) = package.lockfile_key.as_deref() else {
            continue;
        };
        let store_directory = lpm_migrate::pnpm::virtual_store_directory_name(key)?;
        let instance = match virtual_store.open_dir_nofollow(&store_directory) {
            Ok(directory) => directory,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(LpmError::Script(format!(
                    "failed to open pnpm package instance {store_directory}: {error}"
                )));
            }
        };
        let package_root = match open_pnpm_package_directory(&instance, &package.name) {
            Ok(directory) => directory,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(LpmError::Io(error)),
        };
        if !pnpm_manifest_matches(&package_root, &package.name, &package.version)? {
            continue;
        }
        paths.insert(
            key.to_string(),
            format!(
                "node_modules/.pnpm/{store_directory}/node_modules/{}",
                package.name
            ),
        );
    }
    Ok(InstalledPnpmPackagePaths {
        virtual_store_present: true,
        paths_by_lockfile_key: paths,
    })
}

fn open_pnpm_package_directory(
    instance: &cap_std::fs::Dir,
    package_name: &str,
) -> std::io::Result<cap_std::fs::Dir> {
    use cap_fs_ext::DirExt as _;

    let mut directory = instance.open_dir_nofollow("node_modules")?;
    for component in Path::new(package_name).components() {
        let std::path::Component::Normal(name) = component else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "pnpm package name contains an unsafe path component",
            ));
        };
        directory = directory.open_dir_nofollow(name)?;
    }
    Ok(directory)
}

fn pnpm_manifest_matches(
    package_dir: &cap_std::fs::Dir,
    expected_name: &str,
    expected_version: &str,
) -> Result<bool, LpmError> {
    use cap_fs_ext::{FollowSymlinks, OpenOptionsFollowExt as _, OpenOptionsSyncExt as _};

    let mut options = cap_std::fs::OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No).nonblock(true);
    let file = match package_dir.open_with("package.json", &options) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(LpmError::Io(error)),
    };
    let metadata = file.metadata().map_err(LpmError::Io)?;
    if !metadata.is_file() || metadata.is_symlink() {
        return Ok(false);
    }
    let content = lpm_common::read_text_file_capped_from_open_file_with_known_size(
        file.into_std(),
        Path::new("package.json"),
        lpm_common::CONFIG_FILE_SIZE_CAP_BYTES,
        metadata.len(),
    )
    .map_err(|error| {
        LpmError::Script(format!(
            "failed to read installed pnpm package metadata: {error}"
        ))
    })?;
    let manifest: serde_json::Value = serde_json::from_str(&content).map_err(|error| {
        LpmError::Script(format!("invalid installed pnpm package metadata: {error}"))
    })?;
    Ok(
        manifest.get("name").and_then(serde_json::Value::as_str) == Some(expected_name)
            && manifest.get("version").and_then(serde_json::Value::as_str)
                == Some(expected_version),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn instance(n: u8) -> lpm_common::PackageInstanceId {
        lpm_common::PackageInstanceId::parse(&format!("{n:064x}")).unwrap()
    }

    fn locked_at(id: u8, name: &str, version: &str) -> lpm_lockfile::LockedPackage {
        lpm_lockfile::LockedPackage {
            name: name.to_string(),
            version: version.to_string(),
            instance_id: Some(instance(id)),
            ..Default::default()
        }
    }

    #[test]
    fn lpm_discovery_flags_the_packages_install_skips_on_this_platform() {
        let project = tempfile::tempdir().unwrap();
        fs::write(
            project.path().join("package.json"),
            r#"{"name":"app","dependencies":{"host":"1.0.0"}}"#,
        )
        .unwrap();
        let mut host = locked_at(1, "host", "1.0.0");
        host.dependencies = vec!["wasm-only@1.0.0".into()];
        host.dependency_targets = BTreeMap::from([("wasm-only".to_string(), instance(2))]);
        let mut wasm_only = locked_at(2, "wasm-only", "1.0.0");
        wasm_only.optional = true;
        wasm_only.cpu = vec!["wasm32".into()];
        let mut legacy_wasm_only = wasm_only.clone();
        legacy_wasm_only.name = "legacy-wasm-only".into();
        legacy_wasm_only.instance_id = None;
        let lockfile = lpm_lockfile::Lockfile {
            packages: vec![host, wasm_only, legacy_wasm_only],
            ..lpm_lockfile::Lockfile::new()
        };

        let packages = lpm_discovered_packages(project.path(), &lockfile, Reachability::Skip);

        assert_eq!(
            packages
                .iter()
                .map(|package| (package.platform_skipped, package.is_optional))
                .collect::<Vec<_>>(),
            [(false, false), (true, true), (false, true)],
            "a row without an instance id has no resolved install path to confirm its absence"
        );
    }

    fn write_package(directory: &Path, name: &str, version: &str) {
        fs::create_dir_all(directory).unwrap();
        fs::write(
            directory.join("package.json"),
            serde_json::json!({ "name": name, "version": version }).to_string(),
        )
        .unwrap();
    }

    #[test]
    fn only_what_node_would_load_from_an_installed_root_dependency_is_installed() {
        let project = tempfile::tempdir().unwrap();
        let store = tempfile::tempdir().unwrap();
        let siblings = store.path().join("links/host@1.0.0/node_modules");
        write_package(&siblings.join("host"), "host", "1.0.0");
        write_package(&siblings.join("tool"), "tool", "1.0.0");
        let node_modules = project.path().join("node_modules");
        fs::create_dir_all(&node_modules).unwrap();
        lpm_common::create_dir_symlink_or_junction(
            &siblings.join("host"),
            &node_modules.join("host"),
        )
        .unwrap();
        write_package(&node_modules.join("wrong"), "wrong", "2.0.0");
        fs::write(node_modules.join("stray"), "not a package").unwrap();
        fs::create_dir_all(node_modules.join("marked")).unwrap();
        fs::write(
            node_modules.join("marked/package.json"),
            "\u{feff}{\"name\":\"marked\",\"version\":\"1.0.0\"}",
        )
        .unwrap();
        fs::create_dir_all(node_modules.join("local")).unwrap();
        fs::write(
            node_modules.join("local/package.json"),
            r#"{"name":"local"}"#,
        )
        .unwrap();
        let mut host = locked_at(1, "host", "1.0.0");
        host.dependency_targets = BTreeMap::from([
            ("tool".to_string(), instance(2)),
            ("optional-only".to_string(), instance(3)),
        ]);
        let mut wrong = locked_at(4, "wrong", "1.0.0");
        wrong.dependency_targets = BTreeMap::from([("tool".to_string(), instance(2))]);
        let mut dev_only = locked_at(6, "dev-only", "1.0.0");
        dev_only.dependency_targets = BTreeMap::from([("dev-helper".to_string(), instance(7))]);
        let root = |id| lpm_lockfile::LockedRootResolution {
            instance_id: Some(instance(id)),
            ..Default::default()
        };
        let lockfile = lpm_lockfile::Lockfile {
            packages: vec![
                host,
                locked_at(2, "tool", "1.0.0"),
                locked_at(3, "optional-only", "1.0.0"),
                wrong,
                locked_at(5, "stray", "1.0.0"),
                dev_only,
                locked_at(7, "dev-helper", "1.0.0"),
                locked_at(8, "marked", "1.0.0"),
                locked_at(9, "local", "0.0.0"),
            ],
            root_resolutions: BTreeMap::from([
                ("host".to_string(), root(1)),
                ("wrong".to_string(), root(4)),
                ("stray".to_string(), root(5)),
                ("dev-only".to_string(), root(6)),
                ("marked".to_string(), root(8)),
                ("local".to_string(), root(9)),
            ]),
            ..lpm_lockfile::Lockfile::new()
        };

        let packages = lpm_discovered_packages(project.path(), &lockfile, Reachability::Track);

        assert_eq!(
            packages
                .iter()
                .map(|package| (package.name.as_str(), package.installed))
                .collect::<Vec<_>>(),
            [
                ("host", Some(Installation::Installed)),
                ("tool", Some(Installation::Installed)),
                ("optional-only", Some(Installation::Absent)),
                ("wrong", Some(Installation::Absent)),
                ("stray", Some(Installation::Absent)),
                ("dev-only", Some(Installation::Absent)),
                ("dev-helper", Some(Installation::Absent)),
                ("marked", Some(Installation::Installed)),
                ("local", Some(Installation::Installed)),
            ]
        );
    }

    /// A project whose `node_modules/host` links into a store folder of
    /// siblings, as LPM's linked layout installs `host@1.0.0`.
    struct LinkedLayout {
        project: tempfile::TempDir,
        store: tempfile::TempDir,
    }

    impl LinkedLayout {
        fn new() -> Self {
            let layout = Self {
                project: tempfile::tempdir().unwrap(),
                store: tempfile::tempdir().unwrap(),
            };
            write_package(&layout.siblings().join("host"), "host", "1.0.0");
            let node_modules = layout.project.path().join("node_modules");
            fs::create_dir_all(&node_modules).unwrap();
            lpm_common::create_dir_symlink_or_junction(
                &layout.siblings().join("host"),
                &node_modules.join("host"),
            )
            .unwrap();
            layout
        }

        fn siblings(&self) -> PathBuf {
            self.store.path().join("links/host@1.0.0/node_modules")
        }

        /// Whether each package of a lockfile whose only root is `host`
        /// (instance 1), depending on `dependencies` and peering `peers` by
        /// local name and instance, is installed; `others` are the other
        /// packages, in order after `host`.
        fn installed(
            &self,
            dependencies: &[(&str, u8)],
            peers: &[(&str, u8)],
            others: Vec<lpm_lockfile::LockedPackage>,
        ) -> Vec<(String, Option<Installation>)> {
            let edges = |edges: &[(&str, u8)]| {
                edges
                    .iter()
                    .map(|(name, id)| ((*name).to_string(), instance(*id)))
                    .collect()
            };
            let mut host = locked_at(1, "host", "1.0.0");
            host.dependency_targets = edges(dependencies);
            host.peer_targets = edges(peers);
            let mut packages = vec![host];
            packages.extend(others);
            let lockfile = lpm_lockfile::Lockfile {
                packages,
                root_resolutions: BTreeMap::from([(
                    "host".to_string(),
                    lpm_lockfile::LockedRootResolution {
                        instance_id: Some(instance(1)),
                        ..Default::default()
                    },
                )]),
                ..lpm_lockfile::Lockfile::new()
            };
            lpm_discovered_packages(self.project.path(), &lockfile, Reachability::Track)
                .into_iter()
                .map(|package| (package.name, package.installed))
                .collect()
        }
    }

    fn installed_as(entries: &[(&str, Installation)]) -> Vec<(String, Option<Installation>)> {
        entries
            .iter()
            .map(|(name, installation)| ((*name).to_string(), Some(*installation)))
            .collect()
    }

    #[test]
    fn the_walk_follows_scoped_names_and_peer_edges() {
        let layout = LinkedLayout::new();
        write_package(&layout.siblings().join("@acme/util"), "@acme/util", "1.0.0");
        write_package(&layout.siblings().join("react"), "react", "18.0.0");

        let installed = layout.installed(
            &[("@acme/util", 2)],
            &[("react", 3)],
            vec![
                locked_at(2, "@acme/util", "1.0.0"),
                locked_at(3, "react", "18.0.0"),
            ],
        );

        assert_eq!(
            installed,
            installed_as(&[
                ("host", Installation::Installed),
                ("@acme/util", Installation::Installed),
                ("react", Installation::Installed),
            ])
        );
    }

    #[test]
    fn the_walk_ends_on_a_dependency_cycle() {
        let layout = LinkedLayout::new();
        write_package(&layout.siblings().join("util"), "util", "1.0.0");
        let mut util = locked_at(2, "util", "1.0.0");
        util.dependency_targets = BTreeMap::from([("host".to_string(), instance(1))]);

        let installed = layout.installed(&[("util", 2)], &[], vec![util]);

        assert_eq!(
            installed,
            installed_as(&[
                ("host", Installation::Installed),
                ("util", Installation::Installed),
            ])
        );
    }

    #[test]
    fn a_nearer_copy_of_another_version_hides_the_locked_one() {
        let layout = LinkedLayout::new();
        write_package(&layout.siblings().join("shadowed"), "shadowed", "1.0.0");
        write_package(
            &layout.siblings().join("host/node_modules/shadowed"),
            "shadowed",
            "2.0.0",
        );
        fs::write(
            layout
                .siblings()
                .join("host/node_modules/shadowed/index.js"),
            "",
        )
        .unwrap();

        let installed = layout.installed(
            &[("shadowed", 2)],
            &[],
            vec![locked_at(2, "shadowed", "1.0.0")],
        );

        assert_eq!(
            installed,
            installed_as(&[
                ("host", Installation::Installed),
                ("shadowed", Installation::Absent),
            ])
        );
    }

    #[test]
    fn the_walk_looks_past_entries_node_cannot_load() {
        let layout = LinkedLayout::new();
        let nearer = layout.siblings().join("host/node_modules");
        fs::create_dir_all(&nearer).unwrap();
        for name in ["dangling", "bare", "manifest-folder"] {
            write_package(&layout.siblings().join(name), name, "1.0.0");
        }
        lpm_common::create_dir_symlink_or_junction(
            &layout.store.path().join("gone"),
            &nearer.join("dangling"),
        )
        .unwrap();
        fs::create_dir_all(nearer.join("bare/lib")).unwrap();
        fs::create_dir_all(nearer.join("manifest-folder/package.json")).unwrap();

        let installed = layout.installed(
            &[("dangling", 2), ("bare", 3), ("manifest-folder", 4)],
            &[],
            vec![
                locked_at(2, "dangling", "1.0.0"),
                locked_at(3, "bare", "1.0.0"),
                locked_at(4, "manifest-folder", "1.0.0"),
            ],
        );

        assert_eq!(
            installed,
            installed_as(&[
                ("host", Installation::Installed),
                ("dangling", Installation::Installed),
                ("bare", Installation::Installed),
                ("manifest-folder", Installation::Installed),
            ])
        );
    }

    #[test]
    fn a_nearer_folder_node_loads_through_its_index_file_stops_the_walk() {
        let layout = LinkedLayout::new();
        let nearer = layout.siblings().join("host/node_modules");
        for (name, index) in [
            ("js", "index.js"),
            ("json", "index.json"),
            ("addon", "index.node"),
        ] {
            write_package(&layout.siblings().join(name), name, "1.0.0");
            fs::create_dir_all(nearer.join(name)).unwrap();
            fs::write(nearer.join(name).join(index), "").unwrap();
        }

        let installed = layout.installed(
            &[("js", 2), ("json", 3), ("addon", 4)],
            &[],
            vec![
                locked_at(2, "js", "1.0.0"),
                locked_at(3, "json", "1.0.0"),
                locked_at(4, "addon", "1.0.0"),
            ],
        );

        assert_eq!(
            installed,
            installed_as(&[
                ("host", Installation::Installed),
                ("js", Installation::Absent),
                ("json", Installation::Absent),
                ("addon", Installation::Absent),
            ])
        );
    }

    #[test]
    fn a_manifest_that_isnt_utf8_still_names_its_release() {
        let layout = LinkedLayout::new();
        let manifest = layout.siblings().join("latin1/package.json");
        fs::create_dir_all(manifest.parent().unwrap()).unwrap();
        fs::write(
            &manifest,
            b"{\"name\":\"latin1\",\"version\":\"1.0.0\",\"author\":\"Ren\xe9\"}",
        )
        .unwrap();

        let installed =
            layout.installed(&[("latin1", 2)], &[], vec![locked_at(2, "latin1", "1.0.0")]);

        assert_eq!(
            installed,
            installed_as(&[
                ("host", Installation::Installed),
                ("latin1", Installation::Installed),
            ])
        );
    }

    #[test]
    fn a_local_name_that_isnt_a_package_name_is_never_joined() {
        let project = tempfile::tempdir().unwrap();
        write_package(&project.path().join("escaper"), "escaper", "1.0.0");
        write_package(&project.path().join("node_modules/host"), "host", "1.0.0");
        let mut host = locked_at(1, "host", "1.0.0");
        host.dependency_targets = BTreeMap::from([("../../escaper".to_string(), instance(2))]);
        let root = |id| lpm_lockfile::LockedRootResolution {
            instance_id: Some(instance(id)),
            ..Default::default()
        };
        let lockfile = lpm_lockfile::Lockfile {
            packages: vec![
                host,
                locked_at(2, "escaper", "1.0.0"),
                locked_at(3, "rooted", "1.0.0"),
            ],
            root_resolutions: BTreeMap::from([
                ("host".to_string(), root(1)),
                ("../rooted".to_string(), root(3)),
            ]),
            ..lpm_lockfile::Lockfile::new()
        };
        write_package(&project.path().join("rooted"), "rooted", "1.0.0");

        let packages = lpm_discovered_packages(project.path(), &lockfile, Reachability::Track);

        assert_eq!(
            packages
                .iter()
                .map(|package| (package.name.as_str(), package.installed))
                .collect::<Vec<_>>(),
            [
                ("host", Some(Installation::Installed)),
                ("escaper", Some(Installation::Absent)),
                ("rooted", Some(Installation::Absent)),
            ]
        );
        assert_eq!(
            packages
                .iter()
                .map(|package| package.path.as_str())
                .collect::<Vec<_>>(),
            [
                "node_modules/host",
                "node_modules/escaper",
                "node_modules/rooted"
            ],
            "a name that isn't a package name never resolves to a folder"
        );
    }

    #[test]
    fn a_release_is_installed_when_commonjs_or_es_modules_load_it_and_absent_when_neither_does() {
        let layout = LinkedLayout::new();
        let nearer = layout.siblings().join("host/node_modules");
        fs::create_dir_all(&nearer).unwrap();
        let names = [
            "file-js",
            "file-json",
            "file-addon",
            "plain-file",
            "dangling-beside",
            "bare-beside",
        ];
        for name in names {
            write_package(&layout.siblings().join(name), name, "1.0.0");
        }
        fs::write(nearer.join("file-js.js"), "").unwrap();
        fs::write(nearer.join("file-json.json"), "").unwrap();
        fs::write(nearer.join("file-addon.node"), "").unwrap();
        fs::write(nearer.join("plain-file"), "").unwrap();
        lpm_common::create_dir_symlink_or_junction(
            &layout.store.path().join("gone"),
            &nearer.join("dangling-beside"),
        )
        .unwrap();
        fs::write(nearer.join("dangling-beside.js"), "").unwrap();
        fs::create_dir_all(nearer.join("bare-beside")).unwrap();
        fs::write(nearer.join("bare-beside.js"), "").unwrap();

        let installed = layout.installed(
            &names
                .iter()
                .zip(2..)
                .map(|(name, id)| (*name, id))
                .collect::<Vec<_>>(),
            &[],
            names
                .iter()
                .zip(2..)
                .map(|(name, id)| locked_at(id, name, "1.0.0"))
                .collect(),
        );

        assert_eq!(
            installed,
            installed_as(&[
                ("host", Installation::Installed),
                ("file-js", Installation::Installed),
                ("file-json", Installation::Installed),
                ("file-addon", Installation::Installed),
                ("plain-file", Installation::Installed),
                ("dangling-beside", Installation::Installed),
                ("bare-beside", Installation::Absent),
            ]),
            "ES modules look past files and dangling links to the release; \
             CommonJS loads the file beside a folder ES modules stop at"
        );
    }

    #[test]
    fn a_nearer_package_commonjs_cant_load_hides_the_release_only_from_es_modules() {
        let layout = LinkedLayout::new();
        let nearer = layout.siblings().join("host/node_modules");
        let names = ["stub", "with-main", "with-exports", "with-index"];
        for name in names {
            write_package(&layout.siblings().join(name), name, "1.0.0");
            fs::create_dir_all(nearer.join(name)).unwrap();
        }
        let manifest = |name: &str, extra: serde_json::Value| {
            let mut manifest = serde_json::json!({ "name": name, "version": "9.9.9" });
            manifest
                .as_object_mut()
                .unwrap()
                .extend(extra.as_object().unwrap().clone());
            fs::write(nearer.join(name).join("package.json"), manifest.to_string()).unwrap();
        };
        manifest("stub", serde_json::json!({ "types": "index.d.ts" }));
        manifest("with-main", serde_json::json!({ "main": "lib.js" }));
        manifest("with-exports", serde_json::json!({ "exports": "./lib.js" }));
        manifest("with-index", serde_json::json!({}));
        fs::write(nearer.join("with-index/index.js"), "").unwrap();

        let installed = layout.installed(
            &names
                .iter()
                .zip(2..)
                .map(|(name, id)| (*name, id))
                .collect::<Vec<_>>(),
            &[],
            names
                .iter()
                .zip(2..)
                .map(|(name, id)| locked_at(id, name, "1.0.0"))
                .collect(),
        );

        assert_eq!(
            installed,
            installed_as(&[
                ("host", Installation::Installed),
                ("stub", Installation::Installed),
                ("with-main", Installation::Absent),
                ("with-exports", Installation::Absent),
                ("with-index", Installation::Absent),
            ]),
            "CommonJS looks past a package folder with no `main`, `exports` or index file"
        );
    }

    #[test]
    fn a_release_only_commonjs_reaches_beside_a_file_it_may_load_instead_is_unknown() {
        let layout = LinkedLayout::new();
        fs::create_dir_all(layout.siblings().join("host/node_modules/shadowed")).unwrap();
        write_package(&layout.siblings().join("shadowed"), "shadowed", "1.0.0");
        fs::write(layout.siblings().join("shadowed.js"), "").unwrap();

        let installed = layout.installed(
            &[("shadowed", 2)],
            &[],
            vec![locked_at(2, "shadowed", "1.0.0")],
        );

        assert_eq!(
            installed,
            installed_as(&[
                ("host", Installation::Installed),
                ("shadowed", Installation::Unknown),
            ]),
            "ES modules stop at the bare folder and CommonJS loads shadowed.js \
             unless the release's exports take over"
        );
    }

    #[test]
    fn the_project_path_walk_reads_manifests_as_node_does() {
        let project = tempfile::tempdir().unwrap();
        write_package(&project.path().join("node_modules/host"), "host", "1.0.0");
        let nested = project.path().join("node_modules/host/node_modules/marked");
        fs::create_dir_all(&nested).unwrap();
        fs::write(
            nested.join("package.json"),
            "\u{feff}{\"name\":\"marked\",\"version\":\"1.0.0\"}",
        )
        .unwrap();
        let mut host = locked_at(1, "host", "1.0.0");
        host.dependency_targets = BTreeMap::from([("marked".to_string(), instance(2))]);
        let lockfile = lpm_lockfile::Lockfile {
            packages: vec![host, locked_at(2, "marked", "1.0.0")],
            root_resolutions: BTreeMap::from([(
                "host".to_string(),
                lpm_lockfile::LockedRootResolution {
                    instance_id: Some(instance(1)),
                    ..Default::default()
                },
            )]),
            ..lpm_lockfile::Lockfile::new()
        };

        let packages = lpm_discovered_packages(project.path(), &lockfile, Reachability::Skip);

        assert_eq!(packages[1].path, "node_modules/host/node_modules/marked");
    }

    #[test]
    fn package_segments_accept_only_package_names() {
        for (name, expected) in [
            ("tool", Some(("tool", None))),
            ("@acme/util", Some(("@acme", Some("util")))),
            ("tool.js", Some(("tool.js", None))),
            ("", None),
            ("..", None),
            ("../tool", None),
            ("tool/extra", None),
            ("@acme", None),
            ("@/util", None),
            ("@acme/util/extra", None),
            ("tool\\extra", None),
            ("c:tool", None),
            ("tool.", None),
            ("tool ", None),
            ("CON", None),
            ("@acme/nul.txt", None),
            ("tool\0", None),
        ] {
            assert_eq!(
                PackageSegments::of(name).map(|segments| (segments.first, segments.second)),
                expected,
                "{name:?}"
            );
        }
    }

    #[test]
    fn a_manifest_identity_borrows_and_takes_the_last_repeated_field() {
        let package = locked_at(1, "tool", "1.0.0");
        let parse = |text| serde_json::from_str::<ManifestIdentity<'_>>(text).unwrap();

        let plain = parse(r#"{"name":"tool","version":"1.0.0"}"#);
        assert!(matches!(
            &plain.name,
            Field::Text(std::borrow::Cow::Borrowed("tool"))
        ));
        assert!(plain.names(&package));
        assert!(parse(r#"{"name":"other","version":"1.0.0","name":"tool"}"#).names(&package));
        assert!(!parse(r#"{"name":"tool","version":"1.0.0","version":"2.0.0"}"#).names(&package));
        assert!(parse(r#"{"name":"tool","version":"1.0.0"}"#).names(&package));
        assert!(!parse(r#"{"name":"tool","version":1}"#).names(&package));

        let local = locked_at(2, "tool", "0.0.0");
        assert!(parse(r#"{"name":"tool"}"#).names(&local));
        assert!(parse(r#"{"name":"tool","version":null}"#).names(&local));
        assert!(!parse(r#"{"name":null}"#).names(&local));
    }

    #[cfg(unix)]
    #[test]
    fn a_package_json_that_is_a_fifo_leaves_the_release_unknown_without_blocking() {
        let project = tempfile::tempdir().unwrap();
        let fifo_package = project.path().join("node_modules/piped");
        fs::create_dir_all(&fifo_package).unwrap();
        let fifo = std::ffi::CString::new(
            fifo_package
                .join("package.json")
                .into_os_string()
                .into_encoded_bytes(),
        )
        .unwrap();
        // SAFETY: `fifo` is a valid NUL-terminated path.
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o644) }, 0);
        let mut piped = locked_at(1, "piped", "1.0.0");
        piped.dependency_targets = BTreeMap::from([("inner".to_string(), instance(2))]);
        let lockfile = lpm_lockfile::Lockfile {
            packages: vec![piped, locked_at(2, "inner", "1.0.0")],
            root_resolutions: BTreeMap::from([(
                "piped".to_string(),
                lpm_lockfile::LockedRootResolution {
                    instance_id: Some(instance(1)),
                    ..Default::default()
                },
            )]),
            ..lpm_lockfile::Lockfile::new()
        };
        let root = project.path().to_path_buf();
        let (sender, receiver) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let packages = lpm_discovered_packages(&root, &lockfile, Reachability::Track);
            let _ = sender.send(
                packages
                    .into_iter()
                    .map(|package| (package.name, package.installed))
                    .collect::<Vec<_>>(),
            );
        });

        let installed = receiver
            .recv_timeout(std::time::Duration::from_secs(20))
            .expect("discovery blocked on a FIFO");

        assert_eq!(
            installed,
            installed_as(&[
                ("piped", Installation::Unknown),
                ("inner", Installation::Unknown),
            ])
        );
    }

    #[test]
    fn whether_a_package_is_installed_is_left_open_without_root_instances_or_when_not_asked() {
        let project = tempfile::tempdir().unwrap();
        write_package(&project.path().join("node_modules/host"), "host", "1.0.0");
        let without_roots = lpm_lockfile::Lockfile {
            packages: vec![locked_at(1, "host", "1.0.0")],
            ..lpm_lockfile::Lockfile::new()
        };
        let with_roots = lpm_lockfile::Lockfile {
            root_resolutions: BTreeMap::from([(
                "host".to_string(),
                lpm_lockfile::LockedRootResolution {
                    instance_id: Some(instance(1)),
                    ..Default::default()
                },
            )]),
            ..without_roots.clone()
        };

        let installed = |lockfile, reachability| {
            lpm_discovered_packages(project.path(), lockfile, reachability)[0].installed
        };

        assert_eq!(installed(&without_roots, Reachability::Track), None);
        assert_eq!(installed(&with_roots, Reachability::Skip), None);
        assert_eq!(
            installed(&with_roots, Reachability::Track),
            Some(Installation::Installed)
        );
    }

    #[cfg(unix)]
    #[test]
    fn an_entry_that_cant_be_inspected_leaves_only_what_it_reaches_unknown() {
        use std::os::unix::fs::PermissionsExt as _;

        // SAFETY: geteuid has no preconditions. Root ignores the mode below.
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let project = tempfile::tempdir().unwrap();
        let node_modules = project.path().join("node_modules");
        write_package(&node_modules.join("sealed"), "sealed", "1.0.0");
        write_package(&node_modules.join("open"), "open", "1.0.0");
        let mut sealed = locked_at(1, "sealed", "1.0.0");
        sealed.dependency_targets = BTreeMap::from([("inner".to_string(), instance(2))]);
        let root = |id| lpm_lockfile::LockedRootResolution {
            instance_id: Some(instance(id)),
            ..Default::default()
        };
        let lockfile = lpm_lockfile::Lockfile {
            packages: vec![
                sealed,
                locked_at(2, "inner", "1.0.0"),
                locked_at(3, "open", "1.0.0"),
                locked_at(4, "dev-only", "1.0.0"),
            ],
            root_resolutions: BTreeMap::from([
                ("sealed".to_string(), root(1)),
                ("open".to_string(), root(3)),
                ("dev-only".to_string(), root(4)),
            ]),
            ..lpm_lockfile::Lockfile::new()
        };
        let sealed_dir = node_modules.join("sealed");
        fs::set_permissions(&sealed_dir, fs::Permissions::from_mode(0o000)).unwrap();

        let packages = lpm_discovered_packages(project.path(), &lockfile, Reachability::Track);

        fs::set_permissions(&sealed_dir, fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(
            packages
                .iter()
                .map(|package| (package.name.as_str(), package.installed))
                .collect::<Vec<_>>(),
            [
                ("sealed", Some(Installation::Unknown)),
                ("inner", Some(Installation::Unknown)),
                ("open", Some(Installation::Installed)),
                ("dev-only", Some(Installation::Absent)),
            ]
        );
    }

    #[test]
    fn a_skipped_package_with_an_unverifiable_copy_on_disk_stays_a_coverage_gap() {
        let project = tempfile::tempdir().unwrap();
        fs::write(
            project.path().join("package.json"),
            r#"{"name":"app","dependencies":{"host":"1.0.0"}}"#,
        )
        .unwrap();
        let host_dir = project.path().join("node_modules/host");
        fs::create_dir_all(&host_dir).unwrap();
        fs::write(
            host_dir.join("package.json"),
            r#"{"name":"host","version":"1.0.0"}"#,
        )
        .unwrap();
        let alias_dir = project.path().join("node_modules/wasm-alias");
        fs::create_dir_all(&alias_dir).unwrap();
        fs::write(alias_dir.join("package.json"), "{ not json").unwrap();
        let mut host = locked_at(1, "host", "1.0.0");
        host.dependencies = vec!["wasm-alias@1.0.0".into()];
        host.dependency_targets = BTreeMap::from([("wasm-alias".to_string(), instance(2))]);
        let mut wasm_only = locked_at(2, "wasm-only", "1.0.0");
        wasm_only.optional = true;
        wasm_only.cpu = vec!["wasm32".into()];
        let lockfile = lpm_lockfile::Lockfile {
            packages: vec![host, wasm_only],
            root_resolutions: BTreeMap::from([(
                "host".to_string(),
                lpm_lockfile::LockedRootResolution {
                    instance_id: Some(instance(1)),
                    ..Default::default()
                },
            )]),
            ..lpm_lockfile::Lockfile::new()
        };

        let packages = lpm_discovered_packages(project.path(), &lockfile, Reachability::Skip);

        assert!(
            !packages[1].platform_skipped,
            "something is at the package's install path, so its absence isn't confirmed"
        );
    }

    #[test]
    fn npm_counts_an_absent_package_as_not_installed_only_when_its_install_record_leaves_it_out() {
        let lockfile = r#"{"lockfileVersion":3,"packages":{"":{},"node_modules/opt":{"version":"1.0.0","resolved":"https://registry.npmjs.org/opt/-/opt-1.0.0.tgz","optional":true}}}"#;
        let scan_mode = |hidden_lockfile: Option<&str>| {
            let dir = tempfile::tempdir().unwrap();
            fs::write(dir.path().join("package-lock.json"), lockfile).unwrap();
            fs::create_dir_all(dir.path().join("node_modules")).unwrap();
            if let Some(hidden) = hidden_lockfile {
                fs::write(dir.path().join("node_modules/.package-lock.json"), hidden).unwrap();
            }
            discover_packages(dir.path()).unwrap().packages[0].scan_mode
        };

        assert_eq!(
            scan_mode(Some(r#"{"lockfileVersion":3,"packages":{"":{}}}"#)),
            ScanMode::NotInstalled
        );
        assert_eq!(
            scan_mode(None),
            ScanMode::LocalMissing,
            "an empty node_modules"
        );
        assert_eq!(
            scan_mode(Some(
                r#"{"lockfileVersion":3,"packages":{"":{},"node_modules/opt":{"version":"1.0.0"}}}"#
            )),
            ScanMode::LocalMissing,
            "npm installed it, so its files are missing"
        );
    }

    #[test]
    fn removing_packages_drops_their_rows_from_the_retained_lpm_lockfile() {
        let project = tempfile::tempdir().unwrap();
        let lockfile = lpm_lockfile::Lockfile {
            packages: vec![
                locked_at(1, "kept", "1.0.0"),
                locked_at(2, "removed", "1.0.0"),
                locked_at(3, "also-kept", "1.0.0"),
            ],
            ..lpm_lockfile::Lockfile::new()
        };
        let mut discovery = DiscoveryResult {
            manager: ManagerKind::Lpm,
            lockfile_path: None,
            project_root: project.path().to_path_buf(),
            is_degraded: false,
            is_yarn_pnp: false,
            packages: lpm_discovered_packages(project.path(), &lockfile, Reachability::Skip),
            lpm_lockfile: Some(Arc::new(lockfile)),
            lpm_lockfile_content: None,
            workspace_root: None,
        };

        discovery.remove_packages(&[false, true, false]);

        let package_names: Vec<&str> = discovery.packages.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(package_names, ["kept", "also-kept"]);
        let row_names: Vec<&str> = discovery
            .retained_lpm_lockfile()
            .unwrap()
            .packages
            .iter()
            .map(|p| p.name.as_str())
            .collect();
        assert_eq!(row_names, ["kept", "also-kept"]);
    }

    #[test]
    fn installed_dependencies_name_the_rows_an_edge_installs_peers_included() {
        let dep = locked_at(2, "dep-pkg", "1.0.0");
        let react = locked_at(3, "react", "18.0.0");
        let mut wrapper = locked_at(1, "@lpm.dev/acme.ui", "1.0.0");
        wrapper.dependencies = vec!["legacy@1.0.0".into()];
        wrapper.dependency_targets = BTreeMap::from([("legacy".to_string(), instance(2))]);
        wrapper.peer_edges = vec![lpm_common::PeerEdge::registry("react", "react", "18.0.0")];
        wrapper.peer_targets = BTreeMap::from([("react".to_string(), instance(3))]);
        let by_instance = HashMap::from([(instance(2), &dep), (instance(3), &react)]);

        assert_eq!(
            installed_dependencies(&wrapper, &by_instance),
            [
                ("dep-pkg".to_string(), "1.0.0".to_string()),
                ("react".to_string(), "18.0.0".to_string()),
            ]
        );
    }

    #[test]
    fn installed_dependencies_fall_back_to_the_edges_of_a_lockfile_without_targets() {
        let mut wrapper = locked_at(1, "@lpm.dev/acme.ui", "1.0.0");
        wrapper.instance_id = None;
        wrapper.dependencies = vec![
            "legacy@1.0.0".into(),
            "@scope/name@2.0.0".into(),
            "@1.0.0".into(),
        ];
        wrapper.alias_dependencies = vec![["legacy".into(), "dep-pkg".into()]];
        wrapper.peer_edges = vec![lpm_common::PeerEdge::registry("r", "react", "18.0.0")];

        assert_eq!(
            installed_dependencies(&wrapper, &HashMap::new()),
            [
                ("@scope/name".to_string(), "2.0.0".to_string()),
                ("dep-pkg".to_string(), "1.0.0".to_string()),
                ("react".to_string(), "18.0.0".to_string()),
            ]
        );
    }

    #[test]
    fn npm_lockfile_preserves_dependency_edges() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("package.json"),
            r#"{"dependencies": {"express": "4.22.1"}}"#,
        )
        .unwrap();
        fs::write(
            dir.path().join("package-lock.json"),
            r#"{
				"lockfileVersion": 3,
				"packages": {
					"": {"dependencies": {"express": "4.22.1"}},
					"node_modules/express": {
						"version": "4.22.1",
						"resolved": "https://registry.npmjs.org/express/-/express-4.22.1.tgz",
						"integrity": "sha512-abc",
						"dependencies": {"accepts": "1.3.8", "qs": "6.14.0"}
					},
					"node_modules/accepts": {
						"version": "1.3.8",
						"resolved": "https://registry.npmjs.org/accepts/-/accepts-1.3.8.tgz",
						"integrity": "sha512-def"
					},
					"node_modules/qs": {
						"version": "6.14.0",
						"resolved": "https://registry.npmjs.org/qs/-/qs-6.14.0.tgz",
						"integrity": "sha512-ghi"
					}
				}
			}"#,
        )
        .unwrap();

        // Create node_modules dirs so ScanMode is FullLocal
        fs::create_dir_all(dir.path().join("node_modules/express")).unwrap();
        fs::create_dir_all(dir.path().join("node_modules/accepts")).unwrap();
        fs::create_dir_all(dir.path().join("node_modules/qs")).unwrap();

        let result = discover_packages(dir.path()).unwrap();

        assert_eq!(result.manager, ManagerKind::Npm);
        assert_eq!(result.packages.len(), 3);

        // Express should have dependency edges to accepts and qs
        let express = result
            .packages
            .iter()
            .find(|p| p.name == "express")
            .expect("express not found");
        assert_eq!(express.dependencies.len(), 2);
        assert!(
            express
                .dependencies
                .iter()
                .any(|(n, v)| n == "accepts" && v == "1.3.8")
        );
        assert!(
            express
                .dependencies
                .iter()
                .any(|(n, v)| n == "qs" && v == "6.14.0")
        );

        // Leaf packages should have no dependencies
        let accepts = result
            .packages
            .iter()
            .find(|p| p.name == "accepts")
            .expect("accepts not found");
        assert!(accepts.dependencies.is_empty());
    }

    #[test]
    fn npm_nested_deps_get_correct_edges() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("package.json"),
            r#"{"dependencies": {"a": "1.0.0", "qs": "6.14.0"}}"#,
        )
        .unwrap();
        fs::write(
            dir.path().join("package-lock.json"),
            r#"{
				"lockfileVersion": 3,
				"packages": {
					"": {"dependencies": {"a": "1.0.0", "qs": "6.14.0"}},
					"node_modules/a": {
						"version": "1.0.0",
						"resolved": "https://registry.npmjs.org/a/-/a-1.0.0.tgz",
						"dependencies": {"qs": "6.5.3"}
					},
					"node_modules/a/node_modules/qs": {
						"version": "6.5.3",
						"resolved": "https://registry.npmjs.org/qs/-/qs-6.5.3.tgz"
					},
					"node_modules/qs": {
						"version": "6.14.0",
						"resolved": "https://registry.npmjs.org/qs/-/qs-6.14.0.tgz"
					}
				}
			}"#,
        )
        .unwrap();

        // Create node_modules dirs
        fs::create_dir_all(dir.path().join("node_modules/a/node_modules/qs")).unwrap();
        fs::create_dir_all(dir.path().join("node_modules/qs")).unwrap();

        let result = discover_packages(dir.path()).unwrap();

        // Package "a" should depend on qs@6.5.3 (nested), not qs@6.14.0 (hoisted)
        let a = result
            .packages
            .iter()
            .find(|p| p.name == "a")
            .expect("package a not found");
        assert_eq!(a.dependencies.len(), 1);
        assert_eq!(a.dependencies[0], ("qs".to_string(), "6.5.3".to_string()));
    }

    #[test]
    fn node_modules_fallback_builds_edges() {
        let dir = tempfile::tempdir().unwrap();

        // Create packages in node_modules (no lockfile)
        let express_dir = dir.path().join("node_modules/express");
        fs::create_dir_all(&express_dir).unwrap();
        fs::write(
            express_dir.join("package.json"),
            r#"{"name": "express", "version": "4.22.1", "dependencies": {"qs": "6.14.0"}}"#,
        )
        .unwrap();

        let qs_dir = dir.path().join("node_modules/qs");
        fs::create_dir_all(&qs_dir).unwrap();
        fs::write(
            qs_dir.join("package.json"),
            r#"{"name": "qs", "version": "6.14.0"}"#,
        )
        .unwrap();

        let result = discover_packages(dir.path()).unwrap();

        assert_eq!(result.manager, ManagerKind::FallbackNodeModules);
        assert!(result.is_degraded);
        assert_eq!(result.packages.len(), 2);

        let express = result
            .packages
            .iter()
            .find(|p| p.name == "express")
            .expect("express not found");
        // Should resolve edge to qs@6.14.0 from installed version
        assert_eq!(express.dependencies.len(), 1);
        assert_eq!(
            express.dependencies[0],
            ("qs".to_string(), "6.14.0".to_string())
        );
    }

    #[test]
    fn node_modules_fallback_deduplicates_overlapping_dependency_sections() {
        let dir = tempfile::tempdir().unwrap();
        let package_dir = dir.path().join("node_modules/p");
        fs::create_dir_all(&package_dir).unwrap();
        fs::write(
            package_dir.join("package.json"),
            r#"{
                "name": "p",
                "version": "1.0.0",
                "dependencies": {"q": "1.0.0"},
                "optionalDependencies": {"q": "1.0.0"}
            }"#,
        )
        .unwrap();
        let dependency_dir = dir.path().join("node_modules/q");
        fs::create_dir_all(&dependency_dir).unwrap();
        fs::write(
            dependency_dir.join("package.json"),
            r#"{"name":"q","version":"1.0.0"}"#,
        )
        .unwrap();

        let result = discover_from_node_modules(dir.path()).unwrap();
        let package = result
            .packages
            .iter()
            .find(|package| package.name == "p")
            .unwrap();

        assert_eq!(
            package.dependencies,
            vec![("q".to_string(), "1.0.0".to_string())]
        );
    }

    #[test]
    fn node_modules_fallback_discovers_nested_transitive_packages() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("package.json"),
            r#"{"dependencies":{"parent":"1.0.0"}}"#,
        )
        .unwrap();
        fs::create_dir_all(dir.path().join("node_modules/parent/node_modules/child")).unwrap();
        fs::write(
            dir.path().join("node_modules/parent/package.json"),
            r#"{"name":"parent","version":"1.0.0","dependencies":{"child":"1.0.0"}}"#,
        )
        .unwrap();
        fs::write(
            dir.path()
                .join("node_modules/parent/node_modules/child/package.json"),
            r#"{"name":"child","version":"1.0.0"}"#,
        )
        .unwrap();

        let result = discover_from_node_modules(dir.path()).unwrap();

        assert_eq!(result.packages.len(), 2);
        assert!(result.packages.iter().any(|package| {
            package.name == "child" && package.path == "node_modules/parent/node_modules/child"
        }));
        let parent = result
            .packages
            .iter()
            .find(|package| package.name == "parent")
            .unwrap();
        assert_eq!(
            parent.dependencies,
            vec![("child".to_string(), "1.0.0".to_string())]
        );
    }

    #[test]
    fn node_modules_fallback_uses_manifest_name_for_npm_alias_directory() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join("node_modules/local-alias")).unwrap();
        fs::write(
            dir.path().join("node_modules/local-alias/package.json"),
            r#"{"name":"canonical-package","version":"1.0.0"}"#,
        )
        .unwrap();

        let result = discover_from_node_modules(dir.path()).unwrap();

        assert_eq!(result.packages.len(), 1);
        assert_eq!(result.packages[0].name, "canonical-package");
        assert_eq!(result.packages[0].path, "node_modules/local-alias");
    }

    #[test]
    fn node_modules_fallback_resolves_alias_dependencies_to_manifest_identity() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join("node_modules/consumer")).unwrap();
        fs::create_dir_all(dir.path().join("node_modules/local-alias")).unwrap();
        fs::write(
            dir.path().join("node_modules/consumer/package.json"),
            r#"{
                "name": "consumer",
                "version": "1.0.0",
                "dependencies": {"local-alias": "npm:canonical-package@1.0.0"}
            }"#,
        )
        .unwrap();
        fs::write(
            dir.path().join("node_modules/local-alias/package.json"),
            r#"{"name":"canonical-package","version":"1.0.0"}"#,
        )
        .unwrap();

        let result = discover_from_node_modules(dir.path()).unwrap();
        let consumer = result
            .packages
            .iter()
            .find(|package| package.name == "consumer")
            .unwrap();

        assert_eq!(
            consumer.dependencies,
            vec![("canonical-package".to_string(), "1.0.0".to_string())]
        );
    }

    #[test]
    fn lpm_lock_extracts_dependency_edges() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("lpm.lock"),
            r#"
[metadata]
lockfile-version = 1
resolved-with = "pubgrub"

[[packages]]
name = "accepts"
version = "1.3.8"

[[packages]]
name = "express"
version = "4.22.1"
dependencies = ["accepts@1.3.8", "qs@6.14.0"]

[[packages]]
name = "qs"
version = "6.14.0"
"#,
        )
        .unwrap();

        let result = discover_packages(dir.path()).unwrap();

        assert_eq!(result.manager, ManagerKind::Lpm);
        assert_eq!(result.packages.len(), 3);

        let express = result
            .packages
            .iter()
            .find(|p| p.name == "express")
            .expect("express not found");
        assert_eq!(express.dependencies.len(), 2);
        assert!(
            express
                .dependencies
                .iter()
                .any(|(n, v)| n == "accepts" && v == "1.3.8")
        );
        assert!(
            express
                .dependencies
                .iter()
                .any(|(n, v)| n == "qs" && v == "6.14.0")
        );
    }

    #[test]
    fn node_modules_fallback_unresolved_deps_filtered() {
        let dir = tempfile::tempdir().unwrap();

        // Package depends on "missing-pkg" which isn't installed
        let pkg_dir = dir.path().join("node_modules/my-pkg");
        fs::create_dir_all(&pkg_dir).unwrap();
        fs::write(
            pkg_dir.join("package.json"),
            r#"{"name": "my-pkg", "version": "1.0.0", "dependencies": {"missing-pkg": "^1.0.0"}}"#,
        )
        .unwrap();

        let result = discover_packages(dir.path()).unwrap();

        let pkg = result
            .packages
            .iter()
            .find(|p| p.name == "my-pkg")
            .expect("my-pkg not found");
        // missing-pkg is not in node_modules, so it should be filtered out
        assert!(pkg.dependencies.is_empty());
    }

    #[test]
    fn npm_duplicate_name_version_at_different_paths_preserved() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("package.json"),
            r#"{"dependencies": {"a": "1.0.0", "qs": "1.0.0"}}"#,
        )
        .unwrap();
        fs::write(
            dir.path().join("package-lock.json"),
            r#"{
				"lockfileVersion": 3,
				"packages": {
					"": {"dependencies": {"a": "1.0.0", "qs": "1.0.0"}},
					"node_modules/a": {
						"version": "1.0.0",
						"resolved": "https://registry.npmjs.org/a/-/a-1.0.0.tgz",
						"dependencies": {"qs": "1.0.0"}
					},
					"node_modules/a/node_modules/qs": {
						"version": "1.0.0",
						"resolved": "https://registry.npmjs.org/qs/-/qs-1.0.0.tgz"
					},
					"node_modules/qs": {
						"version": "1.0.0",
						"resolved": "https://registry.npmjs.org/qs/-/qs-1.0.0.tgz"
					}
				}
			}"#,
        )
        .unwrap();

        // Create node_modules dirs
        fs::create_dir_all(dir.path().join("node_modules/a/node_modules/qs")).unwrap();
        fs::create_dir_all(dir.path().join("node_modules/qs")).unwrap();
        fs::create_dir_all(dir.path().join("node_modules/a")).unwrap();

        let result = discover_packages(dir.path()).unwrap();

        // Must have 3 packages: a, qs (hoisted), qs (nested under a)
        assert_eq!(
            result.packages.len(),
            3,
            "expected 3 packages, got {}",
            result.packages.len()
        );

        // Both qs instances must have DIFFERENT paths
        let qs_packages: Vec<&DiscoveredPackage> =
            result.packages.iter().filter(|p| p.name == "qs").collect();
        assert_eq!(qs_packages.len(), 2, "expected 2 qs instances");

        let mut paths: Vec<&str> = qs_packages.iter().map(|p| p.path.as_str()).collect();
        paths.sort();
        assert_eq!(
            paths,
            vec!["node_modules/a/node_modules/qs", "node_modules/qs"],
            "qs instances must have distinct paths"
        );
    }

    #[test]
    fn npm_delimiter_ambiguous_coordinates_keep_their_exact_paths() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("package.json"), r#"{"dependencies": {}}"#).unwrap();
        fs::write(
            dir.path().join("package-lock.json"),
            r#"{
                "lockfileVersion": 3,
                "packages": {
                    "node_modules/a@b": {
                        "version": "c",
                        "resolved": "https://registry.npmjs.org/a-at-b/-/a-at-b-c.tgz"
                    },
                    "node_modules/z/node_modules/a": {
                        "version": "b@c",
                        "resolved": "https://registry.npmjs.org/a/-/a-b-c.tgz"
                    }
                }
            }"#,
        )
        .unwrap();
        fs::create_dir_all(dir.path().join("node_modules/a@b")).unwrap();
        fs::create_dir_all(dir.path().join("node_modules/z/node_modules/a")).unwrap();

        let result = discover_packages(dir.path()).unwrap();
        let identities_and_paths: Vec<_> = result
            .packages
            .iter()
            .map(|package| {
                (
                    package.name.as_str(),
                    package.version.as_str(),
                    package.path.as_str(),
                )
            })
            .collect();

        assert_eq!(
            identities_and_paths,
            vec![
                ("a", "b@c", "node_modules/z/node_modules/a"),
                ("a@b", "c", "node_modules/a@b"),
            ]
        );
    }

    #[test]
    fn npm_v1_nested_instances_use_their_exact_installed_paths() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("package.json"), r#"{"dependencies": {}}"#).unwrap();
        fs::write(
            dir.path().join("package-lock.json"),
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
        fs::create_dir_all(dir.path().join("node_modules/a/node_modules/dep")).unwrap();
        fs::create_dir_all(dir.path().join("node_modules/dep")).unwrap();

        let result = discover_packages(dir.path()).unwrap();
        let dep_paths: Vec<_> = result
            .packages
            .iter()
            .filter(|package| package.name == "dep")
            .map(|package| (package.version.as_str(), package.path.as_str()))
            .collect();

        assert_eq!(
            dep_paths,
            vec![
                ("1.0.0", "node_modules/a/node_modules/dep"),
                ("2.0.0", "node_modules/dep"),
            ]
        );
    }

    #[test]
    fn npm_workspace_entries_dont_abort_path_recovery() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("package.json"),
            r#"{"workspaces": ["packages/*"], "dependencies": {"qs": "1.0.0"}}"#,
        )
        .unwrap();
        fs::write(
            dir.path().join("package-lock.json"),
            r#"{
				"lockfileVersion": 3,
				"packages": {
					"": {"workspaces": ["packages/*"], "dependencies": {"qs": "1.0.0"}},
					"node_modules/qs": {
						"version": "1.0.0",
						"resolved": "https://registry.npmjs.org/qs/-/qs-1.0.0.tgz"
					},
					"node_modules/lodash": {
						"version": "4.17.21",
						"resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"
					},
					"node_modules/web": {
						"resolved": "packages/web",
						"link": true
					},
					"packages/web": {
						"name": "web",
						"version": "1.0.0",
						"dependencies": {"lodash": "^4.17.0"}
					},
					"packages/web/node_modules/express": {
						"version": "4.22.1",
						"resolved": "https://registry.npmjs.org/express/-/express-4.22.1.tgz"
					}
				}
			}"#,
        )
        .unwrap();

        fs::create_dir_all(dir.path().join("node_modules/qs")).unwrap();
        fs::create_dir_all(dir.path().join("node_modules/lodash")).unwrap();
        fs::create_dir_all(dir.path().join("packages/web/node_modules/express")).unwrap();

        let result = discover_packages(dir.path()).unwrap();

        // Should discover qs, lodash, AND express (under workspace member)
        assert!(
            result.packages.len() >= 3,
            "expected at least 3 packages, got {}",
            result.packages.len()
        );

        // Express should have the workspace-nested path
        let express = result
            .packages
            .iter()
            .find(|p| p.name == "express")
            .expect("express not found");
        assert_eq!(
            express.path, "packages/web/node_modules/express",
            "express should have workspace-nested path"
        );
    }

    #[test]
    fn malformed_child_lockfile_does_not_fall_back_to_an_ancestor() {
        let dir = tempfile::tempdir().unwrap();
        let child = dir.path().join("child");
        fs::create_dir_all(&child).unwrap();
        fs::write(child.join("package-lock.json"), "{not-json").unwrap();
        fs::write(
            dir.path().join("package-lock.json"),
            r#"{
                "lockfileVersion": 3,
                "packages": {
                    "node_modules/ancestor": {
                        "version": "1.0.0",
                        "resolved": "https://registry.npmjs.org/ancestor/-/ancestor-1.0.0.tgz"
                    }
                }
            }"#,
        )
        .unwrap();

        let error = discover_packages(&child)
            .err()
            .expect("child lockfile must fail");

        assert!(
            error.to_string().contains("package-lock.json"),
            "the malformed child lockfile must be reported instead of selecting the ancestor: {error}"
        );
    }

    #[test]
    fn malformed_lockfile_does_not_fall_back_to_node_modules() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("package-lock.json"), "{not-json").unwrap();
        fs::create_dir_all(dir.path().join("node_modules/fallback")).unwrap();
        fs::write(
            dir.path().join("node_modules/fallback/package.json"),
            r#"{"name":"fallback","version":"1.0.0"}"#,
        )
        .unwrap();

        let error = discover_packages(dir.path())
            .err()
            .expect("malformed lockfile must fail");

        assert!(
            error.to_string().contains("package-lock.json"),
            "the malformed lockfile must be reported instead of using degraded discovery: {error}"
        );
    }

    #[test]
    fn npm_registry_metadata_remains_bound_to_its_exact_package_path() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("package-lock.json"),
            r#"{
                "lockfileVersion": 3,
                "packages": {
                    "node_modules/consumer/node_modules/shared": {
                        "version": "1.0.0"
                    },
                    "node_modules/shared": {
                        "version": "1.0.0",
                        "resolved": "https://registry.npmjs.org/shared/-/shared-1.0.0.tgz",
                        "integrity": "sha512-registry"
                    }
                }
            }"#,
        )
        .unwrap();
        fs::create_dir_all(dir.path().join("node_modules/consumer/node_modules/shared")).unwrap();
        fs::create_dir_all(dir.path().join("node_modules/shared")).unwrap();

        let result = discover_packages(dir.path()).unwrap();

        assert_eq!(result.packages.len(), 1);
        assert_eq!(result.packages[0].path, "node_modules/shared");
        assert_eq!(
            result.packages[0].integrity.as_deref(),
            Some("sha512-registry")
        );
    }

    #[test]
    fn npm_absolute_package_path_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("package-lock.json"),
            r#"{
                "lockfileVersion": 3,
                "packages": {
                    "/tmp/outside/node_modules/escaped": {
                        "version": "1.0.0",
                        "resolved": "https://registry.npmjs.org/escaped/-/escaped-1.0.0.tgz"
                    }
                }
            }"#,
        )
        .unwrap();

        let error = discover_packages(dir.path())
            .err()
            .expect("absolute package path must fail");

        assert!(
            error.to_string().contains("package path"),
            "absolute npm package paths must fail closed: {error}"
        );
    }

    #[test]
    fn pnpm_transitive_package_uses_its_virtual_store_path() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("pnpm-lock.yaml"),
            r#"lockfileVersion: '9.0'
packages:
  child@1.0.0:
    resolution:
      integrity: sha512-child
      tarball: https://registry.npmjs.org/child/-/child-1.0.0.tgz
"#,
        )
        .unwrap();
        let installed = dir
            .path()
            .join("node_modules/.pnpm/child@1.0.0/node_modules/child");
        fs::create_dir_all(&installed).unwrap();
        fs::write(
            installed.join("package.json"),
            r#"{"name":"child","version":"1.0.0"}"#,
        )
        .unwrap();

        let result = discover_packages(dir.path()).unwrap();

        assert_eq!(result.packages.len(), 1);
        assert_eq!(
            result.packages[0].path,
            "node_modules/.pnpm/child@1.0.0/node_modules/child"
        );
        assert_eq!(result.packages[0].scan_mode, ScanMode::FullLocal);
    }

    #[test]
    fn pnpm_peer_contexts_keep_their_exact_paths_and_dependency_edges() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("pnpm-lock.yaml"),
            r#"lockfileVersion: '9.0'
packages:
  consumer@1.0.0:
    resolution: {integrity: sha512-consumer}
  left@1.0.0:
    resolution: {integrity: sha512-left}
  right@2.0.0:
    resolution: {integrity: sha512-right}
snapshots:
  consumer@1.0.0(left@1.0.0):
    dependencies:
      left: 1.0.0
  consumer@1.0.0(right@2.0.0):
    dependencies:
      right: 2.0.0
  left@1.0.0: {}
  right@2.0.0: {}
"#,
        )
        .unwrap();
        for (store_directory, name, version) in [
            ("consumer@1.0.0_left@1.0.0", "consumer", "1.0.0"),
            ("consumer@1.0.0_right@2.0.0", "consumer", "1.0.0"),
            ("left@1.0.0", "left", "1.0.0"),
            ("right@2.0.0", "right", "2.0.0"),
        ] {
            let package = dir
                .path()
                .join("node_modules/.pnpm")
                .join(store_directory)
                .join("node_modules")
                .join(name);
            fs::create_dir_all(&package).unwrap();
            fs::write(
                package.join("package.json"),
                format!(r#"{{"name":"{name}","version":"{version}"}}"#),
            )
            .unwrap();
        }

        let result = discover_packages(dir.path()).unwrap();
        let consumers: Vec<_> = result
            .packages
            .iter()
            .filter(|package| package.name == "consumer")
            .collect();

        assert_eq!(consumers.len(), 2);
        assert!(consumers.iter().any(|package| {
            package.path.contains("consumer@1.0.0_left@1.0.0")
                && package.dependencies == vec![("left".to_string(), "1.0.0".to_string())]
        }));
        assert!(consumers.iter().any(|package| {
            package.path.contains("consumer@1.0.0_right@2.0.0")
                && package.dependencies == vec![("right".to_string(), "2.0.0".to_string())]
        }));
    }

    fn write_optional_pnpm_lockfile(dir: &Path) {
        fs::write(
            dir.join("pnpm-lock.yaml"),
            r#"lockfileVersion: '6.0'
packages:
  /opt-native@1.0.0:
    resolution: {integrity: sha512-opt-native}
    optional: true
"#,
        )
        .unwrap();
    }

    #[test]
    fn an_optional_pnpm_instance_with_a_different_manifest_stays_a_coverage_gap() {
        let dir = tempfile::tempdir().unwrap();
        write_optional_pnpm_lockfile(dir.path());
        let instance = dir
            .path()
            .join("node_modules/.pnpm/opt-native@1.0.0/node_modules/opt-native");
        fs::create_dir_all(&instance).unwrap();
        fs::write(
            instance.join("package.json"),
            r#"{"name":"opt-native","version":"9.9.9"}"#,
        )
        .unwrap();

        let result = discover_packages(dir.path()).unwrap();

        assert!(result.packages[0].is_optional);
        assert_eq!(result.packages[0].scan_mode, ScanMode::LocalMissing);
    }

    #[test]
    fn an_absent_optional_package_whose_install_path_is_a_guess_stays_a_coverage_gap() {
        for virtual_store in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            write_optional_pnpm_lockfile(dir.path());
            if virtual_store {
                fs::create_dir_all(dir.path().join("node_modules/.pnpm")).unwrap();
            }

            let result = discover_packages(dir.path()).unwrap();

            assert!(result.packages[0].is_optional);
            assert_eq!(
                result.packages[0].scan_mode,
                ScanMode::LocalMissing,
                "virtual store present: {virtual_store}"
            );
        }
    }

    #[test]
    fn an_absent_optional_or_dev_npm_package_is_not_installed() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("package-lock.json"),
            r#"{"lockfileVersion":3,"packages":{"":{},"node_modules/opt":{"version":"1.0.0","resolved":"https://registry.npmjs.org/opt/-/opt-1.0.0.tgz","optional":true},"node_modules/devtool":{"version":"1.0.0","resolved":"https://registry.npmjs.org/devtool/-/devtool-1.0.0.tgz","dev":true},"node_modules/required":{"version":"1.0.0","resolved":"https://registry.npmjs.org/required/-/required-1.0.0.tgz"}}}"#,
        )
        .unwrap();
        fs::create_dir_all(dir.path().join("node_modules")).unwrap();
        fs::write(
            dir.path().join("node_modules/.package-lock.json"),
            r#"{"lockfileVersion":3,"packages":{"":{}}}"#,
        )
        .unwrap();

        let result = discover_packages(dir.path()).unwrap();

        let mode = |name: &str| {
            result
                .packages
                .iter()
                .find(|package| package.name == name)
                .unwrap()
                .scan_mode
        };
        assert_eq!(mode("opt"), ScanMode::NotInstalled);
        assert_eq!(mode("devtool"), ScanMode::NotInstalled);
        assert_eq!(mode("required"), ScanMode::LocalMissing);
    }

    #[test]
    fn an_absent_optional_npm_package_is_a_coverage_gap_when_nothing_was_installed() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("package-lock.json"),
            r#"{"lockfileVersion":3,"packages":{"":{},"node_modules/opt":{"version":"1.0.0","resolved":"https://registry.npmjs.org/opt/-/opt-1.0.0.tgz","optional":true},"node_modules/devtool":{"version":"1.0.0","resolved":"https://registry.npmjs.org/devtool/-/devtool-1.0.0.tgz","dev":true}}}"#,
        )
        .unwrap();

        let result = discover_packages(dir.path()).unwrap();

        assert_eq!(
            result
                .packages
                .iter()
                .map(|package| package.scan_mode)
                .collect::<Vec<_>>(),
            [ScanMode::LocalMissing, ScanMode::LocalMissing]
        );
    }

    #[test]
    fn including_the_workspace_root_graph_keeps_packages_and_lockfile_rows_aligned() {
        let member = tempfile::tempdir().unwrap();
        let root = tempfile::tempdir().unwrap();
        let shared = |source: &str| lpm_lockfile::LockedPackage {
            name: "shared".to_string(),
            version: "1.0.0".to_string(),
            source: Some(source.to_string()),
            ..Default::default()
        };
        let member_lockfile = lpm_lockfile::Lockfile {
            packages: vec![shared("registry+https://registry.npmjs.org")],
            ..lpm_lockfile::Lockfile::new()
        };
        let root_lockfile = lpm_lockfile::Lockfile {
            packages: vec![
                shared("registry+https://mirror.example"),
                locked_at(2, "root-only", "1.0.0"),
            ],
            ..lpm_lockfile::Lockfile::new()
        };
        let mut discovery = DiscoveryResult {
            manager: ManagerKind::Lpm,
            lockfile_path: None,
            project_root: member.path().to_path_buf(),
            is_degraded: false,
            is_yarn_pnp: false,
            packages: lpm_discovered_packages(member.path(), &member_lockfile, Reachability::Skip),
            lpm_lockfile: Some(Arc::new(member_lockfile)),
            lpm_lockfile_content: None,
            workspace_root: Some(WorkspaceRootDiscovery {
                project_root: root.path().to_path_buf(),
                lockfile: Arc::new(root_lockfile),
            }),
        };

        discovery.include_workspace_root_graph();

        let rows = &discovery.retained_lpm_lockfile().unwrap().packages;
        assert_eq!(rows.len(), discovery.packages.len());
        for (row, package) in rows.iter().zip(&discovery.packages) {
            assert_eq!((&row.name, &row.version), (&package.name, &package.version));
        }
    }

    #[test]
    fn pnpm_missing_exact_instance_does_not_scan_a_different_hoisted_version() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("pnpm-lock.yaml"),
            r#"lockfileVersion: '9.0'
packages:
  child@1.0.0:
    resolution:
      integrity: sha512-child-v1
      tarball: https://registry.npmjs.org/child/-/child-1.0.0.tgz
"#,
        )
        .unwrap();
        fs::create_dir_all(dir.path().join("node_modules/.pnpm")).unwrap();
        let hoisted = dir.path().join("node_modules/child");
        fs::create_dir_all(&hoisted).unwrap();
        fs::write(
            hoisted.join("package.json"),
            r#"{"name":"child","version":"2.0.0"}"#,
        )
        .unwrap();

        let result = discover_packages(dir.path()).unwrap();

        assert_eq!(result.packages.len(), 1);
        assert_eq!(result.packages[0].version, "1.0.0");
        assert_eq!(result.packages[0].scan_mode, ScanMode::LocalMissing);
        assert_ne!(result.packages[0].path, "node_modules/child");
    }

    #[cfg(unix)]
    #[test]
    fn pnpm_virtual_store_symlink_is_rejected_before_external_manifest_reads() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("pnpm-lock.yaml"),
            r#"lockfileVersion: '9.0'
packages:
  escaped@1.0.0:
    resolution:
      integrity: sha512-escaped
      tarball: https://registry.npmjs.org/escaped/-/escaped-1.0.0.tgz
"#,
        )
        .unwrap();
        let external_package = outside.path().join("escaped@1.0.0/node_modules/escaped");
        fs::create_dir_all(&external_package).unwrap();
        fs::write(
            external_package.join("package.json"),
            r#"{"name":"escaped","version":"1.0.0"}"#,
        )
        .unwrap();
        fs::create_dir_all(dir.path().join("node_modules")).unwrap();
        symlink(outside.path(), dir.path().join("node_modules/.pnpm")).unwrap();

        let error = discover_packages(dir.path())
            .err()
            .expect("linked pnpm virtual store must fail");

        assert!(error.to_string().contains("virtual store"));
    }

    #[test]
    fn newer_bun_binary_lockfile_is_not_replaced_by_stale_text_lockfile() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("bun.lock"), r#"{"packages":{}}"#).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(50));
        fs::write(dir.path().join("bun.lockb"), b"not-a-bun-lockfile").unwrap();

        let error = discover_packages(dir.path())
            .err()
            .expect("selected binary lockfile must fail");

        assert!(
            error.to_string().contains("bun.lockb") || error.to_string().contains("bun"),
            "the selected binary lockfile must remain authoritative: {error}"
        );
    }

    #[test]
    fn npm_discovery_reads_one_lockfile_snapshot() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("package-lock.json"),
            r#"{
                "lockfileVersion": 3,
                "packages": {
                    "node_modules/once": {
                        "version": "1.0.0",
                        "resolved": "https://registry.npmjs.org/once/-/once-1.0.0.tgz"
                    }
                }
            }"#,
        )
        .unwrap();
        FOREIGN_LOCKFILE_SNAPSHOT_READS.set(0);

        discover_packages(dir.path()).unwrap();

        assert_eq!(FOREIGN_LOCKFILE_SNAPSHOT_READS.get(), 1);
    }

    #[test]
    fn pnpm_discovery_reads_one_lockfile_snapshot_for_each_supported_format() {
        for (version, key) in [
            ("5.4", "/once/1.0.0"),
            ("6.0", "/once@1.0.0"),
            ("9.0", "once@1.0.0"),
        ] {
            let dir = tempfile::tempdir().unwrap();
            fs::write(
                dir.path().join("pnpm-lock.yaml"),
                format!(
                    "lockfileVersion: '{version}'\npackages:\n  '{key}':\n    resolution:\n      tarball: https://registry.npmjs.org/once/-/once-1.0.0.tgz\n"
                ),
            )
            .unwrap();
            FOREIGN_LOCKFILE_SNAPSHOT_READS.set(0);

            let discovery = discover_packages(dir.path()).unwrap();

            assert_eq!(
                FOREIGN_LOCKFILE_SNAPSHOT_READS.get(),
                1,
                "pnpm lockfile version {version} was read more than once"
            );
            assert_eq!(discovery.packages.len(), 1);
        }
    }

    #[test]
    fn npm_parent_traversal_package_path_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("package-lock.json"),
            r#"{
                "lockfileVersion": 3,
                "packages": {
                    "../node_modules/escaped": {
                        "version": "1.0.0",
                        "resolved": "https://registry.npmjs.org/escaped/-/escaped-1.0.0.tgz"
                    }
                }
            }"#,
        )
        .unwrap();

        let error = discover_packages(dir.path())
            .err()
            .expect("parent traversal must fail");

        assert!(error.to_string().contains("unsafe package path"));
    }

    #[cfg(unix)]
    #[test]
    fn npm_package_symlink_outside_project_is_rejected() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("package-lock.json"),
            r#"{
                "lockfileVersion": 3,
                "packages": {
                    "node_modules/escaped": {
                        "version": "1.0.0",
                        "resolved": "https://registry.npmjs.org/escaped/-/escaped-1.0.0.tgz"
                    }
                }
            }"#,
        )
        .unwrap();
        fs::create_dir_all(dir.path().join("node_modules")).unwrap();
        symlink(outside.path(), dir.path().join("node_modules/escaped")).unwrap();

        let error = discover_packages(dir.path())
            .err()
            .expect("outside symlink must fail");

        assert!(error.to_string().contains("outside the project"));
    }

    #[cfg(windows)]
    #[test]
    fn node_modules_fallback_rejects_package_junctions() {
        let project = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        fs::create_dir_all(project.path().join("node_modules")).unwrap();
        fs::write(
            outside.path().join("package.json"),
            r#"{"name":"outside","version":"9.0.0"}"#,
        )
        .unwrap();
        lpm_common::create_dir_symlink_or_junction(
            outside.path(),
            &project.path().join("node_modules/outside"),
        )
        .unwrap();

        let error = discover_from_node_modules(project.path())
            .err()
            .expect("junction must fail");

        assert!(
            error
                .to_string()
                .contains("package links require a supported lockfile")
        );
    }

    #[test]
    fn retained_lpm_snapshot_does_not_change_after_lockfile_replacement() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("package.json"),
            r#"{"name":"snapshot","version":"1.0.0"}"#,
        )
        .unwrap();
        let lockfile_path = dir.path().join("lpm.lock");
        fs::write(
            &lockfile_path,
            format!(
                r#"[metadata]
lockfile-version = {}
resolved-with = "pubgrub"

[[packages]]
name = "before"
version = "1.0.0"
"#,
                lpm_lockfile::LOCKFILE_VERSION_WITH_STRUCTURED_PEERS
            ),
        )
        .unwrap();
        let discovery = discover_packages_retaining_lpm_lockfile(dir.path()).unwrap();
        fs::write(
            &lockfile_path,
            format!(
                r#"[metadata]
lockfile-version = {}
resolved-with = "pubgrub"

[[packages]]
name = "after"
version = "2.0.0"
"#,
                lpm_lockfile::LOCKFILE_VERSION_WITH_STRUCTURED_PEERS
            ),
        )
        .unwrap();

        let retained = discovery.lpm_lockfile.as_ref().unwrap();
        assert_eq!(retained.packages[0].name, "before");
        assert!(
            !crate::commands::install::workspace_lockfile::project_lockfile_unchanged(
                dir.path(),
                Some(retained)
            )
            .unwrap()
        );
    }
}
