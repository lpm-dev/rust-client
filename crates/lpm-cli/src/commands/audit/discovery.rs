//! Universal package discovery for audit.
//!
//! Discovers packages from any supported lockfile format or by walking
//! `node_modules/` as a fallback. Reuses parsers from `lpm-migrate`.
//!
//! Priority: `lpm.lock` → `package-lock.json` → `pnpm-lock.yaml`
//!           → `yarn.lock` → `node_modules/` walk (degraded mode).

use lpm_common::LpmError;
use std::path::{Path, PathBuf};

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
}

/// A package discovered during the inventory phase.
#[derive(Debug, Clone)]
#[allow(dead_code)] // is_dev and is_optional used by Phase 31 --fail-on policy
pub struct DiscoveredPackage {
	/// Package name (e.g., "react", "@scope/name", "@lpm.dev/owner.pkg").
	pub name: String,
	/// Exact resolved version.
	pub version: String,
	/// Path relative to project root (e.g., "node_modules/react").
	/// For LPM store packages this is the lockfile key.
	pub path: String,
	/// SRI integrity hash from the lockfile (e.g., "sha512-...").
	pub integrity: Option<String>,
	/// Tarball resolved URL. Used for private registry detection.
	pub resolved_url: Option<String>,
	/// How this package can be scanned.
	pub scan_mode: ScanMode,
	/// Whether this is a dev dependency.
	pub is_dev: bool,
	/// Whether this is an optional dependency.
	pub is_optional: bool,
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
	// Walk up to find a lockfile
	let mut current = start_dir.to_path_buf();
	loop {
		// 1. lpm.lock — always highest priority (LPM-managed project)
		if current.join("lpm.lock").exists() {
			return discover_from_lpm_lock(&current);
		}

		// 2. Foreign lockfiles — use lpm-migrate's mtime-based detection.
		// This correctly handles projects with multiple lockfiles by
		// picking the most recently modified one.
		if let Ok(source) = lpm_migrate::detect::detect_source(&current) {
			return match source.kind {
				lpm_migrate::SourceKind::Npm => discover_from_npm_lockfile(&current),
				lpm_migrate::SourceKind::Pnpm => discover_from_pnpm_lockfile(&current),
				lpm_migrate::SourceKind::Yarn => discover_from_yarn_lockfile(&current),
				lpm_migrate::SourceKind::Bun => discover_from_bun_lockfile(&current),
			};
		}

		// Walk up
		if !current.pop() {
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

fn discover_from_lpm_lock(project_root: &Path) -> Result<DiscoveryResult, LpmError> {
	let lockfile_path = project_root.join("lpm.lock");
	let lockfile = lpm_lockfile::Lockfile::read_fast(&lockfile_path)
		.map_err(|e| LpmError::Registry(format!("failed to read lpm.lock: {e}")))?;

	let packages = lockfile
		.packages
		.iter()
		.map(|p| {
			// All packages in lpm.lock (both @lpm.dev and npm) are in the
			// LPM store at ~/.lpm/store/v1/<name>@<version>/. The store-backed
			// scan uses store.package_dir(name, version), not the path field.
			DiscoveredPackage {
				name: p.name.clone(),
				version: p.version.clone(),
				path: format!("node_modules/{}", p.name),
				integrity: p.integrity.clone(),
				resolved_url: None,
				scan_mode: ScanMode::RegistryAndStore,
				is_dev: false,
				is_optional: false,
			}
		})
		.collect();

	Ok(DiscoveryResult {
		manager: ManagerKind::Lpm,
		lockfile_path: Some(lockfile_path),
		project_root: project_root.to_path_buf(),
		is_degraded: false,
		is_yarn_pnp: false,
		packages,
	})
}

// ─── npm (package-lock.json) ────────────────────────────────────────────────

fn discover_from_npm_lockfile(project_root: &Path) -> Result<DiscoveryResult, LpmError> {
	let lockfile_path = project_root.join("package-lock.json");
	let source = lpm_migrate::DetectedSource {
		kind: lpm_migrate::SourceKind::Npm,
		path: lockfile_path.clone(),
		version: detect_npm_lockfile_version(&lockfile_path)?,
	};

	let migrated = lpm_migrate::npm::parse(&source.path, source.version)?;
	let packages = migrated_to_discovered(project_root, &migrated, &lockfile_path);

	Ok(DiscoveryResult {
		manager: ManagerKind::Npm,
		lockfile_path: Some(lockfile_path),
		project_root: project_root.to_path_buf(),
		is_degraded: false,
		is_yarn_pnp: false,
		packages,
	})
}

/// Read `lockfileVersion` from package-lock.json.
fn detect_npm_lockfile_version(path: &Path) -> Result<u32, LpmError> {
	let content = std::fs::read_to_string(path)?;
	let json: serde_json::Value = serde_json::from_str(&content)
		.map_err(|e| LpmError::Registry(format!("invalid package-lock.json: {e}")))?;
	Ok(json
		.get("lockfileVersion")
		.and_then(|v| v.as_u64())
		.unwrap_or(1) as u32)
}

// ─── pnpm (pnpm-lock.yaml) ─────────────────────────────────────────────────

fn discover_from_pnpm_lockfile(project_root: &Path) -> Result<DiscoveryResult, LpmError> {
	let lockfile_path = project_root.join("pnpm-lock.yaml");

	// Detect lockfile version
	let version = detect_pnpm_lockfile_version(&lockfile_path);
	let migrated = lpm_migrate::pnpm::parse(&lockfile_path, version)?;
	let packages = migrated_to_discovered(project_root, &migrated, &lockfile_path);

	Ok(DiscoveryResult {
		manager: ManagerKind::Pnpm,
		lockfile_path: Some(lockfile_path),
		project_root: project_root.to_path_buf(),
		is_degraded: false,
		is_yarn_pnp: false,
		packages,
	})
}

fn detect_pnpm_lockfile_version(path: &Path) -> u32 {
	if let Ok(content) = std::fs::read_to_string(path) {
		for line in content.lines().take(5) {
			if let Some(rest) = line.strip_prefix("lockfileVersion:") {
				let rest = rest.trim().trim_matches('\'').trim_matches('"');
				if let Ok(v) = rest.parse::<f64>() {
					return v as u32;
				}
			}
		}
	}
	6 // default to latest
}

// ─── yarn (yarn.lock) ───────────────────────────────────────────────────────

fn discover_from_yarn_lockfile(project_root: &Path) -> Result<DiscoveryResult, LpmError> {
	let lockfile_path = project_root.join("yarn.lock");

	// Check for Yarn PnP
	let is_yarn_pnp =
		project_root.join(".pnp.cjs").exists() || project_root.join(".pnp.js").exists();

	let migrated = lpm_migrate::yarn::parse(&lockfile_path, project_root)?;

	let packages: Vec<DiscoveredPackage> = if is_yarn_pnp {
		// PnP mode — packages are in zip archives, can't scan source
		migrated
			.iter()
			.map(|p| DiscoveredPackage {
				name: p.name.clone(),
				version: p.version.clone(),
				path: format!("node_modules/{}", p.name),
				integrity: p.integrity.clone(),
				resolved_url: p.resolved.clone(),
				scan_mode: ScanMode::OsvOnly,
				is_dev: p.is_dev,
				is_optional: p.is_optional,
			})
			.collect()
	} else {
		migrated_to_discovered(project_root, &migrated, &lockfile_path)
	};

	Ok(DiscoveryResult {
		manager: ManagerKind::Yarn,
		lockfile_path: Some(lockfile_path),
		project_root: project_root.to_path_buf(),
		is_degraded: false,
		is_yarn_pnp,
		packages,
	})
}

// ─── bun (bun.lockb / bun.lock) ────────────────────────────────────────────

fn discover_from_bun_lockfile(project_root: &Path) -> Result<DiscoveryResult, LpmError> {
	// bun.lock (text) is parseable; bun.lockb (binary) is not.
	let lockfile_path = if project_root.join("bun.lock").exists() {
		project_root.join("bun.lock")
	} else {
		// bun.lockb is binary — we can't parse it directly.
		// Fall back to node_modules walk if available.
		let nm_dir = project_root.join("node_modules");
		if nm_dir.is_dir() {
			return discover_from_node_modules(project_root);
		}
		return Err(LpmError::NotFound(
			"bun.lockb is a binary lockfile. Run `bun install` to generate \
			 node_modules, then retry lpm audit."
				.into(),
		));
	};

	let migrated = lpm_migrate::bun::parse(&lockfile_path)?;
	let packages = migrated_to_discovered(project_root, &migrated, &lockfile_path);

	Ok(DiscoveryResult {
		manager: ManagerKind::Bun,
		lockfile_path: Some(lockfile_path),
		project_root: project_root.to_path_buf(),
		is_degraded: false,
		is_yarn_pnp: false,
		packages,
	})
}

// ─── node_modules fallback (degraded mode) ──────────────────────────────────

fn discover_from_node_modules(project_root: &Path) -> Result<DiscoveryResult, LpmError> {
	let nm_dir = project_root.join("node_modules");
	let mut packages = Vec::new();

	if let Ok(entries) = std::fs::read_dir(&nm_dir) {
		for entry in entries.flatten() {
			let name = entry.file_name().to_string_lossy().to_string();

			// Skip hidden dirs, .package-lock.json, .lpm, etc.
			if name.starts_with('.') {
				continue;
			}

			if name.starts_with('@') {
				// Scoped package — descend one level
				let scope_dir = entry.path();
				if let Ok(scoped_entries) = std::fs::read_dir(&scope_dir) {
					for scoped_entry in scoped_entries.flatten() {
						let scoped_name = scoped_entry.file_name().to_string_lossy().to_string();
						let full_name = format!("{name}/{scoped_name}");
						if let Some(pkg) = read_package_from_node_modules(
							project_root,
							&scoped_entry.path(),
							&full_name,
						) {
							packages.push(pkg);
						}
					}
				}
			} else if let Some(pkg) =
				read_package_from_node_modules(project_root, &entry.path(), &name)
			{
				packages.push(pkg);
			}
		}
	}

	Ok(DiscoveryResult {
		manager: ManagerKind::FallbackNodeModules,
		lockfile_path: None,
		project_root: project_root.to_path_buf(),
		is_degraded: true,
		is_yarn_pnp: false,
		packages,
	})
}

/// Read a single package's info from its `node_modules/<name>/package.json`.
fn read_package_from_node_modules(
	project_root: &Path,
	pkg_dir: &Path,
	name: &str,
) -> Option<DiscoveredPackage> {
	let pkg_json_path = pkg_dir.join("package.json");
	let content = std::fs::read_to_string(&pkg_json_path).ok()?;
	let json: serde_json::Value = serde_json::from_str(&content).ok()?;
	let version = json.get("version")?.as_str()?.to_string();

	let rel_path = pkg_dir.strip_prefix(project_root).ok()?;
	let path = rel_path.to_string_lossy().to_string();

	Some(DiscoveredPackage {
		name: name.to_string(),
		version,
		path,
		integrity: None,
		resolved_url: None,
		scan_mode: ScanMode::FullLocal,
		is_dev: false,    // Can't determine without lockfile
		is_optional: false, // Can't determine without lockfile
	})
}

// ─── Shared conversion ─────────────────────────────────────────────────────

/// Convert `MigratedPackage` entries from lpm-migrate into `DiscoveredPackage`.
///
/// For each package, checks whether the source exists on disk to set ScanMode.
/// Uses lockfile key as the path when available (npm v2/v3), otherwise
/// constructs `node_modules/<name>`.
fn migrated_to_discovered(
	project_root: &Path,
	migrated: &[lpm_migrate::MigratedPackage],
	lockfile_path: &Path,
) -> Vec<DiscoveredPackage> {
	// For npm v2/v3, we need the raw lockfile to get the `packages` keys
	// (which include nested paths like `node_modules/express/node_modules/qs`).
	// The MigratedPackage doesn't carry this, so we parse the raw keys.
	let raw_paths = parse_npm_package_paths(lockfile_path);

	let mut packages = Vec::with_capacity(migrated.len());

	for mp in migrated {
		// Try to find the exact path from the raw lockfile keys
		let path = raw_paths
			.as_ref()
			.and_then(|paths| paths.get(&format!("{}@{}", mp.name, mp.version)).cloned())
			.unwrap_or_else(|| format!("node_modules/{}", mp.name));

		let abs_path = project_root.join(&path);
		let scan_mode = if abs_path.is_dir() {
			ScanMode::FullLocal
		} else if mp.is_optional {
			ScanMode::LocalMissing
		} else {
			// Not optional but missing — still mark as missing, don't error
			ScanMode::LocalMissing
		};

		packages.push(DiscoveredPackage {
			name: mp.name.clone(),
			version: mp.version.clone(),
			path,
			integrity: mp.integrity.clone(),
			resolved_url: mp.resolved.clone(),
			scan_mode,
			is_dev: mp.is_dev,
			is_optional: mp.is_optional,
		});
	}

	packages
}

/// Parse the raw `packages` keys from `package-lock.json` to build
/// a `"name@version" → "node_modules/..."` map.
///
/// This gives us the exact nested path for each package instance.
/// Returns None for non-npm lockfiles or parse failures.
fn parse_npm_package_paths(lockfile_path: &Path) -> Option<std::collections::HashMap<String, String>> {
	if !lockfile_path
		.file_name()?
		.to_str()?
		.contains("package-lock")
	{
		return None;
	}

	let content = std::fs::read_to_string(lockfile_path).ok()?;
	let json: serde_json::Value = serde_json::from_str(&content).ok()?;
	let packages = json.get("packages")?.as_object()?;

	let mut map = std::collections::HashMap::with_capacity(packages.len());

	for (key, value) in packages {
		if key.is_empty() {
			continue;
		}
		// Skip workspace links
		if value.get("link").and_then(|v| v.as_bool()).unwrap_or(false) {
			continue;
		}

		let version = value.get("version").and_then(|v| v.as_str())?;

		// Extract name from key
		let prefix = "node_modules/";
		let last_nm = key.rfind(prefix)?;
		let name = &key[last_nm + prefix.len()..];

		map.insert(format!("{name}@{version}"), key.clone());
	}

	Some(map)
}
