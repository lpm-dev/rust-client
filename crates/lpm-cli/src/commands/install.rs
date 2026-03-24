use crate::output;
use indicatif::{ProgressBar, ProgressStyle};
use lpm_common::LpmError;
use lpm_linker::LinkTarget;
use lpm_registry::RegistryClient;
use lpm_resolver::{ResolvedPackage, resolve_dependencies_with_overrides};
use lpm_store::PackageStore;
use owo_colors::OwoColorize;
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::Semaphore;

/// Maximum number of concurrent tarball downloads.
const MAX_CONCURRENT_DOWNLOADS: usize = 16;

/// Lightweight representation of a resolved package for the install pipeline.
/// Used both for fresh resolution results and lockfile-restored packages.
#[derive(Debug, Clone)]
struct InstallPackage {
	name: String,
	version: String,
	/// Source registry for lockfile
	source: String,
	/// Dependencies: (dep_name, dep_version)
	dependencies: Vec<(String, String)>,
	/// Whether this is a direct dependency of the root project
	is_direct: bool,
	/// Whether this is an LPM package (for tarball fetching)
	is_lpm: bool,
}

pub async fn run(
	client: &RegistryClient,
	project_dir: &Path,
	json_output: bool,
) -> Result<(), LpmError> {
	run_with_options(client, project_dir, json_output, false).await
}

pub async fn run_with_options(
	client: &RegistryClient,
	project_dir: &Path,
	json_output: bool,
	offline: bool,
) -> Result<(), LpmError> {
	let start = Instant::now();

	// Step 1: Read package.json
	let pkg_json_path = project_dir.join("package.json");
	if !pkg_json_path.exists() {
		return Err(LpmError::NotFound(
			"no package.json found in current directory".to_string(),
		));
	}

	let pkg = lpm_workspace::read_package_json(&pkg_json_path)
		.map_err(|e| LpmError::Registry(format!("failed to read package.json: {e}")))?;

	let pkg_name = pkg.name.as_deref().unwrap_or("(unnamed)");
	if !json_output {
		output::info(&format!(
			"Installing dependencies for {}",
			pkg_name.bold()
		));
	}

	let deps = pkg.dependencies.clone();
	if deps.is_empty() {
		if !json_output {
			output::success("No dependencies to install");
		}
		return Ok(());
	}

	// Collect overrides from package.json (npm overrides + yarn resolutions)
	let mut overrides = pkg.overrides.clone();
	for (k, v) in &pkg.resolutions {
		overrides.entry(k.clone()).or_insert_with(|| v.clone());
	}

	// Step 2: Try lockfile fast path, else resolve
	let lockfile_path = project_dir.join(lpm_lockfile::LOCKFILE_NAME);
	let arc_client = Arc::new(client.clone_with_config());

	// Offline mode: require lockfile, no network
	if offline {
		let locked = try_lockfile_fast_path(&lockfile_path, &deps).ok_or_else(|| {
			LpmError::Registry(
				"--offline requires a lockfile. Run `lpm-rs install` online first.".into(),
			)
		})?;
		if !json_output {
			output::info(&format!(
				"Offline: using lockfile ({} packages)",
				locked.len().to_string().bold()
			));
		}

		// Verify all packages are in the global store
		let store = PackageStore::default_location()?;
		let mut missing = Vec::new();
		for p in &locked {
			if !store.has_package(&p.name, &p.version) {
				missing.push(format!("{}@{}", p.name, p.version));
			}
		}
		if !missing.is_empty() {
			return Err(LpmError::Registry(format!(
				"--offline: {} package(s) not in global store: {}",
				missing.len(),
				missing[..missing.len().min(5)].join(", ")
			)));
		}

		// Go directly to link step (skip resolution and download)
		return run_link_and_finish(
			client,
			project_dir,
			&deps,
			&pkg,
			locked,
			0,
			0,
			true,
			json_output,
			start,
		)
		.await;
	}

	let (packages, resolve_ms, used_lockfile) =
		match try_lockfile_fast_path(&lockfile_path, &deps) {
			Some(locked_packages) => {
				if !json_output {
					output::info(&format!(
						"Using lockfile ({} packages)",
						locked_packages.len().to_string().bold()
					));
				}
				(locked_packages, 0u128, true)
			}
			None => {
				let resolve_start = Instant::now();
				let spinner = make_spinner("Resolving dependency tree...");

				// Batch prefetch: warm the metadata cache for all root deps in one request.
				// This turns 70+ sequential HTTP requests into 1-3 batch requests.
				// Skip if all root deps are already in the metadata cache (warm install).
				let dep_names: Vec<String> = deps.keys().cloned().collect();
				let cache_has_all = dep_names.iter().all(|name| {
					let cache_key = if name.starts_with("@lpm.dev/") {
						format!("lpm:{name}")
					} else {
						format!("npm:{name}")
					};
					// Check if metadata cache file exists and is fresh
					let cache_dir = dirs::home_dir()
						.map(|h| h.join(".lpm").join("cache").join("metadata"));
					cache_dir
						.and_then(|dir| {
							use sha2::{Digest, Sha256};
							let mut hasher = Sha256::new();
							hasher.update(cache_key.as_bytes());
							let hash = format!("{:x}", hasher.finalize());
							let path = dir.join(&hash[..16]);
							let modified = path.metadata().ok()?.modified().ok()?;
							let age = std::time::SystemTime::now().duration_since(modified).ok()?;
							Some(age < std::time::Duration::from_secs(300))
						})
						.unwrap_or(false)
				});

				if !dep_names.is_empty() && !cache_has_all {
					match arc_client.batch_metadata(&dep_names).await {
						Ok(batch) => {
							tracing::debug!(
								"batch prefetch: {} root deps cached",
								batch.len()
							);

							// Wave 2: also prefetch transitive deps discovered from wave 1
							let mut transitive: Vec<String> = Vec::new();
							for meta in batch.values() {
								for ver_meta in meta.versions.values() {
									for dep_name in ver_meta.dependencies.keys() {
										if !batch.contains_key(dep_name) && !transitive.contains(dep_name) {
											transitive.push(dep_name.clone());
										}
									}
								}
							}
							if !transitive.is_empty() {
								if let Ok(wave2) = arc_client.batch_metadata(&transitive).await {
									tracing::debug!(
										"batch prefetch wave 2: {} transitive deps cached",
										wave2.len()
									);

									// Wave 3: one more level of transitive deps
									let mut wave3_deps: Vec<String> = Vec::new();
									let all_cached: std::collections::HashSet<String> = batch
										.keys()
										.chain(wave2.keys())
										.cloned()
										.collect();
									for meta in wave2.values() {
										for ver_meta in meta.versions.values() {
											for dep_name in ver_meta.dependencies.keys() {
												if !all_cached.contains(dep_name) && !wave3_deps.contains(dep_name) {
													wave3_deps.push(dep_name.clone());
												}
											}
										}
									}
									if !wave3_deps.is_empty() {
										if let Ok(wave3) = arc_client.batch_metadata(&wave3_deps).await {
											tracing::debug!(
												"batch prefetch wave 3: {} deps cached",
												wave3.len()
											);
										}
									}
								}
							}
						}
						Err(e) => {
							// Non-fatal: resolver will fetch individually as fallback
							tracing::debug!("batch prefetch failed (non-fatal): {e}");
						}
					}
				}

				let resolved =
					resolve_dependencies_with_overrides(
						arc_client.clone(),
						deps.clone(),
						overrides.clone(),
					)
					.await
					.map_err(|e| {
						LpmError::Registry(format!("resolution failed: {e}"))
					})?;

				let ms = resolve_start.elapsed().as_millis();
				spinner.finish_and_clear();

				let packages = resolved_to_install_packages(&resolved, &deps);

				if !json_output {
					output::info(&format!(
						"Resolved {} packages ({}ms)",
						packages.len().to_string().bold(),
						ms
					));
				}
				(packages, ms, false)
			}
		};

	// Step 3: Download & store (parallel)
	let fetch_start = Instant::now();
	let store = PackageStore::default_location()?;

	let mut to_download = Vec::new();
	let mut cached = 0usize;

	for p in &packages {
		if store.has_package(&p.name, &p.version) {
			cached += 1;
		} else {
			to_download.push(p.clone());
		}
	}

	let downloaded = to_download.len();
	if !to_download.is_empty() {
		let overall = ProgressBar::new(to_download.len() as u64);
		overall.set_style(
			ProgressStyle::default_bar()
				.template(
					"{spinner:.cyan} Downloading [{bar:30.cyan/dim}] {pos}/{len} {msg}",
				)
				.unwrap()
				.progress_chars("━╸─"),
		);
		overall.enable_steady_tick(std::time::Duration::from_millis(80));

		let semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT_DOWNLOADS));
		let mut handles = Vec::new();

		for p in to_download {
			let sem = semaphore.clone();
			let client = arc_client.clone();
			let store_ref = store.clone();
			let overall = overall.clone();

			handles.push(tokio::spawn(async move {
				let _permit = sem
					.acquire()
					.await
					.map_err(|_| LpmError::Registry("download semaphore closed".into()))?;

				overall.set_message(format!("{}@{}", p.name, p.version));

				let tarball_data =
					fetch_tarball_by_name(&client, &p.name, &p.version, p.is_lpm)
						.await?;
				store_ref.store_package(&p.name, &p.version, &tarball_data)?;

				overall.inc(1);
				Ok::<(), LpmError>(())
			}));
		}

		for handle in handles {
			handle
				.await
				.map_err(|e| LpmError::Registry(format!("download task panicked: {e}")))??;
		}

		overall.finish_and_clear();
	}

	let fetch_ms = fetch_start.elapsed().as_millis();
	if !json_output {
		if downloaded > 0 {
			output::info(&format!(
				"Downloaded {} packages, {} from cache ({}ms)",
				downloaded.to_string().bold(),
				cached,
				fetch_ms
			));
		} else {
			output::info(&format!("All {} packages from cache", cached));
		}
	}

	// Step 4: Build link targets
	let link_targets: Vec<LinkTarget> = packages
		.iter()
		.map(|p| LinkTarget {
			name: p.name.clone(),
			version: p.version.clone(),
			store_path: store.package_dir(&p.name, &p.version),
			dependencies: p.dependencies.clone(),
			is_direct: p.is_direct,
		})
		.collect();

	// Step 5: Link into node_modules
	let link_start = Instant::now();
	let spinner = make_spinner("Linking node_modules...");

	let link_result = lpm_linker::link_packages(project_dir, &link_targets)?;

	let link_ms = link_start.elapsed().as_millis();
	spinner.finish_and_clear();

	// Step 6: Lifecycle script security audit
	let policy =
		lpm_security::SecurityPolicy::from_package_json(&project_dir.join("package.json"));
	let audit = lpm_security::audit_lifecycle_scripts(project_dir, &policy);
	if !audit.blocked.is_empty() && !json_output {
		output::warn(&format!(
			"{} package(s) have lifecycle scripts (blocked by default):",
			audit.blocked.len()
		));
		for bp in &audit.blocked {
			println!(
				"    {} ({})",
				bp.name.dimmed(),
				bp.scripts.join(", ").dimmed()
			);
		}
		println!(
			"  Trust them: add to {} in package.json",
			"\"lpm\": { \"trustedDependencies\": [...] }".dimmed()
		);
	}

	// Step 7: LPM-Native Intelligence (Phase 5)
	// Read strictness from package.json "lpm" config
	let strict_deps = pkg
		.lpm
		.as_ref()
		.and_then(|l| l.strict_deps.as_deref())
		.unwrap_or("warn");

	if strict_deps != "loose" && !json_output {
		let installed_names: std::collections::HashSet<String> =
			packages.iter().map(|p| p.name.clone()).collect();

		// Phantom dependency detection
		let phantom_result = crate::intelligence::detect_phantom_deps(
			project_dir,
			&deps,
			&installed_names,
		);

		if !phantom_result.phantom_imports.is_empty() {
			let icon = if strict_deps == "strict" { "✖" } else { "⚠" };
			println!();
			output::warn(&format!(
				"{}  {} phantom dependency import(s) detected:",
				icon,
				phantom_result.phantom_imports.len()
			));
			for phantom in phantom_result.phantom_imports.iter().take(5) {
				let rel_file = phantom
					.file
					.strip_prefix(project_dir)
					.unwrap_or(&phantom.file);
				println!(
					"    {} ({}:{})",
					phantom.package_name.bold(),
					rel_file.display().to_string().dimmed(),
					phantom.line,
				);
				if let Some(via) = &phantom.available_via {
					println!("      {}", via.dimmed());
				}
				println!(
					"      Fix: {}",
					format!("lpm-rs install {}", phantom.package_name).dimmed()
				);
			}
			if phantom_result.phantom_imports.len() > 5 {
				println!(
					"    ... and {} more",
					phantom_result.phantom_imports.len() - 5
				);
			}
		}

		// Import verification (only in strict mode)
		if strict_deps == "strict" {
			let verification = crate::intelligence::verify_imports(
				project_dir,
				&installed_names,
				&deps,
			);
			if !verification.unresolved.is_empty() {
				println!();
				output::warn(&format!(
					"✖  {} import(s) will fail at runtime:",
					verification.unresolved.len()
				));
				for unresolved in &verification.unresolved {
					let rel_file = unresolved
						.file
						.strip_prefix(project_dir)
						.unwrap_or(&unresolved.file);
					println!(
						"    {}:{} → {}",
						rel_file.display().to_string().dimmed(),
						unresolved.line,
						format!("import \"{}\"", unresolved.specifier).bold(),
					);
					println!("      {}", unresolved.suggestion.dimmed());
				}
			}
		}

		// Quality warnings for LPM packages
		let lpm_packages: Vec<(String, String)> = packages
			.iter()
			.filter(|p| p.is_lpm)
			.map(|p| (p.name.clone(), p.version.clone()))
			.collect();

		if !lpm_packages.is_empty() {
			let quality_threshold = pkg
				.lpm
				.as_ref()
				.and_then(|l| l.strict_deps.as_deref()) // reuse as quality gate
				.map(|_| 50u32) // warn if below 50 when any strictness is set
				.unwrap_or(30); // default: only warn below 30

			let warnings = crate::intelligence::check_install_quality(
				&lpm_registry::RegistryClient::new()
					.with_base_url(
						std::env::var("LPM_REGISTRY_URL")
							.unwrap_or_else(|_| lpm_common::DEFAULT_REGISTRY_URL.to_string()),
					)
					.with_token(
						crate::auth::get_token(
							&std::env::var("LPM_REGISTRY_URL")
								.unwrap_or_else(|_| lpm_common::DEFAULT_REGISTRY_URL.to_string()),
						)
						.unwrap_or_default(),
					),
				&lpm_packages,
				quality_threshold,
			)
			.await;

			for warning in &warnings {
				let icon = match warning.severity {
					crate::intelligence::WarningSeverity::Critical => "✖".to_string(),
					crate::intelligence::WarningSeverity::Warning => "⚠".to_string(),
					crate::intelligence::WarningSeverity::Info => "ℹ".to_string(),
				};
				println!(
					"  {icon} {}@{}: {}",
					warning.package_name, warning.version, warning.message
				);
			}

			// Security warnings for LPM packages (AI-detected findings + behavioral tags)
			let security_map: HashMap<String, String> = lpm_packages.iter().cloned().collect();
			crate::security_check::check_installed_packages(
				&lpm_registry::RegistryClient::new()
					.with_base_url(
						std::env::var("LPM_REGISTRY_URL")
							.unwrap_or_else(|_| lpm_common::DEFAULT_REGISTRY_URL.to_string()),
					)
					.with_token(
						crate::auth::get_token(
							&std::env::var("LPM_REGISTRY_URL")
								.unwrap_or_else(|_| lpm_common::DEFAULT_REGISTRY_URL.to_string()),
						)
						.unwrap_or_default(),
					),
				&security_map,
				json_output,
			)
			.await;
		}
	}

	// Step 8: Write lockfile (only if we resolved fresh)
	if !used_lockfile {
		let mut lockfile = lpm_lockfile::Lockfile::new();
		for p in &packages {
			let dep_strings: Vec<String> = p
				.dependencies
				.iter()
				.map(|(dep_name, dep_ver)| format!("{dep_name}@{dep_ver}"))
				.collect();

			lockfile.add_package(lpm_lockfile::LockedPackage {
				name: p.name.clone(),
				version: p.version.clone(),
				source: Some(p.source.clone()),
				integrity: None,
				dependencies: dep_strings,
			});
		}

		lockfile
			.write_all(&lockfile_path)
			.map_err(|e| LpmError::Registry(format!("failed to write lockfile: {e}")))?;
	}

	let elapsed = start.elapsed();

	if json_output {
		let json = serde_json::json!({
			"packages": packages.len(),
			"downloaded": downloaded,
			"cached": cached,
			"linked": link_result.linked,
			"symlinked": link_result.symlinked,
			"used_lockfile": used_lockfile,
			"timing": {
				"resolve_ms": resolve_ms,
				"fetch_ms": fetch_ms,
				"link_ms": link_ms,
				"total_ms": elapsed.as_millis(),
			},
		});
		println!("{}", serde_json::to_string_pretty(&json).unwrap());
	} else {
		println!();
		output::success(&format!(
			"{} packages installed in {:.1}s",
			packages.len().to_string().bold(),
			elapsed.as_secs_f64()
		));
		println!(
			"  {} linked, {} symlinked",
			link_result.linked.to_string().dimmed(),
			link_result.symlinked.to_string().dimmed(),
		);
		println!(
			"  resolve: {}ms  fetch: {}ms  link: {}ms",
			resolve_ms.to_string().dimmed(),
			fetch_ms.to_string().dimmed(),
			link_ms.to_string().dimmed(),
		);
		println!();
	}

	Ok(())
}

/// Try to use the lockfile as a fast path.
///
/// Returns `Some(packages)` if the lockfile exists AND every declared dependency
/// in package.json has a matching entry in the lockfile. Otherwise returns `None`
/// to signal that fresh resolution is needed.
fn try_lockfile_fast_path(
	lockfile_path: &Path,
	deps: &HashMap<String, String>,
) -> Option<Vec<InstallPackage>> {
	if !lpm_lockfile::Lockfile::exists(lockfile_path) {
		return None;
	}

	let lockfile = lpm_lockfile::Lockfile::read_fast(lockfile_path).ok()?;

	// Verify every declared dep has a lockfile entry
	for dep_name in deps.keys() {
		if lockfile.find_package(dep_name).is_none() {
			tracing::debug!("lockfile miss: {dep_name} not found, re-resolving");
			return None;
		}
	}

	// Build the direct dep set for is_direct marking
	let direct_deps: std::collections::HashSet<&str> =
		deps.keys().map(|s| s.as_str()).collect();

	// Convert locked packages to InstallPackage
	let packages: Vec<InstallPackage> = lockfile
		.packages
		.iter()
		.map(|lp| {
			let is_lpm = lp.name.starts_with("@lpm.dev/");

			// Parse dependency strings back to (name, version) tuples
			let dependencies: Vec<(String, String)> = lp
				.dependencies
				.iter()
				.filter_map(|dep_str| {
					// Format: "name@version"
					dep_str.rfind('@').map(|at| {
						(dep_str[..at].to_string(), dep_str[at + 1..].to_string())
					})
				})
				.collect();

			InstallPackage {
				name: lp.name.clone(),
				version: lp.version.clone(),
				source: lp
					.source
					.clone()
					.unwrap_or_else(|| "registry+https://registry.npmjs.org".to_string()),
				dependencies,
				is_direct: direct_deps.contains(lp.name.as_str()),
				is_lpm,
			}
		})
		.collect();

	Some(packages)
}

/// Convert resolver output to InstallPackage list.
fn resolved_to_install_packages(
	resolved: &[ResolvedPackage],
	deps: &HashMap<String, String>,
) -> Vec<InstallPackage> {
	resolved
		.iter()
		.map(|r| {
			let name = r.package.canonical_name();
			let is_lpm = r.package.is_lpm();
			let source = if is_lpm {
				"registry+https://lpm.dev".to_string()
			} else {
				"registry+https://registry.npmjs.org".to_string()
			};

			InstallPackage {
				name: name.clone(),
				version: r.version.to_string(),
				source,
				dependencies: r.dependencies.clone(),
				is_direct: deps.contains_key(&name),
				is_lpm,
			}
		})
		.collect()
}

/// Offline/shared path: link packages from store, write lockfile, print output.
#[allow(clippy::too_many_arguments)]
async fn run_link_and_finish(
	_client: &RegistryClient,
	project_dir: &Path,
	deps: &HashMap<String, String>,
	_pkg: &lpm_workspace::PackageJson,
	packages: Vec<InstallPackage>,
	downloaded: usize,
	cached: usize,
	used_lockfile: bool,
	json_output: bool,
	start: Instant,
) -> Result<(), LpmError> {
	let store = PackageStore::default_location()?;

	let link_targets: Vec<LinkTarget> = packages
		.iter()
		.map(|p| LinkTarget {
			name: p.name.clone(),
			version: p.version.clone(),
			store_path: store.package_dir(&p.name, &p.version),
			dependencies: p.dependencies.clone(),
			is_direct: p.is_direct,
		})
		.collect();

	let link_start = Instant::now();
	let link_result = lpm_linker::link_packages(project_dir, &link_targets)?;
	let link_ms = link_start.elapsed().as_millis();

	// Write lockfile if needed
	if !used_lockfile {
		let lockfile_path = project_dir.join(lpm_lockfile::LOCKFILE_NAME);
		let mut lockfile = lpm_lockfile::Lockfile::new();
		for p in &packages {
			let dep_strings: Vec<String> = p
				.dependencies
				.iter()
				.map(|(n, v)| format!("{n}@{v}"))
				.collect();
			lockfile.add_package(lpm_lockfile::LockedPackage {
				name: p.name.clone(),
				version: p.version.clone(),
				source: Some(p.source.clone()),
				integrity: None,
				dependencies: dep_strings,
			});
		}
		lockfile
			.write_all(&lockfile_path)
			.map_err(|e| LpmError::Registry(format!("failed to write lockfile: {e}")))?;
	}

	let elapsed = start.elapsed();

	if json_output {
		let json = serde_json::json!({
			"packages": packages.len(),
			"downloaded": downloaded,
			"cached": cached,
			"linked": link_result.linked,
			"symlinked": link_result.symlinked,
			"used_lockfile": used_lockfile,
			"offline": true,
			"timing": {
				"link_ms": link_ms,
				"total_ms": elapsed.as_millis(),
			},
		});
		println!("{}", serde_json::to_string_pretty(&json).unwrap());
	} else {
		println!();
		output::success(&format!(
			"{} packages installed in {:.1}s",
			packages.len().to_string().bold(),
			elapsed.as_secs_f64()
		));
		println!(
			"  {} linked, {} symlinked",
			link_result.linked.to_string().dimmed(),
			link_result.symlinked.to_string().dimmed(),
		);
		println!();
	}

	Ok(())
}

/// Fetch tarball by package name and version (used for both fresh and lockfile installs).
async fn fetch_tarball_by_name(
	client: &Arc<RegistryClient>,
	name: &str,
	version: &str,
	is_lpm: bool,
) -> Result<Vec<u8>, LpmError> {
	if is_lpm {
		let pkg = lpm_common::PackageName::parse(name)
			.map_err(|e| LpmError::Registry(e.to_string()))?;
		let metadata = client.get_package_metadata(&pkg).await?;
		let ver_meta = metadata.version(version).ok_or_else(|| {
			LpmError::NotFound(format!("{name}@{version} not found in metadata"))
		})?;
		let url = ver_meta.tarball_url().ok_or_else(|| {
			LpmError::NotFound(format!("no tarball URL for {name}@{version}"))
		})?;
		client.download_tarball(url).await
	} else {
		let metadata = client.get_npm_package_metadata(name).await?;
		let ver_meta = metadata.version(version).ok_or_else(|| {
			LpmError::NotFound(format!("{name}@{version} not found in metadata"))
		})?;
		let url = ver_meta.tarball_url().ok_or_else(|| {
			LpmError::NotFound(format!("no tarball URL for {name}@{version}"))
		})?;
		client.download_tarball(url).await
	}
}

/// Install specific packages: add them to package.json then run full install.
///
/// Handles specs like: `express`, `express@^4.0.0`, `@lpm.dev/neo.highlight@1.0.0`
pub async fn run_add_packages(
	client: &RegistryClient,
	project_dir: &Path,
	packages: &[String],
	save_dev: bool,
	json_output: bool,
) -> Result<(), LpmError> {
	let pkg_json_path = project_dir.join("package.json");
	if !pkg_json_path.exists() {
		return Err(LpmError::NotFound(
			"no package.json found in current directory".to_string(),
		));
	}

	// Read current package.json as raw JSON to preserve formatting
	let content = std::fs::read_to_string(&pkg_json_path)?;
	let mut doc: serde_json::Value =
		serde_json::from_str(&content).map_err(|e| LpmError::Registry(e.to_string()))?;

	let dep_key = if save_dev {
		"devDependencies"
	} else {
		"dependencies"
	};

	// Ensure the deps object exists
	if doc.get(dep_key).is_none() {
		doc[dep_key] = serde_json::json!({});
	}

	// Parse and add each package spec
	for spec in packages {
		let (name, range) = parse_package_spec(spec);
		if !json_output {
			output::info(&format!("Adding {}@{} to {}", name.bold(), range, dep_key));
		}
		doc[dep_key][&name] = serde_json::Value::String(range);
	}

	// Write updated package.json
	let updated = serde_json::to_string_pretty(&doc)
		.map_err(|e| LpmError::Registry(e.to_string()))?;
	std::fs::write(&pkg_json_path, format!("{updated}\n"))?;

	// Remove lockfile to force re-resolution with new deps
	let lockfile_path = project_dir.join(lpm_lockfile::LOCKFILE_NAME);
	if lockfile_path.exists() {
		std::fs::remove_file(&lockfile_path)?;
	}

	// Run full install
	run(client, project_dir, json_output).await
}

/// Parse a package spec like `express@^4.0.0` into (name, range).
/// If no range is specified, defaults to `*` (latest).
fn parse_package_spec(spec: &str) -> (String, String) {
	// Handle scoped packages: @scope/name@version
	if spec.starts_with('@') {
		// Find the second @ (version separator)
		if let Some(at_pos) = spec[1..].find('@') {
			let at_pos = at_pos + 1; // adjust for the skip
			return (spec[..at_pos].to_string(), spec[at_pos + 1..].to_string());
		}
		// No version specified for scoped package
		return (spec.to_string(), "*".to_string());
	}

	// Unscoped: name@version
	if let Some(at_pos) = spec.find('@') {
		(spec[..at_pos].to_string(), spec[at_pos + 1..].to_string())
	} else {
		(spec.to_string(), "*".to_string())
	}
}

fn make_spinner(msg: &str) -> ProgressBar {
	let spinner = ProgressBar::new_spinner();
	spinner.set_style(
		ProgressStyle::default_spinner()
			.template("{spinner:.cyan} {msg}")
			.unwrap(),
	);
	spinner.set_message(msg.to_string());
	spinner.enable_steady_tick(std::time::Duration::from_millis(80));
	spinner
}
