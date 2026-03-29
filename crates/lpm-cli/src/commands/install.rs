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
	/// SRI integrity hash for verification (e.g. "sha512-...")
	integrity: Option<String>,
}

pub async fn run_with_options(
	client: &RegistryClient,
	project_dir: &Path,
	json_output: bool,
	offline: bool,
	allow_new: bool,
	linker_override: Option<&str>,
	no_skills: bool,
) -> Result<(), LpmError> {
	if !json_output {
		output::print_header();
	}

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

	let mut deps = pkg.dependencies.clone();

	// Resolve workspace:* protocol before anything else (lockfile fast path, resolver).
	// This ensures deps HashMap contains real semver ranges, not workspace: references.
	if let Ok(Some(workspace)) = lpm_workspace::discover_workspace(project_dir) {
		let resolved = lpm_workspace::resolve_workspace_protocol(&mut deps, &workspace);
		if !resolved.is_empty() && !json_output {
			for (name, _original, resolved_ver) in &resolved {
				tracing::debug!("workspace protocol: {name} → {resolved_ver}");
			}
		}

		// Also resolve in devDependencies stored on the pkg (not used for install,
		// but keeps consistency if other commands read them post-resolution)
	}

	// Resolve catalog: protocol (centralized version management for monorepos).
	// catalog: → catalogs["default"], catalog:testing → catalogs["testing"].
	if !pkg.catalogs.is_empty() {
		match lpm_workspace::resolve_catalog_protocol(&mut deps, &pkg.catalogs) {
			Ok(resolved) => {
				if !resolved.is_empty() && !json_output {
					for (name, _orig, ver) in &resolved {
						tracing::debug!("catalog: {name} → {ver}");
					}
				}
			}
			Err(e) => {
				return Err(LpmError::Registry(format!(
					"catalog resolution failed: {e}"
				)));
			}
		}
	}

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

	// Determine linker mode early: CLI flag > package.json config > default (isolated)
	let linker_mode = linker_override
		.or_else(|| pkg.lpm.as_ref().and_then(|l| l.linker.as_deref()))
		.map(|s| match s {
			"hoisted" => lpm_linker::LinkerMode::Hoisted,
			_ => lpm_linker::LinkerMode::Isolated,
		})
		.unwrap_or(lpm_linker::LinkerMode::Isolated);

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
			linker_mode,
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

	// Enforce minimumReleaseAge: block recently published packages unless --allow-new.
	// Only checked during fresh resolution (not lockfile fast path) because metadata
	// was already fetched and cached by the resolver — re-fetching hits the 5-min TTL cache.
	if !allow_new && !used_lockfile {
		let policy =
			lpm_security::SecurityPolicy::from_package_json(&project_dir.join("package.json"));
		if policy.minimum_release_age_secs > 0 {
			let mut too_new = Vec::new();
			for p in &packages {
				// Look up the publish timestamp from the metadata cache.
				// During fresh resolution the resolver already fetched all metadata,
				// so these calls hit the local cache (no extra network round-trips).
				let publish_time = if p.is_lpm {
					lpm_common::PackageName::parse(&p.name)
						.ok()
						.and_then(|pkg_name| {
							// This will hit the TTL cache (< 5 min since resolution)
							tokio::task::block_in_place(|| {
								tokio::runtime::Handle::current().block_on(
									arc_client.get_package_metadata(&pkg_name),
								)
							})
							.ok()
						})
						.and_then(|meta| meta.time.get(&p.version).cloned())
				} else {
					tokio::task::block_in_place(|| {
						tokio::runtime::Handle::current()
							.block_on(arc_client.get_npm_package_metadata(&p.name))
					})
					.ok()
					.and_then(|meta| meta.time.get(&p.version).cloned())
				};

				if let Some(published_at) = publish_time {
					if let Some(remaining) = policy.check_release_age(&published_at) {
						let hours = remaining / 3600;
						let minutes = (remaining % 3600) / 60;
						too_new.push((p.name.clone(), p.version.clone(), hours, minutes));
					}
				}
			}

			if !too_new.is_empty() {
				if !json_output {
					output::warn(&format!(
						"{} package(s) blocked by minimumReleaseAge ({}s):",
						too_new.len(),
						policy.minimum_release_age_secs,
					));
					for (name, version, hours, minutes) in &too_new {
						eprintln!(
							"    {}@{} — {}h {}m remaining",
							name, version, hours, minutes
						);
					}
					eprintln!(
						"  Use {} to install anyway, or add {} to package.json to disable.",
						"--allow-new".bold(),
						"\"lpm\": { \"minimumReleaseAge\": 0 }".dimmed(),
					);
				}
				return Err(LpmError::Registry(format!(
					"{} package(s) published too recently (minimumReleaseAge={}s). Use --allow-new to override.",
					too_new.len(),
					policy.minimum_release_age_secs,
				)));
			}
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

				// Verify integrity before storing — prevents tampered tarballs
				// from entering the global store
				if let Some(ref integrity) = p.integrity {
					if let Err(e) = lpm_extractor::verify_integrity(&tarball_data, integrity) {
						return Err(LpmError::Registry(format!(
							"integrity verification failed for {}@{}: {e}",
							p.name, p.version
						)));
					}
				} else {
					tracing::debug!(
						"no integrity hash for {}@{}, skipping verification",
						p.name, p.version
					);
				}

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

	let link_result = match linker_mode {
		lpm_linker::LinkerMode::Hoisted => {
			lpm_linker::link_packages_hoisted(project_dir, &link_targets, false)?
		}
		lpm_linker::LinkerMode::Isolated => {
			lpm_linker::link_packages(project_dir, &link_targets, false, pkg.name.as_deref())?
		}
	};

	let link_ms = link_start.elapsed().as_millis();
	spinner.finish_and_clear();

	// Step 6: Lifecycle script security audit + trusted script execution
	let policy =
		lpm_security::SecurityPolicy::from_package_json(&project_dir.join("package.json"));
	let audit = lpm_security::audit_lifecycle_scripts(project_dir, &policy);

	// Report blocked packages
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

	// Execute lifecycle scripts for trusted packages
	if !audit.trusted.is_empty() {
		run_trusted_lifecycle_scripts(project_dir, &audit.trusted, &packages, json_output);
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

	// Step 8: Auto-install skills for direct LPM packages
	if !json_output && !no_skills {
		let lpm_packages: Vec<String> = packages
			.iter()
			.filter(|p| p.is_lpm && p.is_direct)
			.map(|p| p.name.clone())
			.collect();

		if !lpm_packages.is_empty() {
			install_skills_for_packages(&arc_client, &lpm_packages, project_dir).await;
		}
	}

	// Step 9: Write lockfile (only if we resolved fresh)
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

		lpm_lockfile::ensure_gitattributes(project_dir)
			.map_err(|e| LpmError::Registry(format!("failed to ensure .gitattributes: {e}")))?;

		if !json_output {
			let lockb_path = lockfile_path.with_extension("lockb");
			let lockb_size = std::fs::metadata(&lockb_path).map(|m| m.len()).unwrap_or(0);
			output::info(&format!(
				"Lockfile  lpm.lock ({} packages) + lpm.lockb ({})",
				lockfile.packages.len(),
				lpm_common::format_bytes(lockb_size),
			));
		}
	}

	let elapsed = start.elapsed();

	if json_output {
		let pkg_list: Vec<serde_json::Value> = packages
			.iter()
			.map(|p| {
				serde_json::json!({
					"name": p.name,
					"version": p.version,
					"source": p.source,
					"direct": p.is_direct,
				})
			})
			.collect();

		let json = serde_json::json!({
			"packages": pkg_list,
			"count": packages.len(),
			"downloaded": downloaded,
			"cached": cached,
			"linked": link_result.linked,
			"symlinked": link_result.symlinked,
			"used_lockfile": used_lockfile,
			"duration_ms": elapsed.as_millis() as u64,
			"timing": {
				"resolve_ms": resolve_ms,
				"fetch_ms": fetch_ms,
				"link_ms": link_ms,
				"total_ms": elapsed.as_millis(),
			},
			"warnings": [],
			"errors": [],
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

	// Validate all package sources are safe (HTTPS registries or localhost)
	for lp in &lockfile.packages {
		if let Some(ref source) = lp.source {
			if !lpm_lockfile::is_safe_source(source) {
				tracing::warn!(
					"package {}@{} has unsafe source URL: {} — skipping lockfile fast path",
					lp.name, lp.version, source
				);
				return None; // Force re-resolution from trusted registries
			}
		}
	}

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
				integrity: lp.integrity.clone(),
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
				integrity: None, // Fresh resolution: integrity verified at download time from registry metadata
			}
		})
		.collect()
}

/// Offline/shared path: link packages from store, write lockfile, print output.
#[allow(clippy::too_many_arguments)]
async fn run_link_and_finish(
	_client: &RegistryClient,
	project_dir: &Path,
	_deps: &HashMap<String, String>,
	_pkg: &lpm_workspace::PackageJson,
	packages: Vec<InstallPackage>,
	downloaded: usize,
	cached: usize,
	used_lockfile: bool,
	json_output: bool,
	start: Instant,
	linker_mode: lpm_linker::LinkerMode,
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
	let link_result = match linker_mode {
		lpm_linker::LinkerMode::Hoisted => {
			lpm_linker::link_packages_hoisted(project_dir, &link_targets, false)?
		}
		lpm_linker::LinkerMode::Isolated => {
			lpm_linker::link_packages(project_dir, &link_targets, false, _pkg.name.as_deref())?
		}
	};
	let link_ms = link_start.elapsed().as_millis();

	// Lifecycle script security audit + trusted script execution (same as online path)
	{
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

		if !audit.trusted.is_empty() {
			run_trusted_lifecycle_scripts(project_dir, &audit.trusted, &packages, json_output);
		}
	}

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

		lpm_lockfile::ensure_gitattributes(project_dir)
			.map_err(|e| LpmError::Registry(format!("failed to ensure .gitattributes: {e}")))?;

		if !json_output {
			let lockb_path = lockfile_path.with_extension("lockb");
			let lockb_size = std::fs::metadata(&lockb_path).map(|m| m.len()).unwrap_or(0);
			output::info(&format!(
				"Lockfile  lpm.lock ({} packages) + lpm.lockb ({})",
				lockfile.packages.len(),
				lpm_common::format_bytes(lockb_size),
			));
		}
	}

	let elapsed = start.elapsed();

	if json_output {
		let pkg_list: Vec<serde_json::Value> = packages
			.iter()
			.map(|p| {
				serde_json::json!({
					"name": p.name,
					"version": p.version,
					"source": p.source,
					"direct": p.is_direct,
				})
			})
			.collect();

		let json = serde_json::json!({
			"packages": pkg_list,
			"count": packages.len(),
			"downloaded": downloaded,
			"cached": cached,
			"linked": link_result.linked,
			"symlinked": link_result.symlinked,
			"used_lockfile": used_lockfile,
			"offline": true,
			"duration_ms": elapsed.as_millis() as u64,
			"timing": {
				"link_ms": link_ms,
				"total_ms": elapsed.as_millis(),
			},
			"warnings": [],
			"errors": [],
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
/// For Swift packages (ecosystem=swift), uses SE-0292 registry mode instead.
///
/// Handles specs like: `express`, `express@^4.0.0`, `@lpm.dev/neo.highlight@1.0.0`
pub async fn run_add_packages(
	client: &RegistryClient,
	project_dir: &Path,
	packages: &[String],
	save_dev: bool,
	json_output: bool,
	allow_new: bool,
) -> Result<(), LpmError> {
	// First pass: check if any LPM packages are Swift ecosystem
	// Route Swift packages to SE-0292 registry mode
	let mut js_packages = Vec::new();

	for spec in packages {
		let (name, range) = parse_package_spec(spec);

		if name.starts_with("@lpm.dev/") {
			// Fetch metadata to check ecosystem
			let pkg_name = lpm_common::PackageName::parse(&name)?;
			let metadata = client.get_package_metadata(&pkg_name).await?;
			let latest_ver = metadata.latest_version_tag().ok_or_else(|| {
				LpmError::NotFound(format!("no versions for {name}"))
			})?;

			// Resolve the user-specified version range against available versions.
			// Falls back to latest when no version is specified.
			let resolved_ver =
				resolve_version_from_spec(&range, &metadata, latest_ver)?;
			let ver_meta = metadata.version(resolved_ver).ok_or_else(|| {
				LpmError::NotFound(format!(
					"version {resolved_ver} not found for {name}"
				))
			})?;

			if ver_meta.effective_ecosystem() == "swift" {
				// SE-0292 registry mode
				run_swift_install(
					project_dir, &pkg_name, resolved_ver, ver_meta, json_output,
				)
				.await?;
				continue;
			}
		}

		js_packages.push(spec.clone());
	}

	// If all packages were Swift, we're done
	if js_packages.is_empty() {
		return Ok(());
	}

	// JS path: add to package.json and run install
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
	for spec in &js_packages {
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

	// Run full install (pass allow_new through to release age check)
	run_with_options(client, project_dir, json_output, false, allow_new, None, false).await
}

/// Install a Swift package via SE-0292 registry: edit Package.swift + resolve.
async fn run_swift_install(
	project_dir: &Path,
	name: &lpm_common::PackageName,
	version: &str,
	ver_meta: &lpm_registry::VersionMetadata,
	json_output: bool,
) -> Result<(), LpmError> {
	use crate::swift_manifest;

	let se0292_id = swift_manifest::lpm_to_se0292_id(name);
	let product_name = ver_meta
		.swift_product_name()
		.unwrap_or_else(|| &name.name);

	let manifest_path = swift_manifest::find_package_swift(project_dir).ok_or_else(|| {
		LpmError::Registry(
			"No Package.swift found. Initialize an SPM project first.".into(),
		)
	})?;

	let manifest_dir = manifest_path.parent().unwrap_or(project_dir);

	if !json_output {
		output::info(&format!(
			"Installing {} via SE-0292 registry → {}",
			name.scoped().bold(),
			se0292_id.dimmed(),
		));
	}

	// Detect targets
	let targets = swift_manifest::get_spm_targets(manifest_dir).unwrap_or_default();
	let target_name = if targets.len() == 1 {
		targets[0].clone()
	} else if targets.len() > 1 {
		let selection = dialoguer::Select::new()
			.with_prompt("Which target should use this dependency?")
			.items(&targets)
			.default(0)
			.interact()
			.map_err(|e| LpmError::Registry(format!("prompt failed: {e}")))?;
		targets[selection].clone()
	} else {
		return Err(LpmError::Registry(
			"No non-test targets found in Package.swift.".into(),
		));
	};

	// Edit Package.swift
	let edit = swift_manifest::add_registry_dependency(
		&manifest_path,
		&se0292_id,
		version,
		product_name,
		&target_name,
	)?;

	if edit.already_exists {
		if !json_output {
			output::info(&format!("{} is already in Package.swift", se0292_id.dimmed()));
		}
	} else if !json_output {
		output::success(&format!(
			"Added .package(id: \"{}\", from: \"{}\")",
			se0292_id, version
		));
		output::success(&format!(
			"Added .product(name: \"{}\") to target {}",
			product_name, target_name.bold()
		));
	}

	// Resolve
	if !edit.already_exists {
		if !json_output {
			output::info("Resolving Swift packages...");
		}
		swift_manifest::run_swift_resolve(manifest_dir)?;
	}

	// Output
	if json_output {
		let json = serde_json::json!({
			"package": name.scoped(),
			"version": version,
			"mode": "registry",
			"se0292_id": se0292_id,
			"product_name": product_name,
			"target": target_name,
			"already_existed": edit.already_exists,
		});
		println!("{}", serde_json::to_string_pretty(&json).unwrap());
	} else if !edit.already_exists {
		println!();
		output::success(&format!(
			"Installed {}@{} via SE-0292 registry",
			name.scoped().bold(),
			version,
		));
		println!("  import {} // in your Swift code", product_name.bold());
	}

	// Security check
	if ver_meta.has_security_issues() && !json_output {
		crate::commands::add::print_security_warnings(&name.scoped(), version, ver_meta);
	}

	if !json_output && !edit.already_exists {
		println!();
	}

	Ok(())
}

/// Execute lifecycle scripts for trusted packages.
///
/// For each trusted package, finds its installed location in node_modules/.lpm/
/// and runs any lifecycle scripts (preinstall, install, postinstall) via the shell.
/// Scripts run with the package's directory as cwd and the project's .bin dirs on PATH.
///
/// Non-fatal: if a script fails, we warn but don't abort the install.
fn run_trusted_lifecycle_scripts(
	project_dir: &Path,
	trusted_names: &[String],
	packages: &[InstallPackage],
	json_output: bool,
) {
	use lpm_runner::bin_path;
	use lpm_runner::shell::{self, ShellCommand};

	let path = bin_path::build_path_with_bins(project_dir);
	let empty_envs = HashMap::new();

	// Build a lookup from package name → version for finding the installed dir
	let pkg_versions: HashMap<&str, &str> = packages
		.iter()
		.map(|p| (p.name.as_str(), p.version.as_str()))
		.collect();

	// Ordered lifecycle scripts — must run in this sequence per npm convention
	let lifecycle_order = ["preinstall", "install", "postinstall"];

	for trusted_name in trusted_names {
		// Find the package's installed directory inside node_modules/.lpm/
		let version = match pkg_versions.get(trusted_name.as_str()) {
			Some(v) => *v,
			None => {
				tracing::debug!("trusted package {trusted_name} not in install set, skipping scripts");
				continue;
			}
		};

		// The package lives at node_modules/.lpm/{name}@{version}/node_modules/{name}/
		let pkg_dir = project_dir
			.join("node_modules")
			.join(".lpm")
			.join(format!("{trusted_name}@{version}"))
			.join("node_modules")
			.join(trusted_name);

		if !pkg_dir.exists() {
			tracing::debug!("trusted package dir not found: {}", pkg_dir.display());
			continue;
		}

		let pkg_json_path = pkg_dir.join("package.json");
		let scripts = lpm_security::SecurityPolicy::detect_lifecycle_scripts(&pkg_json_path);
		if scripts.is_empty() {
			continue;
		}

		// Read the actual script commands from package.json
		let pkg = match lpm_workspace::read_package_json(&pkg_json_path) {
			Ok(p) => p,
			Err(_) => continue,
		};

		for script_name in &lifecycle_order {
			if !scripts.contains(&script_name.to_string()) {
				continue;
			}

			let cmd = match pkg.scripts.get(*script_name) {
				Some(c) => c,
				None => continue,
			};

			if !json_output {
				output::info(&format!(
					"Running {} for {} (trusted)",
					script_name.bold(),
					trusted_name.dimmed(),
				));
			}

			match shell::spawn_shell(&ShellCommand {
				command: cmd,
				cwd: &pkg_dir,
				path: &path,
				envs: &empty_envs,
			}) {
				Ok(status) => {
					if !status.success() {
						let code = status.code().unwrap_or(1);
						if !json_output {
							output::warn(&format!(
								"{} for {} exited with code {}",
								script_name, trusted_name, code
							));
						}
					}
				}
				Err(e) => {
					if !json_output {
						output::warn(&format!(
							"Failed to run {} for {}: {}",
							script_name, trusted_name, e
						));
					}
				}
			}
		}
	}
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

/// Resolve the user-specified version range against a package's available versions.
///
/// When the user specifies a version (e.g., `@1.0.0` or `@^2.0.0`), find the best
/// matching version from metadata. When no version is specified (`*`), fall back to
/// `latest_ver`.
///
/// Returns the resolved version string.
fn resolve_version_from_spec<'a>(
	range_spec: &str,
	metadata: &'a lpm_registry::PackageMetadata,
	latest_ver: &'a str,
) -> Result<&'a str, LpmError> {
	// If no version specified (wildcard), use latest
	if range_spec == "*" {
		return Ok(latest_ver);
	}

	let range = lpm_semver::VersionReq::parse(range_spec).map_err(|_| {
		LpmError::InvalidVersionRange(format!("invalid version range: {range_spec}"))
	})?;

	// Parse all available versions and find the best match
	let mut parsed_versions: Vec<(lpm_semver::Version, &str)> = metadata
		.versions
		.keys()
		.filter_map(|v_str| {
			lpm_semver::Version::parse(v_str)
				.ok()
				.map(|v| (v, v_str.as_str()))
		})
		.collect();

	// Sort so max_satisfying-style logic works
	parsed_versions.sort_by(|a, b| a.0.cmp(&b.0));

	// Find the highest version satisfying the range
	let best = parsed_versions
		.iter()
		.rev()
		.find(|(v, _)| range.matches(v));

	match best {
		Some((_, ver_str)) => Ok(ver_str),
		None => Err(LpmError::NotFound(format!(
			"no version matching {range_spec} found (available: {})",
			metadata
				.versions
				.keys()
				.cloned()
				.collect::<Vec<_>>()
				.join(", ")
		))),
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

/// Auto-install agent skills for direct LPM packages.
///
/// For each direct LPM dependency, fetches its skills from the registry and
/// writes them to `.lpm/skills/{owner.package}/`. Also ensures `.gitignore`
/// includes the skills directory and triggers editor auto-integration.
async fn install_skills_for_packages(
	client: &Arc<RegistryClient>,
	packages: &[String],
	project_dir: &Path,
) {
	let mut total_installed = 0;

	for pkg_name in packages {
		let short_name = pkg_name
			.strip_prefix("@lpm.dev/")
			.unwrap_or(pkg_name);

		match client.get_skills(short_name, None).await {
			Ok(response) if !response.skills.is_empty() => {
				let skills_dir = project_dir
					.join(".lpm")
					.join("skills")
					.join(short_name);
				let _ = std::fs::create_dir_all(&skills_dir);

				for skill in &response.skills {
					let content = skill
						.raw_content
						.as_deref()
						.or(skill.content.as_deref())
						.unwrap_or("");
					if !content.is_empty() {
						let path = skills_dir.join(format!("{}.md", skill.name));
						let _ = std::fs::write(&path, content);
						total_installed += 1;
					}
				}
			}
			_ => {} // No skills or API error — skip silently
		}
	}

	if total_installed > 0 {
		output::info(&format!("Installed {total_installed} agent skill(s)"));

		// Ensure .gitignore includes .lpm/skills/
		ensure_skills_gitignore(project_dir);

		// Auto-integrate with editors
		let integrations = crate::editor_skills::auto_integrate_skills(project_dir);
		for msg in &integrations {
			output::info(msg);
		}
	}
}

/// Ensure `.gitignore` contains an entry for `.lpm/skills/`.
pub fn ensure_skills_gitignore(project_dir: &Path) {
	let gitignore_path = project_dir.join(".gitignore");
	let marker = ".lpm/skills/";

	if gitignore_path.exists() {
		let content = std::fs::read_to_string(&gitignore_path).unwrap_or_default();
		if content.contains(marker) {
			return; // Already present
		}
		let mut new = content;
		if !new.ends_with('\n') {
			new.push('\n');
		}
		new.push_str(&format!(
			"\n# LPM Agent Skills (auto-generated)\n{marker}\n"
		));
		let _ = std::fs::write(&gitignore_path, new);
	} else {
		let _ = std::fs::write(
			&gitignore_path,
			format!("# LPM Agent Skills\n{marker}\n"),
		);
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	/// Build a PackageMetadata with the given version strings and latest tag.
	fn make_metadata(versions: &[&str], latest: &str) -> lpm_registry::PackageMetadata {
		let mut version_map = std::collections::HashMap::new();
		for &v in versions {
			version_map.insert(
				v.to_string(),
				lpm_registry::VersionMetadata {
					name: "@lpm.dev/acme.swift-logger".to_string(),
					version: v.to_string(),
					description: None,
					dependencies: Default::default(),
					dev_dependencies: Default::default(),
					peer_dependencies: Default::default(),
					optional_dependencies: Default::default(),
					os: vec![],
					cpu: vec![],
					dist: None,
					readme: None,
					lpm_config: None,
					ecosystem: Some("swift".to_string()),
					swift_meta: None,
					behavioral_tags: None,
					lifecycle_scripts: None,
					security_findings: None,
					quality_score: None,
				},
			);
		}

		let mut dist_tags = std::collections::HashMap::new();
		dist_tags.insert("latest".to_string(), latest.to_string());

		lpm_registry::PackageMetadata {
			name: "@lpm.dev/acme.swift-logger".to_string(),
			description: None,
			dist_tags,
			versions: version_map,
			time: Default::default(),
			downloads: None,
			distribution_mode: None,
			package_type: None,
			latest_version: Some(latest.to_string()),
			ecosystem: Some("swift".to_string()),
		}
	}

	// ── parse_package_spec ──────────────────────────────────────────

	#[test]
	fn parse_spec_scoped_with_exact_version() {
		let (name, range) = parse_package_spec("@lpm.dev/acme.swift-logger@1.0.0");
		assert_eq!(name, "@lpm.dev/acme.swift-logger");
		assert_eq!(range, "1.0.0");
	}

	#[test]
	fn parse_spec_scoped_with_caret_version() {
		let (name, range) = parse_package_spec("@lpm.dev/acme.swift-logger@^2.0.0");
		assert_eq!(name, "@lpm.dev/acme.swift-logger");
		assert_eq!(range, "^2.0.0");
	}

	#[test]
	fn parse_spec_scoped_no_version() {
		let (name, range) = parse_package_spec("@lpm.dev/acme.swift-logger");
		assert_eq!(name, "@lpm.dev/acme.swift-logger");
		assert_eq!(range, "*");
	}

	// ── resolve_version_from_spec ───────────────────────────────────

	#[test]
	fn resolve_wildcard_returns_latest() {
		let meta = make_metadata(&["1.0.0", "2.0.0", "3.0.0"], "3.0.0");
		let result = resolve_version_from_spec("*", &meta, "3.0.0").unwrap();
		assert_eq!(result, "3.0.0");
	}

	#[test]
	fn resolve_exact_version_returns_that_version() {
		let meta = make_metadata(&["1.0.0", "2.0.0", "3.0.0"], "3.0.0");
		let result = resolve_version_from_spec("1.0.0", &meta, "3.0.0").unwrap();
		assert_eq!(result, "1.0.0");
	}

	#[test]
	fn resolve_caret_range_returns_best_match() {
		let meta = make_metadata(&["1.0.0", "1.5.0", "2.0.0", "2.1.0"], "2.1.0");
		let result = resolve_version_from_spec("^1.0.0", &meta, "2.1.0").unwrap();
		assert_eq!(result, "1.5.0");
	}

	#[test]
	fn resolve_tilde_range_returns_best_match() {
		let meta = make_metadata(&["1.0.0", "1.0.5", "1.1.0", "2.0.0"], "2.0.0");
		let result = resolve_version_from_spec("~1.0.0", &meta, "2.0.0").unwrap();
		assert_eq!(result, "1.0.5");
	}

	#[test]
	fn resolve_no_match_returns_error() {
		let meta = make_metadata(&["1.0.0", "1.5.0"], "1.5.0");
		let result = resolve_version_from_spec("^3.0.0", &meta, "1.5.0");
		assert!(result.is_err());
	}

	/// This is the exact bug scenario: user specifies `@1.0.0` but the code
	/// previously ignored it and used `latest_ver` (3.0.0) instead.
	#[test]
	fn bug_version_spec_not_ignored_for_swift_packages() {
		let meta = make_metadata(&["1.0.0", "2.0.0", "3.0.0"], "3.0.0");

		// User asked for @1.0.0 — must get 1.0.0, NOT 3.0.0
		let result = resolve_version_from_spec("1.0.0", &meta, "3.0.0").unwrap();
		assert_eq!(
			result, "1.0.0",
			"user-specified version @1.0.0 should be respected, not silently replaced with latest"
		);

		// User asked for @^2.0.0 — must get 2.0.0, NOT 3.0.0
		let result = resolve_version_from_spec("^2.0.0", &meta, "3.0.0").unwrap();
		assert_eq!(
			result, "2.0.0",
			"user-specified range @^2.0.0 should resolve to 2.0.0, not latest"
		);
	}
}
