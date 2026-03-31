use crate::output;
use lpm_common::LpmError;
use lpm_store::PackageStore;
use owo_colors::OwoColorize;
use std::collections::HashSet;

/// Manage the global content-addressable package store.
///
/// Actions: verify, list, path, gc.
pub async fn run(
	action: &str,
	deep: bool,
	dry_run: bool,
	older_than: Option<&str>,
	force: bool,
	json_output: bool,
) -> Result<(), LpmError> {
	let store = PackageStore::default_location()?;

	match action {
		"verify" => run_verify(&store, deep, json_output),
		"list" | "ls" => run_list(&store, json_output),
		"path" => {
			let path = store.root().display().to_string();
			if json_output {
				println!(
					"{}",
					serde_json::to_string_pretty(&serde_json::json!({"success": true, "path": path})).unwrap()
				);
			} else {
				println!("{path}");
			}
			Ok(())
		}
		"gc" => run_gc(&store, dry_run, older_than, force, json_output),
		_ => Err(LpmError::Store(format!(
			"unknown store action: {action}. Available: verify, list, path, gc"
		))),
	}
}

/// Verify integrity of all packages in the store.
///
/// Basic mode: checks that each package directory has a `package.json` and is non-empty.
/// Deep mode (`--deep`): additionally parses `package.json` to validate name/version consistency
/// and verifies that the directory name matches the declared name@version.
fn run_verify(store: &PackageStore, deep: bool, json_output: bool) -> Result<(), LpmError> {
	let packages = store.list_packages()?;

	if packages.is_empty() {
		if json_output {
			println!(
				"{}",
				serde_json::to_string_pretty(&serde_json::json!({
					"success": true,
					"verified": 0,
					"corrupted": 0,
					"issues": [],
				}))
				.unwrap()
			);
		} else {
			output::info("Store is empty — nothing to verify");
		}
		return Ok(());
	}

	// In deep mode, load lockfile integrity hashes for cross-checking
	let lockfile_integrity: std::collections::HashMap<String, String> = if deep {
		let cwd = std::env::current_dir().unwrap_or_default();
		let lockfile_path = cwd.join("lpm.lock");
		if lockfile_path.exists() {
			lpm_lockfile::Lockfile::read_fast(&lockfile_path)
				.map(|lf| {
					lf.packages
						.iter()
						.filter_map(|p| {
							p.integrity
								.as_ref()
								.map(|i| (format!("{}@{}", p.name, p.version), i.clone()))
						})
						.collect()
				})
				.unwrap_or_default()
		} else {
			std::collections::HashMap::new()
		}
	} else {
		std::collections::HashMap::new()
	};

	let mut verified = 0u32;
	let mut corrupted: Vec<String> = Vec::new();
	let mut security_mismatches = 0u32;
	let mut security_reanalyzed = 0u32;

	for (name, version) in &packages {
		let dir = store.package_dir(name, version);

		// Check 1: directory exists
		if !dir.exists() {
			corrupted.push(format!("{name}@{version} — directory missing"));
			continue;
		}

		// Check 2: package.json exists
		let pkg_json_path = dir.join("package.json");
		if !pkg_json_path.exists() {
			corrupted.push(format!("{name}@{version} — missing package.json"));
			continue;
		}

		// Check 3: directory is non-empty (has at least package.json + something else,
		// or at minimum package.json itself)
		let file_count = match std::fs::read_dir(&dir) {
			Ok(entries) => entries.count(),
			Err(e) => {
				corrupted.push(format!("{name}@{version} — unreadable directory: {e}"));
				continue;
			}
		};

		if file_count == 0 {
			corrupted.push(format!("{name}@{version} — empty directory"));
			continue;
		}

		// Deep mode: parse package.json, validate name/version fields,
		// and verify integrity hash against lockfile.
		if deep {
			match std::fs::read_to_string(&pkg_json_path) {
				Ok(content) => {
					match serde_json::from_str::<serde_json::Value>(&content) {
						Ok(pkg) => {
							// Validate name matches
							if let Some(declared_name) = pkg.get("name").and_then(|v| v.as_str())
							{
								if declared_name != name {
									corrupted.push(format!(
										"{name}@{version} — package.json name mismatch: declared '{declared_name}'"
									));
									continue;
								}
							}
							// Validate version matches
							if let Some(declared_version) =
								pkg.get("version").and_then(|v| v.as_str())
							{
								if declared_version != version {
									corrupted.push(format!(
										"{name}@{version} — package.json version mismatch: declared '{declared_version}'"
									));
									continue;
								}
							}
						}
						Err(e) => {
							corrupted.push(format!(
								"{name}@{version} — invalid package.json: {e}"
							));
							continue;
						}
					}
				}
				Err(e) => {
					corrupted.push(format!(
						"{name}@{version} — unreadable package.json: {e}"
					));
					continue;
				}
			}

			// Verify integrity hash: compare stored .integrity with lockfile
			let key = format!("{name}@{version}");
			if let Some(expected_integrity) = lockfile_integrity.get(&key) {
				match lpm_store::read_stored_integrity(&dir) {
					Some(stored) => {
						if stored != *expected_integrity {
							corrupted.push(format!(
								"{name}@{version} — integrity mismatch: stored '{}...' != lockfile '{}...'",
								&stored[..stored.len().min(20)],
								&expected_integrity[..expected_integrity.len().min(20)],
							));
							continue;
						}
					}
					None => {
						// No .integrity file — package was stored before integrity tracking.
						// Not an error, but noted at debug level.
						tracing::debug!("{name}@{version}: no .integrity file (pre-integrity store)");
					}
				}
			}

			// Security cross-check: re-run behavioral analysis and compare with cached
			let cached = lpm_security::behavioral::read_cached_analysis(&dir);
			let fresh = lpm_security::behavioral::analyze_package(&dir);

			match cached {
				Some(ref cached_analysis) => {
					if !security_analysis_matches(cached_analysis, &fresh) {
						security_mismatches += 1;
						if !json_output {
							eprintln!(
								"    {} {name}@{version} — security analysis mismatch. Re-analyzing...",
								"⚠".yellow()
							);
						}
						// Re-write with fresh results
						if let Err(e) = lpm_security::behavioral::write_cached_analysis(&dir, &fresh) {
							tracing::warn!("failed to re-write .lpm-security.json for {name}@{version}: {e}");
						} else {
							security_reanalyzed += 1;
						}
					}
				}
				None => {
					// No cached analysis — write fresh one
					if let Err(e) = lpm_security::behavioral::write_cached_analysis(&dir, &fresh) {
						tracing::warn!("failed to write .lpm-security.json for {name}@{version}: {e}");
					} else {
						security_reanalyzed += 1;
					}
				}
			}
		}

		verified += 1;
	}

	if json_output {
		let mut result = serde_json::json!({
			"success": true,
			"verified": verified,
			"corrupted": corrupted.len(),
			"issues": corrupted,
		});
		if deep {
			result["securityMismatches"] = serde_json::json!(security_mismatches);
			result["securityReanalyzed"] = serde_json::json!(security_reanalyzed);
		}
		println!(
			"{}",
			serde_json::to_string_pretty(&result).unwrap()
		);
	} else if corrupted.is_empty() {
		let mut msg = format!("{verified} packages verified, all OK");
		if deep && security_reanalyzed > 0 {
			msg.push_str(&format!(
				" ({security_reanalyzed} security cache{} refreshed)",
				if security_reanalyzed == 1 { "" } else { "s" }
			));
		}
		if deep && security_mismatches > 0 {
			output::warn(&format!(
				"{verified} packages verified, {security_mismatches} security analysis mismatch{} (re-analyzed)",
				if security_mismatches == 1 { "" } else { "es" }
			));
		} else {
			output::success(&msg);
		}
	} else {
		output::warn(&format!(
			"{} corrupted, {} OK",
			corrupted.len(),
			verified
		));
		for issue in &corrupted {
			eprintln!("    {} {issue}", "⚠".yellow());
		}
		if deep && security_mismatches > 0 {
			eprintln!(
				"    {} {security_mismatches} security analysis mismatch{} (re-analyzed)",
				"⚠".yellow(),
				if security_mismatches == 1 { "" } else { "es" }
			);
		}
		eprintln!();
		eprintln!(
			"    Fix: {} && {}",
			"lpm store gc".bold(),
			"lpm install".bold()
		);
	}

	Ok(())
}

/// Compare two behavioral analyses for equivalence (ignoring timestamps and metadata).
///
/// Returns `true` if the actual tag values match. Differences in `analyzedAt`,
/// `meta.filesScanned`, or `meta.bytesScanned` are expected and ignored.
fn security_analysis_matches(
	cached: &lpm_security::behavioral::PackageAnalysis,
	fresh: &lpm_security::behavioral::PackageAnalysis,
) -> bool {
	cached.source == fresh.source
		&& cached.supply_chain == fresh.supply_chain
		&& cached.manifest == fresh.manifest
}

/// List all packages currently in the global store.
fn run_list(store: &PackageStore, json_output: bool) -> Result<(), LpmError> {
	let packages = store.list_packages()?;

	if json_output {
		let entries: Vec<_> = packages
			.iter()
			.map(|(name, ver)| serde_json::json!({"name": name, "version": ver}))
			.collect();
		println!(
			"{}",
			serde_json::to_string_pretty(&serde_json::json!({
				"success": true,
				"count": entries.len(),
				"packages": entries,
			}))
			.unwrap()
		);
	} else if packages.is_empty() {
		output::info("Store is empty");
	} else {
		println!(
			"  {} packages in store:",
			packages.len().to_string().bold()
		);
		for (name, version) in &packages {
			println!("    {}@{}", name, version.dimmed());
		}
		println!();
	}

	Ok(())
}

/// Parse a human-readable duration string like "30d" or "24h" into a `Duration`.
///
/// Supported units:
/// - `d` — days (e.g., "7d" = 7 days)
/// - `h` — hours (e.g., "24h" = 24 hours)
fn parse_duration(s: &str) -> Result<std::time::Duration, LpmError> {
	let (num_str, unit) = if s.ends_with('d') {
		(&s[..s.len() - 1], 'd')
	} else if s.ends_with('h') {
		(&s[..s.len() - 1], 'h')
	} else {
		return Err(LpmError::Script(format!(
			"invalid duration: {s}. Use '7d' or '24h'"
		)));
	};
	let num: u64 = num_str
		.parse()
		.map_err(|_| LpmError::Script(format!("invalid number in duration: {s}")))?;
	if num == 0 {
		return Err(LpmError::Script(format!(
			"duration must be positive: {s}"
		)));
	}
	let multiplier: u64 = match unit {
		'd' => 86400,
		'h' => 3600,
		_ => unreachable!(),
	};
	let secs = num.checked_mul(multiplier).ok_or_else(|| {
		LpmError::Script(format!("duration overflow: {s} is too large"))
	})?;
	Ok(std::time::Duration::from_secs(secs))
}

/// Garbage collect: remove packages not referenced by any lockfile in the current project.
///
/// # Warning
/// This only considers packages referenced by the lockfile in the CURRENT directory.
/// Packages used by OTHER projects are NOT considered and may be incorrectly removed.
/// To safely GC across all projects, run `lpm store gc` from each project directory first,
/// or use `--dry-run` to preview what would be removed.
///
/// With `--dry-run`, shows what would be removed without deleting.
/// With `--older-than`, only removes packages whose mtime exceeds the threshold.
/// Without a lockfile, requires `--force` to proceed (prevents accidental deletion of
/// packages used by other projects).
fn run_gc(
	store: &PackageStore,
	dry_run: bool,
	older_than: Option<&str>,
	force: bool,
	json_output: bool,
) -> Result<(), LpmError> {
	// Parse older_than duration if provided
	let max_age = older_than.map(parse_duration).transpose()?;

	// Collect referenced packages from the current directory's lockfile
	let cwd = std::env::current_dir().map_err(LpmError::Io)?;
	let lockfile_path = cwd.join("lpm.lock");

	let referenced: HashSet<String> = if lockfile_path.exists() {
		match lpm_lockfile::Lockfile::read_fast(&lockfile_path) {
			Ok(lockfile) => lockfile
				.packages
				.iter()
				.map(|p| format!("{}@{}", p.name, p.version))
				.collect(),
			Err(e) => {
				tracing::debug!("Failed to read lockfile for GC: {e}");
				HashSet::new()
			}
		}
	} else {
		// No lockfile means no references — GC will remove everything
		if !force && !dry_run {
			output::warn("No lpm.lock found in current directory.");
			output::warn("GC will treat ALL stored packages as unreferenced.");
			output::warn("Run from a project directory with lpm.lock, or use --dry-run first.");
			return Err(LpmError::Script(
				"no lockfile found — refusing to GC without --force".into(),
			));
		}
		if !json_output {
			output::warn(
				"No lpm.lock found in current directory. All packages will be considered unreferenced.",
			);
		}
		HashSet::new()
	};

	if dry_run {
		let preview = store.gc_preview(&referenced, max_age.as_ref())?;

		if json_output {
			let entries: Vec<_> = preview
				.would_remove
				.iter()
				.map(|(name, size)| serde_json::json!({"name": name, "bytes": size}))
				.collect();
			println!(
				"{}",
				serde_json::to_string_pretty(&serde_json::json!({
					"success": true,
					"dry_run": true,
					"would_remove": preview.would_remove.len(),
					"would_keep": preview.would_keep,
					"would_free_bytes": preview.would_free_bytes,
					"would_free": lpm_common::format_bytes(preview.would_free_bytes),
					"packages": entries,
				}))
				.unwrap()
			);
		} else if preview.would_remove.is_empty() {
			output::success(&format!(
				"Nothing to clean ({} packages in use)",
				preview.would_keep
			));
		} else {
			println!(
				"  Would remove {} packages (free {}):",
				preview.would_remove.len().to_string().bold(),
				lpm_common::format_bytes(preview.would_free_bytes).bold(),
			);
			for (name, size) in &preview.would_remove {
				println!(
					"    {} {}",
					name,
					lpm_common::format_bytes(*size).dimmed()
				);
			}
			println!();
			println!(
				"  Run {} to actually remove these packages.",
				"lpm store gc".bold()
			);
		}
	} else {
		let result = store.gc(&referenced, max_age.as_ref())?;

		if json_output {
			println!(
				"{}",
				serde_json::to_string_pretty(&serde_json::json!({
					"success": true,
					"removed": result.removed,
					"kept": result.kept,
					"freed_bytes": result.freed_bytes,
					"freed": lpm_common::format_bytes(result.freed_bytes),
				}))
				.unwrap()
			);
		} else if result.removed == 0 {
			output::success(&format!(
				"Nothing to clean ({} packages in use)",
				result.kept
			));
		} else {
			output::success(&format!(
				"Removed {} unused packages (freed {}), {} kept",
				result.removed,
				lpm_common::format_bytes(result.freed_bytes),
				result.kept,
			));
		}
	}

	Ok(())
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn parse_duration_valid_days() {
		let d = parse_duration("7d").unwrap();
		assert_eq!(d, std::time::Duration::from_secs(604800));
	}

	#[test]
	fn parse_duration_valid_hours() {
		let d = parse_duration("24h").unwrap();
		assert_eq!(d, std::time::Duration::from_secs(86400));
	}

	#[test]
	fn parse_duration_one_day() {
		let d = parse_duration("1d").unwrap();
		assert_eq!(d, std::time::Duration::from_secs(86400));
	}

	#[test]
	fn parse_duration_one_hour() {
		let d = parse_duration("1h").unwrap();
		assert_eq!(d, std::time::Duration::from_secs(3600));
	}

	#[test]
	fn parse_duration_zero_rejected() {
		assert!(parse_duration("0d").is_err());
	}

	#[test]
	fn parse_duration_empty_rejected() {
		assert!(parse_duration("").is_err());
	}

	#[test]
	fn parse_duration_no_unit_rejected() {
		assert!(parse_duration("abc").is_err());
	}

	#[test]
	fn parse_duration_unsupported_unit_rejected() {
		assert!(parse_duration("30m").is_err());
	}

	#[test]
	fn parse_duration_negative_rejected() {
		assert!(parse_duration("-5d").is_err());
	}

	#[test]
	fn parse_duration_overflow_rejected() {
		assert!(parse_duration("999999999999999999d").is_err());
	}
}
