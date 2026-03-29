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
					serde_json::to_string_pretty(&serde_json::json!({"path": path})).unwrap()
				);
			} else {
				println!("{path}");
			}
			Ok(())
		}
		"gc" => run_gc(&store, dry_run, older_than, json_output),
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

	let mut verified = 0u32;
	let mut corrupted: Vec<String> = Vec::new();

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

		// Deep mode: parse package.json and validate name/version fields
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
		}

		verified += 1;
	}

	if json_output {
		println!(
			"{}",
			serde_json::to_string_pretty(&serde_json::json!({
				"verified": verified,
				"corrupted": corrupted.len(),
				"issues": corrupted,
			}))
			.unwrap()
		);
	} else if corrupted.is_empty() {
		output::success(&format!("{verified} packages verified, all OK"));
	} else {
		output::warn(&format!(
			"{} corrupted, {} OK",
			corrupted.len(),
			verified
		));
		for issue in &corrupted {
			eprintln!("    {} {issue}", "⚠".yellow());
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
	Ok(match unit {
		'd' => std::time::Duration::from_secs(num * 86400),
		'h' => std::time::Duration::from_secs(num * 3600),
		_ => unreachable!(),
	})
}

/// Garbage collect: remove packages not referenced by any lockfile in the current project.
///
/// With `--dry-run`, shows what would be removed without deleting.
/// With `--older-than`, only removes packages whose mtime exceeds the threshold.
fn run_gc(
	store: &PackageStore,
	dry_run: bool,
	older_than: Option<&str>,
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
