use crate::output;
use lpm_common::LpmError;
use lpm_registry::RegistryClient;
use owo_colors::OwoColorize;
use std::path::Path;

/// Audit installed LPM packages for security issues.
///
/// Checks: AI security findings, dangerous behavioral tags,
/// lifecycle scripts, and quality scores.
pub async fn run(
	client: &RegistryClient,
	project_dir: &Path,
	json_output: bool,
) -> Result<(), LpmError> {
	// Try lockfile first, fall back to package.json
	let lpm_packages = collect_lpm_packages(project_dir)?;

	if lpm_packages.is_empty() {
		if !json_output {
			output::info("No LPM packages to audit");
		}
		return Ok(());
	}

	if !json_output {
		output::info(&format!(
			"Auditing {} LPM package(s)...",
			lpm_packages.len()
		));
		println!();
	}

	// Batch fetch all metadata in one request
	let names: Vec<String> = lpm_packages.iter().map(|(n, _)| n.clone()).collect();
	let metadata_map = client
		.batch_metadata(&names)
		.await
		.unwrap_or_default();

	let mut results: Vec<AuditResult> = Vec::new();
	let mut checked = 0;

	for (name, version) in &lpm_packages {
		let metadata = match metadata_map.get(name) {
			Some(m) => m,
			None => continue,
		};

		let ver_meta = metadata
			.version(version)
			.or_else(|| metadata.latest());

		let Some(ver_meta) = ver_meta else { continue };
		checked += 1;

		let mut issues: Vec<AuditIssue> = Vec::new();

		// AI security findings
		if let Some(findings) = &ver_meta.security_findings {
			for finding in findings {
				let severity = finding
					.severity
					.as_deref()
					.unwrap_or("moderate");
				let desc = finding
					.description
					.as_deref()
					.unwrap_or("security concern detected");
				issues.push(AuditIssue {
					severity: severity.to_string(),
					message: desc.to_string(),
					category: "security".to_string(),
				});
			}
		}

		// Dangerous behavioral tags
		if let Some(tags) = &ver_meta.behavioral_tags {
			let mut dangerous = Vec::new();
			if tags.eval {
				dangerous.push("eval()");
			}
			if tags.child_process {
				dangerous.push("child_process");
			}
			if tags.shell {
				dangerous.push("shell exec");
			}
			if tags.dynamic_require {
				dangerous.push("dynamic require");
			}
			if !dangerous.is_empty() {
				issues.push(AuditIssue {
					severity: "moderate".to_string(),
					message: format!("uses {}", dangerous.join(", ")),
					category: "behavior".to_string(),
				});
			}

			// Info-level behavioral tags
			let mut notable = Vec::new();
			if tags.network {
				notable.push("network");
			}
			if tags.filesystem {
				notable.push("filesystem");
			}
			if tags.environment_vars {
				notable.push("env vars");
			}
			if tags.native_bindings {
				notable.push("native bindings");
			}
			if !notable.is_empty() {
				issues.push(AuditIssue {
					severity: "info".to_string(),
					message: format!("accesses {}", notable.join(", ")),
					category: "behavior".to_string(),
				});
			}
		}

		// Lifecycle scripts
		if let Some(scripts) = &ver_meta.lifecycle_scripts {
			if !scripts.is_empty() {
				let names: Vec<&str> = scripts.keys().map(|s| s.as_str()).collect();
				issues.push(AuditIssue {
					severity: "moderate".to_string(),
					message: format!("lifecycle scripts: {}", names.join(", ")),
					category: "scripts".to_string(),
				});
			}
		}

		let quality_score = ver_meta.quality_score;

		// Low quality warning
		if let Some(score) = quality_score {
			if score < 40 {
				issues.push(AuditIssue {
					severity: if score < 20 { "high" } else { "moderate" }.to_string(),
					message: format!("low quality score: {score}/100"),
					category: "quality".to_string(),
				});
			}
		}

		results.push(AuditResult {
			name: name.clone(),
			version: version.clone(),
			quality_score,
			issues,
		});
	}

	// Output
	let packages_with_issues = results.iter().filter(|r| !r.issues.is_empty()).count();
	let total_issues: usize = results.iter().map(|r| r.issues.len()).sum();

	if json_output {
		let json = serde_json::json!({
			"checked": checked,
			"packages_with_issues": packages_with_issues,
			"total_issues": total_issues,
			"packages": results.iter().map(|r| {
				serde_json::json!({
					"name": r.name,
					"version": r.version,
					"quality_score": r.quality_score,
					"issues": r.issues.iter().map(|i| {
						serde_json::json!({
							"severity": i.severity,
							"category": i.category,
							"message": i.message,
						})
					}).collect::<Vec<_>>(),
				})
			}).collect::<Vec<_>>(),
		});
		println!("{}", serde_json::to_string_pretty(&json).unwrap());
		return Ok(());
	}

	for result in &results {
		let score_str = result
			.quality_score
			.map(|s| format!(" quality: {s}/100"))
			.unwrap_or_default();

		if result.issues.is_empty() {
			println!(
				"  {} {}{}",
				"✔".green(),
				format!("{}@{}", result.name, result.version).dimmed(),
				score_str.dimmed(),
			);
			continue;
		}

		println!(
			"\n  {} {}",
			result.name.bold(),
			format!("({})", result.version).dimmed(),
		);

		for issue in &result.issues {
			let icon = match issue.severity.as_str() {
				"high" | "critical" => "✖".red().to_string(),
				"moderate" => "⚠".yellow().to_string(),
				_ => "ℹ".blue().to_string(),
			};
			println!("    {icon} {}", issue.message);
		}

		if let Some(score) = result.quality_score {
			println!("    {} quality: {}/100", "ℹ".blue(), score);
		}
	}

	println!();
	if packages_with_issues == 0 {
		output::success(&format!(
			"No issues found ({checked} packages audited)"
		));
	} else {
		output::warn(&format!(
			"{packages_with_issues} package(s) with {total_issues} issue(s) ({checked} audited)"
		));
		println!(
			"  See package details: {}",
			"lpm info @lpm.dev/owner.package".dimmed()
		);
	}
	println!();

	Ok(())
}

/// Collect LPM package names + versions from lockfile or package.json.
fn collect_lpm_packages(project_dir: &Path) -> Result<Vec<(String, String)>, LpmError> {
	// Try lockfile first
	let lockfile_path = project_dir.join("lpm.lock");
	if lockfile_path.exists() {
		let lockfile = lpm_lockfile::Lockfile::read_fast(&lockfile_path)
			.map_err(|e| LpmError::Registry(format!("failed to read lockfile: {e}")))?;
		return Ok(lockfile
			.packages
			.iter()
			.filter(|p| p.name.starts_with("@lpm.dev/"))
			.map(|p| (p.name.clone(), p.version.clone()))
			.collect());
	}

	// Fall back to package.json dependencies
	let pkg_json_path = project_dir.join("package.json");
	if pkg_json_path.exists() {
		let content = std::fs::read_to_string(&pkg_json_path)
			.map_err(|e| LpmError::Io(e))?;
		let pkg: serde_json::Value = serde_json::from_str(&content)
			.map_err(|e| LpmError::Registry(format!("invalid package.json: {e}")))?;

		let mut packages = Vec::new();
		for section in ["dependencies", "devDependencies"] {
			if let Some(deps) = pkg.get(section).and_then(|d| d.as_object()) {
				for (name, version) in deps {
					if name.starts_with("@lpm.dev/") {
						let ver = version.as_str().unwrap_or("*").trim_start_matches('^').trim_start_matches('~');
						packages.push((name.clone(), ver.to_string()));
					}
				}
			}
		}
		return Ok(packages);
	}

	// Try Package.swift for Swift projects
	let package_swift = project_dir.join("Package.swift");
	if package_swift.exists() {
		let content = std::fs::read_to_string(&package_swift)
			.map_err(|e| LpmError::Io(e))?;

		let mut packages = Vec::new();
		// Find .package(id: "lpmdev.owner-pkg", from: "1.0.0") via string scanning
		for line in content.lines() {
			let trimmed = line.trim();
			if !trimmed.contains("lpmdev.") || !trimmed.contains(".package(id:") {
				continue;
			}
			// Extract the SE-0292 id between quotes after "id:"
			if let Some(id_start) = trimmed.find("\"lpmdev.") {
				let id_str = &trimmed[id_start + 1..];
				if let Some(id_end) = id_str.find('"') {
					let se0292_id = &id_str[..id_end]; // "lpmdev.owner-pkg"
					let se0292_name = se0292_id.trim_start_matches("lpmdev.");

					// Extract version from "from:"
					let version = trimmed
						.find("from: \"")
						.and_then(|i| {
							let v = &trimmed[i + 7..];
							v.find('"').map(|end| v[..end].to_string())
						})
						.unwrap_or_else(|| "*".to_string());

					// Convert: owner-pkg → @lpm.dev/owner.pkg
					if let Some(hyphen) = se0292_name.find('-') {
						let owner = &se0292_name[..hyphen];
						let pkg = &se0292_name[hyphen + 1..];
						packages.push((format!("@lpm.dev/{owner}.{pkg}"), version));
					}
				}
			}
		}
		return Ok(packages);
	}

	Err(LpmError::NotFound(
		"No lpm.lock, package.json, or Package.swift found".into(),
	))
}

struct AuditResult {
	name: String,
	version: String,
	quality_score: Option<u32>,
	issues: Vec<AuditIssue>,
}

struct AuditIssue {
	severity: String,
	message: String,
	category: String,
}
