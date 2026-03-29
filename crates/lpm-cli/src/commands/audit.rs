use crate::output;
use lpm_common::LpmError;
use lpm_registry::RegistryClient;
use owo_colors::OwoColorize;
use std::path::Path;

/// Audit installed LPM packages for security issues.
///
/// Checks: AI security findings, dangerous behavioral tags,
/// lifecycle scripts, and quality scores.
/// Convert a severity string to a numeric level for comparison.
/// Higher = more severe.
fn severity_level(severity: &str) -> u8 {
	match severity.to_lowercase().as_str() {
		"critical" | "CRITICAL" => 4,
		"high" | "HIGH" => 3,
		"moderate" | "medium" | "MODERATE" | "MEDIUM" => 2,
		"info" | "low" | "INFO" | "LOW" => 1,
		_ => 0,
	}
}

/// Get the minimum severity level from a --level flag value.
fn min_severity_level(level: &str) -> u8 {
	match level.to_lowercase().as_str() {
		"high" => 3,
		"moderate" => 2,
		"info" => 1,
		_ => 0,
	}
}

pub async fn run(
	client: &RegistryClient,
	project_dir: &Path,
	json_output: bool,
	level: Option<&str>,
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

	// Filter issues by --level if provided
	if let Some(lvl) = level {
		let min_lvl = min_severity_level(lvl);
		for result in &mut results {
			result.issues.retain(|issue| severity_level(&issue.severity) >= min_lvl);
		}
	}

	// Output LPM audit results (human-readable per-package display)
	let packages_with_issues = results.iter().filter(|r| !r.issues.is_empty()).count();
	let total_issues: usize = results.iter().map(|r| r.issues.len()).sum();

	if !json_output {
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
				println!("    {icon} {} {}", format_severity(&issue.severity), issue.message);
			}

			if let Some(score) = result.quality_score {
				println!("    {} quality: {}/100", "ℹ".blue(), score);
			}
		}
	}

	// --- OSV vulnerability scan ---
	let all_packages = collect_all_packages(project_dir);
	let osv_vulns = if !all_packages.is_empty() {
		if !json_output {
			println!();
			output::info("Checking OSV vulnerability database...");
		}
		match query_osv_batch(&all_packages).await {
			Ok(vulns) => vulns,
			Err(e) => {
				tracing::debug!("OSV query failed: {e}");
				if !json_output {
					println!("  {} OSV database unavailable, skipping", "⚠".yellow());
				}
				Vec::new()
			}
		}
	} else {
		Vec::new()
	};

	// Filter OSV vulnerabilities by --level if provided
	let osv_vulns = if let Some(lvl) = level {
		let min_lvl = min_severity_level(lvl);
		osv_vulns.into_iter().filter(|v| severity_level(&v.severity) >= min_lvl).collect()
	} else {
		osv_vulns
	};

	println!();

	// Display OSV results
	if !osv_vulns.is_empty() && !json_output {
		println!("  {}", "Known vulnerabilities (OSV)".bold());
		for vuln in &osv_vulns {
			let icon = match vuln.severity.as_str() {
				"HIGH" | "CRITICAL" => "✖".red().to_string(),
				"MODERATE" | "MEDIUM" => "⚠".yellow().to_string(),
				_ => "ℹ".cyan().to_string(),
			};
			let summary = if vuln.summary.is_empty() {
				String::new()
			} else {
				format!(" — {}", vuln.summary)
			};
			println!(
				"    {icon} {}@{} {} [{}]{summary}",
				vuln.package,
				vuln.version,
				vuln.id.bold(),
				format_severity(&vuln.severity),
			);
		}
		println!(
			"\n  {} vulnerability details: {}",
			"ℹ".blue(),
			"https://osv.dev/vulnerability/VULN_ID".dimmed()
		);
		println!();
	}

	// Final summary
	let total_osv = osv_vulns.len();
	let combined_issues = total_issues + total_osv;

	if json_output {
		// Count severities across all LPM audit issues
		let mut critical_count = 0usize;
		let mut high_count = 0usize;
		let mut moderate_count = 0usize;
		let mut low_count = 0usize;
		let mut info_count = 0usize;
		for r in &results {
			for issue in &r.issues {
				match issue.severity.to_lowercase().as_str() {
					"critical" => critical_count += 1,
					"high" => high_count += 1,
					"moderate" | "medium" => moderate_count += 1,
					"low" => low_count += 1,
					"info" => info_count += 1,
					_ => {}
				}
			}
		}
		// Also count OSV vulnerability severities
		for v in &osv_vulns {
			match v.severity.to_uppercase().as_str() {
				"CRITICAL" => critical_count += 1,
				"HIGH" => high_count += 1,
				"MODERATE" | "MEDIUM" => moderate_count += 1,
				"LOW" => low_count += 1,
				_ => info_count += 1,
			}
		}

		let json = serde_json::json!({
			"scanned": checked + all_packages.len(),
			"checked": checked,
			"packages_with_issues": packages_with_issues,
			"total_issues": total_issues,
			"osv_vulnerabilities": total_osv,
			"counts": {
				"critical": critical_count,
				"high": high_count,
				"moderate": moderate_count,
				"low": low_count,
				"info": info_count,
			},
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
			"vulnerabilities": osv_vulns.iter().map(|v| {
				serde_json::json!({
					"package": v.package,
					"version": v.version,
					"id": v.id,
					"summary": v.summary,
					"severity": v.severity,
				})
			}).collect::<Vec<_>>(),
		});
		println!("{}", serde_json::to_string_pretty(&json).unwrap());
		return Ok(());
	}

	if combined_issues == 0 {
		output::success(&format!(
			"No issues found ({checked} LPM packages audited, {} total packages scanned via OSV)",
			all_packages.len()
		));
	} else {
		if packages_with_issues > 0 {
			output::warn(&format!(
				"{packages_with_issues} LPM package(s) with {total_issues} issue(s) ({checked} audited)"
			));
			println!(
				"  See package details: {}",
				"lpm info @lpm.dev/owner.package".dimmed()
			);
		}
		if total_osv > 0 {
			output::warn(&format!(
				"{total_osv} known vulnerabilities found via OSV"
			));
		}
		if packages_with_issues == 0 && total_osv == 0 {
			output::success(&format!(
				"No issues found ({checked} packages audited)"
			));
		}
	}
	println!();

	Ok(())
}

// ─── OSV.dev integration ─────────────────────────────────────────────────────

#[derive(Debug, serde::Deserialize)]
struct OsvBatchResponse {
	results: Vec<OsvQueryResult>,
}

#[derive(Debug, serde::Deserialize)]
struct OsvQueryResult {
	#[serde(default)]
	vulns: Vec<OsvVuln>,
}

#[derive(Debug, serde::Deserialize)]
struct OsvVuln {
	id: String,
	summary: Option<String>,
	#[serde(default)]
	severity: Vec<OsvSeverityEntry>,
}

#[derive(Debug, serde::Deserialize)]
struct OsvSeverityEntry {
	#[serde(rename = "type")]
	severity_type: String,
	score: String,
}

struct OsvVulnerability {
	package: String,
	version: String,
	id: String,
	summary: String,
	severity: String,
}

/// Query OSV.dev batch API for known vulnerabilities in the given packages.
///
/// Uses the batch endpoint to minimize HTTP round-trips (single request for all packages).
/// Gracefully returns an empty vec on any network/parse failure.
async fn query_osv_batch(
	packages: &[(String, String)],
) -> Result<Vec<OsvVulnerability>, LpmError> {
	if packages.is_empty() {
		return Ok(Vec::new());
	}

	let client = reqwest::Client::new();

	let queries: Vec<serde_json::Value> = packages
		.iter()
		.map(|(name, version)| {
			serde_json::json!({
				"package": { "name": name, "ecosystem": "npm" },
				"version": version,
			})
		})
		.collect();

	let body = serde_json::json!({ "queries": queries });

	let response = client
		.post("https://api.osv.dev/v1/querybatch")
		.json(&body)
		.timeout(std::time::Duration::from_secs(10))
		.send()
		.await
		.map_err(|e| LpmError::Network(format!("OSV API error: {e}")))?;

	if !response.status().is_success() {
		return Ok(Vec::new()); // Graceful fallback — OSV being unavailable should not break audit
	}

	let result: OsvBatchResponse = response
		.json()
		.await
		.map_err(|e| LpmError::Network(format!("OSV parse error: {e}")))?;

	let mut vulns: Vec<OsvVulnerability> = Vec::new();

	for (i, query_result) in result.results.into_iter().enumerate() {
		if i >= packages.len() {
			break;
		}
		for vuln in query_result.vulns {
			vulns.push(OsvVulnerability {
				package: packages[i].0.clone(),
				version: packages[i].1.clone(),
				id: vuln.id,
				summary: vuln.summary.unwrap_or_default(),
				severity: extract_severity(&vuln.severity),
			});
		}
	}

	Ok(vulns)
}

/// Extract the highest severity string from OSV severity entries.
/// Prefers CVSS_V3 over V2. Falls back to "UNKNOWN" if none found.
fn extract_severity(entries: &[OsvSeverityEntry]) -> String {
	// Try CVSS_V3 first
	for entry in entries {
		if entry.severity_type == "CVSS_V3" {
			return cvss_score_to_label(&entry.score);
		}
	}
	// Fall back to any type
	if let Some(entry) = entries.first() {
		return cvss_score_to_label(&entry.score);
	}
	"UNKNOWN".to_string()
}

/// Convert a CVSS vector string to a severity label.
/// Parses the base score if present, otherwise attempts to extract from the vector.
fn cvss_score_to_label(score_str: &str) -> String {
	// If it's a plain number (e.g., "7.5"), convert directly
	if let Ok(score) = score_str.parse::<f64>() {
		return if score >= 9.0 {
			"CRITICAL".to_string()
		} else if score >= 7.0 {
			"HIGH".to_string()
		} else if score >= 4.0 {
			"MEDIUM".to_string()
		} else {
			"LOW".to_string()
		};
	}
	// CVSS vector string — just label as present
	if score_str.contains("CVSS:") {
		"HIGH".to_string() // Conservative default for unparsed vectors
	} else {
		"UNKNOWN".to_string()
	}
}

/// Collect ALL packages (LPM + npm) from lockfile for OSV scanning.
/// Returns an empty vec if no lockfile is found (does not fail).
fn collect_all_packages(project_dir: &Path) -> Vec<(String, String)> {
	let lockfile_path = project_dir.join("lpm.lock");
	if lockfile_path.exists() {
		if let Ok(lockfile) = lpm_lockfile::Lockfile::read_fast(&lockfile_path) {
			return lockfile
				.packages
				.iter()
				.map(|p| (p.name.clone(), p.version.clone()))
				.collect();
		}
	}
	Vec::new()
}

// ─── Package collection (LPM-only, for metadata-based audit) ─────────────────

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

/// Format a severity string with colored terminal output.
fn format_severity(severity: &str) -> String {
	match severity.to_lowercase().as_str() {
		"critical" => format!("{}", " CRITICAL ".on_red().white().bold()),
		"high" => format!("{}", severity.red().bold()),
		"moderate" | "medium" => format!("{}", severity.yellow()),
		"low" => format!("{}", severity.blue()),
		"info" => format!("{}", severity.dimmed()),
		_ => severity.to_string(),
	}
}
