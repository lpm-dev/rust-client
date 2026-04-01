//! Client-side quality scoring for packages before publish.
//!
//! The server is the source of truth — it re-verifies all checks independently
//! using the tarball contents. These client-side checks provide fast feedback
//! before uploading.
//!
//! 4 categories, 100 total points:
//!
//! JS ecosystem:
//! - Documentation: 22pts
//! - Code Quality: 31pts
//! - Testing: 11pts
//! - Health: 36pts
//!
//! Swift ecosystem:
//! - Documentation: 22pts
//! - Code Quality: 31pts
//! - Testing: 11pts
//! - Health: 36pts

use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QualityResult {
	pub score: u32,
	pub max_score: u32,
	pub checks: Vec<QualityCheck>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QualityCheck {
	pub id: String,
	pub category: String,
	pub label: String,
	pub passed: bool,
	pub points: u32,
	pub max_points: u32,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub detail: Option<String>,
	#[serde(default, skip_serializing_if = "std::ops::Not::not")]
	pub server_only: bool,
}

/// Run all client-side quality checks, dispatching by ecosystem.
pub fn run_quality_checks(
	pkg_json: &serde_json::Value,
	readme: Option<&str>,
	project_dir: &Path,
	files: &[String],
	ecosystem: &str,
	swift_manifest: Option<&serde_json::Value>,
) -> QualityResult {
	let mut checks = Vec::new();

	// ── Documentation (22pts) — shared across all ecosystems ───────
	push_documentation_checks(&mut checks, pkg_json, readme, files, ecosystem);

	// ── Code Quality + Testing — ecosystem-specific ───────────────
	match ecosystem {
		"swift" => {
			push_swift_code_quality_checks(&mut checks, swift_manifest, files);
			push_swift_testing_checks(&mut checks, swift_manifest, project_dir);
		}
		_ => {
			push_js_code_quality_checks(&mut checks, pkg_json, files);
			push_js_testing_checks(&mut checks, pkg_json, project_dir);
		}
	}

	// ── Health (36pts) — shared across all ecosystems ──────────────
	push_health_checks(&mut checks, pkg_json, ecosystem);

	// Calculate total
	let score: u32 = checks.iter().map(|c| c.points).sum();
	let max_score: u32 = checks.iter().map(|c| c.max_points).sum();

	QualityResult {
		score,
		max_score,
		checks,
	}
}

// ── Documentation (22pts) ──────────────────────────────────────────────

fn push_documentation_checks(
	checks: &mut Vec<QualityCheck>,
	pkg_json: &serde_json::Value,
	readme: Option<&str>,
	files: &[String],
	ecosystem: &str,
) {
	// has-readme (8pts)
	let readme_len = readme.map(|r| r.len()).unwrap_or(0);
	checks.push(QualityCheck {
		id: "has-readme".into(),
		category: "documentation".into(),
		label: "Has README".into(),
		passed: readme_len > 100,
		points: if readme_len > 100 { 8 } else { 0 },
		max_points: 8,
		detail: if readme_len == 0 {
			Some("No README found".into())
		} else if readme_len <= 100 {
			Some(format!("README too short ({readme_len} chars, need >100)"))
		} else {
			None
		},
		server_only: false,
	});

	// readme-install (3pts) — Swift adds extra detection patterns
	let readme_lower = readme.unwrap_or("").to_lowercase();
	let has_install = readme_lower.contains("install")
		|| readme_lower.contains("getting started")
		|| readme_lower.contains("setup")
		|| readme_lower.contains("npm install")
		|| readme_lower.contains("lpm install")
		|| readme_lower.contains("lpm add")
		|| (ecosystem == "swift"
			&& (readme_lower.contains("requirements")
				|| readme_lower.contains("swift package manager")
				|| readme_lower.contains("package.swift")
				|| readme_lower.contains(".package(")));
	checks.push(QualityCheck {
		id: "readme-install".into(),
		category: "documentation".into(),
		label: "README has install section".into(),
		passed: has_install,
		points: if has_install { 3 } else { 0 },
		max_points: 3,
		detail: if !has_install {
			Some("Add install/setup instructions to README".into())
		} else {
			None
		},
		server_only: false,
	});

	// readme-usage (3pts)
	let has_usage = readme_lower.contains("usage")
		|| readme.unwrap_or("").matches("```").count() >= 4;
	checks.push(QualityCheck {
		id: "readme-usage".into(),
		category: "documentation".into(),
		label: "README has usage examples".into(),
		passed: has_usage,
		points: if has_usage { 3 } else { 0 },
		max_points: 3,
		detail: if !has_usage {
			Some("Add usage examples or 2+ code blocks".into())
		} else {
			None
		},
		server_only: false,
	});

	// readme-api (2pts)
	let has_api = readme_lower.contains("api")
		|| readme_lower.contains("reference")
		|| readme_lower.contains("props")
		|| readme_lower.contains("parameters")
		|| readme_lower.contains("options");
	checks.push(QualityCheck {
		id: "readme-api".into(),
		category: "documentation".into(),
		label: "README has API reference".into(),
		passed: has_api,
		points: if has_api { 2 } else { 0 },
		max_points: 2,
		detail: None,
		server_only: false,
	});

	// has-changelog (3pts)
	let has_changelog = files.iter().any(|f| {
		let lower = f.to_lowercase();
		lower.contains("changelog") || lower.contains("changes") || lower.contains("history")
	});
	checks.push(QualityCheck {
		id: "has-changelog".into(),
		category: "documentation".into(),
		label: "Has CHANGELOG".into(),
		passed: has_changelog,
		points: if has_changelog { 3 } else { 0 },
		max_points: 3,
		detail: None,
		server_only: false,
	});

	// has-license (3pts)
	let has_license = files
		.iter()
		.any(|f| f.to_lowercase().starts_with("license"))
		|| pkg_json.get("license").and_then(|v| v.as_str()).is_some();
	checks.push(QualityCheck {
		id: "has-license".into(),
		category: "documentation".into(),
		label: "Has license".into(),
		passed: has_license,
		points: if has_license { 3 } else { 0 },
		max_points: 3,
		detail: None,
		server_only: false,
	});
}

// ── JS Code Quality (31pts) ────────────────────────────────────────────

fn push_js_code_quality_checks(
	checks: &mut Vec<QualityCheck>,
	pkg_json: &serde_json::Value,
	files: &[String],
) {
	// has-types (8pts)
	let has_types = pkg_json.get("types").is_some()
		|| pkg_json.get("typings").is_some()
		|| files
			.iter()
			.any(|f| f.ends_with(".d.ts") || f.ends_with(".d.cts") || f.ends_with(".d.mts"));
	checks.push(QualityCheck {
		id: "has-types".into(),
		category: "code-quality".into(),
		label: "Has TypeScript types".into(),
		passed: has_types,
		points: if has_types { 8 } else { 0 },
		max_points: 8,
		detail: None,
		server_only: false,
	});

	// esm-exports (3pts)
	let pkg_type = pkg_json
		.get("type")
		.and_then(|v| v.as_str())
		.unwrap_or("");
	let has_module = pkg_json.get("module").is_some();
	let has_exports = pkg_json.get("exports").is_some();
	let is_esm = pkg_type == "module" || has_module || has_exports;
	checks.push(QualityCheck {
		id: "esm-exports".into(),
		category: "code-quality".into(),
		label: "ESM exports".into(),
		passed: is_esm,
		points: if is_esm { 3 } else { 0 },
		max_points: 3,
		detail: None,
		server_only: false,
	});

	// tree-shakable (3pts)
	let side_effects = pkg_json.get("sideEffects");
	let tree_shakable = side_effects
		.map(|v| v.as_bool() == Some(false) || v.is_array())
		.unwrap_or(false)
		|| (has_exports && pkg_type == "module");
	checks.push(QualityCheck {
		id: "tree-shakable".into(),
		category: "code-quality".into(),
		label: "Tree-shakeable".into(),
		passed: tree_shakable,
		points: if tree_shakable { 3 } else { 0 },
		max_points: 3,
		detail: None,
		server_only: false,
	});

	// has-exports-map (3pts)
	checks.push(QualityCheck {
		id: "has-exports-map".into(),
		category: "code-quality".into(),
		label: "Has exports map".into(),
		passed: has_exports,
		points: if has_exports { 3 } else { 0 },
		max_points: 3,
		detail: None,
		server_only: false,
	});

	// has-engines (1pt)
	let has_engines = pkg_json
		.get("engines")
		.and_then(|e| e.get("node"))
		.is_some();
	checks.push(QualityCheck {
		id: "has-engines".into(),
		category: "code-quality".into(),
		label: "Has engines field".into(),
		passed: has_engines,
		points: if has_engines { 1 } else { 0 },
		max_points: 1,
		detail: None,
		server_only: false,
	});

	// small-deps (3pts)
	let dep_count = pkg_json
		.get("dependencies")
		.and_then(|d| d.as_object())
		.map(|o| o.len())
		.unwrap_or(0);
	let dep_pts = match dep_count {
		0 => 3,
		1..=3 => 2,
		4..=7 => 1,
		_ => 0,
	};
	checks.push(QualityCheck {
		id: "small-deps".into(),
		category: "code-quality".into(),
		label: "Small dependency footprint".into(),
		passed: dep_pts > 0,
		points: dep_pts,
		max_points: 3,
		detail: Some(format!("{dep_count} dependencies")),
		server_only: false,
	});

	// source-maps (1pt)
	let has_source_maps = files
		.iter()
		.any(|f| f.ends_with(".js.map") || f.ends_with(".mjs.map"));
	checks.push(QualityCheck {
		id: "source-maps".into(),
		category: "code-quality".into(),
		label: "Has source maps".into(),
		passed: has_source_maps,
		points: if has_source_maps { 1 } else { 0 },
		max_points: 1,
		detail: None,
		server_only: false,
	});

	// Server-only code quality checks
	for (id, label, pts) in [
		("intellisense-coverage", "IntelliSense coverage", 4),
		("no-eval", "No eval() usage", 3),
	] {
		checks.push(QualityCheck {
			id: id.into(),
			category: "code-quality".into(),
			label: label.into(),
			passed: false,
			points: 0,
			max_points: pts,
			detail: Some("Server verifies after upload".into()),
			server_only: true,
		});
	}
}

// ── Swift Code Quality (31pts) ─────────────────────────────────────────

fn push_swift_code_quality_checks(
	checks: &mut Vec<QualityCheck>,
	swift_manifest: Option<&serde_json::Value>,
	files: &[String],
) {
	let empty_arr = serde_json::json!([]);
	let platforms = swift_manifest
		.and_then(|m| m.get("platforms"))
		.and_then(|p| p.as_array())
		.unwrap_or(&empty_arr.as_array().unwrap());
	let dependencies = swift_manifest
		.and_then(|m| m.get("dependencies"))
		.and_then(|d| d.as_array())
		.unwrap_or(&empty_arr.as_array().unwrap());

	// has-platforms (6pts) — Package.swift declares platform requirements
	let platform_names: Vec<String> = platforms
		.iter()
		.filter_map(|p| {
			// Raw manifest uses "platformName", normalized uses "name"
			let name = p
				.get("platformName")
				.or_else(|| p.get("name"))
				.and_then(|n| n.as_str())?;
			let version = p.get("version").and_then(|v| v.as_str()).unwrap_or("");
			if version.is_empty() {
				Some(name.to_string())
			} else {
				Some(format!("{name} {version}"))
			}
		})
		.collect();
	let has_platforms = !platform_names.is_empty();
	checks.push(QualityCheck {
		id: "has-platforms".into(),
		category: "code-quality".into(),
		label: "Has platform declarations".into(),
		passed: has_platforms,
		points: if has_platforms { 6 } else { 0 },
		max_points: 6,
		detail: if has_platforms {
			Some(format!("Platforms: {}", platform_names.join(", ")))
		} else {
			Some("Declare platforms in Package.swift".into())
		},
		server_only: false,
	});

	// recent-tools-version (5pts) — swift-tools-version >= 5.9
	// Raw manifest has toolsVersion as object { _version: "5.9.0" } or string
	let tools_version = swift_manifest
		.and_then(|m| m.get("toolsVersion"))
		.and_then(|tv| {
			tv.as_str().map(|s| s.to_string()).or_else(|| {
				tv.get("_version")
					.and_then(|v| v.as_str())
					.map(|s| s.to_string())
			})
		})
		.unwrap_or_default();
	let tools_version = tools_version.as_str();
	let is_recent = parse_tools_version_recent(tools_version);
	checks.push(QualityCheck {
		id: "recent-tools-version".into(),
		category: "code-quality".into(),
		label: "Uses recent swift-tools-version".into(),
		passed: is_recent,
		points: if is_recent { 5 } else { 0 },
		max_points: 5,
		detail: if !tools_version.is_empty() {
			Some(format!("swift-tools-version: {tools_version}"))
		} else {
			Some("Could not determine swift-tools-version".into())
		},
		server_only: false,
	});

	// multi-platform (4pts) — supports multiple platforms
	let platform_count = platforms.len();
	let multi_pts = match platform_count {
		3.. => 4,
		2 => 3,
		1 => 2,
		_ => 0,
	};
	checks.push(QualityCheck {
		id: "multi-platform".into(),
		category: "code-quality".into(),
		label: "Supports multiple platforms".into(),
		passed: multi_pts > 0,
		points: multi_pts,
		max_points: 4,
		detail: Some(format!(
			"Supports {} platform{}",
			platform_count,
			if platform_count == 1 { "" } else { "s" }
		)),
		server_only: false,
	});

	// has-public-api (5pts) — has .swift source files (server does deeper analysis)
	let swift_source_count = files
		.iter()
		.filter(|f| {
			f.ends_with(".swift")
				&& !f.to_lowercase().contains("tests/")
				&& !f.to_lowercase().contains("test/")
				&& *f != "Package.swift"
				&& !f.ends_with("/Package.swift")
		})
		.count();
	let has_public_api = swift_source_count > 0;
	checks.push(QualityCheck {
		id: "has-public-api".into(),
		category: "code-quality".into(),
		label: "Has public API surface".into(),
		passed: has_public_api,
		points: if has_public_api { 5 } else { 0 },
		max_points: 5,
		detail: if has_public_api {
			Some(format!("{swift_source_count} Swift source files"))
		} else {
			Some("No Swift source files found".into())
		},
		server_only: true,
	});

	// has-doc-comments (7pts) — server-side DocC check
	checks.push(QualityCheck {
		id: "has-doc-comments".into(),
		category: "code-quality".into(),
		label: "Has DocC documentation".into(),
		passed: false,
		points: 0,
		max_points: 7,
		detail: Some("Server verifies after upload".into()),
		server_only: true,
	});

	// small-deps (4pts) — Swift dependency count (different scale than JS)
	let dep_count = dependencies.len();
	let dep_pts = match dep_count {
		0 => 4,
		1..=2 => 3,
		3..=5 => 2,
		6..=10 => 1,
		_ => 0,
	};
	checks.push(QualityCheck {
		id: "small-deps".into(),
		category: "code-quality".into(),
		label: "Small dependency footprint".into(),
		passed: dep_pts > 0,
		points: dep_pts,
		max_points: 4,
		detail: Some(format!("{dep_count} dependencies")),
		server_only: false,
	});
}

/// Parse swift-tools-version string and check if >= 5.9.
fn parse_tools_version_recent(version: &str) -> bool {
	// Handle formats like "5.9", "5.9.0", "6.0", "6.3.0"
	let parts: Vec<&str> = version.split('.').collect();
	if parts.len() < 2 {
		return false;
	}
	let major = parts[0].parse::<u32>().unwrap_or(0);
	let minor = parts[1].parse::<u32>().unwrap_or(0);
	major > 5 || (major == 5 && minor >= 9)
}

// ── JS Testing (11pts) ────────────────────────────────────────────────

fn push_js_testing_checks(
	checks: &mut Vec<QualityCheck>,
	pkg_json: &serde_json::Value,
	project_dir: &Path,
) {
	// has-test-files (7pts)
	let has_test_files = check_test_files_js(project_dir);
	checks.push(QualityCheck {
		id: "has-test-files".into(),
		category: "testing".into(),
		label: "Has test files".into(),
		passed: has_test_files,
		points: if has_test_files { 7 } else { 0 },
		max_points: 7,
		detail: None,
		server_only: false,
	});

	// has-test-script (4pts)
	let test_script = pkg_json
		.get("scripts")
		.and_then(|s| s.get("test"))
		.and_then(|v| v.as_str())
		.unwrap_or("");
	let has_test_script = !test_script.is_empty() && !test_script.contains("no test specified");
	checks.push(QualityCheck {
		id: "has-test-script".into(),
		category: "testing".into(),
		label: "Has test script".into(),
		passed: has_test_script,
		points: if has_test_script { 4 } else { 0 },
		max_points: 4,
		detail: None,
		server_only: false,
	});
}

// ── Swift Testing (11pts) ──────────────────────────────────────────────

fn push_swift_testing_checks(
	checks: &mut Vec<QualityCheck>,
	swift_manifest: Option<&serde_json::Value>,
	project_dir: &Path,
) {
	let empty_arr = serde_json::json!([]);
	let targets = swift_manifest
		.and_then(|m| m.get("targets"))
		.and_then(|t| t.as_array())
		.unwrap_or(&empty_arr.as_array().unwrap());

	let test_targets: Vec<&str> = targets
		.iter()
		.filter(|t| t.get("type").and_then(|v| v.as_str()) == Some("test"))
		.filter_map(|t| t.get("name").and_then(|n| n.as_str()))
		.collect();

	// has-test-files (7pts) — test targets in Package.swift or test directories
	let has_test_targets = !test_targets.is_empty();
	let has_test_dirs = project_dir.join("Tests").is_dir() || project_dir.join("tests").is_dir();
	let has_tests = has_test_targets || has_test_dirs;
	checks.push(QualityCheck {
		id: "has-test-files".into(),
		category: "testing".into(),
		label: "Has test targets".into(),
		passed: has_tests,
		points: if has_tests { 7 } else { 0 },
		max_points: 7,
		detail: if has_test_targets {
			Some(format!(
				"{} test target{}: {}",
				test_targets.len(),
				if test_targets.len() == 1 { "" } else { "s" },
				test_targets.join(", ")
			))
		} else if has_test_dirs {
			Some("Test directory found".into())
		} else {
			Some("No test targets in Package.swift".into())
		},
		server_only: false,
	});

	// has-test-script (4pts) — test targets defined = test configuration exists
	checks.push(QualityCheck {
		id: "has-test-script".into(),
		category: "testing".into(),
		label: "Has test configuration".into(),
		passed: has_test_targets,
		points: if has_test_targets { 4 } else { 0 },
		max_points: 4,
		detail: if has_test_targets {
			Some("Test targets defined in Package.swift".into())
		} else {
			Some("Add test targets to Package.swift".into())
		},
		server_only: false,
	});
}

// ── Health (36pts) — shared across ecosystems ──────────────────────────

fn push_health_checks(checks: &mut Vec<QualityCheck>, pkg_json: &serde_json::Value, ecosystem: &str) {
	// has-description (3pts)
	let desc = pkg_json
		.get("description")
		.and_then(|v| v.as_str())
		.unwrap_or("");
	checks.push(QualityCheck {
		id: "has-description".into(),
		category: "health".into(),
		label: "Has description".into(),
		passed: desc.len() > 10,
		points: if desc.len() > 10 { 3 } else { 0 },
		max_points: 3,
		detail: None,
		server_only: false,
	});

	// has-keywords (1pt)
	let has_keywords = pkg_json
		.get("keywords")
		.and_then(|k| k.as_array())
		.map(|a| !a.is_empty())
		.unwrap_or(false);
	checks.push(QualityCheck {
		id: "has-keywords".into(),
		category: "health".into(),
		label: "Has keywords".into(),
		passed: has_keywords,
		points: if has_keywords { 1 } else { 0 },
		max_points: 1,
		detail: None,
		server_only: false,
	});

	// has-repository (2pts)
	let has_repo = pkg_json.get("repository").is_some();
	checks.push(QualityCheck {
		id: "has-repository".into(),
		category: "health".into(),
		label: "Has repository".into(),
		passed: has_repo,
		points: if has_repo { 2 } else { 0 },
		max_points: 2,
		detail: None,
		server_only: false,
	});

	// has-homepage (1pt)
	let has_homepage = pkg_json.get("homepage").is_some();
	checks.push(QualityCheck {
		id: "has-homepage".into(),
		category: "health".into(),
		label: "Has homepage".into(),
		passed: has_homepage,
		points: if has_homepage { 1 } else { 0 },
		max_points: 1,
		detail: None,
		server_only: false,
	});

	// no-lifecycle-scripts (2pts) — JS only (Swift has no npm lifecycle scripts)
	if ecosystem != "swift" {
		let has_lifecycle = pkg_json
			.get("scripts")
			.and_then(|s| s.as_object())
			.map(|scripts| {
				scripts.keys().any(|k| {
					matches!(
						k.as_str(),
						"preinstall"
							| "install" | "postinstall"
							| "preuninstall" | "uninstall"
							| "postuninstall"
					)
				})
			})
			.unwrap_or(false);
		checks.push(QualityCheck {
			id: "no-lifecycle-scripts".into(),
			category: "health".into(),
			label: "No lifecycle scripts".into(),
			passed: !has_lifecycle,
			points: if !has_lifecycle { 2 } else { 0 },
			max_points: 2,
			detail: None,
			server_only: false,
		});
	}

	// semver-consistency (4pts)
	let version = pkg_json
		.get("version")
		.and_then(|v| v.as_str())
		.unwrap_or("");
	let valid_semver = lpm_semver::Version::parse(version).is_ok();
	checks.push(QualityCheck {
		id: "semver-consistency".into(),
		category: "health".into(),
		label: "SemVer consistency".into(),
		passed: valid_semver,
		points: if valid_semver { 4 } else { 0 },
		max_points: 4,
		detail: None,
		server_only: false,
	});

	// Server-only health checks
	for (id, label, pts) in [
		("no-vulnerabilities", "No known vulnerabilities", 5),
		("maintenance-health", "Active maintenance", 4),
		("author-verified", "Verified author", 3),
		("has-skills", "Has Agent Skills", 7),
		("skills-comprehensive", "Comprehensive Agent Skills", 3),
		("reasonable-size", "Reasonable package size", 3),
	] {
		checks.push(QualityCheck {
			id: id.into(),
			category: "health".into(),
			label: label.into(),
			passed: false,
			points: 0,
			max_points: pts,
			detail: Some("Server verifies after upload".into()),
			server_only: true,
		});
	}
}

/// Check if the project has test files (JS ecosystem).
fn check_test_files_js(project_dir: &Path) -> bool {
	for dir in ["test", "tests", "__tests__", "spec"] {
		if project_dir.join(dir).is_dir() {
			return true;
		}
	}
	for pattern in ["*.test.*", "*.spec.*"] {
		let glob_pattern = project_dir.join("**").join(pattern);
		if let Ok(entries) = glob::glob(&glob_pattern.to_string_lossy()) {
			if entries.into_iter().flatten().next().is_some() {
				return true;
			}
		}
	}
	false
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_js_quality_total_is_100() {
		let pkg = serde_json::json!({
			"name": "test",
			"version": "1.0.0",
		});
		let result = run_quality_checks(&pkg, None, Path::new("/tmp"), &[], "js", None);
		assert_eq!(result.max_score, 100, "JS total should be 100");
	}

	#[test]
	fn test_swift_quality_total_is_100() {
		let pkg = serde_json::json!({
			"name": "test",
			"version": "1.0.0",
		});
		let manifest = serde_json::json!({
			"toolsVersion": "5.9",
			"platforms": [],
			"dependencies": [],
			"targets": [],
		});
		let result =
			run_quality_checks(&pkg, None, Path::new("/tmp"), &[], "swift", Some(&manifest));
		assert_eq!(result.max_score, 100, "Swift total should be 100");
	}

	#[test]
	fn test_swift_platforms_check() {
		let manifest = serde_json::json!({
			"platforms": [
				{"platformName": "ios", "version": "13.0"},
				{"platformName": "macos", "version": "10.15"},
				{"platformName": "watchos", "version": "6.0"},
			],
			"dependencies": [],
			"targets": [],
			"toolsVersion": "5.9",
		});
		let mut checks = Vec::new();
		push_swift_code_quality_checks(&mut checks, Some(&manifest), &[]);

		let platforms_check = checks.iter().find(|c| c.id == "has-platforms").unwrap();
		assert!(platforms_check.passed);
		assert_eq!(platforms_check.points, 6);

		let multi_check = checks.iter().find(|c| c.id == "multi-platform").unwrap();
		assert!(multi_check.passed);
		assert_eq!(multi_check.points, 4); // 3+ platforms = 4pts
	}

	#[test]
	fn test_swift_tools_version() {
		assert!(parse_tools_version_recent("5.9"));
		assert!(parse_tools_version_recent("5.9.0"));
		assert!(parse_tools_version_recent("5.10"));
		assert!(parse_tools_version_recent("6.0"));
		assert!(parse_tools_version_recent("6.3.0"));
		assert!(!parse_tools_version_recent("5.8"));
		assert!(!parse_tools_version_recent("5.7.1"));
		assert!(!parse_tools_version_recent("4.0"));
		assert!(!parse_tools_version_recent(""));
	}

	#[test]
	fn test_swift_deps_scoring() {
		let manifest_0 = serde_json::json!({ "platforms": [], "dependencies": [], "targets": [], "toolsVersion": "5.9" });
		let manifest_2 = serde_json::json!({ "platforms": [], "dependencies": [{"url": "a"}, {"url": "b"}], "targets": [], "toolsVersion": "5.9" });
		let manifest_4 = serde_json::json!({ "platforms": [], "dependencies": [{"url":"a"},{"url":"b"},{"url":"c"},{"url":"d"}], "targets": [], "toolsVersion": "5.9" });

		let mut c0 = Vec::new();
		push_swift_code_quality_checks(&mut c0, Some(&manifest_0), &[]);
		let deps0 = c0.iter().find(|c| c.id == "small-deps").unwrap();
		assert_eq!(deps0.points, 4); // 0 deps = 4pts

		let mut c2 = Vec::new();
		push_swift_code_quality_checks(&mut c2, Some(&manifest_2), &[]);
		let deps2 = c2.iter().find(|c| c.id == "small-deps").unwrap();
		assert_eq!(deps2.points, 3); // 1-2 deps = 3pts

		let mut c4 = Vec::new();
		push_swift_code_quality_checks(&mut c4, Some(&manifest_4), &[]);
		let deps4 = c4.iter().find(|c| c.id == "small-deps").unwrap();
		assert_eq!(deps4.points, 2); // 3-5 deps = 2pts
	}

	#[test]
	fn test_swift_test_targets() {
		let manifest = serde_json::json!({
			"targets": [
				{"name": "MyLib", "type": "regular"},
				{"name": "MyLibTests", "type": "test"},
			],
		});
		let mut checks = Vec::new();
		push_swift_testing_checks(&mut checks, Some(&manifest), Path::new("/tmp"));

		let test_files = checks.iter().find(|c| c.id == "has-test-files").unwrap();
		assert!(test_files.passed);
		assert_eq!(test_files.points, 7);
		assert!(test_files.detail.as_ref().unwrap().contains("MyLibTests"));

		let test_config = checks.iter().find(|c| c.id == "has-test-script").unwrap();
		assert!(test_config.passed);
		assert_eq!(test_config.points, 4);
	}
}
