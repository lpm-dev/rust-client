//! Client-side quality scoring for packages before publish.
//!
//! The server is the source of truth — it re-verifies all checks independently
//! using the tarball contents. These client-side checks provide fast feedback
//! before uploading.
//!
//! 4 categories, 100 total points (JS ecosystem):
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
	pub name: String,
	pub category: String,
	pub points: u32,
	pub max_points: u32,
	pub passed: bool,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub detail: Option<String>,
	#[serde(default)]
	pub server_only: bool,
}

/// Run all client-side quality checks.
pub fn run_quality_checks(
	pkg_json: &serde_json::Value,
	readme: Option<&str>,
	project_dir: &Path,
	files: &[String],
) -> QualityResult {
	let mut checks = Vec::new();

	// ── Documentation (22pts) ──────────────────────────────────────

	// has-readme (8pts)
	let readme_len = readme.map(|r| r.len()).unwrap_or(0);
	checks.push(QualityCheck {
		name: "has-readme".into(),
		category: "documentation".into(),
		points: if readme_len > 100 { 8 } else { 0 },
		max_points: 8,
		passed: readme_len > 100,
		detail: if readme_len == 0 {
			Some("No README found".into())
		} else if readme_len <= 100 {
			Some(format!("README too short ({readme_len} chars, need >100)"))
		} else {
			None
		},
		server_only: false,
	});

	// readme-install (3pts)
	let readme_lower = readme.unwrap_or("").to_lowercase();
	let has_install = readme_lower.contains("install")
		|| readme_lower.contains("getting started")
		|| readme_lower.contains("setup")
		|| readme_lower.contains("npm install")
		|| readme_lower.contains("lpm install")
		|| readme_lower.contains("lpm add");
	checks.push(QualityCheck {
		name: "readme-install".into(),
		category: "documentation".into(),
		points: if has_install { 3 } else { 0 },
		max_points: 3,
		passed: has_install,
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
		name: "readme-usage".into(),
		category: "documentation".into(),
		points: if has_usage { 3 } else { 0 },
		max_points: 3,
		passed: has_usage,
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
		name: "readme-api".into(),
		category: "documentation".into(),
		points: if has_api { 2 } else { 0 },
		max_points: 2,
		passed: has_api,
		detail: None,
		server_only: false,
	});

	// has-changelog (3pts)
	let has_changelog = files.iter().any(|f| {
		let lower = f.to_lowercase();
		lower.contains("changelog") || lower.contains("changes") || lower.contains("history")
	});
	checks.push(QualityCheck {
		name: "has-changelog".into(),
		category: "documentation".into(),
		points: if has_changelog { 3 } else { 0 },
		max_points: 3,
		passed: has_changelog,
		detail: None,
		server_only: false,
	});

	// has-license (3pts)
	let has_license = files.iter().any(|f| f.to_lowercase().starts_with("license"))
		|| pkg_json.get("license").and_then(|v| v.as_str()).is_some();
	checks.push(QualityCheck {
		name: "has-license".into(),
		category: "documentation".into(),
		points: if has_license { 3 } else { 0 },
		max_points: 3,
		passed: has_license,
		detail: None,
		server_only: false,
	});

	// ── Code Quality (31pts) ───────────────────────────────────────

	// has-types (8pts)
	let has_types = pkg_json.get("types").is_some()
		|| pkg_json.get("typings").is_some()
		|| files.iter().any(|f| f.ends_with(".d.ts") || f.ends_with(".d.cts") || f.ends_with(".d.mts"));
	checks.push(QualityCheck {
		name: "has-types".into(),
		category: "code-quality".into(),
		points: if has_types { 8 } else { 0 },
		max_points: 8,
		passed: has_types,
		detail: None,
		server_only: false,
	});

	// esm-exports (3pts)
	let pkg_type = pkg_json.get("type").and_then(|v| v.as_str()).unwrap_or("");
	let has_module = pkg_json.get("module").is_some();
	let has_exports = pkg_json.get("exports").is_some();
	let is_esm = pkg_type == "module" || has_module || has_exports;
	checks.push(QualityCheck {
		name: "esm-exports".into(),
		category: "code-quality".into(),
		points: if is_esm { 3 } else { 0 },
		max_points: 3,
		passed: is_esm,
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
		name: "tree-shakable".into(),
		category: "code-quality".into(),
		points: if tree_shakable { 3 } else { 0 },
		max_points: 3,
		passed: tree_shakable,
		detail: None,
		server_only: false,
	});

	// has-exports-map (3pts)
	checks.push(QualityCheck {
		name: "has-exports-map".into(),
		category: "code-quality".into(),
		points: if has_exports { 3 } else { 0 },
		max_points: 3,
		passed: has_exports,
		detail: None,
		server_only: false,
	});

	// has-engines (1pt)
	let has_engines = pkg_json
		.get("engines")
		.and_then(|e| e.get("node"))
		.is_some();
	checks.push(QualityCheck {
		name: "has-engines".into(),
		category: "code-quality".into(),
		points: if has_engines { 1 } else { 0 },
		max_points: 1,
		passed: has_engines,
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
		name: "small-deps".into(),
		category: "code-quality".into(),
		points: dep_pts,
		max_points: 3,
		passed: dep_pts > 0,
		detail: Some(format!("{dep_count} dependencies")),
		server_only: false,
	});

	// source-maps (1pt)
	let has_source_maps = files.iter().any(|f| f.ends_with(".js.map") || f.ends_with(".mjs.map"));
	checks.push(QualityCheck {
		name: "source-maps".into(),
		category: "code-quality".into(),
		points: if has_source_maps { 1 } else { 0 },
		max_points: 1,
		passed: has_source_maps,
		detail: None,
		server_only: false,
	});

	// Server-only code quality checks
	for (name, pts) in [
		("intellisense-coverage", 4),
		("no-eval", 3),
	] {
		checks.push(QualityCheck {
			name: name.into(),
			category: "code-quality".into(),
			points: 0,
			max_points: pts,
			passed: false,
			detail: Some("Server verifies after upload".into()),
			server_only: true,
		});
	}

	// ── Testing (11pts) ────────────────────────────────────────────

	// has-test-files (7pts)
	let has_test_files = check_test_files(project_dir);
	checks.push(QualityCheck {
		name: "has-test-files".into(),
		category: "testing".into(),
		points: if has_test_files { 7 } else { 0 },
		max_points: 7,
		passed: has_test_files,
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
		name: "has-test-script".into(),
		category: "testing".into(),
		points: if has_test_script { 4 } else { 0 },
		max_points: 4,
		passed: has_test_script,
		detail: None,
		server_only: false,
	});

	// ── Health (36pts) ─────────────────────────────────────────────

	// has-description (3pts)
	let desc = pkg_json
		.get("description")
		.and_then(|v| v.as_str())
		.unwrap_or("");
	checks.push(QualityCheck {
		name: "has-description".into(),
		category: "health".into(),
		points: if desc.len() > 10 { 3 } else { 0 },
		max_points: 3,
		passed: desc.len() > 10,
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
		name: "has-keywords".into(),
		category: "health".into(),
		points: if has_keywords { 1 } else { 0 },
		max_points: 1,
		passed: has_keywords,
		detail: None,
		server_only: false,
	});

	// has-repository (2pts)
	let has_repo = pkg_json.get("repository").is_some();
	checks.push(QualityCheck {
		name: "has-repository".into(),
		category: "health".into(),
		points: if has_repo { 2 } else { 0 },
		max_points: 2,
		passed: has_repo,
		detail: None,
		server_only: false,
	});

	// has-homepage (1pt)
	let has_homepage = pkg_json.get("homepage").is_some();
	checks.push(QualityCheck {
		name: "has-homepage".into(),
		category: "health".into(),
		points: if has_homepage { 1 } else { 0 },
		max_points: 1,
		passed: has_homepage,
		detail: None,
		server_only: false,
	});

	// no-lifecycle-scripts (2pts)
	let has_lifecycle = pkg_json
		.get("scripts")
		.and_then(|s| s.as_object())
		.map(|scripts| {
			scripts.keys().any(|k| {
				matches!(
					k.as_str(),
					"preinstall" | "install" | "postinstall" | "preuninstall" | "uninstall" | "postuninstall"
				)
			})
		})
		.unwrap_or(false);
	checks.push(QualityCheck {
		name: "no-lifecycle-scripts".into(),
		category: "health".into(),
		points: if !has_lifecycle { 2 } else { 0 },
		max_points: 2,
		passed: !has_lifecycle,
		detail: None,
		server_only: false,
	});

	// semver-consistency (4pts)
	let version = pkg_json.get("version").and_then(|v| v.as_str()).unwrap_or("");
	let valid_semver = lpm_semver::Version::parse(version).is_ok();
	checks.push(QualityCheck {
		name: "semver-consistency".into(),
		category: "health".into(),
		points: if valid_semver { 4 } else { 0 },
		max_points: 4,
		passed: valid_semver,
		detail: None,
		server_only: false,
	});

	// Server-only health checks
	for (name, pts) in [
		("no-vulnerabilities", 5),
		("maintenance-health", 4),
		("author-verified", 3),
		("has-skills", 7),
		("skills-comprehensive", 3),
		("reasonable-size", 3),
	] {
		checks.push(QualityCheck {
			name: name.into(),
			category: "health".into(),
			points: 0,
			max_points: pts,
			passed: false,
			detail: Some("Server verifies after upload".into()),
			server_only: true,
		});
	}

	// Calculate total
	let score: u32 = checks.iter().map(|c| c.points).sum();
	let max_score: u32 = checks.iter().map(|c| c.max_points).sum();

	QualityResult {
		score,
		max_score,
		checks,
	}
}

/// Check if the project has test files.
fn check_test_files(project_dir: &Path) -> bool {
	// Check common test directories
	for dir in ["test", "tests", "__tests__", "spec"] {
		if project_dir.join(dir).is_dir() {
			return true;
		}
	}

	// Check for test files in src/ and root
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
