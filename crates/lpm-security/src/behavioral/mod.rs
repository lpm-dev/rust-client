//! Client-side behavioral analysis for all packages (npm + @lpm.dev).
//!
//! Detects 22 security-relevant tags across three groups:
//! - **Source tags** (10): API usage patterns (filesystem, network, eval, etc.)
//! - **Supply chain tags** (7): Obfuscation, entropy, minified, telemetry, etc.
//! - **Manifest tags** (5): License + dependency configuration issues
//!
//! Runs on every extracted package in the store. Results are cached in
//! `.lpm-security.json` alongside the package — computed once per version, forever.
//!
//! ## Security
//!
//! All regex patterns use the `regex` crate which guarantees linear-time matching
//! (Thompson NFA). NEVER use `fancy-regex` here — we scan untrusted input from
//! arbitrary npm packages. See phase-25-todo.md §S1.
//!
//! ## Performance
//!
//! - `RegexSet` + `OnceLock` for compile-once, single-pass matching
//! - File extension filtering before I/O (skip non-source files)
//! - Per-file size limit: 2MB (skip bundled/generated files)
//! - Per-package total limit: 50MB scanned
//! - Shannon entropy pre-filter: 95% of files skip the expensive extraction
//! - Comment stripping: streaming state machine, preserves newlines
//!
//! Target: < 100ms per typical 100-file package on M1.

pub mod manifest;
pub mod source;
pub mod supply_chain;

use manifest::ManifestTags;
use serde::{Deserialize, Serialize};
use source::SourceTags;
use std::collections::HashMap;
use std::path::Path;
use supply_chain::SupplyChainTags;

/// Current schema version for `.lpm-security.json`.
/// Bump this when adding new tags — cached files with older versions
/// will be automatically re-analyzed.
pub const SCHEMA_VERSION: u32 = 2;

/// Maximum file size to scan (2MB). Files larger than this are skipped.
/// No legitimate single source file is this large — it's bundled/generated.
const MAX_FILE_SIZE: u64 = 2 * 1024 * 1024;

/// Maximum total bytes to scan per package (50MB). Analysis aborts (with warning)
/// if cumulative reads exceed this, returning partial results.
const MAX_TOTAL_SCAN_BYTES: u64 = 50 * 1024 * 1024;

/// Maximum number of source files to scan per package.
const MAX_FILES_PER_PACKAGE: usize = 5_000;

/// Source file extensions that should be scanned.
const SOURCE_EXTENSIONS: &[&str] = &[
	"js", "mjs", "cjs", "ts", "mts", "cts", "jsx", "tsx",
];

/// Complete analysis result for a single package.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PackageAnalysis {
	/// Schema version — re-analyze if this doesn't match SCHEMA_VERSION.
	pub version: u32,
	/// ISO 8601 timestamp of when analysis was performed.
	pub analyzed_at: String,
	/// Source code behavioral tags (10).
	pub source: SourceTags,
	/// Supply chain & code quality tags (7).
	pub supply_chain: SupplyChainTags,
	/// Package manifest tags (5).
	pub manifest: ManifestTags,
	/// Additional metadata (file count, URL domains, etc.)
	pub meta: AnalysisMeta,
}

/// Metadata about the analysis run.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AnalysisMeta {
	/// Number of source files scanned.
	#[serde(default)]
	pub files_scanned: usize,
	/// Total bytes of source code scanned.
	#[serde(default)]
	pub bytes_scanned: u64,
	/// Whether any limit was reached during analysis.
	#[serde(default, skip_serializing_if = "std::ops::Not::not")]
	pub limit_reached: bool,
	/// Unique URL domains found in source code.
	#[serde(default, skip_serializing_if = "Vec::is_empty")]
	pub url_domains: Vec<String>,
}

/// Analyze a package directory for all 22 behavioral tags.
///
/// Walks the directory, filters by file extension, reads source files,
/// strips comments, and runs all tag detectors. Returns a complete
/// `PackageAnalysis` that can be serialized to `.lpm-security.json`.
///
/// Respects per-file (2MB) and per-package (50MB) size limits.
/// Skips `.min.js` files for source tag analysis (but flags `minified: true`).
pub fn analyze_package(package_dir: &Path) -> PackageAnalysis {
	// Walk source files
	let source_files = collect_source_files(package_dir);

	// Use rayon for parallel scanning on packages with many files (20+).
	// Smaller packages don't benefit from thread pool overhead.
	let file_result = if source_files.len() >= 20 {
		analyze_files_parallel(&source_files)
	} else {
		analyze_files_sequential(&source_files)
	};

	// Set trivial tag at package level (< 10 lines across ALL source files)
	let mut supply_chain_tags = file_result.supply_chain;
	if file_result.meta.files_scanned > 0 {
		supply_chain_tags.trivial =
			file_result.total_code_lines < 10 && file_result.total_export_count <= 1;
	}

	// Deduplicate URL domains
	let mut url_domains = file_result.url_domains;
	url_domains.sort_unstable();
	url_domains.dedup();
	let mut meta = file_result.meta;
	meta.url_domains = url_domains;

	// Manifest tags (5) — read package.json
	let manifest_tags = analyze_package_manifest(package_dir);

	// Build timestamp
	let analyzed_at = chrono::Utc::now().to_rfc3339();

	PackageAnalysis {
		version: SCHEMA_VERSION,
		analyzed_at,
		source: file_result.source,
		supply_chain: supply_chain_tags,
		manifest: manifest_tags,
		meta,
	}
}

/// Intermediate result from scanning a single file.
struct FileAnalysisResult {
	source: SourceTags,
	supply_chain: SupplyChainTags,
	url_domains: Vec<String>,
	total_code_lines: usize,
	total_export_count: usize,
	files_scanned: usize,
	bytes_scanned: u64,
}

/// Accumulated result from scanning all files.
struct AccumulatedResult {
	source: SourceTags,
	supply_chain: SupplyChainTags,
	url_domains: Vec<String>,
	total_code_lines: usize,
	total_export_count: usize,
	meta: AnalysisMeta,
}

/// Analyze a single file. Returns None if the file should be skipped.
fn analyze_single_file(file_path: &std::path::PathBuf) -> Option<FileAnalysisResult> {
	let file_size = std::fs::metadata(file_path).ok()?.len();

	if file_size > MAX_FILE_SIZE {
		let filename = file_path.file_name()?.to_str().unwrap_or("");
		if supply_chain::is_minified_filename(filename) {
			return Some(FileAnalysisResult {
				source: SourceTags::default(),
				supply_chain: SupplyChainTags { minified: true, ..Default::default() },
				url_domains: Vec::new(),
				total_code_lines: 0,
				total_export_count: 0,
				files_scanned: 0,
				bytes_scanned: 0,
			});
		}
		return None;
	}

	let raw_content = std::fs::read(file_path).ok()?;
	let filename = file_path.file_name()?.to_str().unwrap_or("");

	// Minified filename check
	if supply_chain::is_minified_filename(filename) {
		return Some(FileAnalysisResult {
			source: SourceTags::default(),
			supply_chain: SupplyChainTags { minified: true, ..Default::default() },
			url_domains: Vec::new(),
			total_code_lines: 0,
			total_export_count: 0,
			files_scanned: 1,
			bytes_scanned: raw_content.len() as u64,
		});
	}

	// Minified content check
	if supply_chain::detect_minified(&raw_content) {
		return Some(FileAnalysisResult {
			source: SourceTags::default(),
			supply_chain: SupplyChainTags { minified: true, ..Default::default() },
			url_domains: Vec::new(),
			total_code_lines: 0,
			total_export_count: 0,
			files_scanned: 1,
			bytes_scanned: raw_content.len() as u64,
		});
	}

	// Strip comments (each thread gets its own buffer)
	let mut comment_buf = Vec::with_capacity(raw_content.len());
	source::strip_comments(&raw_content, &mut comment_buf);
	let stripped = String::from_utf8_lossy(&comment_buf);

	let file_source_tags = source::analyze_source(&stripped);
	let file_supply_tags = supply_chain::analyze_supply_chain(&stripped, &raw_content);
	let domains = supply_chain::extract_url_domains(&stripped);
	let trivial = supply_chain::analyze_trivial(&stripped);

	Some(FileAnalysisResult {
		source: file_source_tags,
		supply_chain: file_supply_tags,
		url_domains: domains,
		total_code_lines: trivial.total_code_lines,
		total_export_count: trivial.export_count,
		files_scanned: 1,
		bytes_scanned: raw_content.len() as u64,
	})
}

/// Sequential file scanning (for packages with < 20 files).
fn analyze_files_sequential(files: &[std::path::PathBuf]) -> AccumulatedResult {
	let mut source_tags = SourceTags::default();
	let mut supply_chain_tags = SupplyChainTags::default();
	let mut meta = AnalysisMeta::default();
	let mut all_url_domains = Vec::new();
	let mut total_code_lines = 0usize;
	let mut total_export_count = 0usize;

	for file_path in files {
		if meta.files_scanned >= MAX_FILES_PER_PACKAGE {
			meta.limit_reached = true;
			break;
		}
		if let Some(result) = analyze_single_file(file_path) {
			if meta.bytes_scanned + result.bytes_scanned > MAX_TOTAL_SCAN_BYTES {
				meta.limit_reached = true;
				break;
			}
			source_tags = source::merge_source_tags(&source_tags, &result.source);
			supply_chain_tags =
				supply_chain::merge_supply_chain_tags(&supply_chain_tags, &result.supply_chain);
			all_url_domains.extend(result.url_domains);
			total_code_lines += result.total_code_lines;
			total_export_count += result.total_export_count;
			meta.files_scanned += result.files_scanned;
			meta.bytes_scanned += result.bytes_scanned;
		}
	}

	AccumulatedResult {
		source: source_tags,
		supply_chain: supply_chain_tags,
		url_domains: all_url_domains,
		total_code_lines,
		total_export_count,
		meta,
	}
}

/// Parallel file scanning using rayon (for packages with 20+ files).
fn analyze_files_parallel(files: &[std::path::PathBuf]) -> AccumulatedResult {
	use rayon::prelude::*;
	use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

	let files_scanned = AtomicUsize::new(0);
	let bytes_scanned = AtomicU64::new(0);

	// Analyze all files in parallel, collecting results
	let results: Vec<FileAnalysisResult> = files
		.par_iter()
		.filter_map(|file_path| {
			// Approximate limit checks (may slightly overshoot — acceptable for safety limits)
			if files_scanned.load(Ordering::Relaxed) >= MAX_FILES_PER_PACKAGE {
				return None;
			}
			if bytes_scanned.load(Ordering::Relaxed) > MAX_TOTAL_SCAN_BYTES {
				return None;
			}

			let result = analyze_single_file(file_path)?;
			files_scanned.fetch_add(result.files_scanned, Ordering::Relaxed);
			bytes_scanned.fetch_add(result.bytes_scanned, Ordering::Relaxed);
			Some(result)
		})
		.collect();

	// Merge all results
	let mut source_tags = SourceTags::default();
	let mut supply_chain_tags = SupplyChainTags::default();
	let mut all_url_domains = Vec::new();
	let mut total_code_lines = 0usize;
	let mut total_export_count = 0usize;
	let mut meta = AnalysisMeta::default();

	for result in results {
		source_tags = source::merge_source_tags(&source_tags, &result.source);
		supply_chain_tags =
			supply_chain::merge_supply_chain_tags(&supply_chain_tags, &result.supply_chain);
		all_url_domains.extend(result.url_domains);
		total_code_lines += result.total_code_lines;
		total_export_count += result.total_export_count;
		meta.files_scanned += result.files_scanned;
		meta.bytes_scanned += result.bytes_scanned;
	}

	let limit_reached = files_scanned.load(Ordering::Relaxed) >= MAX_FILES_PER_PACKAGE
		|| bytes_scanned.load(Ordering::Relaxed) > MAX_TOTAL_SCAN_BYTES;
	meta.limit_reached = limit_reached;

	AccumulatedResult {
		source: source_tags,
		supply_chain: supply_chain_tags,
		url_domains: all_url_domains,
		total_code_lines,
		total_export_count,
		meta,
	}
}

/// Collect source files from a package directory, filtered by extension.
///
/// Skips `node_modules/`, hidden files/directories, `.d.ts` files, and `.map` files.
/// Returns paths sorted for deterministic analysis order.
fn collect_source_files(dir: &Path) -> Vec<std::path::PathBuf> {
	let mut files = Vec::new();
	collect_source_files_recursive(dir, &mut files);
	files.sort();
	files
}

fn collect_source_files_recursive(dir: &Path, files: &mut Vec<std::path::PathBuf>) {
	let entries = match std::fs::read_dir(dir) {
		Ok(e) => e,
		Err(_) => return,
	};

	for entry in entries.flatten() {
		let path = entry.path();
		let name = entry.file_name();
		let name_str = name.to_string_lossy();

		// Skip hidden files/directories
		if name_str.starts_with('.') {
			continue;
		}

		if path.is_dir() {
			// Skip node_modules (shouldn't exist in store, but defensive)
			if name_str == "node_modules" || name_str == "__tests__" || name_str == "test" {
				continue;
			}
			collect_source_files_recursive(&path, files);
			continue;
		}

		// Skip non-source files
		let ext = path
			.extension()
			.and_then(|e| e.to_str())
			.unwrap_or("");

		if !SOURCE_EXTENSIONS.contains(&ext) {
			continue;
		}

		// Skip .d.ts type declaration files (no runtime behavior)
		if name_str.ends_with(".d.ts")
			|| name_str.ends_with(".d.mts")
			|| name_str.ends_with(".d.cts")
		{
			continue;
		}

		// Skip .map source maps
		if name_str.ends_with(".map") {
			continue;
		}

		files.push(path);
	}
}

/// Analyze package.json for manifest tags.
fn analyze_package_manifest(package_dir: &Path) -> ManifestTags {
	let pkg_json_path = package_dir.join("package.json");
	let content = match std::fs::read_to_string(&pkg_json_path) {
		Ok(c) => c,
		Err(_) => return ManifestTags::default(),
	};

	let parsed: serde_json::Value = match serde_json::from_str(&content) {
		Ok(v) => v,
		Err(_) => return ManifestTags::default(),
	};

	let license = parsed
		.get("license")
		.and_then(|v| v.as_str());

	// Also check "licence" typo
	let license = license.or_else(|| parsed.get("licence").and_then(|v| v.as_str()));

	let dependencies = parse_deps_map(parsed.get("dependencies"));
	let dev_dependencies = parse_deps_map(parsed.get("devDependencies"));
	let optional_dependencies = parse_deps_map(parsed.get("optionalDependencies"));

	manifest::analyze_manifest(
		license,
		dependencies.as_ref(),
		dev_dependencies.as_ref(),
		optional_dependencies.as_ref(),
	)
}

/// Parse a JSON value into a HashMap<String, String> for dependency maps.
fn parse_deps_map(value: Option<&serde_json::Value>) -> Option<HashMap<String, String>> {
	let obj = value?.as_object()?;
	let mut map = HashMap::with_capacity(obj.len());
	for (key, val) in obj {
		if let Some(v) = val.as_str() {
			map.insert(key.clone(), v.to_string());
		}
	}
	Some(map)
}

/// Read a cached `.lpm-security.json` file from a package directory.
///
/// Returns `None` if:
/// - File doesn't exist (never analyzed)
/// - File can't be parsed
/// - Schema version is outdated (needs re-analysis)
pub fn read_cached_analysis(package_dir: &Path) -> Option<PackageAnalysis> {
	let path = package_dir.join(".lpm-security.json");
	let content = std::fs::read_to_string(&path).ok()?;
	let analysis: PackageAnalysis = serde_json::from_str(&content).ok()?;

	// Check schema version — re-analyze if outdated
	if analysis.version < SCHEMA_VERSION {
		tracing::debug!(
			"cached analysis version {} < current {SCHEMA_VERSION}, needs re-analysis",
			analysis.version
		);
		return None;
	}

	Some(analysis)
}

/// Write analysis results to `.lpm-security.json` in a package directory.
pub fn write_cached_analysis(
	package_dir: &Path,
	analysis: &PackageAnalysis,
) -> Result<(), std::io::Error> {
	let path = package_dir.join(".lpm-security.json");
	let json = serde_json::to_string_pretty(analysis)
		.map_err(std::io::Error::other)?;
	std::fs::write(&path, json)
}

/// Analyze a package directory, using cache if available.
///
/// This is the primary entry point for the store integration:
/// 1. Check for `.lpm-security.json` (cache hit → return immediately)
/// 2. Run full analysis
/// 3. Write cache
/// 4. Return results
pub fn analyze_package_cached(package_dir: &Path) -> PackageAnalysis {
	// Cache hit
	if let Some(cached) = read_cached_analysis(package_dir) {
		return cached;
	}

	// Cache miss — run analysis
	let analysis = analyze_package(package_dir);

	// Write cache (best-effort, don't fail install if write fails)
	if let Err(e) = write_cached_analysis(package_dir, &analysis) {
		tracing::warn!("failed to write .lpm-security.json: {e}");
	}

	analysis
}

/// Check if ANY dangerous tags are set (Critical or High severity).
///
/// Used by post-install summary to decide whether to show the security section.
pub fn has_dangerous_tags(analysis: &PackageAnalysis) -> bool {
	// Critical
	analysis.supply_chain.obfuscated
		|| analysis.supply_chain.protestware
		|| analysis.supply_chain.high_entropy_strings
	// High
		|| analysis.source.eval
		|| analysis.source.child_process
		|| analysis.source.shell
		|| analysis.source.dynamic_require
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::fs;

	fn create_test_package(dir: &Path, files: &[(&str, &str)]) {
		for (path, content) in files {
			let file_path = dir.join(path);
			if let Some(parent) = file_path.parent() {
				fs::create_dir_all(parent).unwrap();
			}
			fs::write(&file_path, content).unwrap();
		}
	}

	// ── Package analysis ──────────────────────────────────────

	#[test]
	fn analyze_simple_package() {
		let dir = tempfile::tempdir().unwrap();
		create_test_package(
			dir.path(),
			&[
				(
					"package.json",
					r#"{"name":"test","version":"1.0.0","license":"MIT"}"#,
				),
				("index.js", r#"const fs = require("fs"); module.exports = fs.readFileSync;"#),
			],
		);

		let analysis = analyze_package(dir.path());
		assert!(analysis.source.filesystem);
		assert!(!analysis.source.network);
		assert!(!analysis.source.eval);
		assert!(!analysis.manifest.copyleft_license);
		assert!(!analysis.manifest.no_license);
		assert_eq!(analysis.meta.files_scanned, 1);
	}

	#[test]
	fn analyze_package_with_network_and_eval() {
		let dir = tempfile::tempdir().unwrap();
		create_test_package(
			dir.path(),
			&[
				("package.json", r#"{"name":"test","license":"MIT"}"#),
				("lib/http.js", "fetch('https://api.example.com')"),
				("lib/dynamic.js", "eval(code)"),
			],
		);

		let analysis = analyze_package(dir.path());
		assert!(analysis.source.network);
		assert!(analysis.source.eval);
		assert!(!analysis.source.filesystem);
		assert_eq!(analysis.meta.files_scanned, 2);
		assert!(!analysis.meta.url_domains.is_empty());
	}

	#[test]
	fn analyze_package_gpl_license() {
		let dir = tempfile::tempdir().unwrap();
		create_test_package(
			dir.path(),
			&[
				("package.json", r#"{"name":"test","license":"GPL-3.0"}"#),
				("index.js", "module.exports = 42"),
			],
		);

		let analysis = analyze_package(dir.path());
		assert!(analysis.manifest.copyleft_license);
		assert!(!analysis.manifest.no_license);
	}

	#[test]
	fn analyze_package_no_license() {
		let dir = tempfile::tempdir().unwrap();
		create_test_package(
			dir.path(),
			&[
				("package.json", r#"{"name":"test"}"#),
				("index.js", "module.exports = 42"),
			],
		);

		let analysis = analyze_package(dir.path());
		assert!(analysis.manifest.no_license);
	}

	#[test]
	fn analyze_package_git_dependencies() {
		let dir = tempfile::tempdir().unwrap();
		create_test_package(
			dir.path(),
			&[(
				"package.json",
				r#"{"name":"test","license":"MIT","dependencies":{"my-fork":"github:owner/repo"}}"#,
			)],
		);

		let analysis = analyze_package(dir.path());
		assert!(analysis.manifest.git_dependency);
	}

	#[test]
	fn skips_dts_files() {
		let dir = tempfile::tempdir().unwrap();
		create_test_package(
			dir.path(),
			&[
				("package.json", r#"{"name":"test","license":"MIT"}"#),
				("index.d.ts", "export declare function readFile(): void;"),
				("index.js", "module.exports = 42"),
			],
		);

		let analysis = analyze_package(dir.path());
		// .d.ts should be skipped — readFile in declaration shouldn't trigger filesystem
		assert!(!analysis.source.filesystem);
		assert_eq!(analysis.meta.files_scanned, 1);
	}

	#[test]
	fn skips_node_modules() {
		let dir = tempfile::tempdir().unwrap();
		create_test_package(
			dir.path(),
			&[
				("package.json", r#"{"name":"test","license":"MIT"}"#),
				("index.js", "module.exports = 42"),
				("node_modules/evil/index.js", "eval('attack')"),
			],
		);

		let analysis = analyze_package(dir.path());
		assert!(!analysis.source.eval);
		assert_eq!(analysis.meta.files_scanned, 1);
	}

	#[test]
	fn skips_non_source_files() {
		let dir = tempfile::tempdir().unwrap();
		create_test_package(
			dir.path(),
			&[
				("package.json", r#"{"name":"test","license":"MIT"}"#),
				("index.js", "module.exports = 42"),
				("styles.css", "body { color: red }"),
				("data.json", r#"{"key": "value"}"#),
				("readme.md", "# Hello"),
			],
		);

		let analysis = analyze_package(dir.path());
		assert_eq!(analysis.meta.files_scanned, 1); // only index.js
	}

	#[test]
	fn skips_minified_filenames() {
		let dir = tempfile::tempdir().unwrap();
		create_test_package(
			dir.path(),
			&[
				("package.json", r#"{"name":"test","license":"MIT"}"#),
				("dist/app.min.js", r#"eval("something")"#),
				("index.js", "module.exports = 42"),
			],
		);

		let analysis = analyze_package(dir.path());
		assert!(analysis.supply_chain.minified);
		// eval in .min.js should NOT be detected (skip source analysis on minified)
		assert!(!analysis.source.eval);
	}

	#[test]
	fn detect_trivial_package() {
		let dir = tempfile::tempdir().unwrap();
		create_test_package(
			dir.path(),
			&[
				("package.json", r#"{"name":"is-odd","license":"MIT"}"#),
				("index.js", "module.exports = n => n % 2 === 1;\n"),
			],
		);

		let analysis = analyze_package(dir.path());
		assert!(analysis.supply_chain.trivial);
	}

	#[test]
	fn not_trivial_real_package() {
		let dir = tempfile::tempdir().unwrap();
		let code = (0..50)
			.map(|i| format!("export function fn{i}() {{ return {i}; }}"))
			.collect::<Vec<_>>()
			.join("\n");
		create_test_package(
			dir.path(),
			&[
				("package.json", r#"{"name":"real-pkg","license":"MIT"}"#),
				("index.js", &code),
			],
		);

		let analysis = analyze_package(dir.path());
		assert!(!analysis.supply_chain.trivial);
	}

	// ── Cache ─────────────────────────────────────────────────

	#[test]
	fn cache_write_and_read() {
		let dir = tempfile::tempdir().unwrap();
		create_test_package(
			dir.path(),
			&[
				("package.json", r#"{"name":"test","license":"MIT"}"#),
				("index.js", "eval('code')"),
			],
		);

		let analysis = analyze_package(dir.path());
		write_cached_analysis(dir.path(), &analysis).unwrap();

		let cached = read_cached_analysis(dir.path()).unwrap();
		assert_eq!(cached.source.eval, analysis.source.eval);
		assert_eq!(cached.version, SCHEMA_VERSION);
	}

	#[test]
	fn cache_outdated_version_returns_none() {
		let dir = tempfile::tempdir().unwrap();
		let path = dir.path().join(".lpm-security.json");
		// Write a cache with old schema version
		fs::write(
			&path,
			r#"{"version":1,"analyzedAt":"2026-01-01T00:00:00Z","source":{},"supplyChain":{},"manifest":{},"meta":{}}"#,
		)
		.unwrap();

		assert!(read_cached_analysis(dir.path()).is_none());
	}

	#[test]
	fn analyze_cached_uses_cache() {
		let dir = tempfile::tempdir().unwrap();
		create_test_package(
			dir.path(),
			&[
				("package.json", r#"{"name":"test","license":"MIT"}"#),
				("index.js", "eval('code')"),
			],
		);

		// First call writes cache
		let a1 = analyze_package_cached(dir.path());
		assert!(a1.source.eval);

		// Modify the source (but cache should be used)
		fs::write(dir.path().join("index.js"), "module.exports = 42").unwrap();

		let a2 = analyze_package_cached(dir.path());
		// Should still show eval=true because cache is used
		assert!(a2.source.eval);
	}

	// ── has_dangerous_tags ────────────────────────────────────

	#[test]
	fn dangerous_tags_detected() {
		let analysis = PackageAnalysis {
			version: SCHEMA_VERSION,
			analyzed_at: String::new(),
			source: SourceTags {
				eval: true,
				..Default::default()
			},
			supply_chain: SupplyChainTags::default(),
			manifest: ManifestTags::default(),
			meta: AnalysisMeta::default(),
		};
		assert!(has_dangerous_tags(&analysis));
	}

	#[test]
	fn no_dangerous_tags() {
		let analysis = PackageAnalysis {
			version: SCHEMA_VERSION,
			analyzed_at: String::new(),
			source: SourceTags {
				filesystem: true,
				network: true,
				..Default::default()
			},
			supply_chain: SupplyChainTags::default(),
			manifest: ManifestTags::default(),
			meta: AnalysisMeta::default(),
		};
		assert!(!has_dangerous_tags(&analysis));
	}

	// ── Comment in string edge case ───────────────────────────

	#[test]
	fn eval_in_comment_not_detected() {
		let dir = tempfile::tempdir().unwrap();
		create_test_package(
			dir.path(),
			&[
				("package.json", r#"{"name":"test","license":"MIT"}"#),
				("index.js", "// eval('bad')\nmodule.exports = 42"),
			],
		);

		let analysis = analyze_package(dir.path());
		assert!(!analysis.source.eval);
	}

	#[test]
	fn eval_in_block_comment_not_detected() {
		let dir = tempfile::tempdir().unwrap();
		create_test_package(
			dir.path(),
			&[
				("package.json", r#"{"name":"test","license":"MIT"}"#),
				("index.js", "/* eval('bad') */\nmodule.exports = 42"),
			],
		);

		let analysis = analyze_package(dir.path());
		assert!(!analysis.source.eval);
	}

	#[test]
	fn url_in_string_not_stripped_as_comment() {
		let dir = tempfile::tempdir().unwrap();
		create_test_package(
			dir.path(),
			&[
				("package.json", r#"{"name":"test","license":"MIT"}"#),
				(
					"index.js",
					r#"const url = "https://api.example.com"; fetch(url)"#,
				),
			],
		);

		let analysis = analyze_package(dir.path());
		// The URL shouldn't be stripped as a comment, and fetch should be detected
		assert!(analysis.source.network);
		assert!(analysis.supply_chain.url_strings);
	}

	// ── Schema version ────────────────────────────────────────

	#[test]
	fn analysis_has_current_schema_version() {
		let dir = tempfile::tempdir().unwrap();
		create_test_package(
			dir.path(),
			&[
				("package.json", r#"{"name":"test","license":"MIT"}"#),
				("index.js", "module.exports = 42"),
			],
		);

		let analysis = analyze_package(dir.path());
		assert_eq!(analysis.version, SCHEMA_VERSION);
	}

	// ── Edge case: jQuery-style minified (NOT obfuscated) ────────

	#[test]
	fn jquery_minified_not_obfuscated() {
		let dir = tempfile::tempdir().unwrap();
		// Simulate a jQuery-style minified bundle: very long line, normal JS patterns
		let mut long_line = String::with_capacity(15_000);
		long_line.push_str("!function(e,t){\"use strict\";");
		for i in 0..500 {
			long_line.push_str(&format!(
				"var a{i}=e.createElement(\"div\");a{i}.className=\"widget\";t.appendChild(a{i});"
			));
		}
		long_line.push_str("}(document,document.body);");

		create_test_package(
			dir.path(),
			&[
				("package.json", r#"{"name":"jquery","version":"3.7.1","license":"MIT"}"#),
				("jquery.js", &long_line),
			],
		);

		let analysis = analyze_package(dir.path());
		assert!(analysis.supply_chain.minified, "should detect minified");
		assert!(
			!analysis.supply_chain.obfuscated,
			"jQuery-style minified must NOT be flagged as obfuscated"
		);
	}

	// ── Edge case: package with zero JS files ────────────────────

	#[test]
	fn json_only_package_no_source_tags() {
		let dir = tempfile::tempdir().unwrap();
		create_test_package(
			dir.path(),
			&[
				("package.json", r#"{"name":"config-data","version":"1.0.0","license":"MIT"}"#),
				("data.json", r#"{"key":"value"}"#),
				("README.md", "# Config Data"),
			],
		);

		let analysis = analyze_package(dir.path());
		// All source + supply chain tags should be false (no .js files to scan)
		assert!(!analysis.source.eval);
		assert!(!analysis.source.network);
		assert!(!analysis.source.filesystem);
		assert!(!analysis.supply_chain.obfuscated);
		assert!(!analysis.supply_chain.protestware);
		// Manifest tags still checked
		assert!(!analysis.manifest.copyleft_license); // MIT is not copyleft
	}

	// ── Edge case: native .node binary alongside JS ──────────────

	#[test]
	fn native_node_file_detected() {
		let dir = tempfile::tempdir().unwrap();
		create_test_package(
			dir.path(),
			&[
				("package.json", r#"{"name":"native-pkg","version":"1.0.0","license":"MIT"}"#),
				("index.js", "const binding = require('./build/Release/addon.node')"),
			],
		);

		let analysis = analyze_package(dir.path());
		assert!(analysis.source.native_bindings);
	}

	// ── Edge case: process.env.NODE_ENV (React pattern) ──────────

	#[test]
	fn process_env_node_env_detected() {
		let dir = tempfile::tempdir().unwrap();
		create_test_package(
			dir.path(),
			&[
				("package.json", r#"{"name":"react-thing","version":"1.0.0","license":"MIT"}"#),
				(
					"index.js",
					"if (process.env.NODE_ENV !== 'production') { console.warn('dev mode') }",
				),
			],
		);

		let analysis = analyze_package(dir.path());
		assert!(
			analysis.source.environment_vars,
			"process.env.NODE_ENV IS reading env — should be detected"
		);
	}

	// ── Edge case: GPL-2.0-or-later SPDX expression ──────────────

	#[test]
	fn gpl_2_or_later_spdx() {
		let dir = tempfile::tempdir().unwrap();
		create_test_package(
			dir.path(),
			&[
				("package.json", r#"{"name":"gpl-pkg","version":"1.0.0","license":"GPL-2.0-or-later"}"#),
				("index.js", "module.exports = 42"),
			],
		);

		let analysis = analyze_package(dir.path());
		assert!(analysis.manifest.copyleft_license);
	}

	// ── Edge case: MIT OR Apache-2.0 (not copyleft) ──────────────

	#[test]
	fn mit_or_apache_not_copyleft() {
		let dir = tempfile::tempdir().unwrap();
		create_test_package(
			dir.path(),
			&[
				("package.json", r#"{"name":"dual-license","version":"1.0.0","license":"MIT OR Apache-2.0"}"#),
				("index.js", "module.exports = 42"),
			],
		);

		let analysis = analyze_package(dir.path());
		assert!(
			!analysis.manifest.copyleft_license,
			"MIT OR Apache-2.0 should NOT be copyleft"
		);
	}

	// ── Edge case: mixed project, partial cache ──────────────────

	#[test]
	fn partial_cache_missing_analysis() {
		let dir = tempfile::tempdir().unwrap();
		create_test_package(
			dir.path(),
			&[
				("package.json", r#"{"name":"test","version":"1.0.0","license":"MIT"}"#),
				("index.js", "const x = 1"),
			],
		);

		// First call — no cache, full analysis
		let a1 = analyze_package_cached(dir.path());
		assert_eq!(a1.version, SCHEMA_VERSION);

		// Cache should exist now
		assert!(dir.path().join(".lpm-security.json").exists());

		// Second call — should use cache (fast path)
		let a2 = analyze_package_cached(dir.path());
		assert_eq!(a2.source, a1.source);
		assert_eq!(a2.supply_chain, a1.supply_chain);
		assert_eq!(a2.manifest, a1.manifest);
	}

	// ── Edge case: corrupted cache file (graceful degradation) ───

	#[test]
	fn corrupted_cache_triggers_reanalysis() {
		let dir = tempfile::tempdir().unwrap();
		create_test_package(
			dir.path(),
			&[
				("package.json", r#"{"name":"test","version":"1.0.0","license":"MIT"}"#),
				("index.js", "const x = 1"),
			],
		);

		// Write corrupted cache
		std::fs::write(dir.path().join(".lpm-security.json"), "not json").unwrap();

		// read_cached_analysis should return None for corrupted cache
		assert!(read_cached_analysis(dir.path()).is_none());

		// analyze_package_cached should re-analyze and return valid result
		let analysis = analyze_package_cached(dir.path());
		assert_eq!(analysis.version, SCHEMA_VERSION);
	}
}
