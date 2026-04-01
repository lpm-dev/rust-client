//! Smart import path rewriting for source-delivered packages.
//!
//! When `lpm add` copies source files into a project, internal imports need
//! to be rewritten from the author's alias to the buyer's alias. Relative
//! imports between installed files are also resolved through the src→dest
//! mapping to keep internal references correct.
//!
//! Mirrors the JS CLI's `import-rewriter.js` logic:
//!   - Per-file context (fileSrcPath, fileDestPath) for relative resolution
//!   - Relative imports resolved via src dir + srcToDestMap
//!   - Author alias imports resolved via src file set + srcToDestMap
//!   - Buyer alias applied to rewritten specifiers
//!   - External/bare specifiers left unchanged

use std::collections::{HashMap, HashSet};

/// File extensions to try when resolving import paths.
const EXTENSIONS: &[&str] = &[".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"];

/// Rewrite imports in a source file using per-file context.
///
/// # Arguments
/// * `content` - The file content
/// * `file_src_path` - The file's path relative to the extraction root (e.g., `"atoms/Icon/Icon.jsx"`)
/// * `file_dest_path` - The file's destination path relative to target dir (e.g., `"atoms/Icon/Icon.jsx"`)
/// * `author_alias` - The alias used by the author (e.g., `"@/"`)
/// * `buyer_alias` - The alias configured in the buyer's project (e.g., `"@/components/"`)
/// * `src_to_dest` - Map from source paths to destination paths
/// * `src_files` - Set of all source file paths
/// * `dest_files` - Set of all destination file paths
///
/// Returns the rewritten content, or None if no changes were made.
pub fn rewrite_imports(
	content: &str,
	file_src_path: &str,
	file_dest_path: &str,
	author_alias: Option<&str>,
	buyer_alias: Option<&str>,
	src_to_dest: &HashMap<String, String>,
	src_files: &HashSet<String>,
	dest_files: &HashSet<String>,
) -> Option<String> {
	// Only rewrite if we have aliases to work with
	if author_alias.is_none() && buyer_alias.is_none() {
		return None;
	}

	let file_src_dir = dirname(file_src_path);
	let file_dest_dir = dirname(file_dest_path);

	let mut result = String::with_capacity(content.len());
	let mut changed = false;
	let mut in_block_comment = false;

	for line in content.lines() {
		// Track block comments
		if in_block_comment {
			if line.contains("*/") {
				in_block_comment = false;
			}
			result.push_str(line);
			result.push('\n');
			continue;
		}
		if line.contains("/*") && !line.contains("*/") {
			in_block_comment = true;
			result.push_str(line);
			result.push('\n');
			continue;
		}

		// Skip single-line comments
		let trimmed = line.trim();
		if trimmed.starts_with("//") {
			result.push_str(line);
			result.push('\n');
			continue;
		}

		// Check for import/require patterns
		if let Some(rewritten) = try_rewrite_line(
			line,
			&file_src_dir,
			&file_dest_dir,
			author_alias,
			buyer_alias,
			src_to_dest,
			src_files,
			dest_files,
		) {
			result.push_str(&rewritten);
			result.push('\n');
			changed = true;
		} else {
			result.push_str(line);
			result.push('\n');
		}
	}

	if changed { Some(result) } else { None }
}

/// Try to rewrite import specifiers in a single line.
fn try_rewrite_line(
	line: &str,
	file_src_dir: &str,
	file_dest_dir: &str,
	author_alias: Option<&str>,
	buyer_alias: Option<&str>,
	src_to_dest: &HashMap<String, String>,
	src_files: &HashSet<String>,
	dest_files: &HashSet<String>,
) -> Option<String> {
	let import_keywords = ["from ", "import(", "require("];
	let mut result = line.to_string();
	let mut any_change = false;

	for keyword in &import_keywords {
		if !line.contains(keyword) {
			continue;
		}

		// Find the specifier between quotes
		for quote in ['"', '\''] {
			if let Some(start) = line.find(keyword) {
				let after_keyword = &line[start + keyword.len()..];
				if let Some(q1) = after_keyword.find(quote) {
					let after_q1 = &after_keyword[q1 + 1..];
					if let Some(q2) = after_q1.find(quote) {
						let specifier = &after_q1[..q2];

						if let Some(new_specifier) = resolve_and_rewrite(
							specifier,
							file_src_dir,
							file_dest_dir,
							author_alias,
							buyer_alias,
							src_to_dest,
							src_files,
							dest_files,
						) {
							result = result.replacen(specifier, &new_specifier, 1);
							any_change = true;
						}
					}
				}
			}
		}
	}

	if any_change { Some(result) } else { None }
}

/// Resolve a specifier and compute its rewritten form.
///
/// Steps:
/// 1. Identify specifier type (relative, author alias, or bare/external)
/// 2. Resolve to a destination file path
/// 3. Compute new specifier using buyer alias
fn resolve_and_rewrite(
	specifier: &str,
	file_src_dir: &str,
	file_dest_dir: &str,
	author_alias: Option<&str>,
	buyer_alias: Option<&str>,
	src_to_dest: &HashMap<String, String>,
	src_files: &HashSet<String>,
	dest_files: &HashSet<String>,
) -> Option<String> {
	// 1. Relative import: ./foo or ../bar
	if specifier.starts_with("./") || specifier.starts_with("../") {
		// Resolve against src directory, then map to dest
		let resolved_src = normalize_path(&join_path(file_src_dir, specifier));
		if let Some(src_match) = try_resolve_file(&resolved_src, src_files) {
			if let Some(dest_path) = src_to_dest.get(&src_match) {
				return compute_new_specifier(dest_path, file_dest_dir, buyer_alias);
			}
		}

		// Fallback: resolve against dest directory directly
		let resolved_dest = normalize_path(&join_path(file_dest_dir, specifier));
		if let Some(dest_match) = try_resolve_file(&resolved_dest, dest_files) {
			return compute_new_specifier(&dest_match, file_dest_dir, buyer_alias);
		}

		return None;
	}

	// 2. Author alias import: e.g., @/lib/utils
	if let Some(alias) = author_alias {
		if specifier.starts_with(alias) {
			let path = &specifier[alias.len()..];

			// Look up in src file set, then map to dest
			if let Some(src_match) = try_resolve_file(path, src_files) {
				if let Some(dest_path) = src_to_dest.get(&src_match) {
					return compute_new_specifier(dest_path, file_dest_dir, buyer_alias);
				}
			}

			// Fallback: try in dest file set directly
			if let Some(_dest_match) = try_resolve_file(path, dest_files) {
				// If buyer has same alias, no change needed
				if buyer_alias == author_alias {
					return None;
				}
				// Simple alias swap
				if let Some(b_alias) = buyer_alias {
					return Some(format!("{b_alias}{path}"));
				}
			}

			// If buyer has a different alias, swap even without file resolution
			if buyer_alias != author_alias {
				if let Some(b_alias) = buyer_alias {
					return Some(format!("{b_alias}{path}"));
				}
			}

			return None;
		}
	}

	// 3. Bare specifier (react, next/link, @scope/pkg) — external, leave unchanged
	None
}

/// Compute the new import specifier for a resolved internal file.
///
/// If a buyer alias is set, uses alias-based path. Otherwise returns None
/// (relative imports already work when file structure is preserved).
fn compute_new_specifier(
	resolved_dest_path: &str,
	_file_dest_dir: &str,
	buyer_alias: Option<&str>,
) -> Option<String> {
	let clean_path = strip_import_extension(resolved_dest_path);

	if let Some(alias) = buyer_alias {
		let a = if alias.ends_with('/') {
			alias.to_string()
		} else {
			format!("{alias}/")
		};
		return Some(format!("{a}{clean_path}"));
	}

	// No buyer alias — no rewrite needed
	None
}

/// Find a path in a file set, trying various extensions.
fn try_resolve_file(candidate: &str, files: &HashSet<String>) -> Option<String> {
	// Normalize: remove leading ./
	let candidate = candidate.strip_prefix("./").unwrap_or(candidate);

	// Exact match
	if files.contains(candidate) {
		return Some(candidate.to_string());
	}

	// Try with extensions
	for ext in EXTENSIONS {
		let with_ext = format!("{candidate}{ext}");
		if files.contains(&with_ext) {
			return Some(with_ext);
		}
	}

	// Try index files
	for ext in EXTENSIONS {
		let index = format!("{candidate}/index{ext}");
		if files.contains(&index) {
			return Some(index);
		}
	}

	None
}

/// Strip file extension for import paths. Also strips /index suffixes.
fn strip_import_extension(path: &str) -> String {
	// Strip /index.ext first
	for ext in EXTENSIONS {
		let suffix = format!("/index{ext}");
		if path.ends_with(&suffix) {
			return path[..path.len() - suffix.len()].to_string();
		}
	}

	// Strip plain extension
	for ext in EXTENSIONS {
		if path.ends_with(ext) {
			return path[..path.len() - ext.len()].to_string();
		}
	}

	path.to_string()
}

/// Get the directory portion of a path. `"a/b/c.js"` → `"a/b"`, `"c.js"` → `""`.
fn dirname(path: &str) -> String {
	match path.rfind('/') {
		Some(pos) => path[..pos].to_string(),
		None => String::new(),
	}
}

/// Join a base directory and a relative path. Handles `..` and `.` segments.
fn join_path(base: &str, relative: &str) -> String {
	if base.is_empty() {
		return relative.to_string();
	}
	format!("{base}/{relative}")
}

/// Normalize a path by resolving `.` and `..` segments.
fn normalize_path(path: &str) -> String {
	let mut parts: Vec<&str> = Vec::new();

	for segment in path.split('/') {
		match segment {
			"" | "." => {}
			".." => {
				parts.pop();
			}
			s => parts.push(s),
		}
	}

	parts.join("/")
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_dirname() {
		assert_eq!(dirname("a/b/c.js"), "a/b");
		assert_eq!(dirname("c.js"), "");
		assert_eq!(dirname("a/b"), "a");
	}

	#[test]
	fn test_normalize_path() {
		assert_eq!(normalize_path("a/b/../c"), "a/c");
		assert_eq!(normalize_path("a/./b/c"), "a/b/c");
		assert_eq!(normalize_path("./a/b"), "a/b");
		assert_eq!(normalize_path("a/b/c/../../d"), "a/d");
	}

	#[test]
	fn test_strip_import_extension() {
		assert_eq!(strip_import_extension("foo/bar.js"), "foo/bar");
		assert_eq!(strip_import_extension("foo/bar.tsx"), "foo/bar");
		assert_eq!(strip_import_extension("foo/bar/index.js"), "foo/bar");
		assert_eq!(strip_import_extension("foo/bar"), "foo/bar");
	}

	#[test]
	fn test_try_resolve_file() {
		let mut files = HashSet::new();
		files.insert("lib/utils.js".to_string());
		files.insert("components/Button/index.tsx".to_string());

		assert_eq!(
			try_resolve_file("lib/utils", &files),
			Some("lib/utils.js".to_string())
		);
		assert_eq!(
			try_resolve_file("lib/utils.js", &files),
			Some("lib/utils.js".to_string())
		);
		assert_eq!(
			try_resolve_file("components/Button", &files),
			Some("components/Button/index.tsx".to_string())
		);
		assert_eq!(try_resolve_file("missing", &files), None);
	}

	#[test]
	fn test_relative_import_rewriting() {
		let mut src_to_dest: HashMap<String, String> = HashMap::new();
		src_to_dest.insert("lib/cn.js".to_string(), "lib/cn.js".to_string());
		src_to_dest.insert(
			"atoms/Icon/Icon.jsx".to_string(),
			"atoms/Icon/Icon.jsx".to_string(),
		);

		let src_files: HashSet<String> = src_to_dest.keys().cloned().collect();
		let dest_files: HashSet<String> = src_to_dest.values().cloned().collect();

		let content = r#"import { cn } from "../../lib/cn"
import Icon from "../Icon/Icon"
import React from "react"
"#;

		let result = rewrite_imports(
			content,
			"atoms/Button/Button.jsx",
			"atoms/Button/Button.jsx",
			Some("@/"),
			Some("@/components/"),
			&src_to_dest,
			&src_files,
			&dest_files,
		);

		let rewritten = result.unwrap();
		assert!(rewritten.contains("@/components/lib/cn"));
		assert!(rewritten.contains("@/components/atoms/Icon/Icon"));
		assert!(rewritten.contains("from \"react\""));
	}

	#[test]
	fn test_author_alias_rewriting() {
		let mut src_to_dest: HashMap<String, String> = HashMap::new();
		src_to_dest.insert("lib/utils.js".to_string(), "lib/utils.js".to_string());

		let src_files: HashSet<String> = src_to_dest.keys().cloned().collect();
		let dest_files: HashSet<String> = src_to_dest.values().cloned().collect();

		let content = r#"import { cn } from "@/lib/utils"
"#;

		let result = rewrite_imports(
			content,
			"atoms/Icon/Icon.jsx",
			"atoms/Icon/Icon.jsx",
			Some("@/"),
			Some("@/design-system/"),
			&src_to_dest,
			&src_files,
			&dest_files,
		);

		let rewritten = result.unwrap();
		assert!(rewritten.contains("@/design-system/lib/utils"));
	}

	#[test]
	fn test_no_rewrite_when_no_alias() {
		let src_to_dest: HashMap<String, String> = HashMap::new();
		let src_files: HashSet<String> = HashSet::new();
		let dest_files: HashSet<String> = HashSet::new();

		let content = r#"import React from "react"
"#;

		let result = rewrite_imports(
			content,
			"index.js",
			"index.js",
			None,
			None,
			&src_to_dest,
			&src_files,
			&dest_files,
		);

		assert!(result.is_none());
	}

	#[test]
	fn test_external_imports_unchanged() {
		let mut src_to_dest: HashMap<String, String> = HashMap::new();
		src_to_dest.insert("lib/cn.js".to_string(), "lib/cn.js".to_string());

		let src_files: HashSet<String> = src_to_dest.keys().cloned().collect();
		let dest_files: HashSet<String> = src_to_dest.values().cloned().collect();

		let content = r#"import React from "react"
import { useState } from "react"
import Link from "next/link"
"#;

		let result = rewrite_imports(
			content,
			"atoms/Button.jsx",
			"atoms/Button.jsx",
			Some("@/"),
			Some("@/components/"),
			&src_to_dest,
			&src_files,
			&dest_files,
		);

		assert!(result.is_none());
	}
}
