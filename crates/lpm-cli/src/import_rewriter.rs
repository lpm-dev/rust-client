//! Smart import path rewriting for source-delivered packages.
//!
//! When `lpm add` copies source files into a project, internal imports need
//! to be rewritten from the author's alias to the buyer's alias.
//!
//! Example: author uses `@/lib/utils`, buyer's tsconfig maps `@/` to `./src/`.
//! Files installed to `src/components/dialog/`, so:
//!   `import { cn } from "@/lib/utils"` → stays as `@/lib/utils` (external to component)
//!   `import { DialogBase } from "./DialogBase"` → `./DialogBase` (relative, preserved)

use std::collections::{HashMap, HashSet};

/// Rewrite imports in a source file.
///
/// # Arguments
/// * `content` - The file content
/// * `author_alias` - The alias used by the author (e.g., `@/`)
/// * `buyer_alias` - The alias configured in the buyer's project (e.g., `@/`)
/// * `src_to_dest` - Map from source paths to destination paths
/// * `dest_files` - Set of all destination file paths
///
/// Returns the rewritten content, or None if no changes were made.
pub fn rewrite_imports(
	content: &str,
	author_alias: Option<&str>,
	buyer_alias: Option<&str>,
	src_to_dest: &HashMap<String, String>,
	dest_files: &HashSet<String>,
) -> Option<String> {
	// Only rewrite if we have aliases to work with
	if author_alias.is_none() && buyer_alias.is_none() {
		return None;
	}

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
			author_alias,
			buyer_alias,
			src_to_dest,
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
	author_alias: Option<&str>,
	buyer_alias: Option<&str>,
	src_to_dest: &HashMap<String, String>,
	dest_files: &HashSet<String>,
) -> Option<String> {
	// Match patterns: from "specifier", from 'specifier', import("specifier"), require("specifier")
	// Regex-free approach: find quote-delimited specifiers after import/from/require keywords

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

						if let Some(new_specifier) = resolve_specifier(
							specifier,
							author_alias,
							buyer_alias,
							src_to_dest,
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

/// Resolve a specifier to a new path based on alias mapping.
fn resolve_specifier(
	specifier: &str,
	author_alias: Option<&str>,
	buyer_alias: Option<&str>,
	src_to_dest: &HashMap<String, String>,
	dest_files: &HashSet<String>,
) -> Option<String> {
	// Skip external packages (bare specifiers)
	if !specifier.starts_with('.') && !specifier.starts_with('@') && !specifier.starts_with('~') {
		return None;
	}

	// Skip if it starts with a scope (@scope/pkg) — external package
	if specifier.starts_with('@') && specifier.contains('/') {
		let after_scope = specifier.split('/').nth(1)?;
		// If the part after scope doesn't look like a path, it's an external package
		if !after_scope.contains('/') && !after_scope.starts_with('.') {
			// Check if this matches the author alias
			if let Some(alias) = author_alias {
				if specifier.starts_with(alias) {
					// This is an author alias import — rewrite
					let path = &specifier[alias.len()..];

					// Try to find in dest files
					if let Some(dest) = find_in_file_set(path, dest_files) {
						let new_path = strip_extension(&dest);
						if let Some(b_alias) = buyer_alias {
							return Some(format!("{b_alias}{new_path}"));
						}
					}

					// If buyer has same alias, keep as-is
					if buyer_alias == author_alias {
						return None;
					}

					// Rewrite alias
					if let Some(b_alias) = buyer_alias {
						return Some(format!("{b_alias}{path}"));
					}
				}
			}
			return None;
		}
	}

	// Handle author alias imports (e.g., @/lib/utils → @/components/dialog/lib/utils)
	if let Some(alias) = author_alias {
		if specifier.starts_with(alias) {
			let path = &specifier[alias.len()..];

			// Try to find in src_to_dest map
			if let Some(dest) = find_in_map(path, src_to_dest) {
				let new_path = strip_extension(&dest);
				if let Some(b_alias) = buyer_alias {
					return Some(format!("{b_alias}{new_path}"));
				}
			}

			// If buyer has same alias, no change needed
			if buyer_alias == author_alias {
				return None;
			}

			// Simple alias swap
			if let Some(b_alias) = buyer_alias {
				return Some(format!("{b_alias}{path}"));
			}
		}
	}

	// Relative imports — resolve against src_to_dest
	if specifier.starts_with('.') {
		// Relative imports typically don't need rewriting since the relative
		// relationship is preserved during copy. Only rewrite if the file
		// structure changed between src and dest.
		return None;
	}

	None
}

/// Find a path in a file set, trying various extensions.
fn find_in_file_set(path: &str, files: &HashSet<String>) -> Option<String> {
	let extensions = [".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"];

	// Try exact
	if files.contains(path) {
		return Some(path.to_string());
	}

	// Try with extensions
	for ext in &extensions {
		let with_ext = format!("{path}{ext}");
		if files.contains(&with_ext) {
			return Some(with_ext);
		}
	}

	// Try index files
	for ext in &extensions {
		let index = format!("{path}/index{ext}");
		if files.contains(&index) {
			return Some(index);
		}
	}

	None
}

/// Find a path in a src→dest map, trying various extensions.
fn find_in_map(path: &str, map: &HashMap<String, String>) -> Option<String> {
	let extensions = [".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"];

	// Try exact
	if let Some(dest) = map.get(path) {
		return Some(dest.clone());
	}

	// Try with extensions
	for ext in &extensions {
		let with_ext = format!("{path}{ext}");
		if let Some(dest) = map.get(&with_ext) {
			return Some(dest.clone());
		}
	}

	// Try index
	for ext in &extensions {
		let index = format!("{path}/index{ext}");
		if let Some(dest) = map.get(&index) {
			return Some(dest.clone());
		}
	}

	None
}

/// Strip file extension for import paths.
fn strip_extension(path: &str) -> String {
	let extensions = [".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"];
	for ext in &extensions {
		if path.ends_with(ext) {
			return path[..path.len() - ext.len()].to_string();
		}
	}

	// Strip /index.ext
	for ext in &extensions {
		let suffix = format!("/index{ext}");
		if path.ends_with(&suffix) {
			return path[..path.len() - suffix.len()].to_string();
		}
	}

	path.to_string()
}
