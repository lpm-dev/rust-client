//! Native `.env` file parser.
//!
//! Parses `.env` files into key-value pairs. Supports:
//! - `KEY=VALUE` basic assignment
//! - `KEY="value with spaces"` double-quoted values (strips quotes)
//! - `KEY='literal value'` single-quoted values (strips quotes)
//! - `KEY="multiline\nvalue"` double-quoted values spanning multiple lines
//! - `# comments` and empty lines (ignored)
//! - `export KEY=VALUE` (strips `export` prefix)
//!
//! Does NOT expand `$VAR` references — values are taken literally.

use std::collections::HashMap;
use std::path::Path;

/// Parse a `.env` file into a key-value map.
///
/// Returns an empty map if the file doesn't exist (not an error).
pub fn parse_env_file(path: &Path) -> HashMap<String, String> {
	let content = match std::fs::read_to_string(path) {
		Ok(c) => c,
		Err(_) => return HashMap::new(),
	};
	parse_env_str(&content)
}

/// Parse `.env` content string into a key-value map.
///
/// Supports multiline values enclosed in double quotes:
/// ```text
/// MY_CERT="-----BEGIN CERTIFICATE-----
/// MIIBkTCB...
/// -----END CERTIFICATE-----"
/// ```
pub fn parse_env_str(content: &str) -> HashMap<String, String> {
	let mut vars = HashMap::new();
	let lines: Vec<&str> = content.lines().collect();
	let mut i = 0;

	while i < lines.len() {
		let trimmed = lines[i].trim();

		// Skip empty lines and comments
		if trimmed.is_empty() || trimmed.starts_with('#') {
			i += 1;
			continue;
		}

		// Strip optional `export ` prefix
		let trimmed = trimmed.strip_prefix("export ").unwrap_or(trimmed);

		// Find the first `=` separator
		let eq_pos = match trimmed.find('=') {
			Some(pos) => pos,
			None => {
				i += 1;
				continue;
			}
		};

		let key = trimmed[..eq_pos].trim().to_string();
		if key.is_empty() {
			i += 1;
			continue;
		}

		let raw_value = trimmed[eq_pos + 1..].trim();

		// Check for multiline double-quoted value: starts with `"` but doesn't end with `"`
		if raw_value.starts_with('"') && !(raw_value.len() >= 2 && raw_value.ends_with('"')) {
			// Multiline: collect lines until we find a closing `"`
			let mut parts = vec![&raw_value[1..]]; // Strip leading quote
			i += 1;
			while i < lines.len() {
				let line = lines[i];
				if line.ends_with('"') {
					parts.push(&line[..line.len() - 1]); // Strip trailing quote
					i += 1;
					break;
				}
				parts.push(line);
				i += 1;
			}
			// If we hit EOF without closing quote, join everything we have
			vars.insert(key, parts.join("\n"));
		} else {
			let value = unquote(raw_value);
			vars.insert(key, value);
			i += 1;
		}
	}

	vars
}

/// Remove surrounding quotes from a value.
///
/// - `"hello world"` → `hello world`
/// - `'hello world'` → `hello world`
/// - `hello world` → `hello world` (no change)
fn unquote(s: &str) -> String {
	if s.len() >= 2 {
		if (s.starts_with('"') && s.ends_with('"'))
			|| (s.starts_with('\'') && s.ends_with('\''))
		{
			return s[1..s.len() - 1].to_string();
		}
	}
	s.to_string()
}

/// Load environment variables from a sequence of `.env` files.
///
/// Files are loaded in order — later files override earlier ones.
/// Only sets variables that are NOT already present in the process environment
/// (process env takes precedence over `.env` files).
///
/// Standard loading order:
/// 1. `.env` — default values (checked into git)
/// 2. `.env.local` — local overrides (gitignored)
/// 3. `.env.{mode}` — mode-specific (e.g., `.env.staging`)
/// 4. `.env.{mode}.local` — mode-specific local overrides
pub fn load_env_files(
	project_dir: &Path,
	mode: Option<&str>,
) -> HashMap<String, String> {
	let mut merged = HashMap::new();

	// 1. .env
	merge_env_file(&mut merged, &project_dir.join(".env"));

	// 2. .env.local
	merge_env_file(&mut merged, &project_dir.join(".env.local"));

	// 3 & 4. Mode-specific files
	if let Some(mode) = mode {
		merge_env_file(&mut merged, &project_dir.join(format!(".env.{mode}")));
		merge_env_file(
			&mut merged,
			&project_dir.join(format!(".env.{mode}.local")),
		);
	}

	// Filter out vars that already exist in process environment
	// (process env takes precedence)
	merged.retain(|key, _| std::env::var(key).is_err());

	merged
}

/// Merge a single `.env` file into an existing map (overwriting existing keys).
fn merge_env_file(target: &mut HashMap<String, String>, path: &Path) {
	let vars = parse_env_file(path);
	for (k, v) in vars {
		target.insert(k, v);
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::fs;

	#[test]
	fn parse_basic_env() {
		let vars = parse_env_str("KEY=value\nOTHER=123");
		assert_eq!(vars.get("KEY").unwrap(), "value");
		assert_eq!(vars.get("OTHER").unwrap(), "123");
	}

	#[test]
	fn parse_double_quoted() {
		let vars = parse_env_str(r#"KEY="hello world""#);
		assert_eq!(vars.get("KEY").unwrap(), "hello world");
	}

	#[test]
	fn parse_single_quoted() {
		let vars = parse_env_str("KEY='hello world'");
		assert_eq!(vars.get("KEY").unwrap(), "hello world");
	}

	#[test]
	fn parse_export_prefix() {
		let vars = parse_env_str("export API_KEY=abc123");
		assert_eq!(vars.get("API_KEY").unwrap(), "abc123");
	}

	#[test]
	fn parse_comments_and_blanks() {
		let vars = parse_env_str(
			"# This is a comment\n\nKEY=value\n  # Another comment\n\nOTHER=123",
		);
		assert_eq!(vars.len(), 2);
		assert_eq!(vars.get("KEY").unwrap(), "value");
	}

	#[test]
	fn parse_value_with_equals() {
		let vars = parse_env_str("URL=https://example.com?a=1&b=2");
		assert_eq!(vars.get("URL").unwrap(), "https://example.com?a=1&b=2");
	}

	#[test]
	fn parse_empty_value() {
		let vars = parse_env_str("EMPTY=\nBLANK=''");
		assert_eq!(vars.get("EMPTY").unwrap(), "");
		assert_eq!(vars.get("BLANK").unwrap(), "");
	}

	#[test]
	fn parse_whitespace_around_equals() {
		let vars = parse_env_str("KEY = value");
		assert_eq!(vars.get("KEY").unwrap(), "value");
	}

	#[test]
	fn parse_no_equals_line_skipped() {
		let vars = parse_env_str("NOEQUALS\nKEY=value");
		assert_eq!(vars.len(), 1);
		assert_eq!(vars.get("KEY").unwrap(), "value");
	}

	#[test]
	fn load_env_file_missing_ok() {
		let vars = parse_env_file(Path::new("/nonexistent/.env"));
		assert!(vars.is_empty());
	}

	#[test]
	fn load_env_files_merge_order() {
		let dir = tempfile::tempdir().unwrap();

		fs::write(dir.path().join(".env"), "A=from-env\nB=from-env").unwrap();
		fs::write(dir.path().join(".env.local"), "B=from-local").unwrap();

		let vars = load_env_files(dir.path(), None);
		assert_eq!(vars.get("A").unwrap(), "from-env");
		assert_eq!(vars.get("B").unwrap(), "from-local");
	}

	#[test]
	fn load_env_files_with_mode() {
		let dir = tempfile::tempdir().unwrap();

		fs::write(dir.path().join(".env"), "A=default\nB=default").unwrap();
		fs::write(dir.path().join(".env.staging"), "B=staging").unwrap();

		let vars = load_env_files(dir.path(), Some("staging"));
		assert_eq!(vars.get("A").unwrap(), "default");
		assert_eq!(vars.get("B").unwrap(), "staging");
	}

	#[test]
	fn process_env_takes_precedence() {
		let dir = tempfile::tempdir().unwrap();

		// HOME is always set in the process env
		fs::write(dir.path().join(".env"), "HOME=/fake/path\nLPM_TEST_UNIQUE_12345=from-dotenv").unwrap();

		let vars = load_env_files(dir.path(), None);
		// HOME should be filtered out (process env wins)
		assert!(!vars.contains_key("HOME"));
		// Our unique key should be present (not in process env)
		assert_eq!(vars.get("LPM_TEST_UNIQUE_12345").unwrap(), "from-dotenv");
	}

	#[test]
	fn parse_multiline_double_quoted_value() {
		let input = "MY_CERT=\"-----BEGIN CERTIFICATE-----\nMIIBkTCB...\n-----END CERTIFICATE-----\"";
		let vars = parse_env_str(input);
		assert_eq!(
			vars.get("MY_CERT").unwrap(),
			"-----BEGIN CERTIFICATE-----\nMIIBkTCB...\n-----END CERTIFICATE-----"
		);
	}

	#[test]
	fn parse_multiline_mixed_with_single_line() {
		let input = "SIMPLE=hello\nMULTI=\"line1\nline2\nline3\"\nAFTER=world";
		let vars = parse_env_str(input);
		assert_eq!(vars.get("SIMPLE").unwrap(), "hello");
		assert_eq!(vars.get("MULTI").unwrap(), "line1\nline2\nline3");
		assert_eq!(vars.get("AFTER").unwrap(), "world");
	}

	#[test]
	fn parse_multiline_single_quoted_not_supported() {
		// Single-quoted multiline is intentionally not supported (matches docker/dotenv behavior)
		// Each line is treated independently
		let input = "KEY='line1\nline2'";
		let vars = parse_env_str(input);
		// Should parse as two separate lines: KEY='line1 and line2' (broken)
		// This is acceptable — multiline is only supported with double quotes
		assert!(vars.contains_key("KEY"));
	}

	#[test]
	fn parse_multiline_unterminated_quote_takes_rest() {
		// Unterminated double-quote consumes everything until EOF
		let input = "KEY=\"unterminated\nrest of file";
		let vars = parse_env_str(input);
		assert_eq!(vars.get("KEY").unwrap(), "unterminated\nrest of file");
	}
}
