//! Yarn v1 lockfile parser.
//!
//! yarn.lock v1 uses a custom format (not YAML, not JSON).
//! This parser uses a two-pass approach:
//! 1. Parse all entries with their specifiers, version, resolved URL, integrity, and dependency ranges.
//! 2. Build a specifier→version map, then resolve each dependency range to an exact version.

use crate::MigratedPackage;
use lpm_common::LpmError;
use std::collections::HashMap;
use std::path::Path;

pub fn parse(path: &Path) -> Result<Vec<MigratedPackage>, LpmError> {
	let content = std::fs::read_to_string(path)?;
	parse_str(&content)
}

pub fn parse_str(content: &str) -> Result<Vec<MigratedPackage>, LpmError> {
	let entries = parse_entries(content)?;

	// Build specifier → version map for dependency resolution.
	// Uses owned Strings so the map doesn't borrow `entries`, allowing consumption below.
	let mut spec_map: HashMap<String, String> = HashMap::with_capacity(entries.len() * 2);
	for entry in &entries {
		for spec in &entry.specifiers {
			spec_map.insert(spec.clone(), entry.version.clone());
		}
	}

	// Second pass: resolve dependency ranges to exact versions.
	let mut buf = String::new();
	let packages: Vec<MigratedPackage> = entries
		.into_iter()
		.map(|entry| {
			let dependencies: Vec<(String, String)> = entry
				.deps_with_ranges
				.iter()
				.filter_map(|(name, range)| {
					buf.clear();
					buf.push_str(name);
					buf.push('@');
					buf.push_str(range);
					spec_map.get(buf.as_str()).map(|v| (name.clone(), v.clone()))
				})
				.collect();

			MigratedPackage {
				name: entry.name,
				version: entry.version,
				resolved: entry.resolved,
				integrity: entry.integrity,
				dependencies,
				is_optional: false,
				is_dev: false,
			}
		})
		.collect();

	Ok(packages)
}

struct YarnEntry {
	/// Raw specifiers like "accepts@~1.3.8", "@scope/pkg@^1.0.0".
	specifiers: Vec<String>,
	/// Package name extracted from the first specifier.
	name: String,
	/// Resolved exact version.
	version: String,
	/// Tarball download URL.
	resolved: Option<String>,
	/// SRI integrity hash.
	integrity: Option<String>,
	/// Dependencies as (name, range) — ranges not yet resolved.
	deps_with_ranges: Vec<(String, String)>,
}

/// Parser states for the line-by-line state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
	/// Expecting a package specifier line or blank/comment.
	TopLevel,
	/// Inside a package entry, reading 2-space-indented properties.
	InEntry,
	/// Inside a `dependencies:` or `optionalDependencies:` block, reading 4-space-indented lines.
	InDeps,
}

/// Split a specifier like `"accepts@~1.3.8"` or `"@scope/pkg@^1.0.0"` into (name, range).
/// The trick: find the LAST `@` that is NOT at position 0.
fn split_specifier(spec: &str) -> Option<(&str, &str)> {
	// Strip surrounding quotes if present.
	let s = spec.trim_matches('"');
	// Find last '@' that is not at index 0.
	let at_pos = s
		.char_indices()
		.rev()
		.find(|&(i, c)| c == '@' && i > 0)
		.map(|(i, _)| i)?;
	let name = &s[..at_pos];
	let range = &s[at_pos + 1..];
	if name.is_empty() || range.is_empty() {
		return None;
	}
	Some((name, range))
}

/// Flush the current entry and attempt to start a new one from a top-level specifier line.
///
/// Returns `Ok(Some(new_entry))` if `line` is a valid specifier line,
/// `Ok(None)` if not, or `Err` if the specifier is unparseable.
fn flush_and_start_new(
	line: &str,
	current: &mut Option<YarnEntry>,
	entries: &mut Vec<YarnEntry>,
) -> Result<Option<State>, LpmError> {
	if let Some(entry) = current.take() {
		entries.push(entry);
	}

	let trimmed = line.trim_end();
	if !trimmed.starts_with(' ') && !trimmed.starts_with('\t') && trimmed.ends_with(':') {
		let spec_line = &trimmed[..trimmed.len() - 1];
		let specifiers: Vec<String> = spec_line
			.split(", ")
			.map(|s| s.trim().trim_matches('"').to_owned())
			.collect();
		let first_spec = &specifiers[0];
		let name = match split_specifier(first_spec) {
			Some((name, _)) => name.to_owned(),
			None => {
				return Err(LpmError::Registry(format!(
					"yarn.lock: invalid specifier: {first_spec}"
				)));
			}
		};
		*current = Some(YarnEntry {
			specifiers,
			name,
			version: String::new(),
			resolved: None,
			integrity: None,
			deps_with_ranges: Vec::new(),
		});
		Ok(Some(State::InEntry))
	} else {
		Ok(Some(State::TopLevel))
	}
}

fn parse_entries(content: &str) -> Result<Vec<YarnEntry>, LpmError> {
	let mut entries: Vec<YarnEntry> = Vec::new();
	let mut state = State::TopLevel;
	let mut current: Option<YarnEntry> = None;

	for line in content.lines() {
		// Skip blank lines.
		if line.trim().is_empty() {
			// If we were in an entry, a blank line terminates it.
			if let Some(entry) = current.take() {
				entries.push(entry);
				state = State::TopLevel;
			}
			continue;
		}

		// Skip comment lines.
		if line.starts_with('#') {
			continue;
		}

		match state {
			State::TopLevel => {
				// Package specifier line: does NOT start with whitespace and ends with ':'.
				let trimmed = line.trim_end();
				if !trimmed.starts_with(' ') && !trimmed.starts_with('\t') && trimmed.ends_with(':') {
					// Remove trailing ':'
					let spec_line = &trimmed[..trimmed.len() - 1];
					// Split by ", " for multiple specifiers.
					let specifiers: Vec<String> = spec_line
						.split(", ")
						.map(|s| s.trim().trim_matches('"').to_owned())
						.collect();

					// Extract package name from first specifier.
					let first_spec = &specifiers[0];
					let name = match split_specifier(first_spec) {
						Some((name, _)) => name.to_owned(),
						None => {
							return Err(LpmError::Registry(format!(
								"yarn.lock: invalid specifier: {first_spec}"
							)));
						}
					};

					current = Some(YarnEntry {
						specifiers,
						name,
						version: String::new(),
						resolved: None,
						integrity: None,
						deps_with_ranges: Vec::new(),
					});
					state = State::InEntry;
				}
			}
			State::InEntry => {
				let entry = current.as_mut().unwrap();

				if line.starts_with("    ") {
					// 4-space indent inside a deps block that was entered from InEntry
					// but state wasn't switched — shouldn't happen. Treat as deps if we just
					// saw dependencies:.
					// Actually this means we transitioned to InDeps but didn't set state.
					// This branch shouldn't be reached with correct state transitions.
					// Fallthrough to handle as a dep line.
					let dep_line = line.trim();
					if let Some((name, range)) = parse_dep_line(dep_line) {
						entry.deps_with_ranges.push((name, range));
					}
				} else if line.starts_with("  ") && !line.starts_with("    ") {
					// 2-space indent: property of the current entry.
					let trimmed = line.trim();
					if trimmed == "dependencies:" || trimmed == "optionalDependencies:" {
						state = State::InDeps;
					} else if let Some(rest) = trimmed.strip_prefix("version ") {
						entry.version = strip_quotes(rest).to_owned();
					} else if let Some(rest) = trimmed.strip_prefix("resolved ") {
						entry.resolved = Some(strip_quotes(rest).to_owned());
					} else if let Some(rest) = trimmed.strip_prefix("integrity ") {
						entry.integrity = Some(strip_quotes(rest).to_owned());
					}
					// Other properties (e.g., languageName, linkType) are ignored.
				} else {
					// Non-indented line while in entry — flush and re-process as top-level.
					state = flush_and_start_new(line, &mut current, &mut entries)?
						.unwrap_or(State::TopLevel);
				}
			}
			State::InDeps => {
				let entry = current.as_mut().unwrap();

				if line.starts_with("    ") {
					// 4-space indent: dependency line.
					let dep_line = line.trim();
					if let Some((name, range)) = parse_dep_line(dep_line) {
						entry.deps_with_ranges.push((name, range));
					}
				} else if line.starts_with("  ") && !line.starts_with("    ") {
					// Back to 2-space indent: another property or another deps block.
					state = State::InEntry;
					let trimmed = line.trim();
					if trimmed == "dependencies:" || trimmed == "optionalDependencies:" {
						state = State::InDeps;
					} else if let Some(rest) = trimmed.strip_prefix("version ") {
						entry.version = strip_quotes(rest).to_owned();
					} else if let Some(rest) = trimmed.strip_prefix("resolved ") {
						entry.resolved = Some(strip_quotes(rest).to_owned());
					} else if let Some(rest) = trimmed.strip_prefix("integrity ") {
						entry.integrity = Some(strip_quotes(rest).to_owned());
					}
				} else {
					// Non-indented: entry ended — flush and re-process as top-level.
					state = flush_and_start_new(line, &mut current, &mut entries)?
						.unwrap_or(State::TopLevel);
				}
			}
		}
	}

	// Flush any remaining entry at end of file.
	if let Some(entry) = current.take() {
		entries.push(entry);
	}

	Ok(entries)
}

/// Parse a dependency line like `"accepts" "~1.3.8"` or `accepts "~1.3.8"`.
fn parse_dep_line(line: &str) -> Option<(String, String)> {
	// Format: `"name" "range"` or `name "range"`.
	// Split on the space between the two quoted (or unquoted) values.
	let line = line.trim();
	if line.is_empty() {
		return None;
	}

	if line.starts_with('"') {
		// Find closing quote of the name.
		let end_name = line[1..].find('"')? + 1;
		let name = &line[1..end_name];
		let rest = line[end_name + 1..].trim_start();
		let range = strip_quotes(rest);
		Some((name.to_owned(), range.to_owned()))
	} else {
		// Unquoted name — split on first space.
		let mut parts = line.splitn(2, ' ');
		let name = parts.next()?;
		let range = strip_quotes(parts.next()?.trim());
		Some((name.to_owned(), range.to_owned()))
	}
}

/// Strip surrounding double quotes if present.
fn strip_quotes(s: &str) -> &str {
	s.trim_matches('"')
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn parse_minimal() {
		let input = r#"# yarn lockfile v1


accepts@~1.3.8:
  version "1.3.8"
  resolved "https://registry.yarnpkg.com/accepts/-/accepts-1.3.8.tgz#0bf0be125b67"
  integrity sha512-PYAthTa2m2VKxuvSD3DPC/Gy+U+sOA1LAuT8mkmRuvw==
"#;
		let packages = parse_str(input).unwrap();
		assert_eq!(packages.len(), 1);
		assert_eq!(packages[0].name, "accepts");
		assert_eq!(packages[0].version, "1.3.8");
		assert_eq!(
			packages[0].resolved.as_deref(),
			Some("https://registry.yarnpkg.com/accepts/-/accepts-1.3.8.tgz#0bf0be125b67")
		);
		assert_eq!(
			packages[0].integrity.as_deref(),
			Some("sha512-PYAthTa2m2VKxuvSD3DPC/Gy+U+sOA1LAuT8mkmRuvw==")
		);
		assert!(packages[0].dependencies.is_empty());
	}

	#[test]
	fn parse_with_dependencies() {
		let input = r#"# yarn lockfile v1


accepts@~1.3.8:
  version "1.3.8"
  resolved "https://registry.yarnpkg.com/accepts/-/accepts-1.3.8.tgz"
  integrity sha512-abc==
  dependencies:
    mime-types "~2.1.34"

mime-types@~2.1.34:
  version "2.1.35"
  resolved "https://registry.yarnpkg.com/mime-types/-/mime-types-2.1.35.tgz"
  integrity sha512-def==
"#;
		let packages = parse_str(input).unwrap();
		assert_eq!(packages.len(), 2);

		let accepts = &packages[0];
		assert_eq!(accepts.name, "accepts");
		assert_eq!(accepts.dependencies.len(), 1);
		assert_eq!(accepts.dependencies[0].0, "mime-types");
		// Range ~2.1.34 resolves to exact version 2.1.35.
		assert_eq!(accepts.dependencies[0].1, "2.1.35");
	}

	#[test]
	fn parse_multiple_specifiers() {
		let input = r#"# yarn lockfile v1


express@^4.0.0, express@^4.17.0:
  version "4.22.1"
  resolved "https://registry.yarnpkg.com/express/-/express-4.22.1.tgz"
  integrity sha512-xyz==
  dependencies:
    accepts "~1.3.8"

accepts@~1.3.8:
  version "1.3.8"
  resolved "https://registry.yarnpkg.com/accepts/-/accepts-1.3.8.tgz"
  integrity sha512-abc==
"#;
		let packages = parse_str(input).unwrap();
		assert_eq!(packages.len(), 2);

		let express = &packages[0];
		assert_eq!(express.name, "express");
		assert_eq!(express.version, "4.22.1");
		assert_eq!(express.dependencies.len(), 1);
		assert_eq!(express.dependencies[0], ("accepts".to_owned(), "1.3.8".to_owned()));
	}

	#[test]
	fn parse_scoped_packages() {
		let input = r#"# yarn lockfile v1


"@babel/core@^7.0.0":
  version "7.24.5"
  resolved "https://registry.yarnpkg.com/@babel/core/-/core-7.24.5.tgz"
  integrity sha512-scoped==
  dependencies:
    "@babel/parser" "^7.24.5"

"@babel/parser@^7.24.5":
  version "7.24.6"
  resolved "https://registry.yarnpkg.com/@babel/parser/-/parser-7.24.6.tgz"
  integrity sha512-parser==
"#;
		let packages = parse_str(input).unwrap();
		assert_eq!(packages.len(), 2);

		let core = &packages[0];
		assert_eq!(core.name, "@babel/core");
		assert_eq!(core.version, "7.24.5");
		assert_eq!(core.dependencies.len(), 1);
		assert_eq!(core.dependencies[0].0, "@babel/parser");
		assert_eq!(core.dependencies[0].1, "7.24.6");

		let parser = &packages[1];
		assert_eq!(parser.name, "@babel/parser");
		assert_eq!(parser.version, "7.24.6");
	}

	#[test]
	fn parse_optional_dependencies() {
		let input = r#"# yarn lockfile v1


my-pkg@^1.0.0:
  version "1.2.3"
  resolved "https://registry.yarnpkg.com/my-pkg/-/my-pkg-1.2.3.tgz"
  integrity sha512-opt==
  dependencies:
    dep-a "^2.0.0"
  optionalDependencies:
    dep-b "^3.0.0"

dep-a@^2.0.0:
  version "2.1.0"
  resolved "https://registry.yarnpkg.com/dep-a/-/dep-a-2.1.0.tgz"

dep-b@^3.0.0:
  version "3.0.1"
  resolved "https://registry.yarnpkg.com/dep-b/-/dep-b-3.0.1.tgz"
"#;
		let packages = parse_str(input).unwrap();
		assert_eq!(packages.len(), 3);

		let my_pkg = &packages[0];
		assert_eq!(my_pkg.name, "my-pkg");
		// Both dependencies and optionalDependencies are included.
		assert_eq!(my_pkg.dependencies.len(), 2);
		assert_eq!(my_pkg.dependencies[0], ("dep-a".to_owned(), "2.1.0".to_owned()));
		assert_eq!(my_pkg.dependencies[1], ("dep-b".to_owned(), "3.0.1".to_owned()));
	}

	#[test]
	fn parse_preserves_integrity() {
		let input = r#"# yarn lockfile v1


pkg@^1.0.0:
  version "1.0.0"
  resolved "https://registry.yarnpkg.com/pkg/-/pkg-1.0.0.tgz"
  integrity sha512-PYAthTa2m2VKxuvSD3DPC/Gy+U+sOA1LAuT8mkmRuvw+NACSaeXEQ+NHcVF7rONl6qcaxV3Uuemwawk+7+SJLw==
"#;
		let packages = parse_str(input).unwrap();
		assert_eq!(packages.len(), 1);
		assert_eq!(
			packages[0].integrity.as_deref(),
			Some("sha512-PYAthTa2m2VKxuvSD3DPC/Gy+U+sOA1LAuT8mkmRuvw+NACSaeXEQ+NHcVF7rONl6qcaxV3Uuemwawk+7+SJLw==")
		);
	}

	#[test]
	fn parse_yarnpkg_resolved_url() {
		let input = r#"# yarn lockfile v1


lodash@^4.17.21:
  version "4.17.21"
  resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz#679591c564c3bffff9f8b1bc00823d00baf9d"; echo
"#;
		let packages = parse_str(input).unwrap();
		assert_eq!(packages.len(), 1);
		assert!(packages[0]
			.resolved
			.as_ref()
			.unwrap()
			.starts_with("https://registry.yarnpkg.com/"));
	}

	#[test]
	fn parse_skips_comments() {
		let input = r#"# THIS IS AN AUTOGENERATED FILE. DO NOT EDIT THIS FILE DIRECTLY.
# yarn lockfile v1
# some other comment


pkg@^1.0.0:
  version "1.0.0"
"#;
		let packages = parse_str(input).unwrap();
		assert_eq!(packages.len(), 1);
		assert_eq!(packages[0].name, "pkg");
		assert_eq!(packages[0].version, "1.0.0");
	}

	#[test]
	fn parse_empty_lockfile() {
		let input = r#"# THIS IS AN AUTOGENERATED FILE. DO NOT EDIT THIS FILE DIRECTLY.
# yarn lockfile v1


"#;
		let packages = parse_str(input).unwrap();
		assert!(packages.is_empty());
	}

	#[test]
	fn mark_dev_optional_from_package_json() {
		// Finding #6: yarn v1 doesn't encode dev/optional at entry level
		let input = r#"# yarn lockfile v1


test-lib@^1.0.0:
  version "1.2.3"
  resolved "https://registry.yarnpkg.com/test-lib/-/test-lib-1.2.3.tgz"
  integrity sha512-test==

prod-lib@^2.0.0:
  version "2.0.1"
  resolved "https://registry.yarnpkg.com/prod-lib/-/prod-lib-2.0.1.tgz"
  integrity sha512-prod==
"#;
		let mut packages = parse_str(input).unwrap();
		assert_eq!(packages.len(), 2);

		// Before marking, both are false
		assert!(!packages.iter().any(|p| p.is_dev));

		// Mark dev deps
		let dev_deps: std::collections::HashSet<String> =
			["test-lib".to_string()].into_iter().collect();
		let optional_deps: std::collections::HashSet<String> = std::collections::HashSet::new();
		crate::normalize::mark_dev_optional(&mut packages, &dev_deps, &optional_deps);

		let test_lib = packages.iter().find(|p| p.name == "test-lib").unwrap();
		assert!(test_lib.is_dev, "test-lib should be marked as dev");

		let prod_lib = packages.iter().find(|p| p.name == "prod-lib").unwrap();
		assert!(!prod_lib.is_dev, "prod-lib should NOT be marked as dev");
	}

	#[test]
	fn parse_real_world_small() {
		let input = r#"# THIS IS AN AUTOGENERATED FILE. DO NOT EDIT THIS FILE DIRECTLY.
# yarn lockfile v1


accepts@~1.3.8:
  version "1.3.8"
  resolved "https://registry.yarnpkg.com/accepts/-/accepts-1.3.8.tgz#0bf0be125b67014adcb0b0921e62db7bffe16b2e"
  integrity sha512-PYAthTa2m2VKxuvSD3DPC/Gy+U+sOA1LAuT8mkmRuvw+NACSaeXEQ+NHcVF7rONl6qcaxV3Uuemwawk+7+SJLw==
  dependencies:
    mime-types "~2.1.34"
    negotiator "0.6.3"

mime-types@~2.1.34:
  version "2.1.35"
  resolved "https://registry.yarnpkg.com/mime-types/-/mime-types-2.1.35.tgz#381a871b62a734450660ae3deee44813f70d959a"
  integrity sha512-ZDY+bPm5zTTF+YpCrAU9nK0UgICYPT0QtT1NZWFv4s++TNkcgVaT0g6+4R2uI4MjQjzysHB1zxuWL50hzaeXiw==
  dependencies:
    mime-db "1.52.0"

mime-db@1.52.0:
  version "1.52.0"
  resolved "https://registry.yarnpkg.com/mime-db/-/mime-db-1.52.0.tgz#bbabcdc02859f4987301c856e3387ce5ec43bf70"
  integrity sha512-sPU4uV7dYlvtWJxwwxHD0PuihVNiE7TyAbQ5SWxDCB9mUYvOgroQOwYQQOKPJ8CIbE+1ETVlOoK1UC2nU3gYvg==

negotiator@0.6.3:
  version "0.6.3"
  resolved "https://registry.yarnpkg.com/negotiator/-/negotiator-0.6.3.tgz#58e323a72fedc0d6f9cd4d31fe49f51479590e6c"
  integrity sha512-+EUsqGPLsM+j/zdChZjsnX51g28XR3AYNjxhMe5ShFKOqF8aKOJ2Wrcag4+Dqg7mu7kHp94KQQlMiLfOk0UXw==
"#;
		let packages = parse_str(input).unwrap();
		assert_eq!(packages.len(), 4);

		// Check accepts has correct deps resolved.
		let accepts = packages.iter().find(|p| p.name == "accepts").unwrap();
		assert_eq!(accepts.version, "1.3.8");
		assert_eq!(accepts.dependencies.len(), 2);
		assert!(accepts.dependencies.contains(&("mime-types".to_owned(), "2.1.35".to_owned())));
		assert!(accepts.dependencies.contains(&("negotiator".to_owned(), "0.6.3".to_owned())));

		// Check mime-types has deps resolved.
		let mime_types = packages.iter().find(|p| p.name == "mime-types").unwrap();
		assert_eq!(mime_types.version, "2.1.35");
		assert_eq!(mime_types.dependencies.len(), 1);
		assert_eq!(
			mime_types.dependencies[0],
			("mime-db".to_owned(), "1.52.0".to_owned())
		);

		// Check leaf packages have no deps.
		let mime_db = packages.iter().find(|p| p.name == "mime-db").unwrap();
		assert!(mime_db.dependencies.is_empty());
		let negotiator = packages.iter().find(|p| p.name == "negotiator").unwrap();
		assert!(negotiator.dependencies.is_empty());

		// All have integrity.
		for pkg in &packages {
			assert!(pkg.integrity.is_some(), "missing integrity for {}", pkg.name);
		}

		// All have resolved URLs.
		for pkg in &packages {
			assert!(pkg.resolved.is_some(), "missing resolved for {}", pkg.name);
			assert!(pkg.resolved.as_ref().unwrap().starts_with("https://registry.yarnpkg.com/"));
		}
	}
}
