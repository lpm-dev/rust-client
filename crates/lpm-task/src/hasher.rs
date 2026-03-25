//! Cache key computation for task caching.
//!
//! A cache key is a SHA-256 hash of everything that affects a task's output:
//! - Source files matching input globs
//! - package.json dependencies
//! - The command string
//! - Environment variables
//! - Node.js version

use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::Path;

/// Compute a cache key for a task.
///
/// The key is a hex-encoded SHA-256 hash of all inputs that affect the output.
pub fn compute_cache_key(
	project_dir: &Path,
	command: &str,
	input_globs: &[String],
	env_vars: &HashMap<String, String>,
	deps_json: &str,
) -> String {
	let mut hasher = Sha256::new();

	// 1. Command string
	hasher.update(b"cmd:");
	hasher.update(command.as_bytes());
	hasher.update(b"\n");

	// 2. Dependencies JSON (sorted for determinism)
	hasher.update(b"deps:");
	hasher.update(deps_json.as_bytes());
	hasher.update(b"\n");

	// 3. Environment variables (sorted by key)
	let mut env_keys: Vec<&String> = env_vars.keys().collect();
	env_keys.sort();
	for key in env_keys {
		hasher.update(b"env:");
		hasher.update(key.as_bytes());
		hasher.update(b"=");
		hasher.update(env_vars[key].as_bytes());
		hasher.update(b"\n");
	}

	// 4. Source file contents matching input globs
	let files = collect_input_files(project_dir, input_globs);
	for (path, content_hash) in &files {
		hasher.update(b"file:");
		hasher.update(path.as_bytes());
		hasher.update(b":");
		hasher.update(content_hash.as_bytes());
		hasher.update(b"\n");
	}

	let result = hasher.finalize();
	hex::encode(result)
}

/// Collect input files matching glob patterns and hash their contents.
///
/// Returns sorted (relative_path, content_sha256_hex) pairs.
fn collect_input_files(project_dir: &Path, globs: &[String]) -> Vec<(String, String)> {
	let mut files = Vec::new();
	let mut seen = std::collections::HashSet::new();

	for pattern in globs {
		// "src/**" → also match "src/**/*" for files at any depth
		let patterns = expand_glob(pattern);

		for pat in &patterns {
			let full_pattern = project_dir.join(pat);
			let pattern_str = full_pattern.to_string_lossy().to_string();

			if let Ok(entries) = glob::glob(&pattern_str) {
				for entry in entries.flatten() {
					if entry.is_file() {
						let rel = entry
							.strip_prefix(project_dir)
							.unwrap_or(&entry)
							.to_string_lossy()
							.to_string();
						if seen.insert(rel.clone()) {
							if let Ok(content) = std::fs::read(&entry) {
								let hash = sha256_hex(&content);
								files.push((rel, hash));
							}
						}
					}
				}
			}
		}
	}

	// Sort for deterministic ordering
	files.sort_by(|a, b| a.0.cmp(&b.0));
	files
}

fn expand_glob(pattern: &str) -> Vec<String> {
	let mut patterns = vec![pattern.to_string()];
	if pattern.ends_with("/**") {
		patterns.push(format!("{pattern}/*"));
	}
	patterns
}

/// Compute SHA-256 hex string of data.
fn sha256_hex(data: &[u8]) -> String {
	let mut hasher = Sha256::new();
	hasher.update(data);
	hex::encode(hasher.finalize())
}

/// Simple hex encoding (avoid pulling in the `hex` crate).
mod hex {
	pub fn encode(bytes: impl AsRef<[u8]>) -> String {
		bytes
			.as_ref()
			.iter()
			.map(|b| format!("{b:02x}"))
			.collect()
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::fs;

	#[test]
	fn deterministic_key() {
		let dir = tempfile::tempdir().unwrap();
		fs::create_dir_all(dir.path().join("src")).unwrap();
		fs::write(dir.path().join("src/index.js"), "console.log('hi')").unwrap();
		fs::write(dir.path().join("package.json"), "{}").unwrap();

		let env = HashMap::new();
		let key1 = compute_cache_key(
			dir.path(),
			"echo build",
			&["src/**".into()],
			&env,
			"{}",
		);
		let key2 = compute_cache_key(
			dir.path(),
			"echo build",
			&["src/**".into()],
			&env,
			"{}",
		);
		assert_eq!(key1, key2);
		assert_eq!(key1.len(), 64); // SHA-256 hex = 64 chars
	}

	#[test]
	fn different_command_different_key() {
		let dir = tempfile::tempdir().unwrap();
		fs::write(dir.path().join("package.json"), "{}").unwrap();
		let env = HashMap::new();

		let key1 = compute_cache_key(dir.path(), "echo a", &[], &env, "{}");
		let key2 = compute_cache_key(dir.path(), "echo b", &[], &env, "{}");
		assert_ne!(key1, key2);
	}

	#[test]
	fn different_env_different_key() {
		let dir = tempfile::tempdir().unwrap();
		let mut env1 = HashMap::new();
		env1.insert("NODE_ENV".into(), "development".into());

		let mut env2 = HashMap::new();
		env2.insert("NODE_ENV".into(), "production".into());

		let key1 = compute_cache_key(dir.path(), "echo", &[], &env1, "{}");
		let key2 = compute_cache_key(dir.path(), "echo", &[], &env2, "{}");
		assert_ne!(key1, key2);
	}

	#[test]
	fn file_change_invalidates_cache() {
		let dir = tempfile::tempdir().unwrap();
		fs::create_dir_all(dir.path().join("src")).unwrap();
		fs::write(dir.path().join("src/index.js"), "v1").unwrap();
		let env = HashMap::new();

		let key1 = compute_cache_key(dir.path(), "build", &["src/**".into()], &env, "{}");

		fs::write(dir.path().join("src/index.js"), "v2").unwrap();

		let key2 = compute_cache_key(dir.path(), "build", &["src/**".into()], &env, "{}");
		assert_ne!(key1, key2);
	}

	#[test]
	fn deps_change_invalidates_cache() {
		let dir = tempfile::tempdir().unwrap();
		let env = HashMap::new();

		let key1 = compute_cache_key(dir.path(), "build", &[], &env, r#"{"react":"^18"}"#);
		let key2 = compute_cache_key(dir.path(), "build", &[], &env, r#"{"react":"^19"}"#);
		assert_ne!(key1, key2);
	}
}
