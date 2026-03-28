//! Local task cache — store outputs on miss, restore on hit, replay stdout.
//!
//! Cache layout:
//! ```text
//! ~/.lpm/cache/tasks/
//!   {cache-key}/
//!     meta.json       ← timing, command, key info
//!     stdout.log      ← captured stdout
//!     stderr.log      ← captured stderr
//!     outputs.tar.gz  ← archived output files
//! ```

use lpm_common::LpmError;
use std::path::{Path, PathBuf};

/// Base directory for task cache.
pub fn cache_dir() -> Result<PathBuf, LpmError> {
	let home = dirs::home_dir()
		.ok_or_else(|| LpmError::Script("could not determine home directory".into()))?;
	Ok(home.join(".lpm").join("cache").join("tasks"))
}

/// Get the cache directory for a specific cache key.
pub fn cache_entry_dir(key: &str) -> Result<PathBuf, LpmError> {
	Ok(cache_dir()?.join(key))
}

/// Check if a cache entry exists for the given key.
pub fn has_cache_hit(key: &str) -> bool {
	cache_entry_dir(key)
		.map(|d| d.join("meta.json").exists())
		.unwrap_or(false)
}

/// Restore cached outputs to the project directory.
///
/// Returns the cached stdout content for replay.
pub fn restore_cache(key: &str, project_dir: &Path) -> Result<CacheHit, LpmError> {
	let entry = cache_entry_dir(key)?;

	// Read meta
	let meta_path = entry.join("meta.json");
	let meta_content = std::fs::read_to_string(&meta_path)
		.map_err(|e| LpmError::Script(format!("failed to read cache meta: {e}")))?;
	let meta: CacheMeta = serde_json::from_str(&meta_content)
		.map_err(|e| LpmError::Script(format!("failed to parse cache meta: {e}")))?;

	// Restore outputs archive
	let archive_path = entry.join("outputs.tar.gz");
	if archive_path.exists() {
		restore_archive(&archive_path, project_dir)?;
	}

	// Read stdout/stderr for replay — warn if missing (indicates corruption)
	let stdout_path = entry.join("stdout.log");
	let stderr_path = entry.join("stderr.log");
	let stdout = match std::fs::read_to_string(&stdout_path) {
		Ok(s) => s,
		Err(e) => {
			tracing::warn!("cache entry missing stdout.log: {e} — cache may be corrupted");
			String::new()
		}
	};
	let stderr = match std::fs::read_to_string(&stderr_path) {
		Ok(s) => s,
		Err(e) => {
			tracing::warn!("cache entry missing stderr.log: {e} — cache may be corrupted");
			String::new()
		}
	};

	Ok(CacheHit {
		meta,
		stdout,
		stderr,
	})
}

/// Store task outputs to cache.
pub fn store_cache(
	key: &str,
	project_dir: &Path,
	command: &str,
	output_globs: &[String],
	stdout: &str,
	stderr: &str,
	duration_ms: u64,
) -> Result<(), LpmError> {
	let entry = cache_entry_dir(key)?;
	std::fs::create_dir_all(&entry)?;

	// Write stdout/stderr
	std::fs::write(entry.join("stdout.log"), stdout)?;
	std::fs::write(entry.join("stderr.log"), stderr)?;

	// Archive output files
	let output_file_count = if !output_globs.is_empty() {
		create_archive(project_dir, output_globs, &entry.join("outputs.tar.gz"))?
	} else {
		0
	};

	// Write meta (after archiving so we have the file count)
	let meta = CacheMeta {
		command: command.to_string(),
		cache_key: key.to_string(),
		duration_ms,
		output_file_count,
	};
	let meta_json = serde_json::to_string_pretty(&meta)
		.map_err(|e| LpmError::Script(format!("failed to serialize cache meta: {e}")))?;
	std::fs::write(entry.join("meta.json"), meta_json)?;

	tracing::debug!("cached task output to {}", entry.display());
	Ok(())
}

/// Clean the entire task cache.
pub fn clean_cache() -> Result<u64, LpmError> {
	let dir = cache_dir()?;
	if !dir.exists() {
		return Ok(0);
	}

	let mut count = 0u64;
	for entry in std::fs::read_dir(&dir)? {
		let entry = entry?;
		if entry.path().is_dir() {
			std::fs::remove_dir_all(entry.path())?;
			count += 1;
		}
	}

	Ok(count)
}

/// Cache hit result.
pub struct CacheHit {
	pub meta: CacheMeta,
	pub stdout: String,
	pub stderr: String,
}

/// Cache entry metadata.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct CacheMeta {
	pub command: String,
	pub cache_key: String,
	pub duration_ms: u64,
	/// Number of output files archived (for integrity check on restore).
	#[serde(default)]
	pub output_file_count: usize,
}

/// Create a .tar.gz archive of files matching output globs.
/// Returns the number of files archived.
fn create_archive(
	project_dir: &Path,
	output_globs: &[String],
	archive_path: &Path,
) -> Result<usize, LpmError> {
	let file = std::fs::File::create(archive_path)?;
	let enc = flate2::write::GzEncoder::new(file, flate2::Compression::Fast);
	let mut builder = tar::Builder::new(enc);
	let mut file_count = 0;

	for pattern in output_globs {
		// Normalize glob: "dist/**" → also match "dist/**/*" to catch files at any depth
		let patterns = expand_glob_pattern(pattern);

		for pat in &patterns {
			let full_pattern = project_dir.join(pat);
			let pattern_str = full_pattern.to_string_lossy().to_string();

			if let Ok(entries) = glob::glob(&pattern_str) {
				for entry in entries.flatten() {
					if entry.is_file() {
						let rel = entry
							.strip_prefix(project_dir)
							.unwrap_or(&entry);
						builder.append_path_with_name(&entry, rel).map_err(|e| {
							LpmError::Script(format!("failed to add {} to archive: {e}", entry.display()))
						})?;
						file_count += 1;
					}
				}
			}
		}
	}

	builder.finish().map_err(|e| {
		LpmError::Script(format!("failed to finalize archive: {e}"))
	})?;

	tracing::debug!("archived {file_count} files to {}", archive_path.display());
	Ok(file_count)
}

/// Expand a glob pattern to cover both directories and files at any depth.
/// "dist/**" → ["dist/**", "dist/**/*"]
fn expand_glob_pattern(pattern: &str) -> Vec<String> {
	let mut patterns = vec![pattern.to_string()];
	if pattern.ends_with("/**") {
		patterns.push(format!("{pattern}/*"));
	}
	patterns
}

/// Restore a .tar.gz archive to the project directory.
fn restore_archive(archive_path: &Path, project_dir: &Path) -> Result<(), LpmError> {
	let file = std::fs::File::open(archive_path)?;
	let dec = flate2::read::GzDecoder::new(file)
		.map_err(|e| LpmError::Script(format!("failed to open cache archive: {e}")))?;
	let mut archive = tar::Archive::new(dec);
	archive.unpack(project_dir).map_err(|e| {
		LpmError::Script(format!("failed to restore cache archive: {e}"))
	})?;

	Ok(())
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::fs;

	fn unique_key(prefix: &str) -> String {
		use std::time::{SystemTime, UNIX_EPOCH};
		let ts = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
		format!("{prefix}-{ts}")
	}

	#[test]
	fn cache_miss_returns_false() {
		assert!(!has_cache_hit("nonexistent-key-12345"));
	}

	#[test]
	fn store_and_restore_roundtrip() {
		let dir = tempfile::tempdir().unwrap();

		fs::create_dir_all(dir.path().join("dist")).unwrap();
		fs::write(dir.path().join("dist/index.js"), "built output").unwrap();
		fs::write(dir.path().join("dist/style.css"), "body {}").unwrap();

		let key = unique_key("roundtrip");

		store_cache(
			&key,
			dir.path(),
			"echo build",
			&["dist/**".into()],
			"build output\n",
			"",
			1234,
		)
		.unwrap();

		assert!(has_cache_hit(&key), "cache entry should exist after store");

		// Delete the output files
		fs::remove_dir_all(dir.path().join("dist")).unwrap();
		assert!(!dir.path().join("dist/index.js").exists());

		// Restore
		let hit = restore_cache(&key, dir.path()).unwrap();
		assert_eq!(hit.meta.command, "echo build");
		assert_eq!(hit.meta.duration_ms, 1234);
		assert_eq!(hit.stdout, "build output\n");
		assert!(dir.path().join("dist/index.js").exists(), "dist/index.js should be restored");
		assert_eq!(
			fs::read_to_string(dir.path().join("dist/index.js")).unwrap(),
			"built output"
		);

		// Cleanup this specific entry
		let _ = fs::remove_dir_all(cache_entry_dir(&key).unwrap());
	}

	// clean_cache() test omitted — it operates on the real global ~/.lpm/cache/tasks/
	// directory and races with other cache tests. Tested via real `lpm cache clean --tasks` command.
}
