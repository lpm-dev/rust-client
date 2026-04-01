//! Cache key computation for task caching.
//!
//! A cache key is a SHA-256 hash of everything that affects a task's output:
//! - Source files matching input globs
//! - package.json dependencies
//! - The command string
//! - Environment variables
//! - Node.js version

use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use std::path::Path;

/// Compute a cache key for a task.
///
/// The key is a hex-encoded SHA-256 hash of all inputs that affect the output.
/// Includes a format version prefix so key format changes invalidate old caches.
pub fn compute_cache_key(
    project_dir: &Path,
    command: &str,
    input_globs: &[String],
    env_vars: &HashMap<String, String>,
    deps_json: &str,
) -> String {
    let mut hasher = Sha256::new();

    // 0. Cache format version — bump this when changing hash inputs
    hasher.update(b"cache-v2\n");

    // 1. Command string
    hasher.update(b"cmd:");
    hasher.update(command.as_bytes());
    hasher.update(b"\n");

    // 2. Dependencies JSON — canonicalize for determinism
    //    serde_json doesn't guarantee key ordering, so we parse and re-serialize
    //    with sorted keys to ensure identical JSON produces identical hashes.
    let canonical_deps = canonicalize_json(deps_json);
    hasher.update(b"deps:");
    hasher.update(canonical_deps.as_bytes());
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
        if !crate::cache::validate_glob_pattern(pattern) {
            tracing::warn!("skipping unsafe glob pattern: {pattern}");
            continue;
        }

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
                            match sha256_hex_file(&entry) {
                                Ok(hash) => {
                                    files.push((rel, hash));
                                }
                                Err(e) => {
                                    tracing::warn!("failed to hash file {}: {e}", entry.display());
                                    // Include a sentinel so the path still affects the key.
                                    // Different devs with different read access won't silently
                                    // get the same cache key.
                                    files.push((rel.clone(), format!("<unreadable:{rel}>")));
                                }
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

/// Compute SHA-256 hex string of a file using streaming reads.
///
/// Reads in 8 KiB chunks to avoid loading large files entirely into memory.
fn sha256_hex_file(path: &Path) -> std::io::Result<String> {
    use std::io::Read;
    let mut hasher = Sha256::new();
    let mut file = std::fs::File::open(path)?;
    let mut buf = [0u8; 8192];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex::encode(hasher.finalize()))
}

/// Canonicalize a JSON string so key ordering is deterministic.
///
/// Parses the JSON, explicitly sorts object keys recursively via `BTreeMap`,
/// then re-serializes. This is safe regardless of whether `serde_json` uses
/// BTreeMap or IndexMap internally (`preserve_order` feature).
/// If parsing fails (not valid JSON), returns the original string as-is.
fn canonicalize_json(json: &str) -> String {
    match serde_json::from_str::<serde_json::Value>(json) {
        Ok(value) => {
            let canonical = canonicalize_value(&value);
            serde_json::to_string(&canonical).unwrap_or_else(|_| json.to_string())
        }
        Err(_) => json.to_string(),
    }
}

/// Recursively sort all object keys using BTreeMap for deterministic output.
fn canonicalize_value(value: &serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Object(map) => {
            let sorted: BTreeMap<String, serde_json::Value> = map
                .iter()
                .map(|(k, v)| (k.clone(), canonicalize_value(v)))
                .collect();
            serde_json::Value::Object(sorted.into_iter().collect())
        }
        serde_json::Value::Array(arr) => {
            serde_json::Value::Array(arr.iter().map(canonicalize_value).collect())
        }
        other => other.clone(),
    }
}

/// Simple hex encoding (avoid pulling in the `hex` crate).
///
/// Pre-allocates the output string to avoid per-byte allocations.
mod hex {
    pub fn encode(bytes: impl AsRef<[u8]>) -> String {
        use std::fmt::Write;
        let bytes = bytes.as_ref();
        let mut s = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            write!(s, "{b:02x}").unwrap();
        }
        s
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
        let key1 = compute_cache_key(dir.path(), "echo build", &["src/**".into()], &env, "{}");
        let key2 = compute_cache_key(dir.path(), "echo build", &["src/**".into()], &env, "{}");
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
    fn deps_json_ordering_does_not_affect_key() {
        let dir = tempfile::tempdir().unwrap();
        let env = HashMap::new();

        // Two different JSON key orderings of the same data
        let key1 = compute_cache_key(
            dir.path(),
            "build",
            &[],
            &env,
            r#"{"react":"^19","lodash":"^4"}"#,
        );
        let key2 = compute_cache_key(
            dir.path(),
            "build",
            &[],
            &env,
            r#"{"lodash":"^4","react":"^19"}"#,
        );
        assert_eq!(
            key1, key2,
            "different JSON key ordering should produce same cache key"
        );
    }

    #[test]
    fn canonicalize_json_sorts_keys() {
        let a = canonicalize_json(r#"{"b":"2","a":"1"}"#);
        let b = canonicalize_json(r#"{"a":"1","b":"2"}"#);
        assert_eq!(a, b);
    }

    #[test]
    fn canonicalize_json_invalid_passthrough() {
        let result = canonicalize_json("not-json");
        assert_eq!(result, "not-json");
    }

    #[test]
    fn deps_change_invalidates_cache() {
        let dir = tempfile::tempdir().unwrap();
        let env = HashMap::new();

        let key1 = compute_cache_key(dir.path(), "build", &[], &env, r#"{"react":"^18"}"#);
        let key2 = compute_cache_key(dir.path(), "build", &[], &env, r#"{"react":"^19"}"#);
        assert_ne!(key1, key2);
    }

    // -- Finding #6: canonicalize_value sorts keys explicitly --

    #[test]
    fn canonicalize_value_sorts_nested_keys() {
        use serde_json::json;
        let a = json!({"z": 1, "a": {"c": 3, "b": 2}});
        let b = json!({"a": {"b": 2, "c": 3}, "z": 1});
        let ca = serde_json::to_string(&canonicalize_value(&a)).unwrap();
        let cb = serde_json::to_string(&canonicalize_value(&b)).unwrap();
        assert_eq!(ca, cb);
    }

    #[test]
    fn canonicalize_value_handles_arrays() {
        use serde_json::json;
        let val = json!([{"b": 2, "a": 1}, {"d": 4, "c": 3}]);
        let canonical = canonicalize_value(&val);
        let s = serde_json::to_string(&canonical).unwrap();
        assert_eq!(s, r#"[{"a":1,"b":2},{"c":3,"d":4}]"#);
    }

    // -- Finding #12: streaming file hash --

    #[test]
    fn sha256_hex_file_correct_hash() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.txt");
        fs::write(&path, "hello world").unwrap();

        let hash = sha256_hex_file(&path).unwrap();
        // SHA-256 of "hello world"
        assert_eq!(
            hash,
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }

    // -- Finding #16: hex encoding --

    #[test]
    fn hex_encode_correct() {
        assert_eq!(hex::encode([0x00, 0xff, 0x0a, 0xab]), "00ff0aab");
        assert_eq!(hex::encode([]), "");
        assert_eq!(hex::encode([0xde, 0xad, 0xbe, 0xef]), "deadbeef");
    }
}
