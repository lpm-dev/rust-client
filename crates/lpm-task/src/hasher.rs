//! Cache key computation for task caching.
//!
//! A cache key is a SHA-256 hash of everything that affects a task's output:
//! - Source files matching input globs
//! - The complete package.json contract
//! - The command string
//! - Environment variables
//! - Node.js version

use cap_fs_ext::{DirExt, FollowSymlinks, OpenOptionsFollowExt};
use cap_std::fs::Dir;
use lpm_common::LpmError;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use std::path::{Component, Path};

const ECOSYSTEM_LOCKFILES: &[&str] = &[
    "package-lock.json",
    "npm-shrinkwrap.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "bun.lock",
    "bun.lockb",
    "deno.lock",
];

/// Compute a cache key for a task.
///
/// The key is a hex-encoded SHA-256 hash of all inputs that affect the output.
/// Includes a format version prefix so key format changes invalidate old caches.
pub fn compute_cache_key(
    project_dir: &Path,
    command: &str,
    extra_args: &[String],
    runtime_identities: &[(String, String)],
    input_globs: &[String],
    env_vars: &HashMap<String, String>,
    package_json: &str,
) -> Result<String, LpmError> {
    let mut hasher = Sha256::new();

    hash_record(&mut hasher, 0, &[b"cache-v6"]);

    hash_record(&mut hasher, 1, &[command.as_bytes()]);

    // The task contract itself affects cache validity even when callers use
    // custom input globs. Hash the project config independently so changes to
    // outputs, environments, or dependency edges cannot reuse an older entry.
    let project = open_project_directory(project_dir);
    hash_implicit_project_file(&mut hasher, project.as_ref(), "config", "lpm.json");
    let has_text_lock =
        hash_implicit_project_file(&mut hasher, project.as_ref(), "lockfile", "lpm.lock");
    if !has_text_lock {
        hash_implicit_project_file(&mut hasher, project.as_ref(), "lockfile", "lpm.lockb");
    }
    for name in ECOSYSTEM_LOCKFILES {
        hash_implicit_project_file(&mut hasher, project.as_ref(), "lockfile", name);
    }

    for argument in extra_args {
        hash_record(&mut hasher, 2, &[argument.as_bytes()]);
    }

    for (runtime, identity) in runtime_identities {
        hash_record(&mut hasher, 3, &[runtime.as_bytes(), identity.as_bytes()]);
    }

    // 2. Complete package contract, canonicalized for deterministic key ordering.
    let canonical_package = canonicalize_json(package_json);
    hash_record(&mut hasher, 4, &[canonical_package.as_bytes()]);

    // 3. Environment variables (sorted by key)
    let mut env_keys: Vec<&String> = env_vars.keys().collect();
    env_keys.sort();
    for key in env_keys {
        hash_record(&mut hasher, 5, &[key.as_bytes(), env_vars[key].as_bytes()]);
    }

    // 4. Source file contents matching input globs
    let files = collect_input_files(project_dir, input_globs)?;
    for (path, content_hash) in &files {
        hash_record(&mut hasher, 6, &[path.as_bytes(), content_hash.as_bytes()]);
    }

    let result = hasher.finalize();
    Ok(hex::encode(result))
}

fn hash_record(hasher: &mut Sha256, kind: u8, fields: &[&[u8]]) {
    hasher.update([kind]);
    hasher.update((fields.len() as u64).to_le_bytes());
    for field in fields {
        hasher.update((field.len() as u64).to_le_bytes());
        hasher.update(field);
    }
}

/// Collect input files matching glob patterns and hash their contents.
///
/// Returns sorted (relative_path, content_sha256_hex) pairs.
fn collect_input_files(
    project_dir: &Path,
    globs: &[String],
) -> Result<Vec<(String, String)>, LpmError> {
    let mut files = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let canonical_project = project_dir.canonicalize().map_err(|error| {
        LpmError::Task(format!(
            "failed to resolve task cache project directory {}: {error}",
            project_dir.display()
        ))
    })?;
    let project = Dir::open_ambient_dir(&canonical_project, cap_std::ambient_authority())?;

    for pattern in globs {
        if !crate::cache::validate_glob_pattern(pattern) {
            return Err(LpmError::Task(format!(
                "invalid task cache input glob: {pattern}"
            )));
        }

        // "src/**" → also match "src/**/*" for files at any depth
        let patterns = expand_glob(pattern);

        for pat in &patterns {
            let pattern_str = lpm_common::rooted_project_glob(project_dir, pat);

            let entries = glob::glob(&pattern_str).map_err(|error| {
                LpmError::Task(format!(
                    "invalid task cache input glob {pattern:?}: {error}"
                ))
            })?;
            for entry in entries {
                let entry = entry.map_err(|error| {
                    LpmError::Task(format!(
                        "failed to expand task cache input glob {pattern:?}: {error}"
                    ))
                })?;
                let resolved = entry.canonicalize().map_err(|error| {
                    LpmError::Task(format!(
                        "failed to resolve task cache input {}: {error}",
                        entry.display()
                    ))
                })?;
                if !resolved.starts_with(&canonical_project) {
                    return Err(LpmError::Task(format!(
                        "task cache input resolves outside project: {}",
                        entry.display()
                    )));
                }
                let metadata = std::fs::metadata(&resolved)?;
                if !metadata.is_file() {
                    continue;
                }
                let relative = entry.strip_prefix(project_dir).map_err(|_| {
                    LpmError::Task(format!(
                        "task cache input is outside project path: {}",
                        entry.display()
                    ))
                })?;
                let relative_text = relative.to_string_lossy().into_owned();
                if seen.insert(relative_text.clone()) {
                    let resolved_relative =
                        resolved.strip_prefix(&canonical_project).map_err(|_| {
                            LpmError::Task(format!(
                                "task cache input resolves outside project: {}",
                                entry.display()
                            ))
                        })?;
                    let mut file = open_project_file_nofollow(&project, resolved_relative)?;
                    let hash = sha256_hex_reader(&mut file).map_err(|error| {
                        LpmError::Task(format!(
                            "failed to hash task cache input {}: {error}",
                            entry.display()
                        ))
                    })?;
                    files.push((relative_text, hash));
                }
            }
        }
    }

    // Sort for deterministic ordering
    files.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(files)
}

fn open_project_file_nofollow(project: &Dir, relative: &Path) -> Result<std::fs::File, LpmError> {
    let mut components = relative.components().peekable();
    let mut parent = project.try_clone()?;
    while let Some(component) = components.next() {
        let Component::Normal(name) = component else {
            return Err(LpmError::Task(format!(
                "invalid task cache input path: {}",
                relative.display()
            )));
        };
        if components.peek().is_some() {
            parent = parent.open_dir_nofollow(name).map_err(|error| {
                LpmError::Task(format!(
                    "task cache input parent is unsafe at {}: {error}",
                    relative.display()
                ))
            })?;
            continue;
        }
        let mut options = cap_std::fs::OpenOptions::new();
        options.read(true).follow(FollowSymlinks::No);
        let file = parent.open_with(name, &options).map_err(|error| {
            LpmError::Task(format!(
                "failed to open task cache input {} without following links: {error}",
                relative.display()
            ))
        })?;
        if !file.metadata()?.is_file() {
            return Err(LpmError::Task(format!(
                "task cache input is not a real file: {}",
                relative.display()
            )));
        }
        return Ok(file.into_std());
    }
    Err(LpmError::Task("invalid empty task cache input path".into()))
}

fn expand_glob(pattern: &str) -> Vec<String> {
    let mut patterns = vec![pattern.to_string()];
    if pattern.ends_with("/**") {
        patterns.push(format!("{pattern}/*"));
    }
    patterns
}

#[cfg(test)]
fn target_stays_in_project(entry: &Path, project_dir: &Path) -> bool {
    entry.canonicalize().is_ok_and(|entry| {
        project_dir
            .canonicalize()
            .is_ok_and(|project| entry.starts_with(project))
    })
}

fn open_project_directory(project_dir: &Path) -> Option<Dir> {
    let canonical_project = project_dir.canonicalize().ok()?;
    Dir::open_ambient_dir(canonical_project, cap_std::ambient_authority()).ok()
}

fn hash_implicit_project_file(
    hasher: &mut Sha256,
    project: Option<&Dir>,
    kind: &str,
    name: &str,
) -> bool {
    let Some(project) = project else {
        hasher.update(kind.as_bytes());
        hasher.update(b":");
        hasher.update(name.as_bytes());
        hasher.update(b":<project-unreadable>\n");
        return true;
    };
    let mut options = cap_std::fs::OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No);
    let file = match project.open_with(name, &options) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return false,
        Err(_) => {
            hash_implicit_file_value(hasher, kind, name, "<unsafe-or-unreadable>");
            return true;
        }
    };
    if !file.metadata().is_ok_and(|metadata| metadata.is_file()) {
        hash_implicit_file_value(hasher, kind, name, "<unsafe-or-unreadable>");
        return true;
    }
    let hash =
        sha256_hex_reader(&mut file.into_std()).unwrap_or_else(|_| "<unsafe-or-unreadable>".into());
    hash_implicit_file_value(hasher, kind, name, &hash);
    true
}

fn hash_implicit_file_value(hasher: &mut Sha256, kind: &str, name: &str, value: &str) {
    hash_record(
        hasher,
        7,
        &[kind.as_bytes(), name.as_bytes(), value.as_bytes()],
    );
}

/// Compute SHA-256 hex string of a file using streaming reads.
///
/// Reads in 8 KiB chunks to avoid loading large files entirely into memory.
fn sha256_hex_reader(reader: &mut impl std::io::Read) -> std::io::Result<String> {
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex::encode(hasher.finalize()))
}

#[cfg(test)]
fn sha256_hex_file(path: &Path) -> std::io::Result<String> {
    sha256_hex_reader(&mut std::fs::File::open(path)?)
}

/// Canonicalize a JSON string so key ordering is deterministic.
///
/// Parses the JSON, explicitly sorts object keys recursively via `BTreeMap`,
/// then re-serializes. If parsing fails, returns the original string as-is.
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

    fn compute_cache_key(
        project_dir: &Path,
        command: &str,
        extra_args: &[String],
        runtime_identities: &[(String, String)],
        input_globs: &[String],
        env_vars: &HashMap<String, String>,
        deps_json: &str,
    ) -> String {
        super::compute_cache_key(
            project_dir,
            command,
            extra_args,
            runtime_identities,
            input_globs,
            env_vars,
            deps_json,
        )
        .unwrap()
    }

    fn collect_input_files(project_dir: &Path, globs: &[String]) -> Vec<(String, String)> {
        super::collect_input_files(project_dir, globs).unwrap()
    }

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
            &[],
            &[],
            &["src/**".into()],
            &env,
            "{}",
        );
        let key2 = compute_cache_key(
            dir.path(),
            "echo build",
            &[],
            &[],
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

        let key1 = compute_cache_key(dir.path(), "echo a", &[], &[], &[], &env, "{}");
        let key2 = compute_cache_key(dir.path(), "echo b", &[], &[], &[], &env, "{}");
        assert_ne!(key1, key2);
    }

    #[test]
    fn lpm_json_change_invalidates_cache_with_custom_inputs() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("source.txt"), "source").unwrap();
        fs::write(dir.path().join("lpm.json"), r#"{"tasks":{}}"#).unwrap();
        let env = HashMap::new();
        let inputs = ["source.txt".into()];
        let key1 = compute_cache_key(dir.path(), "build", &[], &[], &inputs, &env, "{}");

        fs::write(
            dir.path().join("lpm.json"),
            r#"{"tasks":{"build":{"dependsOn":["generate"]}}}"#,
        )
        .unwrap();
        let key2 = compute_cache_key(dir.path(), "build", &[], &[], &inputs, &env, "{}");

        assert_ne!(key1, key2);
    }

    #[test]
    fn authoritative_lockfile_change_invalidates_cache_with_custom_inputs() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("source.txt"), "source").unwrap();
        fs::write(dir.path().join("lpm.lock"), "resolution = 1").unwrap();
        let env = HashMap::new();
        let inputs = ["source.txt".into()];
        let key1 = compute_cache_key(dir.path(), "build", &[], &[], &inputs, &env, "{}");

        fs::write(dir.path().join("lpm.lock"), "resolution = 2").unwrap();
        let key2 = compute_cache_key(dir.path(), "build", &[], &[], &inputs, &env, "{}");

        assert_ne!(key1, key2);
    }

    #[test]
    fn derived_binary_lockfile_does_not_duplicate_authoritative_lockfile_identity() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("lpm.lock"), "resolution = 1").unwrap();
        fs::write(dir.path().join("lpm.lockb"), "derived one").unwrap();
        let env = HashMap::new();
        let key1 = compute_cache_key(dir.path(), "build", &[], &[], &[], &env, "{}");

        fs::write(dir.path().join("lpm.lockb"), "derived two").unwrap();
        let key2 = compute_cache_key(dir.path(), "build", &[], &[], &[], &env, "{}");

        assert_eq!(key1, key2);
    }

    #[test]
    fn ecosystem_lockfile_change_invalidates_cache() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("pnpm-lock.yaml"), "version: 1").unwrap();
        let env = HashMap::new();
        let key1 = compute_cache_key(dir.path(), "build", &[], &[], &[], &env, "{}");

        fs::write(dir.path().join("pnpm-lock.yaml"), "version: 2").unwrap();
        let key2 = compute_cache_key(dir.path(), "build", &[], &[], &[], &env, "{}");

        assert_ne!(key1, key2);
    }

    #[test]
    fn different_env_different_key() {
        let dir = tempfile::tempdir().unwrap();
        let mut env1 = HashMap::new();
        env1.insert("NODE_ENV".into(), "development".into());

        let mut env2 = HashMap::new();
        env2.insert("NODE_ENV".into(), "production".into());

        let key1 = compute_cache_key(dir.path(), "echo", &[], &[], &[], &env1, "{}");
        let key2 = compute_cache_key(dir.path(), "echo", &[], &[], &[], &env2, "{}");
        assert_ne!(key1, key2);
    }

    #[test]
    fn environment_hash_framing_distinguishes_embedded_record_text() {
        let dir = tempfile::tempdir().unwrap();
        let one_variable = HashMap::from([("A".into(), "x\nenv:B=y".into())]);
        let two_variables = HashMap::from([("A".into(), "x".into()), ("B".into(), "y".into())]);

        let one_key = compute_cache_key(dir.path(), "build", &[], &[], &[], &one_variable, "{}");
        let two_keys = compute_cache_key(dir.path(), "build", &[], &[], &[], &two_variables, "{}");

        assert_ne!(one_key, two_keys);
    }

    #[test]
    fn file_change_invalidates_cache() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join("src")).unwrap();
        fs::write(dir.path().join("src/index.js"), "v1").unwrap();
        let env = HashMap::new();

        let key1 = compute_cache_key(
            dir.path(),
            "build",
            &[],
            &[],
            &["src/**".into()],
            &env,
            "{}",
        );

        fs::write(dir.path().join("src/index.js"), "v2").unwrap();

        let key2 = compute_cache_key(
            dir.path(),
            "build",
            &[],
            &[],
            &["src/**".into()],
            &env,
            "{}",
        );
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
            &[],
            &[],
            &env,
            r#"{"react":"^19","lodash":"^4"}"#,
        );
        let key2 = compute_cache_key(
            dir.path(),
            "build",
            &[],
            &[],
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

        let key1 = compute_cache_key(
            dir.path(),
            "build",
            &[],
            &[],
            &[],
            &env,
            r#"{"react":"^18"}"#,
        );
        let key2 = compute_cache_key(
            dir.path(),
            "build",
            &[],
            &[],
            &[],
            &env,
            r#"{"react":"^19"}"#,
        );
        assert_ne!(key1, key2);
    }

    #[test]
    fn different_cli_arguments_produce_different_keys() {
        let dir = tempfile::tempdir().unwrap();
        let env = HashMap::new();

        let key1 = compute_cache_key(
            dir.path(),
            "build",
            &["--target".into(), "node".into()],
            &[],
            &[],
            &env,
            "{}",
        );
        let key2 = compute_cache_key(
            dir.path(),
            "build",
            &["--target".into(), "browser".into()],
            &[],
            &[],
            &env,
            "{}",
        );

        assert_ne!(key1, key2);
    }

    #[test]
    fn different_runtime_identities_produce_different_keys() {
        let dir = tempfile::tempdir().unwrap();
        let env = HashMap::new();

        let key1 = compute_cache_key(
            dir.path(),
            "build",
            &[],
            &[("node".into(), "fingerprint-a".into())],
            &[],
            &env,
            "{}",
        );
        let key2 = compute_cache_key(
            dir.path(),
            "build",
            &[],
            &[("node".into(), "fingerprint-b".into())],
            &[],
            &env,
            "{}",
        );

        assert_ne!(key1, key2);
    }

    #[test]
    fn input_hashing_handles_glob_metacharacters_in_project_path() {
        let root = tempfile::tempdir().unwrap();
        let project = root.path().join("project[abc]");
        fs::create_dir_all(project.join("src")).unwrap();
        fs::write(project.join("src/index.js"), "input").unwrap();

        let files = collect_input_files(&project, &["src/**".into()]);

        assert_eq!(files.len(), 1);
        assert_eq!(files[0].0, Path::new("src/index.js").to_string_lossy());
    }

    // -- canonicalize_value sorts keys explicitly --

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

    // -- streaming file hash --

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

    // -- hex encoding --

    #[test]
    fn hex_encode_correct() {
        assert_eq!(hex::encode([0x00, 0xff, 0x0a, 0xab]), "00ff0aab");
        assert_eq!(hex::encode([]), "");
        assert_eq!(hex::encode([0xde, 0xad, 0xbe, 0xef]), "deadbeef");
    }

    /// A regular file under project_dir is accepted by the containment helper.
    #[test]
    fn target_stays_in_project_accepts_regular_file_under_root() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join("src")).unwrap();
        let file = dir.path().join("src/index.js");
        fs::write(&file, "ok").unwrap();
        assert!(target_stays_in_project(&file, dir.path()));
    }

    /// A committed symlink outside the project must not enter the cache key.
    #[cfg(unix)]
    #[test]
    fn target_stays_in_project_rejects_symlink_pointing_outside() {
        let project = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let secret = outside.path().join("secret.env");
        fs::write(&secret, "API_KEY=hunter2").unwrap();

        let link = project.path().join("escape");
        std::os::unix::fs::symlink(&secret, &link).unwrap();

        assert!(
            !target_stays_in_project(&link, project.path()),
            "symlink to a file outside project_dir must be refused"
        );
    }

    /// A broken symlink also fails closed because canonicalization fails.
    /// Without this we'd silently swallow the entry instead of
    /// flagging it.
    #[cfg(unix)]
    #[test]
    fn target_stays_in_project_rejects_broken_symlink() {
        let project = tempfile::tempdir().unwrap();
        let link = project.path().join("dangling");
        std::os::unix::fs::symlink(project.path().join("does-not-exist"), &link).unwrap();
        assert!(!target_stays_in_project(&link, project.path()));
    }
}
