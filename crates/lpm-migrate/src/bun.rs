//! Parser for Bun lockfiles (`bun.lock` JSON and `bun.lockb` binary).

use crate::{
    BoundedMap, MAX_PACKAGES, MigratedPackage, enforce_package_limit, ensure_lockfile_size,
    read_lockfile_snapshot,
};
use lpm_common::LpmError;
use std::collections::HashMap;
use std::io::Write as _;
use std::path::Path;
use std::process::Stdio;
use std::time::{Duration, Instant};

const BUN_CONVERSION_STDERR_LIMIT_BYTES: u64 = 64 * 1024;
const BUN_CONVERSION_TIMEOUT: Duration = Duration::from_secs(30);

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Parse a bun lockfile (either `bun.lock` JSON or `bun.lockb` binary).
pub fn parse(path: &Path) -> Result<Vec<MigratedPackage>, LpmError> {
    parse_with_options(path, true)
}

/// Parse the exact Bun lockfile selected by the caller.
pub fn parse_selected(path: &Path) -> Result<Vec<MigratedPackage>, LpmError> {
    parse_with_options(path, false)
}

fn parse_with_options(
    path: &Path,
    allow_sibling_text_fallback: bool,
) -> Result<Vec<MigratedPackage>, LpmError> {
    let extension = path.extension().and_then(|e| e.to_str()).unwrap_or("");

    match extension {
        "lock" => parse_json_lockfile(path),
        "lockb" => parse_binary_lockfile(path, allow_sibling_text_fallback),
        _ => Err(LpmError::Script(format!(
            "unknown bun lockfile format: {}",
            path.display()
        ))),
    }
}

/// Parse a `bun.lock` (JSON format, Bun v1.2+).
fn parse_json_lockfile(path: &Path) -> Result<Vec<MigratedPackage>, LpmError> {
    let content = read_lockfile_snapshot(path)?;
    parse_json_str(&content)
}

/// Parse bun lockfile JSON from a string (for testing).
pub fn parse_json_str(content: &str) -> Result<Vec<MigratedPackage>, LpmError> {
    #[derive(serde::Deserialize)]
    struct BunLockfile {
        packages: Option<BoundedMap<serde_json::Map<String, serde_json::Value>, MAX_PACKAGES>>,
    }

    let lockfile: BunLockfile = serde_json::from_str(content)
        .map_err(|e| LpmError::Script(format!("failed to parse bun.lock: {e}")))?;

    let packages = lockfile
        .packages
        .as_ref()
        .ok_or_else(|| LpmError::Script("bun.lock has no 'packages' block".to_string()))?;
    enforce_package_limit(packages.len())?;

    // Build name → resolved_version lookup from all packages.
    // Each package entry's arr[0] is "name@version" with the exact resolved version.
    let mut version_lookup: HashMap<String, String> = HashMap::with_capacity(packages.len());
    for (_key, value) in packages.iter() {
        if let Some(arr) = value.as_array()
            && let Some(nv) = arr.first().and_then(|v| v.as_str())
        {
            let (n, v) = split_name_version(nv);
            if !n.is_empty() && !v.is_empty() {
                version_lookup.insert(n, v);
            }
        }
    }

    let mut result = Vec::with_capacity(packages.len());

    for (key, value) in packages.iter() {
        let arr = match value.as_array() {
            Some(a) => a,
            None => {
                tracing::debug!("skipping non-array package entry: {key}");
                continue;
            }
        };

        if arr.is_empty() {
            continue;
        }

        // arr[0] = "name@version"
        // arr[1] = tarball URL (or empty string)
        // arr[2] = integrity hash (or empty string)
        // arr[3] = metadata object (dependencies, optionalDependencies, etc.)
        let name_version = arr[0].as_str().unwrap_or("");
        let (name, version) = split_name_version(name_version);
        if name.is_empty() {
            tracing::debug!("skipping unparseable bun package key: {key}");
            continue;
        }

        let resolved = arr
            .get(1)
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string());

        let integrity = arr
            .get(2)
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string());

        let metadata = arr.get(3);

        // Parse dependencies from metadata, resolving ranges to exact versions
        let mut dependencies =
            extract_deps_from_metadata(metadata, "dependencies", &version_lookup);
        let optional_deps =
            extract_deps_from_metadata(metadata, "optionalDependencies", &version_lookup);

        let is_optional = metadata
            .and_then(|m| m.get("optional"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        let is_dev = metadata
            .and_then(|m| m.get("dev"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        dependencies.extend(optional_deps);

        result.push(MigratedPackage {
            lockfile_key: None,
            name,
            version,
            resolved,
            integrity,
            dependencies,
            is_optional,
            is_dev,
        });
    }

    // Sort for deterministic output
    result.sort_by(|a, b| a.name.cmp(&b.name).then_with(|| a.version.cmp(&b.version)));

    enforce_package_limit(result.len())?;
    Ok(result)
}

/// Handle `bun.lockb` (binary format).
///
/// Strategy:
/// 1. Look for `bun.lock` (JSON) alongside it — if found, parse that instead.
/// 2. Try running `bun bun.lockb` to get a text representation.
/// 3. Fail with a clear error message.
fn parse_binary_lockfile(
    path: &Path,
    allow_sibling_text_fallback: bool,
) -> Result<Vec<MigratedPackage>, LpmError> {
    ensure_lockfile_size(path)?;
    // Try bun.lock (JSON) alongside bun.lockb
    let json_path = path.with_extension("lock");
    if allow_sibling_text_fallback && json_path.exists() {
        tracing::info!(
            "found bun.lock alongside bun.lockb, using JSON format: {}",
            json_path.display()
        );
        return parse_json_lockfile(&json_path);
    }

    let input = lpm_common::read_file_capped(path, crate::FOREIGN_LOCKFILE_SIZE_CAP_BYTES)
        .map_err(|error| {
            LpmError::Script(format!(
                "failed to snapshot Bun lockfile {}: {error}",
                path.display()
            ))
        })?;
    let mut snapshot = tempfile::Builder::new()
        .prefix("lpm-bun-lock-")
        .suffix(".lockb")
        .tempfile()
        .map_err(LpmError::Io)?;
    snapshot.write_all(&input).map_err(LpmError::Io)?;
    snapshot.flush().map_err(LpmError::Io)?;
    drop(input);

    let output = run_bun_converter(snapshot.path(), BUN_CONVERSION_TIMEOUT)?;
    parse_json_str(&output)
}

fn run_bun_converter(path: &Path, timeout: Duration) -> Result<String, LpmError> {
    let mut command = std::process::Command::new("bun");
    command
        .arg(path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt as _;
        command.process_group(0);
    }
    let mut child = command
        .spawn()
        .map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                LpmError::Script(
                    "cannot parse bun.lockb: 'bun' binary not found.\n\
                     Install bun (https://bun.sh) or generate bun.lock with: bun install --save-text-lockfile"
                        .to_string(),
                )
            } else {
                LpmError::Script(format!("failed to start Bun lockfile converter: {error}"))
            }
        })?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| LpmError::Script("Bun converter stdout was not captured".into()))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| LpmError::Script("Bun converter stderr was not captured".into()))?;
    let (sender, receiver) = std::sync::mpsc::channel();
    let stdout_sender = sender.clone();
    let stdout_reader = std::thread::spawn(move || {
        let result = lpm_common::read_stream_capped(stdout, crate::FOREIGN_LOCKFILE_SIZE_CAP_BYTES);
        let _ = stdout_sender.send((true, result));
    });
    let stderr_reader = std::thread::spawn(move || {
        let result = lpm_common::read_stream_capped(stderr, BUN_CONVERSION_STDERR_LIMIT_BYTES);
        let _ = sender.send((false, result));
    });

    let started = Instant::now();
    let mut stdout_result = None;
    let mut stderr_result = None;
    let mut stream_error = None;
    let status = loop {
        while let Ok((is_stdout, result)) = receiver.try_recv() {
            if let Err(error) = &result {
                stream_error = Some((
                    is_stdout,
                    std::io::Error::new(error.kind(), error.to_string()),
                ));
            }
            if is_stdout {
                stdout_result = Some(result);
            } else {
                stderr_result = Some(result);
            }
        }
        if stream_error.is_some() {
            if let Some(status) = child.try_wait().map_err(LpmError::Io)? {
                break status;
            }
            break terminate_bun_converter(&mut child)?;
        }
        if let Some(status) = child.try_wait().map_err(LpmError::Io)? {
            break status;
        }
        if started.elapsed() >= timeout {
            let _ = terminate_bun_converter(&mut child);
            stdout_reader
                .join()
                .map_err(|_| LpmError::Script("Bun converter stdout reader panicked".into()))?;
            stderr_reader
                .join()
                .map_err(|_| LpmError::Script("Bun converter stderr reader panicked".into()))?;
            return Err(LpmError::Script(format!(
                "Bun lockfile conversion timed out after {} seconds",
                timeout.as_secs_f64()
            )));
        }
        std::thread::sleep(Duration::from_millis(10));
    };

    stdout_reader
        .join()
        .map_err(|_| LpmError::Script("Bun converter stdout reader panicked".into()))?;
    stderr_reader
        .join()
        .map_err(|_| LpmError::Script("Bun converter stderr reader panicked".into()))?;
    while let Ok((is_stdout, result)) = receiver.try_recv() {
        if let Err(error) = &result {
            stream_error = Some((
                is_stdout,
                std::io::Error::new(error.kind(), error.to_string()),
            ));
        }
        if is_stdout {
            stdout_result = Some(result);
        } else {
            stderr_result = Some(result);
        }
    }
    if let Some((is_stdout, error)) = stream_error {
        let stream = if is_stdout { "stdout" } else { "stderr" };
        let limit = if is_stdout {
            crate::FOREIGN_LOCKFILE_SIZE_CAP_BYTES
        } else {
            BUN_CONVERSION_STDERR_LIMIT_BYTES
        };
        return Err(LpmError::Script(format!(
            "Bun converter {stream} exceeds the {limit}-byte limit: {error}"
        )));
    }
    let stdout = stdout_result
        .ok_or_else(|| LpmError::Script("Bun converter produced no stdout result".into()))?
        .map_err(|error| {
            LpmError::Script(format!("failed to read Bun converter stdout: {error}"))
        })?;
    let stderr = stderr_result
        .ok_or_else(|| LpmError::Script("Bun converter produced no stderr result".into()))?
        .map_err(|error| {
            LpmError::Script(format!("failed to read Bun converter stderr: {error}"))
        })?;
    if !status.success() {
        return Err(LpmError::Script(format!(
            "bun failed to convert lockfile (exit {status}): {}",
            String::from_utf8_lossy(&stderr)
        )));
    }
    String::from_utf8(stdout)
        .map_err(|error| LpmError::Script(format!("Bun converter output is not UTF-8: {error}")))
}

fn terminate_bun_converter(
    child: &mut std::process::Child,
) -> Result<std::process::ExitStatus, LpmError> {
    #[cfg(unix)]
    unsafe {
        let process_group = i32::try_from(child.id())
            .map_err(|_| LpmError::Script("Bun converter process identifier exceeds i32".into()))?;
        if libc::kill(-process_group, libc::SIGKILL) != 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() != std::io::ErrorKind::NotFound {
                return Err(LpmError::Io(error));
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = child.kill();
    }
    child.wait().map_err(LpmError::Io)
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Split `"name@version"` into `(name, version)`.
///
/// Handles scoped packages: `"@scope/name@1.0.0"` -> `("@scope/name", "1.0.0")`.
/// Finds the last `@` that is not at position 0.
fn split_name_version(s: &str) -> (String, String) {
    let at_pos = s
        .char_indices()
        .rev()
        .find(|&(i, c)| c == '@' && i > 0)
        .map(|(i, _)| i);

    match at_pos {
        Some(pos) => (s[..pos].to_string(), s[pos + 1..].to_string()),
        None => (s.to_string(), String::new()),
    }
}

/// Extract dependency pairs from a metadata object's named field.
///
/// Bun stores dependency ranges (e.g., `"~1.3.8"`) in metadata, not exact versions.
/// The `version_lookup` resolves each dep name to its exact installed version.
fn extract_deps_from_metadata(
    metadata: Option<&serde_json::Value>,
    field: &str,
    version_lookup: &HashMap<String, String>,
) -> Vec<(String, String)> {
    let deps = metadata
        .and_then(|m| m.get(field))
        .and_then(|d| d.as_object());

    match deps {
        Some(obj) => {
            let mut out: Vec<(String, String)> = obj
                .keys()
                .filter_map(|dep_name| {
                    version_lookup
                        .get(dep_name.as_str())
                        .map(|exact_ver| (dep_name.clone(), exact_ver.clone()))
                })
                .collect();
            out.sort_by(|a, b| a.0.cmp(&b.0));
            out
        }
        None => Vec::new(),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    static PATH_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[cfg(unix)]
    struct EnvRestore {
        key: &'static str,
        value: Option<std::ffi::OsString>,
    }

    #[cfg(unix)]
    impl Drop for EnvRestore {
        fn drop(&mut self) {
            match self.value.take() {
                Some(value) => unsafe { std::env::set_var(self.key, value) },
                None => unsafe { std::env::remove_var(self.key) },
            }
        }
    }

    #[cfg(unix)]
    fn with_fake_bun<T>(script: &str, test: impl FnOnce() -> T) -> T {
        use std::os::unix::fs::PermissionsExt as _;

        let _lock = PATH_LOCK.lock().unwrap();
        let directory = tempfile::tempdir().unwrap();
        let executable = directory.path().join("bun");
        std::fs::write(&executable, script).unwrap();
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).unwrap();
        let old_path = std::env::var_os("PATH");
        let mut paths = vec![directory.path().to_path_buf()];
        if let Some(path) = old_path.as_deref() {
            paths.extend(std::env::split_paths(path));
        }
        let path = std::env::join_paths(paths).unwrap();
        unsafe { std::env::set_var("PATH", path) };
        let _restore = EnvRestore {
            key: "PATH",
            value: old_path,
        };
        test()
    }

    fn sample_json() -> &'static str {
        r#"{
  "lockfileVersion": 0,
  "workspaces": {
    "": {
      "name": "my-project",
      "dependencies": {
        "express": "^4.22.0"
      }
    }
  },
  "packages": {
    "express": ["express@4.22.1", "https://registry.npmjs.org/express/-/express-4.22.1.tgz", "sha512-abc123", { "dependencies": { "accepts": "~1.3.8" } }],
    "accepts": ["accepts@1.3.8", "https://registry.npmjs.org/accepts/-/accepts-1.3.8.tgz", "sha512-xyz789", { "dependencies": { "mime-types": "~2.1.34" } }],
    "mime-types": ["mime-types@2.1.35", "https://registry.npmjs.org/mime-types/-/mime-types-2.1.35.tgz", "sha512-mime", {}]
  }
}"#
    }

    #[test]
    fn parse_json_simple() {
        let packages = parse_json_str(sample_json()).unwrap();
        assert_eq!(packages.len(), 3);

        let express = packages.iter().find(|p| p.name == "express").unwrap();
        assert_eq!(express.version, "4.22.1");
    }

    #[test]
    fn parse_json_with_deps() {
        let packages = parse_json_str(sample_json()).unwrap();
        let express = packages.iter().find(|p| p.name == "express").unwrap();
        assert_eq!(express.dependencies.len(), 1);
        assert_eq!(
            express.dependencies[0],
            ("accepts".to_string(), "1.3.8".to_string())
        );

        let accepts = packages.iter().find(|p| p.name == "accepts").unwrap();
        assert_eq!(accepts.dependencies.len(), 1);
        assert_eq!(
            accepts.dependencies[0],
            ("mime-types".to_string(), "2.1.35".to_string())
        );
    }

    #[test]
    fn parse_json_scoped() {
        let json = r#"{
  "lockfileVersion": 0,
  "packages": {
    "@babel/core": ["@babel/core@7.24.0", "https://registry.npmjs.org/@babel/core/-/core-7.24.0.tgz", "sha512-babel", {}],
    "@types/node": ["@types/node@20.11.0", "", "sha512-types", {}]
  }
}"#;
        let packages = parse_json_str(json).unwrap();
        assert_eq!(packages.len(), 2);

        let babel = packages.iter().find(|p| p.name == "@babel/core").unwrap();
        assert_eq!(babel.version, "7.24.0");
        assert_eq!(
            babel.resolved.as_deref(),
            Some("https://registry.npmjs.org/@babel/core/-/core-7.24.0.tgz")
        );

        let types = packages.iter().find(|p| p.name == "@types/node").unwrap();
        assert_eq!(types.version, "20.11.0");
        // Empty string resolved should become None
        assert!(types.resolved.is_none());
    }

    #[test]
    fn parse_preserves_integrity() {
        let packages = parse_json_str(sample_json()).unwrap();
        let express = packages.iter().find(|p| p.name == "express").unwrap();
        assert_eq!(express.integrity.as_deref(), Some("sha512-abc123"));

        let accepts = packages.iter().find(|p| p.name == "accepts").unwrap();
        assert_eq!(accepts.integrity.as_deref(), Some("sha512-xyz789"));
    }

    #[test]
    fn parse_empty_packages() {
        let json = r#"{"lockfileVersion": 0, "packages": {}}"#;
        let packages = parse_json_str(json).unwrap();
        assert!(packages.is_empty());
    }

    #[test]
    fn parse_optional_and_dev() {
        let json = r#"{
  "lockfileVersion": 0,
  "packages": {
    "fsevents": ["fsevents@2.3.3", "", "sha512-fs", { "optional": true }],
    "eslint": ["eslint@8.57.0", "", "sha512-lint", { "dev": true }]
  }
}"#;
        let packages = parse_json_str(json).unwrap();

        let fse = packages.iter().find(|p| p.name == "fsevents").unwrap();
        assert!(fse.is_optional);
        assert!(!fse.is_dev);

        let eslint = packages.iter().find(|p| p.name == "eslint").unwrap();
        assert!(eslint.is_dev);
        assert!(!eslint.is_optional);
    }

    #[test]
    fn split_name_version_regular() {
        let (name, ver) = split_name_version("express@4.22.1");
        assert_eq!(name, "express");
        assert_eq!(ver, "4.22.1");
    }

    #[test]
    fn split_name_version_scoped() {
        let (name, ver) = split_name_version("@babel/core@7.24.0");
        assert_eq!(name, "@babel/core");
        assert_eq!(ver, "7.24.0");
    }

    #[test]
    fn split_name_version_no_version() {
        let (name, ver) = split_name_version("express");
        assert_eq!(name, "express");
        assert_eq!(ver, "");
    }

    #[test]
    fn binary_fallback_to_json() {
        // Create a temp directory with both bun.lockb and bun.lock
        let dir = tempfile::tempdir().unwrap();
        let lockb_path = dir.path().join("bun.lockb");
        let lock_path = dir.path().join("bun.lock");

        // Write dummy binary file
        std::fs::write(&lockb_path, b"\x00\x01\x02").unwrap();

        // Write valid JSON lockfile
        std::fs::write(
            &lock_path,
            r#"{
  "lockfileVersion": 0,
  "packages": {
    "lodash": ["lodash@4.17.21", "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz", "sha512-lodash", {}]
  }
}"#,
        )
        .unwrap();

        let packages = parse(&lockb_path).unwrap();
        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].name, "lodash");
        assert_eq!(packages[0].version, "4.17.21");
    }

    #[test]
    fn binary_missing_bun_errors() {
        // Create a temp directory with only bun.lockb (no bun.lock, no bun binary)
        let dir = tempfile::tempdir().unwrap();
        let lockb_path = dir.path().join("bun.lockb");
        std::fs::write(&lockb_path, b"\x00\x01\x02").unwrap();

        let result = parse(&lockb_path);
        // This will either fail because bun isn't installed or succeed if it is.
        // On most CI/dev machines without bun, it should error.
        // We just verify it doesn't panic.
        if let Err(e) = result {
            let msg = format!("{e}");
            assert!(
                msg.contains("bun") || msg.contains("parse"),
                "error should mention bun: {msg}"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn binary_converter_output_is_capped() {
        with_fake_bun(
            "#!/bin/sh\ndd if=/dev/zero bs=1024 count=65537 2>/dev/null\n",
            || {
                let dir = tempfile::tempdir().unwrap();
                let path = dir.path().join("bun.lockb");
                std::fs::write(&path, b"bounded input").unwrap();

                let error = parse_selected(&path).unwrap_err();

                assert!(error.to_string().contains("67108864-byte limit"));
            },
        );
    }

    #[cfg(unix)]
    #[test]
    fn binary_converter_stderr_is_capped() {
        with_fake_bun(
            "#!/bin/sh\ndd if=/dev/zero bs=1024 count=65 1>&2\nprintf '{\"packages\":{}}'\n",
            || {
                let dir = tempfile::tempdir().unwrap();
                let path = dir.path().join("bun.lockb");
                std::fs::write(&path, b"bounded input").unwrap();

                let error = parse_selected(&path).unwrap_err();

                assert!(
                    error
                        .to_string()
                        .contains("stderr exceeds the 65536-byte limit"),
                    "unexpected converter error: {error}"
                );
            },
        );
    }

    #[cfg(unix)]
    #[test]
    fn binary_converter_execution_is_bounded() {
        with_fake_bun("#!/bin/sh\nsleep 2\nprintf '{\"packages\":{}}'\n", || {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("bun.lockb");
            std::fs::write(&path, b"bounded input").unwrap();

            let error = run_bun_converter(&path, Duration::from_millis(500)).unwrap_err();

            assert!(error.to_string().contains("timed out after 0.5 seconds"));
        });
    }

    #[cfg(unix)]
    #[test]
    fn binary_converter_reads_the_bounded_immutable_snapshot() {
        with_fake_bun(
            "#!/bin/sh\nprintf ready > \"$BUN_TEST_MARKER\"\nwhile [ ! -e \"$BUN_TEST_RESUME\" ]; do sleep 0.01; done\ncat \"$1\"\n",
            || {
                let dir = tempfile::tempdir().unwrap();
                let path = dir.path().join("bun.lockb");
                let marker = dir.path().join("converter-ready");
                let resume = dir.path().join("converter-resume");
                std::fs::write(
                    &path,
                    br#"{"packages":{"before":["before@1.0.0","","",{}]}}"#,
                )
                .unwrap();
                let marker_restore = EnvRestore {
                    key: "BUN_TEST_MARKER",
                    value: std::env::var_os("BUN_TEST_MARKER"),
                };
                let resume_restore = EnvRestore {
                    key: "BUN_TEST_RESUME",
                    value: std::env::var_os("BUN_TEST_RESUME"),
                };
                unsafe {
                    std::env::set_var("BUN_TEST_MARKER", &marker);
                    std::env::set_var("BUN_TEST_RESUME", &resume);
                }
                let parsed_path = path.clone();
                let parser = std::thread::spawn(move || parse_selected(&parsed_path));
                let deadline = Instant::now() + Duration::from_secs(15);
                while !marker.exists() && !parser.is_finished() && Instant::now() < deadline {
                    std::thread::sleep(Duration::from_millis(10));
                }
                assert!(marker.exists(), "fake Bun converter did not start");
                std::fs::write(&path, br#"{"packages":{"after":["after@2.0.0","","",{}]}}"#)
                    .unwrap();
                std::fs::write(&resume, b"resume").unwrap();

                let packages = parser.join().unwrap().unwrap();

                drop(resume_restore);
                drop(marker_restore);
                assert_eq!(packages.len(), 1);
                assert_eq!(packages[0].name, "before");
                assert_eq!(packages[0].version, "1.0.0");
            },
        );
    }

    #[test]
    fn parse_missing_packages_errors() {
        let json = r#"{"lockfileVersion": 0}"#;
        let result = parse_json_str(json);
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(msg.contains("packages"));
    }

    #[test]
    fn deps_resolve_to_exact_versions_not_ranges() {
        // Deps should have exact versions, not semver ranges
        let json = r#"{
  "lockfileVersion": 0,
  "packages": {
    "express": ["express@4.22.1", "https://registry.npmjs.org/express/-/express-4.22.1.tgz", "sha512-abc", { "dependencies": { "accepts": "~1.3.8" } }],
    "accepts": ["accepts@1.3.8", "https://registry.npmjs.org/accepts/-/accepts-1.3.8.tgz", "sha512-xyz", {}]
  }
}"#;
        let packages = parse_json_str(json).unwrap();
        let express = packages.iter().find(|p| p.name == "express").unwrap();
        assert_eq!(express.dependencies.len(), 1);
        assert_eq!(
            express.dependencies[0],
            ("accepts".to_string(), "1.3.8".to_string()),
            "dependency version should be exact (1.3.8), not a range (~1.3.8)"
        );
    }

    #[test]
    fn parse_with_optional_deps_in_metadata() {
        let json = r#"{
  "lockfileVersion": 0,
  "packages": {
    "sharp": ["sharp@0.33.0", "", "sha512-sharp", {
      "dependencies": { "color": "^4.0.0" },
      "optionalDependencies": { "@img/sharp-darwin-arm64": "0.33.0" }
    }],
    "color": ["color@4.2.3", "", "sha512-color", {}],
    "@img/sharp-darwin-arm64": ["@img/sharp-darwin-arm64@0.33.0", "", "sha512-img", {}]
  }
}"#;
        let packages = parse_json_str(json).unwrap();
        let sharp = packages.iter().find(|p| p.name == "sharp").unwrap();
        assert_eq!(sharp.dependencies.len(), 2);
        assert!(
            sharp
                .dependencies
                .iter()
                .any(|(n, v)| n == "@img/sharp-darwin-arm64" && v == "0.33.0")
        );
        assert!(
            sharp
                .dependencies
                .iter()
                .any(|(n, v)| n == "color" && v == "4.2.3")
        );
    }

    #[test]
    fn package_map_limit_is_enforced_before_the_overflow_value_is_decoded() {
        use std::fmt::Write as _;

        let mut lockfile = String::with_capacity(crate::MAX_PACKAGES * 16);
        lockfile.push_str(r#"{"lockfileVersion":0,"packages":{"#);
        for index in 0..crate::MAX_PACKAGES {
            write!(lockfile, r#""p{index}":null,"#).unwrap();
        }
        lockfile.push_str(r#""overflow":["#);

        let error = parse_json_str(&lockfile).unwrap_err();

        assert!(error.to_string().contains("package map exceeds"));
    }
}
