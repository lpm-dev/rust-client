//! Loader for per-project sandbox configuration: the
//! `package.json > lpm > scripts > sandboxWriteDirs` escape hatch
//! (§9.6).
//!
//! This is the ONE place the shape of that key is read from disk.
//! `execute_script` calls [`load_sandbox_write_dirs`] once per
//! install and threads the resolved absolute paths into every
//! per-package [`crate::SandboxSpec`].

use crate::SandboxError;
use std::path::{Path, PathBuf};

/// Read `package.json > lpm > scripts > sandboxWriteDirs` and return
/// the resolved absolute paths.
///
/// Resolution rules:
/// - Missing `package.json`, missing `lpm` section, missing `scripts`
///   key, or missing `sandboxWriteDirs` array: return an empty `Vec`
///   — the absence of the key means "no extras", not an error.
/// - The key must be a JSON array of strings. A non-array value or
///   non-string element surfaces as [`SandboxError::InvalidSpec`] so
///   the user sees a clear typo-level error rather than a silent
///   ignore.
/// - Each string entry: if absolute, kept verbatim; if relative,
///   joined onto `project_dir`. The result is always absolute so
///   downstream backends can render it without further context.
/// - Empty strings are rejected: they would resolve to `project_dir`
///   itself, which is already covered by the read allow-list and
///   would silently widen the write set to the entire project tree.
pub fn load_sandbox_write_dirs(
    package_json: &Path,
    project_dir: &Path,
) -> Result<Vec<PathBuf>, SandboxError> {
    let raw = match std::fs::read_to_string(package_json) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => {
            return Err(SandboxError::InvalidSpec {
                reason: format!("failed to read {}: {e}", package_json.display()),
            });
        }
    };

    let json: serde_json::Value =
        serde_json::from_str(&raw).map_err(|e| SandboxError::InvalidSpec {
            reason: format!("{} is not valid JSON: {e}", package_json.display()),
        })?;

    let entries = match json
        .get("lpm")
        .and_then(|v| v.get("scripts"))
        .and_then(|v| v.get("sandboxWriteDirs"))
    {
        Some(v) => v,
        None => return Ok(Vec::new()),
    };

    let arr = entries
        .as_array()
        .ok_or_else(|| SandboxError::InvalidSpec {
            reason: format!(
                "{}: `lpm.scripts.sandboxWriteDirs` must be an array of strings, got {}",
                package_json.display(),
                entries
            ),
        })?;

    let mut resolved = Vec::with_capacity(arr.len());
    for (i, item) in arr.iter().enumerate() {
        let s = item.as_str().ok_or_else(|| SandboxError::InvalidSpec {
            reason: format!(
                "{}: `lpm.scripts.sandboxWriteDirs[{i}]` must be a string, got {}",
                package_json.display(),
                item
            ),
        })?;
        if s.is_empty() {
            return Err(SandboxError::InvalidSpec {
                reason: format!(
                    "{}: `lpm.scripts.sandboxWriteDirs[{i}]` is empty; an empty entry \
                     would widen writes to the whole project",
                    package_json.display(),
                ),
            });
        }
        let p = PathBuf::from(s);
        let absolute = if p.is_absolute() {
            p
        } else {
            project_dir.join(p)
        };
        resolved.push(absolute);
    }

    Ok(resolved)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    struct Env {
        _tmp: tempfile::TempDir,
        project: PathBuf,
        package_json: PathBuf,
    }

    fn fixture(package_json_body: &str) -> Env {
        let tmp = tempfile::tempdir().expect("tempdir");
        let project = tmp.path().to_path_buf();
        let package_json = project.join("package.json");
        fs::write(&package_json, package_json_body).expect("write package.json");
        Env {
            _tmp: tmp,
            project,
            package_json,
        }
    }

    #[test]
    fn missing_package_json_returns_empty() {
        let tmp = tempfile::tempdir().unwrap();
        let project = tmp.path().to_path_buf();
        let nonexistent = project.join("package.json");
        let v = load_sandbox_write_dirs(&nonexistent, &project).unwrap();
        assert!(v.is_empty());
    }

    #[test]
    fn package_json_without_lpm_section_returns_empty() {
        let e = fixture(r#"{"name":"x","version":"1.0.0"}"#);
        let v = load_sandbox_write_dirs(&e.package_json, &e.project).unwrap();
        assert!(v.is_empty());
    }

    #[test]
    fn package_json_without_sandbox_write_dirs_returns_empty() {
        let e = fixture(r#"{"lpm":{"scripts":{"autoBuild":true}}}"#);
        let v = load_sandbox_write_dirs(&e.package_json, &e.project).unwrap();
        assert!(v.is_empty());
    }

    #[test]
    fn absolute_entry_kept_verbatim() {
        let e =
            fixture(r#"{"lpm":{"scripts":{"sandboxWriteDirs":["/home/u/.cache/ms-playwright"]}}}"#);
        let v = load_sandbox_write_dirs(&e.package_json, &e.project).unwrap();
        assert_eq!(v.len(), 1);
        assert_eq!(v[0], PathBuf::from("/home/u/.cache/ms-playwright"));
    }

    #[test]
    fn relative_entry_joined_to_project_dir() {
        let e = fixture(r#"{"lpm":{"scripts":{"sandboxWriteDirs":["build-output"]}}}"#);
        let v = load_sandbox_write_dirs(&e.package_json, &e.project).unwrap();
        assert_eq!(v.len(), 1);
        assert_eq!(v[0], e.project.join("build-output"));
        assert!(v[0].is_absolute());
    }

    #[test]
    fn multiple_entries_preserved_in_order() {
        let e = fixture(
            r#"{"lpm":{"scripts":{"sandboxWriteDirs":["/abs/one","rel-two","/abs/three"]}}}"#,
        );
        let v = load_sandbox_write_dirs(&e.package_json, &e.project).unwrap();
        assert_eq!(v.len(), 3);
        assert_eq!(v[0], PathBuf::from("/abs/one"));
        assert_eq!(v[1], e.project.join("rel-two"));
        assert_eq!(v[2], PathBuf::from("/abs/three"));
    }

    #[test]
    fn non_array_value_errors_with_actionable_message() {
        let e = fixture(r#"{"lpm":{"scripts":{"sandboxWriteDirs":"not-an-array"}}}"#);
        match load_sandbox_write_dirs(&e.package_json, &e.project) {
            Err(SandboxError::InvalidSpec { reason }) => {
                assert!(reason.contains("sandboxWriteDirs"));
                assert!(reason.contains("array"));
            }
            other => panic!("expected InvalidSpec, got {other:?}"),
        }
    }

    #[test]
    fn non_string_element_errors_with_index() {
        let e = fixture(r#"{"lpm":{"scripts":{"sandboxWriteDirs":["ok",42]}}}"#);
        match load_sandbox_write_dirs(&e.package_json, &e.project) {
            Err(SandboxError::InvalidSpec { reason }) => {
                assert!(reason.contains("sandboxWriteDirs[1]"));
                assert!(reason.contains("string"));
            }
            other => panic!("expected InvalidSpec, got {other:?}"),
        }
    }

    #[test]
    fn empty_string_entry_rejected_because_it_widens_project_wide() {
        let e = fixture(r#"{"lpm":{"scripts":{"sandboxWriteDirs":[""]}}}"#);
        match load_sandbox_write_dirs(&e.package_json, &e.project) {
            Err(SandboxError::InvalidSpec { reason }) => {
                assert!(reason.contains("empty"));
                assert!(reason.contains("widen"));
            }
            other => panic!("expected InvalidSpec, got {other:?}"),
        }
    }

    #[test]
    fn malformed_json_surfaces_as_invalid_spec() {
        let e = fixture(r#"{"lpm": INVALID"#);
        match load_sandbox_write_dirs(&e.package_json, &e.project) {
            Err(SandboxError::InvalidSpec { reason }) => {
                assert!(reason.contains("not valid JSON"));
            }
            other => panic!("expected InvalidSpec, got {other:?}"),
        }
    }
}
