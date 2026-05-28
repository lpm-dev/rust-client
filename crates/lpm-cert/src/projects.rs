//! Per-machine index of projects whose `ensure_https` has been run.
//!
//! `~/.lpm/cert-projects.json` lets `lpm cert rotate` enumerate the leaves it needs
//! to reissue when the root CA changes. Without an index, rotation could only act on
//! projects the caller passes explicitly via `--project`, and any out-of-tree project
//! checkout would silently keep a leaf chained to the dead old CA.

use crate::paths;
use lpm_common::LpmError;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct IndexFile {
    /// Absolute paths of project directories where `ensure_https` succeeded.
    projects: BTreeSet<String>,
}

/// Path to the projects index file: `~/.lpm/cert-projects.json` (overridable via
/// `LPM_CERT_PROJECTS_INDEX` for tests).
pub fn index_path() -> Result<PathBuf, LpmError> {
    if let Some(p) = std::env::var_os("LPM_CERT_PROJECTS_INDEX") {
        return Ok(PathBuf::from(p));
    }
    let home = dirs::home_dir()
        .ok_or_else(|| LpmError::Cert("could not determine home dir for projects index".into()))?;
    Ok(home.join(".lpm").join("cert-projects.json"))
}

fn read_index() -> Result<IndexFile, LpmError> {
    let path = index_path()?;
    if !path.exists() {
        return Ok(IndexFile::default());
    }
    let bytes = std::fs::read(&path)
        .map_err(|e| LpmError::Cert(format!("failed to read projects index: {e}")))?;
    if bytes.is_empty() {
        return Ok(IndexFile::default());
    }
    serde_json::from_slice(&bytes)
        .map_err(|e| LpmError::Cert(format!("failed to parse projects index: {e}")))
}

fn write_index(idx: &IndexFile) -> Result<(), LpmError> {
    let path = index_path()?;
    if let Some(parent) = path.parent() {
        crate::create_dir_secure(parent)
            .map_err(|e| LpmError::Cert(format!("failed to create projects-index dir: {e}")))?;
    }
    let serialized = serde_json::to_vec_pretty(idx)
        .map_err(|e| LpmError::Cert(format!("failed to serialize projects index: {e}")))?;
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, &serialized)
        .map_err(|e| LpmError::Cert(format!("failed to write projects-index temp: {e}")))?;
    std::fs::rename(&tmp, &path)
        .map_err(|e| LpmError::Cert(format!("failed to promote projects index: {e}")))?;
    Ok(())
}

/// Record `project_dir` as a project we've issued a leaf for. Idempotent.
pub fn record(project_dir: &Path) -> Result<(), LpmError> {
    let canonical = canonicalize_or_keep(project_dir);
    let mut idx = read_index()?;
    idx.projects.insert(canonical);
    write_index(&idx)
}

/// Remove a project from the index, e.g. when its directory has been deleted.
pub fn forget(project_dir: &Path) -> Result<(), LpmError> {
    let canonical = canonicalize_or_keep(project_dir);
    let mut idx = read_index()?;
    if idx.projects.remove(&canonical) {
        write_index(&idx)?;
    }
    Ok(())
}

/// Every project path the index currently knows about, in stable order.
pub fn list() -> Result<Vec<PathBuf>, LpmError> {
    let idx = read_index()?;
    Ok(idx.projects.into_iter().map(PathBuf::from).collect())
}

fn canonicalize_or_keep(p: &Path) -> String {
    p.canonicalize()
        .unwrap_or_else(|_| p.to_path_buf())
        .to_string_lossy()
        .into_owned()
}

/// True iff a project's local CA-issued leaf currently exists on disk.
pub fn project_has_leaf(project_dir: &Path) -> bool {
    paths::project_cert_dir(project_dir).is_ok_and(|d| d.join("cert.pem").exists())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn with_index<T>(f: impl FnOnce(&Path) -> T) -> T {
        let _serial = serial_lock();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cert-projects.json");
        let _g = EnvGuard::set("LPM_CERT_PROJECTS_INDEX", &path);
        f(dir.path())
    }

    #[test]
    fn record_and_list_roundtrip() {
        with_index(|root| {
            let p = root.join("project-a");
            std::fs::create_dir_all(&p).unwrap();
            record(&p).unwrap();
            let entries = list().unwrap();
            assert_eq!(entries.len(), 1);
            assert!(entries[0].ends_with("project-a"));
        });
    }

    #[test]
    fn record_is_idempotent() {
        with_index(|root| {
            let p = root.join("project-a");
            std::fs::create_dir_all(&p).unwrap();
            record(&p).unwrap();
            record(&p).unwrap();
            assert_eq!(list().unwrap().len(), 1);
        });
    }

    #[test]
    fn forget_removes_project() {
        with_index(|root| {
            let p = root.join("project-a");
            std::fs::create_dir_all(&p).unwrap();
            record(&p).unwrap();
            forget(&p).unwrap();
            assert!(list().unwrap().is_empty());
        });
    }

    #[test]
    fn list_returns_stable_order() {
        with_index(|root| {
            for name in ["c", "a", "b"] {
                let p = root.join(name);
                std::fs::create_dir_all(&p).unwrap();
                record(&p).unwrap();
            }
            let entries = list().unwrap();
            assert_eq!(entries.len(), 3);
            let ends: Vec<String> = entries
                .iter()
                .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
                .collect();
            assert!(ends == vec!["a", "b", "c"], "expected sorted, got {ends:?}");
        });
    }

    #[test]
    fn list_missing_file_returns_empty() {
        with_index(|_root| {
            assert!(list().unwrap().is_empty());
        });
    }

    fn serial_lock() -> std::sync::MutexGuard<'static, ()> {
        use std::sync::{Mutex, OnceLock};
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|p| p.into_inner())
    }

    struct EnvGuard {
        key: &'static str,
        prev: Option<std::ffi::OsString>,
    }
    impl EnvGuard {
        fn set<P: AsRef<std::ffi::OsStr>>(key: &'static str, value: P) -> Self {
            let prev = std::env::var_os(key);
            unsafe { std::env::set_var(key, value) };
            Self { key, prev }
        }
    }
    impl Drop for EnvGuard {
        fn drop(&mut self) {
            unsafe {
                match self.prev.take() {
                    Some(v) => std::env::set_var(self.key, v),
                    None => std::env::remove_var(self.key),
                }
            }
        }
    }
}
