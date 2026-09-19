//! Bounded compiler discovery shared by type checking and doctor.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// State of TypeScript for a single tsconfig-owning directory.
pub struct TscStatus {
    /// Path to `tsc` resolved via the local `node_modules/.bin` chain
    /// when run from the probe directory. `Some` is the healthy case —
    /// editor (`tsserver` from `node_modules/typescript`) and CI agree.
    pub local_bin: Option<PathBuf>,

    /// Path to a non-local `tsc` reachable via the system `PATH`.
    /// Populated only when `local_bin` is `None`. When this is `Some`
    /// and `local_bin` is `None`, `lpm check` will succeed but the
    /// editor (which uses workspace `node_modules/typescript`) and CI
    /// may run a different version.
    pub system_bin: Option<PathBuf>,

    /// `typescript` is declared in `dependencies`, `devDependencies`,
    /// `peerDependencies`, or `optionalDependencies` of the manifest at
    /// `dir/package.json` OR — when `dir` is a workspace member — the
    /// workspace root manifest (covers monorepos that hoist `typescript`
    /// to the root only).
    pub in_deps: bool,
}

impl TscStatus {
    #[cfg(test)]
    pub fn probe(dir: &Path) -> Self {
        Self::probe_bounded(dir, &project_boundary(dir))
    }

    pub(crate) fn probe_bounded(dir: &Path, boundary: &Path) -> Self {
        let local_bin =
            lpm_runner::script::resolve_local_bin_path_bounded(dir, boundary, "tsc").ok();
        let system_bin = if local_bin.is_some() {
            None
        } else {
            SystemTscResolver::new().find(dir)
        };
        let in_deps = typescript_declared_in_reachable_manifest(dir, boundary);
        Self {
            local_bin,
            system_bin,
            in_deps,
        }
    }

    #[cfg(test)]
    pub(crate) fn probe_with_snapshot(
        dir: &Path,
        system_bin: Option<&Path>,
        in_deps: bool,
    ) -> Self {
        Self::probe_with_local_snapshot(find_local_tsc(dir), system_bin, in_deps)
    }

    pub(crate) fn probe_with_local_snapshot(
        local_bin: Option<PathBuf>,
        system_bin: Option<&Path>,
        in_deps: bool,
    ) -> Self {
        let system_bin = local_bin
            .is_none()
            .then(|| system_bin.map(Path::to_path_buf))
            .flatten();
        Self {
            local_bin,
            system_bin,
            in_deps,
        }
    }

    /// Some `tsc` is reachable, even if only via system `PATH`.
    #[cfg(test)]
    pub fn runnable(&self) -> bool {
        self.local_bin.is_some() || self.system_bin.is_some()
    }
}

fn project_boundary(dir: &Path) -> PathBuf {
    lpm_workspace::find_workspace_root(dir)
        .ok()
        .flatten()
        .or_else(|| lpm_workspace::find_project_root(dir))
        .unwrap_or_else(|| dir.to_path_buf())
}

#[cfg(test)]
fn find_local_tsc(dir: &Path) -> Option<PathBuf> {
    lpm_runner::script::resolve_local_bin_path_bounded(dir, &project_boundary(dir), "tsc").ok()
}

pub(crate) struct LocalTscResolver {
    boundary: PathBuf,
    by_directory: HashMap<PathBuf, Option<PathBuf>>,
}

impl LocalTscResolver {
    pub(crate) fn new(dir: &Path) -> Self {
        Self {
            boundary: project_boundary(dir),
            by_directory: HashMap::new(),
        }
    }

    pub(crate) fn find(&mut self, dir: &Path) -> Option<PathBuf> {
        let mut visited = Vec::new();
        let mut current = Some(dir);
        let found = loop {
            let Some(directory) = current else {
                break None;
            };
            if !directory.starts_with(&self.boundary) {
                break None;
            }
            if let Some(cached) = self.by_directory.get(directory) {
                break cached.clone();
            }
            visited.push(directory.to_path_buf());
            if let Ok(path) =
                lpm_runner::script::resolve_local_bin_path_bounded(directory, directory, "tsc")
            {
                break Some(path);
            }
            if directory == self.boundary {
                break None;
            }
            current = directory.parent();
        };
        for directory in visited {
            self.by_directory.insert(directory, found.clone());
        }
        found
    }
}

enum SystemPathEntry {
    Absolute(PathBuf),
    Relative(PathBuf),
}

pub(crate) struct SystemTscResolver {
    entries: Vec<SystemPathEntry>,
}

impl SystemTscResolver {
    pub(crate) fn new() -> Self {
        let entries = std::env::var_os("PATH")
            .map(|path| {
                std::env::split_paths(&path)
                    .filter_map(|dir| {
                        if dir.is_absolute() {
                            find_tsc_in_directory(&dir, cfg!(windows))
                                .map(SystemPathEntry::Absolute)
                        } else {
                            Some(SystemPathEntry::Relative(dir))
                        }
                    })
                    .collect()
            })
            .unwrap_or_default();
        Self { entries }
    }

    pub(crate) fn find(&self, cwd: &Path) -> Option<PathBuf> {
        let cwd = std::path::absolute(cwd).ok()?;
        self.entries.iter().find_map(|entry| match entry {
            SystemPathEntry::Absolute(path) => Some(path.clone()),
            SystemPathEntry::Relative(dir) => find_tsc_in_directory(&cwd.join(dir), cfg!(windows)),
        })
    }
}

fn find_tsc_in_directory(dir: &Path, windows: bool) -> Option<PathBuf> {
    let names: &[&str] = if windows {
        &["tsc.cmd", "tsc.exe", "tsc.bat", "tsc"]
    } else {
        &["tsc"]
    };
    for name in names {
        let candidate = dir.join(name);
        let Ok(metadata) = candidate.metadata() else {
            continue;
        };
        if !metadata.is_file() {
            continue;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o111 == 0 {
                continue;
            }
        }
        return Some(candidate);
    }
    None
}

#[cfg(test)]
fn tsc_filename() -> &'static str {
    if cfg!(windows) { "tsc.cmd" } else { "tsc" }
}

/// True when `typescript` appears in any dep map of `dir/package.json`
/// or any ancestor's `package.json`. Captures the common monorepo
/// shape where `typescript` is hoisted to the root manifest only.
fn typescript_declared_in_reachable_manifest(dir: &Path, boundary: &Path) -> bool {
    let mut current = dir.to_path_buf();
    loop {
        let pkg_json_path = current.join("package.json");
        if pkg_json_path.is_file()
            && let Ok(pkg) = lpm_workspace::read_package_json(&pkg_json_path)
            && manifest_declares_typescript(&pkg)
        {
            return true;
        }
        if current == boundary || !current.pop() {
            return false;
        }
    }
}

pub(crate) fn manifest_declares_typescript(pkg: &lpm_workspace::PackageJson) -> bool {
    pkg.dependencies.contains_key("typescript")
        || pkg.dev_dependencies.contains_key("typescript")
        || pkg.peer_dependencies.contains_key("typescript")
        || pkg.optional_dependencies.contains_key("typescript")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn write_pkg(dir: &Path, body: &str) {
        fs::write(dir.join("package.json"), body).unwrap();
    }

    fn make_local_tsc(dir: &Path) -> PathBuf {
        let bin = dir.join("node_modules").join(".bin");
        fs::create_dir_all(&bin).unwrap();
        let tsc = bin.join(tsc_filename());
        fs::write(&tsc, b"#!/bin/sh\nexit 0\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(&tsc).unwrap().permissions();
            perms.set_mode(0o755);
            fs::set_permissions(&tsc, perms).unwrap();
        }
        tsc
    }

    #[test]
    fn system_compiler_lookup_accepts_a_windows_executable_without_a_cmd_sibling() {
        let temp = TempDir::new().unwrap();
        let executable = temp.path().join("tsc.exe");
        fs::write(&executable, b"native compiler fixture").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&executable, fs::Permissions::from_mode(0o755)).unwrap();
        }
        assert_eq!(find_tsc_in_directory(temp.path(), true), Some(executable));
    }

    #[test]
    fn local_bin_at_project_root_is_picked_up() {
        let tmp = TempDir::new().unwrap();
        write_pkg(
            tmp.path(),
            r#"{"name":"x","devDependencies":{"typescript":"^5"}}"#,
        );
        make_local_tsc(tmp.path());

        let status = TscStatus::probe(tmp.path());
        assert!(status.local_bin.is_some(), "expected local bin to resolve");
        assert!(status.runnable());
        assert!(status.in_deps);
    }

    #[test]
    fn local_bin_walks_up_from_member_directory() {
        let tmp = TempDir::new().unwrap();
        write_pkg(
            tmp.path(),
            r#"{"name":"root","workspaces":["packages/*"],"devDependencies":{"typescript":"^5"}}"#,
        );
        make_local_tsc(tmp.path());

        let member_dir = tmp.path().join("packages").join("app");
        fs::create_dir_all(&member_dir).unwrap();
        write_pkg(&member_dir, r#"{"name":"app"}"#);

        let status = TscStatus::probe(&member_dir);
        assert!(
            status.local_bin.is_some(),
            "expected ancestor bin to resolve"
        );
        assert!(status.in_deps, "ancestor manifest declares typescript");
    }

    #[test]
    fn no_local_no_deps_fails_both_predicates() {
        let tmp = TempDir::new().unwrap();
        write_pkg(tmp.path(), r#"{"name":"x"}"#);

        let status = TscStatus::probe(tmp.path());
        assert!(status.local_bin.is_none());
        assert!(!status.in_deps);
    }

    #[test]
    fn snapshot_probe_reuses_the_supplied_system_binary_and_dependency_result() {
        let tmp = TempDir::new().unwrap();
        write_pkg(tmp.path(), r#"{"name":"x"}"#);
        let system_tsc = tmp.path().join("system-bin/tsc");

        let status = TscStatus::probe_with_snapshot(tmp.path(), Some(&system_tsc), true);

        assert_eq!(status.system_bin.as_deref(), Some(system_tsc.as_path()));
        assert!(status.in_deps);
    }

    #[test]
    fn dep_in_dependencies_counts_as_declared() {
        let tmp = TempDir::new().unwrap();
        write_pkg(
            tmp.path(),
            r#"{"name":"x","dependencies":{"typescript":"5"}}"#,
        );

        let status = TscStatus::probe(tmp.path());
        assert!(status.in_deps);
    }

    #[test]
    fn dep_in_optional_dependencies_counts_as_declared() {
        let tmp = TempDir::new().unwrap();
        write_pkg(
            tmp.path(),
            r#"{"name":"x","optionalDependencies":{"typescript":"5"}}"#,
        );

        let status = TscStatus::probe(tmp.path());
        assert!(status.in_deps);
    }

    #[test]
    fn malformed_package_json_does_not_panic() {
        let tmp = TempDir::new().unwrap();
        fs::write(tmp.path().join("package.json"), "{ this is not json").unwrap();

        let status = TscStatus::probe(tmp.path());
        assert!(
            !status.in_deps,
            "malformed manifest treated as not declared"
        );
    }
}
