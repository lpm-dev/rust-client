use super::StoreVerifyEntry;
use crate::commands::manifest_metadata::graph::{PackageIndexes, unique_package_targets_for_kind};
use crate::npm_public_source::LockfileRootIndex;
use lpm_common::sanitize_terminal_inline;
use lpm_lockfile::{LockedPackage, Lockfile};
use std::collections::{HashMap, HashSet, VecDeque};
use std::path::Path;

#[derive(Default)]
pub(super) struct LockfileVerification {
    pub expected: HashMap<usize, String>,
    pub issues: Vec<String>,
    status: &'static str,
    packages: usize,
    bindings: HashMap<usize, Vec<usize>>,
    compared: HashSet<usize>,
}

impl LockfileVerification {
    pub fn attach(&self, output: &mut serde_json::Value, deep: bool) {
        if deep {
            output["lockfile_comparison"] = serde_json::json!({
                "status": self.status(),
                "packages": self.packages,
                "compared_packages": self.compared.len(),
                "uncompared_packages": self.packages.saturating_sub(self.compared.len()),
            });
        }
    }

    pub fn record_comparison(&mut self, entry_index: usize) {
        if let Some(packages) = self.bindings.get(&entry_index) {
            self.compared.extend(packages.iter().copied());
        }
    }

    fn status(&self) -> &str {
        if self.status == "loaded" {
            if self.compared.len() == self.packages {
                "complete"
            } else {
                "partial"
            }
        } else {
            self.status
        }
    }

    pub fn print_scope(&self) {
        if self.status() == "partial" {
            crate::install_ui::warn_untrusted(&format!(
                "Lockfile comparison covered {} of {} package records with integrity; {} had no comparable installed store entry",
                self.compared.len(),
                self.packages,
                self.packages - self.compared.len()
            ));
        }
    }
}

pub(super) fn load(deep: bool, entries: &[StoreVerifyEntry]) -> LockfileVerification {
    let mut result = LockfileVerification::default();
    if !deep {
        return result;
    }
    let project = std::env::current_dir()
        .map_err(|error| error.to_string())
        .and_then(|cwd| match Lockfile::read_for_project(&cwd) {
            Ok(project) => Ok(Some(project)),
            Err(lpm_lockfile::LockfileError::NotFound(_)) => Ok(None),
            Err(error) => Err(error.to_string()),
        });
    let project = match project {
        Ok(Some(project)) => project,
        Ok(None) => {
            result.status = "not_found";
            return result;
        }
        Err(error) => {
            result.status = "unreadable";
            result.issues.push(format!(
                "lpm.lock — unreadable: {}",
                sanitize_terminal_inline(&error)
            ));
            return result;
        }
    };
    let lockfile = &project.lockfile;
    result.packages = lockfile
        .packages
        .iter()
        .filter(|package| package.integrity.is_some())
        .count();
    let project_dir = project
        .path
        .parent()
        .unwrap_or(Path::new("."))
        .join(&project.importer);
    let by_path: HashMap<_, _> = entries
        .iter()
        .enumerate()
        .filter_map(|(index, entry)| entry.dir.canonicalize().ok().map(|path| (path, index)))
        .collect();
    let package_indices: HashMap<_, _> = lockfile
        .packages
        .iter()
        .enumerate()
        .map(|(index, package)| (package as *const LockedPackage, index))
        .collect();
    let roots = LockfileRootIndex::new(Some(lockfile));
    let indexes = PackageIndexes::new(&lockfile.packages);
    let mut queue = VecDeque::new();
    for (local, resolution) in &lockfile.root_resolutions {
        let Some(package) = roots.root_package(local, &resolution.package) else {
            continue;
        };
        let Some(&package_index) = package_indices.get(&(package as *const LockedPackage)) else {
            continue;
        };
        let path = project_dir.join("node_modules").join(local);
        if let Some(&entry_index) = path
            .canonicalize()
            .ok()
            .as_ref()
            .and_then(|path| by_path.get(path))
        {
            queue.push_back((package_index, entry_index));
        }
    }
    let mut visited = HashSet::new();
    while let Some((package_index, entry_index)) = queue.pop_front() {
        if !visited.insert((package_index, entry_index)) {
            continue;
        }
        let package = &lockfile.packages[package_index];
        let entry = &entries[entry_index];
        if let Some(integrity) = &package.integrity {
            if let Some(prior) = result.expected.get(&entry_index) {
                if prior != integrity {
                    result.issues.push(format!(
                        "{}@{} — one store entry is bound to conflicting lockfile integrity records",
                        sanitize_terminal_inline(&entry.name), sanitize_terminal_inline(&entry.version)
                    ));
                    continue;
                }
            } else {
                result.expected.insert(entry_index, integrity.clone());
            }
            result
                .bindings
                .entry(entry_index)
                .or_default()
                .push(package_index);
        }
        if package.name != entry.name || package.version != entry.version {
            result.issues.push(format!(
                "{}@{} — installed link selects {}@{} instead of the locked package",
                sanitize_terminal_inline(&package.name),
                sanitize_terminal_inline(&package.version),
                sanitize_terminal_inline(&entry.name),
                sanitize_terminal_inline(&entry.version)
            ));
            continue;
        }
        if entry.store_version.is_none() {
            continue;
        }
        for (local, target) in unique_targets(package, &indexes) {
            let mut path = entry.dir.clone();
            if local == package.name {
                path.push("node_modules");
            } else {
                path.pop();
                if package.name.starts_with('@') {
                    path.pop();
                }
            }
            path.push(local);
            if let Some(&next_entry) = path
                .canonicalize()
                .ok()
                .as_ref()
                .and_then(|path| by_path.get(path))
            {
                queue.push_back((target, next_entry));
            }
        }
    }
    result.status = "loaded";
    result
}

fn unique_targets<'a>(
    package: &'a LockedPackage,
    indexes: &PackageIndexes<'_>,
) -> HashMap<&'a str, usize> {
    let mut targets = HashMap::new();
    let mut claimed = HashSet::new();
    for peers in [false, true] {
        let Ok(candidates) = unique_package_targets_for_kind(package, indexes, peers) else {
            // An unresolved ordinary slot still shadows a peer at the same path.
            // Do not guess peer bindings after ordinary target resolution fails.
            return targets;
        };
        for (local, target) in candidates {
            if claimed.insert(local) {
                targets.insert(local, target);
            }
        }
    }
    targets
}
