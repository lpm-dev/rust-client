use super::prelude::*;

pub(super) fn is_automation(json_output: bool) -> bool {
    if test_native_auth_override().is_some() {
        return false;
    }
    json_output
        || !std::io::stdin().is_terminal()
        || !std::io::stdout().is_terminal()
        || matches!(
            std::env::var("CI").as_deref(),
            Ok("1") | Ok("true") | Ok("TRUE") | Ok("yes") | Ok("YES")
        )
}

/// A project's resolved root as approvals, unlocks and audit records name
/// it. Windows resolves a directory to a verbatim path (`\\?\C:\work\app`);
/// the root is written the way people and shells write it (`C:\work\app`)
/// when that means the same, as firewall bypass rules write it. Records saved
/// before kept the verbatim form, which [`ProjectRoot::names`] still accepts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ProjectRoot {
    written: String,
    verbatim: Option<String>,
}

impl ProjectRoot {
    pub(super) fn of(project_dir: &Path) -> Self {
        let resolved = std::fs::canonicalize(project_dir)
            .unwrap_or_else(|_| project_dir.to_path_buf())
            .display()
            .to_string();
        Self::from_resolved(resolved, cfg!(windows))
    }

    /// The root for `resolved`, the directory as the file system resolved
    /// it, written plainly where `windows` resolves to verbatim paths.
    pub(super) fn from_resolved(resolved: String, windows: bool) -> Self {
        if windows && let Some(plain) = crate::project_fs::plain_drive_path(&resolved) {
            return Self {
                written: plain.to_owned(),
                verbatim: Some(resolved),
            };
        }
        Self {
            written: resolved,
            verbatim: None,
        }
    }

    pub(super) fn as_str(&self) -> &str {
        &self.written
    }

    pub(super) fn into_string(self) -> String {
        self.written
    }

    /// The verbatim form records saved before named this root by, where it
    /// differs from how the root is written now.
    pub(super) fn verbatim(&self) -> Option<&str> {
        self.verbatim.as_deref()
    }

    /// Whether `saved`, a root a record holds, names this project.
    pub(super) fn names(&self, saved: &str) -> bool {
        saved == self.written || self.verbatim() == Some(saved)
    }
}

pub(super) fn canonical_project_root(project_dir: &Path) -> String {
    ProjectRoot::of(project_dir).into_string()
}

pub(super) fn canonical_global_root() -> Result<String, LpmError> {
    Ok(canonical_project_root(
        &lpm_common::LpmRoot::from_env()?.global_root(),
    ))
}

pub(crate) fn project_dir_is_global_install(project_dir: &Path) -> bool {
    let Ok(root) = lpm_common::LpmRoot::from_env() else {
        return false;
    };
    let global_installs = root.global_installs();
    let canonical_global_installs = canonicalize_existing_prefix(&global_installs);
    let canonical_project = canonicalize_existing_prefix(project_dir);
    canonical_project.starts_with(canonical_global_installs)
}

fn canonicalize_existing_prefix(path: &Path) -> PathBuf {
    if let Ok(canonical) = std::fs::canonicalize(path) {
        return canonical;
    }

    let mut cursor = path;
    let mut suffix = PathBuf::new();
    while let Some(parent) = cursor.parent() {
        if let Some(name) = cursor.file_name() {
            let mut next_suffix = PathBuf::from(name);
            next_suffix.push(&suffix);
            suffix = next_suffix;
        }
        if let Ok(canonical_parent) = std::fs::canonicalize(parent) {
            return canonical_parent.join(suffix);
        }
        cursor = parent;
    }

    path.to_path_buf()
}

pub(super) fn normalized_packages(packages: &[String]) -> Vec<String> {
    let mut values: Vec<_> = packages
        .iter()
        .map(|pkg| pkg.trim())
        .filter(|pkg| !pkg.is_empty())
        .map(str::to_string)
        .collect();
    values.sort();
    values.dedup();
    values
}

fn scope_rank(scope: ApprovalScope) -> usize {
    ApprovalScope::all_scopes()
        .iter()
        .position(|candidate| *candidate == scope)
        .unwrap_or(usize::MAX)
}

pub(super) fn normalized_scopes(scopes: &[ApprovalScope]) -> Vec<ApprovalScope> {
    let mut values = scopes.to_vec();
    values.sort_by_key(|scope| scope_rank(*scope));
    values.dedup();
    values
}

pub(super) fn scope_names(scopes: &[ApprovalScope]) -> Vec<String> {
    normalized_scopes(scopes)
        .into_iter()
        .map(|scope| scope.as_str().to_string())
        .collect()
}

pub(super) fn format_scope_list(scopes: &[ApprovalScope]) -> String {
    scope_names(scopes).join(", ")
}

pub fn format_unlock_duration(ttl_secs: u64) -> String {
    if ttl_secs.is_multiple_of(86_400) {
        return format!("{}d", ttl_secs / 86_400);
    }
    if ttl_secs.is_multiple_of(3_600) {
        return format!("{}h", ttl_secs / 3_600);
    }
    if ttl_secs.is_multiple_of(60) {
        return format!("{}m", ttl_secs / 60);
    }
    format!("{ttl_secs}s")
}

pub(super) fn suggested_unlock_command(
    scope: &str,
    target: UnlockTargetKind,
    packages: &[String],
) -> String {
    let mut command = match target {
        UnlockTargetKind::Project => {
            format!("lpm security unlock {scope} --project . --ttl 10m")
        }
        UnlockTargetKind::Global => {
            format!("lpm security unlock {scope} --global --ttl 10m")
        }
    };
    for package in normalized_packages(packages) {
        command.push_str(&format!(" --package {package}"));
    }
    command
}
