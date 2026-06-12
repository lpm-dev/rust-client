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

pub(super) fn canonical_project_root(project_dir: &Path) -> String {
    std::fs::canonicalize(project_dir)
        .unwrap_or_else(|_| project_dir.to_path_buf())
        .display()
        .to_string()
}

pub(super) fn canonical_global_root() -> Result<String, LpmError> {
    Ok(canonical_project_root(
        &lpm_common::LpmRoot::from_env()?.global_root(),
    ))
}

pub(super) fn project_dir_is_global_install(project_dir: &Path) -> bool {
    let Ok(root) = lpm_common::LpmRoot::from_env() else {
        return false;
    };
    let global_installs = root.global_installs();
    let canonical_global_installs =
        std::fs::canonicalize(&global_installs).unwrap_or(global_installs);
    let canonical_project =
        std::fs::canonicalize(project_dir).unwrap_or_else(|_| project_dir.to_path_buf());
    canonical_project.starts_with(canonical_global_installs)
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
