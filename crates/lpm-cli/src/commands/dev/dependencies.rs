use std::path::Path;

use lpm_common::LpmError;

pub(super) fn can_skip_fresh_install(project_dir: &Path) -> Result<bool, LpmError> {
    // Existing state must reach the installer to reconcile removals and recover interrupted work.
    for artifact in [
        "node_modules",
        "lpm.lock",
        "lpm.lockb",
        "pnpm-workspace.yaml",
        ".lpm",
    ] {
        match project_dir.join(artifact).symlink_metadata() {
            Ok(_) => return Ok(false),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }

    let package = lpm_workspace::read_package_json(&project_dir.join("package.json"))
        .map_err(|error| LpmError::Script(format!("failed to read package.json: {error}")))?;
    if !package.dependencies.is_empty()
        || !package.dev_dependencies.is_empty()
        || !package.optional_dependencies.is_empty()
        || !package.peer_dependencies.is_empty()
        || package.workspaces.is_some()
        || package.lpm.is_some()
        || package.pnpm.is_some()
        || !package.engines.is_empty()
        || !package.overrides.is_empty()
        || !package.resolutions.is_empty()
        || !package.unsupported_override_values.is_empty()
        || !package.catalogs.is_empty()
    {
        return Ok(false);
    }

    if lpm_workspace::find_workspace_root(project_dir)
        .map_err(|error| LpmError::Script(format!("workspace discovery failed: {error}")))?
        .is_some()
    {
        return Ok(false);
    }

    crate::commands::install::validate_dependency_free_dev_config(project_dir)?;
    Ok(true)
}
