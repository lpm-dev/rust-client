use lpm_common::LpmError;
use lpm_runner::bin_path::{ManagedRuntimeHint, ManagedRuntimeInventory};
use std::path::{Path, PathBuf};

pub(super) fn boundary(project_dir: &Path) -> Result<PathBuf, LpmError> {
    Ok(lpm_workspace::find_workspace_root(project_dir)
        .map_err(|error| LpmError::Script(format!("workspace error: {error}")))?
        .or_else(|| lpm_workspace::find_project_root(project_dir))
        .unwrap_or_else(|| project_dir.to_path_buf()))
}

pub(super) struct InstalledRuntimes {
    root: PathBuf,
    inventory: ManagedRuntimeInventory,
    root_hint: ManagedRuntimeHint,
}

impl InstalledRuntimes {
    pub(super) fn new(root: &Path) -> Result<Self, LpmError> {
        let inventory = ManagedRuntimeInventory::default();
        let root_hint = inventory.resolve_detected(&detected_runtimes(root)?)?;
        Ok(Self {
            root: root.to_path_buf(),
            inventory,
            root_hint,
        })
    }

    pub(super) fn path_for(&self, cwd: &Path) -> Result<String, LpmError> {
        let project = lpm_workspace::find_project_root(cwd).unwrap_or_else(|| cwd.to_path_buf());
        let hint = if project == self.root {
            self.root_hint.clone()
        } else {
            let detected = detected_runtimes(&project)?;
            let kinds = detected
                .iter()
                .map(|runtime| runtime.runtime)
                .collect::<Vec<_>>();
            self.inventory
                .resolve_detected(&detected)?
                .inherit_unselected_from(&self.root_hint, &kinds)
        };
        lpm_runner::bin_path::build_path_with_bins_bounded(cwd, &self.root, &hint)
    }
}

fn detected_runtimes(
    project: &Path,
) -> Result<Vec<lpm_runtime::detect::DetectedRuntimeVersion>, LpmError> {
    let config = lpm_runner::lpm_json::read_lpm_json(project).map_err(LpmError::Script)?;
    let runtime = |name| {
        config
            .as_ref()
            .and_then(|config| config.runtime.get(name))
            .map(String::as_str)
    };
    lpm_runtime::detect::detect_runtime_versions_with_lpm_json_specs(
        project,
        runtime("node"),
        runtime("bun"),
    )
    .map_err(Into::into)
}
