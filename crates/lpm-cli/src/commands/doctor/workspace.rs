use std::path::Path;

use crate::doctor_catalog;

use super::check::Check;

/// Check workspace graph for cycles.
pub(super) fn check_workspace(project_dir: &Path, discovery_error: Option<&str>) -> Option<Check> {
    if let Some(error) = discovery_error {
        return Some(Check::fail(
            &doctor_catalog::WORKSPACE_DISCOVERY_FAILED,
            error,
        ));
    }

    let workspace = match crate::workspace_discovery_cache::discover_workspace(project_dir) {
        Ok(workspace) => workspace?,
        Err(error) => {
            return Some(Check::fail(
                &doctor_catalog::WORKSPACE_DISCOVERY_FAILED,
                &error.to_string(),
            ));
        }
    };
    let graph = lpm_task::graph::WorkspaceGraph::from_workspace(&workspace);

    match graph.topological_sort() {
        Ok(sorted) => Some(Check::pass(
            &doctor_catalog::WORKSPACE_ACYCLIC,
            &format!("{} packages, no dependency cycles", sorted.len()),
        )),
        Err(e) => Some(Check::fail(
            &doctor_catalog::WORKSPACE_CYCLE,
            &format!("{e} — resolve circular dependencies"),
        )),
    }
}
