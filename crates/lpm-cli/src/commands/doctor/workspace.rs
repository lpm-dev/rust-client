use std::path::Path;

use crate::doctor_catalog;

use super::check::Check;

/// Check workspace graph for cycles.
pub(super) fn check_workspace(project_dir: &Path) -> Option<Check> {
    let workspace = lpm_workspace::discover_workspace(project_dir).ok()??;
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
