use lpm_workspace::{Workspace, WorkspaceError};
use std::future::Future;
use std::path::Path;
use std::sync::Arc;

tokio::task_local! {
    static ACTIVE_WORKSPACE: Arc<Workspace>;
}

pub(crate) async fn scope<F>(workspace: Arc<Workspace>, future: F) -> F::Output
where
    F: Future,
{
    ACTIVE_WORKSPACE.scope(workspace, future).await
}

pub(crate) fn discover_workspace(
    start_dir: &Path,
) -> Result<Option<Arc<Workspace>>, WorkspaceError> {
    if let Ok(cached) = ACTIVE_WORKSPACE.try_with(|workspace| {
        start_dir
            .starts_with(&workspace.root)
            .then(|| Arc::clone(workspace))
    }) && cached.is_some()
    {
        return Ok(cached);
    }

    lpm_workspace::discover_workspace(start_dir).map(|workspace| workspace.map(Arc::new))
}

pub(crate) fn refresh_target(
    workspace: &mut Workspace,
    target_dir: &Path,
) -> Result<(), WorkspaceError> {
    if target_dir == workspace.root {
        let refreshed_root = lpm_workspace::discover_workspace(target_dir)?
            .filter(|refreshed| refreshed.root == workspace.root)
            .map(|refreshed| refreshed.root_package);
        workspace.root_package = match refreshed_root {
            Some(package) => package,
            None => lpm_workspace::read_package_json(&target_dir.join("package.json"))?,
        };
    } else if let Some(member) = workspace
        .members
        .iter_mut()
        .find(|member| member.path == target_dir)
    {
        member.package = lpm_workspace::read_package_json(&target_dir.join("package.json"))?;
    }

    Ok(())
}
