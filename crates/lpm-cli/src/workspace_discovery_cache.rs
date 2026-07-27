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
    let package = lpm_workspace::read_package_json(&target_dir.join("package.json"))?;

    if target_dir == workspace.root {
        workspace.root_package = package;
    } else if let Some(member) = workspace
        .members
        .iter_mut()
        .find(|member| member.path == target_dir)
    {
        member.package = package;
    }

    Ok(())
}
