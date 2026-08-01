use lpm_workspace::{Workspace, WorkspaceError};
use std::future::Future;
use std::path::Path;
use std::sync::Arc;

tokio::task_local! {
    static ACTIVE_WORKSPACE: Arc<Workspace>;
    static ACTIVE_ROOT_PROVIDER_FINGERPRINT: Option<Arc<str>>;
}

pub(crate) async fn scope<F>(
    workspace: Arc<Workspace>,
    root_provider_fingerprint: Option<Arc<str>>,
    future: F,
) -> F::Output
where
    F: Future,
{
    ACTIVE_WORKSPACE
        .scope(
            workspace,
            ACTIVE_ROOT_PROVIDER_FINGERPRINT.scope(root_provider_fingerprint, future),
        )
        .await
}

pub(crate) fn discover_workspace(
    start_dir: &Path,
) -> Result<Option<Arc<Workspace>>, WorkspaceError> {
    if let Some(cached) = active_workspace(start_dir) {
        return Ok(Some(cached));
    }

    lpm_workspace::discover_workspace(start_dir).map(|workspace| workspace.map(Arc::new))
}

pub(crate) fn active_workspace(start_dir: &Path) -> Option<Arc<Workspace>> {
    ACTIVE_WORKSPACE
        .try_with(|workspace| {
            start_dir
                .starts_with(&workspace.root)
                .then(|| Arc::clone(workspace))
        })
        .ok()
        .flatten()
}

pub(crate) fn root_provider_fingerprint_for_member(start_dir: &Path) -> Option<Arc<str>> {
    let workspace = active_workspace(start_dir)?;
    if start_dir == workspace.root {
        return None;
    }
    ACTIVE_ROOT_PROVIDER_FINGERPRINT
        .try_with(Clone::clone)
        .ok()
        .flatten()
}

pub(crate) fn root_provider_fingerprint_for_locked_member(
    start_dir: &Path,
    locked_fingerprint: Option<&str>,
) -> Option<Arc<str>> {
    locked_fingerprint?;
    root_provider_fingerprint_for_member(start_dir)
}

pub(crate) fn refresh_target(
    workspace: &mut Workspace,
    target_dir: &Path,
) -> Result<(), WorkspaceError> {
    if target_dir == workspace.root {
        workspace.root_package = lpm_workspace::read_workspace_root_package(target_dir)?;
    } else if let Some(member) = workspace
        .members
        .iter_mut()
        .find(|member| member.path == target_dir)
    {
        member.package = lpm_workspace::read_package_json(&target_dir.join("package.json"))?;
    }

    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn refresh_target_root_reloads_manifest_without_following_workspace_symlink_cycles() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::write(
            directory.path().join("package.json"),
            r#"{"name":"root","private":true}"#,
        )
        .unwrap();
        std::fs::write(
            directory.path().join("pnpm-workspace.yaml"),
            "packages:\n  - 'playground/**'\n",
        )
        .unwrap();
        let member = directory.path().join("playground/alias");
        std::fs::create_dir_all(member.join("node_modules/@vitejs")).unwrap();
        std::fs::create_dir_all(member.join("__tests__")).unwrap();
        std::fs::write(
            member.join("package.json"),
            r#"{"name":"@vitejs/test-alias","private":true,"version":"0.0.0"}"#,
        )
        .unwrap();
        let mut workspace = lpm_workspace::discover_workspace(directory.path())
            .unwrap()
            .unwrap();
        std::os::unix::fs::symlink(
            member.canonicalize().unwrap(),
            member.join("node_modules/@vitejs/test-alias"),
        )
        .unwrap();
        std::fs::write(
            directory.path().join("package.json"),
            r#"{"name":"refreshed-root","private":true}"#,
        )
        .unwrap();

        refresh_target(&mut workspace, directory.path()).unwrap();

        assert_eq!(
            workspace.root_package.name.as_deref(),
            Some("refreshed-root")
        );
    }
}
