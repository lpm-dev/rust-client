use lpm_workspace::{Workspace, WorkspaceError};
use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

pub(crate) type WorkspaceFreshnessEntries = Vec<(PathBuf, Vec<u8>)>;

#[derive(Default)]
pub(crate) struct WorkspaceFreshnessCache {
    entries: Mutex<Option<Arc<WorkspaceFreshnessEntries>>>,
}

impl WorkspaceFreshnessCache {
    pub(crate) fn invalidate(&self) {
        *self
            .entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
    }

    fn get_or_init(
        &self,
        build: impl FnOnce() -> WorkspaceFreshnessEntries,
    ) -> Arc<WorkspaceFreshnessEntries> {
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        Arc::clone(entries.get_or_insert_with(|| Arc::new(build())))
    }
}

struct ActiveWorkspaceContext {
    workspace: Arc<Workspace>,
    freshness_cache: Arc<WorkspaceFreshnessCache>,
}

tokio::task_local! {
    static ACTIVE_WORKSPACE: ActiveWorkspaceContext;
    static ACTIVE_ROOT_PROVIDER_FINGERPRINT: Option<Arc<str>>;
}

pub(crate) async fn scope<F>(
    workspace: Arc<Workspace>,
    root_provider_fingerprint: Option<Arc<str>>,
    freshness_cache: Arc<WorkspaceFreshnessCache>,
    future: F,
) -> F::Output
where
    F: Future,
{
    ACTIVE_WORKSPACE
        .scope(
            ActiveWorkspaceContext {
                workspace,
                freshness_cache,
            },
            ACTIVE_ROOT_PROVIDER_FINGERPRINT.scope(root_provider_fingerprint, future),
        )
        .await
}

pub(crate) fn workspace_freshness_entries(
    start_dir: &Path,
    build: impl FnOnce() -> WorkspaceFreshnessEntries,
) -> Arc<WorkspaceFreshnessEntries> {
    if active_workspace(start_dir).is_none() {
        return Arc::new(build());
    }
    match ACTIVE_WORKSPACE.try_with(|context| Arc::clone(&context.freshness_cache)) {
        Ok(cache) => cache.get_or_init(build),
        Err(_) => Arc::new(build()),
    }
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
        .try_with(|context| {
            start_dir
                .starts_with(&context.workspace.root)
                .then(|| Arc::clone(&context.workspace))
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
    use std::sync::atomic::{AtomicUsize, Ordering};

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

    #[tokio::test]
    async fn recursive_targets_reuse_one_workspace_freshness_snapshot() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::write(
            directory.path().join("package.json"),
            r#"{"name":"root","private":true}"#,
        )
        .unwrap();
        let workspace = Arc::new(Workspace {
            root: directory.path().to_path_buf(),
            root_package: lpm_workspace::PackageJson::default(),
            members: Vec::new(),
        });
        let cache = Arc::new(WorkspaceFreshnessCache::default());
        let builds = AtomicUsize::new(0);

        scope(workspace, None, cache, async {
            let first = workspace_freshness_entries(directory.path(), || {
                builds.fetch_add(1, Ordering::SeqCst);
                vec![(directory.path().to_path_buf(), b"first".to_vec())]
            });
            let second = workspace_freshness_entries(directory.path(), || {
                builds.fetch_add(1, Ordering::SeqCst);
                Vec::new()
            });

            assert!(Arc::ptr_eq(&first, &second));
            assert_eq!(builds.load(Ordering::SeqCst), 1);
        })
        .await;
    }

    #[tokio::test]
    async fn lifecycle_invalidation_refreshes_workspace_freshness_snapshot() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::write(
            directory.path().join("package.json"),
            r#"{"name":"root","private":true}"#,
        )
        .unwrap();
        let workspace = Arc::new(Workspace {
            root: directory.path().to_path_buf(),
            root_package: lpm_workspace::PackageJson::default(),
            members: Vec::new(),
        });
        let cache = Arc::new(WorkspaceFreshnessCache::default());
        let scoped_cache = Arc::clone(&cache);

        scope(workspace, None, cache, async {
            let first = workspace_freshness_entries(directory.path(), Vec::new);
            scoped_cache.invalidate();
            let second = workspace_freshness_entries(directory.path(), Vec::new);

            assert!(!Arc::ptr_eq(&first, &second));
        })
        .await;
    }
}
