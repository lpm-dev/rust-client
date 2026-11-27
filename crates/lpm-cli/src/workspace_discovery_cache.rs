use lpm_workspace::{Workspace, WorkspaceError};
use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

#[derive(Default)]
pub(crate) struct WorkspaceFreshnessSnapshot {
    pub(crate) entries: Vec<(PathBuf, Vec<u8>)>,
    pub(crate) flattened: Vec<u8>,
}

impl WorkspaceFreshnessSnapshot {
    pub(crate) fn from_normalized_entries(mut entries: Vec<(PathBuf, Vec<u8>)>) -> Self {
        entries.sort_unstable_by(|left, right| left.0.cmp(&right.0));
        entries.dedup_by(|left, right| left.0 == right.0);
        let capacity = entries.iter().fold(0usize, |total, (path, content)| {
            total
                .saturating_add(path.as_os_str().as_encoded_bytes().len())
                .saturating_add(content.len())
                .saturating_add(2)
        });
        let mut flattened = Vec::with_capacity(capacity);
        for (path, content) in &entries {
            flattened.extend_from_slice(path.to_string_lossy().as_bytes());
            flattened.push(0);
            flattened.extend_from_slice(content);
            flattened.push(0);
        }
        Self { entries, flattened }
    }
}

#[derive(Default)]
pub(crate) struct WorkspaceFreshnessCache {
    snapshot: Mutex<Option<Arc<WorkspaceFreshnessSnapshot>>>,
    canonical_paths: Mutex<std::collections::HashMap<PathBuf, PathBuf>>,
}

impl WorkspaceFreshnessCache {
    pub(crate) fn invalidate(&self) {
        *self
            .snapshot
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
        self.canonical_paths
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clear();
    }

    fn get_or_init(
        &self,
        build: impl FnOnce() -> WorkspaceFreshnessSnapshot,
    ) -> Arc<WorkspaceFreshnessSnapshot> {
        let mut snapshot = self
            .snapshot
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        Arc::clone(snapshot.get_or_insert_with(|| Arc::new(build())))
    }

    fn canonicalize(&self, path: &Path) -> std::io::Result<PathBuf> {
        if let Some(cached) = self
            .canonical_paths
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(path)
            .cloned()
        {
            return Ok(cached);
        }
        let canonical = path.canonicalize()?;
        self.canonical_paths
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(path.to_path_buf(), canonical.clone());
        Ok(canonical)
    }
}

pub(crate) fn canonicalize_cached(path: &Path) -> std::io::Result<PathBuf> {
    match ACTIVE_WORKSPACE.try_with(|context| Arc::clone(&context.freshness_cache)) {
        Ok(cache) => cache.canonicalize(path),
        Err(_) => path.canonicalize(),
    }
}

pub(crate) fn canonicalize_or_original(path: &Path) -> PathBuf {
    canonicalize_cached(path).unwrap_or_else(|_| path.to_path_buf())
}

struct ActiveWorkspaceContext {
    workspace: Option<Arc<Workspace>>,
    scope_root: PathBuf,
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
    let scope_root = workspace.root.clone();
    ACTIVE_WORKSPACE
        .scope(
            ActiveWorkspaceContext {
                workspace: Some(workspace),
                scope_root,
                freshness_cache,
            },
            ACTIVE_ROOT_PROVIDER_FINGERPRINT.scope(root_provider_fingerprint, future),
        )
        .await
}

pub(crate) async fn scope_discovery<F>(
    start_dir: &Path,
    workspace: Option<Arc<Workspace>>,
    future: F,
) -> F::Output
where
    F: Future,
{
    let scope_root = workspace.as_ref().map_or_else(
        || start_dir.to_path_buf(),
        |workspace| workspace.root.clone(),
    );
    ACTIVE_WORKSPACE
        .scope(
            ActiveWorkspaceContext {
                workspace,
                scope_root,
                freshness_cache: Arc::new(WorkspaceFreshnessCache::default()),
            },
            ACTIVE_ROOT_PROVIDER_FINGERPRINT.scope(None, future),
        )
        .await
}

pub(crate) fn workspace_freshness_snapshot(
    start_dir: &Path,
    build: impl FnOnce() -> WorkspaceFreshnessSnapshot,
) -> Arc<WorkspaceFreshnessSnapshot> {
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
    if let Ok(cached) = ACTIVE_WORKSPACE.try_with(|context| {
        start_dir
            .starts_with(&context.scope_root)
            .then(|| context.workspace.clone())
    }) && let Some(cached) = cached
    {
        return Ok(cached);
    }

    lpm_workspace::discover_workspace(start_dir).map(|workspace| workspace.map(Arc::new))
}

pub(crate) fn active_workspace(start_dir: &Path) -> Option<Arc<Workspace>> {
    ACTIVE_WORKSPACE
        .try_with(|context| {
            start_dir
                .starts_with(&context.scope_root)
                .then(|| context.workspace.clone())
                .flatten()
        })
        .ok()
        .flatten()
}

pub(crate) fn find_workspace_root(start_dir: &Path) -> Result<Option<PathBuf>, WorkspaceError> {
    if let Ok(cached) = ACTIVE_WORKSPACE.try_with(|context| {
        start_dir
            .starts_with(&context.scope_root)
            .then(|| context.workspace.as_ref().map(|ws| ws.root.clone()))
    }) && let Some(cached) = cached
    {
        return Ok(cached);
    }
    lpm_workspace::find_workspace_root(start_dir)
}

pub(crate) fn read_workspace_root_package(
    root: &Path,
) -> Result<lpm_workspace::PackageJson, WorkspaceError> {
    if let Some(workspace) = active_workspace(root)
        && workspace.root == root
    {
        return Ok(workspace.root_package.clone());
    }
    lpm_workspace::read_workspace_root_package(root)
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
            let first = workspace_freshness_snapshot(directory.path(), || {
                builds.fetch_add(1, Ordering::SeqCst);
                WorkspaceFreshnessSnapshot::from_normalized_entries(vec![(
                    directory.path().to_path_buf(),
                    b"first".to_vec(),
                )])
            });
            let second = workspace_freshness_snapshot(directory.path(), || {
                builds.fetch_add(1, Ordering::SeqCst);
                WorkspaceFreshnessSnapshot::default()
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
            let first =
                workspace_freshness_snapshot(directory.path(), WorkspaceFreshnessSnapshot::default);
            scoped_cache.invalidate();
            let second =
                workspace_freshness_snapshot(directory.path(), WorkspaceFreshnessSnapshot::default);

            assert!(!Arc::ptr_eq(&first, &second));
        })
        .await;
    }

    #[tokio::test]
    async fn scoped_absence_is_reused_after_workspace_files_appear() {
        let directory = tempfile::tempdir().unwrap();

        scope_discovery(directory.path(), None, async {
            std::fs::write(
                directory.path().join("package.json"),
                r#"{"name":"root","private":true}"#,
            )
            .unwrap();
            std::fs::write(
                directory.path().join("pnpm-workspace.yaml"),
                "packages:\n  - 'packages/*'\n",
            )
            .unwrap();

            assert!(discover_workspace(directory.path()).unwrap().is_none());
        })
        .await;

        assert!(discover_workspace(directory.path()).unwrap().is_some());
    }
}
