use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use lpm_common::LpmError;

pub(super) struct WorkspaceLockfileCoordinator {
    root: PathBuf,
    existing: Option<lpm_lockfile::Lockfile>,
    migration_pending: bool,
    valid_importers: BTreeSet<String>,
    staged: Mutex<BTreeMap<String, lpm_lockfile::Lockfile>>,
    non_persisting_importers: Mutex<BTreeSet<String>>,
}

impl WorkspaceLockfileCoordinator {
    pub(super) fn new(
        root: &Path,
        legacy_importers: &[(String, PathBuf)],
    ) -> Result<Self, LpmError> {
        let path = root.join(lpm_lockfile::LOCKFILE_NAME);
        let root_lockfile = if path.exists() {
            let lockfile = lpm_lockfile::Lockfile::read_fast(&path).map_err(|error| {
                LpmError::Registry(format!(
                    "failed to read workspace lockfile {}: {error}",
                    path.display()
                ))
            })?;
            Some(lockfile)
        } else {
            None
        };
        let mut migration_pending = root_lockfile.as_ref().is_some_and(|lockfile| {
            lockfile.metadata.lockfile_version
                < lpm_lockfile::LOCKFILE_VERSION_WITH_WORKSPACE_PROJECTIONS
        });
        let mut union = match root_lockfile {
            Some(lockfile)
                if lockfile.metadata.lockfile_version
                    >= lpm_lockfile::LOCKFILE_VERSION_WITH_WORKSPACE_PROJECTIONS =>
            {
                lockfile
            }
            Some(lockfile) => {
                let mut union = lpm_lockfile::Lockfile::new_with_resolver(
                    lockfile
                        .metadata
                        .resolved_with
                        .as_deref()
                        .unwrap_or(lpm_lockfile::DEFAULT_RESOLVED_WITH),
                );
                union
                    .absorb_importer(".", lockfile)
                    .map_err(lockfile_error)?;
                union
            }
            None => lpm_lockfile::Lockfile::new(),
        };
        for (importer, importer_root) in legacy_importers {
            if union.importers.contains_key(importer) {
                continue;
            }
            let importer_path = importer_root.join(lpm_lockfile::LOCKFILE_NAME);
            if !importer_path.exists() {
                continue;
            }
            let lockfile = lpm_lockfile::Lockfile::read_fast(&importer_path).map_err(|error| {
                LpmError::Registry(format!(
                    "failed to read importer lockfile {}: {error}",
                    importer_path.display()
                ))
            })?;
            union
                .absorb_importer(importer, lockfile)
                .map_err(lockfile_error)?;
            migration_pending = true;
        }
        let existing = (!union.importers.is_empty()).then_some(union);
        let mut valid_importers = BTreeSet::from([".".to_string()]);
        valid_importers.extend(
            legacy_importers
                .iter()
                .map(|(importer, _)| importer.clone()),
        );
        Ok(Self {
            root: root.to_path_buf(),
            existing,
            migration_pending,
            valid_importers,
            staged: Mutex::new(BTreeMap::new()),
            non_persisting_importers: Mutex::new(BTreeSet::new()),
        })
    }

    pub(super) fn projection(
        &self,
        importer: &str,
    ) -> Result<lpm_lockfile::Lockfile, lpm_lockfile::LockfileError> {
        if let Some(lockfile) = self
            .staged
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(importer)
            .cloned()
        {
            return Ok(lockfile);
        }
        self.existing
            .as_ref()
            .ok_or_else(|| {
                lpm_lockfile::LockfileError::NotFound(
                    "workspace lockfile does not exist".to_string(),
                )
            })?
            .project_importer(importer)
    }

    fn stage(&self, importer: &str, lockfile: lpm_lockfile::Lockfile) {
        self.staged
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(importer.to_string(), lockfile);
    }

    fn mark_non_persisting(&self, importer: &str) {
        self.non_persisting_importers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(importer.to_string());
    }

    pub(super) fn commit(&self, required_importers: &[String]) -> Result<bool, LpmError> {
        let staged = self
            .staged
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let non_persisting_importers = self
            .non_persisting_importers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if staged.is_empty()
            && !required_importers.is_empty()
            && required_importers
                .iter()
                .all(|importer| non_persisting_importers.contains(importer))
        {
            return Ok(!self.migration_pending && self.existing.is_some());
        }
        let mut projections = BTreeMap::new();
        if let Some(existing) = &self.existing {
            for importer in existing
                .importers
                .keys()
                .filter(|importer| self.valid_importers.contains(*importer))
            {
                projections.insert(
                    importer.clone(),
                    existing
                        .project_importer(importer)
                        .map_err(lockfile_error)?,
                );
            }
        }
        for (importer, lockfile) in staged.iter() {
            if !self.valid_importers.contains(importer) {
                return Err(LpmError::Registry(format!(
                    "workspace importer {importer:?} is no longer a member; no lockfile changes were committed"
                )));
            }
            projections.insert(importer.clone(), lockfile.clone());
        }
        for importer in required_importers {
            if !projections.contains_key(importer) && !non_persisting_importers.contains(importer) {
                return Err(LpmError::Registry(format!(
                    "workspace importer {importer:?} completed without producing a lockfile projection"
                )));
            }
        }

        if projections.is_empty() {
            return Ok(false);
        }

        let resolver = projections
            .values()
            .find_map(|lockfile| lockfile.metadata.resolved_with.as_deref())
            .unwrap_or(lpm_lockfile::DEFAULT_RESOLVED_WITH);
        let mut union = lpm_lockfile::Lockfile::new_with_resolver(resolver);
        for (importer, projection) in projections {
            union
                .absorb_importer(&importer, projection)
                .map_err(lockfile_error)?;
        }

        let path = self.root.join(lpm_lockfile::LOCKFILE_NAME);
        lpm_lockfile::ensure_gitattributes(&self.root).map_err(lockfile_error)?;
        if !self.migration_pending && self.existing.as_ref() == Some(&union) {
            return Ok(true);
        }
        union.write_all(&path).map_err(lockfile_error)?;
        Ok(true)
    }
}

fn lockfile_error(error: lpm_lockfile::LockfileError) -> LpmError {
    LpmError::Registry(format!("workspace lockfile transaction failed: {error}"))
}

struct WorkspaceLockfileTarget {
    coordinator: Arc<WorkspaceLockfileCoordinator>,
    importer: Arc<str>,
}

struct WorkspaceLockfileTransaction {
    root: PathBuf,
    coordinator: Arc<WorkspaceLockfileCoordinator>,
    manifest_transactions: Mutex<Vec<crate::manifest_tx::ManifestTransaction>>,
}

tokio::task_local! {
    static ACTIVE_TARGET: WorkspaceLockfileTarget;
    static ACTIVE_TRANSACTION: WorkspaceLockfileTransaction;
}

pub(super) async fn scope<F, T>(
    coordinator: Arc<WorkspaceLockfileCoordinator>,
    importer: Arc<str>,
    future: F,
) -> T
where
    F: Future<Output = T>,
{
    let future = Box::pin(future);
    ACTIVE_TARGET
        .scope(
            WorkspaceLockfileTarget {
                coordinator,
                importer,
            },
            future,
        )
        .await
}

pub(super) async fn scope_member_install<F, T>(project_dir: &Path, future: F) -> Result<T, LpmError>
where
    F: Future<Output = Result<T, LpmError>>,
{
    let future = Box::pin(future);
    if active() {
        return future.await;
    }
    if let Ok((root, coordinator)) = ACTIVE_TRANSACTION.try_with(|transaction| {
        (
            transaction.root.clone(),
            Arc::clone(&transaction.coordinator),
        )
    }) {
        let importer = importer_key(&root, project_dir)?;
        return scope(coordinator, Arc::<str>::from(importer), future).await;
    }
    let Some(initial_workspace) = discover_workspace(project_dir)? else {
        return future.await;
    };
    let workspace_root = initial_workspace.root;
    let workspace_lock = lpm_common::project_install_lock(&workspace_root);
    let transaction = async {
        let workspace = discover_workspace(project_dir)?
            .ok_or_else(|| workspace_changed_while_waiting(&workspace_root, None))?;
        if workspace.root != workspace_root {
            return Err(workspace_changed_while_waiting(
                &workspace_root,
                Some(&workspace.root),
            ));
        }
        let importer = importer_key(&workspace.root, project_dir)?;
        let legacy_importers = workspace
            .members
            .iter()
            .map(|member| {
                importer_key(&workspace.root, &member.path).map(|key| (key, member.path.clone()))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let coordinator = Arc::new(WorkspaceLockfileCoordinator::new(
            &workspace.root,
            &legacy_importers,
        )?);
        let result = scope(
            Arc::clone(&coordinator),
            Arc::<str>::from(importer.as_str()),
            future,
        )
        .await?;
        if coordinator.commit(std::slice::from_ref(&importer))? {
            remove_member_lockfiles(&legacy_importers);
        }
        Ok(result)
    };
    lpm_common::with_exclusive_lock_async(workspace_lock, transaction).await
}

pub(crate) async fn scope_workspace_mutation<F, T>(
    cwd: &Path,
    project_dirs: &[PathBuf],
    future: F,
) -> Result<T, LpmError>
where
    F: Future<Output = Result<T, LpmError>>,
{
    scope_workspace_transaction(cwd, project_dirs, true, future).await
}

pub(crate) async fn scope_workspace_mutation_if_present<F, T>(
    cwd: &Path,
    project_dirs: &[PathBuf],
    future: F,
) -> Result<T, LpmError>
where
    F: Future<Output = Result<T, LpmError>>,
{
    scope_workspace_transaction(cwd, project_dirs, false, future).await
}

async fn scope_workspace_transaction<F, T>(
    cwd: &Path,
    project_dirs: &[PathBuf],
    require_projections: bool,
    future: F,
) -> Result<T, LpmError>
where
    F: Future<Output = Result<T, LpmError>>,
{
    let future = Box::pin(future);
    if ACTIVE_TRANSACTION.try_with(|_| ()).is_ok() {
        return future.await;
    }

    let Some(initial_workspace) = discover_workspace(cwd)? else {
        let project_lock = lpm_common::project_install_lock(cwd);
        let transaction = async {
            if let Some(workspace) = discover_workspace(cwd)? {
                return Err(LpmError::Script(format!(
                    "a workspace rooted at {} appeared while waiting for the install transaction; retry the command",
                    workspace.root.display(),
                )));
            }
            future.await
        };
        return lpm_common::with_exclusive_lock_async(project_lock, transaction).await;
    };

    let workspace_root = initial_workspace.root;
    let workspace_lock = lpm_common::project_install_lock(&workspace_root);
    let transaction = async {
        let workspace = discover_workspace(cwd)?
            .ok_or_else(|| workspace_changed_while_waiting(&workspace_root, None))?;
        if workspace.root != workspace_root {
            return Err(workspace_changed_while_waiting(
                &workspace_root,
                Some(&workspace.root),
            ));
        }
        let required_importers = if require_projections {
            project_dirs
                .iter()
                .map(|project_dir| importer_key(&workspace.root, project_dir))
                .collect::<Result<Vec<_>, _>>()?
        } else {
            Vec::new()
        };
        let legacy_importers = workspace
            .members
            .iter()
            .map(|member| {
                importer_key(&workspace.root, &member.path).map(|key| (key, member.path.clone()))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let coordinator = Arc::new(WorkspaceLockfileCoordinator::new(
            &workspace.root,
            &legacy_importers,
        )?);
        let (result, remove_legacy_importers) = ACTIVE_TRANSACTION
            .scope(
                WorkspaceLockfileTransaction {
                    root: workspace.root.clone(),
                    coordinator: Arc::clone(&coordinator),
                    manifest_transactions: Mutex::new(Vec::new()),
                },
                async {
                    let result = future.await?;
                    let remove_legacy_importers = coordinator.commit(&required_importers)?;
                    commit_pending_manifest_transactions();
                    Ok::<(T, bool), LpmError>((result, remove_legacy_importers))
                },
            )
            .await?;
        if remove_legacy_importers {
            remove_member_lockfiles(&legacy_importers);
        }
        Ok(result)
    };
    lpm_common::with_exclusive_lock_async(workspace_lock, transaction).await
}

fn discover_workspace(project_dir: &Path) -> Result<Option<lpm_workspace::Workspace>, LpmError> {
    lpm_workspace::discover_workspace(project_dir)
        .map_err(|error| LpmError::Script(format!("workspace discovery failed: {error}")))
}

fn workspace_changed_while_waiting(expected: &Path, actual: Option<&Path>) -> LpmError {
    let actual = actual.map_or_else(|| "none".to_string(), |root| root.display().to_string());
    LpmError::Script(format!(
        "workspace root changed while waiting for the install transaction ({} -> {actual}); retry the command",
        expected.display(),
    ))
}

pub(crate) fn commit_manifest_transaction(transaction: crate::manifest_tx::ManifestTransaction) {
    let mut transaction = Some(transaction);
    let staged = ACTIVE_TRANSACTION
        .try_with(|workspace| {
            if let Some(transaction) = transaction.take() {
                workspace
                    .manifest_transactions
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .push(transaction);
            }
        })
        .is_ok();
    if !staged && let Some(transaction) = transaction {
        transaction.commit();
    }
}

fn commit_pending_manifest_transactions() {
    ACTIVE_TRANSACTION.with(|workspace| {
        let transactions = std::mem::take(
            &mut *workspace
                .manifest_transactions
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        );
        for transaction in transactions {
            transaction.commit();
        }
    });
}

pub(super) fn importer_key(root: &Path, target: &Path) -> Result<String, LpmError> {
    let relative = target.strip_prefix(root).map_err(|_| {
        LpmError::Script(format!(
            "workspace target {} is outside root {}",
            target.display(),
            root.display()
        ))
    })?;
    let mut importer = String::new();
    for component in relative.components() {
        let value = component.as_os_str().to_str().ok_or_else(|| {
            LpmError::Script(format!(
                "workspace target {} is not valid UTF-8",
                target.display()
            ))
        })?;
        if !importer.is_empty() {
            importer.push('/');
        }
        importer.push_str(value);
    }
    if importer.is_empty() {
        importer.push('.');
    }
    Ok(importer)
}

pub(super) fn remove_member_lockfiles(importers: &[(String, PathBuf)]) {
    for (_, member_path) in importers {
        for name in [
            lpm_lockfile::LOCKFILE_NAME,
            lpm_lockfile::BINARY_LOCKFILE_NAME,
        ] {
            let path = member_path.join(name);
            if let Err(error) = std::fs::remove_file(&path)
                && error.kind() != std::io::ErrorKind::NotFound
            {
                tracing::warn!(path = %path.display(), %error, "failed to remove obsolete member lockfile");
            }
        }
    }
}

pub(super) fn active() -> bool {
    ACTIVE_TARGET.try_with(|_| ()).is_ok()
}

pub(crate) fn read(
    fallback_path: &Path,
) -> Result<lpm_lockfile::Lockfile, lpm_lockfile::LockfileError> {
    ACTIVE_TARGET
        .try_with(|target| target.coordinator.projection(&target.importer))
        .unwrap_or_else(|_| lpm_lockfile::Lockfile::read_fast(fallback_path))
}

pub(crate) fn read_project(
    project_dir: &Path,
) -> Result<lpm_lockfile::Lockfile, lpm_lockfile::LockfileError> {
    if let Ok(lockfile) =
        ACTIVE_TARGET.try_with(|target| target.coordinator.projection(&target.importer))
    {
        return lockfile;
    }
    if let Ok(result) = ACTIVE_TRANSACTION.try_with(|transaction| {
        let importer = importer_key(&transaction.root, project_dir)
            .map_err(|error| lpm_lockfile::LockfileError::Io(error.to_string()))?;
        transaction.coordinator.projection(&importer)
    }) {
        return result;
    }
    lpm_lockfile::Lockfile::read_for_project(project_dir).map(|project| project.lockfile)
}

pub(crate) fn project_lockfile_unchanged(
    project_dir: &Path,
    expected: Option<&lpm_lockfile::Lockfile>,
) -> Result<bool, lpm_lockfile::LockfileError> {
    let current = match read_project(project_dir) {
        Ok(lockfile) => Some(lockfile),
        Err(lpm_lockfile::LockfileError::NotFound(_)) => None,
        Err(error) => return Err(error),
    };
    match (current, expected.cloned()) {
        (Some(mut current), Some(mut expected)) => {
            current.metadata.lockfile_version = lpm_lockfile::LOCKFILE_VERSION;
            expected.metadata.lockfile_version = lpm_lockfile::LOCKFILE_VERSION;
            Ok(current == expected)
        }
        (None, None) => Ok(true),
        _ => Ok(false),
    }
}

pub(crate) fn mutation_active() -> bool {
    ACTIVE_TRANSACTION.try_with(|_| ()).is_ok()
}

pub(crate) fn exists(fallback_path: &Path) -> bool {
    ACTIVE_TARGET
        .try_with(|target| target.coordinator.projection(&target.importer).is_ok())
        .unwrap_or_else(|_| lpm_lockfile::Lockfile::exists(fallback_path))
}

pub(super) fn stage(lockfile: &lpm_lockfile::Lockfile) -> bool {
    ACTIVE_TARGET
        .try_with(|target| {
            target.coordinator.stage(&target.importer, lockfile.clone());
        })
        .is_ok()
}

pub(super) fn mark_active_importer_non_persisting() {
    let _ = ACTIVE_TARGET.try_with(|target| {
        target.coordinator.mark_non_persisting(&target.importer);
    });
}

pub(crate) fn write(
    project_dir: &Path,
    lockfile: lpm_lockfile::Lockfile,
) -> Result<PathBuf, lpm_lockfile::LockfileError> {
    if stage(&lockfile) {
        return Ok(active_lockfile_path(project_dir));
    }
    if let Ok(result) = ACTIVE_TRANSACTION.try_with(|transaction| {
        let importer = importer_key(&transaction.root, project_dir)
            .map_err(|error| lpm_lockfile::LockfileError::Io(error.to_string()))?;
        transaction.coordinator.stage(&importer, lockfile.clone());
        Ok(transaction.root.join(lpm_lockfile::LOCKFILE_NAME))
    }) {
        return result;
    }
    lpm_lockfile::Lockfile::write_for_project(project_dir, lockfile)
}

pub(crate) fn active_lockfile_path(project_dir: &Path) -> PathBuf {
    if let Ok(path) =
        ACTIVE_TARGET.try_with(|target| target.coordinator.root.join(lpm_lockfile::LOCKFILE_NAME))
    {
        return path;
    }
    if let Ok(path) = ACTIVE_TRANSACTION
        .try_with(|transaction| transaction.root.join(lpm_lockfile::LOCKFILE_NAME))
    {
        return path;
    }
    lpm_lockfile::Lockfile::read_for_project(project_dir).map_or_else(
        |_| project_dir.join(lpm_lockfile::LOCKFILE_NAME),
        |project| project.path,
    )
}

pub(crate) fn active_lockfile_content(project_dir: &Path) -> String {
    ACTIVE_TARGET
        .try_with(|target| {
            target
                .coordinator
                .projection(&target.importer)
                .and_then(|lockfile| lockfile.to_toml())
                .unwrap_or_default()
        })
        .unwrap_or_else(|_| {
            lpm_lockfile::Lockfile::read_for_project(project_dir)
                .and_then(|project| project.lockfile.to_toml())
                .unwrap_or_default()
        })
}
