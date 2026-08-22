use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::path::{Path, PathBuf};
#[cfg(test)]
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use lpm_common::LpmError;
use rayon::prelude::*;

pub(super) struct WorkspaceLockfileCoordinator {
    root: PathBuf,
    existing: Option<lpm_lockfile::ValidatedLockfile>,
    migration_pending: bool,
    exact_graph_migration_pending: bool,
    valid_importers: BTreeSet<String>,
    existing_projection_metadata: Mutex<BTreeMap<String, Arc<lpm_lockfile::Lockfile>>>,
    projection_content: Mutex<BTreeMap<String, (u64, Arc<str>)>>,
    projection_revision: AtomicU64,
    staged: Mutex<BTreeMap<String, Arc<lpm_lockfile::Lockfile>>>,
    non_persisting_importers: Mutex<BTreeSet<String>>,
    #[cfg(test)]
    projection_materializations: AtomicUsize,
}

impl WorkspaceLockfileCoordinator {
    pub(super) fn new(
        root: &Path,
        legacy_importers: &[(String, PathBuf)],
    ) -> Result<Self, LpmError> {
        let path = root.join(lpm_lockfile::LOCKFILE_NAME);
        let root_lockfile = if path.exists() {
            let lockfile = lpm_lockfile::ValidatedLockfile::read_fast(&path).map_err(|error| {
                LpmError::Registry(format!(
                    "failed to read workspace lockfile {}: {error}",
                    path.display()
                ))
            })?;
            Some(lockfile)
        } else {
            None
        };
        let exact_graph_migration_pending = root_lockfile.as_ref().is_some_and(|lockfile| {
            lockfile.as_lockfile().metadata.lockfile_version
                < lpm_lockfile::LOCKFILE_VERSION_WITH_PACKAGE_INSTANCES
        });
        let mut migration_pending = root_lockfile.as_ref().is_some_and(|lockfile| {
            let lockfile = lockfile.as_lockfile();
            lockfile.metadata.lockfile_version
                < lpm_lockfile::LOCKFILE_VERSION_WITH_WORKSPACE_PROJECTIONS
                || lockfile.metadata.lockfile_version
                    < lpm_lockfile::LOCKFILE_VERSION_WITH_PACKAGE_INSTANCES
                || lockfile.metadata.lockfile_version
                    < lpm_lockfile::LOCKFILE_VERSION_WITH_STRUCTURED_PEERS
                    && lockfile
                        .packages
                        .iter()
                        .chain(lockfile.workspace_packages.values())
                        .any(|package| !package.peers.is_empty())
        });
        let mut union = match root_lockfile {
            Some(lockfile)
                if lockfile.as_lockfile().metadata.lockfile_version
                    >= lpm_lockfile::LOCKFILE_VERSION_WITH_WORKSPACE_PROJECTIONS =>
            {
                lockfile
            }
            Some(lockfile) => {
                let mut union = lpm_lockfile::ValidatedLockfile::new_with_resolver(
                    lockfile
                        .as_lockfile()
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
            None => lpm_lockfile::ValidatedLockfile::new(),
        };
        for (importer, importer_root) in legacy_importers {
            if union.as_lockfile().importers.contains_key(importer) {
                continue;
            }
            let importer_path = importer_root.join(lpm_lockfile::LOCKFILE_NAME);
            if !importer_path.exists() {
                continue;
            }
            let lockfile =
                lpm_lockfile::ValidatedLockfile::read_fast(&importer_path).map_err(|error| {
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
        let existing = (!union.as_lockfile().importers.is_empty()).then_some(union);
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
            exact_graph_migration_pending,
            valid_importers,
            existing_projection_metadata: Mutex::new(BTreeMap::new()),
            projection_content: Mutex::new(BTreeMap::new()),
            projection_revision: AtomicU64::new(0),
            staged: Mutex::new(BTreeMap::new()),
            non_persisting_importers: Mutex::new(BTreeSet::new()),
            #[cfg(test)]
            projection_materializations: AtomicUsize::new(0),
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
        {
            return Ok(lockfile.as_ref().clone());
        }
        let existing = self.existing.as_ref().ok_or_else(|| {
            lpm_lockfile::LockfileError::NotFound("workspace lockfile does not exist".to_string())
        })?;
        #[cfg(test)]
        self.projection_materializations
            .fetch_add(1, Ordering::Relaxed);
        existing.project_importer(importer)
    }

    fn projection_content(&self, importer: &str) -> Result<Arc<str>, lpm_lockfile::LockfileError> {
        loop {
            let revision = self.projection_revision.load(Ordering::Acquire);
            if let Some(content) = self
                .projection_content
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .get(importer)
                .filter(|(cached_revision, _)| *cached_revision == revision)
                .map(|(_, content)| Arc::clone(content))
            {
                return Ok(content);
            }

            let content = Arc::<str>::from(self.projection(importer)?.to_toml()?);
            if self.projection_revision.load(Ordering::Acquire) == revision {
                self.projection_content
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .insert(importer.to_string(), (revision, Arc::clone(&content)));
                return Ok(content);
            }
        }
    }

    pub(super) fn projection_metadata_shared(
        &self,
        importer: &str,
    ) -> Result<Arc<lpm_lockfile::Lockfile>, lpm_lockfile::LockfileError> {
        if let Some(lockfile) = self
            .staged
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(importer)
            .map(Arc::clone)
        {
            return Ok(lockfile);
        }
        let mut existing_projection_metadata = self
            .existing_projection_metadata
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(lockfile) = existing_projection_metadata.get(importer) {
            return Ok(Arc::clone(lockfile));
        }
        let existing = self.existing.as_ref().ok_or_else(|| {
            lpm_lockfile::LockfileError::NotFound("workspace lockfile does not exist".to_string())
        })?;
        #[cfg(test)]
        self.projection_materializations
            .fetch_add(1, Ordering::Relaxed);
        let lockfile = Arc::new(existing.project_importer_metadata(importer)?);
        existing_projection_metadata.insert(importer.to_string(), Arc::clone(&lockfile));
        Ok(lockfile)
    }

    pub(super) fn with_projection_packages<R>(
        &self,
        importer: &str,
        inspect: impl FnOnce(Arc<lpm_lockfile::Lockfile>, &[&lpm_lockfile::LockedPackage]) -> R,
    ) -> Result<R, lpm_lockfile::LockfileError> {
        if let Some(lockfile) = self
            .staged
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(importer)
            .map(Arc::clone)
        {
            let packages = lockfile.packages.iter().collect::<Vec<_>>();
            return Ok(inspect(Arc::clone(&lockfile), &packages));
        }
        let metadata = self.projection_metadata_shared(importer)?;
        let packages = self
            .existing
            .as_ref()
            .ok_or_else(|| {
                lpm_lockfile::LockfileError::NotFound(
                    "workspace lockfile does not exist".to_string(),
                )
            })?
            .importer_packages(importer)?;
        Ok(inspect(metadata, &packages))
    }

    pub(super) fn preload_existing_projection_metadata(
        &self,
        importers: &[&str],
    ) -> Result<(), lpm_lockfile::LockfileError> {
        let existing = self.existing.as_ref().ok_or_else(|| {
            lpm_lockfile::LockfileError::NotFound("workspace lockfile does not exist".to_string())
        })?;
        let missing = {
            let existing_projection_metadata = self
                .existing_projection_metadata
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            importers
                .iter()
                .copied()
                .collect::<BTreeSet<_>>()
                .into_iter()
                .filter(|importer| !existing_projection_metadata.contains_key(*importer))
                .collect::<Vec<_>>()
        };
        let projections = missing
            .into_par_iter()
            .map(|importer| {
                #[cfg(test)]
                self.projection_materializations
                    .fetch_add(1, Ordering::Relaxed);
                existing
                    .project_importer_metadata(importer)
                    .map(|lockfile| (importer.to_string(), Arc::new(lockfile)))
            })
            .collect::<Result<Vec<_>, _>>()?;
        self.existing_projection_metadata
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .extend(projections);
        Ok(())
    }

    #[cfg(test)]
    fn projection_materialization_count(&self) -> usize {
        self.projection_materializations.load(Ordering::Relaxed)
    }

    fn stage(&self, importer: &str, lockfile: lpm_lockfile::Lockfile) {
        self.staged
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(importer.to_string(), Arc::new(lockfile));
        self.projection_revision.fetch_add(1, Ordering::Release);
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
            && !self.migration_pending
            && let Some(existing) = &self.existing
            && existing
                .as_lockfile()
                .importers
                .keys()
                .all(|importer| self.valid_importers.contains(importer))
            && required_importers.iter().all(|importer| {
                existing.as_lockfile().importers.contains_key(importer)
                    || non_persisting_importers.contains(importer)
            })
        {
            return Ok(true);
        }
        for importer in staged.keys() {
            if !self.valid_importers.contains(importer) {
                return Err(LpmError::Registry(format!(
                    "workspace importer {importer:?} is no longer a member; no lockfile changes were committed"
                )));
            }
        }
        for importer in required_importers {
            let has_projection = staged.contains_key(importer)
                || self.existing.as_ref().is_some_and(|existing| {
                    self.valid_importers.contains(importer)
                        && existing.as_lockfile().importers.contains_key(importer)
                });
            if !has_projection && !non_persisting_importers.contains(importer) {
                return Err(LpmError::Registry(format!(
                    "workspace importer {importer:?} completed without producing a lockfile projection"
                )));
            }
        }
        if self.exact_graph_migration_pending
            && let Some(existing) = &self.existing
            && let Some(importer) = existing
                .as_lockfile()
                .importers
                .keys()
                .filter(|importer| self.valid_importers.contains(*importer))
                .find(|importer| {
                    !staged.contains_key(*importer) && !non_persisting_importers.contains(*importer)
                })
        {
            return Err(LpmError::Registry(format!(
                "workspace lockfile upgrade requires a fresh projection for importer {importer:?}; run `lpm install --recursive` from the workspace root"
            )));
        }

        let union = if let Some(existing) = &self.existing
            && !self.migration_pending
        {
            let replacements = staged
                .iter()
                .map(|(importer, lockfile)| (importer.clone(), lockfile.as_ref().clone()))
                .collect();
            existing
                .update_workspace_importers(&self.valid_importers, replacements)
                .map_err(lockfile_error)?
        } else {
            let mut projections = BTreeMap::new();
            if let Some(existing) = &self.existing
                && !self.exact_graph_migration_pending
            {
                for importer in existing
                    .as_lockfile()
                    .importers
                    .keys()
                    .filter(|importer| self.valid_importers.contains(*importer))
                {
                    #[cfg(test)]
                    self.projection_materializations
                        .fetch_add(1, Ordering::Relaxed);
                    projections.insert(
                        importer.clone(),
                        existing
                            .project_importer(importer)
                            .map_err(lockfile_error)?,
                    );
                }
            }
            for (importer, lockfile) in staged.iter() {
                projections.insert(importer.clone(), lockfile.as_ref().clone());
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
            union
        };

        let path = self.root.join(lpm_lockfile::LOCKFILE_NAME);
        lpm_lockfile::ensure_gitattributes(&self.root).map_err(lockfile_error)?;
        if !self.migration_pending
            && self
                .existing
                .as_ref()
                .is_some_and(|existing| existing.as_lockfile() == &union)
        {
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
    static ACTIVE_PROJECT_INSTALL_ROOT: PathBuf;
}

pub(super) async fn with_project_install_lock<F, T>(
    project_root: &Path,
    future: F,
) -> Result<T, LpmError>
where
    F: Future<Output = Result<T, LpmError>>,
{
    let canonical_root = project_root.canonicalize().map_err(|error| {
        LpmError::Io(std::io::Error::new(
            error.kind(),
            format!(
                "failed to resolve project lock root {}: {error}",
                project_root.display()
            ),
        ))
    })?;
    if let Ok(active_root) = ACTIVE_PROJECT_INSTALL_ROOT.try_with(Clone::clone) {
        if active_root != canonical_root {
            return Err(LpmError::Script(format!(
                "nested install transaction changed project root ({} -> {}); retry the command",
                active_root.display(),
                canonical_root.display(),
            )));
        }
        return future.await;
    }

    let project_directory =
        cap_std::fs::Dir::open_ambient_dir(&canonical_root, cap_std::ambient_authority()).map_err(
            |error| {
                LpmError::Io(std::io::Error::new(
                    error.kind(),
                    format!(
                        "failed to open project lock root {}: {error}",
                        canonical_root.display()
                    ),
                ))
            },
        )?;
    let lock_directory =
        lpm_common::ProjectLockDirectory::open_or_create(&project_directory, &canonical_root)?;
    let transaction = ACTIVE_PROJECT_INSTALL_ROOT.scope(canonical_root.clone(), async {
        crate::release_plan::ensure_no_pending_release_transaction(&canonical_root)?;
        future.await
    });
    lpm_common::with_project_exclusive_lock_async(
        lock_directory,
        lpm_common::ProjectLockKind::Install,
        transaction,
    )
    .await
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

pub(crate) async fn scope_member_install<F, T>(project_dir: &Path, future: F) -> Result<T, LpmError>
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
    if ACTIVE_PROJECT_INSTALL_ROOT.try_with(|_| ()).is_ok() {
        return future.await;
    }
    let Some(initial_workspace) = discover_workspace(project_dir)? else {
        let transaction = async {
            if let Some(workspace) = discover_workspace(project_dir)? {
                return Err(LpmError::Script(format!(
                    "a workspace rooted at {} appeared while waiting for the install transaction; retry the command",
                    workspace.root.display(),
                )));
            }
            future.await
        };
        return with_project_install_lock(project_dir, transaction).await;
    };
    let workspace_root = initial_workspace.root;
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
        let transaction_root = workspace.root.clone();
        let (result, remove_legacy_importers) = ACTIVE_TRANSACTION
            .scope(
                WorkspaceLockfileTransaction {
                    root: transaction_root,
                    coordinator: Arc::clone(&coordinator),
                    manifest_transactions: Mutex::new(Vec::new()),
                },
                async {
                    let result = scope(
                        Arc::clone(&coordinator),
                        Arc::<str>::from(importer.as_str()),
                        future,
                    )
                    .await?;
                    let remove_legacy_importers =
                        coordinator.commit(std::slice::from_ref(&importer))?;
                    commit_pending_manifest_transactions();
                    Ok::<_, LpmError>((result, remove_legacy_importers))
                },
            )
            .await?;
        if remove_legacy_importers {
            remove_member_lockfiles(&legacy_importers);
        }
        Ok(result)
    };
    with_project_install_lock(&workspace_root, transaction).await
}

pub(crate) async fn scope_member_project_mutation<F, T>(
    project_dir: &Path,
    future: F,
) -> Result<T, LpmError>
where
    F: Future<Output = Result<T, LpmError>>,
{
    let future = Box::pin(future);
    if ACTIVE_TRANSACTION.try_with(|_| ()).is_ok()
        || ACTIVE_PROJECT_INSTALL_ROOT.try_with(|_| ()).is_ok()
    {
        return future.await;
    }

    let initial_workspace = discover_workspace(project_dir)?;
    let lock_root = initial_workspace.as_ref().map_or_else(
        || project_dir.to_path_buf(),
        |workspace| workspace.root.clone(),
    );
    let expected_workspace_root = initial_workspace.map(|workspace| workspace.root);
    let transaction = async {
        let current_workspace_root =
            discover_workspace(project_dir)?.map(|workspace| workspace.root);
        if current_workspace_root != expected_workspace_root {
            return Err(workspace_changed_while_waiting(
                expected_workspace_root.as_deref().unwrap_or(project_dir),
                current_workspace_root.as_deref(),
            ));
        }
        future.await
    };
    with_project_install_lock(&lock_root, transaction).await
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
    if ACTIVE_TRANSACTION.try_with(|_| ()).is_ok()
        || ACTIVE_PROJECT_INSTALL_ROOT.try_with(|_| ()).is_ok()
    {
        return future.await;
    }

    let Some(initial_workspace) = discover_workspace(cwd)? else {
        let transaction = async {
            if let Some(workspace) = discover_workspace(cwd)? {
                return Err(LpmError::Script(format!(
                    "a workspace rooted at {} appeared while waiting for the install transaction; retry the command",
                    workspace.root.display(),
                )));
            }
            future.await
        };
        return with_project_install_lock(cwd, transaction).await;
    };

    let workspace_root = initial_workspace.root;
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
    with_project_install_lock(&workspace_root, transaction).await
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

pub(crate) fn read_metadata_shared(
    fallback_path: &Path,
) -> Result<Arc<lpm_lockfile::Lockfile>, lpm_lockfile::LockfileError> {
    ACTIVE_TARGET
        .try_with(|target| {
            target
                .coordinator
                .projection_metadata_shared(&target.importer)
        })
        .unwrap_or_else(|_| lpm_lockfile::Lockfile::read_fast(fallback_path).map(Arc::new))
}

pub(crate) fn read_full_shared(
    fallback_path: &Path,
) -> Result<Arc<lpm_lockfile::Lockfile>, lpm_lockfile::LockfileError> {
    ACTIVE_TARGET
        .try_with(|target| {
            target
                .coordinator
                .projection(&target.importer)
                .map(Arc::new)
        })
        .unwrap_or_else(|_| lpm_lockfile::Lockfile::read_fast(fallback_path).map(Arc::new))
}

pub(crate) fn with_package_rows<R>(
    fallback_path: &Path,
    inspect: impl FnOnce(Arc<lpm_lockfile::Lockfile>, &[&lpm_lockfile::LockedPackage]) -> R,
) -> Result<R, lpm_lockfile::LockfileError> {
    if ACTIVE_TARGET.try_with(|_| ()).is_ok() {
        return ACTIVE_TARGET.with(|target| {
            target
                .coordinator
                .with_projection_packages(&target.importer, inspect)
        });
    }
    let lockfile = Arc::new(lpm_lockfile::Lockfile::read_fast(fallback_path)?);
    let packages = lockfile.packages.iter().collect::<Vec<_>>();
    Ok(inspect(Arc::clone(&lockfile), &packages))
}

pub(crate) fn package_count(fallback_path: &Path) -> Result<usize, lpm_lockfile::LockfileError> {
    with_package_rows(fallback_path, |_, packages| packages.len())
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

pub(crate) fn read_project_metadata_shared(
    project_dir: &Path,
) -> Result<Arc<lpm_lockfile::Lockfile>, lpm_lockfile::LockfileError> {
    if let Ok(lockfile) = ACTIVE_TARGET.try_with(|target| {
        target
            .coordinator
            .projection_metadata_shared(&target.importer)
    }) {
        return lockfile;
    }
    if let Ok(result) = ACTIVE_TRANSACTION.try_with(|transaction| {
        let importer = importer_key(&transaction.root, project_dir)
            .map_err(|error| lpm_lockfile::LockfileError::Io(error.to_string()))?;
        transaction
            .coordinator
            .projection_metadata_shared(&importer)
    }) {
        return result;
    }
    lpm_lockfile::Lockfile::read_for_project(project_dir).map(|project| Arc::new(project.lockfile))
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
        .try_with(|target| {
            target
                .coordinator
                .projection_metadata_shared(&target.importer)
                .is_ok()
        })
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

pub(crate) fn active_lockfile_content(project_dir: &Path) -> Arc<str> {
    ACTIVE_TARGET
        .try_with(|target| {
            target
                .coordinator
                .projection_content(&target.importer)
                .unwrap_or_default()
        })
        .unwrap_or_else(|_| {
            Arc::from(
                lpm_lockfile::Lockfile::read_for_project(project_dir)
                    .and_then(|project| project.lockfile.to_toml())
                    .unwrap_or_default(),
            )
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_REGISTRY_SOURCE: &str = "registry+https://registry.npmjs.org";

    fn exact_package(name: &str, version: &str, graph_path: &str) -> lpm_lockfile::LockedPackage {
        lpm_lockfile::LockedPackage {
            instance_id: Some(lpm_common::PackageInstanceId::derive(
                name,
                version,
                TEST_REGISTRY_SOURCE,
                graph_path,
            )),
            name: name.to_string(),
            version: version.to_string(),
            source: Some(TEST_REGISTRY_SOURCE.to_string()),
            ..lpm_lockfile::LockedPackage::default()
        }
    }

    fn add_exact_root(
        lockfile: &mut lpm_lockfile::Lockfile,
        local_name: &str,
        requested: &str,
        package: lpm_lockfile::LockedPackage,
    ) {
        let instance_id = package.instance_id.expect("exact fixture package id");
        let package_name = package.name.clone();
        let version = package.version.clone();
        let source = package.source.clone();
        lockfile.add_package(package);
        lockfile
            .importers
            .entry(".".to_string())
            .or_default()
            .dependencies
            .insert(local_name.to_string(), requested.to_string());
        lockfile.root_resolutions.insert(
            local_name.to_string(),
            lpm_lockfile::LockedRootResolution {
                instance_id: Some(instance_id),
                package: package_name,
                version,
                source,
            },
        );
    }

    fn coordinator_with_existing_projection() -> (tempfile::TempDir, WorkspaceLockfileCoordinator) {
        let directory = tempfile::tempdir().expect("create workspace directory");
        let mut standalone = lpm_lockfile::Lockfile::new();
        add_exact_root(
            &mut standalone,
            "axois",
            "^1.0.0",
            exact_package("dependency", "1.0.0", "root/dependency"),
        );
        let mut union = lpm_lockfile::Lockfile::new();
        union
            .absorb_importer(".", standalone)
            .expect("build workspace union");
        union
            .write_to_file(&directory.path().join(lpm_lockfile::LOCKFILE_NAME))
            .expect("write workspace union");
        let coordinator =
            WorkspaceLockfileCoordinator::new(directory.path(), &[]).expect("load workspace union");
        (directory, coordinator)
    }

    #[test]
    fn coordinator_reuses_immutable_projection_metadata_after_first_materialization() {
        let (_directory, coordinator) = coordinator_with_existing_projection();

        coordinator
            .projection_metadata_shared(".")
            .expect("first projection");
        coordinator
            .projection_metadata_shared(".")
            .expect("second projection");

        assert_eq!(coordinator.projection_materialization_count(), 1);
    }

    #[test]
    fn preloaded_projection_metadata_is_reused_by_subsequent_readers() {
        let (_directory, coordinator) = coordinator_with_existing_projection();

        coordinator
            .preload_existing_projection_metadata(&["."])
            .expect("preload projection");
        coordinator
            .projection_metadata_shared(".")
            .expect("first shared reader");
        coordinator
            .projection_metadata_shared(".")
            .expect("second shared reader");

        assert_eq!(coordinator.projection_materialization_count(), 1);
    }

    #[test]
    fn package_row_view_uses_metadata_projection_without_owned_package_clones() {
        let (_directory, coordinator) = coordinator_with_existing_projection();

        let observed = coordinator
            .with_projection_packages(".", |metadata, packages| {
                (metadata.packages.len(), packages[0].name.clone())
            })
            .expect("inspect package rows");

        assert_eq!(observed, (0, "dependency".to_string()));
    }

    #[test]
    fn owned_projection_remains_complete_after_metadata_is_cached() {
        let (_directory, coordinator) = coordinator_with_existing_projection();
        coordinator
            .projection_metadata_shared(".")
            .expect("cache projection metadata");

        let projection = coordinator.projection(".").expect("materialize projection");

        assert_eq!(projection.packages[0].name, "dependency");
    }

    #[test]
    fn staged_projection_takes_precedence_over_cached_existing_projection() {
        let (_directory, coordinator) = coordinator_with_existing_projection();
        coordinator
            .projection(".")
            .expect("cache existing projection");
        let mut staged = lpm_lockfile::Lockfile::new();
        add_exact_root(
            &mut staged,
            "replacement",
            "2.0.0",
            exact_package("replacement", "2.0.0", "root/replacement"),
        );
        coordinator.stage(".", staged.clone());

        assert_eq!(coordinator.projection(".").unwrap(), staged);
    }

    #[test]
    fn unchanged_commit_reuses_validated_union_without_materializing_importers() {
        let (_directory, coordinator) = coordinator_with_existing_projection();

        assert!(coordinator.commit(&[".".to_string()]).unwrap());

        assert_eq!(coordinator.projection_materialization_count(), 0);
    }

    #[test]
    fn unchanged_commit_rejects_a_required_importer_missing_from_the_union() {
        let (_directory, coordinator) = coordinator_with_existing_projection();

        let error = coordinator
            .commit(&["packages/missing".to_string()])
            .expect_err("missing required importer must fail");

        assert!(
            error
                .to_string()
                .contains("without producing a lockfile projection")
        );
    }

    #[test]
    fn unchanged_commit_prunes_importers_that_are_no_longer_workspace_members() {
        let directory = tempfile::tempdir().expect("create workspace directory");
        let mut union = lpm_lockfile::Lockfile::new();
        for importer in [".", "packages/removed"] {
            let mut standalone = lpm_lockfile::Lockfile::new();
            let name = if importer == "." {
                "dependency-root"
            } else {
                "dependency-removed"
            };
            add_exact_root(
                &mut standalone,
                name,
                "1.0.0",
                exact_package(name, "1.0.0", &format!("{importer}/{name}")),
            );
            union
                .absorb_importer(importer, standalone)
                .expect("build workspace union");
        }
        union
            .write_to_file(&directory.path().join(lpm_lockfile::LOCKFILE_NAME))
            .expect("write workspace union");
        let coordinator =
            WorkspaceLockfileCoordinator::new(directory.path(), &[]).expect("load workspace union");

        assert!(coordinator.commit(&[".".to_string()]).unwrap());

        let committed = lpm_lockfile::ValidatedLockfile::read_fast(
            &directory.path().join(lpm_lockfile::LOCKFILE_NAME),
        )
        .expect("read committed workspace union");
        assert!(
            !committed
                .as_lockfile()
                .importers
                .contains_key("packages/removed")
        );
    }

    #[test]
    fn changed_commit_reuses_untouched_union_rows_without_materializing_importers() {
        let directory = tempfile::tempdir().expect("create workspace directory");
        let importers = ["packages/first", "packages/second"];
        let mut union = lpm_lockfile::Lockfile::new();
        for (index, importer) in importers.iter().enumerate() {
            let mut standalone = lpm_lockfile::Lockfile::new();
            let name = format!("dependency-{index}");
            add_exact_root(
                &mut standalone,
                &name,
                "1.0.0",
                exact_package(&name, "1.0.0", &format!("{importer}/{name}")),
            );
            union
                .absorb_importer(importer, standalone)
                .expect("build workspace union");
        }
        union
            .write_to_file(&directory.path().join(lpm_lockfile::LOCKFILE_NAME))
            .expect("write workspace union");
        let legacy_importers = importers
            .iter()
            .map(|importer| (importer.to_string(), directory.path().join(importer)))
            .collect::<Vec<_>>();
        let coordinator = WorkspaceLockfileCoordinator::new(directory.path(), &legacy_importers)
            .expect("load workspace union");
        let mut replacement = lpm_lockfile::Lockfile::new();
        add_exact_root(
            &mut replacement,
            "replacement",
            "2.0.0",
            exact_package("replacement", "2.0.0", "packages/first/replacement"),
        );
        coordinator.stage("packages/first", replacement);

        coordinator
            .commit(&["packages/first".to_string()])
            .expect("commit changed importer");

        assert_eq!(coordinator.projection_materialization_count(), 0);
    }

    #[test]
    fn current_projections_upgrade_v12_workspace_union_to_exact_instance_graph() {
        let directory = tempfile::tempdir().expect("create workspace directory");
        let importers = [".", "packages/app"];
        let source = "registry+https://registry.npmjs.org";
        let mut union = lpm_lockfile::Lockfile::new();
        for (index, importer) in importers.iter().enumerate() {
            let mut legacy = lpm_lockfile::Lockfile::new();
            legacy.metadata.lockfile_version = lpm_lockfile::LOCKFILE_VERSION_WITH_STRUCTURED_PEERS;
            legacy
                .importers
                .insert(".".to_string(), lpm_lockfile::ImporterSnapshot::default());
            legacy.add_package(lpm_lockfile::LockedPackage {
                name: format!("legacy-{index}"),
                version: "1.0.0".to_string(),
                source: Some(source.to_string()),
                ..lpm_lockfile::LockedPackage::default()
            });
            union
                .absorb_importer(importer, legacy)
                .expect("build legacy workspace union");
        }
        union
            .write_to_file(&directory.path().join(lpm_lockfile::LOCKFILE_NAME))
            .expect("write legacy workspace union");

        let legacy_importers = vec![(
            "packages/app".to_string(),
            directory.path().join("packages/app"),
        )];
        let coordinator = WorkspaceLockfileCoordinator::new(directory.path(), &legacy_importers)
            .expect("load legacy workspace union");
        for (index, importer) in importers.iter().enumerate() {
            let parent_name = format!("parent-{index}");
            let child_name = format!("child-{index}");
            let parent_id = lpm_common::PackageInstanceId::derive(
                &parent_name,
                "1.0.0",
                source,
                &format!("{importer}/parent"),
            );
            let child_id = lpm_common::PackageInstanceId::derive(
                &child_name,
                "1.0.0",
                source,
                &format!("{importer}/parent/child"),
            );
            let mut projection = lpm_lockfile::Lockfile::new();
            add_exact_root(
                &mut projection,
                &parent_name,
                "1.0.0",
                lpm_lockfile::LockedPackage {
                    instance_id: Some(parent_id),
                    name: parent_name.clone(),
                    version: "1.0.0".to_string(),
                    source: Some(source.to_string()),
                    dependencies: vec![format!("{child_name}@1.0.0")],
                    dependency_targets: [(child_name.clone(), child_id)].into(),
                    ..lpm_lockfile::LockedPackage::default()
                },
            );
            projection.add_package(lpm_lockfile::LockedPackage {
                instance_id: Some(child_id),
                name: child_name.clone(),
                version: "1.0.0".to_string(),
                source: Some(source.to_string()),
                ..lpm_lockfile::LockedPackage::default()
            });
            coordinator.stage(importer, projection);
        }

        coordinator
            .commit(&importers.map(str::to_string))
            .expect("commit exact workspace projections");

        let committed = lpm_lockfile::ValidatedLockfile::read_fast(
            &directory.path().join(lpm_lockfile::LOCKFILE_NAME),
        )
        .expect("read upgraded workspace union");
        assert_eq!(
            committed.as_lockfile().metadata.lockfile_version,
            lpm_lockfile::LOCKFILE_VERSION_WITH_PACKAGE_INSTANCES,
        );
        for importer in importers {
            let projection = committed.project_importer(importer).unwrap();
            assert!(
                projection
                    .packages
                    .iter()
                    .all(|package| package.instance_id.is_some())
            );
            assert!(
                projection
                    .packages
                    .iter()
                    .any(|package| !package.dependency_targets.is_empty())
            );
            assert!(
                projection
                    .root_resolutions
                    .values()
                    .all(|root| root.instance_id.is_some())
            );
        }
    }

    #[test]
    fn partial_v13_workspace_upgrade_fails_without_rewriting_v12_union() {
        let directory = tempfile::tempdir().expect("create workspace directory");
        let source = "registry+https://registry.npmjs.org";
        let mut union = lpm_lockfile::Lockfile::new();
        for importer in [".", "packages/app"] {
            let mut legacy = lpm_lockfile::Lockfile::new();
            legacy.metadata.lockfile_version = lpm_lockfile::LOCKFILE_VERSION_WITH_STRUCTURED_PEERS;
            legacy
                .importers
                .insert(".".to_string(), lpm_lockfile::ImporterSnapshot::default());
            legacy.add_package(lpm_lockfile::LockedPackage {
                name: format!("legacy-{}", importer.replace(['.', '/'], "root")),
                version: "1.0.0".to_string(),
                source: Some(source.to_string()),
                ..lpm_lockfile::LockedPackage::default()
            });
            union.absorb_importer(importer, legacy).unwrap();
        }
        let lockfile_path = directory.path().join(lpm_lockfile::LOCKFILE_NAME);
        union.write_to_file(&lockfile_path).unwrap();
        let before = std::fs::read(&lockfile_path).unwrap();

        let legacy_importers = vec![(
            "packages/app".to_string(),
            directory.path().join("packages/app"),
        )];
        let coordinator =
            WorkspaceLockfileCoordinator::new(directory.path(), &legacy_importers).unwrap();
        let instance_id = lpm_common::PackageInstanceId::derive(
            "current-root",
            "1.0.0",
            source,
            "root/current-root",
        );
        let mut current = lpm_lockfile::Lockfile::new();
        add_exact_root(
            &mut current,
            "current-root",
            "1.0.0",
            lpm_lockfile::LockedPackage {
                instance_id: Some(instance_id),
                name: "current-root".to_string(),
                version: "1.0.0".to_string(),
                source: Some(source.to_string()),
                ..lpm_lockfile::LockedPackage::default()
            },
        );
        coordinator.stage(".", current);

        let error = coordinator
            .commit(&[".".to_string()])
            .expect_err("partial exact-graph migration must fail");

        assert!(error.to_string().contains("packages/app"));
        assert!(error.to_string().contains("--recursive"));
        assert_eq!(std::fs::read(&lockfile_path).unwrap(), before);
    }

    #[tokio::test]
    async fn active_lockfile_content_materializes_each_importer_once() {
        let (directory, coordinator) = coordinator_with_existing_projection();
        let coordinator = Arc::new(coordinator);

        scope(Arc::clone(&coordinator), Arc::<str>::from("."), async {
            for _ in 0..3 {
                assert!(!active_lockfile_content(directory.path()).is_empty());
            }
        })
        .await;

        assert_eq!(coordinator.projection_materialization_count(), 1);
    }

    #[tokio::test]
    async fn staging_an_importer_invalidates_its_cached_lockfile_content() {
        let (directory, coordinator) = coordinator_with_existing_projection();
        let coordinator = Arc::new(coordinator);
        let before = scope(Arc::clone(&coordinator), Arc::<str>::from("."), async {
            active_lockfile_content(directory.path())
        })
        .await;
        let mut staged = lpm_lockfile::Lockfile::new();
        add_exact_root(
            &mut staged,
            "replacement",
            "2.0.0",
            exact_package("replacement", "2.0.0", "root/replacement"),
        );
        coordinator.stage(".", staged);

        let after = scope(Arc::clone(&coordinator), Arc::<str>::from("."), async {
            active_lockfile_content(directory.path())
        })
        .await;

        assert_ne!(after, before);
        assert!(after.contains("replacement"));
    }

    #[tokio::test]
    async fn typosquat_guard_reuses_active_projection_after_union_lockfile_changes() {
        let (directory, coordinator) = coordinator_with_existing_projection();
        coordinator
            .projection_metadata_shared(".")
            .expect("preload importer metadata");
        std::fs::write(
            directory.path().join(lpm_lockfile::LOCKFILE_NAME),
            "invalid lockfile",
        )
        .expect("replace union lockfile after coordinator load");
        let coordinator = Arc::new(coordinator);

        let locked = scope(Arc::clone(&coordinator), Arc::<str>::from("."), async {
            crate::typosquat_guard::locked_direct_names(directory.path())
        })
        .await;

        assert!(locked.contains("axois"));
        assert_eq!(coordinator.projection_materialization_count(), 1);
    }
}
