use super::*;

pub(crate) struct VersionTransactionScope {
    root_path: PathBuf,
    root: cap_std::fs::Dir,
    lpm: cap_std::fs::Dir,
    project_path: PathBuf,
    project: cap_std::fs::Dir,
}

impl VersionTransactionScope {
    pub(crate) fn new(
        root_path: &Path,
        root: cap_std::fs::Dir,
        lock_directory: &lpm_common::ProjectLockDirectory,
        project_path: &Path,
        project: cap_std::fs::Dir,
    ) -> Result<Self, LpmError> {
        Ok(Self {
            root_path: root_path.to_path_buf(),
            root,
            lpm: lock_directory
                .directory()
                .try_clone()
                .map_err(LpmError::Io)?,
            project_path: project_path.to_path_buf(),
            project,
        })
    }

    pub(crate) fn project_path(&self) -> &Path {
        &self.project_path
    }

    pub(crate) fn validate(&self) -> Result<(), LpmError> {
        use cap_fs_ext::DirExt as _;
        let root = open_root_directory_nofollow(&self.root_path)?;
        same_directory(&root, &self.root, &self.root_path)?;
        let lpm = self.root.open_dir_nofollow(".lpm").map_err(LpmError::Io)?;
        same_directory(&lpm, &self.lpm, &self.root_path.join(".lpm"))?;
        let target = self.target()?;
        same_directory(&target.parent, &self.project, &self.project_path)
    }

    fn target(&self) -> Result<ManifestTarget, LpmError> {
        let path = self.project_path.join("package.json");
        let relative = planned_manifest_relative_path(&self.root_path, &path)?;
        open_manifest_target(&self.root, &self.root_path, &relative)
    }

    fn state(&self, create: bool) -> Result<Option<ReleaseStateDirectory>, LpmError> {
        self.validate()?;
        open_release_state_directory_from_lpm(&self.root_path.join(".lpm"), &self.lpm, create)
    }

    pub(crate) fn ensure_no_pending(&self) -> Result<(), LpmError> {
        if let Some(state) = self.state(false)? {
            ensure_no_pending_release_transaction_in(&state)?;
        }
        Ok(())
    }

    pub(crate) fn recover(
        &self,
        allowed_manifests: &[PathBuf],
        expected: &ReleaseTransactionOperation,
    ) -> Result<ReleaseOperationRecoveryOutcome, LpmError> {
        let Some(state) = self.state(false)? else {
            return Ok(ReleaseOperationRecoveryOutcome::Continue);
        };
        match recover_pending_release_transaction_in(
            &self.root_path,
            &self.root,
            &state,
            allowed_manifests,
        )? {
            RecoveryOutcome::Completed { operation, tag } if operation == *expected => {
                Ok(ReleaseOperationRecoveryOutcome::Completed { tag })
            }
            _ => Ok(ReleaseOperationRecoveryOutcome::Continue),
        }
    }

    pub(crate) fn plan(&self, bump: &VersionBump) -> Result<ReleasePlan, LpmError> {
        self.validate()?;
        let target = self.target()?;
        same_directory(&target.parent, &self.project, &self.project_path)?;
        let bytes = read_manifest_target(&target)?;
        let manifest = parse_workspace_manifest(&self.project_path, target.display, bytes)?;
        plan_manifest(manifest, bump)
    }

    pub(crate) fn write_workspace(
        &self,
        manifests: &[PlannedManifest],
        operation: ReleaseTransactionOperation,
    ) -> Result<(), LpmError> {
        self.validate()?;
        if manifests.is_empty() {
            return Ok(());
        }
        let state = self.state(true)?.ok_or_else(|| {
            LpmError::Script("could not create the release transaction directory".into())
        })?;
        ensure_no_pending_release_transaction_in(&state)?;
        let resolved =
            resolve_planned_manifests_from_open_root(&self.root_path, &self.root, manifests)?;
        self.validate()?;
        let transaction = apply_resolved_manifests_with(
            ReleaseWriteContext {
                canonical_root: self.root_path.clone(),
                root: self.root.try_clone().map_err(LpmError::Io)?,
                state,
                expected_version_parent: None,
            },
            resolved,
            operation,
            None,
            write_manifest_target_durable,
        )?;
        self.validate().map_err(|error| {
            LpmError::Script(format!("{error}; the release journal was preserved"))
        })?;
        transaction.commit()
    }

    pub(crate) fn write<T>(
        &self,
        manifests: &[PlannedManifest],
        operation: ReleaseTransactionOperation,
        git: Option<VersionGitTransaction>,
        after_write: impl FnOnce() -> Result<T, LpmError>,
    ) -> Result<T, LpmError> {
        let state = self.state(true)?.ok_or_else(|| {
            LpmError::Script("could not create the version transaction directory".into())
        })?;
        ensure_no_pending_release_transaction_in(&state)?;
        let resolved =
            resolve_planned_manifests_from_open_root(&self.root_path, &self.root, manifests)?;
        let [manifest] = resolved.as_slice() else {
            return Err(LpmError::Script(
                "version requires exactly one package manifest".into(),
            ));
        };
        same_directory(&manifest.target.parent, &self.project, &self.project_path)?;
        self.validate()?;
        let transaction = apply_resolved_manifests_with(
            ReleaseWriteContext {
                canonical_root: self.root_path.clone(),
                root: self.root.try_clone().map_err(LpmError::Io)?,
                state,
                expected_version_parent: Some(self.project.try_clone().map_err(LpmError::Io)?),
            },
            resolved,
            operation,
            git,
            write_manifest_target_durable,
        )?;
        match self.validate().and_then(|()| after_write()) {
            Ok(value) => {
                transaction.commit()?;
                Ok(value)
            }
            Err(error) => {
                if let Err(changed) = self.validate() {
                    return Err(LpmError::Script(format!(
                        "{error}; rollback refused: {changed}; the release journal was preserved"
                    )));
                }
                transaction.rollback(error)
            }
        }
    }
}

pub(super) fn same_directory(
    current: &cap_std::fs::Dir,
    expected: &cap_std::fs::Dir,
    path: &Path,
) -> Result<(), LpmError> {
    let identity = |directory: &cap_std::fs::Dir| {
        let file = directory.try_clone()?.into_std_file();
        same_file::Handle::from_file(file)
    };
    if identity(current).map_err(LpmError::Io)? != identity(expected).map_err(LpmError::Io)? {
        return Err(LpmError::Script(format!(
            "version directory changed during the transaction: {}; retry after restoring the project",
            path.display()
        )));
    }
    Ok(())
}
