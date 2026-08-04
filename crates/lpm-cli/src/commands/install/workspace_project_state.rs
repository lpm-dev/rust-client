use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

static NEXT_TRANSACTION_ID: AtomicU64 = AtomicU64::new(0);

const PROJECT_STATE_FILES: &[&str] = &[
    ".gitignore",
    ".lpm/install-hash",
    ".lpm/overrides-state.json",
    ".lpm/patch-state.json",
    ".lpm/trust-snapshot.json",
    ".lpm/build-state.json",
    ".lpm/has-local-sources",
];

pub(super) struct WorkspaceProjectStateCoordinator {
    transactions: Box<[std::sync::Mutex<Option<WorkspaceProjectStateTransaction>>]>,
}

impl WorkspaceProjectStateCoordinator {
    pub(super) fn new(target_count: usize) -> Self {
        Self {
            transactions: (0..target_count)
                .map(|_| std::sync::Mutex::new(None))
                .collect(),
        }
    }

    pub(super) fn commit(&self) {
        for transaction in &self.transactions {
            if let Some(transaction) = transaction
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take()
            {
                transaction.commit();
            }
        }
    }

    pub(super) fn rollback(&self) -> Vec<String> {
        let mut errors = Vec::new();
        for transaction in self.transactions.iter().rev() {
            if let Some(transaction) = transaction
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take()
            {
                errors.extend(transaction.rollback());
            }
        }
        errors
    }
}

struct WorkspaceProjectStateTask {
    coordinator: Arc<WorkspaceProjectStateCoordinator>,
    index: usize,
    entered: AtomicBool,
}

impl WorkspaceProjectStateTask {
    fn enter(&self, project_dir: &Path) -> std::io::Result<()> {
        if self.entered.swap(true, Ordering::AcqRel) {
            return Ok(());
        }
        let transaction = WorkspaceProjectStateTransaction::begin(project_dir)?;
        *self.coordinator.transactions[self.index]
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(transaction);
        Ok(())
    }
}

tokio::task_local! {
    static ACTIVE_TASK: WorkspaceProjectStateTask;
}

pub(super) async fn scope<F>(
    coordinator: Arc<WorkspaceProjectStateCoordinator>,
    index: usize,
    future: F,
) -> F::Output
where
    F: Future,
{
    ACTIVE_TASK
        .scope(
            WorkspaceProjectStateTask {
                coordinator,
                index,
                entered: AtomicBool::new(false),
            },
            future,
        )
        .await
}

pub(super) fn enter(project_dir: &Path) -> std::io::Result<()> {
    ACTIVE_TASK
        .try_with(|task| task.enter(project_dir))
        .unwrap_or(Ok(()))
}

pub(super) struct WorkspaceProjectStateTransaction {
    project_dir: PathBuf,
    backup_root: Option<PathBuf>,
    moved_paths: Vec<MovedPath>,
    file_snapshots: Vec<FileSnapshot>,
    dot_lpm_existed: bool,
    finalized: bool,
}

struct MovedPath {
    original: PathBuf,
    backup: Option<PathBuf>,
    existed: bool,
}

struct FileSnapshot {
    path: PathBuf,
    original: Option<Vec<u8>>,
}

impl WorkspaceProjectStateTransaction {
    pub(super) fn begin(project_dir: &Path) -> std::io::Result<Self> {
        let dot_lpm = project_dir.join(".lpm");
        let dot_lpm_existed = match dot_lpm.symlink_metadata() {
            Ok(metadata) if metadata.is_dir() && !lpm_common::is_symlink_or_junction(&metadata) => {
                true
            }
            Ok(_) => {
                return Err(std::io::Error::other(format!(
                    "refusing workspace transaction because {} is not a real directory",
                    dot_lpm.display()
                )));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
            Err(error) => return Err(error),
        };
        let package_json = project_dir.join("package.json");
        let package_json_bytes =
            lpm_common::read_file_capped(&package_json, lpm_common::CONFIG_FILE_SIZE_CAP_BYTES)
                .map_err(std::io::Error::other)?;
        let mut file_snapshots = Vec::with_capacity(PROJECT_STATE_FILES.len() + 1);
        file_snapshots.push(FileSnapshot {
            path: package_json,
            original: Some(package_json_bytes),
        });
        for relative in PROJECT_STATE_FILES {
            let path = project_dir.join(relative);
            let original =
                match lpm_common::read_file_capped(&path, lpm_common::CONFIG_FILE_SIZE_CAP_BYTES) {
                    Ok(bytes) => Some(bytes),
                    Err(lpm_common::BoundedReadError::NotFound { .. }) => None,
                    Err(error) => return Err(std::io::Error::other(error)),
                };
            file_snapshots.push(FileSnapshot { path, original });
        }

        let mut transaction = Self {
            project_dir: project_dir.to_path_buf(),
            backup_root: None,
            moved_paths: Vec::with_capacity(3),
            file_snapshots,
            dot_lpm_existed,
            finalized: false,
        };
        for (relative, backup_name) in [
            ("node_modules", "node_modules"),
            (".lpm/wrappers", "wrappers"),
            (".lpm/hoisted", "hoisted"),
        ] {
            transaction.move_to_backup(relative, backup_name)?;
        }
        Ok(transaction)
    }

    fn move_to_backup(&mut self, relative: &str, backup_name: &str) -> std::io::Result<()> {
        let original = self.project_dir.join(relative);
        let existed = match original.symlink_metadata() {
            Ok(_) => true,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
            Err(error) => return Err(error),
        };
        let backup = if existed {
            let backup = self.reserve_backup_root()?.join(backup_name);
            std::fs::rename(&original, &backup)?;
            Some(backup)
        } else {
            None
        };
        self.moved_paths.push(MovedPath {
            original,
            backup,
            existed,
        });
        Ok(())
    }

    fn reserve_backup_root(&mut self) -> std::io::Result<&Path> {
        if self.backup_root.is_none() {
            let dot_lpm = self.project_dir.join(".lpm");
            std::fs::create_dir_all(&dot_lpm)?;
            loop {
                let transaction_id = NEXT_TRANSACTION_ID.fetch_add(1, Ordering::Relaxed);
                let candidate = dot_lpm.join(format!(
                    ".workspace-install-rollback-{}-{transaction_id}",
                    std::process::id()
                ));
                match std::fs::create_dir(&candidate) {
                    Ok(()) => {
                        self.backup_root = Some(candidate);
                        break;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                    Err(error) => return Err(error),
                }
            }
        }
        Ok(self.backup_root.as_deref().expect("backup root reserved"))
    }

    pub(super) fn commit(mut self) {
        self.finalized = true;
        if let Some(backup_root) = self.backup_root.as_deref()
            && let Err(error) = remove_if_present(backup_root)
        {
            tracing::warn!(path = %backup_root.display(), %error, "failed to remove committed workspace install rollback state");
        }
    }

    pub(super) fn rollback(mut self) -> Vec<String> {
        let errors = self.rollback_inner();
        self.finalized = true;
        errors
    }

    fn rollback_inner(&mut self) -> Vec<String> {
        let mut errors = Vec::new();
        for moved in self.moved_paths.iter().rev() {
            if let Err(error) = remove_if_present(&moved.original) {
                errors.push(format!(
                    "failed to remove replacement {}: {error}",
                    moved.original.display()
                ));
                continue;
            }
            if moved.existed {
                if let Some(parent) = moved.original.parent()
                    && let Err(error) = std::fs::create_dir_all(parent)
                {
                    errors.push(format!(
                        "failed to recreate parent {}: {error}",
                        parent.display()
                    ));
                    continue;
                }
                let backup = moved.backup.as_deref().expect("existing path has a backup");
                if let Err(error) = std::fs::rename(backup, &moved.original) {
                    errors.push(format!(
                        "failed to restore {}: {error}",
                        moved.original.display()
                    ));
                }
            }
        }
        for snapshot in &self.file_snapshots {
            if let Err(error) = restore_file(snapshot) {
                errors.push(format!(
                    "failed to restore {}: {error}",
                    snapshot.path.display()
                ));
            }
        }
        if let Some(backup_root) = self.backup_root.as_deref()
            && let Err(error) = remove_if_present(backup_root)
        {
            errors.push(format!(
                "failed to remove rollback directory {}: {error}",
                backup_root.display()
            ));
        }
        if !self.dot_lpm_existed {
            let dot_lpm = self.project_dir.join(".lpm");
            match std::fs::remove_dir(&dot_lpm) {
                Ok(()) => {}
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::NotFound | std::io::ErrorKind::DirectoryNotEmpty
                    ) => {}
                Err(error) => errors.push(format!(
                    "failed to remove transaction-created {}: {error}",
                    dot_lpm.display()
                )),
            }
        }
        errors
    }
}

impl Drop for WorkspaceProjectStateTransaction {
    fn drop(&mut self) {
        if self.finalized {
            return;
        }
        for error in self.rollback_inner() {
            tracing::error!(%error, "workspace install rollback failed");
        }
    }
}

fn restore_file(snapshot: &FileSnapshot) -> std::io::Result<()> {
    match &snapshot.original {
        Some(original) => {
            if lpm_common::read_file_capped(&snapshot.path, lpm_common::CONFIG_FILE_SIZE_CAP_BYTES)
                .is_ok_and(|current| current == *original)
            {
                return Ok(());
            }
            lpm_common::write_file_atomic(&snapshot.path, original)
        }
        None => match std::fs::remove_file(&snapshot.path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error),
        },
    }
}

fn remove_if_present(path: &Path) -> std::io::Result<()> {
    match path.symlink_metadata() {
        Ok(_) => lpm_common::symlink::remove_path_entry(path),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_project_state(project: &Path) {
        std::fs::create_dir_all(project.join("node_modules/old-package")).unwrap();
        std::fs::create_dir_all(project.join(".lpm/wrappers/old-wrapper")).unwrap();
        std::fs::write(project.join("package.json"), b"{\"name\":\"before\"}").unwrap();
        std::fs::write(project.join(".gitignore"), b"before\n").unwrap();
        std::fs::write(project.join(".lpm/install-hash"), b"old-hash").unwrap();
    }

    #[test]
    fn rollback_restores_project_state_and_removes_replacements() {
        let directory = tempfile::tempdir().unwrap();
        let project = directory.path();
        write_project_state(project);
        let transaction = WorkspaceProjectStateTransaction::begin(project).unwrap();
        std::fs::create_dir_all(project.join("node_modules/new-package")).unwrap();
        std::fs::create_dir_all(project.join(".lpm/wrappers/new-wrapper")).unwrap();
        std::fs::write(project.join("package.json"), b"{\"name\":\"after\"}").unwrap();
        std::fs::write(project.join(".gitignore"), b"after\n").unwrap();
        std::fs::write(project.join(".lpm/install-hash"), b"new-hash").unwrap();

        assert!(transaction.rollback().is_empty());

        assert!(project.join("node_modules/old-package").is_dir());
        assert!(!project.join("node_modules/new-package").exists());
        assert!(project.join(".lpm/wrappers/old-wrapper").is_dir());
        assert!(!project.join(".lpm/wrappers/new-wrapper").exists());
        assert_eq!(
            std::fs::read(project.join("package.json")).unwrap(),
            b"{\"name\":\"before\"}"
        );
        assert_eq!(
            std::fs::read(project.join(".gitignore")).unwrap(),
            b"before\n"
        );
        assert_eq!(
            std::fs::read(project.join(".lpm/install-hash")).unwrap(),
            b"old-hash"
        );
    }

    #[test]
    fn commit_keeps_replacement_state_and_removes_backups() {
        let directory = tempfile::tempdir().unwrap();
        let project = directory.path();
        write_project_state(project);
        let transaction = WorkspaceProjectStateTransaction::begin(project).unwrap();
        let backup_root = transaction.backup_root.clone().unwrap();
        std::fs::create_dir_all(project.join("node_modules/new-package")).unwrap();

        transaction.commit();

        assert!(project.join("node_modules/new-package").is_dir());
        assert!(!project.join("node_modules/old-package").exists());
        assert!(!backup_root.exists());
    }

    #[cfg(unix)]
    #[test]
    fn begin_rejects_a_symlinked_project_state_directory() {
        let directory = tempfile::tempdir().unwrap();
        let project = directory.path().join("project");
        let outside = directory.path().join("outside");
        std::fs::create_dir_all(&project).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(project.join("package.json"), b"{}").unwrap();
        std::fs::write(outside.join("sentinel"), b"unchanged").unwrap();
        std::os::unix::fs::symlink(&outside, project.join(".lpm")).unwrap();

        let error = WorkspaceProjectStateTransaction::begin(&project)
            .err()
            .expect("symlinked .lpm must be rejected");

        assert!(error.to_string().contains("is not a real directory"));
        assert_eq!(
            std::fs::read(outside.join("sentinel")).unwrap(),
            b"unchanged"
        );
    }
}
