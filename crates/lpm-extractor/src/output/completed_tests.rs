use super::*;
use std::io::Write;

fn pending(root: &Path, path: &Path) -> PendingFile {
    let root = root.canonicalize().unwrap();
    let mut tree = OutputTree::new(root.clone(), root).unwrap();
    tree.prepare_parent(path, &mut PathLedgerBudget::new(usize::MAX))
        .unwrap();
    let mut file = tree.create_file(path, false).unwrap();
    file.file.write_all(b"written").unwrap();
    file
}

#[test]
fn completed_file_rolls_back_until_committed() {
    let root = tempfile::tempdir().unwrap();
    let path = Path::new("file");
    drop(pending(root.path(), path).complete().unwrap());
    assert!(!root.path().join(path).exists());
    pending(root.path(), path)
        .complete()
        .unwrap()
        .commit()
        .unwrap();
    assert_eq!(std::fs::read(root.path().join(path)).unwrap(), b"written");
}

#[test]
fn completed_file_preserves_a_replacement_leaf() {
    let root = tempfile::tempdir().unwrap();
    let path = Path::new("file");
    let completed = pending(root.path(), path).complete().unwrap();
    std::fs::rename(root.path().join(path), root.path().join("moved")).unwrap();
    std::fs::write(root.path().join(path), b"replacement").unwrap();
    drop(completed);
    assert_eq!(
        std::fs::read(root.path().join(path)).unwrap(),
        b"replacement"
    );
    assert_eq!(
        std::fs::read(root.path().join("moved")).unwrap(),
        b"written"
    );
}

#[test]
fn completed_file_commit_rejects_a_replacement_and_preserves_both_files() {
    let root = tempfile::tempdir().unwrap();
    let path = Path::new("file");
    let completed = pending(root.path(), path).complete().unwrap();
    std::fs::rename(root.path().join(path), root.path().join("moved")).unwrap();
    std::fs::write(root.path().join(path), b"replacement").unwrap();
    assert!(completed.commit().is_err());
    assert_eq!(
        std::fs::read(root.path().join(path)).unwrap(),
        b"replacement"
    );
    assert_eq!(
        std::fs::read(root.path().join("moved")).unwrap(),
        b"written"
    );
}

#[test]
fn completed_file_commit_rejects_a_missing_leaf() {
    let root = tempfile::tempdir().unwrap();
    let path = Path::new("file");
    let completed = pending(root.path(), path).complete().unwrap();
    std::fs::remove_file(root.path().join(path)).unwrap();
    assert!(completed.commit().is_err());
    assert!(!root.path().join(path).exists());
}

#[cfg(unix)]
#[test]
fn completed_file_commit_rejects_a_symlink_to_the_original_inode() {
    let root = tempfile::tempdir().unwrap();
    let path = Path::new("file");
    let completed = pending(root.path(), path).complete().unwrap();
    std::fs::rename(root.path().join(path), root.path().join("moved")).unwrap();
    std::os::unix::fs::symlink("moved", root.path().join(path)).unwrap();
    assert!(completed.commit().is_err());
    assert!(
        std::fs::symlink_metadata(root.path().join(path))
            .unwrap()
            .is_symlink()
    );
    assert_eq!(
        std::fs::read(root.path().join("moved")).unwrap(),
        b"written"
    );
}

#[cfg(unix)]
#[test]
fn completed_file_cleans_through_the_original_parent_capability() {
    let root = tempfile::tempdir().unwrap();
    let path = Path::new("lib/file");
    let completed = pending(root.path(), path).complete().unwrap();
    std::fs::rename(root.path().join("lib"), root.path().join("moved")).unwrap();
    std::fs::create_dir(root.path().join("lib")).unwrap();
    std::fs::write(root.path().join(path), b"replacement").unwrap();
    drop(completed);
    assert_eq!(
        std::fs::read(root.path().join(path)).unwrap(),
        b"replacement"
    );
    assert!(!root.path().join("moved/file").exists());
}

#[test]
fn completed_file_rolls_back_on_unwind_or_failed_delivery() {
    let root = tempfile::tempdir().unwrap();
    let path = Path::new("file");
    let file = pending(root.path(), path);
    assert!(
        std::panic::catch_unwind(move || {
            let _completed = file.complete().unwrap();
            panic!("injected after completing");
        })
        .is_err()
    );
    assert!(!root.path().join(path).exists());
    let (sender, receiver) = std::sync::mpsc::channel();
    drop(receiver);
    assert!(
        sender
            .send(pending(root.path(), path).complete().unwrap())
            .is_err()
    );
    assert!(!root.path().join(path).exists());
}

#[cfg(windows)]
#[test]
fn completed_file_retains_the_file_handle_until_commit() {
    use std::os::windows::fs::OpenOptionsExt;
    let root = tempfile::tempdir().unwrap();
    let path = Path::new("file");
    let completed = pending(root.path(), path).complete().unwrap();
    let exclusive = || {
        std::fs::OpenOptions::new()
            .read(true)
            .share_mode(0)
            .open(root.path().join(path))
    };
    assert!(exclusive().is_err());
    completed.commit().unwrap();
    assert!(exclusive().is_ok());
}

#[cfg(unix)]
#[test]
fn completed_file_retains_the_file_handle_until_commit() {
    let root = tempfile::tempdir().unwrap();
    let path = Path::new("file");
    let file = pending(root.path(), path);
    file.file.lock().unwrap();
    let completed = file.complete().unwrap();
    let independent = std::fs::File::open(root.path().join(path)).unwrap();
    assert!(matches!(
        independent.try_lock(),
        Err(std::fs::TryLockError::WouldBlock)
    ));
    completed.commit().unwrap();
    independent.try_lock().unwrap();
}
