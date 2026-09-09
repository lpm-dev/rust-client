use super::{digest, invalid, read_regular, sync_directory, write_record};
use cap_fs_ext::{DirExt as _, FollowSymlinks, OpenOptionsFollowExt as _, OpenOptionsSyncExt as _};
use cap_std::fs::Dir;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Component, Path, PathBuf};

pub(super) const DIRECTORY: &str = "sources";
const FILE_LIMIT: u64 = 1024 * 1024 * 1024;
const ENTRY_LIMIT: usize = 20_000;

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
struct Fingerprint {
    digest: [u8; 32],
    mode: Option<u32>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    path: PathBuf,
    original: Option<Fingerprint>,
    written: Vec<Option<Fingerprint>>,
}

impl Record {
    fn key(&self) -> String {
        hex::encode(digest(self.path.as_os_str().as_encoded_bytes()))
    }

    fn accepts(&self, current: Option<Fingerprint>) -> bool {
        self.original == current || self.written.contains(&current)
    }
}

#[derive(Default)]
pub(super) struct Sources {
    records: BTreeMap<PathBuf, Record>,
    directories: BTreeSet<PathBuf>,
}

fn validate_path(path: &Path) -> io::Result<()> {
    if path.as_os_str().is_empty()
        || !path.components().all(|part| matches!(part, Component::Normal(_)))
        || path.components().any(|part| {
            matches!(part, Component::Normal(name) if name.eq_ignore_ascii_case(".git") || name.eq_ignore_ascii_case("node_modules"))
        })
    {
        return Err(invalid("source recovery contains an invalid project path"));
    }
    if path.starts_with(".lpm")
        && path != Path::new(".lpm/added-sources.json")
        && !path.starts_with(".lpm/added-source-backups")
    {
        return Err(invalid("source recovery targets reserved project state"));
    }
    Ok(())
}

fn parent(root: &Dir, path: &Path) -> io::Result<Dir> {
    validate_path(path)?;
    let mut directory = root.try_clone()?;
    for component in path.parent().unwrap_or(Path::new("")).components() {
        directory = directory.open_dir_nofollow(component.as_os_str())?;
    }
    Ok(directory)
}

fn open_regular(directory: &Dir, name: &OsStr) -> io::Result<cap_std::fs::File> {
    let mut options = cap_std::fs::OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No).nonblock(true);
    let file = directory.open_with(name, &options)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > FILE_LIMIT {
        return Err(invalid("source recovery requires a bounded regular file"));
    }
    Ok(file)
}

fn fingerprint(file: &mut cap_std::fs::File) -> io::Result<Fingerprint> {
    file.seek(SeekFrom::Start(0))?;
    let mut hash = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    let mut total = 0u64;
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        total += read as u64;
        if total > FILE_LIMIT {
            return Err(invalid("source recovery file exceeds its size limit"));
        }
        hash.update(&buffer[..read]);
    }
    #[cfg(unix)]
    let mode = {
        use cap_std::fs::PermissionsExt as _;
        Some(file.metadata()?.permissions().mode() & 0o7777)
    };
    #[cfg(not(unix))]
    let mode = None;
    Ok(Fingerprint {
        digest: hash.finalize().into(),
        mode,
    })
}

fn current(directory: &Dir, name: &OsStr) -> io::Result<Option<Fingerprint>> {
    match open_regular(directory, name) {
        Ok(mut file) => fingerprint(&mut file).map(Some),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

fn create_file(directory: &Dir, name: &str) -> io::Result<cap_std::fs::File> {
    let mut options = cap_std::fs::OpenOptions::new();
    options
        .read(true)
        .write(true)
        .create_new(true)
        .follow(FollowSymlinks::No);
    #[cfg(unix)]
    {
        use cap_std::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    directory.open_with(name, &options)
}

fn set_mode(file: &cap_std::fs::File, mode: Option<u32>) -> io::Result<()> {
    #[cfg(unix)]
    if let Some(mode) = mode {
        use cap_std::fs::PermissionsExt as _;
        file.set_permissions(cap_std::fs::Permissions::from_mode(mode))?;
    }
    #[cfg(not(unix))]
    let _ = (file, mode);
    Ok(())
}

fn remove_optional(directory: &Dir, name: impl AsRef<Path>) -> io::Result<()> {
    match directory.remove_file(name) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

pub(super) fn directory(state: &Dir) -> io::Result<Dir> {
    match state.open_dir_nofollow(DIRECTORY) {
        Ok(directory) => Ok(directory),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            state.create_dir(DIRECTORY)?;
            sync_directory(state)?;
            state.open_dir_nofollow(DIRECTORY)
        }
        Err(error) => Err(error),
    }
}

impl Sources {
    pub(super) fn contains(&self, path: &Path) -> bool {
        self.records.contains_key(path)
    }
    pub(super) fn record_directories(&mut self, state: &Dir, paths: &[PathBuf]) -> io::Result<()> {
        for path in paths {
            validate_path(path)?;
        }
        self.directories.extend(paths.iter().cloned());
        if self.directories.len() > ENTRY_LIMIT {
            return Err(invalid("too many source recovery directories"));
        }
        write_record(
            state,
            OsStr::new("directories.json"),
            &serde_json::to_vec(&self.directories)?,
        )
    }

    pub(super) fn write<T>(
        &mut self,
        root: &Dir,
        state: &Dir,
        path: PathBuf,
        mode: Option<u32>,
        write: impl FnOnce(&mut std::fs::File) -> io::Result<T>,
    ) -> io::Result<T> {
        let parent = parent(root, &path)?;
        let name = path
            .file_name()
            .ok_or_else(|| invalid("source recovery path has no name"))?;
        let expected = current(&parent, name)?;
        self.prepare(&parent, state, &path, expected)?;
        let record = self
            .records
            .get_mut(&path)
            .ok_or_else(|| invalid("missing source recovery record"))?;
        let key = record.key();
        let stage = format!("{key}.next");
        remove_optional(state, &stage)?;
        let mut file = create_file(state, &stage)?.into_std();
        let result = write(&mut file)?;
        let mut file = cap_std::fs::File::from_std(file);
        set_mode(
            &file,
            mode.or(expected.and_then(|value| value.mode))
                .or(Some(0o644)),
        )?;
        file.sync_all()?;
        let written = fingerprint(&mut file)?;
        drop(file);
        if !record.written.contains(&Some(written)) {
            record.written.push(Some(written));
        }
        if record.written.len() > 128 {
            return Err(invalid("too many source writes in one transaction"));
        }
        write_record(
            state,
            OsStr::new(&format!("{key}.json")),
            &serde_json::to_vec(record)?,
        )?;
        if current(&parent, name)? != expected {
            return Err(invalid(
                "source destination changed during delivery; retry after reconciling your edits",
            ));
        }
        state.rename(&stage, &parent, name)?;
        sync_directory(&parent)?;
        Ok(result)
    }

    pub(super) fn remove(&mut self, root: &Dir, state: &Dir, path: PathBuf) -> io::Result<()> {
        let parent = parent(root, &path)?;
        let name = path
            .file_name()
            .ok_or_else(|| invalid("source recovery path has no name"))?;
        let expected = current(&parent, name)?;
        self.prepare(&parent, state, &path, expected)?;
        let record = self
            .records
            .get_mut(&path)
            .ok_or_else(|| invalid("missing source recovery record"))?;
        if !record.written.contains(&None) {
            record.written.push(None);
        }
        write_record(
            state,
            OsStr::new(&format!("{}.json", record.key())),
            &serde_json::to_vec(record)?,
        )?;
        if current(&parent, name)? != expected {
            return Err(invalid("source destination changed during removal"));
        }
        remove_optional(&parent, name)?;
        sync_directory(&parent)
    }

    fn prepare(
        &mut self,
        parent: &Dir,
        state: &Dir,
        path: &Path,
        original: Option<Fingerprint>,
    ) -> io::Result<()> {
        if self.records.contains_key(path) {
            return Ok(());
        }
        if self.records.len() >= ENTRY_LIMIT {
            return Err(invalid("too many source recovery files"));
        }
        let record = Record {
            path: path.to_path_buf(),
            original,
            written: Vec::new(),
        };
        let key = record.key();
        if let Some(original) = original {
            let mut source = open_regular(
                parent,
                path.file_name()
                    .ok_or_else(|| invalid("missing source name"))?,
            )?;
            let mut backup = create_file(state, &format!("{key}.original"))?;
            io::copy(&mut source, &mut backup)?;
            backup.sync_all()?;
            if fingerprint(&mut backup)?.digest != original.digest {
                return Err(invalid("source changed while saving its recovery backup"));
            }
        }
        write_record(
            state,
            OsStr::new(&format!("{key}.json")),
            &serde_json::to_vec(&record)?,
        )?;
        self.records.insert(path.to_path_buf(), record);
        Ok(())
    }

    pub(super) fn load(state: &Dir) -> io::Result<Self> {
        let mut result = Self::default();
        for entry in state.entries()? {
            let entry = entry?;
            let name = entry.file_name();
            if name == "directories.json" {
                result.directories =
                    serde_json::from_slice(&read_regular(state, &name, super::RECORD_LIMIT)?)?;
                if result.directories.len() > ENTRY_LIMIT {
                    return Err(invalid("too many source recovery directories"));
                }
                for path in &result.directories {
                    validate_path(path)?;
                }
            } else if name.to_str().is_some_and(|name| name.ends_with(".json")) {
                let record: Record =
                    serde_json::from_slice(&read_regular(state, &name, super::RECORD_LIMIT)?)?;
                validate_path(&record.path)?;
                if name != format!("{}.json", record.key()).as_str()
                    || record.written.len() > 128
                    || result.records.len() >= ENTRY_LIMIT
                {
                    return Err(invalid("invalid source recovery record"));
                }
                result.records.insert(record.path.clone(), record);
            } else if !name.to_str().is_some_and(|name| {
                name.ends_with(".original")
                    || name.ends_with(".next")
                    || lpm_common::atomic_write::is_atomic_temp_name(name)
            }) {
                return Err(invalid("unexpected source recovery entry"));
            }
        }
        Ok(result)
    }

    pub(super) fn validate(&self, root: &Dir, state: &Dir) -> io::Result<()> {
        for record in self.records.values() {
            let parent = match parent(root, &record.path) {
                Ok(parent) => parent,
                Err(error)
                    if error.kind() == io::ErrorKind::NotFound && record.original.is_none() =>
                {
                    continue;
                }
                Err(error) => return Err(error),
            };
            if !record.accepts(current(
                &parent,
                record
                    .path
                    .file_name()
                    .ok_or_else(|| invalid("missing source name"))?,
            )?) {
                return Err(invalid(format!(
                    "Interrupted source delivery found later edits in {}. Your edits were preserved. Original files remain in .lpm/install-recovery/sources. Reconcile this file with its backup, then retry.",
                    record.path.display()
                )));
            }
            if let Some(original) = record.original {
                let mut backup =
                    open_regular(state, OsStr::new(&format!("{}.original", record.key())))?;
                if fingerprint(&mut backup)?.digest != original.digest {
                    return Err(invalid(
                        "source recovery backup failed integrity verification",
                    ));
                }
            }
        }
        Ok(())
    }

    pub(super) fn restore(&self, root: &Dir, state: &Dir) -> io::Result<()> {
        for record in self.records.values() {
            let parent = match parent(root, &record.path) {
                Ok(parent) => parent,
                Err(error)
                    if error.kind() == io::ErrorKind::NotFound && record.original.is_none() =>
                {
                    continue;
                }
                Err(error) => return Err(error),
            };
            let name = record
                .path
                .file_name()
                .ok_or_else(|| invalid("missing source name"))?;
            let actual = current(&parent, name)?;
            if !record.accepts(actual) {
                return Err(invalid(
                    "source changed during recovery; your edits were preserved",
                ));
            }
            if actual == record.original {
                continue;
            }
            if let Some(original) = record.original {
                let key = record.key();
                let stage = format!("{key}.next");
                remove_optional(state, &stage)?;
                let mut backup = open_regular(state, OsStr::new(&format!("{key}.original")))?;
                let mut file = create_file(state, &stage)?;
                io::copy(&mut backup, &mut file)?;
                set_mode(&file, original.mode)?;
                file.sync_all()?;
                drop(file);
                state.rename(&stage, &parent, name)?;
            } else {
                remove_optional(&parent, name)?;
            }
            sync_directory(&parent)?;
        }
        let mut directories: Vec<_> = self.directories.iter().collect();
        directories.sort_unstable_by_key(|path| std::cmp::Reverse(path.components().count()));
        for path in directories {
            match parent(root, path)
                .and_then(|parent| parent.remove_dir(path.file_name().unwrap_or_default()))
            {
                Ok(()) => {}
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::NotFound | io::ErrorKind::DirectoryNotEmpty
                    ) => {}
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }
}

pub(super) fn cleanup(state: Dir) -> io::Result<()> {
    for entry in state.entries()? {
        state.remove_file(entry?.file_name())?;
    }
    sync_directory(&state)?;
    state.remove_open_dir()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    fn fixture() -> (tempfile::TempDir, Dir, Dir) {
        let temp = tempfile::tempdir().unwrap();
        let root = Dir::open_ambient_dir(temp.path(), cap_std::ambient_authority()).unwrap();
        root.create_dir("journal").unwrap();
        let state = root.open_dir("journal").unwrap();
        (temp, root, state)
    }

    fn replace(sources: &mut Sources, root: &Dir, state: &Dir, path: &str, bytes: &[u8]) {
        sources
            .write(root, state, PathBuf::from(path), None, |file| {
                file.write_all(bytes)
            })
            .unwrap();
    }

    #[test]
    fn later_edits_prevent_recovery_without_changing_other_files() {
        let (_temp, root, state) = fixture();
        root.write("original.js", b"original").unwrap();
        let mut sources = Sources::default();
        replace(&mut sources, &root, &state, "original.js", b"replacement");
        replace(&mut sources, &root, &state, "new.js", b"new");
        root.write("new.js", b"user edits").unwrap();
        let loaded = Sources::load(&state).unwrap();
        let error = loaded.validate(&root, &state).unwrap_err();
        assert!(error.to_string().contains("later edits in new.js"));
        assert_eq!(root.read("original.js").unwrap(), b"replacement");
        assert_eq!(root.read("new.js").unwrap(), b"user edits");
    }

    #[test]
    fn corrupt_backup_stops_recovery_before_restoration() {
        let (_temp, root, state) = fixture();
        root.write("original.js", b"original").unwrap();
        let mut sources = Sources::default();
        replace(&mut sources, &root, &state, "original.js", b"replacement");
        let key = sources.records[Path::new("original.js")].key();
        state.write(format!("{key}.original"), b"corrupt").unwrap();
        assert!(
            Sources::load(&state)
                .unwrap()
                .validate(&root, &state)
                .unwrap_err()
                .to_string()
                .contains("integrity")
        );
        assert_eq!(root.read("original.js").unwrap(), b"replacement");
    }

    #[test]
    fn restoration_can_repeat_after_some_originals_are_restored() {
        let (_temp, root, state) = fixture();
        root.create_dir("vendor").unwrap();
        root.write("original.js", b"original").unwrap();
        let mut sources = Sources::default();
        sources
            .record_directories(&state, &[PathBuf::from("vendor")])
            .unwrap();
        replace(&mut sources, &root, &state, "original.js", b"replacement");
        replace(&mut sources, &root, &state, "vendor/new.js", b"new");
        root.write("original.js", b"original").unwrap();
        for _ in 0..2 {
            let loaded = Sources::load(&state).unwrap();
            loaded.validate(&root, &state).unwrap();
            loaded.restore(&root, &state).unwrap();
        }
        assert_eq!(root.read("original.js").unwrap(), b"original");
        assert!(!root.exists("vendor"));
    }

    #[test]
    fn removal_recovers_original_bytes() {
        let (_temp, root, state) = fixture();
        root.write("original.js", b"original").unwrap();
        let mut sources = Sources::default();
        sources
            .remove(&root, &state, PathBuf::from("original.js"))
            .unwrap();
        assert!(!root.exists("original.js"));
        let loaded = Sources::load(&state).unwrap();
        loaded.validate(&root, &state).unwrap();
        loaded.restore(&root, &state).unwrap();
        assert_eq!(root.read("original.js").unwrap(), b"original");
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_parent_is_rejected_during_recovery() {
        let (temp, root, state) = fixture();
        root.create_dir("vendor").unwrap();
        let outside = tempfile::tempdir().unwrap();
        let mut sources = Sources::default();
        replace(&mut sources, &root, &state, "vendor/new.js", b"new");
        root.rename("vendor", &root, "saved-vendor").unwrap();
        std::os::unix::fs::symlink(outside.path(), temp.path().join("vendor")).unwrap();
        assert!(
            Sources::load(&state)
                .unwrap()
                .validate(&root, &state)
                .is_err()
        );
        assert_eq!(root.read("saved-vendor/new.js").unwrap(), b"new");
        assert!(!outside.path().join("new.js").exists());
    }
}
