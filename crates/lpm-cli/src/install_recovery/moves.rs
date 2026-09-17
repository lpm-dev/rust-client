use super::{RECORD_LIMIT, invalid, read_regular, sync_directory, write_record};
use cap_fs_ext::{DirExt as _, FollowSymlinks, OpenOptionsFollowExt as _, OpenOptionsSyncExt as _};
use cap_std::fs::Dir;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::io::{self, Read};
use std::path::{Component, Path, PathBuf};

pub(super) const DIRECTORY: &str = "moves";
const ENTRY_LIMIT: usize = 10_000;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
enum Fingerprint {
    File {
        digest: [u8; 32],
        length: u64,
        mode: Option<u32>,
        identity: Option<(u64, u64)>,
    },
    Link {
        target: PathBuf,
        identity: Option<(u64, u64)>,
    },
    Directory {
        identity: crate::directory_transaction::DirectoryIdentity,
        entries: BTreeMap<PathBuf, Fingerprint>,
    },
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Move {
    schema_version: u32,
    sequence: u64,
    source: PathBuf,
    destination: PathBuf,
    expected: Fingerprint,
    destination_mode: Option<u32>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Archive {
    schema_version: u32,
    path: PathBuf,
    identity: crate::directory_transaction::DirectoryIdentity,
}

#[derive(Default)]
pub(super) struct Moves {
    entries: BTreeMap<u64, Move>,
    archives: BTreeMap<PathBuf, Archive>,
    next_sequence: u64,
    total_bytes: usize,
}

fn validate_path(path: &Path) -> io::Result<()> {
    let mut components = path.components().peekable();
    if path.as_os_str().is_empty() {
        return Err(invalid("empty source move path"));
    }
    while let Some(component) = components.next() {
        let Component::Normal(name) = component else {
            return Err(invalid("unsafe source move path"));
        };
        if name.eq_ignore_ascii_case(".git") || name.eq_ignore_ascii_case("node_modules") {
            return Err(invalid("source move targets reserved project data"));
        }
        if name.eq_ignore_ascii_case(".lpm") {
            let Some(Component::Normal(next)) = components.peek() else {
                return Err(invalid("source move targets project state directory"));
            };
            if *next != OsStr::new("skills")
                && *next != OsStr::new("added-source-backups")
                && !next
                    .to_str()
                    .is_some_and(|name| name.starts_with(".source-remove-"))
            {
                return Err(invalid("source move targets reserved project state"));
            }
        }
    }
    Ok(())
}

fn parent(root: &Dir, path: &Path) -> io::Result<Dir> {
    validate_path(path)?;
    let mut current = root.try_clone()?;
    for component in path.parent().unwrap_or(Path::new("")).components() {
        current =
            crate::directory_transaction::open_directory_shared(&current, component.as_os_str())?;
    }
    Ok(current)
}

fn name(path: &Path) -> io::Result<&OsStr> {
    path.file_name()
        .ok_or_else(|| invalid("source move has no entry name"))
}

#[cfg_attr(
    unix,
    expect(
        clippy::unnecessary_wraps,
        reason = "file identity is unavailable on other platforms"
    )
)]
fn identity(metadata: &cap_std::fs::Metadata) -> Option<(u64, u64)> {
    #[cfg(unix)]
    {
        use cap_std::fs::MetadataExt as _;
        Some((metadata.dev(), metadata.ino()))
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        None
    }
}

#[cfg_attr(
    unix,
    expect(
        clippy::unnecessary_wraps,
        reason = "Unix file modes are unavailable on other platforms"
    )
)]
fn mode(metadata: &cap_std::fs::Metadata) -> Option<u32> {
    #[cfg(unix)]
    {
        use cap_std::fs::PermissionsExt as _;
        Some(metadata.permissions().mode() & 0o7777)
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        None
    }
}

fn fingerprint(
    directory: &Dir,
    name: &OsStr,
    budget: &mut usize,
    depth: usize,
) -> io::Result<Option<Fingerprint>> {
    if *budget == 0 || depth > 64 {
        return Err(invalid("source move fingerprint exceeds its entry limit"));
    }
    *budget -= 1;
    let metadata = match directory.symlink_metadata(name) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    if metadata.is_symlink() {
        return Ok(Some(Fingerprint::Link {
            target: directory.read_link_contents(name)?,
            identity: identity(&metadata),
        }));
    }
    if metadata.is_dir() {
        let child = crate::directory_transaction::open_directory_shared(directory, name)?;
        let identity = crate::directory_transaction::directory_identity(&child)?;
        let mut entries = BTreeMap::new();
        for entry in child.entries()? {
            let entry = entry?;
            let name = entry.file_name();
            let value = fingerprint(&child, &name, budget, depth + 1)?
                .ok_or_else(|| invalid("source directory changed while recording removal"))?;
            entries.insert(PathBuf::from(name), value);
        }
        return Ok(Some(Fingerprint::Directory { identity, entries }));
    }
    if !metadata.is_file() {
        return Err(invalid(
            "source moves require regular files, links, or directories",
        ));
    }
    let mut options = cap_std::fs::OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No).nonblock(true);
    let mut file = directory.open_with(name, &options)?;
    let opened = file.metadata()?;
    if !opened.is_file() || identity(&opened) != identity(&metadata) {
        return Err(invalid("source file changed while recording removal"));
    }
    let mut hash = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    let mut length = 0u64;
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        length += read as u64;
        hash.update(&buffer[..read]);
    }
    Ok(Some(Fingerprint::File {
        digest: hash.finalize().into(),
        length,
        mode: mode(&opened),
        identity: identity(&opened),
    }))
}

fn inspect(root: &Dir, path: &Path) -> io::Result<Option<Fingerprint>> {
    let parent = match parent(root, path) {
        Ok(parent) => parent,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    fingerprint(&parent, name(path)?, &mut { ENTRY_LIMIT }, 0)
}

fn matches(actual: &Fingerprint, expected: &Fingerprint, alternative_mode: Option<u32>) -> bool {
    if actual == expected {
        return true;
    }
    if let (
        Fingerprint::Directory { identity: a, .. },
        Fingerprint::Directory { identity: e, .. },
    ) = (actual, expected)
    {
        return a == e;
    }
    let (
        Fingerprint::File {
            digest: a,
            length: al,
            mode: am,
            identity: ai,
        },
        Fingerprint::File {
            digest: e,
            length: el,
            identity: ei,
            ..
        },
    ) = (actual, expected)
    else {
        return false;
    };
    a == e && al == el && ai == ei && alternative_mode.is_some() && *am == alternative_mode
}

fn set_mode(directory: &Dir, name: &OsStr, value: Option<u32>) -> io::Result<()> {
    #[cfg(unix)]
    if let Some(value) = value {
        use cap_std::fs::PermissionsExt as _;
        let mut options = cap_std::fs::OpenOptions::new();
        options.read(true).follow(FollowSymlinks::No).nonblock(true);
        let file = directory.open_with(name, &options)?;
        if !file.metadata()?.is_file() {
            return Err(invalid("source mode restoration requires a regular file"));
        }
        file.set_permissions(cap_std::fs::Permissions::from_mode(value))?;
        file.sync_all()?;
    }
    #[cfg(not(unix))]
    let _ = (directory, name, value);
    Ok(())
}

fn move_name(sequence: u64) -> String {
    format!("move-{sequence:020}.json")
}
fn archive_name(path: &Path) -> String {
    format!(
        "archive-{}.json",
        hex::encode(Sha256::digest(path.as_os_str().as_encoded_bytes()))
    )
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

impl Moves {
    pub(super) fn load(state: &Dir) -> io::Result<Self> {
        let mut result = Self::default();
        let mut total = 0usize;
        for entry in state.entries()? {
            let entry = entry?;
            let name = entry.file_name();
            if name
                .to_str()
                .is_some_and(lpm_common::atomic_write::is_atomic_temp_name)
            {
                state.remove_file(name)?;
                continue;
            }
            let bytes = read_regular(state, &name, RECORD_LIMIT)?;
            total = total.saturating_add(bytes.len());
            if total > super::TOTAL_LIMIT
                || result.entries.len() + result.archives.len() >= ENTRY_LIMIT
            {
                return Err(invalid("source move journal exceeds its size limit"));
            }
            if name
                .to_str()
                .is_some_and(|name| name.starts_with("archive-"))
            {
                let archive: Archive = serde_json::from_slice(&bytes).map_err(io::Error::other)?;
                validate_path(&archive.path)?;
                if archive.schema_version != 1
                    || name != OsStr::new(&archive_name(&archive.path))
                    || archive.path.parent().and_then(Path::file_name) != Some(OsStr::new(".lpm"))
                    || !archive
                        .path
                        .file_name()
                        .and_then(OsStr::to_str)
                        .is_some_and(|name| name.starts_with(".source-remove-"))
                {
                    return Err(invalid("invalid source removal archive"));
                }
                result.archives.insert(archive.path.clone(), archive);
            } else {
                let record: Move = serde_json::from_slice(&bytes).map_err(io::Error::other)?;
                validate_path(&record.source)?;
                validate_path(&record.destination)?;
                if record.schema_version != 1
                    || name != OsStr::new(&move_name(record.sequence))
                    || record.source == record.destination
                    || record
                        .destination_mode
                        .is_some_and(|mode| mode & !0o7777 != 0)
                {
                    return Err(invalid("invalid source move record"));
                }
                result.next_sequence = result.next_sequence.max(
                    record
                        .sequence
                        .checked_add(1)
                        .ok_or_else(|| invalid("source move sequence overflow"))?,
                );
                result.entries.insert(record.sequence, record);
            }
        }
        result.total_bytes = total;
        Ok(result)
    }

    fn reserve(&mut self, bytes: usize) -> io::Result<()> {
        if self.entries.len() + self.archives.len() >= ENTRY_LIMIT
            || bytes as u64 > RECORD_LIMIT
            || self.total_bytes.saturating_add(bytes) > super::TOTAL_LIMIT
        {
            return Err(invalid("source move journal exceeds its size limit"));
        }
        self.total_bytes += bytes;
        Ok(())
    }

    pub(super) fn next_directory_name(&self) -> String {
        format!("directory-{}", self.next_sequence)
    }

    pub(super) fn register_archive(
        &mut self,
        root: &Dir,
        state: &Dir,
        path: &Path,
    ) -> io::Result<()> {
        if self.archives.contains_key(path) {
            return Ok(());
        }
        validate_path(path)?;
        let parent = parent(root, path)?;
        let archive = parent.open_dir_nofollow(name(path)?)?;
        let record = Archive {
            schema_version: 1,
            path: path.to_path_buf(),
            identity: crate::directory_transaction::directory_identity(&archive)?,
        };
        sync_directory(&parent)?;
        let bytes = serde_json::to_vec(&record).map_err(io::Error::other)?;
        self.reserve(bytes.len())?;
        write_record(state, OsStr::new(&archive_name(path)), &bytes)?;
        self.archives.insert(path.to_path_buf(), record);
        Ok(())
    }

    pub(super) fn reserve_sequence(&mut self) -> io::Result<u64> {
        if self.next_sequence >= ENTRY_LIMIT as u64 {
            return Err(invalid("too many source move checkpoints"));
        }
        let sequence = self.next_sequence;
        self.next_sequence = sequence
            .checked_add(1)
            .ok_or_else(|| invalid("source move sequence overflow"))?;
        Ok(sequence)
    }

    pub(super) fn execute(
        &mut self,
        root: &Dir,
        state: &Dir,
        source: &Path,
        destination: &Path,
        destination_mode: Option<u32>,
        sequence: u64,
    ) -> io::Result<()> {
        if self.entries.len() >= ENTRY_LIMIT {
            return Err(invalid("too many source moves"));
        }
        let source_parent = parent(root, source)?;
        let destination_parent = parent(root, destination)?;
        if inspect(root, destination)?.is_some() {
            return Err(invalid("source move destination already exists"));
        }
        let expected =
            inspect(root, source)?.ok_or_else(|| invalid("source move entry disappeared"))?;
        let record = Move {
            schema_version: 1,
            sequence,
            source: source.to_path_buf(),
            destination: destination.to_path_buf(),
            expected,
            destination_mode,
        };
        let bytes = serde_json::to_vec(&record).map_err(io::Error::other)?;
        self.reserve(bytes.len())?;
        write_record(state, OsStr::new(&move_name(record.sequence)), &bytes)?;
        self.entries.insert(record.sequence, record);
        publish(
            &source_parent,
            name(source)?,
            &destination_parent,
            name(destination)?,
            &self.entries[&sequence].expected,
        )?;
        sync_directory(&source_parent)?;
        sync_directory(&destination_parent)?;
        super::test_pause("after-source-move");
        set_mode(&destination_parent, name(destination)?, destination_mode)?;
        if destination_mode.is_some() {
            super::test_pause("after-source-restore");
        }
        Ok(())
    }

    pub(super) fn archive_for_project(&self, project: &Path) -> Option<&Path> {
        let parent = project.join(".lpm");
        self.archives
            .keys()
            .find(|path| path.parent() == Some(parent.as_path()))
            .map(PathBuf::as_path)
    }

    pub(super) fn undo_last(&mut self, root: &Dir, state: &Dir) -> io::Result<()> {
        let Some((&sequence, _)) = self.entries.last_key_value() else {
            return Ok(());
        };
        self.undo_from(root, state, sequence)
    }

    pub(super) fn undo(&mut self, root: &Dir, state: &Dir) -> io::Result<()> {
        self.undo_from(root, state, 0)
    }

    pub(super) fn undo_from(&mut self, root: &Dir, state: &Dir, minimum: u64) -> io::Result<()> {
        while let Some((&sequence, record)) = self.entries.last_key_value() {
            if sequence < minimum {
                break;
            }
            let source = inspect(root, &record.source)?;
            let destination = inspect(root, &record.destination)?;
            match (&source, &destination) {
                (Some(source), None)
                    if matches(source, &record.expected, record.destination_mode) => {}
                (None, Some(destination))
                    if matches(destination, &record.expected, record.destination_mode) =>
                {
                    let from = parent(root, &record.destination)?;
                    let to = parent(root, &record.source)?;
                    publish(
                        &from,
                        name(&record.destination)?,
                        &to,
                        name(&record.source)?,
                        &record.expected,
                    )?;
                    sync_directory(&from)?;
                    sync_directory(&to)?;
                    super::test_pause("after-source-undo");
                }
                _ => {
                    return Err(invalid(format!(
                        "Interrupted source removal found later edits at {} or {}. Your files were preserved. Reconcile these paths with the removal archive, then retry",
                        record.source.display(),
                        record.destination.display()
                    )));
                }
            }
            if let Fingerprint::File { mode, .. } = &record.expected {
                set_mode(&parent(root, &record.source)?, name(&record.source)?, *mode)?;
            }
            state.remove_file(move_name(sequence))?;
            sync_directory(state)?;
            self.entries.remove(&sequence);
        }
        Ok(())
    }

    pub(super) fn cleanup(&self, root: &Dir, state: &Dir) -> io::Result<()> {
        for archive in self.archives.values() {
            let parent = parent(root, &archive.path)?;
            let directory = match crate::directory_transaction::open_directory_for_publication(
                &parent,
                name(&archive.path)?,
            ) {
                Ok(directory) => directory,
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error),
            };
            if crate::directory_transaction::directory_identity(&directory)? != archive.identity {
                return Err(invalid(
                    "source removal archive was replaced; preserving it",
                ));
            }
            for record in self.entries.values() {
                if record.destination.parent() == Some(archive.path.as_path()) {
                    remove_matching(&directory, name(&record.destination)?, &record.expected)?;
                }
            }
            crate::directory_transaction::discard_private_directory(directory)?;
            sync_directory(&parent)?;
        }
        for entry in state.entries()? {
            state.remove_file(entry?.file_name())?;
        }
        sync_directory(state)
    }
}

fn publish(
    from: &Dir,
    source: &OsStr,
    to: &Dir,
    destination: &OsStr,
    expected: &Fingerprint,
) -> io::Result<()> {
    if let Fingerprint::Directory { identity, .. } = expected {
        let directory = crate::directory_transaction::open_directory_for_publication(from, source)?;
        if crate::directory_transaction::directory_identity(&directory)? != *identity {
            return Err(invalid("source move directory identity changed"));
        }
        crate::directory_transaction::publish_directory_noreplace(
            from,
            &directory,
            source,
            to,
            destination,
        )
    } else {
        crate::directory_transaction::publish_entry_noreplace(from, source, to, destination)
    }
}

fn remove_matching(directory: &Dir, name: &OsStr, expected: &Fingerprint) -> io::Result<()> {
    if let Fingerprint::Directory { identity, entries } = expected {
        let child =
            match crate::directory_transaction::open_directory_for_publication(directory, name) {
                Ok(child) => child,
                Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
                Err(error) => return Err(error),
            };
        if crate::directory_transaction::directory_identity(&child)? != *identity {
            return Err(invalid("source removal archive directory was replaced"));
        }
        for entry in child.entries()? {
            let entry = entry?;
            if !entries.contains_key(&PathBuf::from(entry.file_name())) {
                return Err(invalid(
                    "source removal archive contains later additions; preserving them",
                ));
            }
        }
        for (name, expected) in entries {
            remove_matching(&child, name.as_os_str(), expected)?;
        }
        crate::directory_transaction::discard_private_directory(child)?;
    } else if let Some(actual) = fingerprint(directory, name, &mut { ENTRY_LIMIT }, 0)? {
        if &actual != expected {
            return Err(invalid(
                "source removal archive contains later edits; preserving them",
            ));
        }
        directory.remove_file_or_symlink(name)?;
    }
    sync_directory(directory)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn move_limits_include_archive_records_before_renaming() {
        assert_budget_refuses_move(false);
    }

    #[test]
    fn move_limits_include_total_record_bytes_before_renaming() {
        assert_budget_refuses_move(true);
    }

    fn assert_budget_refuses_move(byte_limit: bool) {
        let temporary = tempfile::tempdir().unwrap();
        let root = Dir::open_ambient_dir(temporary.path(), cap_std::ambient_authority()).unwrap();
        root.create_dir_all(".lpm/.source-remove-limit").unwrap();
        root.create_dir("journal").unwrap();
        root.write("source.txt", b"original").unwrap();
        let state = root.open_dir("journal").unwrap();
        let mut journal = Moves::default();
        journal
            .register_archive(&root, &state, Path::new(".lpm/.source-remove-limit"))
            .unwrap();
        if byte_limit {
            journal.total_bytes = super::super::TOTAL_LIMIT - 1;
        } else {
            let expected = inspect(&root, Path::new("source.txt")).unwrap().unwrap();
            for sequence in 0..(ENTRY_LIMIT - 1) as u64 {
                journal.entries.insert(
                    sequence,
                    Move {
                        schema_version: 1,
                        sequence,
                        source: PathBuf::from("earlier.txt"),
                        destination: PathBuf::from(".lpm/.source-remove-limit/earlier"),
                        expected: expected.clone(),
                        destination_mode: None,
                    },
                );
            }
            journal.next_sequence = ENTRY_LIMIT as u64;
        }
        let result = journal.execute(
            &root,
            &state,
            Path::new("source.txt"),
            Path::new(".lpm/.source-remove-limit/next"),
            None,
            ENTRY_LIMIT as u64,
        );
        assert!(
            result.is_err(),
            "journal must reject a move that its recovery reader cannot accept"
        );
        assert_eq!(root.read("source.txt").unwrap(), b"original");
        assert!(!root.try_exists(".lpm/.source-remove-limit/next").unwrap());
    }
}
