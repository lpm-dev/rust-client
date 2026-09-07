use std::cell::RefCell;
use std::collections::HashMap;
use std::ffi::OsStr;
use std::future::Future;
use std::io::{self, Read, Write};
use std::path::{Component, Path, PathBuf};

use cap_fs_ext::{DirExt as _, FollowSymlinks, OpenOptionsFollowExt as _, OpenOptionsSyncExt as _};
use cap_std::fs::Dir;
use lpm_common::LpmError;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const DIRECTORY: &str = "install-recovery";
const COMMITTED: &str = "committed";
const RECORD_LIMIT: u64 = 32 * 1024 * 1024;
const TOTAL_LIMIT: usize = 128 * 1024 * 1024;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    schema_version: u32,
    path: PathBuf,
    original: String,
    written: Vec<[u8; 32]>,
}

impl Record {
    fn accepts(&self, bytes: &[u8]) -> bool {
        bytes == self.original.as_bytes() || self.written.contains(&digest(bytes))
    }

    fn name(&self) -> String {
        format!(
            "{}.json",
            hex::encode(digest(self.path.as_os_str().as_encoded_bytes()))
        )
    }
}

struct Recovery {
    root: PathBuf,
    directory: Dir,
    records: HashMap<PathBuf, Record>,
    total_bytes: usize,
}

tokio::task_local! {
    static ACTIVE: RefCell<Recovery>;
}

pub(crate) fn pending(root: &Path) -> bool {
    !matches!(std::fs::symlink_metadata(root.join(".lpm").join(DIRECTORY)), Err(error) if error.kind() == io::ErrorKind::NotFound)
}

fn digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

fn open_parent(root: &Dir, relative: &Path) -> io::Result<Dir> {
    if relative.file_name() != Some(OsStr::new("package.json")) {
        return Err(invalid("install recovery only accepts package.json files"));
    }
    let mut parent = root.try_clone()?;
    let components: Vec<_> = relative.components().collect();
    for (index, component) in components.iter().enumerate() {
        let Component::Normal(name) = component else {
            return Err(invalid(
                "install recovery contains an invalid relative path",
            ));
        };
        if *name == OsStr::new("node_modules") || *name == OsStr::new(".lpm") {
            return Err(invalid("install recovery contains a non-project manifest"));
        }
        if index + 1 < components.len() {
            parent = parent.open_dir_nofollow(name)?;
        }
    }
    Ok(parent)
}

fn read_regular(directory: &Dir, name: &OsStr, limit: u64) -> io::Result<Vec<u8>> {
    let mut options = cap_std::fs::OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No).nonblock(true);
    let file = directory.open_with(name, &options)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > limit {
        return Err(invalid("install recovery requires a bounded regular file"));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(limit + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        return Err(invalid("install recovery file exceeds its size limit"));
    }
    Ok(bytes)
}

fn sync_directory(directory: &Dir) -> io::Result<()> {
    #[cfg(unix)]
    directory.open(".")?.sync_all()?;
    #[cfg(not(unix))]
    let _ = directory;
    Ok(())
}

fn write_record(directory: &Dir, name: &OsStr, bytes: &[u8]) -> io::Result<()> {
    lpm_common::write_file_atomic_in_dir_with(directory, name, |file| {
        #[cfg(unix)]
        {
            use cap_std::fs::PermissionsExt as _;
            file.set_permissions(cap_std::fs::Permissions::from_mode(0o600))?;
        }
        file.write_all(bytes)?;
        file.sync_all()
    })?;
    sync_directory(directory)
}

impl Recovery {
    fn state_directory(&self, create: bool) -> io::Result<Option<Dir>> {
        let lpm = self.directory.open_dir_nofollow(".lpm")?;
        match lpm.open_dir_nofollow(DIRECTORY) {
            Ok(directory) => Ok(Some(directory)),
            Err(error) if error.kind() == io::ErrorKind::NotFound && !create => Ok(None),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let builder = cap_std::fs::DirBuilder::new();
                #[cfg(unix)]
                let builder = {
                    use cap_std::fs::DirBuilderExt as _;
                    let mut builder = builder;
                    builder.mode(0o700);
                    builder
                };
                lpm.create_dir_with(DIRECTORY, &builder)?;
                sync_directory(&lpm)?;
                lpm.open_dir_nofollow(DIRECTORY).map(Some)
            }
            Err(error) => Err(error),
        }
    }

    fn conflict(&self, path: &Path) -> io::Error {
        invalid(format!(
            "Interrupted install recovery found later edits in {}. Your edits were preserved. Original manifests are saved in {}. Reconcile the manifest with that backup, then retry the install.",
            self.root.join(path).display(),
            self.root.join(".lpm").join(DIRECTORY).display(),
        ))
    }

    fn recover(&mut self) -> io::Result<()> {
        let Some(state) = self.state_directory(false)? else {
            return Ok(());
        };
        let committed = match read_regular(&state, OsStr::new(COMMITTED), 16) {
            Ok(bytes) if bytes == b"1\n" => true,
            Ok(_) => return Err(invalid("invalid install recovery commit marker")),
            Err(error) if error.kind() == io::ErrorKind::NotFound => false,
            Err(error) => return Err(error),
        };
        let mut names = Vec::new();
        let mut records = Vec::new();
        let mut total_bytes = 0usize;
        for entry in state.entries()? {
            let entry = entry?;
            let name = entry.file_name();
            if name == OsStr::new(COMMITTED) {
                continue;
            }
            if name
                .to_str()
                .is_some_and(lpm_common::atomic_write::is_atomic_temp_name)
            {
                state.remove_file(&name)?;
                continue;
            }
            let bytes = read_regular(&state, &name, RECORD_LIMIT)?;
            total_bytes = total_bytes.saturating_add(bytes.len());
            if total_bytes > TOTAL_LIMIT || names.len() >= 10_000 {
                return Err(invalid("install recovery exceeds its size limit"));
            }
            let record: Record = serde_json::from_slice(&bytes).map_err(io::Error::other)?;
            if record.schema_version != 1
                || name != OsStr::new(&record.name())
                || record.written.is_empty()
                || record.written.len() > 32
                || record.original.len() as u64 > lpm_common::CONFIG_FILE_SIZE_CAP_BYTES
            {
                return Err(invalid("invalid install recovery record"));
            }
            let parent = open_parent(&self.directory, &record.path)?;
            if !committed {
                let current = read_regular(
                    &parent,
                    OsStr::new("package.json"),
                    lpm_common::CONFIG_FILE_SIZE_CAP_BYTES,
                )?;
                if !record.accepts(&current) {
                    return Err(self.conflict(&record.path));
                }
            }
            names.push(name);
            records.push((record, parent));
        }
        if !committed {
            for (record, parent) in &records {
                let current = read_regular(
                    parent,
                    OsStr::new("package.json"),
                    lpm_common::CONFIG_FILE_SIZE_CAP_BYTES,
                )?;
                if !record.accepts(&current) {
                    return Err(self.conflict(&record.path));
                }
                if current != record.original.as_bytes() {
                    lpm_common::write_file_atomic_in_dir_with(
                        parent,
                        OsStr::new("package.json"),
                        |file| {
                            file.write_all(record.original.as_bytes())?;
                            file.sync_all()
                        },
                    )?;
                    sync_directory(parent)?;
                }
                invalidate_hash(parent)?;
            }
            invalidate_hash(&self.directory)?;
        }
        for name in names {
            state.remove_file(name)?;
        }
        if committed {
            state.remove_file(COMMITTED)?;
        }
        sync_directory(&state)?;
        let lpm = self.directory.open_dir_nofollow(".lpm")?;
        state.remove_open_dir()?;
        sync_directory(&lpm)
    }

    fn write(&mut self, path: &Path, expected: &str, contents: &[u8]) -> io::Result<()> {
        let canonical_parent = path
            .parent()
            .ok_or_else(|| invalid("manifest has no parent"))?
            .canonicalize()?;
        let canonical_path = canonical_parent.join("package.json");
        let relative = canonical_path
            .strip_prefix(&self.root)
            .map_err(|_| invalid("install manifest is outside the locked project"))?
            .to_path_buf();
        let parent = open_parent(&self.directory, &relative)?;
        let current = read_regular(
            &parent,
            OsStr::new("package.json"),
            lpm_common::CONFIG_FILE_SIZE_CAP_BYTES,
        )?;
        if current != expected.as_bytes()
            || self.records.get(&relative).is_some_and(|record| {
                record
                    .written
                    .last()
                    .is_some_and(|expected| *expected != digest(&current))
            })
        {
            return Err(self.conflict(&relative));
        }
        if !self.records.contains_key(&relative) {
            self.total_bytes = self.total_bytes.saturating_add(current.len());
            if self.total_bytes > TOTAL_LIMIT / 2 {
                return Err(invalid("install recovery exceeds its size limit"));
            }
            self.records.insert(
                relative.clone(),
                Record {
                    schema_version: 1,
                    path: relative.clone(),
                    original: expected.to_owned(),
                    written: Vec::with_capacity(3),
                },
            );
        }
        let record = self
            .records
            .get_mut(&relative)
            .ok_or_else(|| invalid("missing install recovery record"))?;
        let fingerprint = digest(contents);
        if !record.written.contains(&fingerprint) {
            if record.written.len() >= 32 {
                return Err(invalid("too many staged manifest revisions"));
            }
            record.written.push(fingerprint);
        }
        let name = record.name();
        let bytes = serde_json::to_vec(record).map_err(io::Error::other)?;
        if bytes.len() as u64 > RECORD_LIMIT {
            return Err(invalid("install recovery record exceeds its size limit"));
        }
        let state = self
            .state_directory(true)?
            .ok_or_else(|| invalid("missing install recovery directory"))?;
        // Persist the intended bytes before replacement so interruption in either write is recoverable.
        write_record(&state, OsStr::new(&name), &bytes)?;
        lpm_common::write_file_atomic_in_dir_with(&parent, OsStr::new("package.json"), |file| {
            file.write_all(contents)
        })
    }

    fn finish(&mut self, success: bool) -> io::Result<()> {
        if self.records.is_empty() {
            return Ok(());
        }
        if success {
            let state = self
                .state_directory(false)?
                .ok_or_else(|| invalid("missing install recovery directory"))?;
            write_record(&state, OsStr::new(COMMITTED), b"1\n")?;
        }
        self.recover()
    }
}

fn invalidate_hash(parent: &Dir) -> io::Result<()> {
    let lpm = match parent.open_dir_nofollow(".lpm") {
        Ok(directory) => directory,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    match lpm.remove_file("install-hash") {
        Ok(()) => sync_directory(&lpm),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

pub(crate) fn write_manifest(
    path: &Path,
    expected: &str,
    contents: impl AsRef<[u8]>,
) -> io::Result<()> {
    match ACTIVE.try_with(|recovery| {
        recovery
            .borrow_mut()
            .write(path, expected, contents.as_ref())
    }) {
        Ok(result) => result,
        Err(_) => lpm_common::write_file_atomic(path, contents),
    }
}

pub(crate) fn may_restore(path: &Path) -> bool {
    ACTIVE
        .try_with(|recovery| {
            let recovery = recovery.borrow();
            let Some(parent) = path.parent().and_then(|parent| parent.canonicalize().ok()) else {
                return false;
            };
            let canonical = parent.join(path.file_name().unwrap_or_default());
            let Some(record) = canonical
                .strip_prefix(&recovery.root)
                .ok()
                .and_then(|relative| recovery.records.get(relative))
            else {
                return true;
            };
            open_parent(&recovery.directory, &record.path)
                .and_then(|parent| {
                    read_regular(
                        &parent,
                        OsStr::new("package.json"),
                        lpm_common::CONFIG_FILE_SIZE_CAP_BYTES,
                    )
                })
                .is_ok_and(|current| record.accepts(&current))
        })
        .unwrap_or(true)
}

pub(crate) async fn scope<F, T>(root: &Path, directory: Dir, future: F) -> Result<T, LpmError>
where
    F: Future<Output = Result<T, LpmError>>,
{
    let mut recovery = Recovery {
        root: root.to_path_buf(),
        directory,
        records: HashMap::new(),
        total_bytes: 0,
    };
    recovery.recover()?;
    #[cfg(unix)]
    let mut interrupt = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
    #[cfg(unix)]
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    ACTIVE.scope(RefCell::new(recovery), async {
        let result = {
            tokio::pin!(future);
            #[cfg(unix)]
            let cancelled = async { tokio::select! { _ = interrupt.recv() => {}, _ = terminate.recv() => {} } };
            #[cfg(not(unix))]
            let cancelled = tokio::signal::ctrl_c();
            tokio::select! {
                biased;
                _ = cancelled => Err(LpmError::Io(io::Error::new(io::ErrorKind::Interrupted, "Install interrupted. Retry the install to reconcile node_modules."))),
                result = &mut future => result,
            }
        };
        ACTIVE.with(|recovery| recovery.borrow_mut().finish(result.is_ok()))?;
        result
    }).await
}
