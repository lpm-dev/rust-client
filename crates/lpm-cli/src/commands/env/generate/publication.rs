use super::Error;
use crate::directory_transaction::{self as transaction, DirectoryIdentity};
use cap_fs_ext::{FollowSymlinks, OpenOptionsFollowExt as _, OpenOptionsSyncExt as _};
use cap_std::fs::{Dir, OpenOptions};
use lpm_env_codegen::{Generated, MAX_OUTPUT_BYTES, OWNED_FILES};
use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::io::{Read as _, Write as _};
use std::path::{Component, Path};

fn code<T>(result: std::io::Result<T>) -> Result<T, Error> {
    result.map_err(|_| Error::Code("env.generate_filesystem"))
}

struct Destination {
    root: Dir,
    root_identity: DirectoryIdentity,
    parents: Vec<(OsString, DirectoryIdentity)>,
    parent: Dir,
    name: OsString,
    display_parent: std::path::PathBuf,
}

impl Destination {
    fn open(project: &Path, output: &Path) -> Result<Self, Error> {
        let mut parts = Vec::new();
        for component in output.components() {
            let Component::Normal(part) = component else {
                return Err(Error::Code("env.generate_path"));
            };
            let Some(text) = part.to_str() else {
                return Err(Error::Code("env.generate_path"));
            };
            let stem = text
                .split('.')
                .next()
                .unwrap_or_default()
                .to_ascii_uppercase();
            if text.is_empty()
                || text.ends_with([' ', '.'])
                || text
                    .chars()
                    .any(|c| c.is_control() || "\\:<>\"|?*".contains(c))
                || matches!(
                    stem.as_str(),
                    "CON"
                        | "PRN"
                        | "AUX"
                        | "NUL"
                        | "COM1"
                        | "COM2"
                        | "COM3"
                        | "COM4"
                        | "COM5"
                        | "COM6"
                        | "COM7"
                        | "COM8"
                        | "COM9"
                        | "LPT1"
                        | "LPT2"
                        | "LPT3"
                        | "LPT4"
                        | "LPT5"
                        | "LPT6"
                        | "LPT7"
                        | "LPT8"
                        | "LPT9"
                )
            {
                return Err(Error::Code("env.generate_path"));
            }
            parts.push(part.to_os_string());
        }
        let name = parts.pop().ok_or(Error::Code("env.generate_path"))?;
        let root = code(Dir::open_ambient_dir(project, cap_std::ambient_authority()))?;
        let root_identity = code(transaction::directory_identity(&root))?;
        let mut parent = code(root.try_clone())?;
        let mut parents = Vec::with_capacity(parts.len());
        for name in parts {
            parent = code(transaction::open_directory_shared(&parent, &name))?;
            parents.push((name, code(transaction::directory_identity(&parent))?));
        }
        Ok(Self {
            root,
            root_identity,
            parents,
            parent,
            name,
            display_parent: project.join(output.parent().unwrap_or(Path::new(""))),
        })
    }

    fn verify(&self, project: &Path) -> Result<(), Error> {
        let mut visible = code(Dir::open_ambient_dir(project, cap_std::ambient_authority()))?;
        if code(transaction::directory_identity(&visible))? != self.root_identity {
            return Err(Error::Code("env.generate_destination_changed"));
        }
        for (name, identity) in &self.parents {
            visible = code(transaction::open_directory_shared(&visible, name))?;
            if &code(transaction::directory_identity(&visible))? != identity {
                return Err(Error::Code("env.generate_destination_changed"));
            }
        }
        Ok(())
    }

    fn existing(&self, write: bool) -> Result<Option<Dir>, Error> {
        let opened = if write {
            transaction::open_directory_for_publication(&self.parent, &self.name)
        } else {
            transaction::open_directory_shared(&self.parent, &self.name)
        };
        match opened {
            Ok(directory) => {
                inventory(&directory)?;
                Ok(Some(directory))
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(_) => Err(Error::Code("env.generate_unowned_directory")),
        }
    }

    fn verify_target(&self, old: Option<&Dir>) -> Result<(), Error> {
        match (old, self.existing(false)?) {
            (None, None) => Ok(()),
            (Some(old), Some(visible))
                if code(transaction::directory_identity(old))?
                    == code(transaction::directory_identity(&visible))? =>
            {
                Ok(())
            }
            _ => Err(Error::Code("env.generate_destination_changed")),
        }
    }
}

fn read(directory: &Dir, name: &str) -> Result<Vec<u8>, Error> {
    let mut options = OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No).nonblock(true);
    let file = code(directory.open_with(name, &options))?;
    let metadata = code(file.metadata())?;
    if !metadata.is_file() || is_reparse(&metadata) || metadata.len() > MAX_OUTPUT_BYTES as u64 {
        return Err(Error::Code("env.generate_unowned_directory"));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    code(
        file.take(MAX_OUTPUT_BYTES as u64 + 1)
            .read_to_end(&mut bytes),
    )?;
    if bytes.len() > MAX_OUTPUT_BYTES {
        return Err(Error::Code("env.generate_unowned_directory"));
    }
    Ok(bytes)
}

#[cfg(windows)]
fn is_reparse(metadata: &cap_std::fs::Metadata) -> bool {
    use cap_std::fs::MetadataExt as _;
    metadata.file_attributes() & 0x400 != 0
}
#[cfg(not(windows))]
fn is_reparse(_: &cap_std::fs::Metadata) -> bool {
    false
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    generator: String,
    identity: String,
    files: BTreeMap<String, String>,
}

fn inventory(directory: &Dir) -> Result<(), Error> {
    let mut count = 0;
    for entry in code(directory.entries())? {
        let entry = code(entry)?;
        if !OWNED_FILES
            .iter()
            .any(|name| entry.file_name() == OsStr::new(name))
        {
            return Err(Error::Code("env.generate_unowned_directory"));
        }
        let metadata = code(directory.symlink_metadata(entry.file_name()))?;
        if !metadata.is_file() || is_reparse(&metadata) {
            return Err(Error::Code("env.generate_unowned_directory"));
        }
        count += 1;
    }
    if count != OWNED_FILES.len() {
        return Err(Error::Code("env.generate_unowned_directory"));
    }
    let manifest: Manifest = serde_json::from_slice(&read(directory, ".lpm-env-generated.json")?)
        .map_err(|_| Error::Code("env.generate_unowned_directory"))?;
    let hash = |value: &str| {
        value.len() == 64
            && value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    };
    if manifest.generator != lpm_env_codegen::GENERATOR_VERSION
        || !hash(&manifest.identity)
        || manifest.files.len() != 5
        || OWNED_FILES[..5]
            .iter()
            .any(|name| !manifest.files.get(*name).is_some_and(|value| hash(value)))
    {
        return Err(Error::Code("env.generate_unowned_directory"));
    }
    for (name, digest) in manifest.files {
        if lpm_env_codegen::checksum(&read(directory, &name)?) != digest {
            return Err(Error::Code("env.generate_unowned_directory"));
        }
    }
    Ok(())
}

pub(super) fn write(
    project: &Path,
    output: &Path,
    generated: &Generated,
    check: bool,
    fresh: impl Fn() -> Result<(), Error>,
) -> Result<(), Error> {
    let destination = Destination::open(project, output)?;
    if check {
        let existing = destination
            .existing(false)?
            .ok_or(Error::Code("env.generate_stale"))?;
        for (&name, bytes) in &generated.files {
            if &read(&existing, name)? != bytes {
                return Err(Error::Code("env.generate_stale"));
            }
        }
        destination.verify(project)?;
        destination.verify_target(Some(&existing))?;
        fresh()?;
        return Ok(());
    }
    let locks = lpm_common::ProjectLockDirectory::open_or_create(&destination.root, project)
        .map_err(|_| Error::Code("env.generate_filesystem"))?;
    let mut result = Ok(());
    lpm_common::with_capability_exclusive_lock(
        locks.directory(),
        &project.join(".lpm"),
        OsStr::new(".env-generate.lock"),
        || {
            result = publish(&destination, project, generated, &fresh);
            Ok(())
        },
    )
    .map_err(|_| Error::Code("env.generate_filesystem"))?;
    result
}

trait PublicationIo {
    fn create_stage(&self, private: &Dir) -> std::io::Result<Dir> {
        private.create_dir("next")?;
        transaction::open_directory_for_publication(private, OsStr::new("next"))
    }
    fn identity(&self, directory: &Dir) -> std::io::Result<DirectoryIdentity> {
        transaction::directory_identity(directory)
    }
    fn rename_noreplace(
        &self,
        source: &Dir,
        directory: &Dir,
        name: &OsStr,
        destination: &Dir,
        target: &OsStr,
    ) -> std::io::Result<()> {
        transaction::publish_directory_noreplace(source, directory, name, destination, target)
    }
}

struct NativeIo;
impl PublicationIo for NativeIo {}

fn identity_matches(parent: &Dir, name: &OsStr, retained: &Dir, io: &impl PublicationIo) -> bool {
    let visible =
        transaction::open_directory_shared(parent, name).and_then(|visible| io.identity(&visible));
    matches!((visible,io.identity(retained)),(Ok(visible),Ok(retained)) if visible == retained)
}

#[cfg(target_os = "macos")]
fn retained_directory_path(directory: &Dir) -> std::io::Result<std::path::PathBuf> {
    use std::os::unix::ffi::OsStringExt as _;
    Ok(OsString::from_vec(rustix::fs::getpath(directory)?.into_bytes()).into())
}

#[cfg(target_os = "linux")]
fn retained_directory_path(directory: &Dir) -> std::io::Result<std::path::PathBuf> {
    use std::os::fd::AsRawFd as _;
    std::fs::read_link(format!("/proc/self/fd/{}", directory.as_raw_fd()))
}

#[cfg(windows)]
fn retained_directory_path(directory: &Dir) -> std::io::Result<std::path::PathBuf> {
    use std::os::windows::ffi::OsStringExt as _;
    use std::os::windows::io::AsRawHandle as _;
    use windows_sys::Win32::Storage::FileSystem::GetFinalPathNameByHandleW;
    let mut path = vec![0u16; 512];
    loop {
        let length = unsafe {
            // SAFETY: The directory handle is live and the buffer is writable for its declared length.
            GetFinalPathNameByHandleW(
                directory.as_raw_handle(),
                path.as_mut_ptr(),
                path.len() as u32,
                0,
            )
        };
        if length == 0 {
            return Err(std::io::Error::last_os_error());
        }
        if length as usize >= path.len() {
            path.resize(length as usize + 1, 0);
            continue;
        }
        path.truncate(length as usize);
        return Ok(OsString::from_wide(&path).into());
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
fn retained_directory_path(_: &Dir) -> std::io::Result<std::path::PathBuf> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "directory paths are unavailable",
    ))
}

fn publish(
    destination: &Destination,
    project: &Path,
    generated: &Generated,
    fresh: &impl Fn() -> Result<(), Error>,
) -> Result<(), Error> {
    publish_with(destination, project, generated, fresh, &NativeIo)
}

fn publish_with(
    destination: &Destination,
    project: &Path,
    generated: &Generated,
    fresh: &impl Fn() -> Result<(), Error>,
    io: &impl PublicationIo,
) -> Result<(), Error> {
    let old = destination.existing(true)?;
    let (private_name, private) = code(transaction::create_private_directory(
        &destination.parent,
        "env-generated",
    ))?;
    let recovery = || Error::Recovery {
        directory: retained_directory_path(&private)
            .unwrap_or_else(|_| destination.display_parent.join(&private_name)),
    };
    let stage = match io.create_stage(&private) {
        Ok(stage) => stage,
        Err(_) => {
            match transaction::open_directory_for_publication(&private, OsStr::new("next")) {
                Ok(stage) => {
                    transaction::discard_private_directory(stage).map_err(|_| recovery())?
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => return Err(recovery()),
            }
            discard_transaction(&private).map_err(|_| recovery())?;
            return Err(Error::Code("env.generate_filesystem"));
        }
    };
    let prepare = || {
        for (&name, bytes) in &generated.files {
            let mut options = OpenOptions::new();
            options
                .write(true)
                .create_new(true)
                .follow(FollowSymlinks::No);
            let mut file = code(stage.open_with(name, &options))?;
            code(file.write_all(bytes))?;
            code(file.sync_all())?;
        }
        inventory(&stage)?;
        destination.verify(project)?;
        destination.verify_target(old.as_ref())?;
        fresh()?;
        if !identity_matches(&destination.parent, &private_name, &private, io)
            || !identity_matches(&private, OsStr::new("next"), &stage, io)
        {
            return Err(Error::Code("env.generate_destination_changed"));
        }
        Ok(())
    };
    if let Err(error) = prepare() {
        clean_created(stage).map_err(|_| recovery())?;
        discard_transaction(&private).map_err(|_| recovery())?;
        return Err(error);
    }
    if let Some(old) = old {
        let moved = io.rename_noreplace(
            &destination.parent,
            &old,
            &destination.name,
            &private,
            OsStr::new("previous"),
        );
        let previous =
            transaction::open_directory_for_publication(&private, OsStr::new("previous"));
        match previous {
            Ok(previous) => {
                let admission = (|| {
                    if code(io.identity(&previous))? != code(io.identity(&old))? {
                        return Err(Error::Code("env.generate_destination_changed"));
                    }
                    inventory(&previous)?;
                    destination.verify(project)?;
                    fresh()?;
                    destination.verify(project)
                })();
                if moved.is_err() || admission.is_err() {
                    restore(
                        &private,
                        &previous,
                        &destination.parent,
                        &destination.name,
                        io,
                    )
                    .map_err(|_| recovery())?;
                    clean_created(stage).map_err(|_| recovery())?;
                    discard_transaction(&private).map_err(|_| recovery())?;
                    return Err(admission
                        .err()
                        .unwrap_or(Error::Code("env.generate_filesystem")));
                }
            }
            Err(_) if moved.is_ok() => return Err(recovery()),
            Err(_) => {
                if !identity_matches(&destination.parent, &destination.name, &old, io) {
                    return Err(recovery());
                }
                clean_created(stage).map_err(|_| recovery())?;
                discard_transaction(&private).map_err(|_| recovery())?;
                return Err(Error::Code("env.generate_filesystem"));
            }
        }
        let published = io.rename_noreplace(
            &private,
            &stage,
            OsStr::new("next"),
            &destination.parent,
            &destination.name,
        );
        if published.is_err()
            && !identity_matches(&destination.parent, &destination.name, &stage, io)
        {
            restore(&private, &old, &destination.parent, &destination.name, io)
                .map_err(|_| recovery())?;
            clean_created(stage).map_err(|_| recovery())?;
            discard_transaction(&private).map_err(|_| recovery())?;
            return Err(Error::Code("env.generate_filesystem"));
        }
        if !identity_matches(&destination.parent, &destination.name, &stage, io) {
            return Err(recovery());
        }
        destination.verify(project).map_err(|_| recovery())?;
        clean_owned(old).map_err(|_| recovery())?;
    } else {
        let published = io.rename_noreplace(
            &private,
            &stage,
            OsStr::new("next"),
            &destination.parent,
            &destination.name,
        );
        if published.is_err()
            && !identity_matches(&destination.parent, &destination.name, &stage, io)
        {
            clean_created(stage).map_err(|_| recovery())?;
            discard_transaction(&private).map_err(|_| recovery())?;
            return Err(Error::Code("env.generate_filesystem"));
        }
        destination.verify(project).map_err(|_| recovery())?;
    }
    discard_transaction(&private).map_err(|_| recovery())?;
    destination.verify(project)?;
    Ok(())
}

fn discard_transaction(private: &Dir) -> std::io::Result<()> {
    transaction::discard_private_directory(private.try_clone()?)
}

fn restore(
    private: &Dir,
    previous: &Dir,
    parent: &Dir,
    name: &OsStr,
    io: &impl PublicationIo,
) -> Result<(), Error> {
    let restored = io.rename_noreplace(private, previous, OsStr::new("previous"), parent, name);
    if restored.is_err() && !identity_matches(parent, name, previous, io) {
        return Err(Error::Code("env.generate_recovery_required"));
    }
    Ok(())
}

fn clean_created(directory: Dir) -> Result<(), Error> {
    for name in OWNED_FILES {
        match directory.remove_file(name) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(Error::Code("env.generate_cleanup")),
        }
    }
    code(transaction::discard_private_directory(directory))
}

fn clean_owned(directory: Dir) -> Result<(), Error> {
    inventory(&directory)?;
    clean_created(directory)
}

#[cfg(test)]
mod tests;
