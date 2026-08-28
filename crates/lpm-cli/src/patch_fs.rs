use cap_fs_ext::{DirExt as _, FollowSymlinks, OpenOptionsFollowExt as _, OpenOptionsSyncExt as _};
use cap_std::fs::{Dir, OpenOptions};
use lpm_common::LpmError;
use sha2::{Digest, Sha256};
#[cfg(not(windows))]
use std::ffi::OsStr;
use std::ffi::OsString;
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};

pub const PATCH_FILE_SIZE_CAP_BYTES: u64 = 256 * 1024 * 1024;

#[derive(Debug)]
pub struct PatchArtifact {
    pub relative_path: PathBuf,
    pub bytes: Vec<u8>,
    pub sha256: String,
}

pub struct SafeRoot {
    dir: Dir,
    display: PathBuf,
}

impl SafeRoot {
    pub fn open(path: &Path) -> Result<Self, LpmError> {
        let dir = if let Some(name) = path.file_name() {
            let parent_path = path
                .parent()
                .filter(|parent| !parent.as_os_str().is_empty())
                .unwrap_or_else(|| Path::new("."));
            let parent = Dir::open_ambient_dir(parent_path, cap_std::ambient_authority())
                .map_err(LpmError::Io)?;
            parent.open_dir_nofollow(name).map_err(|error| {
                LpmError::Script(format!(
                    "patch root is missing, linked, or unsafe at {}: {error}",
                    path.display()
                ))
            })?
        } else {
            Dir::open_ambient_dir(path, cap_std::ambient_authority()).map_err(LpmError::Io)?
        };
        if !dir.dir_metadata().map_err(LpmError::Io)?.is_dir() {
            return Err(LpmError::Script(format!(
                "patch root is not a real directory: {}",
                path.display()
            )));
        }
        Ok(Self {
            dir,
            display: path.to_path_buf(),
        })
    }

    pub fn read_regular_file(&self, relative: &Path, limit: u64) -> Result<Vec<u8>, LpmError> {
        let mut file = self.open_regular_file(relative, limit)?;
        let metadata = file.metadata().map_err(LpmError::Io)?;
        let mut bytes = Vec::with_capacity(usize::try_from(metadata.len()).unwrap_or_default());
        Read::by_ref(&mut file)
            .take(limit.saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(LpmError::Io)?;
        if bytes.len() as u64 > limit {
            return Err(LpmError::Script(format!(
                "patch file {} exceeds the {limit}-byte limit",
                self.display.join(relative).display()
            )));
        }
        Ok(bytes)
    }

    pub fn sha256_regular_file(&self, relative: &Path, limit: u64) -> Result<String, LpmError> {
        let mut file = self.open_regular_file(relative, limit)?;
        let mut reader = Read::by_ref(&mut file).take(limit.saturating_add(1));
        let mut hasher = Sha256::new();
        let mut buffer = [0u8; 64 * 1024];
        let mut total = 0u64;
        loop {
            let read = reader.read(&mut buffer).map_err(LpmError::Io)?;
            if read == 0 {
                break;
            }
            total = total.saturating_add(read as u64);
            if total > limit {
                return Err(self.file_size_error(relative, limit));
            }
            hasher.update(&buffer[..read]);
        }
        Ok(format!("sha256-{}", hex::encode(hasher.finalize())))
    }

    pub fn open_directory(&self, relative: &Path) -> Result<Self, LpmError> {
        validate_relative_path(relative)?;
        let mut dir = self.dir.try_clone().map_err(LpmError::Io)?;
        for component in relative.components() {
            let Component::Normal(name) = component else {
                return Err(unsafe_path(relative));
            };
            dir = dir.open_dir_nofollow(name).map_err(|error| {
                LpmError::Script(format!(
                    "patch directory is missing, linked, or unsafe at {}: {error}",
                    self.display.join(relative).display()
                ))
            })?;
        }
        Ok(Self {
            dir,
            display: self.display.join(relative),
        })
    }

    pub fn write_regular_file(
        &self,
        relative: &Path,
        bytes: &[u8],
        mode_hint: Option<u32>,
    ) -> Result<(), LpmError> {
        let (parent, name) = self.open_parent(relative, true)?;
        let exact_mode = match parent.symlink_metadata(&name) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() || !metadata.is_file() {
                    return Err(LpmError::Script(format!(
                        "refusing to replace linked or non-file patch target {}",
                        self.display.join(relative).display()
                    )));
                }
                #[cfg(unix)]
                {
                    Some(file_mode(&metadata))
                }
                #[cfg(not(unix))]
                {
                    mode_hint
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => mode_hint,
            Err(error) => return Err(LpmError::Io(error)),
        };
        #[cfg(windows)]
        {
            let _ = exact_mode;
            return lpm_common::write_file_atomic_in_dir_with(
                &parent,
                &name,
                |temporary| -> std::io::Result<()> {
                    temporary.write_all(bytes)?;
                    temporary.sync_all()
                },
            )
            .map_err(LpmError::Io);
        }
        #[cfg(not(windows))]
        {
            let (temporary_name, mut temporary) = create_temporary(&parent, exact_mode)?;
            let result = (|| -> std::io::Result<()> {
                temporary.write_all(bytes)?;
                #[cfg(unix)]
                if let Some(mode) = exact_mode {
                    use cap_std::fs::PermissionsExt as _;
                    temporary.set_permissions(cap_std::fs::Permissions::from_mode(mode))?;
                }
                temporary.sync_all()?;
                replace_file(&parent, &temporary_name, &name, temporary)
            })();
            if result.is_err() {
                let _ = parent.remove_file(&temporary_name);
            }
            result.map_err(LpmError::Io)
        }
    }

    pub fn remove_regular_file(&self, relative: &Path) -> Result<bool, LpmError> {
        let Some((parent, name)) = self.open_parent_optional(relative, false)? else {
            return Ok(false);
        };
        let metadata = match parent.symlink_metadata(&name) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(LpmError::Io(error)),
        };
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(LpmError::Script(format!(
                "refusing to remove linked or non-file patch target {}",
                self.display.join(relative).display()
            )));
        }
        parent.remove_file(&name).map_err(LpmError::Io)?;
        Ok(true)
    }

    pub fn regular_file_equals(&self, relative: &Path, expected: &[u8]) -> Result<bool, LpmError> {
        if !self.regular_file_exists(relative)? {
            return Ok(false);
        }
        let bytes = match self.read_regular_file(relative, expected.len() as u64) {
            Ok(bytes) => bytes,
            Err(LpmError::Script(message)) if message.contains("exceeds") => return Ok(false),
            Err(error) => return Err(error),
        };
        Ok(bytes == expected)
    }

    pub fn regular_file_exists(&self, relative: &Path) -> Result<bool, LpmError> {
        let Some((parent, name)) = self.open_parent_optional(relative, false)? else {
            return Ok(false);
        };
        match parent.symlink_metadata(&name) {
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
                Err(LpmError::Script(format!(
                    "patch target is linked or is not a regular file: {}",
                    self.display.join(relative).display()
                )))
            }
            Ok(_) => Ok(true),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(LpmError::Io(error)),
        }
    }

    pub fn regular_file_mode(&self, relative: &Path) -> Result<Option<u32>, LpmError> {
        let (parent, name) = self.open_parent(relative, false)?;
        let metadata = parent.symlink_metadata(&name).map_err(LpmError::Io)?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(LpmError::Script(format!(
                "patch target is linked or is not a regular file: {}",
                self.display.join(relative).display()
            )));
        }
        #[cfg(unix)]
        {
            Ok(Some(file_mode(&metadata)))
        }
        #[cfg(not(unix))]
        {
            Ok(None)
        }
    }

    fn open_parent(&self, relative: &Path, create: bool) -> Result<(Dir, OsString), LpmError> {
        self.open_parent_optional(relative, create)?.ok_or_else(|| {
            LpmError::Script(format!(
                "patch path parent is missing at {}",
                self.display.join(relative).display()
            ))
        })
    }

    fn open_regular_file(
        &self,
        relative: &Path,
        limit: u64,
    ) -> Result<cap_std::fs::File, LpmError> {
        let (parent, name) = self.open_parent(relative, false)?;
        let mut options = OpenOptions::new();
        options.read(true).follow(FollowSymlinks::No).nonblock(true);
        let file = parent.open_with(&name, &options).map_err(|error| {
            LpmError::Script(format!(
                "patch file {} is unreadable or is a symbolic link: {error}",
                self.display.join(relative).display()
            ))
        })?;
        let metadata = file.metadata().map_err(LpmError::Io)?;
        if !metadata.is_file() {
            return Err(LpmError::Script(format!(
                "patch file is not a regular file: {}",
                self.display.join(relative).display()
            )));
        }
        if metadata.len() > limit {
            return Err(self.file_size_error(relative, limit));
        }
        Ok(file)
    }

    fn file_size_error(&self, relative: &Path, limit: u64) -> LpmError {
        LpmError::Script(format!(
            "patch file {} exceeds the {limit}-byte limit",
            self.display.join(relative).display()
        ))
    }

    fn open_parent_optional(
        &self,
        relative: &Path,
        create: bool,
    ) -> Result<Option<(Dir, OsString)>, LpmError> {
        validate_relative_path(relative)?;
        let mut components = relative.components().peekable();
        let mut parent = self.dir.try_clone().map_err(LpmError::Io)?;
        while let Some(component) = components.next() {
            let Component::Normal(name) = component else {
                return Err(unsafe_path(relative));
            };
            if components.peek().is_none() {
                return Ok(Some((parent, name.to_os_string())));
            }
            parent = match parent.open_dir_nofollow(name) {
                Ok(next) => next,
                Err(error) if create && error.kind() == std::io::ErrorKind::NotFound => {
                    match parent.create_dir(name) {
                        Ok(()) => {}
                        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                        Err(error) => return Err(LpmError::Io(error)),
                    }
                    parent.open_dir_nofollow(name).map_err(|error| {
                        LpmError::Script(format!(
                            "patch path parent is linked or unsafe at {}: {error}",
                            self.display.join(relative).display()
                        ))
                    })?
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
                Err(error) => {
                    return Err(LpmError::Script(format!(
                        "patch path parent is linked, missing, or unsafe at {}: {error}",
                        self.display.join(relative).display()
                    )));
                }
            };
        }
        Err(unsafe_path(relative))
    }
}

pub fn validate_manifest_patch_path(raw: &str) -> Result<PathBuf, LpmError> {
    if raw.is_empty()
        || raw.starts_with(['/', '\\'])
        || raw.contains('\\')
        || raw.chars().any(char::is_control)
    {
        return Err(LpmError::Script(format!(
            "unsafe patch path {raw:?}; expected a project-relative forward-slash path"
        )));
    }
    let mut relative = PathBuf::new();
    for segment in raw.split('/') {
        if segment == "." {
            continue;
        }
        if segment.is_empty()
            || segment == ".."
            || is_windows_forbidden_component(segment)
            || segment.ends_with(['.', ' '])
        {
            return Err(LpmError::Script(format!(
                "unsafe patch path {raw:?}; expected a project-relative forward-slash path"
            )));
        }
        relative.push(segment);
    }
    validate_relative_path(&relative)?;
    Ok(relative)
}

pub fn is_windows_reserved_component(component: &str) -> bool {
    let stem = component.split('.').next().unwrap_or_default();
    let upper = stem.to_ascii_uppercase();
    matches!(
        upper.as_str(),
        "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
    ) || upper
        .strip_prefix("COM")
        .or_else(|| upper.strip_prefix("LPT"))
        .is_some_and(|suffix| {
            matches!(
                suffix,
                "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"
            )
        })
}

pub fn is_windows_forbidden_component(component: &str) -> bool {
    component
        .chars()
        .any(|character| matches!(character, '<' | '>' | ':' | '"' | '|' | '?' | '*'))
        || is_windows_reserved_component(component)
}

pub fn load_patch_artifact(project_dir: &Path, raw: &str) -> Result<PatchArtifact, LpmError> {
    let relative_path = validate_manifest_patch_path(raw)?;
    let root = SafeRoot::open(project_dir)?;
    let bytes = root.read_regular_file(&relative_path, PATCH_FILE_SIZE_CAP_BYTES)?;
    let sha256 = sha256_bytes(&bytes);
    Ok(PatchArtifact {
        relative_path,
        bytes,
        sha256,
    })
}

pub fn patch_artifact_sha256(project_dir: &Path, raw: &str) -> Result<String, LpmError> {
    let relative_path = validate_manifest_patch_path(raw)?;
    SafeRoot::open(project_dir)?.sha256_regular_file(&relative_path, PATCH_FILE_SIZE_CAP_BYTES)
}

pub fn sha256_bytes(bytes: &[u8]) -> String {
    format!("sha256-{}", hex::encode(Sha256::digest(bytes)))
}

pub fn validate_relative_path(path: &Path) -> Result<(), LpmError> {
    if path.as_os_str().is_empty()
        || path.is_absolute()
        || !path
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
    {
        return Err(unsafe_path(path));
    }
    Ok(())
}

fn unsafe_path(path: &Path) -> LpmError {
    LpmError::Script(format!(
        "patch path must be project-relative and contain only normal components: {}",
        path.display()
    ))
}

#[cfg(not(windows))]
fn create_temporary(
    parent: &Dir,
    mode: Option<u32>,
) -> Result<(OsString, cap_std::fs::File), LpmError> {
    use rand::RngCore as _;

    let mut last_collision = None;
    for _ in 0..32 {
        let mut random = [0u8; 12];
        rand::rngs::OsRng.fill_bytes(&mut random);
        let name = OsString::from(format!(".lpm-patch-{}.tmp", hex::encode(random)));
        let mut options = OpenOptions::new();
        options.read(true).write(true).create_new(true);
        #[cfg(unix)]
        {
            use cap_std::fs::OpenOptionsExt as _;
            options.mode(mode.unwrap_or(0o666));
        }
        match parent.open_with(&name, &options) {
            Ok(file) => return Ok((name, file)),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                last_collision = Some(error);
            }
            Err(error) => return Err(LpmError::Io(error)),
        }
    }
    Err(LpmError::Io(last_collision.unwrap_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "could not allocate patch temporary file",
        )
    })))
}

#[cfg(not(windows))]
fn replace_file(
    parent: &Dir,
    temporary_name: &OsStr,
    destination: &OsStr,
    temporary: cap_std::fs::File,
) -> std::io::Result<()> {
    drop(temporary);
    parent.rename(temporary_name, parent, destination)
}

#[cfg(unix)]
fn file_mode(metadata: &cap_std::fs::Metadata) -> u32 {
    use cap_std::fs::PermissionsExt as _;
    metadata.permissions().mode() & 0o7777
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_patch_artifact_rejects_oversized_regular_file() {
        let project = tempfile::tempdir().unwrap();
        std::fs::create_dir(project.path().join("patches")).unwrap();
        let path = project.path().join("patches/oversized.patch");
        let file = std::fs::File::create(path).unwrap();
        file.set_len(PATCH_FILE_SIZE_CAP_BYTES + 1).unwrap();

        let error = load_patch_artifact(project.path(), "patches/oversized.patch").unwrap_err();

        assert!(format!("{error}").contains("exceeds"));
    }

    #[test]
    fn patch_artifact_sha256_matches_full_digest_across_stream_buffers() {
        let project = tempfile::tempdir().unwrap();
        std::fs::create_dir(project.path().join("patches")).unwrap();
        let mut bytes = vec![b'a'; 128 * 1024 + 13];
        bytes[64 * 1024] = b'b';
        std::fs::write(project.path().join("patches/large.patch"), &bytes).unwrap();

        let digest = patch_artifact_sha256(project.path(), "patches/large.patch").unwrap();

        assert_eq!(digest, sha256_bytes(&bytes));
    }

    #[test]
    fn manifest_patch_path_rejects_windows_device_name() {
        for name in ["CON.patch", "CONIN$.patch", "COM¹.patch"] {
            let error = validate_manifest_patch_path(&format!("patches/{name}")).unwrap_err();
            assert!(format!("{error}").contains("unsafe patch path"));
        }
    }

    #[test]
    fn manifest_patch_path_rejects_windows_forbidden_characters() {
        for character in ['<', '>', '"', '|', '?', '*'] {
            let raw = format!("patches/pkg{character}.patch");
            let error = validate_manifest_patch_path(&raw).unwrap_err();
            assert!(
                format!("{error}").contains("unsafe patch path"),
                "path containing {character:?} must be rejected"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn safe_root_rejects_symbolic_link_root() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("target");
        let linked = directory.path().join("linked");
        std::fs::create_dir(&target).unwrap();
        symlink(&target, &linked).unwrap();

        assert!(SafeRoot::open(&linked).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn safe_root_write_rejects_symbolic_link_parent() {
        use std::os::unix::fs::symlink;

        let project = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        symlink(outside.path(), project.path().join("patches")).unwrap();
        let root = SafeRoot::open(project.path()).unwrap();

        assert!(
            root.write_regular_file(Path::new("patches/escape.patch"), b"escape", None)
                .is_err()
        );
        assert!(!outside.path().join("escape.patch").exists());
    }

    #[cfg(unix)]
    #[test]
    fn load_patch_artifact_rejects_symbolic_link_file() {
        use std::os::unix::fs::symlink;

        let project = tempfile::tempdir().unwrap();
        let outside = tempfile::NamedTempFile::new().unwrap();
        std::fs::create_dir(project.path().join("patches")).unwrap();
        symlink(outside.path(), project.path().join("patches/linked.patch")).unwrap();

        assert!(load_patch_artifact(project.path(), "patches/linked.patch").is_err());
    }
}
