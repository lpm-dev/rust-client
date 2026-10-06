use crate::{MAX_SCHEMA_BYTES, SourceError};
use cap_fs_ext::{DirExt as _, FollowSymlinks, OpenOptionsFollowExt as _, OpenOptionsSyncExt as _};
use std::io::Read as _;

pub(crate) struct Fragment {
    pub content: Vec<u8>,
    pub identity: same_file::Handle,
}

pub(crate) fn import_path(source: &str, import: &str) -> Result<String, SourceError> {
    if import.starts_with('/')
        || import
            .chars()
            .any(|c| c.is_control() || matches!(c, '\\' | ':' | '<' | '>' | '"' | '|' | '?' | '*'))
    {
        return Err(SourceError::new(
            "env.import_path",
            "resolve",
            source,
            "/extends",
        ));
    }
    let mut components: Vec<&str> = source
        .rsplit_once('/')
        .map_or(Vec::new(), |(base, _)| base.split('/').collect());
    for part in import.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                if components.pop().is_none() {
                    return Err(SourceError::new(
                        "env.import_escape",
                        "resolve",
                        source,
                        "/extends",
                    ));
                }
            }
            part if part.ends_with([' ', '.']) || reserved_windows_name(part) => {
                return Err(SourceError::new(
                    "env.import_path",
                    "resolve",
                    source,
                    "/extends",
                ));
            }
            part => components.push(part),
        }
    }
    let path = components.join("/");
    if path.is_empty() || path.len() > 512 {
        return Err(SourceError::new(
            "env.import_path",
            "resolve",
            source,
            "/extends",
        ));
    }
    Ok(path)
}

fn reserved_windows_name(part: &str) -> bool {
    let stem = part.split('.').next().unwrap_or_default();
    matches!(
        stem.to_ascii_uppercase().as_str(),
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
}

fn open_fragment(root: &cap_std::fs::Dir, path: &str) -> Result<cap_std::fs::File, SourceError> {
    let error = || SourceError::new("env.import_unreadable", "read", path, "");
    let mut directory = root.try_clone().map_err(|_| error())?;
    let mut parts = path.split('/').peekable();
    while let Some(part) = parts.next() {
        if parts.peek().is_some() {
            directory = directory.open_dir_nofollow(part).map_err(|_| error())?;
            let metadata = directory.dir_metadata().map_err(|_| error())?;
            if !metadata.is_dir() || is_reparse(&metadata) {
                return Err(error());
            }
            continue;
        }
        let mut options = cap_std::fs::OpenOptions::new();
        options.read(true).follow(FollowSymlinks::No).nonblock(true);
        let file = directory.open_with(part, &options).map_err(|_| error())?;
        let metadata = file.metadata().map_err(|_| error())?;
        if !metadata.is_file() || is_reparse(&metadata) {
            return Err(error());
        }
        if metadata.len() > MAX_SCHEMA_BYTES as u64 {
            return Err(SourceError::new("env.fragment_budget", "read", path, ""));
        }
        return Ok(file);
    }
    Err(error())
}

pub(crate) fn read_fragment(root: &cap_std::fs::Dir, path: &str) -> Result<Fragment, SourceError> {
    let error = || SourceError::new("env.import_unreadable", "read", path, "");
    let file = open_fragment(root, path)?;
    let metadata = file.metadata().map_err(|_| error())?;
    let identity = same_file::Handle::from_file(file.try_clone().map_err(|_| error())?.into_std())
        .map_err(|_| error())?;
    let mut content = Vec::with_capacity((metadata.len() as usize).min(MAX_SCHEMA_BYTES));
    file.into_std()
        .take(MAX_SCHEMA_BYTES as u64 + 1)
        .read_to_end(&mut content)
        .map_err(|_| error())?;
    if content.len() > MAX_SCHEMA_BYTES {
        return Err(SourceError::new("env.fragment_budget", "read", path, ""));
    }
    Ok(Fragment { content, identity })
}

pub(crate) fn verify_fragment(
    root: &cap_std::fs::Dir,
    dependency: &crate::SchemaDependency,
    scratch: &mut [u8],
) -> Result<bool, SourceError> {
    let error = || SourceError::new("env.source_changed", "freshness", &dependency.path, "");
    let file = open_fragment(root, &dependency.path)?;
    if file.metadata().map_err(|_| error())?.len() != dependency.bytes as u64 {
        return Ok(false);
    }
    digest_matches(
        file.into_std().take(MAX_SCHEMA_BYTES as u64 + 1),
        dependency,
        scratch,
    )
}

fn digest_matches(
    mut file: impl std::io::Read,
    dependency: &crate::SchemaDependency,
    scratch: &mut [u8],
) -> Result<bool, SourceError> {
    use sha2::{Digest as _, Sha256};
    let error = || SourceError::new("env.source_changed", "freshness", &dependency.path, "");
    let mut hash = Sha256::new();
    let mut total = 0usize;
    loop {
        let count = match file.read(scratch) {
            Ok(count) => count,
            Err(failure) if failure.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(error()),
        };
        if count == 0 {
            break;
        }
        total += count;
        if total > dependency.bytes {
            return Ok(false);
        }
        hash.update(&scratch[..count]);
    }
    Ok(total == dependency.bytes && <[u8; 32]>::from(hash.finalize()) == dependency.digest)
}

#[cfg(not(windows))]
fn is_reparse(metadata: &cap_std::fs::Metadata) -> bool {
    metadata.is_symlink()
}

#[cfg(windows)]
fn is_reparse(metadata: &cap_std::fs::Metadata) -> bool {
    use cap_std::fs::MetadataExt as _;
    metadata.file_attributes() & 0x400 != 0
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn interrupted_dependency_reads_retry_without_false_freshness_failures() {
        struct InterruptedReader {
            first: bool,
            data: std::io::Cursor<Vec<u8>>,
        }
        impl std::io::Read for InterruptedReader {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                if self.first {
                    self.first = false;
                    return Err(std::io::ErrorKind::Interrupted.into());
                }
                self.data.read(buf)
            }
        }
        let bytes = b"schema contents";
        let dependency = crate::SchemaDependency {
            path: "fragment.json".into(),
            digest: crate::digest(bytes),
            bytes: bytes.len(),
        };
        let reader = InterruptedReader {
            first: true,
            data: std::io::Cursor::new(bytes.to_vec()),
        };
        assert!(digest_matches(reader, &dependency, &mut [0; 4]).unwrap());
    }
}
