use std::fs::{File, Metadata};
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use thiserror::Error;

const INITIAL_BUFFER_CAPACITY_BYTES: u64 = 8 * 1024;

/// Maximum size accepted for local JSON, TOML, YAML, and dotenv configuration.
pub const CONFIG_FILE_SIZE_CAP_BYTES: u64 = 16 * 1024 * 1024;

/// Maximum size accepted for each `.npmrc` configuration layer.
pub const NPMRC_FILE_SIZE_CAP_BYTES: u64 = 1024 * 1024;

/// Maximum size accepted for a CA bundle, client certificate, or private key.
pub const TLS_MATERIAL_FILE_SIZE_CAP_BYTES: u64 = 1024 * 1024;

/// A distinguishable failure from a bounded local-file read.
#[derive(Debug, Error)]
pub enum BoundedReadError {
    /// The path did not exist when the single open operation was attempted.
    #[error("file {path} was not found")]
    NotFound { path: PathBuf },

    /// The opened file supplied more bytes than the configured limit.
    #[error("file {path} exceeds {limit}-byte limit")]
    TooLarge { path: PathBuf, limit: u64 },

    /// A text file contained bytes that are not valid UTF-8.
    #[error("file {path} is not valid UTF-8: {source}")]
    InvalidUtf8 {
        path: PathBuf,
        #[source]
        source: std::str::Utf8Error,
    },

    /// Opening, inspecting, or reading the file failed for another reason.
    #[error("failed to read file {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
}

impl BoundedReadError {
    /// Return the path whose read failed.
    #[inline]
    pub fn path(&self) -> &Path {
        match self {
            Self::NotFound { path }
            | Self::TooLarge { path, .. }
            | Self::InvalidUtf8 { path, .. }
            | Self::Io { path, .. } => path,
        }
    }
}

impl From<BoundedReadError> for crate::error::LpmError {
    fn from(error: BoundedReadError) -> Self {
        Self::Io(io::Error::other(error))
    }
}

/// Read at most `limit + 1` bytes from a local file opened exactly once.
///
/// Descriptor metadata provides an early oversized-file rejection, while the
/// bounded read remains authoritative if the file grows after that check.
/// Symlinks retain normal `File::open` behavior and the limit applies to the
/// opened target.
pub fn read_file_capped(path: &Path, limit: u64) -> Result<Vec<u8>, BoundedReadError> {
    read_file_capped_with_metadata(path, limit).map(|(bytes, _)| bytes)
}

fn read_file_capped_with_metadata(
    path: &Path,
    limit: u64,
) -> Result<(Vec<u8>, Metadata), BoundedReadError> {
    let mut file = match File::open(path) {
        Ok(file) => file,
        Err(source) if source.kind() == io::ErrorKind::NotFound => {
            return Err(BoundedReadError::NotFound {
                path: path.to_path_buf(),
            });
        }
        Err(source) => {
            return Err(BoundedReadError::Io {
                path: path.to_path_buf(),
                source,
            });
        }
    };

    let metadata = file.metadata().map_err(|source| BoundedReadError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    if metadata.len() > limit {
        return Err(BoundedReadError::TooLarge {
            path: path.to_path_buf(),
            limit,
        });
    }

    let bytes = read_opened_file_capped(&mut file, path, limit)?;
    Ok((bytes, metadata))
}

/// Read a bounded local file and validate it as UTF-8 text.
pub fn read_text_file_capped(path: &Path, limit: u64) -> Result<String, BoundedReadError> {
    read_text_file_capped_with_metadata(path, limit).map(|(content, _)| content)
}

/// Read a bounded UTF-8 text file and return metadata from the opened file.
///
/// The metadata and content come from the same file descriptor. Callers can
/// therefore make security decisions about the file that supplied the bytes,
/// even if the path is a symlink or is replaced concurrently.
pub fn read_text_file_capped_with_metadata(
    path: &Path,
    limit: u64,
) -> Result<(String, Metadata), BoundedReadError> {
    let (bytes, metadata) = read_file_capped_with_metadata(path, limit)?;
    String::from_utf8(bytes)
        .map_err(|source| BoundedReadError::InvalidUtf8 {
            path: path.to_path_buf(),
            source: source.utf8_error(),
        })
        .map(|content| (content, metadata))
}

/// Return whether a Unix mode denies all group and other permissions.
#[cfg(unix)]
#[inline]
pub fn permissions_are_owner_only(permissions: &std::fs::Permissions) -> bool {
    use std::os::unix::fs::PermissionsExt;

    permissions.mode() & 0o077 == 0
}

fn read_opened_file_capped<R: Read>(
    reader: &mut R,
    path: &Path,
    limit: u64,
) -> Result<Vec<u8>, BoundedReadError> {
    let read_limit = limit.checked_add(1).ok_or_else(|| BoundedReadError::Io {
        path: path.to_path_buf(),
        source: io::Error::new(io::ErrorKind::InvalidInput, "file size limit is too large"),
    })?;
    let initial_capacity = usize::try_from(read_limit.min(INITIAL_BUFFER_CAPACITY_BYTES))
        .expect("bounded initial capacity fits usize");
    let mut bytes = Vec::with_capacity(initial_capacity);
    reader
        .take(read_limit)
        .read_to_end(&mut bytes)
        .map_err(|source| BoundedReadError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    if bytes.len() as u64 > limit {
        return Err(BoundedReadError::TooLarge {
            path: path.to_path_buf(),
            limit,
        });
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn empty_and_ordinary_files_are_read() {
        let dir = tempfile::tempdir().unwrap();
        let empty = dir.path().join("empty.toml");
        let ordinary = dir.path().join("ordinary.toml");
        std::fs::write(&empty, b"").unwrap();
        std::fs::write(&ordinary, b"key = \"value\"\n").unwrap();

        assert_eq!(read_text_file_capped(&empty, 32).unwrap(), "");
        assert_eq!(
            read_text_file_capped(&ordinary, 32).unwrap(),
            "key = \"value\"\n"
        );
    }

    #[test]
    fn file_exactly_at_limit_is_read() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("exact");
        std::fs::write(&path, b"12345").unwrap();

        assert_eq!(read_file_capped(&path, 5).unwrap(), b"12345");
    }

    #[test]
    fn file_one_byte_over_limit_returns_too_large() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("oversized");
        std::fs::write(&path, b"123456").unwrap();

        assert!(matches!(
            read_file_capped(&path, 5),
            Err(BoundedReadError::TooLarge { limit: 5, .. })
        ));
    }

    #[test]
    fn sparse_oversized_file_is_rejected_from_descriptor_metadata() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sparse");
        let file = File::create(&path).unwrap();
        file.set_len(1024 * 1024 * 1024).unwrap();

        assert!(matches!(
            read_file_capped(&path, 1024),
            Err(BoundedReadError::TooLarge { limit: 1024, .. })
        ));
    }

    #[test]
    fn reader_growth_after_preliminary_size_is_still_bounded() {
        let path = Path::new("growing-config");
        let mut reader = Cursor::new(b"123456789".as_slice());

        assert!(matches!(
            read_opened_file_capped(&mut reader, path, 5),
            Err(BoundedReadError::TooLarge { limit: 5, .. })
        ));
        assert_eq!(reader.position(), 6);
    }

    #[test]
    fn missing_file_remains_distinguishable() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("missing.toml");

        assert!(matches!(
            read_file_capped(&path, 32),
            Err(BoundedReadError::NotFound { .. })
        ));
    }

    #[test]
    fn invalid_utf8_remains_distinguishable_for_text_files() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("invalid.toml");
        std::fs::write(&path, b"TOP_SECRET\xff").unwrap();

        let error = read_text_file_capped(&path, 32).unwrap_err();
        assert!(matches!(error, BoundedReadError::InvalidUtf8 { .. }));
        assert!(!error.to_string().contains("TOP_SECRET"));
        assert!(!format!("{error:?}").contains("TOP_SECRET"));
    }

    #[cfg(unix)]
    #[test]
    fn other_read_only_mode_is_not_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        assert!(!permissions_are_owner_only(
            &std::fs::Permissions::from_mode(0o004)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn owner_and_other_read_mode_is_not_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        assert!(!permissions_are_owner_only(
            &std::fs::Permissions::from_mode(0o404)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn owner_read_write_mode_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        assert!(permissions_are_owner_only(
            &std::fs::Permissions::from_mode(0o600)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn owner_full_access_mode_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        assert!(permissions_are_owner_only(
            &std::fs::Permissions::from_mode(0o700)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn symlink_targets_retain_under_limit_and_oversized_behavior() {
        use std::io::Write;
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let small_target = dir.path().join("small-target");
        let large_target = dir.path().join("large-target");
        let small_link = dir.path().join("small-link");
        let large_link = dir.path().join("large-link");
        std::fs::write(&small_target, b"12345").unwrap();
        let mut large = File::create(&large_target).unwrap();
        large.write_all(b"123456").unwrap();
        symlink(&small_target, &small_link).unwrap();
        symlink(&large_target, &large_link).unwrap();

        assert_eq!(read_file_capped(&small_link, 5).unwrap(), b"12345");
        assert!(matches!(
            read_file_capped(&large_link, 5),
            Err(BoundedReadError::TooLarge { limit: 5, .. })
        ));
    }
}
