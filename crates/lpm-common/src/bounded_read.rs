use std::fs::{File, Metadata};
#[cfg(debug_assertions)]
use std::io::Write as _;
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

/// Maximum aggregate TLS material retained by one registry client bundle.
pub const TLS_MATERIAL_AGGREGATE_CAP_BYTES: u64 = 16 * 1024 * 1024;

/// Read at most `limit + 1` bytes from an arbitrary stream.
///
/// This is intended for pipes and other readers that do not have meaningful
/// descriptor metadata. An oversized stream returns [`io::ErrorKind::InvalidData`].
pub fn read_stream_capped<R: Read>(reader: R, limit: u64) -> io::Result<Vec<u8>> {
    let read_limit = limit.checked_add(1).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "stream size limit is too large",
        )
    })?;
    let initial_capacity = usize::try_from(read_limit.min(INITIAL_BUFFER_CAPACITY_BYTES))
        .map_err(|_| io::Error::other("bounded stream capacity is unsupported"))?;
    let mut bytes = Vec::with_capacity(initial_capacity);
    reader.take(read_limit).read_to_end(&mut bytes)?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > limit {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("stream exceeds {limit}-byte limit"),
        ));
    }
    Ok(bytes)
}

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

/// Read a bounded regular file without blocking on Unix special files.
/// Symlinks are allowed, but the opened target must be a regular file.
pub fn read_regular_file_capped_with_metadata(
    path: &Path,
    limit: u64,
) -> Result<(Vec<u8>, Metadata), BoundedReadError> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;

        options.custom_flags(libc::O_CLOEXEC | libc::O_NONBLOCK);
    }
    let mut file = options.open(path).map_err(|source| {
        if source.kind() == io::ErrorKind::NotFound {
            BoundedReadError::NotFound {
                path: path.to_path_buf(),
            }
        } else {
            BoundedReadError::Io {
                path: path.to_path_buf(),
                source,
            }
        }
    })?;
    let metadata = file.metadata().map_err(|source| BoundedReadError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    if !metadata.is_file() {
        return Err(BoundedReadError::Io {
            path: path.to_path_buf(),
            source: io::Error::new(io::ErrorKind::InvalidData, "not a regular file"),
        });
    }
    let bytes = read_opened_file_capped(&mut file, path, limit, metadata.len())?;
    Ok((bytes, metadata))
}

/// Read bounded UTF-8 text from a regular file without blocking on Unix special files.
pub fn read_text_regular_file_capped_with_metadata(
    path: &Path,
    limit: u64,
) -> Result<(String, Metadata), BoundedReadError> {
    let (bytes, metadata) = read_regular_file_capped_with_metadata(path, limit)?;
    String::from_utf8(bytes)
        .map_err(|source| BoundedReadError::InvalidUtf8 {
            path: path.to_path_buf(),
            source: source.utf8_error(),
        })
        .map(|content| (content, metadata))
}

fn read_file_capped_with_metadata(
    path: &Path,
    limit: u64,
) -> Result<(Vec<u8>, Metadata), BoundedReadError> {
    let file = match File::open(path) {
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

    read_file_capped_from_open_file(file, path, limit)
}

/// Read at most `limit + 1` bytes from an already-open file.
///
/// Use this when path-opening policy is security-sensitive. The returned
/// metadata and bytes always come from the supplied descriptor.
pub fn read_file_capped_from_open_file(
    mut file: File,
    path: &Path,
    limit: u64,
) -> Result<(Vec<u8>, Metadata), BoundedReadError> {
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

    let bytes = read_opened_file_capped(&mut file, path, limit, metadata.len())?;
    Ok((bytes, metadata))
}

/// Read bounded UTF-8 text from an already-open file.
pub fn read_text_file_capped_from_open_file(
    file: File,
    path: &Path,
    limit: u64,
) -> Result<(String, Metadata), BoundedReadError> {
    let (bytes, metadata) = read_file_capped_from_open_file(file, path, limit)?;
    String::from_utf8(bytes)
        .map_err(|source| BoundedReadError::InvalidUtf8 {
            path: path.to_path_buf(),
            source: source.utf8_error(),
        })
        .map(|content| (content, metadata))
}

/// Read bounded UTF-8 text when the caller already queried this descriptor's size.
pub fn read_text_file_capped_from_open_file_with_known_size(
    mut file: File,
    path: &Path,
    limit: u64,
    known_size: u64,
) -> Result<String, BoundedReadError> {
    if known_size > limit {
        return Err(BoundedReadError::TooLarge {
            path: path.to_path_buf(),
            limit,
        });
    }
    let bytes = read_opened_file_capped(&mut file, path, limit, known_size)?;
    String::from_utf8(bytes).map_err(|source| BoundedReadError::InvalidUtf8 {
        path: path.to_path_buf(),
        source: source.utf8_error(),
    })
}

/// Read a bounded local file and validate it as UTF-8 text.
pub fn read_text_file_capped(path: &Path, limit: u64) -> Result<String, BoundedReadError> {
    read_text_file_capped_with_metadata(path, limit).map(|(content, _)| content)
}

/// Read bounded UTF-8 text without following a linked leaf or blocking on a special file.
pub fn read_text_file_capped_nofollow(path: &Path, limit: u64) -> Result<String, BoundedReadError> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;

        options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt as _;
        use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;

        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let file = options.open(path).map_err(|source| {
        if source.kind() == io::ErrorKind::NotFound {
            BoundedReadError::NotFound {
                path: path.to_path_buf(),
            }
        } else {
            BoundedReadError::Io {
                path: path.to_path_buf(),
                source,
            }
        }
    })?;
    let metadata = file.metadata().map_err(|source| BoundedReadError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    if !metadata.is_file() || metadata_is_link_or_reparse(&metadata) {
        return Err(BoundedReadError::Io {
            path: path.to_path_buf(),
            source: io::Error::new(io::ErrorKind::InvalidData, "not a safe regular file"),
        });
    }
    read_text_file_capped_from_open_file_with_known_size(file, path, limit, metadata.len())
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
    estimated_len: u64,
) -> Result<Vec<u8>, BoundedReadError> {
    #[cfg(debug_assertions)]
    record_manifest_read_for_test(path);
    let read_limit = limit.checked_add(1).ok_or_else(|| BoundedReadError::Io {
        path: path.to_path_buf(),
        source: io::Error::new(io::ErrorKind::InvalidInput, "file size limit is too large"),
    })?;
    let initial_capacity = usize::try_from(
        estimated_len
            .saturating_add(1)
            .min(read_limit)
            .min(INITIAL_BUFFER_CAPACITY_BYTES),
    )
    .map_err(|_| BoundedReadError::Io {
        path: path.to_path_buf(),
        source: io::Error::new(
            io::ErrorKind::InvalidInput,
            "bounded read buffer capacity is unsupported on this platform",
        ),
    })?;
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

#[cfg(debug_assertions)]
fn record_manifest_read_for_test(path: &Path) {
    if path.file_name() != Some(std::ffi::OsStr::new("lpm.json")) {
        return;
    }
    let Some(log_path) = std::env::var_os("LPM_TEST_MANIFEST_READ_LOG") else {
        return;
    };
    let Ok(mut log) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path)
    else {
        return;
    };
    let _ = writeln!(log, "{}", path.display());
}

#[cfg(not(windows))]
fn metadata_is_link_or_reparse(metadata: &Metadata) -> bool {
    metadata.file_type().is_symlink()
}

#[cfg(windows)]
fn metadata_is_link_or_reparse(metadata: &Metadata) -> bool {
    use std::os::windows::fs::MetadataExt as _;
    use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
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
    fn small_file_read_does_not_retain_the_generic_read_buffer_capacity() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("small");
        std::fs::write(&path, b"small").unwrap();

        let bytes = read_file_capped(&path, 1024 * 1024).unwrap();

        assert!(
            bytes.capacity() <= 64,
            "small descriptor-backed read retained {} bytes",
            bytes.capacity()
        );
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
            read_opened_file_capped(&mut reader, path, 5, 0),
            Err(BoundedReadError::TooLarge { limit: 5, .. })
        ));
        assert_eq!(reader.position(), 6);
    }

    #[test]
    fn stream_exactly_at_limit_is_read() {
        let reader = Cursor::new(b"12345".as_slice());

        assert_eq!(read_stream_capped(reader, 5).unwrap(), b"12345");
    }

    #[test]
    fn stream_one_byte_over_limit_is_rejected_after_limit_plus_one_bytes() {
        let mut reader = Cursor::new(b"123456789".as_slice());

        let error = read_stream_capped(&mut reader, 5).unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
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
