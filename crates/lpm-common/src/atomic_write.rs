use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Rewrite `path` through a same-directory temporary file and atomic replace.
///
/// Readers of `path` observe either the previous complete file or the new
/// complete file; they never observe the truncate-then-write window created by
/// `std::fs::write` on an existing path.
pub fn write_file_atomic(path: &Path, contents: impl AsRef<[u8]>) -> io::Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = path.file_name().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("path has no file name: {}", path.display()),
        )
    })?;

    let mut last_error = None;
    for _ in 0..16 {
        let tmp_path = temp_path(parent, file_name);
        let result = (|| {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&tmp_path)?;
            file.write_all(contents.as_ref())?;
            drop(file);
            replace_file(&tmp_path, path)
        })();

        match result {
            Ok(()) => return Ok(()),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                last_error = Some(e);
            }
            Err(e) => {
                let _ = fs::remove_file(&tmp_path);
                return Err(e);
            }
        }
    }

    Err(last_error.unwrap_or_else(|| {
        io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!("could not allocate temp path for {}", path.display()),
        )
    }))
}

fn temp_path(parent: &Path, file_name: &std::ffi::OsStr) -> PathBuf {
    let id = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut tmp_name = OsString::from(".");
    tmp_name.push(file_name);
    tmp_name.push(format!(".tmp.{}.{}", std::process::id(), id));
    parent.join(tmp_name)
}

#[cfg(not(windows))]
fn replace_file(from: &Path, to: &Path) -> io::Result<()> {
    fs::rename(from, to)
}

#[cfg(windows)]
fn replace_file(from: &Path, to: &Path) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{
        MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
    };

    fn wide(path: &Path) -> Vec<u16> {
        path.as_os_str().encode_wide().chain(Some(0)).collect()
    }

    let from = wide(from);
    let to = wide(to);
    let flags = MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH;
    // SAFETY: both pointers reference nul-terminated UTF-16 buffers that live
    // for the duration of the call, and the flags request an atomic replace.
    let ok = unsafe { MoveFileExW(from.as_ptr(), to.as_ptr(), flags) };
    if ok == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::write_file_atomic;
    use std::fs;

    #[test]
    fn write_file_atomic_replaces_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("package.json");
        fs::write(&path, br#"{"name":"before"}"#).unwrap();

        write_file_atomic(&path, br#"{"name":"after"}"#).unwrap();

        assert_eq!(fs::read(&path).unwrap(), br#"{"name":"after"}"#);
        let tmp_files = fs::read_dir(dir.path())
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().contains(".tmp."))
            .count();
        assert_eq!(tmp_files, 0);
    }

    #[test]
    fn write_file_atomic_cleans_temp_file_when_replace_fails() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("package.json");
        fs::create_dir(&path).unwrap();

        assert!(write_file_atomic(&path, b"not a directory").is_err());
        let tmp_files = fs::read_dir(dir.path())
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().contains(".tmp."))
            .count();
        assert_eq!(tmp_files, 0);
    }
}
