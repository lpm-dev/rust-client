use std::collections::HashSet;
use std::fs::File;
use std::io::{self, Write as _};
use std::path::Path;

use cap_fs_ext::{FollowSymlinks, OpenOptionsFollowExt as _, OpenOptionsSyncExt as _};
use cap_std::fs::{Dir, OpenOptions};

pub(super) fn add_paths<'a>(
    project_dir: &Path,
    file_paths: impl IntoIterator<Item = &'a Path>,
) -> io::Result<()> {
    let mut file_paths = file_paths.into_iter().peekable();
    if file_paths.peek().is_none() {
        return Ok(());
    }
    let directory = Dir::open_ambient_dir(project_dir, cap_std::ambient_authority())?;
    let mut options = OpenOptions::new();
    options
        .read(true)
        .append(true)
        .create(true)
        .follow(FollowSymlinks::No)
        .nonblock(true);
    let mut attempts = 0;
    let mut file = loop {
        match directory.open_with(".gitignore", &options) {
            Ok(file) => break file.into_std(),
            Err(error) if error.kind() == io::ErrorKind::NotFound && attempts < 2 => {
                attempts += 1;
            }
            Err(error) => return Err(error),
        }
    };
    validate_regular_file(&file)?;
    let _lock = lpm_common::acquire_single_file_exclusive_lock_from_file(file.try_clone()?)
        .map_err(io::Error::other)?;
    validate_current_file(&directory, &file)?;
    let (existing, _) = lpm_common::read_text_file_capped_from_open_file(
        file.try_clone()?,
        &project_dir.join(".gitignore"),
        lpm_common::CONFIG_FILE_SIZE_CAP_BYTES,
    )
    .map_err(io::Error::other)?;
    let existing_entries: HashSet<_> = existing.lines().map(str::trim).collect();
    let mut pending = HashSet::new();
    let mut addition = String::new();
    for path in file_paths {
        let relative = path
            .strip_prefix(project_dir)
            .unwrap_or(path)
            .display()
            .to_string();
        if existing_entries.contains(relative.as_str())
            || existing_entries.contains(format!("/{relative}").as_str())
            || !pending.insert(relative.clone())
        {
            continue;
        }
        if addition.is_empty() && !existing.is_empty() && !existing.ends_with('\n') {
            addition.push('\n');
        }
        addition.push_str(&relative);
        addition.push('\n');
    }
    if !addition.is_empty() {
        validate_current_file(&directory, &file)?;
        file.write_all(addition.as_bytes())?;
        validate_current_file(&directory, &file)?;
    }
    Ok(())
}

fn validate_regular_file(file: &File) -> io::Result<()> {
    let metadata = file.metadata()?;
    if !metadata.is_file() || lpm_common::is_symlink_or_junction(&metadata) {
        return Err(io::Error::other(".gitignore is not a regular file"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        if metadata.nlink() != 1 {
            return Err(io::Error::other(".gitignore has multiple hard links"));
        }
    }
    #[cfg(windows)]
    if windows_identity(file)?.nNumberOfLinks != 1 {
        return Err(io::Error::other(".gitignore has multiple hard links"));
    }
    Ok(())
}

fn validate_current_file(directory: &Dir, file: &File) -> io::Result<()> {
    let mut options = OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No).nonblock(true);
    let current = directory.open_with(".gitignore", &options)?.into_std();
    validate_regular_file(file)?;
    validate_regular_file(&current)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        let retained = file.metadata()?;
        let current = current.metadata()?;
        if retained.dev() != current.dev() || retained.ino() != current.ino() {
            return Err(io::Error::other(".gitignore changed during the update"));
        }
    }
    #[cfg(windows)]
    {
        let retained = windows_identity(file)?;
        let current = windows_identity(&current)?;
        if retained.dwVolumeSerialNumber != current.dwVolumeSerialNumber
            || retained.nFileIndexHigh != current.nFileIndexHigh
            || retained.nFileIndexLow != current.nFileIndexLow
        {
            return Err(io::Error::other(".gitignore changed during the update"));
        }
    }
    Ok(())
}

#[cfg(windows)]
fn windows_identity(
    file: &File,
) -> io::Result<windows_sys::Win32::Storage::FileSystem::BY_HANDLE_FILE_INFORMATION> {
    use std::os::windows::io::AsRawHandle as _;
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle,
    };
    let mut information = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: the file owns a live handle and the output has the Win32 structure's exact layout.
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut information) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(information)
}

#[cfg(test)]
mod tests {
    #[test]
    fn concurrent_ignore_updates_preserve_all_entries_once() {
        let project = tempfile::tempdir().unwrap();
        std::fs::write(project.path().join(".gitignore"), "existing").unwrap();
        let start = std::sync::Barrier::new(8);
        std::thread::scope(|scope| {
            for index in 0..8 {
                let start = &start;
                let root = project.path();
                scope.spawn(move || {
                    start.wait();
                    for _ in 0..2 {
                        super::add_paths(
                            root,
                            [&root.join(format!("secrets-{index}.env")) as &std::path::Path],
                        )
                        .unwrap();
                    }
                });
            }
        });
        let content = std::fs::read_to_string(project.path().join(".gitignore")).unwrap();
        let entries: Vec<_> = content.lines().collect();
        assert_eq!(entries.len(), 9, "{content}");
        assert_eq!(entries[0], "existing");
        for index in 0..8 {
            assert!(
                entries.contains(&format!("secrets-{index}.env").as_str()),
                "{content}"
            );
        }
    }
}
