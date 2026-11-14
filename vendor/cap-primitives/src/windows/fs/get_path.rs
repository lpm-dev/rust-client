use std::ffi::OsString;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};
use std::{fs, io};

/// Calculates system path of `file`.
///
/// This function will automatically strip the extended prefix from the
/// resultant path to allow for joining this resultant path with relative
/// components.
pub(crate) fn get_path(file: &fs::File) -> io::Result<PathBuf> {
    // get system path to the handle
    let path = winx::file::get_file_path(file)?;

    Ok(without_verbatim_prefix(&path))
}

/// `path` without the extended prefix `GetFinalPathNameByHandleW` gives it:
/// `\\?\C:\dir` becomes `C:\dir`, and `\\?\UNC\server\share\dir` becomes
/// `\\server\share\dir`. Any other path stays as it is, since without its
/// prefix it would be relative, and joined to the current directory.
fn without_verbatim_prefix(path: &Path) -> PathBuf {
    const VERBATIM: [u16; 4] = [b'\\' as u16, b'\\' as u16, b'?' as u16, b'\\' as u16];

    let wide: Vec<u16> = path.as_os_str().encode_wide().collect();
    let Some(rest) = wide.strip_prefix(&VERBATIM) else {
        return path.to_path_buf();
    };
    if let Some(share) = strip_unc(rest) {
        let mut unc = Vec::with_capacity(share.len() + 2);
        unc.extend_from_slice(&[b'\\' as u16, b'\\' as u16]);
        unc.extend_from_slice(share);
        return PathBuf::from(OsString::from_wide(&unc));
    }
    if is_drive(rest) {
        return PathBuf::from(OsString::from_wide(rest));
    }
    path.to_path_buf()
}

/// What follows `UNC\` in `rest`, matched without regard to case.
fn strip_unc(rest: &[u16]) -> Option<&[u16]> {
    match rest {
        [u, n, c, separator, share @ ..]
            if ascii_eq_ignore_case(*u, b'U')
                && ascii_eq_ignore_case(*n, b'N')
                && ascii_eq_ignore_case(*c, b'C')
                && *separator == b'\\' as u16 =>
        {
            Some(share)
        }
        _ => None,
    }
}

/// Whether `rest` starts with a drive, as in `C:` or `C:\dir`.
fn is_drive(rest: &[u16]) -> bool {
    match rest {
        [letter, colon, after @ ..] => {
            u8::try_from(*letter).is_ok_and(|letter| letter.is_ascii_alphabetic())
                && *colon == b':' as u16
                && after
                    .first()
                    .is_none_or(|separator| *separator == b'\\' as u16)
        }
        _ => false,
    }
}

fn ascii_eq_ignore_case(unit: u16, letter: u8) -> bool {
    u8::try_from(unit).is_ok_and(|unit| unit.eq_ignore_ascii_case(&letter))
}

/// Convenience function for calling `get_path` and concatenating the result
/// with `path`.
pub(super) fn concatenate(file: &fs::File, path: &Path) -> io::Result<PathBuf> {
    let file_path = get_path(file)?;
    Ok(file_path.join(path))
}

#[cfg(test)]
mod tests {
    use super::without_verbatim_prefix;
    use std::path::{Path, PathBuf};

    #[test]
    fn a_drive_path_loses_its_extended_prefix() {
        assert_eq!(
            without_verbatim_prefix(Path::new(r"\\?\C:\Users\dev\project")),
            PathBuf::from(r"C:\Users\dev\project")
        );
        assert_eq!(
            without_verbatim_prefix(Path::new(r"\\?\C:\")),
            PathBuf::from(r"C:\")
        );
    }

    #[test]
    fn a_network_path_keeps_its_server_and_share() {
        let path = without_verbatim_prefix(Path::new(r"\\?\UNC\server\share\project"));

        assert_eq!(path, PathBuf::from(r"\\server\share\project"));
        assert!(path.is_absolute());
        assert_eq!(
            path.join(".lpm"),
            PathBuf::from(r"\\server\share\project\.lpm")
        );
        assert_eq!(
            without_verbatim_prefix(Path::new(r"\\?\unc\server\share")),
            PathBuf::from(r"\\server\share")
        );
    }

    #[test]
    fn a_path_with_another_prefix_stays_extended_and_absolute() {
        for path in [
            r"\\?\Volume{01234567-89ab-cdef-0123-456789abcdef}\project",
            r"\\?\GLOBALROOT\Device\HarddiskVolume3\project",
            r"\\?\UNCserver\share",
            r"\\?\CC:\project",
        ] {
            let kept = without_verbatim_prefix(Path::new(path));

            assert_eq!(kept, PathBuf::from(path));
            assert!(kept.is_absolute());
        }
    }

    #[test]
    fn a_path_without_an_extended_prefix_is_unchanged() {
        for path in [r"C:\project", r"\\server\share\project"] {
            assert_eq!(
                without_verbatim_prefix(Path::new(path)),
                PathBuf::from(path)
            );
        }
    }
}
