//! File names as the filesystems that fold them compare them.

use std::borrow::Cow;

/// Whether a filesystem that folds names can leave `character` out when it
/// compares them: Unicode's default-ignorable code points, which Linux's
/// casefolding drops, among them the zero-width and directional marks HFS+
/// drops, as git's `core.protectHFS` reads them. A name holding one can open
/// the file named without it.
pub fn is_ignored_in_names(character: char) -> bool {
    matches!(
        character,
        '\u{00AD}'
            | '\u{034F}'
            | '\u{061C}'
            | '\u{115F}'..='\u{1160}'
            | '\u{17B4}'..='\u{17B5}'
            | '\u{180B}'..='\u{180F}'
            | '\u{200B}'..='\u{200F}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2060}'..='\u{206F}'
            | '\u{3164}'
            | '\u{FE00}'..='\u{FE0F}'
            | '\u{FEFF}'
            | '\u{FFA0}'
            | '\u{FFF0}'..='\u{FFF8}'
            | '\u{1BCA0}'..='\u{1BCA3}'
            | '\u{1D173}'..='\u{1D17A}'
            | '\u{E0000}'..='\u{E0FFF}'
    )
}

/// Whether the directory holding `path` leaves the characters
/// [`is_ignored_in_names`] names out of the names it compares: one on an
/// HFS+ volume, or a Linux casefold directory (`chattr +F`), which the
/// directories made in it inherit.
pub fn names_ignore_marks(path: &std::path::Path) -> bool {
    #[cfg(target_os = "macos")]
    {
        path.ancestors()
            .find_map(volume_type)
            .is_some_and(|volume| volume == "hfs")
    }
    #[cfg(target_os = "linux")]
    {
        path.ancestors().find_map(casefolds).unwrap_or(false)
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = path;
        false
    }
}

/// The type of the volume holding `path`, as `statfs` names it.
#[cfg(target_os = "macos")]
fn volume_type(path: &std::path::Path) -> Option<String> {
    use std::os::unix::ffi::OsStrExt as _;
    let path = std::ffi::CString::new(path.as_os_str().as_bytes()).ok()?;
    // SAFETY: an all-zero `statfs` is a valid value for `statfs` to fill.
    let mut volume: libc::statfs = unsafe { std::mem::zeroed() };
    // SAFETY: `path` is NUL-terminated and `volume` is writable storage of
    // the structure `statfs` expects.
    if unsafe { libc::statfs(path.as_ptr(), &mut volume) } != 0 {
        return None;
    }
    // SAFETY: `statfs` NUL-terminates `f_fstypename` within its length.
    let name = unsafe { std::ffi::CStr::from_ptr(volume.f_fstypename.as_ptr()) };
    Some(name.to_string_lossy().into_owned())
}

/// Whether the directory at `path` folds the names in it. `None` when
/// `path` isn't a directory that opens; a filesystem without inode flags
/// folds none.
#[cfg(target_os = "linux")]
fn casefolds(path: &std::path::Path) -> Option<bool> {
    use std::os::fd::AsRawFd as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    const FS_CASEFOLD_FL: libc::c_int = 0x4000_0000;
    let directory = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NONBLOCK)
        .open(path)
        .ok()?;
    let mut flags: libc::c_int = 0;
    // SAFETY: `directory` is an open descriptor and `flags` is the writable
    // `int` `FS_IOC_GETFLAGS` fills.
    let read = unsafe { libc::ioctl(directory.as_raw_fd(), libc::FS_IOC_GETFLAGS, &mut flags) };
    Some(read == 0 && flags & FS_CASEFOLD_FL != 0)
}

/// `name` as a filesystem that sets case aside compares it, `ſ` for `s` and
/// the Kelvin sign for `k` included, and without the characters
/// [`is_ignored_in_names`] names. An ASCII name comes back as it is, to
/// compare with `eq_ignore_ascii_case`.
pub fn fold_name(name: &str) -> Cow<'_, str> {
    if name.is_ascii() {
        return Cow::Borrowed(name);
    }
    // Lowercasing first takes `ẞ` to `ß`, which uppercases to `SS`.
    let kept: String = name
        .chars()
        .filter(|character| !is_ignored_in_names(*character))
        .collect();
    Cow::Owned(kept.to_lowercase().to_uppercase().to_lowercase())
}

/// Whether a path component names a git directory as git reads one on every
/// platform (`core.protectNTFS`, `core.protectHFS`): each part of it a `\`
/// starts, as Windows starts a directory there, that is `.git`, or `git~1`,
/// its NTFS short name, in any case and without the characters
/// [`is_ignored_in_names`] names, followed by nothing but the dots and
/// spaces Win32 drops, up to its end or a `:`, where NTFS starts a stream
/// name.
pub fn is_git_dir_name(name: &str) -> bool {
    name.split('\\').any(|part| {
        let part = part.split(':').next().unwrap_or(part);
        let folded = fold_name(part);
        [".git", "git~1"].into_iter().any(|git| {
            folded
                .get(..git.len())
                .is_some_and(|start| start.eq_ignore_ascii_case(git))
                && folded[git.len()..]
                    .bytes()
                    .all(|byte| byte == b'.' || byte == b' ')
        })
    })
}

/// `name` in Unicode's composed form (NFC), as git on macOS reads the names
/// a directory lists (`core.precomposeunicode`), and HFS+, and APFS for a
/// name made decomposed, list them decomposed.
pub fn composed(name: &str) -> Cow<'_, str> {
    use unicode_normalization::UnicodeNormalization as _;
    if name.is_ascii() || unicode_normalization::is_nfc(name) {
        return Cow::Borrowed(name);
    }
    Cow::Owned(name.nfc().collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_name_folds_without_case_and_without_the_characters_a_filesystem_ignores() {
        for (name, as_read) in [
            ("inspector.d\u{200C}b", "inspector.db"),
            ("\u{FEFF}.LPM", ".lpm"),
            ("lpm-\u{17F}ources.json", "lpm-sources.json"),
            ("\u{212A}ey.pem", "key.pem"),
            // Linux casefolding drops every default-ignorable code point.
            (".l\u{200B}pm", ".lpm"),
            ("\u{AD}.lpm\u{FE0F}", ".lpm"),
            (".lpm\u{E0001}", ".lpm"),
        ] {
            assert!(fold_name(name).eq_ignore_ascii_case(as_read), "{name}");
        }
        assert_eq!(fold_name(".lpm"), ".lpm");
    }

    #[test]
    fn a_git_directory_is_named_as_git_reads_one() {
        for name in [
            ".git",
            ".GIT",
            ".git.",
            ".git ",
            ".git. .",
            "git~1",
            "GIT~1.",
            ".git:x",
            ".git::$INDEX_ALLOCATION",
            ".git\\hooks",
            // Git reads what follows each `\` as a name of its own.
            "x\\.git",
            ".github\\.git ",
            "a\\b\\GIT~1.",
            ".g\u{200C}it",
            "\u{FEFF}.Git.",
        ] {
            assert!(is_git_dir_name(name), "{name:?}");
        }
        for name in [
            ".github",
            ".gitignore",
            ".gitx",
            ".git.x",
            "git",
            ".git~1",
            "git~2",
            "x.git",
            "",
            "a\\b",
        ] {
            assert!(!is_git_dir_name(name), "{name:?}");
        }
    }

    #[test]
    fn a_name_is_composed_as_git_on_macos_reads_it() {
        assert_eq!(composed("cafe\u{301}"), "caf\u{E9}");
        assert!(matches!(composed("caf\u{E9}"), Cow::Borrowed(_)));
        assert!(matches!(composed("dist"), Cow::Borrowed(_)));
    }

    #[test]
    fn an_ordinary_directory_compares_names_with_every_character() {
        let directory = tempfile::tempdir().unwrap();
        if cfg!(target_os = "macos") && names_ignore_marks(directory.path()) {
            return;
        }
        assert!(!names_ignore_marks(&directory.path().join("missing/below")));
    }
}
