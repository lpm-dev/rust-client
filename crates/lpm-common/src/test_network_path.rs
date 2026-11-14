//! Network paths that Windows tests reach a local directory through, the
//! way a project in a shared folder or on a mapped network drive is reached.

use std::path::{Component, Path, PathBuf, Prefix};

/// `local`, an absolute path on a drive with a letter, through that drive's
/// administrative share on this machine, as in `\\localhost\C$\Users\…`,
/// which Windows handles as it handles any network folder.
///
/// `None` when the share can't be reached, as without administrator rights,
/// after saying so on stderr. CI runs Windows tests as an administrator, so
/// there it panics instead, and a test that needs the share never passes
/// without running.
///
/// # Panics
///
/// When `local` isn't on a drive with a letter, or holds `..`; and under CI
/// when the share can't be reached.
#[must_use]
pub fn through_network(local: &Path) -> Option<PathBuf> {
    let mut components = local.components();
    let letter = match components.next() {
        Some(Component::Prefix(prefix)) => match prefix.kind() {
            Prefix::Disk(letter) | Prefix::VerbatimDisk(letter) => char::from(letter),
            _ => panic!("{} is not on a drive with a letter", local.display()),
        },
        _ => panic!("{} is not on a drive with a letter", local.display()),
    };
    let mut network = PathBuf::from(format!(r"\\localhost\{letter}$\"));
    if let Err(error) = std::fs::metadata(&network) {
        assert!(
            std::env::var_os("CI").is_none(),
            "CI runs Windows tests as an administrator, but {} can't be reached: {error}",
            network.display()
        );
        eprintln!(
            "skipped: {} can't be reached ({error}); this test needs administrator rights",
            network.display()
        );
        return None;
    }
    for component in components {
        match component {
            Component::RootDir | Component::CurDir => {}
            Component::Normal(name) => network.push(name),
            Component::ParentDir | Component::Prefix(_) => {
                panic!("{} is not a plain absolute path", local.display())
            }
        }
    }
    Some(network)
}
