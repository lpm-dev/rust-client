//! Files and directories made as root on the installing user's behalf.
//!
//! Each step runs through a privileged program, `sudo` in production. Root
//! never opens a path the installing user controls: bytes reach it on
//! standard input, from handles the user opened. And root writes only under
//! directories no one else can change, into a private temporary entry that a
//! rename moves into place.

use super::proxy_platform::{
    require_success, run_checked_inherited, run_checked_output, run_checked_status,
};
use lpm_common::LpmError;
use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// The `mv` flag that renames onto a target that is a link to a directory,
/// replacing the link, instead of moving into the directory it points to.
#[cfg(target_os = "linux")]
const MV_ONTO_TARGET: &str = "-T";
#[cfg(target_os = "macos")]
const MV_ONTO_TARGET: &str = "-h";

/// Why a user other than root, or `uid`, could change what `path` leads to,
/// if one could: through any directory the kernel passes resolving it, or,
/// while its last components don't exist yet, resolving the nearest
/// ancestor that does.
pub(super) fn changeable_by_others(path: &Path, uid: u32) -> Option<String> {
    let existing = path
        .ancestors()
        .find(|ancestor| std::fs::symlink_metadata(ancestor).is_ok())
        .unwrap_or_else(|| Path::new("/"));
    // On a volume that ignores ownership, as macOS mounts external drives by
    // default, every user owns every file, whatever owner and mode it shows.
    #[cfg(target_os = "macos")]
    let found =
        lpm_common::path_trust::first_changeable_directory_with(existing, uid, |directory| {
            Ok(
                lpm_common::macos_acl::ignores_ownership_at(directory)?.then_some(
                    "it is on a volume that ignores ownership, where every user owns every file",
                ),
            )
        });
    #[cfg(not(target_os = "macos"))]
    let found = lpm_common::path_trust::first_changeable_directory(existing, uid);
    match found {
        Ok(None) => None,
        Ok(Some(found)) => Some(format!(
            "users other than root can change {}: {}",
            found.directory.display(),
            found.reason
        )),
        Err(error) => Some(format!(
            "{} could not be inspected: {error}",
            existing.display()
        )),
    }
}

/// Create the missing directories of `directory` as root, with mode 0755
/// whatever the umask, owned by root, and on macOS without the ACL entries
/// they inherit from their parent.
pub(super) fn create_missing_directories(
    privileged: &Path,
    directory: &Path,
) -> Result<(), LpmError> {
    let mut missing: Vec<&Path> = directory
        .ancestors()
        .take_while(|ancestor| std::fs::symlink_metadata(ancestor).is_err())
        .collect();
    if missing.is_empty() {
        return Ok(());
    }
    missing.reverse();
    run_checked_inherited(
        Command::new(privileged)
            .args(["mkdir", "-m", "0755"])
            .args(&missing),
    )?;
    run_checked_inherited(
        Command::new(privileged)
            .args(["chown", "0:0"])
            .args(&missing),
    )?;
    #[cfg(target_os = "macos")]
    run_checked_inherited(
        Command::new(privileged)
            .args(["chmod", "-N"])
            .args(&missing),
    )?;
    Ok(())
}

/// Make a directory only root can enter inside `parent`, named after
/// `prefix`, for entries root assembles before moving them into place. On
/// macOS it sheds the ACL entries it inherits, so what root creates in it
/// inherits none.
pub(super) fn private_root_directory(
    privileged: &Path,
    parent: &Path,
    prefix: &OsStr,
) -> Result<PathBuf, LpmError> {
    let mut template = OsString::from(prefix);
    template.push(".XXXXXX");
    let created = run_checked_output(
        Command::new(privileged)
            .args(["mktemp", "-d"])
            .arg(parent.join(template)),
    )?;
    let directory = path_from_command_output(&created.stdout);
    if directory.parent() != Some(parent) {
        return Err(LpmError::Script(format!(
            "mktemp created {} outside {}",
            directory.display(),
            parent.display()
        )));
    }
    #[cfg(target_os = "macos")]
    if let Err(error) = run_checked_inherited(
        Command::new(privileged)
            .args(["chmod", "-N"])
            .arg(&directory),
    ) {
        let _ = run_checked_inherited(Command::new(privileged).args(["rm", "-rf"]).arg(&directory));
        return Err(error);
    }
    Ok(directory)
}

/// Replace `destination` with `contents`, owned by root with `mode`.
///
/// `destination`'s directory, and every one on the way to it, must be one
/// only root and `trusted_uid` can change; missing ones are created. The
/// bytes reach root through a pipe and land in a private directory beside
/// `destination`, and a rename moves them into place, so nothing ever reads
/// a half-written file. A link at `destination` is replaced, not followed.
pub(super) fn write_root_file(
    privileged: &Path,
    trusted_uid: u32,
    contents: &[u8],
    destination: &Path,
    mode: &str,
) -> Result<(), LpmError> {
    let (Some(parent), Some(name)) = (destination.parent(), destination.file_name()) else {
        return Err(LpmError::Script(format!(
            "{} is not a file path",
            destination.display()
        )));
    };
    let refuse = |reason: String| {
        LpmError::Script(format!("cannot write {}: {reason}", destination.display()))
    };
    if let Some(reason) = changeable_by_others(parent, trusted_uid) {
        return Err(refuse(reason));
    }
    create_missing_directories(privileged, parent)?;
    if let Some(reason) = changeable_by_others(parent, trusted_uid) {
        return Err(refuse(reason));
    }

    let mut prefix = OsString::from(".");
    prefix.push(name);
    let private = private_root_directory(privileged, parent, &prefix)?;
    let temporary = private.join(name);
    let written = stream_as_root(privileged, &mut &contents[..], &temporary, u64::MAX)
        .and_then(|_| {
            run_checked_inherited(
                Command::new(privileged)
                    .arg("chmod")
                    .arg(mode)
                    .arg(&temporary),
            )
        })
        .and_then(|()| rename_onto(privileged, &temporary, destination));
    let cleanup = run_checked_inherited(Command::new(privileged).args(["rm", "-rf"]).arg(&private));
    written?;
    cleanup
}

/// Rename `from` onto `to` as root, replacing a file or a link there. A
/// directory at `to` is refused, since BSD `mv` would move `from` into it.
pub(super) fn rename_onto(privileged: &Path, from: &Path, to: &Path) -> Result<(), LpmError> {
    if std::fs::symlink_metadata(to).is_ok_and(|metadata| metadata.is_dir()) {
        return Err(LpmError::Script(format!(
            "{} is a directory, not a file",
            to.display()
        )));
    }
    run_checked_inherited(
        Command::new(privileged)
            .args(["mv", "-f", MV_ONTO_TARGET])
            .arg(from)
            .arg(to),
    )
}

/// Write what `source` holds to `destination` as root, passing it through
/// `tee`'s standard input. Returns how many bytes that was, or None when
/// `source` held more than `limit`, of which no more than `limit` reached
/// `destination`. Counting the bytes as they pass, rather than trusting a
/// size read beforehand, holds even if `source` grows meanwhile.
pub(super) fn stream_as_root(
    privileged: &Path,
    source: &mut impl std::io::Read,
    destination: &Path,
    limit: u64,
) -> Result<Option<u64>, LpmError> {
    use std::io::Write as _;

    let mut command = Command::new(privileged);
    command
        .arg("tee")
        .arg(destination)
        .stdin(Stdio::piped())
        .stdout(Stdio::null());
    let mut child = command.spawn().map_err(LpmError::Io)?;
    let mut stdin = child.stdin.take().expect("tee's standard input is piped");
    let mut buffer = vec![0_u8; 128 * 1024];
    let mut copied = 0_u64;
    let streamed = loop {
        let read = match source.read(&mut buffer) {
            Ok(0) => break Ok(Some(copied)),
            Ok(read) => read,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => break Err(error),
        };
        copied += read as u64;
        if copied > limit {
            break Ok(None);
        }
        if let Err(error) = stdin.write_all(&buffer[..read]) {
            break Err(error);
        }
    };
    drop(stdin);
    let status = child.wait().map_err(LpmError::Io)?;
    require_success(&command, status)?;
    streamed.map_err(LpmError::Io)
}

/// Copy what `source` holds to `destination` as root through `tee`'s
/// standard input.
pub(super) fn tee_as_root(
    privileged: &Path,
    source: std::fs::File,
    destination: &Path,
) -> Result<(), LpmError> {
    run_checked_status(
        Command::new(privileged)
            .arg("tee")
            .arg(destination)
            .stdin(source)
            .stdout(Stdio::null()),
    )
}

/// Open `path` as the installing user for copying as root, so the copy can
/// hold only what that user can read, whatever `path` has become. Anything
/// but a regular file is refused, without waiting on a FIFO to open.
pub(super) fn open_for_copy(path: &Path) -> Result<std::fs::File, LpmError> {
    use std::os::unix::fs::OpenOptionsExt as _;

    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(path)
        .map_err(|error| LpmError::Script(format!("open {}: {error}", path.display())))?;
    if !file.metadata().map_err(LpmError::Io)?.is_file() {
        return Err(LpmError::Script(format!(
            "{} is not a regular file",
            path.display()
        )));
    }
    Ok(file)
}

/// The path a command such as `mktemp` printed, without its line ending.
pub(super) fn path_from_command_output(stdout: &[u8]) -> PathBuf {
    use std::os::unix::ffi::OsStrExt as _;

    let line = stdout.strip_suffix(b"\n").unwrap_or(stdout);
    PathBuf::from(OsStr::from_bytes(line))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::proxy::tests::fake_privileged_runner;
    use std::os::unix::fs::PermissionsExt;

    fn current_uid() -> u32 {
        lpm_common::current_uid()
    }

    fn mode_of(path: &Path) -> u32 {
        std::fs::metadata(path).unwrap().permissions().mode() & 0o7777
    }

    fn entries_of(directory: &Path) -> Vec<OsString> {
        let mut entries: Vec<_> = std::fs::read_dir(directory)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        entries.sort();
        entries
    }

    #[test]
    fn path_check_rejects_a_directory_anyone_can_write() {
        let dir = tempfile::tempdir().unwrap();
        let shared = dir.path().join("shared");
        std::fs::create_dir(&shared).unwrap();
        std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o757)).unwrap();

        let reason = changeable_by_others(&shared.join("forwarder"), current_uid())
            .expect("a world-writable directory is not trusted");
        assert!(reason.contains("can change"), "{reason}");

        let private = dir.path().join("private");
        std::fs::create_dir(&private).unwrap();
        std::fs::set_permissions(&private, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(
            changeable_by_others(&private.join("forwarder"), current_uid()),
            None
        );
    }

    #[test]
    fn root_controlled_check_rejects_the_installing_users_own_directories() {
        if current_uid() == 0 {
            return;
        }
        let dir = tempfile::tempdir().unwrap();

        let reason = changeable_by_others(&dir.path().join("forwarder"), 0)
            .expect("a user-owned temporary directory is not root-controlled");

        assert!(reason.contains("can change"), "{reason}");
    }

    #[cfg(target_os = "macos")]
    fn add_acl(path: &Path, entry: &str) {
        assert!(
            Command::new("chmod")
                .args(["+a", entry])
                .arg(path)
                .status()
                .unwrap()
                .success()
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn path_check_rejects_a_directory_whose_acl_lets_others_change_it() {
        let dir = tempfile::tempdir().unwrap();
        let shared = dir.path().join("shared");
        std::fs::create_dir(&shared).unwrap();
        add_acl(
            &shared,
            "everyone allow add_file,add_subdirectory,delete_child",
        );

        let reason = changeable_by_others(&shared.join("forwarder"), current_uid())
            .expect("an ACL that lets others add entries makes the directory untrusted");
        assert!(reason.contains("access control list"), "{reason}");

        let guarded = dir.path().join("guarded");
        std::fs::create_dir(&guarded).unwrap();
        add_acl(&guarded, "everyone deny delete");
        assert_eq!(
            changeable_by_others(&guarded.join("forwarder"), current_uid()),
            None,
            "an ACL that only denies grants nothing"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn path_check_rejects_a_volume_that_ignores_ownership() {
        let dir = tempfile::tempdir().unwrap();
        let mount_point = dir.path().join("volume");
        std::fs::create_dir(&mount_point).unwrap();
        let attached = lpm_common::test_disk_image::AttachedImage::new(
            &dir.path().join("volume.dmg"),
            &mount_point,
            &[
                "-size",
                "2m",
                "-fs",
                "HFS+",
                "-volname",
                "lpm-root-fs-owners-off",
            ],
            &["-owners", "off"],
        );
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(attached.path(), &link).unwrap();
        // A link that only passes through the volume on its way back.
        let trusted = dir.path().join("trusted");
        std::fs::create_dir(&trusted).unwrap();
        std::os::unix::fs::symlink(&trusted, attached.path().join("back")).unwrap();
        let round_trip = dir.path().join("round-trip");
        std::os::unix::fs::symlink(attached.path().join("back"), &round_trip).unwrap();

        for path in [
            attached.path().join("forwarder"),
            link.join("forwarder"),
            round_trip.join("forwarder"),
        ] {
            let reason = changeable_by_others(&path, current_uid())
                .expect("a volume that ignores ownership is not trusted");
            assert!(reason.contains("ignores ownership"), "{reason}");
        }
    }

    #[test]
    fn missing_directories_are_created_0755_whatever_the_umask() {
        let dir = tempfile::tempdir().unwrap();
        let privileged = fake_privileged_runner(dir.path(), "umask 000\n");
        let nested = dir.path().join("etc/lpm/forwarder");

        create_missing_directories(&privileged, &nested).unwrap();

        for directory in [
            dir.path().join("etc"),
            dir.path().join("etc/lpm"),
            nested.clone(),
        ] {
            assert_eq!(mode_of(&directory), 0o755, "{}", directory.display());
        }
        create_missing_directories(&privileged, &nested).unwrap();
    }

    #[test]
    fn write_root_file_replaces_the_destination_with_its_mode_and_leaves_nothing_else() {
        let dir = tempfile::tempdir().unwrap();
        let privileged = fake_privileged_runner(dir.path(), "umask 000\n");
        let destination = dir.path().join("etc/lpm/proxy-forwarder.json");

        write_root_file(&privileged, current_uid(), b"first", &destination, "0644").unwrap();
        write_root_file(&privileged, current_uid(), b"second", &destination, "0600").unwrap();

        assert_eq!(std::fs::read_to_string(&destination).unwrap(), "second");
        assert_eq!(mode_of(&destination), 0o600);
        assert_eq!(mode_of(destination.parent().unwrap()), 0o755);
        assert_eq!(
            entries_of(destination.parent().unwrap()),
            vec![OsString::from("proxy-forwarder.json")]
        );
    }

    #[test]
    fn write_root_file_replaces_a_link_at_the_destination_instead_of_writing_through_it() {
        let dir = tempfile::tempdir().unwrap();
        let privileged = fake_privileged_runner(dir.path(), "");
        let elsewhere = dir.path().join("elsewhere");
        std::fs::create_dir(&elsewhere).unwrap();
        let services = dir.path().join("services");
        std::fs::create_dir(&services).unwrap();
        let to_directory = services.join("forwarder.service");
        std::os::unix::fs::symlink(&elsewhere, &to_directory).unwrap();
        let unrelated = elsewhere.join("unrelated");
        std::fs::write(&unrelated, "unrelated").unwrap();
        let to_file = services.join("forwarder.json");
        std::os::unix::fs::symlink(&unrelated, &to_file).unwrap();

        write_root_file(&privileged, current_uid(), b"unit", &to_directory, "0644").unwrap();
        write_root_file(&privileged, current_uid(), b"config", &to_file, "0644").unwrap();

        for (path, contents) in [(&to_directory, "unit"), (&to_file, "config")] {
            assert!(std::fs::symlink_metadata(path).unwrap().is_file());
            assert_eq!(std::fs::read_to_string(path).unwrap(), contents);
        }
        assert_eq!(std::fs::read_to_string(&unrelated).unwrap(), "unrelated");
        assert_eq!(entries_of(&elsewhere), vec![OsString::from("unrelated")]);
    }

    #[test]
    fn write_root_file_refuses_a_directory_others_can_change() {
        let dir = tempfile::tempdir().unwrap();
        let privileged = fake_privileged_runner(dir.path(), "");
        let shared = dir.path().join("shared");
        std::fs::create_dir(&shared).unwrap();
        std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o757)).unwrap();
        let linked = dir.path().join("linked");
        std::os::unix::fs::symlink(&shared, &linked).unwrap();

        for destination in [
            shared.join("proxy-forwarder.json"),
            shared.join("missing/proxy-forwarder.json"),
            linked.join("proxy-forwarder.json"),
        ] {
            let error =
                write_root_file(&privileged, current_uid(), b"config", &destination, "0644")
                    .expect_err("a directory others can change is refused");
            assert!(error.to_string().contains("cannot write"), "{error}");
        }
        assert!(entries_of(&shared).is_empty());
    }

    #[test]
    fn write_root_file_refuses_a_directory_at_the_destination() {
        let dir = tempfile::tempdir().unwrap();
        let privileged = fake_privileged_runner(dir.path(), "");
        let destination = dir.path().join("etc/proxy-forwarder.json");
        std::fs::create_dir_all(&destination).unwrap();

        let error = write_root_file(&privileged, current_uid(), b"config", &destination, "0644")
            .expect_err("a directory is not replaced");

        assert!(error.to_string().contains("is a directory"), "{error}");
        assert!(entries_of(&destination).is_empty());
        assert_eq!(
            entries_of(destination.parent().unwrap()),
            vec![OsString::from("proxy-forwarder.json")]
        );
    }

    #[test]
    fn stream_as_root_writes_no_more_than_its_limit() {
        let dir = tempfile::tempdir().unwrap();
        let privileged = fake_privileged_runner(dir.path(), "");
        let destination = dir.path().join("copy");

        let copied =
            stream_as_root(&privileged, &mut &b"twelve bytes"[..], &destination, 12).unwrap();
        assert_eq!(copied, Some(12));
        assert_eq!(std::fs::read(&destination).unwrap(), b"twelve bytes");

        let over = vec![7_u8; 300 * 1024];
        let copied = stream_as_root(&privileged, &mut &over[..], &destination, 200 * 1024).unwrap();
        assert_eq!(copied, None);
        assert!(std::fs::metadata(&destination).unwrap().len() <= 200 * 1024);
    }

    #[test]
    fn write_root_file_that_cannot_move_into_place_keeps_the_earlier_file_and_cleans_up() {
        let dir = tempfile::tempdir().unwrap();
        let privileged =
            fake_privileged_runner(dir.path(), "if [ \"$1\" = mv ]; then exit 1; fi\n");
        let destination = dir.path().join("etc/proxy-forwarder.json");
        std::fs::create_dir(destination.parent().unwrap()).unwrap();
        std::fs::write(&destination, "earlier").unwrap();

        write_root_file(&privileged, current_uid(), b"later", &destination, "0644")
            .expect_err("the failed move must be reported");

        assert_eq!(std::fs::read_to_string(&destination).unwrap(), "earlier");
        assert_eq!(
            entries_of(destination.parent().unwrap()),
            vec![OsString::from("proxy-forwarder.json")]
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn write_root_file_leaves_no_acl_the_directory_would_pass_on() {
        let dir = tempfile::tempdir().unwrap();
        let privileged = fake_privileged_runner(dir.path(), "");
        let daemons = dir.path().join("LaunchDaemons");
        std::fs::create_dir(&daemons).unwrap();
        add_acl(
            &daemons,
            "everyone allow read,readattr,readextattr,readsecurity,file_inherit,directory_inherit,only_inherit",
        );
        let destination = daemons.join("dev.lpm.proxy.forwarder.plist");

        write_root_file(&privileged, current_uid(), b"plist", &destination, "0644").unwrap();

        assert!(!lpm_common::macos_acl::has_extended_acl_at(&destination).unwrap());

        add_acl(&daemons, "everyone allow write,file_inherit,only_inherit");
        write_root_file(&privileged, current_uid(), b"plist", &destination, "0644")
            .expect_err("a directory whose ACL lets others add files is refused");
    }

    #[test]
    fn a_copy_holds_what_was_opened_even_if_the_path_is_replaced() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("lpm");
        std::fs::write(&source, "the build that is running").unwrap();
        let replace_source = format!(
            "if [ \"$1\" = tee ]; then printf replaced > '{0}.new' && mv '{0}.new' '{0}'; fi\n",
            source.display()
        );
        let privileged = fake_privileged_runner(dir.path(), &replace_source);
        let copy = dir.path().join("copy");

        tee_as_root(&privileged, open_for_copy(&source).unwrap(), &copy).unwrap();

        assert_eq!(std::fs::read_to_string(&source).unwrap(), "replaced");
        assert_eq!(
            std::fs::read_to_string(&copy).unwrap(),
            "the build that is running"
        );
    }

    #[test]
    fn open_for_copy_refuses_anything_but_a_regular_file_without_blocking() {
        let dir = tempfile::tempdir().unwrap();
        let fifo = dir.path().join("fifo");
        let fifo_path = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: `fifo_path` is a NUL-terminated path that outlives the call.
        assert_eq!(unsafe { libc::mkfifo(fifo_path.as_ptr(), 0o600) }, 0);

        for path in [dir.path().to_path_buf(), fifo] {
            let error = open_for_copy(&path).expect_err("only regular files are copied");
            assert!(error.to_string().contains("not a regular file"), "{error}");
        }
    }
}
