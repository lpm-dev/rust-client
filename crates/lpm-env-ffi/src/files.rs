//! The LPM home and a project's files, kept as the CLI keeps them, for an
//! app that shares them with the CLI: where the home's credential-store
//! entries live, keeping the home and a project's `.lpm` out of git, which
//! directory is the project, and keeping a file of secrets out of git.

use crate::{ABI_VERSION, LPMEnvResult, failure, result};
use serde::Serialize;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::{Path, PathBuf};

/// The longest path these functions take.
const PATH_LIMIT: usize = 32 * 1024;

/// An absolute path from a caller's UTF-8 byte range.
///
/// # Safety
/// A non-null pointer must reference readable bytes for its length during the call.
unsafe fn absolute_path(bytes: *const u8, length: usize) -> Option<PathBuf> {
    if bytes.is_null() || length == 0 || length > PATH_LIMIT {
        return None;
    }
    // SAFETY: The caller supplies a live readable range; its length was bounded above.
    let path = std::str::from_utf8(unsafe { std::slice::from_raw_parts(bytes, length) }).ok()?;
    let path = Path::new(path);
    (!path.as_os_str().as_encoded_bytes().contains(&0) && path.is_absolute())
        .then(|| path.to_path_buf())
}

fn json(output: &impl Serialize) -> LPMEnvResult {
    match serde_json::to_vec(output) {
        Ok(bytes) => result(0, bytes, None),
        Err(_) => failure(3, "env.engine_internal"),
    }
}

/// What the caller is told when an operation is refused or fails.
fn refusal(code: &'static str, message: String, detail: Option<Detail>) -> LPMEnvResult {
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct Refusal {
        abi_version: u32,
        code: &'static str,
        message: String,
        #[serde(flatten, skip_serializing_if = "Option::is_none")]
        detail: Option<Detail>,
    }
    match serde_json::to_vec(&Refusal {
        abi_version: ABI_VERSION,
        code,
        message,
        detail,
    }) {
        Ok(bytes) => result(5, bytes, None),
        Err(_) => failure(3, "env.engine_internal"),
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Detail {
    path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    untrack: Option<String>,
}

fn shown(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

/// Describe the LPM home at `home` for the user whose home directory is
/// `user_home`: whether it is that user's default home, `~/.lpm`, and the
/// suffix the CLI appends to its credential-store service names there.
/// # Safety
/// Both pointers must reference readable bytes for their lengths during the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn lpm_env_describe_home(
    home: *const u8,
    home_length: usize,
    user_home: *const u8,
    user_home_length: usize,
) -> LPMEnvResult {
    // SAFETY: The caller supplies live readable ranges for this call.
    let (Some(home), Some(user_home)) = (unsafe { absolute_path(home, home_length) }, unsafe {
        absolute_path(user_home, user_home_length)
    }) else {
        return failure(2, "env.invalid_input");
    };
    catch_unwind(AssertUnwindSafe(|| {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Output {
            abi_version: u32,
            is_default: bool,
            scope: Option<String>,
        }
        let root = lpm_common::LpmRoot::from_dir(home);
        let scope = root.credential_scope_for(&user_home);
        json(&Output {
            abi_version: ABI_VERSION,
            is_default: scope.is_none(),
            scope,
        })
    }))
    .unwrap_or_else(|_| failure(3, "env.engine_panic"))
}

/// Ready the LPM home at `home` for a write of login or env state, as the
/// CLI does: create it owner-only where it is missing, then keep it out of
/// git with a `.gitignore` that ignores everything in it. Where a git
/// repository around the home can't be kept from committing what it holds,
/// `exposed` says why, and nothing that holds secrets may be written there.
/// # Safety
/// The pointer must reference readable bytes for its length during the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn lpm_env_prepare_home(home: *const u8, home_length: usize) -> LPMEnvResult {
    // SAFETY: The caller supplies a live readable range for this call.
    let Some(home) = (unsafe { absolute_path(home, home_length) }) else {
        return failure(2, "env.invalid_input");
    };
    catch_unwind(AssertUnwindSafe(|| {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Exposed {
            reason: String,
            at_repository_root: bool,
        }
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Output {
            abi_version: u32,
            exposed: Option<Exposed>,
        }
        if let Err(error) = create_owner_only(&home) {
            return refusal(
                "env.home_unavailable",
                format!("failed to create the LPM home {}: {error}", home.display()),
                None,
            );
        }
        let exposed = lpm_common::project_state::keep_lpm_home_out_of_git(&home)
            .err()
            .map(|exposed| Exposed {
                reason: exposed.to_string(),
                at_repository_root: exposed.at_repository_root(),
            });
        json(&Output {
            abi_version: ABI_VERSION,
            exposed,
        })
    }))
    .unwrap_or_else(|_| failure(3, "env.engine_panic"))
}

fn create_owner_only(directory: &Path) -> std::io::Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
    builder.create(directory)
}

/// The project the CLI acts on for `folder`, as its env commands choose
/// it: the nearest directory at or above `folder` that holds a
/// `package.json` or an `lpm.json`, stopping before `user_home`, else
/// `folder`. `stateIsHome` says the project's `.lpm` would be the LPM home
/// at `home`, where the CLI refuses to keep project state.
/// # Safety
/// Each pointer must reference readable bytes for its length during the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn lpm_env_project_root(
    folder: *const u8,
    folder_length: usize,
    user_home: *const u8,
    user_home_length: usize,
    home: *const u8,
    home_length: usize,
) -> LPMEnvResult {
    // SAFETY: The caller supplies live readable ranges for this call.
    let (Some(folder), Some(user_home), Some(home)) = (unsafe {
        (
            absolute_path(folder, folder_length),
            absolute_path(user_home, user_home_length),
            absolute_path(home, home_length),
        )
    }) else {
        return failure(2, "env.invalid_input");
    };
    catch_unwind(AssertUnwindSafe(|| {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Output {
            abi_version: u32,
            root: String,
            is_project: bool,
            state_is_home: bool,
        }
        let root = lpm_workspace::find_project_config_root(&folder, Some(user_home.as_path()))
            .unwrap_or(folder);
        let is_project = root.join("package.json").is_file() || root.join("lpm.json").is_file();
        let state_is_home = lpm_common::LpmRoot::from_dir(lpm_common::project_state_dir(&root))
            .identity()
            == lpm_common::LpmRoot::from_dir(home).identity();
        json(&Output {
            abi_version: ABI_VERSION,
            root: shown(&root),
            is_project,
            state_is_home,
        })
    }))
    .unwrap_or_else(|_| failure(3, "env.engine_panic"))
}

/// Open the `.lpm` of the open project directory `project`, at `display`,
/// as the CLI does and write a new descriptor for it, which the caller
/// closes, to `state`. A project whose `.lpm` would be the LPM home at
/// `home` is refused, as the CLI refuses to keep project state there.
/// # Safety
/// `project` must be an open directory descriptor for the call, `display`
/// and `home` must reference readable bytes for their lengths, and `state`
/// must be writable.
#[cfg(unix)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn lpm_env_open_project_state(
    project: i32,
    display: *const u8,
    display_length: usize,
    home: *const u8,
    home_length: usize,
    state: *mut i32,
) -> LPMEnvResult {
    use std::os::fd::{BorrowedFd, IntoRawFd as _};

    // SAFETY: The caller supplies live readable ranges for this call.
    let (Some(display), Some(home)) = (unsafe {
        (
            absolute_path(display, display_length),
            absolute_path(home, home_length),
        )
    }) else {
        return failure(2, "env.invalid_input");
    };
    if project < 0 || state.is_null() {
        return failure(2, "env.invalid_input");
    }
    catch_unwind(AssertUnwindSafe(|| {
        let state_display = lpm_common::project_state_dir(&display);
        if lpm_common::LpmRoot::from_dir(&state_display).identity()
            == lpm_common::LpmRoot::from_dir(home).identity()
        {
            return refusal(
                "env.project_state_is_home",
                format!(
                    "{} is LPM's own home, so no project can keep its state there",
                    state_display.display()
                ),
                None,
            );
        }
        // SAFETY: The caller keeps `project` open for this call; only a
        // duplicate of it is owned here.
        let duplicate = match unsafe { BorrowedFd::borrow_raw(project) }.try_clone_to_owned() {
            Ok(duplicate) => duplicate,
            Err(error) => {
                return refusal(
                    "env.project_state",
                    format!("failed to open the project {}: {error}", display.display()),
                    None,
                );
            }
        };
        let root = cap_std::fs::Dir::from_std_file(std::fs::File::from(duplicate));
        match lpm_common::ensure_project_state_dir_in(&root, &display) {
            Ok(directory) => {
                let descriptor = directory.into_std_file().into_raw_fd();
                // SAFETY: The caller supplies a writable `state`, checked non-null above.
                unsafe { state.write(descriptor) };
                json(&Version {
                    abi_version: ABI_VERSION,
                })
            }
            Err(error) => {
                let unreal = root
                    .symlink_metadata(lpm_common::PROJECT_STATE_DIR)
                    .is_ok_and(|metadata| metadata.is_symlink() || !metadata.is_dir());
                let code = if unreal {
                    "env.project_state_link"
                } else {
                    "env.project_state"
                };
                refusal(code, error.to_string(), None)
            }
        }
    }))
    .unwrap_or_else(|_| failure(3, "env.engine_panic"))
}

#[cfg(unix)]
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Version {
    abi_version: u32,
}

/// Ready `path` for a file of secrets that the caller then writes, as
/// `lpm env export` readies one for the project at `project`: git is made
/// to ignore it, by a rule in the `.gitignore` of the project or of the
/// repository that holds it, and a file git tracks is refused.
/// # Safety
/// `project` and `path` must reference readable bytes for their lengths
/// during the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn lpm_env_prepare_secret_file(
    project: *const u8,
    project_length: usize,
    path: *const u8,
    path_length: usize,
) -> LPMEnvResult {
    // SAFETY: The caller supplies live readable ranges for this call.
    let (Some(project), Some(path)) = (unsafe {
        (
            absolute_path(project, project_length),
            absolute_path(path, path_length),
        )
    }) else {
        return failure(2, "env.invalid_input");
    };
    catch_unwind(AssertUnwindSafe(|| {
        use lpm_common::project_secret::{
            IgnoreFailure, IgnoreFile, SecretFileError, SecretIgnore,
        };

        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Ignore {
            kind: &'static str,
            files: Vec<String>,
        }
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Output {
            abi_version: u32,
            ignore: Ignore,
            warnings: Vec<String>,
        }
        match lpm_common::project_secret::prepare_secret_destination(
            &project,
            &path,
            IgnoreFile::ProjectGitignore,
            IgnoreFailure::Refuse,
        ) {
            Ok((ignore, warnings)) => {
                let kind = match ignore {
                    SecretIgnore::OutsideProject => "outsideProject",
                    SecretIgnore::AlreadyIgnored => "alreadyIgnored",
                    SecretIgnore::Added { .. } => "added",
                    SecretIgnore::NoRepository { .. } => "noRepository",
                    SecretIgnore::Unverified { .. } => "unverified",
                    SecretIgnore::Failed => "failed",
                };
                json(&Output {
                    abi_version: ABI_VERSION,
                    ignore: Ignore {
                        kind,
                        files: ignore.added_to().iter().map(|file| shown(file)).collect(),
                    },
                    warnings,
                })
            }
            Err(error) => {
                let message = error.to_string();
                let (code, path, untrack) = match error {
                    SecretFileError::Tracked { path, untrack } => {
                        ("env.secret_tracked", path, Some(untrack))
                    }
                    SecretFileError::Link { path } => ("env.secret_link", path, None),
                    SecretFileError::NotRegular { path } => ("env.secret_not_regular", path, None),
                    SecretFileError::Ignore { path, .. } => ("env.secret_ignore", path, None),
                    SecretFileError::Io { path, .. } => ("env.secret_write", path, None),
                };
                refusal(
                    code,
                    message,
                    Some(Detail {
                        path: shown(&path),
                        untrack,
                    }),
                )
            }
        }
    }))
    .unwrap_or_else(|_| failure(3, "env.engine_panic"))
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::lpm_env_release;
    use std::os::unix::fs::PermissionsExt as _;

    /// The status and JSON output of a result, which is then released.
    fn finish(result: LPMEnvResult) -> (u32, serde_json::Value) {
        // SAFETY: The result is live and unreleased until the release below.
        let output = serde_json::from_slice(unsafe {
            std::slice::from_raw_parts(result.data, result.length)
        })
        .unwrap();
        let status = result.status;
        // SAFETY: This is the sole release of the returned result.
        unsafe { lpm_env_release(result) };
        (status, output)
    }

    fn text(path: &Path) -> &str {
        path.to_str().unwrap()
    }

    fn describe(home: &str, user_home: &str) -> (u32, serde_json::Value) {
        // SAFETY: Both strings stay live throughout the synchronous call.
        finish(unsafe {
            lpm_env_describe_home(
                home.as_ptr(),
                home.len(),
                user_home.as_ptr(),
                user_home.len(),
            )
        })
    }

    fn prepare(home: &Path) -> (u32, serde_json::Value) {
        let home = text(home);
        // SAFETY: The string stays live throughout the synchronous call.
        finish(unsafe { lpm_env_prepare_home(home.as_ptr(), home.len()) })
    }

    fn project_root(folder: &Path, user_home: &Path, home: &Path) -> (u32, serde_json::Value) {
        let (folder, user_home, home) = (text(folder), text(user_home), text(home));
        // SAFETY: The strings stay live throughout the synchronous call.
        finish(unsafe {
            lpm_env_project_root(
                folder.as_ptr(),
                folder.len(),
                user_home.as_ptr(),
                user_home.len(),
                home.as_ptr(),
                home.len(),
            )
        })
    }

    /// Opens `project`'s state directory through the ABI: its status and
    /// output, and the descriptor it handed over.
    fn open_state(project: &Path) -> (u32, serde_json::Value, Option<std::os::fd::OwnedFd>) {
        open_state_with_home(project, &project.join("elsewhere/lpm-home"))
    }

    fn open_state_with_home(
        project: &Path,
        home: &Path,
    ) -> (u32, serde_json::Value, Option<std::os::fd::OwnedFd>) {
        use std::os::fd::{AsRawFd as _, FromRawFd as _};

        let directory = std::fs::File::open(project).unwrap();
        let (display, home) = (text(project), text(home));
        let mut state = -1;
        // SAFETY: The directory and strings stay live, and `state` writable, for the call.
        let result = unsafe {
            lpm_env_open_project_state(
                directory.as_raw_fd(),
                display.as_ptr(),
                display.len(),
                home.as_ptr(),
                home.len(),
                &mut state,
            )
        };
        let (status, output) = finish(result);
        // SAFETY: A descriptor the ABI wrote is owned by the caller.
        let state = (state >= 0).then(|| unsafe { std::os::fd::OwnedFd::from_raw_fd(state) });
        (status, output, state)
    }

    fn prepare_secret(project: &Path, path: &Path) -> (u32, serde_json::Value) {
        let (project, path) = (text(project), text(path));
        // SAFETY: The strings stay live throughout the synchronous call.
        finish(unsafe {
            lpm_env_prepare_secret_file(project.as_ptr(), project.len(), path.as_ptr(), path.len())
        })
    }

    fn mode(path: &Path) -> u32 {
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    fn repository() -> Option<tempfile::TempDir> {
        let dir = tempfile::tempdir().unwrap();
        for args in [
            &["init", "-q"][..],
            &["config", "core.excludesFile", "/dev/null"],
        ] {
            let status = lpm_common::project_git::hardened_git_command(dir.path(), args)
                .status()
                .ok()?;
            assert!(status.success(), "git {args:?}");
        }
        Some(dir)
    }

    #[test]
    fn the_default_home_keeps_bare_service_names_and_another_gets_the_cli_s_scope() {
        let user = tempfile::tempdir().unwrap();
        let user_home = text(user.path());

        let (status, output) = describe(&format!("{user_home}/.lpm"), user_home);
        assert_eq!(status, 0);
        assert_eq!(output["isDefault"], true);
        assert!(output["scope"].is_null());

        let other = user.path().join("elsewhere/lpm");
        let (status, output) = describe(text(&other), user_home);
        assert_eq!(status, 0);
        assert_eq!(output["isDefault"], false);
        assert_eq!(
            output["scope"],
            lpm_common::LpmRoot::from_dir(&other)
                .credential_scope_for(user.path())
                .unwrap()
        );

        for (home, user_home) in [
            ("relative/lpm", user_home),
            (text(&other), ""),
            ("/a\0b", user_home),
        ] {
            assert_eq!(describe(home, user_home).0, 2, "{home:?} {user_home:?}");
        }
    }

    #[test]
    fn a_prepared_home_is_owner_only_and_ignored_and_one_git_could_commit_is_reported() {
        let parent = tempfile::tempdir().unwrap();
        let home = parent.path().join("tools/lpm");

        let (status, output) = prepare(&home);
        assert_eq!(status, 0, "{output}");
        assert!(output["exposed"].is_null());
        assert_eq!(mode(&home), 0o700);
        assert_eq!(
            std::fs::read_to_string(home.join(".gitignore")).unwrap(),
            lpm_common::project_state::PROJECT_STATE_IGNORE
        );

        let repository = tempfile::tempdir().unwrap();
        std::fs::create_dir(repository.path().join(".git")).unwrap();
        let (status, output) = prepare(repository.path());
        assert_eq!(status, 0);
        assert_eq!(output["exposed"]["atRepositoryRoot"], true, "{output}");
        let nested = repository.path().join("state");
        std::fs::create_dir(&nested).unwrap();
        std::fs::write(nested.join(".gitignore"), "cache/\n").unwrap();
        let (_, output) = prepare(&nested);
        assert_eq!(output["exposed"]["atRepositoryRoot"], false, "{output}");
        assert!(
            output["exposed"]["reason"]
                .as_str()
                .unwrap()
                .contains("doesn't ignore everything"),
            "{output}"
        );

        let file = parent.path().join("file");
        std::fs::write(&file, "").unwrap();
        let (status, output) = prepare(&file);
        assert_eq!(status, 5);
        assert_eq!(output["code"], "env.home_unavailable");
    }

    #[test]
    fn a_folder_inside_a_project_links_the_project_and_the_home_directory_is_refused() {
        let user = tempfile::tempdir().unwrap();
        let default_home = user.path().join(".lpm");
        let project = user.path().join("work/app");
        std::fs::create_dir_all(project.join("src/deep")).unwrap();
        std::fs::write(project.join("package.json"), "{}").unwrap();

        let (status, output) = project_root(&project.join("src/deep"), user.path(), &default_home);
        assert_eq!(status, 0);
        assert_eq!(output["root"], text(&project));
        assert_eq!(output["isProject"], true);
        assert_eq!(output["stateIsHome"], false);

        // A stray package.json in the home directory doesn't make it a project.
        std::fs::write(user.path().join("package.json"), "{}").unwrap();
        let loose = user.path().join("work/notes");
        std::fs::create_dir_all(&loose).unwrap();
        let (_, output) = project_root(&loose, user.path(), &default_home);
        assert_eq!(output["root"], text(&loose));
        assert_eq!(output["isProject"], false);

        let (_, output) = project_root(user.path(), user.path(), &default_home);
        assert_eq!(output["root"], text(user.path()));
        assert_eq!(output["stateIsHome"], true);
        let (_, output) = project_root(user.path(), user.path(), &user.path().join("lpm-home"));
        assert_eq!(output["stateIsHome"], false);
    }

    #[test]
    fn a_project_s_state_directory_is_opened_owner_only_and_ignored() {
        let project = tempfile::tempdir().unwrap();

        let (status, output, state) = open_state(project.path());
        assert_eq!(status, 0, "{output}");
        let state = std::fs::File::from(state.unwrap());
        assert!(state.metadata().unwrap().is_dir());
        let directory = project.path().join(".lpm");
        assert_eq!(mode(&directory), 0o700);
        assert_eq!(
            std::fs::read_to_string(directory.join(".gitignore")).unwrap(),
            lpm_common::project_state::PROJECT_STATE_IGNORE
        );

        // One an earlier release made open to the group is closed again.
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o755)).unwrap();
        let (status, _, _) = open_state(project.path());
        assert_eq!(status, 0);
        assert_eq!(mode(&directory), 0o700);

        let linked = tempfile::tempdir().unwrap();
        let elsewhere = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(elsewhere.path(), linked.path().join(".lpm")).unwrap();
        let (status, output, state) = open_state(linked.path());
        assert_eq!(status, 5);
        assert_eq!(output["code"], "env.project_state_link");
        assert!(state.is_none());
        assert!(!elsewhere.path().join(".gitignore").exists());
    }

    #[test]
    fn a_project_whose_state_directory_would_be_the_lpm_home_is_refused() {
        let user = tempfile::tempdir().unwrap();
        let home = user.path().join(".lpm");

        let (status, output, state) = open_state_with_home(user.path(), &home);
        assert_eq!(status, 5);
        assert_eq!(output["code"], "env.project_state_is_home");
        assert!(state.is_none());
        assert!(!home.exists(), "nothing is created in the LPM home");

        std::fs::create_dir(&home).unwrap();
        std::os::unix::fs::symlink(user.path(), user.path().join("alias")).unwrap();
        let (status, output, _) = open_state_with_home(&user.path().join("alias"), &home);
        assert_eq!(
            status, 5,
            "a link to the home directory is the home directory"
        );
        assert_eq!(output["code"], "env.project_state_is_home");
        assert!(!home.join(".gitignore").exists());
    }

    #[test]
    fn a_secret_file_is_ignored_before_it_is_written_and_a_tracked_one_is_refused() {
        let Some(project) = repository() else {
            return;
        };
        let env = project.path().join(".env");

        let (status, output) = prepare_secret(project.path(), &env);
        assert_eq!(status, 0, "{output}");
        assert_eq!(output["ignore"]["kind"], "added");
        assert_eq!(
            output["ignore"]["files"][0],
            text(&project.path().join(".gitignore"))
        );
        assert!(!env.exists(), "the caller writes the file");
        let (status, output) = prepare_secret(project.path(), &env);
        assert_eq!(status, 0);
        assert_eq!(output["ignore"]["kind"], "alreadyIgnored");

        let committed = project.path().join(".env.production");
        std::fs::write(&committed, "TOKEN=\n").unwrap();
        let added = lpm_common::project_git::hardened_git_command(
            project.path(),
            &["add", "-f", ".env.production"],
        )
        .status()
        .unwrap();
        assert!(added.success());
        let (status, output) = prepare_secret(project.path(), &committed);
        assert_eq!(status, 5, "{output}");
        assert_eq!(output["code"], "env.secret_tracked");
        assert_eq!(output["path"], text(&committed));
        assert!(
            output["untrack"]
                .as_str()
                .unwrap()
                .contains("rm --cached -- .env.production"),
            "{output}"
        );

        // A file in another repository takes that repository's rule.
        let Some(other) = repository() else {
            return;
        };
        let elsewhere = other.path().join("config/.env");
        std::fs::create_dir(other.path().join("config")).unwrap();
        let (status, output) = prepare_secret(project.path(), &elsewhere);
        assert_eq!(status, 0, "{output}");
        assert_eq!(output["ignore"]["kind"], "added");
        let root = std::fs::canonicalize(other.path()).unwrap();
        assert_eq!(output["ignore"]["files"][0], text(&root.join(".gitignore")));
        assert!(
            std::fs::read_to_string(root.join(".gitignore"))
                .unwrap()
                .contains("/config/.env")
        );

        assert_eq!(
            prepare_secret(Path::new("/"), Path::new("relative/.env")).0,
            2
        );
    }
}
