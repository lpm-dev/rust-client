use super::*;

pub(crate) fn create_version_commit_and_tag(
    project_dir: &Path,
    manifest: &PlannedManifest,
    old_head: &str,
    tag: &str,
    requested_message: &str,
) -> Result<String, LpmError> {
    let repository_root = version_git_repository_root(project_dir)?;
    let repository_manifest = manifest.path.strip_prefix(&repository_root).map_err(|_| {
        LpmError::Script(format!(
            "version manifest is outside its Git worktree: {}",
            manifest.path.display()
        ))
    })?;
    require_version_git_success(
        &repository_root,
        [
            OsStr::new("add"),
            OsStr::new("--"),
            repository_manifest.as_os_str(),
        ],
    )?;
    abort_version_git_stage_for_test("add");
    require_version_git_success(
        &repository_root,
        [
            OsStr::new("commit"),
            OsStr::new("--only"),
            OsStr::new("-m"),
            OsStr::new(requested_message),
            OsStr::new("--"),
            repository_manifest.as_os_str(),
        ],
    )?;
    let created_head = resolve_version_git_commit(&repository_root, "HEAD^{commit}")?;
    if let Err(primary) = verify_version_git_commit(
        &repository_root,
        repository_manifest,
        old_head,
        &created_head,
        &sha256_hex(&manifest.updated_bytes),
    ) {
        return match rollback_created_version_commit(
            &repository_root,
            repository_manifest,
            old_head,
            &created_head,
        ) {
            Ok(()) => Err(primary),
            Err(rollback) => Err(LpmError::Script(format!(
                "{primary}; Git rollback was not safe: {rollback}"
            ))),
        };
    }
    abort_version_git_stage_for_test("commit");

    let actual_message = version_git_commit_message(&repository_root, &created_head)?;
    let tag_args = if version_git_config_bool(&repository_root, "tag.gpgSign")? {
        vec![
            OsString::from("tag"),
            OsString::from("-s"),
            OsString::from("-m"),
            OsString::from(&actual_message),
            OsString::from("--"),
            OsString::from(tag),
            OsString::from(&created_head),
        ]
    } else {
        vec![
            OsString::from("tag"),
            OsString::from("--"),
            OsString::from(tag),
            OsString::from(&created_head),
        ]
    };
    let tag_output = version_git_output(&repository_root, &tag_args)?;
    let tag_error = (!tag_output.status.success()).then(|| {
        let command = tag_args
            .iter()
            .map(|arg| arg.to_string_lossy())
            .collect::<Vec<_>>()
            .join(" ");
        version_git_error(&command, tag_output)
    });
    let mut peeled_tag = OsString::from("refs/tags/");
    peeled_tag.push(tag);
    peeled_tag.push("^{commit}");
    let tag_commit = resolve_optional_version_git_commit(&repository_root, &peeled_tag)?;
    if let Some(error) = tag_error
        && tag_commit.as_deref() != Some(created_head.as_str())
    {
        return Err(error);
    }
    let tag_commit = tag_commit.ok_or_else(|| {
        LpmError::Script(format!(
            "Git reported success but tag `{tag}` was not created"
        ))
    })?;
    if tag_commit != created_head {
        return Err(LpmError::Script(format!(
            "Git tag `{tag}` does not identify the version commit; the release journal was preserved"
        )));
    }
    abort_version_git_stage_for_test("tag");
    Ok(actual_message)
}

pub(super) fn rollback_created_version_commit(
    repository_root: &Path,
    manifest: &Path,
    old_head: &str,
    created_head: &str,
) -> Result<(), LpmError> {
    let current_head = resolve_version_git_commit(repository_root, "HEAD^{commit}")?;
    if current_head == created_head && current_head != old_head {
        require_version_git_success(
            repository_root,
            [
                OsStr::new("update-ref"),
                OsStr::new("-m"),
                OsStr::new("lpm version rejected commit rollback"),
                OsStr::new("HEAD"),
                OsStr::new(old_head),
                OsStr::new(created_head),
            ],
        )?;
    } else if current_head != old_head {
        return Err(LpmError::Script(format!(
            "Git HEAD moved from the rejected version commit {created_head} to {current_head}; no ref was changed"
        )));
    }
    require_version_git_success(
        repository_root,
        [
            OsStr::new("reset"),
            OsStr::new("--quiet"),
            OsStr::new(old_head),
            OsStr::new("--"),
            manifest.as_os_str(),
        ],
    )?;
    Ok(())
}

pub(super) fn version_git_commit_message(
    repository_root: &Path,
    commit: &str,
) -> Result<String, LpmError> {
    let output = require_version_git_success(
        repository_root,
        [
            OsStr::new("log"),
            OsStr::new("-1"),
            OsStr::new("--format=%B"),
            OsStr::new(commit),
        ],
    )?;
    let message = String::from_utf8(output.stdout)
        .map_err(|_| LpmError::Script("version commit message is not valid UTF-8".into()))?;
    Ok(message.trim_end().to_string())
}

pub(super) fn version_git_config_bool(repository_root: &Path, key: &str) -> Result<bool, LpmError> {
    let output = version_git_output(
        repository_root,
        [
            OsStr::new("config"),
            OsStr::new("--type=bool"),
            OsStr::new("--get"),
            OsStr::new(key),
        ],
    )?;
    match output.status.code() {
        Some(0) => match output.stdout.as_slice() {
            b"true\n" | b"true\r\n" => Ok(true),
            b"false\n" | b"false\r\n" => Ok(false),
            _ => Err(LpmError::Script(format!(
                "git config {key} returned an invalid boolean"
            ))),
        },
        Some(1) => Ok(false),
        _ => Err(version_git_error("config --type=bool --get", output)),
    }
}

#[cfg(feature = "internal-test-sigstore-mock")]
pub(super) fn abort_version_git_stage_for_test(stage: &str) {
    if std::env::var_os("LPM_INTERNAL_TEST_VERSION_ABORT_AFTER_GIT_STAGE")
        .is_some_and(|value| value == stage)
    {
        std::process::abort();
    }
}

#[cfg(not(feature = "internal-test-sigstore-mock"))]
pub(super) fn abort_version_git_stage_for_test(_stage: &str) {}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum VersionGitRecoveryState {
    RolledBack,
    Completed,
}

pub(super) fn recover_version_git_transaction(
    canonical_root: &Path,
    git: &VersionGitJournal,
    entries: &[RecoveryEntry],
) -> Result<VersionGitRecoveryState, LpmError> {
    let [entry] = entries else {
        return Err(LpmError::Script(
            "version Git recovery requires exactly one package manifest".into(),
        ));
    };
    let working_dir = entry.target.display.parent().ok_or_else(|| {
        LpmError::Script("version transaction manifest has no parent directory".into())
    })?;
    let canonical_working_dir = working_dir.canonicalize().map_err(LpmError::Io)?;
    if canonical_working_dir != working_dir || !canonical_working_dir.starts_with(canonical_root) {
        return Err(LpmError::Script(format!(
            "version transaction Git directory changed outside the workspace: {}",
            working_dir.display()
        )));
    }

    let repository_root = version_git_repository_root(&canonical_working_dir)?;
    let repository_manifest = entry
        .target
        .display
        .strip_prefix(&repository_root)
        .map_err(|_| {
            LpmError::Script(format!(
                "version transaction manifest is outside its Git worktree: {}",
                entry.target.display.display()
            ))
        })?;
    let old_head =
        resolve_version_git_commit(&repository_root, &format!("{}^{{commit}}", git.old_head))?;
    if old_head != git.old_head {
        return Err(LpmError::Script(
            "version transaction baseline Git commit does not match its journal".into(),
        ));
    }

    let tag_ref = format!("refs/tags/{}", git.tag);
    require_version_git_success(
        &repository_root,
        [OsStr::new("check-ref-format"), OsStr::new(&tag_ref)],
    )?;
    let mut peeled_tag = OsString::from(&tag_ref);
    peeled_tag.push("^{commit}");
    if let Some(tag_commit) = resolve_optional_version_git_commit(&repository_root, &peeled_tag)? {
        if !entry.restore {
            return Err(LpmError::Script(
                "the completed version tag exists but package.json no longer matches its journal; the release journal was preserved".into(),
            ));
        }
        verify_version_git_commit(
            &repository_root,
            repository_manifest,
            &git.old_head,
            &tag_commit,
            &entry.updated_sha256,
        )?;
        return Ok(VersionGitRecoveryState::Completed);
    }
    if version_git_ref_exists(&repository_root, &tag_ref)? {
        return Err(LpmError::Script(format!(
            "Git tag `{}` exists but does not identify the expected version commit; the release journal was preserved",
            git.tag
        )));
    }

    let current_head = resolve_version_git_commit(&repository_root, "HEAD^{commit}")?;
    if current_head != git.old_head {
        verify_version_git_commit(
            &repository_root,
            repository_manifest,
            &git.old_head,
            &current_head,
            &entry.updated_sha256,
        )?;
        require_version_git_success(
            &repository_root,
            [
                OsStr::new("update-ref"),
                OsStr::new("-m"),
                OsStr::new("lpm version rollback"),
                OsStr::new("HEAD"),
                OsStr::new(&git.old_head),
                OsStr::new(&current_head),
            ],
        )?;
    }
    require_version_git_success(
        &repository_root,
        [
            OsStr::new("reset"),
            OsStr::new("--quiet"),
            OsStr::new(&git.old_head),
            OsStr::new("--"),
            repository_manifest.as_os_str(),
        ],
    )?;
    Ok(VersionGitRecoveryState::RolledBack)
}

pub(super) fn verify_version_git_commit(
    repository_root: &Path,
    manifest: &Path,
    old_head: &str,
    candidate: &str,
    updated_sha256: &str,
) -> Result<(), LpmError> {
    let parent = resolve_version_git_commit(repository_root, &format!("{candidate}^{{commit}}^"))?;
    if parent != old_head {
        return Err(LpmError::Script(format!(
            "Git HEAD moved outside the version transaction; expected parent {old_head}, found {parent}. The release journal was preserved."
        )));
    }

    let mut excluded_manifest = OsString::from(":(top,exclude,literal)");
    excluded_manifest.push(manifest.as_os_str());
    let unchanged_elsewhere = version_git_output(
        repository_root,
        [
            OsStr::new("diff"),
            OsStr::new("--quiet"),
            OsStr::new(old_head),
            OsStr::new(candidate),
            OsStr::new("--"),
            OsStr::new("."),
            excluded_manifest.as_os_str(),
        ],
    )?;
    match unchanged_elsewhere.status.code() {
        Some(0) => {}
        Some(1) => {
            return Err(LpmError::Script(
                "the version commit contains changes outside package.json; no automatic Git rollback was attempted and the release journal was preserved".into(),
            ));
        }
        _ => return Err(version_git_error("diff --quiet", unchanged_elsewhere)),
    }

    let mut object_spec = OsString::from(candidate);
    object_spec.push(":");
    object_spec.push(manifest.as_os_str());
    let size_output = require_version_git_success(
        repository_root,
        [
            OsStr::new("cat-file"),
            OsStr::new("-s"),
            object_spec.as_os_str(),
        ],
    )?;
    let size = parse_version_git_usize("cat-file -s", &size_output.stdout)?;
    if size as u64 > lpm_common::CONFIG_FILE_SIZE_CAP_BYTES {
        return Err(LpmError::Script(
            "the version commit contains an oversized package.json; the release journal was preserved"
                .into(),
        ));
    }
    let manifest_output = require_version_git_success(
        repository_root,
        [
            OsStr::new("cat-file"),
            OsStr::new("blob"),
            object_spec.as_os_str(),
        ],
    )?;
    if manifest_output.stdout.len() != size || sha256_hex(&manifest_output.stdout) != updated_sha256
    {
        return Err(LpmError::Script(
            "the version commit does not contain the journaled package.json; no automatic Git rollback was attempted and the release journal was preserved".into(),
        ));
    }
    Ok(())
}

pub(super) fn version_git_repository_root(working_dir: &Path) -> Result<PathBuf, LpmError> {
    let output = require_version_git_success(
        working_dir,
        [OsStr::new("rev-parse"), OsStr::new("--show-toplevel")],
    )?;
    let mut bytes = output.stdout;
    while bytes
        .last()
        .is_some_and(|byte| matches!(byte, b'\n' | b'\r'))
    {
        bytes.pop();
    }
    let path = path_from_git_bytes(bytes)?;
    path.canonicalize().map_err(LpmError::Io)
}

pub(super) fn resolve_version_git_commit(
    repository_root: &Path,
    object: &str,
) -> Result<String, LpmError> {
    let output = require_version_git_success(
        repository_root,
        [
            OsStr::new("rev-parse"),
            OsStr::new("--verify"),
            OsStr::new(object),
        ],
    )?;
    version_git_stdout_text("rev-parse --verify", output.stdout)
}

pub(super) fn resolve_optional_version_git_commit(
    repository_root: &Path,
    object: &OsStr,
) -> Result<Option<String>, LpmError> {
    let output = version_git_output(
        repository_root,
        [
            OsStr::new("rev-parse"),
            OsStr::new("--verify"),
            OsStr::new("--quiet"),
            object,
        ],
    )?;
    match output.status.code() {
        Some(0) => Ok(Some(version_git_stdout_text(
            "rev-parse --verify --quiet",
            output.stdout,
        )?)),
        Some(1) => Ok(None),
        _ => Err(version_git_error("rev-parse --verify --quiet", output)),
    }
}

pub(super) fn version_git_ref_exists(
    repository_root: &Path,
    reference: &str,
) -> Result<bool, LpmError> {
    let output = version_git_output(
        repository_root,
        [
            OsStr::new("rev-parse"),
            OsStr::new("--verify"),
            OsStr::new("--quiet"),
            OsStr::new(reference),
        ],
    )?;
    match output.status.code() {
        Some(0) => Ok(true),
        Some(1) => Ok(false),
        _ => Err(version_git_error("rev-parse --verify --quiet", output)),
    }
}

pub(super) fn require_version_git_success<I, S>(cwd: &Path, args: I) -> Result<Output, LpmError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let args = args
        .into_iter()
        .map(|arg| arg.as_ref().to_os_string())
        .collect::<Vec<_>>();
    let command = args
        .iter()
        .map(|arg| arg.to_string_lossy())
        .collect::<Vec<_>>()
        .join(" ");
    let output = version_git_output(cwd, &args)?;
    if output.status.success() {
        Ok(output)
    } else {
        Err(version_git_error(&command, output))
    }
}

pub(super) fn version_git_output<I, S>(cwd: &Path, args: I) -> Result<Output, LpmError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    Command::new("git")
        .args(args)
        .current_dir(cwd)
        .output()
        .map_err(LpmError::Io)
}

pub(super) fn version_git_stdout_text(command: &str, bytes: Vec<u8>) -> Result<String, LpmError> {
    let value = String::from_utf8(bytes)
        .map_err(|_| LpmError::Script(format!("git {command} returned non-UTF-8 output")))?;
    Ok(value.trim().to_string())
}

pub(super) fn parse_version_git_usize(command: &str, bytes: &[u8]) -> Result<usize, LpmError> {
    std::str::from_utf8(bytes)
        .ok()
        .and_then(|value| value.trim().parse().ok())
        .ok_or_else(|| LpmError::Script(format!("git {command} returned an invalid size")))
}

pub(super) fn version_git_error(command: &str, output: Output) -> LpmError {
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let detail = if stderr.is_empty() { stdout } else { stderr };
    LpmError::Script(format!("git {command} failed: {detail}"))
}

#[cfg(unix)]
#[expect(
    clippy::unnecessary_wraps,
    reason = "matches the fallible non-Unix Git path decoding contract"
)]
pub(super) fn path_from_git_bytes(bytes: Vec<u8>) -> Result<PathBuf, LpmError> {
    use std::os::unix::ffi::OsStringExt as _;
    Ok(PathBuf::from(OsString::from_vec(bytes)))
}

#[cfg(not(unix))]
pub(super) fn path_from_git_bytes(bytes: Vec<u8>) -> Result<PathBuf, LpmError> {
    String::from_utf8(bytes)
        .map(PathBuf::from)
        .map_err(|_| LpmError::Script("Git worktree path is not valid UTF-8".into()))
}
