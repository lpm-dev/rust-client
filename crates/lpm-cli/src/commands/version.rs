use crate::commands::release::release_workspace_manifest_paths;
use crate::install_ui;
use crate::output;
use crate::release_plan;
use lpm_common::LpmError;
use lpm_semver::VersionBump;
use std::path::{Path, PathBuf};
use std::process::Command;

const DEFAULT_MESSAGE: &str = "v%s";

enum VersionOperation {
    Applied {
        plan: release_plan::ReleasePlan,
        tag: String,
        commit_message: String,
    },
    Recovered {
        tag: Option<String>,
    },
}

pub(crate) fn run(
    project_dir: &Path,
    bump: &VersionBump,
    dry_run: bool,
    json_output: bool,
    git_tag_version: bool,
    tag_prefix: &str,
    message: &str,
) -> Result<(), LpmError> {
    let project_dir = project_dir.canonicalize().map_err(LpmError::Io)?;
    let (transaction_root, allowed_manifests) = version_transaction_scope(&project_dir)?;
    let transaction_operation =
        version_transaction_operation(&project_dir, bump, git_tag_version, tag_prefix, message)?;
    let operation = || {
        ensure_version_transaction_scope_unchanged(
            &project_dir,
            &transaction_root,
            &allowed_manifests,
        )?;
        if dry_run {
            release_plan::ensure_no_pending_release_transaction(&transaction_root)?;
        } else {
            let recovery = release_plan::recover_pending_operation_transaction(
                &transaction_root,
                &allowed_manifests,
                &transaction_operation,
            )?;
            if let release_plan::ReleaseOperationRecoveryOutcome::Completed { tag } = recovery {
                return Ok(VersionOperation::Recovered { tag });
            }
        }
        if git_tag_version && !dry_run {
            ensure_clean_git(&project_dir)?;
        }

        let plan = release_plan::plan_single_package(&project_dir, bump)?;
        let planned = plan.planned_manifests()?;
        let package = plan
            .packages
            .first()
            .ok_or_else(|| LpmError::Script("version plan contained no package".into()))?;
        let tag = format!("{tag_prefix}{}", package.new_version);
        let mut commit_message = format_message(message, &package.new_version);

        if git_tag_version && !dry_run {
            ensure_tag_available(&project_dir, &tag)?;
        }

        if !dry_run {
            if git_tag_version {
                let old_head =
                    git_stdout(&project_dir, ["rev-parse", "--verify", "HEAD^{commit}"])?;
                let manifest = planned.first().ok_or_else(|| {
                    LpmError::Script("version transaction contained no package manifest".into())
                })?;
                commit_message = release_plan::write_planned_manifests_then_git(
                    &transaction_root,
                    &planned,
                    transaction_operation.clone(),
                    release_plan::VersionGitTransaction {
                        old_head: old_head.clone(),
                        tag: tag.clone(),
                    },
                    || {
                        release_plan::create_version_commit_and_tag(
                            &project_dir,
                            manifest,
                            &old_head,
                            &tag,
                            &commit_message,
                        )
                    },
                )?;
            } else {
                release_plan::write_planned_manifests(
                    &transaction_root,
                    &planned,
                    transaction_operation.clone(),
                )?;
            }
        }

        Ok(VersionOperation::Applied {
            plan,
            tag,
            commit_message,
        })
    };
    let lock_path = lpm_common::project_install_lock(&transaction_root);
    let outcome = if dry_run {
        lpm_common::with_shared_lock(lock_path, operation)?
    } else {
        lpm_common::with_exclusive_lock(lock_path, operation)?
    };
    let (plan, tag, commit_message) = match outcome {
        VersionOperation::Applied {
            plan,
            tag,
            commit_message,
        } => (plan, tag, commit_message),
        VersionOperation::Recovered { tag } => {
            if json_output {
                let json = serde_json::json!({
                    "success": true,
                    "recovered": true,
                    "git_tag_version": git_tag_version,
                    "tag": tag,
                });
                println!("{}", output::format_json_answer(&json)?);
            } else if let Some(tag) = tag {
                install_ui::done_line(crate::install_ui::terminal_line!(
                    "recovered completed version transaction {}",
                    install_ui::cyan(&tag)
                ));
            } else {
                install_ui::done("Recovered completed version transaction");
            }
            return Ok(());
        }
    };
    let package = plan
        .packages
        .first()
        .ok_or_else(|| LpmError::Script("version plan contained no package".into()))?;

    if json_output {
        let json = serde_json::json!({
            "success": true,
            "dry_run": dry_run,
            "git_tag_version": git_tag_version,
            "commit": if git_tag_version { Some(commit_message) } else { None },
            "tag": if git_tag_version { Some(tag) } else { None },
            "plan": plan.to_json(dry_run),
        });
        println!("{}", output::format_json_answer(&json)?);
    } else {
        install_ui::done_line(crate::install_ui::terminal_line!(
            "{} {} -> {}",
            install_ui::yellow(&package.name),
            install_ui::dim(&package.old_version),
            install_ui::yellow(&package.new_version)
        ));
        if git_tag_version {
            install_ui::detail_line(crate::install_ui::terminal_line!(
                "tag: {}",
                install_ui::cyan(&tag)
            ));
        }
    }
    Ok(())
}

fn version_transaction_operation(
    project_dir: &Path,
    bump: &VersionBump,
    git_tag_version: bool,
    tag_prefix: &str,
    message: &str,
) -> Result<release_plan::ReleaseTransactionOperation, LpmError> {
    let mut identity = serde_json::to_vec(&serde_json::json!({
        "bump": bump.as_str(),
        "git_tag_version": git_tag_version,
        "tag_prefix": tag_prefix,
        "message": message,
    }))?;
    identity.push(0);
    append_version_path_identity(&mut identity, project_dir)?;
    Ok(release_plan::ReleaseTransactionOperation::new(
        release_plan::ReleaseTransactionOperationKind::Version,
        &identity,
    ))
}

#[cfg(unix)]
#[expect(
    clippy::unnecessary_wraps,
    reason = "matches the fallible fallback path encoding contract"
)]
fn append_version_path_identity(identity: &mut Vec<u8>, path: &Path) -> Result<(), LpmError> {
    use std::os::unix::ffi::OsStrExt as _;

    identity.extend_from_slice(path.as_os_str().as_bytes());
    Ok(())
}

#[cfg(windows)]
#[expect(
    clippy::unnecessary_wraps,
    reason = "matches the fallible fallback path encoding contract"
)]
fn append_version_path_identity(identity: &mut Vec<u8>, path: &Path) -> Result<(), LpmError> {
    use std::os::windows::ffi::OsStrExt as _;

    for unit in path.as_os_str().encode_wide() {
        identity.extend_from_slice(&unit.to_le_bytes());
    }
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn append_version_path_identity(identity: &mut Vec<u8>, path: &Path) -> Result<(), LpmError> {
    let path = path
        .to_str()
        .ok_or_else(|| LpmError::Script("version project path is not valid UTF-8".into()))?;
    identity.extend_from_slice(path.as_bytes());
    Ok(())
}

fn version_transaction_scope(project_dir: &Path) -> Result<(PathBuf, Vec<PathBuf>), LpmError> {
    let workspace = lpm_workspace::discover_workspace(project_dir)
        .map_err(|error| LpmError::Workspace(error.to_string()))?;
    if let Some(workspace) = workspace {
        let root = workspace.root.canonicalize().map_err(LpmError::Io)?;
        return Ok((root, release_workspace_manifest_paths(&workspace, true)));
    }
    Ok((
        project_dir.to_path_buf(),
        vec![project_dir.join("package.json")],
    ))
}

fn ensure_version_transaction_scope_unchanged(
    project_dir: &Path,
    expected_root: &Path,
    expected_manifests: &[PathBuf],
) -> Result<(), LpmError> {
    let (current_root, current_manifests) = version_transaction_scope(project_dir)?;
    if current_root != expected_root || current_manifests != expected_manifests {
        return Err(LpmError::Script(format!(
            "version project scope changed while waiting for the transaction lock at {}; retry the command",
            expected_root.display()
        )));
    }
    Ok(())
}

fn ensure_tag_available(project_dir: &Path, tag: &str) -> Result<(), LpmError> {
    if tag.starts_with('-') {
        return Err(LpmError::Script(format!(
            "git tag name `{tag}` is invalid; tags cannot start with `-`"
        )));
    }

    let tag_ref = format!("refs/tags/{tag}");
    let output = Command::new("git")
        .arg("check-ref-format")
        .arg(&tag_ref)
        .current_dir(project_dir)
        .output()
        .map_err(LpmError::Io)?;
    if !output.status.success() {
        return Err(LpmError::Script(format!("git tag name `{tag}` is invalid")));
    }

    let output = Command::new("git")
        .arg("rev-parse")
        .arg("--verify")
        .arg("--quiet")
        .arg(&tag_ref)
        .current_dir(project_dir)
        .output()
        .map_err(LpmError::Io)?;
    match output.status.code() {
        Some(0) => Err(LpmError::Script(format!(
            "git tag `{tag}` already exists; refusing to create a partial version commit"
        ))),
        Some(1) => Ok(()),
        _ => Err(git_error("rev-parse --verify --quiet", output)),
    }
}

pub(crate) fn default_message(message: Option<String>) -> String {
    message.unwrap_or_else(|| DEFAULT_MESSAGE.to_string())
}

fn format_message(template: &str, version: &str) -> String {
    if template.contains("%s") {
        template.replace("%s", version)
    } else {
        template.to_string()
    }
}

fn ensure_clean_git(project_dir: &Path) -> Result<(), LpmError> {
    git(project_dir, ["rev-parse", "--is-inside-work-tree"])?;
    let output = Command::new("git")
        .arg("status")
        .arg("--porcelain")
        .arg("--untracked-files=all")
        .arg("--")
        .arg(":(top,exclude,glob)**/.lpm/.install.lock")
        .arg(":(top,exclude,glob)**/.lpm/.install.lock.writer-intent")
        .arg(":(top,exclude,glob)**/.lpm/.install.lock.writer-queue")
        .arg(":(top,exclude,glob)**/.lpm/.publish.lock")
        .arg(":(top,exclude,glob)**/.lpm/.publish.lock.writer-intent")
        .arg(":(top,exclude,glob)**/.lpm/.publish.lock.writer-queue")
        .current_dir(project_dir)
        .output()
        .map_err(LpmError::Io)?;
    if !output.status.success() {
        return Err(git_error("status --porcelain", output));
    }
    if !output.stdout.is_empty() {
        return Err(LpmError::Script(
            "git working tree must be clean before `lpm version` creates a commit and tag. Use --no-git-tag-version to only edit package.json.".into(),
        ));
    }
    Ok(())
}

fn git<'a>(project_dir: &Path, args: impl IntoIterator<Item = &'a str>) -> Result<(), LpmError> {
    let args: Vec<&str> = args.into_iter().collect();
    let output = Command::new("git")
        .args(&args)
        .current_dir(project_dir)
        .output()
        .map_err(LpmError::Io)?;
    if output.status.success() {
        Ok(())
    } else {
        Err(git_error(&args.join(" "), output))
    }
}

fn git_stdout<'a>(
    project_dir: &Path,
    args: impl IntoIterator<Item = &'a str>,
) -> Result<String, LpmError> {
    let args: Vec<&str> = args.into_iter().collect();
    let output = Command::new("git")
        .args(&args)
        .current_dir(project_dir)
        .output()
        .map_err(LpmError::Io)?;
    if !output.status.success() {
        return Err(git_error(&args.join(" "), output));
    }
    String::from_utf8(output.stdout)
        .map(|value| value.trim().to_string())
        .map_err(|_| LpmError::Script(format!("git {} returned non-UTF-8 output", args.join(" "))))
}

fn git_error(command: &str, output: std::process::Output) -> LpmError {
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let detail = if stderr.is_empty() { stdout } else { stderr };
    LpmError::Script(format!("git {command} failed: {detail}"))
}
