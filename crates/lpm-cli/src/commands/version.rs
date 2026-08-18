use crate::install_ui;
use crate::output;
use crate::release_plan;
use lpm_common::LpmError;
use lpm_semver::VersionBump;
use std::path::Path;
use std::process::Command;

const DEFAULT_MESSAGE: &str = "v%s";

pub(crate) fn run(
    project_dir: &Path,
    bump: &VersionBump,
    dry_run: bool,
    json_output: bool,
    git_tag_version: bool,
    tag_prefix: &str,
    message: &str,
) -> Result<(), LpmError> {
    let operation = || {
        if git_tag_version && !dry_run {
            ensure_clean_git(project_dir)?;
        }

        let plan = release_plan::plan_single_package(project_dir, bump)?;
        let planned = plan.planned_manifests()?;
        let package = plan
            .packages
            .first()
            .ok_or_else(|| LpmError::Script("version plan contained no package".into()))?;
        let tag = format!("{tag_prefix}{}", package.new_version);
        let commit_message = format_message(message, &package.new_version);

        if git_tag_version && !dry_run {
            ensure_tag_available(project_dir, &tag)?;
        }

        if !dry_run {
            release_plan::write_planned_manifests(&planned)?;
            if git_tag_version {
                git(project_dir, ["add", "package.json"])?;
                git(project_dir, ["commit", "-m", commit_message.as_str()])?;
                git(project_dir, ["tag", "--", tag.as_str()])?;
            }
        }

        Ok((plan, tag, commit_message))
    };
    let (plan, tag, commit_message) = if dry_run {
        operation()?
    } else {
        lpm_common::with_exclusive_lock(lpm_common::project_install_lock(project_dir), operation)?
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

fn git_error(command: &str, output: std::process::Output) -> LpmError {
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let detail = if stderr.is_empty() { stdout } else { stderr };
    LpmError::Script(format!("git {command} failed: {detail}"))
}
