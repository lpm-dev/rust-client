//! `lpm env link`, `lpm env unlink` and `lpm env links`: which folders on
//! this machine may use an env project's local values, and the check that
//! asks before a folder that isn't linked uses them.

use std::io::IsTerminal as _;
use std::path::Path;

use lpm_common::LpmError;
use lpm_vault::FolderLink;

use crate::output;

/// Lets `project_dir` use the env project its lpm.json names once it is
/// linked: at a terminal, asks whether to link it; elsewhere refuses with
/// the command that links it.
pub(crate) fn ensure_folder_linked(project_dir: &Path, json_output: bool) -> Result<(), LpmError> {
    match lpm_vault::folder_link(project_dir).map_err(LpmError::Env)? {
        Some(FolderLink::Unlinked(unlinked)) => ask_to_link(project_dir, &unlinked, json_output),
        Some(FolderLink::Linked) | None => Ok(()),
    }
}

/// [`ensure_folder_linked`] for the env project `vault_id`, which the caller
/// read from the folder's lpm.json.
pub(super) fn ensure_folder_linked_to(
    project_dir: &Path,
    vault_id: &str,
    json_output: bool,
) -> Result<(), LpmError> {
    match lpm_vault::folder_link_for_vault_id(project_dir, vault_id).map_err(LpmError::Env)? {
        FolderLink::Unlinked(unlinked) => ask_to_link(project_dir, &unlinked, json_output),
        FolderLink::Linked => Ok(()),
    }
}

fn ask_to_link(
    project_dir: &Path,
    unlinked: &lpm_vault::UnlinkedFolder,
    json_output: bool,
) -> Result<(), LpmError> {
    if json_output || !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
        return Err(LpmError::EnvProjectRefused(unlinked.refusal()));
    }
    output::warn(&describe(unlinked));
    let link = cliclack::confirm(format!(
        "Let {} use this env project?",
        lpm_common::sanitize_terminal_inline(&unlinked.folder.display().to_string())
    ))
    .initial_value(false)
    .interact()
    .map_err(|error| LpmError::Env(format!("prompt failed: {error}")))?;
    if !link {
        return Err(LpmError::EnvProjectRefused(unlinked.refusal()));
    }
    lpm_vault::link_folder_to_vault_id(project_dir, &unlinked.vault_id).map_err(LpmError::Env)
}

/// What the user is asked to link: the project as the vault records it and
/// where it's already linked, then the folder asking.
fn describe(unlinked: &lpm_vault::UnlinkedFolder) -> String {
    let project = match &unlinked.project_name {
        Some(name) => format!("{name:?} ({})", unlinked.vault_id),
        None => unlinked.vault_id.clone(),
    };
    let linked = if unlinked.linked_folders.is_empty() {
        "no folder on this machine".to_owned()
    } else {
        unlinked
            .linked_folders
            .iter()
            .map(|folder| folder.display().to_string())
            .collect::<Vec<_>>()
            .join(", ")
    };
    lpm_common::sanitize_terminal_inline(&format!(
        "This folder's lpm.json names env project {project}, which is linked to {linked}. Link \
         this folder only if it's a checkout of that project."
    ))
    .to_string()
}

pub(super) fn env_link(project_dir: &Path, yes: bool, json_output: bool) -> Result<(), LpmError> {
    let vault_id = lpm_vault::vault_id::read_vault_id(project_dir).ok_or_else(no_project)?;
    let link =
        lpm_vault::folder_link_for_vault_id(project_dir, &vault_id).map_err(LpmError::Env)?;
    if let FolderLink::Unlinked(unlinked) = &link
        && !yes
    {
        if json_output || !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
            return Err(LpmError::Env(
                "linking a folder asks first; pass --yes to link it without asking".to_owned(),
            ));
        }
        output::warn(&describe(unlinked));
        let confirmed = cliclack::confirm("Link this folder?")
            .initial_value(false)
            .interact()
            .map_err(|error| LpmError::Env(format!("prompt failed: {error}")))?;
        if !confirmed {
            return Err(LpmError::ExitCode(1));
        }
    }
    lpm_vault::link_folder_to_vault_id(project_dir, &vault_id).map_err(LpmError::Env)?;
    let folder = resolved(project_dir);
    let already = link == FolderLink::Linked;
    if json_output {
        print_json(&serde_json::json!({
            "success": true,
            "vault_id": vault_id,
            "folder": folder,
            "already_linked": already,
        }));
    } else if already {
        output::success(&format!("{} is already linked", folder.display()));
    } else {
        output::success(&format!("Linked {}", folder.display()));
    }
    Ok(())
}

pub(super) fn env_unlink(
    project_dir: &Path,
    folder: Option<&Path>,
    json_output: bool,
) -> Result<(), LpmError> {
    let folder = match folder {
        Some(folder) => crate::project_fs::project_relative_path(
            &std::env::current_dir().map_err(LpmError::Io)?,
            project_dir,
            folder,
        ),
        None => project_dir.to_path_buf(),
    };
    let (vault_id, removed) = lpm_vault::unlink_folder(project_dir, &folder)
        .map_err(LpmError::Env)?
        .ok_or_else(no_project)?;
    let folder = resolved(&folder);
    if json_output {
        print_json(&serde_json::json!({
            "success": true,
            "vault_id": vault_id,
            "folder": folder,
            "unlinked": removed,
        }));
    } else if removed {
        output::success(&format!("Unlinked {}", folder.display()));
    } else {
        output::info(&format!("{} wasn't linked", folder.display()));
    }
    Ok(())
}

pub(super) fn env_links(project_dir: &Path, json_output: bool) -> Result<(), LpmError> {
    let (vault_id, folders) = lpm_vault::linked_folders(project_dir)
        .map_err(LpmError::Env)?
        .ok_or_else(no_project)?;
    let current = resolved(project_dir);
    if json_output {
        print_json(&serde_json::json!({
            "success": true,
            "vault_id": vault_id,
            "folders": folders,
            "this_folder_linked": folders.contains(&current),
        }));
        return Ok(());
    }
    if folders.is_empty() {
        output::info("No folder on this machine is linked to this env project.");
        return Ok(());
    }
    for folder in &folders {
        let marker = if *folder == current {
            " (this folder)"
        } else {
            ""
        };
        println!(
            "{}{marker}",
            lpm_common::sanitize_terminal_inline(&folder.display().to_string())
        );
    }
    Ok(())
}

/// `folder` as a link names it, or as given when it no longer exists.
fn resolved(folder: &Path) -> std::path::PathBuf {
    folder
        .canonicalize()
        .unwrap_or_else(|_| folder.to_path_buf())
}

fn no_project() -> LpmError {
    LpmError::Env("this directory has no env project".to_owned())
}

fn print_json(value: &serde_json::Value) {
    println!(
        "{}",
        serde_json::to_string_pretty(value).expect("a JSON value serializes")
    );
}
