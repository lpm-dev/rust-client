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
    match lpm_vault::folder_link(project_dir).map_err(vault_error)? {
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
    match lpm_vault::folder_link_for_vault_id(project_dir, vault_id).map_err(vault_error)? {
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
    lpm_vault::link_folder_to_vault_id(project_dir, &unlinked.vault_id)
        .map(drop)
        .map_err(vault_error)
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
    let link = match lpm_vault::folder_link_for_vault_id(project_dir, &vault_id) {
        Ok(link) => link,
        Err(reason) if lpm_vault::folder_links_are_damaged(&reason) => {
            confirm_link(yes, json_output, &reason, "Replace them with this folder?")?;
            lpm_vault::replace_damaged_folder_links(project_dir, &vault_id).map_err(vault_error)?;
            report_link(project_dir, &vault_id, true, json_output);
            return Ok(());
        }
        Err(reason) => return Err(vault_error(reason)),
    };
    if let FolderLink::Unlinked(unlinked) = &link
        && !yes
    {
        confirm_link(yes, json_output, &describe(unlinked), "Link this folder?")?;
    }
    let added = lpm_vault::link_folder_to_vault_id(project_dir, &vault_id).map_err(vault_error)?;
    report_link(project_dir, &vault_id, added, json_output);
    Ok(())
}

/// Asks before a folder is linked, unless `yes`; without a terminal, or
/// with `--json`, it needs `yes`.
fn confirm_link(
    yes: bool,
    json_output: bool,
    warning: &str,
    question: &str,
) -> Result<(), LpmError> {
    if yes {
        return Ok(());
    }
    if json_output || !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
        return Err(LpmError::Env(
            "linking a folder asks first; pass --yes to link it without asking".to_owned(),
        ));
    }
    output::warn(warning);
    let confirmed = cliclack::confirm(question)
        .initial_value(false)
        .interact()
        .map_err(|error| LpmError::Env(format!("prompt failed: {error}")))?;
    if confirmed {
        Ok(())
    } else {
        Err(LpmError::ExitCode(1))
    }
}

fn report_link(project_dir: &Path, vault_id: &str, added: bool, json_output: bool) {
    let folder = resolved(project_dir);
    if json_output {
        print_json(&serde_json::json!({
            "success": true,
            "vault_id": vault_id,
            "folder": folder,
            "already_linked": !added,
        }));
    } else if added {
        output::success(&format!("Linked {}", shown(&folder)));
    } else {
        output::success(&format!("{} is already linked", shown(&folder)));
    }
}

/// An error from the vault's links: an env project's refusal as itself, so
/// it keeps its code, anything else as an env error.
fn vault_error(reason: String) -> LpmError {
    lpm_runner::dotenv::vault_error(LpmError::Env)(reason)
}

pub(super) fn env_unlink(
    project_dir: &Path,
    folder: Option<&Path>,
    json_output: bool,
) -> Result<(), LpmError> {
    // A folder to unlink is usually another checkout, outside this project,
    // so a relative one is taken from where the command runs, as a shell
    // takes it.
    let folder = match folder {
        Some(folder) => std::env::current_dir().map_err(LpmError::Io)?.join(folder),
        None => project_dir.to_path_buf(),
    };
    let (vault_id, removed) = lpm_vault::unlink_folder(project_dir, &folder)
        .map_err(vault_error)?
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
        output::success(&format!("Unlinked {}", shown(&folder)));
    } else {
        output::info(&format!(
            "{} wasn't linked; `lpm env links` lists the linked folders",
            shown(&folder)
        ));
    }
    Ok(())
}

pub(super) fn env_links(project_dir: &Path, json_output: bool) -> Result<(), LpmError> {
    let lpm_vault::LinkedFolders {
        vault_id,
        folders,
        this_folder_linked,
    } = lpm_vault::linked_folders(project_dir)
        .map_err(vault_error)?
        .ok_or_else(no_project)?;
    // A link names a path, so a folder deleted since is marked for unlinking.
    let missing: Vec<&std::path::PathBuf> =
        folders.iter().filter(|folder| !folder.exists()).collect();
    if json_output {
        print_json(&serde_json::json!({
            "success": true,
            "vault_id": vault_id,
            "folders": folders,
            "missing_folders": missing,
            "this_folder_linked": this_folder_linked,
        }));
        return Ok(());
    }
    if folders.is_empty() {
        output::info(if this_folder_linked {
            "No folder on this machine is linked to this env project yet. It holds no values \
             here, so the first folder to store one is linked."
        } else {
            "No folder on this machine is linked to this env project."
        });
        return Ok(());
    }
    let current = resolved(project_dir);
    for folder in &folders {
        let marker = if *folder == current {
            " (this folder)"
        } else if missing.contains(&folder) {
            " (missing: unlink it with `lpm env unlink <folder>`)"
        } else {
            ""
        };
        println!("{}{marker}", shown(folder));
    }
    Ok(())
}

fn shown(folder: &Path) -> String {
    lpm_common::sanitize_terminal_inline(&folder.display().to_string()).into_owned()
}

/// `folder` as a link names it, or as an absolute path when it no longer
/// exists.
fn resolved(folder: &Path) -> std::path::PathBuf {
    folder
        .canonicalize()
        .or_else(|_| std::path::absolute(folder))
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
