use lpm_common::LpmError;
use std::path::{Path, PathBuf};

#[allow(clippy::too_many_arguments)]
pub fn run(
    project: Option<&Path>,
    metadata_dirs: &[PathBuf],
    tools: &[PathBuf],
    user_sid: Option<&str>,
    apply: bool,
    remove: bool,
    yes: bool,
    json: bool,
) -> Result<(), LpmError> {
    #[cfg(not(windows))]
    {
        let _ = (project, metadata_dirs, tools, user_sid, yes);
        if apply || remove {
            return Err(LpmError::Script(
                "Sandbox permission setup is available only on Windows.".into(),
            ));
        }
        if json {
            println!(
                "{}",
                serde_json::to_string_pretty(
                    &serde_json::json!({"success": true, "supported": false, "operation": "preview", "grants": [], "count": 0})
                )?
            );
        } else {
            println!(
                "This sandbox permission setup is for Windows. No setup is needed on this platform."
            );
        }
        Ok(())
    }
    #[cfg(windows)]
    {
        use lpm_sandbox::helper_appcontainer::setup;
        use std::io::IsTerminal;
        let cwd = std::env::current_dir().map_err(LpmError::Io)?;
        let project = project.unwrap_or(&cwd);
        let current_user =
            setup::current_user_sid().map_err(|error| LpmError::Script(error.to_string()))?;
        let canonical_project = setup::canonical_directory(project)
            .map_err(|error| LpmError::Script(error.to_string()))?;
        let mut roots = metadata_dirs
            .iter()
            .map(|path| {
                setup::canonical_directory(path)
                    .map_err(|error| LpmError::Script(error.to_string()))
            })
            .collect::<Result<Vec<_>, _>>()?;
        if user_sid.is_none_or(|sid| sid == current_user) {
            roots.push(std::env::temp_dir());
        }
        roots.sort();
        roots.dedup();
        roots.retain(|root| root != &canonical_project);
        roots.insert(0, canonical_project);
        let mut plan = setup::preview_paths(&roots, tools, user_sid)
            .map_err(|error| LpmError::Script(error.to_string()))?;
        let operation = if remove {
            "remove"
        } else if apply {
            "apply"
        } else {
            "preview"
        };
        if !json {
            println!("Windows sandbox permissions for {}:", plan.user_sid);
            for grant in &plan.grants {
                let permission = match grant.permission {
                    setup::Permission::Metadata => "directory metadata and traversal only",
                    setup::Permission::ToolReadExecute => {
                        "tool tree read/execute, excluding links; no writes"
                    }
                };
                println!(
                    "  {}: {permission} ({})",
                    grant.path.display(),
                    if grant.configured {
                        "configured"
                    } else {
                        "not configured"
                    }
                );
            }
        }
        if apply || remove {
            if !setup::is_elevated().map_err(|error| LpmError::Script(error.to_string()))? {
                return Err(LpmError::Script("Open an administrator terminal to apply or remove permissions. Keep publishing in your normal terminal.".into()));
            }
            if !yes {
                if json || !std::io::stdin().is_terminal() {
                    return Err(LpmError::Script("Review the preview, then pass --yes to apply or remove sandbox permissions in a non-interactive session.".into()));
                }
                if !cliclack::confirm(if remove {
                    "Remove these sandbox permissions?"
                } else {
                    "Apply these sandbox permissions?"
                })
                .interact()
                .map_err(LpmError::Io)?
                {
                    return Ok(());
                }
            }
            setup::apply(&plan, remove).map_err(|error| LpmError::Script(error.to_string()))?;
            plan = setup::preview_paths(&roots, tools, Some(&plan.user_sid))
                .map_err(|error| LpmError::Script(error.to_string()))?;
            if apply && plan.grants.iter().any(|grant| !grant.configured) {
                return Err(LpmError::Script("The selected grants are not all usable after setup. Existing deny rules or directory changes may prevent access. Preview again and review the affected paths; existing restrictions were preserved.".into()));
            }
        }
        let mut apply_args = vec![
            "doctor".to_owned(),
            "sandbox-setup".to_owned(),
            "--project".to_owned(),
            roots[0].display().to_string(),
        ];
        for root in roots.iter().skip(1) {
            apply_args.extend(["--metadata-dir".to_owned(), root.display().to_string()]);
        }
        for grant in &plan.grants {
            if grant.permission != setup::Permission::ToolReadExecute {
                continue;
            }
            apply_args.extend(["--tool-dir".to_owned(), grant.path.display().to_string()]);
        }
        apply_args.extend([
            "--user-sid".to_owned(),
            plan.user_sid.clone(),
            "--apply".to_owned(),
        ]);
        if json {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "success": true, "supported": true, "operation": operation,
                    "user_sid": plan.user_sid,
                    "grants": plan.grants.iter().map(|grant| serde_json::json!({
                        "path": grant.path, "permission": grant.permission, "configured": grant.configured
                    })).collect::<Vec<_>>(),
                    "count": plan.grants.len(),
                    "apply_args": apply_args
                }))?
            );
        } else if apply || remove {
            println!(
                "Sandbox permissions {operation} completed. Run publishing from your normal terminal."
            );
        } else {
            println!(
                "Preview only. Review these permissions, then run this command in an administrator PowerShell terminal:"
            );
            println!(
                "lpm {}",
                apply_args
                    .iter()
                    .map(|value| format!("'{}'", value.replace('\'', "''")))
                    .collect::<Vec<_>>()
                    .join(" ")
            );
            println!(
                "The command preserves your Windows user and temporary-directory paths. Use --tool-dir for additional protected tools. Replace --apply with --remove to revoke the selected grants; shared ancestor grants can affect other projects."
            );
        }
        Ok(())
    }
}
