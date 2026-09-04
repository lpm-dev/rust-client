use super::prelude::*;

#[derive(Clone, Copy)]
enum PullTarget<'a> {
    Personal,
    Organization(&'a str),
    Platform,
    Oidc,
}

fn parse_pull_target<'a>(args: &'a [&str]) -> Result<PullTarget<'a>, LpmError> {
    const USAGE: &str =
        "usage: lpm env pull [--yes] [--org <org-slug> | --from <platform> | --oidc]";

    let command_args = args.get(1..).unwrap_or_default();
    let platform_selected = command_args
        .iter()
        .any(|argument| *argument == "--from" || argument.starts_with("--from="));
    let oidc_selected = command_args.contains(&"--oidc");
    let org_selected = command_args
        .iter()
        .any(|argument| *argument == "--org" || argument.starts_with("--org="));

    if usize::from(platform_selected) + usize::from(oidc_selected) + usize::from(org_selected) > 1 {
        return Err(LpmError::Script(USAGE.into()));
    }
    if platform_selected {
        return Ok(PullTarget::Platform);
    }
    if oidc_selected {
        return Ok(PullTarget::Oidc);
    }

    let mut org_slug = None;
    let mut index = 0;
    while index < command_args.len() {
        let argument = command_args[index];
        if matches!(argument, "--yes" | "-y") {
        } else if argument == "--org" {
            index += 1;
            let slug =
                super::remote::parse_org_slug_value(command_args.get(index).copied(), USAGE)?;
            if org_slug.replace(slug).is_some() {
                return Err(LpmError::Script(USAGE.into()));
            }
        } else if let Some(slug) = argument.strip_prefix("--org=") {
            let slug = super::remote::parse_org_slug_value(Some(slug), USAGE)?;
            if org_slug.replace(slug).is_some() {
                return Err(LpmError::Script(USAGE.into()));
            }
        } else {
            return Err(LpmError::Script(format!(
                "unknown pull argument: {argument}"
            )));
        }
        index += 1;
    }

    Ok(org_slug.map_or(PullTarget::Personal, PullTarget::Organization))
}

pub(super) async fn vars_pull(
    client: &lpm_registry::RegistryClient,
    args: &[&str],
    project_dir: &std::path::Path,
    json_output: bool,
) -> Result<(), LpmError> {
    let target = parse_pull_target(args)?;
    if matches!(target, PullTarget::Platform) {
        return super::platform::vars_platform_pull(client, &args[1..], project_dir, json_output)
            .await;
    }
    if matches!(target, PullTarget::Oidc) {
        return super::oidc::vars_oidc_pull(client, &args[1..], project_dir, json_output).await;
    }

    let yes = args.iter().any(|a| *a == "--yes" || *a == "-y");
    let org_flag = match target {
        PullTarget::Organization(slug) => Some(slug),
        PullTarget::Personal => None,
        PullTarget::Platform | PullTarget::Oidc => unreachable!("delegated pull target"),
    };

    let manifest = super::sync_payload::CloudManifestSnapshot::read(project_dir)?;
    let vault_id = match manifest.vault.vault_id().map_err(LpmError::Script)? {
        Some(vault_id) => vault_id.to_owned(),
        None => {
            lpm_vault::vault_id::get_or_create_vault_id(project_dir).map_err(LpmError::Script)?
        }
    };

    // Org pull: different flow with X25519 decryption
    if let Some(org_slug) = org_flag {
        if !json_output {
            output::info_line(crate::install_ui::terminal_line!(
                "pulling vault from org {}...",
                install_ui::bold(org_slug)
            ));
        }

        let baseline_environments = lpm_vault::try_get_all_environments_for_vault_id(&vault_id)
            .map_err(LpmError::Script)?;
        let expected_principal_id = manifest
            .vault
            .org_sync_principal_for_registry(org_slug, client.base_url())
            .map_err(LpmError::Script)?;

        let (pulled, registry_url) = super::rotation::pull_org_with_local_key_first(
            client,
            org_slug,
            &vault_id,
            "pull",
            expected_principal_id.as_deref(),
        )
        .await?;

        let remote_environments =
            super::sync_payload::parse_remote_pull_payload_for_overwrite(&pulled.raw_json)
                .map_err(LpmError::Script)?;
        let target = lpm_vault::RemoteSyncTarget::Organization {
            slug: org_slug.to_owned(),
        };
        let committed = lpm_vault::commit_remote_environments_for_principal(
            project_dir,
            &vault_id,
            &baseline_environments,
            remote_environments,
            &target,
            pulled.version,
            lpm_vault::vault_id::SyncPrincipal {
                registry_url: &registry_url,
                principal_id: &pulled.principal_id,
            },
        )
        .map_err(LpmError::Script)?;
        let committed_environments = match committed {
            lpm_vault::RemoteEnvironmentCommit::Committed(environments) => environments,
            lpm_vault::RemoteEnvironmentCommit::Conflict(_) => {
                return Err(LpmError::Script(
                    "local secrets changed while the organization vault was downloading; no remote changes were applied. Review the local values and retry."
                        .into(),
                ));
            }
        };
        let total_keys = committed_environments
            .values()
            .map(|env| env.len())
            .sum::<usize>();

        if json_output {
            super::response::print_json_value(&serde_json::json!({
                "success": true,
                "status": "pulled",
                "org": org_slug,
                "version": pulled.version,
                "content_key_version": pulled.content_key_version,
                "count": total_keys,
            }));
        } else {
            output::success_line(crate::install_ui::terminal_line!(
                "pulled {} key{} from org {} (version {})",
                install_ui::bold(&total_keys.to_string()),
                if total_keys == 1 { "" } else { "s" },
                install_ui::bold(org_slug),
                install_ui::bold(&pulled.version.to_string())
            ));
        }
        return Ok(());
    }

    let project_name = manifest.vault.project_name(project_dir);
    let baseline_environments =
        lpm_vault::try_get_all_environments_for_vault_id(&vault_id).map_err(LpmError::Script)?;
    let local_key_count = baseline_environments
        .values()
        .map(|env| env.len())
        .sum::<usize>();

    // Confirmation prompt
    if !yes && !json_output {
        output::warn("this will overwrite your local secrets with the cloud vault");
        output::field("project", &project_name);
        output::field("local keys", &format!("{local_key_count}"));
        let confirm = cliclack::confirm("Continue?")
            .initial_value(false)
            .interact()
            .map_err(|e| LpmError::Script(format!("prompt failed: {e}")))?;
        if !confirm {
            output::info("cancelled");
            return Ok(());
        }
    }

    if !json_output {
        output::info("pulling vault from cloud...");
    }
    let expected_principal_id = manifest
        .vault
        .personal_sync_principal_for_registry(client.base_url())
        .map_err(LpmError::Script)?;

    let (pulled, registry_url) = super::auth::execute_sync_with_bearer(
        client,
        lpm_auth::AuthRequirement::TokenRequired,
        |registry_url, auth_token| {
            let vault_id = vault_id.clone();
            let expected_principal_id = expected_principal_id.clone();
            async move {
                let pulled = lpm_vault::sync::pull_raw_bound_to_principal(
                    &registry_url,
                    &auth_token,
                    &vault_id,
                    expected_principal_id.as_deref(),
                )
                .await?;
                Ok((pulled, registry_url))
            }
        },
    )
    .await?;

    let remote_envs =
        super::sync_payload::parse_remote_pull_payload_for_overwrite(&pulled.raw_json)
            .map_err(LpmError::Script)?;
    let committed = lpm_vault::commit_remote_environments_for_principal(
        project_dir,
        &vault_id,
        &baseline_environments,
        remote_envs,
        &lpm_vault::RemoteSyncTarget::Personal,
        pulled.version,
        lpm_vault::vault_id::SyncPrincipal {
            registry_url: &registry_url,
            principal_id: &pulled.principal_id,
        },
    )
    .map_err(LpmError::Script)?;
    let committed_environments = match committed {
        lpm_vault::RemoteEnvironmentCommit::Committed(environments) => environments,
        lpm_vault::RemoteEnvironmentCommit::Conflict(_) => {
            return Err(LpmError::Script(
                "local secrets changed while the cloud vault was downloading; no remote changes were applied. Review the local values and retry."
                    .into(),
            ));
        }
    };
    let total_keys = committed_environments
        .values()
        .map(|env| env.len())
        .sum::<usize>();

    if json_output {
        super::response::print_json_value(&serde_json::json!({
            "success": true,
            "status": "pulled",
            "version": pulled.version,
            "count": total_keys,
        }));
    } else {
        output::success_line(crate::install_ui::terminal_line!(
            "pulled {} key{} (version {})",
            install_ui::bold(&total_keys.to_string()),
            if total_keys == 1 { "" } else { "s" },
            install_ui::bold(&pulled.version.to_string())
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pull_target_accepts_joined_and_separate_organization_selectors() {
        for args in [
            &["pull", "--org", "acme", "--yes"][..],
            &["pull", "--org=acme", "-y"][..],
        ] {
            let PullTarget::Organization(slug) =
                parse_pull_target(args).expect("organization selector must parse")
            else {
                panic!("organization selector selected another pull target")
            };
            assert_eq!(slug, "acme");
        }
    }

    #[test]
    fn pull_target_rejects_missing_option_like_and_unknown_arguments() {
        for args in [
            &["pull", "--org"][..],
            &["pull", "--org", "--yes"][..],
            &["pull", "--oidc=true"][..],
            &["pull", "--unknown"][..],
        ] {
            assert!(parse_pull_target(args).is_err(), "accepted {args:?}");
        }
    }

    #[test]
    fn pull_target_rejects_conflicting_scope_selectors() {
        for args in [
            &["pull", "--org=acme", "--oidc"][..],
            &["pull", "--org", "acme", "--from=vercel"][..],
            &["pull", "--oidc", "--from", "vercel"][..],
        ] {
            assert!(parse_pull_target(args).is_err(), "accepted {args:?}");
        }
    }
}
