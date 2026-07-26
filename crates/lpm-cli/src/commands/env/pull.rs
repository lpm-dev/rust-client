use super::prelude::*;

pub(super) async fn vars_pull(
    args: &[&str],
    project_dir: &std::path::Path,
    json_output: bool,
) -> Result<(), LpmError> {
    lpm_runner::lpm_json::read_lpm_json(project_dir).map_err(LpmError::Script)?;

    // Route to platform pull if --from flag is present
    if args.iter().any(|a| a.starts_with("--from")) {
        return super::platform::vars_platform_pull(&args[1..], project_dir, json_output).await;
    }

    // Route to OIDC pull if --oidc flag is present
    if args.contains(&"--oidc") {
        return super::oidc::vars_oidc_pull(&args[1..], project_dir, json_output).await;
    }

    let yes = args.iter().any(|a| *a == "--yes" || *a == "-y");
    let org_flag = args
        .iter()
        .position(|a| *a == "--org")
        .and_then(|i| args.get(i + 1).copied());

    let vault_id =
        lpm_vault::vault_id::get_or_create_vault_id(project_dir).map_err(LpmError::Script)?;

    // Org pull: different flow with X25519 decryption
    if let Some(org_slug) = org_flag {
        let registry_url = lpm_common::resolve_lpm_registry_url();
        let auth_token = super::auth::resolve_lpm_bearer(&registry_url, json_output).await?;

        // Classify the sharing-key state before fetching the
        // wrapped vault. RotationRequired refuses silent
        // overwrite and routes the user to
        // `lpm env rotate-sharing-key`; NeedsInitialSet prompts
        // for step-up reauth and registers the local key.
        let private_key = super::rotation::ensure_sharing_key_ready_for_org_op(
            &registry_url,
            &auth_token,
            "pull",
        )
        .await?;

        if !json_output {
            output::info_line(crate::install_ui::terminal_line!(
                "pulling vault from org {}...",
                install_ui::bold(org_slug)
            ));
        }

        let (raw_json, version) = lpm_vault::sync::pull_org(
            &registry_url,
            &auth_token,
            org_slug,
            &vault_id,
            &private_key,
        )
        .await
        .map_err(LpmError::Script)?;

        // Same merge logic as personal pull
        let total_keys;
        if let Ok(wrapper) = serde_json::from_str::<
            std::collections::HashMap<
                String,
                std::collections::HashMap<String, std::collections::HashMap<String, String>>,
            >,
        >(&raw_json)
        {
            if let Some(remote_envs) = wrapper.get("environments") {
                let mut total = 0;
                for (env_name, remote_secrets) in remote_envs {
                    let mut env = lpm_vault::try_get_all_env(project_dir, env_name)
                        .map_err(LpmError::Script)?;
                    env.extend(remote_secrets.clone());
                    total += env.len();
                    let pairs: Vec<(&str, &str)> =
                        env.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
                    lpm_vault::set_env(project_dir, env_name, &pairs).map_err(LpmError::Script)?;
                }
                total_keys = total;
            } else {
                total_keys = 0;
            }
        } else if let Ok(remote_secrets) =
            serde_json::from_str::<std::collections::HashMap<String, String>>(&raw_json)
        {
            let mut merged = lpm_vault::try_get_all(project_dir).map_err(LpmError::Script)?;
            merged.extend(remote_secrets);
            total_keys = merged.len();
            let pairs: Vec<(&str, &str)> = merged
                .iter()
                .map(|(k, v)| (k.as_str(), v.as_str()))
                .collect();
            lpm_vault::set(project_dir, &pairs).map_err(LpmError::Script)?;
        } else {
            return Err(LpmError::Script("failed to parse pulled vault data".into()));
        }

        lpm_vault::vault_id::write_org_sync_version(project_dir, org_slug, version)
            .map_err(LpmError::Script)?;

        if json_output {
            super::response::print_json_value(&serde_json::json!({
                "success": true,
                "status": "pulled",
                "org": org_slug,
                "version": version,
                "count": total_keys,
            }));
        } else {
            output::success_line(crate::install_ui::terminal_line!(
                "pulled {} key{} from org {} (version {})",
                install_ui::bold(&total_keys.to_string()),
                if total_keys == 1 { "" } else { "s" },
                install_ui::bold(org_slug),
                install_ui::bold(&version.to_string())
            ));
        }
        return Ok(());
    }

    let project_name = lpm_vault::vault_id::read_project_name(project_dir);
    let local_secrets = lpm_vault::try_get_all(project_dir).map_err(LpmError::Script)?;

    // Confirmation prompt
    if !yes && !json_output {
        output::warn("this will overwrite your local secrets with the cloud vault");
        output::field("project", &project_name);
        output::field("local keys", &format!("{}", local_secrets.len()));
        let confirm = cliclack::confirm("Continue?")
            .initial_value(false)
            .interact()
            .map_err(|e| LpmError::Script(format!("prompt failed: {e}")))?;
        if !confirm {
            output::info("cancelled");
            return Ok(());
        }
    }

    let registry_url = lpm_common::resolve_lpm_registry_url();
    let auth_token = super::auth::resolve_lpm_bearer(&registry_url, json_output).await?;

    if !json_output {
        output::info("pulling vault from cloud...");
    }

    let (raw_json, version) = lpm_vault::sync::pull_raw(&registry_url, &auth_token, &vault_id)
        .await
        .map_err(LpmError::Script)?;

    let remote_envs = super::sync_payload::parse_remote_pull_payload_for_overwrite(&raw_json)
        .map_err(LpmError::Script)?;
    let total_keys: usize = remote_envs.values().map(|env| env.len()).sum();
    lpm_vault::replace_all_environments(project_dir, &remote_envs).map_err(LpmError::Script)?;

    lpm_vault::vault_id::write_personal_sync_version(project_dir, version)
        .map_err(LpmError::Script)?;

    if json_output {
        super::response::print_json_value(&serde_json::json!({
            "success": true,
            "status": "pulled",
            "version": version,
            "count": total_keys,
        }));
    } else {
        output::success_line(crate::install_ui::terminal_line!(
            "pulled {} key{} (version {})",
            install_ui::bold(&total_keys.to_string()),
            if total_keys == 1 { "" } else { "s" },
            install_ui::bold(&version.to_string())
        ));
    }
    Ok(())
}
