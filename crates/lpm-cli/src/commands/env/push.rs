use super::prelude::*;

pub(super) async fn vars_push(
    args: &[&str],
    project_dir: &std::path::Path,
    json_output: bool,
) -> Result<(), LpmError> {
    // Route to platform push if --to flag is present
    if args.iter().any(|a| a.starts_with("--to")) {
        return super::platform::vars_platform_push(&args[1..], project_dir, json_output).await;
    }

    let force = args.contains(&"--force");
    let yes = args.iter().any(|a| *a == "--yes" || *a == "-y");
    let vault_id = lpm_vault::vault_id::read_vault_id(project_dir)
        .ok_or_else(|| LpmError::Script("no vault configured. Run `lpm env set` first".into()))?;

    let all_envs = lpm_vault::try_get_all_environments(project_dir).map_err(LpmError::Script)?;
    let total_keys: usize = all_envs.values().map(|e| e.len()).sum();
    if total_keys == 0 {
        return Err(LpmError::Script("vault is empty, nothing to push".into()));
    }

    let config = super::sync_payload::read_lpm_json_for_push(project_dir)?;
    let empty_env_map = HashMap::new();
    let env_map = config.as_ref().map_or(&empty_env_map, |c| &c.env);
    let environments = config.as_ref().and_then(|c| c.environments.as_ref());
    let non_empty_envs =
        super::sync_payload::build_sync_environments(&all_envs, env_map, environments);

    let secrets_for_sync: HashMap<String, HashMap<String, HashMap<String, String>>> = {
        let mut wrapper = HashMap::new();
        wrapper.insert("environments".to_string(), non_empty_envs.clone());
        wrapper
    };

    let project_name = lpm_vault::vault_id::read_project_name(project_dir);

    // Confirmation prompt
    if !yes && !json_output {
        output::warn("this will overwrite the cloud vault with your local secrets");
        output::field("project", &project_name);
        output::field("environments", &format!("{}", all_envs.len()));
        output::field("total keys", &format!("{}", total_keys));
        if force {
            output::field("mode", "force (overwrite regardless of version)");
        }
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
        output::info("pushing vault to cloud...");
    }

    let secrets_json = serde_json::to_string(&secrets_for_sync)
        .map_err(|e| LpmError::Script(format!("failed to serialize: {e}")))?;

    let schema_value = super::sync_payload::build_push_schema_value(config.as_ref());

    let push_metadata = lpm_vault::sync::PushMetadata {
        name: Some(&project_name),
        schema: schema_value.as_ref(),
    };
    let expected_version = super::sync_payload::expected_personal_sync_version(project_dir, force);

    let result = lpm_vault::sync::push_raw(
        &registry_url,
        &auth_token,
        &vault_id,
        &secrets_json,
        expected_version,
        force,
        Some(&push_metadata),
    )
    .await
    .map_err(LpmError::Script)?;

    if let Some(version) = result.version {
        lpm_vault::vault_id::write_personal_sync_version(project_dir, version)
            .map_err(LpmError::Script)?;
    }

    if json_output {
        super::response::print_json_value(&serde_json::json!({
            "success": true,
            "status": result.status,
            "version": result.version,
        }));
    } else {
        output::success_line(crate::install_ui::terminal_line!(
            "vault synced (version {})",
            install_ui::bold(&result.version.unwrap_or(0).to_string())
        ));
    }
    Ok(())
}
