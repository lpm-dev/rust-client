use super::prelude::*;

enum PushTarget {
    Personal,
    Platform,
}

fn parse_push_target(args: &[&str]) -> Result<PushTarget, LpmError> {
    const PLATFORM_USAGE: &str = "usage: lpm env push --to <platform> [--org <org-slug>] [--env <environment>] [--clean] [--yes]";
    let command_args = args.get(1..).unwrap_or_default();
    let platform_selected = command_args
        .iter()
        .any(|argument| *argument == "--to" || argument.starts_with("--to="));
    if platform_selected {
        super::platform::validate_platform_push_arguments(command_args, PLATFORM_USAGE)?;
        if command_args
            .iter()
            .any(|argument| *argument == "--oidc" || argument.starts_with("--from"))
        {
            return Err(LpmError::Script(
                "platform push cannot be combined with another cloud scope selector".into(),
            ));
        }
        return Ok(PushTarget::Platform);
    }

    for argument in command_args {
        if !matches!(*argument, "--force" | "--yes" | "-y") {
            return Err(LpmError::Script(format!(
                "unknown push argument: {argument}"
            )));
        }
    }
    Ok(PushTarget::Personal)
}

pub(super) async fn vars_push(
    client: &lpm_registry::RegistryClient,
    args: &[&str],
    project_dir: &std::path::Path,
    json_output: bool,
) -> Result<(), LpmError> {
    if matches!(parse_push_target(args)?, PushTarget::Platform) {
        return super::platform::vars_platform_push(client, &args[1..], project_dir, json_output)
            .await;
    }

    let force = args.contains(&"--force");
    let yes = args.iter().any(|a| *a == "--yes" || *a == "-y");
    let manifest = super::sync_payload::CloudManifestSnapshot::read(project_dir)?;
    let vault_id = manifest
        .vault
        .vault_id()
        .map_err(LpmError::Script)?
        .map(str::to_owned)
        .ok_or_else(|| LpmError::Script("no vault configured. Run `lpm env set` first".into()))?;

    let all_envs =
        lpm_vault::try_get_all_environments_for_vault_id(&vault_id).map_err(LpmError::Script)?;
    let environment_count = all_envs.len();
    let total_keys: usize = all_envs.values().map(|e| e.len()).sum();
    if total_keys == 0 {
        return Err(LpmError::Script("vault is empty, nothing to push".into()));
    }

    let config = manifest.config;
    let non_empty_envs = super::sync_payload::build_sync_environments(all_envs);

    let project_name = manifest.vault.project_name(project_dir);
    let expected_principal_id = manifest
        .vault
        .personal_expected_principal_for_registry(client.base_url())
        .map_err(LpmError::Script)?;

    // Confirmation prompt
    if !yes && !json_output {
        output::warn("this will overwrite the cloud vault with your local secrets");
        output::field("project", &project_name);
        output::field("environments", &format!("{environment_count}"));
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

    if !json_output {
        output::info("pushing vault to cloud...");
    }

    let secrets_json = std::sync::Arc::new({
        let mut wrapper = HashMap::new();
        wrapper.insert("environments".to_string(), non_empty_envs);
        serde_json::to_string(&wrapper)
            .map_err(|e| LpmError::Script(format!("failed to serialize: {e}")))?
    });

    let schema_value = std::sync::Arc::new(super::sync_payload::build_push_schema_value(
        config.as_ref(),
    ));
    drop(config);

    let project_dir = project_dir.to_path_buf();
    let (result, registry_url) = super::auth::execute_sync_with_bearer(
        client,
        |registry_url, auth_token| {
            let project_name = project_name.clone();
            let schema_value = std::sync::Arc::clone(&schema_value);
            let vault_id = vault_id.clone();
            let secrets_json = std::sync::Arc::clone(&secrets_json);
            let project_dir = project_dir.clone();
            let expected_principal_id = expected_principal_id.clone();
            async move {
                let current_manifest = super::sync_payload::fresh_personal_mutation_manifest(
                    &project_dir,
                    &vault_id,
                    &registry_url,
                    expected_principal_id.as_deref(),
                )?;
                let sync_principal_id = current_manifest
                    .personal_sync_principal_for_registry(&registry_url)?;
                let expected_version = if let Some(sync_principal_id) = sync_principal_id.as_deref() {
                    Some(
                        current_manifest
                            .personal_sync_version_for_principal(
                            lpm_vault::vault_id::SyncPrincipal {
                                registry_url: &registry_url,
                                principal_id: sync_principal_id,
                            },
                        )
                            .ok_or_else(|| {
                            lpm_vault::sync::SyncError::from(
                                "this checkout has no durable revision checkpoint for the bound personal cloud vault; pull it before pushing, or use a new vault ID if the remote was deleted before revision floors were recorded",
                            )
                        })?,
                    )
                } else {
                    None
                };
                let push_metadata = lpm_vault::sync::PushMetadata {
                    name: Some(&project_name),
                    schema: schema_value.as_ref().as_ref(),
                };
                let result = lpm_vault::sync::push_raw_with_options(
                    &registry_url,
                    &auth_token,
                    &vault_id,
                    secrets_json.as_str(),
                    lpm_vault::sync::PersonalPushOptions {
                        expected_version,
                        expected_principal_id: expected_principal_id.as_deref(),
                        force,
                        metadata: Some(&push_metadata),
                    },
                )
                .await?;
                if expected_principal_id
                    .as_deref()
                    .is_some_and(|expected| result.principal_id.as_deref() != Some(expected))
                {
                    return Err(lpm_vault::sync::SyncError::from(
                        "personal cloud vault principal changed during push",
                    ));
                }
                Ok((result, registry_url))
            }
        },
    )
    .await?;

    if let Some(version) = result.version {
        let principal_id = result
            .principal_id
            .as_deref()
            .ok_or_else(|| LpmError::Script("sync response omitted the principal ID".into()))?;
        super::sync_payload::persist_personal_sync_version(
            &project_dir,
            &vault_id,
            version,
            &registry_url,
            principal_id,
        )?;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn personal_push_rejects_organization_and_unknown_arguments() {
        for args in [
            &["push", "--org", "acme", "--yes"][..],
            &["push", "--org=acme"][..],
            &["push", "--unknown"][..],
        ] {
            assert!(parse_push_target(args).is_err(), "accepted {args:?}");
        }
    }

    #[test]
    fn push_rejects_conflicting_platform_scope_selectors() {
        for args in [
            &["push", "--to", "vercel", "--oidc"][..],
            &["push", "--to", "vercel", "--orgg", "acme", "--yes"][..],
            &["push", "--to", "vercel", "stray"][..],
            &["push", "--to", "vercel", "--to", "railway"][..],
        ] {
            assert!(parse_push_target(args).is_err(), "accepted {args:?}");
        }
    }

    #[test]
    fn platform_push_accepts_an_explicit_organization_scope() {
        let target = parse_push_target(&["push", "--to=vercel", "--org=acme"])
            .expect("platform organization scope should parse");

        assert!(matches!(target, PushTarget::Platform));
    }
}
