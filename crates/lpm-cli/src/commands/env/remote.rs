use super::prelude::*;

pub(super) async fn env_log(
    project_dir: &std::path::Path,
    json_output: bool,
) -> Result<(), LpmError> {
    let vault_id = lpm_vault::vault_id::read_vault_id(project_dir)
        .ok_or_else(|| LpmError::Script("no vault configured".into()))?;

    let registry_url = lpm_common::resolve_lpm_registry_url();
    let auth_token = super::auth::resolve_lpm_bearer(&registry_url, json_output).await?;

    let result = lpm_vault::sync::get_audit_log(&registry_url, &auth_token, &vault_id, None)
        .await
        .map_err(LpmError::Script)?;

    let entries = result.entries.unwrap_or_default();

    if json_output {
        super::response::print_json_value(&serde_json::json!({
            "success": true,
            "count": entries.len(),
            "entries": entries.iter().map(|e| serde_json::json!({
                "action": e.action,
                "created_at": e.created_at,
            })).collect::<Vec<_>>(),
        }));
    } else if entries.is_empty() {
        output::info("No audit log entries");
    } else {
        output::info(&format!("Vault audit log ({} entries)", entries.len()));
        for entry in &entries {
            println!(
                "{}",
                install_ui::terminal_line!(
                    "  {} {} {}",
                    install_ui::dim(&entry.created_at),
                    install_ui::bold(&entry.action),
                    install_ui::dim(entry.user_id.as_deref().unwrap_or("")),
                )
            );
        }
    }
    Ok(())
}

pub(super) async fn env_share(
    args: &[&str],
    project_dir: &std::path::Path,
    json_output: bool,
) -> Result<(), LpmError> {
    let org_flag = args
        .iter()
        .position(|a| *a == "--org")
        .and_then(|i| args.get(i + 1).copied());
    let org_slug =
        org_flag.ok_or_else(|| LpmError::Script("usage: lpm env share --org <org-slug>".into()))?;

    // Org share has no force semantics: conflict recovery must start
    // from a pull so the client re-wraps against current server state.
    if args.contains(&"--force") {
        return Err(LpmError::Script(
            "`lpm env share --force` is not supported. To resolve a version conflict run `lpm env pull --org <slug>` first, then retry the share.".into(),
        ));
    }

    let vault_id = lpm_vault::vault_id::read_vault_id(project_dir)
        .ok_or_else(|| LpmError::Script("no vault configured. Run `lpm env set` first".into()))?;

    let all_envs = lpm_vault::try_get_all_environments(project_dir).map_err(LpmError::Script)?;
    let total_keys: usize = all_envs.values().map(|e| e.len()).sum();
    if total_keys == 0 {
        return Err(LpmError::Script("vault is empty, nothing to share".into()));
    }

    let registry_url = lpm_common::resolve_lpm_registry_url();
    let auth_token = super::auth::resolve_lpm_bearer(&registry_url, json_output).await?;

    // Classify the sharing-key state before any wrap work. This
    // refuses the silent-overwrite path on RotationRequired and
    // prompts for step-up reauth on NeedsInitialSet, instead of
    // letting `push_org_with_keys`'s internal `ensure_public_key`
    // silently upload over whatever was on the server.
    super::rotation::ensure_sharing_key_ready_for_org_op(&registry_url, &auth_token, "share")
        .await?;

    let config = super::sync_payload::read_lpm_json_for_push(project_dir);
    let empty_env_map = HashMap::new();
    let env_map = config.as_ref().map_or(&empty_env_map, |c| &c.env);
    let environments = config.as_ref().and_then(|c| c.environments.as_ref());
    let non_empty_envs =
        super::sync_payload::build_sync_environments(&all_envs, env_map, environments);
    let mut wrapper = std::collections::HashMap::new();
    wrapper.insert("environments".to_string(), non_empty_envs);
    let secrets_json = serde_json::to_string(&wrapper)
        .map_err(|e| LpmError::Script(format!("failed to serialize: {e}")))?;

    let project_name = lpm_vault::vault_id::read_project_name(project_dir);
    let schema_value = super::sync_payload::build_push_schema_value(config.as_ref());
    let push_metadata = lpm_vault::sync::PushMetadata {
        name: Some(&project_name),
        schema: schema_value.as_ref(),
    };

    if !json_output {
        output::info_line(install_ui::terminal_line!(
            "sharing vault with org {} ({} keys across {} environments)...",
            install_ui::bold(org_slug),
            total_keys,
            all_envs.len(),
        ));
    }

    let result = lpm_vault::sync::push_org_with_keys(
        &registry_url,
        &auth_token,
        org_slug,
        &vault_id,
        &secrets_json,
        super::sync_payload::expected_org_sync_version(project_dir, org_slug),
        Some(&push_metadata),
    )
    .await
    .map_err(LpmError::Script)?;

    if let Some(version) = result.version {
        lpm_vault::vault_id::write_org_sync_version(project_dir, org_slug, version)
            .map_err(LpmError::Script)?;
    }

    if json_output {
        super::response::print_json_value(&serde_json::json!({
            "success": true,
            "status": result.status,
            "org": org_slug,
            "version": result.version,
        }));
    } else {
        output::success_line(install_ui::terminal_line!(
            "vault shared with org {} (version {})",
            install_ui::bold(org_slug),
            install_ui::bold(&result.version.unwrap_or(0).to_string()),
        ));
    }
    Ok(())
}

/// List cloud vaults — personal or org.
pub(super) async fn vars_list_remote(
    org_slug: Option<&str>,
    json_output: bool,
) -> Result<(), LpmError> {
    let registry_url = lpm_common::resolve_lpm_registry_url();
    let auth_token = super::auth::resolve_lpm_bearer(&registry_url, json_output).await?;

    if let Some(slug) = org_slug {
        // List org vaults
        let vaults = lpm_vault::sync::list_org_vaults(&registry_url, &auth_token, slug)
            .await
            .map_err(LpmError::Script)?;

        if json_output {
            let json: Vec<serde_json::Value> = vaults
                .iter()
                .map(|v| serde_json::json!({"vault_id": v.vault_id, "version": v.version, "updated_at": v.updated_at, "org": slug}))
                .collect();
            super::response::print_json_value(&serde_json::json!({
                "success": true,
                "org": slug,
                "count": json.len(),
                "vaults": json,
            }));
            return Ok(());
        }

        if vaults.is_empty() {
            output::info_line(install_ui::terminal_line!(
                "no shared vaults in org {}",
                install_ui::bold(slug),
            ));
            println!(
                "{}",
                install_ui::terminal_line!(
                    "  Share a vault: {}",
                    install_ui::cyan(&format!("lpm env share --org {slug}")),
                )
            );
            return Ok(());
        }

        output::info_line(install_ui::terminal_line!(
            "Org {} vaults ({})",
            install_ui::bold(slug),
            vaults.len(),
        ));
        for v in &vaults {
            let version = v.version.map_or_else(|| "v?".into(), |v| format!("v{v}"));
            let updated = v.updated_at.as_deref().unwrap_or("?");
            println!(
                "{}",
                install_ui::terminal_line!(
                    "  {} {} {} {}",
                    install_ui::cyan("·"),
                    install_ui::bold(&v.vault_id),
                    install_ui::dim(&version),
                    install_ui::dim(&format!("(updated {updated})")),
                )
            );
        }
        println!();
        println!(
            "{}",
            install_ui::terminal_line!(
                "  Pull: {}",
                install_ui::cyan(&format!("cd <project-dir> && lpm env pull --org {slug}")),
            )
        );
        return Ok(());
    }

    // Personal vaults
    let vaults = lpm_vault::sync::list_remote(&registry_url, &auth_token)
        .await
        .map_err(LpmError::Script)?;

    if json_output {
        let json: Vec<serde_json::Value> = vaults
            .iter()
            .map(|v| {
                serde_json::json!({
                    "vault_id": v.vault_id,
                    "version": v.version,
                    "updated_at": v.updated_at,
                })
            })
            .collect();
        super::response::print_json_value(&serde_json::json!({
            "success": true,
            "count": json.len(),
            "vaults": json,
        }));
        return Ok(());
    }

    if vaults.is_empty() {
        output::info("no cloud vaults found");
        println!("  Push a vault with: {}", "lpm env push".cyan());
        return Ok(());
    }

    output::info(&format!("Cloud vaults ({})", vaults.len()));
    for v in &vaults {
        let version = v.version.map_or_else(|| "v?".into(), |v| format!("v{v}"));
        let updated = v.updated_at.as_deref().unwrap_or("?");
        println!(
            "{}",
            install_ui::terminal_line!(
                "  {} {} {} {}",
                install_ui::cyan("·"),
                install_ui::bold(&v.vault_id),
                install_ui::dim(&version),
                install_ui::dim(&format!("(updated {updated})")),
            )
        );
    }
    println!();
    println!(
        "  Pull a vault: {}",
        "cd <project-dir> && lpm env pull".cyan()
    );

    Ok(())
}

/// Compare vault environments or local vs cloud.
///
/// Usage:
///   lpm env diff                     — local default vs cloud
///   lpm env diff staging             — local staging vs cloud staging
///   lpm env diff staging production  — two local environments
pub(super) async fn vars_diff(
    args: &[&str],
    project_dir: &std::path::Path,
    json_output: bool,
) -> Result<(), LpmError> {
    let config = lpm_runner::lpm_json::read_lpm_json(project_dir)
        .ok()
        .flatten();
    let empty_env_map = std::collections::HashMap::new();
    let env_map = config.as_ref().map_or(&empty_env_map, |c| &c.env);
    let environments = config.as_ref().and_then(|c| c.environments.as_ref());

    let (left_label, left_secrets, right_label, right_secrets) = if args.len() >= 2 {
        // Compare two local environments — resolve aliases to canonical names
        let resolved_a = lpm_env::resolver::resolve(args[0], env_map, environments);
        let resolved_b = lpm_env::resolver::resolve(args[1], env_map, environments);
        let a = lpm_vault::try_get_all_env(project_dir, &resolved_a.storage_key)
            .map_err(LpmError::Script)?;
        let b = lpm_vault::try_get_all_env(project_dir, &resolved_b.storage_key)
            .map_err(LpmError::Script)?;
        (
            format!("{} (local)", resolved_a.canonical),
            a,
            format!("{} (local)", resolved_b.canonical),
            b,
        )
    } else if args.len() == 1 {
        // Compare specific env local vs cloud — fetch the same env from cloud, not "default"
        let resolved = lpm_env::resolver::resolve(args[0], env_map, environments);
        let local = lpm_vault::try_get_all_env(project_dir, &resolved.storage_key)
            .map_err(LpmError::Script)?;

        let vault_id = lpm_vault::vault_id::read_vault_id(project_dir)
            .ok_or_else(|| LpmError::Script("no vault configured".into()))?;
        let registry_url = lpm_common::resolve_lpm_registry_url();
        let auth_token = super::auth::resolve_lpm_bearer(&registry_url, json_output).await?;

        let (remote, _version) =
            lpm_vault::sync::pull_env(&registry_url, &auth_token, &vault_id, &resolved.canonical)
                .await
                .map_err(LpmError::Script)?;

        (
            format!("{} (local)", resolved.canonical),
            local,
            format!("{} (cloud)", resolved.canonical),
            remote,
        )
    } else {
        // Default: local default vs cloud
        let local = lpm_vault::try_get_all(project_dir).map_err(LpmError::Script)?;

        let vault_id = lpm_vault::vault_id::read_vault_id(project_dir)
            .ok_or_else(|| LpmError::Script("no vault configured".into()))?;
        let registry_url = lpm_common::resolve_lpm_registry_url();
        let auth_token = super::auth::resolve_lpm_bearer(&registry_url, json_output).await?;

        let (remote, _version) = lpm_vault::sync::pull(&registry_url, &auth_token, &vault_id)
            .await
            .map_err(LpmError::Script)?;

        (
            "default (local)".into(),
            local,
            "default (cloud)".into(),
            remote,
        )
    };

    // Compute diff
    let mut all_keys: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
    for key in left_secrets.keys() {
        all_keys.insert(key.as_str());
    }
    for key in right_secrets.keys() {
        all_keys.insert(key.as_str());
    }

    let mut added = Vec::new();
    let mut removed = Vec::new();
    let mut changed = Vec::new();
    let mut same = 0u32;

    for key in &all_keys {
        let in_left = left_secrets.get(*key);
        let in_right = right_secrets.get(*key);
        match (in_left, in_right) {
            (Some(_), None) => added.push(*key),
            (None, Some(_)) => removed.push(*key),
            (Some(l), Some(r)) if l != r => changed.push(*key),
            (Some(_), Some(_)) => same += 1,
            _ => {}
        }
    }

    if json_output {
        println!(
            "{}",
            serde_json::json!({
                "success": true,
                "left": left_label,
                "right": right_label,
                "added": added,
                "removed": removed,
                "changed": changed,
                "unchanged": same,
            })
        );
        return Ok(());
    }

    println!();
    println!(
        "{}",
        install_ui::terminal_line!(
            "  Comparing {} vs {}",
            install_ui::bold(&left_label),
            install_ui::bold(&right_label),
        )
    );
    println!();

    if added.is_empty() && removed.is_empty() && changed.is_empty() {
        output::success("no differences");
        return Ok(());
    }

    for key in &added {
        println!(
            "{}",
            install_ui::terminal_line!(
                "  {} {} {}",
                install_ui::green("+"),
                install_ui::bold(key),
                install_ui::dim("(only in left)"),
            )
        );
    }
    for key in &removed {
        println!(
            "{}",
            install_ui::terminal_line!(
                "  {} {} {}",
                install_ui::red("-"),
                install_ui::bold(key),
                install_ui::dim("(only in right)"),
            )
        );
    }
    for key in &changed {
        println!(
            "{}",
            install_ui::terminal_line!(
                "  {} {} {}",
                install_ui::yellow("~"),
                install_ui::bold(key),
                install_ui::dim("(changed)"),
            )
        );
    }
    if same > 0 {
        println!("  {} {same} unchanged", "=".dimmed());
    }

    println!();
    println!(
        "{}",
        install_ui::terminal_line!(
            "  Summary: {} added, {} removed, {} changed, {} unchanged",
            install_ui::green(&added.len().to_string()),
            install_ui::red(&removed.len().to_string()),
            install_ui::yellow(&changed.len().to_string()),
            install_ui::dim(&same.to_string()),
        )
    );

    Ok(())
}
