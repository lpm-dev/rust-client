use super::prelude::*;

type SharedEnvironment = std::sync::Arc<HashMap<String, String>>;
type LocalDiffPair = (SharedEnvironment, SharedEnvironment);

pub(super) async fn env_log(
    client: &lpm_registry::RegistryClient,
    project_dir: &std::path::Path,
    json_output: bool,
) -> Result<(), LpmError> {
    let manifest = super::sync_payload::CloudManifestSnapshot::read(project_dir)?;
    let vault_id = manifest
        .vault
        .vault_id()
        .map_err(LpmError::Script)?
        .map(str::to_owned)
        .ok_or_else(|| LpmError::Script("no vault configured".into()))?;

    let result =
        super::auth::execute_sync_with_bearer(client, |registry_url, auth_token| {
            let vault_id = vault_id.clone();
            async move {
                lpm_vault::sync::get_audit_log(&registry_url, &auth_token, &vault_id, None).await
            }
        })
        .await?;

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

pub(super) fn parse_org_slug_value<'a>(
    value: Option<&'a str>,
    error_message: &str,
) -> Result<&'a str, LpmError> {
    value
        .filter(|slug| !slug.trim().is_empty() && !slug.trim_start().starts_with('-'))
        .ok_or_else(|| LpmError::Script(error_message.into()))
}

fn parse_share_org_slug<'a>(args: &'a [&str]) -> Result<&'a str, LpmError> {
    const USAGE: &str = "usage: lpm env share --org <org-slug>";

    let mut org_slug = None;
    let mut index = 0;
    while index < args.len() {
        let argument = args[index];
        if index == 0 && argument == "share" {
        } else if argument == "--org" {
            index += 1;
            let slug = parse_org_slug_value(args.get(index).copied(), USAGE)?;
            if org_slug.replace(slug).is_some() {
                return Err(LpmError::Script(USAGE.into()));
            }
        } else if let Some(slug) = argument.strip_prefix("--org=") {
            let slug = parse_org_slug_value(Some(slug), USAGE)?;
            if org_slug.replace(slug).is_some() {
                return Err(LpmError::Script(USAGE.into()));
            }
        } else if argument == "--accept-recipient-keys" {
            index += 1;
        } else if argument.starts_with("--accept-recipient-keys=") || argument == "--force" {
        } else {
            return Err(LpmError::Script(format!(
                "unknown share argument: {argument}"
            )));
        }
        index += 1;
    }

    org_slug.ok_or_else(|| LpmError::Script(USAGE.into()))
}

pub(super) fn parse_list_remote_org_slug<'a>(
    args: &'a [&str],
) -> Result<Option<&'a str>, LpmError> {
    const USAGE: &str = "usage: lpm env list-remote [--org <org-slug>]";

    let mut org_slug = None;
    let mut index = 0;
    while index < args.len() {
        let argument = args[index];
        if index == 0 && matches!(argument, "list-remote" | "ls-remote") {
        } else if argument == "--org" {
            index += 1;
            let slug = parse_org_slug_value(args.get(index).copied(), USAGE)?;
            if org_slug.replace(slug).is_some() {
                return Err(LpmError::Script(USAGE.into()));
            }
        } else if let Some(slug) = argument.strip_prefix("--org=") {
            let slug = parse_org_slug_value(Some(slug), USAGE)?;
            if org_slug.replace(slug).is_some() {
                return Err(LpmError::Script(USAGE.into()));
            }
        } else {
            return Err(LpmError::Script(format!(
                "unknown list-remote argument: {argument}"
            )));
        }
        index += 1;
    }
    Ok(org_slug)
}

pub(super) async fn env_share(
    client: &lpm_registry::RegistryClient,
    args: &[&str],
    project_dir: &std::path::Path,
    json_output: bool,
) -> Result<(), LpmError> {
    let org_slug = parse_share_org_slug(args)?;
    let recipient_set_acceptance = parse_recipient_set_acceptance(args)?;
    let recreate_missing = args.contains(&"--force");

    let manifest = super::sync_payload::CloudManifestSnapshot::read(project_dir)?;
    let vault_id = manifest
        .vault
        .vault_id()
        .map_err(LpmError::Script)?
        .map(str::to_owned)
        .ok_or_else(|| LpmError::Script("no vault configured. Run `lpm env set` first".into()))?;
    let expected_principal_id = manifest
        .vault
        .org_sync_principal_for_registry(org_slug, client.base_url())
        .map_err(LpmError::Script)?;
    if recreate_missing && expected_principal_id.is_none() {
        return Err(LpmError::Script(
            "`lpm env share --force` can recreate only an organization env previously bound to this checkout"
                .into(),
        ));
    }

    let all_envs =
        lpm_vault::try_get_all_environments_for_vault_id(&vault_id).map_err(LpmError::Script)?;
    let environment_count = all_envs.len();
    let total_keys: usize = all_envs.values().map(|e| e.len()).sum();
    if total_keys == 0 {
        return Err(LpmError::Script("vault is empty, nothing to share".into()));
    }

    let (private_key, member_access) =
        super::rotation::sharing_key_and_member_access_for_org_op(client, org_slug, "share")
            .await?;
    if expected_principal_id
        .as_deref()
        .is_some_and(|expected| expected != member_access.organization_id)
    {
        return Err(LpmError::Script(
			"this env checkout is bound to a different organization; use a separate checkout when switching organizations"
				.into(),
		));
    }
    let member_access = std::sync::Arc::new(member_access);

    let config = manifest.config;
    let non_empty_envs = super::sync_payload::build_sync_environments(all_envs);
    let secrets_json = std::sync::Arc::new({
        let mut wrapper = std::collections::HashMap::new();
        wrapper.insert("environments".to_string(), non_empty_envs);
        serde_json::to_string(&wrapper)
            .map_err(|e| LpmError::Script(format!("failed to serialize: {e}")))?
    });

    let project_name = manifest.vault.project_name(project_dir);
    let schema_value = std::sync::Arc::new(super::sync_payload::build_push_schema_value(
        config.as_ref(),
    ));
    drop(config);
    let project_dir = project_dir.to_path_buf();

    if !json_output {
        output::info_line(install_ui::terminal_line!(
            "sharing vault with org {} ({} keys across {} environments)...",
            install_ui::bold(org_slug),
            total_keys,
            environment_count,
        ));
    }

    let (result, registry_url, organization_id) = super::auth::execute_sync_with_bearer(
        client,
        |registry_url, auth_token| {
            let project_name = project_name.clone();
            let schema_value = std::sync::Arc::clone(&schema_value);
            let vault_id = vault_id.clone();
            let secrets_json = std::sync::Arc::clone(&secrets_json);
            let recipient_set_acceptance = recipient_set_acceptance.clone();
            let project_dir = project_dir.clone();
            let access = std::sync::Arc::clone(&member_access);
            let expected_principal_id = expected_principal_id.clone();
            async move {
                let current_manifest = super::sync_payload::fresh_org_mutation_manifest(
                    &project_dir,
                    &vault_id,
                    org_slug,
                    &registry_url,
                    expected_principal_id.as_deref(),
                )?;
                let checkpoint_version = current_manifest.org_sync_version_for_principal(
                    org_slug,
                    lpm_vault::vault_id::SyncPrincipal {
                        registry_url: &registry_url,
                        principal_id: &access.organization_id,
                    },
                );
                let expected_version = if recreate_missing {
                    let checkpoint_version = checkpoint_version.ok_or_else(|| {
                        lpm_vault::sync::SyncError::from(
                            "`lpm env share --force` requires a durable revision checkpoint for the bound organization env",
                        )
                    })?;
                    let remote_version =
                        lpm_vault::sync::org_version_preflight_bound_to_principal(
                            &registry_url,
                            &auth_token,
                            org_slug,
                            &vault_id,
                            &access.organization_id,
                        )
                        .await?;
                    if let Some(remote_version) = remote_version {
                        if remote_version < checkpoint_version {
                            return Err(lpm_vault::sync::SyncError::from(format!(
                                "cloud env version {remote_version} is older than the durable local version {checkpoint_version}"
                            )));
                        }
                        return Err(lpm_vault::sync::SyncError::from(format!(
                            "organization env still exists at revision {remote_version}; `lpm env share --force` recreates only a deleted remote. Run `lpm env pull --org {org_slug}` before sharing"
                        )));
                    }
                    Some(checkpoint_version)
                } else {
                    checkpoint_version
                };
                let push_metadata = lpm_vault::sync::PushMetadata {
                    name: Some(&project_name),
                    schema: schema_value.as_ref().as_ref(),
                };
                let result = lpm_vault::sync::push_org_with_access(
                    &registry_url,
                    &auth_token,
                    lpm_vault::sync::OrgPushRequest {
                        org_slug,
                        vault_id: &vault_id,
                        secrets_json: secrets_json.as_str(),
                        expected_version,
                        recreate_missing,
                        metadata: Some(&push_metadata),
                        recipient_set_acceptance: recipient_set_acceptance.as_deref(),
                    },
                    &private_key,
                    access.as_ref(),
                )
                .await?;
                Ok((result, registry_url, access.organization_id.clone()))
            }
        },
    )
    .await?;

    if let Some(version) = result.version {
        super::sync_payload::persist_org_sync_version(
            &project_dir,
            &vault_id,
            org_slug,
            version,
            &registry_url,
            &organization_id,
        )?;
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

pub(super) fn parse_recipient_set_acceptance(args: &[&str]) -> Result<Option<String>, LpmError> {
    let mut acceptance = None;
    let mut index = 0;
    while index < args.len() {
        let argument = args[index];
        let value = if argument == "--accept-recipient-keys" {
            index += 1;
            Some(args.get(index).copied().ok_or_else(|| {
                LpmError::Script(
                    "`--accept-recipient-keys` requires a 64-character recipient-set digest".into(),
                )
            })?)
        } else {
            argument.strip_prefix("--accept-recipient-keys=")
        };
        if let Some(value) = value {
            if acceptance.is_some() {
                return Err(LpmError::Script(
                    "`--accept-recipient-keys` may be specified only once".into(),
                ));
            }
            if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                return Err(LpmError::Script(
                    "`--accept-recipient-keys` requires a 64-character hexadecimal recipient-set digest"
                        .into(),
                ));
            }
            acceptance = Some(value.to_ascii_lowercase());
        }
        index += 1;
    }
    Ok(acceptance)
}

/// List cloud vaults — personal or org.
pub(super) async fn vars_list_remote(
    client: &lpm_registry::RegistryClient,
    org_slug: Option<&str>,
    json_output: bool,
) -> Result<(), LpmError> {
    if let Some(slug) = org_slug {
        // List org vaults
        let vaults =
            super::auth::execute_sync_with_bearer(client, |registry_url, auth_token| async move {
                lpm_vault::sync::list_org_vaults(&registry_url, &auth_token, slug).await
            })
            .await?;

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
    let vaults =
        super::auth::execute_sync_with_bearer(client, |registry_url, auth_token| async move {
            lpm_vault::sync::list_remote(&registry_url, &auth_token).await
        })
        .await?;

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
fn take_local_diff_pair(
    mut environments: HashMap<String, HashMap<String, String>>,
    left_storage_key: &str,
    right_storage_key: &str,
) -> LocalDiffPair {
    let left = std::sync::Arc::new(environments.remove(left_storage_key).unwrap_or_default());
    let right = if left_storage_key == right_storage_key {
        std::sync::Arc::clone(&left)
    } else {
        std::sync::Arc::new(environments.remove(right_storage_key).unwrap_or_default())
    };
    (left, right)
}

pub(super) async fn vars_diff(
    client: &lpm_registry::RegistryClient,
    args: &[&str],
    project_dir: &std::path::Path,
    json_output: bool,
) -> Result<(), LpmError> {
    let manifest = super::sync_payload::CloudManifestSnapshot::read(project_dir)?;
    let vault_id = manifest
        .vault
        .vault_id()
        .map_err(LpmError::Script)?
        .map(str::to_owned);
    let config = manifest.config;
    let empty_env_map = std::collections::HashMap::new();
    let env_map = config.as_ref().map_or(&empty_env_map, |c| &c.env);
    let environments = config.as_ref().and_then(|c| c.environments.as_ref());

    let (left_label, left_secrets, right_label, right_secrets) = if args.len() >= 2 {
        // Compare two local environments — resolve aliases to canonical names
        let resolved_a = lpm_env::resolver::resolve(args[0], env_map, environments);
        let resolved_b = lpm_env::resolver::resolve(args[1], env_map, environments);
        let local_environments = match vault_id.as_deref() {
            Some(vault_id) => lpm_vault::try_get_all_environments_for_vault_id(vault_id)
                .map_err(LpmError::Script)?,
            None => HashMap::new(),
        };
        let (a, b) = take_local_diff_pair(
            local_environments,
            &resolved_a.storage_key,
            &resolved_b.storage_key,
        );
        (
            format!("{} (local)", resolved_a.canonical),
            a,
            format!("{} (local)", resolved_b.canonical),
            b,
        )
    } else if args.len() == 1 {
        // Compare specific env local vs cloud — fetch the same env from cloud, not "default"
        let resolved = lpm_env::resolver::resolve(args[0], env_map, environments);
        let vault_id = vault_id
            .as_deref()
            .ok_or_else(|| LpmError::Script("no vault configured".into()))?;
        let local = lpm_vault::try_get_all_env_for_vault_id(vault_id, &resolved.storage_key)
            .map_err(LpmError::Script)?;
        let canonical = resolved.canonical.clone();
        let expected_principal_id = manifest
            .vault
            .personal_expected_principal_for_registry(client.base_url())
            .map_err(LpmError::Script)?;
        let (remote, _version) =
            super::auth::execute_sync_with_bearer(client, |registry_url, auth_token| {
                let vault_id = vault_id.to_owned();
                let canonical = canonical.clone();
                let expected_principal_id = expected_principal_id.clone();
                async move {
                    lpm_vault::sync::pull_env_bound_to_principal(
                        &registry_url,
                        &auth_token,
                        &vault_id,
                        &canonical,
                        expected_principal_id.as_deref(),
                    )
                    .await
                }
            })
            .await?;

        (
            format!("{} (local)", resolved.canonical),
            std::sync::Arc::new(local),
            format!("{} (cloud)", resolved.canonical),
            std::sync::Arc::new(remote),
        )
    } else {
        // Default: local default vs cloud
        let vault_id = vault_id
            .as_deref()
            .ok_or_else(|| LpmError::Script("no vault configured".into()))?;
        let local = lpm_vault::try_get_all_env_for_vault_id(vault_id, "default")
            .map_err(LpmError::Script)?;
        let expected_principal_id = manifest
            .vault
            .personal_expected_principal_for_registry(client.base_url())
            .map_err(LpmError::Script)?;
        let (remote, _version) =
            super::auth::execute_sync_with_bearer(client, |registry_url, auth_token| {
                let vault_id = vault_id.to_owned();
                let expected_principal_id = expected_principal_id.clone();
                async move {
                    lpm_vault::sync::pull_bound_to_principal(
                        &registry_url,
                        &auth_token,
                        &vault_id,
                        expected_principal_id.as_deref(),
                    )
                    .await
                }
            })
            .await?;

        (
            "default (local)".into(),
            std::sync::Arc::new(local),
            "default (cloud)".into(),
            std::sync::Arc::new(remote),
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

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Arc;

    use super::{
        parse_list_remote_org_slug, parse_recipient_set_acceptance, parse_share_org_slug,
        take_local_diff_pair,
    };

    #[test]
    fn same_storage_key_diff_reuses_the_secret_map_allocation() {
        let secrets = HashMap::from([("TOKEN".to_owned(), "x".repeat(1024))]);
        let environments = HashMap::from([("production".to_owned(), secrets)]);

        let (left, right) = take_local_diff_pair(environments, "production", "production");

        assert!(Arc::ptr_eq(&left, &right));
    }

    #[test]
    fn recipient_acceptance_parser_accepts_an_exact_digest() {
        let digest = "A".repeat(64);
        let parsed = parse_recipient_set_acceptance(&[
            "share",
            "--org",
            "acme",
            "--accept-recipient-keys",
            &digest,
        ])
        .expect("valid acceptance digest should parse");

        assert_eq!(parsed, Some("a".repeat(64)));
    }

    #[test]
    fn recipient_acceptance_parser_rejects_a_missing_digest() {
        let error = parse_recipient_set_acceptance(&["share", "--accept-recipient-keys"])
            .expect_err("missing acceptance digest must fail");

        assert!(error.to_string().contains("requires a 64-character"));
    }

    #[test]
    fn recipient_acceptance_parser_rejects_duplicate_flags() {
        let digest = "a".repeat(64);
        let error = parse_recipient_set_acceptance(&[
            "share",
            "--accept-recipient-keys",
            &digest,
            &format!("--accept-recipient-keys={digest}"),
        ])
        .expect_err("duplicate acceptance flags must fail");

        assert!(error.to_string().contains("specified only once"));
    }

    #[test]
    fn share_org_parser_rejects_an_option_as_the_separated_slug() {
        let error = parse_share_org_slug(&[
            "share",
            "--org",
            "--accept-recipient-keys=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ])
        .expect_err("another option must not become the organization slug");

        assert!(error.to_string().contains("--org"));
    }

    #[test]
    fn share_org_parser_accepts_the_equals_form() {
        assert_eq!(
            parse_share_org_slug(&["share", "--org=acme"]).unwrap(),
            "acme"
        );
    }

    #[test]
    fn share_org_parser_rejects_duplicate_org_flags() {
        let error = parse_share_org_slug(&["share", "--org", "acme", "--org=other"])
            .expect_err("duplicate organization flags must fail");

        assert!(error.to_string().contains("--org"));
    }

    #[test]
    fn share_org_parser_rejects_an_empty_equals_slug() {
        let error = parse_share_org_slug(&["share", "--org="])
            .expect_err("an empty organization slug must fail");

        assert!(error.to_string().contains("--org"));
    }

    #[test]
    fn share_org_parser_rejects_an_empty_separated_slug() {
        let error = parse_share_org_slug(&["share", "--org", ""])
            .expect_err("an empty organization slug must fail");

        assert!(error.to_string().contains("--org"));
    }

    #[test]
    fn share_org_parser_rejects_unknown_arguments() {
        let error = parse_share_org_slug(&["share", "--org", "acme", "--bogus"])
            .expect_err("unknown share arguments must fail");

        assert!(
            error
                .to_string()
                .contains("unknown share argument: --bogus")
        );
    }

    #[test]
    fn list_remote_org_parser_accepts_joined_and_separate_selectors() {
        assert_eq!(
            parse_list_remote_org_slug(&["list-remote", "--org", "acme"]).unwrap(),
            Some("acme")
        );
        assert_eq!(
            parse_list_remote_org_slug(&["ls-remote", "--org=acme"]).unwrap(),
            Some("acme")
        );
    }

    #[test]
    fn list_remote_org_parser_rejects_malformed_and_unknown_arguments() {
        for args in [
            &["list-remote", "--org"][..],
            &["list-remote", "--org", "--yes"][..],
            &["list-remote", "--unknown"][..],
            &["list-remote", "--org=acme", "--org", "other"][..],
        ] {
            assert!(
                parse_list_remote_org_slug(args).is_err(),
                "accepted {args:?}"
            );
        }
    }
}
