use crate::commands::env::{auth, sync_payload};
use lpm_common::LpmError;

pub(super) fn validate_selector(value: &str) -> Result<(), LpmError> {
    if value.is_empty()
        || value.len() > 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    {
        return Err(LpmError::Script(
            "--org must be a lowercase organization slug".into(),
        ));
    }
    Ok(())
}

pub(super) fn selector<'a>(args: &[&'a str]) -> Result<Option<&'a str>, LpmError> {
    let mut org = None;
    for arg in args {
        let value = arg
            .strip_prefix("--org=")
            .ok_or_else(|| LpmError::Script(format!("unknown OIDC argument: {arg}")))?;
        validate_selector(value)?;
        if org.replace(value).is_some() {
            return Err(LpmError::Script("supply --org only once".into()));
        }
    }
    Ok(org)
}

pub(super) async fn enable(
    client: &lpm_registry::RegistryClient,
    project_dir: &std::path::Path,
    org: &str,
    vault_id: &str,
    principal_id: &str,
) -> Result<(), LpmError> {
    auth::execute_sync_with_bearer(client, |registry_url, token| async move {
        let escrow = lpm_vault::sync::prepare_org_ci_escrow(
            &registry_url,
            &token,
            org,
            vault_id,
            principal_id,
        )
        .await?;
        sync_payload::fresh_org_mutation_manifest(
            project_dir,
            vault_id,
            org,
            &registry_url,
            Some(principal_id),
        )?;
        escrow.upload(&token).await
    })
    .await
    .map_err(|error| {
        super::oidc_escrow_setup_error("enabling organization CI decryption", &error.to_string())
    })
}

pub(super) async fn disable(
    client: &lpm_registry::RegistryClient,
    args: &[&str],
    project_dir: &std::path::Path,
    json_output: bool,
) -> Result<(), LpmError> {
    let org = selector(args)?
        .ok_or_else(|| LpmError::Script("usage: lpm env oidc disable --org=<slug>".into()))?;
    let manifest = sync_payload::CloudManifestSnapshot::read(project_dir)?;
    let vault_id = manifest
        .vault
        .vault_id()
        .map_err(LpmError::Script)?
        .ok_or_else(|| LpmError::Script("no env project configured".into()))?;
    let principal = manifest.vault.org_sync_principal_for_registry(org, client.base_url()).map_err(LpmError::Script)?
        .ok_or_else(|| LpmError::Script("this checkout has no authenticated organization binding; pull the env project before disabling CI access".into()))?;
    auth::execute_sync_with_bearer(client, |registry_url, token| {
        let principal = &principal;
        async move {
            sync_payload::fresh_org_mutation_manifest(
                project_dir,
                vault_id,
                org,
                &registry_url,
                Some(principal),
            )?;
            lpm_vault::sync::disable_org_ci_escrow(&registry_url, &token, org, vault_id, principal)
                .await
        }
    })
    .await?;
    if json_output {
        println!("{{\"status\":\"disabled\"}}");
    } else {
        crate::output::info(
            "Organization CI decryption disabled; existing CI credentials were revoked",
        );
    }
    Ok(())
}
