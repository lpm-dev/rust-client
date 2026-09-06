use super::prelude::*;

pub(super) async fn env_rotate_key(
    client: &lpm_registry::RegistryClient,
    args: &[&str],
    project_dir: &std::path::Path,
    json_output: bool,
) -> Result<(), LpmError> {
    let options = parse_rotate_key_options(args)?;
    if let Some(org_slug) = options.org_slug {
        return env_rotate_org_key(
            client,
            &org_slug,
            project_dir,
            json_output,
            options.recipient_set_acceptance.as_deref(),
        )
        .await;
    }

    let manifest = super::sync_payload::CloudManifestSnapshot::read(project_dir)?;
    let vault_id = manifest
        .vault
        .vault_id()
        .map_err(LpmError::Script)?
        .map(str::to_owned)
        .ok_or_else(|| LpmError::Script("no vault configured".into()))?;
    let expected_principal_id = manifest
        .vault
        .personal_expected_principal_for_registry(client.base_url())
        .map_err(LpmError::Script)?;

    let (pulled, pulled_registry_url) =
        super::auth::execute_sync_with_bearer(client, |registry_url, auth_token| {
            let vault_id = vault_id.clone();
            let expected_principal_id = expected_principal_id.clone();
            async move {
                let pulled = lpm_vault::sync::pull_raw_for_rotation_bound_to_principal(
                    &registry_url,
                    &auth_token,
                    &vault_id,
                    expected_principal_id.as_deref(),
                )
                .await?;
                Ok((pulled, registry_url))
            }
        })
        .await?;
    let environment_names =
        validate_rotation_payload(&pulled.raw_json).map_err(LpmError::Script)?;
    let raw_json = std::sync::Arc::new(pulled.raw_json);
    let pulled_principal_id = pulled.principal_id;
    let current_version = pulled.version;
    let project_dir = project_dir.to_path_buf();

    if !json_output {
        output::info("rotating vault encryption key...");
    }

    let (result, registry_url) =
        super::auth::execute_sync_with_bearer(client, |registry_url, auth_token| {
            let vault_id = vault_id.clone();
            let raw_json = std::sync::Arc::clone(&raw_json);
            let pulled_registry_url = pulled_registry_url.clone();
            let pulled_principal_id = pulled_principal_id.clone();
            let expected_principal_id = expected_principal_id.clone();
            let project_dir = project_dir.clone();
            async move {
                if registry_url != pulled_registry_url {
                    return Err(lpm_vault::sync::SyncError::from(
                        "the active registry changed during personal key rotation",
                    ));
                }
                super::sync_payload::fresh_personal_mutation_manifest(
                    &project_dir,
                    &vault_id,
                    &registry_url,
                    expected_principal_id.as_deref(),
                )?;
                let result = lpm_vault::sync::push_raw_with_options(
                    &registry_url,
                    &auth_token,
                    &vault_id,
                    raw_json.as_str(),
                    lpm_vault::sync::PersonalPushOptions {
                        expected_version: Some(current_version),
                        expected_principal_id: Some(&pulled_principal_id),
                        force: false,
                        metadata: None,
                    },
                )
                .await?;
                if result.principal_id.as_deref() != Some(pulled_principal_id.as_str()) {
                    return Err(lpm_vault::sync::SyncError::from(
                        "the personal cloud vault principal changed during key rotation",
                    ));
                }
                Ok((result, registry_url))
            }
        })
        .await?;

    let version = result
        .version
        .ok_or_else(|| LpmError::Script("rotation response omitted the new version".into()))?;
    super::sync_payload::persist_personal_sync_version(
        &project_dir,
        &vault_id,
        version,
        &registry_url,
        &pulled_principal_id,
    )?;

    if json_output {
        super::response::print_json_value(&serde_json::json!({
            "success": true,
            "status": "rotated",
            "version": version,
            "environment_count": environment_names.len(),
            "environments": environment_names,
        }));
    } else {
        output::success_line(crate::install_ui::terminal_line!(
            "encryption key rotated (version {}, preserved {} environment{})",
            install_ui::bold(&version.to_string()),
            environment_names.len(),
            if environment_names.len() == 1 {
                ""
            } else {
                "s"
            }
        ));
        if !environment_names.is_empty() {
            output::info(&format!("preserved: {}", environment_names.join(", ")));
        }
    }
    Ok(())
}

struct RotateKeyOptions {
    org_slug: Option<String>,
    recipient_set_acceptance: Option<String>,
}

fn parse_rotate_key_options(args: &[&str]) -> Result<RotateKeyOptions, LpmError> {
    let recipient_set_acceptance = super::remote::parse_recipient_set_acceptance(args)?;
    let mut org_slug = None;
    let mut index = 0;
    while index < args.len() {
        let argument = args[index];
        if argument == "--org" {
            index += 1;
            let slug = super::remote::parse_org_slug_value(
                args.get(index).copied(),
                "`lpm env rotate-key --org` requires exactly one organization slug",
            )?;
            if org_slug.is_some() {
                return Err(LpmError::Script(
                    "`lpm env rotate-key --org` requires exactly one organization slug".into(),
                ));
            }
            org_slug = Some(slug.to_owned());
        } else if let Some(slug) = argument.strip_prefix("--org=") {
            let slug = super::remote::parse_org_slug_value(
                Some(slug),
                "`lpm env rotate-key --org` requires exactly one organization slug",
            )?;
            if org_slug.is_some() {
                return Err(LpmError::Script(
                    "`lpm env rotate-key --org` requires exactly one organization slug".into(),
                ));
            }
            org_slug = Some(slug.to_owned());
        } else if argument == "--accept-recipient-keys" {
            index += 1;
        } else if argument.starts_with("--accept-recipient-keys=") {
        } else {
            return Err(LpmError::Script(format!(
                "unknown rotate-key argument: {argument}"
            )));
        }
        index += 1;
    }
    if recipient_set_acceptance.is_some() && org_slug.is_none() {
        return Err(LpmError::Script(
            "`--accept-recipient-keys` is valid only with `lpm env rotate-key --org <slug>`".into(),
        ));
    }
    Ok(RotateKeyOptions {
        org_slug,
        recipient_set_acceptance,
    })
}

#[cfg(test)]
fn parse_rotate_key_org(args: &[&str]) -> Result<Option<String>, LpmError> {
    Ok(parse_rotate_key_options(args)?.org_slug)
}

async fn env_rotate_org_key(
    client: &lpm_registry::RegistryClient,
    org_slug: &str,
    project_dir: &std::path::Path,
    json_output: bool,
    recipient_set_acceptance: Option<&str>,
) -> Result<(), LpmError> {
    let manifest = super::sync_payload::CloudManifestSnapshot::read(project_dir)?;
    let vault_id = manifest
        .vault
        .vault_id()
        .map_err(LpmError::Script)?
        .map(str::to_owned)
        .ok_or_else(|| LpmError::Script("no vault configured".into()))?;
    let expected_principal_id = manifest
        .vault
        .org_sync_principal_for_registry(org_slug, client.base_url())
        .map_err(LpmError::Script)?;

    let (pulled, pulled_registry_url) = pull_org_with_local_key_first(
        client,
        org_slug,
        &vault_id,
        "rotate the organization content key",
        expected_principal_id.as_deref(),
    )
    .await?;
    let lpm_vault::sync::PulledOrgVault {
        raw_json,
        version: pulled_version,
        content_key_version: pulled_content_key_version,
        principal_id: pulled_principal_id,
        ..
    } = pulled;
    let environment_names = validate_rotation_payload(&raw_json).map_err(LpmError::Script)?;
    let raw_json = std::sync::Arc::new(raw_json);
    let expected_content_key_version =
        pulled_content_key_version.checked_add(1).ok_or_else(|| {
            LpmError::Script("organization content-key version cannot advance further".into())
        })?;
    let project_dir = project_dir.to_path_buf();

    if !json_output {
        output::info("rotating organization env encryption key...");
    }

    let (result, registry_url) =
        super::auth::execute_sync_with_bearer(client, |registry_url, auth_token| {
            let vault_id = vault_id.clone();
            let raw_json = std::sync::Arc::clone(&raw_json);
            let pulled_registry_url = pulled_registry_url.clone();
            let pulled_principal_id = pulled_principal_id.clone();
            let expected_principal_id = expected_principal_id.clone();
            let project_dir = project_dir.clone();
            async move {
                if registry_url != pulled_registry_url {
                    return Err(lpm_vault::sync::SyncError::from(
                        "the active registry changed during organization key rotation",
                    ));
                }
                let access = lpm_vault::sync::get_org_member_key_access(
                    &registry_url,
                    &auth_token,
                    org_slug,
                )
                .await?;
                if access.organization_id != pulled_principal_id {
                    return Err(lpm_vault::sync::SyncError::from(
                        "the organization principal changed during key rotation",
                    ));
                }
                super::sync_payload::fresh_org_mutation_manifest(
                    &project_dir,
                    &vault_id,
                    org_slug,
                    &registry_url,
                    expected_principal_id.as_deref(),
                )?;
                let result = lpm_vault::sync::push_org_with_keys_and_access(
                    &registry_url,
                    &auth_token,
                    lpm_vault::sync::OrgPushRequest {
                        org_slug,
                        vault_id: &vault_id,
                        secrets_json: raw_json.as_str(),
                        expected_version: Some(pulled_version),
                        recreate_missing: false,
                        metadata: None,
                        recipient_set_acceptance,
                    },
                    &access,
                )
                .await?;
                Ok((result, registry_url))
            }
        })
        .await?;
    let version = result
        .version
        .ok_or_else(|| LpmError::Script("rotation response omitted the new version".into()))?;
    let content_key_version = result.content_key_version.ok_or_else(|| {
        LpmError::Script("rotation response omitted the new content-key version".into())
    })?;
    if content_key_version != expected_content_key_version {
        return Err(LpmError::Script(
            "rotation response did not advance the organization content-key version".into(),
        ));
    }

    super::sync_payload::persist_org_sync_version(
        &project_dir,
        &vault_id,
        org_slug,
        version,
        &registry_url,
        &pulled_principal_id,
    )?;

    if json_output {
        super::response::print_json_value(&serde_json::json!({
            "success": true,
            "status": "rotated",
            "org": org_slug,
            "version": version,
            "content_key_version": content_key_version,
            "previous_content_key_version": pulled_content_key_version,
            "environment_count": environment_names.len(),
            "environments": environment_names,
        }));
    } else {
        output::success_line(crate::install_ui::terminal_line!(
            "organization env encryption key rotated for {} (content-key version {})",
            install_ui::bold(org_slug),
            install_ui::bold(&content_key_version.to_string()),
        ));
    }

    Ok(())
}

fn validate_rotation_payload(raw_json: &str) -> Result<Vec<String>, String> {
    use serde::Deserialize;

    let mut deserializer = serde_json::Deserializer::from_str(raw_json);
    let payload = RotationPayload::deserialize(&mut deserializer)
        .and_then(|payload| deserializer.end().map(|()| payload));
    match payload {
        Ok(payload) => Ok(payload.environment_names),
        Err(error) => {
            let message = error.to_string();
            if let Some(validation) = message.strip_prefix("rotation payload: ") {
                return Err(strip_json_error_location(validation).to_string());
            }
            Err(format!("remote vault payload is not valid JSON: {message}"))
        }
    }
}

fn strip_json_error_location(message: &str) -> &str {
    let Some((validation, location)) = message.rsplit_once(" at line ") else {
        return message;
    };
    let Some((line, column)) = location.split_once(" column ") else {
        return message;
    };
    if line.bytes().all(|byte| byte.is_ascii_digit())
        && column.bytes().all(|byte| byte.is_ascii_digit())
    {
        validation
    } else {
        message
    }
}

struct RotationPayload {
    environment_names: Vec<String>,
}

impl<'de> serde::Deserialize<'de> for RotationPayload {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(RotationPayloadVisitor)
    }
}

struct RotationPayloadVisitor;

impl<'de> serde::de::Visitor<'de> for RotationPayloadVisitor {
    type Value = RotationPayload;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a vault payload object")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: serde::de::MapAccess<'de>,
    {
        let mut environment_names = None;
        while let Some(key) = map.next_key::<String>()? {
            if key == "environments" {
                if environment_names.is_some() {
                    return Err(serde::de::Error::custom(
                        "rotation payload: remote environments payload is duplicated",
                    ));
                }
                environment_names = Some(map.next_value::<RotationEnvironments>()?.names);
            } else {
                return Err(serde::de::Error::custom(format!(
                    "rotation payload: remote vault payload contains unknown field {key:?}"
                )));
            }
        }
        if let Some(mut names) = environment_names {
            names.sort_unstable();
            names.dedup();
            return Ok(RotationPayload {
                environment_names: names,
            });
        }
        Err(serde::de::Error::custom(
            "rotation payload: remote vault payload must contain environments",
        ))
    }

    fn visit_bool<E>(self, _value: bool) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Err(E::custom(
            "rotation payload: remote vault payload must be a JSON object",
        ))
    }

    fn visit_i64<E>(self, _value: i64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        self.visit_bool(false)
    }

    fn visit_u64<E>(self, _value: u64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        self.visit_bool(false)
    }

    fn visit_f64<E>(self, _value: f64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        self.visit_bool(false)
    }

    fn visit_str<E>(self, _value: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        self.visit_bool(false)
    }

    fn visit_seq<A>(self, _sequence: A) -> Result<Self::Value, A::Error>
    where
        A: serde::de::SeqAccess<'de>,
    {
        self.visit_bool(false)
    }

    fn visit_none<E>(self) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        self.visit_bool(false)
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        self.visit_bool(false)
    }
}

struct RotationEnvironments {
    names: Vec<String>,
}

impl<'de> serde::Deserialize<'de> for RotationEnvironments {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(RotationEnvironmentsVisitor)
    }
}

struct RotationEnvironmentsVisitor;

impl<'de> serde::de::Visitor<'de> for RotationEnvironmentsVisitor {
    type Value = RotationEnvironments;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("an environments object")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: serde::de::MapAccess<'de>,
    {
        let mut names = Vec::with_capacity(map.size_hint().unwrap_or(0));
        while let Some(name) = map.next_key::<String>()? {
            if name.trim().is_empty() {
                return Err(serde::de::Error::custom(
                    "rotation payload: remote environment names cannot be empty",
                ));
            }
            map.next_value_seed(RotationSecretMapSeed { name: &name })?;
            names.push(name);
        }
        Ok(RotationEnvironments { names })
    }

    fn visit_bool<E>(self, _value: bool) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Err(E::custom(
            "rotation payload: remote environments payload must be an object",
        ))
    }

    fn visit_i64<E>(self, _value: i64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        self.visit_bool(false)
    }

    fn visit_u64<E>(self, _value: u64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        self.visit_bool(false)
    }

    fn visit_f64<E>(self, _value: f64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        self.visit_bool(false)
    }

    fn visit_str<E>(self, _value: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        self.visit_bool(false)
    }

    fn visit_seq<A>(self, _sequence: A) -> Result<Self::Value, A::Error>
    where
        A: serde::de::SeqAccess<'de>,
    {
        self.visit_bool(false)
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        self.visit_bool(false)
    }
}

struct RotationSecretMapSeed<'a> {
    name: &'a str,
}

impl<'de> serde::de::DeserializeSeed<'de> for RotationSecretMapSeed<'_> {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(RotationSecretMapVisitor { name: self.name })
    }
}

struct RotationSecretMapVisitor<'a> {
    name: &'a str,
}

impl<'de> serde::de::Visitor<'de> for RotationSecretMapVisitor<'_> {
    type Value = ();

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a secret key/value object")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: serde::de::MapAccess<'de>,
    {
        while map.next_key::<serde::de::IgnoredAny>()?.is_some() {
            map.next_value_seed(RotationSecretValueSeed { name: self.name })?;
        }
        Ok(())
    }

    fn visit_bool<E>(self, _value: bool) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Err(E::custom(format!(
            "rotation payload: environment {:?} must contain a key/value object",
            self.name
        )))
    }

    fn visit_i64<E>(self, _value: i64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        self.visit_bool(false)
    }

    fn visit_u64<E>(self, _value: u64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        self.visit_bool(false)
    }

    fn visit_f64<E>(self, _value: f64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        self.visit_bool(false)
    }

    fn visit_str<E>(self, _value: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        self.visit_bool(false)
    }

    fn visit_seq<A>(self, _sequence: A) -> Result<Self::Value, A::Error>
    where
        A: serde::de::SeqAccess<'de>,
    {
        self.visit_bool(false)
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        self.visit_bool(false)
    }
}

struct RotationSecretValueSeed<'a> {
    name: &'a str,
}

impl<'de> serde::de::DeserializeSeed<'de> for RotationSecretValueSeed<'_> {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(RotationSecretValueVisitor { name: self.name })
    }
}

struct RotationSecretValueVisitor<'a> {
    name: &'a str,
}

impl<'de> serde::de::Visitor<'de> for RotationSecretValueVisitor<'_> {
    type Value = ();

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a string secret value")
    }

    fn visit_borrowed_str<E>(self, _value: &'de str) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_str<E>(self, _value: &str) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_string<E>(self, _value: String) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_bool<E>(self, _value: bool) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Err(E::custom(format!(
            "rotation payload: environment {:?} contains a non-string secret value",
            self.name
        )))
    }

    fn visit_i64<E>(self, _value: i64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        self.visit_bool(false)
    }

    fn visit_u64<E>(self, _value: u64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        self.visit_bool(false)
    }

    fn visit_f64<E>(self, _value: f64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        self.visit_bool(false)
    }

    fn visit_seq<A>(self, _sequence: A) -> Result<Self::Value, A::Error>
    where
        A: serde::de::SeqAccess<'de>,
    {
        self.visit_bool(false)
    }

    fn visit_map<A>(self, _map: A) -> Result<Self::Value, A::Error>
    where
        A: serde::de::MapAccess<'de>,
    {
        self.visit_bool(false)
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        self.visit_bool(false)
    }
}

pub(super) async fn sharing_key_and_member_access_for_org_op(
    client: &lpm_registry::RegistryClient,
    org_slug: &str,
    op_label: &str,
) -> Result<([u8; 32], lpm_vault::sync::OrgMemberKeyAccess), LpmError> {
    use lpm_vault::sync::PublicKeyRegistrationState;

    let (access, registry_url) =
        super::auth::execute_sync_with_bearer(client, |registry_url, auth_token| async move {
            let access =
                lpm_vault::sync::get_org_member_key_access(&registry_url, &auth_token, org_slug)
                    .await?;
            Ok((access, registry_url))
        })
        .await?;
    let state =
        lpm_vault::sync::resolve_public_key_state_from_member_access(&registry_url, &access)
            .map_err(|error| LpmError::Script(error.to_string()))?;

    match state {
        PublicKeyRegistrationState::Matches(local) => Ok((local.private_key, access)),
        PublicKeyRegistrationState::NeedsInitialSet(local) => {
            let access = register_missing_sharing_key_for_org(
                client,
                org_slug,
                op_label,
                &local,
                &access,
                &registry_url,
            )
            .await?;
            Ok((local.private_key, access))
        }
        PublicKeyRegistrationState::RotationRequired { .. } => {
            Err(sharing_key_rotation_required_error(op_label))
        }
    }
}

async fn register_missing_sharing_key_for_org(
    client: &lpm_registry::RegistryClient,
    org_slug: &str,
    op_label: &str,
    local: &lpm_vault::sync::LocalPublicKeyState,
    initial_access: &lpm_vault::sync::OrgMemberKeyAccess,
    initial_registry_url: &str,
) -> Result<lpm_vault::sync::OrgMemberKeyAccess, LpmError> {
    use lpm_vault::sync::PublicKeyRegistrationState;

    output::info(&format!(
        "no sharing key on file for this account; registering this device's key \
         before continuing with `{op_label}`. You'll be prompted to confirm your \
         password (and authenticator code, if enrolled) to authorize the write."
    ));
    let proof = crate::step_up::request_cli_step_up_proof(client, "vault:public-key:set").await?;
    let (refreshed_access, refreshed_registry_url) =
        super::auth::execute_sync_with_bearer(client, |registry_url, auth_token| {
            let public_key = local.public_key_b64.clone();
            let proof = proof.clone();
            let expected_principal_id = initial_access.caller_user_id.clone();
            async move {
                let access = lpm_vault::sync::upload_public_key_for_org(
                    &registry_url,
                    &auth_token,
                    org_slug,
                    &expected_principal_id,
                    &public_key,
                    &proof,
                )
                .await?;
                Ok((access, registry_url))
            }
        })
        .await?;
    if refreshed_registry_url != initial_registry_url {
        return Err(LpmError::Script(
            "the active registry changed during sharing-key registration; retry the command".into(),
        ));
    }
    ensure_member_access_identity(initial_access, &refreshed_access)?;
    let state = lpm_vault::sync::classify_public_key_state_from_member_access(
        local.clone(),
        &refreshed_access,
    )
    .map_err(|error| LpmError::Script(error.to_string()))?;
    if !matches!(state, PublicKeyRegistrationState::Matches(_)) {
        return Err(LpmError::Script(
            "organization member inventory did not confirm the registered sharing key".into(),
        ));
    }
    Ok(refreshed_access)
}

fn ensure_member_access_identity(
    initial: &lpm_vault::sync::OrgMemberKeyAccess,
    refreshed: &lpm_vault::sync::OrgMemberKeyAccess,
) -> Result<(), LpmError> {
    ensure_member_access_matches_identity(
        &initial.organization_id,
        &initial.caller_user_id,
        refreshed,
    )
}

fn ensure_member_access_matches_identity(
    expected_organization_id: &str,
    expected_caller_user_id: &str,
    access: &lpm_vault::sync::OrgMemberKeyAccess,
) -> Result<(), LpmError> {
    if access.organization_id != expected_organization_id {
        return Err(LpmError::Script(
            "organization identity changed during sharing-key recovery; retry the command".into(),
        ));
    }
    if access.caller_user_id != expected_caller_user_id {
        return Err(LpmError::Script(
            "authenticated caller identity changed during sharing-key recovery; retry the command"
                .into(),
        ));
    }
    Ok(())
}

fn ensure_pulled_organization_identity(
    expected_organization_id: &str,
    pulled: &lpm_vault::sync::PulledOrgVault,
) -> Result<(), LpmError> {
    if pulled.principal_id != expected_organization_id {
        return Err(LpmError::Script(
            "organization identity changed while retrying the pull; retry the command".into(),
        ));
    }
    Ok(())
}

fn sharing_key_rotation_required_error(op_label: &str) -> LpmError {
    LpmError::Script(format!(
        "refusing to {op_label}: this device's sharing key does NOT match the key on \
         the server. Silently overwriting the server-side key would invalidate every \
         org teammate's wrapped access without your knowledge — exactly the attack \
         surface the explicit rotation flow exists to close.\n\nIf you intentionally \
         want to rotate your sharing key (e.g. you lost the previous device's key), \
         run `lpm env rotate-sharing-key` here. That command prompts for step-up \
         reauth, shows the blast radius, and sends an out-of-band security email \
         before invalidating wrapped-key rows."
    ))
}

enum OrgPullAttempt {
    Pulled(lpm_vault::sync::PulledOrgVault, String),
    MemberNeedsRewrap {
        organization_id: String,
        caller_user_id: String,
        registry_url: String,
    },
}

pub(super) async fn pull_org_with_local_key_first(
    client: &lpm_registry::RegistryClient,
    org_slug: &str,
    vault_id: &str,
    op_label: &str,
    expected_principal_id: Option<&str>,
) -> Result<(lpm_vault::sync::PulledOrgVault, String), LpmError> {
    use lpm_vault::sync::PublicKeyRegistrationState;

    let expected_principal_id = expected_principal_id.map(str::to_owned);
    let initial = super::auth::execute_sync_with_bearer(client, |registry_url, auth_token| {
        let vault_id = vault_id.to_owned();
        let expected_principal_id = expected_principal_id.clone();
        async move {
            match lpm_vault::sync::pull_org_with_scoped_key_bound_to_principal(
                &registry_url,
                &auth_token,
                org_slug,
                &vault_id,
                expected_principal_id.as_deref(),
            )
            .await
            {
                Ok(pulled) => Ok(OrgPullAttempt::Pulled(pulled, registry_url)),
                Err(error) => {
                    if let Some((organization_id, caller_user_id)) =
                        error.org_member_rewrap_identity()
                    {
                        Ok(OrgPullAttempt::MemberNeedsRewrap {
                            organization_id: organization_id.to_owned(),
                            caller_user_id: caller_user_id.to_owned(),
                            registry_url,
                        })
                    } else {
                        Err(error)
                    }
                }
            }
        }
    })
    .await?;

    let (initial_organization_id, initial_caller_user_id, initial_registry_url) = match initial {
        OrgPullAttempt::Pulled(pulled, registry_url) => return Ok((pulled, registry_url)),
        OrgPullAttempt::MemberNeedsRewrap {
            organization_id,
            caller_user_id,
            registry_url,
        } => (organization_id, caller_user_id, registry_url),
    };

    let (access, access_registry_url) =
        super::auth::execute_sync_with_bearer(client, |registry_url, auth_token| async move {
            let access =
                lpm_vault::sync::get_org_member_key_access(&registry_url, &auth_token, org_slug)
                    .await?;
            Ok((access, registry_url))
        })
        .await?;
    if access_registry_url != initial_registry_url {
        return Err(LpmError::Script(
            "the active registry changed during sharing-key recovery; retry the command".into(),
        ));
    }
    ensure_member_access_matches_identity(
        &initial_organization_id,
        &initial_caller_user_id,
        &access,
    )?;
    let state =
        lpm_vault::sync::resolve_public_key_state_from_member_access(&access_registry_url, &access)
            .map_err(|error| LpmError::Script(error.to_string()))?;
    match state {
        PublicKeyRegistrationState::NeedsInitialSet(local) => {
            register_missing_sharing_key_for_org(
                client,
                org_slug,
                op_label,
                &local,
                &access,
                &access_registry_url,
            )
            .await?;
        }
        PublicKeyRegistrationState::Matches(_) => {
            return Err(LpmError::Script(
                "your registered sharing key does not have access to this env project yet; ask an organization admin to share it again"
                    .into(),
            ));
        }
        PublicKeyRegistrationState::RotationRequired { .. } => {
            return Err(sharing_key_rotation_required_error(op_label));
        }
    }
    let expected_organization_id = initial_organization_id;
    let expected_organization_id_for_pull = expected_organization_id.clone();

    let result = super::auth::execute_sync_with_bearer(client, |registry_url, auth_token| {
        let vault_id = vault_id.to_owned();
        let expected_organization_id = expected_organization_id_for_pull.clone();
        async move {
            let pulled = lpm_vault::sync::pull_org_with_scoped_key_bound_to_principal(
                &registry_url,
                &auth_token,
                org_slug,
                &vault_id,
                Some(&expected_organization_id),
            )
            .await?;
            Ok((pulled, registry_url))
        }
    })
    .await?;
    ensure_pulled_organization_identity(&expected_organization_id, &result.0)?;
    Ok(result)
}

/// Rotate the user's X25519 sharing keypair, with crash recovery and
/// explicit reauth before the server-side public key is replaced.
pub(super) async fn env_rotate_sharing_key(
    client: &lpm_registry::RegistryClient,
    args: &[&str],
    json_output: bool,
) -> Result<(), LpmError> {
    use std::io::IsTerminal;

    // Non-interactive refusal — the prompt for typed confirmation +
    // password / TOTP cannot work without a TTY, and silently advancing
    // through stdin would either block forever or accept hostile input
    // piped from an unattended runner.
    let yes_skip = args.contains(&"--yes");
    if !std::io::stdin().is_terminal() || yes_skip {
        return Err(LpmError::Script(
            "`lpm env rotate-sharing-key` is an interactive recovery surface and \
             refuses to run without a TTY. Run it manually from your terminal."
                .into(),
        ));
    }

    let (server_key, registry_url) =
        super::auth::execute_sync_with_bearer(client, |registry_url, auth_token| async move {
            let state =
                lpm_vault::sync::get_my_public_key_state(&registry_url, &auth_token).await?;
            Ok((state, registry_url))
        })
        .await?;
    let key_scope = lpm_vault::sync::SharingKeyScope::new(&registry_url, &server_key.principal_id)
        .map_err(LpmError::Script)?;
    let _rotation_lock = lpm_vault::sync::try_acquire_sharing_key_rotation_lock(&key_scope)
		.map_err(LpmError::Script)?
        .ok_or_else(|| {
            LpmError::Script(
                "another `lpm env rotate-sharing-key` command is already running; wait for it to finish before retrying"
                    .into(),
            )
        })?;

    // Crash recovery — if a pending key exists and matches the server,
    // the previous run committed the server side but didn't promote
    // locally. Promote and return; no second rotation needed.
    if let Some(pending) =
        lpm_vault::sync::read_pending_x25519_keypair(&key_scope).map_err(LpmError::Script)?
    {
        if server_key.public_key_b64.as_deref() == Some(&pending.public_key_b64) {
            lpm_vault::sync::promote_pending_x25519_keypair(&key_scope)
                .map_err(LpmError::Script)?;
            if json_output {
                println!(
                    "{}",
                    serde_json::json!({
                        "success": true,
                        "status": "resumed",
                    })
                );
            } else {
                output::success(
                    "resumed pending sharing-key rotation: server already had the new key, \
                     promoted the local slot.",
                );
            }
            return Ok(());
        }
        // Pending exists but doesn't match server — last attempt failed
        // before the server committed. Discard the orphan so the next
        // step can re-generate.
        output::warn(
            "found a stale pending sharing-key from a prior failed rotation. Discarding it \
             and starting fresh.",
        );
        lpm_vault::sync::discard_pending_x25519_keypair(&key_scope).map_err(LpmError::Script)?;
    }

    // Show blast radius. We can't precompute it locally (we don't know
    // which orgs the user belongs to without a server roundtrip we'd
    // duplicate post-rotation), so the message names the EFFECT
    // honestly: every org vault wrapped to this user gets invalidated;
    // owners/admins of each affected org must re-share before pulls
    // resume.
    output::warn(
        "Rotating your sharing key invalidates EVERY org-vault wrapped-key entry stored \
         for you. Until an owner or admin of each affected org runs \
         `lpm env share --org <slug>` to re-wrap, you will not be able to pull those \
         vaults. The dashboard's Member Access view will show those rows as \"Needs share\".",
    );
    output::info(
        "An out-of-band security email will be sent to your account, and a separate \
         impact email to every affected org's owners + admins.",
    );

    let typed: String =
        cliclack::input("Type ROTATE (uppercase) to confirm. Any other input cancels.")
            .interact()
            .map_err(|e| LpmError::Script(format!("confirmation prompt failed: {e}")))?;
    if typed != "ROTATE" {
        return Err(LpmError::Script(
            "rotation cancelled — no server-side or local state changed.".into(),
        ));
    }

    // Acquire the step-up proof BEFORE generating the pending
    // key — a credential refusal must not leave a stale pending file
    // on disk.
    let proof =
        crate::step_up::request_cli_step_up_proof(client, "vault:public-key:rotate").await?;

    let pending =
        lpm_vault::sync::create_pending_x25519_keypair(&key_scope).map_err(LpmError::Script)?;
    let expected_registry_url = registry_url.clone();
    let expected_principal_id = server_key.principal_id.clone();

    output::info("uploading new sharing key...");
    let response = super::auth::execute_sync_with_bearer(client, |registry_url, auth_token| {
        let public_key = pending.public_key_b64.clone();
        let proof = proof.clone();
        let expected_registry_url = expected_registry_url.clone();
        let expected_principal_id = expected_principal_id.clone();
        async move {
            if registry_url != expected_registry_url {
                return Err(lpm_vault::sync::SyncError::from(
                    "the active registry changed during sharing-key rotation",
                ));
            }
            lpm_vault::sync::upload_public_key(
                &registry_url,
                &auth_token,
                &expected_principal_id,
                &public_key,
                Some(&proof),
            )
            .await
        }
    })
    .await;

    let response = match response {
        Ok(r) => r,
        Err(e) => {
            // The server may have committed before the response was lost or
            // became unparsable. Preserve the pending private key so the next
            // invocation can compare its public half with the authoritative
            // server key and either promote it or discard a confirmed orphan.
            return Err(LpmError::Script(e.to_string()));
        }
    };

    // Promote pending → live. A crash here leaves the pending slot
    // and the server-side new key, which the crash-recovery branch
    // at the top of this function will finish on the next run.
    lpm_vault::sync::promote_pending_x25519_keypair(&key_scope).map_err(LpmError::Script)?;

    if json_output {
        println!(
            "{}",
            serde_json::json!({
                "success": true,
                "status": response.status,
                "fingerprintPrefix": response.fingerprint_prefix,
                "previousFingerprintPrefix": response.previous_fingerprint_prefix,
                "invalidatedWrappedKeys": response.invalidated_wrapped_keys,
                "affectedOrgs": response.affected_orgs,
            })
        );
    } else {
        let fp = response
            .fingerprint_prefix
            .as_deref()
            .unwrap_or("(unknown)");
        let invalidated = response.invalidated_wrapped_keys.unwrap_or(0);
        let orgs = response.affected_orgs.unwrap_or(0);
        output::success_line(crate::install_ui::terminal_line!(
            "sharing key rotated. New fingerprint: {}.",
            install_ui::bold(fp)
        ));
        if invalidated > 0 || orgs > 0 {
            output::info(&format!(
                "Invalidated {invalidated} wrapped-key entries across {orgs} org(s). \
                 Ask an owner/admin of each affected org to re-share before pulling again."
            ));
        } else {
            output::info(
                "No org-vault wrapped keys were affected (you weren't sharing into any orgs \
                 yet).",
            );
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        ensure_member_access_identity, ensure_member_access_matches_identity,
        ensure_pulled_organization_identity, parse_rotate_key_org, validate_rotation_payload,
    };

    fn member_access(
        organization_id: &str,
        caller_user_id: &str,
    ) -> lpm_vault::sync::OrgMemberKeyAccess {
        lpm_vault::sync::OrgMemberKeyAccess {
            organization_id: organization_id.to_owned(),
            caller_user_id: caller_user_id.to_owned(),
            members: Vec::new(),
            can_replace_wrapped_keys: true,
        }
    }

    #[test]
    fn refreshed_member_access_must_preserve_the_organization_identity() {
        let initial = member_access("00000000-0000-4000-8000-000000000001", "user-1");
        let refreshed = member_access("00000000-0000-4000-8000-000000000002", "user-1");

        let error = ensure_member_access_identity(&initial, &refreshed)
            .expect_err("a rebound organization slug must fail closed");

        assert!(error.to_string().contains("organization identity changed"));
    }

    #[test]
    fn rewrap_identity_must_match_the_first_member_inventory() {
        let access = member_access("00000000-0000-4000-8000-000000000002", "user-1");

        let error = ensure_member_access_matches_identity(
            "00000000-0000-4000-8000-000000000001",
            "user-1",
            &access,
        )
        .expect_err("a slug rebound after the rewrap response must fail closed");

        assert!(error.to_string().contains("organization identity changed"));
    }

    #[test]
    fn refreshed_member_access_must_preserve_the_caller_identity() {
        let initial = member_access("00000000-0000-4000-8000-000000000001", "user-1");
        let refreshed = member_access("00000000-0000-4000-8000-000000000001", "user-2");

        let error = ensure_member_access_identity(&initial, &refreshed)
            .expect_err("a changed authenticated caller must fail closed");

        assert!(error.to_string().contains("caller identity changed"));
    }

    #[test]
    fn retried_org_pull_must_preserve_the_captured_organization_identity() {
        let pulled = lpm_vault::sync::PulledOrgVault {
            raw_json: "{}".to_owned(),
            version: 1,
            content_key_version: 1,
            principal_id: "00000000-0000-4000-8000-000000000002".to_owned(),
            caller_user_id: "user-1".to_owned(),
        };

        let error =
            ensure_pulled_organization_identity("00000000-0000-4000-8000-000000000001", &pulled)
                .expect_err("a rebound organization pull must fail closed");

        assert!(error.to_string().contains("organization identity changed"));
    }

    #[test]
    fn rotation_payload_streaming_validation_preserves_supported_shapes() {
        assert_eq!(
            validate_rotation_payload(
                r#"{"environments":{"production":{"TOKEN":"secret"},"dev":{"ESCAPED":"line\nvalue"}}}"#,
            )
            .unwrap(),
            ["dev", "production"]
        );
    }

    #[test]
    fn rotation_payload_streaming_validation_rejects_retired_flat_payload() {
        let error = validate_rotation_payload(r#"{"TOKEN":"secret","ESCAPED":"line\nvalue"}"#)
            .expect_err("retired flat payloads must not remain executable");

        assert_eq!(
            error,
            "remote vault payload contains unknown field \"TOKEN\""
        );
    }

    #[test]
    fn rotation_payload_streaming_validation_rejects_invalid_shapes() {
        for (payload, expected) in [
            ("[]", "remote vault payload must be a JSON object"),
            (
                r#"{"environments":[]}"#,
                "remote environments payload must be an object",
            ),
            (
                r#"{"environments":{" ":{}}}"#,
                "remote environment names cannot be empty",
            ),
            (
                r#"{"environments":{"production":[]}}"#,
                "environment \"production\" must contain a key/value object",
            ),
            (
                r#"{"environments":{"production":{"TOKEN":1}}}"#,
                "environment \"production\" contains a non-string secret value",
            ),
            (
                r#"{"TOKEN":false}"#,
                "remote vault payload contains unknown field \"TOKEN\"",
            ),
        ] {
            let error = validate_rotation_payload(payload).expect_err("shape must be rejected");
            assert_eq!(error, expected);
        }
    }

    #[test]
    fn rotation_payload_validation_preserves_environment_names_containing_error_text() {
        let error = validate_rotation_payload(
            r#"{"environments":{"prod at line 7 column 2":["invalid"]}}"#,
        )
        .expect_err("environment value must be an object");

        assert_eq!(
            error,
            "environment \"prod at line 7 column 2\" must contain a key/value object"
        );
    }

    #[test]
    fn rotation_payload_streaming_validation_rejects_trailing_json() {
        let error = validate_rotation_payload(
            r#"{"environments":{"production":{"TOKEN":"secret"}}}{"environments":{"production":{"TOKEN":"other"}}}"#,
        )
        .expect_err("a second JSON value must be rejected");

        assert!(
            error.starts_with("remote vault payload is not valid JSON: trailing characters"),
            "{error}"
        );
    }

    #[test]
    fn parse_rotate_key_org_returns_none_for_personal_rotation() {
        let parsed = parse_rotate_key_org(&[]).expect("personal rotation arguments should parse");

        assert_eq!(parsed, None);
    }

    #[test]
    fn parse_rotate_key_org_accepts_separate_slug_argument() {
        let parsed = parse_rotate_key_org(&["--org", "acme"])
            .expect("separate organization slug should parse");

        assert_eq!(parsed.as_deref(), Some("acme"));
    }

    #[test]
    fn parse_rotate_key_org_accepts_equals_slug_argument() {
        let parsed =
            parse_rotate_key_org(&["--org=acme"]).expect("equals organization slug should parse");

        assert_eq!(parsed.as_deref(), Some("acme"));
    }

    #[test]
    fn parse_rotate_key_org_rejects_missing_slug() {
        let error = parse_rotate_key_org(&["--org"])
            .expect_err("organization flag without a slug must fail");

        assert!(
            error
                .to_string()
                .contains("requires exactly one organization slug")
        );
    }

    #[test]
    fn parse_rotate_key_org_rejects_duplicate_org_flags() {
        let error = parse_rotate_key_org(&["--org", "acme", "--org", "other"])
            .expect_err("duplicate organization flags must fail");

        assert!(
            error
                .to_string()
                .contains("requires exactly one organization slug")
        );
    }

    #[test]
    fn parse_rotate_key_org_rejects_an_option_as_the_separated_slug() {
        let error = parse_rotate_key_org(&[
            "--org",
            "--accept-recipient-keys=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ])
        .expect_err("another option must not become the organization slug");

        assert!(
            error
                .to_string()
                .contains("requires exactly one organization slug")
        );
    }

    #[test]
    fn parse_rotate_key_org_rejects_an_option_like_equals_slug() {
        let error = parse_rotate_key_org(&["--org=--force"])
            .expect_err("an option-like organization slug must fail");

        assert!(
            error
                .to_string()
                .contains("requires exactly one organization slug")
        );
    }

    #[test]
    fn parse_rotate_key_org_rejects_unknown_argument() {
        let error = parse_rotate_key_org(&["--force"])
            .expect_err("unsupported rotation arguments must fail");

        assert!(
            error
                .to_string()
                .contains("unknown rotate-key argument: --force")
        );
    }
}
