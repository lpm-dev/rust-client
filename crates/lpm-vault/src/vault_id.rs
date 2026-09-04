//! Vault ID management — generates and reads project vault UUIDs from lpm.json.
//!
//! Also stores optional project-local sync metadata used for vault CAS:
//! - `vaultSync.personalVersion`: last known personal cloud vault version
//! - `vaultSync.orgVersions.{slug}`: last known shared org vault version
//! - `vaultSync.personalSyncedAt` / `vaultSync.orgSyncedAt.{slug}`:
//!   RFC 3339 timestamp of the last successful sync observed by this checkout

use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultSyncSummary {
    pub synced: bool,
    pub synced_at: Option<String>,
}

#[derive(Debug, Clone, Default, serde::Deserialize)]
pub struct VaultManifestSnapshot {
    #[serde(default)]
    vault: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default, rename = "vaultSync")]
    vault_sync: Option<serde_json::Value>,
}

impl VaultManifestSnapshot {
    pub fn from_parts(
        vault: Option<String>,
        name: Option<String>,
        vault_sync: Option<serde_json::Value>,
    ) -> Self {
        Self {
            vault,
            name,
            vault_sync,
        }
    }

    pub fn read(project_dir: &Path) -> Result<Self, String> {
        let path = project_dir.join("lpm.json");
        let content = match lpm_common::read_text_file_capped(
            &path,
            lpm_common::CONFIG_FILE_SIZE_CAP_BYTES,
        ) {
            Ok(content) => content,
            Err(lpm_common::BoundedReadError::NotFound { .. }) => return Ok(Self::default()),
            Err(error) => return Err(format!("failed to read lpm.json: {error}")),
        };
        Self::parse(&content)
    }

    pub fn parse(content: &str) -> Result<Self, String> {
        serde_json::from_str(content).map_err(|error| format!("failed to parse lpm.json: {error}"))
    }

    pub fn vault_id(&self) -> Result<Option<&str>, String> {
        let Some(vault_id) = self.vault.as_deref() else {
            return Ok(None);
        };
        validate_vault_id(vault_id)?;
        Ok(Some(vault_id))
    }

    pub fn project_name(&self, project_dir: &Path) -> String {
        let package_path = project_dir.join("package.json");
        if let Ok(content) =
            lpm_common::read_text_file_capped(&package_path, lpm_common::CONFIG_FILE_SIZE_CAP_BYTES)
            && let Ok(package) = serde_json::from_str::<serde_json::Value>(&content)
            && let Some(name) = package.get("name").and_then(serde_json::Value::as_str)
        {
            return name.to_owned();
        }

        self.name.clone().unwrap_or_else(|| {
            project_dir.file_name().map_or_else(
                || "unknown".to_owned(),
                |name| name.to_string_lossy().into_owned(),
            )
        })
    }

    pub fn personal_sync_principal_for_registry(
        &self,
        registry_url: &str,
    ) -> Result<Option<String>, String> {
        let Some(sync) = self.sync_object() else {
            return Ok(None);
        };
        active_principal_for_registry(sync, SyncVersionTarget::Personal, registry_url)
    }

    pub fn org_sync_principal_for_registry(
        &self,
        org_slug: &str,
        registry_url: &str,
    ) -> Result<Option<String>, String> {
        let Some(sync) = self.sync_object() else {
            return Ok(None);
        };
        active_principal_for_registry(
            sync,
            SyncVersionTarget::Organization(org_slug),
            registry_url,
        )
    }

    pub fn personal_sync_version_for_principal(&self, principal: SyncPrincipal<'_>) -> Option<i32> {
        let sync = self.sync_object()?;
        if let Some(version) =
            authority_checkpoint_version(sync, SyncVersionTarget::Personal, principal).ok()?
        {
            return Some(version);
        }
        if !stored_sync_principal_matches(sync.get("personalBinding"), principal).ok()? {
            return None;
        }
        sync.get("personalVersion")
            .and_then(serde_json::Value::as_i64)
            .and_then(|version| i32::try_from(version).ok())
    }

    pub fn org_sync_version_for_principal(
        &self,
        org_slug: &str,
        principal: SyncPrincipal<'_>,
    ) -> Option<i32> {
        let sync = self.sync_object()?;
        if let Some(version) =
            authority_checkpoint_version(sync, SyncVersionTarget::Organization(org_slug), principal)
                .ok()?
        {
            return Some(version);
        }
        let binding = sync.get("orgBindings")?.as_object()?.get(org_slug);
        if !stored_sync_principal_matches(binding, principal).ok()? {
            return None;
        }
        sync.get("orgVersions")?
            .as_object()?
            .get(org_slug)
            .and_then(serde_json::Value::as_i64)
            .and_then(|version| i32::try_from(version).ok())
    }

    pub fn sync_summary(&self) -> VaultSyncSummary {
        let Some(sync) = self.vault_sync.as_ref() else {
            return VaultSyncSummary {
                synced: false,
                synced_at: None,
            };
        };
        sync_summary(sync)
    }

    fn sync_object(&self) -> Option<&serde_json::Map<String, serde_json::Value>> {
        self.vault_sync
            .as_ref()
            .and_then(serde_json::Value::as_object)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SyncPrincipal<'a> {
    pub registry_url: &'a str,
    pub principal_id: &'a str,
}

#[derive(Clone, Copy)]
pub(crate) enum SyncVersionTarget<'a> {
    Personal,
    Organization(&'a str),
}

#[derive(Clone, Copy)]
enum AuthorityCheckpointWritePolicy {
    RejectRollback,
    PreserveFloor,
    ResetAfterRemoteRecreation,
}

/// Read the vault ID from lpm.json, or generate one if it doesn't exist.
///
/// The vault ID is stored as `"vault": "uuid-string"` at the top level of lpm.json.
/// If lpm.json doesn't exist, creates a minimal one with just the vault field.
///
/// Existing IDs are validated by [`is_safe_vault_id`] before being
/// returned. The file-fallback vault backend joins the ID into a
/// `~/.lpm/vaults/{id}.enc` path, so an unvalidated `../` or absolute
/// path in `lpm.json["vault"]` from a malicious cloned repo would let
/// `lpm env` modify `.enc` files outside the vaults directory.
pub fn get_or_create_vault_id(project_dir: &Path) -> Result<String, String> {
    lpm_common::update_lpm_json(project_dir, |root, _| {
        if let Some(value) = root.get("vault").filter(|value| !value.is_null()) {
            let vault_id = value
                .as_str()
                .ok_or_else(|| "lpm.json vault field must be a string".to_string())?;
            validate_vault_id(vault_id)?;
            return Ok(lpm_common::LpmJsonMutation::Unchanged(vault_id.to_string()));
        }

        let vault_id = generate_uuid();
        root.insert(
            "vault".to_string(),
            serde_json::Value::String(vault_id.clone()),
        );
        Ok(lpm_common::LpmJsonMutation::Changed(vault_id))
    })
    .map(lpm_common::LpmJsonMutation::into_inner)
    .map_err(|error| error.to_string())
}

fn validate_vault_id(vault_id: &str) -> Result<(), String> {
    if is_safe_vault_id(vault_id) {
        return Ok(());
    }
    Err(format!(
        "lpm.json vault id {vault_id:?} contains path-traversal or non-portable characters; \
         refusing to use as a vault filename. Remove the `vault` field to regenerate."
    ))
}

/// Read the vault ID from lpm.json without creating one.
/// Returns `None` when the field is missing or fails [`is_safe_vault_id`].
pub fn read_vault_id(project_dir: &Path) -> Option<String> {
    let lpm_json_path = project_dir.join("lpm.json");
    let content =
        lpm_common::read_text_file_capped(&lpm_json_path, lpm_common::CONFIG_FILE_SIZE_CAP_BYTES)
            .ok()?;
    let config: serde_json::Value = serde_json::from_str(&content).ok()?;
    let raw = config.get("vault").and_then(|v| v.as_str())?;
    if !is_safe_vault_id(raw) {
        tracing::warn!(
            vault_id = %raw,
            "lpm.json vault id contains path-traversal or non-portable characters; ignoring",
        );
        return None;
    }
    Some(raw.to_string())
}

/// Validate that a `vault` field from `lpm.json` is safe to join into
/// a filesystem path. Rejects empty strings, path separators (`/` and
/// `\\`), `..`/`.` components, null bytes, anything starting with `~`,
/// and absolute Windows drive letters. Standard UUIDs and slug-shaped
/// IDs (alnum + `-` + `_`) pass.
pub fn is_safe_vault_id(id: &str) -> bool {
    if id.is_empty() || id.len() > 128 {
        return false;
    }
    if id == "." || id == ".." {
        return false;
    }
    if id.starts_with('~') {
        return false;
    }
    for c in id.chars() {
        if c.is_control() || matches!(c, '/' | '\\' | ':' | '\0') {
            return false;
        }
    }
    // Reject `..` even outside a path component. This keeps IDs portable
    // across fallback stores that can apply different path normalization.
    if id.contains("..") {
        return false;
    }
    true
}

/// Read the last known personal cloud vault version from `lpm.json`.
pub fn read_personal_sync_version(project_dir: &Path) -> Option<i32> {
    let (_, config) = read_lpm_json_value(project_dir).ok()??;

    config
        .get("vaultSync")
        .and_then(|v| v.get("personalVersion"))
        .and_then(|v| v.as_i64())
        .and_then(|v| i32::try_from(v).ok())
}

pub fn read_personal_sync_version_for_principal(
    project_dir: &Path,
    principal: SyncPrincipal<'_>,
) -> Option<i32> {
    let (_, config) = read_lpm_json_value(project_dir).ok()??;
    let sync = config.get("vaultSync")?.as_object()?;
    if let Some(version) =
        authority_checkpoint_version(sync, SyncVersionTarget::Personal, principal).ok()?
    {
        return Some(version);
    }
    if !stored_sync_principal_matches(sync.get("personalBinding"), principal).ok()? {
        return None;
    }
    sync.get("personalVersion")
        .and_then(serde_json::Value::as_i64)
        .and_then(|version| i32::try_from(version).ok())
}

pub fn read_personal_sync_principal_for_registry(
    project_dir: &Path,
    registry_url: &str,
) -> Result<Option<String>, String> {
    let Some((_, config)) = read_lpm_json_value(project_dir)? else {
        return Ok(None);
    };
    let Some(sync) = config
        .get("vaultSync")
        .and_then(serde_json::Value::as_object)
    else {
        return Ok(None);
    };
    active_principal_for_registry(sync, SyncVersionTarget::Personal, registry_url)
}

pub fn read_personal_sync_synced_at(project_dir: &Path) -> Option<String> {
    let (_, config) = read_lpm_json_value(project_dir).ok()??;

    config
        .get("vaultSync")
        .and_then(|v| v.get("personalSyncedAt"))
        .and_then(|v| v.as_str())
        .map(str::to_string)
}

/// Persist the last known personal cloud vault version in `lpm.json`.
pub fn write_personal_sync_version(project_dir: &Path, version: i32) -> Result<(), String> {
    write_personal_sync_version_at(project_dir, version, &rfc3339_now())
}

pub fn write_personal_sync_version_for_principal(
    project_dir: &Path,
    version: i32,
    principal: SyncPrincipal<'_>,
) -> Result<(), String> {
    write_personal_sync_version_for_principal_at(project_dir, version, principal, &rfc3339_now())
}

pub fn write_personal_sync_version_for_principal_if_vault_matches(
    project_dir: &Path,
    expected_vault_id: &str,
    version: i32,
    principal: SyncPrincipal<'_>,
) -> Result<(), String> {
    commit_sync_version_for_principal_if_vault_matches(
        project_dir,
        expected_vault_id,
        SyncVersionTarget::Personal,
        version,
        principal,
        || Ok(()),
    )
}

/// Persist the first revision of a recreated personal cloud env for its retained principal.
pub fn write_recreated_personal_sync_version_for_principal_if_vault_matches(
    project_dir: &Path,
    expected_vault_id: &str,
    version: i32,
    principal: SyncPrincipal<'_>,
) -> Result<(), String> {
    write_recreated_sync_version_for_principal_if_vault_matches(
        project_dir,
        expected_vault_id,
        SyncVersionTarget::Personal,
        version,
        principal,
    )
}

pub fn write_personal_sync_version_for_principal_at(
    project_dir: &Path,
    version: i32,
    principal: SyncPrincipal<'_>,
    synced_at: &str,
) -> Result<(), String> {
    validate_sync_principal(principal)?;
    lpm_common::update_lpm_json(project_dir, |root, _| {
        let sync = object_entry(root, "vaultSync")?;
        let unbound_floor = legacy_unbound_floor(sync, SyncVersionTarget::Personal)?;
        migrate_legacy_authority_checkpoints(sync)?;
        reject_sync_principal_conflict(sync, SyncVersionTarget::Personal, principal)?;
        let current =
            authority_checkpoint_floor(sync, SyncVersionTarget::Personal, principal.registry_url)?
                .or(unbound_floor);
        reject_sync_version_rollback(current, version)?;
        upsert_authority_checkpoint(
            sync,
            SyncVersionTarget::Personal,
            principal,
            version,
            synced_at,
            AuthorityCheckpointWritePolicy::RejectRollback,
        )?;
        sync.insert("personalVersion".into(), serde_json::json!(version));
        sync.insert(
            "personalSyncedAt".into(),
            serde_json::json!(synced_at.to_string()),
        );
        sync.insert("personalBinding".into(), sync_principal_value(principal)?);
        Ok(lpm_common::LpmJsonMutation::Changed(()))
    })
    .map(|_| ())
    .map_err(|error| error.to_string())
}

pub fn write_personal_sync_version_at(
    project_dir: &Path,
    version: i32,
    synced_at: &str,
) -> Result<(), String> {
    lpm_common::update_lpm_json(project_dir, |root, _| {
        let sync = object_entry(root, "vaultSync")?;
        reject_sync_version_rollback(
            optional_sync_version(sync.get("personalVersion"), "personalVersion")?,
            version,
        )?;
        sync.insert("personalVersion".into(), serde_json::json!(version));
        sync.insert(
            "personalSyncedAt".into(),
            serde_json::json!(synced_at.to_string()),
        );
        Ok(lpm_common::LpmJsonMutation::Changed(()))
    })
    .map(|_| ())
    .map_err(|error| error.to_string())
}

/// Read the last known org-shared cloud vault version for an org slug.
pub fn read_org_sync_version(project_dir: &Path, org_slug: &str) -> Option<i32> {
    let (_, config) = read_lpm_json_value(project_dir).ok()??;

    config
        .get("vaultSync")
        .and_then(|v| v.get("orgVersions"))
        .and_then(|v| v.get(org_slug))
        .and_then(|v| v.as_i64())
        .and_then(|v| i32::try_from(v).ok())
}

pub fn read_org_sync_version_for_principal(
    project_dir: &Path,
    org_slug: &str,
    principal: SyncPrincipal<'_>,
) -> Option<i32> {
    let (_, config) = read_lpm_json_value(project_dir).ok()??;
    let sync = config.get("vaultSync")?.as_object()?;
    if let Some(version) =
        authority_checkpoint_version(sync, SyncVersionTarget::Organization(org_slug), principal)
            .ok()?
    {
        return Some(version);
    }
    let binding = sync.get("orgBindings")?.as_object()?.get(org_slug);
    if !stored_sync_principal_matches(binding, principal).ok()? {
        return None;
    }
    sync.get("orgVersions")?
        .as_object()?
        .get(org_slug)
        .and_then(serde_json::Value::as_i64)
        .and_then(|version| i32::try_from(version).ok())
}

pub fn read_org_sync_principal_for_registry(
    project_dir: &Path,
    org_slug: &str,
    registry_url: &str,
) -> Result<Option<String>, String> {
    let Some((_, config)) = read_lpm_json_value(project_dir)? else {
        return Ok(None);
    };
    let Some(sync) = config
        .get("vaultSync")
        .and_then(serde_json::Value::as_object)
    else {
        return Ok(None);
    };
    active_principal_for_registry(
        sync,
        SyncVersionTarget::Organization(org_slug),
        registry_url,
    )
}

pub fn read_org_sync_synced_at(project_dir: &Path, org_slug: &str) -> Option<String> {
    let (_, config) = read_lpm_json_value(project_dir).ok()??;

    config
        .get("vaultSync")
        .and_then(|v| v.get("orgSyncedAt"))
        .and_then(|v| v.get(org_slug))
        .and_then(|v| v.as_str())
        .map(str::to_string)
}

/// Persist the last known org-shared cloud vault version for an org slug.
pub fn write_org_sync_version(
    project_dir: &Path,
    org_slug: &str,
    version: i32,
) -> Result<(), String> {
    write_org_sync_version_at(project_dir, org_slug, version, &rfc3339_now())
}

pub fn write_org_sync_version_for_principal(
    project_dir: &Path,
    org_slug: &str,
    version: i32,
    principal: SyncPrincipal<'_>,
) -> Result<(), String> {
    write_org_sync_version_for_principal_at(
        project_dir,
        org_slug,
        version,
        principal,
        &rfc3339_now(),
    )
}

pub fn write_org_sync_version_for_principal_if_vault_matches(
    project_dir: &Path,
    expected_vault_id: &str,
    org_slug: &str,
    version: i32,
    principal: SyncPrincipal<'_>,
) -> Result<(), String> {
    commit_sync_version_for_principal_if_vault_matches(
        project_dir,
        expected_vault_id,
        SyncVersionTarget::Organization(org_slug),
        version,
        principal,
        || Ok(()),
    )
}

/// Persist the first revision of a recreated organization cloud env for its retained principal.
pub fn write_recreated_org_sync_version_for_principal_if_vault_matches(
    project_dir: &Path,
    expected_vault_id: &str,
    org_slug: &str,
    version: i32,
    principal: SyncPrincipal<'_>,
) -> Result<(), String> {
    write_recreated_sync_version_for_principal_if_vault_matches(
        project_dir,
        expected_vault_id,
        SyncVersionTarget::Organization(org_slug),
        version,
        principal,
    )
}

pub fn write_org_sync_version_for_principal_at(
    project_dir: &Path,
    org_slug: &str,
    version: i32,
    principal: SyncPrincipal<'_>,
    synced_at: &str,
) -> Result<(), String> {
    validate_sync_principal(principal)?;
    lpm_common::update_lpm_json(project_dir, |root, _| {
        let sync = object_entry(root, "vaultSync")?;
        let target = SyncVersionTarget::Organization(org_slug);
        let unbound_floor = legacy_unbound_floor(sync, target)?;
        migrate_legacy_authority_checkpoints(sync)?;
        reject_sync_principal_conflict(sync, target, principal)?;
        let current =
            authority_checkpoint_floor(sync, target, principal.registry_url)?.or(unbound_floor);
        reject_sync_version_rollback(current, version)?;
        upsert_authority_checkpoint(
            sync,
            target,
            principal,
            version,
            synced_at,
            AuthorityCheckpointWritePolicy::RejectRollback,
        )?;
        let org_versions = object_entry(sync, "orgVersions")?;
        org_versions.insert(org_slug.to_string(), serde_json::json!(version));
        object_entry(sync, "orgSyncedAt")?
            .insert(org_slug.to_string(), serde_json::json!(synced_at));
        object_entry(sync, "orgBindings")?
            .insert(org_slug.to_string(), sync_principal_value(principal)?);
        Ok(lpm_common::LpmJsonMutation::Changed(()))
    })
    .map(|_| ())
    .map_err(|error| error.to_string())
}

pub fn write_org_sync_version_at(
    project_dir: &Path,
    org_slug: &str,
    version: i32,
    synced_at: &str,
) -> Result<(), String> {
    lpm_common::update_lpm_json(project_dir, |root, _| {
        let sync = object_entry(root, "vaultSync")?;
        let org_versions = object_entry(sync, "orgVersions")?;
        reject_sync_version_rollback(
            optional_sync_version(org_versions.get(org_slug), "orgVersions entry")?,
            version,
        )?;
        org_versions.insert(org_slug.to_string(), serde_json::json!(version));
        let org_synced_at = object_entry(sync, "orgSyncedAt")?;
        org_synced_at.insert(org_slug.to_string(), serde_json::json!(synced_at));
        Ok(lpm_common::LpmJsonMutation::Changed(()))
    })
    .map(|_| ())
    .map_err(|error| error.to_string())
}

fn validate_sync_principal(principal: SyncPrincipal<'_>) -> Result<(), String> {
    canonical_registry_url(principal.registry_url)?;
    if principal.principal_id.is_empty()
        || principal.principal_id.len() > 128
        || principal.principal_id.chars().any(char::is_control)
    {
        return Err("sync principal ID is missing or invalid".to_owned());
    }
    Ok(())
}

fn canonical_registry_url(registry_url: &str) -> Result<String, String> {
    if registry_url.is_empty()
        || registry_url.len() > 2048
        || registry_url.chars().any(char::is_control)
    {
        return Err("sync registry URL is missing or invalid".to_owned());
    }
    let mut parsed = reqwest::Url::parse(registry_url)
        .map_err(|_| "sync registry URL is missing or invalid".to_owned())?;
    if !matches!(parsed.scheme(), "http" | "https")
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Err("sync registry URL is missing or invalid".to_owned());
    }
    let normalized_path = parsed.path().trim_end_matches('/').to_owned();
    parsed.set_path(&normalized_path);
    Ok(parsed.as_str().trim_end_matches('/').to_owned())
}

fn sync_principal_value(principal: SyncPrincipal<'_>) -> Result<serde_json::Value, String> {
    Ok(serde_json::json!({
        "registryUrl": canonical_registry_url(principal.registry_url)?,
        "principalId": principal.principal_id,
    }))
}

fn stored_sync_principal_matches(
    value: Option<&serde_json::Value>,
    principal: SyncPrincipal<'_>,
) -> Result<bool, String> {
    let Some(value) = value.filter(|value| !value.is_null()) else {
        return Ok(false);
    };
    let object = value
        .as_object()
        .ok_or("lpm.json vaultSync principal binding must be an object")?;
    let registry_url = object
        .get("registryUrl")
        .and_then(serde_json::Value::as_str)
        .ok_or("lpm.json vaultSync principal binding registryUrl must be a string")?;
    let principal_id = object
        .get("principalId")
        .and_then(serde_json::Value::as_str)
        .ok_or("lpm.json vaultSync principal binding principalId must be a string")?;
    Ok(
        canonical_registry_url(registry_url)? == canonical_registry_url(principal.registry_url)?
            && principal_id == principal.principal_id,
    )
}

fn active_sync_binding(
    sync: &serde_json::Map<String, serde_json::Value>,
    target: SyncVersionTarget<'_>,
) -> Result<Option<(String, String)>, String> {
    let binding = match target {
        SyncVersionTarget::Personal => sync.get("personalBinding"),
        SyncVersionTarget::Organization(slug) => sync
            .get("orgBindings")
            .filter(|value| !value.is_null())
            .map(|value| {
                value
                    .as_object()
                    .ok_or("lpm.json vaultSync orgBindings must be an object")
            })
            .transpose()?
            .and_then(|bindings| bindings.get(slug)),
    };
    binding
        .filter(|value| !value.is_null())
        .map(parse_stored_sync_principal)
        .transpose()
}

fn active_principal_for_registry(
    sync: &serde_json::Map<String, serde_json::Value>,
    target: SyncVersionTarget<'_>,
    registry_url: &str,
) -> Result<Option<String>, String> {
    let expected_registry = canonical_registry_url(registry_url)?;
    let active_principal =
        active_sync_binding(sync, target)?.and_then(|(stored_registry, principal_id)| {
            (stored_registry == expected_registry).then_some(principal_id)
        });
    validate_authority_checkpoints(sync)?;
    let checkpoint_principals = sync
        .get(AUTHORITY_CHECKPOINTS_FIELD)
        .and_then(serde_json::Value::as_object)
        .map(|scopes| checkpoint_registries(scopes, target))
        .transpose()?
        .flatten()
        .and_then(|registries| registries.get(&expected_registry))
        .and_then(serde_json::Value::as_object);
    let checkpoint_principal = match checkpoint_principals {
        Some(principals) if principals.len() > 1 => {
            return Err(
                "this env checkout records different accounts for the same Registry and scope; use a separate checkout"
                    .to_owned(),
            );
        }
        Some(principals) => principals.keys().next().cloned(),
        None => None,
    };
    if active_principal
        .as_ref()
        .zip(checkpoint_principal.as_ref())
        .is_some_and(|(active, checkpoint)| active != checkpoint)
    {
        return Err(
            "this env checkout records different accounts for the same Registry and scope; use a separate checkout"
                .to_owned(),
        );
    }
    Ok(active_principal.or(checkpoint_principal))
}

fn reject_sync_principal_conflict(
    sync: &serde_json::Map<String, serde_json::Value>,
    target: SyncVersionTarget<'_>,
    principal: SyncPrincipal<'_>,
) -> Result<(), String> {
    let Some(active_principal) =
        active_principal_for_registry(sync, target, principal.registry_url)?
    else {
        return Ok(());
    };
    if active_principal == principal.principal_id {
        return Ok(());
    }
    Err(
		"this env checkout is bound to a different account for this Registry and scope; use a separate checkout when switching accounts"
			.to_owned(),
	)
}

const MAX_SYNC_AUTHORITY_CHECKPOINTS: usize = 64;
const AUTHORITY_CHECKPOINTS_FIELD: &str = "authorityCheckpoints";
const PERSONAL_AUTHORITY_CHECKPOINTS_FIELD: &str = "personal";
const ORGANIZATION_AUTHORITY_CHECKPOINTS_FIELD: &str = "organizations";

fn validate_checkpoint_organization_slug(slug: &str) -> Result<(), String> {
    if slug.is_empty() || slug.len() > 128 || slug.chars().any(char::is_control) {
        return Err(
            "lpm.json vaultSync authority checkpoint organization slug is invalid".to_owned(),
        );
    }
    Ok(())
}

fn checkpoint_registries<'a>(
    scopes: &'a serde_json::Map<String, serde_json::Value>,
    target: SyncVersionTarget<'_>,
) -> Result<Option<&'a serde_json::Map<String, serde_json::Value>>, String> {
    let value = match target {
        SyncVersionTarget::Personal => scopes.get(PERSONAL_AUTHORITY_CHECKPOINTS_FIELD),
        SyncVersionTarget::Organization(slug) => {
            validate_checkpoint_organization_slug(slug)?;
            scopes
                .get(ORGANIZATION_AUTHORITY_CHECKPOINTS_FIELD)
                .filter(|value| !value.is_null())
                .map(|value| {
                    value.as_object().ok_or(
                        "lpm.json vaultSync authority checkpoint organizations must be an object",
                    )
                })
                .transpose()?
                .and_then(|organizations| organizations.get(slug))
        }
    };
    value
        .filter(|value| !value.is_null())
        .map(|value| {
            value.as_object().ok_or(
                "lpm.json vaultSync authority checkpoint registries must be an object".into(),
            )
        })
        .transpose()
}

fn checkpoint_registries_mut<'a>(
    scopes: &'a mut serde_json::Map<String, serde_json::Value>,
    target: SyncVersionTarget<'_>,
) -> Result<&'a mut serde_json::Map<String, serde_json::Value>, String> {
    match target {
        SyncVersionTarget::Personal => object_entry(scopes, PERSONAL_AUTHORITY_CHECKPOINTS_FIELD),
        SyncVersionTarget::Organization(slug) => {
            validate_checkpoint_organization_slug(slug)?;
            object_entry(
                object_entry(scopes, ORGANIZATION_AUTHORITY_CHECKPOINTS_FIELD)?,
                slug,
            )
        }
    }
}

fn validate_checkpoint_registries(
    registries_value: &serde_json::Value,
    count: &mut usize,
) -> Result<(), String> {
    let registries = registries_value
        .as_object()
        .ok_or("lpm.json vaultSync authority checkpoint registries must be an object")?;
    for (registry_url, principals_value) in registries {
        if canonical_registry_url(registry_url)? != *registry_url {
            return Err(
                "lpm.json vaultSync authority checkpoint registry URL is not canonical".to_owned(),
            );
        }
        let principals = principals_value
            .as_object()
            .ok_or("lpm.json vaultSync authority checkpoint principals must be an object")?;
        for (principal_id, checkpoint_value) in principals {
            validate_sync_principal(SyncPrincipal {
                registry_url,
                principal_id,
            })?;
            let checkpoint = checkpoint_value
                .as_object()
                .ok_or("lpm.json vaultSync authority checkpoint must be an object")?;
            let version =
                optional_sync_version(checkpoint.get("version"), "authority checkpoint version")?
                    .ok_or("lpm.json vaultSync authority checkpoint version is required")?;
            if version <= 0 {
                return Err(
                    "lpm.json vaultSync authority checkpoint version must be positive".to_owned(),
                );
            }
            if checkpoint
                .get("syncedAt")
                .is_some_and(|value| !value.is_string())
            {
                return Err(
                    "lpm.json vaultSync authority checkpoint syncedAt must be a string".to_owned(),
                );
            }
            *count = count
                .checked_add(1)
                .ok_or("lpm.json vaultSync authority checkpoint count overflowed")?;
        }
    }
    Ok(())
}

fn validate_authority_checkpoints(
    sync: &serde_json::Map<String, serde_json::Value>,
) -> Result<usize, String> {
    let Some(value) = sync
        .get(AUTHORITY_CHECKPOINTS_FIELD)
        .filter(|value| !value.is_null())
    else {
        return Ok(0);
    };
    let scopes = value
        .as_object()
        .ok_or("lpm.json vaultSync authority checkpoints must be an object")?;
    let mut count = 0usize;
    for (scope, scope_value) in scopes {
        match scope.as_str() {
            PERSONAL_AUTHORITY_CHECKPOINTS_FIELD => {
                validate_checkpoint_registries(scope_value, &mut count)?;
            }
            ORGANIZATION_AUTHORITY_CHECKPOINTS_FIELD => {
                let organizations = scope_value.as_object().ok_or(
                    "lpm.json vaultSync authority checkpoint organizations must be an object",
                )?;
                for (slug, registries_value) in organizations {
                    validate_checkpoint_organization_slug(slug)?;
                    validate_checkpoint_registries(registries_value, &mut count)?;
                }
            }
            _ => {
                return Err("lpm.json vaultSync authority checkpoint scope is invalid".to_owned());
            }
        }
    }
    if count > MAX_SYNC_AUTHORITY_CHECKPOINTS {
        return Err(format!(
            "lpm.json vaultSync exceeds the {MAX_SYNC_AUTHORITY_CHECKPOINTS}-authority checkpoint limit"
        ));
    }
    Ok(count)
}

fn authority_checkpoint_version(
    sync: &serde_json::Map<String, serde_json::Value>,
    target: SyncVersionTarget<'_>,
    principal: SyncPrincipal<'_>,
) -> Result<Option<i32>, String> {
    validate_sync_principal(principal)?;
    validate_authority_checkpoints(sync)?;
    let registry_url = canonical_registry_url(principal.registry_url)?;
    let Some(scopes) = sync
        .get(AUTHORITY_CHECKPOINTS_FIELD)
        .and_then(serde_json::Value::as_object)
    else {
        return Ok(None);
    };
    let Some(checkpoint) = checkpoint_registries(scopes, target)?
        .and_then(|registries| registries.get(&registry_url))
        .and_then(serde_json::Value::as_object)
        .and_then(|principals| principals.get(principal.principal_id))
        .and_then(serde_json::Value::as_object)
    else {
        return Ok(None);
    };
    optional_sync_version(checkpoint.get("version"), "authority checkpoint version")
}

fn authority_checkpoint_floor(
    sync: &serde_json::Map<String, serde_json::Value>,
    target: SyncVersionTarget<'_>,
    registry_url: &str,
) -> Result<Option<i32>, String> {
    validate_authority_checkpoints(sync)?;
    let registry_url = canonical_registry_url(registry_url)?;
    let Some(scopes) = sync
        .get(AUTHORITY_CHECKPOINTS_FIELD)
        .and_then(serde_json::Value::as_object)
    else {
        return Ok(None);
    };
    let Some(principals) = checkpoint_registries(scopes, target)?
        .and_then(|registries| registries.get(&registry_url))
        .and_then(serde_json::Value::as_object)
    else {
        return Ok(None);
    };
    principals.values().try_fold(None, |floor, checkpoint| {
        let version = optional_sync_version(
            checkpoint
                .as_object()
                .ok_or("lpm.json vaultSync authority checkpoint must be an object")?
                .get("version"),
            "authority checkpoint version",
        )?
        .ok_or("lpm.json vaultSync authority checkpoint version is required")?;
        Ok(Some(
            floor.map_or(version, |current: i32| current.max(version)),
        ))
    })
}

fn upsert_authority_checkpoint(
    sync: &mut serde_json::Map<String, serde_json::Value>,
    target: SyncVersionTarget<'_>,
    principal: SyncPrincipal<'_>,
    version: i32,
    synced_at: &str,
    policy: AuthorityCheckpointWritePolicy,
) -> Result<(), String> {
    validate_sync_principal(principal)?;
    if version <= 0 {
        return Err("cloud env version must be positive".to_owned());
    }
    let checkpoint_count = validate_authority_checkpoints(sync)?;
    let registry_url = canonical_registry_url(principal.registry_url)?;
    let scopes = object_entry(sync, AUTHORITY_CHECKPOINTS_FIELD)?;
    let registries = checkpoint_registries_mut(scopes, target)?;
    let principals = object_entry(registries, &registry_url)?;
    if let Some(existing) = principals.get_mut(principal.principal_id) {
        let checkpoint = existing
            .as_object_mut()
            .ok_or("lpm.json vaultSync authority checkpoint must be an object")?;
        let current =
            optional_sync_version(checkpoint.get("version"), "authority checkpoint version")?
                .ok_or("lpm.json vaultSync authority checkpoint version is required")?;
        if version < current {
            match policy {
                AuthorityCheckpointWritePolicy::RejectRollback => {
                    return reject_sync_version_rollback(Some(current), version);
                }
                AuthorityCheckpointWritePolicy::PreserveFloor => return Ok(()),
                AuthorityCheckpointWritePolicy::ResetAfterRemoteRecreation => {}
            }
        }
        checkpoint.insert("version".to_owned(), serde_json::json!(version));
        checkpoint.insert("syncedAt".to_owned(), serde_json::json!(synced_at));
        return Ok(());
    }
    if checkpoint_count >= MAX_SYNC_AUTHORITY_CHECKPOINTS {
        return Err(format!(
            "lpm.json vaultSync reached the {MAX_SYNC_AUTHORITY_CHECKPOINTS}-authority checkpoint limit"
        ));
    }
    principals.insert(
        principal.principal_id.to_owned(),
        serde_json::json!({
            "version": version,
            "syncedAt": synced_at,
        }),
    );
    Ok(())
}

fn parse_stored_sync_principal(value: &serde_json::Value) -> Result<(String, String), String> {
    let object = value
        .as_object()
        .ok_or("lpm.json vaultSync principal binding must be an object")?;
    let registry_url = object
        .get("registryUrl")
        .and_then(serde_json::Value::as_str)
        .ok_or("lpm.json vaultSync principal binding registryUrl must be a string")?;
    let principal_id = object
        .get("principalId")
        .and_then(serde_json::Value::as_str)
        .ok_or("lpm.json vaultSync principal binding principalId must be a string")?;
    validate_sync_principal(SyncPrincipal {
        registry_url,
        principal_id,
    })?;
    Ok((
        canonical_registry_url(registry_url)?,
        principal_id.to_owned(),
    ))
}

fn migrate_legacy_authority_checkpoints(
    sync: &mut serde_json::Map<String, serde_json::Value>,
) -> Result<(), String> {
    let mut legacy = Vec::new();
    if let Some(binding) = sync.get("personalBinding").filter(|value| !value.is_null())
        && let Some(version) =
            optional_sync_version(sync.get("personalVersion"), "personalVersion")?
    {
        let (registry_url, principal_id) = parse_stored_sync_principal(binding)?;
        let synced_at = sync
            .get("personalSyncedAt")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .to_owned();
        legacy.push((None, registry_url, principal_id, version, synced_at));
    }
    if let Some(bindings_value) = sync.get("orgBindings").filter(|value| !value.is_null()) {
        let bindings = bindings_value
            .as_object()
            .ok_or("lpm.json vaultSync orgBindings must be an object")?;
        for (slug, binding) in bindings {
            let Some(version) = sync
                .get("orgVersions")
                .and_then(serde_json::Value::as_object)
                .map(|versions| optional_sync_version(versions.get(slug), "orgVersions entry"))
                .transpose()?
                .flatten()
            else {
                continue;
            };
            let (registry_url, principal_id) = parse_stored_sync_principal(binding)?;
            let synced_at = sync
                .get("orgSyncedAt")
                .and_then(serde_json::Value::as_object)
                .and_then(|entries| entries.get(slug))
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default()
                .to_owned();
            legacy.push((
                Some(slug.to_owned()),
                registry_url,
                principal_id,
                version,
                synced_at,
            ));
        }
    }

    for (org_slug, registry_url, principal_id, version, synced_at) in legacy {
        let target = org_slug
            .as_deref()
            .map_or(SyncVersionTarget::Personal, SyncVersionTarget::Organization);
        upsert_authority_checkpoint(
            sync,
            target,
            SyncPrincipal {
                registry_url: &registry_url,
                principal_id: &principal_id,
            },
            version,
            &synced_at,
            AuthorityCheckpointWritePolicy::PreserveFloor,
        )?;
    }
    Ok(())
}

fn legacy_unbound_floor(
    sync: &serde_json::Map<String, serde_json::Value>,
    target: SyncVersionTarget<'_>,
) -> Result<Option<i32>, String> {
    match target {
        SyncVersionTarget::Personal => {
            if sync
                .get("personalBinding")
                .is_some_and(|value| !value.is_null())
            {
                return Ok(None);
            }
            optional_sync_version(sync.get("personalVersion"), "personalVersion")
        }
        SyncVersionTarget::Organization(slug) => {
            let binding = match sync.get("orgBindings").filter(|value| !value.is_null()) {
                Some(value) => Some(
                    value
                        .as_object()
                        .ok_or("lpm.json vaultSync orgBindings must be an object")?
                        .get(slug),
                ),
                None => None,
            }
            .flatten();
            if binding.is_some_and(|value| !value.is_null()) {
                return Ok(None);
            }
            let version = sync
                .get("orgVersions")
                .and_then(serde_json::Value::as_object)
                .map(|versions| optional_sync_version(versions.get(slug), "orgVersions entry"))
                .transpose()?
                .flatten();
            Ok(version)
        }
    }
}

pub(crate) fn commit_sync_version_if_vault_matches(
    project_dir: &Path,
    expected_vault_id: &str,
    target: SyncVersionTarget<'_>,
    version: i32,
    commit: impl FnOnce() -> Result<(), String>,
) -> Result<(), String> {
    commit_sync_version_if_vault_matches_inner(
        project_dir,
        expected_vault_id,
        target,
        version,
        None,
        commit,
    )
}

pub(crate) fn commit_sync_version_for_principal_if_vault_matches(
    project_dir: &Path,
    expected_vault_id: &str,
    target: SyncVersionTarget<'_>,
    version: i32,
    principal: SyncPrincipal<'_>,
    commit: impl FnOnce() -> Result<(), String>,
) -> Result<(), String> {
    validate_sync_principal(principal)?;
    commit_sync_version_if_vault_matches_inner(
        project_dir,
        expected_vault_id,
        target,
        version,
        Some(principal),
        commit,
    )
}

fn write_recreated_sync_version_for_principal_if_vault_matches(
    project_dir: &Path,
    expected_vault_id: &str,
    target: SyncVersionTarget<'_>,
    version: i32,
    principal: SyncPrincipal<'_>,
) -> Result<(), String> {
    validate_vault_id(expected_vault_id)?;
    validate_sync_principal(principal)?;
    let synced_at = rfc3339_now();
    lpm_common::update_lpm_json(project_dir, |root, _| {
        if root.get("vault").and_then(serde_json::Value::as_str) != Some(expected_vault_id) {
            return Err(
                "the project vault ID changed while the cloud operation was in flight".to_owned(),
            );
        }

        let sync = object_entry(root, "vaultSync")?;
        migrate_legacy_authority_checkpoints(sync)?;
        if active_principal_for_registry(sync, target, principal.registry_url)?.as_deref()
            != Some(principal.principal_id)
        {
            return Err(
                "a recreated cloud env can reset only the retained checkpoint for its bound principal"
                    .to_owned(),
            );
        }
        upsert_authority_checkpoint(
            sync,
            target,
            principal,
            version,
            &synced_at,
            AuthorityCheckpointWritePolicy::ResetAfterRemoteRecreation,
        )?;

        match target {
            SyncVersionTarget::Personal => {
                sync.insert("personalVersion".to_owned(), serde_json::json!(version));
                sync.insert(
                    "personalSyncedAt".to_owned(),
                    serde_json::json!(synced_at),
                );
                sync.insert("personalBinding".to_owned(), sync_principal_value(principal)?);
            }
            SyncVersionTarget::Organization(slug) => {
                object_entry(sync, "orgVersions")?
                    .insert(slug.to_owned(), serde_json::json!(version));
                object_entry(sync, "orgSyncedAt")?
                    .insert(slug.to_owned(), serde_json::json!(synced_at));
                object_entry(sync, "orgBindings")?
                    .insert(slug.to_owned(), sync_principal_value(principal)?);
            }
        }
        Ok(lpm_common::LpmJsonMutation::Changed(()))
    })
    .map(|_| ())
    .map_err(|error| error.to_string())
}

fn commit_sync_version_if_vault_matches_inner(
    project_dir: &Path,
    expected_vault_id: &str,
    target: SyncVersionTarget<'_>,
    version: i32,
    principal: Option<SyncPrincipal<'_>>,
    commit: impl FnOnce() -> Result<(), String>,
) -> Result<(), String> {
    validate_vault_id(expected_vault_id)?;
    let synced_at = rfc3339_now();
    let mut commit = Some(commit);
    let mut commit_executed = false;
    let mut previous_sync = None;
    let mut committed_sync = None;
    let update_result = lpm_common::update_lpm_json(project_dir, |root, _| {
        let current_vault_id = root.get("vault").and_then(|value| value.as_str());
        if current_vault_id != Some(expected_vault_id) {
            return Err(
                "the project vault ID changed while the cloud operation was in flight".to_owned(),
            );
        }
        previous_sync = Some(root.get("vaultSync").cloned());
        let sync = object_entry(root, "vaultSync")?;
        let current_version = if let Some(principal) = principal {
            let unbound_floor = legacy_unbound_floor(sync, target)?;
            migrate_legacy_authority_checkpoints(sync)?;
            reject_sync_principal_conflict(sync, target, principal)?;
            authority_checkpoint_floor(sync, target, principal.registry_url)?.or(unbound_floor)
        } else {
            match target {
                SyncVersionTarget::Personal => {
                    optional_sync_version(sync.get("personalVersion"), "personalVersion")?
                }
                SyncVersionTarget::Organization(slug) => optional_sync_version(
                    object_entry(sync, "orgVersions")?.get(slug),
                    "orgVersions entry",
                )?,
            }
        };
        reject_sync_version_rollback(current_version, version)?;
        if let Some(principal) = principal {
            upsert_authority_checkpoint(
                sync,
                target,
                principal,
                version,
                &synced_at,
                AuthorityCheckpointWritePolicy::RejectRollback,
            )?;
        }
        match target {
            SyncVersionTarget::Personal => {
                sync.insert("personalVersion".into(), serde_json::json!(version));
                sync.insert(
                    "personalSyncedAt".into(),
                    serde_json::json!(synced_at.clone()),
                );
                if let Some(principal) = principal {
                    sync.insert("personalBinding".into(), sync_principal_value(principal)?);
                }
            }
            SyncVersionTarget::Organization(slug) => {
                object_entry(sync, "orgVersions")?
                    .insert(slug.to_owned(), serde_json::json!(version));
                object_entry(sync, "orgSyncedAt")?
                    .insert(slug.to_owned(), serde_json::json!(synced_at.clone()));
                if let Some(principal) = principal {
                    object_entry(sync, "orgBindings")?
                        .insert(slug.to_owned(), sync_principal_value(principal)?);
                }
            }
        }
        committed_sync = Some(root.get("vaultSync").cloned());

        let commit = commit
            .take()
            .ok_or_else(|| "cloud operation commit was invoked more than once".to_owned())?;
        commit()?;
        commit_executed = true;
        Ok(lpm_common::LpmJsonMutation::Changed(()))
    });

    match update_result {
        Ok(_) => Ok(()),
        Err(error) if !commit_executed => Err(error.to_string()),
        Err(error) => {
            let metadata_error = error.to_string();
            let previous_sync = previous_sync.flatten();
            let committed_sync = committed_sync.flatten();
            let rollback = lpm_common::update_lpm_json(project_dir, |root, _| {
                if root.get("vault").and_then(|value| value.as_str()) != Some(expected_vault_id) {
                    return Err(
                        "the project vault ID changed before sync metadata rollback".to_owned()
                    );
                }
                let current_sync = root.get("vaultSync").cloned();
                if current_sync == previous_sync {
                    return Ok(lpm_common::LpmJsonMutation::Unchanged(()));
                }
                if current_sync != committed_sync {
                    return Err(
                        "sync metadata changed concurrently; refusing to overwrite it during rollback"
                            .to_owned(),
                    );
                }
                match &previous_sync {
                    Some(value) => {
                        root.insert("vaultSync".to_owned(), value.clone());
                    }
                    None => {
                        root.remove("vaultSync");
                    }
                }
                Ok(lpm_common::LpmJsonMutation::Changed(()))
            });
            match rollback {
                Ok(_) => Err(metadata_error),
                Err(rollback_error) => Err(format!(
                    "{metadata_error}; sync metadata rollback also failed: {rollback_error}"
                )),
            }
        }
    }
}

fn optional_sync_version(
    value: Option<&serde_json::Value>,
    field_name: &str,
) -> Result<Option<i32>, String> {
    let Some(value) = value.filter(|value| !value.is_null()) else {
        return Ok(None);
    };
    value
        .as_i64()
        .and_then(|version| i32::try_from(version).ok())
        .map(Some)
        .ok_or_else(|| format!("lpm.json vaultSync.{field_name} must be a 32-bit integer"))
}

fn reject_sync_version_rollback(current: Option<i32>, proposed: i32) -> Result<(), String> {
    if let Some(current) = current
        && proposed < current
    {
        return Err(format!(
            "cloud env version {proposed} is older than the durable local version {current}"
        ));
    }
    Ok(())
}

pub fn read_sync_summary(project_dir: &Path) -> VaultSyncSummary {
    let Some((_, config)) = read_lpm_json_value(project_dir).ok().flatten() else {
        return VaultSyncSummary {
            synced: false,
            synced_at: None,
        };
    };
    let Some(sync) = config.get("vaultSync") else {
        return VaultSyncSummary {
            synced: false,
            synced_at: None,
        };
    };

    sync_summary(sync)
}

fn sync_summary(sync: &serde_json::Value) -> VaultSyncSummary {
    let personal_synced = sync
        .get("personalVersion")
        .and_then(|v| v.as_i64())
        .is_some();
    let org_synced = sync
        .get("orgVersions")
        .and_then(|v| v.as_object())
        .is_some_and(|versions| versions.values().any(|version| version.as_i64().is_some()));

    let synced_at = sync
        .get("personalSyncedAt")
        .and_then(|v| v.as_str())
        .into_iter()
        .chain(
            sync.get("orgSyncedAt")
                .and_then(|v| v.as_object())
                .into_iter()
                .flat_map(|entries| entries.values().filter_map(|v| v.as_str())),
        )
        .max()
        .map(str::to_string);

    VaultSyncSummary {
        synced: personal_synced || org_synced,
        synced_at,
    }
}

/// Get the project name from package.json or lpm.json.
pub fn read_project_name(project_dir: &Path) -> String {
    // Try package.json first
    let pkg_path = project_dir.join("package.json");
    if let Ok(content) =
        lpm_common::read_text_file_capped(&pkg_path, lpm_common::CONFIG_FILE_SIZE_CAP_BYTES)
        && let Ok(pkg) = serde_json::from_str::<serde_json::Value>(&content)
        && let Some(name) = pkg.get("name").and_then(|v| v.as_str())
    {
        return name.to_string();
    }

    // Try lpm.json
    let lpm_path = project_dir.join("lpm.json");
    if let Ok(content) =
        lpm_common::read_text_file_capped(&lpm_path, lpm_common::CONFIG_FILE_SIZE_CAP_BYTES)
        && let Ok(cfg) = serde_json::from_str::<serde_json::Value>(&content)
        && let Some(name) = cfg.get("name").and_then(|v| v.as_str())
    {
        return name.to_string();
    }

    // Fall back to directory name
    project_dir.file_name().map_or_else(
        || "unknown".to_string(),
        |n| n.to_string_lossy().to_string(),
    )
}

/// Generate a UUID v4 string without external dependencies.
fn generate_uuid() -> String {
    let mut bytes = [0u8; 16];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut bytes);

    // Set version 4 and variant bits
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;

    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0],
        bytes[1],
        bytes[2],
        bytes[3],
        bytes[4],
        bytes[5],
        bytes[6],
        bytes[7],
        bytes[8],
        bytes[9],
        bytes[10],
        bytes[11],
        bytes[12],
        bytes[13],
        bytes[14],
        bytes[15]
    )
}

fn read_lpm_json_value(project_dir: &Path) -> Result<Option<(PathBuf, serde_json::Value)>, String> {
    let lpm_json_path = project_dir.join("lpm.json");
    let content = match lpm_common::read_text_file_capped(
        &lpm_json_path,
        lpm_common::CONFIG_FILE_SIZE_CAP_BYTES,
    ) {
        Ok(content) => content,
        Err(lpm_common::BoundedReadError::NotFound { .. }) => return Ok(None),
        Err(error) => return Err(format!("failed to read lpm.json: {error}")),
    };
    let config =
        serde_json::from_str(&content).map_err(|e| format!("failed to parse lpm.json: {e}"))?;

    Ok(Some((lpm_json_path, config)))
}

fn object_entry<'a>(
    parent: &'a mut serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Result<&'a mut serde_json::Map<String, serde_json::Value>, String> {
    let value = parent
        .entry(key.to_string())
        .or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()));
    if value.is_null() {
        *value = serde_json::Value::Object(serde_json::Map::new());
    }
    value
        .as_object_mut()
        .ok_or_else(|| format!("lpm.json {key} field must be an object"))
}

fn rfc3339_now() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    format_rfc3339(secs)
}

fn format_rfc3339(epoch_secs: u64) -> String {
    const SECS_PER_DAY: u64 = 86_400;
    let days = epoch_secs / SECS_PER_DAY;
    let time_of_day = epoch_secs % SECS_PER_DAY;
    let h = (time_of_day / 3600) as u32;
    let m = ((time_of_day % 3600) / 60) as u32;
    let s = (time_of_day % 60) as u32;

    let z = days as i64 + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m_civil = if mp < 10 { mp + 3 } else { mp - 9 };
    let y_civil = if m_civil <= 2 { y + 1 } else { y };

    format!("{y_civil:04}-{m_civil:02}-{d:02}T{h:02}:{m:02}:{s:02}Z")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_uuid_format() {
        let uuid = generate_uuid();
        assert_eq!(uuid.len(), 36);
        assert_eq!(uuid.chars().filter(|c| *c == '-').count(), 4);
        // Version 4 marker
        assert_eq!(&uuid[14..15], "4");
    }

    #[test]
    fn get_or_create_vault_id_creates_lpm_json() {
        let dir = tempfile::tempdir().unwrap();
        let vault_id = get_or_create_vault_id(dir.path()).unwrap();
        assert_eq!(vault_id.len(), 36);

        // File should exist now
        let content = std::fs::read_to_string(dir.path().join("lpm.json")).unwrap();
        let config: serde_json::Value = serde_json::from_str(&content).unwrap();
        assert_eq!(config["vault"].as_str().unwrap(), vault_id);
        assert!(content.ends_with('\n'));
    }

    #[test]
    fn get_or_create_vault_id_preserves_existing() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("lpm.json"),
            r#"{"runtime": {"node": "22"}, "vault": "existing-id-123"}"#,
        )
        .unwrap();

        let vault_id = get_or_create_vault_id(dir.path()).unwrap();
        assert_eq!(vault_id, "existing-id-123");

        // runtime field should still be there
        let content = std::fs::read_to_string(dir.path().join("lpm.json")).unwrap();
        let config: serde_json::Value = serde_json::from_str(&content).unwrap();
        assert_eq!(config["runtime"]["node"].as_str().unwrap(), "22");
    }

    #[test]
    fn get_or_create_vault_id_adds_to_existing_config() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("lpm.json"),
            r#"{"runtime": {"node": "22"}}"#,
        )
        .unwrap();

        let vault_id = get_or_create_vault_id(dir.path()).unwrap();
        assert_eq!(vault_id.len(), 36);

        // Both fields should exist
        let content = std::fs::read_to_string(dir.path().join("lpm.json")).unwrap();
        let config: serde_json::Value = serde_json::from_str(&content).unwrap();
        assert!(config.get("vault").is_some());
        assert!(config.get("runtime").is_some());
        assert!(content.ends_with('\n'));
    }

    #[test]
    fn read_vault_id_returns_none_when_missing() {
        let dir = tempfile::tempdir().unwrap();
        assert!(read_vault_id(dir.path()).is_none());
    }

    #[test]
    fn read_project_name_from_package_json() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("package.json"),
            r#"{"name": "my-api-server"}"#,
        )
        .unwrap();

        assert_eq!(read_project_name(dir.path()), "my-api-server");
    }

    #[test]
    fn read_project_name_fallback_to_dir() {
        let dir = tempfile::tempdir().unwrap();
        let name = read_project_name(dir.path());
        // tempdir creates something like /tmp/.tmpXXXXXX — just check it's not empty
        assert!(!name.is_empty());
    }

    #[test]
    fn personal_sync_version_round_trips_without_clobbering_existing_fields() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("lpm.json"),
            r#"{"runtime":{"node":"22"},"vault":"vault-123"}"#,
        )
        .unwrap();

        write_personal_sync_version_at(dir.path(), 7, "2026-05-31T08:00:00Z").unwrap();

        assert_eq!(read_personal_sync_version(dir.path()), Some(7));
        assert_eq!(
            read_personal_sync_synced_at(dir.path()).as_deref(),
            Some("2026-05-31T08:00:00Z")
        );

        let content = std::fs::read_to_string(dir.path().join("lpm.json")).unwrap();
        let config: serde_json::Value = serde_json::from_str(&content).unwrap();
        assert_eq!(config["runtime"]["node"], "22");
        assert_eq!(config["vault"], "vault-123");
        assert_eq!(config["vaultSync"]["personalVersion"], 7);
        assert_eq!(
            config["vaultSync"]["personalSyncedAt"],
            "2026-05-31T08:00:00Z"
        );
        assert!(content.ends_with('\n'));
    }

    #[test]
    fn vault_mutations_reject_wrong_shaped_fields_without_modifying_them() {
        let cases = [
            (r#"{"vault":{}}"#, "vault"),
            (r#"{"vaultSync":[]}"#, "vaultSync"),
            (r#"{"vaultSync":{"orgVersions":"wrong"}}"#, "orgVersions"),
        ];

        for (input, field) in cases {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("lpm.json");
            std::fs::write(&path, input).unwrap();

            let result = match field {
                "vault" => get_or_create_vault_id(dir.path()).map(|_| ()),
                "vaultSync" => {
                    write_personal_sync_version_at(dir.path(), 1, "2026-08-13T09:00:00Z")
                }
                _ => write_org_sync_version_at(dir.path(), "acme", 1, "2026-08-13T09:00:00Z"),
            };

            let error = result.expect_err("malformed owned field must be rejected");
            assert!(error.contains(field), "{field}: {error}");
            assert_eq!(std::fs::read_to_string(path).unwrap(), input);
        }
    }

    #[test]
    fn vault_mutations_treat_null_optional_fields_as_missing() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("lpm.json"),
            r#"{"vault":null,"vaultSync":null,"custom":true}"#,
        )
        .unwrap();

        let vault_id = get_or_create_vault_id(dir.path()).unwrap();
        write_personal_sync_version_at(dir.path(), 3, "2026-08-13T09:00:00Z").unwrap();
        let config: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(dir.path().join("lpm.json")).unwrap())
                .unwrap();

        assert_eq!(config["vault"], vault_id);
        assert_eq!(config["vaultSync"]["personalVersion"], 3);
        assert_eq!(config["custom"], true);
    }

    #[test]
    fn org_sync_versions_are_scoped_by_slug() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("lpm.json"), r#"{"vault":"vault-123"}"#).unwrap();

        write_org_sync_version_at(dir.path(), "acme", 4, "2026-05-31T08:00:00Z").unwrap();
        write_org_sync_version_at(dir.path(), "umbrella", 9, "2026-05-31T08:01:00Z").unwrap();

        assert_eq!(read_org_sync_version(dir.path(), "acme"), Some(4));
        assert_eq!(read_org_sync_version(dir.path(), "umbrella"), Some(9));
        assert_eq!(read_org_sync_version(dir.path(), "missing"), None);
        assert_eq!(
            read_org_sync_synced_at(dir.path(), "acme").as_deref(),
            Some("2026-05-31T08:00:00Z")
        );
        assert_eq!(
            read_org_sync_synced_at(dir.path(), "umbrella").as_deref(),
            Some("2026-05-31T08:01:00Z")
        );
    }

    #[test]
    fn personal_sync_version_write_rejects_rollback_without_modifying_metadata() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("lpm.json"), r#"{"vault":"vault-123"}"#).unwrap();
        write_personal_sync_version_at(dir.path(), 5, "2026-08-13T09:00:00Z").unwrap();
        let before = std::fs::read(dir.path().join("lpm.json")).unwrap();

        let error = write_personal_sync_version_at(dir.path(), 4, "2026-08-13T09:01:00Z")
            .expect_err("personal sync metadata must not move backward");

        assert!(error.contains("older"), "{error}");
        assert_eq!(std::fs::read(dir.path().join("lpm.json")).unwrap(), before);
    }

    #[test]
    fn recreated_personal_vault_advances_only_the_matching_authority_checkpoint() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("lpm.json"), r#"{"vault":"vault-123"}"#).unwrap();
        let account = SyncPrincipal {
            registry_url: "https://lpm.dev",
            principal_id: "user-a",
        };
        let other_registry = SyncPrincipal {
            registry_url: "https://registry.example",
            principal_id: "user-a",
        };
        write_personal_sync_version_for_principal_at(
            dir.path(),
            5,
            account,
            "2026-09-04T08:00:00Z",
        )
        .unwrap();
        write_personal_sync_version_for_principal_at(
            dir.path(),
            9,
            other_registry,
            "2026-09-04T08:01:00Z",
        )
        .unwrap();

        write_personal_sync_version_for_principal_if_vault_matches(
            dir.path(),
            "vault-123",
            6,
            account,
        )
        .unwrap();

        assert_eq!(
            read_personal_sync_version_for_principal(dir.path(), account),
            Some(6),
        );
        assert_eq!(
            read_personal_sync_version_for_principal(dir.path(), other_registry),
            Some(9),
        );
    }

    #[test]
    fn recreated_organization_vault_advances_only_the_matching_authority_checkpoint() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("lpm.json"), r#"{"vault":"vault-123"}"#).unwrap();
        let organization = SyncPrincipal {
            registry_url: "https://lpm.dev",
            principal_id: "organization-a",
        };
        let other_registry = SyncPrincipal {
            registry_url: "https://registry.example",
            principal_id: "organization-a",
        };
        let other_organization = SyncPrincipal {
            registry_url: "https://lpm.dev",
            principal_id: "organization-b",
        };
        write_org_sync_version_for_principal_at(
            dir.path(),
            "acme",
            5,
            organization,
            "2026-09-04T08:00:00Z",
        )
        .unwrap();
        write_org_sync_version_for_principal_at(
            dir.path(),
            "acme",
            9,
            other_registry,
            "2026-09-04T08:01:00Z",
        )
        .unwrap();
        write_org_sync_version_for_principal_at(
            dir.path(),
            "other",
            7,
            other_organization,
            "2026-09-04T08:02:00Z",
        )
        .unwrap();

        write_org_sync_version_for_principal_if_vault_matches(
            dir.path(),
            "vault-123",
            "acme",
            6,
            organization,
        )
        .unwrap();

        assert_eq!(
            read_org_sync_version_for_principal(dir.path(), "acme", organization),
            Some(6),
        );
        assert_eq!(
            read_org_sync_version_for_principal(dir.path(), "acme", other_registry),
            Some(9),
        );
        assert_eq!(
            read_org_sync_version_for_principal(dir.path(), "other", other_organization),
            Some(7),
        );
    }

    #[test]
    fn scoped_personal_floor_migrates_legacy_fail_closed_and_retains_authorities() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("lpm.json"),
            r#"{"vault":"vault-123","vaultSync":{"personalVersion":99}}"#,
        )
        .unwrap();
        let account_a = SyncPrincipal {
            registry_url: "https://lpm.dev/",
            principal_id: "user-a",
        };

        assert_eq!(
            read_personal_sync_version_for_principal(dir.path(), account_a),
            None
        );
        let before_legacy_rollback = std::fs::read(dir.path().join("lpm.json")).unwrap();
        let legacy_error = write_personal_sync_version_for_principal_at(
            dir.path(),
            4,
            account_a,
            "2026-09-03T12:00:00Z",
        )
        .expect_err("unbound legacy metadata must remain a fail-closed rollback floor");
        assert!(legacy_error.contains("older"), "{legacy_error}");
        assert_eq!(
            std::fs::read(dir.path().join("lpm.json")).unwrap(),
            before_legacy_rollback,
        );
        write_personal_sync_version_for_principal_at(
            dir.path(),
            100,
            account_a,
            "2026-09-03T12:00:00Z",
        )
        .unwrap();
        assert_eq!(
            read_personal_sync_version_for_principal(
                dir.path(),
                SyncPrincipal {
                    registry_url: "https://lpm.dev",
                    principal_id: "user-a",
                },
            ),
            Some(100),
            "equivalent Registry URLs must resolve to one authority scope",
        );
        assert_eq!(
            read_personal_sync_version_for_principal(
                dir.path(),
                SyncPrincipal {
                    registry_url: "https://lpm.dev",
                    principal_id: "user-b",
                },
            ),
            None,
        );
        assert_eq!(
            read_personal_sync_version_for_principal(
                dir.path(),
                SyncPrincipal {
                    registry_url: "https://registry.example",
                    principal_id: "user-a",
                },
            ),
            None,
        );

        let before_principal_switch = std::fs::read(dir.path().join("lpm.json")).unwrap();
        let principal_error = write_personal_sync_version_for_principal_at(
            dir.path(),
            101,
            SyncPrincipal {
                registry_url: "https://lpm.dev",
                principal_id: "user-b",
            },
            "2026-09-03T12:01:00Z",
        )
        .expect_err("a different principal must not replace the active local binding");
        assert!(
            principal_error.contains("different account"),
            "{principal_error}"
        );
        assert_eq!(
            std::fs::read(dir.path().join("lpm.json")).unwrap(),
            before_principal_switch,
        );
        assert_eq!(
            read_personal_sync_version_for_principal(dir.path(), account_a),
            Some(100),
            "switching principals must retain the earlier rollback floor",
        );
        let other_registry = SyncPrincipal {
            registry_url: "https://registry.example",
            principal_id: "user-a",
        };
        write_personal_sync_version_for_principal_at(
            dir.path(),
            3,
            other_registry,
            "2026-09-03T12:01:30Z",
        )
        .unwrap();
        assert_eq!(
            read_personal_sync_version_for_principal(dir.path(), other_registry),
            Some(3),
        );
        assert_eq!(
            read_personal_sync_version_for_principal(dir.path(), account_a),
            Some(100),
        );
        let before_rollback = std::fs::read(dir.path().join("lpm.json")).unwrap();
        let error = write_personal_sync_version_for_principal_at(
            dir.path(),
            99,
            account_a,
            "2026-09-03T12:02:00Z",
        )
        .expect_err("returning to an earlier principal must preserve its floor");
        assert!(error.contains("older"), "{error}");
        assert_eq!(
            std::fs::read(dir.path().join("lpm.json")).unwrap(),
            before_rollback,
        );
    }

    #[test]
    fn conflicting_personal_checkpoint_principals_fail_closed() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("lpm.json"),
            r#"{
                "vault": "vault-123",
                "vaultSync": {
                    "personalVersion": 2,
                    "personalBinding": {
                        "registryUrl": "https://lpm.dev",
                        "principalId": "user-b"
                    },
                    "authorityCheckpoints": {
                        "personal": {
                            "https://lpm.dev": {
                                "user-a": {
                                    "version": 100,
                                    "syncedAt": "2026-09-03T12:00:00Z"
                                },
                                "user-b": {
                                    "version": 2,
                                    "syncedAt": "2026-09-03T12:01:00Z"
                                }
                            }
                        }
                    }
                }
            }"#,
        )
        .unwrap();
        let before = std::fs::read(dir.path().join("lpm.json")).unwrap();

        let error = write_personal_sync_version_for_principal_at(
            dir.path(),
            99,
            SyncPrincipal {
                registry_url: "https://lpm.dev",
                principal_id: "user-b",
            },
            "2026-09-03T12:02:00Z",
        )
        .expect_err("ambiguous Registry principal history must fail closed");

        assert!(error.contains("different accounts"), "{error}");
        assert_eq!(std::fs::read(dir.path().join("lpm.json")).unwrap(), before);
    }

    #[test]
    fn registry_detour_cannot_replace_a_personal_principal() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("lpm.json"), r#"{"vault":"vault-123"}"#).unwrap();
        let registry_a_principal = SyncPrincipal {
            registry_url: "https://registry-a.example",
            principal_id: "account-a",
        };
        write_personal_sync_version_for_principal_at(
            dir.path(),
            10,
            registry_a_principal,
            "2026-09-04T12:00:00Z",
        )
        .unwrap();
        write_personal_sync_version_for_principal_at(
            dir.path(),
            2,
            SyncPrincipal {
                registry_url: "https://registry-b.example",
                principal_id: "account-b",
            },
            "2026-09-04T12:01:00Z",
        )
        .unwrap();

        assert_eq!(
            read_personal_sync_principal_for_registry(
                dir.path(),
                registry_a_principal.registry_url,
            )
            .unwrap(),
            Some(registry_a_principal.principal_id.to_owned()),
            "the retained checkpoint must bind a Registry that is no longer active",
        );
        let before = std::fs::read(dir.path().join("lpm.json")).unwrap();
        let error = write_personal_sync_version_for_principal_at(
            dir.path(),
            11,
            SyncPrincipal {
                registry_url: registry_a_principal.registry_url,
                principal_id: "account-substitute",
            },
            "2026-09-04T12:02:00Z",
        )
        .expect_err("a Registry detour must not permit personal principal substitution");

        assert!(error.contains("different account"), "{error}");
        assert_eq!(std::fs::read(dir.path().join("lpm.json")).unwrap(), before);
    }

    #[test]
    fn authority_checkpoint_capacity_fails_closed_without_evicting_floors() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("lpm.json"), r#"{"vault":"vault-123"}"#).unwrap();
        for index in 0..MAX_SYNC_AUTHORITY_CHECKPOINTS {
            let principal_id = format!("user-{index}");
            let registry_url = format!("https://registry-{index}.example");
            write_personal_sync_version_for_principal_at(
                dir.path(),
                1,
                SyncPrincipal {
                    registry_url: &registry_url,
                    principal_id: &principal_id,
                },
                "2026-09-03T12:00:00Z",
            )
            .unwrap();
        }
        let before = std::fs::read(dir.path().join("lpm.json")).unwrap();
        let error = write_personal_sync_version_for_principal_at(
            dir.path(),
            1,
            SyncPrincipal {
                registry_url: "https://registry-overflow.example",
                principal_id: "one-too-many",
            },
            "2026-09-03T12:01:00Z",
        )
        .expect_err("checkpoint capacity must not evict an existing rollback floor");
        assert!(error.contains("checkpoint limit"), "{error}");
        assert_eq!(std::fs::read(dir.path().join("lpm.json")).unwrap(), before);
        assert_eq!(
            read_personal_sync_version_for_principal(
                dir.path(),
                SyncPrincipal {
                    registry_url: "https://registry-0.example",
                    principal_id: "user-0",
                },
            ),
            Some(1),
        );
    }

    #[test]
    fn scoped_organization_binding_rejects_a_reused_slug_under_a_different_principal() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("lpm.json"), r#"{"vault":"vault-123"}"#).unwrap();
        let old_org = SyncPrincipal {
            registry_url: "https://lpm.dev",
            principal_id: "org-old",
        };
        let new_org = SyncPrincipal {
            registry_url: "https://lpm.dev",
            principal_id: "org-new",
        };
        write_org_sync_version_for_principal_at(
            dir.path(),
            "acme",
            12,
            old_org,
            "2026-09-03T12:00:00Z",
        )
        .unwrap();

        let before_principal_switch = std::fs::read(dir.path().join("lpm.json")).unwrap();
        let principal_error = write_org_sync_version_for_principal_at(
            dir.path(),
            "acme",
            13,
            new_org,
            "2026-09-03T12:01:00Z",
        )
        .expect_err("a reused slug must not silently replace the active organization binding");

        assert!(
            principal_error.contains("different account"),
            "{principal_error}"
        );
        assert_eq!(
            std::fs::read(dir.path().join("lpm.json")).unwrap(),
            before_principal_switch,
        );
        assert_eq!(
            read_org_sync_version_for_principal(dir.path(), "acme", old_org),
            Some(12),
        );
        assert_eq!(
            read_org_sync_version_for_principal(dir.path(), "acme", new_org),
            None,
        );
        let before_rollback = std::fs::read(dir.path().join("lpm.json")).unwrap();
        let error = write_org_sync_version_for_principal_at(
            dir.path(),
            "acme",
            11,
            old_org,
            "2026-09-03T12:02:00Z",
        )
        .expect_err("a reused slug must not erase the old organization's floor");
        assert!(error.contains("older"), "{error}");
        assert_eq!(
            std::fs::read(dir.path().join("lpm.json")).unwrap(),
            before_rollback,
        );
    }

    #[test]
    fn organization_checkpoint_floors_are_independent_across_slugs() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("lpm.json"), r#"{"vault":"vault-123"}"#).unwrap();
        let acme = SyncPrincipal {
            registry_url: "https://lpm.dev",
            principal_id: "org-acme",
        };
        let umbrella = SyncPrincipal {
            registry_url: "https://lpm.dev",
            principal_id: "org-umbrella",
        };

        write_org_sync_version_for_principal_at(
            dir.path(),
            "acme",
            50,
            acme,
            "2026-09-04T12:00:00Z",
        )
        .unwrap();
        write_org_sync_version_for_principal_at(
            dir.path(),
            "umbrella",
            1,
            umbrella,
            "2026-09-04T12:01:00Z",
        )
        .expect("an independent organization must not inherit another slug's rollback floor");

        assert_eq!(
            read_org_sync_version_for_principal(dir.path(), "acme", acme),
            Some(50),
        );
        assert_eq!(
            read_org_sync_version_for_principal(dir.path(), "umbrella", umbrella),
            Some(1),
        );
    }

    #[test]
    fn registry_detour_cannot_replace_an_organization_principal() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("lpm.json"), r#"{"vault":"vault-123"}"#).unwrap();
        let registry_a_principal = SyncPrincipal {
            registry_url: "https://registry-a.example",
            principal_id: "organization-a",
        };
        write_org_sync_version_for_principal_at(
            dir.path(),
            "acme",
            10,
            registry_a_principal,
            "2026-09-04T12:00:00Z",
        )
        .unwrap();
        write_org_sync_version_for_principal_at(
            dir.path(),
            "acme",
            2,
            SyncPrincipal {
                registry_url: "https://registry-b.example",
                principal_id: "organization-b",
            },
            "2026-09-04T12:01:00Z",
        )
        .unwrap();

        assert_eq!(
            read_org_sync_principal_for_registry(
                dir.path(),
                "acme",
                registry_a_principal.registry_url,
            )
            .unwrap(),
            Some(registry_a_principal.principal_id.to_owned()),
            "the retained checkpoint must bind an organization Registry that is no longer active",
        );
        let before = std::fs::read(dir.path().join("lpm.json")).unwrap();
        let error = write_org_sync_version_for_principal_at(
            dir.path(),
            "acme",
            11,
            SyncPrincipal {
                registry_url: registry_a_principal.registry_url,
                principal_id: "organization-substitute",
            },
            "2026-09-04T12:02:00Z",
        )
        .expect_err("a Registry detour must not permit organization principal substitution");

        assert!(error.contains("different account"), "{error}");
        assert_eq!(std::fs::read(dir.path().join("lpm.json")).unwrap(), before);
    }

    #[test]
    fn conflicting_organization_checkpoint_principals_fail_closed() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("lpm.json"),
            r#"{
                "vault": "vault-123",
                "vaultSync": {
                    "orgVersions": { "acme": 2 },
                    "orgBindings": {
                        "acme": {
                            "registryUrl": "https://lpm.dev",
                            "principalId": "org-current"
                        }
                    },
                    "authorityCheckpoints": {
                        "organizations": {
                            "acme": {
                                "https://lpm.dev": {
                                    "org-previous": {
                                        "version": 50,
                                        "syncedAt": "2026-09-04T12:00:00Z"
                                    },
                                    "org-current": {
                                        "version": 2,
                                        "syncedAt": "2026-09-04T12:01:00Z"
                                    }
                                }
                            }
                        }
                    }
                }
            }"#,
        )
        .unwrap();
        let before = std::fs::read(dir.path().join("lpm.json")).unwrap();

        let error = write_org_sync_version_for_principal_at(
            dir.path(),
            "acme",
            49,
            SyncPrincipal {
                registry_url: "https://lpm.dev",
                principal_id: "org-current",
            },
            "2026-09-04T12:02:00Z",
        )
        .expect_err("ambiguous organization principal history must fail closed");

        assert!(error.contains("different accounts"), "{error}");
        assert_eq!(std::fs::read(dir.path().join("lpm.json")).unwrap(), before);
    }

    #[test]
    fn organization_sync_version_write_rejects_rollback_without_modifying_metadata() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("lpm.json"), r#"{"vault":"vault-123"}"#).unwrap();
        write_org_sync_version_at(dir.path(), "acme", 5, "2026-08-13T09:00:00Z").unwrap();
        let before = std::fs::read(dir.path().join("lpm.json")).unwrap();

        let error = write_org_sync_version_at(dir.path(), "acme", 4, "2026-08-13T09:01:00Z")
            .expect_err("organization sync metadata must not move backward");

        assert!(error.contains("older"), "{error}");
        assert_eq!(std::fs::read(dir.path().join("lpm.json")).unwrap(), before);
    }

    #[test]
    fn is_safe_vault_id_accepts_uuids_and_slugs() {
        assert!(is_safe_vault_id("550e8400-e29b-41d4-a716-446655440000"));
        assert!(is_safe_vault_id("my-vault"));
        assert!(is_safe_vault_id("vault_v2"));
        assert!(is_safe_vault_id("abc123"));
    }

    #[test]
    fn is_safe_vault_id_rejects_path_traversal_and_separators() {
        assert!(!is_safe_vault_id(""));
        assert!(!is_safe_vault_id("."));
        assert!(!is_safe_vault_id(".."));
        assert!(!is_safe_vault_id("../escape"));
        assert!(!is_safe_vault_id("foo/bar"));
        assert!(!is_safe_vault_id("foo\\bar"));
        assert!(!is_safe_vault_id("/etc/passwd"));
        assert!(!is_safe_vault_id("~/.lpm/vaults/x"));
        assert!(!is_safe_vault_id("vault\0null"));
        assert!(!is_safe_vault_id("foo..bar"));
        // 129 chars — over the limit
        assert!(!is_safe_vault_id(&"a".repeat(129)));
    }

    /// End-to-end: a malicious lpm.json vault id is refused by
    /// get_or_create_vault_id rather than blindly used to join a
    /// `.enc` write path.
    #[test]
    fn get_or_create_vault_id_refuses_path_traversal_value() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("lpm.json"),
            r#"{"vault": "../../etc/escape"}"#,
        )
        .unwrap();
        let err =
            get_or_create_vault_id(dir.path()).expect_err("malicious vault id must be refused");
        assert!(err.contains("path-traversal"), "got: {err}");
    }

    #[test]
    fn read_vault_id_returns_none_for_malicious_value() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("lpm.json"), r#"{"vault": "/etc/secret"}"#).unwrap();
        assert!(read_vault_id(dir.path()).is_none());
    }

    #[test]
    fn sync_version_writes_reject_metadata_drift_without_modifying_the_file() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("lpm.json"),
            r#"{"runtime":{"node":"22"},"vault":"vault-123","vaultSync":{"personalVersion":5,"orgVersions":"drifted"}}"#,
        )
        .unwrap();

        let before = std::fs::read_to_string(dir.path().join("lpm.json")).unwrap();
        let error = write_org_sync_version_at(dir.path(), "acme", 9, "2026-05-31T08:00:00Z")
            .expect_err("wrong-shaped orgVersions must be rejected");

        assert!(error.contains("orgVersions"), "{error}");
        assert_eq!(
            std::fs::read_to_string(dir.path().join("lpm.json")).unwrap(),
            before
        );
    }

    #[test]
    fn sync_summary_reports_any_synced_vault_and_latest_timestamp() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("lpm.json"), r#"{"vault":"vault-123"}"#).unwrap();

        assert_eq!(
            read_sync_summary(dir.path()),
            VaultSyncSummary {
                synced: false,
                synced_at: None
            }
        );

        write_personal_sync_version_at(dir.path(), 2, "2026-05-31T08:00:00Z").unwrap();
        write_org_sync_version_at(dir.path(), "acme", 4, "2026-05-31T08:03:00Z").unwrap();

        assert_eq!(
            read_sync_summary(dir.path()),
            VaultSyncSummary {
                synced: true,
                synced_at: Some("2026-05-31T08:03:00Z".to_string())
            }
        );
    }

    #[test]
    fn format_rfc3339_known_epoch() {
        assert_eq!(format_rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(format_rfc3339(946_684_800), "2000-01-01T00:00:00Z");
        assert_eq!(format_rfc3339(1_775_910_896), "2026-04-11T12:34:56Z");
    }
}
