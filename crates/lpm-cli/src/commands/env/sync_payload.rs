use super::prelude::*;

pub(super) struct CloudManifestSnapshot {
    pub config: Option<lpm_runner::lpm_json::LpmJsonConfig>,
    pub vault: lpm_vault::vault_id::VaultManifestSnapshot,
    pub sources: Option<std::sync::Arc<lpm_env_source::SchemaSnapshot>>,
}

impl CloudManifestSnapshot {
    pub fn read(project_dir: &std::path::Path) -> Result<Self, LpmError> {
        let content = match lpm_common::read_text_file_capped(
            &project_dir.join("lpm.json"),
            lpm_common::CONFIG_FILE_SIZE_CAP_BYTES,
        ) {
            Ok(content) => Some(content),
            Err(lpm_common::BoundedReadError::NotFound { .. }) => None,
            Err(error) => {
                return Err(LpmError::Script(format!(
                    "failed to read lpm.json: {error}"
                )));
            }
        };
        let config = content
            .as_deref()
            .map(|content| lpm_runner::lpm_json::parse_lpm_json_in(project_dir, content))
            .transpose()
            .map_err(LpmError::Script)?;
        let sources = match (&content, &config) {
            (Some(content), Some(config)) => Some(match &config.env_schema_resolution {
                Some(snapshot) => std::sync::Arc::clone(snapshot),
                None => {
                    lpm_env_source::resolve_schema(
                        project_dir,
                        content.as_bytes(),
                        lpm_env::EnvSchemaDefinition::default(),
                    )
                    .map_err(|error| LpmError::Script(error.to_string()))?
                    .snapshot
                }
            }),
            _ => None,
        };
        let vault = match config.as_ref() {
            Some(config) => {
                let vault_sync = config
                    .vault_sync
                    .as_ref()
                    .map(serde_json::to_value)
                    .transpose()
                    .map_err(|error| {
                        LpmError::Script(format!(
                            "failed to retain validated lpm.json sync metadata: {error}"
                        ))
                    })?;
                lpm_vault::vault_id::VaultManifestSnapshot::from_parts(
                    config.vault.clone(),
                    config.name.clone(),
                    vault_sync,
                )
            }
            None => lpm_vault::vault_id::VaultManifestSnapshot::default(),
        };
        Ok(Self {
            config,
            vault,
            sources,
        })
    }
}

pub(super) fn verify_schema_snapshot(
    project_dir: &std::path::Path,
    snapshot: Option<&lpm_env_source::SchemaSnapshot>,
) -> Result<(), String> {
    let Some(snapshot) = snapshot else {
        return Ok(());
    };
    let content = lpm_common::read_text_file_capped(
        &project_dir.join("lpm.json"),
        lpm_common::CONFIG_FILE_SIZE_CAP_BYTES,
    )
    .map_err(|_| "env.source_changed at lpm.json/envSchema".to_string())?;
    verify_schema_snapshot_content(snapshot, &content)
}

fn verify_schema_snapshot_content(
    snapshot: &lpm_env_source::SchemaSnapshot,
    content: &str,
) -> Result<(), String> {
    if !snapshot.matches_root_content(content.as_bytes()) {
        return Err("env.source_changed at lpm.json/envSchema".into());
    }
    snapshot
        .verify_dependencies()
        .map_err(|error| error.to_string())
}

pub(super) fn verify_personal_mutation_snapshot(
    project_dir: &std::path::Path,
    expected_vault_id: &str,
    registry_url: &str,
    expected_principal_id: Option<&str>,
    sources: &lpm_env_source::SchemaSnapshot,
) -> Result<(), String> {
    let content = read_mutation_manifest_content(project_dir)?;
    let manifest = lpm_vault::vault_id::VaultManifestSnapshot::parse(
        lpm_common::strip_utf8_bom_str(&content),
    )?;
    verify_personal_mutation_manifest(
        &manifest,
        expected_vault_id,
        registry_url,
        expected_principal_id,
    )?;
    verify_schema_snapshot_content(sources, &content)
}

pub(super) fn verify_org_mutation_snapshot(
    project_dir: &std::path::Path,
    expected_vault_id: &str,
    org_slug: &str,
    registry_url: &str,
    expected_principal_id: Option<&str>,
    sources: &lpm_env_source::SchemaSnapshot,
) -> Result<(), String> {
    let content = read_mutation_manifest_content(project_dir)?;
    let manifest = lpm_vault::vault_id::VaultManifestSnapshot::parse(
        lpm_common::strip_utf8_bom_str(&content),
    )?;
    verify_org_mutation_manifest(
        &manifest,
        expected_vault_id,
        org_slug,
        registry_url,
        expected_principal_id,
    )?;
    verify_schema_snapshot_content(sources, &content)
}

fn read_mutation_manifest_content(project_dir: &std::path::Path) -> Result<String, String> {
    lpm_common::read_text_file_capped(
        &project_dir.join("lpm.json"),
        lpm_common::CONFIG_FILE_SIZE_CAP_BYTES,
    )
    .map_err(|error| format!("failed to read lpm.json: {error}"))
}

pub(super) fn fresh_personal_mutation_manifest(
    project_dir: &std::path::Path,
    expected_vault_id: &str,
    registry_url: &str,
    expected_principal_id: Option<&str>,
) -> Result<lpm_vault::vault_id::VaultManifestSnapshot, String> {
    let manifest = lpm_vault::vault_id::VaultManifestSnapshot::read(project_dir)?;
    verify_personal_mutation_manifest(
        &manifest,
        expected_vault_id,
        registry_url,
        expected_principal_id,
    )?;
    Ok(manifest)
}

fn verify_personal_mutation_manifest(
    manifest: &lpm_vault::vault_id::VaultManifestSnapshot,
    expected_vault_id: &str,
    registry_url: &str,
    expected_principal_id: Option<&str>,
) -> Result<(), String> {
    verify_fresh_vault_id(manifest, expected_vault_id)?;
    let current_principal = manifest.personal_expected_principal_for_registry(registry_url)?;
    if current_principal.as_deref() != expected_principal_id {
        return Err("the personal env manifest principal changed before the cloud write".into());
    }
    Ok(())
}

pub(super) fn fresh_org_mutation_manifest(
    project_dir: &std::path::Path,
    expected_vault_id: &str,
    org_slug: &str,
    registry_url: &str,
    expected_principal_id: Option<&str>,
) -> Result<lpm_vault::vault_id::VaultManifestSnapshot, String> {
    let manifest = lpm_vault::vault_id::VaultManifestSnapshot::read(project_dir)?;
    verify_org_mutation_manifest(
        &manifest,
        expected_vault_id,
        org_slug,
        registry_url,
        expected_principal_id,
    )?;
    Ok(manifest)
}

fn verify_org_mutation_manifest(
    manifest: &lpm_vault::vault_id::VaultManifestSnapshot,
    expected_vault_id: &str,
    org_slug: &str,
    registry_url: &str,
    expected_principal_id: Option<&str>,
) -> Result<(), String> {
    verify_fresh_vault_id(manifest, expected_vault_id)?;
    let current_principal = manifest.org_sync_principal_for_registry(org_slug, registry_url)?;
    if current_principal.as_deref() != expected_principal_id {
        return Err(
            "the organization env manifest principal changed before the cloud write".into(),
        );
    }
    Ok(())
}

fn verify_fresh_vault_id(
    manifest: &lpm_vault::vault_id::VaultManifestSnapshot,
    expected_vault_id: &str,
) -> Result<(), String> {
    let current_vault_id = manifest
        .vault_id()?
        .ok_or("the env manifest removed its vault before the cloud write")?;
    if current_vault_id != expected_vault_id {
        return Err("the env manifest changed to another vault before the cloud write".into());
    }
    Ok(())
}

pub(super) fn build_sync_payload(
    environments: HashMap<String, HashMap<String, String>>,
) -> Result<String, LpmError> {
    #[derive(serde::Serialize)]
    struct SyncPayload {
        environments: HashMap<String, HashMap<String, String>>,
    }
    serde_json::to_string(&SyncPayload { environments })
        .map_err(|error| LpmError::Script(format!("failed to serialize: {error}")))
}

pub(super) fn parse_remote_pull_payload_for_overwrite(
    raw_json: &str,
) -> Result<HashMap<String, HashMap<String, String>>, String> {
    serde_json::from_str::<RemotePullPayload>(raw_json)
        .map(|payload| payload.environments)
        .map_err(|_| "failed to parse pulled vault data".to_string())
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RemotePullPayload {
    environments: HashMap<String, HashMap<String, String>>,
}

/// Read `lpm.json` for an `lpm env push` surface (personal or org).
///
/// Returns `Ok(Some(config))` on a clean parse and `Ok(None)` when the file is
/// absent. Syntax, read, and semantic-validation failures are errors because
/// aliases and schema metadata participate in the pushed payload.
pub(super) fn personal_sync_checkpoint_warnings(
    local_key_checkpoint_failed: bool,
    manifest_result: Result<(), LpmError>,
) -> Vec<&'static str> {
    let mut warnings = Vec::new();
    if local_key_checkpoint_failed {
        warnings.push("The remote update succeeded, but the local key checkpoint could not be stored. Restore local storage access, then pull the latest project revision.");
    }
    if manifest_result.is_err() {
        warnings.push("The remote update succeeded, but the project revision checkpoint could not be stored. Restore the original project's lpm.json and write access, then pull the latest revision.");
    }
    warnings
}

#[cfg(test)]
pub(super) fn read_lpm_json_for_push(
    project_dir: &std::path::Path,
) -> Result<Option<lpm_runner::lpm_json::LpmJsonConfig>, LpmError> {
    lpm_runner::lpm_json::read_lpm_json(project_dir).map_err(LpmError::Script)
}

/// Build the `schema` JSON value sent alongside a vault push.
///
/// Shape: `{ version: 2, envSchema?, envConfig?, environments? }`. The
/// dashboard renders these read-only so a teammate sees which keys are
/// required, secret, etc. Wire shape is identical for personal and org
/// vaults — the calling layer decides whether to send it. Returns `None`
/// when the project has no `lpm.json`. Read, parse, and semantic-validation
/// failures are rejected by [`CloudManifestSnapshot::read`].
pub(super) fn build_push_schema_value(
    config: Option<&lpm_runner::lpm_json::LpmJsonConfig>,
) -> Option<serde_json::Value> {
    let c = config?;
    let mut obj = serde_json::Map::new();
    obj.insert("version".into(), serde_json::json!(2));

    // envSchema: flat var map (serialize .vars directly, not the EnvSchema wrapper)
    if let Some(env_schema) = &c.env_schema
        && let Ok(v) = serde_json::to_value(&env_schema.vars)
    {
        let mut v = v;
        if let Some(vars) = v.as_object_mut() {
            for (key, value) in vars {
                if let Some(rule) = value.as_object_mut() {
                    if env_schema.is_secret(key) {
                        rule.remove("default");
                        rule.remove("enum");
                        rule.remove("defaultsIn");
                    }
                    if env_schema
                        .vars
                        .get(key)
                        .and_then(|rule| rule.required_when.as_ref())
                        .is_some_and(|condition| {
                            matches!(condition, lpm_env::RequiredWhen::Equals(_))
                                && env_schema
                                    .vars
                                    .get(condition.variable())
                                    .is_none_or(|source| source.secret)
                        })
                    {
                        rule.remove("requiredWhen");
                    }
                    rule.retain(|field, value| {
                        !(value.is_null()
                            || matches!(value, serde_json::Value::Bool(false))
                            || field == "empty" && value == "missing")
                    });
                }
            }
        }
        obj.insert("envSchema".into(), v);
        let mut policy = serde_json::Map::new();
        if !env_schema.client_prefixes.is_empty() {
            policy.insert(
                "clientPrefixes".into(),
                serde_json::json!(env_schema.client_prefixes),
            );
        }
        if !env_schema.groups.is_empty() {
            policy.insert("groups".into(), serde_json::json!(env_schema.groups));
        }
        if !policy.is_empty() {
            obj.insert("envSchemaConfig".into(), serde_json::Value::Object(policy));
        }
    }

    // envConfig: alias → canonical mapping from lpm.json "env" field
    if !c.env.is_empty() {
        let env_config: serde_json::Map<_, _> = c
            .env
            .iter()
            .map(|(alias, file_path)| {
                let mode = lpm_env::resolver::resolve_canonical_name(
                    alias,
                    &c.env,
                    c.environments.as_ref(),
                );
                (
                    alias.clone(),
                    serde_json::json!({
                        "canonical": mode,
                        "file": file_path,
                    }),
                )
            })
            .collect();
        obj.insert("envConfig".into(), serde_json::Value::Object(env_config));
    }

    // environments: inheritance config (extends, file, sensitive)
    if let Some(envs) = &c.environments
        && let Ok(v) = serde_json::to_value(envs)
    {
        obj.insert("environments".into(), v);
    }

    Some(serde_json::Value::Object(obj))
}

pub(super) fn persist_personal_sync_version(
    project_dir: &std::path::Path,
    expected_vault_id: &str,
    version: i32,
    registry_url: &str,
    principal_id: &str,
) -> Result<(), LpmError> {
    let principal = lpm_vault::vault_id::SyncPrincipal {
        registry_url,
        principal_id,
    };
    lpm_vault::vault_id::write_personal_sync_version_for_principal_if_vault_matches(
        project_dir,
        expected_vault_id,
        version,
        principal,
    )
    .map_err(LpmError::Script)
}

pub(super) fn persist_org_sync_version(
    project_dir: &std::path::Path,
    expected_vault_id: &str,
    org_slug: &str,
    version: i32,
    registry_url: &str,
    principal_id: &str,
) -> Result<(), LpmError> {
    let principal = lpm_vault::vault_id::SyncPrincipal {
        registry_url,
        principal_id,
    };
    lpm_vault::vault_id::write_org_sync_version_for_principal_if_vault_matches(
        project_dir,
        expected_vault_id,
        org_slug,
        version,
        principal,
    )
    .map_err(LpmError::Script)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mutation_rejects_root_changes_without_authored_schema() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("lpm.json"), r#"{"vault":"captured-env"}"#).unwrap();
        let captured = CloudManifestSnapshot::read(dir.path()).unwrap();
        std::fs::write(
            dir.path().join("lpm.json"),
            r#"{"vault":"captured-env","name":"changed"}"#,
        )
        .unwrap();
        assert_eq!(
            verify_personal_mutation_snapshot(
                dir.path(),
                "captured-env",
                "https://lpm.dev",
                None,
                captured.sources.as_deref().unwrap()
            )
            .unwrap_err(),
            "env.source_changed at lpm.json/envSchema"
        );
        assert_eq!(
            verify_org_mutation_snapshot(
                dir.path(),
                "captured-env",
                "acme",
                "https://lpm.dev",
                None,
                captured.sources.as_deref().unwrap()
            )
            .unwrap_err(),
            "env.source_changed at lpm.json/envSchema"
        );
    }

    #[test]
    fn personal_mutation_accepts_an_unchanged_bom_manifest() {
        let dir = tempfile::tempdir().unwrap();
        let content = "\u{feff}{\"vault\":\"bom-env\"}";
        std::fs::write(dir.path().join("lpm.json"), content).unwrap();
        let captured = CloudManifestSnapshot::read(dir.path()).unwrap();
        verify_personal_mutation_snapshot(
            dir.path(),
            "bom-env",
            "https://lpm.dev",
            None,
            captured.sources.as_deref().unwrap(),
        )
        .unwrap();
    }

    #[test]
    fn org_mutation_accepts_an_unchanged_bom_manifest() {
        let dir = tempfile::tempdir().unwrap();
        let content = "\u{feff}{\"vault\":\"bom-env\"}";
        std::fs::write(dir.path().join("lpm.json"), content).unwrap();
        let captured = CloudManifestSnapshot::read(dir.path()).unwrap();
        verify_org_mutation_snapshot(
            dir.path(),
            "bom-env",
            "acme",
            "https://lpm.dev",
            None,
            captured.sources.as_deref().unwrap(),
        )
        .unwrap();
    }

    // ── env push schema metadata helpers ────────────────────────────

    #[test]
    fn build_push_schema_value_returns_none_when_config_is_missing() {
        // No lpm.json → push sends no schema → server keeps last-known-good schema.
        assert!(build_push_schema_value(None).is_none());
    }

    #[test]
    fn personal_metadata_write_rejects_a_replacement_vault() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("lpm.json"), r#"{"vault":"vault-original"}"#)
            .expect("seed original project");
        let expected_vault_id =
            lpm_vault::vault_id::read_vault_id(dir.path()).expect("capture original vault ID");
        std::fs::write(
            dir.path().join("lpm.json"),
            r#"{"vault":"vault-replacement"}"#,
        )
        .expect("replace project identity");

        let error = persist_personal_sync_version(
            dir.path(),
            &expected_vault_id,
            7,
            "https://lpm.dev",
            "user-1",
        )
        .expect_err("metadata must stay bound to the captured vault ID");

        assert!(error.to_string().contains("vault ID changed"), "{error}");
        let config: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(dir.path().join("lpm.json")).expect("read replacement"),
        )
        .expect("parse replacement");
        assert_eq!(config["vault"], "vault-replacement");
        assert!(config.get("vaultSync").is_none());
    }

    #[test]
    fn personal_mutation_preflight_accepts_the_pinned_platform_principal() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("lpm.json"), r#"{"vault":"vault-original"}"#)
            .expect("seed project");
        lpm_vault::vault_id::pin_personal_platform_principal_if_vault_matches(
            dir.path(),
            "vault-original",
            lpm_vault::vault_id::SyncPrincipal {
                registry_url: "https://lpm.dev",
                principal_id: "account-a",
            },
        )
        .expect("pin platform identity");

        fresh_personal_mutation_manifest(
            dir.path(),
            "vault-original",
            "https://lpm.dev",
            Some("account-a"),
        )
        .expect("platform identity must bind the first cloud mutation");
    }

    #[test]
    fn organization_metadata_write_rejects_a_replacement_vault() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("lpm.json"), r#"{"vault":"vault-original"}"#)
            .expect("seed original project");
        let expected_vault_id =
            lpm_vault::vault_id::read_vault_id(dir.path()).expect("capture original vault ID");
        std::fs::write(
            dir.path().join("lpm.json"),
            r#"{"vault":"vault-replacement"}"#,
        )
        .expect("replace project identity");

        let error = persist_org_sync_version(
            dir.path(),
            &expected_vault_id,
            "acme",
            7,
            "https://lpm.dev",
            "org-1",
        )
        .expect_err("metadata must stay bound to the captured vault ID");

        assert!(error.to_string().contains("vault ID changed"), "{error}");
        let config: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(dir.path().join("lpm.json")).expect("read replacement"),
        )
        .expect("parse replacement");
        assert_eq!(config["vault"], "vault-replacement");
        assert!(config.get("vaultSync").is_none());
    }

    #[test]
    fn personal_metadata_rejects_rollback_without_mutating_the_checkpoint() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("lpm.json"), r#"{"vault":"vault-original"}"#)
            .expect("seed project");
        let principal = lpm_vault::vault_id::SyncPrincipal {
            registry_url: "https://lpm.dev",
            principal_id: "user-1",
        };
        lpm_vault::vault_id::write_personal_sync_version_for_principal(dir.path(), 5, principal)
            .expect("seed checkpoint");
        let path = dir.path().join("lpm.json");
        let before = std::fs::read(&path).expect("snapshot checkpoint");
        let error = persist_personal_sync_version(
            dir.path(),
            "vault-original",
            1,
            "https://lpm.dev",
            "user-1",
        )
        .expect_err("a stale response must not reset its bound checkpoint");

        assert!(
            error
                .to_string()
                .contains("older than the durable local version 5")
        );
        assert_eq!(std::fs::read(path).expect("read checkpoint"), before);
        assert_eq!(
            lpm_vault::vault_id::read_personal_sync_version_for_principal(dir.path(), principal),
            Some(5),
        );
    }

    #[test]
    fn organization_metadata_rejects_rollback_without_mutating_the_checkpoint() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("lpm.json"), r#"{"vault":"vault-original"}"#)
            .expect("seed project");
        let principal = lpm_vault::vault_id::SyncPrincipal {
            registry_url: "https://lpm.dev",
            principal_id: "org-1",
        };
        lpm_vault::vault_id::write_org_sync_version_for_principal(dir.path(), "acme", 5, principal)
            .expect("seed checkpoint");
        let path = dir.path().join("lpm.json");
        let before = std::fs::read(&path).expect("snapshot checkpoint");
        let error = persist_org_sync_version(
            dir.path(),
            "vault-original",
            "acme",
            1,
            "https://lpm.dev",
            "org-1",
        )
        .expect_err("a stale response must not reset its bound checkpoint");

        assert!(
            error
                .to_string()
                .contains("older than the durable local version 5")
        );
        assert_eq!(std::fs::read(path).expect("read checkpoint"), before);
        assert_eq!(
            lpm_vault::vault_id::read_org_sync_version_for_principal(dir.path(), "acme", principal,),
            Some(5),
        );
    }

    #[test]
    fn build_push_schema_value_always_emits_version_marker() {
        // Even an empty config carries the version marker so the server can
        // distinguish "CLI-fresh, but author cleared the schema" from
        // "CLI never sent metadata" (None).
        let cfg = lpm_runner::lpm_json::LpmJsonConfig::default();
        let value =
            build_push_schema_value(Some(&cfg)).expect("empty config still emits an object");
        let obj = value.as_object().expect("schema must be a JSON object");
        assert_eq!(obj.get("version"), Some(&serde_json::json!(2)));
        assert!(!obj.contains_key("envSchema"));
        assert!(!obj.contains_key("envConfig"));
        assert!(!obj.contains_key("environments"));
    }

    #[test]
    fn build_push_schema_value_includes_env_schema_vars() {
        let mut cfg = lpm_runner::lpm_json::LpmJsonConfig::default();
        let mut vars = std::collections::HashMap::new();
        vars.insert(
            "DATABASE_URL".to_string(),
            lpm_env::EnvVarRule {
                required: true,
                ..Default::default()
            },
        );
        cfg.env_schema = Some(lpm_env::EnvSchema {
            vars,
            ..Default::default()
        });

        let value =
            build_push_schema_value(Some(&cfg)).expect("config with envSchema emits a value");
        let env_schema = value
            .get("envSchema")
            .expect("envSchema field must round-trip on push");
        assert!(
            env_schema.get("DATABASE_URL").is_some(),
            "var entries must be flat, not wrapped in EnvSchema"
        );
    }

    #[test]
    fn sync_projection_never_contains_secret_default_or_enum_literals() {
        let cfg = lpm_runner::lpm_json::LpmJsonConfig {
            env_schema: Some(serde_json::from_value(serde_json::json!({"vars":{"TOKEN":{"secret":true,"default":"private-default","enum":["private-enum"]}}})).unwrap()),
            ..Default::default()
        };
        let value = build_push_schema_value(Some(&cfg)).unwrap();
        let text = value.to_string();
        assert!(!text.contains("private-default"));
        assert!(!text.contains("private-enum"));
        assert_eq!(value["envSchema"]["TOKEN"]["secret"], true);
    }

    #[test]
    fn sync_projection_preserves_root_exposure_policy_and_ci_storage() {
        let config = lpm_runner::lpm_json::LpmJsonConfig {
            env_schema: Some(serde_json::from_value(serde_json::json!({"clientPrefixes":["APP_"],"vars":{"APP_API":{"client":true,"ci":"secret"},"BUILD_MODE":{"ci":"variable"}}})).unwrap()),
            ..Default::default()
        };
        let wire = build_push_schema_value(Some(&config)).unwrap();
        assert_eq!(
            wire["envSchemaConfig"]["clientPrefixes"],
            serde_json::json!(["APP_"])
        );
        assert_eq!(wire["envSchema"]["BUILD_MODE"]["ci"], "variable");
        assert_eq!(wire["envSchema"]["APP_API"]["ci"], "secret");
    }

    #[test]
    fn maximum_variable_count_fits_the_sync_metadata_byte_limit() {
        let cfg = lpm_runner::lpm_json::LpmJsonConfig {
            env_schema: Some(lpm_env::EnvSchema {
                vars: (0..4096)
                    .map(|index| (format!("VALUE_{index}"), Default::default()))
                    .collect(),
                ..Default::default()
            }),
            ..Default::default()
        };
        let text = build_push_schema_value(Some(&cfg)).unwrap().to_string();
        assert!(text.len() <= 256 * 1024, "{} bytes", text.len());
    }

    #[test]
    fn build_push_schema_value_includes_env_config_when_aliases_defined() {
        let mut cfg = lpm_runner::lpm_json::LpmJsonConfig::default();
        cfg.env.insert("dev".into(), ".env.development".into());

        let value = build_push_schema_value(Some(&cfg)).expect("config with env emits a value");
        let env_config = value
            .get("envConfig")
            .and_then(|v| v.as_object())
            .expect("envConfig must serialize as an object");
        let dev = env_config
            .get("dev")
            .and_then(|v| v.as_object())
            .expect("alias entry must serialize as an object");
        assert_eq!(
            dev.get("canonical"),
            Some(&serde_json::json!("development"))
        );
        assert_eq!(
            dev.get("file"),
            Some(&serde_json::json!(".env.development"))
        );
    }

    #[test]
    fn sync_projection_preserves_groups_exact_bounds_and_presence_predicates_without_prefixes() {
        let config = lpm_runner::lpm_json::LpmJsonConfig { env_schema: Some(serde_json::from_value(serde_json::json!({"vars":{"N":{"format":"integer","min":"9007199254740993","max":"9223372036854775807","requiredWhen":{"variable":"MODE","present":false}},"MODE":{}},"groups":{"g":{"mode":"exactlyOne","vars":["N","MODE"]}}})).unwrap()), ..Default::default() };
        let wire = build_push_schema_value(Some(&config)).unwrap();
        assert_eq!(wire["envSchema"]["N"]["min"], "9007199254740993");
        assert_eq!(wire["envSchema"]["N"]["requiredWhen"]["present"], false);
        assert_eq!(wire["envSchemaConfig"]["groups"]["g"]["mode"], "exactlyOne");
    }

    #[test]
    fn sync_projection_suppresses_equality_literals_referencing_secret_sources() {
        let config = lpm_runner::lpm_json::LpmJsonConfig { env_schema: Some(serde_json::from_value(serde_json::json!({"vars":{"SOURCE":{"secret":true},"TARGET":{"requiredWhen":{"variable":"SOURCE","equals":"private-condition"}},"PRESENT":{"requiredWhen":{"variable":"SOURCE","present":true}}}})).unwrap()), ..Default::default() };
        let wire = build_push_schema_value(Some(&config)).unwrap();
        assert!(!wire.to_string().contains("private-condition"));
        assert_eq!(
            wire["envSchema"]["PRESENT"]["requiredWhen"]["present"],
            true
        );
    }

    #[test]
    fn read_lpm_json_for_push_returns_none_when_file_missing() {
        // Absent lpm.json is not a warning condition — push just doesn't send schema.
        let dir = tempfile::tempdir().expect("tempdir");
        assert!(read_lpm_json_for_push(dir.path()).unwrap().is_none());
    }

    #[test]
    fn read_lpm_json_for_push_rejects_malformed_lpm_json() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("lpm.json"), "{ this is not json")
            .expect("seed broken lpm.json");
        assert!(
            read_lpm_json_for_push(dir.path()).is_err(),
            "push must not silently drop aliases and schema metadata from malformed lpm.json"
        );
    }

    #[test]
    fn read_lpm_json_for_push_returns_some_on_valid_lpm_json() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            dir.path().join("lpm.json"),
            r#"{"envSchema":{"vars":{"FOO":{"required":true}}}}"#,
        )
        .expect("seed valid lpm.json");
        let parsed = read_lpm_json_for_push(dir.path())
            .expect("valid lpm.json must parse")
            .expect("valid lpm.json must exist");
        assert!(
            parsed.env_schema.is_some(),
            "envSchema field must round-trip through the parser helper"
        );
    }

    #[test]
    fn read_lpm_json_for_push_rejects_oversized_and_unreadable_files() {
        let oversized = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            oversized.path().join("lpm.json"),
            vec![
                b' ';
                usize::try_from(lpm_common::CONFIG_FILE_SIZE_CAP_BYTES + 1)
                    .expect("config cap fits usize")
            ],
        )
        .expect("seed oversized lpm.json");
        assert!(read_lpm_json_for_push(oversized.path()).is_err());

        let unreadable = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir(unreadable.path().join("lpm.json"))
            .expect("seed unreadable lpm.json path");
        assert!(read_lpm_json_for_push(unreadable.path()).is_err());
    }

    #[test]
    fn read_lpm_json_for_push_rejects_semantically_invalid_config() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            dir.path().join("lpm.json"),
            r#"{"envSchema":"must-be-an-object"}"#,
        )
        .expect("seed semantically invalid lpm.json");

        assert!(read_lpm_json_for_push(dir.path()).is_err());
    }

    #[test]
    fn build_sync_payload_preserves_custom_identity_after_alias_change() {
        let mut all_envs = HashMap::new();
        all_envs.insert(
            "dev".into(),
            HashMap::from([(String::from("API_KEY"), String::from("current-secret"))]),
        );

        let sync_envs =
            serde_json::from_str::<RemotePullPayload>(&build_sync_payload(all_envs).unwrap())
                .unwrap()
                .environments;

        assert_eq!(
            sync_envs.len(),
            1,
            "sync payload should contain exactly one environment"
        );
        assert!(
            sync_envs.contains_key("dev"),
            "a later alias must not reinterpret an existing custom environment"
        );
        assert!(
            !sync_envs.contains_key("development"),
            "sync must preserve the environment identity stored by the current writer"
        );
    }

    #[test]
    fn build_sync_payload_keeps_distinct_current_environment_identities() {
        let mut all_envs = HashMap::new();
        all_envs.insert(
            "dev".into(),
            HashMap::from([
                (String::from("SHARED"), String::from("custom")),
                (String::from("ONLY_CUSTOM"), String::from("present")),
            ]),
        );
        all_envs.insert(
            "development".into(),
            HashMap::from([
                (String::from("SHARED"), String::from("canonical")),
                (String::from("ONLY_CANONICAL"), String::from("present")),
            ]),
        );

        let sync_envs =
            serde_json::from_str::<RemotePullPayload>(&build_sync_payload(all_envs).unwrap())
                .unwrap()
                .environments;
        assert_eq!(sync_envs.len(), 2);
        let dev = sync_envs
            .get("dev")
            .expect("custom environment must remain");
        let development = sync_envs
            .get("development")
            .expect("configured environment must remain");
        assert_eq!(dev.get("SHARED").map(String::as_str), Some("custom"));
        assert_eq!(dev.get("ONLY_CUSTOM").map(String::as_str), Some("present"));
        assert_eq!(
            development.get("ONLY_CANONICAL").map(String::as_str),
            Some("present")
        );
    }

    #[test]
    fn build_sync_payload_preserves_named_empty_entries() {
        let environment_count = 5_000;
        let all_envs: HashMap<_, _> = (0..environment_count)
            .map(|index| {
                (
                    format!("canonical-{index}"),
                    if index % 2 == 0 {
                        HashMap::from([("TOKEN".to_string(), index.to_string())])
                    } else {
                        HashMap::new()
                    },
                )
            })
            .collect();

        let sync_envs =
            serde_json::from_str::<RemotePullPayload>(&build_sync_payload(all_envs).unwrap())
                .unwrap()
                .environments;

        assert_eq!(sync_envs.len(), environment_count);
    }

    #[test]
    #[ignore = "manual deterministic performance harness"]
    fn build_sync_payload_large_map_benchmark() {
        let size = 10_000;
        let all_envs = (0..size)
            .map(|index| {
                (
                    format!("mode-{index:05}"),
                    HashMap::from([("TOKEN".to_string(), index.to_string())]),
                )
            })
            .collect();
        let started = std::time::Instant::now();

        let payload = std::hint::black_box(build_sync_payload(all_envs).unwrap());
        let elapsed = started.elapsed();
        let sync_envs = serde_json::from_str::<RemotePullPayload>(&payload)
            .unwrap()
            .environments;

        assert_eq!(sync_envs.len(), size);
        eprintln!(
            "build_sync_payload size={size} elapsed_ns={}",
            elapsed.as_nanos()
        );
    }

    #[test]
    fn parse_remote_pull_payload_for_overwrite_uses_remote_environments_exactly() {
        let raw_json = serde_json::json!({
            "environments": {
                "default": {
                    "KEEP": "remote",
                    "REMOTE_ONLY": "fresh"
                },
                "production": {
                    "PROD_ONLY": "remote"
                }
            }
        })
        .to_string();

        let parsed = parse_remote_pull_payload_for_overwrite(&raw_json).unwrap();

        assert_eq!(parsed.len(), 2);
        assert_eq!(
            parsed
                .get("default")
                .and_then(|env| env.get("KEEP"))
                .map(String::as_str),
            Some("remote")
        );
        assert_eq!(
            parsed
                .get("default")
                .and_then(|env| env.get("REMOTE_ONLY"))
                .map(String::as_str),
            Some("fresh")
        );
        assert!(
            parsed
                .get("default")
                .and_then(|env| env.get("DROP_ME"))
                .is_none()
        );
        assert!(!parsed.contains_key("preview"));
        assert_eq!(
            parsed
                .get("production")
                .and_then(|env| env.get("PROD_ONLY"))
                .map(String::as_str),
            Some("remote")
        );
    }

    #[test]
    fn parse_remote_pull_payload_for_overwrite_rejects_retired_flat_payload() {
        let raw_json = serde_json::json!({
            "KEEP": "remote",
            "REMOTE_ONLY": "fresh"
        })
        .to_string();

        let error = parse_remote_pull_payload_for_overwrite(&raw_json)
            .expect_err("retired flat payloads must not remain executable");

        assert_eq!(error, "failed to parse pulled vault data");
    }

    #[test]
    fn overwrite_payload_moves_the_owned_environment_map() {
        let secret = "x".repeat(1024);
        let secret_pointer = secret.as_ptr();
        let environments = HashMap::from([(
            "default".to_string(),
            HashMap::from([("TOKEN".to_string(), secret)]),
        )]);
        let wrapper = RemotePullPayload { environments };

        let parsed = wrapper.environments;

        let moved = &parsed["default"]["TOKEN"];
        assert_eq!(moved.as_ptr(), secret_pointer);
    }

    #[test]
    fn overwrite_payload_without_environments_is_rejected() {
        let error = parse_remote_pull_payload_for_overwrite(r#"{"metadata":{}}"#)
            .expect_err("wrapper payloads must explicitly contain environments");

        assert_eq!(error, "failed to parse pulled vault data");
    }
}
