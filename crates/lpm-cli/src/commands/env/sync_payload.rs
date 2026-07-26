use super::prelude::*;

pub(super) fn build_sync_environments(
    all_envs: &HashMap<String, HashMap<String, String>>,
    env_map: &HashMap<String, String>,
    environments: Option<&lpm_env::EnvironmentsConfig>,
) -> HashMap<String, HashMap<String, String>> {
    let mut ordered_envs: Vec<_> = all_envs
        .iter()
        .filter(|(_, secrets)| !secrets.is_empty())
        .map(|(storage_key, secrets)| {
            let resolved = lpm_env::resolver::resolve(storage_key, env_map, environments);
            let is_canonical_storage = resolved.canonical == *storage_key;
            (
                resolved.canonical,
                is_canonical_storage,
                storage_key.as_str(),
                secrets,
            )
        })
        .collect();

    ordered_envs.sort_by(|left, right| {
        left.0
            .cmp(&right.0)
            .then(left.1.cmp(&right.1))
            .then(left.2.cmp(right.2))
    });

    let mut canonical_envs = HashMap::new();
    for (canonical, _is_canonical_storage, _storage_key, secrets) in ordered_envs {
        canonical_envs
            .entry(canonical)
            .or_insert_with(HashMap::new)
            .extend(secrets.clone());
    }

    canonical_envs
}

pub(super) fn parse_remote_pull_payload_for_overwrite(
    raw_json: &str,
) -> Result<HashMap<String, HashMap<String, String>>, String> {
    if let Ok(wrapper) =
        serde_json::from_str::<HashMap<String, HashMap<String, HashMap<String, String>>>>(raw_json)
    {
        return Ok(wrapper.get("environments").cloned().unwrap_or_default());
    }

    if let Ok(remote_secrets) = serde_json::from_str::<HashMap<String, String>>(raw_json) {
        return Ok(HashMap::from([("default".to_string(), remote_secrets)]));
    }

    Err("failed to parse pulled vault data".to_string())
}

/// Read `lpm.json` for an `lpm env push` surface (personal or org).
///
/// Returns `Ok(Some(config))` on a clean parse and `Ok(None)` when the file is
/// absent. When JSON syntax is malformed, emits a stderr warning and returns
/// `Ok(None)` rather than failing the push.
/// Push is the user's mainline action and a metadata read should never
/// block it; the stderr warning surfaces the silent-stale-schema failure
/// mode (push succeeds, server keeps last-known-good schema).
pub(super) fn read_lpm_json_for_push(
    project_dir: &std::path::Path,
) -> Result<Option<lpm_runner::lpm_json::LpmJsonConfig>, LpmError> {
    match lpm_runner::lpm_json::read_lpm_json(project_dir) {
        Ok(config) => Ok(config),
        Err(error) if error.starts_with("failed to parse lpm.json:") => {
            output::warn(&format!(
                "lpm.json could not be parsed: {error}. Pushing without schema metadata; server keeps the last-known-good schema."
            ));
            tracing::warn!("lpm.json parse error during env push: {error}");
            Ok(None)
        }
        Err(error) => Err(LpmError::Script(error)),
    }
}

/// Build the `schema` JSON value sent alongside a vault push.
///
/// Shape: `{ version: 2, envSchema?, envConfig?, environments? }`. The
/// dashboard renders these read-only so a teammate sees which keys are
/// required, secret, etc. Wire shape is identical for personal and org
/// vaults — the calling layer decides whether to send it. Returns `None`
/// when the project has no `lpm.json` (or it failed to parse — see
/// [`read_lpm_json_for_push`]). Read and semantic-validation failures remain
/// errors.
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
        obj.insert("envSchema".into(), v);
    }

    // envConfig: alias → canonical mapping from lpm.json "env" field
    if !c.env.is_empty() {
        let env_config: serde_json::Map<_, _> = c
            .env
            .iter()
            .filter_map(|(alias, file_path)| {
                let mode = lpm_env::resolver::extract_mode_from_env_path(file_path)?;
                Some((
                    alias.clone(),
                    serde_json::json!({
                        "canonical": mode,
                        "file": file_path,
                    }),
                ))
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

pub(super) fn expected_personal_sync_version(
    project_dir: &std::path::Path,
    force: bool,
) -> Option<i32> {
    if force {
        return None;
    }

    lpm_vault::vault_id::read_personal_sync_version(project_dir)
}

pub(super) fn expected_org_sync_version(
    project_dir: &std::path::Path,
    org_slug: &str,
) -> Option<i32> {
    lpm_vault::vault_id::read_org_sync_version(project_dir, org_slug)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── env push schema metadata helpers ────────────────────────────

    #[test]
    fn build_push_schema_value_returns_none_when_config_is_missing() {
        // No lpm.json → push sends no schema → server keeps last-known-good schema.
        assert!(build_push_schema_value(None).is_none());
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
        cfg.env_schema = Some(lpm_env::EnvSchema { vars });

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
    fn read_lpm_json_for_push_returns_none_when_file_missing() {
        // Absent lpm.json is not a warning condition — push just doesn't send schema.
        let dir = tempfile::tempdir().expect("tempdir");
        assert!(read_lpm_json_for_push(dir.path()).unwrap().is_none());
    }

    #[test]
    fn read_lpm_json_for_push_returns_none_on_malformed_lpm_json() {
        // Malformed lpm.json must not abort the push — return None and (in practice)
        // emit a stderr warning so the silent-stale-schema state is observable.
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("lpm.json"), "{ this is not json")
            .expect("seed broken lpm.json");
        let parsed = read_lpm_json_for_push(dir.path()).unwrap();
        assert!(
            parsed.is_none(),
            "malformed lpm.json must yield None so the push proceeds without metadata"
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
    fn build_sync_environments_canonicalizes_legacy_alias_keys() {
        let mut env_map = HashMap::new();
        env_map.insert("dev".into(), ".env.development".into());

        let mut all_envs = HashMap::new();
        all_envs.insert(
            "dev".into(),
            HashMap::from([(String::from("API_KEY"), String::from("legacy-secret"))]),
        );

        let sync_envs = build_sync_environments(&all_envs, &env_map, None);

        assert_eq!(
            sync_envs.len(),
            1,
            "sync payload should contain exactly one environment"
        );
        assert!(
            sync_envs.contains_key("development"),
            "legacy alias keys should be canonicalized before sync"
        );
        assert!(
            !sync_envs.contains_key("dev"),
            "legacy alias storage keys should not leak into cloud sync payloads"
        );
    }

    #[test]
    fn build_sync_environments_prefers_canonical_values_when_legacy_alias_collides() {
        let mut env_map = HashMap::new();
        env_map.insert("dev".into(), ".env.development".into());

        let mut all_envs = HashMap::new();
        all_envs.insert(
            "dev".into(),
            HashMap::from([
                (String::from("SHARED"), String::from("legacy")),
                (String::from("ONLY_LEGACY"), String::from("present")),
            ]),
        );
        all_envs.insert(
            "development".into(),
            HashMap::from([
                (String::from("SHARED"), String::from("canonical")),
                (String::from("ONLY_CANONICAL"), String::from("present")),
            ]),
        );

        let sync_envs = build_sync_environments(&all_envs, &env_map, None);
        let development = sync_envs
            .get("development")
            .expect("canonical environment should be present in sync payload");

        assert_eq!(
            sync_envs.len(),
            1,
            "legacy alias and canonical env should collapse into one sync payload entry"
        );
        assert_eq!(
            development.get("SHARED").map(String::as_str),
            Some("canonical")
        );
        assert_eq!(
            development.get("ONLY_LEGACY").map(String::as_str),
            Some("present")
        );
        assert_eq!(
            development.get("ONLY_CANONICAL").map(String::as_str),
            Some("present")
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
    fn parse_remote_pull_payload_for_overwrite_wraps_flat_payload_as_default() {
        let raw_json = serde_json::json!({
            "KEEP": "remote",
            "REMOTE_ONLY": "fresh"
        })
        .to_string();

        let parsed = parse_remote_pull_payload_for_overwrite(&raw_json).unwrap();

        assert_eq!(parsed.len(), 1);
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
    }

    #[test]
    fn expected_personal_sync_version_uses_stored_version_when_not_forced() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("lpm.json"), r#"{"vault":"vault-123"}"#).unwrap();
        lpm_vault::vault_id::write_personal_sync_version(dir.path(), 6).unwrap();

        assert_eq!(expected_personal_sync_version(dir.path(), false), Some(6));
    }

    #[test]
    fn expected_personal_sync_version_skips_cas_in_force_mode() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("lpm.json"), r#"{"vault":"vault-123"}"#).unwrap();
        lpm_vault::vault_id::write_personal_sync_version(dir.path(), 6).unwrap();

        assert_eq!(expected_personal_sync_version(dir.path(), true), None);
    }

    #[test]
    fn expected_org_sync_version_reads_org_scoped_metadata() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("lpm.json"), r#"{"vault":"vault-123"}"#).unwrap();
        lpm_vault::vault_id::write_org_sync_version(dir.path(), "acme", 9).unwrap();

        assert_eq!(expected_org_sync_version(dir.path(), "acme"), Some(9));
        assert_eq!(expected_org_sync_version(dir.path(), "umbrella"), None);
    }
}
