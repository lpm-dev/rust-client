//! Vault ID management — generates and reads project vault UUIDs from lpm.json.
//!
//! Also stores optional project-local sync metadata used for vault CAS:
//! - `vaultSync.personalVersion`: last known personal cloud vault version
//! - `vaultSync.orgVersions.{slug}`: last known shared org vault version

use std::path::{Path, PathBuf};

/// Read the vault ID from lpm.json, or generate one if it doesn't exist.
///
/// The vault ID is stored as `"vault": "uuid-string"` at the top level of lpm.json.
/// If lpm.json doesn't exist, creates a minimal one with just the vault field.
pub fn get_or_create_vault_id(project_dir: &Path) -> Result<String, String> {
    let (lpm_json_path, mut config) =
        read_lpm_json_value(project_dir)?.unwrap_or_else(|| empty_lpm_json(project_dir));

    if let Some(vault_id) = config.get("vault").and_then(|v| v.as_str()) {
        return Ok(vault_id.to_string());
    }

    let vault_id = generate_uuid();
    config["vault"] = serde_json::Value::String(vault_id.clone());
    write_lpm_json_value(&lpm_json_path, &config)?;

    Ok(vault_id)
}

/// Read the vault ID from lpm.json without creating one.
pub fn read_vault_id(project_dir: &Path) -> Option<String> {
    let lpm_json_path = project_dir.join("lpm.json");
    let content = std::fs::read_to_string(lpm_json_path).ok()?;
    let config: serde_json::Value = serde_json::from_str(&content).ok()?;
    config
        .get("vault")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
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

/// Persist the last known personal cloud vault version in `lpm.json`.
pub fn write_personal_sync_version(project_dir: &Path, version: i32) -> Result<(), String> {
    let (lpm_json_path, mut config) =
        read_lpm_json_value(project_dir)?.unwrap_or_else(|| empty_lpm_json(project_dir));

    let root = config.as_object_mut().ok_or_else(|| {
        "failed to update lpm.json: top-level config must be an object".to_string()
    })?;

    let sync = ensure_object_entry(root, "vaultSync");
    sync.insert("personalVersion".into(), serde_json::json!(version));

    write_lpm_json_value(&lpm_json_path, &config)
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

/// Persist the last known org-shared cloud vault version for an org slug.
pub fn write_org_sync_version(
    project_dir: &Path,
    org_slug: &str,
    version: i32,
) -> Result<(), String> {
    let (lpm_json_path, mut config) =
        read_lpm_json_value(project_dir)?.unwrap_or_else(|| empty_lpm_json(project_dir));

    let root = config.as_object_mut().ok_or_else(|| {
        "failed to update lpm.json: top-level config must be an object".to_string()
    })?;

    let sync = ensure_object_entry(root, "vaultSync");
    let org_versions = ensure_object_entry(sync, "orgVersions");
    org_versions.insert(org_slug.to_string(), serde_json::json!(version));

    write_lpm_json_value(&lpm_json_path, &config)
}

/// Get the project name from package.json or lpm.json.
pub fn read_project_name(project_dir: &Path) -> String {
    // Try package.json first
    let pkg_path = project_dir.join("package.json");
    if let Ok(content) = std::fs::read_to_string(&pkg_path)
        && let Ok(pkg) = serde_json::from_str::<serde_json::Value>(&content)
        && let Some(name) = pkg.get("name").and_then(|v| v.as_str())
    {
        return name.to_string();
    }

    // Try lpm.json
    let lpm_path = project_dir.join("lpm.json");
    if let Ok(content) = std::fs::read_to_string(&lpm_path)
        && let Ok(cfg) = serde_json::from_str::<serde_json::Value>(&content)
        && let Some(name) = cfg.get("name").and_then(|v| v.as_str())
    {
        return name.to_string();
    }

    // Fall back to directory name
    project_dir
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "unknown".to_string())
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

fn empty_lpm_json(project_dir: &Path) -> (PathBuf, serde_json::Value) {
    (project_dir.join("lpm.json"), serde_json::json!({}))
}

fn read_lpm_json_value(project_dir: &Path) -> Result<Option<(PathBuf, serde_json::Value)>, String> {
    let lpm_json_path = project_dir.join("lpm.json");
    if !lpm_json_path.exists() {
        return Ok(None);
    }

    let content = std::fs::read_to_string(&lpm_json_path)
        .map_err(|e| format!("failed to read lpm.json: {e}"))?;
    let config =
        serde_json::from_str(&content).map_err(|e| format!("failed to parse lpm.json: {e}"))?;

    Ok(Some((lpm_json_path, config)))
}

fn write_lpm_json_value(lpm_json_path: &Path, config: &serde_json::Value) -> Result<(), String> {
    let content = serde_json::to_string_pretty(config)
        .map_err(|e| format!("failed to serialize lpm.json: {e}"))?
        + "\n";
    let tmp_path = lpm_json_path.with_extension("json.tmp");

    std::fs::write(&tmp_path, content).map_err(|e| format!("failed to write lpm.json: {e}"))?;
    std::fs::rename(&tmp_path, lpm_json_path)
        .map_err(|e| format!("failed to write lpm.json: {e}"))?;

    Ok(())
}

fn ensure_object_entry<'a>(
    parent: &'a mut serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> &'a mut serde_json::Map<String, serde_json::Value> {
    let value = parent
        .entry(key.to_string())
        .or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()));

    if !value.is_object() {
        *value = serde_json::Value::Object(serde_json::Map::new());
    }

    value
        .as_object_mut()
        .expect("vault sync metadata entries should always be objects")
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

        write_personal_sync_version(dir.path(), 7).unwrap();

        assert_eq!(read_personal_sync_version(dir.path()), Some(7));

        let content = std::fs::read_to_string(dir.path().join("lpm.json")).unwrap();
        let config: serde_json::Value = serde_json::from_str(&content).unwrap();
        assert_eq!(config["runtime"]["node"], "22");
        assert_eq!(config["vault"], "vault-123");
        assert_eq!(config["vaultSync"]["personalVersion"], 7);
        assert!(content.ends_with('\n'));
    }

    #[test]
    fn org_sync_versions_are_scoped_by_slug() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("lpm.json"), r#"{"vault":"vault-123"}"#).unwrap();

        write_org_sync_version(dir.path(), "acme", 4).unwrap();
        write_org_sync_version(dir.path(), "umbrella", 9).unwrap();

        assert_eq!(read_org_sync_version(dir.path(), "acme"), Some(4));
        assert_eq!(read_org_sync_version(dir.path(), "umbrella"), Some(9));
        assert_eq!(read_org_sync_version(dir.path(), "missing"), None);
    }

    #[test]
    fn sync_version_writes_recover_from_metadata_drift_across_personal_and_org_modes() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("lpm.json"),
            r#"{"runtime":{"node":"22"},"vault":"vault-123","vaultSync":{"personalVersion":5,"orgVersions":"drifted"}}"#,
        )
        .unwrap();

        write_org_sync_version(dir.path(), "acme", 9).unwrap();
        assert_eq!(read_personal_sync_version(dir.path()), Some(5));
        assert_eq!(read_org_sync_version(dir.path(), "acme"), Some(9));

        write_personal_sync_version(dir.path(), 11).unwrap();
        assert_eq!(read_personal_sync_version(dir.path()), Some(11));
        assert_eq!(read_org_sync_version(dir.path(), "acme"), Some(9));

        let content = std::fs::read_to_string(dir.path().join("lpm.json")).unwrap();
        let config: serde_json::Value = serde_json::from_str(&content).unwrap();
        assert_eq!(config["runtime"]["node"], "22");
        assert_eq!(config["vault"], "vault-123");
        assert_eq!(config["vaultSync"]["personalVersion"], 11);
        assert_eq!(config["vaultSync"]["orgVersions"]["acme"], 9);
        assert!(content.ends_with('\n'));
    }
}
