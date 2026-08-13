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

pub fn write_personal_sync_version_at(
    project_dir: &Path,
    version: i32,
    synced_at: &str,
) -> Result<(), String> {
    lpm_common::update_lpm_json(project_dir, |root, _| {
        let sync = object_entry(root, "vaultSync")?;
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

pub fn write_org_sync_version_at(
    project_dir: &Path,
    org_slug: &str,
    version: i32,
    synced_at: &str,
) -> Result<(), String> {
    lpm_common::update_lpm_json(project_dir, |root, _| {
        let sync = object_entry(root, "vaultSync")?;
        let org_versions = object_entry(sync, "orgVersions")?;
        org_versions.insert(org_slug.to_string(), serde_json::json!(version));
        let org_synced_at = object_entry(sync, "orgSyncedAt")?;
        org_synced_at.insert(org_slug.to_string(), serde_json::json!(synced_at));
        Ok(lpm_common::LpmJsonMutation::Changed(()))
    })
    .map(|_| ())
    .map_err(|error| error.to_string())
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
