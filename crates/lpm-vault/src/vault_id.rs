//! Vault ID management — generates and reads project vault UUIDs from lpm.json.

use std::path::Path;

/// Read the vault ID from lpm.json, or generate one if it doesn't exist.
///
/// The vault ID is stored as `"vault": "uuid-string"` at the top level of lpm.json.
/// If lpm.json doesn't exist, creates a minimal one with just the vault field.
pub fn get_or_create_vault_id(project_dir: &Path) -> Result<String, String> {
	let lpm_json_path = project_dir.join("lpm.json");

	if lpm_json_path.exists() {
		let content = std::fs::read_to_string(&lpm_json_path)
			.map_err(|e| format!("failed to read lpm.json: {e}"))?;
		let mut config: serde_json::Value = serde_json::from_str(&content)
			.map_err(|e| format!("failed to parse lpm.json: {e}"))?;

		// Return existing vault ID if present
		if let Some(vault_id) = config.get("vault").and_then(|v| v.as_str()) {
			return Ok(vault_id.to_string());
		}

		// Generate new vault ID and add to existing config
		let vault_id = generate_uuid();
		config["vault"] = serde_json::Value::String(vault_id.clone());

		let content = serde_json::to_string_pretty(&config)
			.map_err(|e| format!("failed to serialize lpm.json: {e}"))?;
		std::fs::write(&lpm_json_path, content)
			.map_err(|e| format!("failed to write lpm.json: {e}"))?;

		Ok(vault_id)
	} else {
		// Create minimal lpm.json with vault ID
		let vault_id = generate_uuid();
		let config = serde_json::json!({ "vault": vault_id });

		let content = serde_json::to_string_pretty(&config)
			.map_err(|e| format!("failed to serialize lpm.json: {e}"))?;
		std::fs::write(&lpm_json_path, content)
			.map_err(|e| format!("failed to write lpm.json: {e}"))?;

		Ok(vault_id)
	}
}

/// Read the vault ID from lpm.json without creating one.
pub fn read_vault_id(project_dir: &Path) -> Option<String> {
	let lpm_json_path = project_dir.join("lpm.json");
	let content = std::fs::read_to_string(lpm_json_path).ok()?;
	let config: serde_json::Value = serde_json::from_str(&content).ok()?;
	config.get("vault").and_then(|v| v.as_str()).map(|s| s.to_string())
}

/// Get the project name from package.json or lpm.json.
pub fn read_project_name(project_dir: &Path) -> String {
	// Try package.json first
	let pkg_path = project_dir.join("package.json");
	if let Ok(content) = std::fs::read_to_string(&pkg_path) {
		if let Ok(pkg) = serde_json::from_str::<serde_json::Value>(&content) {
			if let Some(name) = pkg.get("name").and_then(|v| v.as_str()) {
				return name.to_string();
			}
		}
	}

	// Try lpm.json
	let lpm_path = project_dir.join("lpm.json");
	if let Ok(content) = std::fs::read_to_string(&lpm_path) {
		if let Ok(cfg) = serde_json::from_str::<serde_json::Value>(&content) {
			if let Some(name) = cfg.get("name").and_then(|v| v.as_str()) {
				return name.to_string();
			}
		}
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
		bytes[0], bytes[1], bytes[2], bytes[3],
		bytes[4], bytes[5],
		bytes[6], bytes[7],
		bytes[8], bytes[9],
		bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]
	)
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
}
